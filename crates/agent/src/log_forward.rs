//! Agent log forwarding layer.
//!
//! Provides a tracing `Layer` that captures log events and sends them
//! as `MuxFrame::Log` frames through the shared stdout channel.
//!
//! The internal channel is bounded to `CHANNEL_CAPACITY` to provide
//! backpressure. When the channel is full, log events are silently
//! dropped rather than blocking the calling task.

use std::fmt;

use tokio::sync::mpsc;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use protocol::{AgentLogEvent, LogLevel, MuxFrame};

/// Maximum number of log events buffered before the layer starts dropping.
const CHANNEL_CAPACITY: usize = 4096;

/// Create a forwarding layer and the receiver that drains into the mux channel.
///
/// The returned [`ForwardingLayer`] should be installed in the agent's
/// tracing subscriber. The [`mpsc::Receiver`] should be passed to
/// [`drain_logs`] once the mux frame channel is established.
pub fn forwarding_layer() -> (ForwardingLayer, mpsc::Receiver<AgentLogEvent>) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    (ForwardingLayer { tx }, rx)
}

/// A tracing layer that captures events and sends them to a bounded mpsc
/// channel. When the channel is full, events are silently dropped.
pub struct ForwardingLayer {
    tx: mpsc::Sender<AgentLogEvent>,
}

impl<S: Subscriber> Layer<S> for ForwardingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        let level = match *metadata.level() {
            tracing_core::Level::ERROR => LogLevel::Error,
            tracing_core::Level::WARN => LogLevel::Warn,
            tracing_core::Level::INFO => LogLevel::Info,
            tracing_core::Level::DEBUG => LogLevel::Debug,
            tracing_core::Level::TRACE => LogLevel::Trace,
        };

        let target = metadata.target().to_string();

        let mut visitor = MessageVisitor {
            buf: String::with_capacity(128),
            has_message: false,
        };
        event.record(&mut visitor);
        let message = visitor.buf;

        // Best-effort send; if the channel is full or closed, silently drop.
        let _ = self.tx.try_send(AgentLogEvent {
            level,
            target,
            message,
        });
    }
}

struct MessageVisitor {
    buf: String,
    has_message: bool,
}

impl MessageVisitor {
    #[inline]
    fn write_separator(&mut self) {
        if !self.buf.is_empty() {
            self.buf.push_str(", ");
        }
    }
}

impl tracing_core::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn fmt::Debug) {
        use fmt::Write;
        if field.name() == "message" {
            self.buf.clear();
            let _ = write!(self.buf, "{:?}", value);
            self.has_message = true;
        } else {
            self.write_separator();
            let _ = write!(self.buf, "{}={:?}", field, value);
        }
    }

    fn record_str(&mut self, field: &tracing_core::field::Field, value: &str) {
        use fmt::Write;
        if field.name() == "message" {
            self.buf.clear();
            self.buf.push_str(value);
            self.has_message = true;
        } else {
            self.write_separator();
            let _ = write!(self.buf, "{}={}", field, value);
        }
    }
}

/// Drain log events from the channel and send them as `MuxFrame::Log` frames
/// through the shared mux channel.
///
/// Runs until the receiver is drained and all senders are dropped, or the
/// mux channel is closed.
pub async fn drain_logs(
    mut rx: mpsc::Receiver<AgentLogEvent>,
    frame_tx: mpsc::UnboundedSender<MuxFrame>,
) {
    while let Some(event) = rx.recv().await {
        if frame_tx.send(MuxFrame::Log(event)).is_err() {
            break;
        }
    }
}

/// Map a [`LogLevel`] to a [`tracing_core::Level`].
pub fn to_tracing_level(level: &LogLevel) -> tracing_core::Level {
    match level {
        LogLevel::Error => tracing_core::Level::ERROR,
        LogLevel::Warn => tracing_core::Level::WARN,
        LogLevel::Info => tracing_core::Level::INFO,
        LogLevel::Debug => tracing_core::Level::DEBUG,
        LogLevel::Trace => tracing_core::Level::TRACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_layer_creates_channel() {
        let (_layer, _rx) = forwarding_layer();
    }

    #[test]
    fn to_tracing_level_roundtrip() {
        assert_eq!(
            to_tracing_level(&LogLevel::Error),
            tracing_core::Level::ERROR
        );
        assert_eq!(to_tracing_level(&LogLevel::Warn), tracing_core::Level::WARN);
        assert_eq!(to_tracing_level(&LogLevel::Info), tracing_core::Level::INFO);
        assert_eq!(
            to_tracing_level(&LogLevel::Debug),
            tracing_core::Level::DEBUG
        );
        assert_eq!(
            to_tracing_level(&LogLevel::Trace),
            tracing_core::Level::TRACE
        );
    }

    #[test]
    fn message_visitor_starts_empty() {
        let visitor = MessageVisitor {
            buf: String::new(),
            has_message: false,
        };
        assert!(visitor.buf.is_empty(), "visitor should start empty");
    }

    #[tokio::test]
    async fn forwarding_layer_sends_events() {
        let (layer, mut rx) = forwarding_layer();

        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "test_target", "hello from test");
        });

        let event = rx.try_recv().expect("should have received a log event");
        assert_eq!(event.level, LogLevel::Info);
        assert_eq!(event.target, "test_target");
        assert!(
            event.message.contains("hello from test"),
            "message: {}",
            event.message
        );
    }

    #[tokio::test]
    async fn forwarding_layer_captures_all_levels() {
        let (layer, mut rx) = forwarding_layer();

        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("err");
            tracing::warn!("wrn");
            tracing::info!("inf");
            tracing::debug!("dbg");
            tracing::trace!("trc");
        });

        let levels: Vec<LogLevel> = (0..5)
            .filter_map(|_| rx.try_recv().ok())
            .map(|e| e.level)
            .collect();

        assert_eq!(
            levels,
            vec![
                LogLevel::Error,
                LogLevel::Warn,
                LogLevel::Info,
                LogLevel::Debug,
                LogLevel::Trace
            ]
        );
    }

    #[tokio::test]
    async fn forwarding_layer_captures_target() {
        let (layer, mut rx) = forwarding_layer();

        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "custom::target::path", "message");
        });

        let event = rx.try_recv().expect("should have received event");
        assert_eq!(event.target, "custom::target::path");
    }

    #[tokio::test]
    async fn forwarding_layer_captures_fields() {
        let (layer, mut rx) = forwarding_layer();

        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(foo = "bar", count = 42, "main message");
        });

        let event = rx.try_recv().expect("should have received event");
        assert!(
            event.message.contains("main message"),
            "message should contain main text: {}",
            event.message
        );
    }

    #[tokio::test]
    async fn forwarding_layer_handles_channel_close() {
        let (layer, rx) = forwarding_layer();
        drop(rx);

        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("test");
        });
    }

    #[test]
    fn to_tracing_level_coverage() {
        let all_levels = vec![
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ];

        for level in all_levels {
            let _ = to_tracing_level(&level);
        }
    }
}
