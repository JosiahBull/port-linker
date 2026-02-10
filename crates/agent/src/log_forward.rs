//! Agent log forwarding layer (Architecture Section 7.1).
//!
//! Provides a tracing `Layer` that captures log events and sends them
//! over a QUIC unidirectional stream to the host in real-time. The events
//! are serialized using the protocol crate's `AgentLogEvent` type.
//!
//! The internal channel is bounded to `CHANNEL_CAPACITY` to provide
//! backpressure. When the channel is full (e.g. the QUIC stream is
//! congested), log events are silently dropped rather than blocking the
//! calling task.

use std::fmt;

use tokio::sync::mpsc;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use protocol::{AgentLogEvent, LogLevel};

/// Maximum number of log events buffered before the layer starts dropping.
///
/// 4096 events is generous for burst logging (a typical log event is
/// ~200-500 bytes serialized, so worst-case buffer is ~2 MB). This
/// prevents unbounded memory growth if the QUIC stream is congested.
const CHANNEL_CAPACITY: usize = 4096;

/// Create a forwarding layer and the receiver that drains into QUIC.
///
/// The returned [`ForwardingLayer`] should be installed in the agent's
/// tracing subscriber. The [`mpsc::Receiver`] should be passed to
/// [`drain_logs_to_quic`] once the QUIC connection is established.
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

        // Format the event fields into a message string.
        // Pre-allocate 128 bytes; typical log messages fit without realloc.
        let mut visitor = MessageVisitor {
            buf: String::with_capacity(128),
            has_message: false,
        };
        event.record(&mut visitor);
        let message = visitor.buf;

        // Best-effort send; if the channel is full or closed, silently drop.
        // Using try_send is critical: a tracing layer MUST NOT block the
        // calling task, and awaiting a bounded send is not possible here
        // (on_event is synchronous).
        let _ = self.tx.try_send(AgentLogEvent {
            level,
            target,
            message,
        });
    }
}

/// A field visitor that formats event fields into a single string.
///
/// Uses in-place `write!` on the buffer instead of `format!` to avoid
/// allocating a new `String` on every field. The `message` field is
/// always written first (tracing emits it before other fields), and
/// additional fields are appended with comma separation.
struct MessageVisitor {
    buf: String,
    /// Whether the special `message` field has been recorded. When true,
    /// subsequent fields are appended after a separator.
    has_message: bool,
}

impl MessageVisitor {
    /// Append a separator before the next field if the buffer already has content.
    #[inline]
    fn write_separator(&mut self) {
        if !self.buf.is_empty() {
            // Writing a literal str to a String is infallible.
            self.buf.push_str(", ");
        }
    }
}

impl tracing_core::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn fmt::Debug) {
        use fmt::Write;
        if field.name() == "message" {
            // Clear any previously accumulated non-message fields and write
            // the message. In practice tracing always emits `message` first,
            // but clear defensively.
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

/// Maximum frame size for log events (64 KB — more than enough for a log line).
const MAX_LOG_FRAME: u32 = 65_536;

/// Drain log events from the channel and write them to a QUIC unidirectional
/// stream as length-prefixed rkyv-encoded `AgentLogEvent` messages.
///
/// Runs until the receiver is drained and all senders are dropped (i.e., the
/// subscriber is torn down) or the QUIC stream errors out.
pub async fn drain_logs_to_quic(
    mut rx: mpsc::Receiver<AgentLogEvent>,
    mut send: quinn::SendStream,
) {
    // Reusable buffer for coalescing the 4-byte length prefix + payload into
    // a single write_all call. Avoids per-event allocation and reduces the
    // number of QUIC stream writes by half.
    let mut write_buf: Vec<u8> = Vec::with_capacity(512);

    while let Some(event) = rx.recv().await {
        let payload = match protocol::encode(&event) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let len = payload.len() as u32;
        if len > MAX_LOG_FRAME {
            continue;
        }

        // Coalesce length prefix + payload into a single write.
        write_buf.clear();
        write_buf.extend_from_slice(&len.to_be_bytes());
        write_buf.extend_from_slice(&payload);

        if send.write_all(&write_buf).await.is_err() {
            break;
        }
    }

    // Best-effort graceful close.
    let _ = send.finish();
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

        // Install the layer in a subscriber and emit an event.
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "test_target", "hello from test");
        });

        // The event should appear in the channel.
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
        // The message should contain the main message text.
        assert!(
            event.message.contains("main message"),
            "message should contain main text: {}",
            event.message
        );
    }

    #[tokio::test]
    async fn forwarding_layer_handles_channel_close() {
        let (layer, rx) = forwarding_layer();

        // Drop the receiver to close the channel.
        drop(rx);

        // Install the layer and emit an event.
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // This should not panic even though the channel is closed.
            tracing::info!("test");
        });
    }

    #[test]
    fn max_log_frame_constant() {
        assert_eq!(MAX_LOG_FRAME, 65_536);
        const { assert!(MAX_LOG_FRAME > 0) };
        assert!(MAX_LOG_FRAME.is_power_of_two());
    }

    #[test]
    fn to_tracing_level_coverage() {
        // Ensure all LogLevel variants are covered.
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
