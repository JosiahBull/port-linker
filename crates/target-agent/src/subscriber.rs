//! Buffered tracing subscriber that sends log events to the host over the TLV protocol.
//!
//! The agent is strictly single-threaded, so we use `thread_local!` storage for the
//! event buffer. Events are flushed periodically in the main loop or when the buffer
//! exceeds a size threshold.

use port_linker_proto::{LogEvent, LogLevel, Message};
use std::cell::{Cell, RefCell};
use std::io::Write;
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Metadata, Subscriber};

/// Size threshold (in bytes) at which the buffer should be flushed.
const FLUSH_THRESHOLD_BYTES: usize = 60 * 1024; // 60KB

thread_local! {
    static LOG_BUFFER: RefCell<Vec<LogEvent>> = const { RefCell::new(Vec::new()) };
    static LOG_BUFFER_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// A tracing subscriber that buffers log events in thread-local storage.
///
/// Events are collected and can be flushed as a `Message::LogBatch` to stdout.
pub struct BufferedStdoutSubscriber;

impl BufferedStdoutSubscriber {
    /// Create a new subscriber.
    pub const fn new() -> Self {
        Self
    }
}

impl Subscriber for BufferedStdoutSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing_core::span::Attributes<'_>) -> tracing_core::span::Id {
        // No span tracking in v1
        tracing_core::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing_core::span::Id, _values: &tracing_core::span::Record<'_>) {
        // No span tracking
    }

    fn record_follows_from(
        &self,
        _span: &tracing_core::span::Id,
        _follows: &tracing_core::span::Id,
    ) {
        // No span tracking
    }

    fn event(&self, event: &Event<'_>) {
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
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);

        let message = if visitor.fields.is_empty() {
            visitor.message
        } else {
            let fields: String = visitor
                .fields
                .iter()
                .map(|(k, v)| format!(" {}={}", k, v))
                .collect();
            let mut msg = visitor.message;
            msg.push_str(&fields);
            msg
        };

        let estimated_size = target.len().saturating_add(message.len()).saturating_add(8);

        LOG_BUFFER.with(|buf| {
            buf.borrow_mut().push(LogEvent {
                level,
                target,
                message,
            });
        });
        LOG_BUFFER_BYTES.with(|bytes| {
            bytes.set(bytes.get().saturating_add(estimated_size));
        });
    }

    fn enter(&self, _span: &tracing_core::span::Id) {
        // No span tracking
    }

    fn exit(&self, _span: &tracing_core::span::Id) {
        // No span tracking
    }
}

/// Visitor that captures the `message` field and any additional key=value fields.
struct MessageVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
}

/// Drain the buffer, encode as `Message::LogBatch`, write to the given writer, and flush.
///
/// Returns the number of events flushed.
pub fn flush_log_buffer(writer: &mut dyn Write) -> usize {
    let events: Vec<LogEvent> = LOG_BUFFER.with(|buf| {
        let mut b = buf.borrow_mut();
        let drained = b.drain(..).collect();
        drained
    });
    LOG_BUFFER_BYTES.with(|bytes| bytes.set(0));

    let count = events.len();
    if count == 0 {
        return 0;
    }

    let msg = Message::LogBatch(events);
    let encoded = msg.encode();
    // Best-effort write; if stdout is broken we can't log about it
    drop(writer.write_all(&encoded));
    drop(writer.flush());

    count
}

/// Returns `true` when the buffer exceeds the flush threshold.
pub fn should_flush() -> bool {
    LOG_BUFFER_BYTES.with(|bytes| bytes.get() >= FLUSH_THRESHOLD_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_empty_buffer() {
        let mut buf = Vec::new();
        let count = flush_log_buffer(&mut buf);
        assert_eq!(count, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_should_flush_initially_false() {
        assert!(!should_flush());
    }

    #[test]
    fn test_buffer_and_flush() {
        // Manually push events into the thread-local buffer
        LOG_BUFFER.with(|buf| {
            buf.borrow_mut().push(LogEvent {
                level: LogLevel::Info,
                target: "test".to_string(),
                message: "hello".to_string(),
            });
        });
        LOG_BUFFER_BYTES.with(|bytes| bytes.set(20));

        let mut output = Vec::new();
        let count = flush_log_buffer(&mut output);
        assert_eq!(count, 1);
        assert!(!output.is_empty());

        // Verify the output can be decoded
        let (decoded, consumed) = Message::decode(&output).unwrap();
        assert_eq!(consumed, output.len());
        match decoded {
            Message::LogBatch(events) => {
                assert_eq!(events.len(), 1);
                assert_eq!(events.first().unwrap().level, LogLevel::Info);
                assert_eq!(events.first().unwrap().target, "test");
                assert_eq!(events.first().unwrap().message, "hello");
            }
            other => panic!("Expected LogBatch, got {:?}", other),
        }

        // Buffer should be empty now
        assert!(!should_flush());
        let count = flush_log_buffer(&mut Vec::new());
        assert_eq!(count, 0);
    }
}
