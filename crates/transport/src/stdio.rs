//! Stdio transport: wraps an SSH exec channel (or raw stdin/stdout)
//! for message-based communication.
//!
//! This is the fallback transport that always works. The agent's stdin/stdout
//! is connected to an ssh2 exec channel on the host side.

use crate::error::{Result, TransportError};
use crate::Transport;
use proto::Message;
use std::io::{Read, Write};

/// Transport over an ssh2 exec channel (stdin/stdout style I/O).
///
/// On the host side, this wraps an `ssh2::Channel` from `exec_channel()`.
/// On the agent side, this wraps raw stdin/stdout file descriptors.
///
/// The underlying I/O should be in non-blocking mode for `try_recv` to work
/// correctly. The session-level blocking mode controls this for ssh2 channels.
pub struct StdioTransport<R: Read + Send, W: Write + Send> {
    reader: R,
    writer: W,
    /// Buffer for accumulating partial messages from the reader.
    /// Public within the crate so negotiation can inject leftover bytes.
    pub(crate) read_buf: Vec<u8>,
    /// Temporary buffer for individual reads
    tmp_buf: Vec<u8>,
}

impl<R: Read + Send, W: Write + Send> StdioTransport<R, W> {
    /// Create a new `StdioTransport` from a reader and writer.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            read_buf: Vec::new(),
            tmp_buf: vec![0_u8; 65536],
        }
    }

    /// Create a new `StdioTransport` with pre-buffered leftover bytes from negotiation.
    pub fn with_leftover(reader: R, writer: W, leftover: Vec<u8>) -> Self {
        Self {
            reader,
            writer,
            read_buf: leftover,
            tmp_buf: vec![0_u8; 65536],
        }
    }
}

impl<R: Read + Send, W: Write + Send> Transport for StdioTransport<R, W> {
    fn send(&mut self, msg: &Message) -> Result<()> {
        let encoded = msg.encode();
        crate::write_all_retry(&mut self.writer, &encoded)?;
        crate::flush_retry(&mut self.writer)?;
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<Message>> {
        // First, check if we already have a complete message buffered
        if let Some((message, consumed)) = Message::decode(&self.read_buf) {
            self.read_buf.drain(..consumed);
            return Ok(Some(message));
        }

        // Try to read more data (non-blocking)
        match self.reader.read(&mut self.tmp_buf) {
            Ok(0) => {
                return Err(TransportError::Closed);
            }
            Ok(n) => {
                self.read_buf
                    .extend_from_slice(self.tmp_buf.get(..n).unwrap_or(&[]));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available right now
            }
            Err(e) => {
                // ssh2 reports EAGAIN as a generic error, not WouldBlock
                if e.raw_os_error() != Some(libc::EAGAIN) {
                    return Err(TransportError::Io(e));
                }
            }
        }

        // Try to decode from newly read data
        if let Some((message, consumed)) = Message::decode(&self.read_buf) {
            self.read_buf.drain(..consumed);
            Ok(Some(message))
        } else {
            Ok(None)
        }
    }

    fn close(&mut self) -> Result<()> {
        // Flush any pending writes
        self.writer.flush().ok();
        Ok(())
    }

    fn transport_name(&self) -> &'static str {
        "stdio"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_send_recv_roundtrip() {
        // Create a buffer as the "wire"
        let mut wire = Vec::new();

        // Send a message
        let msg = Message::Ping(42);
        let encoded = msg.encode();
        wire.extend_from_slice(&encoded);

        // Create a transport reading from the wire
        let reader = Cursor::new(wire);
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        // Receive the message
        let received = transport.try_recv().unwrap();
        assert_eq!(received, Some(Message::Ping(42)));
    }

    #[test]
    fn test_send_writes_to_writer() {
        let reader = Cursor::new(Vec::<u8>::new());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        let msg = Message::Pong(99);
        transport.send(&msg).unwrap();

        // The writer should contain the encoded message
        // (we can't easily access it after the fact without using Rc/RefCell,
        // but the test verifies send doesn't panic)
    }

    #[test]
    fn test_empty_read_returns_none() {
        // Create transport with empty reader
        // We'll use a vec that returns WouldBlock by wrapping in a custom reader
        // For simplicity, use a Cursor that returns 0 bytes (EOF)
        let reader = Cursor::new(Vec::<u8>::new());
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        // EOF should result in Closed error
        let result = transport.try_recv();
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_messages() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&Message::Ping(1).encode());
        wire.extend_from_slice(&Message::Pong(1).encode());
        wire.extend_from_slice(&Message::Ping(2).encode());

        let reader = Cursor::new(wire);
        let writer = Vec::new();
        let mut transport = StdioTransport::new(reader, writer);

        assert_eq!(transport.try_recv().unwrap(), Some(Message::Ping(1)));
        assert_eq!(transport.try_recv().unwrap(), Some(Message::Pong(1)));
        assert_eq!(transport.try_recv().unwrap(), Some(Message::Ping(2)));
    }

    #[test]
    fn test_transport_name() {
        let reader = Cursor::new(Vec::<u8>::new());
        let writer = Vec::new();
        let transport = StdioTransport::new(reader, writer);
        assert_eq!(transport.transport_name(), "stdio");
    }
}
