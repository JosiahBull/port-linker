//! TCP socket transport: wraps a TCP connection (or SSH direct-tcpip channel)
//! for message-based communication.
//!
//! On the agent side, this wraps a `TcpStream` pair (cloned for read/write).
//! On the host side, this wraps an `ssh2::Channel` from `direct_tcpip()`.

use crate::error::{Result, TransportError};
use crate::Transport;
use proto::Message;
use std::io::{Read, Write};

/// Transport over a TCP socket or SSH direct-tcpip channel.
///
/// On the agent side, `R` and `W` are cloned `TcpStream` handles.
/// On the host side, `R` and `W` are cloned `ssh2::Channel` handles.
///
/// The underlying I/O should be in non-blocking mode for `try_recv` to work
/// correctly.
pub struct TcpTransport<R: Read + Send, W: Write + Send> {
    reader: R,
    writer: W,
    /// Buffer for accumulating partial messages from the reader.
    pub(crate) read_buf: Vec<u8>,
    /// Temporary buffer for individual reads.
    tmp_buf: Vec<u8>,
}

impl<R: Read + Send, W: Write + Send> TcpTransport<R, W> {
    /// Create a new `TcpTransport` from a reader and writer.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            read_buf: Vec::new(),
            tmp_buf: vec![0_u8; 65536],
        }
    }
}

impl<R: Read + Send, W: Write + Send> Transport for TcpTransport<R, W> {
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
        "tcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_send_recv_roundtrip() {
        let mut wire = Vec::new();

        let msg = Message::Ping(42);
        let encoded = msg.encode();
        wire.extend_from_slice(&encoded);

        let reader = Cursor::new(wire);
        let writer = Vec::new();
        let mut transport = TcpTransport::new(reader, writer);

        let received = transport.try_recv().unwrap();
        assert_eq!(received, Some(Message::Ping(42)));
    }

    #[test]
    fn test_multiple_messages() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&Message::Ping(1).encode());
        wire.extend_from_slice(&Message::Pong(1).encode());
        wire.extend_from_slice(&Message::Ping(2).encode());

        let reader = Cursor::new(wire);
        let writer = Vec::new();
        let mut transport = TcpTransport::new(reader, writer);

        assert_eq!(transport.try_recv().unwrap(), Some(Message::Ping(1)));
        assert_eq!(transport.try_recv().unwrap(), Some(Message::Pong(1)));
        assert_eq!(transport.try_recv().unwrap(), Some(Message::Ping(2)));
    }

    #[test]
    fn test_transport_name() {
        let reader = Cursor::new(Vec::<u8>::new());
        let writer = Vec::new();
        let transport = TcpTransport::new(reader, writer);
        assert_eq!(transport.transport_name(), "tcp");
    }
}
