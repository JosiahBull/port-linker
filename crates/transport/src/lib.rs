//! Transport layer for port-linker agent communication.
//!
//! This crate defines the `Transport` trait and provides concrete implementations
//! for different communication channels between the host and agent:
//!
//! - `StdioTransport`: Wraps an SSH exec channel (stdin/stdout) with non-blocking I/O.
//!   Maximum compatibility, works everywhere.
//!
//! - TCP socket via SSH direct-tcpip
//! - QUIC over UDP (bypasses SSH for data)

pub mod error;
pub mod negotiate;
pub mod quic;
pub mod quic_config;
pub mod stdio;
pub mod tcp;
pub mod types;

pub use error::{Result, TransportError};
pub use negotiate::{negotiate_transport, negotiate_transport_stdio, select_transport};
pub use stdio::StdioTransport;
pub use tcp::TcpTransport;
pub use types::{NegotiationMessage, TransportAccept, TransportEntry, TransportKind, TransportOffer};

use proto::Message;
use std::io::Write;
use std::time::{Duration, Instant};

/// Maximum time to spend retrying a single send operation.
const SEND_RETRY_TIMEOUT: Duration = Duration::from_millis(500);

/// Sleep duration between retries when a write returns WouldBlock/EAGAIN.
const SEND_RETRY_SLEEP: Duration = Duration::from_micros(100);

/// Write all bytes to a writer, retrying on WouldBlock/EAGAIN.
///
/// Unlike `Write::write_all()`, this handles non-blocking I/O by retrying
/// with brief sleeps when the writer returns WouldBlock or EAGAIN. This is
/// necessary because ssh2 channels in non-blocking mode return EAGAIN when
/// the session's internal state machine needs to run (e.g., key exchange,
/// window updates).
pub(crate) fn write_all_retry<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    let start = Instant::now();
    let mut written = 0;

    while written < data.len() {
        match writer.write(data.get(written..).unwrap_or(&[])) {
            Ok(0) => return Err(TransportError::Closed),
            Ok(n) => {
                written = written.saturating_add(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > SEND_RETRY_TIMEOUT {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "write timed out after retries",
                    )));
                }
                std::thread::sleep(SEND_RETRY_SLEEP);
            }
            Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                if start.elapsed() > SEND_RETRY_TIMEOUT {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "write timed out after retries",
                    )));
                }
                std::thread::sleep(SEND_RETRY_SLEEP);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => return Err(TransportError::Io(e)),
        }
    }

    Ok(())
}

/// Flush a writer, retrying on WouldBlock/EAGAIN.
pub(crate) fn flush_retry<W: Write>(writer: &mut W) -> Result<()> {
    let start = Instant::now();

    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > SEND_RETRY_TIMEOUT {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "flush timed out after retries",
                    )));
                }
                std::thread::sleep(SEND_RETRY_SLEEP);
            }
            Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                if start.elapsed() > SEND_RETRY_TIMEOUT {
                    return Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "flush timed out after retries",
                    )));
                }
                std::thread::sleep(SEND_RETRY_SLEEP);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => return Err(TransportError::Io(e)),
        }
    }
}

/// Synchronous transport trait for sending and receiving protocol messages.
///
/// All implementations must be `Send` so the transport can be moved between threads.
/// Operations are non-blocking where possible.
pub trait Transport: Send {
    /// Send a message. Encodes and writes the message, flushing internally.
    fn send(&mut self, msg: &Message) -> Result<()>;

    /// Try to receive a message (non-blocking).
    ///
    /// Returns `Ok(None)` if no complete message is available yet.
    /// Returns `Ok(Some(msg))` when a complete message has been received.
    /// Returns `Err(...)` on I/O or protocol errors.
    fn try_recv(&mut self) -> Result<Option<Message>>;

    /// Drive internal state (e.g., QUIC timers/retransmits).
    ///
    /// No-op for stdio and TCP transports.
    fn poll(&mut self) -> Result<()> {
        Ok(())
    }

    /// Gracefully close the transport.
    fn close(&mut self) -> Result<()>;

    /// Human-readable name for this transport type.
    fn transport_name(&self) -> &'static str;
}
