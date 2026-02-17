//! QUIC-over-TCP transport adapter for port-linker.
//!
//! Implements `quinn::AsyncUdpSocket` over a TCP stream (typically an SSH
//! `direct-tcpip` channel). This allows QUIC to work through SSH tunnels
//! when UDP is blocked.
//!
//! ## Framing
//!
//! Each UDP datagram is framed as: `[2-byte BE length][payload]`.
//! Maximum datagram size: 65535 bytes.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use quinn::udp::{RecvMeta, Transmit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Maximum framed datagram size (2-byte length prefix -> max 65535).
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Frame header size (2-byte BE length prefix).
const FRAME_HEADER_SIZE: usize = 2;

/// Capacity of the bounded send channel. Provides backpressure when the
/// TCP writer can't keep up with QUIC's send rate.
const SEND_CHANNEL_CAPACITY: usize = 1024;

/// A `quinn::AsyncUdpSocket` implementation over a TCP stream.
///
/// Frames UDP datagrams with a 2-byte BE length prefix for transport
/// over TCP (or any `AsyncRead + AsyncWrite` stream, such as an SSH channel).
///
/// Internally uses channels for both recv and send paths:
/// - Recv: an unbounded mpsc channel from the reader task. A `Mutex` wraps
///   the receiver for interior mutability (required by `&self` in `poll_recv`),
///   but has zero contention since only `poll_recv` ever locks it.
/// - Send: a bounded mpsc channel to the writer task, providing backpressure
///   when the TCP stream can't drain fast enough.
pub struct TcpUdpSocket {
    /// Receive channel. Only locked by `poll_recv`; the reader task uses the
    /// sender side, so there is no contention on this mutex.
    recv_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Bounded send channel to the writer task.
    send_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Waker registered by `poll_writable` when the send channel is full.
    /// Shared with the writer task which wakes it after draining a frame.
    send_waker: Arc<Mutex<Option<Waker>>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl std::fmt::Debug for TcpUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl TcpUdpSocket {
    /// Create a new `TcpUdpSocket` wrapping an async stream.
    ///
    /// Spawns background reader and writer tasks. The reader reads
    /// length-prefixed datagrams from the stream and sends them through a
    /// channel for `poll_recv`. The writer drains a bounded channel of
    /// outgoing frames from `try_send`, ensuring FIFO ordering and
    /// backpressure.
    ///
    /// `local_addr` is reported by `local_addr()`. `remote_addr` is used as
    /// the source address in `RecvMeta` so that quinn can associate incoming
    /// datagrams with the correct connection. Both addresses must have non-zero
    /// ports to satisfy quinn's validation.
    pub fn new<S>(stream: S, local_addr: SocketAddr, remote_addr: SocketAddr) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);

        let (recv_tx, recv_rx) = tokio::sync::mpsc::unbounded_channel();
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(SEND_CHANNEL_CAPACITY);

        let send_waker = Arc::new(Mutex::new(None));

        let socket = Arc::new(TcpUdpSocket {
            recv_rx: Mutex::new(recv_rx),
            send_tx,
            send_waker: Arc::clone(&send_waker),
            local_addr,
            remote_addr,
        });

        // Spawn background reader and writer tasks.
        tokio::spawn(reader_task(read_half, recv_tx));
        tokio::spawn(writer_task(write_half, send_rx, send_waker));

        socket
    }
}

/// Background task that reads length-prefixed datagrams from the TCP stream
/// and sends them through the recv channel. No mutex is held across await
/// points — the channel handles all synchronization.
async fn reader_task<R: AsyncRead + Unpin>(
    mut reader: R,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut header_buf = [0u8; FRAME_HEADER_SIZE];
    let mut read_buf = BytesMut::with_capacity(MAX_DATAGRAM_SIZE);

    loop {
        // Read the 2-byte length prefix.
        if let Err(e) = reader.read_exact(&mut header_buf).await {
            debug!("TcpUdpSocket reader: stream closed: {e}");
            return; // Dropping tx signals closure to poll_recv.
        }

        let len = u16::from_be_bytes(header_buf) as usize;
        if len == 0 || len > MAX_DATAGRAM_SIZE {
            warn!(
                len,
                "TcpUdpSocket reader: invalid frame length, closing socket"
            );
            return;
        }

        // Read the payload.
        read_buf.resize(len, 0);
        if let Err(e) = reader.read_exact(&mut read_buf[..len]).await {
            debug!("TcpUdpSocket reader: stream closed during payload: {e}");
            return;
        }

        let datagram = read_buf[..len].to_vec();
        read_buf.clear();

        if tx.send(datagram).is_err() {
            // Receiver dropped (socket dropped).
            return;
        }
    }
}

/// Background task that writes length-prefixed frames to the TCP stream.
///
/// Receives pre-framed data from the bounded mpsc channel (already includes
/// the 2-byte length prefix) and writes it to the stream in order. After
/// each successful write, wakes any `poll_writable` waker to signal that
/// send capacity is available.
async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    send_waker: Arc<Mutex<Option<Waker>>>,
) {
    while let Some(frame) = rx.recv().await {
        if let Err(e) = writer.write_all(&frame).await {
            debug!("TcpUdpSocket writer: write error: {e}");
            return;
        }
        if let Err(e) = writer.flush().await {
            debug!("TcpUdpSocket writer: flush error: {e}");
            return;
        }
        // Wake poll_writable if it was waiting for send capacity.
        if let Ok(mut waker) = send_waker.lock()
            && let Some(w) = waker.take()
        {
            w.wake();
        }
    }
    debug!("TcpUdpSocket writer: channel closed");
}

impl quinn::AsyncUdpSocket for TcpUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(TcpUdpPoller {
            socket: self.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let data = &transmit.contents;
        if data.len() > MAX_DATAGRAM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram too large",
            ));
        }

        // Build the framed message: [2-byte BE length][payload].
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);

        // Send to the writer task via the bounded channel.
        self.send_tx.try_send(frame).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "send buffer full")
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "TCP writer task closed")
            }
        })?;

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // This lock has zero contention: only poll_recv ever locks recv_rx.
        // The reader task uses the sender side of the channel.
        let mut rx = self.recv_rx.lock().expect("recv lock poisoned");

        // Try to receive the first datagram (registers waker if empty).
        let first = match rx.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "TCP stream closed",
                )));
            }
            Poll::Ready(Some(datagram)) => datagram,
        };

        // Fill the first buffer.
        let max_count = bufs.len().min(meta.len());
        let len = first.len().min(bufs[0].len());
        bufs[0][..len].copy_from_slice(&first[..len]);
        meta[0] = RecvMeta {
            addr: self.remote_addr,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };

        // Try to drain additional datagrams without blocking.
        let mut count = 1;
        while count < max_count {
            match rx.try_recv() {
                Ok(datagram) => {
                    let len = datagram.len().min(bufs[count].len());
                    bufs[count][..len].copy_from_slice(&datagram[..len]);
                    meta[count] = RecvMeta {
                        addr: self.remote_addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Err(_) => break,
            }
        }

        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        // TCP stream doesn't fragment.
        false
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Poller implementation for `TcpUdpSocket`.
#[derive(Debug)]
struct TcpUdpPoller {
    socket: Arc<TcpUdpSocket>,
}

impl quinn::UdpPoller for TcpUdpPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.socket.send_tx.capacity() > 0 {
            return Poll::Ready(Ok(()));
        }
        // Channel full — register waker so the writer task can wake us
        // after draining a frame.
        if let Ok(mut waker) = self.socket.send_waker.lock() {
            *waker = Some(cx.waker().clone());
        }
        // Double-check after registering to avoid missed wakes.
        if self.socket.send_tx.capacity() > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_size() {
        assert_eq!(FRAME_HEADER_SIZE, 2);
    }

    #[test]
    fn test_max_datagram_size() {
        assert_eq!(MAX_DATAGRAM_SIZE, 65535);
    }

    #[test]
    fn test_send_channel_capacity() {
        assert_eq!(SEND_CHANNEL_CAPACITY, 1024);
    }
}
