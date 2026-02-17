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

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use quinn::udp::{RecvMeta, Transmit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Maximum framed datagram size (2-byte length prefix -> max 65535).
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Frame header size (2-byte BE length prefix).
const FRAME_HEADER_SIZE: usize = 2;

/// A synthetic local address used for `RecvMeta`.
fn synthetic_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Inner mutable state for the `TcpUdpSocket`.
struct Inner {
    recv_queue: VecDeque<Vec<u8>>,
    recv_waker: Option<Waker>,
    closed: bool,
}

/// Bounded channel capacity for outgoing datagrams.
const WRITE_CHANNEL_CAPACITY: usize = 256;

/// A `quinn::AsyncUdpSocket` implementation over a TCP stream.
///
/// Frames UDP datagrams with a 2-byte BE length prefix for transport
/// over TCP (or any `AsyncRead + AsyncWrite` stream, such as an SSH channel).
pub struct TcpUdpSocket {
    inner: Arc<Mutex<Inner>>,
    write_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    local_addr: SocketAddr,
}

impl std::fmt::Debug for TcpUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

// Safety: The inner state is protected by tokio::sync::Mutex which is Send+Sync.
// The writer is wrapped in Arc<Mutex<...>> with Send bounds.
unsafe impl Send for TcpUdpSocket {}
unsafe impl Sync for TcpUdpSocket {}

impl TcpUdpSocket {
    /// Create a new `TcpUdpSocket` wrapping an async stream.
    ///
    /// Spawns a background reader task that reads length-prefixed datagrams
    /// from the stream and queues them for `poll_recv`, and a background
    /// writer task that drains a bounded channel of outgoing datagrams.
    pub fn new<S>(stream: S, local_addr: SocketAddr) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);

        let inner = Arc::new(Mutex::new(Inner {
            recv_queue: VecDeque::new(),
            recv_waker: None,
            closed: false,
        }));

        let (write_tx, write_rx) = tokio::sync::mpsc::channel(WRITE_CHANNEL_CAPACITY);

        let socket = Arc::new(TcpUdpSocket {
            inner: inner.clone(),
            write_tx,
            local_addr,
        });

        // Spawn background reader.
        tokio::spawn(reader_task(read_half, inner));
        // Spawn background writer.
        tokio::spawn(writer_task(write_half, write_rx));

        socket
    }
}

/// Background task that writes length-prefixed datagrams to the TCP stream.
async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        if payload.len() > MAX_DATAGRAM_SIZE {
            warn!(
                len = payload.len(),
                "TcpUdpSocket dropping oversized datagram (max {MAX_DATAGRAM_SIZE})"
            );
            continue;
        }
        let len_bytes = (payload.len() as u16).to_be_bytes();
        if let Err(e) = writer.write_all(&len_bytes).await {
            debug!("TcpUdpSocket write header error: {e}");
            return;
        }
        if let Err(e) = writer.write_all(&payload).await {
            debug!("TcpUdpSocket write payload error: {e}");
            return;
        }
        let _ = writer.flush().await;
    }
}

/// Background task that reads length-prefixed datagrams from the TCP stream.
async fn reader_task<R: AsyncRead + Unpin>(mut reader: R, inner: Arc<Mutex<Inner>>) {
    let mut header_buf = [0u8; FRAME_HEADER_SIZE];
    let mut read_buf = BytesMut::with_capacity(MAX_DATAGRAM_SIZE);

    loop {
        // Read the 2-byte length prefix.
        if let Err(e) = reader.read_exact(&mut header_buf).await {
            debug!("TcpUdpSocket reader: stream closed: {e}");
            let mut inner = inner.lock().await;
            inner.closed = true;
            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            return;
        }

        let len = u16::from_be_bytes(header_buf) as usize;
        if len == 0 || len > MAX_DATAGRAM_SIZE {
            warn!(
                len,
                "TcpUdpSocket reader: invalid frame length, closing socket"
            );
            let mut inner = inner.lock().await;
            inner.closed = true;
            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            return;
        }

        // Read the payload.
        read_buf.resize(len, 0);
        if let Err(e) = reader.read_exact(&mut read_buf[..len]).await {
            debug!("TcpUdpSocket reader: stream closed during payload: {e}");
            let mut inner = inner.lock().await;
            inner.closed = true;
            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            return;
        }

        let datagram = read_buf[..len].to_vec();
        read_buf.clear();

        let mut inner = inner.lock().await;
        inner.recv_queue.push_back(datagram);
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }
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

        // Enqueue the datagram for the background writer task.
        // try_send is non-blocking; if the channel is full we report WouldBlock
        // so QUIC can apply backpressure.
        self.write_tx.try_send(data.to_vec()).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "write channel full")
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "writer task closed")
            }
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // We need to check the queue in a non-async way.
        // Use try_lock to avoid blocking.
        let mut inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Can't acquire lock, return pending and rely on the lock
                // holder (reader_task) to wake us when it pushes a datagram.
                return Poll::Pending;
            }
        };

        if inner.recv_queue.is_empty() {
            if inner.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "TCP stream closed",
                )));
            }
            inner.recv_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let count = bufs.len().min(meta.len()).min(inner.recv_queue.len());
        for i in 0..count {
            let datagram = inner.recv_queue.pop_front().unwrap();
            let len = datagram.len().min(bufs[i].len());
            bufs[i][..len].copy_from_slice(&datagram[..len]);
            meta[i] = RecvMeta {
                addr: synthetic_addr(),
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
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
    #[allow(dead_code)]
    socket: Arc<TcpUdpSocket>,
}

impl quinn::UdpPoller for TcpUdpPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        // TCP is always writable (writes are queued).
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_addr() {
        let addr = synthetic_addr();
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn test_frame_header_size() {
        assert_eq!(FRAME_HEADER_SIZE, 2);
    }

    #[test]
    fn test_max_datagram_size() {
        assert_eq!(MAX_DATAGRAM_SIZE, 65535);
    }
}
