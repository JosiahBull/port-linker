//! Forwarding one TCP connection over one QUIC bidirectional stream.
//!
//! # Wire contract
//!
//! ```text
//! host                                             agent
//!   |-- open_bi (local, no round trip) ------------->|
//!   |-- framed TcpStreamInit { port } -------------->|
//!   |-- raw application bytes ... ----------------->|  connect(127.0.0.1:port)
//!   |<-- 1 status byte: 0x00 ok / 0x01 error --------|
//!   |<-- (on error) framed TcpStreamError, finish ---|
//!   |=== raw bidirectional copy =====================|
//! ```
//!
//! The host does not wait for the status byte before it starts forwarding
//! application bytes. Opening a QUIC stream is a local operation, so the init
//! frame and the client's first request travel in the same flight, and the status
//! byte — which costs a full round trip to come back — never delays application
//! data. That is worth one round trip per connection, which at a 60 ms RTT halves
//! the time from a client's `connect()` to its first response byte.
//!
//! The agent needs no buffer for those early bytes: [`recv_framed`] consumes
//! exactly the init frame, and QUIC flow control holds whatever follows until the
//! copy loop starts.
//!
//! The byte sequence on the wire is the same as if the host had waited; only the
//! waiting is gone. An agent that predates this is unaffected, because its framed
//! read cannot over-read into the application bytes behind it.

use std::net::SocketAddr;

use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use protocol::ControlMsg;

use crate::framing::{recv_framed, send_framed};

/// Agent status byte: the connection to the local service succeeded.
pub const STATUS_OK: u8 = 0x00;

/// Agent status byte: the connection to the local service failed. A framed
/// [`ControlMsg::TcpStreamError`] follows.
pub const STATUS_ERROR: u8 = 0x01;

/// `STOP_SENDING` code the agent uses when it could not reach the local service
/// and therefore will never read the bytes the host optimistically sent.
pub const STOP_CONNECT_FAILED: u32 = 1;

fn spawn_pump(
    mut tcp_read: OwnedReadHalf,
    mut quic_send: quinn::SendStream,
) -> JoinHandle<std::io::Result<u64>> {
    tokio::spawn(async move {
        let copied = tokio::io::copy(&mut tcp_read, &mut quic_send).await;
        // Propagate the local half-close so the remote service sees EOF instead
        // of a stalled connection.
        let _ = quic_send.finish();
        copied
    })
}

/// Forward a local TCP connection to `port` on the target, over `connection`.
///
/// Returns when both directions have completed or the stream has failed; errors
/// are logged, not propagated, because each connection is independent of the
/// session.
pub async fn forward_tcp_connection(connection: Connection, tcp_stream: TcpStream, port: u16) {
    // Opening the stream is local: QUIC creates it implicitly with the first
    // STREAM frame, so this costs no round trip as long as stream credit is
    // available (both ends allow 4096 concurrent bidi streams).
    let (mut quic_send, mut quic_recv) = match connection.open_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            error!(port, %e, "failed to open QUIC stream for TCP forward");
            return;
        }
    };

    if let Err(e) = send_framed(&mut quic_send, &ControlMsg::TcpStreamInit { port }).await {
        error!(port, %e, "failed to send TcpStreamInit");
        return;
    }

    let (tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Start draining the local socket into the stream now, so the client's first
    // request rides in the same flight as the init frame above.
    let upstream = spawn_pump(tcp_read, quic_send);

    // The client's bytes are already in flight by the time this resolves, so the
    // round trip it costs is spent rather than waited on.
    let mut status = [0u8; 1];
    if let Err(e) = quic_recv.read_exact(&mut status).await {
        debug!(port, %e, "agent closed stream before status byte");
        upstream.abort();
        return;
    }

    if status[0] != STATUS_OK {
        match recv_framed(&mut quic_recv).await {
            Ok(ControlMsg::TcpStreamError { error, .. }) => {
                warn!(port, %error, "agent could not connect to remote port");
            }
            Ok(other) => {
                warn!(port, ?other, "unexpected message after error status");
            }
            Err(e) => {
                error!(port, %e, "failed to read error from agent");
            }
        }
        // Anything the client already sent is discarded with the connection; it
        // was never delivered anywhere, because the agent never reached the
        // service. Cancelling releases the read half and closing the write half
        // lets the client observe the failure instead of waiting for a response.
        upstream.abort();
        let _ = tcp_write.shutdown().await;
        return;
    }

    debug!(port, "TCP tunnel established, starting bidirectional copy");

    // `join!` rather than `select!`: the two directions close independently, so
    // a client that half-closes after sending its request still receives the
    // response.
    let downstream = async {
        let copied = tokio::io::copy(&mut quic_recv, &mut tcp_write).await;
        // Shut the local write half down as soon as the remote side is done,
        // rather than leaving it to drop when this function returns. A client
        // that waits for EOF before closing its own side would otherwise be
        // waiting on a FIN that is waiting on it — the join below cannot
        // complete until the upstream copy sees the client close.
        let _ = tcp_write.shutdown().await;
        copied
    };
    let (up, down) = tokio::join!(upstream, downstream);

    match up {
        Ok(Err(e)) => debug!(port, %e, "host->agent copy ended"),
        Err(e) if !e.is_cancelled() => debug!(port, %e, "host->agent pump failed"),
        _ => {}
    }
    if let Err(e) = down {
        debug!(port, %e, "agent->host copy ended");
    }

    debug!(port, "TCP tunnel closed");
}

/// Serve one forwarding stream on the agent: read the init frame, connect to the
/// requested loopback port, then copy in both directions.
pub async fn serve_tcp_stream(mut quic_send: quinn::SendStream, mut quic_recv: quinn::RecvStream) {
    let init = match recv_framed(&mut quic_recv).await {
        Ok(msg) => msg,
        Err(e) => {
            warn!(%e, "failed to read TcpStreamInit from host");
            return;
        }
    };

    let port = match init {
        ControlMsg::TcpStreamInit { port } => port,
        other => {
            warn!(?other, "expected TcpStreamInit, got something else");
            return;
        }
    };

    debug!(port, "received TcpStreamInit, connecting to localhost");

    // Application bytes may already be queued behind the init frame. Nothing to
    // do about them here: the framed read above stopped at the frame boundary,
    // and QUIC flow control holds the remainder until the copy loop below.
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let tcp_stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            // Disable Nagle's algorithm for low-latency forwarding.
            let _ = stream.set_nodelay(true);
            if let Err(e) = quic_send.write_all(&[STATUS_OK]).await {
                error!(port, %e, "failed to send OK status");
                return;
            }
            stream
        }
        Err(e) => {
            warn!(port, %e, "failed to connect to local service");
            let _ = quic_send.write_all(&[STATUS_ERROR]).await;
            let err_msg = ControlMsg::TcpStreamError {
                port,
                error: e.to_string(),
            };
            let _ = send_framed(&mut quic_send, &err_msg).await;
            let _ = quic_send.finish();
            // The host may still be sending application bytes that now have
            // nowhere to go. Ask it to stop instead of letting them pile up
            // against our flow-control window. Sent after the diagnostic so the
            // host still gets a readable reason.
            let _ = quic_recv.stop(STOP_CONNECT_FAILED.into());
            return;
        }
    };

    debug!(
        port,
        "connected to local service, starting bidirectional copy"
    );

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let to_host = async {
        let copied = tokio::io::copy(&mut tcp_read, &mut quic_send).await;
        let _ = quic_send.finish();
        copied
    };
    let to_service = async {
        let copied = tokio::io::copy(&mut quic_recv, &mut tcp_write).await;
        // Same reasoning as on the host: the service must see the client's
        // half-close now, not when this task finishes. An echo-style service
        // will not close its own side until it does, and the join below waits
        // for exactly that.
        let _ = tcp_write.shutdown().await;
        copied
    };

    let (up, down) = tokio::join!(to_host, to_service);
    if let Err(e) = up {
        debug!(port, %e, "agent->host copy ended");
    }
    if let Err(e) = down {
        debug!(port, %e, "host->agent copy ended");
    }

    debug!(port, "TCP stream forwarding complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_bytes_are_distinct() {
        assert_ne!(STATUS_OK, STATUS_ERROR);
    }
}
