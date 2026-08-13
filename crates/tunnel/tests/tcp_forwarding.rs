//! Behaviour of the TCP forwarding data plane, over a real QUIC connection.
//!
//! Organised by what is being defended:
//!
//! * **Data integrity** — the optimistic setup puts application bytes on the
//!   wire behind the init frame, so ordering and framing boundaries are the first
//!   thing that could break.
//! * **Server-speaks-first** — protocols where nothing is sent until the service
//!   greets the client gain nothing from the optimisation and must not regress.
//! * **Half-close** — a client that shuts down its write side after a request
//!   must still receive the response, which is why the host joins the two copy
//!   directions instead of racing them.
//! * **Failure paths** — a client whose bytes were already in flight when the
//!   agent failed to connect must observe the failure rather than hang. These are
//!   the cases the optimisation newly makes reachable.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    Loopback, TargetService, finish, pattern, read_exact, read_to_end, read_until_closed, tcp_pair,
    unused_port, within,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunnel::{STATUS_ERROR, STATUS_OK, forward_tcp_connection};

// ---------------------------------------------------------------------------
// Data integrity
// ---------------------------------------------------------------------------

/// The base case: a request goes to the service and the response comes back.
#[tokio::test(flavor = "multi_thread")]
async fn request_and_response_round_trip() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("round trip", async {
        client.write_all(b"hello").await.expect("write request");
        let echoed = read_exact(&mut client, 5).await;
        assert_eq!(&echoed, b"hello", "response mismatch");
    })
    .await;

    drop(client);
    finish("round trip teardown", forward).await;
}

/// Bulk data in both directions must be byte-exact. The forwarding path splits
/// and rejoins the stream, so a dropped or duplicated chunk would show here.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_transfer_is_byte_exact() {
    const SIZE: usize = 1 << 20; // 1 MiB, comfortably past the stream window

    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;
    let (client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    let payload = pattern(SIZE);
    let (mut read_half, mut write_half) = client.into_split();

    // Write and read concurrently: 1 MiB will not fit in the socket buffers,
    // so writing all of it before reading any would deadlock.
    let expected = payload.clone();
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; SIZE];
        read_half
            .read_exact(&mut received)
            .await
            .expect("read echoed payload");
        assert_eq!(received, expected, "echoed bytes differ");
    });

    within("bulk transfer", async {
        write_half.write_all(&payload).await.expect("write payload");
        write_half.shutdown().await.expect("shutdown write half");
        reader.await.expect("reader task");
    })
    .await;

    finish("bulk transfer teardown", forward).await;
}

/// Bytes written before and after the agent's status byte would have arrived must
/// arrive once, in order.
///
/// This is the property the optimistic setup rests on: the init frame is consumed
/// by a length-prefixed read, and everything after it is opaque application data.
/// A framing mistake would splice the two together or reorder them.
#[tokio::test(flavor = "multi_thread")]
async fn early_and_late_bytes_stay_in_order() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("ordered early and late bytes", async {
        // Written immediately: rides in the same flight as the init frame.
        client.write_all(b"AAAA").await.expect("write early bytes");
        // Written after the setup exchange has certainly completed.
        tokio::time::sleep(Duration::from_millis(150)).await;
        client.write_all(b"BBBB").await.expect("write late bytes");

        let echoed = read_exact(&mut client, 8).await;
        assert_eq!(
            &echoed, b"AAAABBBB",
            "early bytes must precede late bytes, exactly once each"
        );
    })
    .await;

    drop(client);
    finish("early and late bytes stay in order teardown", forward).await;
}

/// Concurrent connections must not cross-contaminate: each QUIC stream carries
/// one TCP connection.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_connections_stay_isolated() {
    const CONNECTIONS: usize = 24;

    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;

    let mut workers = Vec::with_capacity(CONNECTIONS);
    for index in 0..CONNECTIONS {
        let host = loopback.host();
        let port = service.port();
        workers.push(tokio::spawn(async move {
            let (mut client, accepted) = tcp_pair().await;
            let forward = tokio::spawn(forward_tcp_connection(host, accepted, port));

            // A distinct payload per connection, so a mix-up is visible.
            let message = format!("connection-{index:04}");
            client
                .write_all(message.as_bytes())
                .await
                .expect("write request");
            let echoed = read_exact(&mut client, message.len()).await;
            assert_eq!(
                String::from_utf8_lossy(&echoed),
                message,
                "connection {index} received another connection's bytes"
            );

            drop(client);
            finish("concurrent connections stay isolated teardown", forward).await;
        }));
    }

    within("concurrent connections", async {
        for worker in workers {
            worker.await.expect("connection worker");
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// Server-speaks-first protocols
// ---------------------------------------------------------------------------

/// A service that greets on accept must reach a client that has sent nothing.
///
/// These protocols gain nothing from the optimistic setup — there are no early
/// bytes to carry — so the point is that they are not broken by it. If the host
/// gated the downstream copy on having sent something, this would hang.
#[tokio::test(flavor = "multi_thread")]
async fn service_banner_reaches_a_silent_client() {
    const BANNER: &[u8] = b"220 service ready\r\n";

    let loopback = Loopback::with_agent().await;
    let service = TargetService::banner_then_echo(BANNER).await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("banner delivery", async {
        let banner = read_exact(&mut client, BANNER.len()).await;
        assert_eq!(&banner, BANNER, "banner mismatch");
    })
    .await;

    drop(client);
    finish("banner teardown", forward).await;
}

/// A greeting followed by a request/response exchange must not interleave: the
/// banner arrives whole, then the echo.
#[tokio::test(flavor = "multi_thread")]
async fn banner_precedes_the_echoed_request() {
    const BANNER: &[u8] = b"+OK ready\r\n";

    let loopback = Loopback::with_agent().await;
    let service = TargetService::banner_then_echo(BANNER).await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("banner then echo", async {
        // Sent immediately, before the banner can have arrived: the client's
        // bytes and the service's greeting cross on the wire.
        client.write_all(b"PING").await.expect("write request");

        let mut received = vec![0u8; BANNER.len() + 4];
        client
            .read_exact(&mut received)
            .await
            .expect("read banner and echo");
        assert_eq!(
            &received[..BANNER.len()],
            BANNER,
            "banner must arrive before the echo"
        );
        assert_eq!(&received[BANNER.len()..], b"PING", "echo mismatch");
    })
    .await;

    drop(client);
    finish("banner precedes the echoed request teardown", forward).await;
}

// ---------------------------------------------------------------------------
// Half-close
// ---------------------------------------------------------------------------

/// A client that half-closes after its request must still get the response.
///
/// This is why the host joins the two directions rather than selecting on them:
/// `select!` would tear the stream down as soon as the upstream copy finished at
/// EOF, losing the reply. The shape of an HTTP/1.0 request.
#[tokio::test(flavor = "multi_thread")]
async fn half_closed_client_still_receives_the_response() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;
    let (client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    let (mut read_half, mut write_half) = client.into_split();

    within("half-close", async {
        write_half.write_all(b"GET /\r\n").await.expect("write");
        write_half.shutdown().await.expect("half-close");

        let mut received = vec![0u8; 7];
        read_half
            .read_exact(&mut received)
            .await
            .expect("response after half-close");
        assert_eq!(&received, b"GET /\r\n", "response mismatch");
    })
    .await;

    finish("half-close teardown", forward).await;
}

/// When the service closes its side, the client must see EOF rather than hang.
///
/// Regression test for a deadlock: both copy directions relied on the write half
/// being dropped when the forwarding function returned, but the function could
/// not return until the *other* direction finished, and that direction was
/// waiting for the peer to close — which required the FIN that was never sent.
/// Any protocol that ends a response by closing (HTTP/1.0, `Connection: close`)
/// hung on the client side. Both ends now shut the write half down as soon as
/// their copy completes.
#[tokio::test(flavor = "multi_thread")]
async fn service_close_is_propagated_to_the_client() {
    let request = b"query";
    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo_once_then_close(request.len()).await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("service close propagates", async {
        client.write_all(request).await.expect("write request");
        let all = read_to_end(&mut client).await;
        assert_eq!(&all, request, "expected the echo, then EOF");
    })
    .await;

    // The connection is now half-open: the service is finished, but the client
    // still holds its write side and could legitimately send more. The tunnel
    // keeps it alive for exactly that reason — closing the client is what should
    // retire the forward.
    drop(client);
    finish("service close teardown", forward).await;
}

/// A client that connects and closes without sending anything must not wedge the
/// forwarder — under optimistic setup the upstream pump starts before the agent
/// has confirmed, so it sees EOF immediately.
#[tokio::test(flavor = "multi_thread")]
async fn client_that_sends_nothing_and_closes_is_clean() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::echo().await;
    let (client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    drop(client);

    within("immediate close", async {
        forward.await.expect("forwarder finished cleanly");
    })
    .await;
}

/// A service that closes on accept, without reading or writing, must leave the
/// client with EOF rather than an indefinite wait for a response.
#[tokio::test(flavor = "multi_thread")]
async fn service_that_closes_immediately_yields_no_data() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::immediate_close().await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    within("immediate service close", async {
        // The write may or may not succeed depending on timing; what matters is
        // that the client is not left waiting for a response forever.
        let _ = client.write_all(b"anything").await;
        let received = read_until_closed(&mut client).await;
        assert!(
            received.is_empty(),
            "a service that never wrote must produce no bytes, got {received:?}"
        );
    })
    .await;

    // As above, the client's write side is still open, so the forward is
    // legitimately still live until the client lets go.
    drop(client);
    finish("immediate service close teardown", forward).await;
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

/// Nothing listening on the target port: the client's socket must be closed, not
/// left open.
#[tokio::test(flavor = "multi_thread")]
async fn connection_refused_closes_the_local_socket() {
    let loopback = Loopback::with_agent().await;
    let port = unused_port().await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, port));

    within("refused connection", async {
        let received = read_until_closed(&mut client).await;
        assert!(
            received.is_empty(),
            "expected no data on a refused connection"
        );
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// The case the optimistic setup newly makes reachable: the client's bytes are
/// already on the wire when the agent reports it could not connect.
///
/// Those bytes are discarded — the connection failed, so nothing was delivered
/// anywhere — and the client must observe the failure promptly.
#[tokio::test(flavor = "multi_thread")]
async fn refused_connection_after_client_already_sent_data() {
    let loopback = Loopback::with_agent().await;
    let port = unused_port().await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, port));

    within("refused after send", async {
        client
            .write_all(b"request that will never be delivered")
            .await
            .expect("write before failure is accepted locally");

        let received = read_until_closed(&mut client).await;
        assert!(
            received.is_empty(),
            "expected no response from a refused connection, got {received:?}"
        );
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// A large body sent to a port with nothing listening must not deadlock.
///
/// The host is pumping into a stream the agent will never read. Without the
/// agent's `STOP_SENDING`, those bytes would pile up against the flow-control
/// window while the host waits, and neither side would make progress.
#[tokio::test(flavor = "multi_thread")]
async fn large_pending_write_to_a_refused_port_does_not_deadlock() {
    const SIZE: usize = 4 << 20; // 4 MiB, several times the stream window

    let loopback = Loopback::with_agent().await;
    let port = unused_port().await;
    let (client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, port));

    let (mut read_half, mut write_half) = client.into_split();
    // The write is expected to fail partway once the connection is torn down;
    // only the absence of a hang is asserted.
    let writer = tokio::spawn(async move {
        let payload = pattern(SIZE);
        let _ = write_half.write_all(&payload).await;
    });

    within("large write to refused port", async {
        let mut sink = Vec::new();
        let _ = read_half.read_to_end(&mut sink).await;
        assert!(sink.is_empty(), "a refused connection returned data");
        forward.await.expect("forwarder finished");
    })
    .await;

    writer.abort();
}

/// An agent that accepts the stream and then says nothing must not hold the
/// client forever once the session is gone.
#[tokio::test(flavor = "multi_thread")]
async fn silent_agent_releases_the_client_when_the_session_drops() {
    let loopback = Loopback::with_handler(Arc::new(|_send, recv| {
        Box::pin(async move {
            // Hold the stream open and never reply.
            let _held = recv;
            std::future::pending::<()>().await;
        })
    }))
    .await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, 9999));

    // Give the stream time to reach the silent handler, then lose the session.
    tokio::time::sleep(Duration::from_millis(100)).await;
    loopback.close();

    within("silent agent", async {
        let received = read_until_closed(&mut client).await;
        assert!(received.is_empty(), "silent agent produced data");
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// A status byte that is neither OK nor the documented error code must be treated
/// as a failure, not as data.
///
/// Reading it as the first byte of the response would corrupt the stream, which
/// is far worse than closing the connection.
#[tokio::test(flavor = "multi_thread")]
async fn unrecognised_status_byte_is_treated_as_failure() {
    let loopback = Loopback::with_handler(Arc::new(|mut send, recv| {
        Box::pin(async move {
            let mut recv = recv;
            let _ = tunnel::recv_framed(&mut recv).await;
            // Neither STATUS_OK nor STATUS_ERROR.
            let _ = send.write_all(&[0x7F]).await;
            let _ = send.finish();
            std::future::pending::<()>().await;
        })
    }))
    .await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, 9999));

    within("unrecognised status", async {
        let received = read_until_closed(&mut client).await;
        assert!(
            received.is_empty(),
            "an unrecognised status byte must not be forwarded as data, got {received:?}"
        );
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// An error status with no diagnostic frame behind it must still close cleanly.
///
/// The host reads the error frame only to log it; a truncated one is a logging
/// problem, not a reason to hang or panic.
#[tokio::test(flavor = "multi_thread")]
async fn error_status_without_a_diagnostic_frame_is_survivable() {
    let loopback = Loopback::with_handler(Arc::new(|mut send, recv| {
        Box::pin(async move {
            let mut recv = recv;
            let _ = tunnel::recv_framed(&mut recv).await;
            let _ = send.write_all(&[STATUS_ERROR]).await;
            // Finish without the TcpStreamError the host expects.
            let _ = send.finish();
        })
    }))
    .await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, 9999));

    within("truncated error frame", async {
        let received = read_until_closed(&mut client).await;
        assert!(received.is_empty(), "expected no data");
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// An agent that resets the stream must end the forward, not strand the client.
#[tokio::test(flavor = "multi_thread")]
async fn stream_reset_by_the_agent_ends_the_forward() {
    let loopback = Loopback::with_handler(Arc::new(|mut send, recv| {
        Box::pin(async move {
            let mut recv = recv;
            let _ = tunnel::recv_framed(&mut recv).await;
            let _ = send.reset(42u32.into());
            let _ = recv.stop(42u32.into());
        })
    }))
    .await;
    let (mut client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(loopback.host(), accepted, 9999));

    within("agent reset", async {
        let mut sink = Vec::new();
        // A reset surfaces as an error or as EOF depending on timing; both mean
        // the client is no longer waiting.
        let _ = client.read_to_end(&mut sink).await;
        assert!(sink.is_empty(), "reset stream produced data");
        forward.await.expect("forwarder finished");
    })
    .await;
}

/// Losing the session mid-transfer must end both copy directions.
#[tokio::test(flavor = "multi_thread")]
async fn session_loss_mid_transfer_ends_the_forward() {
    let loopback = Loopback::with_agent().await;
    let service = TargetService::sink().await;
    let (client, accepted) = tcp_pair().await;

    let forward = tokio::spawn(forward_tcp_connection(
        loopback.host(),
        accepted,
        service.port(),
    ));

    let (mut read_half, mut write_half) = client.into_split();
    let writer = tokio::spawn(async move {
        let chunk = pattern(64 * 1024);
        loop {
            if write_half.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    loopback.close();

    within("session loss", async {
        let mut sink = Vec::new();
        let _ = read_half.read_to_end(&mut sink).await;
        forward.await.expect("forwarder finished");
    })
    .await;

    writer.abort();
}

// ---------------------------------------------------------------------------
// The agent half in isolation
// ---------------------------------------------------------------------------

/// The agent must reject a stream that opens with something other than a valid
/// init frame, without connecting anywhere.
#[tokio::test(flavor = "multi_thread")]
async fn agent_rejects_a_stream_that_does_not_open_with_an_init_frame() {
    let loopback = Loopback::with_agent().await;

    // A length prefix claiming four bytes, followed by four bytes of junk.
    let (mut send, mut recv) = loopback.host().open_bi().await.expect("open stream");
    send.write_all(&4u32.to_be_bytes())
        .await
        .expect("write len");
    send.write_all(b"junk").await.expect("write junk");
    let _ = send.finish();

    within("garbage init frame", async {
        let mut response = Vec::new();
        let _ = recv.read_to_end(64).await.map(|b| response = b);
        assert!(
            response.is_empty(),
            "agent replied to an undecodable init frame: {response:?}"
        );
    })
    .await;
}

/// A length prefix beyond the frame bound must be refused rather than used to
/// size an allocation.
#[tokio::test(flavor = "multi_thread")]
async fn agent_rejects_an_oversized_frame_length() {
    let loopback = Loopback::with_agent().await;

    let (mut send, mut recv) = loopback.host().open_bi().await.expect("open stream");
    send.write_all(&(tunnel::MAX_FRAME_SIZE + 1).to_be_bytes())
        .await
        .expect("write oversized len");
    let _ = send.finish();

    within("oversized frame", async {
        let mut response = Vec::new();
        let _ = recv.read_to_end(64).await.map(|b| response = b);
        assert!(
            response.is_empty(),
            "agent accepted an oversized frame length"
        );
    })
    .await;
}

/// A well-formed frame carrying the wrong message must not cause a connection.
#[tokio::test(flavor = "multi_thread")]
async fn agent_rejects_a_frame_that_is_not_tcp_stream_init() {
    let loopback = Loopback::with_agent().await;

    let (mut send, mut recv) = loopback.host().open_bi().await.expect("open stream");
    tunnel::send_framed(&mut send, &protocol::ControlMsg::Heartbeat)
        .await
        .expect("send heartbeat");
    let _ = send.finish();

    within("wrong message type", async {
        let mut response = Vec::new();
        let _ = recv.read_to_end(64).await.map(|b| response = b);
        assert!(
            response.is_empty(),
            "agent replied to a non-init message: {response:?}"
        );
    })
    .await;
}

/// The agent's success path must put exactly one status byte ahead of the
/// service's bytes — the host reads precisely one, so an extra or missing byte
/// would shift the whole response.
#[tokio::test(flavor = "multi_thread")]
async fn agent_prefixes_exactly_one_status_byte() {
    const BANNER: &[u8] = b"BANNER";

    let loopback = Loopback::with_agent().await;
    let service = TargetService::banner_then_echo(BANNER).await;

    let (mut send, mut recv) = loopback.host().open_bi().await.expect("open stream");
    tunnel::send_framed(
        &mut send,
        &protocol::ControlMsg::TcpStreamInit {
            port: service.port(),
        },
    )
    .await
    .expect("send init");

    within("status byte framing", async {
        let mut framed = vec![0u8; 1 + BANNER.len()];
        recv.read_exact(&mut framed)
            .await
            .expect("read status and banner");
        assert_eq!(framed[0], STATUS_OK, "first byte must be the status byte");
        assert_eq!(
            &framed[1..],
            BANNER,
            "the service's bytes must follow the single status byte"
        );
    })
    .await;
}

/// On failure the agent must send the error status *and* a decodable
/// `TcpStreamError` naming the port, since that string is what the user sees.
#[tokio::test(flavor = "multi_thread")]
async fn agent_reports_a_diagnostic_on_connect_failure() {
    let loopback = Loopback::with_agent().await;
    let port = unused_port().await;

    let (mut send, mut recv) = loopback.host().open_bi().await.expect("open stream");
    tunnel::send_framed(&mut send, &protocol::ControlMsg::TcpStreamInit { port })
        .await
        .expect("send init");

    within("connect failure diagnostic", async {
        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await.expect("read status");
        assert_eq!(status[0], STATUS_ERROR, "expected the error status");

        let message = tunnel::recv_framed(&mut recv)
            .await
            .expect("read error frame");
        match message {
            protocol::ControlMsg::TcpStreamError {
                port: reported,
                error,
            } => {
                assert_eq!(reported, port, "error must name the requested port");
                assert!(
                    !error.is_empty(),
                    "error string must carry something the user can read"
                );
            }
            other => panic!("expected TcpStreamError, got {other:?}"),
        }
    })
    .await;
}
