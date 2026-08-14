use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::Endpoint;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use agent::diff::PortEvent;
use agent::log_forward;
use agent::scan_loop::run_scan_loop;
use agent::scanner::DefaultScanner;
use common::session::{AgentSessionConfig, Identity};
use common::{Error, Result};
use protocol::{ControlMsg, PROTOCOL_VERSION};
use tunnel::{recv_framed as recv_msg, send_framed as send_msg, serve_tcp_stream};

/// How long to wait for the host to deliver the session config on stdin.
const CONFIG_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to keep accepting QUIC connections while waiting for the host.
///
/// Bounded so that an agent whose host went away exits instead of lingering as
/// an orphaned listener.
const ACCEPT_WINDOW: Duration = Duration::from_secs(120);

/// How long to wait for the host to prove it holds the session secret.
const SESSION_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Create the log forwarding layer that will pipe events to the host
    // over a QUIC unidirectional stream once the connection is established.
    let (fwd_layer, log_rx) = log_forward::forwarding_layer();

    // Determine log level from RUST_LOG env var. We use a static LevelFilter
    // instead of EnvFilter to avoid pulling in the regex engine (~133 KB .text).
    use tracing_subscriber::filter::LevelFilter;

    let level = match std::env::var("RUST_LOG").ok().as_deref() {
        Some("trace") => LevelFilter::TRACE,
        Some("debug") => LevelFilter::DEBUG,
        Some("warn") => LevelFilter::WARN,
        Some("error") => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    };

    // Initialize tracing: stderr for pre-QUIC output + forwarding layer.
    // Architecture Section 7.1: stdout is reserved for the handshake protocol.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(fwd_layer)
        .with(level)
        .init();

    if let Err(e) = run(log_rx).await {
        error!("agent exited with error: {e}");
        std::process::exit(1);
    }
}

async fn run(log_rx: tokio::sync::mpsc::Receiver<protocol::AgentLogEvent>) -> Result<()> {
    // 1. Read the session config the host delivered on stdin, inside the SSH
    //    channel. This carries the host's certificate, which we pin, plus the
    //    session secret it must later prove it holds. Without it we have no
    //    peer to trust, so we refuse to listen at all rather than accepting
    //    whoever shows up.
    let session = read_session_config().await?;

    // 2. Generate this session's own identity. The private key never leaves
    //    this process; only the certificate is published, over SSH.
    let identity = Identity::generate("port-linker-agent")?;

    // 3. Build a QUIC server that requires mutual TLS against the host's
    //    pinned certificate. A peer without the matching private key cannot
    //    complete the handshake, so an on-path attacker cannot impersonate
    //    the host and unauthenticated scanners get nothing.
    let rustls_config = common::session::server_tls_config(&identity, &session.client_cert_der)?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| Error::Security(format!("failed to build QUIC server crypto: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    // Enable QUIC datagrams for UDP forwarding.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(1_048_576));
    server_config.transport_config(Arc::new(transport));

    // 4. Bind on 0.0.0.0:0 to get a random port.
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind_addr).map_err(Error::Io)?;

    let local_addr = endpoint.local_addr().map_err(Error::Io)?;
    let port = local_addr.port();

    // 4b. Bind a TCP bridge listener for QUIC-over-TCP fallback.
    // This allows the host to tunnel QUIC datagrams over an SSH direct-tcpip
    // channel when UDP is blocked between host and agent.
    let bridge_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(Error::Io)?;
    let bridge_port = bridge_listener.local_addr().map_err(Error::Io)?.port();

    // 5. Print handshake info to stdout (and flush). This travels back to the
    //    host inside the SSH channel. AGENT_CERT is what the host pins; it is
    //    public, and the session secret is never echoed here.
    //
    //    Built as one string and written once. Rust's stdout is line-buffered, so
    //    a `writeln!` per line is a write syscall per line, and the handshake is
    //    then deliverable in pieces: a reader that stops as soon as it has the
    //    fields it wants closes the pipe, and our next line fails with EPIPE —
    //    fatal here, because stdout is how the host is told we exist. One write
    //    also means a host can never observe a half-handshake.
    {
        let handshake = format!(
            "AGENT_READY\nPORT={port}\nAGENT_CERT={}\nBRIDGE_PORT={bridge_port}\n",
            common::session::to_hex(identity.cert_der())
        );
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(handshake.as_bytes()).map_err(Error::Io)?;
        stdout.flush().map_err(Error::Io)?;
    }

    // Create a session-scoped tracing span so all subsequent logs are enriched
    // with the session_id (Architecture Section 7.2).
    let session_span = tracing::info_span!("session", session_id = %session.session_id);
    let _session_guard = session_span.enter();

    info!(port, bridge_port, "agent listening, waiting for connection");

    // Spawn the TCP bridge task.
    // Accepts TCP connections and proxies length-prefixed UDP datagrams
    // to/from the local QUIC endpoint.
    let quic_port = port;
    tokio::spawn(async move {
        loop {
            match bridge_listener.accept().await {
                Ok((tcp_stream, peer)) => {
                    info!(%peer, "TCP bridge: accepted connection");
                    tokio::spawn(run_tcp_bridge(tcp_stream, quic_port));
                }
                Err(e) => {
                    warn!(%e, "TCP bridge: accept failed");
                    break;
                }
            }
        }
    });

    // 6. Accept a mutually authenticated QUIC connection.
    let connection = accept_authenticated(&endpoint).await?;

    info!(
        remote = %connection.remote_address(),
        "accepted mutually authenticated QUIC connection"
    );

    // 7. Open a bidirectional stream (control stream).
    // The agent opens the stream because it sends the first message (Handshake).
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::QuicStream(format!("failed to open bi stream: {e}")))?;

    info!("control stream opened");

    // 8. Send Handshake and require the host to prove it holds the session
    //    secret before anything else happens on this connection. The peer is
    //    already TLS-authenticated; this additionally binds the connection to
    //    the SSH bootstrap that produced this agent.
    let handshake = ControlMsg::Handshake {
        protocol_version: PROTOCOL_VERSION,
        session_id: session.session_id.clone(),
    };
    send_msg(&mut send, &handshake).await?;
    info!("sent handshake, awaiting session authentication");

    authenticate_host(&mut recv, &session.session_secret).await?;
    info!("host authenticated for this session");

    // 8b. Open a dedicated QUIC unidirectional stream for log forwarding
    // (Architecture Section 7.1). Deliberately after authentication: agent logs
    // describe the target's internals and must not leak to an unauthenticated
    // peer.
    let log_send = connection
        .open_uni()
        .await
        .map_err(|e| Error::QuicStream(format!("failed to open log uni stream: {e}")))?;
    tokio::spawn(log_forward::drain_logs_to_quic(log_rx, log_send));
    info!("log forwarding stream opened");

    // 9. Start the background port scan loop.
    // Pass the QUIC port so the scanner excludes our own UDP endpoint.
    let (tx, mut rx) = mpsc::unbounded_channel::<PortEvent>();
    let scanner = DefaultScanner::new();
    tokio::spawn(run_scan_loop(scanner, tx, port));

    // Shared cache of UDP sockets for datagram forwarding (port -> socket).
    let udp_cache: Arc<RwLock<HashMap<u16, Arc<UdpSocket>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // 10. Main select loop: handle control messages, port events, and data streams.
    loop {
        tokio::select! {
            // Control stream messages from the host.
            msg_result = recv_msg(&mut recv) => {
                match msg_result {
                    Ok(msg) => match msg {
                        ControlMsg::EchoRequest { payload } => {
                            info!(len = payload.len(), "received echo request");
                            let response = ControlMsg::EchoResponse { payload };
                            send_msg(&mut send, &response).await?;
                        }
                        ControlMsg::Heartbeat => {
                            info!("received heartbeat, sending heartbeat back");
                            send_msg(&mut send, &ControlMsg::Heartbeat).await?;
                        }
                        other => {
                            info!(?other, "received unhandled message");
                        }
                    },
                    Err(e) => {
                        info!("control stream ended: {e}");
                        break;
                    }
                }
            }

            // Port scan events from the background scanner.
            Some(event) = rx.recv() => {
                match event {
                    PortEvent::Added(port, proto, process_name) => {
                        let msg = ControlMsg::PortAdded { port, proto, process_name };
                        send_msg(&mut send, &msg).await?;
                    }
                    PortEvent::Removed(port, proto) => {
                        let msg = ControlMsg::PortRemoved { port, proto };
                        send_msg(&mut send, &msg).await?;
                    }
                }
            }

            // Incoming bi-directional streams from the host (TCP forwarding).
            stream_result = connection.accept_bi() => {
                match stream_result {
                    Ok((stream_send, stream_recv)) => {
                        tokio::spawn(serve_tcp_stream(stream_send, stream_recv));
                    }
                    Err(e) => {
                        info!(%e, "failed to accept bi-stream (connection closing?)");
                        break;
                    }
                }
            }

            // Incoming QUIC datagrams from the host (UDP forwarding).
            datagram_result = connection.read_datagram() => {
                match datagram_result {
                    Ok(datagram) => {
                        let cache = udp_cache.clone();
                        tokio::spawn(handle_udp_datagram(datagram, cache));
                    }
                    Err(e) => {
                        debug!(%e, "datagram recv error");
                    }
                }
            }
        }
    }

    // Clean shutdown.
    endpoint.close(0u32.into(), b"done");
    info!("agent shutting down");
    Ok(())
}

// ---------------------------------------------------------------------------
// Session bootstrap
// ---------------------------------------------------------------------------

/// Read the session config the host wrote to our stdin over the SSH channel.
///
/// Reads until the config terminator so the host may keep the channel open.
/// A missing or malformed config is fatal: without the host's certificate we
/// have no way to tell the host apart from an attacker, and serving anyone
/// would expose every loopback service on this machine.
async fn read_session_config() -> Result<AgentSessionConfig> {
    let read = tokio::task::spawn_blocking(|| -> Result<String> {
        use std::io::BufRead;

        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut text = String::new();

        loop {
            let mut line = String::new();
            let bytes = handle.read_line(&mut line).map_err(Error::Io)?;
            if bytes == 0 {
                // EOF.
                break;
            }
            let is_terminator = line.trim() == "END_SESSION";
            text.push_str(&line);
            if is_terminator {
                break;
            }
        }

        Ok(text)
    });

    let text = match tokio::time::timeout(CONFIG_READ_TIMEOUT, read).await {
        Ok(join) => join.map_err(|e| Error::Security(format!("stdin reader failed: {e}")))??,
        Err(_) => {
            return Err(Error::Security(
                "timed out waiting for the session config on stdin".into(),
            ));
        }
    };

    if text.trim().is_empty() {
        return Err(Error::Security(
            "no session config on stdin; this agent must be launched by the \
             port-linker host over SSH, which supplies the pinned certificate \
             it will be reached with"
                .into(),
        ));
    }

    AgentSessionConfig::parse(&text)
}

/// Accept the first QUIC connection that completes the mutual-TLS handshake.
///
/// Handshake failures are expected and harmless — they are exactly what a
/// scanner or impersonator produces — so they are logged and skipped rather
/// than killing the agent, which would let anyone knock the tunnel over.
async fn accept_authenticated(endpoint: &Endpoint) -> Result<quinn::Connection> {
    let deadline = tokio::time::Instant::now() + ACCEPT_WINDOW;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::QuicConnection(
                "no authenticated connection within the accept window".into(),
            ));
        }

        let incoming = match tokio::time::timeout(remaining, endpoint.accept()).await {
            Ok(Some(incoming)) => incoming,
            Ok(None) => {
                return Err(Error::QuicConnection(
                    "endpoint closed before accepting".into(),
                ));
            }
            Err(_) => {
                return Err(Error::QuicConnection(
                    "no authenticated connection within the accept window".into(),
                ));
            }
        };

        let remote = incoming.remote_address();
        match incoming.await {
            Ok(connection) => return Ok(connection),
            Err(e) => {
                warn!(
                    %remote,
                    %e,
                    "rejected connection that failed mutual TLS authentication"
                );
            }
        }
    }
}

/// Require the host's first control message to prove knowledge of the session
/// secret delivered over SSH.
async fn authenticate_host(recv: &mut quinn::RecvStream, expected_secret: &str) -> Result<()> {
    let msg = match tokio::time::timeout(SESSION_AUTH_TIMEOUT, recv_msg(recv)).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(Error::Security(
                "host did not authenticate within the timeout".into(),
            ));
        }
    };

    match msg {
        ControlMsg::SessionAuth { session_secret } => {
            if common::session::secrets_match(&session_secret, expected_secret) {
                Ok(())
            } else {
                Err(Error::Security(
                    "host presented an incorrect session secret".into(),
                ))
            }
        }
        other => Err(Error::Security(format!(
            "expected SessionAuth as the first host message, got {other:?}"
        ))),
    }
}

/// Handle a single incoming UDP datagram, forwarding it to the local service.
/// Uses a shared socket cache to avoid creating a new socket per datagram.
async fn handle_udp_datagram(datagram: Bytes, cache: Arc<RwLock<HashMap<u16, Arc<UdpSocket>>>>) {
    let packet = match protocol::decode::<protocol::Packet>(&datagram) {
        Ok(p) => p,
        Err(e) => {
            debug!(%e, "failed to decode incoming datagram");
            return;
        }
    };

    match packet {
        protocol::Packet::UdpData { port, data } => {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();

            // Try to get cached socket first (fast path).
            let socket = {
                let read_guard = cache.read().await;
                read_guard.get(&port).cloned()
            };

            let socket = match socket {
                Some(s) => s,
                None => {
                    // Slow path: create and cache a new socket.
                    let new_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            debug!(port, %e, "failed to bind UDP socket for forwarding");
                            return;
                        }
                    };
                    let mut write_guard = cache.write().await;
                    write_guard
                        .entry(port)
                        .or_insert_with(|| new_socket.clone());
                    new_socket
                }
            };

            if let Err(e) = socket.send_to(&data, addr).await {
                debug!(port, %e, "failed to forward UDP datagram");
            }
        }
        _ => {
            debug!("received non-UdpData packet as datagram, ignoring");
        }
    }
}

// ---------------------------------------------------------------------------
// TCP bridge for QUIC-over-TCP fallback
// ---------------------------------------------------------------------------

/// Run the TCP bridge: proxy length-prefixed UDP datagrams between a TCP
/// stream and the local QUIC endpoint via a local UDP socket.
///
/// Framing: 2-byte BE length prefix + raw datagram payload per frame.
async fn run_tcp_bridge(tcp_stream: tokio::net::TcpStream, quic_port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = tcp_stream.set_nodelay(true);
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Create a local UDP socket to talk to the QUIC endpoint.
    let udp = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(%e, "TCP bridge: failed to bind local UDP socket");
            return;
        }
    };

    let quic_addr: SocketAddr = ([127, 0, 0, 1], quic_port).into();
    if let Err(e) = udp.connect(quic_addr).await {
        error!(%e, "TCP bridge: failed to connect UDP to QUIC endpoint");
        return;
    }

    let udp2 = udp.clone();

    // TCP -> UDP: read length-prefixed datagrams from TCP, send to QUIC endpoint.
    let tcp_to_udp = async move {
        let mut header = [0u8; 2];
        let mut buf = vec![0u8; 65535];

        loop {
            if let Err(e) = tcp_read.read_exact(&mut header).await {
                debug!("TCP bridge: TCP read closed: {e}");
                break;
            }
            let len = u16::from_be_bytes(header) as usize;
            if len == 0 || len > 65535 {
                warn!(len, "TCP bridge: invalid frame length");
                break;
            }
            if let Err(e) = tcp_read.read_exact(&mut buf[..len]).await {
                debug!("TCP bridge: TCP read payload error: {e}");
                break;
            }
            if let Err(e) = udp.send(&buf[..len]).await {
                debug!("TCP bridge: UDP send error: {e}");
                break;
            }
        }
    };

    // UDP -> TCP: read datagrams from QUIC endpoint, send length-prefixed to TCP.
    let udp_to_tcp = async move {
        let mut buf = vec![0u8; 65535];

        loop {
            match udp2.recv(&mut buf).await {
                Ok(len) if len > 65535 => {
                    warn!(len, "TCP bridge: dropping oversized UDP datagram");
                    continue;
                }
                Ok(len) => {
                    let header = (len as u16).to_be_bytes();
                    if let Err(e) = tcp_write.write_all(&header).await {
                        debug!("TCP bridge: TCP write header error: {e}");
                        break;
                    }
                    if let Err(e) = tcp_write.write_all(&buf[..len]).await {
                        debug!("TCP bridge: TCP write payload error: {e}");
                        break;
                    }
                    if let Err(e) = tcp_write.flush().await {
                        debug!("TCP bridge: TCP flush error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("TCP bridge: UDP recv error: {e}");
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = tcp_to_udp => {}
        _ = udp_to_tcp => {}
    }

    debug!("TCP bridge session ended");
}
