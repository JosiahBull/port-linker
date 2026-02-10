use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::Endpoint;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use agent::diff::PortEvent;
use agent::log_forward;
use agent::scan_loop::run_scan_loop;
use agent::scanner::DefaultScanner;
use common::{Error, Result};
use protocol::{ControlMsg, PROTOCOL_VERSION};

/// Maximum allowed frame size: 1 MB.
const MAX_FRAME_SIZE: u32 = 1_048_576;

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
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr),
        )
        .with(fwd_layer)
        .with(level)
        .init();

    if let Err(e) = run(log_rx).await {
        error!("agent exited with error: {e}");
        std::process::exit(1);
    }
}

async fn run(log_rx: tokio::sync::mpsc::Receiver<protocol::AgentLogEvent>) -> Result<()> {
    // 1. Generate a self-signed TLS certificate.
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| Error::Protocol(format!("failed to generate self-signed cert: {e}")))?;

    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(certified_key.signing_key.serialize_der())
        .map_err(|e| Error::Protocol(format!("failed to parse private key DER: {e}")))?;

    // 2. Build quinn server config with the self-signed cert.
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der)
        .map_err(|e| Error::Protocol(format!("failed to create server config: {e}")))?;

    // Enable QUIC datagrams for UDP forwarding.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(1_048_576));
    server_config.transport_config(Arc::new(transport));

    // 3. Bind on 0.0.0.0:0 to get a random port.
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(Error::Io)?;

    let local_addr = endpoint
        .local_addr()
        .map_err(Error::Io)?;
    let port = local_addr.port();

    // 4. Generate a one-time connection token.
    // The token doubles as a session ID for log correlation (Architecture Section 7.2).
    let token = common::generate_token();

    // 5. Print handshake info to stdout (and flush).
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "AGENT_READY").map_err(Error::Io)?;
        writeln!(stdout, "PORT={port}").map_err(Error::Io)?;
        writeln!(stdout, "TOKEN={token}").map_err(Error::Io)?;
        stdout.flush().map_err(Error::Io)?;
    }

    // Create a session-scoped tracing span so all subsequent logs are enriched
    // with the session_id (Architecture Section 7.2).
    let session_span = tracing::info_span!("session", session_id = %token);
    let _session_guard = session_span.enter();

    info!(port, "agent listening, waiting for connection");

    // 6. Accept one QUIC connection.
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| Error::QuicConnection("endpoint closed before accepting".into()))?;

    let connection = incoming
        .await
        .map_err(|e| Error::QuicConnection(format!("failed to accept connection: {e}")))?;

    info!(
        remote = %connection.remote_address(),
        "accepted QUIC connection"
    );

    // 7. Open a bidirectional stream (control stream).
    // The agent opens the stream because it sends the first message (Handshake).
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::QuicStream(format!("failed to open bi stream: {e}")))?;

    info!("control stream opened");

    // 7b. Open a dedicated QUIC unidirectional stream for log forwarding
    // (Architecture Section 7.1).
    let log_send = connection
        .open_uni()
        .await
        .map_err(|e| Error::QuicStream(format!("failed to open log uni stream: {e}")))?;
    tokio::spawn(log_forward::drain_logs_to_quic(log_rx, log_send));
    info!("log forwarding stream opened");

    // 8. Send Handshake message.
    let handshake = ControlMsg::Handshake {
        protocol_version: PROTOCOL_VERSION,
        token,
    };
    send_msg(&mut send, &handshake).await?;
    info!("sent handshake");

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
                    PortEvent::Added(port, proto) => {
                        let msg = ControlMsg::PortAdded { port, proto };
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
                        tokio::spawn(handle_tcp_stream(stream_send, stream_recv));
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

/// Handle a TCP forwarding request on a new QUIC bidirectional stream.
///
/// Protocol:
/// 1. Read framed `TcpStreamInit { port }` from host
/// 2. Connect to `localhost:port`
/// 3. Send 1-byte status: 0x00 = OK, 0x01 = error
/// 4. On error: send framed `TcpStreamError`, close stream
/// 5. On success: bidirectional raw byte copy
async fn handle_tcp_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
) {
    // Read the TcpStreamInit message.
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

    // Connect to the local service.
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let tcp_stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => {
            // Disable Nagle's algorithm for low-latency forwarding.
            let _ = s.set_nodelay(true);
            // Send success status.
            if let Err(e) = quic_send.write_all(&[0x00]).await {
                error!(port, %e, "failed to send OK status");
                return;
            }
            s
        }
        Err(e) => {
            // Send error status + TcpStreamError.
            warn!(port, %e, "failed to connect to local service");
            let _ = quic_send.write_all(&[0x01]).await;
            let err_msg = ControlMsg::TcpStreamError {
                port,
                error: e.to_string(),
            };
            let _ = send_framed(&mut quic_send, &err_msg).await;
            let _ = quic_send.finish();
            return;
        }
    };

    debug!(port, "connected to local service, starting bidirectional copy");

    // Bidirectional copy - use join to respect TCP half-close semantics.
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let agent_to_host = async {
        let r = tokio::io::copy(&mut tcp_read, &mut quic_send).await;
        let _ = quic_send.finish();
        r
    };
    let host_to_agent = tokio::io::copy(&mut quic_recv, &mut tcp_write);

    let (r1, r2) = tokio::join!(agent_to_host, host_to_agent);
    if let Err(e) = r1 {
        debug!(port, %e, "agent->host copy ended");
    }
    if let Err(e) = r2 {
        debug!(port, %e, "host->agent copy ended");
    }

    debug!(port, "TCP stream forwarding complete");
}

/// Handle a single incoming UDP datagram, forwarding it to the local service.
/// Uses a shared socket cache to avoid creating a new socket per datagram.
async fn handle_udp_datagram(
    datagram: Bytes,
    cache: Arc<RwLock<HashMap<u16, Arc<UdpSocket>>>>,
) {
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
                    write_guard.entry(port).or_insert_with(|| new_socket.clone());
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
// Framed message helpers
// ---------------------------------------------------------------------------

/// Send a length-prefixed, rkyv-encoded control message on a QUIC stream.
async fn send_msg(
    send: &mut quinn::SendStream,
    msg: &ControlMsg,
) -> Result<()> {
    let payload: Bytes = protocol::encode(msg)
        .map_err(|e| Error::Codec(format!("encode error: {e}")))?;

    let len = payload.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::QuicStream(format!("failed to write frame length: {e}")))?;

    send.write_all(&payload)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to write frame payload: {e}")))?;

    Ok(())
}

/// Receive a length-prefixed, rkyv-encoded control message from a QUIC stream.
async fn recv_msg(
    recv: &mut quinn::RecvStream,
) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to read frame length: {e}")))?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to read frame payload: {e}")))?;

    let msg: ControlMsg = protocol::decode(&payload)
        .map_err(|e| Error::Codec(format!("decode error: {e}")))?;

    Ok(msg)
}

/// Send a framed message (used on per-stream TCP forwarding channels).
async fn send_framed(
    send: &mut quinn::SendStream,
    msg: &ControlMsg,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = protocol::encode(msg)?;
    let len = payload.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&payload).await?;
    Ok(())
}

/// Receive a framed message (used on per-stream TCP forwarding channels).
async fn recv_framed(
    recv: &mut quinn::RecvStream,
) -> std::result::Result<ControlMsg, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err("frame too large".into());
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await?;
    let msg = protocol::decode::<ControlMsg>(&buf)?;
    Ok(msg)
}
