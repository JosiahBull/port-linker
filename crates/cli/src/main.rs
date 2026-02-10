mod binding_manager;
mod bootstrap;
mod logging;
mod notifications;
mod ssh;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::{debug, error, info, warn};

use binding_manager::{BindingManager, ConflictPolicy};
use common::{Error, Result};
use protocol::{ControlMsg, PROTOCOL_VERSION};
use ssh::HostKeyPolicy;

/// Maximum allowed frame size (1 MB).
const MAX_FRAME_SIZE: u32 = 1_048_576;

/// Maximum number of Phoenix Agent restart attempts before giving up.
const MAX_RESTART_ATTEMPTS: u32 = 5;

/// Delay between restart attempts (seconds).
const RESTART_DELAY_SECS: u64 = 3;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "port-linker", about = "Host-side CLI for port-linker")]
struct Args {
    /// Remote host to connect to via SSH (e.g. "user@host" or "host").
    /// The agent will be deployed and started automatically.
    #[arg(long, group = "target")]
    remote: Option<String>,

    /// Agent QUIC address to connect to directly (e.g. "127.0.0.1:12345").
    /// Use this for manual mode when the agent is already running.
    #[arg(long, group = "target")]
    agent: Option<SocketAddr>,

    /// Run the echo test and exit immediately (skip the receive loop)
    #[arg(long, default_value_t = false)]
    echo_only: bool,

    /// Maximum number of forwarded ports (FD safety limit)
    #[arg(long)]
    fd_limit: Option<usize>,

    /// How to handle local port conflicts: interactive, auto-skip, or auto-kill
    #[arg(long, value_enum, default_value_t = ConflictPolicy::Interactive)]
    conflict_resolution: ConflictPolicy,

    /// SSH host key verification policy
    #[arg(long, value_enum, default_value_t = HostKeyPolicy::AcceptNew)]
    ssh_host_key_verification: HostKeyPolicy,

    /// Path to a custom agent binary to transfer (bypasses embedded binaries and caching)
    #[arg(long)]
    agent_binary: Option<std::path::PathBuf>,

    /// Enable desktop notifications for port events
    #[arg(long, default_value_t = true)]
    notifications: bool,

    /// Enable notification sounds
    #[arg(long, default_value_t = true)]
    notification_sound: bool,
}

// ---------------------------------------------------------------------------
// TLS: skip server certificate verification (self-signed certs)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Framed message helpers (4-byte big-endian length prefix)
// ---------------------------------------------------------------------------

/// Send a `ControlMsg` with a 4-byte big-endian length prefix.
async fn send_msg(send: &mut quinn::SendStream, msg: &ControlMsg) -> Result<()> {
    let payload = protocol::encode(msg).map_err(|e| Error::Codec(e.to_string()))?;
    let len = payload.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::QuicStream(e.to_string()))?;
    send.write_all(&payload)
        .await
        .map_err(|e| Error::QuicStream(e.to_string()))?;
    Ok(())
}

/// Receive a length-prefixed `ControlMsg` from the stream.
async fn recv_msg(recv: &mut quinn::RecvStream) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::QuicStream(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| Error::QuicStream(e.to_string()))?;

    protocol::decode::<ControlMsg>(&buf).map_err(|e| Error::Codec(e.to_string()))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls before anything else.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();

    // Initialise tracing: file-based logging + optional stderr.
    // Architecture Section 7.2: logs are written to a rolling file at
    // ~/.local/state/port-linker/debug.log. Never printed to stdout
    // (reserved for TUI output).
    let _log_guard = logging::init_logging();

    if args.remote.is_some() {
        // SSH bootstrap mode with Phoenix Agent auto-restart.
        run_with_phoenix_restart(&args).await
    } else if args.agent.is_some() {
        // Direct agent mode — single session, no restart.
        let agent_addr = args.agent.unwrap();
        run_single_session(&args, agent_addr, None).await
    } else {
        Err(Error::Protocol(
            "either --remote or --agent must be specified".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Phoenix Agent: auto-restart on disconnect (Architecture Section 8.3)
// ---------------------------------------------------------------------------

/// Run the CLI in SSH bootstrap mode with Phoenix Agent auto-restart.
///
/// If the QUIC connection drops (agent crash, network failure), the host
/// automatically cleans up, re-deploys the agent via SSH, and resumes
/// port forwarding. Gives up after [`MAX_RESTART_ATTEMPTS`] consecutive
/// failures.
async fn run_with_phoenix_restart(args: &Args) -> Result<()> {
    let remote = args.remote.as_ref().unwrap();
    let mut consecutive_failures: u32 = 0;

    loop {
        info!(
            remote = %remote,
            attempt = consecutive_failures + 1,
            "bootstrapping agent via SSH"
        );

        // Step 1: SSH bootstrap.
        let bootstrap_result = bootstrap_remote(args, remote).await;
        let (agent_addr, remote_agent) = match bootstrap_result {
            Ok(pair) => pair,
            Err(e) => {
                consecutive_failures += 1;
                error!(
                    %e,
                    attempt = consecutive_failures,
                    max = MAX_RESTART_ATTEMPTS,
                    "SSH bootstrap failed"
                );
                if consecutive_failures >= MAX_RESTART_ATTEMPTS {
                    return Err(Error::Protocol(format!(
                        "gave up after {MAX_RESTART_ATTEMPTS} consecutive restart failures: {e}"
                    )));
                }
                warn!(delay = RESTART_DELAY_SECS, "waiting before retry");
                tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)).await;
                continue;
            }
        };

        // Step 2: Run the session.
        let session_result = run_single_session(args, agent_addr, Some(&remote_agent)).await;

        // Step 3: Cleanup the old agent.
        remote_agent.cleanup().await;

        match session_result {
            Ok(()) => {
                // Clean exit (echo-only mode or graceful shutdown).
                info!("session ended cleanly");
                return Ok(());
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(
                    %e,
                    attempt = consecutive_failures,
                    max = MAX_RESTART_ATTEMPTS,
                    "session lost, attempting Phoenix restart"
                );

                if consecutive_failures >= MAX_RESTART_ATTEMPTS {
                    return Err(Error::Protocol(format!(
                        "gave up after {MAX_RESTART_ATTEMPTS} consecutive restart failures: {e}"
                    )));
                }

                warn!(delay = RESTART_DELAY_SECS, "waiting before restart");
                tokio::time::sleep(std::time::Duration::from_secs(RESTART_DELAY_SECS)).await;
            }
        }
    }
}

/// SSH bootstrap: connect, deploy agent, return QUIC address + remote agent.
async fn bootstrap_remote(
    args: &Args,
    remote: &str,
) -> Result<(SocketAddr, bootstrap::RemoteAgent)> {
    let ssh_session = ssh::SshSession::connect(remote, args.ssh_host_key_verification).await?;

    let peer_ip = ssh_session.peer_ip();

    let (handshake, remote_agent) =
        bootstrap::bootstrap_agent(ssh_session, args.agent_binary.as_deref()).await?;

    let agent_addr = SocketAddr::new(peer_ip, handshake.port);

    Ok((agent_addr, remote_agent))
}

// ---------------------------------------------------------------------------
// Single session lifecycle
// ---------------------------------------------------------------------------

/// Run a single QUIC session to the agent.
///
/// Returns `Ok(())` for a clean exit (echo-only or graceful shutdown).
/// Returns `Err` if the connection dropped unexpectedly (triggers Phoenix
/// restart in SSH mode).
async fn run_single_session(
    args: &Args,
    agent_addr: SocketAddr,
    remote_agent: Option<&bootstrap::RemoteAgent>,
) -> Result<()> {
    info!("connecting to agent at {}", agent_addr);

    // Build rustls client config that skips certificate verification.
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let quic_client_config = QuicClientConfig::try_from(rustls_config)
        .map_err(|e| Error::QuicConnection(e.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    // Configure transport: enable datagrams for UDP, increase stream limits.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(1_048_576));
    // Send QUIC PINGs every 10s to prevent the idle timeout (default 30s)
    // from killing the connection when no user traffic is flowing.
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));

    // Create QUIC client endpoint.
    let bind_addr: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|e| Error::Protocol(format!("invalid bind address: {e}")))?;
    let mut endpoint =
        quinn::Endpoint::client(bind_addr).map_err(|e| Error::QuicConnection(e.to_string()))?;
    endpoint.set_default_client_config(client_config);

    // Connect to the agent.
    let connection = endpoint
        .connect(agent_addr, "localhost")
        .map_err(|e| Error::QuicConnection(e.to_string()))?
        .await
        .map_err(|e| Error::QuicConnection(e.to_string()))?;

    info!("QUIC connection established");

    // Accept the control stream opened by the agent.
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| Error::QuicStream(e.to_string()))?;

    info!("control stream accepted");

    // Step 1: Receive handshake from the agent.
    let handshake = recv_msg(&mut recv).await?;
    let session_id = match handshake {
        ControlMsg::Handshake {
            protocol_version,
            token,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "protocol version mismatch: agent={protocol_version}, cli={PROTOCOL_VERSION}"
                )));
            }
            info!(
                protocol_version,
                token = %token,
                "handshake received, protocol version OK"
            );
            token
        }
        other => {
            return Err(Error::Protocol(format!(
                "expected Handshake, got {other:?}"
            )));
        }
    };

    // Create a session-scoped tracing span so all subsequent logs are enriched
    // with the session_id (Architecture Section 7.2). The agent's token serves
    // as the session identifier, correlating Host and Agent logs.
    let session_span = tracing::info_span!("session", session_id = %session_id);
    let _session_guard = session_span.enter();

    // Step 2: Send echo request.
    let echo_payload = b"Hello from port-linker CLI!".to_vec();
    let echo_req = ControlMsg::EchoRequest {
        payload: echo_payload.clone(),
    };
    info!("sending EchoRequest");
    send_msg(&mut send, &echo_req).await?;

    // Step 3: Receive echo response and validate.
    let echo_resp = recv_msg(&mut recv).await?;
    match echo_resp {
        ControlMsg::EchoResponse { payload } => {
            if payload != echo_payload {
                return Err(Error::Protocol(format!(
                    "echo payload mismatch: expected {} bytes, got {} bytes",
                    echo_payload.len(),
                    payload.len()
                )));
            }
            info!("echo response validated, payload matches");
        }
        other => {
            return Err(Error::Protocol(format!(
                "expected EchoResponse, got {other:?}"
            )));
        }
    }

    info!("connection test successful!");

    // Accept the agent's log forwarding unidirectional stream
    // (Architecture Section 7.1). Spawn as background task so it doesn't
    // block the control message loop.
    {
        let conn = connection.clone();
        tokio::spawn(async move {
            match conn.accept_uni().await {
                Ok(recv) => {
                    info!("accepted agent log stream");
                    logging::receive_agent_logs(recv).await;
                }
                Err(e) => {
                    debug!("no agent log stream accepted: {e}");
                }
            }
        });
    }

    if args.echo_only {
        // Gracefully close.
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        // In echo-only mode, cleanup is handled by the caller (Phoenix loop
        // or direct --agent mode).
        if let Some(agent) = remote_agent {
            agent.cleanup().await;
        }
        return Ok(());
    }

    // Initialize the binding manager for port forwarding.
    let mut manager =
        BindingManager::new(connection.clone(), args.fd_limit, args.conflict_resolution);

    // Initialize desktop notifications with 2-second accumulation.
    let mapping = Arc::new(notify::PortMapping::load_default());
    let notifier = Arc::new(notify::Notifier::new(
        args.notifications,
        args.notification_sound,
        Arc::clone(&mapping),
    ));
    let mut accumulator =
        notifications::NotificationAccumulator::new(Arc::clone(&notifier), mapping);

    // Enter the receive loop: listen for control messages from the agent.
    info!("entering receive loop (press Ctrl-C to exit)");
    let session_error = loop {
        tokio::select! {
            msg = recv_msg(&mut recv) => {
                match msg {
                    Ok(ControlMsg::PortAdded { port, proto, process_name }) => {
                        info!(port, ?proto, process = ?process_name, "remote port added");
                        manager.handle_port_added(port, proto);
                        accumulator.port_added(port, proto, process_name.as_deref());
                        info!(active = manager.active_count(), "active bindings");
                    }
                    Ok(ControlMsg::PortRemoved { port, proto }) => {
                        info!(port, ?proto, "remote port removed");
                        manager.handle_port_removed(port, proto);
                        accumulator.port_removed(port, proto);
                        info!(active = manager.active_count(), "active bindings");
                    }
                    Ok(ControlMsg::Heartbeat) => {
                        debug!("received heartbeat, sending heartbeat back");
                        send_msg(&mut send, &ControlMsg::Heartbeat).await?;
                    }
                    Ok(ControlMsg::EchoRequest { payload }) => {
                        debug!("received EchoRequest, sending EchoResponse");
                        send_msg(&mut send, &ControlMsg::EchoResponse { payload }).await?;
                    }
                    Ok(other) => {
                        debug!("received unhandled message: {other:?}");
                    }
                    Err(e) => break e,
                }
            }
            _ = accumulator.next_flush() => {
                accumulator.flush();
            }
        }
    };

    // Flush any remaining accumulated events before exit.
    accumulator.flush();

    // The control stream closed — connection lost.
    info!("control stream closed: {session_error}");
    notifier.notify_event(notify::NotificationEvent::ConnectionLost);

    // Gracefully close.
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    // In --agent mode (no remote_agent), we clean up and return error to
    // signal the connection dropped. In Phoenix mode, the caller handles
    // restart; cleanup happens there.
    if remote_agent.is_none() {
        // Direct --agent mode: exit with the error.
        return Err(session_error);
    }

    // Phoenix mode: return error to trigger restart.
    Err(session_error)
}
