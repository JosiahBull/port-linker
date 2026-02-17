mod binding_manager;
mod bootstrap;
mod logging;
mod notifications;
mod remote_platform;
mod ssh;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::{debug, error, info, warn};

use binding_manager::{BindingManager, ConflictPolicy};
use common::{Error, Result};
use protocol::{ControlMsg, PROTOCOL_VERSION};
use ssh::{HostKeyPolicy, SshChain};

/// Maximum allowed frame size (1 MB).
const MAX_FRAME_SIZE: u32 = 1_048_576;

// ---------------------------------------------------------------------------
// Transport strategy (ProxyJump support)
// ---------------------------------------------------------------------------

/// How to transport QUIC traffic when ProxyJump is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TransportStrategy {
    /// Try UDP relay chain first, fall back to QUIC-over-TCP if UDP is blocked.
    Auto,
    /// Use UDP relay chain on jump hosts (preserves full QUIC end-to-end).
    UdpRelay,
    /// Use QUIC-over-TCP via SSH direct-tcpip tunnel.
    TcpBridge,
}

impl std::fmt::Display for TransportStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::UdpRelay => write!(f, "udp-relay"),
            Self::TcpBridge => write!(f, "tcp-bridge"),
        }
    }
}

/// Active transport context for a session.
#[allow(dead_code)]
enum TransportContext {
    /// Direct QUIC connection (no ProxyJump).
    Direct,
    /// UDP relay chain on jump hosts.
    UdpRelay {
        /// Relay cleanups for each jump host.
        _relay_infos: Vec<bootstrap::RelayInfo>,
    },
    /// QUIC-over-TCP via SSH tunnel.
    TcpBridge {
        /// The abstract socket wrapping the TCP tunnel.
        socket: Arc<quic_over_tcp::TcpUdpSocket>,
    },
}

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

    /// Transport strategy when ProxyJump is configured: auto, udp-relay, or tcp-bridge
    #[arg(long, value_enum, default_value_t = TransportStrategy::Auto)]
    transport: TransportStrategy,

    /// Timeout (seconds) for UDP relay probe when using auto transport detection
    #[arg(long, default_value_t = 5)]
    relay_probe_timeout: u64,

    /// Path to a custom relay binary to transfer to jump hosts
    #[arg(long)]
    relay_binary: Option<std::path::PathBuf>,
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
    let payload: Bytes = protocol::encode(msg).map_err(|e| Error::Codec(e.to_string()))?;
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
        run_single_session(&args, agent_addr, None, None).await
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

        // Step 1: SSH bootstrap (including transport setup for ProxyJump).
        let bootstrap_result = bootstrap_remote(args, remote).await;
        let BootstrapResult {
            agent_addr,
            remote_agent,
            transport_ctx,
            _jump_sessions,
        } = match bootstrap_result {
            Ok(result) => result,
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
        let session_result =
            run_single_session(args, agent_addr, Some(&remote_agent), transport_ctx).await;

        if args.echo_only && session_result.is_ok() {
            // Force-exit immediately. The echo test has passed; the SSH
            // session drop and remote agent cleanup can block indefinitely
            // on the tunnel reader tasks, so skip all teardown.
            info!("echo-only: test passed, exiting");
            std::process::exit(0);
        }

        // Step 3: Cleanup the old agent.
        remote_agent.cleanup().await;

        match session_result {
            Ok(()) => {
                // Clean exit (graceful shutdown).
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

/// Result from bootstrapping a remote connection, including transport context.
struct BootstrapResult {
    agent_addr: SocketAddr,
    remote_agent: bootstrap::RemoteAgent,
    transport_ctx: Option<TransportContext>,
    /// Jump host SSH sessions that must be kept alive for the tunnel chain.
    /// If these are dropped, the tunneled channels die and the target SSH
    /// session (and QUIC connection) will break.
    _jump_sessions: Vec<ssh::SshSession>,
}

/// SSH bootstrap: connect, deploy agent, set up transport, return results.
///
/// If the target host has `ProxyJump` configured in `~/.ssh/config`, the
/// connection is chained through the jump hosts and an appropriate transport
/// strategy is selected (UDP relay, TCP bridge, or auto-detected).
async fn bootstrap_remote(args: &Args, remote: &str) -> Result<BootstrapResult> {
    // Peek at the SSH config to check for ProxyJump.
    let (user_override, host) = if let Some(idx) = remote.find('@') {
        (Some(&remote[..idx]), &remote[idx + 1..])
    } else {
        (None, remote)
    };

    let ssh_config = ssh::config_for_host(host, user_override);

    if let Some(ref jump_hosts) = ssh_config.proxy_jump {
        info!(
            hops = jump_hosts.len(),
            transport = %args.transport,
            "ProxyJump configured, using SSH connection chaining"
        );

        bootstrap_with_proxy_jump(args, remote, jump_hosts).await
    } else {
        // Direct connection — no ProxyJump.
        let ssh_session = ssh::SshSession::connect(remote, args.ssh_host_key_verification).await?;

        let peer_ip = ssh_session.peer_ip();
        let (handshake, remote_agent) =
            bootstrap::bootstrap_agent(ssh_session, args.agent_binary.as_deref()).await?;

        let agent_addr = SocketAddr::new(peer_ip, handshake.port);
        Ok(BootstrapResult {
            agent_addr,
            remote_agent,
            transport_ctx: None,
            _jump_sessions: Vec::new(),
        })
    }
}

/// Bootstrap with ProxyJump: set up SSH chain, deploy agent, select transport.
async fn bootstrap_with_proxy_jump(
    args: &Args,
    remote: &str,
    jump_hosts: &[ssh::JumpHost],
) -> Result<BootstrapResult> {
    let chain = SshChain::connect(remote, args.ssh_host_key_verification, jump_hosts).await?;

    let peer_ip = chain.target.peer_ip();
    let (handshake, remote_agent) =
        bootstrap::bootstrap_agent(chain.target, args.agent_binary.as_deref()).await?;

    // Determine the target's IP for UDP relay targeting.
    //
    // When the SSH config uses a loopback address (e.g., `Hostname 127.0.0.1`
    // for a port-forwarded container/VM), the loopback address only works for
    // the specific SSH-forwarded port — the agent's random QUIC port is NOT
    // reachable at that address from the jump host.
    //
    // We resolve the target's real network IP by running `hostname -I` on the
    // target. For TCP bridge, we tunnel through the target's own SSH session
    // to localhost, so loopback is fine.
    let relay_target_ip = if peer_ip.is_loopback() {
        warn!(
            peer_ip = %peer_ip,
            "target SSH hostname resolves to loopback, \
             resolving actual network IP for relay targeting"
        );
        resolve_target_real_ip(&remote_agent.ssh).await
    } else {
        Some(peer_ip)
    };

    // Select transport strategy.
    match args.transport {
        TransportStrategy::UdpRelay => {
            let agent_ip = relay_target_ip.ok_or_else(|| {
                Error::Protocol(
                    "UDP relay requires a non-loopback target IP, but could not \
                     resolve one. The target appears to be behind a port forward. \
                     Use --transport=tcp-bridge instead."
                        .into(),
                )
            })?;
            let agent_addr = SocketAddr::new(agent_ip, handshake.port);
            let (relay_addr, relay_infos) =
                setup_udp_relay_chain(args, &chain.jump_sessions, agent_addr).await?;
            Ok(BootstrapResult {
                agent_addr: relay_addr,
                remote_agent,
                transport_ctx: Some(TransportContext::UdpRelay {
                    _relay_infos: relay_infos,
                }),
                _jump_sessions: chain.jump_sessions,
            })
        }
        TransportStrategy::TcpBridge => {
            let (bridge_addr, socket) = setup_tcp_bridge(&remote_agent.ssh, &handshake).await?;
            Ok(BootstrapResult {
                agent_addr: bridge_addr,
                remote_agent,
                transport_ctx: Some(TransportContext::TcpBridge { socket }),
                _jump_sessions: chain.jump_sessions,
            })
        }
        TransportStrategy::Auto => {
            // If we have a routable target IP, try UDP relay first.
            if let Some(agent_ip) = relay_target_ip {
                let agent_addr = SocketAddr::new(agent_ip, handshake.port);
                match try_udp_relay_auto(args, &chain.jump_sessions, agent_addr).await {
                    Ok((relay_addr, relay_infos)) => {
                        info!("auto-detection: UDP relay chain working");
                        Ok(BootstrapResult {
                            agent_addr: relay_addr,
                            remote_agent,
                            transport_ctx: Some(TransportContext::UdpRelay {
                                _relay_infos: relay_infos,
                            }),
                            _jump_sessions: chain.jump_sessions,
                        })
                    }
                    Err(e) => {
                        warn!(%e, "auto-detection: UDP relay failed, falling back to TCP bridge");
                        let (bridge_addr, socket) =
                            setup_tcp_bridge(&remote_agent.ssh, &handshake).await?;
                        Ok(BootstrapResult {
                            agent_addr: bridge_addr,
                            remote_agent,
                            transport_ctx: Some(TransportContext::TcpBridge { socket }),
                            _jump_sessions: chain.jump_sessions,
                        })
                    }
                }
            } else {
                // No routable target IP — skip relay, go straight to TCP bridge.
                info!(
                    "target behind loopback with no resolvable network IP, \
                     using TCP bridge directly"
                );
                let (bridge_addr, socket) = setup_tcp_bridge(&remote_agent.ssh, &handshake).await?;
                Ok(BootstrapResult {
                    agent_addr: bridge_addr,
                    remote_agent,
                    transport_ctx: Some(TransportContext::TcpBridge { socket }),
                    _jump_sessions: chain.jump_sessions,
                })
            }
        }
    }
}

/// Set up a chain of UDP relays on jump hosts.
///
/// Works backwards: last relay targets the agent's QUIC port, each prior
/// relay targets the next relay. Host connects to the first relay.
async fn setup_udp_relay_chain(
    args: &Args,
    jump_sessions: &[ssh::SshSession],
    agent_addr: SocketAddr,
) -> Result<(SocketAddr, Vec<bootstrap::RelayInfo>)> {
    let mut relay_infos = Vec::with_capacity(jump_sessions.len());
    let mut next_target = agent_addr;

    // Deploy relays in reverse order (last jump host first).
    for (i, session) in jump_sessions.iter().enumerate().rev() {
        let target_str = next_target.to_string();
        info!(
            hop = i + 1,
            target = %target_str,
            "deploying relay on jump host"
        );

        let relay_info =
            bootstrap::bootstrap_relay(session, &target_str, args.relay_binary.as_deref()).await?;

        // The next target for the previous relay is this relay.
        next_target = SocketAddr::new(session.peer_ip(), relay_info.port);
        relay_infos.push(relay_info);
    }

    // Reverse so relay_infos[0] is the first hop.
    relay_infos.reverse();

    // Host connects to the first relay.
    let first_relay_addr = next_target;
    info!(
        addr = %first_relay_addr,
        chain_len = relay_infos.len(),
        "UDP relay chain established"
    );

    Ok((first_relay_addr, relay_infos))
}

/// Try to set up a UDP relay chain with auto-detection probe.
async fn try_udp_relay_auto(
    args: &Args,
    jump_sessions: &[ssh::SshSession],
    agent_addr: SocketAddr,
) -> Result<(SocketAddr, Vec<bootstrap::RelayInfo>)> {
    let (relay_addr, relay_infos) = setup_udp_relay_chain(args, jump_sessions, agent_addr).await?;

    // Probe the first relay to check if UDP is reachable.
    // NOTE: This only validates the first hop. If UDP is blocked at a later
    // hop, the probe succeeds but QUIC will fail. The auto transport strategy
    // handles this by falling back to TCP bridge on QUIC connection failure.
    let probe_timeout = std::time::Duration::from_secs(args.relay_probe_timeout);
    info!(
        addr = %relay_addr,
        timeout_secs = args.relay_probe_timeout,
        "probing UDP relay connectivity"
    );

    let probe_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Protocol(format!("failed to bind probe socket: {e}")))?;

    probe_socket
        .send_to(b"PLK_PROBE", relay_addr)
        .await
        .map_err(|e| Error::Protocol(format!("failed to send probe: {e}")))?;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(probe_timeout, probe_socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            if &buf[..len] == b"PLK_PROBE_ACK" {
                info!("relay probe: received ACK, UDP path is clear");
                Ok((relay_addr, relay_infos))
            } else {
                Err(Error::Protocol("relay probe: unexpected response".into()))
            }
        }
        Ok(Err(e)) => Err(Error::Protocol(format!("relay probe recv error: {e}"))),
        Err(_) => Err(Error::Protocol(
            "relay probe: timed out (UDP may be blocked)".into(),
        )),
    }
}

/// Set up a QUIC-over-TCP bridge via SSH direct-tcpip tunnel.
///
/// Opens a tunnel through the **target's own SSH session** to `localhost:bridge_port`.
/// This works even when the target is behind a port forward (loopback address in SSH
/// config), because the tunnel endpoint is on the target itself where the bridge
/// listener runs.
async fn setup_tcp_bridge(
    target_session: &ssh::SshSession,
    handshake: &bootstrap::AgentHandshake,
) -> Result<(SocketAddr, Arc<quic_over_tcp::TcpUdpSocket>)> {
    let bridge_port = handshake.bridge_port.ok_or_else(|| {
        Error::Protocol("TCP bridge requested but agent did not report BRIDGE_PORT".into())
    })?;

    info!(
        bridge_port,
        "setting up QUIC-over-TCP bridge via SSH tunnel to target"
    );

    // Open the tunnel through the target's SSH session to localhost:bridge_port.
    // The bridge listener is on the target host itself, so 127.0.0.1 is correct.
    let tunnel_stream = target_session.open_tunnel("127.0.0.1", bridge_port).await?;

    // Use the bridge port as the synthetic address so quinn sees a valid (non-zero) port.
    // The actual routing happens through the TCP tunnel; these addresses are only used
    // by quinn internally to match datagrams to connections.
    let bridge_addr: SocketAddr = SocketAddr::new("127.0.0.1".parse().unwrap(), bridge_port);

    let socket = quic_over_tcp::TcpUdpSocket::new(tunnel_stream, bridge_addr, bridge_addr);

    info!("TCP bridge established");
    Ok((bridge_addr, socket))
}

/// Resolve the target host's actual network IP when SSH config uses a loopback address.
///
/// When the target is configured with `Hostname 127.0.0.1` (common for port-forwarded
/// containers, VMs, or devcontainers), the loopback address only works for the specific
/// SSH-forwarded port. For UDP relay, we need the target's real network IP as seen from
/// the jump host. This function runs `hostname -I` on the target to discover it.
async fn resolve_target_real_ip(ssh: &ssh::SshSession) -> Option<std::net::IpAddr> {
    // Try Linux-style `hostname -I` first (works on most Linux including busybox/Alpine).
    let cmd = "hostname -I 2>/dev/null | awk '{print $1}'";
    if let Ok((stdout, _, Some(0))) = ssh.exec(cmd).await {
        let ip_str = stdout.trim();
        if !ip_str.is_empty()
            && let Ok(ip) = ip_str.parse::<std::net::IpAddr>()
            && !ip.is_loopback()
        {
            info!(ip = %ip, "resolved target's actual network IP via hostname -I");
            return Some(ip);
        }
    }

    // Fallback: use `ip route get` to find the default route's source IP.
    let cmd = r#"ip -4 route get 1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++)if($i=="src")print $(i+1);exit}'"#;
    if let Ok((stdout, _, Some(0))) = ssh.exec(cmd).await {
        let ip_str = stdout.trim();
        if !ip_str.is_empty()
            && let Ok(ip) = ip_str.parse::<std::net::IpAddr>()
            && !ip.is_loopback()
        {
            info!(ip = %ip, "resolved target's actual network IP via ip route");
            return Some(ip);
        }
    }

    warn!("could not resolve target's actual network IP");
    None
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
    transport_ctx: Option<TransportContext>,
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

    // Create QUIC client endpoint based on transport context.
    let (endpoint, connection) = match transport_ctx {
        Some(TransportContext::TcpBridge { ref socket }) => {
            // Use the TcpUdpSocket as the abstract UDP socket for QUIC.
            info!("using QUIC-over-TCP bridge transport");
            let runtime = quinn::default_runtime()
                .ok_or_else(|| Error::QuicConnection("no async runtime".into()))?;
            let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket.clone(),
                runtime,
            )
            .map_err(|e| Error::QuicConnection(e.to_string()))?;
            endpoint.set_default_client_config(client_config);

            let connection = endpoint
                .connect(agent_addr, "localhost")
                .map_err(|e| Error::QuicConnection(e.to_string()))?
                .await
                .map_err(|e| Error::QuicConnection(e.to_string()))?;

            (endpoint, connection)
        }
        _ => {
            // Direct UDP or UDP relay -- standard UDP endpoint.
            let bind_addr: SocketAddr = "0.0.0.0:0"
                .parse()
                .map_err(|e| Error::Protocol(format!("invalid bind address: {e}")))?;
            let mut endpoint = quinn::Endpoint::client(bind_addr)
                .map_err(|e| Error::QuicConnection(e.to_string()))?;
            endpoint.set_default_client_config(client_config);

            let connection = endpoint
                .connect(agent_addr, "localhost")
                .map_err(|e| Error::QuicConnection(e.to_string()))?
                .await
                .map_err(|e| Error::QuicConnection(e.to_string()))?;

            (endpoint, connection)
        }
    };

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
        // Echo test passed. Force-exit immediately — the SSH session
        // teardown and remote agent cleanup can block indefinitely on
        // tunnel reader tasks, and we have nothing left to verify.
        info!("echo-only: test passed, exiting");
        std::process::exit(0);
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
