mod binding_manager;
mod bootstrap;
mod logging;
mod notifications;
mod remote_platform;
mod ssh;
mod update_check;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::{debug, error, info, warn};

use binding_manager::{BindingManager, ConflictPolicy};
use common::{Error, Result};
use protocol::{ControlMsg, PROTOCOL_VERSION};
use ssh::{HostKeyPolicy, SshChain};
use tunnel::{recv_framed as recv_msg, send_framed as send_msg};
use update_check::UpdateCheck;

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

/// Initial delay between restart attempts (seconds). Each subsequent failure
/// doubles this delay until [`MAX_RESTART_DELAY_SECS`] is reached.
const INITIAL_RESTART_DELAY_SECS: u64 = 3;

/// Maximum delay between restart attempts (seconds). The exponential backoff
/// is capped here, after which retries continue indefinitely at this interval.
const MAX_RESTART_DELAY_SECS: u64 = 300;

/// Compute the exponential backoff delay for a given (1-based) consecutive
/// failure count, capped at [`MAX_RESTART_DELAY_SECS`].
fn restart_backoff_secs(consecutive_failures: u32) -> u64 {
    // Cap the exponent so the shift cannot overflow `u64`. Anything past ~20
    // would saturate the cap anyway.
    let exp = consecutive_failures.saturating_sub(1).min(20);
    let multiplier = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
    INITIAL_RESTART_DELAY_SECS
        .checked_mul(multiplier)
        .unwrap_or(MAX_RESTART_DELAY_SECS)
        .min(MAX_RESTART_DELAY_SECS)
}

/// Tracks consecutive restart failures and derives the delay before the next
/// attempt.
///
/// The counter is private so every rule that clears it lives on this type
/// rather than being open-coded in the restart loop.
#[derive(Debug)]
struct RestartBackoff {
    consecutive_failures: u32,
}

impl RestartBackoff {
    const fn new() -> Self {
        Self {
            consecutive_failures: 0,
        }
    }

    /// 1-based number of the attempt about to be made (for logging).
    const fn next_attempt(&self) -> u32 {
        self.consecutive_failures.saturating_add(1)
    }

    /// Consecutive failures recorded so far (for logging).
    const fn failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Record a failed SSH bootstrap. Returns the delay before retrying.
    fn note_bootstrap_failure(&mut self) -> u64 {
        self.note_failure()
    }

    /// Record a lost session. Returns the delay before retrying.
    ///
    /// A session that stayed up for longer than the capped delay clears the
    /// accumulated penalty, so a dropped long-running connection reconnects
    /// promptly instead of waiting out the cap.
    fn note_session_loss(&mut self, session_lasted: std::time::Duration) -> u64 {
        if session_lasted >= std::time::Duration::from_secs(MAX_RESTART_DELAY_SECS) {
            self.consecutive_failures = 0;
        }
        self.note_failure()
    }

    fn note_failure(&mut self) -> u64 {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        restart_backoff_secs(self.consecutive_failures)
    }
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
// `-V` gives the bare version for anything parsing it; `--version` gives the
// full build stamp for a bug report. clap picks between them by flag length.
#[command(
    name = "port-linker",
    about = "Host-side CLI for port-linker",
    version,
    long_version = build_info::long_version(env!("CARGO_PKG_VERSION"))
)]
struct Args {
    /// Remote host to connect to via SSH (e.g. "user@host" or "host").
    /// The agent will be deployed and started automatically.
    #[arg(long, group = "target")]
    remote: Option<String>,

    /// Agent QUIC address to connect to directly (e.g. "127.0.0.1:12345").
    /// Use this for manual mode when the agent is already running.
    /// Requires --session-config, which carries the certificates both ends pin.
    #[arg(long, group = "target", requires = "session_config")]
    agent: Option<SocketAddr>,

    /// Session file holding the pinned identities for manual --agent mode.
    /// If the file does not exist it is created, and the block to feed the
    /// agent's stdin is written alongside it.
    #[arg(long)]
    session_config: Option<std::path::PathBuf>,

    /// Run the echo test and exit immediately (skip the receive loop)
    #[arg(long, default_value_t = false)]
    echo_only: bool,

    /// Maximum number of forwarded ports (FD safety limit)
    #[arg(long)]
    fd_limit: Option<usize>,

    /// How to handle local port conflicts: interactive, auto-skip, or auto-kill
    #[arg(long, value_enum, default_value_t = ConflictPolicy::Interactive)]
    conflict_resolution: ConflictPolicy,

    /// SSH host key verification policy.
    ///
    /// SSH is the root of trust for the whole tunnel — it is what introduces
    /// the two ends to each other — so an unknown key defaults to asking,
    /// and falls back to refusing when there is no terminal to ask on.
    #[arg(long, value_enum, default_value_t = HostKeyPolicy::Ask)]
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

    /// Whether to check GitHub for a newer release: ask, enabled, or disabled.
    ///
    /// Only ever prints a notice — nothing is downloaded and no binary is
    /// replaced. `ask` requests consent once, on a terminal, and records the
    /// answer in `update-check.state` beside the log file; delete that file to
    /// be asked again. A run with no terminal never asks and never checks.
    #[arg(long, value_enum, env = "PLK_UPDATE_CHECK", default_value_t = UpdateCheck::Ask)]
    update_check: UpdateCheck,
}

// ---------------------------------------------------------------------------
// Session security
// ---------------------------------------------------------------------------

/// Everything needed to authenticate one tunnel end-to-end.
///
/// The host's private key stays in this process. Only the certificate half is
/// shipped to the agent, over SSH, and the agent's certificate comes back the
/// same way — so each end pins the other to a key that never crossed the
/// network. See [`common::session`] for the full trust model.
struct SessionSecurity {
    /// The host's own ephemeral TLS identity.
    identity: common::session::Identity,
    /// The block delivered to the agent over SSH.
    agent_config: common::session::AgentSessionConfig,
}

impl SessionSecurity {
    /// Mint a fresh identity, session id and session secret.
    fn generate() -> Result<Self> {
        let identity = common::session::Identity::generate("port-linker-host")?;
        let agent_config = common::session::AgentSessionConfig {
            session_id: common::session::generate_session_id()?,
            session_secret: common::session::generate_session_secret()?,
            client_cert_der: identity.cert_der().to_vec(),
        };
        Ok(Self {
            identity,
            agent_config,
        })
    }

    /// Rebuild from a manual-mode session file.
    fn from_file(file: &common::session::HostSessionFile) -> Result<Self> {
        Ok(Self {
            identity: file.identity()?,
            agent_config: file.agent_config(),
        })
    }

    fn session_id(&self) -> &str {
        &self.agent_config.session_id
    }

    fn session_secret(&self) -> &str {
        &self.agent_config.session_secret
    }
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

    // Once per process, and deliberately not inside the reconnect loop below.
    // Returns promptly: any network work is handed to a detached thread.
    update_check::run(args.update_check);

    if args.remote.is_some() {
        // SSH bootstrap mode with Phoenix Agent auto-restart.
        run_with_phoenix_restart(&args).await
    } else if let Some(agent_addr) = args.agent {
        // Direct agent mode — single session, no restart.
        run_manual_session(&args, agent_addr).await
    } else {
        Err(Error::Protocol(
            "either --remote or --agent must be specified".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Manual mode (--agent)
// ---------------------------------------------------------------------------

/// Connect to an already-running agent using a session file.
///
/// Manual mode has no SSH channel to introduce the two ends, so the operator
/// carries the introduction by hand: the CLI mints the session material, the
/// operator feeds the agent block to the agent, and pastes the certificate the
/// agent prints back into the session file. Both ends still pin each other, so
/// this path is no weaker than the SSH one — only less convenient.
async fn run_manual_session(args: &Args, agent_addr: SocketAddr) -> Result<()> {
    let path = args
        .session_config
        .as_ref()
        .ok_or_else(|| Error::Protocol("--agent requires --session-config".into()))?;

    if !path.exists() {
        return bootstrap_manual_session_file(path);
    }

    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    let file = common::session::HostSessionFile::parse(&text)?;

    let agent_cert = file.agent_cert_der.clone().ok_or_else(|| {
        Error::Security(format!(
            "{} has no AGENT_CERT yet. Start the agent with the companion \
             .agent file on its stdin, then paste the AGENT_CERT= line it \
             prints into the session file.",
            path.display()
        ))
    })?;

    let security = SessionSecurity::from_file(&file)?;
    run_single_session(args, agent_addr, None, None, &security, &agent_cert).await
}

/// Create a fresh manual-mode session file plus the agent-side block.
fn bootstrap_manual_session_file(path: &std::path::Path) -> Result<()> {
    let file = common::session::HostSessionFile::generate()?;
    let agent_path = path.with_extension("agent");

    write_private_file(path, &file.encode())?;
    // The agent block carries no private key, but it does carry the session
    // secret, so it is written with the same permissions.
    write_private_file(&agent_path, &file.agent_config().encode())?;

    println!("Created session files:");
    println!("  host:  {}", path.display());
    println!("  agent: {}", agent_path.display());
    println!();
    println!("1. Copy the agent file to the target and start the agent with it on stdin:");
    println!("     port-linker-agent < {}", agent_path.display());
    println!(
        "2. Copy the AGENT_CERT= line the agent prints into {}",
        path.display()
    );
    println!("3. Re-run this command to connect.");

    Ok(())
}

/// Write a file containing session secrets with owner-only permissions.
fn write_private_file(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(Error::Io)?;
    file.write_all(contents.as_bytes()).map_err(Error::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phoenix Agent: auto-restart on disconnect (Architecture Section 8.3)
// ---------------------------------------------------------------------------

/// Run the CLI in SSH bootstrap mode with Phoenix Agent auto-restart.
///
/// If the QUIC connection drops (agent crash, network failure), the host
/// automatically cleans up, re-deploys the agent via SSH, and resumes
/// port forwarding. Retries indefinitely with exponential backoff capped
/// at [`MAX_RESTART_DELAY_SECS`].
async fn run_with_phoenix_restart(args: &Args) -> Result<()> {
    let remote = args.remote.as_ref().unwrap();
    let mut backoff = RestartBackoff::new();

    loop {
        info!(
            remote = %remote,
            attempt = backoff.next_attempt(),
            "bootstrapping agent via SSH"
        );

        // Fresh identity and session secret for every attempt: a restarted
        // agent is a new peer, and reusing key material across sessions would
        // widen the window in which a leaked key is useful.
        let security = match SessionSecurity::generate() {
            Ok(security) => security,
            Err(e) => {
                error!(%e, "failed to generate session credentials");
                return Err(e);
            }
        };

        // Step 1: SSH bootstrap (including transport setup for ProxyJump).
        let bootstrap_result = bootstrap_remote(args, remote, &security).await;
        let BootstrapResult {
            agent_addr,
            agent_cert,
            remote_agent,
            transport_ctx,
            _jump_sessions,
        } = match bootstrap_result {
            Ok(result) => result,
            Err(e) => {
                let delay = backoff.note_bootstrap_failure();
                error!(
                    %e,
                    attempt = backoff.failures(),
                    delay,
                    "SSH bootstrap failed; retrying with backoff"
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                continue;
            }
        };

        // Note: a successful bootstrap deliberately does not clear the failure
        // count. An agent that is reachable over SSH but dies on startup would
        // otherwise reset the penalty on every pass and be retried at the
        // initial delay forever. The penalty is cleared by a session that stays
        // up longer than the cap — see `RestartBackoff::note_session_loss`.

        // Step 2: Run the session.
        let session_start = std::time::Instant::now();
        let session_result = run_single_session(
            args,
            agent_addr,
            Some(&remote_agent),
            transport_ctx,
            &security,
            &agent_cert,
        )
        .await;
        let session_lasted = session_start.elapsed();

        // Step 3: Cleanup the old agent.
        remote_agent.cleanup().await;

        match session_result {
            Ok(()) => {
                // Clean exit (graceful shutdown).
                info!("session ended cleanly");
                return Ok(());
            }
            Err(e) => {
                let delay = backoff.note_session_loss(session_lasted);
                warn!(
                    %e,
                    attempt = backoff.failures(),
                    delay,
                    "session lost, retrying with backoff"
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Result from bootstrapping a remote connection, including transport context.
struct BootstrapResult {
    agent_addr: SocketAddr,
    /// The agent's certificate, learned over SSH. The QUIC handshake will
    /// accept this certificate and no other.
    agent_cert: Vec<u8>,
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
async fn bootstrap_remote(
    args: &Args,
    remote: &str,
    security: &SessionSecurity,
) -> Result<BootstrapResult> {
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

        bootstrap_with_proxy_jump(args, remote, jump_hosts, security).await
    } else {
        // Direct connection — no ProxyJump.
        let ssh_session = ssh::SshSession::connect(remote, args.ssh_host_key_verification).await?;

        let peer_ip = ssh_session.peer_ip();
        let (handshake, remote_agent) = bootstrap::bootstrap_agent(
            ssh_session,
            args.agent_binary.as_deref(),
            &security.agent_config,
        )
        .await?;

        let agent_addr = SocketAddr::new(peer_ip, handshake.port);
        Ok(BootstrapResult {
            agent_addr,
            agent_cert: handshake.agent_cert,
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
    security: &SessionSecurity,
) -> Result<BootstrapResult> {
    let chain = SshChain::connect(remote, args.ssh_host_key_verification, jump_hosts).await?;

    let peer_ip = chain.target.peer_ip();
    let (handshake, remote_agent) = bootstrap::bootstrap_agent(
        chain.target,
        args.agent_binary.as_deref(),
        &security.agent_config,
    )
    .await?;
    let agent_cert = handshake.agent_cert.clone();

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
            let (relay_addr, relay_infos) = setup_udp_relay_chain(
                args,
                &chain.jump_sessions,
                agent_addr,
                security.session_secret(),
            )
            .await?;
            Ok(BootstrapResult {
                agent_addr: relay_addr,
                agent_cert: agent_cert.clone(),
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
                agent_cert: agent_cert.clone(),
                remote_agent,
                transport_ctx: Some(TransportContext::TcpBridge { socket }),
                _jump_sessions: chain.jump_sessions,
            })
        }
        TransportStrategy::Auto => {
            // If we have a routable target IP, try UDP relay first.
            if let Some(agent_ip) = relay_target_ip {
                let agent_addr = SocketAddr::new(agent_ip, handshake.port);
                match try_udp_relay_auto(
                    args,
                    &chain.jump_sessions,
                    agent_addr,
                    security.session_secret(),
                )
                .await
                {
                    Ok((relay_addr, relay_infos)) => {
                        info!("auto-detection: UDP relay chain working");
                        Ok(BootstrapResult {
                            agent_addr: relay_addr,
                            agent_cert: agent_cert.clone(),
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
                            agent_cert: agent_cert.clone(),
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
                    agent_cert: agent_cert.clone(),
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
    session_secret: &str,
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

        let relay_info = bootstrap::bootstrap_relay(
            session,
            &target_str,
            args.relay_binary.as_deref(),
            session_secret,
        )
        .await?;

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
    session_secret: &str,
) -> Result<(SocketAddr, Vec<bootstrap::RelayInfo>)> {
    let (relay_addr, relay_infos) =
        setup_udp_relay_chain(args, jump_sessions, agent_addr, session_secret).await?;

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

    // The relay ignores unauthenticated probes, so present the session secret.
    let probe = format!("PLK_PROBE:{session_secret}");
    probe_socket
        .send_to(probe.as_bytes(), relay_addr)
        .await
        .map_err(|e| Error::Protocol(format!("failed to send probe: {e}")))?;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(probe_timeout, probe_socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            if buf.get(..len) == Some(b"PLK_PROBE_ACK".as_slice()) {
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

/// Register with the first relay and return the socket to use for QUIC.
///
/// The registration must come from the socket QUIC will send from, because the
/// relay pins the client by source address. Retried a few times because UDP
/// registration can be lost.
async fn register_with_relay(
    relay_addr: SocketAddr,
    session_secret: &str,
) -> Result<std::net::UdpSocket> {
    const ATTEMPTS: u32 = 3;
    const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Protocol(format!("failed to bind relay client socket: {e}")))?;

    let hello = format!("PLK_HELLO:{session_secret}");
    let mut buf = [0u8; 64];

    for attempt in 1..=ATTEMPTS {
        socket
            .send_to(hello.as_bytes(), relay_addr)
            .await
            .map_err(|e| Error::Protocol(format!("failed to send relay registration: {e}")))?;

        match tokio::time::timeout(ATTEMPT_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) if buf.get(..len) == Some(b"PLK_HELLO_ACK".as_slice()) => {
                info!(addr = %relay_addr, "registered with UDP relay");
                return socket
                    .into_std()
                    .map_err(|e| Error::Protocol(format!("failed to convert relay socket: {e}")));
            }
            Ok(Ok(_)) => {
                debug!(attempt, "unexpected relay registration response, retrying");
            }
            Ok(Err(e)) => {
                return Err(Error::Protocol(format!(
                    "relay registration recv error: {e}"
                )));
            }
            Err(_) => {
                debug!(attempt, "relay registration timed out, retrying");
            }
        }
    }

    Err(Error::Security(format!(
        "the relay at {relay_addr} did not accept our session credentials"
    )))
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

    // Fallback: PowerShell (Windows targets).
    let cmd = r#"powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress""#;
    if let Ok((stdout, _, Some(0))) = ssh.exec(cmd).await {
        let ip_str = stdout.trim();
        if !ip_str.is_empty()
            && let Ok(ip) = ip_str.parse::<std::net::IpAddr>()
            && !ip.is_loopback()
        {
            info!(ip = %ip, "resolved target's actual network IP via PowerShell");
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
    security: &SessionSecurity,
    agent_cert: &[u8],
) -> Result<()> {
    info!("connecting to agent at {}", agent_addr);

    // Mutual TLS against the certificate the agent published over SSH. The
    // handshake fails unless the peer holds the private key for exactly that
    // certificate, so an on-path attacker cannot impersonate the agent, and we
    // present our own pinned certificate so it cannot impersonate us either.
    let rustls_config = common::session::client_tls_config(&security.identity, agent_cert)?;

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
        Some(TransportContext::UdpRelay { .. }) => {
            // The relay only forwards for a client that has proved knowledge of
            // the session secret, and it binds that registration to a source
            // address. Register on the very socket QUIC will use, then hand
            // that socket to quinn.
            let socket = register_with_relay(agent_addr, security.session_secret()).await?;
            let runtime = quinn::default_runtime()
                .ok_or_else(|| Error::QuicConnection("no async runtime".into()))?;
            let mut endpoint =
                quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
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
            // Direct UDP -- standard UDP endpoint.
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
    //
    // TLS has already proven the peer holds the private key for the certificate
    // we learned over SSH. The session id check additionally confirms this is
    // the agent process this run bootstrapped, not a leftover from an earlier
    // one that happens to still be listening.
    let handshake = recv_msg(&mut recv).await?;
    let session_id = match handshake {
        ControlMsg::Handshake {
            protocol_version,
            session_id,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "protocol version mismatch: agent={protocol_version}, cli={PROTOCOL_VERSION}"
                )));
            }
            if session_id != security.session_id() {
                return Err(Error::Security(format!(
                    "agent reported session id {session_id}, expected {}",
                    security.session_id()
                )));
            }
            info!(
                protocol_version,
                session_id = %session_id,
                "handshake received, agent identity and session confirmed"
            );
            session_id
        }
        other => {
            return Err(Error::Protocol(format!(
                "expected Handshake, got {other:?}"
            )));
        }
    };

    // Create a session-scoped tracing span so all subsequent logs are enriched
    // with the session_id (Architecture Section 7.2), correlating Host and
    // Agent logs.
    let session_span = tracing::info_span!("session", session_id = %session_id);
    let _session_guard = session_span.enter();

    // Step 2: Prove to the agent that we hold the session secret it received
    // over SSH. The agent serves nothing until this arrives.
    send_msg(
        &mut send,
        &ControlMsg::SessionAuth {
            session_secret: security.session_secret().to_string(),
        },
    )
    .await?;
    info!("session authentication sent");

    // Step 3: Send echo request.
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
        // Echo test passed. Close the QUIC connection and return to allow
        // normal teardown. The endpoint.wait_idle() has a short timeout to
        // avoid blocking indefinitely on tunnel reader tasks.
        info!("echo-only: test passed, shutting down");
        connection.close(0u32.into(), b"echo-ok");
        tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.wait_idle())
            .await
            .ok();
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    /// A session short enough that it should not clear the backoff penalty.
    const BRIEF: Duration = Duration::from_secs(1);

    /// A session long enough to count as "stable" and clear the penalty.
    const STABLE: Duration = Duration::from_secs(MAX_RESTART_DELAY_SECS);

    #[test]
    fn backoff_doubles_then_saturates_at_the_cap() {
        assert_eq!(restart_backoff_secs(1), 3);
        assert_eq!(restart_backoff_secs(2), 6);
        assert_eq!(restart_backoff_secs(3), 12);
        assert_eq!(restart_backoff_secs(4), 24);
        assert_eq!(restart_backoff_secs(5), 48);
        assert_eq!(restart_backoff_secs(6), 96);
        assert_eq!(restart_backoff_secs(7), 192);
        // 3 * 2^7 = 384, capped at 300.
        assert_eq!(restart_backoff_secs(8), MAX_RESTART_DELAY_SECS);
        assert_eq!(restart_backoff_secs(20), MAX_RESTART_DELAY_SECS);
        // Extreme values must saturate rather than overflow or panic.
        assert_eq!(restart_backoff_secs(u32::MAX), MAX_RESTART_DELAY_SECS);
        // Defensive: the unreachable zero-failure case must still be sane.
        assert_eq!(restart_backoff_secs(0), INITIAL_RESTART_DELAY_SECS);
    }

    /// Pins the tuning constants. These reference the real constants, so
    /// editing one in this file actually trips the test.
    #[test]
    fn restart_constants_are_sane() {
        // Short enough that a transient blip recovers promptly.
        const { assert!(INITIAL_RESTART_DELAY_SECS > 0) };
        const { assert!(INITIAL_RESTART_DELAY_SECS < 60) };
        assert_eq!(INITIAL_RESTART_DELAY_SECS, 3);

        // The cap bounds the backoff at a sane retry interval.
        const { assert!(MAX_RESTART_DELAY_SECS >= INITIAL_RESTART_DELAY_SECS) };
        assert_eq!(MAX_RESTART_DELAY_SECS, 300);
    }

    #[test]
    fn repeated_bootstrap_failures_back_off() {
        let mut backoff = RestartBackoff::new();
        let delays: Vec<u64> = (0..5).map(|_| backoff.note_bootstrap_failure()).collect();
        assert_eq!(delays, [3, 6, 12, 24, 48]);
    }

    /// Regression: an agent that is reachable over SSH but dies as soon as it
    /// starts must not be retried at a flat interval forever. Each cycle here
    /// is one full pass of the restart loop — bootstrap succeeds, then the
    /// session drops almost immediately.
    #[test]
    fn repeated_session_losses_back_off() {
        let mut backoff = RestartBackoff::new();

        let delays: Vec<u64> = (0..5)
            .map(|_| {
                // One pass of the restart loop: bootstrap succeeds, then the
                // session drops almost immediately. A successful bootstrap has
                // no effect on the backoff, so the cycle is just the loss.
                backoff.note_session_loss(BRIEF)
            })
            .collect();

        assert_eq!(
            delays,
            [3, 6, 12, 24, 48],
            "a crash-looping agent must be retried with a growing delay, \
             not hammered at the initial interval"
        );
    }

    #[test]
    fn a_stable_session_clears_the_penalty() {
        let mut backoff = RestartBackoff::new();

        // Rack up a penalty on brief sessions.
        for _ in 0..4 {
            backoff.note_session_loss(BRIEF);
        }
        assert_eq!(backoff.failures(), 4);

        // A session that outlived the cap should reconnect promptly.
        assert_eq!(
            backoff.note_session_loss(STABLE),
            INITIAL_RESTART_DELAY_SECS
        );
        assert_eq!(backoff.failures(), 1);
    }

    /// The penalty carries across the bootstrap/session boundary: a remote that
    /// alternates between refusing SSH and dropping the session immediately is
    /// still failing, so the delay must keep growing.
    #[test]
    fn penalty_carries_across_bootstrap_and_session_failures() {
        let mut backoff = RestartBackoff::new();

        assert_eq!(backoff.note_bootstrap_failure(), 3);
        assert_eq!(backoff.note_session_loss(BRIEF), 6);
        assert_eq!(backoff.note_bootstrap_failure(), 12);
        assert_eq!(backoff.note_session_loss(BRIEF), 24);
    }

    #[test]
    fn attempt_counters_track_the_failure_count() {
        let mut backoff = RestartBackoff::new();
        assert_eq!(backoff.next_attempt(), 1);
        assert_eq!(backoff.failures(), 0);

        backoff.note_bootstrap_failure();
        assert_eq!(backoff.failures(), 1);
        assert_eq!(backoff.next_attempt(), 2);
    }
}
