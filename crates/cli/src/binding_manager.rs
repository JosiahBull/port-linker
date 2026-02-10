use std::collections::HashMap;
use std::net::SocketAddr;

use clap::ValueEnum;
use quinn::Connection;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use common::process::{self, ProcessInfo, TransportProto};
use protocol::{ControlMsg, Protocol};

/// Default maximum number of active forwarded ports.
const DEFAULT_FD_LIMIT: usize = 2000;

/// Maximum number of bind retry attempts after killing a conflicting process.
const MAX_BIND_RETRIES: u32 = 3;

/// Delay between kill and retry bind (milliseconds).
const RETRY_DELAY_MS: u64 = 200;

// ---------------------------------------------------------------------------
// ConflictPolicy
// ---------------------------------------------------------------------------

/// How to handle local port conflicts when a remote port is already in use
/// locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConflictPolicy {
    /// Prompt the user interactively (default).
    Interactive,
    /// Silently skip conflicting ports.
    AutoSkip,
    /// Automatically kill the conflicting process.
    AutoKill,
}

impl std::fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interactive => write!(f, "interactive"),
            Self::AutoSkip => write!(f, "auto-skip"),
            Self::AutoKill => write!(f, "auto-kill"),
        }
    }
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// Tracks a single active port binding.
struct Binding {
    /// Aborting this handle stops the accept/forward loop.
    task: JoinHandle<()>,
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// BindingManager
// ---------------------------------------------------------------------------

/// Manages local port bindings that mirror remote listeners.
///
/// When the remote agent reports `PortAdded`, the manager binds the
/// corresponding local port and spawns a forwarding task. When
/// `PortRemoved` arrives, the binding is dropped (aborting the task).
pub struct BindingManager {
    bindings: HashMap<(u16, Protocol), Binding>,
    fd_limit: usize,
    ephemeral_start: u16,
    ephemeral_end: u16,
    connection: Connection,
    policy: ConflictPolicy,
}

impl BindingManager {
    pub fn new(
        connection: Connection,
        fd_limit: Option<usize>,
        policy: ConflictPolicy,
    ) -> Self {
        let (ephemeral_start, ephemeral_end) = common::ephemeral::ephemeral_range();
        info!(
            ephemeral_start,
            ephemeral_end,
            fd_limit = fd_limit.unwrap_or(DEFAULT_FD_LIMIT),
            %policy,
            "binding manager initialized"
        );
        Self {
            bindings: HashMap::new(),
            fd_limit: fd_limit.unwrap_or(DEFAULT_FD_LIMIT),
            ephemeral_start,
            ephemeral_end,
            connection,
            policy,
        }
    }

    /// Handle a PortAdded event from the remote agent.
    pub fn handle_port_added(&mut self, port: u16, proto: Protocol) {
        // Skip if already bound.
        if self.bindings.contains_key(&(port, proto)) {
            debug!(port, ?proto, "port already bound, ignoring duplicate");
            return;
        }

        // Privileged port guard: skip ports below 1024 which require root.
        if port < 1024 {
            warn!(port, ?proto, "refusing to bind privileged port (< 1024)");
            return;
        }

        // Ephemeral port guard.
        if port >= self.ephemeral_start && port <= self.ephemeral_end {
            warn!(
                port,
                ?proto,
                range_start = self.ephemeral_start,
                range_end = self.ephemeral_end,
                "refusing to bind ephemeral port"
            );
            return;
        }

        // FD safety cap.
        if self.bindings.len() >= self.fd_limit {
            warn!(
                port,
                ?proto,
                active = self.bindings.len(),
                limit = self.fd_limit,
                "FD limit reached, refusing to bind"
            );
            return;
        }

        match proto {
            Protocol::Tcp => self.bind_tcp(port),
            Protocol::Udp => self.bind_udp(port),
        }
    }

    /// Handle a PortRemoved event from the remote agent.
    pub fn handle_port_removed(&mut self, port: u16, proto: Protocol) {
        if self.bindings.remove(&(port, proto)).is_some() {
            info!(port, ?proto, "port binding removed");
        } else {
            debug!(port, ?proto, "port was not bound, ignoring remove");
        }
    }

    /// Returns the number of active bindings.
    pub fn active_count(&self) -> usize {
        self.bindings.len()
    }

    fn bind_tcp(&mut self, port: u16) {
        let connection = self.connection.clone();
        let policy = self.policy;
        let task = tokio::spawn(async move {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();

            // Attempt to bind, with conflict resolution retry loop.
            let listener = match try_bind_tcp(addr, port, policy).await {
                Some(l) => l,
                None => return,
            };

            info!(port, "TCP listener bound on 127.0.0.1:{port}");

            loop {
                let (tcp_stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        error!(port, %e, "TCP accept error");
                        break;
                    }
                };

                // Disable Nagle's algorithm for low-latency forwarding.
                let _ = tcp_stream.set_nodelay(true);
                debug!(port, %peer, "accepted local TCP connection");
                let conn = connection.clone();
                tokio::spawn(forward_tcp_connection(conn, tcp_stream, port));
            }
        });

        self.bindings
            .insert((port, Protocol::Tcp), Binding { task });
    }

    fn bind_udp(&mut self, port: u16) {
        let connection = self.connection.clone();
        let policy = self.policy;
        let task = tokio::spawn(async move {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();

            // Attempt to bind, with conflict resolution retry loop.
            let socket = match try_bind_udp(addr, port, policy).await {
                Some(s) => s,
                None => return,
            };

            info!(port, "UDP socket bound on 127.0.0.1:{port}");

            // Read local datagrams and send via QUIC datagrams.
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, _addr)) => {
                        let packet = protocol::Packet::UdpData {
                            port,
                            data: buf[..len].to_vec(),
                        };
                        match protocol::encode(&packet) {
                            Ok(encoded) => {
                                if let Err(e) = connection.send_datagram(encoded) {
                                    debug!(port, %e, "failed to send QUIC datagram");
                                }
                            }
                            Err(e) => {
                                error!(port, %e, "failed to encode UDP packet");
                            }
                        }
                    }
                    Err(e) => {
                        error!(port, %e, "UDP recv error");
                        break;
                    }
                }
            }
        });

        self.bindings
            .insert((port, Protocol::Udp), Binding { task });
    }
}

// ---------------------------------------------------------------------------
// Conflict resolution: bind with retry
// ---------------------------------------------------------------------------

/// Try to bind a TCP listener, resolving conflicts according to the policy.
async fn try_bind_tcp(
    addr: SocketAddr,
    port: u16,
    policy: ConflictPolicy,
) -> Option<TcpListener> {
    // First attempt.
    match TcpListener::bind(addr).await {
        Ok(l) => return Some(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Fall through to conflict resolution.
        }
        Err(e) => {
            error!(port, %e, "failed to bind TCP port");
            return None;
        }
    }

    // Port is in use - resolve the conflict.
    if !resolve_conflict(port, "TCP", TransportProto::Tcp, policy).await {
        return None;
    }

    // Retry bind after killing the conflicting process.
    retry_bind_tcp(addr, port).await
}

/// Try to bind a UDP socket, resolving conflicts according to the policy.
async fn try_bind_udp(
    addr: SocketAddr,
    port: u16,
    policy: ConflictPolicy,
) -> Option<tokio::net::UdpSocket> {
    // First attempt.
    match tokio::net::UdpSocket::bind(addr).await {
        Ok(s) => return Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Fall through to conflict resolution.
        }
        Err(e) => {
            error!(port, %e, "failed to bind UDP port");
            return None;
        }
    }

    // Port is in use - resolve the conflict.
    if !resolve_conflict(port, "UDP", TransportProto::Udp, policy).await {
        return None;
    }

    // Retry bind after killing the conflicting process.
    retry_bind_udp(addr, port).await
}

/// Resolve a port conflict according to the policy.
///
/// Returns `true` if the conflict was resolved (process killed),
/// `false` if the port should be skipped.
async fn resolve_conflict(
    port: u16,
    proto_name: &str,
    transport: TransportProto,
    policy: ConflictPolicy,
) -> bool {
    // Look up who owns the port. This shells out to `lsof` on macOS (can take
    // 200-500ms), so run on the blocking threadpool to avoid starving the
    // async runtime.
    let process_info =
        tokio::task::spawn_blocking(move || process::find_listener(port, transport))
            .await
            .ok()
            .flatten();

    match policy {
        ConflictPolicy::AutoSkip => {
            if let Some(ref info) = process_info {
                info!(
                    port,
                    proto = proto_name,
                    pid = info.pid,
                    process = %info.name,
                    "port conflict, skipping (auto-skip policy)"
                );
            } else {
                info!(
                    port,
                    proto = proto_name,
                    "port conflict (unknown process), skipping (auto-skip policy)"
                );
            }
            false
        }
        ConflictPolicy::AutoKill => {
            if let Some(ref info) = process_info {
                info!(
                    port,
                    proto = proto_name,
                    pid = info.pid,
                    process = %info.name,
                    "port conflict, killing process (auto-kill policy)"
                );
                // kill_process() calls thread::sleep (up to 1.1s total),
                // so run on blocking threadpool.
                let info_clone = info.clone();
                tokio::task::spawn_blocking(move || kill_and_report(&info_clone))
                    .await
                    .unwrap_or(false)
            } else {
                warn!(
                    port,
                    proto = proto_name,
                    "port conflict but cannot identify process, skipping"
                );
                false
            }
        }
        ConflictPolicy::Interactive => {
            interactive_resolve(port, proto_name, process_info).await
        }
    }
}

/// Prompt the user interactively to decide whether to kill a conflicting
/// process. Runs the blocking dialoguer prompt in `spawn_blocking` to avoid
/// freezing the async runtime.
async fn interactive_resolve(
    port: u16,
    proto_name: &str,
    process_info: Option<ProcessInfo>,
) -> bool {
    let Some(info) = process_info else {
        warn!(
            port,
            proto = proto_name,
            "port conflict but cannot identify process, skipping"
        );
        return false;
    };

    let pid = info.pid;
    let name = info.name.clone();
    let proto_owned = proto_name.to_string();

    // Run the interactive prompt in a blocking thread so we don't
    // freeze heartbeats and other async work.
    let should_kill = tokio::task::spawn_blocking(move || {
        let prompt = format!(
            "Remote port {port} ({proto_owned}) is active, but local port {port} is held by: {name} (PID: {pid})\n\
             Kill this process?"
        );
        dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if should_kill {
        info!(port, pid, process = %info.name, "user chose to kill conflicting process");
        kill_and_report(&info)
    } else {
        info!(port, pid, process = %info.name, "user chose to skip conflicting port");
        false
    }
}

/// Kill a process and report success/failure.
/// Returns `true` if the process was successfully killed.
fn kill_and_report(info: &ProcessInfo) -> bool {
    match process::kill_process(info.pid) {
        Ok(()) => {
            info!(pid = info.pid, process = %info.name, "process killed successfully");
            true
        }
        Err(e) => {
            error!(pid = info.pid, process = %info.name, %e, "failed to kill process");
            false
        }
    }
}

/// Retry binding a TCP listener after conflict resolution (with backoff).
async fn retry_bind_tcp(addr: SocketAddr, port: u16) -> Option<TcpListener> {
    for attempt in 1..=MAX_BIND_RETRIES {
        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        match TcpListener::bind(addr).await {
            Ok(l) => {
                info!(port, attempt, "TCP bind succeeded on retry");
                return Some(l);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                debug!(port, attempt, "TCP port still in use, retrying...");
            }
            Err(e) => {
                error!(port, %e, "failed to bind TCP port on retry");
                return None;
            }
        }
    }
    error!(
        port,
        retries = MAX_BIND_RETRIES,
        "TCP bind failed after all retries"
    );
    None
}

/// Retry binding a UDP socket after conflict resolution (with backoff).
async fn retry_bind_udp(addr: SocketAddr, port: u16) -> Option<tokio::net::UdpSocket> {
    for attempt in 1..=MAX_BIND_RETRIES {
        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(s) => {
                info!(port, attempt, "UDP bind succeeded on retry");
                return Some(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                debug!(port, attempt, "UDP port still in use, retrying...");
            }
            Err(e) => {
                error!(port, %e, "failed to bind UDP port on retry");
                return None;
            }
        }
    }
    error!(
        port,
        retries = MAX_BIND_RETRIES,
        "UDP bind failed after all retries"
    );
    None
}

// ---------------------------------------------------------------------------
// TCP forwarding
// ---------------------------------------------------------------------------

/// Forward a single TCP connection through a QUIC bidirectional stream.
///
/// Protocol:
/// 1. Host opens QUIC bi-stream, sends framed `TcpStreamInit { port }`
/// 2. Agent reads init, connects to localhost:port
/// 3. Agent sends 1-byte status: 0x00 = OK, 0x01 = error
/// 4. On error, agent sends framed `TcpStreamError` then closes
/// 5. On success, bidirectional raw byte copy begins
async fn forward_tcp_connection(
    connection: Connection,
    tcp_stream: tokio::net::TcpStream,
    port: u16,
) {
    // Open a new QUIC bidirectional stream for this TCP connection.
    let (mut quic_send, mut quic_recv) = match connection.open_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            error!(port, %e, "failed to open QUIC stream for TCP forward");
            return;
        }
    };

    // Send TcpStreamInit to tell the agent which port to connect to.
    let init_msg = ControlMsg::TcpStreamInit { port };
    if let Err(e) = send_framed(&mut quic_send, &init_msg).await {
        error!(port, %e, "failed to send TcpStreamInit");
        return;
    }

    // Read 1-byte status from agent.
    let mut status = [0u8; 1];
    match quic_recv.read_exact(&mut status).await {
        Ok(()) => {}
        Err(e) => {
            error!(port, %e, "agent closed stream before status byte");
            return;
        }
    }

    if status[0] != 0x00 {
        // Error - read the framed error message.
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
        return;
    }

    debug!(port, "TCP tunnel established, starting bidirectional copy");

    // Split TCP stream and copy bidirectionally.
    // Use join! to respect TCP half-close semantics (both directions complete independently).
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let host_to_agent = async {
        let r = tokio::io::copy(&mut tcp_read, &mut quic_send).await;
        let _ = quic_send.finish();
        r
    };
    let agent_to_host = tokio::io::copy(&mut quic_recv, &mut tcp_write);

    let (r1, r2) = tokio::join!(host_to_agent, agent_to_host);
    if let Err(e) = r1 {
        debug!(port, %e, "host->agent copy ended");
    }
    if let Err(e) = r2 {
        debug!(port, %e, "agent->host copy ended");
    }

    debug!(port, "TCP tunnel closed");
}

// ---------------------------------------------------------------------------
// Framed message helpers for per-stream messages
// ---------------------------------------------------------------------------

async fn send_framed(
    send: &mut quinn::SendStream,
    msg: &ControlMsg,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = protocol::encode(msg)?;
    let len = payload.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&payload).await?;
    Ok(())
}

async fn recv_framed(
    recv: &mut quinn::RecvStream,
) -> Result<ControlMsg, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > 1_048_576 {
        return Err("frame too large".into());
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await?;
    let msg = protocol::decode::<ControlMsg>(&buf)?;
    Ok(msg)
}
