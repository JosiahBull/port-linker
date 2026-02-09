//! Agent session for communicating with the remote agent.
//!
//! The `AgentSession` wraps an SSH channel connected to the deployed agent binary.
//! It provides methods for requesting port scans, starting/stopping UDP forwarding,
//! and managing the agent lifecycle.

use crate::error::{ForwardError, Result};
use agent_embed::get_binary_for_system;
use proto::{LogEvent, LogLevel, Message, ScanFlags, UdpPacket};
use russh::client::Handle;
use scanner::{decode_remote_ports, BindAddress, RemotePort};
use ssh::{ClientHandler, SshClient};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Instant};
use transport::{NegotiationMessage, Transport, TransportAccept, TransportKind, select_transport};
use tracing::{debug, error, info, trace, warn};

/// Interval between healthcheck pings sent to the remote agent.
const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout for considering the agent dead if no pong is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(45);

/// Timeout for establishing the selected transport after negotiation.
/// Kept short so that failed QUIC/TCP attempts fall back quickly to stdio.
/// Real QUIC/TCP connections complete in <100ms; 1s is generous.
const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Detect the remote system's OS and architecture.
async fn detect_remote_system(client: &SshClient) -> Result<(String, String)> {
    let os = client
        .exec("uname -s 2>/dev/null || echo unknown")
        .await
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|_| "unknown".to_string());

    let arch = client
        .exec("uname -m 2>/dev/null || echo unknown")
        .await
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|_| "unknown".to_string());

    debug!("Detected remote system: os={}, arch={}", os, arch);
    Ok((os, arch))
}

/// Reason why the agent stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStopReason {
    /// Explicit shutdown requested
    Shutdown,
    /// Remote agent stopped responding to healthchecks
    HealthcheckTimeout,
    /// SSH channel closed unexpectedly
    ChannelClosed,
}

/// Handle for a local UDP socket forwarding through the agent.
struct LocalUdpForward {
    socket: UdpSocket,
    /// Map packet ID -> client address for routing responses back
    client_map: HashMap<u32, SocketAddr>,
    packet_counter: AtomicU32,
}

/// Commands sent from ForwardManager to the agent background task.
pub enum AgentCommand {
    /// Request a port scan
    Scan {
        flags: ScanFlags,
        reply: oneshot::Sender<Result<Vec<RemotePort>>>,
    },
    /// Start UDP forwarding for a port
    StartUdpForward {
        port: u16,
        bind_addr: BindAddress,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Stop UDP forwarding for a port
    StopUdpForward {
        port: u16,
    },
    /// Shutdown the agent
    Shutdown,
}

/// Handle to communicate with the agent background task.
pub struct AgentSession {
    cmd_tx: mpsc::Sender<AgentCommand>,
    /// Death notification receiver
    death_rx: Option<oneshot::Receiver<AgentStopReason>>,
    /// Path to the agent binary on the remote host
    remote_agent_path: String,
}

impl AgentSession {
    /// Deploy the agent binary and start a session.
    pub async fn deploy_and_start(client: &SshClient) -> Result<Self> {
        let (os, arch) = detect_remote_system(client).await?;

        // Get the appropriate binary
        let binary = get_binary_for_system(&os, &arch).ok_or_else(|| {
            ForwardError::UnsupportedPlatform {
                os: os.clone(),
                arch: arch.clone(),
            }
        })?;

        // Deploy the binary
        let path = format!("/tmp/port-linker-agent-{}", std::process::id());
        info!(
            "Deploying agent to remote: {} (os={}, arch={}, size={})",
            path,
            os,
            arch,
            binary.len()
        );

        client.write_file(&path, binary).await?;
        client.exec(&format!("chmod +x {}", path)).await?;

        // Start the agent
        let channel = client.exec_channel(&path).await?;

        let ssh_handle = client.handle();
        let remote_host = client.host().to_string();

        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (death_tx, death_rx) = oneshot::channel();

        // Spawn the background task
        tokio::spawn(agent_loop(
            channel,
            ssh_handle,
            remote_host,
            cmd_rx,
            death_tx,
        ));

        Ok(Self {
            cmd_tx,
            death_rx: Some(death_rx),
            remote_agent_path: path,
        })
    }

    /// Request a port scan from the remote agent.
    pub async fn request_scan(&self, flags: ScanFlags) -> Result<Vec<RemotePort>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(AgentCommand::Scan {
                flags,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ForwardError::PortForward {
                port: 0,
                message: "Agent session closed".to_string(),
            })?;

        reply_rx.await.map_err(|_| ForwardError::PortForward {
            port: 0,
            message: "Agent session dropped reply".to_string(),
        })?
    }

    /// Start UDP forwarding for a port through the agent.
    pub async fn start_udp_forward(&self, port: u16, bind_addr: &BindAddress) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(AgentCommand::StartUdpForward {
                port,
                bind_addr: bind_addr.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| ForwardError::PortForward {
                port,
                message: "Agent session closed".to_string(),
            })?;

        reply_rx.await.map_err(|_| ForwardError::PortForward {
            port,
            message: "Agent session dropped reply".to_string(),
        })?
    }

    /// Stop UDP forwarding for a port.
    pub async fn stop_udp_forward(&self, port: u16) {
        drop(self.cmd_tx.send(AgentCommand::StopUdpForward { port }).await);
    }

    /// Shutdown the agent session.
    pub async fn shutdown(&self) {
        drop(self.cmd_tx.send(AgentCommand::Shutdown).await);
    }

    /// Check if the agent is still running.
    pub fn is_alive(&mut self) -> bool {
        if let Some(ref mut rx) = self.death_rx {
            matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty))
        } else {
            false
        }
    }

    /// Get the remote agent path for cleanup.
    pub fn remote_path(&self) -> &str {
        &self.remote_agent_path
    }

    /// Clean up the deployed binary.
    pub async fn cleanup(&self, client: &SshClient) {
        drop(
            client
                .exec(&format!("rm -f {}", self.remote_agent_path))
                .await,
        );
    }
}

/// Encode a `BindAddress` into protocol wire format (type byte + address bytes).
fn encode_bind_addr(addr: &BindAddress) -> (u8, Vec<u8>) {
    match addr {
        BindAddress::V4(v4) => (4, v4.octets().to_vec()),
        BindAddress::V6(v6) => (6, v6.octets().to_vec()),
    }
}

/// Re-emit an agent log event through the host's tracing subscriber.
fn emit_agent_log(event: &LogEvent) {
    match event.level {
        LogLevel::Error => {
            error!(source = "agent", agent.target = %event.target, "{}", event.message)
        }
        LogLevel::Warn => {
            warn!(source = "agent", agent.target = %event.target, "{}", event.message)
        }
        LogLevel::Info => {
            info!(source = "agent", agent.target = %event.target, "{}", event.message)
        }
        LogLevel::Debug => {
            debug!(source = "agent", agent.target = %event.target, "{}", event.message)
        }
        LogLevel::Trace => {
            trace!(source = "agent", agent.target = %event.target, "{}", event.message)
        }
    }
}

/// Handle a decoded `Message` from the agent (non-UDP messages only).
///
/// UDP messages require async handling and must be processed at the call site.
async fn handle_agent_message(
    message: Message,
    last_pong: &mut Instant,
    pending_scan_reply: &mut Option<oneshot::Sender<Result<Vec<RemotePort>>>>,
    local_udp: &HashMap<u16, LocalUdpForward>,
) {
    match message {
        Message::Pong(_) => {
            *last_pong = Instant::now();
            trace!("Received agent pong");
        }
        Message::ScanResponse(data) => {
            if let Some(reply) = pending_scan_reply.take() {
                let ports = decode_remote_ports(&data).unwrap_or_default();
                drop(reply.send(Ok(ports)));
            }
        }
        Message::Udp(packet) => {
            // Route response back to the local UDP client
            if let Some(fwd) = local_udp.get(&packet.dst_port) {
                if let Some(&addr) = fwd.client_map.get(&packet.id) {
                    if let Err(e) = fwd.socket.send_to(&packet.data, addr).await {
                        debug!("Failed to send UDP response to {}: {}", addr, e);
                    }
                } else {
                    debug!("No client found for UDP packet id {}", packet.id);
                }
            }
        }
        Message::LogBatch(events) => {
            for event in &events {
                emit_agent_log(event);
            }
        }
        Message::Ping(_)
        | Message::ScanRequest(_)
        | Message::StartUdpForward { .. }
        | Message::StopUdpForward(_) => {
            // Unexpected from agent
        }
    }
}

/// Background task that manages the SSH channel to the agent and routes messages.
async fn agent_loop(
    mut channel: russh::Channel<russh::client::Msg>,
    ssh_handle: Arc<Handle<ClientHandler>>,
    remote_host: String,
    mut cmd_rx: mpsc::Receiver<AgentCommand>,
    death_tx: oneshot::Sender<AgentStopReason>,
) {
    let mut pending_from_remote = Vec::new();

    // --- Transport negotiation phase ---
    debug!("Waiting for transport negotiation from agent");
    let negotiation_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let negotiated = loop {
        match tokio::time::timeout_at(negotiation_deadline, channel.wait()).await {
            Ok(Some(russh::ChannelMsg::Data { data })) => {
                debug!(bytes = data.len(), total = pending_from_remote.len() + data.len(), "Read negotiation data from agent");
                pending_from_remote.extend_from_slice(&data);

                if NegotiationMessage::is_negotiation_type(&pending_from_remote) {
                    if let Some((msg, consumed)) =
                        NegotiationMessage::decode(&pending_from_remote)
                    {
                        if let NegotiationMessage::Offer(offer) = msg {
                            debug!(consumed, "Decoded TransportOffer from agent");
                            pending_from_remote.drain(..consumed);
                            break Some(offer);
                        }
                        // Unexpected Accept from agent
                        debug!("Received unexpected TransportAccept from agent");
                        pending_from_remote.drain(..consumed);
                        break None;
                    }
                    // Incomplete negotiation message, keep reading
                } else if pending_from_remote.len() >= 5 {
                    // First byte is not a negotiation type — old agent, no negotiation
                    debug!("Agent sent proto::Message without negotiation (legacy agent)");
                    break None;
                }
            }
            Ok(Some(russh::ChannelMsg::ExtendedData { data, .. })) => {
                // Agent stderr during negotiation, just log it
                if let Ok(msg) = std::str::from_utf8(&data) {
                    let trimmed = msg.trim();
                    if !trimmed.is_empty() {
                        warn!(source = "agent-stderr", "{}", trimmed);
                    }
                }
            }
            Ok(Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close)) | Ok(None) => {
                debug!("Agent channel closed during negotiation");
                break None;
            }
            Ok(Some(_)) => {}
            Err(_) => {
                debug!("Transport negotiation timed out after 2s, using SSH channel");
                break None;
            }
        }
    };

    // After negotiation, decide on data channel routing.
    //
    // Three modes:
    // - Stdio: data flows over the exec channel (same as before)
    // - TCP:   data flows over an SSH direct-tcpip channel; exec channel monitors stderr
    // - QUIC:  data flows over UDP via bridged mpsc channels; exec channel monitors stderr
    let mut ssh_data_channel: Option<russh::Channel<russh::client::Msg>> = None;
    let mut exec_channel: Option<russh::Channel<russh::client::Msg>> = None;
    let mut quic_incoming: Option<mpsc::UnboundedReceiver<Message>> = None;
    let mut quic_outgoing: Option<mpsc::UnboundedSender<Message>> = None;

    if let Some(offer) = negotiated {
        info!(
            count = offer.transports.len(),
            version = offer.version,
            "Agent offered transports",
        );
        for entry in &offer.transports {
            debug!(kind = ?entry.kind, data_len = entry.data.len(), "  Available transport");
        }

        // Auto-select best transport (QUIC > TCP > Stdio)
        let selected = select_transport(&offer.transports, None);
        info!(selected = ?selected, "Selected transport");

        // Send TransportAccept back to agent
        let accept = TransportAccept { kind: selected };
        let encoded = accept.encode();
        debug!(
            accept_bytes = encoded.len(),
            "Sending TransportAccept to agent"
        );
        if let Err(e) = channel.data(&*encoded).await {
            warn!("Failed to send TransportAccept: {}", e);
        }

        match selected {
            TransportKind::Stdio => {
                ssh_data_channel = Some(channel);
            }
            TransportKind::Tcp => {
                // Extract port from the TCP entry's data field
                let tcp_port = offer
                    .transports
                    .iter()
                    .find(|e| e.kind == TransportKind::Tcp)
                    .and_then(|e| {
                        let hi = *e.data.first()?;
                        let lo = *e.data.get(1)?;
                        Some(u16::from_be_bytes([hi, lo]))
                    });

                if let Some(port) = tcp_port {
                    debug!(port, "Opening SSH direct-tcpip channel for TCP transport");
                    match ssh_handle
                        .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)
                        .await
                    {
                        Ok(tcp_channel) => {
                            info!(port, "TCP transport connected via SSH direct-tcpip");
                            ssh_data_channel = Some(tcp_channel);
                            exec_channel = Some(channel);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to open direct-tcpip channel: {}, falling back to stdio",
                                e
                            );
                            ssh_data_channel = Some(channel);
                        }
                    }
                } else {
                    warn!("TCP selected but no port in offer data, falling back to stdio");
                    ssh_data_channel = Some(channel);
                }
            }
            TransportKind::Quic => {
                // Extract port + fingerprint from QUIC entry (port:2 BE + fingerprint:32 = 34 bytes)
                let quic_data = offer
                    .transports
                    .iter()
                    .find(|e| e.kind == TransportKind::Quic)
                    .filter(|e| e.data.len() >= 34);

                if let Some(entry) = quic_data {
                    let port = u16::from_be_bytes([entry.data[0], entry.data[1]]);
                    let mut fingerprint = [0_u8; 32];
                    fingerprint.copy_from_slice(&entry.data[2..34]);

                    debug!(
                        port,
                        fingerprint_prefix = ?&fingerprint[..8],
                        "Setting up QUIC transport"
                    );

                    // Resolve remote host to SocketAddr
                    let remote_addr_str = format!("{}:{}", remote_host, port);
                    match remote_addr_str.parse::<SocketAddr>().or_else(|_| {
                        use std::net::ToSocketAddrs;
                        remote_addr_str
                            .to_socket_addrs()
                            .map_err(|e| e.to_string())
                            .and_then(|mut addrs| {
                                addrs.next().ok_or_else(|| "no addresses".to_string())
                            })
                    }) {
                        Ok(remote_addr) => {
                            // Spawn a blocking bridge thread for QUIC.
                            // Use a oneshot to signal whether the QUIC handshake succeeded.
                            let (connected_tx, connected_rx) = oneshot::channel::<bool>();
                            let (bridge_tx, incoming_rx) = mpsc::unbounded_channel::<Message>();
                            let (outgoing_tx, mut outgoing_rx) =
                                mpsc::unbounded_channel::<Message>();

                            let _quic_handle = tokio::task::spawn_blocking(move || {
                                // Build QUIC client config
                                let client_config =
                                    match transport::quic_config::build_client_config(fingerprint) {
                                        Ok(c) => c,
                                        Err(e) => {
                                            warn!("QUIC client config failed: {}", e);
                                            let _ = connected_tx.send(false);
                                            return;
                                        }
                                    };

                                // Bind local UDP socket
                                let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!("Failed to bind UDP socket for QUIC: {}", e);
                                        let _ = connected_tx.send(false);
                                        return;
                                    }
                                };
                                if let Err(e) = socket.set_nonblocking(true) {
                                    warn!("Failed to set QUIC socket nonblocking: {}", e);
                                    let _ = connected_tx.send(false);
                                    return;
                                }

                                // Connect
                                let mut qt = match transport::quic::connect_quic_client(
                                    socket,
                                    remote_addr,
                                    client_config,
                                    TRANSPORT_CONNECT_TIMEOUT,
                                ) {
                                    Ok(qt) => {
                                        let _ = connected_tx.send(true);
                                        qt
                                    }
                                    Err(e) => {
                                        warn!("QUIC client connect failed: {}", e);
                                        let _ = connected_tx.send(false);
                                        return;
                                    }
                                };

                                debug!("QUIC bridge thread connected");

                                // Bridge loop
                                loop {
                                    // Drive QUIC state machine
                                    if let Err(e) = qt.poll() {
                                        debug!("QUIC poll error: {}", e);
                                        break;
                                    }

                                    // Receive messages from QUIC and forward to async world
                                    loop {
                                        match qt.try_recv() {
                                            Ok(Some(msg)) => {
                                                if bridge_tx.send(msg).is_err() {
                                                    debug!("QUIC bridge receiver dropped");
                                                    return;
                                                }
                                            }
                                            Ok(None) => break,
                                            Err(e) => {
                                                debug!("QUIC recv error: {}", e);
                                                return;
                                            }
                                        }
                                    }

                                    // Send messages from async world to QUIC
                                    while let Ok(msg) = outgoing_rx.try_recv() {
                                        if let Err(e) = qt.send(&msg) {
                                            debug!("QUIC send error: {}", e);
                                            return;
                                        }
                                    }

                                    std::thread::sleep(std::time::Duration::from_micros(100));
                                }
                            });

                            // Wait for the QUIC bridge to report connection success/failure.
                            // Use TRANSPORT_CONNECT_TIMEOUT + 1s margin for thread overhead.
                            let quic_ok = match tokio::time::timeout(
                                TRANSPORT_CONNECT_TIMEOUT + Duration::from_secs(1),
                                connected_rx,
                            )
                            .await
                            {
                                Ok(Ok(true)) => true,
                                Ok(Ok(false)) => {
                                    warn!("QUIC connection failed, falling back to stdio");
                                    false
                                }
                                Ok(Err(_)) => {
                                    warn!("QUIC bridge thread dropped signal, falling back to stdio");
                                    false
                                }
                                Err(_) => {
                                    warn!("QUIC connection timed out, falling back to stdio");
                                    false
                                }
                            };

                            if quic_ok {
                                info!("QUIC transport connected");
                                quic_incoming = Some(incoming_rx);
                                quic_outgoing = Some(outgoing_tx);
                                exec_channel = Some(channel);
                            } else {
                                ssh_data_channel = Some(channel);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to resolve remote address {}: {}, falling back to stdio",
                                remote_addr_str, e
                            );
                            ssh_data_channel = Some(channel);
                        }
                    }
                } else {
                    warn!("QUIC selected but insufficient offer data, falling back to stdio");
                    ssh_data_channel = Some(channel);
                }
            }
        }
    } else {
        debug!("No transport negotiation, using SSH channel directly");
        ssh_data_channel = Some(channel);
    }

    let mut pending_scan_reply: Option<oneshot::Sender<Result<Vec<RemotePort>>>> = None;

    // Local UDP sockets: port -> socket + client map
    let mut local_udp: HashMap<u16, LocalUdpForward> = HashMap::new();
    let mut recv_buf = [0_u8; 65535];

    // Healthcheck state
    let mut healthcheck_interval = interval(HEALTHCHECK_INTERVAL);
    let mut last_pong = Instant::now();
    let mut ping_counter: u64 = 0;

    // Helper macro: send a message via the active transport.
    // Returns Result<(), String> to unify error types across SSH and QUIC paths.
    macro_rules! send_message {
        ($msg:expr) => {{
            let __msg = $msg;
            if let Some(ref mut ch) = ssh_data_channel {
                let encoded = __msg.encode();
                ch.data(&*encoded).await.map_err(|e| e.to_string())
            } else if let Some(ref tx) = quic_outgoing {
                tx.send(__msg).map_err(|e| e.to_string())
            } else {
                Err("No transport available".to_string())
            }
        }};
    }

    let stop_reason = loop {
        tokio::select! {
            // Healthcheck ping timer
            _ = healthcheck_interval.tick() => {
                if last_pong.elapsed() > HEALTHCHECK_TIMEOUT {
                    warn!("Agent healthcheck timeout");
                    break AgentStopReason::HealthcheckTimeout;
                }

                ping_counter = ping_counter.wrapping_add(1);
                let ping = Message::Ping(ping_counter);
                if let Err(e) = send_message!(ping) {
                    debug!("Failed to send healthcheck ping: {}", e);
                }
            }

            // Commands from ForwardManager
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(AgentCommand::Scan { flags, reply }) => {
                        let msg = Message::ScanRequest(flags);
                        if let Err(e) = send_message!(msg) {
                            drop(reply.send(Err(ForwardError::PortForward {
                                port: 0,
                                message: format!("Failed to send scan request: {}", e),
                            })));
                        } else {
                            pending_scan_reply = Some(reply);
                        }
                    }
                    Some(AgentCommand::StartUdpForward { port, bind_addr, reply }) => {
                        let (addr_type, addr_bytes) = encode_bind_addr(&bind_addr);
                        let msg = Message::StartUdpForward {
                            port,
                            bind_addr_type: addr_type,
                            bind_addr: addr_bytes,
                        };
                        if let Err(e) = send_message!(msg) {
                            drop(reply.send(Err(ForwardError::PortForward {
                                port,
                                message: format!("Failed to send StartUdpForward: {}", e),
                            })));
                            continue;
                        }

                        // Bind local UDP socket
                        match UdpSocket::bind(format!("127.0.0.1:{}", port)).await {
                            Ok(socket) => {
                                local_udp.insert(port, LocalUdpForward {
                                    socket,
                                    client_map: HashMap::new(),
                                    packet_counter: AtomicU32::new(0),
                                });
                                drop(reply.send(Ok(())));
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::AddrInUse {
                                    drop(reply.send(Err(ForwardError::PortInUse(port))));
                                } else {
                                    drop(reply.send(Err(ForwardError::PortForward {
                                        port,
                                        message: format!("Failed to bind local UDP socket: {}", e),
                                    })));
                                }
                            }
                        }
                    }
                    Some(AgentCommand::StopUdpForward { port }) => {
                        local_udp.remove(&port);
                        let msg = Message::StopUdpForward(port);
                        drop(send_message!(msg));
                    }
                    Some(AgentCommand::Shutdown) | None => {
                        if let Some(ref mut ch) = ssh_data_channel {
                            drop(ch.close().await);
                        }
                        if let Some(ref mut ch) = exec_channel {
                            drop(ch.close().await);
                        }
                        break AgentStopReason::Shutdown;
                    }
                }
            }

            // Data from SSH data channel (Stdio or TCP mode)
            msg = async { ssh_data_channel.as_mut().unwrap().wait().await },
                if ssh_data_channel.is_some() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        pending_from_remote.extend_from_slice(&data);

                        while let Some((message, consumed)) = Message::decode(&pending_from_remote) {
                            handle_agent_message(message, &mut last_pong, &mut pending_scan_reply, &local_udp).await;
                            pending_from_remote.drain(..consumed);
                        }
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        if let Ok(msg) = std::str::from_utf8(&data) {
                            let trimmed = msg.trim();
                            if !trimmed.is_empty() {
                                warn!(source = "agent-stderr", "{}", trimmed);
                            }
                        }
                    }
                    Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => {
                        debug!("Agent SSH data channel closed");
                        break AgentStopReason::ChannelClosed;
                    }
                    _ => {}
                }
            }

            // Data from QUIC bridge (QUIC mode)
            msg = async { quic_incoming.as_mut().unwrap().recv().await },
                if quic_incoming.is_some() => {
                match msg {
                    Some(message) => {
                        handle_agent_message(message, &mut last_pong, &mut pending_scan_reply, &local_udp).await;
                    }
                    None => {
                        debug!("QUIC bridge channel closed");
                        break AgentStopReason::ChannelClosed;
                    }
                }
            }

            // Exec channel stderr monitoring (TCP/QUIC modes only)
            msg = async { exec_channel.as_mut().unwrap().wait().await },
                if exec_channel.is_some() => {
                match msg {
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        if let Ok(msg) = std::str::from_utf8(&data) {
                            let trimmed = msg.trim();
                            if !trimmed.is_empty() {
                                warn!(source = "agent-stderr", "{}", trimmed);
                            }
                        }
                    }
                    Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => {
                        debug!("Agent exec channel closed (process exited)");
                        break AgentStopReason::ChannelClosed;
                    }
                    _ => {}
                }
            }
        }

        // Poll all local UDP sockets for incoming packets to forward to the agent
        let mut ports_to_forward: Vec<(u16, u32, SocketAddr, Vec<u8>)> = Vec::new();
        for (&port, fwd) in &mut local_udp {
            match fwd.socket.try_recv_from(&mut recv_buf) {
                Ok((n, src_addr)) => {
                    let id = fwd.packet_counter.fetch_add(1, Ordering::Relaxed);
                    fwd.client_map.insert(id, src_addr);
                    ports_to_forward.push((
                        port,
                        id,
                        src_addr,
                        recv_buf.get(..n).unwrap_or(&[]).to_vec(),
                    ));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    debug!("Local UDP recv error on port {}: {}", port, e);
                }
            }
        }

        for (port, id, _src, data) in ports_to_forward {
            let packet = UdpPacket::new(0, port, id, data);
            let msg = Message::Udp(packet);
            if let Err(e) = send_message!(msg) {
                debug!("Failed to send UDP packet to agent: {}", e);
            }
        }
    };

    // If there was a pending scan reply, send an error
    if let Some(reply) = pending_scan_reply.take() {
        drop(reply.send(Err(ForwardError::PortForward {
            port: 0,
            message: "Agent session terminated".to_string(),
        })));
    }

    #[allow(
        clippy::let_underscore_must_use,
        dropping_copy_types,
        reason = "receiver may be dropped; nothing to do on send failure"
    )]
    let _ = death_tx.send(stop_reason);
}
