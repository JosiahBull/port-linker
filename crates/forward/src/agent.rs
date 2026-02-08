//! Agent session for communicating with the remote agent.
//!
//! The `AgentSession` wraps an SSH channel connected to the deployed agent binary.
//! It provides methods for requesting port scans, starting/stopping UDP forwarding,
//! and managing the agent lifecycle.

use crate::error::{ForwardError, Result};
use agent_embed::get_binary_for_system;
use proto::{LogEvent, LogLevel, Message, ScanFlags, UdpPacket};
use ssh::SshClient;
use scanner::{decode_remote_ports, BindAddress, RemotePort};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Instant};
use tracing::{debug, error, info, trace, warn};

/// Interval between healthcheck pings sent to the remote agent.
const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout for considering the agent dead if no pong is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(45);

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

        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (death_tx, death_rx) = oneshot::channel();

        // Spawn the background task
        tokio::spawn(agent_loop(channel, cmd_rx, death_tx));

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
        drop(client
            .exec(&format!("rm -f {}", self.remote_agent_path))
            .await);
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
        LogLevel::Error => error!(source = "agent", agent.target = %event.target, "{}", event.message),
        LogLevel::Warn => warn!(source = "agent", agent.target = %event.target, "{}", event.message),
        LogLevel::Info => info!(source = "agent", agent.target = %event.target, "{}", event.message),
        LogLevel::Debug => debug!(source = "agent", agent.target = %event.target, "{}", event.message),
        LogLevel::Trace => trace!(source = "agent", agent.target = %event.target, "{}", event.message),
    }
}

/// Background task that manages the SSH channel to the agent and routes messages.
async fn agent_loop(
    mut channel: russh::Channel<russh::client::Msg>,
    mut cmd_rx: mpsc::Receiver<AgentCommand>,
    death_tx: oneshot::Sender<AgentStopReason>,
) {
    let mut pending_from_remote = Vec::new();
    let mut pending_scan_reply: Option<oneshot::Sender<Result<Vec<RemotePort>>>> = None;

    // Local UDP sockets: port -> socket + client map
    let mut local_udp: HashMap<u16, LocalUdpForward> = HashMap::new();
    let mut recv_buf = [0_u8; 65535];

    // Healthcheck state
    let mut healthcheck_interval = interval(HEALTHCHECK_INTERVAL);
    let mut last_pong = Instant::now();
    let mut ping_counter: u64 = 0;

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
                if let Err(e) = channel.data(&*ping.encode()).await {
                    debug!("Failed to send healthcheck ping: {}", e);
                }
            }

            // Commands from ForwardManager
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(AgentCommand::Scan { flags, reply }) => {
                        let msg = Message::ScanRequest(flags);
                        if let Err(e) = channel.data(&*msg.encode()).await {
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
                        if let Err(e) = channel.data(&*msg.encode()).await {
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
                        drop(channel.data(&*msg.encode()).await);
                    }
                    Some(AgentCommand::Shutdown) | None => {
                        drop(channel.close().await);
                        break AgentStopReason::Shutdown;
                    }
                }
            }

            // Data from SSH channel (agent responses)
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        pending_from_remote.extend_from_slice(&data);

                        while let Some((message, consumed)) = Message::decode(&pending_from_remote) {
                            match message {
                                Message::Pong(_) => {
                                    last_pong = Instant::now();
                                    trace!("Received agent pong");
                                }
                                Message::ScanResponse(data) => {
                                    if let Some(reply) = pending_scan_reply.take() {
                                        let ports = decode_remote_ports(&data)
                                            .unwrap_or_default();
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
                        debug!("Agent channel closed");
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
            if let Err(e) = channel.data(&*msg.encode()).await {
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
