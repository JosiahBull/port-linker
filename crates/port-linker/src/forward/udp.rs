//! UDP tunnel implementation using embedded udp-proxy binary.
//!
//! This module handles the local side of UDP tunneling:
//! 1. Detects the remote system architecture
//! 2. Transfers the appropriate udp-proxy binary to the remote host
//! 3. Starts the proxy via SSH
//! 4. Binds a local UDP socket
//! 5. Forwards UDP packets through the SSH channel to the remote proxy

use crate::error::{PortLinkerError, Result};
use crate::ssh::SshClient;
use port_linker_proto::{Message, UdpPacket};
use port_linker_udp_embed::get_binary_for_system;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::{interval, Instant};
use tracing::{debug, error, info, trace, warn};

/// Interval between healthcheck pings sent to the remote proxy.
const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout for considering the proxy dead if no pong is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(45);

/// Detect the remote system's OS and architecture.
async fn detect_remote_system(client: &SshClient) -> Result<(String, String)> {
    // Get OS type (Linux, Darwin, etc.)
    let os = client
        .exec("uname -s 2>/dev/null || echo unknown")
        .await
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|_| "unknown".to_string());

    // Get architecture (x86_64, aarch64, arm64, etc.)
    let arch = client
        .exec("uname -m 2>/dev/null || echo unknown")
        .await
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_else(|_| "unknown".to_string());

    debug!("Detected remote system: os={}, arch={}", os, arch);
    Ok((os, arch))
}

/// Reason why a UDP tunnel stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStopReason {
    /// Explicit shutdown requested
    Shutdown,
    /// Remote proxy stopped responding to healthchecks
    HealthcheckTimeout,
    /// SSH channel closed unexpectedly
    ChannelClosed,
}

/// Handle to a running UDP tunnel.
pub struct UdpTunnelHandle {
    pub local_port: u16,
    pub remote_port: u16,
    shutdown_tx: oneshot::Sender<()>,
    /// Receiver for tunnel death notifications
    death_rx: Option<oneshot::Receiver<TunnelStopReason>>,
}

impl std::fmt::Debug for UdpTunnelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTunnelHandle")
            .field("local_port", &self.local_port)
            .field("remote_port", &self.remote_port)
            .finish()
    }
}

impl UdpTunnelHandle {
    /// Shutdown the UDP tunnel.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Take the death notification receiver.
    /// This can be used to detect when the tunnel dies unexpectedly.
    pub fn take_death_receiver(&mut self) -> Option<oneshot::Receiver<TunnelStopReason>> {
        self.death_rx.take()
    }

    /// Check if the tunnel is still running.
    pub fn is_alive(&mut self) -> bool {
        if let Some(ref mut rx) = self.death_rx {
            matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty))
        } else {
            // No death receiver means we can't tell
            true
        }
    }
}

/// Manager for deploying and running the UDP proxy on remote hosts.
pub struct UdpProxyManager {
    /// Path where the proxy binary is deployed on the remote
    remote_proxy_path: Option<String>,
    /// Cached remote system info (os, arch)
    remote_system: Option<(String, String)>,
}

impl UdpProxyManager {
    pub fn new() -> Self {
        Self {
            remote_proxy_path: None,
            remote_system: None,
        }
    }

    /// Deploy the UDP proxy binary to the remote host if not already deployed.
    pub async fn ensure_deployed(&mut self, client: &SshClient) -> Result<String> {
        if let Some(ref path) = self.remote_proxy_path {
            // Check if still exists
            let check = client.exec(&format!("test -x {} && echo ok", path)).await;
            if check.map(|s| s.trim() == "ok").unwrap_or(false) {
                return Ok(path.clone());
            }
        }

        // Detect remote system if not cached
        let (os, arch) = if let Some(ref sys) = self.remote_system {
            sys.clone()
        } else {
            let sys = detect_remote_system(client).await?;
            self.remote_system = Some(sys.clone());
            sys
        };

        // Get the appropriate binary for this remote system
        let binary = get_binary_for_system(&os, &arch).ok_or_else(|| {
            PortLinkerError::UnsupportedPlatform {
                os: os.clone(),
                arch: arch.clone(),
            }
        })?;

        // Deploy new binary
        let path = format!("/tmp/udp-proxy-{}", std::process::id());
        info!(
            "Deploying UDP proxy to remote: {} (os={}, arch={}, size={})",
            path,
            os,
            arch,
            binary.len()
        );

        client.write_file(&path, binary).await?;
        client.exec(&format!("chmod +x {}", path)).await?;

        self.remote_proxy_path = Some(path.clone());
        Ok(path)
    }

    /// Clean up the deployed binary.
    pub async fn cleanup(&self, client: &SshClient) {
        if let Some(ref path) = self.remote_proxy_path {
            let _ = client.exec(&format!("rm -f {}", path)).await;
        }
    }
}

impl Default for UdpProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Start a UDP tunnel for a specific port.
pub async fn start_udp_tunnel(
    client: &SshClient,
    proxy_path: &str,
    remote_port: u16,
    bind_address: &str,
    local_port: Option<u16>,
) -> Result<UdpTunnelHandle> {
    let local_port = local_port.unwrap_or(remote_port);

    // Normalize bind address for the remote proxy
    let target_addr = match bind_address {
        "0.0.0.0" | "::" | "*" => "127.0.0.1",
        addr => addr,
    };

    // Start the UDP proxy on the remote
    let cmd = format!("{} {} {}", proxy_path, target_addr, remote_port);
    debug!("Starting remote UDP proxy: {}", cmd);

    let channel = client.exec_channel(&cmd).await?;

    // Bind local UDP socket
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", local_port))
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                PortLinkerError::PortInUse(local_port)
            } else {
                PortLinkerError::PortForward {
                    port: local_port,
                    message: format!("Failed to bind UDP socket: {}", e),
                }
            }
        })?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (death_tx, death_rx) = oneshot::channel();

    // Spawn the forwarding task
    tokio::spawn(udp_forward_loop(
        socket,
        channel,
        local_port,
        remote_port,
        shutdown_rx,
        death_tx,
    ));

    info!(
        "UDP tunnel started: localhost:{} -> remote:{}",
        local_port, remote_port
    );

    Ok(UdpTunnelHandle {
        local_port,
        remote_port,
        shutdown_tx,
        death_rx: Some(death_rx),
    })
}

/// Main forwarding loop for UDP tunnel.
async fn udp_forward_loop(
    socket: UdpSocket,
    mut channel: russh::Channel<russh::client::Msg>,
    local_port: u16,
    remote_port: u16,
    mut shutdown_rx: oneshot::Receiver<()>,
    death_tx: oneshot::Sender<TunnelStopReason>,
) {
    // Track client addresses for response routing
    let mut client_map: HashMap<u32, SocketAddr> = HashMap::new();
    let packet_id = AtomicU32::new(0);

    let mut recv_buf = [0u8; 65535];
    let mut pending_from_remote = Vec::new();

    // Healthcheck state
    let mut healthcheck_interval = interval(HEALTHCHECK_INTERVAL);
    let mut last_pong = Instant::now();
    let mut ping_counter: u64 = 0;

    let stop_reason = loop {
        tokio::select! {
            // Send periodic healthcheck pings
            _ = healthcheck_interval.tick() => {
                // Check if we've timed out waiting for pong
                if last_pong.elapsed() > HEALTHCHECK_TIMEOUT {
                    warn!("UDP proxy healthcheck timeout for port {}", remote_port);
                    break TunnelStopReason::HealthcheckTimeout;
                }

                // Send ping
                ping_counter += 1;
                let ping = Message::Ping(ping_counter);
                if let Err(e) = channel.data(&ping.encode()[..]).await {
                    debug!("Failed to send healthcheck ping: {}", e);
                }
            }

            // Receive UDP packets from local clients
            result = socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        let id = packet_id.fetch_add(1, Ordering::Relaxed);
                        client_map.insert(id, src_addr);

                        let packet = UdpPacket::new(
                            src_addr.port(),
                            remote_port,
                            id,
                            recv_buf[..n].to_vec(),
                        );

                        // Send to remote via SSH channel using Message wrapper
                        let message = Message::Udp(packet);
                        if let Err(e) = channel.data(&message.encode()[..]).await {
                            debug!("Failed to send UDP packet to remote: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("UDP recv error on port {}: {}", local_port, e);
                    }
                }
            }

            // Receive data from SSH channel (responses from remote proxy)
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        pending_from_remote.extend_from_slice(&data);

                        // Process complete messages
                        while let Some((message, consumed)) = Message::decode(&pending_from_remote) {
                            match message {
                                Message::Udp(packet) => {
                                    // Route response back to the original client
                                    if let Some(&addr) = client_map.get(&packet.id) {
                                        if let Err(e) = socket.send_to(&packet.data, addr).await {
                                            debug!("Failed to send UDP response to {}: {}", addr, e);
                                        }
                                    } else {
                                        debug!("No client found for packet id {}", packet.id);
                                    }
                                }
                                Message::Pong(_value) => {
                                    // Update last pong time
                                    last_pong = Instant::now();
                                    trace!("Received healthcheck pong for port {}", remote_port);
                                }
                                Message::Ping(_) => {
                                    // Ignore unexpected ping from remote
                                }
                            }
                            pending_from_remote.drain(..consumed);
                        }
                    }
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        // Log stderr from the remote proxy
                        if let Ok(msg) = std::str::from_utf8(&data) {
                            warn!("UDP proxy stderr: {}", msg.trim());
                        }
                    }
                    Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                        debug!("UDP proxy channel closed for port {}", remote_port);
                        break TunnelStopReason::ChannelClosed;
                    }
                    _ => {}
                }
            }

            // Handle shutdown signal
            _ = &mut shutdown_rx => {
                debug!("Shutting down UDP tunnel for port {}", local_port);
                let _ = channel.close().await;
                break TunnelStopReason::Shutdown;
            }
        }
    };

    // Notify about tunnel death
    let _ = death_tx.send(stop_reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_proxy_binaries_available() {
        // At least one binary should be available via the embed crate
        let available = port_linker_udp_embed::available_targets();
        assert!(
            !available.is_empty(),
            "At least one udp-proxy binary should be available"
        );
    }

    #[test]
    fn test_get_binary_returns_none_for_unknown() {
        assert!(get_binary_for_system("windows", "x86_64").is_none());
        assert!(get_binary_for_system("freebsd", "amd64").is_none());
        assert!(get_binary_for_system("unknown", "unknown").is_none());
    }
}
