use crate::error::{ForwardError, Result};
use crate::tcp::{TcpTunnel, TunnelHandle};
use crate::udp::{start_udp_tunnel, TunnelStopReason, UdpProxyManager, UdpTunnelHandle};
use port_linker_notify::{NotificationEvent, Notifier, PortInfo};
use port_linker_proto::Protocol;
use port_linker_ssh::{
    find_process_on_port, kill_process, prompt_kill, ClientHandler, RemotePort, SshClient,
};
use russh::client::Handle;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, error, info, instrument, trace, warn};

/// Key for tracking tunnels - combines port and protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelKey {
    pub port: u16,
    pub protocol: Protocol,
}

impl TunnelKey {
    pub fn new(port: u16, protocol: Protocol) -> Self {
        Self { port, protocol }
    }
}

pub struct ForwardManager {
    tcp_tunnels: HashMap<u16, TunnelHandle>,
    udp_tunnels: HashMap<u16, UdpTunnelHandle>,
    udp_proxy_manager: UdpProxyManager,
    ssh_handle: Arc<Handle<ClientHandler>>,
    ssh_client: Option<Arc<SshClient>>,
    notifier: Arc<Notifier>,
    auto_kill: bool,
    port_filter: Option<Vec<u16>>,
    excluded_ports: HashSet<u16>,
}

impl ForwardManager {
    pub fn new(
        ssh_handle: Arc<Handle<ClientHandler>>,
        notifier: Arc<Notifier>,
        auto_kill: bool,
        port_filter: Option<Vec<u16>>,
        excluded_ports: HashSet<u16>,
    ) -> Self {
        Self {
            tcp_tunnels: HashMap::new(),
            udp_tunnels: HashMap::new(),
            udp_proxy_manager: UdpProxyManager::new(),
            ssh_handle,
            ssh_client: None,
            notifier,
            auto_kill,
            port_filter,
            excluded_ports,
        }
    }

    /// Set the SSH client reference for UDP tunneling.
    pub fn set_ssh_client(&mut self, client: Arc<SshClient>) {
        self.ssh_client = Some(client);
    }

    pub fn update_ssh_handle(&mut self, handle: Arc<Handle<ClientHandler>>) {
        self.ssh_handle = handle;
    }

    /// Sync TCP forwards (legacy method for backward compatibility).
    pub async fn sync_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        self.sync_tcp_forwards(remote_ports).await
    }

    /// Sync all forwards, separating TCP and UDP.
    #[instrument(name = "sync_forwards", skip(self, remote_ports), fields(port_count = remote_ports.len()))]
    pub async fn sync_all_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        let (tcp_ports, udp_ports): (Vec<_>, Vec<_>) = remote_ports
            .into_iter()
            .partition(|p| p.protocol == Protocol::Tcp);

        self.sync_tcp_forwards(tcp_ports).await?;
        self.sync_udp_forwards(udp_ports).await?;

        Ok(())
    }

    /// Sync TCP port forwards.
    #[instrument(name = "sync_tcp", skip(self, remote_ports), fields(port_count = remote_ports.len()))]
    async fn sync_tcp_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        // Filter out excluded ports
        let non_excluded: Vec<RemotePort> = remote_ports
            .into_iter()
            .filter(|p| {
                if self.excluded_ports.contains(&p.port) {
                    trace!("Excluding TCP port {} (in exclusion list)", p.port);
                    false
                } else {
                    true
                }
            })
            .collect();

        // Apply include filter if set
        let desired_ports: Vec<RemotePort> = if let Some(filter) = &self.port_filter {
            non_excluded
                .into_iter()
                .filter(|p| filter.contains(&p.port))
                .collect()
        } else {
            non_excluded
        };

        let desired_port_nums: HashSet<u16> = desired_ports.iter().map(|p| p.port).collect();
        let current_port_nums: HashSet<u16> = self.tcp_tunnels.keys().cloned().collect();

        // Remove tunnels that are no longer needed
        let to_remove: Vec<u16> = current_port_nums
            .difference(&desired_port_nums)
            .cloned()
            .collect();

        let mut removed_ports = Vec::new();
        for port in to_remove {
            if let Some(handle) = self.tcp_tunnels.remove(&port) {
                info!("Removing TCP tunnel for port {}", port);
                handle.shutdown();
                removed_ports.push(PortInfo::new_with_protocol(
                    port,
                    None,
                    Protocol::Tcp,
                    self.notifier.mapping(),
                ));
            }
        }

        self.notifier.notify_ports_removed(removed_ports).await;

        // Add new tunnels
        let to_add: Vec<RemotePort> = desired_ports
            .into_iter()
            .filter(|p| !current_port_nums.contains(&p.port))
            .collect();

        let mut added_ports = Vec::new();
        for remote_port in to_add {
            match self.add_tcp_tunnel_silent(&remote_port).await {
                Ok(()) => {
                    added_ports.push(PortInfo::new_with_protocol(
                        remote_port.port,
                        remote_port.process_name.as_deref(),
                        Protocol::Tcp,
                        self.notifier.mapping(),
                    ));
                }
                Err(ForwardError::PortInUse(port)) => {
                    if let Some(port_info) = self
                        .handle_port_conflict(port, &remote_port, Protocol::Tcp)
                        .await?
                    {
                        added_ports.push(port_info);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to add TCP tunnel for port {}: {}",
                        remote_port.port, e
                    );
                }
            }
        }

        self.notifier.notify_ports_forwarded(added_ports).await;

        Ok(())
    }

    /// Sync UDP port forwards.
    #[instrument(name = "sync_udp", skip(self, remote_ports), fields(port_count = remote_ports.len()))]
    async fn sync_udp_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        let client = match &self.ssh_client {
            Some(c) => c.clone(),
            None => {
                warn!("SSH client not set, skipping UDP forwarding");
                return Ok(());
            }
        };

        // Filter out excluded ports
        let non_excluded: Vec<RemotePort> = remote_ports
            .into_iter()
            .filter(|p| {
                if self.excluded_ports.contains(&p.port) {
                    trace!("Excluding UDP port {} (in exclusion list)", p.port);
                    false
                } else {
                    true
                }
            })
            .collect();

        // Apply include filter if set
        let desired_ports: Vec<RemotePort> = if let Some(filter) = &self.port_filter {
            non_excluded
                .into_iter()
                .filter(|p| filter.contains(&p.port))
                .collect()
        } else {
            non_excluded
        };

        let desired_port_nums: HashSet<u16> = desired_ports.iter().map(|p| p.port).collect();
        let current_port_nums: HashSet<u16> = self.udp_tunnels.keys().cloned().collect();

        // Remove tunnels that are no longer needed
        let to_remove: Vec<u16> = current_port_nums
            .difference(&desired_port_nums)
            .cloned()
            .collect();

        let mut removed_ports = Vec::new();
        for port in to_remove {
            if let Some(handle) = self.udp_tunnels.remove(&port) {
                info!("Removing UDP tunnel for port {}", port);
                handle.shutdown();
                removed_ports.push(PortInfo::new_with_protocol(
                    port,
                    None,
                    Protocol::Udp,
                    self.notifier.mapping(),
                ));
            }
        }

        self.notifier.notify_ports_removed(removed_ports).await;

        // Add new tunnels
        let to_add: Vec<RemotePort> = desired_ports
            .into_iter()
            .filter(|p| !current_port_nums.contains(&p.port))
            .collect();

        if to_add.is_empty() {
            return Ok(());
        }

        // Ensure UDP proxy is deployed
        let proxy_path = match self.udp_proxy_manager.ensure_deployed(&client).await {
            Ok(path) => path,
            Err(e) => {
                error!("Failed to deploy UDP proxy: {}", e);
                return Ok(()); // Don't fail the whole sync
            }
        };

        let mut added_ports = Vec::new();
        for remote_port in to_add {
            match start_udp_tunnel(
                &client,
                &proxy_path,
                remote_port.port,
                &remote_port.bind_address,
                None,
            )
            .await
            {
                Ok(handle) => {
                    added_ports.push(PortInfo::new_with_protocol(
                        remote_port.port,
                        remote_port.process_name.as_deref(),
                        Protocol::Udp,
                        self.notifier.mapping(),
                    ));
                    self.udp_tunnels.insert(remote_port.port, handle);
                }
                Err(ForwardError::PortInUse(port)) => {
                    if let Some(port_info) = self
                        .handle_port_conflict(port, &remote_port, Protocol::Udp)
                        .await?
                    {
                        added_ports.push(port_info);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to add UDP tunnel for port {}: {}",
                        remote_port.port, e
                    );
                }
            }
        }

        self.notifier.notify_ports_forwarded(added_ports).await;

        Ok(())
    }

    async fn add_tcp_tunnel_silent(&mut self, remote_port: &RemotePort) -> Result<()> {
        let port = remote_port.port;

        let handle =
            TcpTunnel::start(self.ssh_handle.clone(), remote_port.clone(), None).await?;

        self.tcp_tunnels.insert(port, handle);
        Ok(())
    }

    #[instrument(name = "handle_conflict", skip(self, remote_port), fields(port = port, protocol = ?protocol))]
    async fn handle_port_conflict(
        &mut self,
        port: u16,
        remote_port: &RemotePort,
        protocol: Protocol,
    ) -> Result<Option<PortInfo>> {
        self.notifier
            .notify_event(NotificationEvent::ConflictDetected { port })
            .await;

        if let Some(proc_info) = find_process_on_port(port) {
            let should_kill = if self.auto_kill {
                true
            } else {
                prompt_kill(&proc_info, port).map_err(|e| ForwardError::PortForward {
                    port,
                    message: format!("Failed to prompt for process kill: {}", e),
                })?
            };

            if should_kill {
                kill_process(&proc_info).map_err(|e| ForwardError::PortForward {
                    port,
                    message: format!("Failed to kill process: {}", e),
                })?;

                self.notifier
                    .notify_event(NotificationEvent::ProcessKilled {
                        port,
                        process_name: proc_info.name.clone(),
                    })
                    .await;

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                match protocol {
                    Protocol::Tcp => {
                        if self.add_tcp_tunnel_silent(remote_port).await.is_ok() {
                            return Ok(Some(PortInfo::new_with_protocol(
                                port,
                                remote_port.process_name.as_deref(),
                                protocol,
                                self.notifier.mapping(),
                            )));
                        }
                    }
                    Protocol::Udp => {
                        if let Some(client) = &self.ssh_client {
                            if let Ok(proxy_path) =
                                self.udp_proxy_manager.ensure_deployed(client).await
                            {
                                if let Ok(handle) = start_udp_tunnel(
                                    client,
                                    &proxy_path,
                                    remote_port.port,
                                    &remote_port.bind_address,
                                    None,
                                )
                                .await
                                {
                                    self.udp_tunnels.insert(remote_port.port, handle);
                                    return Ok(Some(PortInfo::new_with_protocol(
                                        port,
                                        remote_port.process_name.as_deref(),
                                        protocol,
                                        self.notifier.mapping(),
                                    )));
                                }
                            }
                        }
                    }
                }
            } else {
                warn!(
                    "{} port {} conflict not resolved - skipping forward",
                    protocol, port
                );
            }
        } else {
            warn!(
                "Port {} in use but couldn't identify process (try: sudo lsof -i :{})",
                port, port
            );
        }

        Ok(None)
    }

    pub fn active_tcp_tunnels(&self) -> Vec<u16> {
        self.tcp_tunnels.keys().cloned().collect()
    }

    pub fn active_udp_tunnels(&self) -> Vec<u16> {
        self.udp_tunnels.keys().cloned().collect()
    }

    pub fn active_tunnels(&self) -> Vec<u16> {
        self.tcp_tunnels.keys().cloned().collect()
    }

    /// Check for dead UDP tunnels and restart them.
    /// Returns the number of tunnels that were restarted.
    pub async fn check_and_restart_dead_udp_tunnels(
        &mut self,
        remote_ports: &[RemotePort],
    ) -> usize {
        let client = match &self.ssh_client {
            Some(c) => c.clone(),
            None => return 0,
        };

        // Find dead tunnels
        let mut dead_ports: Vec<(u16, TunnelStopReason)> = Vec::new();
        for (port, handle) in self.udp_tunnels.iter_mut() {
            if !handle.is_alive() {
                // Try to get the reason from the death receiver
                let reason = handle
                    .take_death_receiver()
                    .and_then(|mut rx| rx.try_recv().ok())
                    .unwrap_or(TunnelStopReason::ChannelClosed);
                dead_ports.push((*port, reason));
            }
        }

        if dead_ports.is_empty() {
            return 0;
        }

        // Remove dead tunnels
        for (port, reason) in &dead_ports {
            if let Some(handle) = self.udp_tunnels.remove(port) {
                info!(
                    "Removing dead UDP tunnel for port {} (reason: {:?})",
                    port, reason
                );
                // Don't call shutdown() - the tunnel is already dead
                drop(handle);
            }
        }

        // Ensure UDP proxy is deployed (it might need to be redeployed)
        let proxy_path = match self.udp_proxy_manager.ensure_deployed(&client).await {
            Ok(path) => path,
            Err(e) => {
                error!("Failed to deploy UDP proxy for restart: {}", e);
                return 0;
            }
        };

        // Restart dead tunnels
        let mut restarted = 0;
        for (port, reason) in dead_ports {
            // Find the remote port info
            let remote_port = remote_ports.iter().find(|p| p.port == port);
            let (bind_address, _process_name) = match remote_port {
                Some(p) => (p.bind_address.as_str(), p.process_name.as_deref()),
                None => {
                    // Port no longer exists on remote, skip
                    debug!(
                        "UDP port {} no longer exists on remote, not restarting",
                        port
                    );
                    continue;
                }
            };

            info!(
                "Restarting UDP tunnel for port {} (was stopped due to {:?})",
                port, reason
            );

            match start_udp_tunnel(&client, &proxy_path, port, bind_address, None).await {
                Ok(handle) => {
                    self.udp_tunnels.insert(port, handle);
                    restarted += 1;

                    // Notify about restart
                    self.notifier
                        .notify_event(NotificationEvent::TunnelRestarted {
                            port,
                            protocol: Protocol::Udp,
                        })
                        .await;
                }
                Err(e) => {
                    error!("Failed to restart UDP tunnel for port {}: {}", port, e);
                }
            }
        }

        if restarted > 0 {
            info!("Restarted {} UDP tunnel(s)", restarted);
        }

        restarted
    }

    #[instrument(name = "manager_shutdown", skip(self))]
    pub async fn shutdown(&mut self) {
        info!("Shutting down all tunnels");

        // Shutdown TCP tunnels
        let tcp_ports: Vec<u16> = self.tcp_tunnels.keys().cloned().collect();
        for port in tcp_ports {
            if let Some(handle) = self.tcp_tunnels.remove(&port) {
                handle.shutdown();
            }
        }

        // Shutdown UDP tunnels
        let udp_ports: Vec<u16> = self.udp_tunnels.keys().cloned().collect();
        for port in udp_ports {
            if let Some(handle) = self.udp_tunnels.remove(&port) {
                handle.shutdown();
            }
        }

        // Clean up remote UDP proxy
        if let Some(client) = &self.ssh_client {
            self.udp_proxy_manager.cleanup(client).await;
        }
    }
}
