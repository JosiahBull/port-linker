use crate::agent::AgentSession;
use crate::error::{ForwardError, Result};
use crate::tcp::{TcpTunnel, TunnelHandle};
use port_linker_notify::{NotificationEvent, Notifier, PortInfo};
use port_linker_proto::Protocol;
use port_linker_ssh::{
    find_process_on_port, kill_process, prompt_kill, ClientHandler, RemotePort,
};
use russh::client::Handle;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{error, info, instrument, trace, warn};

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
    udp_forwarded_ports: HashSet<u16>,
    agent_session: Option<AgentSession>,
    ssh_handle: Arc<Handle<ClientHandler>>,
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
            udp_forwarded_ports: HashSet::new(),
            agent_session: None,
            ssh_handle,
            notifier,
            auto_kill,
            port_filter,
            excluded_ports,
        }
    }

    /// Set the agent session for scanning and UDP forwarding.
    pub fn set_agent_session(&mut self, session: AgentSession) {
        self.agent_session = Some(session);
    }

    /// Get a reference to the agent session.
    pub fn agent_session(&self) -> Option<&AgentSession> {
        self.agent_session.as_ref()
    }

    /// Get a mutable reference to the agent session (for health checking).
    pub fn agent_session_mut(&mut self) -> Option<&mut AgentSession> {
        self.agent_session.as_mut()
    }

    /// Remove and return the agent session, clearing tracked UDP forwards
    /// since the local sockets are owned by the agent's background task.
    pub fn take_agent_session(&mut self) -> Option<AgentSession> {
        self.udp_forwarded_ports.clear();
        self.agent_session.take()
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
        let current_port_nums: HashSet<u16> = self.tcp_tunnels.keys().copied().collect();

        // Remove tunnels that are no longer needed
        let to_remove: Vec<u16> = current_port_nums
            .difference(&desired_port_nums)
            .copied()
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

    /// Sync UDP port forwards via the agent session.
    #[instrument(name = "sync_udp", skip(self, remote_ports), fields(port_count = remote_ports.len()))]
    async fn sync_udp_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        if self.agent_session.is_none() {
            warn!("No agent session, skipping UDP forwarding");
            return Ok(());
        }

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
        let current_port_nums = self.udp_forwarded_ports.clone();

        // Remove forwards that are no longer needed
        let to_remove: Vec<u16> = current_port_nums
            .difference(&desired_port_nums)
            .copied()
            .collect();

        let mut removed_ports = Vec::new();
        for port in to_remove {
            info!("Removing UDP forward for port {}", port);
            if let Some(agent) = &self.agent_session {
                agent.stop_udp_forward(port).await;
            }
            self.udp_forwarded_ports.remove(&port);
            removed_ports.push(PortInfo::new_with_protocol(
                port,
                None,
                Protocol::Udp,
                self.notifier.mapping(),
            ));
        }

        self.notifier.notify_ports_removed(removed_ports).await;

        // Add new forwards
        let to_add: Vec<RemotePort> = desired_ports
            .into_iter()
            .filter(|p| !current_port_nums.contains(&p.port))
            .collect();

        let mut added_ports = Vec::new();
        for remote_port in to_add {
            let result = if let Some(agent) = &self.agent_session {
                agent
                    .start_udp_forward(remote_port.port, &remote_port.bind_address)
                    .await
            } else {
                continue;
            };

            match result {
                Ok(()) => {
                    added_ports.push(PortInfo::new_with_protocol(
                        remote_port.port,
                        remote_port.process_name.as_deref(),
                        Protocol::Udp,
                        self.notifier.mapping(),
                    ));
                    self.udp_forwarded_ports.insert(remote_port.port);
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
                        "Failed to add UDP forward for port {}: {}",
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
                        if let Some(agent) = &self.agent_session {
                            if agent
                                .start_udp_forward(
                                    remote_port.port,
                                    &remote_port.bind_address,
                                )
                                .await
                                .is_ok()
                            {
                                self.udp_forwarded_ports.insert(remote_port.port);
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
        self.tcp_tunnels.keys().copied().collect()
    }

    pub fn active_udp_tunnels(&self) -> Vec<u16> {
        self.udp_forwarded_ports.iter().copied().collect()
    }

    pub fn active_tunnels(&self) -> Vec<u16> {
        self.tcp_tunnels.keys().copied().collect()
    }

    #[instrument(name = "manager_shutdown", skip(self))]
    pub async fn shutdown(&mut self) {
        info!("Shutting down all tunnels");

        // Shutdown TCP tunnels
        let tcp_ports: Vec<u16> = self.tcp_tunnels.keys().copied().collect();
        for port in tcp_ports {
            if let Some(handle) = self.tcp_tunnels.remove(&port) {
                handle.shutdown();
            }
        }

        // Shutdown agent session (which handles all UDP forwards)
        if let Some(agent) = &self.agent_session {
            agent.shutdown().await;
        }
    }
}
