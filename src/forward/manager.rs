use crate::error::{PortLinkerError, Result};
use crate::forward::tunnel::{ActiveTunnel, TunnelHandle};
use crate::notify::{NotificationEvent, Notifier, PortInfo};
use crate::process;
use crate::ssh::handler::ClientHandler;
use crate::ssh::RemotePort;
use russh::client::Handle;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct ForwardManager {
    tunnels: HashMap<u16, TunnelHandle>,
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
            tunnels: HashMap::new(),
            ssh_handle,
            notifier,
            auto_kill,
            port_filter,
            excluded_ports,
        }
    }

    pub fn update_ssh_handle(&mut self, handle: Arc<Handle<ClientHandler>>) {
        self.ssh_handle = handle;
    }

    pub async fn sync_forwards(&mut self, remote_ports: Vec<RemotePort>) -> Result<()> {
        // First filter out excluded ports
        let non_excluded: Vec<RemotePort> = remote_ports
            .into_iter()
            .filter(|p| {
                if self.excluded_ports.contains(&p.port) {
                    debug!("Excluding port {} (in exclusion list)", p.port);
                    false
                } else {
                    true
                }
            })
            .collect();

        // Then apply include filter if set
        let desired_ports: Vec<RemotePort> = if let Some(filter) = &self.port_filter {
            non_excluded
                .into_iter()
                .filter(|p| filter.contains(&p.port))
                .collect()
        } else {
            non_excluded
        };

        let desired_port_nums: HashSet<u16> = desired_ports.iter().map(|p| p.port).collect();
        let current_port_nums: HashSet<u16> = self.tunnels.keys().cloned().collect();

        // Collect ports to remove
        let to_remove: Vec<u16> = current_port_nums
            .difference(&desired_port_nums)
            .cloned()
            .collect();

        // Remove tunnels and collect info for notification
        let mut removed_ports = Vec::new();
        for port in to_remove {
            if let Some(handle) = self.tunnels.remove(&port) {
                info!("Removing tunnel for port {}", port);
                handle.shutdown();
                removed_ports.push(PortInfo::new(port, None, self.notifier.mapping()));
            }
        }

        // Notify about removed ports (batched)
        self.notifier.notify_ports_removed(removed_ports).await;

        // Collect ports to add
        let to_add: Vec<RemotePort> = desired_ports
            .into_iter()
            .filter(|p| !current_port_nums.contains(&p.port))
            .collect();

        // Add new tunnels and collect info for notification
        let mut added_ports = Vec::new();
        for remote_port in to_add {
            match self.add_tunnel_silent(&remote_port).await {
                Ok(()) => {
                    added_ports.push(PortInfo::new(
                        remote_port.port,
                        remote_port.process_name.as_deref(),
                        self.notifier.mapping(),
                    ));
                }
                Err(PortLinkerError::PortInUse(port)) => {
                    // Handle conflict - this may add to added_ports if resolved
                    if let Some(port_info) = self.handle_port_conflict(port, &remote_port).await? {
                        added_ports.push(port_info);
                    }
                }
                Err(e) => {
                    error!("Failed to add tunnel for port {}: {}", remote_port.port, e);
                }
            }
        }

        // Notify about added ports (batched)
        self.notifier.notify_ports_forwarded(added_ports).await;

        Ok(())
    }

    /// Add a tunnel without sending a notification (for batching)
    async fn add_tunnel_silent(&mut self, remote_port: &RemotePort) -> Result<()> {
        let port = remote_port.port;

        let handle = ActiveTunnel::start(
            self.ssh_handle.clone(),
            remote_port.clone(),
            None, // Use same port locally
        )
        .await?;

        self.tunnels.insert(port, handle);
        Ok(())
    }

    /// Handle port conflict, returns PortInfo if tunnel was successfully created
    async fn handle_port_conflict(
        &mut self,
        port: u16,
        remote_port: &RemotePort,
    ) -> Result<Option<PortInfo>> {
        self.notifier
            .notify_event(NotificationEvent::ConflictDetected { port })
            .await;

        // Find the process using this port
        if let Some(proc_info) = process::detector::find_process_on_port(port) {
            let should_kill = if self.auto_kill {
                true
            } else {
                process::killer::prompt_kill(&proc_info)?
            };

            if should_kill {
                process::killer::kill_process(&proc_info)?;

                self.notifier
                    .notify_event(NotificationEvent::ProcessKilled {
                        port,
                        process_name: proc_info.name.clone(),
                    })
                    .await;

                // Try again after killing
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                if self.add_tunnel_silent(remote_port).await.is_ok() {
                    return Ok(Some(PortInfo::new(
                        port,
                        remote_port.process_name.as_deref(),
                        self.notifier.mapping(),
                    )));
                }
            } else {
                warn!("Port {} conflict not resolved - skipping forward", port);
            }
        } else {
            warn!(
                "Port {} in use but couldn't identify process (try: sudo lsof -i :{})",
                port, port
            );
        }

        Ok(None)
    }

    pub fn active_tunnels(&self) -> Vec<u16> {
        self.tunnels.keys().cloned().collect()
    }

    pub async fn shutdown(&mut self) {
        info!("Shutting down all tunnels");
        let ports: Vec<u16> = self.tunnels.keys().cloned().collect();

        let mut removed_ports = Vec::new();
        for port in ports {
            if let Some(handle) = self.tunnels.remove(&port) {
                handle.shutdown();
                removed_ports.push(PortInfo::new(port, None, self.notifier.mapping()));
            }
        }

        // Don't notify on shutdown - we're exiting anyway
    }
}
