use crate::error::Result;
use crate::forward::ForwardManager;
use crate::notify::{NotificationEvent, Notifier};
use crate::ssh::{Scanner, SshClient};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

pub struct Monitor {
    client: SshClient,
    manager: ForwardManager,
    notifier: Arc<Notifier>,
    scan_interval: Duration,
}

impl Monitor {
    pub fn new(
        client: SshClient,
        manager: ForwardManager,
        notifier: Arc<Notifier>,
        scan_interval: Duration,
    ) -> Self {
        Self {
            client,
            manager,
            notifier,
            scan_interval,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut scan_interval = interval(self.scan_interval);
        let mut reconnect_delay = Duration::from_secs(1);
        let max_reconnect_delay = Duration::from_secs(60);

        info!("Starting port monitoring (interval: {:?})", self.scan_interval);

        loop {
            tokio::select! {
                _ = scan_interval.tick() => {
                    match self.scan_and_sync().await {
                        Ok(_) => {
                            reconnect_delay = Duration::from_secs(1);
                        }
                        Err(e) => {
                            error!("Scan/sync error: {}", e);

                            // Check if connection is still alive
                            if !self.client.is_connected().await {
                                self.notifier.notify_event(NotificationEvent::ConnectionLost).await;

                                // Attempt reconnection with exponential backoff
                                loop {
                                    warn!("Attempting reconnection in {:?}...", reconnect_delay);
                                    tokio::time::sleep(reconnect_delay).await;

                                    match self.client.reconnect().await {
                                        Ok(_) => {
                                            info!("Reconnected successfully");
                                            self.notifier.notify_event(NotificationEvent::ConnectionRestored).await;

                                            // Update manager with new handle
                                            self.manager.update_ssh_handle(
                                                self.client.handle()
                                            );

                                            // Re-establish tunnels
                                            if let Err(e) = self.scan_and_sync().await {
                                                error!("Failed to restore tunnels: {}", e);
                                            }

                                            break;
                                        }
                                        Err(e) => {
                                            error!("Reconnection failed: {}", e);
                                            reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C, shutting down...");
                    self.shutdown().await;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn scan_and_sync(&mut self) -> Result<()> {
        debug!("Scanning remote ports...");

        let remote_ports = Scanner::scan_ports(&self.client).await?;

        debug!(
            "Found {} remote ports: {:?}",
            remote_ports.len(),
            remote_ports.iter().map(|p| p.port).collect::<Vec<_>>()
        );

        self.manager.sync_forwards(remote_ports).await?;

        let active = self.manager.active_tunnels();
        if !active.is_empty() {
            debug!("Active tunnels: {:?}", active);
        }

        Ok(())
    }

    async fn shutdown(&mut self) {
        info!("Shutting down tunnels...");
        self.manager.shutdown().await;
        info!("Goodbye!");
    }
}
