use crate::error::Result;
use crate::forward::ForwardManager;
use crate::notify::{NotificationEvent, Notifier};
use crate::ssh::{Scanner, SshClient};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, instrument, trace, warn};

pub struct Monitor {
    client: Arc<SshClient>,
    manager: ForwardManager,
    notifier: Arc<Notifier>,
    scan_interval: Duration,
    forward_tcp: bool,
    forward_udp: bool,
}

impl Monitor {
    pub fn new(
        client: Arc<SshClient>,
        manager: ForwardManager,
        notifier: Arc<Notifier>,
        scan_interval: Duration,
        forward_tcp: bool,
        forward_udp: bool,
    ) -> Self {
        Self {
            client,
            manager,
            notifier,
            scan_interval,
            forward_tcp,
            forward_udp,
        }
    }

    #[instrument(name = "monitor", skip(self), fields(interval_ms = self.scan_interval.as_millis() as u64))]
    pub async fn run(&mut self) -> Result<()> {
        let mut scan_interval = interval(self.scan_interval);
        let mut reconnect_delay = Duration::from_secs(1);
        let max_reconnect_delay = Duration::from_secs(60);

        info!(
            "Starting port monitoring (interval: {:?})",
            self.scan_interval
        );

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

                                    // Note: reconnect requires mutable access, but we have Arc
                                    // For now, we'll just keep trying with the existing client
                                    // TODO: Handle reconnection properly with Arc<Mutex<SshClient>>
                                    if self.client.is_connected().await {
                                        info!("Connection restored");
                                        self.notifier.notify_event(NotificationEvent::ConnectionRestored).await;

                                        // Update manager with handle
                                        self.manager.update_ssh_handle(
                                            self.client.handle()
                                        );

                                        // Re-establish tunnels
                                        if let Err(e) = self.scan_and_sync().await {
                                            error!("Failed to restore tunnels: {}", e);
                                        }

                                        break;
                                    } else {
                                        error!("Connection still down");
                                        reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
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

    #[instrument(name = "scan_and_sync", skip(self))]
    async fn scan_and_sync(&mut self) -> Result<()> {
        trace!("Starting port scan cycle");
        let scan_start = std::time::Instant::now();

        // Scan based on protocol filter
        let remote_ports = if self.forward_tcp && self.forward_udp {
            Scanner::scan_all_ports(&self.client).await?
        } else if self.forward_udp {
            Scanner::scan_udp_ports(&self.client).await?
        } else {
            Scanner::scan_tcp_ports(&self.client).await?
        };

        trace!(
            "Scan found {} remote ports in {:?}",
            remote_ports.len(),
            scan_start.elapsed()
        );

        // Check for dead UDP tunnels and restart them
        // This handles cases where the remote proxy died (healthcheck timeout, etc.)
        if self.forward_udp {
            let restarted = self
                .manager
                .check_and_restart_dead_udp_tunnels(&remote_ports)
                .await;
            if restarted > 0 {
                debug!("Restarted {} dead UDP tunnel(s)", restarted);
            }
        }

        // Sync based on protocol filter
        self.manager.sync_all_forwards(remote_ports).await?;

        // Log active tunnels summary
        let tcp_active = self.manager.active_tcp_tunnels();
        let udp_active = self.manager.active_udp_tunnels();
        let total = tcp_active.len() + udp_active.len();

        if total > 0 {
            trace!(
                "Active tunnels: {} TCP {:?}, {} UDP {:?}",
                tcp_active.len(),
                tcp_active,
                udp_active.len(),
                udp_active
            );
        }

        trace!("Scan cycle completed in {:?}", scan_start.elapsed());
        Ok(())
    }

    #[instrument(name = "shutdown", skip(self))]
    async fn shutdown(&mut self) {
        info!("Shutting down tunnels...");
        self.manager.shutdown().await;
        info!("Goodbye!");
    }
}
