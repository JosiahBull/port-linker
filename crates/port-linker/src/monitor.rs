use crate::error::Result;
use forward::{AgentSession, ForwardManager};
use notify::{NotificationEvent, Notifier};
use proto::ScanFlags;
use ssh::{RemotePort, Scanner, SshClient};
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
                                        reconnect_delay = reconnect_delay.saturating_mul(2).min(max_reconnect_delay);
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

        // Check if agent is still alive; attempt recovery if not
        self.check_agent_health().await;

        // Try scanning via agent first, fall back to SSH scanner
        let remote_ports = self.scan_ports().await?;

        trace!(
            "Scan found {} remote ports in {:?}",
            remote_ports.len(),
            scan_start.elapsed()
        );

        // Sync all forwards
        self.manager.sync_all_forwards(remote_ports).await?;

        // Log active tunnels summary
        let tcp_active = self.manager.active_tcp_tunnels();
        let udp_active = self.manager.active_udp_tunnels();
        let total = tcp_active.len().saturating_add(udp_active.len());

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

    /// Scan for remote ports, using the agent session if available.
    async fn scan_ports(&self) -> Result<Vec<RemotePort>> {
        // Try agent-based scanning first
        if let Some(agent) = self.manager.agent_session() {
            let flags = ScanFlags {
                tcp: self.forward_tcp,
                udp: self.forward_udp,
            };

            match agent.request_scan(flags).await {
                Ok(ports) => return Ok(ports),
                Err(e) => {
                    warn!("Agent scan failed, falling back to SSH scanner: {}", e);
                }
            }
        }

        // Fallback to SSH-based scanning
        if self.forward_tcp && self.forward_udp {
            Ok(Scanner::scan_all_ports(&self.client).await?)
        } else if self.forward_udp {
            Ok(Scanner::scan_udp_ports(&self.client).await?)
        } else {
            Ok(Scanner::scan_tcp_ports(&self.client).await?)
        }
    }

    /// Check if the agent is still alive and attempt to recover if not.
    async fn check_agent_health(&mut self) {
        if let Some(agent) = self.manager.agent_session_mut() {
            if agent.is_alive() {
                return; // Agent is healthy
            }
            warn!("Target agent is no longer alive, attempting recovery...");
        } else {
            return; // No agent session configured
        }

        // Agent is dead - remove the old session and try to redeploy
        let old_session = self.manager.take_agent_session();
        if let Some(old) = old_session {
            // Clean up old binary on remote
            old.cleanup(&self.client).await;
        }

        // Attempt to deploy a new agent
        match AgentSession::deploy_and_start(&self.client).await {
            Ok(session) => {
                info!("Target agent recovered successfully");
                self.manager.set_agent_session(session);
            }
            Err(e) => {
                debug!("Failed to recover agent: {} - using SSH scanner fallback", e);
            }
        }
    }

    #[instrument(name = "shutdown", skip(self))]
    async fn shutdown(&mut self) {
        info!("Shutting down tunnels...");
        self.manager.shutdown().await;

        // Clean up agent binary on remote
        if let Some(agent) = self.manager.agent_session() {
            agent.cleanup(&self.client).await;
        }

        info!("Goodbye!");
    }
}
