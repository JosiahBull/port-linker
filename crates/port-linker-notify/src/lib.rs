//! Desktop notifications and port mapping for port-linker.
//!
//! This crate provides:
//! - Desktop notifications for port forwarding events
//! - Port mapping configuration for human-readable port descriptions

pub mod desktop;
pub mod error;
pub mod mapping;

pub use error::{NotifyError, Result};
pub use mapping::PortMapping;

use port_linker_proto::Protocol;
use std::sync::Arc;
use tracing::{info, warn};

/// Information about a forwarded port
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub description: String,
    pub protocol: Protocol,
}

impl PortInfo {
    pub fn new(port: u16, process_name: Option<&str>, mapping: &PortMapping) -> Self {
        let description = mapping.describe(port, process_name);
        Self {
            port,
            description,
            protocol: Protocol::Tcp,
        }
    }

    pub fn new_with_protocol(
        port: u16,
        process_name: Option<&str>,
        protocol: Protocol,
        mapping: &PortMapping,
    ) -> Self {
        let description = mapping.describe(port, process_name);
        Self {
            port,
            description,
            protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub enum NotificationEvent {
    PortsForwarded { ports: Vec<PortInfo> },
    PortsRemoved { ports: Vec<PortInfo> },
    ConnectionLost,
    ConnectionRestored,
    ProcessKilled { port: u16, process_name: String },
    ConflictDetected { port: u16 },
    TunnelRestarted { port: u16, protocol: Protocol },
}

impl NotificationEvent {
    pub fn title(&self) -> String {
        match self {
            NotificationEvent::PortsForwarded { ports } => {
                if ports.len() == 1 {
                    "Port Forwarded".to_string()
                } else {
                    format!("{} Ports Forwarded", ports.len())
                }
            }
            NotificationEvent::PortsRemoved { ports } => {
                if ports.len() == 1 {
                    "Port Removed".to_string()
                } else {
                    format!("{} Ports Removed", ports.len())
                }
            }
            NotificationEvent::ConnectionLost => "Connection Lost".to_string(),
            NotificationEvent::ConnectionRestored => "Connection Restored".to_string(),
            NotificationEvent::ProcessKilled { .. } => "Process Killed".to_string(),
            NotificationEvent::ConflictDetected { .. } => "Port Conflict".to_string(),
            NotificationEvent::TunnelRestarted { .. } => "Tunnel Restarted".to_string(),
        }
    }

    pub fn body(&self) -> String {
        match self {
            NotificationEvent::PortsForwarded { ports } => {
                if ports.len() == 1 {
                    let p = &ports[0];
                    format!("{} :{} ({})", p.protocol, p.port, p.description)
                } else {
                    ports
                        .iter()
                        .map(|p| format!("{} :{} ({})", p.protocol, p.port, p.description))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            NotificationEvent::PortsRemoved { ports } => {
                if ports.len() == 1 {
                    format!("Port {} stopped", ports[0].port)
                } else {
                    format!(
                        "Ports {} stopped",
                        ports
                            .iter()
                            .map(|p| p.port.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            NotificationEvent::ConnectionLost => "SSH connection lost. Reconnecting...".to_string(),
            NotificationEvent::ConnectionRestored => "SSH connection restored.".to_string(),
            NotificationEvent::ProcessKilled { port, process_name } => {
                format!("Killed {} on port {}", process_name, port)
            }
            NotificationEvent::ConflictDetected { port } => {
                format!("Port {} is already in use locally", port)
            }
            NotificationEvent::TunnelRestarted { port, protocol } => {
                format!("{} tunnel for port {} restarted", protocol, port)
            }
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(
            self,
            NotificationEvent::ConnectionLost | NotificationEvent::ConflictDetected { .. }
        )
    }
}

pub struct Notifier {
    desktop_enabled: bool,
    sound_enabled: bool,
    mapping: Arc<PortMapping>,
}

impl Notifier {
    pub fn new(desktop_enabled: bool, sound_enabled: bool, mapping: Arc<PortMapping>) -> Self {
        Self {
            desktop_enabled,
            sound_enabled,
            mapping,
        }
    }

    pub fn mapping(&self) -> &PortMapping {
        &self.mapping
    }

    pub async fn notify(&self, event: NotificationEvent) {
        // Always log
        if event.is_error() {
            warn!("{}: {}", event.title(), event.body());
        } else {
            info!("{}: {}", event.title(), event.body().replace('\n', ", "));
        }

        // Desktop notification
        if self.desktop_enabled {
            if let Err(e) = desktop::show_notification(&event, self.sound_enabled) {
                warn!("Failed to show desktop notification: {}", e);
            }
        }
    }

    /// Notify about multiple ports being forwarded (batched)
    pub async fn notify_ports_forwarded(&self, ports: Vec<PortInfo>) {
        if ports.is_empty() {
            return;
        }
        self.notify(NotificationEvent::PortsForwarded { ports })
            .await;
    }

    /// Notify about multiple ports being removed (batched)
    pub async fn notify_ports_removed(&self, ports: Vec<PortInfo>) {
        if ports.is_empty() {
            return;
        }
        self.notify(NotificationEvent::PortsRemoved { ports }).await;
    }

    /// Notify about a single event (connection, conflict, etc.)
    pub async fn notify_event(&self, event: NotificationEvent) {
        self.notify(event).await;
    }
}
