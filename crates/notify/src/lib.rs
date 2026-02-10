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

use std::{fmt::Display, sync::Arc};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp => write!(f, "TCP"),
        }
    }
}

/// Information about a forwarded port
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub description: String,
    pub protocol: Protocol,
}

impl PortInfo {
    pub fn new(
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
            Self::PortsForwarded { ports } => {
                if ports.len() == 1 {
                    "Port Forwarded".to_string()
                } else {
                    format!("{} Ports Forwarded", ports.len())
                }
            }
            Self::PortsRemoved { ports } => {
                if ports.len() == 1 {
                    "Port Removed".to_string()
                } else {
                    format!("{} Ports Removed", ports.len())
                }
            }
            Self::ConnectionLost => "Connection Lost".to_string(),
            Self::ConnectionRestored => "Connection Restored".to_string(),
            Self::ProcessKilled { .. } => "Process Killed".to_string(),
            Self::ConflictDetected { .. } => "Port Conflict".to_string(),
            Self::TunnelRestarted { .. } => "Tunnel Restarted".to_string(),
        }
    }

    pub fn body(&self) -> String {
        match self {
            Self::PortsForwarded { ports } => {
                if let [p] = ports.as_slice() {
                    format!("{} :{} ({})", p.protocol, p.port, p.description)
                } else {
                    ports
                        .iter()
                        .map(|p| format!("{} :{} ({})", p.protocol, p.port, p.description))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            Self::PortsRemoved { ports } => {
                if let [p] = ports.as_slice() {
                    format!("Port {} stopped", p.port)
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
            Self::ConnectionLost => "SSH connection lost. Reconnecting...".to_string(),
            Self::ConnectionRestored => "SSH connection restored.".to_string(),
            Self::ProcessKilled { port, process_name } => {
                format!("Killed {} on port {}", process_name, port)
            }
            Self::ConflictDetected { port } => {
                format!("Port {} is already in use locally", port)
            }
            Self::TunnelRestarted { port, protocol } => {
                format!("{} tunnel for port {} restarted", protocol, port)
            }
        }
    }

    pub const fn is_error(&self) -> bool {
        matches!(self, Self::ConnectionLost | Self::ConflictDetected { .. })
    }
}

pub struct Notifier {
    desktop_enabled: bool,
    sound_enabled: bool,
    mapping: Arc<PortMapping>,
}

impl Notifier {
    pub const fn new(
        desktop_enabled: bool,
        sound_enabled: bool,
        mapping: Arc<PortMapping>,
    ) -> Self {
        Self {
            desktop_enabled,
            sound_enabled,
            mapping,
        }
    }

    pub fn mapping(&self) -> &PortMapping {
        &self.mapping
    }

    pub fn notify(&self, event: NotificationEvent) {
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
    pub fn notify_ports_forwarded(&self, ports: Vec<PortInfo>) {
        if ports.is_empty() {
            return;
        }
        self.notify(NotificationEvent::PortsForwarded { ports });
    }

    /// Notify about multiple ports being removed (batched)
    pub fn notify_ports_removed(&self, ports: Vec<PortInfo>) {
        if ports.is_empty() {
            return;
        }
        self.notify(NotificationEvent::PortsRemoved { ports });
    }

    /// Notify about a single event (connection, conflict, etc.)
    pub fn notify_event(&self, event: NotificationEvent) {
        self.notify(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_port_info(port: u16, desc: &str, protocol: Protocol) -> PortInfo {
        PortInfo {
            port,
            description: desc.to_string(),
            protocol,
        }
    }

    #[test]
    fn test_port_info_new() {
        let mapping = PortMapping::default();
        let info = PortInfo::new(8080, Some("nginx"), Protocol::Tcp, &mapping);
        assert_eq!(info.port, 8080);
        assert_eq!(info.description, "nginx");
        assert_eq!(info.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_port_info_new_with_protocol() {
        let mapping = PortMapping::default();
        let info = PortInfo::new(53, Some("dnsmasq"), Protocol::Udp, &mapping);
        assert_eq!(info.port, 53);
        assert_eq!(info.description, "dnsmasq");
        assert_eq!(info.protocol, Protocol::Udp);
    }

    #[test]
    fn test_port_info_no_process_name() {
        let mapping = PortMapping::default();
        let info = PortInfo::new(9999, None, Protocol::Tcp, &mapping);
        assert_eq!(info.description, "port 9999");
    }

    #[test]
    fn test_title_single_port_forwarded() {
        let event = NotificationEvent::PortsForwarded {
            ports: vec![make_port_info(8080, "nginx", Protocol::Tcp)],
        };
        assert_eq!(event.title(), "Port Forwarded");
    }

    #[test]
    fn test_title_multiple_ports_forwarded() {
        let event = NotificationEvent::PortsForwarded {
            ports: vec![
                make_port_info(8080, "nginx", Protocol::Tcp),
                make_port_info(3000, "node", Protocol::Tcp),
            ],
        };
        assert_eq!(event.title(), "2 Ports Forwarded");
    }

    #[test]
    fn test_title_single_port_removed() {
        let event = NotificationEvent::PortsRemoved {
            ports: vec![make_port_info(8080, "nginx", Protocol::Tcp)],
        };
        assert_eq!(event.title(), "Port Removed");
    }

    #[test]
    fn test_title_multiple_ports_removed() {
        let event = NotificationEvent::PortsRemoved {
            ports: vec![
                make_port_info(8080, "nginx", Protocol::Tcp),
                make_port_info(3000, "node", Protocol::Tcp),
                make_port_info(5432, "postgres", Protocol::Tcp),
            ],
        };
        assert_eq!(event.title(), "3 Ports Removed");
    }

    #[test]
    fn test_title_connection_events() {
        assert_eq!(NotificationEvent::ConnectionLost.title(), "Connection Lost");
        assert_eq!(
            NotificationEvent::ConnectionRestored.title(),
            "Connection Restored"
        );
    }

    #[test]
    fn test_title_process_killed() {
        let event = NotificationEvent::ProcessKilled {
            port: 8080,
            process_name: "nginx".to_string(),
        };
        assert_eq!(event.title(), "Process Killed");
    }

    #[test]
    fn test_title_conflict_and_restart() {
        assert_eq!(
            NotificationEvent::ConflictDetected { port: 80 }.title(),
            "Port Conflict"
        );
        assert_eq!(
            NotificationEvent::TunnelRestarted {
                port: 53,
                protocol: Protocol::Udp
            }
            .title(),
            "Tunnel Restarted"
        );
    }

    #[test]
    fn test_body_single_port_forwarded() {
        let event = NotificationEvent::PortsForwarded {
            ports: vec![make_port_info(8080, "nginx", Protocol::Tcp)],
        };
        assert_eq!(event.body(), "TCP :8080 (nginx)");
    }

    #[test]
    fn test_body_multiple_ports_forwarded() {
        let event = NotificationEvent::PortsForwarded {
            ports: vec![
                make_port_info(8080, "nginx", Protocol::Tcp),
                make_port_info(53, "dnsmasq", Protocol::Udp),
            ],
        };
        let body = event.body();
        assert!(body.contains("TCP :8080 (nginx)"));
        assert!(body.contains("UDP :53 (dnsmasq)"));
        assert!(body.contains('\n'));
    }

    #[test]
    fn test_body_single_port_removed() {
        let event = NotificationEvent::PortsRemoved {
            ports: vec![make_port_info(8080, "nginx", Protocol::Tcp)],
        };
        assert_eq!(event.body(), "Port 8080 stopped");
    }

    #[test]
    fn test_body_multiple_ports_removed() {
        let event = NotificationEvent::PortsRemoved {
            ports: vec![
                make_port_info(8080, "nginx", Protocol::Tcp),
                make_port_info(3000, "node", Protocol::Tcp),
            ],
        };
        assert_eq!(event.body(), "Ports 8080, 3000 stopped");
    }

    #[test]
    fn test_body_connection_events() {
        assert_eq!(
            NotificationEvent::ConnectionLost.body(),
            "SSH connection lost. Reconnecting..."
        );
        assert_eq!(
            NotificationEvent::ConnectionRestored.body(),
            "SSH connection restored."
        );
    }

    #[test]
    fn test_body_process_killed() {
        let event = NotificationEvent::ProcessKilled {
            port: 80,
            process_name: "apache".to_string(),
        };
        assert_eq!(event.body(), "Killed apache on port 80");
    }

    #[test]
    fn test_body_conflict_detected() {
        let event = NotificationEvent::ConflictDetected { port: 3000 };
        assert_eq!(event.body(), "Port 3000 is already in use locally");
    }

    #[test]
    fn test_body_tunnel_restarted() {
        let event = NotificationEvent::TunnelRestarted {
            port: 53,
            protocol: Protocol::Udp,
        };
        assert_eq!(event.body(), "UDP tunnel for port 53 restarted");
    }

    #[test]
    fn test_is_error() {
        assert!(NotificationEvent::ConnectionLost.is_error());
        assert!(NotificationEvent::ConflictDetected { port: 80 }.is_error());

        assert!(!NotificationEvent::ConnectionRestored.is_error());
        assert!(!NotificationEvent::PortsForwarded { ports: vec![] }.is_error());
        assert!(!NotificationEvent::PortsRemoved { ports: vec![] }.is_error());
        assert!(!NotificationEvent::ProcessKilled {
            port: 80,
            process_name: "x".to_string()
        }
        .is_error());
        assert!(!NotificationEvent::TunnelRestarted {
            port: 53,
            protocol: Protocol::Tcp
        }
        .is_error());
    }
}
