use crate::error::{PortLinkerError, Result};
use crate::ssh::SshClient;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePort {
    pub port: u16,
    pub bind_address: String,
    pub process_name: Option<String>,
}

pub struct Scanner;

impl Scanner {
    pub async fn scan_ports(client: &SshClient) -> Result<Vec<RemotePort>> {
        // Try ss first, then netstat (TCP only)
        let output = match client.exec("ss -tlnp 2>/dev/null").await {
            Ok(out) if !out.is_empty() && out.contains("State") => {
                debug!("Using ss for port scanning");
                out
            }
            _ => {
                debug!("Falling back to netstat for port scanning");
                client
                    .exec("netstat -tlnp 2>/dev/null")
                    .await
                    .map_err(|e| {
                        PortLinkerError::PortScan(format!(
                            "Both ss and netstat failed: {}",
                            e
                        ))
                    })?
            }
        };

        Self::parse_output(&output)
    }

    fn parse_output(output: &str) -> Result<Vec<RemotePort>> {
        let mut ports = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header
            if let Some(port) = Self::parse_line(line) {
                // Only include ports bound to localhost or all interfaces
                if Self::is_forwardable_address(&port.bind_address) {
                    ports.push(port);
                }
            }
        }

        // Deduplicate by port
        ports.sort_by_key(|p| p.port);
        ports.dedup_by_key(|p| p.port);

        debug!("Found {} forwardable ports", ports.len());
        Ok(ports)
    }

    fn parse_line(line: &str) -> Option<RemotePort> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            return None;
        }

        // Only process TCP lines
        let proto_str = parts[0].to_lowercase();
        if !proto_str.starts_with("tcp") {
            return None;
        }

        // Find local address column
        // ss format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        // netstat format: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
        let local_addr_idx = if line.contains("LISTEN") || line.contains("UNCONN") {
            // ss format - local address is typically column 4 (0-indexed)
            4
        } else {
            // netstat format - local address is typically column 3
            3
        };

        if parts.len() <= local_addr_idx {
            return None;
        }

        let local_addr = parts[local_addr_idx];
        let (bind_address, port) = Self::parse_address_port(local_addr)?;

        // Try to extract process name
        let process_name = Self::extract_process_name(line);

        Some(RemotePort {
            port,
            bind_address,
            process_name,
        })
    }

    fn parse_address_port(addr: &str) -> Option<(String, u16)> {
        // Handle IPv6 format [::]:port or [::1]:port
        if addr.starts_with('[') {
            let end_bracket = addr.find(']')?;
            let address = &addr[1..end_bracket];
            let port_str = addr.get(end_bracket + 2..)?;
            let port = port_str.parse().ok()?;
            return Some((address.to_string(), port));
        }

        // Handle IPv4 format address:port
        // But also handle :::port (IPv6 any)
        if addr.starts_with(":::") {
            let port_str = &addr[3..];
            let port = port_str.parse().ok()?;
            return Some(("::".to_string(), port));
        }

        // Standard IPv4 or single colon format
        let last_colon = addr.rfind(':')?;
        let address = &addr[..last_colon];
        let port_str = &addr[last_colon + 1..];

        // Handle * as 0.0.0.0
        let address = if address == "*" {
            "0.0.0.0".to_string()
        } else {
            address.to_string()
        };

        let port = port_str.parse().ok()?;
        Some((address, port))
    }

    fn extract_process_name(line: &str) -> Option<String> {
        // ss format: users:(("process",pid=1234,fd=5))
        if let Some(start) = line.find("users:((\"") {
            let rest = &line[start + 9..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }

        // netstat format: 1234/process
        for part in line.split_whitespace().rev() {
            if part.contains('/') {
                let parts: Vec<&str> = part.split('/').collect();
                if parts.len() == 2 {
                    if parts[0].parse::<u32>().is_ok() {
                        return Some(parts[1].to_string());
                    }
                }
            }
        }

        None
    }

    fn is_forwardable_address(addr: &str) -> bool {
        matches!(
            addr,
            "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "*" | "localhost"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     127.0.0.1:3000        0.0.0.0:*         users:(("node",pid=5678,fd=5))
tcp    LISTEN  0       128     [::]:80               [::]:*            users:(("nginx",pid=9012,fd=6))"#;

        let ports = Scanner::parse_output(output).unwrap();
        assert_eq!(ports.len(), 3);

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, "0.0.0.0");
        assert_eq!(port_22.process_name, Some("sshd".to_string()));

        let port_3000 = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(port_3000.bind_address, "127.0.0.1");
        assert_eq!(port_3000.process_name, Some("node".to_string()));
    }

    #[test]
    fn test_parse_address_port() {
        assert_eq!(
            Scanner::parse_address_port("0.0.0.0:8080"),
            Some(("0.0.0.0".to_string(), 8080))
        );
        assert_eq!(
            Scanner::parse_address_port("127.0.0.1:3000"),
            Some(("127.0.0.1".to_string(), 3000))
        );
        assert_eq!(
            Scanner::parse_address_port("[::]:80"),
            Some(("::".to_string(), 80))
        );
        assert_eq!(
            Scanner::parse_address_port(":::8080"),
            Some(("::".to_string(), 8080))
        );
        assert_eq!(
            Scanner::parse_address_port("*:22"),
            Some(("0.0.0.0".to_string(), 22))
        );
    }
}
