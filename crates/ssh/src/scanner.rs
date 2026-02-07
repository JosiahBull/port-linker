use crate::client::SshClient;
use crate::error::{Result, SshError};
use proto::Protocol;
use ::scanner::{BindAddress, RemotePort};
use tracing::{debug, info, trace};

pub struct Scanner;

impl Scanner {
    /// Scan for TCP ports on the remote host.
    pub async fn scan_tcp_ports(client: &SshClient) -> Result<Vec<RemotePort>> {
        let start = std::time::Instant::now();

        // Try ss first, then netstat
        let output = match client.exec("ss -tlnp 2>/dev/null").await {
            Ok(out) if !out.is_empty() && out.contains("State") => {
                trace!("Using ss for TCP port scanning");
                out
            }
            _ => {
                trace!("Falling back to netstat for TCP port scanning");
                client
                    .exec("netstat -tlnp 2>/dev/null")
                    .await
                    .map_err(|e| {
                        SshError::PortScan(format!("Both ss and netstat failed: {}", e))
                    })?
            }
        };

        let result = Self::parse_output(&output, Protocol::Tcp);
        debug!("TCP port scan completed in {:?}", start.elapsed());
        result
    }

    /// Scan for UDP ports on the remote host.
    pub async fn scan_udp_ports(client: &SshClient) -> Result<Vec<RemotePort>> {
        let start = std::time::Instant::now();

        // Try ss first, then netstat
        let output = match client.exec("ss -ulnp 2>/dev/null").await {
            Ok(out) if !out.is_empty() && (out.contains("State") || out.contains("UNCONN")) => {
                trace!("Using ss for UDP port scanning");
                out
            }
            _ => {
                trace!("Falling back to netstat for UDP port scanning");
                client
                    .exec("netstat -ulnp 2>/dev/null")
                    .await
                    .unwrap_or_default() // UDP scan failure is non-fatal
            }
        };

        let result = Self::parse_output(&output, Protocol::Udp);
        debug!("UDP port scan completed in {:?}", start.elapsed());
        result
    }

    /// Scan for both TCP and UDP ports.
    pub async fn scan_all_ports(client: &SshClient) -> Result<Vec<RemotePort>> {
        let start = std::time::Instant::now();
        let mut ports = Self::scan_tcp_ports(client).await?;

        // UDP scan failure shouldn't fail the whole operation
        if let Ok(udp_ports) = Self::scan_udp_ports(client).await {
            ports.extend(udp_ports);
        }

        // Sort by (protocol, port) for consistent ordering
        ports.sort_by_key(|p| (p.protocol == Protocol::Udp, p.port));

        debug!("Full port scan completed in {:?}", start.elapsed());
        Ok(ports)
    }

    /// Legacy method for backward compatibility - scans TCP only.
    pub async fn scan_ports(client: &SshClient) -> Result<Vec<RemotePort>> {
        Self::scan_tcp_ports(client).await
    }

    fn parse_output(output: &str, protocol: Protocol) -> Result<Vec<RemotePort>> {
        let mut ports = Vec::new();
        let expected_prefix = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };

        trace!(
            "Raw {} scan output ({} lines):\n{}",
            expected_prefix.to_uppercase(),
            output.lines().count(),
            output
        );

        for line in output.lines().skip(1) {
            // Skip header
            if let Some(port) = Self::parse_line(line, protocol, expected_prefix) {
                // Only include ports bound to localhost or all interfaces
                if port.bind_address.is_forwardable() {
                    trace!(
                        "Found forwardable port: {}:{} ({})",
                        port.bind_address,
                        port.port,
                        port.process_name.as_deref().unwrap_or("unknown")
                    );
                    ports.push(port);
                } else {
                    trace!(
                        "Skipping non-forwardable port: {}:{} (bound to specific interface)",
                        port.bind_address,
                        port.port
                    );
                }
            }
        }

        // Deduplicate by port (within the same protocol)
        ports.sort_by_key(|p| p.port);
        ports.dedup_by_key(|p| p.port);

        if !ports.is_empty() {
            let port_list: Vec<String> = ports
                .iter()
                .map(|p| {
                    if let Some(ref name) = p.process_name {
                        format!("{}({})", p.port, name)
                    } else {
                        p.port.to_string()
                    }
                })
                .collect();
            info!(
                "Discovered {} {} ports: [{}]",
                ports.len(),
                expected_prefix.to_uppercase(),
                port_list.join(", ")
            );
        } else {
            debug!("No forwardable {} ports found", expected_prefix.to_uppercase());
        }

        Ok(ports)
    }

    fn parse_line(line: &str, protocol: Protocol, expected_prefix: &str) -> Option<RemotePort> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 4 {
            return None;
        }

        let first_col = parts.first()?.to_lowercase();
        let is_state = matches!(
            first_col.as_str(),
            "listen" | "estab" | "established" | "unconn" | "time-wait" | "close-wait" | "syn-sent" | "syn-recv"
        );
        let is_protocol = first_col.starts_with(expected_prefix);

        let local_addr_idx = if is_state {
            3
        } else if is_protocol {
            if parts.get(1).and_then(|p| p.parse::<u32>().ok()).is_some() {
                3 // netstat
            } else {
                4 // ss with Netid
            }
        } else {
            return None;
        };

        let local_addr = parts.get(local_addr_idx)?;
        let (bind_address, port) = Self::parse_address_port(local_addr)?;

        // Try to extract process name
        let process_name = Self::extract_process_name(line);

        Some(RemotePort {
            port,
            bind_address,
            process_name,
            protocol,
        })
    }

    fn parse_address_port(addr: &str) -> Option<(BindAddress, u16)> {
        // Handle IPv6 format [::]:port or [::1]:port
        if addr.starts_with('[') {
            let end_bracket = addr.find(']')?;
            let address = addr.get(1..end_bracket)?;
            let port_str = addr.get(end_bracket.checked_add(2)?..)?;
            let port = port_str.parse().ok()?;
            let bind_addr = BindAddress::parse_str(address)?;
            return Some((bind_addr, port));
        }

        // Handle :::port (IPv6 any)
        if let Some(port_str) = addr.strip_prefix(":::") {
            let port = port_str.parse().ok()?;
            return Some((BindAddress::parse_str("::").unwrap_or(BindAddress::V6(std::net::Ipv6Addr::UNSPECIFIED)), port));
        }

        // Standard IPv4 or single colon format
        let last_colon = addr.rfind(':')?;
        let address = addr.get(..last_colon)?;
        let port_str = addr.get(last_colon.checked_add(1)?..)?;

        let bind_addr = BindAddress::parse_str(address)
            .unwrap_or(BindAddress::V4(std::net::Ipv4Addr::UNSPECIFIED));

        let port = port_str.parse().ok()?;
        Some((bind_addr, port))
    }

    fn extract_process_name(line: &str) -> Option<String> {
        // ss format: users:(("process",pid=1234,fd=5))
        if let Some(start) = line.find("users:((\"") {
            let rest = line.get(start.checked_add(9)?..)?;
            if let Some(end) = rest.find('"') {
                return Some(rest.get(..end)?.to_string());
            }
        }

        // netstat format: 1234/process
        for part in line.split_whitespace().rev() {
            if part.contains('/') {
                let parts: Vec<&str> = part.split('/').collect();
                if parts.len() == 2 {
                    if let Some(pid_str) = parts.first() {
                        if pid_str.parse::<u32>().is_ok() {
                            if let Some(name) = parts.get(1) {
                                return Some((*name).to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_ss_tcp_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     127.0.0.1:3000        0.0.0.0:*         users:(("node",pid=5678,fd=5))
tcp    LISTEN  0       128     [::]:80               [::]:*            users:(("nginx",pid=9012,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 3, "Expected 3 ports, got {:?}", ports);

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_22.process_name, Some("sshd".to_string()));
        assert_eq!(port_22.protocol, Protocol::Tcp);

        let port_3000 = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(port_3000.bind_address, BindAddress::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port_3000.process_name, Some("node".to_string()));
    }

    #[test]
    fn test_parse_ss_udp_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
udp    UNCONN  0       0       0.0.0.0:53            0.0.0.0:*         users:(("dnsmasq",pid=1234,fd=5))
udp    UNCONN  0       0       127.0.0.1:323         0.0.0.0:*         users:(("chronyd",pid=5678,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2, "Expected 2 ports, got {:?}", ports);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
        assert_eq!(port_53.protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_address_port() {
        assert_eq!(
            Scanner::parse_address_port("0.0.0.0:8080"),
            Some((BindAddress::V4(Ipv4Addr::UNSPECIFIED), 8080))
        );
        assert_eq!(
            Scanner::parse_address_port("127.0.0.1:3000"),
            Some((BindAddress::V4(Ipv4Addr::LOCALHOST), 3000))
        );
        assert_eq!(
            Scanner::parse_address_port("[::]:80"),
            Some((BindAddress::V6(Ipv6Addr::UNSPECIFIED), 80))
        );
        assert_eq!(
            Scanner::parse_address_port(":::8080"),
            Some((BindAddress::V6(Ipv6Addr::UNSPECIFIED), 8080))
        );
        assert_eq!(
            Scanner::parse_address_port("*:22"),
            Some((BindAddress::V4(Ipv4Addr::UNSPECIFIED), 22))
        );
    }

    #[test]
    fn test_parse_ss_tcp_output_no_netid() {
        let output = r#"State  Recv-Q Send-Q               Local Address:Port  Peer Address:PortProcess
LISTEN 0      128                        0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096                       0.0.0.0:5432       0.0.0.0:*
LISTEN 0      5                          0.0.0.0:8888       0.0.0.0:*    users:(("python3.13",pid=965181,fd=3))
LISTEN 0      4096                     127.0.0.1:12345      0.0.0.0:*
LISTEN 0      4096                             *:4243             *:*
LISTEN 0      4096                             *:9100             *:*                       "#;

        let ports = Scanner::parse_output(output, Protocol::Tcp).unwrap();

        assert!(ports.len() >= 6, "Expected at least 6 ports, got {}", ports.len());

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_22.protocol, Protocol::Tcp);

        let port_8888 = ports.iter().find(|p| p.port == 8888).unwrap();
        assert_eq!(port_8888.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_8888.process_name, Some("python3.13".to_string()));

        let port_12345 = ports.iter().find(|p| p.port == 12345).unwrap();
        assert_eq!(port_12345.bind_address, BindAddress::V4(Ipv4Addr::LOCALHOST));

        let port_4243 = ports.iter().find(|p| p.port == 4243).unwrap();
        assert_eq!(port_4243.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_ss_udp_output_no_netid() {
        let output = r#"State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
UNCONN 0      0      0.0.0.0:53          0.0.0.0:*     users:(("dnsmasq",pid=1234,fd=5))
UNCONN 0      0      127.0.0.1:323       0.0.0.0:*     users:(("chronyd",pid=5678,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2, "Expected 2 ports, got {:?}", ports);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
        assert_eq!(port_53.protocol, Protocol::Udp);
    }
}
