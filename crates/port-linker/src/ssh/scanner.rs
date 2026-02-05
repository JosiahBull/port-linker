use crate::error::{PortLinkerError, Result};
use crate::ssh::SshClient;
use port_linker_proto::Protocol;
use tracing::{debug, info, trace};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePort {
    pub port: u16,
    pub bind_address: String,
    pub process_name: Option<String>,
    pub protocol: Protocol,
}

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
                        PortLinkerError::PortScan(format!("Both ss and netstat failed: {}", e))
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
                if Self::is_forwardable_address(&port.bind_address) {
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

        // Detect the output format and find the local address column index.
        // We need to handle multiple formats:
        //
        // 1. ss with protocol filter (ss -tlnp or ss -ulnp) - NO Netid column:
        //    State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        //    LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
        //    parts[0] = "LISTEN" (state), local_addr at index 3
        //
        // 2. ss without protocol filter (ss -lnp) - HAS Netid column:
        //    Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        //    tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
        //    parts[0] = "tcp" (protocol), local_addr at index 4
        //
        // 3. netstat format:
        //    Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
        //    tcp   0      0      0.0.0.0:8080  0.0.0.0:*       LISTEN 1234/nginx
        //    parts[0] = "tcp", parts[1] = "0" (number), local_addr at index 3

        let first_col = parts[0].to_lowercase();
        let is_state = matches!(
            first_col.as_str(),
            "listen" | "estab" | "established" | "unconn" | "time-wait" | "close-wait" | "syn-sent" | "syn-recv"
        );
        let is_protocol = first_col.starts_with(expected_prefix);

        let local_addr_idx = if is_state {
            // Format 1: ss with protocol filter, no Netid column
            // State Recv-Q Send-Q LocalAddr:Port ...
            // [0]   [1]    [2]    [3]
            3
        } else if is_protocol {
            // Could be format 2 (ss) or format 3 (netstat)
            if parts[1].parse::<u32>().is_ok() {
                // Format 3: netstat - parts[1] is Recv-Q (a number)
                // Proto Recv-Q Send-Q LocalAddr ...
                // [0]   [1]    [2]    [3]
                3
            } else {
                // Format 2: ss with Netid column - parts[1] is State
                // Netid State Recv-Q Send-Q LocalAddr:Port ...
                // [0]   [1]   [2]    [3]    [4]
                4
            }
        } else {
            // Unknown format or wrong protocol
            return None;
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
            protocol,
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
        if let Some(port_str) = addr.strip_prefix(":::") {
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
                if parts.len() == 2 && parts[0].parse::<u32>().is_ok() {
                    return Some(parts[1].to_string());
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
    fn test_parse_ss_tcp_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     127.0.0.1:3000        0.0.0.0:*         users:(("node",pid=5678,fd=5))
tcp    LISTEN  0       128     [::]:80               [::]:*            users:(("nginx",pid=9012,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 3);

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, "0.0.0.0");
        assert_eq!(port_22.process_name, Some("sshd".to_string()));
        assert_eq!(port_22.protocol, Protocol::Tcp);

        let port_3000 = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(port_3000.bind_address, "127.0.0.1");
        assert_eq!(port_3000.process_name, Some("node".to_string()));
    }

    #[test]
    fn test_parse_ss_udp_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
udp    UNCONN  0       0       0.0.0.0:53            0.0.0.0:*         users:(("dnsmasq",pid=1234,fd=5))
udp    UNCONN  0       0       127.0.0.1:323         0.0.0.0:*         users:(("chronyd",pid=5678,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, "0.0.0.0");
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
        assert_eq!(port_53.protocol, Protocol::Udp);
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

    #[test]
    fn test_parse_ss_tcp_output_no_netid() {
        // ss -tlnp output format (no Netid column because -t implies TCP)
        let output = r#"State  Recv-Q Send-Q               Local Address:Port  Peer Address:PortProcess
LISTEN 0      128                        0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096                       0.0.0.0:5432       0.0.0.0:*
LISTEN 0      5                          0.0.0.0:8888       0.0.0.0:*    users:(("python3.13",pid=965181,fd=3))
LISTEN 0      4096                     127.0.0.1:12345      0.0.0.0:*
LISTEN 0      4096                             *:4243             *:*
LISTEN 0      4096                             *:9100             *:*                       "#;

        let ports = Scanner::parse_output(output, Protocol::Tcp).unwrap();

        // Should find: 22, 5432, 8888, 12345, 4243, 9100 (all forwardable)
        assert!(ports.len() >= 6, "Expected at least 6 ports, got {}", ports.len());

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, "0.0.0.0");
        assert_eq!(port_22.protocol, Protocol::Tcp);

        let port_8888 = ports.iter().find(|p| p.port == 8888).unwrap();
        assert_eq!(port_8888.bind_address, "0.0.0.0");
        assert_eq!(port_8888.process_name, Some("python3.13".to_string()));

        let port_12345 = ports.iter().find(|p| p.port == 12345).unwrap();
        assert_eq!(port_12345.bind_address, "127.0.0.1");

        // * should be normalized to 0.0.0.0
        let port_4243 = ports.iter().find(|p| p.port == 4243).unwrap();
        assert_eq!(port_4243.bind_address, "0.0.0.0");
    }

    #[test]
    fn test_parse_ss_udp_output_no_netid() {
        // ss -ulnp output format (no Netid column because -u implies UDP)
        let output = r#"State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
UNCONN 0      0      0.0.0.0:53          0.0.0.0:*     users:(("dnsmasq",pid=1234,fd=5))
UNCONN 0      0      127.0.0.1:323       0.0.0.0:*     users:(("chronyd",pid=5678,fd=6))"#;

        let ports = Scanner::parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, "0.0.0.0");
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
        assert_eq!(port_53.protocol, Protocol::Udp);
    }
}
