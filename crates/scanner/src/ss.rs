use crate::error::ScanError;
use crate::platform::Platform;
use crate::types::{BindAddress, RemotePort};
use crate::PortScanner;
use proto::Protocol;
use std::process::Command;

/// Scanner that runs `ss` as a local subprocess.
pub struct SsScanner;

impl PortScanner for SsScanner {
    fn name(&self) -> &'static str {
        "ss"
    }

    fn description(&self) -> &'static str {
        "Runs ss locally to discover ports"
    }

    fn valid_platform(&self, platform: &Platform) -> bool {
        platform.has_ss
    }

    fn scan(&self, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError> {
        let flag = match protocol {
            Protocol::Tcp => "t",
            Protocol::Udp => "u",
        };

        let output = run_ss(flag).ok_or_else(|| {
            ScanError::CommandFailed("ss command failed".to_string())
        })?;

        if !is_valid_ss_output(&output, protocol) {
            return Err(ScanError::CommandFailed(
                "ss returned invalid output".to_string(),
            ));
        }

        parse_output(&output, protocol)
    }
}

fn run_ss(proto_flag: &str) -> Option<String> {
    let args = format!("-{}lnp", proto_flag);
    let output = Command::new("ss")
        .args(args.split_whitespace())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

fn is_valid_ss_output(output: &str, protocol: Protocol) -> bool {
    if output.is_empty() {
        return false;
    }
    match protocol {
        Protocol::Tcp => output.contains("State"),
        Protocol::Udp => output.contains("State") || output.contains("UNCONN"),
    }
}

pub fn parse_output(output: &str, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError> {
    let expected_prefix = match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };

    let mut ports = Vec::new();

    for line in output.lines().skip(1) {
        if let Some(port) = parse_line(line, protocol, expected_prefix) {
            if port.bind_address.is_forwardable() {
                ports.push(port);
            }
        }
    }

    // Deduplicate by port
    ports.sort_by_key(|p| p.port);
    ports.dedup_by_key(|p| p.port);

    Ok(ports)
}

fn parse_line(line: &str, protocol: Protocol, expected_prefix: &str) -> Option<RemotePort> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        return None;
    }

    // Detect the output format and find the local address column index.
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

    let first_col = parts.first()?.to_lowercase();
    let is_state = matches!(
        first_col.as_str(),
        "listen"
            | "estab"
            | "established"
            | "unconn"
            | "time-wait"
            | "close-wait"
            | "syn-sent"
            | "syn-recv"
    );
    let is_protocol = first_col.starts_with(expected_prefix);

    let local_addr_idx = if is_state {
        // No Netid column
        3
    } else if is_protocol {
        // Has Netid column
        4
    } else {
        return None;
    };

    let local_addr = parts.get(local_addr_idx)?;
    let (bind_address, port) = parse_address_port(local_addr)?;
    let process_name = extract_process_name(line);

    Some(RemotePort {
        port,
        bind_address,
        process_name,
        protocol,
    })
}

pub fn parse_address_port(addr: &str) -> Option<(BindAddress, u16)> {
    // Handle IPv6 format [::]:port or [::1]:port
    if addr.starts_with('[') {
        let end_bracket = addr.find(']')?;
        let address = addr.get(1..end_bracket)?;
        let port_str = addr.get(end_bracket.checked_add(2)?..)?;
        let port = port_str.parse().ok()?;
        let bind = BindAddress::parse_str(address)?;
        return Some((bind, port));
    }

    // Handle :::port (IPv6 any)
    if let Some(port_str) = addr.strip_prefix(":::") {
        let port = port_str.parse().ok()?;
        return Some((BindAddress::parse_str("::")?, port));
    }

    // Standard IPv4 or single colon format
    let last_colon = addr.rfind(':')?;
    let address = addr.get(..last_colon)?;
    let port_str = addr.get(last_colon.checked_add(1)?..)?;

    // Handle * as 0.0.0.0
    let address = if address == "*" { "0.0.0.0" } else { address };

    let port = port_str.parse().ok()?;
    let bind = BindAddress::parse_str(address)?;
    Some((bind, port))
}

fn extract_process_name(line: &str) -> Option<String> {
    // ss format: users:(("process",pid=1234,fd=5))
    if let Some(start) = line.find("users:((\"") {
        let rest = line.get(start.checked_add(9)?..)?;
        if let Some(end) = rest.find('"') {
            return Some(rest.get(..end)?.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_ss_tcp_output() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     127.0.0.1:3000        0.0.0.0:*         users:(("node",pid=5678,fd=5))
tcp    LISTEN  0       128     [::]:80               [::]:*            users:(("nginx",pid=9012,fd=6))"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 3);

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

        let ports = parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
        assert_eq!(port_53.protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_ss_tcp_no_netid() {
        let output = r#"State  Recv-Q Send-Q               Local Address:Port  Peer Address:PortProcess
LISTEN 0      128                        0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096                       0.0.0.0:5432       0.0.0.0:*
LISTEN 0      5                          0.0.0.0:8888       0.0.0.0:*    users:(("python3.13",pid=965181,fd=3))
LISTEN 0      4096                     127.0.0.1:12345      0.0.0.0:*
LISTEN 0      4096                             *:4243             *:*
LISTEN 0      4096                             *:9100             *:*                       "#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert!(ports.len() >= 6, "Expected at least 6 ports, got {}", ports.len());

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));

        let port_8888 = ports.iter().find(|p| p.port == 8888).unwrap();
        assert_eq!(port_8888.process_name, Some("python3.13".to_string()));

        let port_12345 = ports.iter().find(|p| p.port == 12345).unwrap();
        assert_eq!(port_12345.bind_address, BindAddress::V4(Ipv4Addr::LOCALHOST));

        let port_4243 = ports.iter().find(|p| p.port == 4243).unwrap();
        assert_eq!(port_4243.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_ss_udp_no_netid() {
        let output = r#"State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
UNCONN 0      0      0.0.0.0:53          0.0.0.0:*     users:(("dnsmasq",pid=1234,fd=5))
UNCONN 0      0      127.0.0.1:323       0.0.0.0:*     users:(("chronyd",pid=5678,fd=6))"#;

        let ports = parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
    }

    #[test]
    fn test_parse_address_port() {
        let (addr, port) = parse_address_port("0.0.0.0:8080").unwrap();
        assert_eq!(addr, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 8080);

        let (addr, port) = parse_address_port("127.0.0.1:3000").unwrap();
        assert_eq!(addr, BindAddress::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 3000);

        let (addr, port) = parse_address_port("[::]:80").unwrap();
        assert_eq!(
            addr,
            BindAddress::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(port, 80);

        let (addr, port) = parse_address_port(":::8080").unwrap();
        assert_eq!(
            addr,
            BindAddress::V6(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(port, 8080);

        let (addr, port) = parse_address_port("*:22").unwrap();
        assert_eq!(addr, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 22);
    }

    #[test]
    fn test_non_forwardable_filtered() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port Process
tcp    LISTEN  0       128     192.168.1.5:8080      0.0.0.0:*         users:(("app",pid=111,fd=3))"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert!(ports.is_empty(), "Non-forwardable address should be filtered");
    }

    #[test]
    fn test_is_valid_ss_output_tcp() {
        assert!(is_valid_ss_output("State  Recv-Q\nLISTEN 0", Protocol::Tcp));
        assert!(!is_valid_ss_output("", Protocol::Tcp));
        assert!(!is_valid_ss_output("no header", Protocol::Tcp));
    }

    #[test]
    fn test_is_valid_ss_output_udp() {
        assert!(is_valid_ss_output("State  Recv-Q\nUNCONN 0", Protocol::Udp));
        assert!(is_valid_ss_output("UNCONN something", Protocol::Udp));
        assert!(!is_valid_ss_output("", Protocol::Udp));
    }

    #[test]
    fn test_extract_process_name_ss() {
        assert_eq!(
            extract_process_name("LISTEN 0 128 0.0.0.0:22 users:((\"sshd\",pid=1234,fd=3))"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn test_extract_process_name_none() {
        assert_eq!(
            extract_process_name("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"),
            None
        );
    }

    #[test]
    fn test_parse_address_port_ipv6_loopback() {
        let (addr, port) = parse_address_port("[::1]:8080").unwrap();
        assert_eq!(addr, BindAddress::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_address_port_returns_none_for_garbage() {
        assert!(parse_address_port("not_an_address").is_none());
        assert!(parse_address_port("").is_none());
    }

    #[test]
    fn test_parse_output_empty_body() {
        let output = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n";
        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_line_unknown_first_col() {
        assert!(parse_line("garbage 0 128 0.0.0.0:22 0.0.0.0:*", Protocol::Tcp, "tcp").is_none());
    }

    #[test]
    fn test_parse_output_deduplicates() {
        let output = r#"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 1);
    }
}
