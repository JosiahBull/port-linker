use crate::error::ScanError;
use crate::platform::Platform;
use crate::ss::parse_address_port;
use crate::types::RemotePort;
use crate::PortScanner;
use port_linker_proto::Protocol;
use std::process::Command;

/// Scanner that runs `netstat` as a local subprocess.
pub struct NetstatScanner;

impl PortScanner for NetstatScanner {
    fn name(&self) -> &'static str {
        "netstat"
    }

    fn description(&self) -> &'static str {
        "Runs netstat locally to discover ports"
    }

    fn valid_platform(&self, platform: &Platform) -> bool {
        platform.has_netstat
    }

    fn scan(&self, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError> {
        let flag = match protocol {
            Protocol::Tcp => "t",
            Protocol::Udp => "u",
        };

        let output = run_netstat(flag)
            .ok_or_else(|| ScanError::CommandFailed("netstat command failed".to_string()))?;

        parse_output(&output, protocol)
    }
}

fn run_netstat(proto_flag: &str) -> Option<String> {
    let args = format!("-{}lnp", proto_flag);
    let output = Command::new("netstat")
        .args(args.split_whitespace())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_output(output: &str, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError> {
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

    // netstat format:
    //    Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
    //    tcp   0      0      0.0.0.0:8080  0.0.0.0:*       LISTEN 1234/nginx
    //    parts[0] = "tcp", parts[1] = "0" (number), local_addr at index 3

    let first_col = parts.first()?.to_lowercase();
    if !first_col.starts_with(expected_prefix) {
        return None;
    }

    // Verify this is netstat format: parts[1] should be a number (Recv-Q)
    parts.get(1).and_then(|s| s.parse::<u32>().ok())?;

    let local_addr = parts.get(3)?;
    let (bind_address, port) = parse_address_port(local_addr)?;
    let process_name = extract_process_name(line);

    Some(RemotePort {
        port,
        bind_address,
        process_name,
        protocol,
    })
}

fn extract_process_name(line: &str) -> Option<String> {
    // netstat format: 1234/process
    for part in line.split_whitespace().rev() {
        if part.contains('/') {
            let pieces: Vec<&str> = part.split('/').collect();
            if pieces.len() == 2 {
                if let Some(pid_str) = pieces.first() {
                    if pid_str.parse::<u32>().is_ok() {
                        return pieces.get(1).map(|s| (*s).to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BindAddress;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_netstat_tcp_output() {
        let output = r#"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      5678/node"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_22 = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(port_22.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_22.process_name, Some("sshd".to_string()));

        let port_3000 = ports.iter().find(|p| p.port == 3000).unwrap();
        assert_eq!(port_3000.bind_address, BindAddress::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port_3000.process_name, Some("node".to_string()));
    }

    #[test]
    fn test_parse_netstat_udp_output() {
        let output = r#"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:53              0.0.0.0:*                           1234/dnsmasq
udp        0      0 127.0.0.1:323           0.0.0.0:*                           5678/chronyd"#;

        let ports = parse_output(output, Protocol::Udp).unwrap();
        assert_eq!(ports.len(), 2);

        let port_53 = ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(port_53.bind_address, BindAddress::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port_53.process_name, Some("dnsmasq".to_string()));
    }

    #[test]
    fn test_non_forwardable_filtered() {
        let output = r#"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.5:8080        0.0.0.0:*               LISTEN      111/app"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert!(
            ports.is_empty(),
            "Non-forwardable address should be filtered"
        );
    }

    #[test]
    fn test_extract_process_name() {
        assert_eq!(
            extract_process_name("tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn test_extract_process_name_no_pid() {
        assert_eq!(
            extract_process_name("tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  -"),
            None
        );
    }

    #[test]
    fn test_extract_process_name_empty() {
        assert_eq!(extract_process_name("no slash here"), None);
    }

    #[test]
    fn test_parse_output_empty() {
        let output = "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program\n";
        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_line_short() {
        assert!(parse_line("too short", Protocol::Tcp, "tcp").is_none());
    }

    #[test]
    fn test_parse_line_wrong_protocol() {
        let line = "udp  0  0  0.0.0.0:53  0.0.0.0:*  1234/dnsmasq";
        assert!(parse_line(line, Protocol::Tcp, "tcp").is_none());
    }

    #[test]
    fn test_parse_netstat_ipv6() {
        let output = r#"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp6       0      0 :::80                   :::*                    LISTEN      1234/nginx"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports.first().map(|p| p.port), Some(80));
    }

    #[test]
    fn test_parse_netstat_deduplicates() {
        let output = r#"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      100/app
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      100/app"#;

        let ports = parse_output(output, Protocol::Tcp).unwrap();
        assert_eq!(ports.len(), 1);
    }
}
