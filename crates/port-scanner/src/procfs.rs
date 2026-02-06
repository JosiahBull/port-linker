use crate::error::ScanError;
use crate::platform::Platform;
use crate::types::{BindAddress, RemotePort};
use crate::PortScanner;
use port_linker_proto::Protocol;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Scanner that reads `/proc/net/{tcp,tcp6,udp,udp6}` on Linux.
pub struct ProcfsScanner;

impl PortScanner for ProcfsScanner {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn description(&self) -> &'static str {
        "Reads /proc/net/{tcp,udp}{,6} on Linux"
    }

    fn valid_platform(&self, platform: &Platform) -> bool {
        platform.has_procfs
    }

    fn scan(&self, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError> {
        let (path_v4, path_v6) = match protocol {
            Protocol::Tcp => ("/proc/net/tcp", "/proc/net/tcp6"),
            Protocol::Udp => ("/proc/net/udp", "/proc/net/udp6"),
        };

        let listen_state = match protocol {
            Protocol::Tcp => "0A", // TCP_LISTEN
            Protocol::Udp => "07", // UDP_UNCONN (close / unconnected)
        };

        let mut ports = Vec::new();

        // Build inode -> process name map for process resolution
        let inode_map = build_inode_map();

        // Parse IPv4 entries
        if let Ok(content) = std::fs::read_to_string(path_v4) {
            parse_proc_net(&content, listen_state, false, &inode_map, protocol, &mut ports);
        }

        // Parse IPv6 entries
        if let Ok(content) = std::fs::read_to_string(path_v6) {
            parse_proc_net(&content, listen_state, true, &inode_map, protocol, &mut ports);
        }

        // Deduplicate by port
        ports.sort_by_key(|p| p.port);
        ports.dedup_by_key(|p| p.port);

        Ok(ports)
    }
}

/// Parse a `/proc/net/{tcp,udp}{,6}` file.
///
/// Format (space-delimited, hex-encoded):
/// ```text
///   sl  local_address  rem_address  st  tx_queue:rx_queue  ...  inode  ...
///    0: 00000000:0016 00000000:0000 0A 00000000:00000000  ...  12345  ...
/// ```
///
/// Fields we care about:
/// - `[1]` local_address: `hex_addr:hex_port`
/// - `[3]` state (hex)
/// - `[9]` inode
fn parse_proc_net(
    content: &str,
    listen_state: &str,
    is_v6: bool,
    inode_map: &HashMap<u64, String>,
    protocol: Protocol,
    out: &mut Vec<RemotePort>,
) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // Check state
        if fields.get(3) != Some(&listen_state) {
            continue;
        }

        // Parse local address:port
        let local = match fields.get(1) {
            Some(f) => *f,
            None => continue,
        };
        let (addr_hex, port) = match parse_hex_addr_port(local) {
            Some(v) => v,
            None => continue,
        };

        let bind_address = if is_v6 {
            parse_v6_hex(&addr_hex)
        } else {
            parse_v4_hex(&addr_hex)
        };

        let bind_address = match bind_address {
            Some(a) => a,
            None => continue,
        };

        if !bind_address.is_forwardable() {
            continue;
        }

        // Resolve process name from inode
        let inode: u64 = fields
            .get(9)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let process_name = inode_map.get(&inode).cloned();

        out.push(RemotePort {
            port,
            bind_address,
            process_name,
            protocol,
        });
    }
}

/// Parse `hex_addr:hex_port` into (addr_hex_string, port).
fn parse_hex_addr_port(s: &str) -> Option<(String, u16)> {
    let (addr, port_hex) = s.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr.to_string(), port))
}

/// Parse an IPv4 hex address from procfs into `BindAddress`.
///
/// The address is printed as `%08X` of the native-endian u32.
/// `to_le_bytes()` recovers the original network-order bytes.
fn parse_v4_hex(hex: &str) -> Option<BindAddress> {
    if hex.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex, 16).ok()?;
    let bytes = val.to_le_bytes();
    let addr = Ipv4Addr::new(
        *bytes.first()?,
        *bytes.get(1)?,
        *bytes.get(2)?,
        *bytes.get(3)?,
    );
    Some(BindAddress::V4(addr))
}

/// Parse an IPv6 hex address from procfs into `BindAddress`.
///
/// In `/proc/net/*6`, each 128-bit address is printed as four `%08X`-formatted
/// u32 values concatenated. Each u32 was read from memory in native byte order,
/// so on a little-endian machine the printed hex is the LE representation.
/// Converting back with `to_le_bytes()` recovers the original network-order bytes.
fn parse_v6_hex(hex: &str) -> Option<BindAddress> {
    if hex.len() != 32 {
        return None;
    }

    let mut octets = [0_u8; 16];
    for i in 0_usize..4 {
        let start = i.checked_mul(8)?;
        let end = start.checked_add(8)?;
        let word_hex = hex.get(start..end)?;
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        // The hex represents a native-endian u32; to_le_bytes() on LE is identity,
        // giving us back the original big-endian (network order) bytes.
        let bytes = word.to_le_bytes();
        let offset = i.checked_mul(4)?;
        *octets.get_mut(offset)? = *bytes.first()?;
        *octets.get_mut(offset.checked_add(1)?)? = *bytes.get(1)?;
        *octets.get_mut(offset.checked_add(2)?)? = *bytes.get(2)?;
        *octets.get_mut(offset.checked_add(3)?)? = *bytes.get(3)?;
    }

    let addr = Ipv6Addr::from(octets);

    // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if let Some(v4) = addr.to_ipv4_mapped() {
        return Some(BindAddress::V4(v4));
    }

    Some(BindAddress::V6(addr))
}

/// Build a mapping from socket inode to process name by scanning `/proc/[pid]/fd/`.
fn build_inode_map() -> HashMap<u64, String> {
    let mut map = HashMap::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        // Only look at numeric directories (PIDs)
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid_path = entry.path();
        let fd_dir = pid_path.join("fd");

        let fd_entries = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Read process name once per pid
        let comm_path = pid_path.join("comm");
        let proc_name = std::fs::read_to_string(&comm_path)
            .ok()
            .map(|c| c.trim().to_string());

        if let Some(ref pname) = proc_name {
            for fd_entry in fd_entries.flatten() {
                let link = match std::fs::read_link(fd_entry.path()) {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                let link_str = link.to_string_lossy();
                // Socket links look like "socket:[12345]"
                if let Some(inode_str) = link_str.strip_prefix("socket:[") {
                    if let Some(inode_str) = inode_str.strip_suffix(']') {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, pname.clone());
                        }
                    }
                }
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_port() {
        assert_eq!(
            parse_hex_addr_port("00000000:0016"),
            Some(("00000000".to_string(), 22))
        );
        assert_eq!(
            parse_hex_addr_port("0100007F:0BB8"),
            Some(("0100007F".to_string(), 3000))
        );
    }

    #[test]
    fn test_parse_v4_hex() {
        // 00000000 = 0.0.0.0 (unspecified)
        let addr = parse_v4_hex("00000000");
        assert_eq!(addr, Some(BindAddress::V4(Ipv4Addr::UNSPECIFIED)));

        // 0100007F = 127.0.0.1 in little-endian
        let addr = parse_v4_hex("0100007F");
        assert_eq!(addr, Some(BindAddress::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_v6_hex_unspecified() {
        // All zeros = ::
        let addr = parse_v6_hex("00000000000000000000000000000000");
        assert_eq!(addr, Some(BindAddress::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_parse_v6_hex_loopback() {
        // ::1 in procfs format on a little-endian system.
        // Word 3 = 0x00000001 stored as LE bytes [01,00,00,00], printed as "01000000".
        let addr = parse_v6_hex("00000000000000000000000001000000");
        assert_eq!(addr, Some(BindAddress::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0
   2: 0100A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
"#;
        let inode_map = HashMap::new();
        let mut ports = Vec::new();
        parse_proc_net(content, "0A", false, &inode_map, Protocol::Tcp, &mut ports);

        // Should find 0.0.0.0:22 and 127.0.0.1:3000 (forwardable)
        // Should NOT find 192.168.0.1:8080 (non-forwardable)
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().any(|p| p.port == 22));
        assert!(ports.iter().any(|p| p.port == 3000));
    }

    #[test]
    fn test_parse_proc_net_skips_non_listen() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0 100 0 0 10 0
   1: 00000000:0050 01020304:1234 01 00000000:00000000 00:00000000 00000000  1000        0 200 1 0 100 0 0 10 0
"#;
        let inode_map = HashMap::new();
        let mut ports = Vec::new();
        parse_proc_net(content, "0A", false, &inode_map, Protocol::Tcp, &mut ports);
        // Only the LISTEN (0A) line should match, not ESTABLISHED (01)
        assert_eq!(ports.len(), 1);
        assert_eq!(ports.first().map(|p| p.port), Some(22));
    }

    #[test]
    fn test_parse_proc_net_udp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 300 1 0 100 0 0 10 0
"#;
        let inode_map = HashMap::new();
        let mut ports = Vec::new();
        parse_proc_net(content, "07", false, &inode_map, Protocol::Udp, &mut ports);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports.first().map(|p| p.port), Some(53));
        assert_eq!(
            ports.first().map(|p| p.protocol),
            Some(Protocol::Udp)
        );
    }

    #[test]
    fn test_parse_proc_net_with_inode_map() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0
"#;
        let mut inode_map = HashMap::new();
        inode_map.insert(12345, "sshd".to_string());
        let mut ports = Vec::new();
        parse_proc_net(content, "0A", false, &inode_map, Protocol::Tcp, &mut ports);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports.first().and_then(|p| p.process_name.as_deref()), Some("sshd"));
    }

    #[test]
    fn test_parse_proc_net_malformed_line() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   short line
"#;
        let inode_map = HashMap::new();
        let mut ports = Vec::new();
        parse_proc_net(content, "0A", false, &inode_map, Protocol::Tcp, &mut ports);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_hex_addr_port_invalid() {
        assert!(parse_hex_addr_port("no_colon").is_none());
        assert!(parse_hex_addr_port("ADDR:ZZZZ").is_none());
    }

    #[test]
    fn test_parse_v4_hex_invalid_length() {
        assert!(parse_v4_hex("0000").is_none());
        assert!(parse_v4_hex("0000000000").is_none());
    }

    #[test]
    fn test_parse_v4_hex_invalid_hex() {
        assert!(parse_v4_hex("ZZZZZZZZ").is_none());
    }

    #[test]
    fn test_parse_v6_hex_invalid_length() {
        assert!(parse_v6_hex("0000").is_none());
        assert!(parse_v6_hex("000000000000000000000000000000000000").is_none());
    }

    #[test]
    fn test_parse_v6_hex_ipv4_mapped() {
        // ::ffff:127.0.0.1 in procfs LE format
        // Network bytes: 00,00,00,00 00,00,00,00 00,00,FF,FF 7F,00,00,01
        // LE u32 words:  00000000    00000000    FFFF0000    0100007F
        let addr = parse_v6_hex("0000000000000000FFFF00000100007F");
        assert_eq!(addr, Some(BindAddress::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_v6_hex_non_special() {
        // fe80::1 = FE80:0000:0000:0000:0000:0000:0000:0001
        // In procfs LE format (each u32 is LE-printed):
        // word0 = bytes FE,80,00,00 => LE u32 = 0x000080FE => "000080FE"
        // word1 = 0x00000000 => "00000000"
        // word2 = 0x00000000 => "00000000"
        // word3 = bytes 00,00,00,01 => LE u32 = 0x01000000 => "01000000"
        let addr = parse_v6_hex("000080FE000000000000000001000000");
        assert!(matches!(addr, Some(BindAddress::V6(_))));
    }
}
