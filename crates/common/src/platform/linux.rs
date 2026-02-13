//! Linux platform: `/proc/net` scanner, process lookup, ephemeral range, notifications.

use std::collections::HashSet;
use std::path::PathBuf;

use tracing::{debug, trace, warn};

use super::{Listener, ScanError};

// ---------------------------------------------------------------------------
// Port scanner: /proc/net/{tcp,tcp6,udp,udp6}
// ---------------------------------------------------------------------------

/// TCP socket state for LISTEN.
const TCP_LISTEN_STATE: u8 = 0x0A;

/// Scanner that reads from `/proc/net/` to discover listening ports.
pub struct ProcNetScanner {
    proc_root: PathBuf,
}

impl Default for ProcNetScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcNetScanner {
    /// Create a scanner that reads from the real `/proc` filesystem.
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// Create a scanner that reads from a custom root directory.
    /// Useful for testing with mock proc files.
    pub fn with_root(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }

    fn parse_tcp_file(&self, path: &std::path::Path) -> Result<Vec<u16>, ScanError> {
        let contents = std::fs::read_to_string(path)?;
        let mut ports = Vec::new();

        for (line_idx, line) in contents.lines().enumerate() {
            if line_idx == 0 {
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match parse_proc_net_line(line) {
                Some((port, state)) => {
                    if state == TCP_LISTEN_STATE {
                        trace!(port, state, "found TCP LISTEN socket");
                        ports.push(port);
                    }
                }
                None => {
                    debug!(line_idx, "skipping malformed line in {:?}", path);
                }
            }
        }

        Ok(ports)
    }

    fn parse_udp_file(&self, path: &std::path::Path) -> Result<Vec<u16>, ScanError> {
        let contents = std::fs::read_to_string(path)?;
        let mut ports = Vec::new();

        for (line_idx, line) in contents.lines().enumerate() {
            if line_idx == 0 {
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match parse_proc_net_line(line) {
                Some((port, _state)) => {
                    trace!(port, "found bound UDP socket");
                    ports.push(port);
                }
                None => {
                    debug!(line_idx, "skipping malformed line in {:?}", path);
                }
            }
        }

        Ok(ports)
    }
}

impl super::PortScanner for ProcNetScanner {
    fn scan(&self) -> Result<HashSet<Listener>, ScanError> {
        let mut listeners = HashSet::new();
        let net_dir = self.proc_root.join("net");

        // TCP (IPv4 + IPv6)
        for filename in &["tcp", "tcp6"] {
            let path = net_dir.join(filename);
            match self.parse_tcp_file(&path) {
                Ok(ports) => {
                    for port in ports {
                        listeners.insert((port, protocol::Protocol::Tcp));
                    }
                }
                Err(ScanError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    warn!(?path, "proc net file not found, skipping");
                }
                Err(e) => return Err(e),
            }
        }

        // UDP (IPv4 + IPv6)
        for filename in &["udp", "udp6"] {
            let path = net_dir.join(filename);
            match self.parse_udp_file(&path) {
                Ok(ports) => {
                    for port in ports {
                        listeners.insert((port, protocol::Protocol::Udp));
                    }
                }
                Err(ScanError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    warn!(?path, "proc net file not found, skipping");
                }
                Err(e) => return Err(e),
            }
        }

        debug!(count = listeners.len(), "scan complete");
        Ok(listeners)
    }
}

/// Parse a single line from `/proc/net/{tcp,tcp6,udp,udp6}`.
fn parse_proc_net_line(line: &str) -> Option<(u16, u8)> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let local_addr = fields.next()?;
    let _rem_addr = fields.next()?;
    let state_hex = fields.next()?;
    let port_hex = local_addr.rsplit(':').next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let state = u8::from_str_radix(state_hex, 16).ok()?;
    Some((port, state))
}

// ---------------------------------------------------------------------------
// Process lookup: /proc/net + /proc/*/fd
// ---------------------------------------------------------------------------

pub mod process {
    use crate::process::{ProcessInfo, TransportProto};

    pub fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        let inode = find_socket_inode(port, proto)?;
        let pid = find_pid_for_inode(inode)?;
        let name = read_process_name(pid)?;
        Some(ProcessInfo { pid, name })
    }

    fn find_socket_inode(port: u16, proto: TransportProto) -> Option<u64> {
        let proc_file = match proto {
            TransportProto::Tcp => "/proc/net/tcp",
            TransportProto::Udp => "/proc/net/udp",
        };
        let data = std::fs::read_to_string(proc_file).ok()?;
        let hex_port = format!("{:04X}", port);

        for line in data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let local_addr = fields[1];
            let state = fields[3];

            if proto == TransportProto::Tcp && state != "0A" {
                continue;
            }

            if let Some(addr_port) = local_addr.split(':').nth(1)
                && addr_port == hex_port
            {
                let ip_hex = local_addr.split(':').next().unwrap_or("");
                if ip_hex == "00000000" || ip_hex == "0100007F" {
                    return fields[9].parse().ok();
                }
            }
        }
        None
    }

    fn find_pid_for_inode(target_inode: u64) -> Option<u32> {
        let target = format!("socket:[{}]", target_inode);
        for entry in std::fs::read_dir("/proc").ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name_str = name.to_str()?;
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path())
                        && link.to_string_lossy() == target
                    {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    fn read_process_name(pid: u32) -> Option<String> {
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
        Some(comm.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Ephemeral port range: /proc/sys/net/ipv4/ip_local_port_range
// ---------------------------------------------------------------------------

pub mod ephemeral {
    pub fn detect() -> Option<(u16, u16)> {
        let contents = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
        parse_port_range(&contents)
    }

    fn parse_port_range(contents: &str) -> Option<(u16, u16)> {
        let mut parts = contents.split_whitespace();
        let start: u16 = parts.next()?.parse().ok()?;
        let end: u16 = parts.next()?.parse().ok()?;
        Some((start, end))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_typical_range() {
            assert_eq!(parse_port_range("32768\t60999\n"), Some((32768, 60999)));
        }

        #[test]
        fn parse_with_spaces() {
            assert_eq!(parse_port_range("  49152   65535  "), Some((49152, 65535)));
        }

        #[test]
        fn parse_empty_returns_none() {
            assert_eq!(parse_port_range(""), None);
        }

        #[test]
        fn parse_garbage_returns_none() {
            assert_eq!(parse_port_range("not a number"), None);
        }
    }
}

// ---------------------------------------------------------------------------
// Desktop notifications: notify-rust
// ---------------------------------------------------------------------------

/// Linux notifier using `notify-rust`.
pub struct NotifyRustNotifier;

impl Default for NotifyRustNotifier {
    fn default() -> Self {
        Self
    }
}

impl super::Notifier for NotifyRustNotifier {
    fn show(
        &self,
        title: &str,
        body: &str,
        is_error: bool,
        with_sound: bool,
    ) -> Result<(), String> {
        use notify_rust::{Hint, Notification, Urgency};

        let mut notification = Notification::new();

        notification
            .summary(title)
            .body(body)
            .appname("port-linker");

        if is_error {
            notification.urgency(Urgency::Critical);
        } else {
            notification.urgency(Urgency::Normal);
        }

        if with_sound {
            if is_error {
                notification.hint(Hint::SoundName("dialog-error".to_string()));
            } else {
                notification.hint(Hint::SoundName("message-new-instant".to_string()));
            }
        }

        notification.show().map_err(|e| e.to_string())?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::Protocol;

    fn parse_tcp_listeners(contents: &str) -> HashSet<Listener> {
        let mut listeners = HashSet::new();
        for (idx, line) in contents.lines().enumerate() {
            if idx == 0 {
                continue;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((port, state)) = parse_proc_net_line(line)
                && state == 0x0A
            {
                listeners.insert((port, Protocol::Tcp));
            }
        }
        listeners
    }

    fn parse_udp_listeners(contents: &str) -> HashSet<Listener> {
        let mut listeners = HashSet::new();
        for (idx, line) in contents.lines().enumerate() {
            if idx == 0 {
                continue;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((port, _state)) = parse_proc_net_line(line) {
                listeners.insert((port, Protocol::Udp));
            }
        }
        listeners
    }

    #[test]
    fn parse_tcp_listen_entries() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000
   2: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24680 1 0000000000000000";

        let listeners = parse_tcp_listeners(contents);
        assert!(listeners.contains(&(80, Protocol::Tcp)));
        assert!(listeners.contains(&(53, Protocol::Tcp)));
        assert!(listeners.contains(&(443, Protocol::Tcp)));
        assert_eq!(listeners.len(), 3);
    }

    #[test]
    fn parse_tcp_filters_non_listen_states() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 0100007F:C350 AC10000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000
   2: 0100007F:9C40 AC10000A:0050 06 00000000:00000000 00:00000000 00000000  1000        0 88888 1 0000000000000000";

        let listeners = parse_tcp_listeners(contents);
        assert!(listeners.contains(&(80, Protocol::Tcp)));
        assert!(!listeners.contains(&(50000, Protocol::Tcp)));
        assert!(!listeners.contains(&(40000, Protocol::Tcp)));
        assert_eq!(listeners.len(), 1);
    }

    #[test]
    fn parse_udp_includes_all_bound_sockets() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000
   1: 00000000:14E9 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 24680 1 0000000000000000";

        let listeners = parse_udp_listeners(contents);
        assert!(listeners.contains(&(53, Protocol::Udp)));
        assert!(listeners.contains(&(5353, Protocol::Udp)));
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn parse_empty_tcp_file() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let listeners = parse_tcp_listeners(contents);
        assert!(listeners.is_empty());
    }

    #[test]
    fn parse_empty_udp_file() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let listeners = parse_udp_listeners(contents);
        assert!(listeners.is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   this is completely garbage
   2: ZZZZZZZZ:GGGG 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24680 1 0000000000000000
   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000";

        let listeners = parse_tcp_listeners(contents);
        assert!(listeners.contains(&(80, Protocol::Tcp)));
        assert!(listeners.contains(&(8080, Protocol::Tcp)));
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn parse_ipv6_tcp_listen_entries() {
        let contents = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000";

        let listeners = parse_tcp_listeners(contents);
        assert!(listeners.contains(&(80, Protocol::Tcp)));
        assert!(listeners.contains(&(53, Protocol::Tcp)));
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn parse_line_extracts_correct_port_and_state() {
        let line = "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000";
        let (port, state) = parse_proc_net_line(line).expect("should parse successfully");
        assert_eq!(port, 80);
        assert_eq!(state, 0x0A);
    }

    #[test]
    fn parse_line_returns_none_for_too_few_fields() {
        let line = "   0: 00000000:0050";
        assert!(parse_proc_net_line(line).is_none());
    }

    #[test]
    fn parse_line_returns_none_for_empty_string() {
        assert!(parse_proc_net_line("").is_none());
    }

    #[cfg(target_os = "linux")]
    mod linux_integration {
        use super::super::*;
        use crate::platform::PortScanner;
        use std::fs;

        #[test]
        fn linux_scanner_with_mock_proc() {
            let tmp = std::env::temp_dir().join("port-linker-test-scanner");
            let net_dir = tmp.join("net");
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(&net_dir).unwrap();

            fs::write(
                net_dir.join("tcp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 0100007F:C350 AC10000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000
",
            )
            .unwrap();

            fs::write(
                net_dir.join("udp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000
",
            )
            .unwrap();

            let scanner = ProcNetScanner::with_root(tmp.clone());
            let result = scanner.scan().unwrap();

            assert!(result.contains(&(80, protocol::Protocol::Tcp)));
            assert!(!result.contains(&(50000, protocol::Protocol::Tcp)));
            assert!(result.contains(&(53, protocol::Protocol::Udp)));
            assert_eq!(result.len(), 2);

            let _ = fs::remove_dir_all(&tmp);
        }

        #[test]
        fn linux_scanner_missing_files_are_ok() {
            let tmp = std::env::temp_dir().join("port-linker-test-scanner-empty");
            let net_dir = tmp.join("net");
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(&net_dir).unwrap();

            fs::write(
                net_dir.join("tcp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
",
            )
            .unwrap();

            let scanner = ProcNetScanner::with_root(tmp.clone());
            let result = scanner.scan().unwrap();
            assert!(result.is_empty());

            let _ = fs::remove_dir_all(&tmp);
        }
    }
}
