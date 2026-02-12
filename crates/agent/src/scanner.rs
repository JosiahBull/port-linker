// Re-export from the platform module.
pub use common::platform::{Listener, PortScanner, ScanError};

/// The default scanner for the current platform.
pub type DefaultScanner =
    <common::platform::CurrentPlatform as common::platform::Platform>::Scanner;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use protocol::Protocol;
    use std::collections::HashSet;

    // Re-use the Linux parsing logic for tests regardless of platform.
    // We pull in the parse function directly for unit testing.

    /// Parse a single line from /proc/net/{tcp,udp,...} format.
    /// Returns (port, state) or None if malformed.
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

    /// Helper: given file contents in /proc/net/tcp format, parse TCP listeners.
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

    /// Helper: given file contents in /proc/net/udp format, parse all bound UDP sockets.
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

        assert!(
            listeners.contains(&(80, Protocol::Tcp)),
            "should contain port 80 (0x0050)"
        );
        assert!(
            listeners.contains(&(53, Protocol::Tcp)),
            "should contain port 53 (0x0035)"
        );
        assert!(
            listeners.contains(&(443, Protocol::Tcp)),
            "should contain port 443 (0x01BB)"
        );
        assert_eq!(listeners.len(), 3);
    }

    #[test]
    fn parse_tcp_filters_non_listen_states() {
        // State 01 = ESTABLISHED, 06 = TIME_WAIT - should not be included.
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 0100007F:C350 AC10000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000
   2: 0100007F:9C40 AC10000A:0050 06 00000000:00000000 00:00000000 00000000  1000        0 88888 1 0000000000000000";

        let listeners = parse_tcp_listeners(contents);

        assert!(
            listeners.contains(&(80, Protocol::Tcp)),
            "should contain port 80 (LISTEN)"
        );
        assert!(
            !listeners.contains(&(50000, Protocol::Tcp)),
            "should NOT contain port 50000 (ESTABLISHED)"
        );
        assert!(
            !listeners.contains(&(40000, Protocol::Tcp)),
            "should NOT contain port 40000 (TIME_WAIT)"
        );
        assert_eq!(listeners.len(), 1);
    }

    #[test]
    fn parse_udp_includes_all_bound_sockets() {
        // State 07 = CLOSE, state 01 = ESTABLISHED - both should be included for UDP.
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000
   1: 00000000:14E9 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 24680 1 0000000000000000";

        let listeners = parse_udp_listeners(contents);

        assert!(
            listeners.contains(&(53, Protocol::Udp)),
            "should contain port 53 (0x0035)"
        );
        assert!(
            listeners.contains(&(5353, Protocol::Udp)),
            "should contain port 5353 (0x14E9)"
        );
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

        // Only port 80 (0x0050) and 8080 (0x1F90) should be found.
        // The garbage line and the GGGG port should be skipped.
        assert!(listeners.contains(&(80, Protocol::Tcp)));
        assert!(listeners.contains(&(8080, Protocol::Tcp)));
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn parse_ipv6_tcp_listen_entries() {
        // IPv6 local_address is longer but the port is still after the last colon.
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

    // -----------------------------------------------------------------------
    // File-based integration tests using temp directories (Linux-only).
    // -----------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    mod linux_integration {
        use super::*;
        use std::fs;

        #[test]
        fn linux_scanner_with_mock_proc() {
            let tmp = std::env::temp_dir().join("port-linker-test-scanner");
            let net_dir = tmp.join("net");
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(&net_dir).unwrap();

            // Write mock tcp file.
            fs::write(
                net_dir.join("tcp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 0100007F:C350 AC10000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000
",
            )
            .unwrap();

            // Write mock udp file.
            fs::write(
                net_dir.join("udp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    65534        0 13579 1 0000000000000000
",
            )
            .unwrap();

            let scanner = common::platform::linux::ProcNetScanner::with_root(tmp.clone());
            let result = scanner.scan().unwrap();

            assert!(result.contains(&(80, Protocol::Tcp)));
            assert!(
                !result.contains(&(50000, Protocol::Tcp)),
                "ESTABLISHED socket should not appear"
            );
            assert!(result.contains(&(53, Protocol::Udp)));
            assert_eq!(result.len(), 2);

            // Cleanup.
            let _ = fs::remove_dir_all(&tmp);
        }

        #[test]
        fn linux_scanner_missing_files_are_ok() {
            let tmp = std::env::temp_dir().join("port-linker-test-scanner-empty");
            let net_dir = tmp.join("net");
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(&net_dir).unwrap();

            // Only write tcp - leave tcp6, udp, udp6 missing.
            fs::write(
                net_dir.join("tcp"),
                "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
",
            )
            .unwrap();

            let scanner = common::platform::linux::ProcNetScanner::with_root(tmp.clone());
            let result = scanner.scan().unwrap();

            assert!(result.is_empty());

            let _ = fs::remove_dir_all(&tmp);
        }
    }
}
