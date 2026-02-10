/// Ephemeral (dynamic) port range detection.
///
/// The OS reserves a range of ports for outgoing connections. Binding a
/// listening socket on one of these ports risks breaking outgoing traffic,
/// so we detect the range and refuse to forward those ports.
///
/// The default ephemeral range used when detection fails.
/// IANA suggests 49152–65535; Linux defaults to 32768–60999.
const DEFAULT_START: u16 = 32768;
const DEFAULT_END: u16 = 60999;

/// Returns the ephemeral port range `(start, end)` inclusive.
pub fn ephemeral_range() -> (u16, u16) {
    platform::detect().unwrap_or((DEFAULT_START, DEFAULT_END))
}

/// Returns `true` if `port` falls within the ephemeral range.
pub fn is_ephemeral(port: u16) -> bool {
    let (start, end) = ephemeral_range();
    port >= start && port <= end
}

// ---------------------------------------------------------------------------
// macOS: sysctl net.inet.ip.portrange.first / .last
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    pub fn detect() -> Option<(u16, u16)> {
        let first = sysctl_u16("net.inet.ip.portrange.first")?;
        let last = sysctl_u16("net.inet.ip.portrange.last")?;
        Some((first, last))
    }

    fn sysctl_u16(key: &str) -> Option<u16> {
        let output = Command::new("sysctl").arg("-n").arg(key).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let s = std::str::from_utf8(&output.stdout).ok()?.trim();
        s.parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Linux: /proc/sys/net/ipv4/ip_local_port_range
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod platform {
    use std::fs;

    pub fn detect() -> Option<(u16, u16)> {
        let contents = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
        parse_port_range(&contents)
    }

    fn parse_port_range(contents: &str) -> Option<(u16, u16)> {
        let mut parts = contents.trim().split_whitespace();
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
// Other platforms: fall back to defaults
// ---------------------------------------------------------------------------
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    pub fn detect() -> Option<(u16, u16)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_range_returns_valid_range() {
        let (start, end) = ephemeral_range();
        assert!(
            start < end,
            "start ({start}) should be less than end ({end})"
        );
        assert!(
            start >= 1024,
            "ephemeral range should not include well-known ports"
        );
    }

    #[test]
    fn well_known_ports_are_not_ephemeral() {
        assert!(!is_ephemeral(80));
        assert!(!is_ephemeral(443));
        assert!(!is_ephemeral(22));
        assert!(!is_ephemeral(8080));
    }

    #[test]
    fn high_ports_are_typically_ephemeral() {
        // These should be in the ephemeral range on most systems
        assert!(is_ephemeral(50000));
        assert!(is_ephemeral(55000));
    }

    #[test]
    fn boundary_ports() {
        let (start, end) = ephemeral_range();
        assert!(is_ephemeral(start));
        assert!(is_ephemeral(end));
        if start > 0 {
            assert!(!is_ephemeral(start - 1));
        }
        if end < u16::MAX {
            assert!(!is_ephemeral(end + 1));
        }
    }
}
