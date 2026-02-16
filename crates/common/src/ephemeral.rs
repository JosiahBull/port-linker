/// Ephemeral (dynamic) port range detection.
///
/// The OS reserves a range of ports for outgoing connections. Binding a
/// listening socket on one of these ports risks breaking outgoing traffic,
/// so we detect the range and refuse to forward those ports.
///
/// The default ephemeral range used when detection fails.
/// IANA suggests 49152-65535; Linux defaults to 32768-60999.
const DEFAULT_START: u16 = 32768;
const DEFAULT_END: u16 = 60999;

use crate::platform::{CurrentPlatform, Platform};

/// Returns the ephemeral port range `(start, end)` inclusive.
pub fn ephemeral_range() -> (u16, u16) {
    CurrentPlatform::ephemeral_range().unwrap_or((DEFAULT_START, DEFAULT_END))
}

/// Returns `true` if `port` falls within the ephemeral range.
pub fn is_ephemeral(port: u16) -> bool {
    let (start, end) = ephemeral_range();
    port >= start && port <= end
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
