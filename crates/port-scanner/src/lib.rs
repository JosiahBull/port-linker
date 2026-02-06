//! Port scanning library for discovering listening ports.
//!
//! This crate provides platform-aware port scanning using multiple strategies:
//! - **ProcfsScanner**: Reads `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` on Linux
//! - **SsScanner**: Runs `ss` as a local subprocess
//! - **NetstatScanner**: Runs `netstat` as a local subprocess

mod error;
mod netstat;
mod platform;
mod procfs;
mod serial;
mod ss;
mod types;

pub use error::ScanError;
pub use netstat::NetstatScanner;
pub use platform::{OperatingSystem, Platform};
pub use procfs::ProcfsScanner;
pub use serial::{decode_remote_ports, encode_remote_ports};
pub use ss::SsScanner;
pub use types::{BindAddress, RemotePort};

use port_linker_proto::Protocol;

/// Trait for port scanning implementations.
pub trait PortScanner: Send + Sync {
    /// A short name identifying this scanner.
    fn name(&self) -> &'static str;

    /// A human-readable description.
    fn description(&self) -> &'static str;

    /// Whether this scanner is usable on the given platform.
    fn valid_platform(&self, platform: &Platform) -> bool;

    /// Scan for listening ports of the given protocol.
    fn scan(&self, protocol: Protocol) -> Result<Vec<RemotePort>, ScanError>;
}

/// Pick the best available scanner for the current platform.
pub fn pick_scanner(platform: &Platform) -> Option<Box<dyn PortScanner>> {
    if ProcfsScanner.valid_platform(platform) {
        return Some(Box::new(ProcfsScanner));
    }

    if SsScanner.valid_platform(platform) {
        return Some(Box::new(SsScanner));
    }

    if NetstatScanner.valid_platform(platform) {
        return Some(Box::new(NetstatScanner));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pick_scanner_prefers_procfs() {
        let platform = Platform {
            os: OperatingSystem::Linux,
            has_procfs: true,
            has_ss: true,
            has_netstat: true,
        };
        let scanner = pick_scanner(&platform).unwrap();
        assert_eq!(scanner.name(), "procfs");
    }

    #[test]
    fn test_pick_scanner_falls_back_to_ss() {
        let platform = Platform {
            os: OperatingSystem::Linux,
            has_procfs: false,
            has_ss: true,
            has_netstat: true,
        };
        let scanner = pick_scanner(&platform).unwrap();
        assert_eq!(scanner.name(), "ss");
    }

    #[test]
    fn test_pick_scanner_falls_back_to_netstat() {
        let platform = Platform {
            os: OperatingSystem::MacOs,
            has_procfs: false,
            has_ss: false,
            has_netstat: true,
        };
        let scanner = pick_scanner(&platform).unwrap();
        assert_eq!(scanner.name(), "netstat");
    }

    #[test]
    fn test_pick_scanner_returns_none() {
        let platform = Platform {
            os: OperatingSystem::Unknown("plan9".to_string()),
            has_procfs: false,
            has_ss: false,
            has_netstat: false,
        };
        assert!(pick_scanner(&platform).is_none());
    }
}
