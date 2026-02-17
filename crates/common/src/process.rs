use std::fmt;

use crate::platform::{CurrentPlatform, Platform};

/// Transport protocol for process lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    Tcp,
    Udp,
}

/// Information about a process holding a port.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (PID: {})", self.name, self.pid)
    }
}

/// Look up which process is bound to `port` with the given protocol.
///
/// Returns `None` if no process is found or lookup fails.
pub fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
    CurrentPlatform::find_listener(port, proto)
}

/// Send SIGTERM to a process, wait up to 1 second, then SIGKILL if still alive.
/// On Windows, calls TerminateProcess.
///
/// Returns `Ok(())` if the process was successfully terminated,
/// `Err` with a description if termination failed.
pub fn kill_process(pid: u32) -> Result<(), String> {
    CurrentPlatform::kill_process(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_display() {
        let info = ProcessInfo {
            pid: 1234,
            name: "node".into(),
        };
        assert_eq!(format!("{info}"), "node (PID: 1234)");
    }

    #[test]
    fn find_listener_nonexistent_tcp_port() {
        // Port 1 is almost certainly not in use.
        let result = find_listener(1, TransportProto::Tcp);
        assert!(result.is_none());
    }

    #[test]
    fn find_listener_nonexistent_udp_port() {
        let result = find_listener(1, TransportProto::Udp);
        assert!(result.is_none());
    }
}
