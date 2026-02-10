use std::fmt;

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
    platform::find_listener(port, proto)
}

/// Send SIGTERM to a process, wait up to 1 second, then SIGKILL if still alive.
///
/// Returns `Ok(())` if the process was successfully terminated,
/// `Err` with a description if termination failed.
pub fn kill_process(pid: u32) -> Result<(), String> {
    platform::kill_process(pid)
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::{ProcessInfo, TransportProto};

    /// Use `lsof` to find which process owns a port.
    pub fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        // Output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        let output = match proto {
            TransportProto::Tcp => std::process::Command::new("lsof")
                .args(["-i", &format!("TCP:{port}"), "-sTCP:LISTEN", "-n", "-P"])
                .output()
                .ok()?,
            TransportProto::Udp => std::process::Command::new("lsof")
                .args(["-i", &format!("UDP:{port}"), "-n", "-P"])
                .output()
                .ok()?,
        };

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Skip header line, parse first result.
        let line = stdout.lines().nth(1)?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return None;
        }

        let name = fields[0].to_string();
        let pid: u32 = fields[1].parse().ok()?;
        Some(ProcessInfo { pid, name })
    }

    pub fn kill_process(pid: u32) -> Result<(), String> {
        unix_kill(pid)
    }

    fn unix_kill(pid: u32) -> Result<(), String> {
        super::unix_kill_impl(pid)
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::{ProcessInfo, TransportProto};

    /// Parse /proc/net/{tcp,udp} to find the inode for the socket,
    /// then walk /proc/*/fd to find the owning PID.
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
            // fields[1] = local_address (hex_ip:hex_port)
            // fields[3] = state (0A = LISTEN for TCP)
            let local_addr = fields[1];
            let state = fields[3];

            // TCP: only match LISTEN state. UDP: match any state.
            if proto == TransportProto::Tcp && state != "0A" {
                continue;
            }

            if let Some(addr_port) = local_addr.split(':').nth(1) {
                // Match 0.0.0.0:port or 127.0.0.1:port
                if addr_port == hex_port {
                    let ip_hex = local_addr.split(':').next().unwrap_or("");
                    // 00000000 = 0.0.0.0, 0100007F = 127.0.0.1
                    if ip_hex == "00000000" || ip_hex == "0100007F" {
                        // fields[9] = inode
                        return fields[9].parse().ok();
                    }
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
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        if link.to_string_lossy() == target {
                            return Some(pid);
                        }
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

    pub fn kill_process(pid: u32) -> Result<(), String> {
        super::unix_kill_impl(pid)
    }
}

// ---------------------------------------------------------------------------
// Fallback for other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::{ProcessInfo, TransportProto};

    pub fn find_listener(_port: u16, _proto: TransportProto) -> Option<ProcessInfo> {
        None
    }

    pub fn kill_process(_pid: u32) -> Result<(), String> {
        Err("process termination not supported on this platform".into())
    }
}

// ---------------------------------------------------------------------------
// Shared unix kill implementation (macOS + Linux)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn unix_kill_impl(pid: u32) -> Result<(), String> {
    use std::thread;
    use std::time::Duration;

    let pid_i32 = pid as i32;

    // Send SIGTERM first.
    let ret = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("SIGTERM failed for PID {pid}: {err}"));
    }

    // Wait up to 1 second for the process to exit, polling every 100ms.
    for _ in 0..10 {
        thread::sleep(Duration::from_millis(100));
        // Check if process still exists (signal 0 = existence check).
        let alive = unsafe { libc::kill(pid_i32, 0) };
        if alive != 0 {
            // Process is gone.
            return Ok(());
        }
    }

    // Still alive after 1s - send SIGKILL.
    let ret = unsafe { libc::kill(pid_i32, libc::SIGKILL) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("SIGKILL failed for PID {pid}: {err}"));
    }

    // Brief wait to confirm.
    thread::sleep(Duration::from_millis(100));
    Ok(())
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
