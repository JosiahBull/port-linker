use std::process::Command;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    #[allow(dead_code)]
    pub command: Option<String>,
}

pub fn find_process_on_port(port: u16) -> Option<ProcessInfo> {
    // Use lsof on macOS/Linux to find process using the port
    #[cfg(target_os = "macos")]
    {
        find_with_lsof(port)
            .or_else(|| find_with_netstat_macos(port))
    }

    #[cfg(target_os = "linux")]
    {
        find_with_ss(port).or_else(|| find_with_lsof(port))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        find_with_sysinfo(port)
    }
}

fn find_with_lsof(port: u16) -> Option<ProcessInfo> {
    let output = Command::new("lsof")
        .args(["-i", &format!(":{}", port), "-n", "-P"])
        .output()
        .ok()?;

    if !output.status.success() {
        debug!("lsof failed for port {}", port);
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("lsof output for port {}: {}", port, stdout);

    // Parse lsof output - format:
    // COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
    // node    12345  user   22u  IPv4  0x1234  0t0  TCP *:8080 (LISTEN)
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pid) = parts[1].parse::<u32>() {
                let name = parts[0].to_string();

                // Get full command
                let command = get_process_command(pid);

                debug!("Found process {} (PID {}) on port {}", name, pid, port);

                return Some(ProcessInfo { pid, name, command });
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn find_with_netstat_macos(port: u16) -> Option<ProcessInfo> {
    // netstat on macOS doesn't show PIDs, but we can try lsof with sudo hint
    debug!("netstat fallback for port {} (limited without root)", port);

    // Try to at least confirm something is listening
    let output = Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let port_str = format!(".{}", port);

    for line in stdout.lines() {
        if line.contains(&port_str) && line.contains("LISTEN") {
            debug!("Port {} confirmed in use via netstat, but PID unavailable without root", port);
            // We know it's in use but can't get PID without sudo
            return None;
        }
    }

    None
}

fn get_process_command(pid: u32) -> Option<String> {
    let cmd_output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
        .ok()?;

    if cmd_output.status.success() {
        let cmd = String::from_utf8_lossy(&cmd_output.stdout).trim().to_string();
        if !cmd.is_empty() {
            return Some(cmd);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_with_ss(port: u16) -> Option<ProcessInfo> {
    let output = Command::new("ss")
        .args(["-tlnp", &format!("sport = :{}", port)])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse ss output to extract PID
    // Format: users:(("process",pid=1234,fd=5))
    for line in stdout.lines() {
        if let Some(start) = line.find("pid=") {
            let rest = &line[start + 4..];
            if let Some(end) = rest.find(',') {
                let pid: u32 = rest[..end].parse().ok()?;

                // Get process name from /proc
                let cmdline = std::fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
                let name = cmdline.trim().to_string();

                let command = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                    .ok()
                    .map(|s| s.replace('\0', " ").trim().to_string());

                return Some(ProcessInfo { pid, name, command });
            }
        }
    }

    None
}

#[allow(dead_code)]
fn find_with_sysinfo(_port: u16) -> Option<ProcessInfo> {
    // This is a fallback that doesn't directly find by port
    // Placeholder for other platforms
    None
}
