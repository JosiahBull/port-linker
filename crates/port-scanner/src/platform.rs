use std::path::Path;
use std::process::Command;

/// The operating system family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatingSystem {
    Linux,
    MacOs,
    FreeBsd,
    Unknown(String),
}

/// Information about the platform we are running on.
#[derive(Debug, Clone)]
pub struct Platform {
    pub os: OperatingSystem,
    pub has_procfs: bool,
    pub has_ss: bool,
    pub has_netstat: bool,
}

impl Platform {
    /// Detect the current platform by probing the local system.
    pub fn detect() -> Self {
        let os = detect_os();
        let has_procfs = Path::new("/proc/net/tcp").exists();
        let has_ss = binary_exists("ss");
        let has_netstat = binary_exists("netstat");

        Self {
            os,
            has_procfs,
            has_ss,
            has_netstat,
        }
    }
}

fn detect_os() -> OperatingSystem {
    if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else if cfg!(target_os = "macos") {
        OperatingSystem::MacOs
    } else if cfg!(target_os = "freebsd") {
        OperatingSystem::FreeBsd
    } else {
        // Fall back to uname
        match Command::new("uname").arg("-s").output() {
            Ok(output) if output.status.success() => {
                let name = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_lowercase();
                match name.as_str() {
                    "linux" => OperatingSystem::Linux,
                    "darwin" => OperatingSystem::MacOs,
                    "freebsd" => OperatingSystem::FreeBsd,
                    other => OperatingSystem::Unknown(other.to_string()),
                }
            }
            _ => OperatingSystem::Unknown("unknown".to_string()),
        }
    }
}

fn binary_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
