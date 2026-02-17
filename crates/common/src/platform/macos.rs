//! macOS platform: lsof-based process lookup, sysctl ephemeral range, notifications.

// ---------------------------------------------------------------------------
// Process lookup: lsof
// ---------------------------------------------------------------------------

pub mod process {
    use crate::process::{ProcessInfo, TransportProto};

    /// Use `lsof` to find which process owns a port.
    pub fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        let lsof_args = build_lsof_args(port, proto);

        // Try as current user first.
        if let Some(info) = run_lsof(&lsof_args) {
            return Some(info);
        }

        // Fallback: try with sudo -n (non-interactive, uses cached credentials).
        run_sudo_lsof(&lsof_args)
    }

    fn build_lsof_args(port: u16, proto: TransportProto) -> Vec<String> {
        match proto {
            TransportProto::Tcp => vec![
                "-i".into(),
                format!("TCP:{port}"),
                "-sTCP:LISTEN".into(),
                "-n".into(),
                "-P".into(),
            ],
            TransportProto::Udp => {
                vec!["-i".into(), format!("UDP:{port}"), "-n".into(), "-P".into()]
            }
        }
    }

    fn run_lsof(args: &[String]) -> Option<ProcessInfo> {
        let output = std::process::Command::new("lsof")
            .args(args)
            .output()
            .ok()?;
        parse_lsof_output(&output.stdout)
    }

    fn run_sudo_lsof(args: &[String]) -> Option<ProcessInfo> {
        let mut cmd_args = vec!["-n".to_string(), "lsof".to_string()];
        cmd_args.extend_from_slice(args);
        let output = std::process::Command::new("sudo")
            .args(&cmd_args)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        parse_lsof_output(&output.stdout)
    }

    fn parse_lsof_output(stdout: &[u8]) -> Option<ProcessInfo> {
        let stdout = String::from_utf8_lossy(stdout);
        let line = stdout.lines().nth(1)?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return None;
        }
        let name = fields[0].to_string();
        let pid: u32 = fields[1].parse().ok()?;
        Some(ProcessInfo { pid, name })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_lsof_typical_output() {
            let output = b"COMMAND     PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME\nnginx     12345   root    6u  IPv4  1234567      0t0  TCP *:80 (LISTEN)\n";
            let info = parse_lsof_output(output).expect("should parse typical lsof output");
            assert_eq!(info.name, "nginx");
            assert_eq!(info.pid, 12345);
        }

        #[test]
        fn test_parse_lsof_empty_output() {
            let info = parse_lsof_output(b"");
            assert!(info.is_none(), "empty output should return None");
        }

        #[test]
        fn test_parse_lsof_header_only() {
            let output = b"COMMAND     PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME\n";
            let info = parse_lsof_output(output);
            assert!(info.is_none(), "header-only output should return None");
        }

        #[test]
        fn test_parse_lsof_malformed_pid() {
            let output = b"COMMAND     PID   USER\nnginx     notapid   root\n";
            let info = parse_lsof_output(output);
            assert!(info.is_none(), "non-numeric PID should return None");
        }
    }
}

// ---------------------------------------------------------------------------
// Ephemeral port range: sysctl
// ---------------------------------------------------------------------------

pub mod ephemeral {
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
// Desktop notifications: terminal-notifier / osascript
// ---------------------------------------------------------------------------

/// macOS notifier using terminal-notifier (preferred) or osascript (fallback).
pub struct MacOsNotifier;

impl Default for MacOsNotifier {
    fn default() -> Self {
        Self
    }
}

impl super::Notifier for MacOsNotifier {
    fn show(
        &self,
        title: &str,
        body: &str,
        is_error: bool,
        with_sound: bool,
        icon: Option<&std::path::Path>,
    ) -> Result<(), String> {
        use std::process::Command;

        // Try terminal-notifier first
        let mut args = vec!["-title", title, "-message", body];
        let icon_str;
        if let Some(icon_path) = icon {
            icon_str = icon_path.display().to_string();
            args.extend_from_slice(&["-appIcon", &icon_str]);
        }
        if let Ok(output) = Command::new("terminal-notifier")
            .args(&args)
            .args(if with_sound {
                vec!["-sound", if is_error { "Basso" } else { "Pop" }]
            } else {
                vec![]
            })
            .output()
            && output.status.success()
        {
            return Ok(());
        }

        // Fallback to osascript
        let escaped_title = title.replace('\\', "\\\\").replace('"', "\\\"");
        let escaped_body = body.replace('\\', "\\\\").replace('"', "\\\"");

        let sound_part = if with_sound {
            if is_error {
                " sound name \"Basso\""
            } else {
                " sound name \"Pop\""
            }
        } else {
            ""
        };

        let script = format!(
            "display notification \"{}\" with title \"{}\"{}",
            escaped_body, escaped_title, sound_part
        );

        let output = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| format!("Failed to run osascript: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("osascript failed: {stderr}"));
        }

        Ok(())
    }
}
