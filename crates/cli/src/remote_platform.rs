//! Runtime abstraction over a remote host's OS for bootstrap commands.
//!
//! The local [`Platform`](common::platform::Platform) trait is compile-time.
//! For SSH bootstrap commands against remote targets, we need a runtime
//! abstraction since the remote OS is detected via SSH probe.

use tracing::{info, warn};

use common::{Error, Result};

use crate::ssh::SshExecutor;

/// Runtime abstraction over a remote host's OS for bootstrap commands.
///
/// Detected at connect time via SSH probe. Each method returns a shell command
/// string appropriate for the target OS.
pub trait RemotePlatform: Send + Sync {
    /// Command to detect CPU architecture (stdout: "x86_64" or "aarch64").
    fn detect_arch_cmd(&self) -> &str;

    /// Command to decompress gzip stdin to a file and make it executable.
    fn transfer_compressed_cmd(&self, remote_path: &str) -> String;

    /// Command to write raw stdin to a file and make it executable.
    fn transfer_raw_cmd(&self, remote_path: &str) -> String;

    /// Command to check if a cached binary exists.
    fn check_cache_cmd(&self, cache_path: &str) -> String;

    /// Command to copy a cached binary to the agent path.
    fn copy_cached_cmd(&self, cache_path: &str, remote_path: &str) -> String;

    /// Command to populate the cache (mkdir, copy, prune old entries).
    fn populate_cache_cmd(&self, remote_path: &str, cache_path: &str) -> String;

    /// Command to kill the agent process and remove the binary.
    fn cleanup_cmd(&self, remote_path: &str) -> String;

    /// Resolved cache directory on the remote host.
    fn cache_dir(&self) -> &str;

    /// Resolved temp directory on the remote host.
    fn temp_dir(&self) -> &str;

    /// Normalize a raw architecture string from the remote.
    fn normalize_arch(&self, raw: &str) -> Result<String>;

    /// OS identifier for binary lookup (e.g., "linux", "darwin").
    fn os_id(&self) -> &str;

    /// Binary file extension on this platform ("" or ".exe").
    fn binary_ext(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Unix remote (Linux or macOS)
// ---------------------------------------------------------------------------

/// Unix remote (Linux or macOS).
pub struct RemoteUnix {
    temp: String,
    cache: String,
    os: String,
}

impl RemotePlatform for RemoteUnix {
    fn detect_arch_cmd(&self) -> &str {
        "uname -m"
    }

    fn transfer_compressed_cmd(&self, path: &str) -> String {
        format!("gunzip -c > '{path}' && chmod +x '{path}'")
    }

    fn transfer_raw_cmd(&self, path: &str) -> String {
        format!("cat > '{path}' && chmod +x '{path}'")
    }

    fn check_cache_cmd(&self, cache_path: &str) -> String {
        format!("test -x '{cache_path}' && echo OK")
    }

    fn copy_cached_cmd(&self, cache_path: &str, remote_path: &str) -> String {
        format!("cp '{cache_path}' '{remote_path}' && chmod +x '{remote_path}'")
    }

    fn populate_cache_cmd(&self, remote_path: &str, cache_path: &str) -> String {
        let cache_dir = &self.cache;
        format!(
            "mkdir -p '{cache_dir}' && cp '{remote_path}' '{cache_path}' && \
             find '{cache_dir}' -name 'agent-*' -mtime +7 -delete 2>/dev/null; true"
        )
    }

    fn cleanup_cmd(&self, path: &str) -> String {
        format!("pkill -f '{path}' 2>/dev/null; rm -f '{path}'")
    }

    fn cache_dir(&self) -> &str {
        &self.cache
    }

    fn temp_dir(&self) -> &str {
        &self.temp
    }

    fn normalize_arch(&self, raw: &str) -> Result<String> {
        match raw.trim() {
            "x86_64" => Ok("x86_64".into()),
            "aarch64" | "arm64" => Ok("aarch64".into()),
            other => Err(Error::Protocol(format!(
                "unsupported architecture: {other}"
            ))),
        }
    }

    fn os_id(&self) -> &str {
        &self.os
    }

    fn binary_ext(&self) -> &str {
        ""
    }
}

// ---------------------------------------------------------------------------
// Runtime detection via SSH probe
// ---------------------------------------------------------------------------

/// Detect the remote OS and resolve its directories via SSH.
/// Returns a trait object for use throughout the bootstrap flow.
pub async fn detect_remote_platform(ssh: &(impl SshExecutor + ?Sized)) -> Box<dyn RemotePlatform> {
    // Try uname (succeeds on Unix, fails on Windows).
    if let Ok((stdout, _, Some(0))) = ssh.exec("uname -s 2>/dev/null").await {
        let os_raw = stdout.trim().to_lowercase();
        if os_raw.contains("linux") || os_raw.contains("darwin") {
            let os_id = if os_raw.contains("darwin") {
                "darwin"
            } else {
                "linux"
            };
            // Resolve remote temp dir (respect $TMPDIR, don't assume /tmp).
            let temp =
                if let Ok((t, _, Some(0))) = ssh.exec("printf '%s' \"${TMPDIR:-/tmp}\"").await {
                    t.trim_end_matches('/').to_string()
                } else {
                    "/tmp".to_string()
                };
            let cache = format!("{temp}/.port-linker-cache");
            info!(os = os_id, temp = %temp, "detected Unix remote platform");
            return Box::new(RemoteUnix {
                temp,
                cache,
                os: os_id.to_string(),
            });
        }
    }

    // Default to Unix with /tmp.
    warn!("could not detect remote OS, defaulting to Linux");
    Box::new(RemoteUnix {
        temp: "/tmp".to_string(),
        cache: "/tmp/.port-linker-cache".to_string(),
        os: "linux".to_string(),
    })
}

/// Helpers for constructing platform instances in tests.
#[cfg(test)]
#[allow(dead_code)]
pub mod test_helpers {
    use super::*;

    /// Create a default Unix (Linux) remote platform for tests.
    pub fn unix_platform() -> RemoteUnix {
        RemoteUnix {
            temp: "/tmp".into(),
            cache: "/tmp/.port-linker-cache".into(),
            os: "linux".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_unix_os_id() {
        let u = RemoteUnix {
            temp: "/tmp".into(),
            cache: "/tmp/.port-linker-cache".into(),
            os: "linux".into(),
        };
        assert_eq!(u.os_id(), "linux");
        assert_eq!(u.binary_ext(), "");
    }

    #[test]
    fn remote_unix_normalize_arch() {
        let u = RemoteUnix {
            temp: "/tmp".into(),
            cache: "/tmp/.port-linker-cache".into(),
            os: "linux".into(),
        };
        assert_eq!(u.normalize_arch("x86_64").unwrap(), "x86_64");
        assert_eq!(u.normalize_arch("aarch64").unwrap(), "aarch64");
        assert_eq!(u.normalize_arch("arm64").unwrap(), "aarch64");
        assert!(u.normalize_arch("riscv64").is_err());
    }

    #[test]
    fn remote_unix_transfer_cmds() {
        let u = RemoteUnix {
            temp: "/tmp".into(),
            cache: "/tmp/.port-linker-cache".into(),
            os: "linux".into(),
        };
        let cmd = u.transfer_compressed_cmd("/tmp/agent-xyz");
        assert!(cmd.contains("gunzip"));
        assert!(cmd.contains("chmod +x"));

        let cmd = u.transfer_raw_cmd("/tmp/agent-xyz");
        assert!(cmd.contains("cat >"));
        assert!(cmd.contains("chmod +x"));
    }

    #[test]
    fn remote_unix_cleanup_cmd() {
        let u = RemoteUnix {
            temp: "/tmp".into(),
            cache: "/tmp/.port-linker-cache".into(),
            os: "linux".into(),
        };
        let cmd = u.cleanup_cmd("/tmp/agent-xyz");
        assert!(cmd.contains("pkill"));
        assert!(cmd.contains("rm -f"));
    }

    #[test]
    fn remote_unix_check_cache_cmd() {
        let u = test_helpers::unix_platform();
        let cmd = u.check_cache_cmd("/tmp/.port-linker-cache/agent-hash");
        assert!(cmd.contains("test -x"), "should use test -x");
        assert!(cmd.contains("echo OK"), "should echo OK on success");
    }

    #[test]
    fn remote_unix_copy_cached_cmd() {
        let u = test_helpers::unix_platform();
        let cmd = u.copy_cached_cmd("/tmp/.port-linker-cache/agent-hash", "/tmp/agent-abc");
        assert!(cmd.contains("cp "), "should use cp command");
        assert!(cmd.contains("chmod +x"), "should make executable");
    }
}
