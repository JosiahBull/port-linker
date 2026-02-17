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

    /// OS identifier for binary lookup (e.g., "linux", "darwin", "windows").
    fn os_id(&self) -> &str;

    /// Binary file extension on this platform ("" or ".exe").
    fn binary_ext(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Shell escaping
// ---------------------------------------------------------------------------

/// Escape a string for safe embedding in single-quoted shell arguments.
///
/// Replaces each `'` with `'\''` (end quote, escaped literal quote, reopen quote).
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
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
        let p = shell_escape(path);
        format!("gunzip -c > '{p}' && chmod +x '{p}'")
    }

    fn transfer_raw_cmd(&self, path: &str) -> String {
        let p = shell_escape(path);
        format!("cat > '{p}' && chmod +x '{p}'")
    }

    fn check_cache_cmd(&self, cache_path: &str) -> String {
        let cp = shell_escape(cache_path);
        format!("test -x '{cp}' && echo OK")
    }

    fn copy_cached_cmd(&self, cache_path: &str, remote_path: &str) -> String {
        let cp = shell_escape(cache_path);
        let rp = shell_escape(remote_path);
        format!("cp '{cp}' '{rp}' && chmod +x '{rp}'")
    }

    fn populate_cache_cmd(&self, remote_path: &str, cache_path: &str) -> String {
        let cd = shell_escape(&self.cache);
        let rp = shell_escape(remote_path);
        let cp = shell_escape(cache_path);
        format!(
            "mkdir -p '{cd}' && cp '{rp}' '{cp}' && \
             find '{cd}' \\( -name 'agent-*' -o -name 'relay-*' \\) -mtime +7 -delete 2>/dev/null; true"
        )
    }

    fn cleanup_cmd(&self, path: &str) -> String {
        let p = shell_escape(path);
        format!("pkill -f '{p}' 2>/dev/null; rm -f '{p}'")
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
// Windows remote
// ---------------------------------------------------------------------------

/// Windows remote.
pub struct RemoteWindows {
    temp: String,
    cache: String,
}

impl RemotePlatform for RemoteWindows {
    fn detect_arch_cmd(&self) -> &str {
        "powershell -NoProfile -Command \"if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { 'x86_64' } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { $env:PROCESSOR_ARCHITECTURE }\""
    }

    fn transfer_compressed_cmd(&self, path: &str) -> String {
        format!(
            "powershell -NoProfile -Command \"\
            $input | Set-Content -Path '{path}.gz' -Encoding Byte; \
            $fs = [IO.File]::OpenRead('{path}.gz'); \
            $gz = New-Object IO.Compression.GzipStream($fs, [IO.Compression.CompressionMode]::Decompress); \
            $out = [IO.File]::Create('{path}'); \
            $gz.CopyTo($out); $out.Close(); $gz.Close(); $fs.Close(); \
            Remove-Item '{path}.gz'\""
        )
    }

    fn transfer_raw_cmd(&self, path: &str) -> String {
        format!(
            "powershell -NoProfile -Command \"$input | Set-Content -Path '{path}' -Encoding Byte\""
        )
    }

    fn check_cache_cmd(&self, cache_path: &str) -> String {
        format!("powershell -NoProfile -Command \"if (Test-Path '{cache_path}') {{ 'OK' }}\"")
    }

    fn copy_cached_cmd(&self, cache_path: &str, remote_path: &str) -> String {
        format!("powershell -NoProfile -Command \"Copy-Item '{cache_path}' '{remote_path}'\"")
    }

    fn populate_cache_cmd(&self, remote_path: &str, cache_path: &str) -> String {
        let cache_dir = &self.cache;
        format!(
            "powershell -NoProfile -Command \"\
            New-Item -ItemType Directory -Force -Path '{cache_dir}' | Out-Null; \
            Copy-Item '{remote_path}' '{cache_path}'; \
            Get-ChildItem '{cache_dir}' -Filter 'agent-*' | Where-Object {{ $_.LastWriteTime -lt (Get-Date).AddDays(-7) }} | Remove-Item -Force\""
        )
    }

    fn cleanup_cmd(&self, path: &str) -> String {
        let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
        format!("taskkill /F /IM \"{filename}\" 2>nul & del /F /Q \"{path}\" 2>nul")
    }

    fn cache_dir(&self) -> &str {
        &self.cache
    }

    fn temp_dir(&self) -> &str {
        &self.temp
    }

    fn normalize_arch(&self, raw: &str) -> Result<String> {
        match raw.trim() {
            "x86_64" | "AMD64" => Ok("x86_64".into()),
            "aarch64" | "ARM64" => Ok("aarch64".into()),
            other => Err(Error::Protocol(format!(
                "unsupported architecture: {other}"
            ))),
        }
    }

    fn os_id(&self) -> &str {
        "windows"
    }

    fn binary_ext(&self) -> &str {
        ".exe"
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

    // Try PowerShell (Windows).
    if let Ok((stdout, _, Some(0))) = ssh
        .exec("powershell -NoProfile -Command \"$env:TEMP\"")
        .await
    {
        let temp = stdout.trim().to_string();
        if !temp.is_empty() {
            let cache = format!("{temp}\\.port-linker-cache");
            info!(temp = %temp, "detected Windows remote platform");
            return Box::new(RemoteWindows { temp, cache });
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

    /// Create a default Windows remote platform for tests.
    pub fn windows_platform() -> RemoteWindows {
        RemoteWindows {
            temp: r"C:\Users\Admin\AppData\Local\Temp".into(),
            cache: r"C:\Users\Admin\AppData\Local\Temp\.port-linker-cache".into(),
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
    fn remote_windows_os_id() {
        let w = RemoteWindows {
            temp: r"C:\Users\Admin\AppData\Local\Temp".into(),
            cache: r"C:\Users\Admin\AppData\Local\Temp\.port-linker-cache".into(),
        };
        assert_eq!(w.os_id(), "windows");
        assert_eq!(w.binary_ext(), ".exe");
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
    fn remote_windows_normalize_arch() {
        let w = RemoteWindows {
            temp: "C:\\temp".into(),
            cache: "C:\\temp\\.port-linker-cache".into(),
        };
        assert_eq!(w.normalize_arch("x86_64").unwrap(), "x86_64");
        assert_eq!(w.normalize_arch("AMD64").unwrap(), "x86_64");
        assert_eq!(w.normalize_arch("aarch64").unwrap(), "aarch64");
        assert_eq!(w.normalize_arch("ARM64").unwrap(), "aarch64");
        assert!(w.normalize_arch("IA64").is_err());
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
    fn remote_windows_cleanup_cmd() {
        let w = RemoteWindows {
            temp: "C:\\temp".into(),
            cache: "C:\\temp\\.port-linker-cache".into(),
        };
        let cmd = w.cleanup_cmd("C:\\temp\\agent-xyz.exe");
        assert!(cmd.contains("taskkill"));
        assert!(cmd.contains("del"));
    }

    #[test]
    fn remote_windows_detect_arch_cmd() {
        let w = RemoteWindows {
            temp: "C:\\temp".into(),
            cache: "C:\\temp\\.port-linker-cache".into(),
        };
        let cmd = w.detect_arch_cmd();
        assert!(cmd.contains("PROCESSOR_ARCHITECTURE"));
    }

    #[test]
    fn windows_transfer_compressed_cmd() {
        let w = test_helpers::windows_platform();
        let cmd = w.transfer_compressed_cmd(r"C:\temp\agent-abc.exe");
        assert!(cmd.contains("GzipStream"), "should use gzip decompression");
        assert!(cmd.contains("Set-Content"), "should write via Set-Content");
        assert!(
            cmd.contains("agent-abc.exe"),
            "should contain the remote path"
        );
    }

    #[test]
    fn windows_transfer_raw_cmd() {
        let w = test_helpers::windows_platform();
        let cmd = w.transfer_raw_cmd(r"C:\temp\agent-abc.exe");
        assert!(cmd.contains("Set-Content"), "should write via Set-Content");
        assert!(cmd.contains("Encoding Byte"), "should use byte encoding");
    }

    #[test]
    fn windows_copy_cached_cmd() {
        let w = test_helpers::windows_platform();
        let cmd = w.copy_cached_cmd(r"C:\temp\cache\agent-hash", r"C:\temp\agent-abc.exe");
        assert!(cmd.contains("Copy-Item"), "should use Copy-Item");
        assert!(cmd.contains("agent-hash"), "should contain cache path");
        assert!(cmd.contains("agent-abc.exe"), "should contain remote path");
    }

    #[test]
    fn windows_populate_cache_cmd() {
        let w = test_helpers::windows_platform();
        let cmd = w.populate_cache_cmd(r"C:\temp\agent-abc.exe", r"C:\temp\cache\agent-hash");
        assert!(cmd.contains("New-Item"), "should create directory");
        assert!(
            cmd.contains("AddDays(-7)"),
            "should prune entries older than 7 days"
        );
        assert!(cmd.contains("Copy-Item"), "should copy binary to cache");
    }

    #[test]
    fn windows_check_cache_cmd() {
        let w = test_helpers::windows_platform();
        let cmd = w.check_cache_cmd(r"C:\temp\cache\agent-hash");
        assert!(cmd.contains("Test-Path"), "should use Test-Path");
        assert!(cmd.contains("agent-hash"), "should contain cache path");
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
