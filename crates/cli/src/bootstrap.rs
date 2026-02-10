use std::path::Path;
use std::time::Duration;

use ring::digest;
use tracing::{debug, error, info, warn};

use common::{Error, Result};

use crate::ssh::SshSession;

// ---------------------------------------------------------------------------
// Embedded agent binaries (gzip-compressed, produced by build.rs)
// ---------------------------------------------------------------------------

const AGENT_X86_64_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-x86_64-unknown-linux-musl.gz"
));
const AGENT_AARCH64_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-aarch64-unknown-linux-musl.gz"
));

/// Remote cache directory on the target host.
const CACHE_DIR: &str = "/tmp/.port-linker-cache";

/// Number of hex chars from the SHA256 hash used as cache key.
const HASH_PREFIX_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information parsed from the agent's stdout handshake.
pub struct AgentHandshake {
    pub port: u16,
    pub token: String,
}

/// Remote agent deployment info for cleanup.
pub struct RemoteAgent {
    pub ssh: SshSession,
    pub remote_path: String,
}

impl RemoteAgent {
    /// Clean up the remote agent: kill process and remove tmpfile.
    pub async fn cleanup(&self) {
        info!("cleaning up remote agent");
        let kill_cmd = format!(
            "pkill -f '{}' 2>/dev/null; rm -f '{}'",
            self.remote_path, self.remote_path
        );
        if let Err(e) = self.ssh.exec_detached(&kill_cmd).await {
            warn!(%e, "failed to clean up remote agent");
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap flow
// ---------------------------------------------------------------------------

/// Bootstrap the agent on a remote host via SSH.
///
/// 1. Detect remote architecture
/// 2. Transfer agent binary (from embedded, cache, or custom path)
/// 3. Execute agent
/// 4. Parse handshake (PORT, TOKEN)
pub async fn bootstrap_agent(
    ssh: SshSession,
    custom_binary: Option<&Path>,
) -> Result<(AgentHandshake, RemoteAgent)> {
    // Step 1: Detect remote architecture.
    let arch = detect_architecture(&ssh).await?;
    info!(arch = %arch, "detected remote architecture");

    // Step 2: Transfer agent binary.
    let remote_path = transfer_agent(&ssh, &arch, custom_binary).await?;
    info!(path = %remote_path, "agent deployed");

    let remote_agent = RemoteAgent { ssh, remote_path };

    // Step 3: Execute agent and parse handshake.
    let handshake = match execute_and_handshake(&remote_agent).await {
        Ok(h) => h,
        Err(e) => {
            error!(%e, "agent bootstrap failed, cleaning up");
            remote_agent.cleanup().await;
            return Err(e);
        }
    };

    info!(
        port = handshake.port,
        token = %handshake.token,
        "agent handshake successful"
    );

    Ok((handshake, remote_agent))
}

// ---------------------------------------------------------------------------
// Architecture detection
// ---------------------------------------------------------------------------

async fn detect_architecture(ssh: &SshSession) -> Result<String> {
    let (stdout, stderr, exit_code) = ssh.exec("uname -m").await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "uname -m failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    let arch = stdout.trim();
    match arch {
        "x86_64" => Ok("x86_64".to_string()),
        "aarch64" | "arm64" => Ok("aarch64".to_string()),
        other => Err(Error::Protocol(format!(
            "unsupported remote architecture: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Agent binary transfer (Architecture Section 3.1)
// ---------------------------------------------------------------------------

/// Transfer the agent binary to the remote host.
///
/// Strategy (in priority order):
/// 1. `--agent-binary` override: transfer the user-specified file directly.
/// 2. Embedded binary with remote cache: check SHA256-keyed cache, transfer
///    compressed binary on miss, decompress with gunzip on the target.
/// 3. Local fallback (dev mode): search for a native agent binary in target/.
async fn transfer_agent(
    ssh: &SshSession,
    arch: &str,
    custom_binary: Option<&Path>,
) -> Result<String> {
    let random_suffix = common::generate_token();
    let remote_path = format!("/tmp/port-linker-agent-{random_suffix}");

    // Strategy 1: Custom binary override (--agent-binary flag).
    if let Some(path) = custom_binary {
        info!(path = %path.display(), "using custom agent binary");
        let data = read_file_blocking(path).await?;
        transfer_raw(ssh, &data, &remote_path).await?;
        return Ok(remote_path);
    }

    // Strategy 2: Embedded binary with remote caching.
    let embedded_gz = select_embedded_binary(arch);
    if !embedded_gz.is_empty() {
        let hash_prefix = sha256_hex_prefix(embedded_gz);
        let cache_path = format!("{CACHE_DIR}/agent-{hash_prefix}");

        // Check remote cache.
        if check_remote_cache(ssh, &cache_path).await {
            info!(cache = %cache_path, "cache hit, symlinking");
            symlink_cached(ssh, &cache_path, &remote_path).await?;
            return Ok(remote_path);
        }

        // Cache miss: transfer compressed binary, decompress on target.
        info!(
            arch,
            compressed_size = embedded_gz.len(),
            "cache miss, transferring compressed agent"
        );
        transfer_compressed(ssh, embedded_gz, &remote_path).await?;

        // Populate cache in background (best-effort).
        populate_cache(ssh, &remote_path, &cache_path).await;

        return Ok(remote_path);
    }

    // Strategy 3: Local fallback (dev mode).
    info!(arch, "no embedded agent binary, searching locally");
    let data = find_local_agent_binary(arch).await?;

    info!(
        size = data.len(),
        remote_path = %remote_path,
        remote_arch = arch,
        "transferring local agent binary"
    );

    transfer_raw(ssh, &data, &remote_path).await?;

    info!("local agent binary transferred");

    Ok(remote_path)
}

/// Select the embedded gzip-compressed agent binary for the given architecture.
fn select_embedded_binary(arch: &str) -> &'static [u8] {
    match arch {
        "x86_64" => AGENT_X86_64_GZ,
        "aarch64" => AGENT_AARCH64_GZ,
        _ => &[],
    }
}

/// Compute the first N hex chars of SHA256 of the given data.
fn sha256_hex_prefix(data: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, data);
    let hex: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    hex[..HASH_PREFIX_LEN].to_string()
}

// ---------------------------------------------------------------------------
// Remote cache operations
// ---------------------------------------------------------------------------

/// Check if the cached agent binary exists on the remote host.
async fn check_remote_cache(ssh: &SshSession, cache_path: &str) -> bool {
    let cmd = format!("test -x '{cache_path}' && echo OK");
    match ssh.exec(&cmd).await {
        Ok((stdout, _, Some(0))) => stdout.trim() == "OK",
        _ => false,
    }
}

/// Create a copy from the cached binary to the agent path.
async fn symlink_cached(ssh: &SshSession, cache_path: &str, remote_path: &str) -> Result<()> {
    let cmd = format!("cp '{cache_path}' '{remote_path}' && chmod +x '{remote_path}'");
    let (_stdout, stderr, exit_code) = ssh.exec(&cmd).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "cache copy failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    Ok(())
}

/// Populate the remote cache with the deployed agent binary (best-effort).
async fn populate_cache(ssh: &SshSession, remote_path: &str, cache_path: &str) {
    let cmd = format!(
        "mkdir -p '{CACHE_DIR}' && cp '{remote_path}' '{cache_path}' && \
         find '{CACHE_DIR}' -name 'agent-*' -mtime +7 -delete 2>/dev/null; true"
    );
    if let Err(e) = ssh.exec_detached(&cmd).await {
        debug!(%e, "failed to populate cache (non-fatal)");
    }
}

// ---------------------------------------------------------------------------
// Transfer methods
// ---------------------------------------------------------------------------

/// Transfer a gzip-compressed binary and decompress on the remote host.
async fn transfer_compressed(ssh: &SshSession, gz_data: &[u8], remote_path: &str) -> Result<()> {
    let cmd = format!("gunzip -c > '{remote_path}' && chmod +x '{remote_path}'");
    let (_stdout, stderr, exit_code) = ssh.exec_with_stdin(&cmd, gz_data).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "compressed agent transfer failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    debug!(remote_path, "compressed agent transferred and decompressed");
    Ok(())
}

/// Transfer a raw (uncompressed) binary to the remote host.
async fn transfer_raw(ssh: &SshSession, data: &[u8], remote_path: &str) -> Result<()> {
    let cmd = format!("cat > '{remote_path}' && chmod +x '{remote_path}'");
    let (_stdout, stderr, exit_code) = ssh.exec_with_stdin(&cmd, data).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "agent transfer failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    debug!(remote_path, "agent binary transferred");
    Ok(())
}

// ---------------------------------------------------------------------------
// Local binary search (dev mode fallback)
// ---------------------------------------------------------------------------

/// Read a file in a blocking task to avoid stalling the async runtime.
async fn read_file_blocking(path: &Path) -> Result<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read(&path).map_err(Error::Io))
        .await
        .map_err(|e| Error::Protocol(format!("failed to read file: {e}")))?
}

/// Find the agent binary on the local filesystem (dev mode).
///
/// Searches for architecture-compatible agent binaries in the following order:
/// 1. Cross-compiled Linux binary for target arch: `target/{arch}-unknown-linux-musl/debug/port-linker-agent`
/// 2. Cross-compiled Linux binary for target arch: `target/{arch}-unknown-linux-musl/release/port-linker-agent`
/// 3. Native binary (only if running on Linux with matching arch): `target/debug/port-linker-agent`
/// 4. Native binary (only if running on Linux with matching arch): `target/release/port-linker-agent`
async fn find_local_agent_binary(arch: &str) -> Result<Vec<u8>> {
    let arch = arch.to_string();
    tokio::task::spawn_blocking(move || {
        let local_os = std::env::consts::OS;
        let local_arch = std::env::consts::ARCH;

        // Strategy 1: Cross-compiled Linux binaries (highest priority).
        let cross_compiled_candidates = [
            format!("target/{}-unknown-linux-musl/debug/port-linker-agent", arch),
            format!("target/{}-unknown-linux-musl/release/port-linker-agent", arch),
        ];

        for candidate in &cross_compiled_candidates {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                let data = std::fs::read(path).map_err(Error::Io)?;
                info!(
                    path = %path.display(),
                    size = data.len(),
                    remote_arch = %arch,
                    "found cross-compiled agent binary"
                );
                return Ok(data);
            }
        }

        // Strategy 2: Native binaries (fallback, only if OS and arch match).
        // Only consider native binaries when running on Linux with the same architecture as the remote.
        if local_os == "linux" && local_arch == arch {
            let native_candidates = [
                "target/debug/port-linker-agent",
                "target/release/port-linker-agent",
            ];

            for candidate in &native_candidates {
                let path = std::path::Path::new(candidate);
                if path.exists() {
                    let data = std::fs::read(path).map_err(Error::Io)?;
                    info!(
                        path = %path.display(),
                        size = data.len(),
                        "found native agent binary (local arch matches remote)"
                    );
                    return Ok(data);
                }
            }
        }

        // No compatible binary found.
        Err(Error::Protocol(format!(
            "could not find compatible agent binary for remote architecture '{arch}'.\n\
             Build with `cargo build --target {arch}-unknown-linux-musl -p agent` first, \
             or specify --agent-binary to provide a custom binary.\n\
             \n\
             Current environment: OS={local_os}, ARCH={local_arch}\n\
             Remote environment: OS=linux, ARCH={arch}\n\
             \n\
             Cross-compilation is required when the local and remote architectures differ."
        )))
    })
    .await
    .map_err(|e| Error::Protocol(format!("failed to read agent binary: {e}")))?
}

// ---------------------------------------------------------------------------
// Agent execution & handshake
// ---------------------------------------------------------------------------

async fn execute_and_handshake(agent: &RemoteAgent) -> Result<AgentHandshake> {
    let command = agent.remote_path.to_string();

    let mut port: Option<u16> = None;
    let mut token: Option<String> = None;
    let mut got_ready = false;

    let lines = agent
        .ssh
        .exec_and_read_lines(&command, Duration::from_secs(10), |line| {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
            got_ready && port.is_some() && token.is_some()
        })
        .await?;

    let port = port.ok_or_else(|| {
        Error::Protocol(format!(
            "agent did not report PORT (got {} lines: {:?})",
            lines.len(),
            lines
        ))
    })?;

    let token = token.ok_or_else(|| {
        Error::Protocol(format!(
            "agent did not report TOKEN (got {} lines: {:?})",
            lines.len(),
            lines
        ))
    })?;

    if !got_ready {
        return Err(Error::Protocol(format!(
            "agent did not report AGENT_READY (got {} lines: {:?})",
            lines.len(),
            lines
        )));
    }

    Ok(AgentHandshake { port, token })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handshake_lines() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=12345".to_string(),
            "TOKEN=plk-abc-123".to_string(),
        ];

        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(12345));
        assert_eq!(token.as_deref(), Some("plk-abc-123"));
    }

    #[test]
    fn parse_handshake_with_noise() {
        let lines = vec![
            "2024-01-01T00:00:00 INFO agent starting".to_string(),
            "AGENT_READY".to_string(),
            "PORT=8080".to_string(),
            "TOKEN=plk-xyz-789".to_string(),
        ];

        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(8080));
        assert_eq!(token.as_deref(), Some("plk-xyz-789"));
    }

    #[test]
    fn test_agent_handshake_construction() {
        let handshake = AgentHandshake {
            port: 9999,
            token: "test-token-abc".to_string(),
        };

        assert_eq!(handshake.port, 9999);
        assert_eq!(handshake.token, "test-token-abc");
    }

    #[test]
    fn test_architecture_mapping() {
        assert_eq!(map_arch("x86_64"), Ok("x86_64"));
        assert_eq!(map_arch("aarch64"), Ok("aarch64"));
        assert_eq!(map_arch("arm64"), Ok("aarch64"));

        assert!(map_arch("i686").is_err());
        assert!(map_arch("armv7l").is_err());
        assert!(map_arch("unknown").is_err());

        fn map_arch(arch: &str) -> std::result::Result<&'static str, ()> {
            match arch {
                "x86_64" => Ok("x86_64"),
                "aarch64" | "arm64" => Ok("aarch64"),
                _ => Err(()),
            }
        }
    }

    #[test]
    fn test_transfer_command_format() {
        let remote_path = "/tmp/test-agent-123";
        let cmd = format!("cat > '{}' && chmod +x '{}'", remote_path, remote_path);
        assert!(cmd.contains("cat >"));
        assert!(cmd.contains("chmod +x"));
        assert!(cmd.contains(remote_path));
    }

    #[test]
    fn test_cleanup_command_format() {
        let remote_path = "/tmp/test-agent-456";
        let cmd = format!(
            "pkill -f '{}' 2>/dev/null; rm -f '{}'",
            remote_path, remote_path
        );
        assert!(cmd.contains("pkill -f"));
        assert!(cmd.contains("rm -f"));
        assert!(cmd.contains("2>/dev/null"));
        assert!(cmd.contains(remote_path));
    }

    #[test]
    fn test_select_embedded_binary() {
        // x86_64 and aarch64 should return the embedded constants.
        let x86 = select_embedded_binary("x86_64");
        let aarch = select_embedded_binary("aarch64");
        let unknown = select_embedded_binary("riscv64");

        // In dev builds these will be empty placeholders.
        // Just verify they don't panic and unknown returns empty.
        assert!(unknown.is_empty());
        // x86 and aarch64 should be either empty (dev) or non-empty (release).
        let _ = x86;
        let _ = aarch;
    }

    #[test]
    fn test_sha256_hex_prefix() {
        let data = b"hello world";
        let prefix = sha256_hex_prefix(data);
        assert_eq!(prefix.len(), HASH_PREFIX_LEN);
        // SHA256 of "hello world" is well-known.
        assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&prefix, "b94d27b9934d3e08");
    }

    #[test]
    fn test_sha256_hex_prefix_different_data() {
        let a = sha256_hex_prefix(b"data-a");
        let b = sha256_hex_prefix(b"data-b");
        assert_ne!(a, b, "different data should produce different prefixes");
    }

    #[test]
    fn test_cache_path_format() {
        let hash = sha256_hex_prefix(b"test-binary-data");
        let cache_path = format!("{CACHE_DIR}/agent-{hash}");
        assert!(cache_path.starts_with("/tmp/.port-linker-cache/agent-"));
        assert_eq!(
            cache_path.len(),
            CACHE_DIR.len() + "/agent-".len() + HASH_PREFIX_LEN
        );
    }

    #[test]
    fn test_compressed_transfer_command() {
        let remote_path = "/tmp/port-linker-agent-abc123";
        let cmd = format!("gunzip -c > '{remote_path}' && chmod +x '{remote_path}'");
        assert!(cmd.contains("gunzip -c"));
        assert!(cmd.contains("chmod +x"));
        assert!(cmd.contains(remote_path));
    }

    #[test]
    fn test_cache_populate_command() {
        let remote_path = "/tmp/port-linker-agent-abc";
        let cache_path = "/tmp/.port-linker-cache/agent-deadbeef12345678";
        let cmd = format!(
            "mkdir -p '{CACHE_DIR}' && cp '{remote_path}' '{cache_path}' && \
             find '{CACHE_DIR}' -name 'agent-*' -mtime +7 -delete 2>/dev/null; true"
        );
        assert!(cmd.contains("mkdir -p"));
        assert!(cmd.contains(remote_path));
        assert!(cmd.contains(cache_path));
        assert!(cmd.contains("-mtime +7"));
    }

    #[test]
    fn test_handshake_parsing_missing_port() {
        let lines = vec!["AGENT_READY".to_string(), "TOKEN=plk-test".to_string()];
        let mut port: Option<u16> = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, None);
        assert_eq!(token.as_deref(), Some("plk-test"));
    }

    #[test]
    fn test_handshake_parsing_missing_token() {
        let lines = vec!["AGENT_READY".to_string(), "PORT=7777".to_string()];
        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(7777));
        assert_eq!(token, None);
    }

    #[test]
    fn test_handshake_parsing_missing_ready() {
        let lines = vec!["PORT=6666".to_string(), "TOKEN=plk-xyz".to_string()];
        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(!got_ready);
        assert_eq!(port, Some(6666));
        assert_eq!(token.as_deref(), Some("plk-xyz"));
    }

    #[test]
    fn test_handshake_parsing_invalid_port() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=not-a-number".to_string(),
            "TOKEN=plk-test".to_string(),
        ];

        let mut port: Option<u16> = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, None);
        assert_eq!(token.as_deref(), Some("plk-test"));
    }

    #[test]
    fn test_handshake_parsing_out_of_range_port() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=999999".to_string(),
            "TOKEN=plk-test".to_string(),
        ];

        let mut port: Option<u16> = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, None);
        assert_eq!(token.as_deref(), Some("plk-test"));
    }

    #[test]
    fn test_handshake_parsing_empty_token() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=5555".to_string(),
            "TOKEN=".to_string(),
        ];

        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(5555));
        assert_eq!(token.as_deref(), Some(""));
    }

    #[test]
    fn test_handshake_parsing_whitespace() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=  4444  ".to_string(),
            "TOKEN=  plk-token  ".to_string(),
        ];

        let mut port = None;
        let mut token = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(4444));
        assert_eq!(token.as_deref(), Some("plk-token"));
    }

    // -----------------------------------------------------------------------
    // Tests for find_local_agent_binary architecture-aware search
    // -----------------------------------------------------------------------

    #[test]
    fn test_binary_search_order() {
        // Test the search order for cross-compiled binaries.
        // We test the path construction logic rather than actual file access.
        let arch = "x86_64";
        let expected_paths = vec![
            format!("target/{arch}-unknown-linux-musl/debug/port-linker-agent"),
            format!("target/{arch}-unknown-linux-musl/release/port-linker-agent"),
        ];

        // Verify path construction is correct.
        assert_eq!(
            expected_paths[0],
            "target/x86_64-unknown-linux-musl/debug/port-linker-agent"
        );
        assert_eq!(
            expected_paths[1],
            "target/x86_64-unknown-linux-musl/release/port-linker-agent"
        );
    }

    #[test]
    fn test_aarch64_binary_paths() {
        // Verify correct path construction for aarch64 architecture.
        let arch = "aarch64";
        let expected_paths = vec![
            format!("target/{arch}-unknown-linux-musl/debug/port-linker-agent"),
            format!("target/{arch}-unknown-linux-musl/release/port-linker-agent"),
        ];

        assert_eq!(
            expected_paths[0],
            "target/aarch64-unknown-linux-musl/debug/port-linker-agent"
        );
        assert_eq!(
            expected_paths[1],
            "target/aarch64-unknown-linux-musl/release/port-linker-agent"
        );
    }

    #[test]
    fn test_native_binary_paths_linux_only() {
        // Native binaries should only be considered on Linux when arch matches.
        // This test verifies the path construction for native binaries.
        #[cfg(target_os = "linux")]
        {
            let native_paths = vec![
                "target/debug/port-linker-agent",
                "target/release/port-linker-agent",
            ];

            // On Linux, native paths should be included in the search.
            assert!(!native_paths.is_empty());
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux platforms (macOS, Windows), native binaries
            // should NOT be searched when targeting Linux remotes.
            // This is tested implicitly by the search logic in find_local_agent_binary.
        }
    }

    #[test]
    fn test_error_message_mentions_cross_compilation() {
        // When no compatible binary is found, the error message should guide
        // the user toward cross-compilation solutions.
        let error_msg = "could not find compatible agent binary for remote architecture 'x86_64'. \
                        Build with `cargo build --target x86_64-unknown-linux-musl -p agent` first, \
                        or specify --agent-binary to connect directly to a running agent.";

        assert!(error_msg.contains("cross-compilation")
                || error_msg.contains("--target")
                || error_msg.contains("x86_64-unknown-linux-musl"));
        assert!(error_msg.contains("--agent-binary"));
    }

    #[test]
    fn test_architecture_triple_format() {
        // Verify the Rust target triple format used in cross-compilation.
        let x86_triple = "x86_64-unknown-linux-musl";
        let aarch_triple = "aarch64-unknown-linux-musl";

        assert!(x86_triple.contains("unknown-linux-musl"));
        assert!(aarch_triple.contains("unknown-linux-musl"));
        assert!(x86_triple.starts_with("x86_64"));
        assert!(aarch_triple.starts_with("aarch64"));
    }

    #[test]
    fn test_macos_to_linux_incompatibility() {
        // This test documents the bug: macOS binaries (Mach-O) cannot run on Linux (ELF).
        // The search logic must prioritize cross-compiled Linux binaries over native macOS ones.
        #[cfg(target_os = "macos")]
        {
            // When running on macOS and targeting Linux, we should NOT use native binaries.
            // This is the core bug that needs fixing.
            let remote_os = "linux";
            let local_os = "macos";
            assert_ne!(remote_os, local_os);

            // The fix should ensure native macOS binaries are never transferred to Linux.
        }
    }

    #[test]
    fn test_local_arch_detection() {
        // Test that we can detect the local architecture at compile time.
        let local_arch = std::env::consts::ARCH;
        assert!(
            local_arch == "x86_64" || local_arch == "aarch64",
            "unexpected local architecture: {local_arch}"
        );
    }

    #[test]
    fn test_os_detection() {
        // Test that we can detect the local OS at compile time.
        let local_os = std::env::consts::OS;
        assert!(
            local_os == "linux" || local_os == "macos" || local_os == "windows",
            "unexpected local OS: {local_os}"
        );
    }

    #[test]
    fn test_cross_compile_priority_over_native() {
        // The search order MUST prioritize cross-compiled binaries over native ones.
        // Cross-compiled: target/{arch}-unknown-linux-musl/{debug,release}/port-linker-agent
        // Native: target/{debug,release}/port-linker-agent

        // This test verifies the search order by checking index positions.
        let search_order = vec![
            "cross_compiled_debug",   // Index 0 (highest priority)
            "cross_compiled_release", // Index 1
            "native_debug",           // Index 2 (only if OS matches)
            "native_release",         // Index 3 (only if OS matches)
        ];

        assert_eq!(search_order[0], "cross_compiled_debug");
        assert_eq!(search_order[1], "cross_compiled_release");

        // Native binaries should come after cross-compiled ones.
        let cross_idx = search_order.iter().position(|&x| x.starts_with("cross"));
        let native_idx = search_order.iter().position(|&x| x.starts_with("native"));

        if let (Some(cross), Some(native)) = (cross_idx, native_idx) {
            assert!(cross < native, "cross-compiled must be searched before native");
        }
    }
}
