use std::path::Path;
use std::time::Duration;

use ring::digest;
use tracing::{debug, error, info, warn};

use common::{Error, Result};

use crate::remote_platform::{RemotePlatform, detect_remote_platform};
use crate::ssh::SshSession;

/// Number of hex chars from the SHA256 hash used as cache key.
const HASH_PREFIX_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information parsed from the agent's stdout handshake.
pub struct AgentHandshake {
    pub port: u16,
    pub token: String,
    /// TCP bridge port for QUIC-over-TCP fallback (Phase 3).
    /// Only present when the agent supports the TCP bridge.
    pub bridge_port: Option<u16>,
}

/// Remote agent deployment info for cleanup.
pub struct RemoteAgent {
    pub ssh: SshSession,
    pub remote_path: String,
    /// The detected remote platform (for generating cleanup commands).
    platform: Box<dyn RemotePlatform>,
    /// Relay processes deployed on jump hosts (for cleanup).
    #[allow(dead_code)]
    pub relay_cleanups: Vec<RelayCleanup>,
}

/// Info needed to clean up a relay process on a jump host.
#[allow(dead_code)]
pub struct RelayCleanup {
    pub remote_path: String,
}

impl RemoteAgent {
    /// Clean up the remote agent: kill process and remove tmpfile.
    pub async fn cleanup(&self) {
        info!("cleaning up remote agent");
        let kill_cmd = self.platform.cleanup_cmd(&self.remote_path);
        if let Err(e) = self.ssh.exec_detached(&kill_cmd).await {
            warn!(%e, "failed to clean up remote agent");
        }
    }
}

/// Information about a deployed relay.
pub struct RelayInfo {
    /// The port the relay is listening on.
    pub port: u16,
    /// Remote path of the relay binary (for cleanup).
    #[allow(dead_code)]
    pub remote_path: String,
}

/// Bootstrap a UDP relay on a jump host via an SSH session.
///
/// Similar to `bootstrap_agent`: detect arch, transfer binary, execute,
/// parse handshake (RELAY_READY/PORT=).
pub async fn bootstrap_relay(
    ssh: &SshSession,
    target_addr: &str,
    custom_binary: Option<&std::path::Path>,
) -> Result<RelayInfo> {
    let platform = detect_remote_platform(ssh).await;
    let arch = detect_architecture(ssh, &*platform).await?;
    info!(arch = %arch, os = platform.os_id(), "detected jump host platform for relay");

    let random_suffix = common::generate_token();
    let ext = platform.binary_ext();
    let remote_path = format!(
        "{}/port-linker-relay-{random_suffix}{ext}",
        platform.temp_dir()
    );

    if let Some(path) = custom_binary {
        info!(path = %path.display(), "using custom relay binary");
        let data = read_file_blocking(path).await?;
        transfer_raw(ssh, &*platform, &data, &remote_path).await?;
    } else {
        let embedded_gz = relay_embed::get_relay_binary_for_system(platform.os_id(), &arch)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "no embedded relay binary for {}/{arch}. \
                     Available targets: {:?}.",
                    platform.os_id(),
                    relay_embed::available_relay_targets(),
                ))
            })?;

        let hash_prefix = sha256_hex_prefix(embedded_gz);
        let cache_dir = platform.cache_dir();
        let cache_path = format!("{cache_dir}/relay-{hash_prefix}");

        if check_remote_cache(ssh, &*platform, &cache_path).await {
            info!(cache = %cache_path, "relay cache hit");
            copy_cached(ssh, &*platform, &cache_path, &remote_path).await?;
        } else {
            info!(
                arch,
                compressed_size = embedded_gz.len(),
                "relay cache miss, transferring"
            );
            transfer_compressed(ssh, &*platform, embedded_gz, &remote_path).await?;
            populate_cache(ssh, &*platform, &remote_path, &cache_path).await;
        }
    }

    // Execute the relay and parse handshake.
    let command = format!("{remote_path} --target {target_addr}");
    let mut relay_port: Option<u16> = None;
    let mut got_ready = false;

    let lines = ssh
        .exec_and_read_lines(&command, Duration::from_secs(10), |line| {
            if line == "RELAY_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                relay_port = p.trim().parse().ok();
            }
            got_ready && relay_port.is_some()
        })
        .await?;

    let port = relay_port.ok_or_else(|| {
        Error::Protocol(format!(
            "relay did not report PORT (got {} lines: {:?})",
            lines.len(),
            lines
        ))
    })?;

    if !got_ready {
        return Err(Error::Protocol(format!(
            "relay did not report RELAY_READY (got {} lines: {:?})",
            lines.len(),
            lines
        )));
    }

    info!(port, "relay deployed and listening");

    Ok(RelayInfo { port, remote_path })
}

// ---------------------------------------------------------------------------
// Bootstrap flow
// ---------------------------------------------------------------------------

/// Bootstrap the agent on a remote host via SSH.
///
/// 1. Detect remote platform and architecture
/// 2. Transfer agent binary (from embedded, cache, or custom path)
/// 3. Execute agent
/// 4. Parse handshake (PORT, TOKEN)
pub async fn bootstrap_agent(
    ssh: SshSession,
    custom_binary: Option<&Path>,
) -> Result<(AgentHandshake, RemoteAgent)> {
    // Step 1: Detect remote platform and architecture.
    let platform = detect_remote_platform(&ssh).await;
    let arch = detect_architecture(&ssh, &*platform).await?;
    info!(arch = %arch, os = platform.os_id(), "detected remote platform");

    // Step 2: Transfer agent binary.
    let remote_path = transfer_agent(&ssh, &*platform, &arch, custom_binary).await?;
    info!(path = %remote_path, "agent deployed");

    let remote_agent = RemoteAgent {
        ssh,
        remote_path,
        platform,
        relay_cleanups: Vec::new(),
    };

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

async fn detect_architecture(ssh: &SshSession, platform: &dyn RemotePlatform) -> Result<String> {
    let cmd = platform.detect_arch_cmd();
    let (stdout, stderr, exit_code) = ssh.exec(cmd).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "architecture detection failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    platform.normalize_arch(&stdout)
}

// ---------------------------------------------------------------------------
// Agent binary transfer (Architecture Section 3.1)
// ---------------------------------------------------------------------------

/// Transfer the agent binary to the remote host.
///
/// Strategy (in priority order):
/// 1. `--agent-binary` override: transfer the user-specified file directly.
/// 2. Embedded binary with remote cache: check SHA256-keyed cache, transfer
///    compressed binary on miss, decompress on the target.
async fn transfer_agent(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    arch: &str,
    custom_binary: Option<&Path>,
) -> Result<String> {
    let random_suffix = common::generate_token();
    let ext = platform.binary_ext();
    let remote_path = format!(
        "{}/port-linker-agent-{random_suffix}{ext}",
        platform.temp_dir()
    );

    // Strategy 1: Custom binary override (--agent-binary flag).
    if let Some(path) = custom_binary {
        info!(path = %path.display(), "using custom agent binary");
        let data = read_file_blocking(path).await?;
        transfer_raw(ssh, platform, &data, &remote_path).await?;
        return Ok(remote_path);
    }

    // Strategy 2: Embedded binary with remote caching.
    let embedded_gz =
        agent_embed::get_binary_for_system(platform.os_id(), arch).ok_or_else(|| {
            Error::Protocol(format!(
                "no embedded agent binary for {}/{arch}. \
                 Available targets: {:?}. \
                 Use --agent-binary to provide a custom binary.",
                platform.os_id(),
                agent_embed::available_targets(),
            ))
        })?;

    let hash_prefix = sha256_hex_prefix(embedded_gz);
    let cache_dir = platform.cache_dir();
    let cache_path = format!("{cache_dir}/agent-{hash_prefix}");

    // Check remote cache.
    if check_remote_cache(ssh, platform, &cache_path).await {
        info!(cache = %cache_path, "cache hit, copying cached binary");
        copy_cached(ssh, platform, &cache_path, &remote_path).await?;
        return Ok(remote_path);
    }

    // Cache miss: transfer compressed binary, decompress on target.
    info!(
        arch,
        compressed_size = embedded_gz.len(),
        "cache miss, transferring compressed agent"
    );
    transfer_compressed(ssh, platform, embedded_gz, &remote_path).await?;

    // Populate cache in background (best-effort).
    populate_cache(ssh, platform, &remote_path, &cache_path).await;

    Ok(remote_path)
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

/// Check if the cached binary exists on the remote host.
async fn check_remote_cache(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    cache_path: &str,
) -> bool {
    let cmd = platform.check_cache_cmd(cache_path);
    match ssh.exec(&cmd).await {
        Ok((stdout, _, Some(0))) => stdout.trim() == "OK",
        _ => false,
    }
}

/// Copy from the cached binary to the target path.
async fn copy_cached(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    cache_path: &str,
    remote_path: &str,
) -> Result<()> {
    let cmd = platform.copy_cached_cmd(cache_path, remote_path);
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

/// Populate the remote cache with the deployed binary (best-effort).
async fn populate_cache(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    remote_path: &str,
    cache_path: &str,
) {
    let cmd = platform.populate_cache_cmd(remote_path, cache_path);
    if let Err(e) = ssh.exec_detached(&cmd).await {
        debug!(%e, "failed to populate cache (non-fatal)");
    }
}

// ---------------------------------------------------------------------------
// Transfer methods
// ---------------------------------------------------------------------------

/// Transfer a gzip-compressed binary and decompress on the remote host.
async fn transfer_compressed(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    gz_data: &[u8],
    remote_path: &str,
) -> Result<()> {
    let cmd = platform.transfer_compressed_cmd(remote_path);
    let (_stdout, stderr, exit_code) = ssh.exec_with_stdin(&cmd, gz_data).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "compressed transfer failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    debug!(
        remote_path,
        "compressed binary transferred and decompressed"
    );
    Ok(())
}

/// Transfer a raw (uncompressed) binary to the remote host.
async fn transfer_raw(
    ssh: &SshSession,
    platform: &dyn RemotePlatform,
    data: &[u8],
    remote_path: &str,
) -> Result<()> {
    let cmd = platform.transfer_raw_cmd(remote_path);
    let (_stdout, stderr, exit_code) = ssh.exec_with_stdin(&cmd, data).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "binary transfer failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    debug!(remote_path, "binary transferred");
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

// ---------------------------------------------------------------------------
// Agent execution & handshake
// ---------------------------------------------------------------------------

async fn execute_and_handshake(agent: &RemoteAgent) -> Result<AgentHandshake> {
    let command = agent.remote_path.to_string();

    let mut port: Option<u16> = None;
    let mut token: Option<String> = None;
    let mut bridge_port: Option<u16> = None;
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
            } else if let Some(bp) = line.strip_prefix("BRIDGE_PORT=") {
                bridge_port = bp.trim().parse().ok();
            }
            // BRIDGE_PORT is optional, so don't wait for it.
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

    Ok(AgentHandshake {
        port,
        token,
        bridge_port,
    })
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
            bridge_port: Some(8888),
        };

        assert_eq!(handshake.port, 9999);
        assert_eq!(handshake.token, "test-token-abc");
        assert_eq!(handshake.bridge_port, Some(8888));
    }

    #[test]
    fn parse_handshake_with_bridge_port() {
        let lines = vec![
            "AGENT_READY".to_string(),
            "PORT=12345".to_string(),
            "TOKEN=plk-abc-123".to_string(),
            "BRIDGE_PORT=54321".to_string(),
        ];

        let mut port = None;
        let mut token = None;
        let mut bridge_port = None;
        let mut got_ready = false;

        for line in &lines {
            if line == "AGENT_READY" {
                got_ready = true;
            } else if let Some(p) = line.strip_prefix("PORT=") {
                port = p.trim().parse().ok();
            } else if let Some(t) = line.strip_prefix("TOKEN=") {
                token = Some(t.trim().to_string());
            } else if let Some(bp) = line.strip_prefix("BRIDGE_PORT=") {
                bridge_port = bp.trim().parse().ok();
            }
        }

        assert!(got_ready);
        assert_eq!(port, Some(12345));
        assert_eq!(token.as_deref(), Some("plk-abc-123"));
        assert_eq!(bridge_port, Some(54321));
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
    fn test_transfer_command_format_via_platform() {
        use crate::remote_platform::RemotePlatform;
        let unix = crate::remote_platform::test_helpers::unix_platform();
        let remote_path = "/tmp/test-agent-123";

        let cmd = unix.transfer_raw_cmd(remote_path);
        assert!(cmd.contains("cat >"));
        assert!(cmd.contains("chmod +x"));
        assert!(cmd.contains(remote_path));

        let cmd = unix.cleanup_cmd(remote_path);
        assert!(cmd.contains("pkill"));
        assert!(cmd.contains("rm -f"));
        assert!(cmd.contains(remote_path));
    }

    #[test]
    fn test_embedded_binary_lookup() {
        // Unsupported targets should return None.
        assert!(agent_embed::get_binary_for_system("linux", "riscv64").is_none());
        assert!(agent_embed::get_binary_for_system("freebsd", "x86_64").is_none());

        // Supported targets return Some (non-empty) or None (empty placeholder).
        // Either way, no panic.
        let _ = agent_embed::get_binary_for_system("linux", "x86_64");
        let _ = agent_embed::get_binary_for_system("linux", "aarch64");
        let _ = agent_embed::get_binary_for_system("windows", "x86_64");
        let _ = agent_embed::get_binary_for_system("windows", "aarch64");
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
    fn test_cache_path_format_via_platform() {
        use crate::remote_platform::RemotePlatform;
        let unix = crate::remote_platform::test_helpers::unix_platform();

        let hash = sha256_hex_prefix(b"test-binary-data");
        let cache_dir = unix.cache_dir();
        let cache_path = format!("{cache_dir}/agent-{hash}");
        assert!(cache_path.starts_with("/tmp/.port-linker-cache/agent-"));
        assert_eq!(
            cache_path.len(),
            cache_dir.len() + "/agent-".len() + HASH_PREFIX_LEN
        );
    }

    #[test]
    fn test_compressed_transfer_command_via_platform() {
        use crate::remote_platform::RemotePlatform;
        let unix = crate::remote_platform::test_helpers::unix_platform();
        let remote_path = "/tmp/port-linker-agent-abc123";

        let cmd = unix.transfer_compressed_cmd(remote_path);
        assert!(cmd.contains("gunzip"));
        assert!(cmd.contains("chmod +x"));
        assert!(cmd.contains(remote_path));
    }

    #[test]
    fn test_cache_populate_command_via_platform() {
        use crate::remote_platform::RemotePlatform;
        let unix = crate::remote_platform::test_helpers::unix_platform();
        let remote_path = "/tmp/port-linker-agent-abc";
        let cache_path = "/tmp/.port-linker-cache/agent-deadbeef12345678";

        let cmd = unix.populate_cache_cmd(remote_path, cache_path);
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
}
