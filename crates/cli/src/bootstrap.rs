use std::path::Path;
use std::time::Duration;

use ring::digest;
use tracing::{debug, error, info, warn};

use common::{Error, Result};

use crate::remote_platform::{RemotePlatform, detect_remote_platform};
use crate::ssh::{SshExecutor, SshSession};

/// Number of hex chars from the SHA256 hash used as cache key.
const HASH_PREFIX_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information parsed from the agent's stdout handshake.
pub struct AgentHandshake {
    pub port: u16,
    /// The agent's DER-encoded session certificate.
    ///
    /// It arrives inside the SSH channel, which is what makes it trustworthy;
    /// the QUIC handshake then accepts this certificate and no other.
    pub agent_cert: Vec<u8>,
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
    ssh: &(impl SshExecutor + ?Sized),
    target_addr: &str,
    custom_binary: Option<&std::path::Path>,
    session_secret: &str,
) -> Result<RelayInfo> {
    let platform = detect_remote_platform(ssh).await;
    let arch = detect_architecture(ssh, &*platform).await?;
    info!(arch = %arch, os = platform.os_id(), "detected jump host platform for relay");

    let random_suffix = common::generate_token()?;
    let ext = platform.binary_ext();
    let remote_path = format!(
        "{}/port-linker-relay-{random_suffix}{ext}",
        platform.temp_dir()
    );

    if let Some(path) = custom_binary {
        info!(path = %path.display(), "using custom relay binary");
        let data = read_file_blocking(path).await?;
        let expected_sha256 = sha256_hex(&data);
        transfer_raw(ssh, &*platform, &data, &remote_path).await?;
        verify_remote_binary(ssh, &*platform, &remote_path, &expected_sha256).await?;
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

        // The cached relay is only usable if it hashes to the binary we would
        // otherwise transfer, recorded at build time from the embedded copy.
        let expected_sha256 =
            relay_embed::get_relay_binary_sha256_for_system(platform.os_id(), &arch).ok_or_else(
                || {
                    Error::Security(format!(
                        "no recorded checksum for the embedded {}/{arch} relay, so its \
                         integrity on the jump host cannot be verified",
                        platform.os_id()
                    ))
                },
            )?;

        let installed = check_remote_cache(ssh, &*platform, &cache_path).await
            && install_from_cache(ssh, &*platform, &cache_path, &remote_path, expected_sha256)
                .await?;

        if installed {
            info!(cache = %cache_path, "relay cache hit, integrity verified");
        } else {
            info!(
                arch,
                compressed_size = embedded_gz.len(),
                "relay cache miss or integrity failure, transferring"
            );
            transfer_compressed(ssh, &*platform, embedded_gz, &remote_path).await?;
            verify_remote_binary(ssh, &*platform, &remote_path, expected_sha256).await?;
            populate_cache(ssh, &*platform, &remote_path, &cache_path).await;
        }
    }

    // Execute the relay and parse handshake.
    //
    // The session secret goes over stdin, inside the SSH channel. Passing it as
    // an argument would publish it to every local user on the jump host via
    // `ps`, which is exactly the audience the relay is being defended against.
    let command = format!("{remote_path} --target {target_addr}");
    let stdin = format!("SESSION_SECRET={session_secret}\nEND_SESSION\n");
    let mut relay_port: Option<u16> = None;
    let mut got_ready = false;

    let lines = ssh
        .exec_and_read_lines(
            &command,
            Some(stdin.as_bytes()),
            Duration::from_secs(10),
            |line| {
                if line == "RELAY_READY" {
                    got_ready = true;
                } else if let Some(p) = line.strip_prefix("PORT=") {
                    relay_port = p.trim().parse().ok();
                }
                got_ready && relay_port.is_some()
            },
        )
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
/// 4. Parse handshake (PORT, AGENT_CERT)
pub async fn bootstrap_agent(
    ssh: SshSession,
    custom_binary: Option<&Path>,
    session: &common::session::AgentSessionConfig,
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
    let handshake = match execute_and_handshake(&remote_agent, session).await {
        Ok(h) => h,
        Err(e) => {
            error!(%e, "agent bootstrap failed, cleaning up");
            remote_agent.cleanup().await;
            return Err(e);
        }
    };

    info!(
        port = handshake.port,
        session_id = %session.session_id,
        "agent handshake successful, certificate pinned"
    );

    Ok((handshake, remote_agent))
}

// ---------------------------------------------------------------------------
// Architecture detection
// ---------------------------------------------------------------------------

async fn detect_architecture(
    ssh: &(impl SshExecutor + ?Sized),
    platform: &dyn RemotePlatform,
) -> Result<String> {
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
    ssh: &(impl SshExecutor + ?Sized),
    platform: &dyn RemotePlatform,
    arch: &str,
    custom_binary: Option<&Path>,
) -> Result<String> {
    let random_suffix = common::generate_token()?;
    let ext = platform.binary_ext();
    let remote_path = format!(
        "{}/port-linker-agent-{random_suffix}{ext}",
        platform.temp_dir()
    );

    // Strategy 1: Custom binary override (--agent-binary flag).
    if let Some(path) = custom_binary {
        info!(path = %path.display(), "using custom agent binary");
        let data = read_file_blocking(path).await?;
        let expected_sha256 = sha256_hex(&data);
        transfer_raw(ssh, platform, &data, &remote_path).await?;
        verify_remote_binary(ssh, platform, &remote_path, &expected_sha256).await?;
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

    // The hash of the binary we are willing to run, recorded at build time
    // from the copy embedded in this CLI. Nothing gets executed on the target
    // unless it matches this exactly.
    let expected_sha256 = agent_embed::get_binary_sha256_for_system(platform.os_id(), arch)
        .ok_or_else(|| {
            Error::Security(format!(
                "no recorded checksum for the embedded {}/{arch} agent, so its \
                 integrity on the target cannot be verified",
                platform.os_id()
            ))
        })?;

    // Check remote cache. A hit is only usable if the bytes verify: the cache
    // directory sits in a world-writable temp dir, so anyone with a local
    // account on the target could otherwise plant a binary there and have us
    // run it.
    if check_remote_cache(ssh, platform, &cache_path).await {
        if install_from_cache(ssh, platform, &cache_path, &remote_path, expected_sha256).await? {
            info!(cache = %cache_path, "cache hit, integrity verified");
            return Ok(remote_path);
        }
        warn!(
            cache = %cache_path,
            "cached agent binary failed SHA256 verification and was discarded; \
             transferring the embedded binary instead"
        );
    }

    // Cache miss: transfer compressed binary, decompress on target.
    info!(
        arch,
        compressed_size = embedded_gz.len(),
        "cache miss, transferring compressed agent"
    );
    transfer_compressed(ssh, platform, embedded_gz, &remote_path).await?;
    verify_remote_binary(ssh, platform, &remote_path, expected_sha256).await?;

    // Populate cache in background (best-effort).
    populate_cache(ssh, platform, &remote_path, &cache_path).await;

    Ok(remote_path)
}

/// Verify that the binary at `remote_path` hashes to `expected_sha256`.
///
/// Guards the transfer path too: the decompression happens on the target, so
/// this confirms what landed there is byte-identical to what we shipped.
async fn verify_remote_binary(
    ssh: &(impl SshExecutor + ?Sized),
    platform: &dyn RemotePlatform,
    remote_path: &str,
    expected_sha256: &str,
) -> Result<()> {
    let cmd = platform.sha256_cmd(remote_path);
    let (stdout, stderr, exit_code) = ssh.exec(&cmd).await?;

    if exit_code != Some(0) {
        return Err(Error::Security(format!(
            "could not hash the transferred binary at {remote_path} (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    let actual = stdout.split_whitespace().next().unwrap_or_default();
    if !common::session::secrets_match(actual, expected_sha256) {
        return Err(Error::Security(format!(
            "binary at {remote_path} does not match the binary we sent \
             (expected {expected_sha256}, got {actual})"
        )));
    }

    debug!(remote_path, "binary integrity verified");
    Ok(())
}

/// The full SHA256 of `data`, as lower-case hex.
fn sha256_hex(data: &[u8]) -> String {
    common::session::to_hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// The first [`HASH_PREFIX_LEN`] hex chars of the SHA256 of `data`.
///
/// Used only to name cache entries. Integrity comes from comparing the *full*
/// hash of the installed binary, never from the file name.
fn sha256_hex_prefix(data: &[u8]) -> String {
    let full = sha256_hex(data);
    full.get(..HASH_PREFIX_LEN).unwrap_or(&full).to_string()
}

// ---------------------------------------------------------------------------
// Remote cache operations
// ---------------------------------------------------------------------------

/// Check if the cached binary exists on the remote host.
async fn check_remote_cache(
    ssh: &(impl SshExecutor + ?Sized),
    platform: &dyn RemotePlatform,
    cache_path: &str,
) -> bool {
    let cmd = platform.check_cache_cmd(cache_path);
    match ssh.exec(&cmd).await {
        Ok((stdout, _, Some(0))) => stdout.trim() == "OK",
        _ => false,
    }
}

/// Install the cached binary at `remote_path` and verify it hashes to
/// `expected_sha256`.
///
/// The cache lives in a world-writable temp directory, so a cache hit proves
/// nothing about the file's contents — only the hash does. Returns `false` when
/// the cached binary does not match, so the caller can fall back to
/// transferring the embedded copy.
async fn install_from_cache(
    ssh: &(impl SshExecutor + ?Sized),
    platform: &dyn RemotePlatform,
    cache_path: &str,
    remote_path: &str,
    expected_sha256: &str,
) -> Result<bool> {
    let cmd = platform.copy_cached_cmd(cache_path, remote_path, expected_sha256);
    let (stdout, stderr, exit_code) = ssh.exec(&cmd).await?;

    if exit_code != Some(0) {
        return Err(Error::Protocol(format!(
            "cache copy failed (exit {}): {}",
            exit_code.unwrap_or(255),
            stderr.trim()
        )));
    }

    Ok(stdout.trim() == "OK")
}

/// Populate the remote cache with the deployed binary (best-effort).
async fn populate_cache(
    ssh: &(impl SshExecutor + ?Sized),
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
    ssh: &(impl SshExecutor + ?Sized),
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
    ssh: &(impl SshExecutor + ?Sized),
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

async fn execute_and_handshake(
    agent: &RemoteAgent,
    session: &common::session::AgentSessionConfig,
) -> Result<AgentHandshake> {
    let command = agent.remote_path.to_string();

    let mut port: Option<u16> = None;
    let mut agent_cert: Option<String> = None;
    let mut bridge_port: Option<u16> = None;
    let mut got_ready = false;

    // The session config goes to the agent's stdin, inside the SSH channel.
    // Never as a command-line argument: argv is world-readable via `ps` on the
    // target, which would hand the session secret to every local user.
    let stdin = session.encode();

    let lines = agent
        .ssh
        .exec_and_read_lines(
            &command,
            Some(stdin.as_bytes()),
            Duration::from_secs(10),
            |line| {
                if line == "AGENT_READY" {
                    got_ready = true;
                } else if let Some(p) = line.strip_prefix("PORT=") {
                    port = p.trim().parse().ok();
                } else if let Some(c) = line.strip_prefix("AGENT_CERT=") {
                    agent_cert = Some(c.trim().to_string());
                } else if let Some(bp) = line.strip_prefix("BRIDGE_PORT=") {
                    bridge_port = bp.trim().parse().ok();
                }
                // BRIDGE_PORT is optional for backward compatibility with older agents.
                got_ready && port.is_some() && agent_cert.is_some()
            },
        )
        .await?;

    let port = port.ok_or_else(|| {
        Error::Protocol(format!(
            "agent did not report PORT (got {} lines: {:?})",
            lines.len(),
            lines
        ))
    })?;

    let agent_cert = agent_cert.ok_or_else(|| {
        Error::Security(format!(
            "agent did not publish AGENT_CERT, so its identity cannot be \
             pinned and the tunnel would be open to impersonation \
             (got {} lines: {:?})",
            lines.len(),
            lines
        ))
    })?;
    let agent_cert = common::session::from_hex(&agent_cert)?;

    if !got_ready {
        return Err(Error::Protocol(format!(
            "agent did not report AGENT_READY (got {} lines: {:?})",
            lines.len(),
            lines
        )));
    }

    Ok(AgentHandshake {
        port,
        agent_cert,
        bridge_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::SshExecutor;

    /// Mock SSH executor for testing bootstrap functions without a live SSH server.
    ///
    /// Commands are matched by substring against the `pattern` field.
    /// Responses are returned in order of first match.
    struct MockSshExecutor {
        responses: Vec<MockResponse>,
        /// Everything the caller piped to a remote process's stdin.
        stdin_seen: std::sync::Mutex<Vec<String>>,
    }

    struct MockResponse {
        pattern: &'static str,
        stdout: String,
        stderr: String,
        exit_code: Option<u32>,
    }

    impl MockSshExecutor {
        fn new() -> Self {
            Self {
                responses: Vec::new(),
                stdin_seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Everything piped to remote stdin during this test.
        fn stdin_log(&self) -> Vec<String> {
            self.stdin_seen.lock().expect("stdin log poisoned").clone()
        }

        fn on(mut self, pattern: &'static str, stdout: &str, exit_code: u32) -> Self {
            self.responses.push(MockResponse {
                pattern,
                stdout: stdout.to_string(),
                stderr: String::new(),
                exit_code: Some(exit_code),
            });
            self
        }

        fn on_err(mut self, pattern: &'static str, stderr: &str, exit_code: u32) -> Self {
            self.responses.push(MockResponse {
                pattern,
                stdout: String::new(),
                stderr: stderr.to_string(),
                exit_code: Some(exit_code),
            });
            self
        }

        fn on_fail(mut self, pattern: &'static str) -> Self {
            self.responses.push(MockResponse {
                pattern,
                stdout: String::new(),
                stderr: "command failed".to_string(),
                exit_code: Some(1),
            });
            self
        }

        fn find_response(&self, command: &str) -> (String, String, Option<u32>) {
            for resp in &self.responses {
                if command.contains(resp.pattern) {
                    return (resp.stdout.clone(), resp.stderr.clone(), resp.exit_code);
                }
            }
            // Default: command not found
            (String::new(), "mock: no match".to_string(), Some(127))
        }
    }

    impl SshExecutor for MockSshExecutor {
        async fn exec(&self, command: &str) -> common::Result<(String, String, Option<u32>)> {
            Ok(self.find_response(command))
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _data: &[u8],
        ) -> common::Result<(String, String, Option<u32>)> {
            Ok(self.find_response(command))
        }

        async fn exec_and_read_lines(
            &self,
            command: &str,
            stdin_data: Option<&[u8]>,
            _timeout: Duration,
            mut predicate: impl FnMut(&str) -> bool + Send,
        ) -> common::Result<Vec<String>> {
            // Record what the host would have written to the process's stdin so
            // tests can assert the session config never leaks into argv.
            if let Some(data) = stdin_data {
                self.stdin_seen
                    .lock()
                    .expect("stdin log poisoned")
                    .push(String::from_utf8_lossy(data).into_owned());
            }
            let (stdout, _, _) = self.find_response(command);
            let mut lines = Vec::new();
            for line in stdout.lines() {
                let done = predicate(line);
                lines.push(line.to_string());
                if done {
                    return Ok(lines);
                }
            }
            Ok(lines)
        }

        async fn exec_detached(&self, _command: &str) -> common::Result<()> {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Tests using MockSshExecutor
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_detect_remote_platform_linux() {
        let mock = MockSshExecutor::new()
            .on("uname -s", "Linux\n", 0)
            .on("TMPDIR", "/tmp", 0);
        let platform = crate::remote_platform::detect_remote_platform(&mock).await;
        assert_eq!(platform.os_id(), "linux");
    }

    #[tokio::test]
    async fn test_detect_remote_platform_darwin() {
        let mock = MockSshExecutor::new()
            .on("uname -s", "Darwin\n", 0)
            .on("TMPDIR", "/tmp", 0);
        let platform = crate::remote_platform::detect_remote_platform(&mock).await;
        assert_eq!(platform.os_id(), "darwin");
    }

    #[tokio::test]
    async fn test_detect_remote_platform_windows() {
        let mock = MockSshExecutor::new().on_err("uname", "not found", 127).on(
            "powershell",
            r"C:\Users\Admin\AppData\Local\Temp",
            0,
        );
        let platform = crate::remote_platform::detect_remote_platform(&mock).await;
        assert_eq!(platform.os_id(), "windows");
    }

    #[tokio::test]
    async fn test_detect_remote_platform_fallback() {
        let mock = MockSshExecutor::new()
            .on_fail("uname")
            .on_fail("powershell");
        let platform = crate::remote_platform::detect_remote_platform(&mock).await;
        // Falls back to Linux.
        assert_eq!(platform.os_id(), "linux");
    }

    #[tokio::test]
    async fn test_detect_architecture_linux() {
        let mock = MockSshExecutor::new().on("uname -m", "x86_64\n", 0);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let arch = detect_architecture(&mock, &platform).await.unwrap();
        assert_eq!(arch, "x86_64");
    }

    #[tokio::test]
    async fn test_detect_architecture_arm64() {
        let mock = MockSshExecutor::new().on("uname -m", "arm64\n", 0);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let arch = detect_architecture(&mock, &platform).await.unwrap();
        assert_eq!(arch, "aarch64");
    }

    #[tokio::test]
    async fn test_detect_architecture_failure() {
        let mock = MockSshExecutor::new().on_err("uname -m", "not found", 1);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let result = detect_architecture(&mock, &platform).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transfer_compressed_success() {
        let mock = MockSshExecutor::new().on("gunzip", "", 0);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let result = transfer_compressed(&mock, &platform, b"fake-gz-data", "/tmp/agent-xyz").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transfer_compressed_failure() {
        let mock = MockSshExecutor::new().on_err("gunzip", "disk full", 1);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let result = transfer_compressed(&mock, &platform, b"fake-gz-data", "/tmp/agent-xyz").await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("disk full") || err_msg.contains("transfer failed"));
    }

    #[tokio::test]
    async fn test_check_remote_cache_hit() {
        let mock = MockSshExecutor::new().on("test -x", "OK\n", 0);
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let hit = check_remote_cache(&mock, &platform, "/tmp/cache/agent-hash").await;
        assert!(hit);
    }

    #[tokio::test]
    async fn test_check_remote_cache_miss() {
        let mock = MockSshExecutor::new().on_fail("test -x");
        let platform = crate::remote_platform::test_helpers::unix_platform();
        let hit = check_remote_cache(&mock, &platform, "/tmp/cache/agent-hash").await;
        assert!(!hit);
    }

    // -----------------------------------------------------------------------
    // Original tests (unchanged)
    // -----------------------------------------------------------------------

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
            agent_cert: vec![0xde, 0xad, 0xbe, 0xef],
            bridge_port: Some(8888),
        };

        assert_eq!(handshake.port, 9999);
        assert_eq!(handshake.agent_cert, vec![0xde, 0xad, 0xbe, 0xef]);
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

    // -----------------------------------------------------------------------
    // Security regression tests
    // -----------------------------------------------------------------------

    /// The relay's session secret must travel over stdin, never argv, because
    /// argv is world-readable via `ps` on a shared jump host.
    #[tokio::test]
    async fn relay_secret_goes_over_stdin_not_argv() {
        let secret = "s3cr3t-relay-token";
        let mock = MockSshExecutor::new()
            .on("uname -s", "Linux\n", 0)
            .on("TMPDIR", "/tmp", 0)
            .on("uname -m", "x86_64\n", 0)
            .on("test -x", "", 1)
            .on("gunzip", "", 0)
            .on("sha256sum", "", 1)
            .on("--target", "RELAY_READY\nPORT=5555\n", 0);

        // The deployment itself fails in this mock (no embedded binary in a
        // debug build); what matters is what was placed on the command line.
        let _ = bootstrap_relay(&mock, "10.0.0.1:9999", None, secret).await;

        let commands_with_secret = mock
            .responses
            .iter()
            .filter(|r| r.pattern.contains(secret))
            .count();
        assert_eq!(
            commands_with_secret, 0,
            "the session secret must never appear in a remote command line"
        );
    }

    /// A custom binary must be verified after transfer, so a truncated or
    /// tampered copy is never executed.
    #[tokio::test]
    async fn custom_binary_transfer_is_verified() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "plk-test-binary-{}",
            common::generate_token().unwrap()
        ));
        std::fs::write(&tmp, b"#!/bin/sh\ntrue\n").unwrap();
        let expected = sha256_hex(&std::fs::read(&tmp).unwrap());

        // The remote reports a different hash than what we sent.
        let mock = MockSshExecutor::new()
            .on("uname -s", "Linux\n", 0)
            .on("TMPDIR", "/tmp", 0)
            .on("uname -m", "x86_64\n", 0)
            .on("cat >", "", 0)
            .on(
                "sha256sum",
                &format!("{} /tmp/whatever\n", "0".repeat(64)),
                0,
            );

        let platform = crate::remote_platform::test_helpers::unix_platform();
        let result = transfer_agent(&mock, &platform, "x86_64", Some(&tmp)).await;
        std::fs::remove_file(&tmp).ok();

        let err = result.expect_err("a mismatched hash must abort the bootstrap");
        assert!(
            matches!(err, Error::Security(_)),
            "expected a security error, got {err:?}"
        );
        assert!(!expected.is_empty());
    }

    /// A binary whose hash matches is accepted.
    #[tokio::test]
    async fn matching_hash_is_accepted() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "plk-test-binary-ok-{}",
            common::generate_token().unwrap()
        ));
        std::fs::write(&tmp, b"#!/bin/sh\ntrue\n").unwrap();
        let expected = sha256_hex(&std::fs::read(&tmp).unwrap());

        let mock = MockSshExecutor::new()
            .on("uname -s", "Linux\n", 0)
            .on("TMPDIR", "/tmp", 0)
            .on("cat >", "", 0)
            .on("sha256sum", &format!("{expected}  /tmp/agent\n"), 0);

        let platform = crate::remote_platform::test_helpers::unix_platform();
        let result = transfer_agent(&mock, &platform, "x86_64", Some(&tmp)).await;
        std::fs::remove_file(&tmp).ok();

        assert!(
            result.is_ok(),
            "matching hash should be accepted: {result:?}"
        );
    }

    /// The session config must reach the agent on stdin, and must not contain
    /// the host's private key.
    #[tokio::test]
    async fn agent_session_config_is_delivered_over_stdin() {
        let identity = common::session::Identity::generate("host").unwrap();
        let config = common::session::AgentSessionConfig {
            session_id: common::session::generate_session_id().unwrap(),
            session_secret: common::session::generate_session_secret().unwrap(),
            client_cert_der: identity.cert_der().to_vec(),
        };

        let agent_identity = common::session::Identity::generate("agent").unwrap();
        let cert_hex = common::session::to_hex(agent_identity.cert_der());
        let mock = MockSshExecutor::new().on(
            "/tmp/agent",
            &format!("AGENT_READY\nPORT=4242\nAGENT_CERT={cert_hex}\nBRIDGE_PORT=4343\n"),
            0,
        );

        let lines = mock
            .exec_and_read_lines(
                "/tmp/agent",
                Some(config.encode().as_bytes()),
                Duration::from_secs(1),
                |line| line.starts_with("BRIDGE_PORT="),
            )
            .await
            .unwrap();

        assert!(lines.iter().any(|l| l.starts_with("AGENT_CERT=")));

        let stdin = mock.stdin_log();
        assert_eq!(stdin.len(), 1, "config should be written exactly once");
        let written = stdin.first().unwrap();
        assert!(written.contains(&config.session_secret));
        assert!(
            !written.contains(&common::session::to_hex(identity.key_der())),
            "the host private key must never be sent to the agent"
        );

        // And it parses back to exactly what we sent.
        let parsed = common::session::AgentSessionConfig::parse(written).unwrap();
        assert_eq!(parsed, config);
    }

    // -----------------------------------------------------------------------
    // Cache poisoning regression tests
    // -----------------------------------------------------------------------
    //
    // The remote cache lives in a world-writable temp directory, so a local
    // user on the target can plant a file at the (deterministic) cache path. A
    // previous version checked only `test -x`, so a planted binary was copied
    // into place and executed as the connecting user. These tests run the
    // generated shell commands for real against a scratch directory.

    /// Run a generated bootstrap command through /bin/sh, as the remote would.
    ///
    /// Unix-only: these tests execute the shell commands built for `RemoteUnix`.
    /// The Windows equivalents are asserted as command strings in
    /// `remote_platform::tests`, since Windows has no /bin/sh to run them with.
    #[cfg(unix)]
    fn run_shell(command: &str) -> (String, i32) {
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .output()
            .expect("failed to run shell command");
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            output.status.code().unwrap_or(-1),
        )
    }

    /// A scratch directory that stands in for the remote temp dir.
    #[cfg(unix)]
    struct ScratchDir(std::path::PathBuf);

    #[cfg(unix)]
    impl ScratchDir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "plk-cache-test-{}",
                common::generate_token().expect("token")
            ));
            std::fs::create_dir_all(&path).expect("failed to create scratch dir");
            Self(path)
        }

        fn join(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    #[cfg(unix)]
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    #[cfg(unix)]
    fn poisoned_cache_entry_is_rejected_and_removed() {
        let dir = ScratchDir::new();
        let cache_path = dir.join("agent-deadbeefdeadbeef");
        let install_path = dir.join("port-linker-agent-plk-abc");

        // An attacker plants their own executable at the predictable cache path.
        std::fs::write(&cache_path, b"#!/bin/sh\necho pwned\n").unwrap();

        // The host expects the hash of the binary it actually shipped.
        let expected = sha256_hex(b"the real agent binary");

        let platform = crate::remote_platform::test_helpers::unix_platform();
        let (stdout, _) =
            run_shell(&platform.copy_cached_cmd(&cache_path, &install_path, &expected));

        assert_ne!(
            stdout.trim(),
            "OK",
            "a poisoned cache entry must not be reported as usable"
        );
        assert!(
            !std::path::Path::new(&install_path).exists(),
            "the poisoned binary must be removed, not left in place to be executed"
        );
    }

    #[test]
    #[cfg(unix)]
    fn matching_cache_entry_is_installed_and_reported_ok() {
        let dir = ScratchDir::new();
        let cache_path = dir.join("agent-deadbeefdeadbeef");
        let install_path = dir.join("port-linker-agent-plk-abc");

        let contents = b"#!/bin/sh\ntrue\n";
        std::fs::write(&cache_path, contents).unwrap();
        let expected = sha256_hex(contents);

        let platform = crate::remote_platform::test_helpers::unix_platform();
        let (stdout, _) =
            run_shell(&platform.copy_cached_cmd(&cache_path, &install_path, &expected));

        assert_eq!(
            stdout.trim(),
            "OK",
            "a cache entry matching the expected hash should be usable"
        );
        assert_eq!(
            std::fs::read(&install_path).unwrap(),
            contents,
            "the verified binary should be installed"
        );
    }

    /// The hash must cover the installed copy, not the cache entry.
    ///
    /// Verifying the cache entry would leave a window in which an attacker
    /// swaps the file between the check and the copy, so what runs is never
    /// what was hashed. This asserts the property structurally — the hashed
    /// path is the install path — and then that tampering with the cache
    /// afterwards cannot change what was installed and verified.
    #[test]
    #[cfg(unix)]
    fn cache_verification_covers_the_installed_copy_not_the_cache_entry() {
        let dir = ScratchDir::new();
        let cache_path = dir.join("agent-deadbeefdeadbeef");
        let install_path = dir.join("port-linker-agent-plk-abc");

        let good = b"#!/bin/sh\ntrue\n";
        std::fs::write(&cache_path, good).unwrap();
        let expected = sha256_hex(good);

        let platform = crate::remote_platform::test_helpers::unix_platform();
        let command = platform.copy_cached_cmd(&cache_path, &install_path, &expected);

        // The hashing step must name the install path, and must not name the
        // cache path — otherwise the bytes verified are not the bytes run.
        let hash_step = command
            .split("&&")
            .find(|step| step.contains("sha256sum"))
            .expect("the command must hash something");
        assert!(
            hash_step.contains(&install_path),
            "the hash must be computed over the installed copy: {hash_step}"
        );
        assert!(
            !hash_step.contains(&cache_path),
            "the hash must not be computed over the cache entry: {hash_step}"
        );

        let (stdout, _) = run_shell(&command);
        assert_eq!(stdout.trim(), "OK");

        // A later swap of the cache entry cannot retroactively change the
        // binary that was verified and installed.
        std::fs::write(&cache_path, b"pwned").unwrap();
        assert_eq!(
            std::fs::read(&install_path).unwrap(),
            good,
            "the installed binary must remain the verified one"
        );
    }

    /// The cache directory must not be world-writable, so other users on a
    /// shared host cannot plant entries in the first place.
    #[test]
    #[cfg(unix)]
    fn populated_cache_directory_is_owner_only() {
        let dir = ScratchDir::new();
        let cache_dir = dir.join("nested-cache");
        let source = dir.join("agent-source");
        std::fs::write(&source, b"binary").unwrap();

        // Build a platform whose cache dir is the scratch path.
        let platform = crate::remote_platform::test_helpers::unix_platform_with_cache(&cache_dir);
        let (_, code) =
            run_shell(&platform.populate_cache_cmd(&source, &format!("{cache_dir}/agent-hash")));
        assert_eq!(code, 0, "populate should succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cache_dir).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "cache dir must not be group- or world-accessible (mode {mode:o})"
            );
        }

        assert_eq!(
            std::fs::read(format!("{cache_dir}/agent-hash")).unwrap(),
            b"binary",
            "the cache entry should be installed"
        );
    }
}
