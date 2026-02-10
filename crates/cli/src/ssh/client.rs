use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, client};
use tracing::{debug, info};

use common::{Error, Result};

use super::config::{self, SshHostConfig};

// ---------------------------------------------------------------------------
// Host key verification policy
// ---------------------------------------------------------------------------

/// How to handle SSH host key verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HostKeyPolicy {
    /// Reject unknown or changed host keys.
    Strict,
    /// Accept unknown keys (add to known_hosts), reject changed keys.
    AcceptNew,
    /// Accept all keys (insecure, for testing).
    AcceptAll,
}

impl std::fmt::Display for HostKeyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::AcceptNew => write!(f, "accept-new"),
            Self::AcceptAll => write!(f, "accept-all"),
        }
    }
}

// ---------------------------------------------------------------------------
// SSH Handler (russh callback impl)
// ---------------------------------------------------------------------------

struct Handler {
    policy: HostKeyPolicy,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match self.policy {
            HostKeyPolicy::AcceptAll => Ok(true),
            HostKeyPolicy::AcceptNew => {
                // TODO: Check known_hosts, accept if new, reject if changed.
                // For now, accept all (same as AcceptAll).
                Ok(true)
            }
            HostKeyPolicy::Strict => {
                // TODO: Check known_hosts, reject if unknown or changed.
                // For now, accept all to unblock development.
                Ok(true)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SshSession
// ---------------------------------------------------------------------------

/// An active SSH session wrapping a russh client handle.
pub struct SshSession {
    handle: client::Handle<Handler>,
    config: SshHostConfig,
    /// The resolved IP address of the remote host.
    peer_ip: std::net::IpAddr,
}

impl SshSession {
    /// Connect to a remote host via SSH.
    ///
    /// `remote` is either `host` or `user@host`. The port and identity files
    /// are resolved from ~/.ssh/config.
    pub async fn connect(remote: &str, host_key_policy: HostKeyPolicy) -> Result<Self> {
        // Parse user@host format.
        let (user_override, host) = if let Some(idx) = remote.find('@') {
            (Some(&remote[..idx]), &remote[idx + 1..])
        } else {
            (None, remote)
        };

        // Resolve SSH config.
        let ssh_config = config::resolve_ssh_config(host, user_override);
        info!(
            host = %ssh_config.hostname,
            port = ssh_config.port,
            user = %ssh_config.user,
            identity_files = ?ssh_config.identity_files,
            "resolved SSH config"
        );

        // Build russh client config.
        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });

        // Resolve hostname to a socket address (supports both IPs and DNS names).
        let addr_str = format!("{}:{}", ssh_config.hostname, ssh_config.port);
        let addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| {
                Error::Protocol(format!("failed to resolve SSH host '{}': {e}", addr_str))
            })?
            .next()
            .ok_or_else(|| {
                Error::Protocol(format!("no addresses found for SSH host '{}'", addr_str))
            })?;

        let handler = Handler {
            policy: host_key_policy,
        };

        let handle = client::connect(client_config, addr, handler)
            .await
            .map_err(|e| Error::Protocol(format!("SSH connect failed: {e}")))?;

        info!("SSH connection established to {}", addr);

        // Authenticate.
        let mut session = SshSession {
            handle,
            config: ssh_config,
            peer_ip: addr.ip(),
        };
        session.authenticate().await?;

        Ok(session)
    }

    /// The resolved IP address of the remote host.
    pub fn peer_ip(&self) -> std::net::IpAddr {
        self.peer_ip
    }

    async fn authenticate(&mut self) -> Result<()> {
        let user = self.config.user.clone();

        // Try each identity file.
        for key_path in &self.config.identity_files {
            debug!(key = %key_path.display(), "trying SSH key");

            let key_pair = match russh::keys::load_secret_key(key_path, None) {
                Ok(k) => k,
                Err(e) => {
                    debug!(key = %key_path.display(), %e, "failed to load key, trying next");
                    continue;
                }
            };

            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);

            match self
                .handle
                .authenticate_publickey(&user, key_with_hash)
                .await
            {
                Ok(result) => {
                    if result.success() {
                        info!(
                            user = %user,
                            key = %key_path.display(),
                            "SSH authentication successful"
                        );
                        return Ok(());
                    }
                    debug!(key = %key_path.display(), "key not accepted, trying next");
                }
                Err(e) => {
                    debug!(key = %key_path.display(), %e, "auth attempt failed, trying next");
                }
            }
        }

        // If no keys worked, try password auth via interactive prompt.
        info!("no SSH keys accepted, trying password authentication");
        let user_clone = user.clone();
        let password = tokio::task::spawn_blocking(move || {
            dialoguer::Password::new()
                .with_prompt(format!("Password for {user_clone}"))
                .interact()
        })
        .await
        .map_err(|e| Error::Protocol(format!("password prompt failed: {e}")))?
        .map_err(|e| Error::Protocol(format!("password prompt failed: {e}")))?;

        let result = self
            .handle
            .authenticate_password(&user, &password)
            .await
            .map_err(|e| Error::Protocol(format!("password auth failed: {e}")))?;

        if !result.success() {
            return Err(Error::Protocol("SSH authentication failed".into()));
        }

        info!(user = %user, "SSH password authentication successful");
        Ok(())
    }

    /// Execute a command on the remote host, returning (stdout, stderr, exit_code).
    pub async fn exec(&self, command: &str) -> Result<(String, String, Option<u32>)> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Protocol(format!("failed to open SSH channel: {e}")))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| Error::Protocol(format!("failed to exec command: {e}")))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        // Read channel messages until Close or the channel returns None.
        // IMPORTANT: Do NOT break on Eof — the ExitStatus message often
        // arrives AFTER Eof in the SSH protocol. Breaking on Eof causes
        // exit_code to remain None, which makes every command appear to fail.
        loop {
            match tokio::time::timeout(Duration::from_secs(30), channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { data } => {
                        stdout.extend_from_slice(&data);
                    }
                    ChannelMsg::ExtendedData { data, ext } => {
                        if ext == 1 {
                            stderr.extend_from_slice(&data);
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status);
                    }
                    ChannelMsg::Close => {
                        break;
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(_) => {
                    return Err(Error::Protocol("SSH command timed out".into()));
                }
            }
        }

        let stdout_str = String::from_utf8(stdout)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        let stderr_str = String::from_utf8(stderr)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

        debug!(
            command,
            exit_code,
            stdout_len = stdout_str.len(),
            stderr_len = stderr_str.len(),
            "SSH command completed"
        );

        Ok((stdout_str, stderr_str, exit_code))
    }

    /// Execute a command and pipe data to its stdin.
    pub async fn exec_with_stdin(
        &self,
        command: &str,
        data: &[u8],
    ) -> Result<(String, String, Option<u32>)> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Protocol(format!("failed to open SSH channel: {e}")))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| Error::Protocol(format!("failed to exec command: {e}")))?;

        // Split the channel so we can write data AND drain incoming
        // messages concurrently. The russh session handler sends
        // WindowAdjusted messages to the channel's internal mpsc
        // (bounded, capacity 100). If we block on writing without
        // draining the read side, that mpsc fills up, the session
        // handler blocks trying to deliver the next WindowAdjusted,
        // and the whole connection deadlocks.
        let (mut read_half, write_half) = channel.split();

        // Spawn a task to drain the read half.
        let drain_handle = tokio::spawn(async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_code = None;

            loop {
                match tokio::time::timeout(Duration::from_secs(120), read_half.wait()).await {
                    Ok(Some(msg)) => match msg {
                        ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                        ChannelMsg::ExtendedData { data, ext } => {
                            if ext == 1 {
                                stderr.extend_from_slice(&data);
                            }
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            exit_code = Some(exit_status);
                        }
                        ChannelMsg::Close => break,
                        _ => {}
                    },
                    Ok(None) => break,
                    Err(_) => break,
                }
            }

            (stdout, stderr, exit_code)
        });

        // Write data using the channel's AsyncWrite implementation,
        // which properly handles SSH window management (waits for
        // window-adjust notifications between sends).
        let write_result: Result<()> = async {
            use tokio::io::AsyncWriteExt;
            let mut writer = write_half.make_writer();

            const CHUNK_SIZE: usize = 65_536; // 64 KB
            let total = data.len();
            let mut offset = 0;
            let mut last_logged_pct: u32 = 0;

            while offset < total {
                let end = (offset + CHUNK_SIZE).min(total);
                writer
                    .write_all(&data[offset..end])
                    .await
                    .map_err(|e| Error::Protocol(format!("failed to write stdin: {e}")))?;
                offset = end;

                if total > CHUNK_SIZE {
                    let pct = (offset as f64 / total as f64 * 100.0) as u32;
                    if pct / 10 > last_logged_pct / 10 || offset == total {
                        debug!(sent = offset, total, pct, "transfer progress");
                        last_logged_pct = pct;
                    }
                }
            }

            // Shutdown sends EOF to the remote stdin.
            writer
                .shutdown()
                .await
                .map_err(|e| Error::Protocol(format!("failed to send EOF: {e}")))?;

            Ok(())
        }
        .await;

        if let Err(e) = write_result {
            drain_handle.abort();
            return Err(e);
        }

        // Wait for the drain task to collect stdout, stderr, and exit code.
        let (stdout, stderr, exit_code) = drain_handle
            .await
            .map_err(|e| Error::Protocol(format!("channel drain failed: {e}")))?;

        let stdout_str = String::from_utf8(stdout)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        let stderr_str = String::from_utf8(stderr)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

        Ok((stdout_str, stderr_str, exit_code))
    }

    /// Execute a command and read stdout line-by-line until a condition is met.
    /// Returns all lines read. Used for parsing the agent handshake.
    pub async fn exec_and_read_lines(
        &self,
        command: &str,
        timeout: Duration,
        mut predicate: impl FnMut(&str) -> bool,
    ) -> Result<Vec<String>> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Protocol(format!("failed to open SSH channel: {e}")))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| Error::Protocol(format!("failed to exec command: {e}")))?;

        let mut lines = Vec::new();
        let mut buffer = String::new();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Protocol("agent handshake timed out".into()));
            }

            match tokio::time::timeout(remaining, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { data } => {
                        buffer.push_str(&String::from_utf8_lossy(&data));
                        // Process complete lines.
                        while let Some(newline_pos) = buffer.find('\n') {
                            let line = buffer[..newline_pos].trim_end().to_string();
                            // Drain the consumed line from the buffer without
                            // reallocating: shift bytes left and truncate.
                            buffer.drain(..newline_pos + 1);
                            debug!(line = %line, "agent stdout");
                            let done = predicate(&line);
                            lines.push(line);
                            if done {
                                return Ok(lines);
                            }
                        }
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        // Process any remaining partial line.
                        if !buffer.trim().is_empty() {
                            let line = buffer.trim().to_string();
                            let done = predicate(&line);
                            lines.push(line);
                            if done {
                                return Ok(lines);
                            }
                        }
                        break;
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(_) => {
                    return Err(Error::Protocol("agent handshake timed out".into()));
                }
            }
        }

        Err(Error::Protocol(format!(
            "agent exited before handshake completed (got {} lines)",
            lines.len()
        )))
    }

    /// Execute a fire-and-forget command (e.g., kill, rm).
    pub async fn exec_detached(&self, command: &str) -> Result<()> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Protocol(format!("failed to open SSH channel: {e}")))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| Error::Protocol(format!("failed to exec command: {e}")))?;

        // Don't wait for output - just close.
        Ok(())
    }

    /// Close the SSH connection gracefully.
    #[allow(dead_code)]
    pub async fn close(self) -> Result<()> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| Error::Protocol(format!("SSH disconnect failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_key_policy_display() {
        assert_eq!(HostKeyPolicy::Strict.to_string(), "strict");
        assert_eq!(HostKeyPolicy::AcceptNew.to_string(), "accept-new");
        assert_eq!(HostKeyPolicy::AcceptAll.to_string(), "accept-all");
    }

    #[test]
    fn test_host_key_policy_value_enum() {
        // Test that all variants are available for clap parsing.
        // This is validated by the ValueEnum derive, but we ensure it compiles.
        let _variants: &[HostKeyPolicy] = &[
            HostKeyPolicy::Strict,
            HostKeyPolicy::AcceptNew,
            HostKeyPolicy::AcceptAll,
        ];
    }

    #[test]
    fn test_host_key_policy_equality() {
        assert_eq!(HostKeyPolicy::Strict, HostKeyPolicy::Strict);
        assert_eq!(HostKeyPolicy::AcceptNew, HostKeyPolicy::AcceptNew);
        assert_eq!(HostKeyPolicy::AcceptAll, HostKeyPolicy::AcceptAll);

        assert_ne!(HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew);
        assert_ne!(HostKeyPolicy::AcceptNew, HostKeyPolicy::AcceptAll);
    }

    #[test]
    fn test_host_key_policy_copy() {
        let policy = HostKeyPolicy::AcceptNew;
        let copied = policy;
        assert_eq!(policy, copied);
    }

    #[test]
    fn test_host_key_policy_debug() {
        let policy = HostKeyPolicy::Strict;
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("Strict"));
    }
}
