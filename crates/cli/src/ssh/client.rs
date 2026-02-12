use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, client};
use tracing::{debug, info};

use common::{Error, Result};

use super::config::{self, JumpHost, SshHostConfig};

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

    /// Open a direct-tcpip tunnel to a remote host:port through this SSH session.
    ///
    /// Returns a `ChannelStream` that implements `AsyncRead + AsyncWrite`.
    pub async fn open_tunnel(
        &self,
        host: &str,
        port: u16,
    ) -> Result<russh::ChannelStream<client::Msg>> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| {
                Error::Protocol(format!(
                    "failed to open direct-tcpip tunnel to {host}:{port}: {e}"
                ))
            })?;

        Ok(channel.into_stream())
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

    /// Connect to a host via SSH over an existing stream (e.g., a tunnel).
    ///
    /// This is used for multi-hop SSH connections where the stream is a
    /// `direct-tcpip` channel from a previous SSH session.
    async fn connect_over_stream<S>(
        stream: S,
        ssh_config: SshHostConfig,
        host_key_policy: HostKeyPolicy,
        peer_ip: std::net::IpAddr,
    ) -> Result<Self>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });

        let handler = Handler {
            policy: host_key_policy,
        };

        let handle = client::connect_stream(client_config, stream, handler)
            .await
            .map_err(|e| Error::Protocol(format!("SSH connect over stream failed: {e}")))?;

        let mut session = SshSession {
            handle,
            config: ssh_config,
            peer_ip,
        };
        session.authenticate().await?;
        Ok(session)
    }
}

// ---------------------------------------------------------------------------
// SSH connection chaining (ProxyJump support)
// ---------------------------------------------------------------------------

/// An SSH connection chain through one or more jump hosts.
///
/// Keeps all intermediate SSH sessions alive so the tunneled channels
/// remain valid for the lifetime of the chain.
pub struct SshChain {
    /// Jump host sessions, in order. Must be kept alive for channel lifetime.
    pub jump_sessions: Vec<SshSession>,
    /// The final target SSH session.
    pub target: SshSession,
}

impl SshChain {
    /// Connect to a target host through a chain of jump hosts.
    ///
    /// `jump_hosts` is the ordered list of hops (first = closest to client).
    /// The final connection is made to `remote` (the target).
    pub async fn connect(
        remote: &str,
        host_key_policy: HostKeyPolicy,
        jump_hosts: &[JumpHost],
    ) -> Result<Self> {
        if jump_hosts.is_empty() {
            return Err(Error::Protocol(
                "SshChain::connect called with empty jump_hosts".into(),
            ));
        }

        let mut jump_sessions = Vec::with_capacity(jump_hosts.len());

        // Step 1: Connect to the first jump host directly.
        let first_jump = &jump_hosts[0];
        let first_config = config::SshHostConfig {
            hostname: first_jump.hostname.clone(),
            port: first_jump.port,
            user: first_jump.user.clone().unwrap_or_else(config::whoami_pub),
            identity_files: if first_jump.identity_files.is_empty() {
                config::default_identity_files_pub()
            } else {
                first_jump.identity_files.clone()
            },
            proxy_jump: None,
        };

        info!(
            host = %first_config.hostname,
            port = first_config.port,
            user = %first_config.user,
            "connecting to first jump host"
        );

        let addr_str = format!("{}:{}", first_config.hostname, first_config.port);
        let addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| {
                Error::Protocol(format!("failed to resolve jump host '{}': {e}", addr_str))
            })?
            .next()
            .ok_or_else(|| {
                Error::Protocol(format!("no addresses found for jump host '{}'", addr_str))
            })?;

        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });

        let handler = Handler {
            policy: host_key_policy,
        };

        let handle = client::connect(client_config, addr, handler)
            .await
            .map_err(|e| Error::Protocol(format!("SSH connect to jump host failed: {e}")))?;

        let mut first_session = SshSession {
            handle,
            config: first_config,
            peer_ip: addr.ip(),
        };
        first_session.authenticate().await?;
        info!("connected to first jump host at {}", addr);

        jump_sessions.push(first_session);

        // Step 2: Chain through remaining jump hosts.
        for (i, jump) in jump_hosts.iter().enumerate().skip(1) {
            let prev = &jump_sessions[i - 1];
            let jump_config = config::SshHostConfig {
                hostname: jump.hostname.clone(),
                port: jump.port,
                user: jump.user.clone().unwrap_or_else(config::whoami_pub),
                identity_files: if jump.identity_files.is_empty() {
                    config::default_identity_files_pub()
                } else {
                    jump.identity_files.clone()
                },
                proxy_jump: None,
            };

            info!(
                host = %jump_config.hostname,
                port = jump_config.port,
                hop = i + 1,
                "tunneling to next jump host"
            );

            let stream = prev
                .open_tunnel(&jump_config.hostname, jump_config.port)
                .await?;
            let peer_ip = prev.peer_ip;

            let session =
                SshSession::connect_over_stream(stream, jump_config, host_key_policy, peer_ip)
                    .await?;

            jump_sessions.push(session);
        }

        // Step 3: Connect to the final target through the last jump host.
        let (user_override, host) = if let Some(idx) = remote.find('@') {
            (Some(&remote[..idx]), &remote[idx + 1..])
        } else {
            (None, remote)
        };

        let target_config = config::resolve_ssh_config(host, user_override);
        let last_jump = jump_sessions.last().unwrap();

        info!(
            host = %target_config.hostname,
            port = target_config.port,
            user = %target_config.user,
            "tunneling to final target"
        );

        let stream = last_jump
            .open_tunnel(&target_config.hostname, target_config.port)
            .await?;

        // Resolve target IP (best-effort for peer_ip tracking).
        let target_ip =
            tokio::net::lookup_host(format!("{}:{}", target_config.hostname, target_config.port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|a| a.ip())
                .unwrap_or(last_jump.peer_ip);

        let target =
            SshSession::connect_over_stream(stream, target_config, host_key_policy, target_ip)
                .await?;

        info!("SSH chain established ({} hops)", jump_sessions.len());

        Ok(SshChain {
            jump_sessions,
            target,
        })
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
