use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, client};
use tracing::{debug, error, info, warn};

use common::{Error, Result};

use super::config::{self, JumpHost, SshHostConfig};

// ---------------------------------------------------------------------------
// Host key verification policy
// ---------------------------------------------------------------------------

/// How to handle SSH host key verification.
///
/// SSH is the root of trust for the entire tunnel: it is the channel over which
/// the two ends exchange the certificates they will pin. If the SSH server is
/// not who it claims to be, everything downstream is introduced by the attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HostKeyPolicy {
    /// Show the fingerprint of an unknown key and ask the user. The default.
    ///
    /// Matches OpenSSH. A changed key is still refused outright, and with no
    /// terminal to ask on this behaves as `strict` rather than hanging.
    Ask,
    /// Reject unknown or changed host keys.
    Strict,
    /// Accept unknown keys (adding them to known_hosts), reject changed keys.
    ///
    /// Trust-on-first-use: the first connection to a host is unauthenticated
    /// and can be intercepted; later ones are protected.
    AcceptNew,
    /// Accept all keys. Insecure — provides no protection against an
    /// impersonated server — and intended only for disposable test fixtures.
    AcceptAll,
}

impl std::fmt::Display for HostKeyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ask => write!(f, "ask"),
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
    /// Host name as it should appear in `known_hosts`.
    host: String,
    /// Port as it should appear in `known_hosts`.
    port: u16,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let policy = self.policy;
        let host = self.host.clone();
        let port = self.port;
        let key = server_public_key.clone();

        // `ask` blocks on terminal input, so the whole check runs off-runtime.
        // Prompting on a worker thread would stall every other task sharing it
        // for as long as the user takes to answer.
        let trusted = tokio::task::spawn_blocking(move || {
            verify_host_key(policy, &host, port, &key, None, prompt_to_trust_host_key)
        })
        .await
        .unwrap_or_else(|e| {
            error!(%e, "host key check panicked — refusing to connect");
            false
        });

        Ok(trusted)
    }
}

/// Asks the user whether to trust an unknown host key.
///
/// A function pointer rather than a closure so `verify_host_key` stays concrete
/// and the tests can answer without a terminal.
type ConfirmHostKey = fn(&str, u16, &PublicKey) -> bool;

/// Show an unknown host key's fingerprint and ask whether to trust it.
///
/// Returns `false` without asking when there is no terminal to ask on: a CI job
/// or a backgrounded run has to fail closed rather than block forever on an
/// answer nobody can give.
fn prompt_to_trust_host_key(host: &str, port: u16, server_public_key: &PublicKey) -> bool {
    use std::io::IsTerminal;

    let fingerprint = server_public_key.fingerprint(Default::default());

    // dialoguer reads stdin and draws on stderr, so both have to be a terminal.
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        error!(
            host = %host,
            %fingerprint,
            "unknown SSH host key and no terminal to confirm it on — refusing to \
             connect. Verify the fingerprint out of band and add it to \
             ~/.ssh/known_hosts, or re-run with \
             --ssh-host-key-verification=accept-new to trust it on first use."
        );
        // Tracing goes to the log file unless RUST_LOG is set, and the caller
        // only surfaces "SSH connect failed". Without this the operator of an
        // unattended run gets no fingerprint and no way to act on it.
        eprintln!(
            "The authenticity of host '{host}:{port}' can't be established, and \
             there is no terminal to confirm it on.\n  \
             {} key fingerprint is {fingerprint}\n\
             Add it to ~/.ssh/known_hosts, or pass \
             --ssh-host-key-verification=accept-new to trust it on first use.",
            server_public_key.algorithm().as_str(),
        );
        return false;
    }

    let prompt = format!(
        "The authenticity of host '{host}:{port}' can't be established.\n  \
         {} key fingerprint is {fingerprint}\n\
         Verify this fingerprint out of band before accepting. Continue connecting?",
        server_public_key.algorithm().as_str(),
    );

    // Default to no, and treat a read error or Ctrl-C the same way.
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap_or(false)
}

/// Record a newly trusted key so later connections are pinned to it.
///
/// A failure here is not fatal — the connection is already trusted — but it
/// does mean the next connection is another unauthenticated first contact.
fn record_host_key(
    host: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts: Option<&std::path::Path>,
) {
    let learned = match known_hosts {
        Some(path) => {
            russh::keys::known_hosts::learn_known_hosts_path(host, port, server_public_key, path)
        }
        None => russh::keys::known_hosts::learn_known_hosts(host, port, server_public_key),
    };
    if let Err(e) = learned {
        warn!(host = %host, %e, "failed to record host key in known_hosts");
    }
}

/// Decide whether to trust a server's host key.
///
/// Split out from the `Handler` callback so the decision — the root of trust for
/// the entire tunnel — can be tested directly against a scratch `known_hosts`
/// file. `known_hosts` overrides the standard `~/.ssh/known_hosts` location and
/// is only ever `Some` in tests, as is a `confirm` other than
/// [`prompt_to_trust_host_key`].
///
/// Blocking: `confirm` waits on the user under [`HostKeyPolicy::Ask`], so call
/// this off the async runtime.
fn verify_host_key(
    policy: HostKeyPolicy,
    host: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts: Option<&std::path::Path>,
    confirm: ConfirmHostKey,
) -> bool {
    if policy == HostKeyPolicy::AcceptAll {
        warn!(
            host = %host,
            "accepting SSH host key without verification (--ssh-host-key-verification=accept-all); \
             this connection is not protected against impersonation"
        );
        return true;
    }

    // Returns Ok(false) when the host is absent, and Err(KeyChanged) when a
    // different key is already recorded for it.
    let lookup = match known_hosts {
        Some(path) => russh::keys::check_known_hosts_path(host, port, server_public_key, path),
        None => russh::keys::check_known_hosts(host, port, server_public_key),
    };

    let known = match lookup {
        Ok(known) => known,
        Err(russh::keys::Error::KeyChanged { line }) => {
            error!(
                host = %host,
                line,
                fingerprint = %server_public_key.fingerprint(Default::default()),
                "SSH HOST KEY CHANGED — refusing to connect. This is what an \
                 impersonated server looks like. If the host was legitimately \
                 rekeyed, remove the offending line from ~/.ssh/known_hosts."
            );
            return false;
        }
        Err(e) => {
            error!(host = %host, %e, "failed to read known_hosts");
            return false;
        }
    };

    if known {
        debug!(host = %host, "SSH host key matches known_hosts");
        return true;
    }

    match policy {
        HostKeyPolicy::Ask => {
            if !confirm(host, port, server_public_key) {
                error!(
                    host = %host,
                    fingerprint = %server_public_key.fingerprint(Default::default()),
                    "unknown SSH host key was not confirmed — refusing to connect"
                );
                return false;
            }
            warn!(
                host = %host,
                fingerprint = %server_public_key.fingerprint(Default::default()),
                "unknown SSH host key confirmed by the user, recording it"
            );
            record_host_key(host, port, server_public_key, known_hosts);
            true
        }
        HostKeyPolicy::Strict => {
            error!(
                host = %host,
                fingerprint = %server_public_key.fingerprint(Default::default()),
                "unknown SSH host key and policy is strict — refusing to connect. \
                 Verify the fingerprint out of band and add it to ~/.ssh/known_hosts, \
                 or re-run with --ssh-host-key-verification=accept-new to trust it now."
            );
            false
        }
        HostKeyPolicy::AcceptNew => {
            warn!(
                host = %host,
                fingerprint = %server_public_key.fingerprint(Default::default()),
                "unknown SSH host key, trusting it on first use and recording it"
            );
            record_host_key(host, port, server_public_key, known_hosts);
            true
        }
        // Handled above.
        HostKeyPolicy::AcceptAll => true,
    }
}

/// Read stdout from an exec'd channel line-by-line until `predicate` returns
/// true, or the command exits, or the deadline passes.
async fn read_lines_from_channel(
    channel: &mut russh::Channel<client::Msg>,
    timeout: Duration,
    mut predicate: impl FnMut(&str) -> bool,
) -> Result<Vec<String>> {
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
                        let line = buffer
                            .get(..newline_pos)
                            .unwrap_or_default()
                            .trim_end()
                            .to_string();
                        // Drain the consumed line from the buffer without
                        // reallocating: shift bytes left and truncate.
                        buffer.drain(..newline_pos.saturating_add(1));
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
            host: ssh_config.hostname.clone(),
            port: ssh_config.port,
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

        // Try the SSH agent first, matching OpenSSH. Without this, a
        // passphrase-protected key fails to load and the user is silently
        // dropped to a password prompt — which hands their account password to
        // whatever server answered.
        if self.authenticate_with_agent(&user).await? {
            return Ok(());
        }

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

        // If no keys worked, fall back to an interactive password prompt.
        //
        // The password is only as safe as the server's identity, so make the
        // fallback visible rather than silent: the host key has been verified
        // by this point unless the user explicitly chose accept-all.
        warn!(
            user = %user,
            host = %self.config.hostname,
            "no SSH key was accepted; falling back to password authentication"
        );
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

    /// Try every identity held by the SSH agent, if one is reachable.
    ///
    /// Returns `Ok(true)` when authentication succeeded.
    async fn authenticate_with_agent(&mut self, user: &str) -> Result<bool> {
        // The agent transport is platform-specific: a Unix socket named by
        // SSH_AUTH_SOCK, or on Windows either the OpenSSH named pipe or Pageant.
        #[cfg(unix)]
        {
            match russh::keys::agent::client::AgentClient::connect_env().await {
                Ok(agent) => self.try_agent_identities(user, agent).await,
                Err(e) => {
                    debug!(%e, "no SSH agent available");
                    Ok(false)
                }
            }
        }

        #[cfg(windows)]
        {
            // OpenSSH for Windows first, then Pageant.
            const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
            match russh::keys::agent::client::AgentClient::connect_named_pipe(OPENSSH_PIPE).await {
                Ok(agent) => {
                    if self.try_agent_identities(user, agent).await? {
                        return Ok(true);
                    }
                }
                Err(e) => debug!(%e, "no OpenSSH agent named pipe"),
            }

            match russh::keys::agent::client::AgentClient::connect_pageant().await {
                Ok(agent) => self.try_agent_identities(user, agent).await,
                Err(e) => {
                    debug!(%e, "no Pageant agent available");
                    Ok(false)
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = user;
            Ok(false)
        }
    }

    /// Try every identity an already-connected agent holds.
    async fn try_agent_identities<S>(
        &mut self,
        user: &str,
        mut agent: russh::keys::agent::client::AgentClient<S>,
    ) -> Result<bool>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let identities = match agent.request_identities().await {
            Ok(identities) => identities,
            Err(e) => {
                debug!(%e, "could not list SSH agent identities");
                return Ok(false);
            }
        };

        debug!(count = identities.len(), "trying SSH agent identities");

        for identity in identities {
            // russh 0.62 reports agent identities as an enum rather than a bare
            // public key, so a certificate keeps its CA signature and principals
            // instead of being flattened to the key inside it. Authenticating
            // with the flattened key would fail against a server that only
            // trusts the CA, so each variant takes its own call.
            let fingerprint = identity.public_key().fingerprint(Default::default());
            let attempt = match &identity {
                russh::keys::agent::AgentIdentity::PublicKey { key, .. } => {
                    self.handle
                        .authenticate_publickey_with(user, key.clone(), None, &mut agent)
                        .await
                }
                russh::keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                    self.handle
                        .authenticate_certificate_with(user, certificate.clone(), None, &mut agent)
                        .await
                }
            };

            match attempt {
                Ok(result) if result.success() => {
                    info!(
                        user = %user,
                        %fingerprint,
                        comment = %identity.comment(),
                        "SSH agent authentication successful"
                    );
                    return Ok(true);
                }
                Ok(_) => debug!(%fingerprint, "agent key not accepted, trying next"),
                Err(e) => debug!(%e, %fingerprint, "agent auth attempt failed, trying next"),
            }
        }

        Ok(false)
    }

    /// Execute a command, optionally writing `stdin_data` to its stdin, and
    /// read stdout line-by-line until `predicate` returns true.
    ///
    /// `stdin_data` is written before reading begins, so it must be small
    /// enough to fit in the SSH channel's initial window (it carries the
    /// session config, roughly a kilobyte).
    pub async fn exec_and_read_lines(
        &self,
        command: &str,
        stdin_data: Option<&[u8]>,
        timeout: Duration,
        predicate: impl FnMut(&str) -> bool,
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

        if let Some(data) = stdin_data {
            channel
                .data(data)
                .await
                .map_err(|e| Error::Protocol(format!("failed to write stdin: {e}")))?;
            channel
                .eof()
                .await
                .map_err(|e| Error::Protocol(format!("failed to send stdin EOF: {e}")))?;
        }

        read_lines_from_channel(&mut channel, timeout, predicate).await
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

    // (line reading lives in `read_lines_from_channel` below so that both the
    // stdin and no-stdin paths share it)

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
            host: ssh_config.hostname.clone(),
            port: ssh_config.port,
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
            host: first_config.hostname.clone(),
            port: first_config.port,
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
        assert_eq!(HostKeyPolicy::Ask.to_string(), "ask");
        assert_eq!(HostKeyPolicy::Strict.to_string(), "strict");
        assert_eq!(HostKeyPolicy::AcceptNew.to_string(), "accept-new");
        assert_eq!(HostKeyPolicy::AcceptAll.to_string(), "accept-all");
    }

    /// `default_value_t` renders the default through `Display` and then parses
    /// it back with the `ValueEnum` parser, so a `Display` string that is not
    /// also a valid value makes the CLI panic on startup.
    #[test]
    fn display_round_trips_through_the_value_parser() {
        use clap::ValueEnum;

        for policy in HostKeyPolicy::value_variants() {
            let rendered = policy.to_string();
            let parsed = HostKeyPolicy::from_str(&rendered, true)
                .unwrap_or_else(|_| panic!("'{rendered}' must parse back to a policy"));
            assert_eq!(*policy, parsed);
        }
    }

    #[test]
    fn test_host_key_policy_value_enum() {
        // Test that all variants are available for clap parsing.
        // This is validated by the ValueEnum derive, but we ensure it compiles.
        let _variants: &[HostKeyPolicy] = &[
            HostKeyPolicy::Ask,
            HostKeyPolicy::Strict,
            HostKeyPolicy::AcceptNew,
            HostKeyPolicy::AcceptAll,
        ];
    }

    #[test]
    fn test_host_key_policy_equality() {
        assert_eq!(HostKeyPolicy::Ask, HostKeyPolicy::Ask);
        assert_eq!(HostKeyPolicy::Strict, HostKeyPolicy::Strict);
        assert_eq!(HostKeyPolicy::AcceptNew, HostKeyPolicy::AcceptNew);
        assert_eq!(HostKeyPolicy::AcceptAll, HostKeyPolicy::AcceptAll);

        assert_ne!(HostKeyPolicy::Ask, HostKeyPolicy::Strict);
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

    // -----------------------------------------------------------------------
    // Host key verification regression tests
    // -----------------------------------------------------------------------
    //
    // Guards the SSH host key check, which is the root of trust for the whole
    // tunnel: SSH is the channel over which the two ends exchange the
    // certificates they pin. A previous version stubbed `check_server_key` to
    // return `Ok(true)` for every policy — including `Strict` — so every
    // assertion below that expects a rejection would have failed.

    /// Two distinct, fixed host keys. Using literals keeps the tests
    /// deterministic and free of key-generation dependencies.
    ///
    /// Deliberately written without a trailing comment: `PublicKey`'s `PartialEq`
    /// includes the comment field, and a key read back out of `known_hosts` has
    /// none — as does a key presented by a real server over the wire.
    const HOST_KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKI1DBqYeZFK3W3cVfPeGy1spReDdhIWDVURrciWO4Y5";
    const HOST_KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY2SrpMf7mxwUBWqNxdwdp7g54DifINJagAl6cHIo7s";

    fn host_key(openssh: &str) -> PublicKey {
        openssh.parse().expect("valid openssh public key")
    }

    /// Every policy other than `ask` — and `ask` itself for a key that is
    /// already known or has changed — must decide without consulting the user.
    /// Wiring this in turns an unexpected prompt into a test failure rather
    /// than a CI job hanging on input nobody will type.
    const NEVER_ASKED: ConfirmHostKey =
        |_, _, _| panic!("this policy must not ask the user to confirm a host key");

    /// A user who answers yes.
    const CONFIRMED: ConfirmHostKey = |_, _, _| true;

    /// A user who answers no, which is also what a read error and Ctrl-C
    /// collapse to in the real prompt.
    const DECLINED: ConfirmHostKey = |_, _, _| false;

    /// A scratch known_hosts path that is removed when the test ends.
    struct ScratchKnownHosts(std::path::PathBuf);

    impl ScratchKnownHosts {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "plk-known-hosts-{name}-{}",
                common::generate_token().expect("token")
            ));
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }

        fn record(&self, host: &str, port: u16, key: &PublicKey) {
            russh::keys::known_hosts::learn_known_hosts_path(host, port, key, &self.0)
                .expect("failed to seed known_hosts");
        }

        fn contents(&self) -> String {
            std::fs::read_to_string(&self.0).unwrap_or_default()
        }
    }

    impl Drop for ScratchKnownHosts {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).ok();
        }
    }

    #[test]
    fn strict_rejects_unknown_host_key() {
        let known = ScratchKnownHosts::new("unknown");
        assert!(
            !verify_host_key(
                HostKeyPolicy::Strict,
                "example.com",
                22,
                &host_key(HOST_KEY_A),
                Some(known.path()),
                NEVER_ASKED,
            ),
            "strict must refuse a host it has never seen"
        );
    }

    #[test]
    fn strict_accepts_recorded_host_key() {
        let known = ScratchKnownHosts::new("recorded");
        let key = host_key(HOST_KEY_A);
        known.record("example.com", 22, &key);

        assert!(
            verify_host_key(
                HostKeyPolicy::Strict,
                "example.com",
                22,
                &key,
                Some(known.path()),
                NEVER_ASKED,
            ),
            "strict must accept the key recorded in known_hosts"
        );
    }

    /// The impersonation case: a different key for a host we already know.
    #[test]
    fn strict_rejects_changed_host_key() {
        let known = ScratchKnownHosts::new("changed-strict");
        known.record("example.com", 22, &host_key(HOST_KEY_A));

        assert!(
            !verify_host_key(
                HostKeyPolicy::Strict,
                "example.com",
                22,
                &host_key(HOST_KEY_B),
                Some(known.path()),
                NEVER_ASKED,
            ),
            "a changed host key must be refused"
        );
    }

    /// accept-new is trust-on-first-use, not trust-always: a *changed* key must
    /// still be refused, otherwise the policy offers no protection at all.
    #[test]
    fn accept_new_rejects_changed_host_key() {
        let known = ScratchKnownHosts::new("changed-accept-new");
        known.record("example.com", 22, &host_key(HOST_KEY_A));

        assert!(
            !verify_host_key(
                HostKeyPolicy::AcceptNew,
                "example.com",
                22,
                &host_key(HOST_KEY_B),
                Some(known.path()),
                NEVER_ASKED,
            ),
            "accept-new must still refuse a changed host key"
        );
    }

    #[test]
    fn accept_new_learns_and_then_pins_unknown_host_key() {
        let known = ScratchKnownHosts::new("learn");
        let key = host_key(HOST_KEY_A);

        assert!(
            verify_host_key(
                HostKeyPolicy::AcceptNew,
                "example.com",
                22,
                &key,
                Some(known.path()),
                NEVER_ASKED,
            ),
            "accept-new should trust an unknown key on first use"
        );

        // It must be *recorded*, or every later connection is another first
        // use and the trust never actually pins to anything.
        assert!(
            known.contents().contains("example.com"),
            "accept-new must record the key it trusted: {:?}",
            known.contents()
        );

        // And now a different key for that host is refused.
        assert!(
            !verify_host_key(
                HostKeyPolicy::AcceptNew,
                "example.com",
                22,
                &host_key(HOST_KEY_B),
                Some(known.path()),
                NEVER_ASKED,
            ),
            "once learned, a different key must be refused"
        );
    }

    #[test]
    fn non_default_ports_are_tracked_separately() {
        let known = ScratchKnownHosts::new("ports");
        let key = host_key(HOST_KEY_A);
        known.record("example.com", 2222, &key);

        assert!(
            verify_host_key(
                HostKeyPolicy::Strict,
                "example.com",
                2222,
                &key,
                Some(known.path()),
                NEVER_ASKED,
            ),
            "the key recorded for port 2222 should match"
        );
        assert!(
            !verify_host_key(
                HostKeyPolicy::Strict,
                "example.com",
                22,
                &key,
                Some(known.path()),
                NEVER_ASKED,
            ),
            "a key recorded for port 2222 must not authorise port 22"
        );
    }

    // -----------------------------------------------------------------------
    // ask (the default): confirm an unknown key with the user
    // -----------------------------------------------------------------------

    /// Saying yes has to *pin* the key, not just wave this one connection
    /// through — otherwise every later connection is another first contact and
    /// the user is asked to re-approve a key nothing ever compared against.
    #[test]
    fn ask_records_the_key_the_user_confirmed() {
        let known = ScratchKnownHosts::new("ask-confirmed");
        let key = host_key(HOST_KEY_A);

        assert!(
            verify_host_key(
                HostKeyPolicy::Ask,
                "example.com",
                22,
                &key,
                Some(known.path()),
                CONFIRMED,
            ),
            "ask should trust a key the user confirms"
        );
        assert!(
            known.contents().contains("example.com"),
            "ask must record the confirmed key: {:?}",
            known.contents()
        );

        // Pinned now, so the next connection must not ask again.
        assert!(verify_host_key(
            HostKeyPolicy::Ask,
            "example.com",
            22,
            &key,
            Some(known.path()),
            NEVER_ASKED,
        ));
    }

    /// Declining must leave no trace. Recording a key the user refused would
    /// silently trust it on the next connection.
    #[test]
    fn ask_rejects_and_records_nothing_when_the_user_declines() {
        let known = ScratchKnownHosts::new("ask-declined");

        assert!(
            !verify_host_key(
                HostKeyPolicy::Ask,
                "example.com",
                22,
                &host_key(HOST_KEY_A),
                Some(known.path()),
                DECLINED,
            ),
            "ask must refuse a key the user declines"
        );
        assert!(
            !known.contents().contains("example.com"),
            "a declined key must not be recorded: {:?}",
            known.contents()
        );
    }

    /// A changed key is the impersonation case, not a first contact: `ask` must
    /// refuse it outright rather than offer the user a prompt that would
    /// overwrite the pin. `NEVER_ASKED` panics if the prompt is reached.
    #[test]
    fn ask_refuses_a_changed_host_key_without_asking() {
        let known = ScratchKnownHosts::new("ask-changed");
        known.record("example.com", 22, &host_key(HOST_KEY_A));

        assert!(
            !verify_host_key(
                HostKeyPolicy::Ask,
                "example.com",
                22,
                &host_key(HOST_KEY_B),
                Some(known.path()),
                NEVER_ASKED,
            ),
            "ask must refuse a changed host key without prompting"
        );
    }

    /// accept-all is the documented escape hatch for disposable fixtures. It is
    /// deliberately permissive; this pins that it is the *only* permissive one.
    #[test]
    fn accept_all_is_the_only_policy_that_skips_verification() {
        let known = ScratchKnownHosts::new("accept-all");
        known.record("example.com", 22, &host_key(HOST_KEY_A));
        let impostor = host_key(HOST_KEY_B);

        assert!(verify_host_key(
            HostKeyPolicy::AcceptAll,
            "example.com",
            22,
            &impostor,
            Some(known.path()),
            NEVER_ASKED,
        ));

        // `ask` is included deliberately: a changed key is refused before the
        // user is ever consulted, so even an always-yes user cannot reach it.
        for policy in [
            HostKeyPolicy::Ask,
            HostKeyPolicy::Strict,
            HostKeyPolicy::AcceptNew,
        ] {
            assert!(
                !verify_host_key(
                    policy,
                    "example.com",
                    22,
                    &impostor,
                    Some(known.path()),
                    CONFIRMED,
                ),
                "{policy} must not accept an impostor's key"
            );
        }
    }
}
