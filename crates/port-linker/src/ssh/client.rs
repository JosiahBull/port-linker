use crate::cli::ParsedHost;
use crate::error::{PortLinkerError, Result};
use crate::ssh::handler::ClientHandler;
use dialoguer::Password;
use russh::client::{self, Handle};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{load_secret_key, PrivateKey};
use ssh2_config_rs::{ParseRule, SshConfig};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub struct SshClient {
    handle: Arc<Handle<ClientHandler>>,
    config: SshClientConfig,
}

#[derive(Clone)]
pub struct SshClientConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<PathBuf>,
}

impl SshClient {
    pub async fn connect(
        parsed_host: &ParsedHost,
        ssh_port: u16,
        identity_file: Option<PathBuf>,
    ) -> Result<Self> {
        let ssh_config = load_ssh_config(&parsed_host.host);

        let host = ssh_config
            .as_ref()
            .and_then(|c| c.host_name.clone())
            .unwrap_or_else(|| parsed_host.host.clone());

        let port = ssh_config.as_ref().and_then(|c| c.port).unwrap_or(ssh_port);

        let user = parsed_host
            .user
            .clone()
            .or_else(|| ssh_config.as_ref().and_then(|c| c.user.clone()))
            .unwrap_or_else(|| whoami::username().unwrap_or_else(|_| "root".to_string()));

        let identity_files = get_identity_files(identity_file, &ssh_config);

        let config = SshClientConfig {
            host: host.clone(),
            port,
            user: user.clone(),
            identity_file: identity_files.first().cloned(),
        };

        info!("Connecting to {}@{}:{}", user, host, port);

        let handle = Arc::new(Self::establish_connection(&config, &identity_files).await?);

        Ok(Self { handle, config })
    }

    async fn establish_connection(
        config: &SshClientConfig,
        identity_files: &[PathBuf],
    ) -> Result<Handle<ClientHandler>> {
        let addr = format!("{}:{}", config.host, config.port)
            .to_socket_addrs()
            .map_err(|e| PortLinkerError::SshConnection(format!("Failed to resolve host: {}", e)))?
            .next()
            .ok_or_else(|| {
                PortLinkerError::SshConnection("Could not resolve host address".to_string())
            })?;

        let russh_config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(30)),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            ..Default::default()
        });

        let handler = ClientHandler::new();

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| PortLinkerError::SshConnection(format!("TCP connection failed: {}", e)))?;

        let mut handle = client::connect_stream(russh_config, stream, handler)
            .await
            .map_err(|e| PortLinkerError::SshConnection(e.to_string()))?;

        // Try SSH agent first
        if let Ok(authenticated) = try_agent_auth(&mut handle, &config.user).await {
            if authenticated {
                info!("Authenticated via SSH agent");
                return Ok(handle);
            }
        }

        // Try identity files
        for identity_path in identity_files {
            if identity_path.exists() {
                debug!("Trying identity file: {:?}", identity_path);
                match try_key_auth(&mut handle, &config.user, identity_path).await {
                    Ok(true) => {
                        info!("Authenticated via key: {:?}", identity_path);
                        return Ok(handle);
                    }
                    Ok(false) => {
                        debug!("Key auth failed for {:?}", identity_path);
                    }
                    Err(e) => {
                        debug!("Key auth error for {:?}: {}", identity_path, e);
                    }
                }
            }
        }

        // Fall back to password auth
        warn!("Key authentication failed, falling back to password");
        let password: String = Password::new()
            .with_prompt(format!("Password for {}@{}", config.user, config.host))
            .interact()
            .map_err(|e| PortLinkerError::SshAuth(format!("Password input failed: {}", e)))?;

        let auth_result = handle
            .authenticate_password(&config.user, &password)
            .await
            .map_err(|e| PortLinkerError::SshAuth(e.to_string()))?;

        if auth_result.success() {
            info!("Authenticated via password");
            Ok(handle)
        } else {
            Err(PortLinkerError::SshAuth(
                "Password authentication failed".to_string(),
            ))
        }
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        let identity_files = self
            .config
            .identity_file
            .clone()
            .map(|f| vec![f])
            .unwrap_or_else(get_default_identity_files);

        self.handle = Arc::new(Self::establish_connection(&self.config, &identity_files).await?);
        Ok(())
    }

    pub fn handle(&self) -> Arc<Handle<ClientHandler>> {
        self.handle.clone()
    }

    pub async fn exec(&self, command: &str) -> Result<String> {
        let mut channel =
            self.handle.channel_open_session().await.map_err(|e| {
                PortLinkerError::SshChannel(format!("Failed to open channel: {}", e))
            })?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| PortLinkerError::SshChannel(format!("Failed to exec command: {}", e)))?;

        let mut output = Vec::new();

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    output.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                    output.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                    break;
                }
                _ => {}
            }
        }

        String::from_utf8(output)
            .map_err(|e| PortLinkerError::SshChannel(format!("Invalid UTF-8 in output: {}", e)))
    }

    #[allow(dead_code)]
    pub async fn open_direct_tcpip(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<russh::Channel<russh::client::Msg>> {
        self.handle
            .channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| PortLinkerError::PortForward {
                port: remote_port,
                message: format!("Failed to open direct-tcpip channel: {}", e),
            })
    }

    pub async fn is_connected(&self) -> bool {
        // Try to open a session channel as a health check
        self.handle.channel_open_session().await.is_ok()
    }

    /// Write bytes to a file on the remote host.
    ///
    /// Uses base64 encoding to safely transfer binary data through the shell.
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        use std::io::Write;

        // Base64 encode the data
        let mut encoded = Vec::new();
        {
            let mut encoder = base64::write::EncoderWriter::new(
                &mut encoded,
                &base64::engine::general_purpose::STANDARD,
            );
            encoder.write_all(data).map_err(|e| {
                PortLinkerError::SshChannel(format!("Failed to encode data: {}", e))
            })?;
        }
        let encoded_str = String::from_utf8(encoded).map_err(|e| {
            PortLinkerError::SshChannel(format!("Invalid UTF-8 in encoded data: {}", e))
        })?;

        // Write in chunks to avoid shell command line limits
        // Most shells have a limit around 128KB-1MB, we'll use 64KB chunks to be safe
        const CHUNK_SIZE: usize = 65536;

        // First chunk creates the file
        let first_chunk = if encoded_str.len() > CHUNK_SIZE {
            &encoded_str[..CHUNK_SIZE]
        } else {
            &encoded_str
        };

        let cmd = format!("echo -n '{}' | base64 -d > {}", first_chunk, path);
        self.exec(&cmd).await?;

        // Subsequent chunks append
        let mut offset = CHUNK_SIZE;
        while offset < encoded_str.len() {
            let end = (offset + CHUNK_SIZE).min(encoded_str.len());
            let chunk = &encoded_str[offset..end];
            let cmd = format!("echo -n '{}' | base64 -d >> {}", chunk, path);
            self.exec(&cmd).await?;
            offset = end;
        }

        Ok(())
    }

    /// Execute a command and return the channel for streaming I/O.
    ///
    /// This is used for long-running processes like the UDP proxy where we need
    /// to send and receive data over the channel's stdin/stdout.
    pub async fn exec_channel(&self, command: &str) -> Result<russh::Channel<russh::client::Msg>> {
        let channel =
            self.handle.channel_open_session().await.map_err(|e| {
                PortLinkerError::SshChannel(format!("Failed to open channel: {}", e))
            })?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| PortLinkerError::SshChannel(format!("Failed to exec command: {}", e)))?;

        Ok(channel)
    }
}

fn load_ssh_config(host: &str) -> Option<ssh2_config_rs::HostParams> {
    let config_path = dirs::home_dir()?.join(".ssh").join("config");

    if !config_path.exists() {
        return None;
    }

    let config_content = std::fs::read_to_string(&config_path).ok()?;
    let mut reader = std::io::Cursor::new(config_content);
    let config = SshConfig::default()
        .parse(&mut reader, ParseRule::STRICT)
        .ok()?;

    Some(config.query(host))
}

fn get_identity_files(
    explicit: Option<PathBuf>,
    ssh_config: &Option<ssh2_config_rs::HostParams>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Some(path) = explicit {
        files.push(path);
    }

    if let Some(config) = ssh_config {
        if let Some(ref identity_files) = config.identity_file {
            for identity_path in identity_files {
                let path_str = identity_path.to_string_lossy();
                let expanded = shellexpand::tilde(&path_str).to_string();
                files.push(PathBuf::from(expanded));
            }
        }
    }

    files.extend(get_default_identity_files());

    files
}

fn get_default_identity_files() -> Vec<PathBuf> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };

    let ssh_dir = home.join(".ssh");

    vec![
        ssh_dir.join("id_ed25519"),
        ssh_dir.join("id_rsa"),
        ssh_dir.join("id_ecdsa"),
        ssh_dir.join("id_dsa"),
    ]
}

#[cfg(unix)]
async fn try_agent_auth(handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
    let agent_sock = std::env::var("SSH_AUTH_SOCK").ok();

    if agent_sock.is_none() {
        return Ok(false);
    }

    let mut agent = russh::keys::agent::client::AgentClient::connect_env()
        .await
        .map_err(|e| PortLinkerError::SshAuth(format!("Failed to connect to agent: {}", e)))?;

    let identities = agent
        .request_identities()
        .await
        .map_err(|e| PortLinkerError::SshAuth(format!("Failed to get agent identities: {}", e)))?;

    for identity in identities {
        // Create a fresh agent connection for each auth attempt since AgentClient doesn't implement Clone
        let mut agent_for_auth = russh::keys::agent::client::AgentClient::connect_env()
            .await
            .map_err(|e| PortLinkerError::SshAuth(format!("Failed to connect to agent: {}", e)))?;

        let auth_result = handle
            .authenticate_publickey_with(user, identity, None, &mut agent_for_auth)
            .await;
        match auth_result {
            Ok(result) if result.success() => return Ok(true),
            _ => continue,
        }
    }

    Ok(false)
}

#[cfg(windows)]
async fn try_agent_auth(_handle: &mut Handle<ClientHandler>, _user: &str) -> Result<bool> {
    // SSH agent authentication via Unix socket is not supported on Windows
    Ok(false)
}

async fn try_key_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    key_path: &PathBuf,
) -> Result<bool> {
    let key = load_key_with_passphrase(key_path)?;
    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);

    let auth_result = handle
        .authenticate_publickey(user, key_with_alg)
        .await
        .map_err(|e| PortLinkerError::SshAuth(e.to_string()))?;

    Ok(auth_result.success())
}

fn load_key_with_passphrase(path: &PathBuf) -> Result<PrivateKey> {
    // First try without passphrase
    match load_secret_key(path, None) {
        Ok(key) => return Ok(key),
        Err(e) => {
            // Check if it's an encrypted key
            if !e.to_string().contains("encrypted")
                && !e.to_string().contains("passphrase")
                && !e.to_string().contains("decrypt")
            {
                return Err(PortLinkerError::SshKey(format!(
                    "Failed to load key {:?}: {}",
                    path, e
                )));
            }
        }
    }

    // Key is encrypted, prompt for passphrase
    let passphrase: String = Password::new()
        .with_prompt(format!("Passphrase for {:?}", path))
        .allow_empty_password(true)
        .interact()
        .map_err(|e| PortLinkerError::SshKey(format!("Passphrase input failed: {}", e)))?;

    load_secret_key(path, Some(&passphrase))
        .map_err(|e| PortLinkerError::SshKey(format!("Failed to load key {:?}: {}", path, e)))
}
