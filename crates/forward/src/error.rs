use thiserror::Error;

/// Errors that can occur during forwarding operations.
#[derive(Error, Debug)]
pub enum ForwardError {
    #[error("Port forwarding failed for port {port}: {message}")]
    PortForward { port: u16, message: String },

    #[error("Local port {0} is already in use")]
    PortInUse(u16),

    #[error("SSH error: {0}")]
    Ssh(#[from] ssh::SshError),

    #[error("Unsupported remote platform: {os}/{arch} - no agent binary available")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ForwardError>;
