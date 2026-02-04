use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PortLinkerError {
    #[error("SSH connection failed: {0}")]
    SshConnection(String),

    #[error("SSH authentication failed: {0}")]
    SshAuth(String),

    #[error("SSH channel error: {0}")]
    SshChannel(String),

    #[error("Failed to parse remote host: {0}")]
    HostParse(String),

    #[error("Port scanning failed: {0}")]
    PortScan(String),

    #[error("Port forwarding failed for port {port}: {message}")]
    PortForward { port: u16, message: String },

    #[error("Local port {0} is already in use")]
    PortInUse(u16),

    #[error("Process detection failed: {0}")]
    ProcessDetection(String),

    #[error("Failed to kill process: {0}")]
    ProcessKill(String),

    #[error("Notification failed: {0}")]
    Notification(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSH key error: {0}")]
    SshKey(String),
}

pub type Result<T> = std::result::Result<T, PortLinkerError>;
