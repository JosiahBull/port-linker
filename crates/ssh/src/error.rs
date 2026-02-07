use thiserror::Error;

/// Errors that can occur during SSH operations.
#[derive(Error, Debug)]
pub enum SshError {
    #[error("SSH connection failed: {0}")]
    Connection(String),

    #[error("SSH authentication failed: {0}")]
    Auth(String),

    #[error("SSH channel error: {0}")]
    Channel(String),

    #[error("SSH key error: {0}")]
    Key(String),

    #[error("Port scanning failed: {0}")]
    PortScan(String),

    #[error("Failed to kill process: {0}")]
    ProcessKill(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SshError>;
