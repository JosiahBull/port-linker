use thiserror::Error;

#[derive(Error, Debug)]
pub enum PortLinkerError {
    #[error("SSH error: {0}")]
    Ssh(#[from] ssh::SshError),

    #[error("Forwarding error: {0}")]
    Forward(#[from] forward::ForwardError),

    #[error("Notification error: {0}")]
    Notify(#[from] notify::NotifyError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PortLinkerError>;
