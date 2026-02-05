use thiserror::Error;

#[derive(Error, Debug)]
pub enum PortLinkerError {
    #[error("SSH error: {0}")]
    Ssh(#[from] port_linker_ssh::SshError),

    #[error("Forwarding error: {0}")]
    Forward(#[from] port_linker_forward::ForwardError),

    #[error("Notification error: {0}")]
    Notify(#[from] port_linker_notify::NotifyError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PortLinkerError>;
