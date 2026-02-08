use thiserror::Error;

/// Errors that can occur during transport operations.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Transport closed")]
    Closed,

    #[error("Transport negotiation failed: {0}")]
    Negotiation(String),

    #[error("Transport not supported: {0}")]
    Unsupported(String),

    #[error("Transport timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, TransportError>;
