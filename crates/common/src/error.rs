use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("QUIC connection error: {0}")]
    QuicConnection(String),

    #[error("QUIC stream error: {0}")]
    QuicStream(String),

    #[error("codec error: {0}")]
    Codec(String),

    /// A security guarantee could not be established or was violated:
    /// certificate pinning, session authentication, host key verification, or
    /// binary integrity.
    #[error("security error: {0}")]
    Security(String),
}
