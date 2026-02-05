use thiserror::Error;

/// Errors that can occur during notification operations.
#[derive(Error, Debug)]
pub enum NotifyError {
    #[error("Notification failed: {0}")]
    Notification(String),
}

pub type Result<T> = std::result::Result<T, NotifyError>;
