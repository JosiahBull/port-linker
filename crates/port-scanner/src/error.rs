use std::fmt;

/// Errors that can occur during port scanning.
#[derive(Debug)]
pub enum ScanError {
    /// Failed to read procfs entries.
    ProcfsRead(String),
    /// Failed to run ss/netstat subprocess.
    CommandFailed(String),
    /// Failed to parse scan output.
    ParseError(String),
    /// No suitable scanner found for the platform.
    NoScanner,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcfsRead(msg) => write!(f, "procfs read error: {}", msg),
            Self::CommandFailed(msg) => write!(f, "command failed: {}", msg),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::NoScanner => write!(f, "no suitable port scanner available"),
        }
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_procfs_read() {
        let err = ScanError::ProcfsRead("permission denied".to_string());
        assert_eq!(format!("{}", err), "procfs read error: permission denied");
    }

    #[test]
    fn test_display_command_failed() {
        let err = ScanError::CommandFailed("ss not found".to_string());
        assert_eq!(format!("{}", err), "command failed: ss not found");
    }

    #[test]
    fn test_display_parse_error() {
        let err = ScanError::ParseError("bad format".to_string());
        assert_eq!(format!("{}", err), "parse error: bad format");
    }

    #[test]
    fn test_display_no_scanner() {
        let err = ScanError::NoScanner;
        assert_eq!(format!("{}", err), "no suitable port scanner available");
    }

    #[test]
    fn test_error_trait() {
        let err: Box<dyn std::error::Error> =
            Box::new(ScanError::NoScanner);
        assert_eq!(
            format!("{}", err),
            "no suitable port scanner available"
        );
    }
}
