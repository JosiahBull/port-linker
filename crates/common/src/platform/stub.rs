//! Stub implementations for unsupported platforms.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::warn;

use super::{Listener, ScanError};

/// Stub scanner that returns an empty set on unsupported platforms.
pub struct StubScanner {
    warned: AtomicBool,
}

impl Default for StubScanner {
    fn default() -> Self {
        Self {
            warned: AtomicBool::new(false),
        }
    }
}

impl StubScanner {
    pub fn new() -> Self {
        Self::default()
    }
}

impl super::PortScanner for StubScanner {
    fn scan(&self) -> Result<HashSet<Listener>, ScanError> {
        if !self.warned.swap(true, Ordering::Relaxed) {
            warn!(
                "port scanning is not supported on this platform; \
                 returning empty set"
            );
        }
        Ok(HashSet::new())
    }
}

/// Stub notifier that silently does nothing.
pub struct StubNotifier;

impl Default for StubNotifier {
    fn default() -> Self {
        Self
    }
}

impl super::Notifier for StubNotifier {
    fn show(
        &self,
        _title: &str,
        _body: &str,
        _is_error: bool,
        _with_sound: bool,
    ) -> Result<(), String> {
        Ok(())
    }
}
