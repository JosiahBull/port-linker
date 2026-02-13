// Re-export from the platform module.
pub use common::platform::{Listener, PortScanner, ScanError};

/// The default scanner for the current platform.
pub type DefaultScanner =
    <common::platform::CurrentPlatform as common::platform::Platform>::Scanner;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Parsing tests for /proc/net lines live in `common/src/platform/linux.rs`.
// Only the smoke test below (verifying the type alias resolves) lives here.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scanner_type_compiles() {
        // Verify that DefaultScanner resolves to a concrete type that
        // implements PortScanner. This is a compile-time check.
        fn _assert_scanner<T: PortScanner>() {}
        _assert_scanner::<DefaultScanner>();
    }
}
