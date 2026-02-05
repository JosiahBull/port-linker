//! Embedded udp-proxy binaries for port-linker.
//!
//! This crate provides pre-compiled udp-proxy binaries for various target platforms.
//! The binaries are compiled during the build process and embedded into the library.
//!
//! # Usage
//!
//! ```rust,ignore
//! use port_linker_udp_embed::get_binary_for_system;
//!
//! // Get the binary for a Linux x86_64 system
//! if let Some(binary) = get_binary_for_system("linux", "x86_64") {
//!     // Deploy binary to remote system
//! }
//! ```
//!
//! # Supported Targets
//!
//! - `x86_64-unknown-linux-musl` (Linux x86_64, static binary)
//! - `aarch64-unknown-linux-musl` (Linux ARM64, static binary)
//! - `aarch64-apple-darwin` (macOS ARM64/Apple Silicon)

/// Embedded udp-proxy binaries for different target architectures.
/// Build.rs creates empty placeholder files for targets that fail to compile,
/// so we can unconditionally include them and check length at runtime.
mod binaries {
    /// Linux x86_64 (musl static binary)
    pub static X86_64_LINUX_MUSL: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/udp-proxy-x86_64-unknown-linux-musl"
    ));

    /// Linux aarch64 (musl static binary)
    pub static AARCH64_LINUX_MUSL: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/udp-proxy-aarch64-unknown-linux-musl"
    ));

    /// macOS aarch64 (Apple Silicon)
    pub static AARCH64_DARWIN: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/udp-proxy-aarch64-apple-darwin"));
}

/// Information about a target platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// Operating system (e.g., "linux", "darwin")
    pub os: String,
    /// Architecture (e.g., "x86_64", "aarch64")
    pub arch: String,
}

impl TargetInfo {
    /// Create a new TargetInfo.
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
        }
    }
}

/// Get the udp-proxy binary for the given operating system and architecture.
///
/// # Arguments
///
/// * `os` - Operating system name (case-insensitive): "linux" or "darwin"
/// * `arch` - Architecture name (case-insensitive): "x86_64", "aarch64", or "arm64"
///
/// # Returns
///
/// Returns `Some(&[u8])` containing the binary if available for the target,
/// or `None` if the target is unsupported or the binary failed to compile.
///
/// # Example
///
/// ```rust
/// use port_linker_udp_embed::get_binary_for_system;
///
/// // Check if we have a binary for Linux x86_64
/// if let Some(binary) = get_binary_for_system("linux", "x86_64") {
///     println!("Binary size: {} bytes", binary.len());
/// }
/// ```
pub fn get_binary_for_system(os: &str, arch: &str) -> Option<&'static [u8]> {
    let os = os.to_lowercase();
    let arch = arch.to_lowercase();

    let binary = match (os.as_str(), arch.as_str()) {
        ("linux", "x86_64") => binaries::X86_64_LINUX_MUSL,
        ("linux", "aarch64") => binaries::AARCH64_LINUX_MUSL,
        ("darwin", "aarch64" | "arm64") => binaries::AARCH64_DARWIN,
        _ => return None,
    };

    // Empty files are placeholders for failed builds
    if binary.is_empty() {
        None
    } else {
        Some(binary)
    }
}

/// Get the udp-proxy binary for the given target info.
///
/// This is a convenience wrapper around [`get_binary_for_system`].
pub fn get_binary(target: &TargetInfo) -> Option<&'static [u8]> {
    get_binary_for_system(&target.os, &target.arch)
}

/// List all supported target platforms.
///
/// Returns a list of (os, arch) tuples for all platforms that this crate
/// can potentially provide binaries for.
pub fn supported_targets() -> &'static [(&'static str, &'static str)] {
    &[
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("darwin", "aarch64"),
    ]
}

/// List all available target platforms.
///
/// Returns a list of (os, arch) tuples for platforms where the binary
/// was successfully compiled and is available.
pub fn available_targets() -> Vec<(&'static str, &'static str)> {
    supported_targets()
        .iter()
        .filter(|(os, arch)| get_binary_for_system(os, arch).is_some())
        .copied()
        .collect()
}

/// Check if a binary is available for the given target.
pub fn is_target_available(os: &str, arch: &str) -> bool {
    get_binary_for_system(os, arch).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitivity() {
        // These should all work if the binary is available
        let lower = get_binary_for_system("linux", "x86_64");
        let upper = get_binary_for_system("LINUX", "X86_64");
        let mixed = get_binary_for_system("Linux", "X86_64");

        assert_eq!(lower.is_some(), upper.is_some());
        assert_eq!(lower.is_some(), mixed.is_some());
    }

    #[test]
    fn test_arm64_alias() {
        // arm64 should be treated the same as aarch64
        let aarch64 = get_binary_for_system("darwin", "aarch64");
        let arm64 = get_binary_for_system("darwin", "arm64");

        assert_eq!(aarch64.is_some(), arm64.is_some());
        if let (Some(a), Some(b)) = (aarch64, arm64) {
            assert_eq!(a.len(), b.len());
        }
    }
}
