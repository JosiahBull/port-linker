//! Embedded, gzip-compressed relay binaries for all supported target platforms.
//!
//! This crate mirrors `agent-embed` but for the UDP relay binary.
//! At compile time, it cross-compiles and embeds gzip-compressed relay
//! binaries. At runtime, callers select the appropriate binary by OS and
//! architecture.

// ---------------------------------------------------------------------------
// Embedded binaries (gzip-compressed, produced by build.rs)
// ---------------------------------------------------------------------------

const RELAY_X86_64_LINUX_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/relay-x86_64-unknown-linux-musl.gz"
));

const RELAY_AARCH64_LINUX_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/relay-aarch64-unknown-linux-musl.gz"
));

const RELAY_AARCH64_DARWIN_GZ: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/relay-aarch64-apple-darwin.gz"));

/// All target triples that this crate can potentially embed.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
];

/// Return the gzip-compressed relay binary for the given OS and architecture.
///
/// Returns `None` if:
/// - The OS/arch combination is not supported
/// - The build for that target failed (empty placeholder)
///
/// The caller is responsible for decompressing the gzip data.
pub fn get_relay_binary_for_system(os: &str, arch: &str) -> Option<&'static [u8]> {
    let data = match (os.to_ascii_lowercase().as_str(), normalize_arch(arch)) {
        ("linux", "x86_64") => RELAY_X86_64_LINUX_GZ,
        ("linux", "aarch64") => RELAY_AARCH64_LINUX_GZ,
        ("macos" | "darwin", "aarch64") => RELAY_AARCH64_DARWIN_GZ,
        _ => return None,
    };

    if data.is_empty() { None } else { Some(data) }
}

/// Return the list of targets that have non-empty embedded binaries.
pub fn available_relay_targets() -> Vec<&'static str> {
    let mut targets = Vec::new();

    if !RELAY_X86_64_LINUX_GZ.is_empty() {
        targets.push("x86_64-unknown-linux-musl");
    }
    if !RELAY_AARCH64_LINUX_GZ.is_empty() {
        targets.push("aarch64-unknown-linux-musl");
    }
    if !RELAY_AARCH64_DARWIN_GZ.is_empty() {
        targets.push("aarch64-apple-darwin");
    }

    targets
}

/// Normalize architecture names to canonical form.
fn normalize_arch(arch: &str) -> &str {
    match arch.to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => arch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_os_returns_none() {
        assert!(get_relay_binary_for_system("freebsd", "aarch64").is_none());
    }

    #[test]
    fn unsupported_arch_returns_none() {
        assert!(get_relay_binary_for_system("linux", "riscv64").is_none());
    }

    #[test]
    fn supported_targets_is_complete() {
        assert_eq!(SUPPORTED_TARGETS.len(), 3);
    }

    #[test]
    fn available_targets_subset_of_supported() {
        for target in available_relay_targets() {
            assert!(
                SUPPORTED_TARGETS.contains(&target),
                "{target} not in SUPPORTED_TARGETS"
            );
        }
    }
}
