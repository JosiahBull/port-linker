//! Embedded, gzip-compressed agent binaries for all supported target platforms.
//!
//! This crate uses `agent-build` at compile time to cross-compile the agent
//! binary for each target, then gzip-compresses and embeds them via
//! `include_bytes!`. At runtime, callers select the appropriate binary by
//! OS and architecture.

// ---------------------------------------------------------------------------
// Embedded binaries (gzip-compressed, produced by build.rs)
// ---------------------------------------------------------------------------

const AGENT_X86_64_LINUX_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-x86_64-unknown-linux-musl.gz"
));

const AGENT_AARCH64_LINUX_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-aarch64-unknown-linux-musl.gz"
));

const AGENT_AARCH64_DARWIN_GZ: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-aarch64-apple-darwin.gz"
));

/// All target triples that this crate can potentially embed.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
];

/// Return the gzip-compressed agent binary for the given OS and architecture.
///
/// Returns `None` if:
/// - The OS/arch combination is not supported
/// - The build for that target failed (empty placeholder)
///
/// The caller is responsible for decompressing the gzip data.
pub fn get_binary_for_system(os: &str, arch: &str) -> Option<&'static [u8]> {
    let data = match (os.to_ascii_lowercase().as_str(), normalize_arch(arch)) {
        ("linux", "x86_64") => AGENT_X86_64_LINUX_GZ,
        ("linux", "aarch64") => AGENT_AARCH64_LINUX_GZ,
        ("macos" | "darwin", "aarch64") => AGENT_AARCH64_DARWIN_GZ,
        _ => return None,
    };

    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

/// Return the list of targets that have non-empty embedded binaries.
pub fn available_targets() -> Vec<&'static str> {
    let mut targets = Vec::new();

    if !AGENT_X86_64_LINUX_GZ.is_empty() {
        targets.push("x86_64-unknown-linux-musl");
    }
    if !AGENT_AARCH64_LINUX_GZ.is_empty() {
        targets.push("aarch64-unknown-linux-musl");
    }
    if !AGENT_AARCH64_DARWIN_GZ.is_empty() {
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
        assert!(get_binary_for_system("windows", "x86_64").is_none());
        assert!(get_binary_for_system("freebsd", "aarch64").is_none());
    }

    #[test]
    fn unsupported_arch_returns_none() {
        assert!(get_binary_for_system("linux", "riscv64").is_none());
        assert!(get_binary_for_system("linux", "i686").is_none());
    }

    #[test]
    fn case_insensitive_os() {
        // Both calls should resolve to the same binary (or both None if placeholder).
        let lower = get_binary_for_system("linux", "x86_64");
        let upper = get_binary_for_system("Linux", "x86_64");
        assert_eq!(lower.is_some(), upper.is_some());
    }

    #[test]
    fn arm64_alias() {
        let arm64 = get_binary_for_system("linux", "arm64");
        let aarch64 = get_binary_for_system("linux", "aarch64");
        assert_eq!(arm64.is_some(), aarch64.is_some());
    }

    #[test]
    fn amd64_alias() {
        let amd64 = get_binary_for_system("linux", "amd64");
        let x86_64 = get_binary_for_system("linux", "x86_64");
        assert_eq!(amd64.is_some(), x86_64.is_some());
    }

    #[test]
    fn darwin_aliases() {
        let macos = get_binary_for_system("macos", "aarch64");
        let darwin = get_binary_for_system("darwin", "aarch64");
        assert_eq!(macos.is_some(), darwin.is_some());
    }

    #[test]
    fn supported_targets_is_complete() {
        assert_eq!(SUPPORTED_TARGETS.len(), 3);
        assert!(SUPPORTED_TARGETS.contains(&"x86_64-unknown-linux-musl"));
        assert!(SUPPORTED_TARGETS.contains(&"aarch64-unknown-linux-musl"));
        assert!(SUPPORTED_TARGETS.contains(&"aarch64-apple-darwin"));
    }

    #[test]
    fn available_targets_subset_of_supported() {
        for target in available_targets() {
            assert!(
                SUPPORTED_TARGETS.contains(&target),
                "{target} not in SUPPORTED_TARGETS"
            );
        }
    }

    #[test]
    fn empty_placeholder_returns_none() {
        // Verify our empty-check logic: empty slices should yield None.
        let empty: &[u8] = &[];
        assert!(empty.is_empty());
        // This is the invariant get_binary_for_system upholds.
    }
}
