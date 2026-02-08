//! Cross-compilation build infrastructure for port-linker.
//!
//! This crate provides utilities for cross-compiling Rust binaries for multiple
//! target platforms, with support for:
//! - Nightly toolchain detection and `build-std` optimization
//! - Fallback to the `cross` tool for cross-compilation
//! - Optional UPX compression
//! - Graceful handling of build failures
//!
//! # Usage in build.rs
//!
//! ```rust,ignore
//! use agent_build::{BuildConfig, CrossTarget, build_for_targets};
//!
//! fn main() {
//!     let config = BuildConfig::new("agent")
//!         .target(CrossTarget::linux_x86_64())
//!         .target(CrossTarget::linux_aarch64())
//!         .target(CrossTarget::darwin_aarch64());
//!
//!     build_for_targets(&config);
//! }
//! ```

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A target platform for cross-compilation.
#[derive(Debug, Clone)]
pub struct CrossTarget {
    /// The Rust target triple (e.g., "x86_64-unknown-linux-musl")
    pub triple: String,
    /// Whether to try the `cross` tool if native cargo fails
    pub use_cross_fallback: bool,
    /// Custom cargo profile to use (e.g., "agent-release")
    pub custom_profile: Option<String>,
}

impl CrossTarget {
    /// Create a new cross-compilation target.
    pub fn new<S: Into<String>>(triple: S) -> Self {
        Self {
            triple: triple.into(),
            use_cross_fallback: false,
            custom_profile: None,
        }
    }

    /// Enable fallback to `cross` tool if native cargo fails.
    pub const fn with_cross_fallback(mut self) -> Self {
        self.use_cross_fallback = true;
        self
    }

    /// Set a custom cargo profile for release builds.
    pub fn with_custom_profile<S: Into<String>>(mut self, profile: S) -> Self {
        self.custom_profile = Some(profile.into());
        self
    }

    /// Linux x86_64 with musl (static binary).
    pub fn linux_x86_64() -> Self {
        Self::new("x86_64-unknown-linux-musl").with_cross_fallback()
    }

    /// Linux aarch64 with musl (static binary).
    pub fn linux_aarch64() -> Self {
        Self::new("aarch64-unknown-linux-musl").with_cross_fallback()
    }

    /// macOS aarch64 (Apple Silicon).
    pub fn darwin_aarch64() -> Self {
        Self::new("aarch64-apple-darwin")
    }
}

/// Build configuration for cross-compilation.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    /// The package name to build
    pub package: String,
    /// The workspace root directory
    pub workspace_root: PathBuf,
    /// The output directory for compiled binaries
    pub out_dir: PathBuf,
    /// Target platforms to build for
    pub targets: Vec<CrossTarget>,
    /// Whether to use UPX compression (requires upx in PATH)
    pub use_upx: bool,
    /// Whether this is a release build
    pub is_release: bool,
    /// Binary name (defaults to package name)
    pub binary_name: Option<String>,
    /// Cargo features to enable for the build
    pub features: Vec<String>,
    /// Extra RUSTFLAGS to pass to the cargo build
    pub rustflags: Vec<String>,
}

impl BuildConfig {
    /// Create a new build configuration for the given package.
    pub fn new<S: Into<String>>(package: S) -> Self {
        Self {
            package: package.into(),
            workspace_root: PathBuf::new(),
            out_dir: PathBuf::new(),
            targets: Vec::new(),
            use_upx: false,
            is_release: false,
            binary_name: None,
            features: Vec::new(),
            rustflags: Vec::new(),
        }
    }

    /// Set the workspace root directory.
    pub fn workspace_root<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.workspace_root = path.into();
        self
    }

    /// Set the output directory.
    pub fn out_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.out_dir = path.into();
        self
    }

    /// Add a target platform.
    pub fn target(mut self, target: CrossTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Enable UPX compression for release builds.
    pub const fn with_upx(mut self) -> Self {
        self.use_upx = true;
        self
    }

    /// Set whether this is a release build.
    pub const fn release(mut self, is_release: bool) -> Self {
        self.is_release = is_release;
        self
    }

    /// Set a custom binary name (defaults to package name).
    pub fn binary_name<S: Into<String>>(mut self, name: S) -> Self {
        self.binary_name = Some(name.into());
        self
    }

    /// Add a cargo feature to enable for the build.
    pub fn with_feature<S: Into<String>>(mut self, feature: S) -> Self {
        self.features.push(feature.into());
        self
    }

    /// Add an extra RUSTFLAG to pass to the cargo build.
    pub fn with_rustflag<S: Into<String>>(mut self, flag: S) -> Self {
        self.rustflags.push(flag.into());
        self
    }

    /// Create a configuration from environment variables.
    ///
    /// This reads `CARGO_MANIFEST_DIR`, `OUT_DIR`, and `PROFILE` from the environment.
    pub fn from_env<S: Into<String>>(package: S) -> Self {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let workspace_root = Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_default();

        let out_dir = env::var("OUT_DIR").unwrap_or_default();
        let is_release = env::var("PROFILE").map(|p| p == "release").unwrap_or(false);

        Self::new(package)
            .workspace_root(workspace_root)
            .out_dir(out_dir)
            .release(is_release)
    }
}

/// Result of building for a single target.
#[derive(Debug, Clone)]
pub enum BuildResult {
    /// Build succeeded.
    Success {
        /// Path to the compiled binary
        path: PathBuf,
        /// Size of the binary in bytes
        size: usize,
        /// Whether UPX compression was applied
        compressed: bool,
    },
    /// Build failed.
    Failed {
        /// Reason for failure
        reason: String,
    },
}

impl BuildResult {
    /// Check if the build was successful.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Get the path to the binary if successful.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Success { path, .. } => Some(path),
            Self::Failed { .. } => None,
        }
    }
}

/// Information about available toolchains and tools.
#[derive(Debug, Clone)]
pub struct ToolchainInfo {
    /// Whether nightly toolchain is available
    pub has_nightly: bool,
    /// Whether rust-src component is installed (required for build-std)
    pub has_rust_src: bool,
    /// Whether the `cross` tool is available
    pub has_cross: bool,
    /// Whether UPX is available
    pub has_upx: bool,
}

impl ToolchainInfo {
    /// Detect available toolchains and tools.
    pub fn detect() -> Self {
        Self {
            has_nightly: Self::check_nightly(),
            has_rust_src: Self::check_rust_src(),
            has_cross: Self::check_cross(),
            has_upx: Self::check_upx(),
        }
    }

    /// Check if build-std optimization can be used.
    pub const fn can_use_build_std(&self) -> bool {
        self.has_nightly && self.has_rust_src
    }

    fn check_nightly() -> bool {
        Command::new("rustup")
            .args(["run", "nightly", "rustc", "--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn check_rust_src() -> bool {
        Command::new("rustup")
            .args(["+nightly", "component", "list", "--installed"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.contains("rust-src"))
            })
            .unwrap_or(false)
    }

    fn check_cross() -> bool {
        Command::new("cross")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn check_upx() -> bool {
        Command::new("upx")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Build for all configured targets.
///
/// Returns a map of target triple to build result.
pub fn build_for_targets(config: &BuildConfig) -> HashMap<String, BuildResult> {
    let toolchain = ToolchainInfo::detect();
    let mut results = HashMap::new();

    // Use a separate target directory to avoid cargo lock conflicts
    let build_target_dir = config.workspace_root.join("target").join("cross-build");

    // Create placeholder files for all targets first
    // This ensures include_bytes! doesn't fail even if builds fail
    for target in &config.targets {
        let dest = config.out_dir.join(output_filename(&config.package, &target.triple));
        if !dest.exists() {
            drop(fs::write(&dest, b""));
        }
    }

    // Build each target
    for target in &config.targets {
        let result = build_single_target(config, target, &toolchain, &build_target_dir);
        results.insert(target.triple.clone(), result);
    }

    results
}

/// Generate the output filename for a target.
pub fn output_filename(package: &str, target: &str) -> String {
    format!("{}-{}", package, target)
}

/// Emit cargo rerun-if-changed directives for source directories.
pub fn watch_sources(paths: &[&str]) {
    for path in paths {
        println!("cargo:rerun-if-changed={}", path);
    }
}

fn build_single_target(
    config: &BuildConfig,
    target: &CrossTarget,
    toolchain: &ToolchainInfo,
    build_target_dir: &Path,
) -> BuildResult {
    let dest = config.out_dir.join(output_filename(&config.package, &target.triple));
    let binary_name = config.binary_name.as_deref().unwrap_or(&config.package);

    // Determine if we should use nightly with build-std
    let use_build_std = config.is_release && toolchain.can_use_build_std();

    // Try native cargo first
    let native_result = try_native_cargo(
        config,
        target,
        build_target_dir,
        use_build_std,
    );

    let (build_success, profile_dir) = match native_result {
        Ok(profile) => (true, profile),
        Err(reason) => {
            if target.use_cross_fallback && toolchain.has_cross {
                eprintln!(
                    "cargo:warning=Native cargo failed for {}, trying cross: {}",
                    target.triple, reason
                );

                match try_cross(config, target, build_target_dir) {
                    Ok(profile) => (true, profile),
                    Err(reason) => {
                        eprintln!(
                            "cargo:warning=Cross also failed for {}: {}",
                            target.triple, reason
                        );
                        return BuildResult::Failed { reason };
                    }
                }
            } else {
                eprintln!(
                    "cargo:warning=Could not build for target {}: {}",
                    target.triple, reason
                );
                return BuildResult::Failed { reason };
            }
        }
    };

    if !build_success {
        return BuildResult::Failed {
            reason: "Build failed".to_string(),
        };
    }

    // Find and copy the binary
    let source = find_binary(build_target_dir, &target.triple, &profile_dir, binary_name);

    let source = match source {
        Some(s) => s,
        None => {
            return BuildResult::Failed {
                reason: format!("Binary not found in {}/{}", target.triple, profile_dir),
            };
        }
    };

    if let Err(e) = fs::copy(&source, &dest) {
        return BuildResult::Failed {
            reason: format!("Failed to copy binary: {}", e),
        };
    }

    // Apply UPX compression if enabled
    let compressed = if config.is_release && config.use_upx && toolchain.has_upx {
        apply_upx(&dest)
    } else {
        false
    };

    let size = fs::metadata(&dest).map(|m| m.len() as usize).unwrap_or(0);

    BuildResult::Success {
        path: dest,
        size,
        compressed,
    }
}

fn try_native_cargo(
    config: &BuildConfig,
    target: &CrossTarget,
    build_target_dir: &Path,
    use_build_std: bool,
) -> Result<String, String> {
    let mut args: Vec<String> = Vec::new();

    // Use nightly if build-std is enabled
    if use_build_std {
        args.push("+nightly".to_string());
    }

    args.push("build".to_string());

    // Determine profile
    let profile_dir = if config.is_release {
        if use_build_std {
            if let Some(ref custom) = target.custom_profile {
                args.extend(["--profile".to_string(), custom.clone()]);
                custom.clone()
            } else {
                args.push("--release".to_string());
                "release".to_string()
            }
        } else {
            args.push("--release".to_string());
            "release".to_string()
        }
    } else {
        "debug".to_string()
    };

    // Add build-std flags
    if use_build_std {
        args.extend(["-Z".to_string(), "build-std=std,panic_abort".to_string()]);
        args.extend([
            "-Z".to_string(),
            "build-std-features=optimize_for_size".to_string(),
        ]);
    }

    args.extend([
        "-p".to_string(),
        config.package.clone(),
        "--target".to_string(),
        target.triple.clone(),
    ]);

    if !config.features.is_empty() {
        args.push("--features".to_string());
        args.push(config.features.join(","));
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&config.workspace_root)
        .env("CARGO_TARGET_DIR", build_target_dir)
        .args(&args);

    if !config.rustflags.is_empty() {
        cmd.env("RUSTFLAGS", config.rustflags.join(" "));
    }

    let status = cmd.status();

    match status {
        Ok(s) if s.success() => Ok(profile_dir),
        Ok(s) => Err(format!("cargo exited with code {:?}", s.code())),
        Err(e) => Err(format!("Failed to run cargo: {}", e)),
    }
}

fn try_cross(
    config: &BuildConfig,
    target: &CrossTarget,
    build_target_dir: &Path,
) -> Result<String, String> {
    let mut args = vec!["build".to_string()];

    let profile_dir = if config.is_release {
        args.push("--release".to_string());
        "release".to_string()
    } else {
        "debug".to_string()
    };

    args.extend([
        "-p".to_string(),
        config.package.clone(),
        "--target".to_string(),
        target.triple.clone(),
    ]);

    if !config.features.is_empty() {
        args.push("--features".to_string());
        args.push(config.features.join(","));
    }

    let mut cmd = Command::new("cross");
    cmd.current_dir(&config.workspace_root)
        .env("CARGO_TARGET_DIR", build_target_dir)
        .args(&args);

    if !config.rustflags.is_empty() {
        cmd.env("RUSTFLAGS", config.rustflags.join(" "));
    }

    let status = cmd.status();

    match status {
        Ok(s) if s.success() => Ok(profile_dir),
        Ok(s) => Err(format!("cross exited with code {:?}", s.code())),
        Err(e) => Err(format!("Failed to run cross: {}", e)),
    }
}

fn find_binary(
    build_target_dir: &Path,
    target: &str,
    profile_dir: &str,
    binary_name: &str,
) -> Option<PathBuf> {
    // Try the expected profile directory first
    let path = build_target_dir
        .join(target)
        .join(profile_dir)
        .join(binary_name);

    if path.exists() {
        return Some(path);
    }

    // Fall back to release directory (cross might use this)
    let release_path = build_target_dir
        .join(target)
        .join("release")
        .join(binary_name);

    if release_path.exists() {
        return Some(release_path);
    }

    None
}

fn apply_upx(path: &Path) -> bool {
    let status = Command::new("upx")
        .args(["--best", "--lzma"])
        .arg(path)
        .status();

    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("cargo:warning=upx failed with exit code: {:?}", s.code());
            false
        }
        Err(e) => {
            eprintln!("cargo:warning=upx error: {}", e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_target_builders() {
        let linux = CrossTarget::linux_x86_64();
        assert_eq!(linux.triple, "x86_64-unknown-linux-musl");
        assert!(linux.use_cross_fallback);

        let darwin = CrossTarget::darwin_aarch64();
        assert_eq!(darwin.triple, "aarch64-apple-darwin");
        assert!(!darwin.use_cross_fallback);
    }

    #[test]
    fn test_build_config_builder() {
        let config = BuildConfig::new("my-package")
            .workspace_root("/workspace")
            .out_dir("/out")
            .target(CrossTarget::linux_x86_64())
            .release(true)
            .with_upx();

        assert_eq!(config.package, "my-package");
        assert_eq!(config.workspace_root, PathBuf::from("/workspace"));
        assert_eq!(config.out_dir, PathBuf::from("/out"));
        assert_eq!(config.targets.len(), 1);
        assert!(config.is_release);
        assert!(config.use_upx);
    }

    #[test]
    fn test_output_filename() {
        assert_eq!(
            output_filename("agent", "x86_64-unknown-linux-musl"),
            "agent-x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn test_cross_target_custom_profile() {
        let target = CrossTarget::new("x86_64-unknown-linux-musl")
            .with_custom_profile("agent-release");
        assert_eq!(
            target.custom_profile,
            Some("agent-release".to_string())
        );
        assert!(!target.use_cross_fallback);
    }

    #[test]
    fn test_cross_target_linux_aarch64() {
        let target = CrossTarget::linux_aarch64();
        assert_eq!(target.triple, "aarch64-unknown-linux-musl");
        assert!(target.use_cross_fallback);
    }

    #[test]
    fn test_build_config_features() {
        let config = BuildConfig::new("my-pkg")
            .with_feature("agent-tracing")
            .with_feature("verbose");
        assert_eq!(config.features, vec!["agent-tracing", "verbose"]);
    }

    #[test]
    fn test_build_config_rustflags() {
        let config = BuildConfig::new("my-pkg")
            .with_rustflag("-Zlocation-detail=none")
            .with_rustflag("-Zfmt-debug=none");
        assert_eq!(
            config.rustflags,
            vec!["-Zlocation-detail=none", "-Zfmt-debug=none"]
        );
    }

    #[test]
    fn test_build_config_binary_name() {
        let config = BuildConfig::new("agent").binary_name("agent");
        assert_eq!(config.binary_name, Some("agent".to_string()));
    }

    #[test]
    fn test_build_result_success() {
        let result = BuildResult::Success {
            path: PathBuf::from("/out/binary"),
            size: 1024,
            compressed: true,
        };
        assert!(result.is_success());
        assert_eq!(result.path(), Some(Path::new("/out/binary")));
    }

    #[test]
    fn test_build_result_failed() {
        let result = BuildResult::Failed {
            reason: "build error".to_string(),
        };
        assert!(!result.is_success());
        assert!(result.path().is_none());
    }

    #[test]
    fn test_toolchain_info_can_use_build_std() {
        let both = ToolchainInfo {
            has_nightly: true,
            has_rust_src: true,
            has_cross: false,
            has_upx: false,
        };
        assert!(both.can_use_build_std());

        let no_nightly = ToolchainInfo {
            has_nightly: false,
            has_rust_src: true,
            has_cross: false,
            has_upx: false,
        };
        assert!(!no_nightly.can_use_build_std());

        let no_rust_src = ToolchainInfo {
            has_nightly: true,
            has_rust_src: false,
            has_cross: false,
            has_upx: false,
        };
        assert!(!no_rust_src.can_use_build_std());

        let neither = ToolchainInfo {
            has_nightly: false,
            has_rust_src: false,
            has_cross: false,
            has_upx: false,
        };
        assert!(!neither.can_use_build_std());
    }
}
