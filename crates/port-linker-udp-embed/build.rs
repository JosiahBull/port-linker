use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Target architectures to compile udp-proxy for
const UDP_PROXY_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
];

fn main() {
    // Rerun if udp-proxy sources change
    println!("cargo:rerun-if-changed=../udp-proxy/src");
    println!("cargo:rerun-if-changed=../port-linker-proto/src");

    let out_dir = env::var("OUT_DIR").unwrap();

    // Build udp-proxy for all supported target platforms
    build_udp_proxy_all_targets(&out_dir);
}

/// Check if nightly toolchain is available with rust-src component
fn is_nightly_available() -> bool {
    // Check if nightly toolchain exists
    let nightly_check = Command::new("rustup")
        .args(["run", "nightly", "rustc", "--version"])
        .output();

    if nightly_check.map(|o| o.status.success()).unwrap_or(false) {
        // For build-std, we need rust-src component
        let rust_src_check = Command::new("rustup")
            .args(["+nightly", "component", "list", "--installed"])
            .output();

        if let Ok(comp_output) = rust_src_check {
            let components = String::from_utf8_lossy(&comp_output.stdout);
            return components.lines().any(|l| l.contains("rust-src"));
        }
    }
    false
}

fn build_udp_proxy_all_targets(out_dir: &str) {
    // Get the workspace root (two levels up from this crate)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();

    // Use a separate target directory to avoid cargo lock conflicts
    // The main build holds a lock on the workspace target directory
    let udp_proxy_target_dir = workspace_root.join("target").join("udp-proxy-build");

    // First, create empty placeholder files for all targets
    // This ensures include_bytes! doesn't fail even if builds fail
    for target in UDP_PROXY_TARGETS {
        let dest = Path::new(out_dir).join(format!("udp-proxy-{}", target));
        if !dest.exists() {
            let _ = fs::write(&dest, b"");
        }
    }

    // Now try to build each target
    for target in UDP_PROXY_TARGETS {
        build_udp_proxy_for_target(&udp_proxy_target_dir, workspace_root, out_dir, target);
    }
}

fn build_udp_proxy_for_target(
    udp_proxy_target_dir: &Path,
    workspace_root: &Path,
    out_dir: &str,
    target: &str,
) {
    let is_release = env::var("PROFILE").unwrap() == "release";

    // Name the output file with the target triple for identification
    let dest = Path::new(out_dir).join(format!("udp-proxy-{}", target));

    // Check if we can use nightly with build-std for optimized builds
    let use_nightly = is_release && is_nightly_available();

    // Set up PATH to use nightly toolchain if available
    let proxy_path = if use_nightly {
        let output = Command::new("rustup")
            .args(["which", "cargo", "--toolchain", "nightly"])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let path = String::from_utf8_lossy(&output.stdout);
                let path = Path::new(path.trim());
                path.parent().map(|bin_dir| {
                    let current_path = env::var_os("PATH").unwrap_or_default();
                    let mut paths = env::split_paths(&current_path).collect::<Vec<_>>();
                    paths.insert(0, bin_dir.to_path_buf());
                    env::join_paths(paths).unwrap()
                })
            }
            _ => None,
        }
    } else {
        None
    };

    // Determine the profile and arguments based on the current build mode
    let mut cargo_args: Vec<&str> = if use_nightly && proxy_path.is_none() {
        vec!["+nightly", "build"]
    } else {
        vec!["build"]
    };

    // Determine which profile to use
    let profile_dir = if is_release {
        if use_nightly {
            // Use optimized profile with build-std
            cargo_args.extend(["--profile", "udp-proxy-release"]);
            cargo_args.extend(["-Z", "build-std=std,panic_abort"]);
            "udp-proxy-release"
        } else {
            // Fall back to regular release profile without build-std
            cargo_args.push("--release");
            eprintln!(
                "cargo:warning=Nightly not available for {}, using standard release build (binary will be larger)",
                target
            );
            "release"
        }
    } else {
        "debug"
    };

    cargo_args.extend(["-p", "udp-proxy", "--target", target]);

    // Set up cross-compilation environment if needed
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", udp_proxy_target_dir)
        .args(&cargo_args);

    if let Some(path) = &proxy_path {
        cmd.env("PATH", path);
    }

    // For musl targets, we may need to use cross
    // First try native cargo, then fall back to cross if available
    let status = cmd.status();

    let build_success = match status {
        Ok(s) if s.success() => true,
        _ => {
            // Try with cross for cross-compilation (without nightly-specific flags)
            eprintln!(
                "cargo:warning=Native cargo failed for {}, trying cross",
                target
            );

            // For cross, use simpler args without -Z flags
            let mut cross_args: Vec<&str> = vec!["build"];
            if is_release {
                cross_args.push("--release");
            }
            cross_args.extend(["-p", "udp-proxy", "--target", target]);

            let mut cross_cmd = Command::new("cross");
            cross_cmd
                .current_dir(workspace_root)
                .env("CARGO_TARGET_DIR", udp_proxy_target_dir)
                .args(&cross_args);

            let cross_status = cross_cmd.status();

            match cross_status {
                Ok(s) if s.success() => true,
                _ => {
                    eprintln!(
                        "cargo:warning=Could not build udp-proxy for target {}, skipping",
                        target
                    );
                    false
                }
            }
        }
    };

    if !build_success {
        // Leave the empty placeholder file
        return;
    }

    // Copy binary to OUT_DIR with target-specific name
    let binary_name = "udp-proxy";

    // Try the expected profile dir first, then fall back to release
    let source = udp_proxy_target_dir
        .join(target)
        .join(profile_dir)
        .join(binary_name);

    let source = if source.exists() {
        source
    } else {
        // Fall back to release directory if cross was used
        udp_proxy_target_dir
            .join(target)
            .join("release")
            .join(binary_name)
    };

    if let Err(e) = fs::copy(&source, &dest) {
        eprintln!(
            "cargo:warning=Failed to copy udp-proxy for {}: {:?} -> {:?}: {}",
            target, source, dest, e
        );
        return;
    }

    // Try to compress with upx if available (optional)
    if is_release {
        let status = Command::new("upx")
            .args(["--best", "--lzma"])
            .arg(&dest)
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("cargo:warning=upx failed with exit code: {:?}", s.code());
            }
            Err(e) => {
                eprintln!("cargo:warning=upx not available: {}", e);
            }
        }
    }
}
