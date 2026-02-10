//! Build script for the CLI crate.
//!
//! Produces gzip-compressed agent binaries in `OUT_DIR` for embedding via
//! `include_bytes!`. The agent binaries are sourced from:
//!
//! 1. **Environment variables** (CI mode): `PORT_LINKER_AGENT_X86_64` and
//!    `PORT_LINKER_AGENT_AARCH64` point to pre-built agent binaries.
//! 2. **Pre-built in target directory** (local release): Searches for agent
//!    binaries in `target/cross-build/` and `target/<triple>/`.
//! 3. **Empty placeholder** (local dev): If no binary is found, an empty file
//!    is written. At runtime, the CLI falls back to searching for a native
//!    agent binary in `target/{debug,release}/`.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-musl", "PORT_LINKER_AGENT_X86_64"),
    ("aarch64-unknown-linux-musl", "PORT_LINKER_AGENT_AARCH64"),
];

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Rerun triggers.
    for &(_, env_var) in TARGETS {
        println!("cargo:rerun-if-env-changed={env_var}");
    }
    println!("cargo:rerun-if-changed=../agent/src/");

    for &(target, env_var) in TARGETS {
        embed_agent(&out_dir, target, env_var);
    }
}

fn embed_agent(out_dir: &Path, target: &str, env_var: &str) {
    let output_path = out_dir.join(format!("agent-{target}.gz"));

    // Try 1: Env var with explicit path (CI mode).
    if let Ok(path) = env::var(env_var) {
        let p = Path::new(&path);
        if p.exists() {
            if let Ok(data) = fs::read(p) {
                if !data.is_empty() {
                    let compressed = gzip_compress(&data);
                    fs::write(&output_path, &compressed).unwrap();
                    println!(
                        "cargo:warning=Embedded agent for {target} from {path} ({} -> {} bytes)",
                        data.len(),
                        compressed.len()
                    );
                    return;
                }
            }
        }
    }

    // Try 2: Find pre-built binary in target directory.
    if let Some(data) = find_prebuilt_agent(target) {
        let compressed = gzip_compress(&data);
        fs::write(&output_path, &compressed).unwrap();
        println!(
            "cargo:warning=Embedded agent for {target} from target dir ({} -> {} bytes)",
            data.len(),
            compressed.len()
        );
        return;
    }

    // Fallback: Empty placeholder — runtime will fall back to local binary search.
    fs::write(&output_path, b"").unwrap();
    println!("cargo:warning=No agent binary for {target}, using empty placeholder");
}

fn find_prebuilt_agent(target: &str) -> Option<Vec<u8>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    let workspace_root = Path::new(&manifest_dir).parent()?.parent()?;

    let candidates = [
        // agent-build's cross-build output directory.
        workspace_root
            .join("target/cross-build")
            .join(target)
            .join("agent-release/port-linker-agent"),
        // Standard cargo target directory with custom profile.
        workspace_root
            .join("target")
            .join(target)
            .join("agent-release/port-linker-agent"),
        // Standard cargo release build.
        workspace_root
            .join("target")
            .join(target)
            .join("release/port-linker-agent"),
    ];

    for candidate in &candidates {
        if let Ok(data) = fs::read(candidate) {
            if !data.is_empty() {
                return Some(data);
            }
        }
    }

    None
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}
