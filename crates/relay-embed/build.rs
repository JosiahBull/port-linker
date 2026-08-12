use std::fs;
use std::io::Write;

use agent_build::{BuildConfig, CrossTarget, build_for_targets, watch_sources};

fn main() {
    let config = BuildConfig::from_env("udp-relay")
        .binary_name("port-linker-relay")
        .target(CrossTarget::linux_x86_64().with_custom_profile("agent-release"))
        .target(CrossTarget::linux_aarch64().with_custom_profile("agent-release"))
        .target(CrossTarget::darwin_aarch64().with_custom_profile("agent-release"))
        .target(CrossTarget::windows_x86_64().with_custom_profile("agent-release"))
        .target(CrossTarget::windows_aarch64().with_custom_profile("agent-release"));

    let results = build_for_targets(&config);
    let is_release = config.is_release;

    // Gzip-compress successful builds; fail hard in release mode on any failure.
    let mut failures = Vec::new();
    for target in &config.targets {
        let raw_path = config.out_dir.join(agent_build::output_filename(
            &config.package,
            &target.triple,
        ));
        let gz_path = config.out_dir.join(format!("relay-{}.gz", target.triple));
        let sha_path = config
            .out_dir
            .join(format!("relay-{}.sha256", target.triple));

        if let Some(result) = results.get(&target.triple)
            && result.is_success()
            && let Ok(data) = fs::read(&raw_path)
            && !data.is_empty()
        {
            let compressed = gzip_compress(&data);
            fs::write(&gz_path, &compressed).unwrap();
            // Hash of the *uncompressed* binary. The host compares this against
            // the SHA256 of whatever ends up on the target, so nothing runs
            // there unless it is byte-identical to what was built here.
            fs::write(&sha_path, sha256_hex(&data)).unwrap();
            eprintln!(
                "cargo:warning=Embedded relay for {} ({} -> {} bytes, {:.0}% reduction)",
                target.triple,
                data.len(),
                compressed.len(),
                (1.0 - compressed.len() as f64 / data.len() as f64) * 100.0,
            );
            continue;
        }

        if is_release {
            failures.push(target.triple.clone());
        } else {
            // Debug builds: write empty placeholder so compilation can proceed.
            fs::write(&gz_path, b"").unwrap();
            fs::write(&sha_path, b"").unwrap();
            eprintln!(
                "cargo:warning=No relay binary for {}, using empty placeholder (debug build)",
                target.triple
            );
        }
    }

    if !failures.is_empty() {
        panic!(
            "Failed to build relay binaries for targets: {}. \
             Release builds require all targets to succeed. \
             Ensure nightly + rust-src are installed and cross-rs + Docker are available \
             for Linux musl targets.",
            failures.join(", ")
        );
    }

    // Watch relay + common sources for rebuild triggers.
    watch_sources(&["../udp-relay/src", "../udp-relay/Cargo.toml"]);
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// SHA256 of `data` as lower-case hex.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
