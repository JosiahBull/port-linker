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

    // Gzip-compress successful builds, write empty placeholders for failures.
    for target in &config.targets {
        let raw_path = config.out_dir.join(agent_build::output_filename(
            &config.package,
            &target.triple,
        ));
        let gz_path = config.out_dir.join(format!("relay-{}.gz", target.triple));

        if let Some(result) = results.get(&target.triple)
            && result.is_success()
            && let Ok(data) = fs::read(&raw_path)
            && !data.is_empty()
        {
            let compressed = gzip_compress(&data);
            fs::write(&gz_path, &compressed).unwrap();
            eprintln!(
                "cargo:warning=Embedded relay for {} ({} -> {} bytes, {:.0}% reduction)",
                target.triple,
                data.len(),
                compressed.len(),
                (1.0 - compressed.len() as f64 / data.len() as f64) * 100.0,
            );
            continue;
        }

        // Failed or empty build — write empty placeholder.
        fs::write(&gz_path, b"").unwrap();
        eprintln!(
            "cargo:warning=No relay binary for {}, using empty placeholder",
            target.triple
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
