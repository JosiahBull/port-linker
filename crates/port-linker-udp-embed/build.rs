use port_linker_udp_build::{build_for_targets, watch_sources, BuildConfig, CrossTarget};

fn main() {
    // Rerun if udp-proxy sources change
    watch_sources(&["../udp-proxy/src", "../port-linker-proto/src"]);

    // Configure the build
    let config = BuildConfig::from_env("udp-proxy")
        .target(
            CrossTarget::linux_x86_64()
                .with_custom_profile("udp-proxy-release".to_string()),
        )
        .target(
            CrossTarget::linux_aarch64()
                .with_custom_profile("udp-proxy-release".to_string()),
        )
        .target(
            CrossTarget::darwin_aarch64()
                .with_custom_profile("udp-proxy-release".to_string()),
        )
        .with_upx();

    // Build for all targets
    let results = build_for_targets(&config);

    // Report results
    for (target, result) in &results {
        match result {
            port_linker_udp_build::BuildResult::Success { size, compressed, .. } => {
                let compression = if *compressed { " (compressed)" } else { "" };
                eprintln!(
                    "cargo:warning=Built {} for {}: {} bytes{}",
                    config.package, target, size, compression
                );
            }
            port_linker_udp_build::BuildResult::Failed { reason } => {
                eprintln!(
                    "cargo:warning=Failed to build {} for {}: {}",
                    config.package, target, reason
                );
            }
        }
    }
}
