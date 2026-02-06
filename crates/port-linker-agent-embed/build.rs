use port_linker_agent_build::{
    build_for_targets, watch_sources, BuildConfig, CrossTarget, ToolchainInfo,
};

fn main() {
    // Rerun if target-agent or its dependencies change
    watch_sources(&[
        "../target-agent/src",
        "../port-linker-proto/src",
        "../port-scanner/src",
    ]);

    // Configure the build
    let mut config = BuildConfig::from_env("target-agent")
        .target(
            CrossTarget::linux_x86_64()
                .with_custom_profile("target-agent-release".to_string()),
        )
        .target(
            CrossTarget::linux_aarch64()
                .with_custom_profile("target-agent-release".to_string()),
        )
        .target(
            CrossTarget::darwin_aarch64()
                .with_custom_profile("target-agent-release".to_string()),
        )
        .with_upx();

    // Enable agent-tracing feature for debug builds so agent logs
    // are forwarded to the host via the TLV protocol
    if !config.is_release {
        config = config.with_feature("agent-tracing");
    }

    // Nightly-only size optimizations: strip panic location detail and
    // Debug format implementations (both are dead code with panic=abort
    // and no debug formatting in release)
    if config.is_release {
        let toolchain = ToolchainInfo::detect();
        if toolchain.can_use_build_std() {
            config = config
                .with_rustflag("-Zlocation-detail=none")
                .with_rustflag("-Zfmt-debug=none");
        }
    }

    // Build for all targets
    let results = build_for_targets(&config);

    // Report results
    for (target, result) in &results {
        match result {
            port_linker_agent_build::BuildResult::Success { size, compressed, .. } => {
                let compression = if *compressed { " (compressed)" } else { "" };
                eprintln!(
                    "cargo:warning=Built {} for {}: {} bytes{}",
                    config.package, target, size, compression
                );
            }
            port_linker_agent_build::BuildResult::Failed { reason } => {
                eprintln!(
                    "cargo:warning=Failed to build {} for {}: {}",
                    config.package, target, reason
                );
            }
        }
    }
}
