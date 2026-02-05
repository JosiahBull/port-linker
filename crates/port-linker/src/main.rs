mod cli;
mod error;
mod monitor;

use clap::Parser;
use cli::{Cli, LogFormat};
use monitor::Monitor;
use port_linker_forward::ForwardManager;
use port_linker_notify::{Notifier, PortMapping};
use port_linker_ssh::SshClient;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// A writer that wraps stderr and flushes after each write.
/// This ensures log lines are immediately visible when stderr is piped.
struct FlushingStderr;

impl Write for FlushingStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        let n = handle.write(buf)?;
        handle.flush()?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(&cli);

    if let Err(e) = run(cli).await {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize the logging system based on CLI configuration.
fn init_logging(cli: &Cli) {
    // Build filter that respects RUST_LOG env var but also silences noisy crates at DEBUG level.
    // These crates produce excessive output at DEBUG that should only appear at TRACE.
    let base_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    // Check if user explicitly requested trace level or set specific crate overrides
    let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
    let wants_verbose_ssh = rust_log.contains("russh")
        || rust_log.contains("ssh_key")
        || cli.log_level.to_lowercase() == "trace";

    // Add directives to silence noisy SSH-related crates unless TRACE is requested
    // or the user explicitly sets them in RUST_LOG
    let filter = if wants_verbose_ssh {
        base_filter
    } else {
        base_filter
            .add_directive("russh=info".parse().unwrap())
            .add_directive("russh_keys=info".parse().unwrap())
            .add_directive("internal_russh_forked_ssh_key=info".parse().unwrap())
            .add_directive("ssh_key=info".parse().unwrap())
    };

    // Always silence noisy HTTP crates unless explicitly enabled
    let wants_verbose_http = rust_log.contains("hyper")
        || rust_log.contains("reqwest")
        || rust_log.contains("h2")
        || rust_log.contains("tower");

    let filter = if wants_verbose_http {
        filter
    } else {
        filter
            .add_directive("hyper=info".parse().unwrap())
            .add_directive("reqwest=info".parse().unwrap())
            .add_directive("h2=info".parse().unwrap())
            .add_directive("tower=info".parse().unwrap())
    };

    let use_color = cli.color.should_enable();

    match cli.log_format {
        LogFormat::Json => {
            // JSON format for machine parsing - no colors, structured output
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_span_list(true)
                        .with_writer(|| FlushingStderr),
                )
                .init();
        }
        LogFormat::Compact => {
            // Compact single-line format
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_ansi(use_color)
                        .with_target(false)
                        .with_writer(|| FlushingStderr),
                )
                .init();
        }
        LogFormat::Pretty => {
            // Pretty human-readable format (default)
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .pretty()
                        .with_ansi(use_color)
                        .with_target(false)
                        .with_writer(|| FlushingStderr),
                )
                .init();
        }
    }
}

#[instrument(name = "run", skip(cli), fields(host = %cli.host, protocol = ?cli.protocol))]
async fn run(cli: Cli) -> error::Result<()> {
    let parsed_host = port_linker_ssh::ParsedHost::parse(&cli.host);

    info!(
        "port-linker v{} - Connecting to {}",
        env!("CARGO_PKG_VERSION"),
        cli.host
    );

    // Connect to SSH
    let client =
        Arc::new(SshClient::connect(&parsed_host, cli.ssh_port, cli.identity_file.clone()).await?);

    // Load port mapping
    let port_mapping = Arc::new(PortMapping::load_default());
    debug!("Port mapping loaded");

    // Create notifier
    let notifier = Arc::new(Notifier::new(
        !cli.no_notifications,
        !cli.no_sound,
        port_mapping,
    ));

    // Create forward manager
    let excluded_ports = cli.excluded_ports();
    let mut manager = ForwardManager::new(
        client.handle(),
        notifier.clone(),
        cli.auto_kill,
        cli.ports.clone(),
        excluded_ports,
    );

    // Set SSH client for UDP tunneling
    manager.set_ssh_client(client.clone());

    // Log protocol mode
    match cli.protocol {
        cli::ProtocolFilter::Tcp => info!("Forwarding TCP ports only"),
        cli::ProtocolFilter::Udp => info!("Forwarding UDP ports only"),
        cli::ProtocolFilter::Both => info!("Forwarding both TCP and UDP ports"),
    }

    // Create and run monitor
    let mut monitor = Monitor::new(
        client,
        manager,
        notifier,
        Duration::from_millis(cli.scan_interval_ms),
        cli.forward_tcp(),
        cli.forward_udp(),
    );

    monitor.run().await
}
