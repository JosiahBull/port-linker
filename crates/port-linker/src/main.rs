mod cli;
mod error;
mod forward;
mod mapping;
mod monitor;
mod notify;
mod process;
mod ssh;

use clap::Parser;
use cli::Cli;
use forward::ForwardManager;
use mapping::PortMapping;
use monitor::Monitor;
use notify::Notifier;
use ssh::SshClient;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

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

    // Initialize logging with a flushing writer to ensure logs are visible
    // immediately when stderr is piped (e.g., in tests)
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(|| FlushingStderr)
        .init();

    if let Err(e) = run(cli).await {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> error::Result<()> {
    let parsed_host = cli.parse_host();

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
