use std::collections::HashSet;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use crate::diff::{self, PortEvent};
use crate::scanner::{Listener, PortScanner};

/// Run the scan loop. Scans every second, diffs against previous state,
/// and sends [`PortEvent`]s through the channel.
///
/// `self_port` is the agent's own QUIC listening port, which must be excluded
/// from scan results so we don't try to forward our own tunnel endpoint.
///
/// The scanner is called directly (not via `spawn_blocking`) because `/proc`
/// reads are very fast (<1ms). If scans become slow in the future, wrap the
/// `scanner.scan()` call in `tokio::task::spawn_blocking`.
pub async fn run_scan_loop<S: PortScanner>(
    scanner: S,
    tx: mpsc::UnboundedSender<PortEvent>,
    self_port: u16,
) {
    let excluded: HashSet<Listener> = HashSet::from([
        (self_port, protocol::Protocol::Udp), // agent's own QUIC endpoint
        (22, protocol::Protocol::Tcp),        // SSH
        (53, protocol::Protocol::Udp),        // DNS
        (41641, protocol::Protocol::Udp),     // Tailscale WireGuard
    ]);
    let mut previous: HashSet<Listener> = HashSet::new();

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut current = match scanner.scan() {
            Ok(ports) => ports,
            Err(e) => {
                error!("scan failed: {e}");
                continue;
            }
        };

        // Remove ports that should never be forwarded.
        for listener in &excluded {
            current.remove(listener);
        }

        // Filter out privileged ports (< 1024) — these are system services
        // (DHCP, NTP, etc.) that should not be forwarded.
        current.retain(|&(port, _)| port >= 1024);

        // Filter out ephemeral ports — these are transient outbound sockets,
        // not real services.
        current.retain(|&(port, _)| !common::ephemeral::is_ephemeral(port));

        let events = diff::diff(&previous, &current);
        previous = current;

        for event in events {
            // Enrich Added events with process name lookup.
            let event = match event {
                PortEvent::Added(port, proto, _) => {
                    let process_name = lookup_process_name(port, proto);
                    if let Some(ref name) = process_name {
                        debug!(port, ?proto, process = %name, "port change detected (added)");
                    } else {
                        debug!(
                            port,
                            ?proto,
                            "port change detected (added, unknown process)"
                        );
                    }
                    PortEvent::Added(port, proto, process_name)
                }
                other => {
                    debug!(?other, "port change detected");
                    other
                }
            };

            if tx.send(event).is_err() {
                // Receiver dropped, host disconnected.
                debug!("scan loop stopping: channel closed");
                return;
            }
        }
    }
}

/// Look up the process name for a listening port using the `common::process` module.
fn lookup_process_name(port: u16, proto: protocol::Protocol) -> Option<String> {
    let transport = match proto {
        protocol::Protocol::Tcp => common::process::TransportProto::Tcp,
        protocol::Protocol::Udp => common::process::TransportProto::Udp,
    };
    match common::process::find_listener(port, transport) {
        Some(info) => {
            trace!(port, process = %info.name, pid = info.pid, "identified process");
            Some(info.name)
        }
        None => {
            trace!(port, "could not identify process");
            None
        }
    }
}
