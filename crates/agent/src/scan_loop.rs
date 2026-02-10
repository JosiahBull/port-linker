use std::collections::HashSet;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, error};

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
        (22, protocol::Protocol::Tcp),         // SSH
        (53, protocol::Protocol::Udp),         // DNS
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

        let events = diff::diff(&previous, &current);
        previous = current;

        for event in events {
            debug!(?event, "port change detected");
            if tx.send(event).is_err() {
                // Receiver dropped, host disconnected.
                debug!("scan loop stopping: channel closed");
                return;
            }
        }
    }
}
