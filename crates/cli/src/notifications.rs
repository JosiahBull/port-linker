use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use notify::{Notifier, PortInfo, PortMapping};

/// How long to wait after the first event before flushing a batch.
const ACCUMULATION_WINDOW: Duration = Duration::from_secs(2);

/// Convert from protocol crate's `Protocol` to notify crate's `Protocol`.
fn proto_to_notify(proto: protocol::Protocol) -> notify::Protocol {
    match proto {
        protocol::Protocol::Tcp => notify::Protocol::Tcp,
        protocol::Protocol::Udp => notify::Protocol::Udp,
    }
}

/// Accumulates port add/remove events and flushes them as batched
/// desktop notifications after a 2-second window.
pub struct NotificationAccumulator {
    notifier: Arc<Notifier>,
    mapping: Arc<PortMapping>,
    pending_added: Vec<PortInfo>,
    pending_removed: Vec<PortInfo>,
    deadline: Option<Instant>,
}

impl NotificationAccumulator {
    pub fn new(notifier: Arc<Notifier>, mapping: Arc<PortMapping>) -> Self {
        Self {
            notifier,
            mapping,
            pending_added: Vec::new(),
            pending_removed: Vec::new(),
            deadline: None,
        }
    }

    /// Record a port-added event. Starts the accumulation timer if this is the
    /// first pending event.
    pub fn port_added(&mut self, port: u16, proto: protocol::Protocol, process_name: Option<&str>) {
        let info = PortInfo::new(port, process_name, proto_to_notify(proto), &self.mapping);
        self.pending_added.push(info);
        self.ensure_deadline();
    }

    /// Record a port-removed event. Starts the accumulation timer if this is
    /// the first pending event.
    pub fn port_removed(&mut self, port: u16, proto: protocol::Protocol) {
        let info = PortInfo::new(port, None, proto_to_notify(proto), &self.mapping);
        self.pending_removed.push(info);
        self.ensure_deadline();
    }

    /// Returns a future that resolves when the flush deadline arrives.
    /// If no events are pending, the future never resolves (waits forever).
    pub async fn next_flush(&self) {
        match self.deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }

    /// Drain all pending events and send batched notifications.
    pub fn flush(&mut self) {
        let added: Vec<PortInfo> = self.pending_added.drain(..).collect();
        let removed: Vec<PortInfo> = self.pending_removed.drain(..).collect();
        self.deadline = None;

        self.notifier.notify_ports_forwarded(added);
        self.notifier.notify_ports_removed(removed);
    }

    fn ensure_deadline(&mut self) {
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + ACCUMULATION_WINDOW);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_accumulator() -> NotificationAccumulator {
        let mapping = Arc::new(PortMapping::default());
        let notifier = Arc::new(Notifier::new(false, false, Arc::clone(&mapping)));
        NotificationAccumulator::new(notifier, mapping)
    }

    #[test]
    fn no_deadline_when_empty() {
        let acc = make_accumulator();
        assert!(acc.deadline.is_none());
    }

    #[test]
    fn deadline_set_on_first_add() {
        let mut acc = make_accumulator();
        acc.port_added(8080, protocol::Protocol::Tcp, None);
        assert!(acc.deadline.is_some());
        assert_eq!(acc.pending_added.len(), 1);
    }

    #[test]
    fn deadline_set_on_first_remove() {
        let mut acc = make_accumulator();
        acc.port_removed(8080, protocol::Protocol::Tcp);
        assert!(acc.deadline.is_some());
        assert_eq!(acc.pending_removed.len(), 1);
    }

    #[test]
    fn multiple_adds_accumulate() {
        let mut acc = make_accumulator();
        acc.port_added(8080, protocol::Protocol::Tcp, Some("nginx"));
        acc.port_added(3000, protocol::Protocol::Tcp, Some("node"));
        acc.port_added(5432, protocol::Protocol::Tcp, None);
        assert_eq!(acc.pending_added.len(), 3);
    }

    #[test]
    fn flush_clears_pending() {
        let mut acc = make_accumulator();
        acc.port_added(8080, protocol::Protocol::Tcp, None);
        acc.port_removed(3000, protocol::Protocol::Tcp);
        acc.flush();
        assert!(acc.pending_added.is_empty());
        assert!(acc.pending_removed.is_empty());
        assert!(acc.deadline.is_none());
    }

    #[test]
    fn proto_conversion() {
        assert_eq!(
            proto_to_notify(protocol::Protocol::Tcp),
            notify::Protocol::Tcp
        );
        assert_eq!(
            proto_to_notify(protocol::Protocol::Udp),
            notify::Protocol::Udp
        );
    }
}
