use std::collections::HashSet;

use protocol::Protocol;

use crate::scanner::Listener;

/// An event emitted when the set of listening ports changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortEvent {
    Added(u16, Protocol),
    Removed(u16, Protocol),
}

/// Compare `previous` and `current` port snapshots, returning the events that
/// describe the transition and the new state (which is just `current`).
pub fn diff(
    previous: &HashSet<Listener>,
    current: &HashSet<Listener>,
) -> Vec<PortEvent> {
    let mut events = Vec::new();

    // Ports in current but not in previous → Added
    for &(port, proto) in current {
        if !previous.contains(&(port, proto)) {
            events.push(PortEvent::Added(port, proto));
        }
    }

    // Ports in previous but not in current → Removed
    for &(port, proto) in previous {
        if !current.contains(&(port, proto)) {
            events.push(PortEvent::Removed(port, proto));
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(port: u16, proto: Protocol) -> Listener {
        (port, proto)
    }

    #[test]
    fn no_change_produces_no_events() {
        let state: HashSet<Listener> = [
            listener(80, Protocol::Tcp),
            listener(443, Protocol::Tcp),
        ]
        .into();

        let events = diff(&state, &state);
        assert!(events.is_empty());
    }

    #[test]
    fn added_ports() {
        let prev: HashSet<Listener> = HashSet::new();
        let curr: HashSet<Listener> = [
            listener(80, Protocol::Tcp),
            listener(53, Protocol::Udp),
        ]
        .into();

        let events = diff(&prev, &curr);
        assert_eq!(events.len(), 2);
        assert!(events.contains(&PortEvent::Added(80, Protocol::Tcp)));
        assert!(events.contains(&PortEvent::Added(53, Protocol::Udp)));
    }

    #[test]
    fn removed_ports() {
        let prev: HashSet<Listener> = [
            listener(80, Protocol::Tcp),
            listener(53, Protocol::Udp),
        ]
        .into();
        let curr: HashSet<Listener> = HashSet::new();

        let events = diff(&prev, &curr);
        assert_eq!(events.len(), 2);
        assert!(events.contains(&PortEvent::Removed(80, Protocol::Tcp)));
        assert!(events.contains(&PortEvent::Removed(53, Protocol::Udp)));
    }

    #[test]
    fn mixed_add_and_remove() {
        let prev: HashSet<Listener> = [
            listener(80, Protocol::Tcp),
            listener(443, Protocol::Tcp),
        ]
        .into();
        let curr: HashSet<Listener> = [
            listener(443, Protocol::Tcp),
            listener(8080, Protocol::Tcp),
        ]
        .into();

        let events = diff(&prev, &curr);
        assert_eq!(events.len(), 2);
        assert!(events.contains(&PortEvent::Added(8080, Protocol::Tcp)));
        assert!(events.contains(&PortEvent::Removed(80, Protocol::Tcp)));
    }

    #[test]
    fn protocol_change_is_add_and_remove() {
        // Same port but different protocol should be treated as separate listeners
        let prev: HashSet<Listener> = [listener(53, Protocol::Tcp)].into();
        let curr: HashSet<Listener> = [listener(53, Protocol::Udp)].into();

        let events = diff(&prev, &curr);
        assert_eq!(events.len(), 2);
        assert!(events.contains(&PortEvent::Added(53, Protocol::Udp)));
        assert!(events.contains(&PortEvent::Removed(53, Protocol::Tcp)));
    }

    #[test]
    fn both_empty_produces_no_events() {
        let events = diff(&HashSet::new(), &HashSet::new());
        assert!(events.is_empty());
    }
}
