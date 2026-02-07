//! TCP and UDP tunnel management for port-linker.
//!
//! This crate provides:
//! - TCP port forwarding through SSH tunnels
//! - UDP port forwarding via remote agent (multiplexed)
//! - AgentSession for communicating with the remote agent
//! - ForwardManager for coordinating multiple tunnels

pub mod agent;
pub mod error;
pub mod manager;
pub mod tcp;
pub mod udp;

pub use agent::AgentSession;
pub use error::{ForwardError, Result};
pub use manager::{ForwardManager, TunnelKey};
pub use tcp::{TcpTunnel, TunnelHandle};
pub use udp::{start_udp_tunnel, TunnelStopReason, UdpProxyManager, UdpTunnelHandle};
