//! TCP and UDP tunnel management for port-linker.
//!
//! This crate provides:
//! - TCP port forwarding through SSH tunnels
//! - UDP port forwarding using embedded remote proxy
//! - ForwardManager for coordinating multiple tunnels

pub mod error;
pub mod manager;
pub mod tcp;
pub mod udp;

pub use error::{ForwardError, Result};
pub use manager::{ForwardManager, TunnelKey};
pub use tcp::{TcpTunnel, TunnelHandle};
pub use udp::{start_udp_tunnel, TunnelStopReason, UdpProxyManager, UdpTunnelHandle};
