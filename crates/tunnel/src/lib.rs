//! The port-linker data plane.
//!
//! Both halves of the per-connection TCP forwarding protocol live here — the
//! host's [`forward_tcp_connection`] and the agent's [`serve_tcp_stream`] — so
//! that the wire contract between them is stated once, and so that benchmarks
//! and integration tests can drive the real code rather than a reimplementation
//! of it.
//!
//! [`framing`] holds the length-prefixed `ControlMsg` codec used by both the
//! control stream and the forwarding streams.

pub mod framing;
pub mod tcp;

pub use framing::{MAX_FRAME_SIZE, recv_framed, send_framed};
pub use tcp::{
    STATUS_ERROR, STATUS_OK, STOP_CONNECT_FAILED, StreamSetup, forward_tcp_connection,
    forward_tcp_connection_with, serve_tcp_stream,
};
