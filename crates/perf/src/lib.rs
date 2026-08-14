//! Latency benchmarks for the port-linker data plane.
//!
//! # What this measures
//!
//! The headline number is the cost of *establishing* a forwarded TCP connection:
//! from a local client's `connect()` to the first byte of its response coming
//! back through the tunnel. The scenario opens a real tunnel — the shipped agent
//! binary as a subprocess, the shipped host-side forwarding code, a real QUIC
//! connection — and inserts a deterministic round-trip time with
//! [`shim::LatencyShim`], a userspace UDP relay. No root, no `tc netem`, no
//! container.
//!
//! # Why the numbers are expressed in RTTs
//!
//! Every assertion is a multiple of the configured round-trip time, never an
//! absolute millisecond figure. A connection that costs "one extra round trip"
//! costs that on any machine, whereas a threshold in milliseconds is really a
//! statement about the CI runner. Each sample also times a *second* request on
//! the already-established connection, which is the round trip alone; the
//! difference between the two isolates setup cost and cancels machine speed out.
//!
//! # Getting a number
//!
//! ```text
//! cargo run -p perf -- --rtt-ms 60 --iterations 20
//! ```
//!
//! Run that before and after a change to the data plane and compare. At a given
//! RTT the medians are stable to a fraction of a millisecond, so a real
//! regression stands out. `tests/perf_regression.rs` runs the same scenario with
//! bounds attached, so CI fails if connection setup starts costing a round trip
//! again.
//!
//! # Adding a scenario
//!
//! [`fixture`] provides the reusable pieces — [`fixture::AgentUnderTest`],
//! [`fixture::EchoService`], [`fixture::ForwardedPort`], [`fixture::Tunnel`] —
//! and [`stats::Stats`] the reporting. A new scenario is a function that drives
//! traffic and returns [`stats::Stats`]; see [`scenario`] for the shape, and
//! `tests/perf_regression.rs` for how one becomes an assertion.

pub mod fixture;
pub mod scenario;
pub mod shim;
pub mod stats;

/// Errors here are for a benchmark operator or a failing test, so they are
/// strings rather than a typed enum nothing matches on.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub use scenario::{Bench, ConnectionSample, Measurement};
pub use shim::LatencyShim;
pub use stats::{Stats, ms};
