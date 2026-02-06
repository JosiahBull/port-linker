//! Conditional logging macros for the target agent.
//!
//! When the `agent-tracing` feature is enabled, these macros delegate to `tracing`.
//! When disabled, they compile to nothing (except `agent_error!` which uses `eprintln!`
//! so critical errors still reach the host via stderr/ExtendedData).
//!
//! The `agent_trace!` macro additionally requires the `verbose` feature to be enabled,
//! since trace-level events (per-packet logging) have high volume and serialization cost.

/// Log at info level.
#[cfg(feature = "agent-tracing")]
macro_rules! agent_info {
    ($($t:tt)*) => { tracing::info!($($t)*) }
}

/// Log at info level (no-op without agent-tracing).
#[cfg(not(feature = "agent-tracing"))]
macro_rules! agent_info {
    ($($t:tt)*) => { {} }
}

/// Log at debug level.
#[cfg(feature = "agent-tracing")]
macro_rules! agent_debug {
    ($($t:tt)*) => { tracing::debug!($($t)*) }
}

/// Log at debug level (no-op without agent-tracing).
#[cfg(not(feature = "agent-tracing"))]
macro_rules! agent_debug {
    ($($t:tt)*) => { {} }
}

/// Log at warn level.
#[cfg(feature = "agent-tracing")]
macro_rules! agent_warn {
    ($($t:tt)*) => { tracing::warn!($($t)*) }
}

/// Log at warn level (no-op without agent-tracing).
#[cfg(not(feature = "agent-tracing"))]
macro_rules! agent_warn {
    ($($t:tt)*) => { {} }
}

/// Log at error level. Always outputs to stderr even without `agent-tracing`
/// so critical errors reach the host via SSH ExtendedData.
#[cfg(feature = "agent-tracing")]
macro_rules! agent_error {
    ($($t:tt)*) => { tracing::error!($($t)*) }
}

/// Log at error level. Falls back to eprintln without agent-tracing.
#[cfg(not(feature = "agent-tracing"))]
macro_rules! agent_error {
    ($($t:tt)*) => { eprintln!("[agent:error] {}", format!($($t)*)) }
}

/// Log at trace level. Requires both `agent-tracing` and `verbose` features.
/// Trace-level events are very high volume (per-packet) and have serialization cost.
#[cfg(all(feature = "agent-tracing", feature = "verbose"))]
macro_rules! agent_trace {
    ($($t:tt)*) => { tracing::trace!($($t)*) }
}

/// Log at trace level (no-op without agent-tracing + verbose).
#[cfg(not(all(feature = "agent-tracing", feature = "verbose")))]
macro_rules! agent_trace {
    ($($t:tt)*) => { {} }
}
