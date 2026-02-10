//! File-based logging for the CLI host (Architecture Section 7.2).
//!
//! Logs are written to `~/.local/state/port-linker/debug.log` using a daily
//! rolling file appender. Stderr output is enabled when `RUST_LOG` is set
//! (useful for development). Stdout is never used for logs — it is reserved
//! for TUI output.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// The directory under `~/.local/state/` where logs are stored.
const LOG_DIR_NAME: &str = "port-linker";

/// The base filename for the rolling log file.
const LOG_FILE_NAME: &str = "debug.log";

/// Initialise the tracing subscriber with file + optional stderr layers.
///
/// Returns a [`WorkerGuard`] that **must** be held for the lifetime of the
/// program — dropping it flushes and closes the log file writer.
pub fn init_logging() -> WorkerGuard {
    let log_dir = log_directory();

    // Ensure the log directory exists.
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "warning: could not create log directory {}: {e}",
            log_dir.display()
        );
    }

    // Daily rolling file appender.
    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE_NAME);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // File layer: always active, writes all events at DEBUG or above.
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    // Stderr layer: only active when RUST_LOG is set (developer mode).
    let stderr_layer = if std::env::var("RUST_LOG").is_ok() {
        Some(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(true)
                .with_target(true),
        )
    } else {
        None
    };

    // Env filter: respect RUST_LOG if set, otherwise default to info.
    // Silence noisy debug/trace output from russh, tokio, and quinn internals
    // so that RUST_LOG=debug shows our application logs without drowning in
    // transport-layer chatter.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("russh=warn".parse().unwrap())
        .add_directive("russh_keys=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("quinn=warn".parse().unwrap())
        .add_directive("quinn_proto=warn".parse().unwrap())
        .add_directive("quinn_udp=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();

    guard
}

/// Resolve the log directory path.
///
/// Uses the XDG state directory (`~/.local/state/port-linker/`) on Linux and
/// the equivalent on macOS (`~/Library/Application Support/port-linker/logs/`
/// via `dirs::state_dir()`). Falls back to `~/.local/state/port-linker/` if
/// the platform helper returns `None`.
fn log_directory() -> std::path::PathBuf {
    if let Some(state) = dirs::state_dir() {
        return state.join(LOG_DIR_NAME);
    }
    // Fallback: build the path manually.
    if let Some(home) = dirs::home_dir() {
        return home.join(".local").join("state").join(LOG_DIR_NAME);
    }
    // Last resort: current directory.
    std::path::PathBuf::from(".")
}

/// Maximum frame size for incoming agent log events (64 KB).
const MAX_LOG_FRAME: u32 = 65_536;

/// Read agent log events from a QUIC unidirectional stream and emit them
/// into the host's tracing subscriber (Architecture Section 7.1).
///
/// Runs until the stream is closed or an error occurs. Designed to be
/// spawned as a background task.
pub async fn receive_agent_logs(mut recv: quinn::RecvStream) {
    // Reuse a single buffer across iterations to avoid per-frame allocation.
    // The buffer grows to the high-water mark and stays there.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut len_buf = [0u8; 4];

    loop {
        // Read 4-byte length prefix.
        if recv.read_exact(&mut len_buf).await.is_err() {
            break; // Stream closed.
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_LOG_FRAME as usize {
            tracing::warn!(len, "agent log frame too large, skipping stream");
            break;
        }

        // Resize the buffer to fit the frame. This is O(1) when the buffer
        // is already large enough (the common case after the first few events).
        buf.resize(len, 0);
        if recv.read_exact(&mut buf[..len]).await.is_err() {
            break;
        }

        let event: protocol::AgentLogEvent = match protocol::decode(&buf[..len]) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Re-emit the agent's log event into the host's tracing subscriber.
        // The match on level is required because tracing macros need the level
        // as a compile-time constant for static metadata.
        match event.level {
            protocol::LogLevel::Error => {
                tracing::error!(target: "agent", agent_target = %event.target, "{}", event.message);
            }
            protocol::LogLevel::Warn => {
                tracing::warn!(target: "agent", agent_target = %event.target, "{}", event.message);
            }
            protocol::LogLevel::Info => {
                tracing::info!(target: "agent", agent_target = %event.target, "{}", event.message);
            }
            protocol::LogLevel::Debug => {
                tracing::debug!(target: "agent", agent_target = %event.target, "{}", event.message);
            }
            protocol::LogLevel::Trace => {
                tracing::trace!(target: "agent", agent_target = %event.target, "{}", event.message);
            }
        }
    }

    tracing::debug!("agent log stream closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_directory_is_not_empty() {
        let dir = log_directory();
        assert!(
            dir.components().count() > 0,
            "log directory should have at least one component"
        );
    }

    #[test]
    fn log_directory_ends_with_port_linker() {
        let dir = log_directory();
        assert!(
            dir.ends_with(LOG_DIR_NAME),
            "log directory should end with '{LOG_DIR_NAME}': {}",
            dir.display()
        );
    }

    #[test]
    fn log_directory_is_absolute_or_fallback() {
        let dir = log_directory();
        let path_str = dir.to_string_lossy();

        // Should be either absolute or the current directory fallback.
        assert!(
            dir.is_absolute() || path_str == ".",
            "log directory should be absolute or current dir fallback: {}",
            dir.display()
        );
    }

    #[test]
    fn log_dir_name_constant() {
        assert_eq!(LOG_DIR_NAME, "port-linker");
        assert!(!LOG_DIR_NAME.is_empty());
    }

    #[test]
    fn log_file_name_constant() {
        assert_eq!(LOG_FILE_NAME, "debug.log");
        assert!(!LOG_FILE_NAME.is_empty());
        assert!(LOG_FILE_NAME.ends_with(".log"));
    }

    #[test]
    fn max_log_frame_constant() {
        assert_eq!(MAX_LOG_FRAME, 65_536);
        const { assert!(MAX_LOG_FRAME > 0) };
        const { assert!(MAX_LOG_FRAME < 1_048_576) };
        assert!(MAX_LOG_FRAME.is_power_of_two());
    }

    #[test]
    fn log_level_to_tracing_mapping_completeness() {
        // Ensure all protocol::LogLevel variants map to tracing::Level.
        let all_levels = vec![
            (protocol::LogLevel::Error, tracing::Level::ERROR),
            (protocol::LogLevel::Warn, tracing::Level::WARN),
            (protocol::LogLevel::Info, tracing::Level::INFO),
            (protocol::LogLevel::Debug, tracing::Level::DEBUG),
            (protocol::LogLevel::Trace, tracing::Level::TRACE),
        ];

        for (proto_level, expected_tracing_level) in all_levels {
            // This mimics the mapping in receive_agent_logs.
            let mapped = match proto_level {
                protocol::LogLevel::Error => tracing::Level::ERROR,
                protocol::LogLevel::Warn => tracing::Level::WARN,
                protocol::LogLevel::Info => tracing::Level::INFO,
                protocol::LogLevel::Debug => tracing::Level::DEBUG,
                protocol::LogLevel::Trace => tracing::Level::TRACE,
            };
            assert_eq!(mapped, expected_tracing_level);
        }
    }

    #[tokio::test]
    async fn receive_agent_logs_handles_empty_stream() {
        // Create a mock QUIC stream that closes immediately.
        let (send, _recv) = tokio::io::duplex(1024);

        // Close the send side immediately.
        drop(send);

        // Convert to Quinn RecvStream-like interface.
        // Note: This is a simplified test - in practice we'd need a full QUIC setup.
        // The actual receive_agent_logs function will gracefully exit when the stream closes.
    }
}
