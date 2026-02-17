//! Platform abstraction for OS-specific behavior.
//!
//! Defines the [`Platform`] trait which unifies all OS-specific concerns behind a
//! single compile-time boundary. Each platform implements it once, and all crates
//! consume it through generics or the [`CurrentPlatform`] type alias.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

use crate::process::{ProcessInfo, TransportProto};

// -- Per-platform modules --

#[cfg(unix)]
mod unix;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

mod stub;

// Re-export stubs for platforms that need them.
pub use stub::{StubNotifier, StubScanner};

// ---------------------------------------------------------------------------
// Scanner types
// ---------------------------------------------------------------------------

/// A (port, protocol) pair representing a listening socket.
pub type Listener = (u16, protocol::Protocol);

/// Error type for port scanning failures.
#[derive(Debug)]
pub enum ScanError {
    /// An I/O error occurred while reading proc files.
    Io(std::io::Error),
    /// A generic scan failure with a descriptive message.
    Message(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Io(e) => write!(f, "scan I/O error: {e}"),
            ScanError::Message(msg) => write!(f, "scan error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScanError::Io(e) => Some(e),
            ScanError::Message(_) => None,
        }
    }
}

impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Trait for scanning the OS for listening ports.
pub trait PortScanner: Send + 'static {
    fn scan(&self) -> Result<HashSet<Listener>, ScanError>;
}

/// Trait for showing desktop notifications.
pub trait Notifier: Send + Sync + 'static {
    fn show(
        &self,
        title: &str,
        body: &str,
        is_error: bool,
        with_sound: bool,
        icon: Option<&std::path::Path>,
    ) -> Result<(), String>;
}

/// The unified platform abstraction.
///
/// Each OS implements this trait once. Generic code uses `P: Platform` or
/// the [`CurrentPlatform`] type alias. Associated types provide platform-specific
/// implementations that can be referenced as `P::Scanner`, `P::Notifier`, etc.
pub trait Platform: Send + Sync + 'static {
    /// Port scanner implementation for this platform.
    type Scanner: PortScanner + Default;

    /// Desktop notification implementation for this platform.
    type Notifier: Notifier + Default;

    // -- Process management --

    /// Find which process is listening on `port` with the given protocol.
    fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo>;

    /// Kill a process by PID. Sends SIGTERM then SIGKILL on Unix,
    /// calls TerminateProcess on Windows.
    fn kill_process(pid: u32) -> Result<(), String>;

    // -- Ephemeral port range --

    /// Detect the OS ephemeral (dynamic) port range.
    /// Returns `None` if detection fails (caller uses a default).
    fn ephemeral_range() -> Option<(u16, u16)>;

    // -- Identity --

    /// Get the current username.
    fn username() -> String;

    // -- Directories (default impls via `dirs` crate) --

    /// Temporary directory.
    fn temp_dir() -> PathBuf {
        std::env::temp_dir()
    }

    /// User's cache directory.
    fn cache_dir() -> Option<PathBuf> {
        dirs::cache_dir()
    }

    /// User's state directory.
    fn state_dir() -> Option<PathBuf> {
        dirs::state_dir()
    }

    /// User's config directory.
    fn config_dir() -> Option<PathBuf> {
        dirs::config_dir()
    }

    /// User's home directory.
    fn home_dir() -> Option<PathBuf> {
        dirs::home_dir()
    }
}

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct Linux;

#[cfg(target_os = "linux")]
impl Platform for Linux {
    type Scanner = linux::ProcNetScanner;
    type Notifier = linux::NotifyRustNotifier;

    fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        linux::process::find_listener(port, proto)
    }
    fn kill_process(pid: u32) -> Result<(), String> {
        unix::kill_process(pid)
    }
    fn ephemeral_range() -> Option<(u16, u16)> {
        linux::ephemeral::detect()
    }
    fn username() -> String {
        unix::username()
    }
}

#[cfg(target_os = "macos")]
pub struct MacOs;

#[cfg(target_os = "macos")]
impl Platform for MacOs {
    type Scanner = StubScanner;
    type Notifier = macos::MacOsNotifier;

    fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        macos::process::find_listener(port, proto)
    }
    fn kill_process(pid: u32) -> Result<(), String> {
        unix::kill_process(pid)
    }
    fn ephemeral_range() -> Option<(u16, u16)> {
        macos::ephemeral::detect()
    }
    fn username() -> String {
        unix::username()
    }
}

#[cfg(target_os = "windows")]
pub struct Windows;

#[cfg(target_os = "windows")]
impl Platform for Windows {
    type Scanner = windows::IpHelperScanner;
    type Notifier = windows::ToastNotifier;

    fn find_listener(port: u16, proto: TransportProto) -> Option<ProcessInfo> {
        windows::process::find_listener(port, proto)
    }
    fn kill_process(pid: u32) -> Result<(), String> {
        windows::process::kill_process(pid)
    }
    fn ephemeral_range() -> Option<(u16, u16)> {
        Some((49152, 65535))
    }
    fn username() -> String {
        windows::username()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub struct Stub;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl Platform for Stub {
    type Scanner = StubScanner;
    type Notifier = StubNotifier;

    fn find_listener(_: u16, _: TransportProto) -> Option<ProcessInfo> {
        None
    }
    fn kill_process(_: u32) -> Result<(), String> {
        Err("not supported on this platform".into())
    }
    fn ephemeral_range() -> Option<(u16, u16)> {
        None
    }
    fn username() -> String {
        "root".to_string()
    }
}

// ---------------------------------------------------------------------------
// Compile-time type alias
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub type CurrentPlatform = Linux;

#[cfg(target_os = "macos")]
pub type CurrentPlatform = MacOs;

#[cfg(target_os = "windows")]
pub type CurrentPlatform = Windows;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub type CurrentPlatform = Stub;
