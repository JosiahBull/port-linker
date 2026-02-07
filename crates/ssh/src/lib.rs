//! SSH client, port scanner, and process management for port-linker.
//!
//! This crate provides:
//! - SSH client for connecting to remote hosts
//! - Port scanner for discovering listening ports on remote hosts
//! - Process detection and management for local port conflicts

pub mod client;
pub mod error;
pub mod handler;
pub mod process;
pub mod scanner;

pub use client::{ParsedHost, SshClient, SshClientConfig};
pub use error::{Result, SshError};
pub use handler::ClientHandler;
pub use process::{find_process_on_port, kill_process, prompt_kill, ProcessInfo};
pub use scanner::Scanner;

// Re-export RemotePort from scanner for downstream compatibility
pub use ::scanner::{BindAddress, RemotePort};
