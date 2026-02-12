mod client;
pub(crate) mod config;

use std::time::Duration;

pub use client::{HostKeyPolicy, SshChain, SshSession};
pub use config::JumpHost;

/// Resolve SSH config for a host without connecting.
///
/// This is used to check for ProxyJump before deciding how to connect.
pub fn config_for_host(host: &str, user_override: Option<&str>) -> config::SshHostConfig {
    config::resolve_ssh_config(host, user_override)
}

/// Abstraction over SSH command execution.
///
/// Implemented by `SshSession` for real SSH connections and by `MockSshExecutor`
/// in tests. This enables testing bootstrap logic without a live SSH server.
pub trait SshExecutor: Send + Sync {
    /// Execute a command and return (stdout, stderr, exit_code).
    fn exec(
        &self,
        command: &str,
    ) -> impl std::future::Future<Output = common::Result<(String, String, Option<u32>)>> + Send;

    /// Execute a command with data piped to stdin.
    fn exec_with_stdin(
        &self,
        command: &str,
        data: &[u8],
    ) -> impl std::future::Future<Output = common::Result<(String, String, Option<u32>)>> + Send;

    /// Execute a command and read stdout line-by-line until a predicate returns true.
    fn exec_and_read_lines(
        &self,
        command: &str,
        timeout: Duration,
        predicate: impl FnMut(&str) -> bool + Send,
    ) -> impl std::future::Future<Output = common::Result<Vec<String>>> + Send;

    /// Execute a fire-and-forget command.
    fn exec_detached(
        &self,
        command: &str,
    ) -> impl std::future::Future<Output = common::Result<()>> + Send;
}

impl SshExecutor for SshSession {
    async fn exec(&self, command: &str) -> common::Result<(String, String, Option<u32>)> {
        self.exec(command).await
    }

    async fn exec_with_stdin(
        &self,
        command: &str,
        data: &[u8],
    ) -> common::Result<(String, String, Option<u32>)> {
        self.exec_with_stdin(command, data).await
    }

    async fn exec_and_read_lines(
        &self,
        command: &str,
        timeout: Duration,
        predicate: impl FnMut(&str) -> bool + Send,
    ) -> common::Result<Vec<String>> {
        self.exec_and_read_lines(command, timeout, predicate).await
    }

    async fn exec_detached(&self, command: &str) -> common::Result<()> {
        self.exec_detached(command).await
    }
}
