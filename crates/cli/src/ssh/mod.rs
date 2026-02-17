mod client;
pub(crate) mod config;

pub use client::{HostKeyPolicy, SshChain, SshSession};
pub use config::JumpHost;

/// Resolve SSH config for a host without connecting.
///
/// This is used to check for ProxyJump before deciding how to connect.
pub fn config_for_host(host: &str, user_override: Option<&str>) -> config::SshHostConfig {
    config::resolve_ssh_config(host, user_override)
}
