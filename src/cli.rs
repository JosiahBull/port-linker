use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;

/// Ports excluded by default (common system services that shouldn't be forwarded)
pub const DEFAULT_EXCLUDED_PORTS: &[u16] = &[
    22,    // SSH
    53,    // DNS
    111,   // RPC/portmapper
    631,   // CUPS printing
    5353,  // mDNS
    41641, // Tailscale
];

#[derive(Parser, Debug, Clone)]
#[command(name = "port-linker")]
#[command(
    author,
    version,
    about = "Connect to remote systems via SSH and forward discovered ports to localhost"
)]
pub struct Cli {
    /// Remote host in format `[user@]host`
    #[arg(value_name = "HOST", default_value = "josiah@avocado")]
    pub host: String,

    /// Only forward specific ports (comma-separated)
    #[arg(short = 'p', long = "ports", value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// Exclude specific ports (comma-separated), in addition to defaults
    #[arg(short = 'x', long = "exclude", value_delimiter = ',')]
    pub exclude: Option<Vec<u16>>,

    /// Don't apply default port exclusions (22, 53, etc.)
    #[arg(long = "no-default-excludes")]
    pub no_default_excludes: bool,

    /// Automatically kill conflicting local processes
    #[arg(long = "auto-kill")]
    pub auto_kill: bool,

    /// Disable desktop notifications
    #[arg(long = "no-notifications")]
    pub no_notifications: bool,

    /// Disable notification sounds
    #[arg(long = "no-sound")]
    pub no_sound: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long = "log-level", default_value = "info")]
    pub log_level: String,

    /// Port scan interval in seconds
    #[arg(long = "scan-interval", default_value = "3")]
    pub scan_interval: u64,

    /// Path to SSH identity file
    #[arg(short = 'i', long = "identity")]
    pub identity_file: Option<PathBuf>,

    /// SSH port
    #[arg(short = 'P', long = "port", default_value = "22")]
    pub ssh_port: u16,
}

#[derive(Debug, Clone)]
pub struct ParsedHost {
    pub user: Option<String>,
    pub host: String,
}

impl Cli {
    pub fn parse_host(&self) -> ParsedHost {
        if let Some((user, host)) = self.host.split_once('@') {
            ParsedHost {
                user: Some(user.to_string()),
                host: host.to_string(),
            }
        } else {
            ParsedHost {
                user: None,
                host: self.host.clone(),
            }
        }
    }

    /// Get the set of ports to exclude from forwarding
    pub fn excluded_ports(&self) -> HashSet<u16> {
        let mut excluded = HashSet::new();

        // Add default exclusions unless disabled
        if !self.no_default_excludes {
            excluded.extend(DEFAULT_EXCLUDED_PORTS.iter().copied());
        }

        // Add user-specified exclusions
        if let Some(ref ports) = self.exclude {
            excluded.extend(ports.iter().copied());
        }

        excluded
    }
}
