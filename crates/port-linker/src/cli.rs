use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::path::PathBuf;

/// Log output format.
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable format with colors (if enabled)
    #[default]
    Pretty,
    /// Compact single-line format
    Compact,
    /// JSON format for machine parsing
    Json,
}

/// Color output mode.
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    /// Auto-detect based on terminal capabilities
    #[default]
    Auto,
    /// Always use colors
    Always,
    /// Never use colors
    Never,
}

impl ColorMode {
    /// Determine if colors should be enabled based on mode and terminal detection.
    pub fn should_enable(&self) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => std::io::IsTerminal::is_terminal(&std::io::stderr()),
        }
    }
}

/// Ports excluded by default (common system services that shouldn't be forwarded)
pub const DEFAULT_EXCLUDED_PORTS: &[u16] = &[
    22,    // SSH
    53,    // DNS
    111,   // RPC/portmapper
    631,   // CUPS printing
    5353,  // mDNS
    41641, // Tailscale
];

/// Protocol filter for port discovery and forwarding.
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum ProtocolFilter {
    /// Only forward TCP ports (default, backward compatible)
    #[default]
    Tcp,
    /// Only forward UDP ports
    Udp,
    /// Forward both TCP and UDP ports
    Both,
}

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

    /// Log output format
    #[arg(long = "log-format", value_enum, default_value = "pretty")]
    pub log_format: LogFormat,

    /// Enable colored log output (auto-detected by default)
    #[arg(long = "color", default_value = "auto")]
    pub color: ColorMode,

    /// Port scan interval in milliseconds
    #[arg(long = "scan-interval-ms", default_value = "3000")]
    pub scan_interval_ms: u64,

    /// Path to SSH identity file
    #[arg(short = 'i', long = "identity")]
    pub identity_file: Option<PathBuf>,

    /// SSH port
    #[arg(short = 'P', long = "port", default_value = "22")]
    pub ssh_port: u16,

    /// Protocol to forward: tcp, udp, or both
    #[arg(long = "protocol", value_enum, default_value = "tcp")]
    pub protocol: ProtocolFilter,
}

impl Cli {
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

    /// Check if TCP forwarding is enabled
    pub fn forward_tcp(&self) -> bool {
        matches!(self.protocol, ProtocolFilter::Tcp | ProtocolFilter::Both)
    }

    /// Check if UDP forwarding is enabled
    pub fn forward_udp(&self) -> bool {
        matches!(self.protocol, ProtocolFilter::Udp | ProtocolFilter::Both)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_with(args: &[&str]) -> Cli {
        let mut full_args = vec!["port-linker"];
        full_args.extend_from_slice(args);
        Cli::parse_from(full_args)
    }

    #[test]
    fn test_excluded_ports_defaults() {
        let cli = cli_with(&["host"]);
        let excluded = cli.excluded_ports();
        for &port in DEFAULT_EXCLUDED_PORTS {
            assert!(excluded.contains(&port), "Should contain default port {}", port);
        }
    }

    #[test]
    fn test_excluded_ports_no_defaults() {
        let cli = cli_with(&["host", "--no-default-excludes"]);
        let excluded = cli.excluded_ports();
        assert!(excluded.is_empty());
    }

    #[test]
    fn test_excluded_ports_custom() {
        let cli = cli_with(&["host", "--exclude", "9090,9091"]);
        let excluded = cli.excluded_ports();
        assert!(excluded.contains(&9090));
        assert!(excluded.contains(&9091));
        // Should still include defaults
        assert!(excluded.contains(&22));
    }

    #[test]
    fn test_excluded_ports_custom_no_defaults() {
        let cli = cli_with(&["host", "--no-default-excludes", "--exclude", "9090"]);
        let excluded = cli.excluded_ports();
        assert!(excluded.contains(&9090));
        assert!(!excluded.contains(&22));
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn test_forward_tcp_default() {
        let cli = cli_with(&["host"]);
        assert!(cli.forward_tcp());
        assert!(!cli.forward_udp());
    }

    #[test]
    fn test_forward_udp_only() {
        let cli = cli_with(&["host", "--protocol", "udp"]);
        assert!(!cli.forward_tcp());
        assert!(cli.forward_udp());
    }

    #[test]
    fn test_forward_both() {
        let cli = cli_with(&["host", "--protocol", "both"]);
        assert!(cli.forward_tcp());
        assert!(cli.forward_udp());
    }

    #[test]
    fn test_color_mode_always() {
        assert!(ColorMode::Always.should_enable());
    }

    #[test]
    fn test_color_mode_never() {
        assert!(!ColorMode::Never.should_enable());
    }
}
