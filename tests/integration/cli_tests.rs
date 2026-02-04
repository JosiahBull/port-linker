//! CLI parsing and configuration tests

use clap::Parser;
use std::collections::HashSet;

// We need to test the CLI module, so we'll replicate the key structures here
// to avoid needing to expose the entire crate as a library

/// Ports excluded by default
const DEFAULT_EXCLUDED_PORTS: &[u16] = &[22, 53, 111, 631, 5353, 41641];

#[derive(Parser, Debug, Clone)]
#[command(name = "port-linker")]
struct TestCli {
    #[arg(value_name = "HOST", default_value = "test@localhost")]
    pub host: String,

    #[arg(short = 'p', long = "ports", value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    #[arg(short = 'x', long = "exclude", value_delimiter = ',')]
    pub exclude: Option<Vec<u16>>,

    #[arg(long = "no-default-excludes")]
    pub no_default_excludes: bool,

    #[arg(long = "auto-kill")]
    pub auto_kill: bool,

    #[arg(long = "no-notifications")]
    pub no_notifications: bool,

    #[arg(long = "no-sound")]
    pub no_sound: bool,

    #[arg(long = "log-level", default_value = "info")]
    pub log_level: String,

    #[arg(long = "scan-interval", default_value = "3")]
    pub scan_interval: u64,

    #[arg(short = 'P', long = "port", default_value = "22")]
    pub ssh_port: u16,
}

#[derive(Debug, Clone)]
struct ParsedHost {
    pub user: Option<String>,
    pub host: String,
}

impl TestCli {
    fn parse_host(&self) -> ParsedHost {
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

    fn excluded_ports(&self) -> HashSet<u16> {
        let mut excluded = HashSet::new();

        if !self.no_default_excludes {
            excluded.extend(DEFAULT_EXCLUDED_PORTS.iter().copied());
        }

        if let Some(ref ports) = self.exclude {
            excluded.extend(ports.iter().copied());
        }

        excluded
    }
}

#[test]
fn test_parse_host_with_user() {
    let cli = TestCli::parse_from(["port-linker", "alice@example.com"]);
    let parsed = cli.parse_host();

    assert_eq!(parsed.user, Some("alice".to_string()));
    assert_eq!(parsed.host, "example.com");
}

#[test]
fn test_parse_host_without_user() {
    let cli = TestCli::parse_from(["port-linker", "example.com"]);
    let parsed = cli.parse_host();

    assert_eq!(parsed.user, None);
    assert_eq!(parsed.host, "example.com");
}

#[test]
fn test_parse_host_with_complex_username() {
    let cli = TestCli::parse_from(["port-linker", "user.name@sub.example.com"]);
    let parsed = cli.parse_host();

    assert_eq!(parsed.user, Some("user.name".to_string()));
    assert_eq!(parsed.host, "sub.example.com");
}

#[test]
fn test_port_whitelist() {
    let cli = TestCli::parse_from(["port-linker", "host", "-p", "8080,3000,5432"]);

    assert_eq!(cli.ports, Some(vec![8080, 3000, 5432]));
}

#[test]
fn test_port_whitelist_single() {
    let cli = TestCli::parse_from(["port-linker", "host", "-p", "8080"]);

    assert_eq!(cli.ports, Some(vec![8080]));
}

#[test]
fn test_port_exclusion() {
    let cli = TestCli::parse_from(["port-linker", "host", "-x", "9000,9001"]);
    let excluded = cli.excluded_ports();

    // Should have defaults + custom
    assert!(excluded.contains(&22)); // default
    assert!(excluded.contains(&9000)); // custom
    assert!(excluded.contains(&9001)); // custom
}

#[test]
fn test_default_excluded_ports() {
    let cli = TestCli::parse_from(["port-linker", "host"]);
    let excluded = cli.excluded_ports();

    // All defaults should be present
    assert!(excluded.contains(&22)); // SSH
    assert!(excluded.contains(&53)); // DNS
    assert!(excluded.contains(&111)); // RPC
    assert!(excluded.contains(&631)); // CUPS
    assert!(excluded.contains(&5353)); // mDNS
    assert!(excluded.contains(&41641)); // Tailscale

    // Random ports should not be excluded
    assert!(!excluded.contains(&8080));
    assert!(!excluded.contains(&3000));
}

#[test]
fn test_no_default_excludes() {
    let cli = TestCli::parse_from(["port-linker", "host", "--no-default-excludes"]);
    let excluded = cli.excluded_ports();

    // Should be empty
    assert!(excluded.is_empty());
}

#[test]
fn test_no_default_excludes_with_custom() {
    let cli = TestCli::parse_from(["port-linker", "host", "--no-default-excludes", "-x", "9000"]);
    let excluded = cli.excluded_ports();

    // Only custom exclusion
    assert_eq!(excluded.len(), 1);
    assert!(excluded.contains(&9000));
    assert!(!excluded.contains(&22)); // Default not present
}

#[test]
fn test_auto_kill_flag() {
    let cli = TestCli::parse_from(["port-linker", "host", "--auto-kill"]);
    assert!(cli.auto_kill);

    let cli = TestCli::parse_from(["port-linker", "host"]);
    assert!(!cli.auto_kill);
}

#[test]
fn test_notification_flags() {
    let cli = TestCli::parse_from(["port-linker", "host", "--no-notifications", "--no-sound"]);
    assert!(cli.no_notifications);
    assert!(cli.no_sound);

    let cli = TestCli::parse_from(["port-linker", "host"]);
    assert!(!cli.no_notifications);
    assert!(!cli.no_sound);
}

#[test]
fn test_log_level() {
    let cli = TestCli::parse_from(["port-linker", "host", "--log-level", "debug"]);
    assert_eq!(cli.log_level, "debug");

    let cli = TestCli::parse_from(["port-linker", "host"]);
    assert_eq!(cli.log_level, "info"); // default
}

#[test]
fn test_scan_interval() {
    let cli = TestCli::parse_from(["port-linker", "host", "--scan-interval", "10"]);
    assert_eq!(cli.scan_interval, 10);

    let cli = TestCli::parse_from(["port-linker", "host"]);
    assert_eq!(cli.scan_interval, 3); // default
}

#[test]
fn test_ssh_port() {
    let cli = TestCli::parse_from(["port-linker", "host", "-P", "2222"]);
    assert_eq!(cli.ssh_port, 2222);

    let cli = TestCli::parse_from(["port-linker", "host"]);
    assert_eq!(cli.ssh_port, 22); // default
}

#[test]
fn test_combined_options() {
    let cli = TestCli::parse_from([
        "port-linker",
        "deploy@prod.example.com",
        "-p",
        "8080,3000",
        "-x",
        "9000",
        "--auto-kill",
        "--no-sound",
        "--log-level",
        "warn",
        "--scan-interval",
        "5",
        "-P",
        "2222",
    ]);

    let parsed = cli.parse_host();
    assert_eq!(parsed.user, Some("deploy".to_string()));
    assert_eq!(parsed.host, "prod.example.com");
    assert_eq!(cli.ports, Some(vec![8080, 3000]));
    assert!(cli.auto_kill);
    assert!(cli.no_sound);
    assert!(!cli.no_notifications);
    assert_eq!(cli.log_level, "warn");
    assert_eq!(cli.scan_interval, 5);
    assert_eq!(cli.ssh_port, 2222);

    let excluded = cli.excluded_ports();
    assert!(excluded.contains(&9000)); // custom
    assert!(excluded.contains(&22)); // default
}
