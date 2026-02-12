use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use tracing::{debug, warn};

/// A single jump host in a ProxyJump chain.
#[derive(Debug, Clone)]
pub struct JumpHost {
    pub user: Option<String>,
    pub hostname: String,
    pub port: u16,
    /// Identity files resolved from SSH config for this jump host.
    pub identity_files: Vec<PathBuf>,
}

/// Resolved SSH connection parameters for a host.
pub struct SshHostConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<Vec<JumpHost>>,
}

/// Resolve SSH connection parameters from ~/.ssh/config.
///
/// Falls back to sensible defaults if the config file doesn't exist or
/// doesn't have a matching entry for the host.
pub fn resolve_ssh_config(host: &str, user_override: Option<&str>) -> SshHostConfig {
    let defaults = SshHostConfig {
        hostname: host.to_string(),
        port: 22,
        user: whoami(),
        identity_files: default_identity_files(),
        proxy_jump: None,
    };

    let config_path = match dirs::home_dir() {
        Some(home) => home.join(".ssh").join("config"),
        None => return apply_user_override(defaults, user_override),
    };

    if !config_path.exists() {
        debug!("no SSH config at {}", config_path.display());
        return apply_user_override(defaults, user_override);
    }

    let file = match std::fs::File::open(&config_path) {
        Ok(f) => f,
        Err(e) => {
            warn!(%e, "failed to open SSH config");
            return apply_user_override(defaults, user_override);
        }
    };

    let parsed = match parse_ssh_config(BufReader::new(file), host) {
        Some(p) => p,
        None => return apply_user_override(defaults, user_override),
    };

    debug!(host, ?parsed.hostname, ?parsed.port, ?parsed.user, ?parsed.proxy_jump, "resolved SSH config");

    let hostname = parsed.hostname.unwrap_or_else(|| host.to_string());
    let port = parsed.port.unwrap_or(22);
    let user = parsed.user.unwrap_or_else(|| defaults.user.clone());
    let identity_files = if parsed.identity_files.is_empty() {
        default_identity_files()
    } else {
        parsed.identity_files
    };
    let proxy_jump = parsed
        .proxy_jump
        .and_then(|pj| parse_proxy_jump(&pj, &config_path));

    apply_user_override(
        SshHostConfig {
            hostname,
            port,
            user,
            identity_files,
            proxy_jump,
        },
        user_override,
    )
}

// ---------------------------------------------------------------------------
// SSH config parser
// ---------------------------------------------------------------------------

/// Raw parsed values from a matching Host block (all optional).
#[derive(Default, Debug)]
struct ParsedHost {
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_files: Vec<PathBuf>,
    proxy_jump: Option<String>,
}

/// Parse `~/.ssh/config` and extract directives for the matching `Host` block.
///
/// Supports the subset of SSH config directives that matter for port-linker:
/// `Host`, `Hostname`, `Port`, `User`, `IdentityFile`.
///
/// Wildcard `Host *` entries are applied as defaults (lowest priority).
/// The first specific match wins for each directive, matching OpenSSH semantics
/// where the first obtained value for each parameter is used.
fn parse_ssh_config(reader: impl BufRead, target_host: &str) -> Option<ParsedHost> {
    let mut result = ParsedHost::default();
    let mut in_matching_block = false;
    // Track whether we ever found a matching block.
    let mut found_match = false;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();

        // Skip empty lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split into keyword and argument. SSH config uses whitespace or `=`.
        let (keyword, argument) = match split_directive(trimmed) {
            Some(pair) => pair,
            None => continue,
        };

        if keyword.eq_ignore_ascii_case("Host") {
            // Check if any pattern in the Host line matches our target.
            in_matching_block = argument
                .split_whitespace()
                .any(|pattern| host_pattern_matches(pattern, target_host));
            if in_matching_block {
                found_match = true;
            }
            continue;
        }

        if !in_matching_block {
            continue;
        }

        // Apply directives — first value wins (don't overwrite if already set).
        match keyword.to_ascii_lowercase().as_str() {
            "hostname" => {
                if result.hostname.is_none() {
                    result.hostname = Some(argument.to_string());
                }
            }
            "port" => {
                if result.port.is_none() {
                    result.port = argument.parse().ok();
                }
            }
            "user" => {
                if result.user.is_none() {
                    result.user = Some(argument.to_string());
                }
            }
            "identityfile" => {
                let expanded = expand_tilde(argument);
                result.identity_files.push(PathBuf::from(expanded));
            }
            "proxyjump" => {
                if result.proxy_jump.is_none() {
                    result.proxy_jump = Some(argument.to_string());
                }
            }
            _ => {
                // Ignore unsupported directives.
            }
        }
    }

    if found_match { Some(result) } else { None }
}

/// Split an SSH config line into (keyword, argument).
///
/// Handles both `Keyword value` (whitespace) and `Keyword=value` (equals) forms.
/// Strips inline comments (` #...` or `\t#...`) from the argument.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    // Try `=` first, then whitespace.
    if let Some(eq_pos) = line.find('=') {
        let keyword = line[..eq_pos].trim();
        let argument = strip_inline_comment(line[eq_pos + 1..].trim());
        if !keyword.is_empty() && !argument.is_empty() {
            return Some((keyword, argument));
        }
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let keyword = parts.next()?.trim();
    let argument = strip_inline_comment(parts.next()?.trim());
    if keyword.is_empty() || argument.is_empty() {
        return None;
    }
    Some((keyword, argument))
}

/// Strip an inline comment from an SSH config argument value.
///
/// OpenSSH treats `#` as an inline comment when preceded by whitespace.
/// For example: `avocado  # this is a comment` -> `avocado`
///
/// A `#` at the very start of the argument is NOT stripped here because
/// full-line comments are handled earlier in the parser. A `#` embedded
/// inside a value without preceding whitespace (e.g. `foo#bar`) is kept.
fn strip_inline_comment(value: &str) -> &str {
    // Search for ` #` or `\t#` — a hash preceded by whitespace.
    // We scan byte-by-byte to find the first such occurrence.
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return value[..i].trim_end();
        }
    }
    value
}

/// Match a Host pattern against a target hostname.
///
/// Supports `*` as a glob wildcard (matches anything) and `?` as a single
/// character wildcard. Negated patterns (`!pattern`) are not supported.
fn host_pattern_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == target;
    }
    // Simple glob: convert to a char-by-char match.
    glob_match(pattern.as_bytes(), target.as_bytes())
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Expand `~` at the start of a path to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    path.to_string()
}

/// Parse a ProxyJump value into a chain of jump hosts.
///
/// Handles:
/// - `"none"` -> `None` (disables ProxyJump)
/// - `"host"` -> single hop
/// - `"user@host:port"` -> full format
/// - `"hop1,hop2,hop3"` -> comma-separated chain
///
/// Each jump host's hostname is recursively resolved through the SSH config
/// to pick up its own `Hostname`, `Port`, `User`, `IdentityFile`.
fn parse_proxy_jump(value: &str, config_path: &std::path::Path) -> Option<Vec<JumpHost>> {
    if value.eq_ignore_ascii_case("none") {
        return None;
    }

    let hops: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
    let mut result = Vec::with_capacity(hops.len());
    let mut visited = HashSet::new();

    for hop in hops {
        if hop.is_empty() {
            continue;
        }
        if let Some(jump) = resolve_jump_host(hop, config_path, &mut visited) {
            result.push(jump);
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse a single jump host spec (`[user@]host[:port]`) and resolve it
/// through the SSH config.
fn resolve_jump_host(
    spec: &str,
    config_path: &std::path::Path,
    visited: &mut HashSet<String>,
) -> Option<JumpHost> {
    // Parse [user@]host[:port]
    let (user_part, host_port) = if let Some(at_pos) = spec.find('@') {
        (Some(&spec[..at_pos]), &spec[at_pos + 1..])
    } else {
        (None, spec)
    };

    let (host, port_part) = if let Some(colon_pos) = host_port.rfind(':') {
        let maybe_port = &host_port[colon_pos + 1..];
        if maybe_port.parse::<u16>().is_ok() {
            (&host_port[..colon_pos], Some(maybe_port))
        } else {
            (host_port, None)
        }
    } else {
        (host_port, None)
    };

    // Prevent infinite recursion.
    if !visited.insert(host.to_string()) {
        warn!(host, "circular ProxyJump reference detected, skipping");
        return None;
    }

    // Resolve the jump host through SSH config to pick up Hostname, Port, etc.
    let resolved = resolve_jump_host_from_config(host, config_path);

    let hostname = resolved
        .as_ref()
        .and_then(|r| r.hostname.clone())
        .unwrap_or_else(|| host.to_string());

    let port = port_part
        .and_then(|p| p.parse::<u16>().ok())
        .or(resolved.as_ref().and_then(|r| r.port))
        .unwrap_or(22);

    let user = user_part
        .map(|u| u.to_string())
        .or(resolved.as_ref().and_then(|r| r.user.clone()));

    let identity_files = resolved
        .as_ref()
        .map(|r| r.identity_files.clone())
        .unwrap_or_default();

    Some(JumpHost {
        user,
        hostname,
        port,
        identity_files,
    })
}

/// Resolve a jump host alias through the SSH config file (without recursing
/// into its own ProxyJump to avoid infinite loops).
fn resolve_jump_host_from_config(host: &str, config_path: &std::path::Path) -> Option<ParsedHost> {
    let file = std::fs::File::open(config_path).ok()?;
    parse_ssh_config(BufReader::new(file), host)
}

fn apply_user_override(mut config: SshHostConfig, user_override: Option<&str>) -> SshHostConfig {
    if let Some(user) = user_override {
        config.user = user.to_string();
    }
    config
}

/// Public accessor for `whoami()` used by `SshChain`.
pub(super) fn whoami_pub() -> String {
    whoami()
}

/// Public accessor for `default_identity_files()` used by `SshChain`.
pub(super) fn default_identity_files_pub() -> Vec<PathBuf> {
    default_identity_files()
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

fn default_identity_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    let ssh_dir = home.join(".ssh");
    // Try common key types in order of preference.
    let candidates = ["id_ed25519", "id_rsa", "id_ecdsa"];
    candidates
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|p| p.exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whoami_fallback() {
        let user = whoami();
        assert!(!user.is_empty(), "whoami should return non-empty user");
    }

    #[test]
    fn test_apply_user_override_with_override() {
        let config = SshHostConfig {
            hostname: "test-host".to_string(),
            port: 22,
            user: "default-user".to_string(),
            identity_files: vec![],
            proxy_jump: None,
        };

        let config = apply_user_override(config, Some("override-user"));
        assert_eq!(config.user, "override-user");
    }

    #[test]
    fn test_apply_user_override_without_override() {
        let config = SshHostConfig {
            hostname: "test-host".to_string(),
            port: 22,
            user: "default-user".to_string(),
            identity_files: vec![],
            proxy_jump: None,
        };

        let config = apply_user_override(config, None);
        assert_eq!(config.user, "default-user");
    }

    #[test]
    fn test_default_identity_files_order() {
        let files = default_identity_files();
        let filenames: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .collect();

        if filenames.len() > 1 {
            let expected_order = ["id_ed25519", "id_rsa", "id_ecdsa"];
            for i in 0..filenames.len().saturating_sub(1) {
                let pos1 = expected_order
                    .iter()
                    .position(|&x| x == filenames[i])
                    .unwrap();
                let pos2 = expected_order
                    .iter()
                    .position(|&x| x == filenames[i + 1])
                    .unwrap();
                assert!(pos1 < pos2, "keys should be in preference order");
            }
        }
    }

    #[test]
    fn test_resolve_ssh_config_nonexistent_file() {
        let host = "nonexistent-host";
        let config = resolve_ssh_config(host, None);

        assert_eq!(config.hostname, host);
        assert_eq!(config.port, 22);
        assert!(!config.user.is_empty());
    }

    #[test]
    fn test_resolve_ssh_config_with_user_override() {
        let host = "test-host";
        let config = resolve_ssh_config(host, Some("custom-user"));
        assert_eq!(config.user, "custom-user");
    }

    #[test]
    fn test_ssh_host_config_construction() {
        let config = SshHostConfig {
            hostname: "example.com".to_string(),
            port: 2222,
            user: "testuser".to_string(),
            identity_files: vec![PathBuf::from("/path/to/key")],
            proxy_jump: None,
        };

        assert_eq!(config.hostname, "example.com");
        assert_eq!(config.port, 2222);
        assert_eq!(config.user, "testuser");
        assert_eq!(config.identity_files.len(), 1);
    }

    #[test]
    fn test_default_port() {
        let config = resolve_ssh_config("any-host", None);
        assert_eq!(config.port, 22);
    }

    // ----- Parser unit tests -----

    #[test]
    fn parse_simple_host_block() {
        let config = "\
Host myserver
    Hostname 10.0.0.5
    Port 2222
    User admin
    IdentityFile ~/.ssh/id_custom
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.user.as_deref(), Some("admin"));
        assert_eq!(parsed.identity_files.len(), 1);
    }

    #[test]
    fn parse_wildcard_block() {
        let config = "\
Host *
    User globaluser
    Port 22
";
        let parsed = parse_ssh_config(config.as_bytes(), "anything").unwrap();
        assert_eq!(parsed.user.as_deref(), Some("globaluser"));
        assert_eq!(parsed.port, Some(22));
    }

    #[test]
    fn parse_first_match_wins() {
        let config = "\
Host myserver
    User specific

Host *
    User fallback
    Hostname default.example.com
";
        // The specific block matches first; its User takes priority.
        // But Hostname is only in the wildcard, so it should be picked up.
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.user.as_deref(), Some("specific"));
        // Hostname from wildcard should NOT apply because first-value-wins
        // only applies within matching blocks. In OpenSSH, all matching
        // blocks contribute, and the FIRST value for each key wins.
        // Our parser processes blocks sequentially with in_matching_block,
        // so it only processes the specific block.
    }

    #[test]
    fn parse_no_match_returns_none() {
        let config = "\
Host other
    Hostname other.example.com
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_equals_syntax() {
        let config = "\
Host myserver
    Hostname=10.0.0.5
    Port=2222
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(2222));
    }

    #[test]
    fn parse_comments_and_blanks() {
        let config = "\
# This is a comment
Host myserver
    # Another comment
    Hostname 10.0.0.5

    Port 22
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(22));
    }

    #[test]
    fn parse_case_insensitive_keywords() {
        let config = "\
host myserver
    hostname 10.0.0.5
    PORT 2222
    USER admin
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.user.as_deref(), Some("admin"));
    }

    #[test]
    fn host_pattern_glob() {
        assert!(host_pattern_matches("*", "anything"));
        assert!(host_pattern_matches("server-*", "server-prod"));
        assert!(!host_pattern_matches("server-*", "other-prod"));
        assert!(host_pattern_matches("server-?", "server-1"));
        assert!(!host_pattern_matches("server-?", "server-12"));
        assert!(host_pattern_matches("exact", "exact"));
        assert!(!host_pattern_matches("exact", "other"));
    }

    #[test]
    fn split_directive_whitespace() {
        let (k, v) = split_directive("Hostname 10.0.0.5").unwrap();
        assert_eq!(k, "Hostname");
        assert_eq!(v, "10.0.0.5");
    }

    #[test]
    fn split_directive_equals() {
        let (k, v) = split_directive("Hostname=10.0.0.5").unwrap();
        assert_eq!(k, "Hostname");
        assert_eq!(v, "10.0.0.5");
    }

    #[test]
    fn expand_tilde_with_home() {
        let expanded = expand_tilde("~/.ssh/id_rsa");
        assert!(
            !expanded.starts_with('~'),
            "tilde should be expanded: {expanded}"
        );
        assert!(expanded.ends_with(".ssh/id_rsa"));
    }

    #[test]
    fn expand_tilde_absolute_path() {
        let path = "/absolute/path";
        assert_eq!(expand_tilde(path), path);
    }

    #[test]
    fn parse_proxy_jump_single() {
        let config = "\
Host target
    Hostname 10.0.0.5
    ProxyJump jump1
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("jump1"));
    }

    #[test]
    fn parse_proxy_jump_chain() {
        let config = "\
Host target
    Hostname 10.0.0.5
    ProxyJump jump1,jump2
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("jump1,jump2"));
    }

    #[test]
    fn parse_proxy_jump_none() {
        let config = "\
Host target
    Hostname 10.0.0.5
    ProxyJump none
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("none"));
        // parse_proxy_jump("none") should return None (disables ProxyJump)
    }

    #[test]
    fn parse_proxy_jump_first_value_wins() {
        let config = "\
Host target
    ProxyJump jump1
    ProxyJump jump2
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("jump1"));
    }

    #[test]
    fn parse_proxy_jump_with_user_and_port() {
        let config = "\
Host target
    ProxyJump admin@jump1:2222
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("admin@jump1:2222"));
    }

    #[test]
    fn resolve_jump_host_simple() {
        let mut visited = HashSet::new();
        let jump = resolve_jump_host("myhost", std::path::Path::new("/nonexistent"), &mut visited)
            .unwrap();
        assert_eq!(jump.hostname, "myhost");
        assert_eq!(jump.port, 22);
        assert!(jump.user.is_none());
    }

    #[test]
    fn resolve_jump_host_with_user_and_port() {
        let mut visited = HashSet::new();
        let jump = resolve_jump_host(
            "admin@myhost:2222",
            std::path::Path::new("/nonexistent"),
            &mut visited,
        )
        .unwrap();
        assert_eq!(jump.hostname, "myhost");
        assert_eq!(jump.port, 2222);
        assert_eq!(jump.user.as_deref(), Some("admin"));
    }

    #[test]
    fn resolve_jump_host_circular_detection() {
        let mut visited = HashSet::new();
        visited.insert("myhost".to_string());
        let jump = resolve_jump_host("myhost", std::path::Path::new("/nonexistent"), &mut visited);
        assert!(jump.is_none());
    }

    // ----- Inline comment stripping tests -----

    #[test]
    fn strip_inline_comment_basic() {
        assert_eq!(strip_inline_comment("value # comment"), "value");
    }

    #[test]
    fn strip_inline_comment_no_comment() {
        assert_eq!(strip_inline_comment("value"), "value");
    }

    #[test]
    fn strip_inline_comment_hash_without_space() {
        // A `#` not preceded by whitespace should be kept.
        assert_eq!(strip_inline_comment("foo#bar"), "foo#bar");
    }

    #[test]
    fn strip_inline_comment_tab_before_hash() {
        assert_eq!(strip_inline_comment("value\t# comment"), "value");
    }

    #[test]
    fn strip_inline_comment_multiple_hashes() {
        // Only the first ` #` should trigger stripping.
        assert_eq!(strip_inline_comment("value # comment # more"), "value");
    }

    #[test]
    fn strip_inline_comment_trailing_spaces() {
        assert_eq!(strip_inline_comment("value   # comment"), "value");
    }

    #[test]
    fn parse_hostname_with_inline_comment() {
        let config = "\
Host myserver
    Hostname 10.0.0.5 # internal IP
    Port 2222  # custom port
    User admin # admin user
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.user.as_deref(), Some("admin"));
    }

    #[test]
    fn parse_proxy_jump_with_inline_comment() {
        let config = "\
Host target
    Hostname 10.0.0.5
    ProxyJump avocado             # Bounces through the host defined above
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("avocado"));
    }

    #[test]
    fn parse_proxy_jump_chain_with_inline_comment() {
        let config = "\
Host target
    Hostname 10.0.0.5
    ProxyJump jump1,jump2 # two hops
";
        let parsed = parse_ssh_config(config.as_bytes(), "target").unwrap();
        assert_eq!(parsed.proxy_jump.as_deref(), Some("jump1,jump2"));
    }

    #[test]
    fn parse_identity_file_with_inline_comment() {
        let config = "\
Host myserver
    IdentityFile /path/to/key # my key
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.identity_files.len(), 1);
        assert_eq!(parsed.identity_files[0], PathBuf::from("/path/to/key"));
    }

    #[test]
    fn parse_equals_syntax_with_inline_comment() {
        let config = "\
Host myserver
    Hostname=10.0.0.5 # equals syntax
    Port=2222 # port
";
        let parsed = parse_ssh_config(config.as_bytes(), "myserver").unwrap();
        assert_eq!(parsed.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.port, Some(2222));
    }
}
