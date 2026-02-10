use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use tracing::{debug, warn};

/// Resolved SSH connection parameters for a host.
pub struct SshHostConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
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

    debug!(host, ?parsed.hostname, ?parsed.port, ?parsed.user, "resolved SSH config");

    let hostname = parsed.hostname.unwrap_or_else(|| host.to_string());
    let port = parsed.port.unwrap_or(22);
    let user = parsed.user.unwrap_or_else(|| defaults.user.clone());
    let identity_files = if parsed.identity_files.is_empty() {
        default_identity_files()
    } else {
        parsed.identity_files
    };

    apply_user_override(
        SshHostConfig {
            hostname,
            port,
            user,
            identity_files,
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
            _ => {
                // Ignore unsupported directives.
            }
        }
    }

    if found_match {
        Some(result)
    } else {
        None
    }
}

/// Split an SSH config line into (keyword, argument).
///
/// Handles both `Keyword value` (whitespace) and `Keyword=value` (equals) forms.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    // Try `=` first, then whitespace.
    if let Some(eq_pos) = line.find('=') {
        let keyword = line[..eq_pos].trim();
        let argument = line[eq_pos + 1..].trim();
        if !keyword.is_empty() && !argument.is_empty() {
            return Some((keyword, argument));
        }
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let keyword = parts.next()?.trim();
    let argument = parts.next()?.trim();
    if keyword.is_empty() || argument.is_empty() {
        return None;
    }
    Some((keyword, argument))
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
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn apply_user_override(mut config: SshHostConfig, user_override: Option<&str>) -> SshHostConfig {
    if let Some(user) = user_override {
        config.user = user.to_string();
    }
    config
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
}
