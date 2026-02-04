use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Port descriptions loaded from a mapping file
#[derive(Debug, Default)]
pub struct PortMapping {
    descriptions: HashMap<u16, String>,
}

impl PortMapping {
    /// Load port mappings from the default config location
    pub fn load_default() -> Self {
        let paths = [
            dirs::config_dir().map(|p| p.join("port-linker").join("ports.toml")),
            dirs::home_dir().map(|p| p.join(".port-linker.toml")),
        ];

        for path in paths.into_iter().flatten() {
            if path.exists() {
                debug!("Loading port mapping from {:?}", path);
                if let Some(mapping) = Self::load_from_file(&path) {
                    return mapping;
                }
            }
        }

        Self::default()
    }

    /// Load port mappings from a specific file
    pub fn load_from_file(path: &PathBuf) -> Option<Self> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read port mapping file {:?}: {}", path, e);
                return None;
            }
        };

        Self::parse(&content)
    }

    /// Parse port mappings from TOML content
    ///
    /// Supported formats:
    /// ```toml
    /// # Simple format
    /// 8080 = "Web Server"
    /// 3000 = "React Dev"
    ///
    /// # Or under [ports] section
    /// [ports]
    /// 5432 = "PostgreSQL"
    /// ```
    fn parse(content: &str) -> Option<Self> {
        let mut descriptions = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments, empty lines, and section headers
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            // Parse key = "value" or key = 'value'
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                // Parse port number
                if let Ok(port) = key.parse::<u16>() {
                    // Remove quotes from value
                    let desc = value
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .to_string();

                    if !desc.is_empty() {
                        descriptions.insert(port, desc);
                    }
                }
            }
        }

        if descriptions.is_empty() {
            debug!("No port mappings found in file");
        } else {
            debug!("Loaded {} port mappings", descriptions.len());
        }

        Some(Self { descriptions })
    }

    /// Get description for a port, with fallback to process name
    pub fn describe(&self, port: u16, process_name: Option<&str>) -> String {
        if let Some(desc) = self.descriptions.get(&port) {
            desc.clone()
        } else if let Some(name) = process_name {
            name.to_string()
        } else {
            format!("port {}", port)
        }
    }

    /// Get description for a port only if it exists in the mapping
    #[allow(dead_code)]
    pub fn get(&self, port: u16) -> Option<&str> {
        self.descriptions.get(&port).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let content = r#"
8080 = "Web Server"
3000 = "React Dev Server"
5432 = 'PostgreSQL'
"#;
        let mapping = PortMapping::parse(content).unwrap();
        assert_eq!(mapping.get(8080), Some("Web Server"));
        assert_eq!(mapping.get(3000), Some("React Dev Server"));
        assert_eq!(mapping.get(5432), Some("PostgreSQL"));
    }

    #[test]
    fn test_parse_with_section() {
        let content = r#"
# Port descriptions
[ports]
8080 = "Web Server"
3000 = "React Dev"
"#;
        let mapping = PortMapping::parse(content).unwrap();
        assert_eq!(mapping.get(8080), Some("Web Server"));
        assert_eq!(mapping.get(3000), Some("React Dev"));
    }

    #[test]
    fn test_describe_fallback() {
        let mapping = PortMapping::default();
        assert_eq!(mapping.describe(8080, Some("node")), "node");
        assert_eq!(mapping.describe(8080, None), "port 8080");
    }
}
