//! Port mapping tests using fixture files

use crate::common::read_fixture;
use std::collections::HashMap;

/// Simplified port mapping for testing
#[derive(Debug, Default)]
struct PortMapping {
    descriptions: HashMap<u16, String>,
}

impl PortMapping {
    fn parse(content: &str) -> Option<Self> {
        let mut descriptions = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if let Ok(port) = key.parse::<u16>() {
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

        Some(Self { descriptions })
    }

    fn get(&self, port: u16) -> Option<&str> {
        self.descriptions.get(&port).map(|s| s.as_str())
    }

    fn describe(&self, port: u16, process_name: Option<&str>) -> String {
        if let Some(desc) = self.descriptions.get(&port) {
            desc.clone()
        } else if let Some(name) = process_name {
            name.to_string()
        } else {
            format!("port {}", port)
        }
    }
}

#[test]
fn test_load_custom_mapping_fixture() {
    let content = read_fixture("port_mappings/custom.toml");
    let mapping = PortMapping::parse(&content).unwrap();

    assert_eq!(mapping.get(8080), Some("Development Server"));
    assert_eq!(mapping.get(3000), Some("React Dev"));
    assert_eq!(mapping.get(5432), Some("PostgreSQL"));
    assert_eq!(mapping.get(6379), Some("Redis"));
}

#[test]
fn test_load_simple_mapping_fixture() {
    let content = read_fixture("port_mappings/simple.toml");
    let mapping = PortMapping::parse(&content).unwrap();

    assert_eq!(mapping.get(8080), Some("Web Server"));
    assert_eq!(mapping.get(3000), Some("Node App"));
    assert_eq!(mapping.get(5432), None); // Not in simple.toml
}

#[test]
fn test_mapping_describe_with_mapping() {
    let content = read_fixture("port_mappings/custom.toml");
    let mapping = PortMapping::parse(&content).unwrap();

    // Should use mapping description, ignore process name
    assert_eq!(mapping.describe(8080, Some("java")), "Development Server");
}

#[test]
fn test_mapping_describe_fallback_to_process() {
    let mapping = PortMapping::default();

    // Should use process name when no mapping
    assert_eq!(mapping.describe(9999, Some("my-app")), "my-app");
}

#[test]
fn test_mapping_describe_fallback_to_port() {
    let mapping = PortMapping::default();

    // Should use port number when no mapping and no process name
    assert_eq!(mapping.describe(9999, None), "port 9999");
}

#[test]
fn test_parse_empty_content() {
    let content = "";
    let mapping = PortMapping::parse(content).unwrap();
    assert!(mapping.descriptions.is_empty());
}

#[test]
fn test_parse_comments_only() {
    let content = r#"
# This is a comment
# Another comment
"#;
    let mapping = PortMapping::parse(content).unwrap();
    assert!(mapping.descriptions.is_empty());
}

#[test]
fn test_parse_mixed_quotes() {
    let content = r#"
8080 = "Double quoted"
3000 = 'Single quoted'
"#;
    let mapping = PortMapping::parse(content).unwrap();
    assert_eq!(mapping.get(8080), Some("Double quoted"));
    assert_eq!(mapping.get(3000), Some("Single quoted"));
}

#[test]
fn test_parse_with_extra_whitespace() {
    let content = r#"
  8080   =   "Web Server"
3000="No spaces"
"#;
    let mapping = PortMapping::parse(content).unwrap();
    assert_eq!(mapping.get(8080), Some("Web Server"));
    assert_eq!(mapping.get(3000), Some("No spaces"));
}

#[test]
fn test_parse_invalid_port_ignored() {
    let content = r#"
8080 = "Valid"
notaport = "Invalid"
-1 = "Negative"
"#;
    let mapping = PortMapping::parse(content).unwrap();
    assert_eq!(mapping.get(8080), Some("Valid"));
    assert_eq!(mapping.descriptions.len(), 1);
}
