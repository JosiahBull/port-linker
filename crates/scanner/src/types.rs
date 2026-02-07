use proto::Protocol;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The bind address of a listening port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl BindAddress {
    /// Whether this address is forwardable (unspecified or loopback).
    pub const fn is_forwardable(&self) -> bool {
        match self {
            Self::V4(a) => a.is_unspecified() || a.is_loopback(),
            Self::V6(a) => a.is_unspecified() || a.is_loopback(),
        }
    }

    /// Parse an address string (e.g. from ss/netstat output) into a `BindAddress`.
    ///
    /// Handles: `0.0.0.0`, `127.0.0.1`, `::`, `::1`, `*`, `localhost`,
    /// arbitrary IPv4/IPv6 literals.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "*" | "0.0.0.0" => Some(Self::V4(Ipv4Addr::UNSPECIFIED)),
            "localhost" | "127.0.0.1" => Some(Self::V4(Ipv4Addr::LOCALHOST)),
            "::" => Some(Self::V6(Ipv6Addr::UNSPECIFIED)),
            "::1" => Some(Self::V6(Ipv6Addr::LOCALHOST)),
            other => {
                if let Ok(v4) = other.parse::<Ipv4Addr>() {
                    return Some(Self::V4(v4));
                }
                if let Ok(v6) = other.parse::<Ipv6Addr>() {
                    return Some(Self::V6(v6));
                }
                None
            }
        }
    }
}

impl fmt::Display for BindAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{}", a),
            Self::V6(a) => write!(f, "{}", a),
        }
    }
}

/// A discovered listening port on a remote (or local) system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePort {
    pub port: u16,
    pub bind_address: BindAddress,
    pub process_name: Option<String>,
    pub protocol: Protocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_address_parse_str() {
        assert_eq!(
            BindAddress::parse_str("0.0.0.0"),
            Some(BindAddress::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            BindAddress::parse_str("127.0.0.1"),
            Some(BindAddress::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            BindAddress::parse_str("*"),
            Some(BindAddress::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            BindAddress::parse_str("::"),
            Some(BindAddress::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(
            BindAddress::parse_str("::1"),
            Some(BindAddress::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            BindAddress::parse_str("192.168.1.1"),
            Some(BindAddress::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_bind_address_is_forwardable() {
        assert!(BindAddress::V4(Ipv4Addr::UNSPECIFIED).is_forwardable());
        assert!(BindAddress::V4(Ipv4Addr::LOCALHOST).is_forwardable());
        assert!(BindAddress::V6(Ipv6Addr::UNSPECIFIED).is_forwardable());
        assert!(BindAddress::V6(Ipv6Addr::LOCALHOST).is_forwardable());
        assert!(!BindAddress::V4(Ipv4Addr::new(192, 168, 1, 1)).is_forwardable());
    }

    #[test]
    fn test_bind_address_display() {
        assert_eq!(
            format!("{}", BindAddress::V4(Ipv4Addr::LOCALHOST)),
            "127.0.0.1"
        );
        assert_eq!(format!("{}", BindAddress::V6(Ipv6Addr::LOCALHOST)), "::1");
    }

    #[test]
    fn test_parse_str_localhost() {
        assert_eq!(
            BindAddress::parse_str("localhost"),
            Some(BindAddress::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn test_parse_str_arbitrary_ipv6() {
        let addr = BindAddress::parse_str("fe80::1");
        assert!(matches!(addr, Some(BindAddress::V6(_))));
    }

    #[test]
    fn test_parse_str_invalid() {
        assert!(BindAddress::parse_str("not_an_ip").is_none());
        assert!(BindAddress::parse_str("").is_none());
    }

    #[test]
    fn test_is_forwardable_non_loopback_v6() {
        let addr = BindAddress::V6("fe80::1".parse().unwrap());
        assert!(!addr.is_forwardable());
    }

    #[test]
    fn test_remote_port_fields() {
        let port = RemotePort {
            port: 8080,
            bind_address: BindAddress::V4(Ipv4Addr::UNSPECIFIED),
            process_name: Some("nginx".to_string()),
            protocol: Protocol::Tcp,
        };
        assert_eq!(port.port, 8080);
        assert_eq!(port.process_name, Some("nginx".to_string()));
        assert_eq!(port.protocol, Protocol::Tcp);
    }
}
