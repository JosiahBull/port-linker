//! Wire format serialization for `RemotePort` entries.
//!
//! Format per entry:
//! ```text
//! [protocol:1][port:2][addr_type:1][addr:4|16][name_len:1][name:variable]
//! ```
//!
//! - `protocol`: 0 = TCP, 1 = UDP
//! - `port`: big-endian u16
//! - `addr_type`: 4 = IPv4, 6 = IPv6
//! - `addr`: 4 bytes for IPv4, 16 bytes for IPv6 (network byte order)
//! - `name_len`: length of process name (0 = none, max 255)
//! - `name`: UTF-8 process name bytes

use crate::types::{BindAddress, RemotePort};
use proto::Protocol;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Encode a list of `RemotePort` entries into a byte buffer.
///
/// The output starts with a big-endian u16 count, followed by each entry.
pub fn encode_remote_ports(ports: &[RemotePort]) -> Vec<u8> {
    let count = ports.len().min(u16::MAX as usize) as u16;
    let mut buf = Vec::new();
    buf.extend_from_slice(&count.to_be_bytes());

    for port in ports.iter().take(count as usize) {
        encode_one(port, &mut buf);
    }

    buf
}

fn encode_one(port: &RemotePort, buf: &mut Vec<u8>) {
    // Protocol
    buf.push(match port.protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
    });

    // Port
    buf.extend_from_slice(&port.port.to_be_bytes());

    // Address
    match &port.bind_address {
        BindAddress::V4(addr) => {
            buf.push(4);
            buf.extend_from_slice(&addr.octets());
        }
        BindAddress::V6(addr) => {
            buf.push(6);
            buf.extend_from_slice(&addr.octets());
        }
    }

    // Process name
    match &port.process_name {
        Some(name) => {
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(255) as u8;
            buf.push(len);
            if let Some(slice) = name_bytes.get(..len as usize) {
                buf.extend_from_slice(slice);
            }
        }
        None => {
            buf.push(0);
        }
    }
}

/// Decode a list of `RemotePort` entries from a byte buffer.
///
/// Returns the decoded ports, or `None` if the buffer is malformed.
pub fn decode_remote_ports(buf: &[u8]) -> Option<Vec<RemotePort>> {
    if buf.len() < 2 {
        return None;
    }

    let count = u16::from_be_bytes([*buf.first()?, *buf.get(1)?]) as usize;
    let mut offset = 2;
    let mut ports = Vec::with_capacity(count);

    for _ in 0..count {
        let (port, consumed) = decode_one(buf.get(offset..)?)?;
        ports.push(port);
        offset = offset.checked_add(consumed)?;
    }

    Some(ports)
}

fn decode_one(buf: &[u8]) -> Option<(RemotePort, usize)> {
    // Need at least: protocol(1) + port(2) + addr_type(1) + addr(4) + name_len(1) = 9
    if buf.len() < 5 {
        return None;
    }

    let protocol = match buf.first()? {
        0 => Protocol::Tcp,
        1 => Protocol::Udp,
        _ => return None,
    };

    let port = u16::from_be_bytes([*buf.get(1)?, *buf.get(2)?]);

    let addr_type = *buf.get(3)?;
    let (bind_address, addr_end) = match addr_type {
        4 => {
            if buf.len() < 8 {
                return None;
            }
            let octets: [u8; 4] = [*buf.get(4)?, *buf.get(5)?, *buf.get(6)?, *buf.get(7)?];
            (BindAddress::V4(Ipv4Addr::from(octets)), 8)
        }
        6 => {
            if buf.len() < 20 {
                return None;
            }
            let mut octets = [0_u8; 16];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = *buf.get(4_usize.checked_add(i)?)?;
            }
            (BindAddress::V6(Ipv6Addr::from(octets)), 20)
        }
        _ => return None,
    };

    let name_len = *buf.get(addr_end)? as usize;
    let name_start = addr_end.checked_add(1)?;
    let name_end = name_start.checked_add(name_len)?;

    if buf.len() < name_end {
        return None;
    }

    let process_name = if name_len > 0 {
        let name_bytes = buf.get(name_start..name_end)?;
        Some(String::from_utf8_lossy(name_bytes).to_string())
    } else {
        None
    };

    Some((
        RemotePort {
            port,
            bind_address,
            process_name,
            protocol,
        },
        name_end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_empty() {
        let ports: Vec<RemotePort> = vec![];
        let encoded = encode_remote_ports(&ports);
        let decoded = decode_remote_ports(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_roundtrip_tcp_v4() {
        let ports = vec![RemotePort {
            port: 8080,
            bind_address: BindAddress::V4(Ipv4Addr::LOCALHOST),
            process_name: Some("nginx".to_string()),
            protocol: Protocol::Tcp,
        }];

        let encoded = encode_remote_ports(&ports);
        let decoded = decode_remote_ports(&encoded).unwrap();
        assert_eq!(decoded, ports);
    }

    #[test]
    fn test_roundtrip_udp_v6() {
        let ports = vec![RemotePort {
            port: 53,
            bind_address: BindAddress::V6(Ipv6Addr::UNSPECIFIED),
            process_name: Some("dnsmasq".to_string()),
            protocol: Protocol::Udp,
        }];

        let encoded = encode_remote_ports(&ports);
        let decoded = decode_remote_ports(&encoded).unwrap();
        assert_eq!(decoded, ports);
    }

    #[test]
    fn test_roundtrip_no_process_name() {
        let ports = vec![RemotePort {
            port: 22,
            bind_address: BindAddress::V4(Ipv4Addr::UNSPECIFIED),
            process_name: None,
            protocol: Protocol::Tcp,
        }];

        let encoded = encode_remote_ports(&ports);
        let decoded = decode_remote_ports(&encoded).unwrap();
        assert_eq!(decoded, ports);
    }

    #[test]
    fn test_roundtrip_multiple() {
        let ports = vec![
            RemotePort {
                port: 22,
                bind_address: BindAddress::V4(Ipv4Addr::UNSPECIFIED),
                process_name: Some("sshd".to_string()),
                protocol: Protocol::Tcp,
            },
            RemotePort {
                port: 3000,
                bind_address: BindAddress::V4(Ipv4Addr::LOCALHOST),
                process_name: Some("node".to_string()),
                protocol: Protocol::Tcp,
            },
            RemotePort {
                port: 53,
                bind_address: BindAddress::V6(Ipv6Addr::UNSPECIFIED),
                process_name: None,
                protocol: Protocol::Udp,
            },
        ];

        let encoded = encode_remote_ports(&ports);
        let decoded = decode_remote_ports(&encoded).unwrap();
        assert_eq!(decoded, ports);
    }

    #[test]
    fn test_decode_malformed() {
        // Too short
        assert!(decode_remote_ports(&[]).is_none());
        assert!(decode_remote_ports(&[0]).is_none());

        // Count says 1 but no data
        assert!(decode_remote_ports(&[0, 1]).is_none());
    }
}
