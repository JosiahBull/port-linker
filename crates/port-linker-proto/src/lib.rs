//! Protocol definitions for port-linker UDP tunneling.
//!
//! This crate defines the wire format for tunneling UDP packets over a TCP/SSH connection.
//! It is designed to be minimal with no external dependencies to keep the udp-proxy binary small.
//!
//! # Message Types
//!
//! The protocol supports two message types:
//! - `UdpPacket`: Encapsulated UDP data for forwarding
//! - `ControlMessage`: Protocol control messages (ping/pong for healthcheck)
//!
//! # Wire Format
//!
//! All messages use a type-length-value (TLV) format:
//! ```text
//! [type:1][len:4][payload:variable]
//! ```
//!
//! Message types:
//! - `0x00`: UDP packet
//! - `0x01`: Ping (healthcheck request)
//! - `0x02`: Pong (healthcheck response)

/// Message type constants
pub mod message_type {
    /// UDP packet message
    pub const UDP_PACKET: u8 = 0x00;
    /// Healthcheck ping request
    pub const PING: u8 = 0x01;
    /// Healthcheck pong response
    pub const PONG: u8 = 0x02;
}

/// A protocol message that can be either a UDP packet or a control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A UDP packet to be forwarded
    Udp(UdpPacket),
    /// Healthcheck ping (contains a timestamp or sequence number)
    Ping(u64),
    /// Healthcheck pong (echoes back the ping value)
    Pong(u64),
}

impl Message {
    /// Encode the message for transmission.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Udp(packet) => {
                let inner = packet.encode_inner();
                let mut buf = Vec::with_capacity(1 + 4 + inner.len());
                buf.push(message_type::UDP_PACKET);
                buf.extend_from_slice(&(inner.len() as u32).to_be_bytes());
                buf.extend_from_slice(&inner);
                buf
            }
            Message::Ping(value) => {
                let mut buf = Vec::with_capacity(1 + 4 + 8);
                buf.push(message_type::PING);
                buf.extend_from_slice(&8u32.to_be_bytes());
                buf.extend_from_slice(&value.to_be_bytes());
                buf
            }
            Message::Pong(value) => {
                let mut buf = Vec::with_capacity(1 + 4 + 8);
                buf.push(message_type::PONG);
                buf.extend_from_slice(&8u32.to_be_bytes());
                buf.extend_from_slice(&value.to_be_bytes());
                buf
            }
        }
    }

    /// Decode a message from a byte buffer.
    ///
    /// Returns the decoded message and the number of bytes consumed, or `None` if
    /// the buffer doesn't contain a complete message.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        // Need at least 5 bytes for type + length
        if buf.len() < 5 {
            return None;
        }

        let msg_type = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

        // Sanity check
        if len > 65535 + 16 {
            return None;
        }

        // Check if we have the complete message
        if buf.len() < 5 + len {
            return None;
        }

        let payload = &buf[5..5 + len];

        let message = match msg_type {
            message_type::UDP_PACKET => {
                let packet = UdpPacket::decode_inner(payload)?;
                Message::Udp(packet)
            }
            message_type::PING => {
                if payload.len() < 8 {
                    return None;
                }
                let value = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                Message::Ping(value)
            }
            message_type::PONG => {
                if payload.len() < 8 {
                    return None;
                }
                let value = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                Message::Pong(value)
            }
            _ => return None, // Unknown message type
        };

        Some((message, 5 + len))
    }
}

/// A UDP packet with metadata for tunneling over TCP/SSH.
///
/// The wire format is:
/// ```text
/// [total_len:4][src_port:2][dst_port:2][id:4][data:variable]
/// ```
///
/// Where `total_len` is the length of everything after it (src_port + dst_port + id + data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    /// Source port (used for response routing on the local side)
    pub src_port: u16,
    /// Destination port (the target UDP service port)
    pub dst_port: u16,
    /// Packet ID for correlating requests with responses
    pub id: u32,
    /// The UDP payload
    pub data: Vec<u8>,
}

impl UdpPacket {
    /// Create a new UDP packet.
    pub fn new(src_port: u16, dst_port: u16, id: u32, data: Vec<u8>) -> Self {
        Self {
            src_port,
            dst_port,
            id,
            data,
        }
    }

    /// Encode the packet for transmission over TCP/SSH (legacy format).
    ///
    /// Format: `[len:4][src_port:2][dst_port:2][id:4][data:len-8]`
    ///
    /// This is the standalone packet format. For new code, prefer using
    /// `Message::Udp(packet).encode()` which includes a message type byte.
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = 8 + self.data.len(); // 2 + 2 + 4 + data.len()
        let mut buf = Vec::with_capacity(4 + payload_len);

        // Length prefix (does not include itself)
        buf.extend_from_slice(&(payload_len as u32).to_be_bytes());

        // Header
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Payload
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Encode the packet without the length prefix (used by Message wrapper).
    pub(crate) fn encode_inner(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.data.len());
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode a packet from a byte buffer without length prefix (used by Message wrapper).
    pub(crate) fn decode_inner(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let data = buf[8..].to_vec();

        Some(Self {
            src_port,
            dst_port,
            id,
            data,
        })
    }

    /// Decode a packet from a byte buffer (legacy format).
    ///
    /// Returns the decoded packet and the number of bytes consumed, or `None` if
    /// the buffer doesn't contain a complete packet.
    ///
    /// This is the standalone packet format. For new code, prefer using
    /// `Message::decode()` which handles multiple message types.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        // Need at least 4 bytes for length prefix
        if buf.len() < 4 {
            return None;
        }

        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // Sanity check: len must be at least 8 (header size) and not absurdly large
        if len < 8 || len > 65535 + 8 {
            return None;
        }

        // Check if we have the complete packet
        if buf.len() < 4 + len {
            return None;
        }

        let src_port = u16::from_be_bytes([buf[4], buf[5]]);
        let dst_port = u16::from_be_bytes([buf[6], buf[7]]);
        let id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data = buf[12..4 + len].to_vec();

        Some((
            Self {
                src_port,
                dst_port,
                id,
                data,
            },
            4 + len,
        ))
    }
}

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let packet = UdpPacket::new(12345, 53, 42, b"hello world".to_vec());
        let encoded = packet.encode();
        let (decoded, consumed) = UdpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded, packet);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_incomplete() {
        let packet = UdpPacket::new(12345, 53, 42, b"hello".to_vec());
        let encoded = packet.encode();

        // Try decoding with incomplete data
        assert!(UdpPacket::decode(&encoded[..3]).is_none()); // Not enough for length
        assert!(UdpPacket::decode(&encoded[..10]).is_none()); // Partial packet
    }

    #[test]
    fn test_decode_multiple_packets() {
        let packet1 = UdpPacket::new(1000, 53, 1, b"first".to_vec());
        let packet2 = UdpPacket::new(2000, 80, 2, b"second".to_vec());

        let mut buf = packet1.encode();
        buf.extend(packet2.encode());

        let (decoded1, consumed1) = UdpPacket::decode(&buf).unwrap();
        assert_eq!(decoded1, packet1);

        let (decoded2, consumed2) = UdpPacket::decode(&buf[consumed1..]).unwrap();
        assert_eq!(decoded2, packet2);
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    #[test]
    fn test_empty_data() {
        let packet = UdpPacket::new(0, 0, 0, vec![]);
        let encoded = packet.encode();
        let (decoded, _) = UdpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_max_udp_size() {
        // UDP max payload is 65535 bytes
        let data = vec![0xAB; 65535];
        let packet = UdpPacket::new(1234, 5678, 999, data.clone());
        let encoded = packet.encode();
        let (decoded, _) = UdpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_message_udp_roundtrip() {
        let packet = UdpPacket::new(12345, 53, 42, b"hello world".to_vec());
        let msg = Message::Udp(packet.clone());
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        match decoded {
            Message::Udp(p) => assert_eq!(p, packet),
            _ => panic!("Expected UDP message"),
        }
    }

    #[test]
    fn test_message_ping_pong_roundtrip() {
        let ping = Message::Ping(1234567890);
        let encoded_ping = ping.encode();
        let (decoded_ping, consumed) = Message::decode(&encoded_ping).unwrap();
        assert_eq!(consumed, encoded_ping.len());
        assert_eq!(decoded_ping, ping);

        let pong = Message::Pong(9876543210);
        let encoded_pong = pong.encode();
        let (decoded_pong, consumed) = Message::decode(&encoded_pong).unwrap();
        assert_eq!(consumed, encoded_pong.len());
        assert_eq!(decoded_pong, pong);
    }

    #[test]
    fn test_message_decode_incomplete() {
        let msg = Message::Ping(42);
        let encoded = msg.encode();

        // Not enough for type + length
        assert!(Message::decode(&encoded[..4]).is_none());
        // Partial payload
        assert!(Message::decode(&encoded[..8]).is_none());
    }

    #[test]
    fn test_message_decode_unknown_type() {
        let mut buf = vec![0xFF]; // Unknown type
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);

        assert!(Message::decode(&buf).is_none());
    }

    #[test]
    fn test_message_mixed_stream() {
        let ping = Message::Ping(111);
        let udp = Message::Udp(UdpPacket::new(1000, 53, 1, b"query".to_vec()));
        let pong = Message::Pong(111);

        let mut buf = ping.encode();
        buf.extend(udp.encode());
        buf.extend(pong.encode());

        let (msg1, consumed1) = Message::decode(&buf).unwrap();
        assert_eq!(msg1, ping);

        let (msg2, consumed2) = Message::decode(&buf[consumed1..]).unwrap();
        assert!(matches!(msg2, Message::Udp(_)));

        let (msg3, _) = Message::decode(&buf[consumed1 + consumed2..]).unwrap();
        assert_eq!(msg3, pong);
    }
}
