//! Protocol definitions for port-linker tunneling.
//!
//! This crate defines the wire format for tunneling UDP packets and control messages
//! over a TCP/SSH connection. It is designed to be minimal with no external dependencies
//! to keep the target-agent binary small.
//!
//! # Message Types
//!
//! The protocol supports these message types:
//! - `UdpPacket`: Encapsulated UDP data for forwarding
//! - `Ping`/`Pong`: Healthcheck messages
//! - `ScanRequest`/`ScanResponse`: Port scanning
//! - `StartUdpForward`/`StopUdpForward`: Multiplexed UDP forwarding control
//!
//! # Wire Format
//!
//! All messages use a type-length-value (TLV) format:
//! ```text
//! [type:1][len:4][payload:variable]
//! ```

/// Message type constants
pub mod message_type {
    /// UDP packet message
    pub const UDP_PACKET: u8 = 0x00;
    /// Healthcheck ping request
    pub const PING: u8 = 0x01;
    /// Healthcheck pong response
    pub const PONG: u8 = 0x02;
    /// Port scan request
    pub const SCAN_REQUEST: u8 = 0x03;
    /// Port scan response
    pub const SCAN_RESPONSE: u8 = 0x04;
    /// Start UDP forwarding for a port
    pub const START_UDP_FORWARD: u8 = 0x05;
    /// Stop UDP forwarding for a port
    pub const STOP_UDP_FORWARD: u8 = 0x06;
    /// Batch of log events from the agent
    pub const LOG_BATCH: u8 = 0x07;
}

/// Flags for scan requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanFlags {
    /// Scan for TCP ports
    pub tcp: bool,
    /// Scan for UDP ports
    pub udp: bool,
}

impl ScanFlags {
    /// Encode flags into a single byte: bit 0 = TCP, bit 1 = UDP.
    pub const fn to_byte(self) -> u8 {
        let mut b = 0_u8;
        if self.tcp {
            b |= 0x01;
        }
        if self.udp {
            b |= 0x02;
        }
        b
    }

    /// Decode flags from a byte.
    pub const fn from_byte(b: u8) -> Self {
        Self {
            tcp: b & 0x01 != 0,
            udp: b & 0x02 != 0,
        }
    }
}

/// Log level for agent tracing events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogLevel {
    /// Error level
    Error = 1,
    /// Warn level
    Warn = 2,
    /// Info level
    Info = 3,
    /// Debug level
    Debug = 4,
    /// Trace level
    Trace = 5,
}

impl LogLevel {
    /// Convert from a u8 value.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Error),
            2 => Some(Self::Warn),
            3 => Some(Self::Info),
            4 => Some(Self::Debug),
            5 => Some(Self::Trace),
            _ => None,
        }
    }

    /// Convert to a u8 value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single log event from the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// Severity level
    pub level: LogLevel,
    /// Module/target path (e.g. "target_agent::main")
    pub target: String,
    /// Formatted log message
    pub message: String,
}

/// A protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A UDP packet to be forwarded
    Udp(UdpPacket),
    /// Healthcheck ping (contains a timestamp or sequence number)
    Ping(u64),
    /// Healthcheck pong (echoes back the ping value)
    Pong(u64),
    /// Request a port scan from the agent
    ScanRequest(ScanFlags),
    /// Port scan results (raw bytes, decoded by port-scanner crate)
    ScanResponse(Vec<u8>),
    /// Tell the agent to start UDP forwarding for a port
    StartUdpForward {
        port: u16,
        bind_addr_type: u8,
        bind_addr: Vec<u8>,
    },
    /// Tell the agent to stop UDP forwarding for a port
    StopUdpForward(u16),
    /// Batch of log events from the agent
    LogBatch(Vec<LogEvent>),
}

impl Message {
    /// Encode the message for transmission.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Udp(packet) => {
                let inner = packet.encode_inner();
                let inner_len = inner.len();
                let total = 1_usize.saturating_add(4).saturating_add(inner_len);
                let mut buf = Vec::with_capacity(total);
                buf.push(message_type::UDP_PACKET);
                buf.extend_from_slice(&(inner_len as u32).to_be_bytes());
                buf.extend_from_slice(&inner);
                buf
            }
            Self::Ping(value) => encode_u64_msg(message_type::PING, *value),
            Self::Pong(value) => encode_u64_msg(message_type::PONG, *value),
            Self::ScanRequest(flags) => {
                let mut buf = Vec::with_capacity(6);
                buf.push(message_type::SCAN_REQUEST);
                buf.extend_from_slice(&1_u32.to_be_bytes());
                buf.push(flags.to_byte());
                buf
            }
            Self::ScanResponse(data) => {
                let data_len = data.len();
                let total = 1_usize.saturating_add(4).saturating_add(data_len);
                let mut buf = Vec::with_capacity(total);
                buf.push(message_type::SCAN_RESPONSE);
                buf.extend_from_slice(&(data_len as u32).to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            Self::StartUdpForward {
                port,
                bind_addr_type,
                bind_addr,
            } => {
                // payload: [port:2][addr_type:1][addr:variable]
                let payload_len = 2_usize
                    .saturating_add(1)
                    .saturating_add(bind_addr.len());
                let total = 1_usize.saturating_add(4).saturating_add(payload_len);
                let mut buf = Vec::with_capacity(total);
                buf.push(message_type::START_UDP_FORWARD);
                buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                buf.push(*bind_addr_type);
                buf.extend_from_slice(bind_addr);
                buf
            }
            Self::StopUdpForward(port) => {
                let mut buf = Vec::with_capacity(7);
                buf.push(message_type::STOP_UDP_FORWARD);
                buf.extend_from_slice(&2_u32.to_be_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
            Self::LogBatch(events) => {
                encode_log_batch(events)
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

        let msg_type = *buf.first()?;
        let len = u32::from_be_bytes([
            *buf.get(1)?,
            *buf.get(2)?,
            *buf.get(3)?,
            *buf.get(4)?,
        ]) as usize;

        // Sanity check: max message size
        if len > 65535_usize.saturating_add(16) {
            return None;
        }

        let total = 5_usize.checked_add(len)?;

        // Check if we have the complete message
        if buf.len() < total {
            return None;
        }

        let payload = buf.get(5..total)?;

        let message = match msg_type {
            message_type::UDP_PACKET => {
                let packet = UdpPacket::decode_inner(payload)?;
                Self::Udp(packet)
            }
            message_type::PING => {
                let value = decode_u64_payload(payload)?;
                Self::Ping(value)
            }
            message_type::PONG => {
                let value = decode_u64_payload(payload)?;
                Self::Pong(value)
            }
            message_type::SCAN_REQUEST => {
                let flags_byte = *payload.first()?;
                Self::ScanRequest(ScanFlags::from_byte(flags_byte))
            }
            message_type::SCAN_RESPONSE => Self::ScanResponse(payload.to_vec()),
            message_type::START_UDP_FORWARD => {
                if payload.len() < 3 {
                    return None;
                }
                let port = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
                let bind_addr_type = *payload.get(2)?;
                let bind_addr = payload.get(3..)?.to_vec();
                Self::StartUdpForward {
                    port,
                    bind_addr_type,
                    bind_addr,
                }
            }
            message_type::STOP_UDP_FORWARD => {
                if payload.len() < 2 {
                    return None;
                }
                let port = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
                Self::StopUdpForward(port)
            }
            message_type::LOG_BATCH => {
                let events = decode_log_batch(payload)?;
                Self::LogBatch(events)
            }
            _ => return None, // Unknown message type
        };

        Some((message, total))
    }
}

fn encode_u64_msg(msg_type: u8, value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13);
    buf.push(msg_type);
    buf.extend_from_slice(&8_u32.to_be_bytes());
    buf.extend_from_slice(&value.to_be_bytes());
    buf
}

fn decode_u64_payload(payload: &[u8]) -> Option<u64> {
    if payload.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes([
        *payload.first()?,
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
        *payload.get(4)?,
        *payload.get(5)?,
        *payload.get(6)?,
        *payload.get(7)?,
    ]))
}

/// Encode a log batch into the TLV wire format.
///
/// Wire format:
/// ```text
/// [event_count: u16 BE]
/// [event_1] [event_2] ...
///
/// Each event:
///   [event_len: u16 BE]        -- length of remainder
///   [level: u8]                -- LogLevel as u8
///   [target_len: u8]           -- length of target string (max 255)
///   [target: target_len bytes] -- UTF-8 module path
///   [message: remaining bytes] -- UTF-8 formatted message
/// ```
fn encode_log_batch(events: &[LogEvent]) -> Vec<u8> {
    // Pre-calculate total size
    let mut payload_size = 2_usize; // event_count
    for event in events {
        // event_len(2) + level(1) + target_len(1) + target + message
        let target_len = event.target.len().min(255);
        let event_body = 1_usize
            .saturating_add(1)
            .saturating_add(target_len)
            .saturating_add(event.message.len());
        payload_size = payload_size.saturating_add(2).saturating_add(event_body);
    }

    let total = 1_usize.saturating_add(4).saturating_add(payload_size);
    let mut buf = Vec::with_capacity(total);

    // TLV header
    buf.push(message_type::LOG_BATCH);
    buf.extend_from_slice(&(payload_size as u32).to_be_bytes());

    // Event count (capped to u16::MAX)
    let count = events.len().min(usize::from(u16::MAX));
    buf.extend_from_slice(&(count as u16).to_be_bytes());

    // Each event
    for event in events.get(..count).unwrap_or(events) {
        let target_len = event.target.len().min(255);
        let target_bytes = event.target.as_bytes().get(..target_len).unwrap_or(event.target.as_bytes());
        let event_body_len = 1_usize
            .saturating_add(1)
            .saturating_add(target_len)
            .saturating_add(event.message.len());

        buf.extend_from_slice(&(event_body_len as u16).to_be_bytes());
        buf.push(event.level.as_u8());
        buf.push(target_len as u8);
        buf.extend_from_slice(target_bytes);
        buf.extend_from_slice(event.message.as_bytes());
    }

    buf
}

/// Decode a log batch from TLV payload bytes.
fn decode_log_batch(payload: &[u8]) -> Option<Vec<LogEvent>> {
    if payload.len() < 2 {
        return None;
    }

    let event_count = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    let mut offset = 2_usize;
    let mut events = Vec::with_capacity(usize::from(event_count));

    for _ in 0..event_count {
        // Read event_len
        if payload.len() < offset.saturating_add(2) {
            return None;
        }
        let event_len = u16::from_be_bytes([
            *payload.get(offset)?,
            *payload.get(offset.saturating_add(1))?,
        ]);
        offset = offset.saturating_add(2);

        let event_end = offset.saturating_add(usize::from(event_len));
        if payload.len() < event_end || usize::from(event_len) < 2 {
            return None;
        }

        let level_byte = *payload.get(offset)?;
        let level = LogLevel::from_u8(level_byte)?;

        let target_len = usize::from(*payload.get(offset.saturating_add(1))?);
        let target_start = offset.saturating_add(2);
        let target_end = target_start.saturating_add(target_len);

        if target_end > event_end {
            return None;
        }

        let target_bytes = payload.get(target_start..target_end)?;
        let target = core::str::from_utf8(target_bytes).ok()?.to_string();

        let message_bytes = payload.get(target_end..event_end)?;
        let message = core::str::from_utf8(message_bytes).ok()?.to_string();

        events.push(LogEvent {
            level,
            target,
            message,
        });

        offset = event_end;
    }

    Some(events)
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
    pub const fn new(src_port: u16, dst_port: u16, id: u32, data: Vec<u8>) -> Self {
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
        let payload_len = 8_usize.saturating_add(self.data.len()); // 2 + 2 + 4 + data.len()
        let total = 4_usize.saturating_add(payload_len);
        let mut buf = Vec::with_capacity(total);

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
        let total = 8_usize.saturating_add(self.data.len());
        let mut buf = Vec::with_capacity(total);
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

        let src_port = u16::from_be_bytes([*buf.first()?, *buf.get(1)?]);
        let dst_port = u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?]);
        let id = u32::from_be_bytes([*buf.get(4)?, *buf.get(5)?, *buf.get(6)?, *buf.get(7)?]);
        let data = buf.get(8..)?.to_vec();

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

        let len = u32::from_be_bytes([
            *buf.first()?,
            *buf.get(1)?,
            *buf.get(2)?,
            *buf.get(3)?,
        ]) as usize;

        // Sanity check: len must be at least 8 (header size) and not absurdly large
        if len < 8 || len > 65535_usize.saturating_add(8) {
            return None;
        }

        let total = 4_usize.checked_add(len)?;

        // Check if we have the complete packet
        if buf.len() < total {
            return None;
        }

        let src_port = u16::from_be_bytes([*buf.get(4)?, *buf.get(5)?]);
        let dst_port = u16::from_be_bytes([*buf.get(6)?, *buf.get(7)?]);
        let id = u32::from_be_bytes([
            *buf.get(8)?,
            *buf.get(9)?,
            *buf.get(10)?,
            *buf.get(11)?,
        ]);
        let data = buf.get(12..total)?.to_vec();

        Some((
            Self {
                src_port,
                dst_port,
                id,
                data,
            },
            total,
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
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
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
        let ping = Message::Ping(1_234_567_890);
        let encoded_ping = ping.encode();
        let (decoded_ping, consumed) = Message::decode(&encoded_ping).unwrap();
        assert_eq!(consumed, encoded_ping.len());
        assert_eq!(decoded_ping, ping);

        let pong = Message::Pong(9_876_543_210);
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
        buf.extend_from_slice(&8_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 8]);

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

    #[test]
    fn test_scan_request_roundtrip() {
        let flags = ScanFlags {
            tcp: true,
            udp: true,
        };
        let msg = Message::ScanRequest(flags);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_scan_request_tcp_only() {
        let flags = ScanFlags {
            tcp: true,
            udp: false,
        };
        assert_eq!(flags.to_byte(), 0x01);
        assert_eq!(ScanFlags::from_byte(0x01), flags);
    }

    #[test]
    fn test_scan_response_roundtrip() {
        let data = vec![0x00, 0x02, 0x00, 0x50, 0x04, 127, 0, 0, 1, 0x05];
        let msg = Message::ScanResponse(data.clone());
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            Message::ScanResponse(d) => assert_eq!(d, data),
            _ => panic!("Expected ScanResponse"),
        }
    }

    #[test]
    fn test_start_udp_forward_roundtrip() {
        let msg = Message::StartUdpForward {
            port: 53,
            bind_addr_type: 4,
            bind_addr: vec![0, 0, 0, 0],
        };
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_stop_udp_forward_roundtrip() {
        let msg = Message::StopUdpForward(8080);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_all_message_types_mixed_stream() {
        let messages = vec![
            Message::Ping(1),
            Message::ScanRequest(ScanFlags {
                tcp: true,
                udp: true,
            }),
            Message::ScanResponse(vec![0, 0]),
            Message::StartUdpForward {
                port: 53,
                bind_addr_type: 4,
                bind_addr: vec![127, 0, 0, 1],
            },
            Message::Udp(UdpPacket::new(1000, 53, 42, b"query".to_vec())),
            Message::Pong(1),
            Message::StopUdpForward(53),
            Message::LogBatch(vec![LogEvent {
                level: LogLevel::Info,
                target: "test".to_string(),
                message: "hello".to_string(),
            }]),
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            buf.extend(msg.encode());
        }

        let mut offset = 0;
        for expected in &messages {
            let (decoded, consumed) = Message::decode(&buf[offset..]).unwrap();
            assert_eq!(&decoded, expected);
            offset += consumed;
        }
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_log_level_roundtrip() {
        let levels = [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ];
        for level in levels {
            assert_eq!(LogLevel::from_u8(level.as_u8()), Some(level));
        }
        assert_eq!(LogLevel::from_u8(0), None);
        assert_eq!(LogLevel::from_u8(6), None);
        assert_eq!(LogLevel::from_u8(255), None);
    }

    #[test]
    fn test_log_batch_empty() {
        let msg = Message::LogBatch(vec![]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_log_batch_single_event() {
        let msg = Message::LogBatch(vec![LogEvent {
            level: LogLevel::Info,
            target: "target_agent::main".to_string(),
            message: "Starting agent".to_string(),
        }]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_log_batch_multiple_events() {
        let msg = Message::LogBatch(vec![
            LogEvent {
                level: LogLevel::Error,
                target: "target_agent".to_string(),
                message: "something failed".to_string(),
            },
            LogEvent {
                level: LogLevel::Warn,
                target: "target_agent::udp".to_string(),
                message: "socket issue".to_string(),
            },
            LogEvent {
                level: LogLevel::Debug,
                target: "target_agent::scan".to_string(),
                message: "scanning ports".to_string(),
            },
            LogEvent {
                level: LogLevel::Trace,
                target: "target_agent::main".to_string(),
                message: "packet received".to_string(),
            },
        ]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_log_batch_all_levels() {
        let levels = [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ];
        let events: Vec<LogEvent> = levels
            .iter()
            .map(|&level| LogEvent {
                level,
                target: "test".to_string(),
                message: format!("level {:?}", level),
            })
            .collect();

        let msg = Message::LogBatch(events);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_log_batch_interleaved_with_other_messages() {
        let messages = vec![
            Message::Ping(42),
            Message::LogBatch(vec![LogEvent {
                level: LogLevel::Debug,
                target: "agent".to_string(),
                message: "processing".to_string(),
            }]),
            Message::Udp(UdpPacket::new(1000, 53, 1, b"data".to_vec())),
            Message::LogBatch(vec![
                LogEvent {
                    level: LogLevel::Info,
                    target: "agent".to_string(),
                    message: "forwarded packet".to_string(),
                },
                LogEvent {
                    level: LogLevel::Trace,
                    target: "agent".to_string(),
                    message: "details".to_string(),
                },
            ]),
            Message::Pong(42),
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            buf.extend(msg.encode());
        }

        let mut offset = 0;
        for expected in &messages {
            let (decoded, consumed) = Message::decode(&buf[offset..]).unwrap();
            assert_eq!(&decoded, expected);
            offset += consumed;
        }
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_log_batch_empty_target_and_message() {
        let msg = Message::LogBatch(vec![LogEvent {
            level: LogLevel::Info,
            target: String::new(),
            message: String::new(),
        }]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_message_oversized_length_rejected() {
        // Craft a message with a length field exceeding the max
        let mut buf = vec![message_type::PING];
        // len = 65535 + 17 = 65552, which exceeds 65535+16
        buf.extend_from_slice(&65552_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 8]);
        assert!(Message::decode(&buf).is_none());
    }

    #[test]
    fn test_decode_u64_payload_too_short() {
        // Ping with only 4 bytes of payload instead of 8
        let mut buf = vec![message_type::PING];
        buf.extend_from_slice(&4_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 4]);
        assert!(Message::decode(&buf).is_none());
    }

    #[test]
    fn test_start_udp_forward_too_short() {
        // StartUdpForward with only 2 bytes (needs at least 3)
        let mut buf = vec![message_type::START_UDP_FORWARD];
        buf.extend_from_slice(&2_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 2]);
        assert!(Message::decode(&buf).is_none());
    }

    #[test]
    fn test_stop_udp_forward_too_short() {
        // StopUdpForward with only 1 byte (needs at least 2)
        let mut buf = vec![message_type::STOP_UDP_FORWARD];
        buf.extend_from_slice(&1_u32.to_be_bytes());
        buf.push(0);
        assert!(Message::decode(&buf).is_none());
    }

    #[test]
    fn test_udp_packet_decode_inner_too_short() {
        // Less than 8 bytes for the inner decode
        assert!(UdpPacket::decode_inner(&[0_u8; 7]).is_none());
        assert!(UdpPacket::decode_inner(&[]).is_none());
    }

    #[test]
    fn test_udp_packet_legacy_decode_too_small_len() {
        // Length field says 4 (< 8 minimum header)
        let mut buf = Vec::new();
        buf.extend_from_slice(&4_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 4]);
        assert!(UdpPacket::decode(&buf).is_none());
    }

    #[test]
    fn test_scan_flags_combinations() {
        assert_eq!(ScanFlags { tcp: false, udp: false }.to_byte(), 0x00);
        assert_eq!(ScanFlags { tcp: true, udp: false }.to_byte(), 0x01);
        assert_eq!(ScanFlags { tcp: false, udp: true }.to_byte(), 0x02);
        assert_eq!(ScanFlags { tcp: true, udp: true }.to_byte(), 0x03);

        assert_eq!(ScanFlags::from_byte(0x00), ScanFlags { tcp: false, udp: false });
        assert_eq!(ScanFlags::from_byte(0x03), ScanFlags { tcp: true, udp: true });
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
    }

    #[test]
    fn test_log_batch_truncated_payload() {
        // Valid header but truncated event data
        let mut buf = vec![message_type::LOG_BATCH];
        // payload: event_count=1, but no event data
        let payload: Vec<u8> = vec![0x00, 0x01];
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&payload);
        assert!(Message::decode(&buf).is_none());
    }
}
