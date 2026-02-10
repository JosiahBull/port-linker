use bytes::Bytes;
use rkyv::{
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    de::Pool,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    Archive, Deserialize, Serialize,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Serialize `value` into a `Bytes` buffer using rkyv.
pub fn encode<T>(value: &T) -> Result<Bytes, BoxError>
where
    T: for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>,
{
    let buf = rkyv::to_bytes::<rkyv::rancor::Error>(value)?;
    Ok(Bytes::from(buf.into_vec()))
}

/// Deserialize a `T` from the raw bytes produced by [`encode`].
pub fn decode<T>(bytes: &[u8]) -> Result<T, BoxError>
where
    T: Archive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rkyv::rancor::Error>>
        + Deserialize<T, rkyv::rancor::Strategy<Pool, rkyv::rancor::Error>>,
{
    let value = rkyv::from_bytes::<T, rkyv::rancor::Error>(bytes)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentLogEvent, ControlMsg, LogLevel, Packet, Protocol, PROTOCOL_VERSION};

    /// Helper: encode then decode, assert equality.
    fn roundtrip<T>(value: &T) -> T
    where
        T: for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>
            + Archive
            + PartialEq
            + std::fmt::Debug,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, rkyv::rancor::Error>>
            + Deserialize<T, rkyv::rancor::Strategy<Pool, rkyv::rancor::Error>>,
    {
        let encoded = encode(value).expect("encode failed");
        let decoded: T = decode(&encoded).expect("decode failed");
        assert_eq!(&decoded, value);
        decoded
    }

    // ------------------------------------------------------------------
    // ControlMsg variant round-trips
    // ------------------------------------------------------------------

    #[test]
    fn roundtrip_handshake() {
        roundtrip(&ControlMsg::Handshake {
            protocol_version: PROTOCOL_VERSION,
            token: "secret-token-42".into(),
        });
    }

    #[test]
    fn roundtrip_port_added() {
        roundtrip(&ControlMsg::PortAdded {
            port: 8080,
            proto: Protocol::Tcp,
            process_name: Some("nginx".into()),
        });
    }

    #[test]
    fn roundtrip_port_added_no_process() {
        roundtrip(&ControlMsg::PortAdded {
            port: 3000,
            proto: Protocol::Tcp,
            process_name: None,
        });
    }

    #[test]
    fn roundtrip_port_removed() {
        roundtrip(&ControlMsg::PortRemoved {
            port: 53,
            proto: Protocol::Udp,
        });
    }

    #[test]
    fn roundtrip_heartbeat() {
        roundtrip(&ControlMsg::Heartbeat);
    }

    #[test]
    fn roundtrip_echo_request() {
        roundtrip(&ControlMsg::EchoRequest {
            payload: vec![1, 2, 3, 4],
        });
    }

    #[test]
    fn roundtrip_echo_response() {
        roundtrip(&ControlMsg::EchoResponse {
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
    }

    #[test]
    fn roundtrip_tcp_stream_init() {
        roundtrip(&ControlMsg::TcpStreamInit { port: 8080 });
    }

    #[test]
    fn roundtrip_tcp_stream_error() {
        roundtrip(&ControlMsg::TcpStreamError {
            port: 3000,
            error: "connection refused".into(),
        });
    }

    // ------------------------------------------------------------------
    // Packet round-trips
    // ------------------------------------------------------------------

    #[test]
    fn roundtrip_packet_control() {
        roundtrip(&Packet::Control(ControlMsg::Heartbeat));
    }

    #[test]
    fn roundtrip_packet_udp_data() {
        roundtrip(&Packet::UdpData {
            port: 443,
            data: vec![0xFF; 128],
        });
    }

    // ------------------------------------------------------------------
    // Error handling
    // ------------------------------------------------------------------

    #[test]
    fn decode_garbage_returns_error() {
        let garbage = vec![0x00, 0xFF, 0xAB, 0xCD, 0x12, 0x34];
        let result = decode::<Packet>(&garbage);
        assert!(result.is_err(), "decoding garbage should return Err");
    }

    #[test]
    fn decode_empty_returns_error() {
        let result = decode::<Packet>(&[]);
        assert!(result.is_err(), "decoding empty slice should return Err");
    }

    // ------------------------------------------------------------------
    // Large payload
    // ------------------------------------------------------------------

    #[test]
    fn roundtrip_large_payload() {
        let big = vec![0x42u8; 1_000_000]; // 1 MB
        roundtrip(&Packet::UdpData {
            port: 9999,
            data: big,
        });
    }

    // ------------------------------------------------------------------
    // AgentLogEvent round-trips
    // ------------------------------------------------------------------

    #[test]
    fn roundtrip_agent_log_event() {
        roundtrip(&AgentLogEvent {
            level: LogLevel::Info,
            target: "agent::scan_loop".into(),
            message: "found 3 new listening ports".into(),
        });
    }

    #[test]
    fn roundtrip_agent_log_all_levels() {
        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            roundtrip(&AgentLogEvent {
                level,
                target: "test".into(),
                message: format!("testing level {:?}", level),
            });
        }
    }

    #[test]
    fn roundtrip_agent_log_empty_message() {
        roundtrip(&AgentLogEvent {
            level: LogLevel::Debug,
            target: String::new(),
            message: String::new(),
        });
    }

    #[test]
    fn roundtrip_agent_log_large_message() {
        roundtrip(&AgentLogEvent {
            level: LogLevel::Warn,
            target: "agent".into(),
            message: "x".repeat(100_000),
        });
    }

    #[test]
    fn roundtrip_agent_log_unicode() {
        roundtrip(&AgentLogEvent {
            level: LogLevel::Info,
            target: "agent::module".into(),
            message: "Hello 世界 🌍 Привет مرحبا".into(),
        });
    }

    #[test]
    fn roundtrip_agent_log_special_chars() {
        roundtrip(&AgentLogEvent {
            level: LogLevel::Error,
            target: "agent::parser".into(),
            message: "Line 1\nLine 2\tTab\r\nCRLF\0Null".into(),
        });
    }

    #[test]
    fn roundtrip_agent_log_long_target() {
        let long_target = "agent::".to_string() + &"module::".repeat(100);
        roundtrip(&AgentLogEvent {
            level: LogLevel::Debug,
            target: long_target,
            message: "test".into(),
        });
    }

    // ------------------------------------------------------------------
    // LogLevel-specific tests
    // ------------------------------------------------------------------

    #[test]
    fn log_level_equality() {
        assert_eq!(LogLevel::Error, LogLevel::Error);
        assert_ne!(LogLevel::Error, LogLevel::Warn);
        assert_ne!(LogLevel::Info, LogLevel::Debug);
    }

    #[test]
    fn log_level_clone_copy() {
        let level = LogLevel::Info;
        let cloned = level.clone();
        let copied = level;
        assert_eq!(cloned, LogLevel::Info);
        assert_eq!(copied, LogLevel::Info);
    }
}
