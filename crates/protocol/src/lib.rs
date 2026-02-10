pub mod codec;
pub use codec::{decode, encode};

/// Current wire protocol version. Bump when making breaking changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Transport protocol for a forwarded port.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Log severity level for agent log forwarding (Architecture Section 7.1).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// A structured log event from the agent, sent over a dedicated QUIC
/// unidirectional stream (Architecture Section 7.1).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AgentLogEvent {
    pub level: LogLevel,
    pub target: String,
    pub message: String,
}

/// Messages sent on the QUIC control stream (stream 0).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum ControlMsg {
    /// Initial handshake. Must be the first message on a new connection.
    Handshake {
        protocol_version: u32,
        token: String,
    },
    /// The remote agent discovered a new listening port.
    PortAdded {
        port: u16,
        proto: Protocol,
        process_name: Option<String>,
    },
    /// A previously-reported port is no longer listening.
    PortRemoved { port: u16, proto: Protocol },
    /// Keep-alive ping.
    Heartbeat,
    /// Echo request (for latency measurement / diagnostics).
    EchoRequest { payload: Vec<u8> },
    /// Echo response (mirror of EchoRequest).
    EchoResponse { payload: Vec<u8> },
    /// Sent on a new QUIC stream to request a TCP connection to a port.
    TcpStreamInit { port: u16 },
    /// Sent back on the same stream if the agent cannot connect.
    TcpStreamError { port: u16, error: String },
}

/// Top-level packet that wraps either a control message or raw UDP data.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum Packet {
    /// A control-plane message.
    Control(ControlMsg),
    /// A UDP datagram payload destined for / originating from `port`.
    UdpData { port: u16, data: Vec<u8> },
}
