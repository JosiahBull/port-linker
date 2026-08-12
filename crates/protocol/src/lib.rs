pub mod codec;
pub use codec::{decode, encode};

/// Current wire protocol version. Bump when making breaking changes.
///
/// Version 2 replaced the agent-generated bearer token with mutually pinned
/// TLS identities plus a host-proven session secret, so a v1 agent and a v2
/// host cannot interoperate — by design, since a v1 agent accepts any peer.
pub const PROTOCOL_VERSION: u32 = 2;

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
    /// Agent -> host. The first message on the control stream.
    ///
    /// `session_id` is the non-secret correlation id the host delivered over
    /// SSH; the host checks it to confirm it reached the agent it bootstrapped
    /// rather than a leftover process from an earlier run.
    Handshake {
        protocol_version: u32,
        session_id: String,
    },
    /// Host -> agent. Must be the first message the host sends.
    ///
    /// Proves the host holds the session secret that was delivered over the
    /// SSH channel. TLS has already authenticated both ends by pinned
    /// certificate at this point; this binds the connection to *this* bootstrap
    /// so a stale or replayed session cannot be served.
    SessionAuth { session_secret: String },
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
