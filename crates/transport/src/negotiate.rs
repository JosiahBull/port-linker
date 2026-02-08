//! Transport negotiation between host and agent.
//!
//! After the agent starts via SSH exec channel, the following handshake occurs:
//!
//! 1. Agent probes local capabilities (can bind TCP? can bind UDP for QUIC?)
//! 2. Agent sends `TransportOffer` listing available transports
//! 3. Host picks the best matching transport based on `--transport` preference
//! 4. Host sends `TransportAccept` with the chosen transport
//! 5. Both sides switch to the chosen transport (2s timeout, fallback to stdio)

use crate::error::{Result, TransportError};
use crate::stdio::StdioTransport;
use crate::types::{NegotiationMessage, TransportAccept, TransportEntry, TransportKind, TransportOffer};
use crate::Transport;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Timeout for transport negotiation before falling back to stdio.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Host-side negotiation: wait for the agent's `TransportOffer` and select a transport.
///
/// Returns a boxed `Transport` trait object. On negotiation failure or timeout,
/// falls back to `StdioTransport` over the existing channel.
///
/// `tcp_connector` is called when TCP transport is selected. It receives the port
/// from the offer and should return a `TcpTransport` wrapping the connection.
///
/// `quic_connector` is called when QUIC transport is selected. It receives the
/// raw offer data (port:2 BE + fingerprint:32 = 34 bytes) and should return
/// a `QuicTransport` wrapping the connection.
pub fn negotiate_transport<R, W, F, G>(
    mut reader: R,
    writer: W,
    preferred: Option<TransportKind>,
    tcp_connector: Option<F>,
    quic_connector: Option<G>,
) -> Result<Box<dyn Transport>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    F: FnOnce(u16) -> Result<Box<dyn Transport>>,
    G: FnOnce(&[u8]) -> Result<Box<dyn Transport>>,
{
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];

    // Try to read the TransportOffer from the agent
    loop {
        if start.elapsed() > NEGOTIATION_TIMEOUT {
            debug!("Transport negotiation timed out, using stdio");
            return Ok(Box::new(StdioTransport::new(reader, writer)));
        }

        match reader.read(&mut tmp) {
            Ok(0) => {
                return Err(TransportError::Closed);
            }
            Ok(n) => {
                buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                // ssh2 reports EAGAIN as a generic error, not WouldBlock
                if e.raw_os_error() == Some(libc::EAGAIN) {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(TransportError::Io(e));
            }
        }

        // Try to decode a negotiation message
        if NegotiationMessage::is_negotiation_type(&buf) {
            if let Some((message, consumed)) = NegotiationMessage::decode(&buf) {
                match message {
                    NegotiationMessage::Offer(offer) => {
                        buf.drain(..consumed);
                        return handle_offer(
                            offer,
                            reader,
                            writer,
                            buf,
                            preferred,
                            tcp_connector,
                            quic_connector,
                        );
                    }
                    NegotiationMessage::Accept(_) => {
                        // Unexpected accept during host-side negotiation.
                        debug!("Received TransportAccept during negotiation, falling back to stdio");
                        let mut transport = StdioTransport::new(reader, writer);
                        transport.read_buf = buf;
                        return Ok(Box::new(transport));
                    }
                }
            }
        } else if buf.len() >= 5 {
            // First byte is not a negotiation message type — likely a proto::Message
            // from an old agent without negotiation. Fall back to stdio.
            debug!("Received non-negotiation message during negotiation, falling back to stdio");
            let mut transport = StdioTransport::new(reader, writer);
            transport.read_buf = buf;
            return Ok(Box::new(transport));
        } else {
            // Not enough data yet to determine message type
        }
    }
}

/// Convenience wrapper for callers that don't need TCP or QUIC support.
///
/// Avoids requiring type annotations for the unused connector closures.
pub fn negotiate_transport_stdio<R, W>(
    reader: R,
    writer: W,
    preferred: Option<TransportKind>,
) -> Result<Box<dyn Transport>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    negotiate_transport::<
        R,
        W,
        fn(u16) -> Result<Box<dyn Transport>>,
        fn(&[u8]) -> Result<Box<dyn Transport>>,
    >(reader, writer, preferred, None, None)
}

/// Process the agent's transport offer and select the best transport.
fn handle_offer<R, W, F, G>(
    offer: TransportOffer,
    reader: R,
    mut writer: W,
    leftover_buf: Vec<u8>,
    preferred: Option<TransportKind>,
    tcp_connector: Option<F>,
    quic_connector: Option<G>,
) -> Result<Box<dyn Transport>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    F: FnOnce(u16) -> Result<Box<dyn Transport>>,
    G: FnOnce(&[u8]) -> Result<Box<dyn Transport>>,
{
    info!(
        "Agent offered {} transports (protocol v{})",
        offer.transports.len(),
        offer.version
    );

    for entry in &offer.transports {
        debug!(
            "  Available: {:?} ({} bytes data)",
            entry.kind,
            entry.data.len()
        );
    }

    let selected = select_transport(&offer.transports, preferred);

    info!("Selected transport: {:?}", selected);

    // Send TransportAccept
    let accept = TransportAccept { kind: selected };
    let encoded = accept.encode();
    writer.write_all(&encoded).map_err(|e| {
        TransportError::Negotiation(format!("Failed to send TransportAccept: {}", e))
    })?;
    writer.flush().ok();

    match selected {
        TransportKind::Stdio => {
            let mut transport = StdioTransport::new(reader, writer);
            transport.read_buf = leftover_buf;
            Ok(Box::new(transport))
        }
        TransportKind::Tcp => {
            // Extract port from the TCP entry's data field
            let tcp_entry = offer
                .transports
                .iter()
                .find(|e| e.kind == TransportKind::Tcp);

            let port = tcp_entry.and_then(|e| {
                let hi = *e.data.first()?;
                let lo = *e.data.get(1)?;
                Some(u16::from_be_bytes([hi, lo]))
            });

            if let (Some(port), Some(connector)) = (port, tcp_connector) {
                match connector(port) {
                    Ok(transport) => {
                        info!("TCP transport connected on port {}", port);
                        Ok(transport)
                    }
                    Err(e) => {
                        warn!("TCP connector failed: {}, falling back to stdio", e);
                        let mut transport = StdioTransport::new(reader, writer);
                        transport.read_buf = leftover_buf;
                        Ok(Box::new(transport))
                    }
                }
            } else {
                warn!("TCP selected but no connector or port available, falling back to stdio");
                let mut transport = StdioTransport::new(reader, writer);
                transport.read_buf = leftover_buf;
                Ok(Box::new(transport))
            }
        }
        TransportKind::Quic => {
            let quic_entry = offer
                .transports
                .iter()
                .find(|e| e.kind == TransportKind::Quic);

            if let (Some(entry), Some(connector)) = (quic_entry, quic_connector) {
                match connector(&entry.data) {
                    Ok(transport) => {
                        info!("QUIC transport connected");
                        Ok(transport)
                    }
                    Err(e) => {
                        warn!("QUIC connector failed: {}, falling back to stdio", e);
                        let mut transport = StdioTransport::new(reader, writer);
                        transport.read_buf = leftover_buf;
                        Ok(Box::new(transport))
                    }
                }
            } else {
                warn!(
                    "QUIC selected but no connector or offer data available, falling back to stdio"
                );
                let mut transport = StdioTransport::new(reader, writer);
                transport.read_buf = leftover_buf;
                Ok(Box::new(transport))
            }
        }
    }
}

/// Select the best transport from the available options, respecting user preference.
///
/// Preference logic:
/// - `None` (Auto): QUIC > TCP > Stdio (best available)
/// - `Some(Stdio)`: always Stdio
/// - `Some(Tcp)`: TCP if available, else Stdio
/// - `Some(Quic)`: QUIC if available, else TCP, else Stdio
fn select_transport(
    available: &[TransportEntry],
    preferred: Option<TransportKind>,
) -> TransportKind {
    let has = |kind: TransportKind| available.iter().any(|e| e.kind == kind);

    match preferred {
        Some(TransportKind::Stdio) => TransportKind::Stdio,
        Some(TransportKind::Tcp) => {
            if has(TransportKind::Tcp) {
                TransportKind::Tcp
            } else {
                TransportKind::Stdio
            }
        }
        Some(TransportKind::Quic) => {
            if has(TransportKind::Quic) {
                TransportKind::Quic
            } else if has(TransportKind::Tcp) {
                TransportKind::Tcp
            } else {
                TransportKind::Stdio
            }
        }
        // Auto: best available (QUIC > TCP > Stdio)
        None => {
            if has(TransportKind::Quic) {
                TransportKind::Quic
            } else if has(TransportKind::Tcp) {
                TransportKind::Tcp
            } else {
                TransportKind::Stdio
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_transport_stdio_only() {
        let entries = vec![TransportEntry {
            kind: TransportKind::Stdio,
            data: vec![],
        }];
        assert_eq!(select_transport(&entries, None), TransportKind::Stdio);
    }

    #[test]
    fn test_select_transport_empty() {
        let entries: Vec<TransportEntry> = vec![];
        assert_eq!(select_transport(&entries, None), TransportKind::Stdio);
    }

    #[test]
    fn test_select_transport_multiple() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Tcp,
                data: vec![0x1F, 0x90], // port 8080
            },
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
        ];
        // Auto prefers TCP
        assert_eq!(select_transport(&entries, None), TransportKind::Tcp);
    }

    #[test]
    fn test_select_transport_auto_prefers_tcp() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
            TransportEntry {
                kind: TransportKind::Tcp,
                data: vec![0x1F, 0x90],
            },
        ];
        assert_eq!(select_transport(&entries, None), TransportKind::Tcp);
    }

    #[test]
    fn test_select_transport_auto_prefers_quic_over_tcp() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
            TransportEntry {
                kind: TransportKind::Tcp,
                data: vec![0x1F, 0x90],
            },
            TransportEntry {
                kind: TransportKind::Quic,
                data: vec![0; 34],
            },
        ];
        assert_eq!(select_transport(&entries, None), TransportKind::Quic);
    }

    #[test]
    fn test_select_transport_explicit_quic() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Quic,
                data: vec![0; 34],
            },
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
        ];
        assert_eq!(
            select_transport(&entries, Some(TransportKind::Quic)),
            TransportKind::Quic
        );
    }

    #[test]
    fn test_select_transport_quic_fallback_to_tcp() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Tcp,
                data: vec![0x1F, 0x90],
            },
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
        ];
        assert_eq!(
            select_transport(&entries, Some(TransportKind::Quic)),
            TransportKind::Tcp
        );
    }

    #[test]
    fn test_select_transport_explicit_stdio() {
        let entries = vec![
            TransportEntry {
                kind: TransportKind::Tcp,
                data: vec![0x1F, 0x90],
            },
            TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            },
        ];
        assert_eq!(
            select_transport(&entries, Some(TransportKind::Stdio)),
            TransportKind::Stdio
        );
    }

    #[test]
    fn test_select_transport_tcp_not_available() {
        let entries = vec![TransportEntry {
            kind: TransportKind::Stdio,
            data: vec![],
        }];
        assert_eq!(
            select_transport(&entries, Some(TransportKind::Tcp)),
            TransportKind::Stdio
        );
    }
}
