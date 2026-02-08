//! Transport negotiation types and their wire format.
//!
//! These types are used during the initial handshake between host and agent
//! to select the best available transport (stdio, TCP, or QUIC).
//!
//! # Wire Format
//!
//! TransportOffer and TransportAccept are encoded as TLV messages using the
//! same `[type:1][len:4][payload:variable]` framing as `proto::Message`,
//! but with dedicated type bytes (`0x10` for offer, `0x11` for accept).

/// Message type byte for TransportOffer.
const MSG_TRANSPORT_OFFER: u8 = 0x10;

/// Message type byte for TransportAccept.
const MSG_TRANSPORT_ACCEPT: u8 = 0x11;

/// Available transport mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// SSH exec channel stdin/stdout (always available).
    Stdio,
    /// TCP socket via SSH direct-tcpip.
    Tcp,
    /// QUIC over UDP (bypasses SSH for data).
    Quic,
}

impl TransportKind {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Stdio => 0,
            Self::Tcp => 1,
            Self::Quic => 2,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Stdio),
            1 => Some(Self::Tcp),
            2 => Some(Self::Quic),
            _ => None,
        }
    }
}

/// A single transport entry in a `TransportOffer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportEntry {
    /// Which transport this entry describes.
    pub kind: TransportKind,
    /// Opaque data for the transport (e.g. port bytes, QUIC fingerprint).
    pub data: Vec<u8>,
}

/// Sent by the agent to advertise available transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportOffer {
    /// Protocol version.
    pub version: u32,
    /// Available transports, ordered by agent preference.
    pub transports: Vec<TransportEntry>,
}

/// Sent by the host to select a transport from the offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportAccept {
    /// The chosen transport.
    pub kind: TransportKind,
}

/// A decoded negotiation message (offer or accept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationMessage {
    Offer(TransportOffer),
    Accept(TransportAccept),
}

impl TransportOffer {
    /// Encode as a TLV message: `[0x10][len:4][version:4][count:1][entries...]`
    ///
    /// Each entry: `[kind:1][data_len:2 BE][data:variable]`
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.version.to_be_bytes());

        let count = self.transports.len().min(255);
        payload.push(count as u8);

        for entry in self.transports.get(..count).unwrap_or(&self.transports) {
            payload.push(entry.kind.to_byte());
            let data_len = entry.data.len().min(u16::MAX as usize);
            payload.extend_from_slice(&(data_len as u16).to_be_bytes());
            payload.extend_from_slice(entry.data.get(..data_len).unwrap_or(&entry.data));
        }

        let mut buf = Vec::with_capacity(1_usize.saturating_add(4).saturating_add(payload.len()));
        buf.push(MSG_TRANSPORT_OFFER);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }
}

impl TransportAccept {
    /// Encode as a TLV message: `[0x11][len:4][kind:1]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6);
        buf.push(MSG_TRANSPORT_ACCEPT);
        buf.extend_from_slice(&1_u32.to_be_bytes());
        buf.push(self.kind.to_byte());
        buf
    }
}

impl NegotiationMessage {
    /// Decode a negotiation message from a byte buffer.
    ///
    /// Returns the message and bytes consumed, or `None` if incomplete/invalid.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
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

        let total = 5_usize.checked_add(len)?;
        if buf.len() < total {
            return None;
        }

        let payload = buf.get(5..total)?;

        match msg_type {
            MSG_TRANSPORT_OFFER => {
                if payload.len() < 5 {
                    return None;
                }
                let version = u32::from_be_bytes([
                    *payload.first()?,
                    *payload.get(1)?,
                    *payload.get(2)?,
                    *payload.get(3)?,
                ]);
                let count = usize::from(*payload.get(4)?);
                let mut offset = 5_usize;
                let mut transports = Vec::with_capacity(count);

                for _ in 0..count {
                    if offset.saturating_add(3) > payload.len() {
                        return None;
                    }
                    let kind = TransportKind::from_byte(*payload.get(offset)?)?;
                    let data_len = u16::from_be_bytes([
                        *payload.get(offset.saturating_add(1))?,
                        *payload.get(offset.saturating_add(2))?,
                    ]) as usize;
                    offset = offset.saturating_add(3);

                    if offset.saturating_add(data_len) > payload.len() {
                        return None;
                    }
                    let data = payload.get(offset..offset.saturating_add(data_len))?.to_vec();
                    offset = offset.saturating_add(data_len);
                    transports.push(TransportEntry { kind, data });
                }

                Some((
                    Self::Offer(TransportOffer {
                        version,
                        transports,
                    }),
                    total,
                ))
            }
            MSG_TRANSPORT_ACCEPT => {
                let kind = TransportKind::from_byte(*payload.first()?)?;
                Some((Self::Accept(TransportAccept { kind }), total))
            }
            _ => None,
        }
    }

    /// Check if a buffer's first byte is a negotiation message type.
    ///
    /// This allows callers to distinguish negotiation messages from
    /// `proto::Message` traffic without fully decoding.
    pub const fn is_negotiation_type(buf: &[u8]) -> bool {
        matches!(buf.first(), Some(&MSG_TRANSPORT_OFFER | &MSG_TRANSPORT_ACCEPT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_roundtrip() {
        for kind in [TransportKind::Stdio, TransportKind::Tcp, TransportKind::Quic] {
            assert_eq!(TransportKind::from_byte(kind.to_byte()), Some(kind));
        }
        assert_eq!(TransportKind::from_byte(0xFF), None);
    }

    #[test]
    fn test_offer_roundtrip() {
        let offer = TransportOffer {
            version: 1,
            transports: vec![
                TransportEntry {
                    kind: TransportKind::Quic,
                    data: vec![0; 34],
                },
                TransportEntry {
                    kind: TransportKind::Tcp,
                    data: vec![0x1F, 0x90],
                },
                TransportEntry {
                    kind: TransportKind::Stdio,
                    data: vec![],
                },
            ],
        };
        let encoded = offer.encode();
        let (decoded, consumed) = NegotiationMessage::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, NegotiationMessage::Offer(offer));
    }

    #[test]
    fn test_accept_roundtrip() {
        let accept = TransportAccept {
            kind: TransportKind::Tcp,
        };
        let encoded = accept.encode();
        let (decoded, consumed) = NegotiationMessage::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, NegotiationMessage::Accept(accept));
    }

    #[test]
    fn test_offer_empty_transports() {
        let offer = TransportOffer {
            version: 1,
            transports: vec![],
        };
        let encoded = offer.encode();
        let (decoded, consumed) = NegotiationMessage::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, NegotiationMessage::Offer(offer));
    }

    #[test]
    fn test_decode_incomplete() {
        let offer = TransportOffer {
            version: 1,
            transports: vec![TransportEntry {
                kind: TransportKind::Stdio,
                data: vec![],
            }],
        };
        let encoded = offer.encode();
        assert!(NegotiationMessage::decode(&encoded[..4]).is_none());
        assert!(NegotiationMessage::decode(&encoded[..6]).is_none());
    }

    #[test]
    fn test_is_negotiation_type() {
        assert!(NegotiationMessage::is_negotiation_type(&[MSG_TRANSPORT_OFFER]));
        assert!(NegotiationMessage::is_negotiation_type(&[MSG_TRANSPORT_ACCEPT]));
        assert!(!NegotiationMessage::is_negotiation_type(&[0x00]));
        assert!(!NegotiationMessage::is_negotiation_type(&[]));
    }
}
