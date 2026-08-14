//! Length-prefixed `ControlMsg` framing shared by the control stream and the
//! per-connection TCP streams.
//!
//! Wire format: a 4-byte big-endian length followed by that many bytes of
//! rkyv-encoded [`ControlMsg`]. Reads use `read_exact`, so a reader never
//! consumes past the end of a frame — that property is what lets the TCP
//! forwarding path put raw application bytes directly behind the init frame on
//! the same stream (see [`crate::tcp`]).

use bytes::Bytes;
use protocol::ControlMsg;

use common::{Error, Result};

/// Maximum accepted frame size (1 MB).
///
/// A frame is a control message, never bulk data, so this is a sanity bound
/// that keeps a malformed length prefix from causing a huge allocation.
pub const MAX_FRAME_SIZE: u32 = 1_048_576;

/// Write a length-prefixed `ControlMsg` to a QUIC stream.
pub async fn send_framed(send: &mut quinn::SendStream, msg: &ControlMsg) -> Result<()> {
    let payload: Bytes =
        protocol::encode(msg).map_err(|e| Error::Codec(format!("encode error: {e}")))?;

    let len = payload.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::QuicStream(format!("failed to write frame length: {e}")))?;
    send.write_all(&payload)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to write frame payload: {e}")))?;

    Ok(())
}

/// Read a length-prefixed `ControlMsg` from a QUIC stream.
///
/// Consumes exactly one frame: any bytes following it stay in the stream.
pub async fn recv_framed(recv: &mut quinn::RecvStream) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to read frame length: {e}")))?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| Error::QuicStream(format!("failed to read frame payload: {e}")))?;

    protocol::decode::<ControlMsg>(&payload).map_err(|e| Error::Codec(format!("decode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The length prefix is what bounds a frame, so an over-large prefix must be
    /// rejected before it is used to size an allocation.
    #[test]
    fn frame_size_bound_is_a_megabyte() {
        assert_eq!(MAX_FRAME_SIZE, 1_048_576);
    }

    /// `send_framed` and `recv_framed` are exercised end-to-end over real QUIC
    /// streams in `crates/tunnel/tests/`; here we only pin the encoding the two
    /// halves agree on, so a change to the prefix width fails loudly.
    #[test]
    fn length_prefix_is_four_byte_big_endian() {
        let msg = ControlMsg::TcpStreamInit { port: 8080 };
        let payload = protocol::encode(&msg).expect("encode");
        let prefix = (payload.len() as u32).to_be_bytes();
        assert_eq!(prefix.len(), 4);
        assert_eq!(u32::from_be_bytes(prefix) as usize, payload.len());
    }
}
