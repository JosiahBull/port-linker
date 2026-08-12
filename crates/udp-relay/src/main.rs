//! Minimal stateful UDP relay for port-linker jump hosts.
//!
//! This binary is deployed on SSH jump hosts to relay UDP traffic between
//! the port-linker host and the next hop (another relay or the agent).
//!
//! # Authentication
//!
//! The relay listens on a public interface, so it demands proof of the session
//! secret before it will forward anything. The secret arrives on **stdin**,
//! inside the SSH channel that deployed the relay — never in `argv`, which is
//! world-readable through `ps` on a shared jump host.
//!
//! A client registers by sending `PLK_HELLO:<secret>` and receiving
//! `PLK_HELLO_ACK`. Only that source address is relayed thereafter. Without
//! this, whoever sent the first datagram became the client, so any local user
//! could take over the relay or knock the real host off it.
//!
//! In a multi-hop chain each relay forwards a valid registration to its own
//! target, so every hop learns its upstream neighbour as its client. All hops
//! hold the same secret already, each delivered over its own SSH channel.
//!
//! The relayed payload is QUIC, which is already end-to-end encrypted and
//! mutually authenticated between host and agent, so the relay cannot read or
//! alter the traffic it carries — this check is about who gets to use the relay
//! at all.
//!
//! Protocol:
//! - Reads `SESSION_SECRET=<hex>` from stdin
//! - Binds a UDP socket on `0.0.0.0:0`
//! - Prints `RELAY_READY\nPORT=<port>\n` to stdout
//! - `PLK_HELLO:<secret>` registers the sender as the client, answered by
//!   `PLK_HELLO_ACK`
//! - `PLK_PROBE:<secret>` gets `PLK_PROBE_ACK` (connectivity check)
//! - Subsequent datagrams are forwarded bidirectionally between client and target
//! - Exits after 60s of inactivity

use std::io::BufRead;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

/// Prefix of an authenticated registration request.
const HELLO_PREFIX: &[u8] = b"PLK_HELLO:";

/// Registration acknowledgement.
const HELLO_ACK: &[u8] = b"PLK_HELLO_ACK";

/// Prefix of an authenticated probe request.
const PROBE_PREFIX: &[u8] = b"PLK_PROBE:";

/// Probe acknowledgement payload.
const PROBE_ACK: &[u8] = b"PLK_PROBE_ACK";

/// Idle timeout before the relay exits.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum UDP datagram size.
const MAX_DATAGRAM: usize = 65535;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let target_addr = parse_args();

    let secret = match read_secret() {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("relay error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run(target_addr, &secret).await {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

fn parse_args() -> SocketAddr {
    let args: Vec<String> = std::env::args().collect();

    let target = match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("--target"), Some(target)) if args.len() == 3 => target,
        _ => {
            eprintln!("Usage: port-linker-relay --target <host:port>");
            eprintln!("The session secret is read from stdin as SESSION_SECRET=<hex>.");
            std::process::exit(1);
        }
    };

    target.parse().unwrap_or_else(|e| {
        eprintln!("invalid target address '{target}': {e}");
        std::process::exit(1);
    })
}

/// Read `SESSION_SECRET=<hex>` from stdin.
///
/// Fails closed: with no secret the relay would forward for anyone, so it
/// refuses to start instead.
fn read_secret() -> Result<String, String> {
    let stdin = std::io::stdin();
    let mut secret = None;

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("failed to read stdin: {e}"))?;
        let line = line.trim();
        if let Some(value) = line.strip_prefix("SESSION_SECRET=") {
            secret = Some(value.trim().to_string());
        }
        if line == "END_SESSION" {
            break;
        }
    }

    match secret {
        Some(secret) if !secret.is_empty() => Ok(secret),
        _ => Err(
            "no SESSION_SECRET on stdin; the relay must be launched by the \
             port-linker host, which supplies the secret that authorises use \
             of the relay"
                .to_string(),
        ),
    }
}

/// Compare a presented credential with the expected one without leaking its
/// contents through timing.
fn credential_matches(presented: &[u8], expected: &str) -> bool {
    use subtle::ConstantTimeEq;

    let matches: bool = presented.ct_eq(expected.as_bytes()).into();
    matches
}

async fn run(target_addr: SocketAddr, secret: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    let port = local_addr.port();

    // Print handshake to stdout.
    {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "RELAY_READY")?;
        writeln!(stdout, "PORT={port}")?;
        stdout.flush()?;
    }

    eprintln!("relay listening on {local_addr}, forwarding to {target_addr}");

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut client_addr: Option<SocketAddr> = None;
    let mut last_activity = Instant::now();

    loop {
        let recv_result = timeout(IDLE_TIMEOUT, socket.recv_from(&mut buf)).await;

        match recv_result {
            Ok(Ok((len, src))) => {
                let data = buf.get(..len).unwrap_or_default();

                // Authenticated registration: the sender proves it holds the
                // session secret, and only then becomes the client.
                if let Some(presented) = data.strip_prefix(HELLO_PREFIX) {
                    if credential_matches(presented, secret) {
                        last_activity = Instant::now();
                        if client_addr != Some(src) {
                            eprintln!("relay: client registered as {src}");
                        }
                        client_addr = Some(src);
                        let _ = socket.send_to(HELLO_ACK, src).await;

                        // Propagate the registration down the chain so the next
                        // hop learns *this* relay as its client. Every relay in
                        // the chain already holds the same session secret,
                        // delivered over its own SSH channel. When the target is
                        // the agent rather than another relay, its QUIC endpoint
                        // discards this as a malformed packet.
                        let _ = socket.send_to(data, target_addr).await;
                    } else {
                        eprintln!("relay: rejected registration from {src} (bad secret)");
                    }
                    continue;
                }

                // The acknowledgement a downstream relay sent back to us. It is
                // not tunnel traffic and must not be forwarded to our client.
                if data == HELLO_ACK && src == target_addr {
                    continue;
                }

                // Authenticated probe. Does not register a client, so a probe
                // cannot be used to squat the relay.
                if let Some(presented) = data.strip_prefix(PROBE_PREFIX) {
                    if credential_matches(presented, secret) {
                        last_activity = Instant::now();
                        let _ = socket.send_to(PROBE_ACK, src).await;
                    }
                    continue;
                }

                // Everything else is opaque tunnel traffic, forwarded only
                // between the registered client and the configured target.
                if Some(src) == client_addr {
                    last_activity = Instant::now();
                    let _ = socket.send_to(data, target_addr).await;
                } else if src == target_addr
                    && let Some(client) = client_addr
                {
                    last_activity = Instant::now();
                    let _ = socket.send_to(data, client).await;
                }
                // Datagrams from anyone else are dropped without a response,
                // so the relay is silent to unauthenticated scanners.
            }
            Ok(Err(e)) => {
                eprintln!("relay recv error: {e}");
                break;
            }
            Err(_) => {
                // Idle timeout.
                let idle = last_activity.elapsed();
                if idle >= IDLE_TIMEOUT {
                    eprintln!("relay: idle timeout ({idle:?}), exiting");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_matches_exact_secret() {
        assert!(credential_matches(b"abc123", "abc123"));
    }

    #[test]
    fn credential_rejects_wrong_secret() {
        assert!(!credential_matches(b"abc124", "abc123"));
    }

    #[test]
    fn credential_rejects_prefix_and_suffix() {
        assert!(!credential_matches(b"abc", "abc123"));
        assert!(!credential_matches(b"abc1234", "abc123"));
    }

    #[test]
    fn credential_rejects_empty() {
        assert!(!credential_matches(b"", "abc123"));
    }

    #[test]
    fn hello_prefix_splits_secret() {
        let datagram = b"PLK_HELLO:deadbeef";
        let presented = datagram.strip_prefix(HELLO_PREFIX).unwrap();
        assert_eq!(presented, b"deadbeef");
        assert!(credential_matches(presented, "deadbeef"));
    }

    #[test]
    fn probe_prefix_splits_secret() {
        let datagram = b"PLK_PROBE:deadbeef";
        let presented = datagram.strip_prefix(PROBE_PREFIX).unwrap();
        assert!(credential_matches(presented, "deadbeef"));
    }

    #[test]
    fn tunnel_traffic_is_not_mistaken_for_a_credential() {
        // A QUIC initial packet must not look like a hello or probe.
        let quic_like = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];
        assert!(quic_like.strip_prefix(HELLO_PREFIX).is_none());
        assert!(quic_like.strip_prefix(PROBE_PREFIX).is_none());
    }
}
