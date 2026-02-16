//! Minimal stateful UDP relay for port-linker jump hosts.
//!
//! This binary is deployed on SSH jump hosts to relay UDP traffic between
//! the port-linker host and the next hop (another relay or the agent).
//!
//! Protocol:
//! - Binds a UDP socket on `0.0.0.0:0`
//! - Prints `RELAY_READY\nPORT=<port>\n` to stdout
//! - First datagram from any source becomes the "client"
//! - All subsequent datagrams are forwarded bidirectionally between client and target
//! - `PLK_PROBE` datagram gets `PLK_PROBE_ACK` response (connectivity check)
//! - Exits after 60s of inactivity

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

/// Probe request payload.
const PROBE_REQUEST: &[u8] = b"PLK_PROBE";

/// Probe acknowledgement payload.
const PROBE_ACK: &[u8] = b"PLK_PROBE_ACK";

/// Idle timeout before the relay exits.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum UDP datagram size.
const MAX_DATAGRAM: usize = 65535;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let target_addr = parse_args();

    if let Err(e) = run(target_addr).await {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

fn parse_args() -> SocketAddr {
    let args: Vec<String> = std::env::args().collect();

    let target = if args.len() == 3 && args[1] == "--target" {
        &args[2]
    } else {
        eprintln!("Usage: port-linker-relay --target <host:port>");
        std::process::exit(1);
    };

    target.parse().unwrap_or_else(|e| {
        eprintln!("invalid target address '{target}': {e}");
        std::process::exit(1);
    })
}

async fn run(target_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
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
                last_activity = Instant::now();
                let data = &buf[..len];

                // Handle probe request from any source.
                if data == PROBE_REQUEST {
                    let _ = socket.send_to(PROBE_ACK, src).await;
                    continue;
                }

                if client_addr.is_none() {
                    // First non-probe datagram sets the client.
                    client_addr = Some(src);
                    eprintln!("relay: client registered as {src}");
                }

                if Some(src) == client_addr {
                    // Client -> target.
                    let _ = socket.send_to(data, target_addr).await;
                } else if src == target_addr {
                    // Target -> client.
                    if let Some(client) = client_addr {
                        let _ = socket.send_to(data, client).await;
                    }
                }
                // Ignore datagrams from unknown sources.
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
