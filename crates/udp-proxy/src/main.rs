//! UDP proxy that runs on remote host.
//!
//! This binary is embedded in port-linker and transferred to remote hosts via SSH.
//! It reads framed messages from stdin, forwards UDP packets to local services,
//! responds to healthcheck pings, and writes responses back to stdout.
//!
//! # Usage
//!
//! ```text
//! udp-proxy <bind_address> <port>
//! ```
//!
//! # Protocol
//!
//! Communication uses the port-linker-proto Message format:
//! - Stdin: Receives Message frames (UDP packets or Ping healthchecks)
//! - Stdout: Sends Message frames (UDP responses or Pong healthchecks)
//!
//! # Healthcheck
//!
//! The proxy responds to Ping messages with Pong messages. If no Ping is received
//! for 60 seconds, the proxy automatically shuts down to prevent zombie processes.

use port_linker_proto::{Message, UdpPacket};
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Timeout after which the proxy shuts down if no healthcheck is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

fn main() {
    if let Err(e) = run() {
        eprintln!("udp-proxy error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: udp-proxy <bind_address> <port>");
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  bind_address  Address the target UDP service is bound to (e.g., 127.0.0.1)");
        eprintln!("  port          Port number of the target UDP service");
        std::process::exit(1);
    }

    let bind_addr = &args[1];
    let port: u16 = args[2].parse().expect("Invalid port number");

    // Normalize bind address - convert 0.0.0.0 and :: to localhost for sending
    let target_addr = match bind_addr.as_str() {
        "0.0.0.0" | "::" | "*" => "127.0.0.1",
        addr => addr,
    };
    let target = format!("{}:{}", target_addr, port);

    // Create UDP socket for forwarding to the target service
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;

    // Set read timeout on socket for polling
    socket.set_read_timeout(Some(Duration::from_millis(10)))?;

    // Set stdin to non-blocking using raw fd
    set_nonblocking_stdin()?;

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut read_buf = vec![0u8; 65536];
    let mut pending_buf = Vec::with_capacity(65536);
    let mut recv_buf = [0u8; 65535];

    // Track packet IDs for response correlation
    let mut last_packet_id: u32 = 0;

    // Track last healthcheck time
    let mut last_healthcheck = Instant::now();

    loop {
        // Check healthcheck timeout
        if last_healthcheck.elapsed() > HEALTHCHECK_TIMEOUT {
            eprintln!("Healthcheck timeout - shutting down");
            break;
        }

        // Try to read from stdin (SSH channel)
        match stdin.read(&mut read_buf) {
            Ok(0) => {
                // EOF - SSH channel closed
                break;
            }
            Ok(n) => {
                pending_buf.extend_from_slice(&read_buf[..n]);

                // Process all complete messages in the buffer
                while let Some((message, consumed)) = Message::decode(&pending_buf) {
                    match message {
                        Message::Udp(packet) => {
                            // Remember the packet ID for response correlation
                            last_packet_id = packet.id;

                            // Forward to target UDP service
                            if let Err(e) = socket.send_to(&packet.data, &target) {
                                eprintln!("Failed to send UDP packet: {}", e);
                            }
                        }
                        Message::Ping(value) => {
                            // Update healthcheck timestamp
                            last_healthcheck = Instant::now();

                            // Respond with Pong
                            let pong = Message::Pong(value);
                            let encoded = pong.encode();
                            if let Err(e) = stdout.write_all(&encoded) {
                                eprintln!("Failed to send Pong: {}", e);
                            }
                            let _ = stdout.flush();
                        }
                        Message::Pong(_) => {
                            // Ignore unexpected Pong messages
                        }
                    }

                    pending_buf.drain(..consumed);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available, continue to check for UDP responses
            }
            Err(e) => {
                return Err(e);
            }
        }

        // Try to receive UDP responses from the target service
        match socket.recv_from(&mut recv_buf) {
            Ok((n, _src)) => {
                // Create response packet with the last seen packet ID
                // This allows the local side to correlate responses
                let response = UdpPacket::new(
                    port, // src_port = the service port
                    0,    // dst_port = filled by local side
                    last_packet_id,
                    recv_buf[..n].to_vec(),
                );

                // Write response to stdout (SSH channel) as a Message
                let message = Message::Udp(response);
                let encoded = message.encode();
                stdout.write_all(&encoded)?;
                stdout.flush()?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No response available
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                // Timeout - no response available
            }
            Err(e) => {
                eprintln!("UDP recv error: {}", e);
            }
        }

        // Small sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_micros(100));
    }

    Ok(())
}

/// Set stdin to non-blocking mode on Unix systems.
fn set_nonblocking_stdin() -> io::Result<()> {
    let stdin_fd = io::stdin().as_raw_fd();

    // Get current flags
    let flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    // Set non-blocking flag
    let result = unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
