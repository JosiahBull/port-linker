//! Target agent that runs on the remote host.
//!
//! This binary is embedded in port-linker and transferred to remote hosts via SSH.
//! It provides two capabilities over the stdin/stdout protocol:
//!
//! 1. **Port scanning**: Responds to `ScanRequest` messages with discovered listening ports.
//! 2. **Multiplexed UDP forwarding**: Manages multiple UDP sockets and routes packets
//!    by port, all over a single SSH channel.
//!
//! # Protocol
//!
//! Communication uses the proto crate's Message format over stdin/stdout.
//!
//! # Healthcheck
//!
//! The agent responds to Ping messages with Pong messages. If no Ping is received
//! for 60 seconds, the agent automatically shuts down to prevent zombie processes.

#[macro_use]
mod logging;
#[cfg(feature = "agent-tracing")]
pub(crate) mod subscriber;

use proto::{Message, ScanFlags, UdpPacket};
use scanner::{encode_remote_ports, pick_scanner, Platform, PortScanner};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use transport::{NegotiationMessage, TransportEntry, TransportKind, TransportOffer};

/// Timeout after which the agent shuts down if no healthcheck is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

fn main() {
    #[cfg(feature = "agent-tracing")]
    {
        let sub = subscriber::BufferedStdoutSubscriber::new();
        tracing::subscriber::set_global_default(sub).expect("failed to set tracing subscriber");
    }

    if let Err(e) = run() {
        eprintln!("agent error: {}", e);
        std::process::exit(1);
    }
}

/// State for a single UDP forwarding socket.
struct UdpForwardState {
    socket: UdpSocket,
    target_addr: String,
    last_packet_id: u32,
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "debug-only stat counters behind cfg(debug_assertions)"
)]
fn run() -> io::Result<()> {
    agent_debug!("Starting agent");

    // Detect platform and pick best scanner
    let platform = Platform::detect();
    agent_debug!(
        "Platform: os={:?}, procfs={}, ss={}, netstat={}",
        platform.os,
        platform.has_procfs,
        platform.has_ss,
        platform.has_netstat
    );

    let scanner: Option<Box<dyn PortScanner>> = pick_scanner(&platform);
    #[allow(
        clippy::branches_sharing_code,
        reason = "branches differ when agent-tracing feature is enabled"
    )]
    if let Some(ref _s) = scanner {
        agent_debug!("Using scanner: {}", _s.name());
    } else {
        agent_debug!("No suitable scanner found");
    }

    // Set stdin to non-blocking
    set_nonblocking_stdin()?;

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut read_buf = vec![0_u8; 65536];
    let mut pending_buf = Vec::with_capacity(65536);

    // --- Transport negotiation ---
    agent_debug!("Starting transport negotiation");
    let mut offer_transports = vec![TransportEntry {
        kind: TransportKind::Stdio,
        data: vec![],
    }];

    // Probe TCP capability
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            if let Ok(addr) = listener.local_addr() {
                let port = addr.port();
                agent_debug!("TCP available on port {}", port);
                offer_transports.push(TransportEntry {
                    kind: TransportKind::Tcp,
                    data: port.to_be_bytes().to_vec(),
                });
            }
            drop(listener);
        }
        Err(_e) => {
            agent_debug!("TCP not available: {}", _e);
        }
    }

    // Probe QUIC/UDP capability
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            if let Ok(addr) = sock.local_addr() {
                let port = addr.port();
                agent_debug!("UDP available on port {} (QUIC candidate)", port);
                // QUIC offer data = port:2 BE + fingerprint:32
                // For now just advertise the port; full QUIC setup would generate a cert
                // and include the fingerprint. Since host doesn't have a QUIC connector
                // yet, this just signals capability.
                let mut data = port.to_be_bytes().to_vec();
                data.extend_from_slice(&[0_u8; 32]); // placeholder fingerprint
                offer_transports.push(TransportEntry {
                    kind: TransportKind::Quic,
                    data,
                });
            }
            drop(sock);
        }
        Err(_e) => {
            agent_debug!("UDP not available (no QUIC): {}", _e);
        }
    }

    let offer = TransportOffer {
        version: 1,
        transports: offer_transports,
    };
    agent_debug!(
        "Sending TransportOffer: {} transports (v{})",
        offer.transports.len(),
        offer.version
    );
    let encoded_offer = offer.encode();
    stdout.write_all(&encoded_offer)?;
    stdout.flush()?;

    // Wait for TransportAccept from host (poll non-blocking stdin)
    let accept_start = Instant::now();
    let accept_timeout = Duration::from_secs(2);
    let _selected_transport = loop {
        if accept_start.elapsed() > accept_timeout {
            agent_debug!("Transport negotiation timed out waiting for accept, falling back to stdio");
            break TransportKind::Stdio;
        }

        match stdin.read(&mut read_buf) {
            Ok(0) => {
                agent_debug!("SSH channel closed during negotiation");
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed during negotiation"));
            }
            Ok(n) => {
                pending_buf.extend_from_slice(read_buf.get(..n).unwrap_or(&[]));

                if NegotiationMessage::is_negotiation_type(&pending_buf) {
                    if let Some((msg, consumed)) = NegotiationMessage::decode(&pending_buf) {
                        if let NegotiationMessage::Accept(accept) = msg {
                            agent_debug!("Host selected transport: {:?}", accept.kind);
                            pending_buf.drain(..consumed);
                            break accept.kind;
                        }
                        // Unexpected Offer from host
                        agent_debug!("Received unexpected TransportOffer from host");
                        pending_buf.drain(..consumed);
                        break TransportKind::Stdio;
                    }
                    // Incomplete, keep reading
                } else if pending_buf.len() >= 5 {
                    // Host sent a proto::Message instead of TransportAccept — legacy host
                    agent_debug!("Host sent proto::Message without negotiation (legacy host)");
                    break TransportKind::Stdio;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                agent_debug!("Read error during negotiation: {}", e);
                return Err(e);
            }
        }
    };
    agent_debug!("Transport negotiation complete, selected: {:?}", selected_transport);

    agent_debug!("Initialized, entering main loop");
    let mut recv_buf = [0_u8; 65535];

    // UDP forwarding sockets: port -> state
    let mut udp_sockets: HashMap<u16, UdpForwardState> = HashMap::new();

    // Track last healthcheck time
    let mut last_healthcheck = Instant::now();

    // Stats for debug builds (only used when agent-tracing is also enabled)
    #[cfg(all(debug_assertions, feature = "agent-tracing"))]
    let mut packets_forwarded: u64 = 0;
    #[cfg(all(debug_assertions, feature = "agent-tracing"))]
    let mut packets_received: u64 = 0;
    #[cfg(all(debug_assertions, feature = "agent-tracing"))]
    let mut pings_received: u64 = 0;

    loop {
        // Check healthcheck timeout
        if last_healthcheck.elapsed() > HEALTHCHECK_TIMEOUT {
            agent_warn!("Healthcheck timeout - shutting down");
            eprintln!("Healthcheck timeout - shutting down");
            break;
        }

        // Try to read from stdin (SSH channel)
        match stdin.read(&mut read_buf) {
            Ok(0) => {
                agent_debug!("SSH channel closed (EOF)");
                break;
            }
            Ok(n) => {
                agent_trace!("Read {} bytes from SSH channel", n);
                pending_buf.extend_from_slice(read_buf.get(..n).unwrap_or(&[]));

                // Process all complete messages in the buffer
                while let Some((message, consumed)) = Message::decode(&pending_buf) {
                    match message {
                        Message::Udp(packet) => {
                            handle_udp_packet(&packet, &mut udp_sockets);
                            #[cfg(all(debug_assertions, feature = "agent-tracing"))]
                            {
                                packets_forwarded += 1;
                            }
                        }
                        Message::Ping(value) => {
                            last_healthcheck = Instant::now();
                            #[cfg(all(debug_assertions, feature = "agent-tracing"))]
                            {
                                pings_received += 1;
                            }
                            agent_trace!("Received ping {}, sending pong", value);
                            let pong = Message::Pong(value);
                            let encoded = pong.encode();
                            if let Err(e) = stdout.write_all(&encoded) {
                                agent_error!("Failed to send Pong: {}", e);
                            }
                            drop(stdout.flush());
                        }
                        Message::Pong(_) => {
                            agent_debug!("Received unexpected Pong message");
                        }
                        Message::ScanRequest(flags) => {
                            handle_scan_request(flags, scanner.as_deref(), &mut stdout);
                        }
                        Message::StartUdpForward {
                            port,
                            bind_addr_type: _,
                            bind_addr,
                        } => {
                            handle_start_udp_forward(port, &bind_addr, &mut udp_sockets);
                        }
                        Message::StopUdpForward(port) => {
                            handle_stop_udp_forward(port, &mut udp_sockets);
                        }
                        Message::ScanResponse(_) => {
                            agent_debug!("Received unexpected ScanResponse");
                        }
                        Message::LogBatch(_) => {
                            // Agent should not receive LogBatch messages
                        }
                    }

                    pending_buf.drain(..consumed);

                    // Size-triggered flush inside message decode loop (burst protection)
                    #[cfg(feature = "agent-tracing")]
                    if subscriber::should_flush() {
                        subscriber::flush_log_buffer(&mut stdout);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available, continue
            }
            Err(e) => {
                agent_error!("Stdin read error: {}", e);
                return Err(e);
            }
        }

        // Check all UDP sockets for responses from target services
        for (&port, state) in &mut udp_sockets {
            loop {
                match state.socket.recv_from(&mut recv_buf) {
                    Ok((n, _src)) => {
                        agent_trace!("Received UDP response on port {} ({} bytes)", port, n);
                        #[cfg(all(debug_assertions, feature = "agent-tracing"))]
                        {
                            packets_received += 1;
                        }

                        let response = UdpPacket::new(
                            0,
                            port,
                            state.last_packet_id,
                            recv_buf.get(..n).unwrap_or(&[]).to_vec(),
                        );
                        let message = Message::Udp(response);
                        let encoded = message.encode();
                        if let Err(e) = stdout.write_all(&encoded) {
                            agent_error!("Failed to send UDP response: {}", e);
                        }
                        drop(stdout.flush());
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => {
                        agent_error!("UDP recv error on port {}: {}", port, e);
                        break;
                    }
                }
            }
        }

        // Flush log buffer at end of each main loop iteration
        #[cfg(feature = "agent-tracing")]
        subscriber::flush_log_buffer(&mut stdout);

        // Small sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_micros(100));
    }

    // Log final stats (only when both debug_assertions and agent-tracing are active)
    #[cfg(all(debug_assertions, feature = "agent-tracing"))]
    {
        agent_info!(
            "Shutting down. Stats: forwarded={}, received={}, pings={}",
            packets_forwarded,
            packets_received,
            pings_received
        );
    }

    // Final flush before exit
    #[cfg(feature = "agent-tracing")]
    subscriber::flush_log_buffer(&mut stdout);

    Ok(())
}

fn handle_udp_packet(packet: &UdpPacket, udp_sockets: &mut HashMap<u16, UdpForwardState>) {
    let port = packet.dst_port;
    if let Some(state) = udp_sockets.get_mut(&port) {
        state.last_packet_id = packet.id;
        agent_trace!(
            "Forwarding UDP packet id={} ({} bytes) to {}",
            packet.id,
            packet.data.len(),
            state.target_addr
        );
        if let Err(e) = state.socket.send_to(&packet.data, &state.target_addr) {
            agent_error!("Failed to send UDP packet to port {}: {}", port, e);
        }
    } else {
        agent_debug!("No UDP socket for port {}", port);
    }
}

fn handle_scan_request(
    flags: ScanFlags,
    scanner: Option<&dyn PortScanner>,
    stdout: &mut io::Stdout,
) {
    agent_debug!("Scan request: tcp={}, udp={}", flags.tcp, flags.udp);

    let scanner = match scanner {
        Some(s) => s,
        None => {
            // Send empty response
            let resp = Message::ScanResponse(encode_remote_ports(&[]));
            let encoded = resp.encode();
            drop(stdout.write_all(&encoded));
            drop(stdout.flush());
            return;
        }
    };

    let mut ports = Vec::new();

    if flags.tcp {
        match scanner.scan(proto::Protocol::Tcp) {
            Ok(tcp_ports) => ports.extend(tcp_ports),
            Err(_e) => {
                agent_warn!("TCP scan error: {}", _e);
            }
        }
    }

    if flags.udp {
        match scanner.scan(proto::Protocol::Udp) {
            Ok(udp_ports) => ports.extend(udp_ports),
            Err(_e) => {
                agent_warn!("UDP scan error: {}", _e);
            }
        }
    }

    agent_debug!("Scan found {} ports", ports.len());

    let data = encode_remote_ports(&ports);
    let resp = Message::ScanResponse(data);
    let encoded = resp.encode();
    if let Err(e) = stdout.write_all(&encoded) {
        agent_error!("Failed to send scan response: {}", e);
    }
    drop(stdout.flush());
}

fn handle_start_udp_forward(
    port: u16,
    bind_addr: &[u8],
    udp_sockets: &mut HashMap<u16, UdpForwardState>,
) {
    agent_debug!("Starting UDP forward for port {}", port);

    // Parse bind address from raw bytes
    let target_addr = match bind_addr.len() {
        4 => {
            let a = bind_addr.first().copied().unwrap_or(0);
            let b = bind_addr.get(1).copied().unwrap_or(0);
            let c = bind_addr.get(2).copied().unwrap_or(0);
            let d = bind_addr.get(3).copied().unwrap_or(0);
            let addr = std::net::Ipv4Addr::new(a, b, c, d);
            // Normalize: unspecified -> localhost
            if addr.is_unspecified() {
                format!("127.0.0.1:{}", port)
            } else {
                format!("{}:{}", addr, port)
            }
        }
        16 => {
            let mut octets = [0_u8; 16];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = bind_addr.get(i).copied().unwrap_or(0);
            }
            let addr = std::net::Ipv6Addr::from(octets);
            if addr.is_unspecified() {
                format!("127.0.0.1:{}", port)
            } else if addr.is_loopback() {
                format!("[::1]:{}", port)
            } else {
                format!("[{}]:{}", addr, port)
            }
        }
        _ => {
            // Default to localhost
            format!("127.0.0.1:{}", port)
        }
    };

    // Create and bind UDP socket
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            agent_error!("Failed to bind UDP socket for port {}: {}", port, e);
            return;
        }
    };

    if let Err(e) = socket.set_nonblocking(true) {
        agent_error!("Failed to set non-blocking for port {}: {}", port, e);
        return;
    }

    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(10))) {
        agent_error!("Failed to set read timeout for port {}: {}", port, e);
        return;
    }

    agent_debug!("UDP socket for port {} -> {}", port, target_addr);

    udp_sockets.insert(
        port,
        UdpForwardState {
            socket,
            target_addr,
            last_packet_id: 0,
        },
    );
}

fn handle_stop_udp_forward(port: u16, udp_sockets: &mut HashMap<u16, UdpForwardState>) {
    agent_debug!("Stopping UDP forward for port {}", port);
    udp_sockets.remove(&port);
}

/// Set stdin to non-blocking mode on Unix systems.
fn set_nonblocking_stdin() -> io::Result<()> {
    let stdin_fd = io::stdin().as_raw_fd();

    // SAFETY: fcntl with F_GETFL and F_SETFL are standard POSIX operations
    // on a valid file descriptor (stdin).
    let flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: Setting O_NONBLOCK on stdin's file descriptor.
    let result = unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
