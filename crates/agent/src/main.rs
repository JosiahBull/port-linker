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
//! Communication uses the proto crate's Message format. The transport layer is
//! negotiated at startup: Stdio (SSH exec channel), TCP (SSH direct-tcpip), or
//! QUIC (direct UDP, bypassing SSH for data).
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
use std::net::{TcpListener, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use transport::{
    NegotiationMessage, StdioTransport, TcpTransport, Transport, TransportEntry, TransportKind,
    TransportOffer,
};

/// Timeout after which the agent shuts down if no healthcheck is received.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for accepting a connection after transport negotiation.
/// Kept short so that failed QUIC/TCP attempts fall back quickly to stdio.
/// Real QUIC/TCP connections complete in <100ms; 1s is generous.
const TRANSPORT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

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

    // Probe TCP capability — keep listener alive for later use
    let mut tcp_listener: Option<TcpListener> = None;
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            if let Ok(addr) = listener.local_addr() {
                let port = addr.port();
                agent_debug!("TCP available on port {}", port);
                offer_transports.push(TransportEntry {
                    kind: TransportKind::Tcp,
                    data: port.to_be_bytes().to_vec(),
                });
                tcp_listener = Some(listener);
            }
        }
        Err(_e) => {
            agent_debug!("TCP not available: {}", _e);
        }
    }

    // Probe QUIC/UDP capability — generate real cert and set up server endpoint
    let mut quic_server: Option<(
        transport::quic::QuicEndpoint,
        UdpSocket,
        std::net::SocketAddr,
    )> = None;
    match transport::quic_config::generate_self_signed_cert() {
        Ok((cert_der, key_der, fingerprint)) => {
            match transport::quic_config::build_server_config(cert_der, key_der) {
                Ok(server_config) => match transport::quic::setup_quic_server(server_config) {
                    Ok((endpoint, socket, addr)) => {
                        let port = addr.port();
                        agent_debug!("QUIC server listening on port {}", port);
                        let mut data = port.to_be_bytes().to_vec();
                        data.extend_from_slice(&fingerprint);
                        offer_transports.push(TransportEntry {
                            kind: TransportKind::Quic,
                            data,
                        });
                        quic_server = Some((endpoint, socket, addr));
                    }
                    Err(_e) => {
                        agent_debug!("QUIC server setup failed: {}", _e);
                    }
                },
                Err(_e) => {
                    agent_debug!("QUIC server config failed: {}", _e);
                }
            }
        }
        Err(_e) => {
            agent_debug!("QUIC cert generation failed: {}", _e);
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
    let selected_transport = loop {
        if accept_start.elapsed() > accept_timeout {
            agent_debug!(
                "Transport negotiation timed out waiting for accept, falling back to stdio"
            );
            break TransportKind::Stdio;
        }

        match stdin.read(&mut read_buf) {
            Ok(0) => {
                agent_debug!("SSH channel closed during negotiation");
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed during negotiation",
                ));
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
                    agent_debug!(
                        "Host sent proto::Message without negotiation (legacy host)"
                    );
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
    agent_debug!(
        "Transport negotiation complete, selected: {:?}",
        selected_transport
    );

    // --- Create the transport based on negotiation result ---
    let mut transport: Box<dyn Transport> = match selected_transport {
        TransportKind::Stdio => {
            // Drop resources we won't use
            drop(tcp_listener.take());
            drop(quic_server.take());

            let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
            Box::new(t)
        }
        TransportKind::Tcp => {
            drop(quic_server.take());

            if let Some(listener) = tcp_listener.take() {
                agent_debug!("Waiting for TCP connection from host...");
                listener.set_nonblocking(false).map_err(|e| {
                    io::Error::new(e.kind(), format!("Failed to set TCP listener blocking: {}", e))
                })?;

                // Set a timeout so we don't block forever
                let timeout_result = unsafe {
                    let tv = libc::timeval {
                        tv_sec: TRANSPORT_ACCEPT_TIMEOUT.as_secs() as libc::time_t,
                        tv_usec: 0,
                    };
                    libc::setsockopt(
                        listener.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &tv as *const libc::timeval as *const libc::c_void,
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };
                if timeout_result != 0 {
                    agent_warn!("Failed to set TCP accept timeout, falling back to stdio");
                    let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
                    Box::new(t)
                } else {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            agent_debug!("TCP connection accepted from {}", _addr);
                            stream.set_nonblocking(true).map_err(|e| {
                                io::Error::new(
                                    e.kind(),
                                    format!("Failed to set TCP stream nonblocking: {}", e),
                                )
                            })?;
                            let read_half = stream.try_clone().map_err(|e| {
                                io::Error::new(
                                    e.kind(),
                                    format!("Failed to clone TCP stream: {}", e),
                                )
                            })?;
                            let write_half = stream;
                            Box::new(TcpTransport::new(read_half, write_half))
                        }
                        Err(_e) => {
                            agent_warn!("TCP accept failed: {}, falling back to stdio", _e);
                            let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
                            Box::new(t)
                        }
                    }
                }
            } else {
                agent_warn!("TCP selected but no listener available, falling back to stdio");
                let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
                Box::new(t)
            }
        }
        TransportKind::Quic => {
            drop(tcp_listener.take());

            if let Some((endpoint, socket, _addr)) = quic_server.take() {
                agent_debug!("Waiting for QUIC connection from host...");
                match transport::quic::accept_quic_server(
                    endpoint,
                    socket,
                    TRANSPORT_ACCEPT_TIMEOUT,
                ) {
                    Ok(qt) => {
                        agent_debug!("QUIC transport connected");
                        Box::new(qt)
                    }
                    Err(_e) => {
                        agent_warn!("QUIC accept failed: {}, falling back to stdio", _e);
                        let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
                        Box::new(t)
                    }
                }
            } else {
                agent_warn!("QUIC selected but no server available, falling back to stdio");
                let t = StdioTransport::with_leftover(stdin, stdout, pending_buf);
                Box::new(t)
            }
        }
    };

    agent_debug!(
        "Initialized with {} transport, entering main loop",
        transport.transport_name()
    );
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

        // Drive transport state machine (QUIC timers/retransmits; no-op for others)
        if let Err(_e) = transport.poll() {
            agent_debug!("Transport poll error: {}", _e);
            break;
        }

        // Try to receive messages from the transport
        loop {
            match transport.try_recv() {
                Ok(Some(message)) => {
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
                            if let Err(_e) = transport.send(&pong) {
                                agent_error!("Failed to send Pong: {}", _e);
                            }
                        }
                        Message::Pong(_) => {
                            agent_debug!("Received unexpected Pong message");
                        }
                        Message::ScanRequest(flags) => {
                            handle_scan_request(flags, scanner.as_deref(), &mut *transport);
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

                    // Size-triggered flush inside message decode loop (burst protection)
                    #[cfg(feature = "agent-tracing")]
                    if subscriber::should_flush() {
                        flush_logs_via_transport(&mut *transport);
                    }
                }
                Ok(None) => break,
                Err(_e) => {
                    agent_debug!("Transport recv error: {}", _e);
                    // Transport closed or errored — exit main loop
                    return Ok(());
                }
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
                        if let Err(_e) = transport.send(&message) {
                            agent_error!("Failed to send UDP response: {}", _e);
                        }
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
        flush_logs_via_transport(&mut *transport);

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
    flush_logs_via_transport(&mut *transport);

    drop(transport.close());

    Ok(())
}

/// Drain buffered log events and send them via the transport.
#[cfg(feature = "agent-tracing")]
fn flush_logs_via_transport(transport: &mut dyn Transport) {
    let events = subscriber::drain_log_buffer();
    if events.is_empty() {
        return;
    }
    let msg = Message::LogBatch(events);
    // Best-effort send; if transport is broken we can't log about it
    drop(transport.send(&msg));
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
    transport: &mut dyn Transport,
) {
    agent_debug!("Scan request: tcp={}, udp={}", flags.tcp, flags.udp);

    let scanner = match scanner {
        Some(s) => s,
        None => {
            let resp = Message::ScanResponse(encode_remote_ports(&[]));
            drop(transport.send(&resp));
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
    if let Err(_e) = transport.send(&resp) {
        agent_error!("Failed to send scan response: {}", _e);
    }
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
