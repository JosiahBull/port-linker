//! QUIC transport: bypasses SSH for the data path using quinn-proto.
//!
//! After the agent deploys via SSH and negotiates QUIC transport, the agent
//! binds a UDP socket and the host connects directly. The SSH exec channel
//! is kept alive only for stderr/lifecycle monitoring.
//!
//! Trust model: the agent's self-signed certificate fingerprint (SHA-256) is
//! delivered over the authenticated SSH channel (TOFU).

use crate::error::{Result, TransportError};
use crate::Transport;
use proto::Message;
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Endpoint, EndpointEvent, Event, StreamId,
};
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;
use tracing::{debug, trace, warn};

/// Re-export the QUIC endpoint type so consumers don't need a direct quinn-proto dependency.
pub type QuicEndpoint = Endpoint;

/// QUIC transport over a single bidirectional stream.
pub struct QuicTransport {
    endpoint: Endpoint,
    conn_handle: ConnectionHandle,
    connection: Connection,
    socket: UdpSocket,
    #[allow(dead_code, reason = "needed for future diagnostics")]
    remote_addr: SocketAddr,
    stream_id: Option<StreamId>,
    /// Reassembled stream data buffer for decoding messages.
    recv_buf: Vec<u8>,
    /// Temporary buffer for reading UDP datagrams.
    udp_recv_buf: Vec<u8>,
    /// Reusable buffer for poll_transmit output.
    transmit_buf: Vec<u8>,
    /// Pending endpoint events to deliver.
    endpoint_events: VecDeque<EndpointEvent>,
    closed: bool,
}

impl QuicTransport {
    /// Create a QUIC transport from a connected endpoint.
    ///
    /// The caller must have already completed the QUIC handshake and opened
    /// a bidirectional stream.
    pub fn new(
        endpoint: Endpoint,
        conn_handle: ConnectionHandle,
        connection: Connection,
        socket: UdpSocket,
        remote_addr: SocketAddr,
        stream_id: Option<StreamId>,
    ) -> Self {
        Self {
            endpoint,
            conn_handle,
            connection,
            socket,
            remote_addr,
            stream_id,
            recv_buf: Vec::new(),
            udp_recv_buf: vec![0_u8; 65536],
            transmit_buf: Vec::new(),
            endpoint_events: VecDeque::new(),
            closed: false,
        }
    }

    /// Drive QUIC transmits: send any outgoing datagrams.
    fn drive_transmits(&mut self) -> Result<()> {
        loop {
            self.transmit_buf.clear();
            match self
                .connection
                .poll_transmit(Instant::now(), 1500, &mut self.transmit_buf)
            {
                Some(transmit) => {
                    send_transmit_buf(&self.socket, &transmit.destination, &self.transmit_buf, transmit.size)?;
                }
                None => break,
            }
        }
        Ok(())
    }

    /// Receive UDP datagrams and feed them to the QUIC endpoint/connection.
    fn receive_datagrams(&mut self) -> Result<()> {
        let now = Instant::now();
        let mut response_buf = Vec::new();
        loop {
            match self.socket.recv_from(&mut self.udp_recv_buf) {
                Ok((n, from)) => {
                    let data =
                        bytes::BytesMut::from(self.udp_recv_buf.get(..n).unwrap_or(&[]));
                    response_buf.clear();
                    if let Some(event) = self.endpoint.handle(
                        now,
                        from,
                        None,
                        None,
                        data,
                        &mut response_buf,
                    ) {
                        match event {
                            DatagramEvent::ConnectionEvent(handle, event) => {
                                if handle == self.conn_handle {
                                    self.connection.handle_event(event);
                                }
                            }
                            DatagramEvent::NewConnection(_incoming) => {
                                // Unexpected incoming connection, ignore
                                debug!("Ignoring unexpected incoming QUIC connection");
                            }
                            DatagramEvent::Response(transmit) => {
                                send_transmit_buf(&self.socket, &transmit.destination, &response_buf, transmit.size).ok();
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => break,
                Err(e) => {
                    warn!("QUIC UDP recv error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Handle QUIC connection timeouts.
    fn handle_timeouts(&mut self) {
        let now = Instant::now();
        self.connection.handle_timeout(now);
    }

    /// Process connection events (stream data, connection state changes).
    fn process_events(&mut self) -> Result<()> {
        while let Some(event) = self.connection.poll() {
            match event {
                Event::Stream(quinn_proto::StreamEvent::Readable { id }) => {
                    // Read data from the stream into our buffer
                    self.drain_recv_stream(id)?;
                }
                Event::Stream(quinn_proto::StreamEvent::Writable { .. }) => {
                    // Writing capacity available, nothing to do here
                }
                Event::Stream(quinn_proto::StreamEvent::Finished { .. }) => {
                    debug!("QUIC stream finished");
                }
                Event::Stream(quinn_proto::StreamEvent::Stopped { .. }) => {
                    debug!("QUIC stream stopped");
                }
                Event::Stream(quinn_proto::StreamEvent::Available { .. }) => {
                    // New streams available (for server side)
                    if self.stream_id.is_none() {
                        if let Some(id) = self.connection.streams().accept(quinn_proto::Dir::Bi) {
                            debug!("Accepted new bidirectional stream: {:?}", id);
                            self.stream_id = Some(id);
                        }
                    }
                }
                Event::Stream(quinn_proto::StreamEvent::Opened {
                    dir: quinn_proto::Dir::Bi,
                }) => {
                    // Bidirectional stream opened
                    trace!("Bidirectional stream opened");
                }
                Event::Stream(_) => {}
                Event::DatagramReceived => {}
                Event::Connected => {
                    debug!("QUIC connection established");
                }
                Event::ConnectionLost { reason } => {
                    debug!("QUIC connection lost: {}", reason);
                    self.closed = true;
                    return Err(TransportError::Closed);
                }
                Event::HandshakeDataReady => {}
                Event::DatagramsUnblocked => {}
            }
        }

        // Deliver endpoint events
        while let Some(event) = self.connection.poll_endpoint_events() {
            self.endpoint_events.push_back(event);
        }

        // Feed endpoint events back
        while let Some(event) = self.endpoint_events.pop_front() {
            if let Some(event) = self.endpoint.handle_event(self.conn_handle, event) {
                self.connection.handle_event(event);
            }
        }

        Ok(())
    }

    /// Drain readable data from a QUIC stream into our message decode buffer.
    fn drain_recv_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let mut recv_stream = self.connection.recv_stream(stream_id);
        let mut chunks = match recv_stream.read(true) {
            Ok(chunks) => chunks,
            Err(_) => return Ok(()),
        };

        loop {
            match chunks.next(65536) {
                Ok(Some(chunk)) => {
                    self.recv_buf.extend_from_slice(&chunk.bytes);
                }
                Ok(None) => break,
                Err(quinn_proto::ReadError::Blocked) => break,
                Err(quinn_proto::ReadError::Reset(_)) => {
                    debug!("QUIC stream reset");
                    self.closed = true;
                    #[allow(
                        clippy::let_underscore_must_use,
                        dropping_copy_types,
                        reason = "finalize result is intentionally discarded during cleanup"
                    )]
                    let _ = chunks.finalize();
                    return Err(TransportError::Closed);
                }
            }
        }

        #[allow(
            clippy::let_underscore_must_use,
            dropping_copy_types,
            reason = "finalize result is intentionally discarded during cleanup"
        )]
        let _ = chunks.finalize();
        Ok(())
    }
}

impl Transport for QuicTransport {
    fn send(&mut self, msg: &Message) -> Result<()> {
        if self.closed {
            return Err(TransportError::Closed);
        }

        let stream_id = self
            .stream_id
            .ok_or_else(|| TransportError::Negotiation("No QUIC stream available".to_string()))?;

        let encoded = msg.encode();
        self.connection
            .send_stream(stream_id)
            .write(&encoded)
            .map_err(|e| {
                TransportError::Negotiation(format!("QUIC stream write failed: {}", e))
            })?;

        // Drive transmits to actually send the data
        self.drive_transmits()?;

        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<Message>> {
        if self.closed {
            return Err(TransportError::Closed);
        }

        // Check if we already have a complete message
        if let Some((message, consumed)) = Message::decode(&self.recv_buf) {
            self.recv_buf.drain(..consumed);
            return Ok(Some(message));
        }

        Ok(None)
    }

    fn poll(&mut self) -> Result<()> {
        if self.closed {
            return Err(TransportError::Closed);
        }

        // Receive incoming UDP datagrams
        self.receive_datagrams()?;

        // Handle QUIC timeouts
        self.handle_timeouts();

        // Process connection events (may read stream data into recv_buf)
        self.process_events()?;

        // Drive outgoing transmits
        self.drive_transmits()?;

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.connection
                .close(Instant::now(), 0_u32.into(), bytes::Bytes::from_static(b"shutdown"));
            // Final transmit drain
            drop(self.drive_transmits());
            self.closed = true;
        }
        Ok(())
    }

    fn transport_name(&self) -> &'static str {
        "quic"
    }
}

/// Send data from a transmit buffer via a UDP socket.
///
/// `size` is the number of bytes from `buf` to send (from `Transmit.size`).
fn send_transmit_buf(
    socket: &UdpSocket,
    dest: &SocketAddr,
    buf: &[u8],
    size: usize,
) -> Result<()> {
    let data = buf.get(..size).unwrap_or(buf);
    match socket.send_to(data, dest) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(()),
        Err(e) => Err(TransportError::Io(e)),
    }
}

/// Helper to connect as a QUIC client to a server.
///
/// - `local_socket`: non-blocking UDP socket bound locally
/// - `remote_addr`: the agent's QUIC address (host:port)
/// - `client_config`: quinn-proto client config with fingerprint verification
/// - `timeout`: maximum time to wait for the connection
///
/// Returns a fully-connected `QuicTransport` with a bidirectional stream.
pub fn connect_quic_client(
    socket: UdpSocket,
    remote_addr: SocketAddr,
    client_config: quinn_proto::ClientConfig,
    timeout: std::time::Duration,
) -> Result<QuicTransport> {
    let endpoint_config = quinn_proto::EndpointConfig::default();
    let mut endpoint = Endpoint::new(
        std::sync::Arc::new(endpoint_config),
        None,
        true,
        None,
    );

    let (conn_handle, connection) = endpoint
        .connect(
            Instant::now(),
            client_config,
            remote_addr,
            "port-linker-agent",
        )
        .map_err(|e| TransportError::Negotiation(format!("QUIC connect failed: {}", e)))?;

    let mut transport = QuicTransport::new(
        endpoint,
        conn_handle,
        connection,
        socket,
        remote_addr,
        None,
    );

    // Drive the connection until it's established or timeout
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    let mut connected = false;
    while Instant::now() < deadline && !connected {
        transport.drive_transmits()?;
        transport.receive_datagrams()?;
        transport.handle_timeouts();

        while let Some(event) = transport.connection.poll() {
            match event {
                Event::Connected => {
                    debug!("QUIC client connected");
                    connected = true;
                }
                Event::ConnectionLost { reason } => {
                    return Err(TransportError::Negotiation(format!(
                        "QUIC connection lost during handshake: {}",
                        reason
                    )));
                }
                Event::HandshakeDataReady
                | Event::Stream(_)
                | Event::DatagramReceived
                | Event::DatagramsUnblocked => {}
            }
        }

        // Deliver endpoint events
        while let Some(event) = transport.connection.poll_endpoint_events() {
            if let Some(event) = transport.endpoint.handle_event(conn_handle, event) {
                transport.connection.handle_event(event);
            }
        }

        if !connected {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    if !connected {
        return Err(TransportError::Timeout);
    }

    // Open a bidirectional stream
    let stream_id = transport
        .connection
        .streams()
        .open(quinn_proto::Dir::Bi)
        .ok_or_else(|| {
            TransportError::Negotiation("Failed to open bidirectional QUIC stream".to_string())
        })?;

    transport.stream_id = Some(stream_id);
    transport.drive_transmits()?;

    Ok(transport)
}

/// Helper to set up a QUIC server endpoint (for the agent side).
///
/// Returns `(endpoint, socket, local_addr)`.
pub fn setup_quic_server(
    server_config: quinn_proto::ServerConfig,
) -> Result<(Endpoint, UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(TransportError::Io)?;
    socket
        .set_nonblocking(true)
        .map_err(TransportError::Io)?;

    let local_addr = socket.local_addr().map_err(TransportError::Io)?;

    let endpoint_config = quinn_proto::EndpointConfig::default();
    let endpoint = Endpoint::new(
        std::sync::Arc::new(endpoint_config),
        Some(std::sync::Arc::new(server_config)),
        true,
        None,
    );

    debug!("QUIC server listening on {}", local_addr);

    Ok((endpoint, socket, local_addr))
}

/// Accept a QUIC connection on the server side (blocking with timeout).
///
/// Returns a `QuicTransport` with an accepted bidirectional stream.
pub fn accept_quic_server(
    mut endpoint: Endpoint,
    socket: UdpSocket,
    timeout: std::time::Duration,
) -> Result<QuicTransport> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    let mut udp_buf = vec![0_u8; 65536];
    let mut transmit_buf = Vec::new();
    let mut response_buf = Vec::new();
    let mut conn_handle: Option<ConnectionHandle> = None;
    let mut connection: Option<Connection> = None;
    let mut remote_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut connected = false;

    while Instant::now() < deadline {
        // Receive UDP datagrams
        match socket.recv_from(&mut udp_buf) {
            Ok((n, from)) => {
                remote_addr = from;
                let data = bytes::BytesMut::from(udp_buf.get(..n).unwrap_or(&[]));
                let now = Instant::now();

                response_buf.clear();
                if let Some(event) =
                    endpoint.handle(now, from, None, None, data, &mut response_buf)
                {
                    match event {
                        DatagramEvent::NewConnection(incoming) => {
                            transmit_buf.clear();
                            match endpoint.accept(incoming, Instant::now(), &mut transmit_buf, None)
                            {
                                Ok((handle, conn)) => {
                                    debug!(
                                        "Accepted incoming QUIC connection from {}",
                                        from
                                    );
                                    conn_handle = Some(handle);
                                    connection = Some(conn);
                                    // Send any initial transmits from accept
                                    if !transmit_buf.is_empty() {
                                        drop(socket.send_to(&transmit_buf, from));
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to accept QUIC connection: {:?}", e);
                                }
                            }
                        }
                        DatagramEvent::ConnectionEvent(handle, event) => {
                            if let Some(ref mut conn) = connection {
                                if Some(handle) == conn_handle {
                                    conn.handle_event(event);
                                }
                            }
                        }
                        DatagramEvent::Response(transmit) => {
                            drop(send_transmit_buf(
                                &socket,
                                &transmit.destination,
                                &response_buf,
                                transmit.size,
                            ));
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
            Err(e) => {
                warn!("QUIC server recv error: {}", e);
            }
        }

        // Process connection events
        if let (Some(ref mut conn), Some(handle)) = (&mut connection, conn_handle) {
            // Handle timeouts
            conn.handle_timeout(Instant::now());

            // Drive transmits
            loop {
                transmit_buf.clear();
                match conn.poll_transmit(Instant::now(), 1500, &mut transmit_buf) {
                    Some(transmit) => {
                        drop(send_transmit_buf(
                            &socket,
                            &transmit.destination,
                            &transmit_buf,
                            transmit.size,
                        ));
                    }
                    None => break,
                }
            }

            // Check for events
            while let Some(event) = conn.poll() {
                match event {
                    Event::Connected => {
                        debug!("QUIC server connection established");
                        connected = true;
                    }
                    Event::Stream(quinn_proto::StreamEvent::Available {
                        dir: quinn_proto::Dir::Bi,
                    }) => {
                        // Stream available
                    }
                    Event::ConnectionLost { reason } => {
                        return Err(TransportError::Negotiation(format!(
                            "QUIC server connection lost: {}",
                            reason
                        )));
                    }
                    Event::HandshakeDataReady
                    | Event::Stream(_)
                    | Event::DatagramReceived
                    | Event::DatagramsUnblocked => {}
                }
            }

            // Deliver endpoint events
            while let Some(ep_event) = conn.poll_endpoint_events() {
                if let Some(conn_event) = endpoint.handle_event(handle, ep_event) {
                    conn.handle_event(conn_event);
                }
            }

            if connected {
                break;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let handle = conn_handle.ok_or(TransportError::Timeout)?;
    let mut conn = connection.ok_or(TransportError::Timeout)?;

    if !connected {
        return Err(TransportError::Timeout);
    }

    // Accept a bidirectional stream from the client
    let stream_deadline = Instant::now()
        .checked_add(std::time::Duration::from_secs(2))
        .unwrap_or_else(Instant::now);

    let mut stream_id = None;
    while Instant::now() < stream_deadline && stream_id.is_none() {
        // Receive more data
        if let Ok((n, from)) = socket.recv_from(&mut udp_buf) {
            let data = bytes::BytesMut::from(udp_buf.get(..n).unwrap_or(&[]));
            response_buf.clear();
            if let Some(event) =
                endpoint.handle(Instant::now(), from, None, None, data, &mut response_buf)
            {
                match event {
                    DatagramEvent::ConnectionEvent(h, event) if h == handle => {
                        conn.handle_event(event);
                    }
                    DatagramEvent::Response(transmit) => {
                        send_transmit_buf(
                            &socket,
                            &transmit.destination,
                            &response_buf,
                            transmit.size,
                        ).ok();
                    }
                    DatagramEvent::ConnectionEvent(..)
                    | DatagramEvent::NewConnection(_) => {}
                }
            }
        }

        conn.handle_timeout(Instant::now());

        while let Some(event) = conn.poll() {
            if let Event::Stream(quinn_proto::StreamEvent::Available {
                dir: quinn_proto::Dir::Bi,
            }) = event
            {
                if let Some(id) = conn.streams().accept(quinn_proto::Dir::Bi) {
                    stream_id = Some(id);
                }
            }
        }

        // Deliver endpoint events
        while let Some(ep_event) = conn.poll_endpoint_events() {
            if let Some(conn_event) = endpoint.handle_event(handle, ep_event) {
                conn.handle_event(conn_event);
            }
        }

        // Drive transmits
        loop {
            transmit_buf.clear();
            match conn.poll_transmit(Instant::now(), 1500, &mut transmit_buf) {
                Some(transmit) => {
                    drop(send_transmit_buf(
                        &socket,
                        &transmit.destination,
                        &transmit_buf,
                        transmit.size,
                    ));
                }
                None => break,
            }
        }

        if stream_id.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    let stream_id = stream_id.ok_or_else(|| {
        TransportError::Negotiation("Client did not open a bidirectional stream".to_string())
    })?;

    Ok(QuicTransport::new(
        endpoint,
        handle,
        conn,
        socket,
        remote_addr,
        Some(stream_id),
    ))
}
