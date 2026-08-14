//! In-process harness for the TCP forwarding data plane.
//!
//! Both halves run here: a real QUIC connection between two endpoints in this
//! process, with the agent side answering streams via [`serve_tcp_stream`] — the
//! same function the agent binary calls. That makes these tests hermetic and
//! fast (no subprocess, no SSH, no latency), and lets a test substitute a
//! deliberately misbehaving agent when the point is to check how the host copes.
//!
//! For latency measurement — where the real agent process and a real round trip
//! matter — see `crates/perf` instead.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, Endpoint};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tunnel::serve_tcp_stream;

/// Upper bound on any single test. A forwarding bug is far more likely to show
/// up as a hang than as a wrong byte, so every test is bounded and a hang is
/// reported as a failure with a name attached.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Run `fut` under [`TEST_TIMEOUT`], panicking with `label` if it does not
/// finish.
pub async fn within<F: Future>(label: &str, fut: F) -> F::Output {
    match tokio::time::timeout(TEST_TIMEOUT, fut).await {
        Ok(value) => value,
        Err(_) => panic!("{label} did not finish within {TEST_TIMEOUT:?}"),
    }
}

/// Await a spawned forwarder under [`TEST_TIMEOUT`].
///
/// Always go through this rather than awaiting the handle directly: a forwarding
/// bug that fails to retire the task would otherwise hang the whole suite with no
/// indication of which test was responsible.
pub async fn finish(label: &str, forward: JoinHandle<()>) {
    within(label, async {
        forward.await.expect("forwarder task panicked");
    })
    .await;
}

pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What the agent side does with an incoming forwarding stream.
pub type StreamHandler =
    Arc<dyn Fn(quinn::SendStream, quinn::RecvStream) -> BoxFuture + Send + Sync>;

// ---------------------------------------------------------------------------
// QUIC plumbing
// ---------------------------------------------------------------------------

/// Accepts the harness's own generated certificate.
///
/// Signature verification is still delegated to the crypto provider, so the
/// handshake exercises real TLS; only the identity check is skipped, because
/// there is no SSH bootstrap here to introduce the two ends.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    // Mirror the shipped settings: the stream-credit limit in particular is what
    // makes `open_bi` a local operation rather than a round trip.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(1_048_576));
    Arc::new(transport)
}

/// A host-to-agent QUIC connection with both ends in this process.
///
/// There is no control stream here: these tests exercise the forwarding streams
/// only, and the agent side answers whatever the host opens.
pub struct Loopback {
    host: Connection,
    _client: Endpoint,
    _server: Endpoint,
    accept_loop: JoinHandle<()>,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl Loopback {
    /// A connection whose agent side serves streams exactly as the agent binary
    /// does.
    pub async fn with_agent() -> Self {
        Self::with_handler(Arc::new(|send, recv| {
            Box::pin(serve_tcp_stream(send, recv))
        }))
        .await
    }

    /// A connection whose agent side runs `handler` for each incoming stream.
    ///
    /// Used to stand in a misbehaving agent: one that never replies, sends an
    /// unexpected status byte, or resets the stream.
    pub async fn with_handler(handler: StreamHandler) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed certificate");
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .expect("serialize private key");

        let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der)
            .expect("build QUIC server config");
        server_config.transport_config(transport_config());

        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind QUIC server endpoint");
        let server_addr = server.local_addr().expect("server addr");

        let rustls_client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(rustls_client).expect("QUIC client config"),
        ));
        client_config.transport_config(transport_config());

        let mut client =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind QUIC client endpoint");
        client.set_default_client_config(client_config);

        // Accept on the agent side concurrently with the client's connect.
        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.expect("agent accepted a connection");
            let connection = incoming.await.expect("agent completed handshake");
            (server, connection)
        });

        let host = client
            .connect(server_addr, "localhost")
            .expect("initiate QUIC connection")
            .await
            .expect("complete QUIC handshake");
        let (server, agent) = accept.await.expect("agent accept task");

        let accept_loop = tokio::spawn(async move {
            while let Ok((send, recv)) = agent.accept_bi().await {
                let handler = handler.clone();
                tokio::spawn(async move { handler(send, recv).await });
            }
        });

        Self {
            host,
            _client: client,
            _server: server,
            accept_loop,
        }
    }

    /// The host's view of the tunnel.
    pub fn host(&self) -> Connection {
        self.host.clone()
    }

    /// Close the connection the way a lost session would.
    pub fn close(&self) {
        self.host.close(0u32.into(), b"test over");
    }
}

// ---------------------------------------------------------------------------
// Local socket pair
// ---------------------------------------------------------------------------

/// A connected pair of loopback TCP sockets.
///
/// `client` is what an application on the host holds; `accepted` is what the
/// forwarder is handed, standing in for `BindingManager`'s accepted connection.
pub async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind pair");
    let addr = listener.local_addr().expect("pair addr");
    let connect = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (accepted, _) = listener.accept().await.expect("accept pair");
    let client = connect.await.expect("connect task").expect("connect pair");
    let _ = client.set_nodelay(true);
    let _ = accepted.set_nodelay(true);
    (client, accepted)
}

// ---------------------------------------------------------------------------
// Stand-in target services
// ---------------------------------------------------------------------------

/// A service on the target that the agent will connect to.
pub struct TargetService {
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for TargetService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TargetService {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Echoes everything back.
    pub async fn echo() -> Self {
        Self::spawn(|mut socket| async move {
            let (mut read, mut write) = socket.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        })
        .await
    }

    /// Writes `banner` the moment a connection arrives, then echoes.
    ///
    /// Stands in for the protocols that speak first — MySQL, SMTP, SSH.
    pub async fn banner_then_echo(banner: &'static [u8]) -> Self {
        Self::spawn(move |mut socket| async move {
            if socket.write_all(banner).await.is_err() {
                return;
            }
            let (mut read, mut write) = socket.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        })
        .await
    }

    /// Accepts and closes immediately, without reading or writing.
    pub async fn immediate_close() -> Self {
        Self::spawn(|socket| async move {
            drop(socket);
        })
        .await
    }

    /// Reads everything and never replies.
    pub async fn sink() -> Self {
        Self::spawn(|mut socket| async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        })
        .await
    }

    /// Echoes the request, then closes its side of the connection.
    pub async fn echo_once_then_close(len: usize) -> Self {
        Self::spawn(move |mut socket| async move {
            let mut buf = vec![0u8; len];
            if socket.read_exact(&mut buf).await.is_err() {
                return;
            }
            let _ = socket.write_all(&buf).await;
            let _ = socket.shutdown().await;
        })
        .await
    }

    async fn spawn<F, Fut>(handle: F) -> Self
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let port = listener.local_addr().expect("target addr").port();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                tokio::spawn(handle(socket));
            }
        });
        Self { port, task }
    }
}

/// A port with nothing listening on it.
///
/// Binds to get a port the OS considers free, then releases it. A different
/// process could claim it in between, which would make a test that expects
/// "connection refused" fail rather than pass silently — the safe direction.
pub async fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let port = listener.local_addr().expect("probe addr").port();
    drop(listener);
    port
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Read exactly `len` bytes, failing the test on early EOF.
pub async fn read_exact(socket: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    socket
        .read_exact(&mut buf)
        .await
        .expect("read_exact from local socket");
    buf
}

/// Drain to EOF, asserting the peer closed cleanly rather than hung.
///
/// Use this where a clean FIN is the contract. On a failure path, prefer
/// [`read_until_closed`]: a reset is a legitimate outcome there.
pub async fn read_to_end(socket: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    socket
        .read_to_end(&mut buf)
        .await
        .expect("read to EOF from local socket");
    buf
}

/// Read until the connection ends, however it ends, and return what arrived.
///
/// On a failure path the point is that the client stops waiting and receives no
/// application data — not which of the two ways TCP has of saying so. Closing a
/// socket that still holds unread data in its receive buffer produces an RST
/// rather than a FIN, so a client that had already sent a request sees
/// `ECONNRESET` where one that sent nothing sees EOF. That varies by platform and
/// by timing (macOS resets here where Linux gave EOF), and both mean the same
/// thing to the caller, so both are accepted. A hang would still fail the test,
/// via the enclosing [`within`].
pub async fn read_until_closed(socket: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    match socket.read_to_end(&mut buf).await {
        Ok(_) => buf,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => buf,
        Err(e) => panic!("unexpected error reading from local socket: {e}"),
    }
}

/// A deterministic byte pattern that makes truncation, duplication, and
/// reordering all visible in a failure.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The forwarder's local address for a spawned forward task.
pub fn addr_of(socket: &TcpStream) -> SocketAddr {
    socket.local_addr().expect("local addr")
}
