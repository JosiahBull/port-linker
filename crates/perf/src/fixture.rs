//! Bringing up a real tunnel to measure: agent subprocess, latency shim, QUIC
//! connection, a stand-in target service, and a forwarded local port.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, Endpoint};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tunnel::{StreamSetup, forward_tcp_connection_with};

use crate::Result;
use crate::shim::LatencyShim;

/// How long to wait for the agent to print its handshake banner.
const AGENT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the QUIC handshake through the latency shim. Generous
/// relative to any RTT a benchmark imposes, so exceeding it means datagrams are
/// not flowing at all rather than merely flowing slowly.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Handshake attempts before giving up. See [`Tunnel::handshake`].
const HANDSHAKE_ATTEMPTS: u32 = 2;

// ---------------------------------------------------------------------------
// Agent subprocess
// ---------------------------------------------------------------------------

/// The real agent binary, running as a subprocess.
///
/// The benchmarks drive the shipped agent rather than an in-process stand-in, so
/// that what is measured includes its actual scheduling, its loopback connect,
/// and its select loop.
pub struct AgentUnderTest {
    child: Child,
    port: u16,
}

impl Drop for AgentUnderTest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl AgentUnderTest {
    /// Spawn the agent and read the UDP port it is listening on.
    pub fn spawn() -> Result<Self> {
        let binary = agent_binary()?;

        let mut child = Command::new(&binary)
            .stdout(Stdio::piped())
            // The agent forwards its logs over QUIC once connected, but writes
            // early ones here. Discard them: nothing reads this pipe, and a full
            // pipe buffer would block the agent mid-benchmark.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn agent at {}: {e}", binary.display()))?;

        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture agent stdout")?;

        let deadline = std::time::Instant::now() + AGENT_STARTUP_TIMEOUT;
        let mut reader = BufReader::new(stdout);
        let mut port = None;

        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                break;
            }
            if let Some(value) = line.trim().strip_prefix("PORT=") {
                port = Some(value.parse::<u16>().map_err(|e| e.to_string())?);
                break;
            }
        }

        let port = port.ok_or("agent did not report a PORT before the startup timeout")?;
        Ok(Self { child, port })
    }

    /// The agent's QUIC address.
    pub fn addr(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }
}

/// Locate the agent binary, building it if this is a fresh checkout.
fn agent_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_port-linker-agent") {
        return Ok(PathBuf::from(path));
    }

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("cannot locate workspace root from CARGO_MANIFEST_DIR")?
        .to_path_buf();

    let path = workspace_root.join("target/debug/port-linker-agent");
    if path.exists() {
        return Ok(path);
    }

    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["build", "-p", "agent"])
        .current_dir(&workspace_root)
        .status()
        .map_err(|e| format!("failed to invoke cargo build -p agent: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build -p agent failed with {status}").into());
    }
    if !path.exists() {
        return Err(format!("agent binary still missing at {}", path.display()).into());
    }
    Ok(path)
}

// ---------------------------------------------------------------------------
// QUIC client
// ---------------------------------------------------------------------------

/// Accepts the agent's self-signed certificate.
///
/// The shipped host pins the certificate it learned over SSH; there is no SSH
/// bootstrap here, so verification is skipped. This affects only how the
/// benchmark authenticates, not the data path it measures.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

fn client_config() -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());

    let rustls_config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();

    let quic = QuicClientConfig::try_from(rustls_config).map_err(|e| e.to_string())?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));

    // Match the shipped host's transport settings so the benchmark measures the
    // same stream-credit and keep-alive behaviour production has.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(1_048_576));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    // Deliberately not raising max_idle_timeout above the shipped default: the
    // point is to measure the transport production uses. Startup robustness is
    // handled by the bounded, retried handshake instead.
    config.transport_config(Arc::new(transport));

    Ok(config)
}

// ---------------------------------------------------------------------------
// Target service
// ---------------------------------------------------------------------------

/// A TCP echo server on loopback, standing in for a service on the target.
pub struct EchoService {
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for EchoService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EchoService {
    pub async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        Ok(Self { port, task })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// Forwarded local port
// ---------------------------------------------------------------------------

/// A local listener that forwards each accepted connection over the tunnel.
///
/// This mirrors `BindingManager::bind_tcp` in the CLI: accept, disable Nagle,
/// spawn a forwarding task. It calls the same [`forward_tcp_connection_with`]
/// the shipped host does, so the measurement covers the real host-side code.
pub struct ForwardedPort {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for ForwardedPort {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ForwardedPort {
    pub async fn spawn(
        connection: Connection,
        remote_port: u16,
        setup: StreamSetup,
    ) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                tokio::spawn(forward_tcp_connection_with(
                    connection.clone(),
                    socket,
                    remote_port,
                    setup,
                ));
            }
        });
        Ok(Self { addr, task })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

// ---------------------------------------------------------------------------
// Whole tunnel
// ---------------------------------------------------------------------------

/// A live tunnel: agent subprocess, optional latency shim, QUIC connection, and
/// the background drains the real host performs.
pub struct Tunnel {
    connection: Connection,
    rtt: Duration,
    _endpoint: Endpoint,
    _agent: AgentUnderTest,
    _shim: Option<LatencyShim>,
    /// Held for the lifetime of the tunnel. Dropping a `SendStream` resets the
    /// stream, and the agent treats a dead control stream as end of session and
    /// exits — so this must outlive every measurement.
    _control_send: quinn::SendStream,
    drains: Vec<JoinHandle<()>>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        for drain in &self.drains {
            drain.abort();
        }
    }
}

impl Tunnel {
    /// Bring up a tunnel whose host-to-agent path has the given round-trip time.
    /// A zero `rtt` skips the shim entirely and connects straight to the agent.
    pub async fn establish(rtt: Duration) -> Result<Self> {
        let agent = AgentUnderTest::spawn()?;

        let (target, shim) = if rtt.is_zero() {
            (agent.addr(), None)
        } else {
            let shim = LatencyShim::spawn(agent.addr(), rtt).await?;
            (shim.addr(), Some(shim))
        };

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())?;
        endpoint.set_default_client_config(client_config()?);

        let connection = Self::handshake(&endpoint, target, rtt).await?;

        // The agent opens the control stream and sends its handshake, then keeps
        // pushing port events down it. It also opens a unidirectional stream for
        // logs. The real host reads both; if nobody does, the agent's writes
        // eventually block on flow control and stall its select loop — so drain
        // them here too, or the benchmark would be measuring a wedged agent.
        let mut drains = Vec::with_capacity(2);

        let (control_send, mut control_recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("failed to accept control stream: {e}"))?;
        let _handshake = tunnel::recv_framed(&mut control_recv)
            .await
            .map_err(|e| format!("failed to read agent handshake: {e}"))?;
        drains.push(tokio::spawn(async move {
            while tunnel::recv_framed(&mut control_recv).await.is_ok() {}
        }));

        drains.push(tokio::spawn({
            let connection = connection.clone();
            async move {
                while let Ok(mut stream) = connection.accept_uni().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        while let Ok(Some(_)) = stream.read(&mut buf).await {}
                    });
                }
            }
        }));

        Ok(Self {
            connection,
            rtt,
            _endpoint: endpoint,
            _agent: agent,
            _shim: shim,
            _control_send: control_send,
            drains,
        })
    }

    /// Complete the QUIC handshake, retrying once.
    ///
    /// A benchmark's startup is not what it measures, and a stalled handshake on
    /// an oversubscribed machine is a setup failure rather than a result: if the
    /// scheduler cannot run the shim's timers promptly, an early packet loss
    /// pushes quinn into exponential retransmit backoff and the handshake can
    /// exceed any fixed bound. One retry removes that flake without touching a
    /// single measurement or assertion.
    async fn handshake(
        endpoint: &Endpoint,
        target: SocketAddr,
        rtt: Duration,
    ) -> Result<Connection> {
        let mut last_error = String::new();

        for attempt in 1..=HANDSHAKE_ATTEMPTS {
            let connecting = endpoint
                .connect(target, "localhost")
                .map_err(|e| e.to_string())?;

            match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(e)) => last_error = format!("handshake failed: {e}"),
                Err(_) => {
                    last_error = format!("handshake did not complete within {HANDSHAKE_TIMEOUT:?}");
                }
            }

            if attempt < HANDSHAKE_ATTEMPTS {
                tracing::warn!(attempt, %last_error, "retrying QUIC handshake");
            }
        }

        Err(format!(
            "QUIC {last_error} after {HANDSHAKE_ATTEMPTS} attempts (imposed RTT \
             {rtt:?}). The agent or the latency shim is not passing datagrams — \
             check that the machine is not so oversubscribed that the shim's \
             timers cannot run."
        )
        .into())
    }

    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    pub fn rtt(&self) -> Duration {
        self.rtt
    }
}
