//! Bringing up a real tunnel to measure: agent subprocess, latency shim, QUIC
//! connection, a stand-in target service, and a forwarded local port.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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
    /// The host identity the agent was told to expect, and the secret it will
    /// demand on the control stream.
    identity: common::session::Identity,
    session_secret: String,
    /// The certificate the agent published, which the client pins.
    agent_cert: Vec<u8>,
    /// Held open so the agent's stdin is not closed mid-benchmark.
    _stdin: Option<std::process::ChildStdin>,
    /// The stdout reader, retained for the agent's lifetime.
    ///
    /// Dropping it closes the read end of the pipe, and the agent treats a failed
    /// stdout write as fatal — reasonably so, since stdout is how it reports its
    /// existence to the host. Parsing stops once the needed fields have arrived,
    /// which is before the last handshake line, so without holding this the pipe
    /// closes while the agent is still writing and it dies of EPIPE.
    _stdout: BufReader<std::process::ChildStdout>,
    /// Everything the agent wrote to stderr, drained by a background thread.
    ///
    /// Draining rather than discarding: an unread pipe eventually fills and
    /// blocks the agent, and the agent's own error message is the only useful
    /// diagnostic when a benchmark fails because the agent died rather than
    /// because the code under test got slower.
    stderr: Arc<Mutex<String>>,
}

impl Drop for AgentUnderTest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl AgentUnderTest {
    /// Spawn the agent and perform the introduction the SSH channel normally does.
    ///
    /// The agent fails closed without a session config, so the benchmark plays the
    /// host: it mints an identity and session secret, writes them to the agent's
    /// stdin, and pins the certificate the agent publishes on stdout. This is
    /// bootstrap only — the measured data path is unaffected by how the two ends
    /// were introduced.
    pub fn spawn() -> Result<Self> {
        let binary = agent_binary()?;

        let identity =
            common::session::Identity::generate("port-linker-host").map_err(|e| e.to_string())?;
        let session_id = common::session::generate_session_id().map_err(|e| e.to_string())?;
        let session_secret =
            common::session::generate_session_secret().map_err(|e| e.to_string())?;
        let config = common::session::AgentSessionConfig {
            session_id,
            session_secret: session_secret.clone(),
            client_cert_der: identity.cert_der().to_vec(),
        };

        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn agent at {}: {e}", binary.display()))?;

        {
            use std::io::Write;
            let stdin = child
                .stdin
                .as_mut()
                .ok_or("failed to capture agent stdin")?;
            stdin
                .write_all(config.encode().as_bytes())
                .map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture agent stdout")?;

        let stderr_log = Arc::new(Mutex::new(String::new()));
        if let Some(stderr) = child.stderr.take() {
            let sink = Arc::clone(&stderr_log);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr)
                    .lines()
                    .map_while(std::result::Result::ok)
                {
                    if let Ok(mut sink) = sink.lock() {
                        sink.push_str(&line);
                        sink.push('\n');
                    }
                }
            });
        }

        let deadline = std::time::Instant::now() + AGENT_STARTUP_TIMEOUT;
        let mut reader = BufReader::new(stdout);
        let mut port = None;
        let mut agent_cert = None;

        while std::time::Instant::now() < deadline && (port.is_none() || agent_cert.is_none()) {
            let mut line = String::new();
            // A zero-length read is EOF: the agent exited. Report that rather
            // than letting it fall through to the timeout message, which would
            // describe the wrong failure.
            if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                let _ = child.kill();
                return Err(format!(
                    "agent exited during startup; stderr:\n{}",
                    snapshot(&stderr_log)
                )
                .into());
            }
            let line = line.trim();
            if let Some(value) = line.strip_prefix("PORT=") {
                port = Some(value.parse::<u16>().map_err(|e| e.to_string())?);
            } else if let Some(value) = line.strip_prefix("AGENT_CERT=") {
                agent_cert = Some(common::session::from_hex(value).map_err(|e| e.to_string())?);
            }
        }

        let (Some(port), Some(agent_cert)) = (port, agent_cert) else {
            let _ = child.kill();
            return Err(format!(
                "agent did not publish PORT and AGENT_CERT within \
                 {AGENT_STARTUP_TIMEOUT:?}; stderr:\n{}",
                snapshot(&stderr_log)
            )
            .into());
        };

        let stdin = child.stdin.take();

        Ok(Self {
            child,
            port,
            identity,
            session_secret,
            agent_cert,
            _stdin: stdin,
            // Held, not dropped: see the field's documentation.
            _stdout: reader,
            stderr: stderr_log,
        })
    }

    /// The agent's QUIC address.
    pub fn addr(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    /// What the agent has logged to stderr so far, for failure messages.
    pub fn stderr(&self) -> String {
        snapshot(&self.stderr)
    }
}

fn snapshot(log: &Arc<Mutex<String>>) -> String {
    log.lock().map(|text| text.clone()).unwrap_or_default()
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

/// Build the host-side QUIC config for this agent: present our identity, accept
/// only the certificate the agent published.
///
/// This is the same `common::session` mutual-TLS path the shipped host uses, so
/// the benchmark measures the transport production actually runs — a pinned
/// TLS 1.3 connection with client auth — rather than an unauthenticated one.
fn client_config(agent: &AgentUnderTest) -> Result<quinn::ClientConfig> {
    let rustls_config = common::session::client_tls_config(&agent.identity, &agent.agent_cert)
        .map_err(|e| e.to_string())?;

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
        endpoint.set_default_client_config(client_config(&agent)?);

        let connection = Self::handshake(&endpoint, target, rtt, &agent).await?;

        // The agent opens the control stream and sends its handshake, then keeps
        // pushing port events down it. It also opens a unidirectional stream for
        // logs. The real host reads both; if nobody does, the agent's writes
        // eventually block on flow control and stall its select loop — so drain
        // them here too, or the benchmark would be measuring a wedged agent.
        let mut drains = Vec::with_capacity(2);

        let (mut control_send, mut control_recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("failed to accept control stream: {e}"))?;
        let _handshake = tunnel::recv_framed(&mut control_recv)
            .await
            .map_err(|e| format!("failed to read agent handshake: {e}"))?;

        // mTLS has already proved who we are; the agent additionally requires the
        // session secret it was given over stdin, which binds this connection to
        // this bootstrap. Without it the agent tears the session down.
        tunnel::send_framed(
            &mut control_send,
            &protocol::ControlMsg::SessionAuth {
                session_secret: agent.session_secret.clone(),
            },
        )
        .await
        .map_err(|e| format!("failed to authenticate the session: {e}"))?;

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
        agent: &AgentUnderTest,
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

        // The agent's own log is the first thing to look at: the most likely
        // reason datagrams are not flowing is that the agent is no longer
        // running, and it says why here.
        Err(format!(
            "QUIC {last_error} after {HANDSHAKE_ATTEMPTS} attempts (imposed RTT \
             {rtt:?}). Either the agent is gone or the latency shim is not \
             passing datagrams.\nagent stderr:\n{}",
            agent.stderr()
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
