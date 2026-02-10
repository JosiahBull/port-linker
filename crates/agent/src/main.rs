use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use agent::diff::PortEvent;
use agent::log_forward;
use agent::scan_loop::run_scan_loop;
use agent::scanner::DefaultScanner;
use common::{Error, Result};
use protocol::{ControlMsg, MuxFrame, PROTOCOL_VERSION};

/// Maximum allowed frame size: 1 MB.
const MAX_FRAME_SIZE: u32 = 1_048_576;

// ---------------------------------------------------------------------------
// Minimal stderr tracing layer.
//
// This replaces `tracing_subscriber::fmt::layer()` to avoid pulling in the
// entire `fmt` module (~20 KiB), `nu_ansi_term` (~1.7 KiB), and ANSI color
// support. The agent only needs stderr output as a pre-handshake diagnostic
// fallback; the real log path is the `ForwardingLayer` -> mux channel.
// ---------------------------------------------------------------------------

/// A zero-dependency tracing layer that writes unformatted events to stderr.
struct StderrLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for StderrLayer {
    fn on_event(&self, event: &tracing_core::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        use std::fmt::Write as _;
        let meta = event.metadata();
        let mut buf = String::with_capacity(128);
        let _ = write!(buf, "{} {}: ", meta.level(), meta.target());
        // Extract the message and fields.
        struct Visitor<'a>(&'a mut String);
        impl tracing_core::field::Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                if field.name() == "message" {
                    let _ = write!(self.0, "{:?}", value);
                } else {
                    let _ = write!(self.0, " {}={:?}", field, value);
                }
            }
        }
        event.record(&mut Visitor(&mut buf));
        buf.push('\n');
        // Best-effort write; ignore errors (stderr may be closed).
        let _ = std::io::stderr().write_all(buf.as_bytes());
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Create the log forwarding layer that will pipe events to the host
    // as MuxFrame::Log frames over stdout.
    let (fwd_layer, log_rx) = log_forward::forwarding_layer();

    // Determine log level from RUST_LOG env var. We use a static LevelFilter
    // instead of EnvFilter to avoid pulling in the regex engine (~133 KB .text).
    use tracing_subscriber::filter::LevelFilter;

    let level = match std::env::var("RUST_LOG").ok().as_deref() {
        Some("trace") => LevelFilter::TRACE,
        Some("debug") => LevelFilter::DEBUG,
        Some("warn") => LevelFilter::WARN,
        Some("error") => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    };

    // Initialize tracing: stderr for pre-connection output + forwarding layer.
    // stdout is reserved for the binary mux protocol after handshake.
    tracing_subscriber::registry()
        .with(StderrLayer)
        .with(fwd_layer)
        .with(level)
        .init();

    if let Err(e) = run(log_rx).await {
        error!("agent exited with error: {e}");
        std::process::exit(1);
    }
}

async fn run(log_rx: tokio::sync::mpsc::Receiver<protocol::AgentLogEvent>) -> Result<()> {
    // 1. Generate a session token for log correlation.
    let token = common::generate_token();

    // 2. Print handshake info to stdout (text mode), then switch to binary framing.
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "AGENT_READY").map_err(Error::Io)?;
        writeln!(stdout, "TRANSPORT=mux").map_err(Error::Io)?;
        writeln!(stdout, "TOKEN={token}").map_err(Error::Io)?;
        stdout.flush().map_err(Error::Io)?;
    }

    // Create a session-scoped tracing span for log correlation.
    let session_span = tracing::info_span!("session", session_id = %token);
    let _session_guard = session_span.enter();

    info!("agent ready, using stdio mux transport");

    // 3. Set up the frame output channel.
    // All tasks send MuxFrame values through this channel; a single writer
    // task serializes them to stdout.
    let (frame_tx, frame_rx) = mpsc::unbounded_channel::<MuxFrame>();

    // 4. Start the stdout writer task.
    tokio::spawn(write_frames(frame_rx));

    // 5. Start log forwarding into the frame channel.
    tokio::spawn(log_forward::drain_logs(log_rx, frame_tx.clone()));
    info!("log forwarding active");

    // 6. Send Handshake message.
    let handshake = ControlMsg::Handshake {
        protocol_version: PROTOCOL_VERSION,
        token,
    };
    let _ = frame_tx.send(MuxFrame::Control(handshake));
    info!("sent handshake");

    // 7. Start the background port scan loop.
    // Pass 0 as self_port since we don't have a listening UDP endpoint to exclude.
    let (port_tx, mut port_rx) = mpsc::unbounded_channel::<PortEvent>();
    let scanner = DefaultScanner::new();
    tokio::spawn(run_scan_loop(scanner, port_tx, 0));

    // Forward port events as control frames.
    let scan_frame_tx = frame_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = port_rx.recv().await {
            let msg = match event {
                PortEvent::Added(port, proto, process_name) => {
                    ControlMsg::PortAdded {
                        port,
                        proto,
                        process_name,
                    }
                }
                PortEvent::Removed(port, proto) => ControlMsg::PortRemoved { port, proto },
            };
            if scan_frame_tx.send(MuxFrame::Control(msg)).is_err() {
                break;
            }
        }
    });

    // 8. Active TCP streams: stream_id -> sender for incoming data from host.
    let mut streams: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();

    // Shared cache of UDP sockets for datagram forwarding (port -> socket).
    let udp_cache: Arc<RwLock<HashMap<u16, Arc<UdpSocket>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // 9. Main loop: read frames from stdin and dispatch.
    let mut stdin = tokio::io::stdin();

    loop {
        let frame = match read_frame(&mut stdin).await {
            Ok(frame) => frame,
            Err(e) => {
                info!("stdin closed: {e}");
                break;
            }
        };

        match frame {
            MuxFrame::Control(msg) => match msg {
                ControlMsg::EchoRequest { payload } => {
                    info!(len = payload.len(), "received echo request");
                    let _ = frame_tx.send(MuxFrame::Control(ControlMsg::EchoResponse { payload }));
                }
                ControlMsg::Heartbeat => {
                    info!("received heartbeat, sending heartbeat back");
                    let _ = frame_tx.send(MuxFrame::Control(ControlMsg::Heartbeat));
                }
                other => {
                    info!(?other, "received unhandled control message");
                }
            },

            MuxFrame::StreamOpen { stream_id, port } => {
                debug!(stream_id, port, "received StreamOpen");
                let (data_tx, data_rx) = mpsc::unbounded_channel();
                streams.insert(stream_id, data_tx);
                let ftx = frame_tx.clone();
                tokio::spawn(handle_tcp_stream(stream_id, port, data_rx, ftx));
            }

            MuxFrame::StreamData { stream_id, data } => {
                if let Some(tx) = streams.get(&stream_id) {
                    if tx.send(data).is_err() {
                        streams.remove(&stream_id);
                    }
                }
            }

            MuxFrame::StreamClose { stream_id } => {
                debug!(stream_id, "received StreamClose from host");
                streams.remove(&stream_id);
            }

            MuxFrame::Datagram { port, data } => {
                let cache = udp_cache.clone();
                tokio::spawn(handle_udp_datagram(port, data, cache));
            }

            _ => {
                debug!("received unexpected frame type, ignoring");
            }
        }
    }

    info!("agent shutting down");
    Ok(())
}

/// Handle a TCP forwarding request for a multiplexed stream.
///
/// Protocol:
/// 1. Connect to localhost:port
/// 2. Send StreamResult (success or error)
/// 3. On success: bidirectional forwarding between TCP and mux frames
async fn handle_tcp_stream(
    stream_id: u32,
    port: u16,
    mut data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    frame_tx: mpsc::UnboundedSender<MuxFrame>,
) {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let tcp_stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            let _ = frame_tx.send(MuxFrame::StreamResult {
                stream_id,
                error: None,
            });
            s
        }
        Err(e) => {
            warn!(port, %e, "failed to connect to local service");
            let _ = frame_tx.send(MuxFrame::StreamResult {
                stream_id,
                error: Some(e.to_string()),
            });
            return;
        }
    };

    debug!(stream_id, port, "connected to local service, starting forwarding");

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Host -> Agent -> TCP: write data from mux frames to the TCP socket.
    let write_task = async {
        while let Some(data) = data_rx.recv().await {
            if tcp_write.write_all(&data).await.is_err() {
                break;
            }
        }
    };

    // TCP -> Agent -> Host: read from TCP, send as StreamData frames.
    let ftx = frame_tx.clone();
    let read_task = async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ftx
                        .send(MuxFrame::StreamData {
                            stream_id,
                            data: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ftx.send(MuxFrame::StreamClose { stream_id });
    };

    tokio::select! {
        _ = write_task => {},
        _ = read_task => {},
    }

    debug!(stream_id, port, "TCP stream forwarding complete");
}

/// Handle a single incoming UDP datagram, forwarding it to the local service.
async fn handle_udp_datagram(
    port: u16,
    data: Vec<u8>,
    cache: Arc<RwLock<HashMap<u16, Arc<UdpSocket>>>>,
) {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();

    // Try to get cached socket first (fast path).
    let socket = {
        let read_guard = cache.read().await;
        read_guard.get(&port).cloned()
    };

    let socket = match socket {
        Some(s) => s,
        None => {
            let new_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    debug!(port, %e, "failed to bind UDP socket for forwarding");
                    return;
                }
            };
            let mut write_guard = cache.write().await;
            write_guard
                .entry(port)
                .or_insert_with(|| new_socket.clone());
            new_socket
        }
    };

    if let Err(e) = socket.send_to(&data, addr).await {
        debug!(port, %e, "failed to forward UDP datagram");
    }
}

// ---------------------------------------------------------------------------
// Frame I/O helpers
// ---------------------------------------------------------------------------

/// Read a single length-prefixed, rkyv-encoded MuxFrame from an async reader.
async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<MuxFrame> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Transport(format!("failed to read frame length: {e}")))?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| Error::Transport(format!("failed to read frame payload: {e}")))?;

    let frame: MuxFrame =
        protocol::decode(&payload).map_err(|e| Error::Codec(format!("decode error: {e}")))?;

    Ok(frame)
}

/// Write frames from the channel to stdout as length-prefixed rkyv payloads.
async fn write_frames(mut rx: mpsc::UnboundedReceiver<MuxFrame>) {
    let mut stdout = tokio::io::stdout();
    let mut write_buf: Vec<u8> = Vec::with_capacity(8192);

    while let Some(frame) = rx.recv().await {
        let payload = match protocol::encode(&frame) {
            Ok(p) => p,
            Err(e) => {
                debug!(%e, "failed to encode frame, skipping");
                continue;
            }
        };

        let len = payload.len() as u32;

        // Coalesce length prefix + payload into a single write.
        write_buf.clear();
        write_buf.extend_from_slice(&len.to_be_bytes());
        write_buf.extend_from_slice(&payload);

        if stdout.write_all(&write_buf).await.is_err() {
            break;
        }
        if stdout.flush().await.is_err() {
            break;
        }
    }
}
