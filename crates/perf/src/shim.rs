//! A userspace UDP relay that imposes a fixed round-trip time.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Largest datagram the shim relays. QUIC datagrams stay far below this; the
/// slack means an unexpectedly large one is never silently truncated.
const MAX_DATAGRAM: usize = 65_535;

/// Delays every datagram in both directions by half the configured round-trip
/// time.
///
/// This is how the benchmarks get a deterministic RTT. The alternatives all have
/// problems: `tc netem` needs root and Linux, containers make the measurement
/// depend on Docker's networking, and a real remote host is not reproducible.
/// Because the tunnel is QUIC over UDP, inserting the delay at the datagram
/// layer delays the transport exactly the way a wide-area path would — including
/// the handshake, ACKs, and loss timers — while staying deterministic enough to
/// assert on.
///
/// Point the QUIC client at [`LatencyShim::addr`] instead of the agent's real
/// address. Ordering is preserved: every datagram waits the same amount, so a
/// single FIFO consumer per direction releases them in arrival order.
///
/// The shim assumes one client, which is what the benchmarks use — the tunnel is
/// a single QUIC connection.
pub struct LatencyShim {
    front: SocketAddr,
    rtt: Duration,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for LatencyShim {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl LatencyShim {
    /// Start relaying to `target`, delaying each direction by `rtt / 2`.
    pub async fn spawn(target: SocketAddr, rtt: Duration) -> std::io::Result<Self> {
        let one_way = rtt / 2;

        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let front_addr = front.local_addr()?;

        // Learned from the first datagram the client sends. One client only, and
        // its address does not change, so this is written once in practice.
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        let (to_target_tx, mut to_target_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();

        let mut tasks = Vec::with_capacity(4);

        // client -> queue
        tasks.push(tokio::spawn({
            let front = front.clone();
            let client = client.clone();
            async move {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                loop {
                    let Ok((n, from)) = front.recv_from(&mut buf).await else {
                        break;
                    };
                    *client.lock().expect("shim client addr poisoned") = Some(from);
                    if to_target_tx
                        .send((Instant::now() + one_way, buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }));

        // queue -> target, released in arrival order once the delay has elapsed
        tasks.push(tokio::spawn({
            let back = back.clone();
            async move {
                while let Some((release_at, payload)) = to_target_rx.recv().await {
                    tokio::time::sleep_until(release_at).await;
                    if back.send_to(&payload, target).await.is_err() {
                        break;
                    }
                }
            }
        }));

        // target -> queue
        tasks.push(tokio::spawn({
            let back = back.clone();
            async move {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                loop {
                    let Ok((n, _)) = back.recv_from(&mut buf).await else {
                        break;
                    };
                    if to_client_tx
                        .send((Instant::now() + one_way, buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }));

        // queue -> client
        tasks.push(tokio::spawn({
            let front = front.clone();
            let client = client.clone();
            async move {
                while let Some((release_at, payload)) = to_client_rx.recv().await {
                    tokio::time::sleep_until(release_at).await;
                    // Copy the address out before awaiting: the guard must not be
                    // held across a suspension point.
                    let destination = *client.lock().expect("shim client addr poisoned");
                    let Some(destination) = destination else {
                        continue;
                    };
                    if front.send_to(&payload, destination).await.is_err() {
                        break;
                    }
                }
            }
        }));

        Ok(Self {
            front: front_addr,
            rtt,
            tasks,
        })
    }

    /// The address a client should use in place of the real target.
    pub fn addr(&self) -> SocketAddr {
        self.front
    }

    /// The round-trip time this shim imposes.
    pub fn rtt(&self) -> Duration {
        self.rtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shim must actually delay, and by close to the configured RTT: every
    /// benchmark assertion is expressed as a fraction of it.
    #[tokio::test]
    async fn round_trip_is_delayed_by_the_configured_rtt() {
        let rtt = Duration::from_millis(120);

        // A trivial UDP echo standing in for the agent.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n], from).await;
            }
        });

        let shim = LatencyShim::spawn(server_addr, rtt).await.expect("shim");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let start = Instant::now();
        client.send_to(b"ping", shim.addr()).await.expect("send");
        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("shim relayed within timeout")
            .expect("recv");
        let elapsed = start.elapsed();

        assert_eq!(&buf[..n], b"ping", "payload must survive the relay");
        assert!(
            elapsed >= rtt,
            "expected at least one full RTT of delay, got {elapsed:?}"
        );
        assert!(
            elapsed < rtt * 3,
            "delay should be close to the configured RTT, got {elapsed:?}"
        );
    }

    /// Datagram order must be preserved, or QUIC would see spurious reordering
    /// and the measurements would include unrelated recovery behaviour.
    #[tokio::test]
    async fn datagram_order_is_preserved() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n], from).await;
            }
        });

        let shim = LatencyShim::spawn(server_addr, Duration::from_millis(40))
            .await
            .expect("shim");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");

        for i in 0u8..16 {
            client.send_to(&[i], shim.addr()).await.expect("send");
        }

        let mut received = Vec::new();
        let mut buf = [0u8; 8];
        for _ in 0u8..16 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .expect("all datagrams relayed")
                .expect("recv");
            assert_eq!(n, 1);
            received.push(buf[0]);
        }

        let expected: Vec<u8> = (0u8..16).collect();
        assert_eq!(received, expected, "datagrams must arrive in order");
    }
}
