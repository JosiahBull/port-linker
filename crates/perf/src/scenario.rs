//! The connection-setup latency scenario.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tunnel::StreamSetup;

use crate::Result;
use crate::fixture::{EchoService, ForwardedPort, Tunnel};
use crate::stats::{Stats, ms};

/// One byte in, one byte out. The smallest possible exchange, so what is
/// measured is latency and not bandwidth or window growth.
const PING: &[u8] = b"x";

/// Connections made and discarded before sampling, to get first-connection
/// effects (congestion window, agent task spin-up) out of the numbers.
const WARMUP_CONNECTIONS: usize = 2;

/// Per-sample ceiling. A hang should fail a test, not wedge CI.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Latencies observed on one tunnelled connection.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionSample {
    /// From starting the local connect to the first response byte. Includes
    /// whatever the stream setup costs.
    pub first_request: Duration,
    /// A second request on the same, now-established connection. Setup is
    /// already paid, so this is the steady-state round trip.
    pub second_request: Duration,
}

/// Open one connection through the tunnel and time two request/response pairs.
///
/// Sampling both is what makes the result self-normalising: `second_request` is
/// the round trip alone, so `first_request - second_request` isolates the cost
/// of setting the stream up, independent of how fast the machine is.
async fn sample_connection(addr: SocketAddr) -> Result<ConnectionSample> {
    let sample = async {
        let mut byte = [0u8; 1];

        let start = Instant::now();
        let mut socket = TcpStream::connect(addr).await?;
        socket.set_nodelay(true)?;
        socket.write_all(PING).await?;
        socket.read_exact(&mut byte).await?;
        let first_request = start.elapsed();

        let start = Instant::now();
        socket.write_all(PING).await?;
        socket.read_exact(&mut byte).await?;
        let second_request = start.elapsed();

        let _ = socket.shutdown().await;

        Ok::<_, std::io::Error>(ConnectionSample {
            first_request,
            second_request,
        })
    };

    match tokio::time::timeout(SAMPLE_TIMEOUT, sample).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(format!("sample did not complete within {SAMPLE_TIMEOUT:?}").into()),
    }
}

/// Aggregated result for one [`StreamSetup`].
#[derive(Debug, Clone)]
pub struct Measurement {
    pub setup: StreamSetup,
    pub rtt: Duration,
    pub first_request: Stats,
    pub second_request: Stats,
}

impl Measurement {
    /// Median cost of establishing a tunnelled connection, with the unavoidable
    /// request round trip subtracted out.
    pub fn setup_overhead(&self) -> Duration {
        self.first_request
            .median()
            .saturating_sub(self.second_request.median())
    }

    /// [`Measurement::setup_overhead`] as a multiple of the path's round-trip
    /// time — the machine-independent form the assertions use.
    pub fn setup_overhead_rtts(&self) -> f64 {
        if self.rtt.is_zero() {
            return 0.0;
        }
        self.setup_overhead().as_secs_f64() / self.rtt.as_secs_f64()
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:?}", self.setup)?;
        writeln!(f, "  connect + first request : {}", self.first_request)?;
        writeln!(f, "  second request          : {}", self.second_request)?;
        write!(
            f,
            "  setup overhead          : {:>7.2}ms  ({:.2} x RTT)",
            ms(self.setup_overhead()),
            self.setup_overhead_rtts()
        )
    }
}

/// A benchmark run against one live tunnel.
///
/// Both stream setups are measured over the *same* agent, shim, and QUIC
/// connection, so an A/B comparison is not confounded by a different process, a
/// different congestion window, or a differently loaded machine.
pub struct Bench {
    tunnel: Tunnel,
    echo: EchoService,
}

impl Bench {
    /// Bring up an agent, a target service, and a tunnel with the given RTT.
    pub async fn start(rtt: Duration) -> Result<Self> {
        let echo = EchoService::spawn().await?;
        let tunnel = Tunnel::establish(rtt).await?;
        Ok(Self { tunnel, echo })
    }

    pub fn rtt(&self) -> Duration {
        self.tunnel.rtt()
    }

    /// Measure `iterations` connections, one at a time, for one setup mode.
    ///
    /// Sequential by design: concurrent connections would overlap their round
    /// trips and hide exactly the per-connection cost being measured.
    pub async fn run(&self, setup: StreamSetup, iterations: usize) -> Result<Measurement> {
        let forwarded =
            ForwardedPort::spawn(self.tunnel.connection(), self.echo.port(), setup).await?;
        let addr = forwarded.addr();

        for _ in 0..WARMUP_CONNECTIONS {
            sample_connection(addr).await?;
        }

        let mut first = Vec::with_capacity(iterations);
        let mut second = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let sample = sample_connection(addr).await?;
            first.push(sample.first_request);
            second.push(sample.second_request);
        }

        Ok(Measurement {
            setup,
            rtt: self.tunnel.rtt(),
            first_request: Stats::new(first),
            second_request: Stats::new(second),
        })
    }
}
