//! Performance regression tests for forwarded-TCP connection setup.
//!
//! # What is guarded
//!
//! One round trip is unavoidable: a request has to reach the service and the
//! response has to come back. Connection setup must add nothing on top of that.
//! If someone reintroduces a wait on the critical path — the host blocking on the
//! agent's status byte before it reads the local socket, say — the first request
//! costs two round trips instead of one, and these fail.
//!
//! # How they avoid being flaky
//!
//! Every bound is a multiple of the round-trip time the benchmark itself imposes,
//! never an absolute duration, so the thresholds mean the same thing on a fast
//! laptop and a loaded CI runner. The RTT is set well above the noise floor of
//! loopback and of a debug build, and the statistic compared is a median, so one
//! descheduled sample cannot fail a run.
//!
//! # How they avoid passing vacuously
//!
//! A harness that accidentally measured nothing — no imposed latency, or timing
//! the wrong thing — would satisfy any upper bound. So
//! [`benchmark_measures_a_latency_bearing_path`] asserts the opposite direction:
//! that a request on an *established* connection costs about one full RTT. That
//! can only hold if the shim is really delaying datagrams and the measurement is
//! really going through the tunnel. `LatencyShim`'s own unit tests
//! (`round_trip_is_delayed_by_the_configured_rtt`, `datagram_order_is_preserved`)
//! check the shim itself independently.

use std::sync::LazyLock;
use std::time::Duration;

use perf::{Bench, ms};
use tokio::sync::Mutex;

/// Benchmarks run one at a time.
///
/// Two reasons. Methodologically, concurrent benchmarks contend for the cores and
/// timers they are measuring, which inflates exactly the latencies under test.
/// Practically, each one starts an agent subprocess, a latency shim, and a
/// multi-threaded runtime; several at once oversubscribed a small CI runner badly
/// enough to stall a QUIC handshake past its idle timeout.
///
/// The lock lives here rather than relying on `--test-threads=1` so the property
/// holds however the suite is invoked.
static BENCH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Large enough that scheduling jitter and debug-build overhead are a small
/// fraction of it, small enough to keep the suite quick.
const RTT: Duration = Duration::from_millis(60);

/// Connections sampled per run. The medians are stable well below this.
const ITERATIONS: usize = 12;

/// Setup must add no meaningful fraction of a round trip. Measured values sit at
/// 0.00–0.05 x RTT; 0.40 leaves room for a slow runner without admitting a whole
/// round trip.
const MAX_SETUP_RTTS: f64 = 0.40;

/// Connection setup must not cost a round trip.
///
/// Two independent expressions of the same requirement, because each fails in a
/// way the other might not: the difference between first and steady-state request
/// latency, and the absolute cost of the first request in units of RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_setup_adds_no_round_trip() {
    let _serial = BENCH_LOCK.lock().await;
    let bench = Bench::start(RTT).await.expect("bench startup");
    let measured = bench.run(ITERATIONS).await.expect("measurement");

    println!("{measured}");

    let overhead = measured.setup_overhead_rtts();
    assert!(
        overhead < MAX_SETUP_RTTS,
        "connection setup cost {overhead:.2} x RTT (limit {MAX_SETUP_RTTS:.2}); \
         a round trip has reappeared on the connection-setup path.\n{measured}"
    );

    // A connect-plus-request should cost one round trip and change. Two round
    // trips means setup is waiting for something before forwarding the request.
    let first = measured.first_request.median();
    assert!(
        first < RTT.mul_f64(1.6),
        "connect + first request took {:.2}ms, more than 1.6 x the {:.0}ms RTT; \
         that is close to the two round trips a blocking setup would cost.\n{measured}",
        ms(first),
        ms(RTT)
    );
}

/// The benchmark must be measuring a path that really carries latency.
///
/// This is the guard against a vacuous suite. A request on an already-established
/// connection has no setup left to pay, so it should cost one imposed RTT: if this
/// came back near zero, the shim would not be delaying anything and the upper
/// bounds in the test above would prove nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benchmark_measures_a_latency_bearing_path() {
    let _serial = BENCH_LOCK.lock().await;
    let bench = Bench::start(RTT).await.expect("bench startup");
    let measured = bench.run(ITERATIONS).await.expect("measurement");

    println!("{measured}");

    let steady = measured.second_request.median();
    assert!(
        steady >= RTT.mul_f64(0.8) && steady <= RTT.mul_f64(2.0),
        "a request on an established connection took {:.2}ms, expected roughly \
         one {:.0}ms RTT. The benchmark is not measuring a delayed tunnel, so its \
         other assertions cannot be trusted.\n{measured}",
        ms(steady),
        ms(RTT)
    );
}
