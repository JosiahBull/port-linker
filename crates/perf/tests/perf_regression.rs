//! Performance regression tests for forwarded-TCP connection setup.
//!
//! # How these avoid being flaky
//!
//! Every bound is a multiple of the round-trip time the benchmark itself
//! imposes, never an absolute duration, so the thresholds mean the same thing on
//! a fast laptop and a loaded CI runner. The RTT is set well above the noise
//! floor of loopback and of a debug build, and the statistic compared is a
//! median, so one descheduled sample cannot fail a run.
//!
//! # How these avoid passing vacuously
//!
//! A benchmark that silently measures nothing would pass any upper bound. So the
//! suite also asserts the *opposite* direction on the pre-optimisation code path
//! ([`StreamSetup::WaitForStatus`], kept for exactly this purpose): that path
//! must still show the round trip. If a future change to the harness stops
//! imposing latency, or stops measuring connection setup, that assertion fails
//! and the whole suite is known to be untrustworthy.

use std::sync::LazyLock;
use std::time::Duration;

use perf::{Bench, ms};
use tokio::sync::Mutex;
use tunnel::StreamSetup;

/// Benchmarks run one at a time.
///
/// Two reasons. Methodologically, concurrent benchmarks contend for the cores
/// and timers they are measuring, which inflates exactly the latencies under
/// test. Practically, each one starts an agent subprocess, a latency shim, and a
/// multi-threaded runtime; three at once oversubscribed a small CI runner badly
/// enough to stall a QUIC handshake past its idle timeout.
///
/// The lock lives here rather than relying on `--test-threads=1` so the property
/// holds however the suite is invoked.
static BENCH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Large enough that scheduling jitter and debug-build overhead are a small
/// fraction of it, small enough to keep the suite quick.
const RTT: Duration = Duration::from_millis(60);

/// Connections sampled per mode. The medians are stable well below this.
const ITERATIONS: usize = 12;

/// Optimistic setup must add no meaningful fraction of a round trip. Measured
/// values sit at 0.00–0.05 x RTT; 0.40 leaves room for a slow runner without
/// admitting a whole round trip.
const MAX_OPTIMISTIC_SETUP_RTTS: f64 = 0.40;

/// The legacy path must still cost most of a round trip. Measured values sit at
/// 1.0–1.3 x RTT. If this fails, the harness has stopped measuring setup.
const MIN_LEGACY_SETUP_RTTS: f64 = 0.60;

/// Connection setup must not cost a round trip.
///
/// This is the regression guard for the optimistic stream setup: the host sends
/// the init frame and the client's first bytes together instead of waiting for
/// the agent's status byte. If someone reintroduces a wait on the critical path,
/// the setup overhead jumps back to ~1 x RTT and this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optimistic_setup_costs_no_round_trip() {
    let _serial = BENCH_LOCK.lock().await;
    let bench = Bench::start(RTT).await.expect("bench startup");
    let measured = bench
        .run(StreamSetup::Optimistic, ITERATIONS)
        .await
        .expect("optimistic measurement");

    println!("{measured}");

    let overhead = measured.setup_overhead_rtts();
    assert!(
        overhead < MAX_OPTIMISTIC_SETUP_RTTS,
        "connection setup cost {overhead:.2} x RTT (limit {MAX_OPTIMISTIC_SETUP_RTTS:.2}); \
         a round trip has reappeared on the connection-setup path.\n{measured}"
    );

    // Sanity: a request on the established connection should cost about one
    // round trip. If it does not, the harness is not measuring the tunnel and
    // the bound above proves nothing.
    let steady = measured.second_request.median();
    assert!(
        steady >= RTT.mul_f64(0.8) && steady <= RTT.mul_f64(2.0),
        "steady-state request took {:.2}ms, expected roughly one {:.0}ms RTT; \
         the harness is not measuring what it should be.\n{measured}",
        ms(steady),
        ms(RTT)
    );
}

/// The benchmark must be able to see a round trip when one is really there.
///
/// This measures the pre-optimisation code path and asserts it *is* slow. It is
/// the guard against a vacuous suite: without it, a harness that imposed no
/// latency, or that timed the wrong thing, would sail through the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benchmark_detects_the_round_trip_it_removes() {
    let _serial = BENCH_LOCK.lock().await;
    let bench = Bench::start(RTT).await.expect("bench startup");
    let measured = bench
        .run(StreamSetup::WaitForStatus, ITERATIONS)
        .await
        .expect("baseline measurement");

    println!("{measured}");

    let overhead = measured.setup_overhead_rtts();
    assert!(
        overhead > MIN_LEGACY_SETUP_RTTS,
        "the pre-optimisation path cost only {overhead:.2} x RTT (expected > \
         {MIN_LEGACY_SETUP_RTTS:.2}). The benchmark is no longer measuring \
         connection setup, so its other assertions cannot be trusted.\n{measured}"
    );
}

/// Head-to-head over one tunnel: same agent, same shim, same QUIC connection.
///
/// Separate runs could differ for reasons unrelated to the code — a different
/// congestion window, a differently loaded machine. Measuring both modes over
/// one tunnel makes the comparison attributable to the setup mode alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optimistic_setup_beats_waiting_for_status() {
    let _serial = BENCH_LOCK.lock().await;
    let bench = Bench::start(RTT).await.expect("bench startup");

    let baseline = bench
        .run(StreamSetup::WaitForStatus, ITERATIONS)
        .await
        .expect("baseline measurement");
    let optimistic = bench
        .run(StreamSetup::Optimistic, ITERATIONS)
        .await
        .expect("optimistic measurement");

    println!("{baseline}\n{optimistic}");

    let saved = baseline
        .first_request
        .median()
        .saturating_sub(optimistic.first_request.median());
    let saved_rtts = saved.as_secs_f64() / RTT.as_secs_f64();

    assert!(
        saved_rtts > 0.5,
        "optimistic setup saved only {saved_rtts:.2} x RTT ({:.2}ms); expected \
         close to a full round trip.\n{baseline}\n{optimistic}",
        ms(saved)
    );

    // The two modes differ only in when the host starts reading the local
    // socket, so an established connection must behave identically. A gap here
    // would mean the change leaked into steady-state throughput.
    let baseline_steady = baseline.second_request.median();
    let optimistic_steady = optimistic.second_request.median();
    let gap = baseline_steady.abs_diff(optimistic_steady);
    assert!(
        gap < RTT.mul_f64(0.5),
        "steady-state latency differs by {:.2}ms between setup modes \
         ({:.2}ms vs {:.2}ms); the change should affect setup only.",
        ms(gap),
        ms(baseline_steady),
        ms(optimistic_steady)
    );
}
