//! Ad-hoc benchmark runner.
//!
//! ```text
//! cargo run -p perf --release -- --rtt-ms 60 --iterations 20
//! ```

use std::time::Duration;

use clap::Parser;
use perf::{Bench, Measurement, ms};
use tunnel::StreamSetup;

#[derive(Parser, Debug)]
#[command(
    name = "port-linker-perf",
    about = "Measure forwarded-TCP connection latency through a port-linker tunnel"
)]
struct Args {
    /// Round-trip time to impose between host and agent, in milliseconds.
    #[arg(long, default_value_t = 60)]
    rtt_ms: u64,

    /// Connections to sample per stream-setup mode.
    #[arg(long, default_value_t = 20)]
    iterations: usize,

    /// Measure only this setup mode instead of comparing both.
    #[arg(long, value_enum)]
    only: Option<Mode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Mode {
    /// Stream application bytes behind the init frame (shipped behaviour).
    Optimistic,
    /// Wait for the agent's status byte first (pre-optimisation baseline).
    WaitForStatus,
}

impl From<Mode> for StreamSetup {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Optimistic => StreamSetup::Optimistic,
            Mode::WaitForStatus => StreamSetup::WaitForStatus,
        }
    }
}

#[tokio::main]
async fn main() -> perf::Result<()> {
    let args = Args::parse();
    let rtt = Duration::from_millis(args.rtt_ms);

    println!(
        "imposed RTT {:.0}ms, {} connections per mode\n",
        ms(rtt),
        args.iterations
    );

    let bench = Bench::start(rtt).await?;

    let modes: Vec<StreamSetup> = match args.only {
        Some(mode) => vec![mode.into()],
        // Baseline first, so a reader sees the improvement rather than a
        // regression.
        None => vec![StreamSetup::WaitForStatus, StreamSetup::Optimistic],
    };

    let mut results: Vec<Measurement> = Vec::new();
    for setup in modes {
        let measurement = bench.run(setup, args.iterations).await?;
        println!("{measurement}\n");
        results.push(measurement);
    }

    if let [baseline, optimistic] = results.as_slice() {
        let saved = baseline
            .first_request
            .median()
            .saturating_sub(optimistic.first_request.median());
        println!(
            "optimistic setup saves {:.2}ms per connection ({:.2} x RTT)",
            ms(saved),
            saved.as_secs_f64() / rtt.as_secs_f64().max(f64::MIN_POSITIVE)
        );
    }

    Ok(())
}
