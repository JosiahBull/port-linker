//! Benchmark runner: reports what a forwarded TCP connection costs.
//!
//! ```text
//! cargo run -p perf --release -- --rtt-ms 60 --iterations 20
//! ```
//!
//! Run it before and after a change to the data plane to get a number to compare.
//! The figures are stable to a fraction of a millisecond across runs at a given
//! RTT, so a real regression is easy to see.

use std::time::Duration;

use clap::Parser;
use perf::{Bench, ms};

#[derive(Parser, Debug)]
#[command(
    name = "port-linker-perf",
    about = "Measure forwarded-TCP connection latency through a port-linker tunnel"
)]
struct Args {
    /// Round-trip time to impose between host and agent, in milliseconds.
    #[arg(long, default_value_t = 60)]
    rtt_ms: u64,

    /// Connections to sample.
    #[arg(long, default_value_t = 20)]
    iterations: usize,
}

#[tokio::main]
async fn main() -> perf::Result<()> {
    let args = Args::parse();
    let rtt = Duration::from_millis(args.rtt_ms);

    println!(
        "imposed RTT {:.0}ms, {} connections\n",
        ms(rtt),
        args.iterations
    );

    let bench = Bench::start(rtt).await?;
    let measured = bench.run(args.iterations).await?;

    println!("{measured}\n");

    // Setup overhead is the number to watch: the second request on an established
    // connection costs one round trip and cannot be improved, so anything above
    // it is what connection setup adds.
    println!(
        "connection setup adds {:.2}ms on top of the {:.0}ms round trip ({:.2} x RTT)",
        ms(measured.setup_overhead()),
        ms(rtt),
        measured.setup_overhead_rtts()
    );

    Ok(())
}
