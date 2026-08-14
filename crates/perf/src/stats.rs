//! Summary statistics over latency samples.

use std::fmt;
use std::time::Duration;

/// Render a duration as milliseconds, the unit every number in this crate is
/// reported in.
pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Sorted latency samples with the percentiles the benchmarks report.
///
/// Medians rather than means are what the assertions use: a single scheduler
/// hiccup or a GC-like pause in the agent moves a mean but not a median, and
/// these runs are deliberately short.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    sorted: Vec<Duration>,
}

impl Stats {
    /// Collect samples. Order does not matter; they are sorted here.
    pub fn new(mut samples: Vec<Duration>) -> Self {
        samples.sort_unstable();
        Self { sorted: samples }
    }

    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }

    /// The `q`-quantile, `q` in `0.0..=1.0`. Nearest-rank, no interpolation.
    ///
    /// Returns [`Duration::ZERO`] for an empty sample set, so a caller that
    /// forgot to collect anything reports an obviously wrong zero rather than
    /// panicking inside a benchmark run.
    pub fn percentile(&self, q: f64) -> Duration {
        if self.sorted.is_empty() {
            return Duration::ZERO;
        }
        let rank = (q.clamp(0.0, 1.0) * (self.sorted.len() - 1) as f64).round() as usize;
        self.sorted[rank]
    }

    pub fn min(&self) -> Duration {
        self.percentile(0.0)
    }

    pub fn median(&self) -> Duration {
        self.percentile(0.5)
    }

    pub fn p95(&self) -> Duration {
        self.percentile(0.95)
    }

    pub fn max(&self) -> Duration {
        self.percentile(1.0)
    }

    pub fn mean(&self) -> Duration {
        if self.sorted.is_empty() {
            return Duration::ZERO;
        }
        self.sorted.iter().sum::<Duration>() / self.sorted.len() as u32
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "median {:>7.2}ms  min {:>7.2}ms  p95 {:>7.2}ms  max {:>7.2}ms  (n={})",
            ms(self.median()),
            ms(self.min()),
            ms(self.p95()),
            ms(self.max()),
            self.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let s = Stats::new(vec![d(10), d(20), d(30), d(40), d(50)]);
        assert_eq!(s.min(), d(10));
        assert_eq!(s.median(), d(30));
        assert_eq!(s.max(), d(50));
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn samples_are_sorted_on_construction() {
        let s = Stats::new(vec![d(50), d(10), d(30)]);
        assert_eq!(s.min(), d(10));
        assert_eq!(s.median(), d(30));
        assert_eq!(s.max(), d(50));
    }

    #[test]
    fn mean_averages_all_samples() {
        let s = Stats::new(vec![d(10), d(20), d(60)]);
        assert_eq!(s.mean(), d(30));
    }

    /// An empty sample set must not panic mid-benchmark.
    #[test]
    fn empty_stats_report_zero() {
        let s = Stats::default();
        assert!(s.is_empty());
        assert_eq!(s.median(), Duration::ZERO);
        assert_eq!(s.mean(), Duration::ZERO);
        assert_eq!(s.p95(), Duration::ZERO);
    }

    #[test]
    fn out_of_range_quantiles_are_clamped() {
        let s = Stats::new(vec![d(10), d(20)]);
        assert_eq!(s.percentile(-1.0), d(10));
        assert_eq!(s.percentile(2.0), d(20));
    }
}
