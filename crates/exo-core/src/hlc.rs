//! Hybrid Logical Clock (HLC) for causal ordering.
//!
//! The HLC combines a caller-supplied physical component with a logical
//! counter so that:
//!
//! 1. Timestamps are **monotonically increasing** even when the physical source
//!    is stale or drifts backward.
//! 2. Causally-related events are always ordered correctly.
//! 3. No floating-point arithmetic is involved.

use crate::{
    error::{ExoError, Result},
    types::Timestamp,
};

/// Default maximum tolerable forward drift in milliseconds.
/// If a remote timestamp is more than this far ahead of our local physical
/// source, we reject it as drift.
const MAX_DRIFT_MS: u64 = 5_000; // 5 seconds
/// Deterministic non-zero epoch for default clocks. This intentionally keeps
/// zero-epoch records stale without reading host wall-clock time.
const DEFAULT_DETERMINISTIC_PHYSICAL_MS: u64 = 1_000_000;

/// A Hybrid Logical Clock instance.
///
/// Each node in the EXOCHAIN network maintains its own `HybridClock`.
/// The clock is driven by a deterministic physical source and a logical
/// counter. The default constructor does not read host time; runtime adapters
/// that need deployment-specific physical metadata must inject an explicit HLC
/// source.
pub struct HybridClock {
    /// Last-known HLC physical milliseconds.
    physical: u64,
    /// Logical counter within the same physical millisecond.
    logical: u32,
    /// Maximum tolerated remote forward drift for this clock.
    max_drift_ms: u64,
    /// Physical source — returns current HLC physical milliseconds.
    physical_source: Box<dyn Fn() -> Result<u64> + Send>,
}

impl HybridClock {
    /// Create a new clock driven by EXOCHAIN's deterministic default source.
    #[must_use]
    pub fn new() -> Self {
        let next_physical_ms = std::sync::atomic::AtomicU64::new(DEFAULT_DETERMINISTIC_PHYSICAL_MS);
        Self {
            physical: 0,
            logical: 0,
            max_drift_ms: MAX_DRIFT_MS,
            physical_source: Box::new(move || {
                next_physical_ms
                    .fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |current| current.checked_add(1),
                    )
                    .map_err(|current| ExoError::ClockOverflow {
                        physical_ms: current,
                        logical: u32::MAX,
                    })
            }),
        }
    }

    /// Create a clock with a custom physical source.
    #[must_use]
    pub fn with_wall_clock(physical_source: impl Fn() -> u64 + Send + 'static) -> Self {
        Self::with_wall_clock_and_max_drift(physical_source, MAX_DRIFT_MS)
    }

    /// Create a clock with a custom physical source and drift tolerance.
    #[must_use]
    pub fn with_wall_clock_and_max_drift(
        physical_source: impl Fn() -> u64 + Send + 'static,
        max_drift_ms: u64,
    ) -> Self {
        Self::with_fallible_wall_clock_and_max_drift(move || Ok(physical_source()), max_drift_ms)
    }

    /// Create a clock with a fallible physical source.
    #[must_use]
    pub fn with_fallible_wall_clock(
        physical_source: impl Fn() -> Result<u64> + Send + 'static,
    ) -> Self {
        Self::with_fallible_wall_clock_and_max_drift(physical_source, MAX_DRIFT_MS)
    }

    /// Create a clock with a fallible physical source and drift tolerance.
    #[must_use]
    pub fn with_fallible_wall_clock_and_max_drift(
        physical_source: impl Fn() -> Result<u64> + Send + 'static,
        max_drift_ms: u64,
    ) -> Self {
        Self {
            physical: 0,
            logical: 0,
            max_drift_ms,
            physical_source: Box::new(physical_source),
        }
    }

    /// Return this clock's configured maximum forward drift in milliseconds.
    #[must_use]
    pub fn max_drift_ms(&self) -> u64 {
        self.max_drift_ms
    }

    /// Generate the next timestamp.
    ///
    /// Guarantees: the returned timestamp is strictly greater than any
    /// previously returned by this clock.
    pub fn now(&mut self) -> Result<Timestamp> {
        let physical_now = (self.physical_source)()?;
        if physical_now > self.physical {
            self.physical = physical_now;
            self.logical = 0;
        } else {
            advance_logical_or_carry_physical(&mut self.physical, &mut self.logical)?;
        }
        Ok(Timestamp::new(self.physical, self.logical))
    }

    /// Merge a remote timestamp and advance the local clock.
    ///
    /// The returned timestamp is guaranteed to be greater than both the
    /// local state and the remote timestamp.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::ClockDrift` if the remote timestamp is
    /// unreasonably far ahead of the local physical source.
    pub fn update(&mut self, remote: &Timestamp) -> Result<Timestamp> {
        let physical_now = (self.physical_source)()?;

        // Drift guard
        if remote.physical_ms > physical_now.saturating_add(self.max_drift_ms) {
            return Err(ExoError::ClockDrift {
                physical_ms: remote.physical_ms,
                tolerance_ms: self.max_drift_ms,
            });
        }

        if physical_now > self.physical && physical_now > remote.physical_ms {
            // Local physical source is ahead of both — reset logical
            self.physical = physical_now;
            self.logical = 0;
        } else if self.physical == remote.physical_ms {
            // Same physical — advance logical past both
            self.logical = self.logical.max(remote.logical);
            advance_logical_or_carry_physical(&mut self.physical, &mut self.logical)?;
        } else if remote.physical_ms > self.physical {
            // Remote is ahead — adopt remote physical, advance logical
            self.physical = remote.physical_ms;
            self.logical = remote.logical;
            advance_logical_or_carry_physical(&mut self.physical, &mut self.logical)?;
        } else {
            // Local is ahead — advance own logical
            advance_logical_or_carry_physical(&mut self.physical, &mut self.logical)?;
        }

        Ok(Timestamp::new(self.physical, self.logical))
    }

    /// Causal ordering check: returns `true` if `a` happened-before `b`.
    #[must_use]
    pub fn is_before(a: &Timestamp, b: &Timestamp) -> bool {
        a < b
    }

    /// Return the current state as a `Timestamp` without advancing.
    #[must_use]
    pub fn current(&self) -> Timestamp {
        Timestamp::new(self.physical, self.logical)
    }
}

fn advance_logical_or_carry_physical(physical: &mut u64, logical: &mut u32) -> Result<()> {
    if *logical == u32::MAX {
        if let Some(next_physical) = physical.checked_add(1) {
            *physical = next_physical;
            *logical = 0;
            Ok(())
        } else {
            Err(ExoError::ClockOverflow {
                physical_ms: *physical,
                logical: *logical,
            })
        }
    } else {
        *logical += 1;
        Ok(())
    }
}

impl Default for HybridClock {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for HybridClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridClock")
            .field("physical", &self.physical)
            .field("logical", &self.logical)
            .field("max_drift_ms", &self.max_drift_ms)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;

    /// Helper: create a clock with a controllable wall time.
    fn test_clock(initial: u64) -> (HybridClock, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(initial));
        let t = Arc::clone(&time);
        let clock = HybridClock::with_wall_clock(move || t.load(Ordering::Relaxed));
        (clock, time)
    }

    #[test]
    fn now_monotonic_same_wall_time() {
        let (mut clock, _wall) = test_clock(1000);
        let t1 = clock.now().expect("HLC timestamp");
        let t2 = clock.now().expect("HLC timestamp");
        let t3 = clock.now().expect("HLC timestamp");
        assert!(t1 < t2);
        assert!(t2 < t3);
        // All share the same physical
        assert_eq!(t1.physical_ms, 1000);
        assert_eq!(t2.physical_ms, 1000);
        assert_eq!(t3.physical_ms, 1000);
        // Logical increments
        assert_eq!(t1.logical, 0);
        assert_eq!(t2.logical, 1);
        assert_eq!(t3.logical, 2);
    }

    #[test]
    fn now_advances_with_wall_clock() {
        let (mut clock, wall) = test_clock(1000);
        let t1 = clock.now().expect("HLC timestamp");
        wall.store(2000, Ordering::Relaxed);
        let t2 = clock.now().expect("HLC timestamp");
        assert!(t1 < t2);
        assert_eq!(t2.physical_ms, 2000);
        assert_eq!(t2.logical, 0);
    }

    #[test]
    fn now_handles_backward_wall_clock() {
        let (mut clock, wall) = test_clock(2000);
        let t1 = clock.now().expect("HLC timestamp");
        wall.store(1000, Ordering::Relaxed); // wall goes backward
        let t2 = clock.now().expect("HLC timestamp");
        assert!(t1 < t2);
        // Physical stays at 2000, logical increments
        assert_eq!(t2.physical_ms, 2000);
        assert_eq!(t2.logical, 1);
    }

    #[test]
    fn update_wall_ahead_of_both() {
        let (mut clock, wall) = test_clock(1000);
        let _ = clock.now().expect("HLC timestamp");
        wall.store(5000, Ordering::Relaxed);
        let remote = Timestamp::new(3000, 5);
        let result = clock.update(&remote).expect("ok");
        assert_eq!(result.physical_ms, 5000);
        assert_eq!(result.logical, 0);
    }

    #[test]
    fn update_remote_ahead() {
        let (mut clock, _wall) = test_clock(1000);
        let _ = clock.now().expect("HLC timestamp");
        let remote = Timestamp::new(2000, 10);
        let result = clock.update(&remote).expect("ok");
        assert_eq!(result.physical_ms, 2000);
        assert_eq!(result.logical, 11);
    }

    #[test]
    fn update_same_physical() {
        let (mut clock, _wall) = test_clock(1000);
        let _ = clock.now().expect("HLC timestamp"); // physical=1000, logical=0
        let remote = Timestamp::new(1000, 5);
        let result = clock.update(&remote).expect("ok");
        assert_eq!(result.physical_ms, 1000);
        // max(local_logical=0, remote_logical=5) + 1 = 6
        assert_eq!(result.logical, 6);
    }

    #[test]
    fn update_local_ahead() {
        let (mut clock, wall) = test_clock(3000);
        let _ = clock.now().expect("HLC timestamp"); // physical=3000, logical=0
        wall.store(1000, Ordering::Relaxed); // wall backward
        let remote = Timestamp::new(2000, 0);
        let result = clock.update(&remote).expect("ok");
        // Local physical (3000) > remote (2000), local advances logical
        assert_eq!(result.physical_ms, 3000);
        assert_eq!(result.logical, 1);
    }

    #[test]
    fn update_rejects_excessive_drift() {
        let (mut clock, _wall) = test_clock(1000);
        let remote = Timestamp::new(1000 + MAX_DRIFT_MS + 1, 0);
        let err = clock.update(&remote).unwrap_err();
        assert!(matches!(err, ExoError::ClockDrift { .. }));
    }

    #[test]
    fn update_rejects_remote_more_than_default_five_seconds_ahead() {
        let (mut clock, _wall) = test_clock(1000);
        let remote = Timestamp::new(1000 + 5_001, 0);

        let err = clock
            .update(&remote)
            .expect_err("default HLC drift tolerance must be no more than five seconds");

        assert!(matches!(
            err,
            ExoError::ClockDrift {
                physical_ms: 6001,
                tolerance_ms: 5000
            }
        ));
    }

    #[test]
    fn update_accepts_at_drift_boundary() {
        let (mut clock, _wall) = test_clock(1000);
        let remote = Timestamp::new(1000 + MAX_DRIFT_MS, 0);
        let result = clock.update(&remote);
        assert!(result.is_ok());
    }

    #[test]
    fn update_uses_deployment_configured_drift_tolerance() {
        let mut boundary_clock = HybridClock::with_wall_clock_and_max_drift(|| 1000, 12_000);
        let boundary = boundary_clock
            .update(&Timestamp::new(13_000, 0))
            .expect("configured drift boundary should be accepted");
        assert_eq!(boundary, Timestamp::new(13_000, 1));

        let mut over_boundary_clock = HybridClock::with_wall_clock_and_max_drift(|| 1000, 12_000);
        let err = over_boundary_clock
            .update(&Timestamp::new(13_001, 0))
            .expect_err("remote timestamp beyond configured drift must be rejected");

        assert!(matches!(
            err,
            ExoError::ClockDrift {
                physical_ms: 13001,
                tolerance_ms: 12000
            }
        ));
    }

    #[test]
    fn is_before_ordering() {
        let a = Timestamp::new(1, 0);
        let b = Timestamp::new(1, 1);
        let c = Timestamp::new(2, 0);
        assert!(HybridClock::is_before(&a, &b));
        assert!(HybridClock::is_before(&b, &c));
        assert!(HybridClock::is_before(&a, &c));
        assert!(!HybridClock::is_before(&b, &a));
        assert!(!HybridClock::is_before(&a, &a));
    }

    #[test]
    fn current_does_not_advance() {
        let (mut clock, _wall) = test_clock(1000);
        let _ = clock.now().expect("HLC timestamp");
        let c1 = clock.current();
        let c2 = clock.current();
        assert_eq!(c1, c2);
    }

    #[test]
    fn debug_format() {
        let (clock, _wall) = test_clock(42);
        let dbg = format!("{clock:?}");
        assert!(dbg.contains("HybridClock"));
    }

    #[test]
    fn default_clock() {
        let mut clock = HybridClock::default();
        let t = clock.now().expect("HLC timestamp");
        assert_eq!(t, Timestamp::new(DEFAULT_DETERMINISTIC_PHYSICAL_MS, 0));
    }

    #[test]
    fn default_clock_advances_physical_time_deterministically() {
        let mut clock = HybridClock::default();

        let first = clock.now().expect("first HLC timestamp");
        let second = clock.now().expect("second HLC timestamp");
        let third = clock.now().expect("third HLC timestamp");

        assert_eq!(first, Timestamp::new(DEFAULT_DETERMINISTIC_PHYSICAL_MS, 0));
        assert_eq!(
            second,
            Timestamp::new(DEFAULT_DETERMINISTIC_PHYSICAL_MS + 1, 0)
        );
        assert_eq!(
            third,
            Timestamp::new(DEFAULT_DETERMINISTIC_PHYSICAL_MS + 2, 0)
        );
    }

    #[test]
    fn production_hlc_source_does_not_read_host_wall_clock() {
        let production = include_str!("hlc.rs")
            .split("// ===========================================================================")
            .next()
            .expect("production section");
        let system_time_now = format!("{}{}", "SystemTime::", "now()");
        let date_now = format!("{}{}", "Date::", "now()");

        assert!(
            !production.contains(&system_time_now),
            "production HLC must not read host SystemTime; callers must use deterministic HLC sources"
        );
        assert!(
            !production.contains(&date_now),
            "production HLC must not read browser Date.now; callers must use deterministic HLC sources"
        );
        assert!(
            !production.contains("std::time"),
            "production HLC must not import host wall-clock APIs"
        );
        assert!(
            !production.contains("js_sys::Date"),
            "production HLC must not import browser wall-clock APIs"
        );
    }

    #[test]
    fn concurrent_updates_maintain_monotonicity() {
        let (mut clock, wall) = test_clock(100);
        let _ = clock.now().expect("HLC timestamp");

        // Simulate multiple rapid remote updates
        let remotes = [
            Timestamp::new(100, 3),
            Timestamp::new(100, 1),
            Timestamp::new(100, 7),
            Timestamp::new(100, 2),
        ];

        let mut last = clock.current();
        for r in &remotes {
            let ts = clock.update(r).expect("ok");
            assert!(ts > last, "monotonicity violated: {ts:?} <= {last:?}");
            last = ts;
        }

        // Then advance wall clock
        wall.store(200, Ordering::Relaxed);
        let ts = clock.now().expect("HLC timestamp");
        assert!(ts > last);
        assert_eq!(ts.physical_ms, 200);
        assert_eq!(ts.logical, 0);
    }

    #[test]
    fn now_remains_monotonic_when_logical_counter_is_exhausted() {
        let (mut clock, _wall) = test_clock(1000);
        clock.physical = 1000;
        clock.logical = u32::MAX;

        let ts = clock.now().expect("HLC timestamp");

        assert!(ts > Timestamp::new(1000, u32::MAX));
        assert_eq!(ts.physical_ms, 1001);
        assert_eq!(ts.logical, 0);
    }

    #[test]
    fn update_remains_monotonic_when_logical_counter_is_exhausted() {
        let (mut clock, _wall) = test_clock(1000);
        clock.physical = 1000;
        clock.logical = u32::MAX;

        let ts = clock.update(&Timestamp::new(1000, u32::MAX)).expect("ok");

        assert!(ts > Timestamp::new(1000, u32::MAX));
        assert_eq!(ts.physical_ms, 1001);
        assert_eq!(ts.logical, 0);
    }

    #[test]
    fn now_rejects_terminal_clock_exhaustion_without_reusing_timestamp() {
        let (mut clock, _wall) = test_clock(u64::MAX);
        clock.physical = u64::MAX;
        clock.logical = u32::MAX;

        let err = clock
            .now()
            .expect_err("terminal HLC state must fail closed");

        assert!(matches!(
            err,
            ExoError::ClockOverflow {
                physical_ms: u64::MAX,
                logical: u32::MAX
            }
        ));
        assert_eq!(clock.current(), Timestamp::new(u64::MAX, u32::MAX));
    }

    #[test]
    fn update_rejects_terminal_clock_exhaustion_without_reusing_timestamp() {
        let (mut clock, _wall) = test_clock(u64::MAX);
        clock.physical = u64::MAX;
        clock.logical = u32::MAX;

        let err = clock
            .update(&Timestamp::new(u64::MAX, u32::MAX))
            .expect_err("terminal HLC update must fail closed");

        assert!(matches!(
            err,
            ExoError::ClockOverflow {
                physical_ms: u64::MAX,
                logical: u32::MAX
            }
        ));
        assert_eq!(clock.current(), Timestamp::new(u64::MAX, u32::MAX));
    }

    #[test]
    fn now_propagates_wall_clock_error_without_mutating_state() {
        let mut clock = HybridClock::with_fallible_wall_clock(|| {
            Err(ExoError::ClockUnavailable {
                reason: "injected wall-clock failure".into(),
            })
        });

        let err = clock
            .now()
            .expect_err("wall-clock failures must fail closed");

        assert!(matches!(err, ExoError::ClockUnavailable { .. }));
        assert_eq!(clock.current(), Timestamp::new(0, 0));
    }

    #[test]
    fn update_propagates_wall_clock_error_without_mutating_state() {
        let calls = Arc::new(AtomicU64::new(0));
        let calls_for_clock = Arc::clone(&calls);
        let mut clock = HybridClock::with_fallible_wall_clock(move || {
            if calls_for_clock.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(1000)
            } else {
                Err(ExoError::ClockUnavailable {
                    reason: "injected wall-clock failure".into(),
                })
            }
        });
        let first = clock.now().expect("first timestamp");

        let err = clock
            .update(&Timestamp::new(1000, 0))
            .expect_err("wall-clock failures must fail closed");

        assert!(matches!(err, ExoError::ClockUnavailable { .. }));
        assert_eq!(clock.current(), first);
    }

    #[test]
    fn default_source_has_no_epoch_zero_fallback() {
        let production = include_str!("hlc.rs")
            .split("// ===========================================================================")
            .next()
            .expect("production section");

        assert!(
            !production.contains(".unwrap_or(0)"),
            "HLC wall-clock failures must propagate instead of silently using epoch zero"
        );
    }
}
