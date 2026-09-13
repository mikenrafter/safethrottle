//! Fixed-cycle limiter: never drops, only delays.
//!
//! Semantics (per family, 60s cycles):
//! - **Free band:** `count < soft_start` (default 70% of limit) — grant immediately.
//! - **Soft band:** `soft_start <= count < limit` —
//!   wait `(seconds_left_in_cycle / slots_left) * soft_pace`, then grant.
//! - **Overflow:** `count >= limit` — wait `seconds_left_in_cycle` (no soft_pace),
//!   roll into the next cycle, then grant.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep_until, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitPhase {
    Free,
    Soft,
    OverflowRollover,
}

#[derive(Debug, Clone)]
pub struct AdmitOutcome {
    pub phase: AdmitPhase,
    pub limit: usize,
    /// Active grants in this cycle after this admission.
    pub grants_active: usize,
    pub delay: Duration,
    /// Seconds left in the cycle when the wait was computed.
    pub window_remaining: Duration,
}

#[derive(Debug)]
enum AdmitAction {
    Grant(AdmitOutcome),
    Wait {
        deadline: Instant,
        phase: AdmitPhase,
        delay: Duration,
        window_remaining: Duration,
        rollover: bool,
    },
}

#[derive(Debug)]
struct Inner {
    limit: usize,
    soft_start: usize,
    soft_pace: f64,
    window: Duration,
    cycle_start: Instant,
    count: usize,
}

#[derive(Debug, Clone)]
pub struct SoftLimiter {
    inner: Arc<Mutex<Inner>>,
    notify: Arc<Notify>,
}

impl SoftLimiter {
    pub fn new(limit: u32, soft_ratio: f64, soft_pace: f64, window: Duration) -> Self {
        let limit = limit.max(1) as usize;
        let soft_start = ((limit as f64) * soft_ratio).floor() as usize;
        let soft_start = if limit == 1 {
            0
        } else {
            soft_start.clamp(1, limit - 1)
        };
        Self {
            inner: Arc::new(Mutex::new(Inner {
                limit,
                soft_start,
                soft_pace: soft_pace.clamp(0.01, 1.0),
                window,
                cycle_start: Instant::now(),
                count: 0,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    pub async fn admit(&self) -> AdmitOutcome {
        loop {
            let action = {
                let mut guard = self.inner.lock().await;
                let now = Instant::now();
                Self::advance_cycles(&mut guard, now);

                let count = guard.count;
                let limit = guard.limit;
                let cycle_end = guard.cycle_start + guard.window;
                let window_remaining = cycle_end.saturating_duration_since(now);

                if count < guard.soft_start {
                    guard.count += 1;
                    self.notify.notify_waiters();
                    AdmitAction::Grant(AdmitOutcome {
                        phase: AdmitPhase::Free,
                        limit,
                        grants_active: guard.count,
                        delay: Duration::ZERO,
                        window_remaining,
                    })
                } else if count < limit {
                    let slots_left = (limit - count).max(1);
                    let delay = Self::soft_delay(window_remaining, slots_left, guard.soft_pace);
                    AdmitAction::Wait {
                        deadline: now + delay,
                        phase: AdmitPhase::Soft,
                        delay,
                        window_remaining,
                        rollover: false,
                    }
                } else {
                    let delay = window_remaining.max(Duration::from_millis(1));
                    AdmitAction::Wait {
                        deadline: cycle_end,
                        phase: AdmitPhase::OverflowRollover,
                        delay,
                        window_remaining,
                        rollover: true,
                    }
                }
            };

            let AdmitAction::Wait {
                deadline,
                phase,
                delay,
                window_remaining,
                rollover,
            } = action
            else {
                return match action {
                    AdmitAction::Grant(out) => out,
                    AdmitAction::Wait { .. } => unreachable!(),
                };
            };

            tokio::select! {
                _ = sleep_until(deadline) => {}
                _ = self.notify.notified() => continue,
            }

            let mut guard = self.inner.lock().await;
            let now = Instant::now();
            Self::advance_cycles(&mut guard, now);

            if rollover {
                guard.count += 1;
                self.notify.notify_waiters();
                let cycle_end = guard.cycle_start + guard.window;
                return AdmitOutcome {
                    phase,
                    limit: guard.limit,
                    grants_active: guard.count,
                    delay,
                    window_remaining: cycle_end.saturating_duration_since(now),
                };
            }

            if guard.count >= guard.limit {
                self.notify.notify_waiters();
                continue;
            }

            guard.count += 1;
            self.notify.notify_waiters();
            let cycle_end = guard.cycle_start + guard.window;
            return AdmitOutcome {
                phase,
                limit: guard.limit,
                grants_active: guard.count,
                delay,
                window_remaining: cycle_end.saturating_duration_since(now),
            };
        }
    }

    pub async fn grants_in_cycle(&self) -> usize {
        let mut guard = self.inner.lock().await;
        Self::advance_cycles(&mut guard, Instant::now());
        guard.count
    }

    pub async fn limit(&self) -> usize {
        self.inner.lock().await.limit
    }

    #[cfg(test)]
    async fn set_count(&self, count: usize) {
        let mut guard = self.inner.lock().await;
        guard.count = count;
    }

    #[cfg(test)]
    async fn set_cycle_start(&self, start: Instant) {
        let mut guard = self.inner.lock().await;
        guard.cycle_start = start;
    }

    fn soft_delay(window_remaining: Duration, slots_left: usize, soft_pace: f64) -> Duration {
        let secs_left = window_remaining.as_secs_f64().max(0.001);
        let delay_secs = (secs_left / slots_left as f64) * soft_pace;
        Duration::from_secs_f64(delay_secs.max(0.001))
    }

    fn advance_cycles(inner: &mut Inner, now: Instant) {
        let window = inner.window;
        while now >= inner.cycle_start + window {
            inner.cycle_start += window;
            inner.count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{self, Instant as TokioInstant};

    #[tokio::test(start_paused = true)]
    async fn free_band_grants_immediately() {
        let lim = SoftLimiter::new(20, 0.7, 0.7, Duration::from_secs(60));
        for i in 1..=14 {
            let out = lim.admit().await;
            assert_eq!(out.phase, AdmitPhase::Free);
            assert_eq!(out.grants_active, i);
            assert_eq!(out.delay, Duration::ZERO);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn soft_band_uses_pace_formula() {
        let lim = SoftLimiter::new(20, 0.7, 0.7, Duration::from_secs(60));
        lim.set_count(14).await;
        let start = Instant::now();
        lim.set_cycle_start(start).await;
        time::advance(Duration::from_secs(30)).await;

        let out = lim.admit().await;
        assert_eq!(out.phase, AdmitPhase::Soft);
        assert!((out.delay.as_secs_f64() - 3.5).abs() < 0.01);
        assert_eq!(out.grants_active, 15);
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_waits_for_cycle_boundary() {
        let lim = SoftLimiter::new(20, 0.7, 0.7, Duration::from_secs(60));
        lim.set_count(20).await;
        let start = Instant::now();
        lim.set_cycle_start(start).await;
        time::advance(Duration::from_secs(36)).await;

        let t0 = TokioInstant::now();
        let admit = tokio::spawn({
            let lim = lim.clone();
            async move { lim.admit().await }
        });

        time::sleep(Duration::from_millis(1)).await;
        time::advance(Duration::from_secs(23)).await;
        time::sleep(Duration::from_millis(1)).await;
        assert!(!admit.is_finished());

        time::advance(Duration::from_secs(1)).await;
        time::sleep(Duration::from_millis(1)).await;
        let out = admit.await.expect("join");
        assert_eq!(out.phase, AdmitPhase::OverflowRollover);
        assert!(out.delay >= Duration::from_secs(24));
        assert_eq!(out.grants_active, 1);
        assert!(TokioInstant::now().duration_since(t0) >= Duration::from_secs(24));
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_resets_count() {
        let lim = SoftLimiter::new(5, 0.7, 0.7, Duration::from_secs(10));
        for _ in 0..5 {
            lim.admit().await;
        }
        assert_eq!(lim.grants_in_cycle().await, 5);
        time::advance(Duration::from_secs(10)).await;
        assert_eq!(lim.grants_in_cycle().await, 0);
        let out = lim.admit().await;
        assert_eq!(out.phase, AdmitPhase::Free);
        assert_eq!(out.grants_active, 1);
    }
}
