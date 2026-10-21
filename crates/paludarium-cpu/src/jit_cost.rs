//! Diagnostic-only aggregate for one fresh shared heap and its guest Workers.
//! No clocks or timers occur in these high-frequency paths. Overflow is sticky
//! and makes the diagnostic report invalid rather than wrapping a counter.
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

thread_local! {
    static MEASUREMENT_ENABLED: Cell<bool> = const { Cell::new(true) };
}

/// Diagnostic measurement scope only; each actual Worker owns its setting.
pub fn measurement_enabled() -> bool {
    MEASUREMENT_ENABLED.with(Cell::get)
}
pub fn set_measurement_enabled(enabled: bool) -> bool {
    MEASUREMENT_ENABLED.with(|setting| setting.replace(enabled))
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Counter {
    HookAttempts,
    Checkpoints,
    CacheHits,
    NegativeHits,
    CacheMisses,
    EpochInvalidations,
    LruUpdates,
    SnapshotBytes,
    TranslatedBlocks,
    ExecutedBlocks,
    ExecutedInstructions,
    Fallbacks,
    PrepareCalls,
    ExecuteCalls,
    CompileCount,
    CompileNanoseconds,
    JsTransitions,
    CodeBytesCompared,
    CodeBytesCopied,
    StateBytesCopied,
    PrepareRejections,
    ExecuteRejections,
    InterpreterSteps,
    BudgetCharged,
    ObservationLookups = 88,
    ObservationBytes,
    NextPositive,
    NextPrepared,
    NextMissing,
    NextNegative,
    NextEpoch,
    NextUnprepared,
    NextUnavailable,
    ChainLength1,
    ChainLength2,
    ChainLength3,
    ChainLength4to7,
    ChainLength8plus,
    StopUnsupported,
    StopNegative,
    StopFallback,
    StopEpoch,
    StopBudget,
    StopExit,
    StopKill,
    SiteObserved,
    SiteDropped,
    DecodeHintHit,
    DecodeSlotEmpty,
    DecodeSlotRipCollision,
    DecodeSlotEpochStale,
    DecodedHit,
    ColdSnapshots,
    ColdExtracts,
    ColdEmits,
    WarmExecutions,
}

pub const BASE_FIELDS: usize = 24;
pub const FIELD_COUNT: usize = Counter::WarmExecutions as usize + 1;
pub use crate::jit_cost_sites::{
    count as site_count, field as site_field, observe as observe_site,
};

/// Tracks only actually executed consecutive blocks within one CPU budget.
/// The counter sink is injected so parallel tests never reset global state.
#[derive(Default)]
pub struct Chain {
    length: u64,
    epoch: Option<u64>,
}
impl Chain {
    pub fn success(&mut self, epoch: u64, mut count: impl FnMut(Counter, u64)) {
        if self.epoch.is_some_and(|old| old != epoch) {
            self.stop(Counter::StopEpoch, &mut count);
        }
        self.epoch = Some(epoch);
        self.length = self.length.saturating_add(1);
    }
    pub fn stop(&mut self, reason: Counter, mut count: impl FnMut(Counter, u64)) {
        count(reason, 1);
        let field = match self.length {
            0 => return,
            1 => Counter::ChainLength1,
            2 => Counter::ChainLength2,
            3 => Counter::ChainLength3,
            4..=7 => Counter::ChainLength4to7,
            _ => Counter::ChainLength8plus,
        };
        count(field, 1);
        self.length = 0;
        self.epoch = None;
    }
}

struct Collector {
    values: [AtomicU64; FIELD_COUNT],
    overflow: AtomicBool,
}

impl Collector {
    const fn new() -> Self {
        Self {
            values: [const { AtomicU64::new(0) }; FIELD_COUNT],
            overflow: AtomicBool::new(false),
        }
    }

    fn add(&self, field: usize, value: u64) -> bool {
        let Some(counter) = self.values.get(field) else {
            return false;
        };
        if counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(value)
            })
            .is_err()
        {
            self.overflow.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn get(&self, field: usize) -> Option<u64> {
        self.values.get(field).map(|v| v.load(Ordering::Relaxed))
    }

    fn reset(&self) {
        for value in &self.values {
            value.store(0, Ordering::Relaxed);
        }
        self.overflow.store(false, Ordering::Relaxed);
    }

    fn block_length(&self, length: usize) -> bool {
        if (1..=64).contains(&length) {
            self.add(BASE_FIELDS + length - 1, 1)
        } else {
            self.overflow.store(true, Ordering::Relaxed);
            false
        }
    }
}

static COST: Collector = Collector::new();

pub fn add(counter: Counter, value: u64) {
    if !measurement_enabled() {
        return;
    }
    let _ = COST.add(counter as usize, value);
}

/// Called only by the trusted diagnostic JS import, never by guest code.
pub fn add_field(field: usize, value: u64) -> bool {
    if !measurement_enabled() {
        return field < FIELD_COUNT;
    }
    COST.add(field, value)
}

#[must_use]
pub fn get(field: usize) -> Option<u64> {
    COST.get(field)
}

#[must_use]
pub fn overflowed() -> bool {
    COST.overflow.load(Ordering::Relaxed)
}

/// Only the coordinator calls this, before spawning any guest Worker.
pub fn reset() {
    COST.reset();
    crate::jit_cost_sites::reset();
}

pub fn block_length(length: usize) {
    if !measurement_enabled() {
        return;
    }
    let _ = COST.block_length(length);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn measurement_scope_is_thread_local_and_restores() {
        assert!(measurement_enabled());
        assert!(set_measurement_enabled(false));
        assert!(!measurement_enabled());
        assert!(std::thread::spawn(measurement_enabled).join().unwrap());
        assert!(!set_measurement_enabled(true));
        assert!(measurement_enabled());
    }
    #[test]
    fn disabled_measurement_preserves_field_validation() {
        let previous = set_measurement_enabled(false);
        assert!(!add_field(FIELD_COUNT, 1));
        assert!(add_field(0, u64::MAX));
        assert!(!set_measurement_enabled(previous));
    }

    fn observe(length: u64, reason: Counter) -> Collector {
        let c = Collector::new();
        let mut chain = Chain::default();
        for _ in 0..length {
            chain.success(1, |field, value| {
                c.add(field as usize, value);
            });
        }
        chain.stop(reason, |field, value| {
            c.add(field as usize, value);
        });
        c
    }
    #[test]
    fn u14_chain_empty_stop_has_no_invented_block() {
        let c = observe(0, Counter::StopFallback);
        assert_eq!(c.get(Counter::StopFallback as usize), Some(1));
        assert_eq!(c.get(Counter::ChainLength1 as usize), Some(0));
    }
    #[test]
    fn u14_chain_one_block_unsupported_stop() {
        let c = observe(1, Counter::StopUnsupported);
        assert_eq!(c.get(Counter::ChainLength1 as usize), Some(1));
        assert_eq!(c.get(Counter::StopUnsupported as usize), Some(1));
    }
    #[test]
    fn u14_chain_exact_two_and_three() {
        for (length, field) in [(2, Counter::ChainLength2), (3, Counter::ChainLength3)] {
            assert_eq!(
                observe(length, Counter::StopNegative).get(field as usize),
                Some(1)
            );
        }
    }
    #[test]
    fn u14_chain_bounded_histogram_four_to_seven() {
        for length in 4..=7 {
            assert_eq!(
                observe(length, Counter::StopBudget).get(Counter::ChainLength4to7 as usize),
                Some(1)
            );
        }
    }
    #[test]
    fn u14_chain_long_run_aggregates_without_executing_extra_blocks() {
        assert_eq!(
            observe(1000, Counter::StopBudget).get(Counter::ChainLength8plus as usize),
            Some(1)
        );
    }
    #[test]
    fn u14_chain_epoch_change_flushes_previous_chain() {
        let c = Collector::new();
        let mut chain = Chain::default();
        chain.success(1, |f, v| {
            c.add(f as usize, v);
        });
        chain.success(2, |f, v| {
            c.add(f as usize, v);
        });
        chain.stop(Counter::StopExit, |f, v| {
            c.add(f as usize, v);
        });
        assert_eq!(c.get(Counter::ChainLength1 as usize), Some(2));
        assert_eq!(c.get(Counter::StopEpoch as usize), Some(1));
    }
    #[test]
    fn u14_chain_interpreter_break_cannot_join_later_blocks() {
        let c = Collector::new();
        let mut chain = Chain::default();
        for _ in 0..2 {
            chain.success(1, |f, v| {
                c.add(f as usize, v);
            });
            chain.stop(Counter::StopFallback, |f, v| {
                c.add(f as usize, v);
            });
        }
        assert_eq!(c.get(Counter::ChainLength1 as usize), Some(2));
        assert_eq!(c.get(Counter::ChainLength2 as usize), Some(0));
    }
    #[test]
    fn u14_chain_exit_flush_is_not_duplicated() {
        let c = Collector::new();
        let mut chain = Chain::default();
        chain.success(1, |f, v| {
            c.add(f as usize, v);
        });
        chain.stop(Counter::StopExit, |f, v| {
            c.add(f as usize, v);
        });
        chain.stop(Counter::StopKill, |f, v| {
            c.add(f as usize, v);
        });
        assert_eq!(c.get(Counter::ChainLength1 as usize), Some(1));
        assert_eq!(c.get(Counter::StopKill as usize), Some(1));
    }

    #[test]
    fn cost_fresh_collector_has_complete_zero_population() {
        let c = Collector::new();
        assert_eq!(Counter::BudgetCharged as usize + 1, BASE_FIELDS);
        assert_eq!(FIELD_COUNT, 120);
        assert!((0..FIELD_COUNT).all(|field| c.get(field) == Some(0)));
        assert!(!c.overflow.load(Ordering::Relaxed));
    }

    #[test]
    fn cost_accumulates_exact_values() {
        let c = Collector::new();
        assert!(c.add(Counter::CacheMisses as usize, 4));
        assert!(c.add(Counter::CacheMisses as usize, 7));
        assert_eq!(c.get(Counter::CacheMisses as usize), Some(11));
    }

    #[test]
    fn cost_invalid_field_is_rejected_without_mutation() {
        let c = Collector::new();
        assert!(!c.add(FIELD_COUNT, 1));
        assert_eq!(c.get(FIELD_COUNT), None);
        assert_eq!(c.get(0), Some(0));
    }

    #[test]
    fn cost_overflow_never_wraps_and_is_sticky() {
        let c = Collector::new();
        assert!(c.add(0, u64::MAX));
        assert!(!c.add(0, 1));
        assert_eq!(c.get(0), Some(u64::MAX));
        assert!(c.overflow.load(Ordering::Relaxed));
        assert!(c.add(1, 1));
        assert!(c.overflow.load(Ordering::Relaxed));
    }

    #[test]
    fn cost_exclusive_reset_clears_values_and_overflow() {
        let c = Collector::new();
        c.add(0, u64::MAX);
        c.add(0, 1);
        c.reset();
        assert_eq!(c.get(0), Some(0));
        assert!(!c.overflow.load(Ordering::Relaxed));
    }

    #[test]
    fn cost_block_histogram_separates_one_two_and_sixty_four() {
        let c = Collector::new();
        for length in [1, 2, 2, 64] {
            assert!(c.block_length(length));
        }
        assert_eq!(c.get(BASE_FIELDS), Some(1));
        assert_eq!(c.get(BASE_FIELDS + 1), Some(2));
        assert_eq!(c.get(BASE_FIELDS + 63), Some(1));
    }

    #[test]
    fn cost_invalid_block_lengths_fail_closed() {
        for length in [0, 65, usize::MAX] {
            let c = Collector::new();
            assert!(!c.block_length(length));
            assert!(c.overflow.load(Ordering::Relaxed));
            assert_eq!(c.get(BASE_FIELDS), Some(0));
        }
    }

    #[test]
    fn cost_shared_workers_accumulate_without_lost_updates() {
        let c = std::sync::Arc::new(Collector::new());
        let workers = (0..4)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        assert!(c.add(0, 1));
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(c.get(0), Some(4000));
    }
}
