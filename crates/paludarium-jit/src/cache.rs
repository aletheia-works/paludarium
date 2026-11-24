//! Bounded immutable translations keyed by address space, RIP and MMU epoch.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};

struct Entry<T> {
    generation: u64,
    end: u64,
    translation: T,
    /// The clock at the entry's last use: the least recently used entry has
    /// the smallest. A hit raises it under the shared lock; an insertion
    /// into a full cache looks for the smallest under the exclusive one.
    access: AtomicU64,
}

/// Hits, which every guest thread's Worker makes on every block the JIT
/// runs, share the lock: they read the entries and raise one stamp. Only a
/// change to the entries (an insertion, an epoch's removal, invalidation or
/// the clock's exhaustion) takes it exclusively.
pub(crate) struct EpochCache<T> {
    entries: RwLock<BTreeMap<(u64, u64), Entry<T>>>,
    /// The last stamp handed out. Stamps are unique, so the eviction order
    /// is that of one lock taken for every use.
    clock: AtomicU64,
}

#[cfg(feature = "cost-profile")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Peek<T> {
    Missing,
    Stale,
    Present(T),
}

impl<T: Clone> EpochCache<T> {
    /// Diagnostic observation only: even stale entries retain their recency.
    #[cfg(feature = "cost-profile")]
    pub(crate) fn peek(&self, space: u64, rip: u64, generation: u64) -> Peek<T> {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        match entries.get(&(space, rip)) {
            None => Peek::Missing,
            Some(entry) if entry.generation != generation => Peek::Stale,
            Some(entry) => Peek::Present(entry.translation.clone()),
        }
    }
    pub(crate) fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            clock: AtomicU64::new(0),
        }
    }

    /// The next stamp, or `None` once the clock is exhausted.
    fn tick(&self) -> Option<u64> {
        self.clock
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |clock| {
                clock.checked_add(1)
            })
            .ok()
            .map(|clock| clock + 1)
    }

    /// The next stamp under the exclusive lock. Evicting all entries on
    /// counter exhaustion is a safe fallback.
    fn tick_exclusive(&self, entries: &mut BTreeMap<(u64, u64), Entry<T>>) -> u64 {
        self.tick().unwrap_or_else(|| {
            entries.clear();
            self.clock.store(1, Ordering::Relaxed);
            1
        })
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn get(&self, space: u64, rip: u64, generation: u64) -> Option<T> {
        self.get_selected(space, rip, generation, |_| true)
    }

    pub(crate) fn get_selected(
        &self,
        space: u64,
        rip: u64,
        generation: u64,
        touch: impl FnOnce(&T) -> bool,
    ) -> Option<T> {
        let key = (space, rip);
        {
            let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
            let entry = entries.get(&key)?;
            if entry.generation == generation {
                #[cfg(feature = "cost-profile")]
                paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::CacheHits, 1);
                if !touch(&entry.translation) {
                    return Some(entry.translation.clone());
                }
                if let Some(access) = self.tick() {
                    #[cfg(feature = "cost-profile")]
                    paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::LruUpdates, 1);
                    // The largest: a hit that took its stamp later may
                    // have stored it first.
                    entry.access.fetch_max(access, Ordering::Relaxed);
                    return Some(entry.translation.clone());
                }
            }
        }
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        match entries.get(&key) {
            Some(entry) if entry.generation != generation => {
                #[cfg(feature = "cost-profile")]
                paludarium_cpu::jit_cost::add(
                    paludarium_cpu::jit_cost::Counter::EpochInvalidations,
                    1,
                );
                entries.remove(&key);
            }
            // The clock ran out under the shared lock: as an insertion
            // would, evict everything and restart it.
            Some(_) if self.clock.load(Ordering::Relaxed) == u64::MAX => {
                entries.clear();
                self.clock.store(1, Ordering::Relaxed);
            }
            // Another Worker changed the entries in between: run interpreted.
            _ => {}
        }
        None
    }

    pub(crate) fn insert(
        &self,
        space: u64,
        rip: u64,
        generation: u64,
        length: usize,
        translation: T,
    ) -> bool {
        if length == 0 || length > 960 {
            return false;
        }
        let Some(end) = rip.checked_add(length as u64) else {
            return false;
        };
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let access = self.tick_exclusive(&mut entries);
        #[cfg(feature = "cost-profile")]
        paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::LruUpdates, 1);
        let key = (space, rip);
        entries.remove(&key);
        // A full cache looks for the oldest stamp among its 1024 entries,
        // under the exclusive lock: a miss pays it, and a miss also extracts,
        // emits and compiles a block, which costs far more than the scan.
        if entries.len() >= 1024
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.access.load(Ordering::Relaxed))
                .map(|(&key, _)| key)
        {
            entries.remove(&oldest);
        }
        entries.insert(
            key,
            Entry {
                generation,
                end,
                translation,
                access: AtomicU64::new(access),
            },
        );
        true
    }

    pub(crate) fn invalidate(&self, address: u64) {
        let page = address & !4095;
        let end = page.checked_add(4096);
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        entries
            .retain(|&(_, start), entry| entry.end <= page || end.is_some_and(|end| start >= end));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cost-profile")]
    fn snapshot(cache: &EpochCache<Option<u64>>) -> String {
        let entries = cache.entries.read().unwrap();
        format!(
            "{:?}/{}",
            entries
                .iter()
                .map(|(k, e)| {
                    let access = e.access.load(Ordering::Relaxed);
                    (*k, e.generation, e.end, e.translation, access)
                })
                .collect::<Vec<_>>(),
            cache.clock.load(Ordering::Relaxed)
        )
    }
    #[cfg(feature = "cost-profile")]
    fn unchanged(space: u64, rip: u64, generation: u64, expected: Peek<Option<u64>>) {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 2, 1, Some(42));
        cache.insert(1, 8192, 2, 1, None);
        let before = snapshot(&cache);
        for _ in 0..100 {
            assert_eq!(cache.peek(space, rip, generation), expected);
        }
        assert_eq!(snapshot(&cache), before);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_positive_does_not_touch_recency() {
        unchanged(1, 4096, 2, Peek::Present(Some(42)));
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_negative_does_not_touch_hint() {
        unchanged(1, 8192, 2, Peek::Present(None));
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_stale_does_not_delete_entry() {
        unchanged(1, 4096, 3, Peek::Stale);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_missing_does_not_insert_entry() {
        unchanged(1, 12288, 2, Peek::Missing);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_other_space_is_not_positive() {
        unchanged(2, 4096, 2, Peek::Missing);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_does_not_trigger_clock_exhaustion() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, Some(42));
        cache.clock.store(u64::MAX, Ordering::Relaxed);
        let before = snapshot(&cache);
        assert_eq!(cache.peek(1, 4096, 1), Peek::Present(Some(42)));
        assert_eq!(snapshot(&cache), before);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_does_not_change_eviction_order() {
        let cache = EpochCache::new();
        for rip in 0..1024 {
            cache.insert(1, rip, 1, 1, Some(rip));
        }
        assert_eq!(cache.peek(1, 0, 1), Peek::Present(Some(0)));
        cache.insert(1, 1024, 1, 1, Some(1024));
        assert_eq!(cache.peek(1, 0, 1), Peek::Missing);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn peek_invalidated_mapping_stays_missing() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, Some(42));
        cache.invalidate(4096);
        let before = snapshot(&cache);
        assert_eq!(cache.peek(1, 4096, 1), Peek::Missing);
        assert_eq!(snapshot(&cache), before);
    }

    #[test]
    fn negative_cache_hit_does_not_mutate_recency() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, None::<u64>);
        let clock = cache.clock.load(Ordering::Relaxed);
        for _ in 0..100 {
            assert_eq!(cache.get_selected(1, 4096, 1, Option::is_some), Some(None));
        }
        assert_eq!(cache.clock.load(Ordering::Relaxed), clock);
        assert_eq!(cache.entries.read().unwrap().len(), 1);
        assert_eq!(cache.get_selected(1, 4096, 2, Option::is_some), None);
    }

    #[test]
    fn cache_lru_preserves_hot_low_rip_and_evicts_oldest() {
        let cache = EpochCache::new();
        for rip in 0..1024 {
            cache.insert(1, rip * 4096, 1, 1, rip);
        }
        assert_eq!(cache.get(1, 0, 1), Some(0));
        cache.insert(1, 1024 * 4096, 1, 1, 1024);
        assert_eq!(cache.get(1, 0, 1), Some(0));
        assert_eq!(cache.get(1, 4096, 1), None);
        assert_eq!(cache.get(1, 1024 * 4096, 1), Some(1024));
    }

    #[test]
    fn cache_lru_epoch_removal_and_invalidation_remove_recency() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, 42);
        assert_eq!(cache.get(1, 4096, 2), None);
        assert!(cache.entries.read().unwrap().is_empty());
        cache.insert(1, 4096, 2, 1, 43);
        cache.invalidate(4096);
        assert!(cache.entries.read().unwrap().is_empty());
    }

    #[test]
    fn cache_lru_recency_exhaustion_discards_safely() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, 42);
        cache.clock.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(cache.get(1, 4096, 1), None);
        assert!(cache.entries.read().unwrap().is_empty());
        assert!(cache.insert(1, 8192, 1, 1, 43));
        assert_eq!(cache.get(1, 8192, 1), Some(43));
    }

    #[test]
    fn cache_returns_only_matching_epoch() {
        let cache = EpochCache::new();
        assert!(cache.insert(1, 4096, 2, 10, 42));
        assert_eq!(cache.get(1, 4096, 2), Some(42));
        assert_eq!(cache.get(1, 4096, 3), None);
        assert_eq!(cache.get(1, 4096, 2), None);
    }

    #[test]
    fn cache_separates_address_spaces() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 2, 10, 42);
        cache.insert(2, 4096, 2, 10, 17);
        assert_eq!(cache.get(1, 4096, 2), Some(42));
        assert_eq!(cache.get(2, 4096, 2), Some(17));
    }

    #[test]
    fn cache_cross_page_invalidation_covers_entire_block() {
        let cache = EpochCache::new();
        cache.insert(1, 8191, 2, 10, 42);
        cache.invalidate(8192);
        assert_eq!(cache.get(1, 8191, 2), None);
    }

    #[test]
    fn cache_unrelated_page_is_preserved() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 2, 10, 42);
        cache.invalidate(8192);
        assert_eq!(cache.get(1, 4096, 2), Some(42));
    }

    #[test]
    fn cache_rejects_overflow_and_unbounded_blocks() {
        let cache = EpochCache::new();
        assert!(!cache.insert(1, u64::MAX, 2, 1, 42));
        assert!(!cache.insert(1, 0, 2, 961, 42));
        assert!(!cache.insert(1, 0, 2, 0, 42));
    }

    #[test]
    fn cache_evicts_safely_at_capacity() {
        let cache = EpochCache::new();
        for index in 0..1025 {
            assert!(cache.insert(1, index, 2, 1, index));
        }
        assert_eq!(cache.get(1, 0, 2), None);
        assert_eq!(cache.get(1, 1024, 2), Some(1024));
    }

    #[test]
    fn cache_serializes_shared_worker_invalidation() {
        let cache = std::sync::Arc::new(EpochCache::new());
        cache.insert(1, 4096, 2, 10, 42);
        let other = cache.clone();
        std::thread::spawn(move || other.invalidate(4096))
            .join()
            .unwrap();
        assert_eq!(cache.get(1, 4096, 2), None);
    }

    /// The order of eviction is that of a plain least-recently-used list:
    /// a hit makes an entry the most recent, an insertion adds or replaces
    /// one as the most recent, and a full cache evicts the least recent.
    #[test]
    fn cache_eviction_order_is_least_recently_used() {
        let cache = EpochCache::new();
        // Most recent last.
        let mut model: Vec<u64> = Vec::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for step in 0..20_000_u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let rip = seed % 1536;
            if seed & 0x30000 == 0 {
                assert!(cache.insert(1, rip, 1, 1, rip));
                model.retain(|&other| other != rip);
                if model.len() >= 1024 {
                    model.remove(0);
                }
                model.push(rip);
            } else {
                let expected = model.contains(&rip).then_some(rip);
                assert_eq!(cache.get(1, rip, 1), expected, "step {step}");
                if expected.is_some() {
                    model.retain(|&other| other != rip);
                    model.push(rip);
                }
            }
        }
        let mut held = cache
            .entries
            .read()
            .unwrap()
            .keys()
            .map(|&(_, rip)| rip)
            .collect::<Vec<_>>();
        let mut expected = model.clone();
        held.sort_unstable();
        expected.sort_unstable();
        assert_eq!(held, expected);
        assert_eq!(model.len(), 1024);
    }

    /// Hits from many Workers at once keep every entry and raise each
    /// entry's stamp past the stamps of the insertions before them.
    #[test]
    fn cache_shared_hits_keep_entries_and_stamps() {
        let cache = std::sync::Arc::new(EpochCache::new());
        for rip in 0..64 {
            cache.insert(1, rip, 1, 1, rip);
        }
        let inserted = cache.clock.load(Ordering::Relaxed);
        let workers = (0..4)
            .map(|_| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    for round in 0..1000 {
                        for rip in 0..64 {
                            assert_eq!(cache.get(1, rip, 1), Some(rip), "round {round}");
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            cache.clock.load(Ordering::Relaxed),
            inserted + 4 * 1000 * 64
        );
        let entries = cache.entries.read().unwrap();
        assert_eq!(entries.len(), 64);
        assert!(
            entries
                .values()
                .all(|entry| entry.access.load(Ordering::Relaxed) > inserted)
        );
    }
}
