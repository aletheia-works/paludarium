//! Bounded immutable translations keyed by address space, RIP and MMU epoch.
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

struct Entry<T> {
    generation: u64,
    end: u64,
    translation: T,
    access: u64,
}

struct State<T> {
    entries: BTreeMap<(u64, u64), Entry<T>>,
    accesses: BTreeMap<u64, (u64, u64)>,
    clock: u64,
}
impl<T> State<T> {
    fn tick(&mut self) -> u64 {
        if self.clock == u64::MAX {
            // Evicting all entries on counter exhaustion is a safe fallback.
            self.entries.clear();
            self.accesses.clear();
            self.clock = 0;
        }
        self.clock += 1;
        self.clock
    }
    fn remove(&mut self, key: &(u64, u64)) {
        if let Some(entry) = self.entries.remove(key) {
            self.accesses.remove(&entry.access);
        }
    }
}

pub(crate) struct EpochCache<T> {
    state: Mutex<State<T>>,
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
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.entries.get(&(space, rip)) {
            None => Peek::Missing,
            Some(entry) if entry.generation != generation => Peek::Stale,
            Some(entry) => Peek::Present(entry.translation.clone()),
        }
    }
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                accesses: BTreeMap::new(),
                clock: 0,
            }),
        }
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
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (space, rip);
        if state.entries.get(&key)?.generation != generation {
            #[cfg(feature = "cost-profile")]
            paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::EpochInvalidations, 1);
            state.remove(&key);
            return None;
        }
        #[cfg(feature = "cost-profile")]
        paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::CacheHits, 1);
        let entry = state.entries.get(&key)?;
        if !touch(&entry.translation) {
            return Some(entry.translation.clone());
        }
        let access = state.tick();
        #[cfg(feature = "cost-profile")]
        {
            use paludarium_cpu::jit_cost::{Counter, add};
            add(Counter::LruUpdates, 1);
        }
        let entry = state.entries.get_mut(&key)?;
        let old_access = entry.access;
        entry.access = access;
        let translation = entry.translation.clone();
        state.accesses.remove(&old_access);
        state.accesses.insert(access, key);
        Some(translation)
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
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let access = state.tick();
        #[cfg(feature = "cost-profile")]
        paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::LruUpdates, 1);
        let key = (space, rip);
        state.remove(&key);
        if state.entries.len() >= 1024
            && let Some((_, oldest)) = state.accesses.first_key_value()
        {
            let oldest = *oldest;
            state.remove(&oldest);
        }
        state.entries.insert(
            key,
            Entry {
                generation,
                end,
                translation,
                access,
            },
        );
        state.accesses.insert(access, key);
        true
    }

    pub(crate) fn invalidate(&self, address: u64) {
        let page = address & !4095;
        let end = page.checked_add(4096);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let removed = state
            .entries
            .iter()
            .filter_map(|(&key @ (_, start), entry)| {
                (!(entry.end <= page || end.is_some_and(|end| start >= end))).then_some(key)
            })
            .collect::<Vec<_>>();
        for key in removed {
            state.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cost-profile")]
    fn snapshot(cache: &EpochCache<Option<u64>>) -> String {
        let state = cache.state.lock().unwrap();
        format!(
            "{:?}/{:?}/{}",
            state
                .entries
                .iter()
                .map(|(k, e)| (*k, e.generation, e.end, e.translation, e.access))
                .collect::<Vec<_>>(),
            state.accesses,
            state.clock
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
        cache.state.lock().unwrap().clock = u64::MAX;
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
        let clock = cache.state.lock().unwrap().clock;
        for _ in 0..100 {
            assert_eq!(cache.get_selected(1, 4096, 1, Option::is_some), Some(None));
        }
        assert_eq!(cache.state.lock().unwrap().clock, clock);
        assert_eq!(cache.state.lock().unwrap().accesses.len(), 1);
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
        assert!(cache.state.lock().unwrap().accesses.is_empty());
        cache.insert(1, 4096, 2, 1, 43);
        cache.invalidate(4096);
        assert!(cache.state.lock().unwrap().accesses.is_empty());
    }

    #[test]
    fn cache_lru_recency_exhaustion_discards_safely() {
        let cache = EpochCache::new();
        cache.insert(1, 4096, 1, 1, 42);
        cache.state.lock().unwrap().clock = u64::MAX;
        assert_eq!(cache.get(1, 4096, 1), None);
        assert!(cache.state.lock().unwrap().accesses.is_empty());
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
}
