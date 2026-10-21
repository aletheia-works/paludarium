//! Feature-only no-touch classification of already-decoded boundaries.
//! The bounded retained set is not a claim about global top-frequency sites.
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

pub const CAPACITY: usize = 16_384;
pub const LABEL_BYTES: usize = 256;
type Key = (u64, u64, u64, u64);

struct Site {
    key: Key,
    count: u64,
    label: Vec<u8>,
    truncated: bool,
}

pub(crate) struct Sites {
    index: BTreeMap<Key, usize>,
    rows: Vec<Site>,
}

impl Sites {
    pub const fn new() -> Self {
        Self {
            index: BTreeMap::new(),
            rows: Vec::new(),
        }
    }

    /// False means the event was dropped (capacity or count overflow).
    pub fn observe(&mut self, key: Key, label: impl FnOnce() -> String) -> bool {
        if let Some(&index) = self.index.get(&key) {
            let Some(count) = self.rows[index].count.checked_add(1) else {
                return false;
            };
            self.rows[index].count = count;
            return true;
        }
        if self.rows.len() == CAPACITY {
            return false;
        }
        let label = label().into_bytes();
        let truncated = label.len() > LABEL_BYTES;
        let row = Site {
            key,
            count: 1,
            label: label.into_iter().take(LABEL_BYTES).collect(),
            truncated,
        };
        self.index.insert(key, self.rows.len());
        self.rows.push(row);
        true
    }

    pub fn field(&self, index: usize, field: usize) -> Option<u64> {
        let row = self.rows.get(index)?;
        Some(match field {
            0 => row.key.0,
            1 => row.key.1,
            2 => row.key.2,
            3 => row.key.3,
            4 => row.count,
            5 => row.label.len() as u64,
            6 => u64::from(row.truncated),
            7.. => u64::from(*row.label.get(field - 7)?),
        })
    }
}

static SITES: Mutex<Sites> = Mutex::new(Sites::new());

pub fn observe(
    space: u64,
    epoch: u64,
    rip: u64,
    class: u64,
    instruction: &paludarium_decoder::Instruction,
) {
    if !super::jit_cost::measurement_enabled() {
        return;
    }
    let kept = SITES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .observe((space, epoch, rip, class), || format!("{instruction:?}"));
    super::jit_cost::add(super::jit_cost::Counter::SiteObserved, 1);
    if !kept {
        super::jit_cost::add(super::jit_cost::Counter::SiteDropped, 1);
    }
}

pub fn count() -> usize {
    SITES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .rows
        .len()
}

pub fn field(index: usize, field: usize) -> Option<u64> {
    SITES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .field(index, field)
}

pub fn reset() {
    *SITES.lock().unwrap_or_else(PoisonError::into_inner) = Sites::new();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn sites_same_key_counts_without_formatting_again() {
        let mut s = Sites::new();
        assert!(s.observe((1, 2, 3, 4), || "x".into()));
        assert!(s.observe((1, 2, 3, 4), || panic!("must not reformat")));
        assert_eq!(s.field(0, 4), Some(2));
        assert_eq!(s.rows.len(), 1);
    }
    #[test]
    fn sites_space_is_separate() {
        let mut s = Sites::new();
        s.observe((1, 2, 3, 4), String::new);
        s.observe((2, 2, 3, 4), String::new);
        assert_eq!(s.rows.len(), 2);
    }
    #[test]
    fn sites_epoch_is_separate() {
        let mut s = Sites::new();
        s.observe((1, 2, 3, 4), String::new);
        s.observe((1, 3, 3, 4), String::new);
        assert_eq!(s.rows.len(), 2);
    }
    #[test]
    fn sites_class_is_separate() {
        let mut s = Sites::new();
        s.observe((1, 2, 3, 4), String::new);
        s.observe((1, 2, 3, 5), String::new);
        assert_eq!(s.rows.len(), 2);
    }
    #[test]
    fn sites_capacity_drop_never_replaces_retained_entry() {
        let mut s = Sites::new();
        for i in 0..CAPACITY {
            assert!(s.observe((0, 0, i as u64, 0), String::new));
        }
        assert!(!s.observe((1, 0, 0, 0), || panic!("no allocation after full")));
        assert!(s.observe((0, 0, 0, 0), String::new));
        assert_eq!(s.field(0, 4), Some(2));
        assert_eq!(s.rows.len(), CAPACITY);
    }
    #[test]
    fn sites_counter_never_wraps() {
        let mut s = Sites::new();
        s.observe((0, 0, 0, 0), String::new);
        s.rows[0].count = u64::MAX;
        assert!(!s.observe((0, 0, 0, 0), String::new));
        assert_eq!(s.field(0, 4), Some(u64::MAX));
    }
    #[test]
    fn sites_label_is_bounded_and_truncation_explicit() {
        let mut s = Sites::new();
        s.observe((0, 0, 0, 0), || "x".repeat(300));
        assert_eq!(s.field(0, 5), Some(256));
        assert_eq!(s.field(0, 6), Some(1));
    }
    #[test]
    fn sites_invalid_reads_do_not_insert() {
        let s = Sites::new();
        assert_eq!(s.field(0, 0), None);
        assert!(s.rows.is_empty());
    }
}
