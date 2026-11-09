//! How a [`DecodeCache`] grows.
use super::*;

/// Two addresses in the same slot at every size up to [`MAX_ENTRIES`].
const FIRST: u64 = 0;
const SECOND: u64 = 1 << 40;

fn nop(rip: u64) -> Instruction {
    paludarium_decoder::decode(&[0x90], GuestAddr(rip)).unwrap()
}

/// A window of decodes that each find the other address in their slot.
fn collide(cache: &mut DecodeCache) {
    for i in 0..=GROWTH_WINDOW {
        let rip = if i % 2 == 0 { FIRST } else { SECOND };
        cache.put(rip, 1, nop(rip));
    }
}

#[test]
fn the_addresses_share_a_slot_at_every_size() {
    let mut mask = INITIAL_ENTRIES as u64 - 1;
    while mask < MAX_ENTRIES as u64 {
        assert_eq!(
            DecodeCache::slot_in(mask, FIRST),
            DecodeCache::slot_in(mask, SECOND)
        );
        mask = mask * 2 + 1;
    }
}

#[test]
fn frequent_collisions_double_the_cache_and_keep_its_entries() {
    if MAX_ENTRIES == INITIAL_ENTRIES {
        return;
    }
    let mut cache = DecodeCache::new();
    let other = 4096;
    cache.put(other, 1, nop(other));
    cache.lookup();
    collide(&mut cache);
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES);
    cache.lookup();
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES * 2);
    assert_eq!(cache.mask, INITIAL_ENTRIES as u64 * 2 - 1);
    let found = |rip| cache.get_with_hint(rip, 1).map(|(d, _)| d.instruction);
    assert_eq!(found(other), Some(nop(other)));
    assert_eq!(found(FIRST), Some(nop(FIRST)));
}

#[test]
fn rare_collisions_leave_the_cache_as_it_is() {
    let mut cache = DecodeCache::new();
    for i in 0..=GROWTH_WINDOW {
        for _ in 0..GROWTH_RATIO {
            cache.lookup();
        }
        let rip = if i % 2 == 0 { FIRST } else { SECOND };
        cache.put(rip, 1, nop(rip));
    }
    cache.lookup();
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES);
}

#[test]
fn decodes_after_a_code_change_do_not_count() {
    let mut cache = DecodeCache::new();
    cache.lookup();
    for generation in 0..=GROWTH_WINDOW {
        cache.put(FIRST, generation, nop(FIRST));
    }
    cache.lookup();
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES);
}

#[test]
fn other_addresses_left_from_before_a_code_change_do_not_count() {
    let mut cache = DecodeCache::new();
    cache.lookup();
    // Each decode finds the other address in its slot, decoded under the
    // generation before.
    for generation in 0..=GROWTH_WINDOW {
        let rip = if generation % 2 == 0 { FIRST } else { SECOND };
        cache.put(rip, generation, nop(rip));
    }
    cache.lookup();
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES);
    let mut cache = DecodeCache::new();
    for generation in 0..=GROWTH_WINDOW + 1 {
        let rip = if generation % 2 == 0 { FIRST } else { SECOND };
        assert!(cache.decoded(rip, generation, || Ok(nop(rip))).is_ok());
    }
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES);
}

#[test]
fn the_cache_grows_no_further_than_its_limit() {
    let mut cache = DecodeCache::new();
    while cache.entries.len() < MAX_ENTRIES {
        cache.lookup();
        collide(&mut cache);
        cache.lookup();
    }
    assert_eq!(cache.entries.len(), MAX_ENTRIES);
    collide(&mut cache);
    cache.lookup();
    assert_eq!(cache.entries.len(), MAX_ENTRIES);
}

#[test]
fn the_interpreter_grows_the_cache_it_misses() {
    if MAX_ENTRIES == INITIAL_ENTRIES {
        return;
    }
    let mut cache = DecodeCache::new();
    let decodes = std::cell::Cell::new(0);
    // Each decode finds the other address in its slot.
    for i in 0..=GROWTH_WINDOW + 1 {
        let rip = if i % 2 == 0 { FIRST } else { SECOND };
        let decoded = cache.decoded(rip, 1, || {
            decodes.set(decodes.get() + 1);
            Ok(nop(rip))
        });
        assert_eq!(decoded.map(|d| d.instruction), Ok(nop(rip)));
    }
    assert_eq!(decodes.get(), GROWTH_WINDOW + 2);
    assert_eq!(cache.entries.len(), INITIAL_ENTRIES * 2);
}
