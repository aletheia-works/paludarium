//! How a [`DecodeCache`] keeps blocks and grows.
use super::*;

/// Two addresses in the same slot at every size up to [`MAX_ENTRIES`].
const FIRST: u64 = 0;
const SECOND: u64 = 1 << 40;

fn nop(rip: u64) -> Instruction {
    paludarium_decoder::decode(&[0x90], GuestAddr(rip)).unwrap()
}

/// Appends the block of a lone `nop` at `rip`.
fn lone(code: &mut Vec<Decoded>, rip: u64) -> Result<(), ExitReason> {
    code.push(Decoded::new(nop(rip)));
    Ok(())
}

/// Decodes that each find the other address in their slot, until they
/// make up a window. The first after the room for instructions is emptied
/// finds an empty slot instead.
fn collide(cache: &mut DecodeCache) {
    let start = cache.growth.window_start;
    let mut i = 0;
    while cache.growth.window_start == start {
        let rip = if i % 2 == 0 { FIRST } else { SECOND };
        cache.put(rip, 1, nop(rip));
        i += 1;
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
    cache.lookup();
    collide(&mut cache);
    let other = 4096;
    cache.put(other, 1, nop(other));
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
    cache.lookup();
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES * 2);
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
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
}

#[test]
fn decodes_after_a_code_change_do_not_count() {
    let mut cache = DecodeCache::new();
    cache.lookup();
    for generation in 0..=GROWTH_WINDOW {
        cache.put(FIRST, generation, nop(FIRST));
    }
    cache.lookup();
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
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
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
    let mut cache = DecodeCache::new();
    for generation in 0..=GROWTH_WINDOW + 1 {
        let rip = if generation % 2 == 0 { FIRST } else { SECOND };
        assert!(cache.block(rip, generation, |code| lone(code, rip)).is_ok());
    }
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
}

#[test]
fn the_cache_grows_no_further_than_its_limit() {
    let mut cache = DecodeCache::new();
    while cache.slots.len() < MAX_ENTRIES {
        cache.lookup();
        collide(&mut cache);
        cache.lookup();
    }
    assert_eq!(cache.slots.len(), MAX_ENTRIES);
    collide(&mut cache);
    cache.lookup();
    assert_eq!(cache.slots.len(), MAX_ENTRIES);
}

#[test]
fn the_interpreter_grows_the_cache_it_misses() {
    if MAX_ENTRIES == INITIAL_ENTRIES {
        return;
    }
    let mut cache = DecodeCache::new();
    let decodes = std::cell::Cell::new(0);
    // Each lookup finds the other address in its slot, until they make up
    // a window, and one more grows the cache.
    let mut lookups = 0;
    while cache.slots.len() == INITIAL_ENTRIES {
        let rip = if lookups % 2 == 0 { FIRST } else { SECOND };
        lookups += 1;
        let block = cache.block(rip, 1, |code| {
            decodes.set(decodes.get() + 1);
            lone(code, rip)
        });
        let block = block.map(|b| {
            cache.code[b]
                .iter()
                .map(|d| d.instruction)
                .collect::<Vec<_>>()
        });
        assert_eq!(block, Ok(vec![nop(rip)]));
    }
    assert!(lookups > GROWTH_WINDOW);
    assert_eq!(decodes.get(), lookups);
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES * 2);
}

#[test]
fn a_full_cache_drops_the_code_of_earlier_generations() {
    let mut cache = DecodeCache::new();
    // A thousand blocks, decoded again and again: the room fills with
    // their earlier copies.
    let mut rip = 0;
    while cache.code.len() + MAX_BLOCK <= cache.slots.len() {
        cache.put(rip % 1000, 1, nop(rip % 1000));
        rip += 1;
    }
    cache.put(0, 2, nop(0));
    assert_eq!(cache.code.len(), 1);
    assert_eq!(cache.slots.len(), INITIAL_ENTRIES);
    assert!(cache.get_with_hint(1, 1).is_none());
    assert!(cache.get_with_hint(0, 2).is_some());
}

#[test]
fn a_cache_full_of_current_code_doubles_and_keeps_it() {
    let mut cache = DecodeCache::new();
    // These addresses take a slot each, so every block stays.
    for rip in 0..INITIAL_ENTRIES as u64 {
        cache.put(rip, 1, nop(rip));
    }
    let kept = (0..INITIAL_ENTRIES as u64)
        .filter(|&rip| cache.get_with_hint(rip, 1).is_some())
        .count();
    if MAX_ENTRIES == INITIAL_ENTRIES {
        // No room to grow: everything was dropped once, then refilled.
        assert!(kept < INITIAL_ENTRIES);
    } else {
        assert_eq!(kept, INITIAL_ENTRIES);
        assert_eq!(cache.slots.len(), INITIAL_ENTRIES * 2);
    }
    assert!(cache.code.len() <= cache.slots.len());
}

mod blocks {
    use super::super::*;
    use paludarium_mmu::{MappingKind, Prot};

    const CODE: u64 = 0x40_0000;

    /// Memory with `code` at [`CODE`], on a page that can be written and
    /// executed, followed by one that can only be written.
    fn memory(code: &[u8], at: u64) -> AddressSpace {
        let mut mem = AddressSpace::new();
        mem.map(
            Some(GuestAddr(CODE)),
            0x1000,
            Prot::from_bits(7).unwrap(),
            MappingKind::Anonymous,
        )
        .unwrap();
        mem.map(
            Some(GuestAddr(CODE + 0x1000)),
            0x1000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        mem.write(GuestAddr(at), code).unwrap();
        mem
    }

    /// Runs `budget` instructions from `at` through blocks, and one by one
    /// with nothing cached, from two copies of the code; both must end
    /// alike. Returns the state, the exit and the lookups the cache made.
    fn run_both(code: &[u8], at: u64, budget: u64) -> (CpuState, ExitReason, u64) {
        let cached_mem = memory(code, at);
        let mut cache = DecodeCache::new();
        let mut cached = CpuState::new(GuestAddr(at), GuestAddr(0));
        let exit = run_cached(&mut cached, &cached_mem, budget, &mut cache);
        let mem = memory(code, at);
        let mut expected = CpuState::new(GuestAddr(at), GuestAddr(0));
        let mut expected_exit = ExitReason::BudgetExhausted { rip: GuestAddr(0) };
        for _ in 0..budget {
            if let Err(reason) = step(&mut expected, &mem) {
                expected_exit = reason;
                break;
            }
            expected_exit = ExitReason::BudgetExhausted { rip: expected.rip };
        }
        assert_eq!(cached, expected);
        assert_eq!(exit, expected_exit);
        (cached, exit, cache.growth.lookups)
    }

    #[test]
    fn falling_through_a_block_needs_no_lookup() {
        // Five `nop`s and a `jmp` back to the first.
        let code = [0x90, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xf9];
        let (_, _, lookups) = run_both(&code, CODE, 60);
        assert_eq!(lookups, 10);
        let (state, exit, lookups) = run_both(&code, CODE, 3);
        assert_eq!(state.rip, GuestAddr(CODE + 3));
        assert_eq!(exit, ExitReason::BudgetExhausted { rip: state.rip });
        assert_eq!(lookups, 1);
    }

    #[test]
    fn a_store_into_the_running_block_is_seen() {
        // mov byte [rip + 1], 2; mov eax, 1 (made `mov eax, 2`); hlt
        let code = [0xc6, 0x05, 1, 0, 0, 0, 2, 0xb8, 1, 0, 0, 0, 0xf4];
        let (state, exit, _) = run_both(&code, CODE, 10);
        assert_eq!(state.gpr[reg::RAX], 2);
        assert!(matches!(exit, ExitReason::Halt { .. }));
    }

    #[test]
    fn an_instruction_that_cannot_be_decoded_stops_only_when_reached() {
        // xor eax, eax; je +1; (invalid); hlt
        let taken = [0x31, 0xc0, 0x74, 0x01, 0x06, 0xf4];
        let (_, exit, _) = run_both(&taken, CODE, 10);
        assert_eq!(
            exit,
            ExitReason::Halt {
                rip: GuestAddr(CODE + 5)
            }
        );
        // or eax, 1; je +1; (invalid); hlt
        let not_taken = [0x83, 0xc8, 0x01, 0x74, 0x01, 0x06, 0xf4];
        let (_, exit, _) = run_both(&not_taken, CODE, 10);
        assert!(matches!(
            exit,
            ExitReason::InvalidOpcode { rip, .. } if rip == GuestAddr(CODE + 5)
        ));
    }

    #[test]
    fn an_instruction_that_runs_off_the_executable_page_faults_when_reached() {
        // nop; nop; mov eax, 1 across the end of the executable page
        let at = CODE + 0x1000 - 4;
        let (_, exit, _) = run_both(&[0x90, 0x90, 0xb8, 1, 0, 0, 0], at, 10);
        assert!(matches!(
            exit,
            ExitReason::PageFault { rip, addr, fetch: true, .. }
                if rip == GuestAddr(at + 2) && addr == GuestAddr(CODE + 0x1000)
        ));
    }

    #[test]
    fn a_block_grows_only_by_what_runs() {
        // nop; nop; je +1; (invalid); hlt, from a state where je is taken
        let code = [0x90, 0x90, 0x74, 0x01, 0x06, 0xf4];
        let mem = memory(&code, CODE);
        let mut cache = DecodeCache::new();
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(0));
        state.rflags |= flag::ZF;
        let exit = run_cached(&mut state, &mem, 10, &mut cache);
        assert_eq!(
            exit,
            ExitReason::Halt {
                rip: GuestAddr(CODE + 5)
            }
        );
        let s = cache.slots[cache.slot(CODE)];
        // Three instructions in the first block, the `hlt` in its own: the
        // invalid one was never decoded.
        assert_eq!(s.len, 3);
        assert_eq!(cache.code.len(), 4);
    }

    #[test]
    fn a_block_ends_after_a_jump_and_at_its_limit() {
        // nop ... nop; jmp back to the first
        let mut code = vec![0x90; MAX_BLOCK + 8];
        code.extend_from_slice(&[0xeb, (-(MAX_BLOCK as i8 + 10)) as u8]);
        let (_, _, lookups) = run_both(&code, CODE, 3 * (MAX_BLOCK as u64 + 9));
        // Each round: the block at the first `nop`, then the one of the
        // rest; the first round decodes them.
        assert_eq!(lookups, 6);
        let mem = memory(&code, CODE);
        let mut cache = DecodeCache::new();
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(0));
        run_cached(&mut state, &mem, 2 * (MAX_BLOCK as u64 + 9), &mut cache);
        assert_eq!(cache.slots[cache.slot(CODE)].len as usize, MAX_BLOCK);
        let rest = CODE + MAX_BLOCK as u64;
        assert_eq!(cache.slots[cache.slot(rest)].len, 9);
        assert_eq!(cache.code.len(), MAX_BLOCK + 9);
    }
}
