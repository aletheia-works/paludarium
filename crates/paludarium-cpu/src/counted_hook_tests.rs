use super::*;
use paludarium_mmu::{MappingKind, Prot};

fn specialized_fallback_equivalence(
    budget: u64,
    maximum: u64,
    syscall: bool,
    offered_rips: &[u64],
) {
    let (initial, memory) = machine();
    if syscall {
        memory.write_initial(GuestAddr(4100), &[0x0f, 5]).unwrap();
    }
    let mut expected = initial.clone();
    let expected_exit = run_cached(&mut expected, &memory, budget, &mut DecodeCache::new());
    for enabled in [false, true] {
        let mut actual = initial.clone();
        let mut offered = Vec::new();
        let exit = run_cached_with_counted_hook(
            &mut actual,
            &memory,
            budget,
            &mut DecodeCache::new(),
            AccelerationPolicy {
                maximum_block: maximum,
                cache_rejections: enabled,
            },
            |state, _, rejected| {
                offered.push(state.rip);
                *rejected = true;
                None
            },
        );
        assert_eq!(exit, expected_exit);
        assert_eq!(actual, expected);
        assert_eq!(
            offered,
            offered_rips
                .iter()
                .copied()
                .map(GuestAddr)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn specialized_zero_budget_matches_both_policies() {
    specialized_fallback_equivalence(0, 64, false, &[]);
}
#[test]
fn specialized_short_budget_matches_both_policies() {
    specialized_fallback_equivalence(63, 64, false, &[]);
}
#[test]
fn specialized_exact_budget_matches_both_policies() {
    specialized_fallback_equivalence(64, 64, false, &[4096]);
}
#[test]
fn specialized_disabled_acceleration_matches_both_policies() {
    specialized_fallback_equivalence(65, 0, false, &[]);
}
#[test]
fn specialized_syscall_matches_both_policies() {
    specialized_fallback_equivalence(65, 64, true, &[4096, 4097]);
}
#[test]
fn specialized_opt_out_ignores_existing_rejection() {
    let (mut state, memory) = machine();
    let mut cache = DecodeCache::new();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 0);
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, true, false),
        1
    );
}
#[test]
fn specialized_policy_switch_preserves_epoch_invalidation() {
    let (mut state, memory) = machine();
    let mut cache = DecodeCache::new();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
    memory.write_initial(GuestAddr(4096), &[0x90]).unwrap();
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, true, false),
        1
    );
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 0);
}

fn hinted_dispatch_matches_interpreter(bytes: &[u8], budget: u64, maximum: u64) {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(4096)),
            4096,
            Prot::READ_EXEC,
            MappingKind::ElfSegment,
        )
        .unwrap();
    memory.write_initial(GuestAddr(4096), bytes).unwrap();
    let mut hinted = CpuState::new(GuestAddr(4096), GuestAddr(8192));
    let mut ordinary = hinted.clone();
    let mut cache = DecodeCache::new();
    let generation = memory.code_generation();
    let instruction = paludarium_decoder::decode(bytes, GuestAddr(4096)).unwrap();
    cache.put(4096, generation, instruction);
    cache.reject_acceleration(4096, generation);
    let actual = run_cached_with_counted_hook(
        &mut hinted,
        &memory,
        budget,
        &mut cache,
        AccelerationPolicy {
            maximum_block: maximum,
            cache_rejections: true,
        },
        |_, _, _| panic!("pre-rejected boundary must bypass accelerator"),
    );
    let expected = run_cached(&mut ordinary, &memory, budget, &mut DecodeCache::new());
    assert_eq!(actual, expected);
    assert_eq!(hinted, ordinary);
}
#[test]
fn negative_dispatch_zero_budget() {
    hinted_dispatch_matches_interpreter(&[0x90], 0, 64);
}
#[test]
fn negative_dispatch_one_budget() {
    hinted_dispatch_matches_interpreter(&[0x90], 1, 64);
}
#[test]
fn negative_dispatch_disabled_maximum() {
    hinted_dispatch_matches_interpreter(&[0x90], 1, 0);
}
#[test]
fn negative_dispatch_maximum_u64() {
    hinted_dispatch_matches_interpreter(&[0x90], 1, u64::MAX);
}
#[test]
fn negative_dispatch_register_effect() {
    hinted_dispatch_matches_interpreter(&[0xb8, 42, 0, 0, 0], 1, 64);
}
#[test]
fn negative_dispatch_syscall_exit() {
    hinted_dispatch_matches_interpreter(&[0x0f, 0x05], 64, 64);
}
#[test]
fn negative_dispatch_memory_fault() {
    hinted_dispatch_matches_interpreter(&[0x48, 0x8b, 0x00], 64, 64);
}

/// The cached instruction and its rejection, as [`DecodeCache::get_with_hint`]
/// gives them.
fn hinted(
    cache: &DecodeCache,
    rip: u64,
    generation: u64,
) -> Option<(paludarium_decoder::Instruction, bool)> {
    cache
        .get_with_hint(rip, generation)
        .map(|(_, instruction, rejected)| (instruction, rejected))
}

fn cached_boundary() -> (DecodeCache, paludarium_decoder::Instruction) {
    let instruction = paludarium_decoder::decode(&[0x90], GuestAddr(4096)).unwrap();
    let mut cache = DecodeCache::new();
    cache.put(4096, 1, instruction);
    (cache, instruction)
}

#[test]
fn decode_hint_empty_boundary_requires_fetch() {
    assert!(DecodeCache::new().get_with_hint(4096, 1).is_none());
}

#[test]
fn decode_hint_hit_preserves_exact_decoded_instruction() {
    let (cache, expected) = cached_boundary();
    let (decoded, instruction, rejected) = cache.get_with_hint(4096, 1).unwrap();
    assert_eq!(instruction, expected);
    assert_eq!(decoded.next, expected.next_rip().0);
    assert!(!rejected);
}

#[test]
fn decode_hint_deterministic_rejection_is_returned_with_same_entry() {
    let (mut cache, expected) = cached_boundary();
    cache.reject_acceleration(4096, 1);
    assert_eq!(hinted(&cache, 4096, 1), Some((expected, true)));
}

#[test]
fn decode_hint_wrong_generation_cannot_reuse_instruction_or_rejection() {
    let (mut cache, _) = cached_boundary();
    cache.reject_acceleration(4096, 1);
    assert!(cache.get_with_hint(4096, 2).is_none());
}

#[test]
fn decode_hint_slot_collision_cannot_transfer_rejection() {
    let (mut cache, _) = cached_boundary();
    cache.reject_acceleration(4096, 1);
    let collision = (0..1 << 32)
        .find(|&rip| rip != 4096 && cache.slot(rip) == cache.slot(4096))
        .unwrap();
    let instruction = paludarium_decoder::decode(&[0x90], GuestAddr(collision)).unwrap();
    cache.put(collision, 1, instruction);
    assert!(cache.get_with_hint(4096, 1).is_none());
    assert_eq!(hinted(&cache, collision, 1), Some((instruction, false)));
}

#[test]
fn decode_hint_new_decode_clears_stale_rejection() {
    let (mut cache, instruction) = cached_boundary();
    cache.reject_acceleration(4096, 1);
    cache.put(4096, 2, instruction);
    assert_eq!(hinted(&cache, 4096, 2), Some((instruction, false)));
}

#[test]
fn decode_hint_does_not_change_ordinary_interpreter_cache_contract() {
    let (mut cache, instruction) = cached_boundary();
    cache.reject_acceleration(4096, 1);
    // A decode that would stop shows whether the cache held the entry.
    let stop = |_: &mut Code| Err(ExitReason::Halt { rip: GuestAddr(0) });
    let first = cache
        .block(4096, 1, stop)
        .map(|block| cache.code.instructions[block.start]);
    assert_eq!(first, Ok(instruction));
    assert!(cache.block(4096, 2, stop).is_err());
}

fn hint_attempt(
    state: &mut CpuState,
    memory: &AddressSpace,
    cache: &mut DecodeCache,
    deterministic: bool,
    enabled: bool,
) -> usize {
    state.rip = GuestAddr(4096);
    let mut calls = 0;
    run_cached_with_counted_hook(
        state,
        memory,
        64,
        cache,
        AccelerationPolicy {
            maximum_block: 64,
            cache_rejections: enabled,
        },
        |_, _, rejected| {
            calls += 1;
            *rejected = deterministic;
            None
        },
    );
    calls
}

#[test]
fn counted_negative_hint_skips_only_same_epoch_boundary() {
    let (mut state, memory) = machine();
    let mut cache = DecodeCache::new();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 0);
    memory.write_initial(GuestAddr(4096), &[0x90]).unwrap();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
}
#[test]
fn counted_transient_rejection_remains_retryable() {
    let (mut state, memory) = machine();
    let mut cache = DecodeCache::new();
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, false, true),
        1
    );
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, false, true),
        1
    );
}
#[test]
fn counted_default_opt_out_does_not_cache_rejections() {
    let (mut state, memory) = machine();
    let mut cache = DecodeCache::new();
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, true, false),
        1
    );
    assert_eq!(
        hint_attempt(&mut state, &memory, &mut cache, true, false),
        1
    );
}
#[test]
fn counted_negative_hint_protect_change_invalidates() {
    let (mut state, mut memory) = machine();
    let mut cache = DecodeCache::new();
    hint_attempt(&mut state, &memory, &mut cache, true, true);
    memory
        .protect(GuestAddr(4096), 4096, Prot::from_bits(7).unwrap())
        .unwrap();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
}
#[test]
fn counted_negative_hint_unmap_preserves_fetch_fault() {
    let (mut state, mut memory) = machine();
    let mut cache = DecodeCache::new();
    hint_attempt(&mut state, &memory, &mut cache, true, true);
    memory.unmap(GuestAddr(4096), 4096).unwrap();
    state.rip = GuestAddr(4096);
    assert!(matches!(
        run_cached_with_counted_hook(&mut state, &memory, 64, &mut cache, 64, |_, _, _| panic!(
            "unmapped"
        )),
        ExitReason::PageFault { .. }
    ));
}
#[test]
fn counted_negative_hint_remap_invalidates() {
    let (mut state, mut memory) = machine();
    let mut cache = DecodeCache::new();
    hint_attempt(&mut state, &memory, &mut cache, true, true);
    memory.unmap(GuestAddr(4096), 4096).unwrap();
    memory
        .map(
            Some(GuestAddr(4096)),
            4096,
            Prot::READ_EXEC,
            MappingKind::ElfSegment,
        )
        .unwrap();
    memory.write_initial(GuestAddr(4096), &[0x90; 128]).unwrap();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
}
#[test]
fn counted_negative_hint_other_worker_write_invalidates() {
    let (mut state, memory) = machine();
    let memory = std::sync::Arc::new(memory);
    let mut cache = DecodeCache::new();
    hint_attempt(&mut state, &memory, &mut cache, true, true);
    let other = memory.clone();
    std::thread::spawn(move || other.write_initial(GuestAddr(4096), &[0x90]).unwrap())
        .join()
        .unwrap();
    assert_eq!(hint_attempt(&mut state, &memory, &mut cache, true, true), 1);
}

fn machine() -> (CpuState, AddressSpace) {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(4096)),
            4096,
            Prot::READ_EXEC,
            MappingKind::ElfSegment,
        )
        .unwrap();
    memory.write_initial(GuestAddr(4096), &[0x90; 128]).unwrap();
    (CpuState::new(GuestAddr(4096), GuestAddr(8192)), memory)
}

#[test]
fn counted_hook_charges_actual_instructions() {
    let (mut state, memory) = machine();
    let mut calls = 0;
    let result = run_cached_with_counted_hook(
        &mut state,
        &memory,
        65,
        &mut DecodeCache::new(),
        64,
        |state, _, _| {
            calls += 1;
            state.rip.0 += 2;
            Some((ExitReason::BudgetExhausted { rip: state.rip }, 2))
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(state.rip, GuestAddr(4161));
    assert_eq!(result, ExitReason::BudgetExhausted { rip: state.rip });
}
#[test]
fn counted_hook_small_budget_never_calls_hook() {
    let (mut state, memory) = machine();
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        63,
        &mut DecodeCache::new(),
        64,
        |_, _, _| panic!("small budget"),
    );
    assert_eq!(state.rip, GuestAddr(4159));
}
#[test]
fn counted_hook_zero_budget_preserves_state() {
    let (mut state, memory) = machine();
    let before = state.clone();
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        0,
        &mut DecodeCache::new(),
        64,
        |_, _, _| panic!("zero budget"),
    );
    assert_eq!(state, before);
}
#[test]
fn counted_hook_rejection_executes_decoded_instruction() {
    let (mut state, memory) = machine();
    let mut calls = 0;
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        64,
        &mut DecodeCache::new(),
        64,
        |_, instruction, _| {
            calls += 1;
            assert_eq!(instruction.mnemonic, paludarium_decoder::Mnemonic::Nop);
            None
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(state.rip, GuestAddr(4160));
}
#[test]
fn counted_hook_fetch_fault_does_not_call_hook() {
    let (mut state, _) = machine();
    assert!(matches!(
        run_cached_with_counted_hook(
            &mut state,
            &AddressSpace::new(),
            64,
            &mut DecodeCache::new(),
            64,
            |_, _, _| panic!("fault")
        ),
        ExitReason::PageFault { .. }
    ));
}

#[test]
fn counted_hook_exact_maximum_exhausts_remaining_budget() {
    let (mut state, memory) = machine();
    let mut calls = 0;
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        64,
        &mut DecodeCache::new(),
        64,
        |state, _, _| {
            calls += 1;
            state.rip.0 += 64;
            Some((ExitReason::BudgetExhausted { rip: state.rip }, 64))
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(state.rip, GuestAddr(4160));
}

#[test]
fn counted_hook_syscall_after_short_block_returns_immediately() {
    let (mut state, memory) = machine();
    memory.write_initial(GuestAddr(4098), &[0x0f, 5]).unwrap();
    let reason = run_cached_with_counted_hook(
        &mut state,
        &memory,
        65,
        &mut DecodeCache::new(),
        64,
        |state, _, _| {
            state.rip.0 += 2;
            Some((ExitReason::BudgetExhausted { rip: state.rip }, 2))
        },
    );
    assert!(matches!(reason, ExitReason::Syscall { .. }));
    assert_eq!(state.rip, GuestAddr(4100));
}

#[test]
fn counted_hook_fault_after_short_block_is_preserved() {
    let (mut state, memory) = machine();
    let reason = run_cached_with_counted_hook(
        &mut state,
        &memory,
        65,
        &mut DecodeCache::new(),
        64,
        |state, _, _| {
            state.rip = GuestAddr(8192);
            Some((ExitReason::BudgetExhausted { rip: state.rip }, 2))
        },
    );
    assert!(matches!(
        reason,
        ExitReason::PageFault {
            rip: GuestAddr(8192),
            fetch: true,
            ..
        }
    ));
}
#[test]
#[should_panic(expected = "invalid accelerator instruction count")]
fn counted_hook_rejects_zero_count() {
    let (mut state, memory) = machine();
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        64,
        &mut DecodeCache::new(),
        64,
        |state, _, _| Some((ExitReason::BudgetExhausted { rip: state.rip }, 0)),
    );
}
#[test]
#[should_panic(expected = "invalid accelerator instruction count")]
fn counted_hook_rejects_excessive_count() {
    let (mut state, memory) = machine();
    run_cached_with_counted_hook(
        &mut state,
        &memory,
        64,
        &mut DecodeCache::new(),
        64,
        |state, _, _| Some((ExitReason::BudgetExhausted { rip: state.rip }, 65)),
    );
}

/// Runs the 32 `nop`s at 4096 of `memory` (one block) with an accelerator
/// that turns down the instructions at the addresses `reject` picks, and
/// returns the addresses it was offered and how many instructions were
/// decoded.
fn offered_in_one_block(
    memory: &AddressSpace,
    cache: &mut DecodeCache,
    cache_rejections: bool,
    reject: impl Fn(u64) -> bool,
) -> (Vec<u64>, usize) {
    let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
    let decoded = cache.code.decoded.len();
    let mut offered = Vec::new();
    let exit = run_cached_with_counted_hook(
        &mut state,
        memory,
        32,
        cache,
        AccelerationPolicy {
            maximum_block: 1,
            cache_rejections,
        },
        |state, _, rejected| {
            offered.push(state.rip.0);
            *rejected = reject(state.rip.0);
            None
        },
    );
    assert_eq!(
        exit,
        ExitReason::BudgetExhausted {
            rip: GuestAddr(4096 + 32)
        }
    );
    (offered, cache.code.decoded.len() - decoded)
}

#[test]
fn falling_through_offers_every_instruction_and_decodes_once() {
    let (_, memory) = machine();
    let mut cache = DecodeCache::new();
    let all = (4096..4096 + 32).collect::<Vec<_>>();
    assert_eq!(
        offered_in_one_block(&memory, &mut cache, true, |_| false),
        (all.clone(), 32)
    );
    // The block now holds all 32: running it again decodes nothing, makes
    // one lookup, and still offers each instruction.
    let lookups = cache.growth.lookups;
    assert_eq!(
        offered_in_one_block(&memory, &mut cache, true, |_| false),
        (all, 0)
    );
    assert_eq!(cache.growth.lookups - lookups, 1);
}

#[test]
fn an_instruction_turned_down_inside_a_block_is_not_offered_again() {
    let (_, memory) = machine();
    let mut cache = DecodeCache::new();
    let even = |rip: u64| rip.is_multiple_of(2);
    let (offered, _) = offered_in_one_block(&memory, &mut cache, true, even);
    assert_eq!(offered.len(), 32);
    let odd = (4096..4096 + 32).filter(|r| r % 2 == 1).collect::<Vec<_>>();
    assert_eq!(
        offered_in_one_block(&memory, &mut cache, true, even),
        (odd, 0)
    );
    // Code changed under the block: it is decoded again and every
    // instruction is offered again.
    memory.write_initial(GuestAddr(4096), &[0x90]).unwrap();
    let (offered, decoded) = offered_in_one_block(&memory, &mut cache, true, even);
    assert_eq!((offered.len(), decoded), (32, 32));
}

#[test]
fn without_cached_rejections_every_instruction_is_offered_again() {
    let (_, memory) = machine();
    let mut cache = DecodeCache::new();
    let all = (4096..4096 + 32).collect::<Vec<_>>();
    let even = |rip: u64| rip.is_multiple_of(2);
    assert_eq!(
        offered_in_one_block(&memory, &mut cache, false, even),
        (all.clone(), 32)
    );
    assert_eq!(
        offered_in_one_block(&memory, &mut cache, false, even),
        (all, 0)
    );
}
