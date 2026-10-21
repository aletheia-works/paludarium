//! Synchronous C9 bridge. Compilation runs outside the MMU epoch guard;
//! register-only execution runs inside it and cannot reenter guest memory.
use crate::{CodeCache, block, cache::EpochCache, emit};
use paludarium_cpu::CpuState;
#[cfg(feature = "cost-profile")]
use paludarium_cpu::jit_cost::{self, Counter};
use paludarium_mmu::AddressSpace;
use paludarium_types::{ExitReason, GuestAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};

/// Number of `u64` words in the scratch state a translated block runs on:
/// GPR0..15 (words 0..15), RFLAGS (16), RIP (17), then XMM0..15 as
/// little-endian (low, high) word pairs (words 18..49).
pub const STATE_WORDS: usize = 50;
/// Byte length of the scratch state; the Worker import checks and rolls
/// back exactly this many bytes.
pub const STATE_BYTES: usize = STATE_WORDS * 8;
/// Scratch state exchanged with an [`ExecutionBridge`].
pub type JitState = [u64; STATE_WORDS];
const RFLAGS_WORD: usize = 16;
const RIP_WORD: usize = 17;
const XMM_WORD: usize = 18;
/// Byte offset of XMM0 in the scratch state (XMMn is at `+ 16 * n`).
pub(crate) const XMM_OFFSET: usize = XMM_WORD * 8;

/// Copies the registers a translated block may read or write into scratch.
pub(crate) fn scratch_from(state: &CpuState) -> JitState {
    let mut scratch = [0; STATE_WORDS];
    scratch[..16].copy_from_slice(&state.gpr);
    scratch[RFLAGS_WORD] = state.rflags;
    scratch[RIP_WORD] = state.rip.0;
    for (index, value) in state.xmm.iter().enumerate() {
        scratch[XMM_WORD + index * 2] = *value as u64;
        scratch[XMM_WORD + index * 2 + 1] = (*value >> 64) as u64;
    }
    scratch
}

/// Commits a successful block's scratch back to the CPU. Only called after
/// the bridge reported success; on failure the CPU state is never touched.
pub(crate) fn commit(state: &mut CpuState, scratch: &JitState) {
    state.gpr.copy_from_slice(&scratch[..16]);
    state.rflags = scratch[RFLAGS_WORD];
    state.rip = GuestAddr(scratch[RIP_WORD]);
    for (index, value) in state.xmm.iter_mut().enumerate() {
        *value = u128::from(scratch[XMM_WORD + index * 2])
            | (u128::from(scratch[XMM_WORD + index * 2 + 1]) << 64);
    }
}

/// One Worker-local synchronous wasm compiler/executor. State is trusted Rust
/// scratch storage laid out as described at [`STATE_WORDS`]. Failure must
/// never commit guest state.
pub trait ExecutionBridge: Send + Sync {
    /// Feature-only no-touch observation. None means unsupported observation,
    /// not a missing prepared entry, and never requests preparation.
    #[cfg(feature = "cost-profile")]
    fn diagnostic_prepared(&self, _module_id: u32, _wasm: &[u8]) -> Option<bool> {
        None
    }
    /// Executes an already prepared Worker-local entry. `None` requests cold
    /// preparation outside the MMU guard; failures must roll back scratch.
    fn execute_ready(&self, _module_id: u32, _wasm: &[u8], _state: &mut JitState) -> Option<bool> {
        None
    }
    /// Compiles outside the MMU epoch guard. No guest state may change here.
    fn prepare(&self, _module_id: u32, _wasm: &[u8]) -> bool {
        true
    }
    fn execute(&self, module_id: u32, wasm: &[u8], state: &mut JitState) -> bool;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JitStatistics {
    pub translated_blocks: u64,
    pub executed_blocks: u64,
    pub executed_instructions: u64,
    pub fallbacks: u64,
}

struct Translation {
    id: u32,
    code: Vec<u8>,
    instruction_count: usize,
}
static NEXT_MODULE: AtomicU32 = AtomicU32::new(1);
pub(crate) fn next_module_id() -> Option<u32> {
    NEXT_MODULE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .ok()
}

/// A minimal register-only wasm cache. Unsupported instructions, memory,
/// syscall and fault handling remain entirely in the existing interpreter.
pub struct WasmCodeCache {
    bridge: Arc<dyn ExecutionBridge>,
    cache: EpochCache<Option<Arc<Translation>>>,
    translated: AtomicU64,
    executed: AtomicU64,
    instructions: AtomicU64,
    fallbacks: AtomicU64,
    minimum_block: usize,
}

impl WasmCodeCache {
    #[must_use]
    pub fn new(bridge: Arc<dyn ExecutionBridge>) -> Self {
        Self {
            bridge,
            cache: EpochCache::new(),
            translated: AtomicU64::new(0),
            executed: AtomicU64::new(0),
            instructions: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            minimum_block: 1,
        }
    }
    /// A compilation selection heuristic, never a guest execution limit.
    /// Shorter supported sequences continue through the ordinary interpreter.
    #[must_use]
    pub fn with_minimum_block(mut self, minimum: usize) -> Self {
        self.minimum_block = minimum.clamp(1, 64);
        self
    }
    #[must_use]
    pub fn statistics(&self) -> JitStatistics {
        JitStatistics {
            translated_blocks: self.translated.load(Ordering::Relaxed),
            executed_blocks: self.executed.load(Ordering::Relaxed),
            executed_instructions: self.instructions.load(Ordering::Relaxed),
            fallbacks: self.fallbacks.load(Ordering::Relaxed),
        }
    }
    #[cfg(feature = "cost-profile")]
    fn observe_next(&self, memory: &AddressSpace, space: u64, generation: u64, rip: u64) {
        use crate::cache::Peek;
        jit_cost::add(Counter::ObservationLookups, 1);
        let observed = memory.with_code_epoch(space, generation, || {
            match self.cache.peek(space, rip, generation) {
                Peek::Missing => jit_cost::add(Counter::NextMissing, 1),
                Peek::Stale => jit_cost::add(Counter::NextEpoch, 1),
                Peek::Present(None) => jit_cost::add(Counter::NextNegative, 1),
                Peek::Present(Some(next)) => {
                    jit_cost::add(Counter::NextPositive, 1);
                    let field = match self.bridge.diagnostic_prepared(next.id, &next.code) {
                        Some(true) => Counter::NextPrepared,
                        Some(false) => Counter::NextUnprepared,
                        None => Counter::NextUnavailable,
                    };
                    jit_cost::add(field, 1);
                }
            }
        });
        if observed.is_none() {
            jit_cost::add(Counter::NextEpoch, 1);
        }
    }
    fn run(
        &self,
        state: &mut CpuState,
        memory: &AddressSpace,
        deterministic_rejection: &mut bool,
    ) -> Option<(ExitReason, u64)> {
        if state.repeat_continuation.is_some() {
            return None;
        }
        let (space, generation) = memory.code_epoch();
        let (translation, space, generation) =
            match self
                .cache
                .get_selected(space, state.rip.0, generation, Option::is_some)
            {
                Some(translation) => {
                    *deterministic_rejection = translation.is_none();
                    #[cfg(feature = "cost-profile")]
                    if translation.is_none() {
                        jit_cost::add(Counter::NegativeHits, 1);
                    }
                    (translation?, space, generation)
                }
                None => {
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::CacheMisses, 1);
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::ColdSnapshots, 1);
                    let snapshot = memory.code_snapshot(state.rip, 960).ok()?;
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::SnapshotBytes, snapshot.bytes.len() as u64);
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::ColdExtracts, 1);
                    let Some(block) = block::extract(&snapshot.bytes, state.rip.0) else {
                        *deterministic_rejection = true;
                        // Cache a deterministic unsupported first instruction too.
                        // Any executable mutation changes its epoch before reuse.
                        self.cache.insert(
                            snapshot.address_space,
                            state.rip.0,
                            snapshot.generation,
                            snapshot.bytes.len(),
                            None,
                        );
                        return None;
                    };
                    if block.operations.len() < self.minimum_block {
                        *deterministic_rejection = true;
                        self.cache.insert(
                            snapshot.address_space,
                            state.rip.0,
                            snapshot.generation,
                            snapshot.bytes.len(),
                            None,
                        );
                        return None;
                    }
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::ColdEmits, 1);
                    let code = emit::emit(&block)?;
                    // Never reuse an ID, even on exhaustion: Worker-local JS caches
                    // must not mistake a different module for a previous one.
                    let id = next_module_id()?;
                    let translation = Arc::new(Translation {
                        id,
                        code,
                        instruction_count: block.operations.len(),
                    });
                    if !self.cache.insert(
                        snapshot.address_space,
                        state.rip.0,
                        snapshot.generation,
                        usize::try_from(block.end.checked_sub(block.entry)?).ok()?,
                        Some(translation.clone()),
                    ) {
                        return None;
                    }
                    self.translated.fetch_add(1, Ordering::Relaxed);
                    #[cfg(feature = "cost-profile")]
                    jit_cost::add(Counter::TranslatedBlocks, 1);
                    (translation, snapshot.address_space, snapshot.generation)
                }
            };
        let mut scratch = scratch_from(state);
        let ready = memory.with_code_epoch(space, generation, || {
            self.bridge
                .execute_ready(translation.id, &translation.code, &mut scratch)
        });
        #[cfg(feature = "cost-profile")]
        if ready.is_none() {
            jit_cost::add(Counter::EpochInvalidations, 1);
        }
        let ready = ready?;
        let success = if let Some(success) = ready {
            #[cfg(feature = "cost-profile")]
            jit_cost::add(Counter::WarmExecutions, 1);
            Some(success)
        } else {
            #[cfg(feature = "cost-profile")]
            jit_cost::add(Counter::PrepareCalls, 1);
            if !self.bridge.prepare(translation.id, &translation.code) {
                #[cfg(feature = "cost-profile")]
                jit_cost::add(Counter::PrepareRejections, 1);
                return None;
            }
            memory.with_code_epoch(space, generation, || {
                #[cfg(feature = "cost-profile")]
                jit_cost::add(Counter::ExecuteCalls, 1);
                self.bridge
                    .execute(translation.id, &translation.code, &mut scratch)
            })
        };
        #[cfg(feature = "cost-profile")]
        if success.is_none() {
            jit_cost::add(Counter::EpochInvalidations, 1);
        }
        let success = success?;
        if !success {
            #[cfg(feature = "cost-profile")]
            jit_cost::add(Counter::ExecuteRejections, 1);
            return None;
        }
        commit(state, &scratch);
        self.executed.fetch_add(1, Ordering::Relaxed);
        self.instructions
            .fetch_add(translation.instruction_count as u64, Ordering::Relaxed);
        #[cfg(feature = "cost-profile")]
        {
            jit_cost::add(Counter::ExecutedBlocks, 1);
            jit_cost::add(
                Counter::ExecutedInstructions,
                translation.instruction_count as u64,
            );
            jit_cost::block_length(translation.instruction_count);
            self.observe_next(memory, space, generation, state.rip.0);
        }
        Some((
            ExitReason::BudgetExhausted { rip: state.rip },
            translation.instruction_count as u64,
        ))
    }
}
impl CodeCache for WasmCodeCache {
    fn cache_rejections(&self) -> bool {
        true
    }
    fn eligible(&self, instruction: &paludarium_decoder::Instruction) -> bool {
        crate::eligible_instruction(instruction)
    }
    fn try_run(&self, state: &mut CpuState, memory: &AddressSpace) -> Option<ExitReason> {
        self.try_run_counted(state, memory)
            .map(|(reason, _)| reason)
    }
    fn try_run_counted(
        &self,
        state: &mut CpuState,
        memory: &AddressSpace,
    ) -> Option<(ExitReason, u64)> {
        self.try_run_with_hint(state, memory).0
    }
    fn try_run_with_hint(
        &self,
        state: &mut CpuState,
        memory: &AddressSpace,
    ) -> (Option<(ExitReason, u64)>, bool) {
        let mut deterministic_rejection = false;
        let result = self.run(state, memory, &mut deterministic_rejection);
        if result.is_none() {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "cost-profile")]
            jit_cost::add(Counter::Fallbacks, 1);
        }
        (result, deterministic_rejection)
    }
    fn invalidate(&self, page: GuestAddr) {
        self.cache.invalidate(page.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{MappingKind, Prot};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    struct NodeBridge;
    #[cfg(feature = "cost-profile")]
    #[derive(Default)]
    struct ObservingBridge {
        queries: AtomicU32,
        prepares: AtomicU32,
        executes: AtomicU32,
    }
    #[cfg(feature = "cost-profile")]
    impl ExecutionBridge for ObservingBridge {
        fn diagnostic_prepared(&self, id: u32, _: &[u8]) -> Option<bool> {
            self.queries.fetch_add(1, Ordering::Relaxed);
            Some(id == 17)
        }
        fn prepare(&self, _: u32, _: &[u8]) -> bool {
            self.prepares.fetch_add(1, Ordering::Relaxed);
            false
        }
        fn execute(&self, _: u32, _: &[u8], _: &mut JitState) -> bool {
            self.executes.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
    #[cfg(feature = "cost-profile")]
    fn observation_case(kind: u32, expected_queries: u32) {
        let (state, memory) = machine(&[0xb8, 42, 0, 0, 0], 0);
        let before = state.clone();
        let epoch = memory.code_epoch();
        let bridge = Arc::new(ObservingBridge::default());
        let cache = WasmCodeCache::new(bridge.clone());
        let entry = Some(Arc::new(Translation {
            id: if kind == 2 { 18 } else { 17 },
            code: vec![0],
            instruction_count: 1,
        }));
        match kind {
            0 => {}
            3 => {
                cache.cache.insert(epoch.0, 4096, epoch.1, 1, None);
            }
            4 => {
                cache
                    .cache
                    .insert(epoch.0, 4096, epoch.1.wrapping_add(1), 1, entry);
            }
            5 => {
                cache
                    .cache
                    .insert(epoch.0.wrapping_add(1), 4096, epoch.1, 1, entry);
            }
            _ => {
                cache.cache.insert(epoch.0, 4096, epoch.1, 1, entry);
            }
        }
        if kind == 6 {
            cache.cache.invalidate(4096);
        }
        let statistics = cache.statistics();
        for _ in 0..3 {
            cache.observe_next(&memory, epoch.0, epoch.1, 4096);
        }
        assert_eq!(bridge.queries.load(Ordering::Relaxed), expected_queries);
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 0);
        assert_eq!(bridge.executes.load(Ordering::Relaxed), 0);
        assert_eq!(cache.statistics(), statistics);
        assert_eq!(state, before);
        assert_eq!(memory.code_epoch(), epoch);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_missing_never_prepares() {
        observation_case(0, 0);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_positive_only_queries_worker() {
        observation_case(1, 3);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_unprepared_never_compiles() {
        observation_case(2, 3);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_negative_never_queries_worker() {
        observation_case(3, 0);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_stale_never_queries_worker() {
        observation_case(4, 0);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_other_space_never_queries_worker() {
        observation_case(5, 0);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_invalidated_never_recreates_entry() {
        observation_case(6, 0);
    }
    #[cfg(feature = "cost-profile")]
    #[test]
    fn u14_observe_default_bridge_reports_unavailable_without_prepare() {
        let bridge = WarmBridge::default();
        assert_eq!(bridge.diagnostic_prepared(17, &[]), None);
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 0);
        assert_eq!(bridge.executes.load(Ordering::Relaxed), 0);
    }
    #[derive(Default)]
    struct WarmBridge {
        prepared: AtomicU32,
        prepares: AtomicU32,
        executes: AtomicU32,
        fail: bool,
    }
    impl ExecutionBridge for WarmBridge {
        fn execute_ready(&self, id: u32, _: &[u8], scratch: &mut JitState) -> Option<bool> {
            if self.prepared.load(Ordering::Relaxed) != id {
                return None;
            }
            scratch[0] = 42;
            Some(!self.fail)
        }
        fn prepare(&self, id: u32, _: &[u8]) -> bool {
            self.prepares.fetch_add(1, Ordering::Relaxed);
            self.prepared.store(id, Ordering::Relaxed);
            true
        }
        fn execute(&self, _: u32, _: &[u8], scratch: &mut JitState) -> bool {
            self.executes.fetch_add(1, Ordering::Relaxed);
            scratch[0] = 42;
            !self.fail
        }
    }
    #[test]
    fn u14_warm_bridge_reuses_prepared_entry_without_second_prepare() {
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 0);
        let bridge = Arc::new(WarmBridge::default());
        let cache = WasmCodeCache::new(bridge.clone());
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 1);
        assert_eq!(bridge.executes.load(Ordering::Relaxed), 1);
        assert_eq!(cache.statistics().executed_blocks, 2);
    }
    #[test]
    fn u14_warm_bridge_failure_rolls_back_cpu_and_does_not_hint() {
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 17);
        let bridge = Arc::new(WarmBridge::default());
        let cache = WasmCodeCache::new(bridge.clone());
        assert!(cache.try_run(&mut state, &memory).is_some());
        let failing = WarmBridge {
            prepared: AtomicU32::new(bridge.prepared.load(Ordering::Relaxed)),
            fail: true,
            ..WarmBridge::default()
        };
        let mut scratch = [17; STATE_WORDS];
        assert_eq!(
            failing.execute_ready(bridge.prepared.load(Ordering::Relaxed), &[], &mut scratch),
            Some(false)
        );
        // Cache must never commit scratch returned by a failed ready execution.
        let failing = Arc::new(WarmBridge {
            fail: true,
            ..WarmBridge::default()
        });
        let cache = WasmCodeCache::new(failing);
        let before = state.clone();
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
    }
    #[test]
    fn u14_warm_bridge_epoch_change_requires_new_module_preparation() {
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 0);
        let bridge = Arc::new(WarmBridge::default());
        let cache = WasmCodeCache::new(bridge.clone());
        cache.try_run(&mut state, &memory).unwrap();
        let previous = bridge.prepared.load(Ordering::Relaxed);
        memory.write(GuestAddr(4097), &[17]).unwrap();
        state.rip = GuestAddr(4096);
        cache.try_run(&mut state, &memory).unwrap();
        assert_ne!(previous, bridge.prepared.load(Ordering::Relaxed));
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn u14_warm_bridge_separate_workers_prepare_independently() {
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 0);
        let left = Arc::new(WarmBridge::default());
        let right = Arc::new(WarmBridge::default());
        WasmCodeCache::new(left.clone())
            .try_run(&mut state, &memory)
            .unwrap();
        WasmCodeCache::new(right.clone())
            .try_run(&mut state, &memory)
            .unwrap();
        assert_eq!(left.prepares.load(Ordering::Relaxed), 1);
        assert_eq!(right.prepares.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn u14_bridge_prepare_failure_never_executes_or_changes_state() {
        struct Reject;
        impl ExecutionBridge for Reject {
            fn prepare(&self, _: u32, _: &[u8]) -> bool {
                false
            }
            fn execute(&self, _: u32, _: &[u8], _: &mut JitState) -> bool {
                panic!("unprepared execution");
            }
        }
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(4096)),
                4096,
                Prot::READ_EXEC,
                MappingKind::ElfSegment,
            )
            .unwrap();
        memory
            .write_initial(GuestAddr(4096), &[0xb8, 42, 0, 0, 0, 0xc3])
            .unwrap();
        let cache = WasmCodeCache::new(Arc::new(Reject));
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        let before = state.clone();
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
        assert_eq!(cache.statistics().executed_blocks, 0);
    }

    #[test]
    fn u14_bridge_write_during_prepare_invalidates_before_execution() {
        struct Mutate(Arc<AddressSpace>);
        impl ExecutionBridge for Mutate {
            fn prepare(&self, _: u32, _: &[u8]) -> bool {
                let memory = self.0.clone();
                let (send, receive) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    memory.write(GuestAddr(4096), &[0xcc]).unwrap();
                    send.send(()).unwrap();
                });
                receive
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .expect("compilation must not hold MMU guard");
                worker.join().unwrap();
                true
            }
            fn execute(&self, _: u32, _: &[u8], _: &mut JitState) -> bool {
                panic!("stale prepared execution");
            }
        }
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(4096)),
                4096,
                Prot::from_bits(7).unwrap(),
                MappingKind::ElfSegment,
            )
            .unwrap();
        memory
            .write_initial(GuestAddr(4096), &[0xb8, 42, 0, 0, 0, 0xc3])
            .unwrap();
        let memory = Arc::new(memory);
        let cache = WasmCodeCache::new(Arc::new(Mutate(memory.clone())));
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        let before = state.clone();
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
        assert_eq!(cache.statistics().executed_blocks, 0);
    }
    #[test]
    fn u14_bridge_short_selection_fallback_preserves_state_and_counts() {
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(4096)),
                4096,
                Prot::READ_EXEC,
                MappingKind::ElfSegment,
            )
            .unwrap();
        memory
            .write_initial(GuestAddr(4096), &[0xb8, 42, 0, 0, 0, 0xc3])
            .unwrap();
        let cache = WasmCodeCache::new(Arc::new(NodeBridge)).with_minimum_block(2);
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        let before = state.clone();
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        assert_eq!(state, before);
        let statistics = cache.statistics();
        assert_eq!(statistics.translated_blocks, 0);
        assert_eq!(statistics.executed_blocks, 0);
        assert_eq!(statistics.fallbacks, 2);
        assert_eq!(cache.minimum_block, 2);
        assert_eq!(
            WasmCodeCache::new(Arc::new(NodeBridge))
                .with_minimum_block(0)
                .minimum_block,
            1
        );
        assert_eq!(
            WasmCodeCache::new(Arc::new(NodeBridge))
                .with_minimum_block(usize::MAX)
                .minimum_block,
            64
        );
    }
    fn admission_fixture(bytes: &[u8]) -> AddressSpace {
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
        memory
    }
    #[test]
    fn u14_admission_three_rejects_two_without_preparing_or_mutating() {
        let memory = admission_fixture(&[0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0xc3]);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge)).with_minimum_block(3);
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        let before = state.clone();
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        assert_eq!(state, before);
        assert_eq!(cache.statistics().translated_blocks, 0);
    }
    #[test]
    fn u14_admission_three_accepts_three_actual_wasm_instructions() {
        let memory = admission_fixture(&[
            0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 1, 0xc3,
        ]);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge)).with_minimum_block(3);
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        assert_eq!(cache.try_run_counted(&mut state, &memory).unwrap().1, 3);
        assert_eq!(state.gpr[0], 44);
        assert_eq!(state.rip.0, 4109);
    }
    #[test]
    fn u14_admission_three_rejected_bytes_change_can_become_eligible() {
        let memory = admission_fixture(&[0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0xc3]);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge)).with_minimum_block(3);
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(8192));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        memory
            .write_initial(
                GuestAddr(4096),
                &[
                    0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 1, 0xc3,
                ],
            )
            .unwrap();
        assert_eq!(cache.try_run_counted(&mut state, &memory).unwrap().1, 3);
        assert_eq!(state.gpr[0], 44);
    }
    impl ExecutionBridge for NodeBridge {
        fn execute(&self, _id: u32, wasm: &[u8], state: &mut JitState) -> bool {
            match node_run_many(&[(wasm.to_vec(), *state)]).pop().flatten() {
                Some(values) => {
                    *state = values;
                    true
                }
                None => false,
            }
        }
    }
    /// Runs every module on a fresh copy of its scratch in one real Node
    /// process (actual V8 WebAssembly, shared memory, SIMD). `None` is a
    /// rejected or trapping module whose scratch must not be committed.
    fn node_run_many(cases: &[(Vec<u8>, JitState)]) -> Vec<Option<JitState>> {
        let Ok(node) = std::env::var("PALUDARIUM_TEST_NODE") else {
            panic!("PALUDARIUM_TEST_NODE must name actual current Node executable");
        };
        let script = "import{readFileSync}from'node:fs';const lines=readFileSync(0,'utf8').trim().split('\\n');const memory=new WebAssembly.Memory({initial:1,maximum:65536,shared:true});const state=new BigUint64Array(memory.buffer,64,50);const out=[];for(let i=0;i<lines.length;i+=2){state.set(lines[i+1].split(',').map(BigInt));try{const instance=new WebAssembly.Instance(new WebAssembly.Module(Uint8Array.from(Buffer.from(lines[i],'hex'))),{env:{memory}});out.push(instance.exports.run(64)===0?Array.from(state,String).join(','):'fail');}catch{out.push('fail');}}console.log(out.join('\\n'));";
        let mut child = Command::new(node)
            .args(["--input-type=module", "-e", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = String::new();
        for (wasm, state) in cases {
            let hex: String = wasm.iter().map(|byte| format!("{byte:02x}")).collect();
            let values = state.map(|word| word.to_string()).join(",");
            input.push_str(&format!("{hex}\n{values}\n"));
        }
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "Node batch runner failed");
        let text = String::from_utf8(output.stdout).unwrap();
        let rows: Vec<Option<JitState>> = text
            .trim()
            .split('\n')
            .map(|row| {
                (row != "fail").then(|| {
                    let words: Vec<u64> = row.split(',').map(|w| w.parse().unwrap()).collect();
                    words.try_into().unwrap()
                })
            })
            .collect();
        assert_eq!(rows.len(), cases.len());
        rows
    }
    fn machine(code: &[u8], rax: u64) -> (CpuState, AddressSpace) {
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(4096)),
                8192,
                Prot::from_bits(7).unwrap(),
                MappingKind::ElfSegment,
            )
            .unwrap();
        memory.write_initial(GuestAddr(4096), code).unwrap();
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(12288));
        state.gpr[0] = rax;
        (state, memory)
    }
    fn differential(code: &[u8], rax: u64, instructions: u64) {
        let (mut state, memory) = machine(code, rax);
        let mut expected = state.clone();
        paludarium_cpu::run(&mut expected, &memory, instructions);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert_eq!(state, expected);
        assert_eq!(cache.statistics().executed_instructions, instructions);
    }
    #[test]
    fn u14_bridge_real_wasm_mov_matches_interpreter() {
        differential(
            &[
                0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1, 0xc3,
            ],
            0,
            1,
        );
    }
    #[test]
    fn u14_bridge_real_wasm_add_carry_matches_interpreter() {
        differential(&[0x48, 0x83, 0xc0, 1, 0xc3], u64::MAX, 1);
    }
    #[test]
    fn u14_bridge_real_wasm_sub_overflow_matches_interpreter() {
        differential(&[0x48, 0x83, 0xe8, 1, 0xc3], 1 << 63, 1);
    }
    #[test]
    fn u14_bridge_real_wasm_compare_and_branch_matches_interpreter() {
        for rax in [7, 8] {
            differential(
                &[0x48, 0x83, 0xf8, 7, 0x75, 6, 0xb8, 42, 0, 0, 0, 0xc3],
                rax,
                2,
            );
        }
    }
    fn observed_je(rax: u64, next: u64, flags: u64) {
        let (mut state, memory) = machine(
            &[
                0x48, 0x83, 0xf8, 7, 0x74, 6, 0xb8, 42, 0, 0, 0, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3,
            ],
            rax,
        );
        let mut expected = state.clone();
        paludarium_cpu::run(&mut expected, &memory, 2);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        let (_, count) = cache.try_run_counted(&mut state, &memory).unwrap();
        assert_eq!(count, 2);
        assert_eq!(state, expected);
        assert_eq!(state.rip, GuestAddr(4096 + next));
        assert_eq!(state.rflags & 0x8d5, flags);
        assert_eq!(cache.statistics().executed_blocks, 1);
        assert_eq!(cache.statistics().executed_instructions, 2);
        paludarium_cpu::run(&mut state, &memory, 1);
        assert_eq!(state.gpr[0], if rax == 7 { 9 } else { 42 });
    }
    #[test]
    fn u14_bridge_real_wasm_je_zf1_taken_matches_fresh_native() {
        // c3df1156 native13 oracle: input7 => RAX9, arithmetic flags0x44.
        observed_je(7, 12, 0x44);
    }
    #[test]
    fn u14_bridge_real_wasm_je_zf0_not_taken_matches_fresh_native() {
        // c3df1156 native13 oracle: input8 => RAX42, arithmetic flags0.
        observed_je(8, 6, 0);
    }
    #[test]
    fn u14_bridge_unsupported_fallback_leaves_all_state_untouched() {
        // PXOR xmm0, [rdi]: memory operands stay with the interpreter.
        let (mut state, memory) = machine(&[0x66, 0x0f, 0xef, 0x07], 17);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, true));
        assert_eq!(state, before);
        assert_eq!(cache.statistics().executed_blocks, 0);
    }
    #[test]
    fn u14_bridge_failure_rolls_back_cpu_state() {
        struct Failing;
        impl ExecutionBridge for Failing {
            fn execute(&self, _: u32, _: &[u8], state: &mut JitState) -> bool {
                state.fill(u64::MAX);
                false
            }
        }
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 17);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Failing));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
    }
    #[test]
    fn u14_bridge_real_wasm_self_modification_recompiles() {
        let (mut state, memory) = machine(&[0xb8, 42, 0, 0, 0], 17);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert_eq!(state.gpr[0], 42);
        memory.write(GuestAddr(4097), &[17]).unwrap();
        state.rip = GuestAddr(4096);
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert_eq!(state.gpr[0], 17);
        assert_eq!(cache.statistics().translated_blocks, 2);
    }

    // ----- Loop-back 1 Step33: XMM scratch state, transfer and rollback -----

    /// Deterministic distinct 128-bit patterns (splitmix64 halves).
    fn pattern(seed: u64) -> u128 {
        let mix = |mut z: u64| {
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let low = mix(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1));
        let high = mix(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(2));
        (u128::from(high) << 64) | u128::from(low)
    }
    fn patterned_state(seed: u64) -> CpuState {
        let mut state = CpuState::new(GuestAddr(4096), GuestAddr(12288));
        for (index, register) in state.gpr.iter_mut().enumerate() {
            *register = pattern(seed + index as u64) as u64;
        }
        for (index, register) in state.xmm.iter_mut().enumerate() {
            *register = pattern(seed + 100 + index as u64);
        }
        state.rflags = 0x8d5 | 0x202;
        state.fs_base = 0x1111;
        state.gs_base = 0x2222;
        state.mxcsr = 0x1f80 | 0x3f;
        state
    }

    #[test]
    fn u14_state_layout_places_gpr_flags_rip_then_xmm_pairs() {
        let state = patterned_state(1);
        let scratch = scratch_from(&state);
        assert_eq!(scratch[..16], state.gpr);
        assert_eq!(scratch[16], state.rflags);
        assert_eq!(scratch[17], state.rip.0);
        for index in 0..16 {
            assert_eq!(scratch[18 + index * 2], state.xmm[index] as u64);
            assert_eq!(scratch[19 + index * 2], (state.xmm[index] >> 64) as u64);
        }
    }
    #[test]
    fn u14_state_round_trip_is_identity() {
        for seed in 0..32 {
            let state = patterned_state(seed);
            let mut target = CpuState::default();
            commit(&mut target, &scratch_from(&state));
            assert_eq!(target.gpr, state.gpr);
            assert_eq!(target.xmm, state.xmm);
            assert_eq!(target.rflags, state.rflags);
            assert_eq!(target.rip, state.rip);
        }
    }
    #[test]
    fn u14_state_commit_keeps_registers_outside_scratch() {
        let mut state = patterned_state(2);
        let before = state.clone();
        let mut scratch = scratch_from(&state);
        scratch[0] ^= 1;
        commit(&mut state, &scratch);
        assert_eq!(state.fs_base, before.fs_base);
        assert_eq!(state.gs_base, before.gs_base);
        assert_eq!(state.mxcsr, before.mxcsr);
        assert_eq!(state.rep_fault_flags, before.rep_fault_flags);
        assert_eq!(state.repeat_continuation, before.repeat_continuation);
        assert_eq!(state.gpr[0], before.gpr[0] ^ 1);
    }
    #[test]
    fn u14_state_xmm_low_and_high_halves_are_not_swapped() {
        let mut state = CpuState::default();
        state.xmm[5] = (0xaaaa_aaaa_aaaa_aaaa_u128 << 64) | 0x5555_5555_5555_5555;
        let scratch = scratch_from(&state);
        assert_eq!(scratch[18 + 10], 0x5555_5555_5555_5555);
        assert_eq!(scratch[18 + 11], 0xaaaa_aaaa_aaaa_aaaa);
        let mut swapped = scratch;
        swapped.swap(28, 29);
        let mut target = state.clone();
        commit(&mut target, &swapped);
        assert_ne!(target.xmm[5], state.xmm[5]);
        commit(&mut target, &scratch);
        assert_eq!(target.xmm[5], state.xmm[5]);
    }
    #[test]
    fn u14_state_each_xmm_word_belongs_to_one_register() {
        for word in 18..STATE_WORDS {
            let state = CpuState::default();
            let mut scratch = scratch_from(&state);
            scratch[word] = u64::MAX;
            let mut target = state.clone();
            commit(&mut target, &scratch);
            let register = (word - 18) / 2;
            for (index, value) in target.xmm.iter().enumerate() {
                let expected = if index != register {
                    0
                } else if word % 2 == 0 {
                    u128::from(u64::MAX)
                } else {
                    u128::from(u64::MAX) << 64
                };
                assert_eq!(*value, expected, "word {word} xmm{index}");
            }
            assert_eq!(target.gpr, state.gpr);
        }
    }
    #[test]
    fn u14_state_last_register_occupies_last_words() {
        let mut state = CpuState::default();
        state.xmm[15] = u128::MAX - 1;
        let scratch = scratch_from(&state);
        assert_eq!(scratch[48], u64::MAX - 1);
        assert_eq!(scratch[49], u64::MAX);
        assert!(scratch[18..48].iter().all(|word| *word == 0));
    }
    #[test]
    fn u14_state_scratch_is_an_independent_copy() {
        let mut state = patterned_state(3);
        let scratch = scratch_from(&state);
        state.xmm[0] = 0;
        state.gpr[0] = 0;
        assert_ne!(scratch, scratch_from(&state));
        assert_eq!(scratch[18], patterned_state(3).xmm[0] as u64);
        assert_eq!(scratch[0], patterned_state(3).gpr[0]);
    }

    // ABI layout shared by bridge.rs, emit.rs, paludarium-wasm abi.rs and
    // packages/paludarium-wasm/jit-support.mjs.
    #[test]
    fn u14_abi_state_is_four_hundred_bytes() {
        assert_eq!(STATE_WORDS, 50);
        assert_eq!(STATE_BYTES, 400);
        assert_eq!(std::mem::size_of::<JitState>(), STATE_BYTES);
    }
    #[test]
    fn u14_abi_keeps_original_144_byte_prefix() {
        assert_eq!(XMM_OFFSET, 144);
        assert_eq!(RFLAGS_WORD * 8, 128);
        assert_eq!(RIP_WORD * 8, 136);
    }
    #[test]
    fn u14_abi_xmm_bytes_are_little_endian_u128() {
        let state = patterned_state(4);
        let bytes: Vec<u8> = scratch_from(&state)
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        for (index, value) in state.xmm.iter().enumerate() {
            let offset = XMM_OFFSET + index * 16;
            assert_eq!(
                bytes[offset..offset + 16],
                value.to_le_bytes(),
                "xmm{index}"
            );
        }
    }
    #[test]
    fn u14_abi_emitted_offsets_match_transfer_layout() {
        for register in 0..16u8 {
            let block = block::Block {
                entry: 4096,
                end: 4100,
                operations: vec![block::Operation::Vector {
                    kind: block::Vector::Move,
                    destination: register,
                    source: register,
                }],
            };
            let code = emit::emit(&block).unwrap();
            let offset = XMM_OFFSET + usize::from(register) * 16;
            // v128.load/v128.store, align 3, LEB128 offset.
            let mut memarg = vec![3];
            let mut value = offset;
            loop {
                let byte = (value & 127) as u8;
                value >>= 7;
                memarg.push(byte | if value == 0 { 0 } else { 128 });
                if value == 0 {
                    break;
                }
            }
            for opcode in [0x00, 0x0b] {
                let mut needle = vec![0xfd, opcode];
                needle.extend(&memarg);
                assert!(
                    code.windows(needle.len()).any(|w| w == needle),
                    "xmm{register} opcode {opcode}"
                );
            }
        }
    }
    #[test]
    fn u14_abi_javascript_import_uses_same_state_length() {
        let support = include_str!("../../../packages/paludarium-wasm/jit-support.mjs");
        assert!(support.contains(&format!("export const JIT_STATE_BYTES = {STATE_BYTES};")));
        assert!(support.contains("stateLength !== JIT_STATE_BYTES"));
        assert!(support.contains("new Uint8Array(JIT_STATE_BYTES)"));
        assert!(!support.contains("Uint8Array(144)") && !support.contains("!== 144"));
    }
    #[test]
    fn u14_abi_worker_bridge_passes_state_bytes_constant() {
        let abi = include_str!("../../paludarium-wasm/src/abi.rs");
        assert_eq!(abi.matches("paludarium_jit::STATE_BYTES").count(), 2);
        assert!(!abi.contains("state.as_mut_ptr(), 144"));
        assert_eq!(abi.matches("&mut paludarium_jit::JitState").count(), 2);
    }
    #[test]
    fn u14_abi_module_signature_and_memory_import_are_unchanged() {
        let block = block::extract(&[0x66, 0x0f, 0xfe, 0xc1], 4096).unwrap();
        let code = emit::emit(&block).unwrap();
        assert!(code.starts_with(b"\0asm\x01\0\0\0"));
        // type section: one func (i32) -> i32; import env.memory shared.
        assert_eq!(&code[8..15], &[1, 6, 1, 0x60, 1, 0x7f, 1]);
        let import = b"\x03env\x06memory\x02\x03\x01\x80\x80\x04";
        assert!(code.windows(import.len()).any(|w| w == import));
        let export = b"\x07\x07\x01\x03run\x00\x00";
        assert!(code.windows(export.len()).any(|w| w == export));
    }

    struct Scribble(bool);
    impl ExecutionBridge for Scribble {
        fn execute_ready(&self, _: u32, _: &[u8], state: &mut JitState) -> Option<bool> {
            if self.0 {
                state[18..].fill(0xdead_beef);
                return Some(false);
            }
            None
        }
        fn execute(&self, _: u32, _: &[u8], state: &mut JitState) -> bool {
            state.fill(u64::MAX);
            false
        }
    }
    fn sse_machine(code: &[u8], seed: u64) -> (CpuState, AddressSpace) {
        let (_, memory) = machine(code, 0);
        (patterned_state(seed), memory)
    }
    #[test]
    fn u14_rollback_failed_execute_keeps_all_registers() {
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfe, 0xc1, 0xc3], 5);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Scribble(false)));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
    }
    #[test]
    fn u14_rollback_failed_ready_execution_keeps_xmm() {
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfe, 0xc1, 0xc3], 6);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Scribble(true)));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
        assert_eq!(cache.statistics().executed_blocks, 0);
    }
    #[test]
    fn u14_rollback_prepare_rejection_keeps_xmm() {
        struct Reject;
        impl ExecutionBridge for Reject {
            fn prepare(&self, _: u32, _: &[u8]) -> bool {
                false
            }
            fn execute(&self, _: u32, _: &[u8], _: &mut JitState) -> bool {
                panic!("unprepared execution");
            }
        }
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xef, 0xc0, 0xc3], 7);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Reject));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
    }
    #[test]
    fn u14_rollback_write_during_prepare_keeps_xmm() {
        struct Mutate(Arc<AddressSpace>);
        impl ExecutionBridge for Mutate {
            fn prepare(&self, _: u32, _: &[u8]) -> bool {
                self.0.write(GuestAddr(4098), &[0xfa]).unwrap();
                true
            }
            fn execute(&self, _: u32, _: &[u8], _: &mut JitState) -> bool {
                panic!("stale prepared execution");
            }
        }
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfe, 0xc1, 0xc3], 8);
        let memory = Arc::new(memory);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Mutate(memory.clone())));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
    }
    /// Replaces the final `i32.const 0; end` with `unreachable; nop; end`:
    /// the module traps after every XMM store has already happened.
    fn trapping(mut wasm: Vec<u8>) -> Vec<u8> {
        let length = wasm.len();
        assert_eq!(&wasm[length - 3..], &[0x41, 0, 0x0b]);
        wasm[length - 3] = 0x00;
        wasm[length - 2] = 0x01;
        wasm
    }
    #[test]
    fn u14_rollback_real_wasm_partial_trap_commits_nothing() {
        struct Trap;
        impl ExecutionBridge for Trap {
            fn execute(&self, id: u32, wasm: &[u8], state: &mut JitState) -> bool {
                NodeBridge.execute(id, &trapping(wasm.to_vec()), state)
            }
        }
        // Three stores (xmm0, xmm2, xmm4) before the trap.
        let code = [
            0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0xef, 0xd3, 0x66, 0x0f, 0x6f, 0xe5, 0xc3,
        ];
        let (mut state, memory) = sse_machine(&code, 9);
        let before = state.clone();
        let cache = WasmCodeCache::new(Arc::new(Trap));
        assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
        assert_eq!(state, before);
        // The same module without the trap commits all three stores.
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        let mut expected = before.clone();
        paludarium_cpu::run(&mut expected, &memory, 3);
        assert_eq!(cache.try_run_counted(&mut state, &memory).unwrap().1, 3);
        assert_eq!(state, expected);
    }
    #[test]
    fn u14_rollback_real_wasm_trap_scratch_is_never_returned() {
        let block = block::extract(&[0x66, 0x0f, 0xfe, 0xc1], 4096).unwrap();
        let wasm = emit::emit(&block).unwrap();
        let state = scratch_from(&patterned_state(10));
        let results = node_run_many(&[(trapping(wasm.clone()), state), (wasm, state)]);
        assert_eq!(results[0], None);
        let committed = results[1].unwrap();
        assert_ne!(committed[18..20], state[18..20]);
        assert_eq!(committed[..17], state[..17]);
        assert_eq!(committed[17], 4100);
        assert_eq!(committed[20..], state[20..]);
    }
    #[test]
    fn u14_rollback_sequential_failures_restore_each_pattern() {
        for seed in 11..15 {
            let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfa, 0xc1, 0xc3], seed);
            let before = state.clone();
            let cache = WasmCodeCache::new(Arc::new(Scribble(seed % 2 == 0)));
            for _ in 0..3 {
                assert_eq!(cache.try_run_with_hint(&mut state, &memory), (None, false));
                assert_eq!(state, before);
            }
        }
    }

    // ----- Loop-back 1 Step34: integer-SSE translation against interpreter -----

    /// Every case: interpreter result and real-wasm result of the same block
    /// on the same patterned state, compared on the whole CPU state.
    fn sse_differential(cases: &[(Vec<u8>, CpuState)]) {
        let mut batch = Vec::new();
        let mut expected = Vec::new();
        for (code, state) in cases {
            let mut bytes = code.clone();
            bytes.push(0xc3);
            let (_, memory) = machine(&bytes, 0);
            let block = block::extract(code, 4096).unwrap();
            assert_eq!(block.end - block.entry, code.len() as u64, "{code:02x?}");
            assert!(
                block
                    .operations
                    .iter()
                    .all(|o| matches!(o, block::Operation::Vector { .. }))
            );
            let mut interpreted = state.clone();
            paludarium_cpu::run(&mut interpreted, &memory, block.operations.len() as u64);
            assert_eq!(interpreted.rip.0, 4096 + code.len() as u64);
            expected.push(interpreted);
            batch.push((emit::emit(&block).unwrap(), scratch_from(state)));
        }
        for (((code, state), interpreted), result) in
            cases.iter().zip(expected).zip(node_run_many(&batch))
        {
            let mut actual = state.clone();
            commit(&mut actual, &result.unwrap());
            assert_eq!(actual, interpreted, "{code:02x?}");
            assert_eq!(actual.rflags, state.rflags, "SSE keeps RFLAGS");
            assert_eq!(actual.gpr, state.gpr, "SSE keeps GPRs");
        }
    }
    fn modrm(destination: u8, source: u8) -> (Option<u8>, u8) {
        let rex = 0x40 | ((destination >> 3) << 2) | (source >> 3);
        (
            (rex != 0x40).then_some(rex),
            0xc0 | ((destination & 7) << 3) | (source & 7),
        )
    }
    fn encode(opcode: u8, destination: u8, source: u8, immediate: Option<u8>) -> Vec<u8> {
        let (rex, modrm) = modrm(destination, source);
        let mut bytes = vec![0x66];
        bytes.extend(rex);
        bytes.extend([0x0f, opcode, modrm]);
        bytes.extend(immediate);
        bytes
    }
    #[test]
    fn u14_sse_real_wasm_every_pshufd_imm8_matches_interpreter() {
        let cases: Vec<_> = (0..=255u8)
            .map(|selector| {
                let destination = selector % 16;
                let source = (selector / 16) % 16;
                (
                    encode(0x70, destination, source, Some(selector)),
                    patterned_state(u64::from(selector)),
                )
            })
            .collect();
        sse_differential(&cases);
    }
    #[test]
    fn u14_sse_real_wasm_shift_counts_at_and_above_32_clear_dwords() {
        let mut cases = Vec::new();
        for count in [0u8, 1, 7, 31, 32, 33, 63, 64, 128, 255] {
            for (extension, register) in [(6u8, 3u8), (2, 12)] {
                // 66 [REX.B] 0F 72 /6 ib (PSLLD) and /2 ib (PSRLD).
                let mut bytes = vec![0x66];
                if register >= 8 {
                    bytes.push(0x41);
                }
                bytes.extend([0x0f, 0x72, 0xc0 | (extension << 3) | (register & 7), count]);
                cases.push((bytes, patterned_state(u64::from(count) + 300)));
            }
        }
        sse_differential(&cases);
        let (code, state) = &cases[8]; // PSLLD count 32
        let block = block::extract(code, 4096).unwrap();
        let mut interpreted = state.clone();
        let (_, memory) = machine(&[code.as_slice(), &[0xc3][..]].concat(), 0);
        paludarium_cpu::run(&mut interpreted, &memory, block.operations.len() as u64);
        assert_eq!(interpreted.xmm[3], 0);
    }
    #[test]
    fn u14_sse_real_wasm_packuswb_saturates_like_interpreter() {
        let words = |values: [u16; 8]| {
            values
                .iter()
                .enumerate()
                .fold(0u128, |acc, (n, v)| acc | (u128::from(*v) << (n * 16)))
        };
        let inputs = [
            words([0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000]),
            words([
                0xffff, 0xff00, 0x00ff, 0x0101, 0x8001, 0x1234, 0xfffe, 0x00fe,
            ]),
        ];
        let mut cases = Vec::new();
        for (index, (destination, source)) in [(0u8, 1u8), (1, 0), (9, 14), (2, 2)]
            .into_iter()
            .enumerate()
        {
            let mut state = patterned_state(400 + index as u64);
            state.xmm[usize::from(destination)] = inputs[index % 2];
            if source != destination {
                state.xmm[usize::from(source)] = inputs[(index + 1) % 2];
            }
            cases.push((encode(0x67, destination, source, None), state));
        }
        sse_differential(&cases);
    }
    #[test]
    fn u14_sse_real_wasm_binary_forms_and_all_registers_match_interpreter() {
        let mut cases = Vec::new();
        for opcode in [0x6f, 0x7f, 0xdb, 0xeb, 0xef, 0xfe, 0xfa, 0xf4, 0x62, 0x67] {
            for (destination, source) in [(0u8, 1u8), (15, 0), (7, 8), (13, 13)] {
                let seed = u64::from(opcode) * 64 + u64::from(destination) * 16 + u64::from(source);
                cases.push((
                    encode(opcode, destination, source, None),
                    patterned_state(seed),
                ));
            }
        }
        sse_differential(&cases);
    }
    #[test]
    fn u14_sse_real_wasm_wraparound_and_pmuludq_edges_match_interpreter() {
        let dwords = |values: [u32; 4]| {
            values
                .iter()
                .enumerate()
                .fold(0u128, |acc, (n, v)| acc | (u128::from(*v) << (n * 32)))
        };
        let maximum = dwords([u32::MAX; 4]);
        let mixed = dwords([1, 0x8000_0000, u32::MAX, 0x7fff_ffff]);
        let mut cases = Vec::new();
        for opcode in [0xfe, 0xfa, 0xf4, 0x62] {
            for (a, b) in [(maximum, maximum), (mixed, maximum), (0, mixed), (mixed, 1)] {
                let mut state = patterned_state(u64::from(opcode));
                state.xmm[0] = a;
                state.xmm[1] = b;
                cases.push((encode(opcode, 0, 1, None), state));
            }
        }
        sse_differential(&cases);
    }
    #[test]
    fn u14_sse_real_wasm_long_block_of_every_form_matches_interpreter() {
        let mut code = Vec::new();
        for (index, opcode) in [
            0xfe, 0x70, 0xf4, 0x62, 0xfa, 0x67, 0xdb, 0xeb, 0xef, 0x6f, 0x7f,
        ]
        .into_iter()
        .cycle()
        .take(40)
        .enumerate()
        {
            let destination = (index * 5 % 16) as u8;
            let source = (index * 3 % 16) as u8;
            let immediate = (opcode == 0x70).then_some((index as u8).wrapping_mul(37));
            code.extend(encode(opcode, destination, source, immediate));
        }
        code.extend([0x66, 0x0f, 0x72, 0xf6, 5, 0x66, 0x41, 0x0f, 0x72, 0xd1, 9]);
        sse_differential(&[(code, patterned_state(777))]);
    }
    #[test]
    fn u14_sse_cache_runs_translated_block_and_counts_instructions() {
        // movdqa xmm1,xmm2 ; paddd xmm1,xmm3 ; pslld xmm1,4 ; ret
        let code = [
            0x66, 0x0f, 0x6f, 0xca, 0x66, 0x0f, 0xfe, 0xcb, 0x66, 0x0f, 0x72, 0xf1, 4, 0xc3,
        ];
        let (mut state, memory) = sse_machine(&code, 20);
        let mut expected = state.clone();
        paludarium_cpu::run(&mut expected, &memory, 3);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge)).with_minimum_block(3);
        assert_eq!(cache.try_run_counted(&mut state, &memory).unwrap().1, 3);
        assert_eq!(state, expected);
        let statistics = cache.statistics();
        assert_eq!(statistics.executed_blocks, 1);
        assert_eq!(statistics.executed_instructions, 3);
    }
    #[test]
    fn u14_sse_memory_operand_falls_back_without_state_change() {
        for code in [
            &[0x66, 0x0f, 0xfe, 0x07, 0xc3][..],   // PADDD xmm0,[rdi]
            &[0x66, 0x0f, 0x7f, 0x07, 0xc3],       // MOVDQA [rdi],xmm0
            &[0xc5, 0xf9, 0xfe, 0xc1, 0xc3],       // VEX
            &[0x64, 0x66, 0x0f, 0xfe, 0xc1, 0xc3], // FS prefix
            &[0x66, 0x0f, 0xf2, 0xc1, 0xc3],       // PSLLD xmm,xmm
        ] {
            let (mut state, memory) = sse_machine(code, 21);
            let before = state.clone();
            let cache = WasmCodeCache::new(Arc::new(NodeBridge));
            assert_eq!(
                cache.try_run_with_hint(&mut state, &memory),
                (None, true),
                "{code:02x?}"
            );
            assert_eq!(state, before);
            assert_eq!(cache.statistics().translated_blocks, 0);
        }
    }
    #[test]
    fn u14_sse_block_stops_before_memory_form_and_interpreter_continues() {
        // paddd xmm0,xmm1 ; paddd xmm0,[rdi] ; ret
        let code = [0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0xfe, 0x07, 0xc3];
        let (mut state, memory) = sse_machine(&code, 22);
        let mut expected = state.clone();
        paludarium_cpu::run(&mut expected, &memory, 1);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        assert_eq!(cache.try_run_counted(&mut state, &memory).unwrap().1, 1);
        assert_eq!(state, expected);
        assert_eq!(state.rip.0, 4100);
    }
    #[test]
    fn u14_sse_self_modifying_code_retranslates() {
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfe, 0xc1, 0xc3], 23);
        let initial = state.clone();
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        assert!(cache.try_run(&mut state, &memory).is_some());
        // PADDD -> PSUBD by rewriting the opcode byte.
        memory.write(GuestAddr(4098), &[0xfa]).unwrap();
        let mut expected = initial.clone();
        paludarium_cpu::run(&mut expected, &memory, 1);
        let mut state = initial;
        assert!(cache.try_run(&mut state, &memory).is_some());
        assert_eq!(state, expected);
        assert_eq!(cache.statistics().translated_blocks, 2);
    }
    #[test]
    fn u14_sse_epoch_change_requires_new_preparation() {
        let (mut state, memory) = sse_machine(&[0x66, 0x0f, 0xfe, 0xc1, 0xc3], 24);
        let bridge = Arc::new(WarmBridge::default());
        let cache = WasmCodeCache::new(bridge.clone());
        cache.try_run(&mut state, &memory).unwrap();
        state.rip = GuestAddr(4096);
        cache.try_run(&mut state, &memory).unwrap();
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 1);
        // A write elsewhere on the executable page changes the code epoch.
        memory.write(GuestAddr(4200), &[0x90]).unwrap();
        state.rip = GuestAddr(4096);
        cache.try_run(&mut state, &memory).unwrap();
        assert_eq!(bridge.prepares.load(Ordering::Relaxed), 2);
        assert_eq!(cache.statistics().translated_blocks, 2);
    }
    #[test]
    fn u14_sse_eviction_retranslates_with_same_result() {
        let (state, memory) = sse_machine(&[0x66, 0x0f, 0xf4, 0xc1, 0xc3], 25);
        let mut expected = state.clone();
        paludarium_cpu::run(&mut expected, &memory, 1);
        let cache = WasmCodeCache::new(Arc::new(NodeBridge));
        let mut first = state.clone();
        assert!(cache.try_run(&mut first, &memory).is_some());
        assert_eq!(first, expected);
        let (space, generation) = memory.code_epoch();
        for index in 0..1024u64 {
            assert!(
                cache
                    .cache
                    .insert(space, (1 << 32) | index, generation, 1, None)
            );
        }
        let mut second = state;
        assert!(cache.try_run(&mut second, &memory).is_some());
        assert_eq!(second, expected);
        assert_eq!(cache.statistics().translated_blocks, 2);
    }
}
