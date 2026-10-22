//! JIT code-cache interface for paludarium.
//!
//! The runtime asks the cache first and falls back to the interpreter when
//! it returns `None`. The core emulator ships only [`NoopCodeCache`], which
//! never has translated code; the JIT provides the wasm implementation.
#![forbid(unsafe_code)]

mod block;
mod bridge;
mod cache;
mod emit;
#[cfg(feature = "cost-profile")]
pub mod microbench;
pub use bridge::{
    ExecutionBridge, JitState, JitStatistics, STATE_BYTES, STATE_WORDS, WasmCodeCache,
};
#[cfg(feature = "cost-profile")]
pub use paludarium_cpu::jit_cost;

/// Bounded native sanitizer entry points; absent from production builds.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    /// Exercises actual extraction and wasm emission on untrusted code bytes.
    #[must_use]
    pub fn translate(bytes: &[u8], rip: u64) -> Option<Vec<u8>> {
        let block = super::block::extract(&bytes[..bytes.len().min(960)], rip)?;
        super::emit::emit(&block)
    }

    /// Exercises cache insert/hit/stale/invalidation with bounded keys.
    pub fn cache(bytes: &[u8]) {
        let cache = super::cache::EpochCache::new();
        let mut expected = std::collections::BTreeMap::new();
        for row in bytes.as_chunks::<4>().0.iter().take(512) {
            let space = u64::from(row[1] & 3);
            let rip = u64::from(row[2]) * 4096;
            let generation = u64::from(row[3]);
            match row[0] % 3 {
                0 => {
                    assert!(cache.insert(space, rip, generation, 1, generation));
                    expected.insert((space, rip), generation);
                }
                1 => {
                    let actual = cache.get(space, rip, generation);
                    let wanted = expected
                        .get(&(space, rip))
                        .copied()
                        .filter(|value| *value == generation);
                    assert_eq!(actual, wanted);
                    if wanted.is_none() {
                        expected.remove(&(space, rip));
                    }
                }
                _ => {
                    cache.invalidate(rip);
                    expected.retain(|&(_, address), _| address != rip);
                }
            }
        }
    }
}

use paludarium_cpu::CpuState;
use paludarium_mmu::AddressSpace;
use paludarium_types::{ExitReason, GuestAddr};

/// A cache of translated guest code.
pub trait CodeCache: Send + Sync {
    /// Whether a rejected boundary may remain interpreted until code changes.
    fn cache_rejections(&self) -> bool {
        false
    }
    /// Optional decoded-boundary filter. Existing caches see every boundary.
    fn eligible(&self, _instruction: &paludarium_decoder::Instruction) -> bool {
        true
    }
    /// Runs translated code for `state.rip` if there is any and returns why it
    /// stopped; `None` means "not translated, use the interpreter".
    fn try_run(&self, state: &mut CpuState, mem: &AddressSpace) -> Option<ExitReason>;
    /// Exact accounting when supported; existing implementations retain the
    /// historical conservative 64-instruction charge without API changes.
    fn try_run_counted(
        &self,
        state: &mut CpuState,
        mem: &AddressSpace,
    ) -> Option<(ExitReason, u64)> {
        self.try_run(state, mem).map(|reason| (reason, 64))
    }
    /// Negative hints are allowed only for deterministic unsupported/short code.
    fn try_run_with_hint(
        &self,
        state: &mut CpuState,
        mem: &AddressSpace,
    ) -> (Option<(ExitReason, u64)>, bool) {
        (self.try_run_counted(state, mem), false)
    }
    /// Discards translations of the page containing `page` (guest code was
    /// written).
    fn invalidate(&self, page: GuestAddr);
}

/// Cheap selection using the interpreter's already-decoded instruction. This
/// only rejects unsupported first instructions; translation still validates
/// every instruction and MMU epoch before any execution.
pub fn eligible_instruction(instruction: &paludarium_decoder::Instruction) -> bool {
    block::operation(instruction).is_some()
}

#[cfg(test)]
mod eligibility_tests {
    use super::*;
    fn check(bytes: &[u8], expected: bool) {
        let instruction = paludarium_decoder::decode(bytes, GuestAddr(4096)).unwrap();
        assert_eq!(eligible_instruction(&instruction), expected);
        assert_eq!(crate::block::extract(bytes, 4096).is_some(), expected);
    }
    #[test]
    fn eligible_mov_immediate() {
        check(&[0xb8, 42, 0, 0, 0], true);
    }
    #[test]
    fn eligible_arithmetic_immediate() {
        check(&[0x48, 0x83, 0xc0, 1], true);
    }
    #[test]
    fn eligible_je_and_jne() {
        check(&[0x74, 0], true);
        check(&[0x75, 0], true);
    }
    #[test]
    fn eligible_rejects_memory() {
        check(&[0x48, 0x8b, 7], false);
    }
    #[test]
    fn eligible_rejects_syscall() {
        check(&[0x0f, 5], false);
    }
    #[test]
    fn eligible_sse_register_only_and_rejects_return() {
        check(&[0x66, 0x0f, 0xef, 0x07], false);
        check(&[0x66, 0x0f, 0xef, 0xc0], true);
        check(&[0xc3], false);
    }
    #[test]
    fn eligible_rejects_wrong_width_or_condition() {
        check(&[0x83, 0xc0, 1], false);
        check(&[0x77, 0], false);
    }
}

/// The code cache used when there is no JIT (always native in the core emulator).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCodeCache;

impl CodeCache for NoopCodeCache {
    fn try_run(&self, _state: &mut CpuState, _mem: &AddressSpace) -> Option<ExitReason> {
        None
    }

    fn invalidate(&self, _page: GuestAddr) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_cache_never_runs_code_and_leaves_state_alone() {
        let cache = NoopCodeCache;
        let mut state = CpuState::new(GuestAddr(0x401000), GuestAddr(0x7000));
        let before = state.clone();
        assert_eq!(cache.try_run(&mut state, &AddressSpace::new()), None);
        assert_eq!(state, before);
    }

    #[test]
    fn noop_cache_invalidate_is_harmless() {
        let cache = NoopCodeCache;
        cache.invalidate(GuestAddr(0));
        cache.invalidate(GuestAddr(u64::MAX));
        assert_eq!(
            cache.try_run(&mut CpuState::default(), &AddressSpace::new()),
            None
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let cache: Box<dyn CodeCache> = Box::new(NoopCodeCache);
        assert!(
            cache
                .try_run(&mut CpuState::default(), &AddressSpace::new())
                .is_none()
        );
    }

    #[test]
    fn invalidation_and_fallback_preserve_guest_code() {
        use paludarium_mmu::{MappingKind, Prot};

        let cache = NoopCodeCache;
        let page = GuestAddr(0x401000);
        let mut mem = AddressSpace::new();
        assert!(
            mem.map(Some(page), 4096, Prot::READ_EXEC, MappingKind::ElfSegment)
                .is_ok()
        );
        assert!(mem.write_initial(page, &[0x0f, 0x05]).is_ok());
        let mut state = CpuState::new(page, GuestAddr(0x7000));
        let before = state.clone();
        cache.invalidate(page);
        assert_eq!(cache.try_run(&mut state, &mem), None);
        let mut code = [0; 2];
        assert!(mem.fetch(page, &mut code).is_ok());
        assert_eq!(code, [0x0f, 0x05]);
        assert_eq!(state, before);
    }

    #[test]
    fn shared_cache_supports_concurrent_fallback_and_invalidation() {
        let cache: std::sync::Arc<dyn CodeCache> = std::sync::Arc::new(NoopCodeCache);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|index| {
                    let cache = std::sync::Arc::clone(&cache);
                    scope.spawn(move || {
                        let mut state =
                            CpuState::new(GuestAddr(0x401000 + index * 4096), GuestAddr(0x7000));
                        let before = state.clone();
                        let mem = AddressSpace::new();
                        for _ in 0..32 {
                            cache.invalidate(state.rip);
                            assert_eq!(cache.try_run(&mut state, &mem), None);
                            assert_eq!(state, before);
                        }
                    })
                })
                .collect();
            for handle in handles {
                assert!(handle.join().is_ok());
            }
        });
    }
}
