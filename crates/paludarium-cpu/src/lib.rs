//! x86-64 interpreter for paludarium.
//!
//! [`run`] executes instructions on a [`CpuState`] until a system call, a
//! guest exception or the instruction budget stops it, and reports why as an
//! [`ExitReason`]. The CPU knows nothing about the kernel.
//! Instructions outside the implemented set stop with `InvalidOpcode`. The
//! implemented set is the one the core guests execute.
#![forbid(unsafe_code)]

mod alu;
pub mod compile;
#[cfg(test)]
mod counted_hook_tests;
mod cpuid;
mod crypto;
#[cfg(test)]
mod decode_cache_tests;
#[cfg(test)]
mod encodings_tests;
mod exec;
#[cfg(test)]
mod fast_tests;
#[cfg(test)]
mod instructions_tests;
#[cfg(test)]
mod integer_tests;
/// Opt-in diagnostic counters; absent from ordinary release builds.
#[cfg(feature = "cost-profile")]
pub mod jit_cost;
#[cfg(feature = "cost-profile")]
mod jit_cost_sites;
#[cfg(test)]
mod snapshot_tests;
mod softfloat;
mod sse;
mod state;
mod x87;

use paludarium_decoder::{DecodeError, Instruction, decode};
use paludarium_mmu::AddressSpace;
use paludarium_types::{ExitReason, GuestAddr, InstructionBytes, MAX_INSTRUCTION_LEN};

pub use alu::{condition, sign_extend, size_mask};
pub use state::{
    CpuState, FX_WRITTEN, INITIAL_MXCSR, INITIAL_RFLAGS, RepFaultFlags, RepeatContinuation, flag,
    reg,
};
pub use x87::X87;

use exec::Stop;

/// Number of slots a [`DecodeCache`] starts with, and of instructions it
/// has room for. With room for 4096 instructions, programs as large as jj
/// missed it on one instruction in nine, each miss decoding again. Each
/// slot takes 24 bytes and each instruction 152, 176 bytes in all as the
/// one-instruction slots before blocks did: 2.75 MiB per guest thread.
const INITIAL_ENTRIES: usize = 1 << 14;

/// The most slots, and instructions, a [`DecodeCache`] grows to: 22 MiB.
/// Perl compiling GNU parallel runs about 120,000 distinct instructions,
/// and with room for 16384 one lookup in seven found another instruction in
/// its slot; with room for 131072, one in fifty. The WebAssembly build keeps
/// the size it had, as each Worker's cache takes from the one shared heap.
#[cfg(not(target_family = "wasm"))]
const MAX_ENTRIES: usize = 1 << 17;
#[cfg(target_family = "wasm")]
const MAX_ENTRIES: usize = INITIAL_ENTRIES;

/// A [`DecodeCache`] decides whether to grow after this many lookups have
/// found another block in their slot.
const GROWTH_WINDOW: u64 = 1 << 16;

/// It doubles when more than one lookup in this many found another block
/// of the current code generation in its slot. A block left from before a
/// code change does not count, whatever its address: the lookup would miss
/// in a larger cache too.
const GROWTH_RATIO: u64 = 64;

/// The most instructions a block holds. The limit bounds the copies of
/// instructions that a jump into the middle of a block decodes again.
const MAX_BLOCK: usize = 32;

/// Decoded instructions by address, in blocks: a block holds instructions
/// that follow each other in memory, from the one at its address up to a
/// `jmp`, `call`, `ret`, `syscall` or other instruction after which the next
/// one in memory rarely runs ([`ends_block`]), or [`MAX_BLOCK`] of them. The
/// interpreter looks up the block of an address only when the instruction
/// it runs is not the next one in the current block (after a branch, a
/// system call or a fault, at the end of the block, or after a code
/// change), so falling through from one instruction to the next needs no
/// lookup. A block starts with its first instruction and grows as it runs:
/// an instruction is decoded, as it would be without blocks, when it first
/// runs after the last one of a block, and added to that block if it can
/// take it ([`DecodeCache::extend`]).
///
/// A block is used only while the address space's
/// [`AddressSpace::code_generation`] is unchanged, so writes to executable
/// memory that was fetched from and mapping changes (self-modifying code,
/// `mprotect`, `munmap`) are always seen. A cache serves one address space:
/// make a new one for another (as after `execve`).
///
/// It starts small, as most threads and processes run little code, and
/// doubles up to [`MAX_ENTRIES`] while the blocks a thread runs often keep
/// taking each other's slots, or fill the room for instructions.
pub struct DecodeCache {
    /// The blocks; a block's slot depends on its address only.
    slots: Vec<Slot>,
    /// The number of slots less one; their number is a power of two.
    mask: u64,
    /// The instructions of the blocks, each block's together. It holds at
    /// most as many as there are slots ([`Self::make_room`]).
    code: Code,
    growth: Growth,
    /// The compiled blocks that slots refer to ([`Slot::compiled`]).
    compiled: Vec<std::sync::Arc<dyn compile::CompiledBlock>>,
}

/// When a [`DecodeCache`] grows.
#[derive(Default)]
struct Growth {
    /// Lookups so far.
    lookups: u64,
    /// `lookups` when the current window started.
    window_start: u64,
    /// Lookups in the current window that found another block in their
    /// slot.
    collisions: u64,
    /// Set when a window decided to grow; done at the next lookup, when no
    /// instruction is borrowed.
    pending: bool,
}

impl Growth {
    /// Counts a lookup that found another block in its slot of a cache of
    /// `entries` slots.
    #[cold]
    fn collided(&mut self, entries: usize) {
        self.collisions += 1;
        if self.collisions < GROWTH_WINDOW {
            return;
        }
        let lookups = self.lookups.wrapping_sub(self.window_start);
        self.pending = entries < MAX_ENTRIES && lookups < GROWTH_WINDOW * GROWTH_RATIO;
        self.collisions = 0;
        self.window_start = self.lookups;
    }
}

impl Default for DecodeCache {
    fn default() -> Self {
        DecodeCache {
            slots: vec![Slot::default(); INITIAL_ENTRIES],
            mask: INITIAL_ENTRIES as u64 - 1,
            code: Code::with_capacity(INITIAL_ENTRIES),
            growth: Growth::default(),
            compiled: Vec::new(),
        }
    }
}

/// What running a decoded instruction needs first, worked out once when it
/// is decoded, in one 64-byte cache line (a test checks that it fits);
/// [`Code`] keeps the [`Instruction`] apart. An instruction that has a [`exec::Fast`] form runs from this alone.
#[derive(Clone, Copy)]
struct Decoded {
    /// The form [`exec::execute_fast`] runs, if it has one.
    fast: exec::Fast,
    /// [`Instruction::next_rip`].
    next: u64,
    /// [`exec::keeps_vector_state`].
    keeps_vector_state: bool,
    /// [`exec::fails_cleanly`]: no [`Snapshot`] is needed.
    fails_cleanly: bool,
}

impl Decoded {
    fn new(instruction: &Instruction) -> Self {
        Decoded {
            fast: exec::Fast::of(instruction),
            next: instruction.next_rip().0,
            keeps_vector_state: exec::keeps_vector_state(instruction),
            fails_cleanly: exec::fails_cleanly(instruction),
        }
    }
}

/// Decoded instructions: the [`Decoded`] part of each, which every run of
/// it reads, apart from the [`Instruction`], which only the general path
/// reads. Kept apart, the parts that a run of frequent forms reads lie
/// close together in host memory.
#[derive(Default)]
struct Code {
    decoded: Vec<Decoded>,
    /// The instruction of each of `decoded`, at the same index.
    instructions: Vec<Instruction>,
}

impl Code {
    fn with_capacity(n: usize) -> Self {
        Code {
            decoded: Vec::with_capacity(n),
            instructions: Vec::with_capacity(n),
        }
    }

    fn len(&self) -> usize {
        self.decoded.len()
    }

    fn push(&mut self, instruction: Instruction) {
        self.decoded.push(Decoded::new(&instruction));
        self.instructions.push(instruction);
    }

    fn truncate(&mut self, n: usize) {
        self.decoded.truncate(n);
        self.instructions.truncate(n);
    }

    fn clear(&mut self) {
        self.truncate(0);
    }

    /// Room for `n` instructions in all.
    fn reserve_to(&mut self, n: usize) {
        self.decoded
            .reserve_exact(n.saturating_sub(self.decoded.len()));
        self.instructions
            .reserve_exact(n.saturating_sub(self.instructions.len()));
    }
}

/// Whether the instruction after `insn` in memory starts a block rather
/// than following it in its own: after a jump, call, return, system call or
/// stop, the next instruction in memory runs, if ever, only after a branch
/// to it. A conditional branch does not end a block, as either way is
/// common.
fn ends_block(insn: &Instruction) -> bool {
    use paludarium_decoder::Mnemonic as M;
    matches!(
        insn.mnemonic,
        M::Jmp | M::Call | M::Ret | M::Syscall | M::Hlt | M::Ud2
    )
}

/// The block of instructions decoded from `rip` under `generation`, at
/// `start..start + len` of [`DecodeCache::code`]; empty when `len` is 0.
/// `rejected` when the accelerator has turned down its first instruction.
#[derive(Clone, Copy, Default)]
struct Slot {
    rip: u64,
    generation: u64,
    start: u32,
    len: u8,
    rejected: bool,
    /// How many times [`run_compiled`] has entered the block uncompiled.
    runs: u16,
    /// Its compiled code: 0 for none yet, [`NOT_COMPILED`] when the
    /// compiler turned it down, else one more than its index in
    /// [`DecodeCache::compiled`].
    compiled: u32,
}

/// [`Slot::compiled`] of a block the compiler turned down.
const NOT_COMPILED: u32 = u32::MAX;

/// The most compiled blocks a [`DecodeCache`] keeps; past it, all are
/// dropped and compiled again as they run.
const MAX_COMPILED: usize = 1 << 13;

impl Slot {
    fn holds(&self, rip: u64, generation: u64) -> bool {
        self.len > 0 && self.rip == rip && self.generation == generation
    }

    /// Whether it holds another block of `generation` than the one at
    /// `rip`.
    fn holds_other(&self, rip: u64, generation: u64) -> bool {
        self.len > 0 && self.rip != rip && self.generation == generation
    }

    fn range(&self) -> std::ops::Range<usize> {
        let start = self.start as usize;
        start..start + usize::from(self.len)
    }
}

impl DecodeCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The slot of `rip` in a cache whose slots less one are `mask`.
    fn slot_in(mask: u64, rip: u64) -> usize {
        // The number of slots is a power of two; the mask keeps the index
        // in range.
        usize::try_from((rip ^ (rip >> 12)) & mask).unwrap_or(0)
    }

    fn slot(&self, rip: u64) -> usize {
        Self::slot_in(self.mask, rip)
    }

    /// Counts a lookup, first doubling the cache if the last window decided
    /// to.
    #[inline]
    fn lookup(&mut self) {
        if self.growth.pending {
            self.grow();
        }
        self.growth.lookups = self.growth.lookups.wrapping_add(1);
    }

    /// Doubles the cache. The blocks move to their new slots, so none is
    /// decoded again.
    #[cold]
    #[inline(never)]
    fn grow(&mut self) {
        self.growth.pending = false;
        let mask = self.mask * 2 + 1;
        let mut slots = vec![Slot::default(); self.slots.len() * 2];
        for slot in self.slots.drain(..).filter(|s| s.len > 0) {
            slots[Self::slot_in(mask, slot.rip)] = slot;
        }
        self.slots = slots;
        self.mask = mask;
        self.code.reserve_to(self.slots.len());
    }

    /// Makes room in [`Self::code`] for a block of up to [`MAX_BLOCK`]
    /// instructions decoded under `generation`: doubles the cache if the
    /// blocks of `generation` fill more than half of it, and drops every
    /// block otherwise. Nothing is copied, and the room is not allocated
    /// again: a program that changes its code often, as SBCL does, fills the
    /// room with blocks of earlier generations again and again.
    #[cold]
    #[inline(never)]
    fn make_room(&mut self, generation: u64) {
        let current: usize = self
            .slots
            .iter()
            .filter(|s| s.len > 0 && s.generation == generation)
            .map(|s| usize::from(s.len))
            .sum();
        if current > self.slots.len() / 2 && self.slots.len() < MAX_ENTRIES {
            self.grow();
        }
        if self.code.len() + MAX_BLOCK > self.slots.len() {
            self.slots.fill(Slot::default());
            self.code.clear();
            self.compiled.clear();
        }
    }

    /// Stores the block whose instructions `decode` appends to
    /// [`Self::code`] (one at least, unless it fails) at `rip` under
    /// `generation`.
    fn insert(
        &mut self,
        rip: u64,
        generation: u64,
        decode: impl FnOnce(&mut Code) -> Result<(), ExitReason>,
    ) -> Result<std::ops::Range<usize>, ExitReason> {
        if self.code.len() + MAX_BLOCK > self.slots.len() {
            self.make_room(generation);
        }
        let start = self.code.len();
        if let Err(reason) = decode(&mut self.code) {
            self.code.truncate(start);
            return Err(reason);
        }
        let len = (self.code.len() - start).min(MAX_BLOCK);
        self.code.truncate(start + len);
        let slot = self.slot(rip);
        let entries = self.slots.len();
        let s = &mut self.slots[slot];
        if s.holds_other(rip, generation) {
            self.growth.collided(entries);
        }
        *s = Slot {
            rip,
            generation,
            start: u32::try_from(start).unwrap_or(u32::MAX),
            len: u8::try_from(len).unwrap_or(u8::MAX),
            rejected: false,
            runs: 0,
            compiled: 0,
        };
        Ok(s.range())
    }

    /// Where in [`Self::code`] the block at `rip` under `generation` is,
    /// decoded by `decode` unless the cache holds it. `decode` appends the
    /// block's instructions to the vector it is given, the first at `rip`.
    #[inline]
    fn block(
        &mut self,
        rip: u64,
        generation: u64,
        decode: impl FnOnce(&mut Code) -> Result<(), ExitReason>,
    ) -> Result<std::ops::Range<usize>, ExitReason> {
        self.lookup();
        let s = &self.slots[self.slot(rip)];
        if s.holds(rip, generation) {
            return Ok(s.range());
        }
        self.insert(rip, generation, decode)
    }

    /// Adds to the block at `rip` under `generation`, whose instructions end
    /// at `end` of [`Self::code`], the instruction that follows them, which
    /// `decode` decodes, unless the block cannot take it. It cannot when it
    /// is no longer in its slot, or holds [`MAX_BLOCK`] instructions, or ends
    /// with an instruction that [`ends_block`], or when another block has
    /// been stored after it or the room is full. Returns whether it took the
    /// instruction.
    fn extend(
        &mut self,
        rip: u64,
        end: usize,
        generation: u64,
        decode: impl FnOnce() -> Result<Instruction, ExitReason>,
    ) -> Result<bool, ExitReason> {
        let slot = self.slot(rip);
        let s = &self.slots[slot];
        if !s.holds(rip, generation)
            || s.range().end != end
            || end != self.code.len()
            || end >= self.slots.len()
            || usize::from(s.len) >= MAX_BLOCK
            || ends_block(&self.code.instructions[end - 1])
        {
            return Ok(false);
        }
        self.code.push(decode()?);
        self.slots[slot].len += 1;
        Ok(true)
    }

    /// Stores the instruction that a [`Self::get_with_hint`] after a
    /// [`Self::lookup`] did not find, as a block of its own.
    fn put(&mut self, rip: u64, generation: u64, instruction: Instruction) -> Decoded {
        let block = self.insert(rip, generation, |code| {
            code.push(instruction);
            Ok(())
        });
        // The decode above cannot fail, so the block holds the instruction.
        match block {
            Ok(block) => self.code.decoded[block.start],
            Err(_) => Decoded::new(&instruction),
        }
    }

    /// The first instruction of the block at `rip` under `generation`, and
    /// whether the accelerator has turned it down.
    fn get_with_hint(&self, rip: u64, generation: u64) -> Option<(Decoded, Instruction, bool)> {
        let s = &self.slots[self.slot(rip)];
        let start = s.start as usize;
        s.holds(rip, generation).then(|| {
            (
                self.code.decoded[start],
                self.code.instructions[start],
                s.rejected,
            )
        })
    }

    fn reject_acceleration(&mut self, rip: u64, generation: u64) {
        let slot = self.slot(rip);
        let s = &mut self.slots[slot];
        if s.holds(rip, generation) {
            s.rejected = true;
        }
    }

    #[cfg(feature = "cost-profile")]
    fn observe_slot(&self, rip: u64, generation: u64) {
        use jit_cost::{Counter, add};
        let s = &self.slots[self.slot(rip)];
        let counter = if s.len == 0 {
            Counter::DecodeSlotEmpty
        } else if s.rip != rip {
            Counter::DecodeSlotRipCollision
        } else if s.generation != generation {
            Counter::DecodeSlotEpochStale
        } else if s.rejected {
            Counter::DecodeHintHit
        } else {
            Counter::DecodedHit
        };
        add(counter, 1);
    }
}

/// The stop for the MMU fault `f` at `rip`: a bus error past the end of a
/// mapped file, else a page fault.
fn memory_fault(rip: GuestAddr, f: paludarium_mmu::Fault, write: bool, fetch: bool) -> ExitReason {
    if f.bus {
        ExitReason::BusError {
            rip,
            addr: f.addr,
            write,
            fetch,
            present: f.present,
        }
    } else {
        ExitReason::PageFault {
            rip,
            addr: f.addr,
            write,
            fetch,
            mapped: f.mapped,
            present: f.present,
        }
    }
}

fn fetch_and_decode(state: &CpuState, mem: &AddressSpace) -> Result<Instruction, ExitReason> {
    let rip = state.rip;
    let mut bytes = [0u8; MAX_INSTRUCTION_LEN];
    let available = mem
        .fetch_partial(rip, &mut bytes)
        .map_err(|f| memory_fault(rip, f, false, true))?;
    let fetched = &bytes[..available];
    match decode(fetched, rip) {
        Ok(insn) => Ok(insn),
        Err(DecodeError::NeedMoreBytes) if available < MAX_INSTRUCTION_LEN => {
            // The instruction runs into a page that cannot be executed.
            let addr = u64::try_from(available)
                .ok()
                .and_then(|n| rip.checked_add(n))
                .unwrap_or(rip);
            let fault = mem.fetch(addr, &mut [0]).err();
            Err(match fault {
                Some(f) => memory_fault(rip, paludarium_mmu::Fault { addr, ..f }, false, true),
                None => ExitReason::PageFault {
                    rip,
                    addr,
                    write: false,
                    fetch: true,
                    mapped: false,
                    present: false,
                },
            })
        }
        Err(_) => Err(ExitReason::InvalidOpcode {
            rip,
            bytes: InstructionBytes::new(fetched),
        }),
    }
}

fn instruction_bytes(mem: &AddressSpace, rip: GuestAddr, len: u8) -> InstructionBytes {
    let mut bytes = [0u8; MAX_INSTRUCTION_LEN];
    let n = usize::from(len).min(MAX_INSTRUCTION_LEN);
    let got = mem.fetch_partial(rip, &mut bytes[..n]).unwrap_or(0);
    InstructionBytes::new(&bytes[..got])
}

/// What a failed instruction puts back: the registers, and the vector
/// state unless the instruction leaves it alone
/// ([`exec::keeps_vector_state`]). Copying the whole state before every
/// instruction cost more than most instructions themselves. The repeated
/// comparison's continuation is not kept: a failure clears it.
struct Snapshot {
    gpr: [u64; 16],
    rip: GuestAddr,
    rflags: u64,
    fs_base: u64,
    gs_base: u64,
    vector: Option<([u128; 16], u32)>,
}

impl Snapshot {
    fn of(state: &CpuState, keeps_vector_state: bool) -> Self {
        // Every field is named, so that a new one has to be placed here.
        let CpuState {
            gpr,
            rip,
            rflags,
            fs_base,
            gs_base,
            xmm,
            mxcsr,
            // Its instructions change it after the last thing that can fail.
            x87: _,
            rep_fault_flags: _,
            repeat_continuation: _,
        } = *state;
        Snapshot {
            gpr,
            rip,
            rflags,
            fs_base,
            gs_base,
            vector: (!keeps_vector_state).then_some((xmm, mxcsr)),
        }
    }

    fn restore(self, state: &mut CpuState) {
        state.gpr = self.gpr;
        state.rip = self.rip;
        state.rflags = self.rflags;
        state.fs_base = self.fs_base;
        state.gs_base = self.gs_base;
        if let Some((xmm, mxcsr)) = self.vector {
            state.xmm = xmm;
            state.mxcsr = mxcsr;
        }
    }
}

fn execute_decoded(
    state: &mut CpuState,
    mem: &AddressSpace,
    decoded: &Decoded,
    insn: &Instruction,
) -> Result<(), ExitReason> {
    // A form that fails changes nothing, and runs again below to give the
    // fault.
    if !matches!(decoded.fast, exec::Fast::None)
        && exec::execute_fast(state, mem, insn, &decoded.fast, decoded.next).is_ok()
    {
        state.repeat_continuation = None;
        return Ok(());
    }
    let rip = state.rip;
    let repeating =
        insn.rep != paludarium_decoder::RepPrefix::None && exec::is_string(insn.mnemonic);
    let comparison = repeating && exec::is_comparison_string(insn.mnemonic);
    // Only a repeated comparison keeps its bytes, to tell its continuation
    // from another instruction at the same address: fetching them for every
    // instruction would double the memory lookups of the common case.
    if comparison {
        let bytes = instruction_bytes(mem, rip, insn.len);
        if state
            .repeat_continuation
            .is_some_and(|c| c.instruction != *insn || c.bytes != bytes)
        {
            state.repeat_continuation = None;
        }
        if state.repeat_continuation.is_none() {
            state.repeat_continuation = Some(RepeatContinuation {
                instruction: *insn,
                bytes,
                initial_flags: state.rflags,
            });
        }
    } else {
        state.repeat_continuation = None;
    }
    let snapshot =
        (!decoded.fails_cleanly).then(|| Snapshot::of(state, decoded.keeps_vector_state));
    let result = exec::execute(state, mem, insn);
    if result.is_ok() {
        if state.rip != rip {
            state.repeat_continuation = None;
        }
    } else if let Err(stop) = result {
        if matches!(stop, Stop::Fault(_)) && repeating {
            if state.rep_fault_flags == RepFaultFlags::RestoreInitial
                && let Some(continuation) = state.repeat_continuation
            {
                state.rflags = continuation.initial_flags;
            }
        } else if matches!(stop, Stop::FloatingPointFault(_)) {
            // Unmasked SIMD exceptions preserve destinations but commit the
            // exception status bits which Linux exposes in the signal frame.
            let mxcsr = state.mxcsr;
            if let Some(snapshot) = snapshot {
                snapshot.restore(state);
            }
            state.mxcsr = mxcsr;
        } else if stop != Stop::Syscall
            && let Some(snapshot) = snapshot
        {
            snapshot.restore(state);
        }
        state.repeat_continuation = None;
    }
    result.map_err(|stop| match stop {
        Stop::Fault(f) => memory_fault(rip, f, f.write, f.fetch),
        Stop::Invalid => ExitReason::InvalidOpcode {
            rip,
            bytes: instruction_bytes(mem, rip, insn.len),
        },
        Stop::Halt => ExitReason::Halt { rip },
        Stop::GeneralProtection => ExitReason::GeneralProtection { rip },
        Stop::ArithmeticFault => ExitReason::ArithmeticFault { rip },
        Stop::FloatingPointFault(code) => ExitReason::FloatingPointFault { rip, code },
        Stop::Syscall => ExitReason::Syscall { rip: state.rip },
    })
}

/// Executes one instruction. `Ok(())` means the guest can continue.
pub fn step(state: &mut CpuState, mem: &AddressSpace) -> Result<(), ExitReason> {
    let insn = fetch_for_state(state, mem)?;
    execute_decoded(state, mem, &Decoded::new(&insn), &insn)
}

/// Executes one instruction, reusing decoded instructions from `cache`.
pub fn step_cached(
    state: &mut CpuState,
    mem: &AddressSpace,
    cache: &mut DecodeCache,
) -> Result<(), ExitReason> {
    #[cfg(feature = "cost-profile")]
    jit_cost::add(jit_cost::Counter::InterpreterSteps, 1);
    let generation = mem.code_generation_cached();
    let block = cache.block(state.rip.0, generation, |code| {
        decode_block(state, mem, code)
    })?;
    let code = &cache.code;
    execute_decoded(
        state,
        mem,
        &code.decoded[block.start],
        &code.instructions[block.start],
    )
}

/// Appends to `code` the first instruction of the block at `state.rip`:
/// [`DecodeCache::block`]'s `decode` for the interpreter.
fn decode_block(
    state: &mut CpuState,
    mem: &AddressSpace,
    code: &mut Code,
) -> Result<(), ExitReason> {
    code.push(fetch_for_state(state, mem)?);
    Ok(())
}

fn fetch_for_state(state: &mut CpuState, mem: &AddressSpace) -> Result<Instruction, ExitReason> {
    match fetch_and_decode(state, mem) {
        Ok(insn) => Ok(insn),
        Err(error) => {
            if let Some(continuation) = state.repeat_continuation.take()
                && continuation.instruction.rip == state.rip
                && state.rep_fault_flags == RepFaultFlags::RestoreInitial
            {
                state.rflags = continuation.initial_flags;
            }
            Err(error)
        }
    }
}

/// Runs at most `budget` instructions. Returns why execution stopped;
/// `BudgetExhausted` when the budget ran out.
pub fn run(state: &mut CpuState, mem: &AddressSpace, budget: u64) -> ExitReason {
    run_cached(state, mem, budget, &mut DecodeCache::new())
}

/// [`run`] with a decode cache that the caller keeps between calls (one per
/// guest thread).
pub fn run_cached(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
) -> ExitReason {
    let mut left = budget;
    while left > 0 {
        let generation = mem.code_generation_cached();
        let rip = state.rip.0;
        let block = match cache.block(rip, generation, |code| decode_block(state, mem, code)) {
            Ok(block) => block,
            Err(reason) => return reason,
        };
        let (mut i, mut end) = (block.start, block.end);
        loop {
            #[cfg(feature = "cost-profile")]
            jit_cost::add(jit_cost::Counter::InterpreterSteps, 1);
            let decoded = &cache.code.decoded[i];
            let next = decoded.next;
            if let Err(reason) = execute_decoded(state, mem, decoded, &cache.code.instructions[i]) {
                return reason;
            }
            left -= 1;
            i += 1;
            // The next instruction is looked up again unless it follows in
            // memory, still of the generation the block was decoded under.
            if left == 0 || state.rip.0 != next || mem.code_generation_cached() != generation {
                break;
            }
            // Past the end of the block, the instruction is decoded as it
            // would be without blocks, and added to it when it can be.
            if i == end {
                match cache.extend(rip, end, generation, || fetch_for_state(state, mem)) {
                    Ok(true) => end += 1,
                    Ok(false) => break,
                    Err(reason) => return reason,
                }
            }
        }
    }
    ExitReason::BudgetExhausted { rip: state.rip }
}

/// Offers instruction boundaries to a synchronous accelerator. Its successful
/// budget exit is conservatively charged `maximum_block` instructions. This
/// never postpones the caller's checkpoint beyond its original guest budget.
/// Other exit reasons return immediately. `remaining` includes current RIP.
pub fn run_cached_with_hook(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
    maximum_block: u64,
    mut accelerate: impl FnMut(&mut CpuState, u64) -> Option<ExitReason>,
) -> ExitReason {
    let mut consumed = 0;
    while consumed < budget {
        let remaining = budget - consumed;
        if maximum_block > 0
            && remaining >= maximum_block
            && let Some(reason) = accelerate(state, remaining)
        {
            if matches!(reason, ExitReason::BudgetExhausted { .. }) {
                #[cfg(feature = "cost-profile")]
                jit_cost::add(jit_cost::Counter::BudgetCharged, maximum_block);
                consumed += maximum_block;
                continue;
            }
            return reason;
        }
        if let Err(reason) = step_cached(state, mem, cache) {
            return reason;
        }
        consumed += 1;
    }
    ExitReason::BudgetExhausted { rip: state.rip }
}

/// Accelerator hook with exact successful instruction accounting. The decoded
/// boundary is shared with fallback execution; rejected boundaries add no fetch.
/// A hook must report a positive count no larger than `maximum_block` and must
/// leave state unchanged on rejection, as with `run_cached_with_hook`.
pub struct AccelerationPolicy {
    pub maximum_block: u64,
    /// Opt-in only: rejected boundaries may run interpreted until code changes.
    pub cache_rejections: bool,
}

impl From<u64> for AccelerationPolicy {
    fn from(maximum_block: u64) -> Self {
        Self {
            maximum_block,
            cache_rejections: false,
        }
    }
}

#[inline(never)]
pub fn run_cached_with_counted_hook(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
    policy: impl Into<AccelerationPolicy>,
    mut accelerate: impl FnMut(&mut CpuState, &Instruction, &mut bool) -> Option<(ExitReason, u64)>,
) -> ExitReason {
    let policy = policy.into();
    if policy.cache_rejections {
        run_counted_policy::<true>(
            state,
            mem,
            budget,
            cache,
            policy.maximum_block,
            &mut accelerate,
        )
    } else {
        run_counted_policy::<false>(
            state,
            mem,
            budget,
            cache,
            policy.maximum_block,
            &mut accelerate,
        )
    }
}

// Keep the invariant rejection policy outside each instruction's dispatch loop.
#[inline(never)]
fn run_counted_policy<const CACHE_REJECTIONS: bool>(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
    maximum_block: u64,
    mut accelerate: impl FnMut(&mut CpuState, &Instruction, &mut bool) -> Option<(ExitReason, u64)>,
) -> ExitReason {
    let mut consumed = 0;
    #[cfg(feature = "cost-profile")]
    let mut observed_chain = jit_cost::Chain::default();
    #[cfg(feature = "cost-profile")]
    let observed_space = mem.code_epoch().0;
    while consumed < budget {
        let generation = mem.code_generation_cached();
        #[cfg(feature = "cost-profile")]
        let observed_rip = state.rip.0;
        #[cfg(feature = "cost-profile")]
        if CACHE_REJECTIONS {
            cache.observe_slot(state.rip.0, generation);
        }
        cache.lookup();
        let (decoded, instruction, rejected) = match cache.get_with_hint(state.rip.0, generation) {
            Some(entry) => entry,
            None => match fetch_for_state(state, mem) {
                Ok(instruction) => (
                    cache.put(state.rip.0, generation, instruction),
                    instruction,
                    false,
                ),
                Err(reason) => {
                    #[cfg(feature = "cost-profile")]
                    observed_chain.stop(jit_cost::Counter::StopExit, jit_cost::add);
                    return reason;
                }
            },
        };
        let mut deterministic_rejection = false;
        if !(CACHE_REJECTIONS && rejected)
            && maximum_block > 0
            && budget - consumed >= maximum_block
            && let Some((reason, count)) =
                accelerate(state, &instruction, &mut deterministic_rejection)
        {
            assert!(
                count > 0 && count <= maximum_block,
                "invalid accelerator instruction count"
            );
            #[cfg(feature = "cost-profile")]
            observed_chain.success(generation, jit_cost::add);
            #[cfg(feature = "cost-profile")]
            if CACHE_REJECTIONS {
                jit_cost::observe_site(observed_space, generation, observed_rip, 1, &instruction);
            }
            if matches!(reason, ExitReason::BudgetExhausted { .. }) {
                #[cfg(feature = "cost-profile")]
                jit_cost::add(jit_cost::Counter::BudgetCharged, count);
                consumed += count;
                continue;
            }
            #[cfg(feature = "cost-profile")]
            observed_chain.stop(jit_cost::Counter::StopExit, jit_cost::add);
            return reason;
        }
        #[cfg(feature = "cost-profile")]
        observed_chain.stop(
            if CACHE_REJECTIONS && rejected {
                jit_cost::Counter::StopNegative
            } else if deterministic_rejection {
                jit_cost::Counter::StopUnsupported
            } else if maximum_block > 0 && budget - consumed < maximum_block {
                jit_cost::Counter::StopBudget
            } else {
                jit_cost::Counter::StopFallback
            },
            jit_cost::add,
        );
        if CACHE_REJECTIONS && deterministic_rejection {
            cache.reject_acceleration(state.rip.0, generation);
        }
        #[cfg(feature = "cost-profile")]
        if CACHE_REJECTIONS {
            let class = if rejected {
                2
            } else if deterministic_rejection {
                3
            } else if maximum_block > 0 && budget - consumed < maximum_block {
                4
            } else {
                5
            };
            jit_cost::observe_site(
                observed_space,
                generation,
                observed_rip,
                class,
                &instruction,
            );
        }
        #[cfg(feature = "cost-profile")]
        jit_cost::add(jit_cost::Counter::InterpreterSteps, 1);
        if let Err(reason) = execute_decoded(state, mem, &decoded, &instruction) {
            #[cfg(feature = "cost-profile")]
            observed_chain.stop(jit_cost::Counter::StopExit, jit_cost::add);
            return reason;
        }
        consumed += 1;
    }
    #[cfg(feature = "cost-profile")]
    observed_chain.stop(jit_cost::Counter::StopBudget, jit_cost::add);
    ExitReason::BudgetExhausted { rip: state.rip }
}

/// Address of the instruction a state would execute next.
#[must_use]
pub fn current_rip(state: &CpuState) -> GuestAddr {
    state.rip
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{MappingKind, Prot};

    const CODE: u64 = 0x40_0000;
    const STACK_TOP: u64 = 0x80_0000;

    fn machine(code: &[u8]) -> (CpuState, AddressSpace) {
        let mut mem = AddressSpace::new();
        mem.map(
            Some(GuestAddr(CODE)),
            0x1000,
            Prot::READ_EXEC,
            MappingKind::ElfSegment,
        )
        .unwrap();
        mem.map(
            Some(GuestAddr(STACK_TOP - 0x2000)),
            0x2000,
            Prot::READ_WRITE,
            MappingKind::Stack,
        )
        .unwrap();
        mem.write_initial(GuestAddr(CODE), code).unwrap();
        (CpuState::new(GuestAddr(CODE), GuestAddr(STACK_TOP)), mem)
    }

    #[test]
    fn hook_reaches_supported_boundary_after_interpreter_instruction() {
        let (mut state, memory) = machine(&[0x90, 0xb8, 42, 0, 0, 0, 0xf4]);
        let mut seen = Vec::new();
        let result = run_cached_with_hook(
            &mut state,
            &memory,
            65,
            &mut DecodeCache::new(),
            64,
            |state, remaining| {
                seen.push((state.rip.0, remaining));
                if state.rip.0 == CODE + 1 {
                    state.gpr[reg::RAX] = 42;
                    state.rip = GuestAddr(CODE + 6);
                    Some(ExitReason::BudgetExhausted { rip: state.rip })
                } else {
                    None
                }
            },
        );
        assert_eq!(seen, [(CODE, 65), (CODE + 1, 64)]);
        assert_eq!(
            result,
            ExitReason::BudgetExhausted {
                rip: GuestAddr(CODE + 6)
            }
        );
        assert_eq!(state.gpr[reg::RAX], 42);
    }

    #[test]
    fn hook_none_preserves_interpreter_exit_and_state() {
        for code in [
            vec![0x90, 0xf4],
            vec![0xb8, 60, 0, 0, 0, 0x0f, 0x05],
            vec![0x0f, 0x0b],
            vec![0x48, 0x8b, 0x07],
        ] {
            let (mut expected, memory) = machine(&code);
            let mut actual = expected.clone();
            let expected_exit = run_cached(&mut expected, &memory, 100, &mut DecodeCache::new());
            let actual_exit = run_cached_with_hook(
                &mut actual,
                &memory,
                100,
                &mut DecodeCache::new(),
                64,
                |_, _| None,
            );
            assert_eq!(actual_exit, expected_exit);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn hook_respects_zero_and_exact_remaining_budget() {
        let (mut state, memory) = machine(&[0x90, 0x90, 0xf4]);
        let mut remaining = Vec::new();
        let zero = run_cached_with_hook(
            &mut state,
            &memory,
            0,
            &mut DecodeCache::new(),
            64,
            |_, _| panic!("zero budget cannot execute accelerator"),
        );
        assert_eq!(
            zero,
            ExitReason::BudgetExhausted {
                rip: GuestAddr(CODE)
            }
        );
        run_cached_with_hook(
            &mut state,
            &memory,
            2,
            &mut DecodeCache::new(),
            1,
            |_, budget| {
                remaining.push(budget);
                None
            },
        );
        assert_eq!(remaining, [2, 1]);
        assert_eq!(state.rip, GuestAddr(CODE + 2));
    }

    #[test]
    fn hook_short_budget_never_accelerates() {
        let (mut state, memory) = machine(&[0x90, 0xf4]);
        let result = run_cached_with_hook(
            &mut state,
            &memory,
            1,
            &mut DecodeCache::new(),
            64,
            |_, _| panic!("block would exceed remaining budget"),
        );
        assert_eq!(
            result,
            ExitReason::BudgetExhausted {
                rip: GuestAddr(CODE + 1)
            }
        );
    }

    #[test]
    fn hook_backward_blocks_remain_finitely_charged() {
        let (mut state, memory) = machine(&[0x90]);
        let mut calls = 0;
        let result = run_cached_with_hook(
            &mut state,
            &memory,
            128,
            &mut DecodeCache::new(),
            64,
            |state, _| {
                calls += 1;
                Some(ExitReason::BudgetExhausted { rip: state.rip })
            },
        );
        assert_eq!(calls, 2);
        assert_eq!(
            result,
            ExitReason::BudgetExhausted {
                rip: GuestAddr(CODE)
            }
        );
    }

    #[test]
    fn hook_continues_to_syscall_after_charged_block() {
        let (mut state, memory) = machine(&[0x90, 0x0f, 0x05]);
        state.gpr[reg::RAX] = 60;
        let result = run_cached_with_hook(
            &mut state,
            &memory,
            65,
            &mut DecodeCache::new(),
            64,
            |state, _| {
                state.rip = GuestAddr(CODE + 1);
                Some(ExitReason::BudgetExhausted { rip: state.rip })
            },
        );
        assert_eq!(
            result,
            ExitReason::Syscall {
                rip: GuestAddr(CODE + 3)
            }
        );
    }

    #[test]
    fn hook_continues_to_fault_after_charged_block() {
        let (mut state, memory) = machine(&[0x90, 0x48, 0x8b, 0x07]);
        let mut expected = state.clone();
        expected.rip = GuestAddr(CODE + 1);
        let expected_exit = run_cached(&mut expected, &memory, 1, &mut DecodeCache::new());
        let actual = run_cached_with_hook(
            &mut state,
            &memory,
            65,
            &mut DecodeCache::new(),
            64,
            |state, _| {
                state.rip = GuestAddr(CODE + 1);
                Some(ExitReason::BudgetExhausted { rip: state.rip })
            },
        );
        assert_eq!(actual, expected_exit);
        assert_eq!(state, expected);
    }

    #[test]
    fn runs_until_syscall_with_linux_register_convention() {
        // mov eax, 60; mov edi, 7; syscall
        let code = [0xb8, 60, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05];
        let (mut s, mem) = machine(&code);
        let reason = run(&mut s, &mem, 100);
        assert_eq!(
            reason,
            ExitReason::Syscall {
                rip: GuestAddr(CODE + 12)
            }
        );
        assert_eq!(s.gpr[reg::RAX], 60);
        assert_eq!(s.gpr[reg::RDI], 7);
        assert_eq!(s.gpr[reg::RCX], CODE + 12);
        assert_eq!(s.gpr[reg::R11], s.rflags);
    }

    #[test]
    fn movq_clears_xmm_high_half_and_keeps_flags() {
        let (mut state, memory) = machine(&[0x66, 0x48, 0x0f, 0x6e, 0xc0]);
        state.gpr[reg::RAX] = 0x0123_4567_89ab_cdef;
        state.xmm[0] = u128::MAX;
        state.rflags = 0x8d7;
        step(&mut state, &memory).unwrap();
        assert_eq!(state.xmm[0], 0x0123_4567_89ab_cdef);
        assert_eq!(state.rflags, 0x8d7);
    }

    #[test]
    fn unpack_low_qwords_uses_original_values_for_aliasing() {
        for source in [0, 1] {
            let (mut state, memory) = machine(&[0x66, 0x0f, 0x6c, 0xc0 + source]);
            state.xmm[0] = (u128::from(0xaaaa_bbbb_cccc_ddddu64) << 64) | 0x0123_4567_89ab_cdef;
            state.xmm[1] = (u128::from(0x1111_2222_3333_4444u64) << 64) | 0xfedc_ba98_7654_3210;
            let high = state.xmm[usize::from(source)] as u64;
            state.rflags = 0x8d7;
            step(&mut state, &memory).unwrap();
            assert_eq!(
                state.xmm[0],
                (u128::from(high) << 64) | 0x0123_4567_89ab_cdef
            );
            assert_eq!(state.rflags, 0x8d7);
        }
    }

    #[test]
    fn budget_exhaustion_stops_an_infinite_loop() {
        // jmp $ (eb fe)
        let (mut s, mem) = machine(&[0xeb, 0xfe]);
        assert_eq!(
            run(&mut s, &mem, 1000),
            ExitReason::BudgetExhausted {
                rip: GuestAddr(CODE)
            }
        );
    }

    #[test]
    fn unsupported_and_invalid_bytes_are_invalid_opcode() {
        // ud2 (0f 0b)
        let (mut s, mem) = machine(&[0x0f, 0x0b]);
        match run(&mut s, &mem, 10) {
            ExitReason::InvalidOpcode { rip, bytes } => {
                assert_eq!(rip, GuestAddr(CODE));
                assert_eq!(&bytes.as_slice()[..2], &[0x0f, 0x0b]);
            }
            other => panic!("unexpected {other:?}"),
        }
        // XGETBV remains unsupported by the virtual CPU contract.
        let (mut s, mem) = machine(&[0x0f, 0x01, 0xd0]);
        assert!(matches!(
            run(&mut s, &mem, 10),
            ExitReason::InvalidOpcode { .. }
        ));
    }

    /// Runs `code` once, with `rax` pointing into the stack at `offset`.
    fn fx_run(
        code: &[u8],
        area: &[u8],
        offset: u64,
        s_mem: Option<(CpuState, AddressSpace)>,
    ) -> (CpuState, AddressSpace, ExitReason) {
        let (mut s, mem) = s_mem.unwrap_or_else(|| machine(code));
        let at = STACK_TOP - 0x1000 + offset;
        mem.write(GuestAddr(at), area).unwrap();
        s.gpr[0] = at;
        let reason = run(&mut s, &mem, 1);
        (s, mem, reason)
    }
    #[test]
    fn fxsave_gives_mxcsr_and_the_registers_and_leaves_the_rest() {
        let (mut s, mem) = machine(&[0x0f, 0xae, 0x00]);
        s.mxcsr = 0x1fa0;
        for (n, register) in s.xmm.iter_mut().enumerate() {
            *register = (n as u128 + 1) * 0x0101_0101_0101_0101_0101;
        }
        let xmm = s.xmm;
        let (_, mem, _) = fx_run(&[], &[0x55; 512], 0, Some((s, mem)));
        let mut area = [0; 512];
        mem.read(GuestAddr(STACK_TOP - 0x1000), &mut area).unwrap();
        assert_eq!(&area[..2], &[0x7f, 0x03], "the control word after a reset");
        assert_eq!(&area[2..24], &[0; 22]);
        assert_eq!(&area[24..28], &0x1fa0u32.to_le_bytes());
        assert_eq!(&area[28..32], &0xffffu32.to_le_bytes());
        assert_eq!(&area[32..160], &[0; 128]);
        for (n, value) in xmm.iter().enumerate() {
            assert_eq!(
                &area[160 + 16 * n..176 + 16 * n],
                &value.to_le_bytes(),
                "{n}"
            );
        }
        assert_eq!(&area[416..], &[0x55; 96], "not written");
    }
    #[test]
    fn fxrstor_takes_mxcsr_and_the_registers() {
        let mut area = [0u8; 512];
        area[24..28].copy_from_slice(&0x3f80u32.to_le_bytes());
        for n in 0..16 {
            area[160 + 16 * n..176 + 16 * n].copy_from_slice(&[n as u8 + 1; 16]);
        }
        let (s, _, _) = fx_run(&[0x0f, 0xae, 0x08], &area, 0, None);
        assert_eq!(s.mxcsr, 0x3f80);
        for (n, value) in s.xmm.iter().enumerate() {
            assert_eq!(*value, u128::from_le_bytes([n as u8 + 1; 16]), "{n}");
        }
    }
    #[test]
    fn fxsave_and_fxrstor_refuse_what_linux_faults_on() {
        for code in [&[0x0f, 0xae, 0x00][..], &[0x0f, 0xae, 0x08]] {
            let (_, _, reason) = fx_run(code, &[0; 512], 8, None);
            assert!(
                matches!(reason, ExitReason::GeneralProtection { .. }),
                "misaligned: {reason:?}"
            );
        }
        let mut area = [0u8; 512];
        area[24..28].copy_from_slice(&0x1_0000u32.to_le_bytes());
        let (s, _, reason) = fx_run(&[0x0f, 0xae, 0x08], &area, 0, None);
        assert!(
            matches!(reason, ExitReason::GeneralProtection { .. }),
            "{reason:?}"
        );
        assert_eq!(
            s.mxcsr,
            CpuState::new(GuestAddr(0), GuestAddr(0)).mxcsr,
            "unchanged"
        );
    }
    #[test]
    fn fxsave_and_fxrstor_need_the_whole_area_though_they_use_less() {
        // Its last 96 bytes are past the end of the stack.
        let near_the_end = 0x1000 - 416;
        let (_, mem, reason) = fx_run(&[0x0f, 0xae, 0x00], &[0x55; 416], near_the_end, None);
        assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
        let mut area = [0; 416];
        let at = STACK_TOP - 416;
        mem.read(GuestAddr(at), &mut area).unwrap();
        assert_eq!(area, [0x55; 416], "nothing was written");
        let (s, _, reason) = fx_run(&[0x0f, 0xae, 0x08], &[0; 416], near_the_end, None);
        assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
        assert_eq!(
            s.mxcsr,
            CpuState::new(GuestAddr(0), GuestAddr(0)).mxcsr,
            "nothing was read"
        );
    }
    /// Runs `code` with rax at the start of the stack's first page.
    fn x87_run(code: &[u8], steps: u64) -> (CpuState, AddressSpace, ExitReason) {
        let (mut s, mem) = machine(code);
        s.gpr[0] = STACK_TOP - 0x2000;
        let reason = run(&mut s, &mem, steps);
        (s, mem, reason)
    }
    #[test]
    fn x87_loads_converts_and_stores_through_memory() {
        // fld1; fstp qword [rax]; fldz; fstp dword [rax+8]; fld1; fistp word [rax+16]
        let code = [
            0xd9, 0xe8, 0xdd, 0x18, 0xd9, 0xee, 0xd9, 0x58, 0x08, 0xd9, 0xe8, 0xdf, 0x58, 0x10,
        ];
        let (s, mem, _) = x87_run(&code, 6);
        let mut out = [0; 18];
        mem.read(GuestAddr(STACK_TOP - 0x2000), &mut out).unwrap();
        assert_eq!(&out[..8], &0x3ff0_0000_0000_0000u64.to_le_bytes());
        assert_eq!(&out[8..12], &[0; 4]);
        assert_eq!(&out[16..18], &[1, 0]);
        assert_eq!(s.x87.status_word() >> 11 & 7, 0, "all popped");
    }
    #[test]
    fn x87_stores_and_loads_each_memory_form() {
        let at = GuestAddr(STACK_TOP - 0x2000);
        let run_with = |code: &[u8], memory: &[u8]| {
            let (mut s, mem) = machine(code);
            mem.write(at, memory).unwrap();
            s.gpr[0] = at.0;
            run(&mut s, &mem, 3);
            (s, mem)
        };
        let load_status = |code: [u8; 2], memory: &[u8]| {
            // fld or fild [rax]; fstp tbyte [rax+0x20]
            let (_, mem) = run_with(&[code[0], code[1], 0xdb, 0x78, 0x20], memory);
            let mut out = [0; 10];
            mem.read(GuestAddr(at.0 + 0x20), &mut out).unwrap();
            out
        };
        let one = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];
        assert_eq!(
            load_status([0xd9, 0x00], &0x3f80_0000u32.to_le_bytes()),
            one
        );
        assert_eq!(
            load_status([0xdd, 0x00], &0x3ff0_0000_0000_0000u64.to_le_bytes()),
            one
        );
        assert_eq!(load_status([0xdb, 0x28], &one), one);
        assert_eq!(load_status([0xdf, 0x00], &1u16.to_le_bytes()), one);
        assert_eq!(load_status([0xdb, 0x00], &1u32.to_le_bytes()), one);
        assert_eq!(load_status([0xdf, 0x28], &1u64.to_le_bytes()), one);
        // A negative integer is sign-extended from its own size.
        let minus = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xbf];
        assert_eq!(load_status([0xdf, 0x00], &0xffffu16.to_le_bytes()), minus);
        assert_eq!(load_status([0xdb, 0x00], &u32::MAX.to_le_bytes()), minus);
        assert_eq!(load_status([0xdf, 0x28], &u64::MAX.to_le_bytes()), minus);
        let store_keeps = |code: [u8; 2], size: usize| {
            // fld1; fst or fist [rax]; fxam-free check that it is still there.
            let (s, mem) = run_with(&[0xd9, 0xe8, code[0], code[1]], &[0x55; 16]);
            let mut out = [0; 16];
            mem.read(at, &mut out).unwrap();
            assert!(out[size..].iter().all(|b| *b == 0x55), "{code:02x?}");
            (s.x87.status_word() >> 11 & 7, out)
        };
        let (top, out) = store_keeps([0xd9, 0x10], 4);
        assert_eq!((top, &out[..4]), (7, &0x3f80_0000u32.to_le_bytes()[..]));
        let (top, out) = store_keeps([0xdd, 0x10], 8);
        assert_eq!((top, &out[..2]), (7, &[0, 0][..]));
        assert_eq!(&out[..8], &0x3ff0_0000_0000_0000u64.to_le_bytes());
        let (top, out) = store_keeps([0xdf, 0x10], 2);
        assert_eq!((top, &out[..2]), (7, &[1, 0][..]));
        let (top, out) = store_keeps([0xdb, 0x10], 4);
        assert_eq!((top, &out[..4]), (7, &[1, 0, 0, 0][..]));
    }
    #[test]
    fn x87_compares_into_the_flags_and_pops_for_its_p_forms() {
        // fld1; fldz; fcomi st(1)
        let flags = |code: &[u8], steps: u64| {
            let (mut s, mem) = machine(code);
            s.rflags |= flag::SF | flag::OF | flag::AF;
            run(&mut s, &mem, steps);
            (s.rflags & flag::STATUS, s.x87.status_word() >> 11 & 7)
        };
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xdb, 0xf1];
        assert_eq!(flags(&code, 3), (flag::CF, 6), "0 is below 1");
        // The same, the other way round.
        let code = [0xd9, 0xee, 0xd9, 0xe8, 0xdb, 0xe9];
        assert_eq!(flags(&code, 3), (0, 6), "fucomi: 1 is above 0");
        let code = [0xd9, 0xe8, 0xd9, 0xe8, 0xdf, 0xf1];
        assert_eq!(flags(&code, 3), (flag::ZF, 7), "fcomip: equal, popped");
        let code = [0xd9, 0xe8, 0xd9, 0xe8, 0xdf, 0xe9];
        assert_eq!(flags(&code, 3), (flag::ZF, 7), "fucomip: equal, popped");
        let code = [0xdb, 0xf1];
        assert_eq!(
            flags(&code, 1),
            (flag::ZF | flag::PF | flag::CF, 0),
            "empty: unordered"
        );
    }
    #[test]
    fn x87_status_and_control_words_reach_their_destinations() {
        // fldcw [rax]; fnstcw [rax+2]; fld1; fnstsw ax
        let code = [0xd9, 0x28, 0xd9, 0x78, 0x02, 0xd9, 0xe8, 0xdf, 0xe0];
        let (mut s, mem) = machine(&code);
        let at = GuestAddr(STACK_TOP - 0x2000);
        mem.write(at, &0x27fu16.to_le_bytes()).unwrap();
        s.gpr[0] = at.0;
        run(&mut s, &mem, 4);
        let mut out = [0; 2];
        mem.read(GuestAddr(at.0 + 2), &mut out).unwrap();
        assert_eq!(u16::from_le_bytes(out), 0x27f);
        assert_eq!(s.gpr[0] & 0xffff, 7 << 11, "ax has the top");
        assert_eq!(s.gpr[0] >> 16, (at.0) >> 16, "only ax");
        // fnstsw [rax]
        let (_, mem, _) = x87_run(&[0xd9, 0xe8, 0xdd, 0x38], 2);
        mem.read(at, &mut out).unwrap();
        assert_eq!(u16::from_le_bytes(out), 7 << 11);
        // fnstenv [rax], then fldenv [rax] after fninit.
        let code = [0xd9, 0xe8, 0xd9, 0x30, 0xdb, 0xe3, 0xd9, 0x20];
        let (s, _, _) = x87_run(&code, 4);
        assert_eq!(s.x87.status_word() >> 11 & 7, 7);
        // fnclex and fninit.
        let (s, _, _) = x87_run(&[0xdb, 0xf1, 0xdb, 0xe2], 2);
        assert_eq!(s.x87.status_word() & 0xff, 0);
        let (s, _, _) = x87_run(&[0xd9, 0xe8, 0xdb, 0xe3], 2);
        assert_eq!(s.x87.status_word(), 0);
        assert_eq!(s.x87.control_word(), 0x37f);
    }
    /// The value st(0) holds after `code`, with what it needs of memory at rax.
    fn x87_top(code: &[u8], memory: &[u8], steps: u64) -> (u128, u16) {
        let (mut s, mem) = machine(code);
        s.gpr[0] = STACK_TOP - 0x2000;
        mem.write(GuestAddr(s.gpr[0]), memory).unwrap();
        let reason = run(&mut s, &mem, steps);
        assert!(
            !matches!(reason, ExitReason::InvalidOpcode { .. }),
            "{code:02x?}: {reason:?}"
        );
        // fstp tbyte [rax]
        let (mut after, later) = machine(&[0xdb, 0x38]);
        after.x87 = s.x87;
        after.gpr[0] = STACK_TOP - 0x2000;
        run(&mut after, &later, 1);
        let mut bytes = [0; 16];
        later
            .read(GuestAddr(after.gpr[0]), &mut bytes[..10])
            .unwrap();
        (u128::from_le_bytes(bytes), s.x87.status_word())
    }
    #[test]
    fn x87_arithmetic_takes_each_operand_form() {
        const THREE: u128 = 0x4000_c000_0000_0000_0000;
        const TWO: u128 = 0x4000_8000_0000_0000_0000;
        const FOUR: u128 = 0x4001_8000_0000_0000_0000;
        const ONE: u128 = 0x3fff_8000_0000_0000_0000;
        // fld1 twice, then the rest, in st(0) = 1 and st(1) = 1.
        let of = |rest: &[u8], memory: &[u8]| {
            let code = [&[0xd9, 0xe8, 0xd9, 0xe8][..], rest].concat();
            x87_top(&code, memory, 3).0
        };
        // fadd st(0), st(1); fsub; fmul; fdiv
        assert_eq!(of(&[0xd8, 0xc1], &[]), TWO);
        assert_eq!(of(&[0xd8, 0xe1], &[]), 0);
        assert_eq!(of(&[0xd8, 0xc9], &[]), ONE);
        assert_eq!(of(&[0xd8, 0xf1], &[]), ONE);
        // faddp st(1), st(0) pops.
        let (value, status) = x87_top(&[0xd9, 0xe8, 0xd9, 0xe8, 0xde, 0xc1], &[], 3);
        assert_eq!((value, status >> 11 & 7), (TWO, 7));
        // fadd st(1), st(0) leaves st(0).
        let (value, status) = x87_top(&[0xd9, 0xe8, 0xd9, 0xe8, 0xdc, 0xc1], &[], 3);
        assert_eq!((value, status >> 11 & 7), (ONE, 6));
        // fadd dword, fadd qword, fiadd word and dword, from rax: 1 + 2.
        let double = 2f64.to_bits().to_le_bytes();
        let single = 2f32.to_bits().to_le_bytes();
        let top =
            |rest: &[u8], memory: &[u8]| x87_top(&[&[0xd9, 0xe8][..], rest].concat(), memory, 2).0;
        assert_eq!(top(&[0xdc, 0x00], &double), THREE);
        assert_eq!(top(&[0xd8, 0x00], &single), THREE);
        assert_eq!(top(&[0xde, 0x00], &[2, 0]), THREE);
        assert_eq!(top(&[0xda, 0x00], &[2, 0, 0, 0]), THREE);
        // fisub word is 1 - 2; fisubr word is 2 - 1, and -1 reads as signed.
        assert_eq!(top(&[0xde, 0x20], &[2, 0]), ONE | 1 << 79);
        assert_eq!(top(&[0xde, 0x28], &[2, 0]), ONE);
        assert_eq!(top(&[0xde, 0x00], &[0xff, 0xff]), 0);
        // fild word; fmul word: 2 * 2, fdiv and fdivr
        let two = [2, 0];
        let twos = |rest: &[u8]| x87_top(&[&[0xdf, 0x00][..], rest].concat(), &two, 2).0;
        assert_eq!(twos(&[0xde, 0x08]), FOUR);
        assert_eq!(twos(&[0xde, 0x30]), ONE);
        assert_eq!(twos(&[0xde, 0x38]), ONE);
        // fld1; fsqrt, frndint, and constants: all without a stop.
        assert_eq!(top(&[0xd9, 0xfa], &[]), ONE);
        assert_eq!(top(&[0xd9, 0xfc], &[]), ONE);
        let (value, _) = x87_top(&[0xd9, 0xeb], &[], 1);
        assert_eq!(value, 0x4000_c90f_daa2_2168_c235);
    }
    #[test]
    fn x87_compares_into_the_condition_bits_and_pops_for_each_form() {
        const C: u16 = 1 << 8 | 1 << 10 | 1 << 14;
        let status = |code: &[u8], memory: &[u8], steps| x87_top(code, memory, steps).1;
        // fld1; fldz; fcom st(1): 0 < 1.
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xd8, 0xd1];
        assert_eq!(status(&code, &[], 3) & (C | 7 << 11), 1 << 8 | 6 << 11);
        // fcomp pops one and fcompp both.
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xd8, 0xd9];
        assert_eq!(status(&code, &[], 3) & (C | 7 << 11), 1 << 8 | 7 << 11);
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xde, 0xd9];
        assert_eq!(status(&code, &[], 3) & (C | 7 << 11), 1 << 8);
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xda, 0xe9];
        assert_eq!(status(&code, &[], 3) & (C | 7 << 11), 1 << 8);
        // fucom and fucomp.
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xdd, 0xe1];
        assert_eq!(status(&code, &[], 3) & C, 1 << 8);
        let code = [0xd9, 0xe8, 0xd9, 0xee, 0xdd, 0xe9];
        assert_eq!(status(&code, &[], 3) & (C | 7 << 11), 1 << 8 | 7 << 11);
        // fld1; fcom qword [rax] against 1, fcomp dword, ficom word, ficomp dword, ftst
        let equal = 1 << 14;
        let double = 1f64.to_bits().to_le_bytes();
        let single = 1f32.to_bits().to_le_bytes();
        let with =
            |rest: &[u8], memory: &[u8]| status(&[&[0xd9, 0xe8][..], rest].concat(), memory, 2);
        assert_eq!(
            with(&[0xdc, 0x10], &double) & (C | 7 << 11),
            equal | 7 << 11
        );
        assert_eq!(with(&[0xd8, 0x18], &single) & (C | 7 << 11), equal);
        assert_eq!(
            with(&[0xde, 0x10], &[1, 0]) & (C | 7 << 11),
            equal | 7 << 11
        );
        assert_eq!(with(&[0xda, 0x18], &[1, 0, 0, 0]) & (C | 7 << 11), equal);
        assert_eq!(with(&[0xd9, 0xe4], &[]) & C, 0);
    }
    #[test]
    fn x87_conditional_moves_read_the_flags() {
        // fld1; fldz; fcmov st(0), st(1), by what it reads of each flag.
        let moved = |second: u8, third: u8, flags: u64| {
            let code = [0xd9, 0xe8, 0xd9, 0xee, second, third];
            let (mut s, mem) = machine(&code);
            s.rflags |= flags;
            run(&mut s, &mem, 3);
            let mut after = s.x87;
            after.compare_value(0, false);
            after.status_word() & 1 << 14 == 0
        };
        let (cf, zf, pf) = (flag::CF, flag::ZF, flag::PF);
        for (second, third, on, off) in [
            (0xda, 0xc1, cf, 0),
            (0xda, 0xc9, zf, 0),
            (0xda, 0xd1, cf, 0),
            (0xda, 0xd1, zf, 0),
            (0xda, 0xd9, pf, 0),
            (0xdb, 0xc1, 0, cf),
            (0xdb, 0xc9, 0, zf),
            (0xdb, 0xd1, 0, cf),
            (0xdb, 0xd1, 0, zf),
            (0xdb, 0xd9, 0, pf),
        ] {
            assert!(moved(second, third, on), "{second:x} {third:x} {on:x}");
            assert!(!moved(second, third, off), "{second:x} {third:x} {off:x}");
        }
    }
    #[test]
    fn x87_arithmetic_from_memory_that_faults_changes_nothing() {
        // fld1, then fadd qword [rax] of what is not mapped.
        let (mut s, mem) = machine(&[0xd9, 0xe8, 0xdc, 0x00]);
        s.gpr[0] = 0x1000;
        let reason = run(&mut s, &mem, 2);
        assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
        assert_eq!(s.rip, GuestAddr(CODE + 2));
        assert_eq!(s.x87.status_word() >> 11 & 7, 7);
    }
    #[test]
    fn x87_moves_the_stack() {
        let status = |code: &[u8], steps| x87_run(code, steps).0.x87.status_word();
        // fld1; fld st(0)
        assert_eq!(status(&[0xd9, 0xe8, 0xd9, 0xc0], 2) & 0x7f, 0);
        // fld st(1) of nothing is invalid.
        assert_eq!(status(&[0xd9, 0xc1], 1) & 0x41, 0x41);
        // fld1; fst st(1); fstp st(1); fincstp; fdecstp; ffree st(0); wait; fnop
        let top = |code: &[u8], steps| status(code, steps) >> 11 & 7;
        assert_eq!(top(&[0xd9, 0xe8, 0xdd, 0xd1], 2), 7);
        assert_eq!(top(&[0xd9, 0xe8, 0xdd, 0xd9], 2), 0);
        assert_eq!(top(&[0xd9, 0xf7], 1), 1);
        assert_eq!(top(&[0xd9, 0xf6], 1), 7);
        assert_eq!(top(&[0xd9, 0xe8, 0xdd, 0xc0], 2), 7);
        assert_eq!(status(&[0x9b, 0xd9, 0xd0], 2), 0);
        // fld1; fxch st(1); fchs; fabs; fxam.
        assert_eq!(status(&[0xd9, 0xe8, 0xd9, 0xc9], 2) & 0x41, 0x41);
        let (s, _, _) = x87_run(&[0xd9, 0xe8, 0xd9, 0xe0, 0xd9, 0xe5], 3);
        assert_ne!(s.x87.status_word() & 1 << 9, 0, "fxam: negative");
        let (s, _, _) = x87_run(&[0xd9, 0xe8, 0xd9, 0xe0, 0xd9, 0xe1, 0xd9, 0xe5], 4);
        assert_eq!(s.x87.status_word() & 1 << 9, 0, "fxam: positive");
    }
    #[test]
    fn x87_faults_change_nothing() {
        // fld1, then a store past the stack's first page's end of mapping.
        for store in [[0xdd, 0x18], [0xdb, 0x38], [0xdf, 0x18], [0xdd, 0x10]] {
            let (mut s, mem) = machine(&[0xd9, 0xe8, store[0], store[1]]);
            s.gpr[0] = 0x1000;
            let reason = run(&mut s, &mem, 2);
            assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
            assert_eq!(s.x87.status_word() >> 11 & 7, 7, "{store:02x?}: not popped");
            assert_eq!(s.rip, GuestAddr(CODE + 2));
        }
        // A 10-byte store half in a mapped page leaves that page alone.
        let (mut s, mem) = machine(&[0xd9, 0xe8, 0xdb, 0x38]);
        let last = STACK_TOP - 5;
        s.gpr[0] = last;
        mem.write(GuestAddr(last), &[0x55; 5]).unwrap();
        let reason = run(&mut s, &mem, 2);
        assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
        let mut out = [0; 5];
        mem.read(GuestAddr(last), &mut out).unwrap();
        assert_eq!(out, [0x55; 5]);
        // fnstenv too, and it masks nothing then.
        let (mut s, mem) = machine(&[0xd9, 0x30]);
        s.gpr[0] = STACK_TOP - 5;
        let reason = run(&mut s, &mem, 1);
        assert!(matches!(reason, ExitReason::PageFault { .. }), "{reason:?}");
        assert_eq!(s.x87.control_word(), 0x37f);
    }
    #[test]
    fn x87_environment_of_another_size_is_not_run() {
        // 66 fnstenv and 66 fldenv have the 14-byte layout.
        for code in [[0x66, 0xd9, 0x30], [0x66, 0xd9, 0x20]] {
            let (_, _, reason) = x87_run(&code, 1);
            assert!(
                matches!(reason, ExitReason::InvalidOpcode { .. }),
                "{reason:?}"
            );
        }
    }
    #[test]
    fn fxsave_and_fxrstor_keep_the_x87_state() {
        // fld1; fxsave [rax]; fninit; fxrstor [rax]
        let code = [0xd9, 0xe8, 0x0f, 0xae, 0x00, 0xdb, 0xe3, 0x0f, 0xae, 0x08];
        let (s, mem, _) = x87_run(&code, 4);
        let mut area = [0; 42];
        mem.read(GuestAddr(STACK_TOP - 0x2000), &mut area).unwrap();
        assert_eq!(area[4], 0x80, "R7 is in use");
        assert_eq!(&area[32..42], &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
        assert_eq!(s.x87.status_word() >> 11 & 7, 7, "restored");
    }
    #[test]
    fn rdtsc_splits_a_counter_that_moves_on() {
        let read = |code: &[u8]| {
            let (mut s, mem) = machine(code);
            s.gpr[0] = u64::MAX;
            s.gpr[1] = u64::MAX;
            s.gpr[2] = u64::MAX;
            run(&mut s, &mem, 1);
            s
        };
        let first = read(&[0x0f, 0x31]);
        assert_eq!(first.gpr[0] >> 32, 0);
        assert_eq!(first.gpr[2] >> 32, 0);
        assert_eq!(first.gpr[1], u64::MAX, "rdtsc leaves rcx");
        assert_ne!(first.gpr[2], 0, "the counter is past 32 bits");
        let second = read(&[0x0f, 0x01, 0xf9]);
        assert_eq!(second.gpr[1], 0, "rdtscp sets rcx");
        assert!(second.gpr[2] << 32 | second.gpr[0] > first.gpr[2] << 32 | first.gpr[0]);
    }
    #[test]
    fn memory_faults_report_address_and_direction() {
        // mov [0x1000], eax  (89 04 25 00 10 00 00)
        let (mut s, mem) = machine(&[0x89, 0x04, 0x25, 0x00, 0x10, 0, 0]);
        assert_eq!(
            run(&mut s, &mem, 10),
            ExitReason::PageFault {
                rip: GuestAddr(CODE),
                addr: GuestAddr(0x1000),
                write: true,
                fetch: false,
                mapped: false,
                present: false
            }
        );
        // Jumping to unmapped memory faults on the fetch.
        let (mut s, mem) = machine(&[0xff, 0xe0]); // jmp rax (rax = 0)
        assert_eq!(
            run(&mut s, &mem, 10),
            ExitReason::PageFault {
                rip: GuestAddr(0),
                addr: GuestAddr(0),
                write: false,
                fetch: true,
                mapped: false,
                present: false
            }
        );
    }

    #[test]
    fn call_ret_push_pop_use_the_stack() {
        // call +1; hlt; (target:) push 5; pop rbx; ret
        let code = [0xe8, 0x01, 0, 0, 0, 0xf4, 0x6a, 0x05, 0x5b, 0xc3];
        let (mut s, mem) = machine(&code);
        assert_eq!(
            run(&mut s, &mem, 100),
            ExitReason::Halt {
                rip: GuestAddr(CODE + 5)
            }
        );
        assert_eq!(s.gpr[reg::RBX], 5);
        assert_eq!(s.gpr[reg::RSP], STACK_TOP);
    }

    #[test]
    fn writes_to_32_bit_registers_zero_extend() {
        // mov rax, -1; mov eax, 1; mov rbx, -1; mov bl, 0
        let code = [
            0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0x48, 0xc7, 0xc3, 0xff,
            0xff, 0xff, 0xff, 0xb3, 0x00, 0xf4,
        ];
        let (mut s, mem) = machine(&code);
        assert!(matches!(run(&mut s, &mem, 100), ExitReason::Halt { .. }));
        assert_eq!(s.gpr[reg::RAX], 1);
        assert_eq!(s.gpr[reg::RBX], 0xffff_ffff_ffff_ff00);
    }

    #[test]
    fn rep_stosq_fills_memory_and_divide_by_zero_traps() {
        // lea rdi, [rsp-64]; mov ecx, 8; mov eax, 0x11; rep stosq; xor ecx, ecx; div rcx
        let code = [
            0x48, 0x8d, 0x7c, 0x24, 0xc0, 0xb9, 8, 0, 0, 0, 0xb8, 0x11, 0, 0, 0, 0xf3, 0x48, 0xab,
            0x31, 0xc9, 0x48, 0xf7, 0xf1,
        ];
        let (mut s, mem) = machine(&code);
        assert_eq!(
            run(&mut s, &mem, 100),
            ExitReason::ArithmeticFault {
                rip: GuestAddr(CODE + 20)
            }
        );
        assert_eq!(s.gpr[reg::RCX], 0);
        assert_eq!(mem.read_u64(GuestAddr(STACK_TOP - 64)).unwrap(), 0x11);
        assert_eq!(mem.read_u64(GuestAddr(STACK_TOP - 8)).unwrap(), 0x11);
    }

    #[test]
    fn misaligned_movaps_is_a_general_protection_fault() {
        // movaps [rsp-15], xmm0 (0f 29 44 24 f1)
        let (mut s, mem) = machine(&[0x0f, 0x29, 0x44, 0x24, 0xf1]);
        assert_eq!(
            run(&mut s, &mem, 10),
            ExitReason::GeneralProtection {
                rip: GuestAddr(CODE)
            }
        );
    }

    #[test]
    fn shift_by_zero_keeps_flags_but_zero_extends_32_bit_destination() {
        // Regression found by the insn-shift differential test.
        // mov rax, -1; xor ecx, ecx; stc; shl eax, cl; hlt
        let code = [
            0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x31, 0xc9, 0xf9, 0xd3, 0xe0, 0xf4,
        ];
        let (mut s, mem) = machine(&code);
        // stc is not in the core set; set CF directly and start after it.
        let reason = run(&mut s, &mem, 2);
        assert!(matches!(reason, ExitReason::BudgetExhausted { .. }));
        s.rflags |= flag::CF;
        s.rip = GuestAddr(CODE + 10);
        assert!(matches!(run(&mut s, &mem, 10), ExitReason::Halt { .. }));
        assert_eq!(s.gpr[reg::RAX], 0xffff_ffff);
        assert!(s.flag(flag::CF));
    }

    #[test]
    fn decode_cache_sees_self_modifying_code() {
        // An RWX page: execute `mov eax, 1; hlt`, patch the immediate, rerun.
        let mut mem = AddressSpace::new();
        mem.map(
            Some(GuestAddr(CODE)),
            0x1000,
            Prot::from_bits(7).unwrap(),
            MappingKind::Anonymous,
        )
        .unwrap();
        mem.write(GuestAddr(CODE), &[0xb8, 1, 0, 0, 0, 0xf4])
            .unwrap();
        let mut cache = DecodeCache::new();
        let mut s = CpuState::new(GuestAddr(CODE), GuestAddr(0));
        assert!(matches!(
            run_cached(&mut s, &mem, 10, &mut cache),
            ExitReason::Halt { .. }
        ));
        assert_eq!(s.gpr[reg::RAX], 1);
        mem.write(GuestAddr(CODE + 1), &[2]).unwrap();
        s.rip = GuestAddr(CODE);
        assert!(matches!(
            run_cached(&mut s, &mem, 10, &mut cache),
            ExitReason::Halt { .. }
        ));
        assert_eq!(s.gpr[reg::RAX], 2);
    }

    #[test]
    fn decode_cache_sees_unmapped_code() {
        let (mut s, mut mem) = machine(&[0x90, 0xeb, 0xfd]); // nop; jmp back
        let mut cache = DecodeCache::new();
        assert!(matches!(
            run_cached(&mut s, &mem, 50, &mut cache),
            ExitReason::BudgetExhausted { .. }
        ));
        mem.unmap(GuestAddr(CODE), 0x1000).unwrap();
        assert!(matches!(
            run_cached(&mut s, &mem, 50, &mut cache),
            ExitReason::PageFault { write: false, .. }
        ));
    }

    #[test]
    fn fs_relative_load_uses_fs_base() {
        // mov rax, fs:[8]; hlt
        let code = [0x64, 0x48, 0x8b, 0x04, 0x25, 0x08, 0, 0, 0, 0xf4];
        let (mut s, mem) = machine(&code);
        s.fs_base = STACK_TOP - 0x100;
        mem.write_u64(GuestAddr(STACK_TOP - 0xf8), 0xabcd).unwrap();
        assert!(matches!(run(&mut s, &mem, 10), ExitReason::Halt { .. }));
        assert_eq!(s.gpr[reg::RAX], 0xabcd);
    }
}
