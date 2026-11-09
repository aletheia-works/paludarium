//! Blocks compiled to host code.
//!
//! [`run_compiled`] runs like [`crate::run_cached`], and also counts how
//! often each block of the [`DecodeCache`] is entered. When a block has
//! been entered [`Compiler::threshold`] times, the forms ([`Fast`]) of its
//! first instructions are offered to a [`Compiler`]. Its [`CompiledBlock`]
//! then runs them whenever the block is entered again, while the code
//! generation the block was decoded under lasts. An instruction the
//! compiled code does not run (an instruction without a form, one whose
//! form fails, the instructions after a load or store that saw the code
//! change) runs in the interpreter as before.

use std::sync::Arc;

use paludarium_mmu::AddressSpace;
use paludarium_types::ExitReason;

pub use crate::exec::{Address, Alu, Fast, Source};
use crate::{
    CpuState, DecodeCache, MAX_COMPILED, NOT_COMPILED, decode_block, execute_decoded,
    fetch_for_state,
};

/// An instruction offered to a [`Compiler`]: its address, the address of
/// the instruction after it in memory, and its form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Form {
    pub rip: u64,
    pub next: u64,
    pub fast: Fast,
}

/// The host code of a block's first instructions.
pub trait CompiledBlock: Send + Sync {
    /// Runs the instructions from the first one, exactly as the
    /// interpreter runs their forms, and returns how many ran, with
    /// `state.rip` at the instruction after the last that ran. It stops
    /// before an instruction whose form would fail, changing nothing for
    /// it, so that the interpreter runs it again and reports the fault; it
    /// stops after a branch that leaves the instructions, and after a load
    /// or store after which [`AddressSpace::code_generation_cached`] is not
    /// `generation`.
    fn run(&self, state: &mut CpuState, mem: &AddressSpace, generation: u64) -> usize;

    /// The number of instructions it holds; [`CompiledBlock::run`] runs
    /// at most this many.
    fn len(&self) -> usize;

    /// Whether it holds none.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Makes [`CompiledBlock`]s.
pub trait Compiler: Send + Sync {
    /// How many times a block is entered before it is compiled.
    fn threshold(&self) -> u16;

    /// The host code of `forms`, the first instructions of a block, which
    /// follow each other in memory; `None` turns the block down until it
    /// is decoded again.
    fn compile(&self, forms: &[Form]) -> Option<Arc<dyn CompiledBlock>>;
}

impl DecodeCache {
    /// The compiled code of the block in `slot`, compiling it with
    /// `compiler` when it has been entered often enough.
    fn compiled(&mut self, slot: usize, compiler: &dyn Compiler) -> Option<Arc<dyn CompiledBlock>> {
        let s = &mut self.slots[slot];
        match s.compiled {
            NOT_COMPILED => return None,
            0 => {}
            n => return self.compiled.get(n as usize - 1).cloned(),
        }
        s.runs = s.runs.saturating_add(1);
        if s.runs < compiler.threshold() {
            return None;
        }
        self.compile(slot, compiler)
    }

    #[cold]
    #[inline(never)]
    fn compile(&mut self, slot: usize, compiler: &dyn Compiler) -> Option<Arc<dyn CompiledBlock>> {
        let range = self.slots[slot].range();
        let forms: Vec<Form> = range
            .map(|i| (self.code.decoded[i], self.code.instructions[i].rip.0))
            .take_while(|(d, _)| !matches!(d.fast, Fast::None))
            .map(|(d, rip)| Form {
                rip,
                next: d.next,
                fast: d.fast,
            })
            .collect();
        let compiled = if forms.is_empty() {
            None
        } else {
            compiler.compile(&forms)
        };
        let Some(compiled) = compiled else {
            self.slots[slot].compiled = NOT_COMPILED;
            return None;
        };
        if self.compiled.len() >= MAX_COMPILED {
            self.compiled.clear();
            for s in &mut self.slots {
                if s.compiled != NOT_COMPILED {
                    s.compiled = 0;
                    s.runs = 0;
                }
            }
        }
        self.compiled.push(compiled.clone());
        self.slots[slot].compiled = u32::try_from(self.compiled.len()).unwrap_or(NOT_COMPILED);
        Some(compiled)
    }
}

/// [`crate::run_cached`], running the blocks that `compiler` compiles.
pub fn run_compiled(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
    compiler: &dyn Compiler,
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
        if state.repeat_continuation.is_none()
            && let Some(compiled) = cache.compiled(cache.slot(rip), compiler)
            && left >= compiled.len() as u64
        {
            let ran = compiled.run(state, mem, generation);
            left -= ran as u64;
            i += ran;
            // The interpreter goes on in the block only from the
            // instruction after the last that ran, of the same generation.
            if ran > 0
                && (left == 0
                    || i >= end
                    || state.rip != cache.code.instructions[i].rip
                    || mem.code_generation_cached() != generation)
            {
                continue;
            }
        }
        loop {
            let decoded = &cache.code.decoded[i];
            let next = decoded.next;
            if let Err(reason) = execute_decoded(state, mem, decoded, &cache.code.instructions[i]) {
                return reason;
            }
            left -= 1;
            i += 1;
            if left == 0 || state.rip.0 != next || mem.code_generation_cached() != generation {
                break;
            }
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
