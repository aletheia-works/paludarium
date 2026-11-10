//! Native JIT for paludarium: the blocks the interpreter enters often are
//! compiled to host code with Cranelift.
//!
//! It compiles the instruction forms that the interpreter works out when
//! it decodes ([`paludarium_cpu::compile::Fast`]), to the same meaning, and
//! runs through [`paludarium_cpu::compile::run_compiled`]. Only Linux on
//! x86-64 hosts has it for now; elsewhere [`compiler`] returns `None`.
//!
//! The crate allows `unsafe` code only in `exec`, which maps the code
//! executable and calls it.
#![deny(unsafe_code)]

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod emit;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod exec;
#[cfg(test)]
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod tests;

use std::sync::Arc;

use paludarium_cpu::compile::Compiler;

/// How many times a block is entered before it is compiled, unless the
/// caller gives another number.
pub const DEFAULT_THRESHOLD: u16 = 100;

/// The native compiler for this host, compiling a block once it has been
/// entered `threshold` times on a thread of its own, while the interpreter
/// goes on running the block; `None` when the host has none.
#[must_use]
pub fn compiler(threshold: u16) -> Option<Arc<dyn Compiler>> {
    compiler_with(threshold, true)
}

/// [`compiler`], compiling on the thread that runs the block instead when
/// `background` is false, so that a block runs compiled from the entry that
/// reaches the threshold (as the differential tests want).
#[must_use]
pub fn compiler_with(threshold: u16, background: bool) -> Option<Arc<dyn Compiler>> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        native::NativeCompiler::new(threshold, background).map(|c| Arc::new(c) as Arc<dyn Compiler>)
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        let _ = (threshold, background);
        None
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod native {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    use cranelift_codegen::control::ControlPlane;
    use cranelift_codegen::isa::OwnedTargetIsa;
    use cranelift_codegen::settings::{self, Configurable};
    use paludarium_cpu::CpuState;
    use paludarium_cpu::compile::{CompiledBlock, Compiler, Form};
    use paludarium_mmu::AddressSpace;
    use paludarium_types::GuestAddr;

    use crate::emit::{self, FS_BASE, GS_BASE, RFLAGS, RIP, WORDS};
    use crate::exec::{self, Code, Context};

    /// Counts of what the compiler did, for measuring.
    #[derive(Default)]
    pub(crate) struct Statistics {
        pub blocks: AtomicU64,
        pub instructions: AtomicU64,
        pub nanoseconds: AtomicU64,
        pub failures: AtomicU64,
        /// Blocks offered again, after their code was decoded again,
        /// whose earlier code was reused.
        pub reused: AtomicU64,
    }

    /// The most compiled blocks [`NativeCompiler`] keeps for reuse; past
    /// it, it forgets them all.
    const MAX_KEPT: usize = 1 << 16;

    /// What compiles: shared with the background thread.
    struct Machine {
        isa: OwnedTargetIsa,
        statistics: Statistics,
        /// Whether to report the statistics on standard error
        /// (`PALUDARIUM_JIT_STATS` set).
        report: bool,
    }

    impl Machine {
        /// The machine code of `forms`, `None` when Cranelift fails or the
        /// code would need relocating.
        fn machine_code(&self, forms: &[Form]) -> Option<Vec<u8>> {
            let mut context = cranelift_codegen::Context::for_function(emit::function(
                forms,
                exec::helpers(),
                self.isa.frontend_config(),
            ));
            let compiled = context
                .compile(&*self.isa, &mut ControlPlane::default())
                .ok()?;
            if !compiled.buffer.relocs().is_empty() {
                return None;
            }
            Some(compiled.code_buffer().to_vec())
        }

        /// Compiles `forms` into `block`.
        fn fill(&self, forms: &[Form], block: &PendingBlock) {
            let started = std::time::Instant::now();
            let code = self.machine_code(forms).and_then(|bytes| Code::new(&bytes));
            let s = &self.statistics;
            s.nanoseconds.fetch_add(
                u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            let Some(code) = code else {
                s.failures.fetch_add(1, Ordering::Relaxed);
                let _ = block.code.set(None);
                return;
            };
            let _ = block.code.set(Some(code));
            let blocks = s.blocks.fetch_add(1, Ordering::Relaxed) + 1;
            s.instructions
                .fetch_add(forms.len() as u64, Ordering::Relaxed);
            if self.report && blocks.is_power_of_two() {
                eprintln!(
                    "paludarium: jit: {blocks} blocks of {} instructions in {} ms, {} reused, {} failed",
                    s.instructions.load(Ordering::Relaxed),
                    s.nanoseconds.load(Ordering::Relaxed) / 1_000_000,
                    s.reused.load(Ordering::Relaxed),
                    s.failures.load(Ordering::Relaxed),
                );
            }
        }
    }

    type Job = (Vec<Form>, Arc<PendingBlock>);

    pub(crate) struct NativeCompiler {
        machine: Arc<Machine>,
        threshold: u16,
        /// The code of the forms compiled so far, or being compiled.
        /// Mapping and protecting memory changes the code generation, which
        /// makes the interpreter decode every block again, mostly to the
        /// same forms; their code is the same, so it is reused.
        kept: Mutex<HashMap<Vec<Form>, Arc<PendingBlock>>>,
        /// Where blocks go to be compiled in the background, when they do;
        /// the thread starts with the first.
        queue: Option<Mutex<Option<Sender<Job>>>>,
    }

    impl NativeCompiler {
        pub(crate) fn new(threshold: u16, background: bool) -> Option<Self> {
            // Compiled in the background, `speed` costs little and makes
            // the fastest code ("A native JIT" in docs/design/decisions.md).
            Self::with_settings(threshold, background, &[("opt_level", "speed")])
        }

        /// With these Cranelift settings.
        pub(crate) fn with_settings(
            threshold: u16,
            background: bool,
            set: &[(&str, &str)],
        ) -> Option<Self> {
            let mut flags = settings::builder();
            for (name, value) in set {
                flags.set(name, value).ok()?;
            }
            flags
                .set(
                    "enable_verifier",
                    if cfg!(debug_assertions) {
                        "true"
                    } else {
                        "false"
                    },
                )
                .ok()?;
            let isa = cranelift_native::builder()
                .ok()?
                .finish(settings::Flags::new(flags))
                .ok()?;
            Some(NativeCompiler {
                machine: Arc::new(Machine {
                    isa,
                    statistics: Statistics::default(),
                    report: std::env::var_os("PALUDARIUM_JIT_STATS").is_some(),
                }),
                threshold: threshold.max(1),
                kept: Mutex::new(HashMap::new()),
                queue: background.then(|| Mutex::new(None)),
            })
        }

        #[cfg(test)]
        pub(crate) fn machine_code(&self, forms: &[Form]) -> Option<Vec<u8>> {
            self.machine.machine_code(forms)
        }

        /// Hands `job` to the background thread, starting it first if
        /// need be; false when it cannot be had.
        fn send(&self, queue: &Mutex<Option<Sender<Job>>>, job: Job) -> bool {
            let mut queue = queue.lock().unwrap_or_else(PoisonError::into_inner);
            if queue.is_none() {
                let (sender, receiver) = mpsc::channel::<Job>();
                let machine = self.machine.clone();
                let started = std::thread::Builder::new()
                    .name("paludarium-jit".into())
                    .spawn(move || {
                        for (forms, block) in receiver {
                            machine.fill(&forms, &block);
                        }
                    });
                if started.is_err() {
                    return false;
                }
                *queue = Some(sender);
            }
            queue.as_ref().is_some_and(|q| q.send(job).is_ok())
        }
    }

    impl Compiler for NativeCompiler {
        fn threshold(&self) -> u16 {
            self.threshold
        }

        fn compile(&self, forms: &[Form]) -> Option<Arc<dyn CompiledBlock>> {
            let block = {
                let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(block) = kept.get(forms) {
                    // Forms that failed to compile are turned down again.
                    if matches!(block.code.get(), Some(None)) {
                        return None;
                    }
                    self.machine
                        .statistics
                        .reused
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(block.clone());
                }
                if kept.len() >= MAX_KEPT {
                    kept.clear();
                }
                let block = Arc::new(PendingBlock {
                    code: OnceLock::new(),
                    len: forms.len(),
                });
                kept.insert(forms.to_vec(), block.clone());
                block
            };
            match &self.queue {
                Some(queue) => {
                    if !self.send(queue, (forms.to_vec(), block.clone())) {
                        let _ = block.code.set(None);
                        return None;
                    }
                }
                None => {
                    self.machine.fill(forms, &block);
                    block.code.get()?.as_ref()?;
                }
            }
            Some(block)
        }
    }

    /// A block's code, once it is compiled (`None` when compiling failed):
    /// until then, and after a failure, it runs nothing and the interpreter
    /// runs the block.
    pub(crate) struct PendingBlock {
        code: OnceLock<Option<Code>>,
        len: usize,
    }

    impl CompiledBlock for PendingBlock {
        fn run(&self, state: &mut CpuState, mem: &AddressSpace, generation: u64) -> usize {
            let Some(Some(code)) = self.code.get() else {
                return 0;
            };
            let mut registers = [0; WORDS];
            registers[..16].copy_from_slice(&state.gpr);
            registers[RFLAGS] = state.rflags;
            registers[RIP] = state.rip.0;
            registers[FS_BASE] = state.fs_base;
            registers[GS_BASE] = state.gs_base;
            let context = Context { mem, generation };
            let ran = code.run(&mut registers, &context);
            let ran = usize::try_from(ran).unwrap_or(0).min(self.len);
            if ran > 0 {
                state.gpr.copy_from_slice(&registers[..16]);
                state.rflags = registers[RFLAGS];
                state.rip = GuestAddr(registers[RIP]);
            }
            ran
        }

        fn len(&self) -> usize {
            self.len
        }
    }
}
