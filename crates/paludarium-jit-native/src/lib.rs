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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use paludarium_cpu::compile::Compiler;

/// How many times a block is entered before it is compiled, unless the
/// caller gives another number.
pub const DEFAULT_THRESHOLD: u16 = 300;

/// The native compiler for this host, compiling a block once it has been
/// entered `threshold` times on a thread of its own, while the interpreter
/// goes on running the block; `None` when the host has none.
#[must_use]
pub fn compiler(threshold: u16) -> Option<Arc<dyn Compiler>> {
    compiler_with(threshold, true)
}

/// The requests for code that a guest thread waits for (synchronous mode
/// only), for a test's clock that should not pass while one does.
#[derive(Debug, Default)]
pub struct Waits {
    started: AtomicU64,
    waiting: AtomicUsize,
}

impl Waits {
    /// How many have been made, and how many wait now.
    #[must_use]
    pub fn counts(&self) -> (u64, usize) {
        (
            self.started.load(Ordering::SeqCst),
            self.waiting.load(Ordering::SeqCst),
        )
    }
    /// One more request, which waits until the guard drops, whatever it
    /// comes to.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn begin(&self) -> Waiting<'_> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        self.started.fetch_add(1, Ordering::SeqCst);
        Waiting(self)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
struct Waiting<'a>(&'a Waits);

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

/// [`compiler_with`]`(threshold, false)`, with the counts of its requests.
#[must_use]
pub fn waiting_compiler(threshold: u16) -> Option<(Arc<dyn Compiler>, Arc<Waits>)> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        native::NativeCompiler::new(threshold, false).map(|compiler| {
            let waits = compiler.waits();
            (Arc::new(compiler) as Arc<dyn Compiler>, waits)
        })
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        let _ = threshold;
        None
    }
}

/// [`compiler`], but when `background` is false the thread that runs the
/// block waits for its code, so that a block runs compiled from the entry
/// that reaches the threshold (as the differential tests want). The code is
/// compiled on the JIT's own thread either way: the host CPU time of the
/// thread that runs the block is its guest thread's.
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
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    use cranelift_codegen::control::ControlPlane;
    use cranelift_codegen::isa::OwnedTargetIsa;
    use cranelift_codegen::settings::{self, Configurable};
    use paludarium_cpu::CpuState;
    use paludarium_cpu::compile::{CompiledBlock, Compiler, Form};
    use paludarium_mmu::AddressSpace;

    use crate::exec::{self, Code, Context};
    use crate::{Waits, emit};

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

    /// What compiles: shared with the thread that does.
    struct Machine {
        isa: OwnedTargetIsa,
        statistics: Statistics,
        /// Whether to report the statistics on standard error
        /// (`PALUDARIUM_JIT_STATS` set).
        report: bool,
        /// Makes [`Machine::fill`] panic.
        #[cfg(test)]
        panics: std::sync::atomic::AtomicBool,
    }

    impl Machine {
        /// The machine code of `forms`, `None` when Cranelift fails or the
        /// code would need relocating.
        fn machine_code(&self, forms: &[Form]) -> Option<Vec<u8>> {
            let function = emit::function(forms, exec::helpers(), self.isa.frontend_config());
            let mut context = cranelift_codegen::Context::for_function(function);
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
            #[cfg(test)]
            assert!(!self.panics.load(Ordering::Relaxed), "the compile fails");
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

    type Job = Box<dyn FnOnce() + Send>;

    /// The JIT's own thread, which does the jobs in turn and ends with the
    /// `Worker`; it starts with the first job.
    #[derive(Default)]
    pub(crate) struct Worker {
        queue: Mutex<Option<Sender<Job>>>,
        /// The requests that wait.
        waits: Arc<Waits>,
    }

    impl Worker {
        /// Hands `job` to the thread, starting it first if need be; false
        /// when it cannot be had. A panic in `job` ends the thread, which
        /// then drops the jobs it has not done and cannot be had again.
        fn send(&self, job: Job) -> bool {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            if queue.is_none() {
                let (sender, receiver) = mpsc::channel::<Job>();
                let started = std::thread::Builder::new()
                    .name("paludarium-jit".into())
                    .spawn(move || {
                        for job in receiver {
                            job();
                        }
                    });
                if started.is_err() {
                    return false;
                }
                *queue = Some(sender);
            }
            queue.as_ref().is_some_and(|q| q.send(job).is_ok())
        }

        pub(crate) fn waits(&self) -> Arc<Waits> {
            self.waits.clone()
        }

        /// Does `work` on the thread and waits for its end; false when the
        /// thread cannot be had. `work` may not call this. When `work`
        /// panics, so does this, and the thread goes on to the next job.
        ///
        /// The wait is not one of the host's that count as the guest
        /// thread's context switches (`paludarium_host::switches`).
        pub(crate) fn run(&self, work: impl FnOnce() + Send + 'static) -> bool {
            let _waiting = self.waits.begin();
            let (done, ended) = mpsc::sync_channel(1);
            let job = move || {
                let _ = done.send(catch_unwind(AssertUnwindSafe(work)));
            };
            if !self.send(Box::new(job)) {
                return false;
            }
            match ended.recv() {
                Ok(Ok(())) => true,
                Ok(Err(panic)) => resume_unwind(panic),
                // The thread has gone and dropped the job.
                Err(_) => false,
            }
        }
    }

    pub(crate) struct NativeCompiler {
        machine: Arc<Machine>,
        threshold: u16,
        /// The code of the forms compiled so far, or being compiled.
        /// Mapping and protecting memory changes the code generation, which
        /// makes the interpreter decode every block again, mostly to the
        /// same forms; their code is the same, so it is reused.
        kept: Mutex<HashMap<Vec<Form>, Arc<PendingBlock>>>,
        /// What compiles blocks.
        worker: Worker,
        /// Whether [`Compiler::compile`] leaves a block to `worker` without
        /// waiting for its code.
        background: bool,
    }

    impl NativeCompiler {
        pub(crate) fn new(threshold: u16, background: bool) -> Option<Self> {
            // `none` compiles a block in a fraction of `speed`'s time; with
            // the default threshold it keeps most of the speed-up and costs
            // short programs far less ("A native JIT" in
            // docs/design/decisions.md).
            Self::with_settings(threshold, background, &[("opt_level", "none")])
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
                    #[cfg(test)]
                    panics: std::sync::atomic::AtomicBool::new(false),
                }),
                threshold: threshold.max(1),
                kept: Mutex::new(HashMap::new()),
                worker: Worker::default(),
                background,
            })
        }

        pub(crate) fn waits(&self) -> Arc<Waits> {
            self.worker.waits()
        }

        #[cfg(test)]
        pub(crate) fn machine_code(&self, forms: &[Form]) -> Option<Vec<u8>> {
            self.machine.machine_code(forms)
        }

        /// Whether compiling panics from now on.
        #[cfg(test)]
        pub(crate) fn set_panics(&self, panics: bool) {
            self.machine.panics.store(panics, Ordering::Relaxed);
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
            // No lock is held here that the thread needs: `kept`'s is
            // released above, and `fill` takes none.
            let machine = self.machine.clone();
            let (forms, pending) = (forms.to_vec(), Unfilled(block.clone()));
            let fill = move || machine.fill(&forms, &pending.0);
            if self.background {
                if !self.worker.send(Box::new(fill)) {
                    let _ = block.code.set(None);
                    return None;
                }
            } else {
                if !self.worker.run(fill) {
                    let _ = block.code.set(None);
                }
                block.code.get()?.as_ref()?;
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

    /// A block whose compile has not ended: when its job panics or is
    /// dropped, compiling it has failed, and the same forms are turned down
    /// again.
    struct Unfilled(Arc<PendingBlock>);

    impl Drop for Unfilled {
        fn drop(&mut self) {
            // Nothing once it is filled.
            let _ = self.0.code.set(None);
        }
    }

    impl CompiledBlock for PendingBlock {
        fn run(&self, state: &mut CpuState, mem: &AddressSpace, generation: u64) -> usize {
            let Some(Some(code)) = self.code.get() else {
                return 0;
            };
            let ran = code.run(state, &Context::new(mem, generation));
            usize::try_from(ran).unwrap_or(0).min(self.len)
        }

        fn len(&self) -> usize {
            self.len
        }
    }
}
