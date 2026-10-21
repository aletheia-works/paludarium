//! Each real Host worker owns CPU/decoder/thread context and shares only process resources.
use paludarium_cpu::{DecodeCache, reg, run_cached, run_cached_with_counted_hook};
use paludarium_host::{ClockId, Host, ThreadHandle};
use paludarium_jit::CodeCache;
use paludarium_kernel::{Kernel, Next, Processes, SignalInbox, Thread, ThreadGroup};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Error, ErrorKind, ExitReason, ExitStatus, signal};
use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct Execution {
    host: Arc<dyn Host>,
    mem: Arc<AddressSpace>,
    group: Arc<ThreadGroup>,
    processes: Arc<Processes>,
    kill: Arc<AtomicBool>,
    inbox: Arc<SignalInbox>,
    stopped: Arc<AtomicBool>,
    last_stop: Arc<Mutex<Option<ExitReason>>>,
    cache: Arc<dyn CodeCache>,
    accelerated: bool,
    budget: u64,
    handles: Mutex<Vec<Box<dyn ThreadHandle>>>,
    results: Mutex<Vec<Result<ExitStatus, Error>>>,
}
impl Execution {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: Arc<dyn Host>,
        mem: Arc<AddressSpace>,
        group: Arc<ThreadGroup>,
        processes: Arc<Processes>,
        kill: Arc<AtomicBool>,
        inbox: Arc<SignalInbox>,
        stopped: Arc<AtomicBool>,
        last_stop: Arc<Mutex<Option<ExitReason>>>,
        cache: Arc<dyn CodeCache>,
        accelerated: bool,
        budget: u64,
    ) -> Self {
        Self {
            host,
            mem,
            group,
            processes,
            kill,
            inbox,
            stopped,
            last_stop,
            cache,
            accelerated,
            budget,
            handles: Mutex::new(Vec::new()),
            results: Mutex::new(Vec::new()),
        }
    }
    pub fn execute(self: &Arc<Self>, mut kernel: Kernel, mut thread: Thread) {
        let memory = self.mem.clone();
        self.execute_memory(&mut kernel, &mut thread, memory);
    }
    fn execute_memory(
        self: &Arc<Self>,
        kernel: &mut Kernel,
        thread: &mut Thread,
        mut memory: Arc<AddressSpace>,
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run(kernel, thread, &mut memory)
        }))
        .unwrap_or_else(|_| Err(Error::new(ErrorKind::Host, "execution worker panicked")));
        if result.is_err() {
            self.processes
                .stop_all(ExitStatus::Signaled(signal::SIGKILL));
        }
        kernel.finish_thread(thread, &memory);
        kernel.complete_process(
            result
                .as_ref()
                .copied()
                .unwrap_or(ExitStatus::Signaled(signal::SIGKILL)),
        );
        if kernel.process().pid == 1 || result.is_err() {
            self.results
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(result);
        }
    }
    fn run(
        self: &Arc<Self>,
        kernel: &mut Kernel,
        thread: &mut Thread,
        memory: &mut Arc<AddressSpace>,
    ) -> Result<ExitStatus, Error> {
        let mut decode = DecodeCache::new();
        loop {
            #[cfg(feature = "cost-profile")]
            paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::Checkpoints, 1);
            if self.kill.load(Ordering::SeqCst) {
                #[cfg(feature = "cost-profile")]
                paludarium_cpu::jit_cost::add(paludarium_cpu::jit_cost::Counter::StopKill, 1);
                self.processes
                    .stop_all(ExitStatus::Signaled(signal::SIGKILL));
            }
            match kernel.checkpoint(thread, memory) {
                Next::Exit(status) => return Ok(status),
                Next::Stopped => {
                    self.stopped.store(true, Ordering::SeqCst);
                    self.pause()?;
                    continue;
                }
                _ => self.stopped.store(false, Ordering::SeqCst),
            }
            // JIT blocks execute at most 64 instructions. Smaller explicit
            // budgets retain exact interpreter checkpoint/kill semantics.
            let reason = if self.accelerated && self.budget >= 64 {
                run_cached_with_counted_hook(
                    &mut thread.cpu,
                    memory,
                    self.budget,
                    &mut decode,
                    paludarium_cpu::AccelerationPolicy {
                        maximum_block: 64,
                        cache_rejections: self.cache.cache_rejections(),
                    },
                    |state, instruction, deterministic_rejection| {
                        if !self.cache.eligible(instruction) {
                            *deterministic_rejection = true;
                            return None;
                        }
                        #[cfg(feature = "cost-profile")]
                        paludarium_cpu::jit_cost::add(
                            paludarium_cpu::jit_cost::Counter::HookAttempts,
                            1,
                        );
                        let (result, rejected) = self.cache.try_run_with_hint(state, memory);
                        *deterministic_rejection = rejected;
                        result
                    },
                )
            } else {
                run_cached(&mut thread.cpu, memory, self.budget, &mut decode)
            };
            let next = kernel.handle(thread, memory, reason);
            if let Some(replacement) = kernel.take_exec_memory() {
                *memory = replacement;
                decode = DecodeCache::new();
            }
            if let Some((mut child, mut child_thread)) = kernel.take_child() {
                let tid = child_thread.tid;
                let pid = child.process().pid;
                let child_memory = child.take_spawn_memory().unwrap_or_else(|| memory.clone());
                let execution = self.clone();
                match self.host.spawn_thread(Box::new(move || {
                    execution.execute_memory(&mut child, &mut child_thread, child_memory)
                })) {
                    Ok(handle) => self
                        .handles
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(handle),
                    Err(error) => {
                        kernel.abandon_child(pid, tid);
                        thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
                    }
                }
                if let Err(error) = kernel.wait_vfork(&self.kill) {
                    thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
                }
            }
            match next {
                Next::Resume | Next::Stopped => {}
                Next::Exit(status) => {
                    if !matches!(reason, ExitReason::Syscall { .. }) && kernel.process().pid == 1 {
                        *self
                            .last_stop
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner) = Some(reason);
                    }
                    return Ok(status);
                }
                _ => {
                    return Err(
                        Error::new(ErrorKind::Internal, "unexpected kernel decision")
                            .with_rip(thread.cpu.rip),
                    );
                }
            }
        }
    }
    fn pause(&self) -> Result<(), Error> {
        let clock = ClockId::Monotonic;
        let now = self
            .host
            .clock(clock)
            .map_err(|_| Error::new(ErrorKind::Host, "worker clock"))?;
        self.host
            .wait_until(
                clock,
                now.saturating_add(10_000_000),
                &self.inbox.wake_token(),
            )
            .map_err(|_| Error::new(ErrorKind::Host, "worker wait"))?;
        Ok(())
    }
    pub fn finish(&self) -> Result<ExitStatus, Error> {
        let mut host_error = None;
        while self.processes.active_threads() != 0 {
            if self.kill.load(Ordering::SeqCst) {
                self.processes
                    .stop_all(ExitStatus::Signaled(signal::SIGKILL));
            }
            if let Err(error) = self.pause() {
                self.processes
                    .stop_all(ExitStatus::Signaled(signal::SIGKILL));
                host_error.get_or_insert(error);
            }
        }
        let handles =
            std::mem::take(&mut *self.handles.lock().unwrap_or_else(PoisonError::into_inner));
        for handle in handles {
            if handle.join().is_err() {
                host_error.get_or_insert_with(|| Error::new(ErrorKind::Host, "worker join"));
            }
        }
        self.stopped.store(false, Ordering::SeqCst);
        if let Some(error) = host_error {
            return Err(error);
        }
        let mut results = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = results.iter().position(Result::is_err) {
            return results.remove(index);
        }
        if let Some(status) = self.group.status() {
            return Ok(status);
        }
        results
            .pop()
            .unwrap_or_else(|| Err(Error::new(ErrorKind::Internal, "missing worker result")))
    }
}
