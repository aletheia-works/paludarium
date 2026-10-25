//! Linux system-call layer for paludarium.
//!
//! The kernel owns the process and thread state. It receives the
//! CPU's [`ExitReason`] and decides what happens next: system calls are
//! dispatched by number through an explicit table and unknown numbers return
//! `-ENOSYS`; nothing is ever passed through to the host by number. Guest
//! exceptions end the process with the matching signal; the core emulator
//! records signal registrations but never delivers signals.
#![forbid(unsafe_code)]

mod coredump;
mod inbox;
mod signals;
pub use inbox::SignalInbox;
mod devices;
mod epoll;
mod events;
mod files;
mod futex;
mod memfd;
mod proc;
mod processes;
mod sockets;
mod syscalls;
mod threads;
mod timerfd;
mod timers;
pub use processes::Processes;
pub use threads::ThreadGroup;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};

use paludarium_cpu::{CpuState, reg};
use paludarium_host::Host;
use paludarium_loader::LoadedImage;
use paludarium_mmu::AddressSpace;
use paludarium_types::{ExitReason, ExitStatus, signal};

pub use syscalls::{SyscallTable, nr};

/// What the execution loop does after the kernel handled a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Next {
    /// Continue running the thread.
    Resume,
    /// Job-control stop: retain CPU state until SIGCONT or SIGKILL.
    Stopped,
    /// The process has ended.
    Exit(ExitStatus),
}

/// A guest thread: its id and registers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    pub tid: u32,
    pub cpu: CpuState,
    pub state: ThreadState,
}
impl Thread {
    #[must_use]
    pub fn new(tid: u32, cpu: CpuState) -> Self {
        Self {
            tid,
            cpu,
            state: ThreadState {
                pid: 1,
                ..ThreadState::default()
            },
        }
    }
}

/// A registered signal action (`struct k_sigaction` on x86-64). Recorded
/// only; the core emulator does not deliver signals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// The alternate signal stack (`stack_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

/// `SS_DISABLE`.
pub const SS_DISABLE: u32 = 2;

impl Default for AltStack {
    fn default() -> Self {
        AltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        }
    }
}

/// A guest thread's CPU time: the host thread's CPU time (or, where the host
/// cannot measure it, wall time) since the guest thread's first system call,
/// published for the thread group's total. A clone starts again from zero,
/// as a new Linux thread or process does.
#[derive(Debug, Default)]
pub(crate) struct CpuAccount {
    base: Option<u64>,
    used: Arc<std::sync::atomic::AtomicU64>,
}
impl Clone for CpuAccount {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl PartialEq for CpuAccount {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.used, &other.used)
    }
}
impl Eq for CpuAccount {}

/// Brings the thread's CPU time up to date and returns it in nanoseconds;
/// called at every system call, which publishes it for the process clock,
/// and by the system calls that read the CPU clocks.
pub(crate) fn account_cpu(host: &dyn Host, group: &ThreadGroup, state: &mut ThreadState) -> u64 {
    let now = host
        .thread_cpu_time()
        .or_else(|_| host.clock(paludarium_host::ClockId::Monotonic))
        .unwrap_or(0);
    let account = &mut state.cpu;
    let base = *account.base.get_or_insert_with(|| {
        group.register_cpu(Arc::clone(&account.used));
        now
    });
    let used = now.saturating_sub(base);
    account
        .used
        .store(used, std::sync::atomic::Ordering::SeqCst);
    used
}

/// Thread-owned Linux signal context and lifecycle state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadState {
    pub pid: u32,
    pub signal_actions: BTreeMap<i32, SignalAction>,
    pub signal_mask: u64,
    /// One-time original mask for a signal interrupting epoll_pwait.
    pub(crate) wait_restore_mask: Option<u64>,
    pub alt_stack: AltStack,
    pub clear_child_tid: u64,
    pub exit_status: Option<ExitStatus>,
    pub(crate) pending: Vec<signals::PendingSignal>,
    pub(crate) frames: Vec<signals::SavedFrame>,
    pub(crate) timer: signals::RealTimer,
    /// The earliest POSIX timer deadline, synced from the thread group.
    pub(crate) posix_deadline: Option<u64>,
    pub stopped: bool,
    /// The thread's name (`comm`), NUL-padded: PR_SET_NAME and PR_GET_NAME.
    pub(crate) name: [u8; 16],
    pub(crate) cpu: CpuAccount,
    /// The syscall now returning, when Linux would run it again (rather than
    /// fail it with EINTR) if the signal that interrupted it runs no handler.
    pub(crate) restart: Option<u64>,
    /// What `restart_syscall` resumes after a stop: a wait with a timeout,
    /// which Linux restarts with the time left (ERESTART_RESTARTBLOCK). It
    /// lasts until a handler runs, through the checkpoints of the stop.
    pub(crate) restart_block: Option<signals::RestartBlock>,
}

impl ThreadState {
    /// Names the thread after the last component of `path`, cut to 15
    /// bytes, as Linux's exec does.
    pub fn name_after(&mut self, path: &[u8]) {
        let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
        self.name = [0; 16];
        let length = base.len().min(15);
        self.name[..length].copy_from_slice(&base[..length]);
    }
}

/// Process identity; shared resources are owned by ThreadGroup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
}

/// The emulated Linux kernel for one process.
pub struct Kernel {
    host: Arc<dyn Host>,
    process: Process,
    table: SyscallTable,
    files: files::Files,
    cancellation: Arc<AtomicBool>,
    inbox: Arc<SignalInbox>,
    group: Arc<ThreadGroup>,
    pending_child: Option<(Box<Kernel>, Thread)>,
    processes: Arc<Processes>,
    spawn_memory: Option<Arc<AddressSpace>>,
    exec_memory: Option<Arc<AddressSpace>>,
    vfork_release: Option<Arc<AtomicBool>>,
    vfork_wait: Option<Arc<AtomicBool>>,
    /// System-call numbers the guest called that are not in the table,
    /// shared by every thread and process (diagnostics only).
    unimplemented: Arc<Mutex<BTreeSet<u64>>>,
    /// The task this thread counts as, for a thread other than its process's
    /// leader; the leader's is the process's, kept until it is reaped.
    task: Option<processes::TaskCharge>,
}

impl Kernel {
    /// Creates a kernel that performs host I/O through `host`.
    pub fn new(host: Arc<dyn Host>) -> Self {
        let files = files::Files::with_host(Arc::clone(&host));
        let group = Arc::new(ThreadGroup::default());
        let processes = Arc::new(Processes::new(group.clone()));
        Kernel {
            host,
            process: Process { pid: 1 },
            table: SyscallTable::u1(),
            files,
            cancellation: Arc::new(AtomicBool::new(false)),
            inbox: Arc::new(SignalInbox::default()),
            group,
            pending_child: None,
            processes,
            spawn_memory: None,
            exec_memory: None,
            vfork_release: None,
            vfork_wait: None,
            unimplemented: Arc::default(),
            task: None,
        }
    }

    /// Limits the session to `max` tasks (threads, and processes until they
    /// are reaped), as a cgroup's `pids.max`: `clone` and `fork` beyond it
    /// fail with `EAGAIN`. The first process counts as one.
    #[must_use]
    pub fn with_task_limit(self, max: u64) -> Self {
        self.processes.set_task_limit(max);
        self
    }

    /// Caps RLIMIT_NOFILE at `max`: the first process starts with both its
    /// limits at most `max`, and raising the hard limit beyond it fails with
    /// `EPERM`, as above Linux's `fs.nr_open`.
    #[must_use]
    pub fn with_open_file_limit(self, max: u64) -> Self {
        self.processes.set_open_file_limit(max);
        self
    }

    /// Records the unimplemented system-call numbers the guest calls in `log`.
    #[must_use]
    pub fn with_unimplemented_log(mut self, log: Arc<Mutex<BTreeSet<u64>>>) -> Self {
        self.unimplemented = log;
        self
    }

    /// Explicit virtual terminal dimensions override Host dimensions on stdio.
    #[must_use]
    pub fn with_terminal_size(mut self, columns: u16, rows: u16) -> Self {
        self.files.terminal_size = Some((columns, rows));
        self
    }

    /// Connects the filesystem shared with the loader.
    pub fn with_file_system(mut self, fs: Arc<dyn paludarium_vfs::FileSystem>) -> Self {
        self.files.fs = fs;
        self
    }
    /// Sets an existing virtual directory as the initial guest cwd.
    pub fn with_current_directory(mut self, path: &[u8]) -> Result<Self, paludarium_types::Errno> {
        self.files.set_current_directory(path)?;
        Ok(self)
    }

    /// Connects the session's bounded-wait cancellation token.
    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Connects the runtime's single-process signal queue and wait wake token.
    pub fn with_signal_inbox(mut self, inbox: Arc<SignalInbox>) -> Self {
        self.group.set_process_inbox(Arc::clone(&inbox));
        self.cancellation = inbox.wake_token();
        self.inbox = inbox;
        self
    }

    /// The process state.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.process
    }

    /// Creates the initial thread for a loaded image: rip at the entry
    /// point, rsp at the initial stack, everything else zero.
    #[must_use]
    pub fn spawn_initial(&self, image: &LoadedImage) -> Thread {
        self.group
            .register(self.process.pid, Arc::clone(&self.inbox));
        self.group.set_start_stack(image.initial_stack_pointer.0);
        Thread {
            tid: self.process.pid,
            cpu: CpuState::new(image.entry_point, image.initial_stack_pointer),
            state: ThreadState {
                pid: self.process.pid,
                ..ThreadState::default()
            },
        }
    }

    fn terminate(&mut self, thread: &mut Thread, signal: i32) -> Next {
        let siginfo = coredump::kernel_siginfo(&thread.state, signal);
        self.terminate_with(thread, signal, siginfo)
    }

    /// Ends the process by `signal`, whose siginfo is `siginfo`, and starts
    /// its core dump when the signal dumps core and the process may.
    fn terminate_with(&mut self, thread: &mut Thread, signal: i32, siginfo: [u8; 128]) -> Next {
        if coredump::dumps_core(signal)
            && let Some(limit) = self.processes.core_limit(self.process.pid)
        {
            self.group.begin_core(coredump::Dump {
                signal,
                dumper: thread.tid,
                siginfo,
                limit,
                threads: Vec::new(),
                clear_tids: Vec::new(),
            });
        }
        let status = ExitStatus::Signaled(signal);
        thread.state.exit_status = Some(status);
        self.group.stop(status);
        Next::Exit(status)
    }

    /// Queues a signal in a thread's process-pending view (manual Kernel clients).
    pub fn queue_signal(
        &mut self,
        thread: &mut Thread,
        number: i32,
    ) -> Result<(), paludarium_types::Errno> {
        if !(1..=64).contains(&number) {
            return Err(paludarium_types::Errno::EINVAL);
        }
        if number == 18 {
            self.group.job_continue();
        }
        signals::queue(&mut thread.state, signals::PendingSignal::user(number, 0));
        Ok(())
    }

    /// Delivers an unblocked pending signal at a CPU/Kernel boundary.
    pub fn checkpoint(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        // Only the checkpoint right after the syscall may restart it.
        let restart = thread.state.restart.take();
        if self.group.retired(thread.tid) {
            return Next::Exit(ExitStatus::Exited(0));
        }
        self.group.register(thread.tid, Arc::clone(&self.inbox));
        if let Some(status) = self.group.status() {
            return Next::Exit(status);
        }
        self.sync_actions(thread);
        self.group.drain_process(&mut thread.state);
        self.inbox.drain(&mut thread.state);
        if thread.state.pending.iter().any(|s| s.number == 18) {
            self.group.job_continue();
        }
        if let Ok(now) = self.host.clock(paludarium_host::ClockId::Monotonic) {
            self.group.expire_timer(&mut thread.state, now);
        }
        while let Some(index) = signals::next_pending(&thread.state, false) {
            let signal = thread.state.pending.remove(index);
            let action = thread
                .state
                .signal_actions
                .get(&signal.number)
                .copied()
                .unwrap_or_default();
            if signal.synchronous
                && (action.handler <= 1
                    || thread.state.signal_mask & (1u64 << (signal.number - 1)) != 0)
            {
                let siginfo = signals::siginfo(&thread.state, &signal);
                return self.terminate_with(thread, signal.number, siginfo);
            }
            if action.handler == 1
                || action.handler == 0 && matches!(signal.number, 17 | 18 | 23 | 28)
            {
                continue;
            }
            if signal.number == 19 || action.handler == 0 && matches!(signal.number, 20..=22) {
                thread.state.stopped = true;
                // A group stop is reported once, by the thread that starts it.
                self.processes
                    .job_stop(self.process.pid, &self.group, signal.number);
                // A temporary wait mask (rt_sigsuspend, epoll_pwait) ends here
                // too, so a restarted call sees the original mask again.
                if let Some(mask) = thread.state.wait_restore_mask.take() {
                    thread.state.signal_mask = mask;
                }
                Self::rewind_restart(thread, restart);
                return Next::Stopped;
            }
            if action.handler == 0 || signal.number == 9 {
                let siginfo = signals::siginfo(&thread.state, &signal);
                return self.terminate_with(thread, signal.number, siginfo);
            }
            // A handler ends any restart, as Linux's signal frame setup sets
            // restart_block to do_no_restart_syscall.
            thread.state.restart_block = None;
            let delivery_mask = thread.state.signal_mask;
            let restore_mask = thread.state.wait_restore_mask.take();
            if let Some(mask) = restore_mask {
                // The signal is selected using pwait's temporary mask, but
                // its ucontext must restore the original mask on sigreturn.
                thread.state.signal_mask = mask;
            }
            if signals::install(&mut thread.state, &mut thread.cpu, mem, signal, action).is_err() {
                return self.terminate(thread, signal::SIGSEGV);
            }
            if restore_mask.is_some() {
                // Handler execution still uses the temporary mask, plus the
                // same action/self-block rules as ordinary signal delivery.
                thread.state.signal_mask = delivery_mask | action.mask;
                if action.flags & signals::SA_NODEFER == 0 {
                    thread.state.signal_mask |= 1u64 << (signal.number - 1);
                }
                thread.state.signal_mask &= !signals::unblockable();
            }
            if action.flags & signals::SA_RESETHAND != 0 {
                self.group
                    .set_action(signal.number, SignalAction::default());
            }
            return Next::Resume;
        }
        if let Some(mask) = thread.state.wait_restore_mask.take() {
            thread.state.signal_mask = mask;
        }
        if thread.state.stopped {
            Self::rewind_restart(thread, restart);
            Next::Stopped
        } else {
            Next::Resume
        }
    }

    /// A stop ran no handler, so a syscall it interrupted with EINTR runs
    /// again after the continue, as Linux restarts ERESTARTSYS and
    /// ERESTARTNOHAND: the syscall instruction is re-executed.
    fn rewind_restart(thread: &mut Thread, restart: Option<u64>) {
        if let Some(number) = restart
            && thread.cpu.gpr[reg::RAX] == paludarium_types::Errno(4).to_syscall_return()
            && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
        {
            thread.cpu.rip = paludarium_types::GuestAddr(rip);
            thread.cpu.gpr[reg::RAX] = number;
        }
    }

    /// Handles a stop of `thread` (W3, W4).
    pub fn handle(&mut self, thread: &mut Thread, mem: &AddressSpace, reason: ExitReason) -> Next {
        self.group.register(thread.tid, Arc::clone(&self.inbox));
        let fault = match reason {
            ExitReason::PageFault {
                rip,
                addr,
                write,
                fetch,
                mapped,
                present,
            } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGSEGV,
                    code: if mapped { 2 } else { 1 },
                    addr: addr.0,
                    trap: 14,
                    error: 4
                        | (u64::from(write) * 2)
                        | u64::from(present)
                        | (u64::from(fetch) * 16),
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            ExitReason::InvalidOpcode { rip, .. } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGILL,
                    code: 2,
                    addr: rip.0,
                    trap: 6,
                    error: 0,
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            ExitReason::ArithmeticFault { rip } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGFPE,
                    code: 1,
                    addr: rip.0,
                    trap: 0,
                    error: 0,
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            ExitReason::FloatingPointFault { rip, code } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGFPE,
                    code: i32::from(code),
                    addr: rip.0,
                    trap: 19,
                    error: 0,
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            ExitReason::GeneralProtection { rip } | ExitReason::Halt { rip } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGSEGV,
                    code: 128,
                    addr: 0,
                    trap: 13,
                    error: 0,
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            _ => None,
        };
        if let Some(fault) = fault {
            signals::queue(&mut thread.state, fault);
            return self.checkpoint(thread, mem);
        }
        match reason {
            ExitReason::Syscall { .. } => self.syscall(thread, mem),
            ExitReason::PageFault { .. }
            | ExitReason::GeneralProtection { .. }
            | ExitReason::Halt { .. } => self.terminate(thread, signal::SIGSEGV),
            ExitReason::InvalidOpcode { .. } => self.terminate(thread, signal::SIGILL),
            ExitReason::ArithmeticFault { .. } | ExitReason::FloatingPointFault { .. } => {
                self.terminate(thread, signal::SIGFPE)
            }
            ExitReason::BudgetExhausted { .. } => self.checkpoint(thread, mem),
            // Later units add stop reasons; until then they end the process.
            _ => self.terminate(thread, signal::SIGSEGV),
        }
    }

    fn syscall(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        self.sync_actions(thread);
        // Before the call queues a signal itself (a fault, SIGPIPE, tgkill
        // to itself), so that it does not merge into a discarded one.
        self.group.apply_discards(&mut thread.state);
        self.group.sync_timer(&mut thread.state);
        account_cpu(&*self.host, &self.group, &mut thread.state);
        let mut number = thread.cpu.gpr[reg::RAX];
        let mut args = [
            thread.cpu.gpr[reg::RDI],
            thread.cpu.gpr[reg::RSI],
            thread.cpu.gpr[reg::RDX],
            thread.cpu.gpr[reg::R10],
            thread.cpu.gpr[reg::R8],
            thread.cpu.gpr[reg::R9],
        ];
        thread.state.restart = signals::restarts_without_handler(number, &args).then_some(number);
        // clone reads only the low 32 bits of its flags, as Linux's sys_clone
        // does (lower_32_bits); clone3's wider flags reach the code below.
        if number == 56 {
            args[0] &= 0xffff_ffff;
        }
        // clone3 runs as the clone it describes.
        if number == 435 {
            match processes::clone3_args(mem, args[0], args[1]) {
                Ok(legacy) => (number, args) = (56, legacy),
                Err(error) => {
                    thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
                    return Next::Resume;
                }
            }
        }
        if let Some(next) = self.process_syscall(thread, mem, number, args) {
            return next;
        }
        if let Some(next) = self.thread_syscall(thread, mem, number, args) {
            return next;
        }
        let Some(handler) = self.table.get(number) else {
            self.unimplemented
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(number);
            thread.cpu.gpr[reg::RAX] = paludarium_types::Errno::ENOSYS.to_syscall_return();
            return Next::Resume;
        };
        let mut ctx = syscalls::Context {
            host: &*self.host,
            shared_host: &self.host,
            files: &mut self.files,
            process: &mut thread.state,
            cpu: &mut thread.cpu,
            mem,
            cancellation: &self.cancellation,
            inbox: &self.inbox,
            group: &self.group,
            processes: &self.processes,
        };
        let outcome = handler(&mut ctx, args);
        if number == syscalls::nr::SETITIMER {
            self.group.set_timer(thread.state.timer);
        }
        if number == syscalls::nr::RT_SIGACTION
            && args[1] != 0
            && let Some(action) = thread.state.signal_actions.get(&(args[0] as i32))
        {
            self.group.set_action(args[0] as i32, *action);
        }
        self.inbox.drain(&mut thread.state);
        match outcome {
            syscalls::Outcome::Return(value) => {
                thread.cpu.gpr[reg::RAX] = value;
                // Linux exposes the rewound syscall in a SA_RESTART handler's
                // context only when write was interrupted before any transfer.
                if number == syscalls::nr::WRITE
                    && value == paludarium_types::Errno(4).to_syscall_return()
                {
                    let action = signals::next_pending(&thread.state, true)
                        .and_then(|index| {
                            thread
                                .state
                                .signal_actions
                                .get(&thread.state.pending[index].number)
                        })
                        .filter(|action| action.handler > 1);
                    if action.is_some_and(|a| a.flags & 0x1000_0000 != 0)
                        && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
                    {
                        thread.cpu.rip = paludarium_types::GuestAddr(rip);
                        thread.cpu.gpr[reg::RAX] = number;
                    }
                }
                self.checkpoint(thread, mem)
            }
            syscalls::Outcome::Restored => self.checkpoint(thread, mem),
            syscalls::Outcome::BadFrame => self.terminate(thread, signal::SIGSEGV),
            syscalls::Outcome::Exit(code) => {
                let status = ExitStatus::Exited(code & 0xff);
                thread.state.exit_status = Some(status);
                Next::Exit(status)
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod terminal_tests;

#[cfg(test)]
mod threads_tests;

#[cfg(test)]
mod events_tests;

#[cfg(test)]
mod processes_tests;
#[cfg(test)]
mod wasm_tests;
