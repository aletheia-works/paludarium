//! Linux system-call layer for paludarium.
//!
//! The kernel owns the process and thread state. It receives the
//! CPU's [`ExitReason`] and decides what happens next: system calls are
//! dispatched by number through an explicit table and unknown numbers return
//! `-ENOSYS`; nothing is ever passed through to the host by number. Guest
//! exceptions end the process with the matching signal; the core emulator
//! records signal registrations but never delivers signals.
#![forbid(unsafe_code)]

mod arguments;
mod coredump;
mod credentials;
mod inbox;
mod inotify;
mod landlock;
mod permissions;
mod signalfd;
mod signals;
pub use inbox::SignalInbox;
mod aio;
mod devices;
mod epoll;
mod events;
mod fasync;
mod fifo;
mod files;
mod filesystems;
mod inet;
mod interface;
mod io_uring;
mod ipc;
mod kcmp;
mod loopback;
mod lsm;
mod netlink;
pub use inet::{InvalidRule, NetworkPolicy};
mod futex;
mod memfd;
mod mempolicy;
mod mqueue;
mod msg;
mod namespaces;
mod page_cache;
mod proc;
mod process_vm;
mod processes;
mod pty;
mod record_locks;
mod rseq;
mod scheduling;
mod seccomp;
mod sem;
mod shm;
mod sockets;
mod syscalls;
mod sysctl;
mod syslog;
mod tcp_info;
mod threads;
mod timerfd;
mod timers;
mod unix;
mod users;
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
pub(crate) fn account_cpu(
    host: &dyn Host,
    group: &ThreadGroup,
    state: &mut ThreadState,
    tid: u32,
) -> u64 {
    let now = host
        .thread_cpu_time()
        .or_else(|_| host.clock(paludarium_host::ClockId::Monotonic))
        .unwrap_or(0);
    let account = &mut state.cpu;
    let base = *account.base.get_or_insert_with(|| {
        group.register_cpu(tid, Arc::clone(&account.used));
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
    /// The signals [`signals::queue`] has made pending here that Linux would
    /// have queued ([`signals::wakes`]), each of which its `signalfd_notify`
    /// wakes a signal file for.
    pub(crate) arrivals: u64,
    /// The process inbox's [`SignalInbox::notices`] when this thread last
    /// took in the process's signals.
    pub(crate) process_notices: u64,
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
    /// `rax` as the syscall now returning found it, upper half and all:
    /// Linux's `orig_ax`, which a restart of that same call puts back.
    pub(crate) syscall_rax: u64,
    /// What `restart_syscall` resumes after a stop: a wait with a timeout,
    /// which Linux restarts with the time left (ERESTART_RESTARTBLOCK). It
    /// lasts until a handler runs, through the checkpoints of the stop.
    pub(crate) restart_block: Option<signals::RestartBlock>,
    /// The thread's user and group IDs and capabilities.
    pub credentials: credentials::Credentials,
    /// The execution domain and flags `personality` sets, as Linux's
    /// `task_struct.personality`: copied to new threads and processes, and
    /// kept across exec but for the flags exec clears.
    pub(crate) personality: u32,
    /// The thread's `rseq` area, as Linux's `task_struct.rseq`: a fork
    /// copies it, a new thread or `CLONE_VM` child and an exec start
    /// without one.
    pub(crate) rseq: Option<rseq::Registration>,
    /// The virtual CPU it last ran on while it has `rseq`
    /// ([`Kernel::enter_cpu`]), which `getcpu` reports.
    pub(crate) on_cpu: Option<rseq::OnCpu>,
    /// The area is to be brought up to date before the thread runs again,
    /// as just registered (Linux's `rseq_set_notify_resume`).
    pub(crate) rseq_notify: bool,
    /// The thread's seccomp mode and filters ([`seccomp`]), which a new
    /// thread or process copies and exec keeps.
    pub(crate) seccomp: seccomp::Seccomp,
    /// The group's `SECCOMP_FILTER_FLAG_TSYNC` count when the thread last
    /// took its seccomp state from the group ([`ThreadGroup::take_seccomp`]).
    pub(crate) seccomp_sync: u64,
    /// For a call a signal took back from a seccomp listener, which Linux
    /// runs again whatever the call is: after a stop or a SA_RESTART
    /// handler (ERESTARTSYS, `false`), or after any handler (ERESTARTNOINTR,
    /// `true`). Taken with `restart`.
    pub(crate) seccomp_restart: Option<bool>,
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
    /// The opens of the scripts an exec ran, which close once the image it
    /// replaced has gone ([`Kernel::exec_finished`]).
    exec_closes: Option<processes::ExecOpens>,
    vfork_release: Option<Arc<AtomicBool>>,
    vfork_wait: Option<Arc<AtomicBool>>,
    /// System-call numbers the guest called that are not in the table,
    /// shared by every thread and process (diagnostics only).
    unimplemented: Arc<Mutex<BTreeSet<u64>>>,
    /// The task this thread counts as, for a thread other than its process's
    /// leader; the leader's is the process's, kept until it is reaped.
    task: Option<processes::TaskCharge>,
    /// What this thread last published for `/proc` ([`Self::publish`]).
    published: Option<Published>,
    /// The numbers `clone3`'s `set_tid` asks the clone it runs to take
    /// ([`processes::Processes::allocate_in`]); empty for any other call.
    set_tid: Vec<u32>,
    /// The thread's place among the virtual CPUs while it has `rseq`.
    seat: Option<rseq::Seat>,
}

/// What a thread published for `/proc`, to tell when it changes: the
/// thread, its name, blocked and pending signals, the address space and
/// the files, and its credentials.
#[derive(PartialEq, Eq)]
struct Published {
    tid: u32,
    name: [u8; 16],
    signals: (u64, u64, usize),
    memory: usize,
    files: [usize; 3],
    credentials: credentials::Credentials,
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
            exec_closes: None,
            vfork_release: None,
            vfork_wait: None,
            unimplemented: Arc::default(),
            task: None,
            published: None,
            set_tid: Vec::new(),
            seat: None,
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

    /// Lets the guest reach the destinations `policy` allows, over TCP, and
    /// resolve their names. Without it, `socket` refuses `AF_INET` and
    /// `AF_INET6`.
    #[must_use]
    pub fn with_network(mut self, policy: NetworkPolicy) -> Self {
        self.files.network = Some(Arc::new(inet::Network::new(policy)));
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
        self.files.set_file_system(fs);
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

    /// The program the first process loads to run `path` with `argv` and
    /// `envp`, as exec runs it, and whether `path` is a script: a `#!`
    /// script runs its interpreter, and `argv` becomes the interpreter's
    /// (`load_script`). The first process
    /// runs as root, so an interpreter needs one execute bit; `path` itself
    /// is loaded as it is, without that check.
    pub fn first_program(
        &self,
        path: &[u8],
        argv: &mut Vec<Vec<u8>>,
        envp: &[Vec<u8>],
    ) -> Result<(Vec<u8>, bool), paludarium_types::Errno> {
        let loaded = self.files.exec_path(path.to_vec())?;
        let resolved = loaded.clone();
        let program = self.files.fs.metadata(&loaded, true).ok();
        let mut budget = (paludarium_loader::MAX_ARG_BYTES as usize).saturating_sub(
            argv.iter()
                .chain(envp)
                .map(|s| s.len() + 1 + 8)
                .sum::<usize>(),
        );
        let (loaded, _) = processes::follow_scripts(
            &self.files,
            &credentials::Credentials::default(),
            (path.to_vec(), loaded),
            program,
            &mut true,
            (argv, &mut budget),
            &mut processes::ExecOpens::default(),
        )?;
        let script = loaded != resolved;
        Ok((loaded, script))
    }

    /// What the mappings of the first program's ELF interpreter, at `path`,
    /// keep while they last: a hold on its file, as Linux's hold theirs.
    pub fn interpreter_keep(&self, path: &[u8]) -> Option<paludarium_loader::Keep> {
        self.files.interpreter_keep(path)
    }
    /// Records `path` as the program the first process runs, as
    /// `/proc/self/exe` names it: with its symbolic links resolved.
    pub fn set_executable(&self, path: &[u8]) {
        let path = self
            .files
            .exec_path(path.to_vec())
            .unwrap_or_else(|_| path.to_vec());
        let path = crate::files::resolved(&self.files, &path).unwrap_or(path);
        // It runs, so its file may not be opened for writing (ETXTBSY). A
        // writer can only be the host's here, which is not counted, so the
        // program still runs, without the denial.
        if let Ok(denied) = crate::processes::deny_writes(&self.files, &path) {
            self.group.set_exe_file(denied.map(Arc::new));
        }
        self.group.set_executable(path);
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
                credentials: thread.state.credentials.clone(),
                clear_tids: Vec::new(),
                robust_lists: Vec::new(),
            });
        }
        let status = ExitStatus::Signaled(signal);
        thread.state.exit_status = Some(status);
        self.group.stop(status);
        Next::Exit(status)
    }

    /// A system call seccomp does not let run ([`seccomp::Verdict`]): it
    /// returns what the filter says, or SIGSYS is forced with `rax` as the
    /// call found it (Linux's `syscall_rollback`), or the thread ends. A
    /// thread that is not the last ends alone, as Linux's `do_exit` does;
    /// the last one ends the process, by SIGSYS with a core dump or, in
    /// strict mode, by SIGKILL.
    fn refuse(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        verdict: seccomp::Verdict,
    ) -> Next {
        thread.state.restart = None;
        thread.state.syscall_rax = thread.cpu.gpr[reg::RAX];
        match verdict {
            seccomp::Verdict::Allow | seccomp::Verdict::Notify(_) => Next::Resume,
            seccomp::Verdict::Return(value) => {
                thread.cpu.gpr[reg::RAX] = value;
                self.checkpoint(thread, mem)
            }
            seccomp::Verdict::Trap(info) => {
                signals::queue(
                    &mut thread.state,
                    signals::PendingSignal {
                        synchronous: true,
                        queued: Some(info),
                        ..signals::PendingSignal::thread(signal::SIGSYS, 1)
                    },
                );
                self.checkpoint(thread, mem)
            }
            seccomp::Verdict::Kill { process, siginfo } => {
                if !process && self.group.active_threads() > 1 {
                    Next::Exit(ExitStatus::Signaled(signal::SIGSYS))
                } else {
                    self.terminate_with(thread, signal::SIGSYS, seccomp::full_siginfo(&siginfo))
                }
            }
            seccomp::Verdict::Strict => {
                if self.group.active_threads() > 1 {
                    Next::Exit(ExitStatus::Signaled(signal::SIGKILL))
                } else {
                    self.terminate(thread, signal::SIGKILL)
                }
            }
        }
    }

    /// A system call seccomp sends to a listener: it waits for the answer,
    /// then runs (`None`) or returns what the listener says, or EINTR to be
    /// run again when a signal ends the wait.
    fn notify(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        number: u64,
        notify: &seccomp::Notify,
    ) -> Option<Next> {
        memfd::enter(self.group.memlock());
        signalfd::observe(&thread.state, &self.inbox, &self.group);
        let mut ctx = syscalls::Context {
            number,
            tid: thread.tid,
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
        let reply = seccomp::notify(&mut ctx, notify);
        self.inbox.drain(&mut thread.state);
        thread.state.syscall_rax = thread.cpu.gpr[reg::RAX];
        thread.state.restart = None;
        match reply {
            seccomp::Reply::Continue => return None,
            seccomp::Reply::Return(value) => thread.cpu.gpr[reg::RAX] = value,
            seccomp::Reply::Interrupted { always } => {
                thread.cpu.gpr[reg::RAX] = paludarium_types::Errno(4).to_syscall_return();
                thread.state.restart = Some(number);
                thread.state.seccomp_restart = Some(always);
            }
        }
        Some(self.checkpoint(thread, mem))
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

    /// Publishes what other processes read of this thread in `/proc`, when
    /// it has changed since the last time.
    pub(crate) fn publish(&mut self, tid: u32, state: &ThreadState, mem: &AddressSpace) {
        let pending = state
            .pending
            .iter()
            .filter(|s| (1..=64).contains(&s.number))
            .fold(0u64, |mask, s| mask | 1 << (s.number - 1));
        let signals = (state.signal_mask, pending, state.pending.len());
        let memory = std::ptr::from_ref(mem).addr();
        let files = self.files.identity();
        if self.published.as_ref().is_some_and(|p| {
            p.tid == tid
                && p.name == state.name
                && p.signals == signals
                && p.memory == memory
                && p.files == files
                && p.credentials == state.credentials
        }) {
            return;
        }
        self.group.publish(
            tid,
            threads::PublicThread {
                name: state.name,
                blocked: signals.0,
                pending,
                queued: signals.2,
                credentials: state.credentials.clone(),
                memory: Some(mem.view()),
                files: self.files.view(),
                seccomp: (state.seccomp.mode, state.seccomp.filters()),
            },
        );
        self.published = Some(Published {
            tid,
            name: state.name,
            signals,
            memory,
            files,
            credentials: state.credentials.clone(),
        });
    }

    /// Delivers an unblocked pending signal at a CPU/Kernel boundary.
    pub fn checkpoint(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        // Only the checkpoint right after the syscall may restart it.
        let restart = thread.state.restart.take();
        let seccomp_restart = thread.state.seccomp_restart.take();
        if self.group.retired(thread.tid) {
            return Next::Exit(ExitStatus::Exited(0));
        }
        self.group.register(thread.tid, Arc::clone(&self.inbox));
        if let Some(status) = self.group.status() {
            return Next::Exit(status);
        }
        self.publish(thread.tid, &thread.state, mem);
        // A write found no memory under the session's limit: the process
        // ends by SIGKILL, as the cgroup OOM killer ends one, before it can
        // see the failed write as a fault or EFAULT.
        if mem.take_out_of_memory() {
            return self.terminate(thread, signal::SIGKILL);
        }
        self.sync_actions(thread);
        self.group.drain_process(&mut thread.state);
        self.inbox.drain(&mut thread.state);
        if thread.state.pending.iter().any(|s| s.number == 18) {
            self.group.job_continue();
        }
        // The CPU-time interval timers count what this thread has run since
        // its last system call too, as Linux's tick does.
        if self.group.cpu_timers_armed() {
            account_cpu(&*self.host, &self.group, &mut thread.state, thread.tid);
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
            // The init of a nested PID namespace takes no signal it has no
            // handler for, but SIGKILL and SIGSTOP, which come only forced
            // (Linux's SIGNAL_UNKILLABLE in `get_signal`).
            if action.handler == 0 && !matches!(signal.number, 9 | 19) && self.group.unkillable() {
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
            // With SA_RESTART the frame resumes at the syscall instruction,
            // so the call runs again when the handler returns.
            if action.flags & signals::SA_RESTART != 0 || seccomp_restart == Some(true) {
                Self::rewind_restart(
                    thread,
                    restart.filter(|&number| {
                        seccomp_restart.is_some() || signals::restarts_with_handler(number)
                    }),
                );
            }
            let delivery_mask = thread.state.signal_mask;
            let restore_mask = thread.state.wait_restore_mask.take();
            if let Some(mask) = restore_mask {
                // The signal is selected using pwait's temporary mask, but
                // its ucontext must restore the original mask on sigreturn.
                thread.state.signal_mask = mask;
            }
            // Linux's rseq_signal_deliver: an area it cannot bring up to
            // date sends SIGSEGV, fatal when that is the signal delivered.
            let forced = !Self::rseq_signal(thread, mem);
            if forced && signal.number == signal::SIGSEGV {
                return self.terminate(thread, signal::SIGSEGV);
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
            if forced {
                // Delivered before the handler runs, as Linux's loop on the
                // way back to user space does.
                signals::queue(&mut thread.state, rseq::forced_sigsegv());
                continue;
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

    /// Runs a syscall interrupted with EINTR again, as Linux restarts
    /// ERESTARTSYS and ERESTARTNOHAND after a stop (which runs no handler)
    /// and ERESTARTSYS after a SA_RESTART handler: the syscall instruction
    /// is re-executed, from the handler's frame in the second case.
    fn rewind_restart(thread: &mut Thread, restart: Option<u64>) {
        if let Some(number) = restart
            && thread.cpu.gpr[reg::RAX] == paludarium_types::Errno(4).to_syscall_return()
            && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
        {
            thread.cpu.rip = paludarium_types::GuestAddr(rip);
            // The call itself runs again with the whole register, as Linux
            // puts back orig_ax; restart_syscall is put in afresh.
            let rax = thread.state.syscall_rax;
            thread.cpu.gpr[reg::RAX] = if number == u64::from(rax as u32) {
                rax
            } else {
                number
            };
        }
    }

    /// Handles a stop of `thread` (W3, W4).
    pub fn handle(&mut self, thread: &mut Thread, mem: &AddressSpace, reason: ExitReason) -> Next {
        // The thread runs no guest code until it takes a CPU again.
        self.leave_cpu();
        // A caller that did not finish the last exec finishes it now.
        self.exec_finished();
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
                    sender_uid: None,
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
                    sender_uid: None,
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
                    sender_uid: None,
                    queued: None,
                    born: signals::generation(),
                })
            }
            // Past the end of a mapped file: BUS_ADRERR, with the page
            // fault's trap and error code, as Linux's do_sigbus sends it.
            ExitReason::BusError {
                rip,
                addr,
                write,
                fetch,
                present,
            } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGBUS,
                    code: 2,
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
                    sender_uid: None,
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
                    sender_uid: None,
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
                    sender_uid: None,
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
            ExitReason::Syscall { .. } => {
                self.inbox.set_in_call(true);
                let next = self.syscall(thread, mem);
                self.inbox.set_in_call(false);
                next
            }
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
        self.group.take_landlock(&mut thread.state.credentials);
        // Before the call queues a signal itself (a fault, SIGPIPE, tgkill
        // to itself), so that it does not merge into a discarded one.
        self.group.apply_discards(&mut thread.state);
        self.group.sync_timer(&mut thread.state);
        account_cpu(&*self.host, &self.group, &mut thread.state, thread.tid);
        // The number is an int, as Linux's do_syscall_64 takes it, compared
        // unsigned: a dirty upper half of rax is not read, and a negative
        // number is past every table (ENOSYS).
        let mut number = u64::from(thread.cpu.gpr[reg::RAX] as u32);
        let mut args = [
            thread.cpu.gpr[reg::RDI],
            thread.cpu.gpr[reg::RSI],
            thread.cpu.gpr[reg::RDX],
            thread.cpu.gpr[reg::R10],
            thread.cpu.gpr[reg::R8],
            thread.cpu.gpr[reg::R9],
        ];
        self.group.take_seccomp(thread.tid, &mut thread.state);
        if thread.state.seccomp.mode != 0 {
            match seccomp::check(&thread.state.seccomp, number as u32, args, thread.cpu.rip.0) {
                seccomp::Verdict::Allow => {}
                seccomp::Verdict::Notify(notify) => {
                    if let Some(next) = self.notify(thread, mem, number, &notify) {
                        return next;
                    }
                }
                verdict => return self.refuse(thread, mem, verdict),
            }
        }
        arguments::narrow(number, &mut args);
        thread.state.syscall_rax = thread.cpu.gpr[reg::RAX];
        thread.state.restart = signals::restarts_without_handler(number, &args).then_some(number);
        // clone reads only the low 32 bits of its flags, as Linux's sys_clone
        // does (lower_32_bits); clone3's wider flags reach the code below.
        if number == 56 {
            args[0] &= 0xffff_ffff;
        }
        // clone3 runs as the clone it describes.
        self.set_tid.clear();
        if number == 435 {
            match processes::clone3_args(mem, args[0], args[1]) {
                Ok((legacy, set_tid)) => {
                    (number, args) = (56, legacy);
                    self.set_tid = set_tid;
                }
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
        memfd::enter(self.group.memlock());
        signalfd::observe(&thread.state, &self.inbox, &self.group);
        let mut ctx = syscalls::Context {
            number,
            tid: thread.tid,
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
        aio::progress(&ctx);
        let outcome = handler(&mut ctx, args);
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
mod aio_tests;

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
