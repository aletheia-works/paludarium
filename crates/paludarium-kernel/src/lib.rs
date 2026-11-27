//! Linux system-call layer for paludarium.
//!
//! The kernel owns the process and thread state. It receives the
//! CPU's [`ExitReason`] and decides what happens next: system calls are
//! dispatched by number through an explicit table and unknown numbers return
//! `-ENOSYS`; nothing is ever passed through to the host by number. Guest
//! exceptions end the process with the matching signal; the core emulator
//! records signal registrations but never delivers signals.
#![forbid(unsafe_code)]
// Proving that `Kernel` is `Send` walks every type it holds, its child
// `Kernel`s' among them, and io_uring's registered buffers (their pinned
// pages) take it past the default depth of 128.
#![recursion_limit = "256"]

mod admin;
mod arguments;
mod coredump;
mod cpuinfo;
mod credentials;
mod inbox;
mod inotify;
mod landlock;
mod permissions;
mod signalfd;
#[cfg(test)]
mod signalfd_tests;
mod signals;
mod skb;
pub use inbox::SignalInbox;
mod aio;
mod blocked;
mod bpf;
mod bpf_classic;
mod bpf_fs;
mod bpf_interp;
mod bpf_prog;
#[cfg(test)]
mod bpf_prog_tests;
mod bpf_test_run;
#[cfg(test)]
mod bpf_tests;
mod bpf_trie;
mod bpf_verifier;
mod deadlines;
mod devices;
mod dnotify;
mod epoll;
mod events;
#[cfg(test)]
mod extack_tests;
mod fanotify;
mod fasync;
mod fifo;
mod files;
mod filesystems;
mod hugetlb;
mod inet;
mod interface;
mod io_accounting;
mod io_uring;
mod ipc;
mod kcmp;
mod keys;
mod kstrto;
mod leases;
mod loopback;
mod lsm;
mod mctp;
#[cfg(test)]
mod mctp_tests;
mod netconf;
mod netdev;
mod netlink;
pub use inet::{InvalidRule, NetworkPolicy};
mod anycast;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod cpu_clock_tests;
mod futex;
mod memfd;
mod mempolicy;
#[cfg(test)]
mod mempolicy_tests;
mod mounts;
mod mqueue;
#[cfg(test)]
mod mqueue_tests;
mod msg;
mod multicast;
mod multipath;
mod namespaces;
mod page_cache;
mod pagemap_scan;
mod perf;
mod proc;
mod proc_net;
mod process_vm;
mod processes;
mod program_name;
mod ptrace;
mod pty;
#[cfg(test)]
mod pty_tests;
mod record_locks;
mod rseq;
mod scheduling;
mod seccomp;
#[cfg(test)]
mod seccomp_tests;
mod sem;
mod seq;
mod shm;
#[cfg(test)]
mod sock_diag_tests;
mod sockets;
mod syscalls;
mod sysctl;
mod syslog;
mod targets;
#[cfg(test)]
mod tasks_tests;
mod tcp_info;
mod tcp_metrics;
mod threads;
mod timerfd;
mod timers;
mod unix;
mod userfaultfd;
mod users;
mod vsyscall;
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
    /// The hardware breakpoints a tracer enabled for the thread, which the
    /// CPU matches while it runs ([`paludarium_cpu::breakpoints::run_watched`]).
    #[must_use]
    pub fn breakpoints(&self) -> Option<paludarium_cpu::breakpoints::Breakpoints> {
        self.state.ptrace.debug.active().copied()
    }
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
/// cannot measure it, wall time) since the guest thread's start, published
/// for the thread group's total, with what else it has used ([`Usage`]). A
/// clone starts again from zero, as a new Linux thread or process does.
#[derive(Debug, Default)]
pub(crate) struct CpuAccount {
    base: Option<u64>,
    used: Arc<Usage>,
    /// Whether the thread group lists [`Self::used`] yet
    /// ([`ThreadGroup::register_cpu`]): from the thread's start
    /// ([`Kernel::start_thread`]), or else its first account.
    registered: bool,
    /// The CPU the thread was last seen on, for its migrations, with the
    /// thread group's [`ThreadGroup::affinity_generation`] when it was the
    /// lowest its mask allows; `None` for a virtual CPU of `rseq`, which is
    /// not looked up again.
    on: Option<(u32, Option<u64>)>,
    /// Whether the thread has slept or moved to another CPU since perf last
    /// looked ([`Kernel::scheduled_in`]).
    resumed: bool,
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

/// What a guest thread has used: its CPU time in nanoseconds, as of its
/// latest system call or of the latest look at its clock
/// ([`Usage::sample`]), the times it
/// went to sleep ([`paludarium_host::switches`]) and the times it moved to
/// another CPU, as of its latest system call, and the page faults its
/// accesses take ([`paludarium_mmu::faults`]), in its own code and in the
/// kernel's work for it (`kernel_faults`), as they are taken. The software
/// events of `perf` count these. The faults of its reads and writes
/// through `get_user_pages` are kept apart (`forced_faults`), as they count
/// to its `min_flt` but are no `perf` event, and so are its major faults
/// (`major_faults`, Linux's `maj_flt`): those of the kernel's accesses that
/// a `userfaultfd` had try again. So are the faults of its own code that
/// ended with no page (`unfinished_faults`): a `userfaultfd`'s wait that a
/// signal ended, which `page-faults` counts as the fault starts, and no
/// `min_flt` or `minor-faults` as it never ends; and those of the kernel's
/// accesses that failed (`unfinished_kernel_faults`), as with `EFAULT`.
#[derive(Debug, Default)]
pub(crate) struct Usage {
    /// Grows only, under [`Self::time`]'s lock.
    cpu: std::sync::atomic::AtomicU64,
    /// Its clock, from its start ([`Kernel::start_thread`]) to its end
    /// ([`Self::retire`]).
    clock: std::sync::Mutex<Option<CpuClock>>,
    /// Where its CPU time went.
    time: std::sync::Mutex<TimeOnCpus>,
    pub(crate) faults: std::sync::atomic::AtomicU64,
    pub(crate) kernel_faults: std::sync::atomic::AtomicU64,
    pub(crate) forced_faults: std::sync::atomic::AtomicU64,
    pub(crate) major_faults: std::sync::atomic::AtomicU64,
    pub(crate) unfinished_faults: std::sync::atomic::AtomicU64,
    pub(crate) unfinished_kernel_faults: std::sync::atomic::AtomicU64,
    pub(crate) switches: std::sync::atomic::AtomicU64,
    pub(crate) migrations: std::sync::atomic::AtomicU64,
    /// The CPU it was last seen on (Linux's `task_cpu`), which
    /// `/proc/<pid>/stat` gives as `processor`.
    pub(crate) last_cpu: std::sync::atomic::AtomicU32,
    /// Its faults, switches and migrations on each CPU, for the `perf`
    /// events of one CPU ([`CpuCounts`]).
    pub(crate) per_cpu_counts: std::sync::Mutex<CpuCounts>,
    /// The latest faults of its own code and of the kernel's accesses for
    /// it, by their numbers in the counts and their addresses, once some
    /// `perf` event asks for them.
    fault_addresses: std::sync::Mutex<[std::collections::VecDeque<FaultAt>; 2]>,
    /// It runs on a virtual CPU of `rseq`, which no CPU mask moves.
    pub(crate) virtual_cpu: std::sync::atomic::AtomicBool,
}

/// The clock of a running thread's CPU time, which other threads read too.
struct CpuClock {
    clock: Arc<dyn paludarium_host::ThreadCpuClock>,
    /// What it showed as the thread started.
    base: u64,
    /// The host thread whose time it is.
    owner: std::thread::ThreadId,
}
impl core::fmt::Debug for CpuClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuClock")
            .field("base", &self.base)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}
/// The wall time, where the host cannot measure CPU time, of a thread that
/// is not asleep in a wait: what it slept counts at its own next account,
/// and other threads see none of it meanwhile, as a sleeping thread uses no
/// CPU.
struct WallClock {
    host: Arc<dyn Host>,
    asleep: Arc<std::sync::atomic::AtomicBool>,
}
impl paludarium_host::ThreadCpuClock for WallClock {
    fn read(&self) -> Option<u64> {
        if self.asleep.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        self.host.clock(paludarium_host::ClockId::Monotonic).ok()
    }
}
/// What the host shows of the calling thread's CPU time: the wall time
/// where it cannot measure it.
fn host_cpu_time(host: &dyn Host) -> u64 {
    host.thread_cpu_time()
        .or_else(|_| host.clock(paludarium_host::ClockId::Monotonic))
        .unwrap_or(0)
}

/// The fewest instructions a run is given while a sampling clock counts
/// its thread ([`Kernel::run_budget`]).
pub const PACE_FLOOR: u64 = 5_000;

/// How far a thread runs while a sampling clock counts it
/// ([`Kernel::run_budget`]).
#[derive(Debug, Default)]
struct Pace {
    /// The nanoseconds of the thread's CPU time until the first sampling
    /// clock that counts it fires, as of its last checkpoint: `None` with
    /// none.
    due: Option<u64>,
    /// The instructions its current run was given, and its CPU time then.
    run: Option<(u64, u64)>,
    /// The instructions and the nanoseconds of its last whole run.
    rate: Option<(u64, u64)>,
}

impl Pace {
    /// The run ran all it was given: the rate it ran at.
    fn ran(&mut self, host: &dyn Host) {
        if let Some((instructions, from)) = self.run.take() {
            let ns = host_cpu_time(host).saturating_sub(from);
            // A clock that has not moved tells nothing.
            if ns != 0 {
                self.rate = Some((instructions, ns));
            }
        }
    }
}

/// A thread's CPU time on each CPU.
#[derive(Debug, Default)]
struct TimeOnCpus {
    /// In nanoseconds, by the CPU's number: what it ran between two looks
    /// at its time counts to the CPU it was on at the first, for
    /// `/proc/stat`'s `cpuN` lines.
    ran: Vec<u64>,
    /// The CPU it is on.
    on: Option<u32>,
    /// What it ran before it was first seen on one, which is that one's.
    before: u64,
}
impl TimeOnCpus {
    fn add(&mut self, ran: u64) {
        let Some(cpu) = self.on else {
            self.before = self.before.saturating_add(ran);
            return;
        };
        let cpu = cpu as usize;
        if self.ran.len() <= cpu {
            self.ran.resize(cpu + 1, 0);
        }
        self.ran[cpu] = self.ran[cpu].saturating_add(ran);
    }
    fn arrive(&mut self, cpu: u32) {
        self.on = Some(cpu);
        let before = std::mem::take(&mut self.before);
        if before != 0 {
            self.add(before);
        }
    }
}

/// The minor and major faults of a thread, a process or the children it
/// reaped (Linux's `min_flt` and `maj_flt`, `cmin_flt` and `cmaj_flt`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Faults {
    pub minor: u64,
    pub major: u64,
}

impl Faults {
    pub(crate) fn plus(self, other: Self) -> Self {
        Self {
            minor: self.minor.saturating_add(other.minor),
            major: self.major.saturating_add(other.major),
        }
    }
}

/// What a [`Usage`] counts on each CPU, in [`CpuCounts`]'s order.
pub(crate) type Counts = [u64; 7];

/// One of a thread's latest faults: the minor, major and unfinished faults
/// it had counted in its own code or in the kernel's work with this one,
/// which of them this one is ([`FaultKind::All`] for an unfinished one,
/// which `page-faults` alone counts), and where it was.
#[derive(Clone, Copy, Debug)]
struct FaultAt {
    minor: u64,
    major: u64,
    unfinished: u64,
    kind: FaultKind,
    at: paludarium_mmu::faults::At,
}

/// Which of a thread's faults a `perf` event counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultKind {
    /// `page-faults`: every one.
    All,
    Minor,
    Major,
}

/// What a thread's [`Usage`] counted on each CPU: its minor faults in its
/// own code and the kernel's, its switches, its migrations, its major
/// faults, its unfinished ones and the kernel's unfinished ones, in that
/// order.
/// Those of the CPU it is on are what it counted since it came there; a
/// migration counts to the CPU it comes to, as Linux's
/// `perf_sw_event_sched` of `PERF_COUNT_SW_CPU_MIGRATIONS` runs there.
#[derive(Debug, Default)]
pub(crate) struct CpuCounts {
    /// What it counted on each CPU it has left, by the CPU's number.
    done: Vec<Counts>,
    /// The CPU it is on, and its counts when it came there.
    on: Option<(u32, Counts)>,
}

impl Usage {
    fn time(&self) -> std::sync::MutexGuard<'_, TimeOnCpus> {
        self.time
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Its CPU time in nanoseconds, as of the latest look at it.
    pub(crate) fn cpu_time(&self) -> u64 {
        self.cpu.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Its CPU time is `used` now, which counts to the CPU it is on from
    /// the latest look at it. The thread and those that look at its clock
    /// all tell it so, in any order: it is the most that one of them saw.
    /// Returns it.
    fn ran(&self, used: u64) -> u64 {
        use std::sync::atomic::Ordering::SeqCst;
        let mut time = self.time();
        let before = self.cpu.load(SeqCst);
        if used <= before {
            return before;
        }
        self.cpu.store(used, SeqCst);
        time.add(used - before);
        used
    }
    /// Brings its CPU time up to now from its clock, as Linux's
    /// `task_sched_runtime` does for a task that runs, and tells whether it
    /// could: not once it has ended, nor where the host has no such clock.
    /// Its own thread has no need to, as each system call accounts it
    /// ([`account_cpu`]).
    pub(crate) fn sample(&self) -> bool {
        // The lock is held as the clock is read, so that the thread does
        // not end meanwhile ([`Self::retire`]).
        let clock = self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(clock) = clock.as_ref() else {
            return false;
        };
        if clock.owner == std::thread::current().id() {
            return false;
        }
        let Some(now) = clock.clock.read() else {
            return false;
        };
        self.ran(now.saturating_sub(clock.base));
        true
    }
    /// The calling thread, whose it is, ends: its CPU time is what it is
    /// now, and its clock, which a host could give to another thread after
    /// this one, is let go of.
    fn retire(&self) {
        let clock = self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(clock) = clock
            && let Some(now) = clock.clock.read()
        {
            self.ran(now.saturating_sub(clock.base));
        }
    }
    /// Its faults, switches and migrations, as [`CpuCounts`] orders them.
    pub(crate) fn counts(&self) -> Counts {
        use std::sync::atomic::Ordering::SeqCst;
        [
            self.faults.load(SeqCst),
            self.kernel_faults.load(SeqCst),
            self.switches.load(SeqCst),
            self.migrations.load(SeqCst),
            self.major_faults.load(SeqCst),
            self.unfinished_faults.load(SeqCst),
            self.unfinished_kernel_faults.load(SeqCst),
        ]
    }
    /// The thread is on `cpu` now: what it counted since it came to the
    /// CPU it was on counts to that one.
    fn arrive(&self, cpu: u32) {
        let now = self.counts();
        let mut counts = self
            .per_cpu_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match counts.on {
            Some((was, _)) if was == cpu => {}
            Some((was, since)) => {
                let was = was as usize;
                if counts.done.len() <= was {
                    counts.done.resize(was + 1, [0; 7]);
                }
                for (done, (now, since)) in counts.done[was].iter_mut().zip(now.iter().zip(since)) {
                    *done = done.saturating_add(now.saturating_sub(since));
                }
                counts.on = Some((cpu, now));
            }
            // What it counted before it was first seen is the first CPU's.
            None => counts.on = Some((cpu, [0; 7])),
        }
    }
    /// Another thread's `sched_setaffinity` left it the mask whose lowest
    /// CPU is `cpu`: Linux moves a running thread there before the call
    /// returns (`__set_cpus_allowed_ptr`), so what it counts from now is
    /// that CPU's, and its next account counts the migration there. One on
    /// a virtual CPU of `rseq` stays where it is.
    /// Where its clock can be read, the CPU time it runs from now is that
    /// CPU's too.
    pub(crate) fn moved_to(&self, cpu: u32) {
        if !self.virtual_cpu.load(std::sync::atomic::Ordering::SeqCst) {
            if self.sample() {
                self.time().arrive(cpu);
            }
            self.arrive(cpu);
        }
    }
    /// `n` switches, just counted, that it made on `cpu`: they count there
    /// even if it has been moved from it since.
    fn switched_on(&self, cpu: u32, n: u64) {
        let mut counts = self
            .per_cpu_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((on, since)) = counts.on.as_mut() else {
            return;
        };
        if *on == cpu {
            return;
        }
        since[2] = since[2].saturating_add(n);
        let cpu = cpu as usize;
        if counts.done.len() <= cpu {
            counts.done.resize(cpu + 1, [0; 7]);
        }
        counts.done[cpu][2] = counts.done[cpu][2].saturating_add(n);
    }
    /// What it counted on `cpu`, as [`CpuCounts`] orders it.
    pub(crate) fn counts_on(&self, cpu: u32) -> Counts {
        let now = self.counts();
        let counts = self
            .per_cpu_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut on = counts.done.get(cpu as usize).copied().unwrap_or_default();
        if let Some((current, since)) = counts.on
            && current == cpu
        {
            for (on, (now, since)) in on.iter_mut().zip(now.iter().zip(since)) {
                *on = on.saturating_add(now.saturating_sub(since));
            }
        }
        on
    }
    /// Adds what it counted on each CPU to `sums`.
    pub(crate) fn add_counts(&self, sums: &mut Vec<Counts>) {
        let cpus: Vec<u32> = {
            let counts = self
                .per_cpu_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let on = counts.on.map(|(cpu, _)| cpu);
            let left = u32::try_from(counts.done.len()).unwrap_or(u32::MAX);
            let more = on.filter(|&cpu| cpu >= left);
            (0..left).chain(more).collect()
        };
        for cpu in cpus {
            let counts = self.counts_on(cpu);
            let cpu = cpu as usize;
            if sums.len() <= cpu {
                sums.resize(cpu + 1, [0; 7]);
            }
            for (sum, count) in sums[cpu].iter_mut().zip(counts) {
                *sum = sum.saturating_add(count);
            }
        }
    }
    /// Its CPU time in nanoseconds and what of it was on `cpu`, as of the
    /// latest look at it.
    pub(crate) fn time_on(&self, cpu: u32) -> (u64, u64) {
        let time = self.time();
        let on = time.ran.get(cpu as usize).copied().unwrap_or(0);
        (self.cpu_time(), on)
    }
    /// The addresses of the latest `n` of its first `counted` faults of
    /// `kind` of its own code or of the `kernel`'s accesses for it, 0 for
    /// one that is not known.
    pub(crate) fn fault_addresses(
        &self,
        kernel: bool,
        kind: FaultKind,
        counted: u64,
        n: u64,
    ) -> Vec<paludarium_mmu::faults::At> {
        let addresses = self
            .fault_addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let latest = &addresses[usize::from(kernel)];
        // Its number among those of `kind`, and whether it is one: each
        // count grows with the faults, so they are in its order.
        let nth = |fault: &FaultAt| match kind {
            FaultKind::All => (fault.minor + fault.major + fault.unfinished, true),
            FaultKind::Minor => (fault.minor, fault.kind == FaultKind::Minor),
            FaultKind::Major => (fault.major, fault.kind == FaultKind::Major),
        };
        // Those before are gone.
        let known = n.min(FAULT_ADDRESSES as u64);
        let mut out =
            vec![paludarium_mmu::faults::At::default(); usize::try_from(n - known).unwrap_or(0)];
        out.extend((0..known).map(|i| {
            let wanted = counted.saturating_sub(known - 1 - i);
            // The first that has counted it is it, if it is of `kind`.
            let at = latest.partition_point(|fault| nth(fault).0 < wanted);
            latest
                .get(at)
                .filter(|fault| nth(fault) == (wanted, true))
                .map_or_else(paludarium_mmu::faults::At::default, |fault| fault.at)
        }));
        out
    }
    /// Adds its CPU time on each CPU to `sums`.
    pub(crate) fn add_times(&self, sums: &mut Vec<u64>) {
        let time = self.time();
        if sums.len() < time.ran.len() {
            sums.resize(time.ran.len(), 0);
        }
        for (sum, &ran) in sums.iter_mut().zip(&time.ran) {
            *sum = sum.saturating_add(ran);
        }
    }
    /// Its minor faults (Linux's `min_flt`): every fault it took but the
    /// major ones, its own code's, the kernel's for it and those through
    /// `get_user_pages`.
    pub(crate) fn minor_faults(&self) -> u64 {
        use std::sync::atomic::Ordering::SeqCst;
        self.faults
            .load(SeqCst)
            .saturating_add(self.kernel_faults.load(SeqCst))
            .saturating_add(self.forced_faults.load(SeqCst))
    }
    /// A fault of its own code `at` ended with no page: one more of the
    /// faults `page-faults` alone counts.
    pub(crate) fn unfinished_fault(&self, at: paludarium_mmu::faults::At) {
        self.unfinished_fault_of(false, at);
    }
    /// [`Self::unfinished_fault`] of its own code or of the `kernel`'s
    /// accesses for it.
    fn unfinished_fault_of(&self, kernel: bool, at: paludarium_mmu::faults::At) {
        use std::sync::atomic::Ordering::SeqCst;
        let mut addresses = self
            .fault_addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = if kernel {
            &self.unfinished_kernel_faults
        } else {
            &self.unfinished_faults
        };
        let nth = count.fetch_add(1, SeqCst).wrapping_add(1);
        if !paludarium_mmu::faults::addresses_traced() {
            return;
        }
        let latest = &mut addresses[usize::from(kernel)];
        if latest.len() == FAULT_ADDRESSES {
            latest.pop_front();
        }
        let (minor, major) = if kernel {
            (
                self.kernel_faults.load(SeqCst),
                self.major_faults.load(SeqCst),
            )
        } else {
            (self.faults.load(SeqCst), 0)
        };
        latest.push_back(FaultAt {
            minor,
            major,
            unfinished: nth,
            kind: FaultKind::All,
            at,
        });
    }
    /// Its minor and major faults (Linux's `min_flt` and `maj_flt`).
    pub(crate) fn fault_counts(&self) -> Faults {
        Faults {
            minor: self.minor_faults(),
            major: self.major_faults.load(std::sync::atomic::Ordering::SeqCst),
        }
    }
}

impl paludarium_mmu::faults::Sink for Usage {
    fn user(&self) -> &std::sync::atomic::AtomicU64 {
        &self.faults
    }
    fn kernel(&self) -> &std::sync::atomic::AtomicU64 {
        &self.kernel_faults
    }
    fn forced(&self) -> &std::sync::atomic::AtomicU64 {
        &self.forced_faults
    }
    fn major(&self) -> &std::sync::atomic::AtomicU64 {
        &self.major_faults
    }
    fn unfinished(&self, at: paludarium_mmu::faults::At) {
        self.unfinished_fault_of(true, at);
    }
    fn fault(&self, kernel: bool, major: bool, nth: u64, at: paludarium_mmu::faults::At) {
        let mut addresses = self
            .fault_addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let latest = &mut addresses[usize::from(kernel)];
        // The count of the other kind as this one is taken. The kernel's
        // accesses alone take major faults.
        let load =
            |count: &std::sync::atomic::AtomicU64| count.load(std::sync::atomic::Ordering::SeqCst);
        let other = match (major, kernel) {
            (true, true) => load(&self.kernel_faults),
            (true, false) => load(&self.faults),
            (false, true) => load(&self.major_faults),
            (false, false) => 0,
        };
        let unfinished = if kernel {
            load(&self.unfinished_kernel_faults)
        } else {
            load(&self.unfinished_faults)
        };
        if latest.len() == FAULT_ADDRESSES {
            latest.pop_front();
        }
        let (minor, major_count) = if major { (other, nth) } else { (nth, other) };
        latest.push_back(FaultAt {
            minor,
            major: major_count,
            unfinished,
            kind: if major {
                FaultKind::Major
            } else {
                FaultKind::Minor
            },
            at,
        });
    }
}
/// How many of a thread's latest faults keep their addresses, for the
/// samples its next system call takes of them.
const FAULT_ADDRESSES: usize = 4096;

/// While it lives, the calling host thread's kernel accesses that fault are
/// resolved by a [`userfaultfd::KernelCopies`], with the call's signal mask
/// and `CAP_IPC_LOCK`; then by what was there.
struct KernelCopies {
    resolver: Option<Arc<dyn paludarium_mmu::faults::Resolver>>,
    call: (u64, bool),
}
impl KernelCopies {
    fn install(copies: Arc<userfaultfd::KernelCopies>, mask: u64, ipc_lock: bool) -> Self {
        Self {
            call: userfaultfd::enter_call(mask, ipc_lock),
            resolver: paludarium_mmu::faults::set_resolver(Some(copies)),
        }
    }
}
impl Drop for KernelCopies {
    fn drop(&mut self) {
        paludarium_mmu::faults::set_resolver(self.resolver.take());
        userfaultfd::leave_call(self.call);
    }
}

/// While it lives, the calling host thread's faults count to the guest
/// thread's [`Usage`] as the kernel's for it (Linux tells a fault of user
/// mode from one of the kernel's accesses to user memory); after it, as the
/// thread's own code's.
/// It puts back what it found, so one inside another leaves the outer one
/// the kernel's.
pub(crate) struct KernelFaults {
    was: bool,
}

impl KernelFaults {
    pub(crate) fn enter(state: &ThreadState) -> Self {
        paludarium_mmu::faults::bind(Arc::clone(&state.cpu.used) as _);
        KernelFaults {
            was: paludarium_mmu::faults::set_kernel(true),
        }
    }
}

impl Drop for KernelFaults {
    fn drop(&mut self) {
        paludarium_mmu::faults::set_kernel(self.was);
    }
}

/// Lists the thread's [`Usage`] in its thread group, once.
fn register_usage(group: &ThreadGroup, tid: u32, account: &mut CpuAccount) {
    if !account.registered {
        account.registered = true;
        group.register_cpu(tid, Arc::clone(&account.used));
    }
}

impl Kernel {
    /// The calling host thread runs `thread` from now on: its faults count
    /// to it from the first one, as Linux's `mm_account_fault` counts each
    /// to `current`, and they show in `/proc` and `getrusage` before its
    /// first system call. Its CPU time starts, and other threads may look at
    /// it while what this returns lives, at most as long as the host thread
    /// ([`Self::finish_thread`] ends it earlier).
    #[must_use]
    pub fn start_thread(&self, thread: &mut Thread) -> ThreadClock {
        let account = &mut thread.state.cpu;
        register_usage(&self.group, thread.tid, account);
        let used = Arc::clone(&account.used);
        paludarium_mmu::faults::bind(Arc::clone(&used) as _);
        let base = start_account(&*self.host, &self.group, account, thread.tid, || {
            host_cpu_time(&*self.host)
        });
        let clock = match self.host.thread_cpu_clock() {
            // The host measures it only for the calling thread.
            None if self.host.thread_cpu_time().is_ok() => None,
            None => Some(Arc::new(WallClock {
                host: Arc::clone(&self.host),
                asleep: Arc::clone(self.inbox.blocked_flag()),
            }) as _),
            clock => clock,
        };
        *used
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = clock.map(|clock| CpuClock {
            clock,
            base,
            owner: std::thread::current().id(),
        });
        ThreadClock(used)
    }
}

/// While it lives, other threads may look at the CPU time of the guest
/// thread the host thread that made it runs ([`Kernel::start_thread`]).
#[derive(Debug)]
pub struct ThreadClock(Arc<Usage>);
impl Drop for ThreadClock {
    fn drop(&mut self) {
        self.0.retire();
    }
}

/// The host's reading the thread's CPU time counts from: `now`'s, the first
/// time.
fn start_account(
    host: &dyn Host,
    group: &ThreadGroup,
    account: &mut CpuAccount,
    tid: u32,
    now: impl FnOnce() -> u64,
) -> u64 {
    *account.base.get_or_insert_with(|| {
        // A thread no clone made, the first process's, was made about now.
        group.set_started(
            tid,
            host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0),
        );
        now()
    })
}

/// Brings the thread's CPU time and [`Usage`] up to date and returns its
/// CPU time in nanoseconds; called at every system call, which publishes
/// them for the process clock and `perf`, and by the system calls that read
/// the CPU clocks.
pub(crate) fn account_cpu(
    host: &dyn Host,
    group: &ThreadGroup,
    state: &mut ThreadState,
    tid: u32,
) -> u64 {
    use std::sync::atomic::Ordering;
    let now = host_cpu_time(host);
    let on_cpu = state.on_cpu.map(|on| on.cpu);
    let account = &mut state.cpu;
    register_usage(group, tid, account);
    let base = start_account(host, group, account, tid, || now);
    let usage = &account.used;
    let used = usage.ran(now.saturating_sub(base));
    let switches = paludarium_host::switches::take();
    if switches != 0 {
        account.resumed = true;
        usage.switches.fetch_add(switches, Ordering::SeqCst);
        // Its sleeps since its last account were on the CPU it was on
        // then, though another thread's `sched_setaffinity` moved its
        // counts since ([`Usage::moved_to`]).
        if let Some((was, _)) = account.on {
            usage.switched_on(was, switches);
        }
    }
    // The CPU it runs on: its virtual one with `rseq`, else the lowest its
    // mask allows (`getcpu`), looked up again only when a mask changed.
    let generation = group.affinity_generation();
    let seen = match (on_cpu, account.on) {
        (Some(cpu), _) => (cpu, None),
        (None, Some((cpu, Some(seen)))) if seen == generation => (cpu, Some(seen)),
        (None, _) => (group.lowest_cpu(tid), Some(generation)),
    };
    let was = account.on.replace(seen).map(|(was, _)| was);
    usage.last_cpu.store(seen.0, Ordering::SeqCst);
    usage.virtual_cpu.store(seen.1.is_none(), Ordering::SeqCst);
    // What it counted until now is the CPU's it was on, and a migration the
    // new one's.
    usage.arrive(seen.0);
    if was.is_some_and(|was| was != seen.0) {
        account.resumed = true;
        usage.migrations.fetch_add(1, Ordering::SeqCst);
    }
    usage.time().arrive(seen.0);
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
    /// How it takes the process's signals in.
    pub(crate) seat: targets::Seat,
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
    /// When something is next due in the session ([`deadlines`]).
    pub(crate) due: Option<u64>,
    pub stopped: bool,
    /// The thread's name (`comm`), NUL-padded: PR_SET_NAME and PR_GET_NAME.
    pub(crate) name: [u8; 16],
    pub(crate) cpu: CpuAccount,
    /// The syscall now returning, when Linux would run it again (rather than
    /// fail it with EINTR) if the signal that interrupted it runs no handler.
    pub(crate) restart: Option<u64>,
    /// The call a group stop rewound to run again, with its
    /// `seccomp_restart` and whether a tracer left it no restart after a
    /// handler (`ERESTARTNOHAND`), until the stop ends: a handler that runs
    /// as it ends makes the call fail with EINTR instead, unless the handler
    /// runs it again, as Linux decides the restart only once `get_signal`
    /// has gone on past the stop ([`Kernel::checkpoint`]).
    pub(crate) stop_rewound: Option<(u64, Option<bool>, bool)>,
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
    /// What the thread keeps of ptrace ([`ptrace::Local`]).
    pub(crate) ptrace: ptrace::Local,
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
    /// What resolves its calls' faulting copies ([`KernelCopies`]).
    copies: Option<Arc<userfaultfd::KernelCopies>>,
    /// Its thread's faults are refused, for an event to sample each at its
    /// instruction ([`paludarium_mmu::faults::arm`]).
    armed: bool,
    /// How far its thread runs while a sampling clock counts it.
    pace: Pace,
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
    personality: u32,
    /// Its mode and filters, by identity, so that a `seccomp` or `prctl`
    /// that changes them publishes them.
    seccomp: seccomp::Seccomp,
}

impl Kernel {
    /// Creates a kernel that performs host I/O through `host`.
    pub fn new(host: Arc<dyn Host>) -> Self {
        let files = files::Files::with_host(Arc::clone(&host));
        let group = Arc::new(ThreadGroup::default());
        group.watch(&files.readiness.deadlines);
        let processes = Arc::new(Processes::new(group.clone()));
        Kernel {
            host,
            process: Process { pid: 1 },
            table: SyscallTable::u1(),
            files,
            cancellation: Arc::new(AtomicBool::new(false)),
            inbox: Arc::new(SignalInbox::default()),
            group,
            copies: None,
            armed: false,
            pace: Pace::default(),
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
        let program = self.files.fs().metadata(&loaded, true).ok();
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
            &mut Vec::new(),
            (argv, &mut budget),
            &mut processes::ExecOpens::default(),
        )?;
        let script = loaded != resolved;
        Ok((loaded, script))
    }

    /// What the mappings of the first program's ELF interpreter, at `path`,
    /// keep while they last: a hold on its file, as Linux's hold theirs.
    pub fn interpreter_keep(&self, path: &[u8]) -> Option<paludarium_loader::Keep> {
        // Named as the program is, resolved and marked once removed.
        let name = crate::program_name::ProgramName::of(&self.files, path);
        Some(name.keep(self.files.interpreter_keep(path)))
    }
    /// What the segments of the first program, at `path`, keep while they
    /// last: their name, as `/proc/self/maps` and a core give it (see
    /// [`Self::set_executable`]).
    pub fn program_keep(&self, path: &[u8]) -> paludarium_loader::Keep {
        let path = self
            .files
            .exec_path(path.to_vec())
            .unwrap_or_else(|_| path.to_vec());
        crate::program_name::ProgramName::of(&self.files, &path).keep(None)
    }
    /// Records `path` as the program the first process runs, as
    /// `/proc/self/exe` names it: with its symbolic links resolved, and
    /// marked ` (deleted)` once nothing links its file.
    pub fn set_executable(&self, path: &[u8]) {
        let path = self
            .files
            .exec_path(path.to_vec())
            .unwrap_or_else(|_| path.to_vec());
        let name = crate::program_name::ProgramName::of(&self.files, &path);
        let path = crate::files::resolved(&self.files, &path).unwrap_or(path);
        // It runs, so its file may not be opened for writing (ETXTBSY). A
        // writer can only be the host's here, which is not counted, so the
        // program still runs, without the denial.
        if let Ok(denied) = crate::processes::deny_writes(&self.files, &path) {
            self.group.set_exe_file(denied.map(Arc::new));
        }
        self.group.set_executable(name);
    }

    /// Creates the initial thread for a loaded image: rip at the entry
    /// point, rsp at the initial stack, everything else zero, but for the
    /// signals the host started the emulator with ignored, which stay
    /// ignored as an `execve` keeps them (`flush_signal_handlers`).
    #[must_use]
    pub fn spawn_initial(&self, image: &LoadedImage) -> Thread {
        self.group
            .register(self.process.pid, Arc::clone(&self.inbox));
        self.group.set_program(image);
        let ignored = self.host.ignored_signals() & !signals::unblockable();
        let signal_actions: BTreeMap<i32, SignalAction> = (1..=64)
            .filter(|n| ignored & (1u64 << (n - 1)) != 0)
            .map(|n| {
                let action = SignalAction {
                    handler: signals::SIG_IGN,
                    ..SignalAction::default()
                };
                self.group.set_action(n, action);
                (n, action)
            })
            .collect();
        Thread {
            tid: self.process.pid,
            cpu: CpuState::new(image.entry_point, image.initial_stack_pointer),
            state: ThreadState {
                pid: self.process.pid,
                signal_actions,
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
            // Decided before (`ptrace_seccomp`); ENOSYS as with no tracer.
            seccomp::Verdict::Trace(_) => {
                thread.cpu.gpr[reg::RAX] = paludarium_types::Errno::ENOSYS.to_syscall_return();
                self.checkpoint(thread, mem)
            }
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
                    // `force_sig_seccomp` forces it as `HANDLER_EXIT`.
                    self.group.force_exit_action(signal::SIGSYS);
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
        let reply = self.listener_reply(thread, mem, number, notify);
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

    /// What the listener `notify` names answers for the call `number`.
    pub(crate) fn listener_reply(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        number: u64,
        notify: &seccomp::Notify,
    ) -> seccomp::Reply {
        memfd::enter(self.group.memlock());
        fanotify::enter(thread.state.pid, thread.tid);
        proc::enter(
            thread.state.pid,
            thread.tid,
            thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
        );
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
        reply
    }

    /// A fault of `thread`'s own code at `addr` that ends in a signal: of
    /// a user address or the `vsyscall` page, as Linux's
    /// `do_user_addr_fault` has them, `page-faults` counted it as it
    /// started, and `mm_account_fault` counts no error in `min_flt` or
    /// `minor-faults`. One of a kernel address (`do_kern_addr_fault`)
    /// counts nothing; so does a non-canonical one, a #GP on Linux.
    fn signalled_fault(thread: &Thread, addr: u64, present: bool) {
        if addr < vsyscall::TASK_SIZE_MAX || (vsyscall::START..vsyscall::END).contains(&addr) {
            thread
                .state
                .cpu
                .used
                .unfinished_fault(paludarium_mmu::faults::At { addr, present });
        }
    }

    /// The fault of `thread` on a page the `userfaultfd` numbered `context`
    /// waits for ([`userfaultfd::fault`]): it waits, or with
    /// `UFFD_FEATURE_SIGBUS` takes SIGBUS (`BUS_ADRERR`), as Linux's
    /// `do_sigbus` sends it for the address.
    fn userfault(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        context: u64,
        access: userfaultfd::Access,
    ) -> Next {
        memfd::enter(self.group.memlock());
        fanotify::enter(thread.state.pid, thread.tid);
        proc::enter(
            thread.state.pid,
            thread.tid,
            thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
        );
        signalfd::observe(&thread.state, &self.inbox, &self.group);
        let mut ctx = syscalls::Context {
            number: 0,
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
        let sigbus = userfaultfd::fault(&mut ctx, context, access) == Some(true);
        // Unless a signal is to be taken first, the fault is tried again
        // (`fault_signal_pending`), and counts.
        let retried = !sigbus && !events::signalled(&ctx);
        self.inbox.drain(&mut thread.state);
        if retried {
            mem.retry_own_fault(
                paludarium_types::GuestAddr(access.address),
                access.write,
                access.fetch,
            );
        } else {
            // Not tried again, it ends here: `page-faults` counted it as it
            // started (`do_user_addr_fault`), and `mm_account_fault` counts
            // no `VM_FAULT_RETRY` or `VM_FAULT_SIGBUS`. After a signal to be
            // taken the instruction faults again.
            thread
                .state
                .cpu
                .used
                .unfinished_fault(paludarium_mmu::faults::At {
                    addr: access.address,
                    present: access.reason == paludarium_mmu::UserfaultReason::Protected,
                });
        }
        if sigbus {
            signals::queue(
                &mut thread.state,
                signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGBUS,
                    code: 2,
                    addr: access.address,
                    trap: 14,
                    // A write-protected page is present.
                    error: 4
                        | u64::from(access.reason == paludarium_mmu::UserfaultReason::Protected)
                        | (u64::from(access.write) * 2)
                        | (u64::from(access.fetch) * 16),
                    synchronous: true,
                    timer: None,
                    child: None,
                    sender: None,
                    sender_uid: None,
                    queued: None,
                    born: signals::generation(),
                },
            );
        }
        self.checkpoint(thread, mem)
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
                && p.personality == state.personality
                && p.seccomp == state.seccomp
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
                personality: state.personality,
            },
        );
        self.published = Some(Published {
            tid,
            name: state.name,
            signals,
            memory,
            files,
            credentials: state.credentials.clone(),
            personality: state.personality,
            seccomp: state.seccomp.clone(),
        });
    }

    /// Has the calling host thread's kernel accesses that fault served for
    /// `thread` while what it returns lives. Its resolver is kept from call
    /// to call, while it serves the same thread.
    fn resolve_copies(&mut self, thread: &Thread) -> KernelCopies {
        let copies = match &self.copies {
            Some(copies)
                if copies.serves(
                    &self.group,
                    &self.files.readiness,
                    &self.inbox,
                    self.process.pid,
                    thread.tid,
                ) =>
            {
                Arc::clone(copies)
            }
            _ => {
                let copies = Arc::new(userfaultfd::KernelCopies {
                    group: Arc::clone(&self.group),
                    tid: thread.tid,
                    hub: Arc::clone(&self.files.readiness),
                    host: Arc::clone(&self.host),
                    inbox: Arc::clone(&self.inbox),
                    processes: Arc::clone(&self.processes),
                    pid: self.process.pid,
                });
                self.copies = Some(Arc::clone(&copies));
                copies
            }
        };
        KernelCopies::install(
            copies,
            thread.state.signal_mask,
            thread.state.credentials.capable(1 << 14),
        )
    }

    /// The instructions the thread is to run before its next checkpoint, at
    /// most `budget`. While a sampling `cpu-clock` or `task-clock` counts
    /// it, the run ends about when the first of them is to fire, at the
    /// rate the thread ran its last whole run at, so that each checkpoint
    /// has about one sample of each, with its own registers. It is not an
    /// interrupt: a run is at least [`PACE_FLOOR`] instructions.
    pub fn run_budget(&mut self, budget: u64) -> u64 {
        // A run not paced tells nothing of the rate.
        let Some(due) = self.pace.due else {
            self.pace.run = None;
            return budget;
        };
        let n = match self.pace.rate {
            Some((instructions, ns)) => {
                let n = u128::from(due) * u128::from(instructions) / u128::from(ns.max(1));
                u64::try_from(n).unwrap_or(u64::MAX)
            }
            None => PACE_FLOOR,
        };
        let n = n.max(PACE_FLOOR).min(budget);
        self.pace.run = Some((n, host_cpu_time(&*self.host)));
        n
    }

    /// The thread's run may have ended before it ran all that
    /// [`Kernel::run_budget`] gave it, though it ends with a used-up
    /// budget: with the trap flag, or a tracer's breakpoints, it runs one
    /// instruction at a time. It tells nothing of the rate.
    pub fn run_cut_short(&mut self) {
        self.pace.run = None;
    }

    /// Delivers an unblocked pending signal at a CPU/Kernel boundary.
    pub fn checkpoint(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        let next = self.checkpoint_once(thread, mem);
        // What a handler's mask blocks is told before the handler runs.
        self.group.settle_mask(&mut thread.state);
        if let Some(tif) = thread.state.seat.tif() {
            tif.set_halted(next == Next::Stopped);
            tif.set_held(
                !thread.state.pending.is_empty()
                    && signals::next_pending(&thread.state, false).is_some(),
            );
        }
        next
    }
    fn checkpoint_once(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        // Its writes to user memory, a signal frame's and the rseq area's,
        // are the kernel's work for the thread on its way back to user space
        // (`get_signal`, `rseq_handle_notify_resume`): their faults are the
        // kernel's, wherever it is called from.
        let _faults = KernelFaults::enter(&thread.state);
        // And they are served as a system call's copies are: the frame of a
        // signal grows a stack, and waits for a `userfaultfd`.
        let _copies = self.resolve_copies(thread);
        // As in `handle`: a wait here shows the thread asleep.
        let _attached = paludarium_host::blocked::attach(self.inbox.blocked_flag());
        // A traced thread's clone goes on once the new task has started.
        if thread.state.ptrace.hold {
            return Next::Resume;
        }
        // Only the checkpoint right after the syscall may restart it.
        let mut restart = ptrace::Restart {
            number: thread.state.restart.take(),
            seccomp: thread.state.seccomp_restart.take(),
            no_handler: false,
            traced: false,
        };
        let mut rewound = thread.state.stop_rewound.take();
        if self.group.retired(thread.tid) {
            return Next::Exit(ExitStatus::Exited(0));
        }
        self.group.register(thread.tid, Arc::clone(&self.inbox));
        thread
            .state
            .seat
            .take(self.inbox.tif(), thread.state.signal_mask);
        if let Some(status) = self.group.status() {
            return Next::Exit(status);
        }
        if let Some(name) = self.group.take_rename(thread.tid) {
            thread.state.name = name;
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
        // `get_signal` takes the process's too, for a thread with one of its
        // own.
        if !thread.state.pending.is_empty() && signals::next_pending(&thread.state, false).is_some()
        {
            self.group.take_process(&mut thread.state);
        }
        if thread.state.pending.iter().any(|s| s.number == 18) {
            self.group.job_continue();
        }
        // The CPU-time interval timers count what this thread has run since
        // its last system call too, as Linux's tick does, and so do the
        // sampling perf events, whose clocks overflow as it runs.
        let sampling = perf::sampling(&self.processes.perf_events);
        // So does a thread that slept, whose events' user pages show it.
        let slept = perf::buffers_mapped(&self.processes.perf_events)
            && paludarium_host::switches::pending();
        if self.group.cpu_timers_armed() || sampling || slept {
            account_cpu(&*self.host, &self.group, &mut thread.state, thread.tid);
            self.scheduled_in(thread);
        }
        if sampling {
            self.perf_samples(thread, mem);
        }
        // A sampling clock that counts it ends its runs by its next sample.
        if sampling || self.pace.due.is_some() {
            self.pace.due = sampling
                .then(|| {
                    perf::clock_due(
                        &self.processes.perf_events,
                        &self.group,
                        thread.tid,
                        thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
                    )
                })
                .flatten();
        }
        // A fault of its own code that an event samples stops the thread at
        // its instruction.
        if sampling || self.armed {
            self.armed = sampling
                && perf::samples_faults(
                    &self.processes.perf_events,
                    &self.group,
                    thread.tid,
                    thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
                );
            paludarium_mmu::faults::arm(self.armed);
        }
        if let Ok(now) = self.host.clock(paludarium_host::ClockId::Monotonic) {
            self.group.expire_timer(&mut thread.state, now);
        }
        // A timerfd that has expired may be what a waiting aio poll waits
        // for, in this process or another: it completes here as the program
        // runs without a call, as Linux's timer completes it from its
        // wake-up (`timerfd_tmrproc`).
        aio::complete_ready(&self.processes.aio, &self.files.readiness);
        // So do the io_uring requests that wait for a file this thread's
        // call made ready, as task work of the threads that submitted them.
        io_uring::complete_ready(&self.processes.io_uring, &*self.host);
        self.ptrace_traps(thread, &mut restart);
        // io_uring's task work runs on the way back to the program, after
        // the call's ptrace stops and before a signal is taken, as Linux's
        // `exit_to_user_mode_loop` runs it (`TIF_NOTIFY_SIGNAL`), but not
        // while the thread is stopped. A call it ended runs again if no
        // handler runs ([`Self::rewind_restart`] below).
        let notified = !thread.state.stopped && io_uring::task_work_due(&self.inbox);
        if notified {
            let mut ctx = syscalls::Context {
                number: u64::MAX,
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
            io_uring::run_task_work(&mut ctx);
        }
        let mut delivered = false;
        while let Some(index) = signals::next_pending(&thread.state, false) {
            let mut signal = thread.state.pending.remove(index);
            // A traced thread reports each signal but SIGKILL and one whose
            // action is `SA_IMMUTABLE` to its tracer first, which may cancel
            // or change it (`ptrace_signal`).
            if signal.number != signal::SIGKILL
                && thread
                    .state
                    .signal_actions
                    .get(&signal.number)
                    .is_none_or(|action| action.flags & signals::SA_IMMUTABLE == 0)
                && self.traced(thread.tid)
            {
                match self.ptrace_signal(thread, signal, &mut restart) {
                    Some(given) => signal = given,
                    None => continue,
                }
            }
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
                // A traced thread stops for its tracer instead, which may let
                // it run on.
                if self.traced(thread.tid) {
                    self.ptrace_group_stop(thread, &mut restart);
                    if !thread.state.stopped {
                        continue;
                    }
                }
                // A temporary wait mask (rt_sigsuspend, epoll_pwait) stays
                // through the stop, as Linux puts the saved mask back only
                // as the signal work ends: a signal it unblocks, sent while
                // the thread is stopped, is taken as the stop ends.
                Self::stop_rewind(thread, &restart, rewound);
                return Next::Stopped;
            }
            if action.handler == 0 || signal.number == 9 {
                let siginfo = signals::siginfo(&thread.state, &signal);
                return self.terminate_with(thread, signal.number, siginfo);
            }
            // A handler ends any restart, as Linux's signal frame setup sets
            // restart_block to do_no_restart_syscall.
            thread.state.restart_block = None;
            // A call the stop that just ended rewound fails with EINTR when
            // the handler would not run it again, as below.
            if let Some((number, seccomp, no_handler)) = rewound.take()
                && !restart.traced
                && (no_handler
                    || seccomp != Some(true)
                        && (action.flags & signals::SA_RESTART == 0
                            || seccomp.is_none() && !signals::restarts_with_handler(number)))
            {
                thread.cpu.rip = paludarium_types::GuestAddr(thread.cpu.rip.0 + 2);
                thread.cpu.gpr[reg::RAX] = paludarium_types::Errno(4).to_syscall_return();
            }
            // With SA_RESTART the frame resumes at the syscall instruction,
            // so the call runs again when the handler returns.
            if !restart.no_handler
                && (action.flags & signals::SA_RESTART != 0 || restart.seccomp == Some(true))
            {
                Self::rewind_restart(
                    thread,
                    restart.number.filter(|&number| {
                        restart.seccomp.is_some() || signals::restarts_with_handler(number)
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
            let stepped = self.ptrace_handler_entering(thread);
            let limits = self.stack_limits(thread);
            if signals::install(
                &mut thread.state,
                &mut thread.cpu,
                mem,
                signal,
                action,
                limits,
            )
            .is_err()
            {
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
            if stepped {
                self.ptrace_handler_entered(thread, &mut restart);
                return Next::Resume;
            }
            // Linux's way back to user space sets up a frame for each signal
            // it may deliver, the next on this one, before any handler runs
            // (`exit_to_user_mode_loop`); only the first restarts the call.
            restart.number = None;
            restart.seccomp = None;
            delivered = true;
        }
        if delivered {
            return Next::Resume;
        }
        // The temporary wait mask ends with no handler run, unless the
        // thread is still stopped (above).
        if !thread.state.stopped
            && let Some(mask) = thread.state.wait_restore_mask.take()
        {
            thread.state.signal_mask = mask;
        }
        // A call a ptrace stop interrupted runs again when no handler
        // runs, as after any stop.
        // So does one io_uring task work ended, as Linux's
        // `arch_do_signal_or_restart` restarts a call with no signal to
        // deliver: ERESTARTSYS, ERESTARTNOHAND and ERESTARTNOINTR run again,
        // and ERESTART_RESTARTBLOCK through restart_syscall; a call that
        // gives EINTR (epoll_wait) gives it.
        if thread.state.stopped {
            Self::stop_rewind(thread, &restart, rewound);
        } else if restart.traced || notified {
            Self::rewind_restart(thread, restart.number);
        }
        if thread.state.stopped {
            Next::Stopped
        } else {
            Next::Resume
        }
    }

    /// Rewinds the call a group stop interrupted ([`Self::rewind_restart`])
    /// and keeps it, or the one an earlier checkpoint of the same stop
    /// rewound, in `stop_rewound` for the checkpoint that ends the stop:
    /// the restart as the call left it or a tracer that stopped the thread
    /// first left it. Not once a tracer has seen the rewound registers.
    fn stop_rewind(
        thread: &mut Thread,
        restart: &ptrace::Restart,
        rewound: Option<(u64, Option<bool>, bool)>,
    ) {
        thread.state.stop_rewound = if Self::rewind_restart(thread, restart.number) {
            restart
                .number
                .map(|number| (number, restart.seccomp, restart.no_handler))
        } else if restart.traced {
            None
        } else {
            rewound
        };
    }

    /// Runs a syscall interrupted with EINTR again, as Linux restarts
    /// ERESTARTSYS and ERESTARTNOHAND after a stop (which runs no handler)
    /// and ERESTARTSYS after a SA_RESTART handler: the syscall instruction
    /// is re-executed, from the handler's frame in the second case.
    fn rewind_restart(thread: &mut Thread, restart: Option<u64>) -> bool {
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
            return true;
        }
        false
    }

    /// Whether the access a fault stopped can be made now.
    fn accessible(
        mem: &AddressSpace,
        addr: paludarium_types::GuestAddr,
        write: bool,
        fetch: bool,
    ) -> bool {
        if fetch {
            mem.fetch(addr, &mut [0]).is_ok()
        } else if write {
            mem.check_write(addr, 1).is_ok()
        } else {
            mem.check_read(addr, 1).is_ok()
        }
    }

    /// What a mapping that grows down may grow to for `thread`
    /// ([`AddressSpace::grow_down`]): its RLIMIT_STACK in bytes, and the
    /// pages it may have locked, its RLIMIT_MEMLOCK unless it has
    /// `CAP_IPC_LOCK`.
    fn stack_limits(&self, thread: &Thread) -> (u64, u64) {
        const RLIMIT_STACK: usize = 3;
        const RLIMIT_MEMLOCK: usize = 8;
        const CAP_IPC_LOCK: u64 = 1 << 14;
        let stack = self.processes.soft_limit(self.process.pid, RLIMIT_STACK);
        let lock = if thread.state.credentials.capable(CAP_IPC_LOCK) {
            u64::MAX
        } else {
            self.processes.soft_limit(self.process.pid, RLIMIT_MEMLOCK) >> 12
        };
        (stack, lock)
    }

    /// Handles a stop of `thread` (W3, W4).
    pub fn handle(&mut self, thread: &mut Thread, mem: &AddressSpace, reason: ExitReason) -> Next {
        // Its work for the thread is the kernel's: the faults of its
        // accesses count as the kernel's, those of the thread's code before
        // it as the thread's own.
        let _faults = KernelFaults::enter(&thread.state);
        // And its accesses that fault are served as an instruction's are: a
        // mapping that grows down grows, and a `userfaultfd` is waited for.
        let _copies = self.resolve_copies(thread);
        // What it waits for in the host while it handles the stop shows it
        // as sleeping (`/proc/<pid>/stat`), and nothing else does.
        let _attached = paludarium_host::blocked::attach(self.inbox.blocked_flag());
        // `orig_rax`: the call it enters, as it entered it, or -1.
        let orig_rax = if matches!(reason, ExitReason::Syscall { .. }) {
            thread.cpu.gpr[reg::RAX]
        } else {
            u64::MAX
        };
        thread.state.ptrace.enter(thread.tid, orig_rax);
        // As Linux's `pt_regs` keeps them for `/proc/<pid>/syscall`.
        let gpr = &thread.cpu.gpr;
        let call = orig_rax != u64::MAX;
        self.inbox.enter_kernel(inbox::KernelEntry {
            number: orig_rax,
            arguments: if call {
                [
                    gpr[reg::RDI],
                    gpr[reg::RSI],
                    gpr[reg::RDX],
                    gpr[reg::R10],
                    gpr[reg::R8],
                    gpr[reg::R9],
                ]
            } else {
                [0; 6]
            },
            stack_pointer: gpr[reg::RSP],
            instruction_pointer: reason.rip().0,
        });
        // The thread runs no guest code until it takes a CPU again.
        self.leave_cpu();
        // A caller that did not finish the last exec finishes it now.
        self.exec_finished();
        self.group.register(thread.tid, Arc::clone(&self.inbox));
        thread
            .state
            .seat
            .take(self.inbox.tif(), thread.state.signal_mask);
        // Running the `vsyscall` page, which Linux emulates before it looks
        // for a VMA (`do_user_addr_fault`).
        if let Some(address) = vsyscall::entered(&reason) {
            Self::signalled_fault(thread, address, false);
            return self.vsyscall(thread, mem, address);
        }
        // A fault below a mapping that grows down extends it, and the
        // instruction runs again, as Linux's `lock_mm_and_find_vma` expands
        // the stack VMA before it handles the fault. So it does when the
        // access can be made by now, as another thread grew the mapping
        // first; a fault the access still meets (a guard page, a page that
        // cannot be executed) is the signal's, or the instruction would only
        // fault again.
        if let ExitReason::PageFault {
            rip,
            addr,
            write,
            fetch,
            mapped: false,
            ..
        } = reason
            && {
                let (stack, lock) = self.stack_limits(thread);
                mem.grow_down(addr, stack, lock) || Self::accessible(mem, addr, write, fetch)
            }
        {
            thread.cpu.rip = rip;
            return self.checkpoint(thread, mem);
        }
        // A page a `userfaultfd` registered, which has none, or a write to
        // one it write-protected: the thread waits for it, then the
        // instruction runs again (`handle_userfault`).
        if let ExitReason::PageFault {
            rip,
            addr,
            write,
            fetch,
            mapped: true,
            ..
        } = reason
            && let Some((context, reason)) = mem.userfault_for(addr, write, fetch)
        {
            thread.cpu.rip = rip;
            let access = userfaultfd::Access {
                address: addr.0,
                write,
                fetch,
                reason,
            };
            return self.userfault(thread, mem, context, access);
        }
        // One a sampling event is to see ([`paludarium_mmu::faults::arm`]):
        // the page is brought in, and the samples and signals are those of
        // the instruction, which then runs again, as Linux's return from the
        // fault runs the task work of its overflow first.
        if let ExitReason::PageFault {
            rip,
            addr,
            write,
            fetch,
            mapped: true,
            ..
        } = reason
            && self.armed
            && mem.touch(addr, write, fetch)
        {
            thread.cpu.rip = rip;
            return self.checkpoint(thread, mem);
        }
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
                Self::signalled_fault(thread, addr.0, present);
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGSEGV,
                    code: if mapped { 2 } else { 1 },
                    addr: addr.0,
                    trap: 14,
                    error: 4
                        | (u64::from(write) * 2)
                        // Above user space always a protection fault, to
                        // hide the kernel's layout (`sanitize_error_code`).
                        | u64::from(present || addr.0 >= vsyscall::TASK_SIZE_MAX)
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
            // fault's trap and error code, as Linux's do_sigbus sends it; a
            // poisoned page BUS_MCEERR_AR, whose `si_addr_lsb` is the page
            // shift ([`signals::siginfo`]).
            ExitReason::BusError {
                rip,
                addr,
                write,
                fetch,
                present,
                poison,
            } => {
                thread.cpu.rip = rip;
                Self::signalled_fault(thread, addr.0, present);
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGBUS,
                    code: if poison { signals::BUS_MCEERR_AR } else { 2 },
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
            ExitReason::FloatingPointFault { rip, code } | ExitReason::MathFault { rip, code } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGFPE,
                    code: i32::from(code),
                    addr: rip.0,
                    // #XF for SIMD, #MF for the x87 unit.
                    trap: if matches!(reason, ExitReason::MathFault { .. }) {
                        16
                    } else {
                        19
                    },
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
            // The single-step trap: SIGTRAP with TRAP_TRACE and the address
            // past the instruction, as Linux's exc_debug_user sends it
            // (send_sigtrap, trap 1).
            ExitReason::SingleStep { rip } => {
                thread.cpu.rip = rip;
                // DR6 as a tracer reads it: the step (`virtual_dr6`).
                thread.state.ptrace.debug.dr6 = ptrace::DR_STEP;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGTRAP,
                    code: 2,
                    addr: rip.0,
                    trap: 1,
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
            // A hardware breakpoint: SIGTRAP with TRAP_HWBKPT, or TRAP_TRACE
            // when a step came with it (`get_si_code`), at the address the
            // thread is at, and DR6 with the breakpoints hit.
            ExitReason::HardwareBreakpoint { rip, hits, step } => {
                thread.cpu.rip = rip;
                thread.state.ptrace.debug.dr6 =
                    u64::from(hits) | if step { ptrace::DR_STEP } else { 0 };
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGTRAP,
                    code: if step { 2 } else { 4 },
                    addr: rip.0,
                    trap: 1,
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
            // int3: SIGTRAP from the kernel (SI_KERNEL), as do_int3_user's
            // do_trap forces it (trap 3).
            ExitReason::Breakpoint { rip } => {
                thread.cpu.rip = rip;
                Some(signals::PendingSignal {
                    target: signals::PendingTarget::Thread,
                    number: signal::SIGTRAP,
                    code: signals::SI_KERNEL,
                    addr: 0,
                    trap: 3,
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
            ExitReason::SegmentFault { rip, trap, error } => {
                thread.cpu.rip = rip;
                Some(signals::segment_fault(trap, error))
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
                // The entry saves `__USER_CS` and `__USER_DS` as the task's
                // cs and ss (`entry_SYSCALL_64`), which the return gives
                // back unless a tracer or `rt_sigreturn` changes them.
                thread.cpu.segments[paludarium_cpu::segments::CS] =
                    paludarium_cpu::segments::USER_CS;
                thread.cpu.segments[paludarium_cpu::segments::SS] =
                    paludarium_cpu::segments::USER_DS;
                self.syscall(thread, mem)
            }
            ExitReason::PageFault { .. }
            | ExitReason::GeneralProtection { .. }
            | ExitReason::SegmentFault { trap: 13, .. }
            | ExitReason::Halt { .. } => self.terminate(thread, signal::SIGSEGV),
            ExitReason::SegmentFault { .. } => self.terminate(thread, signal::SIGBUS),
            ExitReason::InvalidOpcode { .. } => self.terminate(thread, signal::SIGILL),
            ExitReason::ArithmeticFault { .. }
            | ExitReason::FloatingPointFault { .. }
            | ExitReason::MathFault { .. } => self.terminate(thread, signal::SIGFPE),
            ExitReason::BudgetExhausted { .. } => {
                self.pace.ran(&*self.host);
                self.checkpoint(thread, mem)
            }
            // Later units add stop reasons; until then they end the process.
            _ => self.terminate(thread, signal::SIGSEGV),
        }
    }

    /// The samples the perf events that count the thread take of what it
    /// has done since its last system call or checkpoint
    /// ([`perf::overflow`]), and the SIGTRAP of those with `sigtrap`.
    fn perf_samples(&self, thread: &mut Thread, mem: &AddressSpace) {
        const SIGTRAP: u64 = 1 << 4;
        let task = perf::Task {
            pid: thread.state.pid,
            tid: thread.tid,
            cpu: thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
            regs: &thread.cpu,
            mem,
            blocks_sigtrap: thread.state.signal_mask & SIGTRAP != 0,
        };
        // The `sigtrap` of an event that overflowed, for the thread.
        let per_tick = self.processes.sysctls.perf_max_samples_per_tick();
        for signal in perf::overflow(&self.processes.perf_events, &self.group, &task, per_tick) {
            signals::queue(&mut thread.state, signal);
        }
    }

    /// After [`account_cpu`]: a thread that slept or moved to another CPU
    /// since its last account was scheduled in again, which updates its
    /// events' user pages ([`perf::scheduled_in`]).
    fn scheduled_in(&self, thread: &mut Thread) {
        if std::mem::take(&mut thread.state.cpu.resumed) {
            perf::scheduled_in(&self.processes.perf_events, &self.group, thread.tid);
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
        self.scheduled_in(thread);
        if perf::sampling(&self.processes.perf_events) {
            self.perf_samples(thread, mem);
        }
        thread.state.ptrace.in_syscall = true;
        // The tracer may see and change the call first, or skip it.
        if self.group.traced() && !self.ptrace_syscall_entry(thread) {
            return self.checkpoint(thread, mem);
        }
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
        if thread.state.seccomp.mode != 0 && !self.seccomp_suspended(thread.tid) {
            let mut verdict =
                seccomp::check(&thread.state.seccomp, number as u32, args, thread.cpu.rip.0);
            // SECCOMP_RET_TRACE: the tracer may change or skip the call,
            // which the filters then see again (`__seccomp_filter`).
            if let seccomp::Verdict::Trace(data) = verdict {
                let Some(traced) = self.ptrace_seccomp(thread, data) else {
                    thread.state.restart = None;
                    thread.state.syscall_rax = thread.cpu.gpr[reg::RAX];
                    return self.checkpoint(thread, mem);
                };
                number = traced;
                args = [
                    thread.cpu.gpr[reg::RDI],
                    thread.cpu.gpr[reg::RSI],
                    thread.cpu.gpr[reg::RDX],
                    thread.cpu.gpr[reg::R10],
                    thread.cpu.gpr[reg::R8],
                    thread.cpu.gpr[reg::R9],
                ];
                verdict = match seccomp::check(
                    &thread.state.seccomp,
                    number as u32,
                    args,
                    thread.cpu.rip.0,
                ) {
                    seccomp::Verdict::Trace(_) => seccomp::Verdict::Allow,
                    verdict => verdict,
                };
            }
            match verdict {
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
        // A traced thread's clone reports its event once the task it makes
        // has started.
        if number == 56 || number == 57 || number == 58 {
            thread.state.ptrace.hold = self.group.traced() && self.traced(thread.tid);
            if thread.state.ptrace.hold {
                self.ptrace_clone(thread, number, args[0]);
            }
        }
        if let Some(next) = self.process_syscall(thread, mem, number, args) {
            return self.ptrace_cloned(thread, mem, next);
        }
        if let Some(next) = self.thread_syscall(thread, mem, number, args) {
            return self.ptrace_cloned(thread, mem, next);
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
        fanotify::enter(thread.state.pid, thread.tid);
        proc::enter(
            thread.state.pid,
            thread.tid,
            thread.state.cpu.on.map_or(0, |(cpu, _)| cpu),
        );
        // A rename through `comm` comes before what the call does, as
        // Linux's takes effect when it is written.
        if let Some(name) = self.group.take_rename(thread.tid) {
            thread.state.name = name;
        }
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
        // What the call made ready completes the polls that wait for it,
        // in any process, before the call returns.
        aio::progress(&ctx);
        if number == syscalls::nr::RT_SIGACTION
            && args[1] != 0
            && let Some(action) = thread.state.signal_actions.get(&(args[0] as i32))
        {
            self.group.set_action(args[0] as i32, *action);
        }
        // `sched_setaffinity` moves the thread before it returns
        // (`__set_cpus_allowed_ptr`): what it does next is the new CPU's.
        if number == syscalls::nr::SCHED_SETAFFINITY {
            account_cpu(&*self.host, &self.group, &mut thread.state, thread.tid);
            self.scheduled_in(thread);
        }
        self.inbox.drain(&mut thread.state);
        match outcome {
            syscalls::Outcome::Return(value) => {
                thread.cpu.gpr[reg::RAX] = value;
                self.checkpoint(thread, mem)
            }
            syscalls::Outcome::Restored => self.checkpoint(thread, mem),
            syscalls::Outcome::BadFrame => self.terminate(thread, signal::SIGSEGV),
            // The return to the restored context faults on its SS, as
            // Linux's `iret` does, at the restored instruction.
            syscalls::Outcome::RestoredFault(fault) => {
                signals::queue(
                    &mut thread.state,
                    signals::segment_fault(fault.trap(), fault.error()),
                );
                self.checkpoint(thread, mem)
            }
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
mod fanotify_tests;
#[cfg(test)]
mod keys_tests;
#[cfg(test)]
mod perf_sample_tests;
#[cfg(test)]
mod perf_side_band_tests;
#[cfg(test)]
mod perf_tests;
#[cfg(test)]
mod processes_tests;
#[cfg(test)]
mod userfaultfd_tests;
#[cfg(test)]
mod wasm_tests;
