//! Emulated process registry; no lock spans Host waits or guest execution.
use crate::credentials::TaskIds;
use crate::fasync::{FileOwner, OwnerKind, Reason};
use crate::inotify::reported_open;
use crate::namespaces::Namespace;
use crate::scheduling;
use crate::{Kernel, Next, SignalInbox, Thread, ThreadGroup, ThreadState, signals};
use paludarium_cpu::{CpuState, reg};
use paludarium_host::{ClockId, FileHandle, WaitToken};
use paludarium_loader::{LoadError, StartInfo};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, ExitStatus, GuestAddr};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
};

struct Entry {
    parent: u32,
    group: Arc<ThreadGroup>,
    status: Option<ExitStatus>,
    /// Process group ID; inherited on fork and kept across exec.
    pgid: u32,
    /// Session ID, inherited the same way. The first process's session is
    /// outside the emulator, so its ID reads as 0, as a PID namespace reports
    /// an ID it cannot see; a session leader is the process whose PID it is.
    sid: u32,
    /// Whether the process has run `execve` since its fork (Linux clears
    /// PF_FORKNOEXEC then); its parent can no longer change its group.
    executed: bool,
    /// How many times it has run `execve` (Linux's `self_exec_id`), which a
    /// message queue's registration must still match to signal it.
    execs: u64,
    /// Resource limits (soft, hard), inherited on fork and kept across exec.
    /// They are recorded and reported; RLIMIT_FSIZE and RLIMIT_NOFILE are
    /// enforced through the copy of their soft limits in the thread group,
    /// RLIMIT_CPU through its pair there ([`Entry::limits`]), and
    /// RLIMIT_CORE when a core is dumped.
    limits: [(u64, u64); RLIMITS],
    /// PR_SET_PDEATHSIG: sent to this process when its parent exits; cleared
    /// on fork.
    death_signal: i32,
    /// PR_SET_DUMPABLE and PR_SET_NO_NEW_PRIVS, recorded for PR_GET_*.
    dumpable: bool,
    no_new_privs: bool,
    /// A stop by this signal, and a continue, not yet reported to a wait.
    stop_report: Option<i32>,
    continue_report: bool,
    /// CPU time of the children this process has waited for, and theirs.
    children_cpu: u64,
    /// The signal its exit sends the parent (clone's CSIGNAL bits); only a
    /// SIGCHLD child can be reaped automatically.
    exit_signal: i32,
    /// PR_SET_CHILD_SUBREAPER: orphaned descendants come to this process
    /// rather than to the first one. Not inherited on fork, kept on exec.
    subreaper: bool,
    /// Whether its fatal signal wrote a whole core (CLD_DUMPED).
    dumped: bool,
    /// Its controlling terminal (Linux's `signal->tty`), when that is a
    /// pseudo-terminal of the emulator: inherited on fork, kept across
    /// exec, and lost by `setsid`.
    terminal: Option<Arc<crate::pty::Terminal>>,
    /// The task the process counts as until it is reaped, as its leader does
    /// in Linux's pids controller even as a zombie.
    _task: TaskCharge,
    /// The PID namespace it is in (Linux's `task_active_pid_ns`), which
    /// numbers it, and the IDs it is shown, from its own up to the first.
    space: Arc<Namespace>,
    /// The init of a nested PID namespace whose exit waits for the rest of
    /// the namespace to be gone, as Linux's `zap_pid_ns_processes` waits,
    /// before its parent is told.
    held: bool,
}
impl Entry {
    /// The resource limits as they are now: the `RLIMIT_CPU` soft limit is
    /// the thread group's, which sending SIGXCPU raises.
    fn limits(&self) -> [(u64, u64); RLIMITS] {
        let mut limits = self.limits;
        limits[RLIMIT_CPU].0 = self.group.cpu_soft_limit();
        limits
    }
}

/// The tasks of a session and their limit, as a cgroup's `pids.current` and
/// `pids.max`: every thread counts, and a process until it is reaped.
struct TaskCount {
    live: AtomicU64,
    max: AtomicU64,
}

/// One task counted against the session's limit, released when dropped.
pub(crate) struct TaskCharge(Arc<TaskCount>);

impl Drop for TaskCharge {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

const SIGHUP: i32 = 1;
const SIGCONT: i32 = 18;
/// RLIMIT_CPU ... RLIMIT_RTTIME.
pub(crate) const RLIMITS: usize = 16;
const INFINITY: u64 = u64::MAX;
/// The limits a fresh Linux process gets from the kernel, with NPROC and
/// SIGPENDING (which Linux sizes from memory) fixed at 4096.
const DEFAULT_LIMITS: [(u64, u64); RLIMITS] = [
    (INFINITY, INFINITY), // CPU
    (INFINITY, INFINITY), // FSIZE
    (INFINITY, INFINITY), // DATA
    (8 << 20, INFINITY),  // STACK
    (0, INFINITY),        // CORE
    (INFINITY, INFINITY), // RSS
    (4096, 4096),         // NPROC
    (1024, 4096),         // NOFILE
    (8 << 20, 8 << 20),   // MEMLOCK
    (INFINITY, INFINITY), // AS
    (INFINITY, INFINITY), // LOCKS
    (4096, 4096),         // SIGPENDING
    (819_200, 819_200),   // MSGQUEUE
    (0, 0),               // NICE
    (0, 0),               // RTPRIO
    (INFINITY, INFINITY), // RTTIME
];
const RLIMIT_CPU: usize = 0;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;
/// Linux's TASK_UNMAPPED_BASE on x86-64: a third of TASK_SIZE, page-aligned.
const TASK_UNMAPPED_BASE: u64 = (((1 << 47) - 4096) / 3 + 4095) & !4095;
/// A thread `getpriority` or `setpriority` found.
struct PriorityThread {
    group: Arc<ThreadGroup>,
    tid: u32,
    nice: i32,
    ids: TaskIds,
    /// The RLIMIT_NICE and RLIMIT_RTPRIO soft limits of its process.
    nice_limit: u64,
    rtprio_limit: u64,
}
/// fs.nr_open: the highest RLIMIT_NOFILE Linux accepts by default.
const NR_OPEN: u64 = 1 << 20;
/// `pid_max`, at its highest (`PID_MAX_LIMIT`), as on a 64-bit Linux that
/// systemd starts: `set_tid` takes numbers below it.
pub(crate) const PID_MAX: u32 = 4_194_304;
/// A process as [`Processes::view`] gives it.
pub(crate) struct ProcessView {
    pub parent: u32,
    pub group_id: u32,
    pub session: u32,
    pub children_cpu: u64,
    /// The RLIMIT_RSS and RLIMIT_SIGPENDING soft limits.
    pub rss_limit: u64,
    pub queue_limit: u64,
    pub no_new_privs: bool,
    pub dumpable: bool,
    /// It has ended and waits to be reaped.
    pub zombie: bool,
    pub exit_signal: i32,
    pub group: Arc<ThreadGroup>,
    /// The controlling terminal.
    pub terminal: Option<Arc<crate::pty::Terminal>>,
    /// The PID namespace it is numbered in, its own.
    pub space: Arc<Namespace>,
}
pub struct Processes {
    next: AtomicU32,
    /// The IDs from `next` on that `clone3`'s `set_tid` took out of turn,
    /// which [`Self::allocate`] passes over; held while `next` moves.
    taken: Mutex<std::collections::BTreeSet<u32>>,
    entries: Mutex<BTreeMap<u32, Entry>>,
    tasks: Arc<TaskCount>,
    /// The highest RLIMIT_NOFILE hard limit a process may set, as fs.nr_open.
    nr_open: AtomicU64,
    /// Notified whenever a process exits, stops or continues, lets its vfork
    /// parent go, or is sent a signal by a process (`kill`, a queued signal),
    /// so that a wait for a child wakes at once for these; another signal (a
    /// timer's, a thread's own) reaches it through the 10 ms poll.
    changed: WaitToken,
    /// The owners of the open files that are neither pipes nor sockets.
    file_owners: Mutex<crate::fasync::Owners>,
    /// The machine's byte-range locks (`fcntl`'s `F_SETLK` and OFD locks).
    locks: crate::record_locks::Locks,
    /// The machine's FIFOs, which every process opening one joins.
    fifos: Arc<crate::fifo::Fifos>,
    /// The machine's virtual CPUs, which threads with `rseq` run on.
    pub(crate) cpus: Arc<crate::rseq::Cpus>,
    /// The bytes the users' POSIX message queues charge.
    pub(crate) mqueue_charges: Arc<crate::mqueue::Charges>,
    /// The queues `/dev/mqueue` shows: the first IPC namespace's.
    pub(crate) mqueue_mount: crate::mqueue::Queues,
    /// The cookies `kcmp` hides objects behind, drawn once.
    kcmp_cookies: std::sync::OnceLock<[[u64; 2]; crate::kcmp::TYPES]>,
    /// The events the machine's aio contexts take, and their limit.
    pub(crate) aio: Arc<crate::aio::Limits>,
}
impl Processes {
    pub(crate) fn new(group: Arc<ThreadGroup>) -> Self {
        let space = group.namespaces(1).pid.clone();
        let tasks = Arc::new(TaskCount {
            live: AtomicU64::new(1),
            max: AtomicU64::new(u64::MAX),
        });
        Self {
            next: AtomicU32::new(2),
            taken: Mutex::default(),
            nr_open: AtomicU64::new(NR_OPEN),
            changed: WaitToken::default(),
            file_owners: Mutex::default(),
            locks: crate::record_locks::Locks::default(),
            fifos: Arc::default(),
            cpus: Arc::default(),
            mqueue_charges: Arc::default(),
            mqueue_mount: group.namespaces(1).ipc.mq.clone(),
            kcmp_cookies: std::sync::OnceLock::new(),
            aio: Arc::default(),
            entries: Mutex::new(BTreeMap::from([(
                1,
                Entry {
                    parent: 0,
                    group,
                    status: None,
                    // Like its session, the first process's group is outside
                    // the emulator, and Linux shows an ID outside a PID
                    // namespace as 0. So the process is no group's leader and
                    // may start a session.
                    pgid: 0,
                    sid: 0,
                    executed: false,
                    execs: 0,
                    limits: DEFAULT_LIMITS,
                    death_signal: 0,
                    dumpable: true,
                    no_new_privs: false,
                    stop_report: None,
                    continue_report: false,
                    children_cpu: 0,
                    exit_signal: signals::SIGCHLD,
                    subreaper: false,
                    dumped: false,
                    terminal: None,
                    _task: TaskCharge(Arc::clone(&tasks)),
                    space,
                    held: false,
                },
            )])),
            tasks,
        }
    }
    /// Limits the session to `max` tasks: a clone or fork beyond it fails
    /// with EAGAIN, as past a cgroup's `pids.max`.
    pub(crate) fn set_task_limit(&self, max: u64) {
        self.tasks.max.store(max, Ordering::SeqCst);
    }
    /// Counts one more task, or fails with EAGAIN at the limit.
    pub(crate) fn charge_task(&self) -> Result<TaskCharge, Errno> {
        let max = self.tasks.max.load(Ordering::SeqCst);
        self.tasks
            .live
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                (live < max).then_some(live + 1)
            })
            .map_err(|_| Errno::EAGAIN)?;
        Ok(TaskCharge(Arc::clone(&self.tasks)))
    }
    /// Caps RLIMIT_NOFILE at `max`, as a container started with that limit
    /// and fs.nr_open: raising the hard limit beyond it fails with EPERM. Set
    /// before the guest starts, when the first process is the only one; the
    /// processes it creates inherit its limits.
    pub(crate) fn set_open_file_limit(&self, max: u64) {
        self.nr_open.store(max, Ordering::SeqCst);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        debug_assert_eq!(entries.len(), 1, "set before the guest starts");
        for entry in entries.values_mut() {
            let (soft, hard) = entry.limits[7];
            entry.limits[7] = (soft.min(max), hard.min(max));
            entry.group.set_soft_limit(7, soft.min(max));
        }
    }
    /// The live tasks, threads included, and the last ID handed out, for
    /// `/proc/loadavg`.
    pub(crate) fn task_counts(&self) -> (usize, u32) {
        let live = self.tasks.live.load(Ordering::SeqCst);
        let next = self.next.load(Ordering::SeqCst);
        (
            usize::try_from(live).unwrap_or(usize::MAX),
            next.saturating_sub(1),
        )
    }
    /// The next ID, which no task has had: the IDs of the first PID
    /// namespace are handed out once each, and those `set_tid` took are
    /// passed over.
    pub(crate) fn allocate(&self) -> Result<u32, Errno> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let id = self
                .next
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    (value < i32::MAX as u32).then_some(value + 1)
                })
                .map_err(|_| Errno::EAGAIN)?;
            if !taken.remove(&id) {
                return Ok(id);
            }
        }
    }
    /// Whether ID `id` is free for `set_tid`: no task has had it. One
    /// handed out before is not, even once it is freed, as IDs here are
    /// never used twice (where Linux's `idr_alloc` takes a freed one).
    fn is_free(&self, id: u32) -> bool {
        let taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        id >= self.next.load(Ordering::SeqCst) && !taken.contains(&id)
    }
    /// Takes ID `id` for `set_tid`, or `EEXIST` when it is not free.
    fn take(&self, id: u32) -> Result<u32, Errno> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        if id < self.next.load(Ordering::SeqCst) || !taken.insert(id) {
            return Err(Errno::EEXIST);
        }
        Ok(id)
    }
    /// The ID of a new task in PID namespace `space`, numbered there and in
    /// each namespace it is in, as Linux's `alloc_pid`. `set_tid` (`clone3`'s)
    /// gives the numbers to take, from `space` out, the first namespace's
    /// being the ID itself. For each, from `space` out: `EINVAL` beyond the
    /// namespaces, for a number below 1 or from `pid_max` on, and for one
    /// other than 1 in a namespace with no init yet; `EPERM` unless
    /// `credentials` (the caller's) have CAP_SYS_ADMIN or
    /// CAP_CHECKPOINT_RESTORE in the user namespace owning the namespace;
    /// and `EEXIST` for a number that is taken.
    pub(crate) fn allocate_in(
        &self,
        space: &Namespace,
        set_tid: &[u32],
        credentials: &crate::credentials::Credentials,
    ) -> Result<u32, Errno> {
        let levels = space.levels();
        if set_tid.len() > levels.len() {
            return Err(Errno::EINVAL);
        }
        for (&number, &level) in set_tid.iter().zip(levels.iter().rev()) {
            if !(1..PID_MAX).contains(&number) || number != 1 && level.init().is_none() {
                return Err(Errno::EINVAL);
            }
            let owner = level.owner();
            if !credentials.capable_in(crate::credentials::CAP_SYS_ADMIN, owner)
                && !credentials.capable_in(crate::credentials::CAP_CHECKPOINT_RESTORE, owner)
            {
                return Err(Errno::EPERM);
            }
            let taken = if level.is_first() {
                !self.is_free(number)
            } else {
                level.task(number).is_some()
            };
            if taken {
                return Err(Errno::EEXIST);
            }
        }
        let id = match set_tid.get(levels.len() - 1) {
            Some(&id) => self.take(id)?,
            None => self.allocate()?,
        };
        // When the namespaces refuse it, the ID stays used up, as one from
        // `allocate` does: IDs here are never handed out twice.
        space.enter(id, &set_tid[..set_tid.len().min(levels.len() - 1)])?;
        Ok(id)
    }
    pub(crate) fn insert(
        &self,
        pid: u32,
        parent: u32,
        group: Arc<ThreadGroup>,
        exit_signal: i32,
        task: TaskCharge,
        space: Arc<Namespace>,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (pgid, sid, limits, dumpable, no_new_privs, terminal) =
            entries
                .get(&parent)
                .map_or((pid, 0, DEFAULT_LIMITS, true, false, None), |p| {
                    (
                        p.pgid,
                        p.sid,
                        p.limits(),
                        p.dumpable,
                        p.no_new_privs,
                        p.terminal.clone(),
                    )
                });
        entries.insert(
            pid,
            Entry {
                parent,
                group,
                status: None,
                pgid,
                sid,
                executed: false,
                execs: 0,
                limits,
                death_signal: 0,
                dumpable,
                no_new_privs,
                stop_report: None,
                continue_report: false,
                children_cpu: 0,
                exit_signal,
                subreaper: false,
                dumped: false,
                terminal,
                _task: task,
                space,
                held: false,
            },
        );
    }
    /// `prctl` options kept per process.
    fn prctl(&self, pid: u32, option: u64, a: [u64; 6]) -> Result<Option<i32>, Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        match option {
            // PR_SET_PDEATHSIG, PR_GET_PDEATHSIG (written out by the caller)
            1 => {
                let number = i32::try_from(a[1]).map_err(|_| Errno::EINVAL)?;
                if !(0..=64).contains(&number) {
                    return Err(Errno::EINVAL);
                }
                entry.death_signal = number;
                Ok(None)
            }
            2 => Ok(Some(entry.death_signal)),
            // PR_GET_DUMPABLE, PR_SET_DUMPABLE
            3 => Ok(Some(i32::from(entry.dumpable))),
            4 if a[1] <= 1 => {
                entry.dumpable = a[1] == 1;
                Ok(None)
            }
            // PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER (written out by
            // the caller)
            36 => {
                entry.subreaper = a[1] != 0;
                Ok(None)
            }
            37 => Ok(Some(i32::from(entry.subreaper))),
            // PR_SET_NO_NEW_PRIVS (only to 1, for good), PR_GET_NO_NEW_PRIVS
            38 if a[1] == 1 && a[2] == 0 && a[3] == 0 && a[4] == 0 => {
                entry.no_new_privs = true;
                Ok(None)
            }
            39 if a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 => {
                Ok(Some(i32::from(entry.no_new_privs)))
            }
            _ => Err(Errno::EINVAL),
        }
    }
    /// The controlling terminal of process `pid`.
    pub(crate) fn terminal(&self, pid: u32) -> Option<Arc<crate::pty::Terminal>> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).and_then(|entry| entry.terminal.clone())
    }
    /// The process group and session of process `pid`.
    pub(crate) fn group_and_session(&self, pid: u32) -> Result<(u32, u32), Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(&pid)
            .map(|entry| (entry.pgid, entry.sid))
            .ok_or(Errno(3))
    }
    /// Sends `number` to every process of group `pgid`: from the kernel,
    /// or with `sender` (its PID and real user ID) as `kill` sends it.
    pub(crate) fn signal_group(&self, pgid: u32, number: i32, sender: Option<(u32, u32)>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let signal = match sender {
            Some((pid, uid)) => Self::from_process(number, pid, uid),
            None => Self::from_kernel(number),
        };
        Self::signal_members(&mut entries, pgid, signal);
        self.changed.notify();
    }
    fn signal_members(
        entries: &mut BTreeMap<u32, Entry>,
        pgid: u32,
        signal: signals::PendingSignal,
    ) {
        let members: Vec<u32> = entries
            .iter()
            .filter(|(_, entry)| entry.pgid == pgid)
            .map(|(&pid, _)| pid)
            .collect();
        for member in members {
            let _ = Self::deliver(entries, member, None, signal);
        }
    }
    /// Whether group `pgid` is orphaned (Linux's `will_become_orphaned_pgrp`
    /// with no task left out): no live member has a parent in another
    /// group of its session.
    pub(crate) fn group_orphaned(&self, pgid: u32) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        !entries
            .values()
            .filter(|entry| entry.pgid == pgid && entry.status.is_none())
            .any(|entry| Self::links_group(&entries, entry))
    }
    /// The session of process group `id`, or of process `id` when no group
    /// has that ID (Linux's `session_of_pgrp`); `None` when neither exists.
    pub(crate) fn session_of_group(&self, id: u32) -> Option<u32> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .values()
            .find(|entry| entry.pgid == id)
            .or_else(|| entries.get(&id))
            .map(|entry| entry.sid)
    }
    /// `TIOCSCTTY` from `pid`, as Linux's `tiocsctty`: a session leader
    /// without a controlling terminal takes `terminal`, with its group in
    /// the foreground, unless another session has it, which only
    /// CAP_SYS_ADMIN with `steal` takes away. A descriptor not open for
    /// reading needs CAP_SYS_ADMIN too.
    pub(crate) fn set_terminal(
        &self,
        pid: u32,
        terminal: &Arc<crate::pty::Terminal>,
        steal: bool,
        readable: bool,
        admin: bool,
    ) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid).ok_or(Errno(3))?;
        let (sid, pgid) = (entry.sid, entry.pgid);
        let leader = sid == pid;
        if leader && terminal.session() == Some(sid) {
            return Ok(());
        }
        if !leader || entry.terminal.is_some() {
            return Err(Errno::EPERM);
        }
        if let Some(other) = terminal.session() {
            if !(steal && admin) {
                return Err(Errno::EPERM);
            }
            Self::clear_session(&mut entries, other);
        }
        if !readable && !admin {
            return Err(Errno::EPERM);
        }
        if let Some(entry) = entries.get_mut(&pid) {
            entry.terminal = Some(Arc::clone(terminal));
        }
        terminal.control(sid, pgid);
        Ok(())
    }
    /// An open of `terminal` without `O_NOCTTY` by `pid`, as Linux's
    /// `tty_open_proc_set_tty`: a session leader without a controlling
    /// terminal gets it, if no session has it.
    pub(crate) fn open_terminal(&self, pid: u32, terminal: &Arc<crate::pty::Terminal>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid)
            && entry.sid == pid
            && entry.terminal.is_none()
            && terminal.session().is_none()
        {
            entry.terminal = Some(Arc::clone(terminal));
            terminal.control(entry.sid, entry.pgid);
        }
    }
    /// `TIOCNOTTY` from `pid`, whose controlling terminal `terminal` is: a
    /// session leader's session loses it, its foreground group told with
    /// SIGHUP and SIGCONT (Linux's `disassociate_ctty(0)`); any other
    /// process only lets it go.
    pub(crate) fn leave_terminal(
        &self,
        pid: u32,
        terminal: &Arc<crate::pty::Terminal>,
    ) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        if entry.sid != pid {
            entry.terminal = None;
            return Ok(());
        }
        Self::disassociate(&mut entries, pid, terminal, true);
        self.changed.notify();
        Ok(())
    }
    /// Linux's `disassociate_ctty` for session leader `pid`: the terminal's
    /// foreground group gets SIGHUP from the kernel, and with `cont`, as
    /// for `TIOCNOTTY`, SIGCONT too, from `pid`; then no process of the
    /// session has it, and it controls no session.
    fn disassociate(
        entries: &mut BTreeMap<u32, Entry>,
        pid: u32,
        terminal: &Arc<crate::pty::Terminal>,
        cont: bool,
    ) {
        if let Some(pgrp) = terminal.foreground() {
            let uid = entries
                .get(&pid)
                .map_or(0, |entry| entry.group.task_ids(pid, pid).uid);
            let sent = |number| {
                if cont {
                    Self::from_process(number, pid, uid)
                } else {
                    Self::from_kernel(number)
                }
            };
            Self::signal_members(entries, pgrp, sent(SIGHUP));
            if cont {
                Self::signal_members(entries, pgrp, sent(SIGCONT));
            }
        }
        Self::clear_session(entries, pid);
        terminal.release();
    }
    /// `session_clear_tty`: no process of session `sid` has a controlling
    /// terminal.
    fn clear_session(entries: &mut BTreeMap<u32, Entry>, sid: u32) {
        for entry in entries.values_mut().filter(|entry| entry.sid == sid) {
            entry.terminal = None;
        }
    }
    /// A hang-up of `terminal`, whose master closed, as Linux's
    /// `tty_signal_session_leader`: the processes of the session it
    /// controls lose it, and the session's leader gets SIGHUP and SIGCONT.
    pub(crate) fn hang_up_terminal(&self, terminal: &Arc<crate::pty::Terminal>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sid) = terminal.session() {
            for entry in entries.values_mut().filter(|entry| entry.sid == sid) {
                if entry
                    .terminal
                    .as_ref()
                    .is_some_and(|own| Arc::ptr_eq(own, terminal))
                {
                    entry.terminal = None;
                }
            }
            for number in [SIGHUP, SIGCONT] {
                let _ = Self::deliver(&mut entries, sid, None, Self::from_kernel(number));
            }
        }
        terminal.release();
        self.changed.notify();
    }
    fn pgid(&self, pid: u32) -> Result<u32, Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map(|e| e.pgid).ok_or(Errno(3))
    }
    fn sid(&self, pid: u32) -> Result<u32, Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map(|e| e.sid).ok_or(Errno(3))
    }
    /// `setsid` from `caller`, as Linux's ksys_setsid: a process group
    /// leader (or any process whose PID names a group) gets EPERM; otherwise
    /// the caller leads a new session and a new group, both its PID.
    fn set_sid(&self, caller: u32) -> Result<u32, Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.values().any(|e| e.pgid == caller) {
            return Err(Errno::EPERM);
        }
        let entry = entries.get_mut(&caller).ok_or(Errno(3))?;
        (entry.sid, entry.pgid) = (caller, caller);
        entry.terminal = None;
        Ok(caller)
    }
    /// `setpgid` from `caller`, in Linux's order: the target is the caller or
    /// one of its children in the caller's session that has not run `execve`
    /// (EACCES), and not a session leader; a new group either is the target's
    /// own or exists in that session, where an unreaped zombie still counts.
    fn set_pgid(&self, caller: u32, pid: u32, pgid: u32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let session = entries.get(&caller).ok_or(Errno(3))?.sid;
        let target = entries.get(&pid).ok_or(Errno(3))?;
        if pid != caller && target.parent != caller {
            return Err(Errno(3)); // ESRCH
        }
        if pid != caller {
            if target.sid != session {
                return Err(Errno::EPERM);
            }
            if target.executed {
                return Err(Errno::EACCES);
            }
        }
        if target.sid == pid {
            return Err(Errno::EPERM);
        }
        if pgid != pid && !entries.values().any(|e| e.pgid == pgid && e.sid == session) {
            return Err(Errno::EPERM);
        }
        if let Some(entry) = entries.get_mut(&pid) {
            entry.pgid = pgid;
        }
        Ok(())
    }
    /// The threads `getpriority` and `setpriority` act on, with their nice
    /// values, as Linux finds them: for `PRIO_PROCESS` the thread `who` (0 is
    /// `tid`, the caller), for `PRIO_PGRP` every thread of the group's
    /// processes (0 is the caller's group), and for `PRIO_USER` every thread
    /// of real user ID `who` (0 is `uid`, the caller's). An unreaped process
    /// still counts, by its leader.
    fn priority_threads(
        &self,
        which: i32,
        who: i32,
        caller: u32,
        tid: u32,
        uid: u32,
    ) -> Result<Vec<PriorityThread>, Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let thread = |pid: u32, entry: &Entry, tid: u32, nice: i32| PriorityThread {
            group: Arc::clone(&entry.group),
            tid,
            nice,
            ids: entry.group.task_ids(pid, tid),
            nice_limit: entry.limits[RLIMIT_NICE].0,
            rtprio_limit: entry.limits[RLIMIT_RTPRIO].0,
        };
        let all = |(&pid, entry): (&u32, &Entry)| {
            entry
                .group
                .nices()
                .into_iter()
                .map(|(tid, nice)| thread(pid, entry, tid, nice))
                .collect::<Vec<_>>()
        };
        Ok(match which {
            0 => {
                let tid = if who == 0 { tid } else { who as u32 };
                entries
                    .iter()
                    .filter(|_| who >= 0)
                    .find_map(|(&pid, e)| e.group.nice(tid).map(|nice| thread(pid, e, tid, nice)))
                    .into_iter()
                    .collect()
            }
            1 => {
                let pgid = match who {
                    0 => entries.get(&caller).ok_or(Errno(3))?.pgid,
                    who => who as u32,
                };
                entries
                    .iter()
                    .filter(|(_, e)| who >= 0 && e.pgid == pgid)
                    .flat_map(all)
                    .collect()
            }
            2 => {
                let uid = if who == 0 { uid } else { who as u32 };
                entries
                    .iter()
                    .flat_map(all)
                    .filter(|thread| thread.ids.uid == uid)
                    .collect()
            }
            _ => return Err(Errno::EINVAL),
        })
    }
    /// An effective or filesystem ID of the process changed: it becomes
    /// undumpable (`fs.suid_dumpable`, 0 by default) and forgets its
    /// parent-death signal, as Linux's `commit_creds` does.
    pub(crate) fn credentials_changed(&self, pid: u32) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            entry.dumpable = false;
            entry.death_signal = 0;
        }
    }
    /// After exec, the process is dumpable or not, may forget its
    /// parent-death signal, and a secure exec lowers its RLIMIT_STACK soft
    /// limit to 8 MiB (`_STK_LIM`), as Linux's `begin_new_exec` does.
    pub(crate) fn executed_as(
        &self,
        pid: u32,
        dumpable: bool,
        forget_death_signal: bool,
        secure: bool,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            entry.dumpable = dumpable;
            if forget_death_signal {
                entry.death_signal = 0;
            }
            if secure {
                entry.limits[3].0 = entry.limits[3].0.min(8 << 20);
            }
        }
    }
    pub(crate) fn mark_executed(&self, pid: u32) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            entry.executed = true;
            entry.execs += 1;
        }
    }
    /// `prlimit64` from `sender`: returns the old limit of the process of
    /// thread `named`, after setting `new` if given. As Linux's
    /// `check_prlimit_permission`, a thread may always use its own, by its own
    /// ID (`own`), and raising a hard limit needs CAP_SYS_RESOURCE.
    fn limit(
        &self,
        sender: TaskIds,
        own: bool,
        named: u32,
        resource: usize,
        new: Option<(u64, u64)>,
    ) -> Result<(u64, u64), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // A thread's ID names its process, as `kill` finds it.
        let pid = entries
            .iter()
            .find(|&(&key, entry)| {
                key == named || (entry.status.is_none() && entry.group.has_member(named))
            })
            .map(|(&key, _)| key)
            .ok_or(Errno(3))?;
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        if !own && !sender.may_prlimit(&entry.group.task_ids(pid, named)) {
            return Err(Errno::EPERM);
        }
        let old = *entry.limits().get(resource).ok_or(Errno::EINVAL)?;
        if let Some((soft, hard)) = new {
            if soft > hard {
                return Err(Errno::EINVAL);
            }
            if resource == 7 && hard > self.nr_open.load(Ordering::SeqCst) {
                return Err(Errno::EPERM);
            }
            if hard > old.1 && !sender.capable(crate::credentials::CAP_SYS_RESOURCE) {
                return Err(Errno::EPERM);
            }
            entry.limits[resource] = (soft, hard);
            entry.group.set_soft_limit(resource, soft);
            if resource == RLIMIT_CPU {
                entry.group.set_cpu_limit(soft, hard);
            }
        }
        Ok(old)
    }
    /// How many times process `pid` has run `execve`, while it runs; none
    /// once it has ended or is gone.
    pub(crate) fn execs(&self, pid: u32) -> Option<u64> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(&pid)
            .filter(|entry| entry.status.is_none())
            .map(|entry| entry.execs)
    }
    /// A POSIX message queue's `SIGEV_SIGNAL` notification to process
    /// `pid`, as Linux's `__do_notify` sends it past the checks of `kill`:
    /// `number` with `si_code` `SI_MESGQ`, the sending process `sender` as
    /// the receiver's PID namespace numbers it, the sender's user ID `uid`
    /// (as the registration's user namespace shows it) and the
    /// registration's `value`, unless `pid` has run `execve` since it
    /// registered, after `execs` of them.
    pub(crate) fn notify_message_queue(
        &self,
        pid: u32,
        execs: u64,
        number: i32,
        sender: u32,
        uid: u32,
        value: u64,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = entries.get(&pid) else {
            return;
        };
        if entry.status.is_some() || entry.execs != execs {
            return;
        }
        let mut info = [0u8; 48];
        info[0..4].copy_from_slice(&number.to_le_bytes());
        info[8..12].copy_from_slice(&crate::mqueue::SI_MESGQ.to_le_bytes());
        info[16..20].copy_from_slice(&entry.space.number(sender).to_le_bytes());
        info[20..24].copy_from_slice(&uid.to_le_bytes());
        info[24..32].copy_from_slice(&value.to_le_bytes());
        let signal = signals::PendingSignal {
            queued: Some(info),
            ..signals::PendingSignal::user(number, crate::mqueue::SI_MESGQ)
        };
        let _ = self.send(&mut entries, pid, None, signal);
    }
    /// The CPU time of the children `pid` has waited for.
    pub(crate) fn children_cpu(&self, pid: u32) -> u64 {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map_or(0, |entry| entry.children_cpu)
    }
    /// The parent, process group, session, waited-for children's CPU time
    /// and RLIMIT_RSS soft limit of `pid`, for `/proc/<pid>/stat`.
    pub(crate) fn stat_of(&self, pid: u32) -> (u32, u32, u32, u64, u64) {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map_or((0, 0, 0, 0, u64::MAX), |entry| {
            (
                entry.parent,
                entry.pgid,
                entry.sid,
                entry.children_cpu,
                entry.limits[5].0,
            )
        })
    }
    /// What `/proc/self/status` shows of `pid`: its parent, its
    /// RLIMIT_SIGPENDING soft limit and PR_SET_NO_NEW_PRIVS.
    pub(crate) fn status_of(&self, pid: u32) -> (u32, u64, bool) {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map_or((0, 4096, false), |entry| {
            (entry.parent, entry.limits[11].0, entry.no_new_privs)
        })
    }
    /// The live process that thread `tid` is in.
    pub(crate) fn thread_leader(&self, tid: u32) -> Option<u32> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .find(|(_, entry)| entry.status.is_none() && entry.group.has_member(tid))
            .map(|(&pid, _)| pid)
    }
    /// The processes there are, zombies too, in order, as `/proc` lists them.
    pub(crate) fn pids(&self) -> Vec<u32> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.keys().copied().collect()
    }
    /// What `/proc/<pid>` shows of a process other than the reader, or
    /// `None` when there is no such process.
    pub(crate) fn view(&self, pid: u32) -> Option<ProcessView> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid)?;
        Some(ProcessView {
            parent: entry.parent,
            group_id: entry.pgid,
            session: entry.sid,
            children_cpu: entry.children_cpu,
            rss_limit: entry.limits[5].0,
            queue_limit: entry.limits[11].0,
            no_new_privs: entry.no_new_privs,
            dumpable: entry.dumpable,
            zombie: entry.status.is_some(),
            exit_signal: entry.exit_signal,
            group: Arc::clone(&entry.group),
            terminal: entry.terminal.clone(),
            space: Arc::clone(&entry.space),
        })
    }
    fn parent(&self, pid: u32) -> u32 {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&pid)
            .map_or(0, |entry| entry.parent)
    }
    /// The token a wait for a child sleeps on ([`Self::changed`]'s field).
    pub(crate) fn changed(&self) -> &WaitToken {
        &self.changed
    }
    pub(crate) fn remove(&self, pid: u32) {
        Self::release(
            &mut self.entries.lock().unwrap_or_else(PoisonError::into_inner),
            pid,
        );
    }
    pub(crate) fn locks(&self) -> &crate::record_locks::Locks {
        &self.locks
    }
    pub(crate) fn fifos(&self) -> Arc<crate::fifo::Fifos> {
        Arc::clone(&self.fifos)
    }
    /// The soft limit of `resource` of process `pid`, or infinity for a
    /// process that is gone.
    pub(crate) fn soft_limit(&self, pid: u32, resource: usize) -> u64 {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&pid)
            .and_then(|entry| entry.limits().get(resource).copied())
            .map_or(u64::MAX, |(soft, _)| soft)
    }
    pub(crate) fn finish(&self, pid: u32, status: ExitStatus) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            if entry.group.active_threads() != 0 {
                return;
            }
            entry.status = Some(entry.group.status().unwrap_or(status));
        } else {
            return;
        }
        // A session leader's exit, as Linux's disassociate_ctty(1): the
        // foreground group of its pseudo-terminal gets SIGHUP, and the
        // session loses the terminal.
        if let Some(terminal) = entries
            .get(&pid)
            .filter(|entry| entry.sid == pid)
            .and_then(|entry| entry.terminal.clone())
        {
            Self::disassociate(&mut entries, pid, &terminal, false);
        }
        // The init of a PID namespace (the first process is the emulator's):
        // when it exits, every other process the namespace numbers gets
        // SIGKILL from the kernel, and no process may join a nested one any
        // more, as in Linux's zap_pid_ns_processes.
        let space = entries.get(&pid).map(|entry| entry.space.clone());
        let zapped = space.filter(|space| space.init() == Some(pid));
        if let Some(space) = &zapped {
            if !space.is_first() {
                space.close();
            }
            let live: Vec<u32> = entries
                .iter()
                .filter(|&(&other, entry)| {
                    other != pid && entry.status.is_none() && entry.space.is_within(space)
                })
                .map(|(&other, _)| other)
                .collect();
            for other in live {
                let _ = Self::deliver(&mut entries, other, None, Self::from_kernel(9));
            }
        }
        // Children that asked for it learn that this process exited.
        let parent_ids = entries.get(&pid).map(|p| p.group.task_ids(pid, pid));
        let parent_session = entries.get(&pid).map(|p| p.sid);
        let same_session = |child: &Entry| Some(child.sid) == parent_session;
        for (&child_pid, child) in entries.iter() {
            if child.parent == pid && child.status.is_none() && child.death_signal != 0 {
                // Linux sends it as the exiting parent, as with `kill`.
                let sender = parent_ids.clone().unwrap_or_default();
                let target = child.group.task_ids(child_pid, child_pid);
                if (sender.may_signal(&target)
                    || (child.death_signal == SIGCONT && same_session(child)))
                    && !crate::landlock::scoped(
                        &sender.landlock,
                        &target.landlock,
                        crate::landlock::SCOPE_SIGNAL,
                    )
                {
                    // From outside the child's PID namespace it is forced;
                    // the init of one drops what it has no handler for.
                    let from = child.space.number(pid);
                    let blocked = child.group.blocked(child_pid);
                    if !child
                        .group
                        .drops_as_init(child.death_signal, from == 0, blocked)
                    {
                        let _ = child
                            .group
                            .send_process_from(child.death_signal, from, sender.uid);
                    }
                }
            }
        }
        // As Linux's forget_original_parent: the children go to the nearest
        // live ancestor that is a child subreaper, else to the first
        // process, with SIGCHLD as their exit signal, and one that has
        // already exited is reported to its new parent. Then, as
        // kill_orphaned_pgrp, a child's group this exit orphans is told.
        let reaper = Self::new_reaper(&entries, pid);
        let orphans: Vec<u32> = entries
            .iter()
            .filter(|(_, entry)| entry.parent == pid)
            .map(|(&orphan, _)| orphan)
            .collect();
        for orphan in orphans {
            let mut reaped = false;
            if let Some(reaper) = reaper {
                if let Some(entry) = entries.get_mut(&orphan) {
                    entry.parent = reaper;
                    entry.exit_signal = signals::SIGCHLD;
                }
                reaped = entries
                    .get(&orphan)
                    .is_some_and(|entry| entry.status.is_some())
                    && Self::notify_parent(&entries, orphan);
            }
            // The exiting init of a nested PID namespace reaps a child that
            // has already exited itself, as zap_pid_ns_processes does.
            reaped |= zapped.as_ref().is_some_and(|space| !space.is_first())
                && entries
                    .get(&orphan)
                    .is_some_and(|entry| entry.status.is_some());
            // As reparent_leader, also for a zombie reaped just now.
            Self::hang_up_orphaned(&mut entries, orphan, pid);
            if reaped {
                Self::release(&mut entries, orphan);
            }
        }
        Self::hang_up_orphaned(&mut entries, pid, pid);
        if let Some(space) = zapped.filter(|space| !space.is_first())
            && Self::populated(&entries, &space, pid)
        {
            if let Some(entry) = entries.get_mut(&pid) {
                entry.held = true;
            }
        } else if Self::notify_parent(&entries, pid) {
            Self::release(&mut entries, pid);
        }
        self.changed.notify();
    }
    /// Whether a process other than `init` is in PID namespace `space` or
    /// one nested in it.
    fn populated(entries: &BTreeMap<u32, Entry>, space: &Namespace, init: u32) -> bool {
        entries
            .iter()
            .any(|(&other, entry)| other != init && entry.space.is_within(space))
    }
    /// Removes process `pid`, which is reaped, and forgets its numbers, as
    /// Linux's `release_task`. The init of a nested PID namespace that
    /// waited for it to be gone now tells its parent.
    fn release(entries: &mut BTreeMap<u32, Entry>, pid: u32) {
        let Some(entry) = entries.remove(&pid) else {
            return;
        };
        entry.space.leave(pid);
        let held: Vec<u32> = entries
            .iter()
            .filter(|&(&init, other)| {
                other.held
                    && entry.space.is_within(&other.space)
                    && !Self::populated(entries, &other.space, init)
            })
            .map(|(&init, _)| init)
            .collect();
        for init in held {
            if let Some(other) = entries.get_mut(&init) {
                other.held = false;
            }
            if Self::notify_parent(entries, init) {
                Self::release(entries, init);
            }
        }
    }
    /// As Linux's kill_orphaned_pgrp, after `exiting` has exited: if `pid`
    /// (`exiting` itself or one of its children) was in a group that `exiting`
    /// or its parent linked to its session, the exit orphans that group, and
    /// a member of it is stopped, every member gets SIGHUP and then SIGCONT
    /// from the kernel, so a stopped job does not stay stopped for good.
    fn hang_up_orphaned(entries: &mut BTreeMap<u32, Entry>, pid: u32, exiting: u32) {
        let Some(entry) = entries.get(&pid) else {
            return;
        };
        let (pgid, sid) = (entry.pgid, entry.sid);
        let link = if pid == exiting {
            entry.parent
        } else {
            exiting
        };
        let linked = entries
            .get(&link)
            .is_none_or(|parent| parent.pgid != pgid && parent.sid == sid);
        let ignored = (pid == exiting).then_some(pid);
        let members = || entries.iter().filter(move |(_, e)| e.pgid == pgid);
        let orphaned = members()
            .filter(|&(&member, e)| Some(member) != ignored && e.status.is_none())
            .all(|(_, e)| !Self::links_group(entries, e));
        let stopped = members().any(|(_, e)| e.status.is_none() && e.group.is_stopped());
        if !(linked && orphaned && stopped) {
            return;
        }
        // A zombie member would ignore them, as on Linux.
        let group: Vec<u32> = members()
            .filter(|(_, e)| e.status.is_none())
            .map(|(&member, _)| member)
            .collect();
        for number in [1, 18] {
            for &member in &group {
                let _ = Self::deliver(entries, member, None, Self::from_kernel(number));
            }
        }
    }
    /// Whether the parent of `entry` keeps its group from being orphaned
    /// (will_become_orphaned_pgrp): a live process in another group of the
    /// same session. The first process's parent is outside the emulator and
    /// counts as one, as the shell that started it would; an exited parent,
    /// which only the first process can be, does not.
    fn links_group(entries: &BTreeMap<u32, Entry>, entry: &Entry) -> bool {
        entries.get(&entry.parent).is_none_or(|parent| {
            parent.status.is_none() && parent.pgid != entry.pgid && parent.sid == entry.sid
        })
    }
    /// Who adopts the children of `pid`: the nearest ancestor that set
    /// PR_SET_CHILD_SUBREAPER and has not exited, else the first process,
    /// which acts as the init of a PID namespace. None when that is `pid`
    /// itself or has exited.
    fn new_reaper(entries: &BTreeMap<u32, Entry>, pid: u32) -> Option<u32> {
        let space = &entries.get(&pid)?.space;
        let mut ancestor = entries.get(&pid)?.parent;
        // As find_new_reaper, only within the PID namespace.
        while let Some(entry) = entries.get(&ancestor)
            && Arc::ptr_eq(&entry.space, space)
        {
            if entry.subreaper && entry.status.is_none() {
                return Some(ancestor);
            }
            ancestor = entry.parent;
        }
        // The init of a nested namespace takes them even once it has
        // exited, and reaps them, as zap_pid_ns_processes does.
        let init = space.init().filter(|&init| init != pid)?;
        entries
            .get(&init)
            .filter(|entry| !space.is_first() || entry.status.is_none())
            .map(|_| init)
    }
    /// Tells the parent of `pid`, which has exited, as Linux's
    /// do_notify_parent: a SIGCHLD child of a parent that ignores SIGCHLD or
    /// set SA_NOCLDWAIT is to be reaped at once (true), and with SIGCHLD
    /// ignored the parent gets no signal. A child reaped this way does not
    /// add its CPU time to the parent's children's, as in Linux, where only a
    /// wait adds it.
    fn notify_parent(entries: &BTreeMap<u32, Entry>, pid: u32) -> bool {
        let Some(entry) = entries.get(&pid) else {
            return false;
        };
        let (Some(status), Some(parent)) = (entry.status, entries.get(&entry.parent)) else {
            return false;
        };
        // The exited init of a nested PID namespace reaps its children.
        if parent.status.is_some()
            && !parent.space.is_first()
            && parent.space.init() == Some(entry.parent)
        {
            return true;
        }
        let (ignored, no_wait) = parent.group.child_exit_disposition();
        let reap = entry.exit_signal == signals::SIGCHLD && (ignored || no_wait);
        let (code, status) = match status {
            ExitStatus::Signaled(signal) if entry.dumped => (signals::CLD_DUMPED, signal),
            ExitStatus::Signaled(signal) => (signals::CLD_KILLED, signal),
            ExitStatus::Exited(code) => (signals::CLD_EXITED, code & 255),
            _ => (signals::CLD_EXITED, 0),
        };
        if !(reap && ignored) {
            let cpu = entry.group.process_cpu();
            parent.group.notify_child(
                code,
                signals::ChildSignal {
                    pid: parent.space.number(pid),
                    uid: entry.group.task_ids(pid, pid).uid,
                    status,
                    cpu,
                },
            );
        }
        reap
    }
    pub fn active_threads(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|entry| entry.group.active_threads())
            .sum()
    }
    pub fn stop_all(&self, status: ExitStatus) {
        for entry in self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            entry.group.stop(status);
        }
    }
    /// The first child of `parent`, in PID order, that `wanted` selects and
    /// that has an event `wait` asks for, as Linux's `do_wait` looks: an
    /// exit (removing the child), else an unreported stop, else an
    /// unreported continue. With `keep` (WNOWAIT) nothing is consumed.
    /// `ECHILD` when no child can be waited for: as in `do_wait`, an exited
    /// child counts only with WEXITED or WCONTINUED. The child is given as
    /// the waiter's PID namespace `space` numbers it.
    pub(crate) fn reap(
        &self,
        parent: u32,
        space: &Namespace,
        wanted: Wanted,
        wait: WaitFor,
    ) -> Result<Option<(u32, ChildEvent, u64, u32)>, Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let matching = |pid: u32, entry: &Entry| {
            entry.parent == parent
                && match wanted {
                    Wanted::Any => true,
                    Wanted::Pid(wanted) => pid == wanted,
                    Wanted::Pgid(pgid) => entry.pgid == pgid,
                }
        };
        if !entries.iter().any(|(&pid, entry)| {
            matching(pid, entry) && (entry.status.is_none() || wait.exits || wait.continues)
        }) {
            return Err(Errno(10));
        }
        let ready = entries.iter().find_map(|(&pid, entry)| {
            if !matching(pid, entry) {
                return None;
            }
            // A held init has not finished exiting yet.
            if entry.held {
                return None;
            }
            let event = match entry.status {
                Some(ExitStatus::Signaled(signal)) if entry.dumped => {
                    wait.exits.then_some(ChildEvent::Dumped(signal))
                }
                Some(status) => wait.exits.then_some(ChildEvent::Exited(status)),
                None => match entry.stop_report {
                    Some(signal) if wait.stops => Some(ChildEvent::Stopped(signal)),
                    _ => (wait.continues && entry.continue_report).then_some(ChildEvent::Continued),
                },
            }?;
            let cpu = entry.group.process_cpu().saturating_add(entry.children_cpu);
            Some((pid, event, cpu, entry.group.task_ids(pid, pid).uid))
        });
        let number = ready.map(|(pid, ..)| space.number(pid));
        if let Some((pid, event, cpu, _)) = ready
            && !wait.keep
        {
            match event {
                // A reaped child's CPU time joins its parent's children's.
                ChildEvent::Exited(_) | ChildEvent::Dumped(_) => {
                    Self::release(&mut entries, pid);
                    if let Some(parent) = entries.get_mut(&parent) {
                        parent.children_cpu = parent.children_cpu.saturating_add(cpu);
                    }
                }
                ChildEvent::Stopped(_) => {
                    if let Some(entry) = entries.get_mut(&pid) {
                        entry.stop_report = None;
                    }
                }
                ChildEvent::Continued => {
                    if let Some(entry) = entries.get_mut(&pid) {
                        entry.continue_report = false;
                    }
                }
            }
        }
        Ok(ready
            .zip(number)
            .map(|((_, event, cpu, uid), number)| (number, event, cpu, uid)))
    }
    /// Stops `group` (process `pid`) on `signal`. A new group stop is
    /// recorded for the parent's wait, and the parent gets SIGCHLD unless it
    /// ignores it or asked for SA_NOCLDSTOP. Under the table's lock, so a
    /// SIGCONT from [`Self::signal`] comes wholly before or after it.
    pub(crate) fn job_stop(&self, pid: u32, group: &ThreadGroup, signal: i32) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !group.job_stop() {
            return;
        }
        let Some(entry) = entries.get_mut(&pid) else {
            return;
        };
        entry.stop_report = Some(signal);
        entry.continue_report = false;
        self.changed.notify();
        let parent = entry.parent;
        let child = signals::ChildSignal {
            pid,
            uid: group.task_ids(pid, pid).uid,
            status: signal,
            cpu: group.process_cpu(),
        };
        if let Some(parent) = entries.get(&parent)
            && parent.group.wants_stop_notices()
        {
            let pid = parent.space.number(pid);
            parent
                .group
                .notify_child(signals::CLD_STOPPED, signals::ChildSignal { pid, ..child });
        }
    }
    /// Whether a live process other than `pid` runs in `space` (`CLONE_VM`
    /// without `CLONE_THREAD`), as Linux's `current_is_single_threaded`
    /// looks for one.
    pub(crate) fn shares_memory(&self, pid: u32, space: &AddressSpace) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.iter().any(|(&other, entry)| {
            other != pid && entry.status.is_none() && entry.group.uses_memory(space)
        })
    }
    /// The thread group of the live thread named by its ID, in any process,
    /// as `find_task_by_vpid` finds it.
    /// The bandwidth every live deadline thread takes, but thread `tid` of
    /// `group`.
    fn deadline_bandwidth(&self, group: &Arc<ThreadGroup>, tid: u32) -> u64 {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .values()
            .filter(|entry| entry.status.is_none())
            .map(|entry| {
                let except = Arc::ptr_eq(&entry.group, group).then_some(tid);
                entry.group.deadline_bandwidth(except)
            })
            .sum()
    }
    pub(crate) fn group_of(&self, named: u32) -> Option<Arc<ThreadGroup>> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .find(|&(&key, entry)| {
                entry.status.is_none() && (key == named || entry.group.has_member(named))
            })
            .map(|(_, entry)| Arc::clone(&entry.group))
    }
    /// What another thread named by its ID looks like to the thread acting
    /// on it, as `kill` finds it.
    pub(crate) fn task_ids(&self, named: u32) -> Option<TaskIds> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (&pid, entry) = entries.iter().find(|&(&key, entry)| {
            key == named || (entry.status.is_none() && entry.group.has_member(named))
        })?;
        Some(entry.group.task_ids(pid, named))
    }
    /// The RLIMIT_CORE soft limit of `pid` when a fatal signal may dump its
    /// core: the process is dumpable and the limit is at least one page.
    pub(crate) fn core_limit(&self, pid: u32) -> Option<u64> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid)?;
        let limit = entry.limits[4].0;
        (entry.dumpable && limit >= crate::coredump::MIN_LIMIT).then_some(limit)
    }
    /// Who `pid` is, for its core, whose leader has the IDs `leader`.
    pub(crate) fn core_identity(
        &self,
        pid: u32,
        leader: crate::credentials::TaskIds,
        cpu: u64,
        start_stack: u64,
    ) -> Option<crate::coredump::Identity> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid)?;
        Some(crate::coredump::Identity {
            pid,
            ppid: entry.parent,
            pgrp: entry.pgid,
            sid: entry.sid,
            // As its own user namespace shows them (`fill_psinfo`).
            uid: leader.user.shown(crate::users::Ids::User, leader.uid),
            gid: leader.user.shown(crate::users::Ids::Group, leader.gid),
            cpu,
            children_cpu: entry.children_cpu,
            start_stack,
            space: entry.space.clone(),
        })
    }
    pub(crate) fn set_dumped(&self, pid: u32) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            entry.dumped = true;
        }
    }
    /// Whether `pid` has exited: `None` once it is reaped (or never was).
    fn exited(&self, pid: u32) -> Option<bool> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map(|entry| entry.status.is_some())
    }
    /// Whether `process_mrelease` finds the memory of process `pid` on its
    /// way to be freed, as Linux's `task_will_free_mem` does: it is dying
    /// ([`ThreadGroup::will_free_memory`]), and so is every other live
    /// process that runs in its memory. `None` once it has exited, as a
    /// zombie keeps no memory for Linux's `find_lock_task_mm` to find, or
    /// is reaped (or never was).
    fn will_free_memory(&self, pid: u32) -> Option<bool> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid).filter(|entry| entry.status.is_none())?;
        if !entry.group.will_free_memory() {
            return Some(false);
        }
        let spaces = entry.group.memory_identities();
        Some(entries.iter().all(|(&other, sharer)| {
            other == pid
                || sharer.status.is_some()
                || sharer.group.will_free_memory()
                || !sharer
                    .group
                    .memory_identities()
                    .iter()
                    .any(|space| spaces.contains(space))
        }))
    }
    /// What `pidfd_open` finds at `pid`: a process (`Ok`), a thread of one
    /// (`ENOENT`) or nothing (`ESRCH`).
    fn pidfd_target(&self, pid: u32) -> Result<(), Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.contains_key(&pid) {
            Ok(())
        } else if entries.values().any(|entry| entry.group.has_member(pid)) {
            Err(Errno::ENOENT)
        } else {
            Err(Errno(3))
        }
    }
    /// `kill(target, number)` from `caller`, in PID namespace `space`, as
    /// Linux's kill_something_info: a positive target is that process (or
    /// the process of that thread), 0 the caller's process group, -1 every
    /// process the namespace numbers but its init and the caller, and any
    /// other negative target the group `-target`, the IDs as the namespace
    /// numbers them. Zombies count until they are reaped. With no process
    /// to send to it is `ESRCH`, even for an invalid signal; otherwise a
    /// group succeeds if any member took the signal, and -1 reports the
    /// last error.
    fn kill(
        &self,
        caller: u32,
        space: &Namespace,
        sender: TaskIds,
        target: i32,
        number: i32,
    ) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // The processes, with the thread each is named by, whose credentials
        // decide: Linux signals a thread group through the task it finds.
        let pids: Vec<(u32, u32)> = match target {
            // A thread's ID names its process, as Linux finds the task and
            // signals its thread group.
            pid if pid > 0 => {
                let pid = Kernel::named(space, pid.cast_unsigned());
                entries
                    .iter()
                    .find(|&(&key, entry)| {
                        key == pid || (entry.status.is_none() && entry.group.has_member(pid))
                    })
                    .map(|(&key, _)| (key, pid))
                    .into_iter()
                    .collect()
            }
            -1 => entries
                .iter()
                .filter(|&(&pid, entry)| {
                    pid != caller && entry.space.is_within(space) && space.number(pid) > 1
                })
                .map(|(&pid, _)| (pid, pid))
                .collect(),
            i32::MIN => Vec::new(),
            group => {
                let pgid = if group == 0 {
                    entries.get(&caller).ok_or(Errno(3))?.pgid
                } else {
                    Kernel::named(space, group.unsigned_abs())
                };
                entries
                    .iter()
                    .filter(|(_, entry)| entry.pgid == pgid)
                    .map(|(&pid, _)| (pid, pid))
                    .collect()
            }
        };
        if pids.is_empty() {
            return Err(Errno(3));
        }
        let signal = Self::from_process(number, caller, sender.uid);
        let (mut last, mut delivered) = (Ok(()), false);
        for (pid, named) in pids {
            let result = Self::check_kill(&entries, caller, &sender, pid, named, number)
                .and_then(|()| self.send(&mut entries, pid, None, signal));
            delivered |= result.is_ok();
            // -1 does not report a process it may not signal, so with only
            // those it succeeds, as Linux's `kill_something_info`.
            if target != -1 || result != Err(Errno::EPERM) {
                last = result;
            }
        }
        if delivered && target != -1 {
            Ok(())
        } else {
            last
        }
    }
    /// Linux's `check_kill_permission` of `number` from a thread of `caller`
    /// to process `pid` through its thread `named`: an invalid signal is left
    /// for delivery to refuse (EINVAL first), its own process may always be
    /// signalled, and SIGCONT may also be sent within the session. Then a
    /// Landlock domain that scopes signals keeps the sender from a thread
    /// outside it (`hook_task_kill`, `EPERM`).
    fn check_kill(
        entries: &BTreeMap<u32, Entry>,
        caller: u32,
        sender: &TaskIds,
        pid: u32,
        named: u32,
        number: i32,
    ) -> Result<(), Errno> {
        if !(0..=64).contains(&number) || pid == caller {
            return Ok(());
        }
        let entry = entries.get(&pid).ok_or(Errno(3))?;
        let session = entries.get(&caller).map(|c| c.sid);
        let target = entry.group.task_ids(pid, named);
        if (sender.may_signal(&target) || (number == SIGCONT && session == Some(entry.sid)))
            && !crate::landlock::scoped(
                &sender.landlock,
                &target.landlock,
                crate::landlock::SCOPE_SIGNAL,
            )
        {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    }
    /// The processes (and, for a thread owner, the thread) `owner` names:
    /// a thread, a process (or the process of one of its threads), or a
    /// process group.
    fn owned_by(entries: &BTreeMap<u32, Entry>, owner: FileOwner) -> Vec<(u32, Option<u32>)> {
        let id = owner.id;
        entries
            .iter()
            .filter_map(|(&pid, entry)| {
                let member = entry.status.is_none() && entry.group.has_member(id);
                match owner.kind {
                    OwnerKind::Thread => member.then_some((pid, Some(id))),
                    OwnerKind::Process => (pid == id || member).then_some((pid, None)),
                    OwnerKind::Group => (entry.pgid == id).then_some((pid, None)),
                }
            })
            .collect()
    }
    /// Whether anything is there in the role `owner` names it in: a thread,
    /// a process or a member of a group (Linux's `pid_task`).
    pub(crate) fn owner_present(&self, owner: FileOwner) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        !Self::owned_by(&entries, owner).is_empty()
    }
    /// Whether `owner`'s ID is in use, as Linux's `f_setown` and
    /// `SCM_CREDENTIALS` find it with `find_vpid` (ESRCH otherwise): a
    /// thread, or a process, group or session, whatever kind of owner it is.
    pub(crate) fn owner_exists(&self, owner: FileOwner) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let id = owner.id;
        !Self::owned_by(&entries, owner).is_empty()
            || entries
                .iter()
                .any(|(&pid, entry)| pid == id || entry.pgid == id || entry.sid == id)
    }
    fn send_owner(&self, owner: FileOwner, signal: signals::PendingSignal) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        for (pid, thread) in Self::owned_by(&entries, owner) {
            let _ = self.send(&mut entries, pid, thread, signal);
        }
    }
    /// Sends SIGURG from the kernel to `owner`, as a socket's out-of-band
    /// byte does.
    pub(crate) fn send_urgent(&self, owner: FileOwner) {
        self.send_owner(owner, Self::from_kernel(23));
    }
    /// Sends `owner` the signal of an `O_ASYNC` file, registered through
    /// descriptor `fd`, as Linux's `send_sigio`: SIGIO from the kernel, or
    /// with `F_SETSIG` that signal with `si_code`, `si_band` and `si_fd`. A
    /// `Priority` change sends only the latter, SIGURG telling the rest.
    pub(crate) fn send_io(&self, owner: FileOwner, fd: i32, reason: Reason) {
        if owner.id == 0 {
            return;
        }
        let signal = match owner.signal {
            0 if reason == Reason::Priority => return,
            0 => Self::from_kernel(29),
            number => signals::PendingSignal {
                queued: Some(crate::fasync::siginfo(number, fd, reason)),
                ..signals::PendingSignal::user(number, reason as i32)
            },
        };
        self.send_owner(owner, signal);
    }
    /// The owner `F_SETOWN` gave `file`, which is not a pipe or a socket.
    pub(crate) fn file_owner(&self, file: &Arc<dyn FileHandle>) -> FileOwner {
        self.file_owners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(file)
    }
    pub(crate) fn set_file_owner(&self, file: &Arc<dyn FileHandle>, owner: FileOwner) {
        self.file_owners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(file, owner);
    }
    /// Whether `pidfd_send_signal` from `caller` may signal process `pid`.
    fn may_signal(&self, caller: u32, sender: TaskIds, pid: u32, number: i32) -> Result<(), Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Self::check_kill(&entries, caller, &sender, pid, pid, number)
    }
    fn signal(&self, caller: u32, uid: u32, pid: u32, number: i32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        self.send(
            &mut entries,
            pid,
            None,
            Self::from_process(number, caller, uid),
        )
    }
    /// `rt_sigqueueinfo` of `signal` to `pid`, which a thread's ID also
    /// names, as `kill` finds it.
    fn queue(
        &self,
        caller: u32,
        sender: TaskIds,
        pid: u32,
        signal: signals::PendingSignal,
    ) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let found = entries
            .iter()
            .find(|&(&key, entry)| {
                key == pid || (entry.status.is_none() && entry.group.has_member(pid))
            })
            .map(|(&key, _)| key)
            .ok_or(Errno(3))?;
        Self::check_kill(&entries, caller, &sender, found, pid, signal.number)?;
        // The sender only decides whether the receiver sees it (`deliver`).
        let signal = signals::PendingSignal {
            sender: Some(caller),
            ..signal
        };
        self.send(&mut entries, found, None, signal)
    }
    /// `rt_tgsigqueueinfo` of `signal` to thread `tid` of process `tgid`.
    fn queue_thread(
        &self,
        caller: u32,
        sender: TaskIds,
        tgid: u32,
        tid: u32,
        signal: signals::PendingSignal,
    ) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !entries
            .get(&tgid)
            .is_some_and(|entry| entry.group.has_member(tid))
        {
            return Err(Errno(3));
        }
        Self::check_kill(&entries, caller, &sender, tgid, tid, signal.number)?;
        let signal = signals::PendingSignal {
            sender: Some(caller),
            ..signal
        };
        self.send(&mut entries, tgid, Some(tid), signal)
    }
    /// [`Self::deliver`] for a process's `kill` or queued signal, which wakes
    /// the waits for a child: the signal may interrupt one, or, a SIGCONT,
    /// resume a stopped child.
    fn send(
        &self,
        entries: &mut BTreeMap<u32, Entry>,
        pid: u32,
        thread: Option<u32>,
        signal: signals::PendingSignal,
    ) -> Result<(), Errno> {
        let result = Self::deliver(entries, pid, thread, signal);
        self.changed.notify();
        result
    }
    /// A signal the kernel sends itself (`SI_KERNEL`).
    fn from_kernel(number: i32) -> signals::PendingSignal {
        signals::PendingSignal::user(number, signals::SI_KERNEL)
    }
    /// A signal process `sender`, of real user ID `uid`, sends with `kill`
    /// (`SI_USER`).
    fn from_process(number: i32, sender: u32, uid: u32) -> signals::PendingSignal {
        signals::PendingSignal {
            sender: Some(sender),
            sender_uid: Some(uid),
            ..signals::PendingSignal::user(number, 0)
        }
    }
    /// Sends `signal` to `pid`, or to its thread `thread`.
    fn deliver(
        entries: &mut BTreeMap<u32, Entry>,
        pid: u32,
        thread: Option<u32>,
        signal: signals::PendingSignal,
    ) -> Result<(), Errno> {
        let number = signal.number;
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        if number == 0 {
            return Ok(());
        }
        // `si_pid` is the sender as the receiver's PID namespace numbers it,
        // 0 from outside it, as Linux's `send_signal_locked` gives it; a
        // signal from outside, or from the kernel, is forced.
        let mut signal = signal;
        let mut forced = signal.code == signals::SI_KERNEL;
        if let Some(sender) = signal.sender {
            let number = entry.space.number(sender);
            forced |= number == 0;
            signal.sender = Some(number);
            // A queued siginfo keeps its own `si_pid`, but not from outside.
            if number == 0
                && let Some(queued) = signal.queued.as_mut()
            {
                queued[16..20].fill(0);
            }
        }
        // The init of a nested PID namespace drops what it has no handler
        // for, as the receiving thread (the leader for its process) blocks
        // it or not; a signal it blocked it drops when it takes it.
        let blocked = entry.group.blocked(thread.unwrap_or(pid));
        if (1..=64).contains(&number) && entry.group.drops_as_init(number, forced, blocked) {
            return Ok(());
        }
        let send = |group: &ThreadGroup| match thread {
            Some(tid) => group.send_thread_signal(tid, signal),
            None => group.send_process_signal(signal),
        };
        // SIGCONT resumes a stopped process at once, as Linux's
        // prepare_signal does, and its parent's wait can see that.
        if number == 18 && entry.status.is_none() && entry.group.is_stopped() {
            send(&entry.group)?;
            entry.group.job_continue();
            entry.stop_report = None;
            entry.continue_report = true;
            let parent = entry.parent;
            let child = signals::ChildSignal {
                pid,
                uid: entry.group.task_ids(pid, pid).uid,
                status: 18,
                cpu: entry.group.process_cpu(),
            };
            if let Some(parent) = entries.get(&parent)
                && parent.group.wants_stop_notices()
            {
                let pid = parent.space.number(pid);
                parent.group.notify_child(
                    signals::CLD_CONTINUED,
                    signals::ChildSignal { pid, ..child },
                );
            }
            return Ok(());
        }
        send(&entry.group)?;
        // SIGKILL ends the whole process from the moment it is sent, as
        // Linux's complete_signal marks it.
        if number == 9 {
            entry.group.set_killed();
        }
        Ok(())
    }
}

/// What a wait reports, and whether it consumes it (see [`Processes::reap`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WaitFor {
    pub keep: bool,
    pub exits: bool,
    pub stops: bool,
    pub continues: bool,
}
/// A child's event a wait reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildEvent {
    Exited(ExitStatus),
    /// Ended by this signal after writing a core.
    Dumped(i32),
    Stopped(i32),
    Continued,
}

/// Which children a wait looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wanted {
    Any,
    Pid(u32),
    Pgid(u32),
}

/// No task's ID: what a number a PID namespace has not handed out names.
pub(crate) const NOBODY: u32 = u32::MAX;
const WNOHANG: u64 = 1;
const WEXITED: u64 = 4;
const WNOWAIT: u64 = 0x0100_0000;
const PIDFD_NONBLOCK: u64 = 0x800;
const PIDFD_THREAD: u64 = 0x80;
/// `O_CLOEXEC`, which a pidfd from `open_by_handle_at` keeps in its flags.
const O_CLOEXEC: u32 = 0o2000000;

/// A pidfd (`pidfd_open`): readable once its process has exited, and hung
/// up once that process is reaped, as Linux's `pidfd_poll` reports. It is
/// only a handle; reading or writing it is `EINVAL`.
pub(crate) struct PidFd {
    pid: u32,
    processes: Arc<Processes>,
    flags: AtomicU32,
}
impl PidFd {
    /// A close-on-exec pidfd of process `pid` (ESRCH when it is gone), as
    /// the kernel's `pidfd_prepare` makes for `SCM_PIDFD` and
    /// `SO_PEERPIDFD`.
    pub(crate) fn of(processes: &Arc<Processes>, pid: u32) -> Result<Arc<Self>, Errno> {
        processes.pidfd_target(pid)?;
        Ok(Arc::new(Self {
            pid,
            processes: Arc::clone(processes),
            flags: AtomicU32::new(2),
        }))
    }
    /// The pidfd `open_by_handle_at` makes from a pidfs handle naming inode
    /// `inode`, as Linux's `pidfs_fh_to_dentry` finds its `struct pid`
    /// ([`PidFd::inode`]) and `pidfs_export_open` opens it: `ESTALE` once the
    /// process is reaped or for one the caller's PID namespace `space` does
    /// not number. It is always opened for reading and writing, with the
    /// access asked for added, and keeps `O_NONBLOCK` and `O_CLOEXEC` of
    /// `flags` (Linux 7.0's `pidfs_export_open`, which gives them to
    /// `dentry_open`; `O_EXCL`, `PIDFD_THREAD`, goes, which Linux 7.2 and
    /// later keep).
    pub(crate) fn by_inode(
        processes: &Arc<Processes>,
        space: &Namespace,
        inode: u64,
        flags: u32,
    ) -> Result<Arc<Self>, Errno> {
        let pid = u32::try_from(inode).map_err(|_| crate::files::ESTALE)?;
        if processes.exited(pid).is_none() || space.number(pid) == 0 {
            return Err(crate::files::ESTALE);
        }
        Ok(Arc::new(Self {
            pid,
            processes: Arc::clone(processes),
            flags: AtomicU32::new(2 | flags & (3 | PIDFD_NONBLOCK as u32 | O_CLOEXEC)),
        }))
    }
    /// The pidfs inode of its process, which `fstat` gives as `st_ino` and
    /// its file handle holds: Linux numbers each `struct pid` once, from a
    /// counter, and IDs here are never handed out twice, so the process's
    /// ID does.
    pub(crate) fn inode(&self) -> u64 {
        u64::from(self.pid)
    }
}
impl paludarium_host::FileHandle for PidFd {
    /// The same process's pidfd as a new open file description, as root
    /// opens one through `/proc/self/fd` (Linux's pidfs gives it no `open`
    /// of its own): the access it is opened with and `O_NONBLOCK` of its
    /// own, even once the process is gone.
    fn reopen(&self, flags: u32) -> Result<Arc<dyn paludarium_host::FileHandle>, Errno> {
        Ok(Arc::new(Self {
            pid: self.pid,
            processes: Arc::clone(&self.processes),
            flags: AtomicU32::new(flags & (3 | PIDFD_NONBLOCK as u32)),
        }))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        // POLLIN | POLLRDNORM after the exit, with POLLHUP after the reaping;
        // a child reaped automatically has both from its exit, as in Linux's
        // pidfd_poll once the task is gone.
        Ok(match self.processes.exited(self.pid) {
            Some(false) => (0, 0, 0),
            Some(true) => (0x41, 1, 0),
            None => (0x51, 2, 0),
        })
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<paludarium_host::FileStat, Errno> {
        // pidfs's inode: root's 0700, with its file type hidden as Linux's
        // anon_inode_getattr hides it, numbered for the process.
        Ok(paludarium_host::FileStat {
            mode: 0o700,
            links: 1,
            inode: self.inode(),
            ..paludarium_host::FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        // The access stays what it was opened with, and so do
        // `PIDFD_THREAD` and `O_CLOEXEC`, which `F_SETFL` cannot change.
        let kept = self.flags.load(Ordering::SeqCst) & (3 | PIDFD_THREAD as u32 | O_CLOEXEC);
        self.flags
            .store(kept | flags & PIDFD_NONBLOCK as u32, Ordering::SeqCst);
        Ok(())
    }
}

impl Kernel {
    #[must_use]
    pub fn processes(&self) -> Arc<Processes> {
        self.processes.clone()
    }
    pub fn take_spawn_memory(&mut self) -> Option<Arc<AddressSpace>> {
        self.spawn_memory.take()
    }
    pub fn take_exec_memory(&mut self) -> Option<Arc<AddressSpace>> {
        self.exec_memory.take()
    }
    /// Ends an exec once the caller let go of the image it replaced: the
    /// scripts it ran close after that image's files, as the `fput`s Linux
    /// defers run newest first, the old `mm`'s after the scripts'.
    pub fn exec_finished(&mut self) {
        drop(self.exec_closes.take());
    }
    pub fn complete_process(&self, status: ExitStatus) {
        self.processes.finish(self.process.pid, status);
        if self.group.active_threads() == 0 {
            self.release_vfork();
        }
    }
    fn release_vfork(&self) {
        if let Some(release) = &self.vfork_release {
            release.store(true, Ordering::SeqCst);
            self.processes.changed().notify();
        }
    }
    pub fn abandon_child(&mut self, pid: u32, tid: u32) {
        if pid == self.process.pid {
            self.abandon_thread(tid);
        } else {
            self.processes.remove(pid);
        }
        if let Some(release) = self.vfork_wait.take() {
            release.store(true, Ordering::SeqCst);
            self.processes.changed().notify();
        }
    }
    pub fn wait_vfork(&mut self, kill: &AtomicBool) -> Result<(), Errno> {
        let Some(release) = self.vfork_wait.take() else {
            return Ok(());
        };
        loop {
            let ticket = self.processes.changed().value();
            if release.load(Ordering::SeqCst) || self.group.status().is_some() {
                return Ok(());
            }
            if kill.load(Ordering::SeqCst) {
                self.processes.stop_all(ExitStatus::Signaled(9));
                return Err(Errno(4));
            }
            self.wait_for_children(ticket)?;
        }
    }
    /// Sleeps until a process changes or is sent a signal after `ticket`
    /// was taken from [`Processes::changed`], or at most 10 ms pass, as the
    /// thread's wake token (any other signal) is polled; a host without
    /// tickets waits out the time.
    fn wait_for_children(&self, ticket: u32) -> Result<(), Errno> {
        let end = self
            .host
            .clock(ClockId::Monotonic)?
            .saturating_add(10_000_000);
        let deadline = Some((ClockId::Monotonic, end));
        match self.host.wait_on(
            self.processes.changed(),
            ticket,
            deadline,
            &self.cancellation,
        ) {
            Err(error) if error == Errno::ENOSYS => self
                .host
                .wait_until(ClockId::Monotonic, end, &self.cancellation)
                .map(drop),
            result => result.map(drop),
        }
    }
    pub(crate) fn process_syscall(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        n: u64,
        a: [u64; 6],
    ) -> Option<Next> {
        let result = match n {
            56 if a[0] & 0x10000 == 0 => self.clone_process(thread, mem, a),
            57 => self.clone_process(thread, mem, [17, 0, 0, 0, 0, 0]),
            58 => self.clone_process(thread, mem, [0x4111, 0, 0, 0, 0, 0]),
            59 | 322 => match self.exec(thread, mem, n, a) {
                Ok(closed) => {
                    self.close_on_exec(thread, mem, closed);
                    return Some(Next::Resume);
                }
                Err(error) => Err(error),
            },
            61 => self.wait4(thread, mem, a),
            247 => self.waitid(thread, mem, a),
            434 => self.pidfd_open(thread, a),
            424 => self.pidfd_send_signal(thread, a),
            312 => self.kcmp(thread, mem, a),
            274 => self.get_robust_list(thread, mem, a),
            310 | 311 => self.process_vm(thread, mem, a, n == 311),
            438 => self.pidfd_getfd(thread, a),
            440 => self.process_madvise(thread, mem, a),
            448 => self.process_mrelease(a),
            256 => self.migrate_pages(thread, mem, a),
            279 => self.move_pages(thread, mem, a),
            129 => self.sigqueueinfo(thread, mem, a),
            297 => self.tgsigqueueinfo(thread, mem, a),
            // The IDs these give are as the caller's PID namespace numbers
            // them: 0 for a process outside it.
            110 => Ok(u64::from(
                self.pid_space(thread.tid)
                    .number(self.processes.parent(self.process.pid)),
            )),
            157 => self.prctl(thread, mem, a),
            // setpgid, getpgid, getpgrp
            109 => self.setpgid(thread, a),
            121 => self
                .target_pid(thread.tid, a[0])
                .and_then(|pid| self.processes.pgid(pid))
                .map(|id| u64::from(self.pid_space(thread.tid).number(id))),
            111 => self
                .processes
                .pgid(self.process.pid)
                .map(|id| u64::from(self.pid_space(thread.tid).number(id))),
            // setsid, getsid
            112 => self
                .processes
                .set_sid(self.process.pid)
                .map(|id| u64::from(self.pid_space(thread.tid).number(id))),
            124 => self
                .target_pid(thread.tid, a[0])
                .and_then(|pid| self.processes.sid(pid))
                .map(|id| u64::from(self.pid_space(thread.tid).number(id))),
            // getpriority, setpriority
            140 => self.getpriority(thread, a),
            141 => self.setpriority(thread, a),
            252 => self.ioprio_get(thread, a),
            251 => self.ioprio_set(thread, a),
            // sched_setparam, sched_setscheduler, sched_setattr
            142 => self.sched_setscheduler(thread, mem, a[0], None, a[1]),
            144 => match a[1] as i32 {
                policy if policy < 0 => Err(Errno::EINVAL),
                policy => self.sched_setscheduler(thread, mem, a[0], Some(policy as u32), a[2]),
            },
            314 => self.sched_setattr(thread, mem, a),
            272 => self.unshare(thread, mem, a[0]),
            308 => self.setns(thread, mem, a),
            // prlimit64, getrlimit, setrlimit
            302 => self.prlimit(thread, mem, a[0], a[1], a[2], a[3]),
            97 => self.prlimit(thread, mem, 0, a[0], 0, a[1]),
            160 => self.prlimit(thread, mem, 0, a[0], a[1], 0),
            62 => self
                .processes
                .kill(
                    self.process.pid,
                    &self.pid_space(thread.tid),
                    thread.state.credentials.task_ids(),
                    a[0] as i32,
                    a[1] as i32,
                )
                .map(|()| 0),
            _ => return None,
        };
        thread.cpu.gpr[reg::RAX] = result.unwrap_or_else(Errno::to_syscall_return);
        Some(self.checkpoint(thread, mem))
    }
    /// A pid argument of thread `tid`: 0 is the caller, another its PID
    /// namespace's number of a task; anything that is not a pid is ESRCH.
    fn target_pid(&self, tid: u32, value: u64) -> Result<u32, Errno> {
        match value as u32 as i32 {
            0 => Ok(self.process.pid),
            pid if pid > 0 => Ok(Self::named(&self.pid_space(tid), pid as u32)),
            _ => Err(Errno(3)),
        }
    }
    /// The `who` of `getpriority` and the others for `which`, as the
    /// caller's PID namespace numbers it: a thread or a process group.
    fn priority_who(&self, tid: u32, which: i32, who: i32) -> i32 {
        if matches!(which, 0 | 1) && who > 0 {
            Self::named(&self.pid_space(tid), who.cast_unsigned()).cast_signed()
        } else {
            who
        }
    }
    /// `prctl(option, ...)`: PR_SET/GET_NAME and PR_SET/GET_KEEPCAPS (per thread),
    /// PR_SET/GET_PDEATHSIG, PR_SET/GET_DUMPABLE, PR_SET/GET_CHILD_SUBREAPER
    /// and PR_SET/GET_NO_NEW_PRIVS; any other option is EINVAL, as Linux
    /// gives for options it does not know.
    fn prctl(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        match a[0] {
            // PR_SET_NAME: up to 15 bytes, ending at a NUL; the rest of the
            // name is cleared.
            15 => {
                let mut name = [0; 16];
                for (i, byte) in name.iter_mut().take(15).enumerate() {
                    let mut b = [0];
                    mem.read(GuestAddr(a[1].wrapping_add(i as u64)), &mut b)
                        .map_err(|_| Errno::EFAULT)?;
                    if b[0] == 0 {
                        break;
                    }
                    *byte = b[0];
                }
                thread.state.name = name;
                return Ok(0);
            }
            // PR_GET_NAME: all 16 bytes.
            16 => {
                mem.write(GuestAddr(a[1]), &thread.state.name)
                    .map_err(|_| Errno::EFAULT)?;
                return Ok(0);
            }
            // PR_GET_KEEPCAPS, PR_SET_KEEPCAPS (0 or 1), kept per thread with
            // its credentials.
            7 => return Ok(u64::from(thread.state.credentials.keep_caps)),
            8 if a[1] <= 1 => {
                thread.state.credentials.keep_caps = a[1] == 1;
                return Ok(0);
            }
            8 => return Err(Errno::EINVAL),
            // PR_GET_SECCOMP, PR_SET_SECCOMP
            21 => return Ok(crate::seccomp::mode(&thread.state)),
            22 => {
                return crate::seccomp::prctl_set(
                    &mut crate::seccomp::Caller {
                        state: &mut thread.state,
                        tid: thread.tid,
                        mem,
                        group: &self.group,
                        processes: &self.processes,
                        files: None,
                    },
                    a[1],
                    a[2],
                );
            }
            _ => {}
        }
        match self.processes.prctl(self.process.pid, a[0], a)? {
            Some(value) if a[0] == 2 || a[0] == 37 => {
                mem.write(GuestAddr(a[1]), &value.to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
                Ok(0)
            }
            Some(value) => Ok(value as u32 as u64),
            None => Ok(0),
        }
    }
    /// `getpriority(which, who)`: the highest priority among the threads,
    /// as `20 - nice` (1 to 40), or ESRCH when there are none.
    fn getpriority(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let threads = self.processes.priority_threads(
            a[0] as i32,
            self.priority_who(thread.tid, a[0] as i32, a[1] as i32),
            self.process.pid,
            thread.tid,
            thread.state.credentials.uid,
        )?;
        threads
            .iter()
            .map(|found| (20 - found.nice) as u64)
            .max()
            .ok_or(Errno(3))
    }
    /// `ioprio_get(which, who)`: the I/O priority of a thread
    /// (`IOPRIO_WHO_PROCESS`), or the best of a process group's threads
    /// (`IOPRIO_WHO_PGRP`) or of a user's (`IOPRIO_WHO_USER`), found as
    /// `getpriority` finds them, as Linux's `ioprio_best` compares them. A
    /// thread reports the priority it was given, or 0
    /// ([`scheduling::reported_ioprio`]).
    /// None found is `ESRCH`.
    fn ioprio_get(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let which = match a[0] as i32 {
            which @ 1..=3 => which - 1,
            _ => return Err(Errno::EINVAL),
        };
        let threads = self.processes.priority_threads(
            which,
            self.priority_who(thread.tid, which, a[1] as i32),
            self.process.pid,
            thread.tid,
            thread.state.credentials.uid,
        )?;
        threads
            .iter()
            .map(|found| scheduling::reported_ioprio(&found.group.sched(found.tid)))
            .reduce(scheduling::best_ioprio)
            .map(u64::from)
            .ok_or(Errno(3))
    }
    /// `ioprio_set(which, who, ioprio)`, as Linux's: the priority is checked
    /// first (`ioprio_check_cap`), then each thread found as `ioprio_get`
    /// finds them is given it in turn, stopping at the first the caller may
    /// not change (`EPERM`: its real user ID is not the caller's real or
    /// effective one, and the caller lacks CAP_SYS_NICE). The priority is
    /// kept and reported, and a new thread or process keeps one with a class.
    fn ioprio_set(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let ioprio = a[2] as i32;
        let caller = thread.state.credentials.task_ids();
        scheduling::check_ioprio(
            ioprio,
            caller.capable(crate::credentials::CAP_SYS_NICE)
                || thread.state.credentials.may_administer(),
        )?;
        let which = match a[0] as i32 {
            which @ 1..=3 => which - 1,
            _ => return Err(Errno::EINVAL),
        };
        let threads = self.processes.priority_threads(
            which,
            self.priority_who(thread.tid, which, a[1] as i32),
            self.process.pid,
            thread.tid,
            caller.uid,
        )?;
        let mut result = Err(Errno(3));
        for found in threads {
            if found.ids.uid != caller.euid
                && found.ids.uid != caller.uid
                && !caller.capable(crate::credentials::CAP_SYS_NICE)
            {
                return Err(Errno::EPERM);
            }
            let mut sched = found.group.sched(found.tid);
            sched.io = Some(ioprio as u16);
            // set_task_ioprio gives a thread without an I/O context one.
            if sched.io_context == 0 {
                sched.io_context = scheduling::new_io_context();
            }
            found.group.set_sched(found.tid, sched);
            result = Ok(0);
        }
        result
    }
    /// The thread `pid` names for the `sched_set*` calls: 0 is the caller.
    fn sched_thread(&self, thread: &Thread, pid: i32) -> Result<PriorityThread, Errno> {
        self.processes
            .priority_threads(
                0,
                self.priority_who(thread.tid, 0, pid),
                self.process.pid,
                thread.tid,
                thread.state.credentials.uid,
            )?
            .into_iter()
            .next()
            .ok_or(Errno(3))
    }
    /// `sched_setscheduler(pid, policy, param)` and, with no policy,
    /// `sched_setparam(pid, param)`, as Linux's `do_sched_setscheduler`: a
    /// NULL `param` or a negative `pid` is `EINVAL`, then the parameter is
    /// read (`EFAULT`) and the thread found (`ESRCH`). `SCHED_RESET_ON_FORK`
    /// in the policy is the flag; the nice value stays.
    fn sched_setscheduler(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        pid: u64,
        policy: Option<u32>,
        param: u64,
    ) -> Result<u64, Errno> {
        let pid = pid as u32 as i32;
        if param == 0 || pid < 0 {
            return Err(Errno::EINVAL);
        }
        let mut priority = [0u8; 4];
        mem.read(GuestAddr(param), &mut priority)
            .map_err(|_| Errno::EFAULT)?;
        let target = self.sched_thread(thread, pid)?;
        let mut attr = scheduling::Attr {
            policy,
            priority: u32::from_le_bytes(priority),
            nice: target.nice,
            ..scheduling::Attr::default()
        };
        if let Some(policy) = policy
            && policy & scheduling::SCHED_RESET_ON_FORK != 0
        {
            attr.flags |= scheduling::FLAG_RESET_ON_FORK;
            attr.policy = Some(policy & !scheduling::SCHED_RESET_ON_FORK);
        }
        self.apply_sched(thread, &target, &attr)
    }
    /// `sched_setattr(pid, attr, flags)`, as Linux's: `EINVAL` for a NULL
    /// `attr`, a negative `pid` or any flag; `struct sched_attr` read as
    /// `sched_copy_attr` reads it (a size of 0 is 48; one below 48, above a
    /// page or with nonzero bytes past the 56 known is `E2BIG`, with 56
    /// written as the size; the clamps need all 56 bytes); a negative policy
    /// is `EINVAL`; `SCHED_FLAG_KEEP_POLICY` and `SCHED_FLAG_KEEP_PARAMS`
    /// keep the thread's.
    fn sched_setattr(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let (pid, address, flags) = (a[0] as u32 as i32, a[1], a[2] as u32);
        if address == 0 || pid < 0 || flags != 0 {
            return Err(Errno::EINVAL);
        }
        let mut word = [0u8; 4];
        mem.read(GuestAddr(address), &mut word)
            .map_err(|_| Errno::EFAULT)?;
        let size = match u32::from_le_bytes(word) {
            0 => 48,
            size => size,
        };
        let too_big = || {
            let _ = mem.write(GuestAddr(address), &56u32.to_le_bytes());
            Err(Errno(7)) // E2BIG
        };
        if !(48..=4096).contains(&size) {
            return too_big();
        }
        let mut bytes = vec![0u8; size as usize];
        mem.read(GuestAddr(address), &mut bytes)
            .map_err(|_| Errno::EFAULT)?;
        if bytes.iter().skip(56).any(|&b| b != 0) {
            return too_big();
        }
        bytes.resize(56, 0);
        let u32_at =
            |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or_default());
        let u64_at =
            |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default());
        let sched_flags = u64_at(8);
        if sched_flags & (scheduling::FLAG_UTIL_CLAMP_MIN | scheduling::FLAG_UTIL_CLAMP_MAX) != 0
            && size < 56
        {
            return Err(Errno::EINVAL);
        }
        let policy = u32_at(4);
        if (policy as i32) < 0 {
            return Err(Errno::EINVAL);
        }
        let mut attr = scheduling::Attr {
            policy: (sched_flags & scheduling::FLAG_KEEP_POLICY == 0).then_some(policy),
            flags: sched_flags,
            nice: (u32_at(16) as i32).clamp(-20, 19),
            priority: u32_at(20),
            runtime: u64_at(24),
            deadline: u64_at(32),
            period: u64_at(40),
            util_min: u32_at(48),
            util_max: u32_at(52),
        };
        let target = self.sched_thread(thread, pid)?;
        if sched_flags & scheduling::FLAG_KEEP_PARAMS != 0 {
            // get_params.
            let current = target.group.sched(target.tid);
            if current.deadline_policy() {
                attr.priority = current.priority;
                attr.runtime = current.runtime;
                attr.deadline = current.deadline;
                attr.period = current.period;
                attr.flags = attr.flags & !0x1000_0006 | current.dl_flags;
            } else if scheduling::rt_policy(current.policy) {
                attr.priority = current.priority;
            } else {
                attr.nice = target.nice;
                attr.runtime = current
                    .slice
                    .unwrap_or_else(|| crate::syscalls::scheduler_slice(&*self.host).slice);
            }
        }
        self.apply_sched(thread, &target, &attr)
    }
    /// Decides and makes a change of scheduling attributes
    /// ([`scheduling::set`]), with the deadline capacity of Linux 6.12: 95%
    /// of each CPU (`sched_rt_runtime_us`), less the 5% its fair server
    /// takes.
    fn apply_sched(
        &self,
        thread: &Thread,
        target: &PriorityThread,
        attr: &scheduling::Attr,
    ) -> Result<u64, Errno> {
        let caller = thread.state.credentials.task_ids();
        let cpus = self.host.cpu_count().clamp(1, 8192);
        let every_cpu = target.group.affinity(target.tid).is_none_or(|mask| {
            (0..cpus).all(|cpu| {
                mask.get(cpu / 64)
                    .is_some_and(|word| word >> (cpu % 64) & 1 != 0)
            })
        });
        let decided = scheduling::Target {
            sched: target.group.sched(target.tid),
            nice: target.nice,
            nice_limit: target.nice_limit,
            rtprio_limit: target.rtprio_limit,
            same_owner: caller.euid == target.ids.euid || caller.euid == target.ids.uid,
            every_cpu,
            base_slice: crate::syscalls::scheduler_slice(&*self.host).slice,
        };
        let per_cpu = scheduling::ratio(1_000_000_000, 950_000_000)
            - scheduling::ratio(1_000_000_000, 50_000_000);
        let change = scheduling::set(
            &decided,
            attr,
            caller.capable(crate::credentials::CAP_SYS_NICE),
            self.processes.deadline_bandwidth(&target.group, target.tid),
            per_cpu * cpus as u64,
        )?;
        target.group.set_sched(target.tid, change.sched);
        if let Some(nice) = change.nice {
            target.group.update_nice(target.tid, nice);
        }
        Ok(0)
    }
    /// `unshare(flags)`, as Linux's `ksys_unshare` with its checks in order.
    /// `CLONE_FILES` and `CLONE_FS` give the thread its own descriptor table
    /// and its own working directory and umask; `CLONE_THREAD`,
    /// `CLONE_SIGHAND` and `CLONE_VM` succeed where there is nothing to
    /// unshare (one thread, dispositions and memory no other process shares)
    /// and are `EINVAL` otherwise, as Linux has them. `CLONE_SYSVSEM` and
    /// `CLONE_NEWIPC` leave the semaphore undo list, as an exit does
    /// (`exit_sem`). A namespace flag gives the thread a new namespace of
    /// that kind ([`crate::namespaces::check`] has which).
    fn unshare(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        flags: u64,
    ) -> Result<u64, Errno> {
        const VM: u64 = 0x100;
        const FS: u64 = 0x200;
        const FILES: u64 = 0x400;
        const SIGHAND: u64 = 0x800;
        const THREAD: u64 = 0x1_0000;
        const NEWNS: u64 = crate::namespaces::CLONE_NEWNS;
        const SYSVSEM: u64 = 0x4_0000;
        const NEWUSER: u64 = crate::namespaces::CLONE_NEWUSER;
        const NAMESPACES: u64 = crate::namespaces::ALL;
        let mut flags = flags;
        if flags & NEWUSER != 0 {
            flags |= THREAD | FS;
        }
        if flags & VM != 0 {
            flags |= SIGHAND;
        }
        if flags & SIGHAND != 0 {
            flags |= THREAD;
        }
        if flags & NEWNS != 0 {
            flags |= FS;
        }
        // check_unshare_flags.
        if flags & !(THREAD | FS | NEWNS | SIGHAND | VM | FILES | SYSVSEM | NEWUSER | NAMESPACES)
            != 0
        {
            return Err(Errno::EINVAL);
        }
        if flags & (THREAD | SIGHAND | VM) != 0 && self.group.active_threads() > 1 {
            return Err(Errno::EINVAL);
        }
        if flags & (SIGHAND | VM) != 0 && self.group.shares_actions() {
            return Err(Errno::EINVAL);
        }
        if flags & VM != 0 && self.processes.shares_memory(self.process.pid, mem) {
            return Err(Errno::EINVAL);
        }
        // unshare_userns, then unshare_nsproxy_namespaces with the
        // credentials it gave.
        let own = self.group.namespaces(thread.tid);
        let msgqueue = self.processes.soft_limit(self.process.pid, 12);
        let credentials =
            crate::namespaces::user_for(&own, &thread.state.credentials, flags, msgqueue)?;
        crate::namespaces::check(flags, credentials.administers_own())?;
        if flags & NAMESPACES != 0 {
            let mut namespaces = own.unshared(flags, &credentials.user.0)?;
            namespaces.user = Arc::clone(&credentials.user.0);
            if flags & crate::namespaces::CLONE_NEWIPC != 0 {
                namespaces.ipc.mq.made_by(
                    credentials.fsuid,
                    credentials.fsgid,
                    self.host.clock(ClockId::Realtime).unwrap_or(0),
                );
            }
            self.group.set_namespaces(thread.tid, namespaces);
        }
        if credentials != thread.state.credentials {
            self.group.set_task_ids(thread.tid, credentials.task_ids());
            thread.state.credentials = credentials;
        }
        if flags & FILES != 0 {
            self.files = self.files.unshared(flags & FS == 0);
        } else if flags & FS != 0 {
            self.files = self.files.for_clone(true, false);
        }
        if flags & (SYSVSEM | crate::namespaces::CLONE_NEWIPC) != 0 {
            self.group
                .leave_sem_undo_list(thread.tid, self.process.pid, self.wall_seconds());
        }
        Ok(0)
    }
    /// `setpriority(which, who, nice)`: sets the nice value of every thread
    /// the caller may change to `nice`, cut to -20..19, as Linux's
    /// `set_one_prio`. Going lower needs CAP_SYS_NICE or room in the thread's
    /// RLIMIT_NICE. A refusal is reported though other threads changed, the
    /// last one when there are several.
    fn setpriority(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let sender = thread.state.credentials.task_ids();
        let threads = self.processes.priority_threads(
            a[0] as i32,
            self.priority_who(thread.tid, a[0] as i32, a[1] as i32),
            self.process.pid,
            thread.tid,
            sender.uid,
        )?;
        let nice = (a[2] as i32).clamp(-20, 19);
        let mut result = Err(Errno(3));
        for found in threads {
            if !sender.may_set_priority(&found.ids) {
                result = Err(Errno::EPERM);
            } else if nice < found.nice
                && (20 - nice) as u64 > found.nice_limit
                && !sender.capable(crate::credentials::CAP_SYS_NICE)
            {
                result = Err(Errno::EACCES);
            } else {
                found.group.update_nice(found.tid, nice);
                if result == Err(Errno(3)) {
                    result = Ok(0);
                }
            }
        }
        result
    }
    fn setpgid(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let pgid = a[1] as u32 as i32;
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let pid = self.target_pid(thread.tid, a[0])?;
        let pgid = if pgid == 0 {
            pid
        } else {
            Self::named(&self.pid_space(thread.tid), pgid as u32)
        };
        self.processes
            .set_pgid(self.process.pid, pid, pgid)
            .map(|()| 0)
    }
    fn prlimit(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        pid: u64,
        resource: u64,
        new: u64,
        old: u64,
    ) -> Result<u64, Errno> {
        // Linux's order: read the new limit, find the process, check and set
        // the limit, and only then write the old one out.
        let new = if new == 0 {
            None
        } else {
            let soft = mem.read_u64(GuestAddr(new)).map_err(|_| Errno::EFAULT)?;
            let hard = mem
                .read_u64(GuestAddr(new + 8))
                .map_err(|_| Errno::EFAULT)?;
            Some((soft, hard))
        };
        let named = self.target_pid(thread.tid, pid)?;
        let own = pid as u32 == 0 || named == thread.tid;
        let resource = usize::try_from(resource as u32).map_err(|_| Errno::EINVAL)?;
        let sender = thread.state.credentials.task_ids();
        let (soft, hard) = self.processes.limit(sender, own, named, resource, new)?;
        if old != 0 {
            mem.write_u64(GuestAddr(old), soft)
                .map_err(|_| Errno::EFAULT)?;
            mem.write_u64(GuestAddr(old + 8), hard)
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(0)
    }
    /// `setns(fd, nstype)`, as Linux's: `fd` is a namespace file of
    /// `/proc/<pid>/ns`, whose kind `nstype` names or is 0, or a pidfd and
    /// the namespaces of its process to enter (`EINVAL` for none or another
    /// flag). Each is checked in Linux's order (`validate_nsset`) before
    /// any is entered: a user namespace must not be the thread's own, nor be
    /// entered by a thread sharing its memory or working directory
    /// (`EINVAL`), and needs CAP_SYS_ADMIN in it (`EPERM`), which then gives
    /// the thread every capability there, for the checks after it; a mount
    /// namespace needs CAP_SYS_ADMIN and CAP_SYS_CHROOT, and a working
    /// directory no other thread shares when it is all that is entered; a
    /// time namespace a thread alone in its memory (`EUSERS`); every one
    /// CAP_SYS_ADMIN over it, in the user namespace that owns it, and in
    /// the thread's own (`EPERM`); a PID namespace is the thread's own or
    /// one nested in it (`EINVAL`). Entering a mount namespace moves the
    /// working directory to its root; a PID namespace is the one children
    /// take, and a time namespace is the thread's and its children's.
    fn setns(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        use crate::namespaces::{self as ns, Kind};
        const CAP_SYS_CHROOT: u64 = 1 << 18;
        const CAP_SYS_PTRACE: u64 = 1 << 19;
        let flags = a[1];
        let d = self.files.descriptor(a[0])?;
        let any = d.file.as_any();
        let (flags, theirs) =
            if let Some(file) = any.and_then(|v| v.downcast_ref::<ns::NamespaceFile>()) {
                let kind = file.namespace.kind.flag();
                if flags != 0 && flags != kind {
                    return Err(Errno::EINVAL);
                }
                (kind, Err(file.namespace.clone()))
            } else if let Some(pidfd) = any.and_then(|v| v.downcast_ref::<PidFd>()) {
                if flags == 0 || flags & !ns::ALL != 0 {
                    return Err(Errno::EINVAL);
                }
                let view = self
                    .processes
                    .view(pidfd.pid)
                    .filter(|view| !view.zombie)
                    .ok_or(Errno(3))?; // ESRCH
                // ptrace_may_access with the real IDs.
                let reader = &thread.state.credentials;
                let target = view.group.task_ids(pidfd.pid, pidfd.pid);
                if pidfd.pid != self.process.pid
                    && !reader.capable_in(CAP_SYS_PTRACE, &target.user)
                    && !(view.dumpable
                        && [target.uid, target.euid, target.suid] == [reader.uid; 3]
                        && [target.gid, target.egid, target.sgid] == [reader.gid; 3])
                {
                    return Err(Errno::EPERM);
                }
                (flags, Ok(view.group.namespaces(pidfd.pid)))
            } else {
                return Err(Errno::EINVAL);
            };
        let namespace = |kind: Kind| match &theirs {
            Err(one) => one.clone(),
            Ok(all) => match kind {
                Kind::Net => all.net.clone(),
                Kind::Uts => all.uts.clone(),
                Kind::Ipc => all.ipc.clone(),
                Kind::Pid => all.pid.clone(),
                Kind::User => all.user.clone(),
                Kind::Mnt => all.mnt.clone(),
                Kind::Cgroup => all.cgroup.clone(),
                Kind::Time => all.time.clone(),
            },
        };
        let mut credentials = thread.state.credentials.clone();
        let order = [
            Kind::User,
            Kind::Mnt,
            Kind::Uts,
            Kind::Ipc,
            Kind::Pid,
            Kind::Cgroup,
            Kind::Net,
            Kind::Time,
        ];
        let entered: Vec<Kind> = order
            .into_iter()
            .filter(|kind| flags & kind.flag() != 0)
            .collect();
        for &kind in &entered {
            let target = namespace(kind);
            let admin = credentials.capable_in(crate::credentials::CAP_SYS_ADMIN, target.owner())
                && credentials.administers_own();
            match kind {
                // userns_install.
                Kind::User => {
                    if Arc::ptr_eq(&target, &credentials.user.0)
                        || self.group.active_threads() > 1
                        || self.processes.shares_memory(self.process.pid, mem)
                        || self.files.shares_fs()
                    {
                        return Err(Errno::EINVAL);
                    }
                    if !credentials.capable_in(crate::credentials::CAP_SYS_ADMIN, &target) {
                        return Err(Errno::EPERM);
                    }
                    credentials = crate::credentials::Credentials {
                        user: crate::users::UserNs(Arc::clone(&target)),
                        permitted: crate::credentials::ALL_CAPABILITIES,
                        effective: crate::credentials::ALL_CAPABILITIES,
                        inheritable: 0,
                        keep_caps: false,
                        ..credentials
                    };
                }
                Kind::Mnt if !admin || credentials.effective & CAP_SYS_CHROOT == 0 => {
                    return Err(Errno::EPERM);
                }
                // With more than the mount namespace, Linux enters it with
                // a copy of the working directory, which it then gives the
                // shared one.
                Kind::Mnt if flags == ns::CLONE_NEWNS && self.files.shares_fs() => {
                    return Err(Errno::EINVAL);
                }
                Kind::Time
                    if self.group.active_threads() > 1
                        || self.processes.shares_memory(self.process.pid, mem) =>
                {
                    return Err(Errno(87)); // EUSERS
                }
                _ if !admin => return Err(Errno::EPERM),
                // pidns_install: only the thread's own PID namespace or one
                // nested in it, so that its children stay within it.
                Kind::Pid if !target.is_within(&self.pid_space(thread.tid)) => {
                    return Err(Errno::EINVAL);
                }
                _ => {}
            }
        }
        let mut mine = (*self.group.namespaces(thread.tid)).clone();
        for kind in entered {
            let new = namespace(kind);
            match kind {
                Kind::Net => mine.net = new,
                Kind::Uts => mine.uts = new,
                // ipcns_install leaves the semaphore undo list (`exit_sem`).
                Kind::Ipc => {
                    mine.ipc = new;
                    self.group.leave_sem_undo_list(
                        thread.tid,
                        self.process.pid,
                        self.wall_seconds(),
                    );
                }
                Kind::Pid => mine.pid_for_children = new,
                Kind::User => mine.user = new,
                Kind::Mnt => {
                    mine.mnt = new;
                    self.files.enter_root();
                }
                Kind::Cgroup => mine.cgroup = new,
                Kind::Time => {
                    mine.time = new.clone();
                    mine.time_for_children = new;
                }
            }
        }
        self.group.set_namespaces(thread.tid, mine);
        if credentials != thread.state.credentials {
            self.group.set_task_ids(thread.tid, credentials.task_ids());
            thread.state.credentials = credentials;
        }
        Ok(0)
    }
    fn clone_process(
        &mut self,
        parent: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let flags = a[0];
        let known = 0xff
            | 0x100
            | 0x200
            | 0x400
            | 0x800
            | 0x4000
            | 0x40000
            | 0x80000
            | 0x100000
            | 0x200000
            | 0x400000
            | 0x1000000
            | CLONE_CLEAR_SIGHAND
            | crate::namespaces::ALL & !crate::namespaces::CLONE_NEWTIME
            | crate::namespaces::CLONE3_NEWTIME;
        // A new mount or user namespace needs a new working directory and
        // root, which CLONE_FS would share.
        let namespaces = namespace_flags(flags);
        if flags & 0x200 != 0
            && namespaces & (crate::namespaces::CLONE_NEWNS | crate::namespaces::CLONE_NEWUSER) != 0
        {
            return Err(Errno::EINVAL);
        }
        if flags & 0x800 != 0 && flags & 0x100 == 0 || flags & 0xff > 64 {
            return Err(Errno::EINVAL);
        }
        if flags & !known != 0 {
            return Err(Errno::EINVAL);
        }
        if a[1] >= paludarium_types::USER_ADDRESS_LIMIT
            || flags & 0x80000 != 0 && a[4] >= paludarium_types::USER_ADDRESS_LIMIT
        {
            return Err(Errno::EPERM);
        }
        // sched_fork: a deadline task's child is EAGAIN.
        let (sched, reset_nice) = self
            .group
            .sched(parent.tid)
            .forked(self.group.nice(parent.tid).unwrap_or(0))?;
        let task = self.processes.charge_task()?;
        // copy_namespaces; CLONE_NEWIPC leaves the semaphore undo list,
        // which CLONE_SYSVSEM would share.
        // copy_creds first, whose new user namespace the others are in.
        let own = self.group.namespaces(parent.tid);
        let msgqueue = self.processes.soft_limit(self.process.pid, 12);
        let credentials =
            crate::namespaces::user_for(&own, &parent.state.credentials, namespaces, msgqueue)?;
        crate::namespaces::check(namespaces, credentials.administers_own())?;
        if namespaces & crate::namespaces::CLONE_NEWIPC != 0 && flags & 0x40000 != 0 {
            return Err(Errno::EINVAL);
        }
        let mut child_namespaces =
            own.for_child(namespaces, flags & 0x100 != 0, &credentials.user.0)?;
        child_namespaces.user = Arc::clone(&credentials.user.0);
        if namespaces & crate::namespaces::CLONE_NEWIPC != 0 {
            child_namespaces.ipc.mq.made_by(
                credentials.fsuid,
                credentials.fsgid,
                self.host.clock(ClockId::Realtime).unwrap_or(0),
            );
        }
        let child_mem = if flags & 0x100 == 0 {
            Some(Arc::new(mem.fork()))
        } else {
            None
        };
        // Numbered in the PID namespace children take, and those it is in.
        let space = child_namespaces.pid.clone();
        let set_tid = std::mem::take(&mut self.set_tid);
        let pid = self
            .processes
            .allocate_in(&space, &set_tid, &parent.state.credentials)?;
        let group = Arc::new(self.group.fork(flags & 0x800 != 0));
        if !space.is_first() && space.init() == Some(pid) {
            group.set_unkillable();
        }
        // CLONE_CLEAR_SIGHAND resets handled signals to their default and
        // keeps ignored ones, as execve does.
        if flags & CLONE_CLEAR_SIGHAND != 0 {
            group.exec_actions();
        }
        let inbox = Arc::new(SignalInbox::default());
        group.set_process_inbox(inbox.clone());
        if let Some(value) = self.group.nice(parent.tid) {
            group.set_nice(pid, if reset_nice { 0 } else { value });
        }
        group.set_sched(pid, sched);
        if let Some(mask) = self.group.affinity(parent.tid) {
            group.set_affinity(pid, mask);
        }
        self.group
            .numa()
            .new_process(group.numa(), parent.tid, pid, flags & 0x100 != 0);
        self.group
            .aio()
            .new_process(group.aio(), child_mem.as_deref(), group.numa());
        group.register(pid, inbox.clone());
        // copy_semundo: CLONE_SYSVSEM shares the undo list, which the
        // parent is given first if it has none.
        if flags & 0x40000 != 0 {
            group.set_sem_undo_list(pid, self.group.sem_undo_list(parent.tid).share());
        }
        let mut state = parent.state.clone();
        state.credentials = credentials.clone();
        state.pid = pid;
        state.pending.clear();
        // Nothing has come for the new task yet, which its group counts.
        state.arrivals = 0;
        state.frames.clear();
        state.exit_status = None;
        state.timer = signals::RealTimer::default();
        // A new process has taken no `LANDLOCK_RESTRICT_SELF_TSYNC` of its own.
        state.credentials.landlock_sync = 0;
        // Nor any `SECCOMP_FILTER_FLAG_TSYNC`; it starts with the parent's
        // seccomp state as it is now.
        state.seccomp = self
            .group
            .seccomp_of_state(parent.tid, &parent.state.seccomp);
        state.seccomp_sync = 0;
        // The child is a user of its filters until it ends.
        if state.seccomp.mode != 0 {
            group.seccomp_threads().insert(pid, state.seccomp.clone());
        }
        state.clear_child_tid = if flags & 0x200000 != 0 { a[3] } else { 0 };
        if flags & 0x100 != 0 {
            state.alt_stack = crate::AltStack::default();
            // A child sharing the memory registers its own rseq area, as
            // Linux's rseq_fork gives a CLONE_VM child none.
            state.rseq = None;
            state.rseq_notify = false;
        }
        state.on_cpu = None;
        if flags & CLONE_CLEAR_SIGHAND != 0 {
            state.signal_actions.retain(|_, action| action.handler == 1);
        }
        let mut cpu = parent.cpu.clone();
        cpu.gpr[reg::RAX] = 0;
        if a[1] != 0 {
            cpu.gpr[reg::RSP] = a[1];
        }
        if flags & 0x80000 != 0 {
            cpu.fs_base = a[4];
        }
        // The parent's word has the child as the parent's PID namespace
        // numbers it, which `clone` returns; the child's, as its own does.
        let number = self.pid_space(parent.tid).number(pid);
        if flags & 0x100000 != 0 {
            let _ = mem.write(GuestAddr(a[2]), &number.to_le_bytes());
        }
        if flags & 0x1000000 != 0 {
            let _ = child_mem
                .as_deref()
                .unwrap_or(mem)
                .write(GuestAddr(a[3]), &space.number(pid).to_le_bytes());
        }
        let release = (flags & 0x4000 != 0).then(|| Arc::new(AtomicBool::new(false)));
        group.set_task_ids(pid, credentials.task_ids());
        group.set_namespaces(pid, child_namespaces);
        self.processes.insert(
            pid,
            self.process.pid,
            group.clone(),
            (flags & 0xff) as i32,
            task,
            space,
        );
        let mut child = Kernel {
            host: self.host.clone(),
            process: crate::Process { pid },
            table: crate::SyscallTable::u1(),
            files: self.files.for_clone(flags & 0x400 != 0, flags & 0x200 != 0),
            cancellation: inbox.wake_token(),
            inbox,
            group,
            processes: self.processes.clone(),
            pending_child: None,
            spawn_memory: child_mem,
            exec_memory: None,
            exec_closes: None,
            vfork_release: release.clone(),
            vfork_wait: None,
            unimplemented: self.unimplemented.clone(),
            task: None,
            published: None,
            set_tid: Vec::new(),
            seat: None,
        };
        // Shown in /proc from the start, before its first system call.
        let memory = child.spawn_memory.clone();
        child.publish(pid, &state, memory.as_deref().unwrap_or(mem));
        self.vfork_wait = release;
        self.pending_child = Some((
            Box::new(child),
            Thread {
                tid: pid,
                cpu,
                state,
            },
        ));
        Ok(u64::from(number))
    }
    /// The PID namespace thread `tid` is in, which numbers the tasks it
    /// names and sees.
    pub(crate) fn pid_space(&self, tid: u32) -> Arc<Namespace> {
        self.group.namespaces(tid).pid.clone()
    }
    /// The task a thread of PID namespace `space` names by `number`, or
    /// [`NOBODY`] for one it does not number, which nothing matches.
    fn named(space: &Namespace, number: u32) -> u32 {
        space.task(number).unwrap_or(NOBODY)
    }
    fn wait4(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        if a[2] & !(1 | 2 | 8 | 0xe0000000) != 0 {
            return Err(Errno::EINVAL);
        }
        // -1 is any child, 0 this process's group, below -1 that group, as
        // the caller's PID namespace numbers them, and so is what it gives.
        let space = self.pid_space(thread.tid);
        let wanted = match a[0] as i32 {
            -1 => Wanted::Any,
            0 => Wanted::Pgid(self.processes.pgid(self.process.pid)?),
            i32::MIN => return Err(Errno(3)),
            pgid if pgid < 0 => Wanted::Pgid(Self::named(&space, pgid.unsigned_abs())),
            pid => Wanted::Pid(Self::named(&space, pid as u32)),
        };
        let wait = WaitFor {
            exits: true,
            stops: a[2] & 2 != 0,
            continues: a[2] & 8 != 0,
            ..WaitFor::default()
        };
        loop {
            let ticket = self.processes.changed().value();
            if let Some((pid, event, cpu, _)) =
                self.processes
                    .reap(self.process.pid, &space, wanted, wait)?
            {
                let raw = match event {
                    ChildEvent::Exited(ExitStatus::Exited(code)) => (code & 255) << 8,
                    ChildEvent::Exited(ExitStatus::Signaled(signal)) => signal & 127,
                    // WCOREDUMP.
                    ChildEvent::Dumped(signal) => signal & 127 | 0x80,
                    ChildEvent::Exited(_) => return Err(Errno::EINVAL),
                    ChildEvent::Stopped(signal) => (signal << 8) | 0x7f,
                    ChildEvent::Continued => 0xffff,
                };
                // Native wait-fault oracle: Linux consumes the zombie before copyout.
                if a[1] != 0 {
                    mem.write(GuestAddr(a[1]), &raw.to_le_bytes())
                        .map_err(|_| Errno::EFAULT)?;
                }
                if a[3] != 0 {
                    mem.write(GuestAddr(a[3]), &crate::syscalls::rusage(cpu))
                        .map_err(|_| Errno::EFAULT)?;
                }
                return Ok(u64::from(pid));
            }
            if a[2] & 1 != 0 {
                return Ok(0);
            }
            self.group.drain_process(&mut thread.state);
            let receipt = self.inbox.drain(&mut thread.state);
            if receipt.interrupted
                || self.group.status().is_some()
                || signals::next_pending(&thread.state, true).is_some()
            {
                return Err(Errno(4));
            }
            self.wait_for_children(ticket)?;
        }
    }
    /// `waitid(idtype, id, infop, options, rusage)` with Linux's checks and
    /// copy-out: the siginfo fields (`si_signo`, `si_errno`, `si_code`,
    /// `si_pid`, `si_uid`, `si_status`) are written, as zeros when no child
    /// is reported, even on an error; the rusage (the child's CPU time) only
    /// with a child.
    fn waitid(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        let found = self.waitid_child(thread, a);
        if let Ok(Some((_, _, cpu, _))) = found
            && a[4] != 0
        {
            mem.write(GuestAddr(a[4]), &crate::syscalls::rusage(cpu))
                .map_err(|_| Errno::EFAULT)?;
        }
        if a[2] != 0 {
            let (signo, code, pid, uid, status) = match found {
                Ok(Some((pid, ChildEvent::Exited(ExitStatus::Exited(code)), _, uid))) => {
                    (17, 1, pid, uid, code & 255)
                }
                Ok(Some((pid, ChildEvent::Exited(ExitStatus::Signaled(signal)), _, uid))) => {
                    (17, 2, pid, uid, signal)
                }
                Ok(Some((pid, ChildEvent::Dumped(signal), _, uid))) => (17, 3, pid, uid, signal),
                // CLD_STOPPED and CLD_CONTINUED.
                Ok(Some((pid, ChildEvent::Stopped(signal), _, uid))) => (17, 5, pid, uid, signal),
                Ok(Some((pid, ChildEvent::Continued, _, uid))) => (17, 6, pid, uid, 18),
                _ => (0, 0, 0, 0, 0),
            };
            let mut info = [0; 28];
            for (at, value) in [
                (0, signo),
                (8, code),
                (16, pid as i32),
                (
                    20,
                    thread
                        .state
                        .credentials
                        .user
                        .shown(crate::users::Ids::User, uid) as i32,
                ),
                (24, status),
            ] {
                info[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            mem.write(GuestAddr(a[2]), &info)
                .map_err(|_| Errno::EFAULT)?;
        }
        found.map(|_| 0)
    }
    fn waitid_child(
        &self,
        thread: &mut Thread,
        a: [u64; 6],
    ) -> Result<Option<(u32, ChildEvent, u64, u32)>, Errno> {
        const KNOWN: u64 =
            WNOHANG | 2 | WEXITED | 8 | WNOWAIT | 0x2000_0000 | 0x4000_0000 | 0x8000_0000;
        let options = u64::from(a[3] as u32);
        if options & !KNOWN != 0 || options & (2 | WEXITED | 8) == 0 {
            return Err(Errno::EINVAL);
        }
        let id = a[1] as i32;
        let mut nonblocking = false;
        let space = self.pid_space(thread.tid);
        let wanted = match a[0] as i32 {
            0 => Wanted::Any,
            1 if id > 0 => Wanted::Pid(Self::named(&space, id as u32)),
            2 if id > 0 => Wanted::Pgid(Self::named(&space, id as u32)),
            2 if id == 0 => Wanted::Pgid(self.processes.pgid(self.process.pid)?),
            3 if id >= 0 => {
                let d = self.files.descriptor(id as u64)?;
                let pidfd = d
                    .file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PidFd>())
                    .ok_or(Errno::EBADF)?;
                // A nonblocking pidfd waits as WNOHANG, but reports EAGAIN.
                nonblocking = u64::from(d.file.flags()) & PIDFD_NONBLOCK != 0;
                Wanted::Pid(pidfd.pid)
            }
            _ => return Err(Errno::EINVAL),
        };
        loop {
            let ticket = self.processes.changed().value();
            let found = self.processes.reap(
                self.process.pid,
                &space,
                wanted,
                WaitFor {
                    keep: options & WNOWAIT != 0,
                    exits: options & WEXITED != 0,
                    stops: options & 2 != 0,
                    continues: options & 8 != 0,
                },
            )?;
            if found.is_some() || options & WNOHANG != 0 {
                return Ok(found);
            }
            if nonblocking {
                return Err(Errno::EAGAIN);
            }
            self.group.drain_process(&mut thread.state);
            let receipt = self.inbox.drain(&mut thread.state);
            if receipt.interrupted
                || self.group.status().is_some()
                || signals::next_pending(&thread.state, true).is_some()
            {
                return Err(Errno(4));
            }
            self.wait_for_children(ticket)?;
        }
    }
    /// `kcmp(pid1, pid2, type, idx1, idx2)`: each number, an `int`, names
    /// a thread as the caller's PID namespace numbers them (`ESRCH`), as
    /// Linux's `find_task_by_vpid`; the caller's own thread is taken as it
    /// is now, and another as of its last checkpoint. [`crate::kcmp`] does
    /// the rest.
    fn kcmp(&self, thread: &Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        let space = self.pid_space(thread.tid);
        let find = |number: u64| -> Option<crate::kcmp::Task> {
            let tid = space.task(u32::try_from(number as i32).ok().filter(|&n| n > 0)?)?;
            if tid == thread.tid {
                let public = crate::threads::PublicThread {
                    credentials: thread.state.credentials.clone(),
                    memory: Some(mem.view()),
                    files: self.files.view(),
                    ..Default::default()
                };
                let dumpable = self.processes.view(self.process.pid)?.dumpable;
                return Some(crate::kcmp::Task::new(
                    tid,
                    Arc::clone(&self.group),
                    false,
                    dumpable,
                    public,
                ));
            }
            let pid = match self.processes.view(tid) {
                Some(_) => tid,
                None => self.processes.thread_leader(tid)?,
            };
            let view = self.processes.view(pid)?;
            let public = view.group.public(tid)?;
            Some(crate::kcmp::Task::new(
                tid,
                Arc::clone(&view.group),
                view.zombie,
                view.dumpable,
                public,
            ))
        };
        let (Some(first), Some(second)) = (find(a[0]), find(a[1])) else {
            return Err(Errno(3)); // ESRCH
        };
        let cookies = self.processes.kcmp_cookies.get_or_init(|| {
            let mut random = [0; crate::kcmp::TYPES * 16];
            // Linux draws them at boot and kcmp never fails for want of
            // them: without the host's bytes they come from std's randomly
            // keyed hasher, never all zeros.
            if self.host.random_bytes(&mut random).is_err() {
                crate::kcmp::fallback_random(&mut random);
            }
            crate::kcmp::cookies(&random)
        });
        crate::kcmp::compare(
            cookies,
            (&self.group, &thread.state.credentials),
            mem,
            [&first, &second],
            a[2] as i32,
            [a[3], a[4]],
        )
    }
    /// `process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags)` and
    /// `process_vm_writev`, as Linux's `process_vm_rw`: the iovecs are
    /// checked first ([`crate::process_vm::segments`]), then `pid`, an
    /// `int`, names a thread as the caller's PID namespace numbers them
    /// (`ESRCH`, as `find_get_task_by_vpid`), which has memory (`ESRCH` for
    /// a zombie, as `mm_access`), and which the caller may attach to unless
    /// it shares the caller's memory (`EPERM`). Then
    /// [`crate::process_vm::transfer`] copies.
    fn process_vm(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
        write: bool,
    ) -> Result<u64, Errno> {
        let Some(segments) = crate::process_vm::segments(mem, a)? else {
            return Ok(0);
        };
        let target = self.attachable(thread, mem, a[0] as i32)?;
        crate::process_vm::transfer(mem, &target, &segments, write)
    }
    /// The memory of the thread the caller's PID namespace numbers
    /// `number`, as Linux's `mm_access` with `PTRACE_MODE_ATTACH_REALCREDS`
    /// gives it: `ESRCH` for no such thread or one without memory (a
    /// zombie's), and `EPERM` unless it is the caller's own memory, the
    /// thread is of the caller's process, or the caller may attach to it
    /// ([`Self::may_attach`]).
    fn attachable(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        number: i32,
    ) -> Result<paludarium_mmu::MemoryView, Errno> {
        let esrch = Errno(3);
        let number = u32::try_from(number).ok().filter(|&n| n > 0).ok_or(esrch)?;
        let tid = self.pid_space(thread.tid).task(number).ok_or(esrch)?;
        if tid == thread.tid || self.group.has_member(tid) {
            return Ok(mem.view());
        }
        let pid = match self.processes.view(tid) {
            Some(_) => tid,
            None => self.processes.thread_leader(tid).ok_or(esrch)?,
        };
        let view = self.processes.view(pid).ok_or(esrch)?;
        let public = view.group.public(tid).ok_or(esrch)?;
        let memory = public
            .memory
            .clone()
            .filter(|_| !view.zombie)
            .ok_or(esrch)?;
        if !memory.is_of(mem) && !Self::may_attach(thread, &view, &public) {
            return Err(Errno::EPERM);
        }
        Ok(memory)
    }
    /// `get_robust_list(pid, head, length)`, as Linux's
    /// `futex_get_robust_list_common`: the task the caller's PID namespace
    /// numbers `pid`, an `int` (the caller for 0, `ESRCH` for none), must be
    /// of the caller's process or one it may read (`ptrace_may_access` with
    /// `PTRACE_MODE_READ_REALCREDS`, [`Self::may_attach`], `EPERM`); then the
    /// length is written and the head (`EFAULT`). A zombie's list went as it
    /// ended, so its head is 0.
    fn get_robust_list(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let esrch = Errno(3);
        let number = a[0] as i32;
        let tid = if number == 0 {
            thread.tid
        } else {
            let number = u32::try_from(number).map_err(|_| esrch)?;
            self.pid_space(thread.tid).task(number).ok_or(esrch)?
        };
        let head = if tid == thread.tid || self.group.has_member(tid) {
            self.group.robust_list(tid).ok_or(esrch)?
        } else {
            let pid = match self.processes.view(tid) {
                Some(_) => tid,
                None => self.processes.thread_leader(tid).ok_or(esrch)?,
            };
            let view = self.processes.view(pid).ok_or(esrch)?;
            let public = view.group.public(tid).ok_or(esrch)?;
            if !Self::may_attach(thread, &view, &public) {
                return Err(Errno::EPERM);
            }
            if view.zombie {
                0
            } else {
                view.group.robust_list(tid).ok_or(esrch)?
            }
        };
        mem.write_u64(GuestAddr(a[2]), crate::futex::ROBUST_LIST_HEAD)
            .and_then(|()| mem.write_u64(GuestAddr(a[1]), head))
            .map_err(|_| Errno::EFAULT)?;
        Ok(0)
    }
    /// Whether the caller may attach to or read a thread of another process,
    /// as Linux's `__ptrace_may_access` with `PTRACE_MODE_ATTACH_REALCREDS`
    /// or `PTRACE_MODE_READ_REALCREDS` decides
    /// ([`crate::credentials::Credentials::may_read_task`] with the real
    /// IDs). The two modes differ only in Yama, which restricts attaching
    /// and is not applied here. A zombie keeps the dumpability it had, as
    /// Linux 7.1 and later keep it in the task's `exec_state` (before, a
    /// task with no `mm` skipped the check).
    fn may_attach(
        thread: &Thread,
        view: &ProcessView,
        public: &crate::threads::PublicThread,
    ) -> bool {
        thread
            .state
            .credentials
            .may_read_task(&public.credentials, view.dumpable, true)
    }
    /// `pidfd_getfd(pidfd, targetfd, flags)`, as Linux's: `flags` must be 0
    /// (`EINVAL`) and `pidfd` a pidfd (`EBADF`); its process must not be
    /// reaped (`ESRCH`), the caller must be able to attach to it (`EPERM`)
    /// and it must not have exited (`ESRCH`); then `targetfd` must be open
    /// in it (`EBADF`). The copy shares the open file description and gets
    /// the lowest free number with `FD_CLOEXEC` set (`EMFILE`).
    fn pidfd_getfd(&mut self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        if a[2] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let d = self.files.descriptor(u64::from(a[0] as u32))?;
        let pidfd = d
            .file
            .as_any()
            .and_then(|any| any.downcast_ref::<PidFd>())
            .ok_or(Errno::EBADF)?;
        let target = a[1] as u32;
        let descriptor = if pidfd.pid == self.process.pid {
            self.files.descriptor(u64::from(target))?
        } else {
            let esrch = Errno(3);
            let view = self.processes.view(pidfd.pid).ok_or(esrch)?;
            let public = view.group.public(pidfd.pid).ok_or(esrch)?;
            if !Self::may_attach(thread, &view, &public) {
                return Err(Errno::EPERM);
            }
            if view.zombie {
                return Err(esrch);
            }
            public.files.descriptor(target).ok_or(Errno::EBADF)?
        };
        let n = self.files.reserve(self.group.nofile())?;
        self.files.fill(n, descriptor.received(true));
        Ok(u64::from(n))
    }
    /// `process_madvise(pidfd, vec, vlen, advice, flags)`, as Linux's:
    /// `flags` must be 0 (`EINVAL`) and the iovecs are read as
    /// `import_iovec` reads them; then the task, `PIDFD_SELF_THREAD` or
    /// `PIDFD_SELF_THREAD_GROUP` for the caller's, or a pidfd's process
    /// (`EBADF` for no pidfd, `ESRCH` once it is reaped), and its memory
    /// (`ESRCH` for a zombie), which another process's must let the caller
    /// read it with its filesystem IDs (`EACCES`). Then the advice must be
    /// one Linux knows (`EINVAL`, before any range, as Linux master checks
    /// it; the CI's kernel checks it with each range); for another
    /// process's memory only `MADV_COLD`, `MADV_PAGEOUT`, `MADV_WILLNEED` and `MADV_COLLAPSE`
    /// (`EINVAL`), and with `CAP_SYS_NICE` (`EPERM`). Each range is then
    /// advised in turn, as `madvise` would advise the caller's memory
    /// ([`crate::syscalls::advise`]); another process's only needs to be
    /// mapped (`ENOMEM`), as the four only hint at how pages will be used.
    /// The bytes of the ranges before the first that fails are the result,
    /// or its error when there are none.
    fn process_madvise(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        const PIDFD_SELF_THREAD: i32 = -10000;
        const PIDFD_SELF_THREAD_GROUP: i32 = -10001;
        const CAP_SYS_NICE: u64 = 1 << 23;
        if a[4] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let ranges =
            crate::files::iovecs_checked(mem, a[1], u64::from(a[2] as u32), |_, _| Ok(()))?;
        let esrch = Errno(3);
        let pidfd = a[0] as i32;
        let target = if pidfd == PIDFD_SELF_THREAD || pidfd == PIDFD_SELF_THREAD_GROUP {
            None
        } else {
            let d = self.files.descriptor(u64::from(pidfd as u32))?;
            let pidfd = d
                .file
                .as_any()
                .and_then(|any| any.downcast_ref::<PidFd>())
                .ok_or(Errno::EBADF)?;
            if pidfd.pid == self.process.pid {
                None
            } else {
                let view = self.processes.view(pidfd.pid).ok_or(esrch)?;
                let public = view.group.public(pidfd.pid).ok_or(esrch)?;
                let memory = public
                    .memory
                    .clone()
                    .filter(|_| !view.zombie)
                    .ok_or(esrch)?;
                if memory.is_of(mem) {
                    None
                } else {
                    let readable = thread.state.credentials.may_read_task(
                        &public.credentials,
                        view.dumpable,
                        false,
                    );
                    if !readable {
                        return Err(Errno::EACCES);
                    }
                    Some(memory)
                }
            }
        };
        let advice = a[3] as i32;
        if !matches!(advice, 0..=4 | 8..=25 | 100..=103) {
            return Err(Errno::EINVAL);
        }
        if target.is_some() {
            // MADV_WILLNEED, MADV_COLD, MADV_PAGEOUT, MADV_COLLAPSE
            if !matches!(advice, 3 | 20 | 21 | 25) {
                return Err(Errno::EINVAL);
            }
            if !thread.state.credentials.capable(CAP_SYS_NICE) {
                return Err(Errno::EPERM);
            }
        }
        let mut done = 0u64;
        for (start, len) in ranges {
            let len = len as u64;
            // check_input_range: the lengths are cut short of wrapping.
            let result =
                if start & 4095 != 0 || start.checked_add(len.next_multiple_of(4096)).is_none() {
                    Err(Errno::EINVAL)
                } else if len == 0 {
                    Ok(())
                } else {
                    match &target {
                        None => crate::syscalls::advise(
                            mem,
                            &thread.state.credentials,
                            start,
                            len,
                            advice as u64,
                        ),
                        Some(memory) => Self::mapped_whole(memory, start, len),
                    }
                };
            match result {
                Ok(()) => done += len,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
    }
    /// `process_mrelease(pidfd, flags)`, as Linux master's: `flags` must be
    /// 0 (`EINVAL`); then the task, `PIDFD_SELF_THREAD` or
    /// `PIDFD_SELF_THREAD_GROUP` for the caller's, or a pidfd's process
    /// (`EBADF` for no pidfd, `ESRCH` once it is reaped). It must still have
    /// its memory (`ESRCH` once it has exited, as a zombie), and that memory
    /// must be on its way to be freed ([`Processes::will_free_memory`]), or
    /// there is nothing to release early (`EINVAL`). There is nothing to do then:
    /// the memory goes as the process's last thread ends, which is no later
    /// than Linux's reaper would free it.
    fn process_mrelease(&self, a: [u64; 6]) -> Result<u64, Errno> {
        const PIDFD_SELF_THREAD: i32 = -10000;
        const PIDFD_SELF_THREAD_GROUP: i32 = -10001;
        if a[1] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let pid = match a[0] as i32 {
            PIDFD_SELF_THREAD | PIDFD_SELF_THREAD_GROUP => self.process.pid,
            _ => {
                let d = self.files.descriptor(u64::from(a[0] as u32))?;
                d.file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PidFd>())
                    .ok_or(Errno::EBADF)?
                    .pid
            }
        };
        match self.processes.will_free_memory(pid) {
            None => Err(Errno(3)),
            Some(true) => Ok(0),
            Some(false) => Err(Errno::EINVAL),
        }
    }
    /// Whether `[start, start + len)` of `memory` is mapped through, as
    /// `madvise_walk_vmas` finds a hole (`ENOMEM`).
    fn mapped_whole(
        memory: &paludarium_mmu::MemoryView,
        start: u64,
        len: u64,
    ) -> Result<(), Errno> {
        let end = start.saturating_add(len.next_multiple_of(4096));
        if end > paludarium_types::USER_ADDRESS_LIMIT {
            return Err(Errno::ENOMEM);
        }
        let mut mappings = memory.mappings().unwrap_or_default();
        mappings.sort_unstable_by_key(|m| m.start.0);
        let covered = mappings
            .iter()
            .filter(|m| m.start.0 < end && m.end() > start)
            .fold(start, |covered, m| {
                if m.start.0 <= covered {
                    covered.max(m.end())
                } else {
                    covered
                }
            });
        if covered < end {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }
    /// The memory of the task the caller's PID namespace numbers `number`
    /// (the caller's for 0), for a call that may change where its pages lie,
    /// as Linux's `find_get_task_by_vpid` and `ptrace_may_access` with
    /// `PTRACE_MODE_READ_REALCREDS` give it: `ESRCH` for no such task, and
    /// `EPERM` unless it is of the caller's process or the caller may read
    /// it ([`Self::may_attach`]); `None` for a zombie, which has none.
    fn movable_memory(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        number: i32,
    ) -> Result<Option<paludarium_mmu::MemoryView>, Errno> {
        if number == 0 {
            return Ok(Some(mem.view()));
        }
        let esrch = Errno(3);
        let number = u32::try_from(number).map_err(|_| esrch)?;
        let tid = self.pid_space(thread.tid).task(number).ok_or(esrch)?;
        if tid == thread.tid || self.group.has_member(tid) {
            return Ok(Some(mem.view()));
        }
        let pid = match self.processes.view(tid) {
            Some(_) => tid,
            None => self.processes.thread_leader(tid).ok_or(esrch)?,
        };
        let view = self.processes.view(pid).ok_or(esrch)?;
        let public = view.group.public(tid).ok_or(esrch)?;
        if !Self::may_attach(thread, &view, &public) {
            return Err(Errno::EPERM);
        }
        Ok(public.memory.clone().filter(|_| !view.zombie))
    }
    /// `migrate_pages(pid, maxnode, old_nodes, new_nodes)`, as Linux's
    /// `kernel_migrate_pages`: both masks are read first
    /// ([`crate::mempolicy::migration_masks`]), then the task
    /// ([`Self::movable_memory`]), then the nodes it may be given
    /// ([`crate::mempolicy::migration_targets`]), and a zombie is `EINVAL`.
    /// Every page is on node 0, so none moves and none is left behind.
    fn migrate_pages(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let (_, new) = crate::mempolicy::migration_masks(mem, a[2], a[3], a[1])?;
        let memory = self.movable_memory(thread, mem, a[0] as i32)?;
        crate::mempolicy::migration_targets(&new, thread.state.credentials.capable(1 << 23))?;
        memory.map(|_| 0).ok_or(Errno::EINVAL)
    }
    /// `move_pages(pid, count, pages, nodes, status, flags)`, as Linux's
    /// `kernel_move_pages`: flags other than `MPOL_MF_MOVE` and
    /// `MPOL_MF_MOVE_ALL` are `EINVAL`, and the latter needs `CAP_SYS_NICE`
    /// (`EPERM`); then the task ([`Self::movable_memory`], `EINVAL` for a
    /// zombie), whose pages [`crate::mempolicy::move_pages`] reports.
    fn move_pages(&self, thread: &Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        const MPOL_MF_MOVE: i32 = 2;
        const MPOL_MF_MOVE_ALL: i32 = 4;
        let flags = a[5] as i32;
        if flags & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & MPOL_MF_MOVE_ALL != 0 && !thread.state.credentials.capable(1 << 23) {
            return Err(Errno::EPERM);
        }
        let target = self
            .movable_memory(thread, mem, a[0] as i32)?
            .ok_or(Errno::EINVAL)?;
        crate::mempolicy::move_pages(mem, &target, a[1], a[2], a[3], a[4])
    }
    /// `pidfd_open(pid, flags)`: a close-on-exec pidfd for a process.
    /// `PIDFD_THREAD` is accepted, and shows in `F_GETFL` as `O_EXCL` as on
    /// Linux, but still names the whole process.
    fn pidfd_open(&mut self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let flags = u64::from(a[1] as u32);
        if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || a[0] as i32 <= 0 {
            return Err(Errno::EINVAL);
        }
        let pid = Self::named(&self.pid_space(thread.tid), a[0] as u32);
        match self.processes.pidfd_target(pid) {
            Err(e) if e == Errno::ENOENT && flags & PIDFD_THREAD != 0 => {
                // A pidfd for one thread of another process is not supported.
                return Err(Errno::EINVAL);
            }
            result => result?,
        }
        let pidfd = Arc::new(PidFd {
            pid,
            processes: Arc::clone(&self.processes),
            flags: AtomicU32::new((2 | flags & (PIDFD_NONBLOCK | PIDFD_THREAD)) as u32),
        });
        self.files
            .install(pidfd, true, self.group.nofile())
            .map(u64::from)
    }
    /// `rt_sigqueueinfo(pid, sig, info)`, as Linux's `do_rt_sigqueueinfo`:
    /// the caller's siginfo goes to `pid` as it is. Only a thread signalling
    /// itself may give a `si_code` that `kill` or `tkill` would (`EPERM`).
    fn sigqueueinfo(&self, thread: &Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        let (pid, number) = (a[0] as i32, a[1] as i32);
        let signal = queued_siginfo(mem, a[2], number)?;
        let space = self.pid_space(thread.tid);
        if impersonates(signal.code) && pid != space.number(thread.tid) as i32 {
            return Err(Errno(1));
        }
        if pid <= 0 {
            return Err(Errno(3));
        }
        self.processes
            .queue(
                self.process.pid,
                thread.state.credentials.task_ids(),
                Self::named(&space, pid.cast_unsigned()),
                signal,
            )
            .map(|()| 0)
    }
    /// `rt_tgsigqueueinfo(tgid, tid, sig, info)`, as `do_rt_tgsigqueueinfo`:
    /// the same, directed at thread `tid` of process `tgid`.
    fn tgsigqueueinfo(
        &self,
        thread: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let (tgid, tid, number) = (a[0] as i32, a[1] as i32, a[2] as i32);
        let signal = queued_siginfo(mem, a[3], number)?;
        if tgid <= 0 || tid <= 0 {
            return Err(Errno::EINVAL);
        }
        let space = self.pid_space(thread.tid);
        if impersonates(signal.code) && tid != space.number(thread.tid) as i32 {
            return Err(Errno(1));
        }
        self.processes
            .queue_thread(
                self.process.pid,
                thread.state.credentials.task_ids(),
                Self::named(&space, tgid.cast_unsigned()),
                Self::named(&space, tid.cast_unsigned()),
                signal,
            )
            .map(|()| 0)
    }
    /// `pidfd_send_signal(pidfd, sig, info, flags)`, as `kill` on the
    /// pidfd's process; a siginfo and the scope flags are not supported
    /// (`EINVAL`). `PIDFD_SELF_THREAD` (-10000) names the calling thread,
    /// which takes the signal as from `tkill`, and `PIDFD_SELF_THREAD_GROUP`
    /// (-10001) its process, as Linux master's sentinels do; any other
    /// number must be a pidfd (`EBADF`).
    fn pidfd_send_signal(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        const PIDFD_SELF_THREAD: i32 = -10000;
        const PIDFD_SELF_THREAD_GROUP: i32 = -10001;
        if a[3] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let target = match a[0] as i32 {
            PIDFD_SELF_THREAD => None,
            PIDFD_SELF_THREAD_GROUP => Some(self.process.pid),
            _ => {
                let d = self.files.descriptor(u64::from(a[0] as u32))?;
                let pidfd = d
                    .file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PidFd>())
                    .ok_or(Errno::EBADF)?;
                Some(pidfd.pid)
            }
        };
        let number = a[1] as i32;
        if !(0..=64).contains(&number) || a[2] != 0 {
            return Err(Errno::EINVAL);
        }
        let sender = thread.state.credentials.task_ids();
        let Some(pid) = target else {
            // The thread itself, which may always signal itself.
            let own = self.pid_space(thread.tid).number(self.process.pid);
            return self
                .group
                .send(thread.tid, number, own, sender.uid)
                .map(|()| 0);
        };
        // A zombie takes the signal and drops it; a reaped process is gone.
        let exited = self.processes.exited(pid).ok_or(Errno(3))?;
        self.processes
            .may_signal(self.process.pid, sender.clone(), pid, number)?;
        if exited {
            return Ok(0);
        }
        self.processes
            .signal(self.process.pid, sender.uid, pid, number)
            .map(|()| 0)
    }
    /// Closes what exec closed, as Linux's `__fput` does on the way back to
    /// the new program: a socket's last descriptor waits for its linger
    /// time ([`crate::inet::linger`]).
    fn close_on_exec(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        closed: Vec<crate::files::Descriptor>,
    ) {
        let tid = thread.tid;
        let mut c = crate::syscalls::Context {
            // execve, whose closing descriptors these are.
            number: 59,
            tid,
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
        for descriptor in closed {
            crate::record_locks::closed(&c, &descriptor);
            crate::mqueue::closed(&c, &descriptor);
            crate::inet::linger(&mut c, &descriptor.file);
        }
    }
    /// Replaces the program; returns the descriptors it closed
    /// (`FD_CLOEXEC`), for the caller to close.
    fn exec(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        n: u64,
        a: [u64; 6],
    ) -> Result<Vec<crate::files::Descriptor>, Errno> {
        const AT_FDCWD: u64 = -100i64 as u64;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        const AT_EMPTY_PATH: u64 = 0x1000;
        // execve(path, argv, envp), execveat(dir, path, argv, envp, flags)
        let (dir, a) = if n == 322 {
            (a[0], [a[1], a[2], a[3], a[4], 0, 0])
        } else {
            (AT_FDCWD, [a[0], a[1], a[2], 0, 0, 0])
        };
        let raw = read_string(mem, a[0], 4096, Errno::ENAMETOOLONG)?;
        if a[3] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno::EINVAL);
        }
        // The name the program gets (`AT_EXECFN`, and a script's argument),
        // as Linux's `alloc_bprm` makes it for a path from a descriptor.
        let fd = dir as i32;
        let named = if raw.first() == Some(&b'/') || fd == -100 {
            raw.clone()
        } else if raw.is_empty() {
            format!("/dev/fd/{fd}").into_bytes()
        } else {
            [format!("/dev/fd/{fd}/").as_bytes(), &raw].concat()
        };
        // A link in `/proc/self/fd`, as `fexecve` falls back to, runs the
        // file its descriptor holds while a path still names it, and a file
        // none names (a memfd, a removed one) from the descriptor.
        let program = crate::files::exec_program(&self.files, self.process.pid, dir, &raw, a[3])?;
        let mut budget = paludarium_loader::MAX_ARG_BYTES as usize;
        let creds = &thread.state.credentials;
        // What runs: a path's program, whose scripts are followed below, or
        // the bytes of a file only a descriptor holds (`image`), which, if a
        // script, hands over to its interpreter by path.
        // The denial of writes to the file a path names, held from the
        // open on, as `do_open_execat` takes it, until exec ends; the program
        // it loads takes its own.
        let mut opened = None;
        // Exec's opens of the files it runs, for inotify, in their order.
        let mut opens = ExecOpens::default();
        let (start, program, mut readable, image) = match program {
            crate::files::Program::Path(path) => {
                let (program, readable) =
                    crate::permissions::exec(&self.files, creds, dir, &raw, &path)?;
                opens
                    .0
                    .push(exec_opened(&self.files, &path, reported_open()));
                opened = deny_writes(&self.files, &path)?;
                ((named.clone(), path.clone(), path), program, readable, None)
            }
            crate::files::Program::File {
                file,
                name,
                entry,
                removed,
            } => {
                let stat = file.stat()?;
                if stat.mode & 0o170000 != 0o100000 {
                    return Err(Errno::EACCES);
                }
                crate::permissions::permission(creds, &stat, crate::permissions::MAY_EXEC)?;
                let readable =
                    crate::permissions::permission(creds, &stat, crate::permissions::MAY_READ)
                        .is_ok();
                // Landlock's check of the open for execution, which for a
                // removed file walks up from where it was, the file itself
                // still the object it was (a memfd is in no hierarchy).
                if let Some(path) = &removed {
                    let device = crate::page_cache::mount_device(&self.files.fs.mounts(), path);
                    let files = &self.files;
                    crate::landlock::check_with(
                        &creds.landlock,
                        &|p| {
                            if p == path.as_slice() {
                                Some((device, stat.inode))
                            } else {
                                crate::files::file_identity(files, p)
                            }
                        },
                        path,
                        crate::landlock::READ_FILE | crate::landlock::EXECUTE,
                    )?;
                }
                // A memfd is on a device of its own; a removed file still on
                // its mount's.
                let device = match &removed {
                    Some(path) => crate::page_cache::mount_device(&self.files.fs.mounts(), path),
                    None => crate::memfd::DEVICE,
                };
                // `do_open_execat` opens the descriptor's file again.
                opens.0.push(crate::inotify::Closing::of_handle(
                    &self.files.caches,
                    &self.files.fs,
                    &file,
                    device,
                    &stat,
                ));
                let denied = self.files.caches.deny_write_access((device, stat.inode))?;
                (
                    (Vec::new(), Vec::new(), entry),
                    Some(stat),
                    readable,
                    Some((file, name, denied)),
                )
            }
        };
        let mut argv = read_vector(mem, a[1], &mut budget)?;
        let envp = read_vector(mem, a[2], &mut budget)?;
        let (named_first, first, comm) = start;
        let mut path = comm;
        let image = match image {
            Some((file, name, denied)) => {
                let mut head = [0; SCRIPT_HEAD];
                read_from(&*file, &mut head)?;
                if let Some(Some(opened)) = opens.0.last() {
                    opened.read();
                }
                match script_interpreter(&head)? {
                    // Only an ELF program is read whole, and no more of it
                    // than the memory limit could hold (ENOMEM), as a file
                    // may be sparse and far larger.
                    None if head[..4] != *b"\x7fELF" => return Err(Errno(8)),
                    None => {
                        let limit = mem.memory_meter().map_or(u64::MAX, |m| m.max());
                        if file.stat()?.size > limit {
                            return Err(Errno::ENOMEM);
                        }
                        Some((read_whole(&*file, limit)?, name, denied))
                    }
                    // A script reads itself by its name, which a descriptor
                    // closed on exec leaves to nothing
                    // (`BINPRM_FLAGS_PATH_INACCESSIBLE`).
                    Some((interpreter, argument)) => {
                        if fd != -100 && raw.first() != Some(&b'/') && self.files.is_cloexec(dir) {
                            return Err(Errno::ENOENT);
                        }
                        splice_script(
                            &mut argv,
                            &mut budget,
                            &interpreter,
                            argument,
                            named.clone(),
                        )?;
                        if interpreter.is_empty() {
                            return Err(Errno::EACCES);
                        }
                        let loaded = self.files.exec_path(interpreter.clone())?;
                        let (program, may_read) = crate::permissions::exec(
                            &self.files,
                            creds,
                            AT_FDCWD,
                            &interpreter,
                            &loaded,
                        )?;
                        readable = may_read;
                        opens
                            .0
                            .push(exec_opened(&self.files, &loaded, reported_open()));
                        let (loaded, program) = follow_scripts(
                            &self.files,
                            creds,
                            (interpreter, loaded),
                            program,
                            &mut readable,
                            (&mut argv, &mut budget),
                            &mut opens,
                        )?;
                        path = loaded.clone();
                        // The script's own denial ends once its interpreter
                        // takes over (`exec_binprm`).
                        drop(denied);
                        let exe = deny_writes(&self.files, &loaded)?
                            .map(|exe| exe.closing(opens.0.pop().flatten()));
                        let done = self.exec_image(
                            thread,
                            mem,
                            (named, path, loaded),
                            program,
                            readable,
                            (argv, envp),
                            None,
                            exe,
                        );
                        if done.is_ok() {
                            self.exec_closes = Some(opens);
                        }
                        return done;
                    }
                }
            }
            None => None,
        };
        let (loaded, program, image, exe) = match image {
            Some((bytes, name, denied)) => (
                Vec::new(),
                program,
                Some((bytes, name)),
                Some(denied.closing(opens.0.pop().flatten())),
            ),
            None => {
                let (loaded, program) = follow_scripts(
                    &self.files,
                    creds,
                    (named_first, first),
                    program,
                    &mut readable,
                    (&mut argv, &mut budget),
                    &mut opens,
                )?;
                // The program's own open closes with the process's last use
                // of it (`exe_file`).
                let exe = deny_writes(&self.files, &loaded)?
                    .map(|exe| exe.closing(opens.0.pop().flatten()));
                (loaded, program, None, exe)
            }
        };
        let done = self.exec_image(
            thread,
            mem,
            (named, path, loaded),
            program,
            readable,
            (argv, envp),
            image,
            exe,
        );
        drop(opened);
        // The scripts' opens close at the end of exec, as the `fput`s
        // `exec_binprm` defers, once the old image has gone.
        if done.is_ok() {
            self.exec_closes = Some(opens);
        }
        done
    }
    /// The rest of exec, once the program is known: `raw` is its name,
    /// `path` names the process, and `loaded` is what loads, unless `image`
    /// holds the bytes of a file no path names and what `/proc/self/exe`
    /// reads of it. `exe` denies writes to the program's file, which the
    /// process keeps while it runs it (Linux's `exe_file`).
    #[allow(clippy::too_many_arguments)]
    fn exec_image(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        (raw, path, loaded): (Vec<u8>, Vec<u8>, Vec<u8>),
        program: Option<paludarium_host::FileStat>,
        mut readable: bool,
        (argv, envp): (Vec<Vec<u8>>, Vec<Vec<u8>>),
        held: Option<(Vec<u8>, Vec<u8>)>,
        program_file: Option<crate::page_cache::WriteAccess>,
    ) -> Result<Vec<crate::files::Descriptor>, Errno> {
        let mut random = [0; 16];
        self.host
            .random_bytes(&mut random)
            .map_err(|_| Errno::EIO)?;
        let (_, _, no_new_privs) = self.processes.status_of(self.process.pid);
        let (credentials, secure) = thread
            .state
            .credentials
            .after_exec(program.as_ref(), no_new_privs);
        let start = StartInfo {
            argv: &argv,
            envp: &envp,
            execfn: &raw,
            random,
            ids: [
                credentials.uid,
                credentials.euid,
                credentials.gid,
                credentials.egid,
            ],
            secure,
        };
        let mut memory = match mem.memory_meter() {
            Some(meter) => AddressSpace::new().with_memory_meter(meter),
            None => AddressSpace::new(),
        };
        // An exec that fails from here closes the program before the
        // interpreter it opened: `free_bprm`'s `fput` comes after
        // `load_elf_binary`'s, and runs first.
        let mut failing = FailingExec {
            exe: program_file,
            interpreters: Vec::new(),
        };
        // A 64-bit program drops READ_IMPLIES_EXEC (x86's
        // set_personality_64bit), and a set-ID one PER_CLEAR_ON_SETID too
        // (begin_new_exec), before the layout is picked.
        let mut personality = thread.state.personality & !crate::syscalls::READ_IMPLIES_EXEC;
        if secure {
            personality &= !crate::syscalls::PER_CLEAR_ON_SETID;
        }
        // ADDR_COMPAT_LAYOUT: Linux's legacy layout, upward from
        // TASK_UNMAPPED_BASE (a third of TASK_SIZE), not randomized here.
        if personality & crate::syscalls::ADDR_COMPAT_LAYOUT != 0 {
            memory.set_bottom_up(Some(GuestAddr(TASK_UNMAPPED_BASE)));
        }
        // The loader reads the files whole, which is no open of the guest's:
        // exec's own are told of as Linux makes them.
        let report = reported_open();
        // As Linux's `open_exec` of an interpreter: it needs execute
        // permission (EACCES), and an unreadable one makes the program
        // undumpable (`would_dump`). Its set-ID bits do not count.
        let mut interpreter = |name: &[u8]| {
            // An empty name finds the working directory.
            if name.is_empty() {
                return Err(Errno::EACCES);
            }
            let path = self.files.exec_path(name.to_vec())?;
            let (_, may_read) = crate::permissions::exec(
                &self.files,
                &thread.state.credentials,
                -100i64 as u64,
                name,
                &path,
            )?;
            let closing = exec_opened(&self.files, &path, report);
            // Denied only while it loads, as `load_elf_binary` gives it back.
            drop(deny_writes(&self.files, &path)?);
            if let Some(closing) = &closing {
                closing.read();
            }
            readable &= may_read;
            // Its mappings keep the open, which closes with the last of them
            // (`vm_file`), before they let go of the file.
            let closing = Arc::new(Mutex::new(closing));
            failing.interpreters.push(Arc::clone(&closing));
            let keep: paludarium_loader::Keep =
                Arc::new((closing, self.files.interpreter_keep(&path)));
            Ok((path, Some(keep)))
        };
        let fs = &*self.files.fs;
        let image = crate::inotify::unopened(|| match &held {
            Some((bytes, name)) => paludarium_loader::load_file_with(
                fs,
                bytes,
                name,
                &start,
                &mut memory,
                &mut interpreter,
            ),
            None => {
                paludarium_loader::load_with(fs, &loaded, &start, &mut memory, &mut interpreter)
            }
        })
        .map_err(|error| match error {
            // The new image did not fit under the memory limit.
            _ if memory.take_out_of_memory() => Errno::ENOMEM,
            LoadError::NotFound => Errno::ENOENT,
            LoadError::Interpreter(error) => error,
            LoadError::TooLarge => Errno(7),
            LoadError::Errno(error) => error,
            _ => Errno(8),
        })?;
        // MMAP_PAGE_ZERO: SVr4's read-only page 0, as load_elf_binary maps it
        // last, when the new credentials may map below mmap_min_addr
        // (CAP_SYS_RAWIO); a failure is ignored, as there.
        if personality & crate::syscalls::MMAP_PAGE_ZERO != 0 && credentials.may_map_low() {
            let _ = memory.map_shared(
                Some(GuestAddr(0)),
                4096,
                paludarium_mmu::Prot::READ.union(paludarium_mmu::Prot::EXEC),
                paludarium_mmu::MappingKind::Anonymous,
            );
        }
        // All validation precedes retirement. Old siblings must stop touching
        // their image and shared descriptors before the replacement is visible.
        self.group.begin_exec(thread.tid)?;
        while self.group.active_threads() > 1 {
            if self.group.status().is_some() {
                return Err(Errno(4));
            }
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
        // Linux walks the robust list on the old image's memory
        // (`futex_exec_release`), and the new program has none.
        if let Some(head) = self.group.take_robust_list(thread.tid) {
            crate::futex::exit_robust_list(&self.group.futexes, mem, thread.tid, head);
        }
        // The program runs in the namespaces of the thread that ran it, and
        // in the time namespace its children take.
        let namespaces = self.group.namespaces(thread.tid).exec();
        // A thread other than the leader takes the leader's number, and its
        // own goes, as Linux's `exchange_tids`.
        if thread.tid != self.process.pid {
            namespaces.pid.leave(thread.tid);
        }
        self.group
            .end_exec(thread.tid, self.process.pid, Arc::clone(&self.inbox));
        // The thread is now the leader, which the process entry counts.
        self.task = None;
        // exec deletes the POSIX timers (the interval timer stays).
        self.group
            .with_timers(&mut thread.state, |timers| timers.clear());
        // The thread's undo list goes with its new number.
        if thread.tid != self.process.pid
            && let Some(list) = self.group.take_sem_undo_list(thread.tid)
        {
            self.group.set_sem_undo_list(self.process.pid, list);
        }
        thread.tid = self.process.pid;
        let closed = self.files.take_close_on_exec();
        self.files = self.files.for_exec();
        self.group.exec_actions();
        thread.cpu = CpuState::new(image.entry_point, image.initial_stack_pointer);
        self.group.set_start_stack(image.initial_stack_pointer.0);
        self.group.set_executable(match held {
            Some((_, name)) => name,
            None => crate::files::resolved(&self.files, &loaded).unwrap_or(loaded),
        });
        // The exec is done: the program and the interpreter close as the
        // process and the mappings end.
        failing.interpreters.clear();
        self.group.set_exe_file(failing.exe.take().map(Arc::new));
        let ignored = thread
            .state
            .signal_actions
            .iter()
            .filter(|(_, action)| action.handler == 1)
            .map(|(&number, &action)| (number, action))
            .collect();
        // exec keeps the thread's CPU time, as it keeps the process.
        let cpu = std::mem::take(&mut thread.state.cpu);
        let old = std::mem::take(&mut thread.state.credentials);
        thread.state = ThreadState {
            pid: self.process.pid,
            signal_mask: thread.state.signal_mask,
            signal_actions: ignored,
            cpu,
            personality,
            arrivals: thread.state.arrivals,
            process_notices: thread.state.process_notices,
            // exec keeps the seccomp mode and filters.
            seccomp: std::mem::take(&mut thread.state.seccomp),
            seccomp_sync: thread.state.seccomp_sync,
            ..ThreadState::default()
        };
        thread.state.name_after(&path);
        // Linux decides from the IDs before exec, then installs the new ones
        // as a change of credentials (`commit_creds`). A program the thread
        // may not read runs undumpable (`would_dump`).
        let changed = old.resets_dumpable(&credentials);
        let dumpable = old.euid == old.uid && old.egid == old.gid && readable && !changed;
        self.processes
            .executed_as(self.process.pid, dumpable, secure || changed, secure);
        self.group
            .reset_task_ids(self.process.pid, credentials.task_ids());
        self.group
            .reset_seccomp(self.process.pid, &thread.state.seccomp);
        self.group.reset_namespaces(self.process.pid, namespaces);
        thread.state.credentials = credentials;
        self.processes.mark_executed(self.process.pid);
        self.exec_memory = Some(Arc::new(memory));
        self.release_vfork();
        Ok(closed)
    }
}
/// `clone3`'s own flag: reset the signal handlers in the child.
pub(crate) const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
/// The namespace flags of `clone`'s flags, with `clone3`'s `CLONE_NEWTIME`
/// as itself.
pub(crate) fn namespace_flags(flags: u64) -> u64 {
    let time = if flags & crate::namespaces::CLONE3_NEWTIME != 0 {
        crate::namespaces::CLONE_NEWTIME
    } else {
        0
    };
    flags & crate::namespaces::ALL & !crate::namespaces::CLONE_NEWTIME | time
}

/// Reads `struct clone_args` for `clone3` with Linux's checks in Linux's
/// order (`copy_clone_args_from_user`, then `clone3_args_valid` and
/// `kernel_clone`), and returns the legacy `clone` arguments: flags with the
/// exit signal, the stack top, the parent and child TID addresses and the
/// TLS; and the numbers of `set_tid`, which [`Processes::allocate_in`]
/// checks. `CLONE_INTO_CGROUP` is not supported (`EINVAL`).
pub(crate) fn clone3_args(
    mem: &AddressSpace,
    address: u64,
    size: u64,
) -> Result<([u64; 6], Vec<u32>), Errno> {
    const VER0: u64 = 64;
    const KNOWN: u64 = 88;
    if size > 4096 {
        return Err(Errno(7)); // E2BIG
    }
    if size < VER0 {
        return Err(Errno::EINVAL);
    }
    // copy_struct_from_user: a larger struct is fine if the rest is zero.
    let mut bytes = vec![0; usize::try_from(size).unwrap_or(4096)];
    mem.read(GuestAddr(address), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    if bytes.iter().skip(KNOWN as usize).any(|&b| b != 0) {
        return Err(Errno(7));
    }
    bytes.resize(KNOWN as usize, 0);
    let word =
        |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap_or_default());
    let [
        flags,
        _pidfd,
        child_tid,
        parent_tid,
        exit_signal,
        stack,
        stack_size,
        tls,
        set_tid,
        set_tid_size,
    ] = std::array::from_fn(word);
    if set_tid_size > 32
        || (set_tid == 0) != (set_tid_size == 0)
        || exit_signal & !0xff != 0
        || exit_signal > 64
    {
        return Err(Errno::EINVAL);
    }
    let mut numbers = vec![0; usize::try_from(set_tid_size).unwrap_or(0) * 4];
    if !numbers.is_empty() {
        mem.read(GuestAddr(set_tid), &mut numbers)
            .map_err(|_| Errno::EFAULT)?;
    }
    let set_tid = numbers
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&n| u32::from_le_bytes(n))
        .collect();
    const LEGACY: u64 = 0xffff_ffff & !0xff;
    const DETACHED: u64 = 0x400000;
    const SIGHAND: u64 = 0x800;
    const THREAD_OR_PARENT: u64 = 0x10000 | 0x8000;
    // CSIGNAL's bits are clone3's exit_signal; CLONE_NEWTIME (0x80) is the
    // one flag among them.
    if flags & !(LEGACY | 0x80 | CLONE_CLEAR_SIGHAND) != 0
        || flags & (DETACHED | 0x7f) != 0
        || flags & (SIGHAND | CLONE_CLEAR_SIGHAND) == SIGHAND | CLONE_CLEAR_SIGHAND
        || flags & THREAD_OR_PARENT != 0 && exit_signal != 0
    {
        return Err(Errno::EINVAL);
    }
    let top = match (stack, stack_size) {
        (0, 0) => 0,
        (0, _) | (_, 0) => return Err(Errno::EINVAL),
        (stack, size) => stack
            .checked_add(size)
            .filter(|&top| top <= paludarium_types::USER_ADDRESS_LIMIT)
            .ok_or(Errno::EINVAL)?,
    };
    // CLONE_NEWTIME moves out of the exit signal's bits.
    let flags = if flags & 0x80 != 0 {
        flags & !0x80 | crate::namespaces::CLONE3_NEWTIME
    } else {
        flags
    };
    Ok((
        [flags | exit_signal, top, parent_tid, child_tid, tls, 0],
        set_tid,
    ))
}
fn read_string(
    mem: &AddressSpace,
    address: u64,
    limit: usize,
    long: Errno,
) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::new();
    for offset in 0..limit {
        let mut byte = [0];
        mem.read(
            GuestAddr(address.checked_add(offset as u64).ok_or(Errno::EFAULT)?),
            &mut byte,
        )
        .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(long)
}
/// Follows the `#!` lines from `named`, the program as exec was given it, at
/// `loaded`, to the program that runs, as Linux's `load_script` does: each
/// script runs its interpreter, which may be a script too, with the arguments
/// [`splice_script`] gives it. Returns the path loaded and its status, whose
/// set-ID bits are the ones exec takes; `readable` drops when one of them may
/// not be read.
pub(crate) fn follow_scripts(
    files: &crate::files::Files,
    credentials: &crate::credentials::Credentials,
    (mut named, mut loaded): (Vec<u8>, Vec<u8>),
    mut program: Option<paludarium_host::FileStat>,
    readable: &mut bool,
    (argv, budget): (&mut Vec<Vec<u8>>, &mut usize),
    opens: &mut ExecOpens,
) -> Result<(Vec<u8>, Option<paludarium_host::FileStat>), Errno> {
    for depth in 0.. {
        if program.is_some()
            && let Some(Some(opened)) = opens.0.last()
        {
            opened.read();
        }
        let Some(head) = program.as_ref().and_then(|_| read_head(files, &loaded)) else {
            break;
        };
        let Some((interpreter, argument)) = script_interpreter(&head)? else {
            break;
        };
        splice_script(argv, budget, &interpreter, argument, named)?;
        // `open_exec` of an empty name finds the working directory.
        if interpreter.is_empty() {
            return Err(Errno::EACCES);
        }
        loaded = files.exec_path(interpreter.clone())?;
        let may_read;
        (program, may_read) =
            crate::permissions::exec(files, credentials, -100i64 as u64, &interpreter, &loaded)?;
        opens.0.push(exec_opened(files, &loaded, reported_open()));
        drop(deny_writes(files, &loaded)?);
        *readable = may_read;
        named = interpreter;
        // `exec_binprm` takes six handlers at most.
        if depth == MAX_SCRIPT_DEPTH && program.is_some() {
            return Err(Errno(40));
        }
    }
    Ok((loaded, program))
}
/// Exec's opens of the files it runs, a script's first, for inotify: each
/// was `IN_OPEN` (`do_open_execat`), and closes when this drops, the last
/// first, as the `fput`s Linux defers to the end of the call run.
#[derive(Default)]
pub(crate) struct ExecOpens(Vec<Option<crate::inotify::Closing>>);
impl Drop for ExecOpens {
    fn drop(&mut self) {
        while self.0.pop().is_some() {}
    }
}
/// What an exec that fails once its program is known closes: the program
/// first, then the ELF interpreter it opened, whoever still holds that.
struct FailingExec {
    exe: Option<crate::page_cache::WriteAccess>,
    interpreters: Vec<Arc<Mutex<Option<crate::inotify::Closing>>>>,
}
impl Drop for FailingExec {
    fn drop(&mut self) {
        drop(self.exe.take());
        for interpreter in &self.interpreters {
            drop(
                interpreter
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take(),
            );
        }
    }
}
/// Tells inotify of exec's open of the file at `path` (`IN_OPEN`), and gives
/// what tells it of the file's read and its close: none for a file that
/// cannot be looked at, or when the open is not the guest's (`report`).
fn exec_opened(
    files: &crate::files::Files,
    path: &[u8],
    report: bool,
) -> Option<crate::inotify::Closing> {
    if !report {
        return None;
    }
    let path = crate::files::resolved(files, path)?;
    let node = files.fs.metadata(&path, false).ok()?;
    let device = crate::page_cache::mount_device(&files.fs.mounts(), &path);
    Some(crate::inotify::Closing::open(
        &files.caches,
        &files.fs,
        &path,
        device,
        &node,
        0,
    ))
}
/// Write access to the regular file `path` names denied (ETXTBSY while a
/// description has it open for writing), as Linux's `do_open_execat` denies
/// it to each file exec opens; none for another file, which fails later.
/// It finds the file by its path again, after the permission check did, where
/// Linux does both on the one file `do_open_execat` opened; a rename between
/// the two may check another file.
pub(crate) fn deny_writes(
    files: &crate::files::Files,
    path: &[u8],
) -> Result<Option<crate::page_cache::WriteAccess>, Errno> {
    let Ok(stat) = files.fs.metadata(path, true) else {
        return Ok(None);
    };
    if stat.mode & 0o170000 != 0o100000 {
        return Ok(None);
    }
    let key = (
        crate::page_cache::mount_device(&files.fs.mounts(), path),
        stat.inode,
    );
    files.caches.deny_write_access(key).map(Some)
}
/// All of `file`, read from its start, for exec of a file only a
/// descriptor holds.
/// It grows as the bytes come, as [`paludarium_vfs`]'s `read_file` reads a
/// path's program, and stops past `limit` bytes (ENOMEM), however the file
/// grows meanwhile.
fn read_whole(file: &dyn paludarium_host::FileHandle, limit: u64) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        match file.read_at(bytes.len() as u64, &mut chunk)? {
            0 => return Ok(bytes),
            n => bytes.extend_from_slice(&chunk[..n]),
        }
        if bytes.len() as u64 > limit {
            return Err(Errno::ENOMEM);
        }
    }
}
/// The first bytes of `file` into `head`, zero after its end.
fn read_from(file: &dyn paludarium_host::FileHandle, head: &mut [u8]) -> Result<(), Errno> {
    let mut at = 0;
    while at < head.len() {
        match file.read_at(at as u64, &mut head[at..])? {
            0 => break,
            n => at += n,
        }
    }
    Ok(())
}
/// A script's interpreter, and its argument if any.
pub(crate) type Script = (Vec<u8>, Option<Vec<u8>>);
/// How many scripts deep the last one may be counted from 0.
const MAX_SCRIPT_DEPTH: usize = 5;
/// `BINPRM_BUF_SIZE`: how much of a file exec looks at.
const SCRIPT_HEAD: usize = 256;
/// The first [`SCRIPT_HEAD`] bytes of the file at `path`, zero after its end,
/// or `None` when it cannot be read, which loading it then reports.
fn read_head(files: &crate::files::Files, path: &[u8]) -> Option<[u8; SCRIPT_HEAD]> {
    let file = crate::inotify::unnoticed(|| files.fs.open(path, 0, 0)).ok()?;
    let mut head = [0; SCRIPT_HEAD];
    let mut at = 0;
    while at < SCRIPT_HEAD {
        match file.read(&mut head[at..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => at += n,
        }
    }
    Some(head)
}
/// A script's interpreter and its one optional argument, as Linux's
/// `load_script` parses them from the first line of `head`, or `None` for a
/// file that does not start with `#!`. The line is cut at the buffer's end,
/// which is `ENOEXEC` when the interpreter's name may be cut, or when there is
/// no name. Spaces and tabs separate them, and the argument runs on to the end
/// of the line, without the spaces and tabs that end it.
pub(crate) fn script_interpreter(head: &[u8; SCRIPT_HEAD]) -> Result<Option<Script>, Errno> {
    const ENOEXEC: Errno = Errno(8);
    let blank = |b: u8| b == b' ' || b == b'\t';
    let terminator = |b: u8| blank(b) || b == 0;
    if &head[..2] != b"#!" {
        return Ok(None);
    }
    // The last byte of the buffer does not count.
    let last = SCRIPT_HEAD - 1;
    // `strnchr` stops at a zero byte.
    let line = head[..last]
        .iter()
        .take_while(|&&b| b != 0)
        .position(|&b| b == b'\n');
    let next_non_blank = |from: usize, to: usize| (from..to).find(|&at| !blank(head[at]));
    let next_terminator = |from: usize, to: usize| (from..to).find(|&at| terminator(head[at]));
    let mut end = match line {
        Some(line) => line,
        None => {
            let first = next_non_blank(2, last).ok_or(ENOEXEC)?;
            next_terminator(first, last).ok_or(ENOEXEC)?;
            last
        }
    };
    while blank(head[end - 1]) {
        end -= 1;
    }
    let name = next_non_blank(2, end)
        .filter(|&name| name != end)
        .ok_or(ENOEXEC)?;
    let separator = next_terminator(name, end);
    let argument = separator
        .filter(|&at| head[at] != 0)
        .and_then(|at| next_non_blank(at, end));
    let string = |from: usize, to: usize| {
        let bytes = &head[from..to];
        let length = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        bytes[..length].to_vec()
    };
    Ok(Some((
        string(name, separator.unwrap_or(end)),
        argument.map(|argument| string(argument, end)),
    )))
}
/// The arguments of a script's interpreter, as Linux's `load_script` splices
/// them: its name, its argument if any, and then the script's path in place of
/// the first of `argv`, which takes their room (`E2BIG`).
fn splice_script(
    argv: &mut Vec<Vec<u8>>,
    budget: &mut usize,
    interpreter: &[u8],
    argument: Option<Vec<u8>>,
    script: Vec<u8>,
) -> Result<(), Errno> {
    let mut take = |length: usize| {
        *budget = budget.checked_sub(length + 1 + 8).ok_or(Errno(7))?;
        Ok::<(), Errno>(())
    };
    take(interpreter.len())?;
    take(script.len())?;
    if let Some(argument) = &argument {
        take(argument.len())?;
    }
    if !argv.is_empty() {
        let first = argv.remove(0);
        *budget += first.len() + 1 + 8;
    }
    argv.insert(0, script);
    if let Some(argument) = argument {
        argv.insert(0, argument);
    }
    argv.insert(0, interpreter.to_vec());
    Ok(())
}
fn read_vector(
    mem: &AddressSpace,
    address: u64,
    budget: &mut usize,
) -> Result<Vec<Vec<u8>>, Errno> {
    let mut strings = Vec::new();
    if address == 0 {
        return Ok(strings);
    }
    for index in 0..paludarium_loader::MAX_ARG_BYTES / 8 {
        let pointer = mem
            .read_u64(GuestAddr(
                address.checked_add(index * 8).ok_or(Errno::EFAULT)?,
            ))
            .map_err(|_| Errno::EFAULT)?;
        if pointer == 0 {
            return Ok(strings);
        }
        let value = read_string(mem, pointer, (*budget).min(131072), Errno(7))?;
        *budget = budget.checked_sub(value.len() + 1 + 8).ok_or(Errno(7))?;
        strings.push(value);
    }
    Err(Errno(7))
}

/// Whether a `si_code` is one only the kernel, `kill` or `tkill` gives:
/// zero or more (`SI_USER`, `SI_KERNEL` and the signal-specific codes) or
/// `SI_TKILL`.
fn impersonates(code: i32) -> bool {
    code >= 0 || code == signals::SI_TKILL
}

/// The siginfo at `addr` for signal `number`, as Linux's
/// `__copy_siginfo_from_user` takes it: the first 48 bytes
/// (`kernel_siginfo`), with `si_signo` set to the signal. For a `si_code`
/// whose layout Linux does not know, the other 80 bytes must be zero
/// (`E2BIG`).
fn queued_siginfo(
    mem: &AddressSpace,
    addr: u64,
    number: i32,
) -> Result<signals::PendingSignal, Errno> {
    let mut queued = [0u8; 48];
    mem.read(GuestAddr(addr), &mut queued)
        .map_err(|_| Errno::EFAULT)?;
    let code = i32::from_le_bytes([queued[8], queued[9], queued[10], queued[11]]);
    if !known_layout(number, code) {
        let mut rest = [0u8; 80];
        mem.read(GuestAddr(addr.wrapping_add(48)), &mut rest)
            .map_err(|_| Errno::EFAULT)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(Errno(7));
        }
    }
    queued[0..4].copy_from_slice(&number.to_le_bytes());
    Ok(signals::PendingSignal {
        queued: Some(queued),
        ..signals::PendingSignal::user(number, code)
    })
}

/// Linux's `known_siginfo_layout`: `SI_KERNEL`; another positive code up to
/// the last one of its signal (`NSIGILL`, `NSIGFPE`, ...; `NSIGPOLL` for the
/// rest); `SI_USER` down to `SI_DETHREAD`; and `SI_ASYNCNL`.
fn known_layout(number: i32, code: i32) -> bool {
    let last = match number {
        4 => 11,  // SIGILL
        5 => 6,   // SIGTRAP
        7 => 5,   // SIGBUS
        8 => 15,  // SIGFPE
        11 => 10, // SIGSEGV
        17 => 6,  // SIGCHLD
        31 => 2,  // SIGSYS
        _ => 6,   // NSIGPOLL
    };
    if code == signals::SI_KERNEL {
        true
    } else if code > 0 {
        code <= last
    } else {
        code >= -7 || code == -60
    }
}
