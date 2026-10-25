//! Emulated process registry; no lock spans Host waits or guest execution.
use crate::{Kernel, Next, SignalInbox, Thread, ThreadGroup, ThreadState, signals};
use paludarium_cpu::{CpuState, reg};
use paludarium_host::ClockId;
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
    /// Resource limits (soft, hard), inherited on fork and kept across exec.
    /// They are recorded and reported; RLIMIT_FSIZE and RLIMIT_NOFILE are
    /// enforced, through the copy of their soft limits in the thread group.
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
    /// The task the process counts as until it is reaped, as its leader does
    /// in Linux's pids controller even as a zombie.
    _task: TaskCharge,
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
/// fs.nr_open: the highest RLIMIT_NOFILE Linux accepts by default.
const NR_OPEN: u64 = 1 << 20;
pub struct Processes {
    next: AtomicU32,
    entries: Mutex<BTreeMap<u32, Entry>>,
    tasks: Arc<TaskCount>,
    /// The highest RLIMIT_NOFILE hard limit a process may set, as fs.nr_open.
    nr_open: AtomicU64,
}
impl Processes {
    pub(crate) fn new(group: Arc<ThreadGroup>) -> Self {
        let tasks = Arc::new(TaskCount {
            live: AtomicU64::new(1),
            max: AtomicU64::new(u64::MAX),
        });
        Self {
            next: AtomicU32::new(2),
            nr_open: AtomicU64::new(NR_OPEN),
            entries: Mutex::new(BTreeMap::from([(
                1,
                Entry {
                    parent: 0,
                    group,
                    status: None,
                    pgid: 1,
                    sid: 0,
                    executed: false,
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
                    _task: TaskCharge(Arc::clone(&tasks)),
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
    pub(crate) fn allocate(&self) -> Result<u32, Errno> {
        self.next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                (value < i32::MAX as u32).then_some(value + 1)
            })
            .map_err(|_| Errno::EAGAIN)
    }
    pub(crate) fn insert(
        &self,
        pid: u32,
        parent: u32,
        group: Arc<ThreadGroup>,
        exit_signal: i32,
        task: TaskCharge,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (pgid, sid, limits, dumpable, no_new_privs) = entries
            .get(&parent)
            .map_or((pid, 0, DEFAULT_LIMITS, true, false), |p| {
                (p.pgid, p.sid, p.limits, p.dumpable, p.no_new_privs)
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
                _task: task,
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
    /// of user `who` (0 is the caller's), where every process is root's. An
    /// unreaped process still counts, by its leader.
    fn priority_threads(
        &self,
        which: i32,
        who: i32,
        caller: u32,
        tid: u32,
    ) -> Result<Vec<(Arc<ThreadGroup>, u32, i32)>, Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let all = |entry: &Entry| {
            entry
                .group
                .nices()
                .into_iter()
                .map(|(tid, nice)| (Arc::clone(&entry.group), tid, nice))
                .collect::<Vec<_>>()
        };
        Ok(match which {
            0 => {
                let tid = if who == 0 { tid } else { who as u32 };
                entries
                    .values()
                    .filter(|_| who >= 0)
                    .find_map(|e| {
                        e.group
                            .nice(tid)
                            .map(|nice| (Arc::clone(&e.group), tid, nice))
                    })
                    .into_iter()
                    .collect()
            }
            1 => {
                let pgid = match who {
                    0 => entries.get(&caller).ok_or(Errno(3))?.pgid,
                    who => who as u32,
                };
                entries
                    .values()
                    .filter(|e| who >= 0 && e.pgid == pgid)
                    .flat_map(all)
                    .collect()
            }
            2 if who == 0 => entries.values().flat_map(all).collect(),
            2 => Vec::new(),
            _ => return Err(Errno::EINVAL),
        })
    }
    pub(crate) fn mark_executed(&self, pid: u32) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&pid) {
            entry.executed = true;
        }
    }
    /// `prlimit64`: returns the old limit, after setting `new` if given.
    fn limit(
        &self,
        pid: u32,
        resource: usize,
        new: Option<(u64, u64)>,
    ) -> Result<(u64, u64), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        let old = *entry.limits.get(resource).ok_or(Errno::EINVAL)?;
        if let Some((soft, hard)) = new {
            if soft > hard {
                return Err(Errno::EINVAL);
            }
            if resource == 7 && hard > self.nr_open.load(Ordering::SeqCst) {
                return Err(Errno::EPERM);
            }
            entry.limits[resource] = (soft, hard);
            entry.group.set_soft_limit(resource, soft);
        }
        Ok(old)
    }
    /// The CPU time of the children `pid` has waited for.
    pub(crate) fn children_cpu(&self, pid: u32) -> u64 {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map_or(0, |entry| entry.children_cpu)
    }
    /// What `/proc/self/status` shows of `pid`: its parent, its
    /// RLIMIT_SIGPENDING soft limit and PR_SET_NO_NEW_PRIVS.
    pub(crate) fn status_of(&self, pid: u32) -> (u32, u64, bool) {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.get(&pid).map_or((0, 4096, false), |entry| {
            (entry.parent, entry.limits[11].0, entry.no_new_privs)
        })
    }
    fn parent(&self, pid: u32) -> u32 {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&pid)
            .map_or(0, |entry| entry.parent)
    }
    pub(crate) fn remove(&self, pid: u32) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&pid);
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
        // The first process is the init of the emulator's PID namespace: when
        // it exits, every other process gets SIGKILL from the kernel, as in
        // Linux's zap_pid_ns_processes.
        if pid == 1 {
            let live: Vec<u32> = entries
                .iter()
                .filter(|&(&other, entry)| other != 1 && entry.status.is_none())
                .map(|(&other, _)| other)
                .collect();
            for other in live {
                let _ = Self::deliver(&mut entries, other, None, Self::from_kernel(9));
            }
        }
        // Children that asked for it learn that this process exited.
        for child in entries.values() {
            if child.parent == pid && child.status.is_none() && child.death_signal != 0 {
                let _ = child.group.send_process_from(child.death_signal, pid);
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
            // As reparent_leader, also for a zombie reaped just now.
            Self::hang_up_orphaned(&mut entries, orphan, pid);
            if reaped {
                entries.remove(&orphan);
            }
        }
        Self::hang_up_orphaned(&mut entries, pid, pid);
        if Self::notify_parent(&entries, pid) {
            entries.remove(&pid);
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
        let mut ancestor = entries.get(&pid)?.parent;
        while let Some(entry) = entries.get(&ancestor) {
            if entry.subreaper && entry.status.is_none() {
                return Some(ancestor);
            }
            ancestor = entry.parent;
        }
        entries
            .get(&1)
            .filter(|entry| pid != 1 && entry.status.is_none())
            .map(|_| 1)
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
            parent
                .group
                .notify_child(code, signals::ChildSignal { pid, status, cpu });
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
    /// child counts only with WEXITED or WCONTINUED.
    pub(crate) fn reap(
        &self,
        parent: u32,
        wanted: Wanted,
        wait: WaitFor,
    ) -> Result<Option<(u32, ChildEvent, u64)>, Errno> {
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
            Some((pid, event, cpu))
        });
        if let Some((pid, event, cpu)) = ready
            && !wait.keep
        {
            match event {
                // A reaped child's CPU time joins its parent's children's.
                ChildEvent::Exited(_) | ChildEvent::Dumped(_) => {
                    entries.remove(&pid);
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
        Ok(ready)
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
        let parent = entry.parent;
        let child = signals::ChildSignal {
            pid,
            status: signal,
            cpu: group.process_cpu(),
        };
        if let Some(parent) = entries.get(&parent)
            && parent.group.wants_stop_notices()
        {
            parent.group.notify_child(signals::CLD_STOPPED, child);
        }
    }
    /// The RLIMIT_CORE soft limit of `pid` when a fatal signal may dump its
    /// core: the process is dumpable and the limit is at least one page.
    pub(crate) fn core_limit(&self, pid: u32) -> Option<u64> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid)?;
        let limit = entry.limits[4].0;
        (entry.dumpable && limit >= crate::coredump::MIN_LIMIT).then_some(limit)
    }
    /// Who `pid` is, for its core.
    pub(crate) fn core_identity(
        &self,
        pid: u32,
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
            cpu,
            children_cpu: entry.children_cpu,
            start_stack,
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
    /// `kill(target, number)` from `caller`, as Linux's kill_something_info:
    /// a positive target is that process (or the process of that thread), 0
    /// the caller's process group, -1 every process but the first and the
    /// caller, and any other negative target the group `-target`. Zombies
    /// count until they are reaped. With no process to send to it is `ESRCH`,
    /// even for an invalid signal; otherwise a group succeeds if any member
    /// took the signal, and -1 reports the last error.
    fn kill(&self, caller: u32, target: i32, number: i32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let pids: Vec<u32> = match target {
            // A thread's ID names its process, as Linux finds the task and
            // signals its thread group.
            pid if pid > 0 => {
                let pid = pid.cast_unsigned();
                entries
                    .iter()
                    .find(|&(&key, entry)| {
                        key == pid || (entry.status.is_none() && entry.group.has_member(pid))
                    })
                    .map(|(&key, _)| key)
                    .into_iter()
                    .collect()
            }
            -1 => entries
                .keys()
                .copied()
                .filter(|&pid| pid != 1 && pid != caller)
                .collect(),
            i32::MIN => Vec::new(),
            group => {
                let pgid = if group == 0 {
                    entries.get(&caller).ok_or(Errno(3))?.pgid
                } else {
                    group.unsigned_abs()
                };
                entries
                    .iter()
                    .filter(|(_, entry)| entry.pgid == pgid)
                    .map(|(&pid, _)| pid)
                    .collect()
            }
        };
        if pids.is_empty() {
            return Err(Errno(3));
        }
        let (mut last, mut delivered) = (Ok(()), false);
        for pid in pids {
            last = Self::deliver(&mut entries, pid, None, Self::from_process(number, caller));
            delivered |= last.is_ok();
        }
        if delivered && target != -1 {
            Ok(())
        } else {
            last
        }
    }
    fn signal(&self, sender: u32, pid: u32, number: i32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Self::deliver(&mut entries, pid, None, Self::from_process(number, sender))
    }
    /// `rt_sigqueueinfo` of `signal` to `pid`, which a thread's ID also
    /// names, as `kill` finds it.
    fn queue(&self, pid: u32, signal: signals::PendingSignal) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let found = entries
            .iter()
            .find(|&(&key, entry)| {
                key == pid || (entry.status.is_none() && entry.group.has_member(pid))
            })
            .map(|(&key, _)| key)
            .ok_or(Errno(3))?;
        Self::deliver(&mut entries, found, None, signal)
    }
    /// `rt_tgsigqueueinfo` of `signal` to thread `tid` of process `tgid`.
    fn queue_thread(
        &self,
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
        Self::deliver(&mut entries, tgid, Some(tid), signal)
    }
    /// A signal the kernel sends itself (`SI_KERNEL`).
    fn from_kernel(number: i32) -> signals::PendingSignal {
        signals::PendingSignal::user(number, signals::SI_KERNEL)
    }
    /// A signal process `sender` sends with `kill` (`SI_USER`).
    fn from_process(number: i32, sender: u32) -> signals::PendingSignal {
        signals::PendingSignal {
            sender: Some(sender),
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
                status: 18,
                cpu: entry.group.process_cpu(),
            };
            if let Some(parent) = entries.get(&parent)
                && parent.group.wants_stop_notices()
            {
                parent.group.notify_child(signals::CLD_CONTINUED, child);
            }
            return Ok(());
        }
        send(&entry.group)
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

const WNOHANG: u64 = 1;
const WEXITED: u64 = 4;
const WNOWAIT: u64 = 0x0100_0000;
const PIDFD_NONBLOCK: u64 = 0x800;
const PIDFD_THREAD: u64 = 0x80;

/// A pidfd (`pidfd_open`): readable once its process has exited, and hung
/// up once that process is reaped, as Linux's `pidfd_poll` reports. It is
/// only a handle; reading or writing it is `EINVAL`.
pub(crate) struct PidFd {
    pid: u32,
    processes: Arc<Processes>,
    flags: AtomicU32,
}
impl paludarium_host::FileHandle for PidFd {
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
        // An anonymous inode: permissions, but no file type.
        Ok(paludarium_host::FileStat {
            mode: 0o600,
            links: 1,
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
        self.flags
            .store(2 | flags & PIDFD_NONBLOCK as u32, Ordering::SeqCst);
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
    pub fn complete_process(&self, status: ExitStatus) {
        self.processes.finish(self.process.pid, status);
        if self.group.active_threads() == 0 {
            self.release_vfork();
        }
    }
    fn release_vfork(&self) {
        if let Some(release) = &self.vfork_release {
            release.store(true, Ordering::SeqCst);
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
        }
    }
    pub fn wait_vfork(&mut self, kill: &AtomicBool) -> Result<(), Errno> {
        let Some(release) = self.vfork_wait.take() else {
            return Ok(());
        };
        while !release.load(Ordering::SeqCst) && self.group.status().is_none() {
            if kill.load(Ordering::SeqCst) {
                self.processes.stop_all(ExitStatus::Signaled(9));
                return Err(Errno(4));
            }
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
        Ok(())
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
            59 => match self.exec(thread, mem, a) {
                Ok(()) => return Some(Next::Resume),
                Err(error) => Err(error),
            },
            61 => self.wait4(thread, mem, a),
            247 => self.waitid(thread, mem, a),
            434 => self.pidfd_open(a),
            424 => self.pidfd_send_signal(a),
            129 => self.sigqueueinfo(thread, mem, a),
            297 => self.tgsigqueueinfo(thread, mem, a),
            110 => Ok(u64::from(self.processes.parent(self.process.pid))),
            157 => self.prctl(thread, mem, a),
            // setpgid, getpgid, getpgrp
            109 => self.setpgid(a),
            121 => self
                .target_pid(a[0])
                .and_then(|pid| self.processes.pgid(pid))
                .map(u64::from),
            111 => self.processes.pgid(self.process.pid).map(u64::from),
            // setsid, getsid
            112 => self.processes.set_sid(self.process.pid).map(u64::from),
            124 => self
                .target_pid(a[0])
                .and_then(|pid| self.processes.sid(pid))
                .map(u64::from),
            // getpriority, setpriority
            140 => self.getpriority(thread, a),
            141 => self.setpriority(thread, a),
            // prlimit64, getrlimit, setrlimit
            302 => self.prlimit(mem, a[0], a[1], a[2], a[3]),
            97 => self.prlimit(mem, 0, a[0], 0, a[1]),
            160 => self.prlimit(mem, 0, a[0], a[1], 0),
            62 => self
                .processes
                .kill(self.process.pid, a[0] as i32, a[1] as i32)
                .map(|()| 0),
            _ => return None,
        };
        thread.cpu.gpr[reg::RAX] = result.unwrap_or_else(Errno::to_syscall_return);
        if (n == 61 || n == 247)
            && result == Err(Errno(4))
            && signals::next_pending(&thread.state, true)
                .and_then(|index| {
                    thread
                        .state
                        .signal_actions
                        .get(&thread.state.pending[index].number)
                })
                .is_some_and(|action| action.handler > 1 && action.flags & 0x10000000 != 0)
            && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
        {
            thread.cpu.rip = GuestAddr(rip);
            thread.cpu.gpr[reg::RAX] = n;
        }
        Some(self.checkpoint(thread, mem))
    }
    /// A pid argument: 0 is the caller; anything that is not a pid is ESRCH.
    fn target_pid(&self, value: u64) -> Result<u32, Errno> {
        match value as u32 as i32 {
            0 => Ok(self.process.pid),
            pid if pid > 0 => Ok(pid as u32),
            _ => Err(Errno(3)),
        }
    }
    /// `prctl(option, ...)`: PR_SET/GET_NAME (per thread),
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
            a[1] as i32,
            self.process.pid,
            thread.tid,
        )?;
        threads
            .iter()
            .map(|&(_, _, nice)| (20 - nice) as u64)
            .max()
            .ok_or(Errno(3))
    }
    /// `setpriority(which, who, nice)`: sets every thread's nice value to
    /// `nice`, cut to -20..19. The guest is root, which may also lower it.
    fn setpriority(&self, thread: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
        let threads = self.processes.priority_threads(
            a[0] as i32,
            a[1] as i32,
            self.process.pid,
            thread.tid,
        )?;
        let nice = (a[2] as i32).clamp(-20, 19);
        if threads.is_empty() {
            return Err(Errno(3));
        }
        for (group, tid, _) in threads {
            group.update_nice(tid, nice);
        }
        Ok(0)
    }
    fn setpgid(&self, a: [u64; 6]) -> Result<u64, Errno> {
        let pgid = a[1] as u32 as i32;
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let pid = self.target_pid(a[0])?;
        let pgid = if pgid == 0 { pid } else { pgid as u32 };
        self.processes
            .set_pgid(self.process.pid, pid, pgid)
            .map(|()| 0)
    }
    fn prlimit(
        &self,
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
        let pid = self.target_pid(pid)?;
        let resource = usize::try_from(resource as u32).map_err(|_| Errno::EINVAL)?;
        let (soft, hard) = self.processes.limit(pid, resource, new)?;
        if old != 0 {
            mem.write_u64(GuestAddr(old), soft)
                .map_err(|_| Errno::EFAULT)?;
            mem.write_u64(GuestAddr(old + 8), hard)
                .map_err(|_| Errno::EFAULT)?;
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
            | CLONE_CLEAR_SIGHAND;
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
        let task = self.processes.charge_task()?;
        let child_mem = if flags & 0x100 == 0 {
            Some(Arc::new(mem.fork()?))
        } else {
            None
        };
        let pid = self.processes.allocate()?;
        let group = Arc::new(self.group.fork(flags & 0x800 != 0));
        // CLONE_CLEAR_SIGHAND resets handled signals to their default and
        // keeps ignored ones, as execve does.
        if flags & CLONE_CLEAR_SIGHAND != 0 {
            group.exec_actions();
        }
        let inbox = Arc::new(SignalInbox::default());
        group.set_process_inbox(inbox.clone());
        if let Some(value) = self.group.nice(parent.tid) {
            group.set_nice(pid, value);
        }
        group.register(pid, inbox.clone());
        let mut state = parent.state.clone();
        state.pid = pid;
        state.pending.clear();
        state.frames.clear();
        state.exit_status = None;
        state.timer = signals::RealTimer::default();
        state.clear_child_tid = if flags & 0x200000 != 0 { a[3] } else { 0 };
        if flags & 0x100 != 0 {
            state.alt_stack = crate::AltStack::default();
        }
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
        if flags & 0x100000 != 0 {
            let _ = mem.write(GuestAddr(a[2]), &pid.to_le_bytes());
        }
        if flags & 0x1000000 != 0 {
            let _ = child_mem
                .as_deref()
                .unwrap_or(mem)
                .write(GuestAddr(a[3]), &pid.to_le_bytes());
        }
        let release = (flags & 0x4000 != 0).then(|| Arc::new(AtomicBool::new(false)));
        self.processes.insert(
            pid,
            self.process.pid,
            group.clone(),
            (flags & 0xff) as i32,
            task,
        );
        let child = Kernel {
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
            vfork_release: release.clone(),
            vfork_wait: None,
            unimplemented: self.unimplemented.clone(),
            task: None,
        };
        self.vfork_wait = release;
        self.pending_child = Some((
            Box::new(child),
            Thread {
                tid: pid,
                cpu,
                state,
            },
        ));
        Ok(u64::from(pid))
    }
    fn wait4(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        if a[2] & !(1 | 2 | 8 | 0xe0000000) != 0 {
            return Err(Errno::EINVAL);
        }
        // -1 is any child, 0 this process's group, below -1 that group.
        let wanted = match a[0] as i32 {
            -1 => Wanted::Any,
            0 => Wanted::Pgid(self.processes.pgid(self.process.pid)?),
            i32::MIN => return Err(Errno(3)),
            pgid if pgid < 0 => Wanted::Pgid(pgid.unsigned_abs()),
            pid => Wanted::Pid(pid as u32),
        };
        let wait = WaitFor {
            exits: true,
            stops: a[2] & 2 != 0,
            continues: a[2] & 8 != 0,
            ..WaitFor::default()
        };
        loop {
            if let Some((pid, event, cpu)) = self.processes.reap(self.process.pid, wanted, wait)? {
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
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
    }
    /// `waitid(idtype, id, infop, options, rusage)` with Linux's checks and
    /// copy-out: the siginfo fields (`si_signo`, `si_errno`, `si_code`,
    /// `si_pid`, `si_uid`, `si_status`) are written, as zeros when no child
    /// is reported, even on an error; the rusage (the child's CPU time) only
    /// with a child.
    fn waitid(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        let found = self.waitid_child(thread, a);
        if let Ok(Some((_, _, cpu))) = found
            && a[4] != 0
        {
            mem.write(GuestAddr(a[4]), &crate::syscalls::rusage(cpu))
                .map_err(|_| Errno::EFAULT)?;
        }
        if a[2] != 0 {
            let (signo, code, pid, status) = match found {
                Ok(Some((pid, ChildEvent::Exited(ExitStatus::Exited(code)), _))) => {
                    (17, 1, pid, code & 255)
                }
                Ok(Some((pid, ChildEvent::Exited(ExitStatus::Signaled(signal)), _))) => {
                    (17, 2, pid, signal)
                }
                Ok(Some((pid, ChildEvent::Dumped(signal), _))) => (17, 3, pid, signal),
                // CLD_STOPPED and CLD_CONTINUED.
                Ok(Some((pid, ChildEvent::Stopped(signal), _))) => (17, 5, pid, signal),
                Ok(Some((pid, ChildEvent::Continued, _))) => (17, 6, pid, 18),
                _ => (0, 0, 0, 0),
            };
            let mut info = [0; 28];
            for (at, value) in [(0, signo), (8, code), (16, pid as i32), (24, status)] {
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
    ) -> Result<Option<(u32, ChildEvent, u64)>, Errno> {
        const KNOWN: u64 =
            WNOHANG | 2 | WEXITED | 8 | WNOWAIT | 0x2000_0000 | 0x4000_0000 | 0x8000_0000;
        let options = u64::from(a[3] as u32);
        if options & !KNOWN != 0 || options & (2 | WEXITED | 8) == 0 {
            return Err(Errno::EINVAL);
        }
        let id = a[1] as i32;
        let mut nonblocking = false;
        let wanted = match a[0] as i32 {
            0 => Wanted::Any,
            1 if id > 0 => Wanted::Pid(id as u32),
            2 if id > 0 => Wanted::Pgid(id as u32),
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
            let found = self.processes.reap(
                self.process.pid,
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
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
    }
    /// `pidfd_open(pid, flags)`: a close-on-exec pidfd for a process.
    /// `PIDFD_THREAD` is accepted but still names the whole process.
    fn pidfd_open(&mut self, a: [u64; 6]) -> Result<u64, Errno> {
        let flags = u64::from(a[1] as u32);
        if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || a[0] as i32 <= 0 {
            return Err(Errno::EINVAL);
        }
        let pid = a[0] as u32;
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
            flags: AtomicU32::new((2 | flags & PIDFD_NONBLOCK) as u32),
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
        if impersonates(signal.code) && pid != thread.tid as i32 {
            return Err(Errno(1));
        }
        if pid <= 0 {
            return Err(Errno(3));
        }
        self.processes
            .queue(pid.cast_unsigned(), signal)
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
        if impersonates(signal.code) && tid != thread.tid as i32 {
            return Err(Errno(1));
        }
        self.processes
            .queue_thread(tgid.cast_unsigned(), tid.cast_unsigned(), signal)
            .map(|()| 0)
    }
    /// `pidfd_send_signal(pidfd, sig, info, flags)`, as `kill` on the
    /// pidfd's process; a siginfo and the scope flags are not supported
    /// (`EINVAL`).
    fn pidfd_send_signal(&self, a: [u64; 6]) -> Result<u64, Errno> {
        if a[3] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let d = self.files.descriptor(u64::from(a[0] as u32))?;
        let pidfd = d
            .file
            .as_any()
            .and_then(|any| any.downcast_ref::<PidFd>())
            .ok_or(Errno::EBADF)?;
        let number = a[1] as i32;
        if !(0..=64).contains(&number) || a[2] != 0 {
            return Err(Errno::EINVAL);
        }
        // A zombie takes the signal and drops it; a reaped process is gone.
        match self.processes.exited(pidfd.pid) {
            Some(false) => self
                .processes
                .signal(self.process.pid, pidfd.pid, number)
                .map(|()| 0),
            Some(true) => Ok(0),
            None => Err(Errno(3)),
        }
    }
    fn exec(&mut self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<(), Errno> {
        let path = read_string(mem, a[0], 4096, Errno::ENAMETOOLONG)?;
        let path = self.files.exec_path(path)?;
        let mut budget = paludarium_loader::MAX_ARG_BYTES as usize;
        let argv = read_vector(mem, a[1], &mut budget)?;
        let envp = read_vector(mem, a[2], &mut budget)?;
        let mut random = [0; 16];
        self.host
            .random_bytes(&mut random)
            .map_err(|_| Errno::EIO)?;
        let start = StartInfo {
            argv: &argv,
            envp: &envp,
            execfn: &path,
            random,
        };
        let mut memory = match mem.memory_meter() {
            Some(meter) => AddressSpace::new().with_memory_meter(meter),
            None => AddressSpace::new(),
        };
        let image = paludarium_loader::load(&*self.files.fs, &path, &start, &mut memory).map_err(
            |error| match error {
                // The new image did not fit under the memory limit.
                _ if memory.take_out_of_memory() => Errno::ENOMEM,
                LoadError::NotFound => Errno::ENOENT,
                LoadError::TooLarge => Errno(7),
                LoadError::Errno(error) => error,
                _ => Errno(8),
            },
        )?;
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
        self.group
            .end_exec(thread.tid, self.process.pid, Arc::clone(&self.inbox));
        // The thread is now the leader, which the process entry counts.
        self.task = None;
        // exec deletes the POSIX timers (the interval timer stays).
        self.group
            .with_timers(&mut thread.state, |timers| timers.clear());
        thread.tid = self.process.pid;
        self.files = self.files.for_exec();
        self.group.exec_actions();
        thread.cpu = CpuState::new(image.entry_point, image.initial_stack_pointer);
        self.group.set_start_stack(image.initial_stack_pointer.0);
        let ignored = thread
            .state
            .signal_actions
            .iter()
            .filter(|(_, action)| action.handler == 1)
            .map(|(&number, &action)| (number, action))
            .collect();
        // exec keeps the thread's CPU time, as it keeps the process.
        let cpu = std::mem::take(&mut thread.state.cpu);
        thread.state = ThreadState {
            pid: self.process.pid,
            signal_mask: thread.state.signal_mask,
            signal_actions: ignored,
            cpu,
            ..ThreadState::default()
        };
        thread.state.name_after(&path);
        self.processes.mark_executed(self.process.pid);
        self.exec_memory = Some(Arc::new(memory));
        self.release_vfork();
        Ok(())
    }
}
/// `clone3`'s own flag: reset the signal handlers in the child.
pub(crate) const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;

/// Reads `struct clone_args` for `clone3` with Linux's checks in Linux's
/// order (`copy_clone_args_from_user`, then `clone3_args_valid` and
/// `kernel_clone`), and returns the legacy `clone` arguments: flags with the
/// exit signal, the stack top, the parent and child TID addresses and the
/// TLS. `set_tid` and `CLONE_INTO_CGROUP` are not supported (`EINVAL`).
pub(crate) fn clone3_args(mem: &AddressSpace, address: u64, size: u64) -> Result<[u64; 6], Errno> {
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
    if set_tid_size > 32 || (set_tid == 0) != (set_tid_size == 0) || exit_signal & !0xff != 0 {
        return Err(Errno::EINVAL);
    }
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
    if set_tid != 0 || exit_signal > 64 {
        return Err(Errno::EINVAL);
    }
    Ok([flags | exit_signal, top, parent_tid, child_tid, tls, 0])
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
