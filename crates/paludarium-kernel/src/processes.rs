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
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

struct Entry {
    parent: u32,
    group: Arc<ThreadGroup>,
    status: Option<ExitStatus>,
    /// Process group ID; inherited on fork and kept across exec.
    pgid: u32,
    /// Resource limits (soft, hard), inherited on fork and kept across exec.
    /// They are recorded and reported, not enforced.
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
}
impl Processes {
    pub(crate) fn new(group: Arc<ThreadGroup>) -> Self {
        Self {
            next: AtomicU32::new(2),
            entries: Mutex::new(BTreeMap::from([(
                1,
                Entry {
                    parent: 0,
                    group,
                    status: None,
                    pgid: 1,
                    limits: DEFAULT_LIMITS,
                    death_signal: 0,
                    dumpable: true,
                    no_new_privs: false,
                    stop_report: None,
                    continue_report: false,
                    children_cpu: 0,
                },
            )])),
        }
    }
    pub(crate) fn allocate(&self) -> Result<u32, Errno> {
        self.next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                (value < i32::MAX as u32).then_some(value + 1)
            })
            .map_err(|_| Errno::EAGAIN)
    }
    pub(crate) fn insert(&self, pid: u32, parent: u32, group: Arc<ThreadGroup>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (pgid, limits, dumpable, no_new_privs) = entries
            .get(&parent)
            .map_or((pid, DEFAULT_LIMITS, true, false), |p| {
                (p.pgid, p.limits, p.dumpable, p.no_new_privs)
            });
        entries.insert(
            pid,
            Entry {
                parent,
                group,
                status: None,
                pgid,
                limits,
                death_signal: 0,
                dumpable,
                no_new_privs,
                stop_report: None,
                continue_report: false,
                children_cpu: 0,
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
    /// `setpgid` from `caller`: the target is the caller or one of its
    /// children, and a new group either is the target's own or already exists.
    fn set_pgid(&self, caller: u32, pid: u32, pgid: u32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let target = entries.get(&pid).ok_or(Errno(3))?;
        if pid != caller && target.parent != caller {
            return Err(Errno(3)); // ESRCH
        }
        if pgid != pid
            && !entries
                .values()
                .any(|e| e.status.is_none() && e.pgid == pgid)
        {
            return Err(Errno::EPERM);
        }
        if let Some(entry) = entries.get_mut(&pid) {
            entry.pgid = pgid;
        }
        Ok(())
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
            if resource == 7 && hard > NR_OPEN {
                return Err(Errno::EPERM);
            }
            entry.limits[resource] = (soft, hard);
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
        let (parent, status, cpu) = if let Some(entry) = entries.get_mut(&pid) {
            if entry.group.active_threads() != 0 {
                return;
            }
            let status = entry.group.status().unwrap_or(status);
            entry.status = Some(status);
            (entry.parent, status, entry.group.process_cpu())
        } else {
            return;
        };
        if let Some(parent) = entries.get(&parent) {
            let (code, status) = match status {
                ExitStatus::Signaled(signal) => (signals::CLD_KILLED, signal),
                ExitStatus::Exited(code) => (signals::CLD_EXITED, code & 255),
                _ => (signals::CLD_EXITED, 0),
            };
            parent
                .group
                .notify_child(code, signals::ChildSignal { pid, status, cpu });
        }
        // Children that asked for it learn that this process exited.
        for child in entries.values() {
            if child.parent == pid && child.status.is_none() && child.death_signal != 0 {
                let _ = child.group.send_process(child.death_signal);
            }
        }
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
                ChildEvent::Exited(_) => {
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
    fn signal(&self, pid: u32, number: i32) -> Result<(), Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&pid).ok_or(Errno(3))?;
        if number == 0 {
            return Ok(());
        }
        // SIGCONT resumes a stopped process at once, as Linux's
        // prepare_signal does, and its parent's wait can see that.
        if number == 18 && entry.status.is_none() && entry.group.is_stopped() {
            entry.group.send_process(number)?;
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
        entry.group.send_process(number)
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
        // POLLIN | POLLRDNORM after the exit, with POLLHUP after the reaping.
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
            110 => Ok(u64::from(self.processes.parent(self.process.pid))),
            157 => self.prctl(thread, mem, a),
            // setpgid, getpgid, getpgrp
            109 => self.setpgid(a),
            121 => self
                .target_pid(a[0])
                .and_then(|pid| self.processes.pgid(pid))
                .map(u64::from),
            111 => self.processes.pgid(self.process.pid).map(u64::from),
            // prlimit64, getrlimit, setrlimit
            302 => self.prlimit(mem, a[0], a[1], a[2], a[3]),
            97 => self.prlimit(mem, 0, a[0], 0, a[1]),
            160 => self.prlimit(mem, 0, a[0], a[1], 0),
            62 => {
                if a[1] > 64 {
                    Err(Errno::EINVAL)
                } else {
                    let pid = if a[0] == 0 {
                        self.process.pid
                    } else {
                        match u32::try_from(a[0]) {
                            Ok(pid) => pid,
                            Err(_) => return Some(self.return_process_error(thread, Errno(3))),
                        }
                    };
                    self.processes.signal(pid, a[1] as i32).map(|()| 0)
                }
            }
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
    /// `prctl(option, ...)`: PR_SET/GET_NAME (per thread), PR_SET/GET_PDEATHSIG,
    /// PR_SET/GET_DUMPABLE and PR_SET/GET_NO_NEW_PRIVS; any other option is
    /// EINVAL, as Linux gives
    /// for options it does not know.
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
            Some(value) if a[0] == 2 => {
                mem.write(GuestAddr(a[1]), &value.to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
                Ok(0)
            }
            Some(value) => Ok(value as u32 as u64),
            None => Ok(0),
        }
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
    fn return_process_error(&self, thread: &mut Thread, error: Errno) -> Next {
        thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
        Next::Resume
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
        let pid = self.processes.allocate()?;
        let group = Arc::new(self.group.fork(flags & 0x800 != 0));
        // CLONE_CLEAR_SIGHAND resets handled signals to their default and
        // keeps ignored ones, as execve does.
        if flags & CLONE_CLEAR_SIGHAND != 0 {
            group.exec_actions();
        }
        let inbox = Arc::new(SignalInbox::default());
        group.set_process_inbox(inbox.clone());
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
        let child_mem = (flags & 0x100 == 0).then(|| Arc::new(mem.fork()));
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
        self.processes.insert(pid, self.process.pid, group.clone());
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
        self.files.install(pidfd, true).map(u64::from)
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
            Some(false) => self.processes.signal(pidfd.pid, number).map(|()| 0),
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
        let mut memory = AddressSpace::new();
        let image = paludarium_loader::load(&*self.files.fs, &path, &start, &mut memory).map_err(
            |error| match error {
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
        // exec deletes the POSIX timers (the interval timer stays).
        self.group
            .with_timers(&mut thread.state, |timers| timers.clear());
        thread.tid = self.process.pid;
        self.files = self.files.for_exec();
        self.group.exec_actions();
        thread.cpu = CpuState::new(image.entry_point, image.initial_stack_pointer);
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
