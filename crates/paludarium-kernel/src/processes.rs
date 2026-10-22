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
        let parent = if let Some(entry) = entries.get_mut(&pid) {
            if entry.group.active_threads() != 0 {
                return;
            }
            entry.status = Some(entry.group.status().unwrap_or(status));
            entry.parent
        } else {
            return;
        };
        if let Some(parent) = entries.get(&parent) {
            parent.group.notify_child();
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
    pub(crate) fn reap(
        &self,
        parent: u32,
        wanted: i64,
    ) -> Result<Option<(u32, ExitStatus)>, Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let matching = |pid: u32, entry: &Entry| {
            entry.parent == parent && (wanted == -1 || wanted == 0 || wanted == i64::from(pid))
        };
        if !entries.iter().any(|(&pid, entry)| matching(pid, entry)) {
            return Err(Errno(10));
        }
        let ready = entries.iter().find_map(|(&pid, entry)| {
            (matching(pid, entry))
                .then_some(entry.status)
                .flatten()
                .map(|status| (pid, status))
        });
        if let Some((pid, _)) = ready {
            entries.remove(&pid);
        }
        Ok(ready)
    }
    fn signal(&self, pid: u32, number: i32) -> Result<(), Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid).ok_or(Errno(3))?;
        if number == 0 {
            Ok(())
        } else {
            entry.group.send_process(number)
        }
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
        if n == 61
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
            | 0x1000000;
        if flags & 0x800 != 0 && flags & 0x100 == 0 || flags & 0xff > 64 {
            return Err(Errno::EINVAL);
        }
        if flags & !known != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & 0x800 != 0 {
            return Err(Errno::ENOSYS);
        } // Shared dispositions require their own ownership model.
        if a[1] >= paludarium_types::USER_ADDRESS_LIMIT
            || flags & 0x80000 != 0 && a[4] >= paludarium_types::USER_ADDRESS_LIMIT
        {
            return Err(Errno::EPERM);
        }
        let pid = self.processes.allocate()?;
        let group = Arc::new(self.group.fork());
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
        loop {
            if let Some((pid, status)) = self.processes.reap(self.process.pid, a[0] as i64)? {
                let raw = match status {
                    ExitStatus::Exited(code) => (code & 255) << 8,
                    ExitStatus::Signaled(signal) => signal & 127,
                    _ => return Err(Errno::EINVAL),
                };
                // Native wait-fault oracle: Linux consumes the zombie before copyout.
                if a[1] != 0 {
                    mem.write(GuestAddr(a[1]), &raw.to_le_bytes())
                        .map_err(|_| Errno::EFAULT)?;
                }
                if a[3] != 0 {
                    mem.write(GuestAddr(a[3]), &[0; 144])
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
        thread.state = ThreadState {
            pid: self.process.pid,
            signal_mask: thread.state.signal_mask,
            signal_actions: ignored,
            ..ThreadState::default()
        };
        thread.state.name_after(&path);
        self.exec_memory = Some(Arc::new(memory));
        self.release_vfork();
        Ok(())
    }
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
