//! Shared process termination, signal dispositions, registry and futex queues.
//! Each worker owns its Kernel thread context; no process lock spans CPU/I/O/wait.
use crate::{
    AltStack, Kernel, Next, SignalAction, SignalInbox, Thread, ThreadState, futex::Futexes, signals,
};
use paludarium_cpu::reg;
use paludarium_host::{ClockId, WaitOutcome};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, ExitStatus, GuestAddr};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

pub struct ThreadGroup {
    exec_owner: AtomicU32,
    retired: Mutex<BTreeSet<u32>>,
    stopped: std::sync::atomic::AtomicBool,
    members: Mutex<BTreeMap<u32, Arc<SignalInbox>>>,
    status: Mutex<Option<ExitStatus>>,
    actions: Mutex<BTreeMap<i32, SignalAction>>,
    process_inbox: Mutex<Arc<SignalInbox>>,
    process_pending: Mutex<ThreadState>,
    timer_generation: AtomicU64,
    pub(crate) futexes: Futexes,
}
impl Default for ThreadGroup {
    fn default() -> Self {
        Self {
            exec_owner: AtomicU32::new(0),
            retired: Mutex::new(BTreeSet::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            members: Mutex::new(BTreeMap::new()),
            status: Mutex::new(None),
            actions: Mutex::new(BTreeMap::new()),
            process_inbox: Mutex::new(Arc::new(SignalInbox::default())),
            process_pending: Mutex::new(ThreadState::default()),
            timer_generation: AtomicU64::new(0),
            futexes: Futexes::default(),
        }
    }
}
impl ThreadGroup {
    pub(crate) fn retired(&self, tid: u32) -> bool {
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&tid)
    }
    pub(crate) fn begin_exec(&self, tid: u32) -> Result<(), Errno> {
        self.exec_owner
            .compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Errno(4))?;
        let members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let mut retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
        for (&other, inbox) in members.iter() {
            if other != tid {
                retired.insert(other);
                inbox.interrupt();
            }
        }
        Ok(())
    }
    pub(crate) fn end_exec(&self, old_tid: u32, pid: u32, inbox: Arc<SignalInbox>) {
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        members.remove(&old_tid);
        members.insert(pid, inbox);
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&pid);
        self.exec_owner.store(0, Ordering::SeqCst);
    }
    pub(crate) fn fork(&self) -> Self {
        Self {
            actions: Mutex::new(
                self.actions
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ),
            ..Self::default()
        }
    }
    pub(crate) fn notify_child(&self) {
        let _ = self
            .process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(17);
    }
    pub(crate) fn send_process(&self, number: i32) -> Result<(), Errno> {
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(number)
    }
    pub(crate) fn exec_actions(&self) {
        self.actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, action| action.handler == 1);
    }
    pub(crate) fn sync_timer(&self, local: &mut ThreadState) {
        local.timer = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer;
    }
    pub(crate) fn set_timer(&self, timer: signals::RealTimer) {
        self.process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer = timer;
        self.timer_generation.fetch_add(1, Ordering::SeqCst);
        // A timer update is a deadline change, not a signal. Existing Host waits
        // must return so they can recompute the shared deadline.
        for inbox in self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            inbox.timer_changed();
        }
    }
    pub(crate) fn timer_generation(&self) -> u64 {
        self.timer_generation.load(Ordering::SeqCst)
    }
    pub(crate) fn expire_timer(&self, local: &mut ThreadState, now: u64) {
        {
            let mut pending = self
                .process_pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            signals::expire_timer(&mut pending, now);
            local.timer = pending.timer;
        }
        self.drain_process(local);
    }
    pub(crate) fn register(&self, tid: u32, inbox: Arc<SignalInbox>) {
        let wake = inbox.wake_token();
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let owner = self.exec_owner.load(Ordering::SeqCst);
        if owner != 0 && owner != tid {
            self.retired
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(tid);
            inbox.interrupt();
        }
        let new = members.insert(tid, inbox).is_none();
        drop(members);
        if new {
            self.process_inbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .subscribe(&wake);
        }
    }
    pub fn status(&self) -> Option<ExitStatus> {
        *self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
    pub fn active_threads(&self) -> usize {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
    pub fn stop(&self, status: ExitStatus) {
        let mut current = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        if current.is_none() {
            *current = Some(status);
        }
        for inbox in self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            inbox.interrupt();
        }
    }
    fn send(&self, tid: u32, number: i32) -> Result<(), Errno> {
        let members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let inbox = members.get(&tid).ok_or(Errno(3))?;
        if number == 0 {
            return Ok(());
        }
        inbox.send_thread(number)
    }
    pub(crate) fn set_process_inbox(&self, inbox: Arc<SignalInbox>) {
        *self
            .process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = inbox;
    }
    pub(crate) fn job_stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
    pub(crate) fn job_continue(&self) {
        self.stopped.store(false, Ordering::SeqCst);
    }
    pub(crate) fn drain_process(&self, local: &mut ThreadState) {
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_process(&mut pending);
        if pending.pending.iter().any(|s| s.number == 18) {
            self.stopped.store(false, Ordering::SeqCst);
        }
        pending.signal_mask = local.signal_mask;
        pending.signal_actions = local.signal_actions.clone();
        while let Some(index) = signals::next_pending(&pending, false) {
            let s = pending.pending.remove(index);
            signals::queue(local, s);
        }
        local.stopped = self.stopped.load(Ordering::SeqCst);
    }
    pub(crate) fn set_action(&self, n: i32, a: SignalAction) {
        self.actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(n, a);
    }
}
impl Kernel {
    #[must_use]
    pub fn thread_group(&self) -> Arc<ThreadGroup> {
        self.group.clone()
    }
    pub fn take_child(&mut self) -> Option<(Box<Kernel>, Thread)> {
        self.pending_child.take()
    }
    pub fn abandon_thread(&self, tid: u32) {
        self.group
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid);
    }
    pub fn finish_thread(&mut self, thread: &Thread, mem: &AddressSpace) {
        self.files.release_descriptors();
        let addr = thread.state.clear_child_tid;
        if addr != 0 && mem.write(GuestAddr(addr), &0u32.to_le_bytes()).is_ok() {
            let _ = self.group.futexes.wake(mem, addr, false, 1, u32::MAX);
        }
        self.group
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&thread.tid);
    }
    pub(crate) fn sync_actions(&mut self, thread: &mut Thread) {
        let shared = self
            .group
            .actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (&n, &a) in shared.iter() {
            thread.state.signal_actions.insert(n, a);
        }
    }
    pub(crate) fn thread_syscall(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        n: u64,
        a: [u64; 6],
    ) -> Option<Next> {
        let result = match n {
            56 => self.clone_thread(thread, mem, a),
            186 => Ok(u64::from(thread.tid)),
            218 => {
                thread.state.clear_child_tid = a[0];
                Ok(u64::from(thread.tid))
            }
            60 => {
                return Some(Next::Exit(ExitStatus::Exited((a[0] & 255) as i32)));
            }
            231 => {
                let status = ExitStatus::Exited((a[0] & 255) as i32);
                thread.state.exit_status = Some(status);
                self.group.stop(status);
                return Some(Next::Exit(status));
            }
            202 => self.futex_wait(thread, mem, a),
            62 => {
                if a[1] > 64 {
                    Err(Errno::EINVAL)
                } else if a[0] != 0 && a[0] != u64::from(self.process.pid) {
                    Err(Errno(3))
                } else if a[1] == 0 {
                    Ok(0)
                } else {
                    self.group
                        .process_inbox
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .send(a[1] as i32)
                        .map(|()| 0)
                }
            }
            200 | 234 => {
                let (tid, number) = if n == 234 {
                    if a[0] != u64::from(self.process.pid) {
                        return Some(self.return_error(thread, Errno(3)));
                    }
                    (a[1], a[2])
                } else {
                    (a[0], a[1])
                };
                if number > 64 {
                    Err(Errno::EINVAL)
                } else {
                    u32::try_from(tid)
                        .map_err(|_| Errno(3))
                        .and_then(|tid| self.group.send(tid, number as i32))
                        .map(|()| 0)
                }
            }
            _ => return None,
        };
        thread.cpu.gpr[reg::RAX] = result.unwrap_or_else(Errno::to_syscall_return);
        // Native WAIT/WAIT_BITSET without a timeout restart after SA_RESTART.
        // Timed waits return EINTR instead (native cases36/37); replaying their
        // relative request would also incorrectly extend its deadline.
        if n == 202
            && matches!(a[1] & !128, 0 | 9 | 265)
            && a[3] == 0
            && result == Err(Errno(4))
            && signals::next_pending(&thread.state, true)
                .and_then(|index| {
                    thread
                        .state
                        .signal_actions
                        .get(&thread.state.pending[index].number)
                })
                .is_some_and(|action| action.handler > 1 && action.flags & 0x1000_0000 != 0)
            && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
        {
            // The handler's saved context resumes the syscall, rechecking the
            // futex value when it returns (including a handler's value change).
            thread.cpu.rip = GuestAddr(rip);
            thread.cpu.gpr[reg::RAX] = n;
        }
        Some(self.checkpoint(thread, mem))
    }
    fn return_error(&self, thread: &mut Thread, error: Errno) -> Next {
        thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
        Next::Resume
    }
    fn clone_thread(
        &mut self,
        parent: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        const VM: u64 = 0x100;
        const SIGHAND: u64 = 0x800;
        const THREAD: u64 = 0x10000;
        let flags = a[0];
        let known = VM
            | 0x200
            | 0x400
            | SIGHAND
            | THREAD
            | 0x40000
            | 0x80000
            | 0x100000
            | 0x200000
            // musl's pthread clone retains this obsolete, ignored Linux bit.
            // U6 Tokio native trace observes it on both worker creations.
            | 0x400000
            | 0x1000000;
        if flags & THREAD != 0 && flags & SIGHAND == 0 || flags & SIGHAND != 0 && flags & VM == 0 {
            return Err(Errno::EINVAL);
        }
        if flags & THREAD == 0 {
            return Err(Errno::ENOSYS);
        } // U8 owns process clone/fork.
        if flags & !known != 0 || flags & VM == 0 {
            return Err(Errno::EINVAL);
        }
        if a[1] >= paludarium_types::USER_ADDRESS_LIMIT
            || flags & 0x80000 != 0 && a[4] >= paludarium_types::USER_ADDRESS_LIMIT
        {
            return Err(Errno::EPERM);
        }
        let tid = self.processes.allocate()?;
        if tid > i32::MAX as u32 {
            return Err(Errno::EAGAIN);
        }
        let mut cpu = parent.cpu.clone();
        cpu.gpr[reg::RAX] = 0;
        if a[1] != 0 {
            cpu.gpr[reg::RSP] = a[1];
        }
        if flags & 0x80000 != 0 {
            cpu.fs_base = a[4];
        }
        let mut state = parent.state.clone();
        state.timer = signals::RealTimer::default();
        state.pending.clear();
        state.frames.clear();
        state.alt_stack = AltStack::default();
        state.exit_status = None;
        state.clear_child_tid = if flags & 0x200000 != 0 { a[3] } else { 0 };
        let inbox = Arc::new(SignalInbox::default());
        let child = Kernel {
            host: self.host.clone(),
            process: self.process.clone(),
            table: crate::SyscallTable::u1(),
            files: self.files.for_clone(flags & 0x400 != 0, flags & 0x200 != 0),
            cancellation: inbox.wake_token(),
            inbox: inbox.clone(),
            group: self.group.clone(),
            pending_child: None,
            processes: self.processes.clone(),
            spawn_memory: None,
            exec_memory: None,
            vfork_release: self.vfork_release.clone(),
            vfork_wait: None,
        };
        self.group.register(tid, inbox);
        // Linux ignores unsuccessful parent/child TID stores (native case 23).
        if flags & 0x100000 != 0 {
            let _ = mem.write(GuestAddr(a[2]), &tid.to_le_bytes());
        }
        if flags & 0x1000000 != 0 {
            let _ = mem.write(GuestAddr(a[3]), &tid.to_le_bytes());
        }
        self.pending_child = Some((Box::new(child), Thread { tid, cpu, state }));
        Ok(u64::from(tid))
    }
    fn futex_wait(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let op = a[1] & !128;
        let private = a[1] & 128 != 0;
        let mask = if matches!(op, 9 | 10 | 265) {
            a[5] as u32
        } else {
            u32::MAX
        };
        if matches!(op, 1 | 10) {
            return self
                .group
                .futexes
                .wake(mem, a[0], private, a[2] as u32, mask);
        }
        if !matches!(op, 0 | 9 | 265) {
            return Err(Errno::ENOSYS);
        }
        if a[0] & 3 != 0 || mask == 0 {
            return Err(Errno::EINVAL);
        }
        let clock = if op == 265 {
            ClockId::Realtime
        } else {
            ClockId::Monotonic
        };
        let deadline = if a[3] != 0 {
            let mut b = [0; 16];
            mem.read(GuestAddr(a[3]), &mut b)
                .map_err(|_| Errno::EFAULT)?;
            let seconds = i64::from_le_bytes(b[..8].try_into().map_err(|_| Errno::EINVAL)?);
            let ns = i64::from_le_bytes(b[8..].try_into().map_err(|_| Errno::EINVAL)?);
            if seconds < 0 || !(0..1_000_000_000).contains(&ns) {
                return Err(Errno::EINVAL);
            }
            let value = (seconds as u64)
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(ns as u64))
                .ok_or(Errno::EINVAL)?;
            Some(if op == 0 {
                self.host.clock(clock)?.saturating_add(value)
            } else {
                value
            })
        } else {
            None
        };
        let waiter = self
            .group
            .futexes
            .register(mem, a[0], private, a[2] as u32, mask)?;
        let mut interrupted = false;
        loop {
            let state = waiter.state.load(Ordering::SeqCst);
            if state != 0 {
                return if state == 1 {
                    Ok(0)
                } else {
                    Err(Errno(if state == 2 { 110 } else { 4 }))
                };
            }
            self.group.drain_process(&mut thread.state);
            interrupted |= self.inbox.drain(&mut thread.state).interrupted;
            interrupted |= !self.inbox.owns_wake(&self.cancellation)
                && self.cancellation.load(Ordering::SeqCst);
            if let Ok(now) = self.host.clock(ClockId::Monotonic) {
                self.group.expire_timer(&mut thread.state, now);
            }
            let now = match self.host.clock(clock) {
                Ok(now) => now,
                Err(error) => {
                    self.group.futexes.finish(mem, a[0], private, &waiter, 3);
                    return Err(error);
                }
            };
            let result = if self.group.status().is_some()
                || signals::next_pending(&thread.state, true).is_some()
                || interrupted
            {
                3
            } else if deadline.is_some_and(|end| now >= end) {
                2
            } else {
                0
            };
            if result != 0 {
                self.group
                    .futexes
                    .finish(mem, a[0], private, &waiter, result);
                continue;
            }
            let end = deadline
                .unwrap_or(u64::MAX)
                .min(now.saturating_add(10_000_000));
            let outcome =
                match self
                    .host
                    .wait_on(&waiter.token, 0, Some((clock, end)), &self.cancellation)
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        self.group.futexes.finish(mem, a[0], private, &waiter, 3);
                        return Err(error);
                    }
                };
            if outcome == WaitOutcome::Interrupted {
                interrupted |= self.inbox.drain(&mut thread.state).interrupted;
            }
        }
    }
}

#[cfg(test)]
mod exec_thread_tests {
    use super::*;
    fn group() -> ThreadGroup {
        let group = ThreadGroup::default();
        group.register(1, Arc::default());
        group.register(2, Arc::default());
        group
    }
    #[test]
    fn retires_only_sibling() {
        let group = group();
        group.begin_exec(1).unwrap();
        assert!(!group.retired(1));
        assert!(group.retired(2));
        assert_eq!(group.status(), None);
    }
    #[test]
    fn retirement_wakes_blocked_sibling() {
        let group = group();
        let inbox = group.members.lock().unwrap().get(&2).unwrap().clone();
        group.begin_exec(1).unwrap();
        assert!(inbox.drain(&mut ThreadState::default()).interrupted);
    }
    #[test]
    fn racing_exec_has_one_owner() {
        let group = group();
        group.begin_exec(1).unwrap();
        assert_eq!(group.begin_exec(2), Err(Errno(4)));
    }
    #[test]
    fn late_clone_is_retired() {
        let group = group();
        group.begin_exec(1).unwrap();
        group.register(3, Arc::default());
        assert!(group.retired(3));
    }
    #[test]
    fn single_thread_exec_keeps_process_live() {
        let group = ThreadGroup::default();
        group.register(1, Arc::default());
        group.begin_exec(1).unwrap();
        assert!(!group.retired(1));
        assert_eq!(group.active_threads(), 1);
        assert_eq!(group.status(), None);
    }
    #[test]
    fn nonleader_becomes_leader() {
        let group = group();
        group.begin_exec(2).unwrap();
        group.members.lock().unwrap().remove(&1);
        group.end_exec(2, 1, Arc::default());
        assert!(!group.retired(1));
        assert_eq!(group.active_threads(), 1);
        assert!(group.members.lock().unwrap().contains_key(&1));
    }
    #[test]
    fn subsequent_exec_can_acquire_owner() {
        let group = group();
        group.begin_exec(1).unwrap();
        group.members.lock().unwrap().remove(&2);
        group.end_exec(1, 1, Arc::default());
        assert_eq!(group.begin_exec(1), Ok(()));
    }
}
