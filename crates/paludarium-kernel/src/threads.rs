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
    /// Each thread's nice value, which Linux keeps per thread. The leader's
    /// stays after it exits, as its zombie task does, until the process is
    /// reaped.
    nice: Mutex<BTreeMap<u32, i32>>,
    status: Mutex<Option<ExitStatus>>,
    /// The signal dispositions, which clone with `CLONE_SIGHAND` also shares
    /// with another process (Linux's `sighand_struct`).
    actions: Mutex<Arc<Mutex<BTreeMap<i32, SignalAction>>>>,
    process_inbox: Mutex<Arc<SignalInbox>>,
    process_pending: Mutex<ThreadState>,
    discards: Arc<signals::Discards>,
    timer_generation: AtomicU64,
    /// The RLIMIT_NOFILE soft limit, which bounds the descriptor numbers this
    /// process allocates, and the RLIMIT_FSIZE one, which bounds the files it
    /// writes. The process entry keeps the limit pairs `prlimit` reports.
    nofile: AtomicU64,
    fsize: AtomicU64,
    pub(crate) futexes: Futexes,
    pub(crate) timers: Mutex<crate::timers::Timers>,
    /// Every thread's CPU time, live or exited, for the process's total.
    cpu: Mutex<Vec<Arc<AtomicU64>>>,
    /// The core dump a fatal signal started, which the last thread to end
    /// writes. Locked before `members`.
    pub(crate) core: Mutex<Option<crate::coredump::Dump>>,
    /// The initial stack pointer of the running program (argc, argv, envp
    /// and the auxiliary vector), for a core dump.
    start_stack: AtomicU64,
}
impl Default for ThreadGroup {
    fn default() -> Self {
        Self {
            exec_owner: AtomicU32::new(0),
            retired: Mutex::new(BTreeSet::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            members: Mutex::new(BTreeMap::new()),
            nice: Mutex::default(),
            status: Mutex::new(None),
            actions: Mutex::default(),
            process_inbox: Mutex::new(Arc::new(SignalInbox::default())),
            process_pending: Mutex::new(ThreadState::default()),
            discards: Arc::default(),
            timer_generation: AtomicU64::new(0),
            nofile: AtomicU64::new(1024),
            fsize: AtomicU64::new(u64::MAX),
            futexes: Futexes::default(),
            timers: Mutex::default(),
            cpu: Mutex::default(),
            core: Mutex::default(),
            start_stack: AtomicU64::new(0),
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
        // The thread that ran execve keeps its nice value as the leader.
        let mut nice = self.nice.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(value) = nice.remove(&old_tid) {
            nice.insert(pid, value);
        }
        // execve waited for the other threads to finish, which dropped their
        // values, so only the PID's value is kept.
        nice.retain(|&tid, _| tid == pid);
        drop(nice);
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&pid);
        self.exec_owner.store(0, Ordering::SeqCst);
    }
    /// A new process's group: a copy of the dispositions, or with
    /// `share_actions` (`CLONE_SIGHAND`) the same ones.
    pub(crate) fn fork(&self, share_actions: bool) -> Self {
        let actions = self.shared_actions();
        let actions = if share_actions {
            actions
        } else {
            let copy = actions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            Arc::new(Mutex::new(copy))
        };
        Self {
            actions: Mutex::new(actions),
            nofile: AtomicU64::new(self.nofile()),
            fsize: AtomicU64::new(self.fsize()),
            // A fork keeps the memory, and so the program's initial stack.
            start_stack: AtomicU64::new(self.start_stack()),
            ..Self::default()
        }
    }
    pub(crate) fn nofile(&self) -> u64 {
        self.nofile.load(Ordering::SeqCst)
    }
    pub(crate) fn fsize(&self) -> u64 {
        self.fsize.load(Ordering::SeqCst)
    }
    /// Takes the new soft limit of an enforced resource (RLIMIT_FSIZE or
    /// RLIMIT_NOFILE); the others are only recorded.
    pub(crate) fn set_soft_limit(&self, resource: usize, soft: u64) {
        match resource {
            1 => self.fsize.store(soft, Ordering::SeqCst),
            7 => self.nofile.store(soft, Ordering::SeqCst),
            _ => {}
        }
    }
    pub(crate) fn shared_actions(&self) -> Arc<Mutex<BTreeMap<i32, SignalAction>>> {
        self.actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    pub(crate) fn register_cpu(&self, used: Arc<AtomicU64>) {
        self.cpu
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(used);
    }
    /// The process's CPU time: the sum of its threads' latest accounts.
    pub(crate) fn process_cpu(&self) -> u64 {
        self.cpu
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|used| used.load(Ordering::SeqCst))
            .fold(0u64, u64::saturating_add)
    }
    /// Sends this process SIGCHLD about `child`, with its `CLD_*` `code`.
    pub(crate) fn notify_child(&self, code: i32, child: signals::ChildSignal) {
        let _ = self
            .process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_child(code, child);
    }
    /// Sends this process a signal from process `sender`, as `kill` does.
    pub(crate) fn send_process_from(&self, number: i32, sender: u32) -> Result<(), Errno> {
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_from(number, sender)
    }
    /// Sends this process `signal` as it is.
    pub(crate) fn send_process_signal(&self, signal: signals::PendingSignal) -> Result<(), Errno> {
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_pending(signal)
    }
    /// Sends thread `tid` of this process `signal`, directed at it.
    pub(crate) fn send_thread_signal(
        &self,
        tid: u32,
        signal: signals::PendingSignal,
    ) -> Result<(), Errno> {
        let members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        members
            .get(&tid)
            .ok_or(Errno(3))?
            .send_pending(signals::PendingSignal {
                target: signals::PendingTarget::Thread,
                ..signal
            })
    }
    /// Resets handled signals to their default and keeps ignored ones, as
    /// execve does. The process gets its own copy, so a process sharing the
    /// dispositions through `CLONE_SIGHAND` keeps its handlers.
    pub(crate) fn exec_actions(&self) {
        let mut slot = self.actions.lock().unwrap_or_else(PoisonError::into_inner);
        let kept = slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, action)| action.handler == 1)
            .map(|(&number, &action)| (number, action))
            .collect();
        *slot = Arc::new(Mutex::new(kept));
    }
    pub(crate) fn sync_timer(&self, local: &mut ThreadState) {
        local.timer = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer;
        local.posix_deadline = self.posix_deadline();
    }
    fn posix_deadline(&self) -> Option<u64> {
        self.timers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next_deadline()
    }
    pub(crate) fn set_timer(&self, timer: signals::RealTimer) {
        self.process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer = timer;
        self.timers_changed();
    }
    /// Runs `f` on the POSIX timers, then lets waits see the new deadlines.
    pub(crate) fn with_timers<T>(
        &self,
        local: &mut ThreadState,
        f: impl FnOnce(&mut crate::timers::Timers) -> T,
    ) -> T {
        let result = f(&mut self.timers.lock().unwrap_or_else(PoisonError::into_inner));
        local.posix_deadline = self.posix_deadline();
        self.timers_changed();
        result
    }
    fn timers_changed(&self) {
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
        self.discards.apply(local);
        {
            let mut pending = self
                .process_pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            signals::expire_timer(&mut pending, now);
            let directed = self
                .timers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .expire(&mut pending, now);
            local.timer = pending.timer;
            drop(pending);
            // A thread that has exited loses its timer's signal, as on Linux.
            for (tid, signal) in directed {
                let inbox = self
                    .members
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&tid)
                    .cloned();
                if let Some((id, overrun)) = inbox.and_then(|inbox| inbox.send_timer(signal)) {
                    self.timers
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .set_overrun(id, overrun);
                }
            }
        }
        local.posix_deadline = self.posix_deadline();
        self.drain_process(local);
    }
    pub(crate) fn register(&self, tid: u32, inbox: Arc<SignalInbox>) {
        inbox.attach(Arc::clone(&self.discards));
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
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(tid)
            .or_insert(0);
        if new {
            self.process_inbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .subscribe(&wake);
        }
    }
    /// The nice value of thread `tid`, if it has one (a live thread, or the
    /// leader of an unreaped process).
    pub(crate) fn nice(&self, tid: u32) -> Option<i32> {
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .copied()
    }
    pub(crate) fn set_nice(&self, tid: u32, value: i32) {
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, value);
    }
    /// `setpriority`'s change: only a thread that still has a value, so one
    /// that exited since it was found is not given one again.
    pub(crate) fn update_nice(&self, tid: u32, value: i32) {
        if let Some(nice) = self
            .nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&tid)
        {
            *nice = value;
        }
    }
    /// The nice values of every thread, for `PRIO_PGRP` and `PRIO_USER`.
    pub(crate) fn nices(&self) -> Vec<(u32, i32)> {
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(&tid, &value)| (tid, value))
            .collect()
    }
    fn forget_nice(&self, tid: u32) {
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid);
    }
    pub(crate) fn has_member(&self, tid: u32) -> bool {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&tid)
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
    pub(crate) fn set_start_stack(&self, stack: u64) {
        self.start_stack.store(stack, Ordering::SeqCst);
    }
    pub(crate) fn start_stack(&self) -> u64 {
        self.start_stack.load(Ordering::SeqCst)
    }
    /// Starts a core dump for the fatal signal that ends the process, unless
    /// the process is already ending.
    pub(crate) fn begin_core(&self, dump: crate::coredump::Dump) {
        let mut core = self.core.lock().unwrap_or_else(PoisonError::into_inner);
        if core.is_none() && self.status().is_none() {
            *core = Some(dump);
        }
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
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
    /// Whether this process ignores SIGCHLD and whether it set
    /// SA_NOCLDWAIT, which decide if an exiting child is reaped at once.
    pub(crate) fn child_exit_disposition(&self) -> (bool, bool) {
        self.shared_actions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&signals::SIGCHLD)
            .map_or((false, false), |action| {
                (
                    action.handler == signals::SIG_IGN,
                    action.flags & signals::SA_NOCLDWAIT != 0,
                )
            })
    }
    /// Whether a child's stop or continue sends this process SIGCHLD: not
    /// when it ignores SIGCHLD or set SA_NOCLDSTOP, as in Linux's
    /// `do_notify_parent_cldstop`.
    pub(crate) fn wants_stop_notices(&self) -> bool {
        self.shared_actions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&signals::SIGCHLD)
            .is_none_or(|action| {
                action.handler != signals::SIG_IGN && action.flags & signals::SA_NOCLDSTOP == 0
            })
    }
    /// Starts a group stop; false when the group was already stopped.
    pub(crate) fn job_stop(&self) -> bool {
        !self.stopped.swap(true, Ordering::SeqCst)
    }
    pub(crate) fn job_continue(&self) {
        self.stopped.store(false, Ordering::SeqCst);
    }
    /// Discards the pending instances of signal `number` in the process and
    /// in every thread of it, as `sigaction` does when it makes the signal
    /// ignored (Linux's `flush_sigqueue_mask`). Threads drop the ones they
    /// already took in when they next take in signals or queue one
    /// themselves; `local`, the caller's, drops them now.
    pub(crate) fn discard_pending(&self, number: i32, local: &mut ThreadState) {
        self.discards.mark(number);
        self.discards.apply(local);
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.pending.retain(|signal| signal.number != number);
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .purge(number);
        for inbox in self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            inbox.purge(number);
        }
    }
    /// Drops what `local` holds of signals discarded since they were sent.
    pub(crate) fn apply_discards(&self, local: &mut ThreadState) {
        self.discards.apply(local);
    }
    pub(crate) fn drain_process(&self, local: &mut ThreadState) {
        self.discards.apply(local);
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
    /// Takes the lowest process-directed signal in `set`, even a blocked one
    /// that [`Self::drain_process`] leaves for another thread
    /// (`rt_sigtimedwait`).
    pub(crate) fn take_process_signal(&self, set: u64) -> Option<signals::PendingSignal> {
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_process(&mut pending);
        let index = signals::lowest_in(&pending.pending, set)?;
        Some(pending.pending.remove(index))
    }
    /// The process-directed signals waiting here, as a signal set.
    pub(crate) fn process_pending_set(&self) -> u64 {
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_process(&mut pending);
        pending
            .pending
            .iter()
            .fold(0, |set, signal| set | 1 << (signal.number - 1))
    }
    pub(crate) fn set_action(&self, n: i32, a: SignalAction) {
        self.shared_actions()
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
        self.group.forget_nice(tid);
    }
    pub fn finish_thread(&mut self, thread: &Thread, mem: &AddressSpace) {
        self.files.release_descriptors();
        let addr = thread.state.clear_child_tid;
        // While a core dump is under way, a thread leaves its state for it
        // and its clear_child_tid word stays until the core is written, as
        // Linux dumps before the threads exit.
        let mut core = self
            .group
            .core
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(dump) = core.as_mut() {
            dump.threads.push(crate::coredump::ThreadCore {
                tid: thread.tid,
                cpu: thread.cpu.clone(),
                pending: thread
                    .state
                    .pending
                    .iter()
                    .fold(0, |set, s| set | 1u64 << (s.number - 1)),
                blocked: thread.state.signal_mask,
                name: thread.state.name,
            });
            if addr != 0 {
                dump.clear_tids.push(addr);
            }
        } else {
            Self::clear_child_tid(&self.group, mem, addr);
        }
        // The last thread writes the core while it still counts, so that no
        // other thread's completion records the exit before it is dumped.
        let last = {
            let members = self
                .group
                .members
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            members.len() == 1 && members.contains_key(&thread.tid)
        };
        if last && let Some(dump) = core.take() {
            self.write_core(&dump, mem);
            for addr in dump.clear_tids {
                Self::clear_child_tid(&self.group, mem, addr);
            }
        }
        self.group
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&thread.tid);
        drop(core);
        if thread.tid != self.process.pid {
            self.group.forget_nice(thread.tid);
        }
    }
    fn clear_child_tid(group: &ThreadGroup, mem: &AddressSpace, addr: u64) {
        if addr != 0 && mem.write(GuestAddr(addr), &0u32.to_le_bytes()).is_ok() {
            let _ = group.futexes.wake(mem, addr, false, 1, u32::MAX);
        }
    }
    /// Writes the core of `dump` to `core` in the working directory. Once the
    /// file is made the process counts as dumped, even if the core is cut at
    /// the limit, as Linux's binfmt_elf sets `has_dumped` before it writes.
    fn write_core(&self, dump: &crate::coredump::Dump, mem: &AddressSpace) {
        let pid = self.process.pid;
        let Some(identity) =
            self.processes
                .core_identity(pid, self.group.process_cpu(), self.group.start_stack())
        else {
            return;
        };
        let Ok(file) = self.files.create_core() else {
            return;
        };
        self.processes.set_dumped(pid);
        crate::coredump::write(dump, &identity, mem, &mut |piece| {
            let mut at = 0;
            while at < piece.len() {
                match file.write(&piece[at..]) {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => at += n,
                }
            }
            true
        });
    }
    pub(crate) fn sync_actions(&mut self, thread: &mut Thread) {
        let actions = self.group.shared_actions();
        let shared = actions.lock().unwrap_or_else(PoisonError::into_inner);
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
            // restart_syscall resuming a timed futex wait a stop interrupted.
            219 if matches!(
                thread.state.restart_block,
                Some(signals::RestartBlock::Futex { .. })
            ) =>
            {
                let Some(signals::RestartBlock::Futex {
                    uaddr,
                    value,
                    private,
                    mask,
                    clock,
                    deadline,
                }) = thread.state.restart_block.take()
                else {
                    unreachable!("matched above")
                };
                self.futex_wait_until(
                    thread,
                    mem,
                    uaddr,
                    value,
                    private,
                    mask,
                    clock,
                    Some(deadline),
                )
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
            // The events Tokio native trace observes it on both worker creations.
            | 0x400000
            | 0x1000000;
        if flags & THREAD != 0 && flags & SIGHAND == 0 || flags & SIGHAND != 0 && flags & VM == 0 {
            return Err(Errno::EINVAL);
        }
        if flags & THREAD == 0 {
            return Err(Errno::ENOSYS);
        } // Process clone/fork is handled by the processes code.
        if flags & !known != 0 || flags & VM == 0 {
            return Err(Errno::EINVAL);
        }
        if a[1] >= paludarium_types::USER_ADDRESS_LIMIT
            || flags & 0x80000 != 0 && a[4] >= paludarium_types::USER_ADDRESS_LIMIT
        {
            return Err(Errno::EPERM);
        }
        let task = self.processes.charge_task()?;
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
            unimplemented: self.unimplemented.clone(),
            task: Some(task),
        };
        // A new thread starts with its creator's nice value, set before it
        // is registered so that no one sees it without one.
        if let Some(value) = self.group.nice(parent.tid) {
            self.group.set_nice(tid, value);
        }
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
        self.futex_wait_until(
            thread,
            mem,
            a[0],
            a[2] as u32,
            private,
            mask,
            clock,
            deadline,
        )
    }
    /// The wait of FUTEX_WAIT and FUTEX_WAIT_BITSET until `deadline` (on
    /// `clock`), or without one. Interrupted with a deadline, a stop resumes
    /// it through `restart_syscall` with the same deadline, rechecking the
    /// value first, as Linux's `futex_wait_restart` does.
    #[allow(clippy::too_many_arguments)]
    fn futex_wait_until(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        uaddr: u64,
        value: u32,
        private: bool,
        mask: u32,
        clock: ClockId,
        deadline: Option<u64>,
    ) -> Result<u64, Errno> {
        let result = self.futex_wait_on(thread, mem, uaddr, value, private, mask, clock, deadline);
        if result == Err(Errno(4))
            && let Some(deadline) = deadline
        {
            thread.state.restart = Some(219);
            thread.state.restart_block = Some(signals::RestartBlock::Futex {
                uaddr,
                value,
                private,
                mask,
                clock,
                deadline,
            });
        }
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn futex_wait_on(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        uaddr: u64,
        value: u32,
        private: bool,
        mask: u32,
        clock: ClockId,
        deadline: Option<u64>,
    ) -> Result<u64, Errno> {
        let waiter = self
            .group
            .futexes
            .register(mem, uaddr, private, value, mask)?;
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
                    self.group.futexes.finish(mem, uaddr, private, &waiter, 3);
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
                    .finish(mem, uaddr, private, &waiter, result);
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
                        self.group.futexes.finish(mem, uaddr, private, &waiter, 3);
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
