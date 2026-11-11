//! Shared process termination, signal dispositions, registry and futex queues.
//! Each worker owns its Kernel thread context; no process lock spans CPU/I/O/wait.
use crate::credentials::TaskIds;
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
    /// Each thread's scheduling attributes and I/O priority, kept as its
    /// nice value is; one without has the defaults.
    sched: Mutex<BTreeMap<u32, crate::scheduling::Sched>>,
    /// The CPU mask `sched_setaffinity` gave each thread, which Linux keeps
    /// per thread; one without lets every CPU run it.
    affinity: Mutex<BTreeMap<u32, Vec<u64>>>,
    /// How many times a CPU mask has been set, so that a thread on a
    /// virtual CPU reads its mask again only after a change.
    affinity_changes: std::sync::atomic::AtomicU64,
    /// The NUMA memory policies of its threads and of its address space.
    numa: crate::mempolicy::Numa,
    /// What signalling each thread looks at, for other processes to read;
    /// a thread without one is root's ([`TaskIds`]).
    task_ids: Mutex<BTreeMap<u32, TaskIds>>,
    /// Each thread's namespaces, which Linux keeps per thread (`nsproxy`),
    /// for the thread itself and for other processes to read; a thread
    /// without them has the first ones, which every process made from this
    /// one shares.
    namespaces: Mutex<BTreeMap<u32, Arc<crate::namespaces::Namespaces>>>,
    first_namespaces: Arc<crate::namespaces::Namespaces>,
    /// The last `LANDLOCK_RESTRICT_SELF_TSYNC`: its number and the domain
    /// every thread takes when it next enters the kernel.
    landlock_syncs: AtomicU64,
    landlock_sync: Mutex<crate::landlock::Landlock>,
    status: Mutex<Option<ExitStatus>>,
    /// The signal dispositions, which clone with `CLONE_SIGHAND` also shares
    /// with another process (Linux's `sighand_struct`).
    actions: Mutex<Arc<Mutex<BTreeMap<i32, SignalAction>>>>,
    process_inbox: Mutex<Arc<SignalInbox>>,
    process_pending: Mutex<ThreadState>,
    discards: Arc<signals::Discards>,
    /// The signals the threads' drains made pending, for the signal files
    /// of the other threads ([`SignalInbox::others_arrivals`]).
    arrivals: Arc<AtomicU64>,
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
    /// The head `set_robust_list` gave each thread that called it.
    robust_lists: Mutex<BTreeMap<u32, u64>>,
    /// Each thread's System V semaphore undo list, once it has one, which
    /// `CLONE_SYSVSEM` shares (Linux's `sysvsem.undo_list`).
    sem_undo: Mutex<BTreeMap<u32, Arc<crate::sem::UndoList>>>,
    /// The path of the program the process runs, which `/proc/self/exe`
    /// names (Linux's `exe_file`).
    executable: Mutex<Vec<u8>>,
    /// The denial of writes to that program's file, which the process holds
    /// while it runs it, and a fork shares (Linux's `exe_file`, which
    /// `dup_mm_exe_file` denies again); none for a program of no regular
    /// file.
    exe_file: Mutex<Option<Arc<crate::page_cache::WriteAccess>>>,
    /// What each thread keeps itself that other processes read in `/proc`,
    /// as of its last checkpoint. The leader's stays while it is a zombie.
    public: Mutex<BTreeMap<u32, PublicThread>>,
    /// The process is the init of a nested PID namespace, which takes only
    /// the signals it handles, and SIGKILL and SIGSTOP from outside (Linux's
    /// SIGNAL_UNKILLABLE), until a fault ends it.
    unkillable: std::sync::atomic::AtomicBool,
}
/// What `/proc/<pid>` shows another process of a thread: its name, signal
/// state and credentials, and its process's memory and files, which it
/// does not keep alive.
#[derive(Clone, Default)]
pub(crate) struct PublicThread {
    pub name: [u8; 16],
    pub blocked: u64,
    /// The signals pending for it, and how many are queued.
    pub pending: u64,
    pub queued: usize,
    pub credentials: crate::credentials::Credentials,
    pub memory: Option<paludarium_mmu::MemoryView>,
    pub files: crate::files::FilesView,
}
impl Default for ThreadGroup {
    fn default() -> Self {
        Self {
            exec_owner: AtomicU32::new(0),
            retired: Mutex::new(BTreeSet::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            members: Mutex::new(BTreeMap::new()),
            nice: Mutex::default(),
            sched: Mutex::default(),
            affinity: Mutex::default(),
            affinity_changes: std::sync::atomic::AtomicU64::new(0),
            numa: crate::mempolicy::Numa::default(),
            task_ids: Mutex::default(),
            namespaces: Mutex::default(),
            first_namespaces: Arc::default(),
            landlock_syncs: AtomicU64::new(0),
            landlock_sync: Mutex::default(),
            status: Mutex::new(None),
            actions: Mutex::default(),
            process_inbox: Mutex::new(Arc::new(SignalInbox::default())),
            process_pending: Mutex::new(ThreadState::default()),
            discards: Arc::default(),
            arrivals: Arc::default(),
            timer_generation: AtomicU64::new(0),
            nofile: AtomicU64::new(1024),
            fsize: AtomicU64::new(u64::MAX),
            futexes: Futexes::machine(),
            timers: Mutex::default(),
            cpu: Mutex::default(),
            core: Mutex::default(),
            start_stack: AtomicU64::new(0),
            robust_lists: Mutex::default(),
            sem_undo: Mutex::default(),
            executable: Mutex::default(),
            exe_file: Mutex::default(),
            public: Mutex::default(),
            unkillable: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl ThreadGroup {
    /// Whether the process is the init of a nested PID namespace.
    pub(crate) fn unkillable(&self) -> bool {
        self.unkillable.load(Ordering::SeqCst)
    }
    /// Whether the init of a nested PID namespace drops signal `number`
    /// (1 to 64) as it is sent, as Linux's `sig_task_ignored` with
    /// SIGNAL_UNKILLABLE: it has no handler for it, the receiving thread
    /// does not block it (`blocked`), and it is not SIGKILL or SIGSTOP
    /// `forced`, from outside the namespace or by the kernel.
    pub(crate) fn drops_as_init(&self, number: i32, forced: bool, blocked: u64) -> bool {
        let handled = self
            .shared_actions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&number)
            .is_some_and(|action| action.handler != 0);
        self.unkillable()
            && !handled
            && blocked & (1u64 << (number - 1)) == 0
            && !(forced && matches!(number, 9 | 19))
    }
    /// The signals thread `tid` last published as blocked.
    pub(crate) fn blocked(&self, tid: u32) -> u64 {
        self.public(tid).map_or(0, |thread| thread.blocked)
    }
    /// Makes the process the init of a nested PID namespace.
    pub(crate) fn set_unkillable(&self) {
        self.unkillable.store(true, Ordering::SeqCst);
    }
    /// Keeps the robust list head of `tid`.
    pub(crate) fn set_robust_list(&self, tid: u32, head: u64) {
        self.robust_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, head);
    }
    /// The robust list head of `tid`, 0 if it has none, or `None` if no such
    /// thread is in this group.
    pub(crate) fn robust_list(&self, tid: u32) -> Option<u64> {
        if !self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&tid)
        {
            return None;
        }
        Some(
            self.robust_lists
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&tid)
                .copied()
                .unwrap_or(0),
        )
    }
    /// Takes the robust list head of `tid`, as it ends or calls `execve`.
    pub(crate) fn take_robust_list(&self, tid: u32) -> Option<u64> {
        self.robust_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid)
    }
    /// The undo list of `tid`, which it is given now if it has none
    /// (Linux's `get_undo_list`).
    pub(crate) fn sem_undo_list(&self, tid: u32) -> Arc<crate::sem::UndoList> {
        Arc::clone(
            self.sem_undo
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(tid)
                .or_insert_with(crate::sem::UndoList::new),
        )
    }
    /// Gives `tid` the undo list `list`.
    pub(crate) fn set_sem_undo_list(&self, tid: u32, list: Arc<crate::sem::UndoList>) {
        self.sem_undo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, list);
    }
    /// Takes the undo list of `tid`, as it ends or leaves it.
    pub(crate) fn take_sem_undo_list(&self, tid: u32) -> Option<Arc<crate::sem::UndoList>> {
        self.sem_undo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid)
    }
    /// Thread `tid` of process `pid` leaves its undo list, if it has one,
    /// which the last thread to leave applies (`exit_sem`).
    pub(crate) fn leave_sem_undo_list(&self, tid: u32, pid: u32, now: i64) {
        if let Some(list) = self.take_sem_undo_list(tid) {
            list.leave(pid, now);
        }
    }
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
        let mut sched = self.sched.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(value) = sched.remove(&old_tid) {
            sched.insert(pid, value);
        }
        sched.retain(|&tid, _| tid == pid);
        drop(sched);
        // So is the record of the thread that ran it, until it publishes
        // what the new program shows.
        let mut public = self.public.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(record) = public.remove(&old_tid) {
            public.insert(pid, record);
        }
        public.retain(|&tid, _| tid == pid);
        drop(public);
        // So does its CPU mask.
        let mut affinity = self.affinity.lock().unwrap_or_else(PoisonError::into_inner);
        let kept = affinity.remove(&old_tid);
        affinity.clear();
        if let Some(mask) = kept {
            affinity.insert(pid, mask);
        }
        drop(affinity);
        // And its memory policy; the new address space has none of its own.
        self.numa.exec(old_tid, pid);
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
            // A fork keeps the memory, and so the program's initial stack
            // and the program itself (Linux's `exe_file`).
            start_stack: AtomicU64::new(self.start_stack()),
            executable: Mutex::new(self.executable()),
            first_namespaces: self.first_namespaces.clone(),
            exe_file: Mutex::new(
                self.exe_file
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ),
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
    /// Sends this process a signal from process `sender`, whose real user
    /// ID is `uid`, as `kill` does.
    pub(crate) fn send_process_from(
        &self,
        number: i32,
        sender: u32,
        uid: u32,
    ) -> Result<(), Errno> {
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_from(number, sender, uid)
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
    #[cfg(test)]
    pub(crate) fn set_timer(&self, timer: signals::RealTimer) {
        self.process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer = timer;
        self.timers_changed();
    }
    /// The process's interval timer, once what is due at `now` has expired,
    /// replaced by `new` when there is one; what it was before.
    pub(crate) fn swap_timer(
        &self,
        local: &mut ThreadState,
        now: u64,
        new: Option<signals::RealTimer>,
    ) -> signals::RealTimer {
        self.expire_timer(local, now);
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let old = pending.timer;
        if let Some(new) = new {
            pending.timer = new;
        }
        local.timer = pending.timer;
        drop(pending);
        if new.is_some() {
            self.timers_changed();
        }
        old
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
        inbox.attach(Arc::clone(&self.discards), Arc::clone(&self.arrivals));
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
    /// The NUMA memory policies ([`crate::mempolicy`]).
    pub(crate) fn numa(&self) -> &crate::mempolicy::Numa {
        &self.numa
    }
    /// The CPU mask of thread `tid`, if `sched_setaffinity` gave it one.
    pub(crate) fn affinity(&self, tid: u32) -> Option<Vec<u64>> {
        self.affinity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .cloned()
    }
    pub(crate) fn set_affinity(&self, tid: u32, mask: Vec<u64>) {
        self.affinity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, mask);
        self.affinity_changes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    /// Changes with every [`Self::set_affinity`].
    pub(crate) fn affinity_generation(&self) -> u64 {
        self.affinity_changes
            .load(std::sync::atomic::Ordering::SeqCst)
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
    /// The scheduling attributes of thread `tid`.
    pub(crate) fn sched(&self, tid: u32) -> crate::scheduling::Sched {
        self.sched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .copied()
            .unwrap_or_default()
    }
    pub(crate) fn set_sched(&self, tid: u32, value: crate::scheduling::Sched) {
        self.sched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, value);
    }
    /// The bandwidth the group's deadline threads take, but `except`'s.
    pub(crate) fn deadline_bandwidth(&self, except: Option<u32>) -> u64 {
        self.sched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|&(&tid, _)| Some(tid) != except)
            .map(|(_, sched)| sched.bandwidth())
            .sum()
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
    /// Records what acting on thread `tid` looks at, when its credentials
    /// change or it starts.
    pub(crate) fn set_task_ids(&self, tid: u32, ids: TaskIds) {
        self.task_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, ids);
    }
    /// What acting on thread `tid` of process `pid` looks at: a thread no
    /// longer here counts as the leader, whose credentials a zombie keeps.
    pub(crate) fn task_ids(&self, pid: u32, tid: u32) -> TaskIds {
        let ids = self.task_ids.lock().unwrap_or_else(PoisonError::into_inner);
        ids.get(&tid)
            .or_else(|| ids.get(&pid))
            .cloned()
            .unwrap_or_default()
    }
    /// Thread `tid`'s namespaces.
    pub(crate) fn namespaces(&self, tid: u32) -> Arc<crate::namespaces::Namespaces> {
        self.namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .cloned()
            .unwrap_or_else(|| self.first_namespaces.clone())
    }
    pub(crate) fn set_namespaces(&self, tid: u32, namespaces: crate::namespaces::Namespaces) {
        self.namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, Arc::new(namespaces));
    }
    /// After exec, thread `pid` is all there is, with `namespaces`.
    pub(crate) fn reset_namespaces(&self, pid: u32, namespaces: crate::namespaces::Namespaces) {
        let mut all = self
            .namespaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        all.clear();
        all.insert(pid, Arc::new(namespaces));
    }
    /// `LANDLOCK_RESTRICT_SELF_TSYNC`: every thread takes `domain`, which
    /// is what acting on them looks at from now on. Returns the number the
    /// caller, which takes it itself, records as taken.
    pub(crate) fn sync_landlock(&self, domain: &crate::landlock::Landlock) -> u64 {
        let mut sync = self
            .landlock_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *sync = domain.clone();
        for ids in self
            .task_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values_mut()
        {
            ids.landlock = domain.clone();
        }
        self.landlock_syncs.fetch_add(1, Ordering::SeqCst) + 1
    }
    /// A thread entering the kernel takes the domain of a
    /// `LANDLOCK_RESTRICT_SELF_TSYNC` it has not taken yet, as Linux's task
    /// work does before it returns to the thread.
    pub(crate) fn take_landlock(&self, credentials: &mut crate::credentials::Credentials) {
        let syncs = self.landlock_syncs.load(Ordering::SeqCst);
        if syncs != credentials.landlock_sync {
            let sync = self
                .landlock_sync
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            credentials.landlock = sync.clone();
            credentials.landlock_sync = self.landlock_syncs.load(Ordering::SeqCst);
        }
    }
    /// Thread `tid` is gone, unless it led process `pid`.
    fn forget_task_ids(&self, pid: u32, tid: u32) {
        if tid != pid {
            self.task_ids
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&tid);
            let namespaces = self
                .namespaces
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&tid);
            // Its number goes with it; the leader's waits for the process.
            if let Some(namespaces) = namespaces {
                namespaces.pid.leave(tid);
            }
        }
    }
    /// After exec, thread `pid` is all there is.
    pub(crate) fn reset_task_ids(&self, pid: u32, ids: TaskIds) {
        let mut all = self.task_ids.lock().unwrap_or_else(PoisonError::into_inner);
        all.clear();
        all.insert(pid, ids);
    }
    fn forget_nice(&self, tid: u32) {
        self.nice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid);
        self.sched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&tid);
    }
    /// Publishes what thread `tid` shows in `/proc`.
    pub(crate) fn publish(&self, tid: u32, thread: PublicThread) {
        self.public
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tid, thread);
    }
    /// What thread `tid` last published, if it is here.
    pub(crate) fn public(&self, tid: u32) -> Option<PublicThread> {
        self.public
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .cloned()
    }
    /// Thread `tid` is gone, unless it led process `pid`, whose zombie
    /// keeps what it showed.
    fn forget_public(&self, pid: u32, tid: u32) {
        if tid != pid {
            self.public
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&tid);
        }
    }
    /// The live threads, in order, and whether each is in a system call.
    pub(crate) fn threads(&self) -> Vec<(u32, bool)> {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(&tid, inbox)| (tid, inbox.in_call()))
            .collect()
    }
    /// Whether a thread of this group runs in `space`, as it last published.
    pub(crate) fn uses_memory(&self, space: &paludarium_mmu::AddressSpace) -> bool {
        self.public
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .any(|thread| thread.memory.as_ref().is_some_and(|view| view.is_of(space)))
    }
    /// Whether another process shares these signal dispositions
    /// (`CLONE_SIGHAND`), as Linux's `sighand->count` above one.
    pub(crate) fn shares_actions(&self) -> bool {
        Arc::strong_count(&self.actions.lock().unwrap_or_else(PoisonError::into_inner)) > 1
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
    /// Keeps the denial of writes to the program's file, giving back the
    /// one of the program before.
    pub(crate) fn set_exe_file(&self, denied: Option<Arc<crate::page_cache::WriteAccess>>) {
        *self.exe_file.lock().unwrap_or_else(PoisonError::into_inner) = denied;
    }
    pub(crate) fn set_executable(&self, path: Vec<u8>) {
        *self
            .executable
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = path;
    }
    pub(crate) fn executable(&self) -> Vec<u8> {
        self.executable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
    /// `tkill` of thread `tid` from a thread of this process, `sender` as
    /// their PID namespace numbers the process. The init of a nested one
    /// drops what it would from any thread of the namespace.
    fn send(&self, tid: u32, number: i32, sender: u32, uid: u32) -> Result<(), Errno> {
        let inbox = self
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .cloned()
            .ok_or(Errno(3))?;
        if number == 0 || self.drops_as_init(number, false, self.blocked(tid)) {
            return Ok(());
        }
        inbox.send_thread_from(number, sender, uid)
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
        // The actions are the process's, as Linux's sighand_struct is: a
        // thread that has waited since another one set a handler would
        // otherwise take a signal in as ignored and wait on past it.
        for (&number, &action) in self
            .shared_actions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            local.signal_actions.insert(number, action);
        }
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
    /// The process-directed signals waiting here, as a signal set, and how
    /// many have come so far.
    pub(crate) fn process_pending_set(&self) -> (u64, u64) {
        let mut pending = self
            .process_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.process_inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_process(&mut pending);
        let set = pending
            .pending
            .iter()
            .fold(0, |set, signal| set | 1 << (signal.number - 1));
        (set, pending.arrivals)
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
        let alone = {
            let mut members = self
                .group
                .members
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            members.remove(&tid);
            members.is_empty()
        };
        self.group
            .leave_sem_undo_list(tid, self.process.pid, self.wall_seconds());
        // As in `finish_thread`: no thread left runs the program.
        if alone {
            self.group.set_exe_file(None);
        }
        self.group.forget_nice(tid);
        self.group.forget_task_ids(self.process.pid, tid);
        self.group.forget_public(self.process.pid, tid);
    }
    /// The time of day in seconds, for System V semaphores' times.
    pub(crate) fn wall_seconds(&self) -> i64 {
        self.host
            .clock(ClockId::Realtime)
            .map_or(0, |nanos| (nanos / 1_000_000_000) as i64)
    }
    pub fn finish_thread(&mut self, thread: &Thread, mem: &AddressSpace) {
        // The last task to let go of the table closes its files
        // (`put_files_struct`), each close dropping that task's process's
        // message queue registrations (`mqueue_flush_file`).
        let closed = self.files.release_descriptors();
        crate::mqueue::exited(&closed, self.process.pid);
        drop(closed);
        let addr = thread.state.clear_child_tid;
        let robust = self.group.take_robust_list(thread.tid);
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
            if let Some(head) = robust {
                dump.robust_lists.push((thread.tid, head));
            }
            if addr != 0 {
                dump.clear_tids.push(addr);
            }
        } else {
            if let Some(head) = robust {
                crate::futex::exit_robust_list(&self.group.futexes, mem, thread.tid, head);
            }
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
            for (tid, head) in dump.robust_lists {
                crate::futex::exit_robust_list(&self.group.futexes, mem, tid, head);
            }
            for addr in dump.clear_tids {
                Self::clear_child_tid(&self.group, mem, addr);
            }
        }
        // exit_sem: the last thread sharing the undo list applies it.
        self.group
            .leave_sem_undo_list(thread.tid, self.process.pid, self.wall_seconds());
        let alone = {
            let mut members = self
                .group
                .members
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            members.remove(&thread.tid);
            members.is_empty()
        };
        drop(core);
        // The last thread's exit ends the process's use of its program,
        // whose file may be written again (`exit_mm`).
        if alone {
            self.group.set_exe_file(None);
        }
        if thread.tid != self.process.pid {
            self.group.forget_nice(thread.tid);
        }
        self.group.forget_task_ids(self.process.pid, thread.tid);
        self.group.forget_public(self.process.pid, thread.tid);
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
        let Some(identity) = self.processes.core_identity(
            pid,
            self.group.task_ids(pid, pid),
            self.group.process_cpu(),
            self.group.start_stack(),
        ) else {
            return;
        };
        let Ok(file) = self.files.create_core(&dump.credentials) else {
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
            // As the thread's PID namespace numbers it.
            186 => Ok(u64::from(self.pid_space(thread.tid).number(thread.tid))),
            218 => {
                thread.state.clear_child_tid = a[0];
                Ok(u64::from(self.pid_space(thread.tid).number(thread.tid)))
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
            // futex_waitv, futex_wake, futex_wait (futex2)
            449 => self.futex_waitv(thread, mem, a),
            454 => futex2_flags(a[3] as u32).and_then(|(private, numa)| {
                if a[1] >> 32 != 0 {
                    return Err(Errno::EINVAL);
                }
                self.group.futexes.wake_word(
                    mem,
                    a[0],
                    private,
                    numa,
                    a[2] as i32,
                    a[1] as u32,
                    true,
                )
            }),
            455 => self.futex2_wait(thread, mem, a),
            // futex_requeue(waiters, flags, nr_wake, nr_requeue): no flags
            // and a list of two (`EINVAL`), read as `futex_waitv` reads its
            // own, with the same flags for both, as Linux after 6.12 asks;
            // the first's value is compared.
            456 => (|| {
                if a[1] != 0 || a[0] == 0 {
                    return Err(Errno::EINVAL);
                }
                let words = futex_words(mem, a[0], 2)?;
                let flags = |w: &crate::futex::Word| (w.private, w.numa);
                if flags(&words[0]) != flags(&words[1]) {
                    return Err(Errno::EINVAL);
                }
                let word = |w: &crate::futex::Word| (w.addr, w.private, w.numa);
                self.group.futexes.requeue(
                    mem,
                    word(&words[0]),
                    word(&words[1]),
                    a[2] as i32,
                    a[3] as i32,
                    Some(words[0].value),
                )
            })(),
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
                let space = self.pid_space(thread.tid);
                let own = space.number(self.process.pid);
                let (tid, number) = if n == 234 {
                    if a[0] != u64::from(own) {
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
                        .ok()
                        .and_then(|tid| space.task(tid))
                        .ok_or(Errno(3))
                        .and_then(|tid| {
                            self.group
                                .send(tid, number as i32, own, thread.state.credentials.uid)
                        })
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
            | 0x1000000
            | crate::namespaces::ALL & !crate::namespaces::CLONE_NEWTIME
            | crate::namespaces::CLONE3_NEWTIME;
        let namespaces = crate::processes::namespace_flags(flags);
        // copy_process: a new mount or user namespace needs a working
        // directory and root of its own, and a thread can have neither a
        // new user nor a new PID namespace.
        if flags & 0x200 != 0
            && namespaces & (crate::namespaces::CLONE_NEWNS | crate::namespaces::CLONE_NEWUSER) != 0
        {
            return Err(Errno::EINVAL);
        }
        if flags & THREAD != 0 && flags & SIGHAND == 0 || flags & SIGHAND != 0 && flags & VM == 0 {
            return Err(Errno::EINVAL);
        }
        // Nor can it be numbered in another PID namespace than its process,
        // as after `unshare(CLONE_NEWPID)` or `setns` to one.
        let own = self.group.namespaces(parent.tid);
        if flags & THREAD != 0
            && (namespaces & (crate::namespaces::CLONE_NEWUSER | crate::namespaces::CLONE_NEWPID)
                != 0
                || !Arc::ptr_eq(&own.pid, &own.pid_for_children))
        {
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
        // sched_fork: a deadline thread's child is EAGAIN.
        let forked = self
            .group
            .sched(parent.tid)
            .forked(self.group.nice(parent.tid).unwrap_or(0))?;
        let task = self.processes.charge_task()?;
        // copy_namespaces; CLONE_NEWIPC leaves the semaphore undo list,
        // which CLONE_SYSVSEM would share.
        crate::namespaces::check(namespaces, parent.state.credentials.administers_own())?;
        if namespaces & crate::namespaces::CLONE_NEWIPC != 0 && flags & 0x40000 != 0 {
            return Err(Errno::EINVAL);
        }
        let child_namespaces = own.for_child(namespaces, true, &parent.state.credentials.user.0)?;
        let set_tid = std::mem::take(&mut self.set_tid);
        let tid = self.processes.allocate_in(
            &child_namespaces.pid,
            &set_tid,
            &parent.state.credentials,
        )?;
        let mut cpu = parent.cpu.clone();
        cpu.gpr[reg::RAX] = 0;
        if a[1] != 0 {
            cpu.gpr[reg::RSP] = a[1];
        }
        if flags & 0x80000 != 0 {
            cpu.fs_base = a[4];
        }
        let mut state = parent.state.clone();
        self.group
            .set_task_ids(tid, parent.state.credentials.task_ids());
        self.group.set_namespaces(tid, child_namespaces);
        state.timer = signals::RealTimer::default();
        state.pending.clear();
        // Nothing has come for the new thread yet, which its group counts.
        state.arrivals = 0;
        state.frames.clear();
        state.alt_stack = AltStack::default();
        state.exit_status = None;
        state.clear_child_tid = if flags & 0x200000 != 0 { a[3] } else { 0 };
        // A new thread registers its own rseq area (Linux's rseq_fork).
        state.rseq = None;
        state.on_cpu = None;
        state.rseq_notify = false;
        let inbox = Arc::new(SignalInbox::default());
        let mut child = Kernel {
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
            published: None,
            set_tid: Vec::new(),
            seat: None,
        };
        // A new thread starts with its creator's nice value, set before it
        // is registered so that no one sees it without one, and its
        // scheduling attributes as sched_fork passes them on.
        let nice = self.group.nice(parent.tid);
        let (sched, reset_nice) = forked;
        self.group.set_sched(tid, sched);
        if let Some(value) = nice {
            self.group.set_nice(tid, if reset_nice { 0 } else { value });
        }
        // And its CPU mask, as Linux's `dup_task_struct` copies it.
        if let Some(mask) = self.group.affinity(parent.tid) {
            self.group.set_affinity(tid, mask);
        }
        // And its memory policy.
        self.group.numa().new_thread(parent.tid, tid);
        self.group.register(tid, inbox);
        // copy_semundo: CLONE_SYSVSEM shares the undo list, which the
        // creator is given first if it has none.
        if flags & 0x40000 != 0 {
            let list = self.group.sem_undo_list(parent.tid).share();
            self.group.set_sem_undo_list(tid, list);
        }
        // Linux ignores unsuccessful parent/child TID stores (native case 23).
        if flags & 0x100000 != 0 {
            let _ = mem.write(GuestAddr(a[2]), &tid.to_le_bytes());
        }
        if flags & 0x1000000 != 0 {
            let _ = mem.write(GuestAddr(a[3]), &tid.to_le_bytes());
        }
        child.publish(tid, &state, mem);
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
        // FUTEX_REQUEUE and FUTEX_CMP_REQUEUE: `val` waiters woken and up
        // to `val2`, which Linux takes from the timeout argument, moved to
        // `uaddr2`; the second compares `val3` first.
        if matches!(op, 3 | 4) {
            let word = |addr| (addr, private, false);
            let compare = (op == 4).then_some(a[5] as u32);
            return self.group.futexes.requeue(
                mem,
                word(a[0]),
                word(a[4]),
                a[2] as u32 as i32,
                a[3] as u32 as i32,
                compare,
            );
        }
        if matches!(op, 1 | 10) {
            return self
                .group
                .futexes
                .wake(mem, a[0], private, a[2] as u32 as i32, mask);
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
            // Linux's ktime saturates at KTIME_MAX, as does adding the
            // relative wait of FUTEX_WAIT to now (`ktime_add_safe`).
            let value = ktime(seconds, ns);
            Some(if op == 0 {
                self.host
                    .clock(clock)?
                    .saturating_add(value)
                    .min(i64::MAX as u64)
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
        self.futex_sleep(thread, &[waiter], clock, deadline)
            .map(|_| 0)
    }
    /// `futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`, as
    /// Linux's: no `flags`, from 1 to `FUTEX_WAITV_MAX` (128) waiters and
    /// a list (`EINVAL`), the timeout ([`Self::futex2_deadline`]), then each
    /// 24-byte `struct futex_waitv` ([`futex_words`]). It gives the index of
    /// a word that was woken.
    fn futex_waitv(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        if a[2] != 0 || a[1] == 0 || a[1] > FUTEX_WAITV_MAX || a[0] == 0 {
            return Err(Errno::EINVAL);
        }
        let (clock, deadline) = self.futex2_deadline(mem, a[3], a[4] as i32)?;
        let words = futex_words(mem, a[0], a[1])?;
        let waiters = self.group.futexes.register_all(mem, &words)?;
        self.futex_sleep(thread, &waiters, clock, deadline)
            .map(|index| index as u64)
    }
    /// futex2's `futex_wait(uaddr, val, mask, flags, timeout, clockid)`, as
    /// Linux's: the flags ([`futex2_flags`]), a value and a mask that fit
    /// in 32 bits (`EINVAL`), the timeout ([`Self::futex2_deadline`]), and
    /// then FUTEX_WAIT_BITSET's wait, whose mask may not be 0.
    fn futex2_wait(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let (private, numa) = futex2_flags(a[3] as u32)?;
        if a[1] >> 32 != 0 || a[2] >> 32 != 0 {
            return Err(Errno::EINVAL);
        }
        let (clock, deadline) = self.futex2_deadline(mem, a[4], a[5] as i32)?;
        if a[2] == 0 {
            return Err(Errno::EINVAL);
        }
        let word = crate::futex::Word {
            addr: a[0],
            private,
            numa,
            value: a[1] as u32,
            mask: a[2] as u32,
        };
        let waiters = self.group.futexes.register_all(mem, &[word])?;
        self.futex_sleep(thread, &waiters, clock, deadline)
            .map(|_| 0)
    }
    /// The absolute timeout of futex2's waits, as Linux's
    /// `futex2_setup_timeout`: none without one, else on `CLOCK_REALTIME`
    /// or `CLOCK_MONOTONIC` (`EINVAL`), read (`EFAULT`) and valid
    /// (`EINVAL`), saturating at `KTIME_MAX`.
    fn futex2_deadline(
        &self,
        mem: &AddressSpace,
        timeout: u64,
        clock: i32,
    ) -> Result<(ClockId, Option<u64>), Errno> {
        if timeout == 0 {
            return Ok((ClockId::Monotonic, None));
        }
        let clock = match clock {
            0 => ClockId::Realtime,
            1 => ClockId::Monotonic,
            _ => return Err(Errno::EINVAL),
        };
        let mut b = [0; 16];
        mem.read(GuestAddr(timeout), &mut b)
            .map_err(|_| Errno::EFAULT)?;
        let seconds = i64::from_le_bytes(b[..8].try_into().map_err(|_| Errno::EINVAL)?);
        let ns = i64::from_le_bytes(b[8..].try_into().map_err(|_| Errno::EINVAL)?);
        if seconds < 0 || !(0..1_000_000_000).contains(&ns) {
            return Err(Errno::EINVAL);
        }
        Ok((clock, Some(ktime(seconds, ns))))
    }
    /// Sleeps until one of `waiters`, which share a token, is woken, giving
    /// its index (the last one woken, as Linux's `futex_unqueue_multiple`
    /// finds it), until `deadline` on `clock` (`ETIMEDOUT`), or until a
    /// signal or the group's end (`EINTR`). Every other waiter leaves its
    /// queue.
    fn futex_sleep(
        &mut self,
        thread: &mut Thread,
        waiters: &[Arc<crate::futex::Waiter>],
        clock: ClockId,
        deadline: Option<u64>,
    ) -> Result<usize, Errno> {
        let token = Arc::clone(&waiters[0].token);
        let finish = |futexes: &crate::futex::Futexes, result: u32| {
            for waiter in waiters {
                futexes.finish(waiter, result);
            }
        };
        let mut interrupted = false;
        loop {
            if let Some(index) = waiters
                .iter()
                .rposition(|w| w.state.load(Ordering::SeqCst) == 1)
            {
                finish(&self.group.futexes, 3);
                return Ok(index);
            }
            if let Some(state) = waiters
                .iter()
                .map(|w| w.state.load(Ordering::SeqCst))
                .find(|&state| state != 0)
            {
                return Err(Errno(if state == 2 { 110 } else { 4 }));
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
                    finish(&self.group.futexes, 3);
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
                finish(&self.group.futexes, result);
                continue;
            }
            let end = deadline
                .unwrap_or(u64::MAX)
                .min(now.saturating_add(10_000_000));
            let outcome = match self
                .host
                .wait_on(&token, 0, Some((clock, end)), &self.cancellation)
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    finish(&self.group.futexes, 3);
                    return Err(error);
                }
            };
            if outcome == WaitOutcome::Interrupted {
                interrupted |= self.inbox.drain(&mut thread.state).interrupted;
            }
        }
    }
}

/// `FUTEX_WAITV_MAX`, the most words one `futex_waitv` waits on.
const FUTEX_WAITV_MAX: u64 = 128;
/// A valid `timespec` as Linux's ktime, which saturates at `KTIME_MAX`.
fn ktime(seconds: i64, ns: i64) -> u64 {
    (seconds as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ns as u64)
        .min(i64::MAX as u64)
}
/// futex2's flags as Linux's `futex2_to_flags` and `futex_flags_valid` take
/// them: only `FUTEX2_SIZE_U32` (the 32-bit words implemented), with
/// `FUTEX2_NUMA`, `FUTEX2_MPOL` (a node from the memory policy, which is
/// always node 0 here) and `FUTEX2_PRIVATE`, else `EINVAL`. It gives
/// whether the word is private and followed by a node word.
fn futex2_flags(flags: u32) -> Result<(bool, bool), Errno> {
    const SIZE_MASK: u32 = 3;
    const SIZE_U32: u32 = 2;
    const NUMA: u32 = 4;
    const MPOL: u32 = 8;
    const PRIVATE: u32 = 128;
    if flags & !(SIZE_MASK | NUMA | MPOL | PRIVATE) != 0 || flags & SIZE_MASK != SIZE_U32 {
        return Err(Errno::EINVAL);
    }
    Ok((flags & PRIVATE != 0, flags & NUMA != 0))
}
/// The `count` words of a `struct futex_waitv` list at `list`, as Linux's
/// `futex_parse_waitv` reads them one after another: each readable
/// (`EFAULT`), with known flags and no `__reserved` ([`futex2_flags`],
/// `EINVAL`) and a value that fits the word (`EINVAL`).
fn futex_words(
    mem: &AddressSpace,
    list: u64,
    count: u64,
) -> Result<Vec<crate::futex::Word>, Errno> {
    (0..count)
        .map(|i| {
            let mut b = [0; 24];
            mem.read(GuestAddr(list.wrapping_add(24 * i)), &mut b)
                .map_err(|_| Errno::EFAULT)?;
            let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default());
            let (value, addr, flags) = (word(0), word(8), word(16));
            if flags >> 32 != 0 {
                return Err(Errno::EINVAL);
            }
            let (private, numa) = futex2_flags(flags as u32)?;
            if value >> 32 != 0 {
                return Err(Errno::EINVAL);
            }
            Ok(crate::futex::Word {
                addr,
                private,
                numa,
                value: value as u32,
                mask: u32::MAX,
            })
        })
        .collect()
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
