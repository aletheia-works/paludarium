//! Which thread a signal wakes, as Linux's `complete_signal` chooses it. Each
//! thread has a [`Tif`], which others read and set without its
//! [`crate::ThreadState`], and a thread group lists its threads' in
//! [`Targets`]. A thread takes the process's signals in only as its own says
//! ([`crate::ThreadGroup::drain_process`]).
//!
//! [`Targets`]' lock is a leaf: whoever holds it takes no other lock, so it
//! may be taken under any. A send takes it under an inbox's queue's, and a
//! thread that is made under the members'. What waits for a signal (a signal
//! file, `rt_sigtimedwait`, an io_uring poll) is told of it by the wake tokens
//! alone, which take no lock.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::signals;

/// What `wants_signal` reads of a thread, with its `TIF_SIGPENDING`.
#[derive(Default)]
pub(crate) struct Tif {
    /// The signals it blocks, as it last told ([`crate::ThreadGroup::settle_mask`]).
    blocked: AtomicU64,
    /// Those of them it waits for (`rt_sigtimedwait`), which it blocks no
    /// more meanwhile, where Linux keeps them in `real_blocked`.
    waited: AtomicU64,
    /// It is to look at the process's signals: one was sent it was chosen
    /// for, or it may take one it could not before (`recalc_sigpending`).
    look: AtomicBool,
    /// A signal it may take is in its own hands, and not delivered yet.
    held: AtomicBool,
    /// It is in a group stop, or in a ptrace stop its tracer has not ended.
    halted: AtomicBool,
    trapped: AtomicBool,
    /// It is traced (`t->ptrace`).
    traced: AtomicBool,
    /// Whether it waits in the host, so that it is not `task_curr`.
    asleep: Arc<AtomicBool>,
    /// It is in a wait only a fatal signal ends, which looks around now and
    /// then: it sleeps all along.
    killable: AtomicBool,
    /// What wakes it from such a wait.
    wake: Arc<AtomicBool>,
}

impl Tif {
    pub(crate) fn new(asleep: Arc<AtomicBool>, wake: Arc<AtomicBool>) -> Self {
        Self {
            // A new thread looks, as `calculate_sigpending` has it.
            look: AtomicBool::new(true),
            asleep,
            wake,
            ..Self::default()
        }
    }
    pub(crate) fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::SeqCst)
    }
    pub(crate) fn set_blocked(&self, mask: u64) {
        self.blocked.store(mask, Ordering::SeqCst);
    }
    /// The signals it waits for from now, 0 for none any more.
    pub(crate) fn wait_for(&self, set: u64) {
        self.waited.store(set, Ordering::SeqCst);
    }
    pub(crate) fn set_look(&self) {
        self.look.store(true, Ordering::SeqCst);
    }
    pub(crate) fn looks(&self) -> bool {
        self.look.load(Ordering::SeqCst)
    }
    /// Whether it was to look, which it does now.
    pub(crate) fn take_look(&self) -> bool {
        self.look.load(Ordering::SeqCst) && self.look.swap(false, Ordering::SeqCst)
    }
    pub(crate) fn set_held(&self, held: bool) {
        if self.held.load(Ordering::SeqCst) != held {
            self.held.store(held, Ordering::SeqCst);
        }
    }
    pub(crate) fn set_halted(&self, halted: bool) {
        if self.halted.load(Ordering::SeqCst) != halted {
            self.halted.store(halted, Ordering::SeqCst);
            // `recalc_sigpending` as the stop ends.
            self.set_look();
        }
    }
    pub(crate) fn set_trapped(&self, trapped: bool) {
        self.trapped.store(trapped, Ordering::SeqCst);
    }
    pub(crate) fn set_traced(&self, traced: bool) {
        self.traced.store(traced, Ordering::SeqCst);
    }
    /// It sleeps until what is returned goes (`TASK_KILLABLE`).
    pub(crate) fn sleep_killable(self: &Arc<Self>) -> Killable {
        self.killable.store(true, Ordering::SeqCst);
        Killable(Arc::clone(self))
    }
    /// Whether it is not `task_curr`.
    fn sleeps(&self) -> bool {
        self.asleep.load(Ordering::SeqCst) || self.killable.load(Ordering::SeqCst)
    }
    fn blocks(&self, bit: u64) -> bool {
        self.blocked() & !self.waited.load(Ordering::SeqCst) & bit != 0
    }
    /// `task_sigpending`.
    fn sigpending(&self) -> bool {
        self.looks() || self.held.load(Ordering::SeqCst)
    }
    /// `wants_signal` of a signal other than SIGKILL, by its bit, in a thread
    /// that does not exit.
    fn wants(&self, bit: u64) -> bool {
        !self.blocks(bit)
            && !self.halted.load(Ordering::SeqCst)
            && !self.trapped.load(Ordering::SeqCst)
            && (!self.sleeps() || !self.sigpending())
    }
    /// `signal_wake_up`.
    fn wake_up(&self) {
        self.set_look();
        self.wake.store(true, Ordering::SeqCst);
    }
    /// `complete_signal` of signal `number`, directed at this thread.
    pub(crate) fn complete(&self, number: i32) {
        if number == 9 || self.wants(signals::bit(number)) {
            self.set_look();
        }
    }
}

/// A wait of [`Tif::sleep_killable`].
pub(crate) struct Killable(Arc<Tif>);
impl Drop for Killable {
    fn drop(&mut self) {
        self.0.killable.store(false, Ordering::SeqCst);
    }
}

/// The task a signal for a process is sent to (`complete_signal`'s `p`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The process's leader.
    Leader,
    /// This thread.
    Thread(u32),
    /// This thread, or if it has gone, the first that has not
    /// (`find_alive_thread`).
    Alive(u32),
    /// The thread that runs, whose CPU time runs a timer out.
    Running,
}

/// A thread group's threads that do not exit, in the order they were made.
#[derive(Default)]
pub(crate) struct Targets(Mutex<List>);
#[derive(Default)]
struct List {
    leader: u32,
    /// `curr_target`.
    current: u32,
    threads: Vec<(u32, Arc<Tif>)>,
}
impl List {
    fn position(&self, tid: u32) -> Option<usize> {
        self.threads.iter().position(|&(id, _)| id == tid)
    }
    /// Where `sent` is in the list, unless it exits.
    fn sent(&self, sent: Sent) -> Option<usize> {
        match sent {
            Sent::Leader => self.position(self.leader),
            Sent::Thread(tid) => self.position(tid),
            Sent::Alive(tid) => self
                .position(tid)
                .or_else(|| (!self.threads.is_empty()).then_some(0)),
            Sent::Running => self
                .threads
                .iter()
                .position(|(_, tif)| !tif.sleeps())
                .or_else(|| self.position(self.leader)),
        }
    }
}
impl Targets {
    fn list(&self) -> MutexGuard<'_, List> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Adds thread `tid`, the leader if it is the first.
    pub(crate) fn add(&self, tid: u32, tif: &Arc<Tif>) {
        let mut list = self.list();
        if list.leader == 0 {
            (list.leader, list.current) = (tid, tid);
        }
        match list.position(tid) {
            Some(at) => list.threads[at].1 = Arc::clone(tif),
            None => list.threads.push((tid, Arc::clone(tif))),
        }
    }
    /// Thread `tid` exits (`exit_signals`, and `__exit_signal`'s
    /// `curr_target`).
    pub(crate) fn remove(&self, tid: u32) {
        let mut list = self.list();
        let Some(at) = list.position(tid) else {
            return;
        };
        list.threads.remove(at);
        if list.current == tid {
            let next = list.threads.get(at).or_else(|| list.threads.first());
            list.current = next.map_or(list.leader, |&(id, _)| id);
        }
    }
    /// The group is one thread, the leader `tid`, from now (`de_thread`).
    pub(crate) fn exec(&self, tid: u32, tif: &Arc<Tif>) {
        let mut list = self.list();
        (list.leader, list.current) = (tid, tid);
        list.threads = vec![(tid, Arc::clone(tif))];
    }
    /// No thread is in a group stop any more: SIGCONT came.
    pub(crate) fn resume(&self) {
        for (_, tif) in &self.list().threads {
            tif.set_halted(false);
        }
    }
    pub(crate) fn find(&self, tid: u32) -> Option<Arc<Tif>> {
        let list = self.list();
        list.position(tid).map(|at| Arc::clone(&list.threads[at].1))
    }
    /// Whether `sent` blocks signal `number`, waited for or not, and whether
    /// it is traced, as `sig_ignored` asks.
    pub(crate) fn keeps(&self, sent: Sent, number: i32) -> bool {
        let list = self.list();
        list.sent(sent).is_some_and(|at| {
            let tif = &list.threads[at].1;
            tif.blocked() & signals::bit(number) != 0
                || number != 9 && tif.traced.load(Ordering::SeqCst)
        })
    }
    /// Whether thread `tid`, or with none any, wants signal `number`.
    pub(crate) fn wanted(&self, number: i32, tid: Option<u32>) -> bool {
        let bit = signals::bit(number);
        let list = self.list();
        let mut threads = list.threads.iter();
        threads.any(|&(id, ref tif)| tid.is_none_or(|tid| tid == id) && tif.wants(bit))
    }
    /// `complete_signal` of signal `number`, queued for the process.
    pub(crate) fn complete(&self, number: i32, sent: Sent) {
        let mut list = self.list();
        if number == 9 {
            // Every thread gets SIGKILL of its own.
            list.threads.iter().for_each(|(_, tif)| tif.wake_up());
            return;
        }
        let bit = signals::bit(number);
        let sent = list.sent(sent);
        if let Some(at) = sent
            && list.threads[at].1.wants(bit)
        {
            list.threads[at].1.wake_up();
            return;
        }
        let first = list.position(list.current).unwrap_or(0);
        let count = list.threads.len();
        if count == 1 && sent.is_some() {
            return;
        }
        let found = (0..count)
            .map(|i| (first + i) % count)
            .find(|&at| list.threads[at].1.wants(bit));
        if let Some(at) = found {
            list.threads[at].1.wake_up();
            list.current = list.threads[at].0;
        }
    }
    /// `retarget_shared_pending`: the signals `set`, pending for the process,
    /// are for the other threads than `tif`'s from now.
    pub(crate) fn retarget(&self, tif: &Tif, mut set: u64) {
        let list = self.list();
        let count = list.threads.len();
        let after = list
            .threads
            .iter()
            .position(|(_, other)| std::ptr::eq(&**other, tif))
            .map_or(0, |at| at + 1);
        for (_, other) in (0..count).map(|i| &list.threads[(after + i) % count]) {
            if std::ptr::eq(&**other, tif) || set & !other.blocked() == 0 {
                continue;
            }
            set &= other.blocked();
            if !other.sigpending() {
                other.wake_up();
            }
            if set == 0 {
                break;
            }
        }
    }
}

/// How a [`crate::ThreadState`] takes the process's signals in.
#[derive(Default)]
pub(crate) enum Seat {
    /// All it does not block, as no other thread does.
    #[default]
    Alone,
    /// As its thread's [`Tif`] says.
    Thread(Arc<Tif>),
    /// None: a copy of a thread's state.
    Copy,
}
impl Seat {
    pub(crate) fn tif(&self) -> Option<&Arc<Tif>> {
        match self {
            Self::Thread(tif) => Some(tif),
            _ => None,
        }
    }
    /// Whether the thread is to look at the process's signals now.
    pub(crate) fn looks(&self) -> bool {
        match self {
            Self::Alone => true,
            Self::Thread(tif) => tif.looks(),
            Self::Copy => false,
        }
    }
    pub(crate) fn take_look(&self) -> bool {
        match self {
            Self::Alone => true,
            Self::Thread(tif) => tif.take_look(),
            Self::Copy => false,
        }
    }
    /// The state is `tif`'s thread's, which blocks `mask`.
    pub(crate) fn take(&mut self, tif: &Arc<Tif>, mask: u64) {
        if self.tif().is_none_or(|own| !Arc::ptr_eq(own, tif)) {
            tif.set_blocked(mask);
            *self = Self::Thread(Arc::clone(tif));
        }
    }
}
impl Clone for Seat {
    /// A copy of a state takes nothing until it is a thread's.
    fn clone(&self) -> Self {
        match self {
            Self::Alone => Self::Alone,
            _ => Self::Copy,
        }
    }
}
/// Two states that differ in this alone are the same.
impl PartialEq for Seat {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for Seat {}
impl std::fmt::Debug for Seat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Alone => "Alone",
            Self::Thread(_) => "Thread",
            Self::Copy => "Copy",
        })
    }
}
