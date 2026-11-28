//! Synchronized runtime-to-Kernel signal transport; it never holds an MMU lock.
use crate::targets::{Sent, Targets, Tif};
use crate::{ThreadState, signals};
use paludarium_types::Errno;
use std::sync::{
    Arc, Mutex, PoisonError, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

pub struct SignalInbox {
    queue: Mutex<Vec<signals::PendingSignal>>,
    wake: Arc<AtomicBool>,
    control_wake: AtomicBool,
    timer_wake: AtomicBool,
    listeners: Mutex<Vec<Weak<AtomicBool>>>,
    /// Its thread's part in `complete_signal`, and the thread group's threads,
    /// of which a signal sent here for the process wakes one.
    tif: Arc<Tif>,
    targets: Mutex<Option<Arc<Targets>>>,
    /// How many signals have been sent here and woken the listeners, so that
    /// a thread they woke can tell a signal from another wake.
    notices: AtomicU64,
    /// The discards of the thread group this inbox belongs to.
    discards: Mutex<Option<Arc<signals::Discards>>>,
    /// The thread group's count of the signals its threads made pending
    /// ([`ThreadState::arrivals`]), which this inbox's thread adds its own
    /// to ([`Self::publish`]); the thread's count when it last did, and how
    /// much it has added in all.
    arrivals: Mutex<Option<Arc<crate::signalfd::Arrivals>>>,
    /// The thread group's actions, which decide whether a signal sent here
    /// for the thread is ignored ([`Self::send_to`]).
    actions: Mutex<Option<crate::threads::ActionSlot>>,
    published: AtomicU64,
    contributed: AtomicU64,
    /// Whether the thread is blocked in a wait of the host, which `/proc`
    /// shows as sleeping, as Linux shows a task that is not running; the
    /// host's waits set it ([`paludarium_host::blocked`]).
    blocked: Arc<AtomicBool>,
    /// The registers of its last entry into the kernel
    /// ([`Self::enter_kernel`]).
    entry: Entry,
    /// The thread's io_uring task work (`tctx->task_list`), which any
    /// thread or process may add to as a request it waited for becomes
    /// ready.
    task_work: Mutex<crate::io_uring::TaskWork>,
    /// `TIF_NOTIFY_SIGNAL`: task work waits to run. Until the thread runs
    /// it, every interruptible wait ends as a signal would end it
    /// ([`WakeReceipt::interrupted`]).
    notify: AtomicBool,
}
impl Default for SignalInbox {
    fn default() -> Self {
        let (wake, blocked) = (Arc::<AtomicBool>::default(), Arc::<AtomicBool>::default());
        Self {
            queue: Mutex::default(),
            control_wake: AtomicBool::default(),
            timer_wake: AtomicBool::default(),
            listeners: Mutex::default(),
            tif: Arc::new(Tif::new(Arc::clone(&blocked), Arc::clone(&wake))),
            targets: Mutex::default(),
            notices: AtomicU64::default(),
            discards: Mutex::default(),
            arrivals: Mutex::default(),
            actions: Mutex::default(),
            published: AtomicU64::default(),
            contributed: AtomicU64::default(),
            entry: Entry::default(),
            task_work: Mutex::default(),
            notify: AtomicBool::default(),
            wake,
            blocked,
        }
    }
}
/// The registers Linux's `collect_syscall` reads of a task that has entered
/// the kernel: `orig_ax` (the call's number, or -1 for another reason),
/// the six arguments, the user stack pointer and the instruction pointer.
/// Only its own thread writes them, around a count that is odd while it
/// does, so another reads them whole ([`SignalInbox::entry`]).
#[derive(Default)]
struct Entry {
    writes: AtomicU64,
    words: [AtomicU64; 9],
}
/// What [`SignalInbox::entry`] reads: Linux's `struct syscall_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct KernelEntry {
    /// `orig_ax`: the call's number, or `u64::MAX` (-1) for an entry that
    /// was no call.
    pub number: u64,
    /// Its arguments, 0 for an entry that was no call.
    pub arguments: [u64; 6],
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
}
#[derive(Default)]
pub(crate) struct WakeReceipt {
    pub signals: bool,
    pub timer_changed: bool,
    /// The wait is to end: the emulator interrupted it, or task work waits
    /// to run (`signal_pending` with `TIF_NOTIFY_SIGNAL`).
    pub interrupted: bool,
    /// The emulator interrupted it ([`SignalInbox::interrupt`]), which
    /// task work alone does not (`task_sigpending`).
    pub control: bool,
}
impl SignalInbox {
    /// Its thread's part in `complete_signal`.
    pub(crate) fn tif(&self) -> &Arc<Tif> {
        &self.tif
    }
    /// The signals sent here for the process are those of `targets`.
    pub(crate) fn join(&self, targets: Arc<Targets>) {
        *self.targets.lock().unwrap_or_else(PoisonError::into_inner) = Some(targets);
    }
    /// A signal for the process, `number`, was queued elsewhere: the threads
    /// look, and the one it wakes takes it.
    pub(crate) fn queued_elsewhere(&self, number: i32, sent: Sent) {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        self.notices.fetch_add(1, Ordering::SeqCst);
        self.complete(number, sent);
        self.wake.store(true, Ordering::SeqCst);
        self.notify_listeners();
    }
    /// The process's signals are another thread's to take now.
    pub(crate) fn passed_on(&self) {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        self.notices.fetch_add(1, Ordering::SeqCst);
        self.wake.store(true, Ordering::SeqCst);
        self.notify_listeners();
    }
    fn complete(&self, number: i32, sent: Sent) {
        if let Some(targets) = &*self.targets.lock().unwrap_or_else(PoisonError::into_inner) {
            targets.complete(number, sent);
        }
    }
    /// The flag its thread's waits set ([`paludarium_host::blocked::attach`]).
    pub(crate) fn blocked_flag(&self) -> &Arc<AtomicBool> {
        &self.blocked
    }
    /// Whether its thread is blocked in a wait.
    pub(crate) fn blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
    /// Records, as its thread enters the kernel, the registers of the entry
    /// (`/proc/<pid>/syscall`). Only that thread calls it.
    pub(crate) fn enter_kernel(&self, entry: KernelEntry) {
        let Entry { writes, words } = &self.entry;
        let count = writes.load(Ordering::Relaxed);
        writes.store(count.wrapping_add(1), Ordering::Relaxed);
        std::sync::atomic::fence(Ordering::Release);
        let values = [
            entry.number,
            entry.arguments[0],
            entry.arguments[1],
            entry.arguments[2],
            entry.arguments[3],
            entry.arguments[4],
            entry.arguments[5],
            entry.stack_pointer,
            entry.instruction_pointer,
        ];
        for (word, value) in words.iter().zip(values) {
            word.store(value, Ordering::Relaxed);
        }
        writes.store(count.wrapping_add(2), Ordering::Release);
    }
    /// The registers of the thread's last entry into the kernel, read whole
    /// whatever the thread does meanwhile.
    pub(crate) fn entry(&self) -> KernelEntry {
        let Entry { writes, words } = &self.entry;
        loop {
            let before = writes.load(Ordering::Acquire);
            if before % 2 == 1 {
                std::hint::spin_loop();
                continue;
            }
            let values: [u64; 9] = std::array::from_fn(|i| words[i].load(Ordering::Relaxed));
            std::sync::atomic::fence(Ordering::Acquire);
            if writes.load(Ordering::Relaxed) == before {
                return KernelEntry {
                    number: values[0],
                    arguments: [
                        values[1], values[2], values[3], values[4], values[5], values[6],
                    ],
                    stack_pointer: values[7],
                    instruction_pointer: values[8],
                };
            }
        }
    }
    /// Queues a signal for the single guest process from outside the
    /// emulator. The guest cannot see the sender, so `si_pid` is 0, as a PID
    /// namespace reports a sender outside it.
    pub fn send(&self, number: i32) -> Result<(), Errno> {
        self.send_from(number, 0, 0)
    }
    /// Queues a signal that process `sender`, of real user ID `uid`, sent
    /// (`SI_USER`).
    pub(crate) fn send_from(&self, number: i32, sender: u32, uid: u32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            sender: Some(sender),
            sender_uid: Some(uid),
            ..signals::PendingSignal::user(number, 0)
        })
    }
    /// Queues SIGCHLD with the child's siginfo. Like any standard signal it
    /// is dropped while one is already pending, as Linux keeps the first.
    pub(crate) fn send_child(
        &self,
        code: i32,
        child: signals::ChildSignal,
        sent: Sent,
    ) -> Result<(), Errno> {
        let signal = signals::PendingSignal {
            child: Some(child),
            ..signals::PendingSignal::user(17, code)
        };
        self.send_to(signal, sent)
    }
    #[cfg(test)]
    pub(crate) fn send_thread(&self, number: i32, uid: u32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            sender_uid: Some(uid),
            ..signals::PendingSignal::thread(number, -6)
        })
    }
    /// The same from process `sender`, as the receiver numbers it.
    pub(crate) fn send_thread_from(&self, number: i32, sender: u32, uid: u32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            sender: Some(sender),
            sender_uid: Some(uid),
            ..signals::PendingSignal::thread(number, -6)
        })
    }
    /// Queues a timer's thread-directed signal. While the timer's previous
    /// signal still waits here, the expiry adds to its overrun instead, as
    /// Linux does with a timer's one pending signal. Returns the timer and
    /// the overrun its signal now has.
    pub(crate) fn send_timer(&self, signal: signals::PendingSignal) -> Option<(i32, i32)> {
        let timer = signal.timer?;
        let ignored = self.ignores(signal.number, signal.synchronous);
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(queued) = queue
            .iter_mut()
            .find_map(|s| s.timer.as_mut().filter(|t| t.id == timer.id))
        {
            queued.overrun = queued
                .overrun
                .saturating_add(timer.overrun)
                .saturating_add(1);
            return Some((timer.id, queued.overrun));
        }
        let mut signal = signal;
        if signal.target == signals::PendingTarget::Thread
            && let Some(ignored) = ignored
        {
            signal.counted = self.count_sent(signal.number, ignored);
        }
        queue.push(signal);
        self.tif.complete(signal.number);
        self.wake.store(true, Ordering::SeqCst);
        self.notices.fetch_add(1, Ordering::SeqCst);
        drop(queue);
        self.notify_listeners();
        Some((timer.id, timer.overrun))
    }
    pub(crate) fn send_pending(&self, signal: signals::PendingSignal) -> Result<(), Errno> {
        self.send_to(signal, Sent::Leader)
    }
    /// Queues `signal`, and wakes the thread `complete_signal` chooses for it,
    /// sent to `sent` if it is for the process.
    /// A signal for the thread that Linux would queue ([`Tif::queues`])
    /// counts as an arrival as it is sent, as `signalfd_notify` wakes the
    /// process's signal files then, not as its thread takes it in later.
    pub(crate) fn send_to(&self, signal: signals::PendingSignal, sent: Sent) -> Result<(), Errno> {
        let number = signal.number;
        if !(1..=64).contains(&number) {
            return Err(Errno::EINVAL);
        }
        let ignored = (signal.target == signals::PendingTarget::Thread)
            .then(|| self.ignores(number, signal.synchronous))
            .flatten();
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if number < 32
            && queue
                .iter()
                .any(|s| s.number == number && s.target == signal.target)
        {
            return Ok(());
        }
        let mut signal = signal;
        if let Some(ignored) = ignored {
            signal.counted = self.count_sent(number, ignored);
        }
        queue.push(signal);
        match signal.target {
            signals::PendingTarget::Process => self.complete(number, sent),
            signals::PendingTarget::Thread => self.tif.complete(number),
        }
        self.wake.store(true, Ordering::SeqCst);
        self.notices.fetch_add(1, Ordering::SeqCst);
        self.notify_listeners();
        Ok(())
    }
    pub(crate) fn subscribe(&self, wake: &Arc<AtomicBool>) {
        let mut listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        listeners.retain(|listener| listener.strong_count() != 0);
        let listener = Arc::downgrade(wake);
        if !listeners.iter().any(|existing| existing.ptr_eq(&listener)) {
            listeners.push(listener);
        }
    }
    /// How many signals have been sent here ([`Self::send_pending`],
    /// [`Self::send_timer`]); an interruption does not count. Read under
    /// the lock a send holds, it comes before or after the whole of a send:
    /// its count and the wakes it sets.
    pub(crate) fn notices(&self) -> u64 {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        self.notices.load(Ordering::SeqCst)
    }
    fn notify_listeners(&self) {
        let mut listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        listeners.retain(|listener| {
            if let Some(wake) = listener.upgrade() {
                wake.store(true, Ordering::SeqCst);
                true
            } else {
                false
            }
        });
    }
    /// Interrupts a native wait without modifying CPU or guest memory.
    pub fn interrupt(&self) {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        // Only the owning worker may acknowledge a control notification.
        // A different worker draining process signals must not erase it.
        self.control_wake.store(true, Ordering::SeqCst);
        self.wake.store(true, Ordering::SeqCst);
        self.notify_listeners();
    }
    /// Deadline metadata wakes an owner without requesting guest interruption.
    pub(crate) fn timer_changed(&self) {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        self.timer_wake.store(true, Ordering::SeqCst);
        self.wake.store(true, Ordering::SeqCst);
    }
    /// The thread's io_uring task work.
    pub(crate) fn task_work(&self) -> std::sync::MutexGuard<'_, crate::io_uring::TaskWork> {
        self.task_work
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// Sets `TIF_NOTIFY_SIGNAL` for task work just added, as
    /// `task_work_add` does with `TWA_SIGNAL` or `TWA_SIGNAL_NO_IPI`:
    /// `__set_notify_signal` wakes the thread from an interruptible wait
    /// (`wake_up_state`), so work another task adds wakes it (`remote`).
    pub(crate) fn notify_signal(&self, remote: bool) {
        let _queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        self.notify.store(true, Ordering::SeqCst);
        if remote {
            self.wake.store(true, Ordering::SeqCst);
            self.notify_listeners();
        }
    }
    /// Whether task work waits to run (`TIF_NOTIFY_SIGNAL`).
    pub(crate) fn notified(&self) -> bool {
        self.notify.load(Ordering::SeqCst)
    }
    /// Clears `TIF_NOTIFY_SIGNAL` once no task work is left
    /// (`clear_notify_signal`), under the task work's lock, which work is
    /// added and the flag set under, so work added after the check sets it
    /// again.
    pub(crate) fn clear_notify_if_idle(&self) -> bool {
        let work = self.task_work();
        if work.is_empty() {
            self.notify.store(false, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
    pub(crate) fn owns_wake(&self, token: &AtomicBool) -> bool {
        std::ptr::eq(&*self.wake, token)
    }
    #[must_use]
    pub fn wake_token(&self) -> Arc<AtomicBool> {
        self.wake.clone()
    }
    /// Joins the thread group whose discards this inbox's thread follows,
    /// and whose count of arrivals its drains add to.
    pub(crate) fn attach(
        &self,
        discards: Arc<signals::Discards>,
        arrivals: Arc<crate::signalfd::Arrivals>,
    ) {
        *self.discards.lock().unwrap_or_else(PoisonError::into_inner) = Some(discards);
        *self.arrivals.lock().unwrap_or_else(PoisonError::into_inner) = Some(arrivals);
    }
    /// Follows the thread group's actions, as they are now and after an
    /// `execve` gives the group its own.
    pub(crate) fn follow_actions(&self, actions: crate::threads::ActionSlot) {
        *self.actions.lock().unwrap_or_else(PoisonError::into_inner) = Some(actions);
    }
    /// Whether the thread group's action ignores signal `number` (`SIG_IGN`,
    /// or `SIG_DFL` for one ignored by default), as `sig_task_ignored` reads
    /// it; `None` for an inbox of no group. Read before the queue's lock is
    /// taken, which no action's lock is held around.
    /// The init of a nested PID namespace also drops one it has no handler
    /// for ([`Tif::drops_unhandled`]).
    fn ignores(&self, number: i32, synchronous: bool) -> Option<bool> {
        let slot = self
            .actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        let actions = Arc::clone(&slot.lock().unwrap_or_else(PoisonError::into_inner));
        let action = actions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&number)
            .copied()
            .unwrap_or_default();
        Some(
            action.handler == signals::SIG_IGN
                || action.handler == 0
                    && (matches!(number, 17 | 18 | 23 | 28)
                        || self.tif.drops_unhandled(number, synchronous)),
        )
    }
    /// Counts signal `number`, sent for this inbox's thread, as an arrival
    /// for every thread of the group if Linux would queue it; whether it did.
    /// Under the queue's lock, which a drain sets the thread's own pending
    /// signals under ([`Tif::set_own`]).
    fn count_sent(&self, number: i32, ignored: bool) -> bool {
        if !self.tif.queues(number, ignored) {
            return false;
        }
        if let Some(count) = &*self.arrivals.lock().unwrap_or_else(PoisonError::into_inner) {
            count.add(1);
        }
        true
    }
    /// Adds the signals this inbox's thread made pending since it last did
    /// to the group's count, whether a drain took them in or the kernel
    /// queued them for the thread itself.
    pub(crate) fn publish(&self, process: &ThreadState) {
        let added = process
            .arrivals
            .wrapping_sub(self.published.swap(process.arrivals, Ordering::SeqCst));
        if added == 0 {
            return;
        }
        self.contributed.fetch_add(added, Ordering::SeqCst);
        if let Some(count) = &*self.arrivals.lock().unwrap_or_else(PoisonError::into_inner) {
            count.add(added);
        }
    }
    /// The arrivals the group's other threads made: the group's count less
    /// what this inbox's thread added.
    pub(crate) fn others_arrivals(&self) -> u64 {
        let total = self
            .arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(0, |count| count.count());
        total.wrapping_sub(self.contributed.load(Ordering::SeqCst))
    }
    /// The signals queued here, as a signal set, and how many of them a
    /// drain into `process` will count as arrivals ([`signals::queue`] keeps
    /// one of each standard signal).
    pub(crate) fn queued_set(&self, process: &ThreadState) -> (u64, u64) {
        let pending = &process.pending;
        let queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let set = queue
            .iter()
            .filter(|s| (1..=64).contains(&s.number))
            .fold(0, |set, s| set | 1 << (s.number - 1));
        // As `signals::queue` keeps them: every real-time signal, and a
        // standard one only when neither the pending signals nor one queued
        // earlier here (two timers' can be) has its number and target.
        let coming = queue
            .iter()
            .enumerate()
            .filter(|&(at, s)| {
                let same =
                    |p: &signals::PendingSignal| p.number == s.number && p.target == s.target;
                !s.counted
                    && (s.number >= 32
                        || !(pending.iter().any(same) || queue[..at].iter().any(same)))
                    && signals::wakes(process, s)
            })
            .count();
        (set, coming as u64)
    }
    /// Whether a signal `fatal` picks is queued, without taking it in.
    pub(crate) fn queued_any(&self, fatal: &dyn Fn(i32) -> bool) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|s| fatal(s.number))
    }
    /// Drops the queued instances of signal `number`.
    pub(crate) fn purge(&self, number: i32) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|signal| signal.number != number);
    }
    /// Takes the signals directed at this thread. One directed at the
    /// process stays for [`crate::ThreadGroup::drain_process`], even in the
    /// leader's inbox, which is also the process's: it goes to the process's
    /// shared queue first, so that every thread sees the process's signals in
    /// one queue and in the order they came, as Linux keeps them.
    pub(crate) fn drain(&self, process: &mut ThreadState) -> WakeReceipt {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(discards) = &*self.discards.lock().unwrap_or_else(PoisonError::into_inner) {
            discards.apply(process);
        }
        let control = self.control_wake.swap(false, Ordering::SeqCst);
        let received = WakeReceipt {
            signals: !queue.is_empty(),
            timer_changed: self.timer_wake.swap(false, Ordering::SeqCst),
            interrupted: control || self.notify.load(Ordering::SeqCst),
            control,
        };
        queue.retain(|signal| {
            if signal.target == signals::PendingTarget::Thread {
                signals::queue(process, *signal);
                false
            } else {
                true
            }
        });
        self.tif.set_own(signals::own_set(process));
        self.publish(process);
        // Sender stores while holding this same mutex, preventing a lost wake.
        // A process signal still queued keeps it until it is dispatched.
        self.wake.store(!queue.is_empty(), Ordering::SeqCst);
        received
    }
    /// Process dispatch must leave directed signals in their owning thread inbox.
    pub(crate) fn drain_process(&self, process: &mut ThreadState) {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        queue.retain(|signal| {
            if signal.target == signals::PendingTarget::Process {
                signals::queue(process, *signal);
                false
            } else {
                true
            }
        });
        self.wake.store(
            !queue.is_empty()
                || self.control_wake.load(Ordering::SeqCst)
                || self.timer_wake.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
}

#[cfg(test)]
mod signals_time_tests {
    use super::*;

    #[test]
    fn a_threads_arrivals_reach_the_others() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for inbox in [&one, &two] {
            inbox.attach(Arc::default(), Arc::clone(&count));
        }
        let mut state = ThreadState {
            signal_mask: !0,
            ..ThreadState::default()
        };
        one.send_thread(10, 0).unwrap();
        one.send_thread(40, 0).unwrap();
        one.drain(&mut state);
        assert_eq!(one.others_arrivals(), 0);
        assert_eq!(two.others_arrivals(), 2);
        // A standard signal already pending makes nothing more.
        one.send_thread(10, 0).unwrap();
        one.drain(&mut state);
        assert_eq!(two.others_arrivals(), 2);
        // What the kernel queues for the thread itself counts once published.
        signals::queue(&mut state, signals::PendingSignal::thread(41, 0));
        one.publish(&state);
        assert_eq!(two.others_arrivals(), 3);
        assert_eq!(one.others_arrivals(), 0);
    }

    /// A signal sent for another thread counts for the group's signal files
    /// as it is sent, when Linux would queue it, and not again as that
    /// thread takes it in: not one ignored and unblocked, nor a standard one
    /// already pending for it.
    #[test]
    fn a_signal_for_another_thread_counts_as_it_is_sent() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let actions = crate::threads::ActionSlot::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for inbox in [&one, &two] {
            inbox.attach(Arc::default(), Arc::clone(&count));
            inbox.follow_actions(Arc::clone(&actions));
        }
        let mut state = ThreadState::default();
        // Until its first drain, its own pending signals are not known.
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 0);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 1);
        two.send_thread(40, 0).unwrap();
        two.send_thread(12, 0).unwrap();
        assert_eq!(one.others_arrivals(), 3);
        let (_, coming) = two.queued_set(&state);
        assert_eq!(coming, 0);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 3);
        // SIGUSR2 is pending for it already, and SIGURG is ignored.
        two.send_thread(12, 0).unwrap();
        two.send_thread(23, 0).unwrap();
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 3);
        // A blocked or ignored by its action, it is queued.
        two.tif().set_blocked(1 << 22);
        two.send_thread(23, 0).unwrap();
        assert_eq!(one.others_arrivals(), 4);
        actions.lock().unwrap().lock().unwrap().insert(
            41,
            crate::SignalAction {
                handler: signals::SIG_IGN,
                ..Default::default()
            },
        );
        // The thread's own copy, which a thread syncs with the group's.
        state.signal_actions.insert(
            41,
            crate::SignalAction {
                handler: signals::SIG_IGN,
                ..Default::default()
            },
        );
        two.send_thread(41, 0).unwrap();
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 4);
    }

    /// A signal counted for the group's signal files wakes, as it is sent,
    /// each file table a thread waited on in `epoll` with a signal file
    /// open, once for each signal; one not counted wakes none.
    #[test]
    fn a_counted_signal_wakes_the_waits_at_once() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for inbox in [&one, &two] {
            inbox.attach(Arc::default(), Arc::clone(&count));
            inbox.follow_actions(crate::threads::ActionSlot::default());
        }
        let hub = Arc::<crate::events::ReadinessHub>::default();
        count.wait_on(&hub);
        count.wait_on(&hub);
        let ticket = hub.token.value();
        let mut state = ThreadState::default();
        two.drain(&mut state);
        two.send_thread(40, 0).unwrap();
        assert_eq!(hub.token.value(), ticket.wrapping_add(1));
        assert_eq!(one.others_arrivals(), 1);
        // SIGURG is ignored by default and unblocked: nothing comes.
        two.send_thread(23, 0).unwrap();
        assert_eq!(hub.token.value(), ticket.wrapping_add(1));
        // What the kernel queues for the thread itself, as it publishes it.
        signals::queue(&mut state, signals::PendingSignal::thread(41, 0));
        two.publish(&state);
        assert_eq!(hub.token.value(), ticket.wrapping_add(2));
        // A file table that is gone is woken no more.
        drop(hub);
        two.send_thread(42, 0).unwrap();
        assert_eq!(one.others_arrivals(), 3);
    }

    /// A standard signal its thread has taken, by delivery or a wait, is no
    /// longer pending for it: one sent next counts as it is sent, before
    /// the thread's next drain.
    #[test]
    fn a_signal_taken_without_a_drain_is_pending_no_more() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let actions = crate::threads::ActionSlot::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for inbox in [&one, &two] {
            inbox.attach(Arc::default(), Arc::clone(&count));
            inbox.follow_actions(Arc::clone(&actions));
        }
        let mut state = ThreadState::default();
        state.seat.take(two.tif(), 0);
        two.send_thread(10, 0).unwrap();
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 1);
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 1);
        two.drain(&mut state);
        let index = signals::lowest_in(&state.pending, 1 << 9).unwrap();
        assert_eq!(signals::take_pending(&mut state, index).number, 10);
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 2);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 2);
    }

    /// Nor is one that a discard took away (`flush_sigqueue_mask`), or that
    /// SIGCONT, or a stop signal, took away as it was queued.
    #[test]
    fn a_discarded_signal_is_pending_no_more() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let actions = crate::threads::ActionSlot::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for inbox in [&one, &two] {
            inbox.attach(Arc::default(), Arc::clone(&count));
            inbox.follow_actions(Arc::clone(&actions));
        }
        let mut state = ThreadState::default();
        state.seat.take(two.tif(), 0);
        two.send_thread(10, 0).unwrap();
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 1);
        // The caller's own discard.
        let discards = signals::Discards::default();
        discards.mark(10);
        discards.apply(&mut state);
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 2);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 2);
        // Another thread's, which it drops at its next drain.
        discards.mark(10);
        two.tif().forget_own(10);
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 3);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 3);
        assert_eq!(state.pending.len(), 1);
        // SIGCONT takes a pending SIGTSTP away as it is queued.
        two.send_thread(20, 0).unwrap();
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 4);
        signals::queue(&mut state, signals::PendingSignal::thread(18, 0));
        two.send_thread(20, 0).unwrap();
        assert_eq!(one.others_arrivals(), 5);
    }

    /// The init of a nested PID namespace drops a signal it has no handler
    /// for as it is sent (SIGNAL_UNKILLABLE), so neither the send nor the
    /// drain counts it, unless it is blocked, SIGKILL, or a fault's.
    #[test]
    fn a_nested_inits_unhandled_signal_does_not_count() {
        let count = Arc::<crate::signalfd::Arrivals>::default();
        let actions = crate::threads::ActionSlot::default();
        let targets = Arc::<Targets>::default();
        let [one, two] = [SignalInbox::default(), SignalInbox::default()];
        for (tid, inbox) in [(1, &one), (2, &two)] {
            inbox.attach(Arc::default(), Arc::clone(&count));
            inbox.follow_actions(Arc::clone(&actions));
            targets.add(tid, inbox.tif());
        }
        targets.set_unkillable();
        let mut state = ThreadState::default();
        state.seat.take(two.tif(), 0);
        two.drain(&mut state);
        two.send_thread(10, 0).unwrap();
        assert_eq!(one.others_arrivals(), 0);
        two.drain(&mut state);
        assert_eq!(one.others_arrivals(), 0);
        // What it handles, or blocks, it takes.
        let handled = crate::SignalAction {
            handler: 0x1000,
            ..Default::default()
        };
        actions.lock().unwrap().lock().unwrap().insert(12, handled);
        state.signal_actions.insert(12, handled);
        two.send_thread(12, 0).unwrap();
        assert_eq!(one.others_arrivals(), 1);
        two.tif().set_blocked(1 << 13);
        two.send_thread(14, 0).unwrap();
        assert_eq!(one.others_arrivals(), 2);
        // A fault's signal is forced on it, and SIGKILL comes through.
        two.tif().set_blocked(0);
        two.send_pending(signals::segment_fault(13, 0)).unwrap();
        two.send_thread(9, 0).unwrap();
        assert_eq!(one.others_arrivals(), 4);
        // So too for one the kernel queues for the thread itself.
        signals::queue(&mut state, signals::PendingSignal::user(13, 0));
        two.publish(&state);
        assert_eq!(one.others_arrivals(), 4);
        // Another process is no init.
        let other = Arc::new(Tif::default());
        Targets::default().add(3, &other);
        assert!(!other.drops_unhandled(10, false));
    }

    #[test]
    fn queued_arrivals_count_a_standard_signal_once() {
        let inbox = SignalInbox::default();
        let mut process = ThreadState {
            signal_mask: !0,
            ..ThreadState::default()
        };
        let thread = |number| signals::PendingSignal::thread(number, 0);
        // Two timers' SIGALRM come in without the queue's own coalescing.
        inbox
            .queue
            .lock()
            .unwrap()
            .extend([thread(14), thread(14), thread(40), thread(40)]);
        assert_eq!(inbox.queued_set(&process).1, 3);
        let before = process.arrivals;
        inbox.drain(&mut process);
        assert_eq!(process.arrivals - before, 3);
        // One already pending counts nothing more.
        inbox.queue.lock().unwrap().push(thread(14));
        assert_eq!(inbox.queued_set(&process).1, 0);
    }
    #[test]
    fn a_signal_from_outside_has_no_sender() {
        let inbox = SignalInbox::default();
        inbox.send(10).unwrap();
        let mut process = ThreadState {
            pid: 1,
            ..ThreadState::default()
        };
        inbox.drain_process(&mut process);
        let info = signals::siginfo(&process, &process.pending[0]);
        assert_eq!(info[8..12], 0i32.to_le_bytes());
        assert_eq!(info[16..20], 0u32.to_le_bytes());
    }
    #[test]
    fn inbox_control_signal_survives_realtime_backlog() {
        let inbox = SignalInbox::default();
        for _ in 0..2048 {
            inbox.send(32).unwrap();
        }
        inbox.send(19).unwrap();
        inbox.send(18).unwrap();
        inbox.send(9).unwrap();
        let mut process = ThreadState::default();
        inbox.drain_process(&mut process);
        assert!(process.pending.iter().any(|s| s.number == 9));
        assert!(!process.stopped);
        assert_eq!(
            process.pending.iter().filter(|s| s.number == 32).count(),
            2048
        );
    }
    #[test]
    fn inbox_sender_drain_race_preserves_realtime_count() {
        let inbox = Arc::new(SignalInbox::default());
        let sender = inbox.clone();
        let runner = std::thread::spawn(move || {
            for _ in 0..1000 {
                sender.send(32).unwrap();
            }
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut process = ThreadState::default();
        let mut count = 0;
        while count < 1000 {
            assert!(
                std::time::Instant::now() < deadline,
                "signal transport did not drain"
            );
            inbox.drain_process(&mut process);
            count += process.pending.len();
            process.pending.clear();
            std::thread::yield_now();
        }
        runner.join().unwrap();
        assert_eq!(count, 1000);
        assert!(!inbox.wake.load(Ordering::SeqCst));
    }
    #[test]
    fn a_thread_drain_leaves_process_signals_for_the_process() {
        let inbox = SignalInbox::default();
        inbox.send(10).unwrap();
        inbox.send_thread(12, 0).unwrap();
        let mut thread = ThreadState::default();
        let receipt = inbox.drain(&mut thread);
        assert!(receipt.signals);
        assert_eq!(
            thread.pending.iter().map(|s| s.number).collect::<Vec<_>>(),
            [12]
        );
        // The process signal still wakes, until the process takes it.
        assert!(inbox.wake.load(Ordering::SeqCst));
        let mut process = ThreadState::default();
        inbox.drain_process(&mut process);
        assert_eq!(
            process.pending.iter().map(|s| s.number).collect::<Vec<_>>(),
            [10]
        );
        assert!(!inbox.wake.load(Ordering::SeqCst));
    }
}
