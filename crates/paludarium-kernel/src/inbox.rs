//! Synchronized runtime-to-Kernel signal transport; it never holds an MMU lock.
use crate::{ThreadState, signals};
use paludarium_types::Errno;
use std::sync::{
    Arc, Mutex, PoisonError, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Default)]
pub struct SignalInbox {
    queue: Mutex<Vec<signals::PendingSignal>>,
    wake: Arc<AtomicBool>,
    control_wake: AtomicBool,
    timer_wake: AtomicBool,
    listeners: Mutex<Vec<Weak<AtomicBool>>>,
    /// How many signals have been sent here and woken the listeners, so that
    /// a thread they woke can tell a signal from another wake.
    notices: AtomicU64,
    /// The discards of the thread group this inbox belongs to.
    discards: Mutex<Option<Arc<signals::Discards>>>,
    /// The thread group's count of the signals its threads made pending
    /// ([`ThreadState::arrivals`]), which this inbox's thread adds its own
    /// to ([`Self::publish`]); the thread's count when it last did, and how
    /// much it has added in all.
    arrivals: Mutex<Option<Arc<AtomicU64>>>,
    published: AtomicU64,
    contributed: AtomicU64,
    /// Whether the thread is in a system call, where it waits if it waits,
    /// which `/proc` shows other processes as sleeping.
    in_call: AtomicBool,
}
#[derive(Default)]
pub(crate) struct WakeReceipt {
    pub signals: bool,
    pub timer_changed: bool,
    pub interrupted: bool,
}
impl SignalInbox {
    pub(crate) fn set_in_call(&self, in_call: bool) {
        self.in_call.store(in_call, Ordering::Relaxed);
    }
    pub(crate) fn in_call(&self) -> bool {
        self.in_call.load(Ordering::Relaxed)
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
    pub(crate) fn send_child(&self, code: i32, child: signals::ChildSignal) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            child: Some(child),
            ..signals::PendingSignal::user(17, code)
        })
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
        queue.push(signal);
        self.wake.store(true, Ordering::SeqCst);
        self.notices.fetch_add(1, Ordering::SeqCst);
        drop(queue);
        self.notify_listeners();
        Some((timer.id, timer.overrun))
    }
    pub(crate) fn send_pending(&self, signal: signals::PendingSignal) -> Result<(), Errno> {
        let number = signal.number;
        if !(1..=64).contains(&number) {
            return Err(Errno::EINVAL);
        }
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if number < 32
            && queue
                .iter()
                .any(|s| s.number == number && s.target == signal.target)
        {
            return Ok(());
        }
        queue.push(signal);
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
    /// [`Self::send_timer`]); an interruption does not count.
    pub(crate) fn notices(&self) -> u64 {
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
    pub(crate) fn owns_wake(&self, token: &AtomicBool) -> bool {
        std::ptr::eq(&*self.wake, token)
    }
    #[must_use]
    pub fn wake_token(&self) -> Arc<AtomicBool> {
        self.wake.clone()
    }
    /// Joins the thread group whose discards this inbox's thread follows,
    /// and whose count of arrivals its drains add to.
    pub(crate) fn attach(&self, discards: Arc<signals::Discards>, arrivals: Arc<AtomicU64>) {
        *self.discards.lock().unwrap_or_else(PoisonError::into_inner) = Some(discards);
        *self.arrivals.lock().unwrap_or_else(PoisonError::into_inner) = Some(arrivals);
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
            count.fetch_add(added, Ordering::SeqCst);
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
            .map_or(0, |count| count.load(Ordering::SeqCst));
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
                (s.number >= 32 || !(pending.iter().any(same) || queue[..at].iter().any(same)))
                    && signals::wakes(process, s)
            })
            .count();
        (set, coming as u64)
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
        let received = WakeReceipt {
            signals: !queue.is_empty(),
            timer_changed: self.timer_wake.swap(false, Ordering::SeqCst),
            interrupted: self.control_wake.swap(false, Ordering::SeqCst),
        };
        queue.retain(|signal| {
            if signal.target == signals::PendingTarget::Thread {
                signals::queue(process, *signal);
                false
            } else {
                true
            }
        });
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
        let count = Arc::<AtomicU64>::default();
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
