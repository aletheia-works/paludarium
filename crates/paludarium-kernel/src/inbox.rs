//! Synchronized runtime-to-Kernel signal transport; it never holds an MMU lock.
use crate::{ThreadState, signals};
use paludarium_types::Errno;
use std::sync::{
    Arc, Mutex, PoisonError, Weak,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub struct SignalInbox {
    queue: Mutex<Vec<signals::PendingSignal>>,
    wake: Arc<AtomicBool>,
    control_wake: AtomicBool,
    timer_wake: AtomicBool,
    listeners: Mutex<Vec<Weak<AtomicBool>>>,
    /// The discards of the thread group this inbox belongs to.
    discards: Mutex<Option<Arc<signals::Discards>>>,
}
#[derive(Default)]
pub(crate) struct WakeReceipt {
    pub signals: bool,
    pub timer_changed: bool,
    pub interrupted: bool,
}
impl SignalInbox {
    /// Queues a signal for the single guest process from outside the
    /// emulator. The guest cannot see the sender, so `si_pid` is 0, as a PID
    /// namespace reports a sender outside it.
    pub fn send(&self, number: i32) -> Result<(), Errno> {
        self.send_from(number, 0)
    }
    /// Queues a signal that process `sender` sent (`SI_USER`).
    pub(crate) fn send_from(&self, number: i32, sender: u32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            sender: Some(sender),
            ..signals::PendingSignal::user(number, 0)
        })
    }
    /// Queues a signal the kernel sends itself, with `SI_KERNEL`.
    pub(crate) fn send_kernel(&self, number: i32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal::user(number, signals::SI_KERNEL))
    }
    /// Queues SIGCHLD with the child's siginfo. Like any standard signal it
    /// is dropped while one is already pending, as Linux keeps the first.
    pub(crate) fn send_child(&self, code: i32, child: signals::ChildSignal) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal {
            child: Some(child),
            ..signals::PendingSignal::user(17, code)
        })
    }
    pub(crate) fn send_thread(&self, number: i32) -> Result<(), Errno> {
        self.send_pending(signals::PendingSignal::thread(number, -6))
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
        drop(queue);
        self.notify_listeners();
        Some((timer.id, timer.overrun))
    }
    fn send_pending(&self, signal: signals::PendingSignal) -> Result<(), Errno> {
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
    /// Joins the thread group whose discards this inbox's thread follows.
    pub(crate) fn attach(&self, discards: Arc<signals::Discards>) {
        *self.discards.lock().unwrap_or_else(PoisonError::into_inner) = Some(discards);
    }
    /// Drops the queued instances of signal `number`.
    pub(crate) fn purge(&self, number: i32) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|signal| signal.number != number);
    }
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
        for signal in queue.drain(..) {
            signals::queue(process, signal);
        }
        // Sender stores while holding this same mutex, preventing a lost wake.
        self.wake.store(false, Ordering::SeqCst);
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
    fn a_signal_from_outside_has_no_sender() {
        let inbox = SignalInbox::default();
        inbox.send(10).unwrap();
        let mut process = ThreadState {
            pid: 1,
            ..ThreadState::default()
        };
        inbox.drain(&mut process);
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
        inbox.drain(&mut process);
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
            inbox.drain(&mut process);
            count += process.pending.len();
            process.pending.clear();
            std::thread::yield_now();
        }
        runner.join().unwrap();
        assert_eq!(count, 1000);
        assert!(!inbox.wake.load(Ordering::SeqCst));
    }
}
