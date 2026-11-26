//! What happens at a time with no system call to make it happen, as Linux's
//! timers of a TCP connection send the data it held back.
//!
//! Every wait, sleep and checkpoint of the session's threads runs what is
//! due ([`crate::ThreadGroup::expire_timer`]) and lasts no longer than the
//! next time, and a socket runs it before it shows its state. Run late, it
//! acts as of its own time. Where nothing is due at any time, all of this
//! is one atomic load.
//!
//! A wait looks again within 10 ms, but a sleep only at the time it knew
//! ([`Deadlines::sleeping`]): an earlier one that another thread sets wakes
//! it.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use crate::SignalInbox;

/// No time: nothing is due.
pub(crate) const NEVER: u64 = u64::MAX;

/// What is run at its time.
pub(crate) trait Due: Send + Sync {
    /// Does what is due by now, and sets its next time
    /// ([`Deadlines::set`]) to a later one.
    fn run(&self);
}

/// A thread that sleeps until a time known beforehand.
pub(crate) trait Sleeper: Send + Sync {
    /// Wakes it to look at the times again.
    fn look(&self);
}
impl Sleeper for SignalInbox {
    fn look(&self) {
        self.timer_changed();
    }
}

/// When, whose, and what is run then.
type Entry = (u64, usize, Weak<dyn Due>);
/// Who sleeps, named by its inbox.
type Asleep = (usize, Arc<dyn Sleeper>);

/// The times of a session's connections, in nanoseconds of the host's
/// monotonic clock.
pub(crate) struct Deadlines {
    /// The earliest of the table's.
    next: AtomicU64,
    table: Mutex<Vec<Entry>>,
    sleepers: Mutex<Vec<Asleep>>,
}
impl Default for Deadlines {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(NEVER),
            table: Mutex::default(),
            sleepers: Mutex::default(),
        }
    }
}
impl Deadlines {
    /// The next time something is due.
    pub(crate) fn next(&self) -> Option<u64> {
        Some(self.next.load(Ordering::SeqCst)).filter(|&at| at != NEVER)
    }
    /// `id`'s time, which was `old`, is `new`, when `due` is run;
    /// [`NEVER`] is none. Called with the lock held that keeps `id`'s time.
    pub(crate) fn set(&self, id: usize, (old, new): (u64, u64), due: &Weak<dyn Due>) {
        if old == new {
            return;
        }
        // A connection has one entry at most.
        let mut table = self.table();
        table.retain(|&(_, whose, _)| whose != id);
        if new != NEVER {
            table.push((new, id, Weak::clone(due)));
        }
        // A sleeper is listed before it reads the time kept here.
        if self.store(&table) {
            for (_, sleeper) in &*self.sleepers() {
                sleeper.look();
            }
        }
    }
    fn table(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn sleepers(&self) -> MutexGuard<'_, Vec<Asleep>> {
        self.sleepers.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Keeps the earliest time, and whether it is earlier than before.
    fn store(&self, table: &[Entry]) -> bool {
        let next = table.iter().map(|&(at, ..)| at).min();
        let next = next.unwrap_or(NEVER);
        self.next.swap(next, Ordering::SeqCst) > next
    }
    /// The thread of `inbox` sleeps from here on until what this gives goes:
    /// a time earlier than [`Self::next`] wakes it.
    pub(crate) fn sleeping(&self, inbox: &Arc<SignalInbox>) -> Sleeping<'_> {
        let id = Arc::as_ptr(inbox).addr();
        let sleeper = Arc::clone(inbox) as Arc<dyn Sleeper>;
        self.sleepers().push((id, sleeper));
        Sleeping(self, id)
    }
    /// Runs what is due by `now`, which is read only if there may be any.
    /// Called with no lock held that what is run takes.
    pub(crate) fn run(&self, now: impl FnOnce() -> Option<u64>) {
        if self.next().is_none() {
            return;
        }
        let Some(now) = now() else { return };
        if self.next().is_none_or(|at| at > now) {
            return;
        }
        let mut due: Vec<Entry> = {
            let mut table = self.table();
            let due = table.extract_if(.., |&mut (at, ..)| at <= now);
            let due = due.collect();
            self.store(&table);
            due
        };
        due.sort_unstable_by_key(|&(at, id, _)| (at, id));
        for (_, _, one) in due {
            if let Some(one) = one.upgrade() {
                one.run();
            }
        }
    }
}
/// A thread's sleep ([`Deadlines::sleeping`]).
pub(crate) struct Sleeping<'a>(&'a Deadlines, usize);
impl Drop for Sleeping<'_> {
    fn drop(&mut self) {
        let mut sleepers = self.0.sleepers();
        if let Some(mine) = sleepers.iter().position(|s| s.0 == self.1) {
            sleepers.swap_remove(mine);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Ticks {
        deadlines: Arc<Deadlines>,
        ran: AtomicU64,
    }
    impl Due for Ticks {
        fn run(&self) {
            self.ran.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn what_is_due_runs_once_and_what_has_gone_not_at_all() {
        let ticks = Arc::new(Ticks::default());
        let due = Arc::downgrade(&ticks) as Weak<dyn Due>;
        let all = &ticks.deadlines;
        all.run(|| unreachable!("nothing is due"));
        all.set(1, (NEVER, 50), &due);
        all.set(2, (NEVER, 30), &due);
        assert_eq!(all.next(), Some(30));
        all.run(|| Some(29));
        assert_eq!(ticks.ran.load(Ordering::SeqCst), 0);
        all.run(|| Some(30));
        assert_eq!(ticks.ran.load(Ordering::SeqCst), 1);
        assert_eq!(all.next(), Some(50));
        all.set(1, (50, 40), &due);
        assert_eq!(all.next(), Some(40));
        all.set(1, (40, NEVER), &due);
        assert_eq!(all.next(), None);
        // One whose connection has gone is passed over.
        let gone = Arc::downgrade(&Arc::new(Ticks::default())) as Weak<dyn Due>;
        all.set(3, (NEVER, 5), &gone);
        all.run(|| Some(5));
        assert_eq!(all.next(), None);
        // Without a clock nothing is known to be due.
        all.set(1, (NEVER, 60), &due);
        all.run(|| None);
        assert_eq!(all.next(), Some(60));
    }
    #[test]
    fn an_earlier_time_wakes_those_that_sleep() {
        let ticks = Arc::new(Ticks::default());
        let due = Arc::downgrade(&ticks) as Weak<dyn Due>;
        let all = &ticks.deadlines;
        let inbox = Arc::new(SignalInbox::default());
        let woken = || {
            inbox
                .drain(&mut crate::ThreadState::default())
                .timer_changed
        };
        let sleeping = all.sleeping(&inbox);
        all.set(1, (NEVER, 50), &due);
        assert!(woken());
        // Not a later one, nor one that goes.
        all.set(2, (NEVER, 60), &due);
        all.set(1, (50, NEVER), &due);
        assert!(!woken());
        all.set(1, (NEVER, 55), &due);
        assert!(woken());
        drop(sleeping);
        all.set(1, (55, 40), &due);
        assert!(!woken());
    }
}
