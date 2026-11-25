//! The requests that wait for a lock, as Linux's `fs/locks.c` keeps them
//! (`flc_blocker`, `flc_blocked_requests` and `flc_blocked_member`): those
//! of `F_SETLKW`, `F_OFD_SETLKW` and `flock`, and the opens that break a
//! lease. Each is under the lock in its way or, when an earlier one under
//! that lock conflicts with it too, under that one (`__locks_insert_block`),
//! which it leaves the lock to. `/proc/locks` lists them under their lock
//! and `F_SETLKW` follows them to find a deadlock.
//!
//! A lock that goes or is cut wakes the requests right under it
//! (`locks_wake_up_blocks`), which then try again; those under them stay
//! there until they are done. A request that gets its lock takes the ones
//! under it along (`locks_move_blocks`), and one that ends otherwise wakes
//! them (`locks_delete_block`).

use crate::namespaces::Namespace;
use crate::record_locks::{Key, Kind, Lock, Owner, Status};
use paludarium_host::FileHandle;
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError, Weak};

/// `MAX_DEADLK_ITERATIONS`.
const MAX_DEADLOCK_ITERATIONS: usize = 10;

/// What a request is for.
#[derive(Clone, Debug)]
pub(crate) enum Class {
    /// A record lock of this owner.
    Record(Owner),
    /// A `flock` lock of this description.
    Flock(Weak<dyn FileHandle>),
    /// An open, or a truncate, that breaks a lease.
    Breaker,
}

/// The lock a request waits to get.
#[derive(Clone, Debug)]
pub(crate) struct Wanted {
    pub(crate) class: Class,
    pub(crate) kind: Kind,
    pub(crate) key: Key,
    pub(crate) range: (u64, u64),
    /// The process that waits (`flc_pid`).
    pub(crate) pid: u32,
}
impl Wanted {
    /// `posix_locks_conflict`, `flock_locks_conflict` or `leases_conflict`.
    fn conflicts(&self, other: &Self) -> bool {
        let apart = match (&self.class, &other.class) {
            (Class::Record(a), Class::Record(b)) => {
                a.same(b) || self.range.0 > other.range.1 || other.range.0 > self.range.1
            }
            (Class::Flock(a), Class::Flock(b)) => Weak::ptr_eq(a, b),
            (Class::Breaker, Class::Breaker) => false,
            _ => true,
        };
        !apart && self.kind.conflicts(other.kind)
    }
    /// Whether it is a record lock that a descriptor table owns
    /// (`FL_POSIX` without `FL_OFDLCK`).
    fn posix(&self) -> bool {
        matches!(self.class, Class::Record(Owner::Files(_)))
    }
    /// What `/proc/locks` shows of it.
    fn status(&self, space: &Namespace) -> Status {
        let pid = space.number(self.pid) as i32;
        match &self.class {
            Class::Record(owner) => {
                Status::record(owner, self.kind, self.pid, self.key, self.range, space)
            }
            Class::Flock(_) => Status::flock(self.key, self.kind, pid),
            Class::Breaker => Status::breaker(self.kind, pid),
        }
    }
}

/// What a request is under: the lock with this number, or another request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Blocker {
    Lock(u64),
    Request(u64),
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    /// `None` once woken (`__locks_unlink_block`).
    blocker: Option<Blocker>,
    /// It is in Linux's `blocked_hash`, where a deadlock is looked for.
    hashed: bool,
    wanted: Wanted,
}

/// The requests that wait, those under one blocker in the order they came.
#[derive(Debug, Default)]
struct Waiters {
    list: Vec<Waiter>,
    /// How many requests were made.
    made: u64,
}
impl Waiters {
    fn get(&self, id: u64) -> Option<&Waiter> {
        self.list.iter().find(|w| w.id == id)
    }
    /// Wakes those under `blocker` (`__locks_wake_up_blocks`).
    fn wake(&mut self, blocker: Blocker) {
        for w in &mut self.list {
            if w.blocker == Some(blocker) {
                w.blocker = None;
                w.hashed = false;
            }
        }
    }
    /// What the request or lock `owner` has a request waiting for
    /// (`what_owner_is_waiting_for`): the owner of the lock at the top of
    /// the requests, or of the topmost one if that was woken. `None` for a
    /// `flock` lock or a lease at the top, which own no record lock.
    fn waited_for(&self, owner: &Owner, locks: &BTreeMap<Key, Vec<Lock>>) -> Option<Owner> {
        let holder = |w: &Waiter| match w.blocker {
            Some(Blocker::Lock(number)) => locks
                .get(&w.wanted.key)?
                .iter()
                .find(|l| l.live() && l.number() == number)
                .map(|l| l.owner.clone()),
            _ => None,
        };
        let waits = |w: &&Waiter| {
            w.hashed
                && matches!(&w.wanted.class, Class::Record(o) if o.same(owner))
                && match w.blocker {
                    Some(Blocker::Lock(_)) => holder(w).is_some(),
                    Some(Blocker::Request(_)) => true,
                    None => false,
                }
        };
        // The latest comes first in its bucket (`hash_add`).
        let mut top = self.list.iter().rev().find(waits)?;
        while let Some(Blocker::Request(id)) = top.blocker {
            top = self.get(id)?;
        }
        if let Some(owner) = holder(top) {
            return Some(owner);
        }
        match &top.wanted.class {
            Class::Record(owner) => Some(owner.clone()),
            _ => None,
        }
    }
}

/// The requests that wait for a lock anywhere (Linux's `blocked_lock_lock`
/// is their mutex, which is taken after that of the locks).
#[derive(Debug, Default)]
pub(crate) struct Blocked(Mutex<Waiters>);

impl Blocked {
    fn waiters(&self) -> std::sync::MutexGuard<'_, Waiters> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// A request that may come to wait, until it is dropped.
    pub(crate) fn request(&self) -> Request<'_> {
        let mut waiters = self.waiters();
        waiters.made += 1;
        Request {
            blocked: self,
            id: waiters.made,
        }
    }
    /// Wakes the requests right under lock `number`, which stays but changed
    /// (`locks_wake_up_blocks`). Those under one that goes need no call: a
    /// number is never used again.
    pub(crate) fn wake(&self, number: u64) {
        self.waiters().wake(Blocker::Lock(number));
    }
    /// Whether `owner`, about to wait for a lock of `blocker`, would wait for
    /// itself (`posix_locks_deadlock`).
    fn deadlock(
        waiters: &Waiters,
        owner: &Owner,
        blocker: &Owner,
        locks: &BTreeMap<Key, Vec<Lock>>,
    ) -> bool {
        if matches!(owner, Owner::Description(_)) {
            return false;
        }
        let mut blocker = blocker.clone();
        for _ in 0..=MAX_DEADLOCK_ITERATIONS {
            match waiters.waited_for(&blocker, locks) {
                Some(next) if next.same(owner) => return true,
                Some(next) => blocker = next,
                None => return false,
            }
        }
        false
    }
    /// The requests under each of the locks `numbers`, with their depths, as
    /// `locks_show` goes through them.
    pub(crate) fn under(&self, numbers: &[u64], space: &Namespace) -> Vec<Vec<(usize, Status)>> {
        let waiters = self.waiters();
        let right_under = |blocker, level| {
            let list = waiters.list.iter().rev();
            list.filter(move |w| w.blocker == Some(blocker))
                .map(move |w| (level, w))
        };
        let under = |&number: &u64| {
            let mut shown = Vec::new();
            let mut next: Vec<_> = right_under(Blocker::Lock(number), 1).collect();
            while let Some((level, w)) = next.pop() {
                shown.push((level, w.wanted.status(space)));
                next.extend(right_under(Blocker::Request(w.id), level + 1));
            }
            shown
        };
        numbers.iter().map(under).collect()
    }
}

/// A task's request for a lock (Linux's `file_lock` on its stack), which no
/// longer waits once this is dropped (`locks_delete_block`).
#[derive(Debug)]
pub(crate) struct Request<'a> {
    blocked: &'a Blocked,
    id: u64,
}
impl Request<'_> {
    /// Whether it waits for another request, so that it must not try for
    /// its lock yet.
    pub(crate) fn behind(&self) -> bool {
        let waiters = self.blocked.waiters();
        matches!(
            waiters.get(self.id).and_then(|w| w.blocker),
            Some(Blocker::Request(_))
        )
    }
    /// Whether it still waits: behind another request, or for the lock it
    /// is under, which `holds` tells is still in its way.
    pub(crate) fn asleep(&self, holds: impl Fn(u64) -> bool) -> bool {
        let waiters = self.blocked.waiters();
        match waiters.get(self.id).and_then(|w| w.blocker) {
            Some(Blocker::Request(_)) => true,
            Some(Blocker::Lock(number)) => holds(number),
            None => false,
        }
    }
    /// Waits for lock `number` (`locks_insert_block`); `posix` tells whether
    /// that is a descriptor table's record lock.
    pub(crate) fn wait(&self, (number, posix): (u64, bool), wanted: Wanted) {
        self.place(&mut self.blocked.waiters(), (number, posix), wanted);
    }
    /// Waits for record lock `blocker` of `locks`, unless that is a deadlock:
    /// then it waits for nothing. Gives whether it waits.
    pub(crate) fn wait_for_record(
        &self,
        blocker: &Lock,
        wanted: Wanted,
        locks: &BTreeMap<Key, Vec<Lock>>,
    ) -> bool {
        let mut waiters = self.blocked.waiters();
        // So that no deadlock is found through the requests under this.
        waiters.wake(Blocker::Request(self.id));
        waiters.list.retain(|w| w.id != self.id);
        if let Class::Record(owner) = &wanted.class
            && Blocked::deadlock(&waiters, owner, &blocker.owner, locks)
        {
            return false;
        }
        let posix = matches!(blocker.owner, Owner::Files(_));
        self.place(&mut waiters, (blocker.number(), posix), wanted);
        true
    }
    /// `__locks_insert_block`.
    fn place(&self, waiters: &mut Waiters, (number, mut posix): (u64, bool), wanted: Wanted) {
        waiters.list.retain(|w| w.id != self.id);
        let mut blocker = Blocker::Lock(number);
        while let Some(before) = waiters
            .list
            .iter()
            .find(|w| w.blocker == Some(blocker) && w.wanted.conflicts(&wanted))
        {
            blocker = Blocker::Request(before.id);
            posix = before.wanted.posix();
        }
        waiters.list.push(Waiter {
            id: self.id,
            blocker: Some(blocker),
            hashed: posix,
            wanted,
        });
        waiters.wake(Blocker::Request(self.id));
    }
    /// It got its lock, the new lock `number`, which those under it now wait
    /// for (`locks_move_blocks`).
    pub(crate) fn got(&self, number: u64) {
        for w in &mut self.blocked.waiters().list {
            if w.blocker == Some(Blocker::Request(self.id)) {
                w.blocker = Some(Blocker::Lock(number));
            }
        }
    }
    /// It waits for no lock the kernel knows of, and those under it try
    /// again (`locks_delete_block`).
    pub(crate) fn unlink(&self) {
        let mut waiters = self.blocked.waiters();
        waiters.list.retain(|w| w.id != self.id);
        waiters.wake(Blocker::Request(self.id));
    }
}
impl Drop for Request<'_> {
    fn drop(&mut self) {
        self.unlink();
    }
}
