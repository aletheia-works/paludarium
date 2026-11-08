//! `fcntl`'s byte-range locks, as Linux's `fs/locks.c` keeps them: POSIX
//! record locks (`F_SETLK`, `F_SETLKW`, `F_GETLK`), which a process owns, and
//! open file description locks (`F_OFD_SETLK`, `F_OFD_SETLKW`,
//! `F_OFD_GETLK`), which an open file description owns. Both are advisory and
//! conflict with each other; one machine-wide table keeps them by file.
//!
//! A process's record locks on a file go when it closes any descriptor of the
//! file, or exits; a description's go when the description does. Locks are
//! the guest's own: a host program does not see them, nor they its.

use crate::files::Descriptor;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

/// `OFFSET_MAX`: the end of a lock that runs to the end of the file.
const OFFSET_MAX: u64 = i64::MAX as u64;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
/// How many owners `posix_locks_deadlock` follows before it gives up.
const MAX_DEADLOCK_ITERATIONS: usize = 10;

/// A file, as its device and inode name it.
pub(crate) type Key = (u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub(crate) enum Owner {
    /// A process's record lock.
    Process(u32),
    /// An open file description's lock; it goes with the description.
    Description(Weak<dyn FileHandle>),
}
impl Owner {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Process(a), Self::Process(b)) => a == b,
            (Self::Description(a), Self::Description(b)) => Weak::ptr_eq(a, b),
            _ => false,
        }
    }
    fn live(&self) -> bool {
        match self {
            Self::Process(_) => true,
            Self::Description(d) => d.strong_count() > 0,
        }
    }
    /// The `l_pid` that `F_GETLK` reports: -1 for a description's lock.
    fn pid(&self) -> i32 {
        match self {
            Self::Process(pid) => *pid as i32,
            Self::Description(_) => -1,
        }
    }
}

/// A lock on the bytes `start..=end`.
#[derive(Clone, Debug)]
pub(crate) struct Lock {
    pub(crate) owner: Owner,
    pub(crate) kind: Kind,
    pub(crate) start: u64,
    pub(crate) end: u64,
}
impl Lock {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }
}

#[derive(Default)]
pub(crate) struct Locks {
    files: Mutex<BTreeMap<Key, Vec<Lock>>>,
    /// The process each waiting process waits for, for deadlock detection.
    waiting: Mutex<BTreeMap<u32, u32>>,
}

impl Locks {
    fn files(&self) -> std::sync::MutexGuard<'_, BTreeMap<Key, Vec<Lock>>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The first lock of another owner that `kind` on `start..=end` would
    /// conflict with, as `posix_test_lock` finds it.
    pub(crate) fn conflict(
        &self,
        key: Key,
        owner: &Owner,
        kind: Kind,
        start: u64,
        end: u64,
    ) -> Option<Lock> {
        let mut files = self.files();
        let list = files.get_mut(&key)?;
        list.retain(|l| l.owner.live());
        list.iter()
            .find(|l| {
                !l.owner.same(owner)
                    && l.overlaps(start, end)
                    && (kind == Kind::Write || l.kind == Kind::Write)
            })
            .cloned()
    }
    /// Sets `kind` on `start..=end`, or with `None` unlocks it, for `owner`,
    /// as `posix_lock_inode` does: the owner's own locks there are replaced,
    /// split around the range, or merged with it when of the same kind and
    /// touching it. A conflicting lock of another owner is the error.
    pub(crate) fn set(
        &self,
        key: Key,
        owner: &Owner,
        kind: Option<Kind>,
        start: u64,
        end: u64,
    ) -> Result<(), Lock> {
        let mut files = self.files();
        let list = files.entry(key).or_default();
        list.retain(|l| l.owner.live());
        if let Some(kind) = kind
            && let Some(conflict) = list.iter().find(|l| {
                !l.owner.same(owner)
                    && l.overlaps(start, end)
                    && (kind == Kind::Write || l.kind == Kind::Write)
            })
        {
            return Err(conflict.clone());
        }
        let (mut new_start, mut new_end) = (start, end);
        let mut kept = Vec::with_capacity(list.len() + 1);
        for l in list.drain(..) {
            if !l.owner.same(owner) {
                kept.push(l);
                continue;
            }
            let touches = l.start <= end.saturating_add(1) && start <= l.end.saturating_add(1);
            if Some(l.kind) == kind && touches {
                new_start = new_start.min(l.start);
                new_end = new_end.max(l.end);
            } else if l.overlaps(start, end) {
                if l.start < start {
                    kept.push(Lock {
                        end: start - 1,
                        ..l.clone()
                    });
                }
                if l.end > end {
                    kept.push(Lock {
                        start: end + 1,
                        ..l
                    });
                }
            } else {
                kept.push(l);
            }
        }
        if let Some(kind) = kind {
            kept.push(Lock {
                owner: owner.clone(),
                kind,
                start: new_start,
                end: new_end,
            });
        }
        kept.sort_by_key(|l| l.start);
        if kept.is_empty() {
            files.remove(&key);
        } else {
            *list = kept;
        }
        Ok(())
    }
    /// Drops `owner`'s locks on the file, as a process's close of any of its
    /// descriptors does to its record locks (`locks_remove_posix`).
    pub(crate) fn release(&self, key: Key, owner: &Owner) {
        let mut files = self.files();
        if let Some(list) = files.get_mut(&key) {
            list.retain(|l| l.owner.live() && !l.owner.same(owner));
            if list.is_empty() {
                files.remove(&key);
            }
        }
    }
    /// Drops every record lock of process `pid`, which exited.
    pub(crate) fn release_process(&self, pid: u32) {
        let owner = Owner::Process(pid);
        self.files().retain(|_, list| {
            list.retain(|l| l.owner.live() && !l.owner.same(&owner));
            !list.is_empty()
        });
        self.stop_waiting(pid);
    }
    /// Whether process `pid` waiting for `blocker` would wait forever: the
    /// chain of processes waiting for each other's record locks leads back to
    /// it, as `posix_locks_deadlock` finds. A description's locks take no part.
    #[cfg(test)]
    fn would_deadlock(&self, pid: u32, blocker: &Owner) -> bool {
        let waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        Self::closes_cycle(&waiting, pid, blocker)
    }
    fn closes_cycle(waiting: &BTreeMap<u32, u32>, pid: u32, blocker: &Owner) -> bool {
        let &Owner::Process(mut next) = blocker else {
            return false;
        };
        for _ in 0..MAX_DEADLOCK_ITERATIONS {
            if next == pid {
                return true;
            }
            match waiting.get(&next) {
                Some(&other) => next = other,
                None => return false,
            }
        }
        false
    }
    /// Records that process `pid` waits for `blocker`'s record lock, or with
    /// `false` that the wait would close a cycle. One check under one lock,
    /// as Linux holds `blocked_lock_lock` from `posix_locks_deadlock` to
    /// `__locks_insert_block`: two processes asking for each other's locks at
    /// once cannot both miss the cycle and wait forever.
    pub(crate) fn wait_for_owner(&self, pid: u32, blocker: &Owner) -> bool {
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        if Self::closes_cycle(&waiting, pid, blocker) {
            waiting.remove(&pid);
            return false;
        }
        match blocker {
            &Owner::Process(other) => waiting.insert(pid, other),
            Owner::Description(_) => waiting.remove(&pid),
        };
        true
    }
    #[cfg(test)]
    fn wait_for(&self, pid: u32, blocker: u32) {
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(pid, blocker);
    }
    fn stop_waiting(&self, pid: u32) {
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&pid);
    }
}

/// The file `d` opens, for the table: its device and inode.
fn key(c: &Context<'_>, d: &Descriptor) -> Result<Key, Errno> {
    Ok((crate::files::descriptor_device(c, d), d.file.stat()?.inode))
}

/// After this process closed `d`, drops its record locks on the file.
pub(crate) fn closed(c: &Context<'_>, d: &Descriptor) {
    if let Ok(key) = key(c, d) {
        c.processes
            .locks()
            .release(key, &Owner::Process(c.process.pid));
    }
}

/// The range a `struct flock` names, as `flock64_to_posix_lock` reads it.
fn range(d: &Descriptor, whence: i16, start: i64, len: i64) -> Result<(u64, u64), Errno> {
    let base = match whence {
        0 => 0,
        1 => d.file.seek(0, 1)? as i64,
        2 => d.file.stat()?.size as i64,
        _ => return Err(Errno::EINVAL),
    };
    let start = base.checked_add(start).ok_or(Errno::EINVAL)?;
    if start < 0 {
        return Err(Errno::EINVAL);
    }
    let (start, end) = match len {
        0 => (start, i64::MAX),
        len if len > 0 => {
            if len - 1 > i64::MAX - start {
                return Err(Errno::EOVERFLOW);
            }
            (start, start + (len - 1))
        }
        len => {
            if start + len < 0 {
                return Err(Errno::EINVAL);
            }
            (start + len, start - 1)
        }
    };
    Ok((start as u64, end as u64))
}

fn kind(l_type: i16) -> Result<Option<Kind>, Errno> {
    match l_type {
        F_RDLCK => Ok(Some(Kind::Read)),
        F_WRLCK => Ok(Some(Kind::Write)),
        F_UNLCK => Ok(None),
        _ => Err(Errno::EINVAL),
    }
}

/// `fcntl`'s lock commands on descriptor `d`: `F_GETLK` (5), `F_SETLK` (6),
/// `F_SETLKW` (7), `F_OFD_GETLK` (36), `F_OFD_SETLK` (37) and
/// `F_OFD_SETLKW` (38), with the checks of Linux's `fcntl_getlk` and
/// `fcntl_setlk` in their order.
pub(crate) fn fcntl(
    c: &mut Context<'_>,
    d: &Descriptor,
    command: u64,
    arg: u64,
) -> Result<u64, Errno> {
    let ofd = command >= 36;
    let mut raw = [0u8; 32];
    c.mem
        .read(GuestAddr(arg), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let i16_at = |at: usize| i16::from_le_bytes([raw[at], raw[at + 1]]);
    let i64_at = |at: usize| i64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or_default());
    let (l_type, whence, l_start, l_len) = (i16_at(0), i16_at(2), i64_at(8), i64_at(16));
    let l_pid = i32::from_le_bytes(raw[24..28].try_into().unwrap_or_default());
    let owner = if ofd {
        Owner::Description(Arc::downgrade(&d.file))
    } else {
        Owner::Process(c.process.pid)
    };
    let key = key(c, d)?;
    let processes = Arc::clone(c.processes);
    let locks = processes.locks();
    if command == 5 || command == 36 {
        // fcntl_getlk: the type, the range, then an OFD lock's l_pid.
        let kind = kind(l_type)?.ok_or(Errno::EINVAL)?;
        let (start, end) = range(d, whence, l_start, l_len)?;
        if ofd && l_pid != 0 {
            return Err(Errno::EINVAL);
        }
        match locks.conflict(key, &owner, kind, start, end) {
            Some(lock) => {
                let l_type = if lock.kind == Kind::Write {
                    F_WRLCK
                } else {
                    F_RDLCK
                };
                let len = if lock.end == OFFSET_MAX {
                    0
                } else {
                    (lock.end - lock.start + 1) as i64
                };
                raw[0..2].copy_from_slice(&l_type.to_le_bytes());
                raw[2..4].copy_from_slice(&0i16.to_le_bytes());
                raw[8..16].copy_from_slice(&(lock.start as i64).to_le_bytes());
                raw[16..24].copy_from_slice(&len.to_le_bytes());
                raw[24..28].copy_from_slice(&lock.owner.pid().to_le_bytes());
            }
            None => raw[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
        }
        c.mem
            .write(GuestAddr(arg), &raw)
            .map_err(|_| Errno::EFAULT)?;
        return Ok(0);
    }
    // fcntl_setlk: the range and type, the access the type needs, then an
    // OFD lock's l_pid.
    let (start, end) = range(d, whence, l_start, l_len)?;
    let kind = kind(l_type)?;
    let access = d.file.flags() & 3;
    match kind {
        Some(Kind::Read) if access == 1 => return Err(Errno::EBADF),
        Some(Kind::Write) if access == 0 => return Err(Errno::EBADF),
        _ => {}
    }
    if ofd && l_pid != 0 {
        return Err(Errno::EINVAL);
    }
    let wait = command == 7 || command == 38;
    let pid = c.process.pid;
    loop {
        match locks.set(key, &owner, kind, start, end) {
            Ok(()) => {
                locks.stop_waiting(pid);
                return Ok(0);
            }
            Err(_) if !wait => return Err(Errno::EAGAIN),
            Err(blocker) => {
                if !ofd && !locks.wait_for_owner(pid, &blocker.owner) {
                    return Err(Errno(35));
                }
                if let Err(e) = crate::files::pause_for_lock(c) {
                    locks.stop_waiting(pid);
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_vfs::HostFs;

    const KEY: Key = (1, 2);

    fn ranges(locks: &Locks) -> Vec<(u64, u64, Kind)> {
        locks.files().get(&KEY).map_or_else(Vec::new, |list| {
            list.iter().map(|l| (l.start, l.end, l.kind)).collect()
        })
    }

    #[test]
    fn an_owner_never_conflicts_with_itself() {
        let locks = Locks::default();
        let a = Owner::Process(1);
        assert!(locks.set(KEY, &a, Some(Kind::Write), 0, 9).is_ok());
        assert!(locks.conflict(KEY, &a, Kind::Write, 0, 9).is_none());
        assert!(locks.set(KEY, &a, Some(Kind::Read), 3, 4).is_ok());
        assert_eq!(
            ranges(&locks),
            [(0, 2, Kind::Write), (3, 4, Kind::Read), (5, 9, Kind::Write)]
        );
    }

    #[test]
    fn readers_share_and_writers_conflict() {
        let locks = Locks::default();
        let (a, b) = (Owner::Process(1), Owner::Process(2));
        assert!(locks.set(KEY, &a, Some(Kind::Read), 0, 9).is_ok());
        assert!(locks.set(KEY, &b, Some(Kind::Read), 5, 14).is_ok());
        let blocker = locks.set(KEY, &b, Some(Kind::Write), 9, 9).unwrap_err();
        assert!(blocker.owner.same(&a));
        assert!(locks.set(KEY, &b, Some(Kind::Write), 10, 14).is_ok());
    }

    #[test]
    fn unlocking_splits_and_same_kind_merges() {
        let locks = Locks::default();
        let a = Owner::Process(1);
        locks.set(KEY, &a, Some(Kind::Write), 0, 9).unwrap();
        locks.set(KEY, &a, None, 3, 4).unwrap();
        assert_eq!(ranges(&locks), [(0, 2, Kind::Write), (5, 9, Kind::Write)]);
        locks.set(KEY, &a, Some(Kind::Write), 3, 4).unwrap();
        assert_eq!(ranges(&locks), [(0, 9, Kind::Write)]);
        // Adjacent locks of the same kind merge too.
        locks
            .set(KEY, &a, Some(Kind::Write), 10, OFFSET_MAX)
            .unwrap();
        assert_eq!(ranges(&locks), [(0, OFFSET_MAX, Kind::Write)]);
        locks.set(KEY, &a, None, 0, OFFSET_MAX).unwrap();
        assert!(locks.files().is_empty());
    }

    #[test]
    fn a_description_lock_goes_with_the_description() {
        let locks = Locks::default();
        let file = paludarium_vfs::MemFs::new().open(b"/f", 66, 0o600).unwrap();
        let owner = Owner::Description(Arc::downgrade(&file));
        locks.set(KEY, &owner, Some(Kind::Write), 0, 0).unwrap();
        let other = Owner::Process(7);
        assert!(locks.conflict(KEY, &other, Kind::Read, 0, 0).is_some());
        assert_eq!(
            locks
                .conflict(KEY, &other, Kind::Read, 0, 0)
                .unwrap()
                .owner
                .pid(),
            -1
        );
        drop(file);
        assert!(locks.conflict(KEY, &other, Kind::Read, 0, 0).is_none());
    }

    #[test]
    fn release_drops_only_that_owner() {
        let locks = Locks::default();
        let (a, b) = (Owner::Process(1), Owner::Process(2));
        locks.set(KEY, &a, Some(Kind::Read), 0, 0).unwrap();
        locks.set(KEY, &b, Some(Kind::Read), 0, 0).unwrap();
        locks.release(KEY, &a);
        assert!(locks.conflict(KEY, &a, Kind::Write, 0, 0).is_some());
        locks.release_process(2);
        assert!(locks.files().is_empty());
    }

    #[test]
    fn a_cycle_of_waiting_processes_is_a_deadlock() {
        let locks = Locks::default();
        // 2 waits for 3, which waits for 1: 1 waiting for 2 closes the cycle.
        locks.wait_for(2, 3);
        locks.wait_for(3, 1);
        assert!(locks.would_deadlock(1, &Owner::Process(2)));
        assert!(!locks.would_deadlock(4, &Owner::Process(2)));
        locks.stop_waiting(3);
        assert!(!locks.would_deadlock(1, &Owner::Process(2)));
    }

    #[test]
    fn the_second_of_two_waiters_for_each_other_gets_the_deadlock() {
        let locks = Locks::default();
        assert!(locks.wait_for_owner(1, &Owner::Process(2)));
        assert!(!locks.wait_for_owner(2, &Owner::Process(1)));
        // The refused one waits for nothing; the first still waits.
        assert!(!locks.would_deadlock(1, &Owner::Process(2)));
        assert!(locks.would_deadlock(2, &Owner::Process(1)));
    }
}
