//! `fcntl`'s byte-range locks, as Linux's `fs/locks.c` keeps them: POSIX
//! record locks (`F_SETLK`, `F_SETLKW`, `F_GETLK`), which a descriptor table
//! owns (Linux's `current->files`: a process's, shared by its threads and by
//! a `CLONE_FILES` child), and
//! open file description locks (`F_OFD_SETLK`, `F_OFD_SETLKW`,
//! `F_OFD_GETLK`), which an open file description owns. Both are advisory and
//! conflict with each other; one machine-wide table keeps them by file.
//!
//! A table's record locks on a file go when a task using it closes any
//! descriptor of the file, or when the last task using it lets go of it
//! (`put_files_struct`); a description's go when the description does. Locks are
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
    /// A record lock of the descriptor table with this number
    /// ([`crate::files::Files::table`]).
    Files(u64),
    /// An open file description's lock; it goes with the description.
    Description(Weak<dyn FileHandle>),
}
impl Owner {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Files(a), Self::Files(b)) => a == b,
            (Self::Description(a), Self::Description(b)) => Weak::ptr_eq(a, b),
            _ => false,
        }
    }
    fn live(&self) -> bool {
        match self {
            Self::Files(_) => true,
            Self::Description(d) => d.strong_count() > 0,
        }
    }
}

/// The description a lock was set through and the process that set it.
type Setter = (Option<Weak<dyn FileHandle>>, u32);

/// A lock on the bytes `start..=end`.
#[derive(Clone, Debug)]
pub(crate) struct Lock {
    pub(crate) owner: Owner,
    pub(crate) kind: Kind,
    pub(crate) start: u64,
    pub(crate) end: u64,
    /// The description it was set through (Linux's `flc_file`), which
    /// `/proc/self/fdinfo` lists it under.
    file: Option<Weak<dyn FileHandle>>,
    /// The process that set it (Linux's `flc_pid`, the caller's `tgid`).
    pid: u32,
    /// The table of a record lock, which goes once no task uses the table,
    /// as `close_files` drops it; `None` for one that lasts until it is let
    /// go of.
    table: Option<Weak<crate::files::Table>>,
}
impl Lock {
    fn live(&self) -> bool {
        self.owner.live() && self.table.as_ref().is_none_or(|t| t.strong_count() > 0)
    }
    /// The `l_pid` that `F_GETLK` reports to a process of PID namespace
    /// `space`: the process that set it as `space` numbers it (0 outside
    /// it), as Linux's `locks_translate_pid`, or -1 for a description's.
    fn pid(&self, space: &crate::namespaces::Namespace) -> i32 {
        match self.owner {
            Owner::Files(_) => space.number(self.pid) as i32,
            Owner::Description(_) => -1,
        }
    }
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }
}

/// What a waiting table's task waits for: the table that holds the lock in
/// its way, and that lock, so that a change to it ends the wait in the
/// deadlock table as Linux's `locks_wake_up_blocks` does.
#[derive(Clone, Copy, Debug)]
struct Wait {
    blocker: u64,
    key: Key,
    start: u64,
    end: u64,
}

#[derive(Default)]
struct Table {
    files: BTreeMap<Key, Vec<Lock>>,
    /// The wait of each table one of whose tasks waits, for deadlock
    /// detection (Linux's `blocked_hash`, by `flc_owner`).
    waiting: BTreeMap<u64, Wait>,
}

impl Table {
    /// Whether table `pid` waiting for `blocker` would wait forever: the
    /// chain of tables waiting for each other's record locks leads back to
    /// it, as `posix_locks_deadlock` finds. A description's locks take no part.
    fn closes_cycle(&self, pid: u64, blocker: &Owner) -> bool {
        let &Owner::Files(mut next) = blocker else {
            return false;
        };
        for _ in 0..MAX_DEADLOCK_ITERATIONS {
            if next == pid {
                return true;
            }
            match self.waiting.get(&next) {
                Some(wait) => next = wait.blocker,
                None => return false,
            }
        }
        false
    }
    /// Ends the waits for `owner`'s locks on the file in `changed`, which a
    /// change replaced, split or merged.
    fn wake(&mut self, key: Key, owner: &Owner, changed: &[(u64, u64)]) {
        let &Owner::Files(pid) = owner else {
            return;
        };
        self.waiting.retain(|_, w| {
            !(w.blocker == pid
                && w.key == key
                && changed.iter().any(|&(s, e)| w.start <= e && s <= w.end))
        });
    }
}

/// Why [`Locks::set_through`] did not set a lock.
#[derive(Debug)]
pub(crate) enum Refused {
    /// Another owner's lock is in the way.
    Conflict,
    /// Waiting for that lock would close a cycle of waiting processes.
    Deadlock,
}

#[derive(Default)]
pub(crate) struct Locks {
    /// The locks and the waits for them under one lock, as Linux checks a
    /// conflict, a deadlock and records the wait under `flc_lock` and
    /// `blocked_lock_lock` at once: a lock let go of in between cannot leave
    /// a stale wait behind, and two processes asking for each other's locks
    /// cannot both miss the cycle.
    table: Mutex<Table>,
    /// The `flock` lock of each description that has one, for
    /// `/proc/self/fdinfo` only: the file system keeps the lock itself and
    /// decides its conflicts. Each has the kind and the process that set it
    /// (Linux's `flc_pid`).
    flocks: Mutex<Vec<Flock>>,
}

/// A description's `flock` lock: the description, the kind and the process
/// that set it.
type Flock = (Weak<dyn FileHandle>, Kind, u32);

impl Locks {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut table = self.table();
        let list = table.files.get_mut(&key)?;
        list.retain(|l| l.live());
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
    /// touching it, and the waits for them end. A conflicting lock of another
    /// owner is the error; with `waiter`, the table whose task will wait for
    /// it, the wait is recorded unless it would close a cycle.
    #[cfg(test)]
    pub(crate) fn set(
        &self,
        key: Key,
        owner: &Owner,
        kind: Option<Kind>,
        start: u64,
        end: u64,
        waiter: Option<u64>,
    ) -> Result<(), Refused> {
        self.set_through(key, owner, kind, (start, end), waiter, (None, 0, None))
    }
    /// `set` through the description `file` by process `pid` of a task using
    /// the table `holder`. A lock merged with the owner's first one of the same kind
    /// keeps that one's description and process, as `posix_lock_inode`
    /// extends it; a new or replacing one takes `file` and `pid`, and the
    /// pieces of a split one keep theirs.
    pub(crate) fn set_through(
        &self,
        key: Key,
        owner: &Owner,
        kind: Option<Kind>,
        (start, end): (u64, u64),
        waiter: Option<u64>,
        (file, pid, holder): (
            Option<Weak<dyn FileHandle>>,
            u32,
            Option<Weak<crate::files::Table>>,
        ),
    ) -> Result<(), Refused> {
        let mut table = self.table();
        let list = table.files.entry(key).or_default();
        list.retain(|l| l.live());
        if let Some(kind) = kind
            && let Some(conflict) = list.iter().find(|l| {
                !l.owner.same(owner)
                    && l.overlaps(start, end)
                    && (kind == Kind::Write || l.kind == Kind::Write)
            })
        {
            let conflict = conflict.clone();
            if let Some(waiter) = waiter {
                if table.closes_cycle(waiter, &conflict.owner) {
                    table.waiting.remove(&waiter);
                    return Err(Refused::Deadlock);
                }
                match conflict.owner {
                    Owner::Files(blocker) => {
                        let wait = Wait {
                            blocker,
                            key,
                            start: conflict.start,
                            end: conflict.end,
                        };
                        table.waiting.insert(waiter, wait);
                    }
                    Owner::Description(_) => {
                        table.waiting.remove(&waiter);
                    }
                }
            }
            return Err(Refused::Conflict);
        }
        let (mut new_start, mut new_end) = (start, end);
        // The first lock merged into the new one, by its start, and its
        // description and process.
        let mut merged: Option<(u64, Setter)> = None;
        let mut kept = Vec::with_capacity(list.len() + 1);
        // The owner's locks this replaces, splits or merges, whose waits end.
        let mut changed = Vec::new();
        for l in list.drain(..) {
            if !l.owner.same(owner) {
                kept.push(l);
                continue;
            }
            let touches = l.start <= end.saturating_add(1) && start <= l.end.saturating_add(1);
            if Some(l.kind) == kind && touches {
                new_start = new_start.min(l.start);
                new_end = new_end.max(l.end);
                changed.push((l.start, l.end));
                if merged.as_ref().is_none_or(|&(first, _)| l.start < first) {
                    merged = Some((l.start, (l.file.clone(), l.pid)));
                }
            } else if l.overlaps(start, end) {
                changed.push((l.start, l.end));
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
            let (file, pid) = merged.map_or((file, pid), |(_, setter)| setter);
            kept.push(Lock {
                owner: owner.clone(),
                kind,
                start: new_start,
                end: new_end,
                file,
                pid,
                table: holder,
            });
        }
        kept.sort_by_key(|l| l.start);
        if kept.is_empty() {
            table.files.remove(&key);
        } else {
            *list = kept;
        }
        if let Some(waiter) = waiter {
            table.waiting.remove(&waiter);
        }
        table.wake(key, owner, &changed);
        Ok(())
    }
    /// Drops `owner`'s locks on the file, as a close of any descriptor of it
    /// through the table does to the table's record locks
    /// (`locks_remove_posix`).
    pub(crate) fn release(&self, key: Key, owner: &Owner) {
        let mut table = self.table();
        if let Some(list) = table.files.get_mut(&key) {
            list.retain(|l| l.live() && !l.owner.same(owner));
            if list.is_empty() {
                table.files.remove(&key);
            }
        }
        table.wake(key, owner, &[(0, OFFSET_MAX)]);
    }
    /// Drops every record lock of descriptor table `pid`, which no task uses
    /// any more (`put_files_struct` closing its files), and the waits for
    /// them and its own.
    pub(crate) fn release_table(&self, pid: u64) {
        let owner = Owner::Files(pid);
        let mut table = self.table();
        table.files.retain(|_, list| {
            list.retain(|l| l.live() && !l.owner.same(&owner));
            !list.is_empty()
        });
        table
            .waiting
            .retain(|&waiter, w| waiter != pid && w.blocker != pid);
    }
    /// Notes what `flock(op)` through `file` by process `pid` did, as
    /// `flock_lock_inode` changes a description's lock: an unlock, or a
    /// change of kind, drops the old lock first, even when the new one then
    /// conflicts (`EAGAIN`); asking again for the kind it has keeps the lock
    /// as it was, with the process that set it.
    pub(crate) fn flocked(
        &self,
        file: &Arc<dyn FileHandle>,
        pid: u32,
        op: u32,
        result: Result<(), Errno>,
    ) {
        const LOCK_SH: u32 = 1;
        const LOCK_EX: u32 = 2;
        const LOCK_UN: u32 = 8;
        let kind = match op & !4 {
            LOCK_SH => Some(Kind::Read),
            LOCK_EX => Some(Kind::Write),
            LOCK_UN => None,
            _ => return,
        };
        if result.is_err_and(|e| e != Errno::EAGAIN) {
            return;
        }
        let this = Arc::downgrade(file);
        let mut flocks = self.flocks.lock().unwrap_or_else(PoisonError::into_inner);
        flocks.retain(|(f, ..)| f.strong_count() > 0);
        let had = flocks.iter().position(|(f, ..)| Weak::ptr_eq(f, &this));
        if let (Some(i), Some(kind)) = (had, kind)
            && flocks[i].1 == kind
        {
            return;
        }
        if let Some(i) = had {
            flocks.remove(i);
        }
        if let (Some(kind), Ok(())) = (kind, result) {
            flocks.push((this, kind, pid));
        }
    }
    /// The `flock` lock description `file` has, and the process that set it.
    fn flock_of(&self, file: &Arc<dyn FileHandle>) -> Option<(Kind, u32)> {
        let this = Arc::downgrade(file);
        let flocks = self.flocks.lock().unwrap_or_else(PoisonError::into_inner);
        flocks
            .iter()
            .find(|(f, ..)| Weak::ptr_eq(f, &this))
            .map(|&(_, kind, pid)| (kind, pid))
    }
    /// Ends table `pid`'s wait, which a signal interrupted.
    pub(crate) fn stop_waiting(&self, pid: u64) {
        self.table().waiting.remove(&pid);
    }
}

/// The file `d` opens, for the table: its device and inode.
fn key(c: &Context<'_>, d: &Descriptor) -> Result<Key, Errno> {
    Ok((crate::files::descriptor_device(c, d), d.file.stat()?.inode))
}

/// The `lock:` lines `/proc/self/fdinfo` has for descriptor `d`, as Linux's
/// `show_fd_locks`: the description's `flock` lock, then the record locks
/// set through it that this process or the description owns, by where they
/// start, numbered from 1 across both.
pub(crate) fn fdinfo(c: &Context<'_>, d: &Descriptor) -> Vec<u8> {
    let Ok(key) = key(c, d) else {
        return Vec::new();
    };
    // `new_encode_dev` undone.
    let (device, inode) = key;
    let major = (device >> 8) & 0xfff;
    let minor = (device & 0xff) | ((device >> 12) & !0xff);
    let mut out = Vec::new();
    let mut id = 0;
    let mut line = |what: &str, kind: Kind, pid: i32, range: &str| {
        id += 1;
        let kind = if kind == Kind::Write { "WRITE" } else { "READ" };
        out.extend_from_slice(
            format!("lock:\t{id}: {what} {kind} {pid} {major:02x}:{minor:02x}:{inode} {range}\n")
                .as_bytes(),
        );
    };
    let locks = c.processes.locks();
    if let Some((kind, pid)) = locks.flock_of(&d.file) {
        line(
            "FLOCK  ADVISORY ",
            kind,
            c.pid_space().number(pid) as i32,
            "0 EOF",
        );
    }
    let this = Arc::downgrade(&d.file);
    let ours = Owner::Files(c.files.table());
    let table = locks.table();
    let Some(list) = table.files.get(&key) else {
        return out;
    };
    let shown = list.iter().filter(|l| {
        l.live()
            && l.file.as_ref().is_some_and(|f| Weak::ptr_eq(f, &this))
            && (l.owner.same(&ours) || l.owner.same(&Owner::Description(this.clone())))
    });
    for lock in shown {
        let what = match lock.owner {
            Owner::Files(_) => "POSIX  ADVISORY ",
            Owner::Description(_) => "OFDLCK ADVISORY ",
        };
        let pid = lock.pid(&c.pid_space());
        let end = if lock.end == OFFSET_MAX {
            "EOF".to_owned()
        } else {
            lock.end.to_string()
        };
        line(what, lock.kind, pid, &format!("{} {end}", lock.start));
    }
    out
}

/// After a close of `d` through this task's table, drops the table's
/// record locks on the file.
pub(crate) fn closed(c: &Context<'_>, d: &Descriptor) {
    if let Ok(key) = key(c, d) {
        c.processes
            .locks()
            .release(key, &Owner::Files(c.files.table()));
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
        Owner::Files(c.files.table())
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
                raw[24..28].copy_from_slice(&lock.pid(&c.pid_space()).to_le_bytes());
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
    // An OFD lock's wait takes no part in deadlock detection.
    let waiter = (wait && !ofd).then_some(c.files.table());
    loop {
        match locks.set_through(
            key,
            &owner,
            kind,
            (start, end),
            waiter,
            (
                Some(Arc::downgrade(&d.file)),
                c.process.pid,
                (!ofd).then(|| c.files.table_token()),
            ),
        ) {
            Ok(()) => return Ok(0),
            Err(Refused::Deadlock) => return Err(Errno(35)),
            Err(Refused::Conflict) if !wait => return Err(Errno::EAGAIN),
            Err(Refused::Conflict) => {
                if let Err(e) = crate::files::pause_for_lock(c) {
                    if let Some(pid) = waiter {
                        locks.stop_waiting(pid);
                    }
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
        locks.table().files.get(&KEY).map_or_else(Vec::new, |list| {
            list.iter().map(|l| (l.start, l.end, l.kind)).collect()
        })
    }

    #[test]
    fn an_owner_never_conflicts_with_itself() {
        let locks = Locks::default();
        let a = Owner::Files(1);
        assert!(locks.set(KEY, &a, Some(Kind::Write), 0, 9, None).is_ok());
        assert!(locks.conflict(KEY, &a, Kind::Write, 0, 9).is_none());
        assert!(locks.set(KEY, &a, Some(Kind::Read), 3, 4, None).is_ok());
        assert_eq!(
            ranges(&locks),
            [(0, 2, Kind::Write), (3, 4, Kind::Read), (5, 9, Kind::Write)]
        );
    }

    #[test]
    fn readers_share_and_writers_conflict() {
        let locks = Locks::default();
        let (a, b) = (Owner::Files(1), Owner::Files(2));
        assert!(locks.set(KEY, &a, Some(Kind::Read), 0, 9, None).is_ok());
        assert!(locks.set(KEY, &b, Some(Kind::Read), 5, 14, None).is_ok());
        assert!(matches!(
            locks.set(KEY, &b, Some(Kind::Write), 9, 9, None),
            Err(Refused::Conflict)
        ));
        let blocker = locks.conflict(KEY, &b, Kind::Write, 9, 9).unwrap();
        assert!(blocker.owner.same(&a));
        assert!(locks.set(KEY, &b, Some(Kind::Write), 10, 14, None).is_ok());
    }

    #[test]
    fn unlocking_splits_and_same_kind_merges() {
        let locks = Locks::default();
        let a = Owner::Files(1);
        locks.set(KEY, &a, Some(Kind::Write), 0, 9, None).unwrap();
        locks.set(KEY, &a, None, 3, 4, None).unwrap();
        assert_eq!(ranges(&locks), [(0, 2, Kind::Write), (5, 9, Kind::Write)]);
        locks.set(KEY, &a, Some(Kind::Write), 3, 4, None).unwrap();
        assert_eq!(ranges(&locks), [(0, 9, Kind::Write)]);
        // Adjacent locks of the same kind merge too.
        locks
            .set(KEY, &a, Some(Kind::Write), 10, OFFSET_MAX, None)
            .unwrap();
        assert_eq!(ranges(&locks), [(0, OFFSET_MAX, Kind::Write)]);
        locks.set(KEY, &a, None, 0, OFFSET_MAX, None).unwrap();
        assert!(locks.table().files.is_empty());
    }

    #[test]
    fn a_description_lock_goes_with_the_description() {
        let locks = Locks::default();
        let file = paludarium_vfs::MemFs::new().open(b"/f", 66, 0o600).unwrap();
        let owner = Owner::Description(Arc::downgrade(&file));
        locks
            .set(KEY, &owner, Some(Kind::Write), 0, 0, None)
            .unwrap();
        let other = Owner::Files(7);
        assert!(locks.conflict(KEY, &other, Kind::Read, 0, 0).is_some());
        assert_eq!(
            locks
                .conflict(KEY, &other, Kind::Read, 0, 0)
                .unwrap()
                .pid(&crate::namespaces::Namespaces::default().pid),
            -1
        );
        drop(file);
        assert!(locks.conflict(KEY, &other, Kind::Read, 0, 0).is_none());
    }

    #[test]
    fn release_drops_only_that_owner() {
        let locks = Locks::default();
        let (a, b) = (Owner::Files(1), Owner::Files(2));
        locks.set(KEY, &a, Some(Kind::Read), 0, 0, None).unwrap();
        locks.set(KEY, &b, Some(Kind::Read), 0, 0, None).unwrap();
        locks.release(KEY, &a);
        assert!(locks.conflict(KEY, &a, Kind::Write, 0, 0).is_some());
        locks.release_table(2);
        assert!(locks.table().files.is_empty());
    }

    fn deadlock(locks: &Locks, pid: u64, start: u64) -> bool {
        matches!(
            locks.set(
                KEY,
                &Owner::Files(pid),
                Some(Kind::Write),
                start,
                start,
                Some(pid)
            ),
            Err(Refused::Deadlock)
        )
    }

    #[test]
    fn a_cycle_of_waiting_processes_is_a_deadlock() {
        let locks = Locks::default();
        for pid in 1..=3 {
            let start = pid;
            locks
                .set(
                    KEY,
                    &Owner::Files(pid),
                    Some(Kind::Write),
                    start,
                    start,
                    None,
                )
                .unwrap();
        }
        // 2 waits for 3, which waits for 1: 1 waiting for 2 closes the cycle,
        // and 1 is refused without waiting.
        assert!(!deadlock(&locks, 2, 3));
        assert!(!deadlock(&locks, 3, 1));
        assert!(deadlock(&locks, 1, 2));
        assert!(!locks.table().waiting.contains_key(&1));
        // 3 no longer waits once interrupted, and then nothing closes a cycle.
        locks.stop_waiting(3);
        assert!(!deadlock(&locks, 1, 2));
    }

    #[test]
    fn the_second_of_two_waiters_for_each_other_gets_the_deadlock() {
        let locks = Locks::default();
        locks
            .set(KEY, &Owner::Files(1), Some(Kind::Write), 1, 1, None)
            .unwrap();
        locks
            .set(KEY, &Owner::Files(2), Some(Kind::Write), 2, 2, None)
            .unwrap();
        assert!(!deadlock(&locks, 1, 2));
        assert!(deadlock(&locks, 2, 1));
        // The refused one waits for nothing; the first still waits.
        assert!(!locks.table().waiting.contains_key(&2));
        assert_eq!(locks.table().waiting.get(&1).map(|w| w.blocker), Some(2));
    }

    #[test]
    fn letting_go_of_a_lock_ends_the_waits_for_it() {
        let locks = Locks::default();
        let (a, b) = (Owner::Files(1), Owner::Files(2));
        locks.set(KEY, &a, Some(Kind::Write), 0, 0, None).unwrap();
        locks.set(KEY, &a, Some(Kind::Write), 5, 5, None).unwrap();
        locks.set(KEY, &b, Some(Kind::Write), 1, 1, None).unwrap();
        // 2 waits for 1's byte 0; 1 unlocking it ends the wait, so 1 may then
        // wait for 2's byte 1 with no deadlock.
        assert!(!deadlock(&locks, 2, 0));
        locks.set(KEY, &a, None, 0, 0, None).unwrap();
        assert!(!locks.table().waiting.contains_key(&2));
        assert!(!deadlock(&locks, 1, 1));
        // A change to another of 1's locks leaves a wait for byte 5 alone,
        // and so does a lock of another kind next to it, which leaves it as
        // it was.
        locks.stop_waiting(1);
        assert!(!deadlock(&locks, 2, 5));
        locks.set(KEY, &a, Some(Kind::Read), 9, 9, None).unwrap();
        locks.set(KEY, &a, Some(Kind::Read), 6, 6, None).unwrap();
        assert!(locks.table().waiting.contains_key(&2));
        // Merging it with a write lock next to it changes it.
        locks.set(KEY, &a, Some(Kind::Write), 4, 4, None).unwrap();
        assert!(!locks.table().waiting.contains_key(&2));
        assert!(!deadlock(&locks, 2, 5));
        // Closing the file, or exiting, ends the waits for all of 1's locks.
        locks.release(KEY, &a);
        assert!(!locks.table().waiting.contains_key(&2));
        assert!(!deadlock(&locks, 1, 1));
        locks.release_table(2);
        assert!(locks.table().waiting.is_empty());
    }
}
