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

use crate::blocked::{Blocked, Class, Request, Wanted};
use crate::files::Descriptor;
use crate::namespaces::Namespace;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

/// `OFFSET_MAX`: the end of a lock that runs to the end of the file.
const OFFSET_MAX: u64 = i64::MAX as u64;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

/// A file, as its device and inode name it.
pub(crate) type Key = (u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Read,
    Write,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
    /// `locks_conflict`.
    pub(crate) fn conflicts(self, other: Self) -> bool {
        self == Self::Write || other == Self::Write
    }
}

/// What a lock's line in `/proc/locks` and `/proc/<pid>/fdinfo` shows.
#[derive(Clone, Debug)]
pub(crate) struct Status {
    /// Its class and state.
    pub(crate) class: &'static str,
    pub(crate) kind: &'static str,
    /// The process that set it as the reader numbers it, 0 for one outside
    /// the reader's PID namespace, and -1 for a description's record lock.
    pub(crate) pid: i32,
    /// Its file, which the open that breaks a lease has none of.
    pub(crate) key: Option<Key>,
    pub(crate) range: (u64, u64),
}
impl Status {
    pub(crate) fn record(
        owner: &Owner,
        kind: Kind,
        pid: u32,
        key: Key,
        range: (u64, u64),
        space: &Namespace,
    ) -> Self {
        Self {
            class: match owner {
                Owner::Files(_) => "POSIX  ADVISORY ",
                Owner::Description(_) => "OFDLCK ADVISORY ",
            },
            kind: kind.name(),
            pid: owner.pid(pid, space),
            key: Some(key),
            range,
        }
    }
    pub(crate) fn flock(key: Key, kind: Kind, pid: i32) -> Self {
        Self {
            class: "FLOCK  ADVISORY ",
            kind: kind.name(),
            pid,
            key: Some(key),
            range: (0, OFFSET_MAX),
        }
    }
    pub(crate) fn breaker(kind: Kind, pid: i32) -> Self {
        Self {
            class: "LEASE  BREAKER  ",
            kind: kind.name(),
            pid,
            key: None,
            range: (0, OFFSET_MAX),
        }
    }
    /// The line, numbered `id`, as `lock_get_status` prints it, of a lock or
    /// of a request `level` deep under it.
    fn line(&self, id: u64, level: usize) -> String {
        let Self {
            class, kind, pid, ..
        } = self;
        let arrow = match level {
            0 => String::new(),
            level => format!("{:>1$}", "-> ", level + 2),
        };
        let file = match self.key {
            // `new_encode_dev` undone.
            Some((device, inode)) => {
                let (major, minor) = paludarium_types::device_numbers(device);
                format!("{major:02x}:{minor:02x}:{inode}")
            }
            None => "<none>:0".to_owned(),
        };
        let (start, end) = self.range;
        let end = match end {
            OFFSET_MAX => "EOF".to_owned(),
            end => end.to_string(),
        };
        format!("{id}: {arrow}{class} {kind} {pid} {file} {start} {end}\n")
    }
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
    pub(crate) fn same(&self, other: &Self) -> bool {
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
    /// The process `pid`, which set a lock of this owner, as `space` numbers
    /// it (0 outside it), as `locks_translate_pid` gives it, or -1 for a
    /// description's.
    fn pid(&self, pid: u32, space: &Namespace) -> i32 {
        match self {
            Self::Files(_) => space.number(pid) as i32,
            Self::Description(_) => -1,
        }
    }
}

/// A lock, or a lease, with the requests that wait for it and how deep each
/// is under it.
struct Locked {
    status: Status,
    waiters: Vec<(usize, Status)>,
}
impl Locked {
    /// Its lines in `/proc/locks`, numbered `id`.
    fn lines(&self, id: u64) -> String {
        let waiters = self.waiters.iter();
        std::iter::once(self.status.line(id, 0))
            .chain(waiters.map(|(level, waiter)| waiter.line(id, *level)))
            .collect()
    }
}

/// Where a lock is in Linux's lists of all locks (`file_lock_list`), one for
/// each CPU: the CPU it was taken on (`flc_link_cpu`) and how many were taken
/// before it. A list has the latest first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Link {
    cpu: u32,
    number: u64,
}
impl Link {
    /// Its number, which no other lock ever has.
    pub(crate) fn number(self) -> u64 {
        self.number
    }
}

/// How a lock is set: the description it is set through and the process that
/// sets it, the table of a record lock, and the CPU that process runs on.
#[derive(Clone, Default)]
pub(crate) struct Setter {
    file: Option<Weak<dyn FileHandle>>,
    pid: u32,
    holder: Option<Weak<crate::files::Table>>,
    cpu: u32,
}

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
    /// Its place in `/proc/locks`.
    link: Link,
}
impl Lock {
    /// Its number among all locks, its own as long as it lives.
    pub(crate) fn number(&self) -> u64 {
        self.link.number
    }
    pub(crate) fn live(&self) -> bool {
        self.owner.live() && self.table.as_ref().is_none_or(|t| t.strong_count() > 0)
    }
    /// The `l_pid` that `F_GETLK` reports to a process of PID namespace
    /// `space`.
    fn pid(&self, space: &Namespace) -> i32 {
        self.owner.pid(self.pid, space)
    }
    fn status(&self, key: Key, space: &Namespace) -> Status {
        let range = (self.start, self.end);
        Status::record(&self.owner, self.kind, self.pid, key, range, space)
    }
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
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
    /// The record locks by their file.
    records: Mutex<BTreeMap<Key, Vec<Lock>>>,
    /// The `flock` lock of each description that has one, for
    /// `/proc/self/fdinfo` and `/proc/locks` only: the file system keeps the
    /// lock itself and decides its conflicts.
    flocks: Mutex<Vec<Flock>>,
    /// How many locks of any kind, leases too, were taken.
    taken: AtomicU64,
    /// The requests that wait for one. A conflict with a record lock, the
    /// deadlock that waiting for it may be and the wait are one step under
    /// the locks' mutex and then this one's, as under Linux's `flc_lock` and
    /// `blocked_lock_lock`: two processes asking for each other's locks
    /// cannot both miss the cycle.
    blocked: Blocked,
}

/// A description's `flock` lock.
struct Flock {
    file: Weak<dyn FileHandle>,
    key: Key,
    kind: Kind,
    /// The process that set it (Linux's `flc_pid`).
    pid: u32,
    link: Link,
}

impl Locks {
    fn records(&self) -> std::sync::MutexGuard<'_, BTreeMap<Key, Vec<Lock>>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The place of a lock taken now on `cpu` (`locks_insert_global_locks`).
    pub(crate) fn link(&self, cpu: u32) -> Link {
        Link {
            cpu,
            number: self.taken.fetch_add(1, Ordering::SeqCst),
        }
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
        let mut records = self.records();
        let list = records.get_mut(&key)?;
        list.retain(|l| l.live());
        list.iter()
            .find(|l| !l.owner.same(owner) && l.overlaps(start, end) && kind.conflicts(l.kind))
            .cloned()
    }
    /// Sets `kind` on `start..=end`, or with `None` unlocks it, for `owner`,
    /// as `posix_lock_inode` does: the owner's own locks there are replaced,
    /// split around the range, or merged with it when of the same kind and
    /// touching it, and the requests that wait for one this cuts or drops
    /// wake. A conflicting lock of another owner is the error; `request`, if
    /// any, then waits for it, unless it would wait for itself.
    #[cfg(test)]
    pub(crate) fn set(
        &self,
        key: Key,
        owner: &Owner,
        kind: Option<Kind>,
        start: u64,
        end: u64,
        request: Option<&Request<'_>>,
    ) -> Result<(), Refused> {
        self.set_through(key, owner, kind, (start, end), request, &Setter::default())
    }
    /// `set` by `setter`. A lock merged with the owner's first one of the
    /// same kind keeps that one's description, process and place in
    /// `/proc/locks`, as `posix_lock_inode` extends it, unless one of the
    /// other kind it covers comes before that: then, as any new lock, it
    /// takes `setter`'s. The pieces of a split lock keep its description and
    /// process, and the right one its place.
    pub(crate) fn set_through(
        &self,
        key: Key,
        owner: &Owner,
        kind: Option<Kind>,
        (start, end): (u64, u64),
        request: Option<&Request<'_>>,
        setter: &Setter,
    ) -> Result<(), Refused> {
        let mut records = self.records();
        let list = records.entry(key).or_default();
        list.retain(|l| l.live());
        // A request that was not woken sleeps on.
        if request.is_some_and(|r| r.asleep(|n| list.iter().any(|l| l.number() == n))) {
            return Err(Refused::Conflict);
        }
        if let Some(kind) = kind
            && let Some(conflict) = list
                .iter()
                .find(|l| !l.owner.same(owner) && l.overlaps(start, end) && kind.conflicts(l.kind))
        {
            let Some(request) = request else {
                return Err(Refused::Conflict);
            };
            let conflict = conflict.clone();
            let wanted = Wanted {
                class: Class::Record(owner.clone()),
                kind,
                key,
                range: (start, end),
                pid: setter.pid,
            };
            return Err(if request.wait_for_record(&conflict, wanted, &records) {
                Refused::Conflict
            } else {
                Refused::Deadlock
            });
        }
        // The owner's locks, by their start, out of the list, where they are
        // together: their place in it.
        let place = list
            .iter()
            .position(|l| l.owner.same(owner))
            .unwrap_or(list.len());
        let mut own = Vec::new();
        list.retain(|l| {
            let mine = l.owner.same(owner);
            if mine {
                own.push(l.clone());
            }
            !mine
        });
        let mut kept: Vec<Lock> = Vec::with_capacity(own.len() + 2);
        // The owner's locks this cuts, which wake the requests under them.
        let mut cut = Vec::new();
        // The new lock, if this makes one.
        let mut new = None;
        let made = |kind, (start, end)| Lock {
            owner: owner.clone(),
            kind,
            start,
            end,
            file: setter.file.clone(),
            pid: setter.pid,
            table: setter.holder.clone(),
            link: self.link(setter.cpu),
        };
        // The new lock's range, which the locks merged with it extend, and
        // its place in `kept` once one of them is there.
        let (mut new_start, mut new_end) = (start, end);
        let mut at: Option<usize> = None;
        // A lock this splits in two: its left piece, which is new.
        let mut left = None;
        for l in own {
            let touches =
                l.start <= new_end.saturating_add(1) && new_start <= l.end.saturating_add(1);
            if Some(l.kind) == kind && touches {
                new_start = new_start.min(l.start);
                new_end = new_end.max(l.end);
                match at {
                    Some(at) => {
                        kept[at] = Lock {
                            start: new_start,
                            end: new_end,
                            ..kept[at].clone()
                        }
                    }
                    None => {
                        at = Some(kept.len());
                        kept.push(Lock {
                            start: new_start,
                            end: new_end,
                            ..l
                        });
                    }
                }
            } else if l.overlaps(new_start, new_end) {
                let (before, after) = (l.start < new_start, l.end > new_end);
                if before || after {
                    cut.push(l.number());
                }
                if before && after {
                    left = Some(Lock {
                        end: new_start - 1,
                        ..l.clone()
                    });
                } else if before {
                    kept.push(Lock {
                        end: new_start - 1,
                        ..l.clone()
                    });
                }
                if after {
                    kept.push(Lock {
                        start: new_end + 1,
                        ..l
                    });
                } else if !before
                    && at.is_none()
                    && let Some(kind) = kind
                {
                    at = Some(kept.len());
                    let lock = made(kind, (new_start, new_end));
                    new = Some(lock.number());
                    kept.push(lock);
                }
            } else {
                kept.push(l);
            }
        }
        if at.is_none()
            && let Some(kind) = kind
        {
            let lock = made(kind, (new_start, new_end));
            new = Some(lock.number());
            kept.push(lock);
        }
        // The left piece is newer than the lock that split it off.
        if let Some(left) = left {
            kept.push(Lock {
                link: self.link(setter.cpu),
                ..left
            });
        }
        kept.sort_by_key(|l| l.start);
        list.splice(place..place, kept);
        if list.is_empty() {
            records.remove(&key);
        }
        // A lock merged into an old one wakes the requests under it as the
        // request is dropped.
        if let (Some(request), Some(new)) = (request, new) {
            request.got(new);
        }
        for number in cut {
            self.blocked.wake(number);
        }
        Ok(())
    }
    /// Drops `owner`'s locks on the file, as a close of any descriptor of it
    /// through the table does to the table's record locks
    /// (`locks_remove_posix`).
    pub(crate) fn release(&self, key: Key, owner: &Owner) {
        let mut records = self.records();
        if let Some(list) = records.get_mut(&key) {
            list.retain(|l| l.live() && !l.owner.same(owner));
            if list.is_empty() {
                records.remove(&key);
            }
        }
    }
    /// Drops every record lock of descriptor table `pid`, which no task uses
    /// any more (`put_files_struct` closing its files).
    pub(crate) fn release_table(&self, pid: u64) {
        let owner = Owner::Files(pid);
        self.records().retain(|_, list| {
            list.retain(|l| l.live() && !l.owner.same(&owner));
            !list.is_empty()
        });
    }
    /// Notes what `flock(op)` through `file` by process `pid` did, as
    /// `flock_lock_inode` changes a description's lock: an unlock, or a
    /// change of kind, drops the old lock first, even when the new one then
    /// conflicts (`EAGAIN`); asking again for the kind it has keeps the lock
    /// as it was, with the process that set it. `key` is its file, without
    /// which a new lock is not listed, and `cpu` the CPU the process runs on.
    /// A conflict makes `request`, if any, wait for the first lock in its
    /// way, unless only a program on the host has one.
    pub(crate) fn flocked(
        &self,
        (file, key): (&Arc<dyn FileHandle>, Option<Key>),
        (pid, cpu): (u32, u32),
        op: u32,
        result: Result<(), Errno>,
        request: Option<&Request<'_>>,
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
        flocks.retain(|l| l.file.strong_count() > 0);
        let had = flocks.iter().position(|l| Weak::ptr_eq(&l.file, &this));
        if let (Some(i), Some(kind)) = (had, kind)
            && flocks[i].kind == kind
        {
            return;
        }
        if let Some(i) = had {
            flocks.remove(i);
        }
        let (Some(kind), Some(key)) = (kind, key) else {
            return;
        };
        if result.is_ok() {
            let link = self.link(cpu);
            if let Some(request) = request {
                request.got(link.number);
            }
            flocks.push(Flock {
                file: this,
                key,
                kind,
                pid,
                link,
            });
        } else if let Some(request) = request {
            let mut conflicts = flocks
                .iter()
                .filter(|l| l.key == key && kind.conflicts(l.kind))
                .map(|l| l.link.number);
            if request.asleep(|number| conflicts.clone().any(|n| n == number)) {
                return;
            }
            match conflicts.next() {
                Some(number) => request.wait(
                    (number, false),
                    Wanted {
                        class: Class::Flock(this),
                        kind,
                        key,
                        range: (0, OFFSET_MAX),
                        pid,
                    },
                ),
                None => request.unlink(),
            }
        }
    }
    /// The `flock` lock description `file` has, and the process that set it.
    fn flock_of(&self, file: &Arc<dyn FileHandle>) -> Option<(Kind, u32)> {
        let this = Arc::downgrade(file);
        let flocks = self.flocks.lock().unwrap_or_else(PoisonError::into_inner);
        flocks
            .iter()
            .find(|l| Weak::ptr_eq(&l.file, &this))
            .map(|l| (l.kind, l.pid))
    }
    /// The locks of all files, and the leases `leases`, each with the
    /// requests that wait for it, where Linux keeps them in
    /// `file_lock_list`. No lock or request changes meanwhile.
    fn all(&self, leases: &[crate::leases::Lease], space: &Namespace) -> Vec<Locked> {
        let records = self.records();
        let flocks = self.flocks.lock().unwrap_or_else(PoisonError::into_inner);
        let mut all = Vec::new();
        for (&key, list) in records.iter() {
            let live = list.iter().filter(|l| l.live());
            all.extend(live.map(|l| (l.link, l.status(key, space))));
        }
        let live = flocks.iter().filter(|l| l.file.strong_count() > 0);
        all.extend(live.map(|l| {
            let pid = space.number(l.pid) as i32;
            (l.link, Status::flock(l.key, l.kind, pid))
        }));
        all.extend(leases.iter().map(|l| (l.link(), l.status(space))));
        // Each CPU's list in turn, the latest lock of it first.
        all.sort_by_key(|(link, _)| (link.cpu, std::cmp::Reverse(link.number)));
        let numbers: Vec<u64> = all.iter().map(|(link, _)| link.number).collect();
        let waiters = self.blocked.under(&numbers, space);
        all.into_iter()
            .zip(waiters)
            .map(|((_, status), waiters)| Locked { status, waiters })
            .collect()
    }
    /// The requests that wait for a lock.
    pub(crate) fn blocked(&self) -> &Blocked {
        &self.blocked
    }
}

/// The file `d` opens, for the table: its device and inode.
pub(crate) fn key(c: &Context<'_>, d: &Descriptor) -> Result<Key, Errno> {
    Ok((crate::files::descriptor_device(c, d), d.file.stat()?.inode))
}

/// The `lock:` lines `/proc/self/fdinfo` has for descriptor `d`, as Linux's
/// `show_fd_locks`: the description's `flock` lock, then the record locks
/// set through it that this process or the description owns, in the file's
/// list, then its lease, numbered from 1 across them.
pub(crate) fn fdinfo(
    c: &Context<'_>,
    d: &Descriptor,
    fs: &dyn paludarium_vfs::FileSystem,
    table: u64,
) -> Vec<u8> {
    let Ok(inode) = d.file.stat().map(|stat| stat.inode) else {
        return Vec::new();
    };
    let key = (crate::files::descriptor_device_in(fs, d), inode);
    let space = c.pid_space();
    let locks = c.processes.locks();
    let mut shown = Vec::new();
    if let Some((kind, pid)) = locks.flock_of(&d.file) {
        shown.push(Status::flock(key, kind, space.number(pid) as i32));
    }
    let this = Arc::downgrade(&d.file);
    let ours = Owner::Files(table);
    if let Some(list) = locks.records().get(&key) {
        let listed = list.iter().filter(|l| {
            l.live()
                && l.file.as_ref().is_some_and(|f| Weak::ptr_eq(f, &this))
                && (l.owner.same(&ours) || l.owner.same(&Owner::Description(this.clone())))
        });
        shown.extend(listed.map(|l| l.status(key, &space)));
    }
    shown.extend(crate::leases::of(&c.files.caches, &d.file).map(|l| l.status(&space)));
    let lines = (1..).zip(shown);
    lines
        .flat_map(|(id, status)| format!("lock:\t{}", status.line(id, 0)).into_bytes())
        .collect()
}

/// `/proc/locks`, as Linux's `locks_show` prints the locks there are when a
/// read reaches them: those of each CPU in turn, the latest taken on it
/// first, each with the requests that wait for it, and without those of
/// processes the reader's PID namespace does not number, which keep their
/// places.
pub(crate) fn proc_file(c: &Context<'_>, flags: u32) -> crate::seq::SeqFile {
    let records = ProcRecords {
        processes: Arc::clone(c.processes),
        caches: Arc::clone(&c.files.caches),
        space: c.pid_space(),
    };
    crate::seq::SeqFile::open(Box::new(records), flags)
}
struct ProcRecords {
    processes: Arc<crate::processes::Processes>,
    caches: Arc<crate::page_cache::PageCaches>,
    space: Arc<Namespace>,
}
impl ProcRecords {
    fn now(&self) -> crate::seq::Held {
        let leases = crate::leases::leases(&self.caches);
        let all = self.processes.locks().all(&leases, &self.space);
        let lines = |(id, locked): (u64, Locked)| match locked.status.pid {
            0 => Vec::new(),
            _ => locked.lines(id).into_bytes(),
        };
        crate::seq::Held((1..).zip(all).map(lines).collect())
    }
}
impl crate::seq::Records for ProcRecords {
    fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
        self.now().record(index)
    }
    /// `locks_start`'s `file_rwsem` and `blocked_lock_lock`.
    fn held(&self) -> Option<Box<dyn crate::seq::Records>> {
        Some(Box::new(self.now()))
    }
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
    let request = wait.then(|| locks.blocked().request());
    loop {
        match locks.set_through(
            key,
            &owner,
            kind,
            (start, end),
            request.as_ref(),
            &Setter {
                file: Some(Arc::downgrade(&d.file)),
                pid: c.process.pid,
                holder: (!ofd).then(|| c.files.table_token()),
                cpu: crate::syscalls::cpu(c),
            },
        ) {
            Ok(()) => return Ok(0),
            Err(Refused::Deadlock) => return Err(Errno(35)),
            Err(Refused::Conflict) if !wait => return Err(Errno::EAGAIN),
            Err(Refused::Conflict) => crate::files::pause_for_lock(c)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_vfs::HostFs;

    const KEY: Key = (1, 2);

    fn ranges(locks: &Locks) -> Vec<(u64, u64, Kind)> {
        locks.records().get(&KEY).map_or_else(Vec::new, |list| {
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
        assert!(locks.records().is_empty());
    }

    /// The locks of `KEY` by their start, with how many were taken before
    /// each and the process that set it.
    fn places(locks: &Locks) -> Vec<(u64, u64, u64, u32)> {
        let records = locks.records();
        let mut all: Vec<_> = records[&KEY]
            .iter()
            .map(|l| (l.start, l.end, l.link.number, l.pid))
            .collect();
        all.sort_unstable();
        all
    }

    #[test]
    fn locks_keep_or_take_their_places_as_posix_lock_inode_lists_them() {
        let locks = Locks::default();
        let a = Owner::Files(1);
        let set = |kind, start, end, pid| {
            let setter = Setter {
                pid,
                ..Setter::default()
            };
            locks
                .set_through(KEY, &a, kind, (start, end), None, &setter)
                .unwrap();
        };
        let (read, write) = (Some(Kind::Read), Some(Kind::Write));
        set(write, 0, 9, 1);
        set(read, 20, 29, 2);
        // Merged into the first, which keeps its place and process.
        set(write, 10, 14, 3);
        assert_eq!(places(&locks), [(0, 14, 0, 1), (20, 29, 1, 2)]);
        // Split: the left piece is new.
        set(None, 3, 4, 4);
        assert_eq!(
            places(&locks),
            [(0, 2, 2, 1), (5, 14, 0, 1), (20, 29, 1, 2)]
        );
        // Covering a write lock before it meets a read lock: a new lock,
        // which the read lock is merged into.
        set(read, 5, 19, 5);
        assert_eq!(places(&locks), [(0, 2, 2, 1), (5, 29, 3, 5)]);
        // Splitting one with a lock of the other kind: that one first.
        set(write, 10, 12, 6);
        assert_eq!(
            places(&locks),
            [(0, 2, 2, 1), (5, 9, 5, 5), (10, 12, 4, 6), (13, 29, 3, 5)]
        );
        // A cut at either end keeps the lock.
        set(None, 0, 0, 7);
        set(None, 29, 40, 7);
        assert_eq!(
            places(&locks),
            [(1, 2, 2, 1), (5, 9, 5, 5), (10, 12, 4, 6), (13, 28, 3, 5)]
        );
    }

    #[test]
    fn the_first_conflict_is_the_first_owners_to_lock_the_file() {
        let locks = Locks::default();
        let (a, b, c) = (Owner::Files(1), Owner::Files(2), Owner::Files(3));
        locks.set(KEY, &b, Some(Kind::Write), 50, 59, None).unwrap();
        locks.set(KEY, &a, Some(Kind::Write), 0, 9, None).unwrap();
        locks.set(KEY, &b, Some(Kind::Write), 20, 29, None).unwrap();
        let first = locks.conflict(KEY, &c, Kind::Read, 0, 99).unwrap();
        assert_eq!((first.start, first.end), (20, 29));
    }

    #[test]
    fn the_locks_are_listed_by_cpu_and_the_latest_first() {
        let locks = Locks::default();
        let space = crate::namespaces::Namespaces::default().pid;
        for (start, cpu) in [(0, 1), (10, 0), (20, 1), (30, 0)] {
            let setter = Setter {
                pid: 7,
                cpu,
                ..Setter::default()
            };
            locks
                .set_through(
                    KEY,
                    &Owner::Files(start),
                    Some(Kind::Read),
                    (start, OFFSET_MAX),
                    None,
                    &setter,
                )
                .unwrap();
        }
        let lines: Vec<String> = locks
            .all(&[], &space)
            .iter()
            .map(|lock| lock.lines(3))
            .collect();
        assert_eq!(
            lines,
            [30, 10, 20, 0]
                .map(|start| format!("3: POSIX  ADVISORY  READ 7 00:01:2 {start} EOF\n"))
        );
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
        assert!(locks.records().is_empty());
    }

    fn owned(pid: u64) -> Owner {
        Owner::Files(pid)
    }
    /// Takes a write lock on byte `start` for table `pid`.
    fn take(locks: &Locks, pid: u64, start: u64) {
        locks
            .set(KEY, &owned(pid), Some(Kind::Write), start, start, None)
            .unwrap();
    }
    /// Asks for a write lock on byte `start` for table `pid` with `request`,
    /// which waits: whether that is a deadlock.
    fn deadlock(locks: &Locks, request: &Request<'_>, pid: u64, start: u64) -> bool {
        let range = (start, start);
        match waits(locks, request, &owned(pid), Kind::Write, range) {
            Err(Refused::Deadlock) => true,
            Err(Refused::Conflict) => false,
            Ok(()) => panic!("no conflict"),
        }
    }
    fn waits(
        locks: &Locks,
        request: &Request<'_>,
        owner: &Owner,
        kind: Kind,
        range: (u64, u64),
    ) -> Result<(), Refused> {
        let setter = match owner {
            Owner::Files(pid) => Setter {
                pid: *pid as u32,
                ..Setter::default()
            },
            Owner::Description(_) => Setter::default(),
        };
        locks.set_through(KEY, owner, Some(kind), range, Some(request), &setter)
    }
    /// `/proc/locks`, without the locks' numbers and files.
    fn listed(locks: &Locks) -> Vec<String> {
        let space = crate::namespaces::Namespaces::default().pid;
        let lines: Vec<String> = locks
            .all(&[], &space)
            .iter()
            .flat_map(|lock| {
                let lines = lock.lines(1);
                lines.lines().map(str::to_owned).collect::<Vec<_>>()
            })
            .collect();
        let strip = |line: &String| {
            let line = line.strip_prefix("1: ").unwrap().trim_end();
            line.replace(" ADVISORY ", "").replace(" 00:01:2", "")
        };
        lines.iter().map(strip).collect()
    }

    #[test]
    fn a_cycle_of_waiting_processes_is_a_deadlock() {
        let locks = Locks::default();
        for pid in 1..=3 {
            take(&locks, pid, pid);
        }
        let [one, two, three] = [0; 3].map(|_| locks.blocked().request());
        // 2 waits for 3, which waits for 1: 1 waiting for 2 closes the cycle,
        // and 1 is refused without waiting.
        assert!(!deadlock(&locks, &two, 2, 3));
        assert!(!deadlock(&locks, &three, 3, 1));
        assert!(deadlock(&locks, &one, 1, 2));
        assert!(!one.asleep(|_| true));
        // 3 no longer waits once interrupted, and then nothing closes a cycle.
        drop(three);
        assert!(!deadlock(&locks, &one, 1, 2));
    }

    #[test]
    fn the_second_of_two_waiters_for_each_other_gets_the_deadlock() {
        let locks = Locks::default();
        take(&locks, 1, 1);
        take(&locks, 2, 2);
        let [one, two] = [0; 2].map(|_| locks.blocked().request());
        assert!(!deadlock(&locks, &one, 1, 2));
        assert!(deadlock(&locks, &two, 2, 1));
        // The refused one waits for nothing; the first still waits.
        assert!(!two.asleep(|_| true));
        assert!(one.asleep(|_| true));
    }

    #[test]
    fn a_deadlock_is_looked_for_through_eleven_waiters() {
        for length in [11, 12] {
            let locks = Locks::default();
            // Each waits for the next, and the last for the first.
            for pid in 0..=length {
                take(&locks, pid, pid);
            }
            let requests: Vec<_> = (0..=length).map(|_| locks.blocked().request()).collect();
            for pid in 1..=length {
                let next = (pid + 1) % (length + 1);
                assert!(!deadlock(&locks, &requests[pid as usize], pid, next));
            }
            assert_eq!(deadlock(&locks, &requests[0], 0, 1), length == 11);
        }
    }

    #[test]
    fn a_description_that_waits_takes_part_in_another_owners_deadlock() {
        let locks = Locks::default();
        let file = paludarium_vfs::MemFs::new().open(b"/f", 66, 0o600).unwrap();
        let description = Owner::Description(Arc::downgrade(&file));
        take(&locks, 1, 1);
        locks
            .set(KEY, &description, Some(Kind::Write), 2, 2, None)
            .unwrap();
        let [one, other] = [0; 2].map(|_| locks.blocked().request());
        // The description's own request is never the deadlock.
        assert!(!deadlock(&locks, &one, 1, 2));
        assert!(matches!(
            waits(&locks, &other, &description, Kind::Write, (1, 1)),
            Err(Refused::Conflict)
        ));
        drop(one);
        let one = locks.blocked().request();
        assert!(deadlock(&locks, &one, 1, 2));
    }

    #[test]
    fn letting_go_of_a_lock_ends_the_waits_for_it() {
        let locks = Locks::default();
        let a = owned(1);
        take(&locks, 1, 0);
        take(&locks, 1, 5);
        take(&locks, 2, 1);
        let [mut one, two] = [0; 2].map(|_| locks.blocked().request());
        // 2 waits for 1's byte 0; 1 unlocking it ends the wait, so 1 may then
        // wait for 2's byte 1 with no deadlock.
        assert!(!deadlock(&locks, &two, 2, 0));
        locks.set(KEY, &a, None, 0, 0, None).unwrap();
        assert!(!deadlock(&locks, &one, 1, 1));
        // A change to another of 1's locks leaves a wait for byte 5 alone,
        // and so does a lock of another kind next to it, which leaves it as
        // it was, and a lock it takes in.
        drop(one);
        one = locks.blocked().request();
        assert!(!deadlock(&locks, &two, 2, 5));
        locks.set(KEY, &a, Some(Kind::Read), 9, 9, None).unwrap();
        locks.set(KEY, &a, Some(Kind::Read), 6, 6, None).unwrap();
        locks.set(KEY, &a, Some(Kind::Write), 4, 4, None).unwrap();
        assert!(deadlock(&locks, &one, 1, 1));
        // Cutting it wakes the request, as does dropping it for one of
        // another kind.
        locks.set(KEY, &a, None, 4, 4, None).unwrap();
        assert!(!deadlock(&locks, &one, 1, 1));
        drop(one);
        one = locks.blocked().request();
        assert!(!deadlock(&locks, &two, 2, 5));
        locks.set(KEY, &a, Some(Kind::Read), 5, 5, None).unwrap();
        assert!(!deadlock(&locks, &one, 1, 1));
        drop(one);
        one = locks.blocked().request();
        // Closing the file, or exiting, ends the waits for all of 1's locks.
        assert!(!deadlock(&locks, &two, 2, 5));
        assert!(deadlock(&locks, &one, 1, 1));
        locks.release(KEY, &a);
        assert!(!deadlock(&locks, &one, 1, 1));
        drop(one);
        one = locks.blocked().request();
        take(&locks, 1, 5);
        assert!(!deadlock(&locks, &two, 2, 5));
        locks.release_table(1);
        assert!(!deadlock(&locks, &one, 1, 1));
    }

    #[test]
    fn a_request_waits_behind_an_earlier_one_it_conflicts_with() {
        let locks = Locks::default();
        locks
            .set_through(
                KEY,
                &owned(1),
                Some(Kind::Write),
                (0, 99),
                None,
                &Setter {
                    pid: 1,
                    ..Setter::default()
                },
            )
            .unwrap();
        let [two, three, four, five] = [0; 4].map(|_| locks.blocked().request());
        let ask = |request: &Request<'_>, pid, kind, range| {
            let result = waits(&locks, request, &owned(pid), kind, range);
            matches!(result, Err(Refused::Conflict))
        };
        assert!(ask(&two, 2, Kind::Write, (0, 9)));
        assert!(ask(&three, 3, Kind::Read, (5, 14)));
        assert!(ask(&four, 4, Kind::Read, (20, 29)));
        assert!(ask(&five, 5, Kind::Write, (10, 10)));
        // 5 is behind 3, which is behind 2; 4 conflicts with neither.
        let before = [
            "POSIX  WRITE 1 0 99",
            "-> POSIX  WRITE 2 0 9",
            " -> POSIX  READ 3 5 14",
            "-> POSIX  READ 4 20 29",
            "-> POSIX  WRITE 5 10 10",
        ];
        assert_eq!(listed(&locks), before);
        assert!(three.behind() && !five.behind());
        // Asking again changes nothing.
        assert!(ask(&three, 3, Kind::Read, (5, 14)));
        assert!(ask(&two, 2, Kind::Write, (0, 9)));
        assert_eq!(listed(&locks), before);
        // Once 1 lets go, 3 still lets 2 go first, whose lock it then waits
        // for.
        locks.release(KEY, &owned(1));
        assert!(ask(&three, 3, Kind::Read, (5, 14)));
        assert!(waits(&locks, &two, &owned(2), Kind::Write, (0, 9)).is_ok());
        assert_eq!(
            listed(&locks),
            ["POSIX  WRITE 2 0 9", "-> POSIX  READ 3 5 14"]
        );
        drop(two);
        assert!(waits(&locks, &four, &owned(4), Kind::Read, (20, 29)).is_ok());
        // 3's end leaves 5 free to take its lock.
        assert!(waits(&locks, &five, &owned(5), Kind::Write, (10, 10)).is_ok());
        assert!(ask(&three, 3, Kind::Read, (5, 14)));
        drop(three);
        assert_eq!(
            listed(&locks),
            [
                "POSIX  WRITE 5 10 10",
                "POSIX  READ 4 20 29",
                "POSIX  WRITE 2 0 9"
            ]
        );
    }

    #[test]
    fn a_request_that_ends_or_moves_wakes_those_behind_it() {
        let locks = Locks::default();
        take(&locks, 1, 0);
        take(&locks, 1, 2);
        let [two, three] = [0; 2].map(|_| locks.blocked().request());
        let ask = |request: &Request<'_>, pid, range| {
            let result = waits(&locks, request, &owned(pid), Kind::Write, range);
            matches!(result, Err(Refused::Conflict))
        };
        assert!(ask(&two, 2, (0, 2)));
        assert!(ask(&three, 3, (0, 0)));
        assert!(three.behind());
        // 2 goes on to wait for the other lock; 3, woken, finds nothing in
        // its way.
        locks.set(KEY, &owned(1), None, 0, 0, None).unwrap();
        assert!(ask(&two, 2, (0, 2)));
        assert!(!three.behind());
        assert!(waits(&locks, &three, &owned(3), Kind::Write, (0, 0)).is_ok());
        drop(three);
        let three = locks.blocked().request();
        assert!(ask(&three, 3, (2, 2)));
        assert!(three.behind());
        drop(two);
        assert!(!three.behind());
        assert!(ask(&three, 3, (2, 2)));
        assert!(!three.behind() && three.asleep(|_| true));
    }

    #[test]
    fn flock_requests_are_listed_under_the_first_lock_in_their_way() {
        let locks = Locks::default();
        let fs = paludarium_vfs::MemFs::new();
        let [a, b, c, d] = [0; 4].map(|_| fs.open(b"/f", 66, 0o600).unwrap());
        let (shared, exclusive, again) = (1, 2, Err(Errno::EAGAIN));
        locks.flocked((&a, Some(KEY)), (1, 0), shared, Ok(()), None);
        let [two, three, four] = [0; 3].map(|_| locks.blocked().request());
        locks.flocked((&b, Some(KEY)), (2, 0), exclusive, again, Some(&two));
        locks.flocked((&c, Some(KEY)), (3, 0), exclusive, again, Some(&three));
        // Not one of the guest's is in its way.
        locks.flocked((&d, Some((1, 3))), (4, 0), exclusive, again, Some(&four));
        assert!(!two.behind() && three.behind() && !four.asleep(|_| true));
        assert_eq!(
            listed(&locks),
            [
                "FLOCK  READ 1 0 EOF",
                "-> FLOCK  WRITE 2 0 EOF",
                " -> FLOCK  WRITE 3 0 EOF"
            ]
        );
        locks.flocked((&a, Some(KEY)), (1, 0), 8, Ok(()), None);
        assert!(three.behind());
        locks.flocked((&b, Some(KEY)), (2, 0), exclusive, Ok(()), Some(&two));
        drop(two);
        assert!(!three.behind());
        assert_eq!(
            listed(&locks),
            ["FLOCK  WRITE 2 0 EOF", "-> FLOCK  WRITE 3 0 EOF"]
        );
        // Its description's close ends the lock.
        drop(b);
        locks.flocked((&c, Some(KEY)), (3, 0), exclusive, Ok(()), Some(&three));
        assert_eq!(listed(&locks), ["FLOCK  WRITE 3 0 EOF"]);
    }

    #[test]
    fn opens_that_break_a_lease_are_listed_under_it() {
        let blocked = Blocked::default();
        let space = crate::namespaces::Namespaces::default().pid;
        let wanted = |kind| Wanted {
            class: Class::Breaker,
            kind,
            key: KEY,
            range: (0, OFFSET_MAX),
            pid: 5,
        };
        let requests = [0; 4].map(|_| blocked.request());
        let kinds = [Kind::Read, Kind::Read, Kind::Write, Kind::Write];
        for (request, kind) in requests.iter().zip(kinds) {
            request.wait((7, false), wanted(kind));
        }
        let lines: Vec<String> = blocked.under(&[7], &space)[0]
            .iter()
            .map(|(level, status)| status.line(2, *level))
            .collect();
        assert_eq!(
            lines,
            [
                "2: -> LEASE  BREAKER   READ 5 <none>:0 0 EOF\n",
                "2:  -> LEASE  BREAKER   WRITE 5 <none>:0 0 EOF\n",
                "2:   -> LEASE  BREAKER   WRITE 5 <none>:0 0 EOF\n",
                "2: -> LEASE  BREAKER   READ 5 <none>:0 0 EOF\n",
            ]
        );
    }

    #[test]
    fn a_flock_lock_of_an_unknown_file_is_not_listed_and_its_unlock_is() {
        const LOCK_SH: u32 = 1;
        const LOCK_EX: u32 = 2;
        const LOCK_UN: u32 = 8;
        let locks = Locks::default();
        let file = paludarium_vfs::MemFs::new().open(b"/f", 66, 0o600).unwrap();
        let flock = |key, op| {
            locks.flocked((&file, key), (1, 0), op, Ok(()), None);
            locks.flock_of(&file)
        };
        assert_eq!(flock(None, LOCK_SH), None);
        assert_eq!(flock(Some(KEY), LOCK_SH), Some((Kind::Read, 1)));
        // The kind it has stays, and a change of kind drops the old lock.
        assert_eq!(flock(None, LOCK_SH), Some((Kind::Read, 1)));
        assert_eq!(flock(None, LOCK_EX), None);
        assert_eq!(flock(Some(KEY), LOCK_EX), Some((Kind::Write, 1)));
        assert_eq!(flock(None, LOCK_UN), None);
    }
}
