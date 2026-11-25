//! File leases (`fcntl`'s `F_SETLEASE` and `F_GETLEASE`), as Linux's
//! `fs/locks.c` takes and gives them back: a read or a write lease on an
//! open description of a regular file, held until `F_UNLCK` or the
//! description's last close (`locks_remove_file`).
//!
//! A lease is refused as `fcntl_setlease`, `vfs_setlease` and
//! `generic_add_lease` refuse it, in their order: a directory, then a type
//! other than `F_RDLCK`, `F_WRLCK` or `F_UNLCK` (`EINVAL`); a file the
//! caller neither owns (by its file system user ID) nor has `CAP_LEASE`
//! over in the first user namespace (`EACCES`); a file whose file system
//! takes none, or one that is not regular (`EINVAL`); an open that
//! conflicts (`lease_open_conflict`, `EAGAIN`): for a read lease, any
//! description open for writing, and for a write lease, any description
//! but this one open for reading or writing, or a program running from
//! the file; for a write lease, another description's lease (`EAGAIN`);
//! and a new lease while `/proc/sys/fs/leases-enable` is 0 (`EINVAL`).
//! Asking again through the same description changes its lease's type.
//! A lease taken gives the description an owner if it has none
//! (`lease_setup`'s `__f_setown`), and one given back takes the owner and
//! the `F_SETSIG` signal away (`lease_modify`'s `f_delown`); `F_UNLCK`
//! with no lease is `EAGAIN` (`generic_delete_lease`). `F_GETLEASE` gives
//! the type the description's lease is to become while a break of it is
//! pending (`target_leasetype`), its type otherwise, or `F_UNLCK`.
//!
//! An open ([`breaking`]) or a `truncate` that conflicts with a lease breaks
//! it as `__break_lease` does: an open for reading only a write lease, any
//! other both kinds, the opener's own leases too. The first break of a
//! lease signals its holder (`SIGIO`, or the `F_SETSIG` signal with
//! `POLL_MSG`), and the opener waits, with its write or read access counted
//! already, until the holder gives the lease back or makes it one that does
//! not conflict, or until `/proc/sys/fs/lease-break-time` seconds pass,
//! when the lease is taken away, or made a read lease if only a reader
//! broke it (`time_out_leases`); 0 or less waits without end. `O_NONBLOCK`
//! gives `EWOULDBLOCK` in place of the wait, and a signal ends it
//! (`ERESTARTSYS`).

use crate::files::Descriptor;
use crate::namespaces::Namespace;
use crate::page_cache::{Key, PageCaches, ReadAccess, WriteAccess};
use crate::record_locks::{Link, Status};
use crate::syscalls::Context;
use paludarium_host::{ClockId, FileHandle};
use paludarium_types::Errno;
use std::cell::Cell;
use std::sync::{Arc, PoisonError};

const F_RDLCK: u64 = 0;
const F_WRLCK: u64 = 1;
const F_UNLCK: u64 = 2;
const CAP_LEASE: u64 = 1 << 28;
const REGULAR: u32 = 0o100000;
const DIRECTORY: u32 = 0o040000;
const O_NONBLOCK: u32 = 0o4000;
const O_PATH: u32 = 0o10000000;

/// A lease on a file, held by an open description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    key: Key,
    /// The description's address, which tells it from the others while it
    /// is open; it gives its leases back as it goes ([`closed`]).
    file: usize,
    /// `F_RDLCK` or `F_WRLCK`.
    kind: u64,
    /// The process that took it (`flc_pid`).
    pid: u32,
    /// Its place in `/proc/locks`.
    link: Link,
    /// The descriptor it was last set through (`fa_fd`), which its signal
    /// names.
    fd: i32,
    /// `FL_UNLOCK_PENDING`: a writer broke it.
    unlock_pending: bool,
    /// `FL_DOWNGRADE_PENDING`: a reader broke it.
    downgrade_pending: bool,
    /// When a writer's break takes it away (`fl_break_time`), in monotonic
    /// nanoseconds; 0 is never. Kept after the break, as Linux keeps it.
    break_time: u64,
    /// When a reader's break makes it a read lease (`fl_downgrade_time`).
    downgrade_time: u64,
}
impl Lease {
    fn new(key: Key, file: usize, kind: u64, fd: i32) -> Self {
        Self {
            key,
            file,
            kind,
            pid: 0,
            link: Link::default(),
            fd,
            unlock_pending: false,
            downgrade_pending: false,
            break_time: 0,
            downgrade_time: 0,
        }
    }
    /// `lease_modify` of a lease that stays, with `lease_clear_pending`.
    fn modify(&mut self, kind: u64) {
        if kind == F_RDLCK {
            self.downgrade_pending = false;
        }
        self.kind = kind;
    }
    /// `leases_conflict`: whether an open of `key`, for more than reading if
    /// `write`, breaks it.
    fn conflicts(&self, key: Key, write: bool) -> bool {
        self.key == key && (write || self.kind == F_WRLCK)
    }
    pub(crate) fn link(&self) -> Link {
        self.link
    }
    /// What `/proc/locks` shows of it (`lock_get_status`).
    pub(crate) fn status(&self, space: &Namespace) -> Status {
        Status {
            class: if self.unlock_pending || self.downgrade_pending {
                "LEASE  BREAKING "
            } else {
                "LEASE  ACTIVE   "
            },
            kind: match self.target() {
                F_RDLCK => "READ",
                F_WRLCK => "WRITE",
                _ => "UNLCK",
            },
            pid: space.number(self.pid) as i32,
            key: self.key,
            range: (0, i64::MAX as u64),
        }
    }
    /// `target_leasetype`.
    fn target(&self) -> u64 {
        if self.unlock_pending {
            F_UNLCK
        } else if self.downgrade_pending {
            F_RDLCK
        } else {
            self.kind
        }
    }
}

fn address(file: &Arc<dyn FileHandle>) -> usize {
    Arc::as_ptr(file).cast::<()>().addr()
}

fn leases(caches: &PageCaches) -> std::sync::MutexGuard<'_, Vec<Lease>> {
    caches.leases.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `past_time`.
fn past(now: u64, then: u64) -> bool {
    then != 0 && now > then
}

/// `time_out_leases`: the leases of `key` whose break's time is over become
/// read leases, or go. Gives the descriptions of those that went, whose
/// owners [`disown`] takes away.
fn time_out(list: &mut Vec<Lease>, key: Key, now: u64) -> Vec<usize> {
    let mut gone = Vec::new();
    list.retain_mut(|lease| {
        if lease.key != key {
            return true;
        }
        if past(now, lease.downgrade_time) {
            lease.modify(F_RDLCK);
        }
        if past(now, lease.break_time) {
            gone.push(lease.file);
            return false;
        }
        true
    });
    gone
}

/// `lease_modify`'s `f_delown` of each of the descriptions `files`, with
/// its `F_SETSIG` signal. `f_modown` with no PID, forced, keeps
/// `PIDTYPE_TGID`.
fn disown(c: &Context<'_>, files: &[usize]) {
    for &file in files {
        c.processes.set_file_owner_at(
            file,
            crate::fasync::FileOwner {
                kind: crate::fasync::OwnerKind::Process,
                id: 0,
                signal: 0,
            },
        );
    }
}

/// `fcntl_setlease`: the lease `arg` on the open file of descriptor `fd`,
/// which is `d`.
pub(crate) fn set(c: &Context<'_>, fd: u64, d: &Descriptor, arg: u64) -> Result<u64, Errno> {
    let stat = d.file.stat()?;
    if stat.mode & 0o170000 == DIRECTORY {
        return Err(Errno::EINVAL);
    }
    // `lease_alloc`'s `assign_type`, before anything else of a new lease.
    let arg = arg as u32 as u64;
    if arg != F_UNLCK && arg != F_RDLCK && arg != F_WRLCK {
        return Err(Errno::EINVAL);
    }
    // `vfs_setlease`.
    let creds = &c.process.credentials;
    if stat.uid != creds.fsuid && !creds.capable(CAP_LEASE) {
        return Err(Errno::EACCES);
    }
    // `kernel_setlease`, then `generic_setlease`.
    if !d.file.leasable() || stat.mode & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    let caches = &c.files.caches;
    let file = address(&d.file);
    let key = (crate::files::descriptor_device(c, d), stat.inode);
    if arg == F_UNLCK {
        // `generic_delete_lease`, then `lease_modify`'s `f_delown`.
        let mut list = leases(caches);
        let at = list
            .iter()
            .position(|l| l.file == file)
            .ok_or(Errno::EAGAIN)?;
        list.remove(at);
        drop(list);
        disown(c, &[file]);
        return Ok(0);
    }
    let now = c.host.clock(ClockId::Monotonic)?;
    let gone = time_out(&mut leases(caches), key, now);
    disown(c, &gone);
    // `lease_open_conflict`.
    let access = d.file.flags() & 3;
    let conflict = if arg == F_RDLCK {
        caches.write_count(key) > 0
    } else {
        let (own_writes, own_reads) = match access {
            1 | 2 => (1, 0),
            0 => (0, 1),
            _ => (0, 0),
        };
        caches.write_count(key) != own_writes || caches.read_count(key) != own_reads
    };
    if conflict {
        return Err(Errno::EAGAIN);
    }
    {
        let mut list = leases(caches);
        let mut mine = None;
        for (at, lease) in list.iter().enumerate().filter(|(_, l)| l.key == key) {
            if lease.file == file {
                mine = Some(at);
                continue;
            }
            // No write lease beside another description's lease, and no
            // read lease while a writer breaks one.
            if arg == F_WRLCK || lease.unlock_pending {
                return Err(Errno::EAGAIN);
            }
        }
        match mine {
            // `lease_modify`: the lease changes type.
            Some(at) => {
                list[at].modify(arg);
                // `fasync_insert_entry`.
                list[at].fd = fd as i32;
            }
            None => {
                if c.processes.sysctls.leases_enable() == 0 {
                    return Err(Errno::EINVAL);
                }
                list.push(Lease {
                    pid: c.process.pid,
                    link: c.processes.locks().link(crate::syscalls::cpu(c)),
                    ..Lease::new(key, file, arg, fd as i32)
                });
            }
        }
    }
    // `lease_setup`: `__f_setown` without force gives the caller's process
    // the description if it has no owner.
    let owner = c.processes.file_owner(&d.file);
    if owner.id == 0 {
        c.processes.set_file_owner(
            &d.file,
            crate::fasync::FileOwner {
                kind: crate::fasync::OwnerKind::Process,
                id: c.process.pid,
                ..owner
            },
        );
    }
    Ok(0)
}

/// `fcntl_getlease`: the type of the lease the open file of `d` holds, or
/// is to hold after its break, or `F_UNLCK`.
pub(crate) fn get(c: &Context<'_>, d: &Descriptor) -> Result<u64, Errno> {
    let file = address(&d.file);
    let now = c.host.clock(ClockId::Monotonic)?;
    let mut list = leases(&c.files.caches);
    let Some(key) = list.iter().find(|l| l.file == file).map(|l| l.key) else {
        return Ok(F_UNLCK);
    };
    let gone = time_out(&mut list, key, now);
    let kind = list
        .iter()
        .find(|l| l.file == file)
        .map_or(F_UNLCK, Lease::target);
    drop(list);
    disown(c, &gone);
    Ok(kind)
}

/// What [`check`] does with an open that conflicts with a lease.
#[derive(Clone, Copy)]
enum Opens {
    /// Nothing: an open of the kernel's own, which breaks no lease.
    Kept,
    /// Refuses it, for [`breaking`] to break the lease.
    Broken,
    /// It refused one of this file.
    Refused(Key),
}

thread_local! {
    static OPENS: Cell<Opens> = const { Cell::new(Opens::Kept) };
}

/// Whether an open with `flags` is for more than reading
/// (`openmode_to_lease_flags`).
fn writes(flags: u32) -> bool {
    flags & 3 != 0
}

/// Whether any file has a lease, so that an open need look for its own.
pub(crate) fn any(caches: &PageCaches) -> bool {
    !leases(caches).is_empty()
}

/// Where `do_dentry_open` calls `break_lease`: refuses the guest's open of
/// `key` with `flags` while it conflicts with a lease, which [`breaking`]
/// then breaks before it opens again.
pub(crate) fn check(caches: &PageCaches, key: Key, flags: u32) -> Result<(), Errno> {
    if flags & O_PATH == 0
        && matches!(OPENS.with(Cell::get), Opens::Broken)
        && leases(caches)
            .iter()
            .any(|l| l.conflicts(key, writes(flags)))
    {
        OPENS.with(|opens| opens.set(Opens::Refused(key)));
        return Err(Errno::EAGAIN);
    }
    Ok(())
}

/// The access an open counts before it breaks a lease.
enum Access {
    Read(#[expect(dead_code, reason = "held until the open is over")] ReadAccess),
    Write(#[expect(dead_code, reason = "held until the open is over")] WriteAccess),
}

/// Runs `open`, the guest's open of a file with `flags`, breaking the leases
/// it conflicts with and waiting for them as `do_dentry_open` does, with the
/// open's read or write access counted.
pub(crate) fn breaking<T>(
    c: &mut Context<'_>,
    flags: u32,
    mut open: impl FnMut(&mut Context<'_>) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let mut _access = None;
    loop {
        let outer = OPENS.with(|opens| opens.replace(Opens::Broken));
        let result = open(c);
        let Opens::Refused(key) = OPENS.with(|opens| opens.replace(outer)) else {
            return result;
        };
        let caches = Arc::clone(&c.files.caches);
        // Given back only once its successor is counted.
        _access = Some(if writes(flags) {
            Access::Write(caches.write_access(key)?)
        } else {
            Access::Read(caches.read_access(key))
        });
        break_lease(c, key, flags)?;
    }
}

/// `__break_lease` of the leases of `key` that an open with `flags`
/// conflicts with.
fn break_lease(c: &mut Context<'_>, key: Key, flags: u32) -> Result<(), Errno> {
    let write = writes(flags);
    let caches = Arc::clone(&c.files.caches);
    let seconds = c.processes.sysctls.lease_break_time();
    let now = c.host.clock(ClockId::Monotonic)?;
    let break_time = match u64::try_from(seconds) {
        Ok(seconds) if seconds > 0 => now.saturating_add(seconds * 1_000_000_000),
        _ => 0,
    };
    let mut list = leases(&caches);
    let gone = time_out(&mut list, key, now);
    let mut broken = Vec::new();
    for lease in list.iter_mut().filter(|l| l.conflicts(key, write)) {
        if write {
            if lease.unlock_pending {
                continue;
            }
            lease.unlock_pending = true;
            lease.break_time = break_time;
        } else {
            if lease.unlock_pending || lease.downgrade_pending {
                continue;
            }
            lease.downgrade_pending = true;
            lease.downgrade_time = break_time;
        }
        broken.push((lease.file, lease.fd));
    }
    let mut conflict = list.iter().any(|l| l.conflicts(key, write));
    drop(list);
    disown(c, &gone);
    // `lease_break_callback`.
    for (file, fd) in broken {
        let owner = c.processes.file_owner_at(file);
        c.processes
            .send_io(owner, fd, crate::fasync::Reason::Message);
    }
    while conflict {
        if flags & O_NONBLOCK != 0 {
            return Err(Errno::EAGAIN);
        }
        crate::files::pause_for_lock(c)?;
        let now = c.host.clock(ClockId::Monotonic)?;
        let mut list = leases(&caches);
        let gone = time_out(&mut list, key, now);
        conflict = list.iter().any(|l| l.conflicts(key, write));
        drop(list);
        disown(c, &gone);
    }
    Ok(())
}

/// Every file's leases.
pub(crate) fn all(caches: &PageCaches) -> Vec<Lease> {
    leases(caches).clone()
}

/// The lease the description `file` holds.
pub(crate) fn of(caches: &PageCaches, file: &Arc<dyn FileHandle>) -> Option<Lease> {
    let file = address(file);
    leases(caches).iter().find(|l| l.file == file).copied()
}

/// `locks_remove_file`: the description at `file` goes, and its leases.
pub(crate) fn closed(caches: &PageCaches, file: usize) {
    let mut list = leases(caches);
    if !list.is_empty() {
        list.retain(|l| l.file != file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = (1, 2);

    #[test]
    fn a_closed_description_gives_its_leases_back() {
        let caches = PageCaches::default();
        leases(&caches).extend([
            Lease::new(KEY, 10, F_RDLCK, 3),
            Lease::new(KEY, 20, F_RDLCK, 4),
        ]);
        closed(&caches, 10);
        assert_eq!(*leases(&caches), [Lease::new(KEY, 20, F_RDLCK, 4)]);
    }

    #[test]
    fn a_break_that_takes_too_long_downgrades_or_removes_the_lease() {
        let read_broken = Lease {
            downgrade_pending: true,
            downgrade_time: 100,
            ..Lease::new(KEY, 10, F_WRLCK, 3)
        };
        let write_broken = Lease {
            unlock_pending: true,
            break_time: 100,
            ..Lease::new(KEY, 20, F_RDLCK, 4)
        };
        // Broken with no time to wait, and another file's.
        let endless = Lease {
            unlock_pending: true,
            ..Lease::new(KEY, 30, F_RDLCK, 5)
        };
        let other = Lease {
            break_time: 100,
            ..Lease::new((1, 3), 40, F_RDLCK, 6)
        };
        assert_eq!(read_broken.target(), F_RDLCK);
        assert_eq!(write_broken.target(), F_UNLCK);
        let mut list = vec![read_broken, write_broken, endless, other];
        assert_eq!(time_out(&mut list, KEY, 100), []);
        assert_eq!(list, [read_broken, write_broken, endless, other]);
        assert_eq!(time_out(&mut list, KEY, 101), [20]);
        let downgraded = Lease {
            kind: F_RDLCK,
            downgrade_pending: false,
            ..read_broken
        };
        assert_eq!(list, [downgraded, endless, other]);
        // A read lease conflicts with a writer only.
        assert!(!downgraded.conflicts(KEY, false));
        assert!(downgraded.conflicts(KEY, true));
        assert!(!downgraded.conflicts((1, 3), true));
        assert!(read_broken.conflicts(KEY, false));
    }

    #[test]
    fn only_a_guests_open_is_refused_for_a_lease() {
        let caches = PageCaches::default();
        leases(&caches).push(Lease::new(KEY, 10, F_RDLCK, 3));
        assert_eq!(check(&caches, KEY, 1), Ok(()));
        OPENS.with(|opens| opens.set(Opens::Broken));
        assert_eq!(check(&caches, KEY, 0), Ok(()));
        assert_eq!(check(&caches, KEY, O_PATH | 1), Ok(()));
        assert_eq!(check(&caches, (1, 3), 1), Ok(()));
        assert_eq!(check(&caches, KEY, 1), Err(Errno::EAGAIN));
        assert!(matches!(
            OPENS.with(|opens| opens.replace(Opens::Kept)),
            Opens::Refused(KEY)
        ));
    }
}
