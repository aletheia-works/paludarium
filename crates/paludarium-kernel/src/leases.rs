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
//! the description's lease type, or `F_UNLCK`.

use crate::files::Descriptor;
use crate::page_cache::{Key, PageCaches};
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::Errno;
use std::sync::{Arc, PoisonError};

const F_RDLCK: u64 = 0;
const F_WRLCK: u64 = 1;
const F_UNLCK: u64 = 2;
const CAP_LEASE: u64 = 1 << 28;
const REGULAR: u32 = 0o100000;
const DIRECTORY: u32 = 0o040000;

/// A lease on a file, held by an open description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    key: Key,
    /// The description's address, which tells it from the others while it
    /// is open; it gives its leases back as it goes ([`closed`]).
    file: usize,
    /// `F_RDLCK` or `F_WRLCK`.
    kind: u64,
}

fn address(file: &Arc<dyn FileHandle>) -> usize {
    Arc::as_ptr(file).cast::<()>().addr()
}

fn leases(caches: &PageCaches) -> std::sync::MutexGuard<'_, Vec<Lease>> {
    caches.leases.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `fcntl_setlease`: the lease `arg` on the open file of descriptor `fd`.
pub(crate) fn set(c: &Context<'_>, d: &Descriptor, arg: u64) -> Result<u64, Errno> {
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
        // `f_modown` with no PID, forced, keeps `PIDTYPE_TGID`.
        c.processes.set_file_owner(
            &d.file,
            crate::fasync::FileOwner {
                kind: crate::fasync::OwnerKind::Process,
                id: 0,
                signal: 0,
            },
        );
        return Ok(0);
    }
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
            // No write lease beside another description's lease.
            if arg == F_WRLCK {
                return Err(Errno::EAGAIN);
            }
        }
        match mine {
            // `lease_modify`: the lease changes type.
            Some(at) => list[at].kind = arg,
            None => {
                if c.processes.sysctls.leases_enable() == 0 {
                    return Err(Errno::EINVAL);
                }
                list.push(Lease {
                    key,
                    file,
                    kind: arg,
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
/// `F_UNLCK`.
pub(crate) fn get(c: &Context<'_>, d: &Descriptor) -> u64 {
    let file = address(&d.file);
    leases(&c.files.caches)
        .iter()
        .find(|l| l.file == file)
        .map_or(F_UNLCK, |l| l.kind)
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

    #[test]
    fn a_closed_description_gives_its_leases_back() {
        let caches = PageCaches::default();
        leases(&caches).extend([
            Lease {
                key: (1, 2),
                file: 10,
                kind: F_RDLCK,
            },
            Lease {
                key: (1, 2),
                file: 20,
                kind: F_RDLCK,
            },
        ]);
        closed(&caches, 10);
        assert_eq!(
            *leases(&caches),
            [Lease {
                key: (1, 2),
                file: 20,
                kind: F_RDLCK,
            }]
        );
    }
}
