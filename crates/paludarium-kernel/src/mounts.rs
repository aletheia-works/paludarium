//! `mount(2)` and `umount2(2)`, in Linux master's order of checks
//! (`fs/namespace.c`), over the mount namespace's table
//! ([`paludarium_vfs::MountTable`]).
//!
//! `mount` makes new tmpfs mounts (`shmem_parse_one`'s options, sizes and
//! modes as `statfs` and `stat` report them, with nothing enforced), bind
//! mounts (`MS_BIND`, with `MS_REC` the mounts below too), remounts a
//! superblock (`MS_REMOUNT`) or a mount's flags alone (`MS_REMOUNT |
//! MS_BIND`), and changes a mount's propagation type (`MS_SHARED`,
//! `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`, with `MS_REC` the mounts on
//! it too), which mountinfo shows; nothing propagates between peers. It
//! moves a mount and those on it (`MS_MOVE`), and `pivot_root` puts the
//! old root under a new one; both take the roots and working directories
//! of the processes along. Read-only mounts and superblocks refuse writes
//! (`EROFS`, in the calls that write). What it does not do yet gives
//! `EOPNOTSUPP` once Linux's checks before it have passed: `MS_NOSYMFOLLOW`
//! on a tmpfs or set by a remount, a mount on, a bind mount of or a move of
//! `/proc` or `/dev`, which the kernel generates, and a move of a mount
//! from start-up that the lower filesystem shows. Any other file system
//! type is `ENODEV`, as from a kernel without it.
//!
//! `umount2` unmounts the mounts `mount` made, and the old root after a
//! `pivot_root`; a mount from start-up (the root, a `--mount` directory)
//! otherwise stays: `EINVAL` when it is locked, else `EBUSY`.
use std::sync::Arc;

use paludarium_host::{ClockId, HostFs};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{MemFs, NewTmpfs, Propagation, Settings, Target, mount_flags as mnt};

use crate::namespaces::Namespace;
use crate::syscalls::{Context, Outcome};

mod context;
pub(crate) use context::{FsContext, sys_fsconfig, sys_fsmount, sys_fsopen, sys_fspick};
mod listing;
pub(crate) use listing::{sys_listmount, sys_statmount};

const CAP_SYS_ADMIN: u64 = 1 << 21;
const EBUSY: Errno = Errno(16);
const E2BIG: Errno = Errno(7);
const ENODEV: Errno = Errno(19);
const PAGE: u64 = 4096;
const PATH_MAX: u64 = 4096;

const MS_RDONLY: u64 = 1;
const MS_NOSUID: u64 = 2;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_SYNCHRONOUS: u64 = 16;
const MS_REMOUNT: u64 = 32;
const MS_MANDLOCK: u64 = 64;
const MS_DIRSYNC: u64 = 128;
const MS_NOSYMFOLLOW: u64 = 256;
const MS_NOATIME: u64 = 1024;
const MS_NODIRATIME: u64 = 2048;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_REC: u64 = 16384;
const MS_SILENT: u64 = 32768;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_POSIXACL: u64 = 1 << 16;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_RELATIME: u64 = 1 << 21;
const MS_I_VERSION: u64 = 1 << 23;
const MS_STRICTATIME: u64 = 1 << 24;
const MS_LAZYTIME: u64 = 1 << 25;
const MS_NOUSER: u64 = 1 << 31;
const MS_MGC_VAL: u64 = 0xC0ED_0000;
const MS_MGC_MSK: u64 = 0xffff_0000;
/// The superblock flags a remount changes (`MS_RMT_MASK`).
const MS_RMT_MASK: u64 = MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME;

const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

pub(crate) fn sys_mount(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(mount(c, a))
}
pub(crate) fn sys_umount2(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(umount(c, a[0], a[1] as u32 as u64))
}
pub(crate) fn sys_pivot_root(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(pivot_root(c, a[0], a[1]))
}
pub(crate) fn sys_open_tree(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(open_tree(c, a[0], a[1], a[2] & 0xffff_ffff))
}
pub(crate) fn sys_move_mount(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(move_mount_call(c, a))
}
pub(crate) fn sys_mount_setattr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(mount_setattr(c, a))
}
pub(crate) fn sys_open_tree_attr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(open_tree_attr(c, a))
}

const MOUNT_ATTR_RDONLY: u64 = 0x01;
const MOUNT_ATTR_NOSUID: u64 = 0x02;
const MOUNT_ATTR_NODEV: u64 = 0x04;
const MOUNT_ATTR_NOEXEC: u64 = 0x08;
const MOUNT_ATTR_ATIME: u64 = 0x70;
const MOUNT_ATTR_NOATIME: u64 = 0x10;
const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;
/// `MOUNT_SETATTR_VALID_FLAGS`.
const MOUNT_SETATTR_VALID: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_ATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_IDMAP
    | MOUNT_ATTR_NOSYMFOLLOW;
/// `MOUNT_ATTR_SIZE_VER0`: `struct mount_attr`'s `attr_set`, `attr_clr`,
/// `propagation` and `userns_fd`.
const MOUNT_ATTR_SIZE: u64 = 32;

/// What `mount_setattr` changes (`struct mount_kattr`).
struct Change {
    set: u32,
    clear: u32,
    propagation: Option<Propagation>,
    recurse: bool,
}

/// `attr_flags_to_mnt_flags`: the mount flags of the attributes.
fn attr_mount_flags(attrs: u64) -> u32 {
    let mut out = 0;
    for (attr, flag) in [
        (MOUNT_ATTR_RDONLY, mnt::READONLY),
        (MOUNT_ATTR_NOSUID, mnt::NOSUID),
        (MOUNT_ATTR_NODEV, mnt::NODEV),
        (MOUNT_ATTR_NOEXEC, mnt::NOEXEC),
        (MOUNT_ATTR_NODIRATIME, mnt::NODIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, mnt::NOSYMFOLLOW),
    ] {
        if attrs & attr != 0 {
            out |= flag;
        }
    }
    out
}

/// `wants_mount_setattr` and `build_mount_kattr`: a `struct mount_attr` of
/// `size` bytes at `ptr` (`E2BIG` beyond a page, `EINVAL` under 32 bytes),
/// `CAP_SYS_ADMIN` over the caller's mount namespace (`EPERM`), its copy
/// (`EFAULT`, `E2BIG` for bytes past it that are not 0), none for one that
/// changes nothing; then one propagation type at most and known attributes
/// (`EINVAL`), the access-time setting only with all of
/// `MOUNT_ATTR__ATIME` cleared (`EINVAL`), and an idmapping's user
/// namespace (`build_mount_idmapped`: `EINVAL` to clear one but from a new
/// copy, `EBADF`, `EINVAL` for a descriptor of no user namespace, `EPERM`
/// for the first one or one the caller does not administer). An idmapped
/// mount is not supported (`EOPNOTSUPP`).
fn wanted_change(
    c: &Context<'_>,
    ptr: u64,
    size: u64,
    recurse: bool,
    fresh_copy: bool,
) -> Result<Option<Change>, Errno> {
    if size > PAGE {
        return Err(E2BIG);
    }
    if size < MOUNT_ATTR_SIZE {
        return Err(Errno::EINVAL);
    }
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    let mut raw = vec![0u8; size as usize];
    c.mem
        .read(GuestAddr(ptr), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    if raw[MOUNT_ATTR_SIZE as usize..].iter().any(|&b| b != 0) {
        return Err(E2BIG);
    }
    let word = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap_or_default());
    let (attr_set, attr_clr, propagation, userns_fd) = (word(0), word(1), word(2), word(3));
    if attr_set == 0 && attr_clr == 0 && propagation == 0 {
        return Ok(None);
    }
    let kinds = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;
    if propagation & !kinds != 0 || propagation.count_ones() > 1 {
        return Err(Errno::EINVAL);
    }
    if (attr_set | attr_clr) & !MOUNT_SETATTR_VALID != 0 {
        return Err(Errno::EINVAL);
    }
    let mut set = attr_mount_flags(attr_set);
    let mut clear = attr_mount_flags(attr_clr);
    if attr_clr & MOUNT_ATTR_ATIME != 0 {
        if attr_clr & MOUNT_ATTR_ATIME != MOUNT_ATTR_ATIME {
            return Err(Errno::EINVAL);
        }
        clear |= mnt::RELATIME | mnt::NOATIME;
        set |= match attr_set & MOUNT_ATTR_ATIME {
            0 => mnt::RELATIME,
            MOUNT_ATTR_NOATIME => mnt::NOATIME,
            MOUNT_ATTR_STRICTATIME => 0,
            _ => return Err(Errno::EINVAL),
        };
    } else if attr_set & MOUNT_ATTR_ATIME != 0 {
        return Err(Errno::EINVAL);
    }
    if (attr_set | attr_clr) & MOUNT_ATTR_IDMAP != 0 {
        if attr_clr & MOUNT_ATTR_IDMAP != 0 && !fresh_copy {
            return Err(Errno::EINVAL);
        }
        if attr_set & MOUNT_ATTR_IDMAP != 0 {
            if userns_fd > i32::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            let file = c.files.descriptor(userns_fd)?.file;
            let Some(ns) = file
                .as_any()
                .and_then(|v| v.downcast_ref::<crate::namespaces::NamespaceFile>())
            else {
                return Err(Errno::EINVAL);
            };
            if ns.namespace.kind != crate::namespaces::Kind::User {
                return Err(Errno::EINVAL);
            }
            if Arc::ptr_eq(&ns.namespace, crate::users::first()) {
                return Err(Errno::EPERM);
            }
            if !c
                .process
                .credentials
                .capable_in(CAP_SYS_ADMIN, &ns.namespace)
            {
                return Err(Errno::EPERM);
            }
            return Err(Errno::EOPNOTSUPP);
        }
    }
    Ok(Some(Change {
        set,
        clear,
        propagation: match propagation {
            0 => None,
            MS_SHARED => Some(Propagation::Shared),
            MS_PRIVATE => Some(Propagation::Private),
            MS_SLAVE => Some(Propagation::Slave),
            _ => Some(Propagation::Unbindable),
        },
        recurse,
    }))
}

/// `do_mount_setattr` at the resolved `path`: a mount's root (`EINVAL`),
/// of the namespace or a detached tree's root (`EINVAL`), then the change
/// ([`paludarium_vfs::NamespacedFs::set_attributes`]), where setting
/// `MOUNT_ATTR_NOSYMFOLLOW` on any mount that has it not is not supported
/// (`EOPNOTSUPP`).
fn apply_change(c: &Context<'_>, path: &[u8], change: &Change) -> Result<(), Errno> {
    let namespaced = c.files.namespaced();
    let found = namespaced.target(path)?;
    if !found.root {
        return Err(Errno::EINVAL);
    }
    namespaced.set_attributes(
        found.id,
        change.recurse,
        change.clear,
        change.set,
        change.propagation,
    )
}

/// `mount_setattr(dfd, path, flags, attr, size)`, as Linux master's: the
/// flags (`EINVAL`), then the attributes ([`wanted_change`]), which may
/// change nothing (0 before any lookup), then the lookup, its last link
/// followed unless `AT_SYMLINK_NOFOLLOW` (`AT_EMPTY_PATH` names `dfd`
/// itself), then the change, of each mount below it too with
/// `AT_RECURSIVE` ([`apply_change`]). `/proc` and `/dev`, which the kernel
/// generates, are not supported (`EOPNOTSUPP`).
fn mount_setattr(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[2] & 0xffff_ffff;
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return Err(Errno::EINVAL);
    }
    let recurse = flags & AT_RECURSIVE != 0;
    let Some(change) = wanted_change(c, a[3], a[4], recurse, false)? else {
        return Ok(0);
    };
    let empty = flags & AT_EMPTY_PATH != 0;
    let raw = maybe_empty(c, a[1], empty)?;
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let path = crate::files::mount_at(c, a[0], raw, follow, empty)?.ok_or(Errno::EOPNOTSUPP)?;
    apply_change(c, &path, &change)?;
    Ok(0)
}

/// `open_tree_attr(dfd, path, flags, attr, size)`, as Linux master's:
/// `EINVAL` for a size without an attribute pointer, then [`open_tree`],
/// then its descriptor's mount takes the attributes as `mount_setattr`
/// gives them (an idmapping may be cleared from a new copy); a failure
/// takes the descriptor away again.
fn open_tree_attr(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[2] & 0xffff_ffff;
    if a[3] == 0 && a[4] != 0 {
        return Err(Errno::EINVAL);
    }
    let fd = open_tree(c, a[0], a[1], flags)?;
    if a[3] == 0 {
        return Ok(fd);
    }
    let applied = (|| {
        let recurse = flags & AT_RECURSIVE != 0;
        let fresh = flags & OPEN_TREE_CLONE != 0;
        let Some(change) = wanted_change(c, a[3], a[4], recurse, fresh)? else {
            return Ok(());
        };
        let path = c.files.descriptor(fd)?.path;
        apply_change(c, &path, &change)
    })();
    if let Err(errno) = applied {
        c.files
            .fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(fd as u32));
        return Err(errno);
    }
    Ok(fd)
}

const AT_FDCWD: u64 = (-100i64) as u64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_RECURSIVE: u64 = 0x8000;
const OPEN_TREE_CLONE: u64 = 1;
const OPEN_TREE_NAMESPACE: u64 = 2;
const OPEN_TREE_DROP_MNTNS_MOUNTS: u64 = 4;
const O_CLOEXEC: u64 = 0o2000000;
const O_NOFOLLOW: u64 = 0o400000;
const O_PATH: u64 = 0o10000000;
const MOVE_MOUNT_F_SYMLINKS: u64 = 0x01;
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x04;
const MOVE_MOUNT_T_SYMLINKS: u64 = 0x10;
const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;
const MOVE_MOUNT_SET_GROUP: u64 = 0x100;
const MOVE_MOUNT_BENEATH: u64 = 0x200;
const MOVE_MOUNT_MASK: u64 = 0x377;

/// A path argument that `AT_EMPTY_PATH` lets be empty or null
/// (`getname_maybe_null`).
fn maybe_empty(c: &Context<'_>, ptr: u64, empty: bool) -> Result<Vec<u8>, Errno> {
    if empty && ptr == 0 {
        return Ok(Vec::new());
    }
    crate::files::path(c, ptr)
}

/// `open_tree(dfd, path, flags)`, as Linux master's `vfs_open_tree`: the
/// flags first (`EINVAL` for an unknown one, `OPEN_TREE_DROP_MNTNS_MOUNTS`
/// without a recursive copy, `AT_RECURSIVE` without a copy, or both kinds
/// of copy), then `CAP_SYS_ADMIN` in the caller's user namespace for
/// `OPEN_TREE_NAMESPACE` and over its mount namespace for
/// `OPEN_TREE_CLONE` (`EPERM`), then the lookup, its last link followed
/// unless `AT_SYMLINK_NOFOLLOW` (`AT_EMPTY_PATH` names `dfd` itself). It
/// gives an `O_PATH` descriptor of the file; with `OPEN_TREE_CLONE` of a
/// copy of its mount, with `AT_RECURSIVE` of the mounts below it too, in a
/// tree of its own ([`paludarium_vfs::NamespacedFs::clone_tree`]) that
/// goes with the descriptor's last close unless `move_mount` attached it.
/// `OPEN_TREE_NAMESPACE`, new in Linux master, and a copy of `/proc` or
/// `/dev`, which the kernel generates, are not supported (`EOPNOTSUPP`).
fn open_tree(c: &mut Context<'_>, dfd: u64, ptr: u64, flags: u64) -> Result<u64, Errno> {
    let known = AT_EMPTY_PATH
        | AT_NO_AUTOMOUNT
        | AT_RECURSIVE
        | AT_SYMLINK_NOFOLLOW
        | OPEN_TREE_CLONE
        | O_CLOEXEC
        | OPEN_TREE_NAMESPACE
        | OPEN_TREE_DROP_MNTNS_MOUNTS;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let copies = flags & (OPEN_TREE_CLONE | OPEN_TREE_NAMESPACE);
    if flags & OPEN_TREE_DROP_MNTNS_MOUNTS != 0 && (flags & AT_RECURSIVE == 0 || copies == 0) {
        return Err(Errno::EINVAL);
    }
    if flags & AT_RECURSIVE != 0 && copies == 0 || copies.count_ones() > 1 {
        return Err(Errno::EINVAL);
    }
    let creds = &c.process.credentials;
    if flags & OPEN_TREE_NAMESPACE != 0 && !creds.capable_in(CAP_SYS_ADMIN, &creds.user.0) {
        return Err(Errno::EPERM);
    }
    let namespaces = c.group.namespaces(c.tid);
    if flags & OPEN_TREE_CLONE != 0 && !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let empty = flags & AT_EMPTY_PATH != 0;
    let raw = maybe_empty(c, ptr, empty)?;
    let found = crate::files::mount_at(c, dfd, raw.clone(), follow, empty)?;
    if flags & OPEN_TREE_NAMESPACE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let cloexec = flags & O_CLOEXEC;
    if flags & OPEN_TREE_CLONE == 0 {
        // The file itself, as an `O_PATH` open of it.
        let (dir, raw) = match (raw.is_empty(), dfd == AT_FDCWD) {
            (false, _) => (dfd, raw),
            (true, true) => (AT_FDCWD, b".".to_vec()),
            (true, false) => (AT_FDCWD, c.files.descriptor(dfd)?.path),
        };
        let nofollow = if follow && !raw.is_empty() && raw != b"." {
            0
        } else {
            O_NOFOLLOW
        };
        return crate::files::open_at(c, dir, raw, O_PATH | nofollow | cloexec, 0, 0);
    }
    let found = found.ok_or(Errno::EOPNOTSUPP)?;
    let (point, pin) =
        c.files
            .namespaced()
            .clone_tree(&found, follow, flags & AT_RECURSIVE != 0)?;
    let opened = crate::files::open_at(c, AT_FDCWD, point, O_PATH | O_NOFOLLOW | cloexec, 0, 0);
    drop(pin);
    opened
}

/// `move_mount(from_dfd, from_path, to_dfd, to_path, flags)`, as Linux
/// master's: `CAP_SYS_ADMIN` over the caller's mount namespace (`EPERM`)
/// first, then the flags (`EINVAL`), then the target and then the source
/// are looked up, each following its last link only with its
/// `MOVE_MOUNT_*_SYMLINKS` and naming its descriptor itself when empty
/// with its `MOVE_MOUNT_*_EMPTY_PATH`; a Landlock domain is `EPERM`
/// (`hook_move_mount`). `MOVE_MOUNT_SET_GROUP` puts the target in the
/// source's peer group ([`paludarium_vfs::NamespacedFs::set_group`]);
/// otherwise the source mount moves onto the target as `MS_MOVE` moves
/// it, or a detached tree from `open_tree` is attached there.
/// `MOVE_MOUNT_BENEATH`, and `/proc` or `/dev`, which the kernel
/// generates, are not supported (`EOPNOTSUPP`).
fn move_mount_call(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[4] & 0xffff_ffff;
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    if flags & !MOVE_MOUNT_MASK != 0
        || flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
            == MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP
    {
        return Err(Errno::EINVAL);
    }
    let follow_to = flags & MOVE_MOUNT_T_SYMLINKS != 0;
    let empty_to = flags & MOVE_MOUNT_T_EMPTY_PATH != 0;
    let raw = maybe_empty(c, a[3], empty_to)?;
    let to = crate::files::mount_at(c, a[2], raw, follow_to, empty_to)?;
    let follow_from = flags & MOVE_MOUNT_F_SYMLINKS != 0;
    let empty_from = flags & MOVE_MOUNT_F_EMPTY_PATH != 0;
    let raw = maybe_empty(c, a[1], empty_from)?;
    let from = crate::files::mount_at(c, a[0], raw, follow_from, empty_from)?;
    if c.process.credentials.landlock.handles_fs() {
        return Err(Errno::EPERM);
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err(Errno::EOPNOTSUPP);
    };
    let namespaced = c.files.namespaced();
    if flags & MOVE_MOUNT_SET_GROUP != 0 {
        namespaced.set_group(&from, follow_from, &to, follow_to)?;
        return Ok(0);
    }
    if flags & MOVE_MOUNT_BENEATH != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if !check_mnt(c, &namespaces.mnt) {
        return Err(Errno::EINVAL);
    }
    c.files.relocate(c.processes, |paths| {
        namespaced.move_mount_following(&from, follow_from, &to, follow_to, paths)
    })?;
    Ok(0)
}

/// `copy_mount_string`: none for a null pointer, else the string as
/// `strndup_user(s, PATH_MAX)` takes it: `EFAULT` where it cannot be read,
/// `EINVAL` when no 0 ends it within `PATH_MAX` bytes.
fn mount_string(c: &Context<'_>, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    user_string(c, addr, PATH_MAX)
}
/// `strndup_user(s, limit)`: none for a null pointer, else the string,
/// `EFAULT` where it cannot be read, `EINVAL` when no 0 ends it within
/// `limit` bytes.
fn user_string(c: &Context<'_>, addr: u64, limit: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let mut out = Vec::new();
    for i in 0..limit {
        let mut byte = [0];
        c.mem
            .read(
                GuestAddr(addr.checked_add(i).ok_or(Errno::EFAULT)?),
                &mut byte,
            )
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(Some(out));
        }
        out.push(byte[0]);
    }
    Err(Errno::EINVAL)
}
/// `copy_mount_options`: up to a page from `addr`, as far as it can be read
/// (`EFAULT` when none of it can), the page's last byte 0, as `path_mount`
/// ends it; the options are the string it starts with.
fn mount_options(c: &Context<'_>, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let mut out = Vec::new();
    for i in 0..PAGE - 1 {
        let mut byte = [0];
        let Some(at) = addr.checked_add(i) else { break };
        if c.mem.read(GuestAddr(at), &mut byte).is_err() {
            if i == 0 {
                return Err(Errno::EFAULT);
            }
            break;
        }
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    Ok(Some(out))
}

/// `may_mount`: CAP_SYS_ADMIN in the user namespace that owns the caller's
/// mount namespace.
fn may_mount(c: &Context<'_>, ns: &Namespace) -> bool {
    c.process.credentials.capable_in(CAP_SYS_ADMIN, ns.owner())
}
/// `check_mnt`: the caller's root and working directory are on the
/// mounts of its own mount namespace (they may not be after a `setns` of
/// more than one namespace by a thread sharing them).
fn check_mnt(c: &Context<'_>, ns: &Namespace) -> bool {
    Arc::ptr_eq(
        &c.files.mount_table(),
        &crate::namespaces::mount_table(ns, c.files),
    )
}

/// `mount(source, target, type, flags, data)`, as Linux's `SYSCALL_DEFINE5(mount)`,
/// `do_mount` and `path_mount`: the type, the source and the options are
/// copied first (`EFAULT`, `EINVAL`), then the target is looked up with its
/// links followed; `MS_MGC_VAL` is dropped, `MS_NOUSER` is `EINVAL`, a
/// Landlock domain `EPERM` (`hook_sb_mount`), and the caller needs
/// CAP_SYS_ADMIN over its mount namespace (`EPERM`) before the flags pick
/// what is done.
fn mount(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let kind = mount_string(c, a[2])?;
    let source = mount_string(c, a[0])?;
    let data = mount_options(c, a[4])?;
    let target = crate::files::mount_target(c, a[1], true)?;
    // Only the low 32 bits are flags (`do_change_type` takes an int).
    let mut flags = a[3] & 0xffff_ffff;
    if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags &= !MS_MGC_MSK;
    }
    if flags & MS_NOUSER != 0 {
        return Err(Errno::EINVAL);
    }
    if c.process.credentials.landlock.handles_fs() {
        return Err(Errno::EPERM);
    }
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    let mut mount_flags = if flags & MS_NOATIME == 0 {
        mnt::RELATIME
    } else {
        0
    };
    for (flag, kept) in [
        (MS_NOSUID, mnt::NOSUID),
        (MS_NODEV, mnt::NODEV),
        (MS_NOEXEC, mnt::NOEXEC),
        (MS_NOATIME, mnt::NOATIME),
        (MS_NODIRATIME, mnt::NODIRATIME),
        (MS_RDONLY, mnt::READONLY),
        (MS_NOSYMFOLLOW, mnt::NOSYMFOLLOW),
    ] {
        if flags & flag != 0 {
            mount_flags |= kept;
        }
    }
    if flags & MS_STRICTATIME != 0 {
        mount_flags &= !(mnt::RELATIME | mnt::NOATIME);
    }
    let Some(target) = target else {
        // `/proc` and `/dev`, which the kernel generates, hold no mounts.
        return Err(Errno::EOPNOTSUPP);
    };
    let sb_flags = flags
        & (MS_RDONLY
            | MS_SYNCHRONOUS
            | MS_MANDLOCK
            | MS_DIRSYNC
            | MS_SILENT
            | MS_POSIXACL
            | MS_LAZYTIME
            | MS_I_VERSION);
    if flags & MS_REMOUNT != 0 {
        let found = c.files.namespaced().target(&target)?;
        // A remount keeps the access-time flags unless it names one.
        if flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME) == 0 {
            mount_flags = mount_flags & !mnt::ATIME | found.flags & mnt::ATIME;
        }
        if flags & MS_BIND != 0 {
            return remount_bind(c, &found, mount_flags, &namespaces.mnt);
        }
        return remount(
            c,
            &found,
            sb_flags,
            mount_flags,
            data.as_deref(),
            &namespaces.mnt,
        );
    }
    if flags & MS_BIND != 0 {
        return bind(c, source, &target, flags & MS_REC != 0, &namespaces.mnt);
    }
    if flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE) != 0 {
        return change_type(c, &target, flags, &namespaces.mnt);
    }
    if flags & MS_MOVE != 0 {
        return move_mount(c, source, &target, &namespaces.mnt);
    }
    let fs = new_tmpfs(c, kind, source, data.as_deref(), sb_flags, mount_flags)?;
    // do_add_mount: the parent is in the caller's namespace (`EINVAL`), then
    // graft_tree's check that a directory is mounted on a directory.
    if !check_mnt(c, &namespaces.mnt) {
        return Err(Errno::EINVAL);
    }
    let namespaced = c.files.namespaced();
    if namespaced.metadata(&target, false)?.mode & 0o170000 != 0o040000 {
        return Err(Errno::ENOTDIR);
    }
    if fs.flags & mnt::NOSYMFOLLOW != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    namespaced.mount(&target, fs)?;
    Ok(0)
}

/// `do_loopback`: a source (`EINVAL` for none or an empty one), looked up
/// with its last link followed (`kern_path`), and a target in the caller's
/// namespace (`check_mnt`, `EINVAL`) before the bind mount is made
/// ([`paludarium_vfs::NamespacedFs::bind`]). The flags other than `MS_REC`
/// change nothing: the new mount has the source mount's. A source in
/// `/proc` or `/dev`, which the kernel generates, is not supported yet.
fn bind(
    c: &Context<'_>,
    source: Option<Vec<u8>>,
    target: &[u8],
    recurse: bool,
    ns: &Namespace,
) -> Result<u64, Errno> {
    let source = source.filter(|s| !s.is_empty()).ok_or(Errno::EINVAL)?;
    let source = crate::files::mount_path(c, source, true)?.ok_or(Errno::EOPNOTSUPP)?;
    if !check_mnt(c, ns) {
        return Err(Errno::EINVAL);
    }
    c.files.namespaced().bind(&source, target, recurse)?;
    Ok(0)
}

/// `do_move_mount_old` (`MS_MOVE`): a source (`EINVAL` for none or an
/// empty one), looked up with its last link followed, in the caller's
/// namespace (`check_mnt`, `EINVAL`); then the mount at its root goes,
/// with those on it, onto the target
/// ([`paludarium_vfs::NamespacedFs::move_mount`]), and the roots and
/// working directories in them with it. A source in `/proc` or `/dev`,
/// which the kernel generates, is not supported.
fn move_mount(
    c: &mut Context<'_>,
    source: Option<Vec<u8>>,
    target: &[u8],
    ns: &Namespace,
) -> Result<u64, Errno> {
    let source = source.filter(|s| !s.is_empty()).ok_or(Errno::EINVAL)?;
    let source = crate::files::mount_path(c, source, true)?.ok_or(Errno::EOPNOTSUPP)?;
    if !check_mnt(c, ns) {
        return Err(Errno::EINVAL);
    }
    let namespaced = c.files.namespaced();
    c.files.relocate(c.processes, |paths| {
        namespaced.move_mount(&source, target, paths)
    })?;
    Ok(0)
}

/// `pivot_root(new_root, put_old)`, as Linux master's `SYSCALL_DEFINE2(pivot_root)`
/// and `path_pivot_root`: both are looked up as directories with their
/// links followed (`ENOENT`, `ENOTDIR` and the like, the new root first);
/// then CAP_SYS_ADMIN over the caller's mount namespace (`EPERM`), a
/// Landlock domain `EPERM` (`hook_sb_pivotroot`), and the caller's root
/// and working directory on its namespace's mounts (`check_mnt`,
/// `EINVAL`) before the mounts change places
/// ([`paludarium_vfs::NamespacedFs::pivot_root`]). Each process on the
/// namespace whose root or working directory was the old root is on the
/// new one, and the others' stay with their mounts. `/proc` and `/dev`,
/// which the kernel generates, are no mounts to take part (`EINVAL`).
fn pivot_root(c: &mut Context<'_>, new: u64, put_old: u64) -> Result<u64, Errno> {
    let new = crate::files::mount_directory(c, new)?;
    let put_old = crate::files::mount_directory(c, put_old)?;
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) || c.process.credentials.landlock.handles_fs() {
        return Err(Errno::EPERM);
    }
    if !check_mnt(c, &namespaces.mnt) {
        return Err(Errno::EINVAL);
    }
    let (Some(new), Some(put_old)) = (new, put_old) else {
        return Err(Errno::EINVAL);
    };
    let root = c.files.root();
    let namespaced = c.files.namespaced();
    c.files.relocate(c.processes, |paths| {
        namespaced.pivot_root(&new, &put_old, &root, paths)
    })?;
    Ok(0)
}

/// `do_change_type`: the target is a mount's root (`EINVAL`), the flags
/// name one propagation type (`EINVAL`), and the caller needs CAP_SYS_ADMIN
/// over the mount's namespace (`may_change_propagation`); then the mount,
/// with `MS_REC` each mount on it too, takes the type
/// ([`paludarium_vfs::NamespacedFs::change_type`]).
fn change_type(c: &Context<'_>, target: &[u8], flags: u64, ns: &Namespace) -> Result<u64, Errno> {
    let found = c.files.namespaced().target(target)?;
    if !found.root {
        return Err(Errno::EINVAL);
    }
    let kind = flags & !(MS_REC | MS_SILENT);
    if kind & !(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE) != 0 || !kind.is_power_of_two() {
        return Err(Errno::EINVAL);
    }
    if !may_mount(c, ns) {
        return Err(Errno::EPERM);
    }
    let kind = match kind {
        MS_SHARED => Propagation::Shared,
        MS_PRIVATE => Propagation::Private,
        MS_SLAVE => Propagation::Slave,
        _ => Propagation::Unbindable,
    };
    c.files
        .namespaced()
        .change_type(found.id, kind, flags & MS_REC != 0)?;
    Ok(0)
}

/// `can_change_locked_flags`: a flag a copy into a less privileged
/// namespace locked stays set, and locked access-time flags stay as they
/// are.
fn may_change_locked(found: &Target, flags: u32) -> bool {
    let locks = found.locks;
    for (lock, flag) in [
        (mnt::LOCK_READONLY, mnt::READONLY),
        (mnt::LOCK_NODEV, mnt::NODEV),
        (mnt::LOCK_NOSUID, mnt::NOSUID),
        (mnt::LOCK_NOEXEC, mnt::NOEXEC),
    ] {
        if locks & lock != 0 && flags & flag == 0 {
            return false;
        }
    }
    locks & mnt::LOCK_ATIME == 0 || found.flags & mnt::ATIME == flags & mnt::ATIME
}

/// `do_reconfigure_mnt` (`MS_REMOUNT | MS_BIND`): a mount in the caller's
/// namespace (`EINVAL`), at its root (`EINVAL`), whose locked flags stay
/// (`EPERM`), takes `flags`; making it read-only needs no file open for
/// writing on it (`EBUSY`).
fn remount_bind(c: &Context<'_>, found: &Target, flags: u32, ns: &Namespace) -> Result<u64, Errno> {
    if !check_mnt(c, ns) || !found.root {
        return Err(Errno::EINVAL);
    }
    if !may_change_locked(found, flags) {
        return Err(Errno::EPERM);
    }
    if flags & !found.flags & mnt::NOSYMFOLLOW != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    c.files.namespaced().reconfigure_mount(found.id, flags)?;
    Ok(0)
}

/// The superblock's options as `show_sb_opts` shows them.
fn common_options(sb_flags: u64) -> String {
    [
        (MS_SYNCHRONOUS, ",sync"),
        (MS_DIRSYNC, ",dirsync"),
        (MS_MANDLOCK, ",mand"),
        (MS_LAZYTIME, ",lazytime"),
    ]
    .iter()
    .filter(|(flag, _)| sb_flags & flag != 0)
    .map(|(_, name)| *name)
    .collect()
}

/// `do_remount` (`MS_REMOUNT`): a mount in the caller's namespace
/// (`EINVAL`), at its root (`EINVAL`), whose locked flags stay (`EPERM`);
/// then its file system's options are parsed (`EINVAL`), the caller needs
/// CAP_SYS_ADMIN over the superblock's user namespace (`EPERM`), and
/// `reconfigure_super` changes only the flags a remount may
/// (`MS_RMT_MASK`, an option naming another is `EINVAL`), making it
/// read-only only with no file open for writing on its mounts (`EBUSY`),
/// then tmpfs's own (`shmem_reconfigure`, `EINVAL`). The mount then takes
/// `flags`. A mount from start-up keeps no options but whether it is
/// read-only: a `hostfs` one takes only the common ones.
fn remount(
    c: &Context<'_>,
    found: &Target,
    sb_flags: u64,
    flags: u32,
    data: Option<&[u8]>,
    ns: &Namespace,
) -> Result<u64, Errno> {
    if !check_mnt(c, ns) || !found.root {
        return Err(Errno::EINVAL);
    }
    if !may_change_locked(found, flags) {
        return Err(Errno::EPERM);
    }
    let mut asked = Tmpfs::fresh(c, None);
    for option in data.map(split_options).unwrap_or_default() {
        let Some((key, value)) = option_pair(option) else {
            continue;
        };
        if found.kind == "tmpfs" {
            asked.parse(c, key, Value::of(value))?;
        } else if !asked.parse_common(key) {
            return Err(Errno::EINVAL);
        }
    }
    if !over_superblock(c, found) {
        return Err(Errno::EPERM);
    }
    let mask = MS_RMT_MASK | asked.sb_set | asked.sb_clear;
    if mask & !MS_RMT_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !found.flags & mnt::NOSYMFOLLOW != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let requested = (sb_flags | asked.sb_set) & !asked.sb_clear;
    reconfigure_superblock(
        c,
        found,
        &asked,
        requested & MS_RDONLY != 0,
        mask,
        requested,
        flags,
    )?;
    Ok(0)
}

/// `reconfigure_super` of `found`'s superblock as `asked` asks, with the
/// flags in `mask` taken from `requested` and read-only with `read_only`
/// (`EBUSY` with a file open for writing on it), then tmpfs's own
/// (`shmem_reconfigure`); the mount then takes `flags`.
fn reconfigure_superblock(
    c: &Context<'_>,
    found: &Target,
    asked: &Tmpfs,
    read_only: bool,
    mask: u64,
    requested: u64,
    flags: u32,
) -> Result<(), Refused> {
    let mut message = String::new();
    c.files
        .namespaced()
        .reconfigure(found.id, read_only, flags, &mut |old| {
            let Some((settings, used, files)) = old else {
                return Ok(None);
            };
            let Some(old) = settings.parsed.downcast_ref::<Tmpfs>() else {
                return Ok(None);
            };
            let mut new = old.reconfigured(asked, used, files).map_err(|refused| {
                message = refused.message;
                refused.errno
            })?;
            new.sb_flags = old.sb_flags & !mask | requested & mask;
            Ok(Some(new.settings()))
        })
        .map_err(|errno| Refused { errno, message })
}

/// Whether the caller has CAP_SYS_ADMIN over the user namespace that owns
/// the superblock of `found` (the first one for a mount from start-up).
fn over_superblock(c: &Context<'_>, found: &Target) -> bool {
    let creds = &c.process.credentials;
    match found
        .owner
        .as_ref()
        .and_then(|owner| owner.downcast_ref::<Namespace>())
    {
        Some(owner) => creds.capable_in(CAP_SYS_ADMIN, owner),
        None => creds.capable(CAP_SYS_ADMIN),
    }
}

/// One option as `vfs_parse_fs_string` takes it: a key and maybe a value,
/// none for an empty one or one with no key.
fn option_pair(option: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if option.is_empty() {
        return None;
    }
    match option.iter().position(|&b| b == b'=') {
        Some(0) => None,
        Some(at) => Some((&option[..at], Some(&option[at + 1..]))),
        None => Some((option, None)),
    }
}

/// A parameter's value, as `fsconfig` gives it (`fs_value_is_*`): none
/// (`FSCONFIG_SET_FLAG`, an option without `=`), a string, or another kind
/// (a blob, a path or a descriptor), which no tmpfs parameter takes.
#[derive(Clone, Copy)]
enum Value<'a> {
    Flag,
    String(&'a [u8]),
    Other,
}
impl<'a> Value<'a> {
    /// The value of an option of `mount`'s data.
    fn of(value: Option<&'a [u8]>) -> Self {
        value.map_or(Value::Flag, Value::String)
    }
}
/// A parameter or a change refused: its errno, and the message Linux logs
/// in the file system context, which `fsconfig`'s descriptor reads back
/// (`invalf`, or `invalfc` with the type's name before it), without the
/// level and the newline; empty for none.
#[derive(Debug)]
struct Refused {
    errno: Errno,
    message: String,
}
impl From<Errno> for Refused {
    fn from(errno: Errno) -> Self {
        Self {
            errno,
            message: String::new(),
        }
    }
}
impl From<Refused> for Errno {
    fn from(refused: Refused) -> Self {
        refused.errno
    }
}
impl Refused {
    /// `invalfc` of tmpfs: `EINVAL`, the message after `tmpfs: `.
    fn tmpfs(message: String) -> Self {
        Self::plain(format!("tmpfs: {message}"))
    }
    /// `invalf`: `EINVAL`, the message as it is.
    fn plain(message: String) -> Self {
        Self {
            errno: Errno::EINVAL,
            message,
        }
    }
}

/// tmpfs's options, as `shmem_init_fs_context` starts them and
/// `shmem_parse_one` changes them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tmpfs {
    /// `None` until `size` or `nr_blocks` gives them (`SHMEM_SEEN_BLOCKS`).
    blocks: Option<u64>,
    inodes: Option<u64>,
    mode: u32,
    uid: u32,
    gid: u32,
    inode32: bool,
    /// `inode32` or `inode64` was given (`SHMEM_SEEN_INUMS`).
    inums_seen: bool,
    huge: Option<&'static str>,
    mpol: Option<Vec<u8>>,
    noswap: bool,
    quota: (bool, bool),
    limits: [Option<u64>; 4],
    /// The superblock flags the options set and clear (`ro`, `sync`, ...).
    sb_set: u64,
    sb_clear: u64,
    /// The source, from the call or a `source` option (`fc->source`).
    source: Option<Vec<u8>>,
    /// The superblock's flags once mounted (`s_flags`).
    sb_flags: u64,
}
/// `totalram_pages()`: the memory `sysinfo` reports, in pages.
const RAM_PAGES: u64 = paludarium_vfs::MEMORY_BYTES / PAGE;
/// `shmem_default_max_blocks` and `shmem_default_max_inodes`.
const DEFAULT_BLOCKS: u64 = RAM_PAGES / 2;
const DEFAULT_INODES: u64 = RAM_PAGES / 2;
const BOGO_INODE_SIZE: u64 = 1024;
/// `SHMEM_QUOTA_MAX_SPC_LIMIT` and `SHMEM_QUOTA_MAX_INO_LIMIT`.
const QUOTA_MAX: u64 = 0x7fff_ffff_ffff_ffff;

/// `simple_strtoull(s, &end, 0)`: the number `s` starts with, in the base
/// its prefix gives (`0x` hex, `0` octal), wrapping on overflow, and where
/// it ends.
fn strtoull(s: &[u8]) -> (u64, usize) {
    let (base, mut at) = match s {
        [b'0', x, d, ..] if x.eq_ignore_ascii_case(&b'x') && d.is_ascii_hexdigit() => (16, 2),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let mut value: u64 = 0;
    while let Some(&b) = s.get(at) {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' | b'A'..=b'F' => u64::from(b.to_ascii_lowercase() - b'a') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value.wrapping_mul(base).wrapping_add(digit);
        at += 1;
    }
    (value, at)
}
/// `memparse`: a number with a `K`, `M`, `G`, `T`, `P` or `E` suffix,
/// `u64::MAX` past it, and whatever follows.
fn memparse(s: &[u8]) -> (u64, &[u8]) {
    let (value, end) = strtoull(s);
    let shift = match s.get(end).map(u8::to_ascii_lowercase) {
        Some(b'e') => 60,
        Some(b'p') => 50,
        Some(b't') => 40,
        Some(b'g') => 30,
        Some(b'm') => 20,
        Some(b'k') => 10,
        _ => 0,
    };
    if shift != 0 && end != 0 {
        let shifted = if value.leading_zeros() < shift {
            u64::MAX
        } else {
            value << shift
        };
        return (shifted, &s[end + 1..]);
    }
    (value, &s[end..])
}
/// `kstrtouint(s, base)`: the whole string, a `+` and a newline allowed.
fn kstrtouint(s: &[u8], base: u64) -> Option<u32> {
    let s = s.strip_prefix(b"+").unwrap_or(s);
    let (base, s) = match (base, s) {
        (0, [b'0', x, d, ..]) if x.eq_ignore_ascii_case(&b'x') && d.is_ascii_hexdigit() => {
            (16, &s[2..])
        }
        (0, [b'0', ..]) => (8, s),
        (0, _) => (10, s),
        (16, [b'0', x, ..]) if x.eq_ignore_ascii_case(&b'x') => (16, &s[2..]),
        _ => (base, s),
    };
    let mut value: u64 = 0;
    let mut digits = 0;
    for &b in s {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' | b'A'..=b'F' => u64::from(b.to_ascii_lowercase() - b'a') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value.checked_mul(base)?.checked_add(digit)?;
        digits += 1;
    }
    let rest = &s[digits..];
    if digits == 0 || !(rest.is_empty() || rest == b"\n") {
        return None;
    }
    u32::try_from(value).ok()
}
/// `mpol_parse_str` for the one node there is: a mode, and for `prefer`,
/// `bind`, `interleave`, `weighted_interleave` and `prefer_many` a node
/// list (`0`), with `=static`, `=relative` or `=local` after it.
fn mpol_valid(value: &[u8]) -> bool {
    let (policy, flags) = match value.iter().position(|&b| b == b'=') {
        Some(at) => (&value[..at], Some(&value[at + 1..])),
        None => (value, None),
    };
    let (mode, nodes) = match policy.iter().position(|&b| b == b':') {
        Some(at) => (&policy[..at], Some(&policy[at + 1..])),
        None => (policy, None),
    };
    let nodes_ok = |nodes: Option<&[u8]>| nodes.is_none_or(|n| n == b"0" || n == b"0-0");
    let ok = match mode {
        b"default" | b"local" => nodes.is_none(),
        b"prefer" => nodes_ok(nodes),
        b"interleave" | b"weighted_interleave" => nodes_ok(nodes),
        b"bind" | b"prefer_many" => nodes.is_some() && nodes_ok(nodes),
        _ => false,
    };
    ok && match flags {
        None => true,
        Some(b"static" | b"relative") => mode != b"default" && mode != b"local",
        Some(_) => false,
    }
}
impl Tmpfs {
    /// The options `shmem_init_fs_context` starts from: the root owned by
    /// the caller's filesystem IDs, mode 01777, and the source given.
    fn fresh(c: &Context<'_>, source: Option<Vec<u8>>) -> Self {
        let creds = &c.process.credentials;
        Self {
            blocks: None,
            inodes: None,
            mode: 0o1777,
            uid: creds.fsuid,
            gid: creds.fsgid,
            inode32: false,
            inums_seen: false,
            huge: None,
            mpol: None,
            noswap: false,
            quota: (false, false),
            limits: [None; 4],
            sb_set: 0,
            sb_clear: 0,
            source,
            sb_flags: 0,
        }
    }
    /// A common superblock flag (`vfs_parse_sb_flag`), if `key` is one.
    fn parse_common(&mut self, key: &[u8]) -> bool {
        let set = |flag: u64| (flag, 0);
        let clear = |flag: u64| (0, flag);
        let common = match key {
            b"dirsync" => Some(set(MS_DIRSYNC)),
            b"lazytime" => Some(set(MS_LAZYTIME)),
            b"mand" => Some(set(MS_MANDLOCK)),
            b"ro" => Some(set(MS_RDONLY)),
            b"sync" => Some(set(MS_SYNCHRONOUS)),
            b"async" => Some(clear(MS_SYNCHRONOUS)),
            b"nolazytime" => Some(clear(MS_LAZYTIME)),
            b"nomand" => Some(clear(MS_MANDLOCK)),
            b"rw" => Some(clear(MS_RDONLY)),
            _ => None,
        };
        let Some((on, off)) = common else {
            return false;
        };
        self.sb_set = (self.sb_set | on) & !off;
        self.sb_clear = (self.sb_clear | off) & !on;
        true
    }
    /// One parameter (`vfs_parse_fs_param`): a common superblock flag, of
    /// any value, then tmpfs's own (`shmem_fs_parameters`, `shmem_parse_one`),
    /// then the source; anything else, or a value of the wrong kind, is
    /// refused with the message Linux logs for it.
    fn parse(&mut self, c: &Context<'_>, key: &[u8], value: Value<'_>) -> Result<(), Refused> {
        if self.parse_common(key) {
            return Ok(());
        }
        let creds = &c.process.credentials;
        let first = creds.user.is_first_user();
        let name = String::from_utf8_lossy(key).into_owned();
        let bad = || Refused::tmpfs(format!("Bad value for '{name}'"));
        // `fs_param_is_string` and the like: a string, not empty.
        let string = || match value {
            Value::String(v) if !v.is_empty() => Ok(v.to_vec()),
            _ => Err(bad()),
        };
        // A flag parameter given a value (`__fs_parse`).
        let flag = || match value {
            Value::Flag => Ok(()),
            _ => Err(Refused::tmpfs(format!("Unexpected value for '{name}'"))),
        };
        match key {
            b"size" => {
                let v = string()?;
                let (mut size, mut rest) = memparse(&v);
                if rest.first() == Some(&b'%') {
                    size = (size << 12).wrapping_mul(RAM_PAGES) / 100;
                    rest = &rest[1..];
                }
                if !rest.is_empty() {
                    return Err(bad());
                }
                self.blocks = Some(size.div_ceil(PAGE));
            }
            b"nr_blocks" => {
                let v = string()?;
                let (blocks, rest) = memparse(&v);
                if !rest.is_empty() || blocks > i64::MAX as u64 {
                    return Err(bad());
                }
                self.blocks = Some(blocks);
            }
            b"nr_inodes" => {
                let v = string()?;
                let (inodes, rest) = memparse(&v);
                if !rest.is_empty() || inodes > u64::MAX / BOGO_INODE_SIZE {
                    return Err(bad());
                }
                self.inodes = Some(inodes);
            }
            b"mode" => {
                let mode = kstrtouint(&string()?, 8).ok_or_else(bad)?;
                self.mode = mode & 0o7777;
            }
            b"uid" | b"gid" => {
                let ids = if key == b"uid" {
                    crate::users::Ids::User
                } else {
                    crate::users::Ids::Group
                };
                let text = string()?;
                let id = kstrtouint(&text, 0).ok_or_else(bad)?;
                // `fs_param_is_uid`'s make_kuid in the caller's namespace,
                // whose mapping `shmem_parse_one` then needs.
                let kernel = creds.user.kernel_of(ids, id).ok_or_else(|| {
                    Refused::tmpfs(format!(
                        "Invalid {name} '{}'",
                        String::from_utf8_lossy(&text)
                    ))
                })?;
                if key == b"uid" {
                    self.uid = kernel;
                } else {
                    self.gid = kernel;
                }
            }
            b"huge" => {
                self.huge = Some(match &string()?[..] {
                    b"never" => "never",
                    b"always" => "always",
                    b"within_size" => "within_size",
                    b"advise" => "advise",
                    _ => return Err(bad()),
                });
            }
            b"mpol" => {
                let v = string()?;
                if !mpol_valid(&v) {
                    return Err(bad());
                }
                self.mpol = Some(v);
            }
            b"inode32" | b"inode64" => {
                flag()?;
                self.inode32 = key == b"inode32";
                self.inums_seen = true;
            }
            b"noswap" => {
                flag()?;
                if !first || !creds.capable(CAP_SYS_ADMIN) {
                    return Err(Refused::tmpfs(
                        "Turning off swap in unprivileged tmpfs mounts unsupported".into(),
                    ));
                }
                self.noswap = true;
            }
            b"quota" | b"usrquota" | b"grpquota" => {
                flag()?;
                if !first {
                    return Err(Refused::tmpfs(
                        "Quotas in unprivileged tmpfs mounts are unsupported".into(),
                    ));
                }
                self.quota.0 |= key != b"grpquota";
                self.quota.1 |= key != b"usrquota";
            }
            b"usrquota_block_hardlimit"
            | b"usrquota_inode_hardlimit"
            | b"grpquota_block_hardlimit"
            | b"grpquota_inode_hardlimit" => {
                let v = string()?;
                let (limit, rest) = memparse(&v);
                if !rest.is_empty() || limit == 0 {
                    return Err(bad());
                }
                let (at, what) = match key {
                    b"usrquota_block_hardlimit" => (0, "User quota block"),
                    b"grpquota_block_hardlimit" => (1, "Group quota block"),
                    b"usrquota_inode_hardlimit" => (2, "User quota inode"),
                    _ => (3, "Group quota inode"),
                };
                if limit > QUOTA_MAX {
                    return Err(Refused::tmpfs(format!("{what} hardlimit too large.")));
                }
                self.limits[at] = Some(limit);
            }
            // Case folding needs CONFIG_UNICODE, which this kernel is
            // built without, as tmpfs then refuses it (its message has its
            // own prefix and newline).
            b"casefold" | b"strict_encoding" => {
                if key == b"strict_encoding" {
                    flag()?;
                } else if matches!(value, Value::Other) {
                    return Err(bad());
                }
                return Err(Refused::tmpfs(
                    "tmpfs: Kernel not built with CONFIG_UNICODE\n".into(),
                ));
            }
            // vfs_parse_fs_param_source.
            b"source" => {
                let Value::String(value) = value else {
                    return Err(Refused::plain("Non-string source".into()));
                };
                if self.source.is_some() {
                    return Err(Refused::plain("Multiple sources".into()));
                }
                self.source = Some(value.to_vec());
            }
            _ => return Err(Refused::plain(format!("tmpfs: Unknown parameter '{name}'"))),
        }
        Ok(())
    }
    /// `shmem_reconfigure`: these options, as a remount `asked` for them,
    /// of a tmpfs whose files use `used` blocks and `files` inodes. A size
    /// or inode limit on one mounted without it, or below what is used,
    /// is `EINVAL`, as are `noswap` on one that swaps, quotas on one
    /// without them and a changed quota limit. The size, inodes, `huge`,
    /// `inode32` and `mpol` given change; the mode and owner do not.
    fn reconfigured(&self, asked: &Self, used: u64, files: u64) -> Result<Self, Refused> {
        let refused = |message: &str| Err(Refused::tmpfs(message.into()));
        let blocks = self.blocks.unwrap_or(DEFAULT_BLOCKS);
        let inodes = self.inodes.unwrap_or(DEFAULT_INODES);
        if let Some(new) = asked.blocks.filter(|&b| b != 0) {
            if blocks == 0 {
                return refused("Cannot retroactively limit size");
            }
            if used > new {
                return refused("Too small a size for current use");
            }
        }
        if let Some(new) = asked.inodes.filter(|&i| i != 0) {
            if inodes == 0 {
                return refused("Cannot retroactively limit inodes");
            }
            if new < files {
                return refused("Too few inodes for current use");
            }
        }
        if asked.noswap && !self.noswap {
            return refused("Cannot disable swap on remount");
        }
        if (asked.quota.0 || asked.quota.1) && !(self.quota.0 || self.quota.1) {
            return refused("Cannot enable quota on remount");
        }
        for (new, old) in asked.limits.iter().zip(&self.limits) {
            if let Some(new) = new
                && Some(*new) != *old
            {
                return refused("Cannot change global quota limit on remount");
            }
        }
        let mut out = Self {
            mpol: asked.mpol.clone().or_else(|| self.mpol.clone()),
            ..self.clone()
        };
        if asked.huge.is_some() {
            out.huge = asked.huge;
        }
        if asked.inums_seen {
            out.inode32 = asked.inode32;
        }
        if asked.blocks.is_some() {
            out.blocks = asked.blocks;
        }
        if asked.inodes.is_some() {
            out.inodes = asked.inodes;
        }
        Ok(out)
    }
    /// What the superblock keeps of these options.
    fn settings(self) -> Settings {
        Settings {
            blocks: self.blocks.unwrap_or(DEFAULT_BLOCKS),
            inodes: self.inodes.unwrap_or(DEFAULT_INODES),
            common_options: common_options(self.sb_flags),
            super_options: self.shown(),
            parsed: Arc::new(self),
        }
    }
    /// `shmem_show_options`, after the common ones (`show_sb_opts`).
    fn shown(&self) -> String {
        let mut out = String::new();
        let blocks = self.blocks.unwrap_or(DEFAULT_BLOCKS);
        if blocks != DEFAULT_BLOCKS {
            out.push_str(&format!(",size={}k", blocks << 2));
        }
        let inodes = self.inodes.unwrap_or(DEFAULT_INODES);
        if inodes != DEFAULT_INODES {
            out.push_str(&format!(",nr_inodes={inodes}"));
        }
        if self.mode != 0o1777 {
            out.push_str(&format!(",mode={:03o}", self.mode));
        }
        if self.uid != 0 {
            out.push_str(&format!(",uid={}", self.uid));
        }
        if self.gid != 0 {
            out.push_str(&format!(",gid={}", self.gid));
        }
        out.push_str(if self.inode32 { ",inode32" } else { ",inode64" });
        if let Some(huge) = self.huge.filter(|&h| h != "never") {
            out.push_str(&format!(",huge={huge}"));
        }
        if let Some(mpol) = &self.mpol
            && mpol != b"default"
        {
            out.push_str(&format!(",mpol={}", String::from_utf8_lossy(mpol)));
        }
        if self.noswap {
            out.push_str(",noswap");
        }
        if self.quota.0 {
            out.push_str(",usrquota");
        }
        if self.quota.1 {
            out.push_str(",grpquota");
        }
        for (limit, name) in self.limits.iter().zip([
            "usrquota_block_hardlimit",
            "grpquota_block_hardlimit",
            "usrquota_inode_hardlimit",
            "grpquota_inode_hardlimit",
        ]) {
            if let Some(limit) = limit {
                out.push_str(&format!(",{name}={limit}"));
            }
        }
        out
    }
}

/// `shmem_next_opt`: the options split at each comma not followed by a
/// digit (an `mpol` node list has those).
fn split_options(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b',' && !data.get(i + 1).is_some_and(u8::is_ascii_digit) {
            out.push(&data[start..i]);
            start = i + 1;
        }
    }
    out.push(&data[start..]);
    out
}

/// `do_new_mount`: a type (`EINVAL` for none), one this kernel has
/// (`ENODEV` for any but `tmpfs`), its options (`EINVAL`), and
/// CAP_SYS_ADMIN in the caller's user namespace (`mount_capable`, as tmpfs
/// is `FS_USERNS_MOUNT`). Its root is a directory of mode 01777 owned by
/// the caller's filesystem IDs, unless `mode`, `uid` and `gid` say
/// otherwise. `ro` makes the superblock read-only, as `MS_RDONLY` does,
/// which makes the mount read-only too.
fn new_tmpfs(
    c: &Context<'_>,
    kind: Option<Vec<u8>>,
    source: Option<Vec<u8>>,
    data: Option<&[u8]>,
    sb_flags: u64,
    mount_flags: u32,
) -> Result<NewTmpfs, Errno> {
    let kind = kind.ok_or(Errno::EINVAL)?;
    if kind != b"tmpfs" {
        return Err(ENODEV);
    }
    let creds = &c.process.credentials;
    let mut options = Tmpfs::fresh(c, source);
    for option in data.map(split_options).unwrap_or_default() {
        let Some((key, value)) = option_pair(option) else {
            continue;
        };
        options.parse(c, key, Value::of(value))?;
    }
    if !creds.administers_own() {
        return Err(Errno::EPERM);
    }
    built_tmpfs(c, options, sb_flags, mount_flags)
}
/// The new tmpfs `shmem_fill_super` makes of `options`, with the
/// superblock flags `sb_flags` and those they set, and the mount flags
/// `mount_flags`.
fn built_tmpfs(
    c: &Context<'_>,
    mut options: Tmpfs,
    sb_flags: u64,
    mount_flags: u32,
) -> Result<NewTmpfs, Errno> {
    let creds = &c.process.credentials;
    options.sb_flags = (sb_flags | options.sb_set) & !options.sb_clear;
    let host = Arc::clone(c.shared_host);
    let fs = MemFs::with_clock(Arc::new(move || host.clock(ClockId::Realtime)));
    fs.set_mode(b"/", options.mode)?;
    fs.set_owner(b"/", true, Some(options.uid), Some(options.gid))?;
    let now = c.host.clock(ClockId::Realtime)?;
    fs.set_times(b"/", true, None, Some(i128::from(now)))?;
    let read_only = options.sb_flags & MS_RDONLY != 0;
    let source = options.source.take().unwrap_or_else(|| b"none".to_vec());
    Ok(NewTmpfs {
        fs,
        settings: options.settings(),
        read_only,
        flags: mount_flags,
        source,
        owner: Some(Arc::clone(&creds.user.0) as Arc<dyn std::any::Any + Send + Sync>),
    })
}

/// `umount2(target, flags)`, as Linux's `ksys_umount`, `can_umount` and
/// `do_umount`: unknown flags are `EINVAL` before the target is looked up
/// (its last link followed unless `UMOUNT_NOFOLLOW`); then CAP_SYS_ADMIN
/// over the caller's mount namespace (`EPERM`); the root of a mount in that
/// namespace, not locked (`EINVAL`); `MNT_FORCE` CAP_SYS_ADMIN over the
/// superblock's user namespace (`EPERM`); a Landlock domain `EPERM`
/// (`hook_sb_umount`); `MNT_EXPIRE` alone, and not of the root (`EINVAL`),
/// marks a mount in use by nothing (`EBUSY`) and is `EAGAIN` the first
/// time; the caller's root without `MNT_DETACH` is `EPERM` without
/// CAP_SYS_ADMIN over its superblock, else stays with its superblock
/// remounted read-only (`do_umount_root`); the namespace's root `EINVAL`; and a mount in use `EBUSY`
/// unless `MNT_DETACH` takes it away at once. The target is looked up as
/// Linux's `LOOKUP_MOUNTPOINT` does, into a mount on where it starts. A
/// mount from start-up that the lower filesystem shows cannot go: `EBUSY`.
fn umount(c: &mut Context<'_>, ptr: u64, flags: u64) -> Result<u64, Errno> {
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return Err(Errno::EINVAL);
    }
    let target = paludarium_vfs::keeping_expiry(|| {
        crate::files::mount_target(c, ptr, flags & UMOUNT_NOFOLLOW == 0)
    })?;
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    let Some(target) = target else {
        return Err(Errno::EINVAL);
    };
    let namespaced = c.files.namespaced();
    let found = namespaced.umount_target(&target)?;
    if !found.root || !check_mnt(c, &namespaces.mnt) || found.locked {
        return Err(Errno::EINVAL);
    }
    let creds = &c.process.credentials;
    let over_superblock = over_superblock(c, &found);
    if flags & MNT_FORCE != 0 && !over_superblock {
        return Err(Errno::EPERM);
    }
    if creds.landlock.handles_fs() {
        return Err(Errno::EPERM);
    }
    let root = c.files.root();
    let is_root = namespaced.target(&root).is_ok_and(|r| r.id == found.id);
    if flags & MNT_EXPIRE != 0 {
        if is_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return Err(Errno::EINVAL);
        }
        if found.boot {
            return Err(EBUSY);
        }
        namespaced.expire(found.id)?;
        return Ok(0);
    }
    if is_root && flags & MNT_DETACH == 0 {
        if !over_superblock {
            return Err(Errno::EPERM);
        }
        // `do_umount_root`: its superblock is remounted read-only, the
        // rest as it was (`EBUSY` with a file open for writing on it).
        if !found.read_only.superblock {
            namespaced.reconfigure(found.id, true, found.flags, &mut |old| {
                Ok(old.map(|(settings, ..)| settings.clone()))
            })?;
        }
        return Ok(0);
    }
    if found.namespace_root {
        return Err(Errno::EINVAL);
    }
    if found.boot {
        return Err(EBUSY);
    }
    namespaced.umount(found.id, flags & MNT_DETACH != 0)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memparse_takes_a_prefix_and_a_suffix() {
        assert_eq!(memparse(b"1m"), (1 << 20, &b""[..]));
        assert_eq!(memparse(b"0x10K"), (16 << 10, &b""[..]));
        assert_eq!(memparse(b"010"), (8, &b""[..]));
        assert_eq!(memparse(b"5%"), (5, &b"%"[..]));
        // A suffix without a number is not one.
        assert_eq!(memparse(b"k"), (0, &b"k"[..]));
        assert_eq!(memparse(b"16E"), (u64::MAX, &b""[..]));
        assert_eq!(memparse(b"0x"), (0, &b"x"[..]));
    }

    #[test]
    fn kstrtouint_takes_the_whole_string() {
        assert_eq!(kstrtouint(b"0750", 8), Some(0o750));
        assert_eq!(kstrtouint(b"+17\n", 8), Some(0o17));
        assert_eq!(kstrtouint(b"8", 8), None);
        assert_eq!(kstrtouint(b"", 8), None);
        assert_eq!(kstrtouint(b"0x10", 0), Some(16));
        assert_eq!(kstrtouint(b"4294967296", 0), None);
    }

    #[test]
    fn options_split_where_no_digit_follows_a_comma() {
        assert_eq!(
            split_options(b"size=1m,mpol=bind:0,1,mode=700"),
            vec![&b"size=1m"[..], b"mpol=bind:0,1", b"mode=700"]
        );
        assert!(mpol_valid(b"bind:0"));
        assert!(mpol_valid(b"interleave"));
        assert!(!mpol_valid(b"bind"));
        assert!(!mpol_valid(b"local:0"));
        assert!(!mpol_valid(b"bind:1"));
    }
}
