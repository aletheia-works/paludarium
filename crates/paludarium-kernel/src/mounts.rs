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
//! it too), which mountinfo shows; nothing propagates between peers.
//! Read-only mounts and superblocks refuse writes (`EROFS`, in the calls
//! that write). What it does not do yet gives `EOPNOTSUPP` once Linux's
//! checks before it have passed: `MS_MOVE`, `MS_NOSYMFOLLOW` on a tmpfs or
//! set by a remount, and a mount on, or a bind mount of, `/proc` or
//! `/dev`, which the kernel generates. Any other file system type is
//! `ENODEV`, as from a kernel without it.
//!
//! `umount2` unmounts the mounts `mount` made; a mount from start-up (the root, a
//! `--mount` directory) stays: `EINVAL` when it is locked, else `EBUSY`.
use std::sync::Arc;

use paludarium_host::{ClockId, HostFs};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{MemFs, NewTmpfs, Propagation, Settings, Target, mount_flags as mnt};

use crate::namespaces::Namespace;
use crate::syscalls::{Context, Outcome};

const CAP_SYS_ADMIN: u64 = 1 << 21;
const EBUSY: Errno = Errno(16);
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

/// `copy_mount_string`: none for a null pointer, else the string as
/// `strndup_user(s, PATH_MAX)` takes it: `EFAULT` where it cannot be read,
/// `EINVAL` when no 0 ends it within `PATH_MAX` bytes.
fn mount_string(c: &Context<'_>, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let mut out = Vec::new();
    for i in 0..PATH_MAX {
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
        return Err(Errno::EOPNOTSUPP);
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
            asked.parse(c, key, value)?;
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
    c.files
        .namespaced()
        .reconfigure(found.id, requested & MS_RDONLY != 0, flags, &mut |old| {
            let Some((settings, used, files)) = old else {
                return Ok(None);
            };
            let Some(old) = settings.parsed.downcast_ref::<Tmpfs>() else {
                return Ok(None);
            };
            let mut new = old.reconfigured(&asked, used, files)?;
            new.sb_flags = old.sb_flags & !mask | requested & mask;
            Ok(Some(new.settings()))
        })?;
    Ok(0)
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
    /// One `key[=value]` of the options (`vfs_parse_fs_param`): a common
    /// superblock flag, then tmpfs's own (`shmem_fs_parameters`), then the
    /// source; anything else, or a value of the wrong kind, is `EINVAL`.
    fn parse(&mut self, c: &Context<'_>, key: &[u8], value: Option<&[u8]>) -> Result<(), Errno> {
        if self.parse_common(key) {
            return Ok(());
        }
        let creds = &c.process.credentials;
        let first = creds.user.is_first_user();
        let bad = Err(Errno::EINVAL);
        // A string parameter given no value, and a flag given one, are bad.
        let string = |value: Option<&[u8]>| match value {
            Some(v) if !v.is_empty() => Ok(v.to_vec()),
            _ => Err(Errno::EINVAL),
        };
        let flag = |value: Option<&[u8]>| match value {
            None => Ok(()),
            Some(_) => Err(Errno::EINVAL),
        };
        match key {
            b"size" => {
                let v = string(value)?;
                let (mut size, mut rest) = memparse(&v);
                if rest.first() == Some(&b'%') {
                    size = (size << 12).wrapping_mul(RAM_PAGES) / 100;
                    rest = &rest[1..];
                }
                if !rest.is_empty() {
                    return bad;
                }
                self.blocks = Some(size.div_ceil(PAGE));
            }
            b"nr_blocks" => {
                let v = string(value)?;
                let (blocks, rest) = memparse(&v);
                if !rest.is_empty() || blocks > i64::MAX as u64 {
                    return bad;
                }
                self.blocks = Some(blocks);
            }
            b"nr_inodes" => {
                let v = string(value)?;
                let (inodes, rest) = memparse(&v);
                if !rest.is_empty() || inodes > u64::MAX / BOGO_INODE_SIZE {
                    return bad;
                }
                self.inodes = Some(inodes);
            }
            b"mode" => {
                let mode = kstrtouint(&string(value)?, 8).ok_or(Errno::EINVAL)?;
                self.mode = mode & 0o7777;
            }
            b"uid" | b"gid" => {
                let ids = if key == b"uid" {
                    crate::users::Ids::User
                } else {
                    crate::users::Ids::Group
                };
                let id = kstrtouint(&string(value)?, 0).ok_or(Errno::EINVAL)?;
                // make_kuid, then kuid_has_mapping in the same namespace.
                let kernel = creds.user.kernel_of(ids, id).ok_or(Errno::EINVAL)?;
                if key == b"uid" {
                    self.uid = kernel;
                } else {
                    self.gid = kernel;
                }
            }
            b"huge" => {
                self.huge = Some(match &string(value)?[..] {
                    b"never" => "never",
                    b"always" => "always",
                    b"within_size" => "within_size",
                    b"advise" => "advise",
                    _ => return bad,
                });
            }
            b"mpol" => {
                let v = string(value)?;
                if !mpol_valid(&v) {
                    return bad;
                }
                self.mpol = Some(v);
            }
            b"inode32" | b"inode64" => {
                flag(value)?;
                self.inode32 = key == b"inode32";
                self.inums_seen = true;
            }
            b"noswap" => {
                flag(value)?;
                if !first || !creds.capable(CAP_SYS_ADMIN) {
                    return bad;
                }
                self.noswap = true;
            }
            b"quota" | b"usrquota" | b"grpquota" => {
                flag(value)?;
                if !first {
                    return bad;
                }
                self.quota.0 |= key != b"grpquota";
                self.quota.1 |= key != b"usrquota";
            }
            b"usrquota_block_hardlimit"
            | b"usrquota_inode_hardlimit"
            | b"grpquota_block_hardlimit"
            | b"grpquota_inode_hardlimit" => {
                let v = string(value)?;
                let (limit, rest) = memparse(&v);
                if !rest.is_empty() || limit == 0 || limit > QUOTA_MAX {
                    return bad;
                }
                let at = match key {
                    b"usrquota_block_hardlimit" => 0,
                    b"grpquota_block_hardlimit" => 1,
                    b"usrquota_inode_hardlimit" => 2,
                    _ => 3,
                };
                self.limits[at] = Some(limit);
            }
            // Case folding needs CONFIG_UNICODE, which this kernel is
            // built without, as tmpfs then refuses it.
            b"casefold" | b"strict_encoding" => return bad,
            // vfs_parse_fs_param_source.
            b"source" => {
                let Some(value) = value else {
                    return bad;
                };
                if self.source.is_some() {
                    return bad;
                }
                self.source = Some(value.to_vec());
            }
            _ => return bad,
        }
        Ok(())
    }
    /// `shmem_reconfigure`: these options, as a remount `asked` for them,
    /// of a tmpfs whose files use `used` blocks and `files` inodes. A size
    /// or inode limit on one mounted without it, or below what is used,
    /// is `EINVAL`, as are `noswap` on one that swaps, quotas on one
    /// without them and a changed quota limit. The size, inodes, `huge`,
    /// `inode32` and `mpol` given change; the mode and owner do not.
    fn reconfigured(&self, asked: &Self, used: u64, files: u64) -> Result<Self, Errno> {
        let bad = Err(Errno::EINVAL);
        let blocks = self.blocks.unwrap_or(DEFAULT_BLOCKS);
        let inodes = self.inodes.unwrap_or(DEFAULT_INODES);
        if let Some(new) = asked.blocks.filter(|&b| b != 0)
            && (blocks == 0 || used > new)
        {
            return bad;
        }
        if let Some(new) = asked.inodes.filter(|&i| i != 0)
            && (inodes == 0 || new < files)
        {
            return bad;
        }
        if asked.noswap && !self.noswap {
            return bad;
        }
        if (asked.quota.0 || asked.quota.1) && !(self.quota.0 || self.quota.1) {
            return bad;
        }
        for (new, old) in asked.limits.iter().zip(&self.limits) {
            if let Some(new) = new
                && Some(*new) != *old
            {
                return bad;
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
        options.parse(c, key, value)?;
    }
    if !creds.administers_own() {
        return Err(Errno::EPERM);
    }
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
/// unless `MNT_DETACH` takes it away at once. A mount from start-up cannot
/// go: `EBUSY`.
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
    let found = namespaced.target(&target)?;
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
