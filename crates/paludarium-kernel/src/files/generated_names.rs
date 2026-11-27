//! The calls that make, remove or rename a name in a directory of `/proc`
//! or `/dev`, which the kernel generates, in Linux's order: the directory
//! (`filename_parentat`), the last name (`.`, `..`), its lookup (procfs
//! finds no name it does not have, `ENOENT`, where devtmpfs has a negative
//! dentry), the trailing slashes, the permission to write the directory
//! (`may_create`, `may_delete`) and then the directory's operation, which
//! procfs and devpts do not have (`EPERM`).
//!
//! The directory's permission is procfs's own: a process's directory and
//! a thread's are immutable (`S_IMMUTABLE`, `EPERM` before any mode), a
//! process's `fd` lets its own threads in (`proc_fd_permission`), and no
//! directory of `/proc/sys` may be written (`proc_sys_permission`); the
//! rest go by their mode, as `/dev` (devtmpfs, 0755 root).
use super::{device, generated_stat, in_shm, landlock_name};
use crate::permissions::{MAY_EXEC, MAY_WRITE, permission};
use crate::syscalls::Context;
use paludarium_host::FileStat;
use paludarium_types::Errno;

const DIRECTORY: u32 = 0o040000;
const TYPE: u32 = 0o170000;
const EBUSY: Errno = Errno(16);
const EXDEV: Errno = Errno(18);
const ENOTEMPTY: Errno = Errno(39);
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

/// The last name of a path, as `filename_parentat` sorts it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Last {
    Name,
    Dot,
    DotDot,
    Root,
}

/// Where a name is: the file system that holds its directory, as the
/// mount a walk to it ends on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Holder {
    Proc,
    /// devtmpfs, which has every directory operation.
    Dev,
    /// `/dev/pts`, which has none.
    Devpts,
}

/// A name the call takes: its directory, the path to it and how it ends.
struct Name {
    /// The directory, normalized, from the machine's root.
    dir: Vec<u8>,
    /// The name's own path, without the slashes it ends in.
    path: Vec<u8>,
    last: Last,
    /// The path ends in a slash.
    trailing: bool,
    holder: Holder,
}

/// The name `raw` (as written) resolves to at `p` (from the machine's
/// root, as [`super::Files::named_parent_linked`] gives it), when its
/// directory is in `/proc` or `/dev`. None for any other: `/dev/shm`, the
/// queues of `/dev/mqueue` and `/proc` or `/dev` themselves, whose
/// directory is the root's.
fn name(raw: &[u8], p: &[u8]) -> Option<Name> {
    let trimmed = |s: &[u8]| -> usize { s.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1) };
    let raw_end = trimmed(raw);
    let last = last_of(raw);
    let end = trimmed(p);
    let path = p[..end].to_vec();
    // The directory the name, `.` or `..` is in.
    let dir = parent(&path)?;
    let holder = holder(&dir)?;
    Some(Name {
        dir,
        path,
        last,
        trailing: raw.len() > raw_end,
        holder,
    })
}

/// How the path `raw` ends, as written.
fn last_of(raw: &[u8]) -> Last {
    let end = raw.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    let written = &raw[..end];
    match written.rsplit(|&b| b == b'/').next().unwrap_or(written) {
        _ if end == 0 => Last::Root,
        b"." => Last::Dot,
        b".." => Last::DotDot,
        _ => Last::Name,
    }
}

/// The directory, normalized, that holds the last name of `path`.
fn parent(path: &[u8]) -> Option<Vec<u8>> {
    let at = path.iter().rposition(|&b| b == b'/')?;
    let dir = if at == 0 {
        b"/".to_vec()
    } else {
        path[..at].to_vec()
    };
    Some(paludarium_vfs::normalize_path(&dir).unwrap_or(dir))
}

/// The root's directory, when the name `raw` resolves to at `p` is
/// `/proc` or `/dev` itself, which the machine's root holds with a mount on
/// it.
fn top<'a>(raw: &[u8], p: &[u8]) -> Option<&'a [u8]> {
    let end = p.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    let written = raw.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    let last = raw[..written].rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    let named = paludarium_vfs::normalize_path(&p[..end]).ok()?;
    (matches!(&named[..], b"/proc" | b"/dev") && last != b"." && last != b"..").then_some(b"/")
}

/// The file system of the generated directory `dir`, a normalized path.
fn holder(dir: &[u8]) -> Option<Holder> {
    let under =
        |base: &[u8]| dir == base || dir.starts_with(base) && dir.get(base.len()) == Some(&b'/');
    if under(b"/proc") {
        Some(Holder::Proc)
    } else if under(b"/dev/pts") {
        Some(Holder::Devpts)
    } else if under(b"/dev") && !in_shm(dir) && !under(b"/dev/mqueue") {
        Some(Holder::Dev)
    } else {
        None
    }
}

/// How procfs checks the permission on a directory of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// `/proc/<pid>` and `/proc/<pid>/task/<tid>` (`S_IMMUTABLE`).
    Immutable,
    /// A process's `fd`, and whether the reader is of that process.
    Descriptors {
        own: bool,
    },
    /// `/proc/sys` and the directories below.
    Sysctl,
    Mode,
}

fn kind(c: &Context<'_>, dir: &[u8]) -> Kind {
    let Some(rest) = dir.strip_prefix(b"/proc/") else {
        return Kind::Mode;
    };
    let parts: Vec<&[u8]> = rest.split(|&b| b == b'/').collect();
    let number = |part: &[u8]| -> Option<u32> { std::str::from_utf8(part).ok()?.parse().ok() };
    // A process's directory, its own (`self`) or a thread's of it
    // (`thread-self`, a `task` directory), and what is below.
    let (pid, below) = match parts[0] {
        b"sys" => return Kind::Sysctl,
        // A thread's own `task` directory.
        b"thread-self" => (c.process.pid, &parts[1..]),
        part => {
            let pid = match part {
                b"self" => c.process.pid,
                _ => match number(part) {
                    Some(pid) => pid,
                    None => return Kind::Mode,
                },
            };
            match parts.get(1..3) {
                Some([b"task", tid]) if number(tid).is_some() => (pid, &parts[3..]),
                _ => (pid, &parts[1..]),
            }
        }
    };
    match below {
        [] => Kind::Immutable,
        [b"fd"] => Kind::Descriptors {
            own: pid == c.process.pid,
        },
        _ => Kind::Mode,
    }
}

/// `inode_permission` of the directory for `mask`.
fn allowed(c: &Context<'_>, dir: &[u8], stat: &FileStat, mask: u32) -> Result<(), Errno> {
    let creds = &c.process.credentials;
    match kind(c, dir) {
        Kind::Immutable if mask & MAY_WRITE != 0 => Err(Errno::EPERM),
        Kind::Sysctl if mask & MAY_WRITE != 0 => Err(Errno::EACCES),
        Kind::Descriptors { own: true } => Ok(()),
        _ => permission(creds, stat, mask),
    }
}

/// `filename_parentat` of the name: its directory is there and is one,
/// and may be searched.
fn directory(c: &Context<'_>, name: &Name) -> Result<FileStat, Errno> {
    let (stat, ..) = generated_stat(c, &name.dir, true)?.ok_or(Errno::ENOENT)?;
    if stat.mode & TYPE != DIRECTORY {
        return Err(Errno::ENOTDIR);
    }
    allowed(c, &name.dir, &stat, MAY_EXEC)?;
    Ok(stat)
}

/// The lookup of the name in its directory: its file, none for one that is
/// not there in `/dev` (a negative dentry), and `ENOENT` in `/proc`, whose
/// lookups find only what is there.
fn looked_up(c: &Context<'_>, name: &Name) -> Result<Option<FileStat>, Errno> {
    match generated_stat(c, &name.path, false)? {
        Some((stat, ..)) => Ok(Some(stat)),
        // `/dev/shm`, a mount of the file system's own.
        None if mount_point(name) => Ok(c.files.fs().metadata(&name.path, false).ok()),
        None if name.holder == Holder::Proc => Err(Errno::ENOENT),
        None => Ok(None),
    }
}

/// `may_delete_dentry` of the name's file `victim`, before its type is
/// checked: the permission to write the directory, then the file itself,
/// which a process's or a thread's directory refuses (`S_IMMUTABLE`).
fn deletable(c: &Context<'_>, name: &Name, dir: &FileStat, victim: &FileStat) -> Result<(), Errno> {
    allowed(c, &name.dir, dir, MAY_WRITE | MAY_EXEC)?;
    if is_directory(victim) && kind(c, &name.path) == Kind::Immutable {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn is_directory(stat: &FileStat) -> bool {
    stat.mode & TYPE == DIRECTORY
}

/// Whether the name is a mount point on Linux, which no call removes or
/// renames (`EBUSY`): `/dev/pts`, `/dev/shm` and `/dev/mqueue`.
fn mount_point(name: &Name) -> bool {
    matches!(&name.path[..], b"/dev/pts" | b"/dev/shm" | b"/dev/mqueue")
}

/// `unlink` (`directory_call` false) and `rmdir` of the name `raw` resolves to
/// at `p`, when it is in a generated directory: Linux's error, or `EPERM`
/// as root in `/dev`, where devtmpfs would remove it. None for a name
/// elsewhere.
pub(crate) fn remove(c: &Context<'_>, raw: &[u8], p: &[u8], directory_call: bool) -> Option<Errno> {
    if let Some(top) = top(raw, p) {
        // `may_delete_dentry` in the root's directory, then the mount on
        // the name: `unlink` finds a directory (`EISDIR`), `rmdir` a mount
        // point (`EBUSY`).
        return Some(match c.files.fs().metadata(top, true) {
            Err(e) => e,
            Ok(stat) => permission(&c.process.credentials, &stat, MAY_WRITE | MAY_EXEC)
                .err()
                .unwrap_or(if directory_call { EBUSY } else { Errno::EISDIR }),
        });
    }
    let name = name(raw, p)?;
    Some(
        removed(c, &name, directory_call)
            .err()
            .unwrap_or(Errno::EPERM),
    )
}

fn removed(c: &Context<'_>, name: &Name, directory_call: bool) -> Result<(), Errno> {
    let dir = directory(c, name)?;
    match (name.last, directory_call) {
        (Last::Name, _) => {}
        (_, false) => return Err(Errno::EISDIR),
        (Last::Dot, true) => return Err(Errno::EINVAL),
        (Last::DotDot, true) => return Err(ENOTEMPTY),
        (Last::Root, true) => return Err(EBUSY),
    }
    let victim = looked_up(c, name)?.ok_or(Errno::ENOENT)?;
    // `do_unlinkat`'s trailing slash, once the name is found.
    if !directory_call && name.trailing {
        return Err(if is_directory(&victim) {
            Errno::EISDIR
        } else {
            Errno::ENOTDIR
        });
    }
    let request = if directory_call {
        crate::landlock::REMOVE_DIR
    } else {
        crate::landlock::REMOVE_FILE
    };
    landlock_name(c, &name.path, request)?;
    deletable(c, name, &dir, &victim)?;
    match (directory_call, is_directory(&victim)) {
        (true, false) => return Err(Errno::ENOTDIR),
        (false, true) => return Err(Errno::EISDIR),
        _ => {}
    }
    if name.holder == Holder::Dev && mount_point(name) {
        return Err(EBUSY);
    }
    Err(Errno::EPERM)
}

/// `mkdir` (`directory_call` true), `mknod` and `symlink` of the name
/// `raw` resolves to at `p`, when it is in a generated directory: Linux's
/// error, or `ENOENT` as root in `/dev`, where devtmpfs would make it. None
/// for a name elsewhere.
///
/// `request` is Landlock's right to make it.
pub(crate) fn make(
    c: &Context<'_>,
    raw: &[u8],
    p: &[u8],
    directory_call: bool,
    request: u64,
) -> Option<Errno> {
    if top(raw, p).is_some() {
        return Some(Errno::EEXIST);
    }
    let name = name(raw, p)?;
    Some(
        made(c, &name, directory_call, request)
            .err()
            .unwrap_or(Errno::ENOENT),
    )
}

fn made(c: &Context<'_>, name: &Name, directory_call: bool, request: u64) -> Result<(), Errno> {
    let dir = directory(c, name)?;
    if name.last != Last::Name {
        return Err(Errno::EEXIST);
    }
    if looked_up(c, name)?.is_some() {
        return Err(Errno::EEXIST);
    }
    // `filename_create`: a name that is not there ends in no slash unless
    // a directory is made.
    if name.trailing && !directory_call {
        return Err(Errno::ENOENT);
    }
    landlock_name(c, &name.path, request)?;
    // `may_create_dentry`, then devpts has no operation to make a name.
    allowed(c, &name.dir, &dir, MAY_WRITE | MAY_EXEC)?;
    if name.holder == Holder::Devpts {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// The new name of `link(old, new)` that `raw` resolves to at `p`, when it
/// is in a generated directory, once the old file was found: the new
/// name's errors (`filename_create`), then `EXDEV`, as no file elsewhere
/// is on that file system, and else the permission to write the directory
/// (`may_create_dentry`) and `EPERM`, as procfs links nothing. None for a
/// name elsewhere.
pub(crate) fn link_to(c: &Context<'_>, old: &[u8], raw: &[u8], p: &[u8]) -> Option<Errno> {
    if top(raw, p).is_some() {
        return Some(Errno::EEXIST);
    }
    let name = name(raw, p)?;
    let linked = || -> Result<(), Errno> {
        let dir = directory(c, &name)?;
        if name.last != Last::Name || looked_up(c, &name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        if name.trailing {
            return Err(Errno::ENOENT);
        }
        if holder_of(old) != Some(name.holder) {
            return Err(EXDEV);
        }
        allowed(c, &name.dir, &dir, MAY_WRITE | MAY_EXEC)?;
        Err(Errno::EPERM)
    };
    linked().err()
}

/// The file system of the file at the resolved `path`, when it is a
/// generated one.
fn holder_of(path: &[u8]) -> Option<Holder> {
    let path = paludarium_vfs::normalize_path(path).ok()?;
    holder(&parent(&path)?)
}

/// Whether the old name of `link(old, new)`, written `raw` and at the
/// resolved `old`, is in a generated directory: there, a name that is not
/// there is `ENOENT`, and one that is no directory `ENOTDIR` with a
/// trailing slash, before the new name is looked at.
pub(crate) fn link_from(
    c: &Context<'_>,
    raw: &[u8],
    old: &[u8],
    follow: bool,
) -> Option<Result<(), Errno>> {
    holder_of(old)?;
    let old = paludarium_vfs::normalize_path(old).ok()?;
    Some(
        match generated_stat(c, &old, follow || raw.ends_with(b"/")) {
            Ok(Some((stat, ..))) if raw.ends_with(b"/") && !is_directory(&stat) => {
                Err(Errno::ENOTDIR)
            }
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(Errno::ENOENT),
            Err(e) => Err(e),
        },
    )
}

/// `renameat2(old, new, flags)` of the names `old_raw` and `new_raw`
/// resolve to at `old` and `new`, when either is in a generated directory:
/// Linux's error (`EXDEV` between file systems), `0` for a name renamed
/// onto itself, and else `EPERM` (devtmpfs would rename it as root). None
/// when neither is.
pub(crate) fn rename(
    c: &Context<'_>,
    (old_raw, old): (&[u8], &[u8]),
    (new_raw, new): (&[u8], &[u8]),
    flags: u32,
) -> Option<Result<u64, Errno>> {
    let old_name = name(old_raw, old);
    let new_name = name(new_raw, new);
    if old_name.is_none() && new_name.is_none() {
        if top(old_raw, old).is_none() && top(new_raw, new).is_none() {
            return None;
        }
        return Some(renamed_top(c, (old_raw, old), (new_raw, new), flags));
    }
    Some(renamed(
        c,
        old_name.as_ref(),
        new_name.as_ref(),
        (old, new),
        flags,
    ))
}

/// `renameat2` where `/proc` or `/dev` itself is a name, in the root's
/// directory, and the other is not in a generated directory: both are on
/// the root's file system or it is `EXDEV`; a name onto itself is `0`; the
/// permission to change each directory, the new name's type, and then the
/// mount on `/proc` or `/dev` (`EBUSY`).
fn renamed_top(
    c: &Context<'_>,
    (old_raw, old): (&[u8], &[u8]),
    (new_raw, new): (&[u8], &[u8]),
    flags: u32,
) -> Result<u64, Errno> {
    let creds = &c.process.credentials;
    let fs = c.files.fs();
    let normal = |p: &[u8]| paludarium_vfs::normalize_path(p).unwrap_or_else(|_| p.to_vec());
    let (old, new) = (normal(old), normal(new));
    elsewhere(c, &old)?;
    elsewhere(c, &new)?;
    let (old_dir, new_dir) = (parent(&old).ok_or(EBUSY)?, parent(&new).ok_or(EBUSY)?);
    if device(c, &old_dir) != device(c, &new_dir) {
        return Err(EXDEV);
    }
    if last_of(old_raw) != Last::Name {
        return Err(EBUSY);
    }
    if last_of(new_raw) != Last::Name {
        return Err(if flags & RENAME_NOREPLACE != 0 {
            Errno::EEXIST
        } else {
            EBUSY
        });
    }
    let stat_of = |p: &[u8], raw: &[u8]| -> Option<FileStat> {
        if top(raw, p).is_some() {
            generated_stat(c, p, false)
                .ok()
                .flatten()
                .map(|(stat, ..)| stat)
        } else {
            fs.metadata(p, false).ok()
        }
    };
    let old_file = stat_of(&old, old_raw).ok_or(Errno::ENOENT)?;
    let new_file = stat_of(&new, new_raw);
    if flags & RENAME_NOREPLACE != 0 && new_file.is_some() {
        return Err(Errno::EEXIST);
    }
    let exchange = flags & RENAME_EXCHANGE != 0;
    if exchange && new_file.is_none() {
        return Err(Errno::ENOENT);
    }
    let (old_trailing, new_trailing) = (old_raw.ends_with(b"/"), new_raw.ends_with(b"/"));
    if exchange && new_trailing && !new_file.as_ref().is_some_and(is_directory) {
        return Err(Errno::ENOTDIR);
    }
    if !is_directory(&old_file) && (old_trailing || !exchange && new_trailing) {
        return Err(Errno::ENOTDIR);
    }
    if new_file.is_some() && old == new {
        return Ok(0);
    }
    let writable = |dir: &[u8]| -> Result<(), Errno> {
        permission(creds, &fs.metadata(dir, true)?, MAY_WRITE | MAY_EXEC)
    };
    writable(&old_dir)?;
    writable(&new_dir)?;
    if let Some(file) = &new_file {
        let is_dir = if exchange {
            is_directory(file)
        } else {
            is_directory(&old_file)
        };
        match (is_dir, is_directory(file)) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
    }
    Err(EBUSY)
}

/// `filename_parentat` of a name not in a generated directory, at the
/// resolved `p`: its directory is there and is one.
fn elsewhere(c: &Context<'_>, p: &[u8]) -> Result<(), Errno> {
    let end = p.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    let Some(dir) = parent(&p[..end]) else {
        return Ok(());
    };
    let stat = c.files.fs().metadata(&dir, true)?;
    if stat.mode & TYPE != DIRECTORY {
        return Err(Errno::ENOTDIR);
    }
    Ok(())
}

fn renamed(
    c: &Context<'_>,
    old: Option<&Name>,
    new: Option<&Name>,
    paths: (&[u8], &[u8]),
    flags: u32,
) -> Result<u64, Errno> {
    // `filename_parentat` of each, then their mounts.
    let old_dir = match old {
        Some(name) => Some(directory(c, name)?),
        None => {
            elsewhere(c, paths.0)?;
            None
        }
    };
    let new_dir = match new {
        Some(name) => Some(directory(c, name)?),
        None => {
            elsewhere(c, paths.1)?;
            None
        }
    };
    let (Some(old), Some(new), Some(old_dir), Some(new_dir)) = (old, new, old_dir, new_dir) else {
        return Err(EXDEV);
    };
    if old.holder != new.holder {
        return Err(EXDEV);
    }
    if old.last != Last::Name {
        return Err(EBUSY);
    }
    if new.last != Last::Name {
        return Err(if flags & RENAME_NOREPLACE != 0 {
            Errno::EEXIST
        } else {
            EBUSY
        });
    }
    // `__start_renaming`'s lookups.
    let old_file = looked_up(c, old)?.ok_or(Errno::ENOENT)?;
    let new_file = looked_up(c, new)?;
    if flags & RENAME_NOREPLACE != 0 && new_file.is_some() {
        return Err(Errno::EEXIST);
    }
    if flags & RENAME_EXCHANGE != 0 && new_file.is_none() {
        return Err(Errno::ENOENT);
    }
    let exchange = flags & RENAME_EXCHANGE != 0;
    if exchange && new.trailing && !new_file.as_ref().is_some_and(is_directory) {
        return Err(Errno::ENOTDIR);
    }
    if !is_directory(&old_file) && (old.trailing || !exchange && new.trailing) {
        return Err(Errno::ENOTDIR);
    }
    // `vfs_rename`: a name onto itself changes nothing.
    if new_file.is_some() && old.path == new.path {
        return Ok(0);
    }
    let directory_rename = is_directory(&old_file);
    deletable(c, old, &old_dir, &old_file)?;
    match &new_file {
        None => allowed(c, &new.dir, &new_dir, MAY_WRITE | MAY_EXEC)?,
        Some(file) => {
            deletable(c, new, &new_dir, file)?;
            let is_dir = if exchange {
                is_directory(file)
            } else {
                directory_rename
            };
            match (is_dir, is_directory(file)) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                _ => {}
            }
        }
    }
    if old.holder == Holder::Dev && (mount_point(old) || mount_point(new)) {
        return Err(EBUSY);
    }
    Err(Errno::EPERM)
}

/// An open with `O_CREAT` (`flags`) of the name `raw` resolves to at `p`,
/// when it is in a generated directory or is `/proc` or `/dev`, as
/// `open_last_lookups` and `do_open` take it: a trailing slash is `EISDIR`,
/// a file that is there `EEXIST` with `O_EXCL` and a directory `EISDIR`;
/// one that is not there is `ENOENT` in `/proc`, which makes no file, and
/// needs the permission to write `/dev` (`may_o_create`, else `ENOENT` as
/// root, where devtmpfs would make it). None for an open that goes on: a
/// file that is there and no directory, without `O_EXCL`.
pub(crate) fn open_create(c: &Context<'_>, raw: &[u8], p: &[u8], flags: u32) -> Option<Errno> {
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_NOFOLLOW: u32 = 0o400000;
    if flags & O_CREAT == 0 {
        return None;
    }
    let exclusive = flags & O_EXCL != 0;
    let follow = !exclusive && flags & O_NOFOLLOW == 0;
    // A file that is there: `EEXIST` with `O_EXCL`, `EISDIR` for a
    // directory, else the open goes on.
    let there = |stat: &FileStat| -> Option<Errno> {
        if exclusive {
            Some(Errno::EEXIST)
        } else if is_directory(stat) {
            Some(Errno::EISDIR)
        } else {
            None
        }
    };
    if top(raw, p).is_some() {
        if raw.ends_with(b"/") {
            return Some(Errno::EISDIR);
        }
        return if exclusive {
            Some(Errno::EEXIST)
        } else {
            Some(Errno::EISDIR)
        };
    }
    let name = name(raw, p)?;
    let opened = || -> Result<Option<Errno>, Errno> {
        let dir = directory(c, &name)?;
        if name.last != Last::Name {
            return Ok(if exclusive {
                Some(Errno::EEXIST)
            } else {
                Some(Errno::EISDIR)
            });
        }
        if name.trailing {
            return Err(Errno::EISDIR);
        }
        if let Some((stat, ..)) = generated_stat(c, &name.path, follow)? {
            return Ok(there(&stat));
        }
        if name.holder == Holder::Proc {
            return Err(Errno::ENOENT);
        }
        landlock_name(c, &name.path, crate::landlock::MAKE_REG)?;
        allowed(c, &name.dir, &dir, MAY_WRITE | MAY_EXEC)?;
        Err(if name.holder == Holder::Devpts {
            Errno::EACCES
        } else {
            Errno::ENOENT
        })
    };
    match opened() {
        Ok(error) => error,
        Err(error) => Some(error),
    }
}
