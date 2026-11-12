//! Inode flags, as tmpfs keeps them (`mm/shmem.c`) and Linux's
//! `fs/file_attr.c` reads and changes them: `file_getattr` and
//! `file_setattr` (Linux 6.17), and the `FS_IOC_GETFLAGS`,
//! `FS_IOC_SETFLAGS`, `FS_IOC_FSGETXATTR` and `FS_IOC_FSSETXATTR` ioctls. A
//! file in memory that is a regular file or a directory keeps
//! `FS_IMMUTABLE_FL`, `FS_APPEND_FL`, `FS_NODUMP_FL` and `FS_NOATIME_FL`;
//! any other file, as one in a mounted host directory or under `/proc`,
//! behaves as a file system without them.
use super::{copy_struct, output, xattrs::Target};
use crate::credentials::Credentials;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicBool, Ordering};

const E2BIG: Errno = Errno(7);
const PAGE_SIZE: u64 = 4096;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const CAP_LINUX_IMMUTABLE: u64 = 1 << 9;

// The flags of `FS_IOC_GETFLAGS`.
const FS_SYNC_FL: u32 = 0x8;
pub(crate) const FS_IMMUTABLE_FL: u32 = 0x10;
pub(crate) const FS_APPEND_FL: u32 = 0x20;
const FS_NODUMP_FL: u32 = 0x40;
const FS_NOATIME_FL: u32 = 0x80;
const FS_VERITY_FL: u32 = 0x0010_0000;
const FS_DAX_FL: u32 = 0x0200_0000;
const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
const FS_CASEFOLD_FL: u32 = 0x4000_0000;
/// `FS_COMMON_FL`: the flags that have an `FS_XFLAG_*` of their own.
const FS_COMMON_FL: u32 = FS_SYNC_FL
    | FS_IMMUTABLE_FL
    | FS_APPEND_FL
    | FS_NODUMP_FL
    | FS_NOATIME_FL
    | FS_DAX_FL
    | FS_PROJINHERIT_FL
    | FS_VERITY_FL;
/// `SHMEM_FL_USER_MODIFIABLE`.
const MODIFIABLE: u32 =
    FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL | FS_CASEFOLD_FL;

// The flags of `struct fsxattr` and `struct file_attr`.
const XFLAG_REALTIME: u32 = 0x1;
const XFLAG_PREALLOC: u32 = 0x2;
const XFLAG_IMMUTABLE: u32 = 0x8;
const XFLAG_APPEND: u32 = 0x10;
const XFLAG_SYNC: u32 = 0x20;
const XFLAG_NOATIME: u32 = 0x40;
const XFLAG_NODUMP: u32 = 0x80;
const XFLAG_RTINHERIT: u32 = 0x100;
const XFLAG_PROJINHERIT: u32 = 0x200;
const XFLAG_NOSYMLINKS: u32 = 0x400;
const XFLAG_EXTSIZE: u32 = 0x800;
const XFLAG_EXTSZINHERIT: u32 = 0x1000;
const XFLAG_NODEFRAG: u32 = 0x2000;
const XFLAG_FILESTREAM: u32 = 0x4000;
const XFLAG_DAX: u32 = 0x8000;
const XFLAG_COWEXTSIZE: u32 = 0x1_0000;
const XFLAG_VERITY: u32 = 0x2_0000;
const XFLAG_CASEFOLD: u32 = 0x4_0000;
const XFLAG_CASENONPRESERVING: u32 = 0x8_0000;
const XFLAG_HASATTR: u32 = 0x8000_0000;
/// `FS_XFLAG_COMMON`.
const XFLAG_COMMON: u32 = XFLAG_SYNC
    | XFLAG_IMMUTABLE
    | XFLAG_APPEND
    | XFLAG_NODUMP
    | XFLAG_NOATIME
    | XFLAG_DAX
    | XFLAG_PROJINHERIT
    | XFLAG_VERITY;
/// `FS_XFLAG_RDONLY_MASK`: what a caller cannot set.
const XFLAG_RDONLY: u32 =
    XFLAG_PREALLOC | XFLAG_HASATTR | XFLAG_VERITY | XFLAG_CASEFOLD | XFLAG_CASENONPRESERVING;
/// `FS_XFLAGS_MASK`: every flag Linux knows.
const XFLAGS_MASK: u32 = XFLAG_COMMON
    | XFLAG_RDONLY
    | XFLAG_EXTSIZE
    | XFLAG_COWEXTSIZE
    | XFLAG_RTINHERIT
    | XFLAG_NOSYMLINKS
    | XFLAG_EXTSZINHERIT
    | XFLAG_REALTIME
    | XFLAG_NODEFRAG
    | XFLAG_FILESTREAM;
/// Each flag with an `FS_XFLAG_*` and that flag, as `fileattr_fill_*`
/// translate them.
const PAIRS: [(u32, u32); 9] = [
    (FS_IMMUTABLE_FL, XFLAG_IMMUTABLE),
    (FS_APPEND_FL, XFLAG_APPEND),
    (FS_SYNC_FL, XFLAG_SYNC),
    (FS_NOATIME_FL, XFLAG_NOATIME),
    (FS_NODUMP_FL, XFLAG_NODUMP),
    (FS_DAX_FL, XFLAG_DAX),
    (FS_PROJINHERIT_FL, XFLAG_PROJINHERIT),
    (FS_VERITY_FL, XFLAG_VERITY),
    (FS_CASEFOLD_FL, XFLAG_CASEFOLD),
];

/// `FILE_ATTR_SIZE_VER0`, the size of `struct file_attr`.
const FILE_ATTR_SIZE_VER0: u64 = 24;
/// The size of `struct fsxattr`, with its 8 bytes of padding.
const FSXATTR_SIZE: usize = 28;
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FS_IOC_FSGETXATTR: u32 = 0x801c_581f;
const FS_IOC_FSSETXATTR: u32 = 0x401c_5820;

/// Whether a file of the machine `files` belongs to may now be immutable
/// or append-only. Until one was made so, root's path walks may skip their
/// checks, as no file can refuse root.
pub(crate) fn any_flagged(files: &crate::files::Files) -> bool {
    files.caches.flagged.load(Ordering::Relaxed)
}

/// `IS_IMMUTABLE`.
pub(crate) fn immutable(stat: &FileStat) -> bool {
    stat.attributes & FS_IMMUTABLE_FL != 0
}

/// `IS_APPEND`.
pub(crate) fn append_only(stat: &FileStat) -> bool {
    stat.attributes & FS_APPEND_FL != 0
}

/// `IS_IMMUTABLE || IS_APPEND`, which refuses a change of mode, owner or
/// times (`may_setattr`), a link (`vfs_link`) or a change of extended
/// attributes (`may_write_xattr`) with EPERM.
pub(crate) fn unchangeable(stat: &FileStat) -> Result<(), Errno> {
    if stat.attributes & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// `may_open`'s checks of the flags of a file that is not a directory or a
/// symbolic link: an immutable one is not opened to write or truncate,
/// and an append-only one only to append (EPERM).
pub(crate) fn may_open(stat: &FileStat, flags: u32) -> Result<(), Errno> {
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;
    let writes = flags & 3 != 0;
    if immutable(stat) && (writes || flags & O_TRUNC != 0) {
        return Err(Errno::EPERM);
    }
    if append_only(stat) && ((writes && flags & O_APPEND == 0) || flags & O_TRUNC != 0) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Linux's `struct file_kattr`: both forms of the flags, the `fsxattr`
/// fields, and which form a caller gave.
#[derive(Clone, Copy, Default)]
struct Kattr {
    flags: u32,
    xflags: u32,
    extsize: u32,
    nextents: u32,
    projid: u32,
    cowextsize: u32,
    flags_valid: bool,
    fsx_valid: bool,
}
impl Kattr {
    /// `fileattr_fill_flags`.
    fn from_flags(flags: u32) -> Self {
        let xflags = PAIRS
            .iter()
            .filter(|(flag, _)| flags & flag != 0)
            .fold(0, |x, (_, xflag)| x | xflag);
        Self {
            flags,
            xflags,
            flags_valid: true,
            ..Self::default()
        }
    }
    /// `fileattr_fill_xflags`.
    fn from_xflags(xflags: u32) -> Self {
        let flags = PAIRS
            .iter()
            .filter(|(_, xflag)| xflags & xflag != 0)
            .fold(0, |f, (flag, _)| f | flag);
        Self {
            flags,
            xflags,
            fsx_valid: true,
            ..Self::default()
        }
    }
}

/// A `with_attributes` of one file.
type Reach<'a> = dyn Fn(&mut dyn FnMut(&mut u32)) -> Result<(), Errno> + 'a;

/// The flags of the file a `with_attributes` reaches (`fileattr_get`).
fn current(with: &Reach<'_>) -> Result<u32, Errno> {
    let mut flags = 0;
    with(&mut |f| flags = *f)?;
    Ok(flags)
}

/// `vfs_fileattr_set` with `fileattr_set_prepare` and tmpfs's
/// `shmem_fileattr_set`, on a file of status `stat` whose flags `with`
/// reaches: the owner or `CAP_FOWNER` (EPERM), `CAP_LINUX_IMMUTABLE` to
/// change `FS_IMMUTABLE_FL` or `FS_APPEND_FL` (EPERM), the project ID and
/// extent size checks (EINVAL), then only what tmpfs keeps (EOPNOTSUPP).
fn set(
    (creds, flagged): (&Credentials, &AtomicBool),
    stat: &FileStat,
    with: &Reach<'_>,
    mut fa: Kattr,
) -> Result<(), Errno> {
    let old_flags = current(with)?;
    if !crate::permissions::owner_or_capable(creds, stat) {
        return Err(Errno::EPERM);
    }
    let old = Kattr::from_flags(old_flags);
    // What a caller left out is kept as it is.
    if fa.flags_valid {
        fa.xflags |= old.xflags & !XFLAG_COMMON;
        fa.extsize = old.extsize;
        fa.nextents = old.nextents;
        fa.projid = old.projid;
        fa.cowextsize = old.cowextsize;
    } else {
        fa.flags |= old.flags & !FS_COMMON_FL;
    }
    if (fa.flags ^ old.flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) != 0
        && !creds.capable(CAP_LINUX_IMMUTABLE)
    {
        return Err(Errno::EPERM);
    }
    // Only the first user namespace may change the project ID, to a valid
    // one.
    if creds.user != crate::users::UserNs::default() {
        if old.projid != fa.projid || (old.xflags ^ fa.xflags) & XFLAG_PROJINHERIT != 0 {
            return Err(Errno::EINVAL);
        }
    } else if old.projid != fa.projid && fa.projid == u32::MAX {
        return Err(Errno::EINVAL);
    }
    let kind = stat.mode & 0o170000;
    let (regular, directory) = (kind == 0o100000, kind == 0o040000);
    if (fa.xflags & XFLAG_EXTSIZE != 0 && !regular)
        || (fa.xflags & XFLAG_EXTSZINHERIT != 0 && !directory)
        || (fa.xflags & (XFLAG_COWEXTSIZE | XFLAG_DAX) != 0 && !regular && !directory)
    {
        return Err(Errno::EINVAL);
    }
    if fa.extsize == 0 {
        fa.xflags &= !(XFLAG_EXTSIZE | XFLAG_EXTSZINHERIT);
    }
    if fa.cowextsize == 0 {
        fa.xflags &= !XFLAG_COWEXTSIZE;
    }
    // tmpfs keeps no `fsxattr` field of its own, and only some flags.
    if fa.fsx_valid
        && (fa.xflags & !XFLAG_COMMON != 0
            || fa.extsize != 0
            || fa.projid != 0
            || fa.cowextsize != 0)
    {
        return Err(Errno::EOPNOTSUPP);
    }
    if fa.flags & !MODIFIABLE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    // A tmpfs mounted without an encoding has no case folding.
    if fa.flags & FS_CASEFOLD_FL != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let flags = fa.flags & MODIFIABLE;
    if flags & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
        flagged.store(true, Ordering::Relaxed);
    }
    with(&mut |f| {
        *f = (*f & !MODIFIABLE) | flags;
        // `fsnotify_xattr`: IN_ATTRIB.
        crate::inotify::xattrs_changed();
    })
}

/// `struct file_attr` or `struct fsxattr` of `flags`: the flags as
/// `FS_XFLAG_*`, and every other field 0 on tmpfs.
fn xflags_of(flags: u32) -> u32 {
    Kattr::from_flags(flags).xflags & XFLAGS_MASK
}

/// `file_getattr(dfd, path, attr, size, at_flags)`: the flags (EINVAL for
/// others), the size (`E2BIG` above a page, `EINVAL` below 24 bytes), the
/// file as the `*xattrat` calls find it, then `EOPNOTSUPP` for one without
/// flags. The rest of a larger struct is zeroed (`copy_struct_to_user`).
fn file_getattr(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (addr, size, flags) = (a[2], a[3], a[4]);
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    if size > PAGE_SIZE {
        return Err(E2BIG);
    }
    if size < FILE_ATTR_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let target = Target::at(c, [a[0], a[1], flags], true)?;
    let current = current(&|f: &mut dyn FnMut(&mut u32)| target.with_attributes(c, f))?;
    let mut out = vec![0; size as usize];
    out[..8].copy_from_slice(&u64::from(xflags_of(current)).to_le_bytes());
    output(c, addr, &out)?;
    Ok(0)
}

/// `file_setattr(dfd, path, attr, size, at_flags)`: the flags (EINVAL),
/// the struct (`copy_struct_from_user`), its flags (EINVAL for one Linux
/// does not know), then the file as `file_getattr` finds it and [`set`].
fn file_setattr(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (addr, size, flags) = (a[2], a[3], a[4]);
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    if size > PAGE_SIZE {
        return Err(E2BIG);
    }
    let attr = copy_struct(c, addr, size, FILE_ATTR_SIZE_VER0)?;
    let word = |at: usize| u32::from_le_bytes(attr[at..at + 4].try_into().unwrap_or([0; 4]));
    let xflags = u64::from_le_bytes(attr[..8].try_into().unwrap_or([0; 8]));
    if xflags & !u64::from(XFLAGS_MASK) != 0 {
        return Err(Errno::EINVAL);
    }
    let fa = Kattr {
        extsize: word(8),
        projid: word(16),
        cowextsize: word(20),
        ..Kattr::from_xflags(xflags as u32 & !XFLAG_RDONLY)
    };
    let target = Target::at(c, [a[0], a[1], flags], true)?;
    set(
        (&c.process.credentials, &c.files.caches.flagged),
        target.stat(),
        &|f: &mut dyn FnMut(&mut u32)| target.with_attributes(c, f),
        fa,
    )?;
    Ok(0)
}

/// The calls, `file_getattr` (468) and `file_setattr` (469).
pub(super) fn call(c: &Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    match n {
        468 => file_getattr(c, a),
        _ => file_setattr(c, a),
    }
}

/// The `FS_IOC_*` ioctls of `file`, or `None` for another command or a file
/// that keeps no flags, which the ioctl's other handlers then get (ENOTTY).
/// As Linux's `ioctl_setflags` and `ioctl_fssetxattr`, a change is read
/// and checked (EFAULT, EOPNOTSUPP for an unknown `FS_XFLAG_*`) before
/// the file is asked for its flags.
pub(crate) fn ioctl(
    c: &Context<'_>,
    file: &dyn FileHandle,
    cmd: u32,
    arg: u64,
) -> Option<Result<u64, Errno>> {
    let read = |size: usize| {
        let mut bytes = vec![0; size];
        c.mem
            .read(GuestAddr(arg), &mut bytes)
            .map_err(|_| Errno::EFAULT)?;
        Ok::<_, Errno>(bytes)
    };
    let word =
        |b: &[u8], i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
    let change = match cmd {
        FS_IOC_GETFLAGS | FS_IOC_FSGETXATTR => None,
        FS_IOC_SETFLAGS => match read(4) {
            Ok(b) => Some(Kattr::from_flags(word(&b, 0))),
            Err(e) => return Some(Err(e)),
        },
        FS_IOC_FSSETXATTR => {
            let b = match read(FSXATTR_SIZE) {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            let xflags = word(&b, 0);
            if xflags & !XFLAGS_MASK != 0 {
                return Some(Err(Errno::EOPNOTSUPP));
            }
            Some(Kattr {
                extsize: word(&b, 1),
                nextents: word(&b, 2),
                projid: word(&b, 3),
                cowextsize: word(&b, 4),
                ..Kattr::from_xflags(xflags & !XFLAG_RDONLY)
            })
        }
        _ => return None,
    };
    let with = |f: &mut dyn FnMut(&mut u32)| file.with_attributes(f);
    let current = match current(&with) {
        Err(Errno::EOPNOTSUPP) => return None,
        other => other,
    };
    Some((|| {
        let current = current?;
        match (cmd, change) {
            (_, Some(fa)) => set(
                (&c.process.credentials, &c.files.caches.flagged),
                &file.stat()?,
                &with,
                fa,
            )?,
            (FS_IOC_GETFLAGS, None) => output(c, arg, &current.to_le_bytes())?,
            _ => {
                let mut out = [0; FSXATTR_SIZE];
                out[..4].copy_from_slice(&xflags_of(current).to_le_bytes());
                output(c, arg, &out)?;
            }
        }
        Ok(0)
    })())
}
