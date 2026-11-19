//! Extended attributes, as Linux's `fs/xattr.c` handles them. They are kept
//! with a file in memory; what holds no attributes, as a mounted host
//! directory, behaves as a file system without them.
use super::{Followed, O_PATH, copy_struct, generated_stat, lookup, output, path};
use crate::credentials::Credentials;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat, Xattrs};
use paludarium_types::{Errno, GuestAddr};
use std::sync::{Arc, PoisonError};

const E2BIG: Errno = Errno(7);
const ERANGE: Errno = Errno(34);
const ENODATA: Errno = Errno(61);
const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: u64 = 65536;
const XATTR_LIST_MAX: u64 = 65536;
const NAMESPACES: [&[u8]; 3] = [b"user.", b"trusted.", b"security."];
use crate::permissions::CAPS;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 1;
const CAP_SETFCAP: u64 = 1 << 31;
const MAY_READ: u32 = 4;
const MAY_WRITE: u32 = 2;
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
/// The size of `struct xattr_args` (`value`, `size`, `flags`) in its first
/// version, `XATTR_ARGS_SIZE_VER0`.
const XATTR_ARGS_SIZE_VER0: u64 = 16;

/// What a call works on, found before its name and value are looked at.
pub(super) enum Target {
    Path {
        path: Vec<u8>,
        follow: bool,
        stat: FileStat,
    },
    /// A descriptor's file, opened at `path`.
    File {
        file: Arc<dyn FileHandle>,
        path: Vec<u8>,
        stat: FileStat,
    },
    /// A file the kernel makes up, as under `/proc`: it holds none.
    Generated { stat: FileStat },
}
impl Target {
    fn at_path(c: &Context<'_>, ptr: u64, follow: bool) -> Result<Self, Errno> {
        Self::at_name(c, AT_FDCWD as u64, path(c, ptr)?, follow)
    }
    /// What the path `raw` names from directory `dir`.
    fn at_name(c: &Context<'_>, dir: u64, raw: Vec<u8>, follow: bool) -> Result<Self, Errno> {
        let (path, found) = lookup(c, dir, raw, follow)?;
        // A link in `/proc/self/fd` leads to the descriptor's file, whatever
        // its access, as an `O_PATH` one has none.
        match super::followed(c, &path, follow)? {
            Some(Followed::Path { path, follow }) => return Self::found(c, path, follow, None),
            Some(Followed::File(d)) => {
                let stat = d.file.stat()?;
                return Ok(Self::File {
                    file: d.file,
                    path: d.path,
                    stat,
                });
            }
            None => {}
        }
        Self::found(c, path, follow, found.file)
    }
    /// What the `*xattrat` calls work on, as Linux's `path_*xattrat` finds
    /// it: the path at `ptr` from `dir`, the last symbolic link itself with
    /// `AT_SYMLINK_NOFOLLOW`. With `AT_EMPTY_PATH`, a null or empty path
    /// (`getname_maybe_null`) is descriptor `dir`'s file (EBADF if it has
    /// none, or only `O_PATH`). Only `setxattrat` and `getxattrat` take a
    /// negative `dir` as a directory to walk no further from: the working
    /// directory for `AT_FDCWD`, and EBADF for any other.
    pub(super) fn at(
        c: &Context<'_>,
        [dir, ptr, flags]: [u64; 3],
        walks: bool,
    ) -> Result<Self, Errno> {
        let raw = if flags & AT_EMPTY_PATH == 0 {
            Some(path(c, ptr)?)
        } else if ptr == 0 {
            None
        } else {
            Some(path(c, ptr)?).filter(|raw| !raw.is_empty())
        };
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        match raw {
            Some(raw) => Self::at_name(c, dir, raw, follow),
            None if !walks || dir as i64 >= 0 => Self::at_descriptor(c, dir),
            None if dir as i64 == i64::from(AT_FDCWD) => {
                let cwd = c
                    .files
                    .cwd
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                Self::found(c, cwd, follow, None)
            }
            None => Err(Errno::EBADF),
        }
    }
    /// The file at `path`, of which a walk to it may have given the status.
    fn found(
        c: &Context<'_>,
        path: Vec<u8>,
        follow: bool,
        walked: Option<FileStat>,
    ) -> Result<Self, Errno> {
        if let Some((stat, ..)) = generated_stat(c, &path, follow)? {
            return Ok(Self::Generated { stat });
        }
        // A walk leaves out the last name's status when it does not need it.
        let stat = match walked {
            Some(stat) => stat,
            None => match c.files.fs().metadata(&path, follow) {
                // A link on the way to a file the kernel generates.
                Err(e) => {
                    let target = super::generated_target(c, &path, follow, e)?;
                    return Self::found(c, target, follow, None);
                }
                Ok(stat) => stat,
            },
        };
        if super::in_proc(&path) {
            return Ok(Self::Generated { stat });
        }
        Ok(Self::Path { path, follow, stat })
    }
    fn at_descriptor(c: &Context<'_>, fd: u64) -> Result<Self, Errno> {
        let d = c.files.descriptor(fd)?;
        if d.file.flags() & O_PATH != 0 {
            return Err(Errno::EBADF);
        }
        let stat = d.file.stat()?;
        Ok(Self::File {
            file: d.file,
            path: d.path,
            stat,
        })
    }
    /// `mnt_want_write` of its mount: `EROFS` on a read-only one.
    pub(super) fn want_write(&self, c: &Context<'_>) -> Result<(), Errno> {
        match self {
            Self::Path { path, follow, .. } => {
                crate::permissions::want_write(c.files, path, *follow)
            }
            Self::File { path, .. } => crate::permissions::want_write(c.files, path, false),
            Self::Generated { .. } => Ok(()),
        }
    }
    pub(super) fn stat(&self) -> &FileStat {
        match self {
            Self::Path { stat, .. } | Self::File { stat, .. } | Self::Generated { stat } => stat,
        }
    }
    /// Runs `f` on the inode flags; `EOPNOTSUPP` if it keeps none.
    pub(super) fn with_attributes(
        &self,
        c: &Context<'_>,
        f: &mut dyn FnMut(&mut u32),
    ) -> Result<(), Errno> {
        match self {
            Self::Path { path, follow, .. } => c.files.fs().with_attributes(path, *follow, f),
            Self::File { file, .. } => file.with_attributes(f),
            Self::Generated { .. } => Err(Errno::EOPNOTSUPP),
        }
    }
    /// Runs `f` on the attributes; `EOPNOTSUPP` if it holds none.
    fn with(&self, c: &Context<'_>, f: &mut dyn FnMut(&mut Xattrs)) -> Result<(), Errno> {
        match self {
            Self::Path { path, follow, .. } => c.files.fs().with_xattrs(path, *follow, f),
            Self::File { file, .. } => file.with_xattrs(f),
            Self::Generated { .. } => Err(Errno::EOPNOTSUPP),
        }
    }
    /// The attributes, of which a file that holds none has no value.
    fn read<T>(&self, c: &Context<'_>, f: impl Fn(&Xattrs) -> T, none: T) -> Result<T, Errno> {
        let mut out = None;
        match self.with(c, &mut |map| out = Some(f(map))) {
            Err(Errno::EOPNOTSUPP) => Ok(none),
            Err(e) => Err(e),
            Ok(()) => out.ok_or(Errno::EIO),
        }
    }
}

/// `import_xattr_name`: from 1 to 255 bytes, or `ERANGE`.
fn name(c: &Context<'_>, ptr: u64) -> Result<Vec<u8>, Errno> {
    let mut name = Vec::new();
    loop {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(ptr.wrapping_add(name.len() as u64)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
        if name.len() == XATTR_NAME_MAX {
            return Err(ERANGE);
        }
        name.push(byte[0]);
    }
    if name.is_empty() {
        return Err(ERANGE);
    }
    Ok(name)
}

/// `xattr_resolve_name`: a namespace this file system has, with a name in it.
fn namespace(name: &[u8]) -> Result<(), Errno> {
    match NAMESPACES.iter().find(|n| name.starts_with(n)) {
        Some(n) if name.len() == n.len() => Err(Errno::EINVAL),
        Some(_) => Ok(()),
        None => Err(Errno::EOPNOTSUPP),
    }
}

/// `xattr_permission`: `security.*` and `system.*` are left to the security
/// module and the file system, `trusted.*` needs `CAP_SYS_ADMIN`, and
/// `user.*` is for regular files and directories, whose access it needs; in
/// a sticky directory only its owner or a caller with `CAP_FOWNER` may
/// change them.
fn permitted(creds: &Credentials, stat: &FileStat, name: &[u8], write: bool) -> Result<(), Errno> {
    // `may_write_xattr`: not an immutable or append-only file (EPERM).
    if write {
        super::attributes::unchangeable(stat)?;
    }
    if name.starts_with(b"security.") || name.starts_with(b"system.") {
        return Ok(());
    }
    let refused = if write { Errno::EPERM } else { ENODATA };
    if name.starts_with(b"trusted.") && !creds.may_administer() {
        return Err(refused);
    }
    let kind = stat.mode & 0o170000;
    if name.starts_with(b"user.") {
        if kind != 0o100000 && kind != 0o040000 {
            return Err(refused);
        }
        if kind == 0o040000
            && stat.mode & 0o1000 != 0
            && write
            && !crate::permissions::owner_or_capable(creds, stat)
        {
            return Err(Errno::EPERM);
        }
    }
    let mask = if write { MAY_WRITE } else { MAY_READ };
    crate::permissions::permission(creds, stat, mask)
}

/// What the capability module asks of a change to a `security.*`
/// attribute (`cap_inode_setxattr`, `cap_inode_removexattr`): `CAP_SYS_ADMIN`,
/// but for the file capabilities, which `cap_convert_nscap` checks as they
/// are written and which need `CAP_SETFCAP` over the file to be removed.
fn security_permitted(
    creds: &Credentials,
    stat: &FileStat,
    name: &[u8],
    remove: bool,
) -> Result<(), Errno> {
    if !name.starts_with(b"security.") {
        return Ok(());
    }
    let allowed = if name == CAPS {
        !remove || crate::permissions::capable(creds, stat, CAP_SETFCAP)
    } else {
        creds.may_administer()
    };
    if allowed { Ok(()) } else { Err(Errno::EPERM) }
}

/// The revision of a `struct vfs_cap_data` (or `vfs_ns_cap_data`) value:
/// 2 or 3 for one of that revision's size whose magic names it, whatever
/// its effective flag (`is_v2header`, `is_v3header`).
fn revision(value: &[u8]) -> Option<u32> {
    let revision = match value.len() {
        20 => VFS_CAP_REVISION_2,
        24 => VFS_CAP_REVISION_3,
        _ => return None,
    };
    let magic = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    (magic & !VFS_CAP_FLAGS_EFFECTIVE == revision).then_some(revision)
}

/// `value`'s capabilities as a value of `revision`, the effective flag kept,
/// with `root` as the root ID of a revision 3 one.
fn capabilities(value: &[u8], revision: u32, root: u32) -> Vec<u8> {
    let magic = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    let mut out = (revision | magic & VFS_CAP_FLAGS_EFFECTIVE)
        .to_le_bytes()
        .to_vec();
    out.extend_from_slice(&value[4..20]);
    if revision == VFS_CAP_REVISION_3 {
        out.extend_from_slice(&root.to_le_bytes());
    }
    out
}

/// `cap_convert_nscap`: a value of file capabilities as it is written. It
/// must be of revision 2 or 3 (`EINVAL`), and the caller needs
/// `CAP_SETFCAP` in a user namespace that maps the file's owner and group
/// (`EPERM`). One with `CAP_SETFCAP` over the file system's namespace (the
/// first) keeps a revision 2 value; any other value becomes a revision 3 one
/// whose root is the kernel ID of the root it names in the caller's
/// namespace (0 for revision 2), which that namespace must map (`EINVAL`).
fn written_capabilities(
    creds: &Credentials,
    stat: &FileStat,
    value: Vec<u8>,
) -> Result<Vec<u8>, Errno> {
    let Some(revision) = revision(&value) else {
        return Err(Errno::EINVAL);
    };
    if !crate::permissions::capable(creds, stat, CAP_SETFCAP) {
        return Err(Errno::EPERM);
    }
    if revision == VFS_CAP_REVISION_2 && creds.capable(CAP_SETFCAP) {
        return Ok(value);
    }
    let root = if revision == VFS_CAP_REVISION_3 {
        u32::from_le_bytes([value[20], value[21], value[22], value[23]])
    } else {
        0
    };
    let root = creds
        .user
        .kernel_of(crate::users::Ids::User, root)
        .ok_or(Errno::EINVAL)?;
    Ok(capabilities(&value, VFS_CAP_REVISION_3, root))
}

/// `cap_inode_getsecurity`: the stored file capabilities as the caller's
/// user namespace reads them. A root that it maps to an ID other than 0
/// gives a revision 3 value with that ID; a root that is root there or in a
/// namespace above gives a revision 2 one; any other root is `EOVERFLOW`,
/// and a stored value of neither revision `EINVAL`.
fn read_capabilities(creds: &Credentials, stored: &[u8]) -> Result<Vec<u8>, Errno> {
    let root = match revision(stored) {
        Some(VFS_CAP_REVISION_2) => 0,
        Some(_) => u32::from_le_bytes([stored[20], stored[21], stored[22], stored[23]]),
        None => return Err(Errno::EINVAL),
    };
    match creds.user.id_of(crate::users::Ids::User, root) {
        Some(mapped) if mapped != 0 => Ok(capabilities(stored, VFS_CAP_REVISION_3, mapped)),
        _ if creds.user.root_here_or_above(root) => Ok(capabilities(stored, VFS_CAP_REVISION_2, 0)),
        _ => Err(Errno::EOVERFLOW),
    }
}

/// `getxattr`: the name, then the file (as since Linux 6.13), then the value.
fn get(
    c: &Context<'_>,
    target: impl FnOnce(&Context<'_>) -> Result<Target, Errno>,
    [ptr, addr, size]: [u64; 3],
) -> Result<u64, Errno> {
    let name = name(c, ptr)?;
    let target = target(c)?;
    permitted(&c.process.credentials, target.stat(), &name, false)?;
    namespace(&name)?;
    let mut value = target
        .read(c, |map| map.get(&name).cloned(), None)?
        .ok_or(ENODATA)?;
    if name == CAPS {
        value = read_capabilities(&c.process.credentials, &value)?;
    }
    let length = value.len() as u64;
    if size != 0 {
        if length > size.min(XATTR_SIZE_MAX) {
            return Err(ERANGE);
        }
        output(c, addr, &value)?;
    }
    Ok(length)
}

fn list(c: &Context<'_>, target: &Target, addr: u64, size: u64) -> Result<u64, Errno> {
    let administers = c.process.credentials.may_administer();
    let names = target.read(
        c,
        |map| {
            let mut names = Vec::new();
            for name in map.keys() {
                if administers || !name.starts_with(b"trusted.") {
                    names.extend_from_slice(name);
                    names.push(0);
                }
            }
            names
        },
        Vec::new(),
    )?;
    let length = names.len() as u64;
    if size != 0 {
        // `listxattr` copies at most XATTR_LIST_MAX, and says so of a list
        // that does not fit a buffer of that size.
        if length > size.min(XATTR_LIST_MAX) {
            return Err(if size >= XATTR_LIST_MAX {
                E2BIG
            } else {
                ERANGE
            });
        }
        output(c, addr, &names)?;
    }
    Ok(length)
}

fn set(
    c: &Context<'_>,
    target: impl FnOnce(&Context<'_>) -> Result<Target, Errno>,
    [ptr, addr, size, flags]: [u64; 4],
) -> Result<u64, Errno> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = name(c, ptr)?;
    if size > XATTR_SIZE_MAX {
        return Err(E2BIG);
    }
    let mut value = vec![0; size as usize];
    c.mem
        .read(GuestAddr(addr), &mut value)
        .map_err(|_| Errno::EFAULT)?;
    let target = target(c)?;
    target.want_write(c)?;
    let creds = &c.process.credentials;
    // `vfs_setxattr` converts file capabilities before it checks anything
    // else of the change.
    if name == CAPS && !value.is_empty() {
        value = written_capabilities(creds, target.stat(), value)?;
    }
    permitted(creds, target.stat(), &name, true)?;
    security_permitted(creds, target.stat(), &name, false)?;
    namespace(&name)?;
    let mut result = Ok(0);
    target.with(c, &mut |map| {
        let there = map.contains_key(&name);
        if flags & XATTR_CREATE != 0 && there {
            result = Err(Errno::EEXIST);
        } else if flags & XATTR_REPLACE != 0 && !there {
            result = Err(ENODATA);
        } else {
            map.insert(name.clone(), value.clone());
            crate::inotify::xattrs_changed();
        }
    })?;
    result
}

/// `removexattr`: the name, then the file (as since Linux 6.13).
fn remove(
    c: &Context<'_>,
    target: impl FnOnce(&Context<'_>) -> Result<Target, Errno>,
    ptr: u64,
) -> Result<u64, Errno> {
    let name = name(c, ptr)?;
    let target = target(c)?;
    target.want_write(c)?;
    permitted(&c.process.credentials, target.stat(), &name, true)?;
    security_permitted(&c.process.credentials, target.stat(), &name, true)?;
    namespace(&name)?;
    let mut result = Err(ENODATA);
    target.with(c, &mut |map| {
        if map.remove(&name).is_some() {
            result = Ok(0);
            crate::inotify::xattrs_changed();
        }
    })?;
    result
}

/// `struct xattr_args` at `addr` of `size` bytes: its `value`, `size` and
/// `flags`.
fn args(c: &Context<'_>, addr: u64, size: u64) -> Result<[u64; 3], Errno> {
    let args = copy_struct(c, addr, size, XATTR_ARGS_SIZE_VER0)?;
    let field = |at: usize, width: usize| {
        let mut bytes = [0; 8];
        bytes[..width].copy_from_slice(&args[at..at + width]);
        u64::from_le_bytes(bytes)
    };
    Ok([field(0, 8), field(8, 4), field(12, 4)])
}

/// `at_flags` of the `*xattrat` calls: only these two, or `EINVAL`.
fn at_flags(flags: u64) -> Result<(), Errno> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The calls, with `n` from 188 to 199 (which, as since Linux 6.13, read a
/// name before they find the file), and `setxattrat` (463),
/// `getxattrat` (464), `listxattrat` (465) and `removexattrat` (466) of
/// Linux 6.13.
pub(super) fn call(c: &Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    let at = [a[0], a[1], a[2]];
    match n {
        188 | 189 => set(
            c,
            |c| Target::at_path(c, a[0], n == 188),
            [a[1], a[2], a[3], a[4]],
        ),
        190 => set(
            c,
            |c| Target::at_descriptor(c, a[0]),
            [a[1], a[2], a[3], a[4]],
        ),
        191 | 192 => get(
            c,
            |c| Target::at_path(c, a[0], n == 191),
            [a[1], a[2], a[3]],
        ),
        193 => get(c, |c| Target::at_descriptor(c, a[0]), [a[1], a[2], a[3]]),
        194 | 195 => list(c, &Target::at_path(c, a[0], n == 194)?, a[1], a[2]),
        196 => list(c, &Target::at_descriptor(c, a[0])?, a[1], a[2]),
        197 | 198 => remove(c, |c| Target::at_path(c, a[0], n == 197), a[1]),
        199 => remove(c, |c| Target::at_descriptor(c, a[0]), a[1]),
        463 => {
            let [value, size, flags] = args(c, a[4], a[5])?;
            at_flags(a[2])?;
            set(c, |c| Target::at(c, at, true), [a[3], value, size, flags])
        }
        464 => {
            let [value, size, flags] = args(c, a[4], a[5])?;
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            at_flags(a[2])?;
            get(c, |c| Target::at(c, at, true), [a[3], value, size])
        }
        465 => {
            at_flags(a[2])?;
            list(c, &Target::at(c, at, false)?, a[3], a[4])
        }
        _ => {
            at_flags(a[2])?;
            remove(c, |c| Target::at(c, at, false), a[3])
        }
    }
}
