//! Extended attributes, as Linux's `fs/xattr.c` handles them. They are kept
//! with a file in memory; what holds no attributes, as a mounted host
//! directory, behaves as a file system without them.
use super::{Followed, O_PATH, generated_stat, looked_up, output};
use crate::credentials::Credentials;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat, Xattrs};
use paludarium_types::{Errno, GuestAddr};
use std::sync::Arc;

const E2BIG: Errno = Errno(7);
const ERANGE: Errno = Errno(34);
const ENODATA: Errno = Errno(61);
const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: u64 = 65536;
const XATTR_LIST_MAX: u64 = 65536;
const NAMESPACES: [&[u8]; 3] = [b"user.", b"trusted.", b"security."];
const MAY_READ: u32 = 4;
const MAY_WRITE: u32 = 2;

/// What a call works on, found before its name and value are looked at.
enum Target {
    Path {
        path: Vec<u8>,
        follow: bool,
        stat: FileStat,
    },
    File {
        file: Arc<dyn FileHandle>,
        stat: FileStat,
    },
    /// A file the kernel makes up, as under `/proc`: it holds none.
    Generated { stat: FileStat },
}
impl Target {
    fn at_path(c: &Context<'_>, ptr: u64, follow: bool) -> Result<Self, Errno> {
        let (path, found) = looked_up(c, (-100i32) as u64, ptr, follow)?;
        // A link in `/proc/self/fd` leads to the descriptor's file, whatever
        // its access, as an `O_PATH` one has none.
        match super::followed(c, &path, follow)? {
            Some(Followed::Path { path, follow }) => return Self::found(c, path, follow, None),
            Some(Followed::File(d)) => {
                let stat = d.file.stat()?;
                return Ok(Self::File { file: d.file, stat });
            }
            None => {}
        }
        Self::found(c, path, follow, found.file)
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
            None => c.files.fs.metadata(&path, follow)?,
        };
        if super::in_proc(&path) {
            return Ok(Self::Generated { stat });
        }
        Ok(Self::Path { path, follow, stat })
    }
    fn at_descriptor(c: &Context<'_>, fd: u64) -> Result<Self, Errno> {
        let file = c.files.descriptor(fd)?.file;
        if file.flags() & O_PATH != 0 {
            return Err(Errno::EBADF);
        }
        let stat = file.stat()?;
        Ok(Self::File { file, stat })
    }
    fn stat(&self) -> &FileStat {
        match self {
            Self::Path { stat, .. } | Self::File { stat, .. } | Self::Generated { stat } => stat,
        }
    }
    /// Runs `f` on the attributes; `EOPNOTSUPP` if it holds none.
    fn with(&self, c: &Context<'_>, f: &mut dyn FnMut(&mut Xattrs)) -> Result<(), Errno> {
        match self {
            Self::Path { path, follow, .. } => c.files.fs.with_xattrs(path, *follow, f),
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

/// `xattr_permission`, then what `cap_inode_setxattr` asks of a change.
fn permitted(creds: &Credentials, stat: &FileStat, name: &[u8], write: bool) -> Result<(), Errno> {
    let refused = if write { Errno::EPERM } else { ENODATA };
    if name.starts_with(b"trusted.") && !creds.may_administer() {
        return Err(refused);
    }
    let kind = stat.mode & 0o170000;
    if name.starts_with(b"user.") && kind != 0o100000 && kind != 0o040000 {
        return Err(refused);
    }
    let mask = if write { MAY_WRITE } else { MAY_READ };
    crate::permissions::permission(creds, stat, mask)?;
    if write && name.starts_with(b"security.") && !creds.may_administer() {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn get(c: &Context<'_>, target: &Target, ptr: u64, addr: u64, size: u64) -> Result<u64, Errno> {
    let name = name(c, ptr)?;
    permitted(&c.process.credentials, target.stat(), &name, false)?;
    namespace(&name)?;
    let value = target
        .read(c, |map| map.get(&name).cloned(), None)?
        .ok_or(ENODATA)?;
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
    permitted(&c.process.credentials, target.stat(), &name, true)?;
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

fn remove(c: &Context<'_>, target: &Target, ptr: u64) -> Result<u64, Errno> {
    let name = name(c, ptr)?;
    permitted(&c.process.credentials, target.stat(), &name, true)?;
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

/// The calls, with `n` from 188 to 199.
pub(super) fn call(c: &Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    match n {
        188 | 189 => set(
            c,
            |c| Target::at_path(c, a[0], n == 188),
            [a[1], a[2], a[3], a[4]],
        ),
        190 => {
            let target = Target::at_descriptor(c, a[0])?;
            set(c, |_| Ok(target), [a[1], a[2], a[3], a[4]])
        }
        191 | 192 => get(c, &Target::at_path(c, a[0], n == 191)?, a[1], a[2], a[3]),
        193 => get(c, &Target::at_descriptor(c, a[0])?, a[1], a[2], a[3]),
        194 | 195 => list(c, &Target::at_path(c, a[0], n == 194)?, a[1], a[2]),
        196 => list(c, &Target::at_descriptor(c, a[0])?, a[1], a[2]),
        197 | 198 => remove(c, &Target::at_path(c, a[0], n == 197)?, a[1]),
        _ => remove(c, &Target::at_descriptor(c, a[0])?, a[1]),
    }
}
