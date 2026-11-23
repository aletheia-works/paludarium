//! What the BPF file system's inodes do (Linux's `kernel/bpf/inode.c`):
//! `BPF_OBJ_PIN` leaves a map in a file there and `BPF_OBJ_GET` takes a
//! descriptor of it again (`bpf_obj_pin_user`, `bpf_obj_get_user`); its
//! directories make no files but those, directories and symbolic links
//! (`bpf_dir_iops`), and look up no name with a dot that is not there
//! (`bpf_lookup`). A mount of it is [`crate::mounts`]'.
use paludarium_types::Errno;

use crate::syscalls::Context;

/// `AT_FDCWD`.
const AT_FDCWD: u64 = -100i64 as u64;
/// `BPF_F_PATH_FD`: `path_fd` is the directory the path starts from.
const F_PATH_FD: u32 = 1 << 14;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

/// Where the path at `p` (from the machine's root) is in a BPF file
/// system's files, none when it is not in one.
fn on_bpffs(c: &Context<'_>, p: &[u8], follow: bool) -> Option<paludarium_vfs::MemoryAt> {
    c.files
        .namespaced()
        .memory_at(p, follow)
        .ok()
        .flatten()
        .filter(|at| at.kind == "bpf")
}

/// Whether the path at `p` is in a BPF file system.
pub(crate) fn holds(c: &Context<'_>, p: &[u8], follow: bool) -> bool {
    on_bpffs(c, p, follow).is_some()
}

/// `p`'s directory and its last name.
fn split(p: &[u8]) -> (Vec<u8>, &[u8]) {
    let p = p.strip_suffix(b"/").unwrap_or(p);
    match p.iter().rposition(|&b| b == b'/') {
        Some(0) => (b"/".to_vec(), &p[1..]),
        Some(at) => (p[..at].to_vec(), &p[at + 1..]),
        None => (b"/".to_vec(), p),
    }
}

/// `bpf_lookup`: in a BPF file system's directory with any mode bits
/// (`S_IALLUGO`, whoever looks), a name with a dot that is not there is
/// `EPERM`, as it keeps such names for itself.
pub(crate) fn lookup(c: &Context<'_>, p: &[u8]) -> Result<(), Errno> {
    let (dir, name) = split(p);
    if name == b"." || name == b".." || !name.contains(&b'.') {
        return Ok(());
    }
    if c.files.fs().metadata(p, false).is_ok() || on_bpffs(c, &dir, true).is_none() {
        return Ok(());
    }
    // A directory of mode 0 takes the name as any other, and one not
    // there is the walk's own error (`ENOENT`), before any lookup in it.
    if c.files
        .fs()
        .metadata(&dir, true)
        .map_or(true, |d| d.mode & 0o7777 == 0)
    {
        return Ok(());
    }
    // The walk to the directory comes first: a directory the thread may
    // not search is the call's own error (`EACCES`), not this one.
    if crate::permissions::search(c.files, &c.process.credentials, AT_FDCWD, p, false).is_err() {
        return Ok(());
    }
    Err(Errno::EPERM)
}

/// What a BPF file system refuses of an open at `p` with `flags`: an
/// unnamed file in one of its directories (`EOPNOTSUPP`, as for no
/// `tmpfile`) and a new regular file (`EACCES`, as for no `create`).
pub(crate) fn may_open(c: &Context<'_>, p: &[u8], flags: u32) -> Result<(), Errno> {
    const O_CREAT: u32 = 0o100;
    const O_TMPFILE: u32 = 0o20000000;
    if flags & O_TMPFILE != 0 {
        if on_bpffs(c, p, true).is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
    } else if flags & O_CREAT != 0
        && c.files.fs().metadata(p, true).is_err()
        && makes_no_files(c, p)
    {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Whether the directory that would hold the new name `p` is a BPF file
/// system's, whose `bpf_dir_iops` make no file of another kind: no regular
/// one (`EACCES`, as for no `create`), no node (`EPERM`, as for no
/// `mknod`) and no unnamed one (`EOPNOTSUPP`, as for no `tmpfile`).
pub(crate) fn makes_no_files(c: &Context<'_>, p: &[u8]) -> bool {
    on_bpffs(c, &split(p).0, true).is_some()
}

/// The `path_fd` of a `BPF_OBJ` attribute, for `file_flags` (`EINVAL` for
/// one without `BPF_F_PATH_FD`).
fn path_dir(file_flags: u32, path_fd: u32) -> Result<u64, Errno> {
    if file_flags & F_PATH_FD == 0 {
        if path_fd != 0 {
            return Err(Errno::EINVAL);
        }
        return Ok(AT_FDCWD);
    }
    Ok(i64::from(path_fd as i32) as u64)
}

/// `BPF_OBJ_PIN`, as Linux's `bpf_obj_pin` and `bpf_obj_do_pin`: no flag
/// but `BPF_F_PATH_FD` (`EINVAL`), a map's descriptor (`EINVAL` for
/// anything else), then a new name (`EEXIST`, or `ENOENT` with a slash
/// after it) on a writable mount (`EROFS`) in a BPF file system's
/// directory (`EPERM`), which the thread may write and search (`EACCES`):
/// a regular file of mode 0600 less the umask, the thread's, that holds
/// the map.
pub(crate) fn pin(
    c: &mut Context<'_>,
    pathname: u64,
    fd: u32,
    file_flags: u32,
    path_fd: u32,
) -> Result<u64, Errno> {
    if file_flags & !F_PATH_FD != 0 {
        return Err(Errno::EINVAL);
    }
    let dir = path_dir(file_flags, path_fd)?;
    // `bpf_fd_probe_obj`: a map, a program or a link; here only maps.
    let map = crate::bpf::pinnable(c, fd).ok_or(Errno::EINVAL)?;
    let raw = crate::files::path(c, pathname)?;
    let creds = &c.process.credentials;
    let found = crate::permissions::search(c.files, creds, dir, &raw, false)?;
    let p = c.files.named(dir, raw.clone())?;
    let (_, name) = split(&raw);
    if name == b"." || name == b".." {
        return Err(Errno::EEXIST);
    }
    lookup(c, &p)?;
    if c.files.fs().metadata(&p, false).is_ok() {
        return Err(Errno::EEXIST);
    }
    if raw.last() == Some(&b'/') {
        return Err(Errno::ENOENT);
    }
    // The directory must be there for the checks after it.
    c.files.fs().metadata(&split(&p).0, true)?;
    crate::permissions::want_write_new(c.files, dir, &raw, false)?;
    let Some(at) = on_bpffs(c, &p, false) else {
        return Err(Errno::EPERM);
    };
    crate::files::landlock_name(c, &p, crate::landlock::MAKE_REG)?;
    if let Some(parent) = &found.parent {
        crate::permissions::may_create(creds, parent)?;
    }
    let mode = 0o600 & !c.files.umask();
    at.fs.make_object(&at.path, mode, map)?;
    if let Some(parent) = &found.parent {
        crate::permissions::own(c.files, creds, &p, false, parent);
    } else {
        let group = c
            .files
            .fs()
            .metadata(&split(&p).0, true)
            .ok()
            .filter(|d| d.mode & 0o2000 == 0)
            .map(|_| creds.fsgid);
        let _ = crate::inotify::unnoticed(|| {
            c.files.fs().set_owner(&p, false, Some(creds.fsuid), group)
        });
    }
    c.files.caches.notify.created(&*c.files.namespaced(), &p);
    Ok(0)
}

/// `BPF_OBJ_GET`, as Linux's `bpf_obj_get` and `bpf_obj_do_get`: no
/// descriptor and no flag but the access and `BPF_F_PATH_FD` (`EINVAL`),
/// one access (`EINVAL`), then the file at the path, its links followed,
/// which the thread may open for that access (`EACCES`) and which holds a
/// map (`EACCES` for any other file): a new descriptor of it with that
/// access.
pub(crate) fn get(
    c: &mut Context<'_>,
    pathname: u64,
    fd: u32,
    file_flags: u32,
    path_fd: u32,
) -> Result<u64, Errno> {
    const OBJ_FLAGS: u32 = crate::bpf::flag::RDONLY | crate::bpf::flag::WRONLY;
    if fd != 0 || file_flags & !(OBJ_FLAGS | F_PATH_FD) != 0 {
        return Err(Errno::EINVAL);
    }
    let dir = path_dir(file_flags, path_fd)?;
    let access = crate::bpf::file_access(file_flags)?;
    let raw = crate::files::path(c, pathname)?;
    let p = c.files.path(dir, raw.clone())?;
    lookup(c, &p)?;
    let creds = &c.process.credentials;
    crate::permissions::search(c.files, creds, dir, &raw, true)?;
    let stat = c.files.fs().metadata(&p, true)?;
    // `path_permission` for ACC_MODE of the access.
    let mask = match access {
        0 => crate::permissions::MAY_READ,
        1 => crate::permissions::MAY_WRITE,
        _ => crate::permissions::MAY_READ | crate::permissions::MAY_WRITE,
    };
    crate::permissions::permission(creds, &stat, mask)?;
    let object = match on_bpffs(c, &p, true) {
        Some(at) if stat.mode & S_IFMT == S_IFREG => at.fs.object(&at.path, true)?,
        _ => None,
    };
    let map = object
        .and_then(|object| object.downcast::<crate::bpf::Map>().ok())
        .ok_or(Errno::EACCES)?;
    crate::bpf::map_fd(c, map, access)
}
