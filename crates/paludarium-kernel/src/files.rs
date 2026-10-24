//! Linux x86-64 file ABI and descriptor table. All guest memory is checked.
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, HostFs, MemFs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
pub const NUMBERS: &[u64] = &[
    0, 2, 3, 4, 5, 6, 8, 17, 18, 19, 20, 21, 22, 32, 33, 72, 73, 74, 75, 76, 77, 79, 80, 81, 82,
    83, 84, 85, 86, 87, 88, 89, 90, 91, 95, 137, 138, 162, 217, 221, 257, 258, 262, 263, 264, 265,
    266, 267, 268, 269, 280, 292, 293, 295, 296, 439,
];
#[derive(Clone)]
pub(crate) struct Descriptor {
    pub(crate) file: Arc<dyn FileHandle>,
    path: Vec<u8>,
    cloexec: bool,
}
#[derive(Clone)]
pub struct Files {
    pub(crate) readiness: Arc<crate::events::ReadinessHub>,
    pub terminal_size: Option<(u16, u16)>,
    pub fs: Arc<dyn FileSystem>,
    pub(crate) fds: Arc<Mutex<BTreeMap<u32, Descriptor>>>,
    /// Numbers an unfinished open has taken, as Linux's alloc_fd marks them
    /// before the file exists: no allocation gets them and no lookup sees
    /// them. Shared exactly as `fds` is; locked after it.
    reserved: Arc<Mutex<BTreeSet<u32>>>,
    cwd: Arc<Mutex<Vec<u8>>>,
    /// Shared with the cwd: `CLONE_FS` shares both, as on Linux.
    umask: Arc<AtomicU32>,
}
impl Default for Files {
    fn default() -> Self {
        let fs = MemFs::new();
        let _ = fs.mkdir(b"/tmp", 0o1777);
        Self {
            readiness: Arc::default(),
            terminal_size: None,
            fs: Arc::new(fs),
            fds: Arc::new(Mutex::new(BTreeMap::new())),
            reserved: Arc::default(),
            cwd: Arc::new(Mutex::new(b"/".to_vec())),
            umask: Arc::new(AtomicU32::new(0o022)),
        }
    }
}
impl Files {
    pub(crate) fn set_current_directory(&mut self, path: &[u8]) -> Result<(), Errno> {
        let path = paludarium_vfs::normalize_path(path)?;
        if self.fs.metadata(&path, true)?.mode & 0o170000 != 0o040000 {
            return Err(Errno::ENOTDIR);
        }
        *self.cwd.lock().unwrap_or_else(PoisonError::into_inner) = path;
        Ok(())
    }
    pub(crate) fn release_descriptors(&mut self) {
        // Detach this worker's table reference without closing a table still
        // shared by live CLONE_FILES siblings.
        self.fds = Arc::new(Mutex::new(BTreeMap::new()));
        self.reserved = Arc::default();
    }
    pub(crate) fn umask(&self) -> u32 {
        self.umask.load(Ordering::SeqCst)
    }
    pub(crate) fn exec_path(&self, path: Vec<u8>) -> Result<Vec<u8>, Errno> {
        self.path((-100i32) as u64, path)
    }
    pub(crate) fn for_exec(&self) -> Self {
        let child = self.for_clone(false, false);
        child
            .fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, descriptor| !descriptor.cloexec);
        child
    }
    pub(crate) fn install(
        &mut self,
        file: Arc<dyn FileHandle>,
        cloexec: bool,
        limit: u64,
    ) -> Result<u32, Errno> {
        self.allocate(
            Descriptor {
                file,
                path: Vec::new(),
                cloexec,
            },
            0,
            limit,
        )
    }
    /// Installs a pair, as pipe and socketpair do: both descriptors or, with
    /// fewer than two free below `limit`, neither (EMFILE). One lock covers
    /// both, so no other thread sees only the first.
    pub(crate) fn install_pair(
        &mut self,
        files: [Arc<dyn FileHandle>; 2],
        cloexec: bool,
        limit: u64,
    ) -> Result<[u32; 2], Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let one = lowest_free(&fds, &reserved, 0, limit)?;
        let two = lowest_free(&fds, &reserved, one + 1, limit)?;
        for (n, file) in [one, two].into_iter().zip(files) {
            let path = Vec::new();
            fds.insert(
                n,
                Descriptor {
                    file,
                    path,
                    cloexec,
                },
            );
        }
        Ok([one, two])
    }
    /// Takes the lowest free number below `limit` (EMFILE otherwise) before
    /// a call such as open has any effect, as Linux's get_unused_fd_flags;
    /// [`Self::fill`] or [`Self::unreserve`] ends the reservation.
    pub(crate) fn reserve(&self, limit: u64) -> Result<u32, Errno> {
        let fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let n = lowest_free(&fds, &reserved, 0, limit)?;
        reserved.insert(n);
        Ok(n)
    }
    pub(crate) fn fill(&self, n: u32, d: Descriptor) {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        fds.insert(n, d);
        self.unreserve(n);
    }
    pub(crate) fn unreserve(&self, n: u32) {
        self.reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&n);
    }
    /// Puts `d` at `n`, closing what was there, as dup2 does; EBUSY when an
    /// unfinished open of another thread has taken `n`, as in Linux.
    pub(crate) fn replace(&self, n: u32, d: Descriptor) -> Result<(), Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        if reserved.contains(&n) {
            return Err(Errno(16));
        }
        fds.insert(n, d);
        Ok(())
    }
    pub fn with_host(host: Arc<dyn paludarium_host::Host>) -> Self {
        let files = Self::default();
        for channel in 0..3 {
            files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    channel,
                    Descriptor {
                        file: Arc::new(StandardFile {
                            host: Arc::clone(&host),
                            channel,
                        }),
                        path: Vec::new(),
                        cloexec: false,
                    },
                );
        }
        files
    }
    pub(crate) fn stdio_channel(&self, fd: u64) -> Result<Option<u32>, Errno> {
        Ok(self.descriptor(fd)?.file.stdio_channel())
    }
    pub fn uses_original_stdio(&self, fd: u64) -> bool {
        self.descriptor(fd)
            .ok()
            .and_then(|d| d.file.stdio_channel())
            == u32::try_from(fd).ok()
    }
    /// Gives `d` the lowest free number from `min`, which must be below the
    /// RLIMIT_NOFILE soft limit `limit` (EMFILE).
    fn allocate(&mut self, d: Descriptor, min: u32, limit: u64) -> Result<u32, Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let n = lowest_free(&fds, &reserved, min, limit)?;
        fds.insert(n, d);
        Ok(n)
    }
    pub(crate) fn descriptor(&self, fd: u64) -> Result<Descriptor, Errno> {
        self.fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&u32::try_from(fd).map_err(|_| Errno::EBADF)?)
            .cloned()
            .ok_or(Errno::EBADF)
    }
    fn path(&self, dir: u64, p: Vec<u8>) -> Result<Vec<u8>, Errno> {
        if p.is_empty() {
            return Err(Errno::ENOENT);
        }
        if p.first() == Some(&b'/') {
            return Ok(p);
        }
        let mut base = if dir as i32 == -100 {
            self.cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        } else {
            let d = self.descriptor(dir)?;
            if d.file.stat()?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            d.file.guest_path_hint().unwrap_or(d.path)
        };
        if base.last() != Some(&b'/') {
            base.push(b'/')
        }
        base.extend_from_slice(&p);
        Ok(base)
    }
    pub(crate) fn for_clone(&self, share_files: bool, share_fs: bool) -> Self {
        let mut child = self.clone();
        if !share_files {
            child.fds = Arc::new(Mutex::new(
                self.fds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
            child.reserved = Arc::default();
        }
        if !share_fs {
            child.cwd = Arc::new(Mutex::new(
                self.cwd
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
            child.umask = Arc::new(AtomicU32::new(self.umask.load(Ordering::SeqCst)));
        }
        child
    }
}
/// The lowest number from `min` with no descriptor or reservation, which
/// must be below the RLIMIT_NOFILE soft limit `limit` (EMFILE), as in Linux's
/// alloc_fd.
fn lowest_free(
    fds: &BTreeMap<u32, Descriptor>,
    reserved: &BTreeSet<u32>,
    min: u32,
    limit: u64,
) -> Result<u32, Errno> {
    let mut n = min;
    while fds.contains_key(&n) || reserved.contains(&n) {
        n = n.checked_add(1).ok_or(Errno::EMFILE)?;
    }
    if u64::from(n) < limit {
        Ok(n)
    } else {
        Err(Errno::EMFILE)
    }
}
fn path(c: &Context<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut b = Vec::new();
    for i in 0..4096 {
        let mut v = [0];
        c.mem
            .read(GuestAddr(addr.checked_add(i).ok_or(Errno::EFAULT)?), &mut v)
            .map_err(|_| Errno::EFAULT)?;
        if v[0] == 0 {
            return Ok(b);
        }
        b.push(v[0]);
    }
    Err(Errno::ENAMETOOLONG)
}
fn at(c: &Context<'_>, dir: u64, ptr: u64) -> Result<Vec<u8>, Errno> {
    c.files.path(dir, path(c, ptr)?)
}
/// `faccessat2(dirfd, path, mode, flags)`. The guest is root, so reading and
/// writing are always allowed and executing needs an execute bit (or a
/// directory), as Linux grants root.
fn access(c: &Context<'_>, dir: u64, ptr: u64, mode: u64, flags: u64) -> Result<u64, Errno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EACCESS: u64 = 0x200;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if mode & !7 != 0 || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let raw = path(c, ptr)?;
    let stat = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        c.files.descriptor(dir)?.file.stat()?
    } else {
        let p = c.files.path(dir, raw)?;
        match generated_stat(c, &p) {
            Some(stat) => stat,
            None => c.files.fs.metadata(&p, flags & AT_SYMLINK_NOFOLLOW == 0)?,
        }
    };
    let directory = stat.mode & 0o170000 == 0o040000;
    if mode & 1 != 0 && !directory && stat.mode & 0o111 == 0 {
        return Err(Errno(13)); // EACCES
    }
    Ok(0)
}
/// What `fstatfs` reports for a pipe or a socket: an empty pseudo filesystem.
fn pseudo_fs(kind: u64) -> paludarium_host::FsStats {
    paludarium_host::FsStats {
        kind,
        block_size: 4096,
        name_max: 255,
        ..Default::default()
    }
}
/// Linux's 120-byte `struct statfs`. `f_flags` is ST_VALID and `f_fsid` 0.
fn write_statfs(c: &Context<'_>, addr: u64, s: paludarium_host::FsStats) -> Result<u64, Errno> {
    let mut b = [0u8; 120];
    for (i, v) in [
        s.kind,
        s.block_size,
        s.blocks,
        s.blocks_free,
        s.blocks_available,
        s.files,
        s.files_free,
        0, // f_fsid
        s.name_max,
        s.block_size, // f_frsize
        0x20,         // f_flags: ST_VALID
    ]
    .iter()
    .enumerate()
    {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    output(c, addr, &b)?;
    Ok(0)
}
const UTIME_NOW: u64 = (1 << 30) - 1;
const UTIME_OMIT: u64 = (1 << 30) - 2;
/// `utimensat(dirfd, path, times, flags)`, in the order Linux checks it.
fn utimensat(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    let now = || c.host.clock(ClockId::Realtime).map(i128::from);
    let (atime, mtime) = if a[2] == 0 {
        let now = now()?;
        (Some(now), Some(now))
    } else {
        let mut raw = [0u8; 32];
        c.mem
            .read(GuestAddr(a[2]), &mut raw)
            .map_err(|_| Errno::EFAULT)?;
        let field =
            |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        let mut times = [None, None];
        for (slot, i) in times.iter_mut().zip([0, 2]) {
            let (seconds, nanos) = (field(i) as i64, field(i + 1));
            *slot = match nanos {
                UTIME_OMIT => None,
                UTIME_NOW => Some(now()?),
                0..1_000_000_000 => Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos)),
                _ => return Err(Errno::EINVAL),
            };
        }
        // Linux: "Nothing to do, we must not even check the path."
        if times == [None, None] {
            return Ok(0);
        }
        (times[0], times[1])
    };
    if a[3] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    // A null path with a descriptor is futimens.
    let descriptor = if a[1] == 0 && a[0] as i32 != -100 {
        if a[3] != 0 {
            return Err(Errno::EINVAL);
        }
        true
    } else {
        a[3] & AT_EMPTY_PATH != 0 && path(c, a[1])?.is_empty()
    };
    if descriptor {
        let file = c.files.descriptor(a[0])?.file;
        return file.set_times(atime, mtime).map(|()| 0);
    }
    let p = at(c, a[0], a[1])?;
    let follow = a[3] & AT_SYMLINK_NOFOLLOW == 0;
    c.files.fs.set_times(&p, follow, atime, mtime).map(|()| 0)
}
fn output(c: &Context<'_>, addr: u64, b: &[u8]) -> Result<(), Errno> {
    c.mem.write(GuestAddr(addr), b).map_err(|_| Errno::EFAULT)
}
/// Linux's largest single read or write (`MAX_RW_COUNT`).
const MAX_RW_COUNT: usize = 0x7fff_f000;
/// The file a positioned read or write uses, checked in Linux's order: a
/// negative offset (EINVAL), the descriptor (EBADF), a file without a
/// position such as a pipe or socket (ESPIPE), then the access mode (EBADF).
fn positioned(
    c: &Context<'_>,
    fd: u64,
    offset: u64,
    write: bool,
) -> Result<Arc<dyn FileHandle>, Errno> {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = c.files.descriptor(fd)?.file;
    file.seek(0, 1).map_err(|_| Errno::ESPIPE)?;
    if file.flags() & 3 == if write { 0 } else { 1 } {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// The bytes to transfer for a request of `count` at `offset`: at most
/// `MAX_RW_COUNT`, and for a read of a regular file no more than it holds.
/// An end past the largest offset is EINVAL, and reading a directory EISDIR.
fn request(
    file: &Arc<dyn FileHandle>,
    count: u64,
    offset: u64,
    read: bool,
) -> Result<usize, Errno> {
    if (count as i64) < 0
        || offset
            .checked_add(count)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(Errno::EINVAL);
    }
    let len = usize::try_from(count)
        .map_err(|_| Errno::EINVAL)?
        .min(MAX_RW_COUNT);
    if !read {
        return Ok(len);
    }
    let metadata = file.stat()?;
    match metadata.mode & 0o170000 {
        0o040000 => Err(Errno::EISDIR),
        // Saturating, so a remainder past usize (wasm32) does not wrap.
        0o100000 => Ok(
            len.min(usize::try_from(metadata.size.saturating_sub(offset)).unwrap_or(usize::MAX))
        ),
        _ => Ok(len),
    }
}
fn buffer(len: usize) -> Result<Vec<u8>, Errno> {
    let mut b = Vec::new();
    b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    b.resize(len, 0);
    Ok(b)
}
/// A positioned read; a file kind without `read_at` reads through its
/// position, which is then put back.
fn read_at(file: &Arc<dyn FileHandle>, offset: u64, b: &mut [u8]) -> Result<usize, Errno> {
    match file.read_at(offset, b) {
        Err(e) if e == Errno::ENODEV => {
            let position = file.seek(0, 1)?;
            file.seek(offset as i64, 0)?;
            let result = file.read(b);
            file.seek(position as i64, 0)?;
            result
        }
        result => result,
    }
}
/// A positioned write, falling back like [`read_at`].
fn write_at(file: &Arc<dyn FileHandle>, offset: u64, b: &[u8]) -> Result<usize, Errno> {
    match file.write_at(offset, b) {
        Err(e) if e == Errno::ENODEV => {
            let position = file.seek(0, 1)?;
            file.seek(offset as i64, 0)?;
            let result = file.write(b);
            file.seek(position as i64, 0)?;
            result
        }
        result => result,
    }
}
/// The `struct iovec` array of readv, writev and their positioned forms, as
/// Linux's `import_iovec` reads it: at most 1024 entries (EINVAL), each
/// buffer accessible (EFAULT), and the total cut to `MAX_RW_COUNT`.
fn iovecs(c: &Context<'_>, at: u64, count: u64, write: bool) -> Result<Vec<(u64, usize)>, Errno> {
    if count > 1024 {
        return Err(Errno::EINVAL);
    }
    let mut segments = Vec::new();
    let mut total = 0usize;
    for index in 0..count {
        let addr = at.checked_add(index * 16).ok_or(Errno::EFAULT)?;
        let base = c.mem.read_u64(GuestAddr(addr)).map_err(|_| Errno::EFAULT)?;
        let length = c
            .mem
            .read_u64(GuestAddr(addr.checked_add(8).ok_or(Errno::EFAULT)?))
            .map_err(|_| Errno::EFAULT)?;
        if (length as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        let length = usize::try_from(length)
            .unwrap_or(usize::MAX)
            .min(MAX_RW_COUNT - total);
        let checked = if write {
            c.mem.check_write(GuestAddr(base), length)
        } else {
            c.mem.check_read(GuestAddr(base), length)
        };
        checked.map_err(|_| Errno::EFAULT)?;
        total += length;
        segments.push((base, length));
    }
    Ok(segments)
}
/// Copies `bytes` into the guest buffers of `segments`, in order.
fn scatter(c: &Context<'_>, segments: &[(u64, usize)], mut bytes: &[u8]) -> Result<(), Errno> {
    for &(base, length) in segments {
        let (head, rest) = bytes.split_at(length.min(bytes.len()));
        output(c, base, head)?;
        bytes = rest;
    }
    Ok(())
}
/// A read that waits while a blocking file has nothing to give yet.
fn read_blocking(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    b: &mut [u8],
) -> Result<usize, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        match file.read(b) {
            Err(e)
                if e == Errno::EAGAIN
                    && file.readiness().is_ok()
                    && file.flags() & crate::events::NONBLOCK == 0 =>
            {
                crate::events::wait(c, ticket, None)?
            }
            result => return result,
        }
    }
}
/// `stat` of a file at guest `path`: its `st_dev` names the mount holding
/// it, numbered as /proc/self/mountinfo numbers mounts (0:1 is the root).
fn stat(c: &Context<'_>, addr: u64, s: FileStat, path: &[u8]) -> Result<u64, Errno> {
    let mut bytes = encode_stat(s)?;
    bytes[0..8].copy_from_slice(&device(c, path).to_le_bytes());
    output(c, addr, &bytes)?;
    Ok(0)
}
/// The minor number of the mount that holds `path` (the longest matching
/// mount point), so that each mount is its own device.
fn device(c: &Context<'_>, path: &[u8]) -> u64 {
    let inside = |root: &[u8]| {
        root == b"/"
            || path == root
            || path.starts_with(root) && path.get(root.len()) == Some(&b'/')
    };
    c.files
        .fs
        .mounts()
        .iter()
        .enumerate()
        .filter(|(_, m)| inside(&m.path))
        .max_by_key(|(_, m)| m.path.len())
        .map_or(1, |(i, _)| i as u64 + 1)
}
fn encode_stat(s: FileStat) -> Result<[u8; 144], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 144];
    b[8..16].copy_from_slice(&s.inode.to_le_bytes());
    b[16..24].copy_from_slice(&s.links.to_le_bytes());
    b[24..28].copy_from_slice(&s.mode.to_le_bytes());
    b[48..56].copy_from_slice(&s.size.to_le_bytes());
    b[56..64].copy_from_slice(&4096u64.to_le_bytes());
    b[64..72].copy_from_slice(&s.size.div_ceil(512).to_le_bytes());
    b[88..96].copy_from_slice(&seconds.to_le_bytes());
    b[96..104].copy_from_slice(&nanos.to_le_bytes());
    Ok(b)
}
fn linux_mtime(ns: i128) -> Result<(i64, u64), Errno> {
    let seconds = i64::try_from(ns.div_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    let nanos = u64::try_from(ns.rem_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    Ok((seconds, nanos))
}
#[cfg(test)]
mod mtime_tests {
    use super::*;
    #[test]
    fn umask_is_shared_exactly_with_clone_fs() {
        let files = Files::default();
        let shared = files.for_clone(false, true);
        let separate = files.for_clone(true, false);
        shared.umask.store(0o077, Ordering::SeqCst);
        assert_eq!(files.umask(), 0o077);
        assert_eq!(separate.umask(), 0o022);
        assert_eq!(files.for_exec().umask(), 0o077);
    }
    #[test]
    fn mtime_stat_codec_signed_boundaries() {
        for (ns, seconds, nanos) in [
            (-1_000_000_000, -1i64, 0u64),
            (-500_000_000, -1, 500_000_000),
            (-1, -1, 999_999_999),
            (0, 0, 0),
            (1, 0, 1),
            (1_500_000_000, 1, 500_000_000),
            (i128::from(u64::MAX), 18_446_744_073, 709_551_615),
        ] {
            let bytes = encode_stat(FileStat {
                mtime_ns: ns,
                ..FileStat::default()
            })
            .unwrap();
            assert_eq!(&bytes[88..96], &seconds.to_le_bytes());
            assert_eq!(&bytes[96..104], &nanos.to_le_bytes());
        }
    }
    #[test]
    fn mtime_stat_codec_checked_seconds_overflow() {
        for ns in [
            i128::MIN,
            i128::MAX,
            (i128::from(i64::MAX) + 1) * 1_000_000_000,
            i128::from(i64::MIN) * 1_000_000_000 - 1,
        ] {
            assert_eq!(
                encode_stat(FileStat {
                    mtime_ns: ns,
                    ..FileStat::default()
                }),
                Err(Errno(75))
            );
        }
        assert_eq!(
            linux_mtime(i128::from(i64::MIN) * 1_000_000_000),
            Ok((i64::MIN, 0))
        );
        assert_eq!(
            linux_mtime(i128::from(i64::MAX) * 1_000_000_000 + 999_999_999),
            Ok((i64::MAX, 999_999_999))
        );
    }
}
pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let n = c.cpu.gpr[paludarium_cpu::reg::RAX];
    match run(c, n, a) {
        Ok(v) => Outcome::Return(v),
        Err(e) => Outcome::Return(e.to_syscall_return()),
    }
}
pub(crate) fn run(c: &mut Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    match n {
        // pread64, pwrite64, preadv, pwritev: at an offset, leaving the file
        // position. On x86-64 the offset of preadv and pwritev is a[3] alone.
        17 => {
            let file = positioned(c, a[0], a[3], false)?;
            let len = request(&file, a[2], a[3], true)?;
            c.mem
                .check_write(GuestAddr(a[1]), len)
                .map_err(|_| Errno::EFAULT)?;
            let mut b = buffer(len)?;
            let count = read_at(&file, a[3], &mut b)?;
            output(c, a[1], &b[..count])?;
            Ok(count as u64)
        }
        18 => {
            let file = positioned(c, a[0], a[3], true)?;
            let len = request(&file, a[2], a[3], false)?;
            // Check the guest buffer before allocating its copy, as write does.
            c.mem
                .check_read(GuestAddr(a[1]), len)
                .map_err(|_| Errno::EFAULT)?;
            let mut b = buffer(len)?;
            c.mem
                .read(GuestAddr(a[1]), &mut b)
                .map_err(|_| Errno::EFAULT)?;
            write_at(&file, a[3], &b).map(|count| count as u64)
        }
        19 => {
            let file = c.files.descriptor(a[0])?.file;
            if file.flags() & 3 == 1 {
                return Err(Errno::EBADF);
            }
            let segments = iovecs(c, a[1], a[2], true)?;
            let total = segments.iter().map(|(_, length)| length).sum::<usize>();
            let position = file.seek(0, 1).ok();
            let len = match position {
                Some(position) => request(&file, total as u64, position, true)?,
                None => total,
            };
            let mut b = buffer(len)?;
            let count = read_blocking(c, &file, &mut b)?;
            scatter(c, &segments, &b[..count])?;
            Ok(count as u64)
        }
        295 | 296 => {
            let file = positioned(c, a[0], a[3], n == 296)?;
            let segments = iovecs(c, a[1], a[2], n == 295)?;
            let total = segments.iter().map(|(_, length)| length).sum::<usize>();
            let len = request(&file, total as u64, a[3], n == 295)?;
            if n == 295 {
                let mut b = buffer(len)?;
                let count = read_at(&file, a[3], &mut b)?;
                scatter(c, &segments, &b[..count])?;
                return Ok(count as u64);
            }
            let mut b = Vec::new();
            b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            for &(base, length) in &segments {
                let start = b.len();
                b.resize(start + length, 0);
                c.mem
                    .read(GuestAddr(base), &mut b[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            write_at(&file, a[3], &b).map(|count| count as u64)
        }
        22 | 293 => {
            let flags = if n == 22 {
                0
            } else {
                u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?
            };
            if flags & !(crate::events::NONBLOCK | crate::events::CLOEXEC) != 0 {
                return Err(Errno::EINVAL);
            }
            c.mem
                .check_write(GuestAddr(a[0]), 8)
                .map_err(|_| Errno::EFAULT)?;
            let ends = crate::sockets::PipeEnd::pair(flags, Arc::clone(&c.files.readiness))?;
            let [first, second] = c.files.install_pair(
                ends.map(|end| end as Arc<dyn FileHandle>),
                flags & crate::events::CLOEXEC != 0,
                c.group.nofile(),
            )?;
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&first.to_le_bytes());
            bytes[4..].copy_from_slice(&second.to_le_bytes());
            output(c, a[0], &bytes)?;
            Ok(0)
        }
        20 => {
            if a[2] > 1024 {
                return Err(Errno::EINVAL);
            }
            let descriptor = c.files.descriptor(a[0])?;
            let mut bytes = Vec::new();
            for index in 0..a[2] {
                let addr = a[1].checked_add(index * 16).ok_or(Errno::EFAULT)?;
                let base = c.mem.read_u64(GuestAddr(addr)).map_err(|_| Errno::EFAULT)?;
                let length = c
                    .mem
                    .read_u64(GuestAddr(addr + 8))
                    .map_err(|_| Errno::EFAULT)?;
                let length = usize::try_from(length).map_err(|_| Errno::EINVAL)?;
                let total = bytes
                    .len()
                    .checked_add(length)
                    .filter(|v| *v <= 0x7fff_f000)
                    .ok_or(Errno::EINVAL)?;
                c.mem
                    .check_read(GuestAddr(base), length)
                    .map_err(|_| Errno::EFAULT)?;
                bytes.try_reserve(length).map_err(|_| Errno::ENOMEM)?;
                let start = bytes.len();
                bytes.resize(total, 0);
                c.mem
                    .read(GuestAddr(base), &mut bytes[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            write_io(c, &descriptor.file, &bytes, false)
        }
        0 | 1 => {
            let requested = usize::try_from(a[2].min(0x7fff_f000)).map_err(|_| Errno::EINVAL)?;
            let d = Some(c.files.descriptor(a[0])?);
            let len = if n == 0 {
                if let Some(d) = &d {
                    let metadata = d.file.stat()?;
                    if metadata.mode & 0o170000 != 0o100000 {
                        requested
                    } else {
                        let size = metadata.size;
                        let pos = d.file.seek(0, 1)?;
                        requested
                            .min(usize::try_from(size.saturating_sub(pos)).unwrap_or(usize::MAX))
                    }
                } else {
                    requested
                }
            } else {
                requested
            };
            if n == 1 {
                c.mem
                    .check_read(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            } else {
                c.mem
                    .check_write(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let mut b = Vec::new();
            b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            b.resize(len, 0);
            if n == 1 {
                c.mem
                    .read(GuestAddr(a[1]), &mut b)
                    .map_err(|_| Errno::EFAULT)?;
                return write_io(c, &d.ok_or(Errno::EBADF)?.file, &b, false);
            }
            let count = if let Some(d) = d {
                read_blocking(c, &d.file, &mut b)?
            } else if a[0] == 0 {
                c.host.read_stdin(&mut b)?
            } else {
                return Err(Errno::EBADF);
            };
            output(c, a[1], &b[..count])?;
            Ok(count as u64)
        }
        2 | 85 | 257 => {
            let (p, flags, mode) = match n {
                2 => (at(c, (-100i32) as u64, a[0])?, a[1], a[2]),
                85 => (at(c, (-100i32) as u64, a[0])?, 577, a[1]),
                _ => (at(c, a[0], a[1])?, a[2], a[3]),
            };
            let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
            if flags & 3 == 3 {
                return Err(Errno::EINVAL);
            }
            // Linux takes the descriptor before it opens, so with none free
            // nothing is opened or created.
            let fd = c.files.reserve(c.group.nofile())?;
            let opened = (|| -> Result<Arc<dyn FileHandle>, Errno> {
                Ok(if p == b"/dev/null" {
                    Arc::new(crate::null::NullFile::new(flags))
                } else if let Some(mountinfo) = crate::proc::mount_table(&p) {
                    let content = crate::proc::render(&c.files.fs.mounts(), mountinfo);
                    Arc::new(crate::proc::GeneratedFile::open(content, flags))
                } else if let Some(entry) = crate::proc::own_entry(&p, c.process.pid) {
                    match entry {
                        crate::proc::OwnEntry::Directory => Arc::new(crate::proc::OwnDirectory),
                        crate::proc::OwnEntry::Status => {
                            Arc::new(crate::proc::GeneratedFile::open(status(c), flags))
                        }
                    }
                } else {
                    c.files
                        .fs
                        .open(&p, flags, (mode as u32) & !c.files.umask())?
                })
            })();
            match opened {
                Ok(file) => {
                    let cloexec = flags & 0x80000 != 0;
                    c.files.fill(
                        fd,
                        Descriptor {
                            file,
                            path: p,
                            cloexec,
                        },
                    );
                    Ok(u64::from(fd))
                }
                Err(error) => {
                    c.files.unreserve(fd);
                    Err(error)
                }
            }
        }
        3 => {
            c.files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&(a[0] as u32))
                .ok_or(Errno::EBADF)?;
            Ok(0)
        }
        4 | 6 | 262 => {
            let (p, out, follow) = if n == 262 {
                if a[3] & !0x1100 != 0 {
                    return Err(Errno::EINVAL);
                }
                let raw = path(c, a[1])?;
                if raw.is_empty() && a[3] & 0x1000 != 0 {
                    let d = c.files.descriptor(a[0])?;
                    return stat(c, a[2], d.file.stat()?, &d.path);
                }
                (c.files.path(a[0], raw)?, a[2], a[3] & 0x100 == 0)
            } else {
                (at(c, (-100i32) as u64, a[0])?, a[1], n == 4)
            };
            if let Some(generated) = generated_stat(c, &p) {
                return stat(c, out, generated, &p);
            }
            stat(c, out, c.files.fs.metadata(&p, follow)?, &p)
        }
        5 => {
            let d = c.files.descriptor(a[0])?;
            stat(c, a[1], d.file.stat()?, &d.path)
        }
        8 => c
            .files
            .descriptor(a[0])?
            .file
            .seek(a[1] as i64, a[2] as u32),
        32 => {
            let d = Descriptor {
                cloexec: false,
                ..c.files.descriptor(a[0])?
            };
            c.files.allocate(d, 0, c.group.nofile()).map(u64::from)
        }
        33 | 292 => {
            // Both take unsigned int descriptors.
            let (old, new) = (a[0] as u32, a[1] as u32);
            if n == 292 && (a[2] & !0x80000 != 0 || old == new) {
                return Err(Errno::EINVAL);
            }
            // dup2 onto itself only checks the descriptor, keeping its flags.
            if old == new {
                return c.files.descriptor(u64::from(old)).map(|_| u64::from(new));
            }
            if u64::from(new) >= c.group.nofile() {
                return Err(Errno::EBADF);
            }
            let d = Descriptor {
                cloexec: n == 292 && a[2] & 0x80000 != 0,
                ..c.files.descriptor(u64::from(old))?
            };
            c.files.replace(new, d)?;
            Ok(u64::from(new))
        }
        72 => {
            let mut d = c.files.descriptor(a[0])?;
            match a[1] {
                0 | 1030 => {
                    d.cloexec = a[1] == 1030;
                    // F_DUPFD takes an int, and a start at or past the limit
                    // is EINVAL rather than EMFILE.
                    let from = a[2] as u32;
                    let limit = c.group.nofile();
                    if u64::from(from) >= limit {
                        return Err(Errno::EINVAL);
                    }
                    c.files.allocate(d, from, limit).map(u64::from)
                }
                1 => Ok(u64::from(d.cloexec)),
                2 => {
                    d.cloexec = a[2] & 1 != 0;
                    c.files
                        .fds
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(a[0] as u32, d);
                    Ok(0)
                }
                3 => Ok(d.file.flags() as u64),
                // F_SETPIPE_SZ and F_GETPIPE_SZ, for pipes only.
                1031 | 1032 => {
                    let pipe = d
                        .file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<crate::sockets::PipeEnd>())
                        .ok_or(Errno::EBADF)?;
                    if a[1] == 1031 {
                        pipe.set_size(a[2] as u32)
                    } else {
                        Ok(pipe.size())
                    }
                }
                4 => {
                    d.file.set_flags(a[2] as u32)?;
                    Ok(0)
                }
                _ => Err(Errno::EINVAL),
            }
        }
        73 => {
            let d = c.files.descriptor(a[0])?;
            loop {
                match d.file.flock(a[1] as u32) {
                    Ok(()) => return Ok(0),
                    Err(e) if e == Errno::EAGAIN && a[1] & 4 == 0 => {
                        let timer_generation = c.group.timer_generation();
                        let receipt = c.inbox.drain(c.process);
                        c.group.drain_process(c.process);
                        let now = c.host.clock(ClockId::Monotonic)?;
                        c.group.expire_timer(c.process, now);
                        if c.group.status().is_some()
                            || crate::signals::next_pending(c.process, true).is_some()
                            || receipt.interrupted
                        {
                            return Err(Errno(4));
                        }
                        if !c.inbox.owns_wake(c.cancellation)
                            && c.cancellation.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            return Err(Errno(4));
                        }
                        let outcome = c.host.wait_until(
                            ClockId::Monotonic,
                            now.saturating_add(10_000_000),
                            c.cancellation,
                        )?;
                        let receipt = c.inbox.drain(c.process);
                        c.group.drain_process(c.process);
                        if c.group.status().is_some()
                            || crate::signals::next_pending(c.process, true).is_some()
                            || receipt.interrupted
                            || (outcome == paludarium_host::WaitOutcome::Interrupted
                                && !receipt.timer_changed
                                && !receipt.signals
                                && c.group.timer_generation() == timer_generation)
                        {
                            return Err(Errno(4));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        76 | 77 => {
            let f = if n == 77 {
                c.files.descriptor(a[0])?.file
            } else {
                c.files.fs.open(&at(c, (-100i32) as u64, a[0])?, 1, 0)?
            };
            if a[1] > i64::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            f.truncate(a[1])?;
            Ok(0)
        }
        79 => {
            let mut p = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            p.push(0);
            if a[1] < p.len() as u64 {
                return Err(Errno::ERANGE);
            }
            output(c, a[0], &p)?;
            Ok(p.len() as u64)
        }
        80 | 81 => {
            let p = if n == 80 {
                at(c, (-100i32) as u64, a[0])?
            } else {
                c.files.descriptor(a[0])?.path
            };
            if c.files.fs.metadata(&p, true)?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            *c.files.cwd.lock().unwrap_or_else(PoisonError::into_inner) = p;
            Ok(0)
        }
        82 | 264 => {
            let (old, new) = if n == 82 {
                (
                    at(c, (-100i32) as u64, a[0])?,
                    at(c, (-100i32) as u64, a[1])?,
                )
            } else {
                (at(c, a[0], a[1])?, at(c, a[2], a[3])?)
            };
            c.files.fs.rename(&old, &new)?;
            for d in c
                .files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values_mut()
            {
                if d.path == old || d.path.starts_with(&old) && d.path.get(old.len()) == Some(&b'/')
                {
                    let mut p = new.clone();
                    p.extend_from_slice(&d.path[old.len()..]);
                    d.path = p;
                }
            }
            let mut cwd = c.files.cwd.lock().unwrap_or_else(PoisonError::into_inner);
            if *cwd == old || cwd.starts_with(&old) && cwd.get(old.len()) == Some(&b'/') {
                let mut p = new.clone();
                p.extend_from_slice(&cwd[old.len()..]);
                *cwd = p;
            }
            Ok(0)
        }
        83 | 258 => {
            let (p, mode) = if n == 83 {
                (at(c, (-100i32) as u64, a[0])?, a[1])
            } else {
                (at(c, a[0], a[1])?, a[2])
            };
            c.files.fs.mkdir(&p, (mode as u32) & !c.files.umask())?;
            Ok(0)
        }
        84 | 87 | 263 => {
            let (p, dir) = if n == 263 {
                if a[2] & !512 != 0 {
                    return Err(Errno::EINVAL);
                }
                (at(c, a[0], a[1])?, a[2] & 512 != 0)
            } else {
                (at(c, (-100i32) as u64, a[0])?, n == 84)
            };
            c.files.fs.unlink(&p, dir)?;
            Ok(0)
        }
        86 | 265 => {
            let (old, new) = if n == 86 {
                (
                    at(c, (-100i32) as u64, a[0])?,
                    at(c, (-100i32) as u64, a[1])?,
                )
            } else {
                if a[4] != 0 {
                    return Err(Errno::EINVAL);
                }
                (at(c, a[0], a[1])?, at(c, a[2], a[3])?)
            };
            c.files.fs.link(&old, &new)?;
            Ok(0)
        }
        88 | 266 => {
            let target = path(c, a[0])?;
            let p = if n == 88 {
                at(c, (-100i32) as u64, a[1])?
            } else {
                at(c, a[1], a[2])?
            };
            c.files.fs.symlink(&target, &p)?;
            Ok(0)
        }
        89 | 267 => {
            let (p, buf, len) = if n == 89 {
                (at(c, (-100i32) as u64, a[0])?, a[1], a[2])
            } else {
                (at(c, a[0], a[1])?, a[2], a[3])
            };
            if len == 0 {
                return Err(Errno::EINVAL);
            }
            // `/proc/self` is a link to this process's directory.
            let b = if p == b"/proc/self" {
                c.process.pid.to_string().into_bytes()
            } else {
                c.files.fs.readlink(&p)?
            };
            let count = b
                .len()
                .min(usize::try_from(len).map_err(|_| Errno::EINVAL)?);
            output(c, buf, &b[..count])?;
            Ok(count as u64)
        }
        217 => {
            let d = c.files.descriptor(a[0])?;
            if d.file.stat()?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            let entries = c.files.fs.read_dir(&d.path)?;
            let position = d.file.seek(0, 1)? as usize;
            let mut bytes = Vec::new();
            let mut count = 0;
            for (i, e) in entries.iter().enumerate().skip(position) {
                let size = (19 + e.name.len() + 1).div_ceil(8) * 8;
                if bytes.len() + size > a[2] as usize {
                    if bytes.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    break;
                }
                let pos = bytes.len();
                bytes.resize(pos + size, 0);
                bytes[pos..pos + 8].copy_from_slice(&e.inode.to_le_bytes());
                bytes[pos + 8..pos + 16].copy_from_slice(&((i + 1) as u64).to_le_bytes());
                bytes[pos + 16..pos + 18].copy_from_slice(&(size as u16).to_le_bytes());
                bytes[pos + 18] = e.kind;
                bytes[pos + 19..pos + 19 + e.name.len()].copy_from_slice(&e.name);
                count += 1;
            }
            output(c, a[1], &bytes)?;
            d.file.seek(count, 1)?;
            Ok(bytes.len() as u64)
        }
        // umask
        95 => Ok(u64::from(
            c.files.umask.swap(a[0] as u32 & 0o777, Ordering::SeqCst),
        )),
        // chmod, fchmod, fchmodat (which has no flags argument)
        90 => {
            let p = at(c, (-100i32) as u64, a[0])?;
            c.files.fs.set_mode(&p, a[1] as u32).map(|()| 0)
        }
        91 => c
            .files
            .descriptor(a[0])?
            .file
            .set_mode(a[1] as u32)
            .map(|()| 0),
        268 => {
            let p = at(c, a[0], a[1])?;
            c.files.fs.set_mode(&p, a[2] as u32).map(|()| 0)
        }
        280 => utimensat(c, a),
        // statfs, fstatfs
        137 => {
            let p = at(c, (-100i32) as u64, a[0])?;
            write_statfs(c, a[1], c.files.fs.statfs(&p)?)
        }
        138 => {
            let d = c.files.descriptor(a[0])?;
            let stats = match d.file.stat()?.mode & 0o170000 {
                0o010000 => pseudo_fs(0x5049_5045), // PIPEFS_MAGIC
                0o140000 => pseudo_fs(0x534F_434B), // SOCKFS_MAGIC
                _ => c
                    .files
                    .fs
                    .statfs(&d.path)
                    .or_else(|_| c.files.fs.statfs(b"/"))?,
            };
            write_statfs(c, a[1], stats)
        }
        // access, faccessat, faccessat2
        21 => access(c, (-100i32) as u64, a[0], a[1], 0),
        269 => access(c, a[0], a[1], a[2], 0),
        439 => access(c, a[0], a[1], a[2], a[3]),
        // fsync, fdatasync: both write everything, as nothing is cached
        74 | 75 => c.files.descriptor(a[0])?.file.sync().map(|()| 0),
        // sync: nothing is cached, so there is nothing to write
        162 => Ok(0),
        // fadvise64: a hint, checked as Linux checks it
        221 => {
            let file = c.files.descriptor(a[0])?.file;
            if file.stat()?.mode & 0o170000 == 0o010000 {
                return Err(Errno(29)); // ESPIPE
            }
            if (a[2] as i64) < 0 || a[3] > 5 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// Blocking stream writes preserve partial progress across readiness retries.
/// No descriptor-table, stream-state or guest-memory lock spans a Host wait.
pub(crate) fn write_io(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
) -> Result<u64, Errno> {
    let stream = file
        .as_any()
        .is_some_and(|a| a.is::<crate::sockets::SocketPairEnd>());
    let mut done = 0;
    loop {
        let ticket = c.files.readiness.token.value();
        let nonblocking = file.flags() & crate::events::NONBLOCK != 0;
        match file.write(&bytes[done..]) {
            Ok(count) => {
                done += count;
                if count == 0 || done == bytes.len() || nonblocking || !stream {
                    return Ok(done as u64);
                }
            }
            Err(e) if e == Errno::EAGAIN && file.readiness().is_ok() && !nonblocking => {
                if let Err(e) = crate::events::wait(c, ticket, None) {
                    return if done != 0 { Ok(done as u64) } else { Err(e) };
                }
            }
            Err(e) => {
                if done != 0 {
                    return Ok(done as u64);
                }
                let sigpipe = file
                    .as_any()
                    .and_then(|a| a.downcast_ref::<crate::sockets::SocketPairEnd>())
                    .is_none_or(crate::sockets::SocketPairEnd::raises_sigpipe);
                if e == Errno(32) && !nosignal && sigpipe {
                    crate::signals::queue(c.process, crate::signals::PendingSignal::user(13, 0));
                }
                return Err(e);
            }
        }
    }
}
struct StandardFile {
    host: Arc<dyn paludarium_host::Host>,
    channel: u32,
}
impl FileHandle for StandardFile {
    fn stdio_channel(&self) -> Option<u32> {
        Some(self.channel)
    }
    fn read(&self, b: &mut [u8]) -> Result<usize, Errno> {
        if self.channel == 0 {
            self.host.read_stdin(b)
        } else {
            Err(Errno::EBADF)
        }
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        match self.channel {
            1 => self.host.write_stdout(b),
            2 => self.host.write_stderr(b),
            _ => Err(Errno::EBADF),
        }
    }
    fn seek(&self, _o: i64, _w: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.channel as u64,
            size: 0,
            mode: 0o010666,
            links: 1,
            mtime_ns: 0,
        })
    }
    fn truncate(&self, _n: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _o: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        u32::from(self.channel != 0)
    }
    fn set_flags(&self, _f: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}
#[cfg(test)]
mod files_tests {
    use super::*;
    fn d(fs: &MemFs, p: &[u8]) -> Descriptor {
        Descriptor {
            file: fs.open(p, 66, 0o600).unwrap(),
            path: p.to_vec(),
            cloexec: false,
        }
    }
    #[test]
    fn fd_allocate() {
        let fs = MemFs::new();
        let mut f = Files::default();
        assert_eq!(f.allocate(d(&fs, b"/a"), 3, 1024), Ok(3));
        assert_eq!(f.allocate(d(&fs, b"/b"), 3, 1024), Ok(4));
    }
    #[test]
    fn fd_limit() {
        let fs = MemFs::new();
        let mut f = Files::default();
        assert_eq!(f.allocate(d(&fs, b"/a"), 3, 5), Ok(3));
        assert_eq!(f.allocate(d(&fs, b"/b"), 3, 5), Ok(4));
        assert_eq!(f.allocate(d(&fs, b"/c"), 3, 5), Err(Errno::EMFILE));
        assert_eq!(f.reserve(0), Err(Errno::EMFILE));
        // A pair needs two free descriptors; with one (0), neither is taken.
        let [x, y] = crate::sockets::PipeEnd::pair(0, Arc::clone(&f.readiness))
            .unwrap()
            .map(|end| end as Arc<dyn FileHandle>);
        assert_eq!(
            f.install_pair([x.clone(), y.clone()], false, 1),
            Err(Errno::EMFILE)
        );
        assert!(f.descriptor(0).is_err());
        assert_eq!(f.install_pair([x, y], false, 2), Ok([0, 1]));
    }
    #[test]
    fn fd_reservation() {
        let fs = MemFs::new();
        let mut f = Files::default();
        // An open's number is taken but not seen until the file is there.
        assert_eq!(f.reserve(1024), Ok(0));
        assert_eq!(f.allocate(d(&fs, b"/a"), 0, 1024), Ok(1));
        assert_eq!(f.reserve(2), Err(Errno::EMFILE));
        assert!(f.descriptor(0).is_err());
        assert_eq!(f.replace(0, d(&fs, b"/b")), Err(Errno(16)));
        f.fill(0, d(&fs, b"/c"));
        assert_eq!(f.descriptor(0).unwrap().path, b"/c");
        assert_eq!(f.replace(0, d(&fs, b"/b")), Ok(()));
        // A failed open gives its number back.
        assert_eq!(f.reserve(1024), Ok(2));
        f.unreserve(2);
        assert_eq!(f.allocate(d(&fs, b"/d"), 0, 1024), Ok(2));
        // A process of its own starts with no reservations.
        assert_eq!(f.reserve(1024), Ok(3));
        assert_eq!(
            f.for_clone(false, false).allocate(d(&fs, b"/e"), 0, 1024),
            Ok(3)
        );
    }
    #[test]
    fn fd_minimum() {
        let fs = MemFs::new();
        assert_eq!(Files::default().allocate(d(&fs, b"/a"), 20, 1024), Ok(20));
    }
    #[test]
    fn fd_bad() {
        assert!(matches!(
            Files::default().descriptor(100),
            Err(Errno::EBADF)
        ));
    }
    #[test]
    fn fd_relative() {
        assert_eq!(
            Files::default().path((-100i32) as u64, b"a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn fd_absolute_ignores_bad_dir() {
        assert_eq!(
            Files::default().path(999, b"/a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn fd_empty() {
        assert_eq!(
            Files::default().path((-100i32) as u64, vec![]),
            Err(Errno::ENOENT)
        );
    }
    #[test]
    fn fd_directory_type() {
        let fs = MemFs::new();
        let mut f = Files::default();
        f.allocate(d(&fs, b"/a"), 3, 1024).unwrap();
        assert_eq!(f.path(3, b"b".to_vec()), Err(Errno::ENOTDIR));
    }
    #[test]
    fn fd_shared_offset() {
        let fs = MemFs::new();
        let x = d(&fs, b"/a");
        x.file.write(b"abc").unwrap();
        let y = x.clone();
        y.file.seek(0, 0).unwrap();
        let mut b = [0];
        x.file.read(&mut b).unwrap();
        assert_eq!(y.file.seek(0, 1), Ok(1));
    }
}

/// The `stat` of a generated /proc path, or `None` for any other path.
fn generated_stat(c: &Context<'_>, path: &[u8]) -> Option<FileStat> {
    if let Some(mountinfo) = crate::proc::mount_table(path) {
        return Some(crate::proc::stat(
            crate::proc::render(&c.files.fs.mounts(), mountinfo).len(),
        ));
    }
    Some(match crate::proc::own_entry(path, c.process.pid)? {
        crate::proc::OwnEntry::Directory => crate::proc::directory_stat(),
        crate::proc::OwnEntry::Status => crate::proc::stat(status(c).len()),
    })
}

/// This process's `/proc/self/status`.
fn status(c: &Context<'_>) -> Vec<u8> {
    let (parent, queue_limit, no_new_privs) = c.processes.status_of(c.process.pid);
    let mask = |numbers: &mut dyn Iterator<Item = i32>| {
        numbers
            .filter(|n| (1..=64).contains(n))
            .fold(0u64, |mask, n| mask | 1 << (n - 1))
    };
    let actions = &c.process.signal_actions;
    let descriptors = c
        .files
        .fds
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .keys()
        .next_back()
        .map_or(0, |&fd| fd as usize + 1);
    crate::proc::render_status(&crate::proc::Status {
        name: &c.process.name,
        umask: c.files.umask(),
        pid: c.process.pid,
        parent,
        descriptors,
        threads: c.group.active_threads(),
        queued: c.process.pending.len(),
        queue_limit,
        pending: mask(&mut c.process.pending.iter().map(|s| s.number)),
        blocked: c.process.signal_mask,
        ignored: mask(
            &mut actions
                .iter()
                .filter(|(_, a)| a.handler == 1)
                .map(|(&n, _)| n),
        ),
        caught: mask(
            &mut actions
                .iter()
                .filter(|(_, a)| a.handler > 1)
                .map(|(&n, _)| n),
        ),
        no_new_privs,
    })
}
