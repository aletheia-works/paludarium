//! Linux x86-64 file ABI and descriptor table. All guest memory is checked.
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, HostFs, MemFs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
pub const NUMBERS: &[u64] = &[
    0, 2, 3, 4, 5, 6, 8, 17, 18, 19, 20, 21, 22, 32, 33, 40, 72, 73, 74, 75, 76, 77, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 95, 137, 138, 162, 217, 221, 257, 258, 262, 263, 264,
    265, 266, 267, 268, 269, 280, 285, 292, 293, 295, 296, 319, 326, 332, 436, 439,
];
#[derive(Clone)]
pub(crate) struct Descriptor {
    pub(crate) file: Arc<dyn FileHandle>,
    path: Vec<u8>,
    cloexec: bool,
}
impl Descriptor {
    /// The descriptor a process gets for this one's open file over
    /// `SCM_RIGHTS`: the same file and path, with its own close-on-exec flag.
    pub(crate) fn received(self, cloexec: bool) -> Self {
        Self { cloexec, ..self }
    }
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
                            rises: AtomicU64::new(0),
                            was_ready: std::sync::atomic::AtomicBool::new(false),
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
    /// The file a core dump goes to: `core` in the working directory, made
    /// afresh with mode 0600 less the umask, as Linux's `do_coredump` removes
    /// an old one and opens it with `O_CREAT | O_EXCL | O_NOFOLLOW`.
    pub(crate) fn create_core(&self) -> Result<Arc<dyn paludarium_host::FileHandle>, Errno> {
        let path = paludarium_vfs::normalize_path(&self.path(-100i64 as u64, b"core".to_vec())?)?;
        let _ = self.fs.unlink(&path, false);
        self.fs
            .open(&path, 0o1 | 0o100 | 0o200 | 0o400000, 0o600 & !self.umask())
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
    const AT_EACCESS: u64 = 0x200;
    if mode & !7 != 0 || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let raw = path(c, ptr)?;
    let stat = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        c.files.descriptor(dir)?.file.stat()?
    } else {
        let p = c.files.path(dir, raw)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        match generated_stat(c, &p, follow) {
            Some((stat, _)) => stat,
            None => c.files.fs.metadata(&p, follow)?,
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
/// The bytes of a `len`-byte write at `offset` (the file's position when
/// `None`) that RLIMIT_FSIZE lets through, as Linux's generic_write_checks:
/// an O_APPEND file starts at its size whatever the offset, as its pwrite
/// appends; only regular files are limited, and a write starting at or past
/// the limit raises SIGXFSZ and fails with EFBIG.
fn size_limited(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    offset: Option<u64>,
    len: usize,
) -> Result<usize, Errno> {
    let limit = c.group.fsize();
    if limit == u64::MAX || len == 0 {
        return Ok(len);
    }
    let metadata = file.stat()?;
    if metadata.mode & 0o170000 != 0o100000 {
        return Ok(len);
    }
    let start = match offset {
        _ if file.flags() & 0o2000 != 0 => metadata.size,
        Some(offset) => offset,
        None => file.seek(0, 1)?,
    };
    let room = size_room(c, start)?;
    Ok(len.min(usize::try_from(room).unwrap_or(usize::MAX)))
}
/// The bytes RLIMIT_FSIZE lets a regular file take from `start`, as Linux's
/// generic_write_check_limits: from the limit on none, raising SIGXFSZ and
/// failing with EFBIG.
fn size_room(c: &mut Context<'_>, start: u64) -> Result<u64, Errno> {
    let limit = c.group.fsize();
    if limit == u64::MAX {
        return Ok(u64::MAX);
    }
    if start >= limit {
        crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
        return Err(Errno(27));
    }
    Ok(limit - start)
}
const REGULAR: u32 = 0o100000;
/// A new inode number for a file on no mount (a pipe, a socket or a memfd),
/// so that no two share one, as Linux numbers its pipefs, sockfs and tmpfs
/// inodes.
pub(crate) fn anonymous_inode() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
const DIRECTORY: u32 = 0o040000;
/// A guest `loff_t *` argument: none when null, else its value (EFAULT).
fn offset_argument(c: &Context<'_>, at: u64) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    c.mem
        .read_u64(GuestAddr(at))
        .map(Some)
        .map_err(|_| Errno::EFAULT)
}
/// Copies up to `count` bytes from `input` at `from` to `output` at `to`, in
/// pieces, stopping early at the input's end or a short write. An error
/// after some bytes are copied ends the copy with their count, as Linux
/// reports it on the next call.
fn copy_bytes(
    input: &Arc<dyn FileHandle>,
    from: u64,
    output: &Arc<dyn FileHandle>,
    to: u64,
    count: u64,
) -> Result<u64, Errno> {
    let mut piece = buffer(usize::try_from(count).unwrap_or(usize::MAX).min(1 << 20))?;
    let mut done = 0;
    while done < count {
        let want = usize::try_from(count - done).map_or(piece.len(), |n| n.min(piece.len()));
        let copied = read_at(input, from + done, &mut piece[..want])
            .and_then(|read| Ok((read, write_at(output, to + done, &piece[..read])?)));
        let (read, written) = match copied {
            Ok(counts) => counts,
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        };
        done += written as u64;
        if read == 0 || written < read {
            break;
        }
    }
    Ok(done)
}
/// `fallocate(fd, mode, offset, len)`, with the checks of Linux's
/// vfs_fallocate in order. Files behave as on tmpfs: plain allocation (which
/// may grow the file) allocates the pages of the range, `FALLOC_FL_KEEP_SIZE`
/// keeps the size, `FALLOC_FL_PUNCH_HOLE` frees the pages it covers, and the
/// other modes give `EOPNOTSUPP`.
fn fallocate(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const KEEP_SIZE: u32 = 0x01;
    const PUNCH_HOLE: u32 = 0x02;
    // PUNCH_HOLE, COLLAPSE_RANGE, ZERO_RANGE, INSERT_RANGE, UNSHARE_RANGE
    // and WRITE_ZEROES; plain allocation is no bit.
    const MODE_MASK: u32 = 0xfa;
    const EOPNOTSUPP: Errno = Errno(95);
    let d = c.files.descriptor(a[0])?;
    let (mode, offset, len) = (a[1] as u32, a[2] as i64, a[3] as i64);
    if offset < 0 || len <= 0 {
        return Err(Errno::EINVAL);
    }
    if mode & !(MODE_MASK | KEEP_SIZE) != 0 {
        return Err(EOPNOTSUPP);
    }
    match mode & MODE_MASK {
        // Allocation, UNSHARE_RANGE and ZERO_RANGE take KEEP_SIZE or not.
        0 | 0x40 | 0x10 => {}
        PUNCH_HOLE if mode & KEEP_SIZE != 0 => {}
        // COLLAPSE_RANGE, INSERT_RANGE and WRITE_ZEROES do not take it.
        0x08 | 0x20 | 0x80 if mode & KEEP_SIZE == 0 => {}
        _ => return Err(EOPNOTSUPP),
    }
    if d.file.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    let stat = d.file.stat()?;
    match stat.mode & 0o170000 {
        0o010000 => return Err(Errno::ESPIPE),
        DIRECTORY => return Err(Errno::EISDIR),
        REGULAR => {}
        _ => return Err(Errno(19)), // ENODEV
    }
    let end = offset.checked_add(len).ok_or(Errno(27))? as u64; // EFBIG
    let memfd = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
    match mode & MODE_MASK {
        0 => {
            let grows = end > stat.size;
            // Going past RLIMIT_FSIZE raises SIGXFSZ (inode_newsize_ok); a
            // memfd, a tmpfs file, is checked even with KEEP_SIZE, as
            // shmem_fallocate checks it, and then its F_SEAL_GROW.
            if grows && (mode & KEEP_SIZE == 0 || memfd.is_some()) && end > c.group.fsize() {
                crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
                return Err(Errno(27));
            }
            if let Some(memfd) = memfd {
                memfd.check_allocate(end)?;
            }
            // The pages of the range are allocated, and count in st_blocks.
            d.file.allocate(offset as u64, len as u64)?;
            if grows && mode & KEEP_SIZE == 0 {
                d.file.truncate(end)?;
            }
        }
        PUNCH_HOLE => d.file.zero_range(offset as u64, len as u64)?,
        _ => return Err(EOPNOTSUPP),
    }
    Ok(0)
}
/// `close_range(first, last, flags)`, as Linux's ksys_close_range: the
/// arguments are `unsigned int`s, numbers with no open descriptor are skipped,
/// `CLOSE_RANGE_CLOEXEC` marks instead of closing, and `CLOSE_RANGE_UNSHARE`
/// first gives this thread its own copy of a shared table.
fn close_range(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const CLOSE_RANGE_UNSHARE: u32 = 2;
    const CLOSE_RANGE_CLOEXEC: u32 = 4;
    let (first, last, flags) = (a[0] as u32, a[1] as u32, a[2] as u32);
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return Err(Errno::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        *c.files = c.files.for_clone(false, true);
    }
    let mut fds = c.files.fds.lock().unwrap_or_else(PoisonError::into_inner);
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        for descriptor in fds.range_mut(first..=last).map(|(_, d)| d) {
            descriptor.cloexec = true;
        }
        return Ok(0);
    }
    let closed = fds
        .extract_if(first..=last, |_, _| true)
        .collect::<Vec<_>>();
    // The closed files are released only after the table is unlocked.
    drop(fds);
    drop(closed);
    Ok(0)
}
/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)`, with the
/// checks of Linux's generic_copy_file_checks and rw_verify_area in order.
fn copy_file_range(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    if a[5] != 0 {
        return Err(Errno::EINVAL);
    }
    let input = c.files.descriptor(a[0])?;
    let output = c.files.descriptor(a[2])?;
    // A file without a position (a pipe) is at 0, and fails as no regular file.
    let from = match offset_argument(c, a[1])? {
        Some(offset) => offset,
        None => input.file.seek(0, 1).unwrap_or(0),
    };
    let to = match offset_argument(c, a[3])? {
        Some(offset) => offset,
        None => output.file.seek(0, 1).unwrap_or(0),
    };
    let (source, target) = (input.file.stat()?, output.file.stat()?);
    if source.mode & 0o170000 == DIRECTORY || target.mode & 0o170000 == DIRECTORY {
        return Err(Errno::EISDIR);
    }
    if source.mode & 0o170000 != REGULAR || target.mode & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    if input.file.flags() & 3 == 1
        || output.file.flags() & 3 == 0
        || output.file.flags() & 0o2000 != 0
    {
        return Err(Errno::EBADF);
    }
    // Both files must be on one filesystem.
    let same_mount = descriptor_device(c, &input) == descriptor_device(c, &output);
    if !same_mount {
        return Err(Errno(18));
    }
    // Offsets that wrap with the requested length, compared as unsigned (a
    // negative one wraps with a long enough request).
    if from.checked_add(a[4]).is_none() || to.checked_add(a[4]).is_none() {
        return Err(Errno::EOVERFLOW);
    }
    // Shortened to the input's end, then to what RLIMIT_FSIZE allows.
    let mut count = if (from as i64) >= 0 && from >= source.size {
        0
    } else {
        a[4].min(source.size.wrapping_sub(from))
    };
    if (to as i64) >= 0 {
        count = count.min(size_room(c, to)?);
    }
    if same_mount
        && source.inode == target.inode
        && to.wrapping_add(count) > from
        && to < from.wrapping_add(count)
    {
        return Err(Errno::EINVAL);
    }
    for start in [from, to] {
        if (start as i64) < 0
            || start
                .checked_add(count)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(Errno::EINVAL);
        }
    }
    let count = count.min(MAX_RW_COUNT as u64);
    if count == 0 {
        return Ok(0);
    }
    let copied = copy_bytes(&input.file, from, &output.file, to, count)?;
    for (pointer, file, start) in [(a[1], &input.file, from), (a[3], &output.file, to)] {
        if pointer != 0 {
            c.mem
                .write_u64(GuestAddr(pointer), start + copied)
                .map_err(|_| Errno::EFAULT)?;
        } else {
            file.seek((start + copied) as i64, 0)?;
        }
    }
    Ok(copied)
}
/// `sendfile(out_fd, in_fd, offset, count)`, in the order of Linux's
/// do_sendfile: the input must be a readable regular file, and the output a
/// writable file without O_APPEND. Given an offset, the input's position
/// stays and the offset is written back, even after an error.
fn sendfile(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let offset = offset_argument(c, a[2])?;
    let result = send(c, a[0], a[1], offset, a[3]);
    if let Some(start) = offset {
        let sent = result.as_ref().map_or(0, |sent| *sent);
        c.mem
            .write_u64(GuestAddr(a[2]), start + sent)
            .map_err(|_| Errno::EFAULT)?;
    }
    result
}
fn send(
    c: &mut Context<'_>,
    out: u64,
    fd: u64,
    offset: Option<u64>,
    count: u64,
) -> Result<u64, Errno> {
    let input = c.files.descriptor(fd)?.file;
    if input.flags() & 3 == 1 {
        return Err(Errno::EBADF);
    }
    // An offset needs a file with a position (ESPIPE); without one, a pipe
    // input is at 0 and fails below as no regular file.
    let position = input.seek(0, 1);
    let from = match offset {
        Some(offset) => position.map(|_| offset).map_err(|_| Errno::ESPIPE)?,
        None => position.unwrap_or(0),
    };
    if (count as i64) < 0
        || (from as i64) < 0
        || from
            .checked_add(count)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(Errno::EINVAL);
    }
    let count = count.min(MAX_RW_COUNT as u64);
    let output = c.files.descriptor(out)?.file;
    if output.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    let pipe = output
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::sockets::PipeEnd>())
        .map(crate::sockets::PipeEnd::size);
    // do_splice_direct refuses O_APPEND; a pipe output does not use it.
    if pipe.is_none() && output.flags() & 0o2000 != 0 {
        return Err(Errno::EINVAL);
    }
    if count == 0 {
        return Ok(0);
    }
    let source = input.stat()?;
    if source.mode & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    let count = count.min(source.size.saturating_sub(from));
    if count == 0 {
        return Ok(0);
    }
    let sent = if output.stat()?.mode & 0o170000 == REGULAR {
        let to = output.seek(0, 1)?;
        let count = count.min(size_room(c, to)?);
        let sent = copy_bytes(&input, from, &output, to, count)?;
        output.seek((to + sent) as i64, 0)?;
        sent
    } else {
        // A pipe takes at most what it holds, as splice_file_to_pipe does;
        // other files take 1 MiB pieces until a short write.
        let count = pipe.map_or(count, |size| count.min(size));
        let mut piece = buffer(usize::try_from(count).unwrap_or(usize::MAX).min(1 << 20))?;
        let mut sent = 0;
        while sent < count {
            let want = usize::try_from(count - sent).map_or(piece.len(), |n| n.min(piece.len()));
            let written = read_at(&input, from + sent, &mut piece[..want])
                .and_then(|read| Ok((read, write_io(c, &output, &piece[..read], false)?)));
            let (read, written) = match written {
                Ok(counts) => counts,
                Err(_) if sent > 0 => break,
                Err(error) => return Err(error),
            };
            sent += written;
            if read == 0 || written < read as u64 {
                break;
            }
        }
        sent
    };
    if offset.is_none() {
        input.seek((from + sent) as i64, 0)?;
    }
    Ok(sent)
}
/// The `struct iovec` array of readv, writev and their positioned forms, as
/// Linux's `import_iovec` reads it: at most 1024 entries (EINVAL), each
/// buffer accessible (EFAULT), and the total cut to `MAX_RW_COUNT`.
pub(crate) fn iovecs(
    c: &Context<'_>,
    at: u64,
    count: u64,
    write: bool,
) -> Result<Vec<(u64, usize)>, Errno> {
    iovecs_checked(c, at, count, |base, length| {
        if write {
            c.mem.check_write(GuestAddr(base), length)
        } else {
            c.mem.check_read(GuestAddr(base), length)
        }
        .map_err(|_| Errno::EFAULT)
    })
}
/// [`iovecs`] with `check` for each buffer in place of the access check.
pub(crate) fn iovecs_checked(
    c: &Context<'_>,
    at: u64,
    count: u64,
    check: impl Fn(u64, usize) -> Result<(), Errno>,
) -> Result<Vec<(u64, usize)>, Errno> {
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
        check(base, length)?;
        total += length;
        segments.push((base, length));
    }
    Ok(segments)
}
/// Copies `bytes` into the guest buffers of `segments`, in order.
pub(crate) fn scatter(
    c: &Context<'_>,
    segments: &[(u64, usize)],
    mut bytes: &[u8],
) -> Result<(), Errno> {
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
    wait_for_read(c, file, false, || file.read(b))
}
/// Repeats `read` while it finds nothing yet (EAGAIN) and `file` blocks:
/// neither `O_NONBLOCK` nor, with `dontwait`, `MSG_DONTWAIT`.
pub(crate) fn wait_for_read<T>(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    dontwait: bool,
    mut read: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        match read() {
            Err(e)
                if e == Errno::EAGAIN
                    && !dontwait
                    && file.readiness().is_ok()
                    && file.flags() & crate::events::NONBLOCK == 0 =>
            {
                crate::events::wait(c, ticket, None)?
            }
            result => return result,
        }
    }
}
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
/// AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC; both together are invalid.
const AT_STATX_SYNC_TYPE: u64 = 0x6000;
/// STATX_TYPE ... STATX_BLOCKS: the fields a `stat` also has.
const STATX_BASIC_STATS: u32 = 0x7ff;
/// `statx(dirfd, path, flags, mask, buffer)`, with the checks of Linux's
/// do_statx and vfs_statx. As since Linux 6.11, a null path with
/// AT_EMPTY_PATH names the descriptor like an empty one.
fn statx(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (dir, flags, mask, out) = (a[0], a[2], a[3] as u32, a[4]);
    let raw = if a[1] == 0 && flags & AT_EMPTY_PATH != 0 {
        Vec::new()
    } else {
        path(c, a[1])?
    };
    if mask & 0x8000_0000 != 0 || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
        return Err(Errno::EINVAL);
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0 {
        return Err(Errno::EINVAL);
    }
    let (s, device) = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dir as i32 == -100 {
            let cwd = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            (c.files.fs.metadata(&cwd, true)?, device(c, &cwd))
        } else {
            let d = c.files.descriptor(dir)?;
            (d.file.stat()?, descriptor_device(c, &d))
        }
    } else {
        let p = c.files.path(dir, raw)?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        match generated_stat(c, &p, follow) {
            Some(generated) => generated,
            None => (c.files.fs.metadata(&p, follow)?, device(c, &p)),
        }
    };
    output(c, out, &encode_statx(s, device)?)?;
    Ok(0)
}
/// `struct statx` with what [`encode_stat`] gives a `struct stat`: the basic
/// fields, no birth time, and the mount's number as the device minor.
fn encode_statx(s: FileStat, device: u64) -> Result<[u8; 256], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 256];
    b[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    b[4..8].copy_from_slice(&4096u32.to_le_bytes());
    b[16..20].copy_from_slice(&u32::try_from(s.links).unwrap_or(u32::MAX).to_le_bytes());
    b[28..30].copy_from_slice(&(s.mode as u16).to_le_bytes());
    b[32..40].copy_from_slice(&s.inode.to_le_bytes());
    b[40..48].copy_from_slice(&s.size.to_le_bytes());
    b[48..56].copy_from_slice(&blocks(&s).to_le_bytes());
    b[112..120].copy_from_slice(&seconds.to_le_bytes());
    b[120..124].copy_from_slice(&(nanos as u32).to_le_bytes());
    // Linux's encoding of a device number into its major and minor.
    let split = |device: u64| {
        (
            ((device >> 8) & 0xfff) as u32,
            ((device & 0xff) | ((device >> 12) & !0xff)) as u32,
        )
    };
    let (rdev_major, rdev_minor) = split(s.rdev);
    b[128..132].copy_from_slice(&rdev_major.to_le_bytes());
    b[132..136].copy_from_slice(&rdev_minor.to_le_bytes());
    let (major, minor) = split(device);
    b[136..140].copy_from_slice(&major.to_le_bytes());
    b[140..144].copy_from_slice(&minor.to_le_bytes());
    Ok(b)
}
/// `stat` of a file at guest `path`: its `st_dev` names the mount holding
/// it, numbered as /proc/self/mountinfo numbers mounts (0:1 is the root).
fn stat(c: &Context<'_>, addr: u64, s: FileStat, device: u64) -> Result<u64, Errno> {
    let mut bytes = encode_stat(s)?;
    bytes[0..8].copy_from_slice(&device.to_le_bytes());
    output(c, addr, &bytes)?;
    Ok(0)
}
/// The device of the file a descriptor holds: a memfd's own (it is on no
/// mount), else that of the mount holding its path.
fn descriptor_device(c: &Context<'_>, d: &Descriptor) -> u64 {
    if d.file
        .as_any()
        .is_some_and(|v| v.is::<crate::memfd::Memfd>())
    {
        crate::memfd::DEVICE
    } else {
        device(c, &d.path)
    }
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
/// `st_blocks`: what the file system counts, or the size in 512-byte blocks.
fn blocks(s: &FileStat) -> u64 {
    s.blocks.unwrap_or(s.size.div_ceil(512))
}
fn encode_stat(s: FileStat) -> Result<[u8; 144], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 144];
    b[8..16].copy_from_slice(&s.inode.to_le_bytes());
    b[16..24].copy_from_slice(&s.links.to_le_bytes());
    b[24..28].copy_from_slice(&s.mode.to_le_bytes());
    b[40..48].copy_from_slice(&s.rdev.to_le_bytes());
    b[48..56].copy_from_slice(&s.size.to_le_bytes());
    b[56..64].copy_from_slice(&4096u64.to_le_bytes());
    b[64..72].copy_from_slice(&blocks(&s).to_le_bytes());
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
        40 => sendfile(c, a),
        332 => statx(c, a),
        326 => copy_file_range(c, a),
        436 => close_range(c, a),
        285 => fallocate(c, a),
        319 => crate::memfd::memfd_create(c, a),
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
            let len = size_limited(c, &file, Some(a[3]), len)?;
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
            let len = size_limited(c, &file, Some(a[3]), len)?;
            let mut b = Vec::new();
            b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            for &(base, length) in &segments {
                let start = b.len();
                b.resize(start + length, 0);
                c.mem
                    .read(GuestAddr(base), &mut b[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            b.truncate(len);
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
            let len = size_limited(c, &descriptor.file, None, bytes.len())?;
            write_io(c, &descriptor.file, &bytes[..len], false)
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
            } else if let Some(d) = &d {
                size_limited(c, &d.file, None, requested)?
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
            let opened = open_path(c, &p, flags, mode as u32);
            match opened {
                Ok((file, path)) => {
                    let cloexec = flags & 0x80000 != 0;
                    c.files.fill(
                        fd,
                        Descriptor {
                            file,
                            path,
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
                    return stat(c, a[2], d.file.stat()?, descriptor_device(c, &d));
                }
                (c.files.path(a[0], raw)?, a[2], a[3] & 0x100 == 0)
            } else {
                (at(c, (-100i32) as u64, a[0])?, a[1], n == 4)
            };
            if let Some((generated, device)) = generated_stat(c, &p, follow) {
                return stat(c, out, generated, device);
            }
            stat(c, out, c.files.fs.metadata(&p, follow)?, device(c, &p))
        }
        5 => {
            let d = c.files.descriptor(a[0])?;
            stat(c, a[1], d.file.stat()?, descriptor_device(c, &d))
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
                // F_ADD_SEALS and F_GET_SEALS, for memfds only.
                1033 | 1034 => {
                    let memfd = d
                        .file
                        .as_any()
                        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
                    match (a[1], memfd) {
                        (1034, Some(memfd)) => Ok(u64::from(memfd.seals())),
                        (1033, Some(memfd)) => {
                            memfd.add_seals(d.file.flags() & 3 != 0, a[2] as u32)?;
                            Ok(0)
                        }
                        // memfd_add_seals checks the access and the bits first.
                        (1033, None) if d.file.flags() & 3 == 0 => Err(Errno::EPERM),
                        _ => Err(Errno::EINVAL),
                    }
                }
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
            // Growing a file past RLIMIT_FSIZE raises SIGXFSZ (inode_newsize_ok).
            if a[1] > c.group.fsize() && f.stat()?.size < a[1] {
                crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
                return Err(Errno(27));
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
            // `/proc/self` is a link to this process's directory, and each
            // entry of its `fd` to a descriptor's file.
            let p = crate::devices::through_link(&p).unwrap_or(p);
            let b = if p == b"/proc/self" {
                c.process.pid.to_string().into_bytes()
            } else if let Some(entry) = crate::devices::entry(&p) {
                let crate::devices::Entry::Link(target) = entry else {
                    return Err(Errno::EINVAL);
                };
                target.to_vec()
            } else if let Some(entry) = crate::proc::own_entry(&p, c.process.pid) {
                let crate::proc::OwnEntry::Descriptor(n) = entry else {
                    return Err(Errno::EINVAL);
                };
                let d = c
                    .files
                    .descriptor(u64::from(n))
                    .map_err(|_| Errno::ENOENT)?;
                link_target(c, &d)?
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
            let entries = match crate::proc::own_entry(&d.path, c.process.pid) {
                Some(crate::proc::OwnEntry::Descriptors) => descriptor_entries(c),
                _ if crate::devices::entry(&d.path) == Some(crate::devices::Entry::Directory) => {
                    crate::devices::entries(c.files.fs.metadata(b"/", true)?.inode)
                }
                _ => c.files.fs.read_dir(&d.path)?,
            };
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
    write_with(c, file, bytes, nosignal, false, |b| file.write(b))
}
/// [`write_io`] through `write`, which writes to `file`; with `dontwait`
/// (`MSG_DONTWAIT`) it does not wait, as if `file` were nonblocking.
pub(crate) fn write_with(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
    dontwait: bool,
    mut write: impl FnMut(&[u8]) -> Result<usize, Errno>,
) -> Result<u64, Errno> {
    let stream = file
        .as_any()
        .is_some_and(|a| a.is::<crate::sockets::SocketPairEnd>());
    let mut done = 0;
    loop {
        let ticket = c.files.readiness.token.value();
        let nonblocking = dontwait || file.flags() & crate::events::NONBLOCK != 0;
        match write(&bytes[done..]) {
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
    /// For edge-triggered epoll on standard input: how often it has become
    /// ready, and whether it was ready when last asked.
    rises: AtomicU64,
    was_ready: std::sync::atomic::AtomicBool,
}
impl FileHandle for StandardFile {
    fn stdio_channel(&self) -> Option<u32> {
        Some(self.channel)
    }
    /// For epoll: standard input is readable as `poll` finds it, and hung
    /// up as well at its end; the output streams are writable. A host stream
    /// has no generation of its own, so the input's counts each time it
    /// becomes ready, and an edge-triggered interest sees that.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        if self.channel != 0 {
            return Ok((4, 0, 0));
        }
        let mask = match self.host.stdin_state() {
            Some(paludarium_host::StdinState::Waiting) => 0,
            Some(paludarium_host::StdinState::Ended) => 1 | 0x10,
            _ => 1,
        };
        let ready = mask != 0;
        if ready && !self.was_ready.swap(true, Ordering::SeqCst) {
            self.rises.fetch_add(1, Ordering::SeqCst);
        } else if !ready {
            self.was_ready.store(false, Ordering::SeqCst);
        }
        Ok((mask, self.rises.load(Ordering::SeqCst), 0))
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
            rdev: 0,
            blocks: None,
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

/// The file that opening guest path `p` gives, and the path its descriptor
/// records: the generated files, a link in `/proc/self/fd` opened again,
/// or the filesystem's file.
fn open_path(
    c: &mut Context<'_>,
    p: &[u8],
    flags: u32,
    mode: u32,
) -> Result<(Arc<dyn FileHandle>, Vec<u8>), Errno> {
    const O_NOFOLLOW: u32 = 0o400000;
    if let Some(target) = crate::devices::through_link(p) {
        return open_path(c, &target, flags, mode);
    }
    let file: Arc<dyn FileHandle> = if let Some(entry) = crate::devices::entry(p) {
        const O_DIRECTORY: u32 = 0o200000;
        match entry {
            // A directory opens only for reading, a device not as one.
            crate::devices::Entry::Directory if flags & 3 != 0 => return Err(Errno::EISDIR),
            crate::devices::Entry::Directory => Arc::new(crate::proc::OwnDirectory::new(
                crate::devices::directory_stat(),
            )),
            crate::devices::Entry::Device(_) if flags & O_DIRECTORY != 0 => {
                return Err(Errno::ENOTDIR);
            }
            crate::devices::Entry::Device(kind) => Arc::new(crate::devices::Device::new(
                kind,
                flags,
                Some(Arc::clone(c.shared_host)),
            )),
            crate::devices::Entry::Link(_) if flags & O_NOFOLLOW != 0 => {
                return Err(Errno(40)); // ELOOP
            }
            crate::devices::Entry::Link(target) => return open_path(c, target, flags, mode),
        }
    } else if let Some(mountinfo) = crate::proc::mount_table(p) {
        let content = crate::proc::render(&c.files.fs.mounts(), mountinfo);
        Arc::new(crate::proc::GeneratedFile::open(content, flags))
    } else if let Some(entry) = crate::proc::own_entry(p, c.process.pid) {
        match entry {
            crate::proc::OwnEntry::Directory => {
                Arc::new(crate::proc::OwnDirectory::new(crate::proc::directory_stat()))
            }
            crate::proc::OwnEntry::Descriptors => Arc::new(crate::proc::OwnDirectory::new(
                crate::proc::descriptors_stat(),
            )),
            crate::proc::OwnEntry::Status => {
                Arc::new(crate::proc::GeneratedFile::open(status(c), flags))
            }
            crate::proc::OwnEntry::Descriptor(n) => return reopen(c, n, flags, mode),
        }
    } else {
        c.files.fs.open(p, flags, mode & !c.files.umask())?
    };
    Ok((file, p.to_vec()))
}
/// Opening `/proc/self/fd/<n>`: a new handle on the file descriptor `n`
/// holds, as Linux opens the link's file again. A file with a path is opened
/// again by it while the path still names that file; a memfd gets a new
/// handle on its file; a pipe or the standard streams give the same handle
/// for the access it has. The rest, and a removed file, cannot be opened
/// again: a socket gives ENXIO, as on Linux, and so do the others here.
fn reopen(
    c: &mut Context<'_>,
    n: u32,
    flags: u32,
    mode: u32,
) -> Result<(Arc<dyn FileHandle>, Vec<u8>), Errno> {
    const ENXIO: Errno = Errno(6);
    let d = c
        .files
        .descriptor(u64::from(n))
        .map_err(|_| Errno::ENOENT)?;
    if let Some(memfd) = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
    {
        return Ok((memfd.reopen(flags)?, Vec::new()));
    }
    let stat = d.file.stat()?;
    match stat.mode & 0o170000 {
        0o010000 if d.path.is_empty() => {
            if flags & 3 == d.file.flags() & 3 {
                Ok((d.file, Vec::new()))
            } else {
                Err(ENXIO)
            }
        }
        _ if d.path.is_empty() => Err(ENXIO),
        _ if generated(&d.path) => open_path(c, &d.path.clone(), flags, mode),
        _ => match current_path(c, &d, stat.inode) {
            Some(path) => open_path(c, &path, flags, mode),
            None => Err(ENXIO),
        },
    }
}
/// Whether `path` is one of the generated files, which no filesystem holds.
fn generated(path: &[u8]) -> bool {
    crate::devices::entry(path).is_some() || path.starts_with(b"/proc/")
}
/// `path` as `realpath` gives it: absolute, with `.`, `..` and every
/// symbolic link resolved one component at a time (at most 40 links, as
/// Linux follows), or `None` when a component is missing.
fn resolved(c: &Context<'_>, path: &[u8]) -> Option<Vec<u8>> {
    const SYMLINK: u32 = 0o120000;
    let mut pending: Vec<Vec<u8>> = path
        .split(|&b| b == b'/')
        .rev()
        .map(<[u8]>::to_vec)
        .collect();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut links = 0;
    let join = |parts: &[Vec<u8>]| -> Vec<u8> {
        let joined = parts
            .iter()
            .flat_map(|p| [&b"/"[..], p].concat())
            .collect::<Vec<_>>();
        if joined.is_empty() {
            b"/".to_vec()
        } else {
            joined
        }
    };
    while let Some(part) = pending.pop() {
        match &part[..] {
            b"" | b"." => continue,
            b".." => {
                parts.pop();
                continue;
            }
            _ => {}
        }
        parts.push(part);
        let candidate = join(&parts);
        if c.files.fs.metadata(&candidate, false).ok()?.mode & 0o170000 == SYMLINK {
            links += 1;
            if links > 40 {
                return None;
            }
            let target = c.files.fs.readlink(&candidate).ok()?;
            parts.pop();
            if target.first() == Some(&b'/') {
                parts.clear();
            }
            pending.extend(target.split(|&b| b == b'/').rev().map(<[u8]>::to_vec));
        }
    }
    Some(join(&parts))
}
/// The path that still names the file of `d` (its recorded path resolved),
/// or `None` once nothing does.
fn current_path(c: &Context<'_>, d: &Descriptor, inode: u64) -> Option<Vec<u8>> {
    let path = resolved(c, &d.path)?;
    c.files
        .fs
        .metadata(&path, false)
        .is_ok_and(|s| s.inode == inode)
        .then_some(path)
}
/// What a link in `/proc/self/fd` reads: the path of a file on a mount
/// (marked ` (deleted)` once removed), `pipe:[<inode>]`, `socket:[<inode>]`,
/// `anon_inode:[<kind>]` for a file of no type, or a memfd's own name.
fn link_target(c: &Context<'_>, d: &Descriptor) -> Result<Vec<u8>, Errno> {
    let any = d.file.as_any();
    if let Some(memfd) = any.and_then(|v| v.downcast_ref::<crate::memfd::Memfd>()) {
        return Ok(memfd.link_target());
    }
    let stat = d.file.stat()?;
    let anonymous = |kind: &str| format!("anon_inode:[{kind}]").into_bytes();
    Ok(match stat.mode & 0o170000 {
        0o010000 if d.path.is_empty() => format!("pipe:[{}]", stat.inode).into_bytes(),
        0o140000 => format!("socket:[{}]", stat.inode).into_bytes(),
        0 => anonymous(match any {
            Some(v) if v.is::<crate::events::EventCounter>() => "eventfd",
            Some(v) if v.is::<crate::epoll::EpollInstance>() => "eventpoll",
            Some(v) if v.is::<crate::timerfd::TimerFile>() => "timerfd",
            // The last kind of no type; Linux 6.9 and later name it from
            // pidfs instead.
            _ => "pidfd",
        }),
        _ if generated(&d.path) => match d.path.strip_prefix(b"/proc/self") {
            Some(rest) => [format!("/proc/{}", c.process.pid).as_bytes(), rest].concat(),
            None => d.path.clone(),
        },
        _ => current_path(c, d, stat.inode).unwrap_or_else(|| {
            let mut path =
                paludarium_vfs::normalize_path(&d.path).unwrap_or_else(|_| d.path.clone());
            path.extend_from_slice(b" (deleted)");
            path
        }),
    })
}
/// The entries of `/proc/self/fd`: `.`, `..` and a link per descriptor, in
/// order, as Linux lists them.
fn descriptor_entries(c: &Context<'_>) -> Vec<paludarium_host::DirectoryEntry> {
    const DT_DIR: u8 = 4;
    const DT_LNK: u8 = 10;
    let fds = c.files.fds.lock().unwrap_or_else(PoisonError::into_inner);
    [b".".to_vec(), b"..".to_vec()]
        .into_iter()
        .map(|name| (name, DT_DIR))
        .chain(fds.keys().map(|n| (n.to_string().into_bytes(), DT_LNK)))
        .enumerate()
        .map(|(i, (name, kind))| paludarium_host::DirectoryEntry {
            name,
            inode: i as u64 + 1,
            kind,
        })
        .collect()
}
/// The `stat` of a generated /proc path, and its device, or `None` for any
/// other path (and for a link to a descriptor that is not open). A link in
/// `/proc/self/fd` is followed to its file unless `follow` is false.
fn generated_stat(c: &Context<'_>, path: &[u8], follow: bool) -> Option<(FileStat, u64)> {
    if let Some(target) = crate::devices::through_link(path) {
        return generated_stat(c, &target, follow);
    }
    match crate::devices::entry(path) {
        Some(crate::devices::Entry::Link(target)) if follow => {
            return generated_stat(c, target, follow);
        }
        Some(entry) => return Some((crate::devices::stat(entry), device(c, path))),
        None => {}
    }
    if let Some(mountinfo) = crate::proc::mount_table(path) {
        let length = crate::proc::render(&c.files.fs.mounts(), mountinfo).len();
        return Some((crate::proc::stat(length), device(c, path)));
    }
    let stat = match crate::proc::own_entry(path, c.process.pid)? {
        crate::proc::OwnEntry::Directory => crate::proc::directory_stat(),
        crate::proc::OwnEntry::Descriptors => crate::proc::descriptors_stat(),
        crate::proc::OwnEntry::Status => crate::proc::stat(status(c).len()),
        crate::proc::OwnEntry::Descriptor(n) => {
            let d = c.files.descriptor(u64::from(n)).ok()?;
            if follow {
                return Some((d.file.stat().ok()?, descriptor_device(c, &d)));
            }
            crate::proc::link_stat(d.file.flags() & 3)
        }
    };
    Some((stat, device(c, path)))
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
