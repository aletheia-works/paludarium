//! `memfd_create` and file seals. A memfd is the one file of its own
//! in-memory filesystem, which nothing else can reach, so it shows no links;
//! it is wrapped so that its seals (`F_ADD_SEALS`, `F_GET_SEALS`) restrict
//! writes, resizes and mode changes as Linux's tmpfs does. Opening it again
//! through `/proc/self/fd` gives a new handle on the same file and seals.
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat, HostFs};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

const MFD_CLOEXEC: u32 = 0x01;
const MFD_ALLOW_SEALING: u32 = 0x02;
const MFD_HUGETLB: u32 = 0x04;
const MFD_NOEXEC_SEAL: u32 = 0x08;
const MFD_EXEC: u32 = 0x10;
/// The huge page size a `MFD_HUGETLB` call may encode in bits 26 to 31.
const MFD_HUGE_SIZES: u32 = 0x3f << 26;
/// NAME_MAX less the `memfd:` prefix Linux puts before the name.
const NAME_MAX: usize = 249;

pub(crate) const F_SEAL_SEAL: u32 = 0x01;
pub(crate) const F_SEAL_SHRINK: u32 = 0x02;
pub(crate) const F_SEAL_GROW: u32 = 0x04;
pub(crate) const F_SEAL_WRITE: u32 = 0x08;
pub(crate) const F_SEAL_FUTURE_WRITE: u32 = 0x10;
pub(crate) const F_SEAL_EXEC: u32 = 0x20;
const PAGE: u64 = 4096;
/// Memfds share a device of their own, as Linux's live on its internal
/// tmpfs mount: minor 0, which no mount here has.
pub(crate) const DEVICE: u64 = 0;
/// Where a memfd's file lives in its own filesystem.
const PATH: &[u8] = b"/memfd";

pub(crate) struct Memfd {
    file: Arc<dyn FileHandle>,
    fs: Arc<paludarium_vfs::MemFs>,
    inode: u64,
    seals: Arc<AtomicU32>,
    /// Held while seals are added and while a shared mapping is made, so
    /// that a mapping that may write and `F_SEAL_WRITE` cannot pass each
    /// other, as Linux's inode lock and `i_mmap_writable` keep them apart.
    sealing: Arc<Mutex<()>>,
    name: Arc<[u8]>,
    /// A `memfd_secret` file ([`memfd_secret`]): no reads or writes, a
    /// size set once, shared mappings only, and its own name.
    secret: bool,
    /// What a secret file's pages charge its creator ([`SecretCharge`]).
    charge: Option<Arc<SecretCharge>>,
}
/// secretmem's `statfs` type, `SECRETMEM_MAGIC`.
pub(crate) const SECRETMEM_MAGIC: u64 = 0x5345_434d;
impl Memfd {
    /// Whether it is a `memfd_secret` file.
    pub(crate) fn is_secret(&self) -> bool {
        self.secret
    }
    /// The name `/proc/self/maps` shows for a mapping of it: its path, which
    /// a secret file shows ` (deleted)` though it has a link, as every
    /// pseudo file's `simple_dname` does.
    pub(crate) fn mapped_name(&self) -> Vec<u8> {
        if self.secret {
            self.link_target()
        } else {
            self.path()
        }
    }
    /// What `/proc/self/fd` shows for it: `/memfd:<name> (deleted)`.
    pub(crate) fn link_target(&self) -> Vec<u8> {
        [&self.path()[..], b" (deleted)"].concat()
    }
    /// Its path, `/memfd:<name>`, which no name links.
    pub(crate) fn path(&self) -> Vec<u8> {
        if self.secret {
            return b"/secretmem".to_vec();
        }
        [b"/memfd:", &self.name[..]].concat()
    }
    /// A new handle on the same file, as opening `/proc/self/fd/<n>` gives:
    /// with the new access mode and flags (`O_CREAT` and `O_EXCL` do nothing
    /// to an existing file). `O_TRUNC` empties it whatever the access mode,
    /// as Linux's open does, unless `F_SEAL_SHRINK` keeps a non-empty file.
    /// A secret file's inode has no open of its own (`no_open`, `ENXIO`).
    pub(crate) fn reopen(&self, flags: u32) -> Result<Arc<Self>, Errno> {
        if self.secret {
            return Err(Errno(6)); // ENXIO
        }
        if flags & 0o1000 != 0 && self.seals() & F_SEAL_SHRINK != 0 && self.file.stat()?.size > 0 {
            return Err(Errno::EPERM);
        }
        let file = self.fs.open(PATH, flags & !0o300 | 0o100000, 0)?;
        Ok(Arc::new(Self {
            file,
            fs: Arc::clone(&self.fs),
            inode: self.inode,
            seals: Arc::clone(&self.seals),
            sealing: Arc::clone(&self.sealing),
            name: Arc::clone(&self.name),
            secret: false,
            charge: None,
        }))
    }
    pub(crate) fn seals(&self) -> u32 {
        self.seals.load(Ordering::SeqCst)
    }
    /// Keeps seals from being added while a shared mapping is made.
    pub(crate) fn lock_seals(&self) -> MutexGuard<'_, ()> {
        self.sealing.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// `F_ADD_SEALS` through a descriptor open for writing or not, in the
    /// order of Linux's memfd_add_seals. `F_SEAL_EXEC` on a file with an
    /// execute bit also seals writes and the size, so that it stays W^X.
    /// Then sealing writes is refused (`EBUSY`) while a shared mapping that
    /// may write shows the file, which `mapped_writable` tells with no
    /// mapping being made meanwhile.
    pub(crate) fn add_seals(
        &self,
        writable: bool,
        seals: u32,
        mapped_writable: impl FnOnce() -> bool,
    ) -> Result<(), Errno> {
        if !writable {
            return Err(Errno::EPERM);
        }
        if seals & !0x3f != 0 {
            return Err(Errno::EINVAL);
        }
        let _sealing = self.lock_seals();
        let current = self.seals();
        if current & F_SEAL_SEAL != 0 {
            return Err(Errno::EPERM);
        }
        let mut seals = seals;
        if seals & F_SEAL_EXEC != 0 && self.file.stat()?.mode & 0o111 != 0 {
            seals |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
        }
        if seals & F_SEAL_WRITE != 0 && current & F_SEAL_WRITE == 0 && mapped_writable() {
            return Err(Errno(16)); // EBUSY
        }
        self.seals
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current & F_SEAL_SEAL == 0).then_some(current | seals)
            })
            .map(|_| ())
            .map_err(|_| Errno::EPERM)
    }
    /// `F_SEAL_GROW` on `fallocate` to `end`, which tmpfs checks even with
    /// `FALLOC_FL_KEEP_SIZE`.
    pub(crate) fn check_allocate(&self, end: u64) -> Result<(), Errno> {
        if self.seals() & F_SEAL_GROW != 0 && end > self.file.stat()?.size {
            return Err(Errno::EPERM);
        }
        Ok(())
    }
    /// How much of a `len`-byte write at `start` the seals let through, as
    /// tmpfs's write_begin: none with a write seal, and with `F_SEAL_GROW`
    /// the pages that end within the file, since Linux writes a page at a
    /// time and stops at the first one that would grow it.
    fn writable(&self, start: u64, len: usize) -> Result<usize, Errno> {
        if len == 0 {
            return Ok(0);
        }
        let seals = self.seals();
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
            return Err(Errno::EPERM);
        }
        let end = start.saturating_add(len as u64);
        if seals & F_SEAL_GROW == 0 {
            return Ok(len);
        }
        let size = self.file.stat()?.size;
        if end <= size {
            return Ok(len);
        }
        match (size / PAGE * PAGE).checked_sub(start) {
            Some(room) if room > 0 => Ok(room as usize),
            _ => Err(Errno::EPERM),
        }
    }
}
impl FileHandle for Memfd {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// A secret file has no `read_iter` (`FMODE_CAN_READ`, `EINVAL`), and
    /// the same for writes.
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        self.file.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        let start = if self.flags() & 0o2000 != 0 {
            self.file.stat()?.size
        } else {
            self.file.seek(0, 1)?
        };
        let count = self.writable(start, buf.len())?;
        self.file.write(&buf[..count])
    }
    /// A secret file has no `llseek` (`FMODE_LSEEK`, `ESPIPE`).
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        if self.secret {
            return Err(Errno::ESPIPE);
        }
        self.file.seek(offset, whence)
    }
    /// A memfd has no link; a secret file's anonymous inode has one, and
    /// counts no blocks.
    fn stat(&self) -> Result<FileStat, Errno> {
        let stat = self.file.stat()?;
        Ok(FileStat {
            inode: self.inode,
            links: u64::from(self.secret),
            blocks: if self.secret { Some(0) } else { stat.blocks },
            ..stat
        })
    }
    /// A secret file's size is set once: `secretmem_setattr` refuses any
    /// other once it has one (`EINVAL`).
    fn truncate(&self, size: u64) -> Result<(), Errno> {
        let old = self.file.stat()?.size;
        if self.secret && old != 0 {
            return Err(Errno::EINVAL);
        }
        let seals = self.seals();
        if (size < old && seals & F_SEAL_SHRINK != 0) || (size > old && seals & F_SEAL_GROW != 0) {
            return Err(Errno::EPERM);
        }
        self.file.truncate(size)
    }
    fn flock(&self, op: u32) -> Result<(), Errno> {
        self.file.flock(op)
    }
    fn flags(&self) -> u32 {
        self.file.flags()
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.file.set_flags(flags)
    }
    /// A memfd is a tmpfs file, with tmpfs's inode flags.
    fn with_attributes(&self, f: &mut dyn FnMut(&mut u32)) -> Result<(), Errno> {
        self.file.with_attributes(f)
    }
    fn cached_pages(&self, first: u64, last: u64) -> u64 {
        self.file.cached_pages(first, last)
    }
    /// `F_SEAL_EXEC` keeps the execute bits as they are.
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        if self.seals() & F_SEAL_EXEC != 0 && (self.file.stat()?.mode ^ mode) & 0o111 != 0 {
            return Err(Errno::EPERM);
        }
        self.file.set_mode(mode)
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.file.set_owner(uid, gid)
    }
    fn set_times(&self, atime: Option<i128>, mtime: Option<i128>) -> Result<(), Errno> {
        self.file.set_times(atime, mtime)
    }
    /// A memfd is shmem's, which a tmpfs is.
    fn file_system(&self) -> Option<u64> {
        Some(if self.secret {
            SECRETMEM_MAGIC
        } else {
            0x0102_1994
        })
    }
    /// A secret file has no `fsync` (`EINVAL`).
    fn sync(&self) -> Result<(), Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        self.file.sync()
    }
    /// For the guest's `pread` and the like; a mapping of a secret file
    /// reads its pages from [`pages_source`].
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        self.file.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        let start = if self.flags() & 0o2000 != 0 {
            self.file.stat()?.size
        } else {
            offset
        };
        let count = self.writable(start, buf.len())?;
        self.file.write_at(offset, &buf[..count])
    }
    fn write_at_unappended(&self, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        if self.secret {
            return Err(Errno::EINVAL);
        }
        let count = self.writable(offset, buf.len())?;
        self.file.write_at_unappended(offset, &buf[..count])
    }
    /// A secret file has no `fallocate` (`EOPNOTSUPP`).
    fn allocate(&self, offset: u64, len: u64) -> Result<(), Errno> {
        if self.secret {
            return Err(Errno::EOPNOTSUPP);
        }
        self.file.allocate(offset, len)
    }
    /// A shared mapping's pages reach the file whatever the seals, as the
    /// mapping existed before them or was made read-only by them.
    fn write_back(&self, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        self.file.write_back(offset, buf)
    }
    fn zero_range(&self, offset: u64, len: u64) -> Result<(), Errno> {
        if self.secret {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.seals() & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
            return Err(Errno::EPERM);
        }
        self.file.zero_range(offset, len)
    }
}

/// `memfd_create(name, flags)`, in the order of Linux's: the flags, then
/// the name (at most 249 bytes, `EINVAL`). With `vm.memfd_noexec` at its
/// default of 0, a call without `MFD_EXEC` or `MFD_NOEXEC_SEAL` gets an
/// executable file. `MFD_HUGETLB` gives `ENOSYS`, as from a kernel built
/// without hugetlbfs.
pub(crate) fn memfd_create(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[1] as u32;
    let known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    let allowed = if flags & MFD_HUGETLB != 0 {
        known | MFD_HUGE_SIZES
    } else {
        known
    };
    if flags & !allowed != 0 || flags & (MFD_EXEC | MFD_NOEXEC_SEAL) == MFD_EXEC | MFD_NOEXEC_SEAL {
        return Err(Errno::EINVAL);
    }
    let mut name = Vec::new();
    loop {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(a[0].wrapping_add(name.len() as u64)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
        name.push(byte[0]);
        if name.len() > NAME_MAX {
            return Err(Errno::EINVAL);
        }
    }
    if flags & MFD_HUGETLB != 0 {
        return Err(Errno::ENOSYS);
    }
    let fs = Arc::new(paludarium_vfs::MemFs::new());
    let mode = if flags & MFD_NOEXEC_SEAL != 0 {
        0o666
    } else {
        0o777
    };
    drop(fs.open(PATH, 0o102, mode)?);
    // Opened again without O_CREAT, so that F_GETFL shows O_RDWR | O_LARGEFILE.
    let file = fs.open(PATH, 0o100002, 0)?;
    // Its inode belongs to the thread's filesystem IDs, as `shmem_get_inode`
    // gives it.
    let credentials = &c.process.credentials;
    file.set_owner(Some(credentials.fsuid), Some(credentials.fsgid))?;
    let seals = if flags & MFD_NOEXEC_SEAL != 0 {
        F_SEAL_EXEC
    } else if flags & MFD_ALLOW_SEALING != 0 {
        0
    } else {
        F_SEAL_SEAL
    };
    let inode = crate::files::anonymous_inode();
    // No name links it: its watches hear `IN_DELETE_SELF` once nothing
    // holds it, as the inode's eviction tells them.
    c.files.caches.notify.unlinked_from_start((DEVICE, inode));
    let memfd = Arc::new(Memfd {
        file,
        fs,
        inode,
        seals: Arc::new(AtomicU32::new(seals)),
        sealing: Arc::default(),
        name: name.into(),
        secret: false,
        charge: None,
    });
    let file =
        crate::page_cache::CoherentFile::with_device(memfd, Arc::clone(&c.files.caches), DEVICE);
    let fd = c
        .files
        .install(Arc::new(file), flags & MFD_CLOEXEC != 0, c.group.nofile())?;
    Ok(u64::from(fd))
}

thread_local! {
    /// The RLIMIT_MEMLOCK soft limit of the process whose thread this host
    /// thread runs, as of its last system call ([`enter`]). Every guest
    /// thread has a host worker of its own (a Web Worker in WebAssembly),
    /// so the limit is never another thread's.
    static MEMLOCK: std::cell::RefCell<Option<Arc<AtomicU64>>> = const { std::cell::RefCell::new(None) };
}

/// Records, as a system call starts, the RLIMIT_MEMLOCK of the process
/// whose thread runs on this host thread: the limit a fault of a secret
/// page counts against, as Linux's `rlimit` reads the faulting task's.
pub(crate) fn enter(memlock: &Arc<AtomicU64>) {
    MEMLOCK.with(|current| {
        let mut current = current.borrow_mut();
        if !current
            .as_ref()
            .is_some_and(|known| Arc::ptr_eq(known, memlock))
        {
            *current = Some(Arc::clone(memlock));
        }
    });
}

/// The `memfd_secret` pages each user has, by kernel user ID: Linux's
/// `locked_vm` of the `user_struct`, for the whole machine.
#[derive(Default)]
pub(crate) struct SecretPages(Mutex<std::collections::BTreeMap<u32, u64>>);

/// What a secret file's pages charge: the user who made it, for each page
/// a fault brought in, until the file goes (Linux's
/// `secretmem_inode_state`). A fault past the faulting process's
/// RLIMIT_MEMLOCK, which the creator's stands for until that process makes
/// a system call, is refused (`SIGBUS`); `CAP_IPC_LOCK` gives no room.
pub(crate) struct SecretCharge {
    pages: Arc<SecretPages>,
    user: u32,
    creator: Arc<AtomicU64>,
    /// The offsets of the pages charged.
    charged: Mutex<std::collections::BTreeSet<u64>>,
}

impl SecretCharge {
    /// Whether the page at `offset` is in the file: charged before, or
    /// charged now if the user's pages stay within the limit
    /// (`__secretmem_account_pages`).
    pub(crate) fn admit(&self, offset: u64) -> bool {
        let page = offset & !4095;
        // The file's own lock, then the machine's: `Drop` takes only the
        // machine's, so the order never inverts.
        let mut charged = self.charged.lock().unwrap_or_else(PoisonError::into_inner);
        if charged.contains(&page) {
            return true;
        }
        let limit = MEMLOCK
            .with(|current| {
                current
                    .borrow()
                    .as_ref()
                    .map(|limit| limit.load(Ordering::SeqCst))
            })
            .unwrap_or_else(|| self.creator.load(Ordering::SeqCst))
            / 4096;
        let mut users = self.pages.0.lock().unwrap_or_else(PoisonError::into_inner);
        let held = users.entry(self.user).or_default();
        if *held + 1 > limit {
            return false;
        }
        *held += 1;
        charged.insert(page);
        true
    }
}

impl Drop for SecretCharge {
    /// The file goes: its pages no longer count (`secretmem_unaccount_all_folios`).
    fn drop(&mut self) {
        let count = self
            .charged
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .len() as u64;
        let mut users = self.pages.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = users.get_mut(&self.user) {
            *held = held.saturating_sub(count);
        }
    }
}

/// What a secret file's pages charge, for the mapping of `file` to take
/// its faults from; `None` for any other file.
pub(crate) fn secret_charge(file: &Arc<dyn FileHandle>) -> Option<Arc<SecretCharge>> {
    file.as_any()
        .and_then(|any| any.downcast_ref::<Memfd>())
        .and_then(|memfd| memfd.charge.clone())
}

/// What a mapping of `file` reads its pages from and writes them back to:
/// for a secret file the file itself, which the guest may not read or
/// write; else `file`.
pub(crate) fn pages_source(file: &Arc<dyn FileHandle>) -> Arc<dyn FileHandle> {
    match file
        .as_any()
        .and_then(|any| any.downcast_ref::<Memfd>())
        .filter(|memfd| memfd.secret)
    {
        Some(memfd) => Arc::clone(&memfd.file),
        None => Arc::clone(file),
    }
}

/// `memfd_secret(flags)`, as Linux's on x86-64, where secretmem is enabled:
/// `O_CLOEXEC` is the only flag (`EINVAL`). The file is a regular file of
/// size 0 and mode 0600, owned by the thread's filesystem IDs, open for
/// reading and writing, on a pseudo filesystem of its own
/// ([`SECRETMEM_MAGIC`]). Its size can be set once, by `ftruncate`, and it
/// can only be mapped shared; it cannot be read, written, sought, synced,
/// allocated, sealed or opened again ([`Memfd`]'s refusals).
pub(crate) fn memfd_secret(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const O_CLOEXEC: u32 = 0o2000000;
    let flags = a[0] as u32;
    if flags & !O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let fs = Arc::new(paludarium_vfs::MemFs::new());
    drop(fs.open(PATH, 0o102, 0o600)?);
    let file = fs.open(PATH, 0o100002, 0)?;
    let credentials = &c.process.credentials;
    file.set_owner(Some(credentials.fsuid), Some(credentials.fsgid))?;
    let inode = crate::files::anonymous_inode();
    let charge = Arc::new(SecretCharge {
        pages: Arc::clone(&c.processes.secret_pages),
        user: credentials.uid,
        creator: Arc::clone(c.group.memlock()),
        charged: Mutex::default(),
    });
    let secret = Arc::new(Memfd {
        file,
        fs,
        inode,
        seals: Arc::new(AtomicU32::new(F_SEAL_SEAL)),
        sealing: Arc::default(),
        name: Arc::from(&b"secretmem"[..]),
        secret: true,
        charge: Some(charge),
    });
    let file =
        crate::page_cache::CoherentFile::with_device(secret, Arc::clone(&c.files.caches), DEVICE);
    let fd = c
        .files
        .install(Arc::new(file), flags & O_CLOEXEC != 0, c.group.nofile())?;
    Ok(u64::from(fd))
}
