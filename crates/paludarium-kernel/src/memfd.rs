//! `memfd_create` and file seals. A memfd is the one file of its own
//! in-memory filesystem, which nothing else can reach, so it shows no links;
//! it is wrapped so that its seals (`F_ADD_SEALS`, `F_GET_SEALS`) restrict
//! writes, resizes and mode changes as Linux's tmpfs does. Opening it again
//! through `/proc/self/fd` gives a new handle on the same file and seals.
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat, HostFs};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicU32, Ordering};
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
}
impl Memfd {
    /// What `/proc/self/fd` shows for it: `/memfd:<name> (deleted)`.
    pub(crate) fn link_target(&self) -> Vec<u8> {
        [b"/memfd:", &self.name[..], b" (deleted)"].concat()
    }
    /// A new handle on the same file, as opening `/proc/self/fd/<n>` gives:
    /// with the new access mode and flags (`O_CREAT` and `O_EXCL` do nothing
    /// to an existing file). `O_TRUNC` empties it whatever the access mode,
    /// as Linux's open does, unless `F_SEAL_SHRINK` keeps a non-empty file.
    pub(crate) fn reopen(&self, flags: u32) -> Result<Arc<Self>, Errno> {
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
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.file.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let start = if self.flags() & 0o2000 != 0 {
            self.file.stat()?.size
        } else {
            self.file.seek(0, 1)?
        };
        let count = self.writable(start, buf.len())?;
        self.file.write(&buf[..count])
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        self.file.seek(offset, whence)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            links: 0,
            ..self.file.stat()?
        })
    }
    fn truncate(&self, size: u64) -> Result<(), Errno> {
        let old = self.file.stat()?.size;
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
    fn sync(&self) -> Result<(), Errno> {
        self.file.sync()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.file.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        let start = if self.flags() & 0o2000 != 0 {
            self.file.stat()?.size
        } else {
            offset
        };
        let count = self.writable(start, buf.len())?;
        self.file.write_at(offset, &buf[..count])
    }
    fn allocate(&self, offset: u64, len: u64) -> Result<(), Errno> {
        self.file.allocate(offset, len)
    }
    /// A shared mapping's pages reach the file whatever the seals, as the
    /// mapping existed before them or was made read-only by them.
    fn write_back(&self, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        self.file.write_back(offset, buf)
    }
    fn zero_range(&self, offset: u64, len: u64) -> Result<(), Errno> {
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
    let seals = if flags & MFD_NOEXEC_SEAL != 0 {
        F_SEAL_EXEC
    } else if flags & MFD_ALLOW_SEALING != 0 {
        0
    } else {
        F_SEAL_SEAL
    };
    let memfd = Arc::new(Memfd {
        file,
        fs,
        inode: crate::files::anonymous_inode(),
        seals: Arc::new(AtomicU32::new(seals)),
        sealing: Arc::default(),
        name: name.into(),
    });
    let file =
        crate::page_cache::CoherentFile::with_device(memfd, Arc::clone(&c.files.caches), DEVICE);
    let fd = c
        .files
        .install(Arc::new(file), flags & MFD_CLOEXEC != 0, c.group.nofile())?;
    Ok(u64::from(fd))
}
