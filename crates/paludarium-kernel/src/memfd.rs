//! `memfd_create` and file seals. A memfd is a file of its own in-memory
//! filesystem, unlinked as soon as it is made, wrapped so that its seals
//! (`F_ADD_SEALS`, `F_GET_SEALS`) restrict writes, resizes and mode changes
//! as Linux's tmpfs does.
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat, HostFs};
use paludarium_types::{Errno, GuestAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
/// tmpfs mount: minor 0, which no mount here has. Their inode numbers count
/// up across every memfd, so that two never share one.
pub(crate) const DEVICE: u64 = 0;
static NEXT_INODE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Memfd {
    file: Arc<dyn FileHandle>,
    inode: u64,
    seals: AtomicU32,
}
impl Memfd {
    pub(crate) fn seals(&self) -> u32 {
        self.seals.load(Ordering::SeqCst)
    }
    /// `F_ADD_SEALS` through a descriptor open for writing or not, in the
    /// order of Linux's memfd_add_seals. `F_SEAL_EXEC` on a file with an
    /// execute bit also seals writes and the size, so that it stays W^X.
    pub(crate) fn add_seals(&self, writable: bool, seals: u32) -> Result<(), Errno> {
        if !writable {
            return Err(Errno::EPERM);
        }
        if seals & !0x3f != 0 {
            return Err(Errno::EINVAL);
        }
        let mut seals = seals;
        if seals & F_SEAL_EXEC != 0 && self.file.stat()?.mode & 0o111 != 0 {
            seals |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
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
    // The name is only checked: nothing shows it (there is no /proc/self/fd).
    let mut length = 0;
    loop {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(a[0].wrapping_add(length as u64)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
        length += 1;
        if length > NAME_MAX {
            return Err(Errno::EINVAL);
        }
    }
    if flags & MFD_HUGETLB != 0 {
        return Err(Errno::ENOSYS);
    }
    let fs = paludarium_vfs::MemFs::new();
    let mode = if flags & MFD_NOEXEC_SEAL != 0 {
        0o666
    } else {
        0o777
    };
    drop(fs.open(b"/memfd", 0o102, mode)?);
    // Opened again without O_CREAT, so that F_GETFL shows O_RDWR | O_LARGEFILE.
    let file = fs.open(b"/memfd", 0o100002, 0)?;
    fs.unlink(b"/memfd", false)?;
    let seals = if flags & MFD_NOEXEC_SEAL != 0 {
        F_SEAL_EXEC
    } else if flags & MFD_ALLOW_SEALING != 0 {
        0
    } else {
        F_SEAL_SEAL
    };
    let memfd = Arc::new(Memfd {
        file,
        inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
        seals: AtomicU32::new(seals),
    });
    let fd = c
        .files
        .install(memfd, flags & MFD_CLOEXEC != 0, c.group.nofile())?;
    Ok(u64::from(fd))
}
