//! Typed host filesystem boundary. Guest syscall numbers never cross it.
use paludarium_types::Errno;
use std::sync::Arc;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStat {
    pub inode: u64,
    pub size: u64,
    pub mode: u32,
    pub links: u64,
    /// Signed nanoseconds since the Unix epoch; includes the former u64 range.
    pub mtime_ns: i128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: Vec<u8>,
    pub inode: u64,
    pub kind: u8,
}
pub trait FileHandle: Send + Sync {
    /// Guest poll mask and separate rising-edge generations for input/output.
    /// Kernel-owned descriptions override this; ordinary files cannot join epoll.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Err(Errno::EPERM)
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
    fn stdio_channel(&self) -> Option<u32> {
        None
    }
    fn guest_path_hint(&self) -> Option<Vec<u8>> {
        None
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno>;
    fn write(&self, buf: &[u8]) -> Result<usize, Errno>;
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno>;
    fn stat(&self) -> Result<FileStat, Errno>;
    fn truncate(&self, size: u64) -> Result<(), Errno>;
    /// Nonblocking attempt. Kernel owns interruptible blocking retries.
    fn flock(&self, op: u32) -> Result<(), Errno>;
    fn flags(&self) -> u32;
    fn set_flags(&self, flags: u32) -> Result<(), Errno>;
    /// `fchmod`: replaces the permission bits with the low 12 bits of `mode`.
    fn set_mode(&self, _mode: u32) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }
    /// `futimens`: sets the access and modification times in nanoseconds
    /// since the Unix epoch; `None` leaves that time as it is.
    fn set_times(&self, _atime: Option<i128>, _mtime: Option<i128>) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }
    /// `fsync` and `fdatasync`. Kinds that cannot be synchronised (pipes,
    /// sockets, terminals, devices) give `EINVAL`, as on Linux.
    fn sync(&self) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
}
pub trait HostFs: Send + Sync {
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno>;
    fn metadata(&self, path: &[u8], follow: bool) -> Result<FileStat, Errno>;
    fn mkdir(&self, path: &[u8], mode: u32) -> Result<(), Errno>;
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno>;
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno>;
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno>;
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno>;
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno>;
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno>;
    /// `chmod`: replaces the permission bits of `path` (following a final
    /// symbolic link) with the low 12 bits of `mode`.
    fn set_mode(&self, _path: &[u8], _mode: u32) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }
    /// `utimensat`: as [`FileHandle::set_times`], for `path`; with `follow`
    /// false a final symbolic link itself is changed.
    fn set_times(
        &self,
        _path: &[u8],
        _follow: bool,
        _atime: Option<i128>,
        _mtime: Option<i128>,
    ) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }
}
