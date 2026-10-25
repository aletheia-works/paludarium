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
    /// A device file's number, as `stat`'s `st_rdev` encodes it (0 for any
    /// other file).
    pub rdev: u64,
    /// The 512-byte blocks the file takes (`st_blocks`), when the file
    /// system counts them; otherwise its size rounded up to them.
    pub blocks: Option<u64>,
}
/// What `statfs` reports about the filesystem holding a path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsStats {
    /// Linux's `f_type` magic number.
    pub kind: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u64,
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
    /// Reads from `offset` without moving the file position, filling `buf`
    /// unless the file ends first; `mmap` copies a file in with it. Kinds
    /// that cannot be mapped (pipes, sockets, terminals, devices, generated
    /// files) give `ENODEV`, as on Linux.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::ENODEV)
    }
    /// Writes `buf` at `offset` without moving the file position (`pwrite`);
    /// an `O_APPEND` file appends instead, as on Linux. Kinds without it give
    /// `ENODEV`, and the kernel then writes through the file position.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Errno> {
        Err(Errno::ENODEV)
    }
    /// `fallocate`'s `FALLOC_FL_PUNCH_HOLE`: the bytes from `offset` to
    /// `offset + len` read as zeros afterwards, at those offsets even in an
    /// `O_APPEND` file, and the size stays; a file with holes frees the pages
    /// the range covers. Kinds without it give `EOPNOTSUPP`.
    fn zero_range(&self, _offset: u64, _len: u64) -> Result<(), Errno> {
        Err(Errno(95))
    }
    /// `fallocate` without a mode: allocates the range without changing what
    /// it reads. A file without holes has every byte allocated already.
    fn allocate(&self, _offset: u64, _len: u64) -> Result<(), Errno> {
        Ok(())
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
    /// `statfs`: the filesystem that holds `path` (which must exist).
    fn statfs(&self, _path: &[u8]) -> Result<FsStats, Errno> {
        Err(Errno::ENOSYS)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A file and a filesystem that have only the methods they must have.
    struct BareFile;
    struct BareFs;
    impl FileHandle for BareFile {
        fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
            Ok(0)
        }
        fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
            Ok(buf.len())
        }
        fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
            Ok(0)
        }
        fn stat(&self) -> Result<FileStat, Errno> {
            Ok(FileStat::default())
        }
        fn truncate(&self, _: u64) -> Result<(), Errno> {
            Ok(())
        }
        fn flock(&self, _: u32) -> Result<(), Errno> {
            Ok(())
        }
        fn flags(&self) -> u32 {
            0
        }
        fn set_flags(&self, _: u32) -> Result<(), Errno> {
            Ok(())
        }
    }
    impl HostFs for BareFs {
        fn open(&self, _: &[u8], _: u32, _: u32) -> Result<Arc<dyn FileHandle>, Errno> {
            Ok(Arc::new(BareFile))
        }
        fn metadata(&self, _: &[u8], _: bool) -> Result<FileStat, Errno> {
            Ok(FileStat::default())
        }
        fn mkdir(&self, _: &[u8], _: u32) -> Result<(), Errno> {
            Ok(())
        }
        fn unlink(&self, _: &[u8], _: bool) -> Result<(), Errno> {
            Ok(())
        }
        fn link(&self, _: &[u8], _: &[u8]) -> Result<(), Errno> {
            Ok(())
        }
        fn symlink(&self, _: &[u8], _: &[u8]) -> Result<(), Errno> {
            Ok(())
        }
        fn readlink(&self, _: &[u8]) -> Result<Vec<u8>, Errno> {
            Ok(Vec::new())
        }
        fn rename(&self, _: &[u8], _: &[u8]) -> Result<(), Errno> {
            Ok(())
        }
        fn read_dir(&self, _: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_file_without_the_optional_methods_refuses_them_as_linux_does() {
        let file = BareFile;
        // The required methods, which the stand-in answers trivially.
        assert_eq!(file.read(&mut [0]), Ok(0));
        assert_eq!((file.write(b"x"), file.seek(0, 0)), (Ok(1), Ok(0)));
        assert_eq!(file.stat(), Ok(FileStat::default()));
        assert_eq!((file.truncate(0), file.flock(0)), (Ok(()), Ok(())));
        assert_eq!((file.flags(), file.set_flags(0)), (0, Ok(())));
        assert_eq!(file.readiness(), Err(Errno::EPERM));
        assert!(file.as_any().is_none());
        assert_eq!(file.stdio_channel(), None);
        assert_eq!(file.guest_path_hint(), None);
        assert_eq!(file.set_mode(0o644), Err(Errno::EPERM));
        assert_eq!(file.set_times(Some(1), None), Err(Errno::EPERM));
        assert_eq!(file.sync(), Err(Errno::EINVAL));
        assert_eq!(file.read_at(0, &mut [0; 4]), Err(Errno::ENODEV));
        assert_eq!(file.write_at(0, b"x"), Err(Errno::ENODEV));
        assert_eq!(file.zero_range(0, 1), Err(Errno(95))); // EOPNOTSUPP
    }

    #[test]
    fn a_filesystem_without_the_optional_methods_refuses_them() {
        let fs = BareFs;
        assert!(fs.open(b"/a", 0, 0).is_ok());
        assert_eq!(fs.metadata(b"/a", true), Ok(FileStat::default()));
        assert_eq!(
            (fs.mkdir(b"/d", 0), fs.unlink(b"/a", false)),
            (Ok(()), Ok(()))
        );
        assert_eq!(
            (fs.link(b"/a", b"/b"), fs.symlink(b"/a", b"/c")),
            (Ok(()), Ok(()))
        );
        assert_eq!(
            (fs.readlink(b"/c"), fs.read_dir(b"/")),
            (Ok(Vec::new()), Ok(Vec::new()))
        );
        assert_eq!(fs.rename(b"/a", b"/e"), Ok(()));
        assert_eq!(fs.statfs(b"/"), Err(Errno::ENOSYS));
        assert_eq!(fs.set_mode(b"/a", 0o644), Err(Errno::EPERM));
        assert_eq!(fs.set_times(b"/a", true, None, Some(1)), Err(Errno::EPERM));
    }
}
