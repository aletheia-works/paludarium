//! Native filesystem operations relative to a retained directory capability.
use crate::{DirectoryEntry, FileHandle, FileStat, HostFs};
#[cfg(windows)]
use cap_fs_ext::OpenOptionsMaybeDirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use fs2::FileExt;
use paludarium_types::Errno;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};
fn err(e: std::io::Error) -> Errno {
    // Only Linux host codes share the guest's errno namespace.
    #[cfg(target_os = "linux")]
    if let Some(code) = e.raw_os_error() {
        return Errno(code);
    }
    match e.kind() {
        std::io::ErrorKind::NotFound => Errno::ENOENT,
        std::io::ErrorKind::PermissionDenied => Errno(13), // EACCES
        std::io::ErrorKind::AlreadyExists => Errno::EEXIST,
        std::io::ErrorKind::NotADirectory => Errno::ENOTDIR,
        std::io::ErrorKind::IsADirectory => Errno::EISDIR,
        std::io::ErrorKind::DirectoryNotEmpty => Errno(39), // ENOTEMPTY
        std::io::ErrorKind::Interrupted => Errno(4),        // EINTR
        std::io::ErrorKind::Unsupported => Errno::ENOSYS,
        _ => crate::errno_from_io(&e),
    }
}
fn lock_err(e: std::io::Error) -> Errno {
    // Windows ERROR_LOCK_VIOLATION is not categorized as WouldBlock by std.
    if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
        Errno::EAGAIN
    } else {
        err(e)
    }
}
fn path(b: &[u8]) -> Result<PathBuf, Errno> {
    if b.contains(&0) {
        return Err(Errno::EINVAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(b)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(
            std::str::from_utf8(b).map_err(|_| Errno::EINVAL)?,
        ))
    }
}
fn bytes(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        p.to_string_lossy().as_bytes().to_vec()
    }
}
fn mtime_ns(time: std::time::SystemTime) -> Result<i128, Errno> {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).map_err(|_| Errno(75)),
        Err(before) => i128::try_from(before.duration().as_nanos())
            .ok()
            .and_then(i128::checked_neg)
            .ok_or(Errno(75)),
    }
}
fn stat(m: std::fs::Metadata) -> Result<FileStat, Errno> {
    let mtime_ns = mtime_ns(m.modified().map_err(|_| Errno::EIO)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileStat {
            inode: m.ino(),
            size: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            mtime_ns,
        })
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        let (inode, links) = {
            use std::os::windows::fs::MetadataExt;
            (
                m.file_index().ok_or(Errno::EIO)?,
                u64::from(m.number_of_links().ok_or(Errno::EIO)?),
            )
        };
        #[cfg(not(windows))]
        let (inode, links) = (0, 1);
        Ok(FileStat {
            inode,
            size: m.len(),
            mode: if m.is_dir() {
                0o040755
            } else if m.is_symlink() {
                0o120777
            } else {
                0o100644
            },
            links,
            mtime_ns,
        })
    }
}
/// Ambient authority is used only to acquire the explicitly configured root.
pub struct NativeFs {
    root: Dir,
}
impl NativeFs {
    pub fn new(root: &Path) -> Result<Self, Errno> {
        Ok(Self {
            root: Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(err)?,
        })
    }
}
struct NativeFile {
    file: Mutex<std::fs::File>,
    flags: Mutex<u32>,
}
impl FileHandle for NativeFile {
    fn read(&self, b: &mut [u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 1 {
            return Err(Errno::EBADF);
        }
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(b)
            .map_err(err)
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 0 {
            return Err(Errno::EBADF);
        }
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(b)
            .map_err(err)
    }
    fn seek(&self, o: i64, w: u32) -> Result<u64, Errno> {
        let s = match w {
            0 => SeekFrom::Start(u64::try_from(o).map_err(|_| Errno::EINVAL)?),
            1 => SeekFrom::Current(o),
            2 => SeekFrom::End(o),
            _ => return Err(Errno::EINVAL),
        };
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seek(s)
            .map_err(err)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        let metadata = self
            .file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .metadata()
            .map_err(err)?;
        stat(metadata)
    }
    fn truncate(&self, n: u64) -> Result<(), Errno> {
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_len(n)
            .map_err(err)
    }
    fn flock(&self, o: u32) -> Result<(), Errno> {
        let f = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        match o & !4 {
            1 => FileExt::try_lock_shared(&*f),
            2 => FileExt::try_lock_exclusive(&*f),
            8 => FileExt::unlock(&*f),
            _ => return Err(Errno::EINVAL),
        }
        .map_err(lock_err)
    }
    fn flags(&self) -> u32 {
        *self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn set_flags(&self, f: u32) -> Result<(), Errno> {
        #[cfg(unix)]
        {
            let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
            let current = rustix::fs::fcntl_getfl(&*file).map_err(|e| err(e.into()))?;
            let mutable = rustix::fs::OFlags::APPEND | rustix::fs::OFlags::NONBLOCK;
            let flags = (current & !mutable) | (rustix::fs::OFlags::from_bits_retain(f) & mutable);
            rustix::fs::fcntl_setfl(&*file, flags).map_err(|e| err(e.into()))?;
            let mut saved = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
            *saved = (*saved & !3072) | (f & 3072);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = f;
            Err(Errno::ENOSYS)
        }
    }
}
impl HostFs for NativeFs {
    fn open(&self, p: &[u8], f: u32, m: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        if f & (64 | 65536) == 64 | 65536 {
            return Err(Errno::EINVAL);
        }
        let mut o = OpenOptions::new();
        // Windows requires an explicit directory-capable open. The existing
        // post-open metadata check still enforces Linux O_DIRECTORY.
        #[cfg(windows)]
        o.maybe_dir(f & 65536 != 0);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            o.mode(m);
        }
        #[cfg(not(unix))]
        let _ = m;
        o.read(f & 3 != 1)
            .write(f & 3 != 0)
            .create(f & 64 != 0)
            .create_new(f & 192 == 192)
            .truncate(f & 512 != 0)
            .append(f & 1024 != 0);
        if f & 131072 != 0 {
            o.follow(FollowSymlinks::No);
        }
        let relative = path(p)?;
        let readonly_create = f & 3 == 0 && f & 64 != 0 && f & (128 | 512) == 0;
        if readonly_create {
            o.create(false);
        }
        if f & 3 == 0 && f & (128 | 512) != 0 {
            o.write(true);
        }
        let file = match self.root.open_with(&relative, &o) {
            Ok(file) => file,
            Err(e) if readonly_create && e.kind() == std::io::ErrorKind::NotFound => {
                let mut create = o.clone();
                create.write(true).create_new(true);
                match self.root.open_with(&relative, &create) {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.root.open_with(&relative, &o).map_err(err)?
                    }
                    Err(e) => return Err(err(e)),
                }
            }
            Err(e) => return Err(err(e)),
        }
        .into_std();
        if f & 65536 != 0 && !file.metadata().map_err(err)?.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(Arc::new(NativeFile {
            file: Mutex::new(file),
            flags: Mutex::new(f),
        }))
    }
    fn metadata(&self, p: &[u8], follow: bool) -> Result<FileStat, Errno> {
        let p = path(p)?;
        let m = if follow {
            self.root.metadata(p)
        } else {
            self.root.symlink_metadata(p)
        }
        .map_err(err)?;
        cap_stat(m)
    }
    fn mkdir(&self, p: &[u8], m: u32) -> Result<(), Errno> {
        let builder = cap_std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            let mut builder = builder;
            use cap_std::fs::DirBuilderExt;
            builder.mode(m);
            builder
        };
        #[cfg(not(unix))]
        let _ = m;
        self.root.create_dir_with(path(p)?, &builder).map_err(err)
    }
    fn unlink(&self, p: &[u8], d: bool) -> Result<(), Errno> {
        if d {
            self.root.remove_dir(path(p)?)
        } else {
            self.root.remove_file(path(p)?)
        }
        .map_err(err)
    }
    fn link(&self, a: &[u8], b: &[u8]) -> Result<(), Errno> {
        self.root
            .hard_link(path(a)?, &self.root, path(b)?)
            .map_err(err)
    }
    fn symlink(&self, a: &[u8], b: &[u8]) -> Result<(), Errno> {
        #[cfg(not(windows))]
        {
            self.root.symlink(path(a)?, path(b)?).map_err(err)
        }
        #[cfg(windows)]
        {
            let target = path(a)?;
            let link = path(b)?;
            // Windows records whether a reparse point targets a directory.
            // Resolve the target from the link's parent through the retained
            // capability; never inspect an ambient path to select its type.
            let resolved = link.parent().unwrap_or(Path::new("")).join(&target);
            // Creating a link does not access its target. Keep unresolvable
            // targets as file links, including cross-mount guest targets which
            // MountedFs resolves separately. Subsequent Host access still uses
            // the retained capability and rejects targets outside that root.
            let directory = self
                .root
                .metadata(resolved)
                .is_ok_and(|metadata| metadata.is_dir());
            if directory {
                self.root.symlink_dir(target, link)
            } else {
                self.root.symlink_file(target, link)
            }
            .map_err(err)
        }
    }
    fn readlink(&self, p: &[u8]) -> Result<Vec<u8>, Errno> {
        self.root
            .read_link_contents(path(p)?)
            .map(|p| bytes(&p))
            .map_err(err)
    }
    fn rename(&self, a: &[u8], b: &[u8]) -> Result<(), Errno> {
        self.root
            .rename(path(a)?, &self.root, path(b)?)
            .map_err(err)
    }
    fn read_dir(&self, p: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        self.root
            .read_dir(path(p)?)
            .map_err(err)?
            .map(|entry| {
                let e = entry.map_err(err)?;
                let m = e.metadata().map_err(err)?;
                // Windows DirEntry metadata lacks handle-only fields such
                // as link count. DirectoryEntry does not expose those fields.
                #[cfg(unix)]
                let inode = {
                    use cap_std::fs::MetadataExt;
                    m.ino()
                };
                #[cfg(not(unix))]
                let inode = 0;
                Ok(DirectoryEntry {
                    name: bytes(Path::new(&e.file_name())),
                    inode,
                    kind: if m.is_dir() {
                        4
                    } else if m.is_symlink() {
                        10
                    } else {
                        8
                    },
                })
            })
            .collect()
    }
}
fn cap_stat(m: cap_std::fs::Metadata) -> Result<FileStat, Errno> {
    let mtime_ns = mtime_ns(m.modified().map_err(|_| Errno::EIO)?.into_std())?;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Ok(FileStat {
            inode: m.ino(),
            size: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            mtime_ns,
        })
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        let (inode, links) = {
            use cap_std::fs::MetadataExt;
            (
                m.file_index().ok_or(Errno::EIO)?,
                u64::from(m.number_of_links().ok_or(Errno::EIO)?),
            )
        };
        #[cfg(not(windows))]
        let (inode, links) = (0, 1);
        Ok(FileStat {
            inode,
            size: m.len(),
            mode: if m.is_dir() {
                0o040755
            } else if m.is_symlink() {
                0o120777
            } else {
                0o100644
            },
            links,
            mtime_ns,
        })
    }
}
#[cfg(test)]
mod files_tests {
    use super::*;
    #[test]
    fn mtime_system_time_before_epoch() {
        for ns in [1, 99, 100, 101, 500_000_000, 1_000_000_000] {
            let represented_ns = if cfg!(windows) { ns / 100 * 100 } else { ns };
            assert_eq!(
                mtime_ns(std::time::UNIX_EPOCH - std::time::Duration::from_nanos(ns)),
                Ok(-i128::from(represented_ns))
            );
        }
    }
    #[test]
    fn mtime_system_time_epoch_positive_range() {
        for ns in [0, 1, 99, 100, 101, 1_500_000_000, u64::MAX] {
            let represented_ns = if cfg!(windows) { ns / 100 * 100 } else { ns };
            assert_eq!(
                mtime_ns(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns)),
                Ok(i128::from(represented_ns))
            );
        }
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    // Fixture-only policy: open descendants can temporarily deny a Windows
    // parent-directory rename (independently verified by the test below).
    // Never change NativeFs error mapping or retry permission errors elsewhere.
    fn retry_fixture_exchange(
        name: &str,
        directory_rename: bool,
        deadline: std::time::Instant,
        conflicts: &AtomicU64,
        mut operation: impl FnMut() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        loop {
            match operation() {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.raw_os_error() == Some(32)
                        || (directory_rename && error.raw_os_error() == Some(5)) =>
                {
                    conflicts.fetch_add(1, Ordering::Relaxed);
                    if std::time::Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => {
                    eprintln!(
                        "FILES_WINDOWS_EXCHANGE operation={name} os_error={:?} error={error}",
                        error.raw_os_error()
                    );
                    return Err(error);
                }
            }
        }
    }

    #[test]
    fn fixture_directory_rename_retries_transient_handle_denial() {
        for code in [5, 32] {
            let conflicts = AtomicU64::new(0);
            let mut calls = 0;
            retry_fixture_exchange(
                "directory-rename",
                true,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                &conflicts,
                || {
                    calls += 1;
                    if calls == 1 {
                        Err(std::io::Error::from_raw_os_error(code))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap();
            assert_eq!(calls, 2);
            assert_eq!(conflicts.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn fixture_persistent_directory_permission_is_deadline_failure() {
        let conflicts = AtomicU64::new(0);
        let mut calls = 0;
        let error = retry_fixture_exchange(
            "directory-rename",
            true,
            std::time::Instant::now(),
            &conflicts,
            || {
                calls += 1;
                Err(std::io::Error::from_raw_os_error(5))
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(calls, 1);
    }

    #[test]
    fn fixture_nonrename_permission_is_not_retried() {
        let conflicts = AtomicU64::new(0);
        let mut calls = 0;
        let error = retry_fixture_exchange(
            "remove-symlink",
            false,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &conflicts,
            || {
                calls += 1;
                Err(std::io::Error::from_raw_os_error(5))
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(calls, 1);
        assert_eq!(conflicts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fixture_unrelated_errors_propagate_unchanged() {
        let conflicts = AtomicU64::new(0);
        let error = retry_fixture_exchange(
            "directory-rename",
            true,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &conflicts,
            || Err(std::io::Error::from_raw_os_error(13)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(13));
        assert_eq!(conflicts.load(Ordering::Relaxed), 0);
    }

    struct Fixture {
        base: PathBuf,
        fs: Option<NativeFs>,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "paludarium-files-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(base.join("root")).unwrap();
            std::fs::write(base.join("sentinel"), b"outside").unwrap();
            let fs = NativeFs::new(&base.join("root")).unwrap();
            Self { base, fs: Some(fs) }
        }
        fn fs(&self) -> &NativeFs {
            self.fs.as_ref().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.fs.take());
            std::fs::remove_dir_all(&self.base).unwrap();
        }
    }
    #[test]
    fn native_io() {
        let x = Fixture::new();
        let f = x.fs().open(b"a", 66, 0o600).unwrap();
        assert_eq!(f.write(b"abc"), Ok(3));
        f.seek(0, 0).unwrap();
        let mut b = [0; 3];
        assert_eq!(f.read(&mut b), Ok(3));
        assert_eq!(&b, b"abc");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn mtime_retained_file_and_path_stat_pre_epoch() {
        let x = Fixture::new();
        let handle = x.fs().open(b"mtime", 66, 0o600).unwrap();
        let file = std::fs::File::open(x.base.join("root/mtime")).unwrap();
        for ns in [1, 500_000_000, 1_000_000_000] {
            file.set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH - std::time::Duration::from_nanos(ns)),
            )
            .unwrap();
            assert_eq!(handle.stat().unwrap().mtime_ns, -i128::from(ns));
            assert_eq!(
                x.fs().metadata(b"mtime", true).unwrap().mtime_ns,
                -i128::from(ns)
            );
        }
    }
    #[test]
    fn native_links() {
        let x = Fixture::new();
        let file = x.fs().open(b"a", 66, 0o600).unwrap();
        x.fs().link(b"a", b"b").unwrap();
        assert_eq!(x.fs().metadata(b"a", true).unwrap().links, 2);
        assert_eq!(file.stat().unwrap().links, 2);
        x.fs().unlink(b"a", false).unwrap();
        assert_eq!(x.fs().metadata(b"b", true).unwrap().links, 1);
        assert_eq!(file.stat().unwrap().links, 1);
    }
    #[test]
    fn native_error_namespace() {
        use std::io::{Error, ErrorKind};
        assert_eq!(lock_err(fs2::lock_contended_error()), Errno::EAGAIN);
        for (kind, expected) in [
            (ErrorKind::NotFound, Errno::ENOENT),
            (ErrorKind::AlreadyExists, Errno::EEXIST),
            (ErrorKind::NotADirectory, Errno::ENOTDIR),
            (ErrorKind::WouldBlock, Errno::EAGAIN),
            (ErrorKind::PermissionDenied, Errno(13)),
        ] {
            assert_eq!(err(Error::from(kind)), expected);
        }
        #[cfg(target_os = "linux")]
        assert_eq!(err(Error::from_raw_os_error(40)), Errno(40)); // ELOOP
        #[cfg(target_os = "macos")]
        assert_eq!(err(Error::from_raw_os_error(35)), Errno::EAGAIN);
    }
    #[test]
    fn fixture_releases_root_before_removing_directory() {
        let fixture = Fixture::new();
        let base = fixture.base.clone();
        fixture.fs().open(b"a", 66, 0o600).unwrap();
        drop(fixture);
        assert!(!base.exists());
    }
    #[test]
    fn native_rename() {
        let x = Fixture::new();
        x.fs()
            .open(b"a", 66, 0o600)
            .unwrap()
            .write(b"data")
            .unwrap();
        x.fs().rename(b"a", b"b").unwrap();
        assert_eq!(x.fs().metadata(b"a", true), Err(Errno::ENOENT));
        assert_eq!(x.fs().metadata(b"b", true).unwrap().size, 4);
    }
    #[test]
    fn native_directory() {
        let x = Fixture::new();
        x.fs().mkdir(b"d", 0o700).unwrap();
        x.fs().open(b"d/a", 66, 0o600).unwrap();
        assert_eq!(x.fs().read_dir(b"d").unwrap().len(), 1);
        assert!(x.fs().unlink(b"d", true).is_err());
        x.fs().unlink(b"d/a", false).unwrap();
        x.fs().unlink(b"d", true).unwrap();
    }
    #[test]
    fn native_parent_escape() {
        let x = Fixture::new();
        assert!(x.fs().open(b"../sentinel", 2, 0).is_err());
        assert!(x.fs().rename(b"../sentinel", b"stolen").is_err());
        assert!(x.fs().link(b"../sentinel", b"stolen").is_err());
        assert_eq!(std::fs::read(x.base.join("sentinel")).unwrap(), b"outside");
    }
    #[test]
    #[cfg(unix)]
    fn native_symlink_escape() {
        let x = Fixture::new();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("../sentinel", x.base.join("root/escape")).unwrap();
            assert!(x.fs().open(b"escape", 2, 0).is_err());
            assert!(x.fs().metadata(b"escape", true).is_err());
            assert_eq!(x.fs().readlink(b"escape").unwrap(), b"../sentinel");
            assert_eq!(std::fs::read(x.base.join("sentinel")).unwrap(), b"outside");
        }
    }
    #[test]
    fn native_lock() {
        let x = Fixture::new();
        let a = x.fs().open(b"a", 66, 0o600).unwrap();
        let b = x.fs().open(b"a", 2, 0).unwrap();
        a.flock(2 | 4).unwrap();
        assert_eq!(b.flock(2 | 4), Err(Errno::EAGAIN));
        a.flock(8).unwrap();
        b.flock(2 | 4).unwrap();
    }
    #[test]
    fn native_nofollow() {
        let x = Fixture::new();
        x.fs().open(b"a", 66, 0o600).unwrap();
        x.fs().symlink(b"a", b"s").unwrap();
        assert!(x.fs().open(b"s", 131072, 0).is_err());
        assert_eq!(
            x.fs().metadata(b"s", false).unwrap().mode & 0o170000,
            0o120000
        );
    }
    #[test]
    fn native_symlink_rename_race() {
        #[cfg(unix)]
        {
            const NAME: &str = "native_fs::files_tests::native_symlink_rename_race";
            if std::env::var_os("PALUDARIUM_FILES_RACE_CHILD").is_none() {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", NAME, "--nocapture"])
                    .env("PALUDARIUM_FILES_RACE_CHILD", "1")
                    .spawn()
                    .unwrap();
                let start = std::time::Instant::now();
                loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        assert!(status.success());
                        break;
                    }
                    if start.elapsed() > std::time::Duration::from_secs(30) {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("files race exceeded 30 seconds")
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                return;
            }
            let x = Fixture::new();
            std::fs::create_dir(x.base.join("outside")).unwrap();
            std::fs::write(x.base.join("outside/sentinel"), b"outside").unwrap();
            x.fs().mkdir(b"pivot", 0o700).unwrap();
            x.fs()
                .open(b"pivot/sentinel", 66, 0o600)
                .unwrap()
                .write(b"inside")
                .unwrap();
            let root = x.base.join("root");
            let outside = x.base.join("outside");
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done = Arc::clone(&stop);
            let attacker = std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    std::fs::rename(root.join("pivot"), root.join("held")).unwrap();
                    std::os::unix::fs::symlink(&outside, root.join("pivot")).unwrap();
                    std::fs::remove_file(root.join("pivot")).unwrap();
                    std::fs::rename(root.join("held"), root.join("pivot")).unwrap();
                }
            });
            for _ in 0..1000 {
                if let Ok(f) = x.fs().open(b"pivot/sentinel", 2, 0) {
                    let _ = f.write(b"inside");
                }
                let _ = x.fs().metadata(b"pivot/sentinel", true);
                let _ = x.fs().read_dir(b"pivot");
                let _ = x.fs().open(b"pivot/new", 66, 0o600);
                let _ = x.fs().link(b"pivot/sentinel", b"pivot/link");
                let _ = x.fs().rename(b"pivot/new", b"pivot/renamed");
                let _ = x.fs().unlink(b"pivot/renamed", false);
                let _ = x.fs().unlink(b"pivot/link", false);
            }
            stop.store(true, Ordering::Relaxed);
            attacker.join().unwrap();
            assert_eq!(
                std::fs::read(x.base.join("outside/sentinel")).unwrap(),
                b"outside"
            );
            assert_eq!(
                std::fs::read_dir(x.base.join("outside")).unwrap().count(),
                1
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_recreated_symlink_has_distinct_handle_identity() {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let x = Fixture::new();
        let outside = x.base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        let link = x.base.join("root/pending-link");
        std::os::windows::fs::symlink_dir(&outside, &link).unwrap();
        // Retain the old reparse-point handle across name deletion/recreation.
        // Windows CI permits recreation with DELETE sharing; validate identity
        // and cleanup rather than assuming a delete-pending permission failure.
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(7) // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            .custom_flags(0x0220_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            .open(&link)
            .unwrap();
        let old_id = handle.metadata().unwrap().file_index().unwrap();
        std::fs::remove_dir(&link).unwrap();
        std::os::windows::fs::symlink_dir(&outside, &link).unwrap();
        let replacement = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&link)
            .unwrap();
        let new_id = replacement.metadata().unwrap().file_index().unwrap();
        assert_ne!(old_id, new_id, "old handle must not alias replacement link");
        assert_eq!(handle.metadata().unwrap().file_index(), Some(old_id));
        drop(handle);
        assert_eq!(replacement.metadata().unwrap().file_index(), Some(new_id));
        assert_eq!(std::fs::read_link(&link).unwrap(), outside);
        assert_eq!(std::fs::read(link.join("sentinel")).unwrap(), b"outside");
        drop(replacement);
        std::fs::remove_dir(&link).unwrap();
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        let base = x.base.clone();
        drop(x);
        assert!(!base.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_open_child_blocks_parent_rename_until_close() {
        let x = Fixture::new();
        let root = x.base.join("root");
        x.fs().mkdir(b"parent", 0o700).unwrap();
        let child = x.fs().open(b"parent/child", 66, 0o600).unwrap();
        child.write(b"inside").unwrap();
        let error = std::fs::rename(root.join("parent"), root.join("moved")).unwrap_err();
        println!(
            "FILES_WINDOWS_OPEN_CHILD_RENAME os_error={:?}",
            error.raw_os_error()
        );
        assert_eq!(error.raw_os_error(), Some(5));
        assert!(root.join("parent").is_dir());
        assert!(!root.join("moved").exists());
        drop(child);
        std::fs::rename(root.join("parent"), root.join("moved")).unwrap();
        assert_eq!(std::fs::read(root.join("moved/child")).unwrap(), b"inside");
        let base = x.base.clone();
        drop(x);
        assert!(!base.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_symlink_rename_race() {
        use std::sync::{Barrier, atomic::AtomicBool};
        const NAME: &str = "native_fs::files_tests::native_windows_symlink_rename_race";
        if std::env::var_os("PALUDARIUM_FILES_WINDOWS_RACE_CHILD").is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env("PALUDARIUM_FILES_WINDOWS_RACE_CHILD", "1")
                .spawn()
                .unwrap();
            let start = std::time::Instant::now();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "Windows fixture child failed: {status}");
                    println!(
                        "FILES_WINDOWS_WATCHDOG elapsed_ms={} child_exit={status}",
                        start.elapsed().as_millis()
                    );
                    return;
                }
                if start.elapsed() >= std::time::Duration::from_secs(30) {
                    child.kill().unwrap();
                    let status = child.wait().unwrap();
                    panic!("Windows fixture exceeded 30 seconds; killed/reaped: {status}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        // Every ambient operation below is confined to this newly created fixture.
        let x = Fixture::new();
        let root = x.base.join("root");
        let outside = x.base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        std::os::windows::fs::symlink_dir(&outside, root.join("permission-probe"))
            .expect("Windows fixture directory symlink permission is required; no skip");
        assert!(
            std::fs::symlink_metadata(root.join("permission-probe"))
                .unwrap()
                .is_symlink()
        );
        std::fs::remove_dir(root.join("permission-probe")).unwrap();
        println!("FILES_WINDOWS_SYMLINK_PERMISSION=true");
        x.fs().mkdir(b"pivot", 0o700).unwrap();
        x.fs()
            .open(b"pivot/sentinel", 66, 0o600)
            .unwrap()
            .write(b"inside")
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let exchanges = Arc::new(AtomicU64::new(0));
        let sharing_conflicts = Arc::new(AtomicU64::new(0));
        let active_operation = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(Barrier::new(2));
        let done = Arc::clone(&stop);
        let count = Arc::clone(&exchanges);
        let conflicts = Arc::clone(&sharing_conflicts);
        let active = Arc::clone(&active_operation);
        let ready = Arc::clone(&barrier);
        let attacker = std::thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
            ready.wait();
            while !done.load(Ordering::Acquire) {
                // Windows can temporarily deny renaming an open directory.
                // Count only complete real directory/symlink exchanges.
                retry_fixture_exchange("rename-pivot-to-held", true, deadline, &conflicts, || {
                    let result = std::fs::rename(root.join("pivot"), root.join("held"));
                    if result
                        .as_ref()
                        .is_err_and(|error| error.raw_os_error() == Some(5))
                    {
                        eprintln!(
                            "FILES_WINDOWS_RENAME_CONTEXT active_operation={} pivot_metadata={:?} held_exists={}",
                            active.load(Ordering::Acquire),
                            std::fs::symlink_metadata(root.join("pivot"))
                                .map(|m| (m.is_dir(), m.is_symlink())),
                            root.join("held").exists()
                        );
                    }
                    result
                })?;
                let link = std::os::windows::fs::symlink_dir(&outside, root.join("pivot"));
                if let Err(error) = link {
                    eprintln!(
                        "FILES_WINDOWS_EXCHANGE operation=create-pivot-symlink os_error={:?} error={error}",
                        error.raw_os_error()
                    );
                    std::fs::rename(root.join("held"), root.join("pivot"))?;
                    return Err(error);
                }
                std::thread::yield_now();
                retry_fixture_exchange(
                    "remove-pivot-symlink",
                    false,
                    deadline,
                    &conflicts,
                    || std::fs::remove_dir(root.join("pivot")),
                )?;
                retry_fixture_exchange("rename-held-to-pivot", true, deadline, &conflicts, || {
                    std::fs::rename(root.join("held"), root.join("pivot"))
                })?;
                count.fetch_add(1, Ordering::Release);
            }
            Ok(())
        });
        barrier.wait();
        for _ in 0..1000 {
            active_operation.store(1, Ordering::Release); // open/write sentinel
            if let Ok(file) = x.fs().open(b"pivot/sentinel", 2, 0) {
                let _ = file.write(b"inside");
            }
            active_operation.store(2, Ordering::Release); // metadata
            let _ = x.fs().metadata(b"pivot/sentinel", true);
            active_operation.store(3, Ordering::Release); // directory iteration
            let _ = x.fs().read_dir(b"pivot");
            active_operation.store(4, Ordering::Release); // create file
            let _ = x.fs().open(b"pivot/new", 66, 0o600);
            active_operation.store(5, Ordering::Release); // hard link
            let _ = x.fs().link(b"pivot/sentinel", b"pivot/link");
            active_operation.store(6, Ordering::Release); // file rename
            let _ = x.fs().rename(b"pivot/new", b"pivot/renamed");
            active_operation.store(7, Ordering::Release); // unlink renamed file
            let _ = x.fs().unlink(b"pivot/renamed", false);
            active_operation.store(8, Ordering::Release); // unlink hard link
            let _ = x.fs().unlink(b"pivot/link", false);
            active_operation.store(0, Ordering::Release);
        }
        stop.store(true, Ordering::Release);
        attacker
            .join()
            .expect("fixture exchange thread panicked")
            .expect("fixture exchange failed");
        let exchanges = exchanges.load(Ordering::Acquire);
        assert!(exchanges > 0, "no real Windows exchange occurred");
        assert_eq!(
            std::fs::read(x.base.join("outside/sentinel")).unwrap(),
            b"outside"
        );
        let listing: Vec<_> = std::fs::read_dir(x.base.join("outside"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(listing, [std::ffi::OsString::from("sentinel")]);
        let base = x.base.clone();
        drop(x); // Closes NativeFs directory handle before strict fixture deletion.
        assert!(!base.exists());
        println!(
            "FILES_WINDOWS_RACE iterations=1000 exchanges={exchanges} outside_unchanged=true cleanup=true"
        );
        println!(
            "FILES_WINDOWS_SHARING_CONFLICTS={}",
            sharing_conflicts.load(Ordering::Relaxed)
        );
    }
}
