//! Bind mounts of the files the kernel generates (`/dev`'s and `/proc`'s),
//! which no file system here holds: the mount keeps what the kernel told of
//! the file, and a walk that reaches it is handed back to the kernel by the
//! file's own path ([`NamespacedFs::generated`]).
use super::*;

/// A file the kernel generates, as a bind mount of it shows it elsewhere.
#[derive(Clone, Debug)]
pub struct GeneratedSource {
    /// Its file system's type, as mountinfo shows it (`devtmpfs`, `proc`).
    pub kind: &'static str,
    /// Its file system's device, as `stat` gives it.
    pub device: u64,
    /// Where its file system is, from the machine's root (`/dev`, `/proc`).
    pub base: Vec<u8>,
    /// Its path in its file system (`/null` for `/dev/null`), the mount's
    /// root.
    pub path: Vec<u8>,
    /// Its `stat`.
    pub stat: FileStat,
    /// Its mount's flags ([`mount_flags`]), which the new mount takes.
    pub flags: u32,
    /// Whether a walk finds only its root, not a directory at each name
    /// below: the kernel's own `/dev` where it is, whose names the kernel
    /// finds by their paths, and below which a walk goes only into the
    /// mounts on it (`/dev/shm`).
    pub shallow: bool,
}
impl GeneratedSource {
    /// Its path from the machine's root, where the kernel finds it.
    pub(super) fn machine_path(&self, rest: &[u8]) -> Vec<u8> {
        joined(&self.base, &joined(&self.path, rest))
    }
}

/// The stand-in a walk sees for a bind mount of a generated file: its root
/// with the file's `stat` and, below a directory's, a directory at each
/// name, so a walk goes through by the names alone and the kernel finds
/// what is there; every other call on it is the kernel's. The kernel's own
/// `/dev` ([`GeneratedSource::shallow`]) has nothing there at all
/// (`ENOENT`), so a call reached through a link is the kernel's as before.
#[derive(Debug)]
pub(super) struct GeneratedFs(pub(super) GeneratedSource);
impl GeneratedFs {
    /// `error`, or `ENOENT` for the kernel's own `/dev`.
    fn refused<T>(&self, error: Errno) -> Result<T, Errno> {
        Err(if self.0.shallow { Errno::ENOENT } else { error })
    }
}
impl HostFs for GeneratedFs {
    fn open(&self, _path: &[u8], _flags: u32, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn metadata(&self, path: &[u8], _follow: bool) -> Result<FileStat, Errno> {
        if path == self.0.path.as_slice() {
            Ok(self.0.stat)
        } else if !self.0.shallow
            && self.0.stat.mode & S_IFMT == S_IFDIR
            && within(path, &self.0.path)
        {
            Ok(FileStat {
                mode: S_IFDIR | 0o555,
                links: 2,
                ..FileStat::default()
            })
        } else {
            Err(Errno::ENOENT)
        }
    }
    fn mkdir(&self, _path: &[u8], _mode: u32) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn unlink(&self, _path: &[u8], _directory: bool) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn link(&self, _old: &[u8], _new: &[u8]) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn symlink(&self, _target: &[u8], _path: &[u8]) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn readlink(&self, _path: &[u8]) -> Result<Vec<u8>, Errno> {
        self.refused(Errno::EINVAL)
    }
    fn rename(&self, _old: &[u8], _new: &[u8]) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn rename_with(&self, _old: &[u8], _new: &[u8], flags: u32) -> Result<(), Errno> {
        self.refused(if flags == 0 {
            Errno::EOPNOTSUPP
        } else {
            Errno::EINVAL
        })
    }
    fn read_dir(&self, _path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        self.refused(Errno::ENOTDIR)
    }
    fn statfs(&self, _path: &[u8]) -> Result<FsStats, Errno> {
        self.refused(Errno::ENOSYS)
    }
    fn make_socket(&self, _path: &[u8], _mode: u32) -> Result<FileStat, Errno> {
        self.refused(Errno::EPERM)
    }
    fn make_fifo(&self, _path: &[u8], _mode: u32) -> Result<FileStat, Errno> {
        self.refused(Errno::EPERM)
    }
    fn with_xattrs(
        &self,
        _path: &[u8],
        _follow: bool,
        _f: &mut dyn FnMut(&mut paludarium_host::Xattrs),
    ) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn with_attributes(
        &self,
        _path: &[u8],
        _follow: bool,
        _f: &mut dyn FnMut(&mut u32),
    ) -> Result<(), Errno> {
        self.refused(Errno::EOPNOTSUPP)
    }
    fn set_mode(&self, _path: &[u8], _mode: u32) -> Result<(), Errno> {
        self.refused(Errno::EPERM)
    }
    fn set_owner(
        &self,
        _path: &[u8],
        _follow: bool,
        _uid: Option<u32>,
        _gid: Option<u32>,
    ) -> Result<(), Errno> {
        self.refused(Errno::EPERM)
    }
    fn set_times(
        &self,
        _path: &[u8],
        _follow: bool,
        _atime: Option<i128>,
        _mtime: Option<i128>,
    ) -> Result<(), Errno> {
        self.refused(Errno::EPERM)
    }
}
impl FileSystem for GeneratedFs {}

impl NamespacedFs {
    /// `do_loopback` of a file the kernel generates onto the resolved
    /// `target`: the new mount shows `source`, a file on a file and a
    /// directory on a directory (`graft_tree`, `ENOTDIR`), and on a shared
    /// mount it is shared too, in a new peer group. A mount below the
    /// directory (`/dev/shm` of `/dev`) does not come along, even with
    /// `MS_REC`, and when locked it is refused (`has_locked_children`).
    pub fn bind_generated(&self, source: GeneratedSource, target: &[u8]) -> Result<(), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let to = self.walk(&entries, target, true, false, true)?;
        let parent = self.entry(&entries, &to);
        let directory = source.stat.mode & S_IFMT == S_IFDIR;
        if directory != (self.lstat(&entries, &to)?.mode & S_IFMT == S_IFDIR) {
            return Err(Errno::ENOTDIR);
        }
        // `has_locked_children`: what is mounted below a directory, locked
        // in a namespace of a less privileged owner, stays covered (`EINVAL`
        // without `MS_REC`, which takes nothing along here).
        if directory {
            let base = source.machine_path(b"/");
            if entries
                .iter()
                .any(|e| e.locked && e.point != base && within(&e.point, &base))
            {
                return Err(Errno::EINVAL);
            }
        }
        // `clone_mnt` keeps the flags' locks of the mount it copies, the
        // one of `/dev` or `/proc` from start-up, which a namespace of a
        // less privileged owner has, as all it copied, which stay locked
        // where they are (`EINVAL` to unmount).
        let mut locks = 0;
        if entries.iter().any(|e| e.locked) {
            locks |= mount_flags::LOCK_ATIME;
            for (flag, lock) in [
                (mount_flags::READONLY, mount_flags::LOCK_READONLY),
                (mount_flags::NODEV, mount_flags::LOCK_NODEV),
                (mount_flags::NOSUID, mount_flags::LOCK_NOSUID),
                (mount_flags::NOEXEC, mount_flags::LOCK_NOEXEC),
            ] {
                if source.flags & flag != 0 {
                    locks |= lock;
                }
            }
        }
        let group = if parent.group == 0 {
            0
        } else {
            self.table.new_group()
        };
        let entry = self.generated_entry(source, parent.id(), to.path, locks, group);
        self.table.update(|entries| {
            entries.push(entry);
            Ok(())
        })
    }
    /// The mount of the generated file `source` on mount `parent` at
    /// `point`, with the flags' locks `locks`, in peer group `group`.
    fn generated_entry(
        &self,
        source: GeneratedSource,
        parent: u64,
        point: Vec<u8>,
        locks: u32,
        group: u64,
    ) -> Entry {
        let numbers = &self.table.numbers;
        Entry {
            token: Token::new(
                Numbers::take(&numbers.ids, 21),
                numbers,
                None,
                Arc::new(SuperState::default()),
            ),
            parent,
            point,
            root: source.path.clone(),
            flags: source.flags,
            locks,
            locked: false,
            source: source.kind.as_bytes().to_vec(),
            group,
            master: 0,
            unbindable: false,
            hidden: false,
            backing: Backing::Generated(Arc::new(GeneratedFs(source))),
        }
    }
    /// The mounts Linux has from start-up in the kernel's own `/dev`: that
    /// directory itself, `devices` (a stand-in, [`GeneratedSource::shallow`],
    /// the lower filesystem need have no `/dev`), and the tmpfs `shm` on
    /// its `/shm`, as systemd mounts `/dev/shm`. Before any other mount.
    pub fn mount_devices(&self, devices: GeneratedSource, shm: NewTmpfs) -> Result<(), Errno> {
        let entries = self.table.snapshot();
        if entries.iter().any(Entry::runtime) {
            return Err(Errno(16)); // EBUSY
        }
        let point = devices.machine_path(b"/");
        let parent = entries[self.table.boot_index(&entries, &point)].id();
        let devices = self.generated_entry(devices, parent, point.clone(), 0, 0);
        let shm = self.new_entry(shm, devices.id(), joined(&point, b"/shm"));
        self.table.update(|entries| {
            entries.push(devices);
            entries.push(shm);
            Ok(())
        })
    }
    /// Where the kernel finds the file at the resolved `path` (its last
    /// link followed with `follow`), when it is in a bind mount of a file
    /// the kernel generates: that file's own path, as `/dev/null` for a
    /// file `/dev/null` was bound onto, and the path the walk reached,
    /// which names it there. `None` for any other path, and for a path the
    /// walk does not reach, which the call then finds as it would.
    #[must_use]
    pub fn generated(&self, path: &[u8], follow: bool) -> Option<(Vec<u8>, Vec<u8>)> {
        if !self.table.generated.load(Ordering::SeqCst) {
            return None;
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true).ok()?;
        let e = &entries[loc.at?];
        match &e.backing {
            Backing::Generated(fs) => {
                Some((fs.0.machine_path(&relative(&e.point, &loc.path)), loc.path))
            }
            _ => None,
        }
    }
}
