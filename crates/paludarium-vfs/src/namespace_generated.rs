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
}
impl GeneratedSource {
    /// Its path from the machine's root, where the kernel finds it.
    fn machine_path(&self, rest: &[u8]) -> Vec<u8> {
        joined(&self.base, &joined(&self.path, rest))
    }
}

/// The stand-in a walk sees for a bind mount of a generated file: its root
/// with the file's `stat` and, below a directory's, a directory at each
/// name, so a walk goes through by the names alone and the kernel finds
/// what is there; every other call on it is the kernel's.
#[derive(Debug)]
pub(super) struct GeneratedFs(pub(super) GeneratedSource);
impl HostFs for GeneratedFs {
    fn open(&self, _path: &[u8], _flags: u32, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn metadata(&self, path: &[u8], _follow: bool) -> Result<FileStat, Errno> {
        if path == self.0.path.as_slice() {
            Ok(self.0.stat)
        } else if self.0.stat.mode & S_IFMT == S_IFDIR && within(path, &self.0.path) {
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
        Err(Errno::EOPNOTSUPP)
    }
    fn unlink(&self, _path: &[u8], _directory: bool) -> Result<(), Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn link(&self, _old: &[u8], _new: &[u8]) -> Result<(), Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn symlink(&self, _target: &[u8], _path: &[u8]) -> Result<(), Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn readlink(&self, _path: &[u8]) -> Result<Vec<u8>, Errno> {
        Err(Errno::EINVAL)
    }
    fn rename(&self, _old: &[u8], _new: &[u8]) -> Result<(), Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn read_dir(&self, _path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        Err(Errno::ENOTDIR)
    }
}
impl FileSystem for GeneratedFs {}

impl NamespacedFs {
    /// `do_loopback` of a file the kernel generates onto the resolved
    /// `target`: the new mount shows `source`, a file on a file and a
    /// directory on a directory (`graft_tree`, `ENOTDIR`), and on a shared
    /// mount it is shared too, in a new peer group. No table here holds a
    /// mount below a generated directory, so none is locked
    /// (`has_locked_children`) or comes along with `MS_REC`.
    pub fn bind_generated(&self, source: GeneratedSource, target: &[u8]) -> Result<(), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let to = self.walk(&entries, target, true, false, true)?;
        let parent = self.entry(&entries, &to);
        let directory = source.stat.mode & S_IFMT == S_IFDIR;
        if directory != (self.lstat(&entries, &to)?.mode & S_IFMT == S_IFDIR) {
            return Err(Errno::ENOTDIR);
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
        let numbers = &self.table.numbers;
        let entry = Entry {
            token: Token::new(
                Numbers::take(&numbers.ids, 21),
                numbers,
                None,
                Arc::new(SuperState::default()),
            ),
            parent: parent.id(),
            point: to.path,
            root: source.path.clone(),
            flags: source.flags,
            locks,
            locked: false,
            source: source.kind.as_bytes().to_vec(),
            group: if parent.group == 0 {
                0
            } else {
                self.table.new_group()
            },
            master: 0,
            unbindable: false,
            hidden: false,
            backing: Backing::Generated(Arc::new(GeneratedFs(source))),
        };
        self.table.update(|entries| {
            entries.push(entry);
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
