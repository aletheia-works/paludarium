//! Mount namespaces: the mounts a process sees, over the machine's
//! filesystem ([`MountedFs`], whose mounts exist from start-up).
//!
//! A [`MountTable`] is one namespace's tree of mounts, as Linux's
//! `mnt_namespace` holds its `struct mount`s: the ones from start-up
//! ("boot" mounts, the lower filesystem's own) first, then those `mount`
//! made. A [`NamespacedFs`] is the filesystem seen through a table. While a
//! table has only boot mounts every call goes straight to the lower
//! filesystem; otherwise a path is walked one name at a time, as Linux's
//! `link_path_walk` does, stepping into the topmost mount on a directory
//! (`handle_mounts`) and out of a mount's root with `..`
//! (`follow_dotdot`).
use crate::*;
use std::collections::BTreeSet;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Linux's per-mount flags (`MNT_*`), as a mount keeps them.
pub mod mount_flags {
    pub const NOSUID: u32 = 0x01;
    pub const NODEV: u32 = 0x02;
    pub const NOEXEC: u32 = 0x04;
    pub const NOATIME: u32 = 0x08;
    pub const NODIRATIME: u32 = 0x10;
    pub const RELATIME: u32 = 0x20;
    pub const READONLY: u32 = 0x40;
    pub const NOSYMFOLLOW: u32 = 0x80;
}

/// `show_vfsmnt_opts`: the per-mount options `/proc/self/mountinfo` shows
/// after `rw`.
fn shown_flags(flags: u32) -> String {
    use mount_flags::*;
    [
        (NOSUID, ",nosuid"),
        (NODEV, ",nodev"),
        (NOEXEC, ",noexec"),
        (NOATIME, ",noatime"),
        (NODIRATIME, ",nodiratime"),
        (RELATIME, ",relatime"),
        (NOSYMFOLLOW, ",nosymfollow"),
    ]
    .iter()
    .filter(|(flag, _)| flags & flag != 0)
    .map(|(_, name)| *name)
    .collect()
}

/// The IDs and device minors in use, which every table made from the first
/// one shares: Linux's `mnt_id_ida` and `unnamed_dev_ida`, each handing out
/// the lowest free number.
#[derive(Default)]
struct Numbers {
    ids: Mutex<BTreeSet<u64>>,
    minors: Mutex<BTreeSet<u64>>,
}
impl Numbers {
    fn take(set: &Mutex<BTreeSet<u64>>, from: u64) -> u64 {
        let mut set = lock(set);
        let mut n = from;
        while set.contains(&n) {
            n += 1;
        }
        set.insert(n);
        n
    }
}

/// One mount's identity: its ID, held until the last [`MountPin`] and
/// the table both let go of it, as Linux frees a mount's ID with it.
struct Token {
    id: u64,
    numbers: Arc<Numbers>,
    /// The superblock of a tmpfs mount, which its open files keep (only
    /// held).
    _superblock: Option<Arc<Superblock>>,
    /// How many [`MountPin`]s hold it: Linux's `mnt_count` less the
    /// parent's and the lookup's own references.
    pins: AtomicUsize,
}
impl Drop for Token {
    fn drop(&mut self) {
        lock(&self.numbers.ids).remove(&self.id);
    }
}

/// What keeps a mount in use (`EBUSY` for `umount2` without
/// `MNT_DETACH`): an open file on it, or a working directory or a root in
/// it. It keeps a detached mount's file system too. Its mount is behind a
/// trait object, which keeps the auto-trait checks of the files that hold
/// one shallow.
pub struct MountPin(Arc<dyn Pinned>);
/// A mount a [`MountPin`] holds.
trait Pinned: Send + Sync {
    fn token(&self) -> &Token;
}
impl Pinned for Token {
    fn token(&self) -> &Token {
        self
    }
}
impl MountPin {
    fn new(token: &Arc<Token>) -> Self {
        token.pins.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(token) as Arc<dyn Pinned>)
    }
}
impl Clone for MountPin {
    fn clone(&self) -> Self {
        self.0.token().pins.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(&self.0))
    }
}
impl Drop for MountPin {
    fn drop(&mut self) {
        self.0.token().pins.fetch_sub(1, Ordering::SeqCst);
    }
}
impl std::fmt::Debug for MountPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MountPin({})", self.0.token().id)
    }
}

/// A tmpfs superblock: its files, its device, and what `statfs` and
/// mountinfo report of it. Its device minor is free again once it goes,
/// as `kill_anon_super` frees it.
struct Superblock {
    /// Behind a trait object, which keeps the auto-trait checks of what
    /// holds a table shallow.
    fs: Arc<dyn FileSystem>,
    minor: u64,
    numbers: Arc<Numbers>,
    blocks: u64,
    inodes: u64,
    common: String,
    shown: String,
    owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}
impl Drop for Superblock {
    fn drop(&mut self) {
        lock(&self.numbers.minors).remove(&self.minor);
    }
}
impl Superblock {
    fn device(&self) -> u64 {
        self.minor & 0xff | (self.minor & !0xff) << 12
    }
}

/// A new tmpfs to mount, as the kernel parsed its options.
pub struct NewTmpfs {
    /// Its files: an empty tree whose root has the mode and owner asked
    /// for.
    pub fs: MemFs,
    /// Its size in 4 KiB blocks and its inodes, 0 for no limit, which
    /// `statfs` reports (and nothing enforces).
    pub blocks: u64,
    pub inodes: u64,
    /// What mountinfo shows of the superblock after `rw`: the common
    /// options (`,sync`), and tmpfs's own (`,size=1024k,inode64`).
    pub common_options: String,
    pub super_options: String,
    /// The per-mount flags ([`mount_flags`]).
    pub flags: u32,
    /// What it was mounted from, `none` if nothing.
    pub source: Vec<u8>,
    /// The user namespace that owns the superblock, which the kernel keeps
    /// (`s_user_ns`).
    pub owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

#[derive(Clone)]
enum Backing {
    /// A mount from start-up, the `index`th of the lower filesystem's.
    Boot {
        kind: &'static str,
        device: u64,
    },
    Memory(Arc<Superblock>),
    /// A bind mount of the lower filesystem's files, in the boot mount at
    /// `base`, whose type and device it shows.
    Lower {
        kind: &'static str,
        device: u64,
        base: Vec<u8>,
    },
}

#[derive(Clone)]
struct Entry {
    token: Arc<Token>,
    parent: u64,
    point: Vec<u8>,
    backing: Backing,
    /// Where its root is in its file system (`mnt_root`): `/` for a new
    /// tmpfs, the directory or file a bind mount was made from, a path
    /// from the machine's root for one of the lower filesystem's.
    root: Vec<u8>,
    flags: u32,
    locked: bool,
    /// `MNT_EXPIRE`'s mark (`mnt_expiry_mark`).
    expiring: bool,
    source: Vec<u8>,
}
impl Entry {
    fn id(&self) -> u64 {
        self.token.id
    }
    fn memory(&self) -> Option<&Arc<Superblock>> {
        match &self.backing {
            Backing::Memory(sb) => Some(sb),
            Backing::Boot { .. } | Backing::Lower { .. } => None,
        }
    }
    /// Made after start-up, by `mount`: a walk steps into it itself.
    fn runtime(&self) -> bool {
        !matches!(self.backing, Backing::Boot { .. })
    }
    /// The path in its file system of `path`, a path in the mount.
    fn inside(&self, path: &[u8]) -> Vec<u8> {
        joined(&self.root, &relative(&self.point, path))
    }
    /// Whether it shows the same file system as `other`.
    fn same_files(&self, other: &Self) -> bool {
        match (&self.backing, &other.backing) {
            (Backing::Memory(a), Backing::Memory(b)) => Arc::ptr_eq(a, b),
            (Backing::Memory(_), _) | (_, Backing::Memory(_)) => false,
            _ => true,
        }
    }
}

/// One mount namespace's mounts.
pub struct MountTable {
    entries: RwLock<Arc<Vec<Entry>>>,
    /// Whether every mount is a boot one, so calls go straight through.
    boot_only: AtomicBool,
    /// How many boot mounts there are: the first entries.
    boot: usize,
    numbers: Arc<Numbers>,
}
impl std::fmt::Debug for MountTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<u64> = self.snapshot().iter().map(Entry::id).collect();
        write!(f, "MountTable{ids:?}")
    }
}
impl MountTable {
    /// The first namespace's table: the mounts of `lower`, with the IDs,
    /// parents and devices it gives them.
    pub fn new(lower: &dyn FileSystem) -> Arc<Self> {
        let numbers = Arc::new(Numbers::default());
        let mounts = lower.mounts();
        let entries = mounts
            .iter()
            .map(|m| {
                lock(&numbers.ids).insert(m.id);
                lock(&numbers.minors).insert(m.device & 0xff | (m.device >> 12) & !0xff);
                Entry {
                    token: Arc::new(Token {
                        id: m.id,
                        numbers: Arc::clone(&numbers),
                        _superblock: None,
                        pins: AtomicUsize::new(0),
                    }),
                    parent: m.parent,
                    point: m.path.clone(),
                    backing: Backing::Boot {
                        kind: m.kind,
                        device: m.device,
                    },
                    root: m.path.clone(),
                    flags: mount_flags::RELATIME,
                    locked: false,
                    expiring: false,
                    source: m.source.clone(),
                }
            })
            .collect();
        Arc::new(Self {
            entries: RwLock::new(Arc::new(entries)),
            boot_only: AtomicBool::new(true),
            boot: mounts.len(),
            numbers,
        })
    }
    /// A new namespace's copy of this one (`copy_mnt_ns`): every mount
    /// again, with a new ID, on the same file systems. With `locked` (the new
    /// namespace has another user namespace) each copy is locked, as
    /// `lock_mnt_tree` locks all but the copy's root; here the root is
    /// locked too, standing for Linux's `/`, which sits on its rootfs.
    #[must_use]
    pub fn copy(&self, locked: bool) -> Arc<Self> {
        let old = self.snapshot();
        let mut ids = BTreeMap::new();
        let mut entries = Vec::with_capacity(old.len());
        for e in old.iter() {
            let id = Numbers::take(&self.numbers.ids, 21);
            ids.insert(e.id(), id);
            entries.push(Entry {
                token: Arc::new(Token {
                    id,
                    numbers: Arc::clone(&self.numbers),
                    _superblock: e.memory().cloned(),
                    pins: AtomicUsize::new(0),
                }),
                parent: ids.get(&e.parent).copied().unwrap_or(e.parent),
                locked: e.locked || locked,
                ..e.clone()
            });
        }
        Arc::new(Self {
            entries: RwLock::new(Arc::new(entries)),
            boot_only: AtomicBool::new(self.boot_only.load(Ordering::SeqCst)),
            boot: self.boot,
            numbers: Arc::clone(&self.numbers),
        })
    }
    fn snapshot(&self) -> Arc<Vec<Entry>> {
        Arc::clone(&self.entries.read().unwrap_or_else(PoisonError::into_inner))
    }
    fn update<T>(&self, f: impl FnOnce(&mut Vec<Entry>) -> Result<T, Errno>) -> Result<T, Errno> {
        let mut guard = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let mut entries = (**guard).clone();
        let out = f(&mut entries)?;
        self.boot_only
            .store(entries.len() == self.boot, Ordering::SeqCst);
        *guard = Arc::new(entries);
        Ok(out)
    }
    /// The boot mount holding `path`: the longest mount point.
    fn boot_index(&self, entries: &[Entry], path: &[u8]) -> usize {
        entries[..self.boot]
            .iter()
            .enumerate()
            .filter(|(_, e)| within(path, &e.point))
            .max_by_key(|(_, e)| e.point.len())
            .map_or(0, |(i, _)| i)
    }
}

/// Whether `path` is `point` or below it.
fn within(path: &[u8], point: &[u8]) -> bool {
    point == b"/"
        || path == point
        || path.starts_with(point) && path.get(point.len()) == Some(&b'/')
}
/// `path` from the root of the mount at `point`.
fn relative(point: &[u8], path: &[u8]) -> Vec<u8> {
    if path == point {
        b"/".to_vec()
    } else if point == b"/" {
        path.to_vec()
    } else {
        path[point.len()..].to_vec()
    }
}
/// `rest`, a path from a directory, from where the directory is, `at`.
fn joined(at: &[u8], rest: &[u8]) -> Vec<u8> {
    if rest == b"/" {
        at.to_vec()
    } else if at == b"/" {
        rest.to_vec()
    } else {
        [at, rest].concat()
    }
}
/// `name` in the directory `dir`.
fn child_path(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = dir.to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}
fn parent_path(path: &[u8]) -> Vec<u8> {
    let at = path.iter().rposition(|b| *b == b'/').unwrap_or(0);
    path[..at.max(1)].to_vec()
}
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const EBUSY: Errno = Errno(16);
const EXDEV: Errno = Errno(18);
const ELOOP: Errno = Errno(40);

/// Where a walk got to: a path from the machine's root, and the tmpfs
/// mount it is on (an index into the table), or none for the lower
/// filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Loc {
    at: Option<usize>,
    path: Vec<u8>,
}

/// What `umount2` and `mount` learn of the mount a path is in.
#[derive(Debug, Clone)]
pub struct Target {
    pub id: u64,
    /// The path is the mount's root (Linux's `path_mounted`).
    pub root: bool,
    /// The mount exists from start-up.
    pub boot: bool,
    /// The namespace's own root, which has no parent.
    pub namespace_root: bool,
    pub locked: bool,
    /// Other mounts are on it.
    pub covered: bool,
    /// The user namespace that owns its superblock; none for the first.
    pub owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

/// The filesystem through a mount namespace's table.
pub struct NamespacedFs {
    /// The machine's filesystem from its root.
    lower: Arc<dyn FileSystem>,
    /// The same from `root`, which the calls of a table of boot mounts go to.
    view: Arc<dyn FileSystem>,
    table: Arc<MountTable>,
    root: Vec<u8>,
}
impl NamespacedFs {
    #[must_use]
    pub fn new(lower: Arc<dyn FileSystem>, table: Arc<MountTable>) -> Self {
        Self {
            view: Arc::clone(&lower),
            lower,
            table,
            root: b"/".to_vec(),
        }
    }
    #[must_use]
    pub fn table(&self) -> &Arc<MountTable> {
        &self.table
    }
    fn fast(&self) -> bool {
        self.table.boot_only.load(Ordering::SeqCst)
    }
    /// The index of the mount numbered `id` that `mount` made, none for a
    /// boot one.
    fn runtime_index(entries: &[Entry], id: u64) -> Option<usize> {
        entries
            .iter()
            .position(|e| e.id() == id)
            .filter(|&i| entries[i].runtime())
    }
    fn id_of(&self, entries: &[Entry], loc: &Loc) -> u64 {
        match loc.at {
            Some(i) => entries[i].id(),
            None => entries[self.table.boot_index(entries, &loc.path)].id(),
        }
    }
    fn entry<'a>(&self, entries: &'a [Entry], loc: &Loc) -> &'a Entry {
        match loc.at {
            Some(i) => &entries[i],
            None => &entries[self.table.boot_index(entries, &loc.path)],
        }
    }
    /// The mount on `loc`, if any.
    fn covering(&self, entries: &[Entry], loc: &Loc) -> Option<usize> {
        let id = self.id_of(entries, loc);
        entries
            .iter()
            .position(|e| e.runtime() && e.parent == id && e.point == loc.path)
    }
    /// Into the topmost mount on `loc` (`handle_mounts`).
    fn cross(&self, entries: &[Entry], mut loc: Loc) -> Loc {
        while let Some(i) = self.covering(entries, &loc) {
            loc.at = Some(i);
        }
        loc
    }
    /// The file system `loc` is on and its path there.
    fn backing<'a>(&'a self, entries: &'a [Entry], loc: &Loc) -> (&'a dyn FileSystem, Vec<u8>) {
        // A walk is only ever on a mount `mount` made or the lower
        // filesystem.
        match loc.at.map(|i| &entries[i]) {
            Some(e) => (
                e.memory().map_or(&*self.lower, |sb| &*sb.fs),
                e.inside(&loc.path),
            ),
            None => (&*self.lower, loc.path.clone()),
        }
    }
    fn lstat(&self, entries: &[Entry], loc: &Loc) -> Result<FileStat, Errno> {
        let (fs, path) = self.backing(entries, loc);
        fs.metadata(&path, false)
    }
    /// Where the process's root is: its path walked from the machine's
    /// root, stepping into each mount on the way.
    fn root_loc(&self, entries: &[Entry]) -> Loc {
        let mut loc = Loc {
            at: None,
            path: b"/".to_vec(),
        };
        for part in self.root.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            loc.path = child_path(&loc.path, part);
            loc = self.cross(entries, loc);
        }
        loc
    }
    /// Walks `path` one name at a time, as [`MountedFs`] does, through the
    /// mounts: with `follow` a last symbolic link is followed, with
    /// `missing` a missing last name is where it would be, and with `cross`
    /// a mount on the last name is stepped into.
    fn walk(
        &self,
        entries: &[Entry],
        path: &[u8],
        follow: bool,
        missing: bool,
        cross: bool,
    ) -> Result<Loc, Errno> {
        validate(path)?;
        if path[0] != b'/' {
            return Err(Errno::ENOENT);
        }
        let trailing = path.last() == Some(&b'/');
        let mut queue: VecDeque<Vec<u8>> = path
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .map(Vec::from)
            .collect();
        let mut current = Loc {
            at: None,
            path: b"/".to_vec(),
        };
        let mut links = 0;
        while let Some(part) = queue.pop_front() {
            if self.lstat(entries, &current)?.mode & S_IFMT != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
            if part == b"." {
                continue;
            }
            if part == b".." {
                if current.path != b"/" && current.path != self.root {
                    // Out of each mount whose root this is, to where it
                    // is mounted, then up (`follow_dotdot`).
                    while let Some(i) = current.at
                        && entries[i].point == current.path
                    {
                        current.at = Self::runtime_index(entries, entries[i].parent);
                    }
                    current.path = parent_path(&current.path);
                }
                continue;
            }
            let next = Loc {
                at: current.at,
                path: child_path(&current.path, &part),
            };
            let stat = match self.lstat(entries, &next) {
                Ok(stat) => stat,
                Err(e) if e == Errno::ENOENT && queue.is_empty() && missing => return Ok(next),
                Err(e) => return Err(e),
            };
            if stat.mode & S_IFMT == S_IFLNK && (follow || !queue.is_empty() || trailing) {
                links += 1;
                if links > 40 {
                    return Err(ELOOP);
                }
                let (fs, at) = self.backing(entries, &next);
                let target = fs.readlink(&at)?;
                validate(&target)?;
                if target[0] == b'/' {
                    current = self.root_loc(entries);
                }
                for component in target.split(|b| *b == b'/').filter(|p| !p.is_empty()).rev() {
                    queue.push_front(component.to_vec());
                }
            } else {
                current = if cross || !queue.is_empty() {
                    self.cross(entries, next)
                } else {
                    next
                };
            }
        }
        if trailing && self.lstat(entries, &current)?.mode & S_IFMT != S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        Ok(current)
    }
    /// The trailing-slash check of a name to remove: it must be a directory.
    fn trailing_directory(&self, entries: &[Entry], path: &[u8]) -> Result<(), Errno> {
        if path.last() == Some(&b'/') {
            let end = path.iter().rposition(|b| *b != b'/').map_or(1, |i| i + 1);
            let loc = self.walk(entries, &path[..end], false, false, false)?;
            if self.lstat(entries, &loc)?.mode & S_IFMT != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
        }
        Ok(())
    }
    /// Where `path` is for its device: the file, or the nearest directory
    /// above it that is there.
    fn locate(&self, entries: &[Entry], path: &[u8]) -> Loc {
        let mut path = path.to_vec();
        loop {
            if let Ok(loc) = self.walk(entries, &path, true, true, true) {
                return loc;
            }
            if path.len() <= 1 {
                return Loc {
                    at: None,
                    path: b"/".to_vec(),
                };
            }
            path = parent_path(&path);
        }
    }
    /// Moves the mounts below `old` in the mount `id` to below `new`, as
    /// a rename moves the dentries they are on.
    fn moved(&self, id: u64, old: &[u8], new: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let entries = self.table.snapshot();
        let below = |p: &[u8]| p.len() > old.len() && within(p, old) && old != b"/";
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| e.runtime()) {
            if !below(&e.point) {
                continue;
            }
            // The mount of the topmost of its ancestors still below `old`.
            let mut at = e;
            while let Some(i) = Self::runtime_index(&entries, at.parent)
                && below(&entries[i].point)
            {
                at = &entries[i];
            }
            if at.parent == id {
                out.push((e.id(), [new, &e.point[old.len()..]].concat()));
            }
        }
        out
    }
    /// What `umount2` and `mount` find at the resolved `path` (whose last
    /// symbolic link is not followed).
    pub fn target(&self, path: &[u8]) -> Result<Target, Errno> {
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, false, true)?;
        let e = self.entry(&entries, &loc);
        let id = e.id();
        Ok(Target {
            id,
            root: e.point == loc.path,
            boot: !e.runtime(),
            namespace_root: entries.first().is_some_and(|first| first.id() == id),
            locked: e.locked,
            covered: entries.iter().any(|c| c.parent == id && c.id() != id),
            owner: e.memory().and_then(|sb| sb.owner.clone()),
        })
    }
    /// Mounts `new` on the directory at the resolved `path`, on top of what
    /// is there (`do_add_mount`): `ENOTDIR` for another file.
    pub fn mount(&self, path: &[u8], new: NewTmpfs) -> Result<(), Errno> {
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        if self.lstat(&entries, &loc)?.mode & S_IFMT != S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        let parent = self.id_of(&entries, &loc);
        let numbers = &self.table.numbers;
        let minor = Numbers::take(&numbers.minors, 1);
        let sb = Arc::new(Superblock {
            fs: Arc::new(new.fs),
            minor,
            numbers: Arc::clone(numbers),
            blocks: new.blocks,
            inodes: new.inodes,
            common: new.common_options,
            shown: new.super_options,
            owner: new.owner,
        });
        let entry = Entry {
            token: Arc::new(Token {
                id: Numbers::take(&numbers.ids, 21),
                numbers: Arc::clone(numbers),
                _superblock: Some(Arc::clone(&sb)),
                pins: AtomicUsize::new(0),
            }),
            parent,
            point: loc.path,
            backing: Backing::Memory(sb),
            root: b"/".to_vec(),
            flags: new.flags,
            locked: false,
            expiring: false,
            source: new.source,
        };
        self.table.update(|entries| {
            entries.push(entry);
            Ok(())
        })
    }
    /// Binds what the resolved `source` names onto the resolved `target`
    /// (`do_loopback`), both with their last links followed: a new mount of
    /// the source's mount's file system, rooted there, with that mount's
    /// flags, its source and its type, not locked. With `recurse`
    /// (`copy_tree`) the mounts below the source come along, each still
    /// locked if it was; without, a locked one below it is `EINVAL`
    /// (`has_locked_children`). A directory goes on a directory, a file on
    /// a file (`graft_tree`, `ENOTDIR`).
    pub fn bind(&self, source: &[u8], target: &[u8], recurse: bool) -> Result<(), Errno> {
        let entries = self.table.snapshot();
        let from = self.walk(&entries, source, true, false, true)?;
        let to = self.walk(&entries, target, true, false, true)?;
        let old = self.entry(&entries, &from);
        let below =
            |e: &Entry| e.parent == old.id() && e.id() != old.id() && within(&e.point, &from.path);
        if !recurse && entries.iter().any(|e| below(e) && e.locked) {
            return Err(Errno::EINVAL);
        }
        let directory = |loc: &Loc| -> Result<bool, Errno> {
            Ok(self.lstat(&entries, loc)?.mode & S_IFMT == S_IFDIR)
        };
        if directory(&from)? != directory(&to)? {
            return Err(Errno::ENOTDIR);
        }
        let numbers = &self.table.numbers;
        // `clone_mnt` of `e`, rooted at `root` in its file system.
        let clone = |e: &Entry, root: Vec<u8>, parent: u64, point: Vec<u8>, locked: bool| Entry {
            token: Arc::new(Token {
                id: Numbers::take(&numbers.ids, 21),
                numbers: Arc::clone(numbers),
                _superblock: e.memory().cloned(),
                pins: AtomicUsize::new(0),
            }),
            parent,
            point,
            backing: match &e.backing {
                Backing::Boot { kind, device } => Backing::Lower {
                    kind,
                    device: *device,
                    base: e.point.clone(),
                },
                other => other.clone(),
            },
            root,
            flags: e.flags,
            locked,
            expiring: false,
            source: e.source.clone(),
        };
        let top = clone(
            old,
            self.backing(&entries, &from).1,
            self.id_of(&entries, &to),
            to.path.clone(),
            false,
        );
        let mut new = vec![top];
        if recurse {
            // Each mount below, its parent's copy before it (`next_mnt`).
            let mut copies = BTreeMap::from([(old.id(), new[0].id())]);
            let mut queue: Vec<&Entry> = entries.iter().filter(|e| below(e)).rev().collect();
            while let Some(e) = queue.pop() {
                let point = joined(&to.path, &relative(&from.path, &e.point));
                let copy = clone(e, e.root.clone(), copies[&e.parent], point, e.locked);
                copies.insert(e.id(), copy.id());
                new.push(copy);
                queue.extend(
                    entries
                        .iter()
                        .filter(|c| c.parent == e.id() && c.id() != e.id())
                        .rev(),
                );
            }
        }
        self.table.update(|entries| {
            entries.extend(new);
            Ok(())
        })
    }
    /// Unmounts the tmpfs mount `id` (`umount_tree`): with `detach` it and
    /// every mount on it go at once, its open files staying usable;
    /// without, a mount in use or with others on it is `EBUSY`
    /// (`propagate_mount_busy`).
    pub fn umount(&self, id: u64, detach: bool) -> Result<(), Errno> {
        self.table.update(|entries| {
            let i = Self::runtime_index(entries, id).ok_or(Errno::EINVAL)?;
            if !detach
                && (entries.iter().any(|e| e.parent == id)
                    || entries[i].token.pins.load(Ordering::SeqCst) != 0)
            {
                return Err(EBUSY);
            }
            let mut gone = BTreeSet::from([id]);
            loop {
                let more: Vec<u64> = entries
                    .iter()
                    .filter(|e| gone.contains(&e.parent) && !gone.contains(&e.id()))
                    .map(Entry::id)
                    .collect();
                if more.is_empty() {
                    break;
                }
                gone.extend(more);
            }
            entries.retain(|e| !gone.contains(&e.id()));
            Ok(())
        })
    }
    /// `MNT_EXPIRE` of mount `id`, not in use and with no mounts on it
    /// (else `EBUSY`): the first call marks it and is `EAGAIN`, the next
    /// unmounts it. Nothing clears the mark, where Linux's every use of the
    /// mount does.
    pub fn expire(&self, id: u64) -> Result<(), Errno> {
        let marked = self.table.update(|entries| {
            let i = Self::runtime_index(entries, id).ok_or(Errno::EINVAL)?;
            if entries.iter().any(|e| e.parent == id)
                || entries[i].token.pins.load(Ordering::SeqCst) != 0
            {
                return Err(EBUSY);
            }
            Ok(std::mem::replace(&mut entries[i].expiring, true))
        })?;
        if !marked {
            return Err(Errno::EAGAIN);
        }
        self.umount(id, false)
    }
}

impl FileSystem for NamespacedFs {
    fn rooted(&self, root: &[u8]) -> Option<Arc<dyn FileSystem>> {
        let view = if root == b"/" {
            Arc::clone(&self.lower)
        } else {
            self.lower.rooted(root)?
        };
        Some(Arc::new(Self {
            lower: Arc::clone(&self.lower),
            view,
            table: Arc::clone(&self.table),
            root: root.to_vec(),
        }))
    }
    fn mounts(&self) -> Vec<MountPoint> {
        let entries = self.table.snapshot();
        entries
            .iter()
            .map(|e| {
                let (kind, device, root, common_options, super_options) = match &e.backing {
                    Backing::Boot { kind, device } => {
                        (*kind, *device, b"/".to_vec(), String::new(), String::new())
                    }
                    Backing::Lower { kind, device, base } => (
                        *kind,
                        *device,
                        relative(base, &e.root),
                        String::new(),
                        String::new(),
                    ),
                    Backing::Memory(sb) => (
                        "tmpfs",
                        sb.device(),
                        e.root.clone(),
                        sb.common.clone(),
                        sb.shown.clone(),
                    ),
                };
                MountPoint {
                    path: e.point.clone(),
                    root,
                    kind,
                    id: e.id(),
                    parent: e.parent,
                    device,
                    source: e.source.clone(),
                    options: shown_flags(e.flags),
                    common_options,
                    super_options,
                }
            })
            .collect()
    }
    fn device(&self, path: &[u8]) -> u64 {
        if self.fast() {
            return self.lower.device(path);
        }
        let entries = self.table.snapshot();
        let loc = self.locate(&entries, path);
        match loc.at.and_then(|i| entries[i].memory()) {
            Some(sb) => sb.device(),
            None => self.lower.device(&self.backing(&entries, &loc).1),
        }
    }
    fn mount_id(&self, path: &[u8]) -> u64 {
        let entries = self.table.snapshot();
        if self.fast() {
            return entries[self.table.boot_index(&entries, path)].id();
        }
        let loc = self.locate(&entries, path);
        self.id_of(&entries, &loc)
    }
    fn mount_root(&self, path: &[u8]) -> Vec<u8> {
        let entries = self.table.snapshot();
        if self.fast() {
            return entries[self.table.boot_index(&entries, path)].point.clone();
        }
        let loc = self.locate(&entries, path);
        self.entry(&entries, &loc).point.clone()
    }
    fn mount_pin(&self, path: &[u8]) -> Option<MountPin> {
        if self.fast() {
            return None;
        }
        let entries = self.table.snapshot();
        let loc = self.locate(&entries, path);
        loc.at.map(|i| MountPin::new(&entries[i].token))
    }
    fn memory_path(&self, anchor: &[u8], inode: u64) -> Option<Vec<u8>> {
        if self.fast() {
            return self.view.memory_path(anchor, inode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, anchor, true, false, true).ok()?;
        let (fs, at) = self.backing(&entries, &loc);
        let found = fs.memory_path(&at, inode)?;
        match loc.at.map(|i| &entries[i]) {
            // Reached from the mount's root, which a bind mount may not
            // be its file system's.
            Some(e) => {
                within(&found, &e.root).then(|| joined(&e.point, &relative(&e.root, &found)))
            }
            None => Some(found),
        }
    }
}

impl HostFs for NamespacedFs {
    fn root(&self) -> &[u8] {
        &self.root
    }
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        if self.fast() {
            return self.view.open(path, flags, mode);
        }
        const O_CREAT: u32 = 0o100;
        const O_EXCL: u32 = 0o200;
        const O_DIRECTORY: u32 = 0o200000;
        const O_NOFOLLOW: u32 = 0o400000;
        if flags & (O_CREAT | O_DIRECTORY) == O_CREAT | O_DIRECTORY {
            return Err(Errno::EINVAL);
        }
        let entries = self.table.snapshot();
        if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL
            && self.walk(&entries, path, false, false, true).is_ok()
        {
            return Err(Errno::EEXIST);
        }
        let loc = self.walk(
            &entries,
            path,
            flags & O_NOFOLLOW == 0,
            flags & O_CREAT != 0,
            true,
        )?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.open(&at, flags, mode)
    }
    fn metadata(&self, path: &[u8], follow: bool) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.metadata(path, follow);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        self.lstat(&entries, &loc)
    }
    fn mkdir(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.mkdir(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.mkdir(&at, mode)
    }
    fn make_socket(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.make_socket(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.make_socket(&at, mode)
    }
    fn make_fifo(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.make_fifo(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.make_fifo(&at, mode)
    }
    /// A mount point in this namespace is `EBUSY` to `rmdir` and `unlink`,
    /// as Linux's `vfs_rmdir` and `vfs_unlink` find it
    /// `is_local_mountpoint`.
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno> {
        if self.fast() {
            return self.view.unlink(path, directory);
        }
        let entries = self.table.snapshot();
        self.trailing_directory(&entries, path)?;
        let loc = self.walk(&entries, path, false, false, false)?;
        if self.covering(&entries, &loc).is_some() {
            return Err(EBUSY);
        }
        let (fs, at) = self.backing(&entries, &loc);
        fs.unlink(&at, directory)
    }
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        if self.fast() {
            return self.view.link(old, new);
        }
        let entries = self.table.snapshot();
        let from = self.walk(&entries, old, false, false, true)?;
        let to = self.walk(&entries, new, false, true, false)?;
        if from.at != to.at {
            return Err(EXDEV);
        }
        let (fs, a) = self.backing(&entries, &from);
        let (_, b) = self.backing(&entries, &to);
        fs.link(&a, &b)
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno> {
        if self.fast() {
            return self.view.symlink(target, path);
        }
        validate(target)?;
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.symlink(target, &at)
    }
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        if self.fast() {
            return self.view.readlink(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.readlink(&at)
    }
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        self.rename_with(old, new, 0)
    }
    /// Across mounts `EXDEV`; of a mount point in this namespace `EBUSY`
    /// (`vfs_rename`'s `is_local_mountpoint`). The mounts below a renamed
    /// directory move with it, and a bind mount of a file it renames
    /// keeps showing that file, as a mount holds its root's dentry.
    fn rename_with(&self, old: &[u8], new: &[u8], flags: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.rename_with(old, new, flags);
        }
        const EXCHANGE: u32 = 2;
        let entries = self.table.snapshot();
        self.trailing_directory(&entries, old)?;
        if flags & EXCHANGE != 0 {
            self.trailing_directory(&entries, new)?;
        }
        let from = self.walk(&entries, old, false, false, false)?;
        let to = self.walk(&entries, new, false, flags & EXCHANGE == 0, false)?;
        if from.at != to.at {
            return Err(EXDEV);
        }
        if self.covering(&entries, &from).is_some() || self.covering(&entries, &to).is_some() {
            return Err(EBUSY);
        }
        let id = self.id_of(&entries, &from);
        let mut moves = self.moved(id, &from.path, &to.path);
        if flags & EXCHANGE != 0 {
            moves.extend(self.moved(id, &to.path, &from.path));
        }
        let (fs, a) = self.backing(&entries, &from);
        let (_, b) = self.backing(&entries, &to);
        fs.rename_with(&a, &b, flags)?;
        let on = self.entry(&entries, &from).clone();
        let mut roots = Vec::new();
        for e in entries.iter().filter(|e| e.runtime() && e.same_files(&on)) {
            let renamed = |old: &[u8], new: &[u8]| {
                (old != b"/" && within(&e.root, old)).then(|| joined(new, &relative(old, &e.root)))
            };
            let root = renamed(&a, &b)
                .or_else(|| (flags & EXCHANGE != 0).then(|| renamed(&b, &a)).flatten());
            if let Some(root) = root {
                roots.push((e.id(), root));
            }
        }
        if !moves.is_empty() || !roots.is_empty() {
            self.table.update(|entries| {
                for (id, point) in moves {
                    if let Some(e) = entries.iter_mut().find(|e| e.id() == id) {
                        e.point = point;
                    }
                }
                for (id, root) in roots {
                    if let Some(e) = entries.iter_mut().find(|e| e.id() == id) {
                        e.root = root;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        if self.fast() {
            return self.view.read_dir(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.read_dir(&at)
    }
    /// A tmpfs mount's: what it holds, against the size and inodes it
    /// was mounted with (`shmem_statfs`), 0 for those without a limit.
    fn statfs(&self, path: &[u8]) -> Result<FsStats, Errno> {
        if self.fast() {
            return self.view.statfs(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        let mut stats = fs.statfs(&at)?;
        if let Some(sb) = loc.at.and_then(|i| entries[i].memory()) {
            let used = stats.blocks - stats.blocks_free;
            let files = stats.files - stats.files_free;
            stats.blocks = sb.blocks;
            stats.blocks_free = sb.blocks.saturating_sub(used);
            stats.blocks_available = stats.blocks_free;
            stats.files = sb.inodes;
            stats.files_free = sb.inodes.saturating_sub(files);
        }
        Ok(stats)
    }
    fn with_xattrs(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut paludarium_host::Xattrs),
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.with_xattrs(path, follow, f);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.with_xattrs(&at, false, f)
    }
    fn with_attributes(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut u32),
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.with_attributes(path, follow, f);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.with_attributes(&at, false, f)
    }
    fn set_mode(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_mode(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_mode(&at, mode)
    }
    fn set_owner(
        &self,
        path: &[u8],
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_owner(path, follow, uid, gid);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_owner(&at, false, uid, gid)
    }
    fn set_times(
        &self,
        path: &[u8],
        follow: bool,
        atime: Option<i128>,
        mtime: Option<i128>,
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_times(path, follow, atime, mtime);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_times(&at, false, atime, mtime)
    }
}

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;
