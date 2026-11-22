//! Safe in-memory filesystem and the host capability mount boundary.
#![forbid(unsafe_code)]
pub use paludarium_host::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs};
use paludarium_types::Errno;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
mod contents;
use contents::{Contents, Usage};
pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;
pub const DEFAULT_MODE: u32 = 0o755;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestFile {
    pub path: Vec<u8>,
    pub content: Vec<u8>,
    pub mode: u32,
}
impl GuestFile {
    pub fn new(path: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
            mode: DEFAULT_MODE,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mode: u32,
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
fn validate(path: &[u8]) -> Result<(), Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.len() >= PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    for p in path.split(|b| *b == b'/') {
        if p.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        // A 0 starts only the name of a detached mount tree, which no path
        // a program gives can hold ([`NamespacedFs::clone_tree`]).
        if p.iter().skip(1).any(|&b| b == 0) {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}
pub fn normalize_path(path: &[u8]) -> Result<Vec<u8>, Errno> {
    validate(path)?;
    if path[0] != b'/' {
        return Err(Errno::ENOENT);
    }
    let mut parts = Vec::new();
    for p in path.split(|b| *b == b'/') {
        match p {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            _ => parts.push(p),
        }
    }
    let mut out = Vec::new();
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p)
    }
    if out.is_empty() {
        out.push(b'/')
    }
    Ok(out)
}
/// [`normalize_path`] for a process whose root is `root`: a `..` there
/// stays, as Linux's `follow_dotdot` keeps a walk at `fs->root`, so no
/// path that passes through the root leaves it.
pub fn normalize_in(root: &[u8], path: &[u8]) -> Result<Vec<u8>, Errno> {
    if root == b"/" {
        return normalize_path(path);
    }
    validate(path)?;
    if path[0] != b'/' {
        return Err(Errno::ENOENT);
    }
    let mut out = b"/".to_vec();
    for p in path.split(|b| *b == b'/') {
        match p {
            b"" | b"." => {}
            b".." if out == root || out == b"/" => {}
            b".." => {
                let at = out.iter().rposition(|b| *b == b'/').unwrap_or(0);
                out.truncate(at.max(1));
            }
            _ => {
                if out != b"/" {
                    out.push(b'/');
                }
                out.extend_from_slice(p);
            }
        }
    }
    Ok(out)
}
/// `TMPFS_MAGIC`: what the in-memory filesystem calls itself.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
/// The size the in-memory filesystem reports, the memory `sysinfo` reports.
pub const MEMORY_BYTES: u64 = 4 << 30;
const BLOCK: u64 = 4096;
/// One line of the mount table: where, which filesystem type, and what
/// `/proc/self/mountinfo` shows of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountPoint {
    pub path: Vec<u8>,
    /// Where its root is in its file system (`mnt_root`), as mountinfo's
    /// fourth field shows it: `/` but for a bind mount.
    pub root: Vec<u8>,
    pub kind: &'static str,
    /// The mount's ID, and its parent's (`mnt_id`, `mnt_parent->mnt_id`).
    pub id: u64,
    pub parent: u64,
    /// Its superblock's device, in `stat`'s encoding (`new_encode_dev`).
    pub device: u64,
    /// What it was mounted from (`mnt_devname`).
    pub source: Vec<u8>,
    /// The per-mount options after `rw` or `ro` (`show_vfsmnt_opts`):
    /// `,relatime`.
    pub options: String,
    /// The mount is read-only (`MNT_READONLY`), as mountinfo's sixth field
    /// shows it, and its superblock is (`SB_RDONLY`), as the field after the
    /// source shows it.
    pub read_only: bool,
    pub super_read_only: bool,
    /// mountinfo's optional fields, each with a space before it:
    /// ` shared:1 master:2 unbindable`.
    pub tags: String,
    /// The superblock's common options after `rw` (`show_sb_opts`):
    /// `,sync`, `,dirsync`, `,lazytime`.
    pub common_options: String,
    /// The file system's own options (`show_options`): `,size=1024k`.
    pub super_options: String,
    /// What `statmount` shows besides: the mount's ID unique until the
    /// machine ends (`mnt_id_unique`, from `1 << 31` on) and its parent's,
    /// its own if it has none; its flags ([`mount_flags`]); its peer group,
    /// the peer group of its master, the nearest one with a member in the
    /// namespace (`get_dominating_id`, 0 for none), and whether it is
    /// unbindable. All 0 for a filesystem that keeps no table.
    pub unique: u64,
    pub parent_unique: u64,
    pub flags: u32,
    pub group: u64,
    pub master: u64,
    pub propagate_from: u64,
    pub unbindable: bool,
}
impl MountPoint {
    /// The `index`th mount that exists from start-up, at `path`: its ID is
    /// 21 on, its parent the first one's (the first one's parent 1), its
    /// device minor `index + 1`, and its type its source.
    #[must_use]
    pub fn boot(index: usize, path: Vec<u8>, kind: &'static str) -> Self {
        Self {
            path,
            root: b"/".to_vec(),
            kind,
            id: 21 + index as u64,
            parent: if index == 0 { 1 } else { 21 },
            device: index as u64 + 1,
            source: kind.as_bytes().to_vec(),
            options: ",relatime".to_string(),
            read_only: false,
            super_read_only: false,
            tags: String::new(),
            common_options: String::new(),
            super_options: String::new(),
            unique: 0,
            parent_unique: 0,
            flags: 0,
            group: 0,
            master: 0,
            propagate_from: 0,
            unbindable: false,
        }
    }
}
/// Whether writing through a path's mount is refused (`EROFS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadOnly {
    /// The mount or its superblock is read-only (`__mnt_is_readonly`),
    /// which `mnt_want_write` refuses.
    pub mount: bool,
    /// The superblock is (`sb_rdonly`), which `inode_permission` refuses
    /// before it checks the file's mode (`sb_permission`).
    pub superblock: bool,
}
/// The number of the mount holding `path` (the longest matching mount
/// point, counting from 1), which `stat` gives as the device minor.
#[must_use]
pub fn mount_device(mounts: &[MountPoint], path: &[u8]) -> u64 {
    let inside = |root: &[u8]| {
        root == b"/"
            || path == root
            || path.starts_with(root) && path.get(root.len()) == Some(&b'/')
    };
    mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| inside(&m.path))
        .max_by_key(|(_, m)| m.path.len())
        .map_or(1, |(i, _)| i as u64 + 1)
}
pub trait FileSystem: HostFs {
    /// This filesystem seen by a process whose root is the directory at
    /// `root`, a resolved path from the machine's root ([`HostFs::root`]):
    /// `None` when it cannot be.
    fn rooted(&self, _root: &[u8]) -> Option<Arc<dyn FileSystem>> {
        None
    }
    /// This filesystem without its mounts below the mount point `point`,
    /// so each shows the directory it covers, as a bind mount of that
    /// mount without `MS_REC` shows it: `None` when it has no mounts.
    fn uncovered(&self, _point: &[u8]) -> Option<Arc<dyn FileSystem>> {
        None
    }
    /// The mounts, root first, for `/proc/self/mountinfo`.
    fn mounts(&self) -> Vec<MountPoint> {
        vec![MountPoint::boot(0, b"/".to_vec(), "tmpfs")]
    }
    /// The device of the mount holding `path`, as `stat` gives it
    /// (`st_dev`): of the longest mount point here.
    fn device(&self, path: &[u8]) -> u64 {
        mount_device(&self.mounts(), path)
    }
    /// The ID of the mount holding `path`, as `/proc/self/mountinfo` and
    /// `statx` give it.
    fn mount_id(&self, path: &[u8]) -> u64 {
        let mounts = self.mounts();
        let device = mount_device(&mounts, path);
        mounts
            .iter()
            .find(|m| m.device == device)
            .map_or(20 + device, |m| m.id)
    }
    /// The mount point of the mount holding `path`.
    fn mount_root(&self, path: &[u8]) -> Vec<u8> {
        let mounts = self.mounts();
        let device = mount_device(&mounts, path);
        mounts
            .into_iter()
            .find(|m| m.device == device)
            .map_or_else(|| b"/".to_vec(), |m| m.path)
    }
    /// What keeps the mount holding `path` in use while it lasts, as an
    /// open file, a working directory or a root holds Linux's mount: none
    /// for a mount that cannot be unmounted.
    fn mount_pin(&self, _path: &[u8]) -> Option<MountPin> {
        None
    }
    /// `statfs`'s `f_flags` for `path`: `ST_VALID`, and `ST_RELATIME` as
    /// mountinfo shows.
    fn statfs_flags(&self, _path: &[u8]) -> u64 {
        0x1020
    }
    /// Whether any mount or superblock here is read-only, before a
    /// lookup of one is worth making.
    fn any_read_only(&self) -> bool {
        false
    }
    /// Whether the mount holding `path` (its last link followed with
    /// `follow`) is read-only: nothing is, but for mounts made so.
    fn read_only(&self, _path: &[u8], _follow: bool) -> ReadOnly {
        ReadOnly::default()
    }
    /// What keeps the mount holding `path` written to while it lasts, as a
    /// file open for writing holds Linux's (`mnt_get_write_access`), which
    /// a remount read-only refuses (`EBUSY`).
    fn mount_writer(&self, _path: &[u8], _follow: bool) -> Option<MountPin> {
        None
    }
    /// The path of the file numbered `inode` on the in-memory file system
    /// that holds `anchor`, as a tmpfs file handle decoded on that mount
    /// reaches the file: `None` when `anchor` is on another file system, or
    /// when no name the guest reaches links the file.
    fn memory_path(&self, _anchor: &[u8], _inode: u64) -> Option<Vec<u8>> {
        None
    }
    fn read_file(&self, path: &[u8]) -> Result<Arc<[u8]>, Errno> {
        let f = self.open(path, 0, 0)?;
        if f.stat()?.mode & 0o170000 == 0o040000 {
            return Err(Errno::EISDIR);
        }
        let mut out = Vec::new();
        let mut b = [0; 4096];
        loop {
            let n = f.read(&mut b)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&b[..n])
        }
        Ok(out.into())
    }
    fn stat(&self, path: &[u8]) -> Result<Stat, Errno> {
        let s = self.metadata(path, true)?;
        if s.mode & 0o170000 == 0o040000 {
            return Err(Errno::EISDIR);
        }
        Ok(Stat {
            size: s.size,
            mode: s.mode & 0o7777,
        })
    }
}
enum Kind {
    File(Contents),
    Dir(BTreeMap<Vec<u8>, u64>),
    Symlink(Vec<u8>),
    /// A node without contents, of the type its mode gives: a socket file,
    /// as `bind` of an AF_UNIX socket to a path makes one, or a FIFO, as
    /// `mknod` makes one.
    Special,
}
struct Node {
    kind: Kind,
    mode: u32,
    /// The owner and group, root's until `chown`.
    owner: (u32, u32),
    xattrs: paludarium_host::Xattrs,
    /// tmpfs's inode flags (`FS_IOC_GETFLAGS`): `FS_IMMUTABLE_FL`,
    /// `FS_APPEND_FL`, `FS_NODUMP_FL` and `FS_NOATIME_FL`.
    attributes: u32,
    links: u64,
    locks: BTreeMap<u64, u32>,
    mtime_ns: i128,
    clock: Arc<dyn Fn() -> Result<u64, Errno> + Send + Sync>,
    /// The inode and the page of a long symbolic link it takes of its
    /// file system's [`Usage`], until it goes (`shmem_free_inode`); only
    /// its `Drop` reads it.
    _charge: Charge,
}
/// `SHORT_SYMLINK_LEN`: a symbolic link whose target and NUL are no longer
/// is kept in its inode, a longer one in a page.
const SHORT_SYMLINK_LEN: usize = 128;
/// An inode's part of its file system's [`Usage`], given back when it goes.
struct Charge {
    usage: Arc<Usage>,
    pages: u64,
}
impl Charge {
    /// An inode, with `pages` more for a long symbolic link (one whose
    /// target and NUL go past `SHORT_SYMLINK_LEN`, 128): `ENOSPC` past the
    /// inodes or the size, with nothing taken.
    fn take(usage: &Arc<Usage>, pages: u64) -> Result<Self, Errno> {
        usage.take_inode()?;
        if let Err(e) = usage.take_pages(pages) {
            usage.free_inode();
            return Err(e);
        }
        Ok(Self {
            usage: Arc::clone(usage),
            pages,
        })
    }
    /// The root's inode, which a new file system, without limits yet, has.
    fn root(usage: &Arc<Usage>) -> Self {
        usage.add_inode();
        Self {
            usage: Arc::clone(usage),
            pages: 0,
        }
    }
    /// The pages `kind` takes of its own, besides a file's contents.
    fn pages_of(kind: &Kind) -> u64 {
        match kind {
            Kind::Symlink(target) if target.len() + 1 > SHORT_SYMLINK_LEN => 1,
            _ => 0,
        }
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.usage.free_inode();
        self.usage.free_pages(self.pages);
    }
}
impl Node {
    fn stat(&self, id: u64) -> FileStat {
        FileStat {
            inode: id,
            size: match &self.kind {
                Kind::File(contents) => contents.len(),
                Kind::Symlink(b) => b.len() as u64,
                Kind::Dir(_) | Kind::Special => 0,
            },
            blocks: match &self.kind {
                Kind::File(contents) => Some(contents.blocks()),
                _ => None,
            },
            mode: self.mode,
            uid: self.owner.0,
            gid: self.owner.1,
            links: self.links,
            mtime_ns: self.mtime_ns,
            rdev: 0,
            attributes: self.attributes,
        }
    }
    /// Runs `f` on the flags of a regular file or a directory, the inodes
    /// whose operations have tmpfs's `fileattr_get` and `fileattr_set`.
    fn with_attributes(&mut self, f: &mut dyn FnMut(&mut u32)) -> Result<(), Errno> {
        match self.kind {
            Kind::File(_) | Kind::Dir(_) => {
                f(&mut self.attributes);
                Ok(())
            }
            Kind::Symlink(_) | Kind::Special => Err(Errno::EOPNOTSUPP),
        }
    }
}
/// `chmod`: the file type stays, the permission bits are replaced.
fn set_node_mode(node: &mut Node, mode: u32) {
    node.mode = (node.mode & 0o170000) | (mode & 0o7777);
}
/// `chown`: `None` keeps the owner or the group as it is.
fn set_node_owner(node: &mut Node, uid: Option<u32>, gid: Option<u32>) {
    node.owner = (uid.unwrap_or(node.owner.0), gid.unwrap_or(node.owner.1));
}
/// `utimensat`: only the modification time is kept; the access time is not.
fn set_node_mtime(node: &mut Node, mtime: Option<i128>) {
    if let Some(mtime) = mtime {
        node.mtime_ns = mtime;
    }
}
struct Tree {
    nodes: BTreeMap<u64, Arc<Mutex<Node>>>,
    /// The pages and inodes the files take, also those of one unlinked but
    /// still open.
    usage: Arc<Usage>,
    next: u64,
    owner: u64,
    clock: Arc<dyn Fn() -> Result<u64, Errno> + Send + Sync>,
}
impl Tree {
    /// The 4 KiB blocks the files and symbolic links hold, as `statfs`
    /// reports them used: every file's pages, also those of a file unlinked
    /// but still open, as tmpfs frees them only with the file, and a page
    /// for each long symbolic link (a short one is kept in its inode).
    fn used_blocks(&self) -> u64 {
        self.usage.pages()
    }
    fn require_trailing_directory(&self, path: &[u8]) -> Result<(), Errno> {
        if path.last() == Some(&b'/') {
            let end = path.iter().rposition(|b| *b != b'/').map_or(1, |i| i + 1);
            let id = self.resolve(&path[..end], false)?;
            if !matches!(lock(&*self.node(id)?).kind, Kind::Dir(_)) {
                return Err(Errno::ENOTDIR);
            }
        }
        Ok(())
    }
    /// The first path, breadth first and in name order, that links node
    /// `id` and that `reached` takes; the root's is `/`.
    fn path_of(&self, id: u64, reached: &dyn Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
        let mut queue = VecDeque::from([(1, b"/".to_vec())]);
        while let Some((at, path)) = queue.pop_front() {
            if at == id && reached(&path) {
                return Some(path);
            }
            let node = self.node(at).ok()?;
            if let Kind::Dir(children) = &lock(&node).kind {
                for (name, &child) in children {
                    let mut next = path.clone();
                    if next.last() != Some(&b'/') {
                        next.push(b'/');
                    }
                    next.extend_from_slice(name);
                    queue.push_back((child, next));
                }
            }
        }
        None
    }
    fn node(&self, id: u64) -> Result<Arc<Mutex<Node>>, Errno> {
        self.nodes.get(&id).cloned().ok_or(Errno::ENOENT)
    }
    /// A new inode of `kind`, `ENOSPC` when the file system has no inode
    /// or (for a long symbolic link) page left (`shmem_get_inode`).
    fn allocate(&mut self, kind: Kind, mode: u32) -> Result<u64, Errno> {
        let mtime_ns = i128::from((self.clock)()?);
        let charge = Charge::take(&self.usage, Charge::pages_of(&kind))?;
        let links = if matches!(kind, Kind::Dir(_)) { 2 } else { 1 };
        let id = self.next;
        self.next += 1;
        self.nodes.insert(
            id,
            Arc::new(Mutex::new(Node {
                kind,
                mode,
                owner: (0, 0),
                xattrs: Default::default(),
                attributes: 0,
                links,
                locks: BTreeMap::new(),
                mtime_ns,
                clock: self.clock.clone(),
                _charge: charge,
            })),
        );
        Ok(id)
    }
    fn resolve(&self, path: &[u8], follow: bool) -> Result<u64, Errno> {
        validate(path)?;
        if path[0] != b'/' {
            return Err(Errno::ENOENT);
        }
        let mut queue: VecDeque<Vec<u8>> = path
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .map(Vec::from)
            .collect();
        let mut stack = vec![1];
        let mut links = 0;
        while let Some(p) = queue.pop_front() {
            let current = *stack.last().ok_or(Errno::EIO)?;
            let parent = self.node(current)?;
            let n = lock(&parent);
            let Kind::Dir(children) = &n.kind else {
                return Err(Errno::ENOTDIR);
            };
            if p == b"." {
                continue;
            }
            if p == b".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let id = *children.get(&p).ok_or(Errno::ENOENT)?;
            drop(n);
            let arc = self.node(id)?;
            let child = lock(&arc);
            if let Kind::Symlink(target) = &child.kind
                && (follow || !queue.is_empty() || path.last() == Some(&b'/'))
            {
                links += 1;
                if links > 40 {
                    return Err(Errno(40));
                }
                if target.is_empty() {
                    return Err(Errno::ENOENT);
                }
                if target[0] == b'/' {
                    stack.truncate(1)
                }
                for part in target.split(|b| *b == b'/').filter(|p| !p.is_empty()).rev() {
                    queue.push_front(part.to_vec())
                }
                continue;
            }
            stack.push(id);
        }
        let id = *stack.last().ok_or(Errno::EIO)?;
        if path.last() == Some(&b'/') && !matches!(lock(&*self.node(id)?).kind, Kind::Dir(_)) {
            return Err(Errno::ENOTDIR);
        }
        Ok(id)
    }
    fn parent(&self, path: &[u8]) -> Result<(u64, Vec<u8>), Errno> {
        validate(path)?;
        let trimmed = path.trim_suffix(b"/");
        let pos = trimmed
            .iter()
            .rposition(|b| *b == b'/')
            .ok_or(Errno::ENOENT)?;
        let name = trimmed[pos + 1..].to_vec();
        if name.is_empty() || name == b"." || name == b".." {
            return Err(Errno::EINVAL);
        }
        let parent = self.resolve(if pos == 0 { b"/" } else { &trimmed[..pos] }, true)?;
        if !matches!(lock(&*self.node(parent)?).kind, Kind::Dir(_)) {
            return Err(Errno::ENOTDIR);
        }
        Ok((parent, name))
    }
    fn insert(&mut self, path: &[u8], kind: Kind, mode: u32) -> Result<u64, Errno> {
        let (p, name) = self.parent(path)?;
        let arc = self.node(p)?;
        let mut n = lock(&arc);
        // inode_init_owner: in a set-group-ID directory a new file takes the
        // directory's group, and a new directory the bit as well.
        let group = (n.mode & 0o2000 != 0).then_some(n.owner.1);
        // tmpfs's `SHMEM_FL_INHERITED`: FS_NODUMP_FL and FS_NOATIME_FL.
        let inherited = n.attributes & (0x40 | 0x80);
        let Kind::Dir(children) = &mut n.kind else {
            return Err(Errno::ENOTDIR);
        };
        if children.contains_key(&name) {
            return Err(Errno::EEXIST);
        }
        let directory = matches!(kind, Kind::Dir(_));
        let id = self.allocate(kind, mode)?;
        if inherited != 0 {
            lock(&*self.node(id)?).attributes = inherited;
        }
        if let Some(group) = group {
            let node = self.node(id)?;
            let mut child = lock(&node);
            child.owner.1 = group;
            if directory {
                child.mode |= 0o2000;
            }
        }
        children.insert(name, id);
        if directory {
            n.links += 1;
        }
        Ok(id)
    }
}
pub struct MemFs {
    tree: Arc<Mutex<Tree>>,
}
impl Default for MemFs {
    fn default() -> Self {
        Self::with_clock(Arc::new(|| Ok(0)))
    }
}
impl MemFs {
    /// Typed realtime clock used for created and modified files. The default
    /// preserves deterministic epoch metadata for existing standalone callers.
    pub fn with_clock(clock: Arc<dyn Fn() -> Result<u64, Errno> + Send + Sync>) -> Self {
        let usage = Arc::<Usage>::default();
        let charge = Charge::root(&usage);
        let root = Node {
            _charge: charge,
            kind: Kind::Dir(BTreeMap::new()),
            mode: 0o040755,
            owner: (0, 0),
            xattrs: Default::default(),
            attributes: 0,
            links: 2,
            locks: BTreeMap::new(),
            mtime_ns: 0,
            clock: clock.clone(),
        };
        Self {
            tree: Arc::new(Mutex::new(Tree {
                nodes: BTreeMap::from([(1, Arc::new(Mutex::new(root)))]),
                usage,
                next: 2,
                owner: 1,
                clock,
            })),
        }
    }
}
impl MemFs {
    /// What its files take, against the limits a mount sets.
    pub(crate) fn usage(&self) -> Arc<Usage> {
        Arc::clone(&lock(&self.tree).usage)
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_file(&mut self, file: GuestFile) -> Result<(), Errno> {
        let path = normalize_path(&file.path)?;
        if path == b"/" {
            return Err(Errno::EISDIR);
        }
        let mut t = lock(&self.tree);
        let mut prefix = Vec::new();
        let parts: Vec<_> = path
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .collect();
        for p in &parts[..parts.len() - 1] {
            prefix.push(b'/');
            prefix.extend_from_slice(p);
            if t.resolve(&prefix, true) == Err(Errno::ENOENT) {
                t.insert(&prefix, Kind::Dir(BTreeMap::new()), 0o040755)?;
            }
        }
        let contents = Contents::with_bytes(&t.usage, &file.content);
        let id = t.insert(&path, Kind::File(contents), 0o100000 | (file.mode & 0o7777))?;
        lock(&*t.node(id)?).mtime_ns = 0;
        Ok(())
    }
}
#[cfg(test)]
mod core_tests;
#[cfg(test)]
mod entries_tests;
#[cfg(test)]
mod files_tests;
#[cfg(test)]
mod wasm_tests;

mod entries;
pub use entries::{EntryKind, GuestEntry, MAX_ENTRIES, MAX_ENTRY_BYTES};

mod mount;
pub use mount::MountedFs;

mod namespace;
pub use namespace::{
    FIRST_NAMESPACE_ID, GeneratedSource, InUse, MountChange, MountHook, MountPin, MountTable,
    NamespacedFs, NewTmpfs, Propagation, Reach, ReleaseHook, Settings, SuperblockHook, Target,
    UNIQUE_OFFSET, keeping_expiry, mount_flags,
};

mod open_file;
use open_file::MemFile;
mod operations;
