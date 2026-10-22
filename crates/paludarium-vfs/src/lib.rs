//! Safe in-memory filesystem and the host capability mount boundary.
#![forbid(unsafe_code)]
pub use paludarium_host::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs};
use paludarium_types::Errno;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    for p in path.split(|b| *b == b'/') {
        if p.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
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
/// `TMPFS_MAGIC`: what the in-memory filesystem calls itself.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
/// The size the in-memory filesystem reports, the memory `sysinfo` reports.
pub const MEMORY_BYTES: u64 = 4 << 30;
const BLOCK: u64 = 4096;
/// One line of the mount table: where, and which filesystem type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountPoint {
    pub path: Vec<u8>,
    pub kind: &'static str,
}
pub trait FileSystem: HostFs {
    /// The mounts, root first, for `/proc/self/mountinfo`.
    fn mounts(&self) -> Vec<MountPoint> {
        vec![MountPoint {
            path: b"/".to_vec(),
            kind: "tmpfs",
        }]
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
    File(Vec<u8>),
    Dir(BTreeMap<Vec<u8>, u64>),
    Symlink(Vec<u8>),
}
struct Node {
    kind: Kind,
    mode: u32,
    links: u64,
    locks: BTreeMap<u64, u32>,
    mtime_ns: i128,
    clock: Arc<dyn Fn() -> Result<u64, Errno> + Send + Sync>,
}
impl Node {
    fn stat(&self, id: u64) -> FileStat {
        FileStat {
            inode: id,
            size: match &self.kind {
                Kind::File(b) | Kind::Symlink(b) => b.len() as u64,
                Kind::Dir(_) => 0,
            },
            mode: self.mode,
            links: self.links,
            mtime_ns: self.mtime_ns,
        }
    }
}
/// `chmod`: the file type stays, the permission bits are replaced.
fn set_node_mode(node: &mut Node, mode: u32) {
    node.mode = (node.mode & 0o170000) | (mode & 0o7777);
}
/// `utimensat`: only the modification time is kept; the access time is not.
fn set_node_mtime(node: &mut Node, mtime: Option<i128>) {
    if let Some(mtime) = mtime {
        node.mtime_ns = mtime;
    }
}
struct Tree {
    nodes: BTreeMap<u64, Arc<Mutex<Node>>>,
    next: u64,
    owner: u64,
    clock: Arc<dyn Fn() -> Result<u64, Errno> + Send + Sync>,
}
impl Tree {
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
    fn node(&self, id: u64) -> Result<Arc<Mutex<Node>>, Errno> {
        self.nodes.get(&id).cloned().ok_or(Errno::ENOENT)
    }
    fn allocate(&mut self, kind: Kind, mode: u32) -> Result<u64, Errno> {
        let mtime_ns = i128::from((self.clock)()?);
        let links = if matches!(kind, Kind::Dir(_)) { 2 } else { 1 };
        let id = self.next;
        self.next += 1;
        self.nodes.insert(
            id,
            Arc::new(Mutex::new(Node {
                kind,
                mode,
                links,
                locks: BTreeMap::new(),
                mtime_ns,
                clock: self.clock.clone(),
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
        let trimmed = path.strip_suffix(b"/").unwrap_or(path);
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
        let Kind::Dir(children) = &mut n.kind else {
            return Err(Errno::ENOTDIR);
        };
        if children.contains_key(&name) {
            return Err(Errno::EEXIST);
        }
        let directory = matches!(kind, Kind::Dir(_));
        let id = self.allocate(kind, mode)?;
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
        let root = Node {
            kind: Kind::Dir(BTreeMap::new()),
            mode: 0o040755,
            links: 2,
            locks: BTreeMap::new(),
            mtime_ns: 0,
            clock: clock.clone(),
        };
        Self {
            tree: Arc::new(Mutex::new(Tree {
                nodes: BTreeMap::from([(1, Arc::new(Mutex::new(root)))]),
                next: 2,
                owner: 1,
                clock,
            })),
        }
    }
}
impl MemFs {
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
        let id = t.insert(
            &path,
            Kind::File(file.content),
            0o100000 | (file.mode & 0o7777),
        )?;
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

mod open_file;
use open_file::MemFile;
mod operations;
