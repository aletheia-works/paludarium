//! Placing a whole tree before start: directories, symlinks and hard links,
//! each with its mode and modification time, as a snapshot lists them.
use crate::*;

/// At most this many entries are placed (the inode count `statfs` reports).
pub const MAX_ENTRIES: usize = 1 << 20;
/// At most this many content bytes are placed, file contents and symlink
/// targets together; a hard link adds none.
pub const MAX_ENTRY_BYTES: usize = 256 << 20;

/// What one [`GuestEntry`] is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File(Vec<u8>),
    Directory,
    /// The target bytes.
    Symlink(Vec<u8>),
    /// Another name for the file or symlink of an entry at this path. It has
    /// that entry's mode and modification time.
    HardLink(Vec<u8>),
}

/// One path placed by [`MemFs::add_entries`]. `mode` holds the permission
/// bits only (0o7777); a symlink's are always 0o777.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestEntry {
    pub path: Vec<u8>,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime_ns: i128,
}

fn depth(path: &[u8]) -> usize {
    path.iter().filter(|b| **b == b'/').count()
}

impl Tree {
    /// The node at a normalized path, without following any symlink. A
    /// symlink or file on the way is `ENOTDIR`.
    fn lookup(&self, path: &[u8]) -> Result<Option<u64>, Errno> {
        let mut id = 1;
        for name in path.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            let node = self.node(id)?;
            let n = lock(&node);
            let Kind::Dir(children) = &n.kind else {
                return Err(Errno::ENOTDIR);
            };
            let Some(child) = children.get(name) else {
                return Ok(None);
            };
            id = *child;
        }
        Ok(Some(id))
    }
    /// The directory that will hold a normalized path, which must not exist.
    fn place(&self, path: &[u8]) -> Result<(), Errno> {
        let parent = &path[..path.iter().rposition(|b| *b == b'/').ok_or(Errno::EINVAL)?];
        let parent = self
            .lookup(if parent.is_empty() { b"/" } else { parent })?
            .ok_or(Errno::ENOENT)?;
        if !matches!(lock(&*self.node(parent)?).kind, Kind::Dir(_)) {
            return Err(Errno::ENOTDIR);
        }
        if self.lookup(path)?.is_some() {
            return Err(Errno::EEXIST);
        }
        Ok(())
    }
}

impl MemFs {
    /// Places `entries` in any order: each path must be normalized, appear
    /// once and have an existing directory, or a directory entry, as its
    /// parent, with no symlink on the way. A directory entry for an existing
    /// directory (`/`, for one) sets its mode and time. Times are set last,
    /// so placing children does not change them.
    pub fn add_entries(&mut self, entries: &[GuestEntry]) -> Result<(), Errno> {
        if entries.len() > MAX_ENTRIES {
            return Err(Errno::EINVAL);
        }
        let mut bytes = 0usize;
        for entry in entries {
            if normalize_path(&entry.path)? != entry.path || entry.mode & !0o7777 != 0 {
                return Err(Errno::EINVAL);
            }
            match &entry.kind {
                EntryKind::File(content) => bytes = bytes.saturating_add(content.len()),
                EntryKind::Symlink(target) => {
                    if target.is_empty() || entry.mode != 0o777 {
                        return Err(Errno::EINVAL);
                    }
                    validate(target)?;
                    bytes = bytes.saturating_add(target.len());
                }
                EntryKind::Directory => {}
                EntryKind::HardLink(old) => {
                    if normalize_path(old)? != *old {
                        return Err(Errno::EINVAL);
                    }
                }
            }
        }
        if bytes > MAX_ENTRY_BYTES {
            return Err(Errno::EINVAL);
        }
        // Parents first; hard links after everything they may name.
        let mut order: Vec<&GuestEntry> = entries.iter().collect();
        order.sort_by(|a, b| {
            let link = |e: &GuestEntry| matches!(e.kind, EntryKind::HardLink(_));
            (link(a), depth(&a.path), &a.path).cmp(&(link(b), depth(&b.path), &b.path))
        });
        if order.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(Errno::EEXIST);
        }
        let mut t = lock(&self.tree);
        for entry in &order {
            let path = &entry.path;
            match &entry.kind {
                EntryKind::Directory => match t.lookup(path)? {
                    Some(id) => {
                        let node = t.node(id)?;
                        let mut n = lock(&node);
                        if !matches!(n.kind, Kind::Dir(_)) {
                            return Err(Errno::EEXIST);
                        }
                        set_node_mode(&mut n, entry.mode);
                    }
                    None => {
                        t.place(path)?;
                        t.insert(path, Kind::Dir(BTreeMap::new()), 0o040000 | entry.mode)?;
                    }
                },
                EntryKind::File(content) => {
                    t.place(path)?;
                    let contents = Contents::with_bytes(&t.usage, content);
                    t.insert(path, Kind::File(contents), 0o100000 | entry.mode)?;
                }
                EntryKind::Symlink(target) => {
                    t.place(path)?;
                    t.insert(path, Kind::Symlink(target.clone()), 0o120777)?;
                }
                EntryKind::HardLink(old) => {
                    t.place(path)?;
                    let id = t.lookup(old)?.ok_or(Errno::ENOENT)?;
                    let node = t.node(id)?;
                    if matches!(lock(&node).kind, Kind::Dir(_)) {
                        return Err(Errno::EPERM);
                    }
                    let (parent, name) = t.parent(path)?;
                    let parent = t.node(parent)?;
                    let Kind::Dir(children) = &mut lock(&parent).kind else {
                        return Err(Errno::ENOTDIR);
                    };
                    children.insert(name, id);
                    lock(&node).links += 1;
                }
            }
        }
        for entry in order.iter().rev() {
            if !matches!(entry.kind, EntryKind::HardLink(_)) {
                let id = t.lookup(&entry.path)?.ok_or(Errno::ENOENT)?;
                lock(&*t.node(id)?).mtime_ns = entry.mtime_ns;
            }
        }
        Ok(())
    }
}
