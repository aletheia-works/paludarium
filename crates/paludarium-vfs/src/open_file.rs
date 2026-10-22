use crate::*;
pub(super) struct MemFile {
    pub(super) tree: Arc<Mutex<Tree>>,
    pub(super) node: Arc<Mutex<Node>>,
    pub(super) inode: u64,
    pub(super) owner: u64,
    pub(super) state: Mutex<(u64, u32)>,
}
impl Drop for MemFile {
    fn drop(&mut self) {
        lock(&self.node).locks.remove(&self.owner);
    }
}
impl FileHandle for MemFile {
    fn guest_path_hint(&self) -> Option<Vec<u8>> {
        let t = lock(&self.tree);
        let mut q = VecDeque::from([(1, b"/".to_vec())]);
        while let Some((id, p)) = q.pop_front() {
            if id == self.inode {
                return Some(p);
            }
            if let Kind::Dir(children) = &lock(&*t.node(id).ok()?).kind {
                for (name, id) in children {
                    let mut next = p.clone();
                    if next.last() != Some(&b'/') {
                        next.push(b'/')
                    }
                    next.extend_from_slice(name);
                    q.push_back((*id, next));
                }
            }
        }
        None
    }
    fn read(&self, b: &mut [u8]) -> Result<usize, Errno> {
        let mut s = lock(&self.state);
        if s.1 & 3 == 1 {
            return Err(Errno::EBADF);
        }
        let n = lock(&self.node);
        let Kind::File(data) = &n.kind else {
            return Err(Errno::EISDIR);
        };
        let pos = usize::try_from(s.0).map_err(|_| Errno::EINVAL)?;
        let count = b.len().min(data.len().saturating_sub(pos));
        if count > 0 {
            b[..count].copy_from_slice(&data[pos..pos + count]);
        }
        s.0 += count as u64;
        Ok(count)
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        let mut s = lock(&self.state);
        if s.1 & 3 == 0 {
            return Err(Errno::EBADF);
        }
        let mut n = lock(&self.node);
        let modified = (n.clock)()?;
        let Kind::File(data) = &mut n.kind else {
            return Err(Errno::EISDIR);
        };
        if s.1 & 1024 != 0 {
            s.0 = data.len() as u64
        }
        let pos = usize::try_from(s.0).map_err(|_| Errno::EINVAL)?;
        let end = pos.checked_add(b.len()).ok_or(Errno::EINVAL)?;
        if end > data.len() {
            data.try_reserve(end - data.len())
                .map_err(|_| Errno::ENOMEM)?;
            data.resize(end, 0)
        }
        data[pos..end].copy_from_slice(b);
        s.0 = end as u64;
        if !b.is_empty() {
            n.mtime_ns = i128::from(modified);
        }
        Ok(b.len())
    }
    fn seek(&self, off: i64, w: u32) -> Result<u64, Errno> {
        let mut s = lock(&self.state);
        let n = lock(&self.node);
        let base = match w {
            0 => 0,
            1 => s.0,
            2 => n.stat(self.inode).size,
            _ => return Err(Errno::EINVAL),
        };
        s.0 = base
            .checked_add_signed(off)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Errno::EINVAL)?;
        Ok(s.0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(lock(&self.node).stat(self.inode))
    }
    fn truncate(&self, size: u64) -> Result<(), Errno> {
        if self.flags() & 3 == 0 {
            return Err(Errno::EINVAL);
        }
        let mut n = lock(&self.node);
        let modified = (n.clock)()?;
        let Kind::File(b) = &mut n.kind else {
            return Err(Errno::EISDIR);
        };
        let len = usize::try_from(size).map_err(|_| Errno::EINVAL)?;
        if len > b.len() {
            b.try_reserve(len - b.len()).map_err(|_| Errno::ENOMEM)?;
        }
        b.resize(len, 0);
        n.mtime_ns = i128::from(modified);
        Ok(())
    }
    fn flock(&self, op: u32) -> Result<(), Errno> {
        let kind = op & !4;
        if !matches!(kind, 1 | 2 | 8) || op & !15 != 0 {
            return Err(Errno::EINVAL);
        }
        let mut n = lock(&self.node);
        n.locks.remove(&self.owner);
        if kind == 8 {
            return Ok(());
        }
        if n.locks.values().any(|v| kind == 2 || *v == 2) {
            return Err(Errno::EAGAIN);
        }
        n.locks.insert(self.owner, kind);
        Ok(())
    }
    fn flags(&self) -> u32 {
        lock(&self.state).1
    }
    fn set_flags(&self, f: u32) -> Result<(), Errno> {
        let mut s = lock(&self.state);
        s.1 = (s.1 & !3072) | (f & 3072);
        Ok(())
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        set_node_mode(&mut lock(&self.node), mode);
        Ok(())
    }
    fn set_times(&self, _atime: Option<i128>, mtime: Option<i128>) -> Result<(), Errno> {
        set_node_mtime(&mut lock(&self.node), mtime);
        Ok(())
    }
    /// Memory needs no synchronising; files and directories both succeed.
    fn sync(&self) -> Result<(), Errno> {
        Ok(())
    }
}
