use crate::*;
impl HostFs for MemFs {
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        if flags & (64 | 65536) == 64 | 65536 {
            return Err(Errno::EINVAL);
        }
        let mut t = lock(&self.tree);
        let id = match t.resolve(path, flags & 131072 == 0) {
            Ok(id) => {
                if flags & 192 == 192 {
                    return Err(Errno::EEXIST);
                }
                id
            }
            Err(e) if e == Errno::ENOENT && flags & 64 != 0 => {
                let mut target = path.to_vec();
                let mut traversals = 0;
                loop {
                    match t.resolve(&target, false) {
                        Ok(id) => {
                            let a = t.node(id)?;
                            let n = lock(&a);
                            if let Kind::Symlink(link) = &n.kind {
                                if flags & 128 != 0 {
                                    return Err(Errno::EEXIST);
                                }
                                if flags & 131072 != 0 {
                                    return Err(Errno(40));
                                }
                                traversals += 1;
                                if traversals > 40 {
                                    return Err(Errno(40));
                                }
                                target = if link.first() == Some(&b'/') {
                                    link.clone()
                                } else {
                                    let mut p = target[..target
                                        .iter()
                                        .rposition(|b| *b == b'/')
                                        .ok_or(Errno::ENOENT)?
                                        + 1]
                                        .to_vec();
                                    p.extend_from_slice(link);
                                    p
                                };
                            } else {
                                break id;
                            }
                        }
                        Err(e) if e == Errno::ENOENT => {
                            let contents = Contents::new(&t.usage);
                            break t.insert(
                                &target,
                                Kind::File(contents),
                                0o100000 | (mode & 0o7777),
                            )?;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => return Err(e),
        };
        let node = t.node(id)?;
        let mut n = lock(&node);
        if matches!(n.kind, Kind::Symlink(_)) {
            return Err(Errno(40));
        }
        if flags & 65536 != 0 && !matches!(n.kind, Kind::Dir(_)) {
            return Err(Errno::ENOTDIR);
        }
        if matches!(n.kind, Kind::Dir(_)) && (flags & 3 != 0 || flags & 512 != 0) {
            return Err(Errno::EISDIR);
        }
        if flags & 512 != 0 && matches!(n.kind, Kind::File(_)) {
            let modified = (n.clock)()?;
            let Kind::File(b) = &mut n.kind else {
                unreachable!()
            };
            b.set_len(0);
            n.mtime_ns = i128::from(modified);
        }
        drop(n);
        let owner = t.owner;
        t.owner += 1;
        Ok(Arc::new(MemFile {
            tree: Arc::clone(&self.tree),
            node,
            inode: id,
            owner,
            state: Mutex::new((0, flags)),
        }))
    }
    fn metadata(&self, path: &[u8], follow: bool) -> Result<FileStat, Errno> {
        let t = lock(&self.tree);
        let id = t.resolve(path, follow)?;
        Ok(lock(&*t.node(id)?).stat(id))
    }
    fn set_mode(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        let t = lock(&self.tree);
        let node = t.node(t.resolve(path, true)?)?;
        set_node_mode(&mut lock(&node), mode);
        Ok(())
    }
    fn set_times(
        &self,
        path: &[u8],
        follow: bool,
        _atime: Option<i128>,
        mtime: Option<i128>,
    ) -> Result<(), Errno> {
        let t = lock(&self.tree);
        let node = t.node(t.resolve(path, follow)?)?;
        set_node_mtime(&mut lock(&node), mtime);
        Ok(())
    }
    /// A tmpfs of [`MEMORY_BYTES`]: the blocks and inodes used are what the
    /// tree holds.
    fn statfs(&self, path: &[u8]) -> Result<FsStats, Errno> {
        let t = lock(&self.tree);
        t.resolve(path, true)?;
        let used = t.used_blocks();
        let blocks = MEMORY_BYTES / BLOCK;
        let files = 1 << 20;
        Ok(FsStats {
            kind: TMPFS_MAGIC,
            block_size: BLOCK,
            blocks,
            blocks_free: blocks.saturating_sub(used),
            blocks_available: blocks.saturating_sub(used),
            files,
            files_free: files.saturating_sub(t.nodes.len() as u64),
            name_max: NAME_MAX as u64,
        })
    }
    fn mkdir(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        lock(&self.tree).insert(path, Kind::Dir(BTreeMap::new()), 0o040000 | (mode & 0o7777))?;
        Ok(())
    }
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno> {
        let mut t = lock(&self.tree);
        t.require_trailing_directory(path)?;
        let (p, name) = t.parent(path)?;
        let parent = t.node(p)?;
        let mut n = lock(&parent);
        let Kind::Dir(children) = &mut n.kind else {
            return Err(Errno::ENOTDIR);
        };
        let id = *children.get(&name).ok_or(Errno::ENOENT)?;
        let arc = t.node(id)?;
        let mut child = lock(&arc);
        match &child.kind {
            Kind::Dir(entries) => {
                if !directory {
                    return Err(Errno::EISDIR);
                }
                if !entries.is_empty() {
                    return Err(Errno(39));
                }
            }
            _ if directory => return Err(Errno::ENOTDIR),
            _ => {}
        }
        children.remove(&name);
        if directory {
            n.links -= 1;
            child.links = 0;
        } else {
            child.links = child.links.saturating_sub(1);
        }
        let orphan = child.links == 0;
        drop(child);
        drop(n);
        if orphan {
            t.nodes.remove(&id);
        }
        Ok(())
    }
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        let t = lock(&self.tree);
        let id = t.resolve(old, false)?;
        let arc = t.node(id)?;
        if matches!(lock(&arc).kind, Kind::Dir(_)) {
            return Err(Errno::EPERM);
        }
        let (p, name) = t.parent(new)?;
        let parent = t.node(p)?;
        let mut n = lock(&parent);
        let Kind::Dir(children) = &mut n.kind else {
            return Err(Errno::ENOTDIR);
        };
        if children.contains_key(&name) {
            return Err(Errno::EEXIST);
        }
        children.insert(name, id);
        lock(&arc).links += 1;
        Ok(())
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno> {
        validate(target)?;
        lock(&self.tree).insert(path, Kind::Symlink(target.to_vec()), 0o120777)?;
        Ok(())
    }
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        let t = lock(&self.tree);
        let id = t.resolve(path, false)?;
        match &lock(&*t.node(id)?).kind {
            Kind::Symlink(b) => Ok(b.clone()),
            _ => Err(Errno::EINVAL),
        }
    }
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        let mut t = lock(&self.tree);
        t.require_trailing_directory(old)?;
        let (op, on) = t.parent(old)?;
        let (np, nn) = t.parent(new)?;
        let oa = t.node(op)?;
        let id = match &lock(&oa).kind {
            Kind::Dir(m) => *m.get(&on).ok_or(Errno::ENOENT)?,
            _ => return Err(Errno::ENOTDIR),
        };
        let na = t.node(np)?;
        let dst = match &lock(&na).kind {
            Kind::Dir(m) => m.get(&nn).copied(),
            _ => return Err(Errno::ENOTDIR),
        };
        if dst == Some(id) {
            return Ok(());
        }
        let src_dir = matches!(lock(&*t.node(id)?).kind, Kind::Dir(_));
        if src_dir {
            let mut ancestors = VecDeque::from([id]);
            while let Some(a) = ancestors.pop_front() {
                if a == np {
                    return Err(Errno::EINVAL);
                }
                if let Kind::Dir(m) = &lock(&*t.node(a)?).kind {
                    ancestors.extend(m.values().copied())
                }
            }
        }
        if let Some(d) = dst {
            let a = t.node(d)?;
            let n = lock(&a);
            match &n.kind {
                Kind::Dir(m) => {
                    if !src_dir {
                        return Err(Errno::EISDIR);
                    }
                    if !m.is_empty() {
                        return Err(Errno(39));
                    }
                }
                _ if src_dir => return Err(Errno::ENOTDIR),
                _ => {}
            }
            let dst_dir = matches!(n.kind, Kind::Dir(_));
            drop(n);
            let mut removed = lock(&a);
            if dst_dir {
                removed.links = 0;
            } else {
                removed.links -= 1;
            }
            let orphan = removed.links == 0;
            drop(removed);
            if orphan {
                t.nodes.remove(&d);
            }
            if dst_dir {
                lock(&na).links -= 1;
            }
        }
        if let Kind::Dir(m) = &mut lock(&oa).kind {
            m.remove(&on);
        }
        if let Kind::Dir(m) = &mut lock(&na).kind {
            m.insert(nn, id);
        }
        if src_dir && op != np {
            lock(&oa).links -= 1;
            lock(&na).links += 1;
        }
        Ok(())
    }
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        let t = lock(&self.tree);
        let id = t.resolve(path, true)?;
        let a = t.node(id)?;
        let n = lock(&a);
        let Kind::Dir(m) = &n.kind else {
            return Err(Errno::ENOTDIR);
        };
        let mut out = vec![
            DirectoryEntry {
                name: b".".to_vec(),
                inode: id,
                kind: 4,
            },
            DirectoryEntry {
                name: b"..".to_vec(),
                inode: 1,
                kind: 4,
            },
        ];
        for (name, id) in m {
            let s = lock(&*t.node(*id)?).stat(*id);
            out.push(DirectoryEntry {
                name: name.clone(),
                inode: *id,
                kind: (s.mode >> 12) as u8,
            })
        }
        Ok(out)
    }
}
impl FileSystem for MemFs {}
