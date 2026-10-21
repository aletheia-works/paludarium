//! Compose inode-backed private files with explicit directory capabilities.
use crate::*;
use std::collections::BTreeSet;
pub struct MountedFs {
    base: MemFs,
    mounts: Vec<(Vec<u8>, Arc<dyn HostFs>)>,
    private_files: BTreeSet<Vec<u8>>,
    private_dirs: BTreeSet<Vec<u8>>,
    // Host storage uses confined relative targets; guests retain their namespace.
    targets: Mutex<BTreeMap<(usize, u64), Vec<u8>>>,
}
impl MountedFs {
    fn require_trailing_directory(&self, path: &[u8]) -> Result<(), Errno> {
        if path.last() == Some(&b'/') {
            let end = path.iter().rposition(|b| *b != b'/').map_or(1, |i| i + 1);
            let p = self.resolve(&path[..end], false, false)?;
            if self.raw_metadata(&p)?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
        }
        Ok(())
    }
    pub fn new(base: MemFs) -> Self {
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        {
            let tree = lock(&base.tree);
            let mut queue = VecDeque::from([(1, b"/".to_vec())]);
            while let Some((id, p)) = queue.pop_front() {
                if let Ok(node) = tree.node(id) {
                    let n = lock(&node);
                    match &n.kind {
                        Kind::Dir(children) => {
                            for (name, id) in children {
                                let mut next = p.clone();
                                if next.last() != Some(&b'/') {
                                    next.push(b'/')
                                }
                                next.extend_from_slice(name);
                                queue.push_back((*id, next));
                            }
                        }
                        _ => {
                            files.insert(p.clone());
                            let mut parent = p;
                            while let Some(pos) = parent.iter().rposition(|b| *b == b'/') {
                                parent.truncate(pos.max(1));
                                dirs.insert(parent.clone());
                                if parent == b"/" {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        Self {
            base,
            mounts: Vec::new(),
            private_files: files,
            private_dirs: dirs,
            targets: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn mount(&mut self, path: Vec<u8>, fs: Arc<dyn HostFs>) -> Result<(), Errno> {
        let path = normalize_path(&path)?;
        if self.mounts.iter().any(|(p, _)| *p == path) {
            return Err(Errno::EEXIST);
        }
        let mut prefix = Vec::new();
        for part in path.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            prefix.push(b'/');
            prefix.extend_from_slice(part);
            match self.base.mkdir(&prefix, 0o755) {
                Ok(()) => {}
                Err(e) if e == Errno::EEXIST => {
                    if self.base.metadata(&prefix, true)?.mode & 0o170000 != 0o040000 {
                        return Err(Errno::ENOTDIR);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.mounts.push((path, fs));
        self.mounts.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Ok(())
    }
    fn route<'a>(&'a self, p: &[u8]) -> Result<(usize, &'a dyn HostFs, Vec<u8>), Errno> {
        validate(p)?;
        if !self.private_files.contains(p) {
            for (i, (root, fs)) in self.mounts.iter().enumerate() {
                if p == root
                    || root == b"/"
                    || p.starts_with(root) && p.get(root.len()) == Some(&b'/')
                {
                    let suffix = if root == b"/" {
                        &p[1..]
                    } else {
                        p.get(root.len() + 1..).unwrap_or(b"")
                    };
                    let relative = if suffix.is_empty() {
                        b".".to_vec()
                    } else {
                        suffix.to_vec()
                    };
                    if self.private_dirs.contains(p)
                        && fs.metadata(&relative, false) == Err(Errno::ENOENT)
                    {
                        break;
                    }
                    return Ok((i, fs.as_ref(), relative));
                }
            }
        }
        Ok((self.mounts.len(), &self.base, p.to_vec()))
    }
    fn raw_metadata(&self, p: &[u8]) -> Result<FileStat, Errno> {
        let (i, fs, relative) = self.route(p)?;
        let mut s = fs.metadata(&relative, false)?;
        if s.mode & 0o170000 == 0o120000
            && let Some(target) = lock(&self.targets).get(&(i, s.inode))
        {
            s.size = target.len() as u64;
        }
        Ok(s)
    }
    fn raw_readlink(&self, p: &[u8]) -> Result<Vec<u8>, Errno> {
        let (i, fs, relative) = self.route(p)?;
        let s = fs.metadata(&relative, false)?;
        if s.mode & 0o170000 != 0o120000 {
            return Err(Errno::EINVAL);
        }
        if let Some(target) = lock(&self.targets).get(&(i, s.inode)) {
            return Ok(target.clone());
        }
        fs.readlink(&relative)
    }
    /// Walk components before dot-dot, and expand links in the guest namespace.
    fn resolve(&self, p: &[u8], follow: bool, missing: bool) -> Result<Vec<u8>, Errno> {
        validate(p)?;
        if p[0] != b'/' {
            return Err(Errno::ENOENT);
        }
        let mut queue: VecDeque<Vec<u8>> = p
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .map(Vec::from)
            .collect();
        let mut current = b"/".to_vec();
        let mut links = 0;
        while let Some(part) = queue.pop_front() {
            if self.raw_metadata(&current)?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            if part == b"." {
                continue;
            }
            if part == b".." {
                if current != b"/" {
                    let at = current.iter().rposition(|b| *b == b'/').ok_or(Errno::EIO)?;
                    current.truncate(at.max(1));
                }
                continue;
            }
            let mut next = current.clone();
            if next.last() != Some(&b'/') {
                next.push(b'/')
            }
            next.extend_from_slice(&part);
            let s = match self.raw_metadata(&next) {
                Ok(s) => s,
                Err(e) if e == Errno::ENOENT && queue.is_empty() && missing => return Ok(next),
                Err(e) => return Err(e),
            };
            if s.mode & 0o170000 == 0o120000
                && (follow || !queue.is_empty() || p.last() == Some(&b'/'))
            {
                links += 1;
                if links > 40 {
                    return Err(Errno(40));
                }
                let target = self.raw_readlink(&next)?;
                validate(&target)?;
                if target[0] == b'/' {
                    current = b"/".to_vec()
                }
                for component in target.split(|b| *b == b'/').filter(|p| !p.is_empty()).rev() {
                    queue.push_front(component.to_vec())
                }
            } else {
                current = next
            }
        }
        if p.last() == Some(&b'/') && self.raw_metadata(&current)?.mode & 0o170000 != 0o040000 {
            return Err(Errno::ENOTDIR);
        }
        Ok(current)
    }
}
impl FileSystem for MountedFs {}
impl HostFs for MountedFs {
    fn open(&self, p: &[u8], f: u32, m: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        if f & (64 | 65536) == 64 | 65536 {
            return Err(Errno::EINVAL);
        }
        if f & 192 == 192 && self.raw_metadata(p).is_ok() {
            return Err(Errno::EEXIST);
        }
        let p = self.resolve(p, f & 131072 == 0, f & 64 != 0)?;
        let (_, fs, p) = self.route(&p)?;
        fs.open(&p, f, m)
    }
    fn metadata(&self, p: &[u8], follow: bool) -> Result<FileStat, Errno> {
        self.raw_metadata(&self.resolve(p, follow, false)?)
    }
    fn mkdir(&self, p: &[u8], m: u32) -> Result<(), Errno> {
        let p = self.resolve(p, false, true)?;
        let (_, fs, p) = self.route(&p)?;
        fs.mkdir(&p, m)
    }
    fn unlink(&self, p: &[u8], directory: bool) -> Result<(), Errno> {
        self.require_trailing_directory(p)?;
        let p = self.resolve(p, false, false)?;
        let (i, fs, relative) = self.route(&p)?;
        let old = fs.metadata(&relative, false)?;
        fs.unlink(&relative, directory)?;
        if old.links <= 1 {
            lock(&self.targets).remove(&(i, old.inode));
        }
        Ok(())
    }
    fn link(&self, a: &[u8], b: &[u8]) -> Result<(), Errno> {
        let a = self.resolve(a, false, false)?;
        let b = self.resolve(b, false, true)?;
        let (i, fs, a) = self.route(&a)?;
        let (j, _, b) = self.route(&b)?;
        if i != j {
            return Err(Errno(18));
        }
        fs.link(&a, &b)
    }
    fn symlink(&self, target: &[u8], p: &[u8]) -> Result<(), Errno> {
        validate(target)?;
        let p = self.resolve(p, false, true)?;
        let (i, fs, relative) = self.route(&p)?;
        if i == self.mounts.len() {
            return fs.symlink(target, &relative);
        }
        let root = &self.mounts[i].0;
        let parent = p[..p.iter().rposition(|b| *b == b'/').ok_or(Errno::ENOENT)? + 1].to_vec();
        let absolute = if target[0] == b'/' {
            target.to_vec()
        } else {
            let mut a = parent;
            a.extend_from_slice(target);
            normalize_path(&a)?
        };
        let stored = if target[0] != b'/' {
            target.to_vec()
        } else if absolute == *root
            || root == b"/"
            || absolute.starts_with(root) && absolute.get(root.len()) == Some(&b'/')
        {
            let suffix = if root == b"/" {
                &absolute[1..]
            } else {
                absolute.get(root.len() + 1..).unwrap_or(b"")
            };
            let depth = relative
                .split(|b| *b == b'/')
                .filter(|p| !p.is_empty())
                .count()
                .saturating_sub(1);
            let mut out = Vec::new();
            for _ in 0..depth {
                out.extend_from_slice(b"../")
            }
            out.extend_from_slice(suffix);
            if out.is_empty() {
                out.extend_from_slice(b".")
            }
            out
        } else {
            b".paludarium-guest-namespace-target".to_vec()
        };
        fs.symlink(&stored, &relative)?;
        let inode = fs.metadata(&relative, false)?.inode;
        lock(&self.targets).insert((i, inode), target.to_vec());
        Ok(())
    }
    fn readlink(&self, p: &[u8]) -> Result<Vec<u8>, Errno> {
        self.raw_readlink(&self.resolve(p, false, false)?)
    }
    fn rename(&self, a: &[u8], b: &[u8]) -> Result<(), Errno> {
        self.require_trailing_directory(a)?;
        let a = self.resolve(a, false, false)?;
        let b = self.resolve(b, false, true)?;
        let (i, fs, old) = self.route(&a)?;
        let (j, _, new) = self.route(&b)?;
        if i != j {
            return Err(Errno(18));
        }
        let old_inode = fs.metadata(&old, false)?.inode;
        let replaced = fs.metadata(&new, false).ok();
        fs.rename(&old, &new)?;
        if let Some(s) = replaced
            && s.inode != old_inode
            && s.links <= 1
        {
            lock(&self.targets).remove(&(i, s.inode));
        }
        Ok(())
    }
    fn read_dir(&self, p: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        let p = self.resolve(p, true, false)?;
        let (_, fs, relative) = self.route(&p)?;
        let mut entries: BTreeMap<Vec<u8>, DirectoryEntry> = fs
            .read_dir(&relative)?
            .into_iter()
            .map(|e| (e.name.clone(), e))
            .collect();
        if let Ok(private) = self.base.read_dir(&p) {
            for e in private {
                let mut child = p.clone();
                if child.last() != Some(&b'/') {
                    child.push(b'/')
                }
                child.extend_from_slice(&e.name);
                if self.private_files.contains(&child) || !entries.contains_key(&e.name) {
                    entries.insert(e.name.clone(), e);
                }
            }
        }
        Ok(entries.into_values().collect())
    }
}
#[cfg(test)]
mod mount_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        fs: MountedFs,
        root: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "paludarium-u7-mount-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            let mut fs = MountedFs::new(MemFs::new());
            fs.mount(
                b"/mnt".to_vec(),
                Arc::new(paludarium_host::NativeFs::new(&root).unwrap()),
            )
            .unwrap();
            Self { fs, root }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(std::mem::replace(
                &mut self.fs,
                MountedFs::new(MemFs::new()),
            ));
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn mount_open_metadata() {
        let x = Fixture::new();
        x.fs.open(b"/mnt/a", 66, 0o600)
            .unwrap()
            .write(b"value")
            .unwrap();
        assert_eq!(x.fs.metadata(b"/mnt/a", true).unwrap().size, 5);
        assert_eq!(&*x.fs.read_file(b"/mnt/a").unwrap(), b"value");
    }
    #[test]
    fn mount_directory_listing() {
        let x = Fixture::new();
        assert!(
            x.fs.read_dir(b"/")
                .unwrap()
                .iter()
                .any(|e| e.name == b"mnt")
        );
        x.fs.mkdir(b"/mnt/d", 0o700).unwrap();
        x.fs.open(b"/mnt/d/a", 66, 0o600).unwrap();
        assert!(
            x.fs.read_dir(b"/mnt/d")
                .unwrap()
                .iter()
                .any(|e| e.name == b"a")
        );
        x.fs.unlink(b"/mnt/d/a", false).unwrap();
        x.fs.unlink(b"/mnt/d", true).unwrap();
    }
    #[test]
    fn mount_link_unlink() {
        let x = Fixture::new();
        x.fs.open(b"/mnt/a", 66, 0o600).unwrap();
        x.fs.link(b"/mnt/a", b"/mnt/b").unwrap();
        assert_eq!(x.fs.metadata(b"/mnt/a", true).unwrap().links, 2);
        x.fs.unlink(b"/mnt/a", false).unwrap();
        assert_eq!(x.fs.metadata(b"/mnt/b", true).unwrap().links, 1);
    }
    #[test]
    fn mount_symlink() {
        let x = Fixture::new();
        x.fs.open(b"/mnt/a", 66, 0o600).unwrap();
        x.fs.symlink(b"a", b"/mnt/s").unwrap();
        assert_eq!(x.fs.readlink(b"/mnt/s").unwrap(), b"a");
        assert_eq!(
            x.fs.metadata(b"/mnt/s", false).unwrap().mode & 0o170000,
            0o120000
        );
        assert!(x.fs.metadata(b"/mnt/s", true).is_ok());
    }
    #[test]
    fn mount_rename() {
        let x = Fixture::new();
        x.fs.open(b"/mnt/a", 66, 0o600)
            .unwrap()
            .write(b"a")
            .unwrap();
        x.fs.rename(b"/mnt/a", b"/mnt/b").unwrap();
        assert_eq!(&*x.fs.read_file(b"/mnt/b").unwrap(), b"a");
        assert_eq!(x.fs.metadata(b"/mnt/a", true), Err(Errno::ENOENT));
    }
    #[test]
    fn mount_cross_device() {
        let x = Fixture::new();
        x.fs.open(b"/a", 66, 0o600).unwrap();
        assert_eq!(x.fs.link(b"/a", b"/mnt/a"), Err(Errno(18)));
        assert_eq!(x.fs.rename(b"/a", b"/mnt/a"), Err(Errno(18)));
    }
    #[test]
    fn mount_duplicate() {
        let mut x = Fixture::new();
        assert_eq!(
            x.fs.mount(b"/mnt".to_vec(), Arc::new(MemFs::new())),
            Err(Errno::EEXIST)
        );
    }
    #[test]
    fn mount_prefix_boundary() {
        let x = Fixture::new();
        assert!(x.fs.open(b"/mntx/a", 66, 0o600).is_err());
        assert!(std::fs::read_dir(&x.root).unwrap().next().is_none());
    }
    #[test]
    fn mount_private_to_host_link() {
        let x = Fixture::new();
        x.fs.open(b"/mnt/a", 66, 0o600)
            .unwrap()
            .write(b"host")
            .unwrap();
        x.fs.symlink(b"/mnt/a", b"/s").unwrap();
        assert_eq!(&*x.fs.read_file(b"/s").unwrap(), b"host");
    }
    #[test]
    fn mount_host_to_private_link() {
        let x = Fixture::new();
        x.fs.open(b"/a", 66, 0o600)
            .unwrap()
            .write(b"private")
            .unwrap();
        x.fs.symlink(b"/a", b"/mnt/s").unwrap();
        assert_eq!(&*x.fs.read_file(b"/mnt/s").unwrap(), b"private");
        assert_eq!(x.fs.readlink(b"/mnt/s").unwrap(), b"/a");
        assert_eq!(x.fs.metadata(b"/mnt/s", false).unwrap().size, 2);
    }
    #[test]
    fn mount_link_dotdot_namespace() {
        let x = Fixture::new();
        x.fs.mkdir(b"/mnt/d", 0o700).unwrap();
        x.fs.open(b"/mnt/a", 66, 0o600)
            .unwrap()
            .write(b"a")
            .unwrap();
        x.fs.symlink(b"/mnt/d", b"/s").unwrap();
        assert_eq!(&*x.fs.read_file(b"/s/../a").unwrap(), b"a");
    }
    #[test]
    fn mount_cross_namespace_loop() {
        let x = Fixture::new();
        x.fs.symlink(b"/mnt/s", b"/s").unwrap();
        x.fs.symlink(b"/s", b"/mnt/s").unwrap();
        assert_eq!(x.fs.metadata(b"/s", true), Err(Errno(40)));
    }
    #[test]
    fn mount_link_lifetime() {
        let x = Fixture::new();
        x.fs.symlink(b"/a", b"/mnt/s").unwrap();
        x.fs.link(b"/mnt/s", b"/mnt/t").unwrap();
        x.fs.unlink(b"/mnt/s", false).unwrap();
        assert_eq!(x.fs.readlink(b"/mnt/t").unwrap(), b"/a");
        assert_eq!(lock(&x.fs.targets).len(), 1);
        x.fs.unlink(b"/mnt/t", false).unwrap();
        assert!(lock(&x.fs.targets).is_empty());
    }
    #[test]
    fn mount_relative_link_after_rename() {
        let x = Fixture::new();
        x.fs.mkdir(b"/mnt/d", 0o700).unwrap();
        x.fs.mkdir(b"/mnt/e", 0o700).unwrap();
        x.fs.open(b"/mnt/e/a", 66, 0o600)
            .unwrap()
            .write(b"new")
            .unwrap();
        x.fs.symlink(b"a", b"/mnt/d/s").unwrap();
        x.fs.rename(b"/mnt/d/s", b"/mnt/e/s").unwrap();
        assert_eq!(&*x.fs.read_file(b"/mnt/e/s").unwrap(), b"new");
        assert_eq!(
            std::fs::read_link(x.root.join("e/s")).unwrap(),
            std::path::PathBuf::from("a")
        );
    }
    #[test]
    fn mount_root_private_preload() {
        let x = Fixture::new();
        std::fs::write(x.root.join("program"), b"host").unwrap();
        let base = MemFs::new();
        base.open(b"/program", 66, 0o600)
            .unwrap()
            .write(b"private")
            .unwrap();
        let mut fs = MountedFs::new(base);
        fs.mount(
            b"/".to_vec(),
            Arc::new(paludarium_host::NativeFs::new(&x.root).unwrap()),
        )
        .unwrap();
        assert_eq!(&*fs.read_file(b"/program").unwrap(), b"private");
        assert_eq!(std::fs::read(x.root.join("program")).unwrap(), b"host");
        assert!(
            fs.read_dir(b"/")
                .unwrap()
                .iter()
                .any(|e| e.name == b"program")
        );
    }
    #[test]
    fn mount_private_nested_preload() {
        let x = Fixture::new();
        let base = MemFs::new();
        base.mkdir(b"/d", 0o700).unwrap();
        base.open(b"/d/program", 66, 0o600)
            .unwrap()
            .write(b"private")
            .unwrap();
        let mut fs = MountedFs::new(base);
        fs.mount(
            b"/".to_vec(),
            Arc::new(paludarium_host::NativeFs::new(&x.root).unwrap()),
        )
        .unwrap();
        assert_eq!(&*fs.read_file(b"/d/program").unwrap(), b"private");
        assert!(fs.read_dir(b"/").unwrap().iter().any(|e| e.name == b"d"));
        assert!(
            fs.read_dir(b"/d")
                .unwrap()
                .iter()
                .any(|e| e.name == b"program")
        );
        assert!(!x.root.join("d").exists());
    }
}
