//! Explicit private VFS ownership. Mutations are exclusive with guest leases.
use paludarium_host::Host;
use paludarium_runtime::{Config, Session};
use paludarium_types::{Errno, Error};
use paludarium_vfs::{FileSystem, normalize_path};
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) struct PrivateFs {
    filesystem: Arc<dyn FileSystem>,
    state: Mutex<State>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Active,
    Closed,
}
pub(crate) struct Lease {
    owner: Arc<PrivateFs>,
}
impl Lease {
    pub(crate) fn filesystem(&self) -> Arc<dyn FileSystem> {
        self.owner.filesystem.clone()
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *state == State::Active {
            *state = State::Idle;
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: Vec<u8>,
    pub mode: u32,
    pub inode: u64,
    pub links: u64,
    pub mtime_ns: i128,
    pub content: Vec<u8>,
}
pub(crate) fn snapshot_bytes(entries: &[Entry]) -> Option<Vec<u8>> {
    let mut data = u32::MAX.to_le_bytes().to_vec();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&u32::try_from(entries.len()).ok()?.to_le_bytes());
    for entry in entries {
        data.extend_from_slice(&u32::try_from(entry.path.len()).ok()?.to_le_bytes());
        data.extend_from_slice(&entry.path);
        data.extend_from_slice(&entry.mode.to_le_bytes());
        data.extend_from_slice(&entry.inode.to_le_bytes());
        data.extend_from_slice(&entry.links.to_le_bytes());
        data.extend_from_slice(&entry.mtime_ns.to_le_bytes());
        data.extend_from_slice(&u32::try_from(entry.content.len()).ok()?.to_le_bytes());
        data.extend_from_slice(&entry.content);
        if data.len() > 64 * 1024 * 1024 {
            return None;
        }
    }
    Some(data)
}
impl PrivateFs {
    pub(crate) fn new(config: Config, host: Arc<dyn Host>) -> Result<Arc<Self>, Error> {
        let session = Session::new(config, host)?;
        Ok(Arc::new(Self {
            filesystem: session.initial_file_system()?,
            state: Mutex::new(State::Idle),
        }))
    }
    pub(crate) fn acquire(self: &Arc<Self>) -> Result<Lease, Errno> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if *state != State::Idle {
            return Err(Errno::EAGAIN);
        }
        *state = State::Active;
        Ok(Lease {
            owner: self.clone(),
        })
    }
    pub(crate) fn snapshot(&self) -> Result<Vec<Entry>, Errno> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if *state != State::Idle {
            return Err(Errno::EAGAIN);
        }
        let mut entries = Vec::new();
        self.walk(b"/", &mut entries)?;
        Ok(entries)
    }
    pub(crate) fn close(&self) -> Result<(), Errno> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if *state != State::Idle {
            return Err(Errno::EAGAIN);
        }
        *state = State::Closed;
        Ok(())
    }
    fn walk(&self, path: &[u8], entries: &mut Vec<Entry>) -> Result<(), Errno> {
        let stat = self.filesystem.metadata(path, false)?;
        let kind = stat.mode & 0o170000;
        let content = match kind {
            0o100000 => self.filesystem.read_file(path)?.to_vec(),
            0o120000 => self.filesystem.readlink(path)?,
            0o040000 => Vec::new(),
            _ => return Err(Errno::EIO),
        };
        entries.push(Entry {
            path: path.to_vec(),
            mode: stat.mode,
            inode: stat.inode,
            links: stat.links,
            mtime_ns: stat.mtime_ns,
            content,
        });
        if kind == 0o040000 {
            for child in self.filesystem.read_dir(path)? {
                if child.name == b"." || child.name == b".." {
                    continue;
                }
                let mut next = if path == b"/" {
                    Vec::new()
                } else {
                    path.to_vec()
                };
                next.push(b'/');
                next.extend_from_slice(&child.name);
                self.walk(&next, entries)?;
            }
        }
        Ok(())
    }
    pub(crate) fn remove(&self, path: &[u8], recursive: bool) -> Result<(), Errno> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if *state != State::Idle {
            return Err(Errno::EAGAIN);
        }
        let path = normalize_path(path)?;
        if path == b"/" {
            return Err(Errno::EINVAL);
        }
        self.remove_inner(&path, recursive)
    }
    fn remove_inner(&self, path: &[u8], recursive: bool) -> Result<(), Errno> {
        let directory = self.filesystem.metadata(path, false)?.mode & 0o170000 == 0o040000;
        if directory && recursive {
            for child in self.filesystem.read_dir(path)? {
                if child.name == b"." || child.name == b".." {
                    continue;
                }
                let mut next = path.to_vec();
                next.push(b'/');
                next.extend_from_slice(&child.name);
                self.remove_inner(&next, true)?;
            }
        }
        self.filesystem.unlink(path, directory)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mtime_snapshot_signed_bytes_and_positive_range() {
        for ns in [
            -1_000_000_000,
            -500_000_000,
            -1,
            0,
            1,
            1_500_000_000,
            i128::from(u64::MAX),
        ] {
            let entry = Entry {
                path: b"/".to_vec(),
                mode: 0o100644,
                inode: 1,
                links: 1,
                mtime_ns: ns,
                content: vec![],
            };
            let bytes = snapshot_bytes(&[entry]).unwrap();
            assert_eq!(&bytes[..12], &[255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0]);
            assert_eq!(&bytes[37..53], &ns.to_le_bytes());
            assert_eq!(bytes.len(), 57);
        }
    }
    use paludarium_host::testing::RecordingHost;
    fn fixture() -> Arc<PrivateFs> {
        PrivateFs::new(
            Config::new(b"/guest".to_vec(), vec![])
                .with_file_mode(b"/guest".to_vec(), b"bytes".to_vec(), 0o644)
                .with_file(b"/nested/file".to_vec(), b"second".to_vec()),
            Arc::new(RecordingHost::default()),
        )
        .unwrap()
    }
    #[test]
    fn filesystem_close_idle() {
        assert_eq!(fixture().close(), Ok(()));
    }
    #[test]
    fn filesystem_close_active_rejected() {
        let fs = fixture();
        let _lease = fs.acquire().unwrap();
        assert_eq!(fs.close(), Err(Errno::EAGAIN));
    }
    #[test]
    fn filesystem_close_after_release() {
        let fs = fixture();
        let lease = fs.acquire().unwrap();
        assert_eq!(fs.close(), Err(Errno::EAGAIN));
        drop(lease);
        assert_eq!(fs.close(), Ok(()));
    }
    #[test]
    fn filesystem_closed_acquire_rejected() {
        let fs = fixture();
        fs.close().unwrap();
        assert!(matches!(fs.acquire(), Err(Errno::EAGAIN)));
    }
    #[test]
    fn filesystem_closed_snapshot_rejected() {
        let fs = fixture();
        fs.close().unwrap();
        assert_eq!(fs.snapshot(), Err(Errno::EAGAIN));
    }
    #[test]
    fn filesystem_closed_remove_rejected() {
        let fs = fixture();
        fs.close().unwrap();
        assert_eq!(fs.remove(b"/guest", false), Err(Errno::EAGAIN));
    }
    #[test]
    fn filesystem_closed_close_rejected() {
        let fs = fixture();
        fs.close().unwrap();
        assert_eq!(fs.close(), Err(Errno::EAGAIN));
    }
    /// A snapshot as the JavaScript side passes it back: the first path of
    /// each inode carries the node, the others are hard links to it.
    fn entries_of(snapshot: &[Entry]) -> Vec<paludarium_vfs::GuestEntry> {
        use paludarium_vfs::{EntryKind, GuestEntry};
        let mut first = std::collections::BTreeMap::new();
        snapshot
            .iter()
            .map(|entry| {
                let kind = if let Some(path) = first.get(&entry.inode) {
                    EntryKind::HardLink(Vec::clone(path))
                } else {
                    first.insert(entry.inode, entry.path.clone());
                    match entry.mode & 0o170000 {
                        0o040000 => EntryKind::Directory,
                        0o120000 => EntryKind::Symlink(entry.content.clone()),
                        _ => EntryKind::File(entry.content.clone()),
                    }
                };
                GuestEntry {
                    path: entry.path.clone(),
                    kind,
                    mode: entry.mode & 0o7777,
                    mtime_ns: entry.mtime_ns,
                }
            })
            .collect()
    }
    /// Path, mode, content, time, link count and the first path of the inode.
    type Comparable = (Vec<u8>, u32, Vec<u8>, i128, u64, Vec<u8>);
    /// Paths, kinds, modes, contents, times and link counts, with each inode
    /// replaced by the first path that has it.
    fn comparable(snapshot: &[Entry]) -> Vec<Comparable> {
        let mut first = std::collections::BTreeMap::new();
        snapshot
            .iter()
            .map(|entry| {
                let group = first
                    .entry(entry.inode)
                    .or_insert_with(|| entry.path.clone());
                (
                    entry.path.clone(),
                    entry.mode,
                    entry.content.clone(),
                    entry.mtime_ns,
                    entry.links,
                    group.clone(),
                )
            })
            .collect()
    }
    #[test]
    fn filesystem_snapshot_entries_round_trip() {
        let fs = fixture();
        let lease = fs.acquire().unwrap();
        let guest = lease.filesystem();
        guest.mkdir(b"/empty", 0o700).unwrap();
        guest.symlink(b"../guest", b"/nested/up").unwrap();
        guest.link(b"/nested/up", b"/up2").unwrap();
        guest.link(b"/guest", b"/nested/again").unwrap();
        guest.link(b"/guest", b"/third").unwrap();
        guest
            .set_times(b"/nested", false, None, Some(-1_500_000_000))
            .unwrap();
        guest.set_times(b"/guest", false, None, Some(42)).unwrap();
        guest.set_mode(b"/tmp", 0o700).unwrap();
        drop(lease);
        let before = fs.snapshot().unwrap();
        let mut config = Config::new(b"/guest".to_vec(), vec![]);
        config.entries = entries_of(&before);
        let rebuilt = PrivateFs::new(config, Arc::new(RecordingHost::default())).unwrap();
        let after = rebuilt.snapshot().unwrap();
        assert_eq!(comparable(&before), comparable(&after));
        assert!(before.iter().any(|entry| entry.links == 3));
        assert!(
            before
                .iter()
                .any(|entry| entry.mode == 0o120777 && entry.links == 2)
        );
    }
    #[test]
    fn filesystem_modes_and_contents() {
        let fs = fixture();
        let entries = fs.snapshot().unwrap();
        let guest = entries
            .iter()
            .find(|entry| entry.path == b"/guest")
            .unwrap();
        assert_eq!(guest.mode, 0o100644);
        assert_eq!(guest.content, b"bytes");
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.path == b"/nested/file")
                .unwrap()
                .mode,
            0o100755
        );
    }
    #[test]
    fn filesystem_active_mutation_rejected() {
        let fs = fixture();
        let _lease = fs.acquire().unwrap();
        assert_eq!(fs.remove(b"/guest", false), Err(Errno::EAGAIN));
        assert_eq!(fs.snapshot(), Err(Errno::EAGAIN));
    }
    #[test]
    fn filesystem_second_borrow_rejected_and_drop_releases() {
        let fs = fixture();
        let lease = fs.acquire().unwrap();
        assert!(matches!(fs.acquire(), Err(Errno::EAGAIN)));
        drop(lease);
        assert!(fs.acquire().is_ok());
    }
    #[test]
    fn filesystem_recursive_removal_preserves_other_files() {
        let fs = fixture();
        fs.remove(b"/nested", true).unwrap();
        let entries = fs.snapshot().unwrap();
        assert!(
            !entries
                .iter()
                .any(|entry| entry.path.starts_with(b"/nested"))
        );
        assert!(entries.iter().any(|entry| entry.path == b"/guest"));
    }
    #[test]
    fn filesystem_root_and_missing_removal_rejected() {
        let fs = fixture();
        assert_eq!(fs.remove(b"/", true), Err(Errno::EINVAL));
        assert_eq!(fs.remove(b"/missing", true), Err(Errno::ENOENT));
    }
    #[test]
    fn filesystem_nonrecursive_directory_failure() {
        assert_eq!(fixture().remove(b"/nested", false), Err(Errno(39)));
    }
    #[test]
    fn filesystem_instances_are_isolated_and_lease_retains_state() {
        let first = fixture();
        let second = fixture();
        let lease = first.acquire().unwrap();
        lease.filesystem().unlink(b"/guest", false).unwrap();
        drop(lease);
        assert!(
            !first
                .snapshot()
                .unwrap()
                .iter()
                .any(|entry| entry.path == b"/guest")
        );
        assert!(
            second
                .snapshot()
                .unwrap()
                .iter()
                .any(|entry| entry.path == b"/guest")
        );
    }
}
