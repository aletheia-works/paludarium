//! `/dev`: the character devices null, zero, full, random and urandom, each
//! a kernel object, and the links into `/proc/self/fd` that Linux systems
//! have there (`fd`, `stdin`, `stdout`, `stderr`).
use paludarium_host::{DirectoryEntry, FileHandle, FileStat, Host};
use paludarium_types::Errno;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// The memory devices of major 1, by minor number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Null = 3,
    Zero = 5,
    Full = 7,
    Random = 8,
    Urandom = 9,
}
/// What a path under `/dev` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Directory,
    Device(Kind),
    /// A symbolic link, and its target.
    Link(&'static [u8]),
}
/// The names in `/dev`, sorted as it lists them. Each has the inode number
/// two more than its place here, and `/dev` itself has 1, so that `stat` and
/// `getdents` agree.
const NAMES: [(&[u8], Entry); 9] = [
    (b"fd", Entry::Link(b"/proc/self/fd")),
    (b"full", Entry::Device(Kind::Full)),
    (b"null", Entry::Device(Kind::Null)),
    (b"random", Entry::Device(Kind::Random)),
    (b"stderr", Entry::Link(b"/proc/self/fd/2")),
    (b"stdin", Entry::Link(b"/proc/self/fd/0")),
    (b"stdout", Entry::Link(b"/proc/self/fd/1")),
    (b"urandom", Entry::Device(Kind::Urandom)),
    (b"zero", Entry::Device(Kind::Zero)),
];
const DIRECTORY_INODE: u64 = 1;
fn inode(entry: Entry) -> u64 {
    NAMES
        .iter()
        .position(|&(_, e)| e == entry)
        .map_or(DIRECTORY_INODE, |i| i as u64 + 2)
}
pub(crate) fn entry(path: &[u8]) -> Option<Entry> {
    if path == b"/dev" || path == b"/dev/" {
        return Some(Entry::Directory);
    }
    let name = path.strip_prefix(b"/dev/")?;
    NAMES.iter().find(|(n, _)| *n == name).map(|&(_, e)| e)
}
/// A path through one of the links, with the link replaced by its target
/// (`/dev/fd/3` is `/proc/self/fd/3`); `None` for any other path, and for a
/// link itself.
pub(crate) fn through_link(path: &[u8]) -> Option<Vec<u8>> {
    let name = path.strip_prefix(b"/dev/")?;
    NAMES.iter().find_map(|&(link, entry)| {
        let Entry::Link(target) = entry else {
            return None;
        };
        let rest = name.strip_prefix(link)?;
        (rest.first() == Some(&b'/')).then(|| [target, rest].concat())
    })
}
/// `/dev`'s `stat`: a 0755 directory.
pub(crate) fn directory_stat() -> FileStat {
    FileStat {
        inode: DIRECTORY_INODE,
        mode: 0o040_755,
        links: 2,
        ..FileStat::default()
    }
}
pub(crate) fn stat(entry: Entry) -> FileStat {
    match entry {
        Entry::Directory => directory_stat(),
        // A device: 0666 with its number; a link: 0777, as large as its
        // target.
        Entry::Device(kind) => FileStat {
            inode: inode(entry),
            mode: 0o020_666,
            links: 1,
            rdev: 1 << 8 | kind as u64,
            ..FileStat::default()
        },
        Entry::Link(target) => FileStat {
            inode: inode(entry),
            mode: 0o120_777,
            links: 1,
            size: target.len() as u64,
            ..FileStat::default()
        },
    }
}
/// `/dev`'s entries: `.`, `..` (the root, with inode `root`), then the
/// devices and links by name.
pub(crate) fn entries(root: u64) -> Vec<DirectoryEntry> {
    const DT_CHR: u8 = 2;
    const DT_DIR: u8 = 4;
    const DT_LNK: u8 = 10;
    let named = NAMES.iter().map(|&(name, entry)| {
        let kind = if matches!(entry, Entry::Link(_)) {
            DT_LNK
        } else {
            DT_CHR
        };
        (name, inode(entry), kind)
    });
    [(&b"."[..], DIRECTORY_INODE, DT_DIR), (b"..", root, DT_DIR)]
        .into_iter()
        .chain(named)
        .map(|(name, inode, kind)| DirectoryEntry {
            name: name.to_vec(),
            inode,
            kind,
        })
        .collect()
}

/// An open memory device: null reads nothing, zero and full read zeros,
/// random and urandom read the host's random bytes; full refuses writes with
/// ENOSPC, and the others take them all.
pub(crate) struct Device {
    kind: Kind,
    flags: AtomicU32,
    host: Option<Arc<dyn Host>>,
}
impl Device {
    pub(crate) fn new(kind: Kind, flags: u32, host: Option<Arc<dyn Host>>) -> Self {
        Self {
            kind,
            flags: AtomicU32::new(flags & !0x80000),
            host,
        }
    }
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }
}
impl FileHandle for Device {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, bytes: &mut [u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 1 {
            return Err(Errno::EBADF);
        }
        match self.kind {
            Kind::Null => Ok(0),
            Kind::Zero | Kind::Full => {
                bytes.fill(0);
                Ok(bytes.len())
            }
            Kind::Random | Kind::Urandom => {
                let host = self.host.as_ref().ok_or(Errno::EIO)?;
                host.random_bytes(bytes).map_err(|_| Errno::EIO)?;
                Ok(bytes.len())
            }
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 0 {
            return Err(Errno::EBADF);
        }
        if self.kind == Kind::Full {
            return Err(Errno(28)); // ENOSPC
        }
        Ok(bytes.len())
    }
    fn read_at(&self, _: u64, bytes: &mut [u8]) -> Result<usize, Errno> {
        self.read(bytes)
    }
    fn write_at(&self, _: u64, bytes: &[u8]) -> Result<usize, Errno> {
        self.write(bytes)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(stat(Entry::Device(self.kind)))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(
            (self.flags() & 3) | (flags & !3 & !0x80000),
            Ordering::SeqCst,
        );
        Ok(())
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Ok((crate::events::IN | crate::events::OUT, 1, 1))
    }
}
#[cfg(test)]
mod device_tests {
    use super::*;
    fn null(flags: u32) -> Device {
        Device::new(Kind::Null, flags, None)
    }
    #[test]
    fn read_eof() {
        assert_eq!(null(0).read(&mut [0; 8]), Ok(0));
    }
    #[test]
    fn write_consumes() {
        assert_eq!(null(1).write(b"abc"), Ok(3));
    }
    #[test]
    fn access_mode() {
        assert_eq!(null(1).read(&mut [0]), Err(Errno::EBADF));
        assert_eq!(null(0).write(b"x"), Err(Errno::EBADF));
    }
    #[test]
    fn read_write_mode() {
        let file = null(2);
        assert_eq!(file.read(&mut [0]), Ok(0));
        assert_eq!(file.write(b"x"), Ok(1));
    }
    #[test]
    fn character_stat_and_seek() {
        let file = null(0);
        assert_eq!(file.stat().unwrap().mode & 0o170000, 0o020000);
        assert_eq!(file.seek(100, 0), Ok(0));
        assert_eq!(file.truncate(0), Err(Errno::EINVAL));
    }
    #[test]
    fn flags_preserve_access_mode() {
        let file = null(0x80002);
        assert_eq!(file.flags(), 2);
        file.set_flags(0x800).unwrap();
        assert_eq!(file.flags(), 0x802);
    }
    #[test]
    fn readiness_and_empty_write() {
        let file = null(2);
        assert_eq!(file.readiness().unwrap().0, 5);
        assert_eq!(file.write(b""), Ok(0));
    }
    #[test]
    fn zero_full_and_random() {
        let mut b = [7; 4];
        assert_eq!(Device::new(Kind::Zero, 2, None).read(&mut b), Ok(4));
        assert_eq!(b, [0; 4]);
        let full = Device::new(Kind::Full, 2, None);
        assert_eq!(full.write(b"x"), Err(Errno(28)));
        assert_eq!(full.stat().unwrap().rdev, 0x107);
        let host: Arc<dyn Host> = Arc::new(paludarium_host::testing::RecordingHost::new());
        assert_eq!(
            Device::new(Kind::Urandom, 0, Some(host)).read(&mut b),
            Ok(4)
        );
    }
    #[test]
    fn dev_names_and_links() {
        assert_eq!(entry(b"/dev/zero"), Some(Entry::Device(Kind::Zero)));
        assert_eq!(entry(b"/dev/stdin"), Some(Entry::Link(b"/proc/self/fd/0")));
        assert_eq!(entry(b"/dev/zeros"), None);
        assert_eq!(
            through_link(b"/dev/fd/3"),
            Some(b"/proc/self/fd/3".to_vec())
        );
        assert_eq!(through_link(b"/dev/fd"), None);
        assert_eq!(through_link(b"/dev/fdx/3"), None);
        let listed = entries(7);
        let names: Vec<_> = listed.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names[..4],
            [
                b".".to_vec(),
                b"..".to_vec(),
                b"fd".to_vec(),
                b"full".to_vec()
            ]
        );
        // Each entry's inode is the one its stat reports.
        assert_eq!(listed[1].inode, 7);
        assert_eq!(listed[0].inode, directory_stat().inode);
        for e in &listed[2..] {
            let path = [&b"/dev/"[..], &e.name].concat();
            assert_eq!(stat(entry(&path).unwrap()).inode, e.inode);
        }
    }
}
