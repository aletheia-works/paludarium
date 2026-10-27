//! The page caches of mapped files. Linux keeps one page cache per file,
//! which its mappings show (a `MAP_PRIVATE` one until it writes a page) and
//! its `read` and `write` go through, so the two always agree. Here a mapped
//! file gets a [`FileCache`] that every mapping of it shows (in every process),
//! and the file's handles ([`CoherentFile`], given out by [`CoherentFs`])
//! keep the file and the cache in step: a read, a `stat` or a sync first
//! writes the pages a guest store changed back to the file, and a write, a
//! truncation or a punched hole changes the cache too. The pages are also
//! written back by `msync` and when the last mapping of the file goes away
//! (unmapped, or with the address space of a process that exits or execs).
use paludarium_host::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs};
use paludarium_mmu::{MemoryMeter, SharedPages};
use paludarium_types::{Errno, PAGE_SIZE};
use paludarium_vfs::{FileSystem, MountPoint};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

/// A file, as `stat` names it: its device (the mount's number, or a
/// memfd's) and its inode.
pub(crate) type Key = (u64, u64);

const REGULAR: u32 = 0o100000;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;

/// The page caches of one machine, by file.
#[derive(Default)]
pub(crate) struct PageCaches {
    /// How many caches exist: none, the common case, costs the file
    /// handles one load.
    live: AtomicUsize,
    files: Mutex<HashMap<Key, Weak<FileCache>>>,
}

impl PageCaches {
    /// The cache of `key`, made now, with the file's `size`, if the file has
    /// none.
    pub(crate) fn cache(
        self: &Arc<Self>,
        key: Key,
        meter: Option<Arc<MemoryMeter>>,
        size: u64,
    ) -> Arc<FileCache> {
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cache) = files.get(&key).and_then(Weak::upgrade) {
            return cache;
        }
        files.retain(|_, cache| cache.strong_count() > 0);
        self.live.fetch_add(1, Ordering::SeqCst);
        let cache = Arc::new(FileCache {
            pages: SharedPages::new(),
            writer: Mutex::new(None),
            size: AtomicU64::new(size),
            shrinks: Mutex::default(),
            shrink_count: AtomicU64::new(0),
            writable: AtomicUsize::new(0),
            clean: AtomicU64::new(0),
            meter,
            caches: Arc::clone(self),
        });
        files.insert(key, Arc::downgrade(&cache));
        cache
    }
    /// The cache of `key`, if the file has one.
    pub(crate) fn find(&self, key: Key) -> Option<Arc<FileCache>> {
        if self.live.load(Ordering::SeqCst) == 0 {
            return None;
        }
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .and_then(Weak::upgrade)
    }
    fn any(&self) -> bool {
        self.live.load(Ordering::SeqCst) != 0
    }
    /// Writes every cache back (`msync`): all of them, even after one fails,
    /// and gives the first error.
    pub(crate) fn write_back_all(&self) -> Result<(), Errno> {
        if !self.any() {
            return Ok(());
        }
        let caches: Vec<_> = self
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut first = Ok(());
        for cache in &caches {
            if let Err(error) = cache.write_back() {
                first = first.and(Err(error));
            }
        }
        first
    }
}

/// The page cache of one file: its pages, keyed by file offset, and the
/// handle they are written back through.
pub(crate) struct FileCache {
    pages: SharedPages,
    /// A handle open for writing, from the first mapping that may write.
    writer: Mutex<Option<Arc<dyn FileHandle>>>,
    /// The file's size, kept by its handles: a mapping cannot reach a page
    /// wholly past it (SIGBUS).
    size: AtomicU64,
    /// The sizes the file shrank to, each after how many shrinks, kept
    /// only while no later one is as small: the first one after a count is
    /// the smallest since ([`paludarium_mmu::PageSource::shrunk_since`]).
    shrinks: Mutex<Vec<(u64, u64)>>,
    shrink_count: AtomicU64,
    /// The mappings that may write, which `F_SEAL_WRITE` refuses to seal.
    writable: AtomicUsize,
    /// The pages' generation when they were last written back: a store
    /// bumps it again after it marks its page dirty, so a store that a
    /// write-back missed always leaves it behind.
    clean: AtomicU64,
    meter: Option<Arc<MemoryMeter>>,
    caches: Arc<PageCaches>,
}

impl Drop for FileCache {
    fn drop(&mut self) {
        // The last mapping went away: its stores reach the file now. The
        // table stays locked meanwhile, so that a new mapping or a read of
        // the file, which finds no cache, waits for them. Nothing drops a
        // cache with the table locked.
        let files = self
            .caches
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _ = self.write_back();
        self.caches.live.fetch_sub(1, Ordering::SeqCst);
        drop(files);
    }
}

/// One mapping's hold on a cache, counting it among the writable ones.
struct Mapped {
    cache: Arc<FileCache>,
    writable: bool,
}

impl Drop for Mapped {
    fn drop(&mut self) {
        if self.writable {
            self.cache.writable.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl FileCache {
    /// The pages for a new mapping of `[offset, offset+len)` of `file`, with
    /// the pages of the file's first `size` bytes filled from it where the
    /// cache has none. A mapping that `may_write` keeps `file` to write the
    /// pages back through, unless the cache has a handle already.
    pub(crate) fn map(
        self: &Arc<Self>,
        file: &Arc<dyn FileHandle>,
        offset: u64,
        len: u64,
        may_write: bool,
    ) -> Result<SharedPages, Errno> {
        let size = file.stat()?.size;
        let end = offset.saturating_add(len);
        let mut page = vec![0; PAGE_SIZE as usize];
        let mut key = offset;
        while key < end.min(size) {
            if !self.pages.contains(key) {
                let n = file.read_at(key, &mut page)?;
                self.pages.fill(key, &page[..n], self.meter.as_ref())?;
            }
            key += PAGE_SIZE;
        }
        if may_write {
            let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            writer.get_or_insert_with(|| Arc::clone(file));
            self.writable.fetch_add(1, Ordering::SeqCst);
        }
        let mapped = self.pages.with_owner(Arc::new(Mapped {
            cache: Arc::clone(self),
            writable: may_write,
        }));
        Ok(mapped.with_source(FilePages::new(file, self)))
    }
    /// The pages for a new private mapping of `file`, which reads them from
    /// the file on first touch.
    pub(crate) fn map_private(self: &Arc<Self>, file: &Arc<dyn FileHandle>) -> SharedPages {
        self.pages
            .with_owner(Arc::new(Mapped {
                cache: Arc::clone(self),
                writable: false,
            }))
            .with_source(FilePages::new(file, self))
    }
    /// Whether a mapping that may write shows the cache.
    pub(crate) fn mapped_writable(&self) -> bool {
        self.writable.load(Ordering::SeqCst) != 0
    }
    /// Writes the pages changed since the last time back to the file, and
    /// says whether there were any.
    pub(crate) fn write_back(&self) -> Result<bool, Errno> {
        let generation = self.pages.generation();
        if self.clean.load(Ordering::SeqCst) == generation {
            return Ok(false);
        }
        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut wrote = false;
        if let Some(writer) = writer.as_ref() {
            self.pages.write_back(|key, page| {
                wrote = true;
                writer.write_back(key, page)
            })?;
        }
        self.clean.store(generation, Ordering::SeqCst);
        Ok(wrote)
    }
    /// The file got `data` at `offset`.
    fn wrote(&self, offset: u64, data: &[u8]) {
        self.size
            .fetch_max(offset.saturating_add(data.len() as u64), Ordering::SeqCst);
        self.pages.store(offset, data);
    }
    /// The file went from `old` bytes to `size`: what lay past the end reads
    /// as zeros if it grows again.
    fn resized(&self, old: u64, size: u64) {
        if size < old {
            let mut shrinks = self.shrinks.lock().unwrap_or_else(PoisonError::into_inner);
            let count = self.shrink_count.fetch_add(1, Ordering::SeqCst) + 1;
            while shrinks
                .last()
                .is_some_and(|&(_, smallest)| smallest >= size)
            {
                shrinks.pop();
            }
            shrinks.push((count, size));
        }
        self.size.store(size, Ordering::SeqCst);
        self.pages.zero(old.min(size), u64::MAX);
    }
    /// The bytes from `start` to `end` read as zeros now.
    fn zeroed(&self, start: u64, end: u64) {
        self.pages.zero(start, end);
    }
}

/// A mapped file as the MMU reads it ([`paludarium_mmu::PageSource`]), with
/// the size its page cache keeps.
pub(crate) struct FilePages {
    file: Arc<dyn FileHandle>,
    cache: Arc<FileCache>,
}

impl FilePages {
    pub(crate) fn new(file: &Arc<dyn FileHandle>, cache: &Arc<FileCache>) -> Arc<Self> {
        Arc::new(FilePages {
            file: Arc::clone(file),
            cache: Arc::clone(cache),
        })
    }
}

impl paludarium_mmu::PageSource for FilePages {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.file.read_at(offset, buf)
    }
    fn size(&self) -> Option<u64> {
        Some(self.cache.size.load(Ordering::SeqCst))
    }
    fn shrinks(&self) -> u64 {
        self.cache.shrink_count.load(Ordering::SeqCst)
    }
    fn shrunk_since(&self, count: u64) -> Option<u64> {
        let shrinks = self
            .cache
            .shrinks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let first = shrinks.partition_point(|&(after, _)| after <= count);
        shrinks.get(first).map(|&(_, size)| size)
    }
}

/// Where a file handle's device comes from.
enum Device {
    /// The mount holding the path it was opened at.
    Mount(Arc<dyn FileSystem>, Vec<u8>),
    /// A device of its own (a memfd's).
    Fixed(u64),
}

/// The number of the mount holding `path` (the longest matching mount
/// point, counting from 1), which `stat` gives as the device minor.
pub(crate) fn mount_device(mounts: &[MountPoint], path: &[u8]) -> u64 {
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

/// A file handle that keeps its file and the file's page cache in step
/// (see the module). Every other method is passed on unchanged.
pub(crate) struct CoherentFile {
    inner: Arc<dyn FileHandle>,
    caches: Arc<PageCaches>,
    device: Device,
    /// The file's key, found on first use, or none for a file that is not
    /// regular and so cannot be mapped shared.
    key: OnceLock<Option<Key>>,
}

impl CoherentFile {
    /// `inner`, with the device of its own (a memfd's).
    pub(crate) fn with_device(
        inner: Arc<dyn FileHandle>,
        caches: Arc<PageCaches>,
        device: u64,
    ) -> Self {
        CoherentFile {
            inner,
            caches,
            device: Device::Fixed(device),
            key: OnceLock::new(),
        }
    }
    fn cache(&self) -> Option<Arc<FileCache>> {
        if !self.caches.any() {
            return None;
        }
        let key = self.key.get_or_init(|| {
            let stat = self.inner.stat().ok()?;
            let device = match &self.device {
                Device::Mount(fs, path) => mount_device(&fs.mounts(), path),
                Device::Fixed(device) => *device,
            };
            (stat.mode & 0o170000 == REGULAR).then_some((device, stat.inode))
        });
        self.caches.find((*key)?)
    }
    /// Writes the cache back before the file is read. A page that cannot be
    /// written stays dirty and the read goes on, as a Linux read does not
    /// write back; a sync reports the error.
    fn write_back(&self) {
        if let Some(cache) = self.cache() {
            let _ = cache.write_back();
        }
    }
}

impl FileHandle for CoherentFile {
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        self.inner.readiness()
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.inner.as_any()
    }
    fn stdio_channel(&self) -> Option<u32> {
        self.inner.stdio_channel()
    }
    fn guest_path_hint(&self) -> Option<Vec<u8>> {
        self.inner.guest_path_hint()
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.write_back();
        self.inner.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let n = self.inner.write(buf)?;
        if let Some(cache) = self.cache() {
            // The write ended at the position, wherever it started.
            let end = self.inner.seek(0, 1)?;
            cache.wrote(end - n as u64, &buf[..n]);
        }
        Ok(n)
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        self.inner.seek(offset, whence)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        self.write_back();
        self.inner.stat()
    }
    fn truncate(&self, size: u64) -> Result<(), Errno> {
        let Some(cache) = self.cache() else {
            return self.inner.truncate(size);
        };
        let old = self.inner.stat()?.size;
        self.inner.truncate(size)?;
        cache.resized(old, size);
        Ok(())
    }
    fn flock(&self, op: u32) -> Result<(), Errno> {
        self.inner.flock(op)
    }
    fn flags(&self) -> u32 {
        self.inner.flags()
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.inner.set_flags(flags)
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.inner.set_mode(mode)
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.inner.set_owner(uid, gid)
    }
    fn set_times(&self, atime: Option<i128>, mtime: Option<i128>) -> Result<(), Errno> {
        self.inner.set_times(atime, mtime)
    }
    fn sync(&self) -> Result<(), Errno> {
        if let Some(cache) = self.cache() {
            cache.write_back()?;
        }
        self.inner.sync()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.write_back();
        self.inner.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        let n = self.inner.write_at(offset, buf)?;
        if let Some(cache) = self.cache() {
            // An O_APPEND file appended instead.
            let at = if self.inner.flags() & O_APPEND != 0 {
                self.inner.stat()?.size - n as u64
            } else {
                offset
            };
            cache.wrote(at, &buf[..n]);
        }
        Ok(n)
    }
    fn zero_range(&self, offset: u64, len: u64) -> Result<(), Errno> {
        self.inner.zero_range(offset, len)?;
        if let Some(cache) = self.cache() {
            cache.zeroed(offset, offset.saturating_add(len));
        }
        Ok(())
    }
    fn allocate(&self, offset: u64, len: u64) -> Result<(), Errno> {
        self.inner.allocate(offset, len)
    }
    fn write_back(&self, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        self.inner.write_back(offset, buf)
    }
}

/// A file system whose files are [`CoherentFile`]s, and whose `stat` of a
/// path sees the stores of the file's shared mappings. Every other method is
/// passed on unchanged.
pub(crate) struct CoherentFs {
    inner: Arc<dyn FileSystem>,
    caches: Arc<PageCaches>,
}

impl CoherentFs {
    pub(crate) fn new(inner: Arc<dyn FileSystem>, caches: Arc<PageCaches>) -> Self {
        CoherentFs { inner, caches }
    }
}

impl FileSystem for CoherentFs {
    fn mounts(&self) -> Vec<MountPoint> {
        self.inner.mounts()
    }
}

impl HostFs for CoherentFs {
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let file = CoherentFile {
            inner: self.inner.open(path, flags, mode)?,
            caches: Arc::clone(&self.caches),
            device: Device::Mount(Arc::clone(&self.inner), path.to_vec()),
            key: OnceLock::new(),
        };
        if flags & O_TRUNC != 0
            && let Some(cache) = file.cache()
        {
            cache.resized(0, 0);
        }
        Ok(Arc::new(file))
    }
    fn metadata(&self, path: &[u8], follow: bool) -> Result<FileStat, Errno> {
        let stat = self.inner.metadata(path, follow)?;
        if !self.caches.any() || stat.mode & 0o170000 != REGULAR {
            return Ok(stat);
        }
        let key = (mount_device(&self.inner.mounts(), path), stat.inode);
        match self.caches.find(key).map(|cache| cache.write_back()) {
            Some(Ok(true)) => self.inner.metadata(path, follow),
            _ => Ok(stat),
        }
    }
    fn mkdir(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        self.inner.mkdir(path, mode)
    }
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno> {
        self.inner.unlink(path, directory)
    }
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        self.inner.link(old, new)
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno> {
        self.inner.symlink(target, path)
    }
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        self.inner.readlink(path)
    }
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        self.inner.rename(old, new)
    }
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        self.inner.read_dir(path)
    }
    fn statfs(&self, path: &[u8]) -> Result<FsStats, Errno> {
        self.inner.statfs(path)
    }
    fn set_mode(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        self.inner.set_mode(path, mode)
    }
    fn set_owner(
        &self,
        path: &[u8],
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Errno> {
        self.inner.set_owner(path, follow, uid, gid)
    }
    fn set_times(
        &self,
        path: &[u8],
        follow: bool,
        atime: Option<i128>,
        mtime: Option<i128>,
    ) -> Result<(), Errno> {
        self.inner.set_times(path, follow, atime, mtime)
    }
}
