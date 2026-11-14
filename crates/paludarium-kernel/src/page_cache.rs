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
use crate::inotify::Notifier;
use paludarium_host::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs};
use paludarium_mmu::{FileSize, MemoryMeter, SharedPages};
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
const O_PATH: u32 = 0o10000000;
const ETXTBSY: Errno = Errno(26);

/// The page caches of one machine, by file.
#[derive(Default)]
pub(crate) struct PageCaches {
    /// How many caches exist: none, the common case, costs the file
    /// handles one load.
    live: AtomicUsize,
    files: Mutex<HashMap<Key, Weak<FileCache>>>,
    /// Linux's `i_writecount` of each file that has one: above zero, how
    /// many descriptions have it open for writing; below, how many programs
    /// run from it (or are being loaded from it).
    writes: Mutex<HashMap<Key, i64>>,
    /// The machine's inotify watches, which its files' changes are told to.
    pub(crate) notify: Arc<crate::inotify::Notifier>,
    /// Whether any of the machine's files was ever made immutable or
    /// append-only ([`crate::files::attributes::any_flagged`]).
    pub(crate) flagged: std::sync::atomic::AtomicBool,
    /// The open descriptions of the machine's files (each a
    /// [`CoherentFile`], by its handle), which keep a removed file there
    /// for inotify until the last is closed, as Linux's dentry keeps it.
    opens: Mutex<HashMap<usize, Open>>,
    /// The files the machine's processes hold other than by a description,
    /// each with how many [`Hold`]s hold it: working directories, as Linux's
    /// `fs->pwd` holds its dentry, and the ELF interpreters programs run
    /// with, as their mappings hold theirs. They keep a removed file there
    /// for inotify too.
    holds: Mutex<HashMap<Key, usize>>,
    /// The places of the open files the kernel keeps itself
    /// ([`crate::inotify::Closing`]: a FIFO opened by its path, the files
    /// exec opens), by their file, which renames move as they move a
    /// description's, and which keep a removed file there too.
    kept: Mutex<Vec<(Key, Weak<Mutex<Place>>)>>,
}

/// A hold on a file a process keeps without a description (a working
/// directory's `fs->pwd`, or the mappings of a program's interpreter):
/// while it lasts, a removed file's end (`IN_DELETE_SELF`) waits, as for
/// an open description.
pub(crate) struct Hold {
    caches: Arc<PageCaches>,
    key: Key,
}

impl Hold {
    /// Another hold on the same file, as `copy_fs_struct` takes one.
    pub(crate) fn copy(&self) -> Hold {
        self.caches.hold_of(self.key)
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        {
            let mut holds = self
                .caches
                .holds
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = holds.get_mut(&self.key) {
                *count -= 1;
                if *count == 0 {
                    holds.remove(&self.key);
                }
            }
        }
        // As a description's last close: the removal looks again after it
        // puts its end off, so one of the two sees the other.
        if self.caches.notify.waiting() && !self.caches.held(self.key) {
            self.caches.notify.last_closed(self.key);
        }
    }
}

/// An open description in [`PageCaches`]' list: its file's handle, where
/// its device comes from, and its file's key once a look found it, which
/// its close uses even if the file cannot be looked at then.
type Open = (Weak<dyn FileHandle>, Device, OnceLock<Key>);

/// Where an open description's file is, as Linux's dentry keeps it, which
/// inotify reports its events at: the path it was opened at, its symbolic
/// links resolved once a rename or a removal first looks at it, moved by
/// each rename of the file or of a directory above it, and unlinked once an
/// `unlink`, an `rmdir` or a rename onto it took that name away.
#[derive(Default)]
pub(crate) struct Place {
    path: Vec<u8>,
    resolved: bool,
    unlinked: bool,
}
impl Place {
    /// Where the file is now, and whether that name was taken away.
    pub(crate) fn at(place: &Mutex<Self>) -> (Vec<u8>, bool) {
        let place = place.lock().unwrap_or_else(PoisonError::into_inner);
        (place.path.clone(), place.unlinked)
    }
}

/// The places a rename looked at, and its two entries.
struct Moving {
    places: Vec<Arc<Mutex<Place>>>,
    old: Vec<u8>,
    new: Vec<u8>,
}

/// `path` with `prefix` taken off its front, where `prefix` is `path` or one
/// of the directories above it.
fn below<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest.first() == Some(&b'/')).then_some(rest)
}

/// `path` with the directories above its last name resolved, as the entry a
/// rename or a removal changes: none for the root or a missing directory.
fn entry_path(fs: &dyn HostFs, path: &[u8]) -> Option<Vec<u8>> {
    let trimmed = path.trim_suffix(b"/");
    let at = trimmed.iter().rposition(|&b| b == b'/')?;
    let name = &trimmed[at + 1..];
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    let mut entry = crate::files::resolved_in(fs, if at == 0 { b"/" } else { &trimmed[..at] })?;
    if entry != b"/" {
        entry.push(b'/');
    }
    entry.extend_from_slice(name);
    Some(entry)
}

/// One count of [`PageCaches`]' `writes`, given back when dropped: write
/// access a description holds (Linux's `get_write_access`), or the denial
/// of it a running program holds (`deny_write_access`).
pub(crate) struct WriteAccess {
    caches: Arc<PageCaches>,
    key: Key,
    change: i64,
    /// For a running program's denial, exec's open of its file, which
    /// closes with it (`exe_file`'s last `fput`).
    closing: Option<crate::inotify::Closing>,
}

impl WriteAccess {
    /// This denial, closing exec's open `closing` of the program when it
    /// ends.
    pub(crate) fn closing(mut self, closing: Option<crate::inotify::Closing>) -> Self {
        self.closing = closing;
        self
    }
}

impl Drop for WriteAccess {
    fn drop(&mut self) {
        let mut writes = self
            .caches
            .writes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = writes.get_mut(&self.key) {
            *count -= self.change;
            if *count == 0 {
                writes.remove(&self.key);
            }
        }
        drop(writes);
        // `__fput` reports the close before it lets go of the dentry.
        drop(self.closing.take());
        // A program a process ran holds its file (Linux's `exe_file`): a
        // removed one ends once no process runs it, as with a last close.
        if self.change < 0 && self.caches.notify.waiting() && !self.caches.held(self.key) {
            self.caches.notify.last_closed(self.key);
        }
    }
}

impl PageCaches {
    /// The place of an open of file `key` the kernel keeps itself, at
    /// `path`, which renames and removals move from now on, and which holds
    /// the file while it lasts.
    pub(crate) fn keep_place(&self, key: Key, path: &[u8]) -> Arc<Mutex<Place>> {
        let place = Arc::new(Mutex::new(Place {
            path: path.to_vec(),
            resolved: false,
            unlinked: false,
        }));
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((key, Arc::downgrade(&place)));
        place
    }
    /// Whether a description of file `key` is open, a [`Hold`] holds it,
    /// a program runs from it, or the kernel keeps an open of it.
    pub(crate) fn held(&self, key: Key) -> bool {
        let kept = self
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(known, place)| *known == key && place.strong_count() != 0);
        kept || self.held_otherwise(key)
    }
    fn held_otherwise(&self, key: Key) -> bool {
        let opened = {
            let opens = self.opens.lock().unwrap_or_else(PoisonError::into_inner);
            opens.values().any(|(file, device, found)| {
                if let Some(&known) = found.get() {
                    return known == key;
                }
                let Some(stat) = file.upgrade().and_then(|file| file.stat().ok()) else {
                    return false;
                };
                *found.get_or_init(|| (device.number(), stat.inode)) == key
            })
        };
        opened
            || self
                .holds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&key)
            || self
                .writes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&key)
                .is_some_and(|&count| count < 0)
    }
    /// The places of the open descriptions of the machine's files in `fs`,
    /// each once (a reopen shares its description's), and each resolved the
    /// first time a change of names looks at it, before the change.
    fn places(&self, fs: &Arc<dyn FileSystem>) -> Vec<Arc<Mutex<Place>>> {
        let mut places: Vec<_> = {
            let opens = self.opens.lock().unwrap_or_else(PoisonError::into_inner);
            opens
                .values()
                .filter_map(|(_, device, _)| match device {
                    Device::Mount(mount, _, place) if Arc::ptr_eq(mount, fs) => {
                        Some(Arc::clone(place))
                    }
                    _ => None,
                })
                .collect()
        };
        // The kernel's own opens are of the machine's one file system.
        {
            let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            kept.retain(|(_, place)| place.strong_count() != 0);
            places.extend(kept.iter().filter_map(|(_, place)| place.upgrade()));
        }
        // `renamed` moves a place it sees twice twice.
        places.sort_by_key(|place| Arc::as_ptr(place).addr());
        places.dedup_by(|a, b| Arc::ptr_eq(a, b));
        for place in &places {
            let mut place = place.lock().unwrap_or_else(PoisonError::into_inner);
            if !place.resolved {
                place.resolved = true;
                if let Some(path) = crate::files::resolved_in(&**fs, &place.path) {
                    place.path = path;
                }
            }
        }
        places
    }
    /// What a rename from `old` to `new` in `fs` will move, unless it names
    /// one file twice and so does nothing.
    fn before_rename(&self, fs: &Arc<dyn FileSystem>, old: &[u8], new: &[u8]) -> Option<Moving> {
        let mut places = self.places(fs);
        if places.is_empty() {
            return None;
        }
        let (old_entry, new_entry) = (entry_path(&**fs, old)?, entry_path(&**fs, new)?);
        // Only the descriptions at either name or below them can move, and
        // most renames have none: those look at no more files.
        places.retain(|place| {
            let place = place.lock().unwrap_or_else(PoisonError::into_inner);
            below(&place.path, &old_entry).is_some() || below(&place.path, &new_entry).is_some()
        });
        if places.is_empty() {
            return None;
        }
        if let (Ok(from), Ok(to)) = (fs.metadata(old, false), fs.metadata(new, false))
            && from.inode == to.inode
            && mount_device(&fs.mounts(), old) == mount_device(&fs.mounts(), new)
        {
            return None;
        }
        Some(Moving {
            old: old_entry,
            new: new_entry,
            places,
        })
    }
    /// `d_move` (`d_exchange` with `RENAME_EXCHANGE`) of the descriptions
    /// at `old` and below it to `new`; one at `new` that the rename
    /// replaced is unlinked, keeping its name.
    fn renamed(Moving { places, old, new }: &Moving, exchange: bool) {
        for place in places {
            let mut place = place.lock().unwrap_or_else(PoisonError::into_inner);
            // An unlinked dentry is no entry of its own any more, though one
            // of a directory above it may move.
            let moves = |rest: &[u8], unlinked: bool| !(unlinked && rest.is_empty());
            if let Some(rest) = below(&place.path, old)
                && moves(rest, place.unlinked)
            {
                place.path = [&new[..], rest].concat();
            } else if let Some(rest) = below(&place.path, new) {
                if exchange {
                    if moves(rest, place.unlinked) {
                        place.path = [&old[..], rest].concat();
                    }
                } else if rest.is_empty() {
                    place.unlinked = true;
                }
            }
        }
    }
    /// A hold on the file at `path` in `fs`, by the key inotify knows it
    /// by; none if it cannot be looked at.
    pub(crate) fn hold(self: &Arc<Self>, fs: &dyn FileSystem, path: &[u8]) -> Option<Hold> {
        let path = crate::files::resolved_in(fs, path)?;
        let stat = fs.metadata(&path, false).ok()?;
        Some(self.hold_of((mount_device(&fs.mounts(), &path), stat.inode)))
    }
    fn hold_of(self: &Arc<Self>, key: Key) -> Hold {
        *self
            .holds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_default() += 1;
        Hold {
            caches: Arc::clone(self),
            key,
        }
    }
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
            key,
            pages: SharedPages::new(),
            writer: Mutex::new(None),
            size: Arc::new(FileSize::new(size)),
            shrinks: Mutex::default(),
            writable: AtomicUsize::new(0),
            clean: AtomicU64::new(0),
            meter,
            caches: Arc::clone(self),
        });
        files.insert(key, Arc::downgrade(&cache));
        cache
    }
    /// Write access to `key`, which a program running from it refuses
    /// (ETXTBSY), as Linux's `get_write_access`.
    pub(crate) fn write_access(self: &Arc<Self>, key: Key) -> Result<WriteAccess, Errno> {
        self.count(key, 1)
    }
    /// Write access to `key` denied while the guard lives, which a
    /// description open for writing refuses (ETXTBSY), as Linux's
    /// `deny_write_access` of a program it executes.
    pub(crate) fn deny_write_access(self: &Arc<Self>, key: Key) -> Result<WriteAccess, Errno> {
        self.count(key, -1)
    }
    fn count(self: &Arc<Self>, key: Key, change: i64) -> Result<WriteAccess, Errno> {
        let mut writes = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let count = writes.entry(key).or_insert(0);
        if *count * change < 0 {
            return Err(ETXTBSY);
        }
        *count += change;
        Ok(WriteAccess {
            caches: Arc::clone(self),
            key,
            change,
            closing: None,
        })
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
    /// The device and inode of the file.
    key: Key,
    pages: SharedPages,
    /// A handle open for writing, from the first mapping that may write.
    writer: Mutex<Option<Arc<dyn FileHandle>>>,
    /// The file's size, kept by its handles: a mapping cannot reach a page
    /// wholly past it (SIGBUS). With how many times it has shrunk, which the
    /// threads' TLBs hold ([`paludarium_mmu::PageSource::file_size`]).
    size: Arc<FileSize>,
    /// The sizes the file shrank to, each after how many shrinks, kept
    /// only while no later one is as small: the first one after a count is
    /// the smallest since ([`paludarium_mmu::PageSource::shrunk_since`]).
    shrinks: Mutex<Vec<(u64, u64)>>,
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
    /// pages back through, unless the cache has a handle already. `name` is
    /// the file's path ([`FilePages`]).
    pub(crate) fn map(
        self: &Arc<Self>,
        file: &Arc<dyn FileHandle>,
        name: Option<Vec<u8>>,
        offset: u64,
        len: u64,
        may_write: bool,
        charge: Option<Arc<crate::memfd::SecretCharge>>,
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
        // Only a `memfd_secret` file's pages charge anything.
        let secret = charge.is_some();
        Ok(mapped.with_source(FilePages::new(file, name, self, secret, charge)))
    }
    /// The pages for a new private mapping of `file`, named `name`, which
    /// reads them from the file on first touch.
    pub(crate) fn map_private(
        self: &Arc<Self>,
        file: &Arc<dyn FileHandle>,
        name: Option<Vec<u8>>,
    ) -> SharedPages {
        self.pages
            .with_owner(Arc::new(Mapped {
                cache: Arc::clone(self),
                writable: false,
            }))
            .with_source(FilePages::new(file, name, self, false, None))
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
        self.size.grow_to(offset.saturating_add(data.len() as u64));
        self.pages.store(offset, data);
    }
    /// The file went from `old` bytes to `size`: what lay past the end reads
    /// as zeros if it grows again.
    fn resized(&self, old: u64, size: u64) {
        // Under the lock of the list, so that a count and its size go in
        // together, in order.
        let mut shrinks = self.shrinks.lock().unwrap_or_else(PoisonError::into_inner);
        if self.size.set(size) {
            // The size and the zeros before the count: whoever reads the new
            // count then reads the new size, and copies no bytes from before
            // the shrink (`paludarium_mmu::PageSource::shrinks`).
            self.pages.zero(size, u64::MAX);
            let count = self.size.count_shrink();
            while shrinks
                .last()
                .is_some_and(|&(_, smallest)| smallest >= size)
            {
                shrinks.pop();
            }
            shrinks.push((count, size));
        } else {
            self.pages.zero(old, u64::MAX);
        }
    }
    /// The bytes from `start` to `end` read as zeros now.
    fn zeroed(&self, start: u64, end: u64) {
        self.pages.zero(start, end);
    }
}

/// A mapped file as the MMU reads it ([`paludarium_mmu::PageSource`]), with
/// the size its page cache keeps and the path it was mapped by.
pub(crate) struct FilePages {
    file: Arc<dyn FileHandle>,
    cache: Arc<FileCache>,
    name: Option<Vec<u8>>,
    /// The file is a `memfd_secret` file, whose own handle `file` is not.
    secret: bool,
    /// What the pages of a `memfd_secret` file charge as faults bring
    /// them in.
    charge: Option<Arc<crate::memfd::SecretCharge>>,
}

impl FilePages {
    pub(crate) fn new(
        file: &Arc<dyn FileHandle>,
        name: Option<Vec<u8>>,
        cache: &Arc<FileCache>,
        secret: bool,
        charge: Option<Arc<crate::memfd::SecretCharge>>,
    ) -> Arc<Self> {
        Arc::new(FilePages {
            file: Arc::clone(file),
            cache: Arc::clone(cache),
            name,
            secret,
            charge,
        })
    }
    /// The open file the mapping was made of.
    pub(crate) fn file(&self) -> &Arc<dyn FileHandle> {
        &self.file
    }
}

impl paludarium_mmu::PageSource for FilePages {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.file.read_at(offset, buf)
    }
    fn size(&self) -> Option<u64> {
        Some(self.cache.size.get())
    }
    fn shrinks(&self) -> u64 {
        self.cache.size.shrinks()
    }
    fn file_size(&self) -> Option<Arc<FileSize>> {
        Some(Arc::clone(&self.cache.size))
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
    fn linked(&self) -> bool {
        self.file.stat().map_or(true, |stat| stat.links > 0)
    }
    /// Its path, marked ` (deleted)` once no name links it, as Linux's
    /// `d_path` marks it.
    fn name(&self) -> Option<Vec<u8>> {
        let mut name = self.name.clone()?;
        if !self.linked() {
            name.extend_from_slice(b" (deleted)");
        }
        Some(name)
    }
    fn identity(&self) -> (u64, u64) {
        self.cache.key
    }
    fn open_file(&self) -> usize {
        Arc::as_ptr(&self.file).cast::<()>() as usize
    }
    fn admit(&self, offset: u64) -> bool {
        self.charge
            .as_ref()
            .is_none_or(|charge| charge.admit(offset))
    }
    fn secret(&self) -> bool {
        self.secret
    }
    /// `secretmem_mmap_prepare` adds `VM_DONTDUMP`; secretmem's pseudo file
    /// system runs nothing.
    fn vma_flags(&self, flags: u64) -> u64 {
        use paludarium_mmu::vm;
        if self.secret {
            (flags | vm::DONTDUMP) & !vm::MAYEXEC
        } else {
            flags
        }
    }
    fn as_any(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        Some(self)
    }
}

/// Where a file handle's device comes from.
enum Device {
    /// The mount holding the path it was opened at, and where the file is.
    Mount(Arc<dyn FileSystem>, Vec<u8>, Arc<Mutex<Place>>),
    /// A device of its own (a memfd's).
    Fixed(u64),
}
impl Device {
    fn number(&self) -> u64 {
        match self {
            Device::Mount(fs, path, _) => mount_device(&fs.mounts(), path),
            Device::Fixed(device) => *device,
        }
    }
    /// The same device, for another description of the same dentry (a
    /// reopen), which shares its place.
    fn copy(&self) -> Device {
        match self {
            Device::Mount(fs, path, place) => {
                Device::Mount(Arc::clone(fs), path.clone(), Arc::clone(place))
            }
            Device::Fixed(device) => Device::Fixed(*device),
        }
    }
}

pub(crate) use paludarium_vfs::mount_device;

/// A file handle that keeps its file and the file's page cache in step
/// (see the module). Every other method is passed on unchanged.
pub(crate) struct CoherentFile {
    inner: Arc<dyn FileHandle>,
    caches: Arc<PageCaches>,
    device: Device,
    /// The file's key, found on first use, or none for a file that is not
    /// regular and so cannot be mapped shared.
    key: OnceLock<Option<Key>>,
    /// The write access a description open for writing holds, which a
    /// program run from the file refuses while it lasts.
    write: Option<WriteAccess>,
    /// For a description the guest opened, whether for writing: its last
    /// close is `IN_CLOSE_WRITE` or `IN_CLOSE_NOWRITE` (`fsnotify_close`).
    opened: Option<bool>,
}

impl Drop for CoherentFile {
    fn drop(&mut self) {
        if let Some(writing) = self.opened {
            self.event(if writing {
                crate::inotify::CLOSE_WRITE
            } else {
                crate::inotify::CLOSE_NOWRITE
            });
        }
        // `__fput` lets go of the dentry after `fsnotify_close`: a file
        // removed meanwhile ends with its last description.
        let caches = &self.caches;
        let id = Arc::as_ptr(&self.inner).cast::<()>().addr();
        let listed = caches
            .opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if let Some((_, _, found)) = listed
            && caches.notify.waiting()
        {
            let key = found.get().copied().or_else(|| {
                let stat = self.inner.stat().ok()?;
                Some((self.device.number(), stat.inode))
            });
            if let Some(key) = key
                && !caches.held(key)
            {
                caches.notify.last_closed(key);
            }
        }
    }
}

impl CoherentFile {
    /// `inner`, with the device of its own (a memfd's), listed among the
    /// open descriptions, which keep the file there for inotify.
    pub(crate) fn with_device(
        inner: Arc<dyn FileHandle>,
        caches: Arc<PageCaches>,
        device: u64,
    ) -> Self {
        let file = CoherentFile {
            inner,
            caches,
            device: Device::Fixed(device),
            key: OnceLock::new(),
            write: None,
            opened: None,
        };
        file.list();
        file
    }
    /// Lists this description among the open ones.
    fn list(&self) {
        let id = Arc::as_ptr(&self.inner).cast::<()>().addr();
        self.caches
            .opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                (
                    Arc::downgrade(&self.inner),
                    self.device.copy(),
                    OnceLock::new(),
                ),
            );
    }
    /// The file's key, as `stat` names it, or none for a file that is not
    /// regular.
    pub(crate) fn key(&self) -> Option<Key> {
        *self.key.get_or_init(|| {
            let stat = self.inner.stat().ok()?;
            let device = match &self.device {
                Device::Mount(fs, path, _) => mount_device(&fs.mounts(), path),
                Device::Fixed(device) => *device,
            };
            (stat.mode & 0o170000 == REGULAR).then_some((device, stat.inode))
        })
    }
    /// This handle, holding write access to its file when `flags` open it
    /// for writing, as Linux's `do_dentry_open` takes it: refused (ETXTBSY)
    /// while a program runs from the file. A memfd's own descriptor has none,
    /// as `memfd_create` makes its file without `do_dentry_open`.
    pub(crate) fn writing(mut self, flags: u32) -> Result<Self, Errno> {
        if flags & O_PATH == 0
            && flags & 3 != 0
            && let Some(key) = self.key()
        {
            self.write = Some(self.caches.write_access(key)?);
        }
        Ok(self)
    }
    fn cache(&self) -> Option<Arc<FileCache>> {
        if !self.caches.any() {
            return None;
        }
        self.caches.find(self.key()?)
    }
    /// This handle, as the guest's own open with `flags` makes it: its
    /// watches hear `IN_OPEN` (`fsnotify_open`), and will hear its close.
    fn opened(mut self, flags: u32) -> Self {
        self.list();
        if flags & O_PATH == 0 && crate::inotify::reported_open() {
            self.opened = Some(flags & 3 != 0);
            self.event(crate::inotify::OPEN);
        }
        self
    }
    /// Tells the machine's inotify watches of a change to the file
    /// (`notify_change`).
    fn changed(&self, mask: u32) {
        self.tell(mask, false);
    }
    /// Tells them of an event of the open file itself (`fsnotify_file`).
    fn event(&self, mask: u32) {
        self.tell(mask, true);
    }
    fn tell(&self, mask: u32, content: bool) {
        let notify = &self.caches.notify;
        if mask == 0 || !notify.watching() {
            return;
        }
        let Ok(stat) = self.inner.stat() else {
            return;
        };
        let (place, device) = match &self.device {
            Device::Mount(fs, path, place) => {
                let place = place.lock().unwrap_or_else(PoisonError::into_inner);
                (
                    Some((Arc::clone(fs), place.path.clone(), place.unlinked)),
                    mount_device(&fs.mounts(), path),
                )
            }
            Device::Fixed(device) => (None, *device),
        };
        let place = place
            .as_ref()
            .map(|(fs, path, unlinked)| (&**fs, &path[..], *unlinked));
        if content {
            notify.file_event(place, device, &stat, mask);
        } else {
            notify.changed_file(place, device, &stat, mask);
        }
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
    /// The file opened again, in step with the same page cache, which
    /// `O_TRUNC` empties as an open by path does.
    fn reopen(&self, flags: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let file = CoherentFile {
            inner: self.inner.reopen(flags)?,
            caches: Arc::clone(&self.caches),
            device: self.device.copy(),
            key: self
                .key
                .get()
                .copied()
                .map_or_else(OnceLock::new, OnceLock::from),
            write: None,
            opened: None,
        }
        .writing(flags)?
        .opened(flags);
        if flags & O_TRUNC != 0
            && let Some(cache) = file.cache()
        {
            cache.resized(0, 0);
        }
        Ok(Arc::new(file))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.inner.as_any()
    }
    fn notify_event(&self, mask: u32) -> bool {
        if matches!(self.device, Device::Fixed(_)) {
            return false;
        }
        self.event(mask);
        true
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
    /// A truncation is `IN_MODIFY` (`ATTR_SIZE`).
    fn truncate(&self, size: u64) -> Result<(), Errno> {
        if let Some(cache) = self.cache() {
            let old = self.inner.stat()?.size;
            self.inner.truncate(size)?;
            cache.resized(old, size);
        } else {
            self.inner.truncate(size)?;
        }
        self.changed(crate::inotify::MODIFY);
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
    fn with_xattrs(&self, f: &mut dyn FnMut(&mut paludarium_host::Xattrs)) -> Result<(), Errno> {
        let (result, changed) = crate::inotify::changing_xattrs(|| self.inner.with_xattrs(f));
        if result.is_ok() && changed {
            self.changed(crate::inotify::ATTRIB);
        }
        result
    }
    fn cached_pages(&self, first: u64, last: u64) -> u64 {
        self.inner.cached_pages(first, last)
    }
    fn with_attributes(&self, f: &mut dyn FnMut(&mut u32)) -> Result<(), Errno> {
        let (result, changed) = crate::inotify::changing_xattrs(|| self.inner.with_attributes(f));
        if result.is_ok() && changed {
            self.changed(crate::inotify::ATTRIB);
        }
        result
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.inner.set_mode(mode)?;
        self.changed(crate::inotify::ATTRIB);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.inner.set_owner(uid, gid)?;
        if uid.is_some() || gid.is_some() {
            self.changed(crate::inotify::ATTRIB);
        }
        Ok(())
    }
    fn set_times(&self, atime: Option<i128>, mtime: Option<i128>) -> Result<(), Errno> {
        self.inner.set_times(atime, mtime)?;
        self.changed(Notifier::times_mask(atime.is_some(), mtime.is_some()));
        Ok(())
    }
    fn file_system(&self) -> Option<u64> {
        self.inner.file_system()
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
    fn write_at_unappended(&self, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        let n = self.inner.write_at_unappended(offset, buf)?;
        if let Some(cache) = self.cache() {
            cache.wrote(offset, &buf[..n]);
        }
        Ok(n)
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
    fn memory_path(&self, anchor: &[u8], inode: u64) -> Option<Vec<u8>> {
        self.inner.memory_path(anchor, inode)
    }
}

impl HostFs for CoherentFs {
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        // A running program's file is not truncated: `handle_truncate`
        // takes write access first (ETXTBSY), whatever the access mode.
        const O_NOFOLLOW: u32 = 0o400000;
        if flags & O_TRUNC != 0
            && flags & O_PATH == 0
            && let Ok(stat) = self.inner.metadata(path, flags & O_NOFOLLOW == 0)
            && stat.mode & 0o170000 == REGULAR
        {
            let key = (mount_device(&self.inner.mounts(), path), stat.inode);
            drop(self.caches.write_access(key)?);
        }
        const O_CREAT: u32 = 0o100;
        let notify = &self.caches.notify;
        // Whether the file was there, for inotify: a new one is
        // `IN_CREATE`, an old one emptied `IN_MODIFY`.
        let existed = (notify.watching() && flags & (O_CREAT | O_TRUNC) != 0)
            .then(|| self.inner.metadata(path, flags & O_NOFOLLOW == 0).ok());
        let inner = self.inner.open(path, flags, mode)?;
        let created = matches!(existed, Some(None)) && flags & O_CREAT != 0;
        if created {
            notify.created(&*self.inner, path);
        }
        let file = CoherentFile {
            inner,
            caches: Arc::clone(&self.caches),
            device: Device::Mount(
                Arc::clone(&self.inner),
                path.to_vec(),
                Arc::new(Mutex::new(Place {
                    path: path.to_vec(),
                    resolved: false,
                    unlinked: false,
                })),
            ),
            key: OnceLock::new(),
            write: None,
            opened: None,
        }
        .writing(flags)?
        .opened(flags);
        if flags & O_TRUNC != 0
            && let Some(cache) = file.cache()
        {
            cache.resized(0, 0);
        }
        // `handle_truncate`, after the open.
        if let Some(Some(stat)) = existed
            && flags & (O_TRUNC | O_PATH) == O_TRUNC
            && stat.mode & 0o170000 == REGULAR
        {
            notify.changed(&*self.inner, path, true, crate::inotify::MODIFY);
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
        self.inner.mkdir(path, mode)?;
        self.caches.notify.created(&*self.inner, path);
        Ok(())
    }
    fn make_socket(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        let stat = self.inner.make_socket(path, mode)?;
        self.caches.notify.created(&*self.inner, path);
        Ok(stat)
    }
    fn make_fifo(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        let stat = self.inner.make_fifo(path, mode)?;
        self.caches.notify.created(&*self.inner, path);
        Ok(stat)
    }
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno> {
        let notify = &self.caches.notify;
        let removed = notify.before_removal(&*self.inner, path);
        let places = self.caches.places(&self.inner);
        let entry = (!places.is_empty())
            .then(|| entry_path(&*self.inner, path))
            .flatten();
        self.inner.unlink(path, directory)?;
        // `d_delete`: an open description's dentry stays, unhashed.
        if let Some(entry) = entry {
            for place in &places {
                let mut place = place.lock().unwrap_or_else(PoisonError::into_inner);
                if place.path == entry {
                    place.unlinked = true;
                }
            }
        }
        if let Some(removed) = removed {
            notify.unlinked(&removed, directory, &|key| self.caches.held(key));
        }
        Ok(())
    }
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        self.inner.link(old, new)?;
        self.caches.notify.linked(&*self.inner, new);
        Ok(())
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno> {
        self.inner.symlink(target, path)?;
        self.caches.notify.created(&*self.inner, path);
        Ok(())
    }
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        self.inner.readlink(path)
    }
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        let notify = &self.caches.notify;
        let moved = notify.before_rename(&*self.inner, old, new);
        let places = self.caches.before_rename(&self.inner, old, new);
        self.inner.rename(old, new)?;
        if let Some(places) = places {
            PageCaches::renamed(&places, false);
        }
        if let Some(moved) = moved {
            notify.renamed(&moved, 0, &|key| self.caches.held(key));
        }
        Ok(())
    }
    fn rename_with(&self, old: &[u8], new: &[u8], flags: u32) -> Result<(), Errno> {
        let notify = &self.caches.notify;
        let moved = notify.before_rename(&*self.inner, old, new);
        let places = self.caches.before_rename(&self.inner, old, new);
        self.inner.rename_with(old, new, flags)?;
        if let Some(places) = places {
            PageCaches::renamed(&places, flags & crate::inotify::EXCHANGE != 0);
        }
        if let Some(moved) = moved {
            notify.renamed(&moved, flags, &|key| self.caches.held(key));
        }
        Ok(())
    }
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        self.inner.read_dir(path)
    }
    fn statfs(&self, path: &[u8]) -> Result<FsStats, Errno> {
        self.inner.statfs(path)
    }
    fn with_xattrs(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut paludarium_host::Xattrs),
    ) -> Result<(), Errno> {
        let (result, changed) =
            crate::inotify::changing_xattrs(|| self.inner.with_xattrs(path, follow, f));
        if result.is_ok() && changed {
            self.caches
                .notify
                .changed(&*self.inner, path, follow, crate::inotify::ATTRIB);
        }
        result
    }
    fn with_attributes(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut u32),
    ) -> Result<(), Errno> {
        let (result, changed) =
            crate::inotify::changing_xattrs(|| self.inner.with_attributes(path, follow, f));
        if result.is_ok() && changed {
            self.caches
                .notify
                .changed(&*self.inner, path, follow, crate::inotify::ATTRIB);
        }
        result
    }
    fn set_mode(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        self.inner.set_mode(path, mode)?;
        self.caches
            .notify
            .changed(&*self.inner, path, true, crate::inotify::ATTRIB);
        Ok(())
    }
    fn set_owner(
        &self,
        path: &[u8],
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Errno> {
        self.inner.set_owner(path, follow, uid, gid)?;
        if uid.is_some() || gid.is_some() {
            self.caches
                .notify
                .changed(&*self.inner, path, follow, crate::inotify::ATTRIB);
        }
        Ok(())
    }
    fn set_times(
        &self,
        path: &[u8],
        follow: bool,
        atime: Option<i128>,
        mtime: Option<i128>,
    ) -> Result<(), Errno> {
        self.inner.set_times(path, follow, atime, mtime)?;
        let mask = Notifier::times_mask(atime.is_some(), mtime.is_some());
        self.caches.notify.changed(&*self.inner, path, follow, mask);
        Ok(())
    }
}
