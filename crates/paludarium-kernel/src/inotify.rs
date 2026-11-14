//! inotify: `inotify_init`, `inotify_init1`, `inotify_add_watch` and
//! `inotify_rm_watch`. An instance's watches are on files, by their device
//! and inode as `stat` names them ([`Key`]), and the machine's
//! [`Notifier`] hears of every change its file system makes: the handles of
//! [`crate::page_cache::CoherentFs`] tell it what Linux's `fsnotify` hooks
//! tell the watching groups, with the same events in the same order. An
//! instance queues what its watches want as Linux's
//! `inotify_handle_inode_event` does, merging an event into the same one
//! just before it, and a read takes them as `struct inotify_event` records.
//!
//! While no watch exists, a change costs one atomic load.
use crate::events::{CLOEXEC, IN, NONBLOCK, ReadinessHub};
use crate::fasync::{FileOwner, Notice, Reason, Registration};
use crate::page_cache::{Key, PageCaches, Place};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat, HostFs};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, mount_device};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

pub(crate) const ACCESS: u32 = 0x1;
pub(crate) const MODIFY: u32 = 0x2;
pub(crate) const ATTRIB: u32 = 0x4;
pub(crate) const CLOSE_WRITE: u32 = 0x8;
pub(crate) const CLOSE_NOWRITE: u32 = 0x10;
pub(crate) const OPEN: u32 = 0x20;
const MOVED_FROM: u32 = 0x40;
const MOVED_TO: u32 = 0x80;
const CREATE: u32 = 0x100;
const DELETE: u32 = 0x200;
const DELETE_SELF: u32 = 0x400;
const MOVE_SELF: u32 = 0x800;
const UNMOUNT: u32 = 0x2000;
const Q_OVERFLOW: u32 = 0x4000;
const IGNORED: u32 = 0x8000;
const ONLYDIR: u32 = 0x0100_0000;
const DONT_FOLLOW: u32 = 0x0200_0000;
const EXCL_UNLINK: u32 = 0x0400_0000;
const MASK_CREATE: u32 = 0x1000_0000;
const MASK_ADD: u32 = 0x2000_0000;
const ISDIR: u32 = 0x4000_0000;
const ONESHOT: u32 = 0x8000_0000;
/// `IN_ALL_EVENTS`, the events a watch can ask for.
const ALL_EVENTS: u32 = 0xfff;
/// `ALL_INOTIFY_BITS`, the bits `inotify_add_watch` takes.
const ALL_BITS: u32 = ALL_EVENTS
    | UNMOUNT
    | Q_OVERFLOW
    | IGNORED
    | ONLYDIR
    | DONT_FOLLOW
    | EXCL_UNLINK
    | MASK_ADD
    | MASK_CREATE
    | ISDIR
    | ONESHOT;
/// `sizeof(struct inotify_event)`, without its name.
const RECORD: usize = 16;
/// `/proc/sys/fs/inotify/max_queued_events` at first.
const MAX_EVENTS: i32 = 16384;
/// `/proc/sys/fs/inotify/max_user_instances` at first.
const MAX_INSTANCES: u64 = 128;
/// `/proc/sys/fs/inotify/max_user_watches` at first, as Linux's
/// `inotify_user_setup` works it out for the memory `sysinfo` reports: 1% of
/// it, over what a watch costs (a mark and twice an inode, about 1344 bytes
/// on x86-64), between 8192 and 1048576.
const MAX_WATCHES: u64 = {
    let watches = crate::syscalls::SYSINFO_RAM / 100 / 1344;
    if watches < 8192 {
        8192
    } else if watches > 1_048_576 {
        1_048_576
    } else {
        watches
    }
};
/// `RENAME_EXCHANGE`.
pub(crate) const EXCHANGE: u32 = 2;
/// `INOTIFY_IOC_SETNEXTWD`, `_IOW('I', 0, __u32)`.
const SETNEXTWD: u64 = 0x4004_4900;
const FIONREAD: u64 = 0x541b;

thread_local! {
    /// Set while the kernel changes a file on its own account, as it gives a
    /// new file its owner, which Linux does as it makes the inode.
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

thread_local! {
    /// Set by a call that changes a file's extended attributes, which the
    /// file system's `with_xattrs` cannot tell from one that reads them.
    static XATTRS_CHANGED: Cell<bool> = const { Cell::new(false) };
}
/// Says that the `with_xattrs` running now changes the attributes
/// (`fsnotify_xattr`).
pub(crate) fn xattrs_changed() {
    XATTRS_CHANGED.with(|changed| changed.set(true));
}
/// Runs `f`, a `with_xattrs`, and whether it said it changed them.
pub(crate) fn changing_xattrs<T>(f: impl FnOnce() -> Result<T, Errno>) -> (Result<T, Errno>, bool) {
    let was = XATTRS_CHANGED.with(|changed| changed.replace(false));
    let value = f();
    let changed = XATTRS_CHANGED.with(|changed| changed.replace(was));
    (value, changed)
}

thread_local! {
    /// Cleared while the kernel opens a file on its own account, as exec's
    /// loader reads a program whole or `mknod` makes a regular file, which
    /// Linux does without opening one (exec's own opens are told of apart).
    static OPENS: Cell<bool> = const { Cell::new(true) };
}
/// Runs `f`, whose opens are no `IN_OPEN` and whose files no `IN_CLOSE_*`.
pub(crate) fn unopened<T>(f: impl FnOnce() -> T) -> T {
    let was = OPENS.with(|opens| opens.replace(false));
    let value = f();
    OPENS.with(|opens| opens.set(was));
    value
}
/// Whether an open now is the guest's own, which is reported.
pub(crate) fn reported_open() -> bool {
    OPENS.with(Cell::get) && !QUIET.with(Cell::get)
}

/// Runs `f` without telling any watch of what it changes.
pub(crate) fn unnoticed<T>(f: impl FnOnce() -> T) -> T {
    let was = QUIET.with(|quiet| quiet.replace(true));
    let value = f();
    QUIET.with(|quiet| quiet.set(was));
    value
}

/// An open file the kernel does not otherwise keep as one: a FIFO opened
/// by its path, which Linux's `fifo_open` makes an ordinary open file, or a
/// file exec opens (`do_open_execat`), a program, a script or an ELF
/// interpreter. Its watches heard `IN_OPEN` (`fsnotify_open`) when it
/// opened, and hear `IN_CLOSE_WRITE` or `IN_CLOSE_NOWRITE`
/// (`fsnotify_close`) when the last reference goes, which drops this: the
/// FIFO's description's last descriptor, the program's process, the
/// interpreter's mapping. They go to where its dentry is, its [`Place`],
/// which renames move as a description's.
pub(crate) struct Closing {
    caches: Arc<PageCaches>,
    fs: Arc<dyn FileSystem>,
    place: Arc<Mutex<Place>>,
    /// For a file exec runs from a descriptor (a memfd, a removed file):
    /// its handle, which tells its events where its own dentry is, or with
    /// no place when it has none.
    file: Option<Arc<dyn FileHandle>>,
    device: u64,
    node: FileStat,
    writing: bool,
}
impl Closing {
    /// Tells the watches of the guest's open of the FIFO `node` at `path`
    /// with `flags`, and gives what tells them of its close: none for an
    /// open the kernel makes on its own account.
    pub(crate) fn opened(
        caches: &Arc<PageCaches>,
        fs: &Arc<dyn FileSystem>,
        path: &[u8],
        device: u64,
        node: &FileStat,
        flags: u32,
    ) -> Option<Self> {
        if !reported_open() {
            return None;
        }
        Some(Self::open(caches, fs, path, device, node, flags))
    }
    /// [`opened`](Self::opened), for an open known to be the guest's.
    pub(crate) fn open(
        caches: &Arc<PageCaches>,
        fs: &Arc<dyn FileSystem>,
        path: &[u8],
        device: u64,
        node: &FileStat,
        flags: u32,
    ) -> Self {
        let place = caches.keep_place((device, node.inode), path);
        Self::open_at(caches, fs, place, device, node, flags)
    }
    /// Another open of this file's dentry, as through `/proc/self/fd`, with
    /// `flags`: none for an open the kernel makes on its own account.
    pub(crate) fn again(&self, caches: &Arc<PageCaches>, flags: u32) -> Option<Self> {
        if !reported_open() {
            return None;
        }
        let mut node = self.node;
        if let Ok(now) = self.fs.metadata(&Place::at(&self.place).0, false)
            && now.inode == node.inode
        {
            node = now;
        }
        Some(Self::open_at(
            caches,
            &self.fs,
            Arc::clone(&self.place),
            self.device,
            &node,
            flags,
        ))
    }
    /// Tells the watches of exec's open of `file`, which only a descriptor
    /// holds, on `device` with the status `node` (`do_open_execat` of the
    /// descriptor's dentry), and gives what tells them of its close: none
    /// for an open the kernel makes on its own account.
    pub(crate) fn of_handle(
        caches: &Arc<PageCaches>,
        fs: &Arc<dyn FileSystem>,
        file: &Arc<dyn FileHandle>,
        device: u64,
        node: &FileStat,
    ) -> Option<Self> {
        if !reported_open() {
            return None;
        }
        let mut closing = Self::unopened(caches, fs, Arc::default(), device, node, 0);
        closing.file = Some(Arc::clone(file));
        closing.tell(OPEN);
        Some(closing)
    }
    /// The device of the file's node.
    pub(crate) fn device(&self) -> u64 {
        self.device
    }
    fn open_at(
        caches: &Arc<PageCaches>,
        fs: &Arc<dyn FileSystem>,
        place: Arc<Mutex<Place>>,
        device: u64,
        node: &FileStat,
        flags: u32,
    ) -> Self {
        let closing = Self::unopened(caches, fs, place, device, node, flags);
        closing.tell(OPEN);
        closing
    }
    fn unopened(
        caches: &Arc<PageCaches>,
        fs: &Arc<dyn FileSystem>,
        place: Arc<Mutex<Place>>,
        device: u64,
        node: &FileStat,
        flags: u32,
    ) -> Self {
        Self {
            caches: Arc::clone(caches),
            fs: Arc::clone(fs),
            place,
            file: None,
            device,
            node: *node,
            writing: flags & 3 != 0,
        }
    }
    /// Tells the watches of exec's read of the file's first bytes
    /// (`kernel_read`'s `IN_ACCESS`), which an empty file has none of.
    pub(crate) fn read(&self) {
        if self.node.size > 0 {
            self.tell(ACCESS);
        }
    }
    fn tell(&self, mask: u32) {
        let notify = &self.caches.notify;
        if !notify.watching() {
            return;
        }
        if let Some(file) = &self.file {
            if !file.notify_event(mask) {
                notify.file_event(None, self.device, &self.node, mask);
            }
            return;
        }
        let (path, unlinked) = Place::at(&self.place);
        // The links the node has now: none once its name is gone, or names
        // another file.
        let mut node = self.node;
        node.links = match self.fs.metadata(&path, false) {
            Ok(now) if now.inode == node.inode && !unlinked => now.links,
            _ => 0,
        };
        notify.file_event(Some((&*self.fs, &path, unlinked)), self.device, &node, mask);
    }
}
impl Drop for Closing {
    fn drop(&mut self) {
        self.tell(if self.writing {
            CLOSE_WRITE
        } else {
            CLOSE_NOWRITE
        });
        // `__fput` then lets go of the dentry: a removed file the last of
        // its opens held ends now.
        drop(std::mem::take(&mut self.place));
        let key = (self.device, self.node.inode);
        if self.caches.notify.waiting() && !self.caches.held(key) {
            self.caches.notify.last_closed(key);
        }
    }
}

/// The machine's limits of `/proc/sys/fs/inotify`: the instances and
/// watches each user may have (`max_user_instances` and `max_user_watches`,
/// Linux's `ucount_max` of the initial user namespace), and the events an
/// instance made from now on queues (`max_queued_events`).
pub(crate) struct Limits {
    pub(crate) instances: AtomicU64,
    pub(crate) watches: AtomicU64,
    pub(crate) events: AtomicI32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            instances: AtomicU64::new(MAX_INSTANCES),
            watches: AtomicU64::new(MAX_WATCHES),
            events: AtomicI32::new(MAX_EVENTS),
        }
    }
}

/// The instances of one machine, which every change is told to.
#[derive(Default)]
pub(crate) struct Notifier {
    /// `/proc/sys/fs/inotify`.
    pub(crate) limits: Limits,
    /// The watches of every instance: while there are none, a change is
    /// not looked at.
    watches: AtomicUsize,
    /// Files whose last link went while a description of them was open:
    /// their `IN_DELETE_SELF` waits for its last close, as Linux's waits
    /// for the dentry's last reference.
    pending: Mutex<HashSet<Key>>,
    /// Whether `pending` holds any, which a close looks at first.
    waiting: AtomicUsize,
    /// Linux's `fsnotify_sync_cookie`, which ties a rename's two events.
    cookie: AtomicU32,
    registry: Mutex<Registry>,
}

#[derive(Default)]
struct Registry {
    instances: Vec<Weak<Instance>>,
    /// The instances and watches of each effective user ID, as Linux's
    /// `ucounts` count them against the limits.
    users: HashMap<u32, (usize, usize)>,
}

/// A file a change names: where it is, if anywhere, and what is there.
pub(crate) struct Named {
    /// Its directory, when it has one, and its name in it.
    parent: Option<Key>,
    name: Vec<u8>,
    file: Option<Found>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Found {
    key: Key,
    directory: bool,
    links: u64,
}
impl Found {
    fn of(device: u64, stat: &FileStat) -> Self {
        Found {
            key: (device, stat.inode),
            directory: stat.mode & 0o170000 == 0o040000,
            links: stat.links,
        }
    }
    fn isdir(self) -> u32 {
        if self.directory { ISDIR } else { 0 }
    }
}

/// `path` with every symbolic link of it resolved, as
/// [`crate::files::resolved`] gives it, in the file system `fs`.
fn resolved(fs: &dyn HostFs, path: &[u8]) -> Option<Vec<u8>> {
    crate::files::resolved_in(fs, path)
}
/// `path`'s directory and last name; none for the root.
fn split(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let trimmed = path.trim_suffix(b"/");
    let at = trimmed.iter().rposition(|&b| b == b'/')?;
    let name = &trimmed[at + 1..];
    if name.is_empty() {
        return None;
    }
    Some((if at == 0 { b"/" } else { &trimmed[..at] }, name))
}

impl Notifier {
    /// Whether any watch exists, which a change must be told to.
    pub(crate) fn watching(&self) -> bool {
        self.watches.load(Ordering::SeqCst) != 0 && !QUIET.with(Cell::get)
    }
    fn instances(&self) -> Vec<Arc<Instance>> {
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry
            .instances
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    fn cookie(&self) -> u32 {
        self.cookie.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }
    /// What `path` names in `fs`: the file itself with `follow`, the last
    /// symbolic link otherwise.
    pub(crate) fn named(fs: &dyn FileSystem, path: &[u8], follow: bool) -> Option<Named> {
        let path = if follow {
            resolved(fs, path)?
        } else {
            let (directory, name) = split(path)?;
            let mut path = resolved(fs, directory)?;
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            path
        };
        let mounts = fs.mounts();
        let file = fs
            .metadata(&path, false)
            .ok()
            .map(|stat| Found::of(mount_device(&mounts, &path), &stat));
        let (parent, name) = match split(&path) {
            Some((directory, name)) => (
                fs.metadata(directory, true)
                    .ok()
                    .map(|stat| (mount_device(&mounts, directory), stat.inode)),
                name.to_vec(),
            ),
            None => (None, Vec::new()),
        };
        Some(Named { parent, name, file })
    }
    /// An event of a directory's entry (`fsnotify_name`): to the watches of
    /// the directory, with the name.
    fn entry(&self, directory: Option<Key>, mask: u32, name: &[u8], cookie: u32) {
        let Some(directory) = directory else {
            return;
        };
        for instance in self.instances() {
            instance.report(directory, mask, name, cookie, false);
        }
    }
    /// An event of a file itself (`fsnotify_inode`): to its watches, without
    /// a name.
    fn inode(&self, file: Found, mask: u32) {
        for instance in self.instances() {
            instance.report(file.key, mask | file.isdir(), b"", 0, false);
        }
    }
    /// An event of a file that its directory hears of too
    /// (`fsnotify_parent`): to the directory's watches with the file's name,
    /// then to the file's without.
    fn child(&self, named: Option<&Named>, file: Found, mask: u32, unlinked: bool) {
        let mask = mask | file.isdir();
        for instance in self.instances() {
            if let Some(parent) = named.and_then(|named| named.parent.map(|p| (p, named))) {
                instance.report(parent.0, mask, &parent.1.name, 0, unlinked);
            }
            instance.report(file.key, mask, b"", 0, unlinked);
        }
    }
    /// A file whose last link is gone (`fsnotify_inoderemove`): its watches
    /// hear `IN_DELETE_SELF`, then go with `IN_IGNORED`; once the last
    /// description `held` says is open is closed ([`Self::last_closed`]).
    fn removed(&self, file: Found, held: &dyn Fn(Key) -> bool) {
        if held(file.key) {
            {
                let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
                if pending.insert(file.key) {
                    self.waiting.fetch_add(1, Ordering::SeqCst);
                }
            }
            // A last close between the look and the insert saw nothing
            // waiting: looking again after it ends the file now.
            if !held(file.key) {
                self.last_closed(file.key);
            }
            return;
        }
        self.gone(file.key);
    }
    fn gone(&self, key: Key) {
        for instance in self.instances() {
            instance.report(key, DELETE_SELF, b"", 0, false);
            instance.forget(key);
        }
    }
    /// A file no name ever linked (a memfd), which ends, as a removed one
    /// does, at its last close.
    pub(crate) fn unlinked_from_start(&self, key: Key) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.insert(key) {
            self.waiting.fetch_add(1, Ordering::SeqCst);
        }
    }
    /// Whether a removed file waits for its last close.
    pub(crate) fn waiting(&self) -> bool {
        self.waiting.load(Ordering::SeqCst) != 0
    }
    /// The last description of file `key` is closed: a removed file's end
    /// comes now.
    pub(crate) fn last_closed(&self, key: Key) {
        let removed = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending.remove(&key)
        };
        if removed {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            self.gone(key);
        }
    }

    /// A new entry at `path` (`fsnotify_create`, `fsnotify_mkdir`).
    pub(crate) fn created(&self, fs: &dyn FileSystem, path: &[u8]) {
        if !self.watching() {
            return;
        }
        if let Some(named) = Self::named(fs, path, false) {
            let isdir = named.file.map_or(0, Found::isdir);
            self.entry(named.parent, CREATE | isdir, &named.name, 0);
        }
    }
    /// A new link at `path` to a file (`fsnotify_link`): the file's link
    /// count, then the entry.
    pub(crate) fn linked(&self, fs: &dyn FileSystem, path: &[u8]) {
        if !self.watching() {
            return;
        }
        if let Some(named) = Self::named(fs, path, false) {
            if let Some(file) = named.file {
                self.inode(file, ATTRIB);
            }
            self.entry(named.parent, CREATE, &named.name, 0);
        }
    }
    /// What an `unlink` or `rmdir` of `path` is about to remove.
    pub(crate) fn before_removal(&self, fs: &dyn FileSystem, path: &[u8]) -> Option<Named> {
        self.watching()
            .then(|| Self::named(fs, path, false))
            .flatten()
    }
    /// `unlink` and `rmdir` (`vfs_unlink`, `vfs_rmdir`): a file's link
    /// count, then the file's end if that was its last link, then the entry.
    pub(crate) fn unlinked(&self, named: &Named, directory: bool, held: &dyn Fn(Key) -> bool) {
        let Some(file) = named.file else {
            return;
        };
        if !directory {
            self.inode(file, ATTRIB);
        }
        if directory || file.links <= 1 {
            self.removed(file, held);
        }
        self.entry(named.parent, DELETE | file.isdir(), &named.name, 0);
    }
    /// What a rename from `old` to `new` is about to move and replace.
    pub(crate) fn before_rename(
        &self,
        fs: &dyn FileSystem,
        old: &[u8],
        new: &[u8],
    ) -> Option<(Named, Named)> {
        if !self.watching() {
            return None;
        }
        Some((Self::named(fs, old, false)?, Self::named(fs, new, false)?))
    }
    /// `vfs_rename`'s `fsnotify_move`, twice for `RENAME_EXCHANGE`, then the
    /// end of a file it replaced, which goes as the call lets go of it.
    pub(crate) fn renamed(
        &self,
        (old, new): &(Named, Named),
        flags: u32,
        held: &dyn Fn(Key) -> bool,
    ) {
        let Some(source) = old.file else {
            return;
        };
        // A rename onto another link of the same file does nothing.
        if new.file.is_some_and(|target| target.key == source.key) {
            return;
        }
        let exchange = flags & EXCHANGE != 0;
        let replaced = new.file.filter(|_| !exchange);
        self.moved(old, new, source, replaced);
        if exchange && let Some(target) = new.file {
            self.moved(new, old, target, None);
        }
        if let Some(target) = replaced
            && (target.directory || target.links <= 1)
        {
            self.removed(target, held);
        }
    }
    fn moved(&self, from: &Named, to: &Named, source: Found, replaced: Option<Found>) {
        let cookie = self.cookie();
        self.entry(from.parent, MOVED_FROM | source.isdir(), &from.name, cookie);
        self.entry(to.parent, MOVED_TO | source.isdir(), &to.name, cookie);
        if let Some(target) = replaced {
            self.inode(target, ATTRIB);
        }
        self.inode(source, MOVE_SELF);
    }
    /// A change to the file `path` names (`notify_change`, which tells
    /// `fsnotify_change`): `IN_ATTRIB`, `IN_MODIFY` or `IN_ACCESS`.
    pub(crate) fn changed(&self, fs: &dyn FileSystem, path: &[u8], follow: bool, mask: u32) {
        if mask == 0 || !self.watching() {
            return;
        }
        if let Some(named) = Self::named(fs, path, follow)
            && let Some(file) = named.file
        {
            self.child(Some(&named), file, mask, false);
        }
    }
    /// A change to an open file (`notify_change` of its dentry), which is
    /// at `path` in `fs` (unlinked from it, with the flag), or has a device
    /// of its own: its directory hears of it while it is there, and by that
    /// name once no name links the file.
    pub(crate) fn changed_file(
        &self,
        place: Option<(&dyn FileSystem, &[u8], bool)>,
        device: u64,
        stat: &FileStat,
        mask: u32,
    ) {
        self.of_file(place, device, stat, mask, false);
    }
    /// An event of an open file itself (`fsnotify_file`): opening,
    /// closing, reading or writing it. A watch with `IN_EXCL_UNLINK` does
    /// not hear of a file no name links any more, and the directory does
    /// not hear of reads and writes of a FIFO or a device.
    pub(crate) fn file_event(
        &self,
        place: Option<(&dyn FileSystem, &[u8], bool)>,
        device: u64,
        stat: &FileStat,
        mask: u32,
    ) {
        self.of_file(place, device, stat, mask, true);
    }
    fn of_file(
        &self,
        place: Option<(&dyn FileSystem, &[u8], bool)>,
        device: u64,
        stat: &FileStat,
        mask: u32,
        content: bool,
    ) {
        if mask == 0 || !self.watching() {
            return;
        }
        let file = Found::of(device, stat);
        let special = !matches!(stat.mode & 0o170000, 0o100000 | 0o040000 | 0o120000);
        // An unlinked dentry keeps its name and directory, as it stays with
        // its parent; one whose path no longer names the file (a change the
        // host made) is heard of by its own watches only.
        let gone = place.is_some_and(|(_, _, unlinked)| unlinked) || stat.links == 0;
        let named = place
            .and_then(|(fs, path, _)| {
                if gone {
                    Self::named(fs, path, false)
                } else {
                    Self::named(fs, path, true)
                        .filter(|named| named.file.is_some_and(|found| found.key == file.key))
                }
            })
            .filter(|_| !(content && special && mask & (ACCESS | MODIFY) != 0));
        // `fsnotify_handle_inode_event` skips either watch with
        // `IN_EXCL_UNLINK` for an unlinked dentry.
        let unlinked = content && gone;
        self.child(named.as_ref(), file, mask, unlinked);
    }
    /// The mask `set_times` reports (`fsnotify_change`): both times is
    /// `IN_ATTRIB`, only the access time `IN_ACCESS`, only the modification
    /// time `IN_MODIFY`.
    pub(crate) fn times_mask(atime: bool, mtime: bool) -> u32 {
        match (atime, mtime) {
            (true, true) => ATTRIB,
            (true, false) => ACCESS,
            (false, true) => MODIFY,
            (false, false) => 0,
        }
    }

    /// Counts a new instance for `user`: EMFILE past the limit, as Linux's
    /// `inc_ucount` for `UCOUNT_INOTIFY_INSTANCES`.
    fn add_instance(&self, user: u32) -> Result<(), Errno> {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let count = registry.users.entry(user).or_default();
        if count.0 as u64 >= self.limits.instances.load(Ordering::SeqCst) {
            return Err(Errno::EMFILE);
        }
        count.0 += 1;
        Ok(())
    }
    /// Lets `instance` hear of changes.
    fn register(&self, instance: Weak<Instance>) {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry
            .instances
            .retain(|instance| instance.strong_count() > 0);
        registry.instances.push(instance);
    }
    /// Counts a new watch for `user`: ENOSPC past the limit.
    fn add_watch(&self, user: u32) -> Result<(), Errno> {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let count = registry.users.entry(user).or_default();
        if count.1 as u64 >= self.limits.watches.load(Ordering::SeqCst) {
            return Err(Errno::ENOSPC);
        }
        count.1 += 1;
        self.watches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    /// Gives back `watches` watches of `user`, and the instance with them
    /// when `instance`.
    fn release(&self, user: u32, watches: usize, instance: bool) {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = registry.users.get_mut(&user) {
            count.1 -= watches.min(count.1);
            if instance {
                count.0 = count.0.saturating_sub(1);
            }
            if *count == (0, 0) {
                registry.users.remove(&user);
            }
        }
        self.watches.fetch_sub(watches, Ordering::SeqCst);
        if instance {
            registry
                .instances
                .retain(|instance| instance.strong_count() > 0);
        }
    }
}

struct Watch {
    key: Key,
    /// The events it wants, with `IN_EXCL_UNLINK` and `IN_ONESHOT`.
    mask: u32,
    /// When it was made, by the instance's count: Linux lists an instance's
    /// marks the newest first (`marks_list`).
    made: u64,
    /// The file system (`f_type`) of the file, for its handle.
    file_system: u64,
}
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}
impl Event {
    /// The record's length: the name padded with at least one NUL to a
    /// multiple of the record, as Linux's `round_event_name_len`.
    fn len(&self) -> usize {
        RECORD + padded(self.name.len())
    }
}
fn padded(name: usize) -> usize {
    if name == 0 {
        0
    } else {
        (name + 1).div_ceil(RECORD) * RECORD
    }
}

#[derive(Default)]
struct Queue {
    events: VecDeque<Event>,
    /// Whether the `IN_Q_OVERFLOW` event is queued, which is queued once.
    overflowed: bool,
    watches: BTreeMap<i32, Watch>,
    by_key: HashMap<Key, i32>,
    /// Where the next watch descriptor is looked for, as Linux's
    /// `idr_alloc_cyclic` keeps its cursor.
    cursor: i32,
    /// Events queued so far, each a wakeup of the file.
    epoch: u64,
    /// The events it queues at most (`max_events`), as
    /// `max_queued_events` was when the instance was made.
    max: usize,
    /// Watches made so far.
    made: u64,
}
impl Queue {
    /// Queues `event` as Linux's `fsnotify_insert_event`: past the limit
    /// only the overflow event, once; an event the same as the last one
    /// (but for `IN_IGNORED` and moves) is merged into it.
    fn push(&mut self, event: Event) -> bool {
        if self.events.len() >= self.max {
            if self.overflowed {
                return false;
            }
            self.overflowed = true;
            self.events.push_back(Event {
                wd: -1,
                mask: Q_OVERFLOW,
                cookie: 0,
                name: Vec::new(),
            });
        } else {
            if let Some(last) = self.events.back()
                && last.mask & (IGNORED | MOVED_FROM | MOVED_TO) == 0
                && last.mask == event.mask
                && last.wd == event.wd
                && last.name == event.name
            {
                return false;
            }
            self.events.push_back(event);
        }
        self.epoch += 1;
        true
    }
    fn pop(&mut self) -> Option<Event> {
        let event = self.events.pop_front()?;
        if event.mask == Q_OVERFLOW && event.wd == -1 {
            self.overflowed = false;
        }
        Some(event)
    }
    /// Removes watch `wd` and queues its `IN_IGNORED`, as Linux's
    /// `inotify_ignored_and_remove_idr`: none if there is no such watch,
    /// else whether the event was queued.
    fn unwatch(&mut self, wd: i32) -> Option<bool> {
        let watch = self.watches.remove(&wd)?;
        self.by_key.remove(&watch.key);
        Some(self.push(Event {
            wd,
            mask: IGNORED,
            cookie: 0,
            name: Vec::new(),
        }))
    }
    /// The next free watch descriptor from the cursor, wrapping to 1.
    fn allocate(&mut self) -> Result<i32, Errno> {
        let start = self.cursor.max(1);
        let free = |from: i32, to: i32| {
            if from > to {
                return None;
            }
            let mut wd = from;
            for (&used, _) in self.watches.range(from..=to) {
                if used != wd {
                    break;
                }
                wd = used.checked_add(1)?;
            }
            (wd <= to).then_some(wd)
        };
        let wd = free(start, i32::MAX)
            .or_else(|| free(1, start - 1))
            .ok_or(Errno::ENOSPC)?;
        self.cursor = wd.wrapping_add(1).max(0);
        Ok(wd)
    }
}

/// An inotify instance, the file `inotify_init1` gives.
pub(crate) struct Instance {
    notifier: Arc<Notifier>,
    hub: Arc<ReadinessHub>,
    /// The effective user ID whose limits it counts against.
    owner: u32,
    flags: AtomicU32,
    queue: Mutex<Queue>,
    /// Its signal-driven I/O: the owner `F_SETOWN` and `F_SETSIG` gave, and
    /// what sends the signal of the registration `O_ASYNC` made (`fsn_fa`).
    signalling: Mutex<(FileOwner, Option<Signal>)>,
}
/// What signals an instance's owner, once `O_ASYNC` registered it. It keeps
/// the registration out of sight of the types the machine's file system
/// holds, whose `Send` the compiler would otherwise follow too deep.
type Signal = Arc<dyn Fn(FileOwner) + Send + Sync>;
impl Instance {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn signalling(&self) -> std::sync::MutexGuard<'_, (FileOwner, Option<Signal>)> {
        self.signalling
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// `F_GETOWN`: who its signals go to.
    pub(crate) fn file_owner(&self) -> FileOwner {
        self.signalling().0
    }
    /// `F_SETOWN` and `F_SETSIG`.
    pub(crate) fn set_file_owner(&self, owner: FileOwner) {
        self.signalling().0 = owner;
    }
    /// `F_SETFL` turning `O_ASYNC` on, with its registration, or off
    /// (`fsnotify_fasync`).
    pub(crate) fn set_async(&self, registration: Option<Registration>) {
        self.signalling().1 = registration.map(|to| {
            Arc::new(move |owner| {
                Notice {
                    to: to.clone(),
                    owner,
                    reason: Reason::In,
                }
                .send();
            }) as Signal
        });
    }
    /// Wakes its readers for `queued` events newly queued, and signals its
    /// owner once for each, as `fsnotify_insert_event`'s `kill_fasync`
    /// does with `POLL_IN`.
    fn queued(&self, queued: usize) {
        if queued == 0 {
            return;
        }
        self.hub.changed();
        let (owner, signal) = self.signalling().clone();
        if let Some(signal) = signal {
            for _ in 0..queued {
                signal(owner);
            }
        }
    }
    /// An event for the watch on `key`, if there is one that wants it, as
    /// Linux's `fsnotify_handle_inode_event` and
    /// `inotify_handle_inode_event`; a one-shot watch goes with it.
    fn report(&self, key: Key, mask: u32, name: &[u8], cookie: u32, unlinked: bool) {
        let mut queue = self.queue();
        let Some(&wd) = queue.by_key.get(&key) else {
            return;
        };
        let Some(watch) = queue.watches.get(&wd) else {
            return;
        };
        if mask & watch.mask & ALL_EVENTS == 0 || (unlinked && watch.mask & EXCL_UNLINK != 0) {
            return;
        }
        let oneshot = watch.mask & ONESHOT != 0;
        // inotify never reported IN_ISDIR with these.
        let mask = if mask & (MOVE_SELF | DELETE_SELF) != 0 {
            mask & !ISDIR
        } else {
            mask
        };
        let mut queued = usize::from(queue.push(Event {
            wd,
            mask,
            cookie,
            name: name.to_vec(),
        }));
        let gone = if oneshot { queue.unwatch(wd) } else { None };
        queued += usize::from(gone == Some(true));
        drop(queue);
        if gone.is_some() {
            self.notifier.release(self.owner, 1, false);
        }
        self.queued(queued);
    }
    /// Removes the watch on `key`, whose file is gone.
    fn forget(&self, key: Key) {
        let mut queue = self.queue();
        let Some(&wd) = queue.by_key.get(&key) else {
            return;
        };
        let queued = queue.unwatch(wd) == Some(true);
        drop(queue);
        self.notifier.release(self.owner, 1, false);
        self.queued(usize::from(queued));
    }
    /// `inotify_update_watch`: the watch on `key` gets `mask` (or it is
    /// added with `IN_MASK_ADD`), or a new watch is made.
    fn watch(&self, key: Key, file_system: u64, mask: u32) -> Result<i32, Errno> {
        let wanted = mask & (ALL_EVENTS | EXCL_UNLINK | ONESHOT);
        let mut queue = self.queue();
        if let Some(&wd) = queue.by_key.get(&key) {
            if mask & MASK_CREATE != 0 {
                return Err(Errno::EEXIST);
            }
            if let Some(watch) = queue.watches.get_mut(&wd) {
                watch.mask = if mask & MASK_ADD != 0 {
                    watch.mask | wanted
                } else {
                    wanted
                };
            }
            return Ok(wd);
        }
        // The descriptor is taken before the count is (`inotify_new_watch`),
        // so a refused watch still moves the cursor on.
        let wd = queue.allocate()?;
        self.notifier.add_watch(self.owner)?;
        queue.made += 1;
        let made = queue.made;
        queue.watches.insert(
            wd,
            Watch {
                key,
                mask: wanted,
                made,
                file_system,
            },
        );
        queue.by_key.insert(key, wd);
        Ok(wd)
    }
    /// `inotify_rm_watch`: EINVAL for a descriptor no watch has.
    fn unwatch(&self, wd: i32) -> Result<(), Errno> {
        let mut queue = self.queue();
        let queued = queue.unwatch(wd).ok_or(Errno::EINVAL)?;
        drop(queue);
        self.notifier.release(self.owner, 1, false);
        self.queued(usize::from(queued));
        Ok(())
    }
    /// What `/proc/self/fdinfo` shows of its watches after the lines every
    /// descriptor has, as Linux's `inotify_fdinfo`: one line each, the
    /// newest first, with the watch descriptor, the file's inode and its
    /// file system's device (as the kernel numbers it) in hexadecimal, and
    /// the mask the watch was given, then the file's handle as
    /// `show_mark_fhandle` writes it ([`crate::files::file_handle`]): its
    /// size and type in hexadecimal and its bytes in pairs of hex digits.
    pub(crate) fn fdinfo(&self) -> Vec<u8> {
        let queue = self.queue();
        let mut watches: Vec<_> = queue.watches.iter().collect();
        watches.sort_by_key(|(_, watch)| std::cmp::Reverse(watch.made));
        let mut out = Vec::new();
        for (wd, watch) in watches {
            let (device, inode) = watch.key;
            // `new_encode_dev` undone, then `MKDEV`.
            let major = (device >> 8) & 0xfff;
            let minor = (device & 0xff) | ((device >> 12) & !0xff);
            let (kind, handle) = crate::files::file_handle(watch.file_system, device, inode);
            let bytes: String = handle.iter().map(|b| format!("{b:02x}")).collect();
            out.extend_from_slice(
                format!(
                    "inotify wd:{wd:x} ino:{inode:x} sdev:{:x} mask:{:x} ignored_mask:0 \
                     fhandle-bytes:{:x} fhandle-type:{kind:x} f_handle:{bytes}\n",
                    major << 20 | minor,
                    watch.mask,
                    handle.len(),
                )
                .as_bytes(),
            );
        }
        out
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        let watches = self.queue().watches.len();
        self.notifier.release(self.owner, watches, true);
    }
}

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}
pub(crate) fn sys_inotify_init(c: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    outcome(init(c, 0))
}
pub(crate) fn sys_inotify_init1(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(init(c, a[0] as u32))
}
pub(crate) fn sys_inotify_add_watch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(add_watch(c, a[0], a[1], a[2] as u32))
}
pub(crate) fn sys_inotify_rm_watch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(rm_watch(c, a[0], a[1] as i32))
}

/// `do_inotify_init`: the flags, the user's instances (EMFILE), then the
/// descriptor.
fn init(c: &mut Context<'_>, flags: u32) -> Result<u64, Errno> {
    if flags & !(NONBLOCK | CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let notifier = Arc::clone(&c.files.caches.notify);
    let owner = c.process.credentials.euid;
    notifier.add_instance(owner)?;
    // Counted now, and given back when it goes.
    let instance = Arc::new(Instance {
        notifier: Arc::clone(&notifier),
        hub: Arc::clone(&c.files.readiness),
        owner,
        flags: AtomicU32::new(flags & NONBLOCK),
        queue: Mutex::new(Queue {
            max: usize::try_from(notifier.limits.events.load(Ordering::SeqCst)).unwrap_or(0),
            ..Queue::default()
        }),
        signalling: Mutex::default(),
    });
    notifier.register(Arc::downgrade(&instance));
    c.files
        .install(instance, flags & CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

/// The instance descriptor `fd` holds: EBADF for none (or an `O_PATH`
/// one, which `fdget` does not take), EINVAL for another file.
fn instance(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    if file.flags() & crate::files::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// The instance `file` is, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&Instance> {
    file.as_any()?.downcast_ref::<Instance>()
}

/// `inotify_add_watch(fd, path, mask)`, checked in Linux's order: the mask's
/// bits, the descriptor, `IN_MASK_ADD` with `IN_MASK_CREATE`, the file, then
/// the path and the right to read what it names.
fn add_watch(c: &mut Context<'_>, fd: u64, path: u64, mask: u32) -> Result<u64, Errno> {
    if mask & !ALL_BITS != 0 || mask & ALL_BITS == 0 {
        return Err(Errno::EINVAL);
    }
    let file = instance(c, fd)?;
    if mask & MASK_ADD != 0 && mask & MASK_CREATE != 0 {
        return Err(Errno::EINVAL);
    }
    let instance = of(&file).ok_or(Errno::EINVAL)?;
    let (key, file_system) =
        crate::files::watched(c, path, mask & DONT_FOLLOW == 0, mask & ONLYDIR != 0)?;
    instance
        .watch(key, file_system, mask)
        .map(|wd| wd as u32 as u64)
}

fn rm_watch(c: &mut Context<'_>, fd: u64, wd: i32) -> Result<u64, Errno> {
    let file = instance(c, fd)?;
    of(&file).ok_or(Errno::EINVAL)?.unwatch(wd).map(|()| 0)
}

/// A read of an instance into a kernel buffer, as an asynchronous read
/// takes it; `None` for any other file.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    out: &mut [u8],
    nowait: bool,
) -> Option<Result<usize, Errno>> {
    let instance = of(file)?;
    let mut records = Vec::new();
    let result = read_events(c, instance, &mut records, out.len(), usize::MAX, nowait);
    out[..records.len()].copy_from_slice(&records);
    Some(result)
}

/// `read(2)` of an instance, or one buffer of a `readv(2)`, into the
/// guest's `len` bytes at `at`, which `access_ok` has passed, as Linux's
/// `inotify_read` copies each record out as it takes it: the record that
/// meets a page the guest cannot write is taken off the queue too, its bytes
/// up to that page written, and the read is `EFAULT`, whatever came before.
pub(crate) fn read_guest(
    c: &mut Context<'_>,
    instance: &Instance,
    at: u64,
    len: usize,
) -> Result<usize, Errno> {
    let writable = writable(c, at, len);
    let mut records = Vec::new();
    let result = read_events(c, instance, &mut records, len, writable, false);
    let shown = records.len().min(writable);
    c.mem
        .write(GuestAddr(at), &records[..shown])
        .map_err(|_| Errno::EFAULT)?;
    result
}

/// How many of the `len` bytes at `at` the guest can write, from the start.
fn writable(c: &Context<'_>, at: u64, len: usize) -> usize {
    let fits = |n: usize| n == 0 || c.mem.check_write(GuestAddr(at), n).is_ok();
    if fits(len) {
        return len;
    }
    // Whole pages: the first that cannot be written ends the prefix.
    let first = (4096 - (at % 4096) as usize).min(len);
    if !fits(first) {
        return 0;
    }
    let (mut good, mut bad) = (0usize, (len - first).div_ceil(4096));
    while bad - good > 1 {
        let mid = (good + bad) / 2;
        if fits(first + mid * 4096) {
            good = mid;
        } else {
            bad = mid;
        }
    }
    first + good * 4096
}

/// Linux's `inotify_read`: as many whole records as fit `len` bytes,
/// waiting for the first unless the file is non-blocking; EINVAL when the
/// first does not fit, and a pending signal ends the wait (ERESTARTSYS). A
/// record that reaches past the first `writable` bytes is the last taken,
/// and the read is then `EFAULT`.
fn read_events(
    c: &mut Context<'_>,
    instance: &Instance,
    out: &mut Vec<u8>,
    len: usize,
    writable: usize,
    nowait: bool,
) -> Result<usize, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        let mut queue = instance.queue();
        let mut short = false;
        let mut faulted = false;
        while let Some(size) = queue.events.front().map(Event::len) {
            if size > len - out.len() {
                short = true;
                break;
            }
            let Some(event) = queue.pop() else {
                break;
            };
            let at = out.len();
            out.resize(at + size, 0);
            let record = &mut out[at..];
            record[0..4].copy_from_slice(&event.wd.to_le_bytes());
            record[4..8].copy_from_slice(&event.mask.to_le_bytes());
            record[8..12].copy_from_slice(&event.cookie.to_le_bytes());
            record[12..16].copy_from_slice(&((size - RECORD) as u32).to_le_bytes());
            record[RECORD..RECORD + event.name.len()].copy_from_slice(&event.name);
            if out.len() > writable {
                faulted = true;
                break;
            }
        }
        drop(queue);
        if faulted {
            return Err(Errno::EFAULT);
        }
        if !out.is_empty() {
            return Ok(out.len());
        }
        if short {
            return Err(Errno::EINVAL);
        }
        if nowait || instance.flags.load(Ordering::SeqCst) & NONBLOCK != 0 {
            return Err(Errno::EAGAIN);
        }
        if crate::events::signalled(c) {
            return Err(Errno(4));
        }
        crate::events::wait(c, ticket, None)?;
    }
}

/// An instance's own `ioctl` requests (`inotify_ioctl`): `FIONREAD`, the
/// bytes its queued records take, and `INOTIFY_IOC_SETNEXTWD`; `ENOTTY` for
/// any other. `None` for any other file.
pub(crate) fn ioctl(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    request: u64,
    argument: u64,
) -> Option<Result<u64, Errno>> {
    let instance = of(file)?;
    Some(match request & 0xffff_ffff {
        FIONREAD => {
            let bytes: usize = instance.queue().events.iter().map(Event::len).sum();
            c.mem
                .write(GuestAddr(argument), &(bytes as i32).to_le_bytes())
                .map(|()| 0)
                .map_err(|_| Errno::EFAULT)
        }
        SETNEXTWD if (1..=i32::MAX as u64).contains(&argument) => {
            instance.queue().cursor = argument as i32;
            Ok(0)
        }
        SETNEXTWD => Err(Errno::EINVAL),
        _ => Err(Errno::ENOTTY),
    })
}

impl FileHandle for Instance {
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let queue = self.queue();
        Ok((u32::from(!queue.events.is_empty()) * IN, queue.epoch, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// Reads come through [`read`], which can wait.
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EAGAIN)
    }
    /// Opened for reading only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    /// Linux's `noop_llseek`: the position stays 0, whatever is asked.
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(
            flags & (NONBLOCK | crate::fasync::O_ASYNC),
            Ordering::SeqCst,
        );
        Ok(())
    }
}
