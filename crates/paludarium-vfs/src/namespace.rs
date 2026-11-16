//! Mount namespaces: the mounts a process sees, over the machine's
//! filesystem ([`MountedFs`], whose mounts exist from start-up).
//!
//! A [`MountTable`] is one namespace's tree of mounts, as Linux's
//! `mnt_namespace` holds its `struct mount`s: the ones from start-up
//! ("boot" mounts, the lower filesystem's own) first, then those `mount`
//! made. A [`NamespacedFs`] is the filesystem seen through a table. While a
//! table has only boot mounts every call goes straight to the lower
//! filesystem; otherwise a path is walked one name at a time, as Linux's
//! `link_path_walk` does, stepping into the topmost mount on a directory
//! (`handle_mounts`) and out of a mount's root with `..`
//! (`follow_dotdot`).
use crate::*;
use std::collections::BTreeSet;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Linux's per-mount flags (`MNT_*`), as a mount keeps them.
pub mod mount_flags {
    pub const NOSUID: u32 = 0x01;
    pub const NODEV: u32 = 0x02;
    pub const NOEXEC: u32 = 0x04;
    pub const NOATIME: u32 = 0x08;
    pub const NODIRATIME: u32 = 0x10;
    pub const RELATIME: u32 = 0x20;
    pub const READONLY: u32 = 0x40;
    pub const NOSYMFOLLOW: u32 = 0x80;
    /// The flags `mount` and a remount set (`MNT_USER_SETTABLE_MASK`).
    pub const SETTABLE: u32 = 0xff;
    /// The access-time flags (`MNT_ATIME_MASK`).
    pub const ATIME: u32 = NOATIME | NODIRATIME | RELATIME;
    /// What a copy into a less privileged mount namespace may not change
    /// (`MNT_LOCK_*`, set by `lock_mnt_tree`), kept apart from the flags.
    pub const LOCK_ATIME: u32 = 0x100;
    pub const LOCK_READONLY: u32 = 0x200;
    pub const LOCK_NODEV: u32 = 0x400;
    pub const LOCK_NOSUID: u32 = 0x800;
    pub const LOCK_NOEXEC: u32 = 0x1000;
}

/// A propagation type `mount` gives a mount (`MS_SHARED`, `MS_PRIVATE`,
/// `MS_SLAVE`, `MS_UNBINDABLE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Propagation {
    Shared,
    Private,
    Slave,
    Unbindable,
}

/// `show_vfsmnt_opts`: the per-mount options `/proc/self/mountinfo` shows
/// after `rw`.
fn shown_flags(flags: u32) -> String {
    use mount_flags::*;
    [
        (NOSUID, ",nosuid"),
        (NODEV, ",nodev"),
        (NOEXEC, ",noexec"),
        (NOATIME, ",noatime"),
        (NODIRATIME, ",nodiratime"),
        (RELATIME, ",relatime"),
        (NOSYMFOLLOW, ",nosymfollow"),
    ]
    .iter()
    .filter(|(flag, _)| flags & flag != 0)
    .map(|(_, name)| *name)
    .collect()
}

/// The IDs, device minors and peer groups in use, which every table made
/// from the first one shares: Linux's `mnt_id_ida`, `unnamed_dev_ida` and
/// `mnt_group_ida`, each handing out the lowest free number. It also keeps
/// the superblocks of the boot mounts, by device, and every table, which a
/// change of a peer group reaches.
#[derive(Default)]
struct Numbers {
    ids: Mutex<BTreeSet<u64>>,
    minors: Mutex<BTreeSet<u64>>,
    groups: Mutex<BTreeSet<u64>>,
    boot: Mutex<BTreeMap<u64, Arc<SuperState>>>,
    tables: Mutex<Vec<std::sync::Weak<dyn Listed>>>,
    /// What is told of each mount ID once it is free ([`ReleaseHook`]).
    released: Mutex<Option<ReleaseHook>>,
}
/// A table [`Numbers`] keeps, behind a trait object, which keeps the
/// auto-trait checks of what holds a table shallow.
trait Listed: Send + Sync {
    fn table(&self) -> &MountTable;
}
impl Listed for MountTable {
    fn table(&self) -> &MountTable {
        self
    }
}
impl Numbers {
    /// Every table that is still there.
    fn tables(&self) -> Vec<Arc<dyn Listed>> {
        let mut tables = lock(&self.tables);
        tables.retain(|t| t.strong_count() > 0);
        tables.iter().filter_map(std::sync::Weak::upgrade).collect()
    }
    /// The boot superblock of `device`.
    fn boot_state(&self, device: u64) -> Arc<SuperState> {
        Arc::clone(lock(&self.boot).entry(device).or_default())
    }
    /// Peer group `group`'s members have left: when none is left in any table its number is free again,
    /// and its slaves become slaves of `master` (`transfer_propagation`),
    /// or private for none.
    fn left(&self, group: u64, master: u64) {
        if group == 0 {
            return;
        }
        let tables = self.tables();
        if tables
            .iter()
            .any(|t| t.table().snapshot().iter().any(|e| e.group == group))
        {
            return;
        }
        lock(&self.groups).remove(&group);
        for table in &tables {
            let table = table.table();
            if table.snapshot().iter().any(|e| e.master == group) {
                let _ = table.update(|entries| {
                    for e in entries.iter_mut().filter(|e| e.master == group) {
                        e.master = master;
                    }
                    Ok(())
                });
            }
        }
    }
    /// The master of a member of peer group `group`, in any table.
    fn master_of(&self, group: u64) -> u64 {
        self.tables()
            .iter()
            .find_map(|t| {
                t.table()
                    .snapshot()
                    .iter()
                    .find(|e| e.group == group)
                    .map(|e| e.master)
            })
            .unwrap_or(0)
    }
    fn take(set: &Mutex<BTreeSet<u64>>, from: u64) -> u64 {
        let mut set = lock(set);
        let mut n = from;
        while set.contains(&n) {
            n += 1;
        }
        set.insert(n);
        n
    }
}

/// What every mount of a superblock shares: whether it is read-only
/// (`SB_RDONLY`), and how many files are open for writing on its mounts,
/// which a remount read-only refuses (`sb_prepare_remount_readonly`).
#[derive(Default)]
struct SuperState {
    read_only: AtomicBool,
    writers: AtomicUsize,
}

/// One mount's identity: its ID, held until the last [`MountPin`] and
/// the table both let go of it, as Linux frees a mount's ID with it.
struct Token {
    id: u64,
    numbers: Arc<Numbers>,
    /// The superblock of a tmpfs mount, which its open files keep (only
    /// held).
    _superblock: Option<Arc<Superblock>>,
    /// How many [`MountPin`]s hold it: Linux's `mnt_count` less the
    /// parent's and the lookup's own references.
    pins: AtomicUsize,
    /// How many of them are files open for writing (`mnt_writers`).
    writers: AtomicUsize,
    state: Arc<SuperState>,
    /// `MNT_EXPIRE`'s mark (`mnt_expiry_mark`), which any use of the
    /// mount clears (`mntput`).
    expiry: AtomicBool,
}
thread_local! {
    /// Whether this thread's lookups now leave expiry marks ([`keeping_expiry`]).
    static KEEPING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Runs `f`, whose lookups leave the mounts' expiry marks, as `umount2`'s
/// own lookup does (`path_umount` drops it without `mntput`).
pub fn keeping_expiry<T>(f: impl FnOnce() -> T) -> T {
    let was = KEEPING.with(|keeping| keeping.replace(true));
    let value = f();
    KEEPING.with(|keeping| keeping.set(was));
    value
}
impl Token {
    /// `mntput`: a use of the mount ends, which clears its expiry mark.
    fn used(&self) {
        if self.expiry.load(Ordering::Relaxed) && !KEEPING.with(std::cell::Cell::get) {
            self.expiry.store(false, Ordering::SeqCst);
        }
    }
    fn new(
        id: u64,
        numbers: &Arc<Numbers>,
        superblock: Option<Arc<Superblock>>,
        state: Arc<SuperState>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            numbers: Arc::clone(numbers),
            _superblock: superblock,
            pins: AtomicUsize::new(0),
            writers: AtomicUsize::new(0),
            state,
            expiry: AtomicBool::new(false),
        })
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        lock(&self.numbers.ids).remove(&self.id);
        // The mount below the root (numbered 1) is never handed out.
        if self.id >= 21 {
            let hook = lock(&self.numbers.released).clone();
            if let Some(hook) = hook {
                hook(self.id);
            }
        }
    }
}

/// What keeps a mount in use (`EBUSY` for `umount2` without
/// `MNT_DETACH`): an open file on it, or a working directory or a root in
/// it. It keeps a detached mount's file system too. Its mount is behind a
/// trait object, which keeps the auto-trait checks of the files that hold
/// one shallow.
pub struct MountPin(Arc<dyn Pinned>, bool);
/// A mount a [`MountPin`] holds.
trait Pinned: Send + Sync {
    fn token(&self) -> &Token;
}
impl Pinned for Token {
    fn token(&self) -> &Token {
        self
    }
}
impl MountPin {
    /// A pin of `token`'s mount; with `writer` one that writes to it.
    fn new(token: &Arc<Token>, writer: bool) -> Self {
        let pin = Self(Arc::clone(token) as Arc<dyn Pinned>, writer);
        pin.take();
        pin
    }
    fn take(&self) {
        let token = self.0.token();
        token.pins.fetch_add(1, Ordering::SeqCst);
        if self.1 {
            token.writers.fetch_add(1, Ordering::SeqCst);
            token.state.writers.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl Clone for MountPin {
    fn clone(&self) -> Self {
        let pin = Self(Arc::clone(&self.0), self.1);
        pin.take();
        pin
    }
}
impl Drop for MountPin {
    fn drop(&mut self) {
        let token = self.0.token();
        token.used();
        token.pins.fetch_sub(1, Ordering::SeqCst);
        if self.1 {
            token.writers.fetch_sub(1, Ordering::SeqCst);
            token.state.writers.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
impl std::fmt::Debug for MountPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MountPin({})", self.0.token().id)
    }
}

/// A tmpfs superblock: its files, its device, and what `statfs` and
/// mountinfo report of it. Its device minor is free again once it goes,
/// as `kill_anon_super` frees it.
struct Superblock {
    /// Behind a trait object, which keeps the auto-trait checks of what
    /// holds a table shallow.
    fs: Arc<dyn FileSystem>,
    minor: u64,
    numbers: Arc<Numbers>,
    settings: Mutex<Settings>,
    owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}
/// What a tmpfs superblock was mounted or last remounted with.
#[derive(Clone)]
pub struct Settings {
    /// Its size in 4 KiB blocks and its inodes, 0 for no limit, which
    /// `statfs` reports (and nothing enforces).
    pub blocks: u64,
    pub inodes: u64,
    /// What mountinfo shows of the superblock after `rw`: the common
    /// options (`,sync`), and tmpfs's own (`,size=1024k,inode64`).
    pub common_options: String,
    pub super_options: String,
    /// The options as the kernel parsed them, which a remount starts from.
    pub parsed: Arc<dyn std::any::Any + Send + Sync>,
}
/// What a remount reconfigures from: a tmpfs superblock's settings and the
/// blocks and inodes its files use, none for the lower file system's.
pub type InUse<'a> = Option<(&'a Settings, u64, u64)>;
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Settings({} {} {:?} {:?})",
            self.blocks, self.inodes, self.common_options, self.super_options
        )
    }
}
impl Drop for Superblock {
    fn drop(&mut self) {
        lock(&self.numbers.minors).remove(&self.minor);
    }
}
impl Superblock {
    fn device(&self) -> u64 {
        self.minor & 0xff | (self.minor & !0xff) << 12
    }
}

/// A new tmpfs to mount, as the kernel parsed its options.
pub struct NewTmpfs {
    /// Its files: an empty tree whose root has the mode and owner asked
    /// for.
    pub fs: MemFs,
    pub settings: Settings,
    /// Its superblock is read-only (`ro`, `MS_RDONLY`).
    pub read_only: bool,
    /// The per-mount flags ([`mount_flags`]).
    pub flags: u32,
    /// What it was mounted from, `none` if nothing.
    pub source: Vec<u8>,
    /// The user namespace that owns the superblock, which the kernel keeps
    /// (`s_user_ns`).
    pub owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

#[derive(Clone)]
enum Backing {
    /// A mount from start-up, the `index`th of the lower filesystem's.
    Boot {
        kind: &'static str,
        device: u64,
    },
    Memory(Arc<Superblock>),
    /// A bind mount of the lower filesystem's files, in the boot mount at
    /// `base`, whose type and device it shows.
    Lower {
        kind: &'static str,
        device: u64,
        base: Vec<u8>,
    },
}

#[derive(Clone)]
struct Entry {
    token: Arc<Token>,
    parent: u64,
    point: Vec<u8>,
    backing: Backing,
    /// Where its root is in its file system (`mnt_root`): `/` for a new
    /// tmpfs, the directory or file a bind mount was made from, a path
    /// from the machine's root for one of the lower filesystem's.
    root: Vec<u8>,
    flags: u32,
    /// The flags it may not change ([`mount_flags`]'s `LOCK_*`).
    locks: u32,
    locked: bool,
    source: Vec<u8>,
    /// Its peer group (`mnt_group_id`), 0 for none: a mount in one is
    /// shared.
    group: u64,
    /// The peer group it is a slave of (its `mnt_master`'s), 0 for none.
    master: u64,
    unbindable: bool,
    /// The mount below the namespace's root that `pivot_root` and a move
    /// of a mount from start-up leave (Linux's rootfs): the lower
    /// filesystem from its root, which no list shows and no walk enters.
    hidden: bool,
}
impl Entry {
    fn id(&self) -> u64 {
        self.token.id
    }
    fn memory(&self) -> Option<&Arc<Superblock>> {
        match &self.backing {
            Backing::Memory(sb) => Some(sb),
            Backing::Boot { .. } | Backing::Lower { .. } => None,
        }
    }
    /// Made after start-up, by `mount`: a walk steps into it itself.
    fn runtime(&self) -> bool {
        !matches!(self.backing, Backing::Boot { .. })
    }
    /// The path in its file system of `path`, a path in the mount.
    fn inside(&self, path: &[u8]) -> Vec<u8> {
        joined(&self.root, &relative(&self.point, path))
    }
    fn read_only(&self) -> ReadOnly {
        let superblock = self.token.state.read_only.load(Ordering::SeqCst);
        ReadOnly {
            mount: superblock || self.flags & mount_flags::READONLY != 0,
            superblock,
        }
    }
    /// A copy of it made by `clone_mnt`, with a new ID, rooted at `root` in
    /// its file system and mounted at `point` on the mount `parent`: a
    /// peer of it, and a slave of its master. With `slave` (`CL_SLAVE`) it
    /// is no peer, but a slave of its peer group if it has one.
    fn cloned(
        &self,
        numbers: &Arc<Numbers>,
        root: Vec<u8>,
        parent: u64,
        point: Vec<u8>,
        slave: bool,
    ) -> Self {
        let (group, master) = match (slave, self.group) {
            (true, 0) => (0, self.master),
            (true, group) => (0, group),
            (false, group) => (group, self.master),
        };
        Self {
            token: Token::new(
                Numbers::take(&numbers.ids, 21),
                numbers,
                self.memory().cloned(),
                Arc::clone(&self.token.state),
            ),
            parent,
            point,
            backing: match &self.backing {
                Backing::Boot { kind, device } => Backing::Lower {
                    kind,
                    device: *device,
                    base: self.point.clone(),
                },
                other => other.clone(),
            },
            root,
            group,
            master,
            ..self.clone()
        }
    }
    /// Whether it shows the same file system as `other`.
    fn same_files(&self, other: &Self) -> bool {
        match (&self.backing, &other.backing) {
            (Backing::Memory(a), Backing::Memory(b)) => Arc::ptr_eq(a, b),
            (Backing::Memory(_), _) | (_, Backing::Memory(_)) => false,
            _ => true,
        }
    }
}

/// What a table tells of the mounts an unmount takes out of its namespace
/// (`umount_tree`): their IDs, each mount before those on it, after they
/// went. A hook point for fanotify's mount events (`FAN_MNT_DETACH`, which
/// Linux's `mnt_notify` sends). A detached tree that goes with its last
/// descriptor is in no namespace and tells nothing, nor do moves.
pub type UnmountHook = Arc<dyn Fn(&[u64]) + Send + Sync>;

/// What a machine's tables tell of a mount once it is freed, as Linux's
/// last `mntput` does (`cleanup_mnt`, `fsnotify_vfsmount_delete`): its ID,
/// free again, once no table and nothing open holds the mount, whichever
/// way it went (an unmount, a detached tree, a namespace that ended). A
/// hook point for fanotify's marks on mounts, which are kept by mount ID.
/// It may run while a table is being changed, so it must not use one.
pub type ReleaseHook = Arc<dyn Fn(u64) + Send + Sync>;

/// One mount namespace's mounts.
pub struct MountTable {
    entries: RwLock<Arc<Vec<Entry>>>,
    /// Whether every mount is a boot one, so calls go straight through.
    boot_only: AtomicBool,
    /// Where the lower filesystem has its mounts, which it shows itself.
    lower_points: Arc<Vec<Vec<u8>>>,
    /// What is told of mounts that leave the namespace ([`UnmountHook`]).
    unmount_hook: Mutex<Option<UnmountHook>>,
    numbers: Arc<Numbers>,
}
impl std::fmt::Debug for MountTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<u64> = self.snapshot().iter().map(Entry::id).collect();
        write!(f, "MountTable{ids:?}")
    }
}
impl MountTable {
    /// The first namespace's table: the mounts of `lower`, with the IDs,
    /// parents and devices it gives them.
    pub fn new(lower: &dyn FileSystem) -> Arc<Self> {
        let numbers = Arc::new(Numbers::default());
        let mounts = lower.mounts();
        let entries = mounts
            .iter()
            .map(|m| {
                lock(&numbers.ids).insert(m.id);
                lock(&numbers.minors).insert(m.device & 0xff | (m.device >> 12) & !0xff);
                Entry {
                    token: Token::new(m.id, &numbers, None, numbers.boot_state(m.device)),
                    parent: m.parent,
                    point: m.path.clone(),
                    backing: Backing::Boot {
                        kind: m.kind,
                        device: m.device,
                    },
                    root: m.path.clone(),
                    flags: mount_flags::RELATIME,
                    locks: 0,
                    locked: false,
                    source: m.source.clone(),
                    group: 0,
                    master: 0,
                    unbindable: false,
                    hidden: false,
                }
            })
            .collect();
        Self::registered(Self {
            entries: RwLock::new(Arc::new(entries)),
            boot_only: AtomicBool::new(true),
            lower_points: Arc::new(mounts.iter().map(|m| m.path.clone()).collect()),
            unmount_hook: Mutex::default(),
            numbers,
        })
    }
    /// `table`, which the changes of a peer group now reach.
    fn registered(table: Self) -> Arc<Self> {
        let table = Arc::new(table);
        let listed: Arc<dyn Listed> = Arc::clone(&table) as Arc<dyn Listed>;
        lock(&table.numbers.tables).push(Arc::downgrade(&listed));
        table
    }
    /// A new namespace's copy of this one (`copy_mnt_ns`): every mount
    /// again, with a new ID, on the same file systems, unbindable ones too,
    /// each a peer of the one it copies and a slave of its master. With
    /// `locked` (the new namespace has another user namespace) each copy
    /// is locked, as `lock_mnt_tree` locks all but the copy's root (here
    /// the root is locked too, standing for Linux's `/`, which sits on its
    /// rootfs), its flags are locked, and it is a slave of the one it
    /// copies instead of a peer (`CL_SLAVE`).
    #[must_use]
    pub fn copy(&self, locked: bool) -> Arc<Self> {
        use mount_flags::*;
        let old = self.snapshot();
        // Each copy's ID first, as a parent may come after a mount on it
        // once a `pivot_root` moved them; the mount below the root keeps
        // the number it is shown by.
        let ids: BTreeMap<u64, u64> = old
            .iter()
            .filter(|e| !detached(&e.point))
            .map(|e| {
                let id = if e.hidden {
                    e.id()
                } else {
                    Numbers::take(&self.numbers.ids, 21)
                };
                (e.id(), id)
            })
            .collect();
        let mut entries = Vec::with_capacity(old.len());
        // A detached tree stays with the table it was made from.
        for e in old.iter().filter(|e| !detached(&e.point)) {
            let id = ids[&e.id()];
            let (group, master) = match (locked, e.group) {
                (true, 0) => (0, e.master),
                (true, group) => (0, group),
                (false, group) => (group, e.master),
            };
            let mut locks = e.locks;
            if locked {
                locks |= LOCK_ATIME;
                for (flag, lock) in [
                    (READONLY, LOCK_READONLY),
                    (NODEV, LOCK_NODEV),
                    (NOSUID, LOCK_NOSUID),
                    (NOEXEC, LOCK_NOEXEC),
                ] {
                    if e.flags & flag != 0 {
                        locks |= lock;
                    }
                }
            }
            entries.push(Entry {
                token: Token::new(
                    id,
                    &self.numbers,
                    e.memory().cloned(),
                    Arc::clone(&e.token.state),
                ),
                parent: ids.get(&e.parent).copied().unwrap_or(e.parent),
                locked: e.locked || locked,
                locks,
                group,
                master,
                ..e.clone()
            });
        }
        Self::registered(Self {
            entries: RwLock::new(Arc::new(entries)),
            boot_only: AtomicBool::new(self.boot_only.load(Ordering::SeqCst)),
            lower_points: Arc::clone(&self.lower_points),
            unmount_hook: Mutex::default(),
            numbers: Arc::clone(&self.numbers),
        })
    }
    /// Tells `hook` of each mount freed from now on, in this table or any
    /// made from it ([`ReleaseHook`]), in place of any hook before.
    pub fn set_release_hook(&self, hook: Option<ReleaseHook>) {
        *lock(&self.numbers.released) = hook;
    }
    /// Tells `hook` of each unmount from now on, in place of any hook before.
    pub fn set_unmount_hook(&self, hook: Option<UnmountHook>) {
        *lock(&self.unmount_hook) = hook;
    }
    fn snapshot(&self) -> Arc<Vec<Entry>> {
        Arc::clone(&self.entries.read().unwrap_or_else(PoisonError::into_inner))
    }
    fn update<T>(&self, f: impl FnOnce(&mut Vec<Entry>) -> Result<T, Errno>) -> Result<T, Errno> {
        let mut guard = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let mut entries = (**guard).clone();
        let out = f(&mut entries)?;
        self.boot_only
            .store(entries.iter().all(|e| !e.runtime()), Ordering::SeqCst);
        *guard = Arc::new(entries);
        Ok(out)
    }
    /// A peer group's number, the lowest free one (`mnt_alloc_group_id`).
    fn new_group(&self) -> u64 {
        Numbers::take(&self.numbers.groups, 1)
    }
    /// The boot mount holding `path`: the longest mount point.
    fn boot_index(&self, entries: &[Entry], path: &[u8]) -> usize {
        entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.runtime() && within(path, &e.point))
            .max_by_key(|(_, e)| e.point.len())
            .map_or(0, |(i, _)| i)
    }
}

impl Drop for MountTable {
    /// The namespace's mounts go (`put_mnt_ns`), each private first.
    fn drop(&mut self) {
        let entries = self.snapshot();
        for e in entries.iter() {
            self.numbers.left(e.group, e.master);
        }
    }
}

/// Whether `path` is `point` or below it.
fn within(path: &[u8], point: &[u8]) -> bool {
    point == b"/"
        || path == point
        || path.starts_with(point) && path.get(point.len()) == Some(&b'/')
}
/// `path` from the root of the mount at `point`.
fn relative(point: &[u8], path: &[u8]) -> Vec<u8> {
    if path == point {
        b"/".to_vec()
    } else if point == b"/" {
        path.to_vec()
    } else {
        path[point.len()..].to_vec()
    }
}
/// `rest`, a path from a directory, from where the directory is, `at`.
fn joined(at: &[u8], rest: &[u8]) -> Vec<u8> {
    if rest == b"/" {
        at.to_vec()
    } else if at == b"/" {
        rest.to_vec()
    } else {
        [at, rest].concat()
    }
}
/// Whether `point` is in a detached tree ([`NamespacedFs::clone_tree`]),
/// whose names start with a 0 that no path a program gives can hold.
fn detached(point: &[u8]) -> bool {
    point.starts_with(b"/\0")
}
/// `name` in the directory `dir`.
fn child_path(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = dir.to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}
fn parent_path(path: &[u8]) -> Vec<u8> {
    let at = path.iter().rposition(|b| *b == b'/').unwrap_or(0);
    path[..at.max(1)].to_vec()
}
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const EBUSY: Errno = Errno(16);
const EXDEV: Errno = Errno(18);
const ELOOP: Errno = Errno(40);

/// Where a walk got to: a path from the machine's root, and the tmpfs
/// mount it is on (an index into the table), or none for the lower
/// filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Loc {
    at: Option<usize>,
    path: Vec<u8>,
}

/// What `umount2` and `mount` learn of the mount a path is in.
#[derive(Debug, Clone)]
pub struct Target {
    pub id: u64,
    /// The path is the mount's root (Linux's `path_mounted`).
    pub root: bool,
    /// The mount is one from start-up that the lower filesystem shows
    /// where it is, so taking it away would show that again, not the
    /// directory under it: it cannot be unmounted or moved.
    pub boot: bool,
    /// The namespace's own root, which has no parent.
    pub namespace_root: bool,
    pub locked: bool,
    /// Other mounts are on it.
    pub covered: bool,
    /// The user namespace that owns its superblock; none for the first.
    pub owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Its flags, and those it may not change ([`mount_flags`]).
    pub flags: u32,
    pub locks: u32,
    /// Its file system's type.
    pub kind: &'static str,
    /// A tmpfs superblock's settings; none for the lower file system.
    pub settings: Option<Settings>,
    pub read_only: ReadOnly,
}

/// The filesystem through a mount namespace's table.
pub struct NamespacedFs {
    /// The machine's filesystem from its root.
    lower: Arc<dyn FileSystem>,
    /// The same from `root`, which the calls of a table of boot mounts go to.
    view: Arc<dyn FileSystem>,
    table: Arc<MountTable>,
    root: Vec<u8>,
}
impl NamespacedFs {
    #[must_use]
    pub fn new(lower: Arc<dyn FileSystem>, table: Arc<MountTable>) -> Self {
        Self {
            view: Arc::clone(&lower),
            lower,
            table,
            root: b"/".to_vec(),
        }
    }
    #[must_use]
    pub fn table(&self) -> &Arc<MountTable> {
        &self.table
    }
    fn fast(&self) -> bool {
        self.table.boot_only.load(Ordering::SeqCst)
    }
    /// The index of the mount numbered `id` that `mount` made, none for a
    /// boot one.
    fn runtime_index(entries: &[Entry], id: u64) -> Option<usize> {
        entries
            .iter()
            .position(|e| e.id() == id)
            .filter(|&i| entries[i].runtime())
    }
    fn id_of(&self, entries: &[Entry], loc: &Loc) -> u64 {
        match loc.at {
            Some(i) => entries[i].id(),
            None => entries[self.table.boot_index(entries, &loc.path)].id(),
        }
    }
    fn entry<'a>(&self, entries: &'a [Entry], loc: &Loc) -> &'a Entry {
        match loc.at {
            Some(i) => &entries[i],
            None => &entries[self.table.boot_index(entries, &loc.path)],
        }
    }
    /// The mount on `loc`, if any.
    fn covering(&self, entries: &[Entry], loc: &Loc) -> Option<usize> {
        let id = self.id_of(entries, loc);
        entries
            .iter()
            .position(|e| e.runtime() && e.parent == id && e.point == loc.path)
    }
    /// Into the topmost mount on `loc` (`handle_mounts`).
    fn cross(&self, entries: &[Entry], mut loc: Loc) -> Loc {
        while let Some(i) = self.covering(entries, &loc) {
            loc.at = Some(i);
        }
        loc
    }
    /// The file system `loc` is on and its path there.
    fn backing<'a>(&'a self, entries: &'a [Entry], loc: &Loc) -> (&'a dyn FileSystem, Vec<u8>) {
        // A walk is only ever on a mount `mount` made or the lower
        // filesystem.
        match loc.at.map(|i| &entries[i]) {
            Some(e) => (
                e.memory().map_or(&*self.lower, |sb| &*sb.fs),
                e.inside(&loc.path),
            ),
            None => (&*self.lower, loc.path.clone()),
        }
    }
    fn lstat(&self, entries: &[Entry], loc: &Loc) -> Result<FileStat, Errno> {
        let (fs, path) = self.backing(entries, loc);
        fs.metadata(&path, false)
    }
    /// The namespace's root mount: the first, or once a `pivot_root` or a
    /// move left the mount below it, the first on that one's root.
    fn root_index(entries: &[Entry]) -> usize {
        entries
            .iter()
            .find(|e| e.hidden)
            .and_then(|below| {
                entries
                    .iter()
                    .position(|e| !e.hidden && e.parent == below.id() && e.point == b"/")
            })
            .unwrap_or(0)
    }
    /// Where a walk starts: the machine's root, on the namespace's root
    /// mount.
    fn start(entries: &[Entry]) -> Loc {
        let i = Self::root_index(entries);
        Loc {
            at: entries.get(i).filter(|e| e.runtime()).map(|_| i),
            path: b"/".to_vec(),
        }
    }
    /// Where the process's root is: its path walked from the machine's
    /// root, stepping into each mount on the way.
    fn root_loc(&self, entries: &[Entry]) -> Loc {
        let mut loc = Self::start(entries);
        for part in self.root.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            loc.path = child_path(&loc.path, part);
            loc = self.cross(entries, loc);
        }
        loc
    }
    /// Walks `path` one name at a time, as [`MountedFs`] does, through the
    /// mounts: with `follow` a last symbolic link is followed, with
    /// `missing` a missing last name is where it would be, and with `cross`
    /// a mount on the last name is stepped into. The mount it ends on is
    /// used, which clears its expiry mark (`path_put`).
    fn walk(
        &self,
        entries: &[Entry],
        path: &[u8],
        follow: bool,
        missing: bool,
        cross: bool,
    ) -> Result<Loc, Errno> {
        let loc = self.walk_keeping(entries, path, follow, missing, cross)?;
        if let Some(i) = loc.at {
            entries[i].token.used();
        }
        Ok(loc)
    }
    /// [`Self::walk`], leaving the expiry mark, as `umount2`'s lookup does.
    fn walk_keeping(
        &self,
        entries: &[Entry],
        path: &[u8],
        follow: bool,
        missing: bool,
        cross: bool,
    ) -> Result<Loc, Errno> {
        validate(path)?;
        if path[0] != b'/' {
            return Err(Errno::ENOENT);
        }
        let trailing = path.last() == Some(&b'/');
        let mut queue: VecDeque<Vec<u8>> = path
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .map(Vec::from)
            .collect();
        let mut current = Self::start(entries);
        let mut links = 0;
        while let Some(part) = queue.pop_front() {
            if self.lstat(entries, &current)?.mode & S_IFMT != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
            if part == b"." {
                continue;
            }
            // The root of a detached tree, by its name.
            if part.first() == Some(&0) {
                let point = [&b"/"[..], &part].concat();
                let i = entries
                    .iter()
                    .position(|e| e.point == point && e.parent == e.id())
                    .ok_or(Errno::ENOENT)?;
                current = Loc {
                    at: Some(i),
                    path: point,
                };
                continue;
            }
            if part == b".." {
                // A detached tree's root has no parent to go up to.
                let tree_root = detached(&current.path) && !current.path[2..].contains(&b'/');
                if current.path != b"/" && current.path != self.root && !tree_root {
                    // Out of each mount whose root this is, to where it
                    // is mounted, then up (`follow_dotdot`).
                    while let Some(i) = current.at
                        && entries[i].point == current.path
                    {
                        current.at = Self::runtime_index(entries, entries[i].parent);
                    }
                    current.path = parent_path(&current.path);
                }
                continue;
            }
            let next = Loc {
                at: current.at,
                path: child_path(&current.path, &part),
            };
            let stat = match self.lstat(entries, &next) {
                Ok(stat) => stat,
                Err(e) if e == Errno::ENOENT && queue.is_empty() && missing => return Ok(next),
                Err(e) => return Err(e),
            };
            if stat.mode & S_IFMT == S_IFLNK && (follow || !queue.is_empty() || trailing) {
                links += 1;
                if links > 40 {
                    return Err(ELOOP);
                }
                let (fs, at) = self.backing(entries, &next);
                let target = fs.readlink(&at)?;
                validate(&target)?;
                if target[0] == b'/' {
                    current = self.root_loc(entries);
                }
                for component in target.split(|b| *b == b'/').filter(|p| !p.is_empty()).rev() {
                    queue.push_front(component.to_vec());
                }
            } else {
                current = if cross || !queue.is_empty() {
                    self.cross(entries, next)
                } else {
                    next
                };
            }
        }
        if trailing && self.lstat(entries, &current)?.mode & S_IFMT != S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        Ok(current)
    }
    /// The trailing-slash check of a name to remove: it must be a directory.
    fn trailing_directory(&self, entries: &[Entry], path: &[u8]) -> Result<(), Errno> {
        if path.last() == Some(&b'/') {
            let end = path.iter().rposition(|b| *b != b'/').map_or(1, |i| i + 1);
            let loc = self.walk(entries, &path[..end], false, false, false)?;
            if self.lstat(entries, &loc)?.mode & S_IFMT != S_IFDIR {
                return Err(Errno::ENOTDIR);
            }
        }
        Ok(())
    }
    /// Where `path` is for its device: the file, or the nearest directory
    /// above it that is there.
    fn locate(&self, entries: &[Entry], path: &[u8]) -> Loc {
        let mut path = path.to_vec();
        loop {
            if let Ok(loc) = self.walk(entries, &path, true, true, true) {
                return loc;
            }
            if path.len() <= 1 {
                return Self::start(entries);
            }
            path = parent_path(&path);
        }
    }
    /// Moves the mounts below `old` in the mount `id` to below `new`, as
    /// a rename moves the dentries they are on.
    fn moved(&self, id: u64, old: &[u8], new: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let entries = self.table.snapshot();
        let below = |p: &[u8]| p.len() > old.len() && within(p, old) && old != b"/";
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| e.runtime()) {
            if !below(&e.point) {
                continue;
            }
            // The mount of the topmost of its ancestors still below `old`.
            let mut at = e;
            while let Some(i) = Self::runtime_index(&entries, at.parent)
                && below(&entries[i].point)
            {
                at = &entries[i];
            }
            if at.parent == id {
                out.push((e.id(), [new, &e.point[old.len()..]].concat()));
            }
        }
        out
    }
    /// Whether taking mount `e` away would leave the lower filesystem's
    /// own mount showing (see [`Target::boot`]): one from start-up not yet
    /// made movable, or one on a mount of the lower filesystem's files at a
    /// place where that filesystem has another mount.
    fn stays(&self, entries: &[Entry], e: &Entry) -> bool {
        if !e.runtime() {
            return true;
        }
        let Some(parent) = entries
            .iter()
            .find(|p| p.id() == e.parent && p.id() != e.id())
        else {
            return false;
        };
        if parent.memory().is_some() {
            return false;
        }
        let at = parent.inside(&e.point);
        at != parent.root && self.table.lower_points.contains(&at)
    }
    /// Makes the mounts from start-up movable (`pivot_root`): each becomes
    /// a mount of the lower filesystem's files where it is, as a bind
    /// mount of them is, and the lower filesystem from its root goes below
    /// the namespace's root, hidden, numbered as the root's parent is shown
    /// (Linux's rootfs).
    fn materialize(entries: &mut Vec<Entry>, numbers: &Arc<Numbers>) {
        if entries.iter().any(|e| e.hidden) {
            return;
        }
        let Some(Entry {
            parent,
            backing: Backing::Boot { kind, device },
            ..
        }) = entries.first().cloned()
        else {
            return;
        };
        for e in entries.iter_mut() {
            if let Backing::Boot { kind, device } = e.backing {
                e.backing = Backing::Lower {
                    kind,
                    device,
                    base: e.point.clone(),
                };
                e.root.clone_from(&e.point);
            }
        }
        entries.insert(
            0,
            Entry {
                token: Token::new(parent, numbers, None, Arc::default()),
                parent,
                point: b"/".to_vec(),
                backing: Backing::Boot { kind, device },
                root: b"/".to_vec(),
                flags: mount_flags::RELATIME,
                locks: 0,
                locked: false,
                source: Vec::new(),
                group: 0,
                master: 0,
                unbindable: false,
                hidden: true,
            },
        );
    }
    /// What `umount2` and `mount` find at the resolved `path` (whose last
    /// symbolic link is not followed).
    pub fn target(&self, path: &[u8]) -> Result<Target, Errno> {
        self.target_crossing(path, false)
    }
    /// [`Self::target`] as `umount2` looks it up (`LOOKUP_MOUNTPOINT`):
    /// stepping into a mount on where the path starts too, as a mount on
    /// the root or on the working directory.
    pub fn umount_target(&self, path: &[u8]) -> Result<Target, Errno> {
        self.target_crossing(path, true)
    }
    fn target_crossing(&self, path: &[u8], start: bool) -> Result<Target, Errno> {
        let entries = self.table.snapshot();
        let loc = self.walk_keeping(&entries, path, false, false, true)?;
        let loc = if start {
            self.cross(&entries, loc)
        } else {
            loc
        };
        let e = self.entry(&entries, &loc);
        Ok(self.target_entry(&entries, e, e.point == loc.path))
    }
    /// What [`Self::target`] finds of the mount numbered `id`, at its root,
    /// while this table has it.
    #[must_use]
    pub fn target_of(&self, id: u64) -> Option<Target> {
        let entries = self.table.snapshot();
        let e = entries.iter().find(|e| e.id() == id && !e.hidden)?;
        Some(self.target_entry(&entries, e, true))
    }
    fn target_entry(&self, entries: &[Entry], e: &Entry, root: bool) -> Target {
        let id = e.id();
        Target {
            id,
            root,
            boot: self.stays(entries, e),
            namespace_root: entries
                .get(Self::root_index(entries))
                .is_some_and(|root| root.id() == id),
            locked: e.locked,
            covered: entries.iter().any(|c| c.parent == id && c.id() != id),
            owner: e.memory().and_then(|sb| sb.owner.clone()),
            flags: e.flags,
            locks: e.locks,
            kind: match &e.backing {
                Backing::Boot { kind, .. } | Backing::Lower { kind, .. } => kind,
                Backing::Memory(_) => "tmpfs",
            },
            settings: e.memory().map(|sb| lock(&sb.settings).clone()),
            read_only: e.read_only(),
        }
    }
    /// Mounts `new` on the directory at the resolved `path`, on top of what
    /// is there (`do_add_mount`): `ENOTDIR` for another file.
    pub fn mount(&self, path: &[u8], new: NewTmpfs) -> Result<(), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        if self.lstat(&entries, &loc)?.mode & S_IFMT != S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        let parent = self.entry(&entries, &loc);
        let mut entry = self.new_entry(new, parent.id(), loc.path);
        // `attach_recursive_mnt`: a mount on a shared one is shared too.
        if parent.group != 0 {
            entry.group = self.table.new_group();
        }
        self.table.update(|entries| {
            entries.push(entry);
            Ok(())
        })
    }
    /// `fsmount`: a mount of the new tmpfs `new` in a detached tree of its
    /// own, as [`Self::clone_tree`] makes one, named by the path this gives
    /// and kept while the [`MountPin`] this gives, or another on it, lasts;
    /// and its ID.
    pub fn mount_detached(&self, new: NewTmpfs) -> Result<(Vec<u8>, MountPin, u64), Errno> {
        self.swept();
        let mut entry = self.new_entry(new, 0, Vec::new());
        let id = entry.id();
        entry.parent = id;
        entry.point = [&b"/\0"[..], id.to_string().as_bytes()].concat();
        let point = entry.point.clone();
        let pin = MountPin::new(&entry.token, false);
        self.table.update(|entries| {
            entries.push(entry);
            Ok(())
        })?;
        Ok((point, pin, id))
    }
    /// A mount of a new superblock for `new` at `point` on mount `parent`.
    fn new_entry(&self, new: NewTmpfs, parent: u64, point: Vec<u8>) -> Entry {
        let numbers = &self.table.numbers;
        let minor = Numbers::take(&numbers.minors, 1);
        let state = Arc::new(SuperState::default());
        state.read_only.store(new.read_only, Ordering::SeqCst);
        let sb = Arc::new(Superblock {
            fs: Arc::new(new.fs),
            minor,
            numbers: Arc::clone(numbers),
            settings: Mutex::new(new.settings),
            owner: new.owner,
        });
        Entry {
            token: Token::new(
                Numbers::take(&numbers.ids, 21),
                numbers,
                Some(Arc::clone(&sb)),
                state,
            ),
            parent,
            point,
            backing: Backing::Memory(sb),
            root: b"/".to_vec(),
            flags: new.flags,
            locks: 0,
            locked: false,
            source: new.source,
            group: 0,
            master: 0,
            unbindable: false,
            hidden: false,
        }
    }
    /// The copies `__do_loopback` makes of the mount at `from` to go at `at`
    /// on mount `parent`: of the mount, rooted there (`clone_mnt`), a peer
    /// of it and a slave of its master, not locked; with `recurse`
    /// (`copy_tree`) the mounts below it too, each still locked if it
    /// was, but for unbindable ones and what is on them (`EPERM` for a
    /// locked one). An unbindable mount is `EINVAL`, and without `recurse`
    /// a locked one below it too (`has_locked_children`).
    fn copies(
        &self,
        entries: &[Entry],
        from: &Loc,
        parent: u64,
        at: &[u8],
        recurse: bool,
    ) -> Result<Vec<Entry>, Errno> {
        let old = self.entry(entries, from);
        if old.unbindable {
            return Err(Errno::EINVAL);
        }
        let below =
            |e: &Entry| e.parent == old.id() && e.id() != old.id() && within(&e.point, &from.path);
        if !recurse && entries.iter().any(|e| below(e) && e.locked) {
            return Err(Errno::EINVAL);
        }
        let numbers = &self.table.numbers;
        let top = old.cloned(
            numbers,
            self.backing(entries, from).1,
            parent,
            at.to_vec(),
            false,
        );
        let mut new = vec![Entry {
            locked: false,
            unbindable: false,
            ..top
        }];
        if recurse {
            // Each mount below, its parent's copy before it (`next_mnt`),
            // but for an unbindable one and the mounts on it.
            let mut copies = BTreeMap::from([(old.id(), new[0].id())]);
            let mut queue: Vec<&Entry> = entries.iter().filter(|e| below(e)).rev().collect();
            while let Some(e) = queue.pop() {
                if e.unbindable {
                    if e.locked {
                        return Err(Errno::EPERM);
                    }
                    continue;
                }
                let point = joined(at, &relative(&from.path, &e.point));
                let copy = e.cloned(numbers, e.root.clone(), copies[&e.parent], point, false);
                copies.insert(e.id(), copy.id());
                new.push(copy);
                queue.extend(
                    entries
                        .iter()
                        .filter(|c| c.parent == e.id() && c.id() != e.id())
                        .rev(),
                );
            }
        }
        Ok(new)
    }
    /// Binds what the resolved `source` names onto the resolved `target`
    /// (`do_loopback`), both with their last links followed: a new mount of
    /// the source's mount's file system, rooted there, with that mount's
    /// flags, its source and its type, not locked, a peer of it and a slave
    /// of its master. An unbindable source mount is `EINVAL`. With
    /// `recurse` (`copy_tree`) the mounts below the source come along, each
    /// still locked if it was, but for unbindable ones and what is on them
    /// (`EPERM` for a locked one); without, a locked one below it is
    /// `EINVAL` (`has_locked_children`). A directory goes on a directory, a
    /// file on a file (`graft_tree`, `ENOTDIR`). On a shared mount, the new
    /// mounts are shared too, each in a new peer group if it was in none.
    pub fn bind(&self, source: &[u8], target: &[u8], recurse: bool) -> Result<(), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let from = self.walk(&entries, source, true, false, true)?;
        let to = self.walk(&entries, target, true, false, true)?;
        let parent = self.entry(&entries, &to);
        let mut new = self.copies(&entries, &from, parent.id(), &to.path, recurse)?;
        let directory = |loc: &Loc| -> Result<bool, Errno> {
            Ok(self.lstat(&entries, loc)?.mode & S_IFMT == S_IFDIR)
        };
        if directory(&from)? != directory(&to)? {
            return Err(Errno::ENOTDIR);
        }
        if parent.group != 0 {
            for e in &mut new {
                if e.group == 0 {
                    e.group = self.table.new_group();
                }
                e.unbindable = false;
            }
        }
        self.table.update(|entries| {
            entries.extend(new);
            Ok(())
        })
    }
    /// Takes away each detached tree whose root nothing holds any more, as
    /// the last close of `open_tree`'s descriptor does (`dissolve_on_fput`).
    fn swept(&self) {
        let gone: Vec<u64> = self
            .table
            .snapshot()
            .iter()
            .filter(|e| {
                detached(&e.point) && e.parent == e.id() && e.token.pins.load(Ordering::SeqCst) == 0
            })
            .map(Entry::id)
            .collect();
        for id in gone {
            let _ = self.umount(id, true);
        }
    }
    /// `open_tree` with `OPEN_TREE_CLONE` (`open_detached_copy`): a copy of
    /// the mount at the resolved `source` (its last link followed with
    /// `follow`), with `recurse` (`AT_RECURSIVE`) the mounts below it too,
    /// as `__do_loopback` makes for a bind mount, in a tree of its own that
    /// no path of the namespace reaches and no list shows (Linux's
    /// anonymous mount namespace). It is named by the path this gives,
    /// which a walk takes into it, and kept while the [`MountPin`] this
    /// gives, or any other on its root, lasts; [`Self::move_mount`]
    /// attaches it.
    pub fn clone_tree(
        &self,
        source: &[u8],
        follow: bool,
        recurse: bool,
    ) -> Result<(Vec<u8>, MountPin), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let from = self.walk(&entries, source, follow, false, true)?;
        let mut new = self.copies(&entries, &from, 0, b"/", recurse)?;
        let id = new[0].id();
        let point = [&b"/\0"[..], id.to_string().as_bytes()].concat();
        for e in &mut new {
            e.point = joined(&point, &e.point);
        }
        new[0].parent = id;
        let pin = MountPin::new(&new[0].token, false);
        self.table.update(|entries| {
            entries.extend(new);
            Ok(())
        })?;
        Ok((point, pin))
    }
    /// `move_mount` with `MOVE_MOUNT_SET_GROUP` (`do_set_group`): the
    /// mount at the resolved `to` joins the peer group, and takes the
    /// master, of the mount at the resolved `from`. Both must be mounts of
    /// the namespace (`EINVAL`, `may_change_propagation`) at their roots
    /// (`EINVAL`), of one superblock, `to`'s root at or below `from`'s,
    /// with no locked mount of `from` in its place; `to` must be private
    /// and `from` shared or a slave (`EINVAL`).
    pub fn set_group(
        &self,
        from: &[u8],
        follow_from: bool,
        to: &[u8],
        follow_to: bool,
    ) -> Result<(), Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let from_loc = self.walk(&entries, from, follow_from, false, true)?;
        let to_loc = self.walk(&entries, to, follow_to, false, true)?;
        let (a, b) = (
            self.entry(&entries, &from_loc),
            self.entry(&entries, &to_loc),
        );
        if detached(&a.point) || detached(&b.point) {
            return Err(Errno::EINVAL);
        }
        if a.point != from_loc.path || b.point != to_loc.path {
            return Err(Errno::EINVAL);
        }
        let same = match (&a.backing, &b.backing) {
            (Backing::Memory(x), Backing::Memory(y)) => Arc::ptr_eq(x, y),
            (Backing::Memory(_), _) | (_, Backing::Memory(_)) => false,
            (
                Backing::Boot { device: x, .. } | Backing::Lower { device: x, .. },
                Backing::Boot { device: y, .. } | Backing::Lower { device: y, .. },
            ) => x == y,
        };
        if !same || !within(&b.root, &a.root) {
            return Err(Errno::EINVAL);
        }
        if entries.iter().any(|c| {
            c.parent == a.id()
                && c.id() != a.id()
                && c.locked
                && within(&a.inside(&c.point), &b.root)
        }) {
            return Err(Errno::EINVAL);
        }
        if b.group != 0 || b.master != 0 || b.unbindable {
            return Err(Errno::EINVAL);
        }
        if a.group == 0 && a.master == 0 {
            return Err(Errno::EINVAL);
        }
        let (group, master, id) = (a.group, a.master, b.id());
        self.table.update(|entries| {
            if let Some(e) = entries.iter_mut().find(|e| e.id() == id) {
                e.group = group;
                e.master = master;
            }
            Ok(())
        })
    }
    /// The ID of the mount `path` resolves to (its nearest directory that
    /// is there, for one that is not), leaving the expiry marks.
    fn mount_of(&self, entries: &[Entry], path: &[u8]) -> u64 {
        let mut path = path.to_vec();
        loop {
            if let Ok(loc) = self.walk_keeping(entries, &path, true, true, true) {
                return self.id_of(entries, &loc);
            }
            if path.len() <= 1 {
                return self.id_of(entries, &Self::start(entries));
            }
            path = parent_path(&path);
        }
    }
    /// The entry numbered `id`, if this table has it (the root's parent,
    /// before a `pivot_root`, it has not).
    fn by_id(entries: &[Entry], id: u64) -> Option<&Entry> {
        entries.iter().find(|e| e.id() == id)
    }
    /// Whether the mount `from`, going up from mount `mount` at `path`
    /// through each mount's parent, is reached at or below `at`
    /// (`is_path_reachable`).
    fn reachable<'a>(
        entries: &'a [Entry],
        mut mount: &'a Entry,
        mut path: Vec<u8>,
        from: &Entry,
        at: &[u8],
    ) -> bool {
        while mount.id() != from.id() {
            match Self::by_id(entries, mount.parent).filter(|p| !p.hidden && p.id() != mount.id()) {
                Some(parent) => {
                    path.clone_from(&mount.point);
                    mount = parent;
                }
                None => return false,
            }
        }
        within(&path, at)
    }
    /// `MS_MOVE` (`do_move_mount`, Linux master's order): the resolved
    /// `source` is a mount's root (`EINVAL`), a directory goes on a
    /// directory and a file on a file (`EINVAL`), and the mount on top at
    /// the resolved `target` takes it. The namespace's root, a locked
    /// mount and one on a shared mount are `EINVAL`; a tree with an
    /// unbindable mount onto a shared one is `EINVAL`, and onto itself or
    /// a mount on it `ELOOP`. A mount the lower filesystem shows where it
    /// is ([`Target::boot`]) is not supported (`EOPNOTSUPP`). The mount and
    /// those on it move with their mount points, made shared on a shared
    /// mount (`attach_recursive_mnt`). Each of `paths`, a root or a working
    /// directory from the machine's root, comes back where it now is.
    pub fn move_mount(
        &self,
        source: &[u8],
        target: &[u8],
        paths: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, Errno> {
        self.move_mount_following(source, true, target, true, paths)
    }
    /// [`Self::move_mount`] with the last links of `source` and `target`
    /// followed or not (`move_mount`'s `MOVE_MOUNT_F_SYMLINKS` and
    /// `MOVE_MOUNT_T_SYMLINKS`). The root of a detached tree
    /// ([`Self::clone_tree`]) is attached there, onto a mount of the
    /// namespace (`EINVAL` onto its own tree); another mount of one is
    /// `EINVAL` (`anon_ns_root`), and a mount of the namespace goes onto
    /// none (`EINVAL`).
    pub fn move_mount_following(
        &self,
        source: &[u8],
        follow_source: bool,
        target: &[u8],
        follow_target: bool,
        paths: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let from = self.walk(&entries, source, follow_source, false, true)?;
        let old = self.entry(&entries, &from);
        if old.point != from.path {
            return Err(Errno::EINVAL);
        }
        let to = self.walk(&entries, target, follow_target, false, true)?;
        let directory = |loc: &Loc| -> Result<bool, Errno> {
            Ok(self.lstat(&entries, loc)?.mode & S_IFMT == S_IFDIR)
        };
        if directory(&from)? != directory(&to)? {
            return Err(Errno::EINVAL);
        }
        let dest = self.entry(&entries, &to);
        if detached(&old.point) {
            let tree = old.point.split(|b| *b == b'/').nth(1).unwrap_or_default();
            if old.parent != old.id() || dest.point.split(|b| *b == b'/').nth(1) == Some(tree) {
                return Err(Errno::EINVAL);
            }
        } else {
            let root = &entries[Self::root_index(&entries)];
            if old.id() == root.id() || old.locked {
                return Err(Errno::EINVAL);
            }
            if Self::by_id(&entries, old.parent).is_some_and(|p| p.group != 0 && p.id() != old.id())
            {
                return Err(Errno::EINVAL);
            }
            if detached(&dest.point) {
                return Err(Errno::EINVAL);
            }
        }
        let moving = Self::tree(&entries, old.id(), true);
        let has = |id: &u64| Self::by_id(&entries, *id);
        if dest.group != 0 && moving.iter().filter_map(has).any(|e| e.unbindable) {
            return Err(Errno::EINVAL);
        }
        let mut up = Some(dest);
        while let Some(at) = up {
            if at.id() == old.id() {
                return Err(ELOOP);
            }
            up = Self::by_id(&entries, at.parent).filter(|p| p.id() != at.id());
        }
        if self.stays(&entries, old) {
            return Err(Errno::EOPNOTSUPP);
        }
        let (id, point, parent) = (old.id(), old.point.clone(), dest.id());
        let shared = dest.group != 0;
        let mut fresh = Vec::new();
        if shared {
            for e in moving.iter().filter_map(has).filter(|e| e.group == 0) {
                fresh.push((e.id(), self.table.new_group()));
            }
        }
        let placed = paths
            .iter()
            .map(|p| {
                if moving.contains(&self.mount_of(&entries, p)) {
                    joined(&to.path, &relative(&point, p))
                } else {
                    p.clone()
                }
            })
            .collect();
        self.table.update(|entries| {
            for e in entries.iter_mut().filter(|e| moving.contains(&e.id())) {
                e.point = joined(&to.path, &relative(&point, &e.point));
                if let Some((_, group)) = fresh.iter().find(|(id, _)| *id == e.id()) {
                    e.group = *group;
                }
                if e.id() == id {
                    e.parent = parent;
                }
            }
            Ok(())
        })?;
        Ok(placed)
    }
    /// `pivot_root` (`path_pivot_root`, Linux master's order), with the
    /// resolved `new` root, `put_old` and the caller's `root`, each from the
    /// machine's root: a shared mount at `put_old`, under `new` or under the
    /// root is `EINVAL`, a locked `new` too; `new` or `put_old` on the
    /// root's mount `EBUSY`; then the root and `new` must be mounts' roots
    /// (`EINVAL`), `put_old` at or below `new`, and `new` below the root
    /// (`EINVAL`). The mount of `new` and those on it take the root's
    /// place, and the root's mount with the rest of its tree goes on
    /// `put_old`, `new` taking over its lock (`MNT_LOCKED`). Each of
    /// `paths` comes back where it now is, the root itself staying the
    /// root (`chroot_fs_refs`).
    pub fn pivot_root(
        &self,
        new: &[u8],
        put_old: &[u8],
        root: &[u8],
        paths: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, Errno> {
        self.swept();
        let entries = self.table.snapshot();
        let new_loc = self.walk(&entries, new, true, false, true)?;
        let old_loc = self.walk(&entries, put_old, true, false, true)?;
        let root_loc = self.walk(&entries, root, true, false, true)?;
        let new_mnt = self.entry(&entries, &new_loc);
        let old_mnt = self.entry(&entries, &old_loc);
        let root_mnt = self.entry(&entries, &root_loc);
        let shared = |id: u64| Self::by_id(&entries, id).is_some_and(|e| e.group != 0);
        if old_mnt.group != 0 || shared(new_mnt.parent) || shared(root_mnt.parent) {
            return Err(Errno::EINVAL);
        }
        if new_mnt.locked {
            return Err(Errno::EINVAL);
        }
        if new_mnt.id() == root_mnt.id() || old_mnt.id() == root_mnt.id() {
            return Err(EBUSY);
        }
        if root_loc.path != root_mnt.point || new_loc.path != new_mnt.point {
            return Err(Errno::EINVAL);
        }
        if !Self::reachable(
            &entries,
            old_mnt,
            old_loc.path.clone(),
            new_mnt,
            &new_loc.path,
        ) || !Self::reachable(
            &entries,
            new_mnt,
            new_loc.path.clone(),
            root_mnt,
            &root_loc.path,
        ) {
            return Err(Errno::EINVAL);
        }
        let new_tree = Self::tree(&entries, new_mnt.id(), true);
        let old_tree: Vec<u64> = Self::tree(&entries, root_mnt.id(), true)
            .into_iter()
            .filter(|id| !new_tree.contains(id))
            .collect();
        let (n, r) = (new_mnt.point.clone(), root_mnt.point.clone());
        let put = joined(&r, &relative(&n, &old_loc.path));
        let place = |p: &[u8], id: u64| {
            if new_tree.contains(&id) {
                joined(&r, &relative(&n, p))
            } else if old_tree.contains(&id) {
                joined(&put, &relative(&r, p))
            } else {
                p.to_vec()
            }
        };
        let placed = paths
            .iter()
            .map(|p| {
                if *p == root_loc.path {
                    p.clone()
                } else {
                    place(p, self.mount_of(&entries, p))
                }
            })
            .collect();
        let (new_id, root_id, old_id) = (new_mnt.id(), root_mnt.id(), old_mnt.id());
        let (root_parent, root_locked) = (root_mnt.parent, root_mnt.locked);
        let numbers = Arc::clone(&self.table.numbers);
        self.table.update(|entries| {
            Self::materialize(entries, &numbers);
            for e in entries.iter_mut() {
                let id = e.id();
                e.point = place(&e.point, id);
                if id == new_id {
                    e.parent = root_parent;
                    e.locked |= root_locked;
                } else if id == root_id {
                    e.parent = old_id;
                    e.locked = false;
                }
            }
            Ok(())
        })?;
        Ok(placed)
    }
    /// Unmounts the tmpfs mount `id` (`umount_tree`): with `detach` it and
    /// every mount on it go at once, its open files staying usable;
    /// without, a mount in use or with others on it is `EBUSY`
    /// (`propagate_mount_busy`). Each is made private as it goes.
    pub fn umount(&self, id: u64, detach: bool) -> Result<(), Errno> {
        let gone = self.table.update(|entries| {
            let i = Self::runtime_index(entries, id).ok_or(Errno::EINVAL)?;
            if !detach
                && (entries.iter().any(|e| e.parent == id)
                    || entries[i].token.pins.load(Ordering::SeqCst) != 0)
            {
                return Err(EBUSY);
            }
            let mut gone = BTreeSet::from([id]);
            loop {
                let more: Vec<u64> = entries
                    .iter()
                    .filter(|e| gone.contains(&e.parent) && !gone.contains(&e.id()))
                    .map(Entry::id)
                    .collect();
                if more.is_empty() {
                    break;
                }
                gone.extend(more);
            }
            let left: Vec<(u64, u64)> = entries
                .iter()
                .filter(|e| gone.contains(&e.id()))
                .map(|e| (e.group, e.master))
                .collect();
            let told: Vec<u64> = Self::tree(entries, id, true)
                .into_iter()
                .filter(|id| entries.iter().any(|e| e.id() == *id && !detached(&e.point)))
                .collect();
            entries.retain(|e| !gone.contains(&e.id()));
            Ok((left, told))
        })?;
        let (left, told) = gone;
        for (group, master) in left {
            self.table.numbers.left(group, master);
        }
        let hook = lock(&self.table.unmount_hook).clone();
        if let Some(hook) = hook
            && !told.is_empty()
        {
            hook(&told);
        }
        Ok(())
    }
    /// `MNT_EXPIRE` of mount `id`, not in use and with no mounts on it
    /// (else `EBUSY`): the first call marks it and is `EAGAIN`, the next
    /// unmounts it. Nothing clears the mark, where Linux's every use of the
    /// mount does.
    pub fn expire(&self, id: u64) -> Result<(), Errno> {
        let marked = self.table.update(|entries| {
            let i = Self::runtime_index(entries, id).ok_or(Errno::EINVAL)?;
            if entries.iter().any(|e| e.parent == id)
                || entries[i].token.pins.load(Ordering::SeqCst) != 0
            {
                return Err(EBUSY);
            }
            Ok(entries[i].token.expiry.swap(true, Ordering::SeqCst))
        })?;
        if !marked {
            return Err(Errno::EAGAIN);
        }
        self.umount(id, false)
    }
    /// The mount `id` and, with `recurse`, every mount on it, in the order
    /// Linux's `next_mnt` takes them: a mount, then each on it in the order
    /// they were made.
    fn tree(entries: &[Entry], id: u64, recurse: bool) -> Vec<u64> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(at) = stack.pop() {
            out.push(at);
            if recurse {
                stack.extend(
                    entries
                        .iter()
                        .filter(|e| e.parent == at && e.id() != at)
                        .map(Entry::id)
                        .rev(),
                );
            }
        }
        out
    }
    /// `do_change_type` of mount `id`, and with `recurse` of each mount on
    /// it (`change_mnt_propagation`). A shared one is in a peer group,
    /// a new one if it was in none (`invent_group_ids`), and is no longer
    /// unbindable. Any other type takes it out of its peer group: its
    /// slaves then follow a peer, or with none left its own master, which
    /// a slave then follows too; a private or an unbindable one has no
    /// master.
    pub fn change_type(&self, id: u64, kind: Propagation, recurse: bool) -> Result<(), Errno> {
        self.swept();
        let numbers = &self.table.numbers;
        let ids = Self::tree(&self.table.snapshot(), id, recurse);
        for id in ids {
            let mut left = None;
            let fresh = (kind == Propagation::Shared)
                .then(|| {
                    let entries = self.table.snapshot();
                    let e = entries.iter().find(|e| e.id() == id)?;
                    (e.group == 0).then(|| self.table.new_group())
                })
                .flatten();
            self.table.update(|entries| {
                let peers = |group: u64| {
                    group != 0 && entries.iter().filter(|e| e.group == group).count() > 1
                };
                let Some(at) = entries.iter().position(|e| e.id() == id) else {
                    return Ok(());
                };
                let group = entries[at].group;
                let alone = !peers(group);
                let e = &mut entries[at];
                if kind == Propagation::Shared {
                    if let Some(fresh) = fresh {
                        e.group = fresh;
                    }
                    e.unbindable = false;
                    return Ok(());
                }
                // The master it then has: a peer, or its own.
                let mut master = e.master;
                if group != 0 {
                    e.group = 0;
                    if alone {
                        left = Some((group, e.master));
                    } else {
                        master = group;
                    }
                }
                match kind {
                    Propagation::Slave => e.master = master,
                    _ => {
                        e.master = 0;
                        e.unbindable = kind == Propagation::Unbindable;
                    }
                }
                Ok(())
            })?;
            if let Some((group, master)) = left {
                numbers.left(group, master);
            }
        }
        Ok(())
    }
    /// `mount_setattr`'s change of mount `id` and, with `recurse`, of each
    /// mount on it (`mount_setattr_prepare`, then `mount_setattr_commit`):
    /// each one's flags lose `clear` and gain `set`; one whose locked flags
    /// would change is `EPERM` (`can_change_locked_flags`), and one made
    /// read-only with a file open for writing on it `EBUSY`
    /// (`mnt_hold_writers`), changing none. Then each takes `propagation`,
    /// as [`Self::change_type`] gives it. A mount of a detached tree but
    /// for its root is `EINVAL` (`anon_ns_root`). Setting `NOSYMFOLLOW` on
    /// a mount without it is not supported (`EOPNOTSUPP`).
    pub fn set_attributes(
        &self,
        id: u64,
        recurse: bool,
        clear: u32,
        set: u32,
        propagation: Option<Propagation>,
    ) -> Result<(), Errno> {
        use mount_flags::*;
        self.swept();
        let entries = self.table.snapshot();
        let e = Self::by_id(&entries, id).ok_or(Errno::EINVAL)?;
        if detached(&e.point) && e.parent != e.id() {
            return Err(Errno::EINVAL);
        }
        let ids = Self::tree(&entries, id, recurse);
        let mut changed = Vec::with_capacity(ids.len());
        for at in &ids {
            let Some(m) = Self::by_id(&entries, *at) else {
                continue;
            };
            let flags = (m.flags & !clear | set) & SETTABLE;
            for (lock, flag) in [
                (LOCK_READONLY, READONLY),
                (LOCK_NODEV, NODEV),
                (LOCK_NOSUID, NOSUID),
                (LOCK_NOEXEC, NOEXEC),
            ] {
                if m.locks & lock != 0 && flags & flag == 0 {
                    return Err(Errno::EPERM);
                }
            }
            if m.locks & LOCK_ATIME != 0 && m.flags & ATIME != flags & ATIME {
                return Err(Errno::EPERM);
            }
            if set & READONLY != 0
                && m.flags & READONLY == 0
                && m.token.writers.load(Ordering::SeqCst) != 0
            {
                return Err(EBUSY);
            }
            changed.push((*at, flags, m.flags));
        }
        // Setting `MNT_NOSYMFOLLOW`, which no mount here keeps to, is not
        // supported, on any mount of the tree.
        if changed
            .iter()
            .any(|(_, new, old)| new & !old & NOSYMFOLLOW != 0)
        {
            return Err(Errno::EOPNOTSUPP);
        }
        self.table.update(|entries| {
            for (at, flags, _) in &changed {
                if let Some(e) = entries.iter_mut().find(|e| e.id() == *at) {
                    e.flags = *flags;
                }
            }
            Ok(())
        })?;
        if let Some(kind) = propagation {
            self.change_type(id, kind, recurse)?;
        }
        Ok(())
    }
    /// `do_reconfigure_mnt` of mount `id` (`MS_REMOUNT | MS_BIND`): its
    /// flags become `flags`; to make it read-only, no file may be open for
    /// writing on it (`mnt_make_readonly`, `EBUSY`).
    pub fn reconfigure_mount(&self, id: u64, flags: u32) -> Result<(), Errno> {
        self.table.update(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e.id() == id)
                .ok_or(Errno::EINVAL)?;
            if flags & mount_flags::READONLY != 0
                && !e.read_only().mount
                && e.token.writers.load(Ordering::SeqCst) != 0
            {
                return Err(EBUSY);
            }
            e.flags = flags & mount_flags::SETTABLE;
            Ok(())
        })
    }
    /// `reconfigure_super` of mount `id`'s superblock, then its flags
    /// (`do_remount`): to make the superblock read-only, no file may be
    /// open for writing on any of its mounts (`sb_prepare_remount_readonly`,
    /// `EBUSY`); then `configure` checks and makes a tmpfs's new settings
    /// from the old ones (none for the lower file system's) and the blocks
    /// and inodes its files use.
    pub fn reconfigure(
        &self,
        id: u64,
        read_only: bool,
        flags: u32,
        configure: &mut dyn FnMut(InUse<'_>) -> Result<Option<Settings>, Errno>,
    ) -> Result<(), Errno> {
        self.table.update(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e.id() == id)
                .ok_or(Errno::EINVAL)?;
            let state = Arc::clone(&e.token.state);
            if read_only
                && !state.read_only.load(Ordering::SeqCst)
                && state.writers.load(Ordering::SeqCst) != 0
            {
                return Err(EBUSY);
            }
            match e.memory() {
                Some(sb) => {
                    let stats = sb.fs.statfs(b"/")?;
                    let used = stats.blocks.saturating_sub(stats.blocks_free);
                    let files = stats.files.saturating_sub(stats.files_free);
                    let mut settings = lock(&sb.settings);
                    if let Some(new) = configure(Some((&settings, used, files)))? {
                        *settings = new;
                    }
                }
                None => {
                    configure(None)?;
                }
            }
            state.read_only.store(read_only, Ordering::SeqCst);
            e.flags = flags & mount_flags::SETTABLE;
            Ok(())
        })
    }
    /// The peer group nearest along `e`'s masters with a member in this
    /// namespace (`get_dominating_id`), 0 for none.
    fn dominating(&self, entries: &[Entry], e: &Entry) -> u64 {
        let mut group = e.master;
        for _ in 0..64 {
            if group == 0 || entries.iter().any(|m| m.group == group) {
                return group;
            }
            group = self.table.numbers.master_of(group);
        }
        0
    }
}

impl FileSystem for NamespacedFs {
    fn rooted(&self, root: &[u8]) -> Option<Arc<dyn FileSystem>> {
        let view = if root == b"/" {
            Arc::clone(&self.lower)
        } else {
            self.lower.rooted(root)?
        };
        Some(Arc::new(Self {
            lower: Arc::clone(&self.lower),
            view,
            table: Arc::clone(&self.table),
            root: root.to_vec(),
        }))
    }
    fn mounts(&self) -> Vec<MountPoint> {
        self.swept();
        let entries = self.table.snapshot();
        entries
            .iter()
            .filter(|e| !e.hidden && !detached(&e.point))
            .map(|e| {
                let (kind, device, root, common_options, super_options) = match &e.backing {
                    Backing::Boot { kind, device } => {
                        (*kind, *device, b"/".to_vec(), String::new(), String::new())
                    }
                    Backing::Lower { kind, device, base } => (
                        *kind,
                        *device,
                        relative(base, &e.root),
                        String::new(),
                        String::new(),
                    ),
                    Backing::Memory(sb) => {
                        let settings = lock(&sb.settings);
                        (
                            "tmpfs",
                            sb.device(),
                            e.root.clone(),
                            settings.common_options.clone(),
                            settings.super_options.clone(),
                        )
                    }
                };
                // `show_mountinfo`'s optional fields.
                let mut tags = String::new();
                if e.group != 0 {
                    tags.push_str(&format!(" shared:{}", e.group));
                }
                if e.master != 0 {
                    tags.push_str(&format!(" master:{}", e.master));
                    let from = self.dominating(&entries, e);
                    if from != 0 && from != e.master {
                        tags.push_str(&format!(" propagate_from:{from}"));
                    }
                }
                if e.unbindable {
                    tags.push_str(" unbindable");
                }
                MountPoint {
                    path: e.point.clone(),
                    root,
                    kind,
                    id: e.id(),
                    parent: e.parent,
                    device,
                    source: e.source.clone(),
                    options: shown_flags(e.flags),
                    read_only: e.flags & mount_flags::READONLY != 0,
                    super_read_only: e.read_only().superblock,
                    tags,
                    common_options,
                    super_options,
                }
            })
            .collect()
    }
    fn device(&self, path: &[u8]) -> u64 {
        if self.fast() {
            return self.lower.device(path);
        }
        let entries = self.table.snapshot();
        let loc = self.locate(&entries, path);
        match loc.at.and_then(|i| entries[i].memory()) {
            Some(sb) => sb.device(),
            None => self.lower.device(&self.backing(&entries, &loc).1),
        }
    }
    fn mount_id(&self, path: &[u8]) -> u64 {
        let entries = self.table.snapshot();
        if self.fast() {
            return entries[self.table.boot_index(&entries, path)].id();
        }
        let loc = self.locate(&entries, path);
        self.id_of(&entries, &loc)
    }
    fn mount_root(&self, path: &[u8]) -> Vec<u8> {
        let entries = self.table.snapshot();
        if self.fast() {
            return entries[self.table.boot_index(&entries, path)].point.clone();
        }
        let loc = self.locate(&entries, path);
        self.entry(&entries, &loc).point.clone()
    }
    fn mount_pin(&self, path: &[u8]) -> Option<MountPin> {
        if self.fast() {
            return None;
        }
        let entries = self.table.snapshot();
        let loc = self.locate(&entries, path);
        loc.at.map(|i| MountPin::new(&entries[i].token, false))
    }
    /// A boot mount's too, which a remount read-only of it also checks;
    /// while there are only boot mounts, the one whose mount point the
    /// path is under, its links not followed.
    fn mount_writer(&self, path: &[u8], follow: bool) -> Option<MountPin> {
        let entries = self.table.snapshot();
        let token = if self.fast() {
            &entries[self.table.boot_index(&entries, path)].token
        } else {
            let loc = self.walk(&entries, path, follow, false, true).ok()?;
            &self.entry(&entries, &loc).token
        };
        Some(MountPin::new(token, true))
    }
    /// `ST_VALID` and the flags of the mount holding `path`
    /// (`flags_by_mnt`), with `ST_RDONLY` for a read-only superblock.
    fn statfs_flags(&self, path: &[u8]) -> u64 {
        use mount_flags::*;
        let entries = self.table.snapshot();
        let e = match self.walk(&entries, path, true, false, true) {
            Ok(loc) => self.entry(&entries, &loc),
            Err(_) => &entries[0],
        };
        let mut out = 0x20;
        for (flag, bit) in [
            (NOSUID, 0x2),
            (NODEV, 0x4),
            (NOEXEC, 0x8),
            (NOATIME, 0x400),
            (NODIRATIME, 0x800),
            (RELATIME, 0x1000),
            (NOSYMFOLLOW, 0x2000),
        ] {
            if e.flags & flag != 0 {
                out |= bit;
            }
        }
        if e.read_only().mount {
            out |= 1;
        }
        out
    }
    fn any_read_only(&self) -> bool {
        self.table.snapshot().iter().any(|e| e.read_only().mount)
    }
    fn read_only(&self, path: &[u8], follow: bool) -> ReadOnly {
        let entries = self.table.snapshot();
        if !entries.iter().any(|e| e.read_only().mount) {
            return ReadOnly::default();
        }
        // A missing last name is on its directory's mount.
        match self.walk(&entries, path, follow, true, true) {
            Ok(loc) => self.entry(&entries, &loc).read_only(),
            Err(_) => ReadOnly::default(),
        }
    }
    fn memory_path(&self, anchor: &[u8], inode: u64) -> Option<Vec<u8>> {
        if self.fast() {
            return self.view.memory_path(anchor, inode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, anchor, true, false, true).ok()?;
        let (fs, at) = self.backing(&entries, &loc);
        let found = fs.memory_path(&at, inode)?;
        match loc.at.map(|i| &entries[i]) {
            // Reached from the mount's root, which a bind mount may not
            // be its file system's.
            Some(e) => {
                within(&found, &e.root).then(|| joined(&e.point, &relative(&e.root, &found)))
            }
            None => Some(found),
        }
    }
}

impl HostFs for NamespacedFs {
    fn root(&self) -> &[u8] {
        &self.root
    }
    fn open(&self, path: &[u8], flags: u32, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        if self.fast() {
            return self.view.open(path, flags, mode);
        }
        const O_CREAT: u32 = 0o100;
        const O_EXCL: u32 = 0o200;
        const O_DIRECTORY: u32 = 0o200000;
        const O_NOFOLLOW: u32 = 0o400000;
        if flags & (O_CREAT | O_DIRECTORY) == O_CREAT | O_DIRECTORY {
            return Err(Errno::EINVAL);
        }
        let entries = self.table.snapshot();
        if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL
            && self.walk(&entries, path, false, false, true).is_ok()
        {
            return Err(Errno::EEXIST);
        }
        let loc = self.walk(
            &entries,
            path,
            flags & O_NOFOLLOW == 0,
            flags & O_CREAT != 0,
            true,
        )?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.open(&at, flags, mode)
    }
    fn metadata(&self, path: &[u8], follow: bool) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.metadata(path, follow);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        self.lstat(&entries, &loc)
    }
    fn mkdir(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.mkdir(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.mkdir(&at, mode)
    }
    fn make_socket(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.make_socket(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.make_socket(&at, mode)
    }
    fn make_fifo(&self, path: &[u8], mode: u32) -> Result<FileStat, Errno> {
        if self.fast() {
            return self.view.make_fifo(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.make_fifo(&at, mode)
    }
    /// A mount point in this namespace is `EBUSY` to `rmdir` and `unlink`,
    /// as Linux's `vfs_rmdir` and `vfs_unlink` find it
    /// `is_local_mountpoint`.
    fn unlink(&self, path: &[u8], directory: bool) -> Result<(), Errno> {
        if self.fast() {
            return self.view.unlink(path, directory);
        }
        let entries = self.table.snapshot();
        self.trailing_directory(&entries, path)?;
        let loc = self.walk(&entries, path, false, false, false)?;
        if self.covering(&entries, &loc).is_some() {
            return Err(EBUSY);
        }
        let (fs, at) = self.backing(&entries, &loc);
        fs.unlink(&at, directory)
    }
    fn link(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        if self.fast() {
            return self.view.link(old, new);
        }
        let entries = self.table.snapshot();
        let from = self.walk(&entries, old, false, false, true)?;
        let to = self.walk(&entries, new, false, true, false)?;
        if from.at != to.at {
            return Err(EXDEV);
        }
        let (fs, a) = self.backing(&entries, &from);
        let (_, b) = self.backing(&entries, &to);
        fs.link(&a, &b)
    }
    fn symlink(&self, target: &[u8], path: &[u8]) -> Result<(), Errno> {
        if self.fast() {
            return self.view.symlink(target, path);
        }
        validate(target)?;
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, true, false)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.symlink(target, &at)
    }
    fn readlink(&self, path: &[u8]) -> Result<Vec<u8>, Errno> {
        if self.fast() {
            return self.view.readlink(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, false, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.readlink(&at)
    }
    fn rename(&self, old: &[u8], new: &[u8]) -> Result<(), Errno> {
        self.rename_with(old, new, 0)
    }
    /// Across mounts `EXDEV`; of a mount point in this namespace `EBUSY`
    /// (`vfs_rename`'s `is_local_mountpoint`). The mounts below a renamed
    /// directory move with it, and a bind mount of a file it renames
    /// keeps showing that file, as a mount holds its root's dentry.
    fn rename_with(&self, old: &[u8], new: &[u8], flags: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.rename_with(old, new, flags);
        }
        const EXCHANGE: u32 = 2;
        let entries = self.table.snapshot();
        self.trailing_directory(&entries, old)?;
        if flags & EXCHANGE != 0 {
            self.trailing_directory(&entries, new)?;
        }
        let from = self.walk(&entries, old, false, false, false)?;
        let to = self.walk(&entries, new, false, flags & EXCHANGE == 0, false)?;
        if from.at != to.at {
            return Err(EXDEV);
        }
        if self.covering(&entries, &from).is_some() || self.covering(&entries, &to).is_some() {
            return Err(EBUSY);
        }
        let id = self.id_of(&entries, &from);
        let mut moves = self.moved(id, &from.path, &to.path);
        if flags & EXCHANGE != 0 {
            moves.extend(self.moved(id, &to.path, &from.path));
        }
        let (fs, a) = self.backing(&entries, &from);
        let (_, b) = self.backing(&entries, &to);
        fs.rename_with(&a, &b, flags)?;
        let on = self.entry(&entries, &from).clone();
        let mut roots = Vec::new();
        for e in entries.iter().filter(|e| e.runtime() && e.same_files(&on)) {
            let renamed = |old: &[u8], new: &[u8]| {
                (old != b"/" && within(&e.root, old)).then(|| joined(new, &relative(old, &e.root)))
            };
            let root = renamed(&a, &b)
                .or_else(|| (flags & EXCHANGE != 0).then(|| renamed(&b, &a)).flatten());
            if let Some(root) = root {
                roots.push((e.id(), root));
            }
        }
        if !moves.is_empty() || !roots.is_empty() {
            self.table.update(|entries| {
                for (id, point) in moves {
                    if let Some(e) = entries.iter_mut().find(|e| e.id() == id) {
                        e.point = point;
                    }
                }
                for (id, root) in roots {
                    if let Some(e) = entries.iter_mut().find(|e| e.id() == id) {
                        e.root = root;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }
    fn read_dir(&self, path: &[u8]) -> Result<Vec<DirectoryEntry>, Errno> {
        if self.fast() {
            return self.view.read_dir(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.read_dir(&at)
    }
    /// A tmpfs mount's: what it holds, against the size and inodes it
    /// was mounted with (`shmem_statfs`), 0 for those without a limit.
    fn statfs(&self, path: &[u8]) -> Result<FsStats, Errno> {
        if self.fast() {
            return self.view.statfs(path);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        let mut stats = fs.statfs(&at)?;
        if let Some(sb) = loc.at.and_then(|i| entries[i].memory()) {
            let used = stats.blocks - stats.blocks_free;
            let files = stats.files - stats.files_free;
            let settings = lock(&sb.settings);
            stats.blocks = settings.blocks;
            stats.blocks_free = settings.blocks.saturating_sub(used);
            stats.blocks_available = stats.blocks_free;
            stats.files = settings.inodes;
            stats.files_free = settings.inodes.saturating_sub(files);
        }
        Ok(stats)
    }
    fn with_xattrs(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut paludarium_host::Xattrs),
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.with_xattrs(path, follow, f);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.with_xattrs(&at, false, f)
    }
    fn with_attributes(
        &self,
        path: &[u8],
        follow: bool,
        f: &mut dyn FnMut(&mut u32),
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.with_attributes(path, follow, f);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.with_attributes(&at, false, f)
    }
    fn set_mode(&self, path: &[u8], mode: u32) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_mode(path, mode);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, true, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_mode(&at, mode)
    }
    fn set_owner(
        &self,
        path: &[u8],
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_owner(path, follow, uid, gid);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_owner(&at, false, uid, gid)
    }
    fn set_times(
        &self,
        path: &[u8],
        follow: bool,
        atime: Option<i128>,
        mtime: Option<i128>,
    ) -> Result<(), Errno> {
        if self.fast() {
            return self.view.set_times(path, follow, atime, mtime);
        }
        let entries = self.table.snapshot();
        let loc = self.walk(&entries, path, follow, false, true)?;
        let (fs, at) = self.backing(&entries, &loc);
        fs.set_times(&at, false, atime, mtime)
    }
}

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;
