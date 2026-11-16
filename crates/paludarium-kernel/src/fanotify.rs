//! fanotify: `fanotify_init` and `fanotify_mark`, as Linux's
//! `fs/notify/fanotify`. A group's marks are on files (by their device and
//! inode, [`Key`]), on mounts and on file systems (both by the device, as
//! every mount here is a file system of its own), and the machine's
//! [`crate::inotify::Notifier`] tells the groups ([`Registry::dispatch`])
//! what Linux's `fsnotify` hooks tell them: the same events, with the file,
//! its directory and its name where Linux has them. A group queues what its
//! marks want as `fanotify_handle_event` does, merging an event into an
//! earlier one of the same object, and a read gives each as a `struct
//! fanotify_event_metadata` with a descriptor of the file, or with the
//! records of its file handles, its name and the pidfd of the process.
//!
//! Permission events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`,
//! `FAN_OPEN_EXEC_PERM`) are taken by `fanotify_mark` but never sent: what
//! they ask is let through, as no listener answered. `FAN_PRE_ACCESS` is
//! `EOPNOTSUPP`, as no file system here allows pre-content events.
use crate::events::{IN, ReadinessHub};
use crate::page_cache::Key;
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

// The events, as `include/uapi/linux/fanotify.h` numbers them (the same
// bits as `fsnotify`'s).
pub(crate) const ACCESS: u32 = 0x1;
pub(crate) const MODIFY: u32 = 0x2;
pub(crate) const ATTRIB: u32 = 0x4;
const CLOSE_WRITE: u32 = 0x8;
const CLOSE_NOWRITE: u32 = 0x10;
const OPEN: u32 = 0x20;
pub(crate) const MOVED_FROM: u32 = 0x40;
pub(crate) const MOVED_TO: u32 = 0x80;
pub(crate) const CREATE: u32 = 0x100;
pub(crate) const DELETE: u32 = 0x200;
pub(crate) const DELETE_SELF: u32 = 0x400;
pub(crate) const MOVE_SELF: u32 = 0x800;
pub(crate) const OPEN_EXEC: u32 = 0x1000;
/// `FS_UNMOUNT`, which only inotify hears of.
const UNMOUNT: u32 = 0x2000;
const Q_OVERFLOW: u32 = 0x4000;
const FS_ERROR: u32 = 0x8000;
pub(crate) const OPEN_PERM: u32 = 0x1_0000;
pub(crate) const ACCESS_PERM: u32 = 0x2_0000;
pub(crate) const OPEN_EXEC_PERM: u32 = 0x4_0000;
const PRE_ACCESS: u32 = 0x10_0000;
const MNT_ATTACH: u32 = 0x100_0000;
const MNT_DETACH: u32 = 0x200_0000;
pub(crate) const EVENT_ON_CHILD: u32 = 0x800_0000;
pub(crate) const RENAME: u32 = 0x1000_0000;
pub(crate) const ONDIR: u32 = 0x4000_0000;
const CLOSE: u32 = CLOSE_WRITE | CLOSE_NOWRITE;
const MOVE: u32 = MOVED_FROM | MOVED_TO;

// `fanotify_init`'s flags.
const CLOEXEC: u32 = 0x1;
const NONBLOCK: u32 = 0x2;
const CLASS_CONTENT: u32 = 0x4;
const CLASS_PRE_CONTENT: u32 = 0x8;
const UNLIMITED_QUEUE: u32 = 0x10;
const UNLIMITED_MARKS: u32 = 0x20;
const ENABLE_AUDIT: u32 = 0x40;
const REPORT_PIDFD: u32 = 0x80;
const REPORT_TID: u32 = 0x100;
const REPORT_FID: u32 = 0x200;
const REPORT_DIR_FID: u32 = 0x400;
const REPORT_NAME: u32 = 0x800;
const REPORT_TARGET_FID: u32 = 0x1000;
const REPORT_FD_ERROR: u32 = 0x2000;
const REPORT_MNT: u32 = 0x4000;
/// `FANOTIFY_UNPRIV`, the group of a caller without CAP_SYS_ADMIN in the
/// first user namespace: it gives no descriptors, and the IDs of no other
/// process.
const UNPRIV: u32 = 0x8000_0000;

// `fanotify_mark`'s flags.
const MARK_ADD: u32 = 0x1;
const MARK_REMOVE: u32 = 0x2;
const MARK_DONT_FOLLOW: u32 = 0x4;
const MARK_ONLYDIR: u32 = 0x8;
const MARK_MOUNT: u32 = 0x10;
const MARK_IGNORED_MASK: u32 = 0x20;
const MARK_IGNORED_SURV_MODIFY: u32 = 0x40;
const MARK_FLUSH: u32 = 0x80;
const MARK_FILESYSTEM: u32 = 0x100;
const MARK_EVICTABLE: u32 = 0x200;
const MARK_IGNORE: u32 = 0x400;
const MARK_MNTNS: u32 = 0x110;

// `include/linux/fanotify.h`'s sets.
const PATH_EVENTS: u32 = ACCESS | MODIFY | CLOSE | OPEN | OPEN_EXEC;
const DIRENT_EVENTS: u32 = MOVE | CREATE | DELETE | RENAME;
const PERM_EVENTS: u32 = OPEN_PERM | OPEN_EXEC_PERM | ACCESS_PERM | PRE_ACCESS;
const FD_EVENTS: u32 = PATH_EVENTS | PERM_EVENTS;
const INODE_EVENTS: u32 = DIRENT_EVENTS | ATTRIB | MOVE_SELF | DELETE_SELF;
const MOUNT_EVENTS: u32 = MNT_ATTACH | MNT_DETACH;
const EVENTS: u32 = PATH_EVENTS | INODE_EVENTS | FS_ERROR | MOUNT_EVENTS;
const EVENT_FLAGS: u32 = EVENT_ON_CHILD | ONDIR;
const OUTGOING_EVENTS: u32 = EVENTS | PERM_EVENTS | Q_OVERFLOW | ONDIR;
const DIRONLY_EVENT_BITS: u32 = DIRENT_EVENTS | EVENT_ON_CHILD | ONDIR;
const FID_BITS: u32 = REPORT_FID | REPORT_DIR_FID | REPORT_NAME | REPORT_TARGET_FID;
const INFO_MODES: u32 = FID_BITS | REPORT_PIDFD | REPORT_MNT;
const ADMIN_INIT_FLAGS: u32 = CLASS_CONTENT
    | CLASS_PRE_CONTENT
    | REPORT_TID
    | REPORT_PIDFD
    | REPORT_FD_ERROR
    | UNLIMITED_QUEUE
    | UNLIMITED_MARKS;
const USER_INIT_FLAGS: u32 = FID_BITS | REPORT_MNT | CLOEXEC | NONBLOCK;
const INIT_FLAGS: u32 = ADMIN_INIT_FLAGS | USER_INIT_FLAGS;
const MARK_TYPE_BITS: u32 = MARK_MOUNT | MARK_FILESYSTEM;
const MARK_CMD_BITS: u32 = MARK_ADD | MARK_REMOVE | MARK_FLUSH;
const MARK_IGNORE_BITS: u32 = MARK_IGNORED_MASK | MARK_IGNORE;
const MARK_FLAGS: u32 = MARK_TYPE_BITS
    | MARK_CMD_BITS
    | MARK_IGNORE_BITS
    | MARK_DONT_FOLLOW
    | MARK_ONLYDIR
    | MARK_IGNORED_SURV_MODIFY
    | MARK_EVICTABLE;

// `fsnotify`'s sets (`include/linux/fsnotify_backend.h`).
const FS_EVENTS_POSS_ON_CHILD: u32 =
    PERM_EVENTS | ACCESS | MODIFY | ATTRIB | CLOSE | OPEN | OPEN_EXEC;
const ALL_FSNOTIFY_EVENTS: u32 = DIRENT_EVENTS
    | MOUNT_EVENTS
    | FS_EVENTS_POSS_ON_CHILD
    | DELETE_SELF
    | MOVE_SELF
    | UNMOUNT
    | Q_OVERFLOW
    | FS_ERROR;

/// The flags of the descriptors events give that `fanotify_init` takes
/// (`FANOTIFY_INIT_ALL_EVENT_F_BITS`).
const EVENT_F_BITS: u32 =
    3 | 0o2000 | 0o4000 | 0o4_000_000 | 0o10_000 | 0o2_000_000 | O_LARGEFILE | 0o1_000_000;
const O_LARGEFILE: u32 = 0o100_000;
const O_CLOEXEC: u32 = 0o2_000_000;

/// `FAN_NOFD`, `FAN_NOPIDFD`, and `FAN_EPIDFD`.
const NOFD: i32 = -1;
const EPIDFD: i32 = -2;
/// `FANOTIFY_METADATA_VERSION` and `FAN_EVENT_METADATA_LEN`.
const VERSION: u8 = 3;
const METADATA: usize = 24;
/// The info record types.
const INFO_FID: u8 = 1;
const INFO_DFID_NAME: u8 = 2;
const INFO_DFID: u8 = 3;
const INFO_PIDFD: u8 = 4;
const INFO_OLD_DFID_NAME: u8 = 10;
const INFO_NEW_DFID_NAME: u8 = 12;
/// `EXDEV`.
const EXDEV: Errno = Errno(18);
/// `FILEID_INVALID`, a handle that could not be made.
const FILEID_INVALID: u32 = 0xff;

/// `/proc/sys/fs/fanotify` at first: `max_queued_events`,
/// `max_user_groups`, and `max_user_marks` as `fanotify_user_setup` works it
/// out for the memory `sysinfo` reports: 1% of it over what an inode mark
/// costs (twice an inode, about 1264 bytes on x86-64), between 8192 and
/// 1048576.
const MAX_EVENTS: i32 = 16384;
const MAX_GROUPS: u64 = 128;
const MAX_MARKS: u64 = {
    let marks = crate::syscalls::SYSINFO_RAM / 100 / 1264;
    if marks < 8192 {
        8192
    } else if marks > 1_048_576 {
        1_048_576
    } else {
        marks
    }
};

// File systems whose marks Linux restricts.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const SOCKFS_MAGIC: u64 = 0x534F_434B;
const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
const PID_FS_MAGIC: u64 = 0x5049_4446;
const NSFS_MAGIC: u64 = 0x6e73_6673;
const DEVPTS_SUPER_MAGIC: u64 = 0x1cd1;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const SECRETMEM_MAGIC: u64 = 0x5345_4d45;

/// Whether the file system `kind` is one the kernel mounts only for itself
/// (`SB_NOUSER`), which takes no mount or file system mark.
fn internal(kind: u64) -> bool {
    matches!(
        kind,
        PIPEFS_MAGIC | SOCKFS_MAGIC | ANON_INODE_FS_MAGIC | PID_FS_MAGIC | NSFS_MAGIC
    )
}

thread_local! {
    /// The process and thread whose system call runs on this host thread
    /// ([`enter`]): the task an event names, as Linux's `current`.
    static CURRENT: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
}
/// Records, as a system call starts, the process `pid` and thread `tid`
/// it is of.
pub(crate) fn enter(pid: u32, tid: u32) {
    CURRENT.with(|current| current.set((pid, tid)));
}

/// `vfs_get_fsid`, which `statfs` gives as `f_fsid`: the device of the
/// kernel's own file systems, /proc, devpts and mqueue (`simple_statfs`'s
/// `huge_encode_dev(s_dev)`), else a number each file system has of its own,
/// as tmpfs takes it from the UUID it draws when mounted.
pub(crate) fn fsid(c: &Context<'_>, device: u64, kind: u64) -> [u32; 2] {
    if internal(kind)
        || matches!(
            kind,
            PROC_SUPER_MAGIC | DEVPTS_SUPER_MAGIC | MQUEUE_MAGIC | SECRETMEM_MAGIC
        )
    {
        return [device as u32, (device >> 32) as u32];
    }
    let salt = *c.files.caches.notify.fan.salt.get_or_init(|| {
        let mut bytes = [0u8; 8];
        let _ = c.host.random_bytes(&mut bytes);
        u64::from_le_bytes(bytes) | 1
    });
    // A mix of the device into the drawn bits, never all zeros.
    let mut x = salt ^ device.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 31;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 29;
    let fsid = [x as u32, (x >> 32) as u32];
    if fsid == [0, 0] { [1, 0] } else { fsid }
}

/// A file an event names: where it is, its file system (`f_type`), and
/// what it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Object {
    pub(crate) key: Key,
    pub(crate) kind: u64,
    pub(crate) directory: bool,
    pub(crate) regular: bool,
}
impl Object {
    pub(crate) fn of(key: Key, kind: u64, stat: &FileStat) -> Self {
        Self {
            key,
            kind,
            directory: stat.mode & 0o170000 == 0o040000,
            regular: stat.mode & 0o170000 == 0o100000,
        }
    }
    fn handle(self) -> Handle {
        let (kind, bytes) = crate::files::file_handle(self.kind, self.key.0, self.key.1);
        Handle { kind, bytes }
    }
}

/// What opens the file a path event names again, for the descriptor a
/// read gives, with the flags `fanotify_init` gave: Linux's
/// `dentry_open_nonotify` of the event's path, as a description of its own
/// that tells no watch of anything.
pub(crate) type Opener = Arc<dyn Fn(u32) -> Result<Arc<dyn FileHandle>, Errno> + Send + Sync>;

/// An [`Opener`] of the file at `path` in `fs`, which a file the kernel
/// does not keep as a description (a program exec runs) has.
pub(crate) fn path_opener(fs: &Arc<dyn paludarium_vfs::FileSystem>, path: &[u8]) -> Opener {
    let (fs, path) = (Arc::clone(fs), path.to_vec());
    Arc::new(move |flags| crate::page_cache::nonotify(flags, || fs.open(&path, flags, 0)))
}

/// What an event comes with, as `fsnotify`'s data types.
pub(crate) enum Data<'a> {
    /// A path (`FSNOTIFY_EVENT_PATH`): an open file, which a descriptor can
    /// be opened of again, by `opener`, at `path` (where it was then).
    Path {
        object: Object,
        path: Vec<u8>,
        opener: &'a dyn Fn() -> Opener,
    },
    /// A file without a path (`FSNOTIFY_EVENT_DENTRY` and `_INODE`).
    Inode(Object),
    /// A rename's file, moved to the directory `dir` as `name`
    /// (`FSNOTIFY_EVENT_RENAME`).
    Rename {
        moved: Object,
        dir: Object,
        name: &'a [u8],
    },
}
impl Data<'_> {
    fn object(&self) -> Object {
        match self {
            Data::Path { object, .. } | Data::Inode(object) => *object,
            Data::Rename { moved, .. } => *moved,
        }
    }
}

/// The marks of the groups of one machine, which every change is told to.
#[derive(Default)]
pub(crate) struct Registry {
    /// `/proc/sys/fs/fanotify`.
    pub(crate) limits: Limits,
    /// The marks of every group: while there are none, a change is not
    /// looked at.
    marks: AtomicUsize,
    /// The groups, out of sight of the types the machine's file system
    /// holds, whose `Send` the compiler would otherwise follow too deep.
    groups: Mutex<Vec<Weak<dyn Grouped>>>,
    /// The groups and marks of each effective user ID, as Linux's
    /// `ucounts` count them against the limits.
    users: Mutex<HashMap<u32, (u64, u64)>>,
    /// What each file system's `f_fsid` is drawn from.
    salt: OnceLock<u64>,
}

/// The machine's limits of `/proc/sys/fs/fanotify`.
pub(crate) struct Limits {
    pub(crate) groups: AtomicU64,
    pub(crate) marks: AtomicU64,
    pub(crate) events: AtomicI32,
    /// `watchdog_timeout`, which only the permission events no listener
    /// answers would have been watched by.
    pub(crate) watchdog: AtomicI32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            groups: AtomicU64::new(MAX_GROUPS),
            marks: AtomicU64::new(MAX_MARKS),
            events: AtomicI32::new(MAX_EVENTS),
            watchdog: AtomicI32::new(0),
        }
    }
}

/// A [`Group`], as the registry holds it.
trait Grouped: Send + Sync {
    fn group(self: Arc<Self>) -> Arc<Group>;
}
impl Grouped for Group {
    fn group(self: Arc<Self>) -> Arc<Group> {
        self
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a group's marks are on (`FSNOTIFY_OBJ_TYPE_*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    Inode(Key),
    Mount(u64),
    FileSystem(u64),
    /// A mount namespace, by its inode, which only mount events (never
    /// sent here) are of.
    Namespace(u64),
}

/// The kinds of marks an event looks at, in the order `fsnotify`'s
/// iterator takes them (`FSNOTIFY_ITER_TYPE_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Iter {
    Inode = 0,
    Mount = 1,
    FileSystem = 2,
    Parent = 3,
    Inode2 = 4,
}

// The flags of a mark (`FSNOTIFY_MARK_FLAG_*`).
const IGNORED_SURV_MODIFY: u32 = 0x1;
const NO_IREF: u32 = 0x2;
const HAS_IGNORE_FLAGS: u32 = 0x4;
const HAS_FSID: u32 = 0x8;
const WEAK_FSID: u32 = 0x10;

struct Mark {
    target: Target,
    mask: u32,
    ignore: u32,
    flags: u32,
    fsid: [u32; 2],
    /// The file system (`f_type`) and the type of the file it is on.
    kind: u64,
    directory: bool,
}
impl Mark {
    /// `fsnotify_ignore_mask`: the ignore mask with the flags that apply
    /// it, which a mark without `FAN_MARK_IGNORE` takes from its own mask.
    fn ignore_mask(&self) -> u32 {
        if self.flags & HAS_IGNORE_FLAGS != 0 {
            return self.ignore;
        }
        (self.ignore | ONDIR) & !EVENT_ON_CHILD | self.mask & EVENT_ON_CHILD
    }
    /// `fsnotify_effective_ignore_mask`.
    fn effective_ignore(&self, is_dir: bool, iter: Iter) -> u32 {
        let ignore = self.ignore & ALL_FSNOTIFY_EVENTS;
        if ignore == 0 {
            return 0;
        }
        if !is_dir && iter != Iter::Parent {
            return ignore;
        }
        let ignore = self.ignore_mask();
        if !applicable(ignore, is_dir, iter) {
            return 0;
        }
        ignore & ALL_FSNOTIFY_EVENTS
    }
    /// `fsnotify_calc_mask`: what the object it is on must be told of.
    fn calc(&self) -> u32 {
        if self.ignore & ALL_FSNOTIFY_EVENTS == 0 {
            return self.mask;
        }
        let modify = if self.flags & IGNORED_SURV_MODIFY == 0 {
            MODIFY
        } else {
            0
        };
        self.mask | modify | self.ignore
    }
    /// The device of the file system it is in.
    fn device(&self) -> u64 {
        match self.target {
            Target::Inode((device, _)) | Target::Mount(device) | Target::FileSystem(device) => {
                device
            }
            Target::Namespace(_) => crate::namespaces::DEVICE,
        }
    }
    /// `fanotify_mark_user_flags`, which fdinfo shows.
    fn user_flags(&self) -> u32 {
        let mut flags = 0;
        if self.flags & IGNORED_SURV_MODIFY != 0 {
            flags |= MARK_IGNORED_SURV_MODIFY;
        }
        if self.flags & NO_IREF != 0 {
            flags |= MARK_EVICTABLE;
        }
        if self.flags & HAS_IGNORE_FLAGS != 0 {
            flags |= MARK_IGNORE;
        }
        flags
    }
}
/// `fsnotify_mask_applicable`.
fn applicable(mask: u32, is_dir: bool, iter: Iter) -> bool {
    !(is_dir && mask & ONDIR == 0 || iter == Iter::Parent && mask & EVENT_ON_CHILD == 0)
}

/// A file handle, as `exportfs_encode_fid` makes it.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Handle {
    kind: u32,
    bytes: Vec<u8>,
}

enum Body {
    /// `fanotify_path_event`: the file, which a read opens again.
    Path {
        key: Key,
        path: Vec<u8>,
        opener: Opener,
    },
    /// `fanotify_fid_event`.
    Fid {
        fsid: [u32; 2],
        object: Handle,
    },
    /// `fanotify_name_event`: the directory and the name, the new ones of a
    /// rename, and the file's own handle.
    Name {
        fsid: [u32; 2],
        dir: Option<Handle>,
        name: Vec<u8>,
        dir2: Option<Handle>,
        name2: Vec<u8>,
        file: Option<Handle>,
    },
    Overflow,
}

struct Event {
    mask: u32,
    /// The task, by its ID in the emulator; 0 for the overflow event.
    pid: u32,
    body: Body,
    /// A permission event's number in its group's answers ([`Answer`]).
    perm: Option<u64>,
}
impl Event {
    /// `fanotify_should_merge`.
    fn merges(&self, new: &Event) -> bool {
        if self.pid != new.pid
            || self.mask & ONDIR != new.mask & ONDIR
            || self.mask & RENAME != new.mask & RENAME
        {
            return false;
        }
        match (&self.body, &new.body) {
            (Body::Path { key: a, .. }, Body::Path { key: b, .. }) => a == b,
            (
                Body::Fid {
                    fsid: fa,
                    object: a,
                },
                Body::Fid {
                    fsid: fb,
                    object: b,
                },
            ) => !a.bytes.is_empty() && fa == fb && a == b,
            (
                Body::Name {
                    fsid: fa,
                    dir: da,
                    name: na,
                    dir2: d2a,
                    name2: n2a,
                    file: a,
                },
                Body::Name {
                    fsid: fb,
                    dir: db,
                    name: nb,
                    dir2: d2b,
                    name2: n2b,
                    file: b,
                },
            ) => {
                da.is_some()
                    && fa == fb
                    && da == db
                    && d2a == d2b
                    && a == b
                    && na == nb
                    && n2a == n2b
            }
            _ => false,
        }
    }
    fn object_handle(&self) -> Option<&Handle> {
        match &self.body {
            Body::Fid { object, .. } if !object.bytes.is_empty() => Some(object),
            Body::Name {
                file: Some(file), ..
            } if !file.bytes.is_empty() => Some(file),
            _ => None,
        }
    }
    /// `fanotify_event_len`.
    fn len(&self, info_mode: u32) -> usize {
        let mut len = METADATA;
        let mut dot = 0;
        match &self.body {
            Body::Name {
                dir,
                name,
                dir2,
                name2,
                ..
            } if dir.is_some() || dir2.is_some() => {
                if let Some(dir) = dir {
                    len += fid_info_len(dir.bytes.len(), name.len());
                }
                if let Some(dir2) = dir2 {
                    len += fid_info_len(dir2.bytes.len(), name2.len());
                }
            }
            _ => {
                if info_mode & REPORT_NAME != 0 && self.mask & ONDIR != 0 {
                    dot = 1;
                }
            }
        }
        if let Some(object) = self.object_handle() {
            len += fid_info_len(object.bytes.len(), dot);
        }
        if info_mode & REPORT_PIDFD != 0 {
            len += 8;
        }
        len
    }
}
/// `fanotify_fid_info_len`: a record's header, its file system ID and
/// handle header, the handle, and the name with its NUL, to 4 bytes.
fn fid_info_len(handle: usize, name: usize) -> usize {
    let name = if name > 0 { name + 1 } else { 0 };
    (20 + handle + name).next_multiple_of(4)
}

struct Queue {
    events: VecDeque<Event>,
    /// Whether the overflow event is queued, which is queued once.
    overflowed: bool,
    /// Events queued so far, each a wakeup of the file.
    epoch: u64,
    max: usize,
    marks: Vec<Mark>,
}

/// A group, the file `fanotify_init` gives.
pub(crate) struct Group {
    registry: Arc<Registry>,
    hub: Arc<ReadinessHub>,
    /// The effective user ID whose limits it counts against.
    owner: u32,
    /// `fanotify_init`'s flags, with `FANOTIFY_UNPRIV`.
    flags: u32,
    /// The flags of the descriptors its events give.
    event_flags: u32,
    status: AtomicU32,
    queue: Mutex<Queue>,
    /// Its permission events by number, from their queueing to their
    /// answer (`access_list` and each event's `state`).
    answers: Mutex<Answers>,
}

/// Where a permission event is (`FAN_EVENT_INIT`, `_REPORTED`,
/// `_ANSWERED`, `_CANCELED`).
#[derive(Clone, Copy)]
enum Answer {
    /// In the queue, not read yet.
    Queued,
    /// Read, with the descriptor a response names it by.
    Reported(i32),
    /// The response.
    Answered(u32),
    /// Read with that descriptor, and the task stopped waiting (a fatal
    /// signal) before an answer, which a response then only ends.
    Canceled(i32),
}
#[derive(Default)]
struct Answers {
    next: u64,
    states: HashMap<u64, Answer>,
}

/// `FAN_ALLOW`, `FAN_DENY` and `FAN_INFO`.
const ALLOW: u32 = 1;
const DENY: u32 = 2;
const INFO_RESPONSE: u32 = 0x20;

thread_local! {
    /// The permission events the file operation this thread runs asks of
    /// each group ([`Group::handle`]), which [`await_answers`] queues and
    /// waits for, group by group, as `fanotify_handle_event` does; `None`
    /// outside an operation that waits ([`asking`]), whose permission
    /// events are let through.
    static ASKED: RefCell<Option<Vec<Asked>>> = const { RefCell::new(None) };
}

/// A permission event asked of a group, not queued yet.
type Asked = (Weak<Group>, Event);

/// Runs `f`, a file operation whose permission events (an open's) are
/// asked of the groups, then waits for their answers ([`await_answers`]):
/// what `f` gives, or the error a group denies it with.
pub(crate) fn asking<T>(
    c: &mut Context<'_>,
    f: impl FnOnce(&mut Context<'_>) -> T,
) -> (T, Result<bool, Errno>) {
    let outer = ASKED.with(|asked| asked.borrow_mut().replace(Vec::new()));
    let result = f(c);
    let asked = ASKED
        .with(|asked| std::mem::replace(&mut *asked.borrow_mut(), outer))
        .unwrap_or_default();
    let answered = await_answers(c, asked);
    (result, answered)
}

/// How many permission events this thread's operation has asked so far,
/// which tells an open whether to hold back its `FAN_OPEN` until they are
/// answered.
pub(crate) fn asked() -> usize {
    ASKED.with(|asked| asked.borrow().as_ref().map_or(0, Vec::len))
}

/// Queues each permission event of `asked` and waits for its answer, the
/// groups of pre-content first, then of content, as `fsnotify` takes them
/// by priority: whether any was asked, or the error the first denial gives.
/// The wait ends only for an answer, the group's close (let through), or a
/// fatal signal (`TASK_KILLABLE`), which leaves the event to its group.
fn await_answers(c: &mut Context<'_>, mut asked: Vec<Asked>) -> Result<bool, Errno> {
    if asked.is_empty() {
        return Ok(false);
    }
    asked.sort_by_key(|(group, _)| {
        group
            .upgrade()
            .map_or(2, |g| u8::from(g.flags & CLASS_PRE_CONTENT == 0))
    });
    for (group, event) in asked {
        let Some(id) = group.upgrade().and_then(|g| g.ask(event)) else {
            continue;
        };
        loop {
            let ticket = c.files.readiness.token.value();
            let Some(strong) = group.upgrade() else {
                break;
            };
            if let Some(answer) = strong.answer(id) {
                answer?;
                break;
            }
            let _ = c.inbox.drain(c.process);
            c.group.drain_process(c.process);
            if fatal(c) {
                strong.cancel(id);
                return Err(Errno(4));
            }
            drop(strong);
            let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
            let end = Some((
                paludarium_host::ClockId::Monotonic,
                now.saturating_add(10_000_000),
            ));
            match c
                .host
                .wait_on(&c.files.readiness.token, ticket, end, c.cancellation)
            {
                Err(e) if e == Errno::ENOSYS => {
                    c.host.wait_until(
                        paludarium_host::ClockId::Monotonic,
                        now.saturating_add(1_000_000),
                        c.cancellation,
                    )?;
                }
                result => {
                    result?;
                }
            }
        }
    }
    Ok(true)
}

/// Whether the task is to die (`fatal_signal_pending`): its group exits, or
/// a signal it does not block or ignore ends it, SIGKILL or one whose
/// default action is to end the process.
fn fatal(c: &Context<'_>) -> bool {
    if c.group.status().is_some() {
        return true;
    }
    let Some(index) = crate::signals::next_pending(c.process, true) else {
        return false;
    };
    let number = c.process.pending[index].number;
    let handler = c
        .process
        .signal_actions
        .get(&number)
        .map_or(0, |action| action.handler);
    number == 9 || handler == 0 && !matches!(number, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

impl Registry {
    /// How many marks there are.
    #[cfg(test)]
    pub(crate) fn marks_count(&self) -> usize {
        self.marks.load(Ordering::SeqCst)
    }
    /// Whether any mark exists, which a change must be told to.
    pub(crate) fn active(&self) -> bool {
        self.marks.load(Ordering::SeqCst) != 0
    }
    fn groups(&self) -> Vec<Arc<Group>> {
        lock(&self.groups)
            .iter()
            .filter_map(Weak::upgrade)
            .map(Grouped::group)
            .collect()
    }
    fn add_group(&self, user: u32) -> Result<(), Errno> {
        let mut users = lock(&self.users);
        let count = users.entry(user).or_default();
        if count.0 >= self.limits.groups.load(Ordering::SeqCst) {
            return Err(Errno::EMFILE);
        }
        count.0 += 1;
        Ok(())
    }
    fn add_mark(&self, user: u32, unlimited: bool) -> Result<(), Errno> {
        if !unlimited {
            let mut users = lock(&self.users);
            let count = users.entry(user).or_default();
            if count.1 >= self.limits.marks.load(Ordering::SeqCst) {
                return Err(Errno::ENOSPC);
            }
            count.1 += 1;
        }
        self.marks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn release(&self, user: u32, marks: u64, counted: bool, group: bool) {
        let mut users = lock(&self.users);
        if let Some(count) = users.get_mut(&user) {
            if counted {
                count.1 -= marks.min(count.1);
            }
            if group {
                count.0 = count.0.saturating_sub(1);
            }
            if *count == (0, 0) {
                users.remove(&user);
            }
        }
        drop(users);
        self.marks.fetch_sub(marks as usize, Ordering::SeqCst);
        if group {
            lock(&self.groups).retain(|g| g.strong_count() > 0);
        }
    }

    /// `fsnotify_inoderemove`'s end of the marks of a file that is gone.
    pub(crate) fn gone(&self, key: Key) {
        for group in self.groups() {
            let removed = {
                let mut queue = group.queue();
                let before = queue.marks.len();
                queue.marks.retain(|m| m.target != Target::Inode(key));
                (before - queue.marks.len()) as u64
            };
            if removed > 0 {
                self.release(
                    group.owner,
                    removed,
                    group.flags & UNLIMITED_MARKS == 0,
                    false,
                );
            }
        }
    }

    /// Whether the directory `dir` watches its children for `mask`, by
    /// any group's mark on it (`fsnotify_inode_watches_children`).
    fn watches_children(&self, groups: &[Arc<Group>], dir: Key, mask: u32) -> bool {
        groups.iter().any(|group| {
            group.queue().marks.iter().any(|m| {
                m.target == Target::Inode(dir) && {
                    let calc = m.calc();
                    calc & EVENT_ON_CHILD != 0 && calc & FS_EVENTS_POSS_ON_CHILD & mask != 0
                }
            })
        })
    }
    /// Whether the marks of a file, of its mount (for a path event) or of
    /// its file system want its directory and name for `mask`
    /// (`fsnotify_event_needs_parent`).
    fn needs_parent(&self, groups: &[Arc<Group>], object: Object, path: bool, mask: u32) -> bool {
        if mask & ONDIR != 0 {
            return false;
        }
        groups.iter().any(|group| {
            group.queue().marks.iter().any(|m| {
                let on = match m.target {
                    Target::Inode(key) => key == object.key,
                    Target::Mount(device) => path && device == object.key.0,
                    Target::FileSystem(device) => device == object.key.0,
                    Target::Namespace(_) => false,
                };
                let calc = m.calc();
                on && calc & EVENT_ON_CHILD != 0 && calc & FS_EVENTS_POSS_ON_CHILD & mask != 0
            })
        })
    }

    /// An event of a file that its directory may hear of too
    /// (`fsnotify_parent`), with the directory and name it is at (none for
    /// the root, or a file no path names).
    pub(crate) fn parent_event(
        &self,
        mask: u32,
        data: Data<'_>,
        parent: Option<(Object, &[u8])>,
        special_content: bool,
    ) {
        let groups = self.groups();
        if groups.is_empty() {
            return;
        }
        let object = data.object();
        let mask = mask | if object.directory { ONDIR } else { 0 };
        let path = matches!(data, Data::Path { .. });
        let (mut dir, mut name, mut on_child) = (None, None, false);
        if let Some((parent, file_name)) = parent {
            let watched = self.watches_children(&groups, parent.key, FS_EVENTS_POSS_ON_CHILD);
            let needed = !object.directory && self.needs_parent(&groups, object, path, mask);
            // A directory is told of with its parent only when the parent
            // watches its children.
            if (watched || needed) && !(object.directory && !watched) {
                dir = Some(parent);
                let interested =
                    self.watches_children(&groups, parent.key, mask & ALL_FSNOTIFY_EVENTS)
                        && !(path && special_content && mask & (ACCESS | MODIFY) != 0);
                if needed || interested {
                    name = Some(file_name);
                }
                on_child = interested;
            }
        }
        let mask = if on_child {
            mask | EVENT_ON_CHILD
        } else {
            mask
        };
        self.fsnotify(&groups, mask, &data, dir, name, Some(object));
    }

    /// An event of a file itself (`fsnotify_inode`): its link count, a
    /// move of it, its end.
    pub(crate) fn inode_event(&self, mask: u32, object: Object) {
        let groups = self.groups();
        if groups.is_empty() {
            return;
        }
        let mask = mask | if object.directory { ONDIR } else { 0 };
        self.fsnotify(
            &groups,
            mask,
            &Data::Inode(object),
            None,
            None,
            Some(object),
        );
    }

    /// An event of a directory's entry (`fsnotify_name`), with the file it
    /// names.
    pub(crate) fn entry_event(&self, mask: u32, data: Data<'_>, dir: Object, name: &[u8]) {
        let groups = self.groups();
        if groups.is_empty() {
            return;
        }
        self.fsnotify(&groups, mask, &data, Some(dir), Some(name), None);
    }

    /// `fsnotify`: each group with a mark the event reaches, told of it with
    /// those marks.
    fn fsnotify(
        &self,
        groups: &[Arc<Group>],
        mask: u32,
        data: &Data<'_>,
        dir: Option<Object>,
        name: Option<&[u8]>,
        inode: Option<Object>,
    ) {
        let object = inode.or(dir);
        let Some(object) = object else {
            return;
        };
        let (inode2, inode2_iter) = match (inode, data) {
            (None, Data::Rename { dir: new_dir, .. }) if mask & RENAME != 0 => {
                (Some(*new_dir), Iter::Inode2)
            }
            (Some(_), _) if mask & EVENT_ON_CHILD != 0 => (dir, Iter::Parent),
            _ => (None, Iter::Parent),
        };
        let mount = match data {
            Data::Path { object, .. } => Some(object.key.0),
            _ => None,
        };
        let device = object.key.0;
        for group in groups {
            Group::handle(
                group,
                mask,
                data,
                dir,
                name,
                object,
                mount,
                device,
                inode2.map(|o| (o, inode2_iter)),
            );
        }
    }
}

impl Group {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        lock(&self.queue)
    }
    fn fid_mode(&self) -> u32 {
        self.flags & FID_BITS
    }
    fn fan(&self) -> &Registry {
        &self.registry
    }

    /// `send_to_group` and `fanotify_handle_event` for this group's marks
    /// that the event reaches.
    #[allow(clippy::too_many_arguments)]
    fn handle(
        self: &Arc<Self>,
        mask: u32,
        data: &Data<'_>,
        dir: Option<Object>,
        name: Option<&[u8]>,
        object: Object,
        mount: Option<u64>,
        device: u64,
        inode2: Option<(Object, Iter)>,
    ) {
        let mut queue = self.queue();
        // The marks of each kind this event reaches (at most one each).
        let mut found: [Option<usize>; 5] = [None; 5];
        for (i, m) in queue.marks.iter().enumerate() {
            match m.target {
                Target::Inode(key) => {
                    if key == object.key {
                        found[Iter::Inode as usize] = Some(i);
                    }
                    if let Some((other, iter)) = inode2
                        && other.key == key
                    {
                        found[iter as usize] = Some(i);
                    }
                }
                Target::Mount(d) if Some(d) == mount => found[Iter::Mount as usize] = Some(i),
                Target::FileSystem(d) if d == device => {
                    found[Iter::FileSystem as usize] = Some(i);
                }
                _ => {}
            }
        }
        // A parent's mark counts only when it watches its children
        // (`fsnotify_iter_select_report_types`).
        if let Some(i) = found[Iter::Parent as usize] {
            let m = &queue.marks[i];
            if (m.mask | m.ignore_mask()) & EVENT_ON_CHILD == 0 {
                found[Iter::Parent as usize] = None;
            }
        }
        let reported: Vec<(usize, Iter)> = [
            Iter::Inode,
            Iter::Mount,
            Iter::FileSystem,
            Iter::Parent,
            Iter::Inode2,
        ]
        .into_iter()
        .filter_map(|iter| found[iter as usize].map(|i| (i, iter)))
        .collect();
        if reported.is_empty() {
            return;
        }
        // A modification ends the ignore masks that do not survive one.
        if mask & MODIFY != 0 {
            for &(i, _) in &reported {
                let m = &mut queue.marks[i];
                if m.flags & IGNORED_SURV_MODIFY == 0 {
                    m.ignore = 0;
                }
            }
        }
        let is_dir = mask & ONDIR != 0;
        let (mut marks_mask, mut ignore) = (0, 0);
        for &(i, iter) in &reported {
            let m = &queue.marks[i];
            marks_mask |= m.mask;
            ignore |= m.effective_ignore(is_dir, iter);
        }
        if mask & ALL_FSNOTIFY_EVENTS & marks_mask & !ignore == 0 {
            return;
        }
        // `fanotify_group_event_mask`.
        let fid_mode = self.fid_mode();
        let path = matches!(data, Data::Path { .. });
        if self.flags & REPORT_MNT != 0 {
            return;
        } else if fid_mode == 0 {
            if !path {
                return;
            }
            let object = data.object();
            if !object.regular && !object.directory {
                return;
            }
        } else if fid_mode & REPORT_FID == 0 && dir.is_none() && !is_dir {
            return;
        }
        let (mut marks_mask, mut ignore, mut matched) = (0, 0, 0u32);
        for &(i, iter) in &reported {
            let m = &queue.marks[i];
            ignore |= m.effective_ignore(is_dir, iter);
            if !applicable(m.mask, is_dir, iter) {
                continue;
            }
            marks_mask |= m.mask;
            matched |= 1 << iter as u32;
        }
        let test = mask & marks_mask & !ignore;
        let user_mask = if fid_mode != 0 {
            if test & !EVENT_FLAGS == 0 {
                return;
            }
            OUTGOING_EVENTS | EVENT_FLAGS
        } else {
            OUTGOING_EVENTS & !EVENT_FLAGS
        };
        let mask = test & user_mask;
        if mask == 0 {
            return;
        }
        // `fanotify_get_fsid`: the first mark's, in the iterator's order.
        let fsid = if fid_mode != 0 {
            reported
                .iter()
                .map(|&(i, _)| &queue.marks[i])
                .find(|m| m.flags & HAS_FSID != 0)
                .map_or([0, 0], |m| m.fsid)
        } else {
            [0, 0]
        };
        let Some(event) = self.event(mask, data, dir, name, fsid, matched) else {
            return;
        };
        // A permission event waits for the task to queue it and its
        // answer ([`await_answers`]).
        if mask & PERM_EVENTS != 0 {
            drop(queue);
            ASKED.with(|asked| {
                if let Some(asked) = asked.borrow_mut().as_mut() {
                    asked.push((Arc::downgrade(self), event));
                }
            });
            return;
        }
        let queued = Self::insert(&mut queue, event);
        drop(queue);
        if queued {
            self.hub.changed();
        }
    }

    /// `fanotify_alloc_event`.
    fn event(
        &self,
        mask: u32,
        data: &Data<'_>,
        dir: Option<Object>,
        name: Option<&[u8]>,
        fsid: [u32; 2],
        matched: u32,
    ) -> Option<Event> {
        let fid_mode = self.fid_mode();
        let dirent = mask & DIRENT_EVENTS != 0;
        let ondir = mask & ONDIR != 0;
        let data_inode = data.object();
        // `fanotify_fid_inode` and `fanotify_dfid_inode`.
        let mut id = if dirent && fid_mode & REPORT_TARGET_FID == 0 {
            dir
        } else {
            Some(data_inode)
        };
        let mut dirid = if dirent {
            dir
        } else if data_inode.directory {
            Some(data_inode)
        } else {
            dir
        };
        let mut file_name = name;
        let (mut child, mut moved, mut name_event) = (None, None, false);
        if fid_mode & REPORT_DIR_FID != 0 && dirid.is_some() {
            // `fanotify_report_child_fid`.
            let report_child = if dirent {
                fid_mode & REPORT_TARGET_FID != 0
            } else {
                fid_mode & REPORT_FID != 0 && !ondir
            };
            if report_child && id != dirid {
                child = id;
            }
            id = dirid;
            if fid_mode & REPORT_NAME == 0 {
                name_event = child.is_some();
                file_name = None;
            } else if dirent || !ondir {
                name_event = true;
            }
            if mask & RENAME != 0 {
                let sb = matched & (1 << Iter::FileSystem as u32) != 0;
                let report_old = sb || matched & (1 << Iter::Inode as u32) != 0;
                let report_new = sb || matched & (1 << Iter::Inode2 as u32) != 0;
                if !report_old {
                    dirid = None;
                    file_name = None;
                }
                if report_new && let Data::Rename { dir, name, .. } = data {
                    moved = Some((*dir, *name));
                }
            }
        }
        let (pid, tid) = CURRENT.with(Cell::get);
        let pid = if self.flags & REPORT_TID != 0 {
            tid
        } else {
            pid
        };
        let body = if name_event && (file_name.is_some() || moved.is_some() || child.is_some()) {
            Body::Name {
                fsid,
                dir: dirid.map(Object::handle),
                name: file_name.map(<[u8]>::to_vec).unwrap_or_default(),
                dir2: moved.map(|(dir, _)| dir.handle()),
                name2: moved.map(|(_, name)| name.to_vec()).unwrap_or_default(),
                file: child.map(Object::handle),
            }
        } else if fid_mode != 0 {
            Body::Fid {
                fsid,
                object: id.map_or(
                    Handle {
                        kind: 0,
                        bytes: Vec::new(),
                    },
                    Object::handle,
                ),
            }
        } else if let Data::Path {
            object,
            path,
            opener,
        } = data
        {
            Body::Path {
                key: object.key,
                path: path.clone(),
                opener: opener(),
            }
        } else {
            return None;
        };
        Some(Event {
            mask,
            pid,
            body,
            perm: None,
        })
    }

    /// `fsnotify_insert_event` with `fanotify_merge`: past the limit only
    /// the overflow event, once; else an event the same as an earlier one
    /// still queued is merged into it. Whether a new event was queued.
    fn insert(queue: &mut Queue, event: Event) -> bool {
        if queue.events.len() >= queue.max {
            if queue.overflowed {
                return false;
            }
            queue.overflowed = true;
            queue.events.push_back(Event {
                mask: Q_OVERFLOW,
                pid: 0,
                body: Body::Overflow,
                perm: None,
            });
        } else {
            if let Some(old) = queue
                .events
                .iter_mut()
                .rev()
                .filter(|old| !matches!(old.body, Body::Overflow) && old.perm.is_none())
                .find(|old| event.perm.is_none() && old.merges(&event))
            {
                old.mask |= event.mask;
                return false;
            }
            queue.events.push_back(event);
        }
        queue.epoch += 1;
        true
    }

    /// Queues the permission event `event` (`fsnotify_insert_event`): its
    /// number, or none when the queue is full, which lets it through after
    /// the overflow event, as Linux frees an event that was not queued.
    fn ask(&self, mut event: Event) -> Option<u64> {
        let id = {
            let mut answers = lock(&self.answers);
            answers.next += 1;
            answers.next
        };
        event.perm = Some(id);
        let mut queue = self.queue();
        let full = queue.events.len() >= queue.max;
        let queued = Self::insert(&mut queue, event);
        if !full {
            lock(&self.answers).states.insert(id, Answer::Queued);
        }
        drop(queue);
        if queued {
            self.hub.changed();
        }
        (!full).then_some(id)
    }
    /// The answer to permission event `id` once there is one
    /// (`fanotify_get_response`): let through, or the error that denies it
    /// (`EPERM`, or the response's own errno).
    fn answer(&self, id: u64) -> Option<Result<(), Errno>> {
        let mut answers = lock(&self.answers);
        let Some(&Answer::Answered(response)) = answers.states.get(&id) else {
            return None;
        };
        answers.states.remove(&id);
        // An errno in the response is only ever a pre-content group's, as
        // [`write`] refuses one from any other.
        Some(match response & (ALLOW | DENY) {
            ALLOW => Ok(()),
            _ => Err(match response >> 24 {
                0 => Errno::EPERM,
                errno => Errno(errno as i32),
            }),
        })
    }
    /// The task waiting for event `id` stopped (a fatal signal): one not
    /// read yet leaves the queue, and one read waits for its answer to go.
    fn cancel(&self, id: u64) {
        let mut answers = lock(&self.answers);
        match answers.states.get(&id) {
            Some(Answer::Queued) => {
                answers.states.remove(&id);
                drop(answers);
                self.queue().events.retain(|e| e.perm != Some(id));
            }
            Some(&Answer::Reported(fd)) => {
                answers.states.insert(id, Answer::Canceled(fd));
            }
            _ => {
                answers.states.remove(&id);
            }
        }
    }
    /// Permission event `id` was read with the descriptor `fd`: a response
    /// names it by that; one whose read failed or gave no descriptor is
    /// denied (`fanotify_read`).
    fn reported(&self, id: u64, fd: Option<i32>) {
        let mut answers = lock(&self.answers);
        match fd {
            Some(fd) if fd >= 0 => {
                answers.states.insert(id, Answer::Reported(fd));
            }
            _ => {
                answers.states.insert(id, Answer::Answered(DENY));
                drop(answers);
                self.hub.changed();
            }
        }
    }
    /// `process_access_response`'s search of the access list: the read
    /// event `fd` names gets `response`; false when none waits by it.
    fn respond(&self, fd: i32, response: u32) -> bool {
        let mut answers = lock(&self.answers);
        let Some(id) = answers
            .states
            .iter()
            .filter(
                |(_, state)| matches!(state, Answer::Reported(f) | Answer::Canceled(f) if *f == fd),
            )
            .map(|(&id, _)| id)
            .min()
        else {
            return false;
        };
        // `finish_permission_event`: a canceled event just goes.
        if matches!(answers.states.get(&id), Some(Answer::Canceled(_))) {
            answers.states.remove(&id);
        } else {
            answers
                .states
                .insert(id, Answer::Answered(response & !INFO_RESPONSE));
        }
        drop(answers);
        self.hub.changed();
        true
    }

    /// What `/proc/self/fdinfo` shows after the lines every descriptor
    /// has, as Linux's `fanotify_show_fdinfo`: the flags, then a line for
    /// each mark, the newest first; a mount's by the ID `mount_id` gives.
    pub(crate) fn fdinfo(&self, mount_id: &dyn Fn(u64) -> u64) -> Vec<u8> {
        let mut out = format!(
            "fanotify flags:{:x} event-flags:{:x}\n",
            self.flags & INIT_FLAGS,
            self.event_flags
        )
        .into_bytes();
        let queue = self.queue();
        for m in queue.marks.iter().rev() {
            let line = match m.target {
                Target::Inode((device, inode)) => {
                    let handle = Object {
                        key: (device, inode),
                        kind: m.kind,
                        directory: m.directory,
                        regular: false,
                    }
                    .handle();
                    let bytes: String = handle.bytes.iter().map(|b| format!("{b:02x}")).collect();
                    format!(
                        "fanotify ino:{inode:x} sdev:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x} \
                         fhandle-bytes:{:x} fhandle-type:{:x} f_handle:{bytes}\n",
                        sdev(device),
                        m.user_flags(),
                        m.mask,
                        m.ignore,
                        handle.bytes.len(),
                        handle.kind,
                    )
                }
                Target::Mount(device) => format!(
                    "fanotify mnt_id:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}\n",
                    mount_id(device),
                    m.user_flags(),
                    m.mask,
                    m.ignore
                ),
                Target::FileSystem(device) => format!(
                    "fanotify sdev:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}\n",
                    sdev(device),
                    m.user_flags(),
                    m.mask,
                    m.ignore
                ),
                Target::Namespace(inode) => format!(
                    "fanotify mnt_ns:{inode} mflags:{:x} mask:{:x} ignored_mask:{:x}\n",
                    m.user_flags(),
                    m.mask,
                    m.ignore
                ),
            };
            out.extend_from_slice(line.as_bytes());
        }
        out
    }
}
/// A device as the kernel's `s_dev` prints it: `new_encode_dev` undone,
/// then `MKDEV`.
fn sdev(device: u64) -> u64 {
    let major = (device >> 8) & 0xfff;
    let minor = (device & 0xff) | ((device >> 12) & !0xff);
    major << 20 | minor
}

impl Drop for Group {
    /// `fanotify_release`: what waits for its answers is let through.
    fn drop(&mut self) {
        self.hub.changed();
        let marks = self.queue().marks.len() as u64;
        self.fan()
            .release(self.owner, marks, self.flags & UNLIMITED_MARKS == 0, true);
    }
}

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}
pub(crate) fn sys_fanotify_init(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(init(c, a[0] as u32, a[1] as u32))
}
pub(crate) fn sys_fanotify_mark(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(mark(c, a))
}

const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_AUDIT_WRITE: u64 = 1 << 29;

/// `fanotify_init(flags, event_f_flags)`, checked in Linux's order.
fn init(c: &mut Context<'_>, flags: u32, event_flags: u32) -> Result<u64, Errno> {
    let fid_mode = flags & FID_BITS;
    let class = flags & (CLASS_CONTENT | CLASS_PRE_CONTENT);
    let admin = c.process.credentials.capable(CAP_SYS_ADMIN);
    // An unprivileged group reports files by handle only, or mounts.
    if (flags & ADMIN_INIT_FLAGS != 0 || flags & (FID_BITS | REPORT_MNT) == 0) && !admin {
        return Err(Errno::EPERM);
    }
    let internal = if admin { 0 } else { UNPRIV };
    if flags & !(INIT_FLAGS | ENABLE_AUDIT) != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux 7.0's, which the CI runners have: a pidfd is of a process, so
    // not with thread IDs (master takes both, with `PIDFD_THREAD`).
    if flags & REPORT_PIDFD != 0 && flags & REPORT_TID != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & REPORT_MNT != 0 && (class != 0 || flags & (FID_BITS | REPORT_FD_ERROR) != 0) {
        return Err(Errno::EINVAL);
    }
    if event_flags & !EVENT_F_BITS != 0 || event_flags & 3 == 3 {
        return Err(Errno::EINVAL);
    }
    if fid_mode != 0 && class != 0 {
        return Err(Errno::EINVAL);
    }
    if fid_mode & REPORT_NAME != 0 && fid_mode & REPORT_DIR_FID == 0 {
        return Err(Errno::EINVAL);
    }
    if fid_mode & REPORT_TARGET_FID != 0
        && (fid_mode & REPORT_NAME == 0 || fid_mode & REPORT_FID == 0)
    {
        return Err(Errno::EINVAL);
    }
    let fan = Arc::clone(&c.files.caches.notify.fan);
    let owner = c.process.credentials.euid;
    fan.add_group(owner)?;
    let group = Arc::new(Group {
        registry: Arc::clone(&fan),
        hub: Arc::clone(&c.files.readiness),
        owner,
        flags: flags | internal,
        event_flags: event_flags | O_LARGEFILE,
        status: AtomicU32::new(2 | if flags & NONBLOCK != 0 { 0o4000 } else { 0 }),
        answers: Mutex::new(Answers::default()),
        queue: Mutex::new(Queue {
            events: VecDeque::new(),
            overflowed: false,
            epoch: 0,
            max: if flags & UNLIMITED_QUEUE != 0 {
                u32::MAX as usize
            } else {
                usize::try_from(fan.limits.events.load(Ordering::SeqCst)).unwrap_or(0)
            },
            marks: Vec::new(),
        }),
    });
    // Counted now, and given back when it goes.
    let weak: Weak<dyn Grouped> = Arc::downgrade(&group) as Weak<dyn Grouped>;
    lock(&fan.groups).push(weak);
    if class == CLASS_CONTENT | CLASS_PRE_CONTENT {
        return Err(Errno::EINVAL);
    }
    if flags & ENABLE_AUDIT != 0 && !c.process.credentials.capable(CAP_AUDIT_WRITE) {
        return Err(Errno::EPERM);
    }
    c.files
        .install(group, flags & CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

/// The group descriptor `fd` holds, as `fdget` takes it: EBADF for none
/// (or an `O_PATH` one).
fn group_file(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    if file.flags() & crate::files::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// The group `file` is, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&Group> {
    file.as_any()?.downcast_ref::<Group>()
}

/// `fanotify_mark(fd, flags, mask, dirfd, pathname)`, as Linux's
/// `do_fanotify_mark` checks it, in its order.
fn mark(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (flags, mask64, dfd, pathname) = (a[1] as u32, a[2], a[3], a[4]);
    if mask64 >> 32 != 0 {
        return Err(Errno::EINVAL);
    }
    let mut mask = mask64 as u32;
    if flags & !MARK_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let mark_type = flags & MARK_TYPE_BITS;
    let mark_cmd = flags & MARK_CMD_BITS;
    let ignore = flags & MARK_IGNORE_BITS;
    match mark_cmd {
        MARK_ADD | MARK_REMOVE if mask == 0 => return Err(Errno::EINVAL),
        MARK_ADD | MARK_REMOVE => {}
        MARK_FLUSH if flags & !(MARK_TYPE_BITS | MARK_FLUSH) != 0 => return Err(Errno::EINVAL),
        MARK_FLUSH => {}
        _ => return Err(Errno::EINVAL),
    }
    if mask & !(EVENTS | EVENT_FLAGS | PERM_EVENTS) != 0 {
        return Err(Errno::EINVAL);
    }
    if ignore == MARK_IGNORE | MARK_IGNORED_MASK {
        return Err(Errno::EINVAL);
    }
    let mut umask = 0;
    if ignore == MARK_IGNORED_MASK {
        mask &= !EVENT_FLAGS;
        umask = EVENT_FLAGS;
    }
    let file = group_file(c, a[0])?;
    let group = of(&file).ok_or(Errno::EINVAL)?;
    if group.flags & REPORT_MNT != 0 {
        if mask & !MOUNT_EVENTS != 0 || mark_type != MARK_MNTNS {
            return Err(Errno::EINVAL);
        }
    } else if mask & MOUNT_EVENTS != 0 || mark_type == MARK_MNTNS {
        return Err(Errno::EINVAL);
    }
    let admin = c.process.credentials.capable(CAP_SYS_ADMIN);
    if mark_type != 0 && !admin {
        return Err(Errno::EPERM);
    }
    let class = group.flags & (CLASS_CONTENT | CLASS_PRE_CONTENT);
    if mask & PERM_EVENTS != 0 && class == 0 || mask & PRE_ACCESS != 0 && class == CLASS_CONTENT {
        return Err(Errno::EINVAL);
    }
    if mask & FS_ERROR != 0 && mark_type != MARK_FILESYSTEM {
        return Err(Errno::EINVAL);
    }
    if flags & MARK_EVICTABLE != 0 && mark_type != 0 {
        return Err(Errno::EINVAL);
    }
    let fid_mode = group.fid_mode();
    if mask & !(FD_EVENTS | MOUNT_EVENTS | EVENT_FLAGS) != 0
        && (fid_mode == 0 || mark_type == MARK_MOUNT)
    {
        return Err(Errno::EINVAL);
    }
    if mask & RENAME != 0 && fid_mode & REPORT_NAME == 0 {
        return Err(Errno::EINVAL);
    }
    if mask & PRE_ACCESS != 0 && mask & ONDIR != 0 {
        return Err(Errno::EINVAL);
    }
    if mark_cmd == MARK_FLUSH {
        let removed = {
            let mut queue = group.queue();
            let before = queue.marks.len();
            queue.marks.retain(|m| {
                !matches!(
                    (m.target, mark_type),
                    (Target::Inode(_), 0)
                        | (Target::Mount(_), MARK_MOUNT)
                        | (Target::FileSystem(_), MARK_FILESYSTEM)
                        | (Target::Namespace(_), MARK_MNTNS)
                )
            });
            (before - queue.marks.len()) as u64
        };
        group.fan().release(
            group.owner,
            removed,
            group.flags & UNLIMITED_MARKS == 0,
            false,
        );
        return Ok(0);
    }
    let found = crate::files::marked(
        c,
        dfd,
        pathname,
        flags & MARK_DONT_FOLLOW == 0,
        flags & MARK_ONLYDIR != 0,
    )?;
    let object = Object::of(found.key, found.kind, &found.stat);
    if mark_cmd == MARK_ADD {
        // `fanotify_events_supported`.
        let strict =
            group.flags & REPORT_TARGET_FID != 0 || mask & RENAME != 0 || flags & MARK_IGNORE != 0;
        if mask & PRE_ACCESS != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if mask & PERM_EVENTS != 0 && found.kind == PROC_SUPER_MAGIC {
            return Err(Errno::EINVAL);
        }
        if mark_type != 0 && internal(found.kind) {
            return Err(Errno::EINVAL);
        }
        if strict && mark_type == 0 && !object.directory && mask & DIRONLY_EVENT_BITS != 0 {
            return Err(Errno::ENOTDIR);
        }
    }
    crate::permissions::permission(&c.process.credentials, &found.stat, 4)?;
    let mut mark_flags = 0;
    let mut mark_fsid = [0, 0];
    if fid_mode != 0 {
        // `fanotify_test_fsid`: a file system without an ID takes only
        // inode marks; then `fanotify_test_fid`: a mount or file system
        // mark needs handles the file system decodes.
        let id = fsid(c, found.key.0, found.kind);
        mark_flags |= HAS_FSID;
        mark_fsid = id;
        if id == [0, 0] {
            if mark_type != 0 {
                return Err(Errno::ENODEV);
            }
            mark_flags |= WEAK_FSID;
        }
        if mark_type != 0 && !crate::files::exportable(found.kind) {
            return Err(Errno::EOPNOTSUPP);
        }
    }
    let target = match mark_type {
        0 => Target::Inode(found.key),
        MARK_MOUNT => Target::Mount(found.key.0),
        MARK_FILESYSTEM => Target::FileSystem(found.key.0),
        _ => {
            // A mount namespace file names the namespace.
            if found.kind != NSFS_MAGIC {
                return Err(Errno::EINVAL);
            }
            Target::Namespace(found.stat.inode)
        }
    };
    if mark_cmd == MARK_ADD && ignore != 0 && flags & MARK_IGNORED_SURV_MODIFY == 0 {
        let inode = mark_type == 0;
        if ignore == MARK_IGNORE && (!inode || object.directory) {
            return Err(if inode { Errno::EISDIR } else { Errno::EINVAL });
        }
        if inode && c.files.caches.open_for_write(found.key) {
            return Ok(0);
        }
    }
    if mark_type != 0 || !object.directory {
        mask &= !EVENT_ON_CHILD;
        umask = EVENT_ON_CHILD;
        if fid_mode & REPORT_DIR_FID != 0 && mark_cmd == MARK_ADD && ignore == 0 {
            mask |= EVENT_ON_CHILD;
        }
    }
    if mark_cmd == MARK_ADD {
        add_mark(group, target, object, mask, flags, mark_flags, mark_fsid)
    } else {
        remove_mark(group, target, mask, flags, umask)
    }
    .map(|()| 0)
}

/// `fanotify_add_mark`.
fn add_mark(
    group: &Group,
    target: Target,
    object: Object,
    mask: u32,
    flags: u32,
    mark_flags: u32,
    fsid: [u32; 2],
) -> Result<(), Errno> {
    let mut queue = group.queue();
    let at = match queue.marks.iter().position(|m| m.target == target) {
        Some(at) => at,
        None => {
            group
                .fan()
                .add_mark(group.owner, group.flags & UNLIMITED_MARKS != 0)?;
            let mut new = Mark {
                target,
                mask: 0,
                ignore: 0,
                flags: if flags & MARK_EVICTABLE != 0 {
                    NO_IREF
                } else {
                    0
                },
                fsid: [0, 0],
                kind: object.kind,
                directory: object.directory,
            };
            if mark_flags & HAS_FSID != 0 {
                // `fanotify_set_mark_fsid`: the group's marks are of one
                // kind of file system ID.
                new.fsid = fsid;
                new.flags |= mark_flags;
                if let Some(old) = queue.marks.last()
                    && old.flags & HAS_FSID != 0
                {
                    let weak = (new.flags ^ old.flags) & WEAK_FSID != 0;
                    let other = new.flags & WEAK_FSID != 0
                        && (old.device() != new.device() || old.fsid != new.fsid);
                    if weak || other {
                        drop(queue);
                        group.fan().release(
                            group.owner,
                            1,
                            group.flags & UNLIMITED_MARKS == 0,
                            false,
                        );
                        return Err(EXDEV);
                    }
                }
            }
            queue.marks.push(new);
            queue.marks.len() - 1
        }
    };
    let m = &mut queue.marks[at];
    // `fanotify_may_update_existing_mark`.
    if flags & MARK_EVICTABLE != 0 && m.flags & NO_IREF == 0
        || flags & MARK_IGNORED_MASK != 0 && m.flags & HAS_IGNORE_FLAGS != 0
        || flags & MARK_IGNORE != 0
            && flags & MARK_IGNORED_SURV_MODIFY == 0
            && m.flags & IGNORED_SURV_MODIFY != 0
        || (mask | m.mask) & PRE_ACCESS != 0 && (mask | m.mask) & ONDIR != 0
    {
        return Err(Errno::EEXIST);
    }
    // `fanotify_mark_add_to_mask`.
    let ignore = flags & MARK_IGNORE_BITS;
    if ignore == 0 {
        m.mask |= mask;
    } else {
        m.ignore |= mask;
    }
    if ignore == MARK_IGNORE {
        m.flags |= HAS_IGNORE_FLAGS;
    }
    if ignore != 0 && flags & MARK_IGNORED_SURV_MODIFY != 0 {
        m.flags |= IGNORED_SURV_MODIFY;
    }
    if matches!(m.target, Target::Inode(_)) && flags & MARK_EVICTABLE == 0 {
        m.flags &= !NO_IREF;
    }
    Ok(())
}

/// `fanotify_remove_mark`: ENOENT for no mark; one left with nothing to
/// report or ignore goes.
fn remove_mark(
    group: &Group,
    target: Target,
    mask: u32,
    flags: u32,
    umask: u32,
) -> Result<(), Errno> {
    let mut queue = group.queue();
    let at = queue
        .marks
        .iter()
        .position(|m| m.target == target)
        .ok_or(Errno::ENOENT)?;
    let m = &mut queue.marks[at];
    let mask = mask & !umask;
    if flags & MARK_IGNORE_BITS == 0 {
        m.mask &= !mask;
    } else {
        m.ignore &= !mask;
    }
    if (m.mask | m.ignore) & !umask == 0 {
        queue.marks.remove(at);
        drop(queue);
        group
            .fan()
            .release(group.owner, 1, group.flags & UNLIMITED_MARKS == 0, false);
    }
    Ok(())
}

/// A read of a group into a kernel buffer, as an asynchronous read takes
/// it; `None` for any other file.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    out: &mut [u8],
    nowait: bool,
) -> Option<Result<usize, Errno>> {
    let group = of(file)?;
    let mut records = Vec::new();
    let result = read_events(c, group, &mut records, out.len(), usize::MAX, nowait);
    out[..records.len()].copy_from_slice(&records);
    Some(result)
}

/// `read(2)` of a group, or one buffer of a `readv(2)`, into the guest's
/// `len` bytes at `at`, which `access_ok` has passed.
pub(crate) fn read_guest(
    c: &mut Context<'_>,
    group: &Group,
    at: u64,
    len: usize,
) -> Result<usize, Errno> {
    let writable = crate::inotify::writable(c, at, len);
    let mut records = Vec::new();
    let result = read_events(c, group, &mut records, len, writable, false);
    let shown = records.len().min(writable);
    c.mem
        .write(GuestAddr(at), &records[..shown])
        .map_err(|_| Errno::EFAULT)?;
    result
}

/// Linux's `fanotify_read`: as many whole events as fit `len` bytes,
/// waiting for the first unless the file is non-blocking; EINVAL when the
/// first does not fit, and a pending signal ends the wait (ERESTARTSYS).
/// An event whose descriptor cannot be opened is taken and gives its error
/// (but with `FAN_REPORT_FD_ERROR`); one that reaches past the first
/// `writable` bytes is lost, its descriptors closed, and the read is
/// `EFAULT`.
fn read_events(
    c: &mut Context<'_>,
    group: &Group,
    out: &mut Vec<u8>,
    len: usize,
    writable: usize,
    nowait: bool,
) -> Result<usize, Errno> {
    let info_mode = group.flags & INFO_MODES;
    loop {
        let ticket = c.files.readiness.token.value();
        let mut error = None;
        loop {
            let event = {
                let mut queue = group.queue();
                let Some(size) = queue.events.front().map(|e| e.len(info_mode)) else {
                    break;
                };
                if size > len - out.len() {
                    error = Some(Errno::EINVAL);
                    break;
                }
                let event = queue.events.pop_front();
                if matches!(
                    event,
                    Some(Event {
                        body: Body::Overflow,
                        ..
                    })
                ) {
                    queue.overflowed = false;
                }
                event
            };
            let Some(event) = event else {
                break;
            };
            let copied = copy_event(c, group, &event, info_mode, out, writable);
            // A permission event waits for its answer by the descriptor it
            // gave; one that could not be read is denied.
            if let Some(id) = event.perm {
                group.reported(id, copied.as_ref().ok().copied());
            }
            match copied {
                Ok(_) => {}
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        if error == Some(Errno::EFAULT) {
            return Err(Errno::EFAULT);
        }
        if !out.is_empty() {
            return Ok(out.len());
        }
        if let Some(error) = error {
            return Err(error);
        }
        if nowait || group.status.load(Ordering::SeqCst) & 0o4000 != 0 {
            return Err(Errno::EAGAIN);
        }
        if crate::events::signalled(c) {
            return Err(Errno(4));
        }
        crate::events::wait(c, ticket, None)?;
    }
}

/// `copy_event_to_user`: the metadata, then the info records, with the
/// descriptors of the file and the process installed once all is written.
fn copy_event(
    c: &mut Context<'_>,
    group: &Group,
    event: &Event,
    info_mode: u32,
    out: &mut Vec<u8>,
    writable: usize,
) -> Result<i32, Errno> {
    let unpriv = group.flags & UNPRIV != 0;
    let fd_error = group.flags & REPORT_FD_ERROR != 0;
    let space = c.group.namespaces(c.tid).pid.clone();
    let mut pid = space.number(event.pid);
    if unpriv && event.pid != c.process.pid {
        pid = 0;
    }
    let limit = c.group.nofile();
    let mut fd: i32 = -Errno::EBADF.0;
    let mut installed = Vec::new();
    if !unpriv && let Body::Path { path, opener, .. } = &event.body {
        let opened = opener(group.event_flags).and_then(|file| {
            c.files.install_at(
                file,
                path.clone(),
                group.event_flags & O_CLOEXEC != 0,
                limit,
            )
        });
        match opened {
            Ok(n) => {
                fd = n as i32;
                installed.push(n);
            }
            Err(e) if fd_error => fd = -e.0,
            Err(e) => return Err(e),
        }
    }
    let shown_fd = if fd_error || fd >= 0 { fd } else { NOFD };
    let mut pidfd: i32 = -3; // -ESRCH
    if info_mode & REPORT_PIDFD != 0 {
        if pid != 0 {
            let thread = group.flags & REPORT_TID != 0;
            let file = crate::processes::PidFd::stale(c.processes, event.pid, thread);
            match c.files.install(file, true, limit) {
                Ok(n) => {
                    pidfd = n as i32;
                    installed.push(n);
                }
                Err(e) => pidfd = -e.0,
            }
        }
        if !fd_error && pidfd < 0 {
            pidfd = if pidfd == -3 { NOFD } else { EPIDFD };
        }
    }
    let start = out.len();
    let event_len = event.len(info_mode);
    out.extend_from_slice(&(event_len as u32).to_le_bytes());
    out.push(VERSION);
    out.push(0);
    out.extend_from_slice(&(METADATA as u16).to_le_bytes());
    out.extend_from_slice(&u64::from(event.mask & OUTGOING_EVENTS).to_le_bytes());
    out.extend_from_slice(&shown_fd.to_le_bytes());
    out.extend_from_slice(&(pid as i32).to_le_bytes());
    // `copy_info_records_to_user`.
    let fid_mode = info_mode & FID_BITS;
    let mut info_type = 0;
    if let Body::Name {
        fsid,
        dir,
        name,
        dir2,
        name2,
        ..
    } = &event.body
    {
        if let Some(dir) = dir {
            info_type = if name.is_empty() {
                INFO_DFID
            } else {
                INFO_DFID_NAME
            };
            if event.mask & RENAME != 0 {
                info_type = INFO_OLD_DFID_NAME;
            }
            fid_record(out, info_type, *fsid, dir, name);
        }
        if let Some(dir2) = dir2 {
            info_type = INFO_NEW_DFID_NAME;
            fid_record(out, info_type, *fsid, dir2, name2);
        }
    }
    if let Some(object) = event.object_handle() {
        let fsid = match &event.body {
            Body::Fid { fsid, .. } | Body::Name { fsid, .. } => *fsid,
            _ => [0, 0],
        };
        let (record, dot): (u8, &[u8]) = if fid_mode == REPORT_FID || info_type != 0 {
            (INFO_FID, b"")
        } else if fid_mode & REPORT_NAME != 0 && event.mask & ONDIR != 0 {
            (INFO_DFID_NAME, b".")
        } else if event.mask & (DIRENT_EVENTS | ONDIR) != 0 {
            (INFO_DFID, b"")
        } else {
            (INFO_FID, b"")
        };
        fid_record(out, record, fsid, object, dot);
    }
    if info_mode & REPORT_PIDFD != 0 {
        out.extend_from_slice(&[INFO_PIDFD, 0]);
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&pidfd.to_le_bytes());
    }
    debug_assert_eq!(out.len() - start, event_len);
    if out.len() > writable {
        for n in installed {
            c.files.uninstall(n);
        }
        return Err(Errno::EFAULT);
    }
    Ok(shown_fd)
}

/// `copy_fid_info_to_user`: a `struct fanotify_event_info_fid`, its
/// `struct file_handle`, the name with its NUL, and zeros to 4 bytes.
fn fid_record(out: &mut Vec<u8>, info_type: u8, fsid: [u32; 2], handle: &Handle, name: &[u8]) {
    let len = fid_info_len(handle.bytes.len(), name.len());
    let start = out.len();
    out.extend_from_slice(&[info_type, 0]);
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&fsid[0].to_le_bytes());
    out.extend_from_slice(&fsid[1].to_le_bytes());
    out.extend_from_slice(&(handle.bytes.len() as u32).to_le_bytes());
    let kind = if handle.bytes.is_empty() {
        FILEID_INVALID
    } else {
        handle.kind
    };
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&handle.bytes);
    if !name.is_empty() {
        out.extend_from_slice(name);
        out.push(0);
    }
    out.resize(start + len, 0);
}

/// `fanotify_write`: a `struct fanotify_response` to a permission event,
/// with its audit record: the read event its descriptor names gets the
/// answer, `ENOENT` when none waits by it.
pub(crate) fn write(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    at: u64,
    count: u64,
) -> Option<Result<u64, Errno>> {
    let group = of(file)?;
    Some((|| {
        if count < 8 {
            return Err(Errno::EINVAL);
        }
        let mut response = [0u8; 8];
        c.mem
            .read(GuestAddr(at), &mut response)
            .map_err(|_| Errno::EFAULT)?;
        let fd = i32::from_le_bytes(response[..4].try_into().unwrap_or_default());
        let response = u32::from_le_bytes(response[4..].try_into().unwrap_or_default());
        let errno = response >> 24;
        const AUDIT: u32 = 0x10;
        const INFO: u32 = 0x20;
        if response & !(ALLOW | DENY | AUDIT | INFO | 0xff << 24) != 0 {
            return Err(Errno::EINVAL);
        }
        let class = group.flags & (CLASS_CONTENT | CLASS_PRE_CONTENT);
        match response & (ALLOW | DENY) {
            ALLOW if errno != 0 => return Err(Errno::EINVAL),
            ALLOW => {}
            DENY => {
                if errno != 0 && class != CLASS_PRE_CONTENT {
                    return Err(Errno::EINVAL);
                }
                if !matches!(errno, 0 | 5 | 1 | 16 | 26 | 11 | 28 | 122) {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        if response & AUDIT != 0 && group.flags & ENABLE_AUDIT == 0 {
            return Err(Errno::EINVAL);
        }
        if response & INFO != 0 {
            // `process_access_response_info`: one audit rule record.
            let len = count - 8;
            if len != 12 {
                return Err(Errno::EINVAL);
            }
            let mut rule = [0u8; 12];
            c.mem
                .read(GuestAddr(at + 8), &mut rule)
                .map_err(|_| Errno::EFAULT)?;
            if rule[0] != 1 || rule[1] != 0 || u16::from_le_bytes([rule[2], rule[3]]) != 12 {
                return Err(Errno::EINVAL);
            }
            if fd == NOFD {
                return Ok(8 + len);
            }
        }
        if fd < 0 {
            return Err(Errno::EINVAL);
        }
        if group.respond(fd, response) {
            Ok(if response & INFO != 0 { count } else { 8 })
        } else {
            Err(Errno::ENOENT)
        }
    })())
}

/// A group's own `ioctl` requests (`fanotify_ioctl`): `FIONREAD`, the bytes
/// its queued events take; `ENOTTY` for any other. `None` for any other
/// file.
pub(crate) fn ioctl(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    request: u64,
    argument: u64,
) -> Option<Result<u64, Errno>> {
    const FIONREAD: u64 = 0x541b;
    let group = of(file)?;
    Some(match request & 0xffff_ffff {
        FIONREAD => {
            let info_mode = group.flags & INFO_MODES;
            let bytes: usize = group.queue().events.iter().map(|e| e.len(info_mode)).sum();
            c.mem
                .write(GuestAddr(argument), &(bytes as i32).to_le_bytes())
                .map(|()| 0)
                .map_err(|_| Errno::EFAULT)
        }
        _ => Err(Errno::ENOTTY),
    })
}

impl FileHandle for Group {
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
    /// Writes come through [`write`].
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
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
    /// Opened for reading and writing.
    fn flags(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.store(
            2 | flags & (0o4000 | crate::fasync::O_ASYNC),
            Ordering::SeqCst,
        );
        Ok(())
    }
}
