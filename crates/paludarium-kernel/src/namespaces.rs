//! A thread's namespaces, as Linux's `nsproxy` with the user and PID
//! namespaces beside it: each thread has its own set, which `clone`,
//! `unshare` and `setns` change and `/proc/<pid>/ns` shows. The UTS
//! namespace holds the host and domain names that `uname` reports, the IPC
//! namespace the System V shared memory segments, and a PID namespace the
//! numbers it gives the tasks in it ([`Pids`]), and a nested network
//! namespace its own network, with only a loopback, and abstract socket
//! names ([`Sockets`]); the mount, cgroup and time namespaces have nothing
//! in them that paludarium keeps apart (there is no `mount`, no cgroup file
//! and no clock offset), so a new one differs only in its identity. The
//! user namespace is the first one only.
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

pub(crate) const CLONE_NEWTIME: u64 = 0x80;
pub(crate) const CLONE_NEWNS: u64 = 0x2_0000;
pub(crate) const CLONE_NEWCGROUP: u64 = 0x200_0000;
pub(crate) const CLONE_NEWUTS: u64 = 0x400_0000;
pub(crate) const CLONE_NEWIPC: u64 = 0x800_0000;
pub(crate) const CLONE_NEWUSER: u64 = 0x1000_0000;
pub(crate) const CLONE_NEWPID: u64 = 0x2000_0000;
pub(crate) const CLONE_NEWNET: u64 = 0x4000_0000;
/// The namespaces a thread can have new ones of here.
pub(crate) const SUPPORTED: u64 = CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWPID
    | CLONE_NEWNET;
/// Every namespace flag; those not in [`SUPPORTED`] are `EINVAL`, as from a
/// kernel built without them.
pub(crate) const ALL: u64 = SUPPORTED | CLONE_NEWUSER;
/// `clone3`'s `CLONE_NEWTIME`, which is a bit of the exit signal in
/// `clone`'s flags, as `clone3` passes it on to the `clone` it runs.
pub(crate) const CLONE3_NEWTIME: u64 = 1 << 40;

/// The namespace checks of `clone` and `unshare`, as Linux's
/// `copy_namespaces` and `unshare_nsproxy_namespaces` make them: a new
/// namespace but a user one needs CAP_SYS_ADMIN (`EPERM`) in the user
/// namespace the thread then has (`administers`), which a new user
/// namespace gives it.
pub(crate) fn check(flags: u64, administers: bool) -> Result<(), Errno> {
    if flags & SUPPORTED != 0 && !administers {
        return Err(Errno::EPERM);
    }
    Ok(())
}
/// The credentials a thread with `creds` has after `flags`: with
/// `CLONE_NEWUSER`, in a new user namespace in its own, which it owns and
/// has every capability in (Linux's `create_user_ns` and
/// `set_cred_user_ns`), which keeps the thread's `RLIMIT_MSGQUEUE` soft
/// limit `msgqueue` as the most its users' message queues may charge.
pub(crate) fn user_for(
    namespaces: &Namespaces,
    creds: &crate::credentials::Credentials,
    flags: u64,
    msgqueue: u64,
) -> Result<crate::credentials::Credentials, Errno> {
    if flags & CLONE_NEWUSER == 0 {
        return Ok(creds.clone());
    }
    let user = Namespace::new_user(&creds.user.0, namespaces.next_inode(), creds, msgqueue)?;
    Ok(crate::credentials::Credentials {
        user: crate::users::UserNs(user),
        permitted: crate::credentials::ALL_CAPABILITIES,
        effective: crate::credentials::ALL_CAPABILITIES,
        inheritable: 0,
        keep_caps: false,
        ..creds.clone()
    })
}
/// `__NEW_UTS_LEN`: the longest host or domain name.
pub(crate) const NAME_LENGTH: usize = 64;

/// Linux's fixed inode numbers of the first namespaces (`PROC_*_INIT_INO`),
/// then the first ones it hands out (`PROC_DYNAMIC_FIRST`), which the first
/// network and mount namespaces take.
const IPC_INIT: u32 = 0xEFFF_FFFF;
const UTS_INIT: u32 = 0xEFFF_FFFE;
const USER_INIT: u32 = 0xEFFF_FFFD;
const PID_INIT: u32 = 0xEFFF_FFFC;
const CGROUP_INIT: u32 = 0xEFFF_FFFB;
const TIME_INIT: u32 = 0xEFFF_FFFA;
const DYNAMIC_FIRST: u32 = 0xF000_0000;
/// `MAX_PID_NS_LEVEL`: how many PID namespaces nest below the first, which
/// is level 0, as Linux's `init_pid_ns`.
const MAX_PID_LEVEL: u32 = 32;

/// What kind of namespace one is, by its `CLONE_NEW*` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Net,
    Uts,
    Ipc,
    Pid,
    User,
    Mnt,
    Cgroup,
    Time,
}
impl Kind {
    /// The flag `setns` and `clone` name it by (`ns->ops->type`).
    pub(crate) fn flag(self) -> u64 {
        match self {
            Kind::Net => CLONE_NEWNET,
            Kind::Uts => CLONE_NEWUTS,
            Kind::Ipc => CLONE_NEWIPC,
            Kind::Pid => CLONE_NEWPID,
            Kind::User => CLONE_NEWUSER,
            Kind::Mnt => CLONE_NEWNS,
            Kind::Cgroup => CLONE_NEWCGROUP,
            Kind::Time => CLONE_NEWTIME,
        }
    }
    /// The name its link reads with (`ns->ops->name`).
    fn name(self) -> &'static str {
        match self {
            Kind::Net => "net",
            Kind::Uts => "uts",
            Kind::Ipc => "ipc",
            Kind::Pid => "pid",
            Kind::User => "user",
            Kind::Mnt => "mnt",
            Kind::Cgroup => "cgroup",
            Kind::Time => "time",
        }
    }
}

/// The host and domain names of a UTS namespace, as `sethostname` and
/// `setdomainname` set them: at most [`NAME_LENGTH`] bytes each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UtsNames {
    pub host: Vec<u8>,
    pub domain: Vec<u8>,
}

/// One namespace: its kind, the inode number that names it, and, for a UTS
/// namespace, its names.
#[derive(Debug)]
pub(crate) struct Namespace {
    pub kind: Kind,
    pub inode: u32,
    names: Mutex<UtsNames>,
    /// The System V shared memory segments of an IPC namespace, which go
    /// with it, as Linux's `shm_exit_ns` removes them.
    pub shm: crate::shm::Segments,
    /// Its System V semaphore sets, which go with it (`sem_exit_ns`).
    pub sem: crate::sem::Sets,
    /// Its System V message queues, which go with it (`msg_exit_ns`).
    pub msg: crate::msg::Queues,
    /// Its POSIX message queues, the names of its `mqueue` filesystem.
    pub mq: crate::mqueue::Queues,
    /// The numbers of a PID namespace.
    pids: Pids,
    /// A nested network namespace's sockets.
    pub sockets: Sockets,
    /// What a user namespace holds ([`crate::users`]).
    pub users: crate::users::Users,
    /// The user namespace that owns it, whose capabilities act on it
    /// (Linux's `ns->user_ns`); none for one the first user namespace owns.
    owner: Option<Arc<Namespace>>,
}
/// What the sockets of a nested network namespace are in: its own network,
/// and its abstract socket names once a socket looks for them. The first
/// namespace has none, and its sockets are in the session's.
#[derive(Default)]
pub(crate) struct Sockets {
    pub network: OnceLock<Arc<crate::inet::Network>>,
    pub unix: OnceLock<Arc<crate::unix::Names>>,
}
impl std::fmt::Debug for Sockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.network.get().is_some() {
            "Sockets(own)"
        } else {
            "Sockets(first)"
        })
    }
}
impl Namespace {
    fn new(kind: Kind, inode: u32, names: UtsNames) -> Arc<Self> {
        Self::within(kind, inode, names, Pids::default(), None)
    }
    fn within(
        kind: Kind,
        inode: u32,
        names: UtsNames,
        pids: Pids,
        owner: Option<Arc<Namespace>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inode,
            names: Mutex::new(names),
            shm: crate::shm::Segments::default(),
            sem: crate::sem::Sets::default(),
            msg: crate::msg::Queues::default(),
            mq: crate::mqueue::Queues::default(),
            pids,
            sockets: Sockets::default(),
            users: crate::users::Users::default(),
            owner,
        })
    }
    /// The first user namespace ([`crate::users::first`]).
    pub(crate) fn first_user() -> Arc<Self> {
        Self::user(USER_INIT, crate::users::Users::default())
    }
    /// A user namespace, which the namespace it is in owns.
    pub(crate) fn user(inode: u32, users: crate::users::Users) -> Arc<Self> {
        Arc::new(Self {
            kind: Kind::User,
            inode,
            names: Mutex::new(UtsNames {
                host: Vec::new(),
                domain: Vec::new(),
            }),
            shm: crate::shm::Segments::default(),
            sem: crate::sem::Sets::default(),
            msg: crate::msg::Queues::default(),
            mq: crate::mqueue::Queues::default(),
            pids: Pids::default(),
            sockets: Sockets::default(),
            owner: users.parent().cloned(),
            users,
        })
    }
    /// The user namespace that owns it; a user namespace's is its parent,
    /// and the first one's itself.
    pub(crate) fn owner(&self) -> &Namespace {
        self.owner.as_deref().unwrap_or(crate::users::first())
    }
    /// What its link in `/proc/<pid>/ns` reads, as Linux's `ns_get_name`.
    pub(crate) fn link(&self) -> Vec<u8> {
        format!("{}:[{}]", self.kind.name(), self.inode).into_bytes()
    }
    /// The names of a UTS namespace (and a copy of the first one's in any
    /// other).
    pub(crate) fn names(&self) -> UtsNames {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    pub(crate) fn set_host(&self, name: &[u8]) {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .host = name.to_vec();
    }
    pub(crate) fn set_domain(&self, name: &[u8]) {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .domain = name.to_vec();
    }
}

/// What a PID namespace numbers, as Linux's `struct pid` gives a task a
/// number in each namespace from its own up to the first. The first
/// namespace numbers every task by its ID in the emulator, which is what
/// the rest of the kernel names tasks by, so it keeps no table; a nested
/// one hands out its own numbers from 1, and its task 1 is its init.
#[derive(Debug, Default)]
struct Pids {
    /// The namespace it was made in; none for the first.
    parent: Option<Arc<Namespace>>,
    /// How many namespaces it is beneath the first.
    depth: u32,
    numbers: Mutex<Numbers>,
}
#[derive(Debug, Default)]
struct Numbers {
    /// The last number handed out.
    last: u32,
    /// Each task's number, by the task's ID in the emulator, and back.
    by_task: BTreeMap<u32, u32>,
    by_number: BTreeMap<u32, u32>,
    /// The task numbered 1, the namespace's init (Linux's
    /// `child_reaper`), once there is one; it stays after the init exits.
    init: Option<u32>,
    /// Its init has exited, so no task may join it (Linux clears
    /// `PIDNS_ADDING`).
    closed: bool,
}
impl Numbers {
    /// The next number after the last handed out that no task has, as
    /// `idr_alloc_cyclic` skips those `set_tid` took; `EAGAIN` past
    /// `i32::MAX`.
    fn next_free(&mut self) -> Result<u32, Errno> {
        let mut number = self.last;
        loop {
            number = number
                .checked_add(1)
                .filter(|&n| n <= i32::MAX as u32)
                .ok_or(Errno::EAGAIN)?;
            if !self.by_number.contains_key(&number) {
                self.last = number;
                return Ok(number);
            }
        }
    }
}
impl Namespace {
    fn numbers(&self) -> std::sync::MutexGuard<'_, Numbers> {
        self.pids
            .numbers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether this is the first PID namespace.
    pub(crate) fn is_first(&self) -> bool {
        self.pids.parent.is_none()
    }
    /// The number this PID namespace knows task `id` by (Linux's
    /// `pid_nr_ns`): 0 for a task outside it, and for 0.
    pub(crate) fn number(&self, id: u32) -> u32 {
        if self.is_first() {
            return id;
        }
        self.numbers().by_task.get(&id).copied().unwrap_or(0)
    }
    /// The task this PID namespace numbers `number`, by its ID in the
    /// emulator (`find_pid_ns`); `None` for 0 and for a number it has not
    /// handed out.
    pub(crate) fn task(&self, number: u32) -> Option<u32> {
        if number == 0 {
            return None;
        }
        if self.is_first() {
            return Some(number);
        }
        self.numbers().by_number.get(&number).copied()
    }
    /// Whether this PID namespace is `other` or nested within it, so that
    /// `other` numbers every task in it.
    pub(crate) fn is_within(&self, other: &Namespace) -> bool {
        let mut at = self;
        loop {
            if std::ptr::eq(at, other) {
                return true;
            }
            match &at.pids.parent {
                Some(parent) => at = parent,
                None => return false,
            }
        }
    }
    /// The init of this PID namespace, by its ID in the emulator: the first
    /// process for the first namespace, the task numbered 1 of another.
    pub(crate) fn init(&self) -> Option<u32> {
        if self.is_first() {
            return Some(1);
        }
        self.numbers().init
    }
    /// Its init has exited: no task may join it any more.
    pub(crate) fn close(&self) {
        self.numbers().closed = true;
    }
    /// This PID namespace and each one it is in, from the first down to it,
    /// as Linux's `pid->numbers` holds a task's numbers by level.
    pub(crate) fn levels(&self) -> Vec<&Namespace> {
        let mut levels = vec![self];
        let mut at = self;
        while let Some(parent) = &at.pids.parent {
            levels.push(parent);
            at = parent;
        }
        levels.reverse();
        levels
    }
    /// Gives task `id` a number in this PID namespace and in each one it is
    /// in but the first, as Linux's `alloc_pid`: the numbers of `set_tid`
    /// (`clone3`'s), from this namespace out, then the next free one in
    /// each other. `ENOMEM` when its init has exited (as there, only this
    /// namespace's is looked at), `EEXIST` for a number of `set_tid` that
    /// is taken, and the first task of a namespace is its init. On a
    /// failure it has no number in any.
    pub(crate) fn enter(&self, id: u32, set_tid: &[u32]) -> Result<(), Errno> {
        if self.is_first() {
            return Ok(());
        }
        if self.numbers().closed {
            return Err(Errno::ENOMEM);
        }
        let mut at = self;
        let mut level = 0;
        while let Some(parent) = &at.pids.parent {
            let mut numbers = at.numbers();
            let number = match set_tid.get(level) {
                Some(&number) if numbers.by_number.contains_key(&number) => Err(Errno::EEXIST),
                Some(&number) => Ok(number),
                None => numbers.next_free(),
            };
            let number = match number {
                Ok(number) => number,
                Err(error) => {
                    drop(numbers);
                    self.leave(id);
                    return Err(error);
                }
            };
            numbers.by_task.insert(id, number);
            numbers.by_number.insert(number, id);
            if number == 1 {
                numbers.init = Some(id);
            }
            drop(numbers);
            at = parent;
            level += 1;
        }
        Ok(())
    }
    /// Forgets task `id`, which is gone, in this PID namespace and in each
    /// one it is in (`free_pid`).
    pub(crate) fn leave(&self, id: u32) {
        let mut at = self;
        while let Some(parent) = &at.pids.parent {
            let mut numbers = at.numbers();
            if let Some(number) = numbers.by_task.remove(&id) {
                numbers.by_number.remove(&number);
            }
            drop(numbers);
            at = parent;
        }
    }
}

/// The entries of `/proc/<pid>/ns`, in the order Linux lists them
/// (`ns_entries`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Net,
    Uts,
    Ipc,
    Pid,
    PidForChildren,
    User,
    Mnt,
    Cgroup,
    Time,
    TimeForChildren,
}
pub(crate) const ENTRIES: [Entry; 10] = [
    Entry::Net,
    Entry::Uts,
    Entry::Ipc,
    Entry::Pid,
    Entry::PidForChildren,
    Entry::User,
    Entry::Mnt,
    Entry::Cgroup,
    Entry::Time,
    Entry::TimeForChildren,
];
impl Entry {
    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Entry::Net => b"net",
            Entry::Uts => b"uts",
            Entry::Ipc => b"ipc",
            Entry::Pid => b"pid",
            Entry::PidForChildren => b"pid_for_children",
            Entry::User => b"user",
            Entry::Mnt => b"mnt",
            Entry::Cgroup => b"cgroup",
            Entry::Time => b"time",
            Entry::TimeForChildren => b"time_for_children",
        }
    }
    pub(crate) fn named(name: &[u8]) -> Option<Self> {
        ENTRIES.into_iter().find(|entry| entry.name() == name)
    }
}

/// A thread's namespaces. The ones a child takes (`pid_for_children` and
/// `time_for_children`) are kept apart from the thread's own, as Linux
/// keeps them.
#[derive(Clone, Debug)]
pub(crate) struct Namespaces {
    pub net: Arc<Namespace>,
    pub uts: Arc<Namespace>,
    pub ipc: Arc<Namespace>,
    pub pid: Arc<Namespace>,
    pub pid_for_children: Arc<Namespace>,
    pub user: Arc<Namespace>,
    pub mnt: Arc<Namespace>,
    pub cgroup: Arc<Namespace>,
    pub time: Arc<Namespace>,
    pub time_for_children: Arc<Namespace>,
    /// The next inode number to hand out, which every namespace made from
    /// the first ones shares.
    inodes: Arc<AtomicU32>,
}

/// The first namespaces, which the first process starts in: the host name
/// `paludarium` and the domain name `(none)`, as Linux's default.
impl Default for Namespaces {
    fn default() -> Self {
        let names = UtsNames {
            host: b"paludarium".to_vec(),
            domain: b"(none)".to_vec(),
        };
        let new = |kind, inode| Namespace::new(kind, inode, names.clone());
        let pid = new(Kind::Pid, PID_INIT);
        let time = new(Kind::Time, TIME_INIT);
        Self {
            net: new(Kind::Net, DYNAMIC_FIRST),
            uts: new(Kind::Uts, UTS_INIT),
            ipc: new(Kind::Ipc, IPC_INIT),
            pid_for_children: pid.clone(),
            pid,
            user: Arc::clone(crate::users::first()),
            mnt: new(Kind::Mnt, DYNAMIC_FIRST + 1),
            cgroup: new(Kind::Cgroup, CGROUP_INIT),
            time_for_children: time.clone(),
            time,
            inodes: Arc::new(AtomicU32::new(DYNAMIC_FIRST + 2)),
        }
    }
}

impl Namespaces {
    /// The namespace an entry of `/proc/<pid>/ns` names.
    pub(crate) fn entry(&self, entry: Entry) -> &Arc<Namespace> {
        match entry {
            Entry::Net => &self.net,
            Entry::Uts => &self.uts,
            Entry::Ipc => &self.ipc,
            Entry::Pid => &self.pid,
            Entry::PidForChildren => &self.pid_for_children,
            Entry::User => &self.user,
            Entry::Mnt => &self.mnt,
            Entry::Cgroup => &self.cgroup,
            Entry::Time => &self.time,
            Entry::TimeForChildren => &self.time_for_children,
        }
    }
    fn fresh(&self, from: &Namespace, owner: &Arc<Namespace>) -> Arc<Namespace> {
        let inode = self.inodes.fetch_add(1, Ordering::SeqCst);
        Namespace::within(
            from.kind,
            inode,
            from.names(),
            Pids::default(),
            Some(Arc::clone(owner)),
        )
    }
    /// The next inode number, for a new user namespace.
    pub(crate) fn next_inode(&self) -> u32 {
        self.inodes.fetch_add(1, Ordering::SeqCst)
    }
    /// The namespaces with new ones for the [`SUPPORTED`] flags in `flags`,
    /// as Linux's `create_new_namespaces`: a new UTS namespace starts with
    /// a copy of the names, and new time and PID namespaces are the ones
    /// children take, made from the ones they took before. As
    /// `copy_pid_ns`, a new PID namespace is `EINVAL` while the children
    /// already take another than the thread's own, and `ENOSPC` beyond
    /// [`MAX_PID_LEVEL`]; that is checked before anything is made. The new
    /// ones are `owner`'s, the user namespace of the thread that makes them.
    pub(crate) fn unshared(&self, flags: u64, owner: &Arc<Namespace>) -> Result<Self, Errno> {
        if flags & CLONE_NEWPID != 0 {
            if !Arc::ptr_eq(&self.pid, &self.pid_for_children) {
                return Err(Errno::EINVAL);
            }
            // The level Linux gives the new one, the first being 0.
            if self.pid.pids.depth + 1 > MAX_PID_LEVEL {
                return Err(Errno(28)); // ENOSPC
            }
        }
        let mut new = self.clone();
        if flags & CLONE_NEWUTS != 0 {
            new.uts = self.fresh(&self.uts, owner);
        }
        if flags & CLONE_NEWIPC != 0 {
            new.ipc = self.fresh(&self.ipc, owner);
        }
        if flags & CLONE_NEWNS != 0 {
            new.mnt = self.fresh(&self.mnt, owner);
        }
        if flags & CLONE_NEWPID != 0 {
            let inode = self.inodes.fetch_add(1, Ordering::SeqCst);
            let pids = Pids {
                parent: Some(self.pid.clone()),
                depth: self.pid.pids.depth + 1,
                numbers: Mutex::default(),
            };
            new.pid_for_children = Namespace::within(
                Kind::Pid,
                inode,
                self.pid.names(),
                pids,
                Some(Arc::clone(owner)),
            );
        }
        if flags & CLONE_NEWCGROUP != 0 {
            new.cgroup = self.fresh(&self.cgroup, owner);
        }
        if flags & CLONE_NEWNET != 0 {
            new.net = self.fresh(&self.net, owner);
            let network = Arc::new(crate::inet::Network::isolated(owner));
            let _ = new.net.sockets.network.set(network);
        }
        if flags & CLONE_NEWTIME != 0 {
            new.time_for_children = self.fresh(&self.time_for_children, owner);
        }
        Ok(new)
    }
    /// A child's namespaces, as Linux's `copy_namespaces`: new ones for
    /// `flags`; the PID namespace children take, which numbers the child;
    /// and, for a child that does not share the memory (`timens_on_fork`),
    /// the time namespace children take.
    pub(crate) fn for_child(
        &self,
        flags: u64,
        shares_memory: bool,
        owner: &Arc<Namespace>,
    ) -> Result<Self, Errno> {
        let mut new = self.unshared(flags, owner)?;
        if !shares_memory {
            new.time = new.time_for_children.clone();
        }
        new.pid = new.pid_for_children.clone();
        Ok(new)
    }
    /// After exec, as Linux's `exec_task_namespaces`: the program runs in
    /// the time namespace children take.
    pub(crate) fn exec(&self) -> Self {
        let mut new = self.clone();
        new.time = new.time_for_children.clone();
        new
    }
}

/// An open namespace file of `/proc/<pid>/ns` (Linux's nsfs): only a handle
/// for `setns`. Reading or writing it is `EINVAL` (`EBADF` for an access
/// it was not opened for) and seeking `ESPIPE`.
pub(crate) struct NamespaceFile {
    pub namespace: Arc<Namespace>,
    flags: AtomicU32,
}
impl NamespaceFile {
    pub(crate) fn new(namespace: Arc<Namespace>, flags: u32) -> Self {
        Self {
            namespace,
            flags: AtomicU32::new(flags),
        }
    }
}
/// The device of namespace files, as Linux's nsfs has its own.
pub(crate) const DEVICE: u64 = crate::files::Internal::Nsfs.device();
/// The `stat` of a namespace file: a 0444 regular file of no size, whose
/// inode is the namespace's number.
pub(crate) fn file_stat(namespace: &Namespace) -> FileStat {
    FileStat {
        mode: 0o100_444,
        links: 1,
        inode: u64::from(namespace.inode),
        ..FileStat::default()
    }
}
impl FileHandle for NamespaceFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(if self.flags() & 3 == 1 {
            Errno::EBADF
        } else {
            Errno::EINVAL
        })
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.flags() & 3 == 0 {
            Errno::EBADF
        } else {
            Errno::EINVAL
        })
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(file_stat(&self.namespace))
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
        self.flags.store(flags, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_namespaces_read_as_linux_numbers_them() {
        let first = Namespaces::default();
        assert_eq!(first.uts.link(), b"uts:[4026531838]");
        assert_eq!(first.ipc.link(), b"ipc:[4026531839]");
        assert_eq!(first.user.link(), b"user:[4026531837]");
        assert_eq!(first.pid.link(), b"pid:[4026531836]");
        assert_eq!(first.cgroup.link(), b"cgroup:[4026531835]");
        assert_eq!(first.time.link(), b"time:[4026531834]");
        assert_eq!(first.net.link(), b"net:[4026531840]");
        assert_eq!(first.mnt.link(), b"mnt:[4026531841]");
        assert!(Arc::ptr_eq(&first.time, &first.time_for_children));
        assert!(Arc::ptr_eq(&first.pid, &first.pid_for_children));
    }

    #[test]
    fn unsharing_makes_new_namespaces_of_only_the_flags() {
        let first = Namespaces::default();
        let new = first
            .unshared(CLONE_NEWUTS | CLONE_NEWNS, crate::users::first())
            .unwrap();
        assert!(!Arc::ptr_eq(&first.uts, &new.uts));
        assert!(!Arc::ptr_eq(&first.mnt, &new.mnt));
        assert!(Arc::ptr_eq(&first.ipc, &new.ipc));
        assert!(Arc::ptr_eq(&first.cgroup, &new.cgroup));
        assert_ne!(new.uts.inode, new.mnt.inode);
        // A new UTS namespace starts with the old names, then keeps its own.
        assert_eq!(new.uts.names(), first.uts.names());
        new.uts.set_host(b"inside");
        assert_eq!(first.uts.names().host, b"paludarium");
        assert_eq!(new.uts.names().host, b"inside");
    }

    #[test]
    fn a_new_time_namespace_is_for_children() {
        let first = Namespaces::default();
        let new = first
            .unshared(CLONE_NEWTIME, crate::users::first())
            .unwrap();
        assert!(Arc::ptr_eq(&first.time, &new.time));
        assert!(!Arc::ptr_eq(&new.time, &new.time_for_children));
        // A fork enters it; a child sharing the memory (vfork, a thread)
        // does not, until it runs a program.
        let forked = new.for_child(0, false, crate::users::first()).unwrap();
        assert!(Arc::ptr_eq(&forked.time, &new.time_for_children));
        let shared = new.for_child(0, true, crate::users::first()).unwrap();
        assert!(Arc::ptr_eq(&shared.time, &first.time));
        assert!(Arc::ptr_eq(&shared.exec().time, &new.time_for_children));
    }

    #[test]
    fn pid_namespaces_nest_32_levels_below_the_first() {
        let mut at = Namespaces::default();
        for _ in 0..MAX_PID_LEVEL {
            at = at
                .for_child(CLONE_NEWPID, false, crate::users::first())
                .unwrap();
        }
        assert_eq!(at.pid.pids.depth, 32);
        assert_eq!(
            at.unshared(CLONE_NEWPID, crate::users::first())
                .unwrap_err(),
            Errno(28)
        );
    }

    #[test]
    fn a_task_has_a_number_in_each_namespace_it_is_in() {
        let outer = Namespaces::default()
            .for_child(CLONE_NEWPID, false, crate::users::first())
            .unwrap();
        let inner = outer
            .for_child(CLONE_NEWPID, false, crate::users::first())
            .unwrap();
        inner.pid.enter(7, &[]).unwrap();
        assert_eq!((inner.pid.number(7), outer.pid.number(7)), (1, 1));
        assert_eq!(inner.pid.init(), Some(7));
        inner.pid.enter(9, &[]).unwrap();
        assert_eq!(inner.pid.task(2), Some(9));
        inner.pid.leave(9);
        assert_eq!((inner.pid.number(9), outer.pid.number(9)), (0, 0));
        inner.pid.close();
        assert_eq!(inner.pid.enter(11, &[]), Err(Errno::ENOMEM));
        assert_eq!(outer.pid.number(11), 0);
    }

    #[test]
    fn namespace_files_are_only_handles() {
        let first = Namespaces::default();
        let file = NamespaceFile::new(first.uts.clone(), 0);
        assert_eq!(file.read(&mut [0; 4]), Err(Errno::EINVAL));
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        assert_eq!(file.seek(0, 0), Err(Errno::ESPIPE));
        let stat = file.stat().unwrap();
        assert_eq!((stat.mode, stat.inode), (0o100_444, 4_026_531_838));
        assert_eq!(
            Entry::named(b"time_for_children"),
            Some(Entry::TimeForChildren)
        );
        assert_eq!(Entry::named(b"nope"), None);
    }
}
