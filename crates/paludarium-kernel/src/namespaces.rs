//! A thread's namespaces, as Linux's `nsproxy` with the user and PID
//! namespaces beside it: each thread has its own set, which `clone`,
//! `unshare` and `setns` change and `/proc/<pid>/ns` shows. The UTS
//! namespace holds the host and domain names that `uname` reports, and the
//! IPC namespace the System V shared memory segments; the mount, cgroup and
//! time namespaces have nothing in them that paludarium keeps apart (there
//! is no `mount`, no cgroup file and no clock offset), so a new one differs
//! only in its identity. The network,
//! PID and user namespaces are the first ones only.
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) const CLONE_NEWTIME: u64 = 0x80;
pub(crate) const CLONE_NEWNS: u64 = 0x2_0000;
pub(crate) const CLONE_NEWCGROUP: u64 = 0x200_0000;
pub(crate) const CLONE_NEWUTS: u64 = 0x400_0000;
pub(crate) const CLONE_NEWIPC: u64 = 0x800_0000;
pub(crate) const CLONE_NEWUSER: u64 = 0x1000_0000;
pub(crate) const CLONE_NEWPID: u64 = 0x2000_0000;
pub(crate) const CLONE_NEWNET: u64 = 0x4000_0000;
/// The namespaces a thread can have new ones of here.
pub(crate) const SUPPORTED: u64 =
    CLONE_NEWTIME | CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC;
/// Every namespace flag; those not in [`SUPPORTED`] are `EINVAL`, as from a
/// kernel built without them.
pub(crate) const ALL: u64 = SUPPORTED | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;
/// `clone3`'s `CLONE_NEWTIME`, which is a bit of the exit signal in
/// `clone`'s flags, as `clone3` passes it on to the `clone` it runs.
pub(crate) const CLONE3_NEWTIME: u64 = 1 << 40;

/// The namespace checks of `clone` and `unshare`, as Linux's
/// `copy_namespaces` and `unshare_nsproxy_namespaces` make them:
/// `CLONE_NEWUSER`, which needs no capability, is `EINVAL`, as from a kernel
/// without user namespaces; the rest need CAP_SYS_ADMIN (`EPERM`), and those
/// paludarium has no new ones of are `EINVAL` after that.
pub(crate) fn check(flags: u64, may_administer: bool) -> Result<(), Errno> {
    if flags & ALL == 0 {
        return Ok(());
    }
    if flags & CLONE_NEWUSER != 0 {
        return Err(Errno::EINVAL);
    }
    if !may_administer {
        return Err(Errno::EPERM);
    }
    if flags & ALL & !SUPPORTED != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
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
}
impl Namespace {
    fn new(kind: Kind, inode: u32, names: UtsNames) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inode,
            names: Mutex::new(names),
            shm: crate::shm::Segments::default(),
        })
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
            user: new(Kind::User, USER_INIT),
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
    fn fresh(&self, from: &Namespace) -> Arc<Namespace> {
        let inode = self.inodes.fetch_add(1, Ordering::SeqCst);
        Namespace::new(from.kind, inode, from.names())
    }
    /// The namespaces with new ones for the [`SUPPORTED`] flags in `flags`,
    /// as Linux's `create_new_namespaces`: a new UTS namespace starts with
    /// a copy of the names, and a new time namespace is the one children
    /// take, made from the one they took before.
    pub(crate) fn unshared(&self, flags: u64) -> Self {
        let mut new = self.clone();
        if flags & CLONE_NEWUTS != 0 {
            new.uts = self.fresh(&self.uts);
        }
        if flags & CLONE_NEWIPC != 0 {
            new.ipc = self.fresh(&self.ipc);
        }
        if flags & CLONE_NEWNS != 0 {
            new.mnt = self.fresh(&self.mnt);
        }
        if flags & CLONE_NEWCGROUP != 0 {
            new.cgroup = self.fresh(&self.cgroup);
        }
        if flags & CLONE_NEWTIME != 0 {
            new.time_for_children = self.fresh(&self.time_for_children);
        }
        new
    }
    /// A child's namespaces, as Linux's `copy_namespaces`: new ones for
    /// `flags`, and, for a child that does not share the memory
    /// (`timens_on_fork`), the time namespace children take.
    pub(crate) fn for_child(&self, flags: u64, shares_memory: bool) -> Self {
        let mut new = self.unshared(flags);
        if !shares_memory {
            new.time = new.time_for_children.clone();
        }
        new
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
/// The device of namespace files, as Linux's nsfs has its own: a minor
/// number no mount here takes.
pub(crate) const DEVICE: u64 = 1 << 19;
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
        let new = first.unshared(CLONE_NEWUTS | CLONE_NEWNS);
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
        let new = first.unshared(CLONE_NEWTIME);
        assert!(Arc::ptr_eq(&first.time, &new.time));
        assert!(!Arc::ptr_eq(&new.time, &new.time_for_children));
        // A fork enters it; a child sharing the memory (vfork, a thread)
        // does not, until it runs a program.
        let forked = new.for_child(0, false);
        assert!(Arc::ptr_eq(&forked.time, &new.time_for_children));
        let shared = new.for_child(0, true);
        assert!(Arc::ptr_eq(&shared.time, &first.time));
        assert!(Arc::ptr_eq(&shared.exec().time, &new.time_for_children));
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
