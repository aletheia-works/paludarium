//! POSIX message queues: `mq_open`, `mq_unlink`, `mq_timedsend`,
//! `mq_timedreceive`, `mq_notify` and `mq_getsetattr`, in the calling
//! thread's IPC namespace, as Linux's `ipc/mqueue.c` has them.
//!
//! A queue is a file of the IPC namespace's own `mqueue` filesystem, whose
//! root is a sticky directory anyone may write to: `mq_open` gives a
//! descriptor of it, always close-on-exec, which `poll`, `select` and
//! `epoll` watch (readable with a message, writable with room), `read`
//! shows the queue's state in, and `fork` shares. Its messages are taken
//! highest priority first, and in the order they were sent within one
//! priority. A receiver that finds the queue empty waits in turn, and a
//! message sent then goes straight to the first of them; a sender that
//! finds it full waits with its message, which the first receive then
//! queues. Waits end at an absolute `CLOCK_REALTIME` time (`ETIMEDOUT`) or
//! with a signal (`EINTR`, which a signal that runs no handler or one with
//! `SA_RESTART` restarts).
//!
//! The limits are the IPC namespace's, which its `/proc/sys/fs/mqueue`
//! files show and set ([`crate::sysctl`]), and which a new namespace starts
//! with at Linux's defaults: 256 queues (`queues_max`, `ENOSPC` past it
//! without `CAP_SYS_RESOURCE`), 10 messages (`msg_max`, and the default
//! `msg_default`) and 8192 bytes a message (`msgsize_max` and
//! `msgsize_default`); `CAP_SYS_RESOURCE` raises the former to 65536 and
//! 16 MiB. A queue made without attributes takes the smaller of each default
//! and its limit. Each queue charges its messages' bytes and its
//! bookkeeping against `RLIMIT_MSGQUEUE` (`EMFILE` past it) in each user
//! namespace its creator is in ([`accounts`]).
//!
//! `mq_notify` registers the calling process to hear when a message comes
//! to the empty queue while no receiver waits: by a signal (`SIGEV_SIGNAL`,
//! with `si_code` `SI_MESGQ`), by nothing (`SIGEV_NONE`), or by the
//! 32-byte cookie the caller gave, which goes to its netlink socket
//! (`SIGEV_THREAD`, as the C libraries' helper threads read it), its last
//! byte `NOTIFY_WOKENUP`; one the registration loses without a message
//! goes with `NOTIFY_REMOVED`. Its process closing a descriptor of the
//! queue, or ending, drops the registration.
use crate::events::{IN, NONBLOCK, OUT, ReadinessHub};
use crate::namespaces::Namespace;
use crate::processes::Processes;
use crate::syscalls::{Context, Outcome};
use crate::users::Ids as Kind;
use paludarium_host::{ClockId, FileHandle, FileStat, WaitOutcome, WaitToken};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;

const EBUSY: Errno = Errno(16);
const EINTR: Errno = Errno(4);
const EMSGSIZE: Errno = Errno(90);
const ENOTSOCK: Errno = Errno(88);
const ETIMEDOUT: Errno = Errno(110);

const CAP_SYS_RESOURCE: u64 = 1 << 24;
const CAP_FOWNER: u64 = 1 << 3;

/// `MQ_PRIO_MAX`: priorities are below it.
const MQ_PRIO_MAX: u64 = 32768;
/// An IPC namespace's defaults (`DFLT_QUEUESMAX`, `DFLT_MSGMAX`,
/// `DFLT_MSGSIZEMAX`, which `DFLT_MSG` and `DFLT_MSGSIZE` equal), and the
/// most `CAP_SYS_RESOURCE` allows (`HARD_MSGMAX`, `HARD_MSGSIZEMAX`), which
/// also bound what the sysctls take.
const QUEUES_MAX: i32 = 256;
const MSG_MAX: i32 = 10;
const MSGSIZE_MAX: i32 = 8192;
pub(crate) const HARD_MSGMAX: i32 = 65536;
pub(crate) const HARD_MSGSIZEMAX: i32 = 16 << 20;
/// `sizeof(struct msg_msg)` and `sizeof(struct posix_msg_tree_node)` on
/// x86-64, which a queue charges for each message it may hold.
const MSG_MSG_SIZE: u64 = 48;
const TREE_NODE_SIZE: u64 = 48;
/// The size a queue's file reports (`FILENT_SIZE`), and the most its state
/// line takes.
const FILENT_SIZE: usize = 80;
/// `struct mq_attr` and `struct sigevent`.
const ATTR_SIZE: usize = 64;
const SIGEVENT_SIZE: usize = 64;
/// How `mq_notify` tells (`SIGEV_*`).
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
/// The cookie of `SIGEV_THREAD`, and what its last byte says.
const NOTIFY_COOKIE_LEN: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;
/// `si_code` of a queue's notification.
pub(crate) const SI_MESGQ: i32 = -3;
/// Linux's largest time, which a later one saturates to.
const KTIME_MAX: u64 = i64::MAX as u64;
const S_IFREG: u32 = 0o100_000;
const S_IFSOCK: u32 = 0o140_000;
const S_IFMT: u32 = 0o170_000;

/// A count of `RLIMIT_MSGQUEUE` bytes: a user namespace, by its inode, and
/// a kernel user ID (Linux's `ucounts`).
type Account = (u32, u32);

/// Where a queue charges its bytes, from the creator's count up through
/// the user namespaces it is in, and the most each may hold: the
/// creator's (real user ID, its user namespace) up to its
/// `RLIMIT_MSGQUEUE`, then each namespace's owner in the parent, up to the
/// limit the owner had when it made the namespace (`inc_rlimit_ucounts`).
pub(crate) fn accounts(
    credentials: &crate::credentials::Credentials,
    limit: u64,
) -> Vec<(Account, u64)> {
    let mut accounts = vec![((credentials.user.0.inode, credentials.uid), limit)];
    let mut user = &credentials.user.0;
    while let Some(parent) = user.users.parent() {
        accounts.push((
            (parent.inode, user.users.owner()),
            user.users.msgqueue_max(),
        ));
        user = parent;
    }
    accounts
}

/// The bytes the users' queues charge against `RLIMIT_MSGQUEUE` (Linux's
/// `UCOUNT_RLIMIT_MSGQUEUE`), by [`Account`], for the whole machine.
#[derive(Default)]
pub(crate) struct Charges(Mutex<BTreeMap<Account, u64>>);

impl Charges {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<Account, u64>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Charges each of `accounts` for `bytes`, as `inc_rlimit_ucounts`:
    /// `false`, with nothing charged, when one would pass its most or what
    /// Linux's counter, a `long`, cannot hold.
    fn charge(&self, accounts: &[(Account, u64)], bytes: u64) -> bool {
        let mut charges = self.lock();
        let fits = accounts.iter().all(|&(account, most)| {
            let charged = charges.get(&account).copied().unwrap_or_default();
            charged
                .checked_add(bytes)
                .is_some_and(|total| total <= most && total < i64::MAX as u64)
        });
        if fits {
            for &(account, _) in accounts {
                *charges.entry(account).or_default() += bytes;
            }
        }
        fits
    }
    fn release(&self, accounts: &[(Account, u64)], bytes: u64) {
        let mut charges = self.lock();
        for (account, _) in accounts {
            if let Some(charged) = charges.get_mut(account) {
                *charged = charged.saturating_sub(bytes);
                if *charged == 0 {
                    charges.remove(account);
                }
            }
        }
    }
}

/// The queues of an IPC namespace: its `mqueue` filesystem's names, and
/// how many queues there are, named or still open (`mq_queues_count`).
#[derive(Clone, Default)]
pub(crate) struct Queues(Arc<Table>);

impl std::fmt::Debug for Queues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Queues")
    }
}

#[derive(Default)]
struct Table {
    names: Mutex<BTreeMap<Vec<u8>, Arc<Queue>>>,
    count: Arc<AtomicUsize>,
    limits: Limits,
}

/// An IPC namespace's limits and defaults, as its `/proc/sys/fs/mqueue`
/// files have them (`mq_queues_max`, `mq_msg_max`, `mq_msgsize_max`,
/// `mq_msg_default`, `mq_msgsize_default`): each an `int`, which
/// `queues_max` compares as unsigned.
pub(crate) struct Limits {
    pub(crate) queues_max: AtomicI32,
    pub(crate) msg_max: AtomicI32,
    pub(crate) msgsize_max: AtomicI32,
    pub(crate) msg_default: AtomicI32,
    pub(crate) msgsize_default: AtomicI32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            queues_max: AtomicI32::new(QUEUES_MAX),
            msg_max: AtomicI32::new(MSG_MAX),
            msgsize_max: AtomicI32::new(MSGSIZE_MAX),
            msg_default: AtomicI32::new(MSG_MAX),
            msgsize_default: AtomicI32::new(MSGSIZE_MAX),
        }
    }
}

impl Queues {
    /// The namespace's limits.
    pub(crate) fn limits(&self) -> &Limits {
        &self.0.limits
    }
}

impl Table {
    fn names(&self) -> MutexGuard<'_, BTreeMap<Vec<u8>, Arc<Queue>>> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What a queue's registration tells.
enum Notice {
    None,
    Signal {
        number: i32,
        value: u64,
    },
    Thread {
        socket: Arc<dyn FileHandle>,
        cookie: [u8; NOTIFY_COOKIE_LEN],
    },
}

/// The process `mq_notify` registered (`notify_owner`), as many `exec`s in
/// as it was then (`notify_self_exec_id`), and its user namespace, which
/// shows the sender's user ID.
struct Registration {
    owner: u32,
    execs: u64,
    user: crate::users::UserNs,
    notice: Notice,
}

impl Registration {
    fn kind(&self) -> i32 {
        match self.notice {
            Notice::None => SIGEV_NONE,
            Notice::Signal { .. } => SIGEV_SIGNAL,
            Notice::Thread { .. } => SIGEV_THREAD,
        }
    }
    /// Gives up the registration without a message (`remove_notification`):
    /// a `SIGEV_THREAD` socket is told `NOTIFY_REMOVED`.
    fn remove(self) {
        if let Notice::Thread { socket, mut cookie } = self.notice {
            cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_REMOVED;
            if let Some(socket) = crate::netlink::of(&socket) {
                socket.attach(cookie.to_vec());
            }
        }
    }
}

/// What a waiting receiver or sender is told: nothing yet, or that its
/// message was taken or given (`STATE_READY`).
#[derive(Default)]
struct Waiter {
    /// A receiver's message, once given, or a sender's, until taken.
    message: Mutex<Option<(u32, Vec<u8>)>>,
    ready: AtomicBool,
}

impl Waiter {
    fn message(&self) -> MutexGuard<'_, Option<(u32, Vec<u8>)>> {
        self.message.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct State {
    /// By priority, each in the order sent.
    messages: BTreeMap<u32, VecDeque<Vec<u8>>>,
    /// How many there are (`mq_curmsgs`) and their bytes (`qsize`).
    count: i64,
    bytes: u64,
    receivers: VecDeque<Arc<Waiter>>,
    senders: VecDeque<Arc<Waiter>>,
    registration: Option<Registration>,
    /// Bumped whenever Linux wakes the queue's pollers, so edge-triggered
    /// `epoll` sees each change.
    epoch: u64,
}

impl State {
    /// Drops the registration of process `pid`, if it has the queue's
    /// (`remove_notification`).
    fn unregister(&mut self, pid: u32) {
        if self
            .registration
            .as_ref()
            .is_some_and(|registration| registration.owner == pid)
            && let Some(registration) = self.registration.take()
        {
            registration.remove();
        }
    }
    fn insert(&mut self, priority: u32, text: Vec<u8>) {
        self.count += 1;
        self.bytes += text.len() as u64;
        self.messages.entry(priority).or_default().push_back(text);
    }
    /// The first message of the highest priority (`msg_get`).
    fn take(&mut self) -> Option<(u32, Vec<u8>)> {
        let mut entry = self.messages.last_entry()?;
        let priority = *entry.key();
        let text = entry.get_mut().pop_front()?;
        if entry.get().is_empty() {
            entry.remove();
        }
        self.count -= 1;
        self.bytes -= text.len() as u64;
        Some((priority, text))
    }
}

/// A queue: its attributes, its file's owner and mode, and its state
/// (`struct mqueue_inode_info`).
pub(crate) struct Queue {
    maxmsg: i64,
    msgsize: i64,
    /// Its name in the `mqueue` filesystem, and whether that still names it.
    name: Vec<u8>,
    linked: AtomicBool,
    uid: AtomicU32,
    gid: AtomicU32,
    mode: AtomicU32,
    inode: u64,
    created: i128,
    state: Mutex<State>,
    /// Notified whenever a waiter is told, or the queue changes.
    token: WaitToken,
    hub: Arc<ReadinessHub>,
    processes: Weak<Processes>,
    /// What it is counted and charged in, released when the queue goes.
    count: Arc<AtomicUsize>,
    charges: Arc<Charges>,
    charged: (Vec<(Account, u64)>, u64),
}

impl Drop for Queue {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
        self.charges.release(&self.charged.0, self.charged.1);
    }
}

impl Queue {
    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // A registration lasts no longer than its process; a `SIGEV_THREAD`
        // socket is told it is removed, as the process's last close tells it.
        if state.registration.as_ref().is_some_and(|registration| {
            !self
                .processes
                .upgrade()
                .is_some_and(|processes| processes.execs(registration.owner).is_some())
        }) && let Some(registration) = state.registration.take()
        {
            registration.remove();
        }
        state
    }
    fn changed(&self, state: &mut State) {
        state.epoch = state.epoch.wrapping_add(1);
        self.token.notify();
        self.hub.changed();
    }
    fn stat(&self) -> FileStat {
        FileStat {
            inode: self.inode,
            size: FILENT_SIZE as u64,
            mode: S_IFREG | self.mode.load(Ordering::SeqCst),
            uid: self.uid.load(Ordering::SeqCst),
            gid: self.gid.load(Ordering::SeqCst),
            links: 1,
            mtime_ns: self.created,
            ..FileStat::default()
        }
    }
    /// Tells the registered process of a message that came to the empty
    /// queue from process `sender` with real user ID `uid`, and drops the
    /// registration (`__do_notify`), then wakes the pollers.
    fn notify(&self, state: &mut State, sender: u32, uid: u32) {
        if state.count == 1
            && let Some(registration) = state.registration.take()
        {
            match registration.notice {
                Notice::None => {}
                // A signal of 0 is accepted, and sends nothing.
                Notice::Signal { number: 0, .. } => {}
                Notice::Signal { number, value } => {
                    let uid = registration.user.shown(Kind::User, uid);
                    if let Some(processes) = self.processes.upgrade() {
                        processes.notify_message_queue(
                            registration.owner,
                            registration.execs,
                            number,
                            sender,
                            uid,
                            value,
                        );
                    }
                }
                Notice::Thread { socket, mut cookie } => {
                    cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_WOKENUP;
                    if let Some(socket) = crate::netlink::of(&socket) {
                        socket.attach(cookie.to_vec());
                    }
                }
            }
        }
        self.changed(state);
    }
    /// The state line `read` gives (`mqueue_read_file`), with the
    /// registered process as `space` numbers it.
    fn line(&self, space: &Namespace) -> Vec<u8> {
        let state = self.lock();
        let (kind, signal, pid) = state.registration.as_ref().map_or((0, 0, 0), |r| {
            let signal = match r.notice {
                Notice::Signal { number, .. } => number,
                _ => 0,
            };
            (r.kind(), signal, space.number(r.owner))
        });
        let mut line = format!(
            "QSIZE:{:<10} NOTIFY:{kind:<5} SIGNO:{signal:<5} NOTIFY_PID:{pid:<6}\n",
            state.bytes
        )
        .into_bytes();
        line.truncate(FILENT_SIZE - 1);
        line
    }
}

/// An open queue: a descriptor's file (`mqueue_file_operations`).
pub(crate) struct QueueFile {
    queue: Arc<Queue>,
    /// The access mode and `O_NONBLOCK`.
    flags: AtomicU32,
    position: AtomicU64,
    /// The PID namespace of whoever opened it, which `read` numbers the
    /// registered process in.
    space: Arc<Namespace>,
}

impl QueueFile {
    /// What its link in `/proc/self/fd` reads: the queue's path in its
    /// filesystem, marked ` (deleted)` once unlinked.
    pub(crate) fn link_target(&self) -> Vec<u8> {
        let mut path = [b"/", self.queue.name.as_slice()].concat();
        if !self.queue.linked.load(Ordering::SeqCst) {
            path.extend_from_slice(b" (deleted)");
        }
        path
    }
    fn readable(&self) -> bool {
        matches!(self.flags() & O_ACCMODE, 0 | 2)
    }
    fn writable(&self) -> bool {
        matches!(self.flags() & O_ACCMODE, 1 | 2)
    }
    fn nonblocking(&self) -> bool {
        self.flags() & NONBLOCK != 0
    }
}

impl FileHandle for QueueFile {
    /// `mqueue_poll_file`: readable with a message, writable with room,
    /// whatever the access mode.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let state = self.queue.lock();
        let mut mask = 0;
        if state.count != 0 {
            mask |= IN;
        }
        if state.count < self.queue.maxmsg {
            mask |= OUT;
        }
        Ok((mask, state.epoch, state.epoch))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.readable() {
            return Err(Errno::EBADF);
        }
        let line = self.queue.line(&self.space);
        let at = usize::try_from(self.position.load(Ordering::SeqCst)).unwrap_or(usize::MAX);
        let Some(rest) = line.get(at..) else {
            return Ok(0);
        };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.position.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
    /// It has no `write` (`EINVAL`), once the access mode lets it write.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        if self.writable() {
            Err(Errno::EINVAL)
        } else {
            Err(Errno::EBADF)
        }
    }
    /// `default_llseek`, whose end is the file's size.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let base = match whence {
            0 => 0,
            1 => self.position.load(Ordering::SeqCst) as i64,
            2 => FILENT_SIZE as i64,
            _ => return Err(Errno::EINVAL),
        };
        let position = base.checked_add(offset).ok_or(Errno::EINVAL)?;
        if position < 0 {
            return Err(Errno::EINVAL);
        }
        self.position.store(position as u64, Ordering::SeqCst);
        Ok(position as u64)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.queue.stat())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    /// `fchmod` and `fchown` change the queue's file, as on Linux.
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.queue.mode.store(mode & 0o7777, Ordering::SeqCst);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        if let Some(uid) = uid {
            self.queue.uid.store(uid, Ordering::SeqCst);
        }
        if let Some(gid) = gid {
            self.queue.gid.store(gid, Ordering::SeqCst);
        }
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        let mode = self.flags() & O_ACCMODE;
        self.flags.store(mode | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}

fn result(value: Result<u64, Errno>) -> Outcome {
    Outcome::Return(value.unwrap_or_else(Errno::to_syscall_return))
}

/// The queues of the calling thread's IPC namespace.
fn queues(c: &Context<'_>) -> Queues {
    c.group.namespaces(c.tid).ipc.mq.clone()
}

/// A name as `getname` reads it: `EFAULT`, `ENAMETOOLONG` from 4096 bytes,
/// `ENOENT` for an empty one.
fn name(c: &Context<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    let name = crate::files::string(c, addr)?;
    if name.is_empty() {
        return Err(Errno::ENOENT);
    }
    Ok(name)
}

/// The `mqueue` root's lookup of `name` (`lookup_noperm` and
/// `simple_lookup`): `EACCES` for `.`, `..` or one with a `/`,
/// `ENAMETOOLONG` past 255 bytes.
fn look_up(name: &[u8]) -> Result<(), Errno> {
    if name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Errno::EACCES);
    }
    if name.len() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

/// The queue `fd` opens: `EBADF` for no descriptor or another file.
fn queue_file(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(u64::from(fd as u32))?.file;
    file.as_any()
        .is_some_and(|any| any.is::<QueueFile>())
        .then_some(file)
        .ok_or(Errno::EBADF)
}

fn as_queue(file: &Arc<dyn FileHandle>) -> &QueueFile {
    file.as_any()
        .and_then(|any| any.downcast_ref::<QueueFile>())
        .unwrap_or_else(|| unreachable!("checked by queue_file()"))
}

/// `mq_open(name, oflag, mode, attr)`, in Linux's order (`do_mq_open`,
/// `prepare_open`, `mqueue_create_attr`, `mqueue_get_inode`): the
/// attributes are read (`EFAULT`), then the name ([`name`]), a descriptor
/// (`EMFILE`). A name not in use is `ENOENT` without `O_CREAT`; with it, a
/// new queue past `queues_max` is `ENOSPC`, attributes of no messages or
/// bytes, or past the limits, `EINVAL`, and past `RLIMIT_MSGQUEUE`
/// `EMFILE`. A name in use is `EEXIST` with
/// `O_CREAT | O_EXCL`, an access mode of 3 `EINVAL`, and a mode its
/// permissions do not grant `EACCES`.
pub(crate) fn sys_mq_open(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_open(c, a[0], a[1] as u32, a[2] as u32 & 0o7777, a[3]))
}

fn mq_open(c: &mut Context<'_>, at: u64, flags: u32, mode: u32, attr: u64) -> Result<u64, Errno> {
    let attr = if attr == 0 {
        None
    } else {
        let mut bytes = [0u8; ATTR_SIZE];
        c.mem
            .read(GuestAddr(attr), &mut bytes)
            .map_err(|_| Errno::EFAULT)?;
        let field =
            |at: usize| i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default());
        Some((field(8), field(16)))
    };
    let name = name(c, at)?;
    // `get_unused_fd_flags`: a descriptor, before anything else.
    let fd = c.files.reserve(c.group.nofile())?;
    let opened = open_queue(c, &name, flags, mode, attr);
    let queue = match opened {
        Ok(queue) => queue,
        Err(error) => {
            c.files.unreserve(fd);
            return Err(error);
        }
    };
    let file = Arc::new(QueueFile {
        queue,
        flags: AtomicU32::new(flags & (O_ACCMODE | NONBLOCK)),
        position: AtomicU64::new(0),
        space: c.pid_space(),
    });
    c.files.fill_opened(fd, file, Vec::new(), true);
    Ok(u64::from(fd))
}

/// The queue `name` names, made with `O_CREAT` if there is none.
fn open_queue(
    c: &Context<'_>,
    name: &[u8],
    flags: u32,
    mode: u32,
    attr: Option<(i64, i64)>,
) -> Result<Arc<Queue>, Errno> {
    look_up(name)?;
    let queues = queues(c);
    let mut names = queues.0.names();
    if let Some(queue) = names.get(name) {
        if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
            return Err(Errno::EEXIST);
        }
        if flags & O_ACCMODE == 3 {
            return Err(Errno::EINVAL);
        }
        // `inode_permission` with MAY_READ, MAY_WRITE or both.
        let mask = [4, 2, 6][(flags & O_ACCMODE) as usize];
        crate::permissions::permission(&c.process.credentials, &queue.stat(), mask)?;
        return Ok(Arc::clone(queue));
    }
    if flags & O_CREAT == 0 {
        return Err(Errno::ENOENT);
    }
    // `vfs_mkobj` keeps the set-ID and sticky bits.
    let mode = mode & !c.files.umask() & 0o7777;
    let queue = Arc::new(create(c, &queues, name, mode, attr)?);
    names.insert(name.to_vec(), Arc::clone(&queue));
    Ok(queue)
}

/// A new queue with permissions `mode` and attributes `attr` (the most
/// messages and bytes of one), else the defaults.
fn create(
    c: &Context<'_>,
    queues: &Queues,
    name: &[u8],
    mode: u32,
    attr: Option<(i64, i64)>,
) -> Result<Queue, Errno> {
    let credentials = &c.process.credentials;
    let resource = credentials.capable(CAP_SYS_RESOURCE);
    let count = &queues.0.count;
    let limit = |value: &AtomicI32| i64::from(value.load(Ordering::SeqCst));
    let limits = queues.limits();
    let queues_max = limits.queues_max.load(Ordering::SeqCst) as u32;
    if count.load(Ordering::SeqCst) >= queues_max as usize && !resource {
        return Err(Errno::ENOSPC);
    }
    let (msg_max, msgsize_max) = (limit(&limits.msg_max), limit(&limits.msgsize_max));
    let (maxmsg, msgsize) = attr.unwrap_or((
        msg_max.min(limit(&limits.msg_default)),
        msgsize_max.min(limit(&limits.msgsize_default)),
    ));
    if maxmsg <= 0 || msgsize <= 0 {
        return Err(Errno::EINVAL);
    }
    let (most, largest) = if resource {
        (i64::from(HARD_MSGMAX), i64::from(HARD_MSGSIZEMAX))
    } else {
        (msg_max, msgsize_max)
    };
    if maxmsg > most || msgsize > largest {
        return Err(Errno::EINVAL);
    }
    // Both are positive and within the hard limits, so nothing overflows.
    let (maxmsg_u, msgsize_u) = (maxmsg as u64, msgsize as u64);
    let bytes =
        maxmsg_u * msgsize_u + maxmsg_u * MSG_MSG_SIZE + maxmsg_u.min(MQ_PRIO_MAX) * TREE_NODE_SIZE;
    let charges = Arc::clone(&c.processes.mqueue_charges);
    let accounts = accounts(credentials, c.processes.soft_limit(c.process.pid, 12));
    if !charges.charge(&accounts, bytes) {
        return Err(Errno::EMFILE);
    }
    count.fetch_add(1, Ordering::SeqCst);
    let created = c.host.clock(ClockId::Realtime).map_or(0, i128::from);
    Ok(Queue {
        maxmsg,
        msgsize,
        name: name.to_vec(),
        linked: AtomicBool::new(true),
        uid: AtomicU32::new(credentials.fsuid),
        gid: AtomicU32::new(credentials.fsgid),
        mode: AtomicU32::new(mode),
        inode: crate::files::anonymous_inode(),
        created,
        state: Mutex::default(),
        token: WaitToken::default(),
        hub: Arc::clone(&c.files.readiness),
        processes: Arc::downgrade(c.processes),
        count: Arc::clone(count),
        charges,
        charged: (accounts, bytes),
    })
}

/// `mq_unlink(name)`: the name ([`name`]), `ENOENT` for one not in use,
/// then `vfs_unlink`'s checks on the sticky root, which only the queue's
/// owner, the root's (root) or `CAP_FOWNER` passes (`EPERM`). The queue
/// lasts while it is open.
pub(crate) fn sys_mq_unlink(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_unlink(c, a[0]))
}

fn mq_unlink(c: &Context<'_>, at: u64) -> Result<u64, Errno> {
    let name = name(c, at)?;
    look_up(&name)?;
    let queues = queues(c);
    let mut names = queues.0.names();
    let queue = names.get(&name).ok_or(Errno::ENOENT)?;
    let credentials = &c.process.credentials;
    let stat = queue.stat();
    if credentials.fsuid != stat.uid
        && credentials.fsuid != 0
        && !crate::permissions::capable(credentials, &stat, CAP_FOWNER)
    {
        return Err(Errno::EPERM);
    }
    if let Some(queue) = names.remove(&name) {
        queue.linked.store(false, Ordering::SeqCst);
    }
    Ok(0)
}

/// A `struct timespec` timeout at `at`, none for a null one, as
/// `prepare_timeout` reads it (`EFAULT`) and checks it (`EINVAL` for a
/// negative time or nanoseconds past a second): its nanoseconds since the
/// epoch, up to Linux's largest time.
fn timeout(c: &Context<'_>, at: u64) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    let [seconds, nanos] = crate::syscalls::read_words::<2>(c.mem, at)?;
    if (seconds as i64) < 0 || nanos >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(Some(
        seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos)
            .min(KTIME_MAX),
    ))
}

/// `mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)`, in
/// Linux's order (`do_mq_timedsend`): the timeout ([`timeout`]), a priority
/// from `MQ_PRIO_MAX` (`EINVAL`), the queue (`EBADF`), its access mode
/// (`EBADF` without writing), a message past `mq_msgsize` (`EMSGSIZE`), the
/// message (`EFAULT`); then to the first waiting receiver, or into the
/// queue, which tells the registered process if it was empty. A full queue
/// is `EAGAIN` with `O_NONBLOCK`, else a wait for room until the timeout
/// (`ETIMEDOUT`) or a signal (`EINTR`).
pub(crate) fn sys_mq_timedsend(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_timedsend(c, a[0], a[1], a[2], a[3] as u32 as u64, a[4]))
}

fn mq_timedsend(
    c: &mut Context<'_>,
    fd: u64,
    at: u64,
    len: u64,
    priority: u64,
    abs: u64,
) -> Result<u64, Errno> {
    let deadline = timeout(c, abs)?;
    if priority >= MQ_PRIO_MAX {
        return Err(Errno::EINVAL);
    }
    let file = queue_file(c, fd)?;
    let open = as_queue(&file);
    if !open.writable() {
        return Err(Errno::EBADF);
    }
    let queue = &open.queue;
    if len > queue.msgsize as u64 {
        return Err(EMSGSIZE);
    }
    let mut text = vec![0u8; len as usize];
    c.mem
        .read(GuestAddr(at), &mut text)
        .map_err(|_| Errno::EFAULT)?;
    let priority = priority as u32;
    let waiter = {
        let mut state = queue.lock();
        if state.count == queue.maxmsg {
            if open.nonblocking() {
                return Err(Errno::EAGAIN);
            }
            let waiter = Arc::new(Waiter {
                message: Mutex::new(Some((priority, text))),
                ready: AtomicBool::new(false),
            });
            state.senders.push_back(Arc::clone(&waiter));
            waiter
        } else {
            if let Some(receiver) = state.receivers.pop_front() {
                // `pipelined_send`: straight to the receiver.
                *receiver.message() = Some((priority, text));
                receiver.ready.store(true, Ordering::SeqCst);
                queue.token.notify();
            } else {
                state.insert(priority, text);
                queue.notify(&mut state, c.process.pid, c.process.credentials.uid);
            }
            return Ok(0);
        }
    };
    wait(c, queue, &waiter, deadline, false).map(|_| 0)
}

/// `mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)`, in
/// Linux's order (`do_mq_timedreceive`): the timeout ([`timeout`]), the
/// queue (`EBADF`), its access mode (`EBADF` without reading), a buffer
/// smaller than `mq_msgsize` (`EMSGSIZE`); then the first message of the
/// highest priority, the first waiting sender's message taking its place.
/// An empty queue is `EAGAIN` with `O_NONBLOCK`, else a wait for a message
/// until the timeout (`ETIMEDOUT`) or a signal (`EINTR`). The priority and
/// then the message are written (`EFAULT`, the message gone all the same);
/// it returns the message's length.
pub(crate) fn sys_mq_timedreceive(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_timedreceive(c, a[0], a[1], a[2], a[3], a[4]))
}

fn mq_timedreceive(
    c: &mut Context<'_>,
    fd: u64,
    at: u64,
    len: u64,
    priority_at: u64,
    abs: u64,
) -> Result<u64, Errno> {
    let deadline = timeout(c, abs)?;
    let file = queue_file(c, fd)?;
    let open = as_queue(&file);
    if !open.readable() {
        return Err(Errno::EBADF);
    }
    let queue = &open.queue;
    if len < queue.msgsize as u64 {
        return Err(EMSGSIZE);
    }
    let taken = {
        let mut state = queue.lock();
        if let Some(taken) = state.take() {
            // `pipelined_receive`: the first waiting sender's message takes
            // the room, else the pollers hear of it.
            if let Some(sender) = state.senders.pop_front() {
                if let Some((priority, text)) = sender.message().take() {
                    state.insert(priority, text);
                }
                sender.ready.store(true, Ordering::SeqCst);
                queue.token.notify();
            } else {
                queue.changed(&mut state);
            }
            Ok(taken)
        } else if open.nonblocking() {
            return Err(Errno::EAGAIN);
        } else {
            let waiter = Arc::new(Waiter::default());
            state.receivers.push_back(Arc::clone(&waiter));
            Err(waiter)
        }
    };
    let (priority, text) = match taken {
        Ok(taken) => taken,
        Err(waiter) => wait(c, queue, &waiter, deadline, true)?.unwrap_or_default(),
    };
    if priority_at != 0 {
        c.mem
            .write(GuestAddr(priority_at), &priority.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
    }
    c.mem
        .write(GuestAddr(at), &text)
        .map_err(|_| Errno::EFAULT)?;
    Ok(text.len() as u64)
}

/// Waits until `waiter` is told, as Linux's `wq_sleep`: then a receiver
/// has its message. Else it leaves the queue's waiters with `EINTR` for a
/// signal or the end of the thread group, or `ETIMEDOUT` once the realtime
/// clock reaches `deadline`.
fn wait(
    c: &mut Context<'_>,
    queue: &Queue,
    waiter: &Arc<Waiter>,
    deadline: Option<u64>,
    receiving: bool,
) -> Result<Option<(u32, Vec<u8>)>, Errno> {
    let leave = |error: Errno| {
        let mut state = queue.lock();
        if waiter.ready.load(Ordering::SeqCst) {
            return Ok(waiter.message().take());
        }
        let waiters = if receiving {
            &mut state.receivers
        } else {
            &mut state.senders
        };
        waiters.retain(|other| !Arc::ptr_eq(other, waiter));
        Err(error)
    };
    let mut interrupted = false;
    loop {
        let ticket = queue.token.value();
        if waiter.ready.load(Ordering::SeqCst) {
            return Ok(waiter.message().take());
        }
        c.group.drain_process(c.process);
        interrupted |= c.inbox.drain(c.process).interrupted;
        interrupted |= !c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst);
        let now = match c.host.clock(ClockId::Monotonic) {
            Ok(now) => now,
            Err(error) => return leave(error),
        };
        c.group.expire_timer(c.process, now);
        if c.group.status().is_some()
            || crate::signals::next_pending(c.process, true).is_some()
            || interrupted
        {
            return leave(EINTR);
        }
        let mut end = now
            .saturating_add(10_000_000)
            .min(crate::signals::next_deadline(c.process).unwrap_or(u64::MAX));
        if let Some(deadline) = deadline {
            let real = match c.host.clock(ClockId::Realtime) {
                Ok(real) => real,
                Err(error) => return leave(error),
            };
            if real >= deadline {
                return leave(ETIMEDOUT);
            }
            end = end.min(now.saturating_add(deadline - real));
        }
        let outcome = match c.host.wait_on(
            &queue.token,
            ticket,
            Some((ClockId::Monotonic, end)),
            c.cancellation,
        ) {
            Err(error) if error == Errno::ENOSYS => {
                c.host.wait_until(ClockId::Monotonic, end, c.cancellation)
            }
            outcome => outcome,
        };
        match outcome {
            Ok(WaitOutcome::Interrupted) => {
                interrupted |= c.inbox.drain(c.process).interrupted;
            }
            Ok(_) => {}
            Err(error) => return leave(error),
        }
    }
}

/// `mq_notify(mqdes, notification)`, in Linux's order (`do_mq_notify`):
/// the `struct sigevent` is read (`EFAULT`); a `sigev_notify` other than
/// `SIGEV_NONE`, `SIGEV_SIGNAL` and `SIGEV_THREAD` is `EINVAL`, and so is a
/// signal past 64; `SIGEV_THREAD`'s cookie is read (`EFAULT`) and its
/// `sigev_signo` must be a descriptor (`EBADF`) of a socket (`ENOTSOCK`)
/// of netlink (`EINVAL`). Then the queue (`EBADF`). No notification drops
/// the caller's own registration, if it has one; another process's is
/// `EBUSY`; else the caller's process registers.
pub(crate) fn sys_mq_notify(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_notify(c, a[0], a[1]))
}

fn mq_notify(c: &mut Context<'_>, fd: u64, at: u64) -> Result<u64, Errno> {
    let notice = if at == 0 {
        None
    } else {
        let mut event = [0u8; SIGEVENT_SIZE];
        c.mem
            .read(GuestAddr(at), &mut event)
            .map_err(|_| Errno::EFAULT)?;
        let value = u64::from_le_bytes(event[0..8].try_into().unwrap_or_default());
        let signo = i32::from_le_bytes(event[8..12].try_into().unwrap_or_default());
        let kind = i32::from_le_bytes(event[12..16].try_into().unwrap_or_default());
        Some(match kind {
            SIGEV_NONE => Notice::None,
            SIGEV_SIGNAL if (0..=64).contains(&signo) => Notice::Signal {
                number: signo,
                value,
            },
            SIGEV_THREAD => {
                let mut cookie = [0u8; NOTIFY_COOKIE_LEN];
                c.mem
                    .read(GuestAddr(value), &mut cookie)
                    .map_err(|_| Errno::EFAULT)?;
                let socket = c.files.descriptor(u64::from(signo as u32))?.file;
                if socket.stat()?.mode & S_IFMT != S_IFSOCK {
                    return Err(ENOTSOCK);
                }
                if crate::netlink::of(&socket).is_none() {
                    return Err(Errno::EINVAL);
                }
                Notice::Thread { socket, cookie }
            }
            _ => return Err(Errno::EINVAL),
        })
    };
    let file = queue_file(c, fd)?;
    let queue = &as_queue(&file).queue;
    let pid = c.process.pid;
    let mut state = queue.lock();
    match notice {
        None => state.unregister(pid),
        Some(_) if state.registration.is_some() => return Err(EBUSY),
        Some(notice) => {
            let execs = c.processes.execs(pid).unwrap_or_default();
            state.registration = Some(Registration {
                owner: pid,
                execs,
                user: c.process.credentials.user.clone(),
                notice,
            });
        }
    }
    Ok(0)
}

/// `mq_getsetattr(mqdes, newattr, oldattr)`, as Linux's: the new
/// attributes are read (`EFAULT`), and flags but `O_NONBLOCK` are `EINVAL`;
/// then the queue (`EBADF`). The old attributes, with the descriptor's
/// `O_NONBLOCK`, are written (`EFAULT`) after the new flag is set.
pub(crate) fn sys_mq_getsetattr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(mq_getsetattr(c, a[0], a[1], a[2]))
}

fn mq_getsetattr(c: &mut Context<'_>, fd: u64, new: u64, old: u64) -> Result<u64, Errno> {
    let flags = if new == 0 {
        None
    } else {
        let mut bytes = [0u8; ATTR_SIZE];
        c.mem
            .read(GuestAddr(new), &mut bytes)
            .map_err(|_| Errno::EFAULT)?;
        Some(i64::from_le_bytes(
            bytes[0..8].try_into().unwrap_or_default(),
        ))
    };
    if flags.is_some_and(|flags| flags & !i64::from(NONBLOCK) != 0) {
        return Err(Errno::EINVAL);
    }
    let file = queue_file(c, fd)?;
    let open = as_queue(&file);
    let attr = {
        let state = open.queue.lock();
        let mut attr = [0u8; ATTR_SIZE];
        let nonblocking = i64::from(open.flags() & NONBLOCK);
        for (at, value) in [
            nonblocking,
            open.queue.maxmsg,
            open.queue.msgsize,
            state.count,
        ]
        .into_iter()
        .enumerate()
        {
            attr[at * 8..at * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        if let Some(flags) = flags {
            let mode = open.flags() & O_ACCMODE;
            open.flags
                .store(mode | flags as u32 & NONBLOCK, Ordering::SeqCst);
        }
        attr
    };
    if old != 0 {
        c.mem
            .write(GuestAddr(old), &attr)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(0)
}

/// After this process closed `d`, drops its registration on the queue `d`
/// opens, as Linux's `mqueue_flush_file` does on every close.
pub(crate) fn closed(c: &Context<'_>, d: &crate::files::Descriptor) {
    if let Some(open) = d
        .file
        .as_any()
        .and_then(|any| any.downcast_ref::<QueueFile>())
    {
        open.queue.lock().unregister(c.process.pid);
    }
}

/// After process `pid` ended, the last to hold `files`, drops its
/// registrations on the queues among them, as each of their closes does on
/// Linux.
pub(crate) fn exited(files: &[Arc<dyn FileHandle>], pid: u32) {
    for file in files {
        if let Some(open) = file
            .as_any()
            .and_then(|any| any.downcast_ref::<QueueFile>())
        {
            open.queue.lock().unregister(pid);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn messages_come_highest_priority_first_in_the_order_sent() {
        let mut state = State::default();
        for (priority, text) in [(1, "a"), (5, "b"), (1, "c"), (5, "d"), (0, "e")] {
            state.insert(priority, text.as_bytes().to_vec());
        }
        assert_eq!((state.count, state.bytes), (5, 5));
        let order: Vec<_> = std::iter::from_fn(|| state.take())
            .map(|(priority, text)| (priority, String::from_utf8(text).unwrap()))
            .collect();
        assert_eq!(
            order,
            [(5, "b"), (5, "d"), (1, "a"), (1, "c"), (0, "e")].map(|(p, t)| (p, t.to_owned()))
        );
        assert_eq!((state.count, state.bytes), (0, 0));
        assert!(state.messages.is_empty());
    }

    #[test]
    fn charges_stop_at_the_limit_and_are_given_back() {
        let charges = Charges::default();
        let seven = [((1, 7), 1000)];
        assert!(charges.charge(&seven, 600));
        assert!(!charges.charge(&seven, 401));
        assert!(charges.charge(&[((1, 8), 1000)], 1000));
        assert!(charges.charge(&seven, 400));
        charges.release(&seven, 1000);
        assert!(charges.charge(&seven, 1000));
        assert!(!charges.charge(&[((1, 9), u64::MAX)], u64::MAX));
    }

    #[test]
    fn a_nested_user_charges_its_namespace_owner_too() {
        let charges = Charges::default();
        // User 0 of namespace 2, which user 7 of namespace 1 made with a
        // limit of 1000, beside user 7's own queues.
        let nested = [((2, 0), 5000), ((1, 7), 1000)];
        assert!(charges.charge(&[((1, 7), 5000)], 900));
        assert!(!charges.charge(&nested, 200));
        assert!(charges.charge(&nested, 100));
        assert_eq!(charges.lock().get(&(2, 0)), Some(&100));
        assert_eq!(charges.lock().get(&(1, 7)), Some(&1000));
        charges.release(&nested, 100);
        assert_eq!(charges.lock().get(&(2, 0)), None);
    }
}
