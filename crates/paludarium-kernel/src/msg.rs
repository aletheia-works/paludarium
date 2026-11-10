//! System V message queues: `msgget`, `msgsnd`, `msgrcv` and `msgctl`, in
//! the calling thread's IPC namespace, as Linux's `ipc/msg.c` has them.
//!
//! A queue holds its messages in the order they were sent, up to its
//! `msg_qbytes` bytes and as many messages. A receiver that finds no
//! message it wants waits in the queue's list of receivers, in the order
//! the waits began, and a message sent then goes to the first of them that
//! wants it, as Linux's `pipelined_send` hands it over, before it is
//! queued: one whose buffer is too small is told `E2BIG` and the next is
//! tried. A sender that finds the queue full waits until a receive, an
//! `IPC_SET` or the queue's removal changes it, then checks again.
use crate::ipc::{
    self, CAP_IPC_OWNER, CAP_SYS_ADMIN, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE,
    IPC_RMID, IPC_SET, IPC_STAT, Perm,
};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, WaitOutcome, WaitToken};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;
const MSG_COPY: i32 = 0o40000;

const MSG_STAT: i32 = 11;
const MSG_INFO: i32 = 12;
const MSG_STAT_ANY: i32 = 13;

const E2BIG: Errno = Errno(7);
const EIDRM: Errno = Errno(43);
const ENOMSG: Errno = Errno(42);
const EINTR: Errno = Errno(4);

/// Linux's defaults of `kernel.msgmni`, `msgmax` and `msgmnb`, and the
/// values `msginfo` reports from them.
const MSGMNI: usize = 32000;
const MSGMAX: u64 = 8192;
const MSGMNB: u64 = 16384;
const MSGSSZ: i32 = 16;
const MSGPOOL: i32 = (MSGMNI as u64 * MSGMNB / 1024) as i32;
const MSGSEG: u16 = 0xffff;
const MSGMAP: i32 = MSGMNB as i32;
const MSGTQL: i32 = MSGMNB as i32;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

/// `struct msqid64_ds`'s size on x86-64.
const DS_SIZE: usize = 120;
/// `struct msginfo`'s.
const INFO_SIZE: usize = 32;

/// The queues of an IPC namespace.
#[derive(Clone, Default)]
pub(crate) struct Queues(Arc<Mutex<Table>>);

impl std::fmt::Debug for Queues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Queues")
    }
}

impl Queues {
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct Table {
    /// By index.
    queues: BTreeMap<u32, Queue>,
    ids: ipc::Ids,
    /// The messages of all queues, and their bytes (Linux's
    /// `percpu_msg_hdrs` and `percpu_msg_bytes`).
    messages: u64,
    bytes: u64,
}

impl Table {
    /// The queue with this ID, `EINVAL` for none (`msq_obtain_object_check`).
    fn checked(&mut self, id: i32) -> Result<&mut Queue, Errno> {
        self.queues
            .get_mut(&ipc::index(id))
            .filter(|queue| queue.id == id)
            .ok_or(Errno::EINVAL)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Message {
    kind: i64,
    text: Vec<u8>,
}

/// Which messages a receive takes (Linux's `SEARCH_*`), for its `msgtyp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    Any,
    Equal(i64),
    NotEqual(i64),
    /// The lowest type up to this one.
    LessEqual(i64),
    /// The message at this position (`MSG_COPY`).
    Number(i64),
}

impl Search {
    /// Linux's `convert_mode`.
    fn of(kind: i64, flags: i32) -> Self {
        if flags & MSG_COPY != 0 {
            return Self::Number(kind);
        }
        match kind {
            0 => Self::Any,
            i64::MIN => Self::LessEqual(i64::MAX),
            kind if kind < 0 => Self::LessEqual(-kind),
            kind if flags & MSG_EXCEPT != 0 => Self::NotEqual(kind),
            kind => Self::Equal(kind),
        }
    }
    /// Linux's `testmsg`.
    fn takes(self, kind: i64) -> bool {
        match self {
            Self::Any | Self::Number(_) => true,
            Self::Equal(wanted) => kind == wanted,
            Self::NotEqual(wanted) => kind != wanted,
            Self::LessEqual(most) => kind <= most,
        }
    }
    /// The message it takes of `messages`, as Linux's `find_msg`: the first
    /// it takes, the lowest type for `LessEqual`, the one at its position
    /// for `Number`.
    fn find(self, messages: &VecDeque<Message>) -> Option<usize> {
        match self {
            Self::Number(position) => usize::try_from(position)
                .ok()
                .filter(|&at| at < messages.len()),
            Self::LessEqual(most) => {
                let mut found = None;
                let mut most = most;
                for (at, message) in messages.iter().enumerate() {
                    if message.kind <= most {
                        found = Some(at);
                        if message.kind == 1 {
                            break;
                        }
                        most = message.kind - 1;
                    }
                }
                found
            }
            search => messages
                .iter()
                .position(|message| search.takes(message.kind)),
        }
    }
}

/// What a waiting receiver is given: nothing yet, a message, or an error
/// (`E2BIG`, `EIDRM`, or `EAGAIN` to look again).
#[derive(Default)]
struct Slot {
    given: Mutex<Option<Result<Message, Errno>>>,
    token: WaitToken,
}

impl Slot {
    fn give(&self, given: Result<Message, Errno>) {
        *self.given.lock().unwrap_or_else(PoisonError::into_inner) = Some(given);
        self.token.notify();
    }
    fn has_given(&self) -> bool {
        self.given
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
    fn take(&self) -> Option<Result<Message, Errno>> {
        self.given
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// A receiver waiting in a queue (`struct msg_receiver`).
struct Receiver {
    search: Search,
    /// The most bytes it takes; `i32::MAX` with `MSG_NOERROR`.
    most: u64,
    pid: u32,
    slot: Arc<Slot>,
}

/// What a waiting sender looks at: the queue changed, or it went.
#[derive(Default)]
struct Changes {
    token: WaitToken,
    removed: AtomicBool,
}

struct Queue {
    id: i32,
    perm: Perm,
    stime: i64,
    rtime: i64,
    ctime: i64,
    /// The bytes and messages it holds, and the most of each.
    bytes: u64,
    qbytes: u64,
    messages: VecDeque<Message>,
    /// The processes that sent and received last.
    lspid: u32,
    lrpid: u32,
    receivers: Vec<Receiver>,
    changes: Arc<Changes>,
}

impl Queue {
    /// Whether a message of `size` bytes fits (`msg_fits_inqueue`).
    fn fits(&self, size: u64) -> bool {
        self.bytes + size <= self.qbytes && (self.messages.len() as u64) < self.qbytes
    }
    /// Gives `message` to the first waiting receiver that takes it, as
    /// Linux's `pipelined_send`: a receiver with too small a buffer is told
    /// `E2BIG`, and the next tried. `false` when none took it.
    fn hand_over(&mut self, message: &Message, now: i64) -> bool {
        let mut at = 0;
        while at < self.receivers.len() {
            if !self.receivers[at].search.takes(message.kind) {
                at += 1;
                continue;
            }
            let receiver = self.receivers.remove(at);
            if receiver.most < message.text.len() as u64 {
                receiver.slot.give(Err(E2BIG));
                continue;
            }
            self.lrpid = receiver.pid;
            self.rtime = now;
            receiver.slot.give(Ok(message.clone()));
            return true;
        }
        false
    }
    /// Tells every waiting receiver `error` (`expunge_all`) and every
    /// waiting sender to look again.
    fn wake_all(&mut self, error: Errno) {
        for receiver in self.receivers.drain(..) {
            receiver.slot.give(Err(error));
        }
        self.changes.token.notify();
    }
}

/// The queues of the calling thread's IPC namespace.
fn queues(c: &Context<'_>) -> Queues {
    c.group.namespaces(c.tid).ipc.msg.clone()
}

fn result(value: Result<u64, Errno>) -> Outcome {
    Outcome::Return(value.unwrap_or_else(Errno::to_syscall_return))
}

/// `msgget(key, msgflg)`, as Linux's `ksys_msgget` and `ipcget`: a key in
/// use gives its queue unless `IPC_CREAT | IPC_EXCL` (`EEXIST`) or the
/// permissions asked for are not granted (`EACCES`); a key not in use is
/// `ENOENT` without `IPC_CREAT`; a new queue past `MSGMNI` is `ENOSPC`.
pub(crate) fn sys_msgget(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(msgget(c, a[0] as i32, a[1] as i32))
}

fn msgget(c: &Context<'_>, key: i32, flag: i32) -> Result<u64, Errno> {
    let credentials = &c.process.credentials;
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    let queues = queues(c);
    let mut table = queues.lock();
    if key != IPC_PRIVATE {
        if let Some(queue) = table.queues.values().find(|queue| queue.perm.key == key) {
            if flag & IPC_CREAT != 0 && flag & IPC_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if !queue.perm.permitted(credentials, flag as u32, owner) {
                return Err(Errno::EACCES);
            }
            return Ok(u64::from(queue.id as u32));
        }
        if flag & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    let table = &mut *table;
    let id = table.ids.allocate(&table.queues, MSGMNI)?;
    table.queues.insert(
        ipc::index(id),
        Queue {
            id,
            perm: Perm::new(key, credentials, flag),
            stime: 0,
            rtime: 0,
            ctime: ipc::now(c),
            bytes: 0,
            qbytes: MSGMNB,
            messages: VecDeque::new(),
            lspid: 0,
            lrpid: 0,
            receivers: Vec::new(),
            changes: Arc::default(),
        },
    );
    Ok(u64::from(id as u32))
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)`, in Linux's order (`ksys_msgsnd`,
/// `do_msgsnd`): the type is read (`EFAULT`); a size past `MSGMAX` or a
/// negative ID is `EINVAL`, and so is a type below 1; the text is read
/// (`EFAULT`); then the queue (`EINVAL`), the permission to write it
/// (`EACCES`) and, while it is full, `EAGAIN` with `IPC_NOWAIT`, or a wait
/// until it has room, it is removed (`EIDRM`) or a signal comes (`EINTR`,
/// which a signal that runs no handler restarts).
pub(crate) fn sys_msgsnd(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(msgsnd(c, a[0] as i32, a[1], a[2], a[3] as i32))
}

fn msgsnd(c: &mut Context<'_>, id: i32, at: u64, size: u64, flag: i32) -> Result<u64, Errno> {
    let kind = c.mem.read_u64(GuestAddr(at)).map_err(|_| Errno::EFAULT)? as i64;
    if size > MSGMAX || id < 0 || kind < 1 {
        return Err(Errno::EINVAL);
    }
    let mut text = vec![0u8; size as usize];
    c.mem
        .read(GuestAddr(at.wrapping_add(8)), &mut text)
        .map_err(|_| Errno::EFAULT)?;
    let message = Message { kind, text };
    let pid = c.process.pid;
    let queues = queues(c);
    let changes = Arc::clone(&queues.lock().checked(id)?.changes);
    loop {
        let ticket = changes.token.value();
        let owner = ipc::capable(c, CAP_IPC_OWNER);
        let now = ipc::now(c);
        {
            let mut table = queues.lock();
            if changes.removed.load(Ordering::SeqCst) {
                return Err(EIDRM);
            }
            let table = &mut *table;
            let queue = table.checked(id)?;
            if !queue.perm.permitted(&c.process.credentials, 0o222, owner) {
                return Err(Errno::EACCES);
            }
            if queue.fits(size) {
                queue.lspid = pid;
                queue.stime = now;
                if !queue.hand_over(&message, now) {
                    queue.bytes += size;
                    queue.messages.push_back(message);
                    table.messages += 1;
                    table.bytes += size;
                }
                return Ok(0);
            }
            if flag & IPC_NOWAIT != 0 {
                return Err(Errno::EAGAIN);
            }
        }
        wait(c, &changes.token, ticket, &|| false)?;
    }
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)`, in Linux's order
/// (`do_msgrcv`): a negative ID or size is `EINVAL`, and so is `MSG_COPY`
/// with `MSG_EXCEPT` or without `IPC_NOWAIT`; then the queue (`EINVAL`) and
/// the permission to read it (`EACCES`). The message it takes (by
/// `msgtyp`: any, the first of that type, of another with `MSG_EXCEPT`, the
/// lowest type up to minus a negative one, or with `MSG_COPY` the one at
/// that position, which stays) longer than `msgsz` is `E2BIG`, unless
/// `MSG_NOERROR` cuts it; else it is taken off the queue. With none, it is
/// `ENOMSG` with `IPC_NOWAIT`, or a wait until one comes, the queue is
/// removed (`EIDRM`) or a signal comes (`EINTR`, which a signal that runs no
/// handler restarts). The type and as much of the text as fits are written
/// (`EFAULT`, the message gone all the same); it returns the text's length.
pub(crate) fn sys_msgrcv(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(msgrcv(c, a[0] as i32, a[1], a[2], a[3] as i64, a[4] as i32))
}

fn msgrcv(
    c: &mut Context<'_>,
    id: i32,
    at: u64,
    size: u64,
    kind: i64,
    flag: i32,
) -> Result<u64, Errno> {
    if id < 0 || (size as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    if flag & MSG_COPY != 0 && (flag & MSG_EXCEPT != 0 || flag & IPC_NOWAIT == 0) {
        return Err(Errno::EINVAL);
    }
    let search = Search::of(kind, flag);
    let pid = c.process.pid;
    let queues = queues(c);
    queues.lock().checked(id)?;
    let message = loop {
        let owner = ipc::capable(c, CAP_IPC_OWNER);
        let now = ipc::now(c);
        let slot = {
            let mut table = queues.lock();
            let table = &mut *table;
            let Ok(queue) = table.checked(id) else {
                return Err(EIDRM);
            };
            if !queue.perm.permitted(&c.process.credentials, 0o444, owner) {
                return Err(Errno::EACCES);
            }
            if let Some(found) = search.find(&queue.messages) {
                let length = queue.messages[found].text.len() as u64;
                if size < length && flag & MSG_NOERROR == 0 {
                    return Err(E2BIG);
                }
                if flag & MSG_COPY != 0 {
                    // `copy_msg` into a copy of at most `MSGMAX` bytes.
                    if length > size.min(MSGMAX) {
                        return Err(Errno::EINVAL);
                    }
                    break queue.messages[found].clone();
                }
                let message = queue.messages.remove(found).unwrap_or_else(|| Message {
                    kind: 0,
                    text: Vec::new(),
                });
                queue.bytes -= length;
                queue.rtime = now;
                queue.lrpid = pid;
                queue.changes.token.notify();
                table.messages -= 1;
                table.bytes -= length;
                break message;
            }
            if flag & IPC_NOWAIT != 0 {
                return Err(ENOMSG);
            }
            let slot = Arc::new(Slot::default());
            queue.receivers.push(Receiver {
                search,
                most: if flag & MSG_NOERROR != 0 {
                    i32::MAX as u64
                } else {
                    size
                },
                pid,
                slot: Arc::clone(&slot),
            });
            slot
        };
        let ticket = slot.token.value();
        let given = slot.has_given();
        let waited = if given {
            Ok(())
        } else {
            wait(c, &slot.token, ticket, &|| slot.has_given())
        };
        // A message given meanwhile is the receive's, even when a signal
        // came; else the receiver leaves the queue's list.
        let given = {
            let mut table = queues.lock();
            let given = slot.take();
            if given.is_none()
                && let Ok(queue) = table.checked(id)
            {
                queue
                    .receivers
                    .retain(|receiver| !Arc::ptr_eq(&receiver.slot, &slot));
            }
            given
        };
        match given {
            Some(Ok(message)) => break message,
            Some(Err(error)) if error == Errno::EAGAIN => {}
            Some(Err(error)) => return Err(error),
            None => waited?,
        }
    };
    let length = (message.text.len() as u64).min(size);
    c.mem
        .write_u64(GuestAddr(at), message.kind as u64)
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(
            GuestAddr(at.wrapping_add(8)),
            &message.text[..length as usize],
        )
        .map_err(|_| Errno::EFAULT)?;
    Ok(length)
}

/// Waits on `token` from `ticket` until `done` or a change, or else ends
/// with `EINTR` for a signal or the end of the thread group, as the waits of
/// `do_msgsnd` and `do_msgrcv` sleep until woken or signalled.
fn wait(
    c: &mut Context<'_>,
    token: &WaitToken,
    ticket: u32,
    done: &dyn Fn() -> bool,
) -> Result<(), Errno> {
    let mut interrupted = false;
    loop {
        if done() || token.value() != ticket {
            return Ok(());
        }
        c.group.drain_process(c.process);
        interrupted |= c.inbox.drain(c.process).interrupted;
        interrupted |= !c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst);
        let now = c.host.clock(ClockId::Monotonic)?;
        c.group.expire_timer(c.process, now);
        if c.group.status().is_some()
            || crate::signals::next_pending(c.process, true).is_some()
            || interrupted
        {
            return Err(EINTR);
        }
        let end = now
            .saturating_add(10_000_000)
            .min(crate::signals::next_deadline(c.process).unwrap_or(u64::MAX));
        let outcome = match c.host.wait_on(
            token,
            ticket,
            Some((ClockId::Monotonic, end)),
            c.cancellation,
        ) {
            Err(error) if error == Errno::ENOSYS => {
                c.host.wait_until(ClockId::Monotonic, end, c.cancellation)
            }
            outcome => outcome,
        };
        if let Ok(WaitOutcome::Interrupted) = outcome {
            interrupted |= c.inbox.drain(c.process).interrupted;
        }
        outcome?;
    }
}

/// `msgctl(msqid, cmd, buf)`, as Linux's `ksys_msgctl` on x86-64 (where
/// `cmd` has no `IPC_64`): a negative ID or command is `EINVAL`.
pub(crate) fn sys_msgctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(msgctl(c, a[0] as i32, a[1] as i32, a[2]))
}

fn msgctl(c: &Context<'_>, id: i32, cmd: i32, buf: u64) -> Result<u64, Errno> {
    if id < 0 || cmd < 0 {
        return Err(Errno::EINVAL);
    }
    let write = |bytes: &[u8]| {
        c.mem
            .write(GuestAddr(buf), bytes)
            .map_err(|_| Errno::EFAULT)
    };
    match cmd {
        // `msgctl_info`: `struct msginfo`, with what is in use for
        // `MSG_INFO`; the highest index in use.
        IPC_INFO | MSG_INFO => {
            let (max, in_use, messages, bytes) = {
                let queues = queues(c);
                let table = queues.lock();
                (
                    ipc::max_index(&table.queues),
                    table.queues.len() as i32,
                    table.messages.min(i32::MAX as u64) as i32,
                    table.bytes.min(i32::MAX as u64) as i32,
                )
            };
            let (pool, map, tql) = if cmd == MSG_INFO {
                (in_use, messages, bytes)
            } else {
                (MSGPOOL, MSGMAP, MSGTQL)
            };
            let mut info = [0u8; INFO_SIZE];
            for (at, value) in [
                pool,
                map,
                MSGMAX as i32,
                MSGMNB as i32,
                MSGMNI as i32,
                MSGSSZ,
                tql,
            ]
            .into_iter()
            .enumerate()
            {
                info[at * 4..at * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
            info[28..30].copy_from_slice(&MSGSEG.to_le_bytes());
            write(&info)?;
            Ok(max)
        }
        // `msgctl_stat`: by ID, or by index for `MSG_STAT` and
        // `MSG_STAT_ANY`, the latter without the permission to read it.
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            let (ds, returned) = {
                let owner = ipc::capable(c, CAP_IPC_OWNER);
                let queues = queues(c);
                let mut table = queues.lock();
                let queue = if cmd == IPC_STAT {
                    table.checked(id)?
                } else {
                    table.queues.get_mut(&ipc::index(id)).ok_or(Errno::EINVAL)?
                };
                if cmd != MSG_STAT_ANY
                    && !queue.perm.permitted(&c.process.credentials, 0o444, owner)
                {
                    return Err(Errno::EACCES);
                }
                let returned = if cmd == IPC_STAT {
                    0
                } else {
                    u64::from(queue.id as u32)
                };
                (msqid_ds(c, queue), returned)
            };
            write(&ds)?;
            Ok(returned)
        }
        // `msgctl_down`: the owner, the creator or CAP_SYS_ADMIN over the
        // IPC namespace (`EPERM`); `IPC_SET` past `MSGMNB` needs
        // CAP_SYS_RESOURCE (`EPERM`), and the owner must be one the caller's
        // user namespace maps (`EINVAL`). The waits look again.
        IPC_SET | IPC_RMID => {
            let mut ds = [0u8; DS_SIZE];
            if cmd == IPC_SET {
                c.mem
                    .read(GuestAddr(buf), &mut ds)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let qbytes = u64::from_le_bytes(ds[88..96].try_into().unwrap_or_default());
            let now = ipc::now(c);
            let admin = ipc::capable(c, CAP_SYS_ADMIN);
            let resource = c.process.credentials.capable(CAP_SYS_RESOURCE);
            let queues = queues(c);
            let mut table = queues.lock();
            let credentials = &c.process.credentials;
            let queue = table.checked(id)?;
            if !queue.perm.owned_by(credentials) && !admin {
                return Err(Errno::EPERM);
            }
            if cmd == IPC_SET {
                if qbytes > MSGMNB && !resource {
                    return Err(Errno::EPERM);
                }
                queue.perm.update(&ds, &credentials.user)?;
                queue.qbytes = qbytes;
                queue.ctime = now;
                queue.wake_all(Errno::EAGAIN);
                return Ok(0);
            }
            if let Some(mut queue) = table.queues.remove(&ipc::index(id)) {
                table.messages -= queue.messages.len() as u64;
                table.bytes -= queue.bytes;
                queue.changes.removed.store(true, Ordering::SeqCst);
                queue.wake_all(EIDRM);
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `struct msqid64_ds` of `queue`, as x86-64 lays it out: its owners as the
/// caller's user namespace shows them, its processes as its PID namespace
/// numbers them.
fn msqid_ds(c: &Context<'_>, queue: &Queue) -> [u8; DS_SIZE] {
    let mut ds = [0u8; DS_SIZE];
    queue
        .perm
        .put(&mut ds, queue.id, &c.process.credentials.user);
    let space = c.pid_space();
    let mut put = |at: usize, bytes: &[u8]| ds[at..at + bytes.len()].copy_from_slice(bytes);
    put(48, &queue.stime.to_le_bytes());
    put(56, &queue.rtime.to_le_bytes());
    put(64, &queue.ctime.to_le_bytes());
    put(72, &queue.bytes.to_le_bytes());
    put(80, &(queue.messages.len() as u64).to_le_bytes());
    put(88, &queue.qbytes.to_le_bytes());
    put(96, &space.number(queue.lspid).to_le_bytes());
    put(100, &space.number(queue.lrpid).to_le_bytes());
    ds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: i64) -> Message {
        Message {
            kind,
            text: vec![kind as u8],
        }
    }
    fn messages(kinds: &[i64]) -> VecDeque<Message> {
        kinds.iter().map(|&kind| message(kind)).collect()
    }

    #[test]
    fn a_receive_takes_the_message_its_type_asks_for() {
        let queue = messages(&[5, 3, 7, 3, 1]);
        assert_eq!(Search::of(0, 0).find(&queue), Some(0));
        assert_eq!(Search::of(3, 0).find(&queue), Some(1));
        assert_eq!(Search::of(5, MSG_EXCEPT).find(&queue), Some(1));
        assert_eq!(Search::of(9, 0).find(&queue), None);
        // The lowest type up to the bound, the first of equal ones.
        assert_eq!(Search::of(-4, 0).find(&queue), Some(4));
        assert_eq!(Search::of(-4, 0).find(&messages(&[5, 3, 7, 3])), Some(1));
        assert_eq!(Search::of(-2, 0).find(&messages(&[5, 3])), None);
        assert_eq!(Search::of(i64::MIN, 0).find(&queue), Some(4));
        // MSG_COPY takes the message at a position, whatever its type.
        assert_eq!(Search::of(2, MSG_COPY).find(&queue), Some(2));
        assert_eq!(Search::of(5, MSG_COPY).find(&queue), None);
        assert_eq!(Search::of(-1, MSG_COPY).find(&queue), None);
    }

    #[test]
    fn a_message_goes_to_the_first_waiting_receiver_that_takes_it() {
        let mut queue = Queue {
            id: 0,
            perm: Perm::new(0, &crate::credentials::Credentials::default(), 0o600),
            stime: 0,
            rtime: 0,
            ctime: 0,
            bytes: 0,
            qbytes: MSGMNB,
            messages: VecDeque::new(),
            lspid: 0,
            lrpid: 0,
            receivers: Vec::new(),
            changes: Arc::default(),
        };
        let mut wait = |search, most, pid| {
            let slot = Arc::new(Slot::default());
            queue.receivers.push(Receiver {
                search,
                most,
                pid,
                slot: Arc::clone(&slot),
            });
            slot
        };
        let other = wait(Search::Equal(2), 100, 10);
        let small = wait(Search::Any, 0, 11);
        let taker = wait(Search::Any, 100, 12);
        assert!(queue.hand_over(&message(1), 5));
        assert!(other.take().is_none());
        assert_eq!(small.take(), Some(Err(E2BIG)));
        assert_eq!(taker.take(), Some(Ok(message(1))));
        assert_eq!(
            (queue.lrpid, queue.rtime, queue.receivers.len()),
            (12, 5, 1)
        );
        // None that takes it: it is queued.
        assert!(!queue.hand_over(&message(3), 6));
        queue.wake_all(EIDRM);
        assert_eq!(other.take(), Some(Err(EIDRM)));
    }
}
