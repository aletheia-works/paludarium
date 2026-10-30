//! AF_UNIX sockets made with `socket`: `SOCK_STREAM` and `SOCK_SEQPACKET`
//! sockets that bind to a name in the abstract namespace, listen, accept and
//! connect, as Linux's `af_unix.c` does.
//!
//! Each socket holds one end of a socket pair ([`SocketPairEnd`]) from the
//! start, unconnected, and keeps the other: a connection to a listener gives
//! that other end to the socket the listener accepts. Once connected, the
//! socket reads, writes, passes descriptors and takes options as a
//! `socketpair` end does, through that end, which the file shows as itself.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::sockets::SocketPairEnd;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const EPROTONOSUPPORT: Errno = Errno(93);
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EAFNOSUPPORT: Errno = Errno(97);
const EADDRINUSE: Errno = Errno(98);
const EISCONN: Errno = Errno(106);
const ENOTCONN: Errno = Errno(107);
const ECONNREFUSED: Errno = Errno(111);
const SOCK_STREAM: u32 = 1;
const SOCK_SEQPACKET: u32 = 5;
const POLLHUP: u32 = 0x10;
/// `net.core.somaxconn`.
const SOMAXCONN: usize = 4096;
/// `offsetof(struct sockaddr_un, sun_path)`, and the whole structure.
const SUN_PATH: usize = 2;
const SOCKADDR_UN: usize = 110;

/// The abstract names bound on the machine, as Linux's `unix_socket_table`
/// keeps them, and where an autobind looks for the next free one.
#[derive(Default)]
pub(crate) struct Names {
    bound: Mutex<BTreeMap<Vec<u8>, Weak<UnixSocket>>>,
    next: AtomicU32,
}
impl Names {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<Vec<u8>, Weak<UnixSocket>>> {
        self.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An AF_UNIX socket `socket` made.
pub(crate) struct UnixSocket {
    this: Weak<UnixSocket>,
    /// This socket's end of its pair, and the other, until a connection
    /// gives it to the socket the listener accepts.
    end: Arc<SocketPairEnd>,
    spare: Mutex<Option<Arc<SocketPairEnd>>>,
    names: Arc<Names>,
    hub: Arc<ReadinessHub>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    /// The name it is bound to: the whole `sun_path` it gave, starting
    /// with the abstract namespace's 0.
    name: Option<Vec<u8>>,
    /// Once connected, the peer's name, if it had one.
    peer: Option<Option<Vec<u8>>>,
    listen: Option<Listen>,
}
/// A listening socket's connections that wait for `accept`.
struct Listen {
    /// The most that wait is one more (`unix_recvq_full`).
    backlog: usize,
    queue: VecDeque<Arc<UnixSocket>>,
}

/// `socket(AF_UNIX, type, protocol)`, as Linux's `unix_create`: protocol 0
/// or `PF_UNIX` (`EPROTONOSUPPORT`), `SOCK_STREAM` or `SOCK_SEQPACKET`.
/// `SOCK_DGRAM` (and `SOCK_RAW`, which Linux makes one) is not made here
/// (`EAFNOSUPPORT`); another type is `ESOCKTNOSUPPORT`.
pub(crate) fn socket(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let kind = u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?;
    if kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 {
        return Err(Errno::EINVAL);
    }
    if a[2] > 1 {
        return Err(EPROTONOSUPPORT);
    }
    match kind & 0xf {
        SOCK_STREAM | SOCK_SEQPACKET => {}
        2 | 3 => return Err(EAFNOSUPPORT),
        _ => return Err(ESOCKTNOSUPPORT),
    }
    let socket = UnixSocket::new(c, kind)?;
    c.files
        .install(socket, kind & CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

/// The socket calls on an AF_UNIX socket `socket` made: `connect`,
/// `accept`, `bind`, `listen`, `getsockname`, `getpeername` and `accept4`.
pub(crate) fn dispatch(
    c: &mut Context<'_>,
    number: u64,
    a: [u64; 6],
    socket: &Arc<UnixSocket>,
) -> Result<u64, Errno> {
    match number {
        42 => {
            let address = read_address(c, a[1], a[2])?;
            socket.connect(c, &address)
        }
        43 | 288 => {
            let flags = if number == 288 { a[3] } else { 0 };
            if flags & !u64::from(NONBLOCK | CLOEXEC) != 0 {
                return Err(Errno::EINVAL);
            }
            let child = socket.accept(c)?;
            if flags & u64::from(NONBLOCK) != 0 {
                child.set_flags(child.flags() | NONBLOCK)?;
            }
            let peer = child.lock().peer.clone().flatten();
            if a[1] != 0 {
                write_address(c, peer.as_deref(), a[1], a[2])?;
            }
            c.files
                .install(child, flags & u64::from(CLOEXEC) != 0, c.group.nofile())
                .map(u64::from)
        }
        49 => {
            let address = read_address(c, a[1], a[2])?;
            socket.bind(&address).map(|()| 0)
        }
        50 => socket.listen(a[1] as u32 as i32).map(|()| 0),
        51 => {
            let name = socket.lock().name.clone();
            write_address(c, name.as_deref(), a[1], a[2]).map(|()| 0)
        }
        52 => {
            let peer = socket.lock().peer.clone().ok_or(ENOTCONN)?;
            write_address(c, peer.as_deref(), a[1], a[2]).map(|()| 0)
        }
        _ => Err(Errno::ENOSYS),
    }
}

/// The `sockaddr_un` of `len` bytes at `at`.
fn read_address(c: &Context<'_>, at: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let len = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    if len > SOCKADDR_UN {
        return Err(Errno::EINVAL);
    }
    let mut address = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut address)
        .map_err(|_| Errno::EFAULT)?;
    Ok(address)
}
/// An AF_UNIX address, as `unix_getname` gives it: the family, then the
/// name, none for an unnamed socket; cut to the room `len` holds, which
/// then gets the whole length.
fn write_address(c: &Context<'_>, name: Option<&[u8]>, at: u64, len: u64) -> Result<(), Errno> {
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let mut address = 1u16.to_le_bytes().to_vec();
    address.extend_from_slice(name.unwrap_or_default());
    c.mem
        .write(GuestAddr(at), &address[..room.min(address.len())])
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(len), &(address.len() as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)
}
/// An address's checks before its name is looked at, as Linux's
/// `unix_validate_addr`: longer than the family, and AF_UNIX.
fn validate(address: &[u8]) -> Result<(), Errno> {
    if address.len() <= SUN_PATH || address[..2] != 1u16.to_le_bytes() {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl UnixSocket {
    fn new(c: &Context<'_>, kind: u32) -> Result<Arc<Self>, Errno> {
        let [end, spare] = SocketPairEnd::pair(kind, Arc::clone(&c.files.readiness))?;
        end.made_by(c.process.pid, c.shared_host);
        Ok(Arc::new_cyclic(|this: &Weak<Self>| {
            end.attach(Weak::clone(this));
            Self {
                this: Weak::clone(this),
                end,
                spare: Mutex::new(Some(spare)),
                names: Arc::clone(&c.files.unix),
                hub: Arc::clone(&c.files.readiness),
                state: Mutex::default(),
            }
        }))
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    pub(crate) fn listening(&self) -> bool {
        self.lock().listen.is_some()
    }
    /// `bind`, as Linux's `unix_bind`: only the family is `unix_autobind`,
    /// which takes a free name of five hex digits (and keeps one the socket
    /// has); a name in the abstract namespace is taken unless another
    /// socket has it (`EADDRINUSE`), and once bound a socket binds no more
    /// (`EINVAL`). A path in the file system is not bound here (`ENOSYS`).
    fn bind(&self, address: &[u8]) -> Result<(), Errno> {
        if address.len() == SUN_PATH && address[..2] == 1u16.to_le_bytes() {
            return self.autobind();
        }
        validate(address)?;
        let name = &address[SUN_PATH..];
        if name[0] != 0 {
            return Err(Errno::ENOSYS);
        }
        let mut s = self.lock();
        if s.name.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut bound = self.names.lock();
        if bound
            .get(name)
            .is_some_and(|other| other.strong_count() > 0)
        {
            return Err(EADDRINUSE);
        }
        bound.insert(name.to_vec(), Weak::clone(&self.this));
        s.name = Some(name.to_vec());
        Ok(())
    }
    fn autobind(&self) -> Result<(), Errno> {
        let mut s = self.lock();
        if s.name.is_some() {
            return Ok(());
        }
        let mut bound = self.names.lock();
        for _ in 0..=0xfffff {
            let number = self.names.next.fetch_add(1, Ordering::SeqCst) & 0xfffff;
            let mut name = vec![0];
            name.extend_from_slice(format!("{number:05x}").as_bytes());
            if !bound
                .get(&name)
                .is_some_and(|other| other.strong_count() > 0)
            {
                bound.insert(name.clone(), Weak::clone(&self.this));
                s.name = Some(name);
                return Ok(());
            }
        }
        Err(Errno::ENOSPC)
    }
    /// `listen(backlog)`, as Linux's `unix_listen`: a socket with no name
    /// is `EINVAL`, a connected one is left as it is, and a listener takes
    /// the new backlog, at most `somaxconn` (a negative one too).
    fn listen(&self, backlog: i32) -> Result<(), Errno> {
        let mut s = self.lock();
        if s.name.is_none() {
            return Err(Errno::EINVAL);
        }
        if s.peer.is_some() {
            return Ok(());
        }
        let backlog = usize::try_from(backlog).map_or(SOMAXCONN, |b| b.min(SOMAXCONN));
        match s.listen.as_mut() {
            Some(listen) => listen.backlog = backlog,
            None => {
                s.listen = Some(Listen {
                    backlog,
                    queue: VecDeque::new(),
                });
            }
        }
        drop(s);
        // A connect waiting for room may now find it.
        self.hub.changed();
        Ok(())
    }
    /// `connect`, as Linux's `unix_stream_connect` checks it: the address,
    /// then the listener of that name and type (`ECONNREFUSED` where none
    /// listens), whose full queue a nonblocking socket finds `EAGAIN` and a
    /// blocking one waits for, at most `SO_SNDTIMEO`; then this socket,
    /// `EISCONN` once connected, `EINVAL` listening. A path in the file
    /// system has no socket here: `ENOENT`, or `ECONNREFUSED` for another
    /// file there.
    fn connect(&self, c: &mut Context<'_>, address: &[u8]) -> Result<u64, Errno> {
        validate(address)?;
        let name = &address[SUN_PATH..];
        if name[0] != 0 {
            let path: Vec<u8> = name.iter().copied().take_while(|&b| b != 0).collect();
            let path = c.files.exec_path(path)?;
            return Err(match c.files.fs.metadata(&path, true) {
                Ok(_) => ECONNREFUSED,
                Err(e) => e,
            });
        }
        let file: Arc<dyn FileHandle> = self.this.upgrade().ok_or(Errno::EBADF)? as _;
        let wait = crate::sockets::deadline(c, &file, false)?;
        loop {
            let ticket = c.files.readiness.token.value();
            let listener = self
                .names
                .lock()
                .get(name)
                .and_then(Weak::upgrade)
                .filter(|other| other.end.kind() == self.end.kind())
                .ok_or(ECONNREFUSED)?;
            match listener.take(self, c) {
                Ok(()) => return Ok(0),
                Err(e) if e == Errno::EAGAIN => {
                    if self.flags() & NONBLOCK != 0 {
                        return Err(e);
                    }
                    let Some(deadline) = wait.deadline(c)? else {
                        return Err(e);
                    };
                    crate::events::wait(c, ticket, deadline)?;
                }
                Err(e) => return Err(e),
            }
        }
    }
    /// This listener takes a connection from `client`, if it listens and
    /// has room, as the rest of `unix_stream_connect` does: the client's
    /// other end goes to a new socket with this one's name, waiting to be
    /// accepted.
    fn take(&self, client: &UnixSocket, c: &Context<'_>) -> Result<(), Errno> {
        // A listener connecting to itself is refused as listening, once it
        // has room.
        if std::ptr::eq(self, client) {
            let s = self.lock();
            let listen = s.listen.as_ref().ok_or(ECONNREFUSED)?;
            return Err(if listen.queue.len() > listen.backlog {
                Errno::EAGAIN
            } else {
                Errno::EINVAL
            });
        }
        // Both states, locked in the order of their addresses, so that two
        // sockets connecting to each other cannot wait on each other.
        let (mut own, mut theirs) = if std::ptr::from_ref(self) < std::ptr::from_ref(client) {
            let own = self.lock();
            (own, client.lock())
        } else {
            let theirs = client.lock();
            (self.lock(), theirs)
        };
        let name = own.name.clone();
        let Some(listen) = own.listen.as_mut() else {
            return Err(ECONNREFUSED);
        };
        if listen.queue.len() > listen.backlog {
            return Err(Errno::EAGAIN);
        }
        if theirs.peer.is_some() {
            return Err(EISCONN);
        }
        if theirs.listen.is_some() {
            return Err(Errno::EINVAL);
        }
        let spare = {
            let mut slot = client.spare.lock().unwrap_or_else(PoisonError::into_inner);
            let spare = slot.as_ref().ok_or(Errno::EINVAL)?;
            // The accepted socket is blocking until `accept4` says
            // otherwise, whatever the client's flags gave its pair; the end
            // leaves the client only once that is done.
            spare.set_flags(spare.flags() & !NONBLOCK)?;
            slot.take().ok_or(Errno::EINVAL)?
        };
        client.end.made_by(c.process.pid, c.shared_host);
        let child = Arc::new_cyclic(|this: &Weak<Self>| {
            spare.attach(Weak::clone(this));
            Self {
                this: Weak::clone(this),
                end: Arc::clone(&spare),
                spare: Mutex::new(None),
                names: Arc::clone(&self.names),
                hub: Arc::clone(&self.hub),
                state: Mutex::new(State {
                    name: name.clone(),
                    peer: Some(theirs.name.clone()),
                    listen: None,
                }),
            }
        });
        theirs.peer = Some(name);
        drop(theirs);
        client.end.connected();
        spare.connected();
        listen.queue.push_back(child);
        drop(own);
        self.end.arrived();
        Ok(())
    }
    /// `accept`, as Linux's `unix_accept`: `EINVAL` unless listening, then
    /// the first connection waiting, or `EAGAIN` when none does and the
    /// socket is nonblocking, or once `SO_RCVTIMEO` has passed.
    fn accept(&self, c: &mut Context<'_>) -> Result<Arc<Self>, Errno> {
        let file: Arc<dyn FileHandle> = self.this.upgrade().ok_or(Errno::EBADF)? as _;
        let wait = crate::sockets::deadline(c, &file, true)?;
        loop {
            let ticket = c.files.readiness.token.value();
            let child = {
                let mut s = self.lock();
                let listen = s.listen.as_mut().ok_or(Errno::EINVAL)?;
                listen.queue.pop_front()
            };
            if let Some(child) = child {
                // A connect waiting for room may now find it.
                self.hub.changed();
                return Ok(child);
            }
            if self.flags() & NONBLOCK != 0 {
                return Err(Errno::EAGAIN);
            }
            let Some(deadline) = wait.deadline(c)? else {
                return Err(Errno::EAGAIN);
            };
            crate::events::wait(c, ticket, deadline)?;
        }
    }
}
impl Drop for UnixSocket {
    /// The name goes, and a listener's connections not accepted are reset
    /// (`unix_release_sock`).
    fn drop(&mut self) {
        let s = std::mem::take(&mut *self.lock());
        if let Some(name) = &s.name {
            let mut bound = self.names.lock();
            if bound
                .get(name)
                .is_some_and(|socket| std::ptr::eq(socket.as_ptr(), self))
            {
                bound.remove(name);
            }
        }
        if let Some(listen) = s.listen {
            for child in &listen.queue {
                child.end.reset_peer();
            }
            drop(listen);
        }
    }
}
impl FileHandle for UnixSocket {
    /// The end, which the socket calls that a connected socket shares with
    /// a `socketpair` end find.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(&*self.end)
    }
    /// A listener is readable while a connection waits, and no more; an
    /// unconnected socket is writable and hung up (`unix_poll` of a
    /// `TCP_CLOSE` socket); a connected one is its end.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let s = self.lock();
        if let Some(listen) = &s.listen {
            return Ok((
                u32::from(!listen.queue.is_empty()) * IN,
                listen.queue.len() as u64,
                0,
            ));
        }
        if s.peer.is_none() {
            return Ok((OUT | POLLHUP, 0, 0));
        }
        drop(s);
        self.end.readiness()
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.end.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.end.write(buf)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        self.end.stat()
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.end.set_mode(mode)
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.end.set_owner(uid, gid)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.end.flags()
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.end.set_flags(flags)
    }
}
