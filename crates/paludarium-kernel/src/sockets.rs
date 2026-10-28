//! AF_UNIX socket pairs, and pipes built on them, with the signals their
//! `O_ASYNC` sends. Buffers and peer lifetime belong to the Kernel.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, PRI, ReadinessHub};
use crate::fasync::{FileOwner, Notice, O_ASYNC, Reason, Registration};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use paludarium_types::GuestAddr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

// Per-stream flow-control window, not a per-guest memory/fd quota. Native
// queue capacity and packet accounting depend on the host; the oracle compares
// saturation, partial success and readiness transitions instead of byte counts.
pub(crate) const SEND_WINDOW: usize = 212_992;

/// Unidirectional anonymous pipe using the same buffered readiness transport.
pub(crate) struct PipeEnd {
    endpoint: Arc<SocketPairEnd>,
    reader: bool,
    /// One inode for both ends, as a pipe has on Linux.
    inode: u64,
    attributes: Arc<Attributes>,
}
/// What `fchmod` and `fchown` change on the inode of a pipe or a socket, as
/// Linux's `simple_setattr` keeps them: the mode, whose file type stays, and
/// the owner and group.
struct Attributes(Mutex<Owned>);
#[derive(Clone, Copy)]
struct Owned {
    mode: u32,
    uid: u32,
    gid: u32,
}
impl Attributes {
    fn new(mode: u32) -> Self {
        Self(Mutex::new(Owned {
            mode,
            uid: 0,
            gid: 0,
        }))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Owned> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn stat(&self, inode: u64) -> FileStat {
        let Owned { mode, uid, gid } = *self.lock();
        FileStat {
            inode,
            mode,
            uid,
            gid,
            links: 1,
            ..FileStat::default()
        }
    }
    fn set_mode(&self, mode: u32) {
        let mut a = self.lock();
        a.mode = (a.mode & 0o170000) | (mode & 0o7777);
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) {
        let mut a = self.lock();
        a.uid = uid.unwrap_or(a.uid);
        a.gid = gid.unwrap_or(a.gid);
    }
}
#[cfg(test)]
mod pipe_tests {
    use super::*;
    fn pair() -> [Arc<PipeEnd>; 2] {
        PipeEnd::pair(0, Arc::default()).unwrap()
    }
    #[test]
    fn transfer() {
        let [r, w] = pair();
        w.write(b"abc").unwrap();
        let mut b = [0; 3];
        assert_eq!(r.read(&mut b), Ok(3));
        assert_eq!(&b, b"abc");
    }
    #[test]
    fn eof_after_last_writer() {
        let [r, w] = pair();
        let copy = Arc::clone(&w);
        drop(w);
        assert_eq!(r.read(&mut [0]), Err(Errno::EAGAIN));
        drop(copy);
        assert_eq!(r.read(&mut [0]), Ok(0));
    }
    #[test]
    fn broken_pipe_after_reader() {
        let [r, w] = pair();
        drop(r);
        assert_eq!(w.write(b"x"), Err(Errno(32)));
    }
    #[test]
    fn direction_is_enforced() {
        let [r, w] = pair();
        assert_eq!(r.write(b"x"), Err(Errno::EBADF));
        assert_eq!(w.read(&mut [0]), Err(Errno::EBADF));
    }
    #[test]
    fn flags_and_seek() {
        let [r, w] = PipeEnd::pair(NONBLOCK | CLOEXEC, Arc::default()).unwrap();
        assert_eq!(r.flags(), NONBLOCK);
        assert_eq!(w.flags(), NONBLOCK | 1);
        r.set_flags(0).unwrap();
        assert_eq!(r.flags(), 0);
        assert_eq!(r.seek(0, 0), Err(Errno::ESPIPE));
    }
    #[test]
    fn readiness_transition() {
        let [r, w] = pair();
        assert_eq!(r.readiness().unwrap().0, 0);
        assert_eq!(w.readiness().unwrap().0, OUT);
        w.write(b"x").unwrap();
        assert_eq!(r.readiness().unwrap().0, IN);
        drop(w);
        assert_eq!(r.readiness().unwrap().0, IN | 0x10);
    }
    #[test]
    fn buffered_bytes_before_eof() {
        let [r, w] = pair();
        w.write(b"ab").unwrap();
        drop(w);
        assert_eq!(r.read(&mut [0]), Ok(1));
        assert_eq!(r.read(&mut [0]), Ok(1));
        assert_eq!(r.read(&mut [0]), Ok(0));
    }
}
/// A new pipe holds 16 pages, as on Linux.
const PIPE_DEFAULT: usize = 16 * 4096;
impl PipeEnd {
    pub(crate) fn pair(flags: u32, hub: Arc<ReadinessHub>) -> Result<[Arc<Self>; 2], Errno> {
        let [reader, writer] = SocketPairEnd::pair(1 | flags, hub)?;
        reader.pair.window.store(PIPE_DEFAULT, Ordering::SeqCst);
        reader.pair.pipe.store(true, Ordering::SeqCst);
        reader.shutdown(1)?;
        writer.shutdown(0)?;
        let inode = reader.inode;
        let attributes = Arc::new(Attributes::new(0o010600));
        Ok([
            Arc::new(Self {
                endpoint: reader,
                reader: true,
                inode,
                attributes: Arc::clone(&attributes),
            }),
            Arc::new(Self {
                endpoint: writer,
                reader: false,
                inode,
                attributes,
            }),
        ])
    }
}
impl PipeEnd {
    /// `F_GETPIPE_SZ`.
    pub(crate) fn size(&self) -> u64 {
        self.endpoint.pair.window() as u64
    }
    /// `F_SETPIPE_SZ`, as Linux's `pipe_set_size`: the size rounds up to a
    /// power of two of at least a page (`EINVAL` past 2^31), and may not drop
    /// below the pages the unread data fills (`EBUSY`). The guest is root,
    /// so no limit applies. Returns the new size.
    pub(crate) fn set_size(&self, size: u32) -> Result<u64, Errno> {
        if size > 1 << 31 {
            return Err(Errno::EINVAL);
        }
        let size = size.max(4096).next_power_of_two() as usize;
        let sides = self
            .endpoint
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The unread bytes are the reader's; each page holds 4096 of them.
        let unread = sides[if self.reader {
            self.endpoint.side
        } else {
            1 - self.endpoint.side
        }]
        .bytes
        .len();
        if size / 4096 < unread.div_ceil(4096) {
            return Err(Errno(16)); // EBUSY
        }
        self.endpoint.pair.window.store(size, Ordering::SeqCst);
        drop(sides);
        self.endpoint.pair.hub.changed();
        Ok(size as u64)
    }
}
impl FileHandle for PipeEnd {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, bytes: &mut [u8]) -> Result<usize, Errno> {
        if self.reader {
            self.endpoint.read(bytes)
        } else {
            Err(Errno::EBADF)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        if self.reader {
            Err(Errno::EBADF)
        } else {
            self.endpoint.write(bytes)
        }
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let (mask, input, output) = self.endpoint.readiness()?;
        // Unlike a socket, a pipe at end of file is not readable: Linux's
        // `pipe_poll` sets POLLIN only for unread data, and POLLHUP alone once
        // the writers are gone.
        let mask = if self.reader {
            mask & if self.endpoint.unread() == 0 {
                0x10
            } else {
                IN | 0x10
            }
        } else {
            mask & (OUT | 8)
        };
        Ok((mask, input, output))
    }
    fn flags(&self) -> u32 {
        u32::from(!self.reader) | (self.endpoint.flags() & (NONBLOCK | O_ASYNC))
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.endpoint.set_flags(flags)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.attributes.stat(self.inode))
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.attributes.set_mode(mode);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.attributes.set_owner(uid, gid);
        Ok(())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}

pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| match c.cpu.gpr[paludarium_cpu::reg::RAX] {
        41 => Err(Errno(97)),
        53 => {
            if a[0] != 1 {
                return Err(Errno(97));
            }
            if a[2] != 0 {
                return Err(Errno(93));
            }
            c.mem
                .check_write(GuestAddr(a[3]), 8)
                .map_err(|_| Errno::EFAULT)?;
            let kind = u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?;
            let ends = SocketPairEnd::pair(kind, Arc::clone(&c.files.readiness))?;
            ends[0].pair.creator.store(c.process.pid, Ordering::SeqCst);
            let [fd0, fd1] = c.files.install_pair(
                ends.map(|end| end as Arc<dyn FileHandle>),
                kind & CLOEXEC != 0,
                c.group.nofile(),
            )?;
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&fd0.to_le_bytes());
            bytes[4..].copy_from_slice(&fd1.to_le_bytes());
            c.mem
                .write(GuestAddr(a[3]), &bytes)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        48 => {
            let d = c.files.descriptor(a[0])?;
            let socket = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<SocketPairEnd>())
                .ok_or(Errno(88))?;
            socket.shutdown(a[1])?;
            Ok(0)
        }
        54 => set_option(c, a),
        55 => get_option(c, a),
        44 => send_to(c, a),
        45 => receive_from(c, a),
        46 => send_message(c, a),
        47 => receive_message(c, a),
        _ => Err(Errno::ENOSYS),
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: u32 = 1;
const SCM_CREDENTIALS: u32 = 2;
/// `struct ucred`: a process ID, a user and a group.
const UCRED: usize = 12;
/// The user and group a message without credentials reads as, Linux's
/// `overflowuid` and `overflowgid`.
const OVERFLOW_ID: u32 = 65534;
/// `SCM_MAX_FD`: the most descriptors one message passes.
const MAX_PASSED: usize = 253;
/// `struct cmsghdr`: `cmsg_len` (8 bytes), `cmsg_level` and `cmsg_type`.
const CMSG_HEADER: usize = 16;
/// The largest control buffer sendmsg copies in: `sock_kmalloc` refuses one
/// of `net.core.optmem_max` (128 KiB by default since Linux 6.9) or more.
const MAX_CONTROL: u64 = 128 * 1024;

/// A `struct user_msghdr`, as Linux's `__copy_msghdr` checks it.
struct MessageHeader {
    /// `msg_name` when it and `msg_namelen` are both non-zero.
    name: Option<(u64, usize)>,
    /// Whether `msg_name` is set, so recvmsg writes back its length.
    has_name: bool,
    iov: Vec<(u64, usize)>,
    control: u64,
    control_len: u64,
}
/// Reads the `msghdr` at `at` (EFAULT): a negative `msg_namelen` with a name
/// is EINVAL, a longer one counts as `sockaddr_storage`'s 128 bytes, and
/// more than 1024 iovecs are EMSGSIZE.
fn message_header(c: &Context<'_>, at: u64, write: bool) -> Result<MessageHeader, Errno> {
    let mut raw = [0; 56];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let word = |i: usize| u64::from_le_bytes(raw[i..i + 8].try_into().unwrap_or_default());
    let name = word(0);
    let name_len = i32::from_le_bytes(raw[8..12].try_into().unwrap_or_default());
    if name != 0 && name_len < 0 {
        return Err(Errno::EINVAL);
    }
    let name_len = usize::try_from(name_len).unwrap_or(0).min(128);
    if word(24) > 1024 {
        return Err(Errno(90)); // EMSGSIZE
    }
    // recvmsg sees that its buffers can be written before it takes the data,
    // which a failed copy would leave in place. sendmsg's are only checked as
    // access_ok does, as they are copied after the address is checked.
    let iov = if write {
        crate::files::iovecs(c, word(16), word(24), true)?
    } else {
        crate::files::iovecs_checked(c, word(16), word(24), access_ok)?
    };
    Ok(MessageHeader {
        name: (name != 0 && name_len != 0).then_some((name, name_len)),
        has_name: name != 0,
        iov,
        control: word(32),
        control_len: word(40),
    })
}
/// The socket of descriptor `fd`: EBADF, or ENOTSOCK for another file.
fn socket(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    if !file.as_any().is_some_and(|v| v.is::<SocketPairEnd>()) {
        return Err(Errno(88));
    }
    Ok(file)
}
/// The socket end of a socket or a pipe, which keeps its owner and
/// `O_ASYNC` itself.
pub(crate) fn endpoint(file: &Arc<dyn FileHandle>) -> Option<&SocketPairEnd> {
    let any = file.as_any()?;
    any.downcast_ref::<SocketPairEnd>().or_else(|| {
        any.downcast_ref::<PipeEnd>()
            .map(|pipe| pipe.endpoint.as_ref())
    })
}
/// Signals the other end of `file`, if it is a pipe, for `reason`.
fn pipe_notify(file: &Arc<dyn FileHandle>, reason: Reason) {
    if let Some(pipe) = file.as_any().and_then(|any| any.downcast_ref::<PipeEnd>()) {
        let end = &pipe.endpoint;
        end.notify(1 - end.side, reason);
    }
}
/// The end of a read of a pipe, with or without data: its writer gets
/// `POLL_OUT`, as Linux's `pipe_read` gives it.
pub(crate) fn pipe_read_ended(file: &Arc<dyn FileHandle>) {
    pipe_notify(file, Reason::Out);
}
/// A write of a pipe that found it full, once per call: its reader gets
/// `POLL_IN` then too, as Linux's `pipe_write` gives it before a wait.
pub(crate) fn pipe_write_blocked(file: &Arc<dyn FileHandle>) {
    pipe_notify(file, Reason::In);
}
fn as_socket(file: &Arc<dyn FileHandle>) -> Result<&SocketPairEnd, Errno> {
    file.as_any()
        .and_then(|v| v.downcast_ref::<SocketPairEnd>())
        .ok_or(Errno(88))
}
/// The descriptors and credentials the control messages pass, as Linux's
/// `__scm_send` reads them: each header must lie in the buffer (EINVAL),
/// levels other than `SOL_SOCKET` are skipped, and `SOL_SOCKET` takes only
/// `SCM_RIGHTS` and `SCM_CREDENTIALS` (EINVAL). `SCM_RIGHTS` passes at most
/// 253 descriptors in all (EINVAL), each open (EBADF). `SCM_CREDENTIALS` is
/// exactly one `struct ucred` (EINVAL), the last one counting; as the guest
/// runs as root, `scm_check_creds` lets any through, but neither ID may be
/// -1 (EINVAL), and then the process ID must name a process or thread
/// (ESRCH).
fn control_messages(
    c: &Context<'_>,
    control: &[u8],
) -> Result<(Passed, Option<Credentials>), Errno> {
    let mut passed = Passed::new();
    let mut credentials = None;
    let mut at = 0;
    // CMSG_FIRSTHDR and CMSG_NXTHDR: a header must fit in what is left.
    while control.len().saturating_sub(at) >= CMSG_HEADER {
        let field = |i: usize| u32::from_le_bytes(control[i..i + 4].try_into().unwrap_or_default());
        let len = u64::from_le_bytes(control[at..at + 8].try_into().unwrap_or_default());
        // CMSG_OK.
        let len = usize::try_from(len)
            .ok()
            .filter(|len| (CMSG_HEADER..=control.len() - at).contains(len))
            .ok_or(Errno::EINVAL)?;
        if field(at + 8) == SOL_SOCKET && field(at + 12) == SCM_CREDENTIALS {
            if len != CMSG_HEADER + UCRED {
                return Err(Errno::EINVAL);
            }
            let [pid, uid, gid] = [0, 4, 8].map(|i| field(at + CMSG_HEADER + i));
            let owner = FileOwner {
                kind: crate::fasync::OwnerKind::Process,
                id: pid,
                signal: 0,
            };
            // scm_check_creds refuses an ID of -1 first.
            if uid == u32::MAX || gid == u32::MAX {
                return Err(Errno::EINVAL);
            }
            if pid.cast_signed() <= 0 || !c.processes.owner_exists(owner) {
                return Err(Errno(3));
            }
            credentials = Some(Credentials { pid, uid, gid });
        } else if field(at + 8) == SOL_SOCKET {
            if field(at + 12) != SCM_RIGHTS {
                return Err(Errno::EINVAL);
            }
            let count = (len - CMSG_HEADER) / 4;
            if count > MAX_PASSED || passed.len() + count > MAX_PASSED {
                return Err(Errno::EINVAL);
            }
            for i in 0..count {
                let fd = field(at + CMSG_HEADER + 4 * i) as i32;
                let fd = u64::try_from(fd).map_err(|_| Errno::EBADF)?;
                passed.push(c.files.descriptor(fd)?);
            }
        }
        // CMSG_ALIGN.
        at = at.saturating_add(len.next_multiple_of(8));
    }
    Ok((passed, credentials))
}
/// The error of a datagram sent to a valid `address`, as Linux's
/// `unix_find_other` finds it after the data is copied: as no socket can be
/// bound, every address names none, so ECONNREFUSED, or the error of looking
/// up a path that is not there.
fn unreachable_address(c: &Context<'_>, address: &[u8]) -> Errno {
    let path = &address[2..];
    // An abstract name starts with a NUL byte.
    if path[0] == 0 {
        return Errno(111);
    }
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    match c.files.exec_path(path[..end].to_vec()) {
        Ok(path) => match c.files.fs.metadata(&path, true) {
            Ok(_) => Errno(111),
            Err(e) => e,
        },
        Err(e) => e,
    }
}
/// What a send of `len` bytes to `address` checks before the data is copied:
/// a connected stream socket takes no address (EISCONN) and
/// `unix_seqpacket_sendmsg` ignores it, while `unix_dgram_sendmsg` checks it
/// with `unix_validate_addr` (EINVAL) and then the size (EMSGSIZE). Returns
/// whether the address is still to be looked up, after the copy.
fn check_address(socket: &SocketPairEnd, address: &[u8], len: usize) -> Result<bool, Errno> {
    match socket.pair.kind {
        SOCK_STREAM => Err(Errno(106)), // EISCONN
        SOCK_SEQPACKET => Ok(false),
        _ => {
            // More than the family, at most sockaddr_un's 110 bytes, and
            // AF_UNIX.
            if address.len() <= 2 || address.len() > 110 || address[..2] != [1, 0] {
                return Err(Errno::EINVAL);
            }
            if len > MAX_MESSAGE {
                return Err(Errno(90)); // EMSGSIZE
            }
            Ok(true)
        }
    }
}
/// `TASK_SIZE_MAX` on x86-64 with four-level page tables: the end of the user
/// half, less a guard page. With five-level ones Linux allows up to 2^56, so
/// a buffer between the two is EFAULT here before the descriptor is checked
/// and there only when it is copied.
const TASK_SIZE_MAX: u64 = 0x7fff_ffff_f000;
/// The length of the buffer of sendto or recvfrom, as `import_ubuf` takes it
/// before the descriptor is looked up: at most `MAX_RW_COUNT`, and EFAULT
/// when it reaches past the user half (`access_ok`). A buffer there that is
/// not mapped is EFAULT only when it is copied.
fn user_buffer(at: u64, len: u64) -> Result<usize, Errno> {
    let len = usize::try_from(len.min(0x7fff_f000)).map_err(|_| Errno::EFAULT)?;
    access_ok(at, len)?;
    Ok(len)
}
/// Linux's `access_ok`: EFAULT for `len` bytes at `at` that reach past the
/// user half.
fn access_ok(at: u64, len: usize) -> Result<(), Errno> {
    if at > TASK_SIZE_MAX.saturating_sub(len as u64) {
        return Err(Errno::EFAULT);
    }
    Ok(())
}
/// `sendto(fd, buf, len, flags, addr, addrlen)` on a socket pair: sendmsg
/// with one buffer and no control messages. As `move_addr_to_kernel`, an
/// address longer than `sockaddr_storage`'s 128 bytes, or negative, is EINVAL
/// and one of no bytes is none.
fn send_to(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let len = user_buffer(a[1], a[2])?;
    let file = socket(c, a[0])?;
    let mut address = Vec::new();
    if a[4] != 0 {
        let len = usize::try_from(a[5] as u32 as i32)
            .ok()
            .filter(|&len| len <= 128)
            .ok_or(Errno::EINVAL)?;
        address.resize(len, 0);
        c.mem
            .read(GuestAddr(a[4]), &mut address)
            .map_err(|_| Errno::EFAULT)?;
    }
    let socket = as_socket(&file)?;
    socket.check_out_of_band_send(a[3], true, len)?;
    let lookup = !address.is_empty() && check_address(socket, &address, len)?;
    socket.check_out_of_band_send(a[3], false, len)?;
    c.mem
        .check_read(GuestAddr(a[1]), len)
        .map_err(|_| Errno::EFAULT)?;
    let mut bytes = Vec::new();
    bytes.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(len, 0);
    c.mem
        .read(GuestAddr(a[1]), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    if lookup {
        return Err(unreachable_address(c, &address));
    }
    let sender = Sender::process(c.process.pid);
    send_bytes(c, &file, socket, &bytes, a[3], &mut Passed::new(), sender)
}
/// `recvfrom(fd, buf, len, flags, addr, addrlen)` on a socket pair: recvmsg
/// with one buffer and no control buffer, so the descriptors a message passes
/// close. With `addr`, the peer's address length, 0, goes to `addrlen` as
/// `move_addr_to_user` writes it: EFAULT when it cannot be read, and a
/// negative one is EINVAL, after the data is taken.
fn receive_from(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let len = user_buffer(a[1], a[2])?;
    let file = socket(c, a[0])?;
    let socket = as_socket(&file)?;
    socket.check_out_of_band(a[3])?;
    c.mem
        .check_write(GuestAddr(a[1]), len)
        .map_err(|_| Errno::EFAULT)?;
    let mut bytes = Vec::new();
    bytes.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(len, 0);
    let received = receive_with(c, &file, socket, &mut bytes, a[3], true)?;
    let returned = received.returned(a[3]);
    c.mem
        .write(GuestAddr(a[1]), &bytes[..received.count])
        .map_err(|_| Errno::EFAULT)?;
    // Closed here, outside the socket's lock.
    drop(received.passed);
    if a[4] != 0 {
        let mut raw = [0; 4];
        c.mem
            .read(GuestAddr(a[5]), &mut raw)
            .map_err(|_| Errno::EFAULT)?;
        if i32::from_le_bytes(raw) < 0 {
            return Err(Errno::EINVAL);
        }
        c.mem
            .write(GuestAddr(a[5]), &0u32.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(returned)
}
/// `read` (or `readv`) on a socket pair: recvfrom with no flags, but an empty
/// buffer ends it at once, and the descriptors that come close.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    let socket = as_socket(file)?;
    let received = receive_with(c, file, socket, buf, 0, false)?;
    Ok(received.count)
}
/// `sendmsg(fd, msg, flags)` on a socket pair, with `SCM_RIGHTS` and
/// `SCM_CREDENTIALS`. Of the
/// flags `MSG_NOSIGNAL`, `MSG_DONTWAIT` and, on a stream, `MSG_OOB` act
/// ([`send_bytes`]); `MSG_OOB` is EOPNOTSUPP on the other kinds, and the rest
/// are ignored, as Linux's AF_UNIX sockets ignore them.
fn send_message(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    let header = message_header(c, a[1], false)?;
    let mut address = Vec::new();
    if let Some((name, len)) = header.name {
        address.resize(len, 0);
        c.mem
            .read(GuestAddr(name), &mut address)
            .map_err(|_| Errno::EFAULT)?;
    }
    // ____sys_sendmsg: a control buffer past INT_MAX, or one that
    // sock_kmalloc refuses, is ENOBUFS.
    if header.control_len >= MAX_CONTROL {
        return Err(Errno(105));
    }
    let mut control = vec![0; usize::try_from(header.control_len).map_err(|_| Errno(105))?];
    c.mem
        .read(GuestAddr(header.control), &mut control)
        .map_err(|_| Errno::EFAULT)?;
    let (mut passed, credentials) = control_messages(c, &control)?;
    let socket = as_socket(&file)?;
    let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
    socket.check_out_of_band_send(a[2], true, total)?;
    // The address is checked, and the data then copied, in the protocol's
    // sendmsg after __scm_send.
    let lookup = header.name.is_some() && check_address(socket, &address, total)?;
    socket.check_out_of_band_send(a[2], false, total)?;
    let mut bytes = Vec::new();
    bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
    for &(base, len) in &header.iov {
        let start = bytes.len();
        bytes.resize(start + len, 0);
        c.mem
            .read(GuestAddr(base), &mut bytes[start..])
            .map_err(|_| Errno::EFAULT)?;
    }
    if lookup {
        return Err(unreachable_address(c, &address));
    }
    let sender = Sender {
        pid: c.process.pid,
        credentials,
    };
    let result = send_bytes(c, &file, socket, &bytes, a[2], &mut passed, sender);
    // What was not passed closes here, outside the socket's lock.
    drop(passed);
    result
}
/// `recvmsg(fd, msg, flags)` on a socket pair, with `SCM_RIGHTS`,
/// `SCM_CREDENTIALS` and the flags of [`receive_with`].
fn receive_message(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    let header = message_header(c, a[1], true)?;
    let socket = as_socket(&file)?;
    socket.check_out_of_band(a[2])?;
    let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(total, 0);
    let received = receive_with(c, &file, socket, &mut bytes, a[2], true)?;
    let returned = received.returned(a[2]);
    crate::files::scatter(c, &header.iov, &bytes[..received.count])?;
    // ____sys_recvmsg starts msg_flags with MSG_CMSG_CLOEXEC, and
    // unix_stream_recv_urg adds MSG_OOB.
    let mut flags = (a[2] & (MSG_CMSG_CLOEXEC | MSG_OOB)) as u32;
    if received.truncated {
        flags |= MSG_TRUNC;
    }
    let credentials = socket.passes_credentials().then_some(received.credentials);
    let (used, cut) = deliver(
        c,
        &header,
        received.passed,
        credentials,
        a[2] & MSG_CMSG_CLOEXEC != 0,
    );
    if cut {
        flags |= MSG_CTRUNC;
    }
    // A pair's peer has no address, so its length is 0.
    if header.has_name {
        c.mem
            .write(GuestAddr(a[1] + 8), &0u32.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
    }
    c.mem
        .write(GuestAddr(a[1] + 48), &flags.to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(a[1] + 40), &used.to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    Ok(returned)
}
/// Sends `bytes` for sendto or sendmsg with their `flags`. With `MSG_OOB` on
/// a stream, all but the last byte go as data and then, once they all have,
/// the last one out of band, as Linux's `unix_stream_sendmsg` and
/// `queue_oob`; the descriptors go with the first part sent, and every part
/// carries `sender`'s credentials.
fn send_bytes(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &SocketPairEnd,
    bytes: &[u8],
    flags: u64,
    passed: &mut Passed,
    sender: Sender,
) -> Result<u64, Errno> {
    let (nosignal, dontwait) = (flags & MSG_NOSIGNAL != 0, flags & MSG_DONTWAIT != 0);
    let Some((&last, data)) = bytes.split_last().filter(|_| flags & MSG_OOB != 0) else {
        return crate::files::write_with(c, file, bytes, nosignal, dontwait, |b| {
            socket.send(b, passed, sender)
        });
    };
    let sent = if data.is_empty() {
        0
    } else {
        crate::files::write_with(c, file, data, nosignal, dontwait, |b| {
            socket.send(b, passed, sender)
        })?
    };
    if sent != data.len() as u64 {
        return Ok(sent);
    }
    // With the data gone, an out-of-band byte that cannot go leaves what was
    // sent, with no SIGPIPE, as unix_stream_sendmsg returns `sent ? : err`.
    let urgent = if sent == 0 {
        crate::files::write_with(c, file, &[last], nosignal, dontwait, |_| {
            socket.send_out_of_band(last, passed, sender)
        })?
    } else {
        socket
            .send_out_of_band(last, passed, sender)
            .map_or(0, |n| n as u64)
    };
    // The byte sends the receiving end's owner SIGURG, as Linux's
    // `sk_send_sigurg`.
    let owner = socket.peer_owner();
    if urgent != 0 && owner.id != 0 {
        c.processes.send_urgent(owner);
    }
    Ok(sent + urgent)
}
/// Reads for recvmsg or recvfrom with their `flags`, or for read (not a
/// `message`: an empty buffer ends it at once), as Linux's AF_UNIX sockets
/// take them: `MSG_DONTWAIT` does not wait, and `MSG_PEEK` leaves the data,
/// and its descriptors, where they are, from `SO_PEEK_OFF` on. A blocking
/// stream read that is not a peek goes on until it has `SO_RCVLOWAT` bytes,
/// or with `MSG_WAITALL` until `bytes` is full, as Linux's
/// `sock_rcvlowat` sets its target; or until the stream ends or reaches its
/// out-of-band mark, descriptors come, the time is up or a signal arrives
/// after some data, which it then returns, or, with `SO_PASSCRED`, data of
/// other credentials comes. `MSG_OOB` takes a stream's out-of-band byte, and
/// never waits. Other flags have no effect.
fn receive_with(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &SocketPairEnd,
    bytes: &mut [u8],
    flags: u64,
    message: bool,
) -> Result<Received, Errno> {
    let dontwait = flags & MSG_DONTWAIT != 0;
    let peek = flags & MSG_PEEK != 0;
    if flags & MSG_OOB != 0 {
        return socket.receive_out_of_band(bytes, peek);
    }
    // SO_RCVTIMEO bounds the whole call, its later waits too.
    let wait = deadline(c, file, true)?;
    let mut received = crate::files::wait_for_read_until(c, file, dontwait, wait, || {
        socket.receive(bytes, message, peek)
    })?;
    // A peek returns what it found, as unix_stream_read_generic does.
    let target = if flags & MSG_WAITALL != 0 {
        bytes.len()
    } else {
        socket.receive_low_water().min(bytes.len())
    };
    let wait_more = !peek && !socket.pair.messages() && !dontwait && socket.flags() & NONBLOCK == 0;
    while wait_more
        && (1..target).contains(&received.count)
        && received.passed.is_empty()
        && !received.at_mark
    {
        let done = received.count;
        let more = crate::files::wait_for_read_until(c, file, false, wait, || {
            socket.receive_more(&mut bytes[done..], received.credentials)
        });
        match more {
            Ok(more) if more.count != 0 => {
                received.count += more.count;
                received.length += more.count;
                received.passed = more.passed;
                received.at_mark = more.at_mark;
                received.discarded.extend(more.discarded);
            }
            // The end of the stream, or an error such as a signal after
            // some data, which Linux's unix_stream_read_generic returns
            // instead (`copied ? : err`).
            _ => break,
        }
    }
    Ok(received)
}
/// Writes the control messages of a received message, as Linux's
/// `__scm_recv_common`: with no control buffer, only `MSG_CTRUNC` tells of
/// them. Otherwise `credentials`, when the socket passes them, go first
/// ([`put_credentials`]), then the descriptors ([`put_descriptors`]).
/// Returns the control bytes used and whether anything was lost
/// (`MSG_CTRUNC`).
fn deliver(
    c: &mut Context<'_>,
    header: &MessageHeader,
    passed: Passed,
    credentials: Option<Credentials>,
    cloexec: bool,
) -> (u64, bool) {
    if header.control == 0 {
        return (0, credentials.is_some() || !passed.is_empty());
    }
    let mut room = (header.control, header.control_len);
    let mut cut = false;
    if let Some(credentials) = credentials {
        cut |= put_credentials(c, &mut room, credentials);
    }
    if !passed.is_empty() {
        cut |= put_descriptors(c, &mut room, passed, cloexec);
    }
    (header.control_len - room.1, cut)
}
/// Writes the `SCM_CREDENTIALS` message at the start of `room` (the address
/// and length of what is left of the control buffer), as Linux's `put_cmsg`:
/// cut to what is left, nothing when not even its header fits, and `room`
/// as it was when it cannot be written. Returns whether it was cut.
fn put_credentials(c: &Context<'_>, room: &mut (u64, u64), credentials: Credentials) -> bool {
    let (at, left) = *room;
    if left < CMSG_HEADER as u64 {
        return true;
    }
    let full = CMSG_HEADER + UCRED;
    let len = usize::try_from(left).unwrap_or(usize::MAX).min(full);
    let mut cmsg = [0; CMSG_HEADER + UCRED];
    cmsg[..8].copy_from_slice(&(len as u64).to_le_bytes());
    cmsg[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
    cmsg[12..16].copy_from_slice(&SCM_CREDENTIALS.to_le_bytes());
    for (i, id) in [credentials.pid, credentials.uid, credentials.gid]
        .into_iter()
        .enumerate()
    {
        cmsg[CMSG_HEADER + 4 * i..][..4].copy_from_slice(&id.to_le_bytes());
    }
    if c.mem.write(GuestAddr(at), &cmsg[..len]).is_ok() {
        let step = (full.next_multiple_of(8) as u64).min(left);
        *room = (at + step, left - step);
    }
    len < full
}
/// Installs the received descriptors and writes their `SCM_RIGHTS` message
/// in `room`, as Linux's `scm_detach_fds`: as many as it holds, each the
/// lowest free number, until one does not fit under `RLIMIT_NOFILE` or its
/// number cannot be written. The rest are closed. Returns whether any
/// descriptor was lost.
fn put_descriptors(
    c: &mut Context<'_>,
    room: &mut (u64, u64),
    passed: Passed,
    cloexec: bool,
) -> bool {
    let (control, left) = *room;
    let count = passed.len();
    let fit = left.saturating_sub(CMSG_HEADER as u64) / 4;
    let most = usize::try_from(fit).unwrap_or(usize::MAX).min(count);
    let mut installed = 0;
    for descriptor in passed.into_iter().take(most) {
        let Ok(n) = c.files.reserve(c.group.nofile()) else {
            break;
        };
        let at = control + (CMSG_HEADER + 4 * installed) as u64;
        if c.mem.write(GuestAddr(at), &n.to_le_bytes()).is_err() {
            c.files.unreserve(n);
            break;
        }
        c.files.fill(n, descriptor.received(cloexec));
        installed += 1;
    }
    // As scm_detach_fds: the descriptors go in first and the header after,
    // so a header that cannot be written leaves msg_controllen as it was.
    if installed != 0 {
        let len = CMSG_HEADER + 4 * installed;
        let mut cmsg = [0; CMSG_HEADER];
        cmsg[..8].copy_from_slice(&(len as u64).to_le_bytes());
        cmsg[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
        cmsg[12..].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        if c.mem.write(GuestAddr(control), &cmsg).is_ok() {
            let step = (len.next_multiple_of(8) as u64).min(left);
            *room = (control + step, left - step);
        }
    }
    installed < count
}

const SO_DEBUG: u32 = 1;
const SO_REUSEADDR: u32 = 2;
const SO_TYPE: u32 = 3;
const SO_ERROR: u32 = 4;
const SO_DONTROUTE: u32 = 5;
const SO_BROADCAST: u32 = 6;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_KEEPALIVE: u32 = 9;
const SO_OOBINLINE: u32 = 10;
const SO_NO_CHECK: u32 = 11;
const SO_PRIORITY: u32 = 12;
const SO_LINGER: u32 = 13;
const SO_BSDCOMPAT: u32 = 14;
const SO_REUSEPORT: u32 = 15;
const SO_PASSCRED: u32 = 16;
const SO_PEERCRED: u32 = 17;
const SO_RCVLOWAT: u32 = 18;
const SO_SNDLOWAT: u32 = 19;
const SO_RCVTIMEO: u32 = 20;
const SO_SNDTIMEO: u32 = 21;
const SO_TIMESTAMP: u32 = 29;
const SO_RCVTIMEO_NEW: u32 = 66;
const SO_SNDTIMEO_NEW: u32 = 67;
/// The kernel's tick rate, to which Linux rounds `SO_RCVTIMEO` and
/// `SO_SNDTIMEO` (`CONFIG_HZ`).
const HZ: u64 = 1000;
const SO_ACCEPTCONN: u32 = 30;
const SO_SNDBUFFORCE: u32 = 32;
const SO_RCVBUFFORCE: u32 = 33;
const SO_PASSSEC: u32 = 34;
const SO_MARK: u32 = 36;
const SO_PROTOCOL: u32 = 38;
const SO_DOMAIN: u32 = 39;
const SO_PEEK_OFF: u32 = 42;
const SO_BUSY_POLL: u32 = 46;
const SO_INCOMING_CPU: u32 = 49;
/// `net.core.wmem_default` and `rmem_default`, a socket's buffers at first.
const DEFAULT_BUFFER: i32 = 212_992;
/// `net.core.wmem_max` and `rmem_max`, the most `SO_SNDBUF` takes.
const MAX_BUFFER: u32 = 212_992;
/// `SOCK_MIN_SNDBUF` and `SOCK_MIN_RCVBUF`.
const MIN_SEND_BUFFER: i32 = 4608;
const MIN_RECEIVE_BUFFER: i32 = 2304;

/// The `SOL_SOCKET` options of one end that its `setsockopt` keeps, as
/// Linux's `sk_setsockopt` stores them. Only `SO_OOBINLINE` acts here;
/// `SO_SNDBUF` and `SO_RCVBUF` are reported but leave the pair's buffer as it
/// is, and the others have no effect on an AF_UNIX socket on Linux either.
#[derive(Clone, Copy)]
struct Options {
    debug: bool,
    reuse_address: bool,
    dont_route: bool,
    broadcast: bool,
    keep_alive: bool,
    out_of_band_inline: bool,
    no_check: bool,
    priority: i32,
    linger: Option<i32>,
    send_buffer: i32,
    receive_buffer: i32,
    mark: i32,
    busy_poll: i32,
    incoming_cpu: i32,
    receive_timeout: Timeout,
    send_timeout: Timeout,
    /// `SO_RCVLOWAT`: how many bytes a blocking stream read waits for.
    receive_low_water: i32,
}
/// `SO_RCVTIMEO` or `SO_SNDTIMEO`, in ticks of [`HZ`], as Linux's
/// `sk_rcvtimeo` keeps it: a zero `timeval` waits for ever, and a negative
/// one not at all.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Timeout {
    #[default]
    Forever,
    Never,
    Ticks(u64),
}
impl Timeout {
    /// Linux's `sock_set_timeout` of a `timeval` (EDOM for microseconds
    /// outside a second).
    fn from_timeval(seconds: i64, micros: i64) -> Result<Self, Errno> {
        if !(0..1_000_000).contains(&micros) {
            return Err(Errno(33));
        }
        // MAX_SCHEDULE_TIMEOUT / HZ - 1: past it, Linux waits for ever.
        let most = i64::MAX / HZ.cast_signed() - 1;
        Ok(match (seconds, micros) {
            (..0, _) => Timeout::Never,
            (0, 0) => Timeout::Forever,
            (seconds, _) if seconds >= most => Timeout::Forever,
            _ => Timeout::Ticks(
                seconds
                    .cast_unsigned()
                    .saturating_mul(HZ)
                    .saturating_add(micros.cast_unsigned().div_ceil(1_000_000 / HZ)),
            ),
        })
    }
    /// The `timeval` getsockopt gives back, zero unless there is a limit.
    fn timeval(self) -> [u8; 16] {
        let (seconds, micros) = match self {
            Timeout::Ticks(ticks) => (ticks / HZ, ticks % HZ * (1_000_000 / HZ)),
            _ => (0, 0),
        };
        let mut timeval = [0; 16];
        timeval[..8].copy_from_slice(&seconds.to_le_bytes());
        timeval[8..].copy_from_slice(&micros.to_le_bytes());
        timeval
    }
}
/// How long a blocking socket call may wait, from when it starts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    Forever,
    Now,
    Until(u64),
}
impl Wait {
    /// The deadline for [`crate::events::wait`], `None` when the time is up.
    pub(crate) fn deadline(self, c: &Context<'_>) -> Result<Option<Option<u64>>, Errno> {
        Ok(match self {
            Wait::Forever => Some(None),
            Wait::Now => None,
            Wait::Until(end) => {
                (c.host.clock(paludarium_host::ClockId::Monotonic)? < end).then_some(Some(end))
            }
        })
    }
    pub(crate) fn forever(self) -> bool {
        self == Wait::Forever
    }
}
/// How long a blocking read (`receive`) or write of `file` may wait: a
/// socket's `SO_RCVTIMEO` or `SO_SNDTIMEO`, any other file for ever.
pub(crate) fn deadline(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    receive: bool,
) -> Result<Wait, Errno> {
    let Some(socket) = file
        .as_any()
        .and_then(|any| any.downcast_ref::<SocketPairEnd>())
    else {
        return Ok(Wait::Forever);
    };
    let options = *socket
        .options
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(
        match if receive {
            options.receive_timeout
        } else {
            options.send_timeout
        } {
            Timeout::Forever => Wait::Forever,
            Timeout::Never => Wait::Now,
            Timeout::Ticks(ticks) => Wait::Until(
                c.host
                    .clock(paludarium_host::ClockId::Monotonic)?
                    .saturating_add(ticks.saturating_mul(1_000_000_000 / HZ)),
            ),
        },
    )
}
impl Default for Options {
    fn default() -> Self {
        Options {
            debug: false,
            reuse_address: false,
            dont_route: false,
            broadcast: false,
            keep_alive: false,
            out_of_band_inline: false,
            no_check: false,
            priority: 0,
            linger: None,
            send_buffer: DEFAULT_BUFFER,
            receive_buffer: DEFAULT_BUFFER,
            mark: 0,
            busy_poll: 0,
            incoming_cpu: -1,
            receive_timeout: Timeout::Forever,
            send_timeout: Timeout::Forever,
            receive_low_water: 1,
        }
    }
}
/// A socket buffer size as `SO_SNDBUF` or `SO_RCVBUF` sets it: capped at
/// `MAX_BUFFER` unless forced, doubled for Linux's bookkeeping, and at least
/// `least`.
fn buffer_size(value: i32, forced: bool, least: i32) -> i32 {
    let value = value.cast_unsigned();
    let value = if forced { value } else { value.min(MAX_BUFFER) };
    i32::try_from(value.saturating_mul(2))
        .unwrap_or(i32::MAX)
        .max(least)
}
/// `setsockopt(fd, level, name, value, len)` on a socket pair, as Linux's
/// `sk_setsockopt`: a socket pair has only `SOL_SOCKET` options
/// (EOPNOTSUPP for another level), an `int` value of fewer than 4 bytes is
/// EINVAL, and an unknown name, or one whose effect is not modelled here
/// (`SO_PASSSEC`, `SO_TIMESTAMP`), is ENOPROTOOPT. `SO_PASSCRED` makes
/// messages carry credentials ([`Credentials`]), `SO_RCVLOWAT` sets what a
/// stream read waits for ([`receive_with`]; 0 is 1, and a negative value
/// `INT_MAX`), and `SO_PEEK_OFF` where a peek starts (any value, a negative
/// one for none). `SO_RCVTIMEO` and `SO_SNDTIMEO` take a
/// `timeval` ([`Timeout`]). The guest runs as root, so the options that need
/// `CAP_NET_ADMIN` are set.
fn set_option(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    let socket = as_socket(&file)?;
    if a[1] as u32 != SOL_SOCKET {
        return Err(Errno(95));
    }
    let name = a[2] as u32;
    let len = a[4] as u32 as i32;
    if len < 4 {
        return Err(Errno::EINVAL);
    }
    let value = i32::from_le_bytes(
        read_words(c, a[3], 4)?
            .try_into()
            .map_err(|_| Errno::EFAULT)?,
    );
    let on = value != 0;
    if name == SO_PASSCRED {
        socket.lock_sides()[socket.side].pass_credentials = on;
        return Ok(0);
    }
    if name == SO_PEEK_OFF {
        socket.lock_sides()[socket.side].peek_offset = value;
        return Ok(0);
    }
    let mut options = socket
        .options
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match name {
        SO_DEBUG => options.debug = on,
        SO_REUSEADDR => options.reuse_address = on,
        SO_DONTROUTE => options.dont_route = on,
        SO_BROADCAST => options.broadcast = on,
        SO_KEEPALIVE => options.keep_alive = on,
        SO_OOBINLINE => options.out_of_band_inline = on,
        SO_NO_CHECK => options.no_check = on,
        SO_PRIORITY => options.priority = value,
        SO_MARK => options.mark = value,
        SO_BUSY_POLL => options.busy_poll = value,
        SO_INCOMING_CPU => options.incoming_cpu = value,
        SO_RCVLOWAT => options.receive_low_water = if value < 0 { i32::MAX } else { value.max(1) },
        SO_BSDCOMPAT => {}
        SO_SNDBUF | SO_SNDBUFFORCE => {
            options.send_buffer = buffer_size(value, name == SO_SNDBUFFORCE, MIN_SEND_BUFFER);
        }
        SO_RCVBUF | SO_RCVBUFFORCE => {
            options.receive_buffer = buffer_size(value, name == SO_RCVBUFFORCE, MIN_RECEIVE_BUFFER);
        }
        SO_LINGER => {
            if len < 8 {
                return Err(Errno::EINVAL);
            }
            let raw = read_words(c, a[3], 8)?;
            let seconds = i32::from_le_bytes(raw[4..8].try_into().map_err(|_| Errno::EFAULT)?);
            options.linger = on.then_some(seconds);
        }
        SO_RCVTIMEO | SO_SNDTIMEO | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW => {
            if len < 16 {
                return Err(Errno::EINVAL);
            }
            let raw = read_words(c, a[3], 16)?;
            let word = |at: usize| {
                raw.get(at..at + 8)
                    .and_then(|b| b.try_into().ok())
                    .map(i64::from_le_bytes)
                    .ok_or(Errno::EFAULT)
            };
            let timeout = Timeout::from_timeval(word(0)?, word(8)?)?;
            if matches!(name, SO_RCVTIMEO | SO_RCVTIMEO_NEW) {
                options.receive_timeout = timeout;
            } else {
                options.send_timeout = timeout;
            }
        }
        // AF_UNIX takes no SO_REUSEPORT.
        SO_REUSEPORT => return Err(Errno(95)),
        _ => return Err(Errno(92)),
    }
    Ok(0)
}
/// `getsockopt(fd, level, name, value, len)` on a socket pair, as Linux's
/// `sk_getsockopt`: the value, cut to `*len` bytes, and its length back in
/// `*len` (EFAULT when either cannot be read or written, EINVAL for a
/// negative length, ENOPROTOOPT for an unknown name).
fn get_option(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    let socket = as_socket(&file)?;
    if a[1] as u32 != SOL_SOCKET {
        return Err(Errno(95));
    }
    let len = i32::from_le_bytes(
        read_words(c, a[4], 4)?
            .try_into()
            .map_err(|_| Errno::EFAULT)?,
    );
    if len < 0 {
        return Err(Errno::EINVAL);
    }
    let options = *socket
        .options
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let int = |value: i32| value.to_le_bytes().to_vec();
    let value = match a[2] as u32 {
        SO_DEBUG => int(options.debug.into()),
        SO_REUSEADDR => int(options.reuse_address.into()),
        SO_TYPE => int(socket.pair.kind.cast_signed()),
        SO_ERROR | SO_BSDCOMPAT | SO_REUSEPORT | SO_ACCEPTCONN | SO_PASSSEC | SO_TIMESTAMP
        | SO_PROTOCOL => int(0),
        SO_PASSCRED => int(socket.passes_credentials().into()),
        SO_DONTROUTE => int(options.dont_route.into()),
        SO_BROADCAST => int(options.broadcast.into()),
        SO_SNDBUF => int(options.send_buffer),
        SO_RCVBUF => int(options.receive_buffer),
        SO_KEEPALIVE => int(options.keep_alive.into()),
        SO_OOBINLINE => int(options.out_of_band_inline.into()),
        SO_NO_CHECK => int(options.no_check.into()),
        SO_PRIORITY => int(options.priority),
        SO_LINGER => {
            let mut linger = int(options.linger.is_some().into());
            linger.extend(options.linger.unwrap_or(0).to_le_bytes());
            linger
        }
        // The creator's credentials, as root (uid and gid 0).
        SO_PEERCRED => {
            let mut credentials = socket
                .pair
                .creator
                .load(Ordering::SeqCst)
                .to_le_bytes()
                .to_vec();
            credentials.extend([0; 8]);
            credentials
        }
        SO_SNDLOWAT | SO_DOMAIN => int(1),
        SO_RCVLOWAT => int(options.receive_low_water),
        SO_RCVTIMEO | SO_RCVTIMEO_NEW => options.receive_timeout.timeval().to_vec(),
        SO_SNDTIMEO | SO_SNDTIMEO_NEW => options.send_timeout.timeval().to_vec(),
        SO_MARK => int(options.mark),
        SO_PEEK_OFF => int(socket.lock_sides()[socket.side].peek_offset),
        SO_BUSY_POLL => int(options.busy_poll),
        SO_INCOMING_CPU => int(options.incoming_cpu),
        _ => return Err(Errno(92)),
    };
    let len = value.len().min(len.cast_unsigned() as usize);
    c.mem
        .write(GuestAddr(a[3]), &value[..len])
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(a[4]), &(len as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}
/// `len` bytes of guest memory at `at` (EFAULT).
fn read_words(c: &Context<'_>, at: u64, len: usize) -> Result<Vec<u8>, Errno> {
    let mut bytes = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(bytes)
}

/// Descriptors passed with `SCM_RIGHTS`: what one write or message carries.
pub(crate) type Passed = Vec<crate::files::Descriptor>;
/// One successful write, as Linux queues an `sk_buff`.
struct Write {
    len: usize,
    passed: Passed,
    piece: Piece,
    credentials: Credentials,
    /// A message a peek has seen, which a peek from `SO_PEEK_OFF` passes
    /// over once its offset reaches the message's end, empty or not, as
    /// Linux's `skb->peeked`.
    peeked: bool,
}
/// The credentials a write carries, as Linux's `UNIXCB` keeps them for
/// `SCM_CREDENTIALS`: its sender's process ID, user and group when either
/// end passed credentials (`SO_PASSCRED`) as it was sent, or those it gave
/// itself, else none, which a receiver reads as process 0 and the overflow
/// IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Credentials {
    pid: u32,
    uid: u32,
    gid: u32,
}
impl Default for Credentials {
    fn default() -> Self {
        Self {
            pid: 0,
            uid: OVERFLOW_ID,
            gid: OVERFLOW_ID,
        }
    }
}
/// Who sends a write: the sending process, and the credentials sendmsg's
/// `SCM_CREDENTIALS` gave, if any.
#[derive(Clone, Copy, Default)]
pub(crate) struct Sender {
    pid: u32,
    credentials: Option<Credentials>,
}
impl Sender {
    pub(crate) fn process(pid: u32) -> Self {
        Self {
            pid,
            credentials: None,
        }
    }
    /// What a write by this sender carries, when an end `passes` them: the
    /// process's own as root, or as [`Credentials`] says.
    fn credentials(self, passes: bool) -> Credentials {
        self.credentials.unwrap_or(if passes {
            Credentials {
                pid: self.pid,
                uid: 0,
                gid: 0,
            }
        } else {
            Credentials::default()
        })
    }
}
/// What a stream's write is: data, or its out-of-band byte, as Linux's
/// `oob_skb`, which stays in the queue, empty, once `MSG_OOB` took it. A
/// read stops before either, and one that reaches it with nothing read yet
/// drops it, the byte too, and reads on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Piece {
    Data,
    OutOfBand,
    Taken,
}
/// What one read took: the bytes copied, the descriptors that came with them,
/// and whether a message was longer than the buffer (`MSG_TRUNC`).
#[derive(Default)]
pub(crate) struct Received {
    pub(crate) count: usize,
    pub(crate) passed: Passed,
    pub(crate) truncated: bool,
    /// The whole message's length, or the bytes copied from a stream.
    pub(crate) length: usize,
    /// A stream read stopped at the out-of-band mark.
    at_mark: bool,
    /// The credentials of the data read.
    pub(crate) credentials: Credentials,
    /// A stream read with `SO_PASSCRED` stopped before data of other
    /// credentials.
    other_sender: bool,
    /// The descriptors of dropped out-of-band bytes, closed with this,
    /// outside the socket's lock.
    discarded: Passed,
}
impl Received {
    /// What recvmsg or recvfrom returns: with `MSG_TRUNC`, a message's
    /// whole length, even past the buffer, as Linux's AF_UNIX sockets do.
    fn returned(&self, flags: u64) -> u64 {
        if flags & u64::from(MSG_TRUNC) != 0 {
            self.length as u64
        } else {
            self.count as u64
        }
    }
}
#[derive(Default)]
struct Side {
    bytes: VecDeque<u8>,
    /// Remaining bytes per successful write, to retain poll callbacks when
    /// a peer consumes one write while later writes remain unread, and the
    /// descriptors the write passed.
    writes: VecDeque<Write>,
    closed: bool,
    read_shutdown: bool,
    write_shutdown: bool,
    input_epoch: u64,
    output_epoch: u64,
    /// SOCK_DGRAM: a send found the peer closed, so this side has no peer
    /// any more (`ECONNREFUSED` once, then `ENOTCONN`).
    disconnected: bool,
    /// `F_SETOWN` and `F_SETSIG`: who this end's `O_ASYNC` signals and a
    /// stream's out-of-band byte for it (SIGURG) go to, and with what.
    owner: FileOwner,
    /// `O_ASYNC`: this end signals its owner when it changes.
    registration: Option<Registration>,
    /// A send found the buffer full, so the space a read frees signals this
    /// end `POLL_OUT`, once, as Linux's `SOCKWQ_ASYNC_NOSPACE`.
    no_space: bool,
    /// `SO_PASSCRED`: what this end receives carries credentials, and so
    /// does what it sends.
    pass_credentials: bool,
    /// `SO_PEEK_OFF`: where a peek starts, moved on by each peek and back
    /// by each read, as Linux's `sk_peek_off`; a negative value is none.
    peek_offset: i32,
}
struct Pair {
    sides: Mutex<[Side; 2]>,
    /// The process that made the pair, which `SO_PEERCRED` names for both
    /// ends, as Linux's `unix_socketpair` records its credentials.
    creator: AtomicU32,
    hub: Arc<ReadinessHub>,
    /// SOCK_STREAM, SOCK_DGRAM or SOCK_SEQPACKET. The last two keep message
    /// boundaries: each write is one message, and each read returns one
    /// whole message, truncated to the buffer, as on Linux.
    kind: u32,
    /// How many unread bytes each direction holds: the socket send buffer,
    /// or a pipe's capacity (`F_SETPIPE_SZ`).
    window: AtomicUsize,
    /// The pair is a pipe, whose `O_ASYNC` signals differ from a socket's.
    pipe: AtomicBool,
}
impl Pair {
    fn messages(&self) -> bool {
        self.kind != SOCK_STREAM
    }
    fn window(&self) -> usize {
        self.window.load(Ordering::SeqCst)
    }
}
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_SEQPACKET: u32 = 5;
/// Linux refuses a message longer than the send buffer less 32 bytes.
const MAX_MESSAGE: usize = SEND_WINDOW - 32;
pub(crate) struct SocketPairEnd {
    pair: Arc<Pair>,
    side: usize,
    flags: AtomicU32,
    /// Each end is a socket of its own, with its own inode.
    inode: u64,
    attributes: Attributes,
    /// The `SOL_SOCKET` options set on this end ([`Options`]).
    options: Mutex<Options>,
}
impl SocketPairEnd {
    fn lock_sides(&self) -> std::sync::MutexGuard<'_, [Side; 2]> {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// `SO_PASSCRED` on this end.
    fn passes_credentials(&self) -> bool {
        self.lock_sides()[self.side].pass_credentials
    }
    /// `SO_RCVLOWAT` on this end.
    fn receive_low_water(&self) -> usize {
        let low = self
            .options
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .receive_low_water;
        usize::try_from(low).unwrap_or(1)
    }
    /// The bytes waiting to be read on this side.
    fn unread(&self) -> usize {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[self.side]
            .bytes
            .len()
    }
    /// Only a SOCK_STREAM socket raises SIGPIPE with EPIPE, as on Linux.
    pub(crate) fn raises_sigpipe(&self) -> bool {
        self.pair.kind == SOCK_STREAM
    }
    pub fn pair(kind: u32, hub: Arc<ReadinessHub>) -> Result<[Arc<Self>; 2], Errno> {
        if kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 {
            return Err(Errno::EINVAL);
        }
        if !matches!(kind & 0xf, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
            return Err(Errno(94)); // ESOCKTNOSUPPORT
        }
        let pair = Arc::new(Pair {
            creator: AtomicU32::new(0),
            kind: kind & 0xf,
            window: AtomicUsize::new(SEND_WINDOW),
            pipe: AtomicBool::new(false),
            sides: Mutex::new(std::array::from_fn(|_| Side {
                output_epoch: 1,
                peek_offset: -1,
                ..Side::default()
            })),
            hub,
        });
        Ok(std::array::from_fn(|side| {
            Arc::new(Self {
                pair: Arc::clone(&pair),
                side,
                flags: AtomicU32::new(2 | kind & NONBLOCK),
                inode: crate::files::anonymous_inode(),
                attributes: Attributes::new(0o140777),
                options: Mutex::default(),
            })
        }))
    }
    pub fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if how == 0 || how == 2 {
            sides[self.side].read_shutdown = true;
            sides[self.side].input_epoch = sides[self.side].input_epoch.wrapping_add(1);
        }
        if how == 1 || how == 2 {
            sides[self.side].write_shutdown = true;
            sides[1 - self.side].input_epoch = sides[1 - self.side].input_epoch.wrapping_add(1);
        }
        // A stream or packet peer hangs up when both directions shut down in
        // one call, and has data (its end) when only writing does, as Linux's
        // `unix_shutdown`.
        let reason = match how {
            2 => Some(Reason::HangUp),
            1 => Some(Reason::In),
            _ => None,
        };
        let notice = reason
            .filter(|_| self.pair.kind != SOCK_DGRAM && !self.is_pipe())
            .and_then(|reason| Self::notice(&sides, 1 - self.side, reason));
        drop(sides);
        self.pair.hub.changed();
        if let Some(notice) = notice {
            notice.send();
        }
        Ok(())
    }
}
impl SocketPairEnd {
    /// Reads into `buf`; `message` is the form of recvmsg and recvfrom
    /// (`sock_recvmsg`), which an empty buffer does not end at once as read's
    /// does (Linux's `sock_read_iter`). With `peek` (`MSG_PEEK`) the data
    /// stays.
    pub(crate) fn receive(
        &self,
        buf: &mut [u8],
        message: bool,
        peek: bool,
    ) -> Result<Received, Errno> {
        if buf.is_empty() && !message {
            return Ok(Received::default());
        }
        let result = if self.pair.messages() {
            self.read_message(buf, peek)
        } else {
            self.read_stream(buf, peek, None)
        };
        self.after_read(peek, &result);
        result
    }
    /// [`Self::receive`] in a read that already took some of a stream
    /// (`SO_RCVLOWAT`, `MSG_WAITALL`): as Linux's `manage_oob` counts the
    /// whole call, it stops at the out-of-band mark rather than drop or pass
    /// it, and with `SO_PASSCRED` before data of other `credentials` than it
    /// read.
    fn receive_more(&self, buf: &mut [u8], credentials: Credentials) -> Result<Received, Errno> {
        let result = self.read_stream(buf, false, Some(credentials));
        self.after_read(false, &result);
        result
    }
    /// sendmsg's and sendto's `MSG_OOB`, EOPNOTSUPP: a datagram or packet
    /// socket refuses it `before` the address is checked, as Linux's
    /// `unix_dgram_sendmsg` after `__scm_send`, and a stream after it, only
    /// for an empty send; [`send_bytes`] sends a stream's last byte out of
    /// band.
    fn check_out_of_band_send(&self, flags: u64, before: bool, len: usize) -> Result<(), Errno> {
        if flags & MSG_OOB != 0 && self.pair.messages() == before && (before || len == 0) {
            return Err(Errno(95));
        }
        Ok(())
    }
    /// recvmsg's and recvfrom's `MSG_OOB`: only a stream has out-of-band
    /// data (EOPNOTSUPP on the other kinds).
    fn check_out_of_band(&self, flags: u64) -> Result<(), Errno> {
        if flags & MSG_OOB != 0 && self.pair.messages() {
            return Err(Errno(95));
        }
        Ok(())
    }
    /// `SIOCATMARK`: a stream's next write is its out-of-band byte, or the
    /// place `MSG_OOB` took it from; a datagram or packet socket is never at
    /// a mark, as Linux 7.0.0 answers. (Later 7.0 releases refuse it there
    /// with EOPNOTSUPP.)
    pub(crate) fn at_mark(&self) -> bool {
        !self.pair.messages()
            && self
                .pair
                .sides
                .lock()
                .unwrap_or_else(PoisonError::into_inner)[self.side]
                .writes
                .front()
                .is_some_and(|write| write.piece != Piece::Data)
    }
    /// Whether `SO_OOBINLINE` reads the out-of-band byte with the data.
    fn out_of_band_inline(&self) -> bool {
        self.options
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .out_of_band_inline
    }
    /// `F_GETOWN`: who this end's signals go to.
    pub(crate) fn file_owner(&self) -> FileOwner {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[self.side]
            .owner
    }
    /// `F_SETOWN` and `F_SETSIG`.
    pub(crate) fn set_file_owner(&self, owner: FileOwner) {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[self.side]
            .owner = owner;
    }
    /// Who this end's out-of-band bytes reach (the peer's owner).
    fn peer_owner(&self) -> FileOwner {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[1 - self.side]
            .owner
    }
    /// `F_SETFL` turning `O_ASYNC` on, with its registration, or off.
    pub(crate) fn set_async(&self, registration: Option<Registration>) {
        self.pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[self.side]
            .registration = registration;
    }
    fn is_pipe(&self) -> bool {
        self.pair.pipe.load(Ordering::SeqCst)
    }
    /// The signal side `side` owes for `reason`, if it is open with
    /// `O_ASYNC`.
    fn notice(sides: &[Side; 2], side: usize, reason: Reason) -> Option<Notice> {
        let side = &sides[side];
        let to = side.registration.clone().filter(|_| !side.closed)?;
        Some(Notice {
            to,
            owner: side.owner,
            reason,
        })
    }
    /// Signals side `side` for `reason`, if it is open with `O_ASYNC`.
    fn notify(&self, side: usize, reason: Reason) {
        let sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let notice = Self::notice(&sides, side, reason);
        drop(sides);
        if let Some(notice) = notice {
            notice.send();
        }
    }
    /// After a socket read that took data (`peeked` leaves it): a send that
    /// found no room can go on, which signals its end `POLL_OUT`, as
    /// `unix_write_space` (a pipe's reads signal in [`pipe_read_ended`]).
    fn after_read<T>(&self, peeked: bool, result: &Result<T, Errno>) {
        if peeked || result.is_err() || self.is_pipe() {
            return;
        }
        let peer = 1 - self.side;
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let room = sides[self.side].bytes.len() < self.pair.window();
        if !(sides[peer].no_space && room) {
            return;
        }
        sides[peer].no_space = false;
        let notice = Self::notice(&sides, peer, Reason::Out);
        drop(sides);
        if let Some(notice) = notice {
            notice.send();
        }
    }
    /// recvmsg's and recvfrom's `MSG_OOB` on a stream, as Linux's
    /// `unix_stream_recv_urg`: the out-of-band byte, which `peek` leaves,
    /// EINVAL when there is none.
    fn receive_out_of_band(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        let result = self.take_out_of_band(buf, peek);
        self.after_read(peek, &result);
        result
    }
    fn take_out_of_band(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        // With SO_OOBINLINE the byte comes with the data, not on its own.
        if self.out_of_band_inline() {
            return Err(Errno::EINVAL);
        }
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let own = &mut sides[self.side];
        let index = own
            .writes
            .iter()
            .position(|write| write.piece == Piece::OutOfBand)
            .ok_or(Errno::EINVAL)?;
        let at: usize = own.writes.iter().take(index).map(|write| write.len).sum();
        let count = buf.len().min(1);
        if let (Some(byte), Some(&value)) = (buf.first_mut(), own.bytes.get(at)) {
            *byte = value;
        }
        if !peek {
            own.bytes.remove(at);
            if let Some(write) = own.writes.get_mut(index) {
                write.piece = Piece::Taken;
                write.len = 0;
            }
            sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
            self.pair.hub.changed();
        }
        Ok(Received {
            count,
            length: 1,
            ..Received::default()
        })
    }
    /// SOCK_SEQPACKET and SOCK_DGRAM read: the next whole message,
    /// truncated to `buf`, with its descriptors. An empty buffer reaches
    /// here only from recvmsg or recvfrom, and discards the message. A
    /// `peek` leaves the message, and gives copies of its descriptors, as
    /// Linux's `scm_fp_dup`; from `SO_PEEK_OFF` it starts that far in,
    /// past whole messages, as `__skb_try_recv_from_queue`, and the length
    /// it gives is what is left of the message from there.
    fn read_message(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        let nonblocking = self.flags() & NONBLOCK != 0;
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let eof = sides[self.side].read_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].write_shutdown;
        let datagram = self.pair.kind == SOCK_DGRAM;
        let own = &mut sides[self.side];
        if own.read_shutdown && !datagram {
            return Ok(Received::default());
        }
        let offset = usize::try_from(own.peek_offset).ok();
        let mut skip = offset.unwrap_or(0);
        let mut start = 0;
        let found = own.writes.iter().position(|message| {
            let past = offset.is_some() && skip >= message.len && (skip != 0 || message.peeked);
            if past {
                skip -= message.len;
                start += message.len;
            }
            !past
        });
        if peek && let Some(message) = found.and_then(|index| own.writes.get_mut(index)) {
            message.peeked = true;
            let left = message.len - skip;
            let count = buf.len().min(left);
            for (d, s) in buf
                .iter_mut()
                .zip(own.bytes.range(start + skip..start + skip + count))
            {
                *d = *s;
            }
            let received = Received {
                count,
                truncated: count < left,
                passed: message.passed.clone(),
                length: left,
                credentials: message.credentials,
                ..Received::default()
            };
            Self::peeked(own, count);
            return Ok(received);
        }
        let message = if peek { None } else { own.writes.pop_front() };
        let Some(message) = message else {
            // A datagram socket has no end of file from its peer: only its
            // own SHUT_RD ends a blocking read, and a nonblocking one still
            // finds nothing.
            return if datagram {
                if own.read_shutdown && !nonblocking {
                    Ok(Received::default())
                } else {
                    Err(Errno::EAGAIN)
                }
            } else if eof {
                Ok(Received::default())
            } else {
                Err(Errno::EAGAIN)
            };
        };
        let count = buf.len().min(message.len);
        for (i, byte) in own.bytes.drain(..message.len).enumerate() {
            if i < count {
                buf[i] = byte;
            }
        }
        Self::consumed(own, message.len);
        sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        self.pair.hub.changed();
        Ok(Received {
            count,
            truncated: count < message.len,
            passed: message.passed,
            length: message.len,
            credentials: message.credentials,
            ..Received::default()
        })
    }
}
impl SocketPairEnd {
    /// SOCK_STREAM read. As Linux's `unix_stream_read_generic`, it goes on
    /// across writes but ends with the first one that passed descriptors,
    /// which come with its first bytes read; an empty buffer still takes
    /// them. With `SO_PASSCRED` it also ends before a write of other
    /// credentials than the first it reads, or than `after` for a call that
    /// already read some ([`Self::receive_more`]). A `peek` from
    /// `SO_PEEK_OFF` on leaves the data where it is.
    fn read_stream(
        &self,
        buf: &mut [u8],
        peek: bool,
        after: Option<Credentials>,
    ) -> Result<Received, Errno> {
        let inline = self.out_of_band_inline();
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let eof = sides[self.side].read_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].write_shutdown;
        let full = sides[self.side].bytes.len() >= self.pair.window();
        let own = &mut sides[self.side];
        if own.read_shutdown {
            return Ok(Received::default());
        }
        let glue = own.pass_credentials;
        // Past what the call read, the mark ends it.
        let mark = |write: &Write| write.piece != Piece::Data;
        if after.is_some() && own.writes.front().is_some_and(mark) {
            return Ok(Received {
                at_mark: true,
                ..Received::default()
            });
        }
        // The empty places out-of-band bytes were taken from go first.
        let mut discarded = Passed::new();
        if !peek {
            while let Some(taken) = own.writes.pop_front_if(|write| write.piece == Piece::Taken) {
                discarded.extend(taken.passed);
            }
        }
        if own.bytes.is_empty() {
            drop(sides);
            return if eof {
                Ok(Received {
                    discarded,
                    ..Received::default()
                })
            } else {
                Err(Errno::EAGAIN)
            };
        }
        if peek {
            let skip = usize::try_from(own.peek_offset).unwrap_or(0);
            let received = Self::peek_stream(own, buf, skip, inline, glue);
            Self::peeked(own, received.count);
            return if received.count == 0
                && received.passed.is_empty()
                && !buf.is_empty()
                && !received.at_mark
                && !received.other_sender
            {
                if eof {
                    Ok(Received::default())
                } else {
                    Err(Errno::EAGAIN)
                }
            } else {
                Ok(received)
            };
        }
        let mut received = Received {
            discarded,
            ..Received::default()
        };
        let mut credentials = after;
        let mut consumed_write = false;
        while let Some(front) = own.writes.front_mut() {
            // Stop before the mark; at it, drop the out-of-band byte and read
            // on, as Linux's manage_oob.
            if front.piece != Piece::Data && received.count != 0 {
                received.at_mark = true;
                break;
            }
            // SO_OOBINLINE: at the mark, the byte is read as data.
            if front.piece == Piece::OutOfBand && inline {
                front.piece = Piece::Data;
            }
            if front.piece != Piece::Data {
                let dropped = own.writes.pop_front().ok_or(Errno::EIO)?;
                own.bytes.drain(..dropped.len);
                received.discarded.extend(dropped.passed);
                consumed_write = true;
                continue;
            }
            // Writes of other credentials are not read together, as
            // Linux's unix_skb_scm_eq.
            match credentials {
                Some(read) if glue && read != front.credentials => {
                    received.other_sender = true;
                    break;
                }
                Some(_) => {}
                None => credentials = Some(front.credentials),
            }
            let count = front.len.min(buf.len() - received.count);
            for byte in &mut buf[received.count..received.count + count] {
                *byte = own.bytes.pop_front().ok_or(Errno::EIO)?;
            }
            received.count += count;
            front.len -= count;
            let passed = !front.passed.is_empty();
            if passed {
                received.passed = std::mem::take(&mut front.passed);
            }
            if front.len == 0 {
                own.writes.pop_front();
                consumed_write = true;
            }
            if passed || received.count == buf.len() {
                break;
            }
        }
        Self::consumed(&mut sides[self.side], received.count);
        if full || consumed_write {
            sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        }
        self.pair.hub.changed();
        received.length = received.count;
        received.credentials = credentials.unwrap_or_default();
        // Only an out-of-band byte was there, and it is gone.
        if received.count == 0
            && received.passed.is_empty()
            && !buf.is_empty()
            && !received.other_sender
        {
            drop(sides);
            return if eof {
                Ok(received)
            } else {
                drop(received);
                Err(Errno::EAGAIN)
            };
        }
        Ok(received)
    }
    /// What a stream read from `skip` bytes on would take, left in `own`:
    /// it stops after a write that passed descriptors, giving copies of
    /// them, and, when it `glue`s, before one of other credentials.
    fn peek_stream(
        own: &Side,
        buf: &mut [u8],
        mut skip: usize,
        inline: bool,
        glue: bool,
    ) -> Received {
        let mut received = Received::default();
        let mut credentials = None;
        let mut start = 0;
        for write in &own.writes {
            let at = start;
            start += write.len;
            // A peek stops at the mark, as a read does, or passes over it.
            if write.piece != Piece::Data {
                if received.count != 0 {
                    received.at_mark = true;
                    break;
                }
                if !(inline && write.piece == Piece::OutOfBand) {
                    continue;
                }
            }
            if skip >= write.len {
                skip -= write.len;
                continue;
            }
            match credentials {
                Some(read) if glue && read != write.credentials => {
                    received.other_sender = true;
                    break;
                }
                Some(_) => {}
                None => credentials = Some(write.credentials),
            }
            let count = (write.len - skip).min(buf.len() - received.count);
            let from = at + skip;
            for (d, s) in buf[received.count..received.count + count]
                .iter_mut()
                .zip(own.bytes.range(from..from + count))
            {
                *d = *s;
            }
            received.count += count;
            skip = 0;
            if !write.passed.is_empty() {
                received.passed = write.passed.clone();
                break;
            }
            if received.count == buf.len() {
                break;
            }
        }
        received.length = received.count;
        received.credentials = credentials.unwrap_or_default();
        received
    }
    /// A peek of `count` bytes moves `SO_PEEK_OFF` on (`sk_peek_offset_fwd`).
    fn peeked(own: &mut Side, count: usize) {
        if own.peek_offset >= 0 {
            let count = i32::try_from(count).unwrap_or(i32::MAX);
            own.peek_offset = own.peek_offset.saturating_add(count);
        }
    }
    /// A read of `count` bytes, or of a message that long, moves
    /// `SO_PEEK_OFF` back, not below 0 (`sk_peek_offset_bwd`).
    fn consumed(own: &mut Side, count: usize) {
        if own.peek_offset >= 0 {
            let count = i32::try_from(count).unwrap_or(i32::MAX);
            own.peek_offset = own.peek_offset.saturating_sub(count).max(0);
        }
    }
}
impl Drop for SocketPairEnd {
    fn drop(&mut self) {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sides[self.side].closed = true;
        sides[1 - self.side].input_epoch = sides[1 - self.side].input_epoch.wrapping_add(1);
        // The last writer of a pipe gives its reader `POLL_IN`, its last
        // reader the writer `POLL_OUT` (`pipe_release`); a stream or packet
        // socket's peer hangs up (`unix_release_sock`).
        let reason = if self.is_pipe() {
            Some(if sides[self.side].write_shutdown {
                Reason::Out
            } else {
                Reason::In
            })
        } else {
            (self.pair.kind != SOCK_DGRAM).then_some(Reason::HangUp)
        };
        let notice = reason.and_then(|reason| Self::notice(&sides, 1 - self.side, reason));
        // Linux frees the receive queue with the socket, and closes the
        // descriptors in it. Closing one may end another socket, even this
        // pair's other end, so it happens after the lock is released.
        let passed: Vec<Passed> = sides[self.side]
            .writes
            .iter_mut()
            .map(|write| std::mem::take(&mut write.passed))
            .collect();
        drop(sides);
        self.pair.hub.changed();
        if let Some(notice) = notice {
            notice.send();
        }
        drop(passed);
    }
}
impl FileHandle for SocketPairEnd {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let own = &sides[self.side];
        let peer = &sides[1 - self.side];
        // An empty message is readable too, and so is the empty place a
        // stream's out-of-band byte was taken from.
        let readable = !own.bytes.is_empty() || !own.writes.is_empty();
        let urgent = own
            .writes
            .iter()
            .any(|write| write.piece == Piece::OutOfBand);
        if self.pair.kind == SOCK_DGRAM {
            // Only this side's own shutdowns show; a closed peer does not.
            let shut = (u32::from(own.read_shutdown) * (IN | 0x2000))
                | (u32::from(own.read_shutdown && own.write_shutdown) * 0x10);
            let writable = peer.bytes.len() < self.pair.window() || peer.closed;
            let mask = (u32::from(writable) * OUT) | (u32::from(readable) * IN) | shut;
            return Ok((mask, own.input_epoch, own.output_epoch));
        }
        let eof = own.read_shutdown || peer.closed || peer.write_shutdown;
        let mask = (u32::from(peer.bytes.len() < self.pair.window() || peer.closed) * OUT)
            | (u32::from(readable || eof) * IN)
            | (u32::from(urgent) * PRI)
            | if peer.closed {
                0x2010
            } else if peer.write_shutdown {
                0x2000
            } else {
                0
            };
        Ok((mask, own.input_epoch, own.output_epoch))
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        // Descriptors that come to a plain read are closed, as Linux does.
        self.receive(buf, false, false)
            .map(|received| received.count)
    }
    /// A write with no sending process known, as a pipe's; the write
    /// syscalls send through [`Self::send`] with theirs.
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.send(buf, &mut Passed::new(), Sender::default())
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.attributes.stat(self.inode))
    }
    /// `sockfs_setattr`, through `simple_setattr`.
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.attributes.set_mode(mode);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        self.attributes.set_owner(uid, gid);
        Ok(())
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
        self.flags
            .store(2 | flags & (NONBLOCK | O_ASYNC), Ordering::SeqCst);
        Ok(())
    }
}
impl SocketPairEnd {
    /// Writes `buf` from `sender`, taking `passed` with the first bytes that
    /// go; what is left in it went nowhere (a stream write of no bytes
    /// passes nothing, as on Linux), and the caller closes it after the lock
    /// is released.
    pub(crate) fn send(
        &self,
        buf: &[u8],
        passed: &mut Passed,
        sender: Sender,
    ) -> Result<usize, Errno> {
        let result = self.send_data(buf, passed, sender);
        match result {
            // The peer has data (a message may be empty), as Linux's
            // `sk_data_ready` tells it.
            Ok(count) if count != 0 || self.pair.messages() => {
                self.notify(1 - self.side, Reason::In);
            }
            Err(e) if e == Errno::EAGAIN => {
                self.pair
                    .sides
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)[self.side]
                    .no_space = true;
            }
            _ => {}
        }
        result
    }
    fn send_data(&self, buf: &[u8], passed: &mut Passed, sender: Sender) -> Result<usize, Errno> {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // As Linux's unix_maybe_add_creds, as the write is sent.
        let credentials =
            sender.credentials(sides[0].pass_credentials || sides[1].pass_credentials);
        if self.pair.kind == SOCK_DGRAM {
            // unix_dgram_sendmsg's order: the size, this side's shutdown and
            // send buffer, then the peer.
            let [own, peer] = if self.side == 0 {
                let [a, b] = &mut *sides;
                [a, b]
            } else {
                let [a, b] = &mut *sides;
                [b, a]
            };
            if buf.len() > MAX_MESSAGE {
                return Err(Errno(90)); // EMSGSIZE
            }
            if own.write_shutdown {
                return Err(Errno(32));
            }
            // A closed peer's receive queue is freed with it.
            if !peer.closed && self.pair.window().saturating_sub(peer.bytes.len()) < buf.len() {
                return Err(Errno::EAGAIN);
            }
            if own.disconnected {
                return Err(Errno(107)); // ENOTCONN
            }
            if peer.closed {
                own.disconnected = true;
                return Err(Errno(111)); // ECONNREFUSED
            }
            if peer.read_shutdown {
                return Err(Errno(32));
            }
            peer.bytes
                .try_reserve(buf.len())
                .map_err(|_| Errno::ENOMEM)?;
            peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            peer.input_epoch = peer.input_epoch.wrapping_add(1);
            peer.bytes.extend(buf.iter().copied());
            peer.writes.push_back(Write {
                len: buf.len(),
                passed: std::mem::take(passed),
                piece: Piece::Data,
                credentials,
                peeked: false,
            });
            self.pair.hub.changed();
            return Ok(buf.len());
        }
        if sides[self.side].write_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].read_shutdown
        {
            return Err(Errno(32));
        }
        let peer = &mut sides[1 - self.side];
        if self.pair.messages() {
            // A message goes whole or not at all; one that can never fit is
            // EMSGSIZE, and an empty one is a message too.
            if buf.len() > MAX_MESSAGE {
                return Err(Errno(90));
            }
            if self.pair.window().saturating_sub(peer.bytes.len()) < buf.len() {
                return Err(Errno::EAGAIN);
            }
            peer.bytes
                .try_reserve(buf.len())
                .map_err(|_| Errno::ENOMEM)?;
            peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            peer.input_epoch = peer.input_epoch.wrapping_add(1);
            peer.bytes.extend(buf.iter().copied());
            peer.writes.push_back(Write {
                len: buf.len(),
                passed: std::mem::take(passed),
                piece: Piece::Data,
                credentials,
                peeked: false,
            });
            self.pair.hub.changed();
            return Ok(buf.len());
        }
        let count = buf
            .len()
            .min(self.pair.window().saturating_sub(peer.bytes.len()));
        if count == 0 && !buf.is_empty() {
            return Err(Errno::EAGAIN);
        }
        peer.bytes.try_reserve(count).map_err(|_| Errno::ENOMEM)?;
        if count != 0 {
            peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        }
        // Additional bytes wake a readable peer's poll callback as well.
        if count != 0 {
            peer.input_epoch = peer.input_epoch.wrapping_add(1);
        }
        peer.bytes.extend(buf[..count].iter().copied());
        if count != 0 {
            peer.writes.push_back(Write {
                len: count,
                passed: std::mem::take(passed),
                piece: Piece::Data,
                credentials,
                peeked: false,
            });
        }
        self.pair.hub.changed();
        Ok(count)
    }
    /// Queues `byte` as the peer's out-of-band byte, after the stream's
    /// data, as Linux's `queue_oob`: an earlier one still unread becomes
    /// data, and the descriptors not sent yet go with it.
    pub(crate) fn send_out_of_band(
        &self,
        byte: u8,
        passed: &mut Passed,
        sender: Sender,
    ) -> Result<usize, Errno> {
        let result = self.queue_out_of_band(byte, passed, sender);
        // An `F_SETSIG` signal for the urgent byte (SIGURG goes besides),
        // then one for the data, as Linux's `queue_oob`.
        if result.is_ok() {
            self.notify(1 - self.side, Reason::Priority);
            self.notify(1 - self.side, Reason::In);
        }
        result
    }
    fn queue_out_of_band(
        &self,
        byte: u8,
        passed: &mut Passed,
        sender: Sender,
    ) -> Result<usize, Errno> {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let credentials =
            sender.credentials(sides[0].pass_credentials || sides[1].pass_credentials);
        if sides[self.side].write_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].read_shutdown
        {
            return Err(Errno(32));
        }
        let peer = &mut sides[1 - self.side];
        peer.bytes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        for write in &mut peer.writes {
            if write.piece == Piece::OutOfBand {
                write.piece = Piece::Data;
            }
        }
        peer.input_epoch = peer.input_epoch.wrapping_add(1);
        peer.bytes.push_back(byte);
        peer.writes.push_back(Write {
            len: 1,
            passed: std::mem::take(passed),
            piece: Piece::OutOfBand,
            credentials,
            peeked: false,
        });
        self.pair.hub.changed();
        Ok(1)
    }
}
#[cfg(test)]
mod events_tests {
    use super::*;
    fn pair() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(1, Arc::default()).unwrap()
    }
    fn send(end: &SocketPairEnd, bytes: &[u8]) {
        assert_eq!(
            end.send(bytes, &mut Passed::new(), Sender::default()),
            Ok(bytes.len())
        );
    }
    fn set_peek_offset(end: &SocketPairEnd, offset: i32) {
        end.lock_sides()[end.side].peek_offset = offset;
    }
    fn peek_offset(end: &SocketPairEnd) -> i32 {
        end.lock_sides()[end.side].peek_offset
    }
    #[test]
    fn a_stream_peek_starts_at_the_peek_offset() {
        let [a, b] = pair();
        send(&a, b"abc");
        send(&a, b"de");
        set_peek_offset(&b, 0);
        let mut buf = [0; 8];
        assert_eq!(b.receive(&mut buf[..2], true, true).unwrap().count, 2);
        let peeked = b.receive(&mut buf, true, true).unwrap();
        assert_eq!(&buf[..peeked.count], b"cde");
        assert_eq!(peek_offset(&b), 5);
        assert_eq!(b.receive(&mut buf, true, true).err(), Some(Errno::EAGAIN));
        // A read moves it back, not below 0.
        assert_eq!(b.receive(&mut buf[..2], true, false).unwrap().count, 2);
        assert_eq!(peek_offset(&b), 3);
        assert_eq!(b.receive(&mut buf, true, false).unwrap().count, 3);
        assert_eq!(peek_offset(&b), 0);
        // A negative offset is none, and stays.
        send(&a, b"f");
        set_peek_offset(&b, -2);
        assert_eq!(b.receive(&mut buf, true, true).unwrap().count, 1);
        assert_eq!(b.receive(&mut buf, true, false).unwrap().count, 1);
        assert_eq!(peek_offset(&b), -2);
    }
    #[test]
    fn a_message_peek_passes_over_whole_messages() {
        let [a, b] = SocketPairEnd::pair(SOCK_DGRAM, Arc::default()).unwrap();
        send(&a, b"abc");
        send(&a, b"");
        send(&a, b"de");
        set_peek_offset(&b, 1);
        let mut buf = [0; 8];
        let peeked = b.receive(&mut buf[..1], true, true).unwrap();
        assert_eq!((buf[0], peeked.length, peeked.truncated), (b'b', 2, true));
        assert_eq!(b.receive(&mut buf, true, true).unwrap().count, 1);
        assert_eq!(peek_offset(&b), 3);
        // The empty message is peeked once, then passed over.
        let empty = b.receive(&mut buf, true, true).unwrap();
        assert_eq!((empty.count, empty.length), (0, 0));
        let peeked = b.receive(&mut buf, true, true).unwrap();
        assert_eq!(&buf[..peeked.count], b"de");
        assert_eq!(b.receive(&mut buf, true, true).err(), Some(Errno::EAGAIN));
        // A read moves it back by the whole message.
        assert_eq!(b.receive(&mut buf[..1], true, false).unwrap().length, 3);
        assert_eq!(peek_offset(&b), 2);
    }
    #[test]
    fn a_stream_keeps_its_out_of_band_byte_at_the_mark() {
        let [a, b] = pair();
        let mut buf = [0; 8];
        assert_eq!(a.send(b"ab", &mut Passed::new(), Sender::default()), Ok(2));
        assert_eq!(
            a.send_out_of_band(b'c', &mut Passed::new(), Sender::default()),
            Ok(1)
        );
        assert_ne!(b.readiness().unwrap().0 & PRI, 0);
        assert!(!b.at_mark());
        // A read stops before the mark; the byte comes with MSG_OOB, once.
        let read = b.receive(&mut buf, true, false).unwrap();
        assert_eq!((read.count, read.at_mark), (2, true));
        assert!(b.at_mark());
        let peeked = b.receive_out_of_band(&mut buf, true).unwrap();
        assert_eq!((peeked.count, buf[0]), (1, b'c'));
        assert_eq!(b.receive_out_of_band(&mut buf, false).unwrap().count, 1);
        assert_eq!(b.readiness().unwrap().0 & PRI, 0);
        assert!(b.at_mark());
        assert_eq!(
            b.receive_out_of_band(&mut buf, false).err(),
            Some(Errno::EINVAL)
        );
        // A later byte makes an earlier one data; a read that reaches the
        // mark with nothing read drops the byte and reads on.
        assert_eq!(
            a.send_out_of_band(b'x', &mut Passed::new(), Sender::default()),
            Ok(1)
        );
        assert_eq!(
            a.send_out_of_band(b'y', &mut Passed::new(), Sender::default()),
            Ok(1)
        );
        assert_eq!(a.send(b"z", &mut Passed::new(), Sender::default()), Ok(1));
        assert_eq!(b.receive(&mut buf, true, false).unwrap().count, 1);
        assert_eq!(buf[0], b'x');
        assert_eq!(b.receive(&mut buf, true, false).unwrap().count, 1);
        assert_eq!(buf[0], b'z');
        assert_eq!(
            b.receive_out_of_band(&mut buf, false).err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(b.receive(&mut buf, true, false).err(), Some(Errno::EAGAIN));
    }
    #[test]
    fn socket_backpressure_partial_write_and_out_edge() {
        let [a, b] = pair();
        let bytes = vec![7; SEND_WINDOW + 1];
        assert_eq!(a.write(&bytes), Ok(SEND_WINDOW));
        assert_eq!(a.write(&[1]), Err(Errno::EAGAIN));
        let full = a.readiness().unwrap();
        assert_eq!(full.0 & OUT, 0);
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        let ready = a.readiness().unwrap();
        assert_ne!(ready.0 & OUT, 0);
        assert_eq!(ready.2, full.2 + 1);
        assert_eq!(a.write(&[1]), Ok(1));
    }
    fn seqpacket() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(SOCK_SEQPACKET, Arc::default()).unwrap()
    }
    #[test]
    fn seqpacket_keeps_message_boundaries_and_truncates() {
        let [a, b] = seqpacket();
        assert_eq!(a.write(b"first"), Ok(5));
        assert_eq!(a.write(b""), Ok(0));
        assert_eq!(a.write(b"second"), Ok(6));
        let mut bytes = [0; 3];
        // A short buffer gets the start of one message; the rest is gone.
        assert_eq!(b.read(&mut bytes), Ok(3));
        assert_eq!(&bytes, b"fir");
        // An empty read leaves the next message, an empty one, in place.
        assert_eq!(b.read(&mut []), Ok(0));
        assert_ne!(b.readiness().unwrap().0 & IN, 0);
        assert_eq!(b.read(&mut [0; 8]), Ok(0));
        let mut bytes = [0; 16];
        assert_eq!(b.read(&mut bytes), Ok(6));
        assert_eq!(&bytes[..6], b"second");
        assert_eq!(b.read(&mut bytes), Err(Errno::EAGAIN));
        assert_eq!(b.readiness().unwrap().0 & IN, 0);
        drop(a);
        assert_eq!(b.read(&mut bytes), Ok(0));
    }
    #[test]
    fn seqpacket_writes_whole_messages_or_none() {
        let [a, b] = seqpacket();
        assert_eq!(a.write(&vec![0; MAX_MESSAGE + 1]), Err(Errno(90)));
        assert_eq!(a.write(&vec![1; MAX_MESSAGE]), Ok(MAX_MESSAGE));
        assert_eq!(a.write(&[2; 33]), Err(Errno::EAGAIN));
        assert_eq!(a.write(&[2; 32]), Ok(32));
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        assert_eq!(a.write(&[3; 3]), Ok(3));
        let mut bytes = [0; 40];
        assert_eq!(b.read(&mut bytes), Ok(32));
        assert_eq!(b.read(&mut bytes), Ok(3));
        assert_eq!(&bytes[..3], &[3; 3]);
        assert!(SocketPairEnd::pair(3, Arc::default()).is_err_and(|e| e == Errno(94)));
    }
    #[test]
    fn events_socket_empty() {
        assert_eq!(pair()[0].read(&mut [0]), Err(Errno::EAGAIN));
    }
    #[test]
    fn events_socket_transfer() {
        let [a, b] = pair();
        a.write(b"hi").unwrap();
        let mut bytes = [0; 2];
        assert_eq!(b.read(&mut bytes), Ok(2));
        assert_eq!(&bytes, b"hi");
    }
    #[test]
    fn events_socket_bidirectional() {
        let [a, b] = pair();
        a.write(b"a").unwrap();
        b.write(b"b").unwrap();
        let mut byte = [0];
        a.read(&mut byte).unwrap();
        assert_eq!(byte, [b'b']);
        b.read(&mut byte).unwrap();
        assert_eq!(byte, [b'a']);
    }
    #[test]
    fn events_socket_partial() {
        let [a, b] = pair();
        a.write(b"abc").unwrap();
        assert_eq!(b.read(&mut [0; 2]), Ok(2));
        assert_eq!(b.read(&mut [0; 2]), Ok(1));
    }
    #[test]
    fn socket_peer_lifetime() {
        let [a, b] = pair();
        let copy = Arc::clone(&a);
        drop(a);
        assert_eq!(b.read(&mut [0]), Err(Errno::EAGAIN));
        drop(copy);
        assert_eq!(b.read(&mut [0]), Ok(0));
        assert_eq!(b.write(b"x"), Err(Errno(32)));
    }
    #[test]
    fn events_socket_shutdown() {
        let [a, b] = pair();
        a.shutdown(1).unwrap();
        assert_eq!(b.read(&mut [0]), Ok(0));
        assert_eq!(a.write(b"x"), Err(Errno(32)));
        assert_eq!(a.shutdown(3), Err(Errno::EINVAL));
    }
    #[test]
    fn socket_edges() {
        let [a, b] = pair();
        a.write(b"abc").unwrap();
        let e = b.readiness().unwrap().1;
        b.read(&mut [0]).unwrap();
        assert_eq!(b.readiness().unwrap().1, e);
        b.read(&mut [0; 2]).unwrap();
        a.write(b"d").unwrap();
        assert_eq!(b.readiness().unwrap().1, e + 1);
    }
    #[test]
    fn events_socket_flags() {
        let [a, _b] = SocketPairEnd::pair(1 | NONBLOCK | CLOEXEC, Arc::default()).unwrap();
        assert_eq!(a.flags(), 2 | NONBLOCK);
        a.set_flags(0).unwrap();
        assert_eq!(a.flags(), 2);
        assert!(SocketPairEnd::pair(1 | 0x4000, Arc::default()).is_err());
    }
    fn datagram() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(SOCK_DGRAM | NONBLOCK, Arc::default()).unwrap()
    }
    #[test]
    fn datagram_keeps_messages_and_has_no_end_of_file() {
        let [a, b] = datagram();
        assert_eq!(a.write(b"abc"), Ok(3));
        assert_eq!(a.write(b""), Ok(0));
        assert_eq!(a.write(&vec![0; MAX_MESSAGE + 1]), Err(Errno(90)));
        let mut bytes = [0; 8];
        assert_eq!(b.read(&mut bytes[..2]), Ok(2));
        assert_eq!(b.read(&mut bytes), Ok(0));
        // Shutting down writes is this side's own; the peer sees no EOF.
        a.shutdown(1).unwrap();
        assert_eq!(a.write(b"x"), Err(Errno(32)));
        assert_eq!(b.read(&mut bytes), Err(Errno::EAGAIN));
        assert_eq!(b.readiness().unwrap().0, OUT);
        assert_eq!(b.write(b"y"), Ok(1));
        assert_eq!(a.read(&mut bytes), Ok(1));
        // Its own SHUT_RD ends only a blocking read.
        b.shutdown(0).unwrap();
        assert_eq!(b.readiness().unwrap().0, OUT | IN | 0x2000);
        assert_eq!(b.read(&mut bytes), Err(Errno::EAGAIN));
        b.set_flags(0).unwrap();
        assert_eq!(b.read(&mut bytes), Ok(0));
        assert_eq!(a.write(b"z"), Err(Errno(32)));
        b.shutdown(1).unwrap();
        assert_eq!(b.readiness().unwrap().0, OUT | IN | 0x2000 | 0x10);
    }
    #[test]
    fn datagram_peer_close_refuses_then_disconnects() {
        let [a, b] = datagram();
        assert_eq!(b.write(b"zz"), Ok(2));
        assert_eq!(a.write(&vec![0; SEND_WINDOW - 32]), Ok(SEND_WINDOW - 32));
        drop(b);
        let mut bytes = [0; 8];
        assert_eq!(a.read(&mut bytes), Ok(2));
        assert_eq!(a.read(&mut bytes), Err(Errno::EAGAIN));
        assert_eq!(a.readiness().unwrap().0, OUT);
        // The full queue went with the peer, so the send reaches the peer check.
        assert_eq!(a.write(&[1; 64]), Err(Errno(111)));
        assert_eq!(a.write(b"q"), Err(Errno(107)));
        assert!(!a.raises_sigpipe());
        assert!(SocketPairEnd::pair(SOCK_STREAM, Arc::default()).unwrap()[0].raises_sigpipe());
    }
}
