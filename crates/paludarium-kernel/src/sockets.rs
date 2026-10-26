//! AF_UNIX stream endpoints. Buffers and peer lifetime belong to the Kernel.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use paludarium_types::GuestAddr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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
        reader.shutdown(1)?;
        writer.shutdown(0)?;
        let inode = reader.inode;
        Ok([
            Arc::new(Self {
                endpoint: reader,
                reader: true,
                inode,
            }),
            Arc::new(Self {
                endpoint: writer,
                reader: false,
                inode,
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
        u32::from(!self.reader) | (self.endpoint.flags() & NONBLOCK)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.endpoint.set_flags(flags)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            mode: 0o010600,
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
        44 => send_to(c, a),
        45 => receive_from(c, a),
        46 => send_message(c, a),
        47 => receive_message(c, a),
        _ => Err(Errno::ENOSYS),
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: u32 = 1;
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
fn as_socket(file: &Arc<dyn FileHandle>) -> Result<&SocketPairEnd, Errno> {
    file.as_any()
        .and_then(|v| v.downcast_ref::<SocketPairEnd>())
        .ok_or(Errno(88))
}
/// The descriptors the control messages pass, as Linux's `__scm_send` reads
/// them: each header must lie in the buffer (EINVAL), levels other than
/// `SOL_SOCKET` are skipped, and `SOL_SOCKET` takes only `SCM_RIGHTS`
/// (EINVAL), with at most 253 descriptors in all (EINVAL), each open (EBADF).
fn passed_descriptors(c: &Context<'_>, control: &[u8]) -> Result<Passed, Errno> {
    let mut passed = Passed::new();
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
        if field(at + 8) == SOL_SOCKET {
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
    Ok(passed)
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
/// `TASK_SIZE_MAX` on x86-64: the end of the user half, less a guard page.
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
    if a[3] & !(MSG_NOSIGNAL | MSG_DONTWAIT) != 0 {
        return Err(Errno(95));
    }
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
    let lookup = !address.is_empty() && check_address(socket, &address, len)?;
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
    crate::files::write_with(
        c,
        &file,
        &bytes,
        a[3] & MSG_NOSIGNAL != 0,
        a[3] & MSG_DONTWAIT != 0,
        |b| socket.send(b, &mut Passed::new()),
    )
}
/// `recvfrom(fd, buf, len, flags, addr, addrlen)` on a socket pair: recvmsg
/// with one buffer and no control buffer, so the descriptors a message passes
/// close. With `addr`, the peer's address length, 0, goes to `addrlen` as
/// `move_addr_to_user` writes it: EFAULT when it cannot be read, and a
/// negative one is EINVAL, after the data is taken.
fn receive_from(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let len = user_buffer(a[1], a[2])?;
    let file = socket(c, a[0])?;
    if a[3] & !(MSG_DONTWAIT | MSG_CMSG_CLOEXEC) != 0 {
        return Err(Errno(95));
    }
    c.mem
        .check_write(GuestAddr(a[1]), len)
        .map_err(|_| Errno::EFAULT)?;
    let mut bytes = Vec::new();
    bytes.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(len, 0);
    let socket = as_socket(&file)?;
    let received = crate::files::wait_for_read(c, &file, a[3] & MSG_DONTWAIT != 0, || {
        socket.receive(&mut bytes, true)
    })?;
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
    Ok(received.count as u64)
}
/// `sendmsg(fd, msg, flags)` on a socket pair, with `SCM_RIGHTS`. Of the
/// flags only `MSG_NOSIGNAL` and `MSG_DONTWAIT` are taken (EOPNOTSUPP
/// otherwise).
fn send_message(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    if a[2] & !(MSG_NOSIGNAL | MSG_DONTWAIT) != 0 {
        return Err(Errno(95));
    }
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
    let mut passed = passed_descriptors(c, &control)?;
    let socket = as_socket(&file)?;
    let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
    // The address is checked, and the data then copied, in the protocol's
    // sendmsg after __scm_send.
    let lookup = header.name.is_some() && check_address(socket, &address, total)?;
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
    let result = crate::files::write_with(
        c,
        &file,
        &bytes,
        a[2] & MSG_NOSIGNAL != 0,
        a[2] & MSG_DONTWAIT != 0,
        |b| socket.send(b, &mut passed),
    );
    // What was not passed closes here, outside the socket's lock.
    drop(passed);
    result
}
/// `recvmsg(fd, msg, flags)` on a socket pair, with `SCM_RIGHTS`. Of the
/// flags only `MSG_DONTWAIT` and `MSG_CMSG_CLOEXEC` are taken (EOPNOTSUPP
/// otherwise).
fn receive_message(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = socket(c, a[0])?;
    if a[2] & !(MSG_DONTWAIT | MSG_CMSG_CLOEXEC) != 0 {
        return Err(Errno(95));
    }
    let header = message_header(c, a[1], true)?;
    let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(total, 0);
    let socket = as_socket(&file)?;
    let received = crate::files::wait_for_read(c, &file, a[2] & MSG_DONTWAIT != 0, || {
        socket.receive(&mut bytes, true)
    })?;
    crate::files::scatter(c, &header.iov, &bytes[..received.count])?;
    // ____sys_recvmsg starts msg_flags with MSG_CMSG_CLOEXEC.
    let mut flags = (a[2] & MSG_CMSG_CLOEXEC) as u32;
    if received.truncated {
        flags |= MSG_TRUNC;
    }
    let (used, cut) = deliver(c, &header, received.passed, a[2] & MSG_CMSG_CLOEXEC != 0);
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
    Ok(received.count as u64)
}
/// Installs the received descriptors and writes their `SCM_RIGHTS` message,
/// as Linux's `scm_detach_fds`: as many as the control buffer holds, each
/// the lowest free number, until one does not fit under `RLIMIT_NOFILE` or
/// its number cannot be written. The rest are closed. Returns the control
/// bytes used and whether any descriptor was lost (`MSG_CTRUNC`).
fn deliver(
    c: &mut Context<'_>,
    header: &MessageHeader,
    passed: Passed,
    cloexec: bool,
) -> (u64, bool) {
    let count = passed.len();
    if count == 0 {
        return (0, false);
    }
    if header.control == 0 {
        return (0, true);
    }
    let room = header.control_len.saturating_sub(CMSG_HEADER as u64) / 4;
    let most = usize::try_from(room).unwrap_or(usize::MAX).min(count);
    let mut installed = 0;
    for descriptor in passed.into_iter().take(most) {
        let Ok(n) = c.files.reserve(c.group.nofile()) else {
            break;
        };
        let at = header.control + (CMSG_HEADER + 4 * installed) as u64;
        if c.mem.write(GuestAddr(at), &n.to_le_bytes()).is_err() {
            c.files.unreserve(n);
            break;
        }
        c.files.fill(n, descriptor.received(cloexec));
        installed += 1;
    }
    // As scm_detach_fds: the descriptors go in first and the header after,
    // so a header that cannot be written leaves msg_controllen as it was.
    let mut used = 0;
    if installed != 0 {
        let len = CMSG_HEADER + 4 * installed;
        let mut cmsg = [0; CMSG_HEADER];
        cmsg[..8].copy_from_slice(&(len as u64).to_le_bytes());
        cmsg[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
        cmsg[12..].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        if c.mem.write(GuestAddr(header.control), &cmsg).is_ok() {
            used = (len.next_multiple_of(8) as u64).min(header.control_len);
        }
    }
    (used, installed < count)
}

/// Descriptors passed with `SCM_RIGHTS`: what one write or message carries.
pub(crate) type Passed = Vec<crate::files::Descriptor>;
/// One successful write, as Linux queues an `sk_buff`.
struct Write {
    len: usize,
    passed: Passed,
}
/// What one read took: the bytes copied, the descriptors that came with them,
/// and whether a message was longer than the buffer (`MSG_TRUNC`).
#[derive(Default)]
pub(crate) struct Received {
    pub(crate) count: usize,
    pub(crate) passed: Passed,
    pub(crate) truncated: bool,
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
}
struct Pair {
    sides: Mutex<[Side; 2]>,
    hub: Arc<ReadinessHub>,
    /// SOCK_STREAM, SOCK_DGRAM or SOCK_SEQPACKET. The last two keep message
    /// boundaries: each write is one message, and each read returns one
    /// whole message, truncated to the buffer, as on Linux.
    kind: u32,
    /// How many unread bytes each direction holds: the socket send buffer,
    /// or a pipe's capacity (`F_SETPIPE_SZ`).
    window: AtomicUsize,
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
}
impl SocketPairEnd {
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
            kind: kind & 0xf,
            window: AtomicUsize::new(SEND_WINDOW),
            sides: Mutex::new(std::array::from_fn(|_| Side {
                output_epoch: 1,
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
        self.pair.hub.changed();
        Ok(())
    }
}
impl SocketPairEnd {
    /// Reads into `buf`; `message` is the form of recvmsg and recvfrom
    /// (`sock_recvmsg`), which an empty buffer does not end at once as read's
    /// does (Linux's `sock_read_iter`).
    pub(crate) fn receive(&self, buf: &mut [u8], message: bool) -> Result<Received, Errno> {
        if buf.is_empty() && !message {
            return Ok(Received::default());
        }
        if self.pair.messages() {
            self.read_message(buf)
        } else {
            self.read_stream(buf)
        }
    }
    /// SOCK_SEQPACKET and SOCK_DGRAM read: the next whole message,
    /// truncated to `buf`, with its descriptors. An empty buffer reaches
    /// here only from recvmsg or recvfrom, and discards the message.
    fn read_message(&self, buf: &mut [u8]) -> Result<Received, Errno> {
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
        let Some(message) = own.writes.pop_front() else {
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
        sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        self.pair.hub.changed();
        Ok(Received {
            count,
            truncated: count < message.len,
            passed: message.passed,
        })
    }
}
impl SocketPairEnd {
    /// SOCK_STREAM read. As Linux's `unix_stream_read_generic`, it goes on
    /// across writes but ends with the first one that passed descriptors,
    /// which come with its first bytes read; an empty buffer still takes
    /// them.
    fn read_stream(&self, buf: &mut [u8]) -> Result<Received, Errno> {
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
        if own.bytes.is_empty() {
            return if eof {
                Ok(Received::default())
            } else {
                Err(Errno::EAGAIN)
            };
        }
        let mut received = Received::default();
        let mut consumed_write = false;
        while let Some(front) = own.writes.front_mut() {
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
        if full || consumed_write {
            sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        }
        self.pair.hub.changed();
        Ok(received)
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
        // An empty message is readable too.
        let readable = !own.bytes.is_empty() || self.pair.messages() && !own.writes.is_empty();
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
        self.receive(buf, false).map(|received| received.count)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.send(buf, &mut Passed::new())
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            mode: 0o140777,
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
        self.flags.store(2 | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}
impl SocketPairEnd {
    /// Writes `buf`, taking `passed` with the first bytes that go; what is
    /// left in it went nowhere (a stream write of no bytes passes nothing,
    /// as on Linux), and the caller closes it after the lock is released.
    pub(crate) fn send(&self, buf: &[u8], passed: &mut Passed) -> Result<usize, Errno> {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
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
            });
        }
        self.pair.hub.changed();
        Ok(count)
    }
}
#[cfg(test)]
mod events_tests {
    use super::*;
    fn pair() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(1, Arc::default()).unwrap()
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
