//! io_uring's single-shot socket requests, as Linux's `io_uring/net.c`
//! has them: `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`,
//! `_SEND` and `_RECV`.
//!
//! The preparation checks are Linux 7.0's, which the differential tests
//! run on. A request is issued as Linux issues it inline, nonblocking
//! (`IO_URING_F_NONBLOCK`): one that would wait waits for its socket
//! ([`super::arm`]) and is issued again once the socket is ready, unless
//! it asked not to (`REQ_F_NOWAIT`), when it completes with `EAGAIN`.

use std::sync::Arc;

use paludarium_host::FileHandle;
use paludarium_types::Errno;

use super::{
    Chosen, POLL_IN_EVENTS, POLL_OUT_EVENTS, POLL_UNMASK, Ring, Waits, Work, file_of, give_back,
    int_at, select, u16_at, u32_at, u64_at,
};
use crate::files::Descriptor;
use crate::syscalls::Context;

pub(super) const OP_ACCEPT: u8 = 13;
pub(super) const OP_CONNECT: u8 = 16;
pub(super) const OP_SEND: u8 = 26;
pub(super) const OP_RECV: u8 = 27;
pub(super) const OP_SHUTDOWN: u8 = 34;
pub(super) const OP_SOCKET: u8 = 45;

/// `IORING_RECVSEND_*`, `IORING_RECV_MULTISHOT` and `IORING_SEND_*`, a send
/// or receive's flags in its `ioprio`.
const RECVSEND_POLL_FIRST: u16 = 1 << 0;
const RECV_MULTISHOT: u16 = 1 << 1;
const RECVSEND_BUNDLE: u16 = 1 << 4;
const SEND_VECTORIZED: u16 = 1 << 5;
/// Linux 7.0's `SENDMSG_FLAGS` and `RECVMSG_FLAGS`. Linux master adds
/// `IORING_RECVSEND_FIXED_BUF` to both, which here stays `EINVAL` as on
/// the kernel the differential tests run on.
const SENDMSG_FLAGS: u16 = RECVSEND_POLL_FIRST | RECVSEND_BUNDLE | SEND_VECTORIZED;
const RECVMSG_FLAGS: u16 = RECVSEND_POLL_FIRST | RECV_MULTISHOT | RECVSEND_BUNDLE;
/// `IORING_ACCEPT_*`, an accept's flags in its `ioprio`.
const ACCEPT_MULTISHOT: u16 = 1 << 0;
const ACCEPT_DONTWAIT: u16 = 1 << 1;
const ACCEPT_POLL_FIRST: u16 = 1 << 2;
const ACCEPT_FLAGS: u16 = ACCEPT_MULTISHOT | ACCEPT_DONTWAIT | ACCEPT_POLL_FIRST;
/// `IORING_CQE_F_SOCK_NONEMPTY`: more waits to be read or accepted.
const CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
/// `IORING_FILE_INDEX_ALLOC`: a free registered slot.
const FILE_INDEX_ALLOC: u32 = u32::MAX;

const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;
const MSG_ERRQUEUE: u32 = 0x2000;
const MSG_NOSIGNAL: u32 = 0x4000;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2_000_000;
/// `O_NONBLOCK` of a file's flags.
const O_NONBLOCK: u32 = 0o4000;
const POLLIN: u32 = 0x1;
const POLLERR: u32 = 0x8;
const EBADFD: Errno = Errno(77);
const ECONNABORTED: Errno = Errno(103);
const EISCONN: Errno = Errno(106);
const EINPROGRESS: Errno = Errno(115);

/// A socket request, as prepared, and what it found as it went on.
pub(super) struct Net {
    /// The socket's descriptor, or registered slot with `fixed`.
    fd: i32,
    fixed: bool,
    op: Op,
    /// It waited for its socket once (`REQ_F_POLLED`).
    pub(super) polled: bool,
    /// The file it found before it waited, which it goes on with
    /// (`req->file`).
    pub(super) found: Option<crate::files::Descriptor>,
}

enum Op {
    /// `how`, as `shutdown` takes it.
    Shutdown { how: u32 },
    Socket {
        domain: i32,
        kind: u32,
        protocol: u32,
        slot: u32,
    },
    Accept {
        addr: u64,
        addrlen: u64,
        flags: u32,
        iou: u16,
        slot: u32,
    },
    /// The address its preparation read, and how far it got: in progress
    /// once it gave `EINPROGRESS`, and whether it saw `ECONNABORTED`.
    Connect {
        addr: u64,
        len: u64,
        raw: Vec<u8>,
        in_progress: bool,
        seen_aborted: bool,
    },
    /// A send or a receive (`struct io_sr_msg`): the buffer as it is left
    /// to go, the flags, the address a send goes to, the group a receive
    /// selects from, and the bytes done before it waited (`done_io`).
    Transfer {
        send: bool,
        buf: u64,
        len: u32,
        msg_flags: u32,
        flags: u16,
        to: Option<(u64, u16)>,
        group: Option<u16>,
        done: u64,
    },
}

/// Prepares a socket request from its entry (`io_shutdown_prep`,
/// `io_socket_prep`, `io_accept_prep`, `io_connect_prep` and
/// `io_sendmsg_prep` or `io_recvmsg_prep` with `io_send_setup`), but for
/// what it reads of the caller's memory ([`prepare_memory`]). The
/// operations of multishot requests, bundles and vectored sends, and a
/// send's selected buffer, are not there yet (`EINVAL`).
pub(super) fn prepare(opcode: u8, sqe_flags: u8, sqe: &[u8]) -> Result<Work, Errno> {
    let fixed = sqe_flags & super::IOSQE_FIXED_FILE != 0;
    let select = sqe_flags & super::IOSQE_BUFFER_SELECT != 0;
    let (off, addr, len, rw_flags) = (
        u64_at(sqe, 8),
        u64_at(sqe, 16),
        u32_at(sqe, 24),
        u32_at(sqe, 28),
    );
    let (ioprio, buf_index, file_index) = (u16_at(sqe, 2), u16_at(sqe, 40), u32_at(sqe, 44));
    let op = match opcode {
        OP_SHUTDOWN => {
            if off != 0 || addr != 0 || rw_flags != 0 || buf_index != 0 || file_index != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Shutdown { how: len }
        }
        OP_SOCKET => {
            if addr != 0 || rw_flags != 0 || buf_index != 0 {
                return Err(Errno::EINVAL);
            }
            let kind = off as u32;
            let flags = kind & !0xf;
            if file_index != 0 && flags & SOCK_CLOEXEC != 0 {
                return Err(Errno::EINVAL);
            }
            if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Socket {
                domain: int_at(sqe, 4),
                kind,
                protocol: len,
                slot: file_index,
            }
        }
        OP_ACCEPT => {
            if len != 0 || buf_index != 0 {
                return Err(Errno::EINVAL);
            }
            if ioprio & !ACCEPT_FLAGS != 0 {
                return Err(Errno::EINVAL);
            }
            if file_index != 0
                && (rw_flags & SOCK_CLOEXEC != 0
                    || ioprio & ACCEPT_MULTISHOT != 0 && file_index != FILE_INDEX_ALLOC)
            {
                return Err(Errno::EINVAL);
            }
            if rw_flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
                return Err(Errno::EINVAL);
            }
            // Multishot accepts are not there yet.
            if ioprio & ACCEPT_MULTISHOT != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Accept {
                addr,
                addrlen: off,
                flags: rw_flags,
                iou: ioprio,
                slot: file_index,
            }
        }
        OP_CONNECT => {
            if len != 0 || buf_index != 0 || rw_flags != 0 || file_index != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Connect {
                addr,
                len: off,
                raw: Vec::new(),
                in_progress: false,
                seen_aborted: false,
            }
        }
        OP_SEND | OP_RECV => {
            let send = opcode == OP_SEND;
            // `io_recvmsg_prep` takes no address.
            if !send && off != 0 {
                return Err(Errno::EINVAL);
            }
            if (len as i32) < 0 {
                return Err(Errno::EINVAL);
            }
            if ioprio & !if send { SENDMSG_FLAGS } else { RECVMSG_FLAGS } != 0 {
                return Err(Errno::EINVAL);
            }
            let msg_flags = if send {
                rw_flags | MSG_NOSIGNAL
            } else {
                rw_flags
            };
            if !send && ioprio & RECV_MULTISHOT != 0 {
                if !select || msg_flags & MSG_WAITALL != 0 {
                    return Err(Errno::EINVAL);
                }
                // Multishot receives are not there yet.
                return Err(Errno::EINVAL);
            }
            // Only a multishot receive takes `optlen`.
            if !send && file_index != 0 {
                return Err(Errno::EINVAL);
            }
            // Bundles, vectored sends, a send's selected buffer and a
            // selected buffer that a receive fills whole are not there yet.
            if ioprio & (RECVSEND_BUNDLE | SEND_VECTORIZED) != 0
                || select && (send || msg_flags & MSG_WAITALL != 0)
            {
                return Err(Errno::EINVAL);
            }
            // `__pad3[0]`.
            if send && u16_at(sqe, 46) != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Transfer {
                send,
                buf: addr,
                len,
                msg_flags,
                flags: ioprio,
                to: (send && off != 0).then(|| (off, u16_at(sqe, 44))),
                group: select.then_some(buf_index),
                done: 0,
            }
        }
        _ => return Err(super::EOPNOTSUPP),
    };
    Ok(Work::Net(Box::new(Net {
        fd: int_at(sqe, 4),
        fixed,
        op,
        polled: false,
        found: None,
    })))
}

/// What a socket request's preparation reads of the caller's memory: a
/// connect's or a send's address (`move_addr_to_kernel`: longer than 128
/// bytes or negative is `EINVAL`, one that cannot be read `EFAULT`), then
/// a buffer that must be in the user half (`import_ubuf`, `EFAULT`), cut
/// to `MAX_RW_COUNT`.
pub(super) fn prepare_memory(c: &Context<'_>, net: &mut Net) -> Result<(), Errno> {
    match &mut net.op {
        Op::Connect { addr, len, raw, .. } => {
            *raw = crate::inet::read_raw(c, *addr, *len)?;
        }
        &mut Op::Transfer {
            ref mut len,
            buf,
            to,
            group,
            ..
        } => {
            if let Some((at, to_len)) = to {
                crate::inet::read_raw(c, at, u64::from(to_len))?;
            }
            *len = (*len).min(crate::files::MAX_RW_COUNT as u32);
            if group.is_none() {
                crate::sockets::access_ok_u64(buf, u64::from(*len))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// What issuing a request came to: a result with its completion's flags
/// and whether it failed (`req_set_fail`), or a wait for the socket's
/// events `mask` (`IOU_RETRY`).
enum Issued {
    Done(i32, u32, bool),
    Again(u32),
}

/// Issues a socket request (`io_issue_sqe`): its result, its completion's
/// flags, whether it failed, or what it waits for.
pub(super) fn run(
    c: &mut Context<'_>,
    ring: &Ring,
    net: &mut Net,
) -> (i32, u32, bool, Option<Waits>) {
    if let Op::Socket {
        domain,
        kind,
        protocol,
        slot,
    } = net.op
    {
        let res = socket(c, ring, domain, kind, protocol, slot);
        return (res, 0, res < 0, None);
    }
    let opened = match net.found.clone() {
        Some(opened) => opened,
        None => match file_of(c, ring, net.fd, net.fixed) {
            Ok(opened) => opened,
            Err(e) => return (-e.0, 0, true, None),
        },
    };
    let file = Arc::clone(&opened.file);
    let nowait = match &net.op {
        Op::Accept { iou, .. } => iou & ACCEPT_DONTWAIT != 0,
        Op::Transfer { msg_flags, .. } => msg_flags & MSG_DONTWAIT != 0,
        _ => false,
    };
    let issued = match &mut net.op {
        Op::Shutdown { how } => {
            let res = to_res(crate::sockets::route_file(
                c,
                48,
                [0, u64::from(*how), 0, 0, 0, 0],
                &file,
            ));
            Issued::Done(res, 0, false)
        }
        Op::Accept { .. } => accept(c, ring, net.polled, &net.op, &file),
        Op::Connect { .. } => connect(c, &mut net.op, &file),
        Op::Transfer { .. } => transfer(c, ring, net.polled, &mut net.op, &file),
        Op::Socket { .. } => unreachable!(),
    };
    match issued {
        Issued::Done(res, flags, failed) => (res, flags, failed || res < 0, None),
        // `io_queue_async`: one that asked not to wait fails.
        Issued::Again(_) if nowait => (failed(net, Errno::EAGAIN), 0, true, None),
        Issued::Again(mask) => (
            0,
            0,
            false,
            Some(Waits {
                file,
                mask: POLL_UNMASK | mask,
                kept: None,
                found: (opened, None),
            }),
        ),
    }
}

/// `io_sendrecv_fail`: what a request that fails with `e` gives: the bytes a
/// send or a receive moved before it waited, if it moved any.
pub(super) fn failed(net: &Net, e: Errno) -> i32 {
    match net.op {
        Op::Transfer { done, .. } if done != 0 => done as i32,
        _ => -e.0,
    }
}

fn to_res(result: Result<u64, Errno>) -> i32 {
    result.map_or_else(|e| -e.0, |v| v as i32)
}

/// `io_socket`: a descriptor first (`EMFILE`), then the socket, which goes
/// at that descriptor or in registered slot `slot` (one past its index,
/// or a free one with `IORING_FILE_INDEX_ALLOC`).
///
/// The socket is made as the `socket` call makes it, at the lowest free
/// descriptor, from which one for a registered slot goes there: with no
/// descriptor free, that is `EMFILE` too, where Linux needs none.
fn socket(
    c: &mut Context<'_>,
    ring: &Ring,
    domain: i32,
    kind: u32,
    protocol: u32,
    slot: u32,
) -> i32 {
    let a = [
        domain as i64 as u64,
        u64::from(kind),
        u64::from(protocol),
        0,
        0,
        0,
    ];
    if slot == 0 {
        // The lowest free descriptor, which the socket then takes.
        match c.files.reserve(c.group.nofile()) {
            Ok(fd) => c.files.unreserve(fd),
            Err(e) => return -e.0,
        }
    }
    let socket = match crate::sockets::make(c, a) {
        Ok(socket) => socket,
        Err(e) => return -e.0,
    };
    if slot != 0 {
        return install_fixed(ring, Descriptor::unnamed(socket, false), slot);
    }
    to_res(
        c.files
            .install(socket, kind & SOCK_CLOEXEC != 0, c.group.nofile())
            .map(u64::from),
    )
}

/// `io_fixed_fd_install`: `opened` goes in registered slot `slot` (one past
/// its index), emptying it, or in a free one with
/// `IORING_FILE_INDEX_ALLOC`, whose index it gives: with no free slot, or
/// no registered files, that is `ENFILE`; otherwise no registered files
/// are `ENXIO` and a slot past them `EINVAL`. A ring is `EBADF`. The file
/// is let go of on an error.
pub(super) fn install_fixed(ring: &Ring, opened: Descriptor, slot: u32) -> i32 {
    let mut registered = ring
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let alloc = slot == FILE_INDEX_ALLOC;
    let index = if alloc {
        match registered.as_mut().map(super::Files::free) {
            Some(Ok(index)) => index,
            Some(Err(e)) => return -e.0,
            None => return -super::ENFILE.0,
        }
    } else {
        slot - 1
    };
    if opened.file.as_any().is_some_and(|v| v.is::<Ring>()) {
        return -Errno::EBADF.0;
    }
    let Some(files) = registered.as_mut() else {
        return -super::ENXIO.0;
    };
    if index >= files.count {
        return -Errno::EINVAL.0;
    }
    let gone = files.clear(index);
    files.set(index, opened, 0);
    drop(registered);
    ring.put_nodes(gone);
    if alloc { index as i32 } else { 0 }
}

/// `io_accept`: with `IORING_ACCEPT_POLL_FIRST` it waits for a connection
/// first; then a descriptor (`EMFILE`), then the connection
/// ([`crate::sockets::accept_file`]), which goes at that descriptor or in
/// a registered slot ([`install_fixed`]). None waiting, it waits, unless
/// `IORING_ACCEPT_DONTWAIT` (`EAGAIN`). TCP tells whether more wait
/// (`IORING_CQE_F_SOCK_NONEMPTY`), even when the slot fails.
fn accept(
    c: &mut Context<'_>,
    ring: &Ring,
    polled: bool,
    op: &Op,
    file: &Arc<dyn FileHandle>,
) -> Issued {
    let &Op::Accept {
        addr,
        addrlen,
        flags,
        iou,
        slot,
    } = op
    else {
        unreachable!()
    };
    if !polled && iou & ACCEPT_POLL_FIRST != 0 {
        return Issued::Again(POLL_IN_EVENTS);
    }
    let fd = if slot == 0 {
        match c.files.reserve(c.group.nofile()) {
            Ok(fd) => Some(fd),
            Err(e) => return Issued::Done(-e.0, 0, true),
        }
    } else {
        None
    };
    match crate::sockets::accept_file(c, file, addr, addrlen, u64::from(flags), true) {
        Err(e) => {
            if let Some(fd) = fd {
                c.files.unreserve(fd);
            }
            if e == Errno::EAGAIN && iou & ACCEPT_DONTWAIT == 0 {
                return Issued::Again(POLL_IN_EVENTS);
            }
            Issued::Done(-e.0, 0, true)
        }
        Ok((child, more)) => {
            let cflags = if more { CQE_F_SOCK_NONEMPTY } else { 0 };
            let res = match fd {
                Some(fd) => {
                    let cloexec = flags & SOCK_CLOEXEC != 0;
                    c.files
                        .fill(fd, crate::files::Descriptor::unnamed(child, cloexec));
                    fd as i32
                }
                None => install_fixed(ring, Descriptor::unnamed(child, false), slot),
            };
            Issued::Done(res, cflags, res < 0)
        }
    }
}

/// `io_connect`: once in progress, a socket with an error completes with
/// it (`sock_error`); otherwise it connects without waiting, and waits for
/// the socket to be writable while the connection is in progress
/// (`EINPROGRESS`), on `EAGAIN`, or on its first `ECONNABORTED`. As Linux
/// master, `EAGAIN` from a socket that is nonblocking itself (an AF_UNIX
/// listener's full backlog) completes. Once in progress, `EISCONN` (or
/// `EBADFD`) completes with the socket's error.
fn connect(c: &mut Context<'_>, op: &mut Op, file: &Arc<dyn FileHandle>) -> Issued {
    let Op::Connect {
        addr,
        len,
        raw,
        in_progress,
        seen_aborted,
    } = op
    else {
        unreachable!()
    };
    let sock_error = || {
        let res = crate::sockets::take_error(file);
        Issued::Done(res, 0, res < 0)
    };
    if *in_progress && crate::aio::polled(file).0 & POLLERR != 0 {
        return sock_error();
    }
    let result = crate::sockets::connect_file(c, file, raw, *addr, *len, true);
    match result {
        Err(EINPROGRESS) => {
            *in_progress = true;
            return Issued::Again(POLL_OUT_EVENTS);
        }
        Err(ECONNABORTED) => {
            if !*seen_aborted {
                *seen_aborted = true;
                return Issued::Again(POLL_OUT_EVENTS);
            }
        }
        Err(Errno::EAGAIN) if file.flags() & O_NONBLOCK == 0 => {
            return Issued::Again(POLL_OUT_EVENTS);
        }
        Err(EISCONN | EBADFD) if *in_progress => {
            return sock_error();
        }
        _ => {}
    }
    let res = to_res(result);
    Issued::Done(res, 0, res < 0)
}

/// `io_send` and `io_recv`: with `IORING_RECVSEND_POLL_FIRST` it waits for
/// the socket first; then it sends or receives without waiting
/// (`MSG_DONTWAIT`) at most once (`sendto`, `recvfrom`), and waits for the
/// socket on `EAGAIN`. With `MSG_WAITALL`, a stream or sequenced-packet
/// socket that moved fewer bytes than were left waits to move the rest
/// (`io_net_retry`, `done_io`); any other short transfer fails (but not a
/// whole datagram that was cut, which Linux's fails too: `MSG_TRUNC` of
/// the receive is not seen here). A receive
/// may select a provided buffer first (`ENOBUFS`), which goes back to its
/// group when the receive waits or moved nothing (`io_kbuf_recycle`, as
/// Linux master has it), and tells whether more waits to be read
/// ([`crate::sockets::inq_hint`]).
///
/// A send checks for a socket first (`ENOTSOCK`), and so does a receive,
/// as Linux master has it (Linux 7.0 waits first with
/// `IORING_RECVSEND_POLL_FIRST`).
fn transfer(
    c: &mut Context<'_>,
    ring: &Ring,
    polled: bool,
    op: &mut Op,
    file: &Arc<dyn FileHandle>,
) -> Issued {
    let Op::Transfer {
        send,
        buf,
        len,
        msg_flags,
        flags,
        to,
        group,
        done,
    } = op
    else {
        unreachable!()
    };
    let send = *send;
    let mask = if send {
        POLL_OUT_EVENTS
    } else if *msg_flags & MSG_ERRQUEUE != 0 {
        // `REQ_F_CLEAR_POLLIN`.
        POLL_IN_EVENTS & !POLLIN
    } else {
        POLL_IN_EVENTS
    };
    if !crate::sockets::is_socket(file) {
        return Issued::Done(-Errno(88).0, 0, true);
    }
    if !polled && *flags & RECVSEND_POLL_FIRST != 0 {
        return Issued::Again(mask);
    }
    let call_flags = *msg_flags | MSG_DONTWAIT;
    let chosen = match *group {
        Some(bgid) => match select(c, ring, bgid, *len, true) {
            Ok(chosen) => Some(chosen),
            Err(e) => return Issued::Done(-e.0, 0, true),
        },
        None => None,
    };
    let (at, count) = match &chosen {
        Some(chosen) => (
            chosen.addr,
            chosen.len.min(crate::files::MAX_RW_COUNT as u32),
        ),
        None => (*buf, *len),
    };
    let wanted = if *msg_flags & MSG_WAITALL != 0 {
        u64::from(count)
    } else {
        0
    };
    let (to_at, to_len) = to.map_or((0, 0), |(at, len)| (at, u64::from(len)));
    let a = [
        0,
        at,
        u64::from(count),
        u64::from(call_flags),
        to_at,
        to_len,
    ];
    let result = crate::sockets::route_file(c, if send { 44 } else { 45 }, a, file);
    let inq = if send || result.is_err() {
        None
    } else {
        crate::sockets::inq_hint(file)
    };
    let mut failed = false;
    if result.as_ref().map_or(true, |&n| n < wanted) {
        match result {
            Err(Errno::EAGAIN) => {
                if let Some(chosen) = &chosen {
                    recycle(ring, chosen);
                }
                return Issued::Again(mask);
            }
            Ok(n) if n > 0 && crate::sockets::is_stream(file) => {
                // A selected buffer is never filled whole: the preparation
                // refused that.
                *buf = buf.wrapping_add(n);
                *len -= n as u32;
                *done += n;
                return Issued::Again(mask);
            }
            _ => failed = true,
        }
    }
    let res = match result {
        Ok(n) => (n + *done) as i32,
        Err(_) if *done != 0 => *done as i32,
        Err(e) => -e.0,
    };
    let mut cflags = 0;
    if let Some(chosen) = &chosen {
        if res <= 0 {
            recycle(ring, chosen);
        } else {
            cflags |= give_back(c, ring, chosen, &Ok(res as u64));
        }
    }
    if inq.is_some_and(|inq| inq > 0) {
        cflags |= CQE_F_SOCK_NONEMPTY;
    }
    Issued::Done(res, cflags, failed)
}

/// `io_kbuf_recycle`: a provided buffer goes back to the front of its
/// group, whole; a ring's, which a socket's receive uses only once it is
/// done, stays at the ring's head.
fn recycle(ring: &Ring, chosen: &Chosen) {
    if chosen.ring {
        return;
    }
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(super::BufferList::Provided(list)) = lists.get_mut(&chosen.bgid) {
        list.push_front(super::Provided {
            addr: chosen.addr,
            len: chosen.size,
            bid: chosen.bid,
        });
    }
}
