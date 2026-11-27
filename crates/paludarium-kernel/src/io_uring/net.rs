//! io_uring's socket requests, as Linux's `io_uring/net.c`
//! has them: `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`,
//! `_SEND`, `_RECV`, `_SENDMSG` and `_RECVMSG`.
//!
//! The preparation checks are Linux 7.0's, which the differential tests
//! run on. A request is issued as Linux issues it inline, nonblocking
//! (`IO_URING_F_NONBLOCK`): one that would wait waits for its socket
//! ([`super::arm`]) and is issued again once the socket is ready, unless
//! it asked not to (`REQ_F_NOWAIT`), when it completes with `EAGAIN`.

use std::sync::Arc;

use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};

use super::{
    Chosen, POLL_IN_EVENTS, POLL_OUT_EVENTS, POLL_UNMASK, Ring, Waits, Work, file_of, give_back,
    int_at, select, u16_at, u32_at, u64_at,
};
use crate::files::Descriptor;
use crate::sockets::MessageHeader;
use crate::syscalls::Context;

pub(super) const OP_SENDMSG: u8 = 9;
pub(super) const OP_RECVMSG: u8 = 10;
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

const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;
const MSG_ERRQUEUE: u32 = 0x2000;
const MSG_NOSIGNAL: u32 = 0x4000;
const MSG_CMSG_COMPAT: u32 = 0x8000_0000;
/// `struct io_uring_recvmsg_out`: the lengths of the name, the control and
/// the message, and its flags.
const RECVMSG_OUT: u64 = 16;
const EOVERFLOW: Errno = Errno(75);
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
    /// Whether it posts a completion and goes on (`REQ_F_APOLL_MULTISHOT`),
    /// and for a receive that may take no more than so many bytes in all
    /// (`IORING_RECV_MSHOT_LIM`), how many are left.
    multishot: bool,
    limit: Option<u32>,
    /// A multishot request that posted while its socket had nothing more,
    /// as far as it knew, which waits for its socket before it goes on
    /// (`IOU_RETRY`).
    wait: bool,
    /// A multishot receive of messages: the name's and the control's room
    /// its `msghdr` gives, which each buffer starts with after a
    /// `struct io_uring_recvmsg_out` (`io_recvmsg_mshot_prep`).
    layout: Option<(u32, u64)>,
    /// A multishot receive of messages that found the end, which posts its
    /// last completion (`io_recvmsg_multishot`'s `finished`).
    ended: bool,
}

impl Net {
    /// Whether it goes on after `res`, which it posts: an accept after any
    /// connection, a receive after any bytes but the last it may take.
    pub(super) fn goes_on(&mut self, res: i32) -> bool {
        if !self.multishot || self.ended {
            return false;
        }
        if matches!(self.op, Op::Accept { .. }) {
            return res >= 0;
        }
        if res > 0
            && let Some(limit) = &mut self.limit
        {
            *limit = limit.saturating_sub(res as u32);
        }
        res > 0 && self.limit != Some(0)
    }

    /// After a completion posted with `flags`, whether it goes on at once,
    /// as `io_accept` and `io_recv_finish` do while their socket has more
    /// or does not say; else it waits for its socket. Linux requeues a
    /// receive after `MULTISHOT_MAX_RETRY` tries in a row, which gives
    /// other task work a turn; here it goes on.
    pub(super) fn posted(&mut self, flags: u32) {
        let Some(file) = self.found.as_ref().map(|found| Arc::clone(&found.file)) else {
            return;
        };
        let unknown = match self.op {
            // Only TCP tells whether more connections wait (`is_empty`).
            Op::Accept { .. } => crate::inet::of(&file).is_none(),
            _ => crate::sockets::inq_hint(&file).is_none(),
        };
        self.wait = flags & CQE_F_SOCK_NONEMPTY == 0 && !unknown;
    }
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
        /// The `msghdr` of an `IORING_OP_SENDMSG` or `_RECVMSG`, at `buf`.
        message: Option<Box<MessageHeader>>,
    },
}

/// Prepares a socket request from its entry (`io_shutdown_prep`,
/// `io_socket_prep`, `io_accept_prep`, `io_connect_prep` and
/// `io_sendmsg_prep` or `io_recvmsg_prep` with `io_send_setup`), but for
/// what it reads of the caller's memory ([`prepare_memory`]). Bundles,
/// vectored sends and a send's selected buffer are not there yet
/// (`EINVAL`).
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
    let (mut multishot, mut limit) = (false, None);
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
            multishot = ioprio & ACCEPT_MULTISHOT != 0;
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
        OP_SEND | OP_RECV | OP_SENDMSG | OP_RECVMSG => {
            let send = matches!(opcode, OP_SEND | OP_SENDMSG);
            let message = matches!(opcode, OP_SENDMSG | OP_RECVMSG);
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
                // A message's limit is its buffers'.
                if message && file_index != 0 {
                    return Err(Errno::EINVAL);
                }
                multishot = true;
                limit = (file_index != 0).then_some(file_index);
            } else if !send && file_index != 0 {
                // Only a multishot receive takes `optlen`.
                return Err(Errno::EINVAL);
            }
            // Bundles, vectored sends, a send's selected buffer and a
            // selected buffer that a receive fills whole are not there yet.
            // A message is no bundle, and its iovecs are vectored anyway.
            let vectored = ioprio & SEND_VECTORIZED != 0 && !message;
            if ioprio & RECVSEND_BUNDLE != 0
                || vectored
                || select && (send || msg_flags & MSG_WAITALL != 0)
            {
                return Err(Errno::EINVAL);
            }
            // `__pad3[0]`, and what a message has none of.
            if send && !message && u16_at(sqe, 46) != 0
                || send && message && (off != 0 || file_index != 0)
            {
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
                message: message.then(Box::default),
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
        multishot,
        limit,
        wait: false,
        layout: None,
        ended: false,
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
            send,
            ref mut message,
            ..
        } => {
            if let Some(message) = message {
                **message = read_message(c, buf, send, group.is_some())?;
                *len = message.iov.first().map_or(0, |&(_, len)| len as u32);
                if net.multishot {
                    net.layout = Some(layout(c, buf)?);
                }
                return Ok(());
            }
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

/// What a message's preparation reads (`io_msg_copy_hdr`): the `msghdr`
/// (`EFAULT`, `EINVAL`, `EMSGSIZE`), a send's address
/// (`move_addr_to_kernel`, `EFAULT`), and the iovecs (`__import_iovec`); of
/// a receive that selects a buffer, which has one at most (`EINVAL`), the
/// length alone.
fn read_message(
    c: &Context<'_>,
    at: u64,
    send: bool,
    selects: bool,
) -> Result<MessageHeader, Errno> {
    let mut header = crate::sockets::message_header_with(c, at, false, !selects)?;
    if send && let Some((name, len)) = header.name {
        let mut address = vec![0; len];
        c.mem
            .read(GuestAddr(name), &mut address)
            .map_err(|_| Errno::EFAULT)?;
    }
    if selects {
        let [vector, count] = crate::syscalls::read_words::<2>(c.mem, at + 16)?;
        if count > 1 {
            return Err(Errno::EINVAL);
        }
        let len = match count {
            0 => 0,
            _ => crate::syscalls::read_words::<2>(c.mem, vector)?[1],
        };
        header.iov = vec![(0, len as u32 as usize)];
    }
    Ok(header)
}

/// The name's and the control's room in each buffer of a multishot receive
/// of the `msghdr` at `at`, as `io_recvmsg_mshot_prep` takes them: a
/// negative `msg_namelen`, or a header longer than an `int`, is
/// `EOVERFLOW`.
fn layout(c: &Context<'_>, at: u64) -> Result<(u32, u64), Errno> {
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(at + 8), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let name = i32::from_le_bytes(raw);
    let [control] = crate::syscalls::read_words::<1>(c.mem, at + 40)?;
    let name = u32::try_from(name).map_err(|_| EOVERFLOW)?;
    let whole = (RECVMSG_OUT + u64::from(name)).checked_add(control);
    if whole.is_none_or(|whole| whole > i32::MAX as u64) {
        return Err(EOVERFLOW);
    }
    Ok((name, control))
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
    if net.multishot {
        net.found = Some(opened.clone());
    }
    let file = Arc::clone(&opened.file);
    let nowait = match &net.op {
        Op::Accept { iou, .. } => iou & ACCEPT_DONTWAIT != 0,
        Op::Transfer { msg_flags, .. } => msg_flags & MSG_DONTWAIT != 0,
        _ => false,
    };
    if std::mem::take(&mut net.wait) {
        // `IOU_RETRY`: it waits for its socket, as one that waited before.
        let mask = match net.op {
            Op::Transfer { msg_flags, .. } if msg_flags & MSG_ERRQUEUE != 0 => {
                POLL_IN_EVENTS & !POLLIN
            }
            _ => POLL_IN_EVENTS,
        };
        return (
            0,
            0,
            false,
            Some(Waits {
                file,
                mask: POLL_UNMASK | mask,
                kept: None,
                found: (opened, None),
            }),
        );
    }
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
        Op::Transfer { .. } => match net.layout {
            Some(layout) => {
                let (issued, ended) = receive_messages(c, ring, net.polled, &net.op, layout, &file);
                net.ended = ended;
                issued
            }
            None => transfer(c, ring, net.polled, &mut net.op, &file),
        },
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
/// (`io_net_retry`, `done_io`); any other short transfer fails, and so does
/// a receive whose message or ancillary data was cut. A receive
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
        message,
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
    if let Some(message) = message
        && chosen.is_some()
    {
        message.iov = vec![(at, count as usize)];
    }
    let total = match message {
        Some(message) => message.iov.iter().map(|&(_, len)| len as u64).sum(),
        None => u64::from(count),
    };
    let whole = *msg_flags & MSG_WAITALL != 0;
    // A receive with ancillary data is not gone on with.
    let wanted = match message {
        Some(message) if !send && message.control_len != 0 => 0,
        _ if whole => total,
        _ => 0,
    };
    // Whether a message was cut, which fails a receive of the whole:
    // `MSG_TRUNC` has it tell its length.
    let lengths = whole && !send && message.is_none() && !crate::sockets::is_byte_stream(file);
    let asked = if lengths {
        call_flags | MSG_TRUNC
    } else {
        call_flags
    };
    let mut cut = false;
    let result = if let Some(message) = message {
        let a = [0, *buf, u64::from(asked), 0, 0, 0];
        let result = crate::sockets::with_header(*buf, message, || {
            crate::sockets::route_file(c, if send { 46 } else { 47 }, a, file)
        });
        if whole && !send && result.is_ok() {
            let mut flags = [0; 4];
            cut = c
                .mem
                .read(GuestAddr(buf.wrapping_add(48)), &mut flags)
                .is_ok()
                && u32::from_le_bytes(flags) & (MSG_TRUNC | MSG_CTRUNC) != 0;
        }
        result
    } else {
        let (to_at, to_len) = to.map_or((0, 0), |(at, len)| (at, u64::from(len)));
        let a = [0, at, u64::from(count), u64::from(asked), to_at, to_len];
        let result = crate::sockets::route_file(c, if send { 44 } else { 45 }, a, file);
        match result {
            Ok(n) if lengths && n > u64::from(count) => {
                cut = true;
                let told = *msg_flags & MSG_TRUNC != 0;
                Ok(if told { n } else { u64::from(count) })
            }
            result => result,
        }
    };
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
                match message {
                    Some(message) => go_on(message, n, send),
                    None => {
                        *buf = buf.wrapping_add(n);
                        *len -= n as u32;
                    }
                }
                *done += n;
                return Issued::Again(mask);
            }
            _ => failed = true,
        }
    } else if cut {
        failed = true;
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

/// A multishot receive of a message (`io_recvmsg` with
/// `io_recvmsg_prep_multishot` and `io_recvmsg_multishot`), and whether it
/// ended: the buffer it selects (`ENOBUFS`) has its name, its control and
/// its bytes after a `struct io_uring_recvmsg_out` (`EFAULT` for a buffer
/// shorter than all but the bytes), which tells their lengths, the
/// message's whole one, and its flags. The caller's `msghdr` is not
/// written. Its result is the buffer's bytes used; the end of the stream
/// (no bytes) or an error ends it.
fn receive_messages(
    c: &mut Context<'_>,
    ring: &Ring,
    polled: bool,
    op: &Op,
    (name_room, control_len): (u32, u64),
    file: &Arc<dyn FileHandle>,
) -> (Issued, bool) {
    let &Op::Transfer {
        buf,
        len,
        msg_flags,
        flags,
        group: Some(bgid),
        ..
    } = op
    else {
        unreachable!()
    };
    let mask = if msg_flags & MSG_ERRQUEUE != 0 {
        POLL_IN_EVENTS & !POLLIN
    } else {
        POLL_IN_EVENTS
    };
    if !crate::sockets::is_socket(file) {
        return (Issued::Done(-Errno(88).0, 0, true), true);
    }
    if !polled && flags & RECVSEND_POLL_FIRST != 0 {
        return (Issued::Again(mask), false);
    }
    let chosen = match select(c, ring, bgid, len, true) {
        Ok(chosen) => chosen,
        Err(e) => return (Issued::Done(-e.0, 0, true), true),
    };
    let room = u64::from(chosen.len.min(crate::files::MAX_RW_COUNT as u32));
    let head = RECVMSG_OUT + u64::from(name_room) + control_len;
    if room < head {
        recycle(ring, &chosen);
        return (Issued::Done(-Errno::EFAULT.0, 0, true), true);
    }
    let name = chosen.addr + RECVMSG_OUT;
    let control = name + u64::from(name_room);
    let payload = room - head;
    let header = MessageHeader::of_buffer(
        name,
        name_room as usize,
        (control + control_len, payload as usize),
        if control_len == 0 { 0 } else { control },
        control_len,
    );
    let a = [0, buf, u64::from(msg_flags | MSG_DONTWAIT), 0, 0, 0];
    let (result, raw) = crate::sockets::with_shadow_header(buf, &header, name_room, || {
        crate::sockets::route_file(c, 47, a, file)
    });
    let written = result.and_then(|n| {
        let word = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap_or_default());
        let out = [
            if name_room == 0 { 0 } else { word(8) },
            word(40),
            n as u32,
            word(48) & !MSG_CMSG_COMPAT,
        ];
        let bytes: Vec<u8> = out.iter().flat_map(|v| v.to_le_bytes()).collect();
        c.mem
            .write(GuestAddr(chosen.addr), &bytes)
            .map_err(|_| Errno::EFAULT)?;
        Ok(n)
    });
    let n = match written {
        Ok(n) => n,
        Err(e) => {
            recycle(ring, &chosen);
            if e == Errno::EAGAIN {
                return (Issued::Again(mask), false);
            }
            return (Issued::Done(-e.0, 0, true), true);
        }
    };
    let res = head + n.min(payload);
    let mut cflags = give_back(c, ring, &chosen, &Ok(res));
    if crate::sockets::inq_hint(file).is_some_and(|inq| inq > 0) {
        cflags |= CQE_F_SOCK_NONEMPTY;
    }
    (Issued::Done(res as i32, cflags, false), n == 0)
}

/// What is left of a message after `n` bytes of it, a send's without its
/// ancillary data, which went.
fn go_on(message: &mut MessageHeader, n: u64, send: bool) {
    let mut n = n as usize;
    message.iov.retain_mut(|(base, len)| {
        let here = n.min(*len);
        *base = base.wrapping_add(here as u64);
        *len -= here;
        n -= here;
        *len != 0
    });
    if send {
        (message.control, message.control_len) = (0, 0);
    }
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
