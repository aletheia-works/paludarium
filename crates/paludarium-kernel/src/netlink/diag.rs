//! `NETLINK_SOCK_DIAG`, as Linux's `sock_diag` with its AF_UNIX handler,
//! `unix_diag`, the one there is, as in a kernel built without the others.
//!
//! `SOCK_DIAG_BY_FAMILY` names a family: AF_UNIX dumps the sockets of the
//! namespace the netlink socket was made in, or answers for one by its
//! inode, each with what the request's `udiag_show` asks for, as
//! `sk_diag_fill` makes it; another family has no handler (`ENOENT`).
//! Anyone may ask, and join its groups, which hear nothing, as no socket
//! is destroyed through it.
use super::{
    Errno, Header, NLM_F_DUMP, NLM_F_MULTI, NLMSG_DONE, NetlinkSocket, State, attribute, message,
};
use crate::users::Ids;

/// The groups a `NETLINK_SOCK_DIAG` socket has: its four (`SKNLGRP_MAX`),
/// which `netlink_kernel_create` makes 32, as it does any fewer.
pub(super) const GROUPS: u32 = 32;
const TCPDIAG_GETSOCK: u16 = 18;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const AF_UNIX: u8 = 1;
/// The families there are (`AF_MAX`).
const AF_MAX: u8 = 46;
/// A `unix_diag_req`'s and a `unix_diag_msg`'s length.
const UNIX_DIAG_REQ: usize = 24;
const UDIAG_SHOW_NAME: u32 = 0x1;
const UDIAG_SHOW_VFS: u32 = 0x2;
const UDIAG_SHOW_PEER: u32 = 0x4;
const UDIAG_SHOW_ICONS: u32 = 0x8;
const UDIAG_SHOW_RQLEN: u32 = 0x10;
const UDIAG_SHOW_MEMINFO: u32 = 0x20;
const UDIAG_SHOW_UID: u32 = 0x40;
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_VFS: u16 = 1;
const UNIX_DIAG_PEER: u16 = 2;
const UNIX_DIAG_ICONS: u16 = 3;
const UNIX_DIAG_RQLEN: u16 = 4;
const UNIX_DIAG_MEMINFO: u16 = 5;
const UNIX_DIAG_SHUTDOWN: u16 = 6;
const UNIX_DIAG_UID: u16 = 7;
/// A cookie that matches any socket (`INET_DIAG_NOCOOKIE`, twice).
const NO_COOKIE: u64 = u64::MAX;
const ENOENT: Errno = Errno::ENOENT;
const EINVAL: Errno = Errno::EINVAL;
const EOPNOTSUPP: Errno = Errno::EOPNOTSUPP;
const EBUSY: Errno = Errno(16);
const ESTALE: Errno = Errno(116);

/// A `unix_diag_req`.
struct Request {
    states: u32,
    inode: u32,
    show: u32,
    cookie: u64,
}
impl Request {
    fn read(payload: &[u8]) -> Self {
        let word = |i: usize| u32::from_le_bytes(payload[i..i + 4].try_into().unwrap_or_default());
        Self {
            states: word(4),
            inode: word(8),
            show: word(12),
            cookie: u64::from(word(16)) | u64::from(word(20)) << 32,
        }
    }
}

impl NetlinkSocket {
    /// One request, as `sock_diag_rcv_msg` and `__sock_diag_cmd`:
    /// `TCPDIAG_GETSOCK` has no handler (`EOPNOTSUPP`), and a type that is
    /// neither it, `SOCK_DIAG_BY_FAMILY` nor `SOCK_DESTROY` is `EINVAL`;
    /// then a message too short for a `sock_diag_req` or a family past
    /// `AF_MAX` is `EINVAL`, a family with no handler `ENOENT`, and
    /// `SOCK_DESTROY`, which AF_UNIX does not take, `EOPNOTSUPP`.
    /// `Ok(true)` is a dump that began, which is not acknowledged.
    pub(super) fn diag(
        &self,
        s: &mut State,
        header: &Header,
        payload: &[u8],
        port: u32,
    ) -> Result<bool, Errno> {
        match header.kind {
            TCPDIAG_GETSOCK => return Err(EOPNOTSUPP),
            SOCK_DIAG_BY_FAMILY | SOCK_DESTROY => {}
            _ => return Err(EINVAL),
        }
        if payload.len() < 2 || payload[0] >= AF_MAX {
            return Err(EINVAL);
        }
        if payload[0] != AF_UNIX {
            return Err(ENOENT);
        }
        if header.kind == SOCK_DESTROY {
            return Err(EOPNOTSUPP);
        }
        // `unix_diag_handler_dump`.
        if payload.len() < UNIX_DIAG_REQ {
            return Err(EINVAL);
        }
        let request = Request::read(payload);
        if header.flags & NLM_F_DUMP != 0 {
            if s.done.is_some() {
                return Err(EBUSY);
            }
            let mut messages = Vec::new();
            for socket in self.unix.sockets() {
                let Some(diag) = socket.diag() else { continue };
                if request.states & (1 << diag.state) == 0 {
                    continue;
                }
                messages.push(self.unix_message(&diag, &request, header.seq, port, NLM_F_MULTI));
            }
            let done = message(
                NLMSG_DONE,
                NLM_F_MULTI,
                header.seq,
                port,
                &0i32.to_le_bytes(),
            );
            // `unix_diag_dump` goes on while it puts anything, so its
            // `NLMSG_DONE` comes in a part of its own.
            self.start_dump(s, messages, done);
            return Ok(true);
        }
        // `unix_diag_get_exact`.
        if request.inode == 0 {
            return Err(EINVAL);
        }
        let diag = self
            .unix
            .sockets()
            .iter()
            .filter_map(|socket| socket.diag())
            .find(|diag| diag.inode as u32 == request.inode)
            .ok_or(ENOENT)?;
        // `sock_diag_check_cookie`.
        if request.cookie != NO_COOKIE && request.cookie != diag.cookie {
            return Err(ESTALE);
        }
        let reply = self.unix_message(&diag, &request, header.seq, port, 0);
        self.deliver(s, 0, 0, reply);
        Ok(false)
    }
    /// A socket's `unix_diag_msg`, as `sk_diag_fill` makes it: its type,
    /// state, inode and cookie, then what `udiag_show` asks for in this
    /// order: its name, socket file, peer, connections waiting, queues and
    /// memory; always its shutdown; and its owner as the user namespace of
    /// whoever made this socket shows it.
    fn unix_message(
        &self,
        diag: &crate::unix::Diag,
        request: &Request,
        seq: u32,
        port: u32,
        flags: u16,
    ) -> Vec<u8> {
        let word = |value: usize| (value as u32).to_le_bytes();
        let mut out = vec![AF_UNIX, diag.kind, diag.state, 0];
        out.extend_from_slice(&(diag.inode as u32).to_le_bytes());
        out.extend_from_slice(&diag.cookie.to_le_bytes());
        let show = request.show;
        if show & UDIAG_SHOW_NAME != 0
            && let Some(name) = &diag.name
        {
            attribute(&mut out, UNIX_DIAG_NAME, name);
        }
        if show & UDIAG_SHOW_VFS != 0
            && let Some((inode, device)) = diag.file
        {
            let mut vfs = (inode as u32).to_le_bytes().to_vec();
            vfs.extend_from_slice(&kernel_device(device).to_le_bytes());
            attribute(&mut out, UNIX_DIAG_VFS, &vfs);
        }
        if show & UDIAG_SHOW_PEER != 0
            && let Some(peer) = diag.peer
        {
            attribute(&mut out, UNIX_DIAG_PEER, &(peer as u32).to_le_bytes());
        }
        if show & UDIAG_SHOW_ICONS != 0
            && let Some(waiting) = &diag.waiting
        {
            let icons: Vec<u8> = waiting
                .iter()
                .flat_map(|&inode| (inode as u32).to_le_bytes())
                .collect();
            attribute(&mut out, UNIX_DIAG_ICONS, &icons);
        }
        if show & UDIAG_SHOW_RQLEN != 0 {
            let mut rqlen = word(diag.queues.0).to_vec();
            rqlen.extend_from_slice(&word(diag.queues.1));
            attribute(&mut out, UNIX_DIAG_RQLEN, &rqlen);
        }
        if show & UDIAG_SHOW_MEMINFO != 0 {
            // `sock_diag_put_meminfo`: what it receives is charged to the
            // sender, so its receive memory is 0, as are its forward
            // allocation, queued writes, option memory, backlog and drops.
            let (receive, send) = diag.buffers;
            let meminfo: [u32; 9] = [
                0,
                receive as u32,
                diag.sent as u32,
                send as u32,
                0,
                0,
                0,
                0,
                0,
            ];
            let bytes: Vec<u8> = meminfo.iter().flat_map(|v| v.to_le_bytes()).collect();
            attribute(&mut out, UNIX_DIAG_MEMINFO, &bytes);
        }
        attribute(&mut out, UNIX_DIAG_SHUTDOWN, &[diag.shutdown]);
        if show & UDIAG_SHOW_UID != 0 {
            let uid = self.opener_user.shown(Ids::User, diag.uid);
            attribute(&mut out, UNIX_DIAG_UID, &uid.to_le_bytes());
        }
        message(SOCK_DIAG_BY_FAMILY, flags, seq, port, &out)
    }
}
/// A device number as `stat` encodes it (`new_encode_dev`), as the kernel
/// keeps it (`MKDEV`).
fn kernel_device(device: u64) -> u32 {
    let major = (device >> 8) & 0xfff;
    let minor = (device & 0xff) | ((device >> 12) & 0xfff00);
    (major << 20 | minor) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_take_the_kernels_encoding() {
        assert_eq!(kernel_device(3), 3);
        assert_eq!(kernel_device(0x0803), 8 << 20 | 3);
        assert_eq!(kernel_device(0x123_4501), 0x345 << 20 | 0x1201);
    }

    #[test]
    fn requests_read_as_unix_diag_req() {
        let mut raw = [0u8; 24];
        raw[0] = 1;
        raw[4..8].copy_from_slice(&0xfffu32.to_le_bytes());
        raw[8..12].copy_from_slice(&77u32.to_le_bytes());
        raw[12..16].copy_from_slice(&0x7fu32.to_le_bytes());
        raw[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        let request = Request::read(&raw);
        assert_eq!(
            (request.states, request.inode, request.show, request.cookie),
            (0xfff, 77, 0x7f, NO_COOKIE)
        );
    }
}
