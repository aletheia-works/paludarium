//! `AF_NETLINK` sockets of `NETLINK_ROUTE`, in the network namespace each
//! was made in, whose loopback `lo` is its only interface.
//!
//! As Linux's `af_netlink` and `rtnetlink`: a socket is bound to a port ID
//! (the process's ID, or a negative one when that is taken) by `bind`, or by
//! its first `connect` or send. The kernel takes each message of a datagram
//! sent to port 0 in turn: `RTM_GETLINK` and `RTM_GETADDR` dumps
//! (`NLM_F_DUMP`) answer with the loopback and its addresses, then
//! `NLMSG_DONE` at the next receive; `RTM_GETLINK` without a dump answers
//! for `lo` by index or name; `RTM_NEWLINK` and `RTM_SETLINK` bring it up or
//! down with `IFF_UP`, given `CAP_NET_ADMIN` in the user namespace that owns
//! the network namespace. An error, or a success the request asks for with
//! `NLM_F_ACK`, is answered with `NLMSG_ERROR`; any other request is
//! `EOPNOTSUPP`. A datagram to another socket's port reaches it.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::inet::Network;
use crate::sockets::Timeout;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const AF_NETLINK: u16 = 16;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// Types below this are control messages, which the kernel does not handle.
const NLMSG_MIN_TYPE: u16 = 0x10;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
/// The last message type `rtnetlink_rcv_msg` takes (`RTM_MAX`).
const RTM_MAX: u16 = 123;
const AF_INET: u8 = 2;
const AF_BRIDGE: u8 = 7;
const AF_INET6: u8 = 10;
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_QDISC: u16 = 6;
const IFLA_STATS: u16 = 7;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_STATS64: u16 = 23;
const IFLA_GROUP: u16 = 27;
const IFLA_EXT_MASK: u16 = 29;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_CARRIER_UP_COUNT: u16 = 47;
const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_ALLMULTI: u16 = 61;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_PROTO: u16 = 11;
/// `IFAPROT_KERNEL_LO`: the kernel gave the loopback the address, which
/// `addrconf` notes for `::1` alone.
const IFAPROT_KERNEL_LO: u8 = 1;
const IFA_F_PERMANENT: u32 = 0x80;
const RT_SCOPE_HOST: u8 = 254;
const ARPHRD_LOOPBACK: u16 = 772;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x10000;
const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_DOWN: u8 = 2;
const SOL_SOCKET: u64 = 1;
const SOL_NETLINK: u64 = 270;
const NETLINK_CAP_ACK: u64 = 10;
const NETLINK_EXT_ACK: u64 = 11;
const NETLINK_GET_STRICT_CHK: u64 = 12;
const CAP_NET_ADMIN: u64 = 1 << 12;
const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const ENODEV: Errno = Errno(19);
const ERANGE: Errno = Errno(34);
const ENOTSOCK: Errno = Errno(88);
const EMSGSIZE: Errno = Errno(90);
const ENOPROTOOPT: Errno = Errno(92);
const EPROTONOSUPPORT: Errno = Errno(93);
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EOPNOTSUPP: Errno = Errno(95);
const EAFNOSUPPORT: Errno = Errno(97);
const EADDRINUSE: Errno = Errno(98);
const ENOBUFS: Errno = Errno(105);
const ECONNREFUSED: Errno = Errno(111);
const EBUSY: Errno = Errno(16);
const EEXIST: Errno = Errno(17);
/// `net.core.rmem_default` and `wmem_default`, and their `_max`.
const BUFFER_DEFAULT: i32 = 212_992;
const BUFFER_MAX: i32 = 212_992;
/// What `sock_setsockopt` keeps at least (`SOCK_MIN_RCVBUF`, `_SNDBUF`).
const MIN_RECEIVE_BUFFER: i32 = 2304;
const MIN_SEND_BUFFER: i32 = 4608;
/// The loopback's MTU, queue length and GSO limits.
const LO_MTU: u32 = 65536;
const LO_TXQLEN: u32 = 1000;
const GSO_MAX_SEGS: u32 = 65535;
const GSO_MAX_SIZE: u32 = 65536;
/// `struct rtnl_link_stats` (24 `__u32`s) and `rtnl_link_stats64` (25
/// `__u64`s).
const STATS_LEN: usize = 24 * 4;
const STATS64_LEN: usize = 25 * 8;

/// The port IDs bound in a network namespace (`nl_table[NETLINK_ROUTE]`'s
/// hash for it), and the next one an autobind tries when the process's own
/// is taken.
pub(crate) struct Ports {
    bound: Mutex<BTreeMap<u32, Weak<NetlinkSocket>>>,
    rover: AtomicI32,
}
impl Default for Ports {
    fn default() -> Self {
        Self {
            bound: Mutex::default(),
            rover: AtomicI32::new(-4097),
        }
    }
}
impl Ports {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u32, Weak<NetlinkSocket>>> {
        self.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A datagram waiting to be received: who sent it (0 for the kernel), and
/// the group it went to.
struct Datagram {
    from: u32,
    group: u32,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct State {
    /// The port ID, once bound.
    port: Option<u32>,
    /// The multicast groups `bind` asked for (the first 32).
    groups: u32,
    /// Where a send without an address goes (`connect`): a port and a group
    /// number, 0 for none.
    peer: (u32, u32),
    queue: VecDeque<Datagram>,
    /// The bytes waiting in `queue`.
    queued: usize,
    /// A dump's `NLMSG_DONE`, which the next receive queues (Linux's
    /// `cb_running`).
    done: Option<Vec<u8>>,
    /// An error a receive gives before anything else (`sk_err`).
    error: Option<Errno>,
    arrivals: u64,
    receive_buffer: i32,
    send_buffer: i32,
    receive_timeout: Timeout,
    cap_ack: bool,
    ext_ack: bool,
    strict: bool,
}

/// An `AF_NETLINK` socket of `NETLINK_ROUTE`.
pub(crate) struct NetlinkSocket {
    this: Weak<NetlinkSocket>,
    kind: u32,
    network: Arc<Network>,
    /// The network namespace it was made in, whose owner's
    /// `CAP_NET_ADMIN` changes the loopback.
    namespace: Arc<crate::namespaces::Namespace>,
    /// Whether whoever made it had that capability (the socket file's
    /// credentials, which Linux's `netlink_ns_capable` asks as well).
    opener_admin: bool,
    /// The process ID of whoever made it, which a `write` that binds it
    /// takes.
    opener_pid: u32,
    hub: Arc<ReadinessHub>,
    flags: AtomicU32,
    inode: u64,
    mode: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    state: Mutex<State>,
}

/// Who sends: the process ID an autobind takes, and whether it may
/// administer the network.
#[derive(Clone, Copy)]
struct Sender {
    pid: u32,
    admin: bool,
}

/// `socket(AF_NETLINK, type, protocol)`, as Linux's `netlink_create`:
/// `SOCK_RAW` or `SOCK_DGRAM` (`ESOCKTNOSUPPORT`), and only `NETLINK_ROUTE`
/// (`EPROTONOSUPPORT`). Without a network there is none (`EAFNOSUPPORT`).
pub(crate) fn socket(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let kind = a[1] as u32;
    if a[1] > u64::from(u32::MAX) || kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 || kind & 0xf >= 11 {
        return Err(Errno::EINVAL);
    }
    let network = c.network().ok_or(EAFNOSUPPORT)?;
    if !matches!(kind & 0xf, SOCK_RAW | SOCK_DGRAM) {
        return Err(ESOCKTNOSUPPORT);
    }
    if a[2] as i32 != 0 {
        return Err(EPROTONOSUPPORT);
    }
    let namespace = Arc::clone(&c.group.namespaces(c.tid).net);
    let credentials = &c.process.credentials;
    let opener_admin = credentials.capable_in(CAP_NET_ADMIN, namespace.owner());
    let socket = Arc::new_cyclic(|this| NetlinkSocket {
        this: Weak::clone(this),
        kind: kind & 0xf,
        network,
        namespace,
        opener_admin,
        opener_pid: c.pid_space().number(c.process.pid),
        hub: Arc::clone(&c.files.readiness),
        flags: AtomicU32::new(2 | (kind & NONBLOCK)),
        inode: crate::files::anonymous_inode(),
        mode: AtomicU32::new(0o140777),
        uid: AtomicU32::new(credentials.fsuid),
        gid: AtomicU32::new(credentials.fsgid),
        state: Mutex::new(State {
            receive_buffer: BUFFER_DEFAULT,
            send_buffer: BUFFER_DEFAULT,
            ..State::default()
        }),
    });
    c.files
        .install(socket, kind & CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

/// The netlink socket of `file`, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&NetlinkSocket> {
    file.as_any()?.downcast_ref::<NetlinkSocket>()
}

impl NetlinkSocket {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The network it was made in.
    pub(crate) fn network(&self) -> &Network {
        &self.network
    }
    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::SeqCst) & NONBLOCK != 0
    }
    /// The calling thread, as a sender: Linux's `netlink_ns_capable` wants
    /// the capability of both it and whoever opened the socket.
    fn sender(&self, c: &Context<'_>) -> Sender {
        Sender {
            pid: c.pid_space().number(c.process.pid),
            admin: self.opener_admin
                && c.process
                    .credentials
                    .capable_in(CAP_NET_ADMIN, self.namespace.owner()),
        }
    }
    /// Binds to `port`, or with 0 to the process's ID or, that taken, the
    /// next free negative one (`netlink_autobind`).
    fn bind_port(&self, s: &mut State, port: u32, pid: u32) -> Result<(), Errno> {
        let ports = &self.network.netlink;
        let mut bound = ports.lock();
        bound.retain(|_, socket| socket.strong_count() > 0);
        let port = if port != 0 {
            if bound.contains_key(&port) {
                return Err(EADDRINUSE);
            }
            port
        } else {
            let mut port = pid;
            while port == 0 || bound.contains_key(&port) {
                let next = ports.rover.fetch_sub(1, Ordering::SeqCst);
                port = (if next >= -4096 { -4097 } else { next }) as u32;
            }
            port
        };
        bound.insert(port, Weak::clone(&self.this));
        s.port = Some(port);
        Ok(())
    }
    /// Its port, binding it first if it has none.
    fn port(&self, s: &mut State, pid: u32) -> Result<u32, Errno> {
        if let Some(port) = s.port {
            return Ok(port);
        }
        self.bind_port(s, 0, pid)?;
        Ok(s.port.unwrap_or(0))
    }
    /// Queues a datagram for this socket, as `netlink_attachskb`: one that
    /// finds the receive buffer full is dropped, with `ENOBUFS` for the
    /// next receive (`netlink_overrun`).
    fn deliver(&self, s: &mut State, from: u32, group: u32, bytes: Vec<u8>) {
        if s.queued >= usize::try_from(s.receive_buffer).unwrap_or(0) {
            s.error = Some(ENOBUFS);
        } else {
            s.queued += bytes.len();
            s.queue.push_back(Datagram { from, group, bytes });
        }
        s.arrivals += 1;
        self.hub.changed();
    }
    /// `bind`, as Linux's `netlink_bind`: a `sockaddr_nl` (`EINVAL` for a
    /// shorter address or another family); a bound socket takes only its
    /// own port again (`EINVAL`), and a port another socket has is
    /// `EADDRINUSE`. Groups are noted, but no notification is ever sent.
    fn bind(&self, raw: &[u8], sender: Sender) -> Result<u64, Errno> {
        let (port, groups) = address(raw)?;
        let mut s = self.lock();
        match s.port {
            Some(own) if own != port => return Err(Errno::EINVAL),
            Some(_) => {}
            None => self.bind_port(&mut s, port, sender.pid)?,
        }
        s.groups = groups;
        Ok(0)
    }
    /// `connect`, as `netlink_connect`: `AF_UNSPEC` forgets the peer; a
    /// port or group other than the kernel's needs `CAP_NET_ADMIN`
    /// (`EPERM`), as `NETLINK_ROUTE` lets no user send to one.
    fn connect(&self, raw: &[u8], sender: Sender) -> Result<u64, Errno> {
        if raw.len() < 2 {
            return Err(Errno::EINVAL);
        }
        let mut s = self.lock();
        if u16::from_le_bytes([raw[0], raw[1]]) == 0 {
            s.peer = (0, 0);
            return Ok(0);
        }
        let (port, groups) = address(raw)?;
        if (port != 0 || groups != 0) && !sender.admin {
            return Err(Errno::EPERM);
        }
        self.port(&mut s, sender.pid)?;
        s.peer = (port, first_group(groups));
        Ok(0)
    }
    /// The `sockaddr_nl` of its port and groups, or with `peer` of its peer.
    fn name(&self, peer: bool) -> [u8; 12] {
        let s = self.lock();
        let (port, groups) = if peer {
            (s.peer.0, group_mask(s.peer.1))
        } else {
            (s.port.unwrap_or(0), s.groups)
        };
        encode_address(port, groups)
    }
    /// Sends `bytes` to the kernel, or to the socket at `to` (a port and
    /// group, the peer's without one), as `netlink_sendmsg`: the socket
    /// binds first; more than the send buffer takes is `EMSGSIZE`; another
    /// socket's port that none has is `ECONNREFUSED`.
    fn send(&self, bytes: &[u8], to: Option<(u32, u32)>, sender: Sender) -> Result<usize, Errno> {
        let mut s = self.lock();
        let (to, group) = match to {
            Some((port, groups)) => {
                if (port != 0 || groups != 0) && !sender.admin {
                    return Err(Errno::EPERM);
                }
                (port, first_group(groups))
            }
            None => s.peer,
        };
        let port = self.port(&mut s, sender.pid)?;
        if bytes.len() > usize::try_from(s.send_buffer - 32).unwrap_or(0) {
            return Err(EMSGSIZE);
        }
        if to != 0 {
            drop(s);
            let target = self
                .network
                .netlink
                .lock()
                .get(&to)
                .and_then(Weak::upgrade)
                .ok_or(ECONNREFUSED)?;
            let mut t = target.lock();
            // A socket connected elsewhere takes nothing from this one.
            if t.peer.0 != 0 && t.peer.0 != port {
                return Err(ECONNREFUSED);
            }
            target.deliver(&mut t, port, group, bytes.to_vec());
            return Ok(bytes.len());
        }
        self.take(&mut s, bytes, port, sender.admin);
        Ok(bytes.len())
    }
    /// The kernel takes each message of a datagram from `port`, as Linux's
    /// `netlink_rcv_skb` does: it stops at one too short or longer than
    /// what is left; one that is no request, or a control message, is only
    /// acknowledged; an error, or any result with `NLM_F_ACK`, is answered
    /// with `NLMSG_ERROR`, but for a dump that began.
    fn take(&self, s: &mut State, mut bytes: &[u8], port: u32, admin: bool) {
        while bytes.len() >= 16 {
            let header = Header::read(bytes);
            let len = header.len as usize;
            if len < 16 || bytes.len() < len {
                return;
            }
            let message = &bytes[..len];
            let result = if header.flags & NLM_F_REQUEST == 0 || header.kind < NLMSG_MIN_TYPE {
                Ok(false)
            } else {
                self.route(s, &header, &message[16..], port, admin)
            };
            match result {
                Ok(true) => {}
                Ok(false) if header.flags & NLM_F_ACK == 0 => {}
                Ok(false) => {
                    let ack = acknowledgement(message, &header, port, 0, true);
                    self.deliver(s, 0, 0, ack);
                }
                Err(e) => {
                    let ack = acknowledgement(message, &header, port, e.0, s.cap_ack);
                    self.deliver(s, 0, 0, ack);
                }
            }
            bytes = &bytes[align(len).min(bytes.len())..];
        }
    }
    /// One request, as `rtnetlink_rcv_msg`: a type past `RTM_MAX` is
    /// `EOPNOTSUPP`; one with no family byte is taken without effect; any
    /// but a `GET` needs `CAP_NET_ADMIN` (`EPERM`). `Ok(true)` is a dump
    /// that began, which is not acknowledged.
    fn route(
        &self,
        s: &mut State,
        header: &Header,
        payload: &[u8],
        port: u32,
        admin: bool,
    ) -> Result<bool, Errno> {
        if header.kind > RTM_MAX {
            return Err(EOPNOTSUPP);
        }
        let Some(&family) = payload.first() else {
            return Ok(false);
        };
        let get = (header.kind - NLMSG_MIN_TYPE) & 3 == 2;
        if !get && !admin {
            return Err(Errno::EPERM);
        }
        if get && header.flags & NLM_F_DUMP != 0 {
            let messages = match (header.kind, family) {
                // `rtnl_bridge_getlink` has no bridge port to show.
                (RTM_GETLINK, AF_BRIDGE) => Vec::new(),
                (RTM_GETLINK, _) => link_message(&self.network, header.seq, port, NLM_F_MULTI),
                // `rtnl_dump_all` dumps each family's: IPv4's, then IPv6's.
                (RTM_GETADDR, _) => {
                    let mut messages = Vec::new();
                    if family != AF_INET6 {
                        messages.extend(ipv4_message(&self.network, header.seq, port));
                    }
                    if family != AF_INET {
                        messages.extend(ipv6_message(&self.network, header.seq, port));
                    }
                    messages
                }
                _ => return Err(EOPNOTSUPP),
            };
            if s.done.is_some() {
                return Err(EBUSY);
            }
            let done = message(
                NLMSG_DONE,
                NLM_F_MULTI,
                header.seq,
                port,
                &0i32.to_le_bytes(),
            );
            if messages.is_empty() {
                self.deliver(s, 0, 0, done);
            } else {
                self.deliver(s, 0, 0, messages);
                s.done = Some(done);
            }
            return Ok(true);
        }
        match header.kind {
            RTM_GETLINK => {
                self.find_link(payload, header, true)?;
                let reply = link_message(&self.network, header.seq, port, 0);
                self.deliver(s, 0, 0, reply);
                Ok(false)
            }
            RTM_NEWLINK | RTM_SETLINK => {
                let (flags, change) = self.find_link(payload, header, false)?;
                // `rtnl_dev_combine_flags`: only the flags `ifi_change`
                // names, or all with none named; of them only `IFF_UP`.
                if flags != 0 || change != 0 {
                    let up = if change == 0 {
                        flags
                    } else {
                        (flags & change) | (link_flags(&self.network) & !change)
                    } & IFF_UP
                        != 0;
                    self.network.set_up(up);
                }
                Ok(false)
            }
            _ => Err(EOPNOTSUPP),
        }
    }
    /// The `ifinfomsg` of a request for `lo`, which names it by its index
    /// or (with index 0) by `IFLA_IFNAME` or `IFLA_ALT_IFNAME`: `EINVAL` for
    /// a short message, a negative index or, to get, neither; `ENODEV` for
    /// another interface. To set, `NLM_F_EXCL` is `EEXIST` and
    /// `NLM_F_REPLACE` `EOPNOTSUPP` for `RTM_NEWLINK`, and of the
    /// attributes only the name `lo` and `IFLA_EXT_MASK` are taken
    /// (`EOPNOTSUPP` for others). The flags and the change mask.
    fn find_link(&self, payload: &[u8], header: &Header, get: bool) -> Result<(u32, u32), Errno> {
        if payload.len() < 16 {
            return Err(Errno::EINVAL);
        }
        let word = |i: usize| u32::from_le_bytes(payload[i..i + 4].try_into().unwrap_or_default());
        let index = word(4) as i32;
        let attributes = attributes(&payload[16..]);
        let mut name = None;
        for &(kind, value) in &attributes {
            match kind {
                IFLA_IFNAME | IFLA_ALT_IFNAME => {
                    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                    if end > 15 {
                        return Err(ERANGE);
                    }
                    if kind == IFLA_IFNAME || name.is_none() {
                        name = Some(&value[..end]);
                    }
                }
                IFLA_EXT_MASK => {}
                _ if get => {}
                _ => return Err(EOPNOTSUPP),
            }
        }
        let found = match (index, name) {
            (i, _) if i < 0 => return Err(Errno::EINVAL),
            (0, None) if get => return Err(Errno::EINVAL),
            (0, None) => false,
            (0, Some(name)) => name == b"lo",
            (i, _) => i == 1,
        };
        if !found {
            // `rtnl_newlink` makes a link only of a kind it is given.
            if !get && header.kind == RTM_NEWLINK && header.flags & NLM_F_CREATE != 0 {
                return Err(EOPNOTSUPP);
            }
            return Err(ENODEV);
        }
        // Renaming `lo` to another name is not supported.
        if !get && index != 0 && name.is_some_and(|name| name != b"lo") {
            return Err(EOPNOTSUPP);
        }
        if !get && header.kind == RTM_NEWLINK {
            if header.flags & NLM_F_EXCL != 0 {
                return Err(EEXIST);
            }
            if header.flags & NLM_F_REPLACE != 0 {
                return Err(EOPNOTSUPP);
            }
        }
        Ok((word(8), word(12)))
    }
    /// Receives one datagram into `buf`, as `netlink_recvmsg`: a pending
    /// error first, `EAGAIN` while there is none; `peek` leaves it. A
    /// dump's `NLMSG_DONE` is queued after it. The bytes copied, the
    /// datagram's length, and its sender and group.
    fn receive(&self, buf: &mut [u8], peek: bool) -> Result<(usize, usize, u32, u32), Errno> {
        let mut s = self.lock();
        if let Some(error) = s.error.take() {
            return Err(error);
        }
        let Some(first) = s.queue.front() else {
            return Err(Errno::EAGAIN);
        };
        let n = buf.len().min(first.bytes.len());
        buf[..n].copy_from_slice(&first.bytes[..n]);
        let got = (n, first.bytes.len(), first.from, first.group);
        if !peek {
            s.queue.pop_front();
            s.queued -= got.1;
        }
        if s.queued <= usize::try_from(s.receive_buffer / 2).unwrap_or(0)
            && let Some(done) = s.done.take()
        {
            self.deliver(&mut s, 0, 0, done);
        }
        Ok(got)
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        let port = self
            .state
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .port;
        if let Some(port) = port {
            let mut bound = self.network.netlink.lock();
            if bound.get(&port).is_some_and(|w| w.ptr_eq(&self.this)) {
                bound.remove(&port);
            }
        }
    }
}

impl FileHandle for NetlinkSocket {
    /// As `datagram_poll`: always writable, readable with a datagram or an
    /// error waiting.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let s = self.lock();
        let error = u32::from(s.error.is_some()) * 8;
        let ready = u32::from(!s.queue.is_empty()) * IN;
        Ok((OUT | ready | error, s.arrivals, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.receive(buf, false).map(|(n, ..)| n)
    }
    /// A send to the peer; it binds with the opener's process ID and acts
    /// with the opener's capability, as no calling thread is known here.
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let sender = Sender {
            pid: self.opener_pid,
            admin: self.opener_admin,
        };
        self.send(buf, None, sender)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            mode: self.mode.load(Ordering::SeqCst),
            uid: self.uid.load(Ordering::SeqCst),
            gid: self.gid.load(Ordering::SeqCst),
            links: 1,
            ..FileStat::default()
        })
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.mode
            .store(0o140000 | (mode & 0o7777), Ordering::SeqCst);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        if let Some(uid) = uid {
            self.uid.store(uid, Ordering::SeqCst);
        }
        if let Some(gid) = gid {
            self.gid.store(gid, Ordering::SeqCst);
        }
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
        self.flags.store(2 | (flags & NONBLOCK), Ordering::SeqCst);
        Ok(())
    }
}

/// A message's `nlmsghdr`.
struct Header {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
}
impl Header {
    fn read(bytes: &[u8]) -> Self {
        let word = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap_or_default());
        Self {
            len: word(0),
            kind: u16::from_le_bytes([bytes[4], bytes[5]]),
            flags: u16::from_le_bytes([bytes[6], bytes[7]]),
            seq: word(8),
        }
    }
}
/// `NLMSG_ALIGN` and `NLA_ALIGN`.
fn align(len: usize) -> usize {
    (len + 3) & !3
}
/// A message of `kind` with `flags`, `seq` and `port`, around `payload`.
fn message(kind: u16, flags: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut out = Vec::with_capacity(align(len));
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(align(len), 0);
    out
}
/// Appends attribute `kind` of `value`, padded.
fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&((4 + value.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(value);
    out.resize(align(out.len()), 0);
}
/// The attributes of `bytes`, as `nla_parse_deprecated` takes them: it
/// stops at one too short or too long, and the type drops
/// `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER`.
fn attributes(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if len < 4 || len > bytes.len() {
            break;
        }
        out.push((
            u16::from_le_bytes([bytes[2], bytes[3]]) & 0x3fff,
            &bytes[4..len],
        ));
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    out
}
/// `NLMSG_ERROR` for `request` with `error` (0 for an acknowledgement), as
/// `netlink_ack`: an error carries the whole request unless `capped`
/// (`NETLINK_CAP_ACK`), which an acknowledgement always is.
fn acknowledgement(
    request: &[u8],
    header: &Header,
    port: u32,
    error: i32,
    capped: bool,
) -> Vec<u8> {
    let capped = error == 0 || capped;
    let mut payload = (-error).to_le_bytes().to_vec();
    if capped {
        payload.extend_from_slice(&request[..16]);
    } else {
        payload.extend_from_slice(request);
        payload.resize(4 + 16 + align(request.len() - 16), 0);
    }
    let flags = if capped { NLM_F_CAPPED } else { 0 };
    message(NLMSG_ERROR, flags, header.seq, port, &payload)
}
/// The flags of `lo`, as `dev_get_flags`: `IFF_LOOPBACK`, with `IFF_UP`,
/// `IFF_RUNNING` and `IFF_LOWER_UP` while it is up.
fn link_flags(network: &Network) -> u32 {
    if network.is_up() {
        IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP
    } else {
        IFF_LOOPBACK
    }
}
/// `RTM_NEWLINK` for `lo`, as `rtnl_fill_ifinfo` gives it, with the
/// attributes of its name, queue, state, MTU, carrier, queueing
/// discipline, hardware addresses and statistics (all zero).
fn link_message(network: &Network, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let up = network.is_up();
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes());
    body.extend_from_slice(&link_flags(network).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    let u32_of = |v: u32| v.to_le_bytes();
    attribute(&mut body, IFLA_IFNAME, b"lo\0");
    attribute(&mut body, IFLA_TXQLEN, &u32_of(LO_TXQLEN));
    let operstate = if up { IF_OPER_UNKNOWN } else { IF_OPER_DOWN };
    attribute(&mut body, IFLA_OPERSTATE, &[operstate]);
    attribute(&mut body, IFLA_LINKMODE, &[0]);
    attribute(&mut body, IFLA_MTU, &u32_of(LO_MTU));
    attribute(&mut body, IFLA_MIN_MTU, &u32_of(0));
    attribute(&mut body, IFLA_MAX_MTU, &u32_of(0));
    attribute(&mut body, IFLA_GROUP, &u32_of(0));
    attribute(&mut body, IFLA_PROMISCUITY, &u32_of(0));
    attribute(&mut body, IFLA_ALLMULTI, &u32_of(0));
    attribute(&mut body, IFLA_NUM_TX_QUEUES, &u32_of(1));
    attribute(&mut body, IFLA_GSO_MAX_SEGS, &u32_of(GSO_MAX_SEGS));
    attribute(&mut body, IFLA_GSO_MAX_SIZE, &u32_of(GSO_MAX_SIZE));
    attribute(&mut body, IFLA_GRO_MAX_SIZE, &u32_of(GSO_MAX_SIZE));
    attribute(&mut body, IFLA_NUM_RX_QUEUES, &u32_of(1));
    attribute(&mut body, IFLA_CARRIER, &[1]);
    attribute(&mut body, IFLA_CARRIER_CHANGES, &u32_of(0));
    attribute(&mut body, IFLA_PROTO_DOWN, &[0]);
    attribute(&mut body, IFLA_CARRIER_UP_COUNT, &u32_of(0));
    attribute(&mut body, IFLA_CARRIER_DOWN_COUNT, &u32_of(0));
    attribute(&mut body, IFLA_ADDRESS, &[0; 6]);
    attribute(&mut body, IFLA_BROADCAST, &[0; 6]);
    attribute(&mut body, IFLA_STATS64, &[0; STATS64_LEN]);
    attribute(&mut body, IFLA_STATS, &[0; STATS_LEN]);
    // A device gets its queueing discipline when it first opens, and keeps
    // it when it goes down (`dev_activate`).
    let qdisc: &[u8] = if network.has_ipv4_address() {
        b"noqueue\0"
    } else {
        b"noop\0"
    };
    attribute(&mut body, IFLA_QDISC, qdisc);
    message(RTM_NEWLINK, flags, seq, port, &body)
}
/// An `ifaddrmsg` of `lo` for `family`, `prefix` and `flags`.
fn address_header(family: u8, prefix: u8, flags: u32) -> Vec<u8> {
    let mut body = vec![family, prefix, flags as u8, RT_SCOPE_HOST];
    body.extend_from_slice(&1u32.to_le_bytes());
    body
}
/// `struct ifa_cacheinfo`: forever preferred and valid. The times it was
/// made and changed are given as 0.
fn cacheinfo() -> [u8; 16] {
    let mut raw = [0; 16];
    raw[..8].copy_from_slice(&[0xff; 8]);
    raw
}
/// `RTM_NEWADDR` for `127.0.0.1/8`, once the loopback has it, as
/// `inet_fill_ifaddr` gives it.
fn ipv4_message(network: &Network, seq: u32, port: u32) -> Vec<u8> {
    if !network.has_ipv4_address() {
        return Vec::new();
    }
    let mut body = address_header(AF_INET, 8, IFA_F_PERMANENT);
    attribute(&mut body, IFA_ADDRESS, &[127, 0, 0, 1]);
    attribute(&mut body, IFA_LOCAL, &[127, 0, 0, 1]);
    attribute(&mut body, IFA_LABEL, b"lo\0");
    attribute(&mut body, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
    attribute(&mut body, IFA_CACHEINFO, &cacheinfo());
    message(RTM_NEWADDR, NLM_F_MULTI, seq, port, &body)
}
/// `RTM_NEWADDR` for `::1/128` while the loopback is up, as
/// `inet6_fill_ifaddr` gives it.
fn ipv6_message(network: &Network, seq: u32, port: u32) -> Vec<u8> {
    if !network.is_up() {
        return Vec::new();
    }
    let flags = IFA_F_PERMANENT;
    let mut body = address_header(AF_INET6, 128, flags);
    let mut one = [0; 16];
    one[15] = 1;
    attribute(&mut body, IFA_ADDRESS, &one);
    attribute(&mut body, IFA_CACHEINFO, &cacheinfo());
    attribute(&mut body, IFA_FLAGS, &flags.to_le_bytes());
    attribute(&mut body, IFA_PROTO, &[IFAPROT_KERNEL_LO]);
    message(RTM_NEWADDR, NLM_F_MULTI, seq, port, &body)
}
/// The port and groups of a `sockaddr_nl`: `EINVAL` for fewer than its 12
/// bytes or another family.
fn address(raw: &[u8]) -> Result<(u32, u32), Errno> {
    if raw.len() < 12 || u16::from_le_bytes([raw[0], raw[1]]) != AF_NETLINK {
        return Err(Errno::EINVAL);
    }
    let word = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap_or_default());
    Ok((word(4), word(8)))
}
fn encode_address(port: u32, groups: u32) -> [u8; 12] {
    let mut raw = [0; 12];
    raw[..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
    raw[4..8].copy_from_slice(&port.to_le_bytes());
    raw[8..].copy_from_slice(&groups.to_le_bytes());
    raw
}
/// The number of the lowest group of a mask (`ffs`), 0 for none.
fn first_group(groups: u32) -> u32 {
    if groups == 0 {
        0
    } else {
        groups.trailing_zeros() + 1
    }
}
/// The mask of group number `group` (`netlink_group_mask`).
fn group_mask(group: u32) -> u32 {
    if group == 0 { 0 } else { 1 << (group - 1) }
}

/// The system calls of a netlink socket, `file` of descriptor `a[0]`.
pub(crate) fn dispatch(
    c: &mut Context<'_>,
    number: u64,
    a: [u64; 6],
    file: &Arc<dyn FileHandle>,
) -> Result<u64, Errno> {
    let socket = of(file).ok_or(ENOTSOCK)?;
    let sender = socket.sender(c);
    match number {
        42 => {
            let raw = crate::inet::read_raw(c, a[1], a[2])?;
            socket.connect(&raw, sender)
        }
        49 => {
            let raw = crate::inet::read_raw(c, a[1], a[2])?;
            socket.bind(&raw, sender)
        }
        51 | 52 => {
            crate::inet::write_address(c, &socket.name(number == 52), a[1], a[2])?;
            Ok(0)
        }
        // accept, listen and shutdown, which netlink has not.
        43 | 50 | 288 | 48 => Err(EOPNOTSUPP),
        54 => set_option(c, socket, a),
        55 => get_option(c, socket, a),
        44 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let to = if a[4] != 0 && a[5] != 0 {
                Some(address(&crate::inet::read_raw(c, a[4], a[5])?)?)
            } else {
                None
            };
            let mut bytes = vec![0; len];
            c.mem
                .read(GuestAddr(a[1]), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            send(socket, &bytes, a[3], to, sender)
        }
        46 => {
            let header = crate::sockets::message_header(c, a[1], false)?;
            let to = match header.name {
                Some((at, len)) => Some(address(&crate::inet::read_raw(c, at, len as u64)?)?),
                None => None,
            };
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            for &(base, len) in &header.iov {
                let start = bytes.len();
                bytes.resize(start + len, 0);
                c.mem
                    .read(GuestAddr(base), &mut bytes[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            send(socket, &bytes, a[2], to, sender)
        }
        45 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let mut bytes = vec![0; len];
            let (n, length, from, group) = receive(c, file, socket, &mut bytes, a[3])?;
            c.mem
                .write(GuestAddr(a[1]), &bytes[..n])
                .map_err(|_| Errno::EFAULT)?;
            if a[4] != 0 {
                let name = encode_address(from, group_mask(group));
                crate::inet::write_address(c, &name, a[4], a[5])?;
            }
            Ok(returned(n, length, a[3]))
        }
        47 => {
            let header = crate::sockets::message_header(c, a[1], true)?;
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(total, 0);
            let (n, length, from, group) = receive(c, file, socket, &mut bytes, a[2])?;
            crate::files::scatter(c, &header.iov, &bytes[..n])?;
            if header.has_name {
                let name = encode_address(from, group_mask(group));
                if let Some((at, room)) = header.name {
                    let n = room.min(name.len());
                    c.mem
                        .write(GuestAddr(at), &name[..n])
                        .map_err(|_| Errno::EFAULT)?;
                }
                c.mem
                    .write(GuestAddr(a[1] + 8), &(name.len() as u32).to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
            }
            let flags = if length > n { MSG_TRUNC as u32 } else { 0 };
            c.mem
                .write(GuestAddr(a[1] + 40), &0u64.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            c.mem
                .write(GuestAddr(a[1] + 48), &flags.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            Ok(returned(n, length, a[2]))
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// What a receive returns: with `MSG_TRUNC`, the datagram's whole length.
fn returned(n: usize, length: usize, flags: u64) -> u64 {
    (if flags & MSG_TRUNC != 0 { length } else { n }) as u64
}
fn send(
    socket: &NetlinkSocket,
    bytes: &[u8],
    flags: u64,
    to: Option<(u32, u32)>,
    sender: Sender,
) -> Result<u64, Errno> {
    if flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    socket.send(bytes, to, sender).map(|n| n as u64)
}
/// Receives for recvfrom or recvmsg, waiting unless `MSG_DONTWAIT` or the
/// socket's `O_NONBLOCK` says not to, no longer than `SO_RCVTIMEO`.
fn receive(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &NetlinkSocket,
    buf: &mut [u8],
    flags: u64,
) -> Result<(usize, usize, u32, u32), Errno> {
    if flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let dontwait = flags & MSG_DONTWAIT != 0 || socket.nonblocking();
    let timeout = socket.lock().receive_timeout;
    let wait = crate::sockets::wait_for(c, timeout)?;
    crate::files::wait_for_read_until(c, file, dontwait, wait, || {
        socket.receive(buf, flags & MSG_PEEK != 0)
    })
}
/// Reads the `int` of a setsockopt (`EINVAL` for fewer than 4 bytes).
fn option_int(c: &Context<'_>, at: u64, len: u64) -> Result<i32, Errno> {
    if (len as u32 as i32) < 4 {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    Ok(i32::from_le_bytes(raw))
}
/// `setsockopt`: `SO_SNDBUF` and `SO_RCVBUF` (doubled, as Linux keeps
/// them), `SO_RCVTIMEO`, and `SOL_NETLINK`'s `NETLINK_CAP_ACK`,
/// `NETLINK_EXT_ACK` and `NETLINK_GET_STRICT_CHK`, which are kept, though
/// no error carries extended attributes and dumps are not checked
/// strictly. Any other option is `ENOPROTOOPT`.
fn set_option(c: &mut Context<'_>, socket: &NetlinkSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len) = (a[1], a[2], a[3], a[4]);
    match (level, name) {
        (SOL_SOCKET, 20 | 66) => {
            if (len as u32 as i32) < 16 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 16];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let word = |i: usize| i64::from_le_bytes(raw[i..i + 8].try_into().unwrap_or_default());
            socket.lock().receive_timeout = Timeout::from_timeval(word(0), word(8))?;
        }
        (SOL_SOCKET, 7 | 8) => {
            let value = option_int(c, at, len)?.clamp(0, BUFFER_MAX);
            let mut s = socket.lock();
            if name == 7 {
                s.send_buffer = (value * 2).max(MIN_SEND_BUFFER);
            } else {
                s.receive_buffer = (value * 2).max(MIN_RECEIVE_BUFFER);
            }
        }
        (SOL_NETLINK, NETLINK_CAP_ACK | NETLINK_EXT_ACK | NETLINK_GET_STRICT_CHK) => {
            let on = option_int(c, at, len)? != 0;
            let mut s = socket.lock();
            match name {
                NETLINK_CAP_ACK => s.cap_ack = on,
                NETLINK_EXT_ACK => s.ext_ack = on,
                _ => s.strict = on,
            }
        }
        _ => return Err(ENOPROTOOPT),
    }
    Ok(0)
}
/// `getsockopt`: what [`set_option`] keeps, and `SO_TYPE`, `SO_ERROR`
/// (which takes the pending error), `SO_PROTOCOL` and `SO_DOMAIN`. Any
/// other option is `ENOPROTOOPT`.
fn get_option(c: &mut Context<'_>, socket: &NetlinkSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len_at) = (a[1], a[2], a[3], a[4]);
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let value: Vec<u8> = {
        let mut s = socket.lock();
        match (level, name) {
            (SOL_SOCKET, 20 | 66) => s.receive_timeout.timeval().to_vec(),
            (SOL_SOCKET, 3) => (socket.kind as i32).to_le_bytes().to_vec(),
            (SOL_SOCKET, 4) => s.error.take().map_or(0, |e| e.0).to_le_bytes().to_vec(),
            (SOL_SOCKET, 7) => s.send_buffer.to_le_bytes().to_vec(),
            (SOL_SOCKET, 8) => s.receive_buffer.to_le_bytes().to_vec(),
            (SOL_SOCKET, 38) => 0i32.to_le_bytes().to_vec(),
            (SOL_SOCKET, 39) => i32::from(AF_NETLINK).to_le_bytes().to_vec(),
            (SOL_NETLINK, NETLINK_CAP_ACK | NETLINK_EXT_ACK | NETLINK_GET_STRICT_CHK) => {
                // `netlink_getsockopt` wants room for an int.
                if room < 4 {
                    return Err(Errno::EINVAL);
                }
                let on = match name {
                    NETLINK_CAP_ACK => s.cap_ack,
                    NETLINK_EXT_ACK => s.ext_ack,
                    _ => s.strict,
                };
                i32::from(on).to_le_bytes().to_vec()
            }
            _ => return Err(ENOPROTOOPT),
        }
    };
    let n = room.min(value.len());
    c.mem
        .write(GuestAddr(at), &value[..n])
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(len_at), &(n as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_take_linux_layouts() {
        let network = Network::isolated(crate::users::first());
        // Down, a new namespace's loopback has no address.
        assert!(ipv4_message(&network, 1, 7).is_empty());
        assert!(ipv6_message(&network, 1, 7).is_empty());
        let link = link_message(&network, 1, 7, NLM_F_MULTI);
        assert_eq!(link.len() % 4, 0);
        let header = Header::read(&link);
        assert_eq!(
            (header.len as usize, header.kind, header.flags, header.seq),
            (link.len(), RTM_NEWLINK, NLM_F_MULTI, 1)
        );
        assert_eq!(&link[12..16], &7u32.to_le_bytes());
        assert_eq!(&link[24..28], &IFF_LOOPBACK.to_le_bytes());
        let found = attributes(&link[32..]);
        let get = |kind| found.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v);
        assert_eq!(get(IFLA_IFNAME), Some(&b"lo\0"[..]));
        assert_eq!(get(IFLA_OPERSTATE), Some(&[IF_OPER_DOWN][..]));
        assert_eq!(get(IFLA_QDISC), Some(&b"noop\0"[..]));
        assert_eq!(get(IFLA_STATS).map(<[u8]>::len), Some(STATS_LEN));
        // Up, it has both; down again, it keeps 127.0.0.1 alone.
        network.set_up(true);
        let v4 = ipv4_message(&network, 2, 7);
        assert_eq!(&v4[16..24], &[2, 8, 0x80, 254, 1, 0, 0, 0]);
        let v6 = ipv6_message(&network, 2, 7);
        assert_eq!(&v6[16..24], &[10, 128, 0x80, 254, 1, 0, 0, 0]);
        assert_eq!(
            attributes(&v6[24..])[0],
            (
                IFA_ADDRESS,
                &[0; 15].iter().chain(&[1]).copied().collect::<Vec<u8>>()[..]
            )
        );
        network.set_up(false);
        assert!(!ipv4_message(&network, 3, 7).is_empty());
        assert!(ipv6_message(&network, 3, 7).is_empty());
    }

    #[test]
    fn acknowledgements_carry_the_request() {
        let request = message(RTM_GETADDR, NLM_F_REQUEST | NLM_F_ACK, 9, 0, &[0]);
        let header = Header::read(&request);
        // `nlmsg_len` is the request's own, 17, not its padded length.
        let request = &request[..17];
        let ack = acknowledgement(request, &header, 5, 0, false);
        assert_eq!(ack.len(), 36);
        assert_eq!(&ack[4..8], &[2, 0, 0x00, 0x01]);
        assert_eq!(&ack[16..20], &0i32.to_le_bytes());
        let error = acknowledgement(request, &header, 5, 95, false);
        assert_eq!(error.len(), 40);
        assert_eq!(&error[6..8], &0u16.to_le_bytes());
        assert_eq!(&error[16..20], &(-95i32).to_le_bytes());
        assert_eq!(&error[20..37], request);
        assert_eq!(acknowledgement(request, &header, 5, 95, true).len(), 36);
    }

    #[test]
    fn attributes_stop_where_one_is_malformed() {
        let mut bytes = Vec::new();
        attribute(&mut bytes, IFLA_IFNAME | 0x8000, b"lo\0");
        attribute(&mut bytes, IFLA_MTU, &[0; 4]);
        bytes.extend_from_slice(&[40, 0, 1, 0]);
        let found = attributes(&bytes);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], (IFLA_IFNAME, &b"lo\0"[..]));
        assert_eq!(first_group(0b1100), 3);
        assert_eq!(group_mask(3), 0b100);
        assert_eq!(group_mask(0), 0);
    }
}
