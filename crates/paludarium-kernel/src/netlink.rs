//! `AF_NETLINK` sockets of `NETLINK_ROUTE`, in the network namespace each
//! was made in, whose loopback `lo` is its only interface, of
//! `NETLINK_GENERIC` ([`generic`]) and of `NETLINK_SOCK_DIAG` ([`diag`]),
//! each protocol with its own ports.
//!
//! As Linux's `af_netlink` and `rtnetlink`: a socket is bound to a port ID
//! (the process's ID, or a negative one when that is taken) by `bind`, or by
//! its first `connect` or send. The kernel takes each message of a datagram
//! sent to port 0 in turn: `RTM_GETLINK`, `RTM_GETADDR` and `RTM_GETROUTE`
//! dumps (`NLM_F_DUMP`) answer with the loopback, its addresses and its
//! routes, in parts as large as `netlink_dump` makes them, each receive
//! that leaves room sending the next, then `NLMSG_DONE` in a part of its
//! own (after the last IPv6 address, when it has room); `RTM_GETLINK` without a
//! dump answers for `lo` by index or name, and `RTM_GETROUTE` without one
//! looks a route up; `RTM_NEWADDR` and `RTM_DELADDR` add and remove the
//! loopback's addresses ([`crate::interface`]); `RTM_NEWLINK` and `RTM_SETLINK` bring it up or
//! down with `IFF_UP`, given `CAP_NET_ADMIN` in the user namespace that owns
//! the network namespace. An error, or a success the request asks for with
//! `NLM_F_ACK`, is answered with `NLMSG_ERROR`; any other request is
//! `EOPNOTSUPP`. A datagram to another socket's port reaches it, and the
//! members of a group hear of the changes to the link, addresses and
//! routes as Linux tells them.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::inet::Network;
use crate::sockets::Timeout;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

mod diag;
mod generic;
mod inet_diag;

const AF_NETLINK: u16 = 16;
const NETLINK_ROUTE: u32 = 0;
const NETLINK_SOCK_DIAG: u32 = 4;
const NETLINK_GENERIC: u32 = 16;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// Types below this are control messages, which the kernel does not handle.
const NLMSG_MIN_TYPE: u16 = 0x10;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_ECHO: u16 = 0x8;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
/// The groups (`RTNLGRP_*`) notifications go to, and how many there are
/// (`RTNLGRP_MAX`).
const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV4_ROUTE: u32 = 7;
const RTNLGRP_IPV6_IFADDR: u32 = 9;
const RTNLGRP_IPV6_ROUTE: u32 = 11;
const GROUPS: u32 = 39;
/// The bits of groups 30 and 31, the multicast routing ones of a full
/// routing daemon, which need `CAP_NET_ADMIN` (`rtnetlink_bind`).
const PRIVILEGED_GROUPS: u32 = 0x6000_0000;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const NETLINK_DROP_MEMBERSHIP: u64 = 2;
const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
/// `IFA_F_TENTATIVE`, which an IPv6 address has when first told of.
const IFA_F_TENTATIVE: u32 = 0x40;
/// The multicast routing families, whose dumps find no route.
const RTNL_FAMILY_IPMR: u8 = 128;
const RTNL_FAMILY_IP6MR: u8 = 129;
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_UID: u16 = 25;
/// `RTM_F_FIB_MATCH`: a lookup answers with the table's entry.
const RTM_F_FIB_MATCH: u32 = 0x2000;
/// `RTM_F_LOOKUP_TABLE`: a lookup's answer names the table it came from.
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;
/// The flags of a lookup's answer: `RTM_F_CLONED`, with `RTCF_LOCAL`, and
/// `RTCF_BROADCAST` for the broadcast address.
const RTM_F_CLONED: u32 = 0x200;
const RTCF_LOCAL: u32 = 0x8000_0000;
const RTCF_BROADCAST: u32 = 0x1000_0000;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_FLOW: u16 = 11;
const RTA_VIA: u16 = 18;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_NH_ID: u16 = 30;
/// `RTNH_F_ONLINK`.
const RTNH_F_ONLINK: u32 = 4;
/// A table past 255, as an `rtmsg` names it.
const RT_TABLE_COMPAT: u8 = 252;
/// The last route kind (`RTN_MAX`).
const RTN_MAX: u8 = 11;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_PREF: u16 = 20;
/// `RT_SCOPE_UNIVERSE`, the scope of every IPv6 route.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `struct rta_cacheinfo`: eight `__u32`s.
const RTA_CACHEINFO_LEN: usize = 32;
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
const IFLA_MAP: u16 = 14;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_STATS64: u16 = 23;
const IFLA_AF_SPEC: u16 = 26;
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
const IFLA_XDP: u16 = 43;
const IFLA_CARRIER_UP_COUNT: u16 = 47;
const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_DEVLINK_PORT: u16 = 62;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const IFLA_DPLL_PIN: u16 = 65;
const IFLA_MAX_PACING_OFFLOAD_HORIZON: u16 = 66;
const IFLA_NETNS_IMMUTABLE: u16 = 67;
const IFLA_HEADROOM: u16 = 68;
const IFLA_TAILROOM: u16 = 69;
/// The attributes inside `IFLA_XDP` and `IFLA_AF_SPEC`.
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_INET_CONF: u16 = 1;
const IFLA_MCTP_NET: u16 = 1;
const IFLA_MCTP_PHYS_BINDING: u16 = 2;
/// `AF_MCTP`, whose settings `IFLA_AF_SPEC` carries too.
const AF_MCTP: u16 = 45;
const IFLA_INET6_FLAGS: u16 = 1;
const IFLA_INET6_CONF: u16 = 2;
const IFLA_INET6_STATS: u16 = 3;
const IFLA_INET6_CACHEINFO: u16 = 5;
const IFLA_INET6_ICMP6STATS: u16 = 6;
const IFLA_INET6_TOKEN: u16 = 7;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
/// `IF_READY`: IPv6 is ready on a device that is up.
const IF_READY: u32 = 0x8000_0000;
/// The counters of IPv6's `IFLA_INET6_STATS` and `IFLA_INET6_ICMP6STATS`
/// (`__IPSTATS_MIB_MAX`, `__ICMP6_MIB_MAX`), the first of each their count.
const IPSTATS_MIB_MAX: u64 = 38;
const ICMP6_MIB_MAX: u64 = 7;
/// `NLA_F_NESTED`, which a nest made by `nla_nest_start` carries.
const NLA_F_NESTED: u16 = 0x8000;
/// `RTEXT_FILTER_SKIP_STATS`: a link message without statistics.
const RTEXT_FILTER_SKIP_STATS: u32 = 8;
/// `lo`'s largest TSO segment: Linux's `TSO_MAX_SIZE`, which a loopback
/// takes (`loopback_setup`).
const TSO_MAX_SIZE: u32 = 524_280;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_PROTO: u16 = 11;
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
const EBUSY: Errno = Errno(16);
const EEXIST: Errno = Errno(17);
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
const ENETUNREACH: Errno = Errno(101);
const ENOBUFS: Errno = Errno(105);
const ECONNREFUSED: Errno = Errno(111);
const EHOSTUNREACH: Errno = Errno(113);
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

/// The netlink sockets of a network namespace, one table for each protocol.
#[derive(Default)]
pub(crate) struct Ports {
    route: Table,
    diag: Table,
    generic: Table,
}
impl Ports {
    fn table(&self, protocol: u32) -> &Table {
        match protocol {
            NETLINK_GENERIC => &self.generic,
            NETLINK_SOCK_DIAG => &self.diag,
            _ => &self.route,
        }
    }
}

/// The port IDs bound in a network namespace for a protocol (its
/// `nl_table` entry's hash for it), and the next one an autobind tries
/// when the process's own is taken.
struct Table {
    bound: Mutex<BTreeMap<u32, Weak<NetlinkSocket>>>,
    rover: AtomicI32,
    /// Every netlink socket of the namespace, which a notification goes
    /// to when it is a member of the group.
    all: Mutex<Vec<Weak<NetlinkSocket>>>,
}
impl Default for Table {
    fn default() -> Self {
        Self {
            bound: Mutex::default(),
            rover: AtomicI32::new(-4097),
            all: Mutex::default(),
        }
    }
}
impl Table {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u32, Weak<NetlinkSocket>>> {
        self.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The sockets still open, the closed ones forgotten.
    fn members(&self) -> Vec<Arc<NetlinkSocket>> {
        let mut all = self.all.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|socket| socket.strong_count() > 0);
        all.iter().filter_map(Weak::upgrade).collect()
    }
}

/// A datagram waiting to be received: who sent it (0 for the kernel), and
/// the group it went to.
struct Datagram {
    from: u32,
    group: u32,
    bytes: Vec<u8>,
    /// What it takes of the receive buffer: its length, or a kernel
    /// buffer's `truesize` charged before it was queued.
    size: usize,
}

#[derive(Default)]
struct State {
    /// The port ID, once bound.
    port: Option<u32>,
    /// The multicast groups it is a member of, bit `g - 1` for group `g`.
    groups: u64,
    /// Where a send without an address goes (`connect`): a port and a group
    /// number, 0 for none.
    peer: (u32, u32),
    queue: VecDeque<Datagram>,
    /// The bytes waiting in `queue`.
    queued: usize,
    /// The `truesize` of kernel buffers charged to the receive buffer and
    /// not yet queued: `SIGEV_THREAD` cookies of POSIX message queues.
    charged: usize,
    /// A dump's `NLMSG_DONE`, which the next receive queues (Linux's
    /// `cb_running`).
    done: Option<Vec<u8>>,
    /// A dump's messages that have not gone yet, which each receive that
    /// leaves room sends on as much of as one part takes (`netlink_dump`).
    rest: VecDeque<Vec<u8>>,
    /// Whether `done` goes after the last of `rest` when its part has room
    /// for it, as it does after a dump callback that returns 0 when it is
    /// through, rather than in a part of its own.
    joined: bool,
    /// The longest buffer a receive has given, as much as one part of a
    /// dump may take (`max_recvmsg_len`).
    longest_read: usize,
    /// An error a receive gives before anything else (`sk_err`).
    error: Option<Errno>,
    /// Whether a message from the kernel found no room, which holds the
    /// socket congested until a receive empties its queue
    /// (`NETLINK_S_CONGESTED`): no other message nor `SIGEV_THREAD`
    /// cookie is taken till then.
    congested: bool,
    arrivals: u64,
    receive_buffer: i32,
    send_buffer: i32,
    receive_timeout: Timeout,
    cap_ack: bool,
    ext_ack: bool,
    strict: bool,
}

/// An `AF_NETLINK` socket of `NETLINK_ROUTE`, `NETLINK_SOCK_DIAG` or
/// `NETLINK_GENERIC`.
pub(crate) struct NetlinkSocket {
    this: Weak<NetlinkSocket>,
    kind: u32,
    protocol: u32,
    network: Arc<Network>,
    /// The network namespace it was made in, whose owner's
    /// `CAP_NET_ADMIN` changes the loopback.
    namespace: Arc<crate::namespaces::Namespace>,
    /// Whether whoever made it had that capability (the socket file's
    /// credentials, which Linux's `netlink_ns_capable` asks as well).
    opener_admin: bool,
    /// Whether whoever made it had `CAP_BPF` or `CAP_SYS_ADMIN` over the
    /// machine (`bpf_capable`), which a `write` asks.
    opener_bpf: bool,
    /// The process ID of whoever made it, which a `write` that binds it
    /// takes, and its user ID, which a route lookup a `write` sends names.
    opener_pid: u32,
    opener_uid: u32,
    /// The user namespace of whoever made it, which shows the owners
    /// `sock_diag` tells of (`sk_user_ns`), and the AF_UNIX sockets of its
    /// network namespace, which it lists.
    opener_user: crate::users::UserNs,
    unix: Arc<crate::unix::Names>,
    /// The host, whose clock times the sockets `sock_diag` tells of.
    host: Arc<dyn paludarium_host::Host>,
    hub: Arc<ReadinessHub>,
    flags: AtomicU32,
    inode: u64,
    mode: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    state: Mutex<State>,
}

/// Who sends: the process ID an autobind takes, whether it may administer
/// the network, and its user ID as its user namespace shows it, which a
/// route lookup names (`RTA_UID`).
#[derive(Clone, Copy)]
struct Sender {
    pid: u32,
    admin: bool,
    /// `CAP_BPF` or `CAP_SYS_ADMIN` over the machine (`bpf_capable`).
    bpf: bool,
    uid: u32,
}
const CAP_BPF: u64 = 1 << 39;
/// `bpf_capable`.
fn bpf_capable(credentials: &crate::credentials::Credentials) -> bool {
    credentials.capable(CAP_BPF) || credentials.capable(crate::credentials::CAP_SYS_ADMIN)
}

/// `socket(AF_NETLINK, type, protocol)`, as Linux's `netlink_create`:
/// `SOCK_RAW` or `SOCK_DGRAM` (`ESOCKTNOSUPPORT`), and only `NETLINK_ROUTE`,
/// `NETLINK_SOCK_DIAG` and `NETLINK_GENERIC` (`EPROTONOSUPPORT`). Without a
/// network there is none (`EAFNOSUPPORT`).
pub(crate) fn socket(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let kind = a[1] as u32;
    if a[1] > u64::from(u32::MAX) || kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 || kind & 0xf >= 11 {
        return Err(Errno::EINVAL);
    }
    let network = c.network().ok_or(EAFNOSUPPORT)?;
    if !matches!(kind & 0xf, SOCK_RAW | SOCK_DGRAM) {
        return Err(ESOCKTNOSUPPORT);
    }
    let protocol = a[2] as i32 as u32;
    if !matches!(
        protocol,
        NETLINK_ROUTE | NETLINK_SOCK_DIAG | NETLINK_GENERIC
    ) {
        return Err(EPROTONOSUPPORT);
    }
    let namespace = Arc::clone(&c.group.namespaces(c.tid).net);
    let credentials = &c.process.credentials;
    let opener_admin = credentials.capable_in(CAP_NET_ADMIN, namespace.owner());
    let socket = Arc::new_cyclic(|this| NetlinkSocket {
        this: Weak::clone(this),
        kind: kind & 0xf,
        protocol,
        network,
        namespace,
        opener_admin,
        opener_bpf: bpf_capable(credentials),
        opener_pid: c.pid_space().number(c.process.pid),
        opener_uid: c.shown_uid(credentials.uid),
        opener_user: credentials.user.clone(),
        unix: c.unix_names(),
        host: Arc::clone(c.shared_host),
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
    socket
        .table()
        .all
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Arc::downgrade(&socket));
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
    /// The sockets of its protocol in its network namespace.
    fn table(&self) -> &Table {
        self.network.netlink.table(self.protocol)
    }
    /// The groups its protocol has (`ngroups`).
    fn groups(&self) -> u32 {
        match self.protocol {
            NETLINK_GENERIC => generic::GROUPS,
            NETLINK_SOCK_DIAG => diag::GROUPS,
            _ => GROUPS,
        }
    }
    /// The groups of `mask` only `CAP_NET_ADMIN` may join: none of
    /// `NETLINK_GENERIC`'s or `NETLINK_SOCK_DIAG`'s.
    fn privileged(&self, mask: u64) -> bool {
        self.protocol == NETLINK_ROUTE && mask & u64::from(PRIVILEGED_GROUPS) != 0
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
            bpf: bpf_capable(&c.process.credentials),
            uid: c.shown_uid(c.process.credentials.uid),
        }
    }
    /// Binds to `port`, or with 0 to the process's ID or, that taken, the
    /// next free negative one (`netlink_autobind`).
    fn bind_port(&self, s: &mut State, port: u32, pid: u32) -> Result<(), Errno> {
        let ports = self.table();
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
    /// finds the receive buffer full, or the socket congested, is dropped
    /// (`netlink_overrun`), and the first such one gives `ENOBUFS` for the
    /// next receive and holds the socket congested until it is emptied.
    fn deliver(&self, s: &mut State, from: u32, group: u32, bytes: Vec<u8>) {
        self.offer(s, (from, group, bytes), true);
    }
    /// Queues a part of a dump, as `netlink_dump` does without looking at
    /// congestion: one that finds the receive buffer full is dropped, with
    /// `ENOBUFS` for the next receive.
    fn deliver_dump(&self, s: &mut State, bytes: Vec<u8>) {
        self.offer(s, (0, 0, bytes), false);
    }
    fn offer(&self, s: &mut State, (from, group, bytes): (u32, u32, Vec<u8>), overrun: bool) {
        let full = Self::full(s);
        if overrun && (full || s.congested) {
            if !s.congested {
                s.congested = true;
                s.error = Some(ENOBUFS);
            }
        } else if full {
            s.error = Some(ENOBUFS);
        } else {
            Self::push(s, from, group, bytes);
        }
        s.arrivals += 1;
        self.hub.changed();
    }
    /// Queues a datagram another socket sends, and says whether it did:
    /// one that finds the receive buffer full or the socket congested is
    /// left to its sender, which waits or gives `EAGAIN`, and changes
    /// nothing here (`netlink_attachskb` with a user socket).
    fn offer_from_user(&self, s: &mut State, from: u32, group: u32, bytes: &[u8]) -> bool {
        if Self::full(s) || s.congested {
            return false;
        }
        Self::push(s, from, group, bytes.to_vec());
        s.arrivals += 1;
        self.hub.changed();
        true
    }
    fn full(s: &State) -> bool {
        s.queued + s.charged >= usize::try_from(s.receive_buffer).unwrap_or(0)
    }
    fn push(s: &mut State, from: u32, group: u32, bytes: Vec<u8>) {
        let size = bytes.len();
        s.queued += size;
        s.queue.push_back(Datagram {
            from,
            group,
            bytes,
            size,
        });
    }
    /// Charges a kernel buffer of `truesize` bytes held for a later send to
    /// the receive buffer, as `netlink_attachskb` does when the socket holds
    /// nothing or has room for it and is not congested, and says whether it
    /// did; a caller that may wait waits until a receive makes room, and
    /// tries again.
    pub(crate) fn charge(&self, truesize: usize) -> bool {
        let mut s = self.lock();
        let held = s.queued + s.charged + truesize;
        if !s.congested
            && (held == truesize || held <= usize::try_from(s.receive_buffer).unwrap_or(0))
        {
            s.charged += truesize;
            true
        } else {
            false
        }
    }
    /// Gives back a charge that will not be sent (`netlink_detachskb`).
    pub(crate) fn uncharge(&self, truesize: usize) {
        let mut s = self.lock();
        s.charged = s.charged.saturating_sub(truesize);
        self.hub.changed();
    }
    /// Queues `bytes` from the kernel, charged before for `truesize`
    /// ([`Self::charge`]), as `netlink_sendskb` does with a POSIX message
    /// queue's `SIGEV_THREAD` cookie ([`crate::mqueue`]).
    pub(crate) fn attach(&self, bytes: Vec<u8>, truesize: usize) {
        let mut s = self.lock();
        s.charged = s.charged.saturating_sub(truesize);
        s.queued += truesize;
        s.queue.push_back(Datagram {
            from: 0,
            group: 0,
            bytes,
            size: truesize,
        });
        s.arrivals += 1;
        self.hub.changed();
    }
    /// `bind`, as Linux's `netlink_bind`: a `sockaddr_nl` (`EINVAL` for a
    /// shorter address or another family); a bound socket takes only its
    /// own port again (`EINVAL`), and a port another socket has is
    /// `EADDRINUSE`. Its groups replace the first 32 the socket is a member
    /// of; the multicast routing ones need `CAP_NET_ADMIN`
    /// (`rtnetlink_bind`, `EPERM`).
    fn bind(&self, raw: &[u8], sender: Sender) -> Result<u64, Errno> {
        let (port, groups) = address(raw)?;
        let mut s = self.lock();
        if let Some(own) = s.port
            && own != port
        {
            return Err(Errno::EINVAL);
        }
        if self.privileged(u64::from(groups)) && !sender.admin {
            return Err(Errno::EPERM);
        }
        if s.port.is_none() {
            self.bind_port(&mut s, port, sender.pid)?;
        }
        s.groups = (s.groups & !0xffff_ffff) | u64::from(groups);
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
            (s.port.unwrap_or(0), s.groups as u32)
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
                .table()
                .lock()
                .get(&to)
                .and_then(Weak::upgrade)
                .ok_or(ECONNREFUSED)?;
            let mut t = target.lock();
            // A socket connected elsewhere takes nothing from this one.
            if t.peer.0 != 0 && t.peer.0 != port {
                return Err(ECONNREFUSED);
            }
            // `netlink_attachskb` from a user socket: no room, or a
            // congested socket, is `EAGAIN` for the sender to wait on, and
            // only the kernel's own messages overrun a socket.
            if !target.offer_from_user(&mut t, port, group, bytes) {
                return Err(Errno::EAGAIN);
            }
            return Ok(bytes.len());
        }
        let mut notices = Vec::new();
        self.take(&mut s, bytes, port, sender, &mut notices);
        drop(s);
        notify(&self.network, notices, Some(self));
        Ok(bytes.len())
    }
    /// The kernel takes each message of a datagram from `port`, as Linux's
    /// `netlink_rcv_skb` does: it stops at one too short or longer than
    /// what is left; one that is no request, or a control message, is only
    /// acknowledged; an error, or any result with `NLM_F_ACK`, is answered
    /// with `NLMSG_ERROR`, but for a dump that began. What a request
    /// changes adds its notifications to `notices`, to go out once the
    /// socket is unlocked.
    fn take(
        &self,
        s: &mut State,
        mut bytes: &[u8],
        port: u32,
        sender: Sender,
        notices: &mut Vec<Notice>,
    ) {
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
                let mut told = Vec::new();
                let result = match self.protocol {
                    NETLINK_GENERIC => self.generic(s, &header, &message[16..], port),
                    NETLINK_SOCK_DIAG => self.diag(s, &header, &message[16..], port, sender),
                    _ => self.route(s, &header, &message[16..], port, sender, &mut told),
                };
                // This socket hears of what it changed as it happens, before
                // its acknowledgement; the others once it is unlocked.
                for notice in &told {
                    if s.groups & (1u64 << (notice.group - 1)) != 0 && port != notice.origin {
                        self.deliver(s, 0, notice.group, notice.bytes.clone());
                    }
                }
                notices.extend(told);
                result
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
        sender: Sender,
        notices: &mut Vec<Notice>,
    ) -> Result<bool, Errno> {
        if header.kind > RTM_MAX {
            return Err(EOPNOTSUPP);
        }
        let Some(&family) = payload.first() else {
            return Ok(false);
        };
        let get = (header.kind - NLMSG_MIN_TYPE) & 3 == 2;
        if !get && !sender.admin {
            return Err(Errno::EPERM);
        }
        if get && header.flags & NLM_F_DUMP != 0 {
            let messages = match (header.kind, family) {
                // `rtnl_bridge_getlink` has no bridge port to show.
                (RTM_GETLINK, AF_BRIDGE) => Vec::new(),
                (RTM_GETLINK, _) => vec![link_message(
                    &self.network,
                    header.seq,
                    port,
                    NLM_F_MULTI,
                    ext_mask(payload),
                )],
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
                // The multicast routing tables have no route.
                (RTM_GETROUTE, RTNL_FAMILY_IPMR | RTNL_FAMILY_IP6MR) => Vec::new(),
                (RTM_GETROUTE, _) => {
                    let mut messages = Vec::new();
                    if family != AF_INET6 {
                        messages.extend(ipv4_routes(&self.network, header.seq, port));
                    }
                    if family != AF_INET {
                        messages.extend(ipv6_routes(&self.network, header.seq, port));
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
            // `inet6_dump_ifaddr` alone, not split, puts `NLMSG_DONE` after
            // its last message when that part has room for it.
            let joined = header.kind == RTM_GETADDR && family == AF_INET6;
            self.start_dump_as(s, messages, done, joined);
            return Ok(true);
        }
        match header.kind {
            RTM_GETROUTE if matches!(family, AF_INET | AF_INET6) => {
                let reply = lookup(&self.network, payload, header.seq, port, sender.uid)?;
                self.deliver(s, 0, 0, reply);
                Ok(false)
            }
            RTM_NEWADDR | RTM_DELADDR if matches!(family, AF_INET | AF_INET6) => {
                let events = change_address(&self.network, header, payload)?;
                let echo = header.flags & NLM_F_ECHO != 0;
                let told = told(events, header.seq, port, echo, false);
                if echo {
                    // `nlmsg_notify`'s own copy of an IPv4 address's.
                    for notice in told.iter().filter(|n| n.origin == port && port != 0) {
                        self.deliver(s, 0, 0, notice.bytes.clone());
                    }
                }
                notices.extend(told);
                Ok(false)
            }
            RTM_NEWROUTE | RTM_DELROUTE if matches!(family, AF_INET | AF_INET6) => {
                let events = change_route(&self.network, header, payload)?;
                let echo = header.flags & NLM_F_ECHO != 0;
                let told = told(events, header.seq, port, echo, true);
                if echo {
                    for notice in told.iter().filter(|n| n.origin == port && port != 0) {
                        self.deliver(s, 0, 0, notice.bytes.clone());
                    }
                }
                notices.extend(told);
                Ok(false)
            }
            RTM_GETLINK => {
                self.find_link(payload, header, true)?;
                let reply = link_message(&self.network, header.seq, port, 0, ext_mask(payload));
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
                    notices.extend(link_change(&self.network, up));
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
        let got = self.next_datagram(&mut s, buf, peek);
        // `netlink_rcv_wake`, whatever the receive gave: an empty queue is
        // no longer congested.
        if s.congested && s.queue.is_empty() {
            s.congested = false;
            self.hub.changed();
        }
        got
    }
    /// [`Self::receive`] but for its wake.
    fn next_datagram(
        &self,
        s: &mut State,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, usize, u32, u32), Errno> {
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
            let size = first.size;
            s.queue.pop_front();
            s.queued -= size;
            // A `mq_notify` waiting for room looks again
            // (`netlink_rcv_wake`).
            self.hub.changed();
        }
        s.longest_read = s.longest_read.max(buf.len()).min(MOST_DUMP_PART);
        if s.queued <= usize::try_from(s.receive_buffer / 2).unwrap_or(0) {
            if !s.rest.is_empty() {
                let part = dump_part(s);
                self.deliver_dump(s, part);
            } else if let Some(done) = s.done.take() {
                self.deliver_dump(s, done);
            }
        }
        Ok(got)
    }
    /// Begins a dump of `messages`, as `netlink_dump_start`: the first
    /// part goes now, the rest as receives make room, then `done` in a
    /// part of its own, or `done` alone when there is nothing to dump.
    fn start_dump(&self, s: &mut State, messages: Vec<Vec<u8>>, done: Vec<u8>) {
        self.start_dump_as(s, messages, done, false);
    }
    /// [`Self::start_dump`], with `done` after the last message when
    /// `joined` and its part has room for it.
    fn start_dump_as(&self, s: &mut State, messages: Vec<Vec<u8>>, done: Vec<u8>, joined: bool) {
        if messages.is_empty() {
            self.deliver_dump(s, done);
            return;
        }
        s.rest = messages.into();
        s.done = Some(done);
        s.joined = joined;
        let part = dump_part(s);
        self.deliver_dump(s, part);
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
            let mut bound = self.network.netlink.table(self.protocol).lock();
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
            bpf: self.opener_bpf,
            uid: self.opener_uid,
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

/// The least and the most one part of a dump takes: a page's worth
/// (`NLMSG_GOODSIZE`) and 32 KiB, each less the `skb_shared_info` x86-64
/// Linux takes of it (`SKB_WITH_OVERHEAD`).
const LEAST_DUMP_PART: usize = 4096 - 320;
const MOST_DUMP_PART: usize = 32768 - 320;
/// The next part of a dump, as `netlink_dump` fills one: as many of the
/// messages left as its size takes, the longest receive's but no less than
/// a page's, and at least one; then, for a dump whose `NLMSG_DONE` is
/// joined to it, that, when it was the last and there is room left.
fn dump_part(s: &mut State) -> Vec<u8> {
    let room = s.longest_read.max(LEAST_DUMP_PART);
    let mut part = Vec::new();
    while let Some(next) = s.rest.front() {
        if !part.is_empty() && part.len() + next.len() > room {
            break;
        }
        part.extend(s.rest.pop_front().unwrap_or_default());
    }
    if s.joined
        && s.rest.is_empty()
        && let Some(done) = s.done.take_if(|done| part.len() + done.len() <= room)
    {
        part.extend(done);
    }
    part
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
/// The types of the attributes of `bytes`, for tests.
#[cfg(test)]
pub(crate) fn attribute_kinds(bytes: &[u8]) -> Vec<u16> {
    attributes(bytes)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect()
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
/// `RTM_NEWLINK` for `lo`, as `rtnl_fill_ifinfo` gives it, with its
/// attributes in Linux 7.0's order: its name, queue, state, MTU, queues,
/// segment sizes, carrier, hardware addresses, statistics (all zero, and
/// left out for `RTEXT_FILTER_SKIP_STATS` in `mask`), XDP, queueing
/// discipline, its IPv4 and IPv6 settings ([`af_spec`]), its map and empty
/// devlink and DPLL nests.
fn link_message(network: &Network, seq: u32, port: u32, flags: u16, mask: u32) -> Vec<u8> {
    let up = network.is_up();
    let stats = mask & RTEXT_FILTER_SKIP_STATS == 0;
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
    // A loopback may not move to another namespace.
    attribute(&mut body, IFLA_NETNS_IMMUTABLE, &[1]);
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
    attribute(&mut body, IFLA_GSO_IPV4_MAX_SIZE, &u32_of(GSO_MAX_SIZE));
    attribute(&mut body, IFLA_GRO_IPV4_MAX_SIZE, &u32_of(GSO_MAX_SIZE));
    attribute(&mut body, IFLA_TSO_MAX_SIZE, &u32_of(TSO_MAX_SIZE));
    attribute(&mut body, IFLA_TSO_MAX_SEGS, &u32_of(GSO_MAX_SEGS));
    attribute(&mut body, IFLA_MAX_PACING_OFFLOAD_HORIZON, &u32_of(0));
    attribute(&mut body, IFLA_NUM_RX_QUEUES, &u32_of(1));
    attribute(&mut body, IFLA_CARRIER, &[1]);
    attribute(&mut body, IFLA_CARRIER_CHANGES, &u32_of(0));
    attribute(&mut body, IFLA_CARRIER_UP_COUNT, &u32_of(0));
    attribute(&mut body, IFLA_CARRIER_DOWN_COUNT, &u32_of(0));
    attribute(&mut body, IFLA_HEADROOM, &0u16.to_le_bytes());
    attribute(&mut body, IFLA_TAILROOM, &0u16.to_le_bytes());
    attribute(&mut body, IFLA_PROTO_DOWN, &[0]);
    attribute(&mut body, IFLA_ADDRESS, &[0; 6]);
    attribute(&mut body, IFLA_BROADCAST, &[0; 6]);
    if stats {
        attribute(&mut body, IFLA_STATS64, &[0; STATS64_LEN]);
        attribute(&mut body, IFLA_STATS, &[0; STATS_LEN]);
    }
    let mut xdp = Vec::new();
    attribute(&mut xdp, IFLA_XDP_ATTACHED, &[0]);
    attribute(&mut body, IFLA_XDP, &xdp);
    // A device gets its queueing discipline when it first opens, and keeps
    // it when it goes down (`dev_activate`).
    let qdisc: &[u8] = if network.has_been_up() {
        b"noqueue\0"
    } else {
        b"noop\0"
    };
    attribute(&mut body, IFLA_QDISC, qdisc);
    attribute(&mut body, IFLA_AF_SPEC, &af_spec(up, stats));
    attribute(&mut body, IFLA_MAP, &[0; 32]);
    attribute(&mut body, IFLA_DEVLINK_PORT | NLA_F_NESTED, &[]);
    attribute(&mut body, IFLA_DPLL_PIN | NLA_F_NESTED, &[]);
    message(RTM_NEWLINK, flags, seq, port, &body)
}
/// `lo`'s `IFLA_AF_SPEC`, as `mctp_fill_link_af`, `inet_fill_link_af` and
/// `inet6_fill_link_af` give it. Its IPv4 and IPv6 settings are those of a kernel whose sysctls
/// are as built, a loopback's (no IPsec policy, no temporary addresses, no
/// duplicate address detection, its MTU), not the host's a new namespace
/// copies on Linux. IPv6 is ready while `lo` is up; its creation time is
/// 0, its reachable time the base 30 seconds, where Linux's is random; its
/// statistics are zero and left out without `stats`.
fn af_spec(up: bool, stats: bool) -> Vec<u8> {
    const INET: [i32; 33] = [
        0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10000, 1000,
        0, 0, 0, 0, 1,
    ];
    const INET6: [i32; 60] = [
        0, 64, 65536, 1, 1, 1, 1, -1, 4000, 1000, -1, 172_800, 86400, 3, 600, 16, 0, 1, 1, 1,
        60000, 0, 0, 0, 0, 0, 0, -1, 0, 0, 10000, 1000, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 3_600_000,
        0, 0, 1, 0, 0, 0, 0, 0, 1024, 0, 65535, -1, 1, 0, 0, 0,
    ];
    let words =
        |values: &[i32]| -> Vec<u8> { values.iter().flat_map(|v| v.to_le_bytes()).collect() };
    let counters = |count: u64| -> Vec<u8> {
        let mut raw = vec![0u8; 8 * count as usize];
        raw[..8].copy_from_slice(&count.to_le_bytes());
        raw
    };
    let mut inet = Vec::new();
    attribute(&mut inet, IFLA_INET_CONF, &words(&INET));
    let mut inet6 = Vec::new();
    let ready: u32 = if up { IF_READY } else { 0 };
    attribute(&mut inet6, IFLA_INET6_FLAGS, &ready.to_le_bytes());
    // `ifla_cacheinfo`: the largest reassembly, creation time, reachable
    // and retransmission times.
    attribute(
        &mut inet6,
        IFLA_INET6_CACHEINFO,
        &words(&[65535, 0, 30000, 1000]),
    );
    attribute(&mut inet6, IFLA_INET6_CONF, &words(&INET6));
    if stats {
        attribute(&mut inet6, IFLA_INET6_STATS, &counters(IPSTATS_MIB_MAX));
        attribute(&mut inet6, IFLA_INET6_ICMP6STATS, &counters(ICMP6_MIB_MAX));
    }
    attribute(&mut inet6, IFLA_INET6_TOKEN, &[0; 16]);
    attribute(&mut inet6, IFLA_INET6_ADDR_GEN_MODE, &[0]);
    // MCTP's, first, as a kernel built with it (Ubuntu's) gives: its
    // default network, 1, and no physical binding.
    let mut mctp = Vec::new();
    attribute(&mut mctp, IFLA_MCTP_NET, &1u32.to_le_bytes());
    attribute(&mut mctp, IFLA_MCTP_PHYS_BINDING, &[0]);
    let mut spec = Vec::new();
    attribute(&mut spec, AF_MCTP, &mctp);
    attribute(&mut spec, u16::from(AF_INET), &inet);
    attribute(&mut spec, u16::from(AF_INET6), &inet6);
    spec
}
/// The `IFLA_EXT_MASK` of a link request, past its `ifinfomsg`: 0 for
/// none, or for a dump that sends only a family byte.
fn ext_mask(payload: &[u8]) -> u32 {
    payload
        .get(16..)
        .map(attributes)
        .unwrap_or_default()
        .into_iter()
        .find(|(kind, _)| *kind == IFLA_EXT_MASK)
        .and_then(|(_, value)| value.first_chunk().copied())
        .map_or(0, u32::from_le_bytes)
}
/// `struct ifa_cacheinfo`: forever preferred and valid. The times it was
/// made and changed are given as 0.
fn cacheinfo() -> [u8; 16] {
    let mut raw = [0; 16];
    raw[..8].copy_from_slice(&[0xff; 8]);
    raw
}
/// `RTM_NEWADDR` for each IPv4 address of `lo`, in its order, as
/// `inet_fill_ifaddr` gives them.
fn ipv4_message(network: &Network, seq: u32, port: u32) -> Vec<Vec<u8>> {
    let addresses = network.addresses().v4.clone();
    addresses
        .iter()
        .map(|address| ipv4_address(address, RTM_NEWADDR, NLM_F_MULTI, seq, port))
        .collect()
}
/// An IPv4 address's message of `kind`, with `flags`.
fn ipv4_address(
    address: &crate::interface::V4,
    kind: u16,
    flags: u16,
    seq: u32,
    port: u32,
) -> Vec<u8> {
    {
        let mut body = vec![AF_INET, address.prefix, address.flags as u8, address.scope];
        body.extend_from_slice(&1u32.to_le_bytes());
        if !address.address.is_unspecified() {
            attribute(&mut body, IFA_ADDRESS, &address.address.octets());
        }
        if !address.local.is_unspecified() {
            attribute(&mut body, IFA_LOCAL, &address.local.octets());
        }
        if let Some(broadcast) = address.broadcast {
            attribute(&mut body, IFA_BROADCAST, &broadcast.octets());
        }
        if !address.label.is_empty() {
            let mut label = address.label.clone();
            label.push(0);
            attribute(&mut body, IFA_LABEL, &label);
        }
        if address.proto != 0 {
            attribute(&mut body, IFA_PROTO, &[address.proto]);
        }
        attribute(&mut body, IFA_FLAGS, &address.flags.to_le_bytes());
        attribute(&mut body, IFA_CACHEINFO, &cacheinfo());
        message(kind, flags, seq, port, &body)
    }
}
/// `RTM_NEWADDR` for each IPv6 address of `lo`, in its order, as
/// `inet6_fill_ifaddr` gives them.
fn ipv6_message(network: &Network, seq: u32, port: u32) -> Vec<Vec<u8>> {
    let addresses = network.addresses().v6.clone();
    addresses
        .iter()
        .map(|address| ipv6_address(address, false, RTM_NEWADDR, NLM_F_MULTI, seq, port))
        .collect()
}
/// An IPv6 address's message of `kind`, with `flags`, `tentative` or not.
fn ipv6_address(
    address: &crate::interface::V6,
    tentative: bool,
    kind: u16,
    flags: u16,
    seq: u32,
    port: u32,
) -> Vec<u8> {
    {
        let address_flags = address.flags | if tentative { IFA_F_TENTATIVE } else { 0 };
        let mut body = vec![
            AF_INET6,
            address.prefix,
            address_flags as u8,
            address.scope(),
        ];
        body.extend_from_slice(&1u32.to_le_bytes());
        attribute(&mut body, IFA_ADDRESS, &address.address.octets());
        attribute(&mut body, IFA_CACHEINFO, &cacheinfo());
        attribute(&mut body, IFA_FLAGS, &address_flags.to_le_bytes());
        if address.proto != 0 {
            attribute(&mut body, IFA_PROTO, &[address.proto]);
        }
        message(kind, flags, seq, port, &body)
    }
}
/// `RTM_NEWADDR` or `RTM_DELADDR` for `lo`, as `inet_rtm_newaddr`,
/// `inet_rtm_deladdr`, `inet6_rtm_newaddr` and `inet6_rtm_deladdr` take
/// them: `EINVAL` for a message shorter than an `ifaddrmsg`, an IPv4
/// prefix past 32 or an IPv6 one past 128, an IPv4 address without
/// `IFA_LOCAL` to add or an IPv6 one without `IFA_LOCAL` or `IFA_ADDRESS`;
/// `ENODEV` for another interface than index 1. An address added again is
/// `EEXIST`, unless `NLM_F_REPLACE` without `NLM_F_EXCL`, and one to
/// remove that `lo` has not `EADDRNOTAVAIL`. `IFA_LABEL`, `IFA_BROADCAST`,
/// `IFA_FLAGS` (of which `IFA_F_NOPREFIXROUTE` takes effect) and
/// `IFA_PROTO` are kept; lifetimes (`IFA_CACHEINFO`) and `IFA_RT_PRIORITY`
/// are not, and every address is permanent.
fn change_address(
    network: &Network,
    header: &Header,
    payload: &[u8],
) -> Result<Vec<crate::interface::Event>, Errno> {
    use core::net::{Ipv4Addr, Ipv6Addr};
    if payload.len() < 8 {
        return Err(Errno::EINVAL);
    }
    let (family, prefix, header_flags, scope) = (payload[0], payload[1], payload[2], payload[3]);
    let index = u32::from_le_bytes(payload[4..8].try_into().unwrap_or_default());
    let mut local = None;
    let mut address = None;
    let mut broadcast = None;
    let mut label = None;
    let mut flags = u32::from(header_flags);
    let mut proto = 0;
    for (kind, value) in attributes(&payload[8..]) {
        match kind {
            IFA_LOCAL => local = Some(value),
            IFA_ADDRESS => address = Some(value),
            IFA_BROADCAST => broadcast = Some(*value.first_chunk::<4>().ok_or(ERANGE)?),
            IFA_LABEL => {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                if end > 15 {
                    return Err(ERANGE);
                }
                label = Some(value[..end].to_vec());
            }
            IFA_FLAGS => flags = u32::from_le_bytes(*value.first_chunk().ok_or(ERANGE)?),
            IFA_PROTO => proto = *value.first().ok_or(ERANGE)?,
            _ => {}
        }
    }
    let add = header.kind == RTM_NEWADDR;
    let replace = header.flags & NLM_F_REPLACE != 0 && header.flags & NLM_F_EXCL == 0;
    let up = network.is_up();
    if family == AF_INET {
        let v4 = |value: Option<&[u8]>| -> Result<Option<Ipv4Addr>, Errno> {
            value
                .map(|v| {
                    v.first_chunk::<4>()
                        .map(|o| Ipv4Addr::from(*o))
                        .ok_or(ERANGE)
                })
                .transpose()
        };
        let (local, address) = (v4(local)?, v4(address)?);
        if add && (prefix > 32 || local.is_none()) {
            return Err(Errno::EINVAL);
        }
        if index != 1 {
            return Err(ENODEV);
        }
        if !add {
            return network
                .addresses()
                .del_v4(local, address, prefix, label.as_deref());
        }
        let local = local.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut new = crate::interface::V4::new(local, address.unwrap_or(local), prefix, scope);
        new.broadcast = broadcast.map(Ipv4Addr::from);
        new.flags = flags;
        new.proto = proto;
        if let Some(label) = label {
            new.label = label;
        }
        return network.addresses().add_v4(new, replace, up);
    }
    let ip = local
        .or(address)
        .map(|v| {
            v.first_chunk::<16>()
                .map(|o| Ipv6Addr::from(*o))
                .ok_or(ERANGE)
        })
        .transpose()?
        .ok_or(Errno::EINVAL)?;
    if prefix > 128 {
        return Err(Errno::EINVAL);
    }
    if index != 1 {
        return Err(ENODEV);
    }
    if !add {
        return network.addresses().del_v6(ip, prefix);
    }
    let mut new = crate::interface::V6::new(ip, prefix);
    new.flags = flags;
    new.proto = proto;
    network.addresses().add_v6(new, replace, up)
}
/// A table as an `rtmsg` holds it: one past 255 is `RT_TABLE_COMPAT`.
fn table_byte(table: u32) -> u8 {
    u8::try_from(table).unwrap_or(RT_TABLE_COMPAT)
}
/// `struct rta_cacheinfo` of a looked-up route, whose one reference is the
/// lookup's; Linux's counts more where other sockets use it.
fn lookup_cacheinfo() -> [u8; RTA_CACHEINFO_LEN] {
    let mut raw = [0; RTA_CACHEINFO_LEN];
    raw[0] = 1;
    raw
}
/// An IPv4 route as `fib_dump_info` gives it, as a message of `kind` with
/// `flags`, named in `table`: its own, or the main one a lookup names.
fn ipv4_route_of(
    kind: u16,
    route: &crate::interface::Route4,
    table: u32,
    seq: u32,
    port: u32,
    flags: u16,
) -> Vec<u8> {
    let mut body = vec![
        AF_INET,
        route.len,
        0,
        route.tos,
        table_byte(table),
        route.proto,
        route.scope,
        route.kind.code(),
    ];
    let nexthop: u32 = if route.onlink { RTNH_F_ONLINK } else { 0 };
    body.extend_from_slice(&nexthop.to_le_bytes());
    attribute(&mut body, RTA_TABLE, &table.to_le_bytes());
    if route.len != 0 {
        attribute(&mut body, RTA_DST, &route.dst.octets());
    }
    if route.priority != 0 {
        attribute(&mut body, RTA_PRIORITY, &route.priority.to_le_bytes());
    }
    if let Some(source) = route.prefsrc {
        attribute(&mut body, RTA_PREFSRC, &source.octets());
    }
    if let Some(gateway) = route.gateway {
        attribute(&mut body, RTA_GATEWAY, &gateway.octets());
    }
    if route.device {
        attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
    }
    message(kind, flags, seq, port, &body)
}
/// An IPv6 route as `rt6_fill_node` gives it (with an empty
/// `rta_cacheinfo`), as a message of `kind` with `flags`.
fn ipv6_route_of(
    kind: u16,
    route: &crate::interface::Route6,
    seq: u32,
    port: u32,
    flags: u16,
) -> Vec<u8> {
    let mut body = vec![
        AF_INET6,
        route.len,
        0,
        0,
        table_byte(route.table),
        route.proto,
        RT_SCOPE_UNIVERSE,
        route.kind.code(),
    ];
    body.extend_from_slice(&0u32.to_le_bytes());
    attribute(&mut body, RTA_TABLE, &route.table.to_le_bytes());
    if route.len != 0 {
        attribute(&mut body, RTA_DST, &route.dst.octets());
    }
    if let Some(source) = route.prefsrc {
        attribute(&mut body, RTA_PREFSRC, &source.octets());
    }
    attribute(&mut body, RTA_PRIORITY, &route.metric.to_le_bytes());
    attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
    attribute(&mut body, RTA_CACHEINFO, &[0; RTA_CACHEINFO_LEN]);
    attribute(&mut body, RTA_PREF, &[0]);
    message(kind, flags, seq, port, &body)
}
/// A route lookup (`RTM_GETROUTE` without a dump), as `inet_rtm_getroute`
/// and `inet6_rtm_getroute` answer one for the destination `RTA_DST` names
/// (none is `0.0.0.0` or `::`), by the routing tables
/// ([`crate::interface::Addresses::lookup4`] and `lookup6`): `EINVAL` for
/// a request shorter than an `rtmsg`; a destination shorter than its
/// family's address is `ERANGE` for IPv4 and `EINVAL` for IPv6, as their
/// attribute policies give, and a longer one counts as its first bytes;
/// `EOPNOTSUPP` for an input route (`RTA_IIF`), which is not supported;
/// a rejecting route's error, `ENETUNREACH` where no route goes, and for
/// IPv6 while `lo` is down. `0.0.0.0` goes to the loopback from
/// `127.0.0.1`. An `RTA_UID` it names (`ERANGE` when shorter than 4
/// bytes, for either family, as both policies take a `u32`) is the one an
/// IPv4 answer gives, as it is; `RTA_SRC`, `RTA_OIF` and the other
/// selectors are not looked at. An IPv4 answer names the main table but
/// with `RTM_F_LOOKUP_TABLE`, the table it came from (the main one for the
/// local one, whose trie it shares). With `RTM_F_FIB_MATCH` the answer is
/// the table's entry that matched, and `EHOSTUNREACH` for `0.0.0.0`, which
/// no entry is.
fn lookup(
    network: &Network,
    payload: &[u8],
    seq: u32,
    port: u32,
    uid: u32,
) -> Result<Vec<u8>, Errno> {
    use crate::interface::{Kind, TABLE_LOCAL, TABLE_MAIN};
    use core::net::{Ipv4Addr, Ipv6Addr};
    if payload.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let family = payload[0];
    let request_flags = u32::from_le_bytes(payload[8..12].try_into().unwrap_or_default());
    let mut dst = None;
    let mut asked_uid = None;
    for (kind, value) in attributes(&payload[12..]) {
        match kind {
            RTA_DST => dst = Some(value),
            RTA_IIF => return Err(EOPNOTSUPP),
            RTA_UID => asked_uid = Some(u32::from_le_bytes(*value.first_chunk().ok_or(ERANGE)?)),
            _ => {}
        }
    }
    let fib_match = request_flags & RTM_F_FIB_MATCH != 0;
    let addresses = network.addresses();
    if family == AF_INET6 {
        let mut address = [0u8; 16];
        if let Some(value) = dst {
            address = *value.first_chunk().ok_or(Errno::EINVAL)?;
        }
        let ip = Ipv6Addr::from(address);
        if !network.is_up() {
            return Err(ENETUNREACH);
        }
        let route = addresses.lookup6(ip)?;
        if fib_match {
            return Ok(ipv6_route_of(RTM_NEWROUTE, &route, seq, port, 0));
        }
        // `rt6_fill_node` of the route the lookup made, with the request's
        // source, unspecified, and the source it leaves from, then the
        // route's own preferred source again.
        let mut body = vec![
            AF_INET6,
            128,
            128,
            0,
            table_byte(route.table),
            route.proto,
            RT_SCOPE_UNIVERSE,
            route.kind.code(),
        ];
        body.extend_from_slice(&0u32.to_le_bytes());
        attribute(&mut body, RTA_TABLE, &route.table.to_le_bytes());
        attribute(&mut body, RTA_DST, &address);
        attribute(&mut body, RTA_SRC, &[0; 16]);
        if let Some(source) = addresses.source6(&route, ip) {
            attribute(&mut body, RTA_PREFSRC, &source.octets());
        }
        if let Some(source) = route.prefsrc {
            attribute(&mut body, RTA_PREFSRC, &source.octets());
        }
        attribute(&mut body, RTA_PRIORITY, &route.metric.to_le_bytes());
        attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
        attribute(&mut body, RTA_CACHEINFO, &lookup_cacheinfo());
        attribute(&mut body, RTA_PREF, &[0]);
        return Ok(message(RTM_NEWROUTE, 0, seq, port, &body));
    }
    let mut address = [0u8; 4];
    if let Some(value) = dst {
        address = *value.first_chunk().ok_or(ERANGE)?;
    }
    let ip = Ipv4Addr::from(address);
    let (kind, source, gateway, table) = if ip.is_unspecified() {
        if fib_match {
            return Err(EHOSTUNREACH);
        }
        (Kind::Local, Some(Ipv4Addr::LOCALHOST), None, TABLE_MAIN)
    } else {
        let route = addresses.lookup4(ip)?;
        let table = if request_flags & RTM_F_LOOKUP_TABLE == 0 || route.table == TABLE_LOCAL {
            TABLE_MAIN
        } else {
            route.table
        };
        if fib_match {
            return Ok(ipv4_route_of(RTM_NEWROUTE, &route, table, seq, port, 0));
        }
        let gateway = route.gateway.filter(|_| route.uses_gateway);
        (route.kind, addresses.source4(&route, ip), gateway, table)
    };
    // `rt_fill_info` of the cached route the lookup made, which is local as
    // it goes through `lo`.
    let flags = if kind == Kind::Broadcast {
        RTM_F_CLONED | RTCF_LOCAL | RTCF_BROADCAST
    } else {
        RTM_F_CLONED | RTCF_LOCAL
    };
    let mut body = vec![
        AF_INET,
        32,
        0,
        0,
        table_byte(table),
        0,
        RT_SCOPE_UNIVERSE,
        kind.code(),
    ];
    body.extend_from_slice(&flags.to_le_bytes());
    attribute(&mut body, RTA_TABLE, &table.to_le_bytes());
    attribute(&mut body, RTA_DST, &address);
    attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
    if let Some(source) = source {
        attribute(&mut body, RTA_PREFSRC, &source.octets());
    }
    if let Some(gateway) = gateway {
        attribute(&mut body, RTA_GATEWAY, &gateway.octets());
    }
    // An invalid user ID (-1) is left out (`uid_valid`).
    let uid = asked_uid.unwrap_or(uid);
    if uid != u32::MAX {
        attribute(&mut body, RTA_UID, &uid.to_le_bytes());
    }
    attribute(&mut body, RTA_CACHEINFO, &lookup_cacheinfo());
    Ok(message(RTM_NEWROUTE, 0, seq, port, &body))
}
/// The IPv4 routes of every table, as `fib_dump_info` gives them.
fn ipv4_routes(network: &Network, seq: u32, port: u32) -> Vec<Vec<u8>> {
    let routes = network.addresses().dump4();
    routes
        .iter()
        .map(|r| ipv4_route_of(RTM_NEWROUTE, r, r.table, seq, port, NLM_F_MULTI))
        .collect()
}
/// The IPv6 routes of every table, as `rt6_fill_node` gives them.
fn ipv6_routes(network: &Network, seq: u32, port: u32) -> Vec<Vec<u8>> {
    let routes = network.addresses().dump6();
    routes
        .iter()
        .map(|r| ipv6_route_of(RTM_NEWROUTE, r, seq, port, NLM_F_MULTI))
        .collect()
}
/// An `RTM_NEWROUTE` or `RTM_DELROUTE` request, as `inet_rtm_newroute`,
/// `inet_rtm_delroute`, `inet6_rtm_newroute` and `inet6_rtm_delroute`
/// take it ([`crate::interface::Addresses::add_route4`] and the others):
/// `EINVAL` for one shorter than an `rtmsg`; an attribute shorter than its
/// policy's is `ERANGE`, but an IPv6 destination shorter than its prefix,
/// `EINVAL`; then `EINVAL` for a TOS with ECN bits (any for IPv6) or a
/// kind past `RTN_MAX`. Multipath routes, metrics, encapsulations,
/// nexthop objects, realms, expiries, IPv6 gateways, source prefixes and
/// router preferences are `EOPNOTSUPP`. The table is the `rtmsg`'s, or the
/// one `RTA_TABLE` names.
fn change_route(
    network: &Network,
    header: &Header,
    payload: &[u8],
) -> Result<Vec<crate::interface::Event>, Errno> {
    use crate::interface::{Ask4, Ask6, Select4};
    use core::net::{Ipv4Addr, Ipv6Addr};
    if payload.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let (family, dst_len, src_len, tos) = (payload[0], payload[1], payload[2], payload[3]);
    let (proto, scope, kind) = (payload[5], payload[6], payload[7]);
    let flags = u32::from_le_bytes(payload[8..12].try_into().unwrap_or_default());
    let v6 = family == AF_INET6;
    let size = if v6 { 16 } else { 4 };
    let mut table = u32::from(payload[4]);
    let mut dst = None;
    let mut prefsrc = None;
    let mut gateway = None;
    let mut oif = 0;
    let mut priority = 0;
    let mut unsupported = src_len != 0 && v6;
    let number = |value: &[u8]| -> Result<u32, Errno> {
        Ok(u32::from_le_bytes(*value.first_chunk().ok_or(ERANGE)?))
    };
    let address = |value: &[u8]| -> Result<Vec<u8>, Errno> {
        value.get(..size).map(<[u8]>::to_vec).ok_or(ERANGE)
    };
    for (attr, value) in attributes(&payload[12..]) {
        match attr {
            RTA_DST if v6 => {
                let bytes = usize::from(dst_len).div_ceil(8);
                let mut raw = [0u8; 16];
                raw[..bytes.min(16)]
                    .copy_from_slice(value.get(..bytes.min(16)).ok_or(Errno::EINVAL)?);
                if value.len() < bytes {
                    return Err(Errno::EINVAL);
                }
                dst = Some(raw.to_vec());
            }
            RTA_DST => dst = Some(address(value)?),
            RTA_PREFSRC => prefsrc = Some(address(value)?),
            RTA_GATEWAY => {
                let raw = address(value)?;
                unsupported |= v6;
                gateway = Some(raw);
            }
            RTA_OIF => oif = number(value)?,
            RTA_PRIORITY => priority = number(value)?,
            RTA_TABLE => table = number(value)?,
            RTA_PREF if v6 => unsupported |= value.first().is_some_and(|&p| p == 1 || p == 3),
            RTA_METRICS | RTA_MULTIPATH | RTA_FLOW | RTA_VIA | RTA_ENCAP | RTA_EXPIRES
            | RTA_NH_ID => unsupported = true,
            _ => {}
        }
    }
    let add = header.kind == RTM_NEWROUTE;
    if (v6 && tos != 0) || (!v6 && tos & 0x3 != 0) || (kind > RTN_MAX && (add || !v6)) {
        return Err(Errno::EINVAL);
    }
    if unsupported {
        return Err(EOPNOTSUPP);
    }
    let up = network.is_up();
    let mut addresses = network.addresses();
    if v6 {
        let ip = |raw: Option<Vec<u8>>| {
            raw.map(|r| Ipv6Addr::from(<[u8; 16]>::try_from(r).unwrap_or_default()))
        };
        let ask = Ask6 {
            table,
            dst: ip(dst).unwrap_or(Ipv6Addr::UNSPECIFIED),
            len: dst_len,
            kind,
            proto,
            metric: priority,
            prefsrc: ip(prefsrc),
            oif,
            request: header.flags,
        };
        return if add {
            addresses.add_route6(&ask, up)
        } else {
            addresses.del_route6(&ask)
        };
    }
    let ip = |raw: Option<Vec<u8>>| {
        raw.map(|r| Ipv4Addr::from(<[u8; 4]>::try_from(r).unwrap_or_default()))
    };
    let (dst, prefsrc) = (ip(dst).unwrap_or(Ipv4Addr::UNSPECIFIED), ip(prefsrc));
    let gateway = ip(gateway).filter(|g| !g.is_unspecified());
    if add {
        return addresses.add_route4(
            &Ask4 {
                table,
                dst,
                len: dst_len,
                tos,
                priority,
                kind,
                proto,
                scope,
                prefsrc,
                gateway,
                oif,
                flags,
                request: header.flags,
            },
            up,
        );
    }
    addresses.del_route4(&Select4 {
        table,
        dst,
        len: dst_len,
        tos,
        priority,
        kind,
        proto,
        scope,
        prefsrc,
        gateway,
        oif,
    })
}
/// A notification for the members of `group`, which goes to every one of
/// them but the socket whose port is `origin` (`do_one_broadcast`): 0, so
/// no unbound socket, or the port of a request with `NLM_F_ECHO`, which
/// has its own copy instead (`nlmsg_notify`).
pub(crate) struct Notice {
    group: u32,
    origin: u32,
    bytes: Vec<u8>,
}
/// The notifications of `events`, as `rtmsg_ifa`, `inet6_ifa_notify`,
/// `rtmsg_fib` and `inet6_rt_notify` make them. An IPv4 address's carries
/// the request's `seq` and `port`, and with `echo` (`NLM_F_ECHO`) goes to
/// the requester alone of the members at `port`; so does a route's of a
/// route request (`routes`); the rest carry none.
fn told(
    events: Vec<crate::interface::Event>,
    seq: u32,
    port: u32,
    echo: bool,
    routes: bool,
) -> Vec<Notice> {
    use crate::interface::Event;
    let origin = if echo { port } else { 0 };
    let (route_seq, route_port, route_origin) = if routes {
        (seq, port, origin)
    } else {
        (0, 0, 0)
    };
    events
        .into_iter()
        .map(|event| {
            let (group, origin, bytes) = match event {
                Event::NewAddr4(a) => (
                    RTNLGRP_IPV4_IFADDR,
                    origin,
                    ipv4_address(&a, RTM_NEWADDR, 0, seq, port),
                ),
                Event::DelAddr4(a) => (
                    RTNLGRP_IPV4_IFADDR,
                    origin,
                    ipv4_address(&a, RTM_DELADDR, 0, seq, port),
                ),
                Event::NewRoute4(r, flags) => (
                    RTNLGRP_IPV4_ROUTE,
                    route_origin,
                    ipv4_route_of(RTM_NEWROUTE, &r, r.table, route_seq, route_port, flags),
                ),
                Event::DelRoute4(r) => (
                    RTNLGRP_IPV4_ROUTE,
                    route_origin,
                    ipv4_route_of(RTM_DELROUTE, &r, r.table, route_seq, route_port, 0),
                ),
                Event::NewAddr6(a, tentative) => (
                    RTNLGRP_IPV6_IFADDR,
                    0,
                    ipv6_address(&a, tentative, RTM_NEWADDR, 0, 0, 0),
                ),
                Event::DelAddr6(a) => (
                    RTNLGRP_IPV6_IFADDR,
                    0,
                    ipv6_address(&a, false, RTM_DELADDR, 0, 0, 0),
                ),
                Event::NewRoute6(r, flags) => (
                    RTNLGRP_IPV6_ROUTE,
                    route_origin,
                    ipv6_route_of(RTM_NEWROUTE, &r, route_seq, route_port, flags),
                ),
                Event::DelRoute6(r) => (
                    RTNLGRP_IPV6_ROUTE,
                    route_origin,
                    ipv6_route_of(RTM_DELROUTE, &r, route_seq, route_port, 0),
                ),
            };
            Notice {
                group,
                origin,
                bytes,
            }
        })
        .collect()
}
/// Brings `network`'s loopback up or down: `None` when it already is, else
/// the notifications of it, `lo`'s `RTM_NEWLINK` with `IFF_UP` changed
/// first (`rtmsg_ifinfo`), then what happens to its addresses and routes.
fn link_change(network: &Network, up: bool) -> Vec<Notice> {
    let Some(events) = network.set_up(up) else {
        return Vec::new();
    };
    let mut link = link_message(network, 0, 0, 0, 0);
    link[28..32].copy_from_slice(&IFF_UP.to_le_bytes());
    let mut notices = vec![Notice {
        group: RTNLGRP_LINK,
        origin: 0,
        bytes: link,
    }];
    notices.extend(told(events, 0, 0, false, false));
    notices
}
/// Brings `network`'s loopback up or down, as `SIOCSIFFLAGS` does, and
/// tells netlink's members of it.
pub(crate) fn set_up(network: &Network, up: bool) {
    let notices = link_change(network, up);
    notify(network, notices, None);
}
/// Sends each notification to the namespace's sockets that are members of
/// its group, each its own datagram, as `netlink_broadcast` does; a socket
/// whose receive buffer is full loses it, with `ENOBUFS` for its next
/// receive. No socket is locked but the one it goes to, nor `except`,
/// which has had them already.
fn notify(network: &Network, notices: Vec<Notice>, except: Option<&NetlinkSocket>) {
    if notices.is_empty() {
        return;
    }
    let members = network.netlink.route.members();
    for notice in notices {
        let bit = 1u64 << (notice.group - 1);
        for socket in &members {
            if except.is_some_and(|except| core::ptr::eq(except, Arc::as_ptr(socket))) {
                continue;
            }
            let mut s = socket.lock();
            if s.groups & bit != 0 && s.port.unwrap_or(0) != notice.origin {
                socket.deliver(&mut s, 0, notice.group, notice.bytes.clone());
            }
        }
    }
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
            send(c, socket, &bytes, a[3], to, sender)
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
            send(c, socket, &bytes, a[2], to, sender)
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
/// Sends for sendto or sendmsg; a datagram to another socket that has no
/// room for it waits unless `MSG_DONTWAIT` or the socket's `O_NONBLOCK` says
/// not to (`EAGAIN`), as `netlink_unicast` does with the send timeout,
/// which is not limited here.
fn send(
    c: &mut Context<'_>,
    socket: &NetlinkSocket,
    bytes: &[u8],
    flags: u64,
    to: Option<(u32, u32)>,
    sender: Sender,
) -> Result<u64, Errno> {
    if flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let dontwait = flags & MSG_DONTWAIT != 0 || socket.nonblocking();
    loop {
        let ticket = c.files.readiness.token.value();
        match socket.send(bytes, to, sender) {
            Err(Errno::EAGAIN) if !dontwait => crate::events::wait(c, ticket, None)?,
            sent => return sent.map(|n| n as u64),
        }
    }
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
        (SOL_NETLINK, NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP) => {
            // `netlink_setsockopt`: a group past `RTNLGRP_MAX`, or 0, is
            // `EINVAL`, and joining a multicast routing one needs
            // `CAP_NET_ADMIN` (`rtnetlink_bind`).
            let group = option_int(c, at, len)? as u32;
            if group == 0 || group > socket.groups() {
                return Err(Errno::EINVAL);
            }
            let bit = 1u64 << (group - 1);
            if name == NETLINK_ADD_MEMBERSHIP {
                if socket.privileged(bit) && !socket.sender(c).admin {
                    return Err(Errno::EPERM);
                }
                socket.lock().groups |= bit;
            } else {
                socket.lock().groups &= !bit;
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
    if (level, name) == (SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS) {
        // Each whole word that has room, and the length of them all.
        let words = socket.lock().groups.to_le_bytes();
        let all = (socket.groups() as usize).div_ceil(32) * 4;
        let n = room / 4 * 4;
        c.mem
            .write(GuestAddr(at), &words[..n.min(all)])
            .map_err(|_| Errno::EFAULT)?;
        c.mem
            .write(GuestAddr(len_at), &(all as u32).to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
        return Ok(0);
    }
    let value: Vec<u8> = {
        let mut s = socket.lock();
        match (level, name) {
            (SOL_SOCKET, 20 | 66) => s.receive_timeout.timeval().to_vec(),
            (SOL_SOCKET, 3) => (socket.kind as i32).to_le_bytes().to_vec(),
            (SOL_SOCKET, 4) => s.error.take().map_or(0, |e| e.0).to_le_bytes().to_vec(),
            (SOL_SOCKET, 7) => s.send_buffer.to_le_bytes().to_vec(),
            (SOL_SOCKET, 8) => s.receive_buffer.to_le_bytes().to_vec(),
            (SOL_SOCKET, 38) => (socket.protocol as i32).to_le_bytes().to_vec(),
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
    fn dumps_go_in_parts_as_large_as_the_longest_receive() {
        let mut s = State {
            rest: (0..12).map(|_| vec![0; 1000]).collect(),
            ..State::default()
        };
        // A page's worth first, then what the longest receive takes.
        assert_eq!(dump_part(&mut s).len(), 3000);
        s.longest_read = 8000;
        assert_eq!(dump_part(&mut s).len(), 8000);
        assert_eq!(dump_part(&mut s).len(), 1000);
        // One too long for a part still goes, alone.
        s.rest = vec![vec![0; 5000], vec![0; 10]].into();
        s.longest_read = 0;
        assert_eq!(dump_part(&mut s).len(), 5000);
        assert_eq!(dump_part(&mut s).len(), 10);
        assert!(s.rest.is_empty());
    }
    #[test]
    fn a_joined_done_follows_the_last_message_when_there_is_room() {
        let done = message(NLMSG_DONE, NLM_F_MULTI, 1, 7, &0i32.to_le_bytes());
        let mut s = State {
            rest: (0..4).map(|_| vec![0; 1000]).collect(),
            done: Some(done.clone()),
            joined: true,
            ..State::default()
        };
        assert_eq!(dump_part(&mut s).len(), 3000);
        assert_eq!(dump_part(&mut s).len(), 1000 + done.len());
        assert!(s.done.is_none());
        // With no room left after the last, it waits for a part of its own.
        s.rest = (0..3).map(|_| vec![0; 1255]).collect();
        s.done = Some(done.clone());
        assert_eq!(dump_part(&mut s).len(), 3 * 1255);
        assert_eq!(s.done, Some(done.clone()));
        // Not joined, it never goes with the messages.
        s.rest = vec![vec![0; 10]].into();
        s.joined = false;
        assert_eq!(dump_part(&mut s).len(), 10);
        assert_eq!(s.done, Some(done));
    }
    const RT_TABLE_LOCAL: u8 = 255;
    const RTPROT_KERNEL: u8 = 2;
    const RT_SCOPE_LINK: u8 = 253;
    const RT_SCOPE_HOST: u8 = 254;
    const RTN_LOCAL: u8 = 2;
    const RTN_BROADCAST: u8 = 3;

    #[test]
    fn messages_take_linux_layouts() {
        let network = Network::isolated(crate::users::first());
        // Down, a new namespace's loopback has no address.
        assert!(ipv4_message(&network, 1, 7).is_empty());
        assert!(ipv6_message(&network, 1, 7).is_empty());
        let link = link_message(&network, 1, 7, NLM_F_MULTI, 0);
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
        assert_eq!(get(IFLA_NETNS_IMMUTABLE), Some(&[1][..]));
        assert_eq!(get(IFLA_MAP).map(<[u8]>::len), Some(32));
        // IFLA_AF_SPEC: MCTP's, IPv4's 33 settings, then IPv6's, not yet
        // ready.
        let spec = attributes(get(IFLA_AF_SPEC).unwrap());
        assert_eq!(
            spec.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [45, 2, 10]
        );
        assert_eq!(attributes(spec[1].1)[0].1.len(), 33 * 4);
        let inet6 = attributes(spec[2].1);
        assert_eq!(inet6[0], (IFLA_INET6_FLAGS, &[0u8; 4][..]));
        assert_eq!(
            inet6.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [1, 5, 2, 3, 6, 7, 8]
        );
        // RTEXT_FILTER_SKIP_STATS leaves every statistic out.
        let short = link_message(&network, 1, 7, 0, RTEXT_FILTER_SKIP_STATS);
        let found = attributes(&short[32..]);
        assert!(
            !found
                .iter()
                .any(|(k, _)| *k == IFLA_STATS || *k == IFLA_STATS64)
        );
        let spec = found.iter().find(|(k, _)| *k == IFLA_AF_SPEC).unwrap().1;
        let inet6 = attributes(attributes(spec)[2].1);
        assert_eq!(
            inet6.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [1, 5, 2, 7, 8]
        );
        // Up, it has both; down again, it keeps 127.0.0.1 alone.
        network.set_up(true);
        let v4 = ipv4_message(&network, 2, 7).concat();
        assert_eq!(&v4[16..24], &[2, 8, 0x80, 254, 1, 0, 0, 0]);
        let v6 = ipv6_message(&network, 2, 7).concat();
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
    fn routes_follow_the_loopback_and_its_address() {
        let network = Network::isolated(crate::users::first());
        // None before the loopback has been up.
        assert!(ipv4_routes(&network, 1, 7).is_empty());
        assert!(ipv6_routes(&network, 1, 7).is_empty());
        // Up: local 127.0.0.0/8, local 127.0.0.1 and the broadcast route,
        // then local ::1, each in the local table.
        network.set_up(true);
        let v4 = ipv4_routes(&network, 2, 7).concat();
        let mut rest = &v4[..];
        let mut seen = Vec::new();
        while !rest.is_empty() {
            let header = Header::read(rest);
            assert_eq!(
                (header.kind, header.flags, header.seq),
                (RTM_NEWROUTE, NLM_F_MULTI, 2)
            );
            let len = header.len as usize;
            let found = attributes(&rest[28..len]);
            assert_eq!(
                found.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                [RTA_TABLE, RTA_DST, RTA_PREFSRC, RTA_OIF]
            );
            seen.push((rest[17], rest[22], rest[23], found[1].1.to_vec()));
            assert_eq!(&rest[16..17], &[AF_INET]);
            assert_eq!(&rest[20..22], &[RT_TABLE_LOCAL, RTPROT_KERNEL]);
            rest = &rest[len..];
        }
        assert_eq!(
            seen,
            [
                (8, RT_SCOPE_HOST, RTN_LOCAL, vec![127, 0, 0, 0]),
                (32, RT_SCOPE_HOST, RTN_LOCAL, vec![127, 0, 0, 1]),
                (32, RT_SCOPE_LINK, RTN_BROADCAST, vec![127, 255, 255, 255]),
            ]
        );
        let v6 = ipv6_routes(&network, 2, 7).concat();
        assert_eq!(
            &v6[16..24],
            &[
                AF_INET6,
                128,
                0,
                0,
                RT_TABLE_LOCAL,
                RTPROT_KERNEL,
                0,
                RTN_LOCAL
            ]
        );
        assert_eq!(
            attributes(&v6[28..])
                .iter()
                .map(|(kind, _)| *kind)
                .collect::<Vec<_>>(),
            [
                RTA_TABLE,
                RTA_DST,
                RTA_PRIORITY,
                RTA_OIF,
                RTA_CACHEINFO,
                RTA_PREF
            ]
        );
        // Down: the two local routes stay, as Linux keeps them.
        network.set_up(false);
        assert_eq!(ipv4_routes(&network, 3, 7).concat().len(), 2 * 60);
        assert!(ipv6_routes(&network, 3, 7).is_empty());
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
