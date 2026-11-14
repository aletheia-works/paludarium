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
//! own (after the last IPv6 address or link, when it has room); an AF_INET6
//! `RTM_GETLINK` dump shows the loopback as IPv6 does, and an
//! `RTNL_FAMILY_IPMR` one the IPv4 multicast routing table, and AF_MCTP
//! ones the loopback's MCTP addresses and the MCTP routes; `RTM_GETLINK`
//! without a dump answers for `lo` by index or name, an AF_INET6
//! `RTM_GETADDR` without one with an address of it, and `RTM_GETROUTE`
//! without one looks a route up; `RTM_NEWADDR` and `RTM_DELADDR` add and
//! remove the loopback's IPv4, IPv6 and MCTP addresses, and
//! `RTM_NEWROUTE` and `RTM_DELROUTE` IPv4, IPv6 and MCTP routes
//! ([`crate::interface`]); `RTM_NEWLINK`
//! and `RTM_SETLINK` bring it up or down with `IFF_UP`, given
//! `CAP_NET_ADMIN` in the user namespace that owns the network namespace.
//! An error, or a success the request asks for with `NLM_F_ACK`, is
//! answered with `NLMSG_ERROR`; any other request is `EOPNOTSUPP`. Each
//! request's attributes are checked against its policy first, as Linux's
//! `ifla_policy`, `ifa_ipv4_policy` and the others are ([`parse_policy`]). A
//! socket with `NETLINK_GET_STRICT_CHK` has its dumps, link requests and
//! route lookups checked as Linux checks them strictly, and its dumps
//! narrowed as they ask. A datagram to another socket's port reaches it,
//! and the members of a group hear of the changes to the link, addresses
//! and routes as Linux tells them.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::inet::Network;
use crate::interface::MctpRoute;
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
const RTNLGRP_IPV6_IFINFO: u32 = 12;
const RTNLGRP_MCTP_IFADDR: u32 = 34;
/// `RTN_LOCAL`, the type of an MCTP address's own route.
const RTN_LOCAL: u8 = 2;
/// `RTAX_MTU` in `RTA_METRICS`, and the last metric (`RTAX_MAX`,
/// `RTAX_FASTOPEN_NO_COOKIE`).
const RTAX_MTU: u16 = 2;
const RTAX_MAX: u16 = 17;
/// The other metrics `ip_metrics_convert` looks at: `RTAX_LOCK`,
/// `RTAX_CWND`, `RTAX_ADVMSS`, `RTAX_HOPLIMIT`, `RTAX_FEATURES` and
/// `RTAX_CC_ALGO`, and the features a request may set
/// (`RTAX_FEATURE_MASK`).
const RTAX_LOCK: u16 = 1;
const RTAX_CWND: u16 = 7;
const RTAX_ADVMSS: u16 = 8;
const RTAX_HOPLIMIT: u16 = 10;
const RTAX_FEATURES: u16 = 12;
const RTAX_CC_ALGO: u16 = 16;
const RTAX_FEATURE_MASK: u32 = 0x1f;
/// The congestion controls a route may name (`RTAX_CC_ALGO`), by their
/// keys: those built into Linux, `cubic`, the one sockets use, and
/// `reno`, which is always there.
const CONGESTION_CONTROLS: [(u32, &[u8]); 2] = [(1, b"cubic"), (2, b"reno")];
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
/// The attributes of an IPv4 multicast routing table (`IPMRA_TABLE_*`), in
/// an `RTNL_FAMILY_IPMR` link dump's `IFLA_AF_SPEC`.
const IPMRA_TABLE_ID: u16 = 1;
const IPMRA_TABLE_CACHE_RES_QUEUE_LEN: u16 = 2;
const IPMRA_TABLE_MROUTE_REG_VIF_NUM: u16 = 3;
const IPMRA_TABLE_MROUTE_DO_ASSERT: u16 = 4;
const IPMRA_TABLE_MROUTE_DO_PIM: u16 = 5;
const IPMRA_TABLE_VIFS: u16 = 6;
const IPMRA_TABLE_MROUTE_DO_WRVIFWHOLE: u16 = 7;
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
/// The mark `RTM_F_NOTIFY` leaves on a looked-up route.
const RTCF_NOTIFY: u32 = 0x0001_0000;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_FLOW: u16 = 11;
const RTA_VIA: u16 = 18;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_NH_ID: u16 = 30;
/// What a strict route lookup may name besides `RTA_SRC`, `RTA_DST`,
/// `RTA_IIF`, `RTA_OIF` and `RTA_UID`.
const RTA_MARK: u16 = 16;
const RTA_IP_PROTO: u16 = 27;
const RTA_SPORT: u16 = 28;
const RTA_DPORT: u16 = 29;
const RTA_FLOWLABEL: u16 = 31;
/// The last route attribute (`RTA_MAX`, `RTA_DEL_REASON` on Linux master),
/// past which strict checking takes none.
const RTA_MAX: u16 = 32;
/// `RTM_F_NOTIFY`, which a strict IPv4 lookup may ask, and `RTM_F_PREFIX`,
/// which dumps only prefix routes: none of IPv4's, and of IPv6's only
/// those of router advertisements, which `lo` has none of.
const RTM_F_NOTIFY: u32 = 0x100;
const RTM_F_PREFIX: u32 = 0x800;
/// `NLM_F_DUMP_FILTERED`: a dump that its request narrowed.
const NLM_F_DUMP_FILTERED: u16 = 0x20;
/// The multicast routing tables' only table: IPv4's `RT_TABLE_DEFAULT`,
/// and IPv6's `RT6_TABLE_DFLT`, which is its main one.
const RT_TABLE_DEFAULT: u32 = 253;
const RT6_TABLE_DFLT: u32 = 254;
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
/// `IFLA_PROTINFO`, where an AF_INET6 link dump puts IPv6's settings.
const IFLA_PROTINFO: u16 = 12;
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
/// What a link dump takes besides `IFLA_EXT_MASK`: a master to show the
/// devices of, a kind (whose devices `lo` is none of, but the kinds there
/// are depend on the modules loaded, so it is taken without effect), and
/// another namespace's ID, of which none is given.
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_TARGET_NETNSID: u16 = 46;
/// The last link attribute (`IFLA_MAX`, `IFLA_PACING_OFFLOAD` on Linux
/// master).
const IFLA_MAX: u16 = 70;
/// The other link attributes `ifla_policy` names.
const IFLA_LINK: u16 = 5;
const IFLA_WEIGHT: u16 = 15;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_IFALIAS: u16 = 20;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_VF_PORTS: u16 = 24;
const IFLA_PORT_SELF: u16 = 25;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_PHYS_PORT_ID: u16 = 34;
const IFLA_PHYS_SWITCH_ID: u16 = 36;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_EVENT: u16 = 44;
const IFLA_NEW_IFINDEX: u16 = 49;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_PERM_ADDRESS: u16 = 54;
const IFLA_PROTO_DOWN_REASON: u16 = 55;
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PACING_OFFLOAD: u16 = 70;
/// The attributes inside `IFLA_LINKINFO` (`ifla_info_policy`), the last
/// of them `IFLA_INFO_MAX`.
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_INFO_SLAVE_KIND: u16 = 4;
const IFLA_INFO_SLAVE_DATA: u16 = 5;
const IFLA_INFO_MAX: u16 = 5;
/// `MAX_TCP_HEADER` of a kernel built as Ubuntu's is for x86-64
/// (`L1_CACHE_ALIGN(128 + MAX_HEADER)`, `MAX_HEADER` 128 + 48 with
/// `CONFIG_MAC80211_MESH` and the IP tunnels), one less than the least
/// `IFLA_GSO_MAX_SIZE` and `IFLA_GSO_IPV4_MAX_SIZE` that `ifla_policy` takes.
const MAX_TCP_HEADER: u32 = 320;
/// An address dump's other namespace (`IFA_TARGET_NETNSID`), and the last
/// address attribute (`IFA_MAX`, `IFA_MC_USERS`).
const IFA_TARGET_NETNSID: u16 = 10;
const IFA_MAX: u16 = 12;
/// The attributes inside `IFLA_XDP` and `IFLA_AF_SPEC`.
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_INET_CONF: u16 = 1;
const IFLA_MCTP_NET: u16 = 1;
const IFLA_MCTP_PHYS_BINDING: u16 = 2;
/// `AF_MCTP`, whose settings `IFLA_AF_SPEC` carries too, and whose
/// address dump is its own.
const AF_MCTP: u8 = 45;
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
const IFA_RT_PRIORITY: u16 = 9;
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
const EADDRNOTAVAIL: Errno = Errno(99);
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
    /// Takes the pending error (`sock_error`), as `SO_ERROR` does.
    pub(crate) fn take_error(&self) -> Option<Errno> {
        self.lock().error.take()
    }
    /// Makes `error` the pending error without reporting it, as
    /// `do_recvmmsg` writes `sk_err`.
    pub(crate) fn store_error(&self, error: Errno) {
        self.lock().error = Some(error);
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
            // What the request asks is checked as the dump begins, so a
            // bad one ends it at once, its error in `NLMSG_DONE`, which
            // carries the flags (`answer_flags`) the checks set by then.
            let strict = s.strict;
            let mut answer = 0;
            let (seq, network) = (header.seq, &*self.network);
            let dump = match (header.kind, family) {
                // `rtnl_bridge_getlink` has no bridge port to show.
                (RTM_GETLINK, AF_BRIDGE) => bridge_dump_check(payload, strict).map(|()| Vec::new()),
                // `inet6_dump_ifinfo`: each device with IPv6, as IPv6 shows it.
                (RTM_GETLINK, AF_INET6) => bare_link_dump_check(payload, strict)
                    .map(|()| vec![inet6_link_message(network, seq, port, NLM_F_MULTI)]),
                // `ipmr_rtm_dumplink`: each IPv4 multicast routing table.
                (RTM_GETLINK, RTNL_FAMILY_IPMR) => bare_link_dump_check(payload, strict)
                    .map(|()| vec![ipmr_link_message(seq, port)]),
                (RTM_GETLINK, _) => link_dump(network, payload, seq, port, strict),
                // `mctp_dump_addrinfo`: `lo`'s MCTP addresses.
                (RTM_GETADDR, AF_MCTP) => mctp_address_dump_check(payload, strict)
                    .map(|()| mctp_addresses(network, payload, seq, port)),
                // `mctp_dump_rtinfo`, which checks nothing.
                (RTM_GETROUTE, AF_MCTP) => Ok(mctp_routes(network, seq, port)),
                // `rtnl_dump_all` dumps each family's: IPv4's, then IPv6's.
                (RTM_GETADDR, _) => {
                    address_dump(network, payload, family, seq, port, strict, &mut answer)
                }
                (RTM_GETROUTE, _) => {
                    route_dump(network, payload, family, seq, port, strict, &mut answer)
                }
                _ => return Err(EOPNOTSUPP),
            };
            if s.done.is_some() {
                return Err(EBUSY);
            }
            let (messages, error) = match dump {
                Ok(messages) => (messages, 0),
                Err(e) => (Vec::new(), -e.0),
            };
            let done = message(
                NLMSG_DONE,
                NLM_F_MULTI | answer,
                header.seq,
                port,
                &error.to_le_bytes(),
            );
            // `inet6_dump_ifaddr` and `inet6_dump_ifinfo`, not split, put
            // `NLMSG_DONE` after their last message when that part has room
            // for it.
            let joined = matches!(header.kind, RTM_GETADDR | RTM_GETLINK) && family == AF_INET6;
            self.start_dump_as(s, messages, done, joined);
            return Ok(true);
        }
        match header.kind {
            // Only IPv6 answers a single address (`inet6_rtm_getaddr`);
            // IPv4 and MCTP have no `doit`, nor the `PF_UNSPEC` fallback.
            RTM_GETADDR if family == AF_INET6 => {
                let reply = address_get(&self.network, payload, header.seq, port, s.strict)?;
                self.deliver(s, 0, 0, reply);
                Ok(false)
            }
            RTM_GETROUTE if matches!(family, AF_INET | AF_INET6) => {
                lookup_check(payload, s.strict)?;
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
            RTM_NEWADDR | RTM_DELADDR if family == AF_MCTP => {
                let eid = change_mctp_address(&self.network, header, payload)?;
                let echo = header.flags & NLM_F_ECHO != 0;
                // `mctp_addr_notify`, which `rtnl_notify` sends as an IPv4
                // address's.
                let notice = Notice {
                    group: RTNLGRP_MCTP_IFADDR,
                    origin: if echo { port } else { 0 },
                    bytes: mctp_address(eid, header.kind, 0, header.seq, port),
                };
                if echo && port != 0 {
                    self.deliver(s, 0, 0, notice.bytes.clone());
                }
                notices.push(notice);
                Ok(false)
            }
            RTM_NEWROUTE | RTM_DELROUTE if family == AF_MCTP => {
                change_mctp_route(&self.network, header, payload)?;
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
                self.find_link(payload, header, Some(s.strict))?;
                let reply = link_message(&self.network, header.seq, port, 0, ext_mask(payload));
                self.deliver(s, 0, 0, reply);
                Ok(false)
            }
            RTM_NEWLINK | RTM_SETLINK => {
                let (flags, change) = self.find_link(payload, header, None)?;
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
    /// The `ifinfomsg` of a request for `lo`, which names it by a positive
    /// index or else by `IFLA_IFNAME` or `IFLA_ALT_IFNAME`: `EINVAL` for a
    /// short message, for neither to get or set (`RTM_SETLINK`), and for a
    /// negative index to make (`RTM_NEWLINK`); `ENODEV` for another
    /// interface. The attributes are checked against `ifla_policy` first
    /// ([`parse_policy`]). To set, more than one of `IFLA_NET_NS_PID`,
    /// `IFLA_NET_NS_FD` and `IFLA_TARGET_NETNSID` is `EINVAL`
    /// (`rtnl_ensure_unique_netns`), `RTM_NEWLINK` checks what
    /// `IFLA_LINKINFO` holds against `ifla_info_policy`, `NLM_F_EXCL` is
    /// `EEXIST` and `NLM_F_REPLACE` `EOPNOTSUPP` for `RTM_NEWLINK`, and of
    /// the attributes only the name `lo` and `IFLA_EXT_MASK` are taken
    /// (`EOPNOTSUPP` for others). To get, `strict` is `Some` with whether
    /// the socket checks strictly, which takes, as `rtnl_valid_getlink_req`
    /// does, no type, flags or change mask (`EINVAL`), and of the
    /// attributes only the names, `IFLA_EXT_MASK` and
    /// `IFLA_TARGET_NETNSID` (`EINVAL` for others); another
    /// namespace's ID is `EINVAL` either way, as there is none. The flags
    /// and the change mask.
    fn find_link(
        &self,
        payload: &[u8],
        header: &Header,
        strict: Option<bool>,
    ) -> Result<(u32, u32), Errno> {
        if payload.len() < 16 {
            return Err(Errno::EINVAL);
        }
        let get = strict.is_some();
        let word = |i: usize| u32::from_le_bytes(payload[i..i + 4].try_into().unwrap_or_default());
        let index = word(4) as i32;
        if strict == Some(true) {
            strict_link_header(payload, false)?;
        }
        let attributes = parse_policy(&payload[16..], &IFLA_POLICY, strict == Some(true))?;
        let named = |kind: u16| attributes.iter().any(|&(k, _)| k == kind);
        if !get {
            // `rtnl_ensure_unique_netns`: one namespace at most.
            let namespaces = [IFLA_NET_NS_PID, IFLA_NET_NS_FD, IFLA_TARGET_NETNSID];
            if namespaces.into_iter().filter(|&kind| named(kind)).count() > 1 {
                return Err(Errno::EINVAL);
            }
        }
        if !get
            && header.kind == RTM_NEWLINK
            && let Some(&(_, info)) = attributes.iter().rev().find(|&&(k, _)| k == IFLA_LINKINFO)
        {
            parse_policy(info, &IFLA_INFO_POLICY, false)?;
        }
        for &(kind, _) in &attributes {
            match kind {
                IFLA_IFNAME | IFLA_ALT_IFNAME | IFLA_EXT_MASK => {}
                _ if get => {}
                _ => return Err(EOPNOTSUPP),
            }
        }
        // `rtnl_dev_get`: the last `IFLA_IFNAME`, or else `IFLA_ALT_IFNAME`,
        // to its NUL.
        let by_kind = by_type(&attributes);
        let name = by_kind
            .get(&IFLA_IFNAME)
            .or_else(|| by_kind.get(&IFLA_ALT_IFNAME))
            .map(|value| {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                &value[..end]
            });
        if get {
            let named = |kind: u16| attributes.iter().any(|&(k, _)| k == kind);
            if strict == Some(true)
                && attributes.iter().any(|&(kind, _)| {
                    !matches!(
                        kind,
                        IFLA_IFNAME | IFLA_ALT_IFNAME | IFLA_EXT_MASK | IFLA_TARGET_NETNSID
                    )
                })
            {
                return Err(Errno::EINVAL);
            }
            if named(IFLA_TARGET_NETNSID) {
                return Err(Errno::EINVAL);
            }
        }
        // A positive index names the link; otherwise its name does, which
        // `rtnl_getlink` and `rtnl_setlink` need (`EINVAL`), while
        // `rtnl_newlink` takes no negative index (`EINVAL`).
        let newlink = !get && header.kind == RTM_NEWLINK;
        let found = match (index, name) {
            (i, _) if i < 0 && newlink => return Err(Errno::EINVAL),
            (i, _) if i > 0 => i == 1,
            (_, Some(name)) => name == b"lo",
            (_, None) if !newlink => return Err(Errno::EINVAL),
            (_, None) => false,
        };
        if !found {
            // `rtnl_newlink` makes a link only of a kind it is given.
            if !get && header.kind == RTM_NEWLINK && header.flags & NLM_F_CREATE != 0 {
                return Err(EOPNOTSUPP);
            }
            return Err(ENODEV);
        }
        // Renaming `lo` to another name is not supported.
        if !get && index > 0 && name.is_some_and(|name| name != b"lo") {
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
/// What an attribute's `struct nla_policy` asks of it, as `validate_nla`
/// checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nla {
    /// `NLA_UNSPEC` of at least this many bytes (a policy's `len`); a type
    /// the policy does not name is one of 0.
    Unspec(usize),
    U8,
    U16,
    U32,
    S32,
    Be32,
    /// An `NLA_U32` whose value lies from the first to the second
    /// (`NLA_POLICY_MIN`, `NLA_POLICY_MAX`, `NLA_POLICY_FULL_RANGE`).
    U32In(u32, u32),
    /// An `NLA_S32` of at least this (`NLA_POLICY_MIN`).
    S32Min(i32),
    /// `NLA_STRING` of at most this many bytes but a last NUL (none for 0).
    String(usize),
    /// `NLA_NUL_STRING` without a length.
    NulString,
    /// `NLA_BINARY` of at most this many bytes.
    Binary(usize),
    /// `NLA_NESTED` without a nested policy.
    Nested,
    /// `NLA_REJECT`.
    Reject,
}
impl Nla {
    /// The length of an integer, which a strict policy takes alone.
    fn size(self) -> Option<usize> {
        match self {
            Nla::U8 => Some(1),
            Nla::U16 => Some(2),
            Nla::U32 | Nla::S32 | Nla::Be32 | Nla::U32In(..) | Nla::S32Min(_) => Some(4),
            _ => None,
        }
    }
}
/// A message's attribute policy: its last type (`maxtype`), the first type
/// it always checks strictly (`strict_start_type`, none for 0), and each
/// type's [`Nla`].
struct Policy {
    max: u16,
    strict_start: u16,
    of: fn(u16) -> Nla,
}
/// `ifla_policy`, the link requests'.
const IFLA_POLICY: Policy = Policy {
    max: IFLA_MAX,
    strict_start: IFLA_DPLL_PIN,
    of: |kind| match kind {
        IFLA_IFNAME => Nla::String(15),
        IFLA_ALT_IFNAME => Nla::String(127),
        // `MAX_ADDR_LEN` and `MAX_PHYS_ITEM_ID_LEN`.
        IFLA_ADDRESS | IFLA_BROADCAST | IFLA_PHYS_PORT_ID | IFLA_PHYS_SWITCH_ID => Nla::Binary(32),
        // `IFALIASZ - 1`.
        IFLA_IFALIAS => Nla::Binary(255),
        // `struct rtnl_link_ifmap`.
        IFLA_MAP => Nla::Unspec(32),
        IFLA_TXQLEN => Nla::U32In(0, i16::MAX as u32),
        IFLA_GSO_MAX_SIZE | IFLA_GSO_IPV4_MAX_SIZE => Nla::U32In(MAX_TCP_HEADER + 1, u32::MAX),
        IFLA_PACING_OFFLOAD => Nla::U32In(0, 1),
        IFLA_MTU
        | IFLA_LINK
        | IFLA_MASTER
        | IFLA_WEIGHT
        | IFLA_NET_NS_PID
        | IFLA_NET_NS_FD
        | IFLA_EXT_MASK
        | IFLA_PROMISCUITY
        | IFLA_NUM_TX_QUEUES
        | IFLA_NUM_RX_QUEUES
        | IFLA_GSO_MAX_SEGS
        | IFLA_CARRIER_CHANGES
        | IFLA_EVENT
        | IFLA_GROUP
        | IFLA_CARRIER_UP_COUNT
        | IFLA_CARRIER_DOWN_COUNT
        | IFLA_MIN_MTU
        | IFLA_MAX_MTU
        | IFLA_GRO_MAX_SIZE
        | IFLA_GRO_IPV4_MAX_SIZE => Nla::U32,
        IFLA_CARRIER | IFLA_OPERSTATE | IFLA_LINKMODE | IFLA_PROTO_DOWN => Nla::U8,
        IFLA_LINK_NETNSID | IFLA_TARGET_NETNSID => Nla::S32,
        IFLA_NEW_IFINDEX => Nla::S32Min(1),
        IFLA_LINKINFO
        | IFLA_VFINFO_LIST
        | IFLA_VF_PORTS
        | IFLA_PORT_SELF
        | IFLA_AF_SPEC
        | IFLA_XDP
        | IFLA_PROP_LIST
        | IFLA_PROTO_DOWN_REASON => Nla::Nested,
        IFLA_PARENT_DEV_NAME => Nla::NulString,
        IFLA_PERM_ADDRESS
        | IFLA_TSO_MAX_SIZE
        | IFLA_TSO_MAX_SEGS
        | IFLA_ALLMULTI
        | IFLA_MAX_PACING_OFFLOAD_HORIZON
        | IFLA_NETNS_IMMUTABLE
        | IFLA_HEADROOM
        | IFLA_TAILROOM => Nla::Reject,
        _ => Nla::Unspec(0),
    },
};
/// `ifla_info_policy`, inside the `IFLA_LINKINFO` of `RTM_NEWLINK`.
const IFLA_INFO_POLICY: Policy = Policy {
    max: IFLA_INFO_MAX,
    strict_start: 0,
    of: |kind| match kind {
        IFLA_INFO_KIND | IFLA_INFO_SLAVE_KIND => Nla::String(0),
        IFLA_INFO_DATA | IFLA_INFO_SLAVE_DATA => Nla::Nested,
        _ => Nla::Unspec(0),
    },
};
/// `ifa_ipv4_policy`, IPv4's address requests'.
const IFA4_POLICY: Policy = Policy {
    max: IFA_MAX,
    strict_start: 0,
    of: |kind| match kind {
        IFA_LOCAL | IFA_ADDRESS | IFA_BROADCAST | IFA_FLAGS | IFA_RT_PRIORITY => Nla::U32,
        IFA_LABEL => Nla::String(15),
        // `struct ifa_cacheinfo`.
        IFA_CACHEINFO => Nla::Unspec(16),
        IFA_TARGET_NETNSID => Nla::S32,
        IFA_PROTO => Nla::U8,
        _ => Nla::Unspec(0),
    },
};
/// `ifa_ipv6_policy`, IPv6's address requests'.
const IFA6_POLICY: Policy = Policy {
    max: IFA_MAX,
    strict_start: 0,
    of: |kind| match kind {
        IFA_ADDRESS | IFA_LOCAL | IFA_CACHEINFO => Nla::Unspec(16),
        IFA_FLAGS | IFA_RT_PRIORITY => Nla::Unspec(4),
        IFA_TARGET_NETNSID => Nla::S32,
        IFA_PROTO => Nla::U8,
        _ => Nla::Unspec(0),
    },
};
/// `rtm_ipv4_policy`, IPv4's route requests' and every route dump's.
const RTA4_POLICY: Policy = Policy {
    max: RTA_MAX,
    strict_start: RTA_DPORT + 1,
    of: |kind| match kind {
        RTA_DST | RTA_SRC | RTA_IIF | RTA_OIF | RTA_GATEWAY | RTA_PRIORITY | RTA_PREFSRC
        | RTA_FLOW | RTA_UID | RTA_MARK | RTA_TABLE | RTA_NH_ID => Nla::U32,
        RTA_METRICS | RTA_ENCAP => Nla::Nested,
        // `struct rtnexthop`.
        RTA_MULTIPATH => Nla::Unspec(8),
        RTA_ENCAP_TYPE | RTA_SPORT | RTA_DPORT => Nla::U16,
        RTA_IP_PROTO => Nla::U8,
        _ => Nla::Unspec(0),
    },
};
/// `rtm_ipv6_policy`, IPv6's route requests'.
const RTA6_POLICY: Policy = Policy {
    max: RTA_MAX,
    strict_start: RTA_DPORT + 1,
    of: |kind| match kind {
        RTA_GATEWAY | RTA_PREFSRC => Nla::Unspec(16),
        RTA_OIF | RTA_IIF | RTA_PRIORITY | RTA_EXPIRES | RTA_UID | RTA_MARK | RTA_TABLE
        | RTA_NH_ID => Nla::U32,
        RTA_METRICS | RTA_ENCAP => Nla::Nested,
        RTA_MULTIPATH => Nla::Unspec(8),
        RTA_PREF | RTA_IP_PROTO => Nla::U8,
        RTA_ENCAP_TYPE | RTA_SPORT | RTA_DPORT => Nla::U16,
        RTA_FLOWLABEL => Nla::Be32,
        _ => Nla::Unspec(0),
    },
};
/// The attributes of `bytes` (types 1 to the policy's last; an attribute
/// of type 0 or past it is left out), each checked against `policy` in
/// turn, as `__nla_validate_parse` does. `strict` is
/// `nlmsg_parse_deprecated_strict`'s check, for a socket that checks
/// strictly (`NETLINK_GET_STRICT_CHK`): `EINVAL` for a type of 0 or past
/// the last, and for bytes left after the last whole attribute; without
/// it, as `nlmsg_parse_deprecated`, those are passed over. A type from the
/// policy's `strict_start` on is checked as `nlmsg_parse` would
/// ([`validate_nla`]).
fn parse_policy<'a>(
    mut bytes: &'a [u8],
    policy: &Policy,
    strict: bool,
) -> Result<Vec<(u16, &'a [u8])>, Errno> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if len < 4 || len > bytes.len() {
            break;
        }
        let raw = u16::from_le_bytes([bytes[2], bytes[3]]);
        let (kind, value) = (raw & 0x3fff, &bytes[4..len]);
        bytes = &bytes[align(len).min(bytes.len())..];
        if kind == 0 || kind > policy.max {
            if strict {
                return Err(Errno::EINVAL);
            }
            continue;
        }
        let full = policy.strict_start != 0 && kind >= policy.strict_start;
        validate_nla((policy.of)(kind), raw & NLA_F_NESTED != 0, value, full)?;
        out.push((kind, value));
    }
    if strict && !bytes.is_empty() {
        return Err(Errno::EINVAL);
    }
    Ok(out)
}
/// `validate_nla`'s check of an attribute's `value` against `nla`, and
/// whether it is marked `NLA_F_NESTED`. With `strict` (`NL_VALIDATE_STRICT`,
/// as `nlmsg_parse` and a policy's `strict_start_type` ask), `EINVAL` for
/// an integer of another length, for a nest unmarked or another attribute
/// marked (but `NLA_UNSPEC`), and for an `NLA_UNSPEC`. Then `EINVAL` for
/// `NLA_REJECT` and for an `NLA_NUL_STRING` without a NUL; `ERANGE` for an
/// integer, `NLA_UNSPEC` or nest shorter than its policy's, an empty
/// string, a string or binary longer, and an integer out of its range.
fn validate_nla(nla: Nla, nested: bool, value: &[u8], strict: bool) -> Result<(), Errno> {
    let len = value.len();
    if strict {
        let unspec = matches!(nla, Nla::Unspec(_));
        if nla.size().is_some_and(|size| len != size)
            || ((nla == Nla::Nested) != nested && !unspec)
            || unspec
        {
            return Err(Errno::EINVAL);
        }
    }
    let fits = match nla {
        Nla::Reject => return Err(Errno::EINVAL),
        Nla::NulString if !value.contains(&0) => return Err(Errno::EINVAL),
        Nla::NulString => true,
        Nla::Unspec(least) => len >= least,
        Nla::String(most) => {
            let bytes = len - usize::from(value.last() == Some(&0));
            len > 0 && (most == 0 || bytes <= most)
        }
        Nla::Binary(most) => most == 0 || len <= most,
        Nla::Nested => len == 0 || len >= 4,
        _ => nla.size().is_some_and(|size| len >= size),
    };
    if !fits {
        return Err(ERANGE);
    }
    let word = || value.first_chunk().copied().map_or(0, u32::from_le_bytes);
    let within = match nla {
        Nla::U32In(least, most) => (least..=most).contains(&word()),
        Nla::S32Min(least) => word().cast_signed() >= least,
        _ => true,
    };
    if within { Ok(()) } else { Err(ERANGE) }
}
/// The attributes of `bytes` as `nlmsg_parse` and `nla_parse_nested` take
/// them (`NL_VALIDATE_STRICT`), in one walk as `__nla_validate_parse`'s:
/// each in turn is `EINVAL` for a type of 0 or past `max`, or else has
/// `policy` check its type, whether it is marked `NLA_F_NESTED`, and its
/// value; then bytes left after the last whole attribute are `EINVAL`.
fn policy_attributes(
    mut bytes: &[u8],
    max: u16,
    policy: impl Fn(u16, bool, &[u8]) -> Result<(), Errno>,
) -> Result<Vec<(u16, &[u8])>, Errno> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if len < 4 || len > bytes.len() {
            break;
        }
        let raw = u16::from_le_bytes([bytes[2], bytes[3]]);
        let kind = raw & 0x3fff;
        if kind == 0 || kind > max {
            return Err(Errno::EINVAL);
        }
        policy(kind, raw & 0x8000 != 0, &bytes[4..len])?;
        out.push((kind, &bytes[4..len]));
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    if bytes.is_empty() {
        Ok(out)
    } else {
        Err(Errno::EINVAL)
    }
}
/// A strict policy's check of an `NLA_U8`, `NLA_U32` or exact-length
/// binary attribute (`validate_nla`): `EINVAL` for another length, or for
/// one marked `NLA_F_NESTED`.
fn exact(nested: bool, value: &[u8], len: usize) -> Result<(), Errno> {
    if nested || value.len() != len {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}
/// The attributes' values by type, the last of each, in the order of
/// their types, as `nlmsg_parse` puts them in its table.
fn by_type<'a>(attributes: &[(u16, &'a [u8])]) -> BTreeMap<u16, &'a [u8]> {
    attributes.iter().copied().collect()
}
/// A `u32` attribute's value: `ERANGE` for one shorter, as its policy.
fn u32_value(value: &[u8]) -> Result<u32, Errno> {
    value
        .first_chunk()
        .copied()
        .map(u32::from_le_bytes)
        .ok_or(ERANGE)
}
/// Whether the `ifinfomsg` of a strict link request has a type, flags, a
/// change mask or, with `index`, an index: `EINVAL` for a short one or
/// for any of them.
fn strict_link_header(payload: &[u8], index: bool) -> Result<(), Errno> {
    if payload.len() < 16
        || payload[1] != 0
        || payload[2..4] != [0, 0]
        || payload[8..16].iter().any(|&b| b != 0)
        || (index && payload[4..8] != [0; 4])
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
/// A link dump, as `rtnl_dump_ifinfo`: `lo`, as `IFLA_EXT_MASK` asks it.
/// An `IFLA_MASTER` other than 0 shows only the devices of that master,
/// which `lo` is not, and `IFLA_TARGET_NETNSID` is `EINVAL`, as no other
/// namespace has an ID. Unchecked, a request shorter than an `ifinfomsg`
/// is an old `rtgenmsg`, whose attributes follow its 4 bytes, and none
/// is taken where one breaks `ifla_policy`, as a failed
/// `nlmsg_parse_deprecated`; strictly, as `rtnl_valid_dump_ifinfo_req`, it
/// is `EINVAL` with a type, flags, a change mask or an index
/// ([`strict_link_header`]), then the policy's error, and `EINVAL` for
/// attributes but those and `IFLA_LINKINFO`.
fn link_dump(
    network: &Network,
    payload: &[u8],
    seq: u32,
    port: u32,
    strict: bool,
) -> Result<Vec<Vec<u8>>, Errno> {
    let parsed = if strict {
        strict_link_header(payload, true)?;
        parse_policy(&payload[16..], &IFLA_POLICY, true)
    } else {
        let start = if payload.len() < 16 { 4 } else { 16 };
        parse_policy(
            payload.get(start..).unwrap_or_default(),
            &IFLA_POLICY,
            false,
        )
    };
    let attributes = match parsed {
        Ok(attributes) => by_type(&attributes),
        Err(e) if strict => return Err(e),
        Err(_) => BTreeMap::new(),
    };
    let known = |kind: u16| {
        matches!(
            kind,
            IFLA_TARGET_NETNSID | IFLA_EXT_MASK | IFLA_MASTER | IFLA_LINKINFO
        )
    };
    if attributes.contains_key(&IFLA_TARGET_NETNSID)
        || (strict && attributes.keys().any(|&kind| !known(kind)))
    {
        return Err(Errno::EINVAL);
    }
    let value = |kind: u16| {
        attributes
            .get(&kind)
            .map_or(0, |v| u32_value(v).unwrap_or(0))
    };
    let (mask, master) = (value(IFLA_EXT_MASK), value(IFLA_MASTER));
    if master != 0 {
        return Ok(Vec::new());
    }
    Ok(vec![link_message(network, seq, port, NLM_F_MULTI, mask)])
}
/// Strictly, a bridge link dump (`valid_bridge_getlink_req`) takes no
/// type, flags, change mask or index (`EINVAL`), then breaks no rule of
/// `ifla_policy`, and has no attribute but `IFLA_EXT_MASK` (`EINVAL`).
/// Unchecked, nothing is checked.
fn bridge_dump_check(payload: &[u8], strict: bool) -> Result<(), Errno> {
    if !strict {
        return Ok(());
    }
    strict_link_header(payload, true)?;
    let attributes = parse_policy(&payload[16..], &IFLA_POLICY, true)?;
    if attributes.iter().any(|&(kind, _)| kind != IFLA_EXT_MASK) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
/// Strictly, an AF_INET6 link dump (`inet6_valid_dump_ifinfo`) and an
/// `RTNL_FAMILY_IPMR` one (`ipmr_valid_dumplink`) take an `ifinfomsg`
/// alone, with no type, flags, change mask or index (`EINVAL`).
fn bare_link_dump_check(payload: &[u8], strict: bool) -> Result<(), Errno> {
    // `nlmsg_attrlen`: nothing may follow the header.
    if strict && payload.len() > 16 {
        return Err(Errno::EINVAL);
    }
    if strict {
        strict_link_header(payload, true)?;
    }
    Ok(())
}
/// Adds `flags` to each message of `messages`.
fn with_flags(mut messages: Vec<Vec<u8>>, flags: u16) -> Vec<Vec<u8>> {
    for message in &mut messages {
        let old = u16::from_le_bytes([message[6], message[7]]);
        message[6..8].copy_from_slice(&(old | flags).to_le_bytes());
    }
    messages
}
/// An address dump: IPv4's, then IPv6's, as `rtnl_dump_all` dumps each
/// family's, or the one family's. Strictly, as
/// `inet_valid_dump_ifaddr_req` and `inet6_valid_dump_ifaddr_req`, it is
/// `EINVAL` for an `ifaddrmsg` short or with a prefix length, flags or a
/// scope, then the family's policy's error (IPv4's for both), and
/// `EINVAL` for any attribute (`IFA_TARGET_NETNSID` too, as no other
/// namespace has an ID); an index other than 0 shows that device's
/// addresses alone, as `NLM_F_DUMP_FILTERED`, which `NLMSG_DONE` carries
/// too, and is `ENODEV` for another than `lo`'s.
fn address_dump(
    network: &Network,
    payload: &[u8],
    family: u8,
    seq: u32,
    port: u32,
    strict: bool,
    answer: &mut u16,
) -> Result<Vec<Vec<u8>>, Errno> {
    let mut flags = 0;
    if strict {
        if payload.len() < 8 || payload[1..4] != [0; 3] {
            return Err(Errno::EINVAL);
        }
        let index = u32::from_le_bytes(payload[4..8].try_into().unwrap_or_default());
        if index != 0 {
            *answer |= NLM_F_DUMP_FILTERED;
            flags = NLM_F_DUMP_FILTERED;
        }
        // `rtnl_dump_all` asks IPv4's first, whose error ends the dump.
        let policy = if family == AF_INET6 {
            &IFA6_POLICY
        } else {
            &IFA4_POLICY
        };
        if !parse_policy(&payload[8..], policy, true)?.is_empty() {
            return Err(Errno::EINVAL);
        }
        if index > 1 {
            return Err(ENODEV);
        }
    }
    let mut messages = Vec::new();
    if family != AF_INET6 {
        messages.extend(ipv4_message(network, seq, port));
    }
    if family != AF_INET {
        messages.extend(ipv6_message(network, seq, port));
    }
    let mut messages = with_flags(messages, flags);
    // `rtnl_dump_all` goes on to MCTP's, which marks nothing.
    if !matches!(family, AF_INET | AF_INET6) {
        messages.extend(mctp_addresses(network, payload, seq, port));
    }
    Ok(messages)
}
/// The `RTM_NEWADDR` of one IPv6 address of `lo`, as `inet6_rtm_getaddr`
/// gives it to a request that is not a dump. As
/// `inet6_rtm_valid_getaddr_req`, it is `EINVAL` for an `ifaddrmsg` short;
/// then, strictly, `EINVAL` for a prefix length, flags or a scope, and
/// `ifa_ipv6_policy`'s error, with `EINVAL` for an attribute but
/// `IFA_ADDRESS`, `IFA_LOCAL` and `IFA_TARGET_NETNSID`; unchecked, the
/// policy's error alone. `IFA_TARGET_NETNSID` is `EINVAL`, as no other
/// namespace has an ID. The address is `IFA_LOCAL`'s, or else
/// `IFA_ADDRESS`'s (`extract_addr`), and `EINVAL` with neither;
/// `EADDRNOTAVAIL` when `lo` has it not. The index is not checked:
/// `ipv6_get_ifaddr` looks on any device when none has it.
fn address_get(
    network: &Network,
    payload: &[u8],
    seq: u32,
    port: u32,
    strict: bool,
) -> Result<Vec<u8>, Errno> {
    if payload.len() < 8 {
        return Err(Errno::EINVAL);
    }
    if strict && payload[1..4] != [0; 3] {
        return Err(Errno::EINVAL);
    }
    let attributes = parse_policy(&payload[8..], &IFA6_POLICY, strict)?;
    if strict
        && attributes
            .iter()
            .any(|&(kind, _)| !matches!(kind, IFA_ADDRESS | IFA_LOCAL | IFA_TARGET_NETNSID))
    {
        return Err(Errno::EINVAL);
    }
    let by_kind = by_type(&attributes);
    if by_kind.contains_key(&IFA_TARGET_NETNSID) {
        return Err(Errno::EINVAL);
    }
    // The policy has made each at least 16 bytes long.
    let wanted = by_kind
        .get(&IFA_LOCAL)
        .or_else(|| by_kind.get(&IFA_ADDRESS))
        .and_then(|value| value.first_chunk::<16>())
        .map(|octets| core::net::Ipv6Addr::from(*octets))
        .ok_or(Errno::EINVAL)?;
    let addresses = network.addresses().v6.clone();
    let address = addresses
        .iter()
        .find(|address| address.address == wanted)
        .ok_or(EADDRNOTAVAIL)?;
    Ok(ipv6_address(address, false, RTM_NEWADDR, 0, seq, port))
}
/// Strictly, an MCTP address dump (`mctp_dump_addrinfo`) needs a whole
/// `ifaddrmsg` (`EINVAL`), and nothing else: its index only narrows it,
/// without `NLM_F_DUMP_FILTERED`, and it takes any other field and
/// attribute. Unchecked, nothing is checked.
fn mctp_address_dump_check(payload: &[u8], strict: bool) -> Result<(), Errno> {
    if strict && payload.len() < 8 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
/// `lo`'s MCTP addresses, as `mctp_dump_addrinfo` dumps them: all, unless
/// a whole `ifaddrmsg` names another device's index.
fn mctp_addresses(network: &Network, payload: &[u8], seq: u32, port: u32) -> Vec<Vec<u8>> {
    let index = payload
        .get(4..8)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap_or_default()));
    if index > 1 {
        return Vec::new();
    }
    let eids = network.addresses().mctp.clone();
    eids.into_iter()
        .map(|eid| mctp_address(eid, RTM_NEWADDR, NLM_F_MULTI, seq, port))
        .collect()
}
/// An MCTP address of `lo`, as `mctp_fill_addrinfo` gives it: an
/// `ifaddrmsg` of `AF_MCTP` with nothing but the index, then the endpoint
/// ID as `IFA_LOCAL` and as `IFA_ADDRESS`.
fn mctp_address(eid: u8, kind: u16, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    let mut body = vec![AF_MCTP, 0, 0, 0];
    body.extend_from_slice(&1u32.to_le_bytes());
    attribute(&mut body, IFA_LOCAL, &[eid]);
    attribute(&mut body, IFA_ADDRESS, &[eid]);
    message(kind, flags, seq, port, &body)
}
/// The MCTP routes, as `mctp_dump_rtinfo` dumps them: the local route of
/// each of `lo`'s addresses (`mctp_route_add_local`) and the routes
/// through gateways, the newest first, as `mctp_route_add` puts each at
/// the head of the list. As `mctp_fill_rtinfo`: the number of endpoints
/// after the first as `rtm_dst_len`, the default table, `RTPROT_STATIC`,
/// link scope through `lo` and universe scope through a gateway, and the
/// route's type; its first endpoint as `RTA_DST`, metrics with its MTU if
/// it has one (not marked nested), and `lo` as `RTA_OIF` or the gateway's
/// `mctp_fq_addr` as `RTA_GATEWAY`.
fn mctp_routes(network: &Network, seq: u32, port: u32) -> Vec<Vec<u8>> {
    const RTPROT_STATIC: u8 = 4;
    const RT_SCOPE_LINK: u8 = 253;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    let routes = network.addresses().mctp_routes.clone();
    routes
        .into_iter()
        .map(|route| {
            let scope = if route.gateway.is_some() {
                RT_SCOPE_UNIVERSE
            } else {
                RT_SCOPE_LINK
            };
            let mut body = vec![AF_MCTP, route.max - route.min, 0, 0];
            body.extend_from_slice(&[
                table_byte(RT_TABLE_DEFAULT),
                RTPROT_STATIC,
                scope,
                route.kind,
            ]);
            body.extend_from_slice(&0u32.to_le_bytes());
            attribute(&mut body, RTA_DST, &[route.min]);
            let mut metrics = Vec::new();
            if route.mtu != 0 {
                attribute(&mut metrics, RTAX_MTU, &route.mtu.to_le_bytes());
            }
            attribute(&mut body, RTA_METRICS, &metrics);
            match route.gateway {
                None => attribute(&mut body, RTA_OIF, &1u32.to_le_bytes()),
                Some((net, eid)) => {
                    let mut address = net.to_le_bytes().to_vec();
                    address.extend_from_slice(&[eid, 0, 0, 0]);
                    attribute(&mut body, RTA_GATEWAY, &address);
                }
            }
            message(RTM_NEWROUTE, NLM_F_MULTI, seq, port, &body)
        })
        .collect()
}
/// Adds (`RTM_NEWADDR`) or removes (`RTM_DELADDR`) an MCTP address of `lo`,
/// as `mctp_rtm_newaddr` and `mctp_rtm_deladdr` do, and gives its endpoint
/// ID. The request is parsed as `nlmsg_parse` does with `ifa_mctp_policy`:
/// `EINVAL` for a short `ifaddrmsg`, a type of 0 or past `IFA_MAX`, bytes
/// left over, an attribute but `IFA_LOCAL` and `IFA_ADDRESS`, and one of
/// those of other than one byte. The ID is the last `IFA_LOCAL`, or else
/// the last `IFA_ADDRESS` (`EINVAL` for neither); the index is `lo`'s
/// (`ENODEV` for another). Adding, a broadcast or reserved ID (0 to 7 and
/// 255) is `EINVAL` and one `lo` has `EEXIST`; removing, one it has not is
/// `ENOENT`. Its local route comes and goes with it.
fn change_mctp_address(network: &Network, header: &Header, payload: &[u8]) -> Result<u8, Errno> {
    if payload.len() < 8 {
        return Err(Errno::EINVAL);
    }
    // `ifa_mctp_policy`: both are `NLA_U8`, and no other is taken.
    let attributes = policy_attributes(&payload[8..], IFA_MAX, |kind, nested, value| match kind {
        IFA_LOCAL | IFA_ADDRESS => exact(nested, value, 1),
        _ => Err(Errno::EINVAL),
    })?;
    let table = by_type(&attributes);
    let eid = table
        .get(&IFA_LOCAL)
        .or_else(|| table.get(&IFA_ADDRESS))
        .map(|value| value[0])
        .ok_or(Errno::EINVAL)?;
    if u32::from_le_bytes(payload[4..8].try_into().unwrap_or_default()) != 1 {
        return Err(ENODEV);
    }
    let mut addresses = network.addresses();
    let at = addresses.mctp.iter().position(|&e| e == eid);
    if header.kind == RTM_NEWADDR {
        // `mctp_address_unicast`.
        if !(8..255).contains(&eid) {
            return Err(Errno::EINVAL);
        }
        if at.is_some() {
            return Err(EEXIST);
        }
        addresses.mctp.push(eid);
        // `mctp_route_add_local`, whose failure for a route there is
        // already is not the address's.
        let local = MctpRoute {
            min: eid,
            max: eid,
            kind: RTN_LOCAL,
            mtu: 0,
            gateway: None,
        };
        if !addresses.mctp_routes.iter().any(|r| same_range(r, &local)) {
            addresses.mctp_routes.insert(0, local);
        }
    } else {
        let at = at.ok_or(Errno::ENOENT)?;
        addresses.mctp.remove(at);
        // `mctp_route_remove_local`, which may find none.
        addresses
            .mctp_routes
            .retain(|r| !(r.net() == 1 && r.min == eid && r.max == eid && r.kind == RTN_LOCAL));
    }
    Ok(eid)
}
/// Whether two MCTP routes cover the same range of the same network, which
/// `mctp_route_add` takes as a duplicate (`mctp_rt_compare_exact`).
fn same_range(a: &MctpRoute, b: &MctpRoute) -> bool {
    a.net() == b.net() && a.min == b.min && a.max == b.max
}
/// Adds (`RTM_NEWROUTE`) or removes (`RTM_DELROUTE`) an MCTP route, as
/// `mctp_newroute` and `mctp_delroute` do. The request is parsed as
/// `nlmsg_parse` does with `rta_mctp_policy`: `EINVAL` for a short
/// `rtmsg`, a type of 0 or past `RTA_MAX`, bytes left over, an attribute
/// but `RTA_DST` (one byte), `RTA_OIF` (four), `RTA_GATEWAY` (a
/// `mctp_fq_addr`, eight, `ERANGE` for another length) and `RTA_METRICS`
/// (nested, `ERANGE` for one of one to three bytes). Then, in
/// `mctp_route_nlparse_common`'s order: no `RTA_DST` is `EINVAL`, both
/// `RTA_OIF` and `RTA_GATEWAY` or neither `EINVAL`, an interface but `lo`
/// `ENODEV`, a gateway's broadcast or reserved ID `EINVAL`, and a type but
/// `RTN_UNICAST` `EINVAL`. A gateway in network 0 (`MCTP_NET_ANY`) is in
/// the default one, 1. The range is `RTA_DST` and the `rtm_dst_len` IDs
/// after it, `EINVAL` past 254.
///
/// Adding, `RTA_METRICS` is parsed with `rta_metrics_policy` (`EINVAL` for
/// anything but a four-byte `RTAX_MTU`); a route through `lo` is `EINVAL`
/// ("no routes to loopback"), as is a range from a reserved ID, and one of
/// a range a route of the network has `EEXIST`. Removing takes the
/// network, range and type alone, so `RTA_OIF` of `lo` names its network
/// too, whatever the gateway, and does not look inside `RTA_METRICS`
/// (`mctp_route_nlparse_lookup`); none is `ENOENT`. No notification goes
/// out.
fn change_mctp_route(network: &Network, header: &Header, payload: &[u8]) -> Result<(), Errno> {
    const RTN_UNICAST: u8 = 1;
    if payload.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let attributes = policy_attributes(&payload[12..], RTA_MAX, |kind, nested, value| {
        match kind {
            RTA_DST => exact(nested, value, 1),
            RTA_OIF => exact(nested, value, 4),
            // `NLA_POLICY_EXACT_LEN`, a binary range: `ERANGE` for
            // another length (`nla_validate_range_unsigned`).
            RTA_GATEWAY if nested => Err(Errno::EINVAL),
            RTA_GATEWAY if value.len() != 8 => Err(ERANGE),
            RTA_GATEWAY => Ok(()),
            // `NLA_NESTED`: marked, and empty or holding a header.
            RTA_METRICS if !nested => Err(Errno::EINVAL),
            RTA_METRICS if (1..4).contains(&value.len()) => Err(ERANGE),
            RTA_METRICS => Ok(()),
            _ => Err(Errno::EINVAL),
        }
    })?;
    let table = by_type(&attributes);
    let start = table.get(&RTA_DST).ok_or(Errno::EINVAL)?[0];
    let oif = table.get(&RTA_OIF).map_or(0, |value| {
        u32::from_le_bytes(value[..4].try_into().unwrap_or_default())
    });
    let gateway = match (oif, table.get(&RTA_GATEWAY)) {
        (0, None) | (1.., Some(_)) => return Err(Errno::EINVAL),
        (1, None) => None,
        (_, None) => return Err(ENODEV),
        (0, Some(value)) => {
            let eid = value[4];
            if !(8..255).contains(&eid) {
                return Err(Errno::EINVAL);
            }
            let net = u32::from_le_bytes(value[..4].try_into().unwrap_or_default());
            Some((if net == 0 { 1 } else { net }, eid))
        }
    };
    if payload[7] != RTN_UNICAST {
        return Err(Errno::EINVAL);
    }
    let extent = payload[1];
    if u16::from(start) + u16::from(extent) >= 255 {
        return Err(Errno::EINVAL);
    }
    let route = MctpRoute {
        min: start,
        max: start + extent,
        kind: RTN_UNICAST,
        mtu: 0,
        gateway,
    };
    let mut addresses = network.addresses();
    if header.kind == RTM_DELROUTE {
        let before = addresses.mctp_routes.len();
        addresses
            .mctp_routes
            .retain(|r| !(same_range(r, &route) && r.kind == RTN_UNICAST));
        return if addresses.mctp_routes.len() == before {
            Err(Errno::ENOENT)
        } else {
            Ok(())
        };
    }
    let mut mtu = 0;
    if let Some(metrics) = table.get(&RTA_METRICS) {
        let metrics = policy_attributes(metrics, RTAX_MAX, |kind, nested, value| match kind {
            RTAX_MTU => exact(nested, value, 4),
            _ => Err(Errno::EINVAL),
        })?;
        if let Some(value) = by_type(&metrics).get(&RTAX_MTU) {
            mtu = u32::from_le_bytes(value[..4].try_into().unwrap_or_default());
        }
    }
    if gateway.is_none() || start < 8 {
        return Err(Errno::EINVAL);
    }
    if addresses.mctp_routes.iter().any(|r| same_range(r, &route)) {
        return Err(EEXIST);
    }
    addresses.mctp_routes.insert(0, MctpRoute { mtu, ..route });
    Ok(())
}
/// What a route dump shows, as `struct fib_dump_filter`.
#[derive(Default)]
struct RouteFilter {
    /// `RTM_F_CLONED`: only the routes cached from others, of which there
    /// are none.
    cloned: bool,
    /// `RTM_F_PREFIX`: only prefix routes, of which there are none.
    prefix: bool,
    protocol: u8,
    kind: u8,
    table: u32,
    /// Only the routes through `lo` (`RTA_OIF`).
    device: bool,
    /// Whether the messages carry `NLM_F_DUMP_FILTERED`, as every message
    /// of a strict dump does, whose routes or exceptions are left out.
    marked: bool,
}
/// The filter of a route dump. Unchecked, only `RTM_F_PREFIX` is taken,
/// and `RTM_F_CLONED` changes nothing. Strictly, as `ip_valid_fib_dump_req`:
/// `EINVAL` for an `rtmsg` short or with a prefix length, a source prefix
/// length, a TOS or a scope, for flags but `RTM_F_CLONED` and
/// `RTM_F_PREFIX`, then `rtm_ipv4_policy`'s errors (for IPv6's too), and
/// for attributes but `RTA_TABLE` and `RTA_OIF`,
/// whose device is `ENODEV` but `lo`'s; the table, protocol and type, and
/// those, narrow it, as `NLM_F_DUMP_FILTERED` in `NLMSG_DONE` too.
fn route_filter(payload: &[u8], strict: bool, answer: &mut u16) -> Result<RouteFilter, Errno> {
    let flags = payload.get(8..12).map_or(0, |raw| {
        u32::from_le_bytes(raw.try_into().unwrap_or_default())
    });
    if !strict {
        return Ok(RouteFilter {
            prefix: payload.len() >= 12 && flags & RTM_F_PREFIX != 0,
            ..RouteFilter::default()
        });
    }
    if payload.len() < 12 || payload[1..4] != [0; 3] || payload[6] != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(RTM_F_CLONED | RTM_F_PREFIX) != 0 {
        return Err(Errno::EINVAL);
    }
    let mut filter = RouteFilter {
        cloned: flags & RTM_F_CLONED != 0,
        prefix: flags & RTM_F_PREFIX != 0,
        protocol: payload[5],
        kind: payload[7],
        table: u32::from(payload[4]),
        device: false,
        marked: true,
    };
    // `rtm_ipv4_policy`, for IPv6's too.
    let attributes = by_type(&parse_policy(&payload[12..], &RTA4_POLICY, true)?);
    for (&kind, &value) in &attributes {
        match kind {
            RTA_TABLE => filter.table = u32_value(value)?,
            RTA_OIF if u32_value(value)? == 1 => filter.device = true,
            RTA_OIF => return Err(ENODEV),
            _ => return Err(Errno::EINVAL),
        }
    }
    if flags != 0 || filter.protocol != 0 || filter.kind != 0 || filter.table != 0 || filter.device
    {
        *answer = NLM_F_DUMP_FILTERED;
    }
    Ok(filter)
}
/// A route dump: IPv4's routes of every table, as `fib_dump_info` gives
/// them, then IPv6's, as `rt6_fill_node` does, as `rtnl_dump_all` dumps
/// each family's, or the one family's; the multicast routing tables have
/// none. A table the filter names ([`route_filter`]) that the family has
/// not made is `ENOENT` for a dump of that family alone (the multicast
/// ones have only `RT_TABLE_DEFAULT` for IPv4 and `RT6_TABLE_DFLT`, 254,
/// for IPv6), and shows nothing of it otherwise.
fn route_dump(
    network: &Network,
    payload: &[u8],
    family: u8,
    seq: u32,
    port: u32,
    strict: bool,
    answer: &mut u16,
) -> Result<Vec<Vec<u8>>, Errno> {
    let filter = route_filter(payload, strict, answer)?;
    let flags = NLM_F_MULTI
        | if filter.marked {
            NLM_F_DUMP_FILTERED
        } else {
            0
        };
    let taken = |table: u32, kind: u8, proto: u8, device: bool| {
        !filter.cloned
            && !filter.prefix
            && (filter.table == 0 || filter.table == table)
            && (filter.kind == 0 || filter.kind == kind)
            && (filter.protocol == 0 || filter.protocol == proto)
            && (!filter.device || device)
    };
    if matches!(family, RTNL_FAMILY_IPMR | RTNL_FAMILY_IP6MR) {
        let only = if family == RTNL_FAMILY_IPMR {
            RT_TABLE_DEFAULT
        } else {
            RT6_TABLE_DFLT
        };
        if filter.table != 0 && filter.table != only {
            return Err(Errno::ENOENT);
        }
        return Ok(Vec::new());
    }
    let addresses = network.addresses();
    let mut messages = Vec::new();
    // `inet_dump_fib` looks at `RTM_F_PREFIX` before the table.
    if family != AF_INET6 && !filter.prefix {
        if filter.table != 0 && !addresses.has_table4(filter.table) {
            if family == AF_INET {
                return Err(Errno::ENOENT);
            }
        } else {
            messages.extend(
                addresses
                    .dump4()
                    .iter()
                    .filter(|r| taken(r.table, r.kind.code(), r.proto, r.device))
                    .map(|r| ipv4_route_of(RTM_NEWROUTE, r, r.table, seq, port, flags)),
            );
        }
    }
    if family != AF_INET {
        if filter.table != 0 && !addresses.has_table6(filter.table) {
            if family == AF_INET6 {
                return Err(Errno::ENOENT);
            }
        } else {
            messages.extend(
                addresses
                    .dump6()
                    .iter()
                    .filter(|r| taken(r.table, r.kind.code(), r.proto, true))
                    .map(|r| ipv6_route_of(RTM_NEWROUTE, r, seq, port, flags)),
            );
        }
    }
    drop(addresses);
    // `rtnl_dump_all` goes on to MCTP's, which takes no filter.
    if !matches!(family, AF_INET | AF_INET6) {
        messages.extend(mctp_routes(network, seq, port));
    }
    Ok(messages)
}
/// A route lookup's checks, as `inet_rtm_valid_getroute_req` and
/// `inet6_rtm_valid_getroute_req` make them: `EINVAL` for a request
/// shorter than an `rtmsg`, then the family's policy (`rtm_ipv4_policy`,
/// `rtm_ipv6_policy`) unless `strict`. Strictly, it takes: prefix lengths of 0 or the whole
/// address, and one where `RTA_SRC` or `RTA_DST` is given; no table,
/// protocol, scope or type; of the flags only `RTM_F_FIB_MATCH`, and for
/// IPv4 `RTM_F_NOTIFY` and `RTM_F_LOOKUP_TABLE` too; an IPv6 flow label
/// of 20 bits; and only the attributes that select a route. Anything else
/// is `EINVAL`, but the policy's errors, which come after the header's.
fn lookup_check(payload: &[u8], strict: bool) -> Result<(), Errno> {
    if payload.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let v6 = payload[0] == AF_INET6;
    let policy = if v6 { &RTA6_POLICY } else { &RTA4_POLICY };
    if !strict {
        return parse_policy(&payload[12..], policy, false).map(drop);
    }
    let whole = if v6 { 128 } else { 32 };
    let (dst_len, src_len) = (payload[1], payload[2]);
    let flags = u32::from_le_bytes(payload[8..12].try_into().unwrap_or_default());
    let allowed = if v6 {
        RTM_F_FIB_MATCH
    } else {
        RTM_F_NOTIFY | RTM_F_LOOKUP_TABLE | RTM_F_FIB_MATCH
    };
    if (src_len != 0 && src_len != whole)
        || (dst_len != 0 && dst_len != whole)
        || payload[4..8] != [0; 4]
        || flags & !allowed != 0
    {
        return Err(Errno::EINVAL);
    }
    let attributes = by_type(&parse_policy(&payload[12..], policy, true)?);
    if (attributes.contains_key(&RTA_SRC) && src_len == 0)
        || (attributes.contains_key(&RTA_DST) && dst_len == 0)
    {
        return Err(Errno::EINVAL);
    }
    // The policy takes an `NLA_BE32` of 4 bytes alone, past its
    // `strict_start_type`.
    if v6
        && let Some(label) = attributes.get(&RTA_FLOWLABEL).and_then(|v| v.first_chunk())
        && u32::from_be_bytes(*label) & !0x000f_ffff != 0
    {
        return Err(Errno::EINVAL);
    }
    let selects = |kind: u16| {
        matches!(
            kind,
            RTA_SRC
                | RTA_DST
                | RTA_IIF
                | RTA_OIF
                | RTA_MARK
                | RTA_UID
                | RTA_SPORT
                | RTA_DPORT
                | RTA_IP_PROTO
        ) || (v6 && kind == RTA_FLOWLABEL)
    };
    if attributes.keys().any(|&kind| !selects(kind)) {
        return Err(Errno::EINVAL);
    }
    Ok(())
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
    let mut inet = Vec::new();
    attribute(
        &mut inet,
        IFLA_INET_CONF,
        &INET
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    // MCTP's, first, as a kernel built with it (Ubuntu's) gives: its
    // default network, 1, and no physical binding.
    let mut mctp = Vec::new();
    attribute(&mut mctp, IFLA_MCTP_NET, &1u32.to_le_bytes());
    attribute(&mut mctp, IFLA_MCTP_PHYS_BINDING, &[0]);
    let mut spec = Vec::new();
    attribute(&mut spec, u16::from(AF_MCTP), &mctp);
    attribute(&mut spec, u16::from(AF_INET), &inet);
    attribute(&mut spec, u16::from(AF_INET6), &inet6_settings(up, stats));
    spec
}
/// `lo`'s IPv6 settings, as `inet6_fill_ifla6_attrs` gives them, for
/// [`af_spec`] and [`inet6_link_message`].
fn inet6_settings(up: bool, stats: bool) -> Vec<u8> {
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
    inet6
}
/// `RTM_NEWLINK` for `lo` in an AF_INET6 link dump, as `inet6_fill_ifinfo`
/// gives it: an `ifinfomsg` of AF_INET6, its name, hardware address, MTU and
/// state (no `IFLA_LINK`, as `lo` is its own), then its IPv6 settings, with
/// their statistics, in `IFLA_PROTINFO`, which is not marked nested.
fn inet6_link_message(network: &Network, seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let up = network.is_up();
    let mut body = vec![AF_INET6, 0];
    body.extend_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes());
    body.extend_from_slice(&link_flags(network).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    attribute(&mut body, IFLA_IFNAME, b"lo\0");
    attribute(&mut body, IFLA_ADDRESS, &[0; 6]);
    attribute(&mut body, IFLA_MTU, &LO_MTU.to_le_bytes());
    let operstate = if up { IF_OPER_UNKNOWN } else { IF_OPER_DOWN };
    attribute(&mut body, IFLA_OPERSTATE, &[operstate]);
    attribute(&mut body, IFLA_PROTINFO, &inet6_settings(up, true));
    message(RTM_NEWLINK, flags, seq, port, &body)
}
/// `RTM_NEWLINK` for the IPv4 multicast routing table in an
/// `RTNL_FAMILY_IPMR` link dump, as `ipmr_rtm_dumplink` gives it: an
/// `ifinfomsg` with nothing but the family, then, in an `IFLA_AF_SPEC` that
/// is not marked nested, what `ipmr_fill_table` tells of the table a
/// namespace starts with, `RT_TABLE_DEFAULT`, which no socket has set up
/// (no register VIF, assert, PIM or whole-packet `WRVIFWHOLE`, and nothing
/// waiting to be resolved), and its VIFs, of which it has none.
fn ipmr_link_message(seq: u32, port: u32) -> Vec<u8> {
    let mut body = vec![RTNL_FAMILY_IPMR];
    body.resize(16, 0);
    let mut table = Vec::new();
    attribute(&mut table, IPMRA_TABLE_ID, &RT_TABLE_DEFAULT.to_le_bytes());
    attribute(
        &mut table,
        IPMRA_TABLE_CACHE_RES_QUEUE_LEN,
        &0u32.to_le_bytes(),
    );
    attribute(
        &mut table,
        IPMRA_TABLE_MROUTE_REG_VIF_NUM,
        &(-1i32).to_le_bytes(),
    );
    attribute(&mut table, IPMRA_TABLE_MROUTE_DO_ASSERT, &[0]);
    attribute(&mut table, IPMRA_TABLE_MROUTE_DO_PIM, &[0]);
    attribute(&mut table, IPMRA_TABLE_MROUTE_DO_WRVIFWHOLE, &[0]);
    attribute(&mut table, IPMRA_TABLE_VIFS, &[]);
    attribute(&mut body, IFLA_AF_SPEC, &table);
    message(RTM_NEWLINK, NLM_F_MULTI, seq, port, &body)
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
/// them: `EINVAL` for a message shorter than an `ifaddrmsg`; then the
/// family's policy (`ifa_ipv4_policy`, `ifa_ipv6_policy`, which has no
/// label or broadcast address); `EINVAL` for an IPv4 prefix past 32 or an IPv6 one past 128, an IPv4 address without
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
    let v4 = family == AF_INET;
    let policy = if v4 { &IFA4_POLICY } else { &IFA6_POLICY };
    // The policy has made each as long as it reads; IPv6 has no label or
    // broadcast address.
    for (kind, value) in parse_policy(&payload[8..], policy, false)? {
        match kind {
            IFA_LOCAL => local = Some(value),
            IFA_ADDRESS => address = Some(value),
            IFA_BROADCAST if v4 => broadcast = value.first_chunk::<4>().copied(),
            IFA_LABEL if v4 => {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                label = Some(value[..end].to_vec());
            }
            IFA_FLAGS => flags = u32_value(value)?,
            IFA_PROTO => proto = value.first().copied().unwrap_or_default(),
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
    put_metrics(&mut body, &route.metrics);
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
    put_metrics(&mut body, &route.metrics);
    attribute(&mut body, RTA_PRIORITY, &route.metric.to_le_bytes());
    attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
    attribute(&mut body, RTA_CACHEINFO, &[0; RTA_CACHEINFO_LEN]);
    attribute(&mut body, RTA_PREF, &[0]);
    message(kind, flags, seq, port, &body)
}
/// A route lookup (`RTM_GETROUTE` without a dump), as `inet_rtm_getroute`
/// and `inet6_rtm_getroute` answer one for the destination `RTA_DST` names
/// (none is `0.0.0.0` or `::`), by the routing tables
/// ([`crate::interface::Addresses::lookup4_flow`] and `lookup6`): `EINVAL`
/// for a request shorter than an `rtmsg`; an IPv6 source or destination
/// shorter than 16 bytes is `EINVAL` (an IPv4 one is the policy's
/// `ERANGE`), and a longer one counts as its first bytes; `EOPNOTSUPP` for
/// an `RTA_IP_PROTO` but TCP, UDP and the family's ICMP
/// (`rtm_getroute_parse_ip_proto`); then `ENODEV` for an input route
/// (`RTA_IIF`) of another device than `lo`, and `EOPNOTSUPP` for one of
/// `lo`, which is not supported.
///
/// IPv4, as `ip_route_output_key_hash_rcu`: a source (`RTA_SRC`) is
/// `EINVAL` when multicast or the limited broadcast address and
/// `ENETUNREACH` when not the loopback's
/// ([`crate::interface::Addresses::is_local4`]); an output device (`RTA_OIF`) is `ENODEV` but for `lo`, and
/// `ENETUNREACH` while it is down. `0.0.0.0` goes to the loopback, from
/// the source, or else from `127.0.0.1` (with a device, from the address
/// `inet_select_addr` picks of host scope). The tables are looked in by the
/// request's TOS; where they give an error and a device is named, the
/// route is on link through it instead, from an address of link scope. The
/// answer gives the TOS of the route that matched, the source as `RTA_SRC`
/// where the request names one, and else the source the route leaves from
/// as `RTA_PREFSRC`; the `RTA_MARK` it names, but 0 (`ERANGE` when shorter
/// than 4 bytes); and the `RTA_UID` it names (`ERANGE` when shorter than 4
/// bytes, for either family, as both policies take a `u32`), as it is, or
/// the caller's. It names the main table but with `RTM_F_LOOKUP_TABLE`,
/// the table it came from (the main one for the local one, whose trie it
/// shares), or 0 where no table gave it. With `RTM_F_FIB_MATCH` the answer
/// is the table's entry that matched, and `EHOSTUNREACH` where none did.
/// With `RTM_F_NOTIFY` its flags have `RTM_F_NOTIFY` and `RTCF_NOTIFY`,
/// which Linux keeps on the cached route, so that later lookups through it
/// show them too, and this does not.
///
/// IPv6, as `ip6_route_output`: `ENETUNREACH` while `lo` is down, and for
/// an output device but `lo` without a source, or to a loopback,
/// link-local or multicast address (`RT6_LOOKUP_F_IFACE`); the answer
/// gives the request's source as `RTA_SRC`. The mark, the user ID, the
/// protocol and the ports choose among policy rules and multipath routes,
/// of which there are none, so they change nothing.
fn lookup(
    network: &Network,
    payload: &[u8],
    seq: u32,
    port: u32,
    uid: u32,
) -> Result<Vec<u8>, Errno> {
    use crate::interface::{Kind, NO_METRICS, SCOPE_HOST, SCOPE_LINK, SCOPE_UNIVERSE};
    use crate::interface::{TABLE_LOCAL, TABLE_MAIN};
    use core::net::{Ipv4Addr, Ipv6Addr};
    if payload.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let family = payload[0];
    let tos = payload[3];
    let request_flags = u32::from_le_bytes(payload[8..12].try_into().unwrap_or_default());
    let mut dst = None;
    let mut src = None;
    let mut asked_uid = None;
    let mut mark = 0;
    let mut iif = 0;
    let mut oif = 0;
    let mut proto = None;
    let number = |value: &[u8]| -> Result<u32, Errno> {
        Ok(u32::from_le_bytes(*value.first_chunk().ok_or(ERANGE)?))
    };
    for (kind, value) in attributes(&payload[12..]) {
        match kind {
            RTA_DST => dst = Some(value),
            RTA_SRC => src = Some(value),
            RTA_IIF => iif = number(value)?,
            RTA_OIF => oif = number(value)?,
            RTA_UID => asked_uid = Some(number(value)?),
            RTA_MARK => mark = number(value)?,
            RTA_IP_PROTO => proto = Some(value.first().copied().unwrap_or_default()),
            _ => {}
        }
    }
    let v6 = family == AF_INET6;
    // `inet6_rtm_getroute` takes the addresses first.
    let (mut source6, mut address6) = ([0u8; 16], [0u8; 16]);
    if v6 {
        if let Some(value) = src {
            source6 = *value.first_chunk().ok_or(Errno::EINVAL)?;
        }
        if let Some(value) = dst {
            address6 = *value.first_chunk().ok_or(Errno::EINVAL)?;
        }
    }
    let icmp = if v6 { 58 } else { 1 };
    if proto.is_some_and(|p| !matches!(p, 6 | 17) && p != icmp) {
        return Err(EOPNOTSUPP);
    }
    if iif != 0 {
        return Err(if iif == 1 { EOPNOTSUPP } else { ENODEV });
    }
    let fib_match = request_flags & RTM_F_FIB_MATCH != 0;
    let addresses = network.addresses();
    if v6 {
        let ip = Ipv6Addr::from(address6);
        if !network.is_up() {
            return Err(ENETUNREACH);
        }
        // `rt6_score_route`: a route must go through the device named
        // (`RT6_LOOKUP_F_IFACE`) with no source, or to a loopback,
        // link-local or multicast address (`rt6_need_strict`), and every
        // one goes through `lo`.
        let strict = ip.is_loopback() || ip.is_unicast_link_local() || ip.is_multicast();
        if oif != 0 && oif != 1 && (strict || source6 == [0; 16]) {
            return Err(ENETUNREACH);
        }
        let route = addresses.lookup6(ip)?;
        if fib_match {
            return Ok(ipv6_route_of(RTM_NEWROUTE, &route, seq, port, 0));
        }
        // `rt6_fill_node` of the route the lookup made, with the request's
        // source, and the source it leaves from, then the route's own
        // preferred source again.
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
        attribute(&mut body, RTA_DST, &address6);
        attribute(&mut body, RTA_SRC, &source6);
        if let Some(source) = addresses.source6(&route, ip) {
            attribute(&mut body, RTA_PREFSRC, &source.octets());
        }
        if let Some(source) = route.prefsrc {
            attribute(&mut body, RTA_PREFSRC, &source.octets());
        }
        // The route's metrics, which its `rt6_info` shares.
        put_metrics(&mut body, &route.metrics);
        attribute(&mut body, RTA_PRIORITY, &route.metric.to_le_bytes());
        attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
        attribute(&mut body, RTA_CACHEINFO, &lookup_cacheinfo());
        attribute(&mut body, RTA_PREF, &[0]);
        return Ok(message(RTM_NEWROUTE, 0, seq, port, &body));
    }
    let four = |value: Option<&[u8]>| -> Result<[u8; 4], Errno> {
        value.map_or(Ok([0; 4]), |v| v.first_chunk().copied().ok_or(ERANGE))
    };
    let (address, asked_source) = (four(dst)?, four(src)?);
    let ip = Ipv4Addr::from(address);
    let named = Ipv4Addr::from(asked_source);
    let mut source = named;
    if !named.is_unspecified() {
        if named.is_multicast() || named.is_broadcast() {
            return Err(Errno::EINVAL);
        }
        if !addresses.is_local4(named) {
            return Err(ENETUNREACH);
        }
    }
    if oif != 0 {
        if oif != 1 {
            return Err(ENODEV);
        }
        if !network.is_up() {
            return Err(ENETUNREACH);
        }
        if source.is_unspecified() {
            let scope = if ip.is_multicast() {
                Some(SCOPE_UNIVERSE)
            } else if ip.is_unspecified() {
                Some(SCOPE_HOST)
            } else {
                None
            };
            if let Some(picked) = scope.and_then(|scope| addresses.select4(None, scope)) {
                source = picked;
            }
        }
    }
    let lookup_table = request_flags & RTM_F_LOOKUP_TABLE != 0;
    // The route's kind, the TOS it matched, its gateway, the table it came
    // from (none for a route no table gave) and its metrics.
    let (kind, matched_tos, gateway, table, metrics): (
        Kind,
        u8,
        Option<Ipv4Addr>,
        Option<u32>,
        crate::interface::Metrics,
    );
    if ip.is_unspecified() {
        if fib_match {
            return Err(EHOSTUNREACH);
        }
        if source.is_unspecified() {
            source = Ipv4Addr::LOCALHOST;
        }
        (kind, matched_tos, gateway, table, metrics) = (Kind::Local, 0, None, None, NO_METRICS);
    } else {
        match addresses.lookup4_flow(ip, tos, oif) {
            Ok(route) => {
                let from = if route.table == TABLE_LOCAL {
                    TABLE_MAIN
                } else {
                    route.table
                };
                if fib_match {
                    let named = if lookup_table { from } else { TABLE_MAIN };
                    return Ok(ipv4_route_of(RTM_NEWROUTE, &route, named, seq, port, 0));
                }
                if source.is_unspecified()
                    && let Some(picked) = addresses.source4(&route, ip)
                {
                    source = picked;
                }
                // `__mkroute_output` drops the route's `fib_info`, and so
                // its metrics, for the limited broadcast address, and for a
                // multicast one when the route is shorter than
                // 224.0.0.0/4's prefix (the default route, which it takes
                // for want of a multicast one).
                let held = if ip.is_broadcast() || (ip.is_multicast() && route.len < 4) {
                    NO_METRICS
                } else {
                    route.metrics
                };
                let via = route.gateway.filter(|_| route.uses_gateway);
                (kind, matched_tos, gateway, table, metrics) =
                    (route.kind, route.tos, via, Some(from), held);
            }
            // With a device named, the destination is taken to be on link.
            Err(_) if oif != 0 => {
                if fib_match {
                    return Err(EHOSTUNREACH);
                }
                if source.is_unspecified()
                    && let Some(picked) = addresses.select4(None, SCOPE_LINK)
                {
                    source = picked;
                }
                (kind, matched_tos, gateway, table, metrics) =
                    (Kind::Unicast, 0, None, None, NO_METRICS);
            }
            Err(e) => return Err(e),
        }
    }
    let table = if lookup_table {
        table.unwrap_or(0)
    } else {
        TABLE_MAIN
    };
    // `rt_fill_info` of the cached route the lookup made, which is local as
    // it goes through `lo`.
    let mut flags = if kind == Kind::Broadcast {
        RTM_F_CLONED | RTCF_LOCAL | RTCF_BROADCAST
    } else {
        RTM_F_CLONED | RTCF_LOCAL
    };
    if request_flags & RTM_F_NOTIFY != 0 {
        flags |= RTM_F_NOTIFY | RTCF_NOTIFY;
    }
    let mut body = vec![
        AF_INET,
        32,
        if named.is_unspecified() { 0 } else { 32 },
        matched_tos,
        table_byte(table),
        0,
        RT_SCOPE_UNIVERSE,
        kind.code(),
    ];
    body.extend_from_slice(&flags.to_le_bytes());
    attribute(&mut body, RTA_TABLE, &table.to_le_bytes());
    attribute(&mut body, RTA_DST, &address);
    if !named.is_unspecified() {
        attribute(&mut body, RTA_SRC, &asked_source);
    }
    attribute(&mut body, RTA_OIF, &1u32.to_le_bytes());
    if source != named {
        attribute(&mut body, RTA_PREFSRC, &source.octets());
    }
    if let Some(gateway) = gateway {
        attribute(&mut body, RTA_GATEWAY, &gateway.octets());
    }
    put_metrics(&mut body, &metrics);
    // The mark it names, but 0, as `rt_fill_info` gives it; an invalid
    // user ID (-1) is left out (`uid_valid`).
    if mark != 0 {
        attribute(&mut body, RTA_MARK, &mark.to_le_bytes());
    }
    let uid = asked_uid.unwrap_or(uid);
    if uid != u32::MAX {
        attribute(&mut body, RTA_UID, &uid.to_le_bytes());
    }
    attribute(&mut body, RTA_CACHEINFO, &lookup_cacheinfo());
    Ok(message(RTM_NEWROUTE, 0, seq, port, &body))
}
/// An `RTM_NEWROUTE` or `RTM_DELROUTE` request, as `inet_rtm_newroute`,
/// `inet_rtm_delroute`, `inet6_rtm_newroute` and `inet6_rtm_delroute`
/// take it ([`crate::interface::Addresses::add_route4`] and the others):
/// `EINVAL` for one shorter than an `rtmsg`; then the family's policy
/// (`rtm_ipv4_policy`, `rtm_ipv6_policy`), and `EINVAL` for an IPv6
/// destination shorter than its prefix; then `EINVAL` for a TOS with ECN
/// bits (any for IPv6; other bits past the legacy TOS ones are taken, and
/// such a route matches no lookup, as on Linux) or a kind past `RTN_MAX`.
/// Multipath routes, encapsulations, nexthop objects, realms, expiries,
/// IPv6 gateways, source prefixes and router preferences are
/// `EOPNOTSUPP`. A route added takes the metrics `RTA_METRICS` holds
/// ([`convert_metrics`]); an IPv4 one removed must have those it names
/// ([`metrics_match`]), and IPv6's does not look. The table is the
/// `rtmsg`'s, or the one `RTA_TABLE` names.
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
    let mut metrics = None;
    let mut unsupported = src_len != 0 && v6;
    let number = |value: &[u8]| -> Result<u32, Errno> {
        Ok(u32::from_le_bytes(*value.first_chunk().ok_or(ERANGE)?))
    };
    let address = |value: &[u8]| -> Result<Vec<u8>, Errno> {
        value.get(..size).map(<[u8]>::to_vec).ok_or(ERANGE)
    };
    let policy = if v6 { &RTA6_POLICY } else { &RTA4_POLICY };
    for (attr, value) in parse_policy(&payload[12..], policy, false)? {
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
            RTA_METRICS => metrics = Some(value),
            RTA_MULTIPATH | RTA_FLOW | RTA_VIA | RTA_ENCAP | RTA_EXPIRES | RTA_NH_ID => {
                unsupported = true;
            }
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
    let converted = metrics.map_or(Ok(crate::interface::NO_METRICS), convert_metrics);
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
            metrics: converted,
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
                metrics: converted,
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
        metrics: metrics.map_or(Some(Vec::new()), metrics_match),
    })
}
/// The key of the congestion control `RTAX_CC_ALGO`'s `value` names, as
/// `nla_strscpy` and `tcp_ca_get_key_by_name` find it: to a NUL, in at
/// most 15 bytes; 0 (`TCP_CA_UNSPEC`) for none of
/// [`CONGESTION_CONTROLS`]. Linux would load a module for another name.
fn congestion_key(value: &[u8]) -> u32 {
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    let value = &value[..value.len().min(15)];
    let name = value.split(|&b| b == 0).next().unwrap_or_default();
    CONGESTION_CONTROLS
        .iter()
        .find(|&&(_, known)| known == name)
        .map_or(0, |&(key, _)| key)
}
/// A route's metrics from its `RTA_METRICS`, as `ip_metrics_convert`
/// reads them: each attribute in turn, as `nla_for_each_attr` takes
/// them, type 0 passed over; `EINVAL` for a type past `RTAX_MAX`, for a
/// value of other than four bytes but `RTAX_CC_ALGO`'s, for a congestion
/// control there is not, for features past `RTAX_FEATURE_MASK`, and for
/// a locked congestion window of 0. `RTAX_ADVMSS` is held to 65495,
/// `RTAX_MTU` to 65520 and `RTAX_HOPLIMIT` to 255.
fn convert_metrics(bytes: &[u8]) -> Result<crate::interface::Metrics, Errno> {
    let mut metrics = crate::interface::NO_METRICS;
    for (kind, value) in attributes(bytes) {
        if kind == 0 {
            continue;
        }
        if kind > RTAX_MAX {
            return Err(Errno::EINVAL);
        }
        let mut number = if kind == RTAX_CC_ALGO {
            match congestion_key(value) {
                0 => return Err(Errno::EINVAL),
                key => key,
            }
        } else {
            u32::from_le_bytes(value.try_into().map_err(|_| Errno::EINVAL)?)
        };
        match kind {
            RTAX_ADVMSS => number = number.min(65535 - 40),
            RTAX_MTU => number = number.min(65535 - 15),
            RTAX_HOPLIMIT => number = number.min(255),
            RTAX_FEATURES if number & !RTAX_FEATURE_MASK != 0 => return Err(Errno::EINVAL),
            _ => {}
        }
        metrics[usize::from(kind - 1)] = number;
    }
    let locked = metrics[usize::from(RTAX_LOCK - 1)] & (1 << RTAX_CWND) != 0;
    if locked && metrics[usize::from(RTAX_CWND - 1)] == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(metrics)
}
/// The metrics an IPv4 removal names, as `fib_metrics_match` compares
/// them, unheld: each type, with a congestion control's key (0 for one
/// there is not); `None`, which no route matches, for a type past
/// `RTAX_MAX` or a value of other than four bytes but a congestion
/// control's.
fn metrics_match(bytes: &[u8]) -> Option<Vec<(usize, u32)>> {
    let mut wanted = Vec::new();
    for (kind, value) in attributes(bytes) {
        if kind == 0 {
            continue;
        }
        if kind > RTAX_MAX {
            return None;
        }
        let number = if kind == RTAX_CC_ALGO {
            congestion_key(value)
        } else {
            u32::from_le_bytes(value.try_into().ok()?)
        };
        wanted.push((usize::from(kind - 1), number));
    }
    Some(wanted)
}
/// A route's `RTA_METRICS`, as `rtnetlink_put_metrics` gives it, unmarked
/// as nested: each metric but 0, in order, a congestion control by its
/// name, and features only those of `RTAX_FEATURE_MASK`; nothing when
/// none is left.
fn put_metrics(body: &mut Vec<u8>, metrics: &crate::interface::Metrics) {
    let mut nest = Vec::new();
    for (kind, &value) in (1..=RTAX_MAX).zip(metrics) {
        let value = if kind == RTAX_FEATURES {
            value & RTAX_FEATURE_MASK
        } else {
            value
        };
        if value == 0 {
            continue;
        }
        if kind == RTAX_CC_ALGO {
            if let Some(&(_, name)) = CONGESTION_CONTROLS.iter().find(|&&(key, _)| key == value) {
                let mut name = name.to_vec();
                name.push(0);
                attribute(&mut nest, kind, &name);
            }
        } else {
            attribute(&mut nest, kind, &value.to_le_bytes());
        }
    }
    if !nest.is_empty() {
        attribute(body, RTA_METRICS, &nest);
    }
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
/// first (`rtmsg_ifinfo`), then what happens to its addresses and routes;
/// coming up, last, IPv6's own `RTM_NEWLINK` for `RTNLGRP_IPV6_IFINFO`, as
/// `addrconf_notify` sends it at the end of `NETDEV_UP`
/// (`inet6_ifinfo_notify`). Going down tells IPv6's group nothing.
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
    if up {
        notices.push(Notice {
            group: RTNLGRP_IPV6_IFINFO,
            origin: 0,
            bytes: inet6_link_message(network, 0, 0, 0),
        });
    }
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
/// The mask of group number `group` (`netlink_group_mask`): none for 0, or
/// for a group past the 32 a `sockaddr_nl` has bits for.
fn group_mask(group: u32) -> u32 {
    if group == 0 || group > 32 {
        0
    } else {
        1 << (group - 1)
    }
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
/// `NETLINK_EXT_ACK`, which is kept, though no error carries extended
/// attributes, and `NETLINK_GET_STRICT_CHK`, by which dumps, link requests
/// and route lookups are checked strictly. Any other option is
/// `ENOPROTOOPT`.
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
    /// A route dump of `family`'s routes alone, unchecked, to port 7.
    fn routes(network: &Network, family: u8, seq: u32) -> Vec<Vec<u8>> {
        route_dump(network, &[family], family, seq, 7, false, &mut 0).unwrap()
    }
    #[test]
    fn inet_routes_keep_check_and_show_their_metrics() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let request = |kind: u16, flags: u16, dst: &[u8], len: u8, metrics: Option<&[u8]>| {
            let family = if dst.len() == 4 { AF_INET } else { AF_INET6 };
            let mut payload = vec![family, len, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
            attribute(&mut payload, RTA_DST, dst);
            attribute(&mut payload, RTA_OIF, &1u32.to_le_bytes());
            if let Some(metrics) = metrics {
                attribute(&mut payload, RTA_METRICS, metrics);
            }
            let header = Header {
                len: 0,
                kind,
                flags: NLM_F_REQUEST | flags,
                seq: 1,
            };
            change_route(&network, &header, &payload)
        };
        let nest = |metrics: &[(u16, &[u8])]| {
            let mut nest = Vec::new();
            for &(kind, value) in metrics {
                attribute(&mut nest, kind, value);
            }
            nest
        };
        let word = |value: u32| value.to_le_bytes();
        // The routes' metrics in a dump of `family`, those to `dst`.
        let shown = |family: u8, dst: &[u8]| -> Vec<Vec<u8>> {
            routes(&network, family, 1)
                .iter()
                .filter(|m| attributes(&m[28..]).contains(&(RTA_DST, dst)))
                .map(|m| {
                    let found = attributes(&m[28..]);
                    let at = found.iter().position(|&(k, _)| k == RTA_METRICS);
                    at.map(|i| found[i].1.to_vec()).unwrap_or_default()
                })
                .collect()
        };
        // Held to their limits, a type of 0 and a value of 0 left out, and
        // the congestion control by name.
        let (big, hops, one, zero) = (word(70_000), word(300), word(1), word(0));
        let metrics = nest(&[
            (0, &one),
            (RTAX_MTU, &big),
            (RTAX_ADVMSS, &big),
            (RTAX_HOPLIMIT, &hops),
            (RTAX_FEATURES, &one),
            (3, &zero),
            (RTAX_CC_ALGO, b"cubic\0"),
        ]);
        let net8 = [10, 8, 0, 0];
        assert!(request(RTM_NEWROUTE, 0x600, &net8, 16, Some(&metrics)).is_ok());
        let held = nest(&[
            (RTAX_MTU, &word(65520)),
            (RTAX_ADVMSS, &word(65495)),
            (RTAX_HOPLIMIT, &word(255)),
            (RTAX_FEATURES, &one),
            (RTAX_CC_ALGO, b"cubic\0"),
        ]);
        assert_eq!(shown(AF_INET, &net8), std::slice::from_ref(&held));
        // After RTA_PRIORITY and before RTA_PREFSRC, as fib_dump_info puts
        // them; a lookup's answer has them too.
        let mut lookup_request = vec![AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        attribute(&mut lookup_request, RTA_DST, &[10, 8, 1, 1]);
        let answer = lookup(&network, &lookup_request, 1, 7, u32::MAX).unwrap();
        assert!(attributes(&answer[28..]).contains(&(RTA_METRICS, &held[..])));
        // A lookup of the limited broadcast address drops them, as
        // `__mkroute_output` drops the route's `fib_info`.
        assert!(request(RTM_NEWROUTE, 0x600, &[0; 4], 0, Some(&held)).is_ok());
        let mut broadcast = vec![AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        attribute(&mut broadcast, RTA_DST, &[255; 4]);
        let answer = lookup(&network, &broadcast, 1, 7, u32::MAX).unwrap();
        assert!(
            !attributes(&answer[28..])
                .iter()
                .any(|&(k, _)| k == RTA_METRICS)
        );
        let mut elsewhere = vec![AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        attribute(&mut elsewhere, RTA_DST, &[192, 0, 2, 1]);
        let answer = lookup(&network, &elsewhere, 1, 7, u32::MAX).unwrap();
        assert!(attributes(&answer[28..]).contains(&(RTA_METRICS, &held[..])));
        // So does one of a multicast address through the default route,
        // but not through a multicast route of its own.
        let mut group = vec![AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        attribute(&mut group, RTA_DST, &[224, 0, 0, 1]);
        let answer = lookup(&network, &group, 1, 7, u32::MAX).unwrap();
        assert!(
            !attributes(&answer[28..])
                .iter()
                .any(|&(k, _)| k == RTA_METRICS)
        );
        assert!(request(RTM_NEWROUTE, 0x600, &[224, 0, 0, 0], 4, Some(&held)).is_ok());
        let answer = lookup(&network, &group, 1, 7, u32::MAX).unwrap();
        assert!(attributes(&answer[28..]).contains(&(RTA_METRICS, &held[..])));
        // A request that names other metrics adds another route; the same
        // again is EEXIST.
        let mtu = nest(&[(RTAX_MTU, &word(1400))]);
        assert!(request(RTM_NEWROUTE, NLM_F_CREATE, &net8, 16, Some(&mtu)).is_ok());
        assert_eq!(
            request(RTM_NEWROUTE, NLM_F_CREATE, &net8, 16, Some(&mtu)),
            Err(Errno::EEXIST)
        );
        assert_eq!(shown(AF_INET, &net8).len(), 2);
        // EINVAL for a type past RTAX_MAX, a short value, a congestion
        // control there is not, unknown features and a locked window of 0.
        let net9 = [10, 9, 0, 0];
        for bad in [
            nest(&[(RTAX_MAX + 1, &one)]),
            nest(&[(RTAX_MTU, &one[..2])]),
            nest(&[(RTAX_CC_ALGO, b"nosuchcc")]),
            nest(&[(RTAX_CC_ALGO, b"")]),
            nest(&[(RTAX_FEATURES, &word(0x20))]),
            nest(&[(RTAX_LOCK, &word(1 << RTAX_CWND))]),
        ] {
            let added = request(RTM_NEWROUTE, 0x600, &net9, 16, Some(&bad));
            assert_eq!(added, Err(Errno::EINVAL), "{bad:?}");
        }
        let locked = nest(&[(RTAX_LOCK, &word(1 << RTAX_CWND)), (RTAX_CWND, &word(10))]);
        assert!(request(RTM_NEWROUTE, 0x600, &net9, 16, Some(&locked)).is_ok());
        // An empty nest, or one of zeros, shows nothing.
        let net10 = [10, 10, 0, 0];
        assert!(request(RTM_NEWROUTE, 0x600, &net10, 16, Some(&[])).is_ok());
        assert_eq!(shown(AF_INET, &net10), [Vec::<u8>::new()]);
        // Removing matches the values as named, unheld: 70000 is not the
        // 65520 kept, a bad type matches nothing, and an unknown
        // congestion control is none.
        for unmatched in [
            nest(&[(RTAX_MTU, &big)]),
            nest(&[(RTAX_MAX + 1, &one)]),
            nest(&[(RTAX_HOPLIMIT, &one[..2])]),
        ] {
            let removed = request(RTM_DELROUTE, 0, &net8, 16, Some(&unmatched));
            assert_eq!(removed, Err(Errno(3)), "{unmatched:?}");
        }
        let exact = nest(&[(RTAX_MTU, &word(65520)), (RTAX_CC_ALGO, b"cubic")]);
        assert!(request(RTM_DELROUTE, 0, &net8, 16, Some(&exact)).is_ok());
        assert_eq!(shown(AF_INET, &net8), std::slice::from_ref(&mtu));
        // An unknown congestion control is key 0, which a route without
        // one has, and one with cubic has not.
        let unknown = nest(&[(RTAX_CC_ALGO, b"nosuchcc")]);
        assert!(request(RTM_DELROUTE, 0, &net9, 16, Some(&unknown)).is_ok());
        let cubic = nest(&[(RTAX_CC_ALGO, b"cubic\0")]);
        assert!(request(RTM_NEWROUTE, 0x600, &net9, 16, Some(&cubic)).is_ok());
        assert_eq!(
            request(RTM_DELROUTE, 0, &net9, 16, Some(&unknown)),
            Err(Errno(3))
        );
        assert!(request(RTM_DELROUTE, 0, &net10, 16, Some(&unknown)).is_ok());
        // IPv6: before RTA_PRIORITY, as rt6_fill_node puts them; removing
        // does not look at them.
        let net6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let reno = nest(&[(RTAX_MTU, &word(1280)), (RTAX_CC_ALGO, b"reno\0")]);
        assert!(request(RTM_NEWROUTE, 0x600, &net6, 16, Some(&reno)).is_ok());
        assert_eq!(shown(AF_INET6, &net6), std::slice::from_ref(&reno));
        let dumped = routes(&network, AF_INET6, 1);
        let six = dumped
            .iter()
            .find(|m| attributes(&m[28..]).contains(&(RTA_DST, &net6[..])))
            .unwrap();
        let kinds: Vec<u16> = attributes(&six[28..]).iter().map(|&(k, _)| k).collect();
        assert_eq!(kinds[..4], [RTA_TABLE, RTA_DST, RTA_METRICS, RTA_PRIORITY]);
        let net7 = [0xfd, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let bad = nest(&[(RTAX_MAX + 1, &one)]);
        assert_eq!(
            request(RTM_NEWROUTE, 0x600, &net7, 16, Some(&bad)),
            Err(Errno::EINVAL)
        );
        assert!(request(RTM_DELROUTE, 0, &net6, 16, Some(&bad)).is_ok());
    }

    #[test]
    fn route_lookups_take_their_source_device_and_tos() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let add = |dst: [u8; 4], tos: u8, kind: u8| {
            let device = kind == 1;
            let scope = if device { 253 } else { 0 };
            let mut payload = vec![AF_INET, 16, 0, tos, 254, 3, scope, kind, 0, 0, 0, 0];
            attribute(&mut payload, RTA_DST, &dst);
            if device {
                attribute(&mut payload, RTA_OIF, &1u32.to_le_bytes());
            }
            let header = Header {
                len: 0,
                kind: RTM_NEWROUTE,
                flags: NLM_F_REQUEST | 0x600,
                seq: 1,
            };
            change_route(&network, &header, &payload).unwrap();
        };
        add([10, 9, 0, 0], 0, 1);
        add([10, 9, 0, 0], 0x10, 1);
        // A TOS past the legacy bits is taken, and matches nothing.
        add([10, 9, 0, 0], 0x20, 1);
        add([10, 6, 0, 0], 0, 6);
        // A lookup of `dst` with `tos`, `flags` and the attributes, and its
        // answer's rtmsg and attributes.
        let get = |family: u8, tos: u8, flags: u32, attrs: &[(u16, &[u8])]| {
            let mut payload = vec![family, 0, 0, tos, 0, 0, 0, 0];
            payload.extend_from_slice(&flags.to_le_bytes());
            for &(kind, value) in attrs {
                attribute(&mut payload, kind, value);
            }
            lookup(&network, &payload, 1, 7, 0).map(|answer| {
                let found: Vec<(u16, Vec<u8>)> = attributes(&answer[28..])
                    .into_iter()
                    .map(|(k, v)| (k, v.to_vec()))
                    .collect();
                (answer[16..28].to_vec(), found)
            })
        };
        let has = |found: &[(u16, Vec<u8>)], kind: u16| found.iter().any(|(k, _)| *k == kind);
        let value = |found: &[(u16, Vec<u8>)], kind: u16| {
            found
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, v)| v.clone())
        };
        let one = 1u32.to_le_bytes();
        // The TOS: the route of the request's legacy TOS bits, else the one
        // of none; the answer gives the TOS that matched.
        let (header, _) = get(AF_INET, 0x10, 0, &[(RTA_DST, &[10, 9, 1, 1])]).unwrap();
        assert_eq!(header[3], 0x10);
        let (header, _) = get(AF_INET, 0xf0, 0, &[(RTA_DST, &[10, 9, 1, 1])]).unwrap();
        assert_eq!(header[3], 0x10);
        let (header, _) = get(AF_INET, 0x14, 0, &[(RTA_DST, &[10, 9, 1, 1])]).unwrap();
        assert_eq!(header[3], 0);
        let (header, _) = get(AF_INET, 0x20, 0, &[(RTA_DST, &[10, 9, 1, 1])]).unwrap();
        assert_eq!(header[3], 0);
        // RTM_F_NOTIFY marks the answer.
        let (header, _) = get(AF_INET, 0, RTM_F_NOTIFY, &[(RTA_DST, &[10, 9, 1, 1])]).unwrap();
        let flags = u32::from_le_bytes(header[8..12].try_into().unwrap());
        assert_eq!(
            flags,
            RTM_F_CLONED | RTCF_LOCAL | RTM_F_NOTIFY | RTCF_NOTIFY
        );
        // The source: the loopback's, named as RTA_SRC and not RTA_PREFSRC;
        // EINVAL for a multicast or broadcast one, ENETUNREACH for another.
        let from = |source: [u8; 4], to: [u8; 4]| {
            get(AF_INET, 0, 0, &[(RTA_DST, &to), (RTA_SRC, &source)])
        };
        let (header, found) = from([127, 0, 0, 5], [10, 9, 1, 1]).unwrap();
        assert_eq!(header[2], 32);
        assert_eq!(value(&found, RTA_SRC), Some(vec![127, 0, 0, 5]));
        assert!(!has(&found, RTA_PREFSRC));
        assert_eq!(from([10, 1, 1, 1], [10, 9, 1, 1]), Err(ENETUNREACH));
        assert_eq!(from([224, 0, 0, 1], [10, 9, 1, 1]), Err(Errno::EINVAL));
        assert_eq!(from([255; 4], [10, 9, 1, 1]), Err(Errno::EINVAL));
        let (_, found) = from([127, 0, 0, 1], [0; 4]).unwrap();
        assert_eq!(value(&found, RTA_DST), Some(vec![0; 4]));
        assert!(!has(&found, RTA_PREFSRC));
        // The device: ENODEV but for lo. Where the tables give an error, a
        // route on link through it, of no table, from no address of link
        // scope; none matches it, and 0.0.0.0/8 is EINVAL.
        let through = |to: [u8; 4], flags: u32, oif: u32| {
            get(
                AF_INET,
                0,
                flags,
                &[(RTA_DST, &to), (RTA_OIF, &oif.to_le_bytes())],
            )
        };
        assert_eq!(through([10, 9, 1, 1], 0, 2), Err(ENODEV));
        for to in [[192, 0, 2, 1], [10, 6, 1, 1]] {
            assert!(get(AF_INET, 0, 0, &[(RTA_DST, &to)]).is_err());
            let (header, found) = through(to, RTM_F_LOOKUP_TABLE, 1).unwrap();
            assert_eq!((header[4], header[7]), (0, 1));
            assert_eq!(value(&found, RTA_TABLE), Some(vec![0; 4]));
            assert!(!has(&found, RTA_PREFSRC));
            assert_eq!(through(to, RTM_F_FIB_MATCH, 1), Err(EHOSTUNREACH));
        }
        // 0.1.2.3 is no special address (`ipv4_is_zeronet` is 0.0.0.0's).
        assert!(through([0, 1, 2, 3], 0, 1).is_ok());
        assert_eq!(
            get(AF_INET, 0, 0, &[(RTA_DST, &[0, 1, 2, 3])]),
            Err(ENETUNREACH)
        );
        // 0.0.0.0 through it leaves from its address of host scope.
        let (_, found) = through([0; 4], 0, 1).unwrap();
        assert_eq!(value(&found, RTA_PREFSRC), Some(vec![127, 0, 0, 1]));
        let (header, _) = get(AF_INET, 0, RTM_F_LOOKUP_TABLE, &[]).unwrap();
        assert_eq!(header[4], 0);
        // The protocol: TCP, UDP and the family's ICMP; an input route.
        for (family, proto, ok) in [(AF_INET, 6, true), (AF_INET, 1, true), (AF_INET, 58, false)] {
            let found = get(
                family,
                0,
                0,
                &[(RTA_DST, &[10, 9, 1, 1]), (RTA_IP_PROTO, &[proto])],
            );
            assert_eq!(found.is_ok(), ok, "{proto}");
        }
        assert_eq!(
            get(AF_INET, 0, 0, &[(RTA_IP_PROTO, &[132])]),
            Err(EOPNOTSUPP)
        );
        assert_eq!(get(AF_INET, 0, 0, &[(RTA_IIF, &[2, 0, 0, 0])]), Err(ENODEV));
        assert_eq!(get(AF_INET, 0, 0, &[(RTA_IIF, &one)]), Err(EOPNOTSUPP));
        // Down, a device is ENETUNREACH.
        network.set_up(false);
        assert_eq!(through([127, 0, 0, 1], 0, 1), Err(ENETUNREACH));
        assert!(get(AF_INET, 0, 0, &[(RTA_DST, &[127, 0, 0, 1])]).is_ok());
        network.set_up(true);
        // IPv6: the source as RTA_SRC, as it is; another device is
        // ENETUNREACH without a source, or to ::1 with one; ICMP is
        // ICMPv6's.
        let loopback = core::net::Ipv6Addr::LOCALHOST.octets();
        let other = core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let (_, found) = get(AF_INET6, 0, 0, &[(RTA_DST, &loopback), (RTA_SRC, &other)]).unwrap();
        assert_eq!(value(&found, RTA_SRC), Some(other.to_vec()));
        let five = 5u32.to_le_bytes();
        let mut route6 = vec![AF_INET6, 48, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
        attribute(&mut route6, RTA_DST, &other);
        attribute(&mut route6, RTA_OIF, &one);
        let header = Header {
            len: 0,
            kind: RTM_NEWROUTE,
            flags: NLM_F_REQUEST | 0x600,
            seq: 1,
        };
        change_route(&network, &header, &route6).unwrap();
        let six = |attrs: &[(u16, &[u8])]| get(AF_INET6, 0, 0, attrs);
        assert_eq!(
            six(&[(RTA_DST, &loopback), (RTA_OIF, &five)]),
            Err(ENETUNREACH)
        );
        assert_eq!(
            six(&[(RTA_DST, &loopback), (RTA_OIF, &five), (RTA_SRC, &other)]),
            Err(ENETUNREACH)
        );
        assert_eq!(
            six(&[(RTA_DST, &other), (RTA_OIF, &five)]),
            Err(ENETUNREACH)
        );
        let elsewhere = [
            (RTA_DST, &other[..]),
            (RTA_OIF, &five),
            (RTA_SRC, &loopback),
        ];
        assert!(six(&elsewhere).is_ok());
        assert!(six(&[(RTA_DST, &loopback), (RTA_OIF, &one)]).is_ok());
        assert_eq!(six(&[(RTA_IP_PROTO, &[1])]), Err(EOPNOTSUPP));
        assert!(six(&[(RTA_DST, &loopback), (RTA_IP_PROTO, &[58])]).is_ok());
        assert_eq!(six(&[(RTA_SRC, &other[..4])]), Err(Errno::EINVAL));
    }

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
    fn coming_up_tells_ipv6s_link_information_last() {
        let network = Network::isolated(crate::users::first());
        let up = link_change(&network, true);
        assert_eq!(up[0].group, RTNLGRP_LINK);
        let last = up.last().unwrap();
        assert_eq!((last.group, last.origin), (RTNLGRP_IPV6_IFINFO, 0));
        let header = Header::read(&last.bytes);
        assert_eq!((header.kind, header.flags, header.seq), (RTM_NEWLINK, 0, 0));
        assert_eq!(&last.bytes[12..16], &0u32.to_le_bytes());
        assert_eq!(last.bytes, inet6_link_message(&network, 0, 0, 0));
        assert_eq!(last.bytes[16], AF_INET6);
        assert_eq!(
            up.iter().filter(|n| n.group == RTNLGRP_IPV6_IFINFO).count(),
            1
        );
        // Going down, or up again, tells IPv6's group nothing.
        let down = link_change(&network, false);
        assert!(!down.iter().any(|n| n.group == RTNLGRP_IPV6_IFINFO));
        assert!(link_change(&network, false).is_empty());
    }

    #[test]
    fn an_inet6_link_dump_shows_lo_as_ipv6_does() {
        let network = Network::isolated(crate::users::first());
        let link = inet6_link_message(&network, 4, 7, NLM_F_MULTI);
        let header = Header::read(&link);
        assert_eq!(
            (header.len as usize, header.kind, header.flags, header.seq),
            (link.len(), RTM_NEWLINK, NLM_F_MULTI, 4)
        );
        assert_eq!(&link[16..20], &[AF_INET6, 0, 4, 3]);
        assert_eq!(&link[20..24], &1i32.to_le_bytes());
        let found = attributes(&link[32..]);
        assert_eq!(
            found.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [
                IFLA_IFNAME,
                IFLA_ADDRESS,
                IFLA_MTU,
                IFLA_OPERSTATE,
                IFLA_PROTINFO
            ]
        );
        assert_eq!(found[3].1, [IF_OPER_DOWN]);
        // IPv6's settings, as IFLA_AF_SPEC has them, always with statistics.
        let inet6 = attributes(found[4].1);
        assert_eq!(
            inet6.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [1, 5, 2, 3, 6, 7, 8]
        );
        assert_eq!(found[4].1, inet6_settings(false, true));
        network.set_up(true);
        let link = inet6_link_message(&network, 4, 7, NLM_F_MULTI);
        let found = attributes(&link[32..]);
        assert_eq!(found[3].1, [IF_OPER_UNKNOWN]);
        assert_eq!(attributes(found[4].1)[0].1, IF_READY.to_le_bytes());
    }

    #[test]
    fn an_ipmr_link_dump_shows_the_default_table() {
        let link = ipmr_link_message(4, 7);
        let header = Header::read(&link);
        assert_eq!(
            (header.len as usize, header.kind, header.flags, header.seq),
            (88, RTM_NEWLINK, NLM_F_MULTI, 4)
        );
        assert_eq!(
            &link[16..32],
            &[
                RTNL_FAMILY_IPMR,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        );
        // `nla_nest_start_noflag`: IFLA_AF_SPEC without NLA_F_NESTED.
        assert_eq!(&link[32..36], &[56, 0, IFLA_AF_SPEC as u8, 0]);
        let table = attributes(&link[36..]);
        assert_eq!(
            table,
            [
                (IPMRA_TABLE_ID, &253u32.to_le_bytes()[..]),
                (IPMRA_TABLE_CACHE_RES_QUEUE_LEN, &[0; 4][..]),
                (IPMRA_TABLE_MROUTE_REG_VIF_NUM, &[0xff; 4][..]),
                (IPMRA_TABLE_MROUTE_DO_ASSERT, &[0][..]),
                (IPMRA_TABLE_MROUTE_DO_PIM, &[0][..]),
                (IPMRA_TABLE_MROUTE_DO_WRVIFWHOLE, &[0][..]),
                (IPMRA_TABLE_VIFS, &[][..]),
            ]
        );
        // Strictly an ifinfomsg alone, as ipmr_valid_dumplink takes it.
        let bare = ifinfo(RTNL_FAMILY_IPMR, 0, &[]);
        assert_eq!(bare_link_dump_check(&bare, true), Ok(()));
        let index = ifinfo(RTNL_FAMILY_IPMR, 1, &[]);
        assert_eq!(bare_link_dump_check(&index, true), Err(Errno::EINVAL));
        assert_eq!(bare_link_dump_check(&index, false), Ok(()));
        assert_eq!(
            bare_link_dump_check(&[RTNL_FAMILY_IPMR], true),
            Err(Errno::EINVAL)
        );
        assert_eq!(bare_link_dump_check(&[RTNL_FAMILY_IPMR], false), Ok(()));
    }

    #[test]
    fn routes_follow_the_loopback_and_its_address() {
        let network = Network::isolated(crate::users::first());
        // None before the loopback has been up.
        assert!(routes(&network, AF_INET, 1).is_empty());
        assert!(routes(&network, AF_INET6, 1).is_empty());
        // Up: local 127.0.0.0/8, local 127.0.0.1 and the broadcast route,
        // then local ::1, each in the local table.
        network.set_up(true);
        let v4 = routes(&network, AF_INET, 2).concat();
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
        let v6 = routes(&network, AF_INET6, 2).concat();
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
        assert_eq!(routes(&network, AF_INET, 3).concat().len(), 2 * 60);
        assert!(routes(&network, AF_INET6, 3).is_empty());
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

    #[test]
    fn strict_parsing_refuses_unknown_types_and_leftover_bytes() {
        let mut bytes = Vec::new();
        attribute(&mut bytes, IFLA_IFNAME | 0x8000, b"lo\0");
        assert_eq!(
            parse_policy(&bytes, &IFLA_POLICY, true),
            Ok(vec![(IFLA_IFNAME, &b"lo\0"[..])])
        );
        // The last attribute's padding may be left out.
        assert_eq!(
            parse_policy(&bytes[..7], &IFLA_POLICY, true).map(|a| a.len()),
            Ok(1)
        );
        for kind in [0, IFLA_MAX + 1] {
            let mut bytes = Vec::new();
            attribute(&mut bytes, kind, &[0; 4]);
            assert_eq!(parse_policy(&bytes, &IFLA_POLICY, true), Err(Errno::EINVAL));
            // Unchecked, it is passed over.
            assert_eq!(parse_policy(&bytes, &IFLA_POLICY, false), Ok(Vec::new()));
        }
        let mut bytes = Vec::new();
        attribute(&mut bytes, IFLA_MTU, &[0; 4]);
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(parse_policy(&bytes, &IFLA_POLICY, true), Err(Errno::EINVAL));
        assert_eq!(
            parse_policy(&bytes, &IFLA_POLICY, false).map(|a| a.len()),
            Ok(1)
        );
        assert_eq!(attributes(&bytes).len(), 1);
    }

    #[test]
    fn policies_check_each_attribute_in_turn() {
        let parse = |policy: &Policy, strict: bool, list: &[(u16, &[u8])]| {
            let mut bytes = Vec::new();
            for &(kind, value) in list {
                attribute(&mut bytes, kind, value);
            }
            parse_policy(&bytes, policy, strict).map(|a| a.len())
        };
        // A short integer is ERANGE, before a later unknown type, strictly
        // or not; a long one is EINVAL only past `strict_start_type`.
        let short: &[(u16, &[u8])] = &[(IFLA_EXT_MASK, &[0; 2]), (200, &[])];
        assert_eq!(parse(&IFLA_POLICY, true, short), Err(ERANGE));
        assert_eq!(parse(&IFLA_POLICY, false, short), Err(ERANGE));
        let long: &[(u16, &[u8])] = &[(IFLA_EXT_MASK, &[0; 5])];
        assert_eq!(parse(&IFLA_POLICY, true, long), Ok(1));
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PACING_OFFLOAD, &[0; 5])]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PACING_OFFLOAD, &[1, 0, 0, 0])]),
            Ok(1)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PACING_OFFLOAD, &[2, 0, 0, 0])]),
            Err(ERANGE)
        );
        // Unnamed past `strict_start_type`: an `NLA_UNSPEC`, refused.
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_DPLL_PIN, &[])]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse(&RTA4_POLICY, false, &[(RTA_FLOWLABEL, &[0; 4])]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse(&RTA6_POLICY, false, &[(RTA_FLOWLABEL, &[0; 4])]),
            Ok(1)
        );
        assert_eq!(
            parse(&RTA6_POLICY, false, &[(RTA_FLOWLABEL | 0x8000, &[0; 4])]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse(&RTA6_POLICY, false, &[(RTA_FLOWLABEL, &[0; 2])]),
            Err(Errno::EINVAL)
        );
        // Strings: at most their length but a last NUL, and not empty.
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_IFNAME, &[b'a'; 15])]),
            Ok(1)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_IFNAME, b"aaaaaaaaaaaaaaa\0")]),
            Ok(1)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_IFNAME, &[b'a'; 16])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(
                &IFLA_POLICY,
                false,
                &[(IFLA_IFNAME, b"lo\0\0aaaaaaaaaaaaa")]
            ),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_IFNAME, &[])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_ALT_IFNAME, &[b'a'; 127])]),
            Ok(1)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PARENT_DEV_NAME, b"ab")]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PARENT_DEV_NAME, b"ab\0")]),
            Ok(1)
        );
        // Binaries at most, `NLA_UNSPEC` at least, nests empty or whole.
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_ADDRESS, &[0; 33])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_MAP, &[0; 31])]),
            Err(ERANGE)
        );
        assert_eq!(parse(&IFLA_POLICY, true, &[(IFLA_MAP, &[0; 32])]), Ok(1));
        assert_eq!(parse(&IFLA_POLICY, false, &[(IFLA_AF_SPEC, &[])]), Ok(1));
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_AF_SPEC, &[0; 3])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFLA_POLICY, false, &[(IFLA_PERM_ADDRESS, &[])]),
            Err(Errno::EINVAL)
        );
        // Ranges.
        assert_eq!(
            parse(
                &IFLA_POLICY,
                false,
                &[(IFLA_TXQLEN, &32_768u32.to_le_bytes())]
            ),
            Err(ERANGE)
        );
        assert_eq!(
            parse(
                &IFLA_POLICY,
                false,
                &[(IFLA_GSO_MAX_SIZE, &320u32.to_le_bytes())]
            ),
            Err(ERANGE)
        );
        assert_eq!(
            parse(
                &IFLA_POLICY,
                false,
                &[(IFLA_GSO_MAX_SIZE, &321u32.to_le_bytes())]
            ),
            Ok(1)
        );
        assert_eq!(
            parse(
                &IFLA_POLICY,
                false,
                &[(IFLA_NEW_IFINDEX, &0u32.to_le_bytes())]
            ),
            Err(ERANGE)
        );
        // The families' address policies differ.
        assert_eq!(parse(&IFA4_POLICY, false, &[(IFA_ADDRESS, &[0; 4])]), Ok(1));
        assert_eq!(
            parse(&IFA6_POLICY, false, &[(IFA_ADDRESS, &[0; 4])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFA6_POLICY, false, &[(IFA_LABEL, &[b'a'; 40])]),
            Ok(1)
        );
        assert_eq!(
            parse(&IFA4_POLICY, false, &[(IFA_LABEL, &[b'a'; 16])]),
            Err(ERANGE)
        );
        assert_eq!(
            parse(&IFA4_POLICY, false, &[(IFA_CACHEINFO, &[0; 15])]),
            Err(ERANGE)
        );
    }

    /// An `ifinfomsg` of `family` and `index`, then `attributes`.
    fn ifinfo(family: u8, index: i32, attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = vec![family, 0, 0, 0];
        out.extend_from_slice(&index.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        for &(kind, value) in attributes {
            attribute(&mut out, kind, value);
        }
        out
    }

    #[test]
    fn strict_link_dumps_take_only_their_filters() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let dump = |payload: &[u8], strict| link_dump(&network, payload, 1, 7, strict);
        let skip = RTEXT_FILTER_SKIP_STATS.to_le_bytes();
        let plain = dump(&ifinfo(0, 0, &[]), true).unwrap();
        assert_eq!(plain, vec![link_message(&network, 1, 7, NLM_F_MULTI, 0)]);
        let skipped = vec![link_message(
            &network,
            1,
            7,
            NLM_F_MULTI,
            RTEXT_FILTER_SKIP_STATS,
        )];
        assert_eq!(
            dump(&ifinfo(0, 0, &[(IFLA_EXT_MASK, &skip)]), true),
            Ok(skipped.clone())
        );
        // A master lo has not shows nothing; lo has no kind.
        let master = ifinfo(0, 0, &[(IFLA_MASTER, &5u32.to_le_bytes())]);
        assert_eq!(dump(&master, true), Ok(Vec::new()));
        assert_eq!(dump(&master, false), Ok(Vec::new()));
        assert_eq!(
            dump(&ifinfo(0, 0, &[(IFLA_LINKINFO, &[])]), true),
            Ok(plain.clone())
        );
        // No namespace has an ID, checked or not.
        let netnsid = ifinfo(0, 0, &[(IFLA_TARGET_NETNSID, &1u32.to_le_bytes())]);
        assert_eq!(dump(&netnsid, true), Err(Errno::EINVAL));
        assert_eq!(dump(&netnsid, false), Err(Errno::EINVAL));
        // Strictly, an rtgenmsg, a type, flags, an index or another
        // attribute is EINVAL; a short filter is ERANGE.
        let name = ifinfo(0, 0, &[(IFLA_IFNAME, b"lo\0")]);
        let mut typed = ifinfo(0, 0, &[]);
        typed[2] = 4;
        let mut flagged = ifinfo(0, 0, &[]);
        flagged[8] = 1;
        for bad in [&[0][..], &typed, &flagged, &ifinfo(0, 1, &[]), &name] {
            assert_eq!(dump(bad, true), Err(Errno::EINVAL));
        }
        assert_eq!(
            dump(&ifinfo(0, 0, &[(IFLA_MASTER, &[5])]), true),
            Err(ERANGE)
        );
        // Unchecked, those are taken, an old rtgenmsg's attributes after its
        // 4 bytes, and none where one it reads is short.
        assert_eq!(dump(&name, false), Ok(plain.clone()));
        let mut old = vec![0; 4];
        attribute(&mut old, IFLA_EXT_MASK, &skip);
        assert_eq!(dump(&old, false), Ok(skipped));
        let short = ifinfo(0, 0, &[(IFLA_EXT_MASK, &skip), (IFLA_MASTER, &[5])]);
        assert_eq!(dump(&short, false), Ok(plain));
        // The other link dumps.
        assert_eq!(
            bare_link_dump_check(&ifinfo(AF_INET6, 0, &[]), true),
            Ok(())
        );
        let six = ifinfo(AF_INET6, 0, &[(IFLA_EXT_MASK, &skip)]);
        assert_eq!(bare_link_dump_check(&six, true), Err(Errno::EINVAL));
        assert_eq!(bare_link_dump_check(&six, false), Ok(()));
        assert_eq!(
            bare_link_dump_check(&ifinfo(AF_INET6, 1, &[]), true),
            Err(Errno::EINVAL)
        );
        let bridge = ifinfo(AF_BRIDGE, 0, &[(IFLA_EXT_MASK, &skip)]);
        assert_eq!(bridge_dump_check(&bridge, true), Ok(()));
        assert_eq!(bridge_dump_check(&master, true), Err(Errno::EINVAL));
        assert_eq!(
            bridge_dump_check(&ifinfo(AF_BRIDGE, 1, &[]), true),
            Err(Errno::EINVAL)
        );
        assert_eq!(bridge_dump_check(&[AF_BRIDGE], false), Ok(()));
    }

    #[test]
    fn strict_address_dumps_narrow_to_an_index() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let mut answer = 0;
        let all = address_dump(&network, &[0; 8], 0, 1, 7, true, &mut answer).unwrap();
        assert_eq!((all.len(), answer), (2, 0));
        let mut by_index = vec![AF_INET6, 0, 0, 0];
        by_index.extend_from_slice(&1u32.to_le_bytes());
        let lo = address_dump(&network, &by_index, AF_INET6, 1, 7, true, &mut answer).unwrap();
        assert_eq!(lo.len(), 1);
        assert_eq!(
            Header::read(&lo[0]).flags,
            NLM_F_MULTI | NLM_F_DUMP_FILTERED
        );
        assert_eq!(answer, NLM_F_DUMP_FILTERED);
        // Another index is ENODEV, after the filter is marked.
        by_index[4] = 2;
        answer = 0;
        let other = address_dump(&network, &by_index, 0, 1, 7, true, &mut answer);
        assert_eq!((other, answer), (Err(ENODEV), NLM_F_DUMP_FILTERED));
        // Unchecked, the index changes nothing.
        answer = 0;
        let loose = address_dump(&network, &by_index, 0, 1, 7, false, &mut answer).unwrap();
        assert_eq!((loose, answer), (all, 0));
        let mut label = vec![0; 8];
        attribute(&mut label, IFA_LABEL, b"lo\0");
        for bad in [&[0][..], &[0, 8, 0, 0, 0, 0, 0, 0], &label] {
            let found = address_dump(&network, bad, 0, 1, 7, true, &mut 0);
            assert_eq!(found, Err(Errno::EINVAL));
        }
    }

    #[test]
    fn an_ipv6_address_is_got_by_itself() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let one = core::net::Ipv6Addr::LOCALHOST.octets();
        let request = |index: u32, attributes: &[(u16, &[u8])]| {
            let mut payload = vec![AF_INET6, 0, 0, 0];
            payload.extend_from_slice(&index.to_le_bytes());
            for &(kind, value) in attributes {
                attribute(&mut payload, kind, value);
            }
            payload
        };
        // The dump's message, but for its flags; any index finds it.
        let dumped = ipv6_message(&network, 3, 7).remove(0);
        for (index, strict) in [(0, true), (1, true), (9, true), (9, false)] {
            let got = address_get(
                &network,
                &request(index, &[(IFA_ADDRESS, &one)]),
                3,
                7,
                strict,
            );
            let got = got.unwrap();
            assert_eq!(Header::read(&got).flags, 0);
            assert_eq!((&got[..6], &got[8..]), (&dumped[..6], &dumped[8..]));
        }
        // IFA_LOCAL is the address, before IFA_ADDRESS.
        let other = core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets();
        let local = request(0, &[(IFA_ADDRESS, &other), (IFA_LOCAL, &one)]);
        assert!(address_get(&network, &local, 3, 7, true).is_ok());
        let missing = request(0, &[(IFA_ADDRESS, &one), (IFA_LOCAL, &other)]);
        assert_eq!(
            address_get(&network, &missing, 3, 7, true),
            Err(EADDRNOTAVAIL)
        );
        // With neither, a short header or another namespace: EINVAL;
        // a short address is the policy's ERANGE.
        let netnsid = request(
            0,
            &[
                (IFA_ADDRESS, &one),
                (IFA_TARGET_NETNSID, &0i32.to_le_bytes()),
            ],
        );
        for strict in [true, false] {
            for bad in [&request(0, &[])[..], &[AF_INET6, 0, 0, 0], &netnsid] {
                assert_eq!(address_get(&network, bad, 3, 7, strict), Err(Errno::EINVAL));
            }
            let short = request(0, &[(IFA_ADDRESS, &one[..4])]);
            assert_eq!(address_get(&network, &short, 3, 7, strict), Err(ERANGE));
        }
        // Strictly, a prefix length, flags, a scope or another attribute is
        // EINVAL; unchecked, they are taken.
        let mut prefixed = request(0, &[(IFA_ADDRESS, &one)]);
        prefixed[1] = 128;
        let flagged = request(0, &[(IFA_ADDRESS, &one), (IFA_FLAGS, &0u32.to_le_bytes())]);
        for loose in [&prefixed, &flagged] {
            assert_eq!(address_get(&network, loose, 3, 7, true), Err(Errno::EINVAL));
            assert!(address_get(&network, loose, 3, 7, false).is_ok());
        }
    }

    #[test]
    fn group_masks_have_bits_for_the_first_32_groups_alone() {
        assert_eq!(group_mask(0), 0);
        assert_eq!(group_mask(1), 1);
        assert_eq!(group_mask(32), 1 << 31);
        assert_eq!(group_mask(RTNLGRP_MCTP_IFADDR), 0);
    }

    #[test]
    fn mctp_addresses_come_and_go_with_their_local_routes() {
        let network = Network::isolated(crate::users::first());
        let request = |kind: u16, index: u32, attributes: &[(u16, &[u8])]| {
            let mut payload = vec![AF_MCTP, 0, 0, 0];
            payload.extend_from_slice(&index.to_le_bytes());
            for &(kind, value) in attributes {
                attribute(&mut payload, kind, value);
            }
            let header = Header {
                len: 0,
                kind,
                flags: 0,
                seq: 3,
            };
            change_mctp_address(&network, &header, &payload)
        };
        assert_eq!(request(RTM_NEWADDR, 1, &[(IFA_LOCAL, &[8])]), Ok(8));
        assert_eq!(request(RTM_NEWADDR, 1, &[(IFA_LOCAL, &[8])]), Err(EEXIST));
        // IFA_LOCAL before IFA_ADDRESS, whatever their order.
        let both = [(IFA_LOCAL, &[9][..]), (IFA_ADDRESS, &[10][..])];
        assert_eq!(request(RTM_NEWADDR, 1, &both), Ok(9));
        assert_eq!(request(RTM_NEWADDR, 1, &[(IFA_ADDRESS, &[10])]), Ok(10));
        for (index, attributes, error) in [
            (1, &[(IFA_LOCAL, &[7][..])][..], Errno::EINVAL),
            (1, &[(IFA_LOCAL, &[255])], Errno::EINVAL),
            (1, &[], Errno::EINVAL),
            (1, &[(IFA_LOCAL, &[11, 0])], Errno::EINVAL),
            (1, &[(IFA_LOCAL, &[])], Errno::EINVAL),
            (
                1,
                &[(IFA_LOCAL, &[11]), (IFA_LABEL, b"lo\0")],
                Errno::EINVAL,
            ),
            (1, &[(IFA_MAX + 1, &[11])], Errno::EINVAL),
            (2, &[(IFA_LOCAL, &[11])], ENODEV),
            (0, &[(IFA_LOCAL, &[11])], ENODEV),
        ] {
            assert_eq!(request(RTM_NEWADDR, index, attributes), Err(error));
        }
        let header = Header {
            len: 0,
            kind: RTM_NEWADDR,
            flags: 0,
            seq: 3,
        };
        assert_eq!(
            change_mctp_address(&network, &header, &[AF_MCTP, 0, 0, 0]),
            Err(Errno::EINVAL)
        );
        assert_eq!(network.addresses().mctp, [8, 9, 10]);
        // The addresses, the oldest first, and the routes, the newest first.
        let dumped = mctp_addresses(&network, &[AF_MCTP], 4, 7);
        assert_eq!(dumped.len(), 3);
        assert_eq!(dumped[0], mctp_address(8, RTM_NEWADDR, NLM_F_MULTI, 4, 7));
        assert_eq!(&dumped[0][16..24], &[AF_MCTP, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            attributes(&dumped[0][24..]),
            [(IFA_LOCAL, &[8][..]), (IFA_ADDRESS, &[8][..])]
        );
        let mut other = vec![AF_MCTP, 0, 0, 0];
        other.extend_from_slice(&2u32.to_le_bytes());
        assert!(mctp_addresses(&network, &other, 4, 7).is_empty());
        let local = mctp_routes(&network, 4, 7);
        assert_eq!(local.len(), 3);
        assert_eq!(
            &local[0][16..28],
            &[AF_MCTP, 0, 0, 0, 253, 4, 253, 2, 0, 0, 0, 0]
        );
        assert_eq!(
            attributes(&local[0][28..]),
            [
                (RTA_DST, &[10][..]),
                (RTA_METRICS, &[][..]),
                (RTA_OIF, &1u32.to_le_bytes()[..])
            ]
        );
        // rtnl_dump_all's dumps end with MCTP's; a family's own do not.
        network.set_up(true);
        let all = address_dump(&network, &[0], 0, 4, 7, false, &mut 0).unwrap();
        assert_eq!(all[all.len() - 3..], dumped[..]);
        let four = address_dump(&network, &[AF_INET], AF_INET, 4, 7, false, &mut 0).unwrap();
        assert!(!four.iter().any(|m| m[16] == AF_MCTP));
        let all = routes(&network, 0, 4);
        assert_eq!(all.iter().filter(|m| m[16] == AF_MCTP).count(), 3);
        assert!(
            !routes(&network, AF_INET6, 4)
                .iter()
                .any(|m| m[16] == AF_MCTP)
        );
        // Removing: ENOENT for one lo has not.
        assert_eq!(request(RTM_DELADDR, 1, &[(IFA_ADDRESS, &[9])]), Ok(9));
        assert_eq!(
            request(RTM_DELADDR, 1, &[(IFA_LOCAL, &[9])]),
            Err(Errno::ENOENT)
        );
        assert_eq!(request(RTM_DELADDR, 2, &[(IFA_LOCAL, &[8])]), Err(ENODEV));
        assert_eq!(network.addresses().mctp, [8, 10]);
    }

    #[test]
    fn mctp_routes_go_through_gateways_alone() {
        let network = Network::isolated(crate::users::first());
        // An rtmsg of RTN_UNICAST from `dst` with `len` more, then attributes.
        let route = |kind: u16, len: u8, rtn: u8, attributes: &[(u16, &[u8])]| {
            let mut payload = vec![AF_MCTP, len, 0, 0, 0, 0, 0, rtn, 0, 0, 0, 0];
            for &(kind, value) in attributes {
                attribute(&mut payload, kind, value);
            }
            let header = Header {
                len: 0,
                kind,
                flags: 0,
                seq: 3,
            };
            change_mctp_route(&network, &header, &payload)
        };
        let gateway = |net: u32, eid: u8| {
            let mut value = net.to_le_bytes().to_vec();
            value.extend_from_slice(&[eid, 0, 0, 0]);
            value
        };
        let one = gateway(0, 20);
        let lo = 1u32.to_le_bytes();
        let mut mtu = Vec::new();
        attribute(&mut mtu, RTAX_MTU, &1500u32.to_le_bytes());
        let metrics = RTA_METRICS | 0x8000;
        assert_eq!(
            route(
                RTM_NEWROUTE,
                2,
                1,
                &[(RTA_DST, &[30]), (RTA_GATEWAY, &one), (metrics, &mtu)]
            ),
            Ok(())
        );
        assert_eq!(
            route(
                RTM_NEWROUTE,
                2,
                1,
                &[(RTA_DST, &[30]), (RTA_GATEWAY, &gateway(1, 21))]
            ),
            Err(EEXIST)
        );
        // Another range, or another network, is no duplicate.
        assert_eq!(
            route(
                RTM_NEWROUTE,
                0,
                1,
                &[(RTA_DST, &[30]), (RTA_GATEWAY, &gateway(5, 21))]
            ),
            Ok(())
        );
        let short = [1u8, 2];
        for (len, rtn, attributes, error) in [
            // Through lo, and to no output.
            (
                0,
                1,
                &[(RTA_DST, &[40][..]), (RTA_OIF, &lo[..])][..],
                Errno::EINVAL,
            ),
            (0, 1, &[(RTA_DST, &[40])], Errno::EINVAL),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_OIF, &2u32.to_le_bytes())],
                ENODEV,
            ),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_OIF, &lo), (RTA_GATEWAY, &one)],
                Errno::EINVAL,
            ),
            (0, 1, &[(RTA_GATEWAY, &one)], Errno::EINVAL),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &gateway(0, 7))],
                Errno::EINVAL,
            ),
            (
                0,
                2,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &one)],
                Errno::EINVAL,
            ),
            // A reserved first ID, and a range past 254.
            (0, 1, &[(RTA_DST, &[7]), (RTA_GATEWAY, &one)], Errno::EINVAL),
            (
                15,
                1,
                &[(RTA_DST, &[240]), (RTA_GATEWAY, &one)],
                Errno::EINVAL,
            ),
            // The policies.
            (
                0,
                1,
                &[(RTA_DST, &[40, 0]), (RTA_GATEWAY, &one)],
                Errno::EINVAL,
            ),
            (0, 1, &[(RTA_DST, &[40]), (RTA_GATEWAY, &one[..5])], ERANGE),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &one), (RTA_METRICS, &[])],
                Errno::EINVAL,
            ),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &one), (metrics, &short)],
                ERANGE,
            ),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &one), (metrics, &mtu[..6])],
                Errno::EINVAL,
            ),
            (
                0,
                1,
                &[(RTA_DST, &[40]), (RTA_GATEWAY, &one), (RTA_TABLE, &lo)],
                Errno::EINVAL,
            ),
            (
                0,
                1,
                &[(RTA_DST | 0x8000, &[40]), (RTA_GATEWAY, &one)],
                Errno::EINVAL,
            ),
            (0, 1, &[(RTA_MAX + 1, &[40])], Errno::EINVAL),
        ] {
            assert_eq!(
                route(RTM_NEWROUTE, len, rtn, attributes),
                Err(error),
                "{attributes:?}"
            );
        }
        // An address's local route is no duplicate of a gateway's of another
        // network, but takes none where one is.
        let address = |kind: u16, eid: u8| {
            let mut payload = vec![AF_MCTP, 0, 0, 0, 1, 0, 0, 0];
            attribute(&mut payload, IFA_LOCAL, &[eid]);
            let header = Header {
                len: 0,
                kind,
                flags: 0,
                seq: 3,
            };
            change_mctp_address(&network, &header, &payload)
        };
        assert_eq!(address(RTM_NEWADDR, 8), Ok(8));
        assert_eq!(
            route(RTM_NEWROUTE, 0, 1, &[(RTA_DST, &[50]), (RTA_GATEWAY, &one)]),
            Ok(())
        );
        assert_eq!(address(RTM_NEWADDR, 50), Ok(50));
        let dumped = mctp_routes(&network, 4, 7);
        assert_eq!(dumped.len(), 4);
        // The newest first: 50 by 20, 8 through lo, 30 by 5:21, 30-32 by 1:20.
        assert_eq!(
            &dumped[0][16..28],
            &[AF_MCTP, 0, 0, 0, 253, 4, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(
            &dumped[1][16..28],
            &[AF_MCTP, 0, 0, 0, 253, 4, 253, 2, 0, 0, 0, 0]
        );
        assert_eq!(
            &dumped[3][16..28],
            &[AF_MCTP, 2, 0, 0, 253, 4, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(
            attributes(&dumped[3][28..]),
            [
                (RTA_DST, &[30][..]),
                (RTA_METRICS, &mtu[..]),
                (RTA_GATEWAY, &gateway(1, 20)[..])
            ]
        );
        assert_eq!(attributes(&dumped[2][28..])[2].1, &gateway(5, 21)[..]);
        // Removing takes the network, range and type: lo's index names
        // network 1, and an address's route is not RTN_UNICAST.
        assert_eq!(
            route(RTM_DELROUTE, 0, 1, &[(RTA_DST, &[8]), (RTA_OIF, &lo)]),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            route(RTM_DELROUTE, 0, 2, &[(RTA_DST, &[8]), (RTA_OIF, &lo)]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            route(RTM_DELROUTE, 2, 1, &[(RTA_DST, &[30]), (RTA_OIF, &lo)]),
            Ok(())
        );
        assert_eq!(
            route(
                RTM_DELROUTE,
                0,
                1,
                &[(RTA_DST, &[30]), (RTA_GATEWAY, &gateway(5, 99))]
            ),
            Ok(())
        );
        assert_eq!(
            route(RTM_DELROUTE, 15, 1, &[(RTA_DST, &[240]), (RTA_OIF, &lo)]),
            Err(Errno::EINVAL)
        );
        // RTA_OIF of 0 is no interface (`ifindex` is its value): with a
        // gateway it is the gateway's route, alone no output.
        let none = 0u32.to_le_bytes();
        assert_eq!(
            route(
                RTM_NEWROUTE,
                0,
                1,
                &[(RTA_DST, &[60]), (RTA_OIF, &none), (RTA_GATEWAY, &one)]
            ),
            Ok(())
        );
        assert_eq!(
            route(RTM_NEWROUTE, 0, 1, &[(RTA_DST, &[61]), (RTA_OIF, &none)]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            route(RTM_DELROUTE, 0, 1, &[(RTA_DST, &[60]), (RTA_GATEWAY, &one)]),
            Ok(())
        );
        // Removing does not look inside the metrics.
        let mut hoplimit = Vec::new();
        attribute(&mut hoplimit, 10, &64u32.to_le_bytes());
        assert_eq!(
            route(
                RTM_DELROUTE,
                0,
                1,
                &[(RTA_DST, &[60]), (RTA_GATEWAY, &one), (metrics, &hoplimit)]
            ),
            Err(Errno::ENOENT)
        );
        // 50's address goes without a local route to remove.
        assert_eq!(address(RTM_DELADDR, 50), Ok(50));
        assert_eq!(address(RTM_DELADDR, 8), Ok(8));
        let left = network.addresses().mctp_routes.clone();
        assert_eq!(
            left,
            [MctpRoute {
                min: 50,
                max: 50,
                kind: 1,
                mtu: 0,
                gateway: Some((1, 20))
            }]
        );
    }

    #[test]
    fn mctp_address_dumps_check_only_their_length() {
        // A whole ifaddrmsg, whatever it holds; no attribute is checked.
        let mut header = vec![AF_MCTP, 8, 1, 200];
        header.extend_from_slice(&5u32.to_le_bytes());
        attribute(&mut header, 200, &[1, 2, 3]);
        assert_eq!(mctp_address_dump_check(&header, true), Ok(()));
        assert_eq!(mctp_address_dump_check(&header[..8], true), Ok(()));
        assert_eq!(
            mctp_address_dump_check(&header[..7], true),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            mctp_address_dump_check(&[AF_MCTP], true),
            Err(Errno::EINVAL)
        );
        assert_eq!(mctp_address_dump_check(&[AF_MCTP], false), Ok(()));
    }

    /// An `rtmsg` of `family` with `table`, `protocol`, `kind` and
    /// `flags`, then `attributes`.
    fn rtmsg(family: u8, table: u8, protocol: u8, kind: u8, flags: u32) -> Vec<u8> {
        let mut out = vec![family, 0, 0, 0, table, protocol, 0, kind];
        out.extend_from_slice(&flags.to_le_bytes());
        out
    }

    #[test]
    fn strict_route_dumps_narrow_by_table_protocol_type_and_device() {
        let network = Network::isolated(crate::users::first());
        network.set_up(true);
        let dump = |payload: &[u8], family, answer: &mut u16| {
            route_dump(&network, payload, family, 1, 7, true, answer)
        };
        let mut answer = 0;
        let all = dump(&rtmsg(0, 0, 0, 0, 0), 0, &mut answer).unwrap();
        // Every message of a strict dump is marked, NLMSG_DONE only when
        // it was narrowed.
        assert!(
            all.iter()
                .all(|m| Header::read(m).flags == NLM_F_MULTI | NLM_F_DUMP_FILTERED)
        );
        assert_eq!(answer, 0);
        assert_eq!(all.len(), routes(&network, 0, 1).len());
        let local = dump(
            &rtmsg(AF_INET, RT_TABLE_LOCAL, 0, 0, 0),
            AF_INET,
            &mut answer,
        )
        .unwrap();
        assert_eq!((local.len(), answer), (3, NLM_F_DUMP_FILTERED));
        let kind = dump(&rtmsg(0, 0, 0, RTN_BROADCAST, 0), 0, &mut 0).unwrap();
        assert_eq!(kind.len(), 1);
        let protocol = dump(&rtmsg(AF_INET6, 0, 3, 0, 0), AF_INET6, &mut 0).unwrap();
        assert!(protocol.is_empty());
        let mut lo = rtmsg(0, 0, 0, 0, 0);
        attribute(&mut lo, RTA_OIF, &1u32.to_le_bytes());
        assert_eq!(dump(&lo, 0, &mut 0).unwrap().len(), all.len());
        // A table the family has not made is ENOENT for that family alone.
        let mut hundred = rtmsg(AF_INET6, 0, 0, 0, 0);
        attribute(&mut hundred, RTA_TABLE, &100u32.to_le_bytes());
        assert_eq!(dump(&hundred, AF_INET6, &mut 0), Err(Errno::ENOENT));
        hundred[0] = 0;
        assert_eq!(dump(&hundred, 0, &mut 0), Ok(Vec::new()));
        let ipmr = rtmsg(RTNL_FAMILY_IPMR, 100, 0, 0, 0);
        assert_eq!(dump(&ipmr, RTNL_FAMILY_IPMR, &mut 0), Err(Errno::ENOENT));
        let ipmr = rtmsg(RTNL_FAMILY_IPMR, 253, 0, 0, 0);
        assert_eq!(dump(&ipmr, RTNL_FAMILY_IPMR, &mut 0), Ok(Vec::new()));
        let ip6mr = rtmsg(RTNL_FAMILY_IP6MR, 254, 0, 0, 0);
        assert_eq!(dump(&ip6mr, RTNL_FAMILY_IP6MR, &mut 0), Ok(Vec::new()));
        let ip6mr = rtmsg(RTNL_FAMILY_IP6MR, 253, 0, 0, 0);
        assert_eq!(dump(&ip6mr, RTNL_FAMILY_IP6MR, &mut 0), Err(Errno::ENOENT));
        // There are no cached routes and no prefix routes.
        for flags in [RTM_F_CLONED, RTM_F_PREFIX] {
            answer = 0;
            let none = dump(&rtmsg(0, 0, 0, 0, flags), 0, &mut answer);
            assert_eq!((none, answer), (Ok(Vec::new()), NLM_F_DUMP_FILTERED));
        }
        let prefix = rtmsg(0, 0, 0, 0, RTM_F_PREFIX);
        assert_eq!(
            route_dump(&network, &prefix, 0, 1, 7, false, &mut 0),
            Ok(Vec::new())
        );
        // An unknown device is ENODEV; the rest is EINVAL.
        let mut other = rtmsg(0, 0, 0, 0, 0);
        attribute(&mut other, RTA_OIF, &2u32.to_le_bytes());
        assert_eq!(dump(&other, 0, &mut 0), Err(ENODEV));
        let mut dst = rtmsg(0, 0, 0, 0, 0);
        attribute(&mut dst, RTA_DST, &[127, 0, 0, 1]);
        let mut long = rtmsg(0, 0, 0, 0, 0);
        long[1] = 8;
        let lookup = rtmsg(0, 0, 0, 0, RTM_F_LOOKUP_TABLE);
        for bad in [&[0][..], &dst, &long, &lookup] {
            assert_eq!(dump(bad, 0, &mut 0), Err(Errno::EINVAL));
        }
    }

    #[test]
    fn strict_lookups_take_whole_lengths_and_selectors() {
        let lookup = |family: u8, len: u8, flags: u32, extra: Option<(u16, &[u8])>| {
            let mut out = rtmsg(family, 0, 0, 0, flags);
            out[1] = len;
            if family == AF_INET6 {
                attribute(&mut out, RTA_DST, &Ipv6Addr::LOCALHOST.octets());
            } else {
                attribute(&mut out, RTA_DST, &[127, 0, 0, 1]);
            }
            if let Some((kind, value)) = extra {
                attribute(&mut out, kind, value);
            }
            lookup_check(&out, true)
        };
        use core::net::Ipv6Addr;
        assert_eq!(lookup(AF_INET, 32, RTM_F_LOOKUP_TABLE, None), Ok(()));
        assert_eq!(
            lookup(AF_INET, 32, 0, Some((RTA_MARK, &[1, 0, 0, 0]))),
            Ok(())
        );
        assert_eq!(lookup(AF_INET6, 128, RTM_F_FIB_MATCH, None), Ok(()));
        let label = 0x12345u32.to_be_bytes();
        assert_eq!(
            lookup(AF_INET6, 128, 0, Some((RTA_FLOWLABEL, &label))),
            Ok(())
        );
        let wide = 0x10_0000u32.to_be_bytes();
        assert_eq!(
            lookup(AF_INET6, 128, 0, Some((RTA_FLOWLABEL, &wide))),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            lookup(AF_INET6, 128, 0, Some((RTA_FLOWLABEL, &[0]))),
            Err(Errno::EINVAL)
        );
        for bad in [
            lookup(AF_INET, 0, 0, None),
            lookup(AF_INET, 24, 0, None),
            lookup(AF_INET, 32, RTM_F_CLONED, None),
            lookup(AF_INET6, 128, RTM_F_LOOKUP_TABLE, None),
            lookup(AF_INET, 32, 0, Some((RTA_PRIORITY, &[1, 0, 0, 0]))),
            lookup(AF_INET, 32, 0, Some((RTA_FLOWLABEL, &label))),
        ] {
            assert_eq!(bad, Err(Errno::EINVAL));
        }
        let mut table = rtmsg(AF_INET, RT_TABLE_LOCAL, 0, 0, 0);
        table[1] = 32;
        assert_eq!(lookup_check(&table, true), Err(Errno::EINVAL));
    }
}
