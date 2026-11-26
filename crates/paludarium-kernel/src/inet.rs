//! `AF_INET` and `AF_INET6` sockets, when the session allows a network.
//!
//! A TCP socket connects through the host ([`paludarium_host::net`]) to the
//! destinations [`NetworkPolicy`] allows, and behaves as Linux's TCP does
//! for a client. Port 53, at any address, is the built-in DNS stub instead,
//! over UDP (the only destination a UDP socket has) and over TCP: a query is
//! answered from the host's resolver for an allowed name and with
//! `NXDOMAIN` for any other, so the guest's own resolver
//! (`/etc/resolv.conf`, or its default) works unchanged.
//!
//! On the guest's own loopback a TCP socket also binds, listens and accepts
//! ([`crate::loopback`]): a connection to a loopback address where a guest
//! socket listens reaches it in the kernel, whatever the policy allows.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::fasync::{FileOwner, Notice, O_ASYNC, Reason, Registration};
use crate::interface::Flow6;
use crate::loopback::segments::Push;
use crate::loopback::{Binding, Link, Ports};
use crate::sockets::{Timeout, Timestamps};
use crate::syscalls::Context;
use crate::tcp_info::{self, TcpInfo};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use paludarium_host::net::{Driver, Event, Lookup, Phase, Stream};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

mod arrival;
use crate::multicast::Membership;
use crate::sockets::Filtered;

/// The interface requests of `ioctl` ([`Network::interface`]).
pub(crate) const SIOCGIFFLAGS: u64 = 0x8913;
pub(crate) const SIOCSIFFLAGS: u64 = 0x8914;
pub(crate) const SIOCGIFINDEX: u64 = 0x8933;
pub(crate) const SIOCGIFNAME: u64 = 0x8910;
const AF_UNSPEC: u16 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const IPPROTO_ICMP: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const IPPROTO_ICMPV6: u64 = 58;
/// The protocol numbers a flow is hashed with ([`Network::flow6`]), as
/// the `u8` of `flowi6_proto`.
const FLOW_TCP: u8 = 6;
const FLOW_UDP: u8 = 17;
const FLOW_ICMPV6: u8 = 58;
const ENOTSOCK: Errno = Errno(88);
const EDESTADDRREQ: Errno = Errno(89);
const ENOPROTOOPT: Errno = Errno(92);
const EPROTO: Errno = Errno(71);
const EPROTONOSUPPORT: Errno = Errno(93);
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EOPNOTSUPP: Errno = Errno(95);
const EAFNOSUPPORT: Errno = Errno(97);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENETUNREACH: Errno = Errno(101);
const ECONNABORTED: Errno = Errno(103);
const EISCONN: Errno = Errno(106);
const ENOTCONN: Errno = Errno(107);
const EALREADY: Errno = Errno(114);
const EINPROGRESS: Errno = Errno(115);
const ECONNREFUSED: Errno = Errno(111);
const ETIMEDOUT: Errno = Errno(110);
const EHOSTUNREACH: Errno = Errno(113);
/// When a connection out through a veth end to an address nobody there
/// answers ARP for gives up, in seconds: the neighbour's three probes, a
/// second apart (`mcast_probes` with `retrans_time`), fail, and the
/// handshake waiting on it learns of it from ICMP's host unreachable
/// (`arp_error_report`, `tcp_v4_err`).
const ARP_TIMEOUT: u64 = 3;
/// When a client sends a dropped handshake again, in seconds after its
/// first: Linux's 1-second `TCP_TIMEOUT_INIT`, the first four times as it
/// is (`tcp_syn_linear_timeouts`), then doubled each time.
const SYN_RETRIES: [u64; 10] = [1, 2, 3, 4, 5, 7, 11, 19, 35, 67];
/// When the client gives up with `ETIMEDOUT`, in seconds after its first:
/// the next try's time, past the 127 seconds that `tcp_syn_retries` (6)
/// allows (`retransmits_timed_out`).
const SYN_TIMEOUT: u64 = 131;
const EMSGSIZE: Errno = Errno(90);
/// Linux's default `net.core.somaxconn`, the most a `listen` backlog is.
const SOMAXCONN: u32 = 4096;
const POLLERR: u32 = 8;
const POLLHUP: u32 = 0x10;
const POLLRDHUP: u32 = 0x2000;
const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_CTRUNC: u32 = 0x8;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_MORE: u64 = 0x8000;
/// The DNS port, whose datagrams the stub answers.
const DNS: u16 = 53;
/// How long a resolved name is reused before it is looked up again.
const LOOKUP_LIFETIME: u64 = 30_000_000_000;
/// How long after the stub last gave an address for a name the guest may
/// still connect to it under that name.
const NAME_LIFETIME: u64 = 600_000_000_000;

/// One entry of the allow list: a name (`*.` for its subdomains too) or an
/// address, and a port, or every port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    Name {
        name: String,
        subdomains: bool,
        port: Option<u16>,
    },
    Address {
        ip: IpAddr,
        port: Option<u16>,
    },
}

/// An allow-list entry that is not `host`, `host:port`, `[v6]` or
/// `[v6]:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidRule(pub String);
impl std::fmt::Display for InvalidRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid network rule {:?}: expected host, host:port, [ipv6] or [ipv6]:port",
            self.0
        )
    }
}
impl std::error::Error for InvalidRule {}

/// The destinations a guest may reach. A session without one has no
/// network: `socket` refuses `AF_INET` and `AF_INET6`, as before.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    rules: Vec<Rule>,
}
impl NetworkPolicy {
    /// A policy that allows nothing yet; names and addresses are added with
    /// [`Self::allow`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Allows `entry`: a host name (`github.com`), every subdomain of one
    /// (`*.github.com`), an IPv4 address or an IPv6 one (bare, or in
    /// brackets), each optionally with a port (`github.com:443`,
    /// `[::1]:8080`). Names are matched without regard to case; a name
    /// lets the guest resolve it and connect to the addresses it resolved.
    pub fn allow(mut self, entry: &str) -> Result<Self, InvalidRule> {
        let invalid = || InvalidRule(entry.to_owned());
        let port = |text: &str| {
            text.parse::<u16>()
                .ok()
                .filter(|&port| port != 0)
                .ok_or_else(invalid)
        };
        if let Ok(ip) = entry.parse::<IpAddr>() {
            self.rules.push(Rule::Address { ip, port: None });
            return Ok(self);
        }
        if let Some(rest) = entry.strip_prefix('[') {
            let (ip, tail) = rest.split_once(']').ok_or_else(invalid)?;
            let ip = ip.parse::<Ipv6Addr>().map_err(|_| invalid())?;
            let port = match tail {
                "" => None,
                tail => Some(port(tail.strip_prefix(':').ok_or_else(invalid)?)?),
            };
            self.rules.push(Rule::Address {
                ip: IpAddr::V6(ip),
                port,
            });
            return Ok(self);
        }
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, text)) => (host, Some(port(text)?)),
            None => (entry, None),
        };
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            self.rules.push(Rule::Address {
                ip: IpAddr::V4(ip),
                port,
            });
            return Ok(self);
        }
        let (subdomains, name) = match host.strip_prefix("*.") {
            Some(name) => (true, name),
            None => (false, host),
        };
        let name = normal(name).ok_or_else(invalid)?;
        self.rules.push(Rule::Name {
            name,
            subdomains,
            port,
        });
        Ok(self)
    }
    /// Whether `name` (already normalised) is one the guest may resolve.
    fn allows_name(&self, name: &str) -> bool {
        self.rules.iter().any(|rule| match rule {
            Rule::Name {
                name: allowed,
                subdomains,
                ..
            } => matches_name(allowed, *subdomains, name),
            Rule::Address { .. } => false,
        })
    }
}
/// A host name in lower case without its final dot, or `None` for one that
/// is not made of letters, digits, hyphens and dots.
fn normal(name: &str) -> Option<String> {
    let name = name.trim_suffix('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then_some(name)
}
/// Whether `name` is `allowed`, or with `subdomains` one of its subdomains
/// (not the name itself, as a certificate's wildcard).
fn matches_name(allowed: &str, subdomains: bool, name: &str) -> bool {
    if subdomains {
        name.strip_suffix(allowed)
            .is_some_and(|head| head.len() > 1 && head.ends_with('.'))
    } else {
        name == allowed
    }
}
/// Whether a name rule may reach `ip`, which the host resolved `name` to:
/// only a global address, so that no allowed name (nor a subdomain under a
/// `*.` rule, whose owner may point it anywhere) reaches the host's own
/// machine or networks; `localhost` and its subdomains may also reach the
/// loopback. Any address listed itself is reached without this.
fn reachable(name: &str, ip: IpAddr) -> bool {
    let local = name == "localhost" || name.ends_with(".localhost");
    match plain(ip) {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_loopback() {
                return local;
            }
            !(v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                // Shared address space (RFC 6598) and the reserved 240/4.
                || (a == 100 && (64..128).contains(&b))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return local;
            }
            let segments = v6.segments();
            let first = segments[0];
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4
            // address, which must be reachable itself.
            let embedded = |high: u16, low: u16| {
                let [a, b] = high.to_be_bytes();
                let [c, d] = low.to_be_bytes();
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            };
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return reachable(name, embedded(segments[6], segments[7]));
            }
            if first == 0x2002 {
                return reachable(name, embedded(segments[1], segments[2]));
            }
            !(v6.is_unspecified()
                || v6.is_multicast()
                // Unique local (fc00::/7) and link-local (fe80::/10).
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}
/// The IPv4 source of `from`, none for another or an unspecified one.
fn source4(from: Option<IpAddr>) -> Option<Ipv4Addr> {
    match from.map(plain) {
        Some(IpAddr::V4(ip)) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}
/// An IPv4 address that an IPv6 socket names as `::ffff:a.b.c.d` is that
/// IPv4 address.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A session's network: its policy, what the stub has resolved for it,
/// and the lookups in progress.
pub(crate) struct Network {
    policy: NetworkPolicy,
    /// The names each address was resolved from, and when the stub last
    /// gave it, so that a connection to it is allowed as the names are for
    /// [`NAME_LIFETIME`].
    resolved: Mutex<BTreeMap<IpAddr, Vec<(String, u64)>>>,
    lookups: Mutex<BTreeMap<String, (Arc<Lookup>, u64)>>,
    /// The local ports the guest's TCP sockets hold, and its UDP ones.
    /// Locked after a socket's state, never before.
    tcp_ports: Mutex<Ports>,
    udp_ports: Mutex<Ports>,
    /// The loopback connections whose handshake a full queue dropped, to be
    /// tried again. Taken out before any socket's state is locked.
    syns: Mutex<Vec<Syn>>,
    /// The connections out through a veth end that no answer comes to,
    /// each with when it fails, and with what. Taken out before any
    /// socket's state is locked.
    fails: Mutex<Vec<(Weak<Stream>, u64, Errno)>>,
    /// A nested network namespace's, which has nothing but its loopback
    /// and veth ends: no route to the host, and no
    /// DNS stub.
    isolated: bool,
    /// Whether its loopback interface is up.
    up: AtomicBool,
    /// Whether it has ever been up, and so has a queueing discipline.
    ever_up: AtomicBool,
    /// The loopback's addresses and their routes ([`crate::interface`]),
    /// which say what is local; locked after a socket's state, never
    /// before.
    addresses: Mutex<crate::interface::Addresses>,
    /// What has run out of the addresses and routes, as a socket found it
    /// ([`Self::addresses_at`]), for netlink to tell of
    /// ([`crate::netlink::expire`]); locked after the addresses.
    expired: Mutex<Vec<crate::interface::Event>>,
    /// The netlink sockets bound in it ([`crate::netlink`]), with its
    /// namespace IDs. Dropped before the devices, as `cleanup_net` tells
    /// `RTM_DELNSID` (`unhash_nsid`) before `default_device_exit_batch`
    /// takes a veth peer's end with `RTM_DELLINK`.
    pub(crate) netlink: crate::netlink::Ports,
    /// Its network devices ([`crate::netdev`]), each taken out alone:
    /// none of the other locks is taken while it is held.
    devices: Mutex<crate::netdev::Devices>,
    /// Its MCTP sockets' binds and tags ([`crate::mctp`]).
    pub(crate) mctp: crate::mctp::Endpoints,
    /// Its TCP and UDP sockets, oldest first, which `sock_diag` lists.
    sockets: Mutex<Vec<Weak<InetSocket>>>,
    /// The user namespace that owns its network namespace, whose
    /// `CAP_NET_ADMIN` changes it; none for the first one's.
    owner: Option<Arc<crate::namespaces::Namespace>>,
    /// Whose the files of its `/proc/net` are: that namespace's root as it
    /// was mapped when the network namespace was made, else the first's
    /// (`proc_net_ns_init`).
    pub(crate) proc_owner: (u32, u32),
}
/// The flags `SIOCGIFFLAGS` gives the loopback: `IFF_LOOPBACK`, with
/// `IFF_UP` and `IFF_RUNNING` while it is up.
const IFF_UP: u16 = 0x1;
const IFF_LOOPBACK: u16 = 0x8;
const IFF_RUNNING: u16 = 0x40;
const ENODEV: Errno = Errno(19);
/// `CAP_NET_RAW`, which rebinding a socket to a device needs.
const CAP_NET_RAW: u64 = 1 << 13;
impl Network {
    pub(crate) fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            resolved: Mutex::default(),
            lookups: Mutex::default(),
            tcp_ports: Mutex::default(),
            udp_ports: Mutex::default(),
            syns: Mutex::default(),
            fails: Mutex::default(),
            isolated: false,
            up: AtomicBool::new(true),
            ever_up: AtomicBool::new(true),
            addresses: Mutex::new(crate::interface::Addresses::first()),
            devices: {
                // Its loopback is up, and so in this group (`ip_mc_up`).
                let mut devices = crate::netdev::Devices::new();
                if let Some(lo) = devices.by_index_mut(crate::netdev::LOOPBACK_INDEX) {
                    lo.groups4.join(crate::multicast::ALL_HOSTS);
                }
                Mutex::new(devices)
            },
            expired: Mutex::new(Vec::new()),
            netlink: crate::netlink::Ports::default(),
            mctp: crate::mctp::Endpoints::default(),
            sockets: Mutex::default(),
            owner: None,
            proc_owner: (0, 0),
        }
    }
    /// A new network namespace's network: only a loopback, down and without
    /// `::1`, as Linux's `loopback_net_init` makes it. `owner` is the user
    /// namespace that owns the network namespace.
    pub(crate) fn isolated(owner: &Arc<crate::namespaces::Namespace>) -> Self {
        Self {
            isolated: true,
            owner: Some(Arc::clone(owner)),
            proc_owner: {
                use crate::users::Ids;
                (
                    owner.kernel_of(Ids::User, 0).unwrap_or(0),
                    owner.kernel_of(Ids::Group, 0).unwrap_or(0),
                )
            },
            up: AtomicBool::new(false),
            ever_up: AtomicBool::new(false),
            addresses: Mutex::new(crate::interface::Addresses::isolated()),
            devices: Mutex::new(crate::netdev::Devices::new()),
            expired: Mutex::new(Vec::new()),
            ..Self::new(NetworkPolicy::default())
        }
    }
    /// Where a connection or datagram to `to` goes: on the loopback, while
    /// it is up, to an address its local routes have, or the unspecified
    /// one, which goes to `127.0.0.1` or `::1`
    /// ([`crate::loopback::destination`]); else out through a veth end
    /// that a unicast or broadcast route of IPv4 goes through, as
    /// `__mkroute_output` makes the route: of the broadcast type to a
    /// broadcast route's address or the limited broadcast one, of the
    /// multicast type to a group ([`Cast`]), or that a unicast or
    /// multicast route of IPv6 goes through; else off the guest's
    /// networks, which only the first namespace has a route to.
    /// `ENETUNREACH` where no route goes. Before all that, a group or the
    /// limited broadcast address from a source `from` of a veth end's goes
    /// out through that end without a route, as `ip_route_output_key_hash_rcu`
    /// takes the source's device for them.
    ///
    /// Through a device `oif` other than 0, an IPv6 destination's route is
    /// looked up through it, a local one too: strictly
    /// (`RT6_LOOKUP_F_IFACE`) where it is the socket's own (`strict`), or
    /// where the source is not chosen yet, or the destination a group, a
    /// link-local address or `::1` (`ip6_route_output_flags`), and then
    /// `ENETUNREACH` where none goes; else through it rather than another,
    /// among the routes of one prefix and metric. `::` is `::1` by then
    /// (`udpv6_sendmsg`). An IPv4 one goes through it as
    /// [`Self::route4_through`] routes it.
    ///
    /// Of an IPv6 multipath route, the hop the flow takes: from `from`, of
    /// the protocol `proto`, with no flow label, as the guest's sockets
    /// send none ([`Self::flow6`]); of an IPv4 one, the hop a packet from
    /// `from` takes ([`crate::interface::Addresses::output4`]).
    fn route(
        &self,
        to: SocketAddr,
        from: Option<IpAddr>,
        (oif, strict): (u32, bool),
        proto: u8,
        now: Option<u64>,
    ) -> Result<Dest, Errno> {
        let flow = Self::flow6(from, proto);
        let to = if oif != 0 && to.is_ipv6() && !from.is_some_and(|ip| plain(ip).is_ipv4()) {
            crate::loopback::destination(to).unwrap_or(to)
        } else {
            to
        };
        if let IpAddr::V6(ip) = to.ip()
            && oif != 0
            && !ip.is_unspecified()
        {
            use crate::interface::Kind;
            let strict = strict
                || from.is_none_or(|ip| ip.is_unspecified())
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_loopback();
            let route = if strict {
                self.addresses_at(now).lookup6_flow(ip, oif, &flow)?
            } else {
                self.addresses_at(now).lookup6_preferring(ip, oif, &flow)?
            };
            return match route.kind {
                Kind::Local if self.is_up() => Ok(Dest::Here(to)),
                Kind::Unicast | Kind::Multicast if route.oif != crate::netdev::LOOPBACK_OIF => {
                    let index = i32::try_from(route.oif).map_err(|_| ENETUNREACH)?;
                    let cast = if ip.is_multicast() {
                        Cast::Multicast
                    } else {
                        Cast::Unicast
                    };
                    Ok(Dest::Veth(index, cast))
                }
                Kind::Local => Err(ENETUNREACH),
                _ if self.isolated => Err(ENETUNREACH),
                _ => Ok(Dest::Away),
            };
        }
        if let IpAddr::V4(ip) = to.ip()
            && oif != 0
            && !ip.is_unspecified()
        {
            return self.route4_through(to, ip, oif, now);
        }
        if let (Some(IpAddr::V4(src)), IpAddr::V4(ip)) = (from.map(plain), to.ip())
            && !src.is_unspecified()
            && (ip.is_multicast() || ip.is_broadcast())
            && let Some(index) = self.addresses_at(now).device_of4(src)
            && index != crate::netdev::LOOPBACK_INDEX
        {
            let cast = if ip.is_broadcast() {
                Cast::Broadcast
            } else {
                Cast::Multicast
            };
            return Ok(Dest::Veth(index, cast));
        }
        let up = self.is_up();
        let order = self.devices().order();
        let local = match to.ip() {
            ip if ip.is_unspecified() => crate::loopback::destination(to),
            IpAddr::V4(ip) => self.addresses_at(now).local4(ip).then_some(to),
            IpAddr::V6(ip) => self.addresses_at(now).local6(ip).then_some(to),
        };
        match local {
            Some(_) if !up => Err(ENETUNREACH),
            Some(to) => Ok(Dest::Here(to)),
            None => {
                use crate::interface::Kind;
                if let IpAddr::V4(ip) = to.ip()
                    && let Ok(route) =
                        self.addresses_at(now)
                            .output4(ip, 0, 0, source4(from), &order)
                    && matches!(route.kind, Kind::Unicast | Kind::Broadcast)
                    && route.oif != crate::netdev::LOOPBACK_OIF
                    && let Ok(index) = i32::try_from(route.oif)
                {
                    let cast = if route.kind == Kind::Broadcast || ip.is_broadcast() {
                        Cast::Broadcast
                    } else if ip.is_multicast() {
                        Cast::Multicast
                    } else {
                        Cast::Unicast
                    };
                    return Ok(Dest::Veth(index, cast));
                }
                // IPv6's unicast routes through a veth end, and the
                // multicast one each end has (`addrconf_add_mroute`).
                if let IpAddr::V6(ip) = to.ip()
                    && let Ok(route) = self.addresses_at(now).lookup6_flow(ip, 0, &flow)
                    && matches!(route.kind, Kind::Unicast | Kind::Multicast)
                    && route.oif != crate::netdev::LOOPBACK_OIF
                    && let Ok(index) = i32::try_from(route.oif)
                {
                    let cast = if ip.is_multicast() {
                        Cast::Multicast
                    } else {
                        Cast::Unicast
                    };
                    return Ok(Dest::Veth(index, cast));
                }
                if self.isolated {
                    Err(ENETUNREACH)
                } else {
                    Ok(Dest::Away)
                }
            }
        }
    }
    /// What a packet from `from` to `to` out through this namespace's veth
    /// end `index` finds at `now`, its neighbour first, its route's gateway
    /// or else `to` ([`Self::next_hop4`],
    /// [`crate::interface::Addresses::neigh_output`]), one of IPv6 as
    /// [`Self::reach6`] says:
    /// - Nothing answers, as nobody answers ARP for that neighbour
    ///   ([`Reach::Unanswered`]), unless the end has its carrier, so that
    ///   its peer is up (`veth_xmit`), the neighbour is an address of the peer's
    ///   namespace (`arp_process`: its local routes have it), and the peer
    ///   takes a packet from `from` in on it, as `ip_route_input` checks
    ///   the source with its reverse path filtering
    ///   ([`crate::interface::Addresses::validate_source4_on`]); a
    ///   request it answers teaches the peer this end's address for `from`
    ///   ([`crate::interface::Addresses::neigh_learn`]). A neighbour already
    ///   valid needs no ARP.
    /// - The packet is lost ([`Reach::Dropped`]) where its neighbour's
    ///   address is not the peer's, the peer has not its carrier, or the
    ///   peer drops it, as it does a martian from 0.0.0.0.
    /// - The packet comes there, and the answer back ([`Reach::Answered`])
    ///   only where that namespace's comes to this one ([`Self::back4`]);
    ///   else that answer goes nowhere ([`Reach::OneWay`]).
    fn reach(&self, index: i32, from: IpAddr, to: IpAddr, flow: &Flow, now: Option<u64>) -> Reach {
        let (from, to) = match (plain(from), plain(to)) {
            (IpAddr::V4(from), IpAddr::V4(to)) => (from, to),
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                return self.reach6(index, from, to, flow, now);
            }
            _ => return Reach::Unanswered,
        };
        let lladdr = match self.next_hop4(index, to, flow, now) {
            IpAddr::V4(hop) => self.neighbour4(index, from, hop, now),
            IpAddr::V6(hop) => self.neighbour6(index, None, hop, now),
        };
        let Some(lladdr) = lladdr else {
            return Reach::Unanswered;
        };
        let peer = self.veth_peer(index).and_then(|(peer, _)| peer);
        let Some((there, peer_index, _)) = peer.filter(|p| p.2 == lladdr) else {
            return Reach::Dropped;
        };
        let their_rpf = there.rp_filter(peer_index);
        // From no address (where no address fits, as `inet_select_addr`
        // finds none) the packet is a martian there
        // (`ip_route_input_slow`).
        if from.is_unspecified() {
            return Reach::Dropped;
        }
        let arrives = {
            let addresses = there.addresses_at(now);
            !to.is_loopback()
                && addresses.local4(to)
                && addresses
                    .validate_source4_on(from, 0, 0, their_rpf, peer_index)
                    .is_ok()
        };
        if !arrives {
            return Reach::Dropped;
        }
        let answer = Flow {
            src: Some(IpAddr::V4(to)),
            oif: there.answer_oif(IpAddr::V4(to), flow, peer_index),
            proto: flow.proto,
            bound: 0,
            port: None,
        };
        let back = self.back4(&there, from, to, &answer, now);
        Self::answered(there, flow, answer.oif, back)
    }
    /// The Ethernet address of the IPv4 neighbour `hop` of the veth end
    /// `index`, for a packet from `from` at `now`, which resolves it as
    /// [`Self::reach`] says; none where nothing answers.
    fn neighbour4(
        &self,
        index: i32,
        from: Ipv4Addr,
        hop: Ipv4Addr,
        now: Option<u64>,
    ) -> Option<[u8; 6]> {
        let Arp {
            peer,
            answer,
            own_mac,
        } = self.arp(index, from, hop, now)?;
        let at = now.unwrap_or(0);
        let (lladdr, asked, events) = self.addresses_at(now).neigh_output(index, hop, answer, at);
        self.later(events);
        if asked
            && answer.is_some()
            && !from.is_unspecified()
            && let Some((there, peer_index, _)) = &peer
        {
            let events = there
                .addresses_at(now)
                .neigh_learn(*peer_index, from, own_mac, at);
            there.later(events);
        }
        lladdr
    }
    /// [`Self::neighbour4`] of an IPv6 neighbour, as [`Self::reach6`] says;
    /// with no `from`, as an IPv4 packet's through a gateway of IPv6 has
    /// none of the end's, from the end's link-local address
    /// (`ndisc_solicit`).
    fn neighbour6(
        &self,
        index: i32,
        from: Option<Ipv6Addr>,
        hop: Ipv6Addr,
        now: Option<u64>,
    ) -> Option<[u8; 6]> {
        let Nd {
            peer,
            answer,
            own_mac,
            asker,
        } = self.nd(index, from, hop, now)?;
        let at = now.unwrap_or(0);
        let (lladdr, asked, events) = self.addresses_at(now).neigh_output(index, hop, answer, at);
        self.later(events);
        if asked {
            self.solicit(index, asker, hop, at);
        }
        if asked && answer.is_some() {
            Self::teach6(peer.as_ref(), asker, own_mac, at);
        }
        lladdr
    }
    /// The peer of this namespace's veth end `index`, if the end has its
    /// carrier, with its namespace, index and Ethernet address; and the
    /// end's own Ethernet address. `None` for no such end.
    #[allow(clippy::type_complexity)]
    fn veth_peer(&self, index: i32) -> Option<(Option<(Arc<Network>, i32, [u8; 6])>, [u8; 6])> {
        let (peer, own_mac) = {
            let devices = self.devices();
            let veth = devices.by_index(index).and_then(|d| d.veth.as_ref())?;
            let peer = veth
                .peer
                .clone()
                .filter(|_| veth.carrier)
                .and_then(|p| p.network.upgrade().map(|n| (n, p.index)));
            (peer, veth.mac)
        };
        let peer = peer.and_then(|(there, at)| {
            let mac = there
                .devices()
                .by_index(at)
                .and_then(|d| d.veth.as_ref())
                .map(|v| v.mac)?;
            Some((there, at, mac))
        });
        Some((peer, own_mac))
    }
    /// [`Self::veth_peer`], where the peer takes IPv6.
    fn nd_peer(&self, index: i32) -> Option<(Arc<Network>, i32, [u8; 6])> {
        self.veth_peer(index)?.0.filter(|(there, at, _)| {
            there.devices().by_index(*at).is_some_and(|device| {
                device.conf6.disable_ipv6 == 0
                    && device.veth.as_ref().is_some_and(|v| v.mtu >= 1280)
            })
        })
    }
    /// The device named in the route lookup of an answer from this
    /// namespace's address `to` to a packet of the flow `flow`, which came
    /// in on the device `index`: the one its listener is bound to
    /// (`inet_csk_route_req`), 0 for none.
    fn answer_oif(&self, to: IpAddr, flow: &Flow, index: i32) -> u32 {
        flow.port.map_or(0, |port| {
            self.ports(false)
                .listener_device(SocketAddr::new(to, port), index.unsigned_abs())
        })
    }
    /// What a packet of the flow `flow` that comes to `there` finds, whose
    /// answer, routed with the device `oif` named, goes out through the
    /// first end of `back` there and comes in on the second, if it comes: a
    /// socket bound to a device takes it in on that alone.
    fn answered(there: Arc<Network>, flow: &Flow, oif: u32, back: Option<(i32, i32)>) -> Reach {
        match back {
            Some((index, own)) if flow.bound == 0 || flow.bound == own.unsigned_abs() => {
                Reach::Answered(there, Back { index, oif })
            }
            _ => Reach::OneWay(there),
        }
    }
    /// The peer of the veth end `index` of `there`, where it is this
    /// namespace's and the end has its carrier.
    fn own_end(&self, there: &Network, index: i32) -> Option<i32> {
        let devices = there.devices();
        let veth = devices.by_index(index)?.veth.as_ref()?;
        let peer = veth.peer.as_ref().filter(|_| veth.carrier)?;
        core::ptr::eq(peer.network.as_ptr(), self).then_some(peer.index)
    }
    /// The veth end of `there` an answer from its address `to` to `from`,
    /// of the flow `flow`, goes out through, and the one of this namespace
    /// it comes in on, if it comes: `there` routes `from` out through an
    /// end whose peer is this namespace's, to a next hop that is this
    /// namespace's (but a loopback address), as ARP finds it, and this
    /// namespace takes the answer from `to` in there, at its address
    /// `from`. That pair need not be the one the packet took.
    fn back4(
        &self,
        there: &Network,
        from: Ipv4Addr,
        to: Ipv4Addr,
        flow: &Flow,
        now: Option<u64>,
    ) -> Option<(i32, i32)> {
        let back = if flow.oif == 0 {
            let order = there.devices().order();
            let route = there
                .addresses_at(now)
                .output4(from, 0, 0, Some(to), &order)
                .ok()
                .filter(|r| r.kind == crate::interface::Kind::Unicast)?;
            i32::try_from(route.oif).ok()?
        } else {
            let at = SocketAddr::new(IpAddr::V4(from), 0);
            match there.route4_through(at, from, flow.oif, now) {
                Ok(Dest::Veth(back, Cast::Unicast)) => back,
                _ => return None,
            }
        };
        let hop = there.next_hop4(back, from, flow, now);
        let own = self.own_end(there, back)?;
        let rpf = self.rp_filter(own);
        let addresses = self.addresses_at(now);
        let found = match hop {
            IpAddr::V4(hop) => !hop.is_loopback() && addresses.local4(hop),
            IpAddr::V6(hop) => addresses.nd_target(own, hop),
        };
        let comes = addresses.local4(from)
            && found
            && addresses.validate_source4_on(to, 0, 0, rpf, own).is_ok();
        comes.then_some((back, own))
    }
    /// The reverse path filtering of the device `index`: the more of its
    /// and `all`'s (`IN_DEV_RPFILTER`).
    fn rp_filter(&self, index: i32) -> i32 {
        let devices = self.devices();
        devices
            .by_index(index)
            .map_or(0, |d| d.conf4.rp_filter)
            .max(devices.all4.rp_filter)
    }
    /// What ARP finds out through this namespace's veth end `index` for
    /// `to`, asked from `from`: the peer and the end's own Ethernet address
    /// ([`Self::veth_peer`]); and the address of the peer's that answers,
    /// if it does, as `arp_process` takes no request for a loopback address
    /// (with `route_localnet` off) and asks the route in from `from`, which
    /// a request from 0.0.0.0 skips. `None` for no such end.
    fn arp(&self, index: i32, from: Ipv4Addr, to: Ipv4Addr, now: Option<u64>) -> Option<Arp> {
        let (peer, own_mac) = self.veth_peer(index)?;
        let answer = peer.as_ref().and_then(|(there, at, mac)| {
            let their_rpf = there.rp_filter(*at);
            let addresses = there.addresses_at(now);
            let answers = !to.is_loopback()
                && addresses.local4(to)
                && (from.is_unspecified()
                    || addresses
                        .validate_source4_on(from, 0, 0, their_rpf, *at)
                        .is_ok());
            answers.then_some(*mac)
        });
        Some(Arp {
            peer,
            answer,
            own_mac,
        })
    }
    /// A request with `NTF_USE` or `NTF_MANAGED` resolves the neighbour
    /// `to` of the veth end `index` at `now` (`neigh_event_send`): its
    /// probe goes without a packet, from the address `inet_select_addr`
    /// picks on the end for link scope (`arp_solicit`), and an answer
    /// makes it reachable, and teaches the peer, as a packet's does
    /// ([`Self::reach`]); each told of once the request is done.
    pub(crate) fn arp_resolve(&self, index: i32, to: Ipv4Addr, now: u64) {
        let from = {
            let order = self.devices().order();
            self.addresses()
                .select4(index, Some(to), crate::interface::SCOPE_LINK, &order)
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        };
        let Some(Arp {
            peer,
            answer,
            own_mac,
            ..
        }) = self.arp(index, from, to, Some(now))
        else {
            return;
        };
        let (_, asked, events) = self
            .addresses_at(Some(now))
            .neigh_output(index, to, answer, now);
        self.later(events);
        if asked
            && answer.is_some()
            && !from.is_unspecified()
            && let Some((there, peer_index, ..)) = &peer
        {
            let events = there
                .addresses_at(Some(now))
                .neigh_learn(*peer_index, from, own_mac, now);
            there.later(events);
        }
    }
    /// What an IPv6 packet from `from` to `to` out through this
    /// namespace's veth end `index` finds at `now`, as [`Self::reach`]
    /// tells for IPv4, its neighbour, its route's gateway or else `to`
    /// ([`Self::next_hop6`]), resolved by neighbour discovery
    /// ([`Self::nd`]):
    /// - Nothing answers ([`Reach::Unanswered`]) unless the end has its
    ///   carrier, a solicitation goes ([`crate::interface::Addresses::ns_source`]),
    ///   and the peer, taking IPv6, has that neighbour's address on its
    ///   end, not tentative (`ndisc_recv_ns`); its advertisement makes the neighbour
    ///   reachable, and the solicitation teaches the peer its sender
    ///   ([`Self::teach6`]).
    /// - The packet is lost ([`Reach::Dropped`]) where its neighbour's
    ///   address is not the peer's, the peer has not its carrier or takes
    ///   no IPv6, `from` or `to` is a loopback address (`ip6_rcv_core`),
    ///   or the peer's namespace has not `to`, not tentative (no local
    ///   route: `ip6_route_input`, and no forwarding).
    /// - The packet comes there, and the answer back ([`Reach::Answered`])
    ///   only where that namespace's comes to this one ([`Self::back6`]);
    ///   else that answer goes nowhere ([`Reach::OneWay`]).
    fn reach6(
        &self,
        index: i32,
        from: Ipv6Addr,
        to: Ipv6Addr,
        flow: &Flow,
        now: Option<u64>,
    ) -> Reach {
        let hop = self.next_hop6(index, to, &Self::flow6(flow.src, flow.proto), now);
        let Some(lladdr) = self.neighbour6(index, Some(from), hop, now) else {
            return Reach::Unanswered;
        };
        let peer = self.nd_peer(index);
        let Some((there, peer_index, _)) = peer.filter(|p| p.2 == lladdr) else {
            return Reach::Dropped;
        };
        if from.is_loopback() || to.is_loopback() {
            return Reach::Dropped;
        }
        if !there.addresses_at(now).local6(to) {
            return Reach::Dropped;
        }
        // To a link-local address the answer goes out through the device
        // the packet came in on, where the listener is bound to none
        // (`tcp_v6_init_req`, `icmp6_send`).
        let oif = match there.answer_oif(IpAddr::V6(to), flow, peer_index) {
            0 if from.is_unicast_link_local() => peer_index.unsigned_abs(),
            oif => oif,
        };
        let back = self.back6(&there, from, to, oif, flow.proto, now);
        Self::answered(there, flow, oif, back)
    }
    /// [`Self::back4`] of an IPv6 answer of the protocol `proto`, routed
    /// with the device `oif` named (0 for none): its next hop must be an
    /// address of the end it comes in on, as neighbour discovery finds it
    /// ([`crate::interface::Addresses::nd_target`]), and this namespace must
    /// have `from`, not tentative. An ICMPv6 error of Linux's takes the hop
    /// of the packet it tells of (`icmp6_send`), whose flow label is random,
    /// and from 7.2 TCP's answer its own random one
    /// (`ip6_ecmp_set_mp_hash`); here both take the answer's flow's.
    fn back6(
        &self,
        there: &Network,
        from: Ipv6Addr,
        to: Ipv6Addr,
        oif: u32,
        proto: u8,
        now: Option<u64>,
    ) -> Option<(i32, i32)> {
        let flow = Self::flow6(Some(IpAddr::V6(to)), proto);
        let route = there
            .addresses_at(now)
            .lookup6_flow(from, oif, &flow)
            .ok()
            .filter(|r| r.kind == crate::interface::Kind::Unicast)?;
        let back = i32::try_from(route.oif).ok()?;
        let own = self.own_end(there, back)?;
        let hop = route.gateway.unwrap_or(from);
        let addresses = self.addresses_at(now);
        (addresses.local6(from) && addresses.nd_target(own, hop)).then_some((back, own))
    }
    /// The device a packet to this namespace's own address `ip` comes in on:
    /// that of its local route, which for an IPv6 one is its address's
    /// device (`addrconf_f6i_alloc`); 0 for an IPv4 one.
    fn local_device(&self, ip: IpAddr, now: Option<u64>) -> u32 {
        match ip {
            IpAddr::V6(ip) => self
                .addresses_at(now)
                .lookup6(ip)
                .ok()
                .filter(|r| r.kind == crate::interface::Kind::Local)
                .map_or(0, |r| r.oif),
            IpAddr::V4(_) => 0,
        }
    }
    /// The device a packet to this namespace's own `to` comes in on: its
    /// local route's, the address's device, as an IPv6 one comes in on its
    /// route's `rt6i_idev` (`ip6_rcv_core`) and an IPv4 one's `rt_iif` is
    /// that route's device (`ip_route_output_key_hash_rcu` sets `orig_oif`
    /// to it); `lo` for none.
    fn arrival_device(&self, to: SocketAddr, now: Option<u64>) -> u32 {
        let device = match plain(to.ip()) {
            ip @ IpAddr::V6(_) => self.local_device(ip, now),
            IpAddr::V4(ip) => self
                .addresses_at(now)
                .lookup4(ip)
                .ok()
                .filter(|r| r.kind == crate::interface::Kind::Local)
                .map_or(0, |r| r.oif),
        };
        if device == 0 {
            crate::netdev::LOOPBACK_OIF
        } else {
            device
        }
    }
    /// The index the peer of this namespace's veth end `index` has in its
    /// own namespace, where a packet out through the end comes in; 0 for
    /// none.
    fn peer_index(&self, index: i32) -> u32 {
        self.devices()
            .by_index(index)
            .and_then(|d| d.veth.as_ref()?.peer.as_ref().map(|p| p.index))
            .and_then(|i| u32::try_from(i).ok())
            .unwrap_or(0)
    }
    /// Where an IPv4 packet to `to` (its address `ip`) goes through the
    /// device `oif`, as `ip_route_output_key_hash_rcu` routes it with one
    /// named: `ENODEV` for none of it, `ENETUNREACH` while it is down; to
    /// a local group (224.0.0.0/24) or the limited broadcast address out
    /// through it at once; else by the tables' routes through it only,
    /// and where none goes, out through it, on link. Through `lo` that
    /// goes nowhere, which is `ENETUNREACH`, where Linux drops it, but for
    /// a group, which comes back in.
    fn route4_through(
        &self,
        to: SocketAddr,
        ip: Ipv4Addr,
        oif: u32,
        now: Option<u64>,
    ) -> Result<Dest, Errno> {
        use crate::interface::Kind;
        let lo = oif == crate::netdev::LOOPBACK_OIF;
        let index = i32::try_from(oif).map_err(|_| ENODEV)?;
        let up = {
            let devices = self.devices();
            let device = devices.by_index(index).ok_or(ENODEV)?;
            device.veth.as_ref().map_or_else(|| self.is_up(), |v| v.up)
        };
        if !up {
            return Err(ENETUNREACH);
        }
        let cast = if ip.is_broadcast() {
            Cast::Broadcast
        } else if ip.is_multicast() {
            Cast::Multicast
        } else {
            Cast::Unicast
        };
        if !lo && (u32::from(ip) & 0xffff_ff00 == 0xe000_0000 || ip.is_broadcast())
            || lo && cast == Cast::Multicast
        {
            return Ok(Dest::Veth(index, cast));
        }
        match self.addresses_at(now).lookup4_flow(ip, 0, oif) {
            Ok(route) if route.kind == Kind::Local => {
                if self.is_up() {
                    Ok(Dest::Here(to))
                } else {
                    Err(ENETUNREACH)
                }
            }
            Ok(route)
                if matches!(route.kind, Kind::Unicast | Kind::Broadcast)
                    && route.oif != crate::netdev::LOOPBACK_OIF =>
            {
                let index = i32::try_from(route.oif).map_err(|_| ENETUNREACH)?;
                let cast = if route.kind == Kind::Broadcast {
                    Cast::Broadcast
                } else {
                    cast
                };
                Ok(Dest::Veth(index, cast))
            }
            Ok(_) => Err(ENETUNREACH),
            Err(_) if lo => Err(ENETUNREACH),
            // On link, through it.
            Err(_) => Ok(Dest::Veth(index, cast)),
        }
    }
    /// The flow of a packet from `from` (the address a socket is bound
    /// to, none for an unbound one) of the protocol `proto`, which chooses
    /// among an IPv6 multipath route's hops (`rt6_multipath_hash`): its
    /// IPv6 source, or `::`, and no flow label.
    fn flow6(from: Option<IpAddr>, proto: u8) -> Flow6 {
        Flow6 {
            src: match from.map(plain) {
                Some(IpAddr::V6(ip)) => Some(ip),
                _ => None,
            },
            label: 0,
            proto,
        }
    }
    /// The neighbour an IPv4 packet to `to` out through the veth end
    /// `index` goes to at `now`, of the flow `flow`: its route's gateway,
    /// that of the hop of a multipath route [`Self::route`] took, where a
    /// route of link scope reaches it, else `to` itself (`rt_nexthop`).
    fn next_hop4(&self, index: i32, to: Ipv4Addr, flow: &Flow, now: Option<u64>) -> IpAddr {
        let order = self.devices().order();
        self.addresses_at(now)
            .output4(to, 0, flow.oif, source4(flow.src), &order)
            .ok()
            .filter(|r| i64::from(r.oif) == i64::from(index) && r.uses_gateway)
            .and_then(|r| r.gateway)
            .unwrap_or(IpAddr::V4(to))
    }
    /// The neighbour a packet of the flow `flow` to `to` out through the
    /// veth end `index` goes to at `now`: the gateway of its route through
    /// that end, the hop of a multipath route [`Self::route`] took, else
    /// `to` itself (`rt6_nexthop`).
    fn next_hop6(&self, index: i32, to: Ipv6Addr, flow: &Flow6, now: Option<u64>) -> Ipv6Addr {
        self.addresses_at(now)
            .lookup6_flow(to, index.unsigned_abs(), flow)
            .ok()
            .and_then(|r| r.gateway)
            .unwrap_or(to)
    }
    /// What neighbour discovery finds out through this namespace's veth
    /// end `index` for `to`, for a packet from `from` (none for a request's
    /// `NTF_USE`): the peer, if the end has its carrier and the peer takes
    /// IPv6 (it has an IPv6 device, an MTU of 1280 at least, and
    /// `disable_ipv6` off: `ipv6_rcv`), with its namespace, index and
    /// Ethernet address; the address its solicitation leaves from, if one
    /// goes; the peer's Ethernet address, if it answers, as it does for an
    /// address of its end not tentative (`ndisc_recv_ns`); and the end's
    /// own address. `None` for no such end.
    fn nd(&self, index: i32, from: Option<Ipv6Addr>, to: Ipv6Addr, now: Option<u64>) -> Option<Nd> {
        let (_, own_mac) = self.veth_peer(index)?;
        let peer = self.nd_peer(index);
        let asker = self
            .addresses_at(now)
            .ns_source(index, from.filter(|f| !f.is_unspecified()));
        let answer = asker.and(peer.as_ref()).and_then(|(there, at, mac)| {
            there.addresses_at(now).nd_target(*at, to).then_some(*mac)
        });
        Some(Nd {
            peer,
            answer,
            own_mac,
            asker,
        })
    }
    /// A solicitation from `asker` at `own_mac` answered by `peer`: the
    /// peer learns of its sender (`ndisc_recv_ns`), and its advertisement
    /// back goes out through that neighbour at once (`ndisc_send_na`'s
    /// `ip6_finish_output2`), which delays, its probe to be answered, as
    /// this end has `asker`; each told of there.
    fn teach6(
        peer: Option<&(Arc<Network>, i32, [u8; 6])>,
        asker: Option<Ipv6Addr>,
        own_mac: [u8; 6],
        now: u64,
    ) {
        let (Some((there, peer_index, _)), Some(asker)) = (peer, asker) else {
            return;
        };
        let events = {
            let mut addresses = there.addresses_at(Some(now));
            let mut events = addresses.neigh_learn(*peer_index, asker, own_mac, now);
            let (_, _, more) = addresses.neigh_output(*peer_index, asker, Some(own_mac), now);
            events.extend(more);
            events
        };
        there.later(events);
    }
    /// A request with `NTF_USE` or `NTF_MANAGED` resolves the IPv6
    /// neighbour `to` of the veth end `index` at `now`, as
    /// [`Self::arp_resolve`] does IPv4's: its solicitation goes without a
    /// packet, from the end's link-local address (`ndisc_send_ns`'s
    /// `ipv6_get_lladdr`), if it has one.
    pub(crate) fn nd_resolve(&self, index: i32, to: Ipv6Addr, now: u64) {
        let Some(Nd {
            peer,
            answer,
            own_mac,
            asker,
        }) = self.nd(index, None, to, Some(now))
        else {
            return;
        };
        let (_, asked, events) = self
            .addresses_at(Some(now))
            .neigh_output(index, to, answer, now);
        self.later(events);
        if asked {
            self.solicit(index, asker, to, now);
        }
        if asked && answer.is_some() {
            Self::teach6(peer.as_ref(), asker, own_mac, now);
        }
    }
    /// A solicitation for `to` goes out through the veth end `index` at
    /// `now` from `asker`, if it has one (none goes without): to `to`'s
    /// solicited-node group, whose neighbour it takes, as any multicast
    /// packet does ([`Self::noarp`]).
    fn solicit(&self, index: i32, asker: Option<Ipv6Addr>, to: Ipv6Addr, now: u64) {
        if asker.is_none() {
            return;
        }
        let o = to.octets();
        let group = Ipv6Addr::new(
            0xff02,
            0,
            0,
            0,
            0,
            1,
            0xff00 | u16::from(o[13]),
            u16::from_be_bytes([o[14], o[15]]),
        );
        self.noarp(index, IpAddr::V6(group), Some(now));
    }
    /// This namespace answers what came from `from` to its `to` at `now`
    /// (a TCP handshake's, or ICMP's port unreachable): what it sends back
    /// takes its neighbour of `from`, as a packet of its own would
    /// ([`Self::reach`]).
    fn reply(&self, answer: &Back, from: IpAddr, to: IpAddr, proto: u8, now: Option<u64>) {
        let flow = Flow {
            src: Some(to),
            oif: answer.oif,
            proto,
            bound: 0,
            port: None,
        };
        let _ = self.reach(answer.index, to, from, &flow, now);
    }
    /// A broadcast or multicast packet goes out through the veth end
    /// `index` to `to` at `now`, taking its neighbour, which needs no ARP
    /// or neighbour discovery
    /// ([`crate::interface::Addresses::neigh_output`]).
    fn noarp(&self, index: i32, to: IpAddr, now: Option<u64>) {
        let (_, _, events) =
            self.addresses_at(now)
                .neigh_output(index, plain(to), None, now.unwrap_or(0));
        self.later(events);
    }
    /// The UDP sockets a broadcast datagram, or one to an IPv4 group, from
    /// `from` to `to`, out through this namespace's device `index` at
    /// `now`, reaches ([`Ports::broadcast_receivers`]), each with whether
    /// it is this namespace's own copy: where it `loops`, this namespace's
    /// own, as `ip_mc_output` loops one back whether or not it goes out,
    /// one to a group only where the device has joined it; then, where it
    /// `leaves` and the end has its carrier, the peer's namespace's. There
    /// `ip_route_input_slow` takes it as a broadcast: to the limited
    /// broadcast address, or to one its routes make a broadcast one, from
    /// a source its reverse path filtering takes, which it does not check
    /// for 0.0.0.0, a source only the limited one takes; or to a group the
    /// peer's end has joined ([`Self::takes_group4`]). None to an IPv6 one.
    fn copies(
        &self,
        index: i32,
        from: SocketAddr,
        to: SocketAddr,
        (loops, leaves): (bool, bool),
        now: Option<u64>,
    ) -> Vec<(Arc<InetSocket>, bool)> {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (from.ip(), to.ip()) else {
            return Vec::new();
        };
        let group = dst.is_multicast().then_some(dst);
        // The sockets of a namespace its copy in on a device reaches.
        let reached = |network: &Network, dif: i32| -> Vec<Arc<InetSocket>> {
            let dif = dif.unsigned_abs();
            let mut found = network.ports(true).broadcast_receivers(to, from, dif);
            found.retain(|socket| group.is_none_or(|group| socket.takes_group(group, dif)));
            found
        };
        let mut receivers = Vec::new();
        // Its own copy comes in on the end it went out through.
        if loops && group.is_none_or(|group| self.in_group4(index, group)) {
            receivers.extend(reached(self, index).into_iter().map(|s| (s, true)));
        }
        if !leaves {
            return receivers;
        }
        let peer = {
            let devices = self.devices();
            devices
                .by_index(index)
                .and_then(|d| d.veth.as_ref())
                .filter(|v| v.carrier)
                .and_then(|v| v.peer.clone())
        };
        let Some((there, at)) = peer.and_then(|p| p.network.upgrade().map(|n| (n, p.index))) else {
            return receivers;
        };
        let rpf = {
            let devices = there.devices();
            devices
                .by_index(at)
                .map_or(0, |d| d.conf4.rp_filter)
                .max(devices.all4.rp_filter)
        };
        let arrives = if let Some(group) = group {
            there.takes_group4(at, src, group, now)
        } else {
            let addresses = there.addresses_at(now);
            let broadcast = dst.is_broadcast()
                || (!src.is_unspecified()
                    && !dst.is_unspecified()
                    && !dst.is_loopback()
                    && addresses
                        .lookup4(dst)
                        .is_ok_and(|r| r.kind == crate::interface::Kind::Broadcast));
            broadcast
                && !src.is_multicast()
                && !src.is_broadcast()
                && (src.is_unspecified()
                    || addresses.validate_source4_on(src, 0, 0, rpf, at).is_ok())
        };
        if arrives {
            receivers.extend(reached(&there, at).into_iter().map(|s| (s, false)));
        }
        receivers
    }
    /// Keeps what a packet changed for netlink to tell of, as what runs
    /// out is ([`Self::addresses_at`]).
    fn later(&self, events: Vec<crate::interface::Event>) {
        if !events.is_empty() {
            self.expired
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(events);
        }
    }
    /// A packet goes out through the loopback to `to` at the host's
    /// monotonic `now` ([`crate::interface::Addresses::output`]).
    fn output(&self, to: IpAddr, now: Option<u64>) {
        self.addresses().output(plain(to), now.unwrap_or(0));
    }
    /// Its network devices.
    pub(crate) fn devices(&self) -> MutexGuard<'_, crate::netdev::Devices> {
        self.devices.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether it has a device of `index` (`__dev_get_by_index`), which an
    /// address, route or neighbour request names.
    pub(crate) fn has_device(&self, index: impl TryInto<i32>) -> bool {
        index
            .try_into()
            .is_ok_and(|index| self.devices().by_index(index).is_some())
    }
    /// The loopback's addresses.
    pub(crate) fn addresses(&self) -> MutexGuard<'_, crate::interface::Addresses> {
        self.addresses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// The loopback's addresses at the host's monotonic `now`, which a
    /// socket uses: what has run out by then goes first, as Linux's work
    /// would have taken it on time, and what that tells is kept for
    /// netlink ([`crate::netlink::expire`]).
    pub(crate) fn addresses_at(
        &self,
        now: Option<u64>,
    ) -> MutexGuard<'_, crate::interface::Addresses> {
        let mut addresses = self.addresses();
        if let Some(now) = now {
            let events = addresses.expire(now);
            if !events.is_empty() {
                self.expired
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(events);
            }
        }
        addresses
    }
    /// What has run out by `now`, as [`Self::addresses_at`] takes it, after
    /// what a socket found before, in the order it went.
    pub(crate) fn expire(&self, now: u64) -> Vec<crate::interface::Event> {
        let mut addresses = self.addresses();
        let fresh = addresses.expire(now);
        let mut events =
            core::mem::take(&mut *self.expired.lock().unwrap_or_else(PoisonError::into_inner));
        events.extend(fresh);
        events
    }
    /// The address a packet to `to` of the protocol `proto` leaves from at
    /// `now`, from a socket bound to none: its route's source.
    ///
    /// For IPv4 through a device `oif` other than 0, as
    /// `ip_route_output_key_hash_rcu` takes it with a device named: an
    /// address of the device's (`inet_select_addr`) of link scope to a local
    /// group or the limited broadcast address, of any scope to another
    /// group, and to an address no route through it takes, on link; else
    /// its route's; 0.0.0.0 for none of these.
    ///
    /// For IPv6, its route's through the device, if one is named
    /// (`ip6_route_get_saddr`), looked up strictly, as no source is chosen
    /// yet; of a multipath route, the source of the hop the packet takes.
    pub(crate) fn source_through(
        &self,
        to: SocketAddr,
        oif: u32,
        proto: u8,
        now: Option<u64>,
    ) -> IpAddr {
        use crate::interface::{SCOPE_LINK, SCOPE_UNIVERSE};
        let order = self.devices().order();
        let addresses = self.addresses_at(now);
        if let (IpAddr::V4(ip), Ok(index)) = (plain(to.ip()), i32::try_from(oif))
            && oif != 0
        {
            let local_group = u32::from(ip) & 0xffff_ff00 == 0xe000_0000 || ip.is_broadcast();
            let picked = if local_group {
                addresses.select4(index, None, SCOPE_LINK, &order)
            } else if ip.is_multicast() {
                addresses.select4(index, None, SCOPE_UNIVERSE, &order)
            } else {
                match addresses.lookup4_flow(ip, 0, oif) {
                    Ok(route) => addresses.source4(&route, ip, &order),
                    Err(_) => addresses.select4(index, None, SCOPE_LINK, &order),
                }
            };
            return IpAddr::V4(picked.unwrap_or(Ipv4Addr::UNSPECIFIED));
        }
        if let IpAddr::V6(ip) = to.ip() {
            let flow = Self::flow6(None, proto);
            return IpAddr::V6(addresses.source6_through(ip, oif, &flow, &order));
        }
        addresses.source(to.ip(), &order)
    }
    /// Whether a socket may bind to `ip`: the unspecified address, an IPv4
    /// multicast or limited broadcast one, one a local or broadcast route
    /// has (any IPv4 one before there is a route at all, as Linux's
    /// `inet_addr_type` finds none), or an IPv6 address of the loopback.
    fn bindable(&self, ip: IpAddr, now: Option<u64>) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || self.addresses_at(now).bindable4(ip)
            }
            IpAddr::V6(ip) => ip.is_unspecified() || self.addresses_at(now).local6(ip),
        }
    }
    /// Whether IPv4's `inet_addr_type` makes `ip` a broadcast or multicast
    /// address: the limited broadcast address, a group, or one the local
    /// table has a broadcast route to.
    fn broadcast4(&self, ip: Ipv4Addr, now: Option<u64>) -> bool {
        ip.is_broadcast() || ip.is_multicast() || self.subnet_broadcast4(ip, now)
    }
    /// Whether the local table has a broadcast route to `ip`.
    fn subnet_broadcast4(&self, ip: Ipv4Addr, now: Option<u64>) -> bool {
        let addresses = self.addresses_at(now);
        addresses.has_table4(crate::interface::TABLE_LOCAL)
            && addresses.bindable4(ip)
            && !addresses.local4(ip)
    }
    /// Whether a socket on the device `index` (or none, 0) may bind the
    /// IPv6 address `ip` (`ipv6_chk_addr`): an address of this namespace's,
    /// of that device's where it is link-local or a loopback one.
    fn bindable6_on(&self, ip: Ipv6Addr, index: u32, now: Option<u64>) -> bool {
        match i32::try_from(index) {
            Ok(index) if index != 0 => self.addresses_at(now).local6_on(ip, index),
            _ => self.addresses_at(now).local6(ip),
        }
    }
    /// The user namespace whose `CAP_NET_ADMIN` changes this network, as
    /// Linux's `dev_ioctl` asks of `sock_net(sk)->user_ns`.
    pub(crate) fn owner(&self) -> &crate::namespaces::Namespace {
        self.owner.as_deref().unwrap_or(crate::users::first())
    }
    /// The loopback's settings ([`crate::netconf`]).
    pub(crate) fn lo_conf(&self) -> (crate::netdev::Conf4, crate::netdev::Conf6) {
        self.devices()
            .by_index(crate::netdev::LOOPBACK_INDEX)
            .map(|lo| (lo.conf4, lo.conf6))
            .unwrap_or_default()
    }
    /// Whether the loopback's IPv6 is off (`disable_ipv6`).
    pub(crate) fn ipv6_off(&self) -> bool {
        self.lo_conf().1.disable_ipv6 != 0
    }
    /// Whether the loopback is up.
    pub(crate) fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }
    /// Whether the loopback has ever been up.
    pub(crate) fn has_been_up(&self) -> bool {
        self.ever_up.load(Ordering::SeqCst)
    }
    /// Brings the loopback up or down, as `SIOCSIFFLAGS` or netlink's
    /// `RTM_NEWLINK` with `IFF_UP` does, with what that does to its
    /// addresses ([`crate::interface::Addresses::up`] and `down`).
    /// `None` when it already is, else what happened to the addresses and
    /// routes at `now`, for netlink to tell ([`crate::netlink::set_up`]).
    pub(crate) fn set_up(&self, up: bool, now: u64) -> Option<Vec<crate::interface::Event>> {
        // The devices, alone, before the addresses.
        let v6 = !self.ipv6_off();
        let mut addresses = self.addresses();
        if up == self.is_up() {
            return None;
        }
        let events = if up {
            self.ever_up.store(true, Ordering::SeqCst);
            addresses.up(now, v6)
        } else {
            addresses.down()
        };
        self.up.store(up, Ordering::SeqCst);
        drop(addresses);
        // `ip_mc_up` and `ip_mc_down`.
        let lo = crate::netdev::LOOPBACK_INDEX;
        self.change_group4(lo, crate::multicast::ALL_HOSTS, up);
        Some(events)
    }
    /// Turns the loopback's IPv6 off or on, as a change of its
    /// `disable_ipv6` does (`dev_disable_change`): off, it loses its IPv6
    /// addresses and routes (`addrconf_ifdown`); on, while it is up, it
    /// takes `::1` and its permanent addresses' routes back at `now`
    /// (`NETDEV_UP`). What happened, for netlink to tell
    /// ([`crate::netlink::set_ipv6`]).
    pub(crate) fn set_ipv6(&self, on: bool, now: u64) -> Vec<crate::interface::Event> {
        let mut addresses = self.addresses();
        if !on {
            addresses.down6()
        } else if self.is_up() {
            addresses.up6(now)
        } else {
            Vec::new()
        }
    }
    /// `SIOCGIFFLAGS`, `SIOCSIFFLAGS` and `SIOCGIFINDEX` on the interface
    /// `name` (the `ifr_name` of a `struct ifreq`): the loopback `lo`, index
    /// 1, or a veth end ([`crate::netdev`]); `ENODEV` for another. Setting
    /// flags needs CAP_NET_ADMIN (`EPERM`, before the name is looked at) and
    /// takes only `IFF_UP`: a veth end comes up or goes down as
    /// `RTM_SETLINK` has it ([`crate::netlink::veth_set_up`]); the loopback
    /// with what that does to its addresses ([`Self::set_up`]): down, it
    /// loses every IPv6 address; up, it has `127.0.0.1/8` and `::1` back,
    /// made at `now`.
    pub(crate) fn interface(
        self: &Arc<Self>,
        name: &[u8],
        request: u64,
        flags: u16,
        may_administer: bool,
        now: u64,
    ) -> Result<u32, Errno> {
        // `dev_ioctl` checks the capability before it looks the name up.
        if request == SIOCSIFFLAGS && !may_administer {
            return Err(Errno::EPERM);
        }
        let Some(device) = self.devices().by_name(name).cloned() else {
            return Err(ENODEV);
        };
        let index = device.index;
        // A veth end's own flags; bringing it up or down tells both its
        // namespace and its peer's.
        if device.kind == crate::netdev::DeviceKind::Veth {
            return match request {
                SIOCGIFFLAGS => Ok(u32::from(crate::netlink::veth_ioctl_flags(&device))),
                SIOCSIFFLAGS => {
                    let mut notices = Vec::new();
                    crate::netlink::veth_set_up(
                        self,
                        self,
                        index,
                        flags & IFF_UP != 0,
                        now,
                        &mut notices,
                    );
                    crate::netlink::notify_link(self, notices);
                    Ok(0)
                }
                _ => Ok(index.unsigned_abs()),
            };
        }
        match request {
            SIOCGIFFLAGS => Ok(u32::from(if self.up.load(Ordering::SeqCst) {
                IFF_UP | IFF_LOOPBACK | IFF_RUNNING
            } else {
                IFF_LOOPBACK
            })),
            SIOCSIFFLAGS => {
                crate::netlink::set_up(self, flags & IFF_UP != 0, now);
                Ok(0)
            }
            _ => Ok(index.unsigned_abs()),
        }
    }
    /// How many dropped handshakes wait to be tried again.
    #[cfg(test)]
    pub(crate) fn syns(&self) -> usize {
        self.syns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
    fn ports(&self, datagram: bool) -> MutexGuard<'_, Ports> {
        if datagram {
            &self.udp_ports
        } else {
            &self.tcp_ports
        }
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether the guest may connect to `address` at `now`.
    fn allows(&self, address: SocketAddr, now: u64) -> bool {
        let ip = plain(address.ip());
        let resolved = self.resolved.lock().unwrap_or_else(PoisonError::into_inner);
        let names = resolved.get(&ip).map_or(&[][..], Vec::as_slice);
        let names = names
            .iter()
            .filter(|(_, given)| now.saturating_sub(*given) < NAME_LIFETIME)
            .map(|(name, _)| name);
        self.policy.rules.iter().any(|rule| match rule {
            Rule::Address { ip: allowed, port } => {
                plain(*allowed) == ip && port.is_none_or(|port| port == address.port())
            }
            Rule::Name {
                name,
                subdomains,
                port,
            } => {
                port.is_none_or(|port| port == address.port())
                    && names
                        .clone()
                        .any(|resolved| matches_name(name, *subdomains, resolved))
            }
        })
    }
    /// The lookup of `name`: one already made in the last
    /// [`LOOKUP_LIFETIME`], or a new one. Each socket waiting for it adds
    /// its own waker.
    fn lookup(&self, host: &dyn paludarium_host::Host, name: &str) -> Result<Arc<Lookup>, Errno> {
        let now = host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0);
        let mut lookups = self.lookups.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((lookup, started)) = lookups.get(name)
            && (lookup.result().is_none_or(|result| result.is_ok())
                && now.saturating_sub(*started) < LOOKUP_LIFETIME)
        {
            return Ok(Arc::clone(lookup));
        }
        let lookup = host.resolve(name)?;
        lookups.insert(name.to_owned(), (Arc::clone(&lookup), now));
        Ok(lookup)
    }
    /// Notes that the stub gave `addresses` for `name` at `now`, and
    /// forgets what has expired.
    fn note(&self, name: &str, addresses: &[IpAddr], now: u64) {
        let mut resolved = self.resolved.lock().unwrap_or_else(PoisonError::into_inner);
        resolved.retain(|_, names| {
            names.retain(|(_, given)| now.saturating_sub(*given) < NAME_LIFETIME);
            !names.is_empty()
        });
        for ip in addresses {
            let names = resolved.entry(plain(*ip)).or_default();
            names.retain(|(known, _)| known != name);
            names.push((name.to_owned(), now));
        }
    }
}

/// `socket(domain, type, protocol)` for `AF_INET` and `AF_INET6`, with
/// Linux's `inet_create` checks: a stream is TCP and a datagram UDP; an
/// ICMP datagram is `EACCES`, as outside `net.ipv4.ping_group_range`; a raw
/// socket is `EPERM`; any other type `ESOCKTNOSUPPORT`.
pub(crate) fn socket(
    c: &Context<'_>,
    a: [u64; 6],
    network: &Arc<Network>,
) -> Result<Arc<dyn FileHandle>, Errno> {
    let flags = a[1] as u32 & (NONBLOCK | CLOEXEC);
    let family = if a[0] == u64::from(AF_INET) {
        Family::V4
    } else {
        Family::V6
    };
    let datagram = match (a[1] as u32 & 0xf, a[2]) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => false,
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => true,
        (SOCK_DGRAM, IPPROTO_ICMP | IPPROTO_ICMPV6) => return Err(Errno(13)),
        (SOCK_STREAM | SOCK_DGRAM, _) => return Err(EPROTONOSUPPORT),
        (SOCK_RAW, _) => return Err(Errno(1)),
        _ => return Err(ESOCKTNOSUPPORT),
    };
    let socket = InetSocket::new(
        family,
        datagram,
        network,
        c.shared_host,
        &c.files.readiness,
        flags,
    );
    socket.own(c);
    if datagram {
        // `net.core.rmem_default` and `wmem_default`.
        let mut options = socket.options();
        options.send_buffer = 212_992;
        options.receive_buffer = 212_992;
    }
    Ok(socket)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Where a TCP socket's connection stands, as Linux's `socket_state`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Connection {
    #[default]
    Unconnected,
    Connecting,
    Connected,
}

/// A DNS query the stub owes an answer, as one datagram from `from`.
struct Query {
    from: SocketAddr,
    /// Its place among what the socket has received (`State::received`).
    seq: u64,
    id: [u8; 2],
    /// The header's flags word, the question as sent, and its name.
    flags: u16,
    question: Vec<u8>,
    name: String,
    kind: u16,
    answer: Answer,
}
enum Answer {
    Now(u8),
    Lookup(Arc<Lookup>),
}

#[derive(Default)]
struct State {
    // TCP.
    connection: Connection,
    stream: Option<Arc<Stream>>,
    /// The stream's failure was seen: `error` holds it until it is taken.
    noted: bool,
    /// `sk_err`: the pending error, which `SO_ERROR` takes.
    error: Option<Errno>,
    read_shut: bool,
    /// A read has met the peer's end, which moves Linux's `copied_seq`
    /// past its FIN (`tcp_recvmsg`'s `found_fin_ok`).
    eof_read: bool,
    /// A UDP socket's `SHUT_WR` (TCP's is its stream's).
    write_shut: bool,
    /// What the connection has carried, for `tcp_info`.
    counts: Counts,
    // The guest's loopback.
    /// The address a TCP socket holds its local port on: its `bind`'s, or
    /// the one `listen` or a loopback connection took.
    bound: Option<SocketAddr>,
    /// The guest named the port itself, so that a disconnect keeps it
    /// (Linux's `SOCK_BINDPORT_LOCK`), or the address (`SOCK_BINDADDR_LOCK`).
    port_locked: bool,
    address_locked: bool,
    /// An IPv4 socket bound to a broadcast or multicast address sends from
    /// its route's source, not from that address, which stays its name
    /// (`inet_bind`'s `inet_saddr = 0`, "use device").
    device_source: bool,
    /// The address a disconnect kept without its port, which the next
    /// automatic bind takes.
    address: Option<IpAddr>,
    listen: Option<Listen>,
    /// The loopback connection the stream is a side of, once its listener
    /// has taken it.
    link: Option<(Arc<OnceLock<Arc<Link>>>, usize)>,
    // UDP.
    peer: Option<SocketAddr>,
    /// The address of the peer an IPv6 socket had before it disconnected,
    /// which its binding has too ([`Binding::old_peer`]): kept here, as the
    /// disconnect may unbind the socket, for the next bind or autobind.
    old_peer: Option<IpAddr>,
    queries: VecDeque<Query>,
    /// Datagrams other guest sockets sent this one on the loopback.
    inbox: VecDeque<Datagram>,
    /// The IPv4 groups it is a member of (`mc_list`), the newest first.
    groups4: Vec<Membership>,
    /// What the inbox takes of `SO_RCVBUF`, as Linux's `sk_rmem_alloc`.
    inbox_size: usize,
    /// How many datagrams and queries have come, which orders them.
    received: u64,
    /// The socket filter and its lock (`sk_filter`, `SOCK_FILTER_LOCKED`).
    filtering: crate::sockets::FilterSlot,
    /// The datagrams it dropped as they came (`sk_drops`): those its
    /// filter dropped and those its full receive buffer did.
    drops: u32,
    /// A connected socket's last IPv4 ID, from the random one `connect`
    /// gives (`inet_id`), and its flow hash (`sk_txhash`), which `connect`
    /// gives too and a disconnect keeps.
    ip_id: u16,
    txhash: u32,
}

/// What a TCP connection has carried, for `tcp_info`: from its handshake's
/// first segment, or its creation on the side that accepted it.
#[derive(Default, Clone, Copy)]
struct Counts {
    /// When it began, on the host's monotonic clock.
    opened: Option<u64>,
    /// The bytes the guest wrote and read.
    written: u64,
    read: u64,
    /// When the guest last wrote and read bytes.
    wrote: Option<u64>,
    came: Option<u64>,
    /// The receive window scale its handshake offered, which stays
    /// (`tcp_select_initial_window`).
    rcv_wscale: u8,
}
impl Counts {
    /// A connection that begins at `opened` with `options`.
    fn new(opened: Option<u64>, options: &Options) -> Self {
        Self {
            opened,
            rcv_wscale: tcp_info::receive_wscale(
                options
                    .receive_buffer_set
                    .then_some(options.receive_buffer as u32),
            ),
            ..Self::default()
        }
    }
}

/// A datagram from another guest socket.
struct Datagram {
    from: SocketAddr,
    seq: u64,
    /// The real time it came, which a timestamp gives.
    came: Option<u64>,
    bytes: Vec<u8>,
    /// What it takes of the receive buffer ([`truesize`]).
    size: usize,
}
/// What a datagram of `len` bytes on the loopback takes of the receive
/// buffer, as x86-64 Linux 7.0 counts its `skb->truesize`: the `sk_buff`
/// (256 bytes) and its head, from the small head cache or the
/// smallest power of two that holds the headers, the bytes, the room
/// `__ip_append_data` (or `__ip6_append_data`) reserves and the
/// `skb_shared_info`, or past `SKB_MAX_ALLOC` a small head and the bytes in
/// page fragments. An IPv6 datagram too long for the loopback's MTU comes
/// as two fragments, reassembled.
fn truesize(len: usize, ipv4: bool) -> usize {
    use crate::skb::{MAX_ALLOC, SKB, SMALL_HEAD};
    const MTU: usize = 65_536;
    // The IP and UDP headers, and the link header's room and the tail's
    // (IPv4) or the fragment header's (IPv6).
    let (headers, reserved) = if ipv4 { (28, 31) } else { (48, 24) };
    if !ipv4 && len + headers > MTU {
        // The first fragment holds what fits in eights; the rest is small.
        let first = (MTU - headers - 8) & !7;
        return 2 * (SKB + SMALL_HEAD) + first;
    }
    let head = len + headers + reserved;
    if head >= MAX_ALLOC {
        return SKB + SMALL_HEAD + len;
    }
    crate::skb::truesize(head)
}

/// A listening socket's connections, as Linux's accept queue.
struct Listen {
    /// The most connections waiting, less one (`sk_max_ack_backlog`).
    backlog: usize,
    ready: VecDeque<Arc<InetSocket>>,
    arrivals: u64,
    /// The handshakes a full queue dropped (`tcp_listendrop`).
    drops: u32,
}
/// A loopback connection whose handshake found the listener's queue full,
/// which Linux drops (`tcp_conn_request`): the client sends it again at
/// [`SYN_RETRIES`] after `start`, to whatever listens at `to` then.
struct Syn {
    stream: Weak<Stream>,
    /// The namespace whose listener it knocks at: this one's, or that of
    /// a veth end's peer.
    there: Weak<Network>,
    link: Arc<OnceLock<Arc<Link>>>,
    /// What tells the client of an urgent byte.
    notify: crate::loopback::Notify,
    from: SocketAddr,
    to: SocketAddr,
    /// The device it comes in on there.
    dif: u32,
    /// The veth end it goes out through, or `None` on the loopback.
    veth: Option<i32>,
    /// The connecting socket, whose SYN each try is.
    client: Weak<InetSocket>,
    start: u64,
    /// How many of [`SYN_RETRIES`] it has made.
    tries: usize,
}
impl Syn {
    /// Its client's stream, while it still waits to connect.
    fn waiting(&self) -> Option<Arc<Stream>> {
        self.stream
            .upgrade()
            .filter(|stream| stream.phase() == Phase::Connecting && !stream.finished().1)
    }
    /// When it is next tried, or after the last try given up.
    fn next(&self) -> u64 {
        let seconds = SYN_RETRIES.get(self.tries).copied().unwrap_or(SYN_TIMEOUT);
        self.start.saturating_add(seconds * 1_000_000_000)
    }
}
/// Where a connection or datagram goes ([`Network::route`]).
enum Dest {
    /// To an address of its own namespace, through the loopback.
    Here(SocketAddr),
    /// Off the guest's networks, to the host's.
    Away,
    /// Out through the namespace's veth end of this index.
    Veth(i32, Cast),
}
/// The type of a route out through a veth end ([`Network::route`]), whose
/// flags (`RTCF_BROADCAST`, `RTCF_MULTICAST`) TCP refuses
/// (`tcp_v4_connect`: `ENETUNREACH`) and UDP takes only to a group, or
/// with `SO_BROADCAST` (`EACCES`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cast {
    Unicast,
    Broadcast,
    Multicast,
}
/// What the route a packet takes is looked up with, which chooses among a
/// multipath route's hops: the source (the address a socket is bound to,
/// none for an unbound one), the device named (0 for none) and the
/// protocol.
struct Flow {
    src: Option<IpAddr>,
    oif: u32,
    proto: u8,
    /// The device the socket is bound to, 0 for none.
    bound: u32,
    /// The port a TCP connection goes to, whose listener's answer goes out
    /// through the device that is bound to; else answers go by their route
    /// alone.
    port: Option<u16>,
}
/// Where an answer goes out: through the veth end `index`, by a lookup with
/// the device `oif` named (0 for none).
struct Back {
    index: i32,
    oif: u32,
}
/// What a packet out through a veth end finds ([`Network::reach`]).
enum Reach {
    /// It comes to this namespace, and its answers come back.
    Answered(Arc<Network>, Back),
    /// It comes to this namespace, and its answers go nowhere.
    OneWay(Arc<Network>),
    /// ARP is answered, and the packet dropped where it comes.
    Dropped,
    /// Nobody answers ARP for its destination.
    Unanswered,
}
/// What ARP finds out through a veth end ([`Network::arp`]).
struct Arp {
    peer: Option<(Arc<Network>, i32, [u8; 6])>,
    answer: Option<[u8; 6]>,
    own_mac: [u8; 6],
}
/// What neighbour discovery finds out through a veth end ([`Network::nd`]).
struct Nd {
    peer: Option<(Arc<Network>, i32, [u8; 6])>,
    answer: Option<[u8; 6]>,
    own_mac: [u8; 6],
    asker: Option<Ipv6Addr>,
}
/// What a handshake found.
enum Knock {
    Taken,
    Full,
    Refused,
}
impl Listen {
    fn new(backlog: usize) -> Self {
        Self {
            backlog,
            ready: VecDeque::new(),
            arrivals: 0,
            drops: 0,
        }
    }
    fn has_room(&self) -> bool {
        self.ready.len() <= self.backlog
    }
    /// Ends listening, as Linux's `inet_csk_listen_stop`: each connection
    /// not yet accepted is reset. One whose handshake was dropped learns at
    /// its next try.
    fn stop(self) {
        for child in self.ready {
            child.abort();
        }
    }
}
impl State {
    /// The source a route from this socket is looked up with: the address
    /// it is bound to, unless that is one it sends from the route's source
    /// instead of.
    fn source(&self) -> Option<IpAddr> {
        self.bound.filter(|_| !self.device_source).map(|b| b.ip())
    }
    /// Notes the failure of the stream, once.
    fn note(&mut self) {
        if !self.noted
            && let Some(stream) = &self.stream
            && let Phase::Failed(error) = stream.phase()
        {
            self.noted = true;
            self.error = Some(error);
        }
    }
}

/// The `int` options a TCP or UDP socket keeps, with Linux's defaults.
#[derive(Clone, Copy)]
struct Options {
    reuse_address: bool,
    reuse_port: bool,
    keep_alive: bool,
    broadcast: bool,
    out_of_band_inline: bool,
    priority: i32,
    linger: Option<i32>,
    send_buffer: i32,
    receive_buffer: i32,
    /// The guest set `SO_SNDBUF` or `SO_RCVBUF`, which Linux's
    /// `SOCK_SNDBUF_LOCK` and `SOCK_RCVBUF_LOCK` keep from autotuning.
    send_buffer_set: bool,
    receive_buffer_set: bool,
    receive_timeout: Timeout,
    send_timeout: Timeout,
    no_delay: bool,
    cork: bool,
    keep_idle: i32,
    keep_interval: i32,
    keep_count: i32,
    quick_ack: bool,
    user_timeout: i32,
    type_of_service: i32,
    v6_only: bool,
    /// The device the socket is bound to (`sk_bound_dev_if`), which a
    /// link-local address's scope ID gives, or 0.
    device: u32,
    /// `IPV6_MULTICAST_IF` (`mcast_oif`) and `IPV6_UNICAST_IF`
    /// (`ucast_oif`): the device a datagram to a group, or to another
    /// address, goes out through where nothing else names one; 0 for none.
    multicast_device: u32,
    unicast_device: u32,
    /// `IP_MULTICAST_IF`: the device (`mc_index`) a datagram to an IPv4
    /// group goes out through where the socket has none, 0 for none, and
    /// the address (`mc_addr`) it leaves from where it is bound to none.
    multicast4: (u32, Ipv4Addr),
    /// `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP` (whether an IPv4 socket's
    /// datagram to a group comes back here) and `IP_MULTICAST_ALL` (whether
    /// it takes the groups the devices are in for other sockets).
    multicast_ttl: u8,
    multicast_loop: bool,
    multicast_all: bool,
    /// The sticky `IPV6_PKTINFO`'s device (`sticky_pktinfo`), which a
    /// datagram goes out through after the socket's own; its address sends
    /// from nowhere.
    pktinfo_device: u32,
    /// `SO_TIMESTAMP`, its kin and `SO_TIMESTAMPING`.
    timestamps: Timestamps,
}
impl Options {
    /// The device a datagram to the IPv6 address `to` goes out through, of
    /// no scope ID (`udpv6_sendmsg`, `ip6_datagram_flow_key_init`): the
    /// socket's, else the sticky `IPV6_PKTINFO`'s, else
    /// `IPV6_MULTICAST_IF`'s to a group and `IPV6_UNICAST_IF`'s to another
    /// address; 0 for none.
    fn device6(&self, to: Ipv6Addr) -> u32 {
        let last = if to.is_multicast() {
            self.multicast_device
        } else {
            self.unicast_device
        };
        [self.device, self.pktinfo_device, last]
            .into_iter()
            .find(|&device| device != 0)
            .unwrap_or(0)
    }
}
impl Default for Options {
    fn default() -> Self {
        Self {
            reuse_address: false,
            reuse_port: false,
            keep_alive: false,
            broadcast: false,
            out_of_band_inline: false,
            priority: 0,
            linger: None,
            send_buffer: 16384,
            receive_buffer: 131_072,
            send_buffer_set: false,
            receive_buffer_set: false,
            receive_timeout: Timeout::Forever,
            send_timeout: Timeout::Forever,
            no_delay: false,
            cork: false,
            keep_idle: 7200,
            keep_interval: 75,
            keep_count: 9,
            quick_ack: true,
            user_timeout: 0,
            type_of_service: 0,
            v6_only: false,
            device: 0,
            multicast_device: 0,
            unicast_device: 0,
            multicast4: (0, Ipv4Addr::UNSPECIFIED),
            multicast_ttl: 1,
            multicast_loop: true,
            multicast_all: true,
            pktinfo_device: 0,
            timestamps: Timestamps::default(),
        }
    }
}

impl Filtered for InetSocket {
    fn with_filter<R>(&self, f: impl FnOnce(&mut crate::sockets::FilterSlot) -> R) -> R {
        f(&mut self.lock().filtering)
    }
    fn filter_socket(&self) -> (crate::bpf_prog::FilterSocket, u32) {
        (
            crate::bpf_prog::FilterSocket::Inet(Weak::clone(&self.this)),
            self.uid.load(Ordering::SeqCst),
        )
    }
}

/// Signal-driven I/O of a socket, as Linux's `sock_wake_async` sends it:
/// the owner and signal `F_SETOWN` and `F_SETSIG` set, the descriptor
/// `O_ASYNC` was set through, and its `SOCKWQ_ASYNC_WAITDATA` and
/// `SOCKWQ_ASYNC_NOSPACE` bits.
#[derive(Default)]
struct Signals {
    owner: Mutex<FileOwner>,
    registration: Mutex<Option<Registration>>,
    /// A blocking read waits for data, which then signals nothing.
    waiting: AtomicBool,
    /// A write or poll found the buffer full, so room signals `POLL_OUT`.
    no_space: AtomicBool,
    /// Where `F_SETOWN`'s owner lives, for an urgent byte's `SIGURG`.
    processes: Mutex<Weak<crate::processes::Processes>>,
}
impl Signals {
    /// An urgent byte came, as Linux's `sk_send_sigurg`: `SIGURG` to the
    /// owner, if any, and then `POLL_PRI` with `O_ASYNC`.
    fn urgent(&self) {
        let owner = *self.owner.lock().unwrap_or_else(PoisonError::into_inner);
        if owner.id == 0 {
            return;
        }
        let processes = self
            .processes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade();
        if let Some(processes) = processes {
            processes.send_urgent(owner);
        }
        self.send(Reason::Priority);
    }
    fn on(&self) -> bool {
        self.registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
    /// `SOCK_WAKE_IO`: signals `reason`, if `O_ASYNC` is on.
    fn send(&self, reason: Reason) {
        let to = self
            .registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(to) = to {
            let owner = *self.owner.lock().unwrap_or_else(PoisonError::into_inner);
            Notice { to, owner, reason }.send();
        }
    }
    /// `SOCK_WAKE_WAITD`: none while a read waits, which the data wakes.
    fn waking(&self, reason: Reason) {
        if !self.waiting.load(Ordering::SeqCst) {
            self.send(reason);
        }
    }
    /// `SOCK_WAKE_SPACE`: `POLL_OUT` once, if the buffer was found full.
    fn space(&self) {
        if self.no_space.swap(false, Ordering::SeqCst) {
            self.send(Reason::Out);
        }
    }
    /// `sk_set_bit(SOCKWQ_ASYNC_NOSPACE)`, which acts only with `O_ASYNC`.
    fn full(&self) {
        if self.on() {
            self.no_space.store(true, Ordering::SeqCst);
        }
    }
}
/// The host's real time, which stamps what a stream receives.
fn realtime(host: &Arc<dyn paludarium_host::Host>) -> paludarium_host::net::Clock {
    let host = Arc::clone(host);
    Arc::new(move || host.clock(paludarium_host::ClockId::Realtime).ok())
}
/// What a stream's change signals, as Linux's TCP does: `POLL_OUT` when the
/// connection opens (`tcp_finish_connect`), `POLL_ERR` when it fails
/// (`sk_error_report`), `POLL_IN` for data (`sk_data_ready`), for the
/// peer's end `POLL_IN`, or `POLL_HUP` once this side has shut down too
/// (`tcp_fin`), and then `POLL_IN` as for data (`tcp_data_queue` queues the
/// FIN), and `POLL_OUT` for room after a full buffer
/// (`sk_stream_write_space`).
fn stream_waker(
    signals: &Arc<Signals>,
    hub: &Arc<ReadinessHub>,
    stream: &Arc<Stream>,
) -> Arc<dyn Fn(Event) + Send + Sync> {
    let (signals, hub, stream) = (Arc::clone(signals), Arc::clone(hub), Arc::downgrade(stream));
    Arc::new(move |event| {
        let stream = Weak::upgrade(&stream);
        match event {
            Event::Connected => signals.send(Reason::Out),
            Event::Failed => signals.send(Reason::Error),
            Event::Received => signals.waking(Reason::In),
            Event::Ended => {
                signals.waking(
                    if stream.as_ref().is_some_and(|s| s.readiness().write_closed) {
                        Reason::HangUp
                    } else {
                        Reason::In
                    },
                );
                signals.waking(Reason::In);
            }
            Event::Sent => {
                if stream.as_ref().is_some_and(|s| s.readiness().writable) {
                    signals.space();
                }
            }
        }
        hub.changed();
    })
}

/// A TCP or UDP socket of the guest.
pub(crate) struct InetSocket {
    /// This socket, for the bindings that name it.
    this: Weak<InetSocket>,
    family: Family,
    datagram: bool,
    network: Arc<Network>,
    /// For the stub's lookups, which a plain `write` can start.
    host: Arc<dyn paludarium_host::Host>,
    hub: Arc<ReadinessHub>,
    flags: AtomicU32,
    inode: u64,
    mode: AtomicU32,
    /// `fchown`, and whose thread made it (`sock_alloc`).
    uid: AtomicU32,
    gid: AtomicU32,
    state: Mutex<State>,
    options: Mutex<Options>,
    signals: Arc<Signals>,
    /// Its cookie, which `sock_diag` gives it when first asked
    /// (`sock_gen_cookie`).
    cookie: OnceLock<u64>,
    /// A connection in its listener's queue, which has no socket file yet
    /// (`sk_ino` 0 until `sock_graft`).
    embryo: AtomicBool,
}

impl InetSocket {
    /// The socket is the calling thread's.
    fn own(&self, c: &Context<'_>) {
        let creds = &c.process.credentials;
        self.uid.store(creds.fsuid, Ordering::SeqCst);
        self.gid.store(creds.fsgid, Ordering::SeqCst);
    }
    fn new(
        family: Family,
        datagram: bool,
        network: &Arc<Network>,
        host: &Arc<dyn paludarium_host::Host>,
        hub: &Arc<ReadinessHub>,
        flags: u32,
    ) -> Arc<Self> {
        let socket = Arc::new_cyclic(|this| Self {
            this: Weak::clone(this),
            family,
            datagram,
            network: Arc::clone(network),
            host: Arc::clone(host),
            hub: Arc::clone(hub),
            flags: AtomicU32::new(2 | (flags & NONBLOCK)),
            inode: crate::files::anonymous_inode(),
            mode: AtomicU32::new(0o140777),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            state: Mutex::new(State::default()),
            options: Mutex::new(Options::default()),
            signals: Arc::default(),
            cookie: OnceLock::new(),
            embryo: AtomicBool::new(false),
        });
        let mut sockets = network
            .sockets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sockets.retain(|socket| socket.strong_count() > 0);
        sockets.push(Arc::downgrade(&socket));
        drop(sockets);
        socket
    }
    /// Its cookie, given when first asked for, as `sock_gen_cookie`.
    pub(crate) fn cookie(&self) -> u64 {
        *self.cookie.get_or_init(crate::sockets::new_cookie)
    }
    /// Random bytes from the host.
    fn random<const N: usize>(&self) -> [u8; N] {
        let mut b = [0; N];
        let _ = self.host.random_bytes(&mut b);
        b
    }
    /// The network it was made in.
    pub(crate) fn network(&self) -> &Arc<Network> {
        &self.network
    }
    /// `F_GETOWN` and `F_GETSIG`.
    pub(crate) fn file_owner(&self) -> FileOwner {
        *self
            .signals
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// `F_SETOWN` and `F_SETSIG`, with where the owner lives.
    pub(crate) fn set_file_owner(
        &self,
        owner: FileOwner,
        processes: &Arc<crate::processes::Processes>,
    ) {
        *self
            .signals
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = owner;
        *self
            .signals
            .processes
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(processes);
    }
    /// What tells this socket that an urgent byte reached it.
    fn urgent_notify(&self) -> crate::loopback::Notify {
        let (signals, hub) = (Arc::clone(&self.signals), Arc::clone(&self.hub));
        Arc::new(move || {
            signals.urgent();
            hub.changed();
        })
    }
    /// This socket's loopback connection and side, once it has opened.
    fn joined(s: &State) -> Option<(Arc<Link>, usize)> {
        let (slot, side) = s.link.as_ref()?;
        Some((Arc::clone(slot.get()?), *side))
    }
    /// `F_SETFL` turning `O_ASYNC` on, with its registration, or off.
    pub(crate) fn set_async(&self, registration: Option<Registration>) {
        *self
            .signals
            .registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = registration;
    }
    /// A blocking read of this socket starts or stops waiting for data.
    pub(crate) fn wait_data(&self, waits: bool) {
        self.signals
            .waiting
            .store(waits && self.signals.on(), Ordering::SeqCst);
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether this is a UDP socket, not a TCP one.
    pub(crate) fn is_datagram(&self) -> bool {
        self.datagram
    }
    /// Takes the pending error (`sock_error`), as `SO_ERROR` does.
    pub(crate) fn take_error(&self) -> Option<Errno> {
        let mut s = self.lock();
        s.note();
        s.error.take()
    }
    /// Makes `error` the pending error without reporting it, as
    /// `do_recvmmsg` writes `sk_err`.
    pub(crate) fn store_error(&self, error: Errno) {
        let mut s = self.lock();
        s.note();
        s.error = Some(error);
    }
    /// The ports of this socket's protocol, without the holds in
    /// `TIME_WAIT` that have ended.
    fn ports(&self) -> MutexGuard<'_, Ports> {
        let mut ports = self.network.ports(self.datagram);
        if let Some(now) = self.now() {
            ports.expire(now);
        }
        ports
    }
    /// The host's monotonic time; without it, no hold in `TIME_WAIT` begins.
    fn now(&self) -> Option<u64> {
        self.host.clock(paludarium_host::ClockId::Monotonic).ok()
    }
    /// Runs what is due, so that what the socket shows next is as of now.
    /// Called with no socket's state locked.
    fn settle(&self) {
        self.hub.deadlines.run(|| self.now());
    }
    fn options(&self) -> MutexGuard<'_, Options> {
        self.options.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::SeqCst) & NONBLOCK != 0
    }
    /// `SO_RCVTIMEO` or `SO_SNDTIMEO`.
    pub(crate) fn timeout(&self, receive: bool) -> Timeout {
        let options = self.options();
        if receive {
            options.receive_timeout
        } else {
            options.send_timeout
        }
    }
    /// Whether this is a TCP socket, whose writes go on until all is sent.
    pub(crate) fn is_stream(&self) -> bool {
        !self.datagram
    }

    /// Receives into `buf`: `EAGAIN` while nothing has come. A failed
    /// connection gives its error once and then the end, as Linux's
    /// `tcp_recvmsg`; a socket never connected is `ENOTCONN`. Whether the
    /// call `waits` matters to a UDP socket shut down for reading.
    fn receive(&self, buf: &mut [u8], peek: bool, waits: bool) -> Result<Received, Errno> {
        if self.datagram {
            return self.receive_datagram(buf, peek, waits);
        }
        self.settle();
        let inline = self.options().out_of_band_inline;
        let mut s = self.lock();
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(ENOTCONN);
        };
        let ends = !peek && !buf.is_empty();
        if s.read_shut && stream.queued().0 == 0 {
            s.eof_read |= ends && stream.readiness().read_closed;
            return Ok(Received::bytes(0));
        }
        let read = match Self::joined(&s) {
            Some((link, side)) => link.read(side, &stream, buf, (peek, inline)),
            None => stream
                .read_stamped(buf, peek)
                .map(|(n, stamp)| (n, false, stamp)),
        };
        match read {
            Ok((n, at_mark, came)) => {
                s.eof_read |= n == 0 && ends && stream.readiness().read_closed;
                if n > 0 && !peek {
                    s.counts.read += n as u64;
                    s.counts.came = self.now();
                }
                Ok(Received {
                    at_mark,
                    came,
                    ..Received::bytes(n)
                })
            }
            Err(e) if e == Errno::EAGAIN => Err(e),
            Err(_) => match s.error.take() {
                Some(error) => Err(error),
                None => Ok(Received::bytes(0)),
            },
        }
    }
    /// Receives the urgent byte, for `MSG_OOB`, as Linux's `tcp_recv_urg`:
    /// `ENOTCONN` for a listener, `EINVAL` with `SO_OOBINLINE` or none
    /// waiting; `peek` leaves it. Only the guest's own loopback carries one.
    fn receive_urgent(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        self.settle();
        let inline = self.options().out_of_band_inline;
        let s = self.lock();
        if s.listen.is_some() {
            return Err(ENOTCONN);
        }
        if inline {
            return Err(Errno::EINVAL);
        }
        let (link, side) = Self::joined(&s).ok_or(Errno::EINVAL)?;
        let byte = link.take_urgent(side, peek).ok_or(Errno::EINVAL)?;
        let count = usize::from(!buf.is_empty());
        if let Some(first) = buf.first_mut() {
            *first = byte;
        }
        Ok(Received {
            urgent: true,
            ..Received::bytes(count)
        })
    }
    /// Whether the next read is at the urgent mark, for `SIOCATMARK`.
    pub(crate) fn at_mark(&self) -> bool {
        self.settle();
        Self::joined(&self.lock()).is_some_and(|(link, side)| link.urgent_state(side).1)
    }
    /// `write` for the task whose real user and group IDs are `ids`.
    pub(crate) fn write_as(&self, buf: &[u8], ids: (u32, u32)) -> Result<usize, Errno> {
        self.send(buf, None, Push::default(), ids)
    }
    /// Sends `bytes` as `push` says, the last of them urgent with
    /// `MSG_OOB`: a TCP socket
    /// never connected, or shut down for sending, is `EPIPE`; a failed one
    /// gives its pending error first. Only the guest's own loopback carries
    /// the urgent byte as such. A datagram goes to `to`, or the peer, for
    /// the task whose real user and group IDs are `ids`, as its receivers'
    /// filters see it.
    fn send(
        &self,
        bytes: &[u8],
        to: Option<SocketAddr>,
        push: Push,
        ids: (u32, u32),
    ) -> Result<usize, Errno> {
        if self.datagram {
            return self.send_datagram(bytes, to, ids);
        }
        self.settle();
        let (no_delay, cork) = {
            let options = self.options();
            (options.no_delay, options.cork)
        };
        let mut s = self.lock();
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(Errno::EPIPE);
        };
        // Read before the write: a connection open then was open for it,
        // so its EAGAIN is a full buffer and not one still connecting,
        // which Linux's `sk_stream_wait_connect` refuses without
        // `SOCKWQ_ASYNC_NOSPACE`.
        let was_open = stream.phase() == Phase::Open;
        if let Some((link, side)) = Self::joined(&s) {
            let push = Push {
                no_delay,
                cork,
                ..push
            };
            link.sending(side, push);
        }
        let written = stream.write(bytes);
        if let Ok(n) = written
            && n > 0
        {
            s.counts.written += n as u64;
            s.counts.wrote = self.now();
        }
        if let (Ok(n), Some((link, side))) = (&written, Self::joined(&s)) {
            let last = bytes[..*n].last().copied().filter(|_| push.urgent);
            link.wrote(side, *n, last);
        }
        match written {
            // A failed connection's error goes once, as `sk_stream_error`
            // takes it.
            Err(e)
                if e != Errno::EAGAIN
                    && (e != Errno::EPIPE || matches!(stream.phase(), Phase::Failed(_))) =>
            {
                Err(s.error.take().unwrap_or(Errno::EPIPE))
            }
            Err(e) if e == Errno::EAGAIN && was_open => {
                self.signals.full();
                Err(e)
            }
            result => result,
        }
    }

    /// Starts connecting to `address`, or goes on with a connection already
    /// started; waits for it unless the socket is nonblocking or `nowait`
    /// (an io_uring request's issue, as `O_NONBLOCK`). As Linux's
    /// `__inet_stream_connect`: `EISCONN` once connected or listening,
    /// `EALREADY` while still connecting, `EINPROGRESS` when a nonblocking
    /// one starts, and the pending error, or `ECONNABORTED`, when it failed.
    /// A loopback address where a guest socket listens is reached in the
    /// kernel; one where none does is refused, unless the policy allows the
    /// host's.
    fn connect(
        &self,
        c: &mut Context<'_>,
        address: Option<SocketAddr>,
        nowait: bool,
    ) -> Result<u64, Errno> {
        if self.datagram {
            return self.connect_datagram(address);
        }
        let Some(address) = address else {
            // AF_UNSPEC disconnects.
            self.renew(&mut self.lock());
            return Ok(0);
        };
        let mut options = *self.options();
        let wait = crate::sockets::wait_for(c, self.timeout(false))?;
        self.retry_syns();
        let stream = {
            let mut s = self.lock();
            s.note();
            if s.listen.is_some() {
                return Err(EISCONN);
            }
            let connection = s.connection;
            let pending = match connection {
                Connection::Connected => return Err(EISCONN),
                Connection::Connecting => EALREADY,
                Connection::Unconnected => {
                    let plain_to = SocketAddr::new(plain(address.ip()), address.port());
                    // `tcp_v6_connect` takes a group's `ENETUNREACH` first,
                    // which its route gives here.
                    let device = if address.ip().is_multicast() {
                        options.device
                    } else {
                        connect_device(address, options.device, 0)?
                    };
                    if device != options.device {
                        // The options' lock comes before the state's.
                        drop(s);
                        self.put_device(device);
                        options.device = device;
                        s = self.lock();
                    }
                    // `tcp_v4_connect` looks the route up from the bound
                    // source, which an IPv6 socket's IPv4-mapped broadcast
                    // or multicast address fails.
                    if plain_to.is_ipv4()
                        && let Some(bound) = s.bound
                    {
                        self.mapped_source(bound)?;
                    }
                    let dest = self.network.route(
                        plain_to,
                        s.source(),
                        (device, true),
                        FLOW_TCP,
                        self.now(),
                    )?;
                    let to = match dest {
                        Dest::Here(to) => Some(to),
                        Dest::Away | Dest::Veth(..) => None,
                    };
                    // The handshake's first segment goes out through the
                    // loopback, whatever answers it.
                    if let Some(to) = to {
                        self.network.output(to.ip(), self.now());
                    }
                    let opened = match dest {
                        Dest::Here(to) => self.open_loopback(&mut s, to, &options)?,
                        Dest::Away => None,
                        // `tcp_v4_connect` takes no broadcast or multicast
                        // route, and `tcp_v6_connect` no multicast address.
                        Dest::Veth(_, Cast::Broadcast | Cast::Multicast) => {
                            return Err(ENETUNREACH);
                        }
                        Dest::Veth(index, Cast::Unicast) => {
                            match self.open_veth(&mut s, index, plain_to, &options)? {
                                Some(stream) => Some(stream),
                                // The far namespace answers with a reset.
                                None => return self.refused(&mut s, address),
                            }
                        }
                    };
                    let loopback = opened.is_some();
                    let stream = match opened {
                        Some(stream) => stream,
                        None if address.port() == DNS => {
                            DnsOverTcp::open(address, &self.network, &self.host)
                        }
                        None => {
                            let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
                            if self.network.allows(address, now) {
                                let stream = c.host.connect(address)?;
                                stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
                                stream.set_clock(realtime(&self.host));
                                stream
                            } else if let Some(to) = to {
                                // Nothing listens there on the guest's own
                                // loopback, which answers with a reset, back
                                // to the address the connection leaves from.
                                let from = match s.bound.map(|b| b.ip()).or(s.address) {
                                    Some(ip) if !ip.is_unspecified() => ip,
                                    _ => self.network.source_through(to, 0, FLOW_TCP, self.now()),
                                };
                                self.network.output(from, self.now());
                                return self.refused(&mut s, address);
                            } else {
                                return Err(ENETUNREACH);
                            }
                        }
                    };
                    if address.port() == DNS && !loopback {
                        stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
                        stream.set_clock(realtime(&self.host));
                    }
                    stream.set_nodelay(options.no_delay);
                    if let Some(old) = s.stream.replace(Arc::clone(&stream)) {
                        old.close();
                    }
                    s.noted = false;
                    s.read_shut = false;
                    s.eof_read = false;
                    s.counts = Counts::new(self.now(), &options);
                    s.connection = Connection::Connecting;
                    // The stub's own stream is open at once.
                    if address.port() == DNS && !loopback {
                        stream.connected(None);
                    }
                    // Linux sends the handshake's first segment and takes
                    // the answer only once connect has returned, even on its
                    // loopback, so a nonblocking one is in progress however
                    // soon its listener, or the host, opens the connection.
                    if nowait || self.nonblocking() {
                        return Err(EINPROGRESS);
                    }
                    EINPROGRESS
                }
            };
            (s.stream.clone(), pending)
        };
        let (Some(stream), pending) = stream else {
            return Err(ECONNABORTED);
        };
        loop {
            let ticket = c.files.readiness.token.value();
            self.retry_syns();
            match stream.phase() {
                Phase::Open => {
                    self.lock().connection = Connection::Connected;
                    return Ok(0);
                }
                // Linux then disconnects the socket, which is as new.
                Phase::Failed(_) => {
                    let mut s = self.lock();
                    s.note();
                    let error = s.error.take().unwrap_or(ECONNABORTED);
                    self.renew(&mut s);
                    return Err(error);
                }
                Phase::Connecting if nowait || self.nonblocking() => return Err(pending),
                // Past `SO_SNDTIMEO`, Linux's `__inet_stream_connect` gives
                // the error of the state it found: `EALREADY` once one was
                // in progress.
                Phase::Connecting => {
                    let Some(deadline) = wait.deadline(c)? else {
                        return Err(pending);
                    };
                    crate::events::wait(c, ticket, deadline)?;
                }
            }
        }
    }
    /// `shutdown(how)`: `ENOTCONN` for a socket with no open connection;
    /// one still connecting is abandoned, as Linux disconnects it.
    fn shutdown(&self, how: u64) -> Result<u64, Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let mut s = self.lock();
        // Linux's `inet_shutdown` marks a UDP socket either way, and is
        // ENOTCONN for one not connected.
        if self.datagram {
            s.read_shut |= how != 1;
            s.write_shut |= how != 0;
            let connected = s.peer.is_some();
            drop(s);
            self.hub.changed();
            return if connected { Ok(0) } else { Err(ENOTCONN) };
        }
        // A listener stops for SHUT_RD, as Linux's `inet_shutdown`
        // disconnects it, and ignores SHUT_WR.
        if s.listen.is_some() {
            if how != 1 {
                self.renew(&mut s);
            }
            return Ok(0);
        }
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(ENOTCONN);
        };
        match stream.phase() {
            Phase::Connecting => {
                self.renew(&mut s);
                Ok(0)
            }
            Phase::Failed(_) => Err(ENOTCONN),
            Phase::Open if closed(&stream) => Err(ENOTCONN),
            Phase::Open => {
                if how != 1 {
                    s.read_shut = true;
                }
                if how != 0 {
                    stream.shutdown_write();
                }
                self.hub.changed();
                Ok(0)
            }
        }
    }
    /// The socket's own address: the host's once connected, or the
    /// loopback connection's, else the one it is bound to, else the
    /// unspecified one with port 0.
    fn local(&self) -> SocketAddr {
        let s = self.lock();
        s.stream
            .as_ref()
            .and_then(|stream| stream.local())
            .or(s.bound)
            .or(s.address.map(|ip| SocketAddr::new(ip, 0)))
            .unwrap_or(match self.family {
                Family::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                Family::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            })
    }
    /// The peer's address: `ENOTCONN` unless the connection is open.
    fn peer(&self) -> Result<SocketAddr, Errno> {
        let s = self.lock();
        if self.datagram {
            return s.peer.ok_or(ENOTCONN);
        }
        match &s.stream {
            Some(stream) if stream.phase() == Phase::Open && !closed(stream) => Ok(stream.peer()),
            _ => Err(ENOTCONN),
        }
    }

    /// `connect` of a UDP socket: it binds a port on every address if it had
    /// none, even when the connect then fails, and then sends to `address`
    /// and takes datagrams only from it, from that port on the source
    /// address of the route: the loopback's, or elsewhere the host's
    /// (`inet_dgram_connect`, `ip4_datagram_connect`). AF_UNSPEC disconnects
    /// (`__udp_disconnect`), keeping the port and address the guest bound
    /// itself, no device, and of an IPv6 socket its peer's address
    /// ([`State::old_peer`]).
    fn connect_datagram(&self, address: Option<SocketAddr>) -> Result<u64, Errno> {
        if address.is_none() {
            // The options' lock comes before the state's.
            self.put_device(0);
        }
        let options = *self.options();
        let mut s = self.lock();
        let Some(address) = address else {
            let peer = s.peer.take();
            if self.family == Family::V6 {
                s.old_peer = peer.map(|peer| peer.ip()).or(s.old_peer);
            }
            let bindings = State {
                bound: s.bound.take(),
                port_locked: s.port_locked,
                address_locked: s.address_locked,
                device_source: s.device_source,
                address: s.address.take(),
                ..State::default()
            };
            self.keep_locked(&mut s, &bindings);
            self.ports().keep_peer(&self.this, s.old_peer);
            return Ok(0);
        };
        // Linux binds the port first, before it looks the route up.
        let bound = self.autobind(&mut s, &options)?;
        let to = SocketAddr::new(plain(address.ip()), address.port());
        if self.family == Family::V6 && options.v6_only && to.is_ipv4() {
            return Err(ENETUNREACH);
        }
        let device = connect_device(address, options.device, options.multicast_device)?;
        if device != options.device {
            // The options' lock comes before the state's.
            drop(s);
            self.put_device(device);
            s = self.lock();
        }
        // Linux master puts the device back where the route fails
        // (`__ip6_datagram_connect`, since "ipv6: fix device binding after
        // failed datagram connect").
        let connected = self.connect_datagram_to(&mut s, address, bound, device, &options);
        if connected.is_ok() {
            // `ip4_datagram_connect` and `ip6_datagram_connect`: a new flow
            // hash (`sk_set_txhash`, never 0), and a random first ID.
            s.txhash = u32::from_le_bytes(self.random()).max(1);
            s.ip_id = u16::from_le_bytes(self.random());
        }
        if connected.is_err() && device != options.device {
            drop(s);
            self.put_device(options.device);
        }
        connected
    }
    /// The rest of [`Self::connect_datagram`] to `address`, from the port
    /// `bound`, through `device`, once the scope ID has been taken.
    fn connect_datagram_to(
        &self,
        s: &mut State,
        address: SocketAddr,
        bound: SocketAddr,
        device: u32,
        options: &Options,
    ) -> Result<u64, Errno> {
        let to = SocketAddr::new(plain(address.ip()), address.port());
        if to.is_ipv4() {
            self.mapped_source(bound)?;
        }
        // Bound to a broadcast or multicast address, the socket keeps it as
        // its name, which takes the datagrams (`__ip4_datagram_connect`
        // sets only an unset `inet_rcv_saddr`).
        let keep = s.device_source;
        let name = |from: SocketAddr| if keep { bound } else { from };
        let mut source = (!keep).then_some(bound.ip());
        let oif = match to.ip() {
            IpAddr::V6(ip) => Options { device, ..*options }.device6(ip),
            IpAddr::V4(ip) if ip.is_multicast() => {
                let oif;
                (oif, source) = self.group_route(ip, source, options)?;
                oif
            }
            IpAddr::V4(_) => device,
        };
        let through = (oif, device != 0);
        match self
            .network
            .route(to, source, through, FLOW_UDP, self.now())?
        {
            Dest::Here(to) => {
                let from = self.datagram_source(s, to, oif, options)?;
                let name = name(from);
                self.ports().connect(&self.this, name, Some(to));
                s.bound = Some(name);
                s.peer = Some(to);
            }
            // Out through a veth end, from the address its route leaves
            // from, which Linux's `__mkroute_output` takes from no
            // loopback address (`EINVAL`).
            Dest::Veth(index, cast) => {
                let from = self.datagram_source(s, to, oif, options)?;
                if to.is_ipv6() && from.ip().is_unspecified() {
                    return Err(EADDRNOTAVAIL);
                }
                if to.is_ipv4()
                    && plain(from.ip()).is_loopback()
                    && index != crate::netdev::LOOPBACK_INDEX
                {
                    return Err(Errno::EINVAL);
                }
                // `ip4_datagram_connect`.
                if cast == Cast::Broadcast && !options.broadcast {
                    return Err(Errno::EACCES);
                }
                let name = name(from);
                self.ports().connect(&self.this, name, Some(to));
                s.bound = Some(name);
                s.peer = Some(to);
            }
            Dest::Away => {
                // Off the loopback the port moves to the host's address the
                // route leaves from (`ip_route_connect`), unless the guest
                // bound an address. Only for a peer the policy allows, so
                // that a guest without one learns nothing of the host's
                // addresses; then, and on a host that cannot tell, the port
                // stays on every address. Connected there, the socket takes
                // no datagram from the loopback.
                let now = self.host.clock(paludarium_host::ClockId::Monotonic)?;
                let route = if bound.ip().is_unspecified() && self.network.allows(to, now) {
                    self.host.route_source(to)?
                } else {
                    None
                };
                let from = route.map_or(bound, |ip| SocketAddr::new(plain(ip), bound.port()));
                self.ports().connect(&self.this, from, Some(to));
                s.bound = Some(from);
                s.peer = Some(address);
            }
        }
        Ok(0)
    }
    /// The check Linux's `ip_route_output_key_hash_rcu` makes, for IPv4,
    /// of the source an IPv6 socket bound to an IPv4-mapped broadcast or
    /// multicast address has: `__inet6_bind` keeps that address as
    /// `inet_saddr`, where IPv4's `inet_bind` drops it. So the limited
    /// broadcast address and a group are `EINVAL`, and a subnet's
    /// broadcast address, which no device has, `ENETUNREACH`.
    fn mapped_source(&self, bound: SocketAddr) -> Result<(), Errno> {
        let IpAddr::V4(ip) = bound.ip() else {
            return Ok(());
        };
        if self.family != Family::V6 {
            return Ok(());
        }
        if ip.is_broadcast() || ip.is_multicast() {
            return Err(Errno::EINVAL);
        }
        if self.network.subnet_broadcast4(ip, self.now()) {
            return Err(ENETUNREACH);
        }
        Ok(())
    }
    /// This socket's address, with a port bound now on every address, or
    /// on the one the guest kept, if it had none (Linux's `inet_autobind`).
    fn autobind(&self, s: &mut State, options: &Options) -> Result<SocketAddr, Errno> {
        if let Some(bound) = s.bound {
            return Ok(bound);
        }
        let every = SocketAddr::new(s.address.take().unwrap_or(self.unspecified()), 0);
        // Linux's autobind finds no free port with EAGAIN.
        let bound = self
            .ports()
            .bind(Binding {
                old_peer: s.old_peer,
                ..self.binding(every, options)
            })
            .map_err(|_| Errno::EAGAIN)?;
        s.bound = Some(bound);
        Ok(bound)
    }
    fn unspecified(&self) -> IpAddr {
        match self.family {
            Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
    /// The device a datagram to the IPv4 group `group` is routed through
    /// (0 for that of its source or its route), and the source it is routed
    /// with, `source` the address this socket is bound to
    /// (`__ip4_datagram_connect`, `udp_sendmsg`): `IP_MULTICAST_IF`'s device
    /// and address, where the socket has none of its own. `ENETUNREACH` for
    /// a source no device has (`ip_route_output_key_hash_rcu`). One a source
    /// or a route takes through `lo` is routed through that, as
    /// [`Network::route`] takes no group there.
    fn group_route(
        &self,
        group: Ipv4Addr,
        source: Option<IpAddr>,
        options: &Options,
    ) -> Result<(u32, Option<IpAddr>), Errno> {
        let (index, address) = options.multicast4;
        let oif = if options.device != 0 {
            options.device
        } else {
            index
        };
        let some = |ip: &Ipv4Addr| !ip.is_unspecified();
        let source = match source.map(plain) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
        .filter(some)
        .or(Some(address).filter(some));
        let now = self.now();
        let on_lo = match source {
            Some(ip) => {
                let device = self.network.device_with4(ip, now).ok_or(ENETUNREACH)?;
                device == crate::netdev::LOOPBACK_INDEX
            }
            None => oif == 0 && self.network.group_on_lo(group, now),
        };
        let oif = if oif == 0 && on_lo {
            crate::netdev::LOOPBACK_OIF
        } else {
            oif
        };
        Ok((oif, source.map(IpAddr::V4)))
    }
    /// The address a datagram to `to` through the device `oif` (any for 0)
    /// leaves from: this socket's port, on the address it is bound to, or
    /// else, bound to none or to one it sends from the route's source
    /// instead of, `IP_MULTICAST_IF`'s to an IPv4 group, or the route's
    /// source address.
    fn datagram_source(
        &self,
        s: &mut State,
        to: SocketAddr,
        oif: u32,
        options: &Options,
    ) -> Result<SocketAddr, Errno> {
        let bound = self.autobind(s, options)?;
        let group = matches!(to.ip(), IpAddr::V4(ip) if ip.is_multicast());
        let ip = if bound.ip().is_unspecified() || s.device_source {
            let address = options.multicast4.1;
            if group && !address.is_unspecified() {
                IpAddr::V4(address)
            } else {
                self.network.source_through(to, oif, FLOW_UDP, self.now())
            }
        } else {
            bound.ip()
        };
        Ok(SocketAddr::new(ip, bound.port()))
    }
    /// Sends a datagram to `to`, or the connected peer: on the loopback to
    /// the guest socket that takes it, if any, as Linux's loopback delivers
    /// it at once; else a DNS query to the stub, to port 53 at any address.
    /// Any other destination is `ENETUNREACH`. Then, as Linux's
    /// `sock_alloc_send_pskb` checks them, a connected socket's pending
    /// error goes first, and a socket shut down for sending is `EPIPE`.
    fn send_datagram(
        &self,
        bytes: &[u8],
        to: Option<SocketAddr>,
        ids: (u32, u32),
    ) -> Result<usize, Errno> {
        let options = *self.options();
        let mut s = self.lock();
        let to = to.or(s.peer).ok_or(EDESTADDRREQ)?;
        let sendable = |s: &mut State| match s.error.take() {
            Some(error) => Err(error),
            None if s.write_shut => Err(Errno::EPIPE),
            None => Ok(()),
        };
        let plain_to = SocketAddr::new(plain(to.ip()), to.port());
        // `udpv6_sendmsg` hands a datagram to an IPv4 address to
        // `udp_sendmsg` after IPV6_V6ONLY's check; that checks its length,
        // then looks its route up from the bound source.
        if plain_to.is_ipv4()
            && !options.v6_only
            && bytes.len() <= 65_535
            && let Some(bound) = s.bound
        {
            self.mapped_source(bound)?;
        }
        // Out through the scope ID's device, of an address that needs one,
        // else the socket's, the sticky `IPV6_PKTINFO`'s, or the one for a
        // group or another address (`udpv6_sendmsg`).
        let mut source = s.source();
        let oif = match (to, plain_to.ip()) {
            (SocketAddr::V6(v6), _) if v6.scope_id() != 0 && needs_scope_id(*v6.ip()) => {
                v6.scope_id()
            }
            (_, IpAddr::V6(ip)) => options.device6(ip),
            (_, IpAddr::V4(ip)) if ip.is_multicast() => {
                let oif;
                (oif, source) = self.group_route(ip, source, &options)?;
                oif
            }
            (_, IpAddr::V4(_)) => options.device,
        };
        let through = (oif, options.device != 0);
        let flow = Flow {
            src: s.source(),
            oif,
            proto: FLOW_UDP,
            bound: options.device,
            port: None,
        };
        let route = self
            .network
            .route(plain_to, source, through, FLOW_UDP, self.now())?;
        if let Dest::Veth(index, cast) = route {
            let v6 = plain_to.is_ipv6();
            if self.family == Family::V6 && options.v6_only && !v6 {
                return Err(ENETUNREACH);
            }
            // `udp_sendmsg`'s first check, then the route's source, then
            // its type, then what a datagram holds (`__ip_append_data`).
            // IPv6 has no first check, and its source may be none
            // (`ip6_dst_lookup_tail`: `EADDRNOTAVAIL`).
            if !v6 && bytes.len() > 65_535 {
                return Err(EMSGSIZE);
            }
            let from = self.datagram_source(&mut s, plain_to, oif, &options)?;
            if v6 && from.ip().is_unspecified() {
                return Err(EADDRNOTAVAIL);
            }
            let on_lo = index == crate::netdev::LOOPBACK_INDEX;
            if !v6 && plain(from.ip()).is_loopback() && !on_lo {
                return Err(Errno::EINVAL);
            }
            if cast == Cast::Broadcast && !options.broadcast {
                return Err(Errno::EACCES);
            }
            if bytes.len() > if v6 { 65_527 } else { 65_507 } {
                return Err(EMSGSIZE);
            }
            sendable(&mut s)?;
            let mut sent = self.sent(&mut s, from, plain_to, &options, ids);
            let (own_mac, mtu) = self.network.veth_link(index);
            // A broadcast one reaches each socket that takes it, here and
            // across the pair, before `sendto` returns, as both copies go
            // through the backlog of the sending CPU, and so does one to an
            // IPv4 group; one to an IPv6 group no one, as no socket joins
            // one here.
            if cast != Cast::Unicast {
                let now = self.now();
                drop(s);
                let group = cast == Cast::Multicast;
                if group && !v6 {
                    sent.ttl = options.multicast_ttl;
                }
                let dst = if group {
                    crate::multicast::ethernet(plain_to.ip())
                } else {
                    [0xff; 6]
                };
                // An IPv6 socket's is `IPV6_MULTICAST_LOOP` (`sk_mc_loop`).
                let loops = !group || options.multicast_loop || self.family == Family::V6;
                let leaves = !group || options.multicast_ttl != 0;
                let copies = if on_lo {
                    self.network.output(plain_to.ip(), now);
                    let from = SocketAddr::new(plain(from.ip()), from.port());
                    self.network
                        .copies(index, from, plain_to, (true, false), now)
                } else {
                    let from = SocketAddr::new(plain(from.ip()), from.port());
                    let copies = self
                        .network
                        .copies(index, from, plain_to, (loops, leaves), now);
                    if leaves {
                        self.network.noarp(index, plain_to.ip(), now);
                    }
                    copies
                };
                let peer_index = self.network.peer_index(index);
                for (receiver, own) in copies {
                    let way = match own {
                        true if on_lo => arrival::Way::Loopback,
                        true => arrival::Way::Looped {
                            index: index as u32,
                            mtu,
                        },
                        false => arrival::Way::Veth {
                            index: peer_index,
                            src: own_mac,
                            dst,
                            mtu,
                        },
                    };
                    receiver.deliver(from, bytes, &sent, way);
                }
                return Ok(bytes.len());
            }
            let to_peer = s.peer == Some(plain_to);
            drop(s);
            let (there, answer) =
                match self
                    .network
                    .reach(index, from.ip(), to.ip(), &flow, self.now())
                {
                    Reach::Answered(there, answer) => (there, Some(answer)),
                    Reach::OneWay(there) => (there, None),
                    // Dropped once ARP gives up; ICMP's host unreachable that
                    // tells of it is no hard error (`__udp4_lib_err`); or
                    // dropped where it comes.
                    Reach::Unanswered | Reach::Dropped => return Ok(bytes.len()),
                };
            let receiver =
                there
                    .ports(true)
                    .receiver(plain_to, from, self.network.peer_index(index));
            // ICMP's port unreachable comes back, where answers come, through
            // the peer's neighbour of `from`.
            if receiver.is_none()
                && let Some(answer) = &answer
            {
                there.reply(answer, from.ip(), to.ip(), FLOW_ICMPV6, self.now());
            }
            match receiver {
                Some(receiver) => {
                    let peer_index = self.network.peer_index(index);
                    let way = arrival::Way::Veth {
                        index: peer_index,
                        src: own_mac,
                        dst: there.veth_link(peer_index as i32).0,
                        mtu,
                    };
                    receiver.deliver_on(from, bytes, peer_index, &sent, way);
                }
                None if answer.is_some() && to_peer => {
                    self.lock().error = Some(ECONNREFUSED);
                    self.signals.send(Reason::Error);
                    self.hub.changed();
                }
                None => {}
            }
            return Ok(bytes.len());
        }
        if let Dest::Here(dest) = route {
            if self.family == Family::V6 && options.v6_only && dest.is_ipv4() {
                return Err(ENETUNREACH);
            }
            // The most a datagram holds: 65535 bytes less the UDP header,
            // and IPv4's.
            let most = if dest.is_ipv4() { 65_507 } else { 65_527 };
            if bytes.len() > most {
                return Err(EMSGSIZE);
            }
            sendable(&mut s)?;
            let from = self.datagram_source(&mut s, dest, oif, &options)?;
            let to_peer = s.peer == Some(dest);
            let sent = self.sent(&mut s, from, dest, &options, ids);
            drop(s);
            let now = self.now();
            self.network.output(dest.ip(), now);
            let dif = self.network.arrival_device(dest, now);
            let receiver = self.ports().receiver(dest, from, dif);
            if let Some(receiver) = receiver {
                let iif = self.network.local_device(dest.ip(), now);
                receiver.deliver_on(from, bytes, iif, &sent, arrival::Way::Loopback);
                return Ok(bytes.len());
            }
            // A nested namespace has no stub.
            if dest.port() != DNS || self.network.isolated {
                // The loopback answers with ICMP's port unreachable, which
                // goes back out through it, and which only a socket
                // connected there learns of (`__udp4_lib_err`).
                self.network.output(from.ip(), now);
                if to_peer {
                    self.lock().error = Some(ECONNREFUSED);
                    self.signals.send(Reason::Error);
                    self.hub.changed();
                }
                return Ok(bytes.len());
            }
            s = self.lock();
        } else if to.port() != DNS {
            return Err(ENETUNREACH);
        } else {
            sendable(&mut s)?;
        }
        if let Some(mut query) = parse_query(bytes, to) {
            query.seq = s.received;
            s.received += 1;
            start_lookup(&self.network, self.host.as_ref(), &mut query);
            // An answer signals POLL_IN as a datagram's arrival does, and
            // then wakes this socket's waits, so that a poll the answer ends
            // finds the signal pending: at once, or when the host's lookup
            // ends.
            let ready = match &query.answer {
                Answer::Now(_) => true,
                Answer::Lookup(lookup) => {
                    let (signals, hub) = (Arc::clone(&self.signals), Arc::clone(&self.hub));
                    !lookup.add_waker(Arc::new(move || {
                        signals.waking(Reason::In);
                        hub.changed();
                    }))
                }
            };
            s.queries.push_back(query);
            drop(s);
            if ready {
                self.signals.waking(Reason::In);
            }
            self.hub.changed();
        }
        Ok(bytes.len())
    }
    /// Whether it takes a datagram to the IPv4 group `group` that came in on
    /// the device `dif` ([`crate::multicast::allows`]).
    fn takes_group(&self, group: Ipv4Addr, dif: u32) -> bool {
        let all = self.options().multicast_all;
        crate::multicast::allows(&self.lock().groups4, all, group, dif)
    }
    /// A datagram from `from` arrives, as `sent` made it and as it came
    /// `way`, with no device to give as its scope ID.
    fn deliver(&self, from: SocketAddr, bytes: &[u8], sent: &arrival::Sent, way: arrival::Way) {
        self.deliver_on(from, bytes, 0, sent, way);
    }
    /// Queues a datagram from `from` that came in on the device `iif`, which
    /// `recvfrom` gives as the scope ID of a sender that needs one
    /// (`ipv6_iface_scope_id` of `inet6_iif`), as `sent` made it and as it
    /// came `way`. First the socket's filter runs on it, which may drop it
    /// or keep only its first bytes (`sk_filter_trim_cap`); then it is
    /// dropped if it would take the receive buffer past `SO_RCVBUF` while
    /// another waits, as Linux's `__udp_enqueue_schedule_skb` drops it: an
    /// empty buffer takes one of any size, unless `SO_RCVBUF` is over half
    /// of `INT_MAX`. What it takes of the buffer is what it took as it came,
    /// however much the filter kept. Either drop counts in `sk_drops`.
    fn deliver_on(
        &self,
        from: SocketAddr,
        bytes: &[u8],
        iif: u32,
        sent: &arrival::Sent,
        way: arrival::Way,
    ) {
        let from = scoped(from, iif);
        let filter = self.lock().filtering.filter.clone();
        let kept = match filter {
            Some(filter) => sent.filter(&filter, bytes, way, &self.host),
            None => Some(bytes.len()),
        };
        let limit = usize::try_from(self.options().receive_buffer).unwrap_or(0);
        // A datagram from an IPv4 address goes as IPv4, to a dual-stack
        // socket too.
        let size = truesize(bytes.len(), plain(from.ip()).is_ipv4());
        let mut s = self.lock();
        let Some(kept) = kept else {
            s.drops = s.drops.wrapping_add(1);
            return;
        };
        // `SO_RCVBUF` stays under half of `INT_MAX` without
        // `SO_RCVBUFFORCE`, which is not taken here, so only the first
        // clause drops for now.
        if s.inbox_size + size > limit && (s.inbox_size > 0 || limit > (i32::MAX >> 1) as usize) {
            s.drops = s.drops.wrapping_add(1);
            return;
        }
        let seq = s.received;
        s.received += 1;
        s.inbox_size += size;
        s.inbox.push_back(Datagram {
            from,
            seq,
            came: self.host.clock(paludarium_host::ClockId::Realtime).ok(),
            bytes: bytes[..kept].to_vec(),
            size,
        });
        drop(s);
        self.signals.waking(Reason::In);
        self.hub.changed();
    }
    /// What a datagram from `from` to `to` that this socket sends now is
    /// made with (`ip_make_skb`, `ip6_make_skb`), for its receivers'
    /// filters: a connected socket's next IPv4 ID, and its flow hash.
    fn sent(
        &self,
        s: &mut State,
        from: SocketAddr,
        to: SocketAddr,
        options: &Options,
        ids: (u32, u32),
    ) -> arrival::Sent {
        let (from, to) = (
            SocketAddr::new(plain(from.ip()), from.port()),
            SocketAddr::new(plain(to.ip()), to.port()),
        );
        let id = (s.peer.is_some() && to.is_ipv4()).then(|| {
            s.ip_id = s.ip_id.wrapping_add(1);
            s.ip_id
        });
        let hash = match s.txhash {
            0 if to.is_ipv6() => arrival::flow_hash(from, to, &self.host),
            hash => hash,
        };
        arrival::Sent::new(
            from,
            to,
            options.type_of_service as u8,
            id,
            hash,
            options.priority as u32,
            ids,
        )
    }
    /// The first datagram that has come, a guest socket's or the stub's
    /// ready answer, in the order they came: its sender and bytes, whether
    /// it is the answer, and when it came (an answer, none: it comes as it
    /// is read).
    fn first_datagram(&self, s: &State) -> Option<(SocketAddr, Vec<u8>, bool, Option<u64>)> {
        let answer = s
            .queries
            .front()
            .and_then(|query| Some((query.seq, query.from, self.answer(query)?)));
        match (answer, s.inbox.front()) {
            (Some((seq, from, answer)), datagram)
                if datagram.is_none_or(|datagram| seq < datagram.seq) =>
            {
                Some((from, answer, true, None))
            }
            (_, Some(datagram)) => {
                Some((datagram.from, datagram.bytes.clone(), false, datagram.came))
            }
            _ => None,
        }
    }
    /// Takes the first datagram that has come, cut to `buf`; a pending
    /// error first, as Linux's `__skb_try_recv_datagram`. With none, a call
    /// that `waits` on a socket shut down for reading ends at once with 0,
    /// as `__skb_wait_for_more_packets` does; another is `EAGAIN`.
    fn receive_datagram(&self, buf: &mut [u8], peek: bool, waits: bool) -> Result<Received, Errno> {
        // The options' lock comes before the state's.
        let stamped = self.options().timestamps.wanted();
        let mut s = self.lock();
        if let Some(error) = s.error.take() {
            return Err(error);
        }
        let Some((from, bytes, answer, came)) = self.first_datagram(&s) else {
            return if s.read_shut && waits {
                Ok(Received::bytes(0))
            } else {
                Err(Errno::EAGAIN)
            };
        };
        if !peek {
            if answer {
                s.queries.pop_front();
            } else {
                if let Some(datagram) = s.inbox.pop_front() {
                    s.inbox_size -= datagram.size;
                }
            }
        }
        let n = buf.len().min(bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        let came = if answer && stamped {
            self.host.clock(paludarium_host::ClockId::Realtime).ok()
        } else {
            came
        };
        Ok(Received {
            length: bytes.len(),
            from: Some(from),
            came,
            ..Received::bytes(n)
        })
    }
    /// The answer to `query` in a datagram, once it can be given.
    fn answer(&self, query: &Query) -> Option<Vec<u8>> {
        answer(&self.network, self.host.as_ref(), query, UDP_ANSWER)
    }
    /// The first datagram's length, for `FIONREAD` (`first_packet_length`).
    fn next_datagram(&self) -> usize {
        let s = self.lock();
        self.first_datagram(&s)
            .map_or(0, |(_, bytes, ..)| bytes.len())
    }
    /// The bytes waiting to be read, and to be sent, for `FIONREAD` and
    /// `SIOCOUTQ`; a listener has neither (EINVAL, as Linux's `tcp_ioctl`).
    pub(crate) fn queued(&self, outgoing: bool) -> Result<usize, Errno> {
        if self.datagram {
            return Ok(if outgoing { 0 } else { self.next_datagram() });
        }
        self.settle();
        let inline = self.options().out_of_band_inline;
        let s = self.lock();
        if s.listen.is_some() {
            return Err(Errno::EINVAL);
        }
        if outgoing && let Some((link, side)) = Self::joined(&s) {
            let queued = link.segments(side).queued;
            return Ok(usize::try_from(queued).unwrap_or(usize::MAX));
        }
        // Not inline, the urgent byte and what follows it wait past the
        // mark (`tcp_inq`).
        let before_mark = Self::joined(&s)
            .and_then(|(link, side)| link.urgent_state(side).2)
            .filter(|_| !inline);
        Ok(s.stream.as_ref().map_or(0, |stream| {
            let (received, sending) = stream.queued();
            if outgoing {
                sending
            } else {
                before_mark.unwrap_or(received)
            }
        }))
    }

    // The guest's loopback.

    fn binding(&self, address: SocketAddr, options: &Options) -> Binding {
        Binding {
            address,
            v6: self.family == Family::V6,
            v6_only: options.v6_only,
            reuse_address: options.reuse_address,
            reuse_port: options.reuse_port,
            locked: false,
            link: None,
            pooled: self.datagram && options.reuse_port,
            listening: false,
            peer: None,
            old_peer: None,
            device: options.device,
            owner: Weak::clone(&self.this),
            time_wait: None,
        }
    }
    /// Makes `device` (0 for none) the socket's device, as a scope ID of a
    /// bind or connect does.
    fn put_device(&self, device: u32) {
        let mut options = self.options();
        options.device = device;
        self.ports().set_device(&self.this, device);
    }
    /// Landlock's `socket_bind` and `socket_connect` hooks, which only a TCP
    /// socket meets.
    fn landlock(&self, c: &Context<'_>, raw: &[u8], request: u64) -> Result<(), Errno> {
        if self.datagram {
            return Ok(());
        }
        crate::landlock::socket(c, self.family == Family::V6, raw, request)
    }
    /// `bind` of a TCP or UDP socket, with Linux's checks in its order
    /// (`__inet_bind`, `__inet6_bind`). The guest's own addresses are the
    /// loopback's and the unspecified one, and the IPv4 multicast and
    /// broadcast ones Linux takes too; any other is `EADDRNOTAVAIL`. Port 0
    /// takes an ephemeral port.
    fn bind(&self, raw: &[u8]) -> Result<u64, Errno> {
        let mut options = *self.options();
        let mut s = self.lock();
        let taken = |s: &State| s.bound.is_some() || s.stream.is_some();
        // The addresses the loopback's routes have, which IPv4's local
        // routes keep while it is down.
        let own = |ip: Ipv4Addr| self.network.bindable(IpAddr::V4(ip), self.now());
        let address = match self.family {
            Family::V4 => {
                if raw.len() < 16 {
                    return Err(Errno::EINVAL);
                }
                let family = u16::from_le_bytes([raw[0], raw[1]]);
                let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
                // AF_UNSPEC passes with the unspecified address, for old
                // programs.
                if family != AF_INET && !(family == AF_UNSPEC && ip.is_unspecified()) {
                    return Err(EAFNOSUPPORT);
                }
                if !own(ip) {
                    return Err(EADDRNOTAVAIL);
                }
                if taken(&s) {
                    return Err(Errno::EINVAL);
                }
                SocketAddr::from((ip, u16::from_be_bytes([raw[2], raw[3]])))
            }
            Family::V6 => {
                if raw.len() < 24 {
                    return Err(Errno::EINVAL);
                }
                if u16::from_le_bytes([raw[0], raw[1]]) != AF_INET6 {
                    return Err(EAFNOSUPPORT);
                }
                let mut octets = [0; 16];
                octets.copy_from_slice(&raw[8..24]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                let scope = raw
                    .get(24..28)
                    .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                if (ip.is_multicast() && !self.datagram) || taken(&s) {
                    return Err(Errno::EINVAL);
                }
                let device = options.device;
                if let Some(v4) = ip.to_ipv4_mapped() {
                    if options.v6_only {
                        return Err(Errno::EINVAL);
                    }
                    if device != 0 && !self.network.has_device(device) {
                        return Err(ENODEV);
                    }
                    if !own(v4) {
                        return Err(EADDRNOTAVAIL);
                    }
                    SocketAddr::from((v4, port))
                } else if ip.is_unspecified() {
                    SocketAddr::from((ip, port))
                } else {
                    // A link-local address, or a group of the node or the
                    // link, takes its scope ID as the socket's device, which
                    // stays though the bind fails, and needs one.
                    let device = if needs_scope_id(ip) && scope != 0 {
                        scope
                    } else {
                        device
                    };
                    let chosen = if needs_scope_id(ip) && device == 0 {
                        Err(Errno::EINVAL)
                    } else if device != 0 && !self.network.has_device(device) {
                        Err(ENODEV)
                    } else if ip.is_multicast() || self.network.bindable6_on(ip, device, self.now())
                    {
                        Ok(SocketAddr::from((ip, port)))
                    } else {
                        Err(EADDRNOTAVAIL)
                    };
                    if device != options.device {
                        // The options' lock comes before the state's.
                        drop(s);
                        self.put_device(device);
                        options.device = device;
                        s = self.lock();
                    }
                    chosen?
                }
            }
        };
        // An IPv6 address that is neither the unspecified one nor an IPv4
        // one makes the socket IPv6-only (`__inet6_bind`), unless the bind
        // fails.
        let only = matches!(address, SocketAddr::V6(a) if !a.ip().is_unspecified());
        options.v6_only |= only;
        s.bound = Some(self.ports().bind(Binding {
            locked: address.port() != 0,
            old_peer: s.old_peer,
            ..self.binding(address, &options)
        })?);
        s.port_locked = address.port() != 0;
        s.address_locked = !address.ip().is_unspecified();
        s.device_source = match address.ip() {
            IpAddr::V4(ip) if self.family == Family::V4 => self.network.broadcast4(ip, self.now()),
            _ => false,
        };
        s.address = None;
        drop(s);
        if only {
            self.options().v6_only = true;
        }
        Ok(0)
    }
    /// `listen(backlog)`, as Linux's `inet_listen`: `EOPNOTSUPP` for UDP,
    /// `EINVAL` for a socket that has connected; an unbound socket takes an
    /// ephemeral port on every address. A listener only takes the new
    /// backlog.
    fn listen(&self, backlog: u64) -> Result<u64, Errno> {
        if self.datagram {
            return Err(EOPNOTSUPP);
        }
        // Linux takes the int as unsigned, so a negative one is the most.
        let backlog = (backlog as u32).min(SOMAXCONN) as usize;
        let options = *self.options();
        // Tries due before this listener began meet what was there.
        self.retry_syns();
        let mut s = self.lock();
        if s.stream.is_some() {
            return Err(Errno::EINVAL);
        }
        // A dropped handshake still waits for its next try.
        if let Some(listen) = s.listen.as_mut() {
            listen.backlog = backlog;
            return Ok(0);
        }
        {
            let mut ports = self.ports();
            if s.bound.is_none() {
                let ip = s.address.take().unwrap_or(self.unspecified());
                s.bound = Some(ports.bind(self.binding(SocketAddr::new(ip, 0), &options))?);
            }
            ports.listen(&self.this, options.reuse_address, options.reuse_port)?;
        }
        s.listen = Some(Listen::new(backlog));
        Ok(0)
    }
    /// The first connection waiting on this listener, as Linux's
    /// `inet_csk_accept`: `EINVAL` unless listening (`EOPNOTSUPP` for UDP),
    /// `EAGAIN` when none waits and the socket is nonblocking or `nowait`
    /// (as `connect`), or once `SO_RCVTIMEO` has passed. With the
    /// connection, whether more still wait (`arg->is_empty`).
    fn accept(&self, c: &mut Context<'_>, nowait: bool) -> Result<(Arc<InetSocket>, bool), Errno> {
        if self.datagram {
            return Err(EOPNOTSUPP);
        }
        let wait = crate::sockets::wait_for(c, self.timeout(true))?;
        loop {
            let ticket = c.files.readiness.token.value();
            self.retry_syns();
            let child = {
                let mut s = self.lock();
                let Some(listen) = s.listen.as_mut() else {
                    return Err(Errno::EINVAL);
                };
                listen
                    .ready
                    .pop_front()
                    .map(|child| (child, !listen.ready.is_empty()))
            };
            if let Some(accepted) = child {
                return Ok(accepted);
            }
            if nowait || self.nonblocking() {
                return Err(Errno::EAGAIN);
            }
            let Some(deadline) = wait.deadline(c)? else {
                return Err(Errno::EAGAIN);
            };
            crate::events::wait(c, ticket, deadline)?;
        }
    }
    /// Sends again the dropped handshakes whose time has come, in the
    /// order of their tries: each reaches the listener at its address then,
    /// is dropped again while its queue is full, and is refused where none
    /// listens; after the last try the client gives up with `ETIMEDOUT`.
    /// Called with no socket's state locked.
    fn retry_syns(&self) {
        let Some(now) = self.now() else { return };
        let failing: Vec<(Weak<Stream>, u64, Errno)> = self
            .network
            .fails
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extract_if(.., |(stream, at, _)| {
                *at <= now
                    || stream
                        .upgrade()
                        .is_none_or(|s| s.phase() != Phase::Connecting)
            })
            .collect();
        for (stream, _, error) in failing {
            if let Some(stream) = stream.upgrade()
                && stream.phase() == Phase::Connecting
            {
                stream.fail(error);
            }
        }
        let due = |syn: &Syn| syn.next() <= now;
        let mut syns: Vec<Syn> = {
            let mut syns = self
                .network
                .syns
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Those whose client has gone or stopped connecting are forgotten.
            syns.retain(|syn| syn.waiting().is_some());
            syns.extract_if(.., |syn| due(syn)).collect()
        };
        while !syns.is_empty() {
            let next = syns
                .iter()
                .enumerate()
                .filter(|(_, syn)| due(syn))
                .min_by_key(|(_, syn)| syn.next())
                .map(|(i, _)| i);
            let Some(i) = next else { break };
            let syn = &mut syns[i];
            let Some(stream) = syn.waiting() else {
                syns.swap_remove(i);
                continue;
            };
            if syn.tries == SYN_RETRIES.len() {
                stream.fail(ETIMEDOUT);
                syns.swap_remove(i);
                continue;
            }
            syn.tries += 1;
            // Its namespace gone, the veth end it went through has gone
            // too: nothing answers again.
            let Some(there) = syn.there.upgrade() else {
                stream.fail(ETIMEDOUT);
                syns.swap_remove(i);
                continue;
            };
            let ends = (syn.from, syn.to, syn.veth);
            let client = syn.client.upgrade();
            match self.knock(
                client.as_deref(),
                &there,
                &stream,
                (&syn.link, &syn.notify),
                ends,
                syn.dif,
            ) {
                Knock::Full => {}
                Knock::Taken => {
                    syns.swap_remove(i);
                }
                Knock::Refused => {
                    stream.fail(ECONNREFUSED);
                    syns.swap_remove(i);
                }
            }
        }
        if !syns.is_empty() {
            let mut kept = self
                .network
                .syns
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            kept.extend(syns);
        }
    }
    /// A handshake from `stream` at `from` to `to` on the loopback, or out
    /// through a veth end to the namespace `there`: the listener there
    /// takes it into its queue when it has room.
    fn knock(
        &self,
        client: Option<&InetSocket>,
        there: &Network,
        stream: &Arc<Stream>,
        link: (&OnceLock<Arc<Link>>, &crate::loopback::Notify),
        (from, to, veth): (SocketAddr, SocketAddr, Option<i32>),
        dif: u32,
    ) -> Knock {
        let Some(listener) = there.ports(false).listener(from, to, dif) else {
            return Knock::Refused;
        };
        // The SYN sent again is the client's, with a new flow hash, as
        // `tcp_write_timeout` takes one for each retransmission
        // (`sk_rethink_txhash`).
        let kept = client.is_none_or(|client| {
            let options = *client.options();
            let hash = {
                let mut s = client.lock();
                s.txhash = u32::from_le_bytes(client.random()).max(1);
                s.txhash
            };
            client.syn_kept(&listener, there, (from, to, veth), &options, hash)
        });
        let theirs = *listener.options();
        let mut state = listener.lock();
        let locked = state.port_locked;
        let filtering = state.filtering.clone();
        let Some(listen) = state.listen.as_mut() else {
            return Knock::Refused;
        };
        // The filter drops it as a full queue does, and either counts in
        // the listener's `sk_drops`.
        if !kept || !listen.has_room() {
            listen.drops += 1;
            return Knock::Full;
        }
        let child = listener.child((theirs, locked, filtering), stream, link, (from, to, dif));
        listen.ready.push_back(child);
        listen.arrivals += 1;
        drop(state);
        listener.arrived();
        Knock::Taken
    }
    /// A connection came to this listener: `POLL_IN` and a wake, as
    /// Linux's `sk_data_ready` of a listener.
    fn arrived(&self) {
        self.signals.waking(Reason::In);
        self.hub.changed();
    }
    /// The accepted side of a connection from `stream` at `from` to this
    /// listener at `to`, which came in on the device `dif`, joined to it
    /// through `link`. It takes this socket's options and whether the guest
    /// bound its port (`locked`), as Linux's `sk_clone_lock` copies them
    /// with `sk_userlocks`, and holds the listener's port on `to`. From a
    /// link-local address, `dif` is its device where the listener has none
    /// (`tcp_v6_init_req`); an IPv6 one's `IPV6_MULTICAST_IF` is `dif`, not
    /// the listener's (`tcp_v6_syn_recv_sock`, `tcp_v6_mapped_child_init`).
    fn child(
        &self,
        (mut options, locked, filtering): (Options, bool, crate::sockets::FilterSlot),
        stream: &Arc<Stream>,
        (link, notify): (&OnceLock<Arc<Link>>, &crate::loopback::Notify),
        (from, to, dif): (SocketAddr, SocketAddr, u32),
    ) -> Arc<InetSocket> {
        // `tcp_v4_syn_recv_sock`: the hops the handshake's last segment had.
        if plain(from.ip()).is_ipv4() {
            options.multicast4 = (dif, Ipv4Addr::UNSPECIFIED);
            options.multicast_ttl = arrival::HOPS;
        }
        if self.family == Family::V6 {
            options.multicast_device = dif;
            if options.device == 0
                && matches!(from.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
            {
                options.device = dif;
            }
        }
        let child = InetSocket::new(self.family, false, &self.network, &self.host, &self.hub, 0);
        *child.options() = options;
        // `sk_clone_lock` copies the listener's `sk_uid`.
        child
            .uid
            .store(self.uid.load(Ordering::SeqCst), Ordering::SeqCst);
        child.embryo.store(true, Ordering::SeqCst);
        let own = Stream::new(from);
        let mtu = self.network.veth_link(dif.cast_signed()).1;
        own.set_waker(stream_waker(&child.signals, &child.hub, &own));
        own.set_clock(realtime(&child.host));
        size_buffers(&own, &options);
        let joined = Link::join(
            stream,
            &own,
            (from, to),
            (&self.host, &self.hub.deadlines),
            [Arc::clone(notify), child.urgent_notify()],
            mtu,
        );
        let _ = link.set(Arc::clone(&joined));
        let own_link = Arc::new(OnceLock::new());
        let _ = own_link.set(joined);
        self.ports().hold(Binding {
            locked,
            link: Some((Arc::clone(&own_link), 1)),
            ..child.binding(to, &options)
        });
        let mut s = child.lock();
        s.stream = Some(own);
        s.connection = Connection::Connected;
        s.link = Some((own_link, 1));
        s.bound = Some(to);
        s.port_locked = locked;
        s.counts = Counts::new(child.now(), &options);
        // `sk_clone_lock` copies the listener's filter, which it charges
        // again (`sk_filter_charge`), and its lock (`SOCK_FILTER_LOCKED`).
        s.filtering = crate::sockets::FilterSlot {
            filter: filtering.filter.map(|f| crate::sockets::Filter {
                socket: crate::bpf_prog::FilterSocket::Inet(Weak::clone(&child.this)),
                ..f
            }),
            locked: filtering.locked,
        };
        drop(s);
        child
    }
    /// Whether the listener's filter keeps the SYN of a connection from
    /// this socket at `from` to it at `to`, in the namespace `there`, out
    /// through the veth end `veth` or on the loopback, with this socket's
    /// `options` and flow hash `hash` (`tcp_filter` in `tcp_v4_rcv` and
    /// `tcp_v6_rcv`); one with no filter keeps it. It runs as this socket's
    /// owner, as the softirq that sends it runs in its context.
    fn syn_kept(
        &self,
        listener: &InetSocket,
        there: &Network,
        (from, to, veth): (SocketAddr, SocketAddr, Option<i32>),
        options: &Options,
        hash: u32,
    ) -> bool {
        let Some(filter) = listener.lock().filtering.filter.clone() else {
            return true;
        };
        let way = match veth {
            None => arrival::Way::Loopback,
            Some(index) => {
                let (src, mtu) = self.network.veth_link(index);
                let peer = self.network.peer_index(index);
                arrival::Way::Veth {
                    index: peer,
                    src,
                    dst: there.veth_link(peer as i32).0,
                    mtu,
                }
            }
        };
        let (from, to) = (
            SocketAddr::new(plain(from.ip()), from.port()),
            SocketAddr::new(plain(to.ip()), to.port()),
        );
        let ids = (
            self.uid.load(Ordering::SeqCst),
            self.gid.load(Ordering::SeqCst),
        );
        let sent = arrival::Sent::new(
            from,
            to,
            options.type_of_service as u8,
            None,
            hash,
            options.priority as u32,
            ids,
        );
        let window = arrival::syn_window(options.receive_buffer, way, to.is_ipv4());
        sent.syn_kept(&filter, way, window, &self.host)
    }
    /// A connection to `to` on the guest's loopback, when a guest socket
    /// listens there: in its listener's queue, or, when that is full, to be
    /// tried again ([`InetSocket::retry_syns`]).
    /// `None` when none listens there.
    fn open_loopback(
        &self,
        s: &mut State,
        to: SocketAddr,
        options: &Options,
    ) -> Result<Option<Arc<Stream>>, Errno> {
        // An IPv6-only socket reaches no IPv4 address (`tcp_v6_connect`).
        if self.family == Family::V6 && options.v6_only && to.is_ipv4() {
            return Err(ENETUNREACH);
        }
        let dif = self.network.arrival_device(to, self.now());
        if !self.ports().listens(to, dif) {
            return Ok(None);
        }
        // Which of the sockets sharing the port takes it hangs on the port
        // the connection leaves from.
        let bound = s.bound;
        let from = self.loopback_source(s, to, options)?;
        Ok(self.join(&self.network, s, (bound, from), to, options, None))
    }
    /// A connection to `to` out through the veth end `index`, from the
    /// address its route leaves from on a port bound now, as on the
    /// loopback ([`Self::loopback_source`]); `EINVAL` from a loopback
    /// address, which Linux's `__mkroute_output` sends out of no other
    /// device. Where it comes and its answers come back, it is the
    /// listener's there, as on the loopback, or `None` when nothing
    /// listens there, which answers with a reset. Else it fails in time:
    /// unanswered, with `EHOSTUNREACH` once ARP gives up, as ICMP's host
    /// unreachable tells it over the loopback, or with `ETIMEDOUT` once
    /// the handshake's tries are over where that loopback is down; one
    /// whose answers go nowhere with `ETIMEDOUT` too.
    fn open_veth(
        &self,
        s: &mut State,
        index: i32,
        to: SocketAddr,
        options: &Options,
    ) -> Result<Option<Arc<Stream>>, Errno> {
        if self.family == Family::V6 && options.v6_only && to.is_ipv4() {
            return Err(ENETUNREACH);
        }
        let bound = s.bound;
        let from = self.loopback_source(s, to, options)?;
        // IPv6's source may be none (`EADDRNOTAVAIL`); one of a loopback
        // address goes out, and is dropped where it comes.
        if to.is_ipv6() && from.ip().is_unspecified() {
            self.give_back(s, bound);
            return Err(EADDRNOTAVAIL);
        }
        if to.is_ipv4() && plain(from.ip()).is_loopback() {
            self.give_back(s, bound);
            return Err(Errno::EINVAL);
        }
        // `ip_route_connect` looks an IPv4 route up again from the source
        // its first lookup gave, which may take another hop of a
        // multipath one.
        let index = match self.network.route(
            to,
            Some(from.ip()),
            (options.device, options.device != 0),
            FLOW_TCP,
            self.now(),
        ) {
            Ok(Dest::Veth(index, _)) if to.is_ipv4() => index,
            _ => index,
        };
        let flow = Flow {
            src: if to.is_ipv4() {
                Some(from.ip())
            } else {
                bound.map(|b| b.ip())
            },
            oif: options.device,
            proto: FLOW_TCP,
            bound: options.device,
            port: Some(to.port()),
        };
        let failing = match self
            .network
            .reach(index, from.ip(), to.ip(), &flow, self.now())
        {
            Reach::Answered(there, answer) => {
                // Its SYN-ACK, or its reset, comes back.
                there.reply(&answer, from.ip(), to.ip(), FLOW_TCP, self.now());
                return Ok(self.join(&there, s, (bound, from), to, options, Some(index)));
            }
            Reach::OneWay(_) | Reach::Dropped => (SYN_TIMEOUT, ETIMEDOUT),
            Reach::Unanswered if self.network.is_up() => (ARP_TIMEOUT, EHOSTUNREACH),
            Reach::Unanswered => (SYN_TIMEOUT, ETIMEDOUT),
        };
        let stream = Stream::new(to);
        stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
        stream.set_clock(realtime(&self.host));
        size_buffers(&stream, options);
        match self.now() {
            Some(now) => self
                .network
                .fails
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((
                    Arc::downgrade(&stream),
                    now.saturating_add(failing.0 * 1_000_000_000),
                    failing.1,
                )),
            // Without the host's clock no time passes: it fails at once.
            None => stream.fail(failing.1),
        }
        Ok(Some(stream))
    }
    /// Gives back the port a connection bound for itself, keeping the
    /// binding `bound` it had before, as Linux's `tcp_done` does
    /// (`inet_put_port`).
    fn give_back(&self, s: &mut State, bound: Option<SocketAddr>) {
        match bound {
            None => self.ports().unbind(&self.this),
            Some(bound) => self.ports().rebind(&self.this, bound),
        }
        s.bound = bound;
    }
    /// A connection from `from` to `to`, at the listener there in
    /// `there`'s namespace: in its queue, or, when that is full, to be
    /// tried again ([`InetSocket::retry_syns`]). `None`, with the port
    /// given back to the binding `bound` had, when none listens there.
    /// On the `loopback`, the answer goes out through it.
    fn join(
        &self,
        there: &Arc<Network>,
        s: &mut State,
        (bound, from): (Option<SocketAddr>, SocketAddr),
        to: SocketAddr,
        options: &Options,
        veth: Option<i32>,
    ) -> Option<Arc<Stream>> {
        let loopback = veth.is_none();
        // The device it comes in on there: the peer of the end it goes out
        // through, or on the loopback its address's.
        let dif = match veth {
            Some(index) => self.network.peer_index(index),
            None => self.network.arrival_device(to, self.now()),
        };
        let Some(listener) = there.ports(false).listener(from, to, dif) else {
            // The listener closed meanwhile, or none was there: the
            // refused connect gives back the port it took.
            self.give_back(s, bound);
            return None;
        };
        // `tcp_v4_connect` and `tcp_v6_connect` give the socket its flow
        // hash (`sk_set_txhash`), which its SYN goes with.
        s.txhash = u32::from_le_bytes(self.random()).max(1);
        let kept = self.syn_kept(&listener, there, (from, to, veth), options, s.txhash);
        let theirs = *listener.options();
        let mut state = listener.lock();
        let locked = state.port_locked;
        let filtering = state.filtering.clone();
        let listen = state.listen.as_mut()?;
        let stream = Stream::new(to);
        stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
        stream.set_clock(realtime(&self.host));
        size_buffers(&stream, options);
        let link = Arc::new(OnceLock::new());
        s.link = Some((Arc::clone(&link), 0));
        self.ports().attach(&self.this, (&link, 0));
        // The listener's filter runs before its queue is checked, and a
        // SYN it drops is tried again as one a full queue dropped.
        let arrived = kept && listen.has_room();
        if arrived {
            // The listener's answer goes back out through the loopback.
            if loopback {
                self.network.output(from.ip(), self.now());
            }
            let notify = self.urgent_notify();
            let child = listener.child(
                (theirs, locked, filtering),
                &stream,
                (&link, &notify),
                (from, to, dif),
            );
            listen.ready.push_back(child);
            listen.arrivals += 1;
        } else {
            listen.drops += 1;
        }
        drop(state);
        if arrived {
            listener.arrived();
        } else if let Some(start) = self.now() {
            let mut syns = self
                .network
                .syns
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            syns.push(Syn {
                stream: Arc::downgrade(&stream),
                there: Arc::downgrade(there),
                link,
                notify: self.urgent_notify(),
                from,
                to,
                dif,
                veth,
                client: Weak::clone(&self.this),
                start,
                tries: 0,
            });
        } else {
            // Without the host's clock no try can come: the client gives up
            // at once, rather than wait for ever.
            stream.fail(ETIMEDOUT);
        }
        Some(stream)
    }
    /// The address a connection to `to` on the loopback leaves from: the
    /// one this socket is bound to, its port with the loopback's source
    /// address when bound to every address, else an ephemeral port.
    fn loopback_source(
        &self,
        s: &mut State,
        to: SocketAddr,
        options: &Options,
    ) -> Result<SocketAddr, Errno> {
        let source = self
            .network
            .source_through(to, options.device, FLOW_TCP, self.now());
        let mut ports = self.ports();
        // One bound to a broadcast or multicast address takes its route's
        // source as its name too (`tcp_v4_connect`:
        // `inet_bhash2_update_saddr`).
        let from = match s.bound {
            Some(bound) if !bound.ip().is_unspecified() && !s.device_source => bound,
            Some(bound) => {
                let from = SocketAddr::new(source, bound.port());
                ports.rebind(&self.this, from);
                from
            }
            // Linux's connect finds no free port with EADDRNOTAVAIL.
            None => {
                let ip = s.address.take().unwrap_or(source);
                ports
                    .bind(self.binding(SocketAddr::new(ip, 0), options))
                    .map_err(|_| EADDRNOTAVAIL)?
            }
        };
        s.bound = Some(from);
        Ok(from)
    }
    /// A connection the loopback refuses: `ECONNREFUSED`, or for a
    /// nonblocking socket in progress with the error waiting, as Linux's
    /// reset comes once connect has returned.
    fn refused(&self, s: &mut State, address: SocketAddr) -> Result<u64, Errno> {
        if !self.nonblocking() {
            return Err(ECONNREFUSED);
        }
        let stream = Stream::new(address);
        stream.fail(ECONNREFUSED);
        s.stream = Some(stream);
        s.noted = false;
        s.read_shut = false;
        s.connection = Connection::Connecting;
        Err(EINPROGRESS)
    }
    /// Makes the socket as new, as Linux's `tcp_disconnect`: a loopback
    /// connection is reset, a listener stops, and only a port the guest
    /// bound itself is kept.
    fn renew(&self, s: &mut State) {
        let old = std::mem::take(s);
        if old.listen.is_some() {
            self.ports().stop_listening(&self.this);
        }
        self.keep_locked(s, &old);
        if let Some(listen) = old.listen {
            listen.stop();
            self.hub.changed();
        }
        if let Some(stream) = old.stream {
            finish(&stream, old.link.as_ref(), true);
        }
    }
    /// What a disconnect leaves `s` of the binding `old` had, as Linux's
    /// `tcp_disconnect` and `__udp_disconnect` do: its port only if the guest
    /// bound that itself, and its address only if the guest named one.
    fn keep_locked(&self, s: &mut State, old: &State) {
        let Some(bound) = old.bound else {
            s.address = old.address;
            return;
        };
        let ip = if old.address_locked {
            bound.ip()
        } else {
            self.unspecified()
        };
        let mut ports = self.ports();
        if old.port_locked {
            let kept = SocketAddr::new(ip, bound.port());
            ports.connect(&self.this, kept, None);
            s.bound = Some(kept);
        } else {
            ports.unbind(&self.this);
            s.address = old.address_locked.then_some(ip);
        }
        s.port_locked = old.port_locked;
        s.address_locked = old.address_locked;
        s.device_source = old.address_locked && old.device_source;
    }
    /// Resets this socket's connection, as a listener that stops does to
    /// those it has not handed out.
    fn abort(&self) {
        let s = std::mem::take(&mut *self.lock());
        if let Some(stream) = s.stream {
            finish(&stream, s.link.as_ref(), true);
        }
    }
    /// The peer's address, whatever the connection's state, as `accept`
    /// gives it (Linux's `inet_getname` with `peer` 2).
    fn remote(&self) -> Option<SocketAddr> {
        self.lock().stream.as_ref().map(|stream| stream.peer())
    }
}

/// Whether an open connection has ended both ways: the peer's end has come
/// and this side's has gone, so that Linux has moved it to `TCP_CLOSE`.
fn closed(stream: &Stream) -> bool {
    let ready = stream.readiness();
    ready.read_closed && stream.finished().0
}

/// Ends the guest's use of `stream`, as Linux's `tcp_close`: on the
/// loopback a connection with unread input, or closed with `abort` (a zero
/// linger time, a disconnect), is reset; any other ends after what it sent.
/// Returns the loopback connection and this side when it ends the connection
/// first and was not reset, so that the socket holds its port in
/// `TIME_WAIT`.
fn finish(
    stream: &Stream,
    link: Option<&(Arc<OnceLock<Arc<Link>>>, usize)>,
    abort: bool,
) -> Option<(Arc<Link>, usize)> {
    let joined = link.and_then(|(slot, side)| Some((slot.get()?, *side)));
    if let Some((link, side)) = joined
        && (abort || stream.queued().0 > 0)
    {
        link.reset(side);
    }
    stream.close();
    joined
        .filter(|(link, side)| link.closes_first(*side))
        .map(|(link, side)| (Arc::clone(link), side))
}

impl Drop for InetSocket {
    fn drop(&mut self) {
        let abort = self.options().linger == Some(0);
        let s = std::mem::take(&mut *self.lock());
        self.network.drop4(&s.groups4);
        if let Some(listen) = s.listen {
            listen.stop();
        }
        // The side that ends the connection first keeps its port in
        // `TIME_WAIT`.
        if let Some(stream) = s.stream
            && let Some((link, side)) = finish(&stream, s.link.as_ref(), abort)
            && let Some(now) = self.now()
        {
            let cookie = self.cookie();
            self.ports()
                .linger(&self.this, (&link, side, stream.peer()), now, cookie);
        }
    }
}

/// What a receive took: the bytes copied, the whole datagram's length, and
/// where it came from.
struct Received {
    count: usize,
    length: usize,
    from: Option<SocketAddr>,
    /// A stream's read stopped at its urgent mark.
    at_mark: bool,
    /// It was the urgent byte, for `MSG_OOB`.
    urgent: bool,
    /// When a datagram came, which a timestamp gives.
    came: Option<u64>,
}
impl Received {
    fn bytes(count: usize) -> Self {
        Self {
            count,
            length: count,
            from: None,
            at_mark: false,
            urgent: false,
            came: None,
        }
    }
}

impl FileHandle for InetSocket {
    /// As Linux's `tcp_poll`: a socket never connected, or whose connection
    /// ended, is hung up and writable; one connecting is neither readable
    /// nor writable; an open one is readable with bytes or at the end of
    /// input (`POLLRDHUP` too), writable while its buffer has room, and hung
    /// up once both directions are shut. `POLLERR` shows a pending error.
    /// A UDP socket is writable, and readable once an answer is ready.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        if self.datagram {
            let s = self.lock();
            // `datagram_poll`: shut for reading is readable and read-hung-up,
            // and hung up once shut both ways.
            let ready = self.first_datagram(&s).is_some() || s.read_shut;
            let error = u32::from(s.error.is_some()) * POLLERR;
            let ends = (u32::from(s.read_shut) * POLLRDHUP)
                | (u32::from(s.read_shut && s.write_shut) * POLLHUP);
            return Ok((OUT | (u32::from(ready) * IN) | error | ends, s.received, 0));
        }
        self.retry_syns();
        self.settle();
        let inline = self.options().out_of_band_inline;
        let mut s = self.lock();
        // A listener is readable while a connection waits, and no more
        // (`inet_csk_listen_poll`).
        if let Some(listen) = &s.listen {
            return Ok((u32::from(!listen.ready.is_empty()) * IN, listen.arrivals, 0));
        }
        // The stream's readiness is read before its phase, and the failure
        // is noted only when that phase is failed. A host connection moves
        // on from connecting to open to failed at any time and never back,
        // so `note`'s own later reading is failed too, and readings in this
        // order never show a failed connection without its error, as
        // Linux's `tcp_done_with_error` writes `sk_err` before the state; a
        // change after them wakes the wait again.
        // A connection already open before the readiness was read was open
        // in it, so only then is a stream not writable full: one that
        // opened in between was read while connecting, which Linux's
        // `tcp_poll` leaves without `SOCKWQ_ASYNC_NOSPACE`.
        let was_open = s
            .stream
            .as_ref()
            .is_some_and(|stream| stream.phase() == Phase::Open);
        let read = s
            .stream
            .as_ref()
            .map(|stream| (stream.readiness(), stream.phase()));
        if matches!(read, Some((_, Phase::Failed(_)))) {
            s.note();
        }
        let error = u32::from(s.error.is_some()) * POLLERR;
        let (Some(stream), Some((ready, phase))) = (s.stream.clone(), read) else {
            return Ok((OUT | POLLHUP | error, 0, 0));
        };
        // An urgent byte waiting is `POLLPRI`; not inline, a read at its mark
        // needs a byte past it (`tcp_poll`).
        let (urgent, at_mark) = Self::joined(&s).map_or((false, false), |(link, side)| {
            let (urgent, at_mark, _) = link.urgent_state(side);
            (urgent, at_mark && !inline)
        });
        let mut readable = ready.readable;
        if at_mark && !ready.read_closed {
            readable = stream.queued().0 > 1;
        }
        let mask = match phase {
            Phase::Connecting => 0,
            Phase::Failed(_) => IN | OUT | POLLHUP | POLLRDHUP,
            Phase::Open => {
                if was_open && !ready.writable {
                    self.signals.full();
                }
                let read_end = ready.read_closed || s.read_shut;
                (u32::from(urgent) * crate::events::PRI)
                    | (u32::from(readable || s.read_shut) * IN)
                    | (u32::from(ready.writable) * OUT)
                    | (u32::from(read_end) * POLLRDHUP)
                    | (u32::from(read_end && ready.write_closed) * POLLHUP)
            }
        };
        Ok((mask | error, ready.arrivals, ready.departures))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.receive(buf, false, !self.nonblocking())
            .map(|received| received.count)
    }
    /// A write with no task to name, as a splice's: as the socket's
    /// owner. `write` itself sends through [`Self::write_as`].
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let ids = (
            self.uid.load(Ordering::SeqCst),
            self.gid.load(Ordering::SeqCst),
        );
        self.send(buf, None, Push::default(), ids)
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
        self.flags
            .store(2 | (flags & (NONBLOCK | O_ASYNC)), Ordering::SeqCst);
        Ok(())
    }
}

/// `address` with the scope ID it has as a name (`ipv6_iface_scope_id`): the
/// device `device` where its address needs one, else none.
fn scoped(address: SocketAddr, device: u32) -> SocketAddr {
    match address {
        SocketAddr::V6(mut v6) => {
            v6.set_scope_id(if needs_scope_id(*v6.ip()) { device } else { 0 });
            SocketAddr::V6(v6)
        }
        address => address,
    }
}
/// The device a connect to `address` from a socket bound to `device` goes
/// out through, which the socket keeps though the connect then fails
/// (`__ip6_datagram_connect`, `tcp_v6_connect`): a link-local address, or a
/// group of the node or the link, takes its scope ID's, which must be the
/// socket's device where it has one (`sk_dev_equal_l3scope`), and needs one
/// (`EINVAL` for both), a group `multicast` (`IPV6_MULTICAST_IF`'s) where
/// there is no other; any other address the socket's.
fn connect_device(address: SocketAddr, device: u32, multicast: u32) -> Result<u32, Errno> {
    let SocketAddr::V6(v6) = address else {
        return Ok(device);
    };
    if !needs_scope_id(*v6.ip()) {
        return Ok(device);
    }
    let device = match v6.scope_id() {
        0 => device,
        scope if device != 0 && device != scope => return Err(Errno::EINVAL),
        scope => scope,
    };
    let device = if device == 0 && v6.ip().is_multicast() {
        multicast
    } else {
        device
    };
    if device == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(device)
}
/// Whether a peer of `ip` needs an interface (`__ipv6_addr_needs_scope_id`):
/// a link-local unicast address, or a group of the node or the link scope
/// (`ipv6_addr_scope2type`).
fn needs_scope_id(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    if ip.is_multicast() {
        matches!(first & 0xf, 1 | 2)
    } else {
        first & 0xffc0 == 0xfe80
    }
}
/// The inet socket of `file`, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&InetSocket> {
    file.as_any()?.downcast_ref::<InetSocket>()
}

/// Where `sock_diag` finds a TCP socket, as Linux's tables hold it: a
/// listener's, a bound socket's that is closed (`TCP_BOUND_INACTIVE`), or
/// the connections' (`ehash`), which also holds those in `TIME_WAIT`. A UDP
/// socket is in its one table once it has a port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Table {
    Listening,
    Bound,
    Connected,
}
/// What `sock_diag` tells of a TCP or UDP socket of the guest, or of a TCP
/// connection's hold in `TIME_WAIT` after its socket (Linux's
/// `inet_timewait_sock`).
pub(crate) struct Entry {
    pub(crate) v6: bool,
    pub(crate) udp: bool,
    /// `sk_state`, or a hold's `tw_substate`.
    pub(crate) state: u8,
    pub(crate) table: Table,
    /// Its own address, IPv4 as such even on an IPv6 socket, and its peer's.
    pub(crate) local: SocketAddr,
    /// The peer, or with port 0 the address an IPv6 UDP socket keeps of one
    /// it had.
    pub(crate) peer: Option<SocketAddr>,
    /// The device it is bound to (`sk_bound_dev_if`), 0 for none.
    pub(crate) device: u32,
    pub(crate) cookie: u64,
    /// `idiag_timer`, `idiag_retrans` and when the timer ends, on the
    /// host's monotonic clock.
    pub(crate) timer: (u8, u8, Option<u64>),
    /// `idiag_rqueue` and `idiag_wqueue`.
    pub(crate) queues: (u32, u32),
    /// What a socket tells and a hold in `TIME_WAIT` does not.
    pub(crate) full: Option<Full>,
}
/// What `sock_diag` tells of a socket ([`Entry::full`]).
pub(crate) struct Full {
    pub(crate) uid: u32,
    pub(crate) inode: u64,
    pub(crate) shutdown: u8,
    pub(crate) type_of_service: u8,
    pub(crate) v6_only: bool,
    pub(crate) priority: u32,
    /// The guest bound its port (`SOCK_BINDPORT_LOCK`).
    pub(crate) port_locked: bool,
    /// The memory its unread datagrams take (`sk_rmem_alloc`).
    pub(crate) received: u32,
    /// What it dropped (`sk_drops`): a listener's dropped handshakes.
    pub(crate) drops: u32,
    /// A TCP socket's `tcp_info`.
    pub(crate) tcp: Option<TcpInfo>,
    pub(crate) receive_buffer: u32,
    pub(crate) send_buffer: u32,
}
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const IDIAG_TIMER_ON: u8 = 1;
const IDIAG_TIMER_KEEPALIVE: u8 = 2;
const IDIAG_TIMER_TIMEWAIT: u8 = 3;
impl Network {
    /// What `sock_diag` tells of its TCP and UDP sockets, oldest first, and
    /// then of the holds in `TIME_WAIT` whose sockets have gone, at `now`
    /// on the host's monotonic clock.
    pub(crate) fn diag(&self, now: Option<u64>) -> Vec<Entry> {
        let sockets: Vec<Arc<InetSocket>> = self
            .sockets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        // The handshakes whose time has come have been sent again, as
        // Linux's retransmission timer does on its own.
        if let Some(socket) = sockets.first() {
            socket.retry_syns();
            socket.settle();
        }
        let mut entries: Vec<Entry> = sockets.iter().flat_map(|socket| socket.diag(now)).collect();
        let mut ports = self.ports(false);
        if let Some(now) = now {
            ports.expire(now);
        }
        entries.extend(ports.waiting().into_iter().map(|wait| Entry {
            v6: wait.v6,
            udp: false,
            state: wait.state,
            table: Table::Connected,
            local: wait.local,
            peer: Some(wait.peer),
            device: wait.device,
            cookie: wait.cookie,
            timer: (IDIAG_TIMER_TIMEWAIT, 0, wait.until),
            queues: (0, 0),
            full: None,
        }));
        entries
    }
}
impl InetSocket {
    /// What `sock_diag` tells of this socket: nothing while Linux's tables
    /// would not hold it, as a socket with no port; for one whose
    /// connection on the loopback has ended both ways, which it ended
    /// first, a hold in `TIME_WAIT` too, as Linux's `tcp_time_wait` makes
    /// one while the socket stays, closed.
    fn diag(&self, now: Option<u64>) -> Vec<Entry> {
        let options = *self.options();
        let s = self.lock();
        let held = self.ports().holds(&self.this);
        let full = |shutdown: u8, received: usize| Full {
            uid: self.uid.load(Ordering::SeqCst),
            inode: if self.embryo.load(Ordering::SeqCst) {
                0
            } else {
                self.inode
            },
            shutdown,
            type_of_service: options.type_of_service as u8,
            v6_only: options.v6_only,
            priority: options.priority as u32,
            port_locked: s.port_locked,
            received: received as u32,
            drops: s.listen.as_ref().map_or(s.drops, |listen| listen.drops),
            tcp: (!self.datagram).then(|| self.tcp_info(&s, now)),
            receive_buffer: options.receive_buffer as u32,
            send_buffer: options.send_buffer as u32,
        };
        let shutdown = |read: bool, write: bool| u8::from(read) | u8::from(write) << 1;
        let v6 = self.family == Family::V6;
        if self.datagram {
            let Some(local) = s.bound.filter(|_| held) else {
                return Vec::new();
            };
            return vec![Entry {
                v6,
                udp: true,
                state: if s.peer.is_some() {
                    TCP_ESTABLISHED
                } else {
                    TCP_CLOSE
                },
                table: Table::Connected,
                local,
                peer: s.peer.or(s.old_peer.map(|ip| SocketAddr::new(ip, 0))),
                device: options.device,
                cookie: self.cookie(),
                timer: (0, 0, None),
                queues: (s.inbox_size as u32, 0),
                full: Some(full(shutdown(s.read_shut, s.write_shut), s.inbox_size)),
            }];
        }
        let unbound = || SocketAddr::new(self.unspecified(), 0);
        let local = s
            .stream
            .as_ref()
            .and_then(|stream| stream.local())
            .or(s.bound);
        let entry = |state: u8, table: Table, shut: u8| Entry {
            v6,
            udp: false,
            state,
            table,
            local: local.unwrap_or_else(unbound),
            peer: None,
            device: options.device,
            cookie: self.cookie(),
            timer: (0, 0, None),
            queues: (0, 0),
            full: Some(full(shut, 0)),
        };
        if let Some(listen) = &s.listen {
            return vec![Entry {
                queues: (listen.ready.len() as u32, listen.backlog as u32),
                ..entry(TCP_LISTEN, Table::Listening, 0)
            }];
        }
        let Some(stream) = &s.stream else {
            // Bound, never connected or disconnected.
            return if held && local.is_some() {
                vec![entry(TCP_CLOSE, Table::Bound, 0)]
            } else {
                Vec::new()
            };
        };
        // `rcv_nxt - copied_seq` and `write_seq - snd_una`: the peer's
        // FIN counts until a read meets it, and this side's SYN or FIN
        // until its peer has it.
        let (unread, unsent) = stream.queued();
        let unacked = Self::joined(&s).map(|(link, side)| link.segments(side).queued);
        let peer_ended = stream.readiness().read_closed && stream.phase() == Phase::Open;
        let unread = unread + usize::from(peer_ended && !s.eof_read);
        let queues = (unread as u32, unsent as u32);
        // A closed socket stays in its bind bucket only with the port the
        // guest bound (`tcp_set_state`'s `inet_put_port`); `tcp_done` has
        // shut it down both ways.
        let closed = |entries: &mut Vec<Entry>| {
            if held && s.port_locked {
                entries.push(Entry {
                    queues,
                    ..entry(TCP_CLOSE, Table::Bound, 3)
                });
            }
        };
        let mut entries = Vec::new();
        let state = match stream.phase() {
            Phase::Connecting => TCP_SYN_SENT,
            Phase::Failed(_) => {
                closed(&mut entries);
                return entries;
            }
            Phase::Open => {
                let ready = stream.readiness();
                match (ready.write_closed, ready.read_closed) {
                    (false, false) => TCP_ESTABLISHED,
                    (false, true) => TCP_CLOSE_WAIT,
                    (true, false) if unsent > 0 || Self::end_waits(&s) => TCP_FIN_WAIT1,
                    (true, false) => TCP_FIN_WAIT2,
                    (true, true) if unsent > 0 => TCP_LAST_ACK,
                    (true, true) => {
                        closed(&mut entries);
                        let released =
                            Self::joined(&s).and_then(|(link, side)| link.released(side));
                        if let Some(until) = released
                            && now.is_none_or(|now| until > now)
                        {
                            entries.push(Entry {
                                state: TCP_TIME_WAIT,
                                peer: Some(stream.peer()),
                                timer: (IDIAG_TIMER_TIMEWAIT, 0, Some(until)),
                                full: None,
                                ..entry(TCP_TIME_WAIT, Table::Connected, 0)
                            });
                        }
                        return entries;
                    }
                }
            }
        };
        // `sk_shutdown`: what the guest shut down, and the peer's end
        // (`tcp_fin`).
        let ready = stream.readiness();
        let shut = shutdown(s.read_shut || ready.read_closed, ready.write_closed);
        let timer = if state == TCP_SYN_SENT {
            self.syn_of(stream)
                .map_or((IDIAG_TIMER_ON, 0, None), |(tries, next)| {
                    (IDIAG_TIMER_ON, tries, Some(next))
                })
        } else if options.keep_alive {
            let idle = u64::try_from(options.keep_idle).unwrap_or(0) * 1_000_000_000;
            (IDIAG_TIMER_KEEPALIVE, 0, now.map(|now| now + idle))
        } else {
            (0, 0, None)
        };
        let sending = u32::from(matches!(state, TCP_SYN_SENT | TCP_FIN_WAIT1 | TCP_LAST_ACK));
        entries.push(Entry {
            peer: Some(stream.peer()),
            timer,
            queues: (
                queues.0,
                unacked.map_or(queues.1 + sending, |unacked| unacked as u32),
            ),
            ..entry(state, Table::Connected, shut)
        });
        entries
    }
}

impl InetSocket {
    /// How many times the dropped handshake of `stream` has been sent
    /// again, and when it goes next.
    fn syn_of(&self, stream: &Arc<Stream>) -> Option<(u8, u64)> {
        let syns = self
            .network
            .syns
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        syns.iter()
            .find(|syn| {
                syn.stream
                    .upgrade()
                    .is_some_and(|own| Arc::ptr_eq(&own, stream))
            })
            .map(|syn| (syn.tries as u8, syn.next()))
    }
    /// Whether this side's end has gone and waits for its acknowledgement.
    fn end_waits(s: &State) -> bool {
        Self::joined(s).is_some_and(|(link, side)| link.segments(side).end_waits)
    }
    /// What `tcp_get_info` tells of this socket at `now`, on the host's
    /// monotonic clock: a listener's queue, a handshake's tries, or what
    /// its connection has carried (see [`tcp_info`]).
    fn tcp_info(&self, s: &State, now: Option<u64>) -> TcpInfo {
        let uptime = now.unwrap_or(0) / 1_000_000;
        let since = |at: Option<u64>| match (now, at) {
            (Some(now), Some(at)) => {
                u32::try_from(now.saturating_sub(at) / 1_000_000).unwrap_or(u32::MAX)
            }
            _ => 0,
        };
        if let Some(listen) = &s.listen {
            return TcpInfo::listening(listen.ready.len() as u32, listen.backlog as u32);
        }
        let Some(stream) = &s.stream else {
            return TcpInfo::unconnected(TCP_CLOSE, uptime);
        };
        let counts = s.counts;
        let ready = stream.readiness();
        let (unread, unsent) = stream.queued();
        let state = match stream.phase() {
            Phase::Connecting => {
                let tries = self.syn_of(stream).map_or(0, |(tries, _)| tries);
                return TcpInfo::connecting(tries, uptime, since(counts.opened));
            }
            Phase::Failed(_)
                if s.connection != Connection::Connected
                    && counts.written == 0
                    && counts.read == 0 =>
            {
                return TcpInfo::unconnected(TCP_CLOSE, uptime);
            }
            Phase::Failed(_) => TCP_CLOSE,
            Phase::Open => match (ready.write_closed, ready.read_closed) {
                (false, false) => TCP_ESTABLISHED,
                (false, true) => TCP_CLOSE_WAIT,
                (true, false) if unsent > 0 || Self::end_waits(s) => TCP_FIN_WAIT1,
                (true, false) => TCP_FIN_WAIT2,
                (true, true) if unsent > 0 => TCP_LAST_ACK,
                (true, true) => TCP_CLOSE,
            },
        };
        let open = stream.phase() == Phase::Open;
        let unsent = unsent as u64;
        let segments = Self::joined(s).map(|(link, side)| link.segments(side));
        // A loopback connection's times are its segments'.
        let at = |micros: Option<u64>| micros.map(|at| at.saturating_mul(1000)).or(counts.opened);
        let (went, came, acked) = match &segments {
            Some(of) => (at(of.data_went), at(of.data_came), at(of.ack_came)),
            None => {
                let (went, came) = (counts.wrote, counts.came);
                (
                    went.or(counts.opened),
                    came.or(counts.opened),
                    went.max(came).or(counts.opened),
                )
            }
        };
        let carried = tcp_info::Carried {
            accepted: Self::joined(s).is_some_and(|(_, side)| side == 1),
            sent: counts.written.saturating_sub(unsent),
            fin_sent: open && ready.write_closed && unsent == 0,
            received: counts.read + unread as u64,
            fin_received: open && ready.read_closed,
            unsent,
            since_sent: since(went),
            since_received: since(came),
            since_ack: since(acked),
            rcv_wscale: counts.rcv_wscale,
            segments,
        };
        let in_flight = u32::from(matches!(state, TCP_FIN_WAIT1 | TCP_LAST_ACK));
        TcpInfo::connected(state, &carried, in_flight)
    }
    /// Whether closing this socket now waits: a connection on the loopback
    /// with a nonzero linger time, whose bytes still wait for room in the
    /// peer. Unread input, which resets it, does not wait.
    fn lingers(&self) -> Option<u32> {
        let seconds = self.options().linger.filter(|&seconds| seconds != 0)?;
        let s = self.lock();
        let stream = s.stream.as_ref()?;
        Self::joined(&s)?;
        let (unread, unsent) = stream.queued();
        (unread == 0 && unsent > 0).then_some(seconds as u32)
    }
}

/// Holds the close of `file`'s last descriptor, as Linux's `tcp_close` holds
/// a socket with a nonzero linger time in `sk_stream_wait_close`: on the
/// loopback, until the bytes it sent have all reached the peer and its end
/// has gone, the time is up, or a signal comes. It closes all the same, so
/// nothing here fails the close: a clock that fails ends the wait.
pub(crate) fn linger(c: &mut Context<'_>, file: &Arc<dyn FileHandle>) {
    if Arc::strong_count(file) != 1 {
        return;
    }
    let Some(socket) = of(file) else { return };
    let Some(seconds) = socket.lingers() else {
        return;
    };
    // Linux's `sock_setsockopt` takes the time as unsigned seconds.
    let ticks = Timeout::Ticks(u64::from(seconds) * crate::sockets::HZ);
    let Ok(wait) = crate::sockets::wait_for(c, ticks) else {
        return;
    };
    loop {
        let ticket = c.files.readiness.token.value();
        if socket.lingers().is_none() {
            return;
        }
        let Ok(Some(deadline)) = wait.deadline(c) else {
            return;
        };
        // Only a signal ends the wait early; any other error is the
        // clock's, which would fail again.
        match crate::events::wait(c, ticket, deadline) {
            Err(e) if e != Errno(4) || crate::events::signalled(c) => return,
            _ => {}
        }
    }
}

/// Reads a socket address of `len` bytes at `at` for `socket`, as
/// `move_addr_to_kernel` (EINVAL past 128 bytes, EFAULT) and the protocol's
/// checks: `None` for `AF_UNSPEC`, EINVAL when too short, EAFNOSUPPORT for
/// another family. An IPv6 socket takes IPv4-mapped addresses.
fn read_address(
    c: &Context<'_>,
    socket: &InetSocket,
    at: u64,
    len: u64,
) -> Result<Option<SocketAddr>, Errno> {
    parse_address(socket.family, &read_raw(c, at, len)?)
}
/// The `len` bytes of a socket address at `at`, as `move_addr_to_kernel`.
pub(crate) fn read_raw(c: &Context<'_>, at: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let len = usize::try_from(len as u32 as i32)
        .ok()
        .filter(|&len| len <= 128)
        .ok_or(Errno::EINVAL)?;
    let mut raw = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    Ok(raw)
}
fn parse_address(family: Family, raw: &[u8]) -> Result<Option<SocketAddr>, Errno> {
    if raw.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let port = |raw: &[u8]| u16::from_be_bytes([raw[2], raw[3]]);
    match (u16::from_le_bytes([raw[0], raw[1]]), family) {
        (AF_UNSPEC, _) => Ok(None),
        (AF_INET, Family::V4) => {
            if raw.len() < 16 {
                return Err(Errno::EINVAL);
            }
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, port(raw)))))
        }
        (AF_INET6, Family::V6) => {
            if raw.len() < 24 {
                return Err(Errno::EINVAL);
            }
            let mut octets = [0; 16];
            octets.copy_from_slice(&raw[8..24]);
            let ip = Ipv6Addr::from(octets);
            let scope = if raw.len() >= 28 {
                u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]])
            } else {
                0
            };
            let flow = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
            Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port(raw),
                flow,
                scope,
            ))))
        }
        _ => Err(EAFNOSUPPORT),
    }
}
/// `address` as a `sockaddr_in` or `sockaddr_in6` of `family`: an IPv6
/// socket names an IPv4 address IPv4-mapped.
fn encode_address(family: Family, address: SocketAddr) -> Vec<u8> {
    let port = address.port().to_be_bytes();
    match (family, address) {
        (Family::V4, SocketAddr::V4(v4)) => {
            let mut raw = vec![0; 16];
            raw[..2].copy_from_slice(&AF_INET.to_le_bytes());
            raw[2..4].copy_from_slice(&port);
            raw[4..8].copy_from_slice(&v4.ip().octets());
            raw
        }
        (Family::V4, SocketAddr::V6(v6)) => encode_address(
            family,
            SocketAddr::from((
                v6.ip().to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
                v6.port(),
            )),
        ),
        (Family::V6, address) => {
            let (ip, flow, scope) = match address {
                SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped(), 0, 0),
                SocketAddr::V6(v6) => (*v6.ip(), v6.flowinfo(), v6.scope_id()),
            };
            let mut raw = vec![0; 28];
            raw[..2].copy_from_slice(&AF_INET6.to_le_bytes());
            raw[2..4].copy_from_slice(&port);
            raw[4..8].copy_from_slice(&flow.to_be_bytes());
            raw[8..24].copy_from_slice(&ip.octets());
            raw[24..28].copy_from_slice(&scope.to_le_bytes());
            raw
        }
    }
}
/// Writes `address` to `at` with its length at `len_at`, as
/// `move_addr_to_user`: the length read there first (EFAULT, EINVAL when
/// negative) bounds the bytes written, and the full length goes back.
pub(crate) fn write_address(
    c: &Context<'_>,
    address: &[u8],
    at: u64,
    len_at: u64,
) -> Result<(), Errno> {
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let n = room.min(address.len());
    if n > 0 {
        c.mem
            .write(GuestAddr(at), &address[..n])
            .map_err(|_| Errno::EFAULT)?;
    }
    c.mem
        .write(GuestAddr(len_at), &(address.len() as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)
}

/// The system calls of an inet socket, `file` of descriptor `a[0]`.
pub(crate) fn dispatch(
    c: &mut Context<'_>,
    number: u64,
    a: [u64; 6],
    file: &Arc<dyn FileHandle>,
) -> Result<u64, Errno> {
    let socket = of(file).ok_or(ENOTSOCK)?;
    match number {
        // connect
        42 => {
            let raw = read_raw(c, a[1], a[2])?;
            connect_raw(c, socket, &raw, false)
        }
        // accept and accept4
        43 | 288 => accept(c, socket, a, if number == 288 { a[3] } else { 0 }),
        // bind, to the guest's own addresses
        49 => {
            let raw = read_raw(c, a[1], a[2])?;
            socket.landlock(c, &raw, crate::landlock::BIND_TCP)?;
            socket.bind(&raw)
        }
        // listen
        50 => socket.listen(a[1]),
        // getsockname and getpeername
        51 | 52 => {
            let address = if number == 51 {
                socket.local()
            } else {
                socket.peer()?
            };
            let address = scoped(address, socket.options().device);
            write_address(c, &encode_address(socket.family, address), a[1], a[2])?;
            Ok(0)
        }
        48 => socket.shutdown(a[1]),
        54 => set_option(c, socket, a),
        55 => get_option(c, socket, a),
        44 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let to = if a[4] != 0 {
                read_address(c, socket, a[4], a[5])?
            } else {
                None
            };
            let mut bytes = vec![0; len];
            c.mem
                .read(GuestAddr(a[1]), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            send(c, file, socket, &bytes, a[3], to)
        }
        45 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let mut bytes = vec![0; len];
            let received = receive(c, file, socket, &mut bytes, a[3])?;
            if a[3] & MSG_TRUNC == 0 || socket.datagram {
                c.mem
                    .write(GuestAddr(a[1]), &bytes[..received.count])
                    .map_err(|_| Errno::EFAULT)?;
            }
            if a[4] != 0 {
                let address = received
                    .from
                    .map(|from| encode_address(socket.family, from))
                    .unwrap_or_default();
                write_address(c, &address, a[4], a[5])?;
            }
            Ok(returned(&received, a[3], socket.datagram) as u64)
        }
        46 => {
            let header = crate::sockets::message_header(c, a[1], false)?;
            let to = match header.name {
                Some((at, len)) => read_address(c, socket, at, len as u64)?,
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
            send(c, file, socket, &bytes, a[2], to)
        }
        47 => {
            let header = crate::sockets::message_header(c, a[1], true)?;
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(total, 0);
            let received = receive(c, file, socket, &mut bytes, a[2])?;
            if a[2] & MSG_TRUNC == 0 || socket.datagram {
                crate::files::scatter(c, &header.iov, &bytes[..received.count])?;
            }
            let mut flags = 0u32;
            if socket.datagram && received.length > received.count {
                flags |= MSG_TRUNC as u32;
            }
            // `tcp_recv_urg` marks the urgent byte, cut when no room took it.
            if received.urgent {
                flags |= MSG_OOB as u32;
                if total == 0 {
                    flags |= MSG_TRUNC as u32;
                }
            }
            if header.has_name {
                let address = received
                    .from
                    .map(|from| encode_address(socket.family, from))
                    .unwrap_or_default();
                if let Some((at, room)) = header.name {
                    let n = room.min(address.len());
                    c.mem
                        .write(GuestAddr(at), &address[..n])
                        .map_err(|_| Errno::EFAULT)?;
                }
                c.mem
                    .write(GuestAddr(a[1] + 8), &(address.len() as u32).to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
            }
            // A datagram's timestamps, as `udp_recvmsg` gives them
            // (`sock_recv_timestamp`); with no control buffer, only
            // MSG_CTRUNC tells of them.
            let timestamps = socket.options().timestamps;
            let mut used = 0u64;
            if let Some(came) = received.came.filter(|_| timestamps.wanted()) {
                let mut room = (header.control, header.control_len);
                if header.control == 0 || timestamps.put(c, &mut room, came) {
                    flags |= MSG_CTRUNC;
                }
                used = header.control_len - room.1;
            }
            c.mem
                .write(GuestAddr(a[1] + 40), &used.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            c.mem
                .write(GuestAddr(a[1] + 48), &flags.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            Ok(returned(&received, a[2], socket.datagram) as u64)
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// `accept` and `accept4` with `flags` (`SOCK_NONBLOCK` and
/// `SOCK_CLOEXEC`; EINVAL for any other), in Linux's order (`do_accept`):
/// the lowest free descriptor first (EMFILE), then the connection, then its
/// peer's address, which when it cannot be written loses the connection.
fn accept(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6], flags: u64) -> Result<u64, Errno> {
    if flags & !u64::from(NONBLOCK | CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let fd = c.files.reserve(c.group.nofile())?;
    let child = match accepted(c, socket, a[1], a[2], flags, false) {
        Ok((child, _)) => child,
        Err(e) => {
            c.files.unreserve(fd);
            return Err(e);
        }
    };
    let cloexec = flags & u64::from(CLOEXEC) != 0;
    c.files
        .fill(fd, crate::files::Descriptor::unnamed(child, cloexec));
    Ok(u64::from(fd))
}
/// The connection `accept` takes on `socket`, made the caller's, with
/// `SOCK_NONBLOCK` of `flags` and its peer's address written to `at` (none
/// when 0) within the room `len` gives; with whether more wait. `nowait` is
/// as for [`InetSocket::accept`].
fn accepted(
    c: &mut Context<'_>,
    socket: &InetSocket,
    at: u64,
    len: u64,
    flags: u64,
    nowait: bool,
) -> Result<(Arc<InetSocket>, bool), Errno> {
    let (child, more) = socket.accept(c, nowait)?;
    child.own(c);
    child.embryo.store(false, Ordering::SeqCst);
    if flags & u64::from(NONBLOCK) != 0 {
        child.flags.store(2 | NONBLOCK, Ordering::SeqCst);
    }
    if at != 0 {
        let peer = child.remote().unwrap_or(match socket.family {
            Family::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Family::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        });
        let peer = scoped(peer, child.options().device);
        write_address(c, &encode_address(socket.family, peer), at, len)?;
    }
    Ok((child, more))
}
/// An io_uring accept on `file` (`crate::sockets::accept_file`).
pub(crate) fn accept_file(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    at: u64,
    len: u64,
    flags: u64,
    nowait: bool,
) -> Result<(Arc<dyn FileHandle>, bool), Errno> {
    let socket = of(file).ok_or(ENOTSOCK)?;
    let (child, more) = accepted(c, socket, at, len, flags, nowait)?;
    Ok((child, more))
}
/// `connect` of `socket` to the address `raw`, as Landlock allows it;
/// `nowait` is as for [`InetSocket::connect`].
pub(crate) fn connect_raw(
    c: &mut Context<'_>,
    socket: &InetSocket,
    raw: &[u8],
    nowait: bool,
) -> Result<u64, Errno> {
    socket.landlock(c, raw, crate::landlock::CONNECT_TCP)?;
    socket.connect(c, parse_address(socket.family, raw)?, nowait)
}
/// What a receive returns: with `MSG_TRUNC`, a datagram's whole length.
fn returned(received: &Received, flags: u64, datagram: bool) -> usize {
    if datagram && flags & MSG_TRUNC != 0 {
        received.length
    } else {
        received.count
    }
}
fn send(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &InetSocket,
    bytes: &[u8],
    flags: u64,
    to: Option<SocketAddr>,
) -> Result<u64, Errno> {
    if flags & MSG_OOB != 0 && socket.datagram {
        return Err(EOPNOTSUPP);
    }
    // TCP ignores the address of a connected socket's send.
    let to = if socket.datagram { to } else { None };
    let ids = (c.process.credentials.uid, c.process.credentials.gid);
    crate::files::write_with(
        c,
        file,
        bytes,
        flags & MSG_NOSIGNAL != 0,
        flags & MSG_DONTWAIT != 0,
        |part| {
            let push = Push {
                more: flags & MSG_MORE != 0,
                urgent: flags & MSG_OOB != 0,
                ..Push::default()
            };
            socket.send(part, to, push, ids)
        },
    )
}
/// Receives for recvfrom or recvmsg: `MSG_PEEK` keeps the bytes, and on
/// TCP `MSG_WAITALL` waits until the buffer is full, the input ends or the
/// read reaches the urgent mark, and `MSG_OOB` takes the urgent byte (UDP
/// ignores it, as Linux's `udp_recvmsg`).
fn receive(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &InetSocket,
    buf: &mut [u8],
    flags: u64,
) -> Result<Received, Errno> {
    if flags & MSG_OOB != 0 && !socket.datagram {
        return socket.receive_urgent(buf, flags & MSG_PEEK != 0);
    }
    let peek = flags & MSG_PEEK != 0;
    let dontwait = flags & MSG_DONTWAIT != 0;
    let waits = !dontwait && !socket.nonblocking();
    let wait = crate::sockets::wait_for(c, socket.timeout(true))?;
    let mut received = crate::files::wait_for_read_until(c, file, dontwait, wait, || {
        socket.receive(buf, peek, waits)
    })?;
    if socket.datagram || flags & MSG_WAITALL == 0 || peek {
        return Ok(received);
    }
    while received.count > 0 && received.count < buf.len() && !received.at_mark {
        let rest = &mut buf[received.count..];
        match crate::files::wait_for_read_until(c, file, dontwait, wait, || {
            socket.receive(rest, false, waits)
        }) {
            Ok(more) if more.count > 0 => {
                received.count += more.count;
                received.at_mark = more.at_mark;
                received.came = more.came.or(received.came);
            }
            _ => break,
        }
    }
    received.length = received.count;
    Ok(received)
}

/// The priority a type of service gives (`rt_tos2priority`, `ip_tos2prio`):
/// best effort, bulk, interactive or interactive bulk, by its TOS bits.
fn tos_priority(tos: i32) -> i32 {
    const PRIORITIES: [i32; 8] = [0, 0, 2, 2, 6, 6, 4, 4];
    PRIORITIES[((tos & 0x1e) >> 2) as usize]
}
/// Reads the `int` of a setsockopt (EINVAL for fewer than 4 bytes).
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
/// The `int` `do_ipv6_setsockopt` reads before it looks at the option: 0 for
/// no pointer or fewer than 4 bytes.
fn option6_int(c: &Context<'_>, at: u64, len: u64) -> Result<i32, Errno> {
    match len as u32 as i32 {
        ..0 => Err(Errno::EINVAL),
        4.. if at != 0 => option_int(c, at, len),
        _ => Ok(0),
    }
}
/// The `int` `do_ip_setsockopt` reads before it looks at the option: of one
/// byte, of fewer than 4, and 0 for none.
fn option4_int(c: &Context<'_>, at: u64, len: u64) -> Result<i32, Errno> {
    match len as u32 as i32 {
        ..0 => Err(Errno::EINVAL),
        0 => Ok(0),
        1..4 => Ok(i32::from(read_raw(c, at, 1)?[0])),
        4.. => option_int(c, at, len),
    }
}
/// Sets `IP_MULTICAST_IF`, `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP`,
/// `IP_ADD_MEMBERSHIP`, `IP_DROP_MEMBERSHIP` or `IP_MULTICAST_ALL`, the
/// option `name`, as `do_ip_setsockopt` does.
fn set_multicast4(
    c: &Context<'_>,
    socket: &InetSocket,
    name: u64,
    (at, len): (u64, u64),
) -> Result<(), Errno> {
    let tcp = !socket.datagram;
    let size = usize::try_from(len as u32 as i32).map_err(|_| Errno::EINVAL)?;
    // An `ip_mreqn`, an `ip_mreq`, or an address alone.
    let request = |least: usize| -> Result<Membership, Errno> {
        if size < least {
            return Err(Errno::EINVAL);
        }
        let read = match size {
            12.. => 12,
            8.. => 8,
            _ => 4,
        };
        let raw = read_raw(c, at, read)?;
        if read == 4 {
            return Ok(Membership::read(&[&[0; 4], raw.as_slice()].concat()));
        }
        Ok(Membership::read(&raw))
    };
    match name {
        // Not for TCP (`EINVAL`); -1 is 1.
        33 => {
            let value = option4_int(c, at, len)?;
            if tcp || size < 1 {
                return Err(Errno::EINVAL);
            }
            let value = if value == -1 { 1 } else { value };
            let value = u8::try_from(value).map_err(|_| Errno::EINVAL)?;
            socket.options().multicast_ttl = value;
        }
        34 | 49 => {
            let value = option4_int(c, at, len)?;
            if size < 1 || name == 49 && !matches!(value, 0 | 1) {
                return Err(Errno::EINVAL);
            }
            let mut options = socket.options();
            if name == 34 {
                options.multicast_loop = value != 0;
            } else {
                options.multicast_all = value != 0;
            }
        }
        // Not for TCP (`EINVAL`): a device by its index, else by an address
        // of it, or none for 0.0.0.0; `EADDRNOTAVAIL` for one there is not,
        // `EINVAL` for one other than the socket's own.
        32 => {
            if tcp {
                return Err(Errno::EINVAL);
            }
            let asked = request(4)?;
            if asked.index == 0 && asked.address.is_unspecified() {
                socket.options().multicast4 = (0, Ipv4Addr::UNSPECIFIED);
                return Ok(());
            }
            let index = if asked.index != 0 {
                socket
                    .network
                    .has_device(asked.index)
                    .then_some(asked.index)
            } else {
                socket.network.device_with4(asked.address, socket.now())
            };
            let index = index.ok_or(EADDRNOTAVAIL)?.unsigned_abs();
            let mut options = socket.options();
            if options.device != 0 && options.device != index {
                return Err(Errno::EINVAL);
            }
            options.multicast4 = (index, asked.address);
        }
        _ => {
            // TCP's are `EPROTO`, before anything is read.
            if tcp {
                return Err(EPROTO);
            }
            let asked = request(8)?;
            let mut s = socket.lock();
            let now = socket.now();
            if name == 35 {
                socket.network.join4(&mut s.groups4, asked, now)?;
            } else {
                socket.network.leave4(&mut s.groups4, asked, now)?;
            }
        }
    }
    Ok(())
}
/// `setsockopt` of an inet socket: the `SOL_SOCKET` options a client sets,
/// `IPPROTO_TCP`'s `TCP_NODELAY`, keepalive timing (1 to 32767 seconds, at
/// most 127 probes), `TCP_CORK`, `TCP_QUICKACK` and `TCP_USER_TIMEOUT`, `IP_TOS` and
/// `IPV6_V6ONLY`, and the filter options (`SO_ATTACH_FILTER`,
/// `SO_DETACH_FILTER`, `SO_LOCK_FILTER` and `SO_ATTACH_BPF`, as
/// [`crate::sockets::set_filter`] takes them), and the device the socket
/// is bound to (`SO_BINDTODEVICE`, `SO_BINDTOIFINDEX`, [`bind_to_device`]),
/// and those a datagram goes out through (`IPV6_MULTICAST_IF`,
/// `IPV6_UNICAST_IF`, the sticky `IPV6_PKTINFO`), and IPv4's multicast
/// options ([`set_multicast4`]).
/// `SO_PASSCRED`, `SO_PASSSEC`,
/// `SO_PASSPIDFD` and `SO_PASSRIGHTS` are EOPNOTSUPP, as Linux takes them
/// only on AF_UNIX (`sk_may_scm_recv` adds netlink and Bluetooth for the
/// first two). Any other option is ENOPROTOOPT. Only
/// `TCP_NODELAY` reaches the host; the rest are kept for getsockopt.
/// The options are locked once the value is read: the copy may wait for a
/// `userfaultfd`, and a TCP socket's readiness takes them.
fn set_option(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len) = (a[1], a[2], a[3], a[4]);
    let tcp = !socket.datagram;
    match (level, name) {
        (1, _) if Timestamps::is_option(name as u32) => {
            let value = option_int(c, at, len)?;
            if len == 8 && Timestamps::is_struct(name as u32) {
                read_raw(c, at, 8)?;
            }
            // `SOF_TIMESTAMPING_OPT_ID` needs a TCP socket's connection.
            let unconnected = tcp && {
                let s = socket.lock();
                s.listen.is_some() || matches!(s.connection, Connection::Unconnected)
            };
            socket
                .options()
                .timestamps
                .set(name as u32, value, unconnected)?;
        }
        (1, 16 | 34 | 76 | 83) => {
            option_int(c, at, len)?;
            return Err(EOPNOTSUPP);
        }
        // `SO_ATTACH_FILTER`, `SO_DETACH_FILTER`, `SO_LOCK_FILTER` and
        // `SO_ATTACH_BPF`, as a socket pair takes them; the socket's lock,
        // not its options', holds the filter.
        (1, 26 | 27 | 44 | 50) => {
            let value = option_int(c, at, len)?;
            return crate::sockets::set_filter(
                c,
                socket,
                name as u32,
                at,
                len as u32 as i32,
                value,
            )
            .unwrap_or(Err(ENOPROTOOPT));
        }
        // `SO_BINDTODEVICE` (`sock_setbindtodevice`): a device's name, not
        // an `int`, of at most 15 bytes, none or empty for no device;
        // `ENODEV` for a name the namespace has no device of.
        (1, 25) => {
            let Ok(len) = usize::try_from(len as u32 as i32) else {
                return Err(Errno::EINVAL);
            };
            let mut name = vec![0; len.min(15)];
            c.mem
                .read(GuestAddr(at), &mut name)
                .map_err(|_| Errno::EFAULT)?;
            let index = if name.first().is_none_or(|&b| b == 0) {
                0
            } else {
                socket
                    .network
                    .devices()
                    .by_name(&name)
                    .map(|d| d.index.unsigned_abs())
                    .ok_or(ENODEV)?
            };
            bind_to_device(c, socket, &mut socket.options(), index.cast_signed())?;
        }
        (0, 32..=36 | 49) => set_multicast4(c, socket, name, (at, len))?,
        // `IPV6_MULTICAST_IF` (`do_ipv6_setsockopt`, before the socket's
        // lock): not for TCP (`ENOPROTOOPT`); a device of the namespace
        // (`ENODEV`), the socket's own where it has one (`EINVAL`), or 0.
        (41, 17) if socket.family == Family::V6 => {
            let value = option6_int(c, at, len)?;
            if tcp {
                return Err(ENOPROTOOPT);
            }
            if (len as u32 as i32) < 4 {
                return Err(Errno::EINVAL);
            }
            let mut options = socket.options();
            if value != 0 {
                if !socket.network.has_device(value) {
                    return Err(ENODEV);
                }
                if options.device != 0 && options.device != value.cast_unsigned() {
                    return Err(Errno::EINVAL);
                }
            }
            options.multicast_device = value.cast_unsigned();
        }
        // `IPV6_UNICAST_IF`: an `int` exactly (`EINVAL` for another
        // length), an index in network byte order; 0 for none, else a
        // device of the namespace (`EADDRNOTAVAIL`), and not on a socket
        // bound to a device (`EINVAL`).
        (41, 76) if socket.family == Family::V6 => {
            let value = option6_int(c, at, len)?;
            if len as u32 != 4 {
                return Err(Errno::EINVAL);
            }
            let index = u32::from_be_bytes(value.to_le_bytes());
            let mut options = socket.options();
            if index != 0 {
                if !socket.network.has_device(index) {
                    return Err(EADDRNOTAVAIL);
                }
                if options.device != 0 {
                    return Err(Errno::EINVAL);
                }
            }
            options.unicast_device = index;
        }
        // The sticky `IPV6_PKTINFO`: a whole `in6_pktinfo` (`EINVAL` for
        // less), whose device must be the socket's where it has one
        // (`sk_dev_equal_l3scope`); neither the device nor the address is
        // looked for.
        (41, 50) if socket.family == Family::V6 => {
            option6_int(c, at, len)?;
            if (len as u32 as i32) < 20 || at == 0 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 20];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let index = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
            let mut options = socket.options();
            if options.device != 0 && options.device != index {
                return Err(Errno::EINVAL);
            }
            options.pktinfo_device = index;
        }
        (1, 20 | 21 | 66 | 67) => {
            if (len as u32 as i32) < 16 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 16];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let word = |i: usize| i64::from_le_bytes(raw[i..i + 8].try_into().unwrap_or_default());
            let timeout = Timeout::from_timeval(word(0), word(8))?;
            let mut options = socket.options();
            if matches!(name, 20 | 66) {
                options.receive_timeout = timeout;
            } else {
                options.send_timeout = timeout;
            }
        }
        (1, 13) => {
            if (len as u32 as i32) < 8 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 8];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let on = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let seconds = i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
            socket.options().linger = (on != 0).then_some(seconds);
        }
        (1, 2 | 6 | 7 | 8 | 9 | 10 | 12 | 15 | 62)
        | (6, 1 | 3 | 4 | 5 | 6 | 12 | 18)
        | (0, 1)
        | (41, 26) => {
            let value = option_int(c, at, len)?;
            let mut options = socket.options();
            match (level, name) {
                (1, 2 | 15) => {
                    if name == 2 {
                        options.reuse_address = value != 0;
                    } else {
                        options.reuse_port = value != 0;
                    }
                    socket.ports().set_reuse(
                        &socket.this,
                        options.reuse_address,
                        options.reuse_port,
                    );
                }
                (1, 6) => options.broadcast = value != 0,
                // At most `wmem_max` and `rmem_max`, doubled for Linux's
                // bookkeeping (`sk_setsockopt`).
                (1, 7) => {
                    options.send_buffer = crate::sockets::buffer_size(value, false, 4608);
                    options.send_buffer_set = true;
                }
                (1, 8) => {
                    options.receive_buffer = crate::sockets::buffer_size(value, false, 2304);
                    options.receive_buffer_set = true;
                }
                (1, 9) => options.keep_alive = value != 0,
                (1, 10) => options.out_of_band_inline = value != 0,
                (1, 12) => options.priority = value,
                // `SO_BINDTOIFINDEX`, of any index not negative.
                (1, 62) => bind_to_device(c, socket, &mut options, value)?,
                (6, _) if !tcp => return Err(ENOPROTOOPT),
                (6, 1) => {
                    options.no_delay = value != 0;
                    let s = socket.lock();
                    if let Some(stream) = &s.stream {
                        stream.set_nodelay(value != 0);
                    }
                    if let Some((link, side)) = InetSocket::joined(&s) {
                        link.set_no_delay(side, value != 0);
                    }
                }
                (6, 3) => {
                    options.cork = value != 0;
                    let s = socket.lock();
                    if let Some((link, side)) = InetSocket::joined(&s) {
                        link.set_cork(side, value != 0);
                    }
                }
                (6, 4 | 5) if !(1..=32767).contains(&value) => return Err(Errno::EINVAL),
                (6, 4) => options.keep_idle = value,
                (6, 5) => options.keep_interval = value,
                (6, 6) if !(1..=127).contains(&value) => return Err(Errno::EINVAL),
                (6, 6) => options.keep_count = value,
                (6, 12) => {
                    options.quick_ack = value != 0;
                    if let Some((link, side)) = InetSocket::joined(&socket.lock()) {
                        link.set_quick(side, value);
                    }
                }
                (6, 18) if value < 0 => return Err(Errno::EINVAL),
                (6, 18) => options.user_timeout = value,
                // A new type of service sets the priority too
                // (`__ip_sock_set_tos`, `rt_tos2priority`).
                (0, 1) if options.type_of_service != value & 0xfc => {
                    options.type_of_service = value & 0xfc;
                    options.priority = tos_priority(value);
                }
                (0, 1) => {}
                (41, 26) if socket.family == Family::V6 => {
                    // Linux refuses it once the socket has a local port.
                    let s = socket.lock();
                    if s.stream.is_some() || s.bound.is_some() {
                        return Err(Errno::EINVAL);
                    }
                    options.v6_only = value != 0;
                }
                _ => return Err(ENOPROTOOPT),
            }
        }
        _ => return Err(ENOPROTOOPT),
    }
    if tcp && level == 1 && matches!(name, 7 | 8) {
        let now = *socket.options();
        let stream = {
            let s = socket.lock();
            s.link.as_ref().and(s.stream.clone())
        };
        if let Some(stream) = stream {
            size_buffers(&stream, &now);
        }
    }
    Ok(0)
}
/// Binds `socket` to the device of `index` (0 for none), as
/// `sock_bindtoindex_locked`: `EPERM` for one bound to a device already,
/// without `CAP_NET_RAW` in the user namespace that owns its network
/// namespace; `EINVAL` for a negative index, whatever there is of it.
fn bind_to_device(
    c: &Context<'_>,
    socket: &InetSocket,
    options: &mut Options,
    index: i32,
) -> Result<(), Errno> {
    if options.device != 0
        && !c
            .process
            .credentials
            .capable_in(CAP_NET_RAW, socket.network.owner())
    {
        return Err(Errno::EPERM);
    }
    let index = u32::try_from(index).map_err(|_| Errno::EINVAL)?;
    options.device = index;
    socket.ports().set_device(&socket.this, index);
    Ok(())
}
/// Sizes a loopback connection's buffers by the `SO_SNDBUF` and `SO_RCVBUF`
/// the guest set, roughly as Linux bounds them: what waits to be sent by
/// the doubled `SO_SNDBUF` (`sk_wmem_queued`), and what has arrived by half
/// of the doubled `SO_RCVBUF` (the window `tcp_adv_win_scale` 1 leaves).
/// One the guest did not set stays [`paludarium_host::net::BUFFER`], where
/// Linux grows it as it tunes the connection.
fn size_buffers(stream: &Stream, options: &Options) {
    let set = |set: bool, bytes: i32| {
        if set {
            usize::try_from(bytes).unwrap_or(0)
        } else {
            paludarium_host::net::BUFFER
        }
    };
    stream.set_limits(
        set(options.send_buffer_set, options.send_buffer),
        set(options.receive_buffer_set, options.receive_buffer / 2),
    );
}
/// `getsockopt` of an inet socket: the options [`set_option`] keeps (the
/// device as `SO_BINDTODEVICE`'s name and `SO_BINDTOIFINDEX`'s index), and
/// `SO_TYPE`, `SO_ERROR` (which takes the pending error), `SO_ACCEPTCONN`,
/// `SO_PROTOCOL`, `SO_DOMAIN`, `SO_GET_FILTER` (the classic filter, as
/// [`crate::sockets::get_filter`] gives it) and `SO_BPF_EXTENSIONS`. A
/// level the socket does not have is
/// EOPNOTSUPP (setsockopt's is ENOPROTOOPT), as are `SO_PASSCRED`,
/// `SO_PASSSEC`, `SO_PASSPIDFD` and `SO_PASSRIGHTS`; an unknown name is
/// ENOPROTOOPT.
fn get_option(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len_at) = (a[1], a[2], a[3], a[4]);
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let options = *socket.options();
    let tcp = !socket.datagram;
    // A level the protocol does not have goes on to IPv4's, which refuses it
    // (`do_ip_getsockopt`); an IPv6 socket takes IPv4's own options too.
    let known = match level {
        0 | 1 => true,
        6 => tcp,
        17 => !tcp,
        41 => socket.family == Family::V6,
        _ => false,
    };
    if !known {
        return Err(EOPNOTSUPP);
    }
    let value: Vec<u8> = match (level, name) {
        (1, 16 | 34 | 76 | 83) => return Err(EOPNOTSUPP),
        // `SO_GET_FILTER`.
        (1, 26) => return crate::sockets::get_filter(c, socket, at, len_at, room as i32),
        (1, _) if Timestamps::is_option(name as u32) => options.timestamps.get(name as u32),
        (1, 20 | 21 | 66 | 67) => {
            let timeout = if matches!(name, 20 | 66) {
                options.receive_timeout
            } else {
                options.send_timeout
            };
            timeout.timeval().to_vec()
        }
        (6, 11) => {
            let s = socket.lock();
            socket.tcp_info(&s, socket.now()).bytes().to_vec()
        }
        // `SO_BINDTODEVICE` (`sock_getbindtodevice`): nothing for no device,
        // else its name and NUL, in room for a whole name (`EINVAL` for
        // less), and `ENODEV` for an index the namespace has no device of.
        (1, 25) if options.device == 0 => Vec::new(),
        (1, 25) => {
            if room < 16 {
                return Err(Errno::EINVAL);
            }
            let mut name = socket
                .network
                .devices()
                .by_index(options.device.cast_signed())
                .map(|d| d.name.clone())
                .ok_or(ENODEV)?;
            name.push(0);
            name
        }
        // `IP_MULTICAST_IF`: the address, whatever the device.
        (0, 32) => options.multicast4.1.octets().to_vec(),
        (1, 13) => {
            let mut linger = [0; 8];
            linger[..4].copy_from_slice(&i32::from(options.linger.is_some()).to_le_bytes());
            linger[4..].copy_from_slice(&options.linger.unwrap_or(0).to_le_bytes());
            linger.to_vec()
        }
        _ => {
            let int = match (level, name) {
                (1, 2) => i32::from(options.reuse_address),
                (1, 3) => {
                    if tcp {
                        1
                    } else {
                        2
                    }
                }
                (1, 4) => socket.take_error().map_or(0, |e| e.0),
                (1, 6) => i32::from(options.broadcast),
                (1, 7) => options.send_buffer,
                (1, 8) => options.receive_buffer,
                (1, 9) => i32::from(options.keep_alive),
                (1, 10) => i32::from(options.out_of_band_inline),
                (1, 12) => options.priority,
                (1, 15) => i32::from(options.reuse_port),
                (1, 62) => options.device.cast_signed(),
                (1, 30) => i32::from(socket.lock().listen.is_some()),
                (1, 44) => i32::from(socket.with_filter(|slot| slot.locked)),
                // `SO_BPF_EXTENSIONS`: `SKF_AD_MAX` (`bpf_tell_extensions`).
                (1, 48) => 64,
                (1, 38) => {
                    if tcp {
                        6
                    } else {
                        17
                    }
                }
                (1, 39) => i32::from(match socket.family {
                    Family::V4 => AF_INET,
                    Family::V6 => AF_INET6,
                }),
                (6, 1) => i32::from(options.no_delay),
                (6, 3) => i32::from(options.cork),
                (6, 4) => options.keep_idle,
                (6, 5) => options.keep_interval,
                (6, 6) => options.keep_count,
                (6, 12) => i32::from(options.quick_ack),
                (6, 18) => options.user_timeout,
                (0, 1) => options.type_of_service,
                // `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP` and
                // `IP_MULTICAST_ALL`.
                (0, 33) => i32::from(options.multicast_ttl),
                (0, 34) => i32::from(options.multicast_loop),
                (0, 49) => i32::from(options.multicast_all),
                (41, 26) if socket.family == Family::V6 => i32::from(options.v6_only),
                // `IPV6_MULTICAST_IF`, and `IPV6_UNICAST_IF` in network byte
                // order; `IPV6_PKTINFO` has no getsockopt (`ENOPROTOOPT`).
                (41, 17) if socket.family == Family::V6 => options.multicast_device.cast_signed(),
                (41, 76) if socket.family == Family::V6 => {
                    i32::from_le_bytes(options.unicast_device.to_be_bytes())
                }
                _ => return Err(ENOPROTOOPT),
            };
            // `do_ip_getsockopt`'s `copyval`: one byte in room for less than
            // an `int`, where one holds it.
            match u8::try_from(int) {
                Ok(byte) if level == 0 && room < 4 => vec![byte],
                _ => int.to_le_bytes().to_vec(),
            }
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

/// Reads a DNS query: one question with an uncompressed name. A query the
/// stub cannot read is answered `FORMERR`, one of another opcode `NOTIMP`,
/// one of another class with no records; a datagram too short for a header
/// gets no answer. Any other is `NXDOMAIN` until the send finds its name
/// allowed and starts its lookup.
fn parse_query(bytes: &[u8], from: SocketAddr) -> Option<Query> {
    if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
        return None;
    }
    let id = [bytes[0], bytes[1]];
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let mut query = Query {
        from,
        seq: 0,
        id,
        flags,
        question: Vec::new(),
        name: String::new(),
        kind: 0,
        answer: Answer::Now(1),
    };
    if (flags >> 11) & 0xf != 0 {
        query.answer = Answer::Now(4);
        return Some(query);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != 1 {
        return Some(query);
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*bytes.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        if len > 63 || at + 1 + len > bytes.len() {
            return Some(query);
        }
        labels.push(String::from_utf8_lossy(&bytes[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    if at + 4 > bytes.len() {
        return Some(query);
    }
    query.question = bytes[12..at + 4].to_vec();
    query.kind = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let class = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
    query.name = labels.join(".").to_ascii_lowercase();
    query.answer = Answer::Now(match normal(&query.name) {
        Some(_) if class != 1 => 0,
        Some(_) => 3,
        None => 3,
    });
    Some(query)
}
/// Starts the host's lookup of an allowed name the stub cannot answer
/// at once.
fn start_lookup(network: &Network, host: &dyn paludarium_host::Host, query: &mut Query) {
    if matches!(query.answer, Answer::Now(3))
        && !query.question.is_empty()
        && network.policy.allows_name(&query.name)
    {
        query.answer = match network.lookup(host, &query.name) {
            Ok(lookup) => Answer::Lookup(lookup),
            Err(_) => Answer::Now(2),
        };
    }
}

/// The stub over TCP, as a resolver asks it when a datagram answer was
/// truncated: a connection to port 53, at any address, is the stub's own
/// stream, which takes queries with their two-byte lengths, as RFC 1035
/// frames them, and gives each answer, in order, framed the same way. Once
/// the guest has shut its sending down and every answer has gone, the
/// stream ends.
struct DnsOverTcp {
    /// Itself, for the wakers of the lookups it waits for.
    me: Weak<DnsOverTcp>,
    stream: Weak<Stream>,
    peer: SocketAddr,
    network: Arc<Network>,
    host: Arc<dyn paludarium_host::Host>,
    state: Mutex<DnsState>,
}
#[derive(Default)]
struct DnsState {
    /// What the guest sent that is not yet a whole query.
    incoming: Vec<u8>,
    queries: VecDeque<Query>,
    /// Answer bytes the stream had no room for yet.
    outgoing: VecDeque<u8>,
    ended: bool,
}
impl DnsOverTcp {
    fn open(
        peer: SocketAddr,
        network: &Arc<Network>,
        host: &Arc<dyn paludarium_host::Host>,
    ) -> Arc<Stream> {
        let stream = Stream::new(peer);
        let driver = Arc::new_cyclic(|me| Self {
            me: Weak::clone(me),
            stream: Arc::downgrade(&stream),
            peer,
            network: Arc::clone(network),
            host: Arc::clone(host),
            state: Mutex::default(),
        });
        stream.set_driver(driver);
        stream
    }
    /// Reads the guest's queries, starts their lookups, and gives the
    /// answers that are ready.
    fn pump(&self) {
        let Some(stream) = self.stream.upgrade() else {
            return;
        };
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let bytes = stream.take(64 * 1024);
            if bytes.is_empty() {
                break;
            }
            s.incoming.extend_from_slice(&bytes);
        }
        while s.incoming.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([s.incoming[0], s.incoming[1]]));
            if s.incoming.len() < 2 + len {
                break;
            }
            let message: Vec<u8> = s.incoming.drain(..2 + len).skip(2).collect();
            let Some(mut query) = parse_query(&message, self.peer) else {
                continue;
            };
            start_lookup(&self.network, self.host.as_ref(), &mut query);
            if let Answer::Lookup(lookup) = &query.answer {
                let me = Weak::clone(&self.me);
                lookup.add_waker(Arc::new(move || {
                    if let Some(driver) = me.upgrade() {
                        driver.pump();
                    }
                }));
            }
            s.queries.push_back(query);
        }
        while let Some(answer) = s
            .queries
            .front()
            .and_then(|query| answer(&self.network, self.host.as_ref(), query, TCP_ANSWER))
        {
            s.queries.pop_front();
            s.outgoing.extend((answer.len() as u16).to_be_bytes());
            s.outgoing.extend(answer);
        }
        // As much as the stream takes; a read that frees a full stream
        // kicks for the rest.
        while !s.outgoing.is_empty() {
            let chunk = s.outgoing.make_contiguous().to_vec();
            let given = stream.receive(&chunk);
            s.outgoing.drain(..given);
            if given < chunk.len() {
                break;
            }
        }
        if s.queries.is_empty() && s.outgoing.is_empty() && stream.finished().0 && !s.ended {
            s.ended = true;
            drop(s);
            stream.end();
        }
    }
}
impl Driver for DnsOverTcp {
    /// The guest wrote, read or shut down: the stub answers at once, in the
    /// caller's thread, as the stream is unlocked then.
    fn kick(&self) {
        self.pump();
    }
}

/// The answer to `query`, once it can be given, in at most `limit` bytes:
/// only the addresses a name rule may reach, and NXDOMAIN when none is
/// left.
fn answer(
    network: &Network,
    host: &dyn paludarium_host::Host,
    query: &Query,
    limit: usize,
) -> Option<Vec<u8>> {
    let (code, addresses) = match &query.answer {
        Answer::Now(code) => (*code, Vec::new()),
        // Only the addresses a name rule may reach; none is NXDOMAIN.
        Answer::Lookup(lookup) => match lookup.result()? {
            Ok(found) => {
                let found: Vec<IpAddr> = found
                    .into_iter()
                    .filter(|ip| reachable(&query.name, *ip))
                    .collect();
                if found.is_empty() {
                    (3, found)
                } else {
                    let now = host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0);
                    network.note(&query.name, &found, now);
                    (0, found)
                }
            }
            Err(_) => (2, Vec::new()),
        },
    };
    Some(build_answer(query, code, &addresses, limit))
}

/// The most a datagram answer holds, without EDNS.
const UDP_ANSWER: usize = 512;
/// The most a TCP answer holds, as its two-byte length allows.
const TCP_ANSWER: usize = 65535;
/// The answer to `query` with response code `code` and, for an `A` or
/// `AAAA` question, the addresses of that family, each for 60 seconds, as
/// many as fit in `limit` bytes: when some do not, the answer is marked
/// truncated (TC), so that the resolver asks again over TCP.
fn build_answer(query: &Query, code: u8, addresses: &[IpAddr], limit: usize) -> Vec<u8> {
    let mut answer = Vec::with_capacity(limit.min(4096));
    answer.extend_from_slice(&query.id);
    // QR, the opcode and RD as asked, RA, and the code.
    let flags = 0x8080 | (query.flags & 0x7900) | u16::from(code);
    answer.extend_from_slice(&flags.to_be_bytes());
    let questions = u16::from(!query.question.is_empty());
    answer.extend_from_slice(&questions.to_be_bytes());
    answer.extend_from_slice(&[0; 6]);
    answer.extend_from_slice(&query.question);
    let mut count = 0u16;
    for ip in addresses {
        let data: Vec<u8> = match (query.kind, ip) {
            (1, IpAddr::V4(v4)) => v4.octets().to_vec(),
            (28, IpAddr::V6(v6)) => v6.octets().to_vec(),
            _ => continue,
        };
        if answer.len() + 12 + data.len() > limit {
            answer[2] |= 0x02;
            break;
        }
        answer.extend_from_slice(&[0xc0, 0x0c]);
        answer.extend_from_slice(&query.kind.to_be_bytes());
        answer.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        answer.extend_from_slice(&(data.len() as u16).to_be_bytes());
        answer.extend_from_slice(&data);
        count += 1;
    }
    answer[6..8].copy_from_slice(&count.to_be_bytes());
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_of_service_give_linuxs_priorities() {
        // IPTOS_LOWDELAY, IPTOS_THROUGHPUT, IPTOS_RELIABILITY, IPTOS_MINCOST
        // and both delay and throughput; precedence and ECN bits do not count.
        let priorities: Vec<i32> = [0x10, 0x08, 0x04, 0x02, 0x18, 0xe3, 0xf0]
            .into_iter()
            .map(tos_priority)
            .collect();
        assert_eq!(priorities, [6, 2, 0, 0, 4, 0, 6]);
    }

    #[test]
    fn rules_name_hosts_addresses_and_ports() {
        let policy = NetworkPolicy::new()
            .allow("GitHub.com:443")
            .unwrap()
            .allow("*.example.org")
            .unwrap()
            .allow("127.0.0.1:8080")
            .unwrap()
            .allow("[::1]:9000")
            .unwrap()
            .allow("2001:db8::1")
            .unwrap();
        assert!(policy.allows_name("github.com"));
        assert!(policy.allows_name("a.b.example.org"));
        assert!(!policy.allows_name("example.org"));
        assert!(!policy.allows_name("evilgithub.com"));
        let network = Network::new(policy);
        assert!(network.allows("127.0.0.1:8080".parse().unwrap(), 0));
        assert!(network.allows("[::ffff:127.0.0.1]:8080".parse().unwrap(), 0));
        assert!(!network.allows("127.0.0.1:8081".parse().unwrap(), 0));
        assert!(network.allows("[::1]:9000".parse().unwrap(), 0));
        assert!(network.allows("[2001:db8::1]:1".parse().unwrap(), 0));
        let github: SocketAddr = "192.0.2.7:443".parse().unwrap();
        assert!(!network.allows(github, 0));
        network.note("github.com", &[github.ip()], 5);
        assert!(network.allows(github, 5));
        assert!(!network.allows("192.0.2.7:80".parse().unwrap(), 5));
        // The name's address expires; another answer gives it again.
        assert!(!network.allows(github, 5 + NAME_LIFETIME));
        network.note("github.com", &[github.ip()], 5 + NAME_LIFETIME);
        assert!(network.allows(github, 5 + NAME_LIFETIME));
        for bad in [
            "", "a:b", "a:0", "[::1", "[::1]x", "bad name", "a..b", "a:70000",
        ] {
            assert!(NetworkPolicy::new().allow(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn addresses_run_out_as_a_socket_finds_them_and_netlink_hears_of_it_after() {
        use crate::interface::{Event, Lifetimes, V4};
        use core::net::{Ipv4Addr, SocketAddr};
        const SECOND: u64 = 1_000_000_000;
        let network = Network::isolated(crate::users::first());
        network.set_up(true, 0);
        let ip = Ipv4Addr::new(10, 9, 0, 1);
        let life = Lifetimes {
            valid: 2,
            preferred: 1,
        };
        network
            .addresses()
            .add_v4(V4::new(ip, ip, 24, 0), life, false, true, 0)
            .unwrap();
        let at = |now: u64| network.bindable(IpAddr::V4(ip), Some(now));
        // Usable until its valid lifetime ends, without a request.
        assert!(at(SECOND + SECOND / 2));
        assert!(!at(2 * SECOND));
        assert!(
            network
                .route(
                    SocketAddr::new(IpAddr::V4(ip), 9),
                    None,
                    (0, false),
                    0,
                    Some(3 * SECOND)
                )
                .is_err()
        );
        // What the socket found goes to netlink first, in its order: the
        // address deprecated, then gone with its routes.
        let events = network.expire(4 * SECOND);
        assert!(matches!(events.first(), Some(Event::NewAddr4(a)) if a.local == ip));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::DelAddr4(a) if a.local == ip))
        );
        assert!(network.expire(5 * SECOND).is_empty());
    }

    #[test]
    fn name_rules_reach_only_global_addresses() {
        for (name, ip, ok) in [
            ("github.com", "140.82.112.3", true),
            ("github.com", "2606:50c0:8000::153", true),
            ("evil.example.org", "127.0.0.1", false),
            ("evil.example.org", "10.1.2.3", false),
            ("evil.example.org", "172.16.0.1", false),
            ("evil.example.org", "192.168.1.1", false),
            ("evil.example.org", "169.254.169.254", false),
            ("evil.example.org", "100.64.0.1", false),
            ("evil.example.org", "0.0.0.0", false),
            ("evil.example.org", "::1", false),
            ("evil.example.org", "fd00::1", false),
            ("evil.example.org", "fe80::1", false),
            ("evil.example.org", "::ffff:10.0.0.1", false),
            ("evil.example.org", "64:ff9b::7f00:1", false),
            ("evil.example.org", "64:ff9b::c0a8:101", false),
            ("github.com", "64:ff9b::8c52:7003", true),
            ("evil.example.org", "2002:a00:1::1", false),
            ("github.com", "2002:8c52:7003::1", true),
            ("localhost", "127.0.0.1", true),
            ("localhost", "::1", true),
            ("app.localhost", "127.0.0.2", true),
            ("localhost", "10.0.0.1", false),
        ] {
            assert_eq!(reachable(name, ip.parse().unwrap()), ok, "{name} {ip}");
        }
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&[0, 1]);
        bytes
    }

    #[test]
    fn the_stub_answers_a_and_aaaa_questions() {
        let from: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let q = parse_query(&query("GitHub.com", 1), from).unwrap();
        assert_eq!(q.name, "github.com");
        assert_eq!(q.kind, 1);
        let addresses: Vec<IpAddr> =
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        let answer = build_answer(&q, 0, &addresses, UDP_ANSWER);
        assert_eq!(&answer[..4], &[0x12, 0x34, 0x81, 0x80]);
        assert_eq!(&answer[4..12], &[0, 1, 0, 1, 0, 0, 0, 0]);
        assert_eq!(&answer[answer.len() - 4..], &[192, 0, 2, 1]);
        let q6 = parse_query(&query("github.com", 28), from).unwrap();
        let answer = build_answer(&q6, 0, &addresses, UDP_ANSWER);
        assert_eq!(&answer[6..8], &[0, 1]);
        assert_eq!(answer[answer.len() - 1], 2);
        let missing = build_answer(&q, 3, &[], UDP_ANSWER);
        assert_eq!(missing[3] & 0xf, 3);
        assert_eq!(&missing[6..8], &[0, 0]);
        // Too many to fit are cut at 512 bytes.
        let many: Vec<IpAddr> = (0..100)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
            .collect();
        let cut = build_answer(&q, 0, &many, UDP_ANSWER);
        assert!(cut.len() <= 512);
        assert_eq!(cut[2] & 0x02, 0x02, "TC");
        assert_eq!(build_answer(&q, 0, &addresses, UDP_ANSWER)[2] & 0x02, 0);
        // Over TCP they all fit.
        let whole = build_answer(&q, 0, &many, TCP_ANSWER);
        assert_eq!((whole[2] & 0x02, &whole[6..8]), (0, &[0, 100][..]));
        // Another opcode is not implemented; two questions are a format error.
        let mut status = query("a.b", 1);
        status[2] = 0x10;
        assert!(matches!(
            parse_query(&status, from).unwrap().answer,
            Answer::Now(4)
        ));
        let mut two = query("a.b", 1);
        two[5] = 2;
        assert!(matches!(
            parse_query(&two, from).unwrap().answer,
            Answer::Now(1)
        ));
        assert!(parse_query(&[0; 4], from).is_none());
    }

    #[test]
    fn addresses_take_linux_layouts() {
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let raw = encode_address(Family::V4, v4);
        assert_eq!(raw, [2, 0, 1, 187, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_address(Family::V4, &raw), Ok(Some(v4)));
        let mapped = encode_address(Family::V6, v4);
        assert_eq!(mapped.len(), 28);
        assert_eq!(
            &mapped[8..24],
            &Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().octets()
        );
        assert_eq!(parse_address(Family::V4, &mapped), Err(EAFNOSUPPORT));
        assert_eq!(parse_address(Family::V4, &raw[..8]), Err(Errno::EINVAL));
        assert_eq!(parse_address(Family::V6, &mapped[..20]), Err(Errno::EINVAL));
        assert_eq!(parse_address(Family::V6, &[0, 0]), Ok(None));
        assert_eq!(parse_address(Family::V6, &[0]), Err(Errno::EINVAL));
    }

    #[test]
    fn datagrams_take_what_linux_counts() {
        // What the CI runner's x86-64 Linux 7.0 (`7.0.0-1017-azure`) takes
        // for one datagram of each length. The buckets and their boundaries
        // are those `rx_queue` in /proc/net/udp and udp6 showed under
        // Docker's Linux 7.0; the small head is the runner's 704 bytes, the
        // only size its counts in `udp-rcvbuf` allow. Docker's kernel, whose
        // small head is 640 bytes, gives less for the smallest datagrams.
        let expected: &[(usize, usize, usize)] = &[
            (0, 960, 960),
            (241, 960, 960),
            (312, 960, 960),
            (313, 960, 1280),
            (325, 960, 1280),
            (326, 1280, 1280),
            (645, 1280, 2304),
            (646, 2304, 2304),
            (1500, 2304, 2304),
            (1664, 2304, 4352),
            (1689, 4352, 4352),
            (3712, 4352, 8448),
            (3737, 8448, 8448),
            (7808, 8448, 16640),
            (7833, 16640, 16640),
            (15985, 16640, 16640),
            (16000, 16640, 16960),
            (16004, 16640, 16964),
            (16005, 16965, 16965),
            (32000, 32960, 32960),
            (65488, 66448, 66448),
            (65489, 66449, 67400),
            (65507, 66467, 67400),
        ];
        for &(len, ipv4, ipv6) in expected {
            assert_eq!(truesize(len, true), ipv4, "IPv4, {len} bytes");
            assert_eq!(truesize(len, false), ipv6, "IPv6, {len} bytes");
        }
        assert_eq!(truesize(65527, false), 67400);
    }
}
