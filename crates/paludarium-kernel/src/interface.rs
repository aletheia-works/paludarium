//! The addresses of a network namespace's loopback `lo` and its routing
//! tables, as Linux's `devinet`, `fib_frontend`, `fib_trie`, `addrconf` and
//! `ip6_fib` keep them.
//!
//! `127.0.0.1/8` comes with the loopback's first `NETDEV_UP` (and every
//! later one, should it have been removed), `::1/128` with each, and netlink
//! adds and removes others, and routes. An IPv4 address gives the local
//! table the kernel's routes `fib_add_ifaddr` makes: its `local` route at
//! once and, while the loopback is up, a broadcast route it names, its
//! prefix route (`local` too on a loopback) and its subnet's broadcast
//! route. Going down, the loopback loses every IPv4 route through it but
//! those of host scope, without a word, and every IPv6 route and address,
//! each told (`keep_addr_on_down` is 0). An IPv6 address has its `local`
//! route and, from an up, a unicast prefix route of metric 256 in the main
//! table.
//!
//! The local and main IPv4 tables are one trie, as Linux merges them while
//! there is no policy rule: a lookup takes the longest prefix of either,
//! then the default table's (253) where they have no answer. IPv6 looks in
//! the local table, then the main one. The other tables are kept and shown,
//! but no lookup reaches them.
use core::cmp::{Ordering, Reverse};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use paludarium_types::Errno;

const ESRCH: Errno = Errno(3);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENETDOWN: Errno = Errno(100);
const ENETUNREACH: Errno = Errno(101);
const EHOSTUNREACH: Errno = Errno(113);
const EOPNOTSUPP: Errno = Errno(95);
/// `IFA_F_SECONDARY`, `IFA_F_NOPREFIXROUTE` and `IFA_F_PERMANENT`.
pub(crate) const SECONDARY: u32 = 0x01;
pub(crate) const NO_PREFIX_ROUTE: u32 = 0x200;
pub(crate) const PERMANENT: u32 = 0x80;
/// The scopes of addresses and routes (`RT_SCOPE_*`).
pub(crate) const SCOPE_UNIVERSE: u8 = 0;
pub(crate) const SCOPE_LINK: u8 = 253;
pub(crate) const SCOPE_HOST: u8 = 254;
pub(crate) const SCOPE_NOWHERE: u8 = 255;
/// `IFAPROT_KERNEL_LO`: the kernel gave `::1` to the loopback.
pub(crate) const KERNEL_LO: u8 = 1;
/// The tables Linux has by name (`RT_TABLE_*`).
pub(crate) const TABLE_DEFAULT: u32 = 253;
pub(crate) const TABLE_MAIN: u32 = 254;
pub(crate) const TABLE_LOCAL: u32 = 255;
/// `RTPROT_KERNEL`: the kernel's own routes.
pub(crate) const PROTO_KERNEL: u8 = 2;
/// The flags of a request, and of what is told of a route it adds
/// (`NLM_F_*`).
pub(crate) const F_REPLACE: u16 = 0x100;
pub(crate) const F_EXCL: u16 = 0x200;
pub(crate) const F_CREATE: u16 = 0x400;
pub(crate) const F_APPEND: u16 = 0x800;
/// `RTNH_F_DEAD` and `RTNH_F_LINKDOWN`, which no request may set.
const NEXTHOP_DEAD: u32 = 0x1 | 0x10;
/// An IPv6 route's metric when its request names none
/// (`IP6_RT_PRIO_USER`), and an address's prefix route's
/// (`IP6_RT_PRIO_ADDRCONF`).
const METRIC_USER: u32 = 1024;
const METRIC_ADDRCONF: u32 = 256;

/// An IPv4 address of `lo` (Linux's `in_ifaddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V4 {
    pub local: Ipv4Addr,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub broadcast: Option<Ipv4Addr>,
    pub scope: u8,
    /// `IFA_F_*`, with `IFA_F_SECONDARY` and `IFA_F_PERMANENT` as the
    /// kernel sets them.
    pub flags: u32,
    pub proto: u8,
    pub label: Vec<u8>,
}
impl V4 {
    /// An address the guest asks for: `local`, `address` (its peer, or the
    /// same), `prefix` and `scope`.
    pub(crate) fn new(local: Ipv4Addr, address: Ipv4Addr, prefix: u8, scope: u8) -> Self {
        Self {
            local,
            address,
            prefix,
            broadcast: None,
            scope,
            flags: 0,
            proto: 0,
            label: b"lo".to_vec(),
        }
    }
    fn mask(&self) -> u32 {
        mask4(self.prefix)
    }
    /// Whether `ip` is in this address's subnet (`inet_ifa_match`).
    fn covers(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) ^ u32::from(self.address)) & self.mask() == 0
    }
    fn secondary(&self) -> bool {
        self.flags & SECONDARY != 0
    }
}
/// An IPv6 address of `lo` (Linux's `inet6_ifaddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V6 {
    pub address: Ipv6Addr,
    pub prefix: u8,
    pub flags: u32,
    pub proto: u8,
}
impl V6 {
    pub(crate) fn new(address: Ipv6Addr, prefix: u8) -> Self {
        Self {
            address,
            prefix,
            flags: PERMANENT,
            proto: 0,
        }
    }
    /// Its scope, as `ipv6_addr_scope` gives it.
    pub(crate) fn scope(&self) -> u8 {
        scope6(self.address)
    }
    fn covers(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) ^ u128::from(self.address)) & mask6(self.prefix) == 0
    }
    /// Its route in the local table.
    pub(crate) fn local_route(&self) -> Route6 {
        Route6 {
            table: TABLE_LOCAL,
            dst: self.address,
            len: 128,
            kind: Kind::Local,
            metric: 0,
            proto: PROTO_KERNEL,
            prefsrc: None,
            metrics: NO_METRICS,
        }
    }
    /// Its prefix route in the main table (`addrconf_prefix_route`), which
    /// `::1`, the kernel's, has not.
    pub(crate) fn prefix_route(&self) -> Option<Route6> {
        (self.proto != KERNEL_LO && self.flags & NO_PREFIX_ROUTE == 0).then(|| Route6 {
            table: TABLE_MAIN,
            dst: Ipv6Addr::from(u128::from(self.address) & mask6(self.prefix)),
            len: self.prefix,
            kind: Kind::Unicast,
            metric: METRIC_ADDRCONF,
            proto: PROTO_KERNEL,
            prefsrc: None,
            metrics: NO_METRICS,
        })
    }
}
/// The metrics of a route (`RTA_METRICS`), as `ip_metrics_convert`
/// keeps them in a `dst_metrics`: the value of each `RTAX_*` type at its
/// index less one, 0 for none. `RTAX_CC_ALGO`'s is the key of a
/// congestion control.
pub(crate) type Metrics = [u32; 17];
/// A route's metrics when its request names none (`dst_default_metrics`).
pub(crate) const NO_METRICS: Metrics = [0; 17];
fn mask4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}
fn mask6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}
fn scope6(ip: Ipv6Addr) -> u8 {
    if ip.is_loopback() {
        SCOPE_HOST
    } else if ip.segments()[0] & 0xffc0 == 0xfe80 {
        SCOPE_LINK
    } else {
        SCOPE_UNIVERSE
    }
}

/// What a route is (`RTN_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Unicast,
    Local,
    Broadcast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
}
impl Kind {
    /// The kind of `RTN_*` code `code`: `None` for one not supported here.
    pub(crate) fn of(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Unicast,
            2 => Self::Local,
            3 => Self::Broadcast,
            6 => Self::Blackhole,
            7 => Self::Unreachable,
            8 => Self::Prohibit,
            9 => Self::Throw,
            _ => return None,
        })
    }
    /// Its `RTN_*` code.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Unicast => 1,
            Self::Local => 2,
            Self::Broadcast => 3,
            Self::Blackhole => 6,
            Self::Unreachable => 7,
            Self::Prohibit => 8,
            Self::Throw => 9,
        }
    }
    /// What a lookup that ends at a route of this kind gives
    /// (`fib_props`, `fib6_prop`): `EAGAIN`, for a throw route, goes on to
    /// the next table.
    pub(crate) fn error(self) -> Option<Errno> {
        match self {
            Self::Blackhole => Some(Errno::EINVAL),
            Self::Unreachable => Some(EHOSTUNREACH),
            Self::Prohibit => Some(Errno::EACCES),
            Self::Throw => Some(Errno::EAGAIN),
            _ => None,
        }
    }
}
/// An IPv4 route (a `fib_alias` and its `fib_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route4 {
    pub table: u32,
    pub dst: Ipv4Addr,
    pub len: u8,
    pub tos: u8,
    pub priority: u32,
    pub kind: Kind,
    pub proto: u8,
    pub scope: u8,
    pub prefsrc: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    /// Whether it goes through `lo`; the kinds that reject have no device.
    pub device: bool,
    /// `RTNH_F_ONLINK`.
    pub onlink: bool,
    /// Whether its gateway is reached by a route of link scope, so that a
    /// lookup's answer names it (`rt_uses_gateway`).
    pub uses_gateway: bool,
    /// Its `fib_info`'s metrics, which tell two routes apart as
    /// `fib_find_info` does.
    pub metrics: Metrics,
}
impl Route4 {
    /// One of the kernel's routes for an address, in the local table, with
    /// the preferred source `source`.
    fn kernel(dst: Ipv4Addr, len: u8, kind: Kind, source: Ipv4Addr) -> Self {
        Self {
            table: TABLE_LOCAL,
            dst,
            len,
            tos: 0,
            priority: 0,
            kind,
            proto: PROTO_KERNEL,
            scope: if kind == Kind::Broadcast {
                SCOPE_LINK
            } else {
                SCOPE_HOST
            },
            prefsrc: Some(source),
            gateway: None,
            device: true,
            onlink: false,
            uses_gateway: false,
            metrics: NO_METRICS,
        }
    }
    /// The same route of the table, whatever its preferred source.
    fn same(&self, other: &Self) -> bool {
        self.dst == other.dst && self.len == other.len && self.kind == other.kind
    }
    /// Where it goes in the trie: by destination, the longer prefix first,
    /// the local table's before the main one's.
    fn place(&self) -> (u32, Reverse<u8>, Reverse<u32>) {
        (u32::from(self.dst), Reverse(self.len), Reverse(self.table))
    }
}
/// An IPv6 route (a `fib6_info`), through `lo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route6 {
    pub table: u32,
    pub dst: Ipv6Addr,
    pub len: u8,
    pub kind: Kind,
    pub metric: u32,
    pub proto: u8,
    pub prefsrc: Option<Ipv6Addr>,
    /// Its `fib6_metrics`.
    pub metrics: Metrics,
}
impl Route6 {
    fn covers(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) ^ u128::from(self.dst)) & mask6(self.len) == 0
    }
}
/// The order of a walk of a `fib6` tree (`fib6_walk`): children before
/// their node, the 0 branch before the 1 branch, so a prefix comes after
/// the longer ones it holds.
fn walk_order(a: &Route6, b: &Route6) -> Ordering {
    let (x, y) = (u128::from(a.dst), u128::from(b.dst));
    let shorter = u32::from(a.len.min(b.len));
    let common = (x ^ y).leading_zeros().min(shorter);
    if common >= shorter {
        b.len.cmp(&a.len)
    } else {
        let bit = |v: u128| (v >> (127 - common)) & 1;
        bit(x).cmp(&bit(y))
    }
}
/// The order a dump takes a family's tables in: by their hash bucket
/// (the ID's low byte), the newest first within one (`fib_table_hash`).
fn table_order(tables: &[u32]) -> Vec<u32> {
    let mut order: Vec<(usize, u32)> = tables.iter().copied().enumerate().collect();
    order.sort_by_key(|&(i, id)| (id & 255, Reverse(i)));
    order.into_iter().map(|(_, id)| id).collect()
}

/// A change to the addresses or routes Linux tells netlink of
/// (`RTM_NEWADDR`, `RTM_DELADDR`, `RTM_NEWROUTE`, `RTM_DELROUTE`); an
/// IPv6 address may be told of while tentative, and a new route with the
/// flags of its notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    NewAddr4(V4),
    DelAddr4(V4),
    NewRoute4(Route4, u16),
    DelRoute4(Route4),
    NewAddr6(V6, bool),
    DelAddr6(V6),
    NewRoute6(Route6, u16),
    DelRoute6(Route6),
}

/// An IPv4 route a request adds, as `rtm_to_fib_config` reads it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ask4 {
    pub table: u32,
    pub dst: Ipv4Addr,
    pub len: u8,
    pub tos: u8,
    pub priority: u32,
    /// The `RTN_*` code.
    pub kind: u8,
    pub proto: u8,
    pub scope: u8,
    pub prefsrc: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub oif: u32,
    /// `rtm_flags`.
    pub flags: u32,
    /// The request's `NLM_F_*`.
    pub request: u16,
    /// Its metrics, or the error converting them gave
    /// (`ip_fib_metrics_init`), which comes after the scope's.
    pub metrics: Result<Metrics, Errno>,
}
/// An IPv4 route a request removes: the first of `table`'s routes to
/// `dst/len` of `tos` from `priority` on that matches the rest, each
/// matching any when 0 (`RT_SCOPE_NOWHERE` for the scope).
#[derive(Clone, Debug)]
pub(crate) struct Select4 {
    pub table: u32,
    pub dst: Ipv4Addr,
    pub len: u8,
    pub tos: u8,
    pub priority: u32,
    pub kind: u8,
    pub proto: u8,
    pub scope: u8,
    pub prefsrc: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub oif: u32,
    /// The metrics the route must have (`fib_metrics_match`): each as an
    /// index of [`Metrics`] and its value, none for a request that names
    /// none; `None` where the request names one no route has.
    pub metrics: Option<Vec<(usize, u32)>>,
}
/// An IPv6 route a request adds or (each field 0 for any) removes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ask6 {
    pub table: u32,
    pub dst: Ipv6Addr,
    pub len: u8,
    pub kind: u8,
    pub proto: u8,
    pub metric: u32,
    pub prefsrc: Option<Ipv6Addr>,
    pub oif: u32,
    pub request: u16,
    /// Its metrics to add, or the error converting them gave, which comes
    /// once its table is made; a removal does not look at them.
    pub metrics: Result<Metrics, Errno>,
}

/// The loopback's addresses and the routing tables, in Linux's orders.
#[derive(Debug)]
pub(crate) struct Addresses {
    pub v4: Vec<V4>,
    pub v6: Vec<V6>,
    /// IPv4's routes of every table, in their trie's order
    /// ([`Route4::place`]), and as each prefix's list has them.
    routes4: Vec<Route4>,
    /// IPv6's, in the order of a walk ([`walk_order`]), then by metric.
    routes6: Vec<Route6>,
    /// The tables of each family, the oldest first. IPv4 makes them as
    /// routes go to them, so there is no local one before the first route,
    /// when `inet_addr_type` takes every address as broadcast; IPv6 has its
    /// main and local ones from the start.
    tables4: Vec<u32>,
    tables6: Vec<u32>,
    /// The loopback's MCTP endpoint IDs, the first added first, as
    /// `mctp_dev`'s `addrs`.
    pub mctp: Vec<u8>,
    /// The MCTP routes, the newest first, as `mctp_route_add` puts each at
    /// the head of the namespace's list: the local route of each of the
    /// loopback's addresses, and those added through gateways.
    pub mctp_routes: Vec<MctpRoute>,
}
/// An MCTP route (`struct mctp_route`): a range of endpoint IDs in a
/// network, either local through the loopback or through a gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MctpRoute {
    pub min: u8,
    pub max: u8,
    /// `RTN_LOCAL` for an address's own route, else `RTN_UNICAST`.
    pub kind: u8,
    /// Its MTU (`RTAX_MTU`), or 0 for none.
    pub mtu: u32,
    /// The gateway's network and endpoint ID, or `None` for a route
    /// through the loopback.
    pub gateway: Option<(u32, u8)>,
}
impl MctpRoute {
    /// The network the route is in (`mctp_route_netid`): its gateway's,
    /// or the loopback's, which is network 1.
    pub(crate) fn net(&self) -> u32 {
        self.gateway.map_or(1, |(net, _)| net)
    }
}
impl Addresses {
    /// The first namespace's: `127.0.0.1/8` and `::1`, up.
    pub(crate) fn first() -> Self {
        let mut addresses = Self::isolated();
        let _ = addresses.up();
        addresses
    }
    /// A new namespace's: none.
    pub(crate) fn isolated() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
            routes4: Vec::new(),
            routes6: Vec::new(),
            tables4: Vec::new(),
            tables6: vec![TABLE_MAIN, TABLE_LOCAL],
            mctp: Vec::new(),
            mctp_routes: Vec::new(),
        }
    }
    /// The loopback comes up (`NETDEV_UP`), and what Linux tells of it, in
    /// its order: `127.0.0.1/8` if it has it not, with its routes
    /// (`inetdev_event`); the routes every IPv4 address has then that are
    /// not there, in the addresses' order (`fib_netdev_event`); the prefix
    /// route of each IPv6 address added while it was down
    /// (`addrconf_permanent_addr`); and `::1` with its route.
    pub(crate) fn up(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        let mut loopback = V4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 8, SCOPE_HOST);
        loopback.flags = PERMANENT;
        if let Ok(added) = self.add_v4(loopback, false, true) {
            events.extend(added);
        }
        for address in self.v4.clone() {
            for route in self.candidates(&address, true) {
                self.kernel_add4(route, &mut events);
            }
        }
        for address in self.v6.clone() {
            if let Some(route) = address.prefix_route() {
                self.kernel_add6(route, &mut events);
            }
        }
        if !self.local6(Ipv6Addr::LOCALHOST) {
            let mut one = V6::new(Ipv6Addr::LOCALHOST, 128);
            one.proto = KERNEL_LO;
            events.push(Event::NewAddr6(one.clone(), false));
            self.kernel_add6(one.local_route(), &mut events);
            self.insert_v6(one);
        }
        events
    }
    /// The loopback goes down: IPv4's routes through it but those of host
    /// scope go, without a word (`fib_sync_down_dev`); and it loses every
    /// IPv6 route and address, Linux telling of the routes in the order of
    /// a dump (`rt6_disable_ip`), then of the addresses
    /// (`addrconf_ifdown`).
    pub(crate) fn down(&mut self) -> Vec<Event> {
        self.routes4
            .retain(|r| !(r.device && r.scope != SCOPE_HOST));
        let mut events: Vec<Event> = self.dump6().into_iter().map(Event::DelRoute6).collect();
        self.routes6.clear();
        events.extend(self.v6.drain(..).map(Event::DelAddr6));
        events
    }
    /// Adds an IPv4 address as `__inet_insert_ifa` does: the same local
    /// address and subnet again is `EEXIST`, unless `replace`, which takes
    /// its protocol; one in a subnet a primary address has is secondary,
    /// and goes last; a primary goes after the primaries of a scope as wide
    /// or wider. What Linux tells: the address, then the routes it brings
    /// (`fib_add_ifaddr`), those while `up` too.
    pub(crate) fn add_v4(
        &mut self,
        mut new: V4,
        replace: bool,
        up: bool,
    ) -> Result<Vec<Event>, Errno> {
        new.flags &= !SECONDARY;
        new.flags |= PERMANENT;
        let mut last_primary = 0;
        for (i, old) in self.v4.iter_mut().enumerate() {
            if !old.secondary() && new.scope <= old.scope {
                last_primary = i + 1;
            }
            if old.mask() == new.mask() && old.covers(new.address) {
                if old.local == new.local {
                    if !replace {
                        return Err(Errno::EEXIST);
                    }
                    old.proto = new.proto;
                    return Ok(Vec::new());
                }
                new.flags |= SECONDARY;
            }
        }
        let mut events = vec![Event::NewAddr4(new.clone())];
        if new.secondary() {
            self.v4.push(new.clone());
        } else {
            self.v4.insert(last_primary, new.clone());
        }
        for route in self.candidates(&new, up) {
            self.kernel_add4(route, &mut events);
        }
        Ok(events)
    }
    /// Removes the first IPv4 address that has `local`, `label`, and
    /// `address` in a subnet of `prefix`, each as given, as
    /// `inet_rtm_deladdr`: `EADDRNOTAVAIL` for none. A primary takes its
    /// secondaries with it (`promote_secondaries` is 0), which go first.
    /// What Linux tells: each address, then the kernel's routes that go
    /// with it, the prefix route, the broadcast ones, then the local one
    /// (`fib_del_ifaddr`); where its local address is the loopback's no
    /// more, the main table's routes from it (`fib_sync_down_addr`). The
    /// last address takes every route through `lo` with it, without a word
    /// (`fib_disable_ip`).
    pub(crate) fn del_v4(
        &mut self,
        local: Option<Ipv4Addr>,
        address: Option<Ipv4Addr>,
        prefix: u8,
        label: Option<&[u8]>,
    ) -> Result<Vec<Event>, Errno> {
        let found = self
            .v4
            .iter()
            .position(|a| {
                local.is_none_or(|local| a.local == local)
                    && label.is_none_or(|label| a.label == label)
                    && address.is_none_or(|address| a.prefix == prefix && a.covers(address))
            })
            .ok_or(EADDRNOTAVAIL)?;
        let target = self.v4[found].clone();
        let mut gone: Vec<V4> = Vec::new();
        if !target.secondary() {
            gone.extend(
                self.v4
                    .iter()
                    .filter(|a| {
                        a.secondary() && a.mask() == target.mask() && target.covers(a.address)
                    })
                    .cloned(),
            );
        }
        gone.push(target);
        let mut events = Vec::new();
        for address in gone {
            // `fib_del_ifaddr`'s order: the prefix route, the broadcast ones,
            // then the local one.
            let candidates = self.candidates(&address, true);
            let (local, rest) = candidates
                .split_first()
                .map_or((None, &[][..]), |(l, r)| (Some(*l), r));
            let mut order: Vec<Route4> = rest
                .iter()
                .filter(|r| r.kind == Kind::Local)
                .copied()
                .collect();
            order.extend(rest.iter().filter(|r| r.kind == Kind::Broadcast));
            order.extend(local);
            if let Some(i) = self.v4.iter().position(|a| *a == address) {
                self.v4.remove(i);
            }
            let wanted: Vec<Route4> = self
                .v4
                .iter()
                .flat_map(|a| self.candidates(a, true))
                .collect();
            events.push(Event::DelAddr4(address.clone()));
            let mut local_gone = false;
            for route in order {
                if wanted.iter().any(|r| r.same(&route)) {
                    continue;
                }
                local_gone |= route.kind == Kind::Local && route.len == 32;
                self.kernel_del4(&route, &mut events);
            }
            if local_gone && !self.local4(address.local) {
                let stray: Vec<Route4> = self
                    .dump4()
                    .into_iter()
                    .filter(|r| r.table == TABLE_MAIN && r.prefsrc == Some(address.local))
                    .collect();
                for route in stray {
                    self.kernel_del4(&route, &mut events);
                }
            }
            if self.v4.is_empty() {
                self.routes4.retain(|r| !r.device);
            }
        }
        Ok(events)
    }
    /// Adds an IPv6 address: the same one again is `EEXIST`, unless
    /// `replace`. Global ones go before host ones, the newest first
    /// within a scope (`ipv6_link_dev_addr`). What Linux tells: while up,
    /// its prefix route; the address, tentative, then once its duplicate
    /// address detection has ended at once on a loopback, as it is; then
    /// its local route.
    pub(crate) fn add_v6(
        &mut self,
        mut new: V6,
        replace: bool,
        up: bool,
    ) -> Result<Vec<Event>, Errno> {
        if let Some(old) = self.v6.iter_mut().find(|a| a.address == new.address) {
            if !replace {
                return Err(Errno::EEXIST);
            }
            old.proto = new.proto;
            return Ok(Vec::new());
        }
        new.flags |= PERMANENT;
        let mut events = Vec::new();
        if up && let Some(route) = new.prefix_route() {
            self.kernel_add6(route, &mut events);
        }
        events.push(Event::NewAddr6(new.clone(), true));
        events.push(Event::NewAddr6(new.clone(), false));
        self.kernel_add6(new.local_route(), &mut events);
        self.insert_v6(new);
        Ok(events)
    }
    fn insert_v6(&mut self, new: V6) {
        let at = self
            .v6
            .iter()
            .position(|a| a.scope() >= new.scope())
            .unwrap_or(self.v6.len());
        self.v6.insert(at, new);
    }
    /// Removes the IPv6 address `address/prefix` (`EADDRNOTAVAIL` for
    /// none). What Linux tells: the address, its local route, then, if no
    /// other address has its prefix, the first route of the main table to
    /// it, whoever's (`cleanup_prefix_route`).
    pub(crate) fn del_v6(&mut self, address: Ipv6Addr, prefix: u8) -> Result<Vec<Event>, Errno> {
        let found = self
            .v6
            .iter()
            .position(|a| a.address == address && a.prefix == prefix)
            .ok_or(EADDRNOTAVAIL)?;
        let gone = self.v6.remove(found);
        let mut events = vec![Event::DelAddr6(gone.clone())];
        self.kernel_del6(&gone.local_route(), &mut events);
        if gone.flags & NO_PREFIX_ROUTE == 0
            && !self
                .v6
                .iter()
                .any(|a| a.prefix == gone.prefix && a.covers(gone.address))
        {
            let dst = Ipv6Addr::from(u128::from(gone.address) & mask6(gone.prefix));
            if let Some(i) = self
                .routes6
                .iter()
                .position(|r| r.table == TABLE_MAIN && r.dst == dst && r.len == gone.prefix)
            {
                events.push(Event::DelRoute6(self.routes6.remove(i)));
            }
        }
        Ok(events)
    }
    /// The primary address whose subnet `secondary` is in, or itself.
    fn primary_of(&self, address: &V4) -> Ipv4Addr {
        if !address.secondary() {
            return address.local;
        }
        self.v4
            .iter()
            .find(|a| !a.secondary() && a.mask() == address.mask() && a.covers(address.address))
            .map_or(address.local, |a| a.local)
    }
    /// The routes `fib_add_ifaddr` gives `address`, in its order: the local
    /// one; and while up, the broadcast one it names, its prefix route,
    /// `local` on a loopback, and its subnet's broadcast route.
    fn candidates(&self, address: &V4, up: bool) -> Vec<Route4> {
        let source = self.primary_of(address);
        let route = |dst, len, kind| Route4::kernel(dst, len, kind, source);
        let mut routes = vec![route(address.local, 32, Kind::Local)];
        if !up {
            return routes;
        }
        if let Some(broadcast) = address
            .broadcast
            .filter(|b| !b.is_broadcast() && !b.is_unspecified())
        {
            routes.push(route(broadcast, 32, Kind::Broadcast));
        }
        let prefix = Ipv4Addr::from(u32::from(address.address) & address.mask());
        if prefix.is_unspecified()
            || address.secondary()
            || (prefix == address.local && address.prefix == 32)
        {
            return routes;
        }
        if address.flags & NO_PREFIX_ROUTE == 0 {
            routes.push(route(prefix, address.prefix, Kind::Local));
        }
        if address.prefix < 31 {
            routes.push(route(
                Ipv4Addr::from(u32::from(prefix) | !address.mask()),
                32,
                Kind::Broadcast,
            ));
        }
        routes
    }

    /// Makes the IPv4 table `table`, and for the local one the main one it
    /// shares a trie with first (`fib_new_table`).
    fn create4(&mut self, table: u32) {
        if table == TABLE_LOCAL {
            self.create4(TABLE_MAIN);
        }
        if !self.tables4.contains(&table) {
            self.tables4.push(table);
        }
    }
    fn create6(&mut self, table: u32) {
        if !self.tables6.contains(&table) {
            self.tables6.push(table);
        }
    }
    /// Puts `new` in its table as `fib_table_insert` does with the request
    /// flags `flags`. Among the routes to its prefix of its TOS and
    /// priority: `NLM_F_EXCL` is `EEXIST`; with `NLM_F_REPLACE` it takes
    /// the first's place (nothing to do where that is the same, `EEXIST`
    /// where another is); else the same route again is `EEXIST`, and it
    /// goes before them, or after with `NLM_F_APPEND`. Without them, it goes
    /// before the first of a lower priority. Without `NLM_F_CREATE` a new
    /// route is `ENOENT`. The flags Linux tells of it with, or `None` for
    /// nothing done.
    fn insert4(&mut self, new: Route4, flags: u16) -> Result<Option<u16>, Errno> {
        let place = new.place();
        let start = self.routes4.partition_point(|r| r.place() < place);
        let end = self.routes4.partition_point(|r| r.place() <= place);
        let alike = |r: &Route4| r.tos == new.tos && r.priority == new.priority;
        let found = (start..end).find(|&i| {
            let r = &self.routes4[i];
            r.tos < new.tos || (r.tos == new.tos && r.priority >= new.priority)
        });
        let mut told = F_EXCL;
        let mut at = found.unwrap_or(end);
        if let Some(first) = found.filter(|&i| alike(&self.routes4[i])) {
            if flags & F_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            told &= !F_EXCL;
            let run = (first..end)
                .find(|&i| !alike(&self.routes4[i]))
                .unwrap_or(end);
            let matched = (first..run).find(|&i| self.routes4[i] == new);
            if flags & F_REPLACE != 0 {
                return match matched {
                    Some(i) if i == first => Ok(None),
                    Some(_) => Err(Errno::EEXIST),
                    None => {
                        self.routes4[first] = new;
                        Ok(Some(F_REPLACE))
                    }
                };
            }
            if matched.is_some() {
                return Err(Errno::EEXIST);
            }
            if flags & F_APPEND != 0 {
                told |= F_APPEND;
                at = run;
            } else {
                at = first;
            }
        }
        if flags & F_CREATE == 0 {
            return Err(Errno::ENOENT);
        }
        self.routes4.insert(at, new);
        Ok(Some(told | F_CREATE))
    }
    /// Puts `new` in its table as `fib6_add_rt2node` does with the request
    /// flags `flags` (`None` for the kernel's): a route of the same metric
    /// is `EEXIST`, unless `NLM_F_REPLACE`, which takes its place; without
    /// one, `NLM_F_REPLACE` without `NLM_F_CREATE` is `ENOENT`. It goes after
    /// the routes of a metric as low or lower. The flags Linux tells of it
    /// with.
    fn insert6(&mut self, new: Route6, flags: Option<u16>) -> Result<u16, Errno> {
        let asked = |flag: u16| flags.is_some_and(|f| f & flag != 0);
        let mut told = F_EXCL;
        if let Some(i) = self.routes6.iter().position(|r| {
            r.table == new.table && r.dst == new.dst && r.len == new.len && r.metric == new.metric
        }) {
            if asked(F_EXCL) || !asked(F_REPLACE) {
                return Err(Errno::EEXIST);
            }
            self.routes6[i] = new;
            return Ok(F_REPLACE);
        }
        if asked(F_REPLACE) && !asked(F_CREATE) {
            return Err(Errno::ENOENT);
        }
        let at = self
            .routes6
            .iter()
            .position(|r| match walk_order(r, &new) {
                Ordering::Greater => true,
                Ordering::Equal => r.metric > new.metric,
                Ordering::Less => false,
            })
            .unwrap_or(self.routes6.len());
        self.routes6.insert(at, new);
        told |= F_CREATE;
        Ok(told)
    }
    /// One of the kernel's IPv4 routes (`fib_magic`), told of unless the
    /// same is there.
    fn kernel_add4(&mut self, route: Route4, events: &mut Vec<Event>) {
        self.create4(route.table);
        if let Ok(Some(flags)) = self.insert4(route, F_CREATE | F_APPEND) {
            events.push(Event::NewRoute4(route, flags));
        }
    }
    /// Removes one of the kernel's IPv4 routes, whatever its metrics, as
    /// `fib_magic` names none.
    fn kernel_del4(&mut self, route: &Route4, events: &mut Vec<Event>) {
        let same = |r: &Route4| {
            *r == Route4 {
                metrics: r.metrics,
                ..*route
            }
        };
        if let Some(i) = self.routes4.iter().position(same) {
            events.push(Event::DelRoute4(self.routes4.remove(i)));
        }
    }
    fn kernel_add6(&mut self, route: Route6, events: &mut Vec<Event>) {
        self.create6(route.table);
        if let Ok(flags) = self.insert6(route, None) {
            events.push(Event::NewRoute6(route, flags));
        }
    }
    fn kernel_del6(&mut self, route: &Route6, events: &mut Vec<Event>) {
        if let Some(i) = self.routes6.iter().position(|r| r == route) {
            events.push(Event::DelRoute6(self.routes6.remove(i)));
        }
    }

    /// Adds the IPv4 route `ask` asks for, as `inet_rtm_newroute`: its
    /// table is made first, whatever comes of it. `EINVAL` for a prefix
    /// past 32 or with bits past its length, a scope narrower than its
    /// kind's, a kind without a device that names one or a gateway, an
    /// unknown kind, the scope `RT_SCOPE_NOWHERE`, a gateway of host
    /// scope, an on-link route without a gateway, an invalid gateway or a
    /// preferred source that is not the loopback's; `ENODEV` for a device
    /// not `lo`; `ENETDOWN` while it is down, but for a route of host
    /// scope. Anycast, multicast and NAT routes are `EOPNOTSUPP`. The
    /// metrics' error comes after the scope's, as `fib_create_info` makes
    /// them.
    pub(crate) fn add_route4(&mut self, ask: &Ask4, up: bool) -> Result<Vec<Event>, Errno> {
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        self.create4(table);
        if ask.len > 32 || u32::from(ask.dst) & !mask4(ask.len) != 0 {
            return Err(Errno::EINVAL);
        }
        // `fib_props`' scope of each kind.
        let widest = match ask.kind {
            0 | 10 | 11 => SCOPE_NOWHERE,
            2 => SCOPE_HOST,
            3 | 4 => SCOPE_LINK,
            _ => SCOPE_UNIVERSE,
        };
        if widest > ask.scope || ask.flags & NEXTHOP_DEAD != 0 {
            return Err(Errno::EINVAL);
        }
        let metrics = ask.metrics?;
        let kind = Kind::of(ask.kind).ok_or(if matches!(ask.kind, 4 | 5 | 10 | 11) {
            EOPNOTSUPP
        } else {
            Errno::EINVAL
        })?;
        let onlink = ask.flags & 4 != 0;
        let mut route = Route4 {
            table,
            dst: ask.dst,
            len: ask.len,
            tos: ask.tos,
            priority: ask.priority,
            kind,
            proto: ask.proto,
            scope: ask.scope,
            prefsrc: ask.prefsrc,
            gateway: ask.gateway,
            device: true,
            onlink,
            uses_gateway: false,
            metrics,
        };
        if kind.error().is_some() {
            if ask.gateway.is_some() || ask.oif != 0 {
                return Err(Errno::EINVAL);
            }
            route.device = false;
        } else if ask.scope > SCOPE_HOST {
            return Err(Errno::EINVAL);
        } else if ask.scope == SCOPE_HOST {
            if ask.gateway.is_some() {
                return Err(Errno::EINVAL);
            }
            if ask.oif != 1 {
                return Err(Errno::ENODEV);
            }
        } else if let Some(gateway) = ask.gateway {
            route.uses_gateway = self.gateway4(gateway, ask, table, up)?;
        } else if onlink {
            return Err(Errno::EINVAL);
        } else if ask.oif != 1 {
            return Err(Errno::ENODEV);
        } else if !up {
            return Err(ENETDOWN);
        }
        if let Some(source) = ask.prefsrc
            && !self.valid_prefsrc4(source, &route)
        {
            return Err(Errno::EINVAL);
        }
        Ok(self
            .insert4(route, ask.request)?
            .map(|flags| Event::NewRoute4(route, flags))
            .into_iter()
            .collect())
    }
    /// Checks a gateway as `fib_check_nh_v4_gw`: on link, it must be a
    /// unicast address through `lo` while up, for a route wider than link
    /// scope; else a lookup of a narrower scope must reach it by a unicast
    /// or local route, in the route's table then the main one, its error
    /// as it is. Whether a route of link scope reaches it.
    fn gateway4(&self, gateway: Ipv4Addr, ask: &Ask4, table: u32, up: bool) -> Result<bool, Errno> {
        if ask.flags & 4 != 0 {
            if ask.scope >= SCOPE_LINK {
                return Err(Errno::EINVAL);
            }
            if ask.oif != 1 {
                return Err(Errno::ENODEV);
            }
            if !up {
                return Err(ENETDOWN);
            }
            if self.addr_type4(gateway, TABLE_LOCAL) != Kind::Unicast {
                return Err(Errno::EINVAL);
            }
            return Ok(true);
        }
        let scope = (ask.scope + 1).max(SCOPE_LINK);
        let mut found = Err(Errno::EAGAIN);
        let separate = table != TABLE_MAIN && self.tables4.contains(&table);
        if separate {
            found = self.table_lookup4(Self::trie(table), gateway, scope, ask.oif);
        }
        if !separate || found.is_err() {
            found = self.lookup4_in(gateway, scope, ask.oif);
        }
        let via = found?;
        if !matches!(via.kind, Kind::Unicast | Kind::Local) {
            return Err(Errno::EINVAL);
        }
        if !up {
            return Err(ENETDOWN);
        }
        Ok(via.scope == SCOPE_LINK)
    }
    /// Whether `source` may be a route's preferred source
    /// (`fib_valid_prefsrc`): a local route's own destination, or an
    /// address local in its table or the local one.
    fn valid_prefsrc4(&self, source: Ipv4Addr, route: &Route4) -> bool {
        if route.kind == Kind::Local && !route.dst.is_unspecified() && source == route.dst {
            return true;
        }
        let table = if route.table == TABLE_MAIN {
            TABLE_LOCAL
        } else {
            route.table
        };
        self.addr_type4(source, table) == Kind::Local
            || (table != TABLE_LOCAL && self.addr_type4(source, TABLE_LOCAL) == Kind::Local)
    }
    /// Removes the IPv4 route `select` names, as `fib_table_delete`:
    /// `ESRCH` for a table there is not, or no such route; `EINVAL` for a
    /// prefix past 32 or with bits past its length. A route must have the
    /// metrics `select` names (`fib_metrics_match`).
    pub(crate) fn del_route4(&mut self, select: &Select4) -> Result<Vec<Event>, Errno> {
        let table = if select.table == 0 {
            TABLE_MAIN
        } else {
            select.table
        };
        if !self.tables4.contains(&table) {
            return Err(ESRCH);
        }
        if select.len > 32 || u32::from(select.dst) & !mask4(select.len) != 0 {
            return Err(Errno::EINVAL);
        }
        let at = self
            .routes4
            .iter()
            .enumerate()
            .filter(|(_, r)| r.table == table && r.dst == select.dst && r.len == select.len)
            .skip_while(|(_, r)| {
                !(r.tos < select.tos || (r.tos == select.tos && r.priority >= select.priority))
            })
            .take_while(|(_, r)| r.tos == select.tos)
            .find(|(_, r)| {
                (select.kind == 0 || r.kind.code() == select.kind)
                    && (select.scope == SCOPE_NOWHERE || r.scope == select.scope)
                    && select.prefsrc.is_none_or(|s| r.prefsrc == Some(s))
                    && (select.proto == 0 || r.proto == select.proto)
                    && (select.oif == 0 || (r.device && select.oif == 1))
                    && select.gateway.is_none_or(|g| r.gateway == Some(g))
                    && select
                        .metrics
                        .as_ref()
                        .is_some_and(|m| m.iter().all(|&(i, v)| r.metrics[i] == v))
            })
            .map(|(i, _)| i)
            .ok_or(ESRCH)?;
        Ok(vec![Event::DelRoute4(self.routes4.remove(at))])
    }
    /// Adds the IPv6 route `ask` asks for, as `inet6_rtm_newroute`: a
    /// metric of 0 is 1024; `EINVAL` for a prefix past 128 or a preferred
    /// source that is not the loopback's; `ENODEV` for a device not `lo`,
    /// or none for a route that does not reject; `ENETDOWN` for one while
    /// `lo` is down. Its destination is taken to its prefix's length.
    /// Broadcast, anycast, multicast and NAT routes are `EOPNOTSUPP`.
    pub(crate) fn add_route6(&mut self, ask: &Ask6, up: bool) -> Result<Vec<Event>, Errno> {
        if ask.len > 128 {
            return Err(Errno::EINVAL);
        }
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        self.create6(table);
        let metrics = ask.metrics?;
        let kind = match ask.kind {
            0 => Kind::Unicast,
            code => Kind::of(code)
                .filter(|k| *k != Kind::Broadcast)
                .ok_or(EOPNOTSUPP)?,
        };
        if ask.oif != 0 && ask.oif != 1 {
            return Err(Errno::ENODEV);
        }
        if kind.error().is_none() {
            if ask.oif == 0 {
                return Err(Errno::ENODEV);
            }
            if !up {
                return Err(ENETDOWN);
            }
        }
        if let Some(source) = ask.prefsrc
            && !self.local6(source)
        {
            return Err(Errno::EINVAL);
        }
        let route = Route6 {
            table,
            dst: Ipv6Addr::from(u128::from(ask.dst) & mask6(ask.len)),
            len: ask.len,
            kind,
            metric: if ask.metric == 0 {
                METRIC_USER
            } else {
                ask.metric
            },
            proto: ask.proto,
            prefsrc: ask.prefsrc,
            metrics,
        };
        let flags = self.insert6(route, Some(ask.request))?;
        Ok(vec![Event::NewRoute6(route, flags)])
    }
    /// Removes the first IPv6 route of `ask`'s table to its prefix of its
    /// metric and protocol, of any kind (`ip6_route_del`): `ESRCH` for
    /// none.
    pub(crate) fn del_route6(&mut self, ask: &Ask6) -> Result<Vec<Event>, Errno> {
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        if !self.tables6.contains(&table) {
            return Err(ESRCH);
        }
        let dst = Ipv6Addr::from(u128::from(ask.dst) & mask6(ask.len));
        let at = self
            .routes6
            .iter()
            .position(|r| {
                r.table == table
                    && r.dst == dst
                    && r.len == ask.len
                    && (ask.metric == 0 || r.metric == ask.metric)
                    && (ask.proto == 0 || r.proto == ask.proto)
                    && (ask.oif == 0 || ask.oif == 1)
            })
            .ok_or(ESRCH)?;
        Ok(vec![Event::DelRoute6(self.routes6.remove(at))])
    }

    /// The IPv4 routes, as a dump gives them: table by table
    /// ([`table_order`]), each in its trie's order.
    pub(crate) fn dump4(&self) -> Vec<Route4> {
        table_order(&self.tables4)
            .into_iter()
            .flat_map(|t| self.routes4.iter().filter(move |r| r.table == t).copied())
            .collect()
    }
    /// The IPv6 routes, as a dump gives them: table by table, each in the
    /// order of a walk of its tree.
    pub(crate) fn dump6(&self) -> Vec<Route6> {
        table_order(&self.tables6)
            .into_iter()
            .flat_map(|t| self.routes6.iter().filter(move |r| r.table == t).copied())
            .collect()
    }
    /// Whether IPv4 has made the table `table` (`fib_get_table`).
    pub(crate) fn has_table4(&self, table: u32) -> bool {
        self.tables4.contains(&table)
    }
    /// Whether IPv6 has made the table `table` (`fib6_get_table`).
    pub(crate) fn has_table6(&self, table: u32) -> bool {
        self.tables6.contains(&table)
    }
    /// The tables one trie holds: the local and main ones share theirs.
    fn trie(table: u32) -> &'static [u32] {
        match table {
            TABLE_LOCAL | TABLE_MAIN => &[TABLE_LOCAL, TABLE_MAIN],
            TABLE_DEFAULT => &[TABLE_DEFAULT],
            _ => &[],
        }
    }
    /// A lookup in one trie (`fib_table_lookup`): the longest prefix that
    /// has a route of no TOS, of `scope` or narrower and through `oif` (any
    /// for 0), the first such of it; a rejecting one's error; `EAGAIN` for
    /// none. A table not named in [`Self::trie`] is looked in alone.
    fn table_lookup4(
        &self,
        tables: &[u32],
        ip: Ipv4Addr,
        scope: u8,
        oif: u32,
    ) -> Result<Route4, Errno> {
        for len in (0..=32u8).rev() {
            let dst = Ipv4Addr::from(u32::from(ip) & mask4(len));
            for r in self
                .routes4
                .iter()
                .filter(|r| r.dst == dst && r.len == len && tables.contains(&r.table))
            {
                if r.tos != 0 || r.scope < scope {
                    continue;
                }
                if let Some(e) = r.kind.error() {
                    return Err(e);
                }
                if oif != 0 && !(r.device && oif == 1) {
                    continue;
                }
                return Ok(*r);
            }
        }
        Err(Errno::EAGAIN)
    }
    /// A lookup as `fib_lookup` makes it while there is no policy rule:
    /// the local and main tables' trie, then, where that gives `EAGAIN`,
    /// the default table if there is one; `EAGAIN` at the end is
    /// `ENETUNREACH`.
    fn lookup4_in(&self, ip: Ipv4Addr, scope: u8, oif: u32) -> Result<Route4, Errno> {
        let mut found = self.table_lookup4(Self::trie(TABLE_MAIN), ip, scope, oif);
        if found == Err(Errno::EAGAIN) && self.tables4.contains(&TABLE_DEFAULT) {
            found = self.table_lookup4(Self::trie(TABLE_DEFAULT), ip, scope, oif);
        }
        found.map_err(|e| if e == Errno::EAGAIN { ENETUNREACH } else { e })
    }
    /// The route to `ip`, as an output route's lookup takes it.
    pub(crate) fn lookup4(&self, ip: Ipv4Addr) -> Result<Route4, Errno> {
        self.lookup4_in(ip, SCOPE_UNIVERSE, 0)
    }
    /// What `ip` is to `table` (`inet_addr_type_table`): broadcast while
    /// there is no such table, the kind of the route a lookup in it finds,
    /// and unicast where it finds none.
    fn addr_type4(&self, ip: Ipv4Addr, table: u32) -> Kind {
        if !self.tables4.contains(&table) {
            return Kind::Broadcast;
        }
        let tables = match Self::trie(table) {
            [] => core::slice::from_ref(&table),
            trie => trie,
        };
        self.table_lookup4(tables, ip, SCOPE_UNIVERSE, 0)
            .map_or(Kind::Unicast, |r| r.kind)
    }
    /// The address a route through `lo` to `ip` leaves from
    /// (`fib_select_path`): a local route's preferred source or `ip`;
    /// another's preferred source, else the first primary address of a
    /// scope as narrow as the route's, one whose subnet has its gateway
    /// before the others (`inet_select_addr`); `None` for none.
    pub(crate) fn source4(&self, route: &Route4, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        if route.kind == Kind::Local {
            return Some(route.prefsrc.unwrap_or(ip));
        }
        if route.prefsrc.is_some() {
            return route.prefsrc;
        }
        let mut first = None;
        for a in self.v4.iter().filter(|a| !a.secondary()) {
            if a.scope.min(SCOPE_HOST) > route.scope {
                continue;
            }
            if route.gateway.is_none_or(|g| a.covers(g)) {
                return Some(a.local);
            }
            first.get_or_insert(a.local);
        }
        first.or_else(|| {
            self.v4
                .iter()
                .find(|a| !a.secondary() && a.scope != SCOPE_LINK && a.scope <= route.scope)
                .map(|a| a.local)
        })
    }
    /// A lookup in one IPv6 table: the route of the longest prefix that has
    /// `ip`, the lowest metric first.
    fn table_lookup6(&self, table: u32, ip: Ipv6Addr) -> Option<Route6> {
        self.routes6
            .iter()
            .filter(|r| r.table == table && r.covers(ip))
            .min_by_key(|r| (Reverse(r.len), r.metric))
            .copied()
    }
    /// The IPv6 route to `ip` (`fib6_rule_lookup`): the local table's, then
    /// the main one's, where the first has none or a throw route; a
    /// rejecting route's error; `ENETUNREACH` for none.
    pub(crate) fn lookup6(&self, ip: Ipv6Addr) -> Result<Route6, Errno> {
        for table in [TABLE_LOCAL, TABLE_MAIN] {
            if let Some(route) = self.table_lookup6(table, ip) {
                match route.kind.error() {
                    Some(Errno::EAGAIN) => {}
                    Some(e) => return Err(e),
                    None => return Ok(route),
                }
            }
        }
        Err(ENETUNREACH)
    }
    /// The address a route to `ip` leaves from: its preferred source, else
    /// the address `ipv6_dev_get_saddr` picks, by these of its rules: `ip`
    /// itself, the narrowest scope as wide as `ip`'s, the same label, then
    /// the longest prefix shared, up to the address's own.
    pub(crate) fn source6(&self, route: &Route6, ip: Ipv6Addr) -> Option<Ipv6Addr> {
        if route.prefsrc.is_some() {
            return route.prefsrc;
        }
        let scope = |a: Ipv6Addr| -> i32 {
            if a.is_loopback() || a.segments()[0] & 0xffc0 == 0xfe80 {
                2
            } else if a.segments()[0] & 0xffc0 == 0xfec0 {
                5
            } else {
                14
            }
        };
        let wanted = scope(ip);
        let score = |a: &V6| {
            let own = scope(a.address);
            let distance = if own >= wanted { -own } else { own - 128 };
            let shared = (u128::from(a.address) ^ u128::from(ip))
                .leading_zeros()
                .min(u32::from(a.prefix));
            (
                a.address == ip,
                distance,
                label6(a.address) == label6(ip),
                shared,
            )
        };
        let mut best: Option<&V6> = None;
        for a in &self.v6 {
            if best.is_none_or(|b| score(a) > score(b)) {
                best = Some(a);
            }
        }
        best.map(|a| a.address)
    }
    /// Whether a socket may bind to the IPv4 address `ip`: it is local or
    /// broadcast to the local table, or there is none yet.
    pub(crate) fn bindable4(&self, ip: Ipv4Addr) -> bool {
        matches!(
            self.addr_type4(ip, TABLE_LOCAL),
            Kind::Local | Kind::Broadcast
        )
    }
    /// Whether `ip` is an IPv4 address of the loopback's, as a local route
    /// gives it.
    pub(crate) fn local4(&self, ip: Ipv4Addr) -> bool {
        self.tables4.contains(&TABLE_LOCAL) && self.addr_type4(ip, TABLE_LOCAL) == Kind::Local
    }
    /// Whether `ip` is an IPv6 address of the loopback's.
    pub(crate) fn local6(&self, ip: Ipv6Addr) -> bool {
        self.v6.iter().any(|a| a.address == ip)
    }
    /// The address a connection to `to` on the loopback leaves from: its
    /// route's ([`Self::source4`], [`Self::source6`]), `127.0.0.1` or `::1`
    /// where there is none.
    pub(crate) fn source(&self, to: IpAddr) -> IpAddr {
        match to {
            IpAddr::V4(ip) => IpAddr::V4(
                self.lookup4(ip)
                    .ok()
                    .and_then(|r| self.source4(&r, ip))
                    .unwrap_or(Ipv4Addr::LOCALHOST),
            ),
            IpAddr::V6(ip) => IpAddr::V6(
                self.lookup6(ip)
                    .ok()
                    .and_then(|r| self.source6(&r, ip))
                    .unwrap_or(Ipv6Addr::LOCALHOST),
            ),
        }
    }
}
/// The label of `ip` in Linux's default address label table
/// (`ip6addrlbl_init_table`), its longest prefix's.
fn label6(ip: Ipv6Addr) -> u32 {
    const TABLE: [(u128, u8, u32); 10] = [
        (0, 0, 1),
        (0xfc00 << 112, 7, 5),
        (0xfec0 << 112, 10, 11),
        (0x2002 << 112, 16, 2),
        (0x3ffe << 112, 16, 12),
        (0x2001 << 112, 32, 6),
        ((0x2001 << 112) | (0x10 << 96), 28, 7),
        (0xffff << 32, 96, 4),
        (0, 96, 3),
        (1, 128, 0),
    ];
    let ip = u128::from(ip);
    TABLE
        .iter()
        .filter(|(prefix, len, _)| (ip ^ prefix) & mask6(*len) == 0)
        .max_by_key(|(_, len, _)| *len)
        .map_or(1, |(_, _, label)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str, prefix: u8) -> V4 {
        let ip: Ipv4Addr = s.parse().unwrap();
        V4::new(ip, ip, prefix, SCOPE_UNIVERSE)
    }
    /// A short form of a route: its table, prefix and kind.
    fn short4(r: &Route4) -> String {
        format!("{} {}/{} {:?}", r.table, r.dst, r.len, r.kind)
    }
    fn short6(r: &Route6) -> String {
        format!("{} {}/{} {:?} {}", r.table, r.dst, r.len, r.kind, r.metric)
    }

    /// A short form of an event: what it is and its address or route.
    fn told(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                Event::NewAddr4(a) => format!("+addr {}/{}", a.local, a.prefix),
                Event::DelAddr4(a) => format!("-addr {}/{}", a.local, a.prefix),
                Event::NewRoute4(r, flags) => format!("+route {} {flags:#x}", short4(r)),
                Event::DelRoute4(r) => format!("-route {}", short4(r)),
                Event::NewAddr6(a, tentative) => {
                    format!("+addr {}/{} {tentative}", a.address, a.prefix)
                }
                Event::DelAddr6(a) => format!("-addr {}/{}", a.address, a.prefix),
                Event::NewRoute6(r, flags) => format!("+route {} {flags:#x}", short6(r)),
                Event::DelRoute6(r) => format!("-route {}", short6(r)),
            })
            .collect()
    }
    fn ask4(dst: &str, len: u8, kind: u8, request: u16) -> Ask4 {
        Ask4 {
            table: TABLE_MAIN,
            dst: dst.parse().unwrap(),
            len,
            tos: 0,
            priority: 0,
            kind,
            proto: 3,
            scope: if kind == 1 {
                SCOPE_LINK
            } else {
                SCOPE_UNIVERSE
            },
            prefsrc: None,
            gateway: None,
            oif: u32::from(kind == 1),
            flags: 0,
            request,
            metrics: Ok(NO_METRICS),
        }
    }

    #[test]
    fn changes_are_told_in_linux_order() {
        let mut a = Addresses::isolated();
        // Added while down: the address and its local route; IPv6's twice.
        let added = a.add_v4(v4("10.5.5.5", 24), false, false).unwrap();
        assert_eq!(
            told(&added),
            ["+addr 10.5.5.5/24", "+route 255 10.5.5.5/32 Local 0x600"]
        );
        let added = a
            .add_v6(V6::new("2001:db8::5".parse().unwrap(), 64), false, false)
            .unwrap();
        assert_eq!(
            told(&added),
            [
                "+addr 2001:db8::5/64 true",
                "+addr 2001:db8::5/64 false",
                "+route 255 2001:db8::5/128 Local 0 0x600",
            ]
        );
        // Up: 127.0.0.1/8 and its routes, the routes the up brings the
        // other address, IPv6's prefix route, then ::1.
        assert_eq!(
            told(&a.up()),
            [
                "+addr 127.0.0.1/8",
                "+route 255 127.0.0.1/32 Local 0x600",
                "+route 255 127.0.0.0/8 Local 0x600",
                "+route 255 127.255.255.255/32 Broadcast 0x600",
                "+route 255 10.5.5.0/24 Local 0x600",
                "+route 255 10.5.5.255/32 Broadcast 0x600",
                "+route 254 2001:db8::/64 Unicast 256 0x600",
                "+addr ::1/128 false",
                "+route 255 ::1/128 Local 0 0x600",
            ]
        );
        let added = a
            .add_v6(V6::new("2001:db8:1::1".parse().unwrap(), 64), false, true)
            .unwrap();
        assert_eq!(
            told(&added)[0],
            "+route 254 2001:db8:1::/64 Unicast 256 0x600"
        );
        // A primary goes after its secondary: each address, then its
        // routes, the prefix route first and the local one last.
        a.add_v4(v4("10.5.5.9", 24), false, true).unwrap();
        let gone = a
            .del_v4(Some("10.5.5.5".parse().unwrap()), None, 24, None)
            .unwrap();
        assert_eq!(
            told(&gone),
            [
                "-addr 10.5.5.9/24",
                "-route 255 10.5.5.9/32 Local",
                "-addr 10.5.5.5/24",
                "-route 255 10.5.5.0/24 Local",
                "-route 255 10.5.5.255/32 Broadcast",
                "-route 255 10.5.5.5/32 Local",
            ]
        );
        // Down: IPv6's routes, the main table's first, then its addresses.
        assert_eq!(
            told(&a.down()),
            [
                "-route 254 2001:db8::/64 Unicast 256",
                "-route 254 2001:db8:1::/64 Unicast 256",
                "-route 255 ::1/128 Local 0",
                "-route 255 2001:db8::5/128 Local 0",
                "-route 255 2001:db8:1::1/128 Local 0",
                "-addr 2001:db8:1::1/64",
                "-addr 2001:db8::5/64",
                "-addr ::1/128",
            ]
        );
    }

    #[test]
    fn addresses_take_linux_orders_and_routes() {
        let mut a = Addresses::isolated();
        // Every address binds before there is a local table.
        assert!(a.bindable4("10.9.9.9".parse().unwrap()));
        // Added while down: its local route alone.
        a.add_v4(v4("10.1.2.3", 24), false, false).unwrap();
        a.add_v6(V6::new("2001:db8::5".parse().unwrap(), 64), false, false)
            .unwrap();
        assert_eq!(
            a.dump4().iter().map(short4).collect::<Vec<_>>(),
            ["255 10.1.2.3/32 Local"]
        );
        assert!(!a.bindable4("10.9.9.9".parse().unwrap()));
        assert_eq!(a.dump6().len(), 1);
        a.up();
        // 127.0.0.1/8, of host scope, goes first; a secondary goes last.
        a.add_v4(v4("10.1.2.9", 24), false, true).unwrap();
        assert_eq!(
            a.add_v4(v4("10.1.2.3", 24), false, true),
            Err(Errno::EEXIST)
        );
        a.add_v4(v4("10.1.2.3", 16), false, true).unwrap();
        let order: Vec<_> =
            a.v4.iter()
                .map(|a| (a.local.to_string(), a.prefix, a.flags))
                .collect();
        assert_eq!(
            order,
            [
                ("127.0.0.1".to_string(), 8, PERMANENT),
                ("10.1.2.3".to_string(), 24, PERMANENT),
                ("10.1.2.3".to_string(), 16, PERMANENT),
                ("10.1.2.9".to_string(), 24, PERMANENT | SECONDARY),
            ]
        );
        assert_eq!(
            a.dump4().iter().map(short4).collect::<Vec<_>>(),
            [
                "255 10.1.0.0/16 Local",
                "255 10.1.2.0/24 Local",
                "255 10.1.2.3/32 Local",
                "255 10.1.2.9/32 Local",
                "255 10.1.2.255/32 Broadcast",
                "255 10.1.255.255/32 Broadcast",
                "255 127.0.0.0/8 Local",
                "255 127.0.0.1/32 Local",
                "255 127.255.255.255/32 Broadcast",
            ]
        );
        // The subnet is local on a loopback; another is not.
        assert!(a.local4("10.1.2.77".parse().unwrap()));
        assert!(!a.bindable4("10.2.0.1".parse().unwrap()));
        assert_eq!(
            a.source("10.1.2.77".parse().unwrap()),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
        // IPv6: global first, newest first; the prefix route in the main
        // table, before the local ones.
        a.add_v6(V6::new("2001:db8:1::1".parse().unwrap(), 128), false, true)
            .unwrap();
        let order: Vec<_> = a.v6.iter().map(|a| a.address.to_string()).collect();
        assert_eq!(order, ["2001:db8:1::1", "2001:db8::5", "::1"]);
        assert_eq!(
            a.dump6().iter().map(short6).collect::<Vec<_>>(),
            [
                "254 2001:db8::/64 Unicast 256",
                "254 2001:db8:1::1/128 Unicast 256",
                "255 ::1/128 Local 0",
                "255 2001:db8::5/128 Local 0",
                "255 2001:db8:1::1/128 Local 0",
            ]
        );
        let ip: Ipv6Addr = "2001:db8::6".parse().unwrap();
        let via = a.lookup6(ip).unwrap();
        assert_eq!(
            (via.kind, a.source6(&via, ip).unwrap().to_string()),
            (Kind::Unicast, "2001:db8::5".to_string())
        );
        // Down: the IPv4 prefix routes stay, the broadcast ones and IPv6's
        // addresses go.
        a.down();
        assert!(a.v6.is_empty());
        assert_eq!(a.dump4().len(), 6);
        a.up();
        assert_eq!(a.v6.len(), 1);
        // A primary takes its secondary; 127.0.0.1 comes back with the next
        // up.
        a.del_v4(
            Some("10.1.2.3".parse().unwrap()),
            Some("10.1.2.3".parse().unwrap()),
            24,
            None,
        )
        .unwrap();
        assert_eq!(a.v4.len(), 2);
        assert_eq!(
            a.del_v4(None, Some("10.1.2.3".parse().unwrap()), 24, None),
            Err(EADDRNOTAVAIL)
        );
        a.del_v4(Some(Ipv4Addr::LOCALHOST), None, 8, None).unwrap();
        assert!(!a.bindable4(Ipv4Addr::LOCALHOST));
        a.up();
        assert!(a.bindable4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn routes_take_linux_places_and_lookups() {
        let mut a = Addresses::first();
        // Down, a route through lo is `ENETDOWN`; host scope needs it not.
        a.down();
        assert_eq!(
            a.add_route4(&ask4("10.9.0.0", 16, 1, 0x600), false),
            Err(ENETDOWN)
        );
        a.up();
        // The same prefix: prepended, replaced, appended.
        let mut ask = ask4("10.9.0.0", 16, 1, 0x600);
        assert_eq!(
            told(&a.add_route4(&ask, true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0x600"]
        );
        assert_eq!(a.add_route4(&ask, true), Err(Errno::EEXIST));
        ask.request = F_CREATE | F_REPLACE;
        ask.scope = SCOPE_HOST;
        assert_eq!(
            told(&a.add_route4(&ask, true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0x100"]
        );
        assert_eq!(a.add_route4(&ask, true).unwrap(), []);
        ask.request = F_CREATE | F_APPEND;
        ask.scope = SCOPE_LINK;
        assert_eq!(
            told(&a.add_route4(&ask, true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0xc00"]
        );
        assert_eq!(a.add_route4(&ask, true), Err(Errno::EEXIST));
        ask.request = F_CREATE;
        ask.proto = 4;
        assert_eq!(
            told(&a.add_route4(&ask, true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0x400"]
        );
        let protos: Vec<_> = a
            .dump4()
            .iter()
            .filter(|r| r.len == 16)
            .map(|r| (r.proto, r.scope))
            .collect();
        assert_eq!(protos, [(4, SCOPE_LINK), (3, SCOPE_HOST), (3, SCOPE_LINK)]);
        // Removing takes the first that matches.
        let select = Select4 {
            table: TABLE_MAIN,
            dst: "10.9.0.0".parse().unwrap(),
            len: 16,
            tos: 0,
            priority: 0,
            kind: 0,
            proto: 3,
            scope: SCOPE_NOWHERE,
            prefsrc: None,
            gateway: None,
            oif: 0,
            metrics: Some(Vec::new()),
        };
        let gone = a.del_route4(&select).unwrap();
        assert!(matches!(gone[..], [Event::DelRoute4(r)] if r.scope == SCOPE_HOST));
        // A blackhole is EINVAL to a lookup, a throw route goes on to the
        // default table, and the longest prefix wins across the tables.
        a.add_route4(&ask4("10.6.0.0", 16, 6, 0x600), true).unwrap();
        a.add_route4(&ask4("10.3.0.0", 16, 9, 0x600), true).unwrap();
        let mut default = ask4("10.3.0.0", 16, 1, 0x600);
        default.table = TABLE_DEFAULT;
        a.add_route4(&default, true).unwrap();
        assert_eq!(a.lookup4("10.6.1.1".parse().unwrap()), Err(Errno::EINVAL));
        assert_eq!(
            a.lookup4("10.3.1.1".parse().unwrap()).unwrap().table,
            TABLE_DEFAULT
        );
        assert_eq!(a.lookup4("10.8.1.1".parse().unwrap()), Err(ENETUNREACH));
        assert_eq!(
            a.lookup4("127.0.0.1".parse().unwrap()).unwrap().kind,
            Kind::Local
        );
        // A local route makes its addresses the loopback's.
        let mut local = ask4("10.7.0.0", 16, 2, 0x600);
        local.table = TABLE_LOCAL;
        local.scope = SCOPE_HOST;
        local.oif = 1;
        a.add_route4(&local, true).unwrap();
        assert!(a.bindable4("10.7.1.1".parse().unwrap()));
        assert_eq!(
            a.source("10.7.1.1".parse().unwrap()),
            "10.7.1.1".parse::<IpAddr>().unwrap()
        );
        // Down: the routes of link scope go, the default table's too; host
        // scope and rejecting ones stay.
        a.down();
        let left: Vec<_> = a
            .dump4()
            .iter()
            .filter(|r| r.proto != PROTO_KERNEL)
            .map(short4)
            .collect();
        assert_eq!(
            left,
            [
                "254 10.3.0.0/16 Throw",
                "254 10.6.0.0/16 Blackhole",
                "255 10.7.0.0/16 Local",
            ]
        );
        // IPv6: by metric within a prefix, the walk's order across them.
        a.up();
        let ask6 = |dst: &str, len, metric| Ask6 {
            table: TABLE_MAIN,
            dst: dst.parse().unwrap(),
            len,
            kind: 1,
            proto: 3,
            metric,
            prefsrc: None,
            oif: 1,
            request: 0x600,
            metrics: Ok(NO_METRICS),
        };
        a.add_route6(&ask6("::", 0, 0), true).unwrap();
        a.add_route6(&ask6("2001:db8::", 64, 0), true).unwrap();
        a.add_route6(&ask6("2001:db8::", 64, 5), true).unwrap();
        a.add_route6(&ask6("2001:db8::", 48, 0), true).unwrap();
        assert_eq!(
            a.add_route6(&ask6("2001:db8::", 64, 5), true),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            a.dump6().iter().map(short6).collect::<Vec<_>>(),
            [
                "254 2001:db8::/64 Unicast 5",
                "254 2001:db8::/64 Unicast 1024",
                "254 2001:db8::/48 Unicast 1024",
                "254 ::/0 Unicast 1024",
                "255 ::1/128 Local 0",
            ]
        );
        let ip = "2001:db8::9".parse().unwrap();
        let via = a.lookup6(ip).unwrap();
        assert_eq!(
            (via.metric, a.source6(&via, ip)),
            (5, Some(Ipv6Addr::LOCALHOST))
        );
    }
}
