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
//! route and, from an up, a unicast prefix route in the main table, of its
//! priority or else metric 256. Addresses may have lifetimes, and run out
//! as [`Addresses::expire`] finds them.
//!
//! The local and main IPv4 tables are one trie, as Linux merges them while
//! there is no policy rule: a lookup takes the longest prefix of either,
//! then the default table's (253) where they have no answer. IPv6 looks in
//! the local table, then the main one. The other tables are kept and shown,
//! but no lookup reaches them.
use crate::netdev::{LOOPBACK_INDEX, LOOPBACK_OIF};
use crate::netlink::extack;
use core::cmp::{Ordering, Reverse};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use paludarium_types::Errno;

/// The `RTN_*` types of neighbours.
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BROADCAST: u8 = 3;
const RTN_MULTICAST: u8 = 5;
const ESRCH: Errno = Errno(3);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENETDOWN: Errno = Errno(100);
const ENETUNREACH: Errno = Errno(101);
const EHOSTUNREACH: Errno = Errno(113);
const EOPNOTSUPP: Errno = Errno(95);
/// `IFA_F_SECONDARY`, `IFA_F_NOPREFIXROUTE`, `IFA_F_PERMANENT` and
/// `IFA_F_DEPRECATED`.
pub(crate) const SECONDARY: u32 = 0x01;
pub(crate) const NO_PREFIX_ROUTE: u32 = 0x200;
pub(crate) const PERMANENT: u32 = 0x80;
pub(crate) const DEPRECATED: u32 = 0x20;
/// `IFA_F_NODAD`: an IPv6 address is never tentative.
const NO_DAD: u32 = 0x02;
/// The IPv6 address flags a request may set (`inet6_rtm_newaddr`):
/// `IFA_F_NODAD`, `IFA_F_HOMEADDRESS`, `IFA_F_MANAGETEMPADDR`,
/// `IFA_F_NOPREFIXROUTE` and `IFA_F_MCAUTOJOIN`; `IFA_F_OPTIMISTIC` too,
/// which goes again while `optimistic_dad` is 0.
pub(crate) const V6_ASKED: u32 = 0x02 | 0x10 | 0x100 | NO_PREFIX_ROUTE | 0x400;
/// The IPv6 address flags a change takes off before it puts the asked ones
/// on (`inet6_addr_modify`).
const V6_CHANGED: u32 = DEPRECATED | PERMANENT | 0x02 | 0x10 | 0x100 | NO_PREFIX_ROUTE;
/// `INFINITY_LIFE_TIME`: a lifetime that never ends.
pub(crate) const FOREVER: u32 = u32::MAX;
/// A second, in nanoseconds.
const SECOND: u64 = 1_000_000_000;
/// The scopes of addresses and routes (`RT_SCOPE_*`).
pub(crate) const SCOPE_UNIVERSE: u8 = 0;
pub(crate) const SCOPE_LINK: u8 = 253;
pub(crate) const SCOPE_HOST: u8 = 254;
pub(crate) const SCOPE_NOWHERE: u8 = 255;
/// The TOS bits a route's TOS is matched against
/// (`INET_DSCP_LEGACY_TOS_MASK`).
const TOS_LEGACY: u8 = 0x1c;
/// `IFAPROT_KERNEL_LO`: the kernel gave `::1` to the loopback.
pub(crate) const KERNEL_LO: u8 = 1;
/// `IFAPROT_KERNEL_LL`: the kernel made a device's link-local address.
pub(crate) const KERNEL_LL: u8 = 3;
/// How long duplicate address detection takes (`addrconf_dad_kick`,
/// `addrconf_dad_work`): a random delay of up to `rtr_solicit_delay` (1
/// second), taken here as half of it, then its one probe
/// (`dad_transmits`) and a retransmit time after it (1 second): 1.5
/// seconds, where Linux's take 1 to 2.
pub(crate) const DAD_TIME: u64 = SECOND + SECOND / 2;
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
/// `RTNH_F_DEAD` alone.
const NEXTHOP_DEAD_ONLY: u32 = 0x1;
/// `RTNH_F_LINKDOWN` alone.
const NEXTHOP_LINKDOWN: u32 = 0x10;
/// An IPv6 route's metric when its request names none
/// (`IP6_RT_PRIO_USER`), and an address's prefix route's
/// (`IP6_RT_PRIO_ADDRCONF`).
const METRIC_USER: u32 = 1024;
const METRIC_ADDRCONF: u32 = 256;

/// An IPv4 address of a device (Linux's `in_ifaddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V4 {
    /// The index of the device it is on (`ifa_dev`).
    pub index: i32,
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
    /// The metric of its prefix route (`IFA_RT_PRIORITY`).
    pub priority: u32,
    pub life: Life,
}
/// The lifetimes of an address, in seconds from when they were last set,
/// and when it was made and they were set, in nanoseconds of the
/// monotonic clock (`cstamp` and `tstamp`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Life {
    pub valid: u32,
    pub preferred: u32,
    pub created: u64,
    pub changed: u64,
}
impl Life {
    /// The whole seconds since its lifetimes were set, as `inet_fill_ifaddr`
    /// counts them.
    fn age(&self, now: u64) -> u32 {
        u32::try_from(now.saturating_sub(self.changed) / SECOND).unwrap_or(u32::MAX)
    }
    /// The seconds each has left at `now`, as `inet_fill_ifaddr` and
    /// `inet6_fill_ifaddr` tell them of an address that has one: none are
    /// taken from either when the preferred one never ends.
    pub(crate) fn left(&self, now: u64) -> (u32, u32) {
        if self.preferred == FOREVER {
            return (self.preferred, self.valid);
        }
        let age = self.age(now);
        let valid = if self.valid == FOREVER {
            FOREVER
        } else {
            self.valid.saturating_sub(age)
        };
        (self.preferred.saturating_sub(age), valid)
    }
    /// Whether at `now` it is as old as `lifetime` (which is not forever).
    /// Linux's work (`check_lifetime`, `addrconf_verify_rtnl`) is scheduled
    /// for the moment a lifetime ends, and counts an address a little
    /// older (`ADDRCONF_TIMER_FUZZ_MINUS`) only when it runs sooner for
    /// another, which no request here makes it do.
    fn reached(&self, lifetime: u32, now: u64) -> bool {
        lifetime != FOREVER && now.saturating_sub(self.changed) / SECOND >= u64::from(lifetime)
    }
}
/// The valid and preferred lifetimes a request asks an address to have
/// (`IFA_CACHEINFO`), which are forever when it names none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lifetimes {
    pub valid: u32,
    pub preferred: u32,
}
impl Lifetimes {
    pub(crate) const FOREVER: Self = Self {
        valid: FOREVER,
        preferred: FOREVER,
    };
}
impl V4 {
    /// An address the guest asks for on `lo`: `local`, `address` (its
    /// peer, or the same), `prefix` and `scope`.
    pub(crate) fn new(local: Ipv4Addr, address: Ipv4Addr, prefix: u8, scope: u8) -> Self {
        Self {
            index: LOOPBACK_INDEX,
            local,
            address,
            prefix,
            broadcast: None,
            scope,
            flags: 0,
            proto: 0,
            label: b"lo".to_vec(),
            priority: 0,
            life: Life::default(),
        }
    }
    /// Gives it `lifetimes` at `now`, as `set_ifa_lifetime` does: one that
    /// never ends makes it `IFA_F_PERMANENT`, and is not kept; a preferred
    /// one of 0 makes it `IFA_F_DEPRECATED`.
    fn set_life(&mut self, lifetimes: Lifetimes, now: u64) {
        self.flags &= !(PERMANENT | DEPRECATED);
        if lifetimes.valid == FOREVER {
            self.flags |= PERMANENT;
        } else {
            self.life.valid = lifetimes.valid;
        }
        if lifetimes.preferred != FOREVER {
            if lifetimes.preferred == 0 {
                self.flags |= DEPRECATED;
            }
            self.life.preferred = lifetimes.preferred;
        }
        self.life.changed = now;
    }
    /// The lifetimes it has left at `now`: forever while permanent.
    pub(crate) fn left(&self, now: u64) -> (u32, u32) {
        if self.flags & PERMANENT != 0 {
            (FOREVER, FOREVER)
        } else {
            self.life.left(now)
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
    /// Its device's index as a route's device names it.
    fn oif(&self) -> u32 {
        self.index.unsigned_abs()
    }
    /// The kind of its prefix route: local on the loopback
    /// (`IFF_LOOPBACK`), else unicast.
    fn prefix_kind(&self) -> Kind {
        if self.index == LOOPBACK_INDEX {
            Kind::Local
        } else {
            Kind::Unicast
        }
    }
    /// Whether `other` is in the same subnet of the same device, as a
    /// primary address and its secondaries are.
    fn same_subnet(&self, other: &Self) -> bool {
        self.index == other.index && self.mask() == other.mask() && self.covers(other.address)
    }
}
/// An IPv6 address of `lo` or a veth end (Linux's `inet6_ifaddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V6 {
    /// The index of its device.
    pub index: i32,
    pub address: Ipv6Addr,
    pub prefix: u8,
    pub flags: u32,
    pub proto: u8,
    /// The metric of its prefix route, 0 for `IP6_RT_PRIO_ADDRCONF`
    /// (`IFA_RT_PRIORITY`).
    pub priority: u32,
    pub life: Life,
    /// When its duplicate address detection is done, while it is
    /// tentative and that has begun (`addrconf_dad_work`).
    pub dad: Option<u64>,
}
impl V6 {
    /// A permanent address of `lo` that never ends, made at 0.
    pub(crate) fn new(address: Ipv6Addr, prefix: u8) -> Self {
        Self {
            index: LOOPBACK_INDEX,
            dad: None,
            address,
            prefix,
            flags: PERMANENT,
            proto: 0,
            priority: 0,
            life: Life {
                valid: FOREVER,
                preferred: FOREVER,
                created: 0,
                changed: 0,
            },
        }
    }
    /// Gives it `lifetimes` at `now`, as `inet6_rtm_newaddr` reads them: it
    /// is `IFA_F_PERMANENT` unless its valid one ends, and
    /// `IFA_F_DEPRECATED` with a preferred one of 0.
    fn set_life(&mut self, lifetimes: Lifetimes, now: u64) {
        self.flags |= PERMANENT;
        if lifetimes.valid != FOREVER {
            self.flags &= !PERMANENT;
        }
        if lifetimes.preferred == 0 {
            self.flags |= DEPRECATED;
        }
        self.life.valid = lifetimes.valid;
        self.life.preferred = lifetimes.preferred;
        self.life.changed = now;
    }
    /// The lifetimes it has left at `now`, as `inet6_fill_ifaddr`: forever
    /// while permanent with a preferred lifetime that never ends.
    pub(crate) fn left(&self, now: u64) -> (u32, u32) {
        if self.flags & PERMANENT != 0 && self.life.preferred == FOREVER {
            (FOREVER, FOREVER)
        } else {
            self.life.left(now)
        }
    }
    /// When a change gives its prefix route its lifetime
    /// (`modify_prefix_route`): never while it is permanent.
    fn expires(&self) -> Option<u64> {
        (self.flags & PERMANENT == 0)
            .then(|| self.life.changed + u64::from(self.life.valid) * SECOND)
    }
    /// Whether it is tentative (`IFA_F_TENTATIVE`): its detection not
    /// done.
    pub(crate) fn tentative(&self) -> bool {
        self.dad.is_some()
    }
    /// Its scope, as `ipv6_addr_scope` gives it.
    pub(crate) fn scope(&self) -> u8 {
        scope6(self.address)
    }
    fn covers(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) ^ u128::from(self.address)) & mask6(self.prefix) == 0
    }
    /// Its route in the local table, through its device.
    pub(crate) fn local_route(&self) -> Route6 {
        Route6 {
            oif: self.index.unsigned_abs(),
            table: TABLE_LOCAL,
            dst: self.address,
            len: 128,
            kind: Kind::Local,
            metric: 0,
            proto: PROTO_KERNEL,
            prefsrc: None,
            metrics: NO_METRICS,
            expires: None,
            linkdown: false,
            gateway: None,
            onlink: false,
            dead: false,
            weight: 1,
        }
    }
    /// Its prefix route in the main table (`addrconf_prefix_route`), which
    /// `::1`, the kernel's, has not: of its priority, or 256. It does not
    /// run out, whatever the address's lifetime: a route through a
    /// loopback to another address is a rejecting one, whose flags,
    /// `RTF_EXPIRES` among them, its making sets anew (`fib6_is_reject`).
    pub(crate) fn prefix_route(&self) -> Option<Route6> {
        (self.proto != KERNEL_LO && self.flags & NO_PREFIX_ROUTE == 0).then(|| Route6 {
            oif: self.index.unsigned_abs(),
            table: TABLE_MAIN,
            dst: self.prefix_of(),
            len: self.prefix,
            kind: Kind::Unicast,
            metric: self.metric(),
            proto: PROTO_KERNEL,
            prefsrc: None,
            metrics: NO_METRICS,
            expires: None,
            linkdown: false,
            gateway: None,
            onlink: false,
            dead: false,
            weight: 1,
        })
    }
    fn prefix_of(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.address) & mask6(self.prefix))
    }
    fn metric(&self) -> u32 {
        if self.priority == 0 {
            METRIC_ADDRCONF
        } else {
            self.priority
        }
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
/// An IPv4 route's prefix, as `rtm_to_fib_config` checks it: `EINVAL` for
/// a length past 32 or bits past it.
fn prefix4(dst: Ipv4Addr, len: u8) -> Result<(), Errno> {
    if len > 32 {
        return Err(extack::message(Errno::EINVAL, "Invalid prefix length"));
    }
    if u32::from(dst) & !mask4(len) != 0 {
        return Err(extack::message(
            Errno::EINVAL,
            "Invalid prefix for given prefix length",
        ));
    }
    Ok(())
}
fn mask6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}
/// The prefix route of the IPv4 address `address`, of its priority, as
/// `fib_add_ifaddr` and `fib_modify_prefix_metric` make it on a loopback:
/// none for the prefix 0, or a `/32` of its own address.
fn prefix_route4(address: &V4) -> Option<Route4> {
    let prefix = Ipv4Addr::from(u32::from(address.address) & address.mask());
    (!prefix.is_unspecified() && !(prefix == address.local && address.prefix == 32)).then(|| {
        Route4 {
            priority: address.priority,
            ..Route4::kernel(
                prefix,
                address.prefix,
                address.prefix_kind(),
                address.local,
                address.oif(),
            )
        }
    })
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
    /// The kernel's alone: IPv6's multicast route of each device
    /// (`addrconf_add_mroute`), which no request makes here.
    Multicast,
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
            Self::Multicast => 5,
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
/// Whether `route`'s next hops are those a removal's `RTA_MULTIPATH`
/// names, as `fib_nh_match` compares them: each in turn needs one of the
/// request's (those left over count for nothing), of its device where
/// that names one, of its gateway where that names one.
fn multipath_matches4(route: &Route4, hops: &[NextHop4]) -> bool {
    let own = route.next_hops();
    own.len() <= hops.len()
        && own.iter().zip(hops).all(|(nh, asked)| {
            (asked.oif == 0 || asked.oif == nh.oif)
                && asked.gateway.is_none_or(|g| nh.gateway == Some(g))
        })
}
/// One next hop of an IPv4 multipath route (a `fib_nh`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hop4 {
    pub gateway: Option<Ipv4Addr>,
    pub oif: u32,
    pub onlink: bool,
    pub linkdown: bool,
    /// `RTNH_F_DEAD`: its device went down (`fib_sync_down_dev`), which
    /// lookups pass over.
    pub dead: bool,
    pub uses_gateway: bool,
    /// `fib_nh_weight`: one past its `rtnh_hops`.
    pub weight: u16,
}
/// An IPv4 route (a `fib_alias` and its `fib_info`). Its next hop's
/// fields are its first's, or, as a lookup gives it, the one the lookup
/// took; a multipath route has all of them in `hops`, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The index of the device it goes through (`fib_nh_oif`); 0 for the
    /// kinds that reject, which have none.
    pub oif: u32,
    /// `RTNH_F_ONLINK`.
    pub onlink: bool,
    /// `RTNH_F_LINKDOWN`: its device, up, has no carrier, as
    /// `fib_check_nh_nongw` finds it and `fib_sync_down_dev` and
    /// `fib_sync_up` change it for `NETDEV_CHANGE`; a route of host scope
    /// (`RT_SCOPE_NOWHERE`'s next hop) is never so.
    pub linkdown: bool,
    /// Whether its gateway is reached by a route of link scope, so that a
    /// lookup's answer names it (`rt_uses_gateway`).
    pub uses_gateway: bool,
    /// Its `fib_info`'s metrics, which tell two routes apart as
    /// `fib_find_info` does.
    pub metrics: Metrics,
    /// Its next hop's weight (`fib_nh_weight`), as its other next hop
    /// fields: of its one next hop, or a multipath route's first, which
    /// `hops` has too, or in a lookup's answer of the hop it took; 1 but
    /// for one of an `RTA_MULTIPATH` of one next hop, whose weight tells
    /// it apart from another route (`nh_comp`).
    pub weight: u16,
    /// A multipath route's next hops, in order (`fib_nh`); none for one
    /// of a single next hop.
    pub hops: Vec<Hop4>,
    /// A multipath route's `fib_flags`: the request's `rtm_flags`, with
    /// `RTNH_F_LINKDOWN` and `RTNH_F_DEAD` as `fib_create_info`,
    /// `fib_sync_down_dev` and `fib_sync_up` set them for the whole.
    pub fib_flags: u32,
}
impl Route4 {
    /// Its next hops: those of a multipath route, else its one.
    pub(crate) fn next_hops(&self) -> Vec<Hop4> {
        if self.hops.is_empty() {
            vec![Hop4 {
                gateway: self.gateway,
                oif: self.oif,
                onlink: self.onlink,
                linkdown: self.linkdown,
                dead: false,
                uses_gateway: self.uses_gateway,
                weight: self.weight,
            }]
        } else {
            self.hops.clone()
        }
    }
    /// It, its next hop's fields `hop`'s (`res->nh_sel`).
    pub(crate) fn through(&self, hop: Hop4) -> Route4 {
        Route4 {
            gateway: hop.gateway,
            oif: hop.oif,
            onlink: hop.onlink,
            linkdown: hop.linkdown,
            uses_gateway: hop.uses_gateway,
            weight: hop.weight,
            ..self.clone()
        }
    }
    /// Whether `other` is the same route, as `fib_find_info` and `nh_comp`
    /// compare them: whatever their next hops' and its own
    /// `RTNH_F_DEAD` and `RTNH_F_LINKDOWN` (`RTNH_COMPARE_MASK`).
    fn same_info(&self, other: &Route4) -> bool {
        let masked = |r: &Route4| Route4 {
            linkdown: false,
            fib_flags: r.fib_flags & !NEXTHOP_DEAD,
            hops: r
                .hops
                .iter()
                .map(|h| Hop4 {
                    dead: false,
                    linkdown: false,
                    ..*h
                })
                .collect(),
            ..r.clone()
        };
        masked(self) == masked(other)
    }
    /// Its next hop's fields back to its first's, once `hops` changed.
    fn first_again(&mut self) {
        if let Some(&first) = self.hops.first() {
            *self = self.through(first);
        }
    }
}
impl Route4 {
    /// One of the kernel's routes for an address through the device of
    /// `oif`, with the preferred source `source`, as `fib_magic` makes it:
    /// a unicast one in the main table, of link scope; the others in the
    /// local table, a local one of host scope, a broadcast one of link
    /// scope.
    fn kernel(dst: Ipv4Addr, len: u8, kind: Kind, source: Ipv4Addr, oif: u32) -> Self {
        Self {
            table: if kind == Kind::Unicast {
                TABLE_MAIN
            } else {
                TABLE_LOCAL
            },
            dst,
            len,
            tos: 0,
            priority: 0,
            kind,
            proto: PROTO_KERNEL,
            scope: if kind == Kind::Local {
                SCOPE_HOST
            } else {
                SCOPE_LINK
            },
            prefsrc: Some(source),
            gateway: None,
            oif,
            onlink: false,
            linkdown: false,
            uses_gateway: false,
            metrics: NO_METRICS,
            weight: 1,
            hops: Vec::new(),
            fib_flags: 0,
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
/// An IPv6 route (a `fib6_info`), through `lo` or a veth end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route6 {
    /// The index of the device it goes through (`fib6_nh_dev`).
    pub oif: u32,
    pub table: u32,
    pub dst: Ipv6Addr,
    pub len: u8,
    pub kind: Kind,
    pub metric: u32,
    pub proto: u8,
    pub prefsrc: Option<Ipv6Addr>,
    /// Its `fib6_metrics`.
    pub metrics: Metrics,
    /// When it runs out (`RTF_EXPIRES`), in nanoseconds of the monotonic
    /// clock.
    pub expires: Option<u64>,
    /// `RTNH_F_LINKDOWN`: its device, up, has no carrier, as
    /// `fib6_nh_init` finds it for any but a local route and
    /// `rt6_sync_down_dev` and `rt6_sync_up` change it, without a word.
    pub linkdown: bool,
    /// Its next hop's address (`fib_nh_gw6`), which a rejecting route has
    /// not.
    pub gateway: Option<Ipv6Addr>,
    /// `RTNH_F_ONLINK`: the gateway is taken to be on its device's link.
    pub onlink: bool,
    /// `RTNH_F_DEAD`: a multipath sibling whose device went down
    /// (`fib6_ifdown`), which lookups pass over, until the device is
    /// ready again (`rt6_sync_up`).
    pub dead: bool,
    /// Its weight among a multipath route's hops (`fib_nh_weight`): 1,
    /// or one past the `rtnh_hops` of its `RTA_MULTIPATH` next hop.
    pub weight: u16,
}
/// Whether an IPv6 route may be a multipath sibling
/// (`rt6_qualify_for_ecmp`): one with a gateway, which none of the
/// kernel's has here.
fn ecmp6(route: &Route6) -> bool {
    route.gateway.is_some()
}
impl Route6 {
    /// Whether `other` is of the same multipath route as this one: of its
    /// table, prefix and metric, both with a gateway.
    fn sibling_of(&self, other: &Route6) -> bool {
        ecmp6(self)
            && ecmp6(other)
            && self.table == other.table
            && self.dst == other.dst
            && self.len == other.len
            && self.metric == other.metric
    }
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
    /// A multipath route told of in one message, its next hops in the
    /// order of its `RTA_MULTIPATH` ([`Addresses::hops6`]).
    NewMultipath6(Vec<Route6>, u16),
    DelMultipath6(Vec<Route6>),
    /// A neighbour a request changed, told of as `__neigh_update` does,
    /// naming the request's port.
    NewNeighbour(Neighbour),
    DelNeighbour(Neighbour),
}
/// A neighbour of the loopback or of a veth end, as `___neigh_create`
/// makes one for the next hop of a packet out through it, or for a
/// request (`RTM_NEWNEIGH`). On a loopback each is made `NUD_NOARP` with
/// the device's address, all zeros: IPv4's one entry is keyed by
/// `0.0.0.0` (`arp_constructor` keys a loopback's so, whatever is asked),
/// of type `RTN_BROADCAST` (`inet_addr_type` of it); IPv6's are keyed by
/// each next hop, of type `RTN_LOCAL`, or `RTN_MULTICAST` for a multicast
/// one (`ndisc_constructor`). A veth end's are keyed by the address
/// asked and resolved by ARP ([`Neighbour::arp`]) or, for IPv6, by
/// neighbour discovery ([`Neighbour::nd`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Neighbour {
    /// The index of its device.
    pub index: i32,
    pub ip: IpAddr,
    /// The `RTN_*` type.
    pub kind: u8,
    /// When it was made.
    pub made: u64,
    /// Its `NUD_*` state.
    pub state: u8,
    /// Its `NTF_*` flags, the extended ones shifted by 8
    /// (`NTF_EXT_SHIFT`), as `neigh->flags` has them.
    pub flags: u32,
    /// Its link-layer address, shown while its state is valid.
    pub lladdr: [u8; 6],
    /// The protocol a request gave it (`NDA_PROTOCOL`), 0 for none.
    pub protocol: u8,
    /// Its probes (`NDA_PROBES`).
    pub probes: u32,
    /// When it was last used and updated, as a loopback's output
    /// (`neigh_connected_output`) changes neither.
    pub used: u64,
    pub updated: u64,
    /// When it was confirmed: at `confirmed`, or, with `unconfirmed`, two
    /// base reachable times (60 seconds) before it, as `neigh_alloc` and a
    /// new link-layer address set it.
    pub confirmed: u64,
    pub unconfirmed: bool,
    /// Whether its timer is pending, which holds a reference to it
    /// (`neigh_add_timer`): one that a state of `NUD_REACHABLE`,
    /// `NUD_DELAY` or `NUD_PROBE` sets. Only a reachable one's runs here
    /// ([`Self::age`]); a veth end's all run ([`Self::arp_timer`]).
    pub timer: bool,
    /// Whether the peer answers the probe a veth end's neighbour sends
    /// once its delay is over, as found when it began to delay.
    pub answers: bool,
}
/// The `NUD_*` states.
pub(crate) const NUD_INCOMPLETE: u8 = 0x01;
pub(crate) const NUD_REACHABLE: u8 = 0x02;
pub(crate) const NUD_STALE: u8 = 0x04;
pub(crate) const NUD_DELAY: u8 = 0x08;
pub(crate) const NUD_PROBE: u8 = 0x10;
pub(crate) const NUD_FAILED: u8 = 0x20;
pub(crate) const NUD_NOARP: u8 = 0x40;
pub(crate) const NUD_PERMANENT: u8 = 0x80;
/// `NUD_VALID` and `NUD_CONNECTED`.
pub(crate) const NUD_VALID: u8 =
    NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY;
const NUD_CONNECTED: u8 = NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE;
/// The `NTF_*` flags a neighbour keeps, the extended ones shifted by 8.
pub(crate) const NTF_USE: u32 = 0x01;
pub(crate) const NTF_EXT_LEARNED: u32 = 0x10;
pub(crate) const NTF_ROUTER: u32 = 0x80;
pub(crate) const NTF_MANAGED: u32 = 0x100;
pub(crate) const NTF_EXT_VALIDATED: u32 = 0x400;
/// `NLM_F_REPLACE`, `NLM_F_EXCL` and `NLM_F_CREATE`.
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
/// A neighbour table's reachable time, its base one (`REACHABLE_TIME`,
/// 30 seconds), and its delay before a probe (`DELAY_PROBE_TIME`, 5
/// seconds).
const REACHABLE_TIME: u64 = 30 * SECOND;
const DELAY_PROBE_TIME: u64 = 5 * SECOND;
/// `ENOBUFS`.
const ENOBUFS: Errno = Errno(105);
/// A neighbour a request adds or changes (`RTM_NEWNEIGH`), as `neigh_add`
/// reads it, for `lo`: its key as asked, its state, flags (the extended
/// ones shifted by 8), link-layer address (its first six bytes, or none),
/// protocol (0 for none), and the request's `NLM_F_*`; and whether its
/// device has no IPv6 (`in6_dev`), where `ndisc_constructor` makes no
/// IPv6 neighbour.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NeighbourAsk {
    pub ip: IpAddr,
    pub state: u8,
    pub flags: u32,
    pub lladdr: Option<[u8; 6]>,
    pub protocol: u8,
    pub request: u16,
    pub no_inet6: bool,
}
/// A proxy entry (`struct pneigh_entry`): one for `lo` (`device`) or for
/// no device, with the flags (the extended ones shifted by 8) and
/// protocol its last request gave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Proxy {
    pub ip: IpAddr,
    pub device: bool,
    pub flags: u32,
    pub protocol: u8,
    pub permanent: bool,
}
impl Proxy {
    /// Its bucket of `pneigh_hash`, which folds the last four bytes of its
    /// key as the CPU loads them.
    fn bucket(&self) -> u32 {
        let last = match self.ip {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(ip) => {
                let o = ip.octets();
                [o[12], o[13], o[14], o[15]]
            }
        };
        let mut hash = u32::from_le_bytes(last);
        hash ^= hash >> 16;
        hash ^= hash >> 8;
        hash ^= hash >> 4;
        hash & 0xf
    }
}
/// What a change of a neighbour (`__neigh_update`) is asked to do, its
/// `NEIGH_UPDATE_F_*`; every one here is an administrator's.
#[derive(Clone, Copy, Debug, Default)]
struct Update {
    override_: bool,
    override_router: bool,
    learned: bool,
    router: bool,
    managed: bool,
    use_: bool,
    validated: bool,
}
impl Neighbour {
    /// A neighbour as `___neigh_create` makes it for the loopback at
    /// `now` with `flags`: `NUD_NOARP`, `lo`'s address, never confirmed.
    fn new(ip: IpAddr, flags: u32, now: u64) -> Self {
        let kind = match ip {
            IpAddr::V4(_) => RTN_BROADCAST,
            IpAddr::V6(ip) if ip.is_multicast() => RTN_MULTICAST,
            IpAddr::V6(_) => RTN_LOCAL,
        };
        Self {
            index: LOOPBACK_INDEX,
            ip,
            kind,
            made: now,
            state: NUD_NOARP,
            flags,
            lladdr: [0; 6],
            protocol: 0,
            probes: 0,
            used: now,
            updated: now,
            confirmed: now,
            unconfirmed: true,
            timer: false,
            answers: false,
        }
    }
    /// A neighbour of the veth end `index` keyed by `ip`, of the `RTN_*`
    /// type `kind` (`inet_addr_type_dev_table`), as `arp_constructor`
    /// makes it at `now` with `flags`: a multicast one `NUD_NOARP` with its
    /// group's Ethernet address (`ip_eth_mc_map`), a broadcast one
    /// `NUD_NOARP` with the broadcast address, any other `NUD_NONE` for
    /// ARP to resolve.
    fn arp(index: i32, ip: Ipv4Addr, kind: u8, flags: u32, now: u64) -> Self {
        let o = ip.octets();
        let (state, lladdr) = match kind {
            RTN_MULTICAST => (NUD_NOARP, [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]),
            RTN_BROADCAST => (NUD_NOARP, [0xff; 6]),
            _ => (0, [0; 6]),
        };
        Self {
            index,
            kind,
            state,
            lladdr,
            ..Self::new(IpAddr::V4(ip), flags, now)
        }
    }
    /// A neighbour of the veth end `index` keyed by `ip`, as
    /// `ndisc_constructor` makes it at `now` with `flags`: a multicast one
    /// `NUD_NOARP`, of type `RTN_MULTICAST`, with its group's Ethernet
    /// address (`ndisc_mc_map`), any other `NUD_NONE`, of type
    /// `RTN_UNICAST`, for neighbour discovery to resolve.
    fn nd(index: i32, ip: Ipv6Addr, flags: u32, now: u64) -> Self {
        let o = ip.octets();
        let (kind, state, lladdr) = if ip.is_multicast() {
            (
                RTN_MULTICAST,
                NUD_NOARP,
                [0x33, 0x33, o[12], o[13], o[14], o[15]],
            )
        } else {
            (RTN_UNICAST, 0, [0; 6])
        };
        Self {
            index,
            kind,
            state,
            lladdr,
            ..Self::new(IpAddr::V6(ip), flags, now)
        }
    }
    /// `__neigh_update` with `lladdr` (or none) to state `new` at `now`:
    /// whether it is told of, and its error. The flags it is asked for
    /// come first (`neigh_update_flags`); `NTF_USE` and `NTF_MANAGED` only
    /// take `NUD_PERMANENT` away; an invalid state is taken as it is; a
    /// valid one needs an address, given or had while valid (`EINVAL`),
    /// and without `override_` a new one changes nothing. Last, with
    /// `override_router`, `NTF_ROUTER` becomes what `router` asks.
    fn update(
        &mut self,
        lladdr: Option<[u8; 6]>,
        new: u8,
        f: Update,
        now: u64,
    ) -> (bool, Result<(), Errno>) {
        let old = self.state;
        let mut told = false;
        let want = (if f.learned { NTF_EXT_LEARNED } else { 0 })
            | (if f.managed { NTF_MANAGED } else { 0 })
            | (if f.validated { NTF_EXT_VALIDATED } else { 0 });
        for bit in [NTF_EXT_LEARNED, NTF_MANAGED, NTF_EXT_VALIDATED] {
            if (self.flags ^ want) & bit != 0 {
                self.flags ^= bit;
                told = true;
            }
        }
        if f.use_ || f.managed {
            self.state = old & !NUD_PERMANENT;
            return (told, Ok(()));
        }
        if new & NUD_VALID == 0 {
            self.timer = false;
            self.state = new;
            // An assignment in Linux: what the flags told is lost.
            told = old & NUD_VALID != 0
                || (old & (NUD_INCOMPLETE | NUD_PROBE) != 0 && new & NUD_FAILED != 0);
            return (told, Ok(()));
        }
        // Whether the address is a new one, which Linux tells by its
        // pointer: one given, unless the same as that of a valid state.
        let fresh = match lladdr {
            Some(given) => !(old & NUD_VALID != 0 && given == self.lladdr),
            None if old & NUD_VALID == 0 => {
                return (
                    told,
                    Err(extack::message(
                        Errno::EINVAL,
                        "No link layer address given",
                    )),
                );
            }
            None => false,
        };
        if new & NUD_CONNECTED != 0 {
            self.confirmed = now;
            self.unconfirmed = false;
        }
        let mut router = f.override_router;
        if old & NUD_VALID != 0 && fresh && !f.override_ {
            router = false;
        } else {
            if new != old || fresh {
                self.updated = now;
            }
            if new != old {
                self.timer = new & (NUD_REACHABLE | NUD_DELAY | NUD_PROBE) != 0;
                if new & NUD_PROBE != 0 {
                    self.probes = 0;
                }
                self.state = new;
                told = true;
            }
            if fresh {
                self.lladdr = lladdr.unwrap_or_default();
                if new & NUD_CONNECTED == 0 {
                    self.confirmed = now;
                    self.unconfirmed = true;
                }
                told = true;
            }
        }
        if router && (self.flags & NTF_ROUTER != 0) != f.router {
            self.flags ^= NTF_ROUTER;
            told = true;
        }
        (told, Ok(()))
    }
    /// `neigh_timer_handler` for a reachable neighbour by `now`: when its
    /// reachable time since it was confirmed has passed, it delays if it
    /// was used within the delay before a probe of that moment, untold,
    /// and its timer stays (but never runs here); otherwise it is stale,
    /// without a timer. When it went stale, which is told of.
    fn age(&mut self, now: u64) -> Option<u64> {
        if self.state & NUD_REACHABLE == 0 || !self.timer {
            return None;
        }
        let confirmed = if self.unconfirmed {
            self.confirmed.saturating_sub(2 * REACHABLE_TIME)
        } else {
            self.confirmed
        };
        let at = confirmed + REACHABLE_TIME;
        if now <= at {
            return None;
        }
        self.updated = at;
        if at <= self.used + DELAY_PROBE_TIME {
            self.state = NUD_DELAY;
            // A veth end's peer answered while it was reachable.
            self.answers = true;
            return None;
        }
        self.state = NUD_STALE;
        self.timer = false;
        Some(at)
    }
    /// `neigh_event_send` at `now`, which a request with `NTF_USE` or
    /// `NTF_MANAGED` makes: it is used; one connected, delaying or probing
    /// stays so; one stale delays; any other but an incomplete one becomes
    /// incomplete and sends its first probe (`neigh_probe`), its unicast
    /// probes (3) and that one counted. Its timer never runs here, so it
    /// neither probes again nor fails.
    fn event(&mut self, now: u64) {
        self.used = now;
        if self.state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE) != 0 {
            return;
        }
        if self.state & (NUD_STALE | NUD_INCOMPLETE) == 0 {
            self.probes = 4;
            self.state = NUD_INCOMPLETE;
            self.updated = now;
            self.timer = true;
        } else if self.state & NUD_STALE != 0 {
            self.state = NUD_DELAY;
            self.updated = now;
            self.timer = true;
        }
    }
    /// `neigh_timer_handler` for a veth end's neighbour by `now`, which
    /// probes once a second (`retrans_time`): an incomplete one, its
    /// unicast and multicast probes (6) sent, fails 3 seconds after its
    /// first; a delaying one, 5 seconds on (`delay_probe_time`), is
    /// reachable if it was confirmed meanwhile, else probes: its unicast
    /// probe is answered, and it is reachable, or it fails after 3 of them
    /// (one `NTF_EXT_VALIDATED` is stale instead).
    /// Each change but to an incomplete one is told of, with its time; the
    /// probes sent so far count meanwhile.
    fn arp_timer(&mut self, now: u64) -> Vec<(u64, Self)> {
        let mut told = Vec::new();
        if !self.timer || self.index == LOOPBACK_INDEX {
            return told;
        }
        let sent =
            |since: u64| u32::try_from(now.saturating_sub(since) / SECOND).unwrap_or(u32::MAX);
        if self.state & NUD_DELAY != 0 {
            let at = self.updated + DELAY_PROBE_TIME;
            if now < at {
                return told;
            }
            self.updated = at;
            if !self.unconfirmed && at <= self.confirmed + DELAY_PROBE_TIME {
                self.state = NUD_REACHABLE;
                told.push((at, *self));
                return told;
            }
            self.state = NUD_PROBE;
            self.probes = 0;
            told.push((at, *self));
            self.probes = 1;
            if self.answers {
                self.state = NUD_REACHABLE;
                self.confirmed = at;
                self.unconfirmed = false;
                told.push((at, *self));
                return told;
            }
        }
        if self.state & NUD_PROBE != 0 {
            let at = self.updated + 3 * SECOND;
            if now < at {
                self.probes = 1 + sent(self.updated).min(2);
                return told;
            }
            self.probes = 3;
            self.state = if self.flags & NTF_EXT_VALIDATED != 0 {
                NUD_STALE
            } else {
                NUD_FAILED
            };
            self.timer = false;
            self.updated = at;
            told.push((at, *self));
        } else if self.state & NUD_INCOMPLETE != 0 {
            let at = self.updated + 3 * SECOND;
            if now < at {
                self.probes = 4 + sent(self.updated).min(2);
                return told;
            }
            self.probes = 6;
            self.state = NUD_FAILED;
            self.timer = false;
            self.updated = at;
            told.push((at, *self));
        }
        told
    }
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
    /// Whether the namespace has a device of `oif`.
    pub device: bool,
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
    /// The next hops of its `RTA_MULTIPATH` (`fib_nh_match`), as a
    /// request gives them: none where it has none.
    pub multipath: Option<Vec<NextHop4>>,
}
/// A next hop of an IPv4 request's `RTA_MULTIPATH` (`struct rtnexthop`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct NextHop4 {
    /// Its `rtnh_flags`.
    pub flags: u32,
    /// One past its `rtnh_hops`.
    pub weight: u16,
    /// Its `rtnh_ifindex`, and whether the namespace has a device of it.
    pub oif: u32,
    pub device: bool,
    /// Its `RTA_GATEWAY`.
    pub gateway: Option<Ipv4Addr>,
}
/// An IPv4 request's `RTA_MULTIPATH` to add, as `fib_create_info` takes
/// it: whether `fib_count_nexthops` found them all, then its next hops or
/// the error reading them gave (`fib_get_nhs`), which come after the
/// metrics'.
#[derive(Clone, Debug)]
pub(crate) struct Multipath4 {
    pub counted: Result<(), Errno>,
    pub hops: Result<Vec<NextHop4>, Errno>,
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
    /// Its gateway (`RTA_GATEWAY`), and whether it is on link
    /// (`RTNH_F_ONLINK`).
    pub gateway: Option<Ipv6Addr>,
    pub onlink: bool,
    /// Whether the namespace has a device of `oif`.
    pub device: bool,
    /// That device's IPv6 (`inet6_dev`): `None` where it has none (a veth
    /// end made with an MTU below 1280), else whether it is off
    /// (`disable_ipv6`).
    pub ipv6_off: Option<bool>,
    pub request: u16,
    /// Its metrics to add, or the error converting them gave, which comes
    /// once its table is made; a removal does not look at them.
    pub metrics: Result<Metrics, Errno>,
}

/// What a multipath route's hop is chosen by (`rt6_multipath_hash`, of
/// `fib_multipath_hash_policy` 0): the flow's source, flow label and
/// protocol, with its destination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flow6 {
    pub src: Option<Ipv6Addr>,
    pub label: u32,
    pub proto: u8,
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
    /// Whether a request has added an IPv4 local route
    /// (`fib_has_custom_local_routes`), which is never cleared: a packet's
    /// source is then checked by a lookup of it
    /// ([`Self::valid_source4`]).
    custom_local4: bool,
    /// The devices, up, without their carrier (`netif_carrier_ok`), by the
    /// index a route names them by: the routes through them are
    /// `RTNH_F_LINKDOWN`.
    no_carrier: Vec<u32>,
    /// The latest time [`Self::expire`] was called at, in nanoseconds of
    /// the monotonic clock: a netlink request's, which a device going
    /// tells its addresses' lifetimes by.
    seen: u64,
    /// The neighbours of the loopback and of each veth end, the oldest first.
    neighbours: Vec<Neighbour>,
    /// The proxy entries of the namespace, the oldest first.
    proxies: Vec<Proxy>,
    /// The veth ends IPv6 has made ready (`IF_READY`), up with their
    /// carrier, by index.
    ready6: Vec<i32>,
    /// The namespace's key for the hash that chooses among a multipath
    /// route's hops, random as Linux's `mp_seed` is where no
    /// `fib_multipath_hash_seed` is set.
    multipath_seed: std::hash::RandomState,
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
        let _ = addresses.up(0, true);
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
            custom_local4: false,
            no_carrier: Vec::new(),
            seen: 0,
            neighbours: Vec::new(),
            proxies: Vec::new(),
            ready6: Vec::new(),
            multipath_seed: std::hash::RandomState::new(),
        }
    }
    /// A packet goes out through the loopback to `next` at `now`, as
    /// `ip_finish_output2` and `ip6_finish_output2` look its next hop's
    /// neighbour up, or make it, silently.
    pub(crate) fn output(&mut self, next: IpAddr, now: u64) {
        let (ip, kind) = match next {
            IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), RTN_BROADCAST),
            IpAddr::V6(ip) if ip.is_multicast() => (next, RTN_MULTICAST),
            IpAddr::V6(_) => (next, RTN_LOCAL),
        };
        if !self
            .neighbours
            .iter()
            .any(|n| n.index == LOOPBACK_INDEX && n.ip == ip)
        {
            let mut neighbour = Neighbour::new(ip, 0, now);
            neighbour.kind = kind;
            self.neighbours.push(neighbour);
        }
    }
    /// Adds or changes a neighbour of the device of `index`, `lo` or a veth
    /// end, at `now`, as `neigh_add` does once it has found the device and
    /// table and checked the key: what is told of, and the error. One is
    /// looked up by the key asked, which for IPv4 on `lo` finds only
    /// `0.0.0.0`'s; `EEXIST` for it with `NLM_F_EXCL`, and without
    /// `NLM_F_REPLACE` a new address changes nothing. Else `NLM_F_CREATE`
    /// makes one (`ENOENT` without): on `lo` IPv4's is `0.0.0.0`'s, which
    /// may be there already, and on a veth end it is made as ARP's or
    /// neighbour discovery's ([`Self::on_end`]), which makes no IPv6 one
    /// on a device without IPv6 (`EINVAL`); `EINVAL` for a permanent one
    /// `NTF_MANAGED`. One made stays when the change then fails. `NTF_EXT_VALIDATED` needs a valid state, the
    /// one it has for `NTF_USE` and `NTF_MANAGED` (`EINVAL`). Then
    /// [`Neighbour::update`], and for those two, [`Neighbour::event`].
    pub(crate) fn add_neighbour(
        &mut self,
        index: i32,
        ask: NeighbourAsk,
        now: u64,
    ) -> (Vec<Event>, Result<(), Errno>) {
        let flags = ask.flags;
        let using = flags & (NTF_USE | NTF_MANAGED) != 0;
        let mut f = Update {
            override_: true,
            override_router: true,
            learned: flags & NTF_EXT_LEARNED != 0,
            router: flags & NTF_ROUTER != 0,
            managed: flags & NTF_MANAGED != 0,
            use_: flags & NTF_USE != 0,
            validated: flags & NTF_EXT_VALIDATED != 0,
        };
        let device = index;
        let index = if let Some(i) = self
            .neighbours
            .iter()
            .position(|n| n.index == device && n.ip == ask.ip)
        {
            if ask.request & NLM_F_EXCL != 0 {
                return (Vec::new(), Err(Errno::EEXIST));
            }
            if flags & NTF_EXT_VALIDATED != 0 {
                let state = if using {
                    self.neighbours[i].state & !NUD_PERMANENT
                } else {
                    ask.state
                };
                if state & NUD_VALID == 0 {
                    return (
                        Vec::new(),
                        Err(extack::message(
                            Errno::EINVAL,
                            "Cannot mark neighbor as externally validated with an invalid state",
                        )),
                    );
                }
            }
            if ask.request & NLM_F_REPLACE == 0 {
                f.override_ = false;
                f.override_router = false;
            }
            i
        } else {
            if ask.request & NLM_F_CREATE == 0 {
                return (Vec::new(), Err(Errno::ENOENT));
            }
            if ask.state & NUD_PERMANENT != 0 && flags & NTF_MANAGED != 0 {
                return (
                    Vec::new(),
                    Err(extack::message(
                        Errno::EINVAL,
                        "Invalid NTF_* flag for permanent entry",
                    )),
                );
            }
            if flags & NTF_EXT_VALIDATED != 0 {
                let state = if using { 0 } else { ask.state };
                if state & NUD_VALID == 0 {
                    return (
                        Vec::new(),
                        Err(extack::message(
                            Errno::EINVAL,
                            "Cannot create externally validated neighbor with an invalid state",
                        )),
                    );
                }
            }
            let kept = flags & (NTF_EXT_LEARNED | NTF_MANAGED | NTF_EXT_VALIDATED);
            match ask.ip {
                IpAddr::V6(_) if ask.no_inet6 => return (Vec::new(), Err(Errno::EINVAL)),
                ip if device != LOOPBACK_INDEX => {
                    let made = self.on_end(device, ip, kept, now);
                    self.neighbours.push(made);
                    self.neighbours.len() - 1
                }
                _ => {
                    let ip = match ask.ip {
                        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        ip => ip,
                    };
                    match self
                        .neighbours
                        .iter()
                        .position(|n| n.index == device && n.ip == ip)
                    {
                        Some(i) => i,
                        None => {
                            self.neighbours.push(Neighbour::new(ip, kept, now));
                            self.neighbours.len() - 1
                        }
                    }
                }
            }
        };
        let n = &mut self.neighbours[index];
        if ask.protocol != 0 {
            n.protocol = ask.protocol;
        }
        let (told, result) = n.update(ask.lladdr, ask.state, f, now);
        let events = if told {
            vec![Event::NewNeighbour(*n)]
        } else {
            Vec::new()
        };
        if result.is_ok() && using {
            n.event(now);
        }
        (events, result)
    }
    /// Removes the neighbour of the device of `index` keyed by `ip`, as
    /// `neigh_delete` does: `ENOENT` for none (on `lo`, IPv4's only by
    /// `0.0.0.0`). It fails first (`NUD_FAILED`, told of if it was valid),
    /// then goes, told of with `RTM_DELNEIGH` (`neigh_remove_one`).
    pub(crate) fn delete_neighbour(
        &mut self,
        index: i32,
        ip: IpAddr,
        now: u64,
    ) -> Result<Vec<Event>, Errno> {
        let Some(index) = self
            .neighbours
            .iter()
            .position(|n| n.index == index && n.ip == ip)
        else {
            return Err(Errno::ENOENT);
        };
        let mut n = self.neighbours.remove(index);
        let f = Update {
            override_: true,
            ..Update::default()
        };
        let (told, _) = n.update(None, NUD_FAILED, f, now);
        let mut events = Vec::new();
        if told {
            events.push(Event::NewNeighbour(n));
        }
        events.push(Event::DelNeighbour(n));
        Ok(events)
    }
    /// Adds or changes a proxy entry, as `pneigh_create` does: the one of
    /// `ip` for `lo` or for no device changes, if there is one, else one
    /// is made, which for IPv6 needs a device (`ENOBUFS`, as
    /// `pndisc_constructor` refuses). Nothing is told.
    pub(crate) fn add_proxy(&mut self, new: Proxy) -> Result<(), Errno> {
        let found = self
            .proxies
            .iter()
            .rposition(|p| p.ip == new.ip && (p.device == new.device || !p.device));
        match found {
            Some(i) => {
                let p = &mut self.proxies[i];
                p.flags = new.flags;
                p.permanent = new.permanent;
                if new.protocol != 0 {
                    p.protocol = new.protocol;
                }
            }
            None if new.ip.is_ipv6() && !new.device => return Err(ENOBUFS),
            None => self.proxies.push(new),
        }
        Ok(())
    }
    /// Removes the proxy entry of `ip` for `lo` (`device`) or for no
    /// device, which must be the one it has (`pneigh_delete`): `ENOENT`
    /// for none.
    pub(crate) fn delete_proxy(&mut self, ip: IpAddr, device: bool) -> Result<(), Errno> {
        let Some(i) = self
            .proxies
            .iter()
            .position(|p| p.ip == ip && p.device == device)
        else {
            return Err(Errno::ENOENT);
        };
        self.proxies.remove(i);
        Ok(())
    }
    /// The proxy entries of a family, in the order of their hash's
    /// buckets, the newest first in each, as `pneigh_dump_table` goes
    /// through them.
    pub(crate) fn proxies(&self, v6: bool) -> Vec<Proxy> {
        let mut proxies: Vec<Proxy> = self
            .proxies
            .iter()
            .rev()
            .filter(|p| p.ip.is_ipv6() == v6)
            .copied()
            .collect();
        proxies.sort_by_key(Proxy::bucket);
        proxies
    }
    /// The proxy entry `pneigh_lookup` finds for `ip` on `lo` (`device`)
    /// or no device: the first in its bucket that is for that device or
    /// for none.
    pub(crate) fn proxy(&self, ip: IpAddr, device: bool) -> Option<Proxy> {
        self.proxies(ip.is_ipv6())
            .into_iter()
            .find(|p| p.ip == ip && (p.device == device || !p.device))
    }
    /// The latest time [`Self::expire`] was called at.
    pub(crate) fn seen(&self) -> u64 {
        self.seen
    }
    /// The neighbours of every device, the oldest first.
    pub(crate) fn neighbours(&self) -> &[Neighbour] {
        &self.neighbours
    }
    /// What `inet_addr_type` makes of `ip`: broadcast for `0.0.0.0` and
    /// the limited broadcast address, multicast for a group, else the type
    /// of what the local table has for it ([`Self::addr_type4`]).
    pub(crate) fn inet_addr_type4(&self, ip: Ipv4Addr) -> u8 {
        if ip.is_unspecified() || ip.is_broadcast() {
            RTN_BROADCAST
        } else if ip.is_multicast() {
            RTN_MULTICAST
        } else {
            self.addr_type4(ip, TABLE_LOCAL).code()
        }
    }
    /// A neighbour of the veth end `index` keyed by `ip`, made at `now`
    /// with `flags` as ARP makes one ([`Neighbour::arp`], of the type
    /// `inet_addr_type_dev_table` gives its key, [`Self::inet_addr_type4`])
    /// or, for IPv6, neighbour discovery ([`Neighbour::nd`]).
    fn on_end(&self, index: i32, ip: IpAddr, flags: u32, now: u64) -> Neighbour {
        match ip {
            IpAddr::V4(ip) => Neighbour::arp(index, ip, self.inet_addr_type4(ip), flags, now),
            IpAddr::V6(ip) => Neighbour::nd(index, ip, flags, now),
        }
    }
    /// The neighbour of the veth end `index` keyed by `ip`, made at `now`
    /// if there is none ([`Self::on_end`]): its place.
    fn end_neighbour(&mut self, index: i32, ip: IpAddr, now: u64) -> usize {
        if let Some(i) = self
            .neighbours
            .iter()
            .position(|n| n.index == index && n.ip == ip)
        {
            return i;
        }
        let made = self.on_end(index, ip, 0, now);
        self.neighbours.push(made);
        self.neighbours.len() - 1
    }
    /// A packet goes out through the veth end `index` to `ip` at `now`,
    /// as `ip_finish_output2` and `ip6_finish_output2` take its neighbour,
    /// made if there is none ([`Self::on_end`]), and `neigh_event_send`
    /// resolves it: the link-layer address it goes to, if any, whether ARP
    /// or neighbour discovery asked, and what is told of. A valid
    /// one is used, and a stale one delays, its probe to be answered as
    /// `answer` says (some address) now. Any other asks: answered with
    /// `answer`, it is reachable at that address (`arp_process`'s reply, or
    /// a solicited neighbour advertisement, told of); unanswered, it is
    /// incomplete, its first probe sent, and the packet waits for what
    /// never comes ([`Neighbour::arp_timer`]).
    pub(crate) fn neigh_output(
        &mut self,
        index: i32,
        ip: impl Into<IpAddr>,
        answer: Option<[u8; 6]>,
        now: u64,
    ) -> (Option<[u8; 6]>, bool, Vec<Event>) {
        let i = self.end_neighbour(index, ip.into(), now);
        let n = &mut self.neighbours[i];
        n.used = now;
        if n.state & NUD_STALE != 0 {
            n.state = NUD_DELAY;
            n.updated = now;
            n.timer = true;
            n.answers = answer.is_some();
        }
        if n.state & NUD_VALID != 0 {
            return (Some(n.lladdr), false, Vec::new());
        }
        if n.state & NUD_INCOMPLETE == 0 {
            n.probes = 4;
            n.state = NUD_INCOMPLETE;
            n.updated = now;
            n.timer = true;
        }
        let Some(lladdr) = answer else {
            return (None, true, Vec::new());
        };
        n.state = NUD_REACHABLE;
        n.lladdr = lladdr;
        n.updated = now;
        n.confirmed = now;
        n.unconfirmed = false;
        (Some(lladdr), true, vec![Event::NewNeighbour(*n)])
    }
    /// An ARP request, or a neighbour solicitation, from `ip` at `lladdr`
    /// comes in on the veth end `index` at `now` for an address of this
    /// namespace's, as `arp_process` (`neigh_event_ns`) and
    /// `ndisc_recv_ns` learn of its sender: one there is not is made
    /// stale with that address; a permanent or `NUD_NOARP` one stays; a
    /// valid one at that address stays as it is; any other is stale at
    /// it. What is told of.
    pub(crate) fn neigh_learn(
        &mut self,
        index: i32,
        ip: impl Into<IpAddr>,
        lladdr: [u8; 6],
        now: u64,
    ) -> Vec<Event> {
        let i = self.end_neighbour(index, ip.into(), now);
        let n = &mut self.neighbours[i];
        if n.state & (NUD_NOARP | NUD_PERMANENT) != 0
            || (n.state & NUD_VALID != 0 && n.lladdr == lladdr)
        {
            return Vec::new();
        }
        n.state = NUD_STALE;
        n.lladdr = lladdr;
        n.updated = now;
        n.confirmed = now;
        n.unconfirmed = true;
        n.timer = false;
        vec![Event::NewNeighbour(*n)]
    }
    /// The neighbours of the device of `index` flushed, as `neigh_ifdown`
    /// does when it goes down or away, or, `keep_permanent`, as
    /// `neigh_carrier_down` does when it loses its carrier, keeping the
    /// permanent ones and those `NTF_EXT_VALIDATED`: told of with
    /// `RTM_DELNEIGH`, IPv4's, then IPv6's, each the newest first, as each
    /// was put at the head of the device's list.
    pub(crate) fn flush_device(&mut self, index: i32, keep_permanent: bool) -> Vec<Event> {
        let (gone, kept) = self.neighbours.drain(..).partition::<Vec<_>, _>(|n| {
            n.index == index
                && !(keep_permanent
                    && (n.state & NUD_PERMANENT != 0 || n.flags & NTF_EXT_VALIDATED != 0))
        });
        self.neighbours = kept;
        // ARP's table first, then neighbour discovery's, as their
        // notifiers come (`arp_ifdown` in `fib_disable_ip`, or
        // `arp_netdev_event`, then `ndisc_netdev_event`).
        let (v4, v6): (Vec<_>, Vec<_>) = gone.into_iter().partition(|n| n.ip.is_ipv4());
        v4.into_iter()
            .rev()
            .chain(v6.into_iter().rev())
            .map(|mut n| {
                n.timer = false;
                Event::DelNeighbour(n)
            })
            .collect()
    }
    /// The loopback's neighbours of one family flushed
    /// (`neigh_flush_dev`), told of with `RTM_DELNEIGH`, the newest first,
    /// as each was put at the head of the device's list.
    fn flush(&mut self, v6: bool, events: &mut Vec<Event>) {
        let (gone, kept) = self
            .neighbours
            .drain(..)
            .partition::<Vec<_>, _>(|n| n.index == LOOPBACK_INDEX && n.ip.is_ipv6() == v6);
        self.neighbours = kept;
        events.extend(gone.into_iter().rev().map(|mut n| {
            // `neigh_flush_one` stops its timer.
            n.timer = false;
            Event::DelNeighbour(n)
        }));
        // `pneigh_ifdown`: the proxy entries for the loopback, silently.
        self.proxies.retain(|p| p.ip.is_ipv6() != v6 || !p.device);
    }
    /// The loopback comes up (`NETDEV_UP`) at `now`, and what Linux tells
    /// of it, in its order: `127.0.0.1/8` if it has it not, with its routes
    /// (`inetdev_event`); the routes every IPv4 address has then that are
    /// not there, in the addresses' order (`fib_netdev_event`); the prefix
    /// route of each permanent IPv6 address added while it was down
    /// (`addrconf_permanent_addr`); and `::1` with its route. With `v6`
    /// false (`disable_ipv6`) IPv6 does none of it ([`Self::up6`]).
    pub(crate) fn up(&mut self, now: u64, v6: bool) -> Vec<Event> {
        let mut events = Vec::new();
        let loopback = V4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 8, SCOPE_HOST);
        // The kernel's own, which reports nothing when it is there.
        let added = extack::quietly(|| self.add_v4(loopback, Lifetimes::FOREVER, false, true, now));
        if let Ok(added) = added {
            events.extend(added);
        }
        events.extend(self.device_up4(LOOPBACK_INDEX));
        if v6 {
            events.extend(self.up6(now));
        }
        events
    }
    /// IPv4's part of a device of `index` coming up (`fib_netdev_event`'s
    /// `NETDEV_UP`): the routes each of its addresses has then that are not
    /// there, in the addresses' order (`fib_add_ifaddr`).
    pub(crate) fn device_up4(&mut self, index: i32) -> Vec<Event> {
        // `fib_sync_up` of `RTNH_F_DEAD`: the next hops through it live
        // again, and are not down with its carrier.
        let oif = index.unsigned_abs();
        let carrier = !self.no_carrier.contains(&oif);
        for route in self.routes4.iter_mut().filter(|r| !r.hops.is_empty()) {
            for hop in route.hops.iter_mut().filter(|h| h.oif == oif && h.dead) {
                hop.dead = false;
                hop.linkdown = !carrier;
            }
            if route.hops.iter().any(|h| !h.dead) {
                route.fib_flags &= !NEXTHOP_DEAD_ONLY;
                if carrier {
                    route.fib_flags &= !NEXTHOP_LINKDOWN;
                }
            }
            route.first_again();
        }
        let mut events = Vec::new();
        let addresses: Vec<V4> = self
            .v4
            .iter()
            .filter(|a| a.index == index)
            .cloned()
            .collect();
        for address in addresses {
            for route in self.candidates(&address, true) {
                self.kernel_add4(route, &mut events);
            }
        }
        events
    }
    /// The device of `index`, up, has its carrier or loses it
    /// (`fib_netdev_event`'s `NETDEV_CHANGE`): the routes through it but
    /// those of host scope stop or start being `RTNH_F_LINKDOWN`
    /// (`fib_sync_up`, `fib_sync_down_dev`), without a word. A device
    /// coming up takes its carrier so before [`Self::device_up4`].
    pub(crate) fn set_carrier(&mut self, index: i32, carrier: bool) {
        let oif = index.unsigned_abs();
        self.no_carrier.retain(|&o| o != oif);
        if !carrier {
            self.no_carrier.push(oif);
        }
        for route in &mut self.routes4 {
            if route.hops.is_empty() {
                if route.oif == oif && route.scope != SCOPE_HOST {
                    route.linkdown = !carrier;
                }
                continue;
            }
            // A multipath route's next hops through it, and the route
            // as a whole: down where those through it and those dead are
            // all of them (`fib_sync_down_dev` for `NETDEV_CHANGE`), up
            // where one is up (`fib_sync_up`).
            let mut counted = 0;
            for hop in &mut route.hops {
                if hop.dead {
                    counted += 1;
                } else if hop.oif == oif {
                    hop.linkdown = !carrier;
                    counted += 1;
                }
            }
            let all = counted == route.hops.len();
            if !carrier && all {
                route.fib_flags |= NEXTHOP_LINKDOWN;
            }
            if carrier && route.hops.iter().any(|h| !h.linkdown) {
                route.fib_flags &= !NEXTHOP_LINKDOWN;
            }
            route.first_again();
        }
        for route in self
            .routes6
            .iter_mut()
            .filter(|r| r.oif == oif && r.kind != Kind::Local)
        {
            route.linkdown = !carrier;
        }
    }
    /// IPv4's part of the device of `index` going (`NETDEV_UNREGISTER`),
    /// once closed ([`Self::device_down4`]): `inetdev_destroy` removes each of its addresses, the
    /// first first, as [`Self::remove_v4`] does, which tells of each and
    /// of its local route; `fib_disable_ip` then takes what is left of
    /// its routes without a word. The time it is told at.
    pub(crate) fn device_gone4(&mut self, index: i32) -> (Vec<Event>, u64) {
        // Closed: what is not of host scope has gone without a word.
        self.device_down4(index);
        let mut events = Vec::new();
        while let Some(first) = self.v4.iter().position(|a| a.index == index) {
            events.extend(self.remove_v4(first));
        }
        let oif = index.unsigned_abs();
        self.sync_down4(oif, true);
        self.no_carrier.retain(|&o| o != oif);
        (events, self.seen)
    }
    /// IPv4's part of a device of `index` going down (`fib_disable_ip`):
    /// its routes but those of host scope go, without a word
    /// (`fib_sync_down_dev`, `fib_flush`).
    pub(crate) fn device_down4(&mut self, index: i32) {
        self.sync_down4(index.unsigned_abs(), false);
    }
    /// `fib_sync_down_dev` for the device `oif` going down, or away
    /// (`gone`): each next hop through it turns `RTNH_F_DEAD` and
    /// `RTNH_F_LINKDOWN`, but a route of host scope's while it only goes
    /// down; a route whose next hops are all dead goes (`fib_flush`), as
    /// one through it does as it goes away.
    fn sync_down4(&mut self, oif: u32, gone: bool) {
        let mut kept = Vec::new();
        for mut route in core::mem::take(&mut self.routes4) {
            let mut hops = route.next_hops();
            let mut dead = 0;
            for hop in &mut hops {
                if hop.dead {
                    dead += 1;
                } else if hop.oif == oif && (gone || route.scope != SCOPE_HOST) {
                    hop.dead = true;
                    hop.linkdown = true;
                    dead += 1;
                }
            }
            if dead == hops.len() || (gone && hops.iter().any(|h| h.oif == oif)) {
                continue;
            }
            if !route.hops.is_empty() {
                route.hops = hops;
                route.first_again();
            }
            kept.push(route);
        }
        self.routes4 = kept;
    }
    /// IPv6's part of [`Self::up`], as `addrconf_notify` does it for
    /// `NETDEV_UP`: the prefix route of each permanent address
    /// (`addrconf_permanent_addr`), then `::1` with its route
    /// (`init_loopback`).
    pub(crate) fn up6(&mut self, now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        for address in self.v6.clone() {
            if address.index == LOOPBACK_INDEX
                && address.flags & PERMANENT != 0
                && let Some(route) = address.prefix_route()
            {
                self.kernel_add6(route, &mut events);
            }
        }
        if !self.local6(Ipv6Addr::LOCALHOST) {
            let mut one = V6::new(Ipv6Addr::LOCALHOST, 128);
            one.proto = KERNEL_LO;
            one.life.created = now;
            one.life.changed = now;
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
        self.device_down4(LOOPBACK_INDEX);
        // `fib_disable_ip` flushes IPv4's neighbours (`arp_ifdown`); then
        // `addrconf_ifdown` takes IPv6's routes, its neighbours
        // (`rt6_disable_ip`) and its addresses.
        let mut events = Vec::new();
        self.flush(false, &mut events);
        events.extend(self.down6());
        events
    }
    /// IPv6's part of [`Self::down`], as `addrconf_ifdown` does it: every
    /// route through `lo`, told of in the order of a dump
    /// (`rt6_disable_ip`), the neighbours, then every address of it.
    pub(crate) fn down6(&mut self) -> Vec<Event> {
        let mut events = self.routes6_gone(LOOPBACK_OIF);
        self.flush(true, &mut events);
        events.extend(self.addresses6_gone(LOOPBACK_INDEX));
        events
    }
    /// The IPv6 routes through the device of `oif` go, told of in the
    /// order of a dump (`rt6_disable_ip`).
    fn routes6_gone(&mut self, oif: u32) -> Vec<Event> {
        let events = self
            .dump6()
            .into_iter()
            .filter(|r| r.oif == oif)
            .map(Event::DelRoute6)
            .collect();
        self.routes6.retain(|r| r.oif != oif);
        events
    }
    /// The IPv6 addresses of the device of `index` go, told of in their
    /// order.
    fn addresses6_gone(&mut self, index: i32) -> Vec<Event> {
        let (gone, kept) = self
            .v6
            .drain(..)
            .partition::<Vec<_>, _>(|a| a.index == index);
        self.v6 = kept;
        self.ready6.retain(|&i| i != index);
        gone.into_iter().map(Event::DelAddr6).collect()
    }
    /// IPv6's part of the veth end `index` coming up at `now`
    /// (`addrconf_notify`'s `NETDEV_UP`): the prefix route of each of its
    /// permanent addresses (`addrconf_permanent_addr`); then, with its
    /// carrier, what [`Self::link_ready6`] does.
    pub(crate) fn device_up6(
        &mut self,
        index: i32,
        carrier: bool,
        (mac, dad): ([u8; 6], bool),
        now: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        for address in self.v6.clone() {
            if address.index == index
                && address.flags & PERMANENT != 0
                && let Some(route) = address.prefix_route()
            {
                self.kernel_add6(route, &mut events);
            }
        }
        if carrier {
            events.extend(self.link_ready6(index, (mac, dad), now));
        }
        events
    }
    /// The veth end `index`, up, is ready with its carrier at `now`
    /// (`addrconf_dev_config`), once until it goes down: its multicast
    /// route (`ff00::/8` of the local table, `addrconf_add_mroute`), then
    /// its link-local address, made from its Ethernet address `mac`
    /// (`addrconf_addr_gen`, EUI-64), with the prefix route of `fe80::/64`.
    /// That address, and any of the end's waiting, are checked for
    /// duplicates when `dad`, done at `DAD_TIME` on, else at once once the
    /// request is done; a made one is told of only then.
    pub(crate) fn link_ready6(
        &mut self,
        index: i32,
        (mac, dad): ([u8; 6], bool),
        now: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        if self.ready6.contains(&index) {
            return events;
        }
        self.ready6.push(index);
        let oif = index.unsigned_abs();
        // `rt6_sync_up`: its routes are no longer dead, nor down, as it
        // has its carrier.
        for route in self.routes6.iter_mut().filter(|r| r.oif == oif) {
            route.dead = false;
            route.linkdown = false;
        }
        self.kernel_add6(
            Route6 {
                oif,
                table: TABLE_LOCAL,
                dst: Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
                len: 8,
                kind: Kind::Multicast,
                metric: METRIC_ADDRCONF,
                proto: PROTO_KERNEL,
                prefsrc: None,
                metrics: NO_METRICS,
                expires: None,
                linkdown: false,
                gateway: None,
                onlink: false,
                dead: false,
                weight: 1,
            },
            &mut events,
        );
        let done = if dad { now + DAD_TIME } else { now };
        for address in self.v6.iter_mut() {
            if address.index == index && address.dad == Some(u64::MAX) {
                address.dad = Some(done);
            }
        }
        let eui = [
            mac[0] ^ 2,
            mac[1],
            mac[2],
            0xff,
            0xfe,
            mac[3],
            mac[4],
            mac[5],
        ];
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[8..].copy_from_slice(&eui);
        let mut link = V6::new(Ipv6Addr::from(octets), 64);
        link.index = index;
        link.proto = KERNEL_LL;
        link.life.created = now;
        link.life.changed = now;
        link.dad = Some(done);
        if let Some(route) = link.prefix_route() {
            self.kernel_add6(route, &mut events);
        }
        self.insert_v6(link);
        events
    }
    /// IPv6's part of the veth end `index` going down (`addrconf_ifdown`):
    /// its routes ([`Self::routes6_down`]), then its addresses.
    pub(crate) fn device_down6(&mut self, index: i32) -> Vec<Event> {
        let mut events = self.routes6_down(index.unsigned_abs());
        events.extend(self.addresses6_gone(index));
        events
    }
    /// IPv6's part of the veth end `index` going away, once down
    /// (`addrconf_ifdown` for `NETDEV_UNREGISTER`): what is left of its
    /// routes, multipath siblings too, told of in the order of a dump,
    /// then its addresses.
    pub(crate) fn device_gone6(&mut self, index: i32) -> Vec<Event> {
        let mut events = self.routes6_gone(index.unsigned_abs());
        events.extend(self.addresses6_gone(index));
        events
    }
    /// The IPv6 routes through the device of `oif` as it goes down
    /// (`fib6_ifdown` for `NETDEV_DOWN`), told of in the order of a dump:
    /// each goes, but a multipath sibling, which turns `RTNH_F_DEAD` and
    /// `RTNH_F_LINKDOWN` without a word, unless all of its multipath
    /// route would be dead, when all of it goes
    /// (`rt6_multipath_flush`).
    fn routes6_down(&mut self, oif: u32) -> Vec<Event> {
        let routes = self.routes6.clone();
        let flushed = |route: &Route6| {
            let hops = self.hops6(route);
            !hops.is_empty()
                && hops.iter().any(|r| r.oif == oif)
                && hops.iter().all(|r| r.oif == oif || r.dead)
        };
        let gone: Vec<bool> = routes
            .iter()
            .map(|r| {
                if self.hops6(r).is_empty() {
                    r.oif == oif
                } else {
                    flushed(r)
                }
            })
            .collect();
        let mut events: Vec<Event> = Vec::new();
        for route in self.dump6() {
            if let Some(i) = routes.iter().position(|r| *r == route)
                && gone[i]
            {
                events.push(Event::DelRoute6(route));
            }
        }
        let mut kept = Vec::new();
        for (mut route, gone) in routes.into_iter().zip(gone) {
            if gone {
                continue;
            }
            if route.oif == oif && !self.hops6(&route).is_empty() {
                route.dead = true;
                route.linkdown = true;
            }
            kept.push(route);
        }
        self.routes6 = kept;
        events
    }
    /// Adds an IPv4 address with `lifetimes` at `now` to its device, as
    /// `inet_rtm_newaddr` and `__inet_insert_ifa` do among the device's
    /// own: the same local address and subnet again is `EEXIST`, unless
    /// `replace`; one in a subnet an address of another scope has is
    /// `EINVAL`; one in a subnet a primary address has is secondary, and
    /// goes last; a primary goes after the primaries of a scope as wide or
    /// wider. The devices' addresses are kept in the order of their
    /// indices, as a dump goes through them. What Linux tells: the
    /// address, then the routes it brings (`fib_add_ifaddr`), those while
    /// the device is `up` too. One replaced takes the new one's protocol,
    /// priority (its prefix route, while `up`, again with it, then the old
    /// one gone: `fib_modify_prefix_metric`) and lifetimes, and is told of.
    pub(crate) fn add_v4(
        &mut self,
        mut new: V4,
        lifetimes: Lifetimes,
        replace: bool,
        up: bool,
        now: u64,
    ) -> Result<Vec<Event>, Errno> {
        new.flags &= !SECONDARY;
        new.set_life(lifetimes, now);
        new.life.created = now;
        let start = self.v4.partition_point(|a| a.index < new.index);
        let end = self.v4.partition_point(|a| a.index <= new.index);
        let mut last_primary = start;
        for (i, old) in self.v4.iter().enumerate().take(end).skip(start) {
            if !old.secondary() && new.scope <= old.scope {
                last_primary = i + 1;
            }
            if old.mask() == new.mask() && old.covers(new.address) {
                if old.local == new.local {
                    if !replace {
                        return Err(extack::message(
                            Errno::EEXIST,
                            "ipv4: Address already assigned",
                        ));
                    }
                    return Ok(self.change_v4(i, &new, lifetimes, up, now));
                }
                // `__inet_insert_ifa`: a subnet has one scope.
                if old.scope != new.scope {
                    return Err(extack::message(Errno::EINVAL, "ipv4: Invalid scope value"));
                }
                new.flags |= SECONDARY;
            }
        }
        let mut events = vec![Event::NewAddr4(new.clone())];
        if new.secondary() {
            self.v4.insert(end, new.clone());
        } else {
            self.v4.insert(last_primary, new.clone());
        }
        for route in self.candidates(&new, up) {
            self.kernel_add4(route, &mut events);
        }
        Ok(events)
    }
    /// The IPv4 address at `i` replaced by `new`, as `inet_rtm_newaddr`
    /// changes one it has.
    fn change_v4(
        &mut self,
        i: usize,
        new: &V4,
        lifetimes: Lifetimes,
        up: bool,
        now: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        let old = self.v4[i].clone();
        if old.priority != new.priority
            && up
            && old.flags & (SECONDARY | NO_PREFIX_ROUTE) == 0
            && let Some(route) = prefix_route4(&old)
        {
            self.kernel_add4(
                Route4 {
                    priority: new.priority,
                    ..route.clone()
                },
                &mut events,
            );
            self.kernel_del4(&route, &mut events);
        }
        let address = &mut self.v4[i];
        address.priority = new.priority;
        address.proto = new.proto;
        address.set_life(lifetimes, now);
        events.push(Event::NewAddr4(address.clone()));
        events
    }
    /// Removes the first IPv4 address of the device of `index` that has
    /// `local`, `label`, and `address` in a subnet of `prefix`, each as
    /// given, as `inet_rtm_deladdr`: `EADDRNOTAVAIL` for none
    /// ([`Self::remove_v4`]).
    pub(crate) fn del_v4(
        &mut self,
        index: i32,
        local: Option<Ipv4Addr>,
        address: Option<Ipv4Addr>,
        prefix: u8,
        label: Option<&[u8]>,
    ) -> Result<Vec<Event>, Errno> {
        let found = self
            .v4
            .iter()
            .position(|a| {
                a.index == index
                    && local.is_none_or(|local| a.local == local)
                    && label.is_none_or(|label| a.label == label)
                    && address.is_none_or(|address| a.prefix == prefix && a.covers(address))
            })
            .ok_or_else(|| extack::message(EADDRNOTAVAIL, "ipv4: Address not found"))?;
        Ok(self.remove_v4(found))
    }
    /// Removes the IPv4 address at `found` (`__inet_del_ifa`). A primary
    /// takes its secondaries with it (`promote_secondaries` is 0), which go
    /// first. What Linux tells: each address, then the kernel's routes
    /// that go with it, the prefix route, the broadcast ones, then the
    /// local one (`fib_del_ifaddr`); where its local address is the
    /// loopback's no more, the main table's routes from it
    /// (`fib_sync_down_addr`). The last address takes every route through
    /// `lo` with it, without a word (`fib_disable_ip`).
    fn remove_v4(&mut self, found: usize) -> Vec<Event> {
        let target = self.v4[found].clone();
        let mut gone: Vec<V4> = Vec::new();
        if !target.secondary() {
            gone.extend(
                self.v4
                    .iter()
                    .filter(|a| a.secondary() && target.same_subnet(a))
                    .cloned(),
            );
        }
        gone.push(target);
        let mut events = Vec::new();
        for address in gone {
            // `fib_del_ifaddr`'s order: the prefix route, the broadcast ones,
            // then the local one, each named with no priority.
            let candidates = self.candidates(&address, true);
            let (local, rest) = candidates
                .split_first()
                .map_or((None, &[][..]), |(l, r)| (Some(l.clone()), r));
            // The prefix route is local on `lo`, unicast elsewhere.
            let mut order: Vec<Route4> = rest
                .iter()
                .filter(|r| r.kind != Kind::Broadcast)
                .map(|r| Route4 {
                    priority: 0,
                    ..r.clone()
                })
                .collect();
            order.extend(rest.iter().filter(|r| r.kind == Kind::Broadcast).cloned());
            order.extend(local);
            if let Some(i) = self.v4.iter().position(|a| *a == address) {
                self.v4.remove(i);
            }
            // `fib_del_ifaddr` looks at the device's other addresses.
            let wanted: Vec<Route4> = self
                .v4
                .iter()
                .filter(|a| a.index == address.index)
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
            // The device's last address gone, `fib_disable_ip` takes every
            // route through it, and its neighbours (`arp_ifdown`): only
            // the loopback has any.
            if !self.v4.iter().any(|a| a.index == address.index) {
                self.routes4.retain(|r| r.oif != address.oif());
                if address.index == LOOPBACK_INDEX {
                    self.flush(false, &mut events);
                }
            }
        }
        events
    }
    /// Adds an IPv6 address with `lifetimes` at `now` to its device
    /// ([`V6::set_life`]): the same one of the device again is `EEXIST`,
    /// unless `replace` ([`Self::change_v6`]). Global ones go before host
    /// ones, the newest first within a scope (`ipv6_link_dev_addr`). What
    /// Linux tells: while its device is up, its prefix route; the address,
    /// tentative unless `IFA_F_NODAD`; then, once its duplicate address
    /// detection has ended, as it is, and its local route. That ends at
    /// once on a loopback, at `dad` on a veth end that checks it
    /// ([`Self::expire`], `u64::MAX` until the end is up with its
    /// carrier), and at once on one that does not.
    pub(crate) fn add_v6(
        &mut self,
        mut new: V6,
        lifetimes: Lifetimes,
        replace: bool,
        up: bool,
        dad: Option<u64>,
        now: u64,
    ) -> Result<Vec<Event>, Errno> {
        new.set_life(lifetimes, now);
        new.life.created = now;
        if let Some(i) = self
            .v6
            .iter()
            .position(|a| a.index == new.index && a.address == new.address)
        {
            if !replace {
                return Err(extack::message(
                    Errno::EEXIST,
                    "ipv6: address already assigned",
                ));
            }
            return Ok(self.change_v6(i, &new, up));
        }
        let mut events = Vec::new();
        if up && let Some(route) = new.prefix_route() {
            self.kernel_add6(route, &mut events);
        }
        if new.flags & NO_DAD == 0 {
            events.push(Event::NewAddr6(new.clone(), true));
            if let Some(at) = dad {
                new.dad = Some(at);
                self.insert_v6(new);
                return Ok(events);
            }
        }
        events.push(Event::NewAddr6(new.clone(), false));
        self.kernel_add6(new.local_route(), &mut events);
        self.insert_v6(new);
        Ok(events)
    }
    /// The IPv6 address at `i` changed to `new`'s flags, lifetimes and
    /// protocol, and its priority where `new` names one, as
    /// `inet6_addr_modify` does, and told of unless it is tentative. Its prefix route, while
    /// `up`, follows (`modify_prefix_route`): one of another metric goes
    /// and comes again of the new one, and one of the same takes its
    /// lifetime; none, or none it had, is made. One that no longer asks for
    /// it goes as on a removal ([`Self::prefix_gone`]).
    fn change_v6(&mut self, i: usize, new: &V6, up: bool) -> Vec<Event> {
        let old = self.v6[i].clone();
        let had = old.flags & PERMANENT != 0 && old.flags & NO_PREFIX_ROUTE == 0;
        let address = &mut self.v6[i];
        address.flags = address.flags & !V6_CHANGED | new.flags;
        address.life.valid = new.life.valid;
        address.life.preferred = new.life.preferred;
        address.life.changed = new.life.changed;
        address.proto = new.proto;
        if new.priority != 0 {
            address.priority = new.priority;
        }
        let changed = address.clone();
        // `inet6_addr_modify` tells of it only once its duplicate address
        // detection is done.
        let mut events = Vec::new();
        if changed.dad.is_none() {
            events.push(Event::NewAddr6(changed.clone(), false));
        }
        if changed.flags & NO_PREFIX_ROUTE == 0 {
            let found = had
                .then(|| {
                    self.routes6.iter().position(|r| {
                        r.table == TABLE_MAIN
                            && r.dst == changed.prefix_of()
                            && r.len == changed.prefix
                            && r.oif == changed.index.unsigned_abs()
                    })
                })
                .flatten();
            match found {
                Some(at) if self.routes6[at].metric != changed.metric() => {
                    events.push(Event::DelRoute6(self.routes6.remove(at)));
                    if up && let Some(route) = changed.prefix_route() {
                        self.kernel_add6(route, &mut events);
                    }
                }
                Some(at) => self.routes6[at].expires = changed.expires(),
                None => {
                    if up && let Some(route) = changed.prefix_route() {
                        self.kernel_add6(route, &mut events);
                    }
                }
            }
        } else if had {
            self.prefix_gone(&changed, changed.life.changed, &mut events);
        }
        events
    }
    /// What becomes of the prefix route of `gone`, which is going or no
    /// longer asks for one (`check_cleanup_prefix_route`,
    /// `cleanup_prefix_route`): kept where another address of its prefix
    /// is permanent or has none; else, with others, it runs out when the
    /// last of them does, if it did not already; with none, the first
    /// route of the main table to it goes, whoever's.
    fn prefix_gone(&mut self, gone: &V6, now: u64, events: &mut Vec<Event>) {
        let mut others = self
            .v6
            .iter()
            .filter(|a| {
                a.index == gone.index
                    && a.address != gone.address
                    && a.prefix == gone.prefix
                    && a.covers(gone.address)
            })
            .peekable();
        let mut expires = None;
        if others.peek().is_some() {
            let mut last = now;
            for other in others {
                if other.flags & (PERMANENT | NO_PREFIX_ROUTE) != 0 {
                    return;
                }
                last = last.max(other.life.changed + u64::from(other.life.valid) * SECOND);
            }
            expires = Some(last);
        }
        let Some(at) = self.routes6.iter().position(|r| {
            r.table == TABLE_MAIN
                && r.dst == gone.prefix_of()
                && r.len == gone.prefix
                && r.oif == gone.index.unsigned_abs()
        }) else {
            return;
        };
        match expires {
            None => events.push(Event::DelRoute6(self.routes6.remove(at))),
            Some(expires) => {
                let route = &mut self.routes6[at];
                if route.expires.is_none() {
                    route.expires = Some(expires);
                }
            }
        }
    }
    fn insert_v6(&mut self, new: V6) {
        let at = self
            .v6
            .iter()
            .position(|a| a.index == new.index && a.scope() >= new.scope())
            .unwrap_or(self.v6.len());
        self.v6.insert(at, new);
    }
    /// Removes the IPv6 address `address/prefix` of the device of `index`
    /// at `now` (`EADDRNOTAVAIL` for none, [`Self::remove_v6`]).
    pub(crate) fn del_v6(
        &mut self,
        index: i32,
        address: Ipv6Addr,
        prefix: u8,
        now: u64,
    ) -> Result<Vec<Event>, Errno> {
        let found = self
            .v6
            .iter()
            .position(|a| a.index == index && a.address == address && a.prefix == prefix)
            .ok_or_else(|| extack::message(EADDRNOTAVAIL, "ipv6: address not found"))?;
        Ok(self.remove_v6(found, now))
    }
    /// Removes the IPv6 address at `found` (`ipv6_del_addr`). What Linux
    /// tells: the address, its local route, then what becomes of its
    /// prefix route ([`Self::prefix_gone`]), unless it had none.
    fn remove_v6(&mut self, found: usize, now: u64) -> Vec<Event> {
        let gone = self.v6.remove(found);
        let mut events = vec![Event::DelAddr6(gone.clone())];
        self.kernel_del6(&gone.local_route(), &mut events);
        if gone.flags & NO_PREFIX_ROUTE == 0 {
            self.prefix_gone(&gone, now, &mut events);
        }
        events
    }
    /// What has run out by `now`, as Linux's work finds it
    /// (`check_lifetime`, then `addrconf_verify_rtnl`, then the IPv6 routes'
    /// garbage collection, `fib6_run_gc`): an address past its valid
    /// lifetime goes, as on a removal, and one past its preferred lifetime
    /// is `IFA_F_DEPRECATED`, and told of; an IPv6 route past its own goes,
    /// and is told of. A permanent IPv4 address never runs out, nor an IPv6
    /// one whose preferred lifetime never ends. Last, a reachable neighbour
    /// whose reachable time has passed delays or goes stale, and the stale
    /// ones are told of ([`Neighbour::age`]).
    pub(crate) fn expire(&mut self, now: u64) -> Vec<Event> {
        self.seen = self.seen.max(now);
        let mut events = Vec::new();
        let mut i = 0;
        while i < self.v4.len() {
            let a = &mut self.v4[i];
            if a.flags & PERMANENT == 0 {
                if a.life.reached(a.life.valid, now) {
                    events.extend(self.remove_v4(i));
                    i = 0;
                    continue;
                }
                if a.life.reached(a.life.preferred, now) && a.flags & DEPRECATED == 0 {
                    a.flags |= DEPRECATED;
                    events.push(Event::NewAddr4(a.clone()));
                }
            }
            i += 1;
        }
        let mut i = 0;
        while i < self.v6.len() {
            let a = &mut self.v6[i];
            if !(a.flags & PERMANENT != 0 && a.life.preferred == FOREVER) {
                if a.life.reached(a.life.valid, now) {
                    events.extend(self.remove_v6(i, now));
                    i = 0;
                    continue;
                }
                if a.life.reached(a.life.preferred, now) && a.flags & DEPRECATED == 0 {
                    a.flags |= DEPRECATED;
                    let tentative = a.dad.is_some();
                    events.push(Event::NewAddr6(a.clone(), tentative));
                }
            }
            i += 1;
        }
        // Duplicate address detection that has ended (`addrconf_dad_completed`):
        // each address as it is, then its local route.
        let mut done: Vec<(u64, usize)> = self
            .v6
            .iter()
            .enumerate()
            .filter_map(|(i, a)| a.dad.filter(|&at| at <= now).map(|at| (at, i)))
            .collect();
        done.sort_by_key(|&(at, _)| at);
        for (_, i) in done {
            self.v6[i].dad = None;
            let address = self.v6[i].clone();
            events.push(Event::NewAddr6(address.clone(), false));
            self.kernel_add6(address.local_route(), &mut events);
        }
        let expired: Vec<Route6> = self
            .dump6()
            .into_iter()
            .filter(|r| r.expires.is_some_and(|at| at < now))
            .collect();
        for route in expired {
            self.kernel_del6(&route, &mut events);
        }
        // Then the neighbours that have gone stale, in the order their
        // timers ran (`neigh_timer_handler`).
        let mut stale: Vec<(u64, Neighbour)> = self
            .neighbours
            .iter_mut()
            .flat_map(|n| {
                let mut told: Vec<(u64, Neighbour)> =
                    n.age(now).map(|at| (at, *n)).into_iter().collect();
                told.extend(n.arp_timer(now));
                told
            })
            .collect();
        stale.sort_by_key(|&(at, _)| at);
        events.extend(stale.into_iter().map(|(_, n)| Event::NewNeighbour(n)));
        events
    }
    /// The primary address whose subnet `secondary` is in, or itself.
    fn primary_of(&self, address: &V4) -> Ipv4Addr {
        if !address.secondary() {
            return address.local;
        }
        self.v4
            .iter()
            .find(|a| !a.secondary() && a.same_subnet(address))
            .map_or(address.local, |a| a.local)
    }
    /// The routes `fib_add_ifaddr` gives `address`, in its order: the local
    /// one; and while its device is `up`, the broadcast one it names, its
    /// prefix route, `local` on a loopback, and its subnet's broadcast
    /// route.
    fn candidates(&self, address: &V4, up: bool) -> Vec<Route4> {
        let source = self.primary_of(address);
        let route = |dst, len, kind| Route4::kernel(dst, len, kind, source, address.oif());
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
            routes.push(Route4 {
                priority: address.priority,
                ..route(prefix, address.prefix, address.prefix_kind())
            });
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
            let matched = (first..run).find(|&i| self.routes4[i].same_info(&new));
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
    /// the routes of a metric as low or lower, the multipath sibling of
    /// those of its metric with a gateway where it has one
    /// ([`Self::hops6`]). The flags Linux tells of it with: `NLM_F_EXCL`
    /// where no other of its metric is there, and the request's
    /// `NLM_F_APPEND`.
    fn insert6(&mut self, new: Route6, flags: Option<u16>) -> Result<u16, Errno> {
        let asked = |flag: u16| flags.is_some_and(|f| f & flag != 0);
        let mut told = F_EXCL;
        if asked(F_APPEND) {
            told |= F_APPEND;
        }
        // `fib6_add_rt2node`: with `NLM_F_EXCL` any route of the node of
        // the same metric is there already, and `NLM_F_REPLACE` takes the
        // first of them that qualifies for ECMP as the new one does; with
        // neither, only one through the same device and gateway is the
        // same, another of the prefix being another route of its node.
        let same_metric = |r: &Route6| {
            r.table == new.table && r.dst == new.dst && r.len == new.len && r.metric == new.metric
        };
        let ecmp = ecmp6;
        if self.routes6.iter().any(same_metric) {
            told &= !F_EXCL;
        }
        let found = if asked(F_EXCL) {
            self.routes6.iter().position(same_metric)
        } else if asked(F_REPLACE) {
            // The first that qualifies for ECMP as the new one does, else
            // the first of them.
            self.routes6
                .iter()
                .position(|r| same_metric(r) && ecmp(r) == ecmp(&new))
                .or_else(|| self.routes6.iter().position(same_metric))
        } else {
            // `rt6_duplicate_nexthop`: the same device and gateway.
            self.routes6
                .iter()
                .position(|r| same_metric(r) && r.oif == new.oif && r.gateway == new.gateway)
        };
        if let Some(i) = found {
            if asked(F_EXCL) || !asked(F_REPLACE) {
                // The same route through the same device, which runs out,
                // runs out as the new one does instead, if at all
                // (`fib6_add_rt2node`).
                let old = &mut self.routes6[i];
                if !asked(F_EXCL) && old.expires.is_some() {
                    old.expires = new.expires;
                }
                return Err(Errno::EEXIST);
            }
            // Replacing one of a multipath route takes its siblings away
            // too, without a word: those after it with a gateway.
            let siblings = !self.hops6(&self.routes6[i]).is_empty();
            self.routes6[i] = new;
            if siblings {
                let mut at = i + 1;
                // A node's routes are next to each other, by metric.
                while let Some(r) = self.routes6.get(at).filter(|r| same_metric(r)) {
                    if ecmp(r) {
                        self.routes6.remove(at);
                    } else {
                        at += 1;
                    }
                }
            }
            return Ok(F_REPLACE);
        }
        if asked(F_REPLACE) && !asked(F_CREATE) {
            // `fib6_add_1` tells of it where the prefix has no node, which
            // is taken to be where it has no route.
            let node = self
                .routes6
                .iter()
                .any(|r| r.table == new.table && r.dst == new.dst && r.len == new.len);
            if !node {
                return Err(extack::message(
                    Errno::ENOENT,
                    "Can not replace route - no match found",
                ));
            }
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
    fn kernel_add4(&mut self, mut route: Route4, events: &mut Vec<Event>) {
        route.linkdown = route.scope != SCOPE_HOST && self.no_carrier.contains(&route.oif);
        self.create4(route.table);
        if let Ok(Some(flags)) = self.insert4(route.clone(), F_CREATE | F_APPEND) {
            events.push(Event::NewRoute4(route, flags));
        }
    }
    /// Removes the first of the IPv4 routes `route` names, as `fib_magic`
    /// does: whatever their metrics and gateway, and their priority where
    /// it names none (`fib_table_delete`, `fib_nh_match`).
    fn kernel_del4(&mut self, route: &Route4, events: &mut Vec<Event>) {
        let same = |r: &Route4| {
            r.table == route.table
                && r.dst == route.dst
                && r.len == route.len
                && r.tos == route.tos
                && r.kind == route.kind
                && r.scope == route.scope
                && r.prefsrc == route.prefsrc
                && r.proto == route.proto
                && r.oif == route.oif
                && (route.priority == 0 || r.priority == route.priority)
        };
        if let Some(i) = self.routes4.iter().position(same) {
            events.push(Event::DelRoute4(self.routes4.remove(i)));
        }
    }
    fn kernel_add6(&mut self, mut route: Route6, events: &mut Vec<Event>) {
        route.linkdown = route.kind != Kind::Local && self.no_carrier.contains(&route.oif);
        self.create6(route.table);
        if let Ok(flags) = self.insert6(route, None) {
            events.push(Event::NewRoute6(route, flags));
        }
    }
    fn kernel_del6(&mut self, route: &Route6, events: &mut Vec<Event>) {
        let same = |r: &&Route6| {
            Route6 {
                linkdown: false,
                ..**r
            } == Route6 {
                linkdown: false,
                ..*route
            }
        };
        if let Some(i) = self.routes6.iter().position(|r| same(&r)) {
            events.push(Event::DelRoute6(self.routes6.remove(i)));
        }
    }

    /// Adds the IPv4 route `ask` asks for, as `inet_rtm_newroute`: `EINVAL`
    /// for a prefix past 32 or with bits past its length
    /// (`rtm_to_fib_config`); then its table is made, whatever comes of it.
    /// `EINVAL` for a scope narrower than its
    /// kind's, a kind without a device that names one or a gateway, an
    /// unknown kind, the scope `RT_SCOPE_NOWHERE`, a gateway of host
    /// scope, an on-link route without a gateway, an invalid gateway or a
    /// preferred source that is not local; `ENODEV` for none but a
    /// gateway's; `ENETDOWN` while the device it names, or else `lo`, is
    /// down (`up` tells of each device, `lo` for 0), but for a route of
    /// host scope. A gateway's route goes through the device it names or
    /// else the one its gateway is reached through ([`Self::gateway4`]). A
    /// route through a veth end without its carrier is `RTNH_F_LINKDOWN`.
    /// Anycast, multicast and NAT routes are `EOPNOTSUPP`. The metrics'
    /// error comes after the scope's, as `fib_create_info` makes them.
    #[cfg(test)]
    pub(crate) fn add_route4(
        &mut self,
        ask: &Ask4,
        up: &dyn Fn(u32) -> bool,
    ) -> Result<Vec<Event>, Errno> {
        self.add_multipath4(ask, None, up)
    }
    /// [`Self::add_route4`], with the next hops of an `RTA_MULTIPATH`
    /// (`fib_get_nhs`): `EINVAL` for none, data after them, a hop
    /// `RTNH_F_DEAD` or `RTNH_F_LINKDOWN`, a first hop not of the
    /// request's `RTA_OIF` or `RTA_GATEWAY`, a kind that rejects, and
    /// more than one of host scope; each is checked as a route's next hop
    /// (`fib_check_nh`), of its own device, gateway and flags, with the
    /// request's flags past its first byte; and it is `RTNH_F_LINKDOWN`
    /// as a whole where each is.
    pub(crate) fn add_multipath4(
        &mut self,
        ask: &Ask4,
        multipath: Option<&Multipath4>,
        up: &dyn Fn(u32) -> bool,
    ) -> Result<Vec<Event>, Errno> {
        let added = self.insert_route4(ask, multipath, up);
        if added.is_ok() && ask.kind == Kind::Local.code() {
            self.custom_local4 = true;
        }
        added
    }
    /// [`Self::add_route4`], but for what it marks.
    fn insert_route4(
        &mut self,
        ask: &Ask4,
        multipath: Option<&Multipath4>,
        up: &dyn Fn(u32) -> bool,
    ) -> Result<Vec<Event>, Errno> {
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        prefix4(ask.dst, ask.len)?;
        self.create4(table);
        // `fib_props`' scope of each kind.
        let widest = match ask.kind {
            0 | 10 | 11 => SCOPE_NOWHERE,
            2 => SCOPE_HOST,
            3 | 4 => SCOPE_LINK,
            _ => SCOPE_UNIVERSE,
        };
        if widest > ask.scope {
            return Err(extack::message(Errno::EINVAL, "Invalid scope"));
        }
        if ask.flags & NEXTHOP_DEAD != 0 {
            return Err(extack::message(
                Errno::EINVAL,
                "Invalid rtm_flags - can not contain DEAD or LINKDOWN",
            ));
        }
        if let Some(multipath) = multipath {
            multipath.counted?;
        }
        let metrics = ask.metrics.map_err(extack::raise)?;
        // Each next hop a request of its own (`fib_get_nhs`).
        let nexthops: Vec<(Ask4, u16)> = match multipath {
            None => vec![(*ask, 1)],
            Some(multipath) => {
                let hops = multipath.hops.clone()?;
                let asks: Vec<(Ask4, u16)> = hops
                    .iter()
                    .map(|hop| {
                        (
                            Ask4 {
                                gateway: hop.gateway,
                                oif: hop.oif,
                                device: hop.device,
                                flags: (ask.flags & !0xff) | hop.flags,
                                ..*ask
                            },
                            hop.weight,
                        )
                    })
                    .collect();
                if let Some((first, _)) = asks.first() {
                    if ask.oif != 0 && first.oif != ask.oif {
                        return Err(extack::message(
                            Errno::EINVAL,
                            "Nexthop device index does not match RTA_OIF",
                        ));
                    }
                    if ask.gateway.is_some() && first.gateway != ask.gateway {
                        return Err(extack::message(
                            Errno::EINVAL,
                            "Nexthop gateway does not match RTA_GATEWAY or RTA_VIA",
                        ));
                    }
                }
                asks
            }
        };
        let kind = Kind::of(ask.kind).ok_or_else(|| {
            if matches!(ask.kind, 4 | 5 | 10 | 11) {
                EOPNOTSUPP
            } else {
                extack::message(Errno::EINVAL, "Invalid route type")
            }
        })?;
        let (first, weight) = nexthops[0];
        let onlink = first.flags & 4 != 0;
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
            gateway: first.gateway,
            oif: first.oif,
            onlink,
            linkdown: false,
            uses_gateway: false,
            metrics,
            weight,
            hops: Vec::new(),
            fib_flags: 0,
        };
        if kind.error().is_some() {
            if ask.gateway.is_some() || ask.oif != 0 || multipath.is_some() {
                return Err(extack::message(
                    Errno::EINVAL,
                    "Gateway, device and multipath can not be specified for this route type",
                ));
            }
            route.oif = 0;
        } else if ask.scope > SCOPE_HOST {
            return Err(extack::message(Errno::EINVAL, "Invalid scope"));
        } else if ask.scope == SCOPE_HOST {
            if nexthops.len() != 1 {
                return Err(extack::message(
                    Errno::EINVAL,
                    "Route with host scope can not have multiple nexthops",
                ));
            }
            if first.gateway.is_some() {
                return Err(extack::message(
                    Errno::EINVAL,
                    "Route with host scope can not have a gateway",
                ));
            }
            if !first.device {
                return Err(Errno::ENODEV);
            }
        } else {
            let mut hops = Vec::new();
            for (hop, weight) in &nexthops {
                hops.push(Hop4 {
                    weight: *weight,
                    ..self.check_nh4(hop, table, up)?
                });
            }
            if hops.len() > 1 {
                route.fib_flags = ask.flags;
                if hops.iter().all(|h| h.linkdown) {
                    route.fib_flags |= NEXTHOP_LINKDOWN;
                }
                route.hops = hops;
                route.first_again();
            } else {
                route = route.through(hops[0]);
            }
        }
        if let Some(source) = ask.prefsrc
            && !self.valid_prefsrc4(source, &route)
        {
            return Err(extack::message(Errno::EINVAL, "Invalid prefsrc address"));
        }
        Ok(self
            .insert4(route.clone(), ask.request)?
            .map(|flags| Event::NewRoute4(route, flags))
            .into_iter()
            .collect())
    }
    /// A next hop `ask` names, checked as `fib_check_nh` does: through
    /// its gateway ([`Self::gateway4`]); else `EINVAL` on link, `ENODEV`
    /// for no device, `ENETDOWN` while it is down, and `RTNH_F_LINKDOWN`
    /// without its carrier (`fib_check_nh_nongw`).
    fn check_nh4(&self, ask: &Ask4, table: u32, up: &dyn Fn(u32) -> bool) -> Result<Hop4, Errno> {
        let onlink = ask.flags & 4 != 0;
        let mut hop = Hop4 {
            gateway: ask.gateway,
            oif: ask.oif,
            onlink,
            linkdown: false,
            dead: false,
            uses_gateway: false,
            weight: 1,
        };
        if let Some(gateway) = ask.gateway {
            let (oif, uses_gateway) = self.gateway4(gateway, ask, table, up)?;
            hop.oif = oif;
            hop.uses_gateway = uses_gateway;
        } else if onlink {
            return Err(extack::message(
                Errno::EINVAL,
                "Invalid flags for nexthop - PERVASIVE and ONLINK can not be set",
            ));
        } else if !ask.device {
            return Err(Errno::ENODEV);
        } else if !up(ask.oif) {
            return Err(extack::message(ENETDOWN, "Device for nexthop is not up"));
        }
        hop.linkdown = self.no_carrier.contains(&hop.oif);
        Ok(hop)
    }
    /// Checks a gateway as `fib_check_nh_v4_gw`: on link, through the
    /// device the route names, up, for a route wider than link scope, it
    /// must be unicast ([`Self::gateway_type4`]); else a
    /// lookup of a narrower scope, through the device named if any, must
    /// reach it by a unicast or local route, in the route's table then the
    /// main one, its error as it is, and the device that route goes
    /// through must be up. That device, and whether a route of link scope
    /// reaches the gateway, so that the route's packets go to it
    /// (`rt_uses_gateway`).
    fn gateway4(
        &self,
        gateway: Ipv4Addr,
        ask: &Ask4,
        table: u32,
        up: &dyn Fn(u32) -> bool,
    ) -> Result<(u32, bool), Errno> {
        let invalid = |error| extack::message(error, "Nexthop has invalid gateway");
        if ask.flags & 4 != 0 {
            if ask.scope >= SCOPE_LINK {
                return Err(extack::message(Errno::EINVAL, "Nexthop has invalid scope"));
            }
            if !ask.device {
                return Err(extack::message(
                    Errno::ENODEV,
                    "Nexthop device required for onlink",
                ));
            }
            if !up(ask.oif) {
                return Err(extack::message(ENETDOWN, "Nexthop device is not up"));
            }
            if self.gateway_type4(gateway) != Kind::Unicast {
                return Err(invalid(Errno::EINVAL));
            }
            return Ok((ask.oif, true));
        }
        let scope = (ask.scope + 1).max(SCOPE_LINK);
        let mut found = Err(Errno::EAGAIN);
        let separate = table != TABLE_MAIN && self.tables4.contains(&table);
        if separate {
            found = self.table_lookup4(Self::trie(table), gateway, scope, ask.oif, 0);
        }
        if !separate || found.is_err() {
            found = self.lookup4_in(gateway, scope, ask.oif, 0);
        }
        let via = found.map_err(invalid)?;
        if !matches!(via.kind, Kind::Unicast | Kind::Local) {
            return Err(invalid(Errno::EINVAL));
        }
        if !up(via.oif) {
            return Err(ENETDOWN);
        }
        Ok((via.oif, via.scope == SCOPE_LINK))
    }
    /// What an on-link gateway `ip` is (`inet_addr_type_dev_table`, which
    /// takes the local table and no device): a broadcast one for 0.0.0.0,
    /// the limited broadcast address or no local table, a group
    /// multicast, else the kind of the route the local table's trie has to
    /// it, through any device, and unicast where it has none.
    fn gateway_type4(&self, ip: Ipv4Addr) -> Kind {
        if ip.is_unspecified() || ip.is_broadcast() || !self.tables4.contains(&TABLE_LOCAL) {
            return Kind::Broadcast;
        }
        if ip.is_multicast() {
            return Kind::Multicast;
        }
        self.table_lookup4(Self::trie(TABLE_LOCAL), ip, SCOPE_UNIVERSE, 0, 0)
            .map_or(Kind::Unicast, |r| r.kind)
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
    /// Removes the IPv4 route `select` names, as `fib_table_delete`; a
    /// device or gateway it names is its first next hop's, else its
    /// `RTA_MULTIPATH`'s next hops are its own ([`multipath_matches4`]):
    /// `EINVAL` for a prefix past 32 or with bits past its length, then
    /// `ESRCH` for a table there is not, or no such route. A route must have
    /// the metrics `select` names (`fib_metrics_match`).
    pub(crate) fn del_route4(&mut self, select: &Select4) -> Result<Vec<Event>, Errno> {
        let table = if select.table == 0 {
            TABLE_MAIN
        } else {
            select.table
        };
        // `rtm_to_fib_config` checks the prefix before the table is
        // looked for.
        prefix4(select.dst, select.len)?;
        if !self.tables4.contains(&table) {
            return Err(extack::message(ESRCH, "FIB table does not exist"));
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
                    && (select.oif == 0 || r.oif == select.oif)
                    && select.gateway.is_none_or(|g| r.gateway == Some(g))
                    && (select.oif != 0
                        || select.gateway.is_some()
                        || select
                            .multipath
                            .as_ref()
                            .is_none_or(|hops| multipath_matches4(r, hops)))
                    && select
                        .metrics
                        .as_ref()
                        .is_some_and(|m| m.iter().all(|&(i, v)| r.metrics[i] == v))
            })
            .map(|(i, _)| i)
            .ok_or(ESRCH)?;
        Ok(vec![Event::DelRoute4(self.routes4.remove(at))])
    }
    /// Adds the IPv6 route `ask` asks for, as `inet6_rtm_newroute`
    /// (`fib6_nh_init`): a metric of 0 is 1024; `EINVAL` for a prefix past
    /// 128; `ENODEV` for a device named that is not there or has no IPv6;
    /// for an on-link one, `ENODEV` without a device and `ENETDOWN` while
    /// it is down. A rejecting route goes through `lo`, with no gateway;
    /// another's gateway is checked ([`Self::gateway6`]), which finds its
    /// device where none is named, then `ENODEV` for no device, `EACCES`
    /// for one with IPv6 off and `ENETDOWN` for one down; `EINVAL` for a
    /// preferred source that is not local. Its destination is taken to its
    /// prefix's length. Broadcast, anycast, multicast and NAT routes are
    /// `EOPNOTSUPP`. One with a gateway joins another of its prefix and
    /// metric with one as a multipath sibling, told of with its hops.
    pub(crate) fn add_route6(&mut self, ask: &Ask6, up: bool) -> Result<Vec<Event>, Errno> {
        let route = self.make_route6(ask, up)?;
        let flags = self.insert6(route, Some(ask.request))?;
        // `inet6_rt_notify`: with its siblings, where it has some.
        Ok(vec![self.new_route6(route, flags)])
    }
    /// What Linux tells of `route` added, with `flags`: it, or the
    /// multipath route it is of, its hops from it on.
    fn new_route6(&self, route: Route6, flags: u16) -> Event {
        let hops = self.hops6(&route);
        if hops.is_empty() {
            Event::NewRoute6(route, flags)
        } else {
            Event::NewMultipath6(hops, flags)
        }
    }
    /// Adds a multipath route of the next hops `hops`, each a request
    /// ([`Self::add_route6`]) with whether its device is up and its
    /// weight, as `ip6_route_multipath_add` does: each is made and checked
    /// first (`ip6_route_info_create`), two of the same device and gateway
    /// being `EEXIST` (`ip6_route_info_append`); then each is put in its
    /// table in turn, those after the first with `NLM_F_CREATE` and
    /// without `NLM_F_EXCL` and `NLM_F_REPLACE`. One message tells of
    /// them, with `NLM_F_REPLACE` or `NLM_F_CREATE` and the request's
    /// `NLM_F_APPEND`: from the first put in, or with `NLM_F_APPEND` from
    /// the first of the last one's siblings (`ip6_route_mpath_notify`).
    /// Where one fails to go in, those put in are told of so, then go,
    /// each told of (`fib6_del`), before the error.
    pub(crate) fn add_multipath6(
        &mut self,
        hops: &[(Ask6, bool, u16)],
    ) -> (Vec<Event>, Result<(), Errno>) {
        let mut routes: Vec<Route6> = Vec::new();
        for (ask, up, weight) in hops {
            let mut route = match self.make_route6(ask, *up) {
                Ok(route) => route,
                Err(e) => return (Vec::new(), Err(e)),
            };
            route.weight = *weight;
            if routes
                .iter()
                .any(|r| r.oif == route.oif && r.gateway == route.gateway)
            {
                return (Vec::new(), Err(Errno::EEXIST));
            }
            routes.push(route);
        }
        let Some((first, _, _)) = hops.first() else {
            return (Vec::new(), Ok(()));
        };
        let mut flags = first.request;
        let told = (if flags & F_REPLACE != 0 {
            F_REPLACE
        } else {
            F_CREATE
        }) | (flags & F_APPEND);
        let mut added = Vec::new();
        let mut failed = None;
        for route in routes {
            match self.insert6(route, Some(flags)) {
                Ok(_) => added.push(route),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
            flags = (flags & !(F_EXCL | F_REPLACE)) | F_CREATE;
        }
        let mut events = Vec::new();
        if let (Some(&notified), Some(last)) = (added.first(), added.last()) {
            let notified = if told & F_APPEND != 0 {
                self.hops6(last).get(1).copied().unwrap_or(notified)
            } else {
                notified
            };
            events.push(self.new_route6(notified, told));
        }
        let Some(error) = failed else {
            return (events, Ok(()));
        };
        for route in added {
            if let Some(at) = self.routes6.iter().position(|r| *r == route) {
                events.push(Event::DelRoute6(self.routes6.remove(at)));
            }
        }
        (events, Err(error))
    }
    /// The route `ask` asks for, made and checked as [`Self::add_route6`]
    /// tells, its table made, not yet put in.
    fn make_route6(&mut self, ask: &Ask6, up: bool) -> Result<Route6, Errno> {
        if ask.len > 128 {
            return Err(Errno::EINVAL);
        }
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        self.create6(table);
        let metrics = ask.metrics.map_err(extack::raise)?;
        let kind = match ask.kind {
            0 => Kind::Unicast,
            code => Kind::of(code)
                .filter(|k| *k != Kind::Broadcast)
                .ok_or(EOPNOTSUPP)?,
        };
        // `fib6_nh_init`: a device named needs IPv6 (`in6_dev_get`), even
        // for a rejecting route.
        if ask.oif != 0 && (!ask.device || ask.ipv6_off.is_none()) {
            return Err(Errno::ENODEV);
        }
        if ask.onlink {
            if ask.oif == 0 {
                return Err(extack::message(
                    Errno::ENODEV,
                    "Nexthop device required for onlink",
                ));
            }
            if !up {
                return Err(extack::message(ENETDOWN, "Nexthop device is not up"));
            }
        }
        // A rejecting route takes no gateway; another's names its device
        // where the request does not, which a route of the namespace
        // reaches, so that it is up with IPv6 on.
        let mut oif = ask.oif;
        let mut gateway = None;
        if kind.error().is_none() {
            if let Some(via) = ask.gateway {
                oif = self.gateway6(via, ask, table)?;
                gateway = Some(via);
            }
            if oif == 0 {
                return Err(Errno::ENODEV);
            }
            if ask.oif != 0 {
                // Then that it is on, then whether it is up.
                match ask.ipv6_off {
                    None => return Err(Errno::ENODEV),
                    Some(true) => {
                        return Err(extack::message(
                            Errno::EACCES,
                            "IPv6 is disabled on nexthop device",
                        ));
                    }
                    Some(false) => {}
                }
                if !up {
                    return Err(extack::message(ENETDOWN, "Nexthop device is not up"));
                }
            }
        } else {
            // A rejecting one's is `lo` (`ip6_route_info_create`).
            oif = LOOPBACK_OIF;
        }
        if let Some(source) = ask.prefsrc
            && !self.local6(source)
        {
            return Err(extack::message(Errno::EINVAL, "Invalid source address"));
        }
        // Through the device asked or found, `lo` or a veth end
        // (`fib6_nh_init`), `RTNH_F_LINKDOWN` where it has no carrier.
        let route = Route6 {
            oif,
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
            expires: None,
            linkdown: kind.error().is_none()
                && kind != Kind::Local
                && self.no_carrier.contains(&oif),
            gateway,
            onlink: ask.onlink,
            dead: false,
            weight: 1,
        };
        Ok(route)
    }
    /// The device of a route's gateway `via` (`ip6_validate_gw`), the one
    /// `ask` names or else the one a route to it goes through; `EINVAL`,
    /// told of, for an address of the namespace (on that device, for a
    /// link-local one), the unspecified address or a group, an on-link
    /// gateway the main table has a route to of a kind that is not
    /// unicast nor rejecting, no device, or `lo`. A gateway not link-local
    /// and not on link needs a route to it through that device, without a
    /// gateway, that does not reject (`ip6_route_check_nh`): the table's
    /// asked for, else the local and main tables'; `EHOSTUNREACH` for
    /// none.
    fn gateway6(&self, via: Ipv6Addr, ask: &Ask6, table: u32) -> Result<u32, Errno> {
        let invalid = |text| extack::message(Errno::EINVAL, text);
        let first = via.segments()[0];
        let link_local = !via.is_multicast() && first & 0xffc0 == 0xfe80;
        // `ipv6_chk_addr_and_flags`: any device's address, or a
        // link-local one of the device's, not tentative.
        let local = |oif: u32| {
            self.v6.iter().any(|a| {
                a.address == via && !a.tentative() && (!link_local || a.index.unsigned_abs() == oif)
            })
        };
        let gone = invalid("Gateway can not be a local address");
        if ask.oif != 0 && local(ask.oif) {
            return Err(gone);
        }
        let mut oif = ask.oif;
        if !link_local {
            if via.is_unspecified() || via.is_multicast() {
                return Err(invalid("Invalid gateway address"));
            }
            if ask.onlink {
                // `ip6_route_check_nh_onlink`.
                if let Some(found) = self.table_lookup6(TABLE_MAIN, via)
                    && found.kind.error().is_none()
                    && found.kind != Kind::Unicast
                {
                    return Err(invalid("Nexthop has invalid gateway"));
                }
            } else {
                let usable = |r: &Route6| r.kind.error().is_none() && r.gateway.is_none();
                let in_table = (ask.table != 0 && self.tables6.contains(&table))
                    .then(|| self.lookup6_in(table, via, ask.oif, &Flow6::default()))
                    .flatten()
                    .filter(|r| usable(r));
                let found = match in_table {
                    Some(found) => found,
                    None => self
                        .lookup6_on(via, ask.oif)
                        .ok()
                        .filter(|r| usable(r))
                        .ok_or(EHOSTUNREACH)?,
                };
                if ask.oif == 0 {
                    oif = found.oif;
                } else if found.oif != ask.oif {
                    return Err(EHOSTUNREACH);
                }
            }
        }
        if oif == 0 {
            return Err(invalid("Egress device not specified"));
        }
        if oif == LOOPBACK_OIF {
            return Err(invalid(
                "Egress device can not be loopback device for this route",
            ));
        }
        if ask.oif == 0 && local(oif) {
            return Err(gone);
        }
        Ok(oif)
    }
    /// Removes the first IPv6 route of `ask`'s table to its prefix of its
    /// metric and protocol, of any kind (`ip6_route_del`): `ESRCH` for
    /// none. Without a gateway, one of a multipath route takes its
    /// siblings with it, told of in one message
    /// (`__ip6_del_rt_siblings`); with one, only that next hop goes.
    pub(crate) fn del_route6(&mut self, ask: &Ask6) -> Result<Vec<Event>, Errno> {
        self.del_route6_hops(ask, true)
    }
    /// Removes each next hop of `hops` as [`Self::del_route6`] does, but
    /// without its siblings (`ip6_route_multipath_del`): what each tells,
    /// and the last error.
    pub(crate) fn del_multipath6(&mut self, hops: &[Ask6]) -> (Vec<Event>, Result<(), Errno>) {
        let mut events = Vec::new();
        let mut result = Ok(());
        for ask in hops {
            match self.del_route6_hops(ask, false) {
                Ok(told) => events.extend(told),
                Err(e) => result = Err(e),
            }
        }
        (events, result)
    }
    /// [`Self::del_route6`], the siblings too with `all` and no gateway
    /// (`fc_delete_all_nh`).
    fn del_route6_hops(&mut self, ask: &Ask6, all: bool) -> Result<Vec<Event>, Errno> {
        let table = if ask.table == 0 {
            TABLE_MAIN
        } else {
            ask.table
        };
        if !self.tables6.contains(&table) {
            return Err(extack::message(ESRCH, "FIB table does not exist"));
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
                    && (ask.oif == 0 || r.oif == ask.oif)
                    && ask
                        .gateway
                        .is_none_or(|g| r.gateway.unwrap_or(Ipv6Addr::UNSPECIFIED) == g)
            })
            .ok_or(ESRCH)?;
        let hops = self.hops6(&self.routes6[at]);
        if ask.gateway.is_some() || hops.is_empty() || !all {
            return Ok(vec![Event::DelRoute6(self.routes6.remove(at))]);
        }
        let first = self.routes6[at];
        self.routes6.retain(|r| !r.sibling_of(&first));
        Ok(vec![Event::DelMultipath6(hops)])
    }

    /// The IPv4 routes, as a dump gives them: table by table
    /// ([`table_order`]), each in its trie's order.
    pub(crate) fn dump4(&self) -> Vec<Route4> {
        table_order(&self.tables4)
            .into_iter()
            .flat_map(|t| self.routes4.iter().filter(move |r| r.table == t).cloned())
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
    /// The next hops of the multipath route `route` is one of, as
    /// `rt6_fill_node` puts them in `RTA_MULTIPATH`: it, then its
    /// siblings (`fib6_siblings`) in the order they came in, from the one
    /// after it, round to the one before; none where it has no sibling.
    pub(crate) fn hops6(&self, route: &Route6) -> Vec<Route6> {
        let mut hops: Vec<Route6> = self
            .routes6
            .iter()
            .filter(|r| r.sibling_of(route))
            .copied()
            .collect();
        if hops.len() < 2 {
            return Vec::new();
        }
        let at = hops.iter().position(|r| r == route).unwrap_or(0);
        hops.rotate_left(at);
        hops
    }
    /// The IPv6 routes as a dump tells of them, each with its next hops
    /// ([`Self::hops6`]): a multipath route once, as its first sibling,
    /// the walk going on after its last (`fib6_dump_node`), which passes
    /// over any route of its metric between them.
    pub(crate) fn dump6_entries(&self) -> Vec<(Route6, Vec<Route6>)> {
        let routes = self.dump6();
        let mut entries = Vec::new();
        let mut at = 0;
        while let Some(&route) = routes.get(at) {
            let hops = self.hops6(&route);
            at = if hops.is_empty() {
                at + 1
            } else {
                routes
                    .iter()
                    .rposition(|r| r.sibling_of(&route))
                    .map_or(at + 1, |last| last + 1)
            };
            entries.push((route, hops));
        }
        entries
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
    /// has a route of no TOS or the flow's `tos` (its legacy TOS bits,
    /// `fib_dscp_masked_match`), of `scope` or narrower and through `oif`
    /// (any for 0), the first such of it; a rejecting one's error; `EAGAIN`
    /// for none. A table not named in [`Self::trie`] is looked in alone.
    fn table_lookup4(
        &self,
        tables: &[u32],
        ip: Ipv4Addr,
        scope: u8,
        oif: u32,
        tos: u8,
    ) -> Result<Route4, Errno> {
        for len in (0..=32u8).rev() {
            let dst = Ipv4Addr::from(u32::from(ip) & mask4(len));
            for r in self
                .routes4
                .iter()
                .filter(|r| r.dst == dst && r.len == len && tables.contains(&r.table))
            {
                if (r.tos != 0 && r.tos != tos & TOS_LEGACY) || r.scope < scope {
                    continue;
                }
                if let Some(e) = r.kind.error() {
                    return Err(e);
                }
                if r.hops.is_empty() {
                    if oif != 0 && r.oif != oif {
                        continue;
                    }
                    return Ok(r.clone());
                }
                // `fib_lookup_good_nhc`: the first next hop not dead,
                // through `oif` where one is named.
                if let Some(&hop) = r
                    .hops
                    .iter()
                    .find(|h| !h.dead && (oif == 0 || h.oif == oif))
                {
                    return Ok(r.through(hop));
                }
            }
        }
        Err(Errno::EAGAIN)
    }
    /// A lookup as `fib_lookup` makes it while there is no policy rule:
    /// the local and main tables' trie, then, where that gives `EAGAIN`,
    /// the default table if there is one; `EAGAIN` at the end is
    /// `ENETUNREACH`.
    fn lookup4_in(&self, ip: Ipv4Addr, scope: u8, oif: u32, tos: u8) -> Result<Route4, Errno> {
        let mut found = self.table_lookup4(Self::trie(TABLE_MAIN), ip, scope, oif, tos);
        if found == Err(Errno::EAGAIN) && self.tables4.contains(&TABLE_DEFAULT) {
            found = self.table_lookup4(Self::trie(TABLE_DEFAULT), ip, scope, oif, tos);
        }
        found.map_err(|e| if e == Errno::EAGAIN { ENETUNREACH } else { e })
    }
    /// The route to `ip`, as an output route's lookup takes it.
    pub(crate) fn lookup4(&self, ip: Ipv4Addr) -> Result<Route4, Errno> {
        self.lookup4_in(ip, SCOPE_UNIVERSE, 0, 0)
    }
    /// The route to `ip` of a flow of `tos` through `oif` (any for 0).
    pub(crate) fn lookup4_flow(&self, ip: Ipv4Addr, tos: u8, oif: u32) -> Result<Route4, Errno> {
        self.lookup4_in(ip, SCOPE_UNIVERSE, oif, tos)
    }
    /// The route a packet of `tos` to `ip` from `src` (none for a source not
    /// chosen yet) leaves by, through `oif` where one is named, as
    /// `ip_route_output_key_hash_rcu` finds it: [`Self::lookup4_flow`]'s,
    /// of a multipath one the hop [`Self::path4`] takes, but where `oif`
    /// is named, which chooses the hop itself (`fib_select_path`). The
    /// devices come in `order`, as [`Self::select4`] takes them.
    pub(crate) fn output4(
        &self,
        ip: Ipv4Addr,
        tos: u8,
        oif: u32,
        src: Option<Ipv4Addr>,
        order: &[i32],
    ) -> Result<Route4, Errno> {
        let route = self.lookup4_flow(ip, tos, oif)?;
        if oif != 0 || route.kind == Kind::Local {
            return Ok(route);
        }
        let src = src.unwrap_or(Ipv4Addr::UNSPECIFIED);
        Ok(self.path4(route, ip, src, Some(order)))
    }
    /// The route `matched` of a packet from `src` to `ip`, of a multipath
    /// one the next hop `fib_select_multipath` takes by the hash of the two
    /// (`fib_multipath_hash`, of `fib_multipath_hash_policy` 0): each hop
    /// takes the share of the hashes its weight gives it, in their order, a
    /// dead one none (`fib_rebalance`). One whose device's own source
    /// ([`Self::select4`], `nh_saddr`) is `src` comes before the others,
    /// then the first that takes the hash; with no `src`, and for a
    /// forwarded packet (no `order`), only the hash counts.
    pub(crate) fn path4(
        &self,
        matched: Route4,
        ip: Ipv4Addr,
        src: Ipv4Addr,
        order: Option<&[i32]>,
    ) -> Route4 {
        let total: u64 = matched
            .hops
            .iter()
            .filter(|h| !h.dead)
            .map(|h| u64::from(h.weight))
            .sum();
        if total == 0 {
            return matched;
        }
        // Shifted down a bit, as `fib_multipath_hash` gives it.
        let hash =
            (core::hash::BuildHasher::hash_one(&self.multipath_seed, (src, ip)) & 0xffff_ffff) >> 1;
        let order = order.filter(|_| !src.is_unspecified());
        let mut weight = 0u64;
        let mut best: Option<(u8, Hop4)> = None;
        for &hop in matched.hops.iter().filter(|h| !h.dead) {
            weight += u64::from(hop.weight);
            // `fib_rebalance`: `DIV_ROUND_CLOSEST_ULL(weight << 31, total)
            // - 1`, the last hash the hop takes.
            let takes = hash < ((weight << 31) + total / 2) / total;
            let own = order.is_some_and(|order| {
                i32::try_from(hop.oif).is_ok_and(|index| {
                    self.select4(index, hop.gateway, matched.scope, order) == Some(src)
                })
            });
            let score = 2 * u8::from(own) + u8::from(takes);
            if best.is_none_or(|(held, _)| held < score) {
                best = Some((score, hop));
                if score == 3 || order.is_none() && score == 1 {
                    break;
                }
            }
        }
        match best {
            Some((_, hop)) => matched.through(hop),
            None => matched,
        }
    }
    /// Whether a packet in on `lo` from `src` may come, as
    /// `fib_validate_source` checks it with reverse path filtering off, as
    /// a namespace has it: from none of the namespace's addresses; or,
    /// once a request has added a local route, from a source a lookup
    /// finds no route to or a unicast one (`__fib_validate_source`).
    pub(crate) fn valid_source4(&self, src: Ipv4Addr) -> bool {
        if !self.custom_local4 {
            return !self.v4.iter().any(|a| a.local == src);
        }
        self.lookup4(src)
            .ok()
            .is_none_or(|route| route.kind == Kind::Unicast)
    }
    /// `fib_validate_source` for a packet in on device `dev` from `src` of
    /// `tos`, whose route goes out through `oif` (0 for one that is not
    /// forwarded), with reverse path filtering `rpf` (`IN_DEV_RPFILTER`):
    /// `Err` for a source it drops; `Ok(true)` where the reverse route is
    /// one through `dev` of host scope or narrower, as a forwarded one that
    /// goes out where it came in asks to redirect.
    /// - With `rpf` 0 and a route that is not out through `dev`, as
    ///   [`Self::valid_source4`].
    /// - Else as `__fib_validate_source`, looking `src` up. None found is
    ///   dropped with `rpf`, and taken without; a local one is dropped
    ///   (`accept_local` is 0), as is one of another kind than unicast. A
    ///   unicast one through `dev`, by any of a multipath one's next hops
    ///   (`fib_info_nh_uses_dev`), is taken, `true` but for one whose first
    ///   next hop not dead is a gateway, of link scope. One through another
    ///   device is taken without `rpf`, or loosely (2), when `dev` has no
    ///   address, else dropped strictly (1); loosely, a lookup through
    ///   `dev` decides, as the first one did, and gives `false` where it
    ///   finds no unicast route.
    pub(crate) fn validate_source4_on(
        &self,
        src: Ipv4Addr,
        tos: u8,
        oif: u32,
        rpf: i32,
        dev: i32,
    ) -> Result<bool, ()> {
        let dev_oif = u32::try_from(dev).unwrap_or(0);
        if rpf == 0 && oif != dev_oif {
            return if self.valid_source4(src) {
                Ok(false)
            } else {
                Err(())
            };
        }
        let last_resort = if rpf != 0 { Err(()) } else { Ok(false) };
        match self.lookup4_flow(src, tos, 0) {
            Err(_) => last_resort,
            Ok(route) if route.kind != Kind::Unicast => Err(()),
            Ok(route) if route.oif == dev_oif || route.hops.iter().any(|h| h.oif == dev_oif) => {
                Ok(route.gateway.is_none())
            }
            Ok(_) if !self.v4.iter().any(|a| a.index == dev) => last_resort,
            Ok(_) if rpf == 1 => Err(()),
            Ok(_) => Ok(self
                .lookup4_flow(src, tos, dev_oif)
                .is_ok_and(|r| r.kind == Kind::Unicast && r.gateway.is_none())),
        }
    }
    /// Whether `ip` is the loopback's (`__ip_dev_find`): one of its
    /// addresses, or else local to the local table's routes.
    pub(crate) fn is_local4(&self, ip: Ipv4Addr) -> bool {
        self.v4.iter().any(|a| a.local == ip) || self.addr_type4(ip, TABLE_LOCAL) == Kind::Local
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
        self.table_lookup4(tables, ip, SCOPE_UNIVERSE, 0, 0)
            .map_or(Kind::Unicast, |r| r.kind)
    }
    /// The address a route to `ip` leaves from (`fib_select_path`): a
    /// local route's preferred source or `ip`; another's preferred source,
    /// else [`Self::select4`] on its device for its gateway and scope, the
    /// devices in the order they were made, `order`.
    pub(crate) fn source4(&self, route: &Route4, ip: Ipv4Addr, order: &[i32]) -> Option<Ipv4Addr> {
        if route.kind == Kind::Local {
            return Some(route.prefsrc.unwrap_or(ip));
        }
        if route.prefsrc.is_some() {
            return route.prefsrc;
        }
        let index = i32::try_from(route.oif).unwrap_or(LOOPBACK_INDEX);
        self.select4(index, route.gateway, route.scope, order)
    }
    /// The address `inet_select_addr` picks on the device of `index` for
    /// `dst` (any for `None`) of `scope`: the first of its primary
    /// addresses of a scope as narrow (host at most, as no device routes
    /// its local net), one in `dst`'s subnet before the others; else the
    /// first primary one not of link scope of the devices in `order`, the
    /// order they were made in (`dev_base_head`'s, `lo` first); `None` for
    /// none.
    pub(crate) fn select4(
        &self,
        index: i32,
        dst: Option<Ipv4Addr>,
        scope: u8,
        order: &[i32],
    ) -> Option<Ipv4Addr> {
        let mut first = None;
        for a in self
            .v4
            .iter()
            .filter(|a| a.index == index && !a.secondary())
        {
            if a.scope.min(SCOPE_HOST) > scope {
                continue;
            }
            if dst.is_none_or(|d| a.covers(d)) {
                return Some(a.local);
            }
            first.get_or_insert(a.local);
        }
        first.or_else(|| {
            order.iter().find_map(|&device| {
                self.v4
                    .iter()
                    .find(|a| {
                        a.index == device
                            && !a.secondary()
                            && a.scope != SCOPE_LINK
                            && a.scope <= scope
                    })
                    .map(|a| a.local)
            })
        })
    }
    /// A lookup in one IPv6 table: the route of the longest prefix that has
    /// `ip`, the lowest metric first.
    fn table_lookup6(&self, table: u32, ip: Ipv6Addr) -> Option<Route6> {
        self.lookup6_in(table, ip, 0, &Flow6::default())
    }
    /// The route of `table` to `ip` through the device `oif`, any for 0
    /// (`RT6_LOOKUP_F_IFACE`): the longest prefix's, of the lowest metric,
    /// passing over a dead multipath hop (`RTNH_F_DEAD`); of a multipath
    /// route, the hop the flow `flow` takes ([`Self::path6`]).
    fn lookup6_in(&self, table: u32, ip: Ipv6Addr, oif: u32, flow: &Flow6) -> Option<Route6> {
        self.routes6
            .iter()
            .filter(|r| r.table == table && r.covers(ip) && (oif == 0 || r.oif == oif) && !r.dead)
            .min_by_key(|r| (Reverse(r.len), r.metric))
            .map(|r| self.path6(*r, ip, oif, flow))
    }
    /// [`Self::lookup6_in`], not strict: through the device `oif` only
    /// rather than another, among the routes of the longest prefix and the
    /// lowest metric (`rt6_score_route`); one through it is no other hop of
    /// its multipath route (`have_oif_match`).
    fn lookup6_in_preferring(
        &self,
        table: u32,
        ip: Ipv6Addr,
        oif: u32,
        flow: &Flow6,
    ) -> Option<Route6> {
        let matched = self
            .routes6
            .iter()
            .filter(|r| r.table == table && r.covers(ip) && !r.dead)
            .min_by_key(|r| (Reverse(r.len), r.metric, r.oif != oif))?;
        Some(if matched.oif == oif {
            *matched
        } else {
            self.path6(*matched, ip, 0, flow)
        })
    }
    /// The hop of the multipath route of `matched` a flow to `ip` takes,
    /// as `fib6_select_path` chooses it: by the flow's hash, each hop
    /// taking the share of the hashes its weight gives it, in the order
    /// of its siblings, a dead one none (`rt6_multipath_rebalance`); the
    /// first that takes the hash, unless it is not through `oif`, the
    /// device of a strict lookup (`rt6_score_route`), when `matched`.
    fn path6(&self, matched: Route6, ip: Ipv6Addr, oif: u32, flow: &Flow6) -> Route6 {
        let first = self
            .routes6
            .iter()
            .find(|r| r.sibling_of(&matched))
            .copied()
            .unwrap_or(matched);
        let hops = self.hops6(&first);
        if hops.is_empty() {
            return matched;
        }
        let total: u64 = hops
            .iter()
            .filter(|r| !r.dead)
            .map(|r| u64::from(r.weight))
            .sum();
        if total == 0 {
            return matched;
        }
        // `rt6_multipath_hash`: of the flow's addresses, label and
        // protocol, shifted down a bit.
        let key = (
            flow.src.unwrap_or(Ipv6Addr::UNSPECIFIED),
            ip,
            flow.label,
            flow.proto,
        );
        let hash = i64::from(
            u32::try_from(
                core::hash::BuildHasher::hash_one(&self.multipath_seed, key) & u64::from(u32::MAX),
            )
            .unwrap_or(0)
                >> 1,
        );
        let mut weight = 0u64;
        for hop in hops {
            if hop.dead {
                continue;
            }
            weight += u64::from(hop.weight);
            // `rt6_upper_bound_set`: `DIV_ROUND_CLOSEST_ULL(weight << 31,
            // total) - 1`.
            let bound = i64::try_from(((weight << 31) + total / 2) / total).unwrap_or(i64::MAX) - 1;
            if hash > bound {
                continue;
            }
            return if oif == 0 || hop.oif == oif {
                hop
            } else {
                matched
            };
        }
        matched
    }
    /// The IPv6 route to `ip` (`fib6_rule_lookup`): the local table's, then
    /// the main one's, where the first has none or a throw route; a
    /// rejecting route's error; `ENETUNREACH` for none.
    pub(crate) fn lookup6(&self, ip: Ipv6Addr) -> Result<Route6, Errno> {
        self.lookup6_on(ip, 0)
    }
    /// The IPv6 route to `ip` through the device `oif`, as
    /// [`Self::lookup6`] finds one through any for 0.
    pub(crate) fn lookup6_on(&self, ip: Ipv6Addr, oif: u32) -> Result<Route6, Errno> {
        self.lookup6_flow(ip, oif, &Flow6::default())
    }
    /// The IPv6 route to `ip` through the device `oif` (any for 0) of the
    /// flow `flow`, as [`Self::lookup6_on`] finds it, the hop of a
    /// multipath route it takes ([`Self::path6`]).
    pub(crate) fn lookup6_flow(
        &self,
        ip: Ipv6Addr,
        oif: u32,
        flow: &Flow6,
    ) -> Result<Route6, Errno> {
        Self::first6(|table| self.lookup6_in(table, ip, oif, flow))
    }
    /// [`Self::lookup6_flow`], not strict: through the device `oif` rather
    /// than another ([`Self::lookup6_in_preferring`]).
    pub(crate) fn lookup6_preferring(
        &self,
        ip: Ipv6Addr,
        oif: u32,
        flow: &Flow6,
    ) -> Result<Route6, Errno> {
        Self::first6(|table| self.lookup6_in_preferring(table, ip, oif, flow))
    }
    /// The route `lookup` finds in the local table, then in the main one,
    /// where the first has none or a throw route; a rejecting route's
    /// error; `ENETUNREACH` for none.
    fn first6(lookup: impl Fn(u32) -> Option<Route6>) -> Result<Route6, Errno> {
        for table in [TABLE_LOCAL, TABLE_MAIN] {
            if let Some(route) = lookup(table) {
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
    /// The device that has the IPv4 address `ip` (`__ip_dev_find`, by its
    /// addresses only), if any.
    pub(crate) fn device_of4(&self, ip: Ipv4Addr) -> Option<i32> {
        self.v4.iter().find(|a| a.local == ip).map(|a| a.index)
    }
    /// Whether `ip` is an IPv4 address of the loopback's, as a local route
    /// gives it.
    pub(crate) fn local4(&self, ip: Ipv4Addr) -> bool {
        self.tables4.contains(&TABLE_LOCAL) && self.addr_type4(ip, TABLE_LOCAL) == Kind::Local
    }
    /// Whether `ip` is an IPv6 address of this namespace's, and not
    /// tentative: one that `ipv6_chk_addr` finds, banning
    /// `IFA_F_TENTATIVE`, as a bind (`__inet6_bind`) and a packet's
    /// arrival (its local route, made once detection is done) need.
    pub(crate) fn local6(&self, ip: Ipv6Addr) -> bool {
        self.v6.iter().any(|a| a.address == ip && !a.tentative())
    }
    /// Whether `ip` is an address here, not tentative, that a socket on the
    /// device `index` may bind (`ipv6_chk_addr` without `strict`): one of
    /// global scope of any device, a link-local or loopback one only of
    /// that device.
    pub(crate) fn local6_on(&self, ip: Ipv6Addr, index: i32) -> bool {
        let scoped = ip.is_loopback() || ip.segments()[0] & 0xffc0 == 0xfe80;
        self.v6
            .iter()
            .any(|a| a.address == ip && !a.tentative() && (!scoped || a.index == index))
    }
    /// Whether `ip` is an address of the veth end `index`, not tentative,
    /// as `ndisc_recv_ns` answers a solicitation for it there
    /// (`ipv6_get_ifaddr`, strictly on the device).
    pub(crate) fn nd_target(&self, index: i32, ip: Ipv6Addr) -> bool {
        self.v6
            .iter()
            .any(|a| a.index == index && a.address == ip && !a.tentative())
    }
    /// The address a neighbour solicitation out through the veth end
    /// `index` leaves from, for a packet from `from` (`ndisc_solicit`): that
    /// one, if the end has it and it is not tentative; else the end's
    /// link-local one (`ipv6_get_lladdr`, walking its addresses backwards: the
    /// oldest not tentative); else
    /// none, and no solicitation goes.
    pub(crate) fn ns_source(&self, index: i32, from: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        if let Some(from) = from
            && self.nd_target(index, from)
        {
            return Some(from);
        }
        self.v6
            .iter()
            .rev()
            .find(|a| a.index == index && a.scope() == SCOPE_LINK && !a.tentative())
            .map(|a| a.address)
    }
    /// The address `ipv6_dev_get_saddr` picks for a packet to `ip` out
    /// through the device `oif`: of the addresses not tentative on that
    /// device for a multicast or link-local `ip`, else on every device in
    /// `order`, each device's in its list's order (`ipv6_link_dev_addr`:
    /// the widest scope first, the newest first within one), by these of
    /// its rules: `ip` itself, the
    /// narrowest scope as wide as `ip`'s (else the widest), not
    /// deprecated, on `oif`, the same label, then the longest prefix
    /// shared, up to the address's own; the first of the best. A group's
    /// scope is its scope nibble (`ipv6_addr_scope2type`). `None` for
    /// none (`EADDRNOTAVAIL`).
    pub(crate) fn select6(&self, oif: i32, ip: Ipv6Addr, order: &[i32]) -> Option<Ipv6Addr> {
        let scope = |a: Ipv6Addr| -> i32 {
            if a.is_multicast() {
                i32::from(a.segments()[0] & 0xf)
            } else if a.is_loopback() || a.segments()[0] & 0xffc0 == 0xfe80 {
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
            let preferred = a.address.is_loopback() || a.flags & DEPRECATED == 0;
            let shared = (u128::from(a.address) ^ u128::from(ip))
                .leading_zeros()
                .min(u32::from(a.prefix));
            (
                a.address == ip,
                distance,
                preferred,
                a.index == oif,
                label6(a.address) == label6(ip),
                shared,
            )
        };
        let only_oif = ip.is_multicast() || wanted <= 2;
        let devices: Vec<i32> = if only_oif { vec![oif] } else { order.to_vec() };
        let mut best: Option<&V6> = None;
        for device in devices {
            let candidates = self
                .v6
                .iter()
                .filter(|a| a.index == device && !a.tentative());
            for a in candidates {
                if best.is_none_or(|b| score(a) > score(b)) {
                    best = Some(a);
                }
            }
        }
        best.map(|a| a.address)
    }
    /// The address a connection to `to` leaves from: its route's
    /// ([`Self::source4`], [`Self::source6`], [`Self::select6`]); where
    /// that has none, 0.0.0.0 or `::` out through a veth end
    /// (`inet_select_addr` finding no address of a scope to fit, or
    /// `ipv6_dev_get_saddr` none at all), else `127.0.0.1` or `::1`.
    pub(crate) fn source(&self, to: IpAddr, order: &[i32]) -> IpAddr {
        match to {
            IpAddr::V4(ip) => IpAddr::V4(match self.output4(ip, 0, 0, None, order) {
                Ok(r) => self
                    .source4(&r, ip, order)
                    .unwrap_or(if r.oif == LOOPBACK_OIF {
                        Ipv4Addr::LOCALHOST
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    }),
                Err(_) => Ipv4Addr::LOCALHOST,
            }),
            IpAddr::V6(ip) => IpAddr::V6(self.source6_through(ip, 0, order)),
        }
    }
    /// The address a packet to the IPv6 address `ip` through the device
    /// `oif` (any for 0) leaves from: out through a veth end, its route's
    /// preferred source or what `ipv6_dev_get_saddr` picks for the route's
    /// device ([`Self::select6`]); `::` where there is none.
    pub(crate) fn source6_through(&self, ip: Ipv6Addr, oif: u32, order: &[i32]) -> Ipv6Addr {
        match self.lookup6_on(ip, oif) {
            Ok(r) if r.oif != LOOPBACK_OIF => r
                .prefsrc
                .or_else(|| self.select6(i32::try_from(r.oif).unwrap_or(0), ip, order))
                .unwrap_or(Ipv6Addr::UNSPECIFIED),
            r => r
                .ok()
                .and_then(|r| self.source6(&r, ip))
                .unwrap_or(Ipv6Addr::LOCALHOST),
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
    /// The gateways and devices of next hops, a dead one marked so.
    fn via6(hops: &[Route6]) -> String {
        hops.iter()
            .map(|r| {
                let gateway = r.gateway.map_or_else(|| "-".to_owned(), |g| g.to_string());
                format!("{gateway}@{}{}", r.oif, if r.dead { "!" } else { "" })
            })
            .collect::<Vec<_>>()
            .join(",")
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
                Event::NewMultipath6(hops, flags) => {
                    format!("+multipath {} {flags:#x}", via6(hops))
                }
                Event::DelMultipath6(hops) => format!("-multipath {}", via6(hops)),
                Event::NewNeighbour(n) => format!("+neigh {} {:#x}", n.ip, n.state),
                Event::DelNeighbour(n) => format!("-neigh {}", n.ip),
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
            device: kind == 1,
            flags: 0,
            request,
            metrics: Ok(NO_METRICS),
        }
    }

    #[test]
    fn changes_are_told_in_linux_order() {
        let mut a = Addresses::isolated();
        // Added while down: the address and its local route; IPv6's twice.
        let added = a
            .add_v4(
                v4("10.5.5.5", 24),
                crate::interface::Lifetimes::FOREVER,
                false,
                false,
                0,
            )
            .unwrap();
        assert_eq!(
            told(&added),
            ["+addr 10.5.5.5/24", "+route 255 10.5.5.5/32 Local 0x600"]
        );
        let added = a
            .add_v6(
                V6::new("2001:db8::5".parse().unwrap(), 64),
                crate::interface::Lifetimes::FOREVER,
                false,
                false,
                None,
                0,
            )
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
            told(&a.up(0, true)),
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
            .add_v6(
                V6::new("2001:db8:1::1".parse().unwrap(), 64),
                crate::interface::Lifetimes::FOREVER,
                false,
                true,
                None,
                0,
            )
            .unwrap();
        assert_eq!(
            told(&added)[0],
            "+route 254 2001:db8:1::/64 Unicast 256 0x600"
        );
        // A primary goes after its secondary: each address, then its
        // routes, the prefix route first and the local one last.
        a.add_v4(
            v4("10.5.5.9", 24),
            crate::interface::Lifetimes::FOREVER,
            false,
            true,
            0,
        )
        .unwrap();
        let gone = a
            .del_v4(1, Some("10.5.5.5".parse().unwrap()), None, 24, None)
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
        a.add_v4(
            v4("10.1.2.3", 24),
            crate::interface::Lifetimes::FOREVER,
            false,
            false,
            0,
        )
        .unwrap();
        a.add_v6(
            V6::new("2001:db8::5".parse().unwrap(), 64),
            crate::interface::Lifetimes::FOREVER,
            false,
            false,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            a.dump4().iter().map(short4).collect::<Vec<_>>(),
            ["255 10.1.2.3/32 Local"]
        );
        assert!(!a.bindable4("10.9.9.9".parse().unwrap()));
        assert_eq!(a.dump6().len(), 1);
        a.up(0, true);
        // 127.0.0.1/8, of host scope, goes first; a secondary goes last.
        a.add_v4(
            v4("10.1.2.9", 24),
            crate::interface::Lifetimes::FOREVER,
            false,
            true,
            0,
        )
        .unwrap();
        assert_eq!(
            a.add_v4(
                v4("10.1.2.3", 24),
                crate::interface::Lifetimes::FOREVER,
                false,
                true,
                0
            ),
            Err(Errno::EEXIST)
        );
        a.add_v4(
            v4("10.1.2.3", 16),
            crate::interface::Lifetimes::FOREVER,
            false,
            true,
            0,
        )
        .unwrap();
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
            a.source("10.1.2.77".parse().unwrap(), &[1]),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
        // IPv6: global first, newest first; the prefix route in the main
        // table, before the local ones.
        a.add_v6(
            V6::new("2001:db8:1::1".parse().unwrap(), 128),
            crate::interface::Lifetimes::FOREVER,
            false,
            true,
            None,
            0,
        )
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
        a.up(0, true);
        assert_eq!(a.v6.len(), 1);
        // A primary takes its secondary; 127.0.0.1 comes back with the next
        // up.
        a.del_v4(
            1,
            Some("10.1.2.3".parse().unwrap()),
            Some("10.1.2.3".parse().unwrap()),
            24,
            None,
        )
        .unwrap();
        assert_eq!(a.v4.len(), 2);
        assert_eq!(
            a.del_v4(1, None, Some("10.1.2.3".parse().unwrap()), 24, None),
            Err(EADDRNOTAVAIL)
        );
        a.del_v4(1, Some(Ipv4Addr::LOCALHOST), None, 8, None)
            .unwrap();
        assert!(!a.bindable4(Ipv4Addr::LOCALHOST));
        a.up(0, true);
        assert!(a.bindable4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn routes_take_linux_places_and_lookups() {
        let mut a = Addresses::first();
        // Down, a route through lo is `ENETDOWN`; host scope needs it not.
        a.down();
        assert_eq!(
            a.add_route4(&ask4("10.9.0.0", 16, 1, 0x600), &|_| false),
            Err(ENETDOWN)
        );
        a.up(0, true);
        // The same prefix: prepended, replaced, appended.
        let mut ask = ask4("10.9.0.0", 16, 1, 0x600);
        assert_eq!(
            told(&a.add_route4(&ask, &|_| true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0x600"]
        );
        assert_eq!(a.add_route4(&ask, &|_| true), Err(Errno::EEXIST));
        ask.request = F_CREATE | F_REPLACE;
        ask.scope = SCOPE_HOST;
        assert_eq!(
            told(&a.add_route4(&ask, &|_| true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0x100"]
        );
        assert_eq!(a.add_route4(&ask, &|_| true).unwrap(), []);
        ask.request = F_CREATE | F_APPEND;
        ask.scope = SCOPE_LINK;
        assert_eq!(
            told(&a.add_route4(&ask, &|_| true).unwrap()),
            ["+route 254 10.9.0.0/16 Unicast 0xc00"]
        );
        assert_eq!(a.add_route4(&ask, &|_| true), Err(Errno::EEXIST));
        ask.request = F_CREATE;
        ask.proto = 4;
        assert_eq!(
            told(&a.add_route4(&ask, &|_| true).unwrap()),
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
            multipath: None,
        };
        let gone = a.del_route4(&select).unwrap();
        assert!(matches!(&gone[..], [Event::DelRoute4(r)] if r.scope == SCOPE_HOST));
        // A blackhole is EINVAL to a lookup, a throw route goes on to the
        // default table, and the longest prefix wins across the tables.
        a.add_route4(&ask4("10.6.0.0", 16, 6, 0x600), &|_| true)
            .unwrap();
        a.add_route4(&ask4("10.3.0.0", 16, 9, 0x600), &|_| true)
            .unwrap();
        let mut default = ask4("10.3.0.0", 16, 1, 0x600);
        default.table = TABLE_DEFAULT;
        a.add_route4(&default, &|_| true).unwrap();
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
        local.device = true;
        a.add_route4(&local, &|_| true).unwrap();
        assert!(a.bindable4("10.7.1.1".parse().unwrap()));
        assert_eq!(
            a.source("10.7.1.1".parse().unwrap(), &[1]),
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
        a.up(0, true);
        let ask6 = |dst: &str, len, metric| Ask6 {
            table: TABLE_MAIN,
            dst: dst.parse().unwrap(),
            len,
            kind: 1,
            proto: 3,
            metric,
            prefsrc: None,
            oif: 1,
            gateway: None,
            onlink: false,
            device: true,
            ipv6_off: Some(false),
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
    fn v6(s: &str, prefix: u8) -> V6 {
        V6::new(s.parse().unwrap(), prefix)
    }
    fn life(valid: u32, preferred: u32) -> Lifetimes {
        Lifetimes { valid, preferred }
    }

    #[test]
    fn addresses_deprecate_then_go_as_their_lifetimes_run_out() {
        let start = 10 * SECOND;
        let mut a = Addresses::first();
        a.add_v4(v4("10.9.0.1", 24), life(3, 1), false, true, start)
            .unwrap();
        a.add_v6(
            v6("2001:db8:9::1", 64),
            life(5, 2),
            false,
            true,
            None,
            start,
        )
        .unwrap();
        let four = a.v4.iter().find(|x| x.prefix == 24).unwrap().clone();
        assert_eq!(four.flags & (PERMANENT | DEPRECATED), 0);
        assert_eq!((four.life.created, four.life.changed), (start, start));
        assert_eq!(four.left(start), (1, 3));
        assert_eq!(four.left(start + 3 * SECOND / 2), (0, 2));
        let six = a.v6.iter().find(|x| x.prefix == 64).unwrap().clone();
        assert_eq!(six.left(start + 4 * SECOND), (0, 1));
        let prefix = a.dump6().into_iter().find(|r| r.len == 64).unwrap();
        // Through a loopback, it does not run out by itself.
        assert_eq!(prefix.expires, None);
        // Nothing yet, not even just before its second; then IPv4's is
        // deprecated, once.
        assert!(a.expire(start + SECOND / 2).is_empty());
        assert!(a.expire(start + SECOND - 1).is_empty());
        let soon = start + SECOND;
        assert_eq!(told(&a.expire(soon)), ["+addr 10.9.0.1/24"]);
        assert!(a.v4.iter().any(|x| x.flags & DEPRECATED != 0));
        assert!(a.expire(soon).is_empty());
        assert_eq!(
            told(&a.expire(start + 2 * SECOND)),
            ["+addr 2001:db8:9::1/64 false"]
        );
        assert_eq!(
            told(&a.expire(start + 3 * SECOND)),
            [
                "-addr 10.9.0.1/24",
                "-route 255 10.9.0.0/24 Local",
                "-route 255 10.9.0.255/32 Broadcast",
                "-route 255 10.9.0.1/32 Local",
            ]
        );
        assert_eq!(
            told(&a.expire(start + 5 * SECOND)),
            [
                "-addr 2001:db8:9::1/64",
                "-route 255 2001:db8:9::1/128 Local 0",
                "-route 254 2001:db8:9::/64 Unicast 256",
            ]
        );
        // The kernel's own never run out.
        assert!(a.expire(u64::MAX / 2).is_empty());
        assert_eq!(a.v4.len(), 1);
    }

    #[test]
    fn a_priority_is_the_prefix_routes_metric_and_a_replacement_changes_it() {
        let mut a = Addresses::first();
        let mut new = v4("10.1.0.1", 24);
        new.priority = 50;
        a.add_v4(new.clone(), Lifetimes::FOREVER, false, true, 0)
            .unwrap();
        let priority = |a: &Addresses| {
            a.dump4()
                .iter()
                .filter(|r| r.dst == Ipv4Addr::new(10, 1, 0, 0))
                .map(|r| r.priority)
                .collect::<Vec<_>>()
        };
        assert_eq!(priority(&a), [50]);
        // IPv4 takes the replacement's, none being 0, and its lifetimes,
        // the new route first.
        new.priority = 60;
        let events = a
            .add_v4(new.clone(), life(9, 5), true, true, SECOND)
            .unwrap();
        assert_eq!(
            told(&events),
            [
                "+route 255 10.1.0.0/24 Local 0x600",
                "-route 255 10.1.0.0/24 Local",
                "+addr 10.1.0.1/24",
            ]
        );
        assert_eq!(priority(&a), [60]);
        let replaced = a.v4.iter().find(|x| x.prefix == 24).unwrap();
        assert_eq!((replaced.left(SECOND), replaced.life.created), ((5, 9), 0));
        new.priority = 0;
        a.add_v4(new, Lifetimes::FOREVER, true, true, 2 * SECOND)
            .unwrap();
        assert_eq!(priority(&a), [0]);
        assert!(a.v4.iter().all(|x| x.flags & PERMANENT != 0));
        // IPv6 keeps its own when the replacement names none.
        let mut six = v6("2001:db8:1::1", 64);
        six.priority = 300;
        a.add_v6(six.clone(), Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        let metric = |a: &Addresses| {
            a.dump6()
                .iter()
                .filter(|r| r.len == 64)
                .map(|r| (r.metric, r.expires))
                .collect::<Vec<_>>()
        };
        assert_eq!(metric(&a), [(300, None)]);
        six.priority = 0;
        let events = a
            .add_v6(six.clone(), life(7, 7), true, true, None, SECOND)
            .unwrap();
        assert_eq!(told(&events), ["+addr 2001:db8:1::1/64 false"]);
        assert_eq!(metric(&a), [(300, Some(8 * SECOND))]);
        six.priority = 400;
        let events = a
            .add_v6(six.clone(), life(7, 7), true, true, None, SECOND)
            .unwrap();
        // It was not permanent, so its prefix route is made again, and
        // the old one, of another metric, stays.
        assert_eq!(
            told(&events),
            [
                "+addr 2001:db8:1::1/64 false",
                "+route 254 2001:db8:1::/64 Unicast 400 0x600",
            ]
        );
        // Permanent, its route of the same metric runs out no more.
        let events = a
            .add_v6(six.clone(), Lifetimes::FOREVER, true, true, None, SECOND)
            .unwrap();
        assert_eq!(told(&events), ["+addr 2001:db8:1::1/64 false"]);
        assert_eq!(metric(&a), [(300, Some(8 * SECOND)), (400, None)]);
        // Of another metric again, permanent, it goes and comes again.
        six.priority = 500;
        let events = a
            .add_v6(six, Lifetimes::FOREVER, true, true, None, SECOND)
            .unwrap();
        assert_eq!(
            told(&events),
            [
                "+addr 2001:db8:1::1/64 false",
                "-route 254 2001:db8:1::/64 Unicast 300",
                "+route 254 2001:db8:1::/64 Unicast 500 0x600",
            ]
        );
    }

    #[test]
    fn a_prefix_route_outlives_its_address_while_another_has_the_prefix() {
        let mut a = Addresses::first();
        a.add_v6(v6("2001:db8::1", 64), life(10, 10), false, true, None, 0)
            .unwrap();
        a.add_v6(v6("2001:db8::2", 64), life(30, 30), false, true, None, 0)
            .unwrap();
        let expires = |a: &Addresses| {
            a.dump6()
                .iter()
                .filter(|r| r.len == 64)
                .map(|r| r.expires)
                .collect::<Vec<_>>()
        };
        assert_eq!(expires(&a), [None]);
        // With the second gone, it runs out with the first.
        let gone = a
            .del_v6(LOOPBACK_INDEX, "2001:db8::2".parse().unwrap(), 64, SECOND)
            .unwrap();
        assert_eq!(
            told(&gone),
            ["-addr 2001:db8::2/64", "-route 255 2001:db8::2/128 Local 0"]
        );
        assert_eq!(expires(&a), [Some(10 * SECOND)]);
        // A permanent one, whose route is the same, keeps it whatever runs
        // out.
        a.add_v6(
            v6("2001:db8::3", 64),
            Lifetimes::FOREVER,
            false,
            true,
            None,
            0,
        )
        .unwrap();
        assert_eq!(expires(&a), [None]);
        let gone = a
            .del_v6(LOOPBACK_INDEX, "2001:db8::1".parse().unwrap(), 64, SECOND)
            .unwrap();
        assert_eq!(told(&gone).len(), 2);
        assert_eq!(expires(&a), [None]);
        // An IPv6 route past its time goes, and is told of.
        a.add_v6(v6("2001:db8:5::1", 64), life(10, 10), false, true, None, 0)
            .unwrap();
        a.add_v6(v6("2001:db8:5::2", 64), life(2, 2), false, true, None, 0)
            .unwrap();
        a.del_v6(LOOPBACK_INDEX, "2001:db8:5::1".parse().unwrap(), 64, 0)
            .unwrap();
        let events = a.expire(3 * SECOND);
        assert_eq!(
            told(&events),
            [
                "-addr 2001:db8:5::2/64",
                "-route 255 2001:db8:5::2/128 Local 0",
                "-route 254 2001:db8:5::/64 Unicast 256",
            ]
        );
    }

    #[test]
    fn ipv4_multipath_routes_keep_their_hops_and_lose_them_with_their_devices() {
        let mut a = Addresses::isolated();
        for (ip, index) in [("10.0.0.1", 1000), ("10.1.0.1", 1001)] {
            let end = V4 {
                index,
                ..v4(ip, 24)
            };
            a.add_v4(end, Lifetimes::FOREVER, false, true, 0).unwrap();
        }
        let hop = |via: &str, oif, weight| NextHop4 {
            flags: 0,
            weight,
            oif,
            device: true,
            gateway: Some(via.parse().unwrap()),
        };
        let both = Multipath4 {
            counted: Ok(()),
            hops: Ok(vec![hop("10.0.0.2", 1000, 1), hop("10.1.0.2", 1001, 3)]),
        };
        let ask = Ask4 {
            scope: SCOPE_UNIVERSE,
            oif: 0,
            device: false,
            ..ask4("10.2.0.0", 24, 1, 0x600)
        };
        let up = |_: u32| true;
        let events = a.add_multipath4(&ask, Some(&both), &up).unwrap();
        let [Event::NewRoute4(route, _)] = &events[..] else {
            panic!("{events:?}");
        };
        assert_eq!(route.hops.len(), 2);
        assert_eq!((route.oif, route.hops[1].weight), (1000, 3));
        // The same again is there; one naming another device first is not.
        assert_eq!(
            a.add_multipath4(&ask, Some(&both), &up).map(|_| ()),
            Err(Errno::EEXIST)
        );
        let wrong = Ask4 { oif: 1001, ..ask };
        assert_eq!(
            a.add_multipath4(&wrong, Some(&both), &up).map(|_| ()),
            Err(Errno::EINVAL)
        );
        // Its hops down one after the other, it is not down as a whole,
        // and is still the same route as one asked for now, which is.
        a.set_carrier(1000, false);
        a.set_carrier(1001, false);
        assert_eq!(
            a.add_multipath4(&ask, Some(&both), &up).map(|_| ()),
            Err(Errno::EEXIST)
        );
        a.set_carrier(1000, true);
        a.set_carrier(1001, true);
        let host = Ask4 {
            scope: SCOPE_HOST,
            ..ask
        };
        assert_eq!(
            a.add_multipath4(&host, Some(&both), &up).map(|_| ()),
            Err(Errno::EINVAL)
        );
        // A hop's device down leaves it dead, which lookups pass over.
        a.device_down4(1001);
        let route = a.lookup4("10.2.0.9".parse().unwrap()).unwrap();
        assert_eq!(route.oif, 1000);
        a.device_down4(1000);
        assert!(a.lookup4("10.2.0.9".parse().unwrap()).is_err());
        // A removal names each hop in turn.
        a.device_up4(1000);
        a.device_up4(1001);
        a.add_multipath4(&ask, Some(&both), &up).unwrap();
        let select = |hops: Vec<NextHop4>| Select4 {
            table: TABLE_MAIN,
            dst: "10.2.0.0".parse().unwrap(),
            len: 24,
            tos: 0,
            priority: 0,
            kind: 0,
            proto: 0,
            scope: SCOPE_NOWHERE,
            prefsrc: None,
            gateway: None,
            oif: 0,
            metrics: Some(Vec::new()),
            multipath: Some(hops),
        };
        let backwards = select(vec![hop("10.1.0.2", 1001, 1), hop("10.0.0.2", 1000, 1)]);
        assert_eq!(a.del_route4(&backwards).map(|_| ()), Err(ESRCH));
        let forwards = select(vec![hop("10.0.0.2", 1000, 1), hop("10.1.0.2", 0, 1)]);
        assert!(a.del_route4(&forwards).is_ok());
    }
    #[test]
    fn ipv4_multipath_flows_take_hops_by_hash_weight_and_source() {
        let mut a = Addresses::isolated();
        for (ip, index) in [("10.0.0.1", 1000), ("10.1.0.1", 1001)] {
            let end = V4 {
                index,
                ..v4(ip, 24)
            };
            a.add_v4(end, Lifetimes::FOREVER, false, true, 0).unwrap();
        }
        let hop = |via: &str, oif, weight| NextHop4 {
            flags: 0,
            weight,
            oif,
            device: true,
            gateway: Some(via.parse().unwrap()),
        };
        let up = |_: u32| true;
        for (dst, hops) in [
            (
                "10.2.0.0",
                [hop("10.0.0.2", 1000, 1), hop("10.1.0.2", 1001, 3)],
            ),
            (
                "10.3.0.0",
                [hop("10.0.0.2", 1000, 1), hop("10.0.0.3", 1000, 1)],
            ),
        ] {
            let ask = Ask4 {
                scope: SCOPE_UNIVERSE,
                oif: 0,
                device: false,
                ..ask4(dst, 16, 1, 0x600)
            };
            let hops = Multipath4 {
                counted: Ok(()),
                hops: Ok(hops.to_vec()),
            };
            a.add_multipath4(&ask, Some(&hops), &up).unwrap();
        }
        let order = [1, 1000, 1001];
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        // How many of 4096 destinations the hop of weight 3 takes, and of
        // the same device's two hops the second.
        let share = |a: &Addresses, net: [u8; 2], src: Option<Ipv4Addr>, oif, via: &str| {
            (0..4096u16)
                .filter(|n| {
                    let [hi, lo] = n.to_be_bytes();
                    let to = Ipv4Addr::new(net[0], net[1], hi, lo);
                    let route = a.output4(to, 0, oif, src, &order).unwrap();
                    assert_eq!(a.output4(to, 0, oif, src, &order).unwrap(), route);
                    route.gateway == Some(ip(via))
                })
                .count()
        };
        // 3 in 4 within 332 of 4096 (1 in 2 within 384, below), which a
        // random key misses with a chance under 1e-22 (Hoeffding:
        // 2 e^(-2 d^2 / 4096)).
        let heavy = share(&a, [10, 2], None, 0, "10.1.0.2");
        assert!((2740..3404).contains(&heavy), "{heavy}");
        // A hop's own source before the hash, another's by the hash.
        let (own, other) = (Some(ip("10.0.0.1")), Some(ip("10.1.0.1")));
        assert_eq!(share(&a, [10, 2], own, 0, "10.0.0.2"), 4096);
        assert_eq!(share(&a, [10, 2], other, 0, "10.1.0.2"), 4096);
        for src in [None, own, other] {
            let second = share(&a, [10, 3], src, 0, "10.0.0.3");
            assert!((1664..2432).contains(&second), "{second}");
        }
        // A device named chooses itself.
        assert_eq!(share(&a, [10, 2], other, 1000, "10.0.0.2"), 4096);
        // A forwarded packet's hop, by the hash alone.
        let route = a.lookup4(ip("10.2.0.9")).unwrap();
        let taken = (0..4096u16)
            .filter(|n| {
                let [hi, lo] = n.to_be_bytes();
                let to = Ipv4Addr::new(10, 2, hi, lo);
                a.path4(route.clone(), to, ip("10.0.0.1"), None).oif == 1001
            })
            .count();
        assert!((2740..3404).contains(&taken), "{taken}");
        // Its source is that of the hop it takes, and it may come in on
        // the device of any.
        for n in 1..=254u8 {
            let to = Ipv4Addr::new(10, 2, 0, n);
            let route = a.output4(to, 0, 0, None, &order).unwrap();
            let src = if route.oif == 1000 { own } else { other };
            assert_eq!(Some(a.source(IpAddr::V4(to), &order)), src.map(IpAddr::V4));
        }
        for dev in [1000, 1001] {
            assert_eq!(
                a.validate_source4_on(ip("10.2.0.9"), 0, 0, 1, dev),
                Ok(false)
            );
        }
        // A dead hop takes none.
        a.device_down4(1001);
        assert_eq!(share(&a, [10, 2], None, 0, "10.0.0.2"), 4096);
    }
    #[test]
    fn ipv4_gateways_take_the_device_their_route_goes_through() {
        let mut a = Addresses::isolated();
        let mut end = V4 {
            index: 1000,
            label: b"va".to_vec(),
            ..v4("10.0.0.1", 24)
        };
        end.broadcast = Some("10.0.0.255".parse().unwrap());
        a.add_v4(end, Lifetimes::FOREVER, false, true, 0).unwrap();
        let ask = |via: &str, oif: u32, onlink: bool| Ask4 {
            gateway: Some(via.parse().unwrap()),
            oif,
            device: oif == 1 || oif == 1000,
            flags: if onlink { 4 } else { 0 },
            scope: SCOPE_UNIVERSE,
            ..ask4("10.2.0.0", 24, 1, 0x600)
        };
        let up = |_: u32| true;
        let error = |a: &mut Addresses, via, oif, onlink| {
            a.add_route4(&ask(via, oif, onlink), &up).map(|_| ())
        };
        assert_eq!(error(&mut a, "10.9.0.1", 0, false), Err(ENETUNREACH));
        assert_eq!(error(&mut a, "10.0.0.2", 1, false), Err(ENETUNREACH));
        assert_eq!(error(&mut a, "10.0.0.255", 0, false), Err(Errno::EINVAL));
        assert_eq!(error(&mut a, "10.7.0.1", 0, true), Err(Errno::ENODEV));
        assert_eq!(error(&mut a, "10.0.0.1", 1000, true), Err(Errno::EINVAL));
        assert_eq!(error(&mut a, "10.0.0.255", 1000, true), Err(Errno::EINVAL));
        assert_eq!(error(&mut a, "224.0.0.1", 1000, true), Err(Errno::EINVAL));
        // Its device down, the route to the gateway is not taken.
        assert_eq!(
            a.add_route4(&ask("10.0.0.2", 0, false), &|oif| oif != 1000)
                .map(|_| ()),
            Err(ENETDOWN)
        );
        // On link through the device it names; else through the device
        // of its route, whose packets go to the gateway.
        let events = a.add_route4(&ask("10.7.0.1", 1000, true), &up).unwrap();
        assert!(matches!(&events[..], [Event::NewRoute4(r, _)] if r.oif == 1000 && r.uses_gateway));
        let events = a.add_route4(&ask("10.0.0.2", 0, false), &up);
        assert_eq!(events, Err(Errno::EEXIST));
        let mut other = ask("10.0.0.2", 0, false);
        other.dst = "10.6.0.0".parse().unwrap();
        let events = a.add_route4(&other, &up).unwrap();
        assert!(matches!(
            &events[..],
            [Event::NewRoute4(r, _)] if r.oif == 1000 && r.uses_gateway && !r.linkdown
        ));
        // A gateway's route does not reach another gateway.
        let mut further = ask("10.6.0.2", 0, false);
        further.dst = "10.8.0.0".parse().unwrap();
        assert_eq!(a.add_route4(&further, &up).map(|_| ()), Err(ENETUNREACH));
        let route = a.lookup4("10.6.0.9".parse().unwrap()).unwrap();
        assert_eq!(route.gateway, Some("10.0.0.2".parse().unwrap()));
    }
    #[test]
    fn a_veth_ends_addresses_bring_unicast_routes_that_follow_its_state() {
        let mut a = Addresses::isolated();
        let on = |index: i32, s: &str, prefix: u8| V4 {
            index,
            label: b"va".to_vec(),
            ..v4(s, prefix)
        };
        let mut first = on(1000, "10.77.0.1", 24);
        first.broadcast = Some("10.77.0.255".parse().unwrap());
        // Down, an address has its local route alone, through its device.
        assert_eq!(
            told(
                &a.add_v4(first, Lifetimes::FOREVER, false, false, 0)
                    .unwrap()
            ),
            ["+addr 10.77.0.1/24", "+route 255 10.77.0.1/32 Local 0x600"]
        );
        // The same subnet on another device is no secondary there.
        a.add_v4(
            on(1002, "10.77.0.5", 24),
            Lifetimes::FOREVER,
            false,
            false,
            0,
        )
        .unwrap();
        let second = on(1000, "10.77.0.9", 24);
        a.add_v4(second, Lifetimes::FOREVER, false, false, 0)
            .unwrap();
        let shown: Vec<_> =
            a.v4.iter()
                .map(|x| (x.index, x.local.to_string(), x.secondary()))
                .collect();
        assert_eq!(
            shown,
            [
                (1000, "10.77.0.1".into(), false),
                (1000, "10.77.0.9".into(), true),
                (1002, "10.77.0.5".into(), false)
            ]
        );
        // Up without a carrier: a unicast prefix route in the main table,
        // of link scope, and broadcast ones, all but the local ones
        // `RTNH_F_LINKDOWN`; the broadcast address it names once.
        a.set_carrier(1000, false);
        assert_eq!(
            told(&a.device_up4(1000)),
            [
                "+route 255 10.77.0.255/32 Broadcast 0x600",
                "+route 254 10.77.0.0/24 Unicast 0x600"
            ]
        );
        let through: Vec<_> = a
            .dump4()
            .into_iter()
            .filter(|r| r.oif == 1000)
            .map(|r| {
                (
                    short4(&r),
                    r.scope,
                    r.linkdown,
                    r.prefsrc.unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            through,
            [
                (
                    "254 10.77.0.0/24 Unicast".into(),
                    SCOPE_LINK,
                    true,
                    "10.77.0.1".into()
                ),
                (
                    "255 10.77.0.1/32 Local".into(),
                    SCOPE_HOST,
                    false,
                    "10.77.0.1".into()
                ),
                (
                    "255 10.77.0.9/32 Local".into(),
                    SCOPE_HOST,
                    false,
                    "10.77.0.1".into()
                ),
                (
                    "255 10.77.0.255/32 Broadcast".into(),
                    SCOPE_LINK,
                    true,
                    "10.77.0.1".into()
                )
            ]
        );
        // Its carrier comes: they are no longer.
        a.set_carrier(1000, true);
        assert!(a.dump4().iter().all(|r| !r.linkdown));
        // A lookup goes out through it, from its first address; through
        // another device, its own, else the first of the devices in order.
        let route = a.lookup4("10.77.0.2".parse().unwrap()).unwrap();
        assert_eq!((route.oif, route.kind), (1000, Kind::Unicast));
        let order = [1, 1002, 1000];
        assert_eq!(
            a.source4(&route, "10.77.0.2".parse().unwrap(), &order),
            Some("10.77.0.1".parse().unwrap())
        );
        assert_eq!(
            a.select4(1002, None, SCOPE_UNIVERSE, &order),
            Some("10.77.0.5".parse().unwrap())
        );
        assert_eq!(
            a.select4(1, None, SCOPE_UNIVERSE, &order),
            Some("10.77.0.5".parse().unwrap())
        );
        // Removing the primary takes its secondary first; another device's
        // address in the subnet stays.
        assert_eq!(
            told(
                &a.del_v4(1000, Some("10.77.0.1".parse().unwrap()), None, 24, None)
                    .unwrap()
            ),
            [
                "-addr 10.77.0.9/24",
                "-route 255 10.77.0.9/32 Local",
                "-addr 10.77.0.1/24",
                "-route 254 10.77.0.0/24 Unicast",
                "-route 255 10.77.0.255/32 Broadcast",
                "-route 255 10.77.0.1/32 Local"
            ]
        );
        assert_eq!(
            a.del_v4(1000, Some("10.77.0.5".parse().unwrap()), None, 24, None),
            Err(EADDRNOTAVAIL)
        );
        // Down, a device keeps its local routes alone, without a word; gone,
        // it tells of its addresses and their local routes.
        a.add_v4(
            on(1000, "10.77.0.1", 24),
            Lifetimes::FOREVER,
            false,
            true,
            0,
        )
        .unwrap();
        a.device_down4(1000);
        let kept: Vec<_> = a
            .dump4()
            .iter()
            .filter(|r| r.oif == 1000)
            .map(short4)
            .collect();
        assert_eq!(kept, ["255 10.77.0.1/32 Local"]);
        let (gone, _) = a.device_gone4(1000);
        assert_eq!(
            told(&gone),
            ["-addr 10.77.0.1/24", "-route 255 10.77.0.1/32 Local"]
        );
        assert!(a.dump4().iter().all(|r| r.oif != 1000));
        assert_eq!(a.v4.len(), 1);
    }
    #[test]
    fn a_reachable_neighbour_goes_stale_or_delays_as_its_timer_runs() {
        let mut a = Addresses::first();
        let ask = |ip: &str, state, flags| NeighbourAsk {
            ip: ip.parse().unwrap(),
            state,
            flags,
            lladdr: Some([2, 0, 0, 0, 0, 1]),
            protocol: 0,
            request: NLM_F_CREATE,
            no_inet6: false,
        };
        let start = 100 * SECOND;
        let _ = a.add_neighbour(LOOPBACK_INDEX, ask("2001:db8::1", NUD_REACHABLE, 0), start);
        let _ = a.add_neighbour(
            LOOPBACK_INDEX,
            ask("2001:db8::2", NUD_REACHABLE, 0),
            start + SECOND,
        );
        let _ = a.add_neighbour(LOOPBACK_INDEX, ask("2001:db8::3", NUD_PERMANENT, 0), start);
        // Confirmed again: its time starts over.
        let _ = a.add_neighbour(
            LOOPBACK_INDEX,
            ask("2001:db8::1", NUD_REACHABLE, 0),
            start + 2 * SECOND,
        );
        // Used just before its time is out: it delays.
        let _ = a.add_neighbour(LOOPBACK_INDEX, ask("2001:db8::4", NUD_REACHABLE, 0), start);
        let _ = a.add_neighbour(
            LOOPBACK_INDEX,
            ask("2001:db8::4", 0, NTF_USE),
            start + 26 * SECOND,
        );
        let stale = |events: &[Event]| -> Vec<String> {
            events
                .iter()
                .map(|e| match e {
                    Event::NewNeighbour(n) => format!("{} {:#x} {}", n.ip, n.state, n.timer),
                    _ => panic!("{e:?}"),
                })
                .collect()
        };
        assert!(a.expire(start + REACHABLE_TIME).is_empty());
        assert!(stale(&a.expire(start + REACHABLE_TIME + SECOND)).is_empty());
        let state = |a: &Addresses, ip: &str| {
            let n = a
                .neighbours()
                .iter()
                .find(|n| n.ip == ip.parse::<IpAddr>().unwrap())
                .unwrap();
            (n.state, n.timer, n.updated)
        };
        assert_eq!(
            state(&a, "2001:db8::4"),
            (NUD_DELAY, true, start + REACHABLE_TIME)
        );
        assert_eq!(
            stale(&a.expire(start + REACHABLE_TIME + 3 * SECOND)),
            ["2001:db8::2 0x4 false", "2001:db8::1 0x4 false"]
        );
        assert_eq!(
            state(&a, "2001:db8::1"),
            (NUD_STALE, false, start + 2 * SECOND + REACHABLE_TIME)
        );
        assert_eq!(state(&a, "2001:db8::3").0, NUD_PERMANENT);
        assert!(a.expire(start + 100 * REACHABLE_TIME).is_empty());
    }

    #[test]
    fn a_veth_end_makes_its_ipv6_link_local_address_checks_it_and_loses_it_going_down() {
        let mut a = Addresses::first();
        let mac = [2, 0, 0, 0, 0, 0x0a];
        // Up without its carrier: only the prefix routes of what it has,
        // here a permanent address waiting for its carrier to be checked.
        let mut waiting = V6::new("2001:db8:9::1".parse().unwrap(), 64);
        waiting.index = 1000;
        let added = a
            .add_v6(waiting, Lifetimes::FOREVER, false, false, Some(u64::MAX), 0)
            .unwrap();
        assert_eq!(told(&added), ["+addr 2001:db8:9::1/64 true"]);
        assert_eq!(
            told(&a.device_up6(1000, false, (mac, true), SECOND)),
            ["+route 254 2001:db8:9::/64 Unicast 256 0x600"]
        );
        // Ready with it: the multicast route, the link-local prefix route;
        // the addresses are checked, and told of 2 seconds on.
        assert_eq!(
            told(&a.link_ready6(1000, (mac, true), 2 * SECOND)),
            [
                "+route 255 ff00::/8 Multicast 256 0x600",
                "+route 254 fe80::/64 Unicast 256 0x600"
            ]
        );
        assert!(a.link_ready6(1000, (mac, true), 2 * SECOND).is_empty());
        assert!(a.expire(3 * SECOND).is_empty());
        assert_eq!(
            told(&a.expire(4 * SECOND)),
            [
                "+addr 2001:db8:9::1/64 false",
                "+route 255 2001:db8:9::1/128 Local 0 0x600",
                "+addr fe80::ff:fe00:a/64 false",
                "+route 255 fe80::ff:fe00:a/128 Local 0 0x600"
            ]
        );
        let link =
            a.v6.iter()
                .find(|v| v.index == 1000 && v.proto == KERNEL_LL)
                .unwrap();
        assert_eq!(link.local_route().oif, 1000);
        // Another device's route to the same prefix is a route of its own.
        assert_eq!(
            told(&a.link_ready6(1001, ([2, 0, 0, 0, 0, 0x0b], false), 0)).len(),
            2
        );
        // Going down: its routes in a dump's order, then its addresses.
        assert_eq!(
            told(&a.device_down6(1000)),
            [
                "-route 254 2001:db8:9::/64 Unicast 256",
                "-route 254 fe80::/64 Unicast 256",
                "-route 255 2001:db8:9::1/128 Local 0",
                "-route 255 fe80::ff:fe00:a/128 Local 0",
                "-route 255 ff00::/8 Multicast 256",
                "-addr 2001:db8:9::1/64",
                "-addr fe80::ff:fe00:a/64"
            ]
        );
        assert!(a.v6.iter().all(|v| v.index != 1000));
        assert!(a.routes6.iter().all(|r| r.oif != 1000));
        assert!(a.routes6.iter().any(|r| r.oif == 1001));
    }
    #[test]
    fn a_device_binds_its_scoped_addresses_and_any_global_one() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        for (ip, index) in [
            ("2001:db8::1", 1000),
            ("fe80::ff:fe00:a", 1000),
            ("2001:db8:5::1", 1),
        ] {
            let mut address = V6::new(ip6(ip), 64);
            address.index = index;
            a.add_v6(address, Lifetimes::FOREVER, false, true, None, 0)
                .unwrap();
        }
        // A link-local or loopback address only of its own device.
        assert!(a.local6_on(ip6("fe80::ff:fe00:a"), 1000));
        assert!(!a.local6_on(ip6("fe80::ff:fe00:a"), 1));
        assert!(a.local6_on(ip6("::1"), 1));
        assert!(!a.local6_on(ip6("::1"), 1000));
        // A global one of any.
        assert!(a.local6_on(ip6("2001:db8::1"), 1));
        assert!(a.local6_on(ip6("2001:db8:5::1"), 1000));
        assert!(!a.local6_on(ip6("2001:db8::2"), 1000));
    }
    #[test]
    fn ipv6_gateways_take_their_routes_device_and_qualify_for_ecmp() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        let mut end = V6::new(ip6("2001:db8::1"), 64);
        end.index = 1000;
        a.add_v6(end, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        let mut link = V6::new(ip6("fe80::ff:fe00:a"), 64);
        link.index = 1000;
        a.add_v6(link, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        let ask = |via: &str, oif, onlink| Ask6 {
            table: TABLE_MAIN,
            dst: ip6("2001:db8:2::"),
            len: 64,
            kind: 1,
            proto: 3,
            metric: 0,
            prefsrc: None,
            oif,
            gateway: Some(ip6(via)),
            onlink,
            device: oif != 0,
            ipv6_off: (oif != 0).then_some(false),
            request: 0x600,
            metrics: Ok(NO_METRICS),
        };
        let error = |a: &mut Addresses, via, oif, onlink| {
            a.add_route6(&ask(via, oif, onlink), true).map(|_| ())
        };
        for (via, oif) in [
            ("ff02::1", 0),
            ("::", 0),
            ("2001:db8::1", 0),
            ("2001:db8::1", 1000),
            ("::1", 0),
            ("fe80::ff:fe00:b", 0),
            ("fe80::ff:fe00:b", 1),
            ("fe80::ff:fe00:a", 1000),
        ] {
            assert_eq!(error(&mut a, via, oif, false), Err(Errno::EINVAL), "{via}");
        }
        for (via, oif) in [
            ("2001:db8:9::1", 0),
            ("::ffff:10.0.0.1", 0),
            ("2001:db8::2", 1),
        ] {
            assert_eq!(error(&mut a, via, oif, false), Err(EHOSTUNREACH), "{via}");
        }
        assert_eq!(error(&mut a, "2001:db8::2", 0, true), Err(Errno::ENODEV));
        // On link, through the device it names; else through the device
        // of its route.
        let events = a
            .add_route6(&ask("2001:db8:7::1", 1000, true), true)
            .unwrap();
        assert!(matches!(events[..], [Event::NewRoute6(r, _)] if r.oif == 1000 && r.onlink));
        a.del_route6(&ask("2001:db8:7::1", 1000, true)).unwrap();
        let events = a.add_route6(&ask("2001:db8::2", 0, false), true).unwrap();
        assert!(matches!(
            events[..],
            [Event::NewRoute6(r, _)] if r.oif == 1000 && r.gateway == Some(ip6("2001:db8::2"))
        ));
        assert_eq!(error(&mut a, "2001:db8::2", 0, false), Err(Errno::EEXIST));
        // Another gateway of the prefix and metric is its sibling, told of
        // first of the hops, without `NLM_F_EXCL`.
        let mut other = ask("fe80::ff:fe00:b", 1000, false);
        other.request = 0x400;
        assert_eq!(
            told(&a.add_route6(&other, true).unwrap()),
            ["+multipath fe80::ff:fe00:b@1000,2001:db8::2@1000 0x400"]
        );
        // A gateway's route does not reach another gateway.
        let mut further = ask("2001:db8:2::2", 0, false);
        further.dst = ip6("2001:db8:6::");
        assert_eq!(a.add_route6(&further, true).map(|_| ()), Err(EHOSTUNREACH));
        // Replacing the first takes its sibling away too.
        other.request = 0x100;
        assert_eq!(
            told(&a.add_route6(&other, true).unwrap()),
            ["+route 254 2001:db8:2::/64 Unicast 1024 0x100"]
        );
        assert_eq!(
            a.dump6_entries()
                .iter()
                .filter(|(r, _)| r.len == 64 && r.gateway.is_some())
                .count(),
            1
        );
        let route = a.lookup6(ip6("2001:db8:2::2")).unwrap();
        assert_eq!(route.gateway, Some(ip6("fe80::ff:fe00:b")));
        // A removal naming another gateway finds none.
        assert_eq!(
            a.del_route6(&ask("2001:db8::2", 0, false)).map(|_| ()),
            Err(ESRCH)
        );
        a.del_route6(&ask("fe80::ff:fe00:b", 0, false)).unwrap();
        // Strictly through a device, a lookup takes only its routes.
        assert_eq!(
            a.lookup6_on(ip6("2001:db8::2"), 1).map(|_| ()),
            Err(ENETUNREACH)
        );
        assert_eq!(a.lookup6_on(ip6("2001:db8::2"), 1000).unwrap().oif, 1000);
        // Not strictly, another's where none goes through it, and its own
        // of two of one prefix and metric.
        let flow = Flow6::default();
        let through = |a: &Addresses, ip, oif| a.lookup6_preferring(ip, oif, &flow).unwrap().oif;
        assert_eq!(through(&a, ip6("2001:db8::2"), 1), 1000);
        let mut second = V6::new(ip6("2001:db8::9"), 64);
        second.index = 1002;
        a.add_v6(second, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        assert_eq!(through(&a, ip6("2001:db8::2"), 1002), 1002);
        assert_eq!(through(&a, ip6("2001:db8::2"), 1000), 1000);
    }
    #[test]
    fn ipv6_multipath_siblings_dump_once_die_with_their_device_and_go_together() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        for (address, index) in [("2001:db8::1", 1000), ("2001:db8:1::1", 1001)] {
            let mut end = V6::new(ip6(address), 64);
            end.index = index;
            a.add_v6(end, Lifetimes::FOREVER, false, true, None, 0)
                .unwrap();
        }
        let ask = |via: &str, oif, request| Ask6 {
            table: TABLE_MAIN,
            dst: ip6("2001:db8:2::"),
            len: 64,
            kind: 1,
            proto: 3,
            metric: 0,
            prefsrc: None,
            oif,
            gateway: Some(ip6(via)),
            onlink: false,
            device: oif != 0,
            ipv6_off: (oif != 0).then_some(false),
            request,
            metrics: Ok(NO_METRICS),
        };
        let add = |a: &mut Addresses, via, oif, request| {
            told(&a.add_route6(&ask(via, oif, request), true).unwrap())
        };
        assert_eq!(
            add(&mut a, "2001:db8::2", 0, 0x600),
            ["+route 254 2001:db8:2::/64 Unicast 1024 0x600"]
        );
        assert_eq!(
            add(&mut a, "2001:db8:1::2", 0, 0xc00),
            ["+multipath 2001:db8:1::2@1001,2001:db8::2@1000 0xc00"]
        );
        // A route of the metric without a gateway goes after the first two.
        let mut plain = ask("::", 1001, 0x400);
        plain.gateway = None;
        a.add_route6(&plain, true).unwrap();
        assert_eq!(
            add(&mut a, "2001:db8::3", 0, 0x400),
            ["+multipath 2001:db8::3@1000,2001:db8::2@1000,2001:db8:1::2@1001 0x400"]
        );
        // A dump passes over the route without a gateway between them.
        let entries: Vec<_> = a
            .dump6_entries()
            .into_iter()
            .filter(|(r, _)| r.dst == ip6("2001:db8:2::"))
            .map(|(_, hops)| via6(&hops))
            .collect();
        assert_eq!(
            entries,
            ["2001:db8::2@1000,2001:db8:1::2@1001,2001:db8::3@1000"]
        );
        assert_eq!(
            a.routes6
                .iter()
                .filter(|r| r.dst == ip6("2001:db8:2::"))
                .count(),
            4
        );
        // Its device going down leaves a sibling dead, which lookups pass
        // over, told of by none.
        assert_eq!(
            told(&a.device_down6(1000)),
            [
                "-route 254 2001:db8::/64 Unicast 256",
                "-route 255 2001:db8::1/128 Local 0",
                "-addr 2001:db8::1/64"
            ]
        );
        let hops = a.hops6(&a.lookup6(ip6("2001:db8:2::9")).unwrap());
        assert_eq!(
            via6(&hops),
            "2001:db8:1::2@1001,2001:db8::3@1000!,2001:db8::2@1000!"
        );
        // Ready again, it is not dead.
        a.link_ready6(1000, ([2, 0, 0, 0, 0, 1], false), 0);
        assert!(a.routes6.iter().all(|r| !r.dead));
        // All of it on the device going down goes.
        a.del_route6(&ask("2001:db8:1::2", 0, 0)).unwrap();
        let gone = told(&a.device_down6(1000));
        assert_eq!(
            gone.iter()
                .filter(|e| e.contains("2001:db8:2::/64"))
                .count(),
            2,
            "{gone:?}"
        );
        assert!(
            a.routes6
                .iter()
                .all(|r| r.dst != ip6("2001:db8:2::") || r.gateway.is_none())
        );
    }
    #[test]
    fn a_lone_dead_ipv6_hop_stays_dead_until_its_device_is_ready_or_goes_down() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        for (address, index) in [("2001:db8::1", 1000), ("2001:db8:1::1", 1001)] {
            let mut end = V6::new(ip6(address), 64);
            end.index = index;
            a.add_v6(end, Lifetimes::FOREVER, false, true, None, 0)
                .unwrap();
        }
        let ask = |via: &str| Ask6 {
            table: TABLE_MAIN,
            dst: ip6("2001:db8:2::"),
            len: 64,
            kind: 1,
            proto: 3,
            metric: 0,
            prefsrc: None,
            oif: 0,
            gateway: Some(ip6(via)),
            onlink: false,
            device: false,
            ipv6_off: None,
            request: 0x400,
            metrics: Ok(NO_METRICS),
        };
        for via in ["2001:db8::2", "2001:db8:1::2"] {
            a.add_route6(&ask(via), true).unwrap();
        }
        a.device_down6(1000);
        // Its live sibling gone, the dead hop is left alone, as Linux
        // leaves a route `RTNH_F_DEAD`, which lookups pass over.
        a.del_route6(&ask("2001:db8:1::2")).unwrap();
        let left: Vec<_> = a
            .routes6
            .iter()
            .filter(|r| r.dst == ip6("2001:db8:2::"))
            .collect();
        assert!(matches!(left[..], [r] if r.dead && r.oif == 1000));
        assert_eq!(
            a.lookup6(ip6("2001:db8:2::9")).map(|_| ()),
            Err(ENETUNREACH)
        );
        // Ready again, it is not dead.
        a.link_ready6(1000, ([2, 0, 0, 0, 0, 1], false), 0);
        assert_eq!(
            a.lookup6(ip6("2001:db8:2::9")).unwrap().gateway,
            Some(ip6("2001:db8::2"))
        );
        // Its device down again, with no sibling, it goes.
        assert!(
            told(&a.device_down6(1000))
                .contains(&"-route 254 2001:db8:2::/64 Unicast 1024".to_owned())
        );
        assert!(a.routes6.iter().all(|r| r.dst != ip6("2001:db8:2::")));
    }
    #[test]
    fn ipv6_multipath_removal_without_a_gateway_takes_all_its_hops_in_one_message() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        let mut end = V6::new(ip6("2001:db8::1"), 64);
        end.index = 1000;
        a.add_v6(end, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        let ask = |via: Option<&str>| Ask6 {
            table: TABLE_MAIN,
            dst: ip6("2001:db8:2::"),
            len: 64,
            kind: 1,
            proto: 3,
            metric: 0,
            prefsrc: None,
            oif: 0,
            gateway: via.map(ip6),
            onlink: false,
            device: false,
            ipv6_off: None,
            request: 0x400,
            metrics: Ok(NO_METRICS),
        };
        for via in ["2001:db8::2", "2001:db8::3", "2001:db8::4"] {
            a.add_route6(&ask(Some(via)), true).unwrap();
        }
        assert_eq!(
            told(&a.del_route6(&ask(Some("2001:db8::3"))).unwrap()),
            ["-route 254 2001:db8:2::/64 Unicast 1024"]
        );
        assert_eq!(
            told(&a.del_route6(&ask(None)).unwrap()),
            ["-multipath 2001:db8::2@1000,2001:db8::4@1000"]
        );
        assert_eq!(a.del_route6(&ask(None)).map(|_| ()), Err(ESRCH));
    }
    #[test]
    fn ipv6_multipath_requests_put_their_hops_in_together_and_flows_spread_by_weight() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        a.up(0, true);
        let mut end = V6::new(ip6("2001:db8::1"), 64);
        end.index = 1000;
        a.add_v6(end, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        let ask = |via: &str, request| Ask6 {
            table: TABLE_MAIN,
            dst: ip6("2001:db8:2::"),
            len: 64,
            kind: 1,
            proto: 3,
            metric: 0,
            prefsrc: None,
            oif: 0,
            gateway: Some(ip6(via)),
            onlink: false,
            device: false,
            ipv6_off: None,
            request,
            metrics: Ok(NO_METRICS),
        };
        let hops = |vias: &[(&str, u16)], request| -> Vec<(Ask6, bool, u16)> {
            vias.iter()
                .map(|&(via, weight)| (ask(via, request), true, weight))
                .collect()
        };
        // A hop twice is refused before any goes in.
        let (events, result) =
            a.add_multipath6(&hops(&[("2001:db8::2", 1), ("2001:db8::2", 1)], 0x400));
        assert_eq!(
            (told(&events), result),
            (Vec::<String>::new(), Err(Errno::EEXIST))
        );
        let (events, result) =
            a.add_multipath6(&hops(&[("2001:db8::2", 1), ("2001:db8::3", 3)], 0x600));
        assert_eq!(result, Ok(()));
        assert_eq!(
            told(&events),
            ["+multipath 2001:db8::2@1000,2001:db8::3@1000 0x400"]
        );
        assert_eq!(
            a.hops6(
                &a.routes6
                    .iter()
                    .find(|r| r.gateway == Some(ip6("2001:db8::3")))
                    .copied()
                    .unwrap()
            )[0]
            .weight,
            3
        );
        // One already there: those put in are told of, then go.
        let (events, result) =
            a.add_multipath6(&hops(&[("2001:db8::4", 1), ("2001:db8::2", 1)], 0x400));
        assert_eq!(result, Err(Errno::EEXIST));
        assert_eq!(
            told(&events),
            [
                "+multipath 2001:db8::4@1000,2001:db8::2@1000,2001:db8::3@1000 0x400",
                "-route 254 2001:db8:2::/64 Unicast 1024"
            ]
        );
        // Flows take each hop, the heavier more often, and the same flow
        // the same one.
        let mut taken = [0u32; 2];
        for n in 0..400u16 {
            let flow = Flow6 {
                src: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
                label: 0,
                proto: 17,
            };
            let route = a.lookup6_flow(ip6("2001:db8:2::9"), 0, &flow).unwrap();
            assert_eq!(
                a.lookup6_flow(ip6("2001:db8:2::9"), 0, &flow).unwrap(),
                route
            );
            taken[usize::from(route.gateway == Some(ip6("2001:db8::3")))] += 1;
        }
        assert!(taken[0] > 40 && taken[1] > 200, "{taken:?}");
        // A removal of hops takes each, giving the last error.
        let gone = [ask("2001:db8::3", 0), ask("2001:db8::9", 0)];
        let (events, result) = a.del_multipath6(&gone);
        assert_eq!(result, Err(ESRCH));
        assert_eq!(told(&events), ["-route 254 2001:db8:2::/64 Unicast 1024"]);
        assert_eq!(
            a.hops6(&a.lookup6(ip6("2001:db8:2::9")).unwrap()),
            Vec::new()
        );
    }
    #[test]
    fn a_veth_ends_ipv6_neighbours_and_sources_follow_neighbour_discovery() {
        let ip6 = |ip: &str| ip.parse::<Ipv6Addr>().unwrap();
        let mut a = Addresses::first();
        let at = |a: &mut Addresses, ip: &str, prefix, dad| {
            let mut v6 = V6::new(ip6(ip), prefix);
            v6.index = 1000;
            a.add_v6(v6, Lifetimes::FOREVER, false, true, dad, 0)
                .unwrap();
        };
        at(&mut a, "fe80::ff:fe00:a", 64, None);
        at(&mut a, "2001:db8::1", 64, None);
        at(&mut a, "2001:db8:1::1", 64, Some(u64::MAX));
        // Only an address of the end, not tentative, is answered for and
        // solicits from itself; else the link-local one does.
        assert!(a.nd_target(1000, ip6("2001:db8::1")));
        assert!(!a.nd_target(1000, ip6("2001:db8:1::1")));
        assert!(!a.nd_target(1001, ip6("2001:db8::1")));
        assert!(!a.local6(ip6("2001:db8:1::1")));
        assert_eq!(
            a.ns_source(1000, Some(ip6("2001:db8::1"))),
            Some(ip6("2001:db8::1"))
        );
        assert_eq!(
            a.ns_source(1000, Some(ip6("::1"))),
            Some(ip6("fe80::ff:fe00:a"))
        );
        assert_eq!(a.ns_source(1001, None), None);
        // A global destination takes the global address, a link-local or
        // group one the end's link-local one; a tentative one never.
        let order = [LOOPBACK_INDEX, 1000];
        assert_eq!(
            a.select6(1000, ip6("2001:db8::2"), &order),
            Some(ip6("2001:db8::1"))
        );
        assert_eq!(
            a.select6(1000, ip6("2001:db8:1::2"), &order),
            Some(ip6("2001:db8::1"))
        );
        assert_eq!(
            a.select6(1000, ip6("fe80::2"), &order),
            Some(ip6("fe80::ff:fe00:a"))
        );
        assert_eq!(
            a.select6(1000, ip6("ff02::1"), &order),
            Some(ip6("fe80::ff:fe00:a"))
        );
        assert_eq!(a.select6(1001, ip6("ff02::1"), &order), None);
        // A group's scope is its nibble: node-local and reserved ones take
        // the link-local address, a site-local one the site-local one.
        assert_eq!(
            a.select6(1000, ip6("ff01::1"), &order),
            Some(ip6("fe80::ff:fe00:a"))
        );
        assert_eq!(
            a.select6(1000, ip6("ff00::1"), &order),
            Some(ip6("fe80::ff:fe00:a"))
        );
        at(&mut a, "fec0::1", 64, None);
        assert_eq!(
            a.select6(1000, ip6("ff05::1"), &order),
            Some(ip6("fec0::1"))
        );
        // Of two that tie, the newer: the first in the list.
        at(&mut a, "2001:db8::3", 64, None);
        assert_eq!(
            a.select6(1000, ip6("2001:db8::2"), &order),
            Some(ip6("2001:db8::3"))
        );
        // Of two link-local ones, a solicitation leaves from the older.
        at(&mut a, "fe80::b", 64, None);
        assert_eq!(a.ns_source(1000, None), Some(ip6("fe80::ff:fe00:a")));
        // A unicast neighbour is RTN_UNICAST, for neighbour discovery; a
        // group's NUD_NOARP at its 33:33 address.
        let (lladdr, asked, events) =
            a.neigh_output(1000, ip6("2001:db8::2"), Some([2, 0, 0, 0, 0, 0xb]), 0);
        assert_eq!(
            (lladdr, asked, events.len()),
            (Some([2, 0, 0, 0, 0, 0xb]), true, 1)
        );
        let (lladdr, asked, events) = a.neigh_output(1000, ip6("ff02::1:ff00:2"), None, 0);
        assert_eq!(
            (lladdr, asked, events.len()),
            (Some([0x33, 0x33, 0xff, 0, 0, 2]), false, 0)
        );
        let kinds: Vec<(u8, u8)> = a.neighbours().iter().map(|n| (n.kind, n.state)).collect();
        assert_eq!(
            kinds,
            [(RTN_UNICAST, NUD_REACHABLE), (RTN_MULTICAST, NUD_NOARP)]
        );
        // No IPv6 on the device: none is made.
        let ask = NeighbourAsk {
            ip: "2001:db8::5".parse().unwrap(),
            state: NUD_PERMANENT,
            flags: 0,
            lladdr: Some([2, 0, 0, 0, 0, 5]),
            protocol: 0,
            request: NLM_F_CREATE,
            no_inet6: true,
        };
        assert_eq!(a.add_neighbour(1002, ask, 0).1, Err(Errno::EINVAL));
        // Flushed: IPv4's first, then IPv6's, each the newest first.
        let _ = a.neigh_output(1000, "10.77.0.2".parse::<Ipv4Addr>().unwrap(), None, 0);
        let gone: Vec<String> = a
            .flush_device(1000, false)
            .iter()
            .map(|e| match e {
                Event::DelNeighbour(n) => n.ip.to_string(),
                _ => panic!("{e:?}"),
            })
            .collect();
        assert_eq!(gone, ["10.77.0.2", "ff02::1:ff00:2", "2001:db8::2"]);
    }
    #[test]
    fn a_veth_ends_neighbours_are_resolved_learned_timed_and_flushed_as_arps() {
        let ip4 = |ip: &str| ip.parse::<Ipv4Addr>().unwrap();
        let mut a = Addresses::first();
        let start = 100 * SECOND;
        let peer = [2, 0, 0, 0, 0, 0x0b];
        let find = |a: &Addresses, ip: &str| {
            *a.neighbours()
                .iter()
                .find(|n| n.index == 1000 && n.ip == ip.parse::<IpAddr>().unwrap())
                .unwrap()
        };
        let told = |events: &[Event]| -> Vec<String> {
            events
                .iter()
                .map(|e| match e {
                    Event::NewNeighbour(n) => format!("+{} {:#x} {}", n.ip, n.state, n.probes),
                    Event::DelNeighbour(n) => format!("-{} {:#x}", n.ip, n.state),
                    _ => panic!("{e:?}"),
                })
                .collect()
        };
        // Answered at once: reachable, its first probe counted.
        let (lladdr, asked, events) = a.neigh_output(1000, ip4("10.77.0.2"), Some(peer), start);
        assert_eq!((lladdr, asked), (Some(peer), true));
        assert_eq!(told(&events), ["+10.77.0.2 0x2 4"]);
        // Valid now: no ARP.
        assert!(!a.neigh_output(1000, ip4("10.77.0.2"), None, start).1);
        // Unanswered: incomplete, failed 3 seconds on, told of.
        let (lladdr, asked, events) = a.neigh_output(1000, ip4("10.77.0.9"), None, start);
        assert_eq!((lladdr, asked, events.len()), (None, true, 0));
        assert!(a.expire(start + SECOND).is_empty());
        assert_eq!(find(&a, "10.77.0.9").probes, 5);
        assert_eq!(told(&a.expire(start + 3 * SECOND)), ["+10.77.0.9 0x20 6"]);
        // Broadcast and multicast need no ARP.
        let (lladdr, asked, _) = a.neigh_output(1000, Ipv4Addr::BROADCAST, None, start);
        assert_eq!((lladdr, asked), (Some([0xff; 6]), false));
        let (lladdr, _, _) = a.neigh_output(1000, ip4("224.1.130.3"), None, start);
        assert_eq!(lladdr, Some([0x01, 0x00, 0x5e, 0x01, 0x82, 0x03]));
        assert_eq!(find(&a, "224.1.130.3").kind, RTN_MULTICAST);
        // Learned from a request: stale, then delaying once used, then
        // probed 5 seconds on and reachable.
        let host = [2, 0, 0, 0, 0, 0x0a];
        assert_eq!(
            told(&a.neigh_learn(1000, ip4("10.77.0.3"), host, start)),
            ["+10.77.0.3 0x4 0"]
        );
        assert!(
            a.neigh_learn(1000, ip4("10.77.0.3"), host, start)
                .is_empty()
        );
        let (lladdr, asked, _) = a.neigh_output(1000, ip4("10.77.0.3"), Some(host), start + SECOND);
        assert_eq!((lladdr, asked), (Some(host), false));
        assert_eq!(find(&a, "10.77.0.3").state, NUD_DELAY);
        assert!(a.expire(start + 5 * SECOND).is_empty());
        assert_eq!(
            told(&a.expire(start + 6 * SECOND)),
            ["+10.77.0.3 0x10 0", "+10.77.0.3 0x2 1"]
        );
        // One that delays unanswered fails after its 3 probes.
        let _ = a.neigh_learn(1000, ip4("10.77.0.4"), host, start);
        let _ = a.neigh_output(1000, ip4("10.77.0.4"), None, start);
        assert_eq!(told(&a.expire(start + 5 * SECOND)), ["+10.77.0.4 0x10 0"]);
        assert_eq!(find(&a, "10.77.0.4").probes, 1);
        assert_eq!(told(&a.expire(start + 8 * SECOND)), ["+10.77.0.4 0x20 3"]);
        // A permanent one takes nothing learned.
        let ask = NeighbourAsk {
            ip: "10.77.0.5".parse().unwrap(),
            state: NUD_PERMANENT,
            flags: 0,
            lladdr: Some([2, 0, 0, 0, 0, 5]),
            protocol: 0,
            request: NLM_F_CREATE,
            no_inet6: false,
        };
        let (events, result) = a.add_neighbour(1000, ask, start);
        assert_eq!(
            (told(&events), result),
            (vec!["+10.77.0.5 0x80 0".to_owned()], Ok(()))
        );
        assert_eq!(find(&a, "10.77.0.5").kind, Kind::Unicast.code());
        assert!(
            a.neigh_learn(1000, ip4("10.77.0.5"), host, start)
                .is_empty()
        );
        // The carrier going takes all but the permanent ones, the newest
        // first; going down takes that too.
        assert_eq!(
            told(&a.flush_device(1000, true)),
            [
                "-10.77.0.4 0x20",
                "-10.77.0.3 0x2",
                "-224.1.130.3 0x40",
                "-255.255.255.255 0x40",
                "-10.77.0.9 0x20",
                "-10.77.0.2 0x2"
            ]
        );
        assert_eq!(told(&a.flush_device(1000, false)), ["-10.77.0.5 0x80"]);
        assert!(a.neighbours().is_empty());
    }
    #[test]
    fn neighbours_go_with_the_loopback_and_its_last_ipv4_address() {
        let mut a = Addresses::first();
        let one = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let other = IpAddr::V6("2001:db8::1".parse().unwrap());
        a.output(other, 5);
        a.output(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 6);
        a.output(one, 7);
        // IPv4's one entry, however many addresses it went to.
        a.output(IpAddr::V4(Ipv4Addr::LOCALHOST), 8);
        a.output(other, 9);
        let gone = |events: &[Event]| -> Vec<(IpAddr, u8, u64)> {
            events
                .iter()
                .filter_map(|e| match e {
                    Event::DelNeighbour(n) => Some((n.ip, n.kind, n.made)),
                    _ => None,
                })
                .collect()
        };
        let down = a.down();
        let zero = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            gone(&down),
            vec![
                (zero, RTN_BROADCAST, 6),
                (one, RTN_LOCAL, 7),
                (other, RTN_LOCAL, 5)
            ]
        );
        // IPv4's first, then IPv6's routes, its neighbours, its addresses.
        assert!(matches!(down[0], Event::DelNeighbour(_)));
        let first6 = down
            .iter()
            .position(|e| matches!(e, Event::DelNeighbour(n) if n.ip == one));
        let route = down.iter().rposition(|e| matches!(e, Event::DelRoute6(_)));
        let address = down.iter().position(|e| matches!(e, Event::DelAddr6(_)));
        assert!(route < first6 && first6 < address);
        assert!(gone(&a.down()).is_empty());
        let _ = a.up(10, true);
        a.output(IpAddr::V4(Ipv4Addr::LOCALHOST), 11);
        a.output(IpAddr::V6("ff02::1".parse().unwrap()), 12);
        let last = a
            .del_v4(1, Some(Ipv4Addr::LOCALHOST), None, 8, None)
            .unwrap();
        assert_eq!(gone(&last), vec![(zero, RTN_BROADCAST, 11)]);
        assert!(matches!(last.last(), Some(Event::DelNeighbour(_))));
        // A multicast one is of its own type, and stays.
        assert_eq!(
            gone(&a.down()),
            vec![(IpAddr::V6("ff02::1".parse().unwrap()), RTN_MULTICAST, 12)]
        );
    }

    #[test]
    fn nodad_is_told_of_once_and_routes_of_lifetimes_go_by_themselves() {
        let mut a = Addresses::first();
        let mut quiet = v6("2001:db8:7::1", 64);
        quiet.flags = NO_DAD;
        let events = a
            .add_v6(quiet, Lifetimes::FOREVER, false, true, None, 0)
            .unwrap();
        assert_eq!(
            told(&events),
            [
                "+route 254 2001:db8:7::/64 Unicast 256 0x600",
                "+addr 2001:db8:7::1/64 false",
                "+route 255 2001:db8:7::1/128 Local 0 0x600",
            ]
        );
        let mut route = v6("2001:db8:8::1", 64).prefix_route().unwrap();
        route.expires = Some(SECOND);
        a.kernel_add6(route, &mut Vec::new());
        assert!(a.expire(SECOND).is_empty());
        assert_eq!(
            told(&a.expire(SECOND + 1)),
            ["-route 254 2001:db8:8::/64 Unicast 256"]
        );
    }
}
