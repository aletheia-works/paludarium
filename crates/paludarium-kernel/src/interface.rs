//! The addresses of a network namespace's loopback `lo`, and the routes
//! the kernel gives them, as Linux's `devinet`, `fib_frontend` and
//! `addrconf` keep them.
//!
//! `127.0.0.1/8` comes with the loopback's first `NETDEV_UP` (and every
//! later one, should it have been removed), `::1/128` with each, and netlink
//! adds and removes others. An IPv4 address has its `local` route from the
//! start; its prefix route, `local` too on a loopback, comes at the first
//! `NETDEV_UP` it sees and stays when the loopback goes down, and its
//! subnet's broadcast route is there while the loopback is up. An IPv6
//! address has its `local` route and, from the first `NETDEV_UP`, a unicast
//! prefix route in the main table; taking the loopback down removes every
//! IPv6 address (`keep_addr_on_down` is 0).
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use paludarium_types::Errno;

const EEXIST: Errno = Errno(17);
const EADDRNOTAVAIL: Errno = Errno(99);
/// `IFA_F_SECONDARY`, `IFA_F_NOPREFIXROUTE` and `IFA_F_PERMANENT`.
pub(crate) const SECONDARY: u32 = 0x01;
pub(crate) const NO_PREFIX_ROUTE: u32 = 0x200;
pub(crate) const PERMANENT: u32 = 0x80;
/// The scopes of addresses and routes (`RT_SCOPE_*`).
pub(crate) const SCOPE_UNIVERSE: u8 = 0;
pub(crate) const SCOPE_LINK: u8 = 253;
pub(crate) const SCOPE_HOST: u8 = 254;
/// `IFAPROT_KERNEL_LO`: the kernel gave `::1` to the loopback.
pub(crate) const KERNEL_LO: u8 = 1;

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
    /// Whether a `NETDEV_UP` has added its prefix route.
    prefixed: bool,
}
impl V4 {
    /// An address the guest asks for: `local`, `address` (its peer, or the
    /// same), `prefix`, `scope`, `flags`, `proto` and `label`.
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
            prefixed: false,
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
    prefixed: bool,
}
impl V6 {
    pub(crate) fn new(address: Ipv6Addr, prefix: u8) -> Self {
        Self {
            address,
            prefix,
            flags: PERMANENT,
            proto: 0,
            prefixed: false,
        }
    }
    /// Its scope, as `ipv6_addr_scope` gives it.
    pub(crate) fn scope(&self) -> u8 {
        scope6(self.address)
    }
    fn covers(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) ^ u128::from(self.address)) & mask6(self.prefix) == 0
    }
}
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
}
/// An IPv4 route of the local table, its preferred source address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route4 {
    pub dst: Ipv4Addr,
    pub len: u8,
    pub kind: Kind,
    pub source: Ipv4Addr,
}
/// An IPv6 route: a local one of the local table, or a unicast prefix
/// route of the main table, through `lo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route6 {
    pub dst: Ipv6Addr,
    pub len: u8,
    pub kind: Kind,
}

/// The loopback's addresses, in Linux's orders.
#[derive(Debug)]
pub(crate) struct Addresses {
    pub v4: Vec<V4>,
    pub v6: Vec<V6>,
    /// Whether IPv4 has a local table yet: before its first route, Linux's
    /// `inet_addr_type` finds none, and takes every address as broadcast.
    table: bool,
}
impl Addresses {
    /// The first namespace's: `127.0.0.1/8` and `::1`, up.
    pub(crate) fn first() -> Self {
        let mut addresses = Self::isolated();
        addresses.up();
        addresses
    }
    /// A new namespace's: none.
    pub(crate) fn isolated() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
            table: false,
        }
    }
    /// The loopback comes up (`NETDEV_UP`): it takes `127.0.0.1/8` if it
    /// has it not, every IPv4 address its prefix route, and `::1`.
    pub(crate) fn up(&mut self) {
        let mut loopback = V4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 8, SCOPE_HOST);
        loopback.flags = PERMANENT;
        let _ = self.add_v4(loopback, false, true);
        for address in &mut self.v4 {
            address.prefixed = true;
        }
        let mut one = V6::new(Ipv6Addr::LOCALHOST, 128);
        one.proto = KERNEL_LO;
        let _ = self.add_v6(one, false, true);
        for address in &mut self.v6 {
            address.prefixed = true;
        }
    }
    /// The loopback goes down: it loses every IPv6 address.
    pub(crate) fn down(&mut self) {
        self.v6.clear();
    }
    /// Adds an IPv4 address as `__inet_insert_ifa` does: the same local
    /// address and subnet again is `EEXIST`, unless `replace`, which takes
    /// its protocol; one in a subnet a primary address has is secondary,
    /// and goes last; a primary goes after the primaries of a scope as wide
    /// or wider. `up` gives it its prefix route at once.
    pub(crate) fn add_v4(&mut self, mut new: V4, replace: bool, up: bool) -> Result<(), Errno> {
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
                        return Err(EEXIST);
                    }
                    old.proto = new.proto;
                    return Ok(());
                }
                new.flags |= SECONDARY;
            }
        }
        new.prefixed = up;
        self.table = true;
        if new.secondary() {
            self.v4.push(new);
        } else {
            self.v4.insert(last_primary, new);
        }
        Ok(())
    }
    /// Removes the first IPv4 address that has `local`, `label`, and
    /// `address` in a subnet of `prefix`, each as given, as
    /// `inet_rtm_deladdr`: `EADDRNOTAVAIL` for none. A primary takes its
    /// secondaries with it (`promote_secondaries` is 0).
    pub(crate) fn del_v4(
        &mut self,
        local: Option<Ipv4Addr>,
        address: Option<Ipv4Addr>,
        prefix: u8,
        label: Option<&[u8]>,
    ) -> Result<(), Errno> {
        let found = self
            .v4
            .iter()
            .position(|a| {
                local.is_none_or(|local| a.local == local)
                    && label.is_none_or(|label| a.label == label)
                    && address.is_none_or(|address| a.prefix == prefix && a.covers(address))
            })
            .ok_or(EADDRNOTAVAIL)?;
        let gone = self.v4.remove(found);
        if !gone.secondary() {
            self.v4
                .retain(|a| !(a.secondary() && a.mask() == gone.mask() && gone.covers(a.address)));
        }
        Ok(())
    }
    /// Adds an IPv6 address: the same one again is `EEXIST`, unless
    /// `replace`. Global ones go before host ones, the newest first
    /// within a scope (`ipv6_link_dev_addr`).
    pub(crate) fn add_v6(&mut self, mut new: V6, replace: bool, up: bool) -> Result<(), Errno> {
        if let Some(old) = self.v6.iter_mut().find(|a| a.address == new.address) {
            if !replace {
                return Err(EEXIST);
            }
            old.proto = new.proto;
            return Ok(());
        }
        new.flags |= PERMANENT;
        new.prefixed = up;
        let at = self
            .v6
            .iter()
            .position(|a| a.scope() >= new.scope())
            .unwrap_or(self.v6.len());
        self.v6.insert(at, new);
        Ok(())
    }
    /// Removes the IPv6 address `address/prefix` (`EADDRNOTAVAIL` for
    /// none).
    pub(crate) fn del_v6(&mut self, address: Ipv6Addr, prefix: u8) -> Result<(), Errno> {
        let found = self
            .v6
            .iter()
            .position(|a| a.address == address && a.prefix == prefix)
            .ok_or(EADDRNOTAVAIL)?;
        self.v6.remove(found);
        Ok(())
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
    /// The IPv4 routes of the local table, as `fib_add_ifaddr` makes them,
    /// in the order of its trie: by destination, the shorter prefix first.
    pub(crate) fn routes4(&self, up: bool) -> Vec<Route4> {
        let mut routes: Vec<Route4> = Vec::new();
        let mut add = |route: Route4| {
            if !routes
                .iter()
                .any(|r| r.dst == route.dst && r.len == route.len && r.kind == route.kind)
            {
                routes.push(route);
            }
        };
        for address in &self.v4 {
            let source = self.primary_of(address);
            add(Route4 {
                dst: address.local,
                len: 32,
                kind: Kind::Local,
                source,
            });
            if !up {
                // The prefix routes a NETDEV_UP added stay when it goes down.
                if address.prefixed && !address.secondary() && address.flags & NO_PREFIX_ROUTE == 0
                {
                    let prefix = Ipv4Addr::from(u32::from(address.address) & address.mask());
                    if !prefix.is_unspecified() && (prefix != address.local || address.prefix < 32)
                    {
                        add(Route4 {
                            dst: prefix,
                            len: address.prefix,
                            kind: Kind::Local,
                            source,
                        });
                    }
                }
                continue;
            }
            if let Some(broadcast) = address.broadcast.filter(|b| !b.is_broadcast()) {
                add(Route4 {
                    dst: broadcast,
                    len: 32,
                    kind: Kind::Broadcast,
                    source,
                });
            }
            let prefix = Ipv4Addr::from(u32::from(address.address) & address.mask());
            if prefix.is_unspecified()
                || address.secondary()
                || (prefix == address.local && address.prefix == 32)
            {
                continue;
            }
            if address.flags & NO_PREFIX_ROUTE == 0 && address.prefixed {
                add(Route4 {
                    dst: prefix,
                    len: address.prefix,
                    kind: Kind::Local,
                    source,
                });
            }
            if address.prefix < 31 {
                add(Route4 {
                    dst: Ipv4Addr::from(u32::from(prefix) | !address.mask()),
                    len: 32,
                    kind: Kind::Broadcast,
                    source,
                });
            }
        }
        routes.sort_by_key(|r| (u32::from(r.dst), r.len));
        routes
    }
    /// The IPv6 routes: the main table's prefix routes, then the local
    /// table's routes of the addresses, each by destination.
    pub(crate) fn routes6(&self) -> Vec<Route6> {
        let mut main: Vec<Route6> = Vec::new();
        let mut local: Vec<Route6> = Vec::new();
        for address in &self.v6 {
            let route = Route6 {
                dst: address.address,
                len: 128,
                kind: Kind::Local,
            };
            if !local.contains(&route) {
                local.push(route);
            }
            if address.prefixed
                && address.proto != KERNEL_LO
                && address.flags & NO_PREFIX_ROUTE == 0
            {
                let route = Route6 {
                    dst: Ipv6Addr::from(u128::from(address.address) & mask6(address.prefix)),
                    len: address.prefix,
                    kind: Kind::Unicast,
                };
                if !main.contains(&route) {
                    main.push(route);
                }
            }
        }
        main.sort_by_key(|r| (u128::from(r.dst), r.len));
        local.sort_by_key(|r| u128::from(r.dst));
        main.extend(local);
        main
    }
    /// The local table's route to `ip`, the longest prefix first.
    pub(crate) fn lookup4(&self, ip: Ipv4Addr, up: bool) -> Option<Route4> {
        self.routes4(up)
            .into_iter()
            .filter(|r| (u32::from(ip) ^ u32::from(r.dst)) & mask4(r.len) == 0)
            .max_by_key(|r| r.len)
    }
    /// The IPv6 route to `ip`, the local one first, and the address it
    /// leaves from: `ip` itself to an address, else the address whose
    /// prefix route took it.
    pub(crate) fn lookup6(&self, ip: Ipv6Addr) -> Option<(Route6, Ipv6Addr)> {
        if self.v6.iter().any(|a| a.address == ip) {
            let route = Route6 {
                dst: ip,
                len: 128,
                kind: Kind::Local,
            };
            return Some((route, ip));
        }
        let route = self
            .routes6()
            .into_iter()
            .filter(|r| {
                r.kind == Kind::Unicast && (u128::from(ip) ^ u128::from(r.dst)) & mask6(r.len) == 0
            })
            .max_by_key(|r| r.len)?;
        let source = self
            .v6
            .iter()
            .find(|a| a.prefix == route.len && a.covers(ip))
            .map(|a| a.address)?;
        Some((route, source))
    }
    /// Whether a socket may bind to the IPv4 address `ip`: a local or
    /// broadcast route has it, or there is no local table yet.
    pub(crate) fn bindable4(&self, ip: Ipv4Addr, up: bool) -> bool {
        !self.table
            || self.lookup4(ip, up).is_some_and(|r| {
                r.kind == Kind::Local || (r.kind == Kind::Broadcast && r.dst == ip)
            })
    }
    /// Whether `ip` is an IPv4 address of the loopback's, as its local
    /// routes give them.
    pub(crate) fn local4(&self, ip: Ipv4Addr, up: bool) -> bool {
        self.lookup4(ip, up).is_some_and(|r| r.kind == Kind::Local)
    }
    /// Whether `ip` is an IPv6 address of the loopback's.
    pub(crate) fn local6(&self, ip: Ipv6Addr) -> bool {
        self.v6.iter().any(|a| a.address == ip)
    }
    /// The address a connection to `to` on the loopback leaves from: the
    /// preferred source of its route, `127.0.0.1` or `::1` when none has
    /// one.
    pub(crate) fn source(&self, to: IpAddr, up: bool) -> IpAddr {
        match to {
            IpAddr::V4(ip) => IpAddr::V4(
                self.lookup4(ip, up)
                    .map_or(Ipv4Addr::LOCALHOST, |r| r.source),
            ),
            IpAddr::V6(ip) => IpAddr::V6(
                self.lookup6(ip)
                    .map_or(Ipv6Addr::LOCALHOST, |(_, source)| source),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str, prefix: u8) -> V4 {
        let ip: Ipv4Addr = s.parse().unwrap();
        V4::new(ip, ip, prefix, SCOPE_UNIVERSE)
    }
    fn route(s: &str, len: u8, kind: Kind, source: &str) -> Route4 {
        Route4 {
            dst: s.parse().unwrap(),
            len,
            kind,
            source: source.parse().unwrap(),
        }
    }

    #[test]
    fn addresses_take_linux_orders_and_routes() {
        let mut a = Addresses::isolated();
        // Every address binds before there is a local table.
        assert!(a.bindable4("10.9.9.9".parse().unwrap(), false));
        // Added while down: its local route alone.
        a.add_v4(v4("10.1.2.3", 24), false, false).unwrap();
        a.add_v6(V6::new("2001:db8::5".parse().unwrap(), 64), false, false)
            .unwrap();
        assert_eq!(
            a.routes4(false),
            [route("10.1.2.3", 32, Kind::Local, "10.1.2.3")]
        );
        assert!(!a.bindable4("10.9.9.9".parse().unwrap(), false));
        assert_eq!(a.routes6().len(), 1);
        a.up();
        // 127.0.0.1/8, of host scope, goes first; a secondary goes last.
        a.add_v4(v4("10.1.2.9", 24), false, true).unwrap();
        assert_eq!(a.add_v4(v4("10.1.2.3", 24), false, true), Err(EEXIST));
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
            a.routes4(true),
            [
                route("10.1.0.0", 16, Kind::Local, "10.1.2.3"),
                route("10.1.2.0", 24, Kind::Local, "10.1.2.3"),
                route("10.1.2.3", 32, Kind::Local, "10.1.2.3"),
                route("10.1.2.9", 32, Kind::Local, "10.1.2.3"),
                route("10.1.2.255", 32, Kind::Broadcast, "10.1.2.3"),
                route("10.1.255.255", 32, Kind::Broadcast, "10.1.2.3"),
                route("127.0.0.0", 8, Kind::Local, "127.0.0.1"),
                route("127.0.0.1", 32, Kind::Local, "127.0.0.1"),
                route("127.255.255.255", 32, Kind::Broadcast, "127.0.0.1"),
            ]
        );
        // The subnet is local on a loopback; another is not.
        assert!(a.local4("10.1.2.77".parse().unwrap(), true));
        assert!(!a.bindable4("10.2.0.1".parse().unwrap(), true));
        assert_eq!(
            a.source("10.1.2.77".parse().unwrap(), true),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
        // IPv6: global first, newest first; the prefix route in the main
        // table, before the local ones.
        a.add_v6(V6::new("2001:db8:1::1".parse().unwrap(), 128), false, true)
            .unwrap();
        let order: Vec<_> = a.v6.iter().map(|a| a.address.to_string()).collect();
        assert_eq!(order, ["2001:db8:1::1", "2001:db8::5", "::1"]);
        let routes: Vec<_> = a
            .routes6()
            .iter()
            .map(|r| (r.dst.to_string(), r.len, r.kind))
            .collect();
        assert_eq!(
            routes,
            [
                ("2001:db8::".to_string(), 64, Kind::Unicast),
                ("2001:db8:1::1".to_string(), 128, Kind::Unicast),
                ("::1".to_string(), 128, Kind::Local),
                ("2001:db8::5".to_string(), 128, Kind::Local),
                ("2001:db8:1::1".to_string(), 128, Kind::Local),
            ]
        );
        let (via, from) = a.lookup6("2001:db8::6".parse().unwrap()).unwrap();
        assert_eq!(
            (via.kind, from.to_string()),
            (Kind::Unicast, "2001:db8::5".to_string())
        );
        // Down: the IPv4 prefix routes stay, the broadcast ones and IPv6's
        // addresses go.
        a.down();
        assert!(a.v6.is_empty());
        assert_eq!(a.routes4(false).len(), 6);
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
        assert!(!a.bindable4(Ipv4Addr::LOCALHOST, true));
        a.up();
        assert!(a.bindable4(Ipv4Addr::LOCALHOST, true));
    }
}
