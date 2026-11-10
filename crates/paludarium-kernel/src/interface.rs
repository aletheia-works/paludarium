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
    /// Its route in the local table.
    pub(crate) fn local_route(&self) -> Route6 {
        Route6 {
            dst: self.address,
            len: 128,
            kind: Kind::Local,
        }
    }
    /// Its prefix route in the main table, from the first time the loopback
    /// is up with it; `::1`, which the kernel gives, has none.
    pub(crate) fn prefix_route(&self) -> Option<Route6> {
        (self.prefixed && self.proto != KERNEL_LO && self.flags & NO_PREFIX_ROUTE == 0).then(|| {
            Route6 {
                dst: Ipv6Addr::from(u128::from(self.address) & mask6(self.prefix)),
                len: self.prefix,
                kind: Kind::Unicast,
            }
        })
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
impl Route4 {
    /// The same route of the table, whatever its preferred source.
    fn same(&self, other: &Self) -> bool {
        self.dst == other.dst && self.len == other.len && self.kind == other.kind
    }
}
/// A change to the loopback's addresses or routes Linux tells netlink of
/// (`RTM_NEWADDR`, `RTM_DELADDR`, `RTM_NEWROUTE`, `RTM_DELROUTE`); an
/// IPv6 address may be told of while tentative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    NewAddr4(V4),
    DelAddr4(V4),
    NewRoute4(Route4),
    DelRoute4(Route4),
    NewAddr6(V6, bool),
    DelAddr6(V6),
    NewRoute6(Route6),
    DelRoute6(Route6),
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
        let _ = addresses.up();
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
    /// The loopback comes up (`NETDEV_UP`), and what Linux tells of it, in
    /// its order: `127.0.0.1/8` if it has it not, with its routes
    /// (`inetdev_event`); every IPv4 address's routes that come then, in
    /// the addresses' order (`fib_netdev_event`); the prefix route of each
    /// IPv6 address added while it was down (`addrconf_permanent_addr`);
    /// and `::1` with its route.
    pub(crate) fn up(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        let mut seen = self.routes4(false);
        let mut loopback = V4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 8, SCOPE_HOST);
        loopback.flags = PERMANENT;
        if let Ok(added) = self.add_v4(loopback, false, true) {
            for event in added {
                if let Event::NewRoute4(route) = event {
                    seen.push(route);
                }
                events.push(event);
            }
        }
        for address in &mut self.v4 {
            address.prefixed = true;
        }
        for address in &self.v4 {
            for route in self.candidates(address, true) {
                if !seen.iter().any(|r| r.same(&route)) {
                    seen.push(route);
                    events.push(Event::NewRoute4(route));
                }
            }
        }
        let before = self.routes6();
        for address in &mut self.v6 {
            address.prefixed = true;
        }
        for address in &self.v6 {
            if let Some(route) = address.prefix_route().filter(|r| !before.contains(r))
                && !events.contains(&Event::NewRoute6(route))
            {
                events.push(Event::NewRoute6(route));
            }
        }
        if !self.local6(Ipv6Addr::LOCALHOST) {
            let mut one = V6::new(Ipv6Addr::LOCALHOST, 128);
            one.proto = KERNEL_LO;
            one.prefixed = true;
            events.push(Event::NewAddr6(one.clone(), false));
            events.push(Event::NewRoute6(one.local_route()));
            self.insert_v6(one);
        }
        events
    }
    /// The loopback goes down: it loses every IPv6 address, and Linux tells
    /// of their routes going (`rt6_disable_ip`), the main table's then the
    /// local one's, then of the addresses (`addrconf_ifdown`). IPv4's
    /// broadcast routes go without a word.
    pub(crate) fn down(&mut self) -> Vec<Event> {
        let mut events: Vec<Event> = self.routes6().into_iter().map(Event::DelRoute6).collect();
        events.extend(self.v6.drain(..).map(Event::DelAddr6));
        events
    }
    /// Adds an IPv4 address as `__inet_insert_ifa` does: the same local
    /// address and subnet again is `EEXIST`, unless `replace`, which takes
    /// its protocol; one in a subnet a primary address has is secondary,
    /// and goes last; a primary goes after the primaries of a scope as wide
    /// or wider. `up` gives it its prefix route at once. What Linux tells:
    /// the address, then the routes it brings (`fib_add_ifaddr`).
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
                        return Err(EEXIST);
                    }
                    old.proto = new.proto;
                    return Ok(Vec::new());
                }
                new.flags |= SECONDARY;
            }
        }
        new.prefixed = up;
        self.table = true;
        let before = self.routes4(up);
        let mut events = vec![Event::NewAddr4(new.clone())];
        if new.secondary() {
            self.v4.push(new.clone());
        } else {
            self.v4.insert(last_primary, new.clone());
        }
        for route in self.candidates(&new, up) {
            if !before.iter().any(|r| r.same(&route)) && !events.contains(&Event::NewRoute4(route))
            {
                events.push(Event::NewRoute4(route));
            }
        }
        Ok(events)
    }
    /// Removes the first IPv4 address that has `local`, `label`, and
    /// `address` in a subnet of `prefix`, each as given, as
    /// `inet_rtm_deladdr`: `EADDRNOTAVAIL` for none. A primary takes its
    /// secondaries with it (`promote_secondaries` is 0), which go first.
    /// What Linux tells: each address, then the routes that go with it, the
    /// prefix route, the broadcast ones, then the local one
    /// (`fib_del_ifaddr`).
    pub(crate) fn del_v4(
        &mut self,
        local: Option<Ipv4Addr>,
        address: Option<Ipv4Addr>,
        prefix: u8,
        label: Option<&[u8]>,
        up: bool,
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
            let before = self.routes4(up);
            // `fib_del_ifaddr`'s order: the prefix route, the broadcast ones,
            // then the local one.
            let candidates = self.candidates(&address, up);
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
            let after = self.routes4(up);
            events.push(Event::DelAddr4(address));
            for route in order {
                if before.iter().any(|r| r.same(&route)) && !after.iter().any(|r| r.same(&route)) {
                    events.push(Event::DelRoute4(route));
                }
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
                return Err(EEXIST);
            }
            old.proto = new.proto;
            return Ok(Vec::new());
        }
        new.flags |= PERMANENT;
        new.prefixed = up;
        let before = self.routes6();
        let mut events = Vec::new();
        if let Some(route) = new.prefix_route().filter(|r| !before.contains(r)) {
            events.push(Event::NewRoute6(route));
        }
        events.push(Event::NewAddr6(new.clone(), true));
        events.push(Event::NewAddr6(new.clone(), false));
        events.push(Event::NewRoute6(new.local_route()));
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
    /// none). What Linux tells: the address, its local route, then its
    /// prefix route if no other address keeps it.
    pub(crate) fn del_v6(&mut self, address: Ipv6Addr, prefix: u8) -> Result<Vec<Event>, Errno> {
        let found = self
            .v6
            .iter()
            .position(|a| a.address == address && a.prefix == prefix)
            .ok_or(EADDRNOTAVAIL)?;
        let gone = self.v6.remove(found);
        let after = self.routes6();
        let mut events = vec![
            Event::DelAddr6(gone.clone()),
            Event::DelRoute6(gone.local_route()),
        ];
        if let Some(route) = gone.prefix_route().filter(|r| !after.contains(r)) {
            events.push(Event::DelRoute6(route));
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
    /// one; while up, the broadcast one it names; its prefix route, `local`
    /// on a loopback, once a `NETDEV_UP` has added it (it stays when the
    /// loopback goes down); and while up, its subnet's broadcast route.
    fn candidates(&self, address: &V4, up: bool) -> Vec<Route4> {
        let source = self.primary_of(address);
        let route = |dst, len, kind| Route4 {
            dst,
            len,
            kind,
            source,
        };
        let mut routes = vec![route(address.local, 32, Kind::Local)];
        if up && let Some(broadcast) = address.broadcast.filter(|b| !b.is_broadcast()) {
            routes.push(route(broadcast, 32, Kind::Broadcast));
        }
        let prefix = Ipv4Addr::from(u32::from(address.address) & address.mask());
        if prefix.is_unspecified()
            || address.secondary()
            || (prefix == address.local && address.prefix == 32)
        {
            return routes;
        }
        if address.flags & NO_PREFIX_ROUTE == 0 && address.prefixed {
            routes.push(route(prefix, address.prefix, Kind::Local));
        }
        if up && address.prefix < 31 {
            routes.push(route(
                Ipv4Addr::from(u32::from(prefix) | !address.mask()),
                32,
                Kind::Broadcast,
            ));
        }
        routes
    }
    /// The IPv4 routes of the local table, as `fib_add_ifaddr` makes them,
    /// in the order of its trie: by destination, the shorter prefix first.
    pub(crate) fn routes4(&self, up: bool) -> Vec<Route4> {
        let mut routes: Vec<Route4> = Vec::new();
        for address in &self.v4 {
            for route in self.candidates(address, up) {
                if !routes.iter().any(|r| r.same(&route)) {
                    routes.push(route);
                }
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
            let route = address.local_route();
            if !local.contains(&route) {
                local.push(route);
            }
            if let Some(route) = address.prefix_route().filter(|r| !main.contains(r)) {
                main.push(route);
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

    /// A short form of an event: what it is and its address or route.
    fn told(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                Event::NewAddr4(a) => format!("+addr {}/{}", a.local, a.prefix),
                Event::DelAddr4(a) => format!("-addr {}/{}", a.local, a.prefix),
                Event::NewRoute4(r) => format!("+route {}/{} {:?}", r.dst, r.len, r.kind),
                Event::DelRoute4(r) => format!("-route {}/{} {:?}", r.dst, r.len, r.kind),
                Event::NewAddr6(a, tentative) => {
                    format!("+addr {}/{} {tentative}", a.address, a.prefix)
                }
                Event::DelAddr6(a) => format!("-addr {}/{}", a.address, a.prefix),
                Event::NewRoute6(r) => format!("+route {}/{} {:?}", r.dst, r.len, r.kind),
                Event::DelRoute6(r) => format!("-route {}/{} {:?}", r.dst, r.len, r.kind),
            })
            .collect()
    }

    #[test]
    fn changes_are_told_in_linux_order() {
        let mut a = Addresses::isolated();
        // Added while down: the address and its local route; IPv6's twice.
        let added = a.add_v4(v4("10.5.5.5", 24), false, false).unwrap();
        assert_eq!(
            told(&added),
            ["+addr 10.5.5.5/24", "+route 10.5.5.5/32 Local"]
        );
        let added = a
            .add_v6(V6::new("2001:db8::5".parse().unwrap(), 64), false, false)
            .unwrap();
        assert_eq!(
            told(&added),
            [
                "+addr 2001:db8::5/64 true",
                "+addr 2001:db8::5/64 false",
                "+route 2001:db8::5/128 Local",
            ]
        );
        // Up: 127.0.0.1/8 and its routes, the routes the up brings the
        // other address, IPv6's prefix route, then ::1.
        assert_eq!(
            told(&a.up()),
            [
                "+addr 127.0.0.1/8",
                "+route 127.0.0.1/32 Local",
                "+route 127.0.0.0/8 Local",
                "+route 127.255.255.255/32 Broadcast",
                "+route 10.5.5.0/24 Local",
                "+route 10.5.5.255/32 Broadcast",
                "+route 2001:db8::/64 Unicast",
                "+addr ::1/128 false",
                "+route ::1/128 Local",
            ]
        );
        let added = a
            .add_v6(V6::new("2001:db8:1::1".parse().unwrap(), 64), false, true)
            .unwrap();
        assert_eq!(told(&added)[0], "+route 2001:db8:1::/64 Unicast");
        // A primary goes after its secondary: each address, then its
        // routes, the prefix route first and the local one last.
        a.add_v4(v4("10.5.5.9", 24), false, true).unwrap();
        let gone = a
            .del_v4(Some("10.5.5.5".parse().unwrap()), None, 24, None, true)
            .unwrap();
        assert_eq!(
            told(&gone),
            [
                "-addr 10.5.5.9/24",
                "-route 10.5.5.9/32 Local",
                "-addr 10.5.5.5/24",
                "-route 10.5.5.0/24 Local",
                "-route 10.5.5.255/32 Broadcast",
                "-route 10.5.5.5/32 Local",
            ]
        );
        // Down: IPv6's routes, the main table's first, then its addresses.
        assert_eq!(
            told(&a.down()),
            [
                "-route 2001:db8::/64 Unicast",
                "-route 2001:db8:1::/64 Unicast",
                "-route ::1/128 Local",
                "-route 2001:db8::5/128 Local",
                "-route 2001:db8:1::1/128 Local",
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
            true,
        )
        .unwrap();
        assert_eq!(a.v4.len(), 2);
        assert_eq!(
            a.del_v4(None, Some("10.1.2.3".parse().unwrap()), 24, None, true),
            Err(EADDRNOTAVAIL)
        );
        a.del_v4(Some(Ipv4Addr::LOCALHOST), None, 8, None, true)
            .unwrap();
        assert!(!a.bindable4(Ipv4Addr::LOCALHOST, true));
        a.up();
        assert!(a.bindable4(Ipv4Addr::LOCALHOST, true));
    }
}
