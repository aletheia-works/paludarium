//! Multicast groups (Linux's `igmp.c` and IPv6's `mcast.c`): the groups each
//! device has joined, which say what comes in through it
//! (`ip_check_mc_rcu`, `ipv6_chk_mcast_addr`), and the memberships of each
//! socket, which make a device join and leave. No IGMP or MLD packet is
//! sent, as nothing here would see one.

use crate::inet::Network;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use paludarium_types::Errno;

const EADDRINUSE: Errno = Errno(98);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENOBUFS: Errno = Errno(105);
const ENODEV: Errno = Errno(19);

/// `IGMP_ALL_HOSTS`, the group every device is in while it is up
/// (`ip_mc_up`).
pub(crate) const ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// The most memberships a socket has (`net.ipv4.igmp_max_memberships`).
const MAX_MEMBERSHIPS: usize = 20;

/// The groups a device has joined (`in_dev->mc_list`, `idev->mc_list`), the
/// newest first, each with how many times it has been. Of IPv6's, those that
/// sockets joined ([`Network::in_group6`] has the rest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Groups<A> {
    list: Vec<(A, u32)>,
}
impl<A> Default for Groups<A> {
    fn default() -> Self {
        Self { list: Vec::new() }
    }
}
impl<A: Copy + PartialEq> Groups<A> {
    /// The device joins `group` once more (`ip_mc_inc_group`,
    /// `__ipv6_dev_mc_inc`).
    pub(crate) fn join(&mut self, group: A) {
        match self.list.iter_mut().find(|(g, _)| *g == group) {
            Some((_, users)) => *users += 1,
            None => self.list.insert(0, (group, 1)),
        }
    }
    /// The device leaves `group` once, for good with its last user
    /// (`ip_mc_dec_group`, `__ipv6_dev_mc_dec`).
    pub(crate) fn leave(&mut self, group: A) {
        self.list.retain_mut(|(g, users)| {
            if *g == group {
                *users -= 1;
            }
            *users > 0
        });
    }
    /// Whether the device has joined `group` (`ip_check_mc_rcu`).
    pub(crate) fn has(&self, group: A) -> bool {
        self.list.iter().any(|(g, _)| *g == group)
    }
}

/// A membership a socket asks for or has (`struct ip_mreqn`): the group,
/// and the device, by its index or an address of it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Membership {
    pub(crate) group: Ipv4Addr,
    pub(crate) address: Ipv4Addr,
    pub(crate) index: i32,
}
impl Membership {
    /// Reads an `ip_mreqn`, or an `ip_mreq`, which has no index.
    pub(crate) fn read(raw: &[u8]) -> Self {
        let word = |at: usize| {
            raw.get(at..at + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
        };
        Self {
            group: word(0).unwrap_or_default().into(),
            address: word(4).unwrap_or_default().into(),
            index: i32::from_le_bytes(word(8).unwrap_or_default()),
        }
    }
}

/// Whether a socket of `memberships`, the newest first, takes a datagram to
/// `group` that came in on the device `dif`: as a member there, or, in no
/// such group there, while it takes every group's (`IP_MULTICAST_ALL`), as
/// `ip_mc_sf_allow` decides with no source filter.
pub(crate) fn allows(memberships: &[Membership], all: bool, group: Ipv4Addr, dif: u32) -> bool {
    all || memberships
        .iter()
        .any(|m| m.group == group && u32::try_from(m.index) == Ok(dif))
}

/// An IPv6 membership a socket asks for or has (`struct ipv6_mreq`): the
/// group, and the device's index.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Membership6 {
    pub(crate) group: Ipv6Addr,
    pub(crate) index: i32,
}
impl Membership6 {
    /// Reads an `ipv6_mreq`.
    pub(crate) fn read(raw: &[u8; 20]) -> Self {
        let mut group = [0; 16];
        group.copy_from_slice(&raw[..16]);
        Self {
            group: group.into(),
            index: i32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]),
        }
    }
}

/// Whether a socket of `memberships` takes a datagram to the IPv6 group
/// `group`, on whatever device: as a member, or, as none, while it takes
/// every group's (`IPV6_MULTICAST_ALL`), as `inet6_mc_check` decides with no
/// source filter.
pub(crate) fn allows6(memberships: &[Membership6], all: bool, group: Ipv6Addr) -> bool {
    all || memberships.iter().any(|m| m.group == group)
}
/// The scope of an IPv6 group (`IPV6_ADDR_MC_SCOPE`): 1 is the interface's
/// own.
pub(crate) fn scope6(group: Ipv6Addr) -> u8 {
    group.octets()[1] & 0xf
}

impl Network {
    /// The device that has the IPv4 address `ip` (`__ip_dev_find`): by its
    /// addresses, else by the local table's routes.
    pub(crate) fn device_with4(&self, ip: Ipv4Addr, now: Option<u64>) -> Option<i32> {
        let addresses = self.addresses_at(now);
        addresses.device_of4(ip).or_else(|| {
            addresses
                .local4(ip)
                .then(|| addresses.lookup4(ip).ok())
                .flatten()
                .and_then(|route| i32::try_from(route.oif).ok())
        })
    }
    /// The device the route to `group` goes out through, if one does.
    fn device_to4(&self, group: Ipv4Addr, now: Option<u64>) -> Option<i32> {
        use crate::interface::Kind;
        let route = self.addresses_at(now).lookup4(group).ok()?;
        matches!(route.kind, Kind::Unicast | Kind::Broadcast | Kind::Local)
            .then(|| i32::try_from(route.oif).ok())
            .flatten()
    }
    /// Whether `group`'s route goes out through `lo`.
    pub(crate) fn group_on_lo(&self, group: Ipv4Addr, now: Option<u64>) -> bool {
        self.device_to4(group, now) == Some(crate::netdev::LOOPBACK_INDEX)
    }
    /// The device `asked` names (`ip_mc_find_dev`): that of its index, of
    /// its address, or of the route to the group.
    fn group_device(&self, asked: &Membership, now: Option<u64>) -> Option<i32> {
        if asked.index != 0 {
            return self.has_device(asked.index).then_some(asked.index);
        }
        if asked.address.is_unspecified() {
            return self.device_to4(asked.group, now);
        }
        self.device_with4(asked.address, now)
    }
    /// Whether the device `index` has joined `group`.
    pub(crate) fn in_group4(&self, index: i32, group: Ipv4Addr) -> bool {
        self.devices()
            .by_index(index)
            .is_some_and(|d| d.groups4.has(group))
    }
    /// Joins `group` on the device `index`, or leaves it.
    pub(crate) fn change_group4(&self, index: i32, group: Ipv4Addr, join: bool) {
        if let Some(device) = self.devices().by_index_mut(index) {
            if join {
                device.groups4.join(group);
            } else {
                device.groups4.leave(group);
            }
        }
    }
    /// A socket of `memberships` joins the group `asked`
    /// (`__ip_mc_join_group`): `EINVAL` for no group, `ENODEV` for no
    /// device, `EADDRINUSE` as a member there already, `ENOBUFS` at the
    /// most.
    pub(crate) fn join4(
        &self,
        memberships: &mut Vec<Membership>,
        asked: Membership,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = self.group_device(&asked, now).ok_or(ENODEV)?;
        if memberships
            .iter()
            .any(|m| m.group == asked.group && m.index == index)
        {
            return Err(EADDRINUSE);
        }
        if memberships.len() >= MAX_MEMBERSHIPS {
            return Err(ENOBUFS);
        }
        memberships.insert(0, Membership { index, ..asked });
        self.change_group4(index, asked.group, true);
        Ok(())
    }
    /// A socket of `memberships` leaves the group `asked`
    /// (`ip_mc_leave_group`), on the device it names, or, naming one there
    /// is not, by the address it was joined with: `ENODEV` for none at all,
    /// `EADDRNOTAVAIL` as no member. The device it joined leaves the group,
    /// as Linux master has it.
    pub(crate) fn leave4(
        &self,
        memberships: &mut Vec<Membership>,
        asked: Membership,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let index = match self.group_device(&asked, now) {
            Some(index) => index,
            None if asked.index == 0 && asked.address.is_unspecified() => return Err(ENODEV),
            None => asked.index,
        };
        let at = memberships
            .iter()
            .position(|m| {
                m.group == asked.group
                    && if index != 0 {
                        m.index == index
                    } else {
                        m.address == asked.address
                    }
            })
            .ok_or(EADDRNOTAVAIL)?;
        let left = memberships.remove(at);
        self.change_group4(left.index, left.group, false);
        Ok(())
    }
    /// A socket of `memberships` that goes leaves them all
    /// (`ip_mc_drop_socket`).
    pub(crate) fn drop4(&self, memberships: &[Membership]) {
        for m in memberships {
            self.change_group4(m.index, m.group, false);
        }
    }
    /// Whether a packet from `src` to the group `group` in through the
    /// device `index` comes here (`ip_route_input_mc`): the device has
    /// joined it, and `src` is one it may come from (`ip_mc_validate_source`,
    /// with the reverse path filtering `rp_filter`).
    pub(crate) fn takes_group4(
        &self,
        index: i32,
        src: Ipv4Addr,
        group: Ipv4Addr,
        now: Option<u64>,
    ) -> bool {
        if !self.in_group4(index, group) {
            return false;
        }
        let rp_filter = self.rp_filter(index);
        if src.is_multicast() || src.is_broadcast() || src.is_loopback() {
            return false;
        }
        if src.is_unspecified() {
            return local_group(group);
        }
        self.addresses_at(now)
            .validate_source4_on(src, 0, 0, rp_filter, index)
            .is_ok()
    }
}
impl Network {
    /// Whether the device `index` is in the IPv6 group `group`
    /// (`ipv6_chk_mcast_addr`): as one a socket joined, the all-nodes groups
    /// every device with IPv6 is in (`ipv6_add_dev`), the solicited-node
    /// group of an address of a veth end's (`addrconf_join_solict`), or the
    /// all-routers groups of one that forwards (`dev_forward_change`).
    pub(crate) fn in_group6(&self, index: i32, group: Ipv6Addr, now: Option<u64>) -> bool {
        let (joined, veth, routes) = {
            let devices = self.devices();
            let Some(device) = devices.by_index(index) else {
                return false;
            };
            (
                device.groups6.has(group),
                device.veth.is_some(),
                device.conf6.forwarding != 0,
            )
        };
        let first = group.segments()[0];
        let nodes = |id: u16| group.segments() == [first, 0, 0, 0, 0, 0, 0, id];
        joined
            || nodes(1) && matches!(first, 0xff01 | 0xff02)
            || veth && routes && nodes(2) && matches!(first, 0xff01 | 0xff02 | 0xff05)
            || veth && self.addresses_at(now).solicits6(index, group)
    }
    /// Whether the device `index` has IPv6 at all (`in6_dev_get`): not a
    /// veth end of an MTU below 1280.
    fn has_ipv6(&self, index: i32) -> bool {
        self.devices()
            .by_index(index)
            .is_some_and(|d| d.veth.as_ref().is_none_or(|v| v.mtu >= 1280))
    }
    /// Joins the IPv6 group `group` on the device `index`, or leaves it.
    fn change_group6(&self, index: i32, group: Ipv6Addr, join: bool) {
        if let Some(device) = self.devices().by_index_mut(index) {
            if join {
                device.groups6.join(group);
            } else {
                device.groups6.leave(group);
            }
        }
    }
    /// A socket of `memberships` joins the IPv6 group `asked`
    /// (`__ipv6_sock_mc_join`): `EINVAL` for no group, `EADDRINUSE` as a
    /// member there, or anywhere for no device named, `ENODEV` for none
    /// there is or routes to the group, `EINVAL` for one without IPv6.
    pub(crate) fn join6(
        &self,
        memberships: &mut Vec<Membership6>,
        asked: Membership6,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        if memberships
            .iter()
            .any(|m| m.group == asked.group && (asked.index == 0 || m.index == asked.index))
        {
            return Err(EADDRINUSE);
        }
        let index = if asked.index != 0 {
            self.has_device(asked.index).then_some(asked.index)
        } else {
            let route = self.addresses_at(now).lookup6(asked.group).ok();
            route.and_then(|route| i32::try_from(route.oif).ok())
        };
        let index = index.ok_or(ENODEV)?;
        if !self.has_ipv6(index) {
            return Err(Errno::EINVAL);
        }
        memberships.insert(0, Membership6 { index, ..asked });
        self.change_group6(index, asked.group, true);
        Ok(())
    }
    /// A socket of `memberships` leaves the IPv6 group `asked`
    /// (`ipv6_sock_mc_drop`), on the device it names or the newest there is:
    /// `EINVAL` for no group, `EADDRNOTAVAIL` as no member.
    pub(crate) fn leave6(
        &self,
        memberships: &mut Vec<Membership6>,
        asked: Membership6,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let at = memberships
            .iter()
            .position(|m| m.group == asked.group && (asked.index == 0 || m.index == asked.index))
            .ok_or(EADDRNOTAVAIL)?;
        let left = memberships.remove(at);
        self.change_group6(left.index, left.group, false);
        Ok(())
    }
    /// A socket of `memberships` that goes leaves them all
    /// (`__ipv6_sock_mc_close`).
    pub(crate) fn drop6(&self, memberships: &[Membership6]) {
        for m in memberships {
            self.change_group6(m.index, m.group, false);
        }
    }
    /// Whether a packet from `src` to the IPv6 group `group` in through the
    /// veth end `index` comes here: of a scope past the interface's and not
    /// from a loopback address (`ip6_rcv_core`), where a multicast route
    /// takes the group on that end (`ip6_route_input`) and the end is in it
    /// (`ip6_mc_input`).
    pub(crate) fn takes_group6(
        &self,
        index: i32,
        src: Ipv6Addr,
        group: Ipv6Addr,
        now: Option<u64>,
    ) -> bool {
        if scope6(group) <= 1 || src.is_loopback() || src.is_multicast() {
            return false;
        }
        let routed = self
            .addresses_at(now)
            .lookup6_flow(
                group,
                index.unsigned_abs(),
                &crate::interface::Flow6::default(),
            )
            .is_ok_and(|route| route.kind == crate::interface::Kind::Multicast);
        routed && self.has_ipv6(index) && self.in_group6(index, group, now)
    }
}
/// Whether `group` is one of the local network's, 224.0.0.0/24
/// (`ipv4_is_local_multicast`).
pub(crate) fn local_group(group: Ipv4Addr) -> bool {
    group.octets()[..3] == [224, 0, 0]
}
/// The Ethernet address an IPv4 group's packets go to (`ip_eth_mc_map`).
pub(crate) fn ethernet(group: IpAddr) -> [u8; 6] {
    match group {
        IpAddr::V4(group) => {
            let [_, b, c, d] = group.octets();
            [0x01, 0x00, 0x5e, b & 0x7f, c, d]
        }
        IpAddr::V6(group) => {
            let [.., a, b, c, d] = group.octets();
            [0x33, 0x33, a, b, c, d]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 1, 2, 3);
    fn asked(index: i32) -> Membership {
        Membership {
            group: GROUP,
            address: Ipv4Addr::UNSPECIFIED,
            index,
        }
    }

    #[test]
    fn a_device_leaves_with_its_last_user() {
        let mut groups = Groups::default();
        groups.join(GROUP);
        groups.join(GROUP);
        groups.leave(GROUP);
        assert!(groups.has(GROUP));
        groups.leave(GROUP);
        assert!(!groups.has(GROUP));
        // One never joined, nothing.
        groups.leave(GROUP);
    }

    #[test]
    fn sockets_join_and_leave_on_lo() {
        let network = Network::new(crate::inet::NetworkPolicy::default());
        assert!(network.in_group4(1, ALL_HOSTS));
        let mut mine = Vec::new();
        assert_eq!(network.join4(&mut mine, asked(1), None), Ok(()));
        assert_eq!(network.join4(&mut mine, asked(1), None), Err(EADDRINUSE));
        assert_eq!(network.join4(&mut mine, asked(9), None), Err(ENODEV));
        // By the group's route: there is none.
        assert_eq!(network.join4(&mut mine, asked(0), None), Err(ENODEV));
        let unicast = Membership {
            group: Ipv4Addr::LOCALHOST,
            ..asked(1)
        };
        assert_eq!(network.join4(&mut mine, unicast, None), Err(Errno::EINVAL));
        assert!(allows(&mine, false, GROUP, 1) && !allows(&mine, false, GROUP, 2));
        assert!(allows(&mine, true, GROUP, 2));
        assert_eq!(network.leave4(&mut mine, asked(0), None), Err(ENODEV));
        assert_eq!(
            network.leave4(&mut mine, asked(9), None),
            Err(EADDRNOTAVAIL)
        );
        assert!(network.in_group4(1, GROUP));
        // By the address of the device.
        let by_address = Membership {
            address: Ipv4Addr::LOCALHOST,
            ..asked(0)
        };
        assert_eq!(network.leave4(&mut mine, by_address, None), Ok(()));
        assert!(mine.is_empty() && !network.in_group4(1, GROUP));
        for last in 0..MAX_MEMBERSHIPS as u8 {
            let group = Membership {
                group: Ipv4Addr::new(239, 0, 0, last),
                ..asked(1)
            };
            assert_eq!(network.join4(&mut mine, group, None), Ok(()));
        }
        assert_eq!(network.join4(&mut mine, asked(1), None), Err(ENOBUFS));
        network.drop4(&mine);
        assert!(!network.in_group4(1, Ipv4Addr::new(239, 0, 0, 0)));
    }

    #[test]
    fn ipv6_sockets_join_and_leave_on_lo() {
        let network = Network::new(crate::inet::NetworkPolicy::default());
        let nodes: Ipv6Addr = "ff02::1".parse().unwrap();
        let asked = |group: &str, index| Membership6 {
            group: group.parse().unwrap(),
            index,
        };
        let mut mine = Vec::new();
        assert!(network.in_group6(1, nodes, None));
        // No member of a group the device is in.
        assert_eq!(
            network.leave6(&mut mine, asked("ff02::1", 1)),
            Err(EADDRNOTAVAIL)
        );
        assert_eq!(network.join6(&mut mine, asked("ff02::1", 1), None), Ok(()));
        assert_eq!(network.leave6(&mut mine, asked("ff02::1", 0)), Ok(()));
        assert!(network.in_group6(1, nodes, None));
        let group = asked("ff05::7", 1);
        assert_eq!(network.join6(&mut mine, group, None), Ok(()));
        for index in [0, 1] {
            let again = Membership6 { index, ..group };
            assert_eq!(network.join6(&mut mine, again, None), Err(EADDRINUSE));
        }
        assert_eq!(
            network.join6(&mut mine, asked("ff05::7", 9), None),
            Err(ENODEV)
        );
        assert_eq!(
            network.join6(&mut mine, asked("::1", 1), None),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            network.leave6(&mut mine, asked("::1", 1)),
            Err(Errno::EINVAL)
        );
        assert!(network.in_group6(1, group.group, None));
        assert!(allows6(&mine, false, group.group) && !allows6(&mine, false, nodes));
        network.drop6(&mine);
        assert!(!network.in_group6(1, group.group, None));
        // A loopback has no solicited-node nor all-routers group.
        for other in ["ff02::2", "ff02::1:ff00:1", "ff05::1", "ff02::1:0:1"] {
            assert!(!network.in_group6(1, other.parse().unwrap(), None));
        }
        assert_eq!(scope6("ff15::1".parse().unwrap()), 5);
    }

    #[test]
    fn memberships_read_both_layouts() {
        let mreqn = [239, 1, 2, 3, 10, 0, 0, 1, 7, 0, 0, 0];
        let m = Membership::read(&mreqn);
        assert_eq!(
            (m.group, m.address, m.index),
            (GROUP, Ipv4Addr::new(10, 0, 0, 1), 7)
        );
        assert_eq!(Membership::read(&mreqn[..8]).index, 0);
    }

    #[test]
    fn groups_map_to_ethernet() {
        let of = |ip: &str| ethernet(ip.parse().unwrap());
        assert_eq!(of("239.129.2.3"), [1, 0, 0x5e, 1, 2, 3]);
        assert_eq!(of("ff02::1:ff00:a"), [0x33, 0x33, 0xff, 0, 0, 0xa]);
    }
}
