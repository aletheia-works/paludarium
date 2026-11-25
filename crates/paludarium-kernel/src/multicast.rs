//! IPv4 multicast groups (Linux's `igmp.c`): the groups each device has
//! joined, which say what comes in through it (`ip_check_mc_rcu`), and the
//! memberships of each socket, which make a device join and leave. No IGMP
//! packet is sent, as nothing here would see one.

use crate::inet::Network;
use core::net::{IpAddr, Ipv4Addr};
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

/// The groups a device has joined (`in_dev->mc_list`), the newest first,
/// each with how many times it has been.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Groups {
    list: Vec<(Ipv4Addr, u32)>,
}
impl Groups {
    /// The device joins `group` once more (`ip_mc_inc_group`).
    pub(crate) fn join(&mut self, group: Ipv4Addr) {
        match self.list.iter_mut().find(|(g, _)| *g == group) {
            Some((_, users)) => *users += 1,
            None => self.list.insert(0, (group, 1)),
        }
    }
    /// The device leaves `group` once, for good with its last user
    /// (`ip_mc_dec_group`).
    pub(crate) fn leave(&mut self, group: Ipv4Addr) {
        self.list.retain_mut(|(g, users)| {
            if *g == group {
                *users -= 1;
            }
            *users > 0
        });
    }
    /// Whether the device takes what goes to `group` (`ip_check_mc_rcu`).
    pub(crate) fn has(&self, group: Ipv4Addr) -> bool {
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
        let rp_filter = {
            let devices = self.devices();
            let Some(device) = devices.by_index(index).filter(|d| d.groups4.has(group)) else {
                return false;
            };
            device.conf4.rp_filter.max(devices.all4.rp_filter)
        };
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
