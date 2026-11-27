//! IPv6's anycast addresses that sockets join (`net/ipv6/anycast.c`):
//! `IPV6_JOIN_ANYCAST` and `IPV6_LEAVE_ANYCAST`, and what a socket joined
//! going with it. A device's own, the subnet-router anycast address of
//! each of its addresses while it forwards, and the device's list itself
//! are [`crate::interface::Addresses`]'.

use core::net::Ipv6Addr;

use paludarium_types::Errno;

use crate::inet::Network;
use crate::netdev::LOOPBACK_INDEX;

const EADDRNOTAVAIL: Errno = Errno(99);
const ENODEV: Errno = Errno(19);

/// An anycast address a socket has joined (`ipv6_ac_socklist`): of the
/// device of the index.
pub(crate) type Member = (i32, Ipv6Addr);

impl Network {
    /// The socket of `members` joins `address` on the device `index`, or
    /// on that of its route for 0, at `now`, as `ipv6_sock_ac_join` does:
    /// `EPERM` without `CAP_NET_ADMIN` (`admin`), `EINVAL` for a multicast
    /// address or an address of the namespace's that is not tentative;
    /// with no device named, `EADDRNOTAVAIL` for no route to it unless the
    /// namespace forwards (`all`), when it is the first device up that is
    /// no loopback; `ENODEV` for no device, or a named one without IPv6
    /// (`EADDRNOTAVAIL` for one not named); and, on a device that does not
    /// forward, `EADDRNOTAVAIL` for an address of no prefix of its
    /// addresses'. The device joins it ([`Self::tell_anycast`]).
    pub(crate) fn join_anycast6(
        &self,
        members: &mut Vec<Member>,
        (index, address): Member,
        (admin, all_forward): (bool, bool),
        now: u64,
    ) -> Result<(), Errno> {
        if !admin {
            return Err(Errno::EPERM);
        }
        if address.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let named = (index != 0)
            .then(|| self.has_device(index).then_some(index))
            .flatten();
        let device = {
            let addresses = self.addresses_at(Some(now));
            if addresses
                .v6()
                .iter()
                .any(|a| a.address == address && !a.tentative())
            {
                return Err(Errno::EINVAL);
            }
            if index != 0 {
                named
            } else {
                // `rt6_lookup`: the route's device, a local route's the
                // loopback; none for a rejecting one.
                match addresses.lookup6(address) {
                    Ok(route) if route.kind.error().is_none() => {
                        if route.kind == crate::interface::Kind::Local {
                            Some(LOOPBACK_INDEX)
                        } else {
                            i32::try_from(route.oif).ok()
                        }
                    }
                    _ if !all_forward => return Err(EADDRNOTAVAIL),
                    // `netdev_get_by_flags_rcu`: the first that is up and
                    // no loopback.
                    _ => self.first_up_veth(),
                }
            }
        };
        let Some(device) = device else {
            return Err(ENODEV);
        };
        if !self.has_ipv6(device) {
            return Err(if index != 0 { ENODEV } else { EADDRNOTAVAIL });
        }
        let events = {
            let mut addresses = self.addresses_at(Some(now));
            if !addresses.forwards6(device) && !addresses.on_prefix6(device, address) {
                return Err(EADDRNOTAVAIL);
            }
            addresses.anycast_inc(device, address, now)
        };
        members.insert(0, (device, address));
        self.tell_anycast(events, now);
        Ok(())
    }
    /// The socket of `members` leaves `address` on the device `index`, or
    /// on any for 0, at `now` (`ipv6_sock_ac_drop`): the newest it joined
    /// so, `ENOENT` for none; its device, if it is there still, leaves it.
    pub(crate) fn leave_anycast6(
        &self,
        members: &mut Vec<Member>,
        (index, address): Member,
        now: u64,
    ) -> Result<(), Errno> {
        let at = members
            .iter()
            .position(|&(i, a)| (index == 0 || i == index) && a == address)
            .ok_or(Errno::ENOENT)?;
        let (device, address) = members.remove(at);
        let events = self
            .addresses_at(Some(now))
            .anycast_dec(device, address, now)
            .unwrap_or_default();
        self.tell_anycast(events, now);
        Ok(())
    }
    /// What a closed socket joined goes at `now` (`__ipv6_sock_ac_close`),
    /// the newest first.
    pub(crate) fn drop_anycast6(&self, members: &[Member], now: u64) {
        if members.is_empty() {
            return;
        }
        let mut events = Vec::new();
        {
            let mut addresses = self.addresses_at(Some(now));
            for &(device, address) in members {
                events.extend(
                    addresses
                        .anycast_dec(device, address, now)
                        .unwrap_or_default(),
                );
            }
        }
        self.tell_anycast(events, now);
    }
    /// Tells of what a device's anycast addresses' changes made: their
    /// routes and themselves, then their solicited-node groups.
    fn tell_anycast(&self, events: Vec<crate::interface::Event>, now: u64) {
        crate::netlink::tell_events(self, events, now);
        crate::netlink::tell_groups(self);
    }
    /// The first veth end up (`IFF_UP`), in the namespace's order.
    fn first_up_veth(&self) -> Option<i32> {
        self.devices()
            .iter()
            .find(|d| d.veth.as_ref().is_some_and(|v| v.up))
            .map(|d| d.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::{Lifetimes, V6};

    fn network() -> Network {
        use crate::netdev::{Conf4, Conf6, Device};
        let network = Network::isolated(crate::users::first());
        let va = Device::veth(
            1000,
            b"va".to_vec(),
            [2, 0, 0, 0, 0, 0xa],
            1500,
            (Conf4::default(), Conf6::default()),
        );
        network.devices().add(va, true);
        network.register6(1000, 0);
        network
    }
    fn address(network: &Network, index: i32, text: &str, prefix: u8) {
        let mut new = V6::new(text.parse().unwrap(), prefix);
        new.index = index;
        new.flags |= crate::interface::NO_DAD;
        let lifetimes = Lifetimes {
            valid: crate::interface::FOREVER,
            preferred: crate::interface::FOREVER,
        };
        network
            .addresses()
            .add_v6(new, lifetimes, false, true, None, 0)
            .unwrap();
    }
    fn listed(network: &Network) -> Vec<(i32, String, u32)> {
        network
            .addresses()
            .anycast6()
            .iter()
            .map(|a| (a.index, a.address.to_string(), a.users))
            .collect()
    }

    #[test]
    fn a_host_joins_an_address_of_a_prefix_of_the_device() {
        let network = network();
        address(&network, 1000, "2001:db8::1", 64);
        let mut members = Vec::new();
        let ip = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let join = |members: &mut Vec<Member>, index, a: &str| {
            network.join_anycast6(members, (index, ip(a)), (true, false), 1)
        };
        assert_eq!(join(&mut members, 1000, "ff02::1"), Err(Errno::EINVAL));
        assert_eq!(join(&mut members, 1000, "2001:db8::1"), Err(Errno::EINVAL));
        assert_eq!(join(&mut members, 999, "2001:db8::9"), Err(ENODEV));
        assert_eq!(
            join(&mut members, 1000, "2001:db8:1::9"),
            Err(EADDRNOTAVAIL)
        );
        assert_eq!(
            network.join_anycast6(&mut members, (1000, ip("2001:db8::9")), (false, false), 1),
            Err(Errno::EPERM)
        );
        assert_eq!(join(&mut members, 1000, "2001:db8::9"), Ok(()));
        assert_eq!(join(&mut members, 0, "2001:db8::9"), Ok(()));
        assert_eq!(listed(&network), [(1000, "2001:db8::9".into(), 2)]);
        assert_eq!(
            network.leave_anycast6(&mut members, (1000, ip("2001:db8::8")), 2),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            network.leave_anycast6(&mut members, (0, ip("2001:db8::9")), 2),
            Ok(())
        );
        assert_eq!(listed(&network), [(1000, "2001:db8::9".into(), 1)]);
        network.drop_anycast6(&members, 3);
        assert!(listed(&network).is_empty());
    }

    #[test]
    fn a_device_that_forwards_joins_its_subnet_routers_and_any_address() {
        let network = network();
        address(&network, 1000, "2001:db8::1", 64);
        address(&network, 1000, "2001:db8:1::1", 127);
        let events = network.addresses().forward6(1000, true, 1);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(listed(&network), [(1000, "2001:db8::".into(), 1)]);
        address(&network, 1000, "2001:db8::2", 64);
        assert_eq!(listed(&network), [(1000, "2001:db8::".into(), 2)]);
        let mut members = Vec::new();
        let any: Ipv6Addr = "2001:db8:9::1".parse().unwrap();
        assert_eq!(
            network.join_anycast6(&mut members, (1000, any), (true, false), 2),
            Ok(())
        );
        let _ = network.addresses().forward6(1000, false, 3);
        assert_eq!(listed(&network), [(1000, "2001:db8:9::1".into(), 1)]);
    }
}
