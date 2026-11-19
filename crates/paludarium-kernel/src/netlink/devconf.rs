//! The netconf notifications (`RTM_NEWNETCONF`, `RTM_DELNETCONF`) that
//! the members of `RTNLGRP_IPV4_NETCONF` and `RTNLGRP_IPV6_NETCONF` hear
//! as a device's settings come, change or go ([`crate::netconf::Told`]),
//! each as `inet_netconf_fill_devconf` and `inet6_netconf_fill_devconf`
//! fill it: a `netconfmsg` with its family, `NETCONFA_IFINDEX`, and the
//! settings told of, or all of them for a device that comes. Port and
//! sequence number are 0, as `rtnl_notify` sends them.
//!
//! Multicast forwarding, proxy ARP and NDP, broadcast forwarding and
//! ignoring routes with their link down have no setting here, and are 0
//! as Linux is built; IPv6's multicast forwarding is told of as a kernel
//! built with `CONFIG_IPV6_MROUTE` (Ubuntu's) tells it.
use super::{Notice, attribute, message, notify};
use crate::inet::Network;
use crate::netconf::{Told, What};

const RTM_NEWNETCONF: u16 = 80;
const RTM_DELNETCONF: u16 = 81;
const RTNLGRP_IPV4_NETCONF: u32 = 24;
const RTNLGRP_IPV6_NETCONF: u32 = 25;
const NETCONFA_IFINDEX: u16 = 1;
const NETCONFA_FORWARDING: u16 = 2;
const NETCONFA_RP_FILTER: u16 = 3;
const NETCONFA_MC_FORWARDING: u16 = 4;
const NETCONFA_PROXY_NEIGH: u16 = 5;
const NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN: u16 = 6;
const NETCONFA_BC_FORWARDING: u16 = 8;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// The message of `told`.
fn fill(told: Told) -> (u32, Vec<u8>) {
    let (group, family, index, what, settings): (_, _, _, _, Vec<(u16, i32)>) = match told {
        Told::Ipv4(index, what, conf) => (
            RTNLGRP_IPV4_NETCONF,
            AF_INET,
            index,
            what,
            match what {
                What::All => vec![
                    (NETCONFA_FORWARDING, conf.forwarding),
                    (NETCONFA_RP_FILTER, conf.rp_filter),
                    (NETCONFA_MC_FORWARDING, 0),
                    (NETCONFA_BC_FORWARDING, 0),
                    (NETCONFA_PROXY_NEIGH, 0),
                    (NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN, 0),
                ],
                What::Forwarding => vec![(NETCONFA_FORWARDING, conf.forwarding)],
                What::RpFilter => vec![(NETCONFA_RP_FILTER, conf.rp_filter)],
                What::Gone => Vec::new(),
            },
        ),
        Told::Ipv6(index, what, conf) => (
            RTNLGRP_IPV6_NETCONF,
            AF_INET6,
            index,
            what,
            match what {
                What::All => vec![
                    (NETCONFA_FORWARDING, conf.forwarding),
                    (NETCONFA_MC_FORWARDING, 0),
                    (NETCONFA_PROXY_NEIGH, 0),
                    (NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN, 0),
                ],
                What::Forwarding => vec![(NETCONFA_FORWARDING, conf.forwarding)],
                // IPv6 has no `rp_filter`; nothing tells of it.
                What::RpFilter | What::Gone => Vec::new(),
            },
        ),
    };
    // `struct netconfmsg`, its one byte padded to four with zeros
    // (`nlmsg_put`).
    let mut body = vec![family, 0, 0, 0];
    attribute(&mut body, NETCONFA_IFINDEX, &index.to_le_bytes());
    for (kind, value) in settings {
        attribute(&mut body, kind, &value.to_le_bytes());
    }
    let kind = if what == What::Gone {
        RTM_DELNETCONF
    } else {
        RTM_NEWNETCONF
    };
    (group, message(kind, 0, 0, 0, &body))
}

/// The notices of `told`, in its order.
pub(super) fn notices(told: Vec<Told>) -> Vec<Notice> {
    told.into_iter()
        .map(|told| {
            let (group, bytes) = fill(told);
            Notice {
                to: None,
                heard: false,
                group,
                origin: 0,
                bytes,
            }
        })
        .collect()
}

/// Tells `network`'s members of `told`, as a write of `/proc/sys/net`
/// does ([`crate::sysctl`]). No socket is locked.
pub(crate) fn tell(network: &Network, told: Vec<Told>) {
    if !told.is_empty() {
        notify(network, notices(told), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netdev::{Conf4, Conf6};

    #[test]
    fn a_device_that_comes_tells_all_its_settings_and_one_that_goes_its_index() {
        let conf4 = Conf4 {
            forwarding: 1,
            rp_filter: 2,
            rp_filter_set: true,
        };
        let (group, bytes) = fill(Told::Ipv4(5, What::All, conf4));
        assert_eq!(group, RTNLGRP_IPV4_NETCONF);
        // A header, `netconfmsg`, and seven attributes of eight bytes.
        assert_eq!(bytes.len(), 16 + 4 + 7 * 8);
        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 76);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), RTM_NEWNETCONF);
        assert_eq!(&bytes[16..20], &[AF_INET, 0, 0, 0]);
        let attrs: Vec<(u16, i32)> = bytes[20..]
            .chunks(8)
            .map(|a| {
                (
                    u16::from_le_bytes([a[2], a[3]]),
                    i32::from_le_bytes(a[4..8].try_into().unwrap()),
                )
            })
            .collect();
        assert_eq!(
            attrs,
            [(1, 5), (2, 1), (3, 2), (4, 0), (8, 0), (5, 0), (6, 0)]
        );
        let (group, bytes) = fill(Told::Ipv6(5, What::All, Conf6::default()));
        assert_eq!(group, RTNLGRP_IPV6_NETCONF);
        assert_eq!(bytes.len(), 16 + 4 + 5 * 8);
        let (_, bytes) = fill(Told::Ipv6(5, What::Gone, Conf6::default()));
        assert_eq!(bytes.len(), 28);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), RTM_DELNETCONF);
        assert_eq!(&bytes[16..20], &[AF_INET6, 0, 0, 0]);
        let (_, bytes) = fill(Told::Ipv4(-1, What::Forwarding, conf4));
        assert_eq!(
            &bytes[20..],
            &[8, 0, 1, 0, 255, 255, 255, 255, 8, 0, 2, 0, 1, 0, 0, 0]
        );
    }
}
