//! How the settings of a network namespace's devices change, as
//! `/proc/sys/net` sets them ([`crate::sysctl`]): those of `all`, of
//! `default` and of each device ([`crate::netdev::Conf4`],
//! [`crate::netdev::Conf6`]), as Linux's `net/ipv4/devinet.c` and
//! `net/ipv6/addrconf.c` keep them. IPv4's `forwarding` (with
//! `ip_forward`, `all`'s) and `rp_filter`, and IPv6's `forwarding` and
//! `disable_ipv6`.
//!
//! The first namespace has them as Linux is built: all 0. A new namespace
//! copies IPv4's `all` and `default` from the first one and starts IPv6's
//! as built, as Linux does with `net.core.devconf_inherit_init_net` at 0,
//! and its loopback copies `default` ([`inherit`]; `inetdev_init`,
//! `ipv6_add_dev`).
//!
//! A write sets them as the handlers do, with what each sets besides:
//! - IPv4 `forwarding` (`devinet_sysctl_forward`): `all`'s, when it
//!   changes, sets `default`'s and every device's (`inet_forward_change`);
//!   `default`'s and a device's set their own alone.
//! - `rp_filter` (`devinet_conf_proc`): a device the write is to keeps its
//!   own from then on, even when the write fails; one to `default` sets
//!   every device that keeps none.
//! - IPv6 `forwarding` (`addrconf_fixup_forwarding`): `all`'s sets
//!   `default`'s and every device's.
//! - `disable_ipv6` (`addrconf_disable_ipv6`): `all`'s sets `default`'s and
//!   every device's; a device whose IPv6 goes on or off by it loses its
//!   addresses and routes or takes them back ([`Change`]).
//!
//! Each setter gives back what Linux tells netlink's members of
//! `RTNLGRP_IPV4_NETCONF` and `RTNLGRP_IPV6_NETCONF` of it ([`Told`],
//! sent by [`crate::netlink::devconf`]): a change of `forwarding` or
//! `rp_filter`, but not of `disable_ipv6`, which tells nothing so. A device
//! that comes or goes is told of too ([`registered`], [`unregistered`]).
use crate::inet::Network;
use crate::netdev::{Conf4, Conf6, Device, Devices};

/// The `NETCONFA_IFINDEX` of `all`'s and `default`'s settings
/// (`NETCONFA_IFINDEX_ALL`, `NETCONFA_IFINDEX_DEFAULT`).
pub(crate) const INDEX_ALL: i32 = -1;
pub(crate) const INDEX_DEFAULT: i32 = -2;

/// What a netconf notification tells of settings: all that a device's
/// coming tells (`NETCONFA_ALL`), one of them, or that they went
/// (`RTM_DELNETCONF`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum What {
    All,
    Forwarding,
    RpFilter,
    Gone,
}

/// One netconf notification, of IPv4's settings or IPv6's, of the
/// `NETCONFA_IFINDEX` given, as they are once changed
/// (`inet_netconf_notify_devconf`, `inet6_netconf_notify_devconf`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Told {
    Ipv4(i32, What, Conf4),
    Ipv6(i32, What, Conf6),
}

/// Whether a device has IPv6 (`inet6_dev`): `ipv6_add_dev` gives it one
/// only when its MTU is at least `IPV6_MIN_MTU`, 1280.
pub(crate) fn has_ipv6(device: &Device) -> bool {
    device.veth.as_ref().is_none_or(|v| v.mtu >= 1280)
}

/// What a device's coming into its namespace tells: IPv4's settings,
/// then IPv6's if it has IPv6 (`__devinet_sysctl_register` of
/// `inetdev_init`, then `__addrconf_sysctl_register` of `ipv6_add_dev`,
/// as `NETDEV_REGISTER` reaches them).
pub(crate) fn registered(device: &Device) -> Vec<Told> {
    let mut told = vec![Told::Ipv4(device.index, What::All, device.conf4)];
    if has_ipv6(device) {
        told.push(Told::Ipv6(device.index, What::All, device.conf6));
    }
    told
}

/// What a device's going from its namespace tells, as
/// `NETDEV_UNREGISTER` reaches `inetdev_destroy` and `addrconf_ifdown`.
pub(crate) fn unregistered(device: &Device) -> Vec<Told> {
    let mut told = vec![Told::Ipv4(device.index, What::Gone, device.conf4)];
    if has_ipv6(device) {
        told.push(Told::Ipv6(device.index, What::Gone, device.conf6));
    }
    told
}

/// The `NETCONFA_IFINDEX` of `target`.
fn index_of(target: Target) -> i32 {
    match target {
        Target::All => INDEX_ALL,
        Target::Default => INDEX_DEFAULT,
        Target::Device(index) => index,
    }
}

/// Whose settings a file of `/proc/sys/net/ipv{4,6}/conf` shows: `all`'s,
/// `default`'s, or a device's, by its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    All,
    Default,
    Device(i32),
}

/// What a change of `disable_ipv6` does to a device: its IPv6 goes off
/// (`NETDEV_DOWN`) or comes on (`NETDEV_UP`), as `dev_disable_change`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Off,
    On,
}

/// The settings of `target` among `devices`: `None` for a device there
/// is not.
pub(crate) fn get(
    devices: &Devices,
    target: Target,
) -> Option<(crate::netdev::Conf4, crate::netdev::Conf6)> {
    match target {
        Target::All => Some((devices.all4, devices.all6)),
        Target::Default => Some((devices.default4, devices.default6)),
        Target::Device(index) => devices.by_index(index).map(|d| (d.conf4, d.conf6)),
    }
}

/// A write of IPv4's `forwarding` of `target` (`ip_forward` is `all`'s),
/// and what `devinet_sysctl_forward` tells of it, only when it changes:
/// for `all`, `all`'s, `default`'s and then every device's
/// (`inet_forward_change`), in the order of their indices, where Linux's
/// is the order they came in.
pub(crate) fn set_forwarding(devices: &mut Devices, target: Target, value: i32) -> Vec<Told> {
    let forwarding = |index, conf| Told::Ipv4(index, What::Forwarding, conf);
    let mut told = Vec::new();
    match target {
        Target::All => {
            let old = devices.all4.forwarding;
            devices.all4.forwarding = value;
            if value != old {
                devices.default4.forwarding = value;
                told.push(forwarding(INDEX_ALL, devices.all4));
                told.push(forwarding(INDEX_DEFAULT, devices.default4));
                for device in devices.iter_mut() {
                    device.conf4.forwarding = value;
                    told.push(forwarding(device.index, device.conf4));
                }
            }
        }
        Target::Default => {
            let old = devices.default4.forwarding;
            devices.default4.forwarding = value;
            if value != old {
                told.push(forwarding(INDEX_DEFAULT, devices.default4));
            }
        }
        Target::Device(index) => {
            if let Some(device) = devices.by_index_mut(index) {
                let old = device.conf4.forwarding;
                device.conf4.forwarding = value;
                if value != old {
                    told.push(forwarding(index, device.conf4));
                }
            }
        }
    }
    told
}

/// A write of `rp_filter` of `target`: `value` when it was taken, and
/// `None` for one that failed or was past the start, which still marks
/// the device as set and copies `default`'s (`devinet_conf_proc`). It
/// tells of `target`'s when its value changes, not of the devices that
/// take `default`'s.
pub(crate) fn set_rp_filter(
    devices: &mut Devices,
    target: Target,
    value: Option<i32>,
) -> Vec<Told> {
    let conf = match target {
        Target::All => &mut devices.all4,
        Target::Default => &mut devices.default4,
        Target::Device(index) => match devices.by_index_mut(index) {
            Some(device) => &mut device.conf4,
            None => return Vec::new(),
        },
    };
    let old = conf.rp_filter;
    if let Some(value) = value {
        conf.rp_filter = value;
    }
    conf.rp_filter_set = true;
    let mut told = Vec::new();
    if conf.rp_filter != old {
        told.push(Told::Ipv4(index_of(target), What::RpFilter, *conf));
    }
    // `devinet_copy_dflt_conf`.
    if target == Target::Default {
        let default = devices.default4.rp_filter;
        for device in devices.iter_mut().filter(|d| !d.conf4.rp_filter_set) {
            device.conf4.rp_filter = default;
        }
    }
    told
}

/// A write of IPv6's `forwarding` of `target`, and what
/// `addrconf_fixup_forwarding` tells of it, only when it turns on or off
/// (a change from 1 to 2 tells nothing): for `all`, `default`'s, each
/// device's that turns (`dev_forward_change` of
/// `addrconf_forward_change`) and then `all`'s. A device without IPv6
/// ([`has_ipv6`]) tells nothing.
pub(crate) fn set_forwarding6(devices: &mut Devices, target: Target, value: i32) -> Vec<Told> {
    let forwarding = |index, conf| Told::Ipv6(index, What::Forwarding, conf);
    let turns = |old: i32| (old == 0) != (value == 0);
    let mut told = Vec::new();
    match target {
        Target::All => {
            let old = devices.all6.forwarding;
            devices.all6.forwarding = value;
            let old_default = devices.default6.forwarding;
            devices.default6.forwarding = value;
            if turns(old_default) {
                told.push(forwarding(INDEX_DEFAULT, devices.default6));
            }
            for device in devices.iter_mut() {
                let was = device.conf6.forwarding;
                device.conf6.forwarding = value;
                if turns(was) && has_ipv6(device) {
                    told.push(forwarding(device.index, device.conf6));
                }
            }
            if turns(old) {
                told.push(forwarding(INDEX_ALL, devices.all6));
            }
        }
        Target::Default => {
            let old = devices.default6.forwarding;
            devices.default6.forwarding = value;
            if turns(old) {
                told.push(forwarding(INDEX_DEFAULT, devices.default6));
            }
        }
        Target::Device(index) => {
            if let Some(device) = devices.by_index_mut(index) {
                let old = device.conf6.forwarding;
                device.conf6.forwarding = value;
                if turns(old) && has_ipv6(device) {
                    told.push(forwarding(index, device.conf6));
                }
            }
        }
    }
    told
}

/// A write of `disable_ipv6` of `target`: the devices whose IPv6 it turns
/// off or on, by index.
pub(crate) fn set_disable_ipv6(
    devices: &mut Devices,
    target: Target,
    value: i32,
) -> Vec<(i32, Change)> {
    let change = if value != 0 { Change::Off } else { Change::On };
    let mut changed = Vec::new();
    let mut set = |device: &mut crate::netdev::Device| {
        if (device.conf6.disable_ipv6 == 0) != (value == 0) {
            changed.push((device.index, change));
        }
        device.conf6.disable_ipv6 = value;
    };
    match target {
        Target::Default => devices.default6.disable_ipv6 = value,
        // `addrconf_disable_change`.
        Target::All => {
            devices.all6.disable_ipv6 = value;
            devices.default6.disable_ipv6 = value;
            devices.iter_mut().for_each(&mut set);
        }
        Target::Device(index) => {
            if let Some(device) = devices.by_index_mut(index) {
                set(device);
            }
        }
    }
    changed
}

/// A new network namespace's settings: `new` takes `first`'s IPv4 `all`
/// and `default` (`devinet_init_net`), while IPv6's stay as built
/// (`addrconf_init_net`, which copies none at 0), and its devices take
/// `default`'s, as they are made.
pub(crate) fn inherit(new: &Network, first: &Network) {
    let (all4, default4) = {
        let first = first.devices();
        (first.all4, first.default4)
    };
    let mut devices = new.devices();
    devices.all4 = all4;
    devices.default4 = default4;
    for device in devices.iter_mut() {
        device.conf4 = default4;
    }
}

/// [`inherit`] for the network namespace `namespaces` were given by
/// `flags` (`CLONE_NEWNET`), from the session's first network, if both
/// are there.
pub(crate) fn inherit_new(
    namespaces: &crate::namespaces::Namespaces,
    flags: u64,
    first: Option<&std::sync::Arc<Network>>,
) {
    if flags & crate::namespaces::CLONE_NEWNET == 0 {
        return;
    }
    if let (Some(new), Some(first)) = (namespaces.net.sockets.network.get(), first) {
        inherit(new, first);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netdev::LOOPBACK_INDEX as LO;

    #[test]
    fn all_sets_the_others_as_linux_does() {
        let mut devices = Devices::new();
        let lo = |devices: &Devices| get(devices, Target::Device(LO)).unwrap();
        set_forwarding(&mut devices, Target::All, 1);
        assert_eq!(devices.default4.forwarding, 1);
        assert_eq!(lo(&devices).0.forwarding, 1);
        // `default` alone reaches no device.
        set_forwarding(&mut devices, Target::Default, 0);
        assert_eq!(lo(&devices).0.forwarding, 1);
        // The same value again changes nothing else.
        set_forwarding(&mut devices, Target::Device(LO), 0);
        set_forwarding(&mut devices, Target::All, 1);
        assert_eq!(lo(&devices).0.forwarding, 0);
        set_forwarding6(&mut devices, Target::All, 1);
        assert_eq!(lo(&devices).1.forwarding, 1);
        assert_eq!(devices.default6.forwarding, 1);
        assert_eq!(get(&devices, Target::Device(9)), None);
    }

    #[test]
    fn a_write_tells_what_linux_tells_of_it() {
        let mut devices = Devices::new();
        let v4 = |index| {
            Told::Ipv4(
                index,
                What::Forwarding,
                Conf4 {
                    forwarding: 1,
                    ..Conf4::default()
                },
            )
        };
        // `all`'s, `default`'s, then each device's; again, nothing.
        assert_eq!(
            set_forwarding(&mut devices, Target::All, 1),
            [v4(INDEX_ALL), v4(INDEX_DEFAULT), v4(LO)]
        );
        assert!(set_forwarding(&mut devices, Target::All, 1).is_empty());
        assert!(set_forwarding(&mut devices, Target::Device(LO), 1).is_empty());
        // IPv6's: `default`'s, the devices', `all`'s; from 2 to 1, nothing.
        let v6 = |index| {
            Told::Ipv6(
                index,
                What::Forwarding,
                Conf6 {
                    forwarding: 2,
                    ..Conf6::default()
                },
            )
        };
        assert_eq!(
            set_forwarding6(&mut devices, Target::All, 2),
            [v6(INDEX_DEFAULT), v6(LO), v6(INDEX_ALL)]
        );
        assert!(set_forwarding6(&mut devices, Target::All, 1).is_empty());
        assert_eq!(devices.by_index(LO).unwrap().conf6.forwarding, 1);
        // `rp_filter`: `default`'s alone, though the device takes it.
        let told = set_rp_filter(&mut devices, Target::Default, Some(2));
        assert!(
            matches!(told[..], [Told::Ipv4(INDEX_DEFAULT, What::RpFilter, c)] if c.rp_filter == 2)
        );
        assert_eq!(devices.by_index(LO).unwrap().conf4.rp_filter, 2);
        assert!(set_rp_filter(&mut devices, Target::Device(LO), None).is_empty());
        assert!(set_rp_filter(&mut devices, Target::Device(LO), Some(2)).is_empty());
    }

    #[test]
    fn rp_filter_follows_default_until_set() {
        let mut devices = Devices::new();
        set_rp_filter(&mut devices, Target::Default, Some(2));
        assert_eq!(devices.by_index(LO).unwrap().conf4.rp_filter, 2);
        // A failed write still marks the device.
        set_rp_filter(&mut devices, Target::Device(LO), None);
        set_rp_filter(&mut devices, Target::Default, Some(1));
        assert_eq!(devices.by_index(LO).unwrap().conf4.rp_filter, 2);
        assert_eq!(devices.all4.rp_filter, 0);
    }

    #[test]
    fn disable_ipv6_tells_which_devices_change() {
        let mut devices = Devices::new();
        assert!(set_disable_ipv6(&mut devices, Target::Default, 1).is_empty());
        assert_eq!(devices.by_index(LO).unwrap().conf6.disable_ipv6, 0);
        assert_eq!(
            set_disable_ipv6(&mut devices, Target::Device(LO), 2),
            [(LO, Change::Off)]
        );
        assert!(set_disable_ipv6(&mut devices, Target::Device(LO), 1).is_empty());
        assert_eq!(
            set_disable_ipv6(&mut devices, Target::All, 0),
            [(LO, Change::On)]
        );
        assert_eq!(devices.default6.disable_ipv6, 0);
    }

    #[test]
    fn a_new_namespace_takes_the_first_ones_all_and_default() {
        let first = Network::isolated(crate::users::first());
        let new = Network::isolated(crate::users::first());
        {
            let mut devices = first.devices();
            set_disable_ipv6(&mut devices, Target::Default, 1);
            set_forwarding(&mut devices, Target::All, 1);
            set_rp_filter(&mut devices, Target::Device(LO), Some(1));
        }
        inherit(&new, &first);
        let devices = new.devices();
        let lo = devices.by_index(LO).unwrap();
        // IPv6's are as built.
        assert_eq!(lo.conf6.disable_ipv6, 0);
        assert_eq!(devices.default6.disable_ipv6, 0);
        assert_eq!(lo.conf4.forwarding, 1);
        assert_eq!(lo.conf4.rp_filter, 0);
        assert_eq!(devices.all4.forwarding, 1);
    }
}
