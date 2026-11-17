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
//! `RTM_NEWNETCONF` notifications are not sent.
use crate::inet::Network;
use crate::netdev::Devices;

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

/// A write of IPv4's `forwarding` of `target` (`ip_forward` is `all`'s).
pub(crate) fn set_forwarding(devices: &mut Devices, target: Target, value: i32) {
    match target {
        Target::All => {
            let old = devices.all4.forwarding;
            devices.all4.forwarding = value;
            // `inet_forward_change`, when it changes.
            if value != old {
                devices.default4.forwarding = value;
                for device in devices.iter_mut() {
                    device.conf4.forwarding = value;
                }
            }
        }
        Target::Default => devices.default4.forwarding = value,
        Target::Device(index) => {
            if let Some(device) = devices.by_index_mut(index) {
                device.conf4.forwarding = value;
            }
        }
    }
}

/// A write of `rp_filter` of `target`: `value` when it was taken, and
/// `None` for one that failed or was past the start, which still marks
/// the device as set and copies `default`'s (`devinet_conf_proc`).
pub(crate) fn set_rp_filter(devices: &mut Devices, target: Target, value: Option<i32>) {
    let conf = match target {
        Target::All => &mut devices.all4,
        Target::Default => &mut devices.default4,
        Target::Device(index) => match devices.by_index_mut(index) {
            Some(device) => &mut device.conf4,
            None => return,
        },
    };
    if let Some(value) = value {
        conf.rp_filter = value;
    }
    conf.rp_filter_set = true;
    // `devinet_copy_dflt_conf`.
    if target == Target::Default {
        let default = devices.default4.rp_filter;
        for device in devices.iter_mut().filter(|d| !d.conf4.rp_filter_set) {
            device.conf4.rp_filter = default;
        }
    }
}

/// A write of IPv6's `forwarding` of `target`.
pub(crate) fn set_forwarding6(devices: &mut Devices, target: Target, value: i32) {
    match target {
        // `addrconf_forward_change`.
        Target::All => {
            devices.all6.forwarding = value;
            devices.default6.forwarding = value;
            for device in devices.iter_mut() {
                device.conf6.forwarding = value;
            }
        }
        Target::Default => devices.default6.forwarding = value,
        Target::Device(index) => {
            if let Some(device) = devices.by_index_mut(index) {
                device.conf6.forwarding = value;
            }
        }
    }
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
