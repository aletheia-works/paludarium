//! The network devices of a network namespace, as Linux keeps its
//! `net_device`s in a `struct net`: for now its loopback alone, which every
//! namespace has from the start, of index 1 (`LOOPBACK_IFINDEX`) and named
//! `lo`. Netlink, the interface ioctls and the routes find a device here by
//! its index or name.
//!
//! Each device carries its own settings (Linux's `ipv4_devconf` and
//! `ipv6_devconf` of its `in_device` and `inet6_dev`), and the namespace
//! those of `all` and `default`, which the files under
//! `/proc/sys/net/ipv4/conf` and `/proc/sys/net/ipv6/conf` show and set
//! ([`crate::netconf`]).

/// The loopback's index (`LOOPBACK_IFINDEX`), as an `ifinfomsg`'s
/// `ifi_index` and an `ndmsg`'s `ndm_ifindex` have it, and as `RTA_OIF`,
/// `RTA_IIF` and the route requests' devices name it.
pub(crate) const LOOPBACK_INDEX: i32 = 1;
/// [`LOOPBACK_INDEX`] as the attributes of a `u32` carry it.
pub(crate) const LOOPBACK_OIF: u32 = 1;

/// What a device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    /// The namespace's loopback (`loopback_dev`).
    Loopback,
}

/// A device's IPv4 settings, or those of `all` or `default`
/// (`struct ipv4_devconf`), as Linux is built: all 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Conf4 {
    /// `IPV4_DEVCONF_FORWARDING`.
    pub forwarding: i32,
    /// `IPV4_DEVCONF_RP_FILTER`.
    pub rp_filter: i32,
    /// Whether a write has set `rp_filter` (its bit of `cnf->state`), so
    /// that `default`'s no longer does.
    pub rp_filter_set: bool,
}

/// A device's IPv6 settings, or those of `all` or `default`
/// (`struct ipv6_devconf`), as Linux is built: all 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Conf6 {
    pub forwarding: i32,
    pub disable_ipv6: i32,
}

/// One network device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Device {
    /// Its index in the namespace (`ifindex`), positive.
    pub index: i32,
    /// Its name (`IFLA_IFNAME`), at most 15 bytes.
    pub name: Vec<u8>,
    pub kind: DeviceKind,
    pub conf4: Conf4,
    pub conf6: Conf6,
}

impl Device {
    /// The loopback, as a namespace makes it (`loopback_net_init`).
    fn loopback() -> Self {
        Self {
            index: LOOPBACK_INDEX,
            name: b"lo".to_vec(),
            kind: DeviceKind::Loopback,
            conf4: Conf4::default(),
            conf6: Conf6::default(),
        }
    }
}

/// The devices of a namespace, in the order of their indices, as a link
/// dump goes through them, with the namespace's `all` and `default`
/// settings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Devices {
    list: Vec<Device>,
    pub all4: Conf4,
    pub default4: Conf4,
    pub all6: Conf6,
    pub default6: Conf6,
}

impl Default for Devices {
    fn default() -> Self {
        Self::new()
    }
}

impl Devices {
    /// A new namespace's: its loopback alone.
    pub(crate) fn new() -> Self {
        Self {
            list: vec![Device::loopback()],
            all4: Conf4::default(),
            default4: Conf4::default(),
            all6: Conf6::default(),
            default6: Conf6::default(),
        }
    }
    /// The device of `index` (`__dev_get_by_index`), if any.
    pub(crate) fn by_index(&self, index: i32) -> Option<&Device> {
        self.list.iter().find(|d| d.index == index)
    }
    /// The device named `name` (`__dev_get_by_name`), if any: the name's
    /// bytes up to its first NUL.
    pub(crate) fn by_name(&self, name: &[u8]) -> Option<&Device> {
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        self.list.iter().find(|d| d.name == name[..end])
    }
    /// The device `ifinfomsg`'s positive `index` names, or else `name`, as
    /// `rtnl_getlink`, `rtnl_setlink` and `rtnl_dellink` find one: `None`
    /// for neither, or for a device there is not.
    pub(crate) fn find(&self, index: i32, name: Option<&[u8]>) -> Option<&Device> {
        if index > 0 {
            return self.by_index(index);
        }
        name.and_then(|name| self.by_name(name))
    }
    /// The devices, in the order of their indices.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Device> {
        self.list.iter()
    }
    /// The devices, to change their settings.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Device> {
        self.list.iter_mut()
    }
    /// The device of `index`, to change its settings.
    pub(crate) fn by_index_mut(&mut self, index: i32) -> Option<&mut Device> {
        self.list.iter_mut().find(|d| d.index == index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_namespace_has_its_loopback_by_index_and_name() {
        let devices = Devices::new();
        let lo = devices.by_index(LOOPBACK_INDEX).unwrap();
        assert_eq!(
            (lo.name.as_slice(), lo.kind),
            (&b"lo"[..], DeviceKind::Loopback)
        );
        assert_eq!(devices.by_name(b"lo\0\0"), Some(lo));
        assert_eq!(devices.by_name(b"eth0"), None);
        assert_eq!(devices.by_index(2), None);
        // A positive index first, whatever the name; else the name.
        assert_eq!(devices.find(1, Some(b"eth0")), Some(lo));
        assert_eq!(devices.find(2, Some(b"lo")), None);
        assert_eq!(devices.find(0, Some(b"lo")), Some(lo));
        assert_eq!(devices.find(-1, None), None);
        assert_eq!(devices.iter().count(), 1);
    }
}
