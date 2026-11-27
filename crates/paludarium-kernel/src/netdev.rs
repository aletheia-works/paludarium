//! The network devices of a network namespace, as Linux keeps its
//! `net_device`s in a `struct net`: its loopback, which every namespace has
//! from the start, of index 1 (`LOOPBACK_IFINDEX`) and named `lo`, and the
//! ends of veth pairs ([`Veth`]), which netlink makes and removes
//! ([`crate::netlink`]). Netlink, the interface ioctls and the routes find
//! a device here by its index or name. A namespace that goes takes its
//! veth ends with it, and their peers in other namespaces too
//! ([`Devices`]' `Drop`).
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

use std::sync::Weak;

/// What a device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    /// The namespace's loopback (`loopback_dev`).
    Loopback,
    /// An end of a veth pair.
    Veth,
}

/// A veth end's own state (`struct net_device` and `struct veth_priv`).
#[derive(Clone, Debug)]
pub(crate) struct Veth {
    /// Its Ethernet address (`dev_addr`).
    pub mac: [u8; 6],
    pub mtu: u32,
    /// `IFF_UP`.
    pub up: bool,
    /// Whether it has its carrier (`netif_carrier_ok`), which it has while
    /// it and its peer are up (`veth_open`, `veth_close`).
    pub carrier: bool,
    /// Whether the link watch has made its operational state up
    /// (`IF_OPER_UP`, and so `IFF_RUNNING`), which Linux's does a little
    /// after the carrier comes, and here at once.
    pub oper_up: bool,
    /// How often its carrier came and went (`carrier_up_count`,
    /// `carrier_down_count`).
    pub carrier_up: u32,
    pub carrier_down: u32,
    /// Whether it has opened, and so has its queueing discipline,
    /// `noqueue` (`dev_activate`), until it goes.
    pub opened: bool,
    /// Its peer: the other end's namespace and index; `None` once that has
    /// gone, as `veth_dellink` and `veth_newlink` leave it.
    pub peer: Option<Peer>,
}

/// The other end of a veth pair.
#[derive(Clone, Debug)]
pub(crate) struct Peer {
    pub network: Weak<crate::inet::Network>,
    pub index: i32,
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && Weak::ptr_eq(&self.network, &other.network)
    }
}
impl Eq for Peer {}
impl PartialEq for Veth {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac && self.peer == other.peer && self.up == other.up
    }
}
impl Eq for Veth {}

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
/// (`struct ipv6_devconf`), as Linux is built: all 0 but `accept_dad`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Conf6 {
    pub forwarding: i32,
    pub disable_ipv6: i32,
    /// `DEVCONF_ACCEPT_DAD`: `default`'s 1, `all`'s 0, and the loopback's
    /// -1 (`ipv6_add_dev`). An address of a device is checked for
    /// duplicates unless both its and `all`'s are below 1.
    pub accept_dad: i32,
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
    /// The IPv4 multicast groups it has joined.
    pub groups4: crate::multicast::Groups<core::net::Ipv4Addr>,
    /// The IPv6 ones its sockets have.
    pub groups6: crate::multicast::Groups<core::net::Ipv6Addr>,
    /// A veth end's state; `None` for the loopback.
    pub veth: Option<Veth>,
}

impl Device {
    /// The loopback, as a namespace makes it (`loopback_net_init`).
    fn loopback() -> Self {
        Self {
            index: LOOPBACK_INDEX,
            name: b"lo".to_vec(),
            kind: DeviceKind::Loopback,
            conf4: Conf4::default(),
            conf6: Conf6 {
                accept_dad: -1,
                ..Conf6::default()
            },
            groups4: crate::multicast::Groups::default(),
            groups6: crate::multicast::Groups::default(),
            veth: None,
        }
    }
    /// A veth end of `index` named `name`, of Ethernet address `mac` and
    /// MTU `mtu`, as `veth_setup` and `rtnl_create_link` make it, down and
    /// without its carrier (`netif_carrier_off`, which counts), with the
    /// settings `conf` (`default`'s, as `inetdev_init` and `ipv6_add_dev`
    /// copy them).
    pub(crate) fn veth(
        index: i32,
        name: Vec<u8>,
        mac: [u8; 6],
        mtu: u32,
        conf: (Conf4, Conf6),
    ) -> Self {
        Self {
            index,
            name,
            kind: DeviceKind::Veth,
            conf4: conf.0,
            conf6: conf.1,
            groups4: crate::multicast::Groups::default(),
            groups6: crate::multicast::Groups::default(),
            veth: Some(Veth {
                mac,
                mtu,
                up: false,
                carrier: false,
                oper_up: false,
                carrier_up: 0,
                carrier_down: 1,
                opened: false,
                peer: None,
            }),
        }
    }
}

/// The devices of a namespace, in the order of their indices, as a link
/// dump goes through them, with the namespace's `all` and `default`
/// settings.
#[derive(Debug)]
pub(crate) struct Devices {
    list: Vec<Device>,
    /// Their indices in the order they were registered in the namespace
    /// (`dev_base_head`), the loopback first, which `inet_select_addr`
    /// goes through.
    made: Vec<i32>,
    /// Where the next index a device takes without asking one is looked
    /// for (`net->ifindex`, `xa_alloc_cyclic`).
    next: i32,
    pub all4: Conf4,
    pub default4: Conf4,
    pub all6: Conf6,
    pub default6: Conf6,
    /// The changes of the devices' IPv4 groups netlink has yet to tell of
    /// ([`crate::multicast::Told4`]), in their order.
    pub told4: Vec<crate::multicast::Told4>,
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
            made: vec![LOOPBACK_INDEX],
            next: LOOPBACK_INDEX + 1,
            all4: Conf4::default(),
            default4: Conf4::default(),
            all6: Conf6::default(),
            default6: Conf6 {
                accept_dad: 1,
                ..Conf6::default()
            },
            told4: Vec::new(),
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
    /// The IPv4 groups of the device of `index`, with the changes to tell
    /// of ([`Devices::told4`]).
    pub(crate) fn groups4_of(
        &mut self,
        index: i32,
    ) -> Option<(
        &mut crate::multicast::Groups<core::net::Ipv4Addr>,
        &mut Vec<crate::multicast::Told4>,
    )> {
        let device = self.list.iter_mut().find(|d| d.index == index)?;
        Some((&mut device.groups4, &mut self.told4))
    }
    /// The index a new device takes (`dev_index_reserve`): `asked`, if
    /// positive, which another has (`EBUSY`); else the next free from where
    /// the last one taken so was, round to 1 past the largest.
    pub(crate) fn index_for(&self, asked: i32) -> Result<i32, paludarium_types::Errno> {
        if asked > 0 {
            return if self.by_index(asked).is_some() {
                Err(paludarium_types::Errno(16))
            } else {
                Ok(asked)
            };
        }
        let free = |i: &i32| self.by_index(*i).is_none();
        (self.next..=i32::MAX)
            .find(free)
            .or_else(|| (1..self.next).find(free))
            .ok_or(paludarium_types::Errno(105))
    }
    /// The name a new device takes from `name` (`dev_get_valid_name`):
    /// `EINVAL` for one empty, of 16 bytes or more, `.` or `..`, or with
    /// `/`, `:` or white space (`dev_valid_name`); one with `%d` takes the
    /// least number no device's name has (`dev_alloc_name`, `ENFILE` past
    /// 32767); `EEXIST` for one a device has.
    pub(crate) fn name_for(&self, name: &[u8]) -> Result<Vec<u8>, paludarium_types::Errno> {
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let name = &name[..end];
        if name.is_empty()
            || name.len() >= 16
            || name == b"."
            || name == b".."
            || name
                .iter()
                .any(|&b| b == b'/' || b == b':' || b.is_ascii_whitespace())
        {
            return Err(paludarium_types::Errno::EINVAL);
        }
        if let Some(at) = name.windows(2).position(|w| w == b"%d") {
            let (before, after) = (&name[..at], &name[at + 2..]);
            return (0..32768)
                .map(|n: u32| [before, n.to_string().as_bytes(), after].concat())
                .find(|candidate| candidate.len() < 16 && self.by_name(candidate).is_none())
                .ok_or(paludarium_types::Errno(23));
        }
        if self.by_name(name).is_some() {
            return Err(paludarium_types::Errno::EEXIST);
        }
        Ok(name.to_vec())
    }
    /// Adds `device`, in the order of the indices, and moves where the next
    /// unasked index is looked for past one it took so.
    pub(crate) fn add(&mut self, device: Device, asked: bool) {
        if !asked {
            self.next = device.index.saturating_add(1);
        }
        self.made.push(device.index);
        let at = self.list.partition_point(|d| d.index < device.index);
        self.list.insert(at, device);
    }
    /// Removes the device of `index`.
    pub(crate) fn remove(&mut self, index: i32) -> Option<Device> {
        let at = self.list.iter().position(|d| d.index == index)?;
        self.made.retain(|&i| i != index);
        Some(self.list.remove(at))
    }
    /// The devices' indices in the order they were registered in the
    /// namespace (`for_each_netdev`), the loopback first.
    pub(crate) fn order(&self) -> Vec<i32> {
        self.made.clone()
    }
}

impl Drop for Devices {
    /// The namespace goes (`default_device_exit_batch`): each veth end goes
    /// with its peer in another namespace, which is told of there
    /// ([`crate::netlink::peers_gone`]).
    fn drop(&mut self) {
        let peers = std::mem::take(&mut self.list)
            .into_iter()
            .filter_map(|device| {
                let peer = device.veth?.peer?;
                Some((peer.network.upgrade()?, peer.index))
            })
            .collect();
        crate::netlink::peers_gone(peers);
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
