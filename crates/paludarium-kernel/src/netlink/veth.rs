//! veth pairs (Linux's `drivers/net/veth.c`), as `RTM_NEWLINK`,
//! `RTM_SETLINK` and `RTM_DELLINK` make, change and remove them: two
//! Ethernet devices ([`crate::netdev::Veth`]), each the other's peer, in
//! one namespace or two. Each has its carrier while both are up; deleting
//! either takes both, and so does its namespace going. What a member of
//! `RTNLGRP_LINK` hears of each, in its namespace, and the link messages
//! dumps and gets give, follow `rtnl_fill_ifinfo`.
//!
//! Nothing goes through a pair yet: a veth end has no address, route or
//! neighbour here, and no traffic.
use super::{
    Errno, Header, IFF_LOWER_UP, IFF_RUNNING, IFF_UP, IFLA_ADDRESS, IFLA_IFNAME, IFLA_INFO_DATA,
    IFLA_INFO_KIND, IFLA_LINK, IFLA_LINK_NETNSID, IFLA_LINKINFO, IFLA_MAP, IFLA_MTU,
    IFLA_NET_NS_FD, IFLA_NET_NS_PID, IFLA_POLICY, IFLA_PROTINFO, IFLA_TARGET_NETNSID, Nla, Notice,
    Policy, RTM_DELLINK, RTM_NEWLINK, RTNLGRP_LINK, attribute, attributes, by_type, extack,
    message, nsid, parse_policy, u32_value,
};
use crate::credentials::Credentials;
use crate::inet::Network;
use crate::netdev::{Device, Peer};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// `VETH_INFO_PEER`: the peer's `ifinfomsg` and attributes.
pub(super) const VETH_INFO_PEER: u16 = 1;
const ARPHRD_ETHER: u16 = 1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_MULTICAST: u32 = 0x1000;
const IF_OPER_DOWN: u8 = 2;
const IF_OPER_LOWERLAYERDOWN: u8 = 3;
const IF_OPER_UP: u8 = 6;
/// `ETH_DATA_LEN`, `ETH_MIN_MTU` and `ETH_MAX_MTU`.
const ETH_DATA_LEN: u32 = 1500;
const ETH_MIN_MTU: u32 = 68;
const ETH_MAX_MTU: u32 = 65535;
/// What `dev_close_many` tells of a device it closes to remove or move it.
const CLOSED: u32 = IFF_UP | IFF_RUNNING;
/// `IFLA_NEW_NETNSID`, which a move's `RTM_DELLINK` carries with
/// `IFLA_NEW_IFINDEX`.
const IFLA_NEW_NETNSID: u16 = 45;
/// `veth_policy`.
const VETH_POLICY: Policy = Policy {
    max: VETH_INFO_PEER,
    strict_start: 0,
    of: |kind| match kind {
        VETH_INFO_PEER => Nla::Unspec(16),
        _ => Nla::Unspec(0),
    },
};

/// The operational state `rtnl_fill_ifinfo` gives a veth end of
/// `network`: down while it is not running; up with its carrier; else
/// as `default_operstate` finds it, by the device of its `iflink`, its
/// peer's index, looked up in its own namespace: down for none there or
/// one operationally up, else lower layer down. (Linux finds it as its
/// link watch runs; it is found here as it is told of.)
fn operstate(network: &Network, v: &crate::netdev::Veth) -> u8 {
    if !v.up {
        return IF_OPER_DOWN;
    }
    if v.oper_up {
        return IF_OPER_UP;
    }
    let iflink = v.peer.as_ref().map_or(0, |p| p.index);
    let devices = network.devices();
    match devices.by_index(iflink) {
        None => IF_OPER_DOWN,
        // Only a veth end is not up here: `lo`'s stays unknown.
        Some(found) => match &found.veth {
            Some(f) if !(f.up && f.oper_up) => IF_OPER_LOWERLAYERDOWN,
            _ => IF_OPER_DOWN,
        },
    }
}
/// A veth end's flags (`netif_get_flags`): `IFF_BROADCAST` and
/// `IFF_MULTICAST`, and while up `IFF_UP`, with `IFF_RUNNING` once its
/// operational state is up and `IFF_LOWER_UP` while it has its carrier.
fn flags(device: &Device) -> u32 {
    let mut flags = IFF_BROADCAST | IFF_MULTICAST;
    if let Some(v) = &device.veth
        && v.up
    {
        flags |= IFF_UP;
        if v.oper_up {
            flags |= IFF_RUNNING;
        }
        if v.carrier {
            flags |= IFF_LOWER_UP;
        }
    }
    flags
}
/// The flags `SIOCGIFFLAGS` gives of a veth end, the first 16 bits.
pub(crate) fn ioctl_flags(device: &Device) -> u16 {
    (flags(device) & 0xffff) as u16
}

/// The link message `kind` of a veth end of `network` with `change`, as
/// `rtnl_fill_ifinfo` gives it to a socket of `src`, in Linux 7.0's order:
/// as `lo`'s, but an Ethernet device's (its address and the broadcast
/// one, an MTU of 68 to 65535), its kind (`IFLA_LINKINFO`), the namespace
/// of its peer where that is another one (`IFLA_LINK_NETNSID`, which may
/// give `src` an ID for it, told of by the notices it gives with it) and
/// the peer's index (`IFLA_LINK`, 0 once it has gone), and the queueing
/// discipline it has since it opened, `noqueue`, or `noop` for one
/// `going`. It has one queue each way, where Linux's has one for each
/// possible CPU, and no `IFLA_AF_SPEC`; its statistics are zero, and left
/// out with `RTEXT_FILTER_SKIP_STATS` in `mask`.
#[allow(clippy::too_many_arguments)]
pub(super) fn link_message(
    network: &Arc<Network>,
    src: &Arc<Network>,
    device: &Device,
    kind: u16,
    change: u32,
    (seq, port, nl_flags): (u32, u32, u16),
    mask: u32,
    going: bool,
) -> (Vec<u8>, Vec<Notice>) {
    let Some(v) = &device.veth else {
        return (Vec::new(), Vec::new());
    };
    let stats = mask & super::RTEXT_FILTER_SKIP_STATS == 0;
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&ARPHRD_ETHER.to_le_bytes());
    body.extend_from_slice(&device.index.to_le_bytes());
    body.extend_from_slice(&flags(device).to_le_bytes());
    body.extend_from_slice(&change.to_le_bytes());
    let u32_of = |v: u32| v.to_le_bytes();
    let mut name = device.name.clone();
    name.push(0);
    attribute(&mut body, IFLA_IFNAME, &name);
    attribute(&mut body, super::IFLA_TXQLEN, &u32_of(1000));
    let operstate = operstate(network, v);
    attribute(&mut body, super::IFLA_OPERSTATE, &[operstate]);
    attribute(&mut body, super::IFLA_LINKMODE, &[0]);
    attribute(&mut body, super::IFLA_NETNS_IMMUTABLE, &[0]);
    attribute(&mut body, IFLA_MTU, &u32_of(v.mtu));
    attribute(&mut body, super::IFLA_MIN_MTU, &u32_of(ETH_MIN_MTU));
    attribute(&mut body, super::IFLA_MAX_MTU, &u32_of(ETH_MAX_MTU));
    attribute(&mut body, super::IFLA_GROUP, &u32_of(0));
    attribute(&mut body, super::IFLA_PROMISCUITY, &u32_of(0));
    attribute(&mut body, super::IFLA_ALLMULTI, &u32_of(0));
    attribute(&mut body, super::IFLA_NUM_TX_QUEUES, &u32_of(1));
    attribute(
        &mut body,
        super::IFLA_GSO_MAX_SEGS,
        &u32_of(super::GSO_MAX_SEGS),
    );
    attribute(
        &mut body,
        super::IFLA_GSO_MAX_SIZE,
        &u32_of(super::GSO_MAX_SIZE),
    );
    attribute(
        &mut body,
        super::IFLA_GRO_MAX_SIZE,
        &u32_of(super::GSO_MAX_SIZE),
    );
    attribute(
        &mut body,
        super::IFLA_GSO_IPV4_MAX_SIZE,
        &u32_of(super::GSO_MAX_SIZE),
    );
    attribute(
        &mut body,
        super::IFLA_GRO_IPV4_MAX_SIZE,
        &u32_of(super::GSO_MAX_SIZE),
    );
    // `netif_set_tso_max_size(dev, GSO_MAX_SIZE)` in `veth_setup`.
    attribute(
        &mut body,
        super::IFLA_TSO_MAX_SIZE,
        &u32_of(super::GSO_MAX_SIZE),
    );
    attribute(
        &mut body,
        super::IFLA_TSO_MAX_SEGS,
        &u32_of(super::GSO_MAX_SEGS),
    );
    attribute(
        &mut body,
        super::IFLA_MAX_PACING_OFFLOAD_HORIZON,
        &u32_of(0),
    );
    attribute(&mut body, super::IFLA_NUM_RX_QUEUES, &u32_of(1));
    attribute(&mut body, super::IFLA_CARRIER, &[u8::from(v.carrier)]);
    attribute(
        &mut body,
        super::IFLA_CARRIER_CHANGES,
        &u32_of(v.carrier_up + v.carrier_down),
    );
    attribute(
        &mut body,
        super::IFLA_CARRIER_UP_COUNT,
        &u32_of(v.carrier_up),
    );
    attribute(
        &mut body,
        super::IFLA_CARRIER_DOWN_COUNT,
        &u32_of(v.carrier_down),
    );
    attribute(&mut body, super::IFLA_HEADROOM, &0u16.to_le_bytes());
    attribute(&mut body, super::IFLA_TAILROOM, &0u16.to_le_bytes());
    attribute(&mut body, super::IFLA_PROTO_DOWN, &[0]);
    attribute(&mut body, IFLA_ADDRESS, &v.mac);
    attribute(&mut body, super::IFLA_BROADCAST, &[0xff; 6]);
    if stats {
        attribute(&mut body, super::IFLA_STATS64, &[0; super::STATS64_LEN]);
        attribute(&mut body, super::IFLA_STATS, &[0; super::STATS_LEN]);
    }
    let mut xdp = Vec::new();
    attribute(&mut xdp, super::IFLA_XDP_ATTACHED, &[0]);
    attribute(&mut body, super::IFLA_XDP, &xdp);
    let mut info = Vec::new();
    attribute(&mut info, IFLA_INFO_KIND, b"veth\0");
    attribute(&mut body, IFLA_LINKINFO, &info);
    // `rtnl_fill_link_netnsid`, then `nla_put_iflink`, which a veth end
    // always gives, as its link is another device or none.
    let mut notices = Vec::new();
    let peer = v.peer.as_ref();
    if let Some(peer_network) = peer.and_then(|p| p.network.upgrade())
        && !Arc::ptr_eq(&peer_network, network)
    {
        let id = nsid::link_netnsid(src, &peer_network, &mut notices);
        attribute(
            &mut body,
            IFLA_LINK_NETNSID,
            &id.unwrap_or(-1).to_le_bytes(),
        );
    }
    attribute(
        &mut body,
        IFLA_LINK,
        &u32_of(peer.map_or(0, |p| p.index.unsigned_abs())),
    );
    let qdisc: &[u8] = if v.opened && !going {
        b"noqueue\0"
    } else {
        b"noop\0"
    };
    attribute(&mut body, super::IFLA_QDISC, qdisc);
    attribute(&mut body, IFLA_MAP, &[0; 32]);
    attribute(
        &mut body,
        super::IFLA_DEVLINK_PORT | super::NLA_F_NESTED,
        &[],
    );
    attribute(&mut body, super::IFLA_DPLL_PIN | super::NLA_F_NESTED, &[]);
    (message(kind, nl_flags, seq, port, &body), notices)
}

/// What a namespace tells its members of `RTNLGRP_LINK` of its device of
/// `index`: `kind` with `change`, after the `RTM_NEWNSID` that giving its
/// peer's namespace an ID tells.
fn told(network: &Arc<Network>, index: i32, kind: u16, change: u32, going: bool) -> Vec<Notice> {
    let device = network.devices().by_index(index).cloned();
    let Some(device) = device else {
        return Vec::new();
    };
    told_of(network, &device, kind, change, going)
}
fn told_of(
    network: &Arc<Network>,
    device: &Device,
    kind: u16,
    change: u32,
    going: bool,
) -> Vec<Notice> {
    let (bytes, mut notices) =
        link_message(network, network, device, kind, change, (0, 0, 0), 0, going);
    notices.push(Notice {
        to: None,
        heard: false,
        group: RTNLGRP_LINK,
        origin: 0,
        bytes,
    });
    notices
}
/// Sends `list` to the members of `to` through `notices`, which go once
/// the requester's socket is unlocked: `notify` of another namespace also
/// reaches the `NETLINK_LISTEN_ALL_NSID` sockets of those with an ID for
/// it, the requester's among them.
fn tell(own: &Arc<Network>, to: &Arc<Network>, notices: &mut Vec<Notice>, list: Vec<Notice>) {
    if Arc::ptr_eq(own, to) {
        notices.extend(list);
    } else {
        notices.extend(list.into_iter().map(|notice| Notice {
            to: Some(Arc::clone(to)),
            ..notice
        }));
    }
}

/// Sends `network`'s netconf notifications of `told` through `notices`
/// ([`super::devconf`]), as [`tell`] does.
fn tell_netconf(
    own: &Arc<Network>,
    network: &Arc<Network>,
    notices: &mut Vec<Notice>,
    told: Vec<crate::netconf::Told>,
) {
    tell(own, network, notices, super::devconf::notices(told));
}

/// A random Ethernet address, unicast and locally administered
/// (`eth_random_addr`), from a sequence of the emulator's own.
fn random_mac() -> [u8; 6] {
    static NEXT: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut x = NEXT.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    let b = x.to_le_bytes();
    [(b[0] & 0xfe) | 0x02, b[1], b[2], b[3], b[4], b[5]]
}

/// `veth_validate` of a device's attributes: `EINVAL` for an address of
/// other than six bytes, `EADDRNOTAVAIL` for one multicast or of zeros
/// (`is_valid_ether_addr`), `EINVAL` for an MTU past 68 to 65535.
fn validate(tb: &BTreeMap<u16, &[u8]>) -> Result<(), Errno> {
    if let Some(address) = tb.get(&IFLA_ADDRESS) {
        if address.len() != 6 {
            return Err(Errno::EINVAL);
        }
        if address[0] & 1 != 0 || address.iter().all(|&b| b == 0) {
            return Err(super::EADDRNOTAVAIL);
        }
    }
    if let Some(mtu) = tb.get(&IFLA_MTU) {
        let mtu = u32_value(mtu)?;
        if !(ETH_MIN_MTU..=ETH_MAX_MTU).contains(&mtu) {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}
/// The attributes a veth end's request may name here: its name, address
/// and MTU, its namespace, and the request's own.
fn supported(tb: &BTreeMap<u16, &[u8]>) -> bool {
    tb.keys().all(|&kind| {
        matches!(
            kind,
            IFLA_IFNAME
                | IFLA_ADDRESS
                | IFLA_MTU
                | IFLA_LINKINFO
                | IFLA_NET_NS_PID
                | IFLA_NET_NS_FD
                | super::IFLA_EXT_MASK
        )
    })
}

/// `RTM_NEWLINK` of kind `veth`, as `rtnl_newlink`, `__rtnl_newlink`,
/// `rtnl_newlink_create` and `veth_newlink` take it, after `ifla_policy`
/// (`EINVAL` for a short `ifinfomsg`), one namespace at most (`EINVAL`)
/// and `IFLA_LINKINFO`'s policy: `IFLA_INFO_DATA`'s (`veth_policy`, an
/// `ERANGE` peer shorter than an `ifinfomsg`), [`validate`] of the
/// request's attributes and the peer's, the peer's namespace and then the
/// target's (`IFLA_NET_NS_PID` or `IFLA_NET_NS_FD`, `EPERM` without
/// `CAP_NET_ADMIN` over it, [`nsid::link_target`]). Then the link the
/// request names, by a positive index or its name, in the target with
/// `NLM_F_CREATE` and `NLM_F_EXCL`, else here: `Ok(None)` for one there
/// is, which the request changes as any other. Without one, `ENODEV`
/// without `NLM_F_CREATE`; `EOPNOTSUPP` for `IFLA_MAP`, `IFLA_PROTINFO`,
/// and here for an attribute but a name, an address and an MTU.
///
/// The peer is made first, in its namespace (the requester's without
/// one), of the peer's name (or `veth%d`), address (or a random one, as
/// without `VETH_INFO_PEER`), MTU (1500) and, when the request
/// asks the first end an index, the peer's index; then the first end, of
/// the request's, in the target; each told of with `RTM_NEWLINK` in its
/// namespace, the peer's before it has its peer, so with `IFLA_LINK` 0.
/// Each is named and numbered as [`crate::netdev::Devices::name_for`] and
/// `index_for` take it (`EINVAL`, `EEXIST`, `EBUSY`); a first end that
/// cannot be takes the peer away again, told of with `RTM_DELLINK`.
/// The `ifinfomsg`s' flags are not taken.
pub(super) fn newlink(
    own: &Arc<Network>,
    opener: &Credentials,
    header: &Header,
    payload: &[u8],
    notices: &mut Vec<Notice>,
) -> Result<Option<()>, Errno> {
    let parsed = parse_policy(&payload[16..], &IFLA_POLICY, false)?;
    let tb = by_type(&parsed);
    let info = tb
        .get(&IFLA_LINKINFO)
        .map(|info| by_type(&attributes(info)))
        .unwrap_or_default();
    let data = match info.get(&IFLA_INFO_DATA) {
        Some(data) => by_type(&parse_policy(data, &VETH_POLICY, false)?),
        None => BTreeMap::new(),
    };
    validate(&tb)?;
    let peer_info = data.get(&VETH_INFO_PEER).copied();
    let peer_tb = match peer_info {
        Some(peer) => {
            let parsed = parse_policy(&peer[16..], &IFLA_POLICY, false)?;
            let peer_tb = by_type(&parsed);
            validate(&peer_tb)?;
            peer_tb
        }
        None => tb.clone(),
    };
    let value =
        |tb: &BTreeMap<u16, &[u8]>, kind: u16| tb.get(&kind).map(|v| u32_value(v).unwrap_or(0));
    let peer_net = nsid::peer_target(
        own,
        opener,
        value(&peer_tb, IFLA_NET_NS_PID),
        value(&peer_tb, IFLA_NET_NS_FD),
    )?;
    let target = nsid::link_target(
        own,
        opener,
        value(&tb, IFLA_NET_NS_PID),
        value(&tb, IFLA_NET_NS_FD),
        tb.get(&IFLA_TARGET_NETNSID).map(|v| super::s32_value(v)),
    )?
    .unwrap_or_else(|| Arc::clone(own));
    let index = i32::from_le_bytes(payload[4..8].try_into().unwrap_or_default());
    let creating = header.flags & super::NLM_F_CREATE != 0;
    let device_net = if creating && header.flags & super::NLM_F_EXCL != 0 {
        &target
    } else {
        own
    };
    let name = tb.get(&IFLA_IFNAME).copied();
    if index < 0 {
        return Err(extack::message(Errno::EINVAL, "ifindex can't be negative"));
    }
    if device_net.devices().find(index, name).is_some() {
        return Ok(None);
    }
    if !creating {
        return Err(super::ENODEV);
    }
    if tb.contains_key(&IFLA_MAP) || tb.contains_key(&IFLA_PROTINFO) {
        return Err(super::EOPNOTSUPP);
    }
    if !supported(&tb) || !supported(&peer_tb) {
        return Err(super::EOPNOTSUPP);
    }
    // `rtnl_newlink_peer_net`: the peer's own namespace, else the
    // requester's (`link_net`, `IFLA_LINK_NETNSID`, is not taken).
    let peer_net = peer_net.unwrap_or_else(|| Arc::clone(own));
    // The peer first (`veth_newlink`).
    let peer_name = match (peer_info, peer_tb.get(&IFLA_IFNAME)) {
        (Some(_), Some(name)) => name.to_vec(),
        _ => b"veth%d".to_vec(),
    };
    let peer_asked = match peer_info {
        Some(peer) if index != 0 => i32::from_le_bytes(peer[4..8].try_into().unwrap_or_default()),
        _ => 0,
    };
    // Each end's address is its own attributes', else random: the peer
    // takes none of the request's (`if (!ifmp || !tbp[IFLA_ADDRESS])`).
    let device_of = |tb: &BTreeMap<u16, &[u8]>,
                     own_address: bool,
                     network: &Network,
                     name: &[u8],
                     asked: i32| {
        let devices = network.devices();
        let name = devices.name_for(name)?;
        let index = devices.index_for(asked)?;
        let mac = match tb.get(&IFLA_ADDRESS).filter(|_| own_address) {
            Some(mac) => <[u8; 6]>::try_from(*mac).unwrap_or_else(|_| random_mac()),
            None => random_mac(),
        };
        let mtu = tb
            .get(&IFLA_MTU)
            .map_or(Ok(ETH_DATA_LEN), |v| u32_value(v))?;
        Ok::<_, Errno>(Device::veth(
            index,
            name,
            mac,
            mtu,
            (devices.default4, devices.default6),
        ))
    };
    let peer = device_of(
        &peer_tb,
        peer_info.is_some(),
        &peer_net,
        &peer_name,
        peer_asked,
    )?;
    let peer_index = peer.index;
    // `register_netdevice` tells of its settings (`NETDEV_REGISTER`), and
    // `rtnl_configure_link` then of the end.
    let settings = crate::netconf::registered(&peer);
    peer_net.devices().add(peer, peer_asked > 0);
    tell_netconf(own, &peer_net, notices, settings);
    let list = told(&peer_net, peer_index, RTM_NEWLINK, u32::MAX, false);
    tell(own, &peer_net, notices, list);
    // Then the first end.
    let first_name = name.map_or_else(|| b"veth%d".to_vec(), <[u8]>::to_vec);
    let first = match device_of(&tb, true, &target, &first_name, index) {
        Ok(first) => first,
        Err(e) => {
            let gone = peer_net.devices().remove(peer_index);
            if let Some(gone) = gone {
                tell_netconf(own, &peer_net, notices, crate::netconf::unregistered(&gone));
                let list = told_of(&peer_net, &gone, RTM_DELLINK, u32::MAX, true);
                tell(own, &peer_net, notices, list);
            }
            return Err(e);
        }
    };
    let first_index = first.index;
    let settings = crate::netconf::registered(&first);
    target.devices().add(first, index > 0);
    tell_netconf(own, &target, notices, settings);
    let tie = |network: &Network, index: i32, peer: Peer| {
        if let Some(v) = network
            .devices()
            .by_index_mut(index)
            .and_then(|d| d.veth.as_mut())
        {
            v.peer = Some(peer);
        }
    };
    tie(
        &target,
        first_index,
        Peer {
            network: Arc::downgrade(&peer_net),
            index: peer_index,
        },
    );
    tie(
        &peer_net,
        peer_index,
        Peer {
            network: Arc::downgrade(&target),
            index: first_index,
        },
    );
    let list = told(&target, first_index, RTM_NEWLINK, u32::MAX, false);
    tell(own, &target, notices, list);
    Ok(Some(()))
}

/// The peer of `network`'s veth end `index`, as it names it.
fn peer_of(network: &Network, index: i32) -> Option<(Arc<Network>, i32)> {
    let devices = network.devices();
    let peer = devices.by_index(index)?.veth.as_ref()?.peer.as_ref()?;
    Some((peer.network.upgrade()?, peer.index))
}
/// Changes `network`'s veth end `index` with `change`.
fn change(network: &Network, index: i32, change: impl FnOnce(&mut crate::netdev::Veth)) {
    if let Some(v) = network
        .devices()
        .by_index_mut(index)
        .and_then(|d| d.veth.as_mut())
    {
        change(v);
    }
}
/// Brings `network`'s veth end `index` up or down (`dev_open`,
/// `dev_close`), with nothing for one already so: up, it opens, and with
/// its peer up both have their carrier (`veth_open`), which the link watch
/// then makes their operational state, each told of in its namespace with
/// no change (here at once, where Linux's comes a little later); down,
/// both lose their carrier (`veth_close`), and the peer, still up, is told
/// of as the link watch finds it. It is told of first, with `IFF_UP`
/// changed.
pub(crate) fn set_up(
    own: &Arc<Network>,
    network: &Arc<Network>,
    index: i32,
    up: bool,
    now: u64,
    notices: &mut Vec<Notice>,
) {
    switch(own, network, index, up, IFF_UP, now, notices);
}
/// [`set_up`], telling of the end itself with `told_change`: `IFF_UP`
/// for `dev_change_flags`, [`CLOSED`] for the `netif_close` of a move; at
/// `now`, which a duplicate address detection starting counts from.
fn switch(
    own: &Arc<Network>,
    network: &Arc<Network>,
    index: i32,
    up: bool,
    told_change: u32,
    now: u64,
    notices: &mut Vec<Notice>,
) {
    let was = network
        .devices()
        .by_index(index)
        .and_then(|d| d.veth.as_ref().map(|v| v.up));
    if was != Some(!up) {
        return;
    }
    let peer = peer_of(network, index);
    let peer_up = peer
        .as_ref()
        .and_then(|(n, i)| {
            n.devices()
                .by_index(*i)
                .and_then(|d| d.veth.as_ref().map(|v| v.up))
        })
        .unwrap_or(false);
    let carrier = |v: &mut crate::netdev::Veth, on: bool| {
        if v.carrier != on {
            v.carrier = on;
            if on {
                v.carrier_up += 1;
            } else {
                v.carrier_down += 1;
            }
        }
        if !on {
            v.oper_up = false;
        }
    };
    if up {
        change(network, index, |v| {
            v.up = true;
            v.opened = true;
            if peer_up {
                carrier(v, true);
            }
        });
        // `ip_mc_up`, of `NETDEV_UP`.
        network.change_group4(index, crate::multicast::ALL_HOSTS, true);
        if peer_up && let Some((n, i)) = &peer {
            change(n, *i, |v| carrier(v, true));
            let list = super::device_changed4(n, *i, true, true);
            tell(own, n, notices, list);
        }
        let list = told(network, index, RTM_NEWLINK, IFF_UP, false);
        tell(own, network, notices, list);
        // `NETDEV_UP`, after `__dev_notify_flags` has told of the change.
        let list = super::device_up4(network, index, peer_up);
        tell(own, network, notices, list);
        // IPv6's `NETDEV_UP`.
        let list = super::device_up6(network, index, peer_up, now);
        tell(own, network, notices, list);
        if peer_up {
            change(network, index, |v| v.oper_up = true);
            let list = told(network, index, RTM_NEWLINK, 0, false);
            tell(own, network, notices, list);
            if let Some((n, i)) = &peer {
                // The link watch takes the peer's carrier next: its
                // `NETDEV_CHANGE` makes IPv6 ready on it before
                // `netif_state_change` tells of it.
                let list = super::link_ready6(n, *i, now);
                tell(own, n, notices, list);
                change(n, *i, |v| v.oper_up = true);
                let list = told(n, *i, RTM_NEWLINK, 0, false);
                tell(own, n, notices, list);
            }
        }
    } else {
        change(network, index, |v| {
            v.up = false;
            carrier(v, false);
        });
        // `ip_mc_down`, of `NETDEV_DOWN`.
        network.change_group4(index, crate::multicast::ALL_HOSTS, false);
        // `__dev_notify_flags` tells of the change before `NETDEV_DOWN`
        // flushes the end's neighbours; the peer's go as the link watch
        // finds its carrier gone, before it tells of that
        // (`netif_state_change` runs `NETDEV_CHANGE` first).
        let own_list = super::device_changed4(network, index, false, false);
        let peer_was_running = peer.as_ref().is_some_and(|(n, i)| {
            n.devices()
                .by_index(*i)
                .and_then(|d| d.veth.as_ref())
                .is_some_and(|v| v.up && v.oper_up)
        });
        let peer_list = peer.as_ref().map(|(n, i)| {
            change(n, *i, |v| carrier(v, false));
            super::device_changed4(n, *i, true, false)
        });
        let list = told(network, index, RTM_NEWLINK, told_change, false);
        tell(own, network, notices, list);
        tell(own, network, notices, own_list);
        // IPv6's `addrconf_ifdown`.
        let list = super::device_down6(network, index);
        tell(own, network, notices, list);
        if let Some((n, i)) = &peer {
            tell(own, n, notices, peer_list.unwrap_or_default());
            if peer_was_running {
                let list = told(n, *i, RTM_NEWLINK, 0, false);
                tell(own, n, notices, list);
            }
        }
    }
}
/// Takes the devices of `gone`, each out of its namespace, away as
/// `unregister_netdevice_many_notify` does: each up is closed first, told
/// of with `IFF_UP` and `IFF_RUNNING` changed (`netif_close_many`), its
/// neighbours flushed, and
/// only then is each told of, in their order, with `RTM_DELNETCONF` of
/// its settings (`NETDEV_UNREGISTER`) and then `RTM_DELLINK`.
fn unregister(
    own: &Arc<Network>,
    mut gone: Vec<(Arc<Network>, Device)>,
    notices: &mut Vec<Notice>,
) {
    for (network, device) in &mut gone {
        if let Some(v) = device.veth.as_mut() {
            v.peer = None;
            if v.up {
                v.up = false;
                v.oper_up = false;
                if v.carrier {
                    v.carrier = false;
                    v.carrier_down += 1;
                }
                let list = told_of(network, device, RTM_NEWLINK, CLOSED, false);
                tell(own, network, notices, list);
                // `NETDEV_DOWN`: its neighbours go (`arp_ifdown`), and
                // IPv6's routes and addresses (`addrconf_ifdown`).
                let list = super::device_changed4(network, device.index, false, false);
                tell(own, network, notices, list);
                let list = super::device_down6(network, device.index);
                tell(own, network, notices, list);
            }
        }
    }
    for (network, device) in &gone {
        // `NETDEV_UNREGISTER`: IPv4 takes its addresses first.
        let list = super::addresses_gone(network, device.index);
        tell(own, network, notices, list);
        tell_netconf(own, network, notices, crate::netconf::unregistered(device));
        let list = told_of(network, device, RTM_DELLINK, u32::MAX, true);
        tell(own, network, notices, list);
    }
}
/// `RTM_DELLINK` of `network`'s veth end `index` (`veth_dellink`): it
/// goes, and its peer with it, each told of in its namespace.
pub(super) fn delete(
    own: &Arc<Network>,
    network: &Arc<Network>,
    index: i32,
    notices: &mut Vec<Notice>,
) {
    let peer = peer_of(network, index);
    // `veth_dellink` forgets the peers first, and queues the end, then
    // its peer.
    let mut gone = Vec::new();
    if let Some(first) = network.devices().remove(index) {
        gone.push((Arc::clone(network), first));
    }
    if let Some((n, i)) = peer {
        let second = n.devices().remove(i);
        if let Some(second) = second {
            gone.push((n, second));
        }
    }
    unregister(own, gone, notices);
}
/// The peers, each `index` of its namespace, of the veth ends of a
/// namespace that goes (`default_device_exit_batch`, one
/// `unregister_netdevice_many` for them all): they go too, each told of
/// there.
pub(crate) fn peers_gone(peers: Vec<(Arc<Network>, i32)>) {
    let gone: Vec<(Arc<Network>, Device)> = peers
        .into_iter()
        .filter_map(|(network, index)| {
            let device = network.devices().remove(index)?;
            Some((network, device))
        })
        .collect();
    let Some(own) = gone.first().map(|(network, _)| Arc::clone(network)) else {
        return;
    };
    let mut notices = Vec::new();
    unregister(&own, gone, &mut notices);
    // Those of `own` have no `to`; give them it, for one list.
    let notices = notices
        .into_iter()
        .map(|notice| Notice {
            to: Some(notice.to.unwrap_or_else(|| Arc::clone(&own))),
            ..notice
        })
        .collect::<Vec<_>>();
    let mut run: Vec<Notice> = Vec::new();
    for notice in notices {
        if let Some(last) = run.last()
            && !same_place(last, &notice)
        {
            send_going(core::mem::take(&mut run));
        }
        run.push(notice);
    }
    send_going(run);
}
/// Whether two notices go to one namespace.
fn same_place(a: &Notice, b: &Notice) -> bool {
    match (&a.to, &b.to) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
/// [`super::notify_going`] of a run of notices for one namespace.
fn send_going(mut run: Vec<Notice>) {
    let Some(to) = run.first_mut().and_then(|n| n.to.clone()) else {
        return;
    };
    for notice in &mut run {
        notice.to = None;
    }
    super::notify_going(&to, run);
}
/// A move's `RTM_DELLINK` (`rtmsg_ifinfo_newnet`), with `IFLA_NEW_NETNSID`
/// and `IFLA_NEW_IFINDEX` after `IFLA_LINKINFO`, as `rtnl_fill_ifinfo`
/// puts them.
fn with_new_netns(mut message: Vec<u8>, nsid: i32, new_index: i32) -> Vec<u8> {
    let mut at = 16 + 16;
    while at + 4 <= message.len() {
        let len = usize::from(u16::from_le_bytes([message[at], message[at + 1]]));
        let kind = u16::from_le_bytes([message[at + 2], message[at + 3]]) & 0x3fff;
        if len < 4 {
            break;
        }
        at += len.next_multiple_of(4);
        if kind == IFLA_LINKINFO {
            let mut added = Vec::new();
            attribute(&mut added, IFLA_NEW_NETNSID, &nsid.to_le_bytes());
            attribute(
                &mut added,
                super::IFLA_NEW_IFINDEX,
                &new_index.to_le_bytes(),
            );
            let at = at.min(message.len());
            message.splice(at..at, added);
            let total = u32::try_from(message.len()).unwrap_or(u32::MAX);
            message[..4].copy_from_slice(&total.to_le_bytes());
            break;
        }
    }
    message
}
/// Moves `network`'s veth end `index` to `to` (`__dev_change_net_namespace`):
/// `EEXIST` where `to` has a device of its name. It keeps its index in
/// `to`, or takes the next free (`dev_index_reserve`); closed first if up
/// (`netif_close`, told of with `IFF_UP` and `IFF_RUNNING` changed), its
/// settings go (`RTM_DELNETCONF`, as `NETDEV_UNREGISTER` takes them), it
/// gives `to` an ID where it is (`peernet2id_alloc`), is told of there
/// with `RTM_DELLINK`, carrying that ID and its new index, loses its
/// queueing discipline, takes `to`'s `default` settings, told of with
/// `RTM_NEWNETCONF` there (`NETDEV_REGISTER`, `inetdev_init` and
/// `ipv6_add_dev` copying them), and is told of with `RTM_NEWLINK` in
/// `to`; its peer names it there.
pub(super) fn move_to(
    own: &Arc<Network>,
    network: &Arc<Network>,
    index: i32,
    to: &Arc<Network>,
    notices: &mut Vec<Notice>,
) -> Result<(), Errno> {
    let Some(device) = network.devices().by_index(index).cloned() else {
        return Err(super::ENODEV);
    };
    if to.devices().by_name(&device.name).is_some() {
        return Err(Errno::EEXIST);
    }
    // `dev_index_reserve` comes first in Linux, and holds the index; here
    // it is only chosen, so a device made in `to` meanwhile may take it.
    let new_index = {
        let devices = to.devices();
        if devices.by_index(index).is_none() {
            index
        } else {
            devices.index_for(0)?
        }
    };
    switch(own, network, index, false, CLOSED, 0, notices);
    let Some(mut device) = network.devices().by_index(index).cloned() else {
        return Err(super::ENODEV);
    };
    // `NETDEV_UNREGISTER` in the old namespace: IPv4 takes its addresses.
    let list = super::addresses_gone(network, index);
    tell(own, network, notices, list);
    let mut list = super::devconf::notices(crate::netconf::unregistered(&device));
    let nsid = nsid::link_netnsid(network, to, &mut list).unwrap_or(-1);
    let (message, more) = link_message(
        network,
        network,
        &device,
        RTM_DELLINK,
        u32::MAX,
        (0, 0, 0),
        0,
        true,
    );
    list.extend(more);
    list.push(Notice {
        to: None,
        heard: false,
        group: RTNLGRP_LINK,
        origin: 0,
        bytes: with_new_netns(message, nsid, new_index),
    });
    tell(own, network, notices, list);
    network.devices().remove(index);
    device.index = new_index;
    if let Some(v) = device.veth.as_mut() {
        v.opened = false;
    }
    let peer = device.veth.as_ref().and_then(|v| v.peer.clone());
    let settings = {
        let mut devices = to.devices();
        // `ip_mc_destroy_dev`, with the old namespace's `in_device`.
        device.groups4 = crate::multicast::Groups::default();
        device.conf4 = devices.default4;
        device.conf6 = devices.default6;
        let settings = crate::netconf::registered(&device);
        devices.add(device, new_index == index);
        settings
    };
    tell_netconf(own, to, notices, settings);
    if let Some(peer) = peer
        && let Some(n) = peer.network.upgrade()
    {
        change(&n, peer.index, |v| {
            v.peer = Some(Peer {
                network: Arc::downgrade(to),
                index: new_index,
            });
        });
    }
    let list = told(to, new_index, RTM_NEWLINK, u32::MAX, false);
    tell(own, to, notices, list);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `RTM_NEWLINK` for a pair within one namespace: `name` of
    /// `index` with its peer `peer` of `peer_index`, each of the address
    /// given, and `more` attributes for the first end.
    fn pair(
        name: &[u8],
        index: i32,
        peer: &[u8],
        peer_index: i32,
        more: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let ifinfo = |index: i32| {
            let mut out = vec![0, 0, 0, 0];
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out
        };
        let mut peer_info = ifinfo(peer_index);
        attribute(&mut peer_info, IFLA_IFNAME, peer);
        attribute(&mut peer_info, IFLA_ADDRESS, &[2, 0, 0, 0, 0, 0x0b]);
        let mut data = Vec::new();
        attribute(&mut data, VETH_INFO_PEER, &peer_info);
        let mut info = Vec::new();
        attribute(&mut info, IFLA_INFO_KIND, b"veth\0");
        attribute(&mut info, IFLA_INFO_DATA, &data);
        let mut payload = ifinfo(index);
        attribute(&mut payload, IFLA_IFNAME, name);
        attribute(&mut payload, IFLA_ADDRESS, &[2, 0, 0, 0, 0, 0x0a]);
        for &(kind, value) in more {
            attribute(&mut payload, kind, value);
        }
        attribute(&mut payload, IFLA_LINKINFO, &info);
        payload
    }
    fn create(network: &Arc<Network>, payload: &[u8]) -> (Result<Option<()>, Errno>, Vec<Notice>) {
        let header = Header {
            len: 0,
            kind: RTM_NEWLINK,
            flags: super::super::NLM_F_CREATE | super::super::NLM_F_EXCL,
            seq: 1,
        };
        let mut notices = Vec::new();
        let made = newlink(
            network,
            &Credentials::default(),
            &header,
            payload,
            &mut notices,
        );
        (made, notices)
    }
    /// Each link notice's type, index, flags and change.
    fn heard(notices: &[Notice]) -> Vec<(u16, i32, u32, u32)> {
        notices
            .iter()
            .filter(|n| n.group == RTNLGRP_LINK)
            .map(|n| {
                let b = &n.bytes;
                let word = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                (
                    u16::from_le_bytes([b[4], b[5]]),
                    word(20) as i32,
                    word(24),
                    word(28),
                )
            })
            .collect()
    }

    /// Each link and netconf notice's group, type and index.
    fn told_in_order(notices: &[Notice]) -> Vec<(u32, u16, i32)> {
        notices
            .iter()
            .filter(|n| n.group != nsid::RTNLGRP_NSID)
            .map(|n| {
                let b = &n.bytes;
                // The index after an `ifinfomsg`'s family and type, or a
                // `netconfmsg` and `NETCONFA_IFINDEX`'s header.
                let at = if n.group == RTNLGRP_LINK { 20 } else { 24 };
                (
                    n.group,
                    u16::from_le_bytes([b[4], b[5]]),
                    i32::from_le_bytes(b[at..at + 4].try_into().unwrap()),
                )
            })
            .collect()
    }

    #[test]
    fn each_end_tells_of_its_settings_as_it_comes_and_goes() {
        const V4: u32 = 24;
        const V6: u32 = 25;
        const NEW: u16 = 80;
        const DEL: u16 = 81;
        let a = Arc::new(Network::isolated(crate::users::first()));
        let b = Arc::new(Network::isolated(crate::users::first()));
        // The first end's MTU is too small for IPv6 (`ipv6_add_dev`).
        let mtu = 1279u32.to_le_bytes();
        let (made, notices) = create(&a, &pair(b"va", 1000, b"vb", 1001, &[(IFLA_MTU, &mtu)]));
        assert_eq!(made, Ok(Some(())));
        let link = RTNLGRP_LINK;
        assert_eq!(
            told_in_order(&notices),
            [
                (V4, NEW, 1001),
                (V6, NEW, 1001),
                (link, RTM_NEWLINK, 1001),
                (V4, NEW, 1000),
                (link, RTM_NEWLINK, 1000),
            ]
        );
        // A move: its settings go before the ID and the `RTM_DELLINK`,
        // and it takes B's `default` ones, told of before it is.
        b.devices().default4.forwarding = 1;
        let mut notices = Vec::new();
        move_to(&a, &a, 1001, &b, &mut notices).unwrap();
        assert_eq!(
            told_in_order(&notices),
            [
                (V4, DEL, 1001),
                (V6, DEL, 1001),
                (link, RTM_DELLINK, 1001),
                (V4, NEW, 1001),
                (V6, NEW, 1001),
                (link, RTM_NEWLINK, 1001),
            ]
        );
        let gone = notices.iter().position(|n| n.group == V6).unwrap();
        let id = notices
            .iter()
            .position(|n| n.group == nsid::RTNLGRP_NSID)
            .unwrap();
        assert!(gone < id);
        let came = notices
            .iter()
            .rfind(|n| n.group == V4)
            .map(|n| n.bytes[32..36].to_vec())
            .unwrap();
        assert_eq!(came, 1i32.to_le_bytes());
        assert_eq!(
            b.devices().by_index(1001).map(|d| d.conf4.forwarding),
            Some(1)
        );
        // Deleting: each end's settings go just before it does.
        let mut notices = Vec::new();
        delete(&a, &a, 1000, &mut notices);
        assert_eq!(
            told_in_order(&notices),
            [
                (V4, DEL, 1000),
                (link, RTM_DELLINK, 1000),
                (V4, DEL, 1001),
                (V6, DEL, 1001),
                (link, RTM_DELLINK, 1001),
            ]
        );
    }

    #[test]
    fn a_pair_is_made_brought_up_and_taken_away_as_veth_does() {
        let network = Arc::new(Network::isolated(crate::users::first()));
        let (made, notices) = create(&network, &pair(b"va\0", 1000, b"vb\0", 1001, &[]));
        assert_eq!(made, Ok(Some(())));
        // The peer first, before it has its peer; each down, no carrier.
        let all = u32::MAX;
        let down = IFF_BROADCAST | IFF_MULTICAST;
        assert_eq!(
            heard(&notices),
            [
                (RTM_NEWLINK, 1001, down, all),
                (RTM_NEWLINK, 1000, down, all)
            ]
        );
        let devices = network.devices();
        let va = devices.by_index(1000).unwrap().veth.clone().unwrap();
        assert_eq!(
            (va.mac, va.mtu, va.carrier_down),
            ([2, 0, 0, 0, 0, 0x0a], 1500, 1)
        );
        assert_eq!(va.peer.map(|p| p.index), Some(1001));
        drop(devices);
        // Refused: the name again, a short address, an MTU of 67.
        assert_eq!(
            create(&network, &pair(b"vc\0", 0, b"vd\0", 0, &[])).0,
            Ok(Some(()))
        );
        assert_eq!(
            create(&network, &pair(b"va\0", 1005, b"ve\0", 0, &[])).0,
            Err(Errno::EEXIST)
        );
        assert_eq!(
            create(
                &network,
                &pair(b"vf\0", 0, b"vg\0", 0, &[(IFLA_ADDRESS, &[2, 0, 0])])
            )
            .0,
            Err(Errno::EINVAL)
        );
        assert_eq!(
            create(
                &network,
                &pair(b"vf\0", 0, b"vg\0", 0, &[(IFLA_MTU, &67u32.to_le_bytes())])
            )
            .0,
            Err(Errno::EINVAL)
        );
        assert_eq!(
            create(
                &network,
                &pair(
                    b"vf\0",
                    0,
                    b"vg\0",
                    0,
                    &[(IFLA_ADDRESS, &[1, 0, 0x5e, 0, 0, 1])]
                )
            )
            .0,
            Err(super::super::EADDRNOTAVAIL)
        );
        // The second pair took the next free indices.
        assert!(
            network
                .devices()
                .by_name(b"vc")
                .is_some_and(|d| d.index == 3)
        );
        // Up alone, no carrier; with the peer, both have it, then run.
        let mut notices = Vec::new();
        set_up(&network, &network, 1000, true, 0, &mut notices);
        assert_eq!(
            heard(&notices),
            [(RTM_NEWLINK, 1000, down | IFF_UP, IFF_UP)]
        );
        let mut notices = Vec::new();
        set_up(&network, &network, 1001, true, 0, &mut notices);
        let lower = down | IFF_UP | IFF_LOWER_UP;
        assert_eq!(
            heard(&notices),
            [
                (RTM_NEWLINK, 1001, lower, IFF_UP),
                (RTM_NEWLINK, 1001, lower | IFF_RUNNING, 0),
                (RTM_NEWLINK, 1000, lower | IFF_RUNNING, 0),
            ]
        );
        let flags = ioctl_flags(network.devices().by_index(1000).unwrap());
        assert_eq!(u32::from(flags), (lower | IFF_RUNNING) & 0xffff);
        // Down: both lose the carrier, the peer told of as it finds it.
        let mut notices = Vec::new();
        set_up(&network, &network, 1000, false, 0, &mut notices);
        assert_eq!(
            heard(&notices),
            [
                (RTM_NEWLINK, 1000, down, IFF_UP),
                (RTM_NEWLINK, 1001, down | IFF_UP, 0)
            ]
        );
        let vb = network
            .devices()
            .by_index(1001)
            .unwrap()
            .veth
            .clone()
            .unwrap();
        assert_eq!((vb.carrier, vb.carrier_up, vb.carrier_down), (false, 1, 2));
        // Deleting one end takes both: every one still up is closed
        // before either is told gone (`unregister_netdevice_many_notify`).
        let mut notices = Vec::new();
        delete(&network, &network, 1000, &mut notices);
        assert_eq!(
            heard(&notices),
            [
                (RTM_NEWLINK, 1001, down, CLOSED),
                (RTM_DELLINK, 1000, down, all),
                (RTM_DELLINK, 1001, down, all),
            ]
        );
        assert!(network.devices().by_index(1001).is_none());
    }

    #[test]
    fn a_namespace_that_goes_takes_its_peers_end_too() {
        let a = Arc::new(Network::isolated(crate::users::first()));
        let b = Arc::new(Network::isolated(crate::users::first()));
        let mut va = Device::veth(
            1000,
            b"va".to_vec(),
            [2, 0, 0, 0, 0, 0x0a],
            1500,
            Default::default(),
        );
        let mut vb = Device::veth(
            1001,
            b"vb".to_vec(),
            [2, 0, 0, 0, 0, 0x0b],
            1500,
            Default::default(),
        );
        va.veth.as_mut().unwrap().peer = Some(Peer {
            network: Arc::downgrade(&b),
            index: 1001,
        });
        vb.veth.as_mut().unwrap().peer = Some(Peer {
            network: Arc::downgrade(&a),
            index: 1000,
        });
        a.devices().add(va, true);
        b.devices().add(vb, true);
        // A's link message names B by the ID A gives it, told of first.
        let device = a.devices().by_index(1000).cloned().unwrap();
        let (message, told) = link_message(&a, &a, &device, RTM_NEWLINK, 0, (0, 0, 0), 0, false);
        assert_eq!(told.len(), 1);
        let found = by_type(&attributes(&message[32..]))
            .into_iter()
            .map(|(k, v)| (k, v.to_vec()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(found[&IFLA_LINK_NETNSID], 0i32.to_le_bytes());
        assert_eq!(found[&IFLA_LINK], 1001u32.to_le_bytes());
        drop(b);
        assert!(a.devices().by_index(1000).is_none());
    }

    #[test]
    fn a_namespace_that_goes_while_a_request_is_taken_tells_after_it() {
        let a = Arc::new(Network::isolated(crate::users::first()));
        let b = Arc::new(Network::isolated(crate::users::first()));
        let (made, _) = create(&a, &pair(b"va", 1000, b"vb", 1001, &[]));
        assert_eq!(made, Ok(Some(())));
        move_to(&a, &a, 1001, &b, &mut Vec::new()).unwrap();
        // B goes within the request: A's peer end stays until it ends,
        // and what B's going tells A is kept for after it.
        let kept = super::super::deferring(|| drop(b));
        assert!(a.devices().by_index(1000).is_none());
        assert_eq!(
            heard(&kept),
            [(RTM_DELLINK, 1000, IFF_BROADCAST | IFF_MULTICAST, u32::MAX)]
        );
        assert!(
            kept.iter()
                .all(|n| n.to.as_ref().is_some_and(|to| Arc::ptr_eq(to, &a)))
        );
    }

    #[test]
    fn a_peer_without_its_own_attributes_is_the_requesters_and_random() {
        let a = Arc::new(Network::isolated(crate::users::first()));
        // No `VETH_INFO_PEER`: the peer takes the request's MTU, but
        // neither its name nor its address.
        let mut payload = vec![0; 16];
        attribute(&mut payload, IFLA_IFNAME, b"va\0");
        attribute(&mut payload, IFLA_ADDRESS, &[2, 0, 0, 0, 0, 0x0a]);
        attribute(&mut payload, IFLA_MTU, &1400u32.to_le_bytes());
        let mut info = Vec::new();
        attribute(&mut info, IFLA_INFO_KIND, b"veth\0");
        attribute(&mut payload, IFLA_LINKINFO, &info);
        let (made, _) = create(&a, &payload);
        assert_eq!(made, Ok(Some(())));
        let devices = a.devices();
        let peer = devices
            .iter()
            .find(|d| d.name.starts_with(b"veth"))
            .cloned()
            .unwrap();
        let v = peer.veth.unwrap();
        assert_ne!(v.mac, [2, 0, 0, 0, 0, 0x0a]);
        assert_eq!(v.mtu, 1400);
    }

    #[test]
    fn a_move_closes_the_end_and_tells_where_it_went() {
        let a = Arc::new(Network::isolated(crate::users::first()));
        let b = Arc::new(Network::isolated(crate::users::first()));
        let (made, _) = create(&a, &pair(b"va", 1000, b"vb", 1001, &[]));
        assert_eq!(made, Ok(Some(())));
        set_up(&a, &a, 1001, true, 0, &mut Vec::new());
        let mut notices = Vec::new();
        move_to(&a, &a, 1001, &b, &mut notices).unwrap();
        let down = IFF_BROADCAST | IFF_MULTICAST;
        // Closed as `netif_close` tells it, A's ID for B first, gone from
        // A with where it went, then in B.
        assert_eq!(
            heard(&notices),
            [
                (RTM_NEWLINK, 1001, down, CLOSED),
                (RTM_DELLINK, 1001, down, u32::MAX),
                (RTM_NEWLINK, 1001, down, u32::MAX),
            ]
        );
        let first_nsid = notices
            .iter()
            .position(|n| n.group == nsid::RTNLGRP_NSID)
            .unwrap();
        let gone = notices
            .iter()
            .position(|n| n.group == RTNLGRP_LINK && n.bytes[4] == RTM_DELLINK as u8)
            .unwrap();
        assert!(first_nsid < gone);
        let kinds = super::super::attribute_kinds(&notices[gone].bytes[32..]);
        let at = |kind: u16| kinds.iter().position(|&k| k == kind).unwrap();
        assert_eq!(at(IFLA_NEW_NETNSID), at(IFLA_LINKINFO) + 1);
        assert_eq!(at(super::super::IFLA_NEW_IFINDEX), at(IFLA_NEW_NETNSID) + 1);
        assert!(
            notices
                .last()
                .unwrap()
                .to
                .as_ref()
                .is_some_and(|to| Arc::ptr_eq(to, &b))
        );
    }
}
