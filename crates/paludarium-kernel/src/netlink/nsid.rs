//! The IDs a network namespace gives its peers (Linux's `net->netns_ids`),
//! as `net/core/net_namespace.c` keeps them: `RTM_NEWNSID` gives one to the
//! namespace of a process or of a namespace file, `RTM_GETNSID` tells it,
//! or dumps them all, and the members of `RTNLGRP_NSID` hear of each new
//! one. A netlink socket with `NETLINK_LISTEN_ALL_NSID` hears the
//! notifications of each peer its namespace has an ID for, with that ID in
//! a control message, as `do_one_broadcast` sends them.
//!
//! An ID goes when its peer does, and `RTNLGRP_NSID` hears of it with
//! `RTM_DELNSID`, as `unhash_nsid` tells it. A link or address request
//! may name a peer by its ID (`IFLA_TARGET_NETNSID`,
//! `IFA_TARGET_NETNSID`), as [`target`] finds it.
//!
//! A request gives an ID. [`link_netnsid`] is Linux's
//! `peernet2id_alloc`, which gives one on its own for what lies in another
//! namespace than the one telling of it, for a device whose link is there
//! (a veth pair's other end); no device here calls it yet, so no ID is
//! given that way. Its other callers (a device that moves, a queue lease,
//! a devlink instance, a PSP device, an ovpn peer, an openvswitch vport)
//! have no counterpart here.
use super::{
    Errno, Header, NLM_F_MULTI, Nla, Notice, Policy, attribute, extack, message, parse_policy,
};
use crate::credentials::Credentials;
use crate::inet::Network;
use crate::syscalls::Context;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

pub(super) const RTM_NEWNSID: u16 = 88;
const RTM_DELNSID: u16 = 89;
pub(super) const RTM_GETNSID: u16 = 90;
/// The group that hears of new IDs.
pub(super) const RTNLGRP_NSID: u32 = 28;
const NETNSA_NSID: u16 = 1;
const NETNSA_PID: u16 = 2;
const NETNSA_FD: u16 = 3;
const NETNSA_TARGET_NSID: u16 = 4;
const NETNSA_CURRENT_NSID: u16 = 5;
const NETNSA_MAX: u16 = 5;
/// `NETNSA_NSID_NOT_ASSIGNED`.
const NOT_ASSIGNED: i32 = -1;
const CAP_NET_ADMIN: u64 = 1 << 12;
const ESRCH: Errno = Errno(3);
const EEXIST: Errno = Errno(17);
const ENOENT: Errno = Errno(2);
const EACCES: Errno = Errno(13);

/// `rtnl_net_policy`.
const NETNSA_POLICY: Policy = Policy {
    max: NETNSA_MAX,
    strict_start: 0,
    of: |kind| match kind {
        NETNSA_NSID | NETNSA_TARGET_NSID => Nla::S32,
        NETNSA_PID | NETNSA_FD => Nla::U32,
        _ => Nla::Unspec(0),
    },
};

/// A network namespace's IDs of its peers, and the namespaces that have an
/// ID for it, whose sockets with `NETLINK_LISTEN_ALL_NSID` hear of it.
#[derive(Default)]
pub(crate) struct Ids {
    ids: Mutex<BTreeMap<i32, Weak<Network>>>,
    heard_by: Mutex<Vec<Weak<Network>>>,
}
impl Ids {
    /// The IDs, with those of peers that are going until their [`Drop`]
    /// takes them, as Linux keeps them until `cleanup_net`.
    fn live(&self) -> MutexGuard<'_, BTreeMap<i32, Weak<Network>>> {
        self.ids.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The ID of `peer` (`__peernet2id`), if it has one.
    pub(super) fn id_of(&self, peer: &Network) -> Option<i32> {
        self.live()
            .iter()
            .find(|(_, p)| std::ptr::eq(p.as_ptr(), peer))
            .map(|(&id, _)| id)
    }
    /// The peer of `id` (`get_net_ns_by_id`).
    fn peer(&self, id: i32) -> Option<Arc<Network>> {
        self.live().get(&id).and_then(Weak::upgrade)
    }
    /// The namespaces other than this one that have an ID for it.
    pub(super) fn heard_by(&self) -> Vec<Arc<Network>> {
        let mut all = self.heard_by.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|network| network.strong_count() > 0);
        all.iter().filter_map(Weak::upgrade).collect()
    }
}

impl Drop for Ids {
    /// `unhash_nsid`: each namespace that has an ID for this one, which is
    /// going, forgets it and tells `RTNLGRP_NSID` with `RTM_DELNSID`. Its
    /// own IDs go with it, untold.
    fn drop(&mut self) {
        let heard_by = std::mem::take(
            self.heard_by
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for peer in heard_by.iter().filter_map(Weak::upgrade) {
            // This namespace is the one that is going; another going at the
            // same time is told of here or by its own drop, once.
            let gone: Vec<i32> = {
                let mut ids = peer.netlink.ids.live();
                let gone = ids
                    .iter()
                    .filter(|(_, p)| p.strong_count() == 0)
                    .map(|(&id, _)| id)
                    .collect();
                ids.retain(|_, p| p.strong_count() > 0);
                gone
            };
            let notices = gone
                .into_iter()
                .map(|id| Notice {
                    group: RTNLGRP_NSID,
                    origin: 0,
                    bytes: fill(RTM_DELNSID, 0, 0, 0, id, None),
                })
                .collect();
            super::notify(&peer, notices, None);
        }
    }
}

/// How a request names a peer: by a process ID, or a descriptor.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reference {
    Pid(u32),
    Fd(u32),
}
/// A peer a request names, as found.
type Found = Result<Arc<Network>, Errno>;
/// What [`resolve`] found, and the sender's credentials.
type Resolution = (Vec<(Reference, Found)>, Option<Credentials>, bool);
thread_local! {
    /// The peers the requests of the datagram being sent name, found with
    /// the sender's view before the kernel takes them, the sender's
    /// credentials, and whether the send names an address
    /// (`NETLINK_SKB_DST`) ([`resolve`]).
    static RESOLVED: RefCell<Resolution> =
        const { RefCell::new((Vec::new(), None, false)) };
}
/// What [`resolve`] found, until it is dropped.
pub(crate) struct Resolved;
impl Drop for Resolved {
    fn drop(&mut self) {
        RESOLVED.with(|r| *r.borrow_mut() = (Vec::new(), None, false));
    }
}
/// Finds, as the caller of `c` sees them, the namespaces each
/// `RTM_NEWNSID` and `RTM_GETNSID` request of `bytes` names by
/// `NETNSA_PID` (`get_net_ns_by_pid`) or `NETNSA_FD` (`get_net_ns_by_fd`),
/// and each `RTM_NEWLINK` and `RTM_SETLINK` by `IFLA_NET_NS_PID` or
/// `IFLA_NET_NS_FD`, an `RTM_NEWLINK` also inside `IFLA_LINKINFO`'s
/// `IFLA_INFO_DATA`'s `VETH_INFO_PEER` (whatever the kind; the caller of
/// [`peer_target`] checks it), for the kernel to take as it reaches them;
/// finding one changes nothing.
/// A `write` finds them as its caller sees them too ([`super::write`]),
/// as Linux looks in `current`'s. `addressed` is whether the send names
/// an address, as a `write` does not.
pub(super) fn resolve(c: &Context<'_>, mut bytes: &[u8], addressed: bool) -> Resolved {
    let mut found = Vec::new();
    let mut any = false;
    while bytes.len() >= 16 {
        let header = Header::read(bytes);
        let len = header.len as usize;
        if len < 16 || bytes.len() < len {
            break;
        }
        // A link or address request may name a peer by its ID, which
        // needs the sender's `CAP_NET_ADMIN` over it too.
        if matches!(
            header.kind,
            super::RTM_GETLINK | super::RTM_GETADDR | super::RTM_DELLINK
        ) {
            any = true;
        }
        // After an `rtgenmsg`, or a link's `ifinfomsg`: the types that name
        // a process and a descriptor.
        let named = match header.kind {
            RTM_NEWNSID | RTM_GETNSID => Some((4, NETNSA_PID, NETNSA_FD)),
            super::RTM_NEWLINK | super::RTM_SETLINK => {
                Some((16, super::IFLA_NET_NS_PID, super::IFLA_NET_NS_FD))
            }
            _ => None,
        };
        if let Some((skip, by_pid, by_fd)) = named {
            any = true;
            let attributes = bytes[16..len].get(skip..).unwrap_or_default();
            let link = header.kind == super::RTM_NEWLINK;
            references(c, attributes, (by_pid, by_fd), link, &mut found);
        }
        bytes = &bytes[super::align(len).min(bytes.len())..];
    }
    // Only those requests read the sender's credentials ([`admin_over`]).
    let credentials = any.then(|| c.process.credentials.clone());
    RESOLVED.with(|r| *r.borrow_mut() = (found, credentials, addressed));
    Resolved
}
/// The attributes of `bytes`, each of its type and value, until one breaks.
fn each(mut bytes: &[u8], mut found: impl FnMut(u16, &[u8])) {
    while bytes.len() >= 4 {
        let size = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if size < 4 || size > bytes.len() {
            break;
        }
        found(
            u16::from_le_bytes([bytes[2], bytes[3]]) & 0x3fff,
            &bytes[4..size],
        );
        bytes = &bytes[super::align(size).min(bytes.len())..];
    }
}
/// For [`resolve`], the processes and descriptors `attributes` name by the
/// types `by` (a process's, a descriptor's), found into `found`; with
/// `link`, those a veth pair's peer names too (`IFLA_LINKINFO`'s
/// `IFLA_INFO_DATA`'s `VETH_INFO_PEER`, an `ifinfomsg` and its
/// attributes), as `rtnl_get_peer_net` reads them.
fn references(
    c: &Context<'_>,
    attributes: &[u8],
    by: (u16, u16),
    link: bool,
    found: &mut Vec<(Reference, Found)>,
) {
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_INFO_DATA: u16 = 2;
    const VETH_INFO_PEER: u16 = 1;
    each(attributes, |kind, value| {
        if (kind == by.0 || kind == by.1) && value.len() >= 4 {
            let number = u32::from_le_bytes(value[..4].try_into().unwrap_or_default());
            let reference = if kind == by.0 {
                Reference::Pid(number)
            } else {
                Reference::Fd(number)
            };
            if !found.iter().any(|&(r, _)| r == reference) {
                found.push((reference, find(c, reference)));
            }
        }
        if link && kind == IFLA_LINKINFO {
            each(value, |kind, data| {
                if kind != IFLA_INFO_DATA {
                    return;
                }
                each(data, |kind, peer| {
                    if kind == VETH_INFO_PEER {
                        let peer = peer.get(16..).unwrap_or_default();
                        references(c, peer, by, false, found);
                    }
                });
            });
        }
    });
}
/// The namespace `reference` names, for [`resolve`].
fn find(c: &Context<'_>, reference: Reference) -> Result<Arc<Network>, Errno> {
    let namespace = match reference {
        Reference::Pid(pid) => {
            // `find_task_by_vpid`, and a task that still has namespaces.
            let tid = c.pid_space().task(pid).ok_or(ESRCH)?;
            let group = c.processes.group_of(tid).ok_or(ESRCH)?;
            Arc::clone(&group.namespaces(tid).net)
        }
        Reference::Fd(fd) => {
            // An `int`: a negative one is no descriptor.
            if i32::try_from(fd).is_err() {
                return Err(Errno::EBADF);
            }
            let d = c
                .files
                .descriptor(u64::from(fd))
                .map_err(|_| Errno::EBADF)?;
            let file = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<crate::namespaces::NamespaceFile>())
                .filter(|file| file.namespace.kind == crate::namespaces::Kind::Net)
                .ok_or(Errno::EINVAL)?;
            Arc::clone(&file.namespace)
        }
    };
    // A nested namespace has its own network; the first one is the
    // session's, which has none without a network.
    namespace
        .sockets
        .network
        .get()
        .cloned()
        .or_else(|| c.files.network.clone())
        .ok_or(Errno::EINVAL)
}
/// The namespace [`resolve`] found for `reference`.
fn resolved(reference: Reference) -> Result<Arc<Network>, Errno> {
    RESOLVED.with(|r| {
        r.borrow().0.iter().find(|&&(r, _)| r == reference).map_or(
            Err(match reference {
                Reference::Pid(_) => ESRCH,
                Reference::Fd(_) => Errno::EBADF,
            }),
            |(_, found)| found.clone(),
        )
    })
}
/// Whether the sender has `CAP_NET_ADMIN` over `network`, and so did the
/// socket's `opener` (`sk_ns_capable`).
fn admin_over(opener: &Credentials, network: &Network) -> bool {
    let current = RESOLVED.with(|r| r.borrow().1.clone());
    opener.capable_in(CAP_NET_ADMIN, network.owner())
        && current
            .as_ref()
            .unwrap_or(opener)
            .capable_in(CAP_NET_ADMIN, network.owner())
}
/// `rtnl_link_get_net_capable`: the namespace a link change names by
/// `IFLA_NET_NS_PID` or `IFLA_NET_NS_FD`, as [`resolve`] found it, or by
/// `IFLA_TARGET_NETNSID` (`EINVAL` for an ID none has); `EPERM` without
/// `CAP_NET_ADMIN` over it, the sender's and the opener's, or with a send
/// that names an address the sender's alone (`netlink_ns_capable`, which
/// passes over the opener for `NETLINK_SKB_DST`). None for a change that
/// names none.
pub(super) fn link_target(
    network: &Network,
    opener: &Credentials,
    pid: Option<u32>,
    fd: Option<u32>,
    id: Option<i32>,
) -> Result<Option<Arc<Network>>, Errno> {
    let named = match (pid, fd, id) {
        (Some(pid), ..) => resolved(Reference::Pid(pid))?,
        (_, Some(fd), _) => resolved(Reference::Fd(fd))?,
        (.., Some(id)) => network.netlink.ids.peer(id).ok_or(Errno::EINVAL)?,
        _ => return Ok(None),
    };
    let (current, addressed) = RESOLVED.with(|r| {
        let r = r.borrow();
        (r.1.clone(), r.2)
    });
    let capable = if addressed {
        current
            .as_ref()
            .unwrap_or(opener)
            .capable_in(CAP_NET_ADMIN, named.owner())
    } else {
        admin_over(opener, &named)
    };
    if !capable {
        return Err(Errno::EPERM);
    }
    Ok(Some(named))
}
/// `rtnl_get_peer_net`: the namespace a veth pair's peer (its
/// `VETH_INFO_PEER`) names by `IFLA_NET_NS_PID` or `IFLA_NET_NS_FD`, as
/// [`resolve`] found it (`ESRCH`, `EBADF`, `EINVAL`), with
/// `CAP_NET_ADMIN` over it as [`link_target`] asks (`EPERM`); `None` for a
/// peer that names none, which is the pair's own.
#[expect(dead_code, reason = "a veth pair's creation calls it")]
pub(super) fn peer_target(
    network: &Network,
    opener: &Credentials,
    pid: Option<u32>,
    fd: Option<u32>,
) -> Result<Option<Arc<Network>>, Errno> {
    link_target(network, opener, pid, fd, None)
}
/// `rtnl_get_net_ns_capable`: the peer of `id`, `EINVAL` for none and
/// `EACCES` without `CAP_NET_ADMIN` over it.
pub(super) fn target(
    network: &Network,
    opener: &Credentials,
    id: i32,
) -> Result<Arc<Network>, Errno> {
    let target = network.netlink.ids.peer(id).ok_or(Errno::EINVAL)?;
    if !admin_over(opener, &target) {
        return Err(EACCES);
    }
    Ok(target)
}

/// The attributes of a request's `payload` after its `rtgenmsg`, the last
/// of each type, as `nlmsg_parse_deprecated` takes them, or with `strict`
/// `nlmsg_parse_deprecated_strict`.
fn table(payload: &[u8], strict: bool) -> Result<[Option<&[u8]>; 6], Errno> {
    let mut tb = [None; 6];
    for (kind, value) in parse_policy(payload.get(4..).unwrap_or_default(), &NETNSA_POLICY, strict)?
    {
        tb[usize::from(kind)] = Some(value);
    }
    Ok(tb)
}
fn s32(value: &[u8]) -> i32 {
    i32::from_le_bytes(value[..4].try_into().unwrap_or_default())
}
fn u32_of(value: &[u8]) -> u32 {
    u32::from_le_bytes(value[..4].try_into().unwrap_or_default())
}
/// The peer `NETNSA_PID` or `NETNSA_FD` of `tb` names, and that attribute.
fn named<'a>(tb: &[Option<&'a [u8]>; 6]) -> Option<(Found, &'a [u8])> {
    if let Some(value) = tb[usize::from(NETNSA_PID)] {
        Some((resolved(Reference::Pid(u32_of(value))), value))
    } else {
        tb[usize::from(NETNSA_FD)].map(|value| (resolved(Reference::Fd(u32_of(value))), value))
    }
}
/// `rtnl_net_fill`: a `kind` message with the ID `nsid`, and `current`
/// as `NETNSA_CURRENT_NSID`.
fn fill(kind: u16, flags: u16, seq: u32, port: u32, nsid: i32, current: Option<i32>) -> Vec<u8> {
    let mut payload = vec![0; 4];
    attribute(&mut payload, NETNSA_NSID, &nsid.to_le_bytes());
    if let Some(current) = current {
        attribute(&mut payload, NETNSA_CURRENT_NSID, &current.to_le_bytes());
    }
    message(kind, flags, seq, port, &payload)
}

/// `RTM_NEWNSID`, as `rtnl_net_newid`: gives the peer `NETNSA_PID` or
/// `NETNSA_FD` names the ID `NETNSA_NSID`, or with a negative one the
/// lowest free; `EINVAL` without either, `EEXIST` for a peer that has one
/// or an ID taken. The notification of it, which goes to `RTNLGRP_NSID`.
pub(super) fn new_id(
    network: &Arc<Network>,
    header: &Header,
    payload: &[u8],
    port: u32,
    echo: bool,
) -> Result<Notice, Errno> {
    let tb = table(payload, false)?;
    let Some(asked) = tb[usize::from(NETNSA_NSID)] else {
        return Err(extack::message(Errno::EINVAL, "nsid is missing"));
    };
    let nsid = s32(asked);
    let Some((peer, nla)) = named(&tb) else {
        return Err(extack::message(
            Errno::EINVAL,
            "Peer netns reference is missing",
        ));
    };
    let peer = peer.map_err(|e| extack::at(e, nla, "Peer netns reference is invalid"))?;
    let ids = &network.netlink.ids;
    let id = {
        let mut live = ids.live();
        if live
            .values()
            .any(|p| std::ptr::eq(p.as_ptr(), Arc::as_ptr(&peer)))
        {
            return Err(extack::at(
                EEXIST,
                nla,
                "Peer netns already has a nsid assigned",
            ));
        }
        let id = if nsid >= 0 {
            if live.contains_key(&nsid) {
                return Err(extack::at(
                    EEXIST,
                    asked,
                    "The specified nsid is already used",
                ));
            }
            nsid
        } else {
            // `idr_alloc`: the lowest free.
            (0..).find(|id| !live.contains_key(id)).unwrap_or(0)
        };
        live.insert(id, Arc::downgrade(&peer));
        id
    };
    heard(network, &peer);
    // `rtnl_net_notifyid`, which `rtnl_notify` sends to the requester
    // alone of the members with `NLM_F_ECHO`.
    Ok(Notice {
        group: RTNLGRP_NSID,
        origin: if echo { port } else { 0 },
        bytes: fill(RTM_NEWNSID, 0, header.seq, port, id, None),
    })
}

/// Notes that `network` has an ID for `peer`, so that `peer`'s
/// notifications reach `network`'s sockets with `NETLINK_LISTEN_ALL_NSID`
/// and `network` hears of it going (`RTM_DELNSID`).
fn heard(network: &Arc<Network>, peer: &Arc<Network>) {
    if Arc::ptr_eq(peer, network) {
        return;
    }
    let mut heard_by = peer
        .netlink
        .ids
        .heard_by
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    heard_by.retain(|n| n.strong_count() > 0);
    if !heard_by
        .iter()
        .any(|n| std::ptr::eq(n.as_ptr(), Arc::as_ptr(network)))
    {
        heard_by.push(Arc::downgrade(network));
    }
}

/// `peernet2id_alloc`: `this` namespace's ID for `peer`, given now, the
/// lowest free (`alloc_netid`), if it has none, as a device whose link is
/// in `peer` asks for its `IFLA_LINK_NETNSID` (`rtnl_fill_link_netnsid`). A
/// new ID is told to `this` namespace's `RTNLGRP_NSID` (`rtnl_net_notifyid`)
/// through `notices`, before what the caller tells next. `None`
/// (`NETNSA_NSID_NOT_ASSIGNED`) when no ID is free.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "a veth pair's link message calls it")
)]
pub(super) fn link_netnsid(
    this: &Arc<Network>,
    peer: &Arc<Network>,
    notices: &mut Vec<Notice>,
) -> Option<i32> {
    let id = {
        let mut live = this.netlink.ids.live();
        if let Some((&id, _)) = live
            .iter()
            .find(|(_, p)| std::ptr::eq(p.as_ptr(), Arc::as_ptr(peer)))
        {
            return Some(id);
        }
        let id = (0..i32::MAX).find(|id| !live.contains_key(id))?;
        live.insert(id, Arc::downgrade(peer));
        id
    };
    heard(this, peer);
    notices.push(Notice {
        group: RTNLGRP_NSID,
        origin: 0,
        bytes: fill(RTM_NEWNSID, 0, 0, 0, id, None),
    });
    Some(id)
}

/// `RTM_GETNSID`, as `rtnl_net_getid`: the ID of the peer `NETNSA_PID`,
/// `NETNSA_FD` or `NETNSA_NSID` names (`ENOENT` for an ID none has), as
/// this namespace numbers it, or with `NETNSA_TARGET_NSID` as that peer
/// does, with this one's in `NETNSA_CURRENT_NSID`; -1 for none. A socket
/// that checks strictly takes no other attribute (`EINVAL`).
pub(super) fn get_id(
    network: &Arc<Network>,
    opener: &Credentials,
    header: &Header,
    payload: &[u8],
    port: u32,
    strict: bool,
) -> Result<Vec<u8>, Errno> {
    let tb = table(payload, strict)?;
    if strict && tb[usize::from(NETNSA_CURRENT_NSID)].is_some() {
        return Err(extack::message(
            Errno::EINVAL,
            "Unsupported attribute in peer netns getid request",
        ));
    }
    let (peer, nla) = if let Some(found) = named(&tb) {
        found
    } else if let Some(value) = tb[usize::from(NETNSA_NSID)] {
        (network.netlink.ids.peer(s32(value)).ok_or(ENOENT), value)
    } else {
        return Err(extack::message(
            Errno::EINVAL,
            "Peer netns reference is missing",
        ));
    };
    let peer = peer.map_err(|e| extack::at(e, nla, "Peer netns reference is invalid"))?;
    let (target, current) = match tb[usize::from(NETNSA_TARGET_NSID)] {
        Some(value) => {
            let target = target(network, opener, s32(value))
                .map_err(|e| extack::at(e, value, "Target netns reference is invalid"))?;
            let current = network.netlink.ids.id_of(&peer).unwrap_or(NOT_ASSIGNED);
            (target, Some(current))
        }
        None => (Arc::clone(network), None),
    };
    let nsid = target.netlink.ids.id_of(&peer).unwrap_or(NOT_ASSIGNED);
    Ok(fill(RTM_NEWNSID, 0, header.seq, port, nsid, current))
}

/// An `RTM_GETNSID` dump, as `rtnl_net_dumpid`: each ID and its peer, in
/// order. A socket that checks strictly may name another namespace by
/// `NETNSA_TARGET_NSID` to dump its IDs, with this one's of each peer in
/// `NETNSA_CURRENT_NSID`, and nothing else (`EINVAL`), as
/// `rtnl_valid_dump_net_req`.
pub(super) fn dump(
    network: &Arc<Network>,
    opener: &Credentials,
    header: &Header,
    payload: &[u8],
    port: u32,
    strict: bool,
) -> Result<Vec<Vec<u8>>, Errno> {
    let mut target = Arc::clone(network);
    let mut add_ref = false;
    if strict {
        let tb = table(payload, true)?;
        for (kind, value) in (0..=NETNSA_MAX).zip(tb) {
            let Some(value) = value else { continue };
            if kind == NETNSA_TARGET_NSID {
                target = self::target(network, opener, s32(value))
                    .map_err(|e| extack::at(e, value, "Invalid target network namespace id"))?;
                add_ref = true;
            } else {
                return Err(extack::at(
                    Errno::EINVAL,
                    value,
                    "Unsupported attribute in dump request",
                ));
            }
        }
    }
    let ids: Vec<(i32, Option<Arc<Network>>)> = target
        .netlink
        .ids
        .live()
        .iter()
        .map(|(&id, peer)| (id, peer.upgrade()))
        .collect();
    Ok(ids
        .into_iter()
        .map(|(id, peer)| {
            let current = add_ref.then(|| {
                peer.and_then(|peer| network.netlink.ids.id_of(&peer))
                    .unwrap_or(NOT_ASSIGNED)
            });
            fill(RTM_NEWNSID, NLM_F_MULTI, header.seq, port, id, current)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_gives_its_peer_the_lowest_free_id_once() {
        let network = || Arc::new(Network::isolated(crate::users::first()));
        let (this, peer, other) = (network(), network(), network());
        let mut notices = Vec::new();
        // An ID a request gave stays taken.
        this.netlink.ids.live().insert(0, Arc::downgrade(&other));
        assert_eq!(link_netnsid(&this, &peer, &mut notices), Some(1));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].group, RTNLGRP_NSID);
        assert_eq!(notices[0].origin, 0);
        assert_eq!(notices[0].bytes, fill(RTM_NEWNSID, 0, 0, 0, 1, None));
        // Asked again, the same, untold.
        assert_eq!(link_netnsid(&this, &peer, &mut notices), Some(1));
        assert_eq!(notices.len(), 1);
        assert_eq!(this.netlink.ids.id_of(&peer), Some(1));
        // `peer` now tells `this` of itself, and of its going.
        assert!(
            peer.netlink
                .ids
                .heard_by()
                .iter()
                .any(|n| Arc::ptr_eq(n, &this))
        );
    }

    fn network() -> Arc<Network> {
        Arc::new(Network::isolated(crate::users::first()))
    }
    /// A user with no capabilities.
    fn user() -> Credentials {
        Credentials {
            uid: 1000,
            euid: 1000,
            suid: 1000,
            fsuid: 1000,
            permitted: 0,
            effective: 0,
            ..Credentials::default()
        }
    }
    /// What [`resolve`] would have found: `found`, with the sender's
    /// `credentials` and whether the send named an address.
    fn found(
        found: Vec<(Reference, Found)>,
        credentials: Option<Credentials>,
        addressed: bool,
    ) -> Resolved {
        RESOLVED.with(|r| *r.borrow_mut() = (found, credentials, addressed));
        Resolved
    }
    /// A request of `kind` and sequence 7: an `rtgenmsg`, then
    /// `attributes`.
    fn request(kind: u16, attributes: &[(u16, i32)]) -> (Header, Vec<u8>) {
        let mut payload = vec![0; 4];
        for &(kind, value) in attributes {
            attribute(&mut payload, kind, &value.to_le_bytes());
        }
        let header = Header {
            len: 16 + payload.len() as u32,
            kind,
            flags: 0,
            seq: 7,
        };
        (header, payload)
    }
    /// The `NETNSA_NSID` and `NETNSA_CURRENT_NSID` of an answer.
    fn ids_of(answer: &[u8]) -> (i32, Option<i32>) {
        let (mut nsid, mut current) = (i32::MIN, None);
        each(&answer[20..], |kind, value| match kind {
            NETNSA_NSID => nsid = s32(value),
            NETNSA_CURRENT_NSID => current = Some(s32(value)),
            _ => {}
        });
        (nsid, current)
    }

    #[test]
    fn a_new_id_needs_an_id_and_a_peer_that_has_none() {
        let (this, peer, other) = (network(), network(), network());
        let _found = found(
            vec![
                (Reference::Pid(10), Ok(Arc::clone(&peer))),
                (Reference::Fd(3), Ok(Arc::clone(&other))),
                (Reference::Fd(4), Err(Errno::EINVAL)),
            ],
            None,
            false,
        );
        let new = |attributes: &[(u16, i32)], echo| {
            let (header, payload) = request(RTM_NEWNSID, attributes);
            new_id(&this, &header, &payload, 55, echo)
        };
        // `rtnl_net_newid`: no ID, then no peer, are `EINVAL`; a process
        // or descriptor none is gives its own error.
        assert_eq!(new(&[(NETNSA_PID, 10)], false).err(), Some(Errno::EINVAL));
        assert_eq!(new(&[(NETNSA_NSID, 5)], false).err(), Some(Errno::EINVAL));
        assert_eq!(
            new(&[(NETNSA_NSID, 5), (NETNSA_PID, 11)], false).err(),
            Some(ESRCH)
        );
        assert_eq!(
            new(&[(NETNSA_NSID, 5), (NETNSA_FD, 9)], false).err(),
            Some(Errno::EBADF)
        );
        assert_eq!(
            new(&[(NETNSA_NSID, 5), (NETNSA_FD, 4)], false).err(),
            Some(Errno::EINVAL)
        );
        // The ID asked for, told to the group with the request's sequence
        // and port.
        let notice = new(&[(NETNSA_NSID, 5), (NETNSA_PID, 10)], false).unwrap();
        assert_eq!(notice.group, RTNLGRP_NSID);
        assert_eq!(notice.origin, 0);
        assert_eq!(notice.bytes, fill(RTM_NEWNSID, 0, 7, 55, 5, None));
        assert_eq!(this.netlink.ids.id_of(&peer), Some(5));
        assert!(
            peer.netlink
                .ids
                .heard_by()
                .iter()
                .any(|n| Arc::ptr_eq(n, &this))
        );
        // A peer that has one, or an ID taken: `EEXIST`, and nothing
        // changes.
        assert_eq!(
            new(&[(NETNSA_NSID, 6), (NETNSA_PID, 10)], false).err(),
            Some(EEXIST)
        );
        assert_eq!(
            new(&[(NETNSA_NSID, 5), (NETNSA_FD, 3)], false).err(),
            Some(EEXIST)
        );
        assert_eq!(this.netlink.ids.id_of(&other), None);
        // A negative one takes the lowest free; with `NLM_F_ECHO` the
        // requester alone of the members hears of it.
        let notice = new(&[(NETNSA_NSID, -1), (NETNSA_FD, 3)], true).unwrap();
        assert_eq!(notice.origin, 55);
        assert_eq!(ids_of(&notice.bytes), (0, None));
        assert_eq!(this.netlink.ids.id_of(&other), Some(0));
        // The namespace's own ID for itself tells no one.
        let _found = found(
            vec![(Reference::Pid(1), Ok(Arc::clone(&this)))],
            None,
            false,
        );
        assert!(new(&[(NETNSA_NSID, 9), (NETNSA_PID, 1)], false).is_ok());
        assert!(this.netlink.ids.heard_by().is_empty());
    }

    #[test]
    fn get_id_tells_an_id_by_process_descriptor_or_id() {
        let (this, peer, other, target) = (network(), network(), network(), network());
        this.netlink.ids.live().insert(2, Arc::downgrade(&peer));
        this.netlink.ids.live().insert(3, Arc::downgrade(&target));
        target.netlink.ids.live().insert(8, Arc::downgrade(&peer));
        let _found = found(
            vec![
                (Reference::Pid(10), Ok(Arc::clone(&peer))),
                (Reference::Fd(3), Ok(Arc::clone(&other))),
            ],
            None,
            false,
        );
        let opener = Credentials::default();
        let get = |attributes: &[(u16, i32)], strict| {
            let (header, payload) = request(RTM_GETNSID, attributes);
            get_id(&this, &opener, &header, &payload, 55, strict)
        };
        let answer = get(&[(NETNSA_PID, 10)], false).unwrap();
        assert_eq!(answer, fill(RTM_NEWNSID, 0, 7, 55, 2, None));
        assert_eq!(ids_of(&get(&[(NETNSA_NSID, 2)], false).unwrap()), (2, None));
        // A peer with no ID: `NETNSA_NSID_NOT_ASSIGNED`.
        assert_eq!(ids_of(&get(&[(NETNSA_FD, 3)], false).unwrap()), (-1, None));
        // An ID none has, no reference, or a process none is.
        assert_eq!(get(&[(NETNSA_NSID, 4)], false).err(), Some(ENOENT));
        assert_eq!(get(&[], false).err(), Some(Errno::EINVAL));
        assert_eq!(get(&[(NETNSA_PID, 11)], false).err(), Some(ESRCH));
        // Strictly, `NETNSA_CURRENT_NSID` is not the request's to give.
        assert!(get(&[(NETNSA_PID, 10), (NETNSA_CURRENT_NSID, 0)], false).is_ok());
        assert_eq!(
            get(&[(NETNSA_PID, 10), (NETNSA_CURRENT_NSID, 0)], true).err(),
            Some(Errno::EINVAL)
        );
        // As another namespace numbers the peer, with this one's ID too;
        // the other's ID none has is `EINVAL`.
        let answer = get(&[(NETNSA_PID, 10), (NETNSA_TARGET_NSID, 3)], false).unwrap();
        assert_eq!(answer, fill(RTM_NEWNSID, 0, 7, 55, 8, Some(2)));
        assert_eq!(
            ids_of(&get(&[(NETNSA_FD, 3), (NETNSA_TARGET_NSID, 3)], false).unwrap()),
            (-1, Some(-1))
        );
        assert_eq!(
            get(&[(NETNSA_PID, 10), (NETNSA_TARGET_NSID, 9)], false).err(),
            Some(Errno::EINVAL)
        );
        // Without `CAP_NET_ADMIN` over the other one: `EACCES`.
        let user = user();
        let (header, payload) = request(RTM_GETNSID, &[(NETNSA_PID, 10), (NETNSA_TARGET_NSID, 3)]);
        assert_eq!(
            get_id(&this, &user, &header, &payload, 55, false).err(),
            Some(EACCES)
        );
    }

    #[test]
    fn a_dump_lists_the_ids_in_order_or_another_namespaces() {
        let (this, first, second, target) = (network(), network(), network(), network());
        this.netlink.ids.live().insert(4, Arc::downgrade(&second));
        this.netlink.ids.live().insert(1, Arc::downgrade(&first));
        this.netlink.ids.live().insert(6, Arc::downgrade(&target));
        target.netlink.ids.live().insert(0, Arc::downgrade(&second));
        target.netlink.ids.live().insert(3, Arc::downgrade(&this));
        let _found = found(Vec::new(), None, false);
        let opener = Credentials::default();
        let dump_of = |attributes: &[(u16, i32)], strict| {
            let (header, payload) = request(RTM_GETNSID, attributes);
            dump(&this, &opener, &header, &payload, 55, strict)
        };
        let all = dump_of(&[], true).unwrap();
        assert_eq!(
            all,
            [1, 4, 6].map(|id| fill(RTM_NEWNSID, NLM_F_MULTI, 7, 55, id, None))
        );
        // Unchecked, any attribute is passed over.
        assert_eq!(dump_of(&[(NETNSA_TARGET_NSID, 6)], false), Ok(all));
        // Strictly, another namespace's, with this one's ID of each peer.
        let other = dump_of(&[(NETNSA_TARGET_NSID, 6)], true).unwrap();
        assert_eq!(
            other.iter().map(|m| ids_of(m)).collect::<Vec<_>>(),
            [(0, Some(4)), (3, Some(-1))]
        );
        assert_eq!(
            dump_of(&[(NETNSA_TARGET_NSID, 2)], true).err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(
            dump_of(&[(NETNSA_NSID, 1)], true).err(),
            Some(Errno::EINVAL)
        );
        let user = user();
        let (header, payload) = request(RTM_GETNSID, &[(NETNSA_TARGET_NSID, 6)]);
        assert_eq!(
            dump(&this, &user, &header, &payload, 55, true).err(),
            Some(EACCES)
        );
    }

    #[test]
    fn a_link_change_names_a_namespace_it_may_administer() {
        let (this, peer) = (network(), network());
        this.netlink.ids.live().insert(2, Arc::downgrade(&peer));
        let root = Credentials::default();
        let user = user();
        let _found = found(
            vec![(Reference::Pid(10), Ok(Arc::clone(&peer)))],
            None,
            false,
        );
        let named = |opener: &Credentials, pid, fd, id| {
            link_target(&this, opener, pid, fd, id).map(|n| n.map(|n| Arc::ptr_eq(&n, &peer)))
        };
        assert_eq!(named(&root, None, None, None), Ok(None));
        assert_eq!(named(&root, Some(10), None, Some(9)), Ok(Some(true)));
        assert_eq!(named(&root, None, None, Some(2)), Ok(Some(true)));
        assert_eq!(named(&root, None, None, Some(9)), Err(Errno::EINVAL));
        assert_eq!(named(&root, Some(11), None, None), Err(ESRCH));
        assert_eq!(named(&root, None, Some(3), None), Err(Errno::EBADF));
        // Both the opener and the sender need `CAP_NET_ADMIN` over it.
        assert_eq!(named(&user, Some(10), None, None), Err(Errno::EPERM));
        let _found = found(
            vec![(Reference::Pid(10), Ok(Arc::clone(&peer)))],
            Some(user.clone()),
            false,
        );
        assert_eq!(named(&root, Some(10), None, None), Err(Errno::EPERM));
        // A send that names an address asks the sender alone.
        let _found = found(
            vec![(Reference::Pid(10), Ok(Arc::clone(&peer)))],
            Some(root.clone()),
            true,
        );
        assert_eq!(named(&user, Some(10), None, None), Ok(Some(true)));
        let _found = found(
            vec![(Reference::Pid(10), Ok(Arc::clone(&peer)))],
            Some(user.clone()),
            true,
        );
        assert_eq!(named(&root, Some(10), None, None), Err(Errno::EPERM));
    }

    #[test]
    fn an_id_goes_with_its_peer() {
        let (this, other) = (network(), network());
        let peer = network();
        let mut notices = Vec::new();
        assert_eq!(link_netnsid(&this, &peer, &mut notices), Some(0));
        assert_eq!(link_netnsid(&other, &peer, &mut notices), Some(0));
        assert_eq!(link_netnsid(&this, &other, &mut notices), Some(1));
        drop(peer);
        // `unhash_nsid`: each namespace that had an ID for it forgets it,
        // which is free again; the others stay.
        assert_eq!(
            this.netlink.ids.live().keys().copied().collect::<Vec<_>>(),
            [1]
        );
        assert!(other.netlink.ids.live().is_empty());
        assert_eq!(link_netnsid(&this, &network(), &mut notices), Some(0));
    }
}
