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
//! Only a request gives an ID. Linux's `peernet2id_alloc` also gives one
//! on its own, for what lies in another namespace than the one telling
//! of it: a device whose link is there or that moves there, a queue lease,
//! a devlink instance, a PSP device, an ovpn peer or an openvswitch vport.
//! None of those is here, and `lo` may not move.
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
type Resolution = (Vec<(Reference, Found)>, Option<Credentials>);
thread_local! {
    /// The peers the requests of the datagram being sent name, found with
    /// the sender's view before the kernel takes them, and the sender's
    /// credentials ([`resolve`]).
    static RESOLVED: RefCell<Resolution> =
        const { RefCell::new((Vec::new(), None)) };
}
/// What [`resolve`] found, until it is dropped.
pub(crate) struct Resolved;
impl Drop for Resolved {
    fn drop(&mut self) {
        RESOLVED.with(|r| *r.borrow_mut() = (Vec::new(), None));
    }
}
/// Finds, as the caller of `c` sees them, the namespaces each
/// `RTM_NEWNSID` and `RTM_GETNSID` request of `bytes` names by
/// `NETNSA_PID` (`get_net_ns_by_pid`) or `NETNSA_FD` (`get_net_ns_by_fd`),
/// for the kernel to take as it reaches them; finding one changes nothing.
/// A `write` finds them as its caller sees them too ([`super::resolving`]),
/// as Linux looks in `current`'s.
pub(super) fn resolve(c: &Context<'_>, mut bytes: &[u8]) -> Resolved {
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
        if matches!(header.kind, super::RTM_GETLINK | super::RTM_GETADDR) {
            any = true;
        }
        if matches!(header.kind, RTM_NEWNSID | RTM_GETNSID) {
            any = true;
            let mut attributes = bytes[16..len].get(4..).unwrap_or_default();
            while attributes.len() >= 4 {
                let size = usize::from(u16::from_le_bytes([attributes[0], attributes[1]]));
                if size < 4 || size > attributes.len() {
                    break;
                }
                let kind = u16::from_le_bytes([attributes[2], attributes[3]]) & 0x3fff;
                if size >= 8 && matches!(kind, NETNSA_PID | NETNSA_FD) {
                    let value = u32::from_le_bytes(attributes[4..8].try_into().unwrap_or_default());
                    let reference = if kind == NETNSA_PID {
                        Reference::Pid(value)
                    } else {
                        Reference::Fd(value)
                    };
                    if !found.iter().any(|&(r, _)| r == reference) {
                        found.push((reference, find(c, reference)));
                    }
                }
                attributes = &attributes[super::align(size).min(attributes.len())..];
            }
        }
        bytes = &bytes[super::align(len).min(bytes.len())..];
    }
    // Only those requests read the sender's credentials ([`admin_over`]).
    let credentials = any.then(|| c.process.credentials.clone());
    RESOLVED.with(|r| *r.borrow_mut() = (found, credentials));
    Resolved
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
    if !Arc::ptr_eq(&peer, network) {
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
    // `rtnl_net_notifyid`, which `rtnl_notify` sends to the requester
    // alone of the members with `NLM_F_ECHO`.
    Ok(Notice {
        group: RTNLGRP_NSID,
        origin: if echo { port } else { 0 },
        bytes: fill(RTM_NEWNSID, 0, header.seq, port, id, None),
    })
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
