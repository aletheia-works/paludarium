//! `AF_MCTP` sockets, as Linux 7.0's `net/mctp` has them on a kernel built
//! with `CONFIG_MCTP`: datagram sockets of the Management Component
//! Transport Protocol, which reach the endpoint IDs the loopback has
//! ([`crate::netlink`] adds them and their routes).
//!
//! A message goes as `mctp_local_output` sends it: through the route to its
//! endpoint ID, in packets of the route's MTU, each into `mctp_dst_input`,
//! which reassembles them and gives the message to the socket a tag's key
//! or a bind names. A send out of the loopback by its hardware address
//! (`MCTP_OPT_ADDR_EXT`) is lost, as on Linux, where the loopback takes
//! the frame back in as 802.2's. Tags are kept as Linux keeps them: a
//! tag a sender owns has a key for six seconds, or until the answer to it
//! comes, and `SIOCMCTPALLOCTAG` keeps one until `SIOCMCTPDROPTAG`.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::inet::Network;
use crate::skb::{SHARED_INFO, truesize};
use crate::sockets::Timeout;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

pub(crate) const AF_MCTP: u64 = 45;
const SOCK_DGRAM: u32 = 2;
const SOL_SOCKET: u64 = 1;
const SOL_MCTP: u64 = 285;
const MCTP_OPT_ADDR_EXT: u64 = 1;
/// `MCTP_ADDR_NULL`, `MCTP_ADDR_ANY` and `MCTP_NET_ANY`.
const NULL: u8 = 0;
const ANY: u8 = 0xff;
const NET_ANY: u32 = 0;
/// The network the loopback is in, the default one
/// (`MCTP_INITIAL_DEFAULT_NET`).
const DEFAULT_NET: u32 = 1;
/// `smctp_tag`'s bits: the tag, `MCTP_TAG_OWNER` (the header's
/// `MCTP_HDR_FLAG_TO`) and `MCTP_TAG_PREALLOC`.
const TAG_MASK: u8 = 0x07;
const TAG_OWNER: u8 = 0x08;
const TAG_PREALLOC: u8 = 0x10;
/// A packet's `MCTP_HDR_FLAG_SOM` and `MCTP_HDR_FLAG_EOM`, and where its
/// sequence number is.
const SOM: u8 = 0x80;
const EOM: u8 = 0x40;
const SEQ_SHIFT: u8 = 4;
/// `sizeof(struct mctp_hdr)`.
const HEADER: usize = 4;
/// `sizeof(struct sockaddr_mctp)` and `sizeof(struct sockaddr_mctp_ext)`.
const NAME: usize = 12;
const NAME_EXT: usize = 52;
/// `MAX_ADDR_LEN`, and the loopback's hardware address length, MTU and
/// index.
const MAX_ADDR_LEN: usize = 32;
const LO_ADDR_LEN: usize = 6;
const LO_MTU: usize = 65536;
const LO_INDEX: i32 = 1;
/// The longest message a key reassembles (`mctp_message_maxlen`).
const MESSAGE_MAX: usize = 64 * 1024;
/// How long a key lasts (`mctp_key_lifetime`), in nanoseconds.
const KEY_LIFETIME: u64 = 6_000_000_000;
/// How many routes a lookup follows through gateways at most.
const ROUTE_DEPTH: usize = 32;
/// `KMALLOC_MAX_SIZE` on x86-64: the largest head `alloc_skb` makes.
const KMALLOC_MAX: usize = 4 << 20;
/// `LL_RESERVED_SPACE` of the loopback: its Ethernet header, aligned.
const LL_RESERVED: usize = 16;
const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
const CAP_NET_RAW: u64 = 1 << 13;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
/// The tag ioctls (`SIOCPROTOPRIVATE` and on).
const SIOCMCTPALLOCTAG: u32 = 0x89e0;
const SIOCMCTPDROPTAG: u32 = 0x89e1;
const SIOCMCTPALLOCTAG2: u32 = 0x89e2;
const SIOCMCTPDROPTAG2: u32 = 0x89e3;
/// The socket ioctls `sock_ioctl` answers before a family's own.
const SOCKET_IOCTLS: [u32; 16] = [
    0x8901,
    0x8902,
    0x8903,
    0x8904,
    0x8906,
    0x8907,
    0x8010_8906,
    0x8010_8907,
    0x8940,
    0x8941,
    0x89a0,
    0x89a1,
    0x8982,
    0x8983,
    0x894c,
    0x8912,
];
const EACCES: Errno = Errno(13);
const EBUSY: Errno = Errno(16);
const EEXIST: Errno = Errno(17);
const ENOTSOCK: Errno = Errno(88);
const EDESTADDRREQ: Errno = Errno(89);
const EMSGSIZE: Errno = Errno(90);
const ENOPROTOOPT: Errno = Errno(92);
const EPROTONOSUPPORT: Errno = Errno(93);
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EOPNOTSUPP: Errno = Errno(95);
const EAFNOSUPPORT: Errno = Errno(97);
const EADDRINUSE: Errno = Errno(98);
const ENOBUFS: Errno = Errno(105);
const EHOSTUNREACH: Errno = Errno(113);
/// `net.core.rmem_default` and `wmem_default`, and their `_max`.
const BUFFER_DEFAULT: i32 = 212_992;
const BUFFER_MAX: i32 = 212_992;
/// What `sock_setsockopt` keeps at least (`SOCK_MIN_RCVBUF`, `_SNDBUF`).
const MIN_RECEIVE_BUFFER: i32 = 2304;
const MIN_SEND_BUFFER: i32 = 4608;

/// The MCTP sockets of a network namespace: the binds, in the buckets of
/// Linux's `binds` hash table, the newest of each first, and the keys of
/// the tags, the newest first.
#[derive(Default)]
pub(crate) struct Endpoints(Mutex<Table>);
#[derive(Default)]
struct Table {
    binds: BTreeMap<u32, Vec<(Bind, Weak<MctpSocket>)>>,
    keys: Vec<Key>,
}
/// What a socket is bound to: a message type, a local endpoint ID (or
/// `MCTP_ADDR_ANY`), a network (or `MCTP_NET_ANY`), and the peer
/// `connect` named, if it did.
#[derive(Clone, Copy, Default)]
struct Bind {
    kind: u8,
    local: u8,
    net: u32,
    peer: Option<(u32, u8)>,
}
/// A tag's key (`struct mctp_sk_key`): its network, local and peer
/// endpoint IDs (either may be `MCTP_ADDR_ANY`) and tag (with
/// `MCTP_HDR_FLAG_TO` when the peer owns it), the socket it is for, when
/// it runs out, whether `SIOCMCTPALLOCTAG` made it, and the message it is
/// reassembling.
struct Key {
    net: u32,
    local: u8,
    peer: u8,
    tag: u8,
    socket: Weak<MctpSocket>,
    expiry: u64,
    manual: bool,
    reassembly: Option<Reassembly>,
}
/// A message being reassembled: its bytes so far, the last packet's
/// sequence number, and the `truesize` of its packets.
struct Reassembly {
    bytes: Vec<u8>,
    seq: u8,
    size: usize,
}
/// A packet, as `mctp_dst_input` takes it: its header's addresses and
/// flags, what follows the header, its `truesize`, and the network and
/// interface it came in by (`mctp_skb_cb`).
struct Packet<'a> {
    dest: u8,
    src: u8,
    flags: u8,
    data: &'a [u8],
    size: usize,
    net: u32,
    ifindex: i32,
}
/// A message waiting to be received: its type and bytes, where it came
/// from, its tag, and what it takes of the receive buffer.
struct Message {
    bytes: Vec<u8>,
    net: u32,
    src: u8,
    tag: u8,
    ifindex: i32,
    size: usize,
}

/// `hash_32`, with `MCTP_BINDS_BITS` (7) of it: `mctp_bind_hash`.
fn bucket(kind: u8, local: u8, peer: u8) -> u32 {
    let value = u32::from(kind) | u32::from(local) << 8 | u32::from(peer) << 16;
    value.wrapping_mul(0x61c8_8647) >> 25
}
/// `mctp_address_matches`.
fn matches(pattern: u8, eid: u8) -> bool {
    pattern == eid || pattern == ANY
}

impl Endpoints {
    fn lock(&self, now: u64) -> MutexGuard<'_, Table> {
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // `mctp_sk_expire_keys`: a key not made by hand goes once it has
        // run out.
        t.keys
            .retain(|k| (k.manual || k.expiry >= now) && k.socket.strong_count() > 0);
        t
    }
}

impl Table {
    /// The first key that matches (`mctp_lookup_key`).
    fn key(&self, net: u32, local: u8, peer: u8, tag: u8) -> Option<usize> {
        self.keys.iter().position(|k| {
            k.net == net && matches(k.local, local) && matches(k.peer, peer) && k.tag == tag
        })
    }
    /// The socket bound to take a message of `kind` to `dest` from `src`,
    /// as `mctp_lookup_bind` looks in order of widening scope.
    fn bound(&self, net: u32, kind: u8, dest: u8, src: u8) -> Option<Arc<MctpSocket>> {
        let pass = |dest: u8, src: u8, any_net: bool| {
            self.binds
                .get(&bucket(kind, dest, src))?
                .iter()
                .filter(|(b, _)| {
                    (any_net || b.net != NET_ANY)
                        && (b.net == NET_ANY || b.net == net)
                        && b.kind == kind
                        && b.peer.is_none_or(|(_, peer)| matches(peer, src))
                        && matches(b.local, dest)
                })
                .find_map(|(_, socket)| socket.upgrade())
        };
        pass(dest, src, false)
            .or_else(|| pass(ANY, src, false))
            .or_else(|| pass(dest, ANY, false))
            .or_else(|| pass(ANY, ANY, false))
            .or_else(|| pass(ANY, ANY, true))
    }
    /// Done with key `at` (`__mctp_key_done_in`): one made by hand stays,
    /// without its reassembly; any other goes.
    fn done(&mut self, at: usize) {
        if self.keys[at].manual {
            self.keys[at].reassembly = None;
        } else {
            self.keys.remove(at);
        }
    }
    /// Takes `packet` in, as `mctp_dst_input`: to the socket of the key
    /// its addresses and tag match, or the start of a message the peer
    /// owns the tag of to the socket bound for it, reassembling a message
    /// of more than one packet in a key of its own.
    fn input(&mut self, packet: &Packet<'_>, now: u64) -> Result<(), Errno> {
        let tag = packet.flags & (TAG_MASK | TAG_OWNER);
        let net = packet.net;
        let seq = (packet.flags >> SEQ_SHIFT) & 3;
        let key = self.key(net, packet.dest, packet.src, tag);
        if packet.flags & SOM != 0 {
            let socket = match key {
                Some(at) => self.keys[at].socket.upgrade(),
                // The first answer to a broadcast: a key for any peer.
                None => self
                    .key(net, packet.dest, ANY, tag)
                    .and_then(|at| self.keys[at].socket.upgrade())
                    .or_else(|| {
                        (tag & TAG_OWNER != 0)
                            .then(|| {
                                self.bound(net, packet.data[0] & 0x7f, packet.dest, packet.src)
                            })
                            .flatten()
                    }),
            };
            let socket = socket.ok_or(Errno::ENOENT)?;
            if packet.flags & EOM != 0 {
                let queued = socket.queue(Message {
                    bytes: packet.data.to_vec(),
                    net,
                    src: packet.src,
                    tag,
                    ifindex: packet.ifindex,
                    size: packet.size,
                });
                // A reassembly pending there is dropped.
                if let Some(at) = key {
                    self.done(at);
                }
                return queued;
            }
            let reassembly = Reassembly {
                bytes: packet.data.to_vec(),
                seq,
                size: packet.size,
            };
            match key {
                // `mctp_key_add`, which finds no key that matches: the
                // lookup found none.
                None => {
                    self.keys.insert(
                        0,
                        Key {
                            net,
                            local: packet.dest,
                            peer: packet.src,
                            tag,
                            socket: Arc::downgrade(&socket),
                            expiry: now + KEY_LIFETIME,
                            manual: false,
                            reassembly: Some(reassembly),
                        },
                    );
                    Ok(())
                }
                // A second start drops everything.
                Some(at) if self.keys[at].reassembly.is_some() => {
                    self.done(at);
                    Err(EEXIST)
                }
                Some(at) => {
                    self.keys[at].reassembly = Some(reassembly);
                    Ok(())
                }
            }
        } else if let Some(at) = key {
            // `mctp_frag_queue`: the next sequence number, and no more
            // than a message may take; a packet that is neither is dropped,
            // and the reassembly waits on.
            let Some(r) = self.keys[at].reassembly.as_mut() else {
                return Err(Errno::EINVAL);
            };
            if seq != (r.seq + 1) & 3 || r.bytes.len() + packet.data.len() > MESSAGE_MAX {
                return Err(Errno::EINVAL);
            }
            r.bytes.extend_from_slice(packet.data);
            r.seq = seq;
            r.size += packet.size;
            if packet.flags & EOM == 0 {
                return Ok(());
            }
            let r = self.keys[at]
                .reassembly
                .take()
                .unwrap_or_else(|| Reassembly {
                    bytes: Vec::new(),
                    seq: 0,
                    size: 0,
                });
            let queued = match self.keys[at].socket.upgrade() {
                Some(socket) => socket.queue(Message {
                    bytes: r.bytes,
                    net,
                    src: packet.src,
                    tag,
                    ifindex: packet.ifindex,
                    size: r.size,
                }),
                None => Err(Errno::ENOENT),
            };
            self.done(at);
            queued
        } else {
            Err(Errno::ENOENT)
        }
    }
    /// A tag `socket` owns for messages from `local` to `peer`, as
    /// `mctp_alloc_local_tag`: the lowest that no key of another such tag
    /// of the network has (`EBUSY` for none), its key kept for six seconds
    /// or, `manual`, until it is dropped.
    fn allocate(
        &mut self,
        socket: &Weak<MctpSocket>,
        net: u32,
        local: u8,
        peer: u8,
        manual: bool,
        now: u64,
    ) -> Result<u8, Errno> {
        let peer = if peer == NULL { ANY } else { peer };
        let mut free = 0xffu8;
        for k in &self.keys {
            if k.net != net
                || k.tag & TAG_OWNER != 0
                || (peer != ANY && !matches(k.peer, peer))
                || (local != ANY && !matches(k.local, local))
            {
                continue;
            }
            free &= !(1 << k.tag);
        }
        if free == 0 {
            return Err(EBUSY);
        }
        let tag = free.trailing_zeros() as u8;
        self.keys.insert(
            0,
            Key {
                net,
                local,
                peer,
                tag,
                socket: Weak::clone(socket),
                expiry: now + KEY_LIFETIME,
                manual,
                reassembly: None,
            },
        );
        Ok(tag)
    }
}

/// The state of an `AF_MCTP` socket.
#[derive(Default)]
struct State {
    /// What `bind` and `connect` set, and whether it is bound (hashed).
    bind: Bind,
    hashed: bool,
    /// `MCTP_OPT_ADDR_EXT`.
    ext: bool,
    queue: VecDeque<Message>,
    /// The `truesize` of the messages queued (`sk_rmem_alloc`).
    held: usize,
    arrivals: u64,
    receive_buffer: i32,
    send_buffer: i32,
    receive_timeout: Timeout,
}

/// An `AF_MCTP` socket.
pub(crate) struct MctpSocket {
    this: Weak<MctpSocket>,
    network: Arc<Network>,
    hub: Arc<ReadinessHub>,
    flags: AtomicU32,
    inode: u64,
    mode: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    state: Mutex<State>,
}

/// `socket(AF_MCTP, type, protocol)`, as Linux's `mctp_pf_create`: protocol
/// 0 alone (`EPROTONOSUPPORT`), then `SOCK_DGRAM` alone (`ESOCKTNOSUPPORT`).
/// Without a network there is none (`EAFNOSUPPORT`).
pub(crate) fn socket(c: &Context<'_>, a: [u64; 6]) -> Result<Arc<dyn FileHandle>, Errno> {
    let kind = create(c, a)?;
    let credentials = &c.process.credentials;
    let network = c.network().ok_or(EAFNOSUPPORT)?;
    let socket = Arc::new_cyclic(|this| MctpSocket {
        this: Weak::clone(this),
        network,
        hub: Arc::clone(&c.files.readiness),
        flags: AtomicU32::new(2 | (kind & NONBLOCK)),
        inode: crate::files::anonymous_inode(),
        mode: AtomicU32::new(0o140777),
        uid: AtomicU32::new(credentials.fsuid),
        gid: AtomicU32::new(credentials.fsgid),
        state: Mutex::new(State {
            receive_buffer: BUFFER_DEFAULT,
            send_buffer: BUFFER_DEFAULT,
            ..State::default()
        }),
    });
    Ok(socket)
}
/// The checks of `socket` and `socketpair` for `AF_MCTP`, as
/// `__sys_socket` and `__sock_create` make them before `mctp_pf_create`:
/// the type and its flags.
fn create(c: &Context<'_>, a: [u64; 6]) -> Result<u32, Errno> {
    let kind = a[1] as u32;
    if a[1] > u64::from(u32::MAX) || kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 || kind & 0xf >= 11 {
        return Err(Errno::EINVAL);
    }
    c.network().ok_or(EAFNOSUPPORT)?;
    if a[2] as u32 != 0 {
        return Err(EPROTONOSUPPORT);
    }
    if kind & 0xf != SOCK_DGRAM {
        return Err(ESOCKTNOSUPPORT);
    }
    Ok(kind)
}
/// `socketpair(AF_MCTP, ...)`: the sockets are made, then
/// `sock_no_socketpair` refuses (`EOPNOTSUPP`).
pub(crate) fn pair(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    create(c, a)?;
    Err(EOPNOTSUPP)
}

/// The MCTP socket of `file`, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&MctpSocket> {
    file.as_any()?.downcast_ref::<MctpSocket>()
}

impl MctpSocket {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::SeqCst) & NONBLOCK != 0
    }
    /// Queues `message`, as `sock_queue_rcv_skb`: `ENOMEM` once what is
    /// queued takes the receive buffer.
    fn queue(&self, message: Message) -> Result<(), Errno> {
        let mut s = self.lock();
        if s.held >= usize::try_from(s.receive_buffer).unwrap_or(0) {
            return Err(Errno::ENOMEM);
        }
        s.held += message.size;
        s.queue.push_back(message);
        s.arrivals += 1;
        drop(s);
        self.hub.changed();
        Ok(())
    }
    /// `bind`, as `mctp_bind` and `mctp_sk_hash`: a message type (its
    /// integrity check bit left out), a local endpoint ID and a network,
    /// of the network `connect` named if it did; no two sockets may be
    /// bound alike (`EADDRINUSE`).
    fn bind(&self, raw: &[u8], capable: bool) -> Result<u64, Errno> {
        if raw.len() < NAME {
            return Err(Errno::EINVAL);
        }
        if u16::from_le_bytes([raw[0], raw[1]]) != AF_MCTP as u16 {
            return Err(EAFNOSUPPORT);
        }
        if !capable {
            return Err(EACCES);
        }
        if raw[2] | raw[3] | raw[11] != 0 {
            return Err(Errno::EINVAL);
        }
        let mut t = self.network.mctp.lock(0);
        let mut s = self.lock();
        if s.hashed {
            return Err(EADDRINUSE);
        }
        let net = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        s.bind.local = raw[8];
        s.bind.net = if net == NET_ANY && raw[8] != ANY {
            DEFAULT_NET
        } else {
            net
        };
        let kind = raw[9] & 0x7f;
        if let Some((peer_net, _)) = s.bind.peer {
            if s.bind.kind != kind {
                return Err(Errno::EINVAL);
            }
            if s.bind.net == NET_ANY {
                s.bind.net = peer_net;
            }
            if s.bind.net != peer_net {
                return Err(Errno::EINVAL);
            }
        } else {
            s.bind.kind = kind;
        }
        let bind = s.bind;
        let peer = bind.peer.map_or(ANY, |(_, peer)| peer);
        let bucket = t
            .binds
            .entry(bucket(bind.kind, bind.local, peer))
            .or_default();
        bucket.retain(|(_, socket)| socket.strong_count() > 0);
        let taken = bucket.iter().any(|(b, _)| {
            b.kind == bind.kind
                && b.local == bind.local
                && b.peer.map(|(_, p)| p) == bind.peer.map(|(_, p)| p)
                && b.net == bind.net
        });
        if taken {
            return Err(EADDRINUSE);
        }
        bucket.insert(0, (bind, Weak::clone(&self.this)));
        s.hashed = true;
        Ok(0)
    }
    /// `connect`, as `mctp_connect`: the peer a bind is to take messages
    /// from, before it; a send still names where it goes.
    fn connect(&self, raw: &[u8]) -> Result<u64, Errno> {
        if raw.len() != NAME {
            return Err(Errno::EINVAL);
        }
        if u16::from_le_bytes([raw[0], raw[1]]) != AF_MCTP as u16 {
            return Err(EAFNOSUPPORT);
        }
        if raw[2] | raw[3] | raw[11] != 0 || raw[10] != 0 || raw[9] & 0x80 != 0 {
            return Err(Errno::EINVAL);
        }
        let mut s = self.lock();
        if s.hashed || s.bind.peer.is_some() {
            return Err(EADDRINUSE);
        }
        let net = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        s.bind.peer = Some((if net == NET_ANY { DEFAULT_NET } else { net }, raw[8]));
        s.bind.kind = raw[9];
        Ok(0)
    }
    /// Sends a message, as `mctp_sendmsg`: to the `sockaddr_mctp` of
    /// `name` (`EDESTADDRREQ` without one), or with `MCTP_OPT_ADDR_EXT` and
    /// a `sockaddr_mctp_ext` out of the loopback to its hardware address.
    /// `payload` reads the bytes once the address is checked and the
    /// message's buffer made.
    fn send(
        &self,
        name: Option<&[u8]>,
        capable: bool,
        now: u64,
        len: usize,
        payload: impl FnOnce() -> Result<Vec<u8>, Errno>,
    ) -> Result<u64, Errno> {
        let raw = name.ok_or(EDESTADDRREQ)?;
        if raw.len() < NAME
            || u16::from_le_bytes([raw[0], raw[1]]) != AF_MCTP as u16
            || raw[2] | raw[3] | raw[11] != 0
            || raw[10] & !(TAG_MASK | TAG_OWNER | TAG_PREALLOC) != 0
            || (raw[10] & TAG_PREALLOC != 0 && raw[10] & TAG_OWNER == 0)
        {
            return Err(Errno::EINVAL);
        }
        if !capable {
            return Err(EACCES);
        }
        let net = match u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) {
            NET_ANY => DEFAULT_NET,
            net => net,
        };
        let (dest, kind, request) = (raw[8], raw[9], raw[10]);
        let ext = self.lock().ext && raw.len() >= NAME_EXT;
        // Where it goes: out of the loopback to the hardware address
        // (`mctp_dst_from_extaddr`), or through a route (`mctp_route_lookup`).
        let (mtu, out) = if ext {
            if raw[17] | raw[18] | raw[19] != 0 {
                return Err(Errno::EINVAL);
            }
            let index = i32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
            let halen = usize::from(raw[16]);
            if halen > MAX_ADDR_LEN {
                return Err(Errno::EINVAL);
            }
            if index != LO_INDEX {
                return Err(Errno::ENOENT);
            }
            if halen != LO_ADDR_LEN {
                return Err(Errno::EINVAL);
            }
            (LO_MTU, true)
        } else {
            (self.route(net, dest).ok_or(EHOSTUNREACH)?, false)
        };
        // `sock_alloc_send_skb`: the header room, the type and the bytes,
        // in a head `kmalloc` can make (`ENOBUFS`).
        let head = LL_RESERVED + HEADER + 1 + len;
        if head.next_multiple_of(64) + SHARED_INFO > KMALLOC_MAX {
            return Err(ENOBUFS);
        }
        let mut message = Vec::with_capacity(1 + len);
        message.push(kind);
        message.extend(payload()?);
        // `mctp_local_output`: from the loopback's first address
        // (`EHOSTUNREACH` for none), with a tag.
        let mut t = self.network.mctp.lock(now);
        let src = *self.network.addresses().mctp.first().ok_or(EHOSTUNREACH)?;
        let tag = if request & TAG_OWNER != 0 {
            let tag = if request & TAG_PREALLOC != 0 {
                let wanted = request & TAG_MASK;
                t.keys
                    .iter()
                    .find(|k| {
                        k.socket.ptr_eq(&self.this)
                            && k.net == DEFAULT_NET
                            && k.tag == wanted
                            && matches(k.peer, dest)
                            && k.manual
                    })
                    .map(|k| k.tag)
                    .ok_or(Errno::ENOENT)?
            } else {
                t.allocate(&self.this, DEFAULT_NET, src, dest, false, now)?
            };
            tag | TAG_OWNER
        } else {
            request & TAG_MASK
        };
        // `mctp_do_fragment_route`: packets of the MTU, each with its part
        // of the message after the header, sent on until one fails.
        if mtu < HEADER + 1 {
            return Err(EMSGSIZE);
        }
        let part = mtu - HEADER;
        let mut at = 0;
        let mut seq = 0u8;
        while at < message.len() {
            let size = part.min(message.len() - at);
            let mut flags = tag | seq << SEQ_SHIFT;
            if at == 0 {
                flags |= SOM;
            }
            if at + size == message.len() {
                flags |= EOM;
            }
            let packet = Packet {
                dest,
                src,
                flags,
                data: &message[at..at + size],
                size: truesize(LL_RESERVED + HEADER + size),
                net: DEFAULT_NET,
                ifindex: 0,
            };
            // Out of the loopback (`mctp_dst_output`), a packet is lost:
            // down, its `noop` queueing discipline drops it (`NET_XMIT_CN`,
            // which `net_xmit_errno` makes 0); up, it comes back in, but
            // `eth_type_trans` takes `ETH_P_MCTP` (0xfa), below
            // `ETH_P_802_3_MIN`, for an 802.3 length, and gives it to 802.2,
            // so MCTP never sees it. Either way the send succeeds.
            if !out {
                t.input(&packet, now)?;
            }
            seq = (seq + 1) & 3;
            at += size;
        }
        Ok(len as u64)
    }
    /// The MTU of the route to `dest` in `net`, as `mctp_route_lookup`
    /// follows gateways to a route through the loopback, the least of the
    /// MTUs on the way and the loopback's; `None` for no route.
    fn route(&self, net: u32, mut dest: u8) -> Option<usize> {
        let addresses = self.network.addresses();
        let mut mtu = 0;
        for _ in 0..ROUTE_DEPTH {
            let route = addresses
                .mctp_routes
                .iter()
                .find(|r| r.net() == net && r.min <= dest && dest <= r.max)?;
            mtu = match (mtu, route.mtu) {
                (0, m) | (m, 0) => m,
                (a, b) => a.min(b),
            };
            match route.gateway {
                None => {
                    let mtu = usize::try_from(mtu).unwrap_or(LO_MTU);
                    return Some(if mtu == 0 { LO_MTU } else { mtu.min(LO_MTU) });
                }
                Some((_, gateway)) => dest = gateway,
            }
        }
        None
    }
    /// Receives one message into `buf`, as `mctp_recvmsg`: `EAGAIN` while
    /// there is none; `peek` leaves it. The bytes copied, the message's
    /// length, and its name.
    fn receive(&self, buf: &mut [u8], peek: bool) -> Result<(usize, usize, Vec<u8>), Errno> {
        let mut s = self.lock();
        let first = s.queue.front().ok_or(Errno::EAGAIN)?;
        let length = first.bytes.len() - 1;
        let n = buf.len().min(length);
        buf[..n].copy_from_slice(&first.bytes[1..=n]);
        let mut name = vec![AF_MCTP as u8, 0, 0, 0];
        name.extend(first.net.to_le_bytes());
        name.extend([first.src, first.bytes[0], first.tag, 0]);
        if s.ext {
            name.extend(first.ifindex.to_le_bytes());
            name.extend([0; 4 + MAX_ADDR_LEN]);
        }
        if !peek {
            let size = first.size;
            s.queue.pop_front();
            s.held -= size;
        }
        Ok((n, length, name))
    }
}

impl FileHandle for MctpSocket {
    /// As `datagram_poll`: always writable, readable with a message
    /// waiting.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let s = self.lock();
        let ready = u32::from(!s.queue.is_empty()) * IN;
        Ok((OUT | ready, s.arrivals, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.receive(buf, false).map(|(n, ..)| n)
    }
    /// A send without an address, which has nowhere to go.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(EDESTADDRREQ)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            mode: self.mode.load(Ordering::SeqCst),
            uid: self.uid.load(Ordering::SeqCst),
            gid: self.gid.load(Ordering::SeqCst),
            links: 1,
            ..FileStat::default()
        })
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.mode
            .store(0o140000 | (mode & 0o7777), Ordering::SeqCst);
        Ok(())
    }
    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        if let Some(uid) = uid {
            self.uid.store(uid, Ordering::SeqCst);
        }
        if let Some(gid) = gid {
            self.gid.store(gid, Ordering::SeqCst);
        }
        Ok(())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(2 | (flags & NONBLOCK), Ordering::SeqCst);
        Ok(())
    }
}

/// The host's monotonic clock, which times the keys.
fn now(c: &Context<'_>) -> u64 {
    c.host
        .clock(paludarium_host::ClockId::Monotonic)
        .unwrap_or(0)
}

/// The system calls of an MCTP socket, `file` of descriptor `a[0]`.
pub(crate) fn dispatch(
    c: &mut Context<'_>,
    number: u64,
    a: [u64; 6],
    file: &Arc<dyn FileHandle>,
) -> Result<u64, Errno> {
    let socket = of(file).ok_or(ENOTSOCK)?;
    let credentials = &c.process.credentials;
    match number {
        42 => socket.connect(&crate::inet::read_raw(c, a[1], a[2])?),
        49 => {
            let raw = crate::inet::read_raw(c, a[1], a[2])?;
            socket.bind(&raw, credentials.capable(CAP_NET_BIND_SERVICE))
        }
        // accept4's flags are checked first.
        288 if a[3] as u32 & !(NONBLOCK | CLOEXEC) != 0 => Err(Errno::EINVAL),
        // accept, listen, shutdown, getsockname and getpeername, which
        // MCTP has not (`sock_no_*`).
        50 | 48 | 51 | 52 => Err(EOPNOTSUPP),
        54 => set_option(c, socket, a),
        55 => get_option(c, socket, a),
        44 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let name = if a[4] != 0 {
                Some(crate::inet::read_raw(c, a[4], a[5])?)
            } else {
                None
            };
            let capable = credentials.capable(CAP_NET_RAW);
            socket.send(name.as_deref(), capable, now(c), len, || {
                let mut bytes = vec![0; len];
                c.mem
                    .read(GuestAddr(a[1]), &mut bytes)
                    .map_err(|_| Errno::EFAULT)?;
                Ok(bytes)
            })
        }
        46 => {
            if a[2] & MSG_CMSG_COMPAT != 0 {
                return Err(Errno::EINVAL);
            }
            let header = crate::sockets::message_header(c, a[1], false)?;
            let name = match header.name {
                Some((at, len)) => Some(crate::inet::read_raw(c, at, len as u64)?),
                None => None,
            };
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let capable = credentials.capable(CAP_NET_RAW);
            socket.send(name.as_deref(), capable, now(c), total, || {
                let mut bytes = Vec::new();
                bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
                for &(base, len) in &header.iov {
                    let start = bytes.len();
                    bytes.resize(start + len, 0);
                    c.mem
                        .read(GuestAddr(base), &mut bytes[start..])
                        .map_err(|_| Errno::EFAULT)?;
                }
                Ok(bytes)
            })
        }
        45 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let mut bytes = Vec::new();
            bytes.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(len, 0);
            let (n, length, name) = receive(c, file, socket, &mut bytes, a[3])?;
            c.mem
                .write(GuestAddr(a[1]), &bytes[..n])
                .map_err(|_| Errno::EFAULT)?;
            if a[4] != 0 {
                crate::inet::write_address(c, &name, a[4], a[5])?;
            }
            Ok(returned(n, length, a[3]))
        }
        47 => {
            if a[2] & MSG_CMSG_COMPAT != 0 {
                return Err(Errno::EINVAL);
            }
            let header = crate::sockets::message_header(c, a[1], true)?;
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(total, 0);
            let (n, length, name) = receive(c, file, socket, &mut bytes, a[2])?;
            crate::files::scatter(c, &header.iov, &bytes[..n])?;
            if header.has_name {
                if let Some((at, room)) = header.name {
                    let n = room.min(name.len());
                    c.mem
                        .write(GuestAddr(at), &name[..n])
                        .map_err(|_| Errno::EFAULT)?;
                }
                c.mem
                    .write(GuestAddr(a[1] + 8), &(name.len() as u32).to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
            }
            let flags = if length > n { MSG_TRUNC as u32 } else { 0 };
            c.mem
                .write(GuestAddr(a[1] + 40), &0u64.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            c.mem
                .write(GuestAddr(a[1] + 48), &flags.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            Ok(returned(n, length, a[2]))
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// What a receive returns: with `MSG_TRUNC`, the message's whole length.
fn returned(n: usize, length: usize, flags: u64) -> u64 {
    (if flags & MSG_TRUNC != 0 { length } else { n }) as u64
}
/// Receives for recvfrom or recvmsg, waiting unless `MSG_DONTWAIT` or the
/// socket's `O_NONBLOCK` says not to, no longer than `SO_RCVTIMEO`. Flags
/// but those and `MSG_TRUNC` and `MSG_PEEK` are `EOPNOTSUPP`.
fn receive(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &MctpSocket,
    buf: &mut [u8],
    flags: u64,
) -> Result<(usize, usize, Vec<u8>), Errno> {
    if flags & 0xffff_ffff & !(MSG_DONTWAIT | MSG_TRUNC | MSG_PEEK) != 0 {
        return Err(EOPNOTSUPP);
    }
    let dontwait = flags & MSG_DONTWAIT != 0 || socket.nonblocking();
    let timeout = socket.lock().receive_timeout;
    let wait = crate::sockets::wait_for(c, timeout)?;
    crate::files::wait_for_read_until(c, file, dontwait, wait, || {
        socket.receive(buf, flags & MSG_PEEK != 0)
    })
}
/// Reads the `int` of a setsockopt (`EINVAL` for fewer than 4 bytes).
fn option_int(c: &Context<'_>, at: u64, len: u64) -> Result<i32, Errno> {
    if (len as u32 as i32) < 4 {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    Ok(i32::from_le_bytes(raw))
}
/// `setsockopt`: `SO_SNDBUF` and `SO_RCVBUF` (doubled, as Linux keeps
/// them), `SO_RCVTIMEO`, and `SOL_MCTP`'s `MCTP_OPT_ADDR_EXT` of an `int`
/// exactly (`EINVAL`), as `mctp_setsockopt`, which takes no other level
/// (`EINVAL`). Any other option is `ENOPROTOOPT`.
fn set_option(c: &mut Context<'_>, socket: &MctpSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len) = (a[1] as u32 as u64, a[2] as u32 as u64, a[3], a[4]);
    match (level, name) {
        (SOL_SOCKET, 20 | 66) => {
            if (len as u32 as i32) < 16 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 16];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let word = |i: usize| i64::from_le_bytes(raw[i..i + 8].try_into().unwrap_or_default());
            socket.lock().receive_timeout = Timeout::from_timeval(word(0), word(8))?;
        }
        (SOL_SOCKET, 7 | 8) => {
            let value = option_int(c, at, len)?.clamp(0, BUFFER_MAX);
            let mut s = socket.lock();
            if name == 7 {
                s.send_buffer = (value * 2).max(MIN_SEND_BUFFER);
            } else {
                s.receive_buffer = (value * 2).max(MIN_RECEIVE_BUFFER);
            }
        }
        (SOL_SOCKET, _) => return Err(ENOPROTOOPT),
        (SOL_MCTP, MCTP_OPT_ADDR_EXT) => {
            if len as u32 != 4 {
                return Err(Errno::EINVAL);
            }
            let on = option_int(c, at, len)? != 0;
            socket.lock().ext = on;
        }
        (SOL_MCTP, _) => return Err(ENOPROTOOPT),
        _ => return Err(Errno::EINVAL),
    }
    Ok(0)
}
/// `getsockopt`: what [`set_option`] keeps, and `SO_TYPE`, `SO_ERROR`,
/// `SO_PROTOCOL` and `SO_DOMAIN`. `MCTP_OPT_ADDR_EXT` wants room for an
/// `int` exactly (`EINVAL`) and writes no length, as `mctp_getsockopt`.
fn get_option(c: &mut Context<'_>, socket: &MctpSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len_at) = (a[1] as u32 as u64, a[2] as u32 as u64, a[3], a[4]);
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let len = i32::from_le_bytes(raw);
    if level == SOL_MCTP {
        if name != MCTP_OPT_ADDR_EXT {
            return Err(ENOPROTOOPT);
        }
        if len != 4 {
            return Err(Errno::EINVAL);
        }
        let on = i32::from(socket.lock().ext);
        c.mem
            .write(GuestAddr(at), &on.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
        return Ok(0);
    }
    if level != SOL_SOCKET {
        return Err(Errno::EINVAL);
    }
    let room = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    let value: Vec<u8> = {
        let s = socket.lock();
        match name {
            20 | 66 => s.receive_timeout.timeval().to_vec(),
            3 => (SOCK_DGRAM as i32).to_le_bytes().to_vec(),
            4 | 38 => 0i32.to_le_bytes().to_vec(),
            7 => s.send_buffer.to_le_bytes().to_vec(),
            8 => s.receive_buffer.to_le_bytes().to_vec(),
            39 => (AF_MCTP as i32).to_le_bytes().to_vec(),
            _ => return Err(ENOPROTOOPT),
        }
    };
    let n = room.min(value.len());
    c.mem
        .write(GuestAddr(at), &value[..n])
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(len_at), &(n as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// An `ioctl` of an MCTP socket, as `mctp_ioctl`: the tag requests, and
/// `EINVAL` for any other that `sock_ioctl` does not answer for every
/// socket; `None` for those.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    cmd: u64,
    arg: u64,
) -> Option<Result<u64, Errno>> {
    let socket = of(file)?;
    let cmd = cmd as u32;
    // `SIOCDEVPRIVATE` and the wireless extensions' too.
    if SOCKET_IOCTLS.contains(&cmd)
        || (0x89f0..=0x89ff).contains(&cmd)
        || (0x8b00..=0x8bff).contains(&cmd)
    {
        return None;
    }
    Some(match cmd {
        SIOCMCTPALLOCTAG | SIOCMCTPALLOCTAG2 => {
            allocate_tag(c, socket, cmd == SIOCMCTPALLOCTAG2, arg)
        }
        SIOCMCTPDROPTAG | SIOCMCTPDROPTAG2 => drop_tag(c, socket, cmd == SIOCMCTPDROPTAG2, arg),
        _ => Err(Errno::EINVAL),
    })
}
/// A tag request (`struct mctp_ioc_tag_ctl2`, or the older
/// `mctp_ioc_tag_ctl` of the default network): its bytes, network, peer and
/// tag, as `mctp_ioctl_tag_copy_from_user` reads and checks it: no flags
/// and a local ID of `MCTP_ADDR_ANY` or `MCTP_ADDR_NULL` (`EINVAL`).
fn tag_request(c: &Context<'_>, v2: bool, arg: u64) -> Result<(Vec<u8>, u32, u8, u8), Errno> {
    let mut raw = vec![0; if v2 { 12 } else { 4 }];
    c.mem
        .read(GuestAddr(arg), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let (net, peer, local, flags, tag) = if v2 {
        let net = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        (
            net,
            raw[4],
            raw[5],
            u16::from_le_bytes([raw[6], raw[7]]),
            raw[8],
        )
    } else {
        (
            DEFAULT_NET,
            raw[0],
            ANY,
            u16::from_le_bytes([raw[2], raw[3]]),
            raw[1],
        )
    };
    if flags != 0 || (local != ANY && local != NULL) {
        return Err(Errno::EINVAL);
    }
    Ok((raw, net, peer, tag))
}
/// `SIOCMCTPALLOCTAG`, as `mctp_ioctl_alloctag`: a tag the socket owns for
/// the peer, kept until it is dropped, written back with `MCTP_TAG_OWNER`
/// and `MCTP_TAG_PREALLOC`.
fn allocate_tag(
    c: &mut Context<'_>,
    socket: &MctpSocket,
    v2: bool,
    arg: u64,
) -> Result<u64, Errno> {
    let (mut raw, net, peer, tag) = tag_request(c, v2, arg)?;
    if tag != 0 {
        return Err(Errno::EINVAL);
    }
    let now = now(c);
    let tag = socket
        .network
        .mctp
        .lock(now)
        .allocate(&socket.this, net, ANY, peer, true, now)?;
    raw[if v2 { 8 } else { 1 }] = tag | TAG_OWNER | TAG_PREALLOC;
    // Copied out with the keys' lock let go: the copy may wait for a
    // `userfaultfd`.
    if c.mem.write(GuestAddr(arg), &raw).is_err() {
        // Its own key, which no other of the peer has the tag of.
        let peer = if peer == NULL { ANY } else { peer };
        socket.network.mctp.lock(now).keys.retain(|k| {
            !(k.socket.ptr_eq(&socket.this)
                && k.manual
                && k.net == net
                && k.peer == peer
                && k.tag == tag)
        });
        return Err(Errno::EFAULT);
    }
    Ok(0)
}
/// `SIOCMCTPDROPTAG`, as `mctp_ioctl_droptag`: drops the socket's tags made
/// by hand for the network, peer and tag (`EINVAL` for none, or for a tag
/// not so made).
fn drop_tag(c: &mut Context<'_>, socket: &MctpSocket, v2: bool, arg: u64) -> Result<u64, Errno> {
    let (_, net, peer, tag) = tag_request(c, v2, arg)?;
    if tag & !TAG_MASK != TAG_OWNER | TAG_PREALLOC {
        return Err(Errno::EINVAL);
    }
    let peer = if peer == NULL { ANY } else { peer };
    let mut t = socket.network.mctp.lock(now(c));
    let before = t.keys.len();
    t.keys.retain(|k| {
        !(k.socket.ptr_eq(&socket.this)
            && k.manual
            && k.net == net
            && k.peer == peer
            && k.tag == tag & TAG_MASK)
    });
    if t.keys.len() == before {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_sizes_are_linuxs() {
        // hash_32(1 | 9 << 8 | 0xff << 16, 7).
        assert_eq!(
            bucket(1, 9, 0xff),
            (0x00ff_0901u32.wrapping_mul(0x61c8_8647)) >> 25
        );
        assert_eq!(truesize(21 + 5), 960);
        assert_eq!(truesize(21 + 363), 960);
        assert_eq!(truesize(21 + 364), 1280);
        assert_eq!(truesize(20 + 65532), 256 + 131_072);
    }

    /// A table with a socket bound to `bind`, and that socket.
    fn bound(t: &mut Table, bind: Bind, socket: &Arc<MctpSocket>) {
        let peer = bind.peer.map_or(ANY, |(_, p)| p);
        t.binds
            .entry(bucket(bind.kind, bind.local, peer))
            .or_default()
            .insert(0, (bind, Arc::downgrade(socket)));
    }
    fn socket(network: &Arc<Network>) -> Arc<MctpSocket> {
        Arc::new_cyclic(|this| MctpSocket {
            this: Weak::clone(this),
            network: Arc::clone(network),
            hub: Arc::new(ReadinessHub::default()),
            flags: AtomicU32::new(2),
            inode: 1,
            mode: AtomicU32::new(0o140777),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            state: Mutex::new(State {
                receive_buffer: BUFFER_DEFAULT,
                send_buffer: BUFFER_DEFAULT,
                ..State::default()
            }),
        })
    }

    #[test]
    fn messages_find_binds_keys_and_reassemble() {
        let network = Arc::new(Network::isolated(crate::users::first()));
        let (any, nine) = (socket(&network), socket(&network));
        let mut t = Table::default();
        bound(
            &mut t,
            Bind {
                kind: 1,
                local: ANY,
                net: NET_ANY,
                peer: None,
            },
            &any,
        );
        bound(
            &mut t,
            Bind {
                kind: 1,
                local: 9,
                net: 1,
                peer: None,
            },
            &nine,
        );
        let packet = |dest, flags, data: &'static [u8]| Packet {
            dest,
            src: 8,
            flags,
            data,
            size: truesize(LL_RESERVED + HEADER + 1),
            net: 1,
            ifindex: 0,
        };
        // The bind of the endpoint ID first, then the one of any.
        assert_eq!(
            t.input(&packet(9, SOM | EOM | TAG_OWNER, b"\x01a"), 0),
            Ok(())
        );
        assert_eq!(nine.lock().queue.len(), 1);
        assert_eq!(
            t.input(&packet(10, SOM | EOM | TAG_OWNER, b"\x01b"), 0),
            Ok(())
        );
        assert_eq!(any.lock().queue.len(), 1);
        // No bind of the type, and no key of a tag the sender does not own.
        assert_eq!(
            t.input(&packet(9, SOM | EOM | TAG_OWNER, b"\x02c"), 0),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            t.input(&packet(9, SOM | EOM, b"\x01c"), 0),
            Err(Errno::ENOENT)
        );
        // Three packets, the sequence numbers following on; a wrong one
        // is dropped, and the message waits on.
        assert_eq!(
            t.input(&packet(9, SOM | TAG_OWNER | 1, b"\x01x"), 0),
            Ok(())
        );
        assert_eq!(
            t.input(&packet(9, TAG_OWNER | 1 | 2 << SEQ_SHIFT, b"y"), 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            t.input(&packet(9, TAG_OWNER | 1 | 1 << SEQ_SHIFT, b"y"), 0),
            Ok(())
        );
        assert_eq!(
            t.input(&packet(9, EOM | TAG_OWNER | 1 | 2 << SEQ_SHIFT, b"z"), 0),
            Ok(())
        );
        let s = nine.lock();
        assert_eq!(
            s.queue.back().map(|m| m.bytes.clone()),
            Some(b"\x01xyz".to_vec())
        );
        assert_eq!(s.held, 960 * 4);
        drop(s);
        assert!(t.keys.is_empty());
        // Eight tags for a peer, then none; an answer to one frees it.
        let weak = Arc::downgrade(&any);
        for tag in 0..8 {
            assert_eq!(t.allocate(&weak, 1, 8, 9, false, 0), Ok(tag));
        }
        assert_eq!(t.allocate(&weak, 1, 8, 9, false, 0), Err(EBUSY));
        let answer = Packet {
            dest: 8,
            src: 9,
            ..packet(8, SOM | EOM | 3, b"\x01r")
        };
        assert_eq!(t.input(&answer, 0), Ok(()));
        assert_eq!(t.allocate(&weak, 1, 8, 9, false, 0), Ok(3));
        // Keys run out after six seconds.
        let lock = Endpoints(Mutex::new(t));
        assert_eq!(lock.lock(KEY_LIFETIME).keys.len(), 8);
        assert!(lock.lock(KEY_LIFETIME + 1).keys.is_empty());
    }

    #[test]
    fn a_full_receive_buffer_refuses() {
        let network = Arc::new(Network::isolated(crate::users::first()));
        let socket = socket(&network);
        socket.lock().receive_buffer = MIN_RECEIVE_BUFFER;
        let message = || Message {
            bytes: vec![1],
            net: 1,
            src: 8,
            tag: 8,
            ifindex: 0,
            size: truesize(LL_RESERVED + HEADER + 1),
        };
        for _ in 0..3 {
            assert_eq!(socket.queue(message()), Ok(()));
        }
        assert_eq!(socket.queue(message()), Err(Errno::ENOMEM));
    }
}
