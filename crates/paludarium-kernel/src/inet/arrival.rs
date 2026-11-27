//! What a UDP socket's filter sees of a datagram as it comes, and a TCP
//! socket's of a segment
//! (`sk_filter_trim_cap` from `udp_queue_rcv_one_skb` and
//! `udpv6_queue_rcv_one_skb`): the `sk_buff` that x86-64 Linux 7.0 makes
//! of it as it is sent (`ip_make_skb`, `ip6_make_skb`) and as it comes
//! through the loopback or a veth pair, with `skb->data` at the UDP header
//! and the IP header before it.

use crate::bpf_interp::{Packet, Skb};
use crate::loopback::segments::{Segment, Tap};
use crate::loopback::{Link, Names};
// `SKB_MAX_ALLOC`: past it `__ip_append_data` puts the bytes in pages.
use crate::skb::MAX_ALLOC;
use crate::sockets::Filter;
use core::net::{IpAddr, SocketAddr};
use paludarium_host::net::Stream;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock, Weak};

/// `ARPHRD_ETHER` and `ARPHRD_LOOPBACK`, a device's type.
const ETHER: u16 = 1;
const LOOPBACK: u16 = 772;
/// `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST` and
/// `PACKET_LOOPBACK`.
const HOST: u32 = 0;
const BROADCAST: u32 = 1;
const MULTICAST: u32 = 2;
const LOOPED: u32 = 5;
/// The loopback's index (`LOOPBACK_IFINDEX`) and MTU.
const LO_INDEX: u32 = 1;
const LO_MTU: usize = 65_536;
/// `sysctl_ip_default_ttl` and IPv6's `hop_limit`.
pub(super) const HOPS: u8 = 64;
/// `IPPROTO_UDP` and `IPPROTO_TCP`.
const UDP: u8 = 17;
const TCP: u8 = 6;
/// The UDP header's length, which `sk_filter_trim_cap` keeps
/// (`sizeof(struct udphdr)`).
pub(super) const UDP_HEADER: usize = 8;

/// A datagram as it is sent.
#[derive(Clone)]
pub(super) struct Sent {
    /// The source and destination as they go on the wire: IPv4 for an
    /// IPv4-mapped address.
    pub(super) from: SocketAddr,
    pub(super) to: SocketAddr,
    /// `IP_TOS`, of an IPv4 datagram.
    pub(super) tos: u8,
    /// A connected socket's IPv4 ID (`inet_id`, `ip_select_ident_segs`);
    /// `None` for one with no peer, whose ID `__ip_select_ident` hashes from
    /// a secret, as it does for `IP_PMTUDISC_WANT`'s `ignore_df`: drawn at
    /// random here, once for every copy.
    pub(super) id: Option<u16>,
    drawn: OnceLock<u16>,
    /// `skb->hash`: a connected socket's `sk_txhash`
    /// (`skb_set_owner_w`), else for IPv6 the flow's hash, which the auto
    /// flow label takes (`ip6_make_flowlabel`), else 0.
    pub(super) hash: u32,
    /// `sk_priority`.
    pub(super) priority: u32,
    /// The sending task's real user and group IDs: the receive runs in
    /// its context, in the softirq that the send raises.
    pub(super) ids: (u32, u32),
    /// Its time to live, or hop limit.
    pub(super) ttl: u8,
}

/// What a SYN, or the SYN-ACK that acknowledges it, goes with: its sequence
/// number, what it acknowledges, its timestamp and the one it echoes.
#[derive(Clone, Copy)]
pub(super) struct Shake {
    seq: u32,
    ack: Option<u32>,
    stamps: (u32, u32),
}
impl Shake {
    /// A SYN at `now`, in microseconds.
    pub(super) fn syn(names: &Names, now: u64) -> Self {
        Self {
            seq: names.first[0],
            ack: None,
            stamps: (names.stamp(0, now), 0),
        }
    }
    /// The SYN-ACK at `now`, in microseconds, of a SYN that went at `echo`.
    pub(super) fn answer(names: &Names, now: u64, echo: u64) -> Self {
        Self {
            seq: names.first[1],
            ack: Some(names.first[0].wrapping_add(1)),
            stamps: (names.stamp(1, now), names.stamp(0, echo)),
        }
    }
}

/// How a datagram comes to a socket.
#[derive(Clone, Copy)]
pub(super) enum Way {
    /// Through the loopback, to an address of this namespace.
    Loopback,
    /// In through the veth end `index` of the peer's namespace, from the
    /// Ethernet address `src` to `dst`, out through an end of MTU `mtu`.
    Veth {
        index: u32,
        src: [u8; 6],
        dst: [u8; 6],
        mtu: usize,
    },
    /// A broadcast's or a group's copy that `ip_mc_output` loops back on the sending
    /// veth end `index` (`dev_loopback_xmit`), of MTU `mtu`.
    Looped { index: u32, mtu: usize },
}

impl Way {
    /// The MTU of the device it comes through.
    fn mtu(self) -> usize {
        match self {
            Way::Loopback => LO_MTU,
            Way::Veth { mtu, .. } | Way::Looped { mtu, .. } => mtu,
        }
    }
}

impl Sent {
    pub(super) fn new(
        from: SocketAddr,
        to: SocketAddr,
        tos: u8,
        id: Option<u16>,
        hash: u32,
        priority: u32,
        ids: (u32, u32),
    ) -> Self {
        Self {
            from,
            to,
            tos,
            id,
            drawn: OnceLock::new(),
            hash,
            priority,
            ids,
            ttl: HOPS,
        }
    }

    /// Runs `filter` on `payload` as it comes `way` to a socket: how many
    /// of its bytes the socket keeps, or `None` when the filter drops it.
    /// A filter's result keeps that many bytes from the UDP header on, and
    /// the header always (`pskb_trim` to `max(cap, pkt_len)`).
    pub(super) fn filter(
        &self,
        filter: &Filter,
        payload: &[u8],
        way: Way,
        host: &Arc<dyn paludarium_host::Host>,
    ) -> Option<usize> {
        let v4 = self.from.is_ipv4();
        let mtu = way.mtu();
        let ip = if v4 { 20 } else { 40 };
        let fragmented = ip + UDP_HEADER + payload.len() > mtu;
        let data = self.udp(payload, fragmented);
        let linear = linear(payload.len(), v4, mtu);
        self.run(
            filter,
            &data,
            (UDP, UDP_HEADER, !fragmented),
            (linear, (0, 0)),
            way,
            host,
        )
    }

    /// Runs the listener's `filter` on the SYN of a connection to it that
    /// came `way`, with a receive window of `window` bytes and an MSS of
    /// `mss`: whether the filter keeps it (`tcp_filter` in `tcp_v4_rcv`
    /// and `tcp_v6_rcv`, before `tcp_v4_do_rcv` takes it). Or the
    /// client's on the SYN-ACK, as `shake` says.
    pub(super) fn syn_kept(
        &self,
        filter: &Filter,
        way: Way,
        window: (u16, u16, u8),
        shake: Shake,
        host: &Arc<dyn paludarium_host::Host>,
    ) -> bool {
        let data = self.syn(window, shake);
        let len = data.len();
        self.run(filter, &data, (TCP, len, true), (len, (1, 0)), way, host)
            .is_some()
    }

    /// Runs `filter` on the transport header and payload `data`, of
    /// protocol `proto`, whose first `cap` bytes it always keeps
    /// (`pskb_trim` to `max(cap, pkt_len)`), `DF` set when it goes `whole`,
    /// `linear` of its bytes in the linear part and `gso` its segments and
    /// their size, as it came `way`: how many bytes past `cap` it keeps, or `None` when it drops it.
    fn run(
        &self,
        filter: &Filter,
        data: &[u8],
        (proto, cap, whole): (u8, usize, bool),
        (linear, gso): (usize, (u32, u32)),
        way: Way,
        host: &Arc<dyn paludarium_host::Host>,
    ) -> Option<usize> {
        let v4 = self.from.is_ipv4();
        let (mut headers, kind, index) = match way {
            Way::Loopback => (ethernet([0; 6], [0; 6], v4), LOOPBACK, LO_INDEX),
            Way::Veth {
                index, src, dst, ..
            } => (ethernet(dst, src, v4), ETHER, index),
            // `dev_loopback_xmit` sets the MAC header where the network
            // header is.
            Way::Looped { index, .. } => (Vec::new(), ETHER, index),
        };
        let network = headers.len();
        if v4 {
            let id = self.id.unwrap_or_else(|| {
                *self.drawn.get_or_init(|| {
                    let mut b = [0; 2];
                    let _ = host.random_bytes(&mut b);
                    u16::from_le_bytes(b)
                })
            });
            headers.extend(self.ipv4(proto, data.len(), id, whole));
        } else {
            headers.extend(self.ipv6(proto, data.len()));
        }
        let skb = Skb {
            pkt_type: match way {
                Way::Loopback => HOST,
                Way::Veth { dst, .. } if dst == [0xff; 6] => BROADCAST,
                // `eth_type_trans`: a group's address has its low bit set.
                Way::Veth { dst, .. } if dst[0] & 1 != 0 => MULTICAST,
                Way::Veth { .. } => HOST,
                Way::Looped { .. } => LOOPED,
            },
            mark: 0,
            // `____dev_forward_skb` clears it.
            priority: match way {
                Way::Veth { .. } => 0,
                _ => self.priority,
            },
            protocol: if v4 { [0x08, 0x00] } else { [0x86, 0xdd] },
            ingress_ifindex: index,
            hash: self.hash,
            device: Some((index, kind)),
            payload_offset: cap as u32,
            gso,
            cb: [0; 20],
        };
        let packet = Packet {
            linear,
            data,
            headers: &headers,
            mac: Some(0),
            network,
            skb,
        };
        let mut kernel = crate::bpf_prog::Receiving {
            host: Some(host),
            uid: self.ids.0,
            gid: self.ids.1,
            socket: filter.socket.clone(),
            owner: filter.owner,
        };
        match filter.program.run(&packet, &mut kernel) {
            0 => None,
            keep => Some((keep as usize).max(cap).min(data.len()) - cap),
        }
    }

    /// The UDP header and `payload`. Its checksum is the pseudo-header's
    /// alone, as the loopback and veth take it to the device
    /// (`CHECKSUM_PARTIAL`, `udp4_hwcsum`, `udp6_hwcsum_outgoing`), or for
    /// a datagram that goes in fragments the whole one (`udp_csum`), which
    /// is never 0 (`CSUM_MANGLED_0`).
    fn udp(&self, payload: &[u8], full: bool) -> Vec<u8> {
        let len = UDP_HEADER + payload.len();
        let mut data = Vec::with_capacity(len);
        data.extend(self.from.port().to_be_bytes());
        data.extend(self.to.port().to_be_bytes());
        data.extend((len as u16).to_be_bytes());
        data.extend([0, 0]);
        data.extend(payload);
        let sum = self.pseudo(UDP, len);
        let check = if full {
            match !fold(add(sum, &data)) {
                0 => 0xffff,
                c => c,
            }
        } else {
            fold(sum)
        };
        data[6..8].copy_from_slice(&check.to_be_bytes());
        data
    }

    /// The one's complement sum of the pseudo-header of `len` bytes of
    /// protocol `proto` from its source to its destination.
    fn pseudo(&self, proto: u8, len: usize) -> u32 {
        match (self.from.ip(), self.to.ip()) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                let sum = add(add(0, &from.octets()), &to.octets());
                add(add(sum, &[0, proto]), &(len as u16).to_be_bytes())
            }
            (from, to) => {
                let sum = add(add(0, &v6(from)), &v6(to));
                add(add(sum, &(len as u32).to_be_bytes()), &[0, 0, 0, proto])
            }
        }
    }

    /// A connection's SYN (`tcp_connect`) or SYN-ACK
    /// (`tcp_make_synack`): the first sequence number, the window `window`,
    /// unscaled, and `tcp_syn_options`' options in `tcp_options_write`'s
    /// order, MSS `mss`, SACK permitted with the timestamps, and the window
    /// scale `wscale`.
    /// Its checksum is the pseudo-header's (`CHECKSUM_PARTIAL`,
    /// `__tcp_v4_send_check`).
    fn syn(&self, (window, mss, wscale): (u16, u16, u8), shake: Shake) -> Vec<u8> {
        let mut h = Vec::with_capacity(40);
        h.extend(self.from.port().to_be_bytes());
        h.extend(self.to.port().to_be_bytes());
        h.extend(shake.seq.to_be_bytes());
        h.extend(shake.ack.unwrap_or(0).to_be_bytes());
        // 40 bytes (`doff` 10), and SYN, with ACK in the answer.
        h.extend([0xa0, if shake.ack.is_some() { 0x12 } else { 0x02 }]);
        h.extend(window.to_be_bytes());
        h.extend([0, 0, 0, 0]);
        h.extend([2, 4]);
        h.extend(mss.to_be_bytes());
        h.extend([4, 2, 8, 10]);
        h.extend(shake.stamps.0.to_be_bytes());
        h.extend(shake.stamps.1.to_be_bytes());
        h.extend([1, 3, 3, wscale]);
        let check = fold(self.pseudo(TCP, h.len()));
        h[16..18].copy_from_slice(&check.to_be_bytes());
        h
    }

    /// The IPv4 header of a packet of protocol `proto` and `len` bytes from
    /// its transport header on, `DF` set when it goes whole
    /// (`IP_PMTUDISC_WANT`).
    fn ipv4(&self, proto: u8, len: usize, id: u16, whole: bool) -> Vec<u8> {
        let (IpAddr::V4(from), IpAddr::V4(to)) = (self.from.ip(), self.to.ip()) else {
            unreachable!("an IPv4 datagram has IPv4 addresses");
        };
        let mut h = vec![0x45, self.tos];
        h.extend(((20 + len) as u16).to_be_bytes());
        h.extend(id.to_be_bytes());
        h.extend(if whole { [0x40, 0] } else { [0, 0] });
        h.extend([self.ttl, proto, 0, 0]);
        h.extend(from.octets());
        h.extend(to.octets());
        let check = !fold(add(0, &h));
        h[10..12].copy_from_slice(&check.to_be_bytes());
        h
    }

    /// The IPv6 header of a packet of protocol `proto` and `len` bytes from
    /// its transport header on: no traffic class, and the auto flow label of
    /// its hash.
    fn ipv6(&self, proto: u8, len: usize) -> Vec<u8> {
        let label = self.hash.rotate_left(16) & 0xf_ffff;
        let mut h = label.to_be_bytes().to_vec();
        h[0] = 0x60;
        h.extend((len as u16).to_be_bytes());
        h.extend([proto, self.ttl]);
        h.extend(v6(self.from.ip()));
        h.extend(v6(self.to.ip()));
        h
    }
}

/// The filter of a connected TCP socket, which each segment that comes to
/// it passes.
pub(super) struct Listening {
    pub(super) filter: Filter,
    /// What is the same of every segment: the addresses and hash.
    pub(super) sent: Sent,
    pub(super) way: Way,
    /// The side that sends, its stream, and the window scale it offers.
    pub(super) from: usize,
    pub(super) stream: Weak<Stream>,
    pub(super) link: Weak<Link>,
    pub(super) wscale: u8,
    /// The window, MSS and window scale of a SYN-ACK.
    pub(super) syn: (u16, u16, u8),
    pub(super) names: Names,
    pub(super) id: AtomicU16,
    pub(super) host: Arc<dyn paludarium_host::Host>,
}

impl Tap for Listening {
    fn keep(&self, segment: &Segment<'_>) -> Option<u32> {
        let mut data = if segment.syn {
            let shake = Shake::answer(&self.names, segment.at, segment.echo);
            self.sent.syn(self.syn, shake)
        } else {
            self.header(segment)
        };
        let header = data.len();
        self.payload(segment, &mut data);
        let segments = match segment {
            // `tcp_v4_send_reset`'s is no connection's.
            Segment {
                reset: true, at: 0, ..
            } => 0,
            _ => segment.segments,
        };
        let size = if segments > 1 { segment.mss } else { 0 };
        let mut sent = self.sent.clone();
        if let Some(link) = self.link.upgrade() {
            let sender = link.sender(self.from);
            sent.priority = sender.priority;
            sent.tos = sender.tos;
            sent.ids = sender.ids;
        }
        // `ip_select_ident_segs`.
        let step = segments.max(1) as u16;
        sent.id = Some(self.id.fetch_add(step, Ordering::Relaxed));
        let kept = sent.run(
            &self.filter,
            &data,
            (TCP, header, true),
            (header, (segments, size)),
            self.way,
            &self.host,
        )?;
        Some(kept as u32)
    }
}

impl Listening {
    /// The segment's TCP header (`__tcp_transmit_skb`,
    /// `tcp_options_write`), its checksum the pseudo-header's.
    fn header(&self, segment: &Segment<'_>) -> Vec<u8> {
        let (from, to) = (self.from, 1 - self.from);
        // The SYN takes a sequence number.
        let seq = |side: usize, at: u64| {
            self.names.first[side]
                .wrapping_add(1)
                .wrapping_add(at as u32)
        };
        let bare = segment.reset && segment.at == 0;
        let mut h = Vec::with_capacity(60);
        h.extend(self.sent.from.port().to_be_bytes());
        h.extend(self.sent.to.port().to_be_bytes());
        h.extend(seq(from, segment.start).to_be_bytes());
        let (ack, window) = if bare {
            (0, 0)
        } else {
            // `__tcp_select_window` rounds up to what the scale tells.
            let window = segment.window.div_ceil(1 << self.wscale).min(65_535);
            (seq(to, segment.ack), window as u16)
        };
        h.extend(ack.to_be_bytes());
        let urgent = segment
            .urgent
            .and_then(|end| u16::try_from(end - segment.start).ok());
        let mut flags = if bare { 0 } else { 0x10 };
        for (set, flag) in [
            (segment.fin, 1),
            (segment.reset, 4),
            (segment.push && segment.len > 0, 8),
            (urgent.is_some(), 0x20),
        ] {
            flags |= if set { flag } else { 0 };
        }
        h.extend([0, flags]);
        h.extend(window.to_be_bytes());
        h.extend([0, 0]);
        h.extend(urgent.unwrap_or(0).to_be_bytes());
        if !bare {
            h.extend([1, 1, 8, 10]);
            h.extend(self.names.stamp(from, segment.at).to_be_bytes());
            h.extend(self.names.stamp(to, segment.echo).to_be_bytes());
            if !segment.sacks.is_empty() {
                h.extend([1, 1, 5, 2 + 8 * segment.sacks.len() as u8]);
                for &(start, end) in segment.sacks {
                    h.extend(seq(to, start).to_be_bytes());
                    h.extend(seq(to, end).to_be_bytes());
                }
            }
        }
        h[12] = (h.len() as u8 / 4) << 4;
        let len = h.len() + segment.len as usize;
        let check = fold(self.sent.pseudo(TCP, len));
        h[16..18].copy_from_slice(&check.to_be_bytes());
        h
    }

    /// The segment's bytes: those the sender's buffer still holds, and
    /// before them, of one sent again, those that left it.
    fn payload(&self, segment: &Segment<'_>, data: &mut Vec<u8>) {
        let mut len = segment.len as usize;
        let before = segment.moved.saturating_sub(segment.start) as usize;
        if before > 0 {
            // What left it before any filter looked is not kept.
            let lost = before.saturating_sub(segment.behind.len()).min(len);
            data.extend(core::iter::repeat_n(0, lost));
            let held = before - before.saturating_sub(segment.behind.len());
            let take = held.min(len - lost);
            data.extend(
                segment
                    .behind
                    .iter()
                    .skip(segment.behind.len() - held)
                    .take(take),
            );
            len -= lost + take;
        }
        if len > 0
            && let Some(stream) = self.stream.upgrade()
        {
            let at = segment.start.saturating_sub(segment.moved) as usize;
            data.extend(stream.waiting(at, len));
        }
    }
}

impl super::Network {
    /// The Ethernet address and MTU of the peer of its veth end `index`.
    fn peer_link(&self, index: i32) -> ([u8; 6], usize) {
        let peer = self
            .devices()
            .by_index(index)
            .and_then(|d| d.veth.as_ref()?.peer.clone());
        peer.and_then(|peer| Some(peer.network.upgrade()?.veth_link(peer.index)))
            .unwrap_or(([0; 6], LO_MTU))
    }

    /// How packets between this namespace's `local` address and `peer`
    /// come to `local`.
    pub(super) fn way(&self, local: IpAddr, peer: SocketAddr, now: Option<u64>) -> Way {
        let here = match peer.ip() {
            IpAddr::V4(ip) => self.addresses_at(now).is_local4(ip),
            ip @ IpAddr::V6(v6) => v6.is_loopback() || self.local_device(ip, now) != 0,
        };
        let index = self.arrival_device(SocketAddr::new(local, 0), now);
        if here || index == crate::netdev::LOOPBACK_OIF {
            return Way::Loopback;
        }
        let (dst, _) = self.veth_link(index.cast_signed());
        let (src, mtu) = self.peer_link(index.cast_signed());
        Way::Veth {
            index,
            src,
            dst,
            mtu,
        }
    }

    /// The Ethernet address and MTU of its veth end `index`, if it has one.
    pub(super) fn veth_link(&self, index: i32) -> ([u8; 6], usize) {
        self.devices()
            .by_index(index)
            .and_then(|d| d.veth.as_ref())
            .map_or(([0; 6], LO_MTU), |v| (v.mac, v.mtu as usize))
    }
}

/// The window, MSS and window scale of a connection's SYN that comes
/// `way`, from a socket of receive buffer `rcvbuf` (`tcp_connect_init`):
/// the MSS is the
/// device's MTU less the headers (`ipv4_default_advmss`, at most 65,495;
/// `ip6_default_advmss`), and the window is what half the buffer holds
/// (`tcp_full_space`, at `TCP_DEFAULT_SCALING_RATIO`), rounded down to
/// the MSS (`tcp_select_initial_window`), at most 65,535 unscaled; the
/// scale is what the largest of that, `tcp_rmem[2]` (32 MiB) and
/// `rmem_max` takes past 16 bits, at most 14.
pub(super) fn syn_window(rcvbuf: i32, way: Way, v4: bool) -> (u16, u16, u8) {
    let mtu = way.mtu();
    let mss = if v4 {
        (mtu - 40).min(65_495)
    } else {
        (mtu - 60).min(65_535)
    };
    let space = usize::try_from(rcvbuf).unwrap_or(0) / 2;
    let window = if space > mss {
        space - space % mss
    } else {
        space
    };
    let largest = (window as u32).max(crate::tcp_info::RMEM_MAX).max(212_992);
    let wscale = (largest.ilog2().saturating_sub(15)).min(14) as u8;
    (window.min(65_535) as u16, mss as u16, wscale)
}

/// The Ethernet header from `src` to `dst` of an IPv4 or IPv6 packet.
fn ethernet(dst: [u8; 6], src: [u8; 6], v4: bool) -> Vec<u8> {
    let mut h = dst.to_vec();
    h.extend(src);
    h.extend(if v4 { [0x08, 0x00] } else { [0x86, 0xdd] });
    h
}

/// How many of a datagram's bytes from its UDP header on, with `payload`
/// bytes after it, are in the linear part. `__ip_append_data` and
/// `__ip6_append_data` put the bytes there while they fit in
/// [`MAX_ALLOC`] with the IP header and the room they reserve, else in
/// pages; a datagram past the MTU goes in fragments, each its own sk_buff,
/// and reassembled its head is the first's.
fn linear(payload: usize, v4: bool, mtu: usize) -> usize {
    let (ip, reserved) = if v4 { (20, 31) } else { (40, 24) };
    let whole = UDP_HEADER + payload;
    let first = if ip + whole <= mtu {
        whole
    } else if v4 {
        (mtu - ip) & !7
    } else {
        ((mtu - ip) & !7) - 8
    };
    if first + ip + reserved < MAX_ALLOC {
        first
    } else {
        UDP_HEADER
    }
}

/// `skb->hash` of an IPv6 datagram of a socket with no `sk_txhash`
/// (`__get_hash_from_flowi6`): of its addresses and ports, with a secret,
/// as `flow_hash_from_keys`, never 0.
pub(super) fn flow_hash(
    from: SocketAddr,
    to: SocketAddr,
    host: &Arc<dyn paludarium_host::Host>,
) -> u32 {
    use std::hash::{BuildHasher, Hasher};
    static SECRET: OnceLock<u64> = OnceLock::new();
    let secret = *SECRET.get_or_init(|| {
        let mut b = [0; 8];
        let _ = host.random_bytes(&mut b);
        u64::from_le_bytes(b)
    });
    let mut hasher =
        std::hash::BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default()
            .build_hasher();
    hasher.write_u64(secret);
    hasher.write(&v6(from.ip()));
    hasher.write(&v6(to.ip()));
    hasher.write_u16(from.port());
    hasher.write_u16(to.port());
    (hasher.finish() as u32).max(1)
}

/// An address as IPv6's 16 bytes.
fn v6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Adds `bytes` as big-endian 16-bit words to the one's complement `sum`.
fn add(mut sum: u32, bytes: &[u8]) -> u32 {
    for word in bytes.chunks(2) {
        let hi = u32::from(word[0]) << 8;
        sum += hi | word.get(1).map_or(0, |&b| u32::from(b));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

/// The 16 bits of a one's complement sum.
fn fold(sum: u32) -> u16 {
    let sum = (sum & 0xffff) + (sum >> 16);
    ((sum & 0xffff) + (sum >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_are_rfc_1071_s() {
        // RFC 1071's example: 0001 f203 f4f5 f6f7 sums to ddf2.
        assert_eq!(
            fold(add(0, &[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])),
            0xddf2
        );
        // An IPv4 header whose checksum is right sums to all ones.
        let sent = Sent::new(
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
            0,
            Some(1),
            0,
            0,
            (0, 0),
        );
        assert_eq!(fold(add(0, &sent.ipv4(UDP, 12, 1, true))), 0xffff);
        // A whole UDP checksum over its pseudo-header sums to all ones too.
        let data = sent.udp(b"abcd", true);
        let mut sum = add(0, &[127, 0, 0, 1, 127, 0, 0, 1, 0, UDP]);
        sum = add(sum, &12u16.to_be_bytes());
        assert_eq!(fold(add(sum, &data)), 0xffff);
    }

    #[test]
    fn a_syn_has_linux_s_window_and_mss() {
        assert_eq!(
            syn_window(131_072, Way::Loopback, true),
            (65_495, 65_495, 10)
        );
        assert_eq!(
            syn_window(131_072, Way::Loopback, false),
            (65_476, 65_476, 10)
        );
        let veth = Way::Veth {
            index: 2,
            src: [0; 6],
            dst: [0; 6],
            mtu: 1500,
        };
        assert_eq!(syn_window(131_072, veth, true), (64_240, 1460, 10));
        assert_eq!(syn_window(2304, Way::Loopback, true), (1152, 65_495, 10));
    }

    #[test]
    fn the_linear_part_is_what_the_head_holds() {
        assert_eq!(linear(100, true, LO_MTU), 108);
        // 16,064 bytes is SKB_MAX_ALLOC: 59 of them go to headers and room.
        assert_eq!(linear(16_004, true, LO_MTU), 16_012);
        assert_eq!(linear(16_005, true, LO_MTU), 8);
        assert_eq!(linear(16_000, false, LO_MTU), 8);
        // A fragment's head, across a veth of MTU 1500.
        assert_eq!(linear(2000, true, 1500), 1480);
        assert_eq!(linear(2000, false, 1500), 1448);
    }
}
