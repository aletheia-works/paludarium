//! What a UDP socket's filter sees of a datagram as it comes
//! (`sk_filter_trim_cap` from `udp_queue_rcv_one_skb` and
//! `udpv6_queue_rcv_one_skb`): the `sk_buff` that x86-64 Linux 7.0 makes
//! of it as it is sent (`ip_make_skb`, `ip6_make_skb`) and as it comes
//! through the loopback or a veth pair, with `skb->data` at the UDP header
//! and the IP header before it.

use crate::bpf_interp::{Packet, Skb};
use crate::sockets::Filter;
use core::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

/// `ARPHRD_ETHER` and `ARPHRD_LOOPBACK`, a device's type.
const ETHER: u16 = 1;
const LOOPBACK: u16 = 772;
/// `PACKET_HOST`, `PACKET_BROADCAST` and `PACKET_LOOPBACK`.
const HOST: u32 = 0;
const BROADCAST: u32 = 1;
const LOOPED: u32 = 5;
/// The loopback's index (`LOOPBACK_IFINDEX`) and MTU.
const LO_INDEX: u32 = 1;
const LO_MTU: usize = 65_536;
/// `SKB_MAX_ALLOC`: past it `__ip_append_data` puts the bytes in pages.
const MAX_ALLOC: usize = 16_384 - crate::bpf_prog::SKB_SHARED_INFO;
/// `sysctl_ip_default_ttl` and IPv6's `hop_limit`.
const HOPS: u8 = 64;
/// `IPPROTO_UDP`.
const UDP: u8 = 17;
/// The UDP header's length, which `sk_filter_trim_cap` keeps
/// (`sizeof(struct udphdr)`).
pub(super) const UDP_HEADER: usize = 8;

/// A datagram as it is sent.
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
    /// A broadcast's copy that `ip_mc_output` loops back on the sending
    /// veth end `index` (`dev_loopback_xmit`), of MTU `mtu`.
    Looped { index: u32, mtu: usize },
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
        let mtu = match way {
            Way::Loopback => LO_MTU,
            Way::Veth { mtu, .. } | Way::Looped { mtu, .. } => mtu,
        };
        let ip = if v4 { 20 } else { 40 };
        let fragmented = ip + UDP_HEADER + payload.len() > mtu;
        let data = self.udp(payload, fragmented);
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
            headers.extend(self.ipv4(data.len(), id, !fragmented));
        } else {
            headers.extend(self.ipv6(data.len()));
        }
        let skb = Skb {
            pkt_type: match way {
                Way::Loopback => HOST,
                Way::Veth { dst, .. } if dst == [0xff; 6] => BROADCAST,
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
            payload_offset: UDP_HEADER as u32,
        };
        let packet = Packet {
            linear: linear(payload.len(), v4, mtu),
            data: &data,
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
            keep => Some(
                (keep as usize)
                    .max(UDP_HEADER)
                    .min(data.len())
                    .saturating_sub(UDP_HEADER),
            ),
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
        let mut sum = 0;
        match (self.from.ip(), self.to.ip()) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                sum = add(sum, &from.octets());
                sum = add(sum, &to.octets());
                sum = add(sum, &[0, UDP]);
                sum = add(sum, &(len as u16).to_be_bytes());
            }
            (from, to) => {
                sum = add(sum, &v6(from));
                sum = add(sum, &v6(to));
                sum = add(sum, &(len as u32).to_be_bytes());
                sum = add(sum, &[0, 0, 0, UDP]);
            }
        }
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

    /// The IPv4 header of a datagram of `len` bytes from the UDP header on,
    /// `DF` set when it goes whole (`IP_PMTUDISC_WANT`).
    fn ipv4(&self, len: usize, id: u16, whole: bool) -> Vec<u8> {
        let (IpAddr::V4(from), IpAddr::V4(to)) = (self.from.ip(), self.to.ip()) else {
            unreachable!("an IPv4 datagram has IPv4 addresses");
        };
        let mut h = vec![0x45, self.tos];
        h.extend(((20 + len) as u16).to_be_bytes());
        h.extend(id.to_be_bytes());
        h.extend(if whole { [0x40, 0] } else { [0, 0] });
        h.extend([HOPS, UDP, 0, 0]);
        h.extend(from.octets());
        h.extend(to.octets());
        let check = !fold(add(0, &h));
        h[10..12].copy_from_slice(&check.to_be_bytes());
        h
    }

    /// The IPv6 header of a datagram of `len` bytes from the UDP header on:
    /// no traffic class, and the auto flow label of its hash.
    fn ipv6(&self, len: usize) -> Vec<u8> {
        let label = self.hash.rotate_left(16) & 0xf_ffff;
        let mut h = label.to_be_bytes().to_vec();
        h[0] = 0x60;
        h.extend((len as u16).to_be_bytes());
        h.extend([UDP, HOPS]);
        h.extend(v6(self.from.ip()));
        h.extend(v6(self.to.ip()));
        h
    }
}

impl super::Network {
    /// The Ethernet address and MTU of its veth end `index`, if it has one.
    pub(super) fn veth_link(&self, index: i32) -> ([u8; 6], usize) {
        self.devices()
            .by_index(index)
            .and_then(|d| d.veth.as_ref())
            .map_or(([0; 6], LO_MTU), |v| (v.mac, v.mtu as usize))
    }
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
        assert_eq!(fold(add(0, &sent.ipv4(12, 1, true))), 0xffff);
        // A whole UDP checksum over its pseudo-header sums to all ones too.
        let data = sent.udp(b"abcd", true);
        let mut sum = add(0, &[127, 0, 0, 1, 127, 0, 0, 1, 0, UDP]);
        sum = add(sum, &12u16.to_be_bytes());
        assert_eq!(fold(add(sum, &data)), 0xffff);
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
