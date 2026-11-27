//! The lengths of the packets a device's counters take
//! ([`crate::netdev::Tally`]): as a veth end sends them, with their
//! Ethernet header (`veth_xmit`'s `skb->len`), or as the loopback does,
//! from their IP header (`loopback_xmit`, after `eth_type_trans`).

/// An Ethernet header (`ETH_HLEN`), and an ARP packet of IPv4 over it
/// with that header.
pub(crate) const ETHERNET: usize = 14;
pub(crate) const ARP: usize = ETHERNET + 28;
/// The IPv4 and IPv6 headers, without options, IPv6's fragment header,
/// and the UDP and ICMP headers.
const IP4: usize = 20;
const IP6: usize = 40;
const FRAGMENT6: usize = 8;
const UDP: usize = 8;
const ICMP: usize = 8;
/// A neighbour solicitation with the sender's link-layer address, to the
/// target's solicited-node group, and the solicited advertisement that
/// answers it with the target's (`ndisc_send_ns`, `ndisc_send_na`): each
/// an IPv6 header and 24 bytes of ICMPv6 with an 8-byte option, on
/// Ethernet.
pub(crate) const NDISC: usize = ETHERNET + 40 + 24 + 8;
/// A TCP SYN's header with its options (`tcp_syn_options`), and a reset's
/// with none (`tcp_v4_send_reset`, `tcp_v6_send_reset`).
pub(crate) const SYN: usize = 40;
pub(crate) const RESET: usize = 20;
/// What ICMP quotes of a packet at most: what fits in 576 bytes
/// (`icmp_send`), and in IPv6's least MTU (`icmp6_send`).
const QUOTED4: usize = 576 - IP4 - ICMP;
const QUOTED6: usize = 1280 - IP6 - ICMP;

/// The packets of a UDP datagram of `data` bytes, of IPv6 if `v6`, out
/// through a device of MTU `mtu` whose header is `link` bytes: one, or
/// fragments of as many 8-byte blocks as fit (`__ip_append_data`'s and
/// `__ip6_append_data`'s `maxfraglen`).
pub(crate) fn udp(v6: bool, data: usize, mtu: usize, link: usize) -> Vec<usize> {
    let (header, room) = if v6 {
        (
            IP6,
            (mtu.saturating_sub(IP6) & !7).saturating_sub(FRAGMENT6),
        )
    } else {
        (IP4, mtu.saturating_sub(IP4) & !7)
    };
    let payload = UDP + data;
    if header + payload <= mtu || room == 0 {
        return vec![link + header + payload];
    }
    let fragment = if v6 { header + FRAGMENT6 } else { header };
    let mut frames = Vec::new();
    let mut left = payload;
    while left > 0 {
        let part = left.min(room);
        frames.push(link + fragment + part);
        left -= part;
    }
    frames
}

/// ICMP's port unreachable that answers a UDP datagram of `data` bytes, of
/// IPv6 if `v6`, with as much of it as it quotes, out through a device
/// whose header is `link` bytes.
pub(crate) fn unreachable(v6: bool, data: usize, link: usize) -> usize {
    let (header, most) = if v6 { (IP6, QUOTED6) } else { (IP4, QUOTED4) };
    link + header + ICMP + (header + UDP + data).min(most)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrams_split_as_linux_cuts_them() {
        assert_eq!(udp(false, 10, 1500, ETHERNET), [52]);
        assert_eq!(udp(false, 10, 65_536, 0), [38]);
        assert_eq!(udp(false, 3000, 1500, ETHERNET), [1514, 1514, 82]);
        assert_eq!(udp(true, 10, 1500, ETHERNET), [72]);
        assert_eq!(udp(true, 3000, 1500, ETHERNET), [1510, 1510, 174]);
        assert_eq!(unreachable(false, 10, ETHERNET), 80);
        assert_eq!(unreachable(false, 10, 0), 66);
        assert_eq!(unreachable(false, 2000, ETHERNET), 14 + 576);
        assert_eq!(unreachable(true, 2000, 0), 1280);
    }
}
