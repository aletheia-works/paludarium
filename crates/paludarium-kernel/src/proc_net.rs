//! `/proc/<pid>/net`, the files of a task's network namespace (Linux's
//! `fs/proc/proc_net.c`), which `/proc/net` is a link to, of the reader's
//! own: those of its devices, addresses, routes and neighbours. Every file
//! is made as it is read, of the namespace it was opened in. The rest of
//! Linux's names there are `ENOENT`, whatever a mounted directory holds at
//! the path.

use crate::inet::Network;
use crate::interface::{Kind, TABLE_MAIN};
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// A file of the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum File {
    Arp,
    Dev,
    Route,
    IfInet6,
    Ipv6Route,
}
impl File {
    /// The files, in the order Linux's `proc_readdir_de` lists them: by the
    /// length of their names, then by name.
    pub(crate) const ALL: [Self; 5] = [
        Self::Arp,
        Self::Dev,
        Self::Route,
        Self::IfInet6,
        Self::Ipv6Route,
    ];
    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Self::Arp => b"arp",
            Self::Dev => b"dev",
            Self::Route => b"route",
            Self::IfInet6 => b"if_inet6",
            Self::Ipv6Route => b"ipv6_route",
        }
    }
    pub(crate) fn named(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|file| file.name() == name)
    }
    /// Opens it of `network` with `flags`, owned by `owner`
    /// ([`Network::proc_owner`]). A session without a network has no device.
    pub(crate) fn open(
        self,
        network: Option<Arc<Network>>,
        now: impl Fn() -> Option<u64> + Send + Sync + 'static,
        flags: u32,
        owner: (u32, u32),
    ) -> crate::seq::SeqFile {
        let text = move || self.text(network.as_deref(), now());
        crate::seq::SeqFile::open(Box::new(crate::seq::Lines(text)), flags)
            .owned_by(Arc::new(Mutex::new(owner)))
    }
    fn text(self, network: Option<&Network>, now: Option<u64>) -> Vec<u8> {
        match self {
            Self::Arp => arp(network, now),
            Self::Dev => dev(network),
            Self::Route => route(network, now),
            Self::IfInet6 => if_inet6(network, now),
            Self::Ipv6Route => ipv6_route(network, now),
        }
        .into_bytes()
    }
}

/// The name of the device `index`, if there is one.
fn name(network: &Network, index: u32) -> Option<String> {
    let index = i32::try_from(index).ok()?;
    network
        .devices()
        .by_index(index)
        .map(|d| String::from_utf8_lossy(&d.name).into_owned())
}
/// `dev`, as `dev_seq_show` prints it: the devices in the order of their
/// indices, with counters of 0, as nothing counts here.
fn dev(network: Option<&Network>) -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    \
         packets errs drop fifo colls carrier compressed\n",
    );
    let Some(network) = network else { return out };
    for device in network.devices().iter() {
        let name = String::from_utf8_lossy(&device.name);
        let _ = writeln!(
            out,
            "{name:>6}: {0:7} {0:7} {0:4} {0:4} {0:4} {0:5} {0:10} {0:9} \
             {0:8} {0:7} {0:4} {0:4} {0:4} {0:5} {0:7} {0:10}",
            0
        );
    }
    out
}
/// `if_inet6`, as `if6_seq_show` prints it.
fn if_inet6(network: Option<&Network>, now: Option<u64>) -> String {
    let mut out = String::new();
    let Some(network) = network else { return out };
    let addresses: Vec<_> = network.addresses_at(now).v6().to_vec();
    for a in addresses {
        let Some(device) = name(network, a.index.unsigned_abs()) else {
            continue;
        };
        let _ = writeln!(
            out,
            "{:032x} {:02x} {:02x} {:02x} {:02x} {device:>8}",
            u128::from(a.address),
            a.index,
            a.prefix,
            scope(a.address),
            a.flags & 0xff,
        );
    }
    out
}
/// The scope of an IPv6 address as its type has it (`ipv6_addr_scope`,
/// `IPV6_ADDR_LOOPBACK`, `_LINKLOCAL` and `_SITELOCAL`).
fn scope(address: Ipv6Addr) -> u8 {
    match address.segments()[0] & 0xffc0 {
        _ if address.is_loopback() => 0x10,
        0xfe80 => 0x20,
        0xfec0 => 0x40,
        _ => 0,
    }
}
/// `route`, as `fib_route_seq_show` prints the main table: lines of 127
/// bytes and their newlines (`seq_setwidth`); nothing while there is no such
/// table.
fn route(network: Option<&Network>, now: Option<u64>) -> String {
    const RTF_UP: u32 = 1;
    const RTF_GATEWAY: u32 = 2;
    const RTF_HOST: u32 = 4;
    const RTF_REJECT: u32 = 0x200;
    let mut out = String::new();
    let Some(network) = network else { return out };
    let routes = {
        let addresses = network.addresses_at(now);
        if !addresses.has_table4(TABLE_MAIN) {
            return out;
        }
        addresses.dump4()
    };
    let head =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";
    let _ = writeln!(out, "{head:<127}");
    for r in routes {
        if r.table != TABLE_MAIN || matches!(r.kind, Kind::Broadcast | Kind::Multicast) {
            continue;
        }
        let hop = r.next_hops().first().cloned();
        let gateway = hop.as_ref().and_then(|hop| hop.gateway);
        let oif = hop.as_ref().map_or(0, |hop| hop.oif);
        let device = name(network, oif).unwrap_or_else(|| "*".to_owned());
        let mut flags = RTF_UP;
        if matches!(r.kind, Kind::Unreachable | Kind::Prohibit) {
            flags |= RTF_REJECT;
        }
        if gateway.is_some_and(|gateway| !gateway.is_unspecified()) {
            flags |= RTF_GATEWAY;
        }
        if r.len == 32 {
            flags |= RTF_HOST;
        }
        let mask = u32::MAX.checked_shl(32 - u32::from(r.len)).unwrap_or(0);
        // `RTAX_ADVMSS`, `RTAX_WINDOW` and `RTAX_RTT`, by their indices.
        let (advmss, window, rtt) = (r.metrics[7], r.metrics[2], r.metrics[3]);
        let mtu = if advmss == 0 { 0 } else { advmss + 40 };
        let line = format!(
            "{device}\t{:08X}\t{:08X}\t{flags:04X}\t0\t0\t{}\t{:08X}\t{mtu}\t{window}\t{}",
            u32::from(r.dst).swap_bytes(),
            gateway.map_or(0, u32::from).swap_bytes(),
            r.priority,
            mask.swap_bytes(),
            rtt >> 3,
        );
        let _ = writeln!(out, "{line:<127}");
    }
    out
}
/// `ipv6_route`, as `ipv6_route_native_seq_show` prints each table's
/// routes, with a reference each, the last the one that rejects
/// (`fib6_null_entry`), of `lo`, where a table has no default route.
fn ipv6_route(network: Option<&Network>, now: Option<u64>) -> String {
    const RTF_UP: u32 = 1;
    const RTF_GATEWAY: u32 = 2;
    const RTF_REJECT: u32 = 0x200;
    const RTF_NONEXTHOP: u32 = 0x0020_0000;
    const RTF_EXPIRES: u32 = 0x0040_0000;
    const RTF_LOCAL: u32 = 0x8000_0000;
    const RTPROT_KERNEL: u8 = 2;
    let mut out = String::new();
    let Some(network) = network else { return out };
    let (routes, tables) = {
        let addresses = network.addresses_at(now);
        (addresses.dump6(), addresses.tables6())
    };
    let mut line = |dst: Ipv6Addr,
                    len: u8,
                    gateway: Option<Ipv6Addr>,
                    (metric, flags, device): (u32, u32, &str)| {
        let _ = writeln!(
            out,
            "{:032x} {len:02x} {:032x} 00 {:032x} {metric:08x} 00000001 00000000 {flags:08x} {device:>8}",
            u128::from(dst),
            0,
            u128::from(gateway.unwrap_or(Ipv6Addr::UNSPECIFIED)),
        );
    };
    for table in tables {
        let mut default = false;
        for r in routes.iter().filter(|r| r.table == table) {
            default |= r.len == 0;
            let mut flags = RTF_UP;
            match r.kind {
                Kind::Local if r.proto == RTPROT_KERNEL => flags |= RTF_LOCAL | RTF_NONEXTHOP,
                Kind::Local => flags |= RTF_LOCAL,
                Kind::Unreachable | Kind::Prohibit | Kind::Blackhole => {
                    flags = RTF_REJECT | RTF_NONEXTHOP;
                }
                _ => {}
            }
            if r.gateway.is_some() {
                flags |= RTF_GATEWAY;
            }
            if r.expires.is_some() {
                flags |= RTF_EXPIRES;
            }
            let device = name(network, r.oif).unwrap_or_default();
            line(r.dst, r.len, r.gateway, (r.metric, flags, &device));
        }
        if !default {
            let reject = RTF_REJECT | RTF_NONEXTHOP;
            line(Ipv6Addr::UNSPECIFIED, 0, None, (u32::MAX, reject, "lo"));
        }
    }
    out
}
/// `arp`, as `arp_seq_show` prints the neighbours of IPv4 but those that
/// need no ARP (`NEIGH_SEQ_SKIP_NOARP`).
fn arp(network: Option<&Network>, now: Option<u64>) -> String {
    use crate::interface::{
        NUD_DELAY, NUD_NOARP, NUD_PERMANENT, NUD_PROBE, NUD_REACHABLE, NUD_STALE,
    };
    const ETHER: u32 = 1;
    const LOOPBACK: u32 = 772;
    let mut out = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    let Some(network) = network else { return out };
    let neighbours = network.addresses_at(now).neighbours().to_vec();
    for n in neighbours {
        let IpAddr::V4(ip) = n.ip else { continue };
        if n.state & !NUD_NOARP == 0 {
            continue;
        }
        let Some(device) = name(network, n.index.unsigned_abs()) else {
            continue;
        };
        // `arp_state_to_flags`: `ATF_COM`, and `ATF_PERM`.
        let flags = if n.state & NUD_PERMANENT != 0 {
            0x6
        } else if n.state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_NOARP) != 0 {
            0x2
        } else {
            0
        };
        let hardware = if n.index == crate::netdev::LOOPBACK_INDEX {
            LOOPBACK
        } else {
            ETHER
        };
        let lladdr: Vec<String> = n.lladdr.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(
            out,
            "{:<16} 0x{hardware:<10x}0x{flags:<10x}{:<17}     *        {device}",
            ip.to_string(),
            lladdr.join(":"),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inet::NetworkPolicy;

    fn text(file: File, network: &Network) -> String {
        String::from_utf8(file.text(Some(network), None)).unwrap()
    }

    #[test]
    fn names_are_listed_by_length() {
        let names: Vec<_> = File::ALL
            .iter()
            .map(|f| (f.name().len(), f.name()))
            .collect();
        assert!(names.is_sorted());
        for file in File::ALL {
            assert_eq!(File::named(file.name()), Some(file));
        }
        assert_eq!(File::named(b"tcp"), None);
    }

    #[test]
    fn the_first_namespace_shows_its_loopback() {
        let network = Network::new(NetworkPolicy::default());
        let dev = text(File::Dev, &network);
        assert_eq!(dev.lines().count(), 3);
        assert!(dev.ends_with(
            "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        ));
        assert_eq!(
            text(File::IfInet6, &network),
            "00000000000000000000000000000001 01 80 10 80       lo\n"
        );
        assert_eq!(
            text(File::Arp, &network),
            "IP address       HW type     Flags       HW address            Mask     Device\n"
        );
        let routes = text(File::Ipv6Route, &network);
        assert!(routes.contains(&format!(
            "{:032x} 80 {:032x} 00 {:032x} 00000000 00000001 00000000 80200001       lo\n",
            1, 0, 0
        )));
        assert!(routes.contains(&format!(
            "{:032x} 00 {:032x} 00 {:032x} ffffffff 00000001 00000000 00200200       lo\n",
            0, 0, 0
        )));
    }

    #[test]
    fn a_session_without_a_network_has_no_device() {
        assert_eq!(
            File::Dev
                .text(None, None)
                .iter()
                .filter(|&&b| b == b'\n')
                .count(),
            2
        );
        for file in [File::Route, File::IfInet6, File::Ipv6Route] {
            assert!(file.text(None, None).is_empty());
        }
    }
}
