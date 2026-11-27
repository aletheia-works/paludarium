//! `/proc/<pid>/net`, the files of a task's network namespace (Linux's
//! `fs/proc/proc_net.c`), which `/proc/net` is a link to, of the reader's
//! own: those of its devices, addresses, routes and neighbours, and of its
//! sockets, as `sock_diag` tells of them. Every file
//! is made as it is read, of the namespace it was opened in. The rest of
//! Linux's names there are `ENOENT`, whatever a mounted directory holds at
//! the path.

use crate::inet::{Entry, Network, Table};
use crate::interface::{Kind, TABLE_MAIN};
use crate::users::Ids;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

/// A file of the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum File {
    Arp,
    Dev,
    Raw,
    Tcp,
    Udp,
    Icmp,
    Igmp,
    Raw6,
    Tcp6,
    Udp6,
    Unix,
    Icmp6,
    Igmp6,
    Route,
    Packet,
    Netlink,
    Anycast6,
    IfInet6,
    Mcfilter,
    DevMcast,
    Mcfilter6,
    Ipv6Route,
}
/// What a file shows of, as it was opened: the network, its AF_UNIX sockets,
/// and the opener's user namespace, whose IDs the owners are shown in.
pub(crate) struct Source {
    pub(crate) network: Option<Arc<Network>>,
    pub(crate) unix: Option<Arc<crate::unix::Names>>,
    pub(crate) user: crate::users::UserNs,
}
impl File {
    /// The files, in the order Linux's `proc_readdir_de` lists them: by the
    /// length of their names, then by name.
    pub(crate) const ALL: [Self; 22] = [
        Self::Arp,
        Self::Dev,
        Self::Raw,
        Self::Tcp,
        Self::Udp,
        Self::Icmp,
        Self::Igmp,
        Self::Raw6,
        Self::Tcp6,
        Self::Udp6,
        Self::Unix,
        Self::Icmp6,
        Self::Igmp6,
        Self::Route,
        Self::Packet,
        Self::Netlink,
        Self::Anycast6,
        Self::IfInet6,
        Self::Mcfilter,
        Self::DevMcast,
        Self::Mcfilter6,
        Self::Ipv6Route,
    ];
    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Self::Arp => b"arp",
            Self::Dev => b"dev",
            Self::Raw => b"raw",
            Self::Tcp => b"tcp",
            Self::Udp => b"udp",
            Self::Icmp => b"icmp",
            Self::Igmp => b"igmp",
            Self::Raw6 => b"raw6",
            Self::Tcp6 => b"tcp6",
            Self::Udp6 => b"udp6",
            Self::Unix => b"unix",
            Self::Icmp6 => b"icmp6",
            Self::Igmp6 => b"igmp6",
            Self::Route => b"route",
            Self::Packet => b"packet",
            Self::Netlink => b"netlink",
            Self::Anycast6 => b"anycast6",
            Self::IfInet6 => b"if_inet6",
            Self::Mcfilter => b"mcfilter",
            Self::DevMcast => b"dev_mcast",
            Self::Mcfilter6 => b"mcfilter6",
            Self::Ipv6Route => b"ipv6_route",
        }
    }
    pub(crate) fn named(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|file| file.name() == name)
    }
    /// Opens it of `source` with `flags`, owned by `owner`
    /// ([`Network::proc_owner`]). A session without a network has no device.
    pub(crate) fn open(
        self,
        source: Source,
        now: impl Fn() -> Option<u64> + Send + Sync + 'static,
        flags: u32,
        owner: (u32, u32),
    ) -> crate::seq::SeqFile {
        let text = move || self.text(&source, now());
        crate::seq::SeqFile::open(Box::new(crate::seq::Lines(text)), flags)
            .owned_by(Arc::new(Mutex::new(owner)))
    }
    fn text(self, source: &Source, now: Option<u64>) -> Vec<u8> {
        let network = source.network.as_deref();
        match self {
            // Of kinds of socket there are none of here.
            Self::Raw => RAW_HEAD.to_owned(),
            Self::Icmp => padded("  sl  ", DGRAM_HEAD, 127),
            Self::Raw6 | Self::Icmp6 => DGRAM6_HEAD.to_owned(),
            Self::Packet => {
                "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n".to_owned()
            }
            Self::Tcp => tcp(source, now, false),
            Self::Tcp6 => tcp(source, now, true),
            Self::Udp => udp(source, now, false),
            Self::Udp6 => udp(source, now, true),
            Self::Unix => return unix(source),
            Self::Netlink => netlink(network),
            Self::Arp => arp(network, now),
            Self::Dev => dev(network),
            Self::Route => route(network, now),
            Self::Anycast6 => anycast6(network, now),
            Self::IfInet6 => if_inet6(network, now),
            Self::Igmp => igmp(network),
            Self::Igmp6 => igmp6(network),
            Self::Mcfilter => mcfilter(network),
            Self::DevMcast => dev_mcast(network),
            Self::Mcfilter6 => mcfilter6(network),
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
/// indices, with their statistics ([`crate::netdev::Device::stats64`]).
fn dev(network: Option<&Network>) -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    \
         packets errs drop fifo colls carrier compressed\n",
    );
    let Some(network) = network else { return out };
    for device in network.devices().iter() {
        let name = String::from_utf8_lossy(&device.name);
        let s = device.stats64();
        // `dev_seq_printf_stats`: rx_packets 0, tx_packets 1, rx_bytes 2,
        // tx_bytes 3, errors 4 and 5, dropped 6 and 7, multicast 8,
        // collisions 9, and the errors that make up the rest.
        let _ = writeln!(
            out,
            "{name:>6}: {:7} {:7} {:4} {:4} {:4} {:5} {:10} {:9} \
             {:8} {:7} {:4} {:4} {:4} {:5} {:7} {:10}",
            s[2],
            s[0],
            s[4],
            s[6] + s[15],
            s[14],
            s[10] + s[11] + s[12] + s[13],
            s[21],
            s[8],
            s[3],
            s[1],
            s[5],
            s[7],
            s[18],
            s[9],
            s[17] + s[16] + s[20] + s[19],
            s[22],
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
        // `fib_flag_trans` reads `nhc_gw.ipv4`, which an IPv6 gateway's
        // first 4 bytes share, where `fib_route_seq_show` prints only an
        // IPv4 one.
        let first4 = |gateway: IpAddr| match gateway {
            IpAddr::V4(ip) => u32::from(ip),
            IpAddr::V6(ip) => {
                let o = ip.octets();
                u32::from_be_bytes([o[0], o[1], o[2], o[3]])
            }
        };
        if gateway.is_some_and(|gateway| first4(gateway) != 0) {
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
            match gateway {
                Some(IpAddr::V4(ip)) => u32::from(ip),
                _ => 0,
            }
            .swap_bytes(),
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
    const RTF_ANYCAST: u32 = 0x0010_0000;
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
                Kind::Anycast => flags |= RTF_ANYCAST | RTF_NONEXTHOP,
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

/// The devices in the order they were registered in the namespace, as
/// `for_each_netdev` goes through them.
fn registered(devices: &crate::netdev::Devices) -> impl Iterator<Item = &crate::netdev::Device> {
    devices
        .order()
        .into_iter()
        .filter_map(|index| devices.by_index(index))
}
/// `igmp`, as `igmp_mc_seq_show` prints it: under a line of each device
/// that has joined a group, with how many it has and the querier taken to be
/// there (`V3`, as none is heard), its groups, the newest first. No report is
/// sent, so no timer runs and no device is the last to report. The devices
/// are in the order they were registered in.
fn igmp(network: Option<&Network>) -> String {
    let mut out = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    let Some(network) = network else { return out };
    let devices = network.devices();
    for device in registered(&devices) {
        let groups: Vec<_> = device.groups4.shown().collect();
        if groups.is_empty() {
            continue;
        }
        let name = String::from_utf8_lossy(&device.name);
        let _ = writeln!(
            out,
            "{}\t{name:<10}: {:5} {:>7}",
            device.index,
            groups.len(),
            "V3"
        );
        for (group, users, _) in groups {
            // The address as it is in memory, of a little-endian machine.
            let group = u32::from_le_bytes(group.octets());
            let _ = writeln!(out, "\t\t\t\t{group:08X} {users:5} 0:00000000\t\t0");
        }
    }
    out
}
/// The lines of `mcfilter` or `mcfilter6`, as `igmp_mcf_seq_show` and
/// `igmp6_mcf_seq_show` print them, of the devices' `groups`, each with its
/// index and name: a line for each source a group's memberships name, but
/// for those of the devices before the first whose newest group names one,
/// as `igmp_mcf_get_first` and `igmp6_mcf_get_first` begin there.
fn sources<'g, A: Copy + 'g>(
    out: &mut String,
    groups: impl Iterator<
        Item = (
            i32,
            String,
            Vec<(A, u32, &'g [(A, crate::multicast::Counts)])>,
        ),
    >,
    address: impl Fn(A) -> String,
) {
    let mut started = false;
    for (index, name, groups) in groups {
        started |= groups
            .first()
            .is_some_and(|(_, _, sources)| !sources.is_empty());
        if !started {
            continue;
        }
        for (group, _, sources) in groups {
            for &(source, [exclude, include]) in sources {
                let _ = writeln!(
                    out,
                    "{index:3} {name:>6.6} {} {} {include:6} {exclude:6}",
                    address(group),
                    address(source),
                );
            }
        }
    }
}
/// `mcfilter`, the sources of IPv4's groups.
fn mcfilter(network: Option<&Network>) -> String {
    let mut out = String::from("Idx Device        MCA        SRC    INC    EXC\n");
    let Some(network) = network else { return out };
    let devices = network.devices();
    let groups = registered(&devices).map(|d| {
        let name = String::from_utf8_lossy(&d.name).into_owned();
        (d.index, name, d.groups4.shown().collect())
    });
    sources(&mut out, groups, |ip: Ipv4Addr| {
        format!("0x{:08x}", u32::from(ip))
    });
    out
}
/// `igmp6`, as `igmp6_mc_seq_show` prints it: each group of each device
/// that has IPv6, the newest first, with its users and flags, and no timer,
/// as no MLDv1 report is waited for. Its flags are `MAF_NOREPORT` for the
/// link-local all-nodes group and one of a scope below a link's, and
/// `MAF_LOADED` for the rest while their device's IPv6 is up.
fn igmp6(network: Option<&Network>) -> String {
    const LOADED: u32 = 4;
    const NOREPORT: u32 = 8;
    let mut out = String::new();
    let Some(network) = network else { return out };
    network.sync6();
    let devices = network.devices();
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    for d in registered(&devices).filter(|d| d.veth.as_ref().is_none_or(|v| v.mtu >= 1280)) {
        let name = String::from_utf8_lossy(&d.name);
        for (group, users, loaded) in d.groups6.loaded() {
            let scope = crate::multicast::scope6(group);
            let flags = if group == all_nodes || scope < 2 {
                NOREPORT
            } else {
                0
            } | if scope >= 2 && loaded { LOADED } else { 0 };
            let _ = writeln!(
                out,
                "{:<4} {name:<15} {:032x} {users:5} {flags:08X} 0",
                d.index,
                u128::from(group),
            );
        }
    }
    out
}
/// `dev_mcast`, as `dev_mc_seq_show` prints it: each link-layer multicast
/// address of each device, in the order of their indexes, each's in the
/// order it came, with its users and whether it is global, which none is
/// here ([`crate::multicast::Links`]).
fn dev_mcast(network: Option<&Network>) -> String {
    let mut out = String::new();
    let Some(network) = network else { return out };
    network.sync6();
    for d in network.devices().iter() {
        let name = String::from_utf8_lossy(&d.name);
        for (address, users) in d.links.listed() {
            let hex: String = address.iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(out, "{:<4} {name:<15} {users:<5} {:<5} {hex}", d.index, 0);
        }
    }
    out
}
/// `anycast6`, as `ac6_seq_show` prints it: each anycast address of each
/// device, in the namespace's order, each's the newest first, with its
/// users.
fn anycast6(network: Option<&Network>, now: Option<u64>) -> String {
    let mut out = String::new();
    let Some(network) = network else { return out };
    let all = network.addresses_at(now).anycast6().to_vec();
    let devices = network.devices();
    for d in registered(&devices) {
        let name = String::from_utf8_lossy(&d.name);
        for a in all.iter().filter(|a| a.index == d.index) {
            let _ = writeln!(
                out,
                "{:<4} {name:<15} {:032x} {:5}",
                d.index,
                u128::from(a.address),
                a.users,
            );
        }
    }
    out
}
/// `mcfilter6`, the sources of IPv6's groups, of the devices that have IPv6
/// (`__in6_dev_get`): not a veth end of an MTU below 1280.
fn mcfilter6(network: Option<&Network>) -> String {
    let mut out = String::from(
        "Idx Device                Multicast Address                   Source Address    INC    EXC\n",
    );
    let Some(network) = network else { return out };
    network.sync6();
    let devices = network.devices();
    let groups = registered(&devices)
        .filter(|d| d.veth.as_ref().is_none_or(|v| v.mtu >= 1280))
        .map(|d| {
            let name = String::from_utf8_lossy(&d.name).into_owned();
            (d.index, name, d.groups6.shown().collect())
        });
    sources(&mut out, groups, |ip: Ipv6Addr| {
        format!("{:032x}", u128::from(ip))
    });
    out
}

/// The columns of a datagram's file after `sl`, of IPv4.
const DGRAM_HEAD: &str = "local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   \
     uid  timeout inode ref pointer drops";
const RAW_HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when \
     retrnsmt   uid  timeout inode ref pointer drops\n";
/// `IPV6_SEQ_DGRAM_HEADER`.
const DGRAM6_HEAD: &str = "  sl  local_address                         remote_address            \
     \x20           st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";
/// A socket's address in the kernel, as `%pK` hides it.
const POINTER: &str = "0000000000000000";

/// A line of `width` bytes and its newline (`seq_setwidth`, `seq_pad`).
fn padded(start: &str, rest: &str, width: usize) -> String {
    format!("{:<width$}\n", format!("{start}{rest}"))
}
/// An address and port as the files of IPv4's sockets, or `v6`'s, have them:
/// each word of the address in host order.
fn address(address: SocketAddr, v6: bool) -> String {
    let mut out = String::new();
    let ip = match (address.ip(), v6) {
        (IpAddr::V4(ip), false) => ip.octets().to_vec(),
        (IpAddr::V6(_), false) => Ipv4Addr::UNSPECIFIED.octets().to_vec(),
        (IpAddr::V4(ip), true) => ip.to_ipv6_mapped().octets().to_vec(),
        (IpAddr::V6(ip), true) => ip.octets().to_vec(),
    };
    for word in ip.as_chunks::<4>().0 {
        let word = u32::from_le_bytes(*word);
        let _ = write!(out, "{word:08X}");
    }
    let _ = write!(out, ":{:04X}", address.port());
    out
}
/// The addresses of `entry`.
fn addresses(entry: &Entry) -> String {
    let none = if entry.v6 {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    format!(
        "{} {}",
        address(entry.local, entry.v6),
        address(entry.peer.unwrap_or(none), entry.v6)
    )
}
/// Its sockets of IPv4, or of IPv6 (`v6`).
fn entries(source: &Source, now: Option<u64>, udp: bool, v6: bool) -> Vec<Entry> {
    let Some(network) = &source.network else {
        return Vec::new();
    };
    let mut entries = network.diag(now);
    entries.retain(|entry| entry.udp == udp && entry.v6 == v6);
    entries
}
/// `tcp` or `tcp6`, as `tcp4_seq_show` and `tcp6_seq_show` print it: the
/// listeners, then the connections, with those in `TIME_WAIT`. The
/// acknowledgements a connection still sends at once (`icsk_ack.quick`) are
/// not told, and 0.
fn tcp(source: &Source, now: Option<u64>, v6: bool) -> String {
    // `TMPSZ` less one, of `tcp4_seq_show`.
    const WIDTH: usize = 149;
    let pad = |line: String| {
        if v6 {
            format!("{line}\n")
        } else {
            padded(&line, "", WIDTH)
        }
    };
    let mut out = pad(if v6 {
        "  sl  local_address                         remote_address                        st \
         tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
            .to_owned()
    } else {
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
         timeout inode"
            .to_owned()
    });
    let entries = entries(source, now, false, v6);
    let listed = [Table::Listening, Table::Connected]
        .into_iter()
        .flat_map(|table| entries.iter().filter(move |entry| entry.table == table));
    for (i, entry) in listed.enumerate() {
        let (kind, retrans, until) = entry.timer;
        let when = match (until, now) {
            (Some(until), Some(now)) => until.saturating_sub(now) / 10_000_000,
            _ => 0,
        };
        // A listener's second queue is its backlog in `sock_diag` alone.
        let (received, sent) = entry.queues;
        let sent = if entry.table == Table::Listening {
            0
        } else {
            sent
        };
        let head = format!(
            "{i:4}: {} {:02X} {sent:08X}:{received:08X} {kind:02X}:{when:08X}",
            addresses(entry),
            entry.state,
        );
        let line = match &entry.full {
            None => format!("{head} 00000000 {0:5} {0:8} 0 3 {POINTER}", 0),
            Some(full) => {
                let uid = source.user.0.shown(Ids::User, full.uid);
                let rest = full.tcp.as_ref().map_or_else(String::new, |tcp| {
                    // `tcp_in_initial_slowstart`.
                    let ssthresh = if entry.table == Table::Listening {
                        0
                    } else if tcp.snd_ssthresh >= 0x7fff_ffff {
                        -1
                    } else {
                        i64::from(tcp.snd_ssthresh)
                    };
                    let ticks = |microseconds: u32| microseconds / 10_000;
                    // `tcp_info` gives a listener's no RTO.
                    let rto = if entry.table == Table::Listening {
                        crate::tcp_info::RTO_INIT
                    } else {
                        tcp.rto
                    };
                    format!(
                        " {} {} 0 {} {ssthresh}",
                        ticks(rto),
                        ticks(tcp.ato),
                        tcp.snd_cwnd
                    )
                });
                format!(
                    "{head} {retrans:08X} {uid:5} {:8} {} 1 {POINTER}{rest}",
                    0, full.inode
                )
            }
        };
        out.push_str(&pad(line));
    }
    out
}
/// `udp` or `udp6`, as `udp4_format_sock` and `__ip6_dgram_sock_seq_show`
/// print it. `sl` is the bucket of the socket's port, here of the least a
/// machine has (`UDP_HTABLE_SIZE_MIN_PERNET`, with no hash of the namespace).
fn udp(source: &Source, now: Option<u64>, v6: bool) -> String {
    const WIDTH: usize = 127;
    let mut out = if v6 {
        DGRAM6_HEAD.to_owned()
    } else {
        padded("   sl  ", DGRAM_HEAD, WIDTH)
    };
    for entry in entries(source, now, true, v6) {
        let Some(full) = &entry.full else { continue };
        let uid = source.user.0.shown(Ids::User, full.uid);
        let line = format!(
            "{:5}: {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {uid:5} {:8} {} 2 {POINTER} {}",
            entry.local.port() & 255,
            addresses(&entry),
            entry.state,
            0,
            entry.queues.0,
            0,
            full.inode,
            full.drops,
        );
        if v6 {
            let _ = writeln!(out, "{line}");
        } else {
            out.push_str(&padded(&line, "", WIDTH));
        }
    }
    out
}
/// `unix`, as `unix_seq_show` prints it, a connection not yet accepted too.
fn unix(source: &Source) -> Vec<u8> {
    const ACCEPTCON: u32 = 1 << 16;
    let mut out = b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec();
    let Some(names) = &source.unix else {
        return out;
    };
    for socket in names.sockets() {
        let shown = socket.shown();
        let flags = if shown.listening { ACCEPTCON } else { 0 };
        // `SS_UNCONNECTED` and `SS_CONNECTED` of one with a file, else
        // `SS_CONNECTING`.
        let state = match (shown.inode, shown.established) {
            (None, _) => 2,
            (Some(_), true) => 3,
            (Some(_), false) => 1,
        };
        let line = format!(
            "{POINTER}: {:08X} 00000000 {flags:08X} {:04X} {state:02X} {:5}",
            if shown.established { 3 } else { 2 },
            shown.kind,
            shown.inode.unwrap_or(0),
        );
        out.extend_from_slice(line.as_bytes());
        if let Some(name) = &shown.name {
            out.push(b' ');
            // A path's NUL goes, and an abstract name's, and any other in
            // it, is `@`.
            let name = match name.split_last() {
                Some((_, path)) if name[0] != 0 => path,
                _ => &name[..],
            };
            out.extend(name.iter().map(|&b| if b == 0 { b'@' } else { b }));
        }
        out.push(b'\n');
    }
    out
}
/// `netlink`, as `netlink_native_seq_show` prints it: the sockets bound, but
/// for the kernel's own.
fn netlink(network: Option<&Network>) -> String {
    let mut out = String::from(
        "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n",
    );
    let Some(network) = network else { return out };
    for s in network.netlink.shown() {
        let _ = writeln!(
            out,
            "{POINTER} {:<3} {:<10} {:08x} {:<8} {:<8} {:<5} {:<8} {:<8} {:<8}",
            s.protocol,
            s.port,
            s.groups,
            s.received,
            0,
            u8::from(s.dumping),
            2,
            0,
            s.inode,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inet::NetworkPolicy;

    fn source(network: Option<Network>) -> Source {
        Source {
            network: network.map(Arc::new),
            unix: None,
            user: crate::users::UserNs::default(),
        }
    }
    fn text(file: File, network: Network) -> String {
        String::from_utf8(file.text(&source(Some(network)), None)).unwrap()
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
        assert_eq!(File::named(b"snmp"), None);
    }

    #[test]
    fn the_first_namespace_shows_its_loopback() {
        let network = || Network::new(NetworkPolicy::default());
        let dev = text(File::Dev, network());
        assert_eq!(dev.lines().count(), 3);
        assert!(dev.ends_with(
            "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        ));
        assert_eq!(
            text(File::IfInet6, network()),
            "00000000000000000000000000000001 01 80 10 80       lo\n"
        );
        assert_eq!(
            text(File::Arp, network()),
            "IP address       HW type     Flags       HW address            Mask     Device\n"
        );
        let routes = text(File::Ipv6Route, network());
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
    fn addresses_are_words_in_host_order() {
        let at = |text: &str, v6| address(text.parse().unwrap(), v6);
        assert_eq!(at("127.0.0.1:1001", false), "0100007F:03E9");
        assert_eq!(
            at("[2001:db8::7]:80", true),
            "B80D0120000000000000000007000000:0050"
        );
        // An IPv4 address of an IPv6 socket.
        assert_eq!(
            at("127.0.0.1:80", true),
            "0000000000000000FFFF00000100007F:0050"
        );
    }

    #[test]
    fn a_kind_there_is_no_socket_of_has_its_header() {
        let text = |file| text(file, Network::new(NetworkPolicy::default()));
        let common = "local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";
        assert_eq!(text(File::Raw), format!("  sl  {common}\n"));
        assert_eq!(text(File::Icmp), format!("  sl  {common}{:13}\n", ""));
        assert_eq!(text(File::Udp), format!("   sl  {common}{:12}\n", ""));
        assert_eq!(text(File::Raw6), text(File::Icmp6));
        assert_eq!(text(File::Raw6), text(File::Udp6));
        assert_eq!(text(File::Tcp).len(), 150);
        for file in File::ALL {
            let lines = text(file).lines().count();
            if matches!(
                file,
                File::Raw | File::Raw6 | File::Icmp | File::Icmp6 | File::Packet
            ) {
                assert_eq!(lines, 1, "{file:?}");
            }
        }
    }

    #[test]
    fn the_first_namespace_has_lo_in_all_hosts() {
        let network = || Network::new(NetworkPolicy::default());
        assert_eq!(
            text(File::Igmp, network()),
            "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
             1\tlo        :     1      V3\n\
             \t\t\t\t010000E0     1 0:00000000\t\t0\n"
        );
        assert_eq!(
            text(File::Igmp6, network()),
            format!(
                "1    lo              {:032x}     1 0000000C 0\n\
                 1    lo              {:032x}     1 00000008 0\n",
                u128::from(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
                u128::from(Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1)),
            )
        );
        assert_eq!(text(File::Mcfilter, network()).lines().count(), 1);
        assert_eq!(text(File::Mcfilter6, network()).lines().count(), 1);
    }

    #[test]
    fn sources_begin_at_the_first_device_whose_newest_group_names_one() {
        let group = |n: u8| Ipv4Addr::new(239, 0, 0, n);
        let named: &[(Ipv4Addr, crate::multicast::Counts)] =
            &[(Ipv4Addr::new(10, 0, 0, 1), [1, 2])];
        let devices = |first: bool| {
            vec![
                (
                    1,
                    "lo".to_owned(),
                    vec![
                        (group(1), 1, if first { named } else { &[] }),
                        (group(2), 1, named),
                    ],
                ),
                (
                    2,
                    "a-long-name".to_owned(),
                    vec![(group(4), 1, named), (group(3), 1, &[][..])],
                ),
            ]
        };
        let lines = |first| {
            let mut out = String::new();
            sources(&mut out, devices(first).into_iter(), |ip: Ipv4Addr| {
                ip.to_string()
            });
            out
        };
        assert_eq!(
            lines(false),
            "  2 a-long 239.0.0.4 10.0.0.1      2      1\n"
        );
        assert_eq!(lines(true).lines().count(), 3);
    }

    #[test]
    fn a_session_without_a_network_has_no_device() {
        assert_eq!(
            File::Dev
                .text(&source(None), None)
                .iter()
                .filter(|&&b| b == b'\n')
                .count(),
            2
        );
        for file in [File::Route, File::IfInet6, File::Ipv6Route] {
            assert!(file.text(&source(None), None).is_empty());
        }
        assert!(File::Igmp6.text(&source(None), None).is_empty());
        for file in [File::Igmp, File::Mcfilter, File::Mcfilter6] {
            assert_eq!(
                file.text(&source(None), None)
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count(),
                1
            );
        }
    }
}
