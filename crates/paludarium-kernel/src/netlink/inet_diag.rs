//! `inet_diag`, `NETLINK_SOCK_DIAG`'s handler of AF_INET and AF_INET6, with
//! its TCP and UDP handlers (`tcp_diag`, `udp_diag`), as in a kernel built
//! without the others and without `CONFIG_INET_DIAG_DESTROY`.
//!
//! A `SOCK_DIAG_BY_FAMILY` request dumps the namespace's sockets of one
//! protocol that its states, ports and filter (`INET_DIAG_REQ_BYTECODE`,
//! as `ss` makes one) take, or answers for one socket by its addresses and
//! ports; the old `TCPDIAG_GETSOCK` does the same for TCP. Each socket is
//! told as `inet_sk_diag_fill` makes it, and a hold in `TIME_WAIT` as
//! `tcp_twsk_diag_fill` does.
use super::{Errno, Header, NLM_F_DUMP, NLM_F_MULTI, NLMSG_DONE, NetlinkSocket, Sender, State};
use super::{align, attribute, attributes, message};
use crate::inet::{Entry, Table};
use crate::users::Ids;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const TCPDIAG_GETSOCK: u16 = 18;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
/// An `inet_diag_req_v2`'s length, and an `inet_diag_req`'s.
const REQUEST: usize = 56;
const OLD_REQUEST: usize = 60;
const INET_DIAG_REQ_BYTECODE: u16 = 1;
const INET_DIAG_REQ_SK_BPF_STORAGES: u16 = 2;
const INET_DIAG_REQ_PROTOCOL: u16 = 3;
const SK_DIAG_BPF_STORAGE_REQ_MAP_FD: u16 = 1;
const INET_DIAG_MEMINFO: u16 = 1;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_TOS: u16 = 5;
const INET_DIAG_TCLASS: u16 = 6;
const INET_DIAG_SKMEMINFO: u16 = 7;
const INET_DIAG_SHUTDOWN: u16 = 8;
const INET_DIAG_SKV6ONLY: u16 = 11;
const INET_DIAG_MARK: u16 = 15;
const INET_DIAG_CLASS_ID: u16 = 17;
const INET_DIAG_CGROUP_ID: u16 = 21;
const INET_DIAG_SOCKOPT: u16 = 22;
const TCP_SYN_RECV: u8 = 3;
const TCP_CLOSE: u8 = 7;
const TCP_LISTEN: u8 = 10;
const TCP_NEW_SYN_RECV: u8 = 12;
const TCP_BOUND_INACTIVE: u8 = 13;
/// The cgroup every socket is in: the root, as there is no other.
const ROOT_CGROUP: u64 = 1;
/// The congestion control every connection has, Linux's default.
const CONGESTION: &[u8] = b"cubic\0";
const ENOENT: Errno = Errno::ENOENT;
const EINVAL: Errno = Errno::EINVAL;
const EPERM: Errno = Errno(1);
const EOPNOTSUPP: Errno = Errno::EOPNOTSUPP;
const EBUSY: Errno = Errno(16);
const ESTALE: Errno = Errno(116);
const NO_COOKIE: u64 = u64::MAX;

/// A request, as `inet_diag_req_v2` holds it, the old `inet_diag_req`
/// taken into one as `inet_diag_dump_compat` does.
struct Request {
    family: u8,
    protocol: u32,
    ext: u8,
    states: u32,
    /// Its `inet_diag_sockid`: ports as they come, in network order.
    source_port: u16,
    destination_port: u16,
    source: [u8; 16],
    destination: [u8; 16],
    cookie: u64,
}
impl Request {
    fn read(payload: &[u8], old: bool) -> Self {
        let word = |i: usize| u32::from_le_bytes(payload[i..i + 4].try_into().unwrap_or_default());
        let (id, ext, states) = if old {
            (4, payload[3], word(52))
        } else {
            (8, payload[2], word(4))
        };
        let mut source = [0; 16];
        let mut destination = [0; 16];
        source.copy_from_slice(&payload[id + 4..id + 20]);
        destination.copy_from_slice(&payload[id + 20..id + 36]);
        Self {
            family: payload[0],
            protocol: if old {
                IPPROTO_TCP
            } else {
                u32::from(payload[1])
            },
            ext,
            states,
            source_port: u16::from_be_bytes([payload[id], payload[id + 1]]),
            destination_port: u16::from_be_bytes([payload[id + 2], payload[id + 3]]),
            source,
            destination,
            cookie: u64::from(word(id + 40)) | u64::from(word(id + 44)) << 32,
        }
    }
}

impl NetlinkSocket {
    /// An AF_INET or AF_INET6 request, or a `TCPDIAG_GETSOCK` one, as
    /// `inet_diag_handler_cmd` and `inet_diag_rcv_msg_compat` take it: too
    /// short is `EINVAL`; a `SOCK_DIAG_BY_FAMILY` with `NLM_F_DUMP` dumps,
    /// any other asks for one socket. `Ok(true)` is a dump that began.
    pub(super) fn inet(
        &self,
        s: &mut State,
        header: &Header,
        payload: &[u8],
        port: u32,
        sender: Sender,
    ) -> Result<bool, Errno> {
        let old = header.kind == TCPDIAG_GETSOCK;
        let length = if old { OLD_REQUEST } else { REQUEST };
        if payload.len() < length {
            return Err(EINVAL);
        }
        let dump = header.flags & NLM_F_DUMP != 0 && (old || header.kind == SOCK_DIAG_BY_FAMILY);
        // `netlink_dump_start` finds one running before its `start` reads
        // the request.
        if dump && s.done.is_some() {
            return Err(EBUSY);
        }
        let mut request = Request::read(payload, old);
        let attached = payload.get(align(length)..).unwrap_or_default();
        let mut found: [Option<&[u8]>; 4] = [None; 4];
        for (kind, value) in attributes(attached) {
            if kind == INET_DIAG_REQ_PROTOCOL && value.len() != 4 {
                return Err(EINVAL);
            }
            if let Some(slot) = found.get_mut(usize::from(kind)) {
                *slot = Some(value);
            }
        }
        if let Some(value) = found[usize::from(INET_DIAG_REQ_PROTOCOL)] {
            request.protocol = u32::from_le_bytes(value.try_into().unwrap_or_default());
        }
        if !dump {
            if !matches!(request.protocol, IPPROTO_TCP | IPPROTO_UDP) {
                return Err(ENOENT);
            }
            if header.kind != SOCK_DIAG_BY_FAMILY && !old {
                return Err(EOPNOTSUPP);
            }
            let entry = self.exact(&request)?;
            let reply = self.inet_message(&entry, &request, header, port, 0, sender.admin);
            self.deliver(s, 0, 0, reply);
            return Ok(false);
        }
        // `inet_diag_dump_start`.
        let filter = found[usize::from(INET_DIAG_REQ_BYTECODE)];
        if let Some(code) = filter {
            audit(code, sender.admin)?;
        }
        if let Some(storages) = found[usize::from(INET_DIAG_REQ_SK_BPF_STORAGES)] {
            // `bpf_sk_storage_diag_alloc`: no descriptor here is a BPF map.
            if !sender.bpf {
                return Err(EPERM);
            }
            let maps = attributes(storages)
                .into_iter()
                .any(|(kind, _)| kind == SK_DIAG_BPF_STORAGE_REQ_MAP_FD);
            if maps {
                return Err(EINVAL);
            }
        }
        if old {
            request.family = AF_UNSPEC;
        }
        let (messages, error) = match request.protocol {
            IPPROTO_TCP | IPPROTO_UDP => {
                let entries = self.network.diag(self.now());
                let messages = self
                    .dumped(&entries, &request, filter)
                    .map(|entry| {
                        self.inet_message(entry, &request, header, port, NLM_F_MULTI, sender.admin)
                    })
                    .collect();
                (messages, 0)
            }
            // `__inet_diag_dump` finds no handler, which `NLMSG_DONE` tells.
            _ => (Vec::new(), -ENOENT.0),
        };
        let done = message(
            NLMSG_DONE,
            NLM_F_MULTI,
            header.seq,
            port,
            &error.to_le_bytes(),
        );
        self.start_dump(s, messages, done);
        Ok(true)
    }
    /// The host's monotonic time, which the timers count from.
    fn now(&self) -> Option<u64> {
        self.host.clock(paludarium_host::ClockId::Monotonic).ok()
    }
    /// What a dump lists, in Linux's order of tables: for TCP the listeners
    /// (unless a destination port is asked for), then the closed sockets
    /// that hold a port, then the connections, each as `tcp_diag_dump`
    /// takes them; for UDP its sockets as `udp_diag_dump` does.
    fn dumped<'a>(
        &self,
        entries: &'a [Entry],
        request: &'a Request,
        filter: Option<&'a [u8]>,
    ) -> impl Iterator<Item = &'a Entry> {
        let udp = request.protocol == IPPROTO_UDP;
        let mut states = request.states;
        if !udp && states & (1 << TCP_SYN_RECV) != 0 {
            states |= 1 << TCP_NEW_SYN_RECV;
        }
        let family =
            |entry: &Entry| request.family == AF_UNSPEC || request.family == family_of(entry);
        let ports = |entry: &Entry| {
            (request.source_port == 0 || request.source_port == entry.local.port())
                && (request.destination_port == 0
                    || request.destination_port == entry.peer.map_or(0, |peer| peer.port()))
        };
        let passes = move |entry: &Entry| filter.is_none_or(|code| run(code, &filter_entry(entry)));
        let tables: Vec<Table> = if udp {
            vec![Table::Connected]
        } else {
            let mut tables = Vec::new();
            if states & (1 << TCP_LISTEN) != 0 && request.destination_port == 0 {
                tables.push(Table::Listening);
            }
            if states & (1 << TCP_BOUND_INACTIVE) != 0 {
                tables.push(Table::Bound);
            }
            if states & !(1 << TCP_LISTEN) != 0 {
                tables.push(Table::Connected);
            }
            tables
        };
        tables.into_iter().flat_map(move |table| {
            entries.iter().filter(move |entry| {
                entry.udp == udp
                    && entry.table == table
                    && match table {
                        Table::Listening => {
                            request.source_port == 0 || request.source_port == entry.local.port()
                        }
                        Table::Bound => true,
                        Table::Connected => states & (1 << entry.state) != 0 && ports(entry),
                    }
                    && family(entry)
                    && passes(entry)
            })
        })
    }
    /// The one socket a request names, as `tcp_diag_find_one_icsk` and
    /// `udp_diag_dump_one` look it up: TCP as a segment from the request's
    /// destination to its source would find it, a connection before a
    /// listener; UDP as a datagram from its source to its destination
    /// would, the addresses swapped "for historical reasons". A cookie that
    /// does not match is `ENOENT` for TCP and `ESTALE` for UDP.
    fn exact(&self, request: &Request) -> Result<Entry, Errno> {
        let udp = request.protocol == IPPROTO_UDP;
        let v6 = match request.family {
            AF_INET => false,
            AF_INET6 => true,
            _ if udp => return Err(ENOENT),
            _ => return Err(EINVAL),
        };
        let address = |raw: &[u8; 16]| -> IpAddr {
            if v6 {
                IpAddr::V6(Ipv6Addr::from(*raw))
            } else {
                IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
            }
        };
        let source = SocketAddr::new(address(&request.source), request.source_port);
        let destination = SocketAddr::new(address(&request.destination), request.destination_port);
        // A TCP lookup of two IPv4-mapped addresses is IPv4's.
        let (source, destination, v6) = match (plain(source), plain(destination)) {
            (s, d) if !udp && v6 && s.is_ipv4() && d.is_ipv4() => (s, d, false),
            _ => (source, destination, v6),
        };
        let mut entries = self.network.diag(self.now());
        let best = if udp {
            best(&entries, |entry| udp_score(entry, v6, source, destination))
        } else {
            best(&entries, |entry| {
                (entry.table == Table::Connected
                    && covers(entry, v6)
                    && plain(entry.local) == plain(source)
                    && entry.peer.map(plain) == Some(plain(destination)))
                .then_some(16)
            })
            .or_else(|| best(&entries, |entry| listener_score(entry, v6, source)))
        };
        let entry = entries.swap_remove(best.ok_or(ENOENT)?);
        // `sock_diag_check_cookie`.
        if request.cookie != NO_COOKIE && request.cookie != entry.cookie {
            return Err(if udp { ESTALE } else { ENOENT });
        }
        Ok(entry)
    }
    /// A socket's `inet_diag_msg` and its attributes, as
    /// `inet_sk_diag_fill` makes them, or a hold's in `TIME_WAIT`, as
    /// `tcp_twsk_diag_fill` does: only `CAP_NET_ADMIN` is told its mark.
    fn inet_message(
        &self,
        entry: &Entry,
        request: &Request,
        header: &Header,
        port: u32,
        flags: u16,
        admin: bool,
    ) -> Vec<u8> {
        let now = self.now();
        let mut out = vec![family_of(entry), entry.state, entry.timer.0, entry.timer.1];
        out.extend_from_slice(&entry.local.port().to_be_bytes());
        out.extend_from_slice(&entry.peer.map_or(0, |peer| peer.port()).to_be_bytes());
        out.extend_from_slice(&address_bytes(entry.local.ip(), entry.v6));
        out.extend_from_slice(&address_bytes(peer_ip(entry), entry.v6));
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&entry.cookie.to_le_bytes());
        // `jiffies_delta_to_msecs`, which takes a past time as 0.
        let expires = match (entry.timer.2, now) {
            (Some(until), Some(now)) => until.saturating_sub(now).div_ceil(1_000_000),
            _ => 0,
        };
        out.extend_from_slice(&(expires.min(u64::from(u32::MAX)) as u32).to_le_bytes());
        out.extend_from_slice(&entry.queues.0.to_le_bytes());
        out.extend_from_slice(&entry.queues.1.to_le_bytes());
        let Some(full) = &entry.full else {
            out.extend_from_slice(&[0; 8]);
            if admin {
                attribute(&mut out, INET_DIAG_MARK, &0u32.to_le_bytes());
            }
            return message(header.kind, flags, header.seq, port, &out);
        };
        let uid = self.opener_user.shown(Ids::User, full.uid);
        out.extend_from_slice(&uid.to_le_bytes());
        out.extend_from_slice(&(full.inode as u32).to_le_bytes());
        // `inet_diag_msg_attrs_fill`.
        let ext = request.ext;
        attribute(&mut out, INET_DIAG_SHUTDOWN, &[full.shutdown]);
        if ext & bit(INET_DIAG_TOS) != 0 {
            attribute(&mut out, INET_DIAG_TOS, &[full.type_of_service]);
        }
        if entry.v6 {
            if ext & bit(INET_DIAG_TCLASS) != 0 {
                attribute(&mut out, INET_DIAG_TCLASS, &[0]);
            }
            if matches!(entry.state, TCP_LISTEN | TCP_CLOSE) {
                attribute(&mut out, INET_DIAG_SKV6ONLY, &[u8::from(full.v6_only)]);
            }
        }
        if admin {
            attribute(&mut out, INET_DIAG_MARK, &0u32.to_le_bytes());
        }
        // Without a class from the cgroup, the priority.
        if ext & bit(INET_DIAG_TCLASS) != 0 {
            attribute(&mut out, INET_DIAG_CLASS_ID, &full.priority.to_le_bytes());
        }
        attribute(&mut out, INET_DIAG_CGROUP_ID, &ROOT_CGROUP.to_le_bytes());
        // `inet_diag_sockopt`: `is_icsk` for TCP, and `mc_loop`, with
        // `mc_all` for IPv4, as `inet_create` and `inet6_create` set them.
        let sockopt = u8::from(!entry.udp) << 1 | 1 << 4 | u8::from(!entry.v6) << 6;
        attribute(&mut out, INET_DIAG_SOCKOPT, &[sockopt, 0]);
        // What its datagrams take is charged in whole pages, the rest kept
        // as its forward allocation (`udp_rmem_schedule`).
        let received = full.received;
        let forward = received.next_multiple_of(4096) - received;
        if ext & bit(INET_DIAG_MEMINFO) != 0 {
            let memory: Vec<u8> = [received, 0, forward, 0]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            attribute(&mut out, INET_DIAG_MEMINFO, &memory);
        }
        if ext & bit(INET_DIAG_SKMEMINFO) != 0 {
            let memory: Vec<u8> = [
                received,
                full.receive_buffer,
                0,
                full.send_buffer,
                forward,
                0,
                0,
                0,
                full.drops,
            ]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
            attribute(&mut out, INET_DIAG_SKMEMINFO, &memory);
        }
        // A TCP socket that is not closed has its connection's state, but
        // not `tcp_info`, which nothing here keeps.
        if !entry.udp && entry.table != Table::Bound && ext & bit(INET_DIAG_CONG) != 0 {
            attribute(&mut out, INET_DIAG_CONG, CONGESTION);
        }
        message(header.kind, flags, header.seq, port, &out)
    }
}

/// The bit of `idiag_ext` that asks for `attribute`.
fn bit(attribute: u16) -> u8 {
    1 << (attribute - 1)
}
fn family_of(entry: &Entry) -> u8 {
    if entry.v6 { AF_INET6 } else { AF_INET }
}
/// An address as `inet_diag_sockid` holds it: IPv4 in its first word, or
/// for an IPv6 socket IPv6, with IPv4 mapped.
fn address_bytes(ip: IpAddr, v6: bool) -> [u8; 16] {
    match (ip, v6) {
        (IpAddr::V4(v4), false) => {
            let mut out = [0; 16];
            out[..4].copy_from_slice(&v4.octets());
            out
        }
        (IpAddr::V4(v4), true) => v4.to_ipv6_mapped().octets(),
        (IpAddr::V6(v6), _) => v6.octets(),
    }
}
/// The peer's address, or with none the family's unspecified one.
fn peer_ip(entry: &Entry) -> IpAddr {
    match entry.peer {
        Some(peer) => peer.ip(),
        None if entry.v6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}
/// An address with IPv4-mapped IPv6 taken as IPv4.
fn plain(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), address.port()),
            None => address,
        },
        IpAddr::V4(_) => address,
    }
}
/// Whether a lookup in IPv6's connections (`v6`) or IPv4's finds `entry`:
/// an IPv6 socket's connection over IPv4 is in IPv4's.
fn covers(entry: &Entry, v6: bool) -> bool {
    plain(entry.local).is_ipv4() != v6
}
/// The index of the entry `score` ranks highest, the first among equals.
fn best(entries: &[Entry], score: impl Fn(&Entry) -> Option<u32>) -> Option<usize> {
    let mut found: Option<(u32, usize)> = None;
    for (i, entry) in entries.iter().enumerate() {
        if let Some(score) = score(entry)
            && found.is_none_or(|(best, _)| score > best)
        {
            found = Some((score, i));
        }
    }
    found.map(|(_, i)| i)
}
/// How a TCP listener ranks for a connection to `to`, as Linux's
/// `compute_score` and its two passes do: bound to that address before
/// bound to every one, and IPv4 before IPv6. An IPv6-only socket takes no
/// IPv4.
fn listener_score(entry: &Entry, v6: bool, to: SocketAddr) -> Option<u32> {
    let full = entry.full.as_ref()?;
    if entry.udp || entry.table != Table::Listening || entry.local.port() != to.port() {
        return None;
    }
    if !v6 && entry.v6 && full.v6_only {
        return None;
    }
    if v6 && !entry.v6 {
        return None;
    }
    let bound = plain(entry.local).ip();
    let exact = if bound.is_unspecified() {
        false
    } else if bound == plain(to).ip() {
        true
    } else {
        return None;
    };
    Some(u32::from(exact) * 4 + u32::from(!entry.v6) + 1)
}
/// How a UDP socket ranks for a datagram from `from` to `to`, as Linux's
/// UDP `compute_score`: IPv4 before IPv6, then bound to that address, and
/// connected to `from`.
fn udp_score(entry: &Entry, v6: bool, from: SocketAddr, to: SocketAddr) -> Option<u32> {
    let full = entry.full.as_ref()?;
    if !entry.udp || entry.local.port() != to.port() {
        return None;
    }
    if (v6 && !entry.v6) || (!v6 && entry.v6 && full.v6_only) {
        return None;
    }
    let mut score = if entry.v6 { 1 } else { 2 };
    let bound = plain(entry.local).ip();
    if !bound.is_unspecified() {
        if bound != plain(to).ip() {
            return None;
        }
        score += 4;
    }
    if let Some(peer) = entry.peer {
        if plain(peer) != plain(from) {
            return None;
        }
        score += 8;
    }
    Some(score)
}

/// What a filter tests of a socket (`inet_diag_entry`): addresses as
/// `inet_diag_sockid` holds them, ports in host order.
struct FilterEntry {
    family: u8,
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    port_locked: bool,
    cgroup: u64,
}
fn filter_entry(entry: &Entry) -> FilterEntry {
    FilterEntry {
        family: family_of(entry),
        source: address_bytes(entry.local.ip(), entry.v6),
        destination: address_bytes(peer_ip(entry), entry.v6),
        source_port: entry.local.port(),
        destination_port: entry.peer.map_or(0, |peer| peer.port()),
        port_locked: entry.full.as_ref().is_some_and(|full| full.port_locked),
        cgroup: if entry.full.is_some() { ROOT_CGROUP } else { 0 },
    }
}

const BC_NOP: u8 = 0;
const BC_JMP: u8 = 1;
const BC_S_GE: u8 = 2;
const BC_S_LE: u8 = 3;
const BC_D_GE: u8 = 4;
const BC_D_LE: u8 = 5;
const BC_AUTO: u8 = 6;
const BC_S_COND: u8 = 7;
const BC_D_COND: u8 = 8;
const BC_DEV_COND: u8 = 9;
const BC_MARK_COND: u8 = 10;
const BC_S_EQ: u8 = 11;
const BC_D_EQ: u8 = 12;
const BC_CGROUP_COND: u8 = 13;

/// An `inet_diag_bc_op` at `at` of `code`: its code, and the steps forward
/// when its test passes and when it fails. Bytes past the end read as 0.
fn op(code: &[u8], at: usize) -> (u8, usize, usize) {
    let byte = |i: usize| code.get(at + i).copied().unwrap_or(0);
    (
        byte(0),
        usize::from(byte(1)),
        usize::from(u16::from_le_bytes([byte(2), byte(3)])),
    )
}
/// Checks a filter, as `inet_diag_bc_audit`: every operation is known,
/// takes the arguments it needs, and steps forward by whole operations to
/// within the code or just past its end; a mark test needs `CAP_NET_ADMIN`
/// (`EPERM`). Anything else is `EINVAL`.
fn audit(code: &[u8], admin: bool) -> Result<(), Errno> {
    if code.len() < 4 {
        return Err(EINVAL);
    }
    let total = code.len() as i64;
    let mut at = 0usize;
    let mut len = total;
    while len > 0 {
        let (kind, yes, no) = op(code, at);
        let mut least = 4i64;
        let byte = |i: usize| code.get(at + i).copied().unwrap_or(0);
        match kind {
            BC_S_COND | BC_D_COND => {
                // An `inet_diag_hostcond` and its address.
                least += 8;
                if len < least {
                    return Err(EINVAL);
                }
                let address = match byte(4) {
                    AF_UNSPEC => 0,
                    AF_INET => 4,
                    AF_INET6 => 16,
                    _ => return Err(EINVAL),
                };
                least += address;
                if len < least || i64::from(byte(5)) > 8 * address {
                    return Err(EINVAL);
                }
            }
            BC_DEV_COND | BC_S_EQ | BC_S_GE | BC_S_LE | BC_D_EQ | BC_D_GE | BC_D_LE => {
                least += 4;
                if len < least {
                    return Err(EINVAL);
                }
            }
            BC_MARK_COND => {
                if !admin {
                    return Err(EPERM);
                }
                least += 8;
                if len < least {
                    return Err(EINVAL);
                }
            }
            BC_CGROUP_COND => {
                least += 8;
                if len < least {
                    return Err(EINVAL);
                }
            }
            BC_AUTO | BC_JMP | BC_NOP => {}
            _ => return Err(EINVAL),
        }
        let steps = |step: usize| {
            let step = step as i64;
            step >= least && step <= len + 4 && step & 3 == 0
        };
        if kind != BC_NOP {
            if !steps(no) {
                return Err(EINVAL);
            }
            if (no as i64) < len && !valid_target(code, total, len - no as i64) {
                return Err(EINVAL);
            }
        }
        if !steps(yes) {
            return Err(EINVAL);
        }
        at += yes;
        len -= yes as i64;
    }
    if len == 0 { Ok(()) } else { Err(EINVAL) }
}
/// Whether stepping through the code from its start by each operation's
/// `yes` comes to where `left` bytes remain (`valid_cc`).
fn valid_target(code: &[u8], mut len: i64, left: i64) -> bool {
    let mut at = 0usize;
    while len >= 0 {
        if left > len {
            return false;
        }
        if left == len {
            return true;
        }
        let (_, yes, _) = op(code, at);
        if yes < 4 || yes & 3 != 0 {
            return false;
        }
        len -= yes as i64;
        at += yes;
    }
    false
}
/// Runs a filter that [`audit`] passed over `entry`, as
/// `inet_diag_bc_run`: whether it ends exactly at the code's end.
fn run(code: &[u8], entry: &FilterEntry) -> bool {
    let mut at = 0usize;
    let mut len = code.len() as i64;
    let word = |i: usize| u16::from_le_bytes([code[i], code[i + 1]]);
    while len > 0 {
        let (kind, yes_step, no_step) = op(code, at);
        // A port test's port is in the next operation's `no`.
        let port = || word(at + 6);
        let yes = match kind {
            BC_JMP => false,
            BC_S_EQ => entry.source_port == port(),
            BC_S_GE => entry.source_port >= port(),
            BC_S_LE => entry.source_port <= port(),
            BC_D_EQ => entry.destination_port == port(),
            BC_D_GE => entry.destination_port >= port(),
            BC_D_LE => entry.destination_port <= port(),
            BC_AUTO => !entry.port_locked,
            BC_S_COND | BC_D_COND => host_matches(code, at, kind == BC_S_COND, entry),
            BC_DEV_COND => {
                u32::from_le_bytes(code[at + 4..at + 8].try_into().unwrap_or_default()) == 0
            }
            BC_MARK_COND => {
                u32::from_le_bytes(code[at + 4..at + 8].try_into().unwrap_or_default()) == 0
            }
            BC_CGROUP_COND => {
                u64::from_le_bytes(code[at + 4..at + 12].try_into().unwrap_or_default())
                    == entry.cgroup
            }
            _ => true,
        };
        let step = if yes { yes_step } else { no_step };
        at += step;
        len -= step as i64;
    }
    len == 0
}
/// An `inet_diag_hostcond` at `at`: a port, unless -1, and an address
/// prefix of a family, unless `AF_UNSPEC`; an IPv4 one also matches an
/// IPv6 socket's IPv4-mapped address.
fn host_matches(code: &[u8], at: usize, source: bool, entry: &FilterEntry) -> bool {
    let family = code[at + 4];
    let prefix = usize::from(code[at + 5]);
    let port = i32::from_le_bytes(code[at + 8..at + 12].try_into().unwrap_or_default());
    let own_port = if source {
        entry.source_port
    } else {
        entry.destination_port
    };
    if port != -1 && port != i32::from(own_port) {
        return false;
    }
    let address = if source {
        &entry.source
    } else {
        &entry.destination
    };
    let wanted = &code[at + 12..];
    if family != AF_UNSPEC && family != entry.family {
        return entry.family == AF_INET6
            && family == AF_INET
            && address[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
            && prefix_matches(&address[12..], wanted, prefix);
    }
    prefix == 0 || prefix_matches(address, wanted, prefix)
}
/// Whether the first `bits` bits of `a` and `b` agree (`bitstring_match`).
fn prefix_matches(a: &[u8], b: &[u8], bits: usize) -> bool {
    let (whole, rest) = (bits / 8, bits % 8);
    if a.len() < whole + usize::from(rest != 0) || b.len() < whole + usize::from(rest != 0) {
        return false;
    }
    if a[..whole] != b[..whole] {
        return false;
    }
    rest == 0 || (a[whole] ^ b[whole]) & (0xff << (8 - rest)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op_bytes(code: u8, yes: u8, no: u16) -> Vec<u8> {
        let mut out = vec![code, yes];
        out.extend_from_slice(&no.to_le_bytes());
        out
    }
    fn entry(source_port: u16, destination_port: u16) -> FilterEntry {
        FilterEntry {
            family: AF_INET,
            source: address_bytes(IpAddr::V4(Ipv4Addr::LOCALHOST), false),
            destination: address_bytes(IpAddr::V4(Ipv4Addr::LOCALHOST), false),
            source_port,
            destination_port,
            port_locked: true,
            cgroup: ROOT_CGROUP,
        }
    }

    #[test]
    fn port_tests_jump_as_inet_diag_bc_run() {
        // sport >= 1000 and sport <= 2000, as `ss` makes it.
        let mut code = op_bytes(BC_S_GE, 8, 20);
        code.extend(op_bytes(0, 0, 1000));
        code.extend(op_bytes(BC_S_LE, 8, 12));
        code.extend(op_bytes(0, 0, 2000));
        assert_eq!(audit(&code, false), Ok(()));
        assert!(run(&code, &entry(1500, 0)));
        assert!(!run(&code, &entry(999, 0)));
        assert!(!run(&code, &entry(2001, 0)));
    }

    #[test]
    fn audits_refuse_what_linux_refuses() {
        assert_eq!(audit(&[0, 4], false), Err(EINVAL));
        assert_eq!(audit(&op_bytes(99, 4, 4), false), Err(EINVAL));
        // A step that is no whole operation, or past the end.
        assert_eq!(audit(&op_bytes(BC_NOP, 2, 0), false), Err(EINVAL));
        assert_eq!(audit(&op_bytes(BC_JMP, 4, 12), false), Err(EINVAL));
        assert_eq!(audit(&op_bytes(BC_JMP, 4, 8), false), Ok(()));
        let mut mark = op_bytes(BC_MARK_COND, 12, 16);
        mark.extend_from_slice(&[0; 8]);
        assert_eq!(audit(&mark, false), Err(EPERM));
        assert_eq!(audit(&mark, true), Ok(()));
        // A prefix longer than its address.
        let mut host = op_bytes(BC_S_COND, 16, 20);
        host.extend_from_slice(&[AF_INET, 33, 0, 0]);
        host.extend_from_slice(&(-1i32).to_le_bytes());
        host.extend_from_slice(&[127, 0, 0, 1]);
        assert_eq!(audit(&host, false), Err(EINVAL));
        host[5] = 8;
        assert_eq!(audit(&host, false), Ok(()));
        assert!(run(&host, &entry(1, 2)));
        host[12] = 10;
        assert!(!run(&host, &entry(1, 2)));
    }

    #[test]
    fn ipv4_conditions_match_mapped_addresses() {
        let mut host = op_bytes(BC_D_COND, 16, 20);
        host.extend_from_slice(&[AF_INET, 32, 0, 0]);
        host.extend_from_slice(&(-1i32).to_le_bytes());
        host.extend_from_slice(&[127, 0, 0, 1]);
        let mut mapped = entry(1, 2);
        mapped.family = AF_INET6;
        mapped.destination = address_bytes(IpAddr::V4(Ipv4Addr::LOCALHOST), true);
        assert!(run(&host, &mapped));
        mapped.destination = Ipv6Addr::LOCALHOST.octets();
        assert!(!run(&host, &mapped));
    }

    #[test]
    fn prefixes_compare_by_bits() {
        assert!(prefix_matches(&[10, 1, 2, 3], &[10, 1, 255, 0], 16));
        assert!(!prefix_matches(&[10, 1, 2, 3], &[10, 1, 255, 0], 17));
        assert!(prefix_matches(&[0b1010_0000], &[0b1011_1111], 3));
        assert!(!prefix_matches(&[0b1010_0000], &[0b1011_1111], 4));
    }

    #[test]
    fn requests_read_both_layouts() {
        let mut raw = [0u8; 60];
        raw[0] = AF_INET6;
        raw[1] = 17;
        raw[2] = 0x41;
        raw[4..8].copy_from_slice(&0x400u32.to_le_bytes());
        raw[8..10].copy_from_slice(&8080u16.to_be_bytes());
        raw[12] = 0xfe;
        raw[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
        let request = Request::read(&raw, false);
        assert_eq!(
            (
                request.family,
                request.protocol,
                request.ext,
                request.states
            ),
            (AF_INET6, 17, 0x41, 0x400)
        );
        assert_eq!((request.source_port, request.source[0]), (8080, 0xfe));
        assert_eq!(request.cookie, NO_COOKIE);
        let mut old = [0u8; 60];
        old[0] = AF_INET;
        old[3] = 0x4;
        old[4..6].copy_from_slice(&22u16.to_be_bytes());
        old[52..56].copy_from_slice(&0xfffu32.to_le_bytes());
        let request = Request::read(&old, true);
        assert_eq!(
            (
                request.protocol,
                request.ext,
                request.states,
                request.source_port
            ),
            (IPPROTO_TCP, 0x4, 0xfff, 22)
        );
    }
}
