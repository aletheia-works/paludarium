//! `AF_INET` and `AF_INET6` sockets, when the session allows a network.
//!
//! A TCP socket connects through the host ([`paludarium_host::net`]) to the
//! destinations [`NetworkPolicy`] allows, and behaves as Linux's TCP does
//! for a client. Port 53, at any address, is the built-in DNS stub instead,
//! over UDP (the only destination a UDP socket has) and over TCP: a query is
//! answered from the host's resolver for an allowed name and with
//! `NXDOMAIN` for any other, so the guest's own resolver
//! (`/etc/resolv.conf`, or its default) works unchanged.
//!
//! On the guest's own loopback a TCP socket also binds, listens and accepts
//! ([`crate::loopback`]): a connection to a loopback address where a guest
//! socket listens reaches it in the kernel, whatever the policy allows.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::fasync::{FileOwner, Notice, O_ASYNC, Reason, Registration};
use crate::loopback::{Binding, Link, Ports};
use crate::sockets::Timeout;
use crate::syscalls::Context;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use paludarium_host::net::{Driver, Event, Lookup, Phase, Stream};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

const AF_UNSPEC: u16 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const IPPROTO_ICMP: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const IPPROTO_ICMPV6: u64 = 58;
const ENOTSOCK: Errno = Errno(88);
const EDESTADDRREQ: Errno = Errno(89);
const ENOPROTOOPT: Errno = Errno(92);
const EPROTONOSUPPORT: Errno = Errno(93);
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EOPNOTSUPP: Errno = Errno(95);
const EAFNOSUPPORT: Errno = Errno(97);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENETUNREACH: Errno = Errno(101);
const ECONNABORTED: Errno = Errno(103);
const EISCONN: Errno = Errno(106);
const ENOTCONN: Errno = Errno(107);
const EALREADY: Errno = Errno(114);
const EINPROGRESS: Errno = Errno(115);
const ECONNREFUSED: Errno = Errno(111);
const EMSGSIZE: Errno = Errno(90);
/// Linux's default `net.core.somaxconn`, the most a `listen` backlog is.
const SOMAXCONN: u32 = 4096;
const POLLERR: u32 = 8;
const POLLHUP: u32 = 0x10;
const POLLRDHUP: u32 = 0x2000;
const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
/// The DNS port, whose datagrams the stub answers.
const DNS: u16 = 53;
/// How long a resolved name is reused before it is looked up again.
const LOOKUP_LIFETIME: u64 = 30_000_000_000;
/// How long after the stub last gave an address for a name the guest may
/// still connect to it under that name.
const NAME_LIFETIME: u64 = 600_000_000_000;

/// One entry of the allow list: a name (`*.` for its subdomains too) or an
/// address, and a port, or every port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    Name {
        name: String,
        subdomains: bool,
        port: Option<u16>,
    },
    Address {
        ip: IpAddr,
        port: Option<u16>,
    },
}

/// An allow-list entry that is not `host`, `host:port`, `[v6]` or
/// `[v6]:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidRule(pub String);
impl std::fmt::Display for InvalidRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid network rule {:?}: expected host, host:port, [ipv6] or [ipv6]:port",
            self.0
        )
    }
}
impl std::error::Error for InvalidRule {}

/// The destinations a guest may reach. A session without one has no
/// network: `socket` refuses `AF_INET` and `AF_INET6`, as before.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    rules: Vec<Rule>,
}
impl NetworkPolicy {
    /// A policy that allows nothing yet; names and addresses are added with
    /// [`Self::allow`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Allows `entry`: a host name (`github.com`), every subdomain of one
    /// (`*.github.com`), an IPv4 address or an IPv6 one (bare, or in
    /// brackets), each optionally with a port (`github.com:443`,
    /// `[::1]:8080`). Names are matched without regard to case; a name
    /// lets the guest resolve it and connect to the addresses it resolved.
    pub fn allow(mut self, entry: &str) -> Result<Self, InvalidRule> {
        let invalid = || InvalidRule(entry.to_owned());
        let port = |text: &str| {
            text.parse::<u16>()
                .ok()
                .filter(|&port| port != 0)
                .ok_or_else(invalid)
        };
        if let Ok(ip) = entry.parse::<IpAddr>() {
            self.rules.push(Rule::Address { ip, port: None });
            return Ok(self);
        }
        if let Some(rest) = entry.strip_prefix('[') {
            let (ip, tail) = rest.split_once(']').ok_or_else(invalid)?;
            let ip = ip.parse::<Ipv6Addr>().map_err(|_| invalid())?;
            let port = match tail {
                "" => None,
                tail => Some(port(tail.strip_prefix(':').ok_or_else(invalid)?)?),
            };
            self.rules.push(Rule::Address {
                ip: IpAddr::V6(ip),
                port,
            });
            return Ok(self);
        }
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, text)) => (host, Some(port(text)?)),
            None => (entry, None),
        };
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            self.rules.push(Rule::Address {
                ip: IpAddr::V4(ip),
                port,
            });
            return Ok(self);
        }
        let (subdomains, name) = match host.strip_prefix("*.") {
            Some(name) => (true, name),
            None => (false, host),
        };
        let name = normal(name).ok_or_else(invalid)?;
        self.rules.push(Rule::Name {
            name,
            subdomains,
            port,
        });
        Ok(self)
    }
    /// Whether `name` (already normalised) is one the guest may resolve.
    fn allows_name(&self, name: &str) -> bool {
        self.rules.iter().any(|rule| match rule {
            Rule::Name {
                name: allowed,
                subdomains,
                ..
            } => matches_name(allowed, *subdomains, name),
            Rule::Address { .. } => false,
        })
    }
}
/// A host name in lower case without its final dot, or `None` for one that
/// is not made of letters, digits, hyphens and dots.
fn normal(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then_some(name)
}
/// Whether `name` is `allowed`, or with `subdomains` one of its subdomains
/// (not the name itself, as a certificate's wildcard).
fn matches_name(allowed: &str, subdomains: bool, name: &str) -> bool {
    if subdomains {
        name.strip_suffix(allowed)
            .is_some_and(|head| head.len() > 1 && head.ends_with('.'))
    } else {
        name == allowed
    }
}
/// Whether a name rule may reach `ip`, which the host resolved `name` to:
/// only a global address, so that no allowed name (nor a subdomain under a
/// `*.` rule, whose owner may point it anywhere) reaches the host's own
/// machine or networks; `localhost` and its subdomains may also reach the
/// loopback. Any address listed itself is reached without this.
fn reachable(name: &str, ip: IpAddr) -> bool {
    let local = name == "localhost" || name.ends_with(".localhost");
    match plain(ip) {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_loopback() {
                return local;
            }
            !(v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                // Shared address space (RFC 6598) and the reserved 240/4.
                || (a == 100 && (64..128).contains(&b))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return local;
            }
            let segments = v6.segments();
            let first = segments[0];
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4
            // address, which must be reachable itself.
            let embedded = |high: u16, low: u16| {
                let [a, b] = high.to_be_bytes();
                let [c, d] = low.to_be_bytes();
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            };
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return reachable(name, embedded(segments[6], segments[7]));
            }
            if first == 0x2002 {
                return reachable(name, embedded(segments[1], segments[2]));
            }
            !(v6.is_unspecified()
                || v6.is_multicast()
                // Unique local (fc00::/7) and link-local (fe80::/10).
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}
/// An IPv4 address that an IPv6 socket names as `::ffff:a.b.c.d` is that
/// IPv4 address.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A session's network: its policy, what the stub has resolved for it,
/// and the lookups in progress.
pub(crate) struct Network {
    policy: NetworkPolicy,
    /// The names each address was resolved from, and when the stub last
    /// gave it, so that a connection to it is allowed as the names are for
    /// [`NAME_LIFETIME`].
    resolved: Mutex<BTreeMap<IpAddr, Vec<(String, u64)>>>,
    lookups: Mutex<BTreeMap<String, (Arc<Lookup>, u64)>>,
    /// The local ports the guest's TCP sockets hold, and its UDP ones.
    /// Locked after a socket's state, never before.
    tcp_ports: Mutex<Ports>,
    udp_ports: Mutex<Ports>,
}
impl Network {
    pub(crate) fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            resolved: Mutex::default(),
            lookups: Mutex::default(),
            tcp_ports: Mutex::default(),
            udp_ports: Mutex::default(),
        }
    }
    fn ports(&self, datagram: bool) -> MutexGuard<'_, Ports> {
        if datagram {
            &self.udp_ports
        } else {
            &self.tcp_ports
        }
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether the guest may connect to `address` at `now`.
    fn allows(&self, address: SocketAddr, now: u64) -> bool {
        let ip = plain(address.ip());
        let resolved = self.resolved.lock().unwrap_or_else(PoisonError::into_inner);
        let names = resolved.get(&ip).map_or(&[][..], Vec::as_slice);
        let names = names
            .iter()
            .filter(|(_, given)| now.saturating_sub(*given) < NAME_LIFETIME)
            .map(|(name, _)| name);
        self.policy.rules.iter().any(|rule| match rule {
            Rule::Address { ip: allowed, port } => {
                plain(*allowed) == ip && port.is_none_or(|port| port == address.port())
            }
            Rule::Name {
                name,
                subdomains,
                port,
            } => {
                port.is_none_or(|port| port == address.port())
                    && names
                        .clone()
                        .any(|resolved| matches_name(name, *subdomains, resolved))
            }
        })
    }
    /// The lookup of `name`: one already made in the last
    /// [`LOOKUP_LIFETIME`], or a new one. Each socket waiting for it adds
    /// its own waker.
    fn lookup(&self, host: &dyn paludarium_host::Host, name: &str) -> Result<Arc<Lookup>, Errno> {
        let now = host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0);
        let mut lookups = self.lookups.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((lookup, started)) = lookups.get(name)
            && (lookup.result().is_none_or(|result| result.is_ok())
                && now.saturating_sub(*started) < LOOKUP_LIFETIME)
        {
            return Ok(Arc::clone(lookup));
        }
        let lookup = host.resolve(name)?;
        lookups.insert(name.to_owned(), (Arc::clone(&lookup), now));
        Ok(lookup)
    }
    /// Notes that the stub gave `addresses` for `name` at `now`, and
    /// forgets what has expired.
    fn note(&self, name: &str, addresses: &[IpAddr], now: u64) {
        let mut resolved = self.resolved.lock().unwrap_or_else(PoisonError::into_inner);
        resolved.retain(|_, names| {
            names.retain(|(_, given)| now.saturating_sub(*given) < NAME_LIFETIME);
            !names.is_empty()
        });
        for ip in addresses {
            let names = resolved.entry(plain(*ip)).or_default();
            names.retain(|(known, _)| known != name);
            names.push((name.to_owned(), now));
        }
    }
}

/// `socket(domain, type, protocol)` for `AF_INET` and `AF_INET6`, with
/// Linux's `inet_create` checks: a stream is TCP and a datagram UDP; an
/// ICMP datagram is `EACCES`, as outside `net.ipv4.ping_group_range`; a raw
/// socket is `EPERM`; any other type `ESOCKTNOSUPPORT`.
pub(crate) fn socket(
    c: &mut Context<'_>,
    a: [u64; 6],
    network: &Arc<Network>,
) -> Result<u64, Errno> {
    let flags = a[1] as u32 & (NONBLOCK | CLOEXEC);
    let family = if a[0] == u64::from(AF_INET) {
        Family::V4
    } else {
        Family::V6
    };
    let datagram = match (a[1] as u32 & 0xf, a[2]) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => false,
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => true,
        (SOCK_DGRAM, IPPROTO_ICMP | IPPROTO_ICMPV6) => return Err(Errno(13)),
        (SOCK_STREAM | SOCK_DGRAM, _) => return Err(EPROTONOSUPPORT),
        (SOCK_RAW, _) => return Err(Errno(1)),
        _ => return Err(ESOCKTNOSUPPORT),
    };
    let socket = InetSocket::new(
        family,
        datagram,
        network,
        c.shared_host,
        &c.files.readiness,
        flags,
    );
    if datagram {
        // `net.core.rmem_default` and `wmem_default`.
        let mut options = socket.options();
        options.send_buffer = 212_992;
        options.receive_buffer = 212_992;
    }
    c.files
        .install(socket, flags & CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Where a TCP socket's connection stands, as Linux's `socket_state`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Connection {
    #[default]
    Unconnected,
    Connecting,
    Connected,
}

/// A DNS query the stub owes an answer, as one datagram from `from`.
struct Query {
    from: SocketAddr,
    /// Its place among what the socket has received (`State::received`).
    seq: u64,
    id: [u8; 2],
    /// The header's flags word, the question as sent, and its name.
    flags: u16,
    question: Vec<u8>,
    name: String,
    kind: u16,
    answer: Answer,
}
enum Answer {
    Now(u8),
    Lookup(Arc<Lookup>),
}

#[derive(Default)]
struct State {
    // TCP.
    connection: Connection,
    stream: Option<Arc<Stream>>,
    /// The stream's failure was seen: `error` holds it until it is taken.
    noted: bool,
    /// `sk_err`: the pending error, which `SO_ERROR` takes.
    error: Option<Errno>,
    read_shut: bool,
    // The guest's loopback.
    /// The address a TCP socket holds its local port on: its `bind`'s, or
    /// the one `listen` or a loopback connection took.
    bound: Option<SocketAddr>,
    /// The guest named the port itself, so that a disconnect keeps it
    /// (Linux's `SOCK_BINDPORT_LOCK`), or the address (`SOCK_BINDADDR_LOCK`).
    port_locked: bool,
    address_locked: bool,
    /// The address a disconnect kept without its port, which the next
    /// automatic bind takes.
    address: Option<IpAddr>,
    listen: Option<Listen>,
    /// The loopback connection the stream is a side of, once its listener
    /// has taken it.
    link: Option<(Arc<OnceLock<Arc<Link>>>, usize)>,
    // UDP.
    peer: Option<SocketAddr>,
    queries: VecDeque<Query>,
    /// Datagrams other guest sockets sent this one on the loopback.
    inbox: VecDeque<Datagram>,
    /// What the inbox takes of `SO_RCVBUF`, as Linux's `sk_rmem_alloc`.
    inbox_size: usize,
    /// How many datagrams and queries have come, which orders them.
    received: u64,
}

/// A datagram from another guest socket.
struct Datagram {
    from: SocketAddr,
    seq: u64,
    bytes: Vec<u8>,
}
/// What a datagram takes of the receive buffer besides its bytes: about a
/// small `sk_buff`'s `truesize`.
const DATAGRAM_OVERHEAD: usize = 768;

/// A listening socket's connections, as Linux's accept queue.
struct Listen {
    /// The most connections waiting, less one (`sk_max_ack_backlog`).
    backlog: usize,
    ready: VecDeque<Arc<InetSocket>>,
    /// Connections that found the queue full. Linux drops their handshake
    /// and the client tries again; here they wait for room.
    pending: VecDeque<Pending>,
    arrivals: u64,
}
struct Pending {
    stream: Weak<Stream>,
    link: Arc<OnceLock<Arc<Link>>>,
    from: SocketAddr,
    to: SocketAddr,
}
impl Listen {
    fn new(backlog: usize) -> Self {
        Self {
            backlog,
            ready: VecDeque::new(),
            pending: VecDeque::new(),
            arrivals: 0,
        }
    }
    fn has_room(&self) -> bool {
        self.ready.len() <= self.backlog
    }
    /// Ends listening, as Linux's `inet_csk_listen_stop`: each connection
    /// not yet accepted is reset, and each waiting for room refused, as its
    /// next try would be.
    fn stop(self) {
        for child in self.ready {
            child.abort();
        }
        for pending in self.pending {
            if let Some(stream) = pending.stream.upgrade()
                && stream.phase() == Phase::Connecting
            {
                stream.fail(ECONNREFUSED);
            }
        }
    }
}
impl State {
    /// Notes the failure of the stream, once.
    fn note(&mut self) {
        if !self.noted
            && let Some(stream) = &self.stream
            && let Phase::Failed(error) = stream.phase()
        {
            self.noted = true;
            self.error = Some(error);
        }
    }
}

/// The `int` options a TCP or UDP socket keeps, with Linux's defaults.
#[derive(Clone, Copy)]
struct Options {
    reuse_address: bool,
    reuse_port: bool,
    keep_alive: bool,
    broadcast: bool,
    out_of_band_inline: bool,
    priority: i32,
    linger: Option<i32>,
    send_buffer: i32,
    receive_buffer: i32,
    receive_timeout: Timeout,
    send_timeout: Timeout,
    no_delay: bool,
    keep_idle: i32,
    keep_interval: i32,
    keep_count: i32,
    quick_ack: bool,
    user_timeout: i32,
    type_of_service: i32,
    v6_only: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            reuse_address: false,
            reuse_port: false,
            keep_alive: false,
            broadcast: false,
            out_of_band_inline: false,
            priority: 0,
            linger: None,
            send_buffer: 16384,
            receive_buffer: 131_072,
            receive_timeout: Timeout::Forever,
            send_timeout: Timeout::Forever,
            no_delay: false,
            keep_idle: 7200,
            keep_interval: 75,
            keep_count: 9,
            quick_ack: true,
            user_timeout: 0,
            type_of_service: 0,
            v6_only: false,
        }
    }
}

/// Signal-driven I/O of a socket, as Linux's `sock_wake_async` sends it:
/// the owner and signal `F_SETOWN` and `F_SETSIG` set, the descriptor
/// `O_ASYNC` was set through, and its `SOCKWQ_ASYNC_WAITDATA` and
/// `SOCKWQ_ASYNC_NOSPACE` bits.
#[derive(Default)]
struct Signals {
    owner: Mutex<FileOwner>,
    registration: Mutex<Option<Registration>>,
    /// A blocking read waits for data, which then signals nothing.
    waiting: AtomicBool,
    /// A write or poll found the buffer full, so room signals `POLL_OUT`.
    no_space: AtomicBool,
}
impl Signals {
    fn on(&self) -> bool {
        self.registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
    /// `SOCK_WAKE_IO`: signals `reason`, if `O_ASYNC` is on.
    fn send(&self, reason: Reason) {
        let to = self
            .registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(to) = to {
            let owner = *self.owner.lock().unwrap_or_else(PoisonError::into_inner);
            Notice { to, owner, reason }.send();
        }
    }
    /// `SOCK_WAKE_WAITD`: none while a read waits, which the data wakes.
    fn waking(&self, reason: Reason) {
        if !self.waiting.load(Ordering::SeqCst) {
            self.send(reason);
        }
    }
    /// `SOCK_WAKE_SPACE`: `POLL_OUT` once, if the buffer was found full.
    fn space(&self) {
        if self.no_space.swap(false, Ordering::SeqCst) {
            self.send(Reason::Out);
        }
    }
    /// `sk_set_bit(SOCKWQ_ASYNC_NOSPACE)`, which acts only with `O_ASYNC`.
    fn full(&self) {
        if self.on() {
            self.no_space.store(true, Ordering::SeqCst);
        }
    }
}
/// What a stream's change signals, as Linux's TCP does: `POLL_OUT` when the
/// connection opens (`tcp_finish_connect`), `POLL_ERR` when it fails
/// (`sk_error_report`), `POLL_IN` for data (`sk_data_ready`), for the
/// peer's end `POLL_IN`, or `POLL_HUP` once this side has shut down too
/// (`tcp_fin`), and then `POLL_IN` as for data (`tcp_data_queue` queues the
/// FIN), and `POLL_OUT` for room after a full buffer
/// (`sk_stream_write_space`).
fn stream_waker(
    signals: &Arc<Signals>,
    hub: &Arc<ReadinessHub>,
    stream: &Arc<Stream>,
) -> Arc<dyn Fn(Event) + Send + Sync> {
    let (signals, hub, stream) = (Arc::clone(signals), Arc::clone(hub), Arc::downgrade(stream));
    Arc::new(move |event| {
        let stream = Weak::upgrade(&stream);
        match event {
            Event::Connected => signals.send(Reason::Out),
            Event::Failed => signals.send(Reason::Error),
            Event::Received => signals.waking(Reason::In),
            Event::Ended => {
                signals.waking(
                    if stream.as_ref().is_some_and(|s| s.readiness().write_closed) {
                        Reason::HangUp
                    } else {
                        Reason::In
                    },
                );
                signals.waking(Reason::In);
            }
            Event::Sent => {
                if stream.as_ref().is_some_and(|s| s.readiness().writable) {
                    signals.space();
                }
            }
        }
        hub.changed();
    })
}

/// A TCP or UDP socket of the guest.
pub(crate) struct InetSocket {
    /// This socket, for the bindings that name it.
    this: Weak<InetSocket>,
    family: Family,
    datagram: bool,
    network: Arc<Network>,
    /// For the stub's lookups, which a plain `write` can start.
    host: Arc<dyn paludarium_host::Host>,
    hub: Arc<ReadinessHub>,
    flags: AtomicU32,
    inode: u64,
    mode: AtomicU32,
    state: Mutex<State>,
    options: Mutex<Options>,
    signals: Arc<Signals>,
}

impl InetSocket {
    fn new(
        family: Family,
        datagram: bool,
        network: &Arc<Network>,
        host: &Arc<dyn paludarium_host::Host>,
        hub: &Arc<ReadinessHub>,
        flags: u32,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: Weak::clone(this),
            family,
            datagram,
            network: Arc::clone(network),
            host: Arc::clone(host),
            hub: Arc::clone(hub),
            flags: AtomicU32::new(2 | (flags & NONBLOCK)),
            inode: crate::files::anonymous_inode(),
            mode: AtomicU32::new(0o140777),
            state: Mutex::new(State::default()),
            options: Mutex::new(Options::default()),
            signals: Arc::default(),
        })
    }
    /// `F_GETOWN` and `F_GETSIG`.
    pub(crate) fn file_owner(&self) -> FileOwner {
        *self
            .signals
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// `F_SETOWN` and `F_SETSIG`.
    pub(crate) fn set_file_owner(&self, owner: FileOwner) {
        *self
            .signals
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = owner;
    }
    /// `F_SETFL` turning `O_ASYNC` on, with its registration, or off.
    pub(crate) fn set_async(&self, registration: Option<Registration>) {
        *self
            .signals
            .registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = registration;
    }
    /// A blocking read of this socket starts or stops waiting for data.
    pub(crate) fn wait_data(&self, waits: bool) {
        self.signals
            .waiting
            .store(waits && self.signals.on(), Ordering::SeqCst);
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The ports of this socket's protocol.
    fn ports(&self) -> MutexGuard<'_, Ports> {
        self.network.ports(self.datagram)
    }
    fn options(&self) -> MutexGuard<'_, Options> {
        self.options.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::SeqCst) & NONBLOCK != 0
    }
    /// `SO_RCVTIMEO` or `SO_SNDTIMEO`.
    pub(crate) fn timeout(&self, receive: bool) -> Timeout {
        let options = self.options();
        if receive {
            options.receive_timeout
        } else {
            options.send_timeout
        }
    }
    /// Whether this is a TCP socket, whose writes go on until all is sent.
    pub(crate) fn is_stream(&self) -> bool {
        !self.datagram
    }

    /// Receives into `buf`: `EAGAIN` while nothing has come. A failed
    /// connection gives its error once and then the end, as Linux's
    /// `tcp_recvmsg`; a socket never connected is `ENOTCONN`.
    fn receive(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        if self.datagram {
            return self.receive_datagram(buf, peek);
        }
        let mut s = self.lock();
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(ENOTCONN);
        };
        if s.read_shut && stream.queued().0 == 0 {
            return Ok(Received::bytes(0));
        }
        match stream.read(buf, peek) {
            Ok(n) => Ok(Received::bytes(n)),
            Err(e) if e == Errno::EAGAIN => Err(e),
            Err(_) => match s.error.take() {
                Some(error) => Err(error),
                None => Ok(Received::bytes(0)),
            },
        }
    }
    /// Sends `bytes`: a TCP socket never connected, or shut down for
    /// sending, is `EPIPE`; a failed one gives its pending error first.
    fn send(&self, bytes: &[u8], to: Option<SocketAddr>) -> Result<usize, Errno> {
        if self.datagram {
            return self.send_datagram(bytes, to);
        }
        let mut s = self.lock();
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(Errno::EPIPE);
        };
        match stream.write(bytes) {
            // A failed connection's error goes once, as `sk_stream_error`
            // takes it.
            Err(e)
                if e != Errno::EAGAIN
                    && (e != Errno::EPIPE || matches!(stream.phase(), Phase::Failed(_))) =>
            {
                Err(s.error.take().unwrap_or(Errno::EPIPE))
            }
            Err(e) if e == Errno::EAGAIN && stream.phase() == Phase::Open => {
                self.signals.full();
                Err(e)
            }
            result => result,
        }
    }

    /// Starts connecting to `address`, or goes on with a connection already
    /// started; waits for it unless the socket is nonblocking. As Linux's
    /// `__inet_stream_connect`: `EISCONN` once connected or listening,
    /// `EALREADY` while still connecting, `EINPROGRESS` when a nonblocking
    /// one starts, and the pending error, or `ECONNABORTED`, when it failed.
    /// A loopback address where a guest socket listens is reached in the
    /// kernel; one where none does is refused, unless the policy allows the
    /// host's.
    fn connect(&self, c: &mut Context<'_>, address: Option<SocketAddr>) -> Result<u64, Errno> {
        if self.datagram {
            return self.connect_datagram(address);
        }
        let Some(address) = address else {
            // AF_UNSPEC disconnects.
            self.renew(&mut self.lock());
            return Ok(0);
        };
        let options = *self.options();
        let wait = crate::sockets::wait_for(c, self.timeout(false))?;
        let stream = {
            let mut s = self.lock();
            s.note();
            if s.listen.is_some() {
                return Err(EISCONN);
            }
            let pending = match s.connection {
                Connection::Connected => return Err(EISCONN),
                Connection::Connecting => EALREADY,
                Connection::Unconnected => {
                    let to = crate::loopback::destination(SocketAddr::new(
                        plain(address.ip()),
                        address.port(),
                    ));
                    let opened = match to {
                        Some(to) => self.open_loopback(&mut s, to, &options)?,
                        None => None,
                    };
                    let loopback = opened.is_some();
                    let stream = match opened {
                        Some(stream) => stream,
                        None if address.port() == DNS => {
                            DnsOverTcp::open(address, &self.network, &self.host)
                        }
                        None => {
                            let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
                            if self.network.allows(address, now) {
                                let stream = c.host.connect(address)?;
                                stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
                                stream
                            } else if to.is_some() {
                                // Nothing listens there on the guest's own
                                // loopback, which answers with a reset.
                                return self.refused(&mut s, address);
                            } else {
                                return Err(ENETUNREACH);
                            }
                        }
                    };
                    if address.port() == DNS && !loopback {
                        stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
                    }
                    stream.set_nodelay(options.no_delay);
                    if let Some(old) = s.stream.replace(Arc::clone(&stream)) {
                        old.close();
                    }
                    s.noted = false;
                    s.read_shut = false;
                    s.connection = Connection::Connecting;
                    // The stub's own stream is open at once.
                    if address.port() == DNS && !loopback {
                        stream.connected(None);
                    }
                    // Linux's loopback answers the handshake once connect
                    // has returned, so a nonblocking one is in progress
                    // even when its listener took it.
                    if loopback && self.nonblocking() {
                        return Err(EINPROGRESS);
                    }
                    EINPROGRESS
                }
            };
            (s.stream.clone(), pending)
        };
        let (Some(stream), pending) = stream else {
            return Err(ECONNABORTED);
        };
        loop {
            let ticket = c.files.readiness.token.value();
            match stream.phase() {
                Phase::Open => {
                    self.lock().connection = Connection::Connected;
                    return Ok(0);
                }
                // Linux then disconnects the socket, which is as new.
                Phase::Failed(_) => {
                    let mut s = self.lock();
                    s.note();
                    let error = s.error.take().unwrap_or(ECONNABORTED);
                    self.renew(&mut s);
                    return Err(error);
                }
                Phase::Connecting if self.nonblocking() => return Err(pending),
                Phase::Connecting => {
                    let Some(deadline) = wait.deadline(c)? else {
                        return Err(EINPROGRESS);
                    };
                    crate::events::wait(c, ticket, deadline)?;
                }
            }
        }
    }
    /// `shutdown(how)`: `ENOTCONN` for a socket with no open connection;
    /// one still connecting is abandoned, as Linux disconnects it.
    fn shutdown(&self, how: u64) -> Result<u64, Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let mut s = self.lock();
        if self.datagram {
            return if s.peer.is_some() {
                Ok(0)
            } else {
                Err(ENOTCONN)
            };
        }
        // A listener stops for SHUT_RD, as Linux's `inet_shutdown`
        // disconnects it, and ignores SHUT_WR.
        if s.listen.is_some() {
            if how != 1 {
                self.renew(&mut s);
            }
            return Ok(0);
        }
        s.note();
        let Some(stream) = s.stream.clone() else {
            return Err(ENOTCONN);
        };
        match stream.phase() {
            Phase::Connecting => {
                self.renew(&mut s);
                Ok(0)
            }
            Phase::Failed(_) => Err(ENOTCONN),
            Phase::Open if closed(&stream) => Err(ENOTCONN),
            Phase::Open => {
                if how != 1 {
                    s.read_shut = true;
                }
                if how != 0 {
                    stream.shutdown_write();
                }
                self.hub.changed();
                Ok(0)
            }
        }
    }
    /// The socket's own address: the host's once connected, or the
    /// loopback connection's, else the one it is bound to, else the
    /// unspecified one with port 0.
    fn local(&self) -> SocketAddr {
        let s = self.lock();
        s.stream
            .as_ref()
            .and_then(|stream| stream.local())
            .or(s.bound)
            .or(s.address.map(|ip| SocketAddr::new(ip, 0)))
            .unwrap_or(match self.family {
                Family::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                Family::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            })
    }
    /// The peer's address: `ENOTCONN` unless the connection is open.
    fn peer(&self) -> Result<SocketAddr, Errno> {
        let s = self.lock();
        if self.datagram {
            return s.peer.ok_or(ENOTCONN);
        }
        match &s.stream {
            Some(stream) if stream.phase() == Phase::Open && !closed(stream) => Ok(stream.peer()),
            _ => Err(ENOTCONN),
        }
    }

    /// `connect` of a UDP socket: it then sends to `address`, and on the
    /// loopback takes datagrams only from it, from its port, bound now to
    /// every address if it had none, on the loopback's source address
    /// (`inet_dgram_connect`, `ip4_datagram_connect`). AF_UNSPEC disconnects
    /// (`__udp_disconnect`), keeping only what the guest bound itself.
    fn connect_datagram(&self, address: Option<SocketAddr>) -> Result<u64, Errno> {
        let options = *self.options();
        let mut s = self.lock();
        let Some(address) = address else {
            s.peer = None;
            let bindings = State {
                bound: s.bound.take(),
                port_locked: s.port_locked,
                address_locked: s.address_locked,
                address: s.address.take(),
                ..State::default()
            };
            self.keep_locked(&mut s, &bindings);
            return Ok(0);
        };
        let to = SocketAddr::new(plain(address.ip()), address.port());
        match crate::loopback::destination(to) {
            Some(to) => {
                if self.family == Family::V6 && options.v6_only && to.is_ipv4() {
                    return Err(ENETUNREACH);
                }
                let from = self.datagram_source(&mut s, to, &options)?;
                self.ports().connect(&self.this, from, Some(to));
                s.bound = Some(from);
                s.peer = Some(to);
            }
            None => {
                if let Some(bound) = s.bound {
                    self.ports().connect(&self.this, bound, None);
                }
                s.peer = Some(address);
            }
        }
        Ok(0)
    }
    fn unspecified(&self) -> IpAddr {
        match self.family {
            Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
    /// The address a datagram to `to` on the loopback leaves from: this
    /// socket's port, bound now to every address if it had none (Linux's
    /// `inet_autobind`), on the address it is bound to, or else the
    /// loopback's source address.
    fn datagram_source(
        &self,
        s: &mut State,
        to: SocketAddr,
        options: &Options,
    ) -> Result<SocketAddr, Errno> {
        let bound = match s.bound {
            Some(bound) => bound,
            None => {
                let every = SocketAddr::new(s.address.take().unwrap_or(self.unspecified()), 0);
                // Linux's autobind finds no free port with EAGAIN.
                let bound = self
                    .ports()
                    .bind(self.binding(every, options))
                    .map_err(|_| Errno::EAGAIN)?;
                s.bound = Some(bound);
                bound
            }
        };
        let ip = if bound.ip().is_unspecified() {
            crate::loopback::source(to)
        } else {
            bound.ip()
        };
        Ok(SocketAddr::new(ip, bound.port()))
    }
    /// Sends a datagram to `to`, or the connected peer: on the loopback to
    /// the guest socket that takes it, if any, as Linux's loopback delivers
    /// it at once; else a DNS query to the stub, to port 53 at any address.
    /// Any other destination is `ENETUNREACH`. A connected socket's pending
    /// error goes first, as `sock_alloc_send_pskb` gives it.
    fn send_datagram(&self, bytes: &[u8], to: Option<SocketAddr>) -> Result<usize, Errno> {
        let options = *self.options();
        let mut s = self.lock();
        let to = to.or(s.peer).ok_or(EDESTADDRREQ)?;
        if let Some(error) = s.error.take() {
            return Err(error);
        }
        let plain_to = SocketAddr::new(plain(to.ip()), to.port());
        if let Some(dest) = crate::loopback::destination(plain_to) {
            if self.family == Family::V6 && options.v6_only && dest.is_ipv4() {
                return Err(ENETUNREACH);
            }
            // The most a datagram holds: 65535 bytes less the UDP header,
            // and IPv4's.
            let most = if dest.is_ipv4() { 65_507 } else { 65_527 };
            if bytes.len() > most {
                return Err(EMSGSIZE);
            }
            let from = self.datagram_source(&mut s, dest, &options)?;
            let to_peer = s.peer == Some(dest);
            drop(s);
            let receiver = self.ports().receiver(dest, from);
            if let Some(receiver) = receiver {
                receiver.deliver(from, bytes);
                return Ok(bytes.len());
            }
            if dest.port() != DNS {
                // The loopback answers with ICMP's port unreachable, which
                // only a socket connected there learns of
                // (`__udp4_lib_err`).
                if to_peer {
                    self.lock().error = Some(ECONNREFUSED);
                    self.signals.send(Reason::Error);
                    self.hub.changed();
                }
                return Ok(bytes.len());
            }
            s = self.lock();
        } else if to.port() != DNS {
            return Err(ENETUNREACH);
        }
        if let Some(mut query) = parse_query(bytes, to) {
            query.seq = s.received;
            s.received += 1;
            start_lookup(&self.network, self.host.as_ref(), &mut query);
            // An answer signals POLL_IN as a datagram's arrival does, and
            // then wakes this socket's waits, so that a poll the answer ends
            // finds the signal pending: at once, or when the host's lookup
            // ends.
            let ready = match &query.answer {
                Answer::Now(_) => true,
                Answer::Lookup(lookup) => {
                    let (signals, hub) = (Arc::clone(&self.signals), Arc::clone(&self.hub));
                    !lookup.add_waker(Arc::new(move || {
                        signals.waking(Reason::In);
                        hub.changed();
                    }))
                }
            };
            s.queries.push_back(query);
            drop(s);
            if ready {
                self.signals.waking(Reason::In);
            }
            self.hub.changed();
        }
        Ok(bytes.len())
    }
    /// A datagram from `from` arrives, unless the receive buffer is already
    /// over `SO_RCVBUF`, when Linux's `__udp_enqueue_schedule_skb` drops it.
    fn deliver(&self, from: SocketAddr, bytes: &[u8]) {
        let limit = usize::try_from(self.options().receive_buffer).unwrap_or(0);
        let mut s = self.lock();
        if s.inbox_size > limit {
            return;
        }
        let seq = s.received;
        s.received += 1;
        s.inbox_size += bytes.len() + DATAGRAM_OVERHEAD;
        s.inbox.push_back(Datagram {
            from,
            seq,
            bytes: bytes.to_vec(),
        });
        drop(s);
        self.signals.waking(Reason::In);
        self.hub.changed();
    }
    /// The first datagram that has come, a guest socket's or the stub's
    /// ready answer, in the order they came: its sender and bytes.
    fn first_datagram(&self, s: &State) -> Option<(SocketAddr, Vec<u8>, bool)> {
        let answer = s
            .queries
            .front()
            .and_then(|query| Some((query.seq, query.from, self.answer(query)?)));
        match (answer, s.inbox.front()) {
            (Some((seq, from, answer)), datagram)
                if datagram.is_none_or(|datagram| seq < datagram.seq) =>
            {
                Some((from, answer, true))
            }
            (_, Some(datagram)) => Some((datagram.from, datagram.bytes.clone(), false)),
            _ => None,
        }
    }
    /// Takes the first datagram that has come, cut to `buf`; a pending
    /// error first, as Linux's `__skb_try_recv_datagram`.
    fn receive_datagram(&self, buf: &mut [u8], peek: bool) -> Result<Received, Errno> {
        let mut s = self.lock();
        if let Some(error) = s.error.take() {
            return Err(error);
        }
        let Some((from, bytes, answer)) = self.first_datagram(&s) else {
            return Err(Errno::EAGAIN);
        };
        if !peek {
            if answer {
                s.queries.pop_front();
            } else {
                s.inbox.pop_front();
                s.inbox_size -= bytes.len() + DATAGRAM_OVERHEAD;
            }
        }
        let n = buf.len().min(bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(Received {
            count: n,
            length: bytes.len(),
            from: Some(from),
        })
    }
    /// The answer to `query` in a datagram, once it can be given.
    fn answer(&self, query: &Query) -> Option<Vec<u8>> {
        answer(&self.network, self.host.as_ref(), query, UDP_ANSWER)
    }
    /// The first datagram's length, for `FIONREAD` (`first_packet_length`).
    fn next_datagram(&self) -> usize {
        let s = self.lock();
        self.first_datagram(&s)
            .map_or(0, |(_, bytes, _)| bytes.len())
    }
    /// The bytes waiting to be read, and to be sent, for `FIONREAD` and
    /// `SIOCOUTQ`; a listener has neither (EINVAL, as Linux's `tcp_ioctl`).
    pub(crate) fn queued(&self, outgoing: bool) -> Result<usize, Errno> {
        if self.datagram {
            return Ok(if outgoing { 0 } else { self.next_datagram() });
        }
        let s = self.lock();
        if s.listen.is_some() {
            return Err(Errno::EINVAL);
        }
        Ok(s.stream.as_ref().map_or(0, |stream| {
            let (received, sending) = stream.queued();
            if outgoing { sending } else { received }
        }))
    }

    // The guest's loopback.

    fn binding(&self, address: SocketAddr, options: &Options) -> Binding {
        Binding {
            address,
            v6: self.family == Family::V6,
            v6_only: options.v6_only,
            reuse_address: options.reuse_address,
            reuse_port: options.reuse_port,
            listening: false,
            peer: None,
            owner: Weak::clone(&self.this),
        }
    }
    /// `bind` of a TCP or UDP socket, with Linux's checks in its order
    /// (`__inet_bind`, `__inet6_bind`). The guest's own addresses are the
    /// loopback's and the unspecified one, and the IPv4 multicast and
    /// broadcast ones Linux takes too; any other is `EADDRNOTAVAIL`. Port 0
    /// takes an ephemeral port.
    fn bind(&self, raw: &[u8]) -> Result<u64, Errno> {
        let options = *self.options();
        let mut s = self.lock();
        let taken = |s: &State| s.bound.is_some() || s.stream.is_some();
        let own = |ip: Ipv4Addr| {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
        };
        let address = match self.family {
            Family::V4 => {
                if raw.len() < 16 {
                    return Err(Errno::EINVAL);
                }
                let family = u16::from_le_bytes([raw[0], raw[1]]);
                let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
                // AF_UNSPEC passes with the unspecified address, for old
                // programs.
                if family != AF_INET && !(family == AF_UNSPEC && ip.is_unspecified()) {
                    return Err(EAFNOSUPPORT);
                }
                if !own(ip) {
                    return Err(EADDRNOTAVAIL);
                }
                if taken(&s) {
                    return Err(Errno::EINVAL);
                }
                SocketAddr::from((ip, u16::from_be_bytes([raw[2], raw[3]])))
            }
            Family::V6 => {
                if raw.len() < 24 {
                    return Err(Errno::EINVAL);
                }
                if u16::from_le_bytes([raw[0], raw[1]]) != AF_INET6 {
                    return Err(EAFNOSUPPORT);
                }
                let mut octets = [0; 16];
                octets.copy_from_slice(&raw[8..24]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                let scope = raw
                    .get(24..28)
                    .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                if (ip.is_multicast() && !self.datagram) || taken(&s) {
                    return Err(Errno::EINVAL);
                }
                if let Some(v4) = ip.to_ipv4_mapped() {
                    if options.v6_only {
                        return Err(Errno::EINVAL);
                    }
                    if !own(v4) {
                        return Err(EADDRNOTAVAIL);
                    }
                    SocketAddr::from((v4, port))
                } else if ip.is_unspecified() || ip.is_loopback() {
                    SocketAddr::from((ip, port))
                } else if ip.segments()[0] & 0xffc0 == 0xfe80 && scope == 0 {
                    // A link-local address needs its interface.
                    return Err(Errno::EINVAL);
                } else {
                    return Err(EADDRNOTAVAIL);
                }
            }
        };
        s.bound = Some(self.ports().bind(self.binding(address, &options))?);
        s.port_locked = address.port() != 0;
        s.address_locked = !address.ip().is_unspecified();
        s.address = None;
        Ok(0)
    }
    /// `listen(backlog)`, as Linux's `inet_listen`: `EOPNOTSUPP` for UDP,
    /// `EINVAL` for a socket that has connected; an unbound socket takes an
    /// ephemeral port on every address. A listener only takes the new
    /// backlog.
    fn listen(&self, backlog: u64) -> Result<u64, Errno> {
        if self.datagram {
            return Err(EOPNOTSUPP);
        }
        // Linux takes the int as unsigned, so a negative one is the most.
        let backlog = (backlog as u32).min(SOMAXCONN) as usize;
        let options = *self.options();
        let mut s = self.lock();
        if s.stream.is_some() {
            return Err(Errno::EINVAL);
        }
        if let Some(listen) = s.listen.as_mut() {
            listen.backlog = backlog;
            let admitted = self.admit(listen, options);
            drop(s);
            if admitted {
                self.arrived();
            }
            return Ok(0);
        }
        {
            let mut ports = self.ports();
            if s.bound.is_none() {
                let ip = s.address.take().unwrap_or(self.unspecified());
                s.bound = Some(ports.bind(self.binding(SocketAddr::new(ip, 0), &options))?);
            }
            ports.listen(&self.this, options.reuse_address, options.reuse_port)?;
        }
        s.listen = Some(Listen::new(backlog));
        Ok(0)
    }
    /// The first connection waiting on this listener, as Linux's
    /// `inet_csk_accept`: `EINVAL` unless listening (`EOPNOTSUPP` for UDP),
    /// `EAGAIN` when none waits and the socket is nonblocking, or once
    /// `SO_RCVTIMEO` has passed.
    fn accept(&self, c: &mut Context<'_>) -> Result<Arc<InetSocket>, Errno> {
        if self.datagram {
            return Err(EOPNOTSUPP);
        }
        let wait = crate::sockets::wait_for(c, self.timeout(true))?;
        loop {
            let ticket = c.files.readiness.token.value();
            let options = *self.options();
            let (child, admitted) = {
                let mut s = self.lock();
                let Some(listen) = s.listen.as_mut() else {
                    return Err(Errno::EINVAL);
                };
                let child = listen.ready.pop_front();
                let admitted = child.is_some() && self.admit(listen, options);
                (child, admitted)
            };
            if admitted {
                self.arrived();
            }
            if let Some(child) = child {
                return Ok(child);
            }
            if self.nonblocking() {
                return Err(Errno::EAGAIN);
            }
            let Some(deadline) = wait.deadline(c)? else {
                return Err(Errno::EAGAIN);
            };
            crate::events::wait(c, ticket, deadline)?;
        }
    }
    /// Takes the connections that found the queue full into it while it
    /// has room; whether any came.
    fn admit(&self, listen: &mut Listen, options: Options) -> bool {
        let mut any = false;
        while listen.has_room() {
            let Some(pending) = listen.pending.pop_front() else {
                break;
            };
            let Some(stream) = pending.stream.upgrade() else {
                continue;
            };
            if stream.phase() != Phase::Connecting || stream.finished().1 {
                continue;
            }
            let child = self.child(options, &stream, &pending.link, pending.from, pending.to);
            listen.ready.push_back(child);
            listen.arrivals += 1;
            any = true;
        }
        any
    }
    /// A connection came to this listener: `POLL_IN` and a wake, as
    /// Linux's `sk_data_ready` of a listener.
    fn arrived(&self) {
        self.signals.waking(Reason::In);
        self.hub.changed();
    }
    /// The accepted side of a connection from `stream` at `from` to this
    /// listener at `to`, joined to it through `link`. It takes this
    /// socket's options, as Linux's `sk_clone_lock` copies them, and holds
    /// the listener's port on `to`.
    fn child(
        &self,
        options: Options,
        stream: &Arc<Stream>,
        link: &OnceLock<Arc<Link>>,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Arc<InetSocket> {
        let child = InetSocket::new(self.family, false, &self.network, &self.host, &self.hub, 0);
        *child.options() = options;
        let own = Stream::new(from);
        own.set_waker(stream_waker(&child.signals, &child.hub, &own));
        let joined = Link::join(stream, &own, from, to);
        let _ = link.set(Arc::clone(&joined));
        let own_link = Arc::new(OnceLock::new());
        let _ = own_link.set(joined);
        self.ports().hold(child.binding(to, &options));
        let mut s = child.lock();
        s.stream = Some(own);
        s.connection = Connection::Connected;
        s.link = Some((own_link, 1));
        s.bound = Some(to);
        drop(s);
        child
    }
    /// A connection to `to` on the guest's loopback, when a guest socket
    /// listens there: in its listener's queue, or waiting for room in it.
    /// `None` when none listens there.
    fn open_loopback(
        &self,
        s: &mut State,
        to: SocketAddr,
        options: &Options,
    ) -> Result<Option<Arc<Stream>>, Errno> {
        // An IPv6-only socket reaches no IPv4 address (`tcp_v6_connect`).
        if self.family == Family::V6 && options.v6_only && to.is_ipv4() {
            return Err(ENETUNREACH);
        }
        let Some(listener) = self.ports().listener(to) else {
            return Ok(None);
        };
        let theirs = *listener.options();
        let mut state = listener.lock();
        let Some(listen) = state.listen.as_mut() else {
            return Ok(None);
        };
        let from = self.loopback_source(s, to, options)?;
        let stream = Stream::new(to);
        stream.set_waker(stream_waker(&self.signals, &self.hub, &stream));
        let link = Arc::new(OnceLock::new());
        s.link = Some((Arc::clone(&link), 0));
        let arrived = listen.has_room();
        if arrived {
            let child = listener.child(theirs, &stream, &link, from, to);
            listen.ready.push_back(child);
            listen.arrivals += 1;
        } else {
            listen.pending.push_back(Pending {
                stream: Arc::downgrade(&stream),
                link,
                from,
                to,
            });
        }
        drop(state);
        if arrived {
            listener.arrived();
        }
        Ok(Some(stream))
    }
    /// The address a connection to `to` on the loopback leaves from: the
    /// one this socket is bound to, its port with the loopback's source
    /// address when bound to every address, else an ephemeral port.
    fn loopback_source(
        &self,
        s: &mut State,
        to: SocketAddr,
        options: &Options,
    ) -> Result<SocketAddr, Errno> {
        let source = crate::loopback::source(to);
        let mut ports = self.ports();
        let from = match s.bound {
            Some(bound) if !bound.ip().is_unspecified() => bound,
            Some(bound) => {
                let from = SocketAddr::new(source, bound.port());
                ports.rebind(&self.this, from);
                from
            }
            // Linux's connect finds no free port with EADDRNOTAVAIL.
            None => {
                let ip = s.address.take().unwrap_or(source);
                ports
                    .bind(self.binding(SocketAddr::new(ip, 0), options))
                    .map_err(|_| EADDRNOTAVAIL)?
            }
        };
        s.bound = Some(from);
        Ok(from)
    }
    /// A connection the loopback refuses: `ECONNREFUSED`, or for a
    /// nonblocking socket in progress with the error waiting, as Linux's
    /// reset comes once connect has returned.
    fn refused(&self, s: &mut State, address: SocketAddr) -> Result<u64, Errno> {
        if !self.nonblocking() {
            return Err(ECONNREFUSED);
        }
        let stream = Stream::new(address);
        stream.fail(ECONNREFUSED);
        s.stream = Some(stream);
        s.noted = false;
        s.read_shut = false;
        s.connection = Connection::Connecting;
        Err(EINPROGRESS)
    }
    /// Makes the socket as new, as Linux's `tcp_disconnect`: a loopback
    /// connection is reset, a listener stops, and only a port the guest
    /// bound itself is kept.
    fn renew(&self, s: &mut State) {
        let old = std::mem::take(s);
        if old.listen.is_some() {
            self.ports().stop_listening(&self.this);
        }
        self.keep_locked(s, &old);
        if let Some(listen) = old.listen {
            listen.stop();
            self.hub.changed();
        }
        if let Some(stream) = old.stream {
            finish(&stream, old.link.as_ref(), true);
        }
    }
    /// What a disconnect leaves `s` of the binding `old` had, as Linux's
    /// `tcp_disconnect` and `__udp_disconnect` do: its port only if the guest
    /// bound that itself, and its address only if the guest named one.
    fn keep_locked(&self, s: &mut State, old: &State) {
        let Some(bound) = old.bound else {
            s.address = old.address;
            return;
        };
        let ip = if old.address_locked {
            bound.ip()
        } else {
            self.unspecified()
        };
        let mut ports = self.ports();
        if old.port_locked {
            let kept = SocketAddr::new(ip, bound.port());
            ports.connect(&self.this, kept, None);
            s.bound = Some(kept);
        } else {
            ports.unbind(&self.this);
            s.address = old.address_locked.then_some(ip);
        }
        s.port_locked = old.port_locked;
        s.address_locked = old.address_locked;
    }
    /// Resets this socket's connection, as a listener that stops does to
    /// those it has not handed out.
    fn abort(&self) {
        let s = std::mem::take(&mut *self.lock());
        if let Some(stream) = s.stream {
            finish(&stream, s.link.as_ref(), true);
        }
    }
    /// The peer's address, whatever the connection's state, as `accept`
    /// gives it (Linux's `inet_getname` with `peer` 2).
    fn remote(&self) -> Option<SocketAddr> {
        self.lock().stream.as_ref().map(|stream| stream.peer())
    }
}

/// Whether an open connection has ended both ways: the peer's end has come
/// and this side's has gone, so that Linux has moved it to `TCP_CLOSE`.
fn closed(stream: &Stream) -> bool {
    let ready = stream.readiness();
    ready.read_closed && stream.finished().0
}

/// Ends the guest's use of `stream`, as Linux's `tcp_close`: on the
/// loopback a connection with unread input, or closed with `abort` (a zero
/// linger time, a disconnect), is reset; any other ends after what it sent.
fn finish(stream: &Stream, link: Option<&(Arc<OnceLock<Arc<Link>>>, usize)>, abort: bool) {
    let joined = link.and_then(|(slot, side)| Some((slot.get()?, *side)));
    if let Some((link, side)) = joined
        && (abort || stream.queued().0 > 0)
    {
        link.reset(side);
    }
    stream.close();
}

impl Drop for InetSocket {
    fn drop(&mut self) {
        let abort = self.options().linger == Some(0);
        let s = std::mem::take(&mut *self.lock());
        if let Some(listen) = s.listen {
            listen.stop();
        }
        if let Some(stream) = s.stream {
            finish(&stream, s.link.as_ref(), abort);
        }
    }
}

/// What a receive took: the bytes copied, the whole datagram's length, and
/// where it came from.
struct Received {
    count: usize,
    length: usize,
    from: Option<SocketAddr>,
}
impl Received {
    fn bytes(count: usize) -> Self {
        Self {
            count,
            length: count,
            from: None,
        }
    }
}

impl FileHandle for InetSocket {
    /// As Linux's `tcp_poll`: a socket never connected, or whose connection
    /// ended, is hung up and writable; one connecting is neither readable
    /// nor writable; an open one is readable with bytes or at the end of
    /// input (`POLLRDHUP` too), writable while its buffer has room, and hung
    /// up once both directions are shut. `POLLERR` shows a pending error.
    /// A UDP socket is writable, and readable once an answer is ready.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        if self.datagram {
            let s = self.lock();
            let ready = self.first_datagram(&s).is_some();
            let error = u32::from(s.error.is_some()) * POLLERR;
            return Ok((OUT | (u32::from(ready) * IN) | error, s.received, 0));
        }
        let mut s = self.lock();
        // A listener is readable while a connection waits, and no more
        // (`inet_csk_listen_poll`).
        if let Some(listen) = &s.listen {
            return Ok((u32::from(!listen.ready.is_empty()) * IN, listen.arrivals, 0));
        }
        s.note();
        let error = u32::from(s.error.is_some()) * POLLERR;
        let Some(stream) = s.stream.clone() else {
            return Ok((OUT | POLLHUP | error, 0, 0));
        };
        let ready = stream.readiness();
        let mask = match stream.phase() {
            Phase::Connecting => 0,
            Phase::Failed(_) => IN | OUT | POLLHUP | POLLRDHUP,
            Phase::Open => {
                if !ready.writable {
                    self.signals.full();
                }
                let read_end = ready.read_closed || s.read_shut;
                (u32::from(ready.readable || s.read_shut) * IN)
                    | (u32::from(ready.writable) * OUT)
                    | (u32::from(read_end) * POLLRDHUP)
                    | (u32::from(read_end && ready.write_closed) * POLLHUP)
            }
        };
        Ok((mask | error, ready.arrivals, ready.departures))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.receive(buf, false).map(|received| received.count)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.send(buf, None)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.inode,
            mode: self.mode.load(Ordering::SeqCst),
            links: 1,
            ..FileStat::default()
        })
    }
    fn set_mode(&self, mode: u32) -> Result<(), Errno> {
        self.mode
            .store(0o140000 | (mode & 0o7777), Ordering::SeqCst);
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
        self.flags
            .store(2 | (flags & (NONBLOCK | O_ASYNC)), Ordering::SeqCst);
        Ok(())
    }
}

/// The inet socket of `file`, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&InetSocket> {
    file.as_any()?.downcast_ref::<InetSocket>()
}

/// Reads a socket address of `len` bytes at `at` for `socket`, as
/// `move_addr_to_kernel` (EINVAL past 128 bytes, EFAULT) and the protocol's
/// checks: `None` for `AF_UNSPEC`, EINVAL when too short, EAFNOSUPPORT for
/// another family. An IPv6 socket takes IPv4-mapped addresses.
fn read_address(
    c: &Context<'_>,
    socket: &InetSocket,
    at: u64,
    len: u64,
) -> Result<Option<SocketAddr>, Errno> {
    parse_address(socket.family, &read_raw(c, at, len)?)
}
/// The `len` bytes of a socket address at `at`, as `move_addr_to_kernel`.
fn read_raw(c: &Context<'_>, at: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let len = usize::try_from(len as u32 as i32)
        .ok()
        .filter(|&len| len <= 128)
        .ok_or(Errno::EINVAL)?;
    let mut raw = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    Ok(raw)
}
fn parse_address(family: Family, raw: &[u8]) -> Result<Option<SocketAddr>, Errno> {
    if raw.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let port = |raw: &[u8]| u16::from_be_bytes([raw[2], raw[3]]);
    match (u16::from_le_bytes([raw[0], raw[1]]), family) {
        (AF_UNSPEC, _) => Ok(None),
        (AF_INET, Family::V4) => {
            if raw.len() < 16 {
                return Err(Errno::EINVAL);
            }
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, port(raw)))))
        }
        (AF_INET6, Family::V6) => {
            if raw.len() < 24 {
                return Err(Errno::EINVAL);
            }
            let mut octets = [0; 16];
            octets.copy_from_slice(&raw[8..24]);
            let ip = Ipv6Addr::from(octets);
            let scope = if raw.len() >= 28 {
                u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]])
            } else {
                0
            };
            let flow = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
            Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port(raw),
                flow,
                scope,
            ))))
        }
        _ => Err(EAFNOSUPPORT),
    }
}
/// `address` as a `sockaddr_in` or `sockaddr_in6` of `family`: an IPv6
/// socket names an IPv4 address IPv4-mapped.
fn encode_address(family: Family, address: SocketAddr) -> Vec<u8> {
    let port = address.port().to_be_bytes();
    match (family, address) {
        (Family::V4, SocketAddr::V4(v4)) => {
            let mut raw = vec![0; 16];
            raw[..2].copy_from_slice(&AF_INET.to_le_bytes());
            raw[2..4].copy_from_slice(&port);
            raw[4..8].copy_from_slice(&v4.ip().octets());
            raw
        }
        (Family::V4, SocketAddr::V6(v6)) => encode_address(
            family,
            SocketAddr::from((
                v6.ip().to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
                v6.port(),
            )),
        ),
        (Family::V6, address) => {
            let (ip, flow, scope) = match address {
                SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped(), 0, 0),
                SocketAddr::V6(v6) => (*v6.ip(), v6.flowinfo(), v6.scope_id()),
            };
            let mut raw = vec![0; 28];
            raw[..2].copy_from_slice(&AF_INET6.to_le_bytes());
            raw[2..4].copy_from_slice(&port);
            raw[4..8].copy_from_slice(&flow.to_be_bytes());
            raw[8..24].copy_from_slice(&ip.octets());
            raw[24..28].copy_from_slice(&scope.to_le_bytes());
            raw
        }
    }
}
/// Writes `address` to `at` with its length at `len_at`, as
/// `move_addr_to_user`: the length read there first (EFAULT, EINVAL when
/// negative) bounds the bytes written, and the full length goes back.
fn write_address(c: &Context<'_>, address: &[u8], at: u64, len_at: u64) -> Result<(), Errno> {
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let n = room.min(address.len());
    if n > 0 {
        c.mem
            .write(GuestAddr(at), &address[..n])
            .map_err(|_| Errno::EFAULT)?;
    }
    c.mem
        .write(GuestAddr(len_at), &(address.len() as u32).to_le_bytes())
        .map_err(|_| Errno::EFAULT)
}

/// The system calls of an inet socket, `file` of descriptor `a[0]`.
pub(crate) fn dispatch(
    c: &mut Context<'_>,
    number: u64,
    a: [u64; 6],
    file: &Arc<dyn FileHandle>,
) -> Result<u64, Errno> {
    let socket = of(file).ok_or(ENOTSOCK)?;
    match number {
        // connect
        42 => {
            let address = read_address(c, socket, a[1], a[2])?;
            socket.connect(c, address)
        }
        // accept and accept4
        43 | 288 => accept(c, socket, a, if number == 288 { a[3] } else { 0 }),
        // bind, to the guest's own addresses
        49 => socket.bind(&read_raw(c, a[1], a[2])?),
        // listen
        50 => socket.listen(a[1]),
        // getsockname and getpeername
        51 | 52 => {
            let address = if number == 51 {
                socket.local()
            } else {
                socket.peer()?
            };
            write_address(c, &encode_address(socket.family, address), a[1], a[2])?;
            Ok(0)
        }
        48 => socket.shutdown(a[1]),
        54 => set_option(c, socket, a),
        55 => get_option(c, socket, a),
        44 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let to = if a[4] != 0 {
                read_address(c, socket, a[4], a[5])?
            } else {
                None
            };
            let mut bytes = vec![0; len];
            c.mem
                .read(GuestAddr(a[1]), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            send(c, file, socket, &bytes, a[3], to)
        }
        45 => {
            let len = crate::sockets::user_buffer(a[1], a[2])?;
            let mut bytes = vec![0; len];
            let received = receive(c, file, socket, &mut bytes, a[3])?;
            if a[3] & MSG_TRUNC == 0 || socket.datagram {
                c.mem
                    .write(GuestAddr(a[1]), &bytes[..received.count])
                    .map_err(|_| Errno::EFAULT)?;
            }
            if a[4] != 0 {
                let address = received
                    .from
                    .map(|from| encode_address(socket.family, from))
                    .unwrap_or_default();
                write_address(c, &address, a[4], a[5])?;
            }
            Ok(returned(&received, a[3], socket.datagram) as u64)
        }
        46 => {
            let header = crate::sockets::message_header(c, a[1], false)?;
            let to = match header.name {
                Some((at, len)) => read_address(c, socket, at, len as u64)?,
                None => None,
            };
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            for &(base, len) in &header.iov {
                let start = bytes.len();
                bytes.resize(start + len, 0);
                c.mem
                    .read(GuestAddr(base), &mut bytes[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            send(c, file, socket, &bytes, a[2], to)
        }
        47 => {
            let header = crate::sockets::message_header(c, a[1], true)?;
            let total = header.iov.iter().map(|(_, len)| len).sum::<usize>();
            let mut bytes = Vec::new();
            bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(total, 0);
            let received = receive(c, file, socket, &mut bytes, a[2])?;
            if a[2] & MSG_TRUNC == 0 || socket.datagram {
                crate::files::scatter(c, &header.iov, &bytes[..received.count])?;
            }
            let mut flags = 0u32;
            if socket.datagram && received.length > received.count {
                flags |= MSG_TRUNC as u32;
            }
            if header.has_name {
                let address = received
                    .from
                    .map(|from| encode_address(socket.family, from))
                    .unwrap_or_default();
                if let Some((at, room)) = header.name {
                    let n = room.min(address.len());
                    c.mem
                        .write(GuestAddr(at), &address[..n])
                        .map_err(|_| Errno::EFAULT)?;
                }
                c.mem
                    .write(GuestAddr(a[1] + 8), &(address.len() as u32).to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
            }
            c.mem
                .write(GuestAddr(a[1] + 40), &0u64.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            c.mem
                .write(GuestAddr(a[1] + 48), &flags.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            Ok(returned(&received, a[2], socket.datagram) as u64)
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// `accept` and `accept4` with `flags` (`SOCK_NONBLOCK` and
/// `SOCK_CLOEXEC`; EINVAL for any other), in Linux's order (`do_accept`):
/// the lowest free descriptor first (EMFILE), then the connection, then its
/// peer's address, which when it cannot be written loses the connection.
fn accept(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6], flags: u64) -> Result<u64, Errno> {
    if flags & !u64::from(NONBLOCK | CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let fd = c.files.reserve(c.group.nofile())?;
    let child = match socket.accept(c) {
        Ok(child) => child,
        Err(e) => {
            c.files.unreserve(fd);
            return Err(e);
        }
    };
    if flags & u64::from(NONBLOCK) != 0 {
        child.flags.store(2 | NONBLOCK, Ordering::SeqCst);
    }
    if a[1] != 0 {
        let peer = child.remote().unwrap_or(match socket.family {
            Family::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Family::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        });
        if let Err(e) = write_address(c, &encode_address(socket.family, peer), a[1], a[2]) {
            c.files.unreserve(fd);
            return Err(e);
        }
    }
    let cloexec = flags & u64::from(CLOEXEC) != 0;
    c.files
        .fill(fd, crate::files::Descriptor::unnamed(child, cloexec));
    Ok(u64::from(fd))
}
/// What a receive returns: with `MSG_TRUNC`, a datagram's whole length.
fn returned(received: &Received, flags: u64, datagram: bool) -> usize {
    if datagram && flags & MSG_TRUNC != 0 {
        received.length
    } else {
        received.count
    }
}
fn send(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &InetSocket,
    bytes: &[u8],
    flags: u64,
    to: Option<SocketAddr>,
) -> Result<u64, Errno> {
    if flags & MSG_OOB != 0 && socket.datagram {
        return Err(EOPNOTSUPP);
    }
    // TCP ignores the address of a connected socket's send.
    let to = if socket.datagram { to } else { None };
    crate::files::write_with(
        c,
        file,
        bytes,
        flags & MSG_NOSIGNAL != 0,
        flags & MSG_DONTWAIT != 0,
        |part| socket.send(part, to),
    )
}
/// Receives for recvfrom or recvmsg: `MSG_PEEK` keeps the bytes, and on
/// TCP `MSG_WAITALL` waits until the buffer is full or the input ends;
/// `MSG_OOB` finds no urgent byte (EINVAL).
fn receive(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    socket: &InetSocket,
    buf: &mut [u8],
    flags: u64,
) -> Result<Received, Errno> {
    if flags & MSG_OOB != 0 {
        return Err(if socket.datagram {
            EOPNOTSUPP
        } else {
            Errno::EINVAL
        });
    }
    let peek = flags & MSG_PEEK != 0;
    let dontwait = flags & MSG_DONTWAIT != 0;
    let wait = crate::sockets::wait_for(c, socket.timeout(true))?;
    let mut received =
        crate::files::wait_for_read_until(c, file, dontwait, wait, || socket.receive(buf, peek))?;
    if socket.datagram || flags & MSG_WAITALL == 0 || peek {
        return Ok(received);
    }
    while received.count > 0 && received.count < buf.len() {
        let rest = &mut buf[received.count..];
        match crate::files::wait_for_read_until(c, file, dontwait, wait, || {
            socket.receive(rest, false)
        }) {
            Ok(more) if more.count > 0 => received.count += more.count,
            _ => break,
        }
    }
    received.length = received.count;
    Ok(received)
}

/// Reads the `int` of a setsockopt (EINVAL for fewer than 4 bytes).
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
/// `setsockopt` of an inet socket: the `SOL_SOCKET` options a client sets,
/// `IPPROTO_TCP`'s `TCP_NODELAY`, keepalive timing (1 to 32767 seconds, at
/// most 127 probes), `TCP_QUICKACK` and `TCP_USER_TIMEOUT`, `IP_TOS` and
/// `IPV6_V6ONLY`. Any other option is ENOPROTOOPT. Only `TCP_NODELAY`
/// reaches the host; the rest are kept for getsockopt.
fn set_option(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len) = (a[1], a[2], a[3], a[4]);
    let mut options = socket.options();
    let tcp = !socket.datagram;
    match (level, name) {
        (1, 20 | 21 | 66 | 67) => {
            if (len as u32 as i32) < 16 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 16];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let word = |i: usize| i64::from_le_bytes(raw[i..i + 8].try_into().unwrap_or_default());
            let timeout = Timeout::from_timeval(word(0), word(8))?;
            if matches!(name, 20 | 66) {
                options.receive_timeout = timeout;
            } else {
                options.send_timeout = timeout;
            }
        }
        (1, 13) => {
            if (len as u32 as i32) < 8 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0; 8];
            c.mem
                .read(GuestAddr(at), &mut raw)
                .map_err(|_| Errno::EFAULT)?;
            let on = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let seconds = i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
            options.linger = (on != 0).then_some(seconds);
        }
        (1, 2 | 6 | 7 | 8 | 9 | 10 | 12 | 15)
        | (6, 1 | 4 | 5 | 6 | 12 | 18)
        | (0, 1)
        | (41, 26) => {
            let value = option_int(c, at, len)?;
            match (level, name) {
                (1, 2 | 15) => {
                    if name == 2 {
                        options.reuse_address = value != 0;
                    } else {
                        options.reuse_port = value != 0;
                    }
                    socket.ports().set_reuse(
                        &socket.this,
                        options.reuse_address,
                        options.reuse_port,
                    );
                }
                (1, 6) => options.broadcast = value != 0,
                (1, 7) => options.send_buffer = (value.clamp(0, i32::MAX / 2) * 2).max(4608),
                (1, 8) => options.receive_buffer = (value.clamp(0, i32::MAX / 2) * 2).max(2304),
                (1, 9) => options.keep_alive = value != 0,
                (1, 10) => options.out_of_band_inline = value != 0,
                (1, 12) => options.priority = value,
                (6, _) if !tcp => return Err(ENOPROTOOPT),
                (6, 1) => {
                    options.no_delay = value != 0;
                    if let Some(stream) = &socket.lock().stream {
                        stream.set_nodelay(value != 0);
                    }
                }
                (6, 4 | 5) if !(1..=32767).contains(&value) => return Err(Errno::EINVAL),
                (6, 4) => options.keep_idle = value,
                (6, 5) => options.keep_interval = value,
                (6, 6) if !(1..=127).contains(&value) => return Err(Errno::EINVAL),
                (6, 6) => options.keep_count = value,
                (6, 12) => options.quick_ack = value != 0,
                (6, 18) if value < 0 => return Err(Errno::EINVAL),
                (6, 18) => options.user_timeout = value,
                (0, 1) => options.type_of_service = value & 0xfc,
                (41, 26) if socket.family == Family::V6 => {
                    // Linux refuses it once the socket has a local port.
                    let s = socket.lock();
                    if s.stream.is_some() || s.bound.is_some() {
                        return Err(Errno::EINVAL);
                    }
                    options.v6_only = value != 0;
                }
                _ => return Err(ENOPROTOOPT),
            }
        }
        _ => return Err(ENOPROTOOPT),
    }
    Ok(0)
}
/// `getsockopt` of an inet socket: the options [`set_option`] keeps, and
/// `SO_TYPE`, `SO_ERROR` (which takes the pending error), `SO_ACCEPTCONN`,
/// `SO_PROTOCOL` and `SO_DOMAIN`. A level the socket does not have is
/// EOPNOTSUPP (setsockopt's is ENOPROTOOPT), an unknown name ENOPROTOOPT.
fn get_option(c: &mut Context<'_>, socket: &InetSocket, a: [u64; 6]) -> Result<u64, Errno> {
    let (level, name, at, len_at) = (a[1], a[2], a[3], a[4]);
    let mut raw = [0; 4];
    c.mem
        .read(GuestAddr(len_at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let room = usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Errno::EINVAL)?;
    let options = *socket.options();
    let tcp = !socket.datagram;
    // A level the protocol does not have goes on to IPv4's, which refuses it
    // (`do_ip_getsockopt`); an IPv6 socket takes IPv4's own options too.
    let known = match level {
        0 | 1 => true,
        6 => tcp,
        17 => !tcp,
        41 => socket.family == Family::V6,
        _ => false,
    };
    if !known {
        return Err(EOPNOTSUPP);
    }
    let value: Vec<u8> = match (level, name) {
        (1, 20 | 21 | 66 | 67) => {
            let timeout = if matches!(name, 20 | 66) {
                options.receive_timeout
            } else {
                options.send_timeout
            };
            timeout.timeval().to_vec()
        }
        (1, 13) => {
            let mut linger = [0; 8];
            linger[..4].copy_from_slice(&i32::from(options.linger.is_some()).to_le_bytes());
            linger[4..].copy_from_slice(&options.linger.unwrap_or(0).to_le_bytes());
            linger.to_vec()
        }
        _ => {
            let int = match (level, name) {
                (1, 2) => i32::from(options.reuse_address),
                (1, 3) => {
                    if tcp {
                        1
                    } else {
                        2
                    }
                }
                (1, 4) => {
                    let mut s = socket.lock();
                    s.note();
                    s.error.take().map_or(0, |e| e.0)
                }
                (1, 6) => i32::from(options.broadcast),
                (1, 7) => options.send_buffer,
                (1, 8) => options.receive_buffer,
                (1, 9) => i32::from(options.keep_alive),
                (1, 10) => i32::from(options.out_of_band_inline),
                (1, 12) => options.priority,
                (1, 15) => i32::from(options.reuse_port),
                (1, 30) => i32::from(socket.lock().listen.is_some()),
                (1, 38) => {
                    if tcp {
                        6
                    } else {
                        17
                    }
                }
                (1, 39) => i32::from(match socket.family {
                    Family::V4 => AF_INET,
                    Family::V6 => AF_INET6,
                }),
                (6, 1) => i32::from(options.no_delay),
                (6, 4) => options.keep_idle,
                (6, 5) => options.keep_interval,
                (6, 6) => options.keep_count,
                (6, 12) => i32::from(options.quick_ack),
                (6, 18) => options.user_timeout,
                (0, 1) => options.type_of_service,
                (41, 26) if socket.family == Family::V6 => i32::from(options.v6_only),
                _ => return Err(ENOPROTOOPT),
            };
            int.to_le_bytes().to_vec()
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

/// Reads a DNS query: one question with an uncompressed name. A query the
/// stub cannot read is answered `FORMERR`, one of another opcode `NOTIMP`,
/// one of another class with no records; a datagram too short for a header
/// gets no answer. Any other is `NXDOMAIN` until the send finds its name
/// allowed and starts its lookup.
fn parse_query(bytes: &[u8], from: SocketAddr) -> Option<Query> {
    if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
        return None;
    }
    let id = [bytes[0], bytes[1]];
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let mut query = Query {
        from,
        seq: 0,
        id,
        flags,
        question: Vec::new(),
        name: String::new(),
        kind: 0,
        answer: Answer::Now(1),
    };
    if (flags >> 11) & 0xf != 0 {
        query.answer = Answer::Now(4);
        return Some(query);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != 1 {
        return Some(query);
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*bytes.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        if len > 63 || at + 1 + len > bytes.len() {
            return Some(query);
        }
        labels.push(String::from_utf8_lossy(&bytes[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    if at + 4 > bytes.len() {
        return Some(query);
    }
    query.question = bytes[12..at + 4].to_vec();
    query.kind = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let class = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
    query.name = labels.join(".").to_ascii_lowercase();
    query.answer = Answer::Now(match normal(&query.name) {
        Some(_) if class != 1 => 0,
        Some(_) => 3,
        None => 3,
    });
    Some(query)
}
/// Starts the host's lookup of an allowed name the stub cannot answer
/// at once.
fn start_lookup(network: &Network, host: &dyn paludarium_host::Host, query: &mut Query) {
    if matches!(query.answer, Answer::Now(3))
        && !query.question.is_empty()
        && network.policy.allows_name(&query.name)
    {
        query.answer = match network.lookup(host, &query.name) {
            Ok(lookup) => Answer::Lookup(lookup),
            Err(_) => Answer::Now(2),
        };
    }
}

/// The stub over TCP, as a resolver asks it when a datagram answer was
/// truncated: a connection to port 53, at any address, is the stub's own
/// stream, which takes queries with their two-byte lengths, as RFC 1035
/// frames them, and gives each answer, in order, framed the same way. Once
/// the guest has shut its sending down and every answer has gone, the
/// stream ends.
struct DnsOverTcp {
    /// Itself, for the wakers of the lookups it waits for.
    me: Weak<DnsOverTcp>,
    stream: Weak<Stream>,
    peer: SocketAddr,
    network: Arc<Network>,
    host: Arc<dyn paludarium_host::Host>,
    state: Mutex<DnsState>,
}
#[derive(Default)]
struct DnsState {
    /// What the guest sent that is not yet a whole query.
    incoming: Vec<u8>,
    queries: VecDeque<Query>,
    /// Answer bytes the stream had no room for yet.
    outgoing: VecDeque<u8>,
    ended: bool,
}
impl DnsOverTcp {
    fn open(
        peer: SocketAddr,
        network: &Arc<Network>,
        host: &Arc<dyn paludarium_host::Host>,
    ) -> Arc<Stream> {
        let stream = Stream::new(peer);
        let driver = Arc::new_cyclic(|me| Self {
            me: Weak::clone(me),
            stream: Arc::downgrade(&stream),
            peer,
            network: Arc::clone(network),
            host: Arc::clone(host),
            state: Mutex::default(),
        });
        stream.set_driver(driver);
        stream
    }
    /// Reads the guest's queries, starts their lookups, and gives the
    /// answers that are ready.
    fn pump(&self) {
        let Some(stream) = self.stream.upgrade() else {
            return;
        };
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let bytes = stream.take(64 * 1024);
            if bytes.is_empty() {
                break;
            }
            s.incoming.extend_from_slice(&bytes);
        }
        while s.incoming.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([s.incoming[0], s.incoming[1]]));
            if s.incoming.len() < 2 + len {
                break;
            }
            let message: Vec<u8> = s.incoming.drain(..2 + len).skip(2).collect();
            let Some(mut query) = parse_query(&message, self.peer) else {
                continue;
            };
            start_lookup(&self.network, self.host.as_ref(), &mut query);
            if let Answer::Lookup(lookup) = &query.answer {
                let me = Weak::clone(&self.me);
                lookup.add_waker(Arc::new(move || {
                    if let Some(driver) = me.upgrade() {
                        driver.pump();
                    }
                }));
            }
            s.queries.push_back(query);
        }
        while let Some(answer) = s
            .queries
            .front()
            .and_then(|query| answer(&self.network, self.host.as_ref(), query, TCP_ANSWER))
        {
            s.queries.pop_front();
            s.outgoing.extend((answer.len() as u16).to_be_bytes());
            s.outgoing.extend(answer);
        }
        // As much as the stream takes; a read that frees a full stream
        // kicks for the rest.
        while !s.outgoing.is_empty() {
            let chunk = s.outgoing.make_contiguous().to_vec();
            let given = stream.receive(&chunk);
            s.outgoing.drain(..given);
            if given < chunk.len() {
                break;
            }
        }
        if s.queries.is_empty() && s.outgoing.is_empty() && stream.finished().0 && !s.ended {
            s.ended = true;
            drop(s);
            stream.end();
        }
    }
}
impl Driver for DnsOverTcp {
    /// The guest wrote, read or shut down: the stub answers at once, in the
    /// caller's thread, as the stream is unlocked then.
    fn kick(&self) {
        self.pump();
    }
}

/// The answer to `query`, once it can be given, in at most `limit` bytes:
/// only the addresses a name rule may reach, and NXDOMAIN when none is
/// left.
fn answer(
    network: &Network,
    host: &dyn paludarium_host::Host,
    query: &Query,
    limit: usize,
) -> Option<Vec<u8>> {
    let (code, addresses) = match &query.answer {
        Answer::Now(code) => (*code, Vec::new()),
        // Only the addresses a name rule may reach; none is NXDOMAIN.
        Answer::Lookup(lookup) => match lookup.result()? {
            Ok(found) => {
                let found: Vec<IpAddr> = found
                    .into_iter()
                    .filter(|ip| reachable(&query.name, *ip))
                    .collect();
                if found.is_empty() {
                    (3, found)
                } else {
                    let now = host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0);
                    network.note(&query.name, &found, now);
                    (0, found)
                }
            }
            Err(_) => (2, Vec::new()),
        },
    };
    Some(build_answer(query, code, &addresses, limit))
}

/// The most a datagram answer holds, without EDNS.
const UDP_ANSWER: usize = 512;
/// The most a TCP answer holds, as its two-byte length allows.
const TCP_ANSWER: usize = 65535;
/// The answer to `query` with response code `code` and, for an `A` or
/// `AAAA` question, the addresses of that family, each for 60 seconds, as
/// many as fit in `limit` bytes: when some do not, the answer is marked
/// truncated (TC), so that the resolver asks again over TCP.
fn build_answer(query: &Query, code: u8, addresses: &[IpAddr], limit: usize) -> Vec<u8> {
    let mut answer = Vec::with_capacity(limit.min(4096));
    answer.extend_from_slice(&query.id);
    // QR, the opcode and RD as asked, RA, and the code.
    let flags = 0x8080 | (query.flags & 0x7900) | u16::from(code);
    answer.extend_from_slice(&flags.to_be_bytes());
    let questions = u16::from(!query.question.is_empty());
    answer.extend_from_slice(&questions.to_be_bytes());
    answer.extend_from_slice(&[0; 6]);
    answer.extend_from_slice(&query.question);
    let mut count = 0u16;
    for ip in addresses {
        let data: Vec<u8> = match (query.kind, ip) {
            (1, IpAddr::V4(v4)) => v4.octets().to_vec(),
            (28, IpAddr::V6(v6)) => v6.octets().to_vec(),
            _ => continue,
        };
        if answer.len() + 12 + data.len() > limit {
            answer[2] |= 0x02;
            break;
        }
        answer.extend_from_slice(&[0xc0, 0x0c]);
        answer.extend_from_slice(&query.kind.to_be_bytes());
        answer.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        answer.extend_from_slice(&(data.len() as u16).to_be_bytes());
        answer.extend_from_slice(&data);
        count += 1;
    }
    answer[6..8].copy_from_slice(&count.to_be_bytes());
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_name_hosts_addresses_and_ports() {
        let policy = NetworkPolicy::new()
            .allow("GitHub.com:443")
            .unwrap()
            .allow("*.example.org")
            .unwrap()
            .allow("127.0.0.1:8080")
            .unwrap()
            .allow("[::1]:9000")
            .unwrap()
            .allow("2001:db8::1")
            .unwrap();
        assert!(policy.allows_name("github.com"));
        assert!(policy.allows_name("a.b.example.org"));
        assert!(!policy.allows_name("example.org"));
        assert!(!policy.allows_name("evilgithub.com"));
        let network = Network::new(policy);
        assert!(network.allows("127.0.0.1:8080".parse().unwrap(), 0));
        assert!(network.allows("[::ffff:127.0.0.1]:8080".parse().unwrap(), 0));
        assert!(!network.allows("127.0.0.1:8081".parse().unwrap(), 0));
        assert!(network.allows("[::1]:9000".parse().unwrap(), 0));
        assert!(network.allows("[2001:db8::1]:1".parse().unwrap(), 0));
        let github: SocketAddr = "192.0.2.7:443".parse().unwrap();
        assert!(!network.allows(github, 0));
        network.note("github.com", &[github.ip()], 5);
        assert!(network.allows(github, 5));
        assert!(!network.allows("192.0.2.7:80".parse().unwrap(), 5));
        // The name's address expires; another answer gives it again.
        assert!(!network.allows(github, 5 + NAME_LIFETIME));
        network.note("github.com", &[github.ip()], 5 + NAME_LIFETIME);
        assert!(network.allows(github, 5 + NAME_LIFETIME));
        for bad in [
            "", "a:b", "a:0", "[::1", "[::1]x", "bad name", "a..b", "a:70000",
        ] {
            assert!(NetworkPolicy::new().allow(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn name_rules_reach_only_global_addresses() {
        for (name, ip, ok) in [
            ("github.com", "140.82.112.3", true),
            ("github.com", "2606:50c0:8000::153", true),
            ("evil.example.org", "127.0.0.1", false),
            ("evil.example.org", "10.1.2.3", false),
            ("evil.example.org", "172.16.0.1", false),
            ("evil.example.org", "192.168.1.1", false),
            ("evil.example.org", "169.254.169.254", false),
            ("evil.example.org", "100.64.0.1", false),
            ("evil.example.org", "0.0.0.0", false),
            ("evil.example.org", "::1", false),
            ("evil.example.org", "fd00::1", false),
            ("evil.example.org", "fe80::1", false),
            ("evil.example.org", "::ffff:10.0.0.1", false),
            ("evil.example.org", "64:ff9b::7f00:1", false),
            ("evil.example.org", "64:ff9b::c0a8:101", false),
            ("github.com", "64:ff9b::8c52:7003", true),
            ("evil.example.org", "2002:a00:1::1", false),
            ("github.com", "2002:8c52:7003::1", true),
            ("localhost", "127.0.0.1", true),
            ("localhost", "::1", true),
            ("app.localhost", "127.0.0.2", true),
            ("localhost", "10.0.0.1", false),
        ] {
            assert_eq!(reachable(name, ip.parse().unwrap()), ok, "{name} {ip}");
        }
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&[0, 1]);
        bytes
    }

    #[test]
    fn the_stub_answers_a_and_aaaa_questions() {
        let from: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let q = parse_query(&query("GitHub.com", 1), from).unwrap();
        assert_eq!(q.name, "github.com");
        assert_eq!(q.kind, 1);
        let addresses: Vec<IpAddr> =
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        let answer = build_answer(&q, 0, &addresses, UDP_ANSWER);
        assert_eq!(&answer[..4], &[0x12, 0x34, 0x81, 0x80]);
        assert_eq!(&answer[4..12], &[0, 1, 0, 1, 0, 0, 0, 0]);
        assert_eq!(&answer[answer.len() - 4..], &[192, 0, 2, 1]);
        let q6 = parse_query(&query("github.com", 28), from).unwrap();
        let answer = build_answer(&q6, 0, &addresses, UDP_ANSWER);
        assert_eq!(&answer[6..8], &[0, 1]);
        assert_eq!(answer[answer.len() - 1], 2);
        let missing = build_answer(&q, 3, &[], UDP_ANSWER);
        assert_eq!(missing[3] & 0xf, 3);
        assert_eq!(&missing[6..8], &[0, 0]);
        // Too many to fit are cut at 512 bytes.
        let many: Vec<IpAddr> = (0..100)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
            .collect();
        let cut = build_answer(&q, 0, &many, UDP_ANSWER);
        assert!(cut.len() <= 512);
        assert_eq!(cut[2] & 0x02, 0x02, "TC");
        assert_eq!(build_answer(&q, 0, &addresses, UDP_ANSWER)[2] & 0x02, 0);
        // Over TCP they all fit.
        let whole = build_answer(&q, 0, &many, TCP_ANSWER);
        assert_eq!((whole[2] & 0x02, &whole[6..8]), (0, &[0, 100][..]));
        // Another opcode is not implemented; two questions are a format error.
        let mut status = query("a.b", 1);
        status[2] = 0x10;
        assert!(matches!(
            parse_query(&status, from).unwrap().answer,
            Answer::Now(4)
        ));
        let mut two = query("a.b", 1);
        two[5] = 2;
        assert!(matches!(
            parse_query(&two, from).unwrap().answer,
            Answer::Now(1)
        ));
        assert!(parse_query(&[0; 4], from).is_none());
    }

    #[test]
    fn addresses_take_linux_layouts() {
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let raw = encode_address(Family::V4, v4);
        assert_eq!(raw, [2, 0, 1, 187, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_address(Family::V4, &raw), Ok(Some(v4)));
        let mapped = encode_address(Family::V6, v4);
        assert_eq!(mapped.len(), 28);
        assert_eq!(
            &mapped[8..24],
            &Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().octets()
        );
        assert_eq!(parse_address(Family::V4, &mapped), Err(EAFNOSUPPORT));
        assert_eq!(parse_address(Family::V4, &raw[..8]), Err(Errno::EINVAL));
        assert_eq!(parse_address(Family::V6, &mapped[..20]), Err(Errno::EINVAL));
        assert_eq!(parse_address(Family::V6, &[0, 0]), Ok(None));
        assert_eq!(parse_address(Family::V6, &[0]), Err(Errno::EINVAL));
    }
}
