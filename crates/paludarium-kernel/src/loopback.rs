//! The guest's own loopback: the TCP servers a guest binds, listens and
//! accepts on, the connections its other sockets open to them, which the
//! kernel joins itself, and the UDP datagrams its sockets send each other.
//! Only the guest reaches a guest's socket; neither the host nor another
//! machine does.
//!
//! A connection is two [`Stream`]s, one for each socket, that a [`Link`]
//! moves bytes between in the caller's thread whenever either changes, so
//! that a loopback socket reads, writes and polls as one the host connected.
//! [`Ports`] keeps what each TCP or UDP socket holds a local port with, as
//! Linux's bind buckets and UDP hash do, for `bind`'s conflicts and to find
//! a connection's listener or a datagram's receiver.
use crate::inet::InetSocket;
use core::hash::{Hash, Hasher};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use paludarium_host::net::{Driver, Phase, Stream};
use paludarium_types::Errno;
use std::hash::DefaultHasher;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

const EADDRINUSE: Errno = Errno(98);
const ECONNRESET: Errno = Errno(104);
/// Linux's default `net.ipv4.ip_local_port_range`.
const EPHEMERAL: core::ops::RangeInclusive<u16> = 32768..=60999;
/// How long the side that closed a connection first keeps its port, in
/// nanoseconds: Linux's `TCP_TIMEWAIT_LEN`.
pub(crate) const TIME_WAIT: u64 = 60_000_000_000;
/// [`Link::first`] before either side has ended, and once one was reset.
const NO_SIDE: u8 = 2;
const RESET: u8 = 3;

/// The two streams of a connection between guest sockets.
pub(crate) struct Link {
    /// `None` once both sides have closed, or one was reset, so that the
    /// streams, which hold the link as their driver, are freed.
    ends: Mutex<Option<Ends>>,
    /// The side whose end reached the other first, kept after `ends` goes;
    /// [`NO_SIDE`] before, [`RESET`] once either side was reset.
    first: AtomicU8,
}
struct Ends {
    streams: [Arc<Stream>; 2],
    /// Whether each side's end has reached the other.
    ended: [bool; 2],
}

impl Link {
    /// Joins a connecting `client` stream to a new `server` one and opens
    /// both, the server's first: `client` from `client_local`, `server` from
    /// `server_local`.
    pub(crate) fn join(
        client: &Arc<Stream>,
        server: &Arc<Stream>,
        client_local: SocketAddr,
        server_local: SocketAddr,
    ) -> Arc<Self> {
        let link = Arc::new(Self {
            ends: Mutex::new(Some(Ends {
                streams: [Arc::clone(client), Arc::clone(server)],
                ended: [false; 2],
            })),
            first: AtomicU8::new(NO_SIDE),
        });
        client.set_driver(Arc::clone(&link) as Arc<dyn Driver>);
        server.set_driver(Arc::clone(&link) as Arc<dyn Driver>);
        server.connected(Some(server_local));
        client.connected(Some(client_local));
        link
    }
    /// Closes `side` with a reset, as Linux's `tcp_close` sends one for
    /// unread data or a zero linger time, and `inet_csk_listen_stop` for a
    /// connection never accepted: the other side fails with `ECONNRESET`, or
    /// `EPIPE` once it has had this side's end and not shut its own
    /// (`tcp_reset` in `TCP_CLOSE_WAIT`), after the bytes it holds.
    pub(crate) fn reset(&self, side: usize) {
        let ends = self
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.first.store(RESET, Ordering::SeqCst);
        let Some(ends) = ends else { return };
        let (own, peer) = (&ends.streams[side], &ends.streams[1 - side]);
        if !gone(peer) {
            let waiting = ends.ended[side] && !peer.readiness().write_closed;
            peer.fail(if waiting { Errno::EPIPE } else { ECONNRESET });
        }
        own.close();
    }
    /// Whether `side` ends the connection first, with neither side reset:
    /// its end reached the other before the other's did, or neither has yet,
    /// as when it closed with bytes still to send (Linux's `FIN_WAIT1` holds
    /// the port too). Linux keeps that side in `TIME_WAIT` once it closes.
    pub(crate) fn closes_first(&self, side: usize) -> bool {
        let first = self.first.load(Ordering::SeqCst);
        usize::from(first) == side || first == NO_SIDE
    }
    /// Moves what each side sends to the other, as far as the other's
    /// buffer takes it, and each side's end once its bytes have gone. A
    /// side that sends to a closed peer gets a reset, as Linux's peer
    /// answers data after its close (`tcp_rcv_state_process`).
    fn pump(&self) {
        let mut guard = self.ends.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(ends) = guard.as_mut() else { return };
        for from in 0..2 {
            let (own, peer) = (&ends.streams[from], &ends.streams[1 - from]);
            if matches!(own.phase(), Phase::Failed(_)) {
                continue;
            }
            if gone(peer) {
                if own.queued().1 > 0 {
                    // The closed side answers with a reset, which ends its
                    // `TIME_WAIT` too.
                    self.first.store(RESET, Ordering::SeqCst);
                    own.take(usize::MAX);
                    own.fail(if ends.ended[1 - from] {
                        Errno::EPIPE
                    } else {
                        ECONNRESET
                    });
                }
                continue;
            }
            let room = peer.room();
            if room > 0 {
                let bytes = own.take(room);
                if !bytes.is_empty() {
                    peer.receive(&bytes);
                }
            }
            let (shut, closed) = own.finished();
            if (shut || (closed && own.queued().1 == 0)) && !ends.ended[from] {
                ends.ended[from] = true;
                let _ = self.first.compare_exchange(
                    NO_SIDE,
                    from as u8,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                peer.end();
            }
        }
        if ends.streams.iter().all(|stream| stream.finished().1) {
            *guard = None;
        }
    }
}
impl Driver for Link {
    /// A side wrote, read, shut down or closed: the bytes move at once.
    fn kick(&self) {
        self.pump();
    }
}
/// Whether `stream`'s socket has closed it or it was reset.
fn gone(stream: &Stream) -> bool {
    stream.finished().1 || matches!(stream.phase(), Phase::Failed(_))
}

/// A TCP socket's hold on a local port.
#[derive(Clone)]
pub(crate) struct Binding {
    /// Its address, IPv4 as such even on an IPv6 socket; the unspecified
    /// address for every one.
    pub(crate) address: SocketAddr,
    /// An IPv6 socket's, whose unspecified address covers IPv4 too unless
    /// `v6_only`.
    pub(crate) v6: bool,
    pub(crate) v6_only: bool,
    pub(crate) reuse_address: bool,
    pub(crate) reuse_port: bool,
    /// In a group of sockets sharing the port with `SO_REUSEPORT`, which
    /// a TCP listener joins when it listens, and a UDP socket when it
    /// binds (`inet_reuseport_add_sock`, `udp_reuseport_add_sock`).
    pub(crate) pooled: bool,
    pub(crate) listening: bool,
    /// A connected UDP socket's peer, the only sender it receives from.
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) owner: Weak<InetSocket>,
    /// A closed connection's hold in `TIME_WAIT`, after its socket has
    /// gone.
    pub(crate) time_wait: Option<TimeWait>,
}
/// When a hold in `TIME_WAIT` ends, and its connection and side: a reset,
/// or the other side's end reaching it first, ends it sooner.
#[derive(Clone)]
pub(crate) struct TimeWait {
    until: u64,
    link: Arc<Link>,
    side: usize,
}
impl Binding {
    fn carries(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => !self.v6 || !self.v6_only,
            IpAddr::V6(_) => self.v6,
        }
    }
    /// Whether the two hold the same port on an address both cover, as
    /// Linux's `inet_rcv_saddr_equal` with wildcards.
    fn overlaps(&self, other: &Binding) -> bool {
        if self.address.port() != other.address.port() {
            return false;
        }
        let (a, b) = (self.address.ip(), other.address.ip());
        match (a.is_unspecified(), b.is_unspecified()) {
            (true, true) => {
                (self.carries(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                    && other.carries(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
                    || (self.v6 && other.v6)
            }
            (true, false) => self.carries(b),
            (false, true) => other.carries(a),
            (false, false) => a == b,
        }
    }
    /// Whether `self` may not take its port beside `other`, as Linux's
    /// `inet_bind_conflict`: both with `SO_REUSEADDR` share it unless
    /// `other` listens, and both with `SO_REUSEPORT` always.
    fn conflicts(&self, other: &Binding) -> bool {
        self.overlaps(other)
            && !(self.reuse_address && other.reuse_address && !other.listening)
            && !(self.reuse_port && other.reuse_port)
    }
    fn is(&self, owner: &Weak<InetSocket>) -> bool {
        self.time_wait.is_none() && Weak::ptr_eq(&self.owner, owner)
    }
    /// Whether `other` is in `self`'s group: of the same family, on the
    /// same address and port.
    fn pools_with(&self, other: &Binding) -> bool {
        self.pooled
            && other.pooled
            && self.address == other.address
            && self.v6 == other.v6
            && self.v6_only == other.v6_only
            && self.listening == other.listening
    }
}

/// Which of `count` sockets sharing a port a connection or datagram from
/// `from` to `to` reaches, as Linux's `reuseport_select_sock` scales a hash
/// of the four, though not with Linux's own hash and secret.
fn pick(from: SocketAddr, to: SocketAddr, count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    (from, to).hash(&mut hasher);
    let hash = hasher.finish() as u32;
    ((u64::from(hash) * count as u64) >> 32) as usize
}

/// The local ports the TCP sockets, or the UDP ones, hold, and where the
/// next ephemeral one is looked for.
pub(crate) struct Ports {
    bindings: Vec<Binding>,
    next: u16,
}
impl Default for Ports {
    fn default() -> Self {
        Self {
            bindings: Vec::new(),
            next: *EPHEMERAL.start(),
        }
    }
}
impl Ports {
    /// Forgets the sockets that have gone, but for those in `TIME_WAIT`.
    fn live(&mut self) {
        self.bindings
            .retain(|binding| binding.owner.strong_count() > 0 || binding.time_wait.is_some());
    }
    /// Forgets the holds in `TIME_WAIT` that have ended by `now`, or whose
    /// side no longer ends its connection first.
    pub(crate) fn expire(&mut self, now: u64) {
        self.bindings.retain(|binding| {
            binding
                .time_wait
                .as_ref()
                .is_none_or(|wait| wait.until > now && wait.link.closes_first(wait.side))
        });
    }
    /// `owner`, which ends `link` first from `side`, keeps its port in
    /// `TIME_WAIT` until `until`, as it was, with its `SO_REUSEADDR`:
    /// Linux's `inet_twsk_hashdance` puts a `TIME_WAIT` socket in its bind
    /// bucket.
    pub(crate) fn linger(
        &mut self,
        owner: &Weak<InetSocket>,
        (link, side): (&Arc<Link>, usize),
        until: u64,
    ) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.owner = Weak::new();
                binding.time_wait = Some(TimeWait {
                    until,
                    link: Arc::clone(link),
                    side,
                });
            }
        }
    }
    /// Takes `binding`'s port, or with port 0 the next free ephemeral one;
    /// `EADDRINUSE` when it conflicts, or no ephemeral port is free.
    /// Returns the address taken.
    pub(crate) fn bind(&mut self, mut binding: Binding) -> Result<SocketAddr, Errno> {
        self.live();
        if binding.address.port() == 0 {
            let count = EPHEMERAL.len();
            let free = (0..count).find_map(|i| {
                let offset = (usize::from(self.next - EPHEMERAL.start()) + i) % count;
                let port = EPHEMERAL.start() + offset as u16;
                binding.address.set_port(port);
                (!self.bindings.iter().any(|other| binding.overlaps(other))).then_some(port)
            });
            let port = free.ok_or(EADDRINUSE)?;
            self.next = if port == *EPHEMERAL.end() {
                *EPHEMERAL.start()
            } else {
                port + 1
            };
        } else if self.bindings.iter().any(|other| binding.conflicts(other)) {
            return Err(EADDRINUSE);
        }
        let address = binding.address;
        self.bindings.push(binding);
        Ok(address)
    }
    /// Marks `owner` listening, with its options now: `EADDRINUSE` when
    /// another socket on its port forbids it, as `inet_csk_get_port` checks
    /// again.
    pub(crate) fn listen(
        &mut self,
        owner: &Weak<InetSocket>,
        reuse_address: bool,
        reuse_port: bool,
    ) -> Result<(), Errno> {
        self.live();
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.is(owner))
            .ok_or(Errno::EINVAL)?;
        let mut own = self.bindings[index].clone();
        own.reuse_address = reuse_address;
        own.reuse_port = reuse_port;
        own.pooled = reuse_port;
        let blocked = self
            .bindings
            .iter()
            .enumerate()
            .any(|(i, other)| i != index && own.conflicts(other));
        if blocked {
            return Err(EADDRINUSE);
        }
        own.listening = true;
        self.bindings[index] = own;
        Ok(())
    }
    /// Adds `binding` as it is: an accepted connection's, on its
    /// listener's port.
    pub(crate) fn hold(&mut self, binding: Binding) {
        self.live();
        self.bindings.push(binding);
    }
    /// `owner`'s `SO_REUSEADDR` and `SO_REUSEPORT` now, which Linux reads
    /// as they are when it checks a conflict. A socket stays in the group it
    /// joined, as `sock_setsockopt` only sets `sk_reuseport`; while it is
    /// clear, the socket picks no other ([`Ports::shared`]).
    pub(crate) fn set_reuse(&mut self, owner: &Weak<InetSocket>, address: bool, port: bool) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.reuse_address = address;
                binding.reuse_port = port;
            }
        }
    }
    /// `owner` stopped listening.
    pub(crate) fn stop_listening(&mut self, owner: &Weak<InetSocket>) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.listening = false;
                binding.pooled = false;
            }
        }
    }
    /// `owner` now holds its port on `address`, as a connection's source.
    pub(crate) fn rebind(&mut self, owner: &Weak<InetSocket>, address: SocketAddr) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.address = address;
            }
        }
    }
    /// `owner`, a UDP socket, connected from `address` to `peer`, or with
    /// `None` disconnected; on another address it leaves its group, as
    /// Linux's `udp_lib_rehash`.
    pub(crate) fn connect(
        &mut self,
        owner: &Weak<InetSocket>,
        address: SocketAddr,
        peer: Option<SocketAddr>,
    ) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.pooled &= binding.address == address;
                binding.address = address;
                binding.peer = peer;
            }
        }
    }
    /// `owner` gave its port up.
    pub(crate) fn unbind(&mut self, owner: &Weak<InetSocket>) {
        self.bindings.retain(|binding| !binding.is(owner));
    }
    /// The listener a connection from `from` to `to` reaches, as Linux's
    /// `__inet_lookup_listener`: one bound to that address before one bound
    /// to every address, and an IPv4 socket before an IPv6 one; among equals
    /// the first to bind, or one of its group ([`pick`]).
    pub(crate) fn listener(&mut self, from: SocketAddr, to: SocketAddr) -> Option<Arc<InetSocket>> {
        self.live();
        let best = self.best_listener(to)?;
        self.shared(best, from, to, |_| true).owner.upgrade()
    }
    /// Whether a socket listens where a connection to `to` reaches.
    pub(crate) fn listens(&mut self, to: SocketAddr) -> bool {
        self.live();
        self.best_listener(to).is_some()
    }
    /// The listener that ranks first for `to`, before its group.
    fn best_listener(&self, to: SocketAddr) -> Option<&Binding> {
        let ip = to.ip();
        let score = |binding: &Binding| {
            if !binding.listening || binding.address.port() != to.port() || !binding.carries(ip) {
                return None;
            }
            let bound = binding.address.ip();
            let exact = if bound.is_unspecified() {
                false
            } else if bound == ip {
                true
            } else {
                return None;
            };
            Some((exact, !binding.v6))
        };
        let mut best: Option<((bool, bool), &Binding)> = None;
        for binding in &self.bindings {
            if let Some(found) = score(binding)
                && best.is_none_or(|(score, _)| found > score)
            {
                best = Some((found, binding));
            }
        }
        best.map(|(_, binding)| binding)
    }
    /// `best`, or when it shares its port with `SO_REUSEPORT` one of its
    /// group that `takes` from `from` to `to`.
    fn shared<'a>(
        &'a self,
        best: &'a Binding,
        from: SocketAddr,
        to: SocketAddr,
        takes: impl Fn(&Binding) -> bool,
    ) -> &'a Binding {
        if !best.reuse_port {
            return best;
        }
        let group: Vec<&Binding> = self
            .bindings
            .iter()
            .filter(|other| best.pools_with(other))
            .collect();
        if group.is_empty() {
            return best;
        }
        // Linux goes on from the one the hash picks past those that do not
        // take it (`reuseport_select_sock_by_hash`).
        let start = pick(from, to, group.len());
        (0..group.len())
            .map(|i| group[(start + i) % group.len()])
            .find(|binding| takes(binding))
            .unwrap_or(best)
    }
    /// The UDP socket a datagram from `from` to `to` reaches, as Linux's
    /// `compute_score` ranks them: a connected one only from its peer, and
    /// one bound to that address, connected, or IPv4, before others; among
    /// equals the last to bind, which Linux's hash holds first, or one of its
    /// group that is not connected ([`pick`]).
    pub(crate) fn receiver(&mut self, to: SocketAddr, from: SocketAddr) -> Option<Arc<InetSocket>> {
        self.live();
        let ip = to.ip();
        let score = |binding: &Binding| {
            if binding.address.port() != to.port() || !binding.carries(ip) {
                return None;
            }
            let mut score = if binding.v6 { 1 } else { 2 };
            let bound = binding.address.ip();
            if !bound.is_unspecified() {
                if bound != ip {
                    return None;
                }
                score += 4;
            }
            if let Some(peer) = binding.peer {
                if peer != from {
                    return None;
                }
                score += 8;
            }
            Some(score)
        };
        let mut best: Option<(u8, &Binding)> = None;
        for binding in self.bindings.iter().rev() {
            if let Some(found) = score(binding)
                && best.is_none_or(|(score, _)| found > score)
            {
                best = Some((found, binding));
            }
        }
        let (_, best) = best?;
        if best.peer.is_some() {
            return best.owner.upgrade();
        }
        self.shared(best, from, to, |binding| binding.peer.is_none())
            .owner
            .upgrade()
    }
}

/// Where a connection to `to` goes on the guest's own loopback: an address
/// of the loopback itself, or the unspecified one, which Linux connects to
/// the loopback (`ip_route_output_key_hash_rcu`, `tcp_v6_connect`). `None`
/// for any other address.
pub(crate) fn destination(to: SocketAddr) -> Option<SocketAddr> {
    match to.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => Some(to),
        IpAddr::V4(v4) if v4.is_unspecified() => {
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, to.port())))
        }
        IpAddr::V6(v6) if v6.is_loopback() => Some(to),
        IpAddr::V6(v6) if v6.is_unspecified() => {
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, to.port())))
        }
        _ => None,
    }
}
/// The source address of a connection to `to` on the loopback, as the
/// loopback's route gives it: `127.0.0.1` for any IPv4 one, `::1` for IPv6.
pub(crate) fn source(to: SocketAddr) -> IpAddr {
    match to {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(address: &str, v6: bool) -> Binding {
        Binding {
            address: address.parse().unwrap(),
            v6,
            v6_only: false,
            reuse_address: false,
            reuse_port: false,
            pooled: false,
            listening: false,
            peer: None,
            owner: Weak::new(),
            time_wait: None,
        }
    }

    #[test]
    fn bindings_overlap_on_shared_addresses() {
        let any4 = binding("0.0.0.0:80", false);
        let local = binding("127.0.0.1:80", false);
        let other = binding("127.0.0.2:80", false);
        let any6 = binding("[::]:80", true);
        let one6 = binding("[::1]:80", true);
        assert!(any4.overlaps(&local));
        assert!(local.overlaps(&any4));
        assert!(!local.overlaps(&other));
        assert!(any6.overlaps(&local));
        assert!(any6.overlaps(&any4));
        assert!(!one6.overlaps(&local));
        assert!(!one6.overlaps(&any4));
        let only6 = Binding {
            v6_only: true,
            ..any6.clone()
        };
        assert!(!only6.overlaps(&any4));
        assert!(only6.overlaps(&one6));
        assert!(!binding("127.0.0.1:81", false).overlaps(&local));
    }

    #[test]
    fn reuse_shares_a_port_only_beside_no_listener() {
        let reusing = |listening| Binding {
            reuse_address: true,
            listening,
            ..binding("127.0.0.1:80", false)
        };
        assert!(!reusing(false).conflicts(&reusing(false)));
        assert!(reusing(false).conflicts(&reusing(true)));
        assert!(binding("127.0.0.1:80", false).conflicts(&reusing(false)));
        let ported = Binding {
            reuse_port: true,
            listening: true,
            ..binding("127.0.0.1:80", false)
        };
        assert!(!ported.conflicts(&ported));
    }

    #[test]
    fn ephemeral_ports_come_in_turn_and_skip_taken_ones() {
        // These bindings have no socket, so each bind forgets the last one;
        // the search still starts past the port it gave.
        let mut ports = Ports::default();
        let first = ports.bind(binding("127.0.0.1:0", false)).unwrap();
        assert_eq!(first.port(), 32768);
        let second = ports.bind(binding("127.0.0.1:0", false)).unwrap();
        assert_eq!(second.port(), 32769);
        ports.next = *EPHEMERAL.end();
        let last = ports.bind(binding("127.0.0.1:0", false)).unwrap();
        assert_eq!(last.port(), 60999);
        assert_eq!(ports.next, 32768);
    }

    #[test]
    fn loopback_destinations_and_sources() {
        let to = |text: &str| destination(text.parse().unwrap());
        assert_eq!(to("127.0.0.5:80"), Some("127.0.0.5:80".parse().unwrap()));
        assert_eq!(to("0.0.0.0:80"), Some("127.0.0.1:80".parse().unwrap()));
        assert_eq!(to("[::]:80"), Some("[::1]:80".parse().unwrap()));
        assert_eq!(to("[::1]:80"), Some("[::1]:80".parse().unwrap()));
        assert_eq!(to("192.0.2.1:80"), None);
        assert_eq!(
            source("127.0.0.5:80".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }
}
