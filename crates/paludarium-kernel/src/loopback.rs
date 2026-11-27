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
use crate::deadlines::{Deadlines, Due, NEVER};
use crate::inet::InetSocket;
use core::hash::{Hash, Hasher};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use paludarium_host::net::{Driver, Phase, Stream};
use paludarium_types::Errno;
use std::hash::DefaultHasher;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

pub(crate) mod segments;
use segments::{Counts, Flows, Push, Request, Tap, Verdict};

const EADDRINUSE: Errno = Errno(98);
const ECONNRESET: Errno = Errno(104);
const ETIMEDOUT: Errno = Errno(110);
/// Linux's default `net.ipv4.ip_local_port_range`.
const EPHEMERAL: core::ops::RangeInclusive<u16> = 32768..=60999;
/// How long the side that closed a connection first keeps its port, in
/// nanoseconds: Linux's `TCP_TIMEWAIT_LEN`, and its default
/// `tcp_fin_timeout` for `FIN_WAIT2` too.
pub(crate) const TIME_WAIT: u64 = 60_000_000_000;
/// [`Link::ended`] for a side whose end has not reached the other.
const NOT_ENDED: u64 = u64::MAX;
/// [`Link::first`] before either side has ended, and once one was reset.
const NO_SIDE: u8 = 2;
const RESET: u8 = 3;

/// What tells a socket that an urgent byte has reached it, for `SIGURG`.
pub(crate) type Notify = Arc<dyn Fn() + Send + Sync>;

/// A connection's urgent byte one way, as Linux's `urg_data` and
/// `urg_seq` keep it, by bytes counted from the connection's start.
#[derive(Default)]
struct Urgent {
    /// The bytes the sender has queued, those that have reached the
    /// receiver, and those the receiver has read or passed over.
    written: u64,
    delivered: u64,
    copied: u64,
    /// The last urgent byte sent, and where, until it reaches the receiver.
    sending: Option<(u64, u8)>,
    /// The receiver's mark: where its urgent byte is, and the byte until
    /// `MSG_OOB` takes it (`TCP_URG_VALID`, then `TCP_URG_READ`).
    mark: Option<(u64, Option<u8>)>,
    /// An earlier urgent byte the reader had reached when a new one came,
    /// which it passes over (`tcp_check_urg` moves `copied_seq` past it).
    stale: Option<u64>,
}

/// The two streams of a connection between guest sockets.
pub(crate) struct Link {
    /// `None` once both sides have closed, or one was reset, so that the
    /// streams, which hold the link as their driver, are freed.
    ends: Mutex<Option<Ends>>,
    /// The side whose end reached the other first, kept after `ends` goes;
    /// [`NO_SIDE`] before, [`RESET`] once either side was reset.
    first: AtomicU8,
    /// When each side's end reached the other, on the host's monotonic
    /// clock, or [`NOT_ENDED`].
    ended: [AtomicU64; 2],
    host: Arc<dyn paludarium_host::Host>,
    /// The urgent byte toward each side, and what tells each of its arrival.
    urgent: Mutex<[Urgent; 2]>,
    notify: [Notify; 2],
    /// The segments the bytes take on Linux, which say when they reach the
    /// peer. Locked after `ends`.
    flows: Mutex<Flows>,
    this: Weak<Link>,
    /// The two streams, for the filters, which see what the other side
    /// sends; and the connection's first sequence numbers and timestamps,
    /// each side's, once a filter looks.
    streams: [Weak<Stream>; 2],
    names: OnceLock<Names>,
    /// Whether it is a request of its listener's ([`Request`]): 0 for never,
    /// else [`REQUEST`], [`DROPPED`] or, opened, its place in the order
    /// requests opened in, from [`FIRST`] on; and what tells the listener.
    request: AtomicU64,
    opens: OnceLock<Notify>,
    senders: [Mutex<Sender>; 2],
    /// When its timers are next to be run, changed with `flows` locked.
    armed: AtomicU64,
    deadlines: Arc<Deadlines>,
}
/// [`Link::request`]'s values.
const REQUEST: u64 = 1;
const DROPPED: u64 = 2;
const FIRST: u64 = 3;
/// What a connection's segments count from: each side's initial sequence
/// number and timestamp offset.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Names {
    pub(crate) first: [u32; 2],
    pub(crate) stamps: [u32; 2],
}
/// What a side's segments go with, which a filter sees: its `SO_PRIORITY`
/// and `IP_TOS`, and the owner and group of the socket.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sender {
    pub(crate) priority: u32,
    pub(crate) tos: u8,
    pub(crate) ids: (u32, u32),
}
impl Names {
    /// Random ones, from `host`.
    pub(crate) fn new(host: &Arc<dyn paludarium_host::Host>) -> Self {
        let mut random = [0; 16];
        let _ = host.random_bytes(&mut random);
        let mut words = [0; 4];
        for (word, bytes) in words.iter_mut().zip(random.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let [a, b, c, d] = words;
        Self {
            first: [a, b],
            stamps: [c, d],
        }
    }
    /// `side`'s timestamp at `micros`: milliseconds, each side's from an
    /// offset of its own.
    pub(crate) fn stamp(&self, side: usize, micros: u64) -> u32 {
        self.stamps[side].wrapping_add((micros / 1000) as u32)
    }
}
struct Ends {
    streams: [Arc<Stream>; 2],
    /// Whether each side's end has reached the other.
    ended: [bool; 2],
}

impl Link {
    /// Joins a connecting `client` stream to a new `server` one and opens
    /// both, the server's first: `client` from `client_local`, `server` from
    /// `server_local`. `host`'s clock times the segments and each side's
    /// end, `deadlines` run the connection's timers, `notify` tells each
    /// side of an urgent byte, and `mtu` is the devices' it goes through.
    pub(crate) fn join(
        client: &Arc<Stream>,
        server: &Arc<Stream>,
        (client_local, server_local): (SocketAddr, SocketAddr),
        (host, deadlines): (&Arc<dyn paludarium_host::Host>, &Arc<Deadlines>),
        notify: [Notify; 2],
        (mtu, names): (usize, Option<Names>),
    ) -> Arc<Self> {
        let now = host.clock(paludarium_host::ClockId::Monotonic).ok();
        let link = Arc::new_cyclic(|this| Self {
            ends: Mutex::new(Some(Ends {
                streams: [Arc::clone(client), Arc::clone(server)],
                ended: [false; 2],
            })),
            first: AtomicU8::new(NO_SIDE),
            ended: [AtomicU64::new(NOT_ENDED), AtomicU64::new(NOT_ENDED)],
            host: Arc::clone(host),
            urgent: Mutex::default(),
            notify,
            flows: Mutex::new(Flows::new(
                crate::tcp_info::advertised_mss(client_local.is_ipv4(), mtu),
                now.map(|now| now / 1000),
            )),
            this: Weak::clone(this),
            streams: [Arc::downgrade(client), Arc::downgrade(server)],
            names: names.map_or_else(OnceLock::new, OnceLock::from),
            request: AtomicU64::new(0),
            opens: OnceLock::new(),
            senders: Default::default(),
            armed: AtomicU64::new(NEVER),
            deadlines: Arc::clone(deadlines),
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
        let mut guard = self.ends.lock().unwrap_or_else(PoisonError::into_inner);
        self.first.store(RESET, Ordering::SeqCst);
        let Some(ends) = guard.as_ref() else { return };
        if !self.reset_flows(side, self.micros()) {
            // The peer's filter dropped it, so it stays connected.
            let own = Arc::clone(&ends.streams[side]);
            drop(guard);
            own.close();
            return;
        }
        let Some(ends) = guard.take() else { return };
        drop(guard);
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
    /// When the hold of `side`, which ends the connection first and closed
    /// at `closed`, ends: `None` while its bytes still go (`FIN_WAIT1`).
    /// From its end, or its close if later, it waits up to
    /// `tcp_fin_timeout` for the other side's end (`FIN_WAIT2`), and is in
    /// `TIME_WAIT` for `TCP_TIMEWAIT_LEN` from that end, as Linux's
    /// `tcp_time_wait` and `tcp_timewait_state_process` move it on.
    fn holds_until(&self, side: usize, closed: u64) -> Option<u64> {
        let own = self.ended[side].load(Ordering::SeqCst);
        if own == NOT_ENDED {
            return None;
        }
        let waits = own.max(closed).saturating_add(TIME_WAIT);
        let peer = self.ended[1 - side].load(Ordering::SeqCst);
        Some(if peer < waits {
            peer.saturating_add(TIME_WAIT)
        } else {
            waits
        })
    }
    /// When an open socket on `side`, which ended the connection first,
    /// gives its port up: 60 seconds after the other side's end reached it,
    /// as Linux's `tcp_fin` in `FIN_WAIT2` hands the port to a `TIME_WAIT`
    /// socket and closes the socket's own (`tcp_done`). `None` until then.
    pub(crate) fn released(&self, side: usize) -> Option<u64> {
        if usize::from(self.first.load(Ordering::SeqCst)) != side {
            return None;
        }
        let peer = self.ended[1 - side].load(Ordering::SeqCst);
        (peer != NOT_ENDED).then(|| peer.saturating_add(TIME_WAIT))
    }
    /// Runs the timers that are due, and moves what has gone from each side
    /// to the other, as far as the other's buffer takes it, and each side's
    /// end after its bytes ([`Flows`]). A side that sends to a closed peer
    /// gets a reset, as Linux's peer answers data after its close
    /// (`tcp_rcv_state_process`).
    fn pump(&self) {
        let mut guard = self.ends.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(ends) = guard.as_mut() else { return };
        let now = self.micros();
        let (arrived, over) = {
            let mut flows = self.flows();
            if flows.lossy() {
                for (side, stream) in ends.streams.iter().enumerate() {
                    if stream.finished().1 {
                        flows.closed(side);
                    }
                }
            }
            flows.advance(now);
            for from in 0..2 {
                let (own, peer) = (&ends.streams[from], &ends.streams[1 - from]);
                if matches!(own.phase(), Phase::Failed(_)) || flows.dead(from) {
                    continue;
                }
                let edge = if gone(peer) {
                    u64::MAX
                } else {
                    flows.moved(1 - from) + peer.room() as u64
                };
                flows.window(1 - from, edge, now);
                let ready = own.readiness();
                let queued = flows.moved(1 - from) + own.queued().1 as u64;
                let wrote = queued.saturating_sub(flows.written(from));
                flows.write(from, wrote, !ready.writable, now);
                if ready.write_closed {
                    flows.end(from, now);
                }
            }
            self.arm(&flows);
            (flows.arrived(), flows.over())
        };
        for from in 0..2 {
            let (own, peer) = (&ends.streams[from], &ends.streams[1 - from]);
            if !arrived[1 - from] || matches!(own.phase(), Phase::Failed(_)) {
                continue;
            }
            loop {
                let closed = gone(peer);
                // The bytes leave the sender as they count as moved, which
                // a filter looks at too.
                let (bytes, at) = {
                    let mut flows = self.flows();
                    let Some((len, at)) = flows.arrival(1 - from) else {
                        break;
                    };
                    let bytes = if closed {
                        Vec::new()
                    } else {
                        own.take(len as usize)
                    };
                    flows.gave(1 - from, &bytes);
                    (bytes, at)
                };
                if closed {
                    // The closed side answers with a reset, which ends its
                    // `TIME_WAIT` too.
                    self.first.store(RESET, Ordering::SeqCst);
                    if self.reset_flows(1 - from, now) {
                        own.take(usize::MAX);
                        own.fail(if ends.ended[1 - from] {
                            Errno::EPIPE
                        } else {
                            ECONNRESET
                        });
                    }
                    break;
                }
                peer.receive_late(&bytes, now.saturating_sub(at) * 1000);
                self.delivered(1 - from, bytes.len());
            }
            let ended = self.flows().ended(1 - from);
            if let Some(at) = ended
                && !matches!(own.phase(), Phase::Failed(_))
            {
                // The end still reaches a closed side's hold.
                self.end(&mut ends.ended, from, at);
                if !gone(peer) {
                    peer.end();
                }
            }
        }
        for side in if over { 0..2 } else { 0..0 } {
            let (verdict, dead) = {
                let mut flows = self.flows();
                (flows.verdict(side), flows.dead(side))
            };
            if dead {
                self.first.store(RESET, Ordering::SeqCst);
            }
            if let Some(verdict) = verdict {
                self.over(ends, side, verdict);
            }
        }
        if ends.streams.iter().all(|stream| stream.finished().1) && !self.flows().losing() {
            *guard = None;
        }
    }
    /// The connection is over for `side`: a reset came to it (`tcp_reset`),
    /// or what it sent was never acknowledged (`tcp_write_err`).
    fn over(&self, ends: &Ends, side: usize, verdict: Verdict) {
        self.first.store(RESET, Ordering::SeqCst);
        let own = &ends.streams[side];
        let waiting = ends.ended[1 - side] && !own.readiness().write_closed;
        own.take(usize::MAX);
        if !gone(own) {
            own.fail(match verdict {
                Verdict::TimedOut => ETIMEDOUT,
                Verdict::Reset if waiting => Errno::EPIPE,
                Verdict::Reset => ECONNRESET,
            });
        }
    }
    /// `side` was reset, at `now`; whether the other side hears.
    fn reset_flows(&self, side: usize, now: u64) -> bool {
        let mut flows = self.flows();
        let heard = flows.reset(side, now);
        self.arm(&flows);
        heard
    }
    /// Sets when the connection's timers are next to be run, and tells of a
    /// request that has opened or been dropped.
    fn arm(&self, flows: &Flows) {
        if self.request.load(Ordering::SeqCst) == REQUEST {
            static ORDER: AtomicU64 = AtomicU64::new(FIRST);
            match flows.request() {
                Request::Never | Request::Waits { .. } => {}
                Request::Dropped => self.request.store(DROPPED, Ordering::SeqCst),
                Request::Opened => {
                    let place = ORDER.fetch_add(1, Ordering::SeqCst);
                    self.request.store(place, Ordering::SeqCst);
                    if let Some(opens) = self.opens.get() {
                        opens();
                    }
                }
            }
        }
        let at = flows.wake().map_or(NEVER, |at| at.saturating_mul(1000));
        let old = self.armed.swap(at, Ordering::SeqCst);
        if old != at {
            self.deadlines.set(self.id(), (old, at), &self.this());
        }
    }
    fn this(&self) -> Weak<dyn Due> {
        Weak::clone(&self.this) as Weak<dyn Due>
    }
    /// What names the link among the deadlines.
    fn id(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }
    /// Does `f` with the flows, and moves what it let go.
    fn with_flows<R>(&self, f: impl FnOnce(&mut Flows, u64) -> R) -> R {
        let (result, arrived) = {
            let mut flows = self.flows();
            let result = f(&mut flows, self.micros());
            self.arm(&flows);
            (result, flows.arrived() != [false; 2])
        };
        if arrived {
            self.pump();
        }
        result
    }
}
impl Due for Link {
    fn run(&self) {
        // Taken out of the table.
        {
            let _flows = self.flows();
            self.armed.store(NEVER, Ordering::SeqCst);
        }
        self.pump();
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        let armed = self.armed.load(Ordering::SeqCst);
        self.deadlines.set(self.id(), (armed, NEVER), &self.this());
    }
}
impl Link {
    fn flows(&self) -> MutexGuard<'_, Flows> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The host's monotonic clock, in microseconds.
    fn micros(&self) -> u64 {
        micros(&self.host)
    }
    /// What `side`'s writes go with from now on.
    pub(crate) fn sending(&self, side: usize, push: Push) {
        self.flows().sending(side, push);
    }
    /// `side`'s `TCP_NODELAY` was set or cleared.
    pub(crate) fn set_no_delay(&self, side: usize, on: bool) {
        self.with_flows(|flows, now| flows.set_no_delay(side, on, now));
    }
    /// `side`'s `TCP_CORK` was set or cleared.
    pub(crate) fn set_cork(&self, side: usize, on: bool) {
        self.with_flows(|flows, now| flows.set_cork(side, on, now));
    }
    /// `side`'s `TCP_USER_TIMEOUT` was set to `ms` milliseconds.
    pub(crate) fn set_user_timeout(&self, side: usize, ms: u32) {
        self.with_flows(|flows, now| flows.set_user_timeout(side, ms, now));
    }
    /// `side` keeps what it ends with in its network's `metrics`, under its
    /// local and remote `addresses`, and starts from what is kept there.
    pub(crate) fn remember(
        &self,
        side: usize,
        metrics: &Arc<crate::tcp_metrics::Metrics>,
        addresses: (std::net::IpAddr, std::net::IpAddr),
    ) {
        self.with_flows(|flows, now| flows.remember(side, Arc::clone(metrics), addresses, now));
    }
    /// Ends the handshake, with the server's filter its listener's: whether
    /// the connection is open at once. Else it is a request, and `opens`
    /// tells when it has opened.
    pub(crate) fn handshake(&self, opens: Notify) -> bool {
        let _ = self.opens.set(opens);
        let mut flows = self.flows();
        flows.handshake(self.micros());
        let waits = flows.request() != Request::Never;
        if waits {
            self.request.store(REQUEST, Ordering::SeqCst);
        }
        self.arm(&flows);
        !waits
    }
    /// Whether it is a request still, and once opened its place among them.
    pub(crate) fn requested(&self) -> (bool, Option<u64>) {
        let request = self.request.load(Ordering::SeqCst);
        (request == REQUEST, (request >= FIRST).then_some(request))
    }
    /// When a request's SYN-ACK next goes again, on the host's monotonic
    /// clock, and how often it has.
    pub(crate) fn waits(&self) -> Option<(u64, u32)> {
        match self.flows().request() {
            Request::Waits { at, tries } => Some((at.saturating_mul(1000), tries)),
            _ => None,
        }
    }
    /// The listener of a request has closed.
    pub(crate) fn forget(&self) {
        let mut flows = self.flows();
        flows.forget(true);
        self.first.store(RESET, Ordering::SeqCst);
        self.arm(&flows);
    }
    /// What `side`'s segments go with from now on.
    pub(crate) fn set_sender(&self, side: usize, sender: Sender) {
        *self.senders[side]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = sender;
    }
    pub(crate) fn sender(&self, side: usize) -> Sender {
        *self.senders[side]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// `side`'s filter is now the one `make` makes of the stream that sends
    /// to it, the connection and its names, or none.
    pub(crate) fn set_tap(
        &self,
        side: usize,
        make: Option<impl FnOnce(Weak<Stream>, Weak<Link>, Names) -> Arc<dyn Tap>>,
    ) {
        let tap = make.map(|make| {
            let names = *self.names.get_or_init(|| Names::new(&self.host));
            let sender = Weak::clone(&self.streams[1 - side]);
            make(sender, Weak::clone(&self.this), names)
        });
        self.with_flows(|flows, now| flows.tap(side, tap, now));
    }
    /// `side`'s `TCP_QUICKACK` was set to `value`.
    pub(crate) fn set_quick(&self, side: usize, value: i32) {
        self.with_flows(|flows, now| flows.set_quick(side, value, now));
    }
    /// The segments `side` has sent and received.
    pub(crate) fn segments(&self, side: usize) -> Counts {
        self.with_flows(|flows, now| flows.counts(side, now))
    }
    fn urgent(&self) -> MutexGuard<'_, [Urgent; 2]> {
        self.urgent.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// `side` queued `count` bytes to send, the last of them urgent with
    /// `MSG_OOB` (`tcp_mark_urg`).
    pub(crate) fn wrote(&self, side: usize, count: usize, urgent: Option<u8>) {
        let to = 1 - side;
        let arrived = {
            let mut all = self.urgent();
            let way = &mut all[to];
            way.written += count as u64;
            match urgent {
                Some(byte) if count > 0 => {
                    way.sending = Some((way.written - 1, byte));
                    way.arrive()
                }
                _ => false,
            }
        };
        if arrived {
            (self.notify[to])();
        }
    }
    /// `count` more bytes reached `to`.
    fn delivered(&self, to: usize, count: usize) {
        let arrived = {
            let mut all = self.urgent();
            all[to].delivered += count as u64;
            all[to].arrive()
        };
        if arrived {
            (self.notify[to])();
        }
    }
    /// Reads what reached `side` from `stream` into `buf`, as Linux's
    /// `tcp_recvmsg` meets an urgent mark: a read stops before it, and one
    /// that starts there passes over the urgent byte unless it is read
    /// `inline` (`SO_OOBINLINE`), losing it if `MSG_OOB` has not taken it.
    /// Returns the count, whether the read ends at the mark, and when the
    /// stream's last bytes came, the time all its unread bytes take
    /// ([`Stream::read_stamped`]).
    pub(crate) fn read(
        &self,
        side: usize,
        stream: &Stream,
        buf: &mut [u8],
        (peek, inline): (bool, bool),
    ) -> Result<(usize, bool, Option<u64>), Errno> {
        if buf.is_empty() {
            return stream
                .read_stamped(buf, peek)
                .map(|(n, stamp)| (n, false, stamp));
        }
        let (copied, mark, stale) = {
            let all = self.urgent();
            (all[side].copied, all[side].mark, all[side].stale)
        };
        let mut skip = usize::from(!inline && stale == Some(copied));
        let mut limit = buf.len();
        if let Some((at, _)) = mark {
            let ahead = (at.saturating_sub(copied) as usize).saturating_sub(skip);
            if ahead == 0 {
                skip += usize::from(!inline);
            } else {
                limit = limit.min(ahead);
            }
        }
        let (n, stamp) = if peek {
            let mut seen = vec![0; skip + limit];
            let (n, stamp) = stream.read_stamped(&mut seen, true)?;
            if n > 0 && n <= skip {
                // Only the urgent byte waits, which a read passes over.
                return if stream.readiness().read_closed {
                    Ok((0, false, None))
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            let n = n.saturating_sub(skip);
            buf[..n].copy_from_slice(&seen[skip..skip + n]);
            (n, stamp)
        } else {
            let mut passed = 0;
            if skip > 0 {
                passed = stream.read(&mut [0; 2][..skip], false)?;
            }
            let result = stream.read_stamped(&mut buf[..limit], false);
            let n = result.as_ref().map_or(0, |&(n, _)| n);
            self.consumed(side, passed + n);
            if passed > 0 && result.is_err() {
                // The urgent byte went; nothing else waits yet.
                return result.map(|(n, stamp)| (n, false, stamp));
            }
            result?
        };
        let at = mark.is_some_and(|(at, _)| at == copied + (skip + n) as u64);
        Ok((n, at && n > 0, stamp))
    }
    /// `side` read or passed over `count` more bytes; past its mark the
    /// urgent byte is gone (`urg_data` cleared).
    fn consumed(&self, side: usize, count: usize) {
        let mut all = self.urgent();
        let way = &mut all[side];
        way.copied += count as u64;
        if way.mark.is_some_and(|(at, _)| at < way.copied) {
            way.mark = None;
        }
        if way.stale.is_some_and(|at| at < way.copied) {
            way.stale = None;
        }
        drop(all);
        self.with_flows(|flows, now| flows.read(side, count as u64, now));
    }
    /// The urgent byte waiting for `side`'s `MSG_OOB`, which a read without
    /// `peek` takes (`tcp_recv_urg`).
    pub(crate) fn take_urgent(&self, side: usize, peek: bool) -> Option<u8> {
        let mut all = self.urgent();
        let (_, byte) = all[side].mark.as_mut()?;
        let found = *byte;
        if !peek {
            *byte = None;
        }
        found
    }
    /// What `side`'s urgent byte shows: whether one waits for `MSG_OOB`
    /// (`POLLPRI`), whether the next read is at the mark (`SIOCATMARK`),
    /// and the bytes before the mark, which `FIONREAD` counts when the byte
    /// is not read inline (`tcp_inq`).
    pub(crate) fn urgent_state(&self, side: usize) -> (bool, bool, Option<usize>) {
        let all = self.urgent();
        let way = &all[side];
        match way.mark {
            Some((at, byte)) => (
                byte.is_some(),
                at == way.copied,
                Some((at - way.copied) as usize),
            ),
            None => (false, false, None),
        }
    }
    /// `from`'s end reached the other side at `at`, in microseconds.
    fn end(&self, ended: &mut [bool; 2], from: usize, at: u64) {
        if ended[from] {
            return;
        }
        ended[from] = true;
        // Without the host's clock the end counts as long past, so that no
        // hold waits on it.
        self.ended[from].store(at.saturating_mul(1000), Ordering::SeqCst);
        let _ =
            self.first
                .compare_exchange(NO_SIDE, from as u8, Ordering::SeqCst, Ordering::SeqCst);
    }
}
impl Urgent {
    /// Moves the urgent byte sent to the receiver's mark once it has
    /// reached it, as Linux's `tcp_check_urg` and `tcp_urg` do; whether it
    /// did, to signal the receiver.
    fn arrive(&mut self) -> bool {
        let Some((at, byte)) = self.sending else {
            return false;
        };
        if at >= self.delivered {
            return false;
        }
        self.sending = None;
        if let Some((old, _)) = self.mark
            && old == self.copied
        {
            self.stale = Some(old);
        }
        self.mark = Some((at, Some(byte)));
        true
    }
}
impl Driver for Link {
    /// A side wrote, read, shut down or closed: the bytes move at once.
    fn kick(&self) {
        self.pump();
    }
}
/// `host`'s monotonic clock, in microseconds; 0 without one.
fn micros(host: &Arc<dyn paludarium_host::Host>) -> u64 {
    host.clock(paludarium_host::ClockId::Monotonic).unwrap_or(0) / 1000
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
    /// Whether the guest bound the port itself, which Linux's
    /// `SOCK_BINDPORT_LOCK` keeps when the connection ends.
    pub(crate) locked: bool,
    /// A TCP socket's loopback connection, once it opens, and its side.
    pub(crate) link: Option<(Arc<OnceLock<Arc<Link>>>, usize)>,
    /// In a group of sockets sharing the port with `SO_REUSEPORT`, which
    /// a TCP listener joins when it listens, and a UDP socket when it
    /// binds (`inet_reuseport_add_sock`, `udp_reuseport_add_sock`).
    pub(crate) pooled: bool,
    pub(crate) listening: bool,
    /// A connected UDP socket's peer, the only sender it receives from.
    pub(crate) peer: Option<SocketAddr>,
    /// The address of the peer an IPv6 UDP socket had before it
    /// disconnected, which it keeps (`sk_v6_daddr`): the only one it takes
    /// an IPv6 datagram from. IPv4's as such.
    pub(crate) old_peer: Option<IpAddr>,
    /// The device the socket is bound to (`sk_bound_dev_if`), 0 for none:
    /// it takes only what comes in on it, and shares its port with sockets
    /// bound to others.
    pub(crate) device: u32,
    pub(crate) owner: Weak<InetSocket>,
    /// A closed connection's hold in `TIME_WAIT`, after its socket has
    /// gone.
    pub(crate) time_wait: Option<TimeWait>,
}
/// A hold in `TIME_WAIT`: when its socket closed, and its connection and
/// side, whose ends time it ([`Link::holds_until`]); a reset, or the other
/// side's end reaching it first, ends it at once. It keeps its socket's
/// peer and cookie, which `sock_diag` tells of.
#[derive(Clone)]
pub(crate) struct TimeWait {
    closed: u64,
    link: Arc<Link>,
    side: usize,
    peer: SocketAddr,
    cookie: u64,
}
/// A hold in `TIME_WAIT` as `sock_diag` tells of it, as Linux's
/// `inet_timewait_sock`, which outlives its socket.
pub(crate) struct Waiting {
    pub(crate) local: SocketAddr,
    pub(crate) peer: SocketAddr,
    pub(crate) v6: bool,
    /// The device its socket was bound to (`tw_bound_dev_if`).
    pub(crate) device: u32,
    pub(crate) cookie: u64,
    /// Its `tw_substate`: `TCP_FIN_WAIT2` until the other side's end has
    /// come, then `TCP_TIME_WAIT`; `TCP_FIN_WAIT1` while its bytes still go.
    pub(crate) state: u8,
    /// When it ends, once its own end has gone.
    pub(crate) until: Option<u64>,
}
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
impl Binding {
    fn carries(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => !self.v6 || !self.v6_only,
            IpAddr::V6(_) => self.v6,
        }
    }
    /// Whether it holds the port of `to` on an address that covers `to`'s.
    fn covers(&self, to: SocketAddr) -> bool {
        let bound = self.address.ip();
        self.address.port() == to.port()
            && self.carries(to.ip())
            && (bound.is_unspecified() || bound == to.ip())
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
    /// Whether the two may meet on a port by their devices: one of them
    /// bound to none, or both to the same (`inet_bind_conflict`,
    /// `udp_lib_lport_inuse`).
    fn devices_meet(&self, other: &Binding) -> bool {
        self.device == 0 || other.device == 0 || self.device == other.device
    }
    /// Whether `self` may not take its port beside `other`, as Linux's
    /// `inet_bind_conflict`: two bound to other devices share it; both
    /// with `SO_REUSEADDR` share it unless `other` listens, and both with
    /// `SO_REUSEPORT` always.
    fn conflicts(&self, other: &Binding) -> bool {
        self.overlaps(other)
            && self.devices_meet(other)
            && !(self.reuse_address && other.reuse_address && !other.listening)
            && !(self.reuse_port && other.reuse_port)
    }
    fn is(&self, owner: &Weak<InetSocket>) -> bool {
        self.time_wait.is_none() && Weak::ptr_eq(&self.owner, owner)
    }
    /// Whether `other` is in `self`'s group: of the same family, on the
    /// same address, port and device (`inet_reuseport_add_sock`,
    /// `udp_reuseport_add_sock`).
    fn pools_with(&self, other: &Binding) -> bool {
        self.pooled
            && other.pooled
            && self.address == other.address
            && self.device == other.device
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

/// The local ports the TCP sockets, or the UDP ones, hold, where the next
/// ephemeral one is looked for, and the ports no ephemeral one is.
pub(crate) struct Ports {
    bindings: Vec<Binding>,
    next: u16,
    host: Vec<u16>,
}
impl Default for Ports {
    fn default() -> Self {
        Self {
            bindings: Vec::new(),
            next: *EPHEMERAL.start(),
            host: Vec::new(),
        }
    }
}
impl Ports {
    /// No ports held yet, and no ephemeral one among `host`, the ports the
    /// guest reaches the host's loopback at.
    pub(crate) fn beside(host: Vec<u16>) -> Self {
        Self {
            host,
            ..Self::default()
        }
    }
    /// Forgets the sockets that have gone, but for those in `TIME_WAIT`.
    fn live(&mut self) {
        self.bindings
            .retain(|binding| binding.owner.strong_count() > 0 || binding.time_wait.is_some());
    }
    /// Forgets the holds in `TIME_WAIT` that have ended by `now`, or whose
    /// side no longer ends its connection first, and the ports open sockets
    /// whose connection has ended gave up by then, but those the guest bound.
    pub(crate) fn expire(&mut self, now: u64) {
        self.bindings.retain(|binding| {
            if !binding.locked
                && let Some((slot, side)) = &binding.link
                && let Some(link) = slot.get()
                && link.released(*side).is_some_and(|until| until <= now)
            {
                return false;
            }
            binding.time_wait.as_ref().is_none_or(|wait| {
                wait.link.closes_first(wait.side)
                    && wait
                        .link
                        .holds_until(wait.side, wait.closed)
                        .is_none_or(|until| until > now)
            })
        });
    }
    /// `owner`, which ends `link` first from `side` to `peer`, closed at
    /// `closed` and keeps its port in `TIME_WAIT`, as it was, with its
    /// `SO_REUSEADDR` and its `cookie`: Linux's `inet_twsk_hashdance` puts a
    /// `TIME_WAIT` socket in its bind bucket.
    pub(crate) fn linger(
        &mut self,
        owner: &Weak<InetSocket>,
        (link, side, peer): (&Arc<Link>, usize, SocketAddr),
        closed: u64,
        cookie: u64,
    ) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.owner = Weak::new();
                binding.time_wait = Some(TimeWait {
                    closed,
                    link: Arc::clone(link),
                    side,
                    peer,
                    cookie,
                });
            }
        }
    }
    /// Whether `owner` holds a port.
    pub(crate) fn holds(&self, owner: &Weak<InetSocket>) -> bool {
        self.bindings.iter().any(|binding| binding.is(owner))
    }
    /// The holds in `TIME_WAIT`, oldest first.
    pub(crate) fn waiting(&self) -> Vec<Waiting> {
        self.bindings
            .iter()
            .filter_map(|binding| {
                let wait = binding.time_wait.as_ref()?;
                let ended = |side: usize| wait.link.ended[side].load(Ordering::SeqCst) != NOT_ENDED;
                let state = if ended(1 - wait.side) {
                    TCP_TIME_WAIT
                } else if ended(wait.side) {
                    TCP_FIN_WAIT2
                } else {
                    TCP_FIN_WAIT1
                };
                Some(Waiting {
                    local: binding.address,
                    peer: wait.peer,
                    v6: binding.v6,
                    device: binding.device,
                    cookie: wait.cookie,
                    state,
                    until: wait.link.holds_until(wait.side, wait.closed),
                })
            })
            .collect()
    }
    /// Takes `binding`'s port, or with port 0 the next free ephemeral one
    /// that is not among the host's (see [`Self::beside`]); `EADDRINUSE`
    /// when it conflicts, or no ephemeral port is free.
    /// Returns the address taken.
    pub(crate) fn bind(&mut self, mut binding: Binding) -> Result<SocketAddr, Errno> {
        self.live();
        if binding.address.port() == 0 {
            let count = EPHEMERAL.len();
            let free = (0..count).find_map(|i| {
                let offset = (usize::from(self.next - EPHEMERAL.start()) + i) % count;
                let port = EPHEMERAL.start() + offset as u16;
                binding.address.set_port(port);
                (!self.host.contains(&port)
                    && !self
                        .bindings
                        .iter()
                        .any(|other| binding.overlaps(other) && binding.devices_meet(other)))
                .then_some(port)
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
    /// `owner` is now bound to the device `device` (0 for none), which
    /// Linux checks no conflict of (`sock_bindtoindex_locked`).
    pub(crate) fn set_device(&mut self, owner: &Weak<InetSocket>, device: u32) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.device = device;
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
    /// `owner`'s TCP connection on the loopback, `link` from `side`.
    pub(crate) fn attach(
        &mut self,
        owner: &Weak<InetSocket>,
        (link, side): (&Arc<OnceLock<Arc<Link>>>, usize),
    ) {
        for binding in &mut self.bindings {
            if binding.is(owner) {
                binding.link = Some((Arc::clone(link), side));
            }
        }
    }
    /// `owner`, a UDP socket, connected from `address` to `peer`, or with
    /// `None` disconnected, as a TCP socket is that disconnects; on another
    /// address it leaves its group, and comes after the rest, as Linux's
    /// `udp_lib_rehash`.
    pub(crate) fn connect(
        &mut self,
        owner: &Weak<InetSocket>,
        address: SocketAddr,
        peer: Option<SocketAddr>,
    ) {
        let mut moved = false;
        for binding in &mut self.bindings {
            if binding.is(owner) {
                moved = binding.address != address;
                binding.pooled &= !moved;
                binding.address = address;
                binding.peer = peer;
                binding.link = None;
            }
        }
        if moved {
            self.bindings.sort_by_key(|binding| binding.is(owner));
        }
    }
    /// `owner`, an IPv6 UDP socket, disconnected from a peer of the address
    /// `ip`, which it keeps ([`Binding::old_peer`]).
    pub(crate) fn keep_peer(&mut self, owner: &Weak<InetSocket>, ip: Option<IpAddr>) {
        for binding in self.bindings.iter_mut().filter(|b| b.is(owner)) {
            binding.old_peer = ip;
        }
    }
    /// `owner` gave its port up.
    pub(crate) fn unbind(&mut self, owner: &Weak<InetSocket>) {
        self.bindings.retain(|binding| !binding.is(owner));
    }
    /// The listener a connection from `from` to `to` reaches, as Linux's
    /// `__inet_lookup_listener`: one bound to that address before one bound
    /// to every address, and an IPv4 socket before an IPv6 one; among equals
    /// the first to bind, or one of its group ([`pick`]). It comes in on
    /// the device `dif`: one bound to another does not take it, and one bound
    /// to it ranks before one of its family bound to none. A listener bound
    /// to the device ties with one of the other family bound to none when the
    /// first is IPv6's (`compute_score` gives both 2).
    pub(crate) fn listener(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        dif: u32,
    ) -> Option<Arc<InetSocket>> {
        self.live();
        let best = self.best_listener(to, dif)?;
        self.shared(best, from, to, |_| true).owner.upgrade()
    }
    /// Whether a socket other than `except` holds the port of `to` on an
    /// address that covers it, also in `TIME_WAIT`: a connection there is
    /// for the guest's loopback to answer, never the host's.
    pub(crate) fn held(&mut self, to: SocketAddr, except: &Weak<InetSocket>) -> bool {
        self.live();
        self.bindings
            .iter()
            .any(|binding| !binding.is(except) && binding.covers(to))
    }
    /// Whether a socket listens where a connection to `to` in on `dif`
    /// reaches.
    pub(crate) fn listens(&mut self, to: SocketAddr, dif: u32) -> bool {
        self.live();
        self.best_listener(to, dif).is_some()
    }
    /// The device the listener a connection to `to` in on `dif` reaches is
    /// bound to, 0 for none.
    pub(crate) fn listener_device(&mut self, to: SocketAddr, dif: u32) -> u32 {
        self.live();
        self.best_listener(to, dif).map_or(0, |b| b.device)
    }
    /// The listener that ranks first for `to` in on `dif`, before its
    /// group.
    fn best_listener(&self, to: SocketAddr, dif: u32) -> Option<&Binding> {
        let ip = to.ip();
        let score = |binding: &Binding| {
            if !binding.listening
                || binding.address.port() != to.port()
                || !binding.carries(ip)
                || (binding.device != 0 && binding.device != dif)
            {
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
            // `compute_score`: 2 bound to the device, else 1, and one more
            // for IPv4.
            let rank = if binding.device != 0 { 2 } else { 1 } + u8::from(!binding.v6);
            Some((exact, rank))
        };
        let mut best: Option<((bool, u8), &Binding)> = None;
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
    /// `compute_score` ranks them: a connected one only from its peer; one
    /// bound to that address before others, then one connected, one bound
    /// to the device, or IPv4; among
    /// equals the last to bind, which Linux's hash holds first, or one of its
    /// group that is not connected ([`pick`]). It comes in on the device
    /// `dif`: one bound to another does not take it, and one bound to it
    /// ranks after a connected one, before any other but one that keeps the
    /// address of a peer it had ([`Binding::old_peer`]), which takes an IPv6
    /// datagram from that address alone, and ranks as one bound to a device;
    /// both together rank as one connected.
    pub(crate) fn receiver(
        &mut self,
        to: SocketAddr,
        from: SocketAddr,
        dif: u32,
    ) -> Option<Arc<InetSocket>> {
        self.live();
        let ip = to.ip();
        let score = |binding: &Binding| {
            if binding.address.port() != to.port()
                || !binding.carries(ip)
                || (binding.device != 0 && binding.device != dif)
            {
                return None;
            }
            let mut score = if binding.v6 { 1 } else { 2 };
            let bound = binding.address.ip();
            // One bound to the address first, as Linux looks those up
            // before the wildcard ones (`__udp4_lib_lookup`).
            if !bound.is_unspecified() {
                if bound != ip {
                    return None;
                }
                score += 32;
            }
            if let Some(peer) = binding.peer {
                if peer != from {
                    return None;
                }
                score += 16;
            } else if let (Some(old), IpAddr::V6(_)) = (binding.old_peer, from.ip()) {
                if old != from.ip() {
                    return None;
                }
                score += 8;
            }
            if binding.device != 0 {
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
    /// Every UDP socket a broadcast datagram from `from` to `to` reaches,
    /// each taking a copy, as Linux's `__udp4_lib_mcast_deliver` finds
    /// them (`__udp_is_mcast_sock`): of `to`'s port, bound to the
    /// unspecified address or to `to`, connected to none or to `from`,
    /// and not `IPV6_V6ONLY`, bound to no device or to `dif`, which it
    /// comes in on; an IPv6 datagram also passes only one whose kept
    /// address of an old peer ([`Binding::old_peer`]) is `from`'s, as
    /// `__udp_v6_is_mcast_sock` checks `sk_v6_daddr`. A connected one bound
    /// to the unspecified address has taken its route's source by then, so
    /// takes none.
    pub(crate) fn broadcast_receivers(
        &mut self,
        to: SocketAddr,
        from: SocketAddr,
        dif: u32,
    ) -> Vec<Arc<InetSocket>> {
        self.live();
        let ip = to.ip();
        self.bindings
            .iter()
            .filter(|binding| {
                binding.address.port() == to.port()
                    && binding.carries(ip)
                    && (binding.address.ip().is_unspecified() || binding.address.ip() == ip)
                    && binding.peer.is_none_or(|peer| peer == from)
                    && match (binding.peer, binding.old_peer, from.ip()) {
                        (None, Some(old), IpAddr::V6(_)) => old == from.ip(),
                        _ => true,
                    }
                    && (binding.device == 0 || binding.device == dif)
            })
            .filter_map(|binding| binding.owner.upgrade())
            .collect()
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
            locked: false,
            link: None,
            pooled: false,
            listening: false,
            peer: None,
            old_peer: None,
            device: 0,
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
    fn sockets_bound_to_other_devices_share_a_port_and_listeners_rank_by_device() {
        let on = |device, listening| Binding {
            device,
            listening,
            ..binding("0.0.0.0:80", false)
        };
        assert!(!on(1000, false).conflicts(&on(1001, false)));
        assert!(on(1000, false).conflicts(&on(1000, false)));
        assert!(on(0, false).conflicts(&on(1000, false)));
        assert!(on(1000, false).conflicts(&on(0, false)));
        let mut ports = Ports::default();
        for device in [0, 1000] {
            let mut listener = on(device, true);
            listener.v6 = device == 0;
            ports.bindings.push(listener);
        }
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        // Bound to the device it comes in on, before IPv6 bound to none;
        // one bound to another takes it not.
        assert_eq!(ports.best_listener(to, 1000).map(|b| b.device), Some(1000));
        assert_eq!(ports.best_listener(to, 1001).map(|b| b.device), Some(0));
        ports.bindings.retain(|b| b.device != 0);
        assert!(ports.best_listener(to, 1001).is_none());
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
    fn ephemeral_ports_leave_out_the_host_loopback_ones() {
        let mut ports = Ports::beside(vec![32768, 32770]);
        let first = ports.bind(binding("0.0.0.0:0", false)).unwrap();
        assert_eq!(first.port(), 32769);
        let second = ports.bind(binding("127.0.0.1:0", false)).unwrap();
        assert_eq!(second.port(), 32771);
        // A port named itself is still taken.
        let named = ports.bind(binding("127.0.0.1:32770", false)).unwrap();
        assert_eq!(named.port(), 32770);
    }

    #[test]
    fn a_binding_covers_its_port_on_its_address_or_every_one() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let one = binding("127.0.0.2:5000", false);
        assert!(one.covers(at("127.0.0.2:5000")));
        assert!(!one.covers(at("127.0.0.1:5000")));
        assert!(!one.covers(at("127.0.0.2:5001")));
        let every = binding("0.0.0.0:5001", false);
        assert!(every.covers(at("127.0.0.1:5001")));
        // An IPv4 socket's port is not one of IPv6's; an IPv6 one on `::`
        // holds it for both.
        assert!(!every.covers(at("[::1]:5001")));
        let both = binding("[::]:5001", true);
        assert!(both.covers(at("[::1]:5001")));
        assert!(both.covers(at("127.0.0.1:5001")));
    }

    #[test]
    fn loopback_destinations() {
        let to = |text: &str| destination(text.parse().unwrap());
        assert_eq!(to("127.0.0.5:80"), Some("127.0.0.5:80".parse().unwrap()));
        assert_eq!(to("0.0.0.0:80"), Some("127.0.0.1:80".parse().unwrap()));
        assert_eq!(to("[::]:80"), Some("[::1]:80".parse().unwrap()));
        assert_eq!(to("[::1]:80"), Some("[::1]:80".parse().unwrap()));
        assert_eq!(to("192.0.2.1:80"), None);
    }
}
