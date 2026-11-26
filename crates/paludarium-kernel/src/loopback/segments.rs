//! The segments a loopback connection takes on Linux, for `tcp_info`'s
//! counts: what `tcp_write_xmit` cuts from each write (Nagle's check,
//! `MSG_MORE`, `TCP_NODELAY`), when each side acknowledges (quick
//! acknowledgements, then `tcp_send_delayed_ack`'s 40 ms), and the tail loss
//! probe of a write whose acknowledgement waits. It says when the bytes reach
//! the peer, which [`super::Link`] then moves, and counts the segments that
//! carry them, in Linux 7.0's order. Master has the same rules, except
//! that it caps the delayed acknowledgement's time (`ato`) at 200 ms, where
//! 7.0 caps it at the retransmission timeout.
//!
//! A window is the room the peer's buffer has, which does not grow as
//! Linux's does (`tcp_grow_window`), and nothing is lost but what a probe
//! sends again.

use std::collections::VecDeque;

/// Times are in microseconds, on the host's monotonic clock.
const MS: u64 = 1000;
/// `TCP_ATO_MIN`, and what a delayed acknowledgement waits on a path whose
/// round trip is short (`TCP_DELACK_MIN`).
const DELAY: u64 = 40 * MS;
/// `TCP_RTO_MIN`, and the timeout of a short path.
const RTO_MIN: u64 = 200 * MS;
const RTO: u64 = 201 * MS;
/// `TCP_TIMEOUT_MIN_US`: what a loss probe adds to two round trips.
const PROBE_MARGIN: u64 = 2 * MS;
/// `TCP_MAX_QUICKACKS`, `TCP_INIT_CWND`, `TCP_MSS_DEFAULT`, `TCP_MIN_MSS`.
const QUICK_MAX: u32 = 16;
const CWND: u32 = 10;
const MSS_DEFAULT: u32 = 536;
const MSS_MIN: u32 = 88;
/// The header of a segment with timestamps, and of a bare one.
const HEADER: u32 = 32;
const TCP_HEADER: u32 = 20;
/// The window each side offers, after scaling.
const WINDOW: u32 = 65_536;
/// A round trip of the loopback, 8 times over as `srtt_us` keeps it.
const SRTT: u64 = 8 * 30;

/// What `tcp_info` tells of one side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) segs_out: u32,
    pub(crate) segs_in: u32,
    pub(crate) data_segs_out: u32,
    pub(crate) data_segs_in: u32,
    /// The segments acknowledged (`tp->delivered`).
    pub(crate) delivered: u32,
    /// The segments sent and not acknowledged (`packets_out`).
    pub(crate) unacked: u32,
    /// The segments loss probes sent again, whose D-SACK came back, and
    /// their bytes.
    pub(crate) retransmitted: u32,
    pub(crate) resent: u64,
    /// The bytes sent (with those sent again), acknowledged, received and
    /// held back, without the end.
    pub(crate) sent: u64,
    pub(crate) acked: u64,
    pub(crate) received: u64,
    pub(crate) held: u64,
    /// The bytes written and not acknowledged, the end one of them
    /// (`write_seq - snd_una`).
    pub(crate) queued: u64,
    /// This side's end waits to be sent or acknowledged.
    pub(crate) end_waits: bool,
    pub(crate) end_acked: bool,
    pub(crate) end_came: bool,
    /// The delayed acknowledgement's time, and the MSS each way.
    pub(crate) ato: u32,
    pub(crate) snd_mss: u32,
    pub(crate) rcv_mss: u32,
    /// When data last went and came, and an acknowledgement came, in
    /// microseconds (`lsndtime`, `lrcvtime`, `rcv_tstamp`).
    pub(crate) data_went: Option<u64>,
    pub(crate) data_came: Option<u64>,
    pub(crate) ack_came: Option<u64>,
}

/// How a write goes: `MSG_MORE`, `MSG_OOB`, and the socket's
/// `TCP_NODELAY` and `TCP_CORK`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Push {
    pub(crate) more: bool,
    pub(crate) urgent: bool,
    pub(crate) no_delay: bool,
    pub(crate) cork: bool,
}

/// What `tcp_write_xmit` is told of Nagle's check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nagle {
    /// The socket's own (`TCP_NODELAY` and `TCP_CORK`).
    Own,
    /// `MSG_MORE` (`TCP_NAGLE_CORK`): a part waits whatever is in flight.
    Cork,
    /// `TCP_NAGLE_PUSH` and `TCP_NAGLE_OFF`: nothing waits.
    Push,
}

/// A segment, or a GSO buffer of several, on its way.
struct Packet {
    to: usize,
    /// Its data, the segments it counts as, and its last sequence number.
    len: u32,
    segments: u32,
    end: u64,
    push: bool,
    fin: bool,
    ack: u64,
}

/// Data sent and not acknowledged (the retransmit queue).
struct InFlight {
    end: u64,
    len: u32,
    segments: u32,
    at: u64,
}

/// An acknowledgement due (`icsk_ack.pending`).
#[derive(Clone, Copy, Default)]
struct Pending {
    scheduled: bool,
    pushed: bool,
    pushed_twice: bool,
    timer: Option<u64>,
}

/// What the retransmission timer waits for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timer {
    /// `ICSK_TIME_LOSS_PROBE`.
    Loss,
    /// `ICSK_TIME_PROBE0`: data that waits with nothing in flight.
    Window,
}

/// One side. Sequence numbers count from 0, the end taking one.
struct Side {
    mss: u32,
    /// What `mss` is once the peer has sent a window.
    bound: u32,
    advertised: u32,
    no_delay: bool,
    cork: bool,
    /// `TCP_NAGLE_PUSH`: what waits goes, until a write makes a new buffer.
    pushed: bool,
    cwnd: u32,
    cwnd_limited: bool,
    /// `write_seq`, `snd_nxt`, `snd_una` and `snd_sml`.
    written: u64,
    next: u64,
    una: u64,
    small: u64,
    urgent: u64,
    /// The peer's window (`tcp_wnd_end`), and whether it held data back.
    edge: u64,
    blocked: bool,
    /// The end is in the write queue, and sent.
    fin: bool,
    fin_sent: bool,
    in_flight: VecDeque<InFlight>,
    timer: Option<(Timer, u64)>,
    /// `tlp_high_seq`: a probe is out, and whether it sent data again.
    probe: Option<(u64, bool)>,
    srtt: u64,
    /// `rcv_nxt`, `rcv_wup` and `copied_seq`.
    came: u64,
    acked: u64,
    copied: u64,
    fin_came: bool,
    pending: Pending,
    quick: u32,
    pingpong: u32,
    ato: u64,
    last_came: u64,
    rcv_mss: u32,
    last_size: u32,
    counts: Counts,
}

impl Side {
    fn new(mss: u32, bound: u32, advertised: u32) -> Self {
        Self {
            mss,
            bound,
            advertised,
            no_delay: false,
            cork: false,
            pushed: false,
            cwnd: CWND,
            cwnd_limited: false,
            written: 0,
            next: 0,
            una: 0,
            small: 0,
            urgent: 0,
            edge: u64::MAX,
            blocked: false,
            fin: false,
            fin_sent: false,
            in_flight: VecDeque::new(),
            timer: None,
            probe: None,
            srtt: SRTT,
            came: 0,
            acked: 0,
            copied: 0,
            fin_came: false,
            pending: Pending::default(),
            quick: 0,
            pingpong: 0,
            ato: 0,
            last_came: 0,
            // `tcp_initialize_rcv_mss`.
            rcv_mss: bound.min(WINDOW / 2).clamp(MSS_MIN, MSS_DEFAULT),
            last_size: 0,
            counts: Counts {
                delivered: 1,
                ..Counts::default()
            },
        }
    }
    /// The data the peer's window still takes.
    fn window(&self) -> u64 {
        self.edge
            .saturating_sub(self.next - u64::from(self.fin_sent))
    }
    fn packets_out(&self) -> u32 {
        self.in_flight.iter().map(|sent| sent.segments).sum()
    }
    /// `inet_csk_in_pingpong_mode`, of `tcp_pingpong_thresh` 1.
    fn interactive(&self) -> bool {
        self.pingpong > 0
    }
    /// `tcp_incr_quickack`.
    fn more_quick(&mut self) {
        let quick = match WINDOW / (2 * self.rcv_mss) {
            0 => 2,
            quick => quick.min(QUICK_MAX),
        };
        self.quick = self.quick.max(quick);
    }
    /// `tcp_event_ack_sent`: an acknowledgement went, alone or with data.
    fn acknowledged(&mut self) {
        if self.quick > 0 && self.pending.scheduled {
            self.quick -= 1;
            if self.quick == 0 {
                self.ato = DELAY;
            }
        }
        self.pending = Pending::default();
        self.acked = self.came;
    }
    /// `tcp_measure_rcv_mss`.
    fn measure(&mut self, len: u32, push: bool, fin: bool) {
        let last = core::mem::take(&mut self.last_size);
        if len >= self.rcv_mss {
            self.rcv_mss = len.min(self.advertised);
            self.pending.pushed |= push;
            return;
        }
        let whole = len + HEADER;
        if whole >= MSS_DEFAULT + TCP_HEADER || (whole >= MSS_MIN + TCP_HEADER && !push && !fin) {
            self.last_size = len;
            if len == last {
                self.rcv_mss = len;
                return;
            }
        }
        self.pending.pushed_twice |= self.pending.pushed;
        self.pending.pushed = true;
    }
    /// `tcp_event_data_recv`.
    fn data_came(&mut self, size: u32, push: bool, fin: bool, now: u64) {
        self.pending.scheduled = true;
        self.measure(size, push, fin);
        if self.ato == 0 {
            self.more_quick();
            self.ato = DELAY;
        } else {
            let since = now.saturating_sub(self.last_came);
            if since <= DELAY / 2 {
                self.ato = self.ato / 2 + DELAY / 2;
            } else if since < self.ato {
                self.ato = (self.ato / 2 + since).min(RTO);
            } else if since > RTO {
                self.more_quick();
            }
        }
        self.last_came = now;
        self.counts.data_came = Some(now);
    }
    /// `tcp_rtt_estimator`'s round trip, after `sample`.
    fn round_trip(&mut self, sample: u64) {
        let sample = sample.max(SRTT / 8);
        self.srtt = (self.srtt + sample).saturating_sub(self.srtt / 8).max(1);
    }
    /// `tcp_schedule_loss_probe`, which with one segment out waits too
    /// long to matter here.
    fn schedule_probe(&mut self, now: u64) {
        let out = self.packets_out();
        self.timer = (out > 0 && self.probe.is_none()).then(|| {
            let margin = if out == 1 { RTO_MIN } else { PROBE_MARGIN };
            let wait = (self.srtt / 4 + margin).next_multiple_of(MS).min(RTO);
            (Timer::Loss, now + wait)
        });
    }
}

/// Both sides of a connection, client first.
pub(crate) struct Flows {
    sides: [Side; 2],
    /// How each side's writes go now.
    pushes: [Push; 2],
    wire: VecDeque<Packet>,
    /// The side whose system call runs, whose segments wait for it to end
    /// (`sk_backlog`).
    owner: Option<usize>,
    backlog: VecDeque<Packet>,
    now: u64,
    /// No clock runs, so nothing may wait for a timer.
    timeless: bool,
    /// The data that has come to each side and is to be moved there, with
    /// when it came; what has been moved, and when the peer's end came.
    arrivals: [VecDeque<(u64, u64)>; 2],
    moved: [u64; 2],
    end_at: [Option<u64>; 2],
}

impl Flows {
    /// A connection whose sides advertise an MSS of `advertised`, made
    /// `now`, if there is a clock.
    pub(crate) fn new(advertised: u32, now: Option<u64>) -> Self {
        // `tcp_bound_to_half_wnd`: the client has only the SYN-ACK's window
        // until the server's first segment.
        let bound = advertised.min(WINDOW / 2);
        let first = if advertised < WINDOW / 2 {
            bound
        } else {
            advertised / 2
        };
        let mut sides = [
            Side::new(first, bound, advertised),
            Side::new(bound, bound, advertised),
        ];
        // The handshake: the SYN and the last acknowledgement; the SYN-ACK,
        // which the listener sends, counts for the client alone.
        sides[0].counts.segs_out = 2;
        sides[0].counts.segs_in = 1;
        sides[1].counts.segs_in = 2;
        Self {
            sides,
            pushes: [Push::default(); 2],
            wire: VecDeque::new(),
            owner: None,
            backlog: VecDeque::new(),
            now: now.unwrap_or(0),
            timeless: now.is_none(),
            arrivals: Default::default(),
            moved: [0; 2],
            end_at: [None; 2],
        }
    }
    /// What `tcp_info` tells of `side` at `now`.
    pub(crate) fn counts(&mut self, side: usize, now: u64) -> Counts {
        self.advance(now);
        let s = &self.sides[side];
        let end = u64::from(s.fin_sent);
        let end_acked = s.fin_sent && s.una == s.next;
        Counts {
            unacked: s.packets_out(),
            acked: s.una - u64::from(end_acked),
            received: s.came - u64::from(s.fin_came),
            held: s.written - u64::from(s.fin) - (s.next - end),
            queued: s.written - s.una,
            end_waits: s.fin && !end_acked,
            end_acked,
            end_came: s.fin_came,
            ato: s.ato as u32,
            snd_mss: s.mss,
            rcv_mss: s.rcv_mss,
            ..s.counts
        }
    }
    /// `side`'s writes go as `push` says from now on.
    pub(crate) fn sending(&mut self, side: usize, push: Push) {
        self.pushes[side] = push;
    }
    /// The bytes `side` has written.
    pub(crate) fn written(&self, side: usize) -> u64 {
        let s = &self.sides[side];
        s.written - u64::from(s.fin)
    }
    /// `to` takes data up to `edge`, counted from the connection's start.
    pub(crate) fn window(&mut self, to: usize, edge: u64, now: u64) {
        self.advance(now);
        let s = &mut self.sides[1 - to];
        s.edge = edge;
        if s.blocked && s.window() > 0 {
            s.blocked = false;
            self.transmit(1 - to, Nagle::Own, false);
            self.deliver();
        }
    }
    /// The next data to move to `to`, and when it came there.
    pub(crate) fn arrival(&mut self, to: usize) -> Option<(u64, u64)> {
        let arrival = self.arrivals[to].pop_front()?;
        self.moved[to] += arrival.0;
        Some(arrival)
    }
    /// Whether data or an end has come to each side that has not been moved.
    pub(crate) fn arrived(&self) -> [bool; 2] {
        [0, 1].map(|to| !self.arrivals[to].is_empty() || self.end_at[to].is_some())
    }
    /// The data moved to `to`.
    pub(crate) fn moved(&self, to: usize) -> u64 {
        self.moved[to]
    }
    /// When the peer's end came to `to`, which is told once.
    pub(crate) fn ended(&mut self, to: usize) -> Option<u64> {
        self.end_at[to].take()
    }
    /// When a timer may next send data that waits; none while none does.
    pub(crate) fn wake(&self) -> Option<u64> {
        self.sides
            .iter()
            .any(|s| s.written > s.next && (s.window() > 0 || !s.blocked))
            .then(|| self.due())
            .flatten()
            .map(|(at, ..)| at)
    }
    /// `side` sent `len` bytes; a write that fills its buffer is all pushed
    /// (`tcp_sendmsg_locked`, before `sk_stream_wait_memory`).
    pub(crate) fn write(&mut self, side: usize, len: u64, full: bool, now: u64) {
        self.advance(now);
        if len == 0 || self.sides[side].fin {
            return;
        }
        let push = self.pushes[side];
        self.owner = Some(side);
        let s = &mut self.sides[side];
        s.no_delay = push.no_delay;
        s.cork = push.cork;
        // `tcp_skb_entail`, unless the write goes on in the last buffer.
        let waits = s.written - s.next;
        s.pushed &= waits > 0 && waits + len <= u64::from(s.mss);
        s.written += len;
        if push.urgent {
            s.urgent = s.written;
        }
        let nagle = match (full, push.more) {
            (true, _) => Nagle::Push,
            (false, true) => Nagle::Cork,
            (false, false) => Nagle::Own,
        };
        self.transmit(side, nagle, false);
        self.release();
    }
    /// `side`'s end is sent, after what it wrote (`tcp_send_fin`).
    pub(crate) fn end(&mut self, side: usize, now: u64) {
        self.advance(now);
        let s = &mut self.sides[side];
        if s.fin {
            return;
        }
        s.fin = true;
        s.written += 1;
        self.owner = Some(side);
        self.transmit(side, Nagle::Push, false);
        self.release();
    }
    /// `side` was reset, which its peer hears.
    pub(crate) fn reset(&mut self, side: usize, now: u64) {
        self.advance(now);
        self.sides[side].counts.segs_out += 1;
        self.sides[1 - side].counts.segs_in += 1;
        for s in &mut self.sides {
            s.timer = None;
            s.pending = Pending::default();
        }
        self.arrivals = Default::default();
        self.end_at = [None; 2];
    }
    /// `side` read `len` bytes (`tcp_recvmsg`, `__tcp_cleanup_rbuf`).
    pub(crate) fn read(&mut self, side: usize, len: u64, now: u64) {
        self.advance(now);
        if len == 0 {
            return;
        }
        self.owner = Some(side);
        let s = &mut self.sides[side];
        s.copied += len;
        let emptied = s.copied >= s.came - u64::from(s.fin_came);
        let pushed = s.pending.pushed_twice || (s.pending.pushed && !s.interactive());
        if s.pending.scheduled && (s.came - s.acked > u64::from(s.rcv_mss) || (pushed && emptied)) {
            self.send_ack(side);
            self.deliver();
        }
        self.release();
    }
    /// `TCP_NODELAY` set or cleared; set, what waits goes.
    pub(crate) fn set_no_delay(&mut self, side: usize, on: bool, now: u64) {
        self.advance(now);
        self.sides[side].no_delay = on;
        if on {
            self.sides[side].pushed = true;
            self.owner = Some(side);
            self.transmit(side, Nagle::Own, false);
            self.release();
        }
    }
    /// `TCP_CORK` set or cleared, which lets go what it held unless Nagle's
    /// algorithm holds it too (`__tcp_sock_set_cork`).
    pub(crate) fn set_cork(&mut self, side: usize, on: bool, now: u64) {
        self.advance(now);
        let s = &mut self.sides[side];
        s.cork = on;
        if on {
            return;
        }
        s.pushed |= s.no_delay;
        self.owner = Some(side);
        self.transmit(side, Nagle::Own, false);
        self.release();
    }
    /// `TCP_QUICKACK` set to `value` (`__tcp_sock_set_quickack`).
    pub(crate) fn set_quick(&mut self, side: usize, value: i32, now: u64) {
        self.advance(now);
        let s = &mut self.sides[side];
        s.pingpong = u32::from(value == 0);
        if value == 0 || !s.pending.scheduled {
            return;
        }
        s.pending.pushed = true;
        self.owner = Some(side);
        let s = &self.sides[side];
        if s.came - s.acked > u64::from(s.rcv_mss) || s.copied >= s.came - u64::from(s.fin_came) {
            self.send_ack(side);
            self.deliver();
        }
        if value & 1 == 0 {
            self.sides[side].pingpong = 1;
        }
        self.release();
    }

    /// Runs the timers due by `now`, each at its time.
    pub(crate) fn advance(&mut self, now: u64) {
        // Every timer is set for later than its now.
        if now <= self.now {
            return;
        }
        while let Some((at, side, ack)) = self.due().filter(|&(at, ..)| at <= now) {
            self.now = self.now.max(at);
            if ack {
                self.acknowledge_late(side);
            } else {
                self.retransmit_timer(side);
            }
            self.deliver();
        }
        self.now = now;
    }
    /// The next timer: its time, its side, and whether it is the delayed
    /// acknowledgement's.
    fn due(&self) -> Option<(u64, usize, bool)> {
        self.sides
            .iter()
            .enumerate()
            .flat_map(|(side, s)| {
                [
                    s.pending.timer.map(|at| (at, side, true)),
                    s.timer.map(|(_, at)| (at, side, false)),
                ]
            })
            .flatten()
            .min()
    }
    /// `tcp_delack_timer_handler`.
    fn acknowledge_late(&mut self, side: usize) {
        let s = &mut self.sides[side];
        s.pending.timer = None;
        if !s.pending.scheduled {
            return;
        }
        if s.interactive() {
            s.pingpong = 0;
            s.ato = DELAY;
        } else {
            s.ato = (s.ato * 2).min(RTO);
        }
        self.send_ack(side);
    }
    /// A loss probe (`tcp_send_loss_probe`), or data that waited with
    /// nothing in flight (`tcp_write_wakeup`).
    fn retransmit_timer(&mut self, side: usize) {
        let s = &mut self.sides[side];
        let Some((kind, _)) = s.timer.take() else {
            return;
        };
        if kind == Timer::Window {
            self.transmit(side, Nagle::Push, true);
            return;
        }
        if s.probe.is_some() {
            return;
        }
        if s.written > s.next && (s.window() > 0 || s.written - s.next == u64::from(s.fin)) {
            self.transmit(side, Nagle::Push, true);
            let s = &mut self.sides[side];
            // A probe sets the retransmission timer (`tcp_rearm_rto`), not the
            // probe timer, which `transmit` set.
            s.timer = None;
            s.probe = Some((s.next, false));
            return;
        }
        let Some(last) = s.in_flight.back() else {
            return;
        };
        let (end, len, segments) = (last.end, last.len, last.segments);
        let len = if segments > 1 {
            len - (segments - 1) * s.mss
        } else {
            len
        };
        s.probe = Some((s.next, true));
        s.counts.retransmitted += 1;
        s.counts.sent += u64::from(len);
        s.counts.resent += u64::from(len);
        let fin = s.fin_sent && end == s.next;
        self.send(side, (len, 1), end, (true, fin));
    }
    /// Sends what `nagle` and the congestion window let go
    /// (`tcp_write_xmit`); a probe sends one segment whatever is in flight.
    fn transmit(&mut self, side: usize, nagle: Nagle, probe: bool) {
        let mut sent = false;
        self.sides[side].blocked = false;
        loop {
            let s = &mut self.sides[side];
            let waits = s.written - s.next;
            if waits == 0 {
                break;
            }
            let out = s.packets_out();
            let room = s.cwnd.saturating_sub(out);
            if room == 0 && !probe {
                s.cwnd_limited = true;
                break;
            }
            // The end goes with the last data, or alone.
            let data = waits - u64::from(s.fin);
            let window = s.window();
            if data > 0 && window == 0 {
                s.blocked = true;
                break;
            }
            let timeless = self.timeless;
            let quota = room.min((s.cwnd / 2).max(1)).min(WINDOW / 2 / s.mss).max(1);
            let quota = if probe { 1 } else { quota };
            let mut len = data.min(u64::from(quota) * u64::from(s.mss)) as u32;
            if u64::from(len) > window {
                len = window as u32;
                s.blocked = true;
            }
            let last = u64::from(len) == data;
            let part = len % s.mss;
            let urgent = s.urgent > s.una;
            let holds = match nagle {
                Nagle::Push => false,
                Nagle::Cork => true,
                Nagle::Own => {
                    let nagle = !s.no_delay && out > 0 && s.small > s.una;
                    !s.pushed && (s.cork || nagle)
                }
            };
            if part != 0 && last && !s.fin && !urgent && holds && !timeless {
                len -= part;
                if len == 0 {
                    break;
                }
            }
            let fin = s.fin && u64::from(len) == data;
            let segments = len.div_ceil(s.mss).max(1);
            s.next += u64::from(len) + u64::from(fin);
            s.fin_sent |= fin;
            if len < segments * s.mss {
                s.small = s.next;
            }
            s.in_flight.push_back(InFlight {
                end: s.next,
                len,
                segments,
                at: self.now,
            });
            s.counts.sent += u64::from(len);
            let end = s.next;
            self.send(side, (len, segments), end, (u64::from(len) == data, fin));
            sent = true;
            if self.owner == Some(side) {
                self.deliver();
            }
            if probe {
                break;
            }
        }
        let s = &mut self.sides[side];
        if sent {
            let now = self.now;
            s.schedule_probe(now);
        } else if s.in_flight.is_empty()
            && s.written > s.next
            && s.window() > 0
            && s.timer.is_none()
        {
            // `tcp_check_probe_timer`.
            s.timer = Some((Timer::Window, self.now + RTO));
        }
    }
    /// A segment with an acknowledgement goes out (`__tcp_transmit_skb`).
    fn send(&mut self, side: usize, (len, segments): (u32, u32), end: u64, flags: (bool, bool)) {
        let now = self.now;
        let s = &mut self.sides[side];
        s.acknowledged();
        s.counts.segs_out += segments;
        if len > 0 {
            s.counts.data_segs_out += segments;
            s.counts.data_went = Some(now);
            // `tcp_event_data_sent`: a reply soon after data.
            if now.saturating_sub(s.last_came) < s.ato {
                s.pingpong = s.pingpong.saturating_add(1).min(255);
            }
        }
        self.wire.push_back(Packet {
            to: 1 - side,
            len,
            segments,
            end,
            push: flags.0,
            fin: flags.1,
            ack: s.came,
        });
    }
    /// `tcp_send_ack`.
    fn send_ack(&mut self, side: usize) {
        let end = self.sides[side].next;
        self.send(side, (0, 1), end, (false, false));
    }
    /// Takes in what is on the wire (`tcp_v4_rcv`), but for a side whose
    /// call runs.
    fn deliver(&mut self) {
        while let Some(packet) = self.wire.pop_front() {
            let counts = &mut self.sides[packet.to].counts;
            counts.segs_in += packet.segments;
            if packet.len > 0 {
                counts.data_segs_in += packet.segments;
            }
            if self.owner == Some(packet.to) {
                self.backlog.push_back(packet);
            } else {
                self.receive(&packet, false);
            }
        }
    }
    /// The call of the owner ends (`release_sock`): what waited is taken
    /// in, with one acknowledgement for all of it (`TCP_ACK_DEFERRED`).
    fn release(&mut self) {
        let Some(side) = self.owner else { return };
        self.deliver();
        let mut deferred = false;
        while let Some(packet) = self.backlog.pop_front() {
            deferred |= self.receive(&packet, true);
            self.deliver();
        }
        self.owner = None;
        if deferred && self.sides[side].pending.scheduled {
            self.send_ack(side);
        }
        self.deliver();
    }
    /// `tcp_rcv_established`. With `defer`, an acknowledgement due now is
    /// left to the caller: returns whether one is.
    fn receive(&mut self, packet: &Packet, defer: bool) -> bool {
        let side = packet.to;
        let now = self.now;
        let s = &mut self.sides[side];
        // The peer's window has come.
        s.mss = s.bound;
        s.counts.ack_came = Some(now);
        let has_data = packet.len > 0 || packet.fin;
        if has_data && packet.end <= s.came {
            // Sent again: acknowledged at once (`tcp_data_queue`).
            s.more_quick();
            s.pingpong = 0;
            s.ato = DELAY;
            s.pending.scheduled = true;
            self.ack(side, packet.ack);
            if let Some(peer) = self.sides.get_mut(1 - side) {
                // Its D-SACK says both came.
                peer.counts.delivered += 1;
            }
            return self.check_ack(side, defer);
        }
        if packet.len > 0 {
            let size = packet.len.div_ceil(packet.segments);
            let s = &mut self.sides[side];
            s.came = packet.end - u64::from(packet.fin);
            s.data_came(size, packet.push, packet.fin, now);
            let arrivals = &mut self.arrivals[side];
            match arrivals.back_mut() {
                Some((len, at)) if *at == now => *len += u64::from(packet.len),
                _ => arrivals.push_back((u64::from(packet.len), now)),
            }
        }
        self.ack(side, packet.ack);
        if packet.fin {
            let s = &mut self.sides[side];
            s.came = packet.end;
            s.fin_came = true;
            self.end_at[side] = Some(now);
            let s = &mut self.sides[side];
            s.pending.scheduled = true;
            if s.fin_sent {
                // `TCP_FIN_WAIT1` and `TCP_FIN_WAIT2` answer at once.
                self.send_ack(side);
            } else {
                s.pingpong = s.pingpong.max(1);
            }
        }
        // `tcp_data_snd_check`.
        self.transmit(side, Nagle::Own, false);
        has_data && self.check_ack(side, defer)
    }
    /// `tcp_ack`: `side` hears that the peer has all up to `ack`.
    fn ack(&mut self, side: usize, ack: u64) {
        let now = self.now;
        let s = &mut self.sides[side];
        if let Some((high, again)) = s.probe
            && ack >= high
            && (!again || ack <= high)
        {
            s.probe = None;
        }
        if ack <= s.una {
            return;
        }
        let mut first = None;
        let mut newly = 0;
        while let Some(sent) = s.in_flight.front()
            && sent.end <= ack
        {
            first.get_or_insert(sent.at);
            newly += sent.segments;
            s.in_flight.pop_front();
        }
        s.una = ack;
        s.counts.delivered += newly;
        if core::mem::take(&mut s.cwnd_limited) {
            s.cwnd += newly;
        }
        if let Some(at) = first {
            s.round_trip(now.saturating_sub(at));
        }
        s.timer = None;
        if !s.in_flight.is_empty() {
            s.schedule_probe(now);
        }
    }
    /// `tcp_ack_snd_check`: acknowledges now, or sets the timer.
    fn check_ack(&mut self, side: usize, defer: bool) -> bool {
        let now = self.now;
        let s = &mut self.sides[side];
        if !s.pending.scheduled {
            // Data went with it.
            return false;
        }
        // Past a full segment unacknowledged, while the window holds.
        let full = s.came - s.acked > u64::from(s.rcv_mss)
            && s.came.saturating_sub(s.copied) <= u64::from(WINDOW / 2);
        let soon = s
            .pending
            .timer
            .is_some_and(|at| at <= now + s.ato.min(DELAY) / 4);
        if full || (s.quick > 0 && !s.interactive()) || soon || self.timeless {
            if defer && !soon {
                return true;
            }
            self.send_ack(side);
            return false;
        }
        // `tcp_send_delayed_ack`; before any data the timer is the next
        // tick's.
        let due = now + s.ato.clamp(MS, DELAY);
        s.pending.timer = Some(s.pending.timer.map_or(due, |at| at.min(due)));
        false
    }
}

#[cfg(test)]
#[path = "segments_tests.rs"]
mod tests;
