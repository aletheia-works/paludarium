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
//! Linux's does (`tcp_grow_window`). A segment is lost when the filter of
//! the socket it comes to drops or cuts it ([`Tap`]), and is sent again as
//! [`loss`] says.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

pub(crate) mod loss;
use loss::{Flags, Loss, Resend};

/// Times are in microseconds, on the host's monotonic clock.
const MS: u64 = 1000;
/// `TCP_ATO_MIN`, and what a delayed acknowledgement waits on a path whose
/// round trip is short (`TCP_DELACK_MIN`).
const DELAY: u64 = 40 * MS;
/// `TCP_TIMEOUT_INIT`, `sysctl_tcp_synack_retries` and
/// `sysctl_tcp_invalid_ratelimit`.
const SYNACK: u64 = 1000 * MS;
const SYNACK_RETRIES: u32 = 5;
const CHALLENGE: u64 = 500 * MS;
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
/// Its variation, 4 times over as `mdev_us` keeps it.
const MDEV: u64 = 4 * 15;

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
    /// The segments sent again, and their bytes.
    pub(crate) retransmitted: u32,
    pub(crate) resent: u64,
    /// The sender's recovery (`icsk_ca_state`, `sacked_out`, `lost_out`,
    /// `retrans_out` and what it has seen).
    pub(crate) state: u8,
    pub(crate) retransmits: u8,
    pub(crate) backoff: u8,
    pub(crate) rto: u32,
    pub(crate) left: (u32, u32, u32),
    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,
    pub(crate) reordering: u32,
    pub(crate) reordered: u32,
    pub(crate) dsacks: u32,
    pub(crate) timeouts: u16,
    pub(crate) recoveries: u16,
    pub(crate) timeout_ms: u32,
    /// The segments that came out of order.
    pub(crate) disordered: u32,
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
    reset: bool,
    /// The SYN-ACK, sent again.
    syn: bool,
    ack: u64,
    /// When it went, and the time it echoes (its timestamps).
    at: u64,
    echo: u64,
    /// Its SACK blocks, a D-SACK first.
    sacks: Option<Box<[(u64, u64)]>>,
}

impl Packet {
    fn start(&self) -> u64 {
        self.end - u64::from(self.len) - u64::from(self.fin)
    }
}

/// A segment as the filter of the socket it comes to sees it.
#[derive(Debug)]
pub(crate) struct Segment<'a> {
    /// The data's place in the connection's, and its length.
    pub(crate) start: u64,
    pub(crate) len: u32,
    /// `gso_segs`, and the MSS they were cut by.
    pub(crate) segments: u32,
    pub(crate) mss: u32,
    pub(crate) ack: u64,
    pub(crate) push: bool,
    pub(crate) fin: bool,
    pub(crate) reset: bool,
    pub(crate) syn: bool,
    /// Where the urgent data ends, if it is past `start`.
    pub(crate) urgent: Option<u64>,
    /// The window offered, unscaled.
    pub(crate) window: u64,
    /// When it went and the time it echoes, in microseconds.
    pub(crate) at: u64,
    pub(crate) echo: u64,
    pub(crate) sacks: &'a [(u64, u64)],
    /// The bytes before this one have left the sender's buffer; the last of
    /// them, for a segment sent again.
    pub(crate) moved: u64,
    pub(crate) behind: &'a VecDeque<u8>,
}

/// The filter of a socket, which its segments pass as they come
/// (`tcp_filter`).
pub(crate) trait Tap: Send + Sync {
    /// How many bytes of the segment's data the filter keeps; `None` when it
    /// drops the segment.
    fn keep(&self, segment: &Segment<'_>) -> Option<u32>;
}

/// The server's side of a handshake whose last acknowledgement its
/// listener's filter may drop (`struct request_sock`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    /// The handshake ended at once, as it does with no filter.
    Never,
    /// Until `at` the SYN-ACK, sent again `tries` times, waits.
    Waits {
        at: u64,
        tries: u32,
    },
    Opened,
    Dropped,
}

/// Why a connection ended for a side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A reset came.
    Reset,
    /// What it sent was not acknowledged in time.
    TimedOut,
}

/// Data sent and not acknowledged (the retransmit queue): its sequence
/// numbers, the end one of them, and its data.
#[derive(Clone, Copy)]
struct InFlight {
    start: u64,
    end: u64,
    len: u32,
    segments: u32,
    push: bool,
    fin: bool,
    /// When it last went, and in which call.
    at: u64,
    burst: u64,
    marks: u8,
}

/// An acknowledgement due (`icsk_ack.pending`).
#[derive(Clone, Copy, Default)]
struct Pending {
    scheduled: bool,
    pushed: bool,
    pushed_twice: bool,
    /// `ICSK_ACK_NOW`.
    now: bool,
    timer: Option<u64>,
}

/// What the retransmission timer waits for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timer {
    /// `ICSK_TIME_LOSS_PROBE`.
    Loss,
    /// `ICSK_TIME_REO_TIMEOUT`.
    Reorder,
    /// `ICSK_TIME_RETRANS`.
    Resend,
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
    /// `is_cwnd_limited`, `max_packets_out` and `cwnd_usage_seq`.
    cwnd_limited: bool,
    most_out: u32,
    used: u64,
    loss: Loss,
    /// `TCP_USER_TIMEOUT`, in milliseconds; whether the socket is closed.
    user_timeout: u32,
    closed: bool,
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
    /// What came out of order, whether it is the end, and the SACK blocks
    /// that tell of it, the newest first; a D-SACK to send; `ts_recent`.
    ahead: Vec<(u64, u64, bool)>,
    blocks: Vec<(u64, u64)>,
    duplicate: Option<(u64, u64)>,
    recent: u64,
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
            most_out: 0,
            used: 0,
            loss: Loss::default(),
            user_timeout: 0,
            closed: false,
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
            ahead: Vec::new(),
            blocks: Vec::new(),
            duplicate: None,
            recent: 0,
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
    /// The SACK blocks that go with a segment, with timestamps at most
    /// three, a D-SACK first.
    fn sacks(&mut self) -> Option<Box<[(u64, u64)]>> {
        if self.duplicate.is_none() && self.blocks.is_empty() {
            return None;
        }
        let duplicate = self.duplicate.take();
        Some(
            duplicate
                .into_iter()
                .chain(self.blocks.iter().copied())
                .take(3)
                .collect(),
        )
    }
    /// `tcp_dsack_extend`.
    fn extend_duplicate(&mut self, start: u64, end: u64) {
        match &mut self.duplicate {
            Some(block) if start <= block.1 && block.0 <= end => {
                *block = (block.0.min(start), block.1.max(end));
            }
            Some(_) => {}
            none => *none = Some((start, end)),
        }
    }
    /// `tcp_data_queue_ofo`'s queue, in order.
    fn keep_ahead(&mut self, start: u64, end: u64, fin: bool) {
        let mut at = self.ahead.partition_point(|next| next.0 <= start);
        let mut place = true;
        if let Some(&(from, to, _)) = at.checked_sub(1).and_then(|last| self.ahead.get(last))
            && start < to
        {
            if end <= to {
                // All of it is here.
                self.duplicate = Some((start, end));
                place = false;
            } else if start > from {
                self.duplicate = Some((start, to));
            } else {
                at -= 1;
                self.ahead.remove(at);
                self.extend_duplicate(from, to);
            }
        }
        if place {
            while let Some(&(from, to, _)) = self.ahead.get(at)
                && end > from
            {
                if end < to {
                    self.extend_duplicate(from, end);
                    break;
                }
                self.ahead.remove(at);
                self.extend_duplicate(from, to);
            }
            self.ahead.insert(at, (start, end, fin));
        }
        self.tell_ahead(start, end);
    }
    /// `tcp_sack_new_ofo_skb`.
    fn tell_ahead(&mut self, start: u64, end: u64) {
        let meets = |block: &(u64, u64)| start <= block.1 && block.0 <= end;
        let mut block = (start, end);
        if let Some(at) = self.blocks.iter().position(meets) {
            let old = self.blocks.remove(at);
            block = (old.0.min(start), old.1.max(end));
        }
        self.blocks.retain(|other| {
            let joins = block.0 <= other.1 && other.0 <= block.1;
            if joins {
                block = (block.0.min(other.0), block.1.max(other.1));
            }
            !joins
        });
        self.blocks.insert(0, block);
        // `TCP_NUM_SACKS`.
        self.blocks.truncate(4);
    }
    /// `tcp_rtt_estimator`'s round trip, after `sample`.
    fn round_trip(&mut self, sample: u64) {
        let sample = sample.max(SRTT / 8);
        self.srtt = (self.srtt + sample).saturating_sub(self.srtt / 8).max(1);
    }
}

/// A network's metrics, and a side's local and remote addresses in it.
type Kept = (Arc<crate::tcp_metrics::Metrics>, (IpAddr, IpAddr));

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
    /// Counts the calls that send.
    burst: u64,
    /// Each side's filter, the data it has been given of late, and a side
    /// whose socket has gone with no hold left, which answers with a reset.
    taps: [Option<Arc<dyn Tap>>; 2],
    behind: [VecDeque<u8>; 2],
    dead: [bool; 2],
    request: Request,
    /// When the client last challenged a SYN-ACK (`last_oow_ack_time`).
    challenged: Option<u64>,
    verdicts: [Option<Verdict>; 2],
    /// No clock runs, so nothing may wait for a timer.
    timeless: bool,
    /// The data that has come to each side and is to be moved there, with
    /// when it came; what has been moved, and when the peer's end came.
    arrivals: [VecDeque<(u64, u64)>; 2],
    moved: [u64; 2],
    end_at: [Option<u64>; 2],
    /// What each side's network keeps of its connections, with the side's
    /// local and remote addresses, and whether the side has told it how
    /// it ended.
    metrics: [Option<Kept>; 2],
    settled: [bool; 2],
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
            burst: 0,
            taps: [None, None],
            behind: Default::default(),
            dead: [false; 2],
            request: Request::Never,
            challenged: None,
            verdicts: [None; 2],
            timeless: now.is_none(),
            arrivals: Default::default(),
            moved: [0; 2],
            end_at: [None; 2],
            metrics: [None, None],
            settled: [false; 2],
        }
    }
    /// `side` keeps what it ends with in `metrics`, under its `local` and
    /// `remote` addresses, and starts from what is kept there
    /// (`tcp_init_metrics`, as the handshake ends): the threshold, the
    /// reordering, and a longer first timeout from a longer round trip.
    pub(crate) fn remember(
        &mut self,
        side: usize,
        metrics: Arc<crate::tcp_metrics::Metrics>,
        addresses: (IpAddr, IpAddr),
        now: u64,
    ) {
        self.advance(now);
        let s = &mut self.sides[side];
        let start = metrics.start(addresses, s.srtt, self.now);
        if let Some(ssthresh) = start.ssthresh {
            s.loss.ssthresh = ssthresh;
        }
        if let Some(reordering) = start.reordering {
            s.loss.reordering = reordering;
        }
        if let Some(rto) = start.rto {
            s.loss.rto = rto;
        }
        self.metrics[side] = Some((metrics, addresses));
    }
    /// `tcp_update_metrics` of `side`, once its end is acknowledged and the
    /// peer's has come: `tcp_time_wait`, or `TCP_LAST_ACK` done.
    fn settle(&mut self, side: usize) {
        let s = &self.sides[side];
        if self.settled[side] || self.dead[side] || !(s.fin_sent && s.una == s.next && s.fin_came) {
            return;
        }
        self.settled[side] = true;
        let Some((metrics, addresses)) = &self.metrics[side] else {
            return;
        };
        let ended = crate::tcp_metrics::Ended {
            srtt: s.srtt,
            mdev: MDEV,
            backoff: s.loss.backoff,
            cwnd: s.cwnd,
            ssthresh: s.loss.ssthresh,
            open: s.loss.state == loss::State::Open,
            reordering: s.loss.reordering,
        };
        metrics.update(*addresses, ended, self.now);
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
            state: s.loss.state as u8,
            retransmits: s.loss.retransmits,
            backoff: s.loss.backoff,
            rto: s.loss.rto as u32,
            left: s.left(),
            cwnd: s.cwnd,
            ssthresh: s.loss.ssthresh,
            reordering: s.loss.reordering,
            reordered: s.loss.reordered,
            dsacks: s.loss.dsacks,
            timeouts: s.loss.timeouts,
            recoveries: s.loss.recoveries,
            timeout_ms: s.loss.timeout_ms,
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
        [0, 1].map(|to| {
            !self.arrivals[to].is_empty()
                || self.end_at[to].is_some()
                || self.verdicts[to].is_some()
        })
    }
    /// The data moved to `to`.
    pub(crate) fn moved(&self, to: usize) -> u64 {
        self.moved[to]
    }
    /// When the peer's end came to `to`, which is told once.
    pub(crate) fn ended(&mut self, to: usize) -> Option<u64> {
        self.end_at[to].take()
    }
    /// When a timer may next send data that waits, or that was lost; none
    /// while none does.
    pub(crate) fn wake(&self) -> Option<u64> {
        let tapped = self.tapped() || matches!(self.request, Request::Waits { .. });
        let waits = |(side, s): (usize, &Side)| {
            let peer = &self.sides[1 - side];
            (s.written > s.next && (s.window() > 0 || !s.blocked))
                || s.next > peer.came
                || (s.loss.marked && s.next > s.una)
                || peer.acked > s.una
        };
        (tapped || self.sides.iter().enumerate().any(waits))
            .then(|| self.due())
            .flatten()
            .map(|(at, ..)| at)
    }
    /// The handshake's last acknowledgement comes to the server's side,
    /// whose filter is its listener's: until one is kept, the connection is
    /// the client's alone.
    pub(crate) fn handshake(&mut self, now: u64) {
        self.advance(now);
        let mut packet = self.bare(0);
        if self.passes(&mut packet) {
            return;
        }
        self.sides[1].counts.segs_in = 1;
        self.request = Request::Waits {
            at: self.now + SYNACK,
            tries: 0,
        };
    }
    pub(crate) fn request(&self) -> Request {
        self.request
    }
    /// The request is dropped: the server's side has no socket, nor, its
    /// listener `gone`, a filter.
    pub(crate) fn forget(&mut self, gone: bool) {
        self.request = Request::Dropped;
        self.dead[1] = true;
        if gone {
            self.taps[1] = None;
        }
        self.stop(1);
    }
    /// `reqsk_timer_handler`: the SYN-ACK goes again, or the request is
    /// dropped.
    fn request_timer(&mut self) {
        let Request::Waits { at, tries } = self.request else {
            return;
        };
        if tries >= SYNACK_RETRIES {
            self.forget(false);
            return;
        }
        self.request = Request::Waits {
            at: at + (SYNACK << (tries + 1)),
            tries: tries + 1,
        };
        let mut packet = self.bare(1);
        packet.syn = true;
        self.wire.push_back(packet);
    }
    /// A segment of `side`'s with nothing in it but its acknowledgement.
    fn bare(&self, side: usize) -> Packet {
        let s = &self.sides[side];
        Packet {
            to: 1 - side,
            len: 0,
            segments: 1,
            end: s.next,
            push: false,
            fin: false,
            reset: false,
            syn: false,
            ack: s.came,
            at: self.now,
            echo: s.recent,
            sacks: None,
        }
    }
    /// Whether something one side sent is lost and will be sent again.
    pub(crate) fn losing(&self) -> bool {
        let lost = |(side, s): (usize, &Side)| {
            !self.dead[side] && s.timer.is_some() && s.next > self.sides[1 - side].came
        };
        !self.timeless && self.sides.iter().enumerate().any(lost)
    }
    /// Whether a socket has a filter, or something was lost.
    pub(crate) fn lossy(&self) -> bool {
        self.tapped()
            || self
                .sides
                .iter()
                .any(|s| s.loss.marked || s.loss.stamp.is_some())
    }
    /// Whether the connection is over for a side.
    pub(crate) fn over(&self) -> bool {
        self.dead != [false; 2]
    }
    /// Whether a socket has a filter.
    pub(crate) fn tapped(&self) -> bool {
        self.taps.iter().any(Option::is_some)
    }
    /// `side`'s filter is now `tap`.
    pub(crate) fn tap(&mut self, side: usize, tap: Option<Arc<dyn Tap>>, now: u64) {
        self.advance(now);
        self.taps[side] = tap;
    }
    /// `side`'s `TCP_USER_TIMEOUT`, in milliseconds.
    pub(crate) fn set_user_timeout(&mut self, side: usize, ms: u32, now: u64) {
        self.advance(now);
        self.sides[side].user_timeout = ms;
    }
    /// `side`'s socket is closed.
    pub(crate) fn closed(&mut self, side: usize) {
        self.sides[side].closed = true;
    }
    /// `bytes` left `side`'s peer's buffer for `side`.
    pub(crate) fn gave(&mut self, to: usize, bytes: &[u8]) {
        if !self.tapped() {
            return;
        }
        let una = self.sides[1 - to].una;
        let behind = &mut self.behind[to];
        behind.extend(bytes);
        let keep = (self.moved[to].saturating_sub(una) as usize).min(behind.len());
        behind.drain(..behind.len() - keep);
    }
    /// How the connection ended for `side`, told once.
    pub(crate) fn verdict(&mut self, side: usize) -> Option<Verdict> {
        self.verdicts[side].take()
    }
    /// Whether `side`'s socket has gone, unknown to its peer.
    pub(crate) fn dead(&self, side: usize) -> bool {
        self.dead[side]
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
        self.burst += 1;
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
    /// `side` was reset, which its peer hears unless its filter drops it:
    /// then it stays connected, to none. Returns whether it hears.
    pub(crate) fn reset(&mut self, side: usize, now: u64) -> bool {
        self.advance(now);
        self.sides[side].counts.segs_out += 1;
        let mut packet = self.bare(side);
        packet.reset = true;
        let heard = self.passes(&mut packet);
        self.stop(side);
        if heard {
            if side == 0 && matches!(self.request, Request::Waits { .. }) {
                self.forget(false);
            }
            self.sides[1 - side].counts.segs_in += 1;
            self.stop(1 - side);
        } else {
            self.dead[side] = true;
        }
        heard
    }
    /// `side`'s connection is over: its timers stop, and nothing more comes
    /// to it.
    fn stop(&mut self, side: usize) {
        let s = &mut self.sides[side];
        s.timer = None;
        s.pending = Pending::default();
        self.arrivals[side].clear();
        self.end_at[side] = None;
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
        while let Some((at, side, timer)) = self.due().filter(|&(at, ..)| at <= now) {
            self.now = self.now.max(at);
            match timer {
                0 => self.retransmit_timer(side),
                1 => self.acknowledge_late(side),
                _ => self.request_timer(),
            }
            self.deliver();
        }
        self.now = now;
    }
    /// The next timer: its time, its side, and whether it is the sender's
    /// (0), the delayed acknowledgement's (1) or the request's (2).
    fn due(&self) -> Option<(u64, usize, u8)> {
        let request = match self.request {
            Request::Waits { at, .. } => Some((at, 1, 2)),
            _ => None,
        };
        self.sides
            .iter()
            .enumerate()
            .flat_map(|(side, s)| {
                [
                    s.pending.timer.map(|at| (at, side, 1)),
                    s.timer.map(|(_, at)| (at, side, 0)),
                ]
            })
            .chain([request])
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
    /// `tcp_write_timer_handler`.
    fn retransmit_timer(&mut self, side: usize) {
        let now = self.now;
        self.burst += 1;
        let s = &mut self.sides[side];
        let Some((kind, _)) = s.timer else {
            return;
        };
        match kind {
            Timer::Window => {
                // `tcp_write_wakeup`.
                s.timer = None;
                self.transmit(side, Nagle::Push, true);
            }
            Timer::Loss => self.loss_probe(side),
            Timer::Reorder => {
                s.timer = None;
                if s.reorder_timeout() {
                    self.resend(side);
                }
                let s = &mut self.sides[side];
                if !matches!(s.timer, Some((Timer::Resend, _))) {
                    s.rearm(now);
                }
            }
            Timer::Resend => {
                s.timer = None;
                if s.in_flight.is_empty() {
                    return;
                }
                if s.expired(now) {
                    s.done();
                    self.verdicts[side] = Some(Verdict::TimedOut);
                    self.dead[side] = true;
                    return;
                }
                s.enter_loss(now);
                self.send_again(side, 0, 1);
                let s = &mut self.sides[side];
                s.resent(0);
                s.back_off(now);
            }
        }
    }
    /// `tcp_send_loss_probe`.
    fn loss_probe(&mut self, side: usize) {
        let now = self.now;
        let s = &mut self.sides[side];
        if s.probe.is_none() {
            let out = s.packets_out();
            if s.written > s.next && (s.window() > 0 || s.written - s.next == u64::from(s.fin)) {
                self.transmit(side, Nagle::Push, true);
                let s = &mut self.sides[side];
                if s.packets_out() > out {
                    s.probe = Some((s.next, false));
                    s.timer = None;
                }
            } else if let Some(last) = s.in_flight.back() {
                let (len, segments) = (last.len, last.segments);
                let mut at = s.in_flight.len() - 1;
                let whole = (segments - 1) * s.mss;
                if segments > 1 && len > whole {
                    s.fragment(at, whole);
                    at += 1;
                }
                self.send_again(side, at, 1);
                let s = &mut self.sides[side];
                s.probe = Some((s.next, true));
                s.timer = None;
            }
        }
        self.sides[side].rearm(now);
    }
    /// `tcp_xmit_retransmit_queue`: sends what was lost again, as far as
    /// the congestion window goes.
    fn resend(&mut self, side: usize) {
        let now = self.now;
        let mut from = 0;
        let mut rearm = false;
        while let Some((at, room)) = self.sides[side].next_lost(from) {
            let s = &self.sides[side];
            let segments = room.min((WINDOW / s.mss).max(1));
            let segments = self.send_again(side, at, segments);
            let s = &mut self.sides[side];
            s.resent(at);
            s.recovering(segments);
            rearm |= at == 0 && !matches!(s.timer, Some((Timer::Reorder, _)));
            from = at + 1;
        }
        if rearm {
            let s = &mut self.sides[side];
            s.timer = Some((Timer::Resend, now + s.loss.rto));
        }
    }
    /// `__tcp_retransmit_skb` of the segment at `at`, of at most `segments`,
    /// with the small ones after it that the peer does not share; how many
    /// segments it is.
    fn send_again(&mut self, side: usize, at: usize, segments: u32) -> u32 {
        let (now, burst) = (self.now, self.burst);
        let s = &mut self.sides[side];
        s.trim(at);
        let first = s.in_flight[at];
        let window = s.edge.saturating_sub(first.start);
        let mut len = segments.saturating_mul(s.mss);
        if window == 0 {
            len = len.min(s.mss);
        } else if u64::from(len) > window {
            let window = window as u32;
            len = match window / s.mss * s.mss {
                0 => window,
                whole => whole,
            };
        }
        if first.len > len {
            s.fragment(at, len);
        } else if first.len < s.mss {
            self.collapse(side, at);
        }
        let s = &mut self.sides[side];
        let sent = &mut s.in_flight[at];
        sent.segments = sent.len.div_ceil(s.mss).max(1);
        sent.at = now;
        sent.burst = burst;
        sent.marks |= loss::EVER;
        let sent = *sent;
        s.loss.marked = true;
        s.counts.retransmitted += sent.segments;
        s.counts.sent += u64::from(sent.len);
        s.counts.resent += u64::from(sent.len);
        self.send(
            side,
            (sent.len, sent.segments),
            sent.end,
            (sent.push, sent.fin),
        );
        if self.owner == Some(side) {
            self.deliver();
        }
        sent.segments
    }
    /// `tcp_retrans_try_collapse`: the segments after the one at `at` join
    /// it while they fit in one.
    fn collapse(&mut self, side: usize, at: usize) {
        let [a, b] = &mut self.sides;
        let (s, peer) = if side == 0 { (a, b) } else { (b, a) };
        // What the peer has and has not read is shared with it.
        let shared = |sent: &InFlight| {
            sent.marks & loss::CUT == 0
                && ((sent.start < peer.came && sent.end > peer.copied && peer.came > peer.copied)
                    || peer
                        .ahead
                        .iter()
                        .any(|&(start, end, _)| start < sent.end && end > sent.start))
        };
        let window = s.edge.saturating_sub(s.in_flight[at].start);
        let room = u64::from(s.mss).min(window);
        let mut joined = s.in_flight[at];
        if joined.marks & loss::SACKED != 0 || shared(&joined) {
            return;
        }
        while let Some(&next) = s.in_flight.get(at + 1) {
            if next.segments > 1
                || next.marks & loss::SACKED != 0
                || shared(&next)
                || u64::from(joined.len + next.len) > room
            {
                break;
            }
            joined.len += next.len;
            joined.end = next.end;
            joined.push |= next.push;
            joined.fin |= next.fin;
            joined.marks |= next.marks & loss::EVER;
            s.in_flight.remove(at + 1);
        }
        s.in_flight[at] = joined;
    }
    /// Sends what `nagle` and the congestion window let go
    /// (`tcp_write_xmit`); a probe sends one segment whatever is in flight.
    fn transmit(&mut self, side: usize, nagle: Nagle, probe: bool) {
        let mut sent = 0;
        let mut limited = false;
        let s = &mut self.sides[side];
        s.blocked = false;
        if s.written == s.next {
            // `tcp_send_head`.
            return;
        }
        loop {
            let s = &mut self.sides[side];
            let waits = s.written - s.next;
            if waits == 0 {
                break;
            }
            let out = s.packets_out();
            let room = s.cwnd.saturating_sub(s.on_the_way());
            if room == 0 && !probe {
                limited = true;
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
            let start = s.next;
            let push = u64::from(len) == data;
            s.next += u64::from(len) + u64::from(fin);
            s.fin_sent |= fin;
            if len < segments * s.mss {
                s.small = s.next;
            }
            s.in_flight.push_back(InFlight {
                start,
                end: s.next,
                len,
                segments,
                push,
                fin,
                at: self.now,
                burst: self.burst,
                marks: 0,
            });
            // `tcp_event_new_data_sent`.
            if out == 0 || matches!(s.timer, Some((Timer::Loss, _))) {
                let now = self.now;
                s.rearm(now);
            }
            s.counts.sent += u64::from(len);
            let end = s.next;
            self.send(side, (len, segments), end, (push, fin));
            sent += segments;
            if self.owner == Some(side) {
                self.deliver();
            }
            if probe {
                break;
            }
        }
        let s = &mut self.sides[side];
        limited |= s.on_the_way() >= s.cwnd;
        if sent > 0 || limited {
            s.validate(limited);
        }
        if sent > 0 {
            s.recovering(sent);
            if !probe {
                let now = self.now;
                s.schedule_probe(now, false);
            }
        } else if s.in_flight.is_empty()
            && s.written > s.next
            && s.window() > 0
            && s.timer.is_none()
        {
            // `tcp_check_probe_timer`.
            s.timer = Some((Timer::Window, self.now + s.loss.rto));
        }
    }
    /// A segment with an acknowledgement goes out (`__tcp_transmit_skb`).
    fn send(&mut self, side: usize, (len, segments): (u32, u32), end: u64, flags: (bool, bool)) {
        let now = self.now;
        let s = &mut self.sides[side];
        let sacks = s.sacks();
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
            reset: false,
            syn: false,
            ack: s.came,
            at: now,
            echo: s.recent,
            sacks,
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
        while let Some(mut packet) = self.wire.pop_front() {
            if !self.passes(&mut packet) || !self.opens(&packet) || self.unheard(&packet) {
                continue;
            }
            if packet.syn {
                self.challenge(packet.to);
                continue;
            }
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
    /// Runs the filter of the side `packet` comes to, which may cut it;
    /// whether it keeps it (`tcp_filter`).
    fn passes(&mut self, packet: &mut Packet) -> bool {
        let (to, from) = (packet.to, 1 - packet.to);
        let Some(tap) = &self.taps[to] else {
            return true;
        };
        let (s, peer) = (&self.sides[from], &self.sides[to]);
        // `TIME_WAIT` has no filter.
        if peer.closed && peer.fin_sent && peer.una == peer.next {
            return true;
        }
        // Until it grows, whole segments (`tcp_select_initial_window`): the
        // client's of the SYN's MSS, the server's less the timestamps.
        let segment = s.advertised + if from == 0 { HEADER - TCP_HEADER } else { 0 };
        let first = u64::from(WINDOW - WINDOW % segment);
        let window = peer.edge.saturating_sub(packet.ack).min(first);
        let start = packet.start();
        let segment = Segment {
            start,
            len: packet.len,
            segments: packet.segments,
            mss: s.mss,
            ack: packet.ack,
            push: packet.push,
            fin: packet.fin,
            reset: packet.reset,
            syn: packet.syn,
            urgent: (s.urgent > s.una && s.urgent > start).then_some(s.urgent),
            window,
            at: packet.at,
            echo: packet.echo,
            sacks: packet.sacks.as_deref().unwrap_or_default(),
            moved: self.moved[to],
            behind: &self.behind[to],
        };
        let Some(kept) = tap.keep(&segment) else {
            return false;
        };
        if kept < packet.len {
            let end = packet.end;
            packet.len = kept;
            packet.end = start + u64::from(kept) + u64::from(packet.fin);
            let mut sent = self.sides[from].in_flight.iter_mut();
            if let Some(sent) = sent.find(|sent| sent.end == end) {
                sent.marks |= loss::CUT;
            }
        }
        true
    }
    /// Whether `packet` may go on to the side it comes to, which it opens if
    /// that is a request (`tcp_check_req`); a reset drops one.
    fn opens(&mut self, packet: &Packet) -> bool {
        let Request::Waits { tries, .. } = self.request else {
            return true;
        };
        if packet.to == 0 {
            return true;
        }
        if packet.reset {
            self.forget(false);
            return false;
        }
        self.request = Request::Opened;
        self.sides[1].counts.retransmitted = tries;
        true
    }
    /// A SYN-ACK comes to `side`, which is connected: it answers with an
    /// acknowledgement, not often (`tcp_send_challenge_ack`).
    fn challenge(&mut self, side: usize) {
        self.sides[side].counts.segs_in += 1;
        let now = self.now;
        if self.challenged.is_none_or(|at| now >= at + CHALLENGE) {
            self.challenged = Some(now);
            self.send_ack(side);
        }
    }
    /// Whether `packet` comes to a side with no socket, which answers with
    /// a reset (`tcp_v4_send_reset`), or is a reset.
    fn unheard(&mut self, packet: &Packet) -> bool {
        let side = packet.to;
        if self.dead[side] {
            if !packet.reset {
                self.refuse(side, packet.ack);
            }
            return true;
        }
        if packet.reset {
            self.sides[side].counts.segs_in += 1;
            self.verdicts[side] = Some(Verdict::Reset);
            self.dead[side] = true;
            self.sides[side].done();
            return true;
        }
        // Data after a close, when a filter may drop the reset.
        let s = &self.sides[side];
        if s.closed && packet.end - u64::from(packet.fin) > s.came && self.taps[1 - side].is_some()
        {
            self.sides[side].counts.segs_in += packet.segments;
            self.dead[side] = true;
            self.stop(side);
            self.refuse(side, packet.ack);
            return true;
        }
        false
    }
    /// A reset from `side`, whose socket has gone.
    fn refuse(&mut self, side: usize, end: u64) {
        self.wire.push_back(Packet {
            to: 1 - side,
            len: 0,
            segments: 1,
            end,
            push: false,
            fin: false,
            reset: true,
            syn: false,
            ack: self.sides[side].came,
            at: 0,
            echo: 0,
            sacks: None,
        });
    }
    /// `tcp_rcv_established`. With `defer`, an acknowledgement due now is
    /// left to the caller: returns whether one is.
    fn receive(&mut self, packet: &Packet, defer: bool) -> bool {
        let side = packet.to;
        let now = self.now;
        let start = packet.start();
        let has_data = packet.len > 0 || packet.fin;
        let s = &mut self.sides[side];
        // The peer's window has come.
        s.mss = s.bound;
        s.counts.ack_came = Some(now);
        // `tcp_replace_ts_recent`.
        if start <= s.acked {
            s.recent = packet.at;
        }
        let plain = start == s.came && !s.fin_came && s.ahead.is_empty() && packet.sacks.is_none();
        if plain && has_data {
            if packet.len > 0 {
                self.take(packet);
            }
            self.ack(packet);
            if packet.fin {
                self.end_came(side);
            }
        } else {
            self.ack(packet);
            if has_data {
                self.disordered(packet, start);
            }
        }
        self.settle(side);
        // `tcp_data_snd_check`.
        self.transmit(side, Nagle::Own, false);
        has_data && self.check_ack(side, defer)
    }
    /// Takes in what comes next of `packet`'s data (`tcp_queue_rcv`).
    fn take(&mut self, packet: &Packet) {
        let side = packet.to;
        let now = self.now;
        let size = packet.len.div_ceil(packet.segments);
        let s = &mut self.sides[side];
        let came = packet.end - u64::from(packet.fin);
        let len = came - s.came;
        s.came = came;
        s.data_came(size, packet.push, packet.fin, now);
        self.arrive(side, len);
    }
    /// `len` bytes came to `side`, to be moved there.
    fn arrive(&mut self, side: usize, len: u64) {
        let now = self.now;
        if len == 0 {
            return;
        }
        let arrivals = &mut self.arrivals[side];
        match arrivals.back_mut() {
            Some((more, at)) if *at == now => *more += len,
            _ => arrivals.push_back((len, now)),
        }
    }
    /// `tcp_fin`.
    fn end_came(&mut self, side: usize) {
        self.end_at[side] = Some(self.now);
        let s = &mut self.sides[side];
        s.came += 1;
        s.fin_came = true;
        s.ahead.clear();
        s.blocks.clear();
        s.pending.scheduled = true;
        if s.fin_sent {
            // `TCP_FIN_WAIT1` and `TCP_FIN_WAIT2` answer at once.
            self.send_ack(side);
        } else {
            s.pingpong = s.pingpong.max(1);
        }
    }
    /// `tcp_data_queue` of a segment at `start` that does not come next, or
    /// that fills a gap.
    fn disordered(&mut self, packet: &Packet, start: u64) {
        let side = packet.to;
        let s = &mut self.sides[side];
        if s.fin_came && start >= s.came {
            // Past the end: not taken in (`tcp_rcv_state_process`).
            return;
        }
        s.duplicate = None;
        if packet.end <= s.came {
            // Sent again: acknowledged at once.
            s.duplicate = Some((start, packet.end));
            s.more_quick();
            s.pingpong = 0;
            s.ato = DELAY;
            s.pending.scheduled = true;
            return;
        }
        if start > s.came {
            s.measure(
                packet.len.div_ceil(packet.segments),
                packet.push,
                packet.fin,
            );
            s.pending.scheduled = true;
            s.counts.disordered += packet.segments;
            s.keep_ahead(start, packet.end, packet.fin);
            return;
        }
        if start < s.came {
            s.duplicate = Some((start, s.came));
        }
        let before = s.came;
        if packet.len > 0 {
            s.came = packet.end - u64::from(packet.fin);
            let size = packet.len.div_ceil(packet.segments);
            let now = self.now;
            self.sides[side].data_came(size, packet.push, packet.fin, now);
        }
        let mut fin = packet.fin;
        let s = &mut self.sides[side];
        if !s.ahead.is_empty() {
            // `tcp_ofo_queue`.
            let reached = s.came;
            while !fin && s.ahead.first().is_some_and(|next| next.0 <= s.came) {
                let (from, to, end) = s.ahead.remove(0);
                if from < reached {
                    s.extend_duplicate(from, to.min(reached));
                }
                if to > s.came {
                    s.came = to - u64::from(end);
                    fin = end;
                }
            }
            s.pending.now |= s.ahead.is_empty();
            let came = s.came;
            s.blocks.retain(|block| block.0 > came);
        }
        let len = s.came - before;
        self.arrive(side, len);
        if fin {
            self.end_came(side);
        }
    }
    /// `tcp_ack`: the side `packet` comes to hears what the peer has, and
    /// sends again what was lost.
    fn ack(&mut self, packet: &Packet) {
        let side = packet.to;
        let now = self.now;
        let ack = packet.ack;
        let s = &mut self.sides[side];
        let dubious = s.dubious(packet.sacks.is_some());
        if !dubious {
            if let Some((high, again)) = s.probe
                && ack >= high
                && (!again || ack <= high)
            {
                s.probe = None;
            }
            if ack <= s.una {
                return;
            }
        }
        let prior = s.una;
        let mut flags = Flags {
            advanced: ack > prior,
            news: ack > prior || packet.len > 0 || packet.fin,
            ..Flags::default()
        };
        if flags.advanced {
            s.una = ack;
            s.loss.retransmits = 0;
        }
        let empty = s.in_flight.is_empty();
        let lost = s.loss.lost();
        let mut delivered = 0;
        if let Some(sacks) = &packet.sacks {
            delivered += s.tag(sacks, ack, prior, &mut flags);
        }
        delivered += s.clean(prior, now, packet.echo, &mut flags);
        s.counts.delivered += delivered;
        let resend = if empty {
            s.duplicate_acked((prior, ack, packet.echo), now, flags)
        } else {
            s.after_ack((prior, ack, packet.echo), (delivered, lost), now, flags)
        };
        match resend {
            Resend::None => {}
            Resend::New => {
                self.transmit(side, Nagle::Push, false);
                let s = &mut self.sides[side];
                if !s.sent_new() {
                    self.resend(side);
                }
            }
            Resend::Lost => self.resend(side),
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
        let first = full || (s.quick > 0 && !s.interactive()) || s.pending.now || self.timeless;
        if first && defer && !soon {
            return true;
        }
        // A gap is told of at once.
        if first || soon || !s.ahead.is_empty() {
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

#[cfg(test)]
#[path = "segments/loss_tests.rs"]
mod loss_tests;
