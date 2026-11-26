//! What a sender knows of what it sent and what was lost, as Linux 7.0's
//! TCP does with SACK and timestamps: which segments the peer has out of
//! order, RACK's loss detection, tail loss probes, the retransmission
//! timeout, and the recovery that cubic's threshold and proportional rate
//! reduction pace. Nothing on these links is lost but what a socket's
//! filter drops or cuts.

use super::{InFlight, MS, RTO, RTO_MIN, SRTT, Side, Timer};

/// `TCP_RTO_MAX` and `TCP_INFINITE_SSTHRESH`.
const RTO_MAX: u64 = 120_000 * MS;
pub(crate) const SSTHRESH: u32 = 0x7fff_ffff;
/// `sysctl_tcp_reordering` and `sysctl_tcp_max_reordering`.
pub(crate) const REORDERING: u32 = 3;
const REORDERING_MAX: u32 = 300;
/// `sysctl_tcp_retries2`, and the retries of a closed socket's connection
/// (`tcp_orphan_retries`).
const RETRIES: u32 = 15;
const ORPHAN_RETRIES: u32 = 8;

/// `TCPCB_SACKED_ACKED`, `TCPCB_LOST`, `TCPCB_SACKED_RETRANS` and
/// `TCPCB_EVER_RETRANS`; and a segment the peer's filter cut, whose data
/// the peer does not share.
pub(super) const SACKED: u8 = 1;
pub(super) const LOST: u8 = 2;
pub(super) const AGAIN: u8 = 4;
pub(super) const EVER: u8 = 8;
pub(super) const CUT: u8 = 16;
/// `TCPCB_RETRANS`.
const RESENT: u8 = AGAIN | EVER;

/// `icsk_ca_state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum State {
    #[default]
    Open,
    Disorder,
    Reduced,
    Recovery,
    Loss,
}

/// What an acknowledgement says (`tcp_ack`'s `flag`).
#[derive(Clone, Copy, Default)]
pub(super) struct Flags {
    pub(super) advanced: bool,
    /// New data was acknowledged whole (`FLAG_DATA_ACKED`).
    pub(super) acked: bool,
    /// What was never sent again was acknowledged (`FLAG_ORIG_SACK_ACKED`).
    pub(super) original: bool,
    pub(super) sacked: bool,
    pub(super) again_acked: bool,
    pub(super) dsack: bool,
    pub(super) dsack_probe: bool,
    pub(super) set_timer: bool,
    pub(super) lost_again: bool,
    /// Not a duplicate: it has data or moves the window.
    pub(super) news: bool,
}

/// What is sent after an acknowledgement (`tcp_xmit_recovery`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Resend {
    None,
    Lost,
    New,
}

/// A sender's recovery.
pub(super) struct Loss {
    pub(super) state: State,
    pub(super) ssthresh: u32,
    prior_ssthresh: u32,
    prior_cwnd: u32,
    /// `cwnd`'s growth past the threshold.
    grown: u32,
    /// `high_seq`, `undo_marker`, `undo_retrans` and `retrans_stamp`.
    high: u64,
    undo: Option<u64>,
    undo_resent: i32,
    pub(super) stamp: Option<u64>,
    pub(super) retransmits: u8,
    pub(super) backoff: u8,
    /// `icsk_rto`.
    pub(super) rto: u64,
    pub(super) timeouts: u16,
    pub(super) recoveries: u16,
    pub(super) timeout_ms: u32,
    began: Option<u64>,
    frto: bool,
    prr_delivered: u32,
    prr_out: u32,
    /// `tp->lost`.
    lost: u32,
    pub(super) reordering: u32,
    pub(super) reordered: u32,
    pub(super) dsacks: u32,
    /// RACK's newest delivered: when it was sent, its burst, its end.
    newest: (u64, u64, u64),
    advanced: bool,
    /// `retrans_out` and the like may not be 0.
    pub(super) marked: bool,
    /// What [`Side::left`] was as the connection ended.
    ended: Option<(u32, u32, u32)>,
}

impl Default for Loss {
    fn default() -> Self {
        Self {
            state: State::Open,
            ssthresh: SSTHRESH,
            prior_ssthresh: 0,
            prior_cwnd: 0,
            grown: 0,
            high: 0,
            undo: None,
            undo_resent: 0,
            stamp: None,
            retransmits: 0,
            backoff: 0,
            rto: RTO,
            timeouts: 0,
            recoveries: 0,
            timeout_ms: 0,
            began: None,
            frto: false,
            prr_delivered: 0,
            prr_out: 0,
            lost: 0,
            reordering: REORDERING,
            reordered: 0,
            dsacks: 0,
            newest: (0, 0, 0),
            advanced: false,
            marked: false,
            ended: None,
        }
    }
}

impl Loss {
    pub(super) fn lost(&self) -> u32 {
        self.lost
    }
}

impl Side {
    fn count(&self, mark: u8) -> u32 {
        if !self.loss.marked {
            return 0;
        }
        let marked = self.in_flight.iter().filter(|sent| sent.marks & mark != 0);
        marked.map(|sent| sent.segments).sum()
    }
    /// `sacked_out`, `lost_out` and `retrans_out`.
    pub(super) fn left(&self) -> (u32, u32, u32) {
        match self.loss.ended {
            Some(left) => left,
            None => (self.count(SACKED), self.count(LOST), self.count(AGAIN)),
        }
    }
    /// The connection is over (`tcp_done`): nothing is in flight, though the
    /// counts of what was lost stay.
    pub(super) fn done(&mut self) {
        self.loss.ended = Some(self.left());
        self.loss.backoff = 0;
        self.loss.marked = false;
        self.in_flight.clear();
        self.timer = None;
        self.pending = super::Pending::default();
    }
    /// `tcp_packets_in_flight`.
    pub(super) fn on_the_way(&self) -> u32 {
        if !self.loss.marked {
            return self.packets_out();
        }
        let (sacked, lost, again) = self.left();
        (self.packets_out() + again).saturating_sub(sacked + lost)
    }
    /// Where the highest segment the peer has out of order ends
    /// (`tcp_highest_sack_seq`).
    fn highest(&self) -> u64 {
        if !self.loss.marked {
            return self.una;
        }
        let mut sent = self.in_flight.iter().rev();
        sent.find(|sent| sent.marks & SACKED != 0)
            .map_or(self.una, |sent| sent.end)
    }
    /// `tcp_set_rto`, after a round trip was measured: the timeout of a
    /// short path.
    fn measured(&mut self) {
        self.loss.rto = RTO;
        self.loss.backoff = 0;
    }
    /// `tcp_rearm_rto`.
    pub(super) fn rearm(&mut self, now: u64) {
        let Some(head) = self.in_flight.front() else {
            self.timer = None;
            return;
        };
        let at = match self.timer {
            Some((Timer::Loss | Timer::Reorder, _)) => (head.at + self.loss.rto).max(now + 1),
            _ => now + self.loss.rto,
        };
        self.timer = Some((Timer::Resend, at));
    }
    /// `tcp_schedule_loss_probe`, with the timeout to come if the head was
    /// not `advancing`; whether it was set.
    pub(super) fn schedule_probe(&mut self, now: u64, advancing: bool) -> bool {
        let out = self.packets_out();
        if out == 0 || !matches!(self.loss.state, State::Open | State::Reduced) {
            return false;
        }
        let margin = if out == 1 {
            RTO_MIN
        } else {
            super::PROBE_MARGIN
        };
        let mut wait = (self.srtt / 4 + margin).next_multiple_of(MS);
        let until = if advancing {
            self.loss.rto
        } else {
            let head = self.in_flight.front().map_or(now, |head| head.at);
            (head + self.loss.rto).saturating_sub(now)
        };
        if until > 0 {
            wait = wait.min(until);
        }
        self.timer = Some((Timer::Loss, now + wait));
        true
    }
    /// `tcp_set_xmit_timer`.
    fn set_timer(&mut self, now: u64) {
        if !self.schedule_probe(now, true) {
            self.rearm(now);
        }
    }
    /// Whether an acknowledgement with `sacks` takes `tcp_ack`'s long way.
    pub(super) fn dubious(&self, sacks: bool) -> bool {
        sacks || self.loss.marked || self.loss.state != State::Open
    }
    /// Cuts the first `len` bytes off the segment at `at` (`tcp_fragment`).
    pub(super) fn fragment(&mut self, at: usize, len: u32) {
        let mss = self.mss;
        let sent = &mut self.in_flight[at];
        let rest = sent.len - len;
        let second = InFlight {
            start: sent.start + u64::from(len),
            len: rest,
            segments: rest.div_ceil(mss).max(1),
            ..*sent
        };
        sent.end = second.start;
        sent.len = len;
        sent.segments = len.div_ceil(mss).max(1);
        sent.fin = false;
        self.in_flight.insert(at + 1, second);
    }
    /// `tcp_trim_head` of the segment at `at`, up to `una`.
    pub(super) fn trim(&mut self, at: usize) {
        let (una, mss) = (self.una, self.mss);
        let sent = &mut self.in_flight[at];
        let cut = una.saturating_sub(sent.start).min(u64::from(sent.len)) as u32;
        sent.start += u64::from(cut);
        sent.len -= cut;
        if sent.segments > 1 {
            sent.segments = sent.len.div_ceil(mss).max(1);
        }
    }
    /// `tcp_rack_advance`.
    fn newest(&mut self, sent: InFlight) {
        let of = (sent.at, sent.burst, sent.end);
        self.loss.advanced = true;
        self.loss.newest = self.loss.newest.max(of);
    }
    /// `tcp_check_sack_reordering`.
    fn reordered(&mut self, low: u64) {
        let highest = self.highest();
        if low >= highest {
            return;
        }
        let metric = highest - low;
        if metric > u64::from(self.loss.reordering) * u64::from(self.mss) {
            let segments = metric.div_ceil(u64::from(self.mss));
            self.loss.reordering = (segments as u32).min(REORDERING_MAX);
        }
        self.loss.reordered += 1;
    }
    /// `tcp_sacktag_write_queue`: takes in the blocks of an
    /// acknowledgement of `ack`, whose first may tell of a duplicate.
    /// Returns the segments newly delivered.
    pub(super) fn tag(
        &mut self,
        sacks: &[(u64, u64)],
        ack: u64,
        prior: u64,
        flags: &mut Flags,
    ) -> u32 {
        let mut delivered = 0;
        let first = sacks[0];
        let duplicate = first.0 < ack
            || sacks
                .get(1)
                .is_some_and(|next| first.1 <= next.1 && first.0 >= next.0);
        let duplicate = duplicate && self.duplicate(first, prior, &mut delivered, flags);
        let mut low = self.next;
        for (i, &(start, end)) in sacks.iter().enumerate() {
            let duplicate = duplicate && i == 0;
            if !self.valid(duplicate, start, end) || end <= prior {
                continue;
            }
            let mut at = 0;
            while at < self.in_flight.len() && self.in_flight[at].start < end {
                if self.within(at, start, end) {
                    delivered += self.tag_one(at, duplicate, &mut low, flags);
                }
                at += 1;
            }
        }
        if low != self.next {
            self.reordered(low);
        }
        delivered
    }
    /// `tcp_dsack_seen` of the block `first`, and `tcp_check_dsack`'s
    /// count; whether it counts.
    fn duplicate(
        &mut self,
        (start, end): (u64, u64),
        prior: u64,
        delivered: &mut u32,
        flags: &mut Flags,
    ) -> bool {
        if start >= end {
            return false;
        }
        let len = end - start;
        let mut segments = 1;
        if len > u64::from(self.mss) {
            segments = len.div_ceil(u64::from(self.mss)) as u32;
        } else if self.probe.is_some_and(|(high, _)| high == end) {
            flags.dsack_probe = true;
        }
        self.loss.dsacks += segments;
        if self.loss.dsacks > self.counts.retransmitted {
            return false;
        }
        flags.dsack = true;
        *delivered += segments;
        if let Some(undo) = self.loss.undo
            && self.loss.undo_resent > 0
            && end <= prior
            && end > undo
        {
            self.loss.undo_resent = (self.loss.undo_resent - segments as i32).max(0);
        }
        true
    }
    /// `tcp_is_sackblock_valid`.
    fn valid(&self, duplicate: bool, start: u64, end: u64) -> bool {
        if end > self.next || start >= end || start >= self.next {
            return false;
        }
        if start > self.una {
            return true;
        }
        let Some(undo) = self.loss.undo else {
            return false;
        };
        duplicate && end > self.una && (start >= undo || end > undo)
    }
    /// `tcp_match_skb_to_sack`: whether the segment at `at` is within the
    /// block, cut to what is.
    fn within(&mut self, at: usize, start: u64, end: u64) -> bool {
        let sent = self.in_flight[at];
        let inside = start <= sent.start;
        if inside && end >= sent.end {
            return true;
        }
        if sent.segments == 1 || sent.end <= start {
            return false;
        }
        let mss = self.mss;
        let mut len = if inside {
            let len = (end - sent.start) as u32;
            if len < mss {
                return false;
            }
            len
        } else {
            ((start - sent.start) as u32).max(mss)
        };
        if len > mss {
            let whole = len / mss * mss;
            len = whole + if !inside && whole < len { mss } else { 0 };
        }
        if len >= sent.len {
            return inside;
        }
        self.fragment(at, len);
        inside
    }
    /// `tcp_sacktag_one`; the segments newly delivered.
    fn tag_one(&mut self, at: usize, duplicate: bool, low: &mut u64, flags: &mut Flags) -> u32 {
        let mut sent = self.in_flight[at];
        let segments = sent.segments;
        let mut delivered = 0;
        if duplicate && sent.marks & RESENT != 0 {
            if self.loss.undo.is_some_and(|undo| sent.end > undo) && self.loss.undo_resent > 0 {
                self.loss.undo_resent = (self.loss.undo_resent - segments as i32).max(0);
            }
            if sent.marks & SACKED != 0 {
                *low = (*low).min(sent.start);
            }
        }
        if sent.end <= self.una {
            return 0;
        }
        if sent.marks & SACKED == 0 {
            self.newest(sent);
            if sent.marks & AGAIN != 0 {
                if sent.marks & LOST != 0 {
                    sent.marks &= !(LOST | AGAIN);
                }
            } else {
                if sent.marks & RESENT == 0 {
                    if sent.start < self.highest() {
                        *low = (*low).min(sent.start);
                    }
                    flags.original |= sent.end <= self.loss.high;
                }
                sent.marks &= !LOST;
            }
            sent.marks |= SACKED;
            flags.sacked = true;
            delivered = segments;
        }
        if duplicate {
            sent.marks &= !AGAIN;
        }
        self.loss.marked = true;
        self.in_flight[at] = sent;
        delivered
    }
    /// `tcp_clean_rtx_queue`: what `una` covers leaves the queue. Returns
    /// the segments delivered. `echo` is when the peer last heard of what
    /// it acknowledges was sent.
    pub(super) fn clean(&mut self, prior_una: u64, now: u64, echo: u64, flags: &mut Flags) -> u32 {
        let highest = match self.count(SACKED) {
            0 => prior_una,
            _ => self.highest(),
        };
        let mut low = self.next;
        let mut delivered = 0;
        let mut first = None;
        while let Some(&sent) = self.in_flight.front() {
            let mut acked = sent.segments;
            let whole = sent.end <= self.una;
            if !whole {
                if sent.segments == 1 || self.una <= sent.start {
                    break;
                }
                self.trim(0);
                acked -= self.in_flight[0].segments;
                if acked == 0 {
                    break;
                }
            }
            if sent.marks & RESENT != 0 {
                flags.again_acked = true;
            } else if sent.marks & SACKED == 0 {
                first.get_or_insert(sent.at);
                low = low.min(sent.start);
                flags.original |= sent.end <= self.loss.high;
            }
            if sent.marks & SACKED == 0 {
                delivered += acked;
                // `tcp_skb_spurious_retrans`.
                if sent.marks & RESENT == 0 || echo / MS >= sent.at / MS {
                    self.newest(sent);
                }
            }
            flags.acked = true;
            if !whole {
                break;
            }
            self.in_flight.pop_front();
        }
        if self.in_flight.is_empty() {
            self.loss.marked = false;
        }
        if let Some(at) = first.filter(|_| !flags.again_acked) {
            self.round_trip(now.saturating_sub(at));
        }
        if flags.acked {
            self.measured();
            flags.set_timer = true;
            if low < highest {
                self.reordered(low);
            }
        }
        delivered
    }
    /// `tcp_process_tlp_ack`.
    pub(super) fn probe_acked(&mut self, ack: u64, flags: &Flags) {
        let Some((high, again)) = self.probe else {
            return;
        };
        if ack < high {
            return;
        }
        if !again || flags.dsack_probe {
            self.probe = None;
        } else if ack > high {
            self.reduce();
            self.loss.state = State::Reduced;
            self.end_reduction();
            self.keep_open();
        } else if !(flags.advanced || flags.news || flags.sacked) {
            self.probe = None;
        }
    }
    /// Cubic's threshold (`cubictcp_recalc_ssthresh`).
    fn threshold(&self) -> u32 {
        (self.cwnd * 717 / 1024).max(2)
    }
    /// `tcp_current_ssthresh`.
    fn current_threshold(&self) -> u32 {
        match self.loss.state {
            State::Reduced | State::Recovery => self.loss.ssthresh,
            _ => self.loss.ssthresh.max((self.cwnd >> 1) + (self.cwnd >> 2)),
        }
    }
    /// `tcp_init_cwnd_reduction`.
    fn reduce(&mut self) {
        self.loss.high = self.next;
        self.probe = None;
        self.loss.prior_cwnd = self.cwnd;
        self.loss.prr_delivered = 0;
        self.loss.prr_out = 0;
        self.loss.ssthresh = self.threshold();
    }
    /// `tcp_end_cwnd_reduction`.
    fn end_reduction(&mut self) {
        if self.loss.ssthresh < SSTHRESH
            && (self.loss.state == State::Reduced || self.loss.undo.is_some())
        {
            self.cwnd = self.loss.ssthresh;
        }
    }
    /// `tcp_any_retrans_done`.
    fn any_resent(&self) -> bool {
        self.count(AGAIN) > 0
            || self
                .in_flight
                .front()
                .is_some_and(|head| head.marks & EVER != 0)
    }
    /// `tcp_try_keep_open`.
    fn keep_open(&mut self) {
        let (sacked, lost, _) = self.left();
        let state = if sacked + lost > 0 || self.any_resent() {
            State::Disorder
        } else {
            State::Open
        };
        if self.loss.state != state {
            self.loss.state = state;
            self.loss.high = self.next;
        }
    }
    /// `tcp_try_to_open`.
    fn try_open(&mut self) {
        if !self.any_resent() {
            self.loss.stamp = None;
        }
        if self.loss.state != State::Reduced {
            self.keep_open();
        }
    }
    /// `tcp_packet_delayed`: what came back `echo`es a time before the
    /// first retransmission.
    fn delayed(&self, echo: u64) -> bool {
        self.loss.stamp.is_none_or(|stamp| echo / MS < stamp)
    }
    /// `tcp_undo_cwnd_reduction`.
    fn undo(&mut self, unmark: bool) {
        if unmark {
            for sent in &mut self.in_flight {
                sent.marks &= !LOST;
            }
        }
        if self.loss.prior_ssthresh > 0 {
            self.cwnd = self.cwnd.max(self.loss.prior_cwnd);
            self.loss.ssthresh = self.loss.ssthresh.max(self.loss.prior_ssthresh);
        }
        self.loss.undo = None;
        self.loss.advanced = true;
    }
    /// `tcp_may_undo`.
    fn may_undo(&self, echo: u64) -> bool {
        self.loss.undo.is_some() && (self.loss.undo_resent == 0 || self.delayed(echo))
    }
    /// `tcp_try_undo_recovery`.
    fn recovered(&mut self, echo: u64) {
        if self.may_undo(echo) {
            self.undo(false);
        }
        self.loss.state = State::Open;
    }
    /// `tcp_try_undo_dsack`.
    fn undo_by_dsack(&mut self) -> bool {
        let undone = self.loss.undo.is_some() && self.loss.undo_resent == 0;
        if undone {
            self.undo(false);
        }
        undone
    }
    /// `tcp_try_undo_loss`.
    fn undo_loss(&mut self, frto: bool, echo: u64) -> bool {
        if !frto && !self.may_undo(echo) {
            return false;
        }
        self.undo(true);
        self.loss.retransmits = 0;
        self.loss.state = State::Open;
        true
    }
    /// `tcp_init_undo`.
    fn may_be_undone(&mut self) {
        self.loss.undo = Some(self.una);
        let probe = self.probe.is_some_and(|(_, again)| again);
        let again = self.count(AGAIN) as i32 + i32::from(probe);
        self.loss.undo_resent = if again > 0 { again } else { -1 };
    }
    /// `tcp_enter_recovery`.
    fn enter_recovery(&mut self) {
        if !self.any_resent() {
            self.loss.stamp = None;
        }
        self.loss.prior_ssthresh = 0;
        self.may_be_undone();
        if !matches!(self.loss.state, State::Reduced | State::Recovery) {
            self.loss.prior_ssthresh = self.current_threshold();
            self.reduce();
        }
        self.loss.state = State::Recovery;
    }
    /// `tcp_mark_skb_lost`.
    fn mark_lost(&mut self, at: usize) {
        let sent = &mut self.in_flight[at];
        if sent.marks & SACKED != 0 {
            return;
        }
        if sent.marks & LOST != 0 {
            if sent.marks & AGAIN != 0 {
                sent.marks &= !AGAIN;
                self.loss.lost += sent.segments;
            }
        } else {
            sent.marks |= LOST;
            self.loss.lost += sent.segments;
        }
        self.loss.marked = true;
    }
    /// `tcp_rack_detect_loss`: marks what was sent so long before the
    /// newest delivered that it is lost; whether some may yet be found so.
    /// What one call sends goes at one time, and what another sent before
    /// it went earlier than the reordering window, which is a part of a
    /// loopback's short round trip.
    fn rack(&mut self) -> bool {
        if !core::mem::take(&mut self.loss.advanced) {
            return false;
        }
        self.detect()
    }
    fn detect(&mut self) -> bool {
        let (at, burst, end) = self.loss.newest;
        let window = self.loss.reordered > 0
            || (self.loss.state < State::Recovery && self.count(SACKED) < self.loss.reordering);
        let mut may = false;
        for i in 0..self.in_flight.len() {
            let sent = self.in_flight[i];
            let known = sent.marks & LOST != 0 && sent.marks & AGAIN == 0;
            if known
                || sent.marks & SACKED != 0
                || (sent.at, sent.burst, sent.end) >= (at, burst, end)
            {
                continue;
            }
            if window && sent.burst == burst {
                may = true;
            } else {
                self.mark_lost(i);
            }
        }
        may
    }
    /// `tcp_identify_packet_loss`.
    fn identify(&mut self, now: u64, flags: &mut Flags) {
        if self.in_flight.is_empty() {
            return;
        }
        let prior = self.count(AGAIN);
        if self.rack() {
            self.timer = Some((Timer::Reorder, now + super::PROBE_MARGIN + MS));
            flags.set_timer = false;
        }
        flags.lost_again |= prior > self.count(AGAIN);
    }
    /// `tcp_process_loss`.
    fn process_loss(&mut self, flags: &Flags, duplicate: bool, echo: u64) -> Resend {
        let recovered = self.una >= self.loss.high;
        if flags.advanced && self.undo_loss(false, echo) {
            return Resend::None;
        }
        if self.loss.frto {
            if flags.original && self.undo_loss(true, echo) {
                return Resend::None;
            }
            if self.next > self.loss.high {
                if flags.sacked || duplicate {
                    self.loss.frto = false;
                }
            } else if flags.advanced && !recovered {
                self.loss.high = self.next;
                if self.written > self.next && self.window() > 0 {
                    return Resend::New;
                }
                self.loss.frto = false;
            }
        }
        if recovered {
            self.recovered(echo);
            return Resend::None;
        }
        Resend::Lost
    }
    /// `tcp_fastretrans_alert`.
    fn alert(
        &mut self,
        prior: u64,
        duplicate: bool,
        now: u64,
        echo: u64,
        flags: &mut Flags,
    ) -> Resend {
        if self.loss.state == State::Open {
            self.loss.stamp = None;
        } else if self.una >= self.loss.high {
            match self.loss.state {
                State::Reduced if self.una != self.loss.high => {
                    self.end_reduction();
                    self.loss.state = State::Open;
                }
                State::Recovery => {
                    self.recovered(echo);
                    self.end_reduction();
                }
                _ => {}
            }
        }
        match self.loss.state {
            State::Recovery => {
                if flags.advanced && self.loss.undo.is_some() && self.delayed(echo) {
                    // `tcp_try_undo_partial`.
                    self.reordered(prior);
                    if self.count(AGAIN) > 0 {
                        return Resend::None;
                    }
                    if !self.any_resent() {
                        self.loss.stamp = None;
                    }
                    self.undo(true);
                    self.keep_open();
                }
                if self.undo_by_dsack() {
                    self.try_open();
                }
                self.identify(now, flags);
                if self.loss.state != State::Recovery {
                    if self.count(LOST) == 0 {
                        return Resend::None;
                    }
                    self.enter_recovery();
                }
                return Resend::Lost;
            }
            State::Loss => {
                let resend = self.process_loss(flags, duplicate, echo);
                if self.loss.state != State::Loss
                    && let Some(began) = self.loss.began.take()
                {
                    self.loss.timeout_ms += (now / MS).saturating_sub(began) as u32;
                }
                self.identify(now, flags);
                if self.loss.state != State::Open && !flags.lost_again {
                    return resend;
                }
            }
            _ => {}
        }
        if self.loss.state <= State::Disorder {
            self.undo_by_dsack();
        }
        self.identify(now, flags);
        if self.count(LOST) == 0 {
            self.try_open();
            return Resend::None;
        }
        self.enter_recovery();
        Resend::Lost
    }
    /// `tcp_ack` with nothing in flight: a D-SACK may yet undo a reduction.
    pub(super) fn duplicate_acked(
        &mut self,
        (prior, ack, echo): (u64, u64, u64),
        now: u64,
        mut flags: Flags,
    ) -> Resend {
        let mut resend = Resend::None;
        if flags.dsack {
            resend = self.alert(prior, false, now, echo, &mut flags);
        }
        self.probe_acked(ack, &flags);
        resend
    }
    /// Whether new data went past the recovery's end (`tcp_xmit_recovery`);
    /// if not, it is no longer tried.
    pub(super) fn sent_new(&mut self) -> bool {
        let sent = self.next > self.loss.high;
        self.loss.frto &= sent;
        sent
    }
    /// The rest of `tcp_ack`, once the queue is cleaned: what state the
    /// connection is in, its timer and its congestion window. `delivered`
    /// segments came newly.
    pub(super) fn after_ack(
        &mut self,
        (prior, ack, echo): (u64, u64, u64),
        (delivered, lost): (u32, u32),
        now: u64,
        mut flags: Flags,
    ) -> Resend {
        self.probe_acked(ack, &flags);
        let mut resend = Resend::None;
        if !(flags.advanced || flags.news)
            || flags.sacked
            || flags.dsack
            || self.loss.state != State::Open
        {
            let duplicate = !(flags.advanced || flags.news || flags.dsack);
            resend = self.alert(prior, duplicate, now, echo, &mut flags);
        }
        if flags.set_timer {
            self.set_timer(now);
        }
        self.paced(delivered, self.loss.lost - lost, &flags);
        resend
    }
    /// `tcp_cong_control`.
    fn paced(&mut self, delivered: u32, lost: u32, flags: &Flags) {
        if matches!(self.loss.state, State::Reduced | State::Recovery) {
            if delivered > 0 {
                self.reduction(delivered, lost, flags);
            }
        } else if flags.acked {
            self.grow(delivered);
        }
    }
    /// `tcp_cwnd_reduction`.
    fn reduction(&mut self, delivered: u32, lost: u32, flags: &Flags) {
        let out = self.on_the_way();
        self.loss.prr_delivered += delivered;
        let (ssthresh, so_far) = (i64::from(self.loss.ssthresh), i64::from(self.loss.prr_out));
        let total = i64::from(self.loss.prr_delivered);
        let delta = ssthresh - i64::from(out);
        let mut count = if delta < 0 {
            let prior = i64::from(self.loss.prior_cwnd.max(1));
            (ssthresh * total + prior - 1) / prior - so_far
        } else {
            let mut count = (total - so_far).max(i64::from(delivered));
            if flags.advanced && lost == 0 {
                count += 1;
            }
            count.min(delta)
        };
        count = count.max(i64::from(so_far == 0));
        self.cwnd = out + count.max(0) as u32;
    }
    /// `tcp_is_cwnd_limited`, then slow start, and past the threshold a
    /// segment a window, as cubic's does at least.
    fn grow(&mut self, delivered: u32) {
        let slow = self.cwnd < self.loss.ssthresh;
        if !self.cwnd_limited && !(slow && self.cwnd < 2 * self.most_out) {
            return;
        }
        let mut left = delivered;
        if slow {
            let room = self.loss.ssthresh - self.cwnd;
            let step = left.min(room);
            self.cwnd += step;
            left -= step;
        }
        if left > 0 {
            self.loss.grown += left;
            if self.loss.grown >= self.cwnd {
                self.loss.grown -= self.cwnd;
                self.cwnd += 1;
            }
        }
    }
    /// `tcp_cwnd_validate`, after a transmission that stopped at the
    /// window if `limited`.
    pub(super) fn validate(&mut self, limited: bool) {
        let out = self.packets_out();
        if self.una >= self.used || limited || (!self.cwnd_limited && out > self.most_out) {
            self.cwnd_limited = limited;
            self.most_out = out;
            self.used = self.next;
        }
    }
    /// `tcp_model_timeout` of `boundary` retransmissions, in milliseconds.
    fn model(boundary: u32) -> u64 {
        let linear = (RTO_MAX / RTO_MIN).ilog2();
        let ticks = ((2 << boundary.min(linear)) - 1) * RTO_MIN
            + u64::from(boundary.saturating_sub(linear)) * RTO_MAX;
        ticks / MS
    }
    /// `tcp_write_timeout`: whether the connection has been waiting for an
    /// acknowledgement too long.
    pub(super) fn expired(&self, now: u64) -> bool {
        let (Some(stamp), true) = (self.loss.stamp, self.loss.retransmits > 0) else {
            return false;
        };
        let limit = if self.user_timeout > 0 {
            u64::from(self.user_timeout)
        } else if self.closed && self.loss.rto < RTO_MAX {
            Self::model(ORPHAN_RETRIES)
        } else if self.closed {
            return true;
        } else {
            Self::model(RETRIES)
        };
        now / MS >= stamp + limit
    }
    /// `tcp_enter_loss`, and `tcp_update_rto_stats`.
    pub(super) fn enter_loss(&mut self, now: u64) {
        let new = self.loss.state < State::Recovery;
        // `tcp_timeout_mark_lost`.
        let head = self
            .in_flight
            .front()
            .is_some_and(|head| head.marks & SACKED != 0);
        for at in 0..self.in_flight.len() {
            if head {
                self.in_flight[at].marks &= !SACKED;
            } else if at > 0 {
                // What was sent within a round trip may be on its way.
                let sent = self.in_flight[at];
                if sent.at + SRTT / 8 > now {
                    continue;
                }
            }
            self.mark_lost(at);
        }
        if self.loss.state <= State::Disorder
            || self.loss.high <= self.una
            || (self.loss.state == State::Loss && self.loss.retransmits == 0)
        {
            self.loss.prior_ssthresh = self.current_threshold();
            self.loss.prior_cwnd = self.cwnd;
            self.loss.ssthresh = self.threshold();
            self.may_be_undone();
        }
        self.cwnd = self.on_the_way() + 1;
        self.loss.grown = 0;
        if self.loss.state <= State::Disorder && self.count(SACKED) >= REORDERING {
            self.loss.reordering = self.loss.reordering.min(REORDERING);
        }
        self.loss.state = State::Loss;
        self.loss.high = self.next;
        self.probe = None;
        self.loss.frto = new || self.loss.retransmits > 0;
        if self.loss.retransmits == 0 {
            self.loss.recoveries += 1;
            self.loss.began = Some(now / MS);
        }
        self.loss.retransmits = self.loss.retransmits.saturating_add(1);
        self.loss.timeouts += 1;
    }
    /// After the timeout's retransmission: the next one waits twice as
    /// long, but no longer than `TCP_USER_TIMEOUT` leaves.
    pub(super) fn back_off(&mut self, now: u64) {
        self.loss.backoff = self.loss.backoff.saturating_add(1);
        self.loss.rto = (self.loss.rto * 2).min(RTO_MAX);
        let mut wait = self.loss.rto;
        if self.user_timeout > 0 {
            let elapsed = (now / MS).saturating_sub(self.loss.stamp.unwrap_or(now / MS));
            let left = u64::from(self.user_timeout).saturating_sub(elapsed);
            wait = wait.min((left * MS).max(MS));
        }
        self.timer = Some((Timer::Resend, now + wait));
    }
    /// `tcp_rack_reo_timeout`: whether what was lost is to be sent again.
    pub(super) fn reorder_timeout(&mut self) -> bool {
        let prior = self.on_the_way();
        let lost = self.loss.lost;
        // The window has passed.
        self.loss.newest.1 += 1;
        self.detect();
        if prior == self.on_the_way() {
            return false;
        }
        if self.loss.state != State::Recovery {
            self.enter_recovery();
            let lost = self.loss.lost - lost;
            self.reduction(1, lost, &Flags::default());
        }
        true
    }
    /// The next segment to send again, at `from` or after, and how many
    /// segments of it the window lets go (`tcp_xmit_retransmit_queue`).
    pub(super) fn next_lost(&self, from: usize) -> Option<(usize, u32)> {
        let (_, lost, again) = self.left();
        let room = self.cwnd.saturating_sub(self.on_the_way());
        if room == 0 || again >= lost {
            return None;
        }
        let mut sent = self.in_flight.iter().enumerate().skip(from);
        let (at, _) =
            sent.find(|(_, sent)| sent.marks & LOST != 0 && sent.marks & (SACKED | AGAIN) == 0)?;
        Some((at, room))
    }
    /// What was marked sent again: `prr_out`, for recovery.
    pub(super) fn recovering(&mut self, segments: u32) {
        if matches!(self.loss.state, State::Reduced | State::Recovery) {
            self.loss.prr_out += segments;
        }
    }
    /// `tcp_retransmit_skb`'s marks of the segment at `at`.
    pub(super) fn resent(&mut self, at: usize) {
        let sent = &mut self.in_flight[at];
        sent.marks |= AGAIN;
        let (segments, went) = (sent.segments, sent.at);
        self.loss.marked = true;
        self.loss.stamp.get_or_insert(went / MS);
        self.loss.undo_resent = self.loss.undo_resent.max(0) + segments as i32;
    }
}
