//! Segments that a filter drops or cuts, with the numbers a native Linux
//! 7.0.14 gave for the same writes, reads and filters.

use super::{Counts, Flows, MS, Push, Request, Segment, Tap, Verdict};
use std::sync::{Arc, Mutex};

type Rule = fn(&Segment<'_>) -> Option<u32>;

/// A filter that can be set and lifted.
struct Filter(Mutex<Option<Rule>>);
impl Tap for Filter {
    fn keep(&self, segment: &Segment<'_>) -> Option<u32> {
        self.0
            .lock()
            .unwrap()
            .map_or(Some(segment.len), |rule| rule(segment))
    }
}

const DROP_DATA: Rule = |s| (s.len == 0).then_some(0);
const DROP_FIRST: Rule = |s| (s.len == 0 || s.start >= 100).then_some(s.len);
const CUT: Rule = |s| Some(s.len.min(10));
const DROP_ACKS: Rule = |s| (s.len > 0 || s.fin).then_some(s.len);
const DROP_END: Rule = |s| (!s.fin).then_some(s.len);
const DROP_RESET: Rule = |s| (!s.reset).then_some(s.len);
const DROP_ALL: Rule = |_| None;

struct Run {
    flows: Flows,
    filters: [Arc<Filter>; 2],
    now: u64,
}

impl Run {
    fn new() -> Self {
        let mut flows = Flows::new(65_483, Some(1_000_000));
        let filters = [0, 1].map(|_| Arc::new(Filter(Mutex::new(None))));
        for (side, filter) in filters.iter().enumerate() {
            flows.tap(side, Some(Arc::clone(filter) as Arc<dyn Tap>), 1_000_000);
        }
        let push = Push {
            no_delay: true,
            ..Push::default()
        };
        flows.sending(0, push);
        Self {
            flows,
            filters,
            now: 1_060_000,
        }
    }
    fn filter(&self, side: usize, rule: Option<Rule>) {
        *self.filters[side].0.lock().unwrap() = rule;
    }
    fn write(&mut self, len: u64) {
        self.now += 20;
        self.flows.write(0, len, false, self.now);
        self.take();
    }
    /// Moves what has come to the server; how much, and when the last came.
    fn take(&mut self) -> (u64, u64) {
        let mut all = (0, 0);
        while let Some((len, at)) = self.flows.arrival(1) {
            all = (all.0 + len, at.saturating_sub(1_060_000) / MS);
        }
        all
    }
    /// Until `ms` after the start: what came then, and when.
    fn until(&mut self, ms: u64) -> (u64, u64) {
        self.now = 1_060_000 + ms * MS;
        self.flows.advance(self.now);
        self.take()
    }
    fn read(&mut self, len: u64) {
        self.flows.read(1, len, self.now);
    }
    fn counts(&mut self, side: usize) -> Counts {
        self.flows.counts(side, self.now)
    }
    /// ca, retransmits, backoff, unacked, sacked, lost, retrans, cwnd,
    /// ssthresh, total_retrans, segs_out, segs_in, data_segs_out, delivered,
    /// dsacks, bytes acked, sent and resent, timeouts.
    fn sender(&mut self) -> [u64; 19] {
        let c = self.counts(0);
        [
            c.state.into(),
            c.retransmits.into(),
            c.backoff.into(),
            c.unacked.into(),
            c.left.0.into(),
            c.left.1.into(),
            c.left.2.into(),
            c.cwnd.into(),
            c.ssthresh.into(),
            c.retransmitted.into(),
            c.segs_out.into(),
            c.segs_in.into(),
            c.data_segs_out.into(),
            c.delivered.into(),
            c.dsacks.into(),
            c.acked,
            c.sent,
            c.resent,
            c.timeouts.into(),
        ]
    }
    /// segs_out, segs_in, data_segs_in, segments out of order, bytes.
    fn receiver(&mut self) -> [u64; 5] {
        let c = self.counts(1);
        [
            c.segs_out.into(),
            c.segs_in.into(),
            c.data_segs_in.into(),
            c.disordered.into(),
            c.received,
        ]
    }
}
const INF: u64 = 0x7fff_ffff;

#[test]
fn a_segment_dropped_again_and_again_backs_off() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_DATA));
    r.write(100);
    r.until(100);
    assert_eq!(
        r.sender(),
        [0, 0, 0, 1, 0, 0, 0, 10, INF, 0, 3, 1, 1, 1, 0, 0, 100, 0, 0]
    );
    assert_eq!(r.receiver(), [0, 2, 0, 0, 0]);
    r.until(303);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 1, 0, 0, 0, 10, INF, 1, 4, 1, 2, 1, 0, 0, 200, 100, 0
        ]
    );
    r.until(903);
    assert_eq!(
        r.sender(),
        [4, 2, 2, 1, 0, 1, 1, 1, 7, 3, 6, 1, 4, 1, 0, 0, 400, 300, 2]
    );
    r.filter(1, None);
    let (len, at) = r.until(1910);
    assert_eq!((len, (1600..1640).contains(&at)), (100, true), "{at}");
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 4, 7, 2, 5, 2, 0, 100, 500, 400, 3
        ]
    );
    assert_eq!(r.receiver(), [1, 3, 1, 0, 100]);
    r.read(100);
    r.write(10);
    r.until(1970);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 4, 8, 3, 6, 3, 0, 110, 510, 400, 3
        ]
    );
}

#[test]
fn two_dropped_are_sent_again_as_one() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_DATA));
    r.write(100);
    r.write(100);
    r.until(1);
    assert_eq!(
        r.sender(),
        [0, 0, 0, 2, 0, 0, 0, 10, INF, 0, 4, 1, 2, 1, 0, 0, 200, 0, 0]
    );
    r.until(29);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 2, 0, 0, 0, 10, INF, 1, 5, 1, 3, 1, 0, 0, 300, 100, 0
        ]
    );
    r.filter(1, None);
    let (len, at) = r.until(512);
    assert_eq!((len, (201..210).contains(&at)), (200, true), "{at}");
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 2, 6, 2, 4, 2, 0, 200, 500, 300, 1
        ]
    );
    assert_eq!(r.receiver(), [1, 3, 1, 0, 200]);
}

#[test]
fn a_gap_is_found_by_what_came_after() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_FIRST));
    for _ in 0..5 {
        r.write(100);
    }
    assert_eq!(
        r.sender(),
        [3, 0, 0, 2, 1, 1, 1, 1, 7, 1, 5, 2, 3, 2, 0, 0, 300, 100, 0]
    );
    assert_eq!(r.receiver(), [1, 3, 1, 1, 0]);
    r.until(50);
    assert_eq!(
        r.sender(),
        [3, 0, 0, 2, 1, 1, 1, 1, 7, 1, 5, 2, 3, 2, 0, 0, 300, 100, 0]
    );
    r.until(307);
    assert_eq!(
        r.sender(),
        [4, 1, 1, 2, 1, 1, 1, 1, 7, 2, 6, 2, 4, 2, 0, 0, 400, 200, 1]
    );
    r.until(913);
    assert_eq!(
        r.sender(),
        [4, 2, 2, 2, 1, 1, 1, 1, 7, 3, 7, 2, 5, 2, 0, 0, 500, 300, 2]
    );
    r.filter(1, None);
    let (len, at) = r.until(2123);
    assert_eq!((len, (1405..1425).contains(&at)), (500, true), "{at}");
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 4, 9, 4, 7, 4, 0, 500, 900, 400, 3
        ]
    );
    assert_eq!(r.receiver(), [3, 5, 3, 1, 500]);
}

#[test]
fn a_gap_is_filled_at_the_timeout() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_FIRST));
    r.write(100);
    r.write(100);
    r.filter(1, None);
    r.until(20);
    assert_eq!(
        r.sender(),
        [3, 0, 0, 2, 1, 1, 1, 1, 7, 1, 5, 2, 3, 2, 0, 0, 300, 100, 0]
    );
    let (len, _) = r.until(324);
    assert_eq!(len, 200);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 2, 6, 3, 4, 3, 0, 200, 400, 200, 1
        ]
    );
    assert_eq!(r.receiver(), [2, 4, 2, 1, 200]);
}

#[test]
fn a_segment_cut_is_acknowledged_so_far() {
    let mut r = Run::new();
    r.filter(1, Some(CUT));
    r.write(100);
    r.read(10);
    r.until(100);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 1, 0, 0, 0, 10, INF, 0, 3, 2, 1, 1, 0, 10, 100, 0, 0
        ]
    );
    assert_eq!(r.receiver(), [1, 3, 1, 0, 10]);
    assert_eq!(r.until(310).0, 10);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 1, 0, 0, 0, 10, INF, 1, 4, 3, 2, 1, 0, 20, 190, 90, 0
        ]
    );
    r.read(10);
    assert_eq!(r.until(1021).0, 20);
    assert_eq!(
        r.sender(),
        [4, 0, 2, 1, 0, 1, 1, 1, 2, 3, 6, 5, 4, 1, 0, 40, 340, 240, 2]
    );
    assert_eq!(r.counts(0).recoveries, 2);
    r.read(20);
    r.filter(1, None);
    assert_eq!(r.until(3024).0, 60);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 2, 4, 7, 6, 5, 2, 0, 100, 400, 300, 3
        ]
    );
    assert_eq!(r.receiver(), [5, 7, 5, 0, 100]);
}

#[test]
fn two_cut_leave_a_piece_ahead() {
    let mut r = Run::new();
    r.filter(1, Some(CUT));
    r.write(100);
    r.write(100);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 2, 0, 0, 0, 10, INF, 0, 4, 3, 2, 1, 0, 10, 200, 0, 0
        ]
    );
    assert_eq!(r.receiver(), [2, 4, 2, 1, 10]);
    r.read(10);
    r.until(53);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 2, 0, 0, 0, 10, INF, 1, 5, 4, 3, 2, 1, 10, 300, 100, 0
        ]
    );
    r.filter(1, None);
    let (len, at) = r.until(463);
    assert_eq!((len, (200..212).contains(&at)), (190, true), "{at}");
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 3, 7, 2, 6, 5, 4, 4, 2, 200, 490, 290, 1
        ]
    );
    assert_eq!(r.receiver(), [4, 6, 4, 2, 200]);
}

#[test]
fn an_acknowledgement_dropped_leaves_data_sent_again() {
    let mut r = Run::new();
    r.filter(0, Some(DROP_ACKS));
    r.write(100);
    r.read(100);
    r.until(311);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 1, 0, 0, 0, 10, INF, 1, 4, 1, 2, 1, 0, 0, 200, 100, 0
        ]
    );
    assert_eq!(r.receiver(), [2, 4, 2, 0, 100]);
    r.until(521);
    assert_eq!(
        r.sender(),
        [4, 1, 1, 1, 0, 1, 1, 1, 7, 2, 5, 1, 3, 1, 0, 0, 300, 200, 1]
    );
    r.filter(0, None);
    r.until(1223);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 3, 7, 3, 6, 2, 4, 3, 1, 100, 400, 300, 2
        ]
    );
}

#[test]
fn a_timeout_for_nothing_is_undone() {
    let mut r = Run::new();
    r.filter(0, Some(DROP_ACKS));
    for _ in 0..3 {
        r.write(100);
    }
    r.until(58);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 3, 0, 0, 0, 10, INF, 1, 6, 1, 4, 1, 0, 0, 400, 100, 0
        ]
    );
    r.filter(0, None);
    r.until(760);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 10, INF, 2, 7, 2, 5, 5, 1, 300, 500, 200, 1
        ]
    );
}

#[test]
fn an_end_dropped_comes_later() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_END));
    r.flows.end(0, r.now);
    r.until(311);
    assert_eq!(
        r.sender(),
        [0, 0, 0, 1, 0, 0, 0, 10, INF, 1, 4, 1, 0, 1, 0, 0, 0, 0, 0]
    );
    assert_eq!(r.flows.ended(1), None);
    r.filter(1, None);
    r.until(1021);
    assert!(r.flows.ended(1).is_some());
    assert_eq!(
        r.sender(),
        [0, 0, 0, 0, 0, 0, 0, 2, 7, 2, 5, 2, 0, 2, 0, 0, 0, 0, 1]
    );
}

#[test]
fn an_end_on_a_segment_cut_comes_with_what_is_kept() {
    let mut r = Run::new();
    r.filter(1, Some(CUT));
    r.flows.sending(
        0,
        Push {
            more: true,
            ..Push::default()
        },
    );
    r.write(30);
    r.flows.end(0, r.now);
    assert_eq!(r.take().0, 10);
    assert!(r.flows.ended(1).is_some());
    assert_eq!(r.receiver(), [0, 3, 1, 0, 10]);
    r.read(10);
    r.until(310);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 1, 0, 0, 0, 10, INF, 1, 4, 2, 2, 1, 0, 11, 49, 19, 0
        ]
    );
    assert_eq!(r.receiver(), [1, 4, 2, 0, 10]);
    r.until(1220);
    assert_eq!(
        r.sender(),
        [4, 2, 2, 1, 0, 1, 1, 1, 7, 3, 6, 2, 4, 1, 0, 11, 87, 57, 2]
    );
    assert_eq!(r.receiver(), [1, 6, 4, 0, 10]);
}

#[test]
fn a_reset_dropped_is_sent_again_for_each_segment() {
    let mut r = Run::new();
    r.filter(0, Some(DROP_RESET));
    r.write(5);
    assert!(!r.flows.reset(1, r.now));
    r.until(10);
    r.write(5);
    assert_eq!(r.flows.verdict(0), None);
    r.until(330);
    assert_eq!(r.flows.verdict(0), None);
    r.filter(0, None);
    r.until(1020);
    assert_eq!(r.flows.verdict(0), Some(Verdict::Reset));
}

#[test]
fn a_user_timeout_ends_the_connection() {
    let mut r = Run::new();
    r.flows.set_user_timeout(0, 500, r.now);
    r.filter(1, Some(DROP_ALL));
    r.write(100);
    r.until(890);
    assert_eq!(r.flows.verdict(0), None);
    r.until(960);
    assert_eq!(r.flows.verdict(0), Some(Verdict::TimedOut));
    assert!(r.flows.due().is_none());
}

#[test]
fn a_windowful_dropped_is_sent_again_as_one() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_DATA));
    for _ in 0..10 {
        r.write(100);
    }
    r.until(100);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 10, 0, 0, 0, 10, INF, 1, 13, 1, 11, 1, 0, 0, 1100, 100, 0
        ]
    );
    r.filter(1, None);
    assert_eq!(r.until(401).0, 1000);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 2, 7, 2, 14, 2, 12, 2, 0, 1000, 2100, 1100, 1
        ]
    );
}

#[test]
fn large_segments_dropped_are_sent_again_one_by_one() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_DATA));
    r.write(60_000);
    r.until(100);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 2, 0, 0, 0, 10, INF, 1, 5, 1, 3, 1, 0, 0, 87_259, 27_259, 0
        ]
    );
    r.filter(1, None);
    assert_eq!(r.until(411).0, 60_000);
    assert_eq!(
        r.sender(),
        [
            0, 0, 0, 0, 0, 0, 0, 3, 7, 3, 7, 3, 5, 3, 0, 60_000, 147_259, 87_259, 1
        ]
    );
    assert_eq!(r.receiver(), [2, 4, 2, 0, 60_000]);
}

/// Drops what acknowledges and no more.
const DROP_BARE: Rule = |s| (s.len > 0 || s.fin || s.syn || s.reset).then_some(s.len);

#[test]
fn a_request_waits_for_an_acknowledgement() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_BARE));
    r.flows.handshake(r.now);
    assert!(matches!(r.flows.request(), Request::Waits { tries: 0, .. }));
    // Its SYN-ACK goes again after 1 and 3 seconds, and the client answers.
    r.until(1_500);
    assert_eq!(r.sender()[10..12], [3, 2]);
    r.filter(1, None);
    r.until(3_500);
    assert_eq!(r.flows.request(), Request::Opened);
    assert_eq!(r.sender()[10..12], [4, 3]);
    assert_eq!(r.receiver(), [0, 2, 0, 0, 0]);
    assert_eq!(r.counts(1).retransmitted, 2);
}

#[test]
fn data_opens_a_request() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_BARE));
    r.flows.handshake(r.now);
    r.write(5);
    assert_eq!(r.flows.request(), Request::Opened);
    assert_eq!(r.receiver(), [1, 2, 1, 0, 5]);
}

#[test]
fn a_request_is_dropped_by_a_reset_or_in_time() {
    let mut r = Run::new();
    r.filter(1, Some(DROP_BARE));
    r.flows.handshake(r.now);
    assert!(r.flows.reset(0, r.now));
    assert_eq!(r.flows.request(), Request::Dropped);

    let mut r = Run::new();
    r.filter(1, Some(DROP_BARE));
    r.flows.handshake(r.now);
    // 1 + 2 + 4 + 8 + 16 + 32 seconds.
    r.until(62_900);
    assert!(matches!(r.flows.request(), Request::Waits { tries: 5, .. }));
    r.until(63_100);
    assert_eq!(r.flows.request(), Request::Dropped);
    // What comes then is answered with a reset.
    r.write(5);
    assert_eq!(r.flows.verdict(0), Some(Verdict::Reset));
}
