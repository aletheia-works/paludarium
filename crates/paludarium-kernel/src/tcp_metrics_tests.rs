use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

fn ended(srtt: u64, cwnd: u32, ssthresh: u32) -> Ended {
    Ended {
        srtt,
        mdev: 800,
        backoff: 0,
        cwnd,
        ssthresh,
        open: true,
        reordering: REORDERING,
    }
}

fn entry(metrics: &Metrics, local: IpAddr, remote: IpAddr) -> Option<Entry> {
    metrics
        .entries
        .lock()
        .unwrap()
        .get(&(local, remote))
        .copied()
}

#[test]
fn nothing_kept_starts_as_linux() {
    let metrics = Metrics::default();
    assert_eq!(metrics.start((A, B), 240, 0), Start::default());
}

#[test]
fn slow_start_keeps_the_window_not_the_threshold() {
    let metrics = Metrics::default();
    metrics.update((A, B), ended(240, 10, SSTHRESH), 5);
    let kept = entry(&metrics, A, B).unwrap();
    assert_eq!(
        (kept.rtt, kept.rttvar, kept.ssthresh, kept.cwnd),
        (240, 800, 0, 10)
    );
    assert_eq!(kept.stamp, 5);
    assert_eq!(metrics.start((A, B), 240, 6), Start::default());
    // Only the side that ended keeps it.
    assert_eq!(entry(&metrics, B, A), None);
}

#[test]
fn congestion_avoidance_keeps_its_threshold() {
    let metrics = Metrics::default();
    metrics.update((A, B), ended(240, 12, 7), 0);
    let kept = entry(&metrics, A, B).unwrap();
    // max(12 / 2, 7), and the mean of 0 and 12.
    assert_eq!((kept.ssthresh, kept.cwnd), (7, 6));
    let start = metrics.start((A, B), 240, 1);
    assert_eq!(start.ssthresh, Some(7));
    assert_eq!(start.reordering, None);
}

#[test]
fn recovery_keeps_reordering_and_a_higher_threshold() {
    let metrics = Metrics::default();
    metrics.update((A, B), ended(240, 12, 7), 0);
    metrics.update(
        (A, B),
        Ended {
            open: false,
            reordering: 5,
            ..ended(240, 4, 9)
        },
        1,
    );
    let kept = entry(&metrics, A, B).unwrap();
    // (6 + 9) / 2; 9 is above 7; 5 is not the sysctl's 3.
    assert_eq!((kept.cwnd, kept.ssthresh, kept.reordering), (7, 9, 5));
    assert_eq!(metrics.start((A, B), 240, 2).reordering, Some(5));
}

#[test]
fn the_round_trip_rises_at_once_and_falls_slowly() {
    let metrics = Metrics::default();
    metrics.update((A, B), ended(8000, 10, SSTHRESH), 0);
    metrics.update((A, B), ended(80_000, 10, SSTHRESH), 0);
    assert_eq!(entry(&metrics, A, B).unwrap().rtt, 80_000);
    // m = 80000 - 16000 = 64000: an eighth of it, 8000, comes off.
    metrics.update((A, B), ended(16_000, 10, SSTHRESH), 0);
    let kept = entry(&metrics, A, B).unwrap();
    assert_eq!(kept.rtt, 72_000);
    // m / 2 = 32000 is under the 36000 kept: a quarter of the gap comes off.
    assert_eq!(kept.rttvar, 35_000);
}

#[test]
fn a_longer_round_trip_sets_the_first_timeout() {
    let metrics = Metrics::default();
    // 1.6 s, 8 times over: 1600 jiffies, then 1600 + 3200.
    metrics.update((A, B), ended(12_800_000, 10, SSTHRESH), 0);
    assert_eq!(metrics.start((A, B), 240, 0).rto, Some(4_800_000));
    // Under a jiffy, the minimum alone.
    metrics.update((B, A), ended(7999, 10, SSTHRESH), 0);
    assert_eq!(metrics.start((B, A), 240, 0).rto, Some(RTO_MIN));
    // Not longer than the handshake's own.
    assert_eq!(metrics.start((B, A), 7999, 0).rto, None);
}

#[test]
fn a_backoff_forgets_the_round_trip_only() {
    let metrics = Metrics::default();
    let failed = Ended {
        backoff: 1,
        ..ended(240, 10, 5)
    };
    metrics.update((A, B), failed, 0);
    assert_eq!(entry(&metrics, A, B), None);
    metrics.update((A, B), ended(240, 12, 7), 0);
    metrics.update((A, B), failed, 1);
    let kept = entry(&metrics, A, B).unwrap();
    assert_eq!((kept.rtt, kept.ssthresh, kept.stamp), (0, 7, 0));
    let no_rtt = Ended {
        srtt: 0,
        ..ended(240, 10, 5)
    };
    metrics.update((B, A), no_rtt, 0);
    assert_eq!(entry(&metrics, B, A), None);
}

#[test]
fn an_hour_old_entry_starts_over() {
    let metrics = Metrics::default();
    metrics.update((A, B), ended(240, 12, 7), 0);
    assert_eq!(metrics.start((A, B), 240, TIMEOUT).ssthresh, Some(7));
    assert_eq!(metrics.start((A, B), 240, TIMEOUT + 1), Start::default());
    assert_eq!(entry(&metrics, A, B).unwrap().stamp, TIMEOUT + 1);
}

#[test]
fn a_mapped_peer_is_kept_as_ipv4() {
    let metrics = Metrics::default();
    let mapped = |ip: Ipv4Addr| IpAddr::V6(ip.to_ipv6_mapped());
    metrics.update(
        (
            mapped(Ipv4Addr::new(127, 0, 0, 1)),
            mapped(Ipv4Addr::new(127, 0, 0, 2)),
        ),
        ended(240, 12, 7),
        0,
    );
    assert_eq!(metrics.start((A, B), 240, 0).ssthresh, Some(7));
    let six = IpAddr::V6(Ipv6Addr::LOCALHOST);
    metrics.update((six, six), ended(240, 12, 8), 0);
    assert_eq!(metrics.start((six, six), 240, 0).ssthresh, Some(8));
}
