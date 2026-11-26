//! What a network namespace keeps of its finished TCP connections, as
//! Linux 7.0's `tcp_metrics.c` keeps it: for each pair of a local and a
//! remote address, the round trip, its variation, the slow-start threshold,
//! the congestion window and the reordering a connection between them ended
//! with (`tcp_update_metrics`), which the next one starts from
//! (`tcp_init_metrics`). Master has the same rules, but for clamping the
//! window it takes to `TCP_MAX_SND_CWND` and adding nothing to a namespace
//! that is going.
//!
//! Linux's table holds at most five entries in each of its buckets and
//! reuses the oldest of them; this one has no bound. There are no route
//! metrics to lock a value, nor netlink's `TCP_METRICS` family, nor the
//! `tcp_no_metrics_save` and `tcp_no_ssthresh_metrics_save` switches, nor
//! `tcp_peer_is_proven`'s check of a peer when the SYN queue is nearly
//! full, nor Fast Open cookies.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

/// `TCP_INFINITE_SSTHRESH` and `sysctl_tcp_reordering`.
const SSTHRESH: u32 = 0x7fff_ffff;
const REORDERING: u32 = 3;
/// `TCP_METRICS_TIMEOUT`: an entry not changed for an hour starts over when
/// it is looked up (`tcpm_check_stamp`), in microseconds.
const TIMEOUT: u64 = 3_600_000_000;
/// `TCP_RTO_MIN` and a jiffy (`HZ` of 1000), in microseconds.
const RTO_MIN: u64 = 200_000;
const JIFFY: u64 = 1000;

/// What one pair of addresses keeps: the round trip as `srtt_us` holds it
/// (8 times over), its variation as `mdev_us` does (4 times over), and
/// when it last changed. 0 is none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Entry {
    rtt: u64,
    rttvar: u64,
    ssthresh: u32,
    cwnd: u32,
    reordering: u32,
    stamp: u64,
}

/// What a side of a connection ended with, as `tcp_update_metrics` reads
/// it: `srtt_us` and `mdev_us`, `icsk_backoff`, the window and threshold,
/// whether its congestion state is `TCP_CA_Open`, and its reordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ended {
    pub(crate) srtt: u64,
    pub(crate) mdev: u64,
    pub(crate) backoff: u8,
    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,
    pub(crate) open: bool,
    pub(crate) reordering: u32,
}

/// What a new connection takes (`tcp_init_metrics`): its threshold and
/// reordering, and its first retransmission timeout in microseconds when
/// the round trip kept is longer than its own, `srtt`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Start {
    pub(crate) ssthresh: Option<u32>,
    pub(crate) reordering: Option<u32>,
    pub(crate) rto: Option<u64>,
}

/// A network namespace's entries.
#[derive(Debug, Default)]
pub(crate) struct Metrics {
    entries: Mutex<HashMap<(IpAddr, IpAddr), Entry>>,
}

/// The key of `local` and `remote`: an IPv4-mapped peer is kept as IPv4
/// (`tcp_get_metrics`).
fn key(local: IpAddr, remote: IpAddr) -> (IpAddr, IpAddr) {
    match (local, remote) {
        (IpAddr::V6(l), IpAddr::V6(r)) => match (l.to_ipv4_mapped(), r.to_ipv4_mapped()) {
            (Some(l), Some(r)) => (IpAddr::V4(l), IpAddr::V4(r)),
            _ => (local, remote),
        },
        _ => (local, remote),
    }
}

impl Entry {
    /// `tcpm_check_stamp` and `tcpm_suck_dst`: one an hour old starts over
    /// `now`, as one with no route metrics is made.
    fn check(&mut self, now: u64) {
        if now > self.stamp.saturating_add(TIMEOUT) {
            *self = Self {
                stamp: now,
                ..Self::default()
            };
        }
    }
}

impl Metrics {
    /// `tcp_update_metrics` of a side from `local` to `remote` that ended
    /// as `ended` `now`, as it enters `TIME_WAIT` or `LAST_ACK` ends.
    pub(crate) fn update(&self, (local, remote): (IpAddr, IpAddr), ended: Ended, now: u64) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let key = key(local, remote);
        if ended.backoff > 0 || ended.srtt == 0 {
            // It failed to measure a round trip: what was kept goes.
            if let Some(entry) = entries.get_mut(&key) {
                entry.check(now);
                entry.rtt = 0;
            }
            return;
        }
        let entry = entries.entry(key).or_insert(Entry {
            stamp: now,
            ..Entry::default()
        });
        entry.check(now);
        // Longer is taken whole, shorter moves an eighth of the way.
        let m = entry.rtt.cast_signed() - ended.srtt.cast_signed();
        entry.rtt = if m <= 0 {
            ended.srtt
        } else {
            entry.rtt - (m >> 3).cast_unsigned()
        };
        let deviation = (m.unsigned_abs() >> 1).max(ended.mdev);
        entry.rttvar = if deviation >= entry.rttvar {
            deviation
        } else {
            entry.rttvar - ((entry.rttvar - deviation) >> 2)
        };
        let half = ended.cwnd >> 1;
        if ended.ssthresh >= SSTHRESH {
            // `tcp_in_initial_slowstart`: slow start has not ended.
            if entry.ssthresh != 0 && half > entry.ssthresh {
                entry.ssthresh = half;
            }
            entry.cwnd = entry.cwnd.max(ended.cwnd);
        } else if ended.cwnd >= ended.ssthresh && ended.open {
            // Congestion avoidance, whose window is to be believed.
            entry.ssthresh = half.max(ended.ssthresh);
            entry.cwnd = ((u64::from(entry.cwnd) + u64::from(ended.cwnd)) >> 1) as u32;
        } else {
            entry.cwnd = ((u64::from(entry.cwnd) + u64::from(ended.ssthresh)) >> 1) as u32;
            if entry.ssthresh != 0 && ended.ssthresh > entry.ssthresh {
                entry.ssthresh = ended.ssthresh;
            }
            if entry.reordering < ended.reordering && ended.reordering != REORDERING {
                entry.reordering = ended.reordering;
            }
        }
        entry.stamp = now;
    }
    /// `tcp_init_metrics` of a side from `local` to `remote` made `now`,
    /// whose handshake measured `srtt` (8 times over).
    pub(crate) fn start(&self, (local, remote): (IpAddr, IpAddr), srtt: u64, now: u64) -> Start {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = entries.get_mut(&key(local, remote)) else {
            return Start::default();
        };
        entry.check(now);
        let rto = (entry.rtt > srtt).then(|| {
            // As `tcp_rtt_estimator` would set it, in whole jiffies.
            let rtt = entry.rtt / (8 * JIFFY) * JIFFY;
            rtt + (2 * rtt).max(RTO_MIN)
        });
        Start {
            ssthresh: (entry.ssthresh != 0).then_some(entry.ssthresh),
            reordering: (entry.reordering != 0).then_some(entry.reordering),
            rto,
        }
    }
}

#[cfg(test)]
#[path = "tcp_metrics_tests.rs"]
mod tests;
