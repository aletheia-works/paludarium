//! `struct tcp_info`, as Linux's `tcp_get_info` fills it for
//! `getsockopt(TCP_INFO)` and `INET_DIAG_INFO`.
//!
//! The guest's loopback carries bytes, not segments, so what Linux's TCP
//! counts of its own (round trips, rates, windows, segments) takes the
//! values Linux gives a loopback connection in the simplest case: the
//! state, options, window scale, listener's queue, congestion window and
//! threshold, reordering, path MTU, advertised MSS, byte counts and bytes
//! waiting are the connection's own.

/// `sizeof(struct tcp_info)`.
pub(crate) const LEN: usize = 280;
/// The MSS the loopback's MTU gives, with timestamps (`advmss`).
pub(crate) const ADVMSS: u32 = 65_483;
/// What a connection sends per segment, as Linux bounds it to half the
/// window its loopback peer first offers (`tcp_bound_to_half_wnd`).
pub(crate) const SND_MSS: u32 = 32_768;
/// `TCP_MSS_DEFAULT`, before anything has come.
const DEFAULT_MSS: u32 = 536;
/// A loopback path's MTU as `icsk_pmtu_cookie` keeps it.
const PMTU: u32 = 65_535;
/// `TCP_INFINITE_SSTHRESH`, `TCP_INIT_CWND` and `sysctl_tcp_reordering`.
const SSTHRESH: u32 = 0x7fff_ffff;
const CWND: u32 = 10;
const REORDERING: u32 = 3;
/// `TCP_TIMEOUT_INIT` and the retransmission timeout once a loopback round
/// trip has been measured (`TCP_RTO_MIN` and the round trip), in
/// microseconds; `TCP_ATO_MIN` once data has come.
const RTO_INIT: u32 = 1_000_000;
const RTO: u32 = 201_000;
/// `TCP_RTO_MAX`, and the SYN retries that keep the first timeout.
const RTO_MAX: u32 = 120_000_000;
const LINEAR_TIMEOUTS: u8 = 4;
const ATO: u32 = 40_000;
/// A loopback round trip and its variation, in microseconds.
const RTT: u32 = 30;
const RTTVAR: u32 = 15;
/// `mdev_us` before any round trip, `TCP_TIMEOUT_INIT` (`tcp_init_sock`).
const RTTVAR_INIT: u32 = 250_000;
/// The window each side offers on the loopback, after scaling.
const WINDOW: u32 = 65_536;
/// `tcpi_options`: timestamps, SACK and window scaling, as Linux's
/// loopback connections take them.
const OPTIONS: u8 = 0x1 | 0x2 | 0x4;
/// Linux's default `tcp_rmem[2]` (32 MiB), which window scaling covers.
const RMEM_MAX: u32 = 32 << 20;

/// The fields `tcp_get_info` fills, the rest 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TcpInfo {
    pub(crate) state: u8,
    pub(crate) retransmits: u8,
    pub(crate) backoff: u8,
    pub(crate) options: u8,
    /// `tcpi_snd_wscale` and `tcpi_rcv_wscale`.
    pub(crate) wscale: (u8, u8),
    pub(crate) app_limited: bool,
    pub(crate) rto: u32,
    pub(crate) ato: u32,
    pub(crate) snd_mss: u32,
    pub(crate) rcv_mss: u32,
    /// A listener's connections waiting, else the segments in flight.
    pub(crate) unacked: u32,
    /// A listener's backlog.
    pub(crate) sacked: u32,
    /// Milliseconds since data last went and came, and an ACK came.
    pub(crate) last_data_sent: u32,
    pub(crate) last_data_recv: u32,
    pub(crate) last_ack_recv: u32,
    pub(crate) pmtu: u32,
    pub(crate) rcv_ssthresh: u32,
    pub(crate) rtt: u32,
    pub(crate) rttvar: u32,
    pub(crate) snd_ssthresh: u32,
    pub(crate) snd_cwnd: u32,
    pub(crate) advmss: u32,
    pub(crate) reordering: u32,
    pub(crate) rcv_space: u32,
    pub(crate) total_retrans: u32,
    pub(crate) pacing_rate: u64,
    pub(crate) max_pacing_rate: u64,
    pub(crate) bytes_acked: u64,
    pub(crate) bytes_received: u64,
    pub(crate) segs_out: u32,
    pub(crate) segs_in: u32,
    pub(crate) notsent_bytes: u32,
    pub(crate) min_rtt: u32,
    pub(crate) data_segs_in: u32,
    pub(crate) data_segs_out: u32,
    pub(crate) delivery_rate: u64,
    pub(crate) delivered: u32,
    pub(crate) bytes_sent: u64,
    pub(crate) snd_wnd: u32,
    pub(crate) rcv_wnd: u32,
    pub(crate) total_rto: u16,
}

/// What a connection has carried, for [`TcpInfo::connected`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Carried {
    /// This side accepted the connection, so its SYN does not count among
    /// the bytes acknowledged.
    pub(crate) accepted: bool,
    /// The data that reached the peer, and its end too.
    pub(crate) sent: u64,
    pub(crate) fin_sent: bool,
    /// The data that came, read or not, and the peer's end.
    pub(crate) received: u64,
    pub(crate) fin_received: bool,
    /// The bytes written that have not gone yet.
    pub(crate) unsent: u64,
    /// Milliseconds since data went and came.
    pub(crate) since_sent: u32,
    pub(crate) since_received: u32,
    /// This side's receive window scale.
    pub(crate) rcv_wscale: u8,
}

impl TcpInfo {
    /// A socket that has not connected, in `state`: what `tcp_init_sock`
    /// leaves, with its times counted from the jiffies' start, `uptime`
    /// milliseconds less Linux's five minutes ahead (`INITIAL_JIFFIES`).
    pub(crate) fn unconnected(state: u8, uptime: u64) -> Self {
        let since = (uptime as u32).wrapping_sub(300_000);
        Self {
            state,
            retransmits: 0,
            backoff: 0,
            options: 0,
            wscale: (0, 0),
            app_limited: true,
            rto: RTO_INIT,
            ato: 0,
            snd_mss: DEFAULT_MSS,
            rcv_mss: 0,
            unacked: 0,
            sacked: 0,
            last_data_sent: since,
            last_data_recv: since,
            last_ack_recv: since,
            pmtu: 0,
            rcv_ssthresh: 0,
            rtt: 0,
            rttvar: RTTVAR_INIT,
            snd_ssthresh: SSTHRESH,
            snd_cwnd: CWND,
            advmss: 0,
            reordering: REORDERING,
            rcv_space: 0,
            total_retrans: 0,
            pacing_rate: u64::MAX,
            max_pacing_rate: u64::MAX,
            bytes_acked: 0,
            bytes_received: 0,
            segs_out: 0,
            segs_in: 0,
            notsent_bytes: 0,
            min_rtt: u32::MAX,
            data_segs_in: 0,
            data_segs_out: 0,
            delivery_rate: 0,
            delivered: 0,
            bytes_sent: 0,
            snd_wnd: 0,
            rcv_wnd: 0,
            total_rto: 0,
        }
    }
    /// A listener with `ready` connections waiting of its `backlog`: what
    /// `tcp_get_info` tells of every state, and those two.
    pub(crate) fn listening(ready: u32, backlog: u32) -> Self {
        Self {
            unacked: ready,
            sacked: backlog,
            ..Self::zero(10)
        }
    }
    /// A connection's first segment waiting for its answer, sent again
    /// `tries` times (`tcp_connect_init`, `tcp_retransmit_timer`): the
    /// timeout doubles only past `tcp_syn_linear_timeouts` (4) of them.
    pub(crate) fn connecting(tries: u8, uptime: u64, since_sent: u32) -> Self {
        let backoff = tries.saturating_sub(LINEAR_TIMEOUTS);
        Self {
            retransmits: tries,
            backoff,
            rto: RTO_INIT.saturating_mul(1 << backoff.min(7)).min(RTO_MAX),
            snd_mss: ADVMSS,
            unacked: 1,
            last_data_sent: since_sent,
            pmtu: PMTU,
            rcv_ssthresh: ADVMSS,
            advmss: ADVMSS,
            rcv_space: ADVMSS,
            total_retrans: u32::from(tries),
            segs_out: 1 + u32::from(tries),
            total_rto: u16::from(tries),
            ..Self::unconnected(2, uptime)
        }
    }
    /// A connection in `state` that has carried `carried`, with `in_flight`
    /// segments not yet acknowledged (its end).
    pub(crate) fn connected(state: u8, carried: &Carried, in_flight: u32) -> Self {
        let syn = u64::from(!carried.accepted);
        let fin = u64::from(carried.fin_sent);
        // `tcp_update_pacing_rate` in slow start: twice the congestion
        // window a round trip.
        let pacing = u64::from(SND_MSS) * 2_000_000 * u64::from(CWND) / u64::from(RTT);
        let since_ack = carried.since_sent.min(carried.since_received);
        // The data each way in segments of [`SND_MSS`], however the guest
        // split its writes and reads.
        let segments_out = segments(carried.sent);
        let segments_in = segments(carried.received);
        Self {
            state,
            retransmits: 0,
            backoff: 0,
            options: OPTIONS,
            wscale: (wscale(RMEM_MAX), carried.rcv_wscale),
            app_limited: true,
            rto: RTO,
            ato: if carried.received > 0 { ATO } else { 0 },
            snd_mss: SND_MSS,
            rcv_mss: if carried.received > u64::from(DEFAULT_MSS) {
                SND_MSS
            } else {
                DEFAULT_MSS
            },
            unacked: in_flight,
            sacked: 0,
            last_data_sent: carried.since_sent,
            last_data_recv: carried.since_received,
            last_ack_recv: since_ack,
            pmtu: PMTU,
            rcv_ssthresh: ADVMSS,
            rtt: RTT,
            rttvar: RTTVAR,
            snd_ssthresh: SSTHRESH,
            snd_cwnd: CWND,
            advmss: ADVMSS,
            reordering: REORDERING,
            rcv_space: ADVMSS,
            total_retrans: 0,
            pacing_rate: pacing,
            max_pacing_rate: u64::MAX,
            bytes_acked: syn + carried.sent + fin,
            bytes_received: carried.received + u64::from(carried.fin_received),
            // The handshake's segments, then an acknowledgement for each
            // segment of data.
            segs_out: if carried.accepted { 0 } else { 2 } + segments_out + segments_in,
            segs_in: if carried.accepted { 2 } else { 1 } + segments_in + segments_out,
            notsent_bytes: u32::try_from(carried.unsent).unwrap_or(u32::MAX),
            min_rtt: RTT,
            data_segs_in: segments_in,
            data_segs_out: segments_out,
            delivery_rate: if segments_out > 0 {
                carried.sent.min(u64::from(SND_MSS)) * 1_000_000 / u64::from(RTT)
            } else {
                0
            },
            delivered: 1 + segments_out + u32::from(carried.fin_sent),
            bytes_sent: carried.sent,
            snd_wnd: WINDOW,
            rcv_wnd: WINDOW,
            total_rto: 0,
        }
    }
    /// Every field 0 but those `tcp_get_info` fills for any state.
    fn zero(state: u8) -> Self {
        Self {
            state,
            retransmits: 0,
            backoff: 0,
            options: 0,
            wscale: (0, 0),
            app_limited: false,
            rto: 0,
            ato: 0,
            snd_mss: 0,
            rcv_mss: 0,
            unacked: 0,
            sacked: 0,
            last_data_sent: 0,
            last_data_recv: 0,
            last_ack_recv: 0,
            pmtu: 0,
            rcv_ssthresh: 0,
            rtt: 0,
            rttvar: 0,
            snd_ssthresh: 0,
            snd_cwnd: CWND,
            advmss: 0,
            reordering: REORDERING,
            rcv_space: 0,
            total_retrans: 0,
            pacing_rate: u64::MAX,
            max_pacing_rate: u64::MAX,
            bytes_acked: 0,
            bytes_received: 0,
            segs_out: 0,
            segs_in: 0,
            notsent_bytes: 0,
            min_rtt: 0,
            data_segs_in: 0,
            data_segs_out: 0,
            delivery_rate: 0,
            delivered: 0,
            bytes_sent: 0,
            snd_wnd: 0,
            rcv_wnd: 0,
            total_rto: 0,
        }
    }
    /// The structure as x86-64 Linux lays it out.
    pub(crate) fn bytes(&self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0] = self.state;
        out[2] = self.retransmits;
        out[4] = self.backoff;
        out[5] = self.options;
        out[6] = self.wscale.0 & 0xf | self.wscale.1 << 4;
        out[7] = u8::from(self.app_limited);
        let words = [
            (8, self.rto),
            (12, self.ato),
            (16, self.snd_mss),
            (20, self.rcv_mss),
            (24, self.unacked),
            (28, self.sacked),
            (44, self.last_data_sent),
            (52, self.last_data_recv),
            (56, self.last_ack_recv),
            (60, self.pmtu),
            (64, self.rcv_ssthresh),
            (68, self.rtt),
            (72, self.rttvar),
            (76, self.snd_ssthresh),
            (80, self.snd_cwnd),
            (84, self.advmss),
            (88, self.reordering),
            (96, self.rcv_space),
            (100, self.total_retrans),
            (136, self.segs_out),
            (140, self.segs_in),
            (144, self.notsent_bytes),
            (148, self.min_rtt),
            (152, self.data_segs_in),
            (156, self.data_segs_out),
            (192, self.delivered),
            (228, self.snd_wnd),
            (232, self.rcv_wnd),
        ];
        for (at, value) in words {
            out[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let longs = [
            (104, self.pacing_rate),
            (112, self.max_pacing_rate),
            (120, self.bytes_acked),
            (128, self.bytes_received),
            (160, self.delivery_rate),
            (200, self.bytes_sent),
        ];
        for (at, value) in longs {
            out[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[240..242].copy_from_slice(&self.total_rto.to_le_bytes());
        out
    }
}

/// The segments `bytes` take, of [`SND_MSS`] each.
fn segments(bytes: u64) -> u32 {
    u32::try_from(bytes.div_ceil(u64::from(SND_MSS))).unwrap_or(u32::MAX)
}
/// The window scale a receive space of `space` bytes takes
/// (`tcp_select_initial_window`).
pub(crate) fn wscale(space: u32) -> u8 {
    (space.max(1).ilog2().saturating_sub(15)).min(14) as u8
}
/// The receive window scale of a socket: Linux's default, or what a
/// receive buffer the guest set clamps it to (`tcp_full_space`, half the
/// buffer).
pub(crate) fn receive_wscale(buffer: Option<u32>) -> u8 {
    match buffer {
        Some(buffer) => wscale((buffer / 2).min(RMEM_MAX)),
        None => wscale(RMEM_MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(raw: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(raw[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn an_unconnected_socket_has_linuxs_defaults() {
        let raw = TcpInfo::unconnected(7, 355_607 + 300_000).bytes();
        assert_eq!(&raw[..8], &[7, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            [8, 16, 44, 72, 76, 80, 88, 148].map(|at| word(&raw, at)),
            [
                1_000_000,
                536,
                355_607,
                250_000,
                0x7fff_ffff,
                10,
                3,
                u32::MAX
            ]
        );
        assert!(raw[104..120].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn a_listener_tells_its_queue() {
        let raw = TcpInfo::listening(1, 4).bytes();
        assert_eq!(&raw[..8], &[10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            [8, 24, 28, 76, 80, 88].map(|at| word(&raw, at)),
            [0, 1, 4, 0, 10, 3]
        );
        assert!(raw[104..120].iter().all(|&b| b == 0xff));
        assert!(raw[120..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_connection_counts_its_bytes() {
        let carried = Carried {
            sent: 100,
            received: 70_000,
            rcv_wscale: 10,
            ..Carried::default()
        };
        let raw = TcpInfo::connected(1, &carried, 0).bytes();
        assert_eq!(&raw[..8], &[1, 0, 0, 0, 0, 7, 0xaa, 1]);
        assert_eq!(u64::from_le_bytes(raw[120..128].try_into().unwrap()), 101);
        assert_eq!(
            u64::from_le_bytes(raw[128..136].try_into().unwrap()),
            70_000
        );
        assert_eq!(
            [60, 84, 152, 156, 192].map(|at| word(&raw, at)),
            [65_535, 65_483, 3, 1, 2]
        );
        let accepted = Carried {
            accepted: true,
            fin_received: true,
            ..carried
        };
        let raw = TcpInfo::connected(8, &accepted, 0).bytes();
        assert_eq!(u64::from_le_bytes(raw[120..128].try_into().unwrap()), 100);
        assert_eq!(
            u64::from_le_bytes(raw[128..136].try_into().unwrap()),
            70_001
        );
    }

    #[test]
    fn segments_follow_the_bytes_however_they_were_read() {
        let carried = Carried {
            received: 40_000,
            ..Carried::default()
        };
        let raw = TcpInfo::connected(1, &carried, 0).bytes();
        assert_eq!(word(&raw, 152), 2);
        let raw = TcpInfo::connected(
            1,
            &Carried {
                received: 100_000,
                sent: 1,
                ..carried
            },
            0,
        )
        .bytes();
        assert_eq!([152, 156].map(|at| word(&raw, at)), [4, 1]);
    }

    #[test]
    fn a_handshake_backs_off() {
        let raw = TcpInfo::connecting(2, 300_000, 5).bytes();
        assert_eq!(&raw[..6], &[2, 0, 2, 0, 0, 0]);
        assert_eq!(
            [8, 24, 44, 100].map(|at| word(&raw, at)),
            [1_000_000, 1, 5, 2]
        );
        let raw = TcpInfo::connecting(6, 300_000, 5).bytes();
        assert_eq!((raw[2], raw[4], word(&raw, 8)), (6, 2, 4_000_000));
    }

    #[test]
    fn window_scales_follow_the_receive_space() {
        assert_eq!(receive_wscale(None), 10);
        assert_eq!(receive_wscale(Some(212_992)), 1);
        assert_eq!(receive_wscale(Some(4608)), 0);
    }
}
