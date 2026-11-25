//! The numbers are those a native run on Linux 7.0.14 gave for the same
//! calls (a loopback connection, IPv4).
use super::*;

const PLAIN: Push = Push {
    more: false,
    urgent: false,
    no_delay: false,
};

fn flows() -> Flows {
    Flows::new(65_483, 0)
}
/// `side` writes `len` bytes at `now`, as `push` says.
fn write(f: &mut Flows, side: usize, len: u64, push: Push, now: u64) {
    f.sending(side, push);
    f.write(side, len, now);
}
fn of(f: &mut Flows, side: usize, ms: u64) -> [u32; 6] {
    let c = f.counts(side, ms * MS);
    [
        c.unacked,
        c.segs_out,
        c.segs_in,
        c.data_segs_in,
        c.data_segs_out,
        c.delivered,
    ]
}
fn small(f: &mut Flows, count: usize) {
    for _ in 0..count {
        write(f, 0, 1, f.pushes[0], 0);
    }
}

#[test]
fn a_handshake_counts_its_own() {
    let mut f = flows();
    assert_eq!(of(&mut f, 0, 60), [0, 2, 1, 0, 0, 1]);
    assert_eq!(of(&mut f, 1, 60), [0, 0, 2, 0, 0, 1]);
    assert_eq!(f.counts(0, 60 * MS).snd_mss, 32_741);
    assert_eq!(f.counts(1, 60 * MS).snd_mss, 32_768);
}

#[test]
fn small_writes_are_acknowledged_at_once_then_wait() {
    // Sixteen quick acknowledgements.
    let mut f = flows();
    small(&mut f, 16);
    assert_eq!(of(&mut f, 0, 0), [0, 18, 17, 0, 16, 17]);
    assert_eq!(of(&mut f, 1, 0), [0, 16, 18, 16, 0, 1]);
    // The seventeenth's waits 40 ms.
    let mut f = flows();
    small(&mut f, 17);
    assert_eq!(of(&mut f, 0, 0), [1, 19, 17, 0, 17, 17]);
    assert_eq!(of(&mut f, 0, 39), [1, 19, 17, 0, 17, 17]);
    assert_eq!(of(&mut f, 0, 120), [0, 19, 18, 0, 17, 18]);
    assert_eq!(f.counts(1, 120 * MS).ato, 80_000);
    // The rest are held, and go in one.
    let mut f = flows();
    small(&mut f, 30);
    assert_eq!(of(&mut f, 0, 0), [1, 19, 17, 0, 17, 17]);
    assert_eq!(f.counts(0, 0).held, 13);
    assert_eq!(of(&mut f, 0, 120), [0, 20, 19, 0, 18, 19]);
    assert_eq!(of(&mut f, 1, 120), [0, 18, 20, 18, 0, 1]);
}

#[test]
fn a_read_acknowledges_what_waits() {
    let mut f = flows();
    small(&mut f, 20);
    f.read(1, 17, 0);
    assert_eq!(of(&mut f, 0, 0), [1, 20, 18, 0, 18, 18]);
    assert_eq!(of(&mut f, 1, 0), [0, 17, 20, 18, 0, 1]);
    assert_eq!(of(&mut f, 0, 120), [0, 20, 19, 0, 18, 19]);
    // Each write read in turn is acknowledged.
    let mut f = flows();
    for _ in 0..30 {
        write(&mut f, 0, 1, PLAIN, 0);
        f.read(1, 1, 0);
    }
    assert_eq!(of(&mut f, 0, 0), [0, 32, 31, 0, 30, 31]);
    // Held bytes a read takes have gone.
    let mut f = flows();
    small(&mut f, 20);
    f.read(1, 20, 0);
    assert_eq!(f.counts(1, 0).received, 20);
    assert_eq!(f.counts(0, 0).held, 0);
}

#[test]
fn no_delay_sends_each_write_until_the_window_is_full() {
    let mut f = flows();
    f.set_no_delay(0, true, 0);
    f.sending(
        0,
        Push {
            no_delay: true,
            ..PLAIN
        },
    );
    small(&mut f, 30);
    assert_eq!(of(&mut f, 0, 0), [10, 28, 17, 0, 26, 17]);
    assert_eq!(f.counts(0, 0).held, 4);
    // A loss probe sends the rest.
    assert_eq!(of(&mut f, 0, 120), [0, 29, 18, 0, 27, 28]);
    // Set with data held, it sends it, and a probe sends that again.
    let mut f = flows();
    small(&mut f, 20);
    f.set_no_delay(0, true, 0);
    assert_eq!(of(&mut f, 0, 0), [2, 20, 17, 0, 18, 17]);
    assert_eq!(of(&mut f, 0, 120), [0, 21, 18, 0, 19, 20]);
    assert_eq!(of(&mut f, 1, 120), [0, 17, 21, 19, 0, 1]);
    assert_eq!(f.counts(0, 120 * MS).retransmitted, 1);
}

#[test]
fn more_waits_for_the_rest_or_its_timer() {
    let more = Push {
        more: true,
        ..PLAIN
    };
    let mut f = flows();
    for _ in 0..3 {
        write(&mut f, 0, 100, more, 0);
    }
    assert_eq!(of(&mut f, 0, 0), [0, 2, 1, 0, 0, 1]);
    assert_eq!(f.counts(0, 0).held, 300);
    write(&mut f, 0, 100, PLAIN, 0);
    assert_eq!(of(&mut f, 0, 0), [0, 3, 2, 0, 1, 2]);
    let mut f = flows();
    write(&mut f, 0, 100, more, 0);
    assert_eq!(of(&mut f, 0, 100), [0, 2, 1, 0, 0, 1]);
    assert_eq!(of(&mut f, 0, 300), [0, 3, 2, 0, 1, 2]);
}

#[test]
fn a_write_past_the_mss_is_cut() {
    for (len, sent, settled) in [
        (32_741, [0, 3, 2, 0, 1, 2], [0, 3, 2, 0, 1, 2]),
        (32_767, [1, 4, 2, 0, 2, 2], [0, 4, 3, 0, 2, 3]),
        (60_000, [1, 4, 2, 0, 2, 2], [0, 4, 3, 0, 2, 3]),
        // The third segment is the one a probe sends again.
        (65_483, [2, 5, 2, 0, 3, 2], [0, 6, 3, 0, 4, 5]),
    ] {
        let mut f = flows();
        write(&mut f, 0, len, PLAIN, 0);
        assert_eq!(of(&mut f, 0, 0), sent, "{len}");
        assert_eq!(of(&mut f, 0, 120), settled, "{len}");
    }
}

#[test]
fn a_read_of_bytes_held_brings_them_all() {
    let mut f = flows();
    write(&mut f, 0, 1_000_000, PLAIN, 0);
    assert!(f.counts(0, 0).held > 0);
    f.read(1, 1_000_000, 0);
    let c = f.counts(1, 0);
    assert_eq!((c.received, f.counts(0, 0).held), (1_000_000, 0));
    let c = f.counts(0, 120 * MS);
    assert_eq!((c.unacked, c.acked), (0, 1_000_000));
    // Nothing is left to bring.
    f.read(1, 5, 0);
    assert_eq!(f.counts(1, 0).received, 1_000_000);
}

#[test]
fn replies_carry_acknowledgements() {
    let mut f = flows();
    for _ in 0..5 {
        write(&mut f, 0, 10, PLAIN, 0);
        f.read(1, 10, 0);
        write(&mut f, 1, 20, PLAIN, 0);
        f.read(0, 20, 0);
    }
    assert_eq!(of(&mut f, 0, 0), [0, 8, 7, 5, 5, 6]);
    assert_eq!(of(&mut f, 1, 0), [1, 6, 8, 5, 5, 5]);
    assert_eq!(of(&mut f, 0, 120), [0, 9, 7, 5, 5, 6]);
    assert_eq!(of(&mut f, 1, 120), [0, 6, 9, 5, 5, 6]);
    // An interactive side delays its acknowledgements.
    let mut f = flows();
    write(&mut f, 0, 1, PLAIN, 0);
    f.read(1, 1, 0);
    write(&mut f, 1, 1, PLAIN, 0);
    f.read(0, 1, 0);
    assert_eq!(of(&mut f, 0, 0), [0, 4, 3, 1, 1, 2]);
    small(&mut f, 5);
    assert_eq!(of(&mut f, 0, 0), [1, 5, 3, 1, 2, 2]);
    assert_eq!(of(&mut f, 0, 120), [0, 6, 5, 1, 3, 4]);
    assert_eq!(of(&mut f, 1, 120), [0, 4, 6, 3, 1, 2]);
}

#[test]
fn ends_are_segments() {
    let mut f = flows();
    write(&mut f, 0, 10, PLAIN, 0);
    f.end(0, 0);
    assert!(f.counts(0, 0).end_waits);
    assert_eq!(of(&mut f, 0, 60), [0, 4, 3, 0, 1, 3]);
    assert_eq!(of(&mut f, 1, 60), [0, 2, 4, 1, 0, 1]);
    f.read(1, 10, 60 * MS);
    write(&mut f, 1, 5, PLAIN, 60 * MS);
    assert_eq!(of(&mut f, 0, 120), [0, 5, 4, 1, 1, 3]);
    assert_eq!(of(&mut f, 1, 120), [0, 3, 5, 1, 1, 2]);
    f.end(1, 120 * MS);
    assert_eq!(of(&mut f, 0, 180), [0, 6, 5, 1, 1, 3]);
    assert_eq!(of(&mut f, 1, 180), [0, 4, 6, 1, 1, 3]);
    // Held data takes the end along, and a probe sends both again.
    let mut f = flows();
    small(&mut f, 20);
    f.end(0, 0);
    assert_eq!(of(&mut f, 0, 0), [2, 20, 17, 0, 18, 17]);
    assert_eq!(of(&mut f, 0, 120), [0, 21, 18, 0, 19, 20]);
    // Alone, its acknowledgement waits.
    let mut f = flows();
    f.end(0, 0);
    assert_eq!(of(&mut f, 0, 0), [1, 3, 1, 0, 0, 1]);
    assert_eq!(of(&mut f, 0, 60), [0, 3, 2, 0, 0, 2]);
    f.end(1, 60 * MS);
    assert_eq!(of(&mut f, 0, 60), [0, 4, 3, 0, 0, 2]);
    assert_eq!(of(&mut f, 1, 60), [0, 2, 4, 0, 0, 2]);
}

#[test]
fn quick_acknowledgements_turn_off_and_come_back() {
    let mut f = flows();
    f.set_quick(1, 0, 0);
    small(&mut f, 5);
    assert_eq!(of(&mut f, 0, 0), [1, 3, 1, 0, 1, 1]);
    assert_eq!(of(&mut f, 0, 120), [0, 4, 3, 0, 2, 3]);
    assert_eq!(f.counts(1, 120 * MS).ato, 40_000);
    f.set_quick(1, 1, 120 * MS);
    assert_eq!(of(&mut f, 1, 120), [0, 2, 4, 2, 0, 1]);
    // After a long gap they begin again.
    let mut f = flows();
    small(&mut f, 17);
    for _ in 0..5 {
        write(&mut f, 0, 1, PLAIN, 300 * MS);
    }
    assert_eq!(of(&mut f, 0, 300), [0, 24, 23, 0, 22, 23]);
}

#[test]
fn both_ways_unread() {
    let mut f = flows();
    for _ in 0..5 {
        write(&mut f, 0, 1, PLAIN, 0);
        write(&mut f, 1, 1, PLAIN, 0);
    }
    assert_eq!(of(&mut f, 0, 0), [0, 8, 7, 5, 5, 6]);
    assert_eq!(of(&mut f, 1, 0), [1, 6, 8, 5, 5, 5]);
    assert_eq!(of(&mut f, 1, 120), [0, 6, 9, 5, 5, 6]);
}

#[test]
fn urgent_data_does_not_wait() {
    let mut f = flows();
    small(&mut f, 18);
    let urgent = Push {
        urgent: true,
        ..PLAIN
    };
    write(&mut f, 0, 3, urgent, 0);
    assert_eq!(f.counts(0, 0).held, 0);
    assert_eq!(f.counts(0, 0).data_segs_out, 18);
}

#[test]
fn a_reset_is_heard() {
    let mut f = flows();
    f.reset(1, 0);
    assert_eq!(of(&mut f, 0, 0), [0, 2, 2, 0, 0, 1]);
    assert_eq!(f.counts(1, 0).segs_out, 1);
}

#[test]
fn a_veth_s_mss_is_its_mtu_s() {
    let mut f = Flows::new(1448, 0);
    write(&mut f, 0, 4000, PLAIN, 0);
    let c = f.counts(0, 120 * MS);
    assert_eq!((c.data_segs_out, c.snd_mss, c.held), (3, 1448, 0));
}
