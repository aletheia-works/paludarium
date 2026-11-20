use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use testing::RecordingHost;
#[test]
fn fake_monotonic_roundtrip() {
    let h = RecordingHost::new();
    h.set_clock(ClockId::Monotonic, 42);
    assert_eq!(h.clock(ClockId::Monotonic), Ok(42));
}
#[test]
fn fake_realtime_independent() {
    let h = RecordingHost::new();
    h.set_clock(ClockId::Realtime, 42);
    h.set_clock(ClockId::Monotonic, 7);
    assert_eq!(h.clock(ClockId::Realtime), Ok(42));
    assert_eq!(h.clock(ClockId::Monotonic), Ok(7));
}
#[test]
fn deadline_advances_fake_clock() {
    let h = RecordingHost::new();
    assert_eq!(
        h.wait_until(ClockId::Monotonic, 42, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(h.clock(ClockId::Monotonic), Ok(42));
}
#[test]
fn past_deadline_never_rewinds() {
    let h = RecordingHost::new();
    h.set_clock(ClockId::Monotonic, 100);
    h.wait_until(ClockId::Monotonic, 42, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(h.clock(ClockId::Monotonic), Ok(100));
}
#[test]
fn cancellation_preserves_clock() {
    let h = RecordingHost::new();
    assert_eq!(
        h.wait_until(ClockId::Monotonic, 42, &AtomicBool::new(true)),
        Ok(WaitOutcome::Interrupted)
    );
    assert_eq!(h.clock(ClockId::Monotonic), Ok(0));
}
#[test]
fn interruption_is_one_shot() {
    let h = RecordingHost::new();
    h.interrupt_next_wait();
    let c = AtomicBool::new(false);
    assert_eq!(
        h.wait_until(ClockId::Monotonic, 42, &c),
        Ok(WaitOutcome::Interrupted)
    );
    assert_eq!(
        h.wait_until(ClockId::Monotonic, 42, &c),
        Ok(WaitOutcome::Complete)
    );
}
#[test]
fn native_monotonic_does_not_rewind() {
    let h = NativeHost::new();
    let a = h.clock(ClockId::Monotonic).unwrap();
    let b = h.clock(ClockId::Monotonic).unwrap();
    assert!(b >= a);
}
#[test]
fn native_wait_checks_cancellation() {
    let h = NativeHost::new();
    let c = AtomicBool::new(false);
    c.store(true, Ordering::SeqCst);
    assert_eq!(
        h.wait_until(ClockId::Monotonic, u64::MAX, &c),
        Ok(WaitOutcome::Interrupted)
    );
}
/// On Linux the host's NTP state is read without privilege: a tick within
/// the range Linux takes (90% to 110% of USER_TICK_USEC) and Linux's
/// tolerance. A sandbox may refuse even the read (Docker's default seccomp
/// profile, without `CAP_SYS_TIME`), and then the host tells none.
/// Elsewhere the native host tells none.
#[test]
fn native_ntp_state_is_the_hosts() {
    let state = NativeHost::new().ntp_state();
    #[cfg(target_os = "linux")]
    {
        let Some(state) = state else {
            let mut timex = [0i64; 26];
            // SAFETY: `timex` is a live, aligned 208-byte buffer, as the
            // call needs; no mode is set, so it only reads.
            let r = unsafe { libc::syscall(libc::SYS_adjtimex, timex.as_mut_ptr()) };
            let e = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(
                (r, e),
                (-1, Some(libc::EPERM)),
                "only a refused read tells none"
            );
            return;
        };
        assert!((0..=5).contains(&state.result), "{state:?}");
        assert!((9_000..=11_000).contains(&state.tick), "{state:?}");
        assert_eq!(state.tolerance, 32_768_000);
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(state, None);
}
/// A recording host gives the state it was set to in place of the
/// machine's, `None` included.
#[test]
fn recorded_ntp_state_overrides_the_machines() {
    let h = RecordingHost::new();
    let state = NtpState {
        tick: 9_999,
        ..NtpState::default()
    };
    h.set_ntp_state(Some(state));
    assert_eq!(h.ntp_state(), Some(state));
    h.set_ntp_state(None);
    assert_eq!(h.ntp_state(), None);
}
/// A wait marks the attached flag while it lasts, a wait within another
/// keeps it marked, and a thread with no flag attached marks nothing.
#[test]
fn waits_mark_the_attached_flag_while_they_last() {
    use std::sync::Arc;
    std::thread::spawn(|| {
        drop(blocked::Waiting::start());
        let flag = Arc::new(AtomicBool::new(false));
        blocked::attach(&flag);
        let outer = blocked::Waiting::start();
        assert!(flag.load(Ordering::SeqCst));
        drop(blocked::Waiting::start());
        assert!(
            flag.load(Ordering::SeqCst),
            "an inner wait leaves it marked"
        );
        drop(outer);
        assert!(!flag.load(Ordering::SeqCst));
        // The host's own waits mark it, and not after they end.
        let h = RecordingHost::new();
        let seen = Arc::new(AtomicBool::new(false));
        let watcher = {
            let (flag, seen) = (Arc::clone(&flag), Arc::clone(&seen));
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    if flag.load(Ordering::SeqCst) {
                        seen.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::yield_now();
                }
            })
        };
        let _ = h.wait_until(ClockId::Monotonic, 1_000_000_000, &AtomicBool::new(false));
        watcher.join().unwrap();
        assert!(seen.load(Ordering::SeqCst));
        assert!(!flag.load(Ordering::SeqCst));
        // Attaching another replaces it.
        let other = Arc::new(AtomicBool::new(false));
        blocked::attach(&other);
        drop(blocked::Waiting::start());
        let marked = blocked::Waiting::start();
        assert!(other.load(Ordering::SeqCst) && !flag.load(Ordering::SeqCst));
        drop(marked);
    })
    .join()
    .unwrap();
}
