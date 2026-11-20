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
/// A wait marks the attached flag from when it goes to sleep until it ends,
/// a wait within another keeps it marked, and a wait with no flag attached,
/// or after the attachment ended, marks nothing.
#[test]
fn waits_mark_the_attached_flag_while_they_sleep() {
    use std::sync::Arc;
    std::thread::spawn(|| {
        let flag = Arc::new(AtomicBool::new(false));
        let mut early = blocked::Waiting::new();
        early.sleep();
        drop(early);
        let attached = blocked::attach(&flag);
        // Not asleep yet: not marked.
        let mut outer = blocked::Waiting::new();
        assert!(!flag.load(Ordering::SeqCst));
        outer.sleep();
        assert!(flag.load(Ordering::SeqCst));
        let mut inner = blocked::Waiting::new();
        inner.sleep();
        drop(inner);
        assert!(
            flag.load(Ordering::SeqCst),
            "an inner wait leaves it marked"
        );
        drop(outer);
        assert!(!flag.load(Ordering::SeqCst));
        // A host's own wait marks it while it sleeps: another thread sees
        // the mark, and only then ends the wait.
        let h = Arc::new(RecordingHost::new());
        let token = Arc::new(WaitToken::default());
        let watcher = {
            let (flag, token, h) = (Arc::clone(&flag), Arc::clone(&token), Arc::clone(&h));
            std::thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                h.wake(&token);
            })
        };
        let outcome = h.wait_on(&token, 0, None, &AtomicBool::new(false));
        assert_eq!(outcome, Ok(WaitOutcome::Complete));
        watcher.join().unwrap();
        assert!(!flag.load(Ordering::SeqCst));
        // Once the attachment ends, a wait marks nothing.
        drop(attached);
        let mut after = blocked::Waiting::new();
        after.sleep();
        assert!(!flag.load(Ordering::SeqCst));
        drop(after);
        // An attachment within another, of another flag, marks that one
        // and gives the outer one back its own as it ends.
        let _outer = blocked::attach(&flag);
        let other = Arc::new(AtomicBool::new(false));
        let inner = blocked::attach(&other);
        let mut marked = blocked::Waiting::new();
        marked.sleep();
        assert!(other.load(Ordering::SeqCst) && !flag.load(Ordering::SeqCst));
        drop(marked);
        drop(inner);
        let mut marked = blocked::Waiting::new();
        marked.sleep();
        assert!(flag.load(Ordering::SeqCst) && !other.load(Ordering::SeqCst));
    })
    .join()
    .unwrap();
}
