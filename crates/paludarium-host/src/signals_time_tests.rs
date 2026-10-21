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
