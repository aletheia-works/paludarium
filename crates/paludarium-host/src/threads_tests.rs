use super::*;
use std::sync::{Arc, atomic::AtomicBool};
#[test]
fn spawn_join() {
    let v = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let w = v.clone();
    NativeHost
        .spawn_thread(Box::new(move || {
            w.store(7, std::sync::atomic::Ordering::SeqCst);
        }))
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(v.load(std::sync::atomic::Ordering::SeqCst), 7);
}
#[test]
fn wake_before_wait() {
    let t = WaitToken::default();
    NativeHost.wake(&t);
    assert_eq!(
        NativeHost.wait_on(&t, 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
}
#[test]
fn cancelled_wait() {
    assert_eq!(
        NativeHost.wait_on(&WaitToken::default(), 0, None, &AtomicBool::new(true)),
        Ok(WaitOutcome::Interrupted)
    );
}
#[test]
fn expired_wait() {
    assert_eq!(
        NativeHost.wait_on(
            &WaitToken::default(),
            0,
            Some((ClockId::Monotonic, 0)),
            &AtomicBool::new(false)
        ),
        Ok(WaitOutcome::Complete)
    );
}
#[test]
fn multiple_notifications() {
    let t = WaitToken::default();
    t.notify();
    t.notify();
    assert_eq!(t.value(), 2);
}
#[test]
fn worker_panic_is_error() {
    assert_eq!(
        NativeHost
            .spawn_thread(Box::new(|| panic!("worker test")))
            .unwrap()
            .join(),
        Err(Errno::EIO)
    );
}
#[test]
fn wake_during_wait() {
    let t = Arc::new(WaitToken::default());
    let w = t.clone();
    let h = NativeHost
        .spawn_thread(Box::new(move || w.notify()))
        .unwrap();
    assert_eq!(
        NativeHost.wait_on(&t, 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    h.join().unwrap();
}
