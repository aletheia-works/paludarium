use crate::*;
#[test]
fn u7_mtime_preserves_unsigned_clock_maximum() {
    let fs = MemFs::with_clock(Arc::new(|| Ok(u64::MAX)));
    let file = fs.open(b"/maximum", 0o100 | 2, 0o644).unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, i128::from(u64::MAX));
    file.write(b"maximum").unwrap();
    assert_eq!(
        fs.metadata(b"/maximum", false).unwrap().mtime_ns,
        i128::from(u64::MAX)
    );
}
use std::sync::atomic::{AtomicU64, Ordering};
fn fixture() -> (MemFs, Arc<AtomicU64>) {
    let time = Arc::new(AtomicU64::new(1_000_000_001));
    let clock = time.clone();
    (
        MemFs::with_clock(Arc::new(move || Ok(clock.load(Ordering::SeqCst)))),
        time,
    )
}
#[test]
fn u11_mtime_initial_epoch_and_created_clock() {
    let (mut fs, _) = fixture();
    fs.add_file(GuestFile::new(b"/input".to_vec(), vec![1]))
        .unwrap();
    assert_eq!(fs.metadata(b"/input", false).unwrap().mtime_ns, 0);
    assert_eq!(
        fs.open(b"/new", 66, 0o644)
            .unwrap()
            .stat()
            .unwrap()
            .mtime_ns,
        1_000_000_001
    );
}
#[test]
fn u11_mtime_write_truncate_and_hardlink_share_time() {
    let (fs, time) = fixture();
    let file = fs.open(b"/a", 66, 0o644).unwrap();
    fs.link(b"/a", b"/b").unwrap();
    time.store(2_999_999_999, Ordering::SeqCst);
    file.write(b"bytes").unwrap();
    assert_eq!(fs.metadata(b"/b", false).unwrap().mtime_ns, 2_999_999_999);
    time.store(3_000_000_000, Ordering::SeqCst);
    file.truncate(1).unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, 3_000_000_000);
}
#[test]
fn u11_mtime_realtime_can_move_backwards() {
    let (fs, time) = fixture();
    let file = fs.open(b"/a", 66, 0o644).unwrap();
    time.store(42, Ordering::SeqCst);
    file.write(b"x").unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, 42);
    time.store(99, Ordering::SeqCst);
    file.write(b"").unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, 42);
}
#[test]
fn u11_mtime_clock_failure_does_not_create_file() {
    let fs = MemFs::with_clock(Arc::new(|| Err(Errno::EIO)));
    assert!(matches!(fs.open(b"/a", 66, 0o644), Err(Errno::EIO)));
    assert_eq!(fs.metadata(b"/a", false), Err(Errno::ENOENT));
}
#[test]
fn u11_mtime_open_truncate_updates_clock() {
    let (fs, time) = fixture();
    fs.open(b"/a", 66, 0o644).unwrap().write(b"abc").unwrap();
    time.store(700, Ordering::SeqCst);
    let file = fs.open(b"/a", 514, 0o644).unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, 700);
    assert_eq!(file.stat().unwrap().size, 0);
}
#[test]
fn u11_mtime_default_preserves_epoch() {
    let fs = MemFs::new();
    let file = fs.open(b"/a", 66, 0o644).unwrap();
    file.write(b"bytes").unwrap();
    file.truncate(1).unwrap();
    assert_eq!(file.stat().unwrap().mtime_ns, 0);
}
#[test]
fn u11_mtime_failed_write_keeps_bytes_and_time() {
    let time = Arc::new(AtomicU64::new(9));
    let clock = time.clone();
    let fs = MemFs::with_clock(Arc::new(move || {
        let value = clock.load(Ordering::SeqCst);
        if value == u64::MAX {
            Err(Errno::EIO)
        } else {
            Ok(value)
        }
    }));
    let file = fs.open(b"/a", 66, 0o644).unwrap();
    file.write(b"old").unwrap();
    time.store(u64::MAX, Ordering::SeqCst);
    assert_eq!(file.write(b"new"), Err(Errno::EIO));
    assert_eq!(file.stat().unwrap().mtime_ns, 9);
    assert_eq!(&*fs.read_file(b"/a").unwrap(), b"old");
}
