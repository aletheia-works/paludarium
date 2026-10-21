use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn macos_native_monotonic_forward() {
    let h = NativeHost::new();
    let before = h.clock(ClockId::Monotonic).unwrap();
    std::thread::sleep(Duration::from_millis(1));
    assert!(h.clock(ClockId::Monotonic).unwrap() >= before);
}
#[test]
fn macos_native_realtime_epoch() {
    let lower = UNIX_EPOCH.elapsed().unwrap().as_nanos();
    let value = u128::from(NativeHost::new().clock(ClockId::Realtime).unwrap());
    assert!((lower..=UNIX_EPOCH.elapsed().unwrap().as_nanos()).contains(&value));
}
#[test]
fn macos_native_past_deadline() {
    assert_eq!(
        NativeHost::new().wait_until(ClockId::Monotonic, 0, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
}
#[test]
fn macos_native_cancelled_wait() {
    assert_eq!(
        NativeHost::new().wait_until(ClockId::Monotonic, u64::MAX, &AtomicBool::new(true)),
        Ok(WaitOutcome::Interrupted)
    );
}
#[test]
fn macos_native_thread_join_visibility() {
    let state = Arc::new(AtomicUsize::new(0));
    let child = state.clone();
    threads::spawn(Box::new(move || {
        child.store(7, Ordering::SeqCst);
    }))
    .unwrap()
    .join()
    .unwrap();
    assert_eq!(state.load(Ordering::SeqCst), 7);
}
#[test]
fn macos_native_thread_panic_linux_errno() {
    assert_eq!(
        threads::spawn(Box::new(|| panic!("macOS controlled panic")))
            .unwrap()
            .join(),
        Err(Errno::EIO)
    );
}
#[test]
fn macos_native_ticket_and_empty_stdio() {
    let token = WaitToken::default();
    token.notify();
    assert_eq!(
        threads::wait(&NativeHost::new(), &token, 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(NativeHost::new().write_stdout(b""), Ok(0));
    assert_eq!(NativeHost::new().write_stderr(b""), Ok(0));
}

struct Fixture {
    root: std::path::PathBuf,
    fs: Option<Arc<dyn HostFs>>,
}
// This helper is compiled only for tests; setup failures must fail the test.
#[allow(clippy::panic)]
impl Fixture {
    fn new() -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "paludarium-macos-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("root"))
            .unwrap_or_else(|error| panic!("fixture root: {error}"));
        std::fs::write(root.join("outside"), b"sentinel")
            .unwrap_or_else(|error| panic!("fixture sentinel: {error}"));
        let fs = NativeHost::new()
            .mount_fs(&root.join("root"))
            .unwrap_or_else(|error| panic!("fixture mount: {error:?}"));
        Self { root, fs: Some(fs) }
    }
    fn fs(&self) -> &dyn HostFs {
        self.fs
            .as_ref()
            .unwrap_or_else(|| panic!("fixture already closed"))
            .as_ref()
    }
}
// Cleanup failure must fail the test rather than leak a fixture silently.
#[allow(clippy::panic)]
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.fs.take());
        std::fs::remove_dir_all(&self.root)
            .unwrap_or_else(|error| panic!("fixture cleanup: {error}"));
    }
}
#[test]
fn macos_fs_missing_linux_errno() {
    assert_eq!(
        Fixture::new().fs().metadata(b"missing", true),
        Err(Errno::ENOENT)
    );
}
#[test]
fn macos_fs_io_metadata() {
    let x = Fixture::new();
    let f = x.fs().open(b"io", 66, 0o600).unwrap();
    f.write(b"abc").unwrap();
    f.seek(0, 0).unwrap();
    let mut bytes = [0; 3];
    assert_eq!(f.read(&mut bytes), Ok(3));
    assert_eq!(&bytes, b"abc");
    assert_eq!(f.stat().unwrap().size, 3);
}
#[test]
fn macos_fs_nul_rejected() {
    assert_eq!(
        Fixture::new().fs().metadata(b"nul\0path", true),
        Err(Errno::EINVAL)
    );
}
#[test]
fn macos_fs_parent_escape_denied() {
    let x = Fixture::new();
    assert!(x.fs().open(b"../outside", 0, 0).is_err());
    assert_eq!(std::fs::read(x.root.join("outside")).unwrap(), b"sentinel");
}
#[cfg(unix)]
#[test]
fn macos_fs_symlink_hardlink() {
    let x = Fixture::new();
    x.fs().open(b"original", 66, 0o600).unwrap();
    x.fs().symlink(b"original", b"sym").unwrap();
    x.fs().link(b"original", b"hard").unwrap();
    assert_eq!(x.fs().readlink(b"sym"), Ok(b"original".to_vec()));
    assert_eq!(x.fs().metadata(b"hard", true).unwrap().links, 2);
}
#[test]
fn macos_fs_flock_contention() {
    let x = Fixture::new();
    let a = x.fs().open(b"lock", 66, 0o600).unwrap();
    let b = x.fs().open(b"lock", 2, 0).unwrap();
    a.flock(6).unwrap();
    assert_eq!(b.flock(6), Err(Errno::EAGAIN));
    a.flock(8).unwrap();
    b.flock(6).unwrap();
}
#[cfg(unix)]
#[test]
fn macos_fs_negative_mtime() {
    let x = Fixture::new();
    let h = x.fs().open(b"mtime", 66, 0o600).unwrap();
    let f = std::fs::File::open(x.root.join("root/mtime")).unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH - Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        x.fs().metadata(b"mtime", true).unwrap().mtime_ns,
        -1_000_000_000
    );
    assert_eq!(h.stat().unwrap().mtime_ns, -1_000_000_000);
}
