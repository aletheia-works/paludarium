use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn u13_native_monotonic_forward() {
    let h = NativeHost::new();
    let before = h.clock(ClockId::Monotonic).unwrap();
    std::thread::sleep(Duration::from_millis(1));
    assert!(h.clock(ClockId::Monotonic).unwrap() >= before);
}
#[test]
fn u13_native_realtime_epoch() {
    let lower = UNIX_EPOCH.elapsed().unwrap().as_nanos();
    let value = u128::from(NativeHost::new().clock(ClockId::Realtime).unwrap());
    assert!((lower..=UNIX_EPOCH.elapsed().unwrap().as_nanos()).contains(&value));
}
#[test]
fn u13_native_past_deadline() {
    assert_eq!(
        NativeHost::new().wait_until(ClockId::Monotonic, 0, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
}
#[test]
fn u13_native_cancelled_wait() {
    assert_eq!(
        NativeHost::new().wait_until(ClockId::Monotonic, u64::MAX, &AtomicBool::new(true)),
        Ok(WaitOutcome::Interrupted)
    );
}
#[test]
fn u13_native_thread_join_visibility() {
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
fn u13_native_thread_panic_linux_errno() {
    assert_eq!(
        threads::spawn(Box::new(|| panic!("U13 controlled panic")))
            .unwrap()
            .join(),
        Err(Errno::EIO)
    );
}
#[test]
fn u13_native_ticket_and_empty_stdio() {
    let token = WaitToken::default();
    token.notify();
    assert_eq!(
        threads::wait(&NativeHost::new(), &token, 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(NativeHost::new().write_stdout(b""), Ok(0));
    assert_eq!(NativeHost::new().write_stderr(b""), Ok(0));
}

#[test]
fn u13_native_ticket_future_deadline() {
    let host = NativeHost::new();
    let token = WaitToken::default();
    let deadline = host.clock(ClockId::Monotonic).unwrap() + 5_000_000;
    assert_eq!(
        threads::wait(
            &host,
            &token,
            0,
            Some((ClockId::Monotonic, deadline)),
            &AtomicBool::new(false),
        ),
        Ok(WaitOutcome::Complete)
    );
    assert!(host.clock(ClockId::Monotonic).unwrap() >= deadline);
    assert_eq!(token.value(), 0);
}

#[test]
fn u13_native_one_notify_releases_two_waiters() {
    let token = Arc::new(WaitToken::default());
    let ready = Arc::new(std::sync::Barrier::new(3));
    let completed = Arc::new(AtomicUsize::new(0));
    let deadline = NativeHost::new().clock(ClockId::Monotonic).unwrap() + 5_000_000_000;
    let mut workers = Vec::new();
    for _ in 0..2 {
        let token = Arc::clone(&token);
        let ready = Arc::clone(&ready);
        let completed = Arc::clone(&completed);
        workers.push(
            threads::spawn(Box::new(move || {
                ready.wait();
                assert_eq!(
                    threads::wait(
                        &NativeHost::new(),
                        &token,
                        0,
                        Some((ClockId::Monotonic, deadline)),
                        &AtomicBool::new(false),
                    ),
                    Ok(WaitOutcome::Complete)
                );
                assert_eq!(token.value(), 1);
                completed.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap(),
        );
    }
    ready.wait();
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    token.notify();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(completed.load(Ordering::SeqCst), 2);
    assert_eq!(token.value(), 1);
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
            "paludarium-u13-{}-{}",
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
fn u13_fs_missing_linux_errno() {
    assert_eq!(
        Fixture::new().fs().metadata(b"missing", true),
        Err(Errno::ENOENT)
    );
}
#[test]
fn u13_fs_io_metadata() {
    let x = Fixture::new();
    let f = x.fs().open(b"io", 66, 0o600).unwrap();
    f.write(b"abc").unwrap();
    f.seek(0, 0).unwrap();
    let mut bytes = [0; 3];
    assert_eq!(f.read(&mut bytes), Ok(3));
    assert_eq!(&bytes, b"abc");
    assert_eq!(f.stat().unwrap().size, 3);
    x.fs().mkdir(b"filedep", 0o755).unwrap();
    std::fs::write(x.root.join("root/filedep/package.json"), b"{}").unwrap();
    assert_eq!(x.fs().read_dir(b"filedep").unwrap().len(), 1);
    let capability =
        cap_std::fs::Dir::open_ambient_dir(x.root.join("root"), cap_std::ambient_authority())
            .unwrap();
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    let plain = capability.open_with("filedep", &options).map(|_| ());
    eprintln!(
        "U13 directory plain open: {:?}",
        plain
            .as_ref()
            .map_err(|error| (error.kind(), error.raw_os_error()))
    );
    use cap_fs_ext::OpenOptionsMaybeDirExt;
    options.maybe_dir(true);
    let capable = capability.open_with("filedep", &options).map(|_| ());
    eprintln!(
        "U13 directory maybe_dir open: {:?}",
        capable
            .as_ref()
            .map_err(|error| (error.kind(), error.raw_os_error()))
    );
    capable.unwrap();
    for flags in [65536, 65536 | 524288 | 2048] {
        let opened = x.fs().open(b"filedep", flags, 0).map(|_| ());
        eprintln!("U13 directory Host open flags={flags}: {opened:?}");
        opened.unwrap();
    }
    assert!(matches!(x.fs().open(b"io", 65536, 0), Err(Errno::ENOTDIR)));
    assert!(matches!(
        x.fs().open(b"filedep", 65536 | 64, 0),
        Err(Errno::EINVAL)
    ));
}
#[test]
fn u13_fs_nul_rejected() {
    assert_eq!(
        Fixture::new().fs().metadata(b"nul\0path", true),
        Err(Errno::EINVAL)
    );
}
#[test]
fn u13_fs_parent_escape_denied() {
    let x = Fixture::new();
    assert!(x.fs().open(b"../outside", 0, 0).is_err());
    assert_eq!(std::fs::read(x.root.join("outside")).unwrap(), b"sentinel");
}
#[test]
fn u13_fs_symlink_hardlink() {
    let x = Fixture::new();
    x.fs().open(b"original", 66, 0o600).unwrap();
    x.fs().symlink(b"original", b"sym").unwrap();
    x.fs().link(b"original", b"hard").unwrap();
    assert_eq!(x.fs().readlink(b"sym"), Ok(b"original".to_vec()));
    assert_eq!(x.fs().metadata(b"hard", true).unwrap().links, 2);
    x.fs().mkdir(b"dependency", 0o755).unwrap();
    std::fs::write(
        x.root.join("root/dependency/package.json"),
        b"{\"version\":\"1.0.0\"}",
    )
    .unwrap();
    x.fs().symlink(b"dependency", b"dependency-link").unwrap();
    let linked = x.root.join("root/dependency-link");
    eprintln!(
        "U13 directory symlink std metadata: {:?}",
        std::fs::metadata(&linked)
    );
    eprintln!(
        "U13 directory symlink std read_dir: {:?}",
        std::fs::read_dir(&linked).map(|_| ())
    );
    eprintln!(
        "U13 directory symlink canonicalize: {:?}",
        std::fs::canonicalize(&linked)
    );
    eprintln!(
        "U13 directory symlink Host metadata: {:?}",
        x.fs().metadata(b"dependency-link", true)
    );
    eprintln!(
        "U13 directory symlink Host read_dir: {:?}",
        x.fs().read_dir(b"dependency-link")
    );
    let read = x.fs().open(b"dependency-link/package.json", 0, 0);
    eprintln!(
        "U13 directory symlink Host nested open: {:?}",
        read.as_ref().map(|_| ())
    );
    let mut bytes = [0; 19];
    assert_eq!(read.unwrap().read(&mut bytes), Ok(19));
    assert_eq!(&bytes, b"{\"version\":\"1.0.0\"}");
    x.fs().mkdir(b"links", 0o755).unwrap();
    x.fs().symlink(b"../dependency", b"links/nested").unwrap();
    assert_eq!(x.fs().read_dir(b"links/nested").unwrap().len(), 1);
    assert_eq!(
        x.fs().readlink(b"links/nested"),
        Ok(b"../dependency".to_vec())
    );
    x.fs().symlink(b"missing", b"dangling").unwrap();
    assert_eq!(x.fs().readlink(b"dangling"), Ok(b"missing".to_vec()));
    assert_eq!(x.fs().metadata(b"dangling", true), Err(Errno::ENOENT));
    x.fs().symlink(b"../outside", b"escape-link").unwrap();
    assert!(x.fs().metadata(b"escape-link", true).is_err());
    assert!(x.fs().open(b"escape-link", 0, 0).is_err());
    assert_eq!(std::fs::read(x.root.join("outside")).unwrap(), b"sentinel");
    let symlinks = [
        b"sym".as_slice(),
        b"dependency-link",
        b"links/nested",
        b"dangling",
        b"escape-link",
    ];
    let mut inodes = std::collections::BTreeSet::new();
    for name in symlinks {
        let inode = x.fs().metadata(name, false).unwrap().inode;
        eprintln!(
            "U13 symlink Host inode {}: {inode}",
            String::from_utf8_lossy(name)
        );
        assert!(
            inodes.insert(inode),
            "distinct symlinks must not alias their identity"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            // Read the link's own identity from a real handle, without
            // dereferencing its possibly dangling or out-of-root target.
            let raw = std::fs::OpenOptions::new()
                .access_mode(0x80)
                .custom_flags(0x02200000)
                .open(x.root.join("root").join(std::str::from_utf8(name).unwrap()))
                .unwrap()
                .metadata()
                .unwrap()
                .file_index();
            eprintln!(
                "U13 symlink Windows file_index {}: {raw:?}",
                String::from_utf8_lossy(name)
            );
            assert_eq!(Some(inode), raw);
        }
    }
    assert_eq!(
        x.fs().metadata(b"original", true).unwrap().inode,
        x.fs().metadata(b"hard", true).unwrap().inode
    );
    assert_eq!(
        x.fs()
            .open(b"original", 0, 0)
            .unwrap()
            .stat()
            .unwrap()
            .inode,
        x.fs().metadata(b"original", true).unwrap().inode
    );
}
#[test]
fn u13_fs_flock_contention() {
    let x = Fixture::new();
    let a = x.fs().open(b"lock", 66, 0o600).unwrap();
    let b = x.fs().open(b"lock", 2, 0).unwrap();
    a.flock(6).unwrap();
    assert_eq!(b.flock(6), Err(Errno::EAGAIN));
    a.flock(8).unwrap();
    b.flock(6).unwrap();
}
#[test]
fn u13_fs_negative_mtime() {
    let x = Fixture::new();
    let h = x.fs().open(b"mtime", 66, 0o600).unwrap();
    // Windows SetFileTime needs write access to the fixture's attributes.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(x.root.join("root/mtime"))
        .unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH - Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        x.fs().metadata(b"mtime", true).unwrap().mtime_ns,
        -1_000_000_000
    );
    assert_eq!(h.stat().unwrap().mtime_ns, -1_000_000_000);
}
