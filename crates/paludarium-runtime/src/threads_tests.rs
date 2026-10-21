#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_host::{ThreadHandle, testing::RecordingHost};
use paludarium_loader::testing::tiny_exec;
use paludarium_types::Errno;
use std::sync::atomic::AtomicU32;

struct CountingHost {
    record: RecordingHost,
    spawns: AtomicU32,
    fail: bool,
}
impl CountingHost {
    fn new(fail: bool) -> Self {
        Self {
            record: RecordingHost::new(),
            spawns: AtomicU32::new(0),
            fail,
        }
    }
}
impl Host for CountingHost {
    fn read_stdin(&self, b: &mut [u8]) -> Result<usize, Errno> {
        self.record.read_stdin(b)
    }
    fn write_stdout(&self, b: &[u8]) -> Result<usize, Errno> {
        self.record.write_stdout(b)
    }
    fn write_stderr(&self, b: &[u8]) -> Result<usize, Errno> {
        self.record.write_stderr(b)
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), Error> {
        self.record.random_bytes(b)
    }
    fn clock(&self, c: paludarium_host::ClockId) -> Result<u64, Errno> {
        paludarium_host::NativeHost.clock(c)
    }
    fn wait_until(
        &self,
        c: paludarium_host::ClockId,
        d: u64,
        x: &AtomicBool,
    ) -> Result<paludarium_host::WaitOutcome, Errno> {
        paludarium_host::NativeHost.wait_until(c, d, x)
    }
    fn spawn_thread(&self, t: Box<dyn FnOnce() + Send>) -> Result<Box<dyn ThreadHandle>, Errno> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(Errno::ENOSYS)
        } else {
            paludarium_host::NativeHost.spawn_thread(t)
        }
    }
}
fn session(code: &[u8], host: Arc<CountingHost>) -> Session {
    Session::new(
        Config::new("/p", vec![]).with_file("/p", tiny_exec(code, b"X")),
        host,
    )
    .unwrap()
    .with_budget(100)
}
// raw clone(0x10900,0,0,0,0); test rax,rax; jz child; parent exit(0).
fn clone_code(child: &[u8]) -> Vec<u8> {
    let mut code = vec![
        0xb8, 56, 0, 0, 0, 0xbf, 0, 9, 1, 0, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0x45, 0x31,
        0xc0, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 9, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
    ];
    code.extend_from_slice(child);
    code
}
const EXIT0: &[u8] = &[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
#[test]
fn parent_exit_waits_for_worker() {
    let h = Arc::new(CountingHost::new(false));
    let child = [
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0, 0x20, 0x40, 0, 0xba, 1, 0, 0, 0, 0x0f, 0x05,
    ];
    let mut c = child.to_vec();
    c.extend_from_slice(EXIT0);
    assert_eq!(
        session(&clone_code(&c), h.clone()).run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(h.record.stdout(), b"X");
    assert_eq!(h.spawns.load(Ordering::SeqCst), 1);
}
#[test]
fn worker_exit_joins() {
    let h = Arc::new(CountingHost::new(false));
    assert_eq!(
        session(&clone_code(EXIT0), h.clone()).run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(h.spawns.load(Ordering::SeqCst), 1);
}
#[test]
fn failed_spawn_reclaims_registry() {
    let h = Arc::new(CountingHost::new(true));
    assert_eq!(
        session(&clone_code(EXIT0), h.clone()).run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(h.spawns.load(Ordering::SeqCst), 1);
}
#[test]
fn kill_cleans_live_worker() {
    let h = Arc::new(CountingHost::new(false));
    let s = Arc::new(session(&clone_code(&[0xeb, 0xfe]), h.clone()));
    let run = s.clone();
    let handle = paludarium_host::NativeHost
        .spawn_thread(Box::new(move || {
            assert_eq!(run.run(), Ok(ExitStatus::Signaled(signal::SIGKILL)))
        }))
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while h.spawns.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::hint::spin_loop();
    }
    s.kill();
    handle.join().unwrap();
}
#[test]
fn child_fault_stops_group() {
    let h = Arc::new(CountingHost::new(false));
    assert_eq!(
        session(&clone_code(&[0x0f, 0x0b]), h).run(),
        Ok(ExitStatus::Signaled(signal::SIGILL))
    );
}
#[test]
fn repeated_sessions_join_workers() {
    for _ in 0..8 {
        let h = Arc::new(CountingHost::new(false));
        assert_eq!(
            session(&clone_code(EXIT0), h).run(),
            Ok(ExitStatus::Exited(0))
        );
    }
}
