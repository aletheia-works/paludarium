use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_loader::testing::tiny_exec;
use paludarium_vfs::FileSystem;
use std::time::Duration;

/// write(1, DATA, 3); exit_group(3)
const HELLO: [u8; 34] = [
    0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0x00, 0x20, 0x40, 0x00, 0xba, 3, 0, 0, 0, 0x0f, 0x05,
    0xb8, 231, 0, 0, 0, 0xbf, 3, 0, 0, 0, 0x0f, 0x05,
];

fn session(code: &[u8], host: Arc<RecordingHost>) -> Session {
    let config = Config::new("/prog", vec![b"prog".to_vec()])
        .with_env("A", "1")
        .with_file("/prog", tiny_exec(code, b"hi\n"));
    Session::new(config, host).unwrap()
}

#[test]
fn runs_a_program_to_exit_and_captures_output() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&HELLO, host.clone());
    assert_eq!(s.run(), Ok(ExitStatus::Exited(3)));
    assert_eq!(host.stdout(), b"hi\n");
    assert_eq!(s.termination_detail(), None);
}

#[test]
fn u14_runtime_cache_fallback_preserves_syscall_output_and_exit() {
    struct Fallback(std::sync::atomic::AtomicUsize);
    impl CodeCache for Fallback {
        fn try_run(
            &self,
            _: &mut paludarium_cpu::CpuState,
            _: &AddressSpace,
        ) -> Option<ExitReason> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
        fn invalidate(&self, _: paludarium_types::GuestAddr) {}
    }
    let host = Arc::new(RecordingHost::new());
    let cache = Arc::new(Fallback(std::sync::atomic::AtomicUsize::new(0)));
    let s = session(&HELLO, host.clone()).with_code_cache(cache.clone());
    assert_eq!(s.run(), Ok(ExitStatus::Exited(3)));
    assert_eq!(host.stdout(), b"hi\n");
    assert!(cache.0.load(Ordering::Relaxed) > 0);
    assert_eq!(s.termination_detail(), None);
}

#[test]
fn u14_runtime_default_and_explicit_fallback_preserve_fault_detail() {
    for explicit_cache in [false, true] {
        let host = Arc::new(RecordingHost::new());
        let s = session(&[0x0f, 0x0b], host);
        let s = if explicit_cache {
            s.with_code_cache(Arc::new(NoopCodeCache))
        } else {
            s
        };
        assert_eq!(s.run(), Ok(ExitStatus::Signaled(signal::SIGILL)));
        assert!(matches!(
            s.termination_detail(),
            Some(ExitReason::InvalidOpcode { .. })
        ));
    }
}

#[test]
fn guest_exceptions_become_signals() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&[0x0f, 0x0b], host.clone());
    assert_eq!(s.run(), Ok(ExitStatus::Signaled(signal::SIGILL)));
    assert!(matches!(
        s.termination_detail(),
        Some(ExitReason::InvalidOpcode { .. })
    ));
    let s = session(&[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0], host.clone());
    assert_eq!(s.run(), Ok(ExitStatus::Signaled(signal::SIGSEGV)));
    let s = session(&[0xf4], host);
    assert_eq!(s.run(), Ok(ExitStatus::Signaled(signal::SIGSEGV)));
}

#[test]
fn kill_stops_an_endless_guest_at_a_budget_boundary() {
    let host = Arc::new(RecordingHost::new());
    let s = Arc::new(session(&[0xeb, 0xfe], host).with_budget(1000));
    let runner = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.run())
    };
    std::thread::sleep(Duration::from_millis(50));
    s.kill();
    let result = runner.join().unwrap();
    assert_eq!(result, Ok(ExitStatus::Signaled(signal::SIGKILL)));
}

#[test]
fn rejects_unsupported_host_mounts_and_missing_programs() {
    let host: Arc<dyn Host> = Arc::new(RecordingHost::new());
    let mut config = Config::new("/prog", vec![]);
    config.mounts.push(Mount {
        host: PathBuf::from("."),
        guest: b"/mnt".to_vec(),
    });
    let err = Session::new(config, host.clone()).err().unwrap();
    assert_eq!(err.kind, ErrorKind::Host);
    assert_eq!(
        Session::new(Config::new("", vec![]), host.clone())
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidProgram
    );
    let missing = Session::new(Config::new("/nothing", vec![]), host.clone()).unwrap();
    assert_eq!(missing.run().unwrap_err().kind, ErrorKind::InvalidProgram);
}

#[test]
fn invalid_programs_and_file_placements_are_errors() {
    let host: Arc<dyn Host> = Arc::new(RecordingHost::new());
    let config = Config::new("/prog", vec![]).with_file("/prog", b"#!/bin/sh\n".to_vec());
    let err = Session::new(config, host.clone())
        .unwrap()
        .run()
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidProgram);
    let config = Config::new("/prog", vec![]).with_file("relative", b"x".to_vec());
    let err = Session::new(config, host).unwrap().run().unwrap_err();
    assert_eq!(err.message, "invalid file placement");
}

#[test]
fn environment_reaches_the_guest_stack() {
    // The guest reads envp[0] ("A=1") from the initial stack and writes it:
    // mov rsi, [rsp+24] (argc=1, argv[0], NULL, envp[0]); write(1, rsi, 3); exit_group(0)
    let code = [
        0x48, 0x8b, 0x74, 0x24, 0x18, 0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xba, 3, 0, 0, 0, 0x0f,
        0x05, 0xb8, 231, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
    ];
    let host = Arc::new(RecordingHost::new());
    assert_eq!(
        session(&code, host.clone()).run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(host.stdout(), b"A=1");
}
#[path = "signals_time_tests.rs"]
mod signals_time_tests;

#[test]
fn u7_runtime_preload() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&HELLO, host);
    let fs = s.file_system().unwrap();
    assert_eq!(
        &*fs.read_file(b"/prog").unwrap(),
        tiny_exec(&HELLO, b"hi\n")
    );
}
#[test]
fn u7_runtime_default_private() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&HELLO, host);
    assert!(
        s.file_system()
            .unwrap()
            .metadata(b"/etc/passwd", true)
            .is_err()
    );
}
#[test]
fn u7_runtime_tmp() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&HELLO, host);
    assert_eq!(
        s.file_system()
            .unwrap()
            .metadata(b"/tmp", true)
            .unwrap()
            .mode
            & 0o170000,
        0o040000
    );
}
#[test]
fn u7_runtime_mount() {
    let path = std::env::temp_dir().join(format!("paludarium-runtime-u7-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("a"), b"hello").unwrap();
    let mut config = Config::new("/prog", vec![]).with_file("/prog", tiny_exec(&HELLO, b"hi\n"));
    config.mounts.push(Mount {
        host: path.clone(),
        guest: b"/mnt".to_vec(),
    });
    let s = Session::new(config, Arc::new(paludarium_host::NativeHost::new())).unwrap();
    let fs = s.file_system().unwrap();
    assert_eq!(&*fs.read_file(b"/mnt/a").unwrap(), b"hello");
    fs.open(b"/mnt/b", 66, 0o600)
        .unwrap()
        .write(b"world")
        .unwrap();
    assert_eq!(std::fs::read(path.join("b")).unwrap(), b"world");
    drop(fs);
    drop(s);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn u7_runtime_missing_mount_root() {
    let mut c = Config::new("/prog", vec![]);
    c.mounts.push(Mount {
        host: PathBuf::from("/paludarium-u7-does-not-exist"),
        guest: b"/mnt".to_vec(),
    });
    assert!(Session::new(c, Arc::new(paludarium_host::NativeHost::new())).is_err());
}
#[test]
fn u7_runtime_duplicate_mount() {
    let mut c = Config::new("/prog", vec![]);
    for _ in 0..2 {
        c.mounts.push(Mount {
            host: std::env::temp_dir(),
            guest: b"/mnt".to_vec(),
        });
    }
    assert!(Session::new(c, Arc::new(paludarium_host::NativeHost::new())).is_err());
}
#[test]
fn u7_runtime_invalid_placement() {
    let c = Config::new("/prog", vec![]).with_file(b"/bad\0".to_vec(), vec![]);
    let s = Session::new(c, Arc::new(RecordingHost::new())).unwrap();
    assert!(s.file_system().is_err());
}
#[test]
fn u7_runtime_cross_mount() {
    let root = std::env::temp_dir().join(format!("paludarium-u7-cross-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut fs = MountedFs::new(MemFs::new());
    fs.mount(
        b"/mnt".to_vec(),
        Arc::new(paludarium_host::NativeFs::new(&root).unwrap()),
    )
    .unwrap();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.link(b"/a", b"/mnt/a"), Err(paludarium_types::Errno(18)));
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    drop(fs);
    std::fs::remove_dir(&root).unwrap();
}
