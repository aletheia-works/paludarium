use super::*;

#[test]
fn u4_kill_before_run_prevents_first_instruction() {
    let host = Arc::new(RecordingHost::new());
    let s = session(&HELLO, host.clone());
    s.kill();
    assert_eq!(s.run(), Ok(ExitStatus::Signaled(signal::SIGKILL)));
    assert!(host.stdout().is_empty());
}
#[test]
fn u4_budget_one_still_reaches_syscalls() {
    let host = Arc::new(RecordingHost::new());
    assert_eq!(
        session(&HELLO, host.clone()).with_budget(0).run(),
        Ok(ExitStatus::Exited(3))
    );
    assert_eq!(host.stdout(), b"hi\n");
}
#[test]
fn u4_default_signal_from_syscall_terminates() {
    // kill(1,SIGTERM); an exit syscall must never be reached.
    let code = [
        0xb8, 62, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 15, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    assert_eq!(
        session(&code, Arc::new(RecordingHost::new()))
            .with_budget(1)
            .run(),
        Ok(ExitStatus::Signaled(15))
    );
}
#[test]
fn u4_invalid_signal_errno_reaches_next_syscall() {
    // kill(1,65); exit_group(-return) => EINVAL.
    let code = [
        0xb8, 62, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 65, 0, 0, 0, 0x0f, 0x05, 0x48, 0xf7, 0xd8, 0x48,
        0x89, 0xc7, 0xb8, 231, 0, 0, 0, 0x0f, 0x05,
    ];
    assert_eq!(
        session(&code, Arc::new(RecordingHost::new())).run(),
        Ok(ExitStatus::Exited(22))
    );
}
#[test]
fn u4_malformed_return_terminates_without_host_panic() {
    let code = [0xb8, 15, 0, 0, 0, 0x0f, 0x05];
    assert_eq!(
        session(&code, Arc::new(RecordingHost::new())).run(),
        Ok(ExitStatus::Signaled(11))
    );
}
#[test]
fn u4_fetch_fault_records_immutable_access_kind() {
    // Jump to an unmapped canonical address.
    let code = [0xb8, 0, 0, 0, 0x70, 0xff, 0xe0];
    let s = session(&code, Arc::new(RecordingHost::new()));
    assert_eq!(s.run(), Ok(ExitStatus::Signaled(11)));
    assert!(matches!(
        s.termination_detail(),
        Some(ExitReason::PageFault {
            fetch: true,
            mapped: false,
            present: false,
            ..
        })
    ));
}
#[test]
fn u4_zero_sleep_returns_without_advancing_fake_clock() {
    let host = Arc::new(RecordingHost::new());
    let code = [
        0xb8, 35, 0, 0, 0, 0xbf, 0, 0x20, 0x40, 0, 0x31, 0xf6, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8,
        231, 0, 0, 0, 0x0f, 0x05,
    ];
    let config = Config::new("/prog", vec![]).with_file("/prog", tiny_exec(&code, &[0; 16]));
    assert_eq!(
        Session::new(config, host.clone()).unwrap().run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(host.clock(paludarium_host::ClockId::Monotonic), Ok(0));
}
#[test]
fn u4_kill_interrupts_native_wait_with_bounded_join() {
    // nanosleep(60 seconds), then exit. The wait must observe Session::kill.
    let code = [
        0xb8, 35, 0, 0, 0, 0xbf, 0, 0x20, 0x40, 0, 0x31, 0xf6, 0x0f, 0x05, 0xb8, 231, 0, 0, 0,
        0x31, 0xff, 0x0f, 0x05,
    ];
    let mut data = [0; 16];
    data[..8].copy_from_slice(&60u64.to_le_bytes());
    let config = Config::new("/prog", vec![]).with_file("/prog", tiny_exec(&code, &data));
    let s = Arc::new(Session::new(config, Arc::new(paludarium_host::NativeHost::new())).unwrap());
    let (send, receive) = std::sync::mpsc::channel();
    let worker = s.clone();
    let runner = std::thread::spawn(move || {
        send.send(worker.run()).unwrap();
    });
    std::thread::sleep(Duration::from_millis(30));
    s.kill();
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(3)).unwrap(),
        Ok(ExitStatus::Signaled(signal::SIGKILL))
    );
    runner.join().unwrap();
}
fn wait_for_stop(s: &Session) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !s.is_stopped() {
        assert!(
            std::time::Instant::now() < deadline,
            "stop checkpoint not observed"
        );
        std::thread::yield_now();
    }
}
#[test]
fn u4_stop_continue_retains_cpu_until_resumed() {
    let host = Arc::new(RecordingHost::new());
    let s = Arc::new(session(&HELLO, host.clone()).with_budget(1));
    s.signal(19).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = s.clone();
    let runner = std::thread::spawn(move || send.send(worker.run()).unwrap());
    wait_for_stop(&s);
    assert!(host.stdout().is_empty());
    assert!(receive.try_recv().is_err());
    s.signal(18).unwrap();
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(3)).unwrap(),
        Ok(ExitStatus::Exited(3))
    );
    assert_eq!(host.stdout(), b"hi\n");
    runner.join().unwrap();
    assert!(!s.is_stopped());
}
#[test]
fn u4_stopped_guest_remains_killable() {
    let s = Arc::new(session(&[0xeb, 0xfe], Arc::new(RecordingHost::new())));
    s.signal(19).unwrap();
    let worker = s.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let runner = std::thread::spawn(move || send.send(worker.run()).unwrap());
    wait_for_stop(&s);
    s.kill();
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(3)).unwrap(),
        Ok(ExitStatus::Signaled(9))
    );
    runner.join().unwrap();
}
#[test]
fn u4_pending_kill_wins_while_stopped() {
    let s = Arc::new(session(&[0xeb, 0xfe], Arc::new(RecordingHost::new())));
    s.signal(19).unwrap();
    let worker = s.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let runner = std::thread::spawn(move || send.send(worker.run()).unwrap());
    wait_for_stop(&s);
    s.signal(9).unwrap();
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(3)).unwrap(),
        Ok(ExitStatus::Signaled(9))
    );
    runner.join().unwrap();
}
