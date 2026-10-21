use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::Ordering;
const DATA: u64 = 0x600000;
#[test]
fn timer_receipt_survives_process_dispatch_and_owner_acknowledges_kind() {
    let inbox = SignalInbox::default();
    let mut other = ThreadState::default();
    inbox.timer_changed();
    inbox.drain_process(&mut other);
    assert!(inbox.wake_token().load(Ordering::SeqCst));
    let receipt = inbox.drain(&mut other);
    assert!(receipt.timer_changed);
    assert!(!receipt.interrupted);
    assert!(!inbox.wake_token().load(Ordering::SeqCst));
    inbox.timer_changed();
    inbox.interrupt();
    inbox.send_thread(10).unwrap();
    inbox.drain_process(&mut other);
    let receipt = inbox.drain(&mut other);
    assert!(receipt.timer_changed && receipt.interrupted && receipt.signals);
    let receipt = inbox.drain(&mut other);
    assert!(!receipt.timer_changed && !receipt.interrupted && !receipt.signals);
    std::thread::scope(|scope| {
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(0);
        let inbox = &inbox;
        scope.spawn(move || {
            ack_rx.recv().unwrap();
            inbox.timer_changed();
            inbox.send_thread(12).unwrap();
        });
        ack_tx.send(()).unwrap();
    });
    let receipt = inbox.drain(&mut other);
    assert!(receipt.timer_changed && receipt.signals && !receipt.interrupted);
}
#[test]
fn preentry_timer_metadata_keeps_sleep_deadline_but_real_interrupt_wins() {
    use paludarium_host::{ClockId, Host};
    for (changes, mode) in [(1, 0), (2, 0), (8, 0), (2, 1), (2, 2), (2, 3), (2, 4)] {
        let host = Arc::new(paludarium_host::testing::RecordingHost::new());
        let inbox = Arc::new(SignalInbox::default());
        let mut k = Kernel::new(host.clone()).with_signal_inbox(inbox.clone());
        k.group.register(1, inbox.clone());
        let group = k.group.clone();
        std::thread::spawn(move || {
            for i in 0..changes {
                group.set_timer(signals::RealTimer {
                    deadline: (i % 2 == 1).then_some(1_000_000_000),
                    interval: 0,
                });
            }
            group.drain_process(&mut ThreadState::default());
        })
        .join()
        .unwrap();
        if mode == 1 {
            inbox.interrupt();
        }
        assert!(inbox.wake_token().load(Ordering::SeqCst));
        let mut t = thread();
        match mode {
            2 => {
                t.state.signal_mask = 1 << 9;
                inbox.send_thread(10).unwrap();
            }
            3 => {
                t.state.signal_actions.insert(
                    10,
                    SignalAction {
                        handler: 1,
                        ..SignalAction::default()
                    },
                );
                inbox.send_thread(10).unwrap();
            }
            4 => k.group.stop(ExitStatus::Signaled(9)),
            _ => {}
        }
        let m = memory();
        m.write(GuestAddr(DATA + 8), &200_000_000u64.to_le_bytes())
            .unwrap();
        t.cpu.gpr[reg::RAX] = syscalls::nr::NANOSLEEP;
        t.cpu.gpr[reg::RDI] = DATA;
        let next = k.handle(
            &mut t,
            &m,
            ExitReason::Syscall {
                rip: GuestAddr(0x400000),
            },
        );
        if mode == 4 {
            assert!(matches!(next, Next::Exit(ExitStatus::Signaled(9))));
            continue;
        }
        assert!(matches!(next, Next::Resume));
        assert_eq!(
            t.cpu.gpr[reg::RAX],
            if mode == 1 {
                Errno(4).to_syscall_return()
            } else {
                0
            }
        );
        assert_eq!(
            host.clock(ClockId::Monotonic).unwrap(),
            if mode == 1 { 0 } else { 200_000_000 }
        );
    }
}
fn memory() -> AddressSpace {
    let mem = AddressSpace::new();
    mem.map_shared(
        Some(GuestAddr(DATA)),
        4096,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    mem
}
fn kernel() -> Kernel {
    Kernel::new(Arc::new(paludarium_host::NativeHost))
}
fn thread() -> Thread {
    Thread {
        tid: 1,
        state: ThreadState {
            pid: 1,
            ..ThreadState::default()
        },
        cpu: CpuState::default(),
    }
}
fn clone(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, flags: u64) -> u64 {
    k.thread_syscall(t, m, 56, [flags, DATA + 4096, DATA, DATA + 4, DATA + 8, 0]);
    t.cpu.gpr[reg::RAX]
}
#[test]
fn clone_registers_and_tls() {
    let mut k = kernel();
    let mut t = thread();
    t.cpu.rip = GuestAddr(0x400123);
    let m = memory();
    let tid = clone(&mut k, &mut t, &m, 0x1390900);
    assert_eq!(tid, 2);
    let (_c, ct) = k.take_child().unwrap();
    assert_eq!(ct.cpu.gpr[reg::RAX], 0);
    assert_eq!(ct.cpu.gpr[reg::RSP], DATA + 4096);
    assert_eq!(ct.cpu.fs_base, DATA + 8);
    assert_eq!(ct.cpu.rip, t.cpu.rip);
    assert_eq!(ct.state.clear_child_tid, DATA + 4);
}
#[test]
fn clone_parent_child_tid() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    let tid = clone(&mut k, &mut t, &m, 0x1310900);
    let mut b = [0; 8];
    m.read(GuestAddr(DATA), &mut b).unwrap();
    assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()) as u64, tid);
    assert_eq!(u32::from_le_bytes(b[4..].try_into().unwrap()) as u64, tid);
}
#[test]
fn clone_invalid_dependencies() {
    assert_eq!(
        clone(&mut kernel(), &mut thread(), &memory(), 0x10100),
        Errno::EINVAL.to_syscall_return()
    );
}
#[test]
fn clone_process_is_u8() {
    assert_eq!(
        clone(&mut kernel(), &mut thread(), &memory(), 0),
        Errno::ENOSYS.to_syscall_return()
    );
}
#[test]
fn clone_unknown_flags() {
    assert_eq!(
        clone(
            &mut kernel(),
            &mut thread(),
            &memory(),
            0x10900 | 0x20000000
        ),
        Errno::EINVAL.to_syscall_return()
    );
}
#[test]
fn clear_child_tid_on_finish() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x1310900);
    let (mut child, ct) = k.take_child().unwrap();
    child.finish_thread(&ct, &m);
    let mut b = [0; 4];
    m.read(GuestAddr(DATA + 4), &mut b).unwrap();
    assert_eq!(b, [0; 4]);
    assert_eq!(k.group.active_threads(), 1);
}
#[test]
fn individual_exit_does_not_stop_group() {
    let mut k = kernel();
    let mut t = thread();
    assert_eq!(
        k.thread_syscall(&mut t, &memory(), 60, [7, 0, 0, 0, 0, 0]),
        Some(Next::Exit(ExitStatus::Exited(7)))
    );
    assert_eq!(k.group.status(), None);
}
#[test]
fn exit_group_stops_all() {
    let mut k = kernel();
    let mut t = thread();
    k.thread_syscall(&mut t, &memory(), 231, [17, 0, 0, 0, 0, 0]);
    assert_eq!(k.group.status(), Some(ExitStatus::Exited(17)));
}
#[test]
fn futex_mismatch() {
    assert!(matches!(
        futex::Futexes::default().register(&memory(), DATA, false, 1, 1),
        Err(Errno::EAGAIN)
    ));
}
#[test]
fn futex_fault() {
    assert!(matches!(
        futex::Futexes::default().register(&memory(), 0, false, 0, 1),
        Err(Errno::EFAULT)
    ));
}
#[test]
fn futex_alignment() {
    assert!(matches!(
        futex::Futexes::default().register(&memory(), DATA + 1, false, 0, 1),
        Err(Errno::EINVAL)
    ));
}
#[test]
fn futex_empty_mask() {
    assert!(matches!(
        futex::Futexes::default().register(&memory(), DATA, false, 0, 0),
        Err(Errno::EINVAL)
    ));
}
#[test]
fn futex_bitset_selects_waiter() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    let b = f.register(&m, DATA, true, 0, 2).unwrap();
    assert_eq!(f.wake(&m, DATA, true, 1, 2), Ok(1));
    assert_eq!(a.state.load(Ordering::SeqCst), 0);
    assert_eq!(b.state.load(Ordering::SeqCst), 1);
    assert_eq!(f.wake(&m, DATA, true, 1, 1), Ok(1));
}
#[test]
fn futex_private_shared_keys() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    assert_eq!(f.wake(&m, DATA, false, 1, 1), Ok(0));
    assert_eq!(a.state.load(Ordering::SeqCst), 0);
    assert_eq!(f.wake(&m, DATA, true, 1, 1), Ok(1));
}
#[test]
fn futex_wake_before_host_wait_retained() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    f.wake(&m, DATA, true, 1, 1).unwrap();
    assert_eq!(a.token.value(), 1);
    assert_eq!(f.finish(&m, DATA, true, &a, 2), 1);
}
#[test]
fn futex_timeout_wins_once() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    assert_eq!(f.finish(&m, DATA, true, &a, 2), 2);
    assert_eq!(f.wake(&m, DATA, true, 1, 1), Ok(0));
    assert_eq!(f.finish(&m, DATA, true, &a, 3), 2);
}

#[test]
fn tkill_transport_preserves_code_and_thread_target() {
    for number in [200, 234] {
        let mut k = kernel();
        let mut t = thread();
        let m = memory();
        t.state.signal_mask = 1 << 35;
        t.cpu.gpr[reg::RAX] = number;
        t.cpu.gpr[reg::RDI] = 1;
        t.cpu.gpr[reg::RSI] = if number == 200 { 36 } else { 1 };
        t.cpu.gpr[reg::RDX] = 36;
        assert_eq!(
            k.handle(
                &mut t,
                &m,
                ExitReason::Syscall {
                    rip: GuestAddr(0x400000)
                }
            ),
            Next::Resume
        );
        assert_eq!(t.state.pending.len(), 1);
        assert_eq!(t.state.pending[0].target, signals::PendingTarget::Thread);
        assert_eq!(t.state.pending[0].code, -6);
    }
}

#[test]
fn process_dispatch_does_not_steal_initial_thread_signal() {
    let inbox = Arc::new(SignalInbox::default());
    let k = kernel().with_signal_inbox(inbox.clone());
    let mut child = ThreadState::default();
    inbox.send_thread(36).unwrap();
    inbox.send(35).unwrap();
    k.group.drain_process(&mut child);
    assert_eq!(child.pending.len(), 1);
    assert_eq!(child.pending[0].number, 35);
    let mut initial = ThreadState::default();
    inbox.drain(&mut initial);
    assert_eq!(initial.pending.len(), 1);
    assert_eq!(initial.pending[0].number, 36);
    assert_eq!(initial.pending[0].target, signals::PendingTarget::Thread);
    assert_eq!(initial.pending[0].code, -6);
}

#[test]
fn process_signal_interrupts_registered_child_wait_token() {
    let inbox = Arc::new(SignalInbox::default());
    let k = kernel().with_signal_inbox(inbox.clone());
    let child = Arc::new(SignalInbox::default());
    k.group.register(2, child.clone());
    inbox.send(35).unwrap();
    assert!(child.wake_token().load(Ordering::SeqCst));
    let mut child_state = ThreadState::default();
    child.drain(&mut child_state);
    k.group.drain_process(&mut child_state);
    assert_eq!(child_state.pending.len(), 1);
    assert_eq!(child_state.pending[0].number, 35);
    assert_eq!(
        child_state.pending[0].target,
        signals::PendingTarget::Process
    );
}

/// The first Host wait acknowledges entry before the other worker changes the
/// timer. No wall-clock sleep is used to infer guest/Host scheduling.
struct EnteredWaitHost {
    inner: paludarium_host::testing::RecordingHost,
    first: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<u64>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl paludarium_host::Host for EnteredWaitHost {
    fn clock(&self, clock: paludarium_host::ClockId) -> Result<u64, Errno> {
        self.inner.clock(clock)
    }
    fn wait_until(
        &self,
        clock: paludarium_host::ClockId,
        deadline: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<paludarium_host::WaitOutcome, Errno> {
        if self.first.swap(false, Ordering::SeqCst) {
            self.entered.send(deadline).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            assert!(
                cancel.load(Ordering::SeqCst),
                "timer update must wake the sleeping worker"
            );
        }
        self.inner.wait_until(clock, deadline, cancel)
    }
    fn wait_on(
        &self,
        token: &paludarium_host::WaitToken,
        expected: u32,
        deadline: Option<(paludarium_host::ClockId, u64)>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<paludarium_host::WaitOutcome, Errno> {
        self.entered.send(deadline.unwrap().1).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        if self.first.swap(false, Ordering::SeqCst) {
            assert!(cancel.load(Ordering::SeqCst));
        }
        paludarium_host::Host::wait_on(
            &paludarium_host::NativeHost,
            token,
            expected,
            deadline,
            cancel,
        )
    }
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.inner.read_stdin(buf)
    }
    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.inner.write_stdout(buf)
    }
    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.inner.write_stderr(buf)
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), paludarium_types::Error> {
        self.inner.random_bytes(buf)
    }
}
fn change_timer_after_host_wait(initial: Option<u64>, replacement: Option<u64>) {
    use paludarium_host::{ClockId, Host};
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let host = Arc::new(EnteredWaitHost {
        inner: paludarium_host::testing::RecordingHost::new(),
        first: std::sync::atomic::AtomicBool::new(true),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let inbox = Arc::new(SignalInbox::default());
    let mut k = Kernel::new(host.clone()).with_signal_inbox(inbox.clone());
    let group = k.group.clone();
    group.set_timer(signals::RealTimer {
        deadline: initial,
        interval: 0,
    });
    let mut t = thread();
    inbox.drain(&mut t.state);
    let m = memory();
    m.write(GuestAddr(DATA), &2u64.to_le_bytes()).unwrap();
    t.cpu.gpr[reg::RAX] = syscalls::nr::NANOSLEEP;
    t.cpu.gpr[reg::RDI] = DATA;
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let next = k.handle(
            &mut t,
            &m,
            ExitReason::Syscall {
                rip: GuestAddr(0x400000),
            },
        );
        done_tx.send((next, t.cpu.gpr[reg::RAX])).unwrap();
    });
    assert_eq!(
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap(),
        initial.unwrap_or(2_000_000_000)
    );
    host.inner.set_clock(ClockId::Monotonic, 50_000_000);
    group.set_timer(signals::RealTimer {
        deadline: replacement,
        interval: 0,
    });
    // The timer-setting child's next checkpoint also drains process signals.
    // It must not acknowledge the sleeping parent's control notification.
    group.drain_process(&mut ThreadState::default());
    release_tx.send(()).unwrap();
    let (next, value) = done_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    worker.join().unwrap();
    if let Some(deadline) = replacement {
        assert_eq!(next, Next::Exit(ExitStatus::Signaled(14)));
        assert_eq!(host.clock(ClockId::Monotonic), Ok(deadline));
    } else {
        assert_eq!(next, Next::Resume);
        assert_eq!(value, 0, "cancellation notification alone is not EINTR");
        assert_eq!(host.clock(ClockId::Monotonic), Ok(2_000_000_000));
    }
}
#[test]
fn timer_set_recomputes_existing_host_sleep() {
    change_timer_after_host_wait(None, Some(100_000_000));
}
#[test]
fn timer_shorten_recomputes_existing_host_sleep() {
    change_timer_after_host_wait(Some(1_500_000_000), Some(100_000_000));
}
#[test]
fn timer_cancel_notification_does_not_interrupt_sleep() {
    change_timer_after_host_wait(Some(100_000_000), None);
}

#[test]
fn timer_notification_does_not_interrupt_futex_wait() {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let host = Arc::new(EnteredWaitHost {
        inner: paludarium_host::testing::RecordingHost::new(),
        first: std::sync::atomic::AtomicBool::new(true),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let mut k = Kernel::new(host).with_signal_inbox(Arc::new(SignalInbox::default()));
    let group = k.group.clone();
    let m = Arc::new(memory());
    let worker_mem = m.clone();
    let mut t = thread();
    t.cpu.gpr[reg::RAX] = 202;
    t.cpu.gpr[reg::RDI] = DATA;
    t.cpu.gpr[reg::RSI] = 128;
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        k.handle(
            &mut t,
            &worker_mem,
            ExitReason::Syscall {
                rip: GuestAddr(0x400000),
            },
        );
        done_tx.send(t.cpu.gpr[reg::RAX]).unwrap();
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    group.set_timer(signals::RealTimer::default());
    release_tx.send(()).unwrap();
    // Re-entry proves the metadata wake did not return EINTR to the guest.
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    assert_eq!(group.futexes.wake(&m, DATA, true, 1, u32::MAX), Ok(1));
    release_tx.send(()).unwrap();
    assert_eq!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap(),
        0
    );
    worker.join().unwrap();
}

#[test]
fn timer_notification_does_not_interrupt_flock_wait() {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let host = Arc::new(EnteredWaitHost {
        inner: paludarium_host::testing::RecordingHost::new(),
        first: std::sync::atomic::AtomicBool::new(true),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let mut k = Kernel::new(host).with_signal_inbox(Arc::new(SignalInbox::default()));
    let blocker = k.files.fs.open(b"/lock", 0x42, 0o600).unwrap();
    blocker.flock(2).unwrap();
    let group = k.group.clone();
    let m = memory();
    m.write(GuestAddr(DATA), b"/lock\0").unwrap();
    let mut t = thread();
    t.cpu.gpr[reg::RAX] = 2;
    t.cpu.gpr[reg::RDI] = DATA;
    k.handle(
        &mut t,
        &m,
        ExitReason::Syscall {
            rip: GuestAddr(0x400000),
        },
    );
    let fd = t.cpu.gpr[reg::RAX];
    assert!((3..100).contains(&fd));
    t.cpu.gpr[reg::RAX] = 73;
    t.cpu.gpr[reg::RDI] = fd;
    t.cpu.gpr[reg::RSI] = 2;
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        k.handle(
            &mut t,
            &m,
            ExitReason::Syscall {
                rip: GuestAddr(0x400000),
            },
        );
        done_tx.send(t.cpu.gpr[reg::RAX]).unwrap();
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    group.set_timer(signals::RealTimer::default());
    blocker.flock(8).unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap(),
        0
    );
    worker.join().unwrap();
}

#[test]
fn futex_signal_frame_restarts_only_untimed_sa_restart() {
    for op in [128, 137, 393] {
        for timed in [false, true] {
            for restart in [false, true] {
                let mut k = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
                let m = memory();
                m.write(GuestAddr(DATA + 16), &1u64.to_le_bytes()).unwrap();
                let mut t = thread();
                t.state.signal_actions.insert(
                    10,
                    SignalAction {
                        handler: DATA + 64,
                        flags: 0x0400_0000 | if restart { 0x1000_0000 } else { 0 },
                        restorer: DATA + 80,
                        mask: 0,
                    },
                );
                k.queue_signal(&mut t, 10).unwrap();
                t.cpu.rip = GuestAddr(DATA + 122);
                t.cpu.gpr[reg::RSP] = DATA + 4096;
                t.cpu.gpr[reg::RAX] = 202;
                t.cpu.gpr[reg::RDI] = DATA;
                t.cpu.gpr[reg::RSI] = op;
                t.cpu.gpr[reg::R10] = if timed { DATA + 16 } else { 0 };
                t.cpu.gpr[reg::R9] = 1;
                assert_eq!(
                    k.handle(
                        &mut t,
                        &m,
                        ExitReason::Syscall {
                            rip: GuestAddr(DATA + 120)
                        }
                    ),
                    Next::Resume
                );
                let saved = &t.state.frames.last().unwrap().cpu;
                assert_eq!(
                    saved.rip,
                    GuestAddr(DATA + if restart && !timed { 120 } else { 122 })
                );
                assert_eq!(
                    saved.gpr[reg::RAX],
                    if restart && !timed {
                        202
                    } else {
                        Errno(4).to_syscall_return()
                    }
                );
            }
        }
    }
}
