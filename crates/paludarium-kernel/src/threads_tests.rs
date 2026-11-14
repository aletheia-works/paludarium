use super::*;
use crate::credentials::TaskIds;
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
    inbox.send_thread(10, 0).unwrap();
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
            inbox.send_thread(12, 0).unwrap();
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
                inbox.send_thread(10, 0).unwrap();
            }
            3 => {
                t.state.signal_actions.insert(
                    10,
                    SignalAction {
                        handler: 1,
                        ..SignalAction::default()
                    },
                );
                inbox.send_thread(10, 0).unwrap();
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
/// A signal sent to the process after its last checkpoint and before it
/// sleeps ends the sleep at once: the sleep takes it in while it expires the
/// timers, which clears the wake the host wait watches, so it must not wait
/// first. GNU parallel kills its `sleep 10101` placeholders in this window.
#[test]
fn a_signal_sent_before_a_sleep_ends_it_without_waiting() {
    use paludarium_host::{ClockId, Host};
    for (number, handled) in [(9, false), (15, false), (10, true)] {
        let host = Arc::new(paludarium_host::testing::RecordingHost::new());
        let inbox = Arc::new(SignalInbox::default());
        let mut k = Kernel::new(host.clone()).with_signal_inbox(inbox.clone());
        k.group.register(1, inbox.clone());
        let mut t = thread();
        if handled {
            let action = SignalAction {
                handler: 0x401000,
                ..SignalAction::default()
            };
            t.state.signal_actions.insert(number, action);
            k.group.set_action(number, action);
        }
        k.group
            .send_process_signal(signals::PendingSignal::user(number, 0))
            .unwrap();
        let m = memory();
        m.write(GuestAddr(DATA), &10_101u64.to_le_bytes()).unwrap();
        t.cpu.gpr[reg::RAX] = syscalls::nr::CLOCK_NANOSLEEP;
        t.cpu.gpr[reg::RDX] = DATA;
        t.cpu.gpr[reg::RSP] = DATA + 4096;
        let next = k.handle(
            &mut t,
            &m,
            ExitReason::Syscall {
                rip: GuestAddr(0x400000),
            },
        );
        assert_eq!(
            host.clock(ClockId::Monotonic).unwrap(),
            0,
            "signal {number}"
        );
        if handled {
            assert!(matches!(next, Next::Resume), "signal {number}");
            assert_eq!(t.cpu.rip, GuestAddr(0x401000), "signal {number}");
        } else {
            assert!(
                matches!(next, Next::Exit(ExitStatus::Signaled(n)) if n == number),
                "signal {number}"
            );
        }
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
/// A robust list at `DATA + 0x100` with `entries` at the given addresses, each
/// followed 8 bytes on by its futex word.
fn robust_list(m: &AddressSpace, entries: &[u64], pending: u64) -> u64 {
    let head = DATA + 0x100;
    let mut at = head;
    for entry in entries {
        m.write_u64(GuestAddr(at), *entry).unwrap();
        at = *entry & !1;
    }
    m.write_u64(GuestAddr(at), head).unwrap();
    m.write_u64(GuestAddr(head + 8), 8).unwrap();
    m.write_u64(GuestAddr(head + 16), pending).unwrap();
    head
}
fn word(m: &AddressSpace, addr: u64) -> u32 {
    let mut bytes = [0; 4];
    m.read(GuestAddr(addr), &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}
fn set_word(m: &AddressSpace, addr: u64, value: u32) {
    m.write(GuestAddr(addr), &value.to_le_bytes()).unwrap();
}
#[test]
fn an_ending_thread_marks_the_robust_futexes_it_owned() {
    const DIED: u32 = 0x4000_0000;
    const WAITERS: u32 = 0x8000_0000;
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x1310900);
    let (mut child, ct) = k.take_child().unwrap();
    let (a, b, c, d) = (DATA + 0x200, DATA + 0x300, DATA + 0x400, DATA + 0x500);
    set_word(&m, a + 8, ct.tid);
    set_word(&m, b + 8, ct.tid | WAITERS | DIED);
    set_word(&m, c + 8, ct.tid + 1);
    set_word(&m, d + 8, ct.tid);
    let head = robust_list(&m, &[a, b, c], d);
    child.group.set_robust_list(ct.tid, head);
    assert_eq!(child.group.robust_list(ct.tid), Some(head));
    child.finish_thread(&ct, &m);
    assert_eq!(word(&m, a + 8), DIED);
    assert_eq!(word(&m, b + 8), DIED | WAITERS);
    assert_eq!(word(&m, c + 8), ct.tid + 1, "another's");
    assert_eq!(word(&m, d + 8), DIED, "pending");
    assert_eq!(k.group.robust_list(ct.tid), None);
}
#[test]
fn a_robust_list_stops_where_it_cannot_be_read() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x1310900);
    let (mut child, ct) = k.take_child().unwrap();
    let (a, b) = (DATA + 0x200, DATA + 0x300);
    set_word(&m, b + 8, ct.tid);
    // A misaligned futex word ends the walk, so nothing after it is marked.
    let head = robust_list(&m, &[a, b], 0);
    m.write_u64(GuestAddr(head + 8), 9).unwrap();
    child.group.set_robust_list(ct.tid, head);
    child.finish_thread(&ct, &m);
    assert_eq!(word(&m, b + 8), ct.tid);
}
#[test]
fn a_robust_list_made_into_a_ring_ends_at_the_limit() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x1310900);
    let (mut child, ct) = k.take_child().unwrap();
    let a = DATA + 0x200;
    let head = robust_list(&m, &[a], 0);
    m.write_u64(GuestAddr(a), a).unwrap();
    set_word(&m, a + 8, ct.tid);
    child.group.set_robust_list(ct.tid, head);
    child.finish_thread(&ct, &m);
    assert_eq!(word(&m, a + 8), 0x4000_0000);
}
#[test]
fn a_released_pending_robust_futex_is_left_at_zero() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x1310900);
    let (mut child, ct) = k.take_child().unwrap();
    let a = DATA + 0x200;
    let head = robust_list(&m, &[], a);
    child.group.set_robust_list(ct.tid, head);
    child.finish_thread(&ct, &m);
    assert_eq!(word(&m, a + 8), 0);
}
#[test]
fn a_finished_thread_leaves_no_task_ids_behind() {
    let mut k = kernel();
    let mut t = thread();
    let m = memory();
    clone(&mut k, &mut t, &m, 0x10900);
    let (mut child, ct) = k.take_child().unwrap();
    let pid = k.process.pid;
    let leader = k.group.task_ids(pid, pid);
    let other = TaskIds {
        uid: 2000,
        euid: 2000,
        suid: 2000,
        ..TaskIds::default()
    };
    k.group.set_task_ids(ct.tid, other.clone());
    assert_eq!(k.group.task_ids(pid, ct.tid), other);
    // A thread's ID names that thread, as `capget` finds it.
    assert_eq!(k.processes.task_ids(ct.tid), Some(other));
    child.finish_thread(&ct, &m);
    assert_eq!(k.group.task_ids(pid, ct.tid), leader);
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
fn futex_shared_memory_keys_reach_other_spaces() {
    // One page of shared memory, at different addresses in two spaces.
    let pages = paludarium_mmu::SharedPages::new();
    let spaces = [(0x600000, 0), (0x700000, 0)].map(|(at, offset)| {
        let mem = AddressSpace::new();
        mem.map_shared(
            Some(GuestAddr(at)),
            4096,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        mem.share_pages(
            GuestAddr(at),
            4096,
            &pages,
            offset,
            paludarium_mmu::SharedWrites::Allowed,
        )
        .unwrap();
        mem
    });
    let f = futex::Futexes::default();
    let a = f
        .register(&spaces[0], 0x600008, false, 0, u32::MAX)
        .unwrap();
    // A private wake names the waker's own space, as Linux's does.
    assert_eq!(f.wake(&spaces[1], 0x700008, true, 1, u32::MAX), Ok(0));
    assert_eq!(f.wake(&spaces[1], 0x700004, false, 1, u32::MAX), Ok(0));
    assert_eq!(f.wake(&spaces[1], 0x700008, false, 1, u32::MAX), Ok(1));
    assert_eq!(a.state.load(Ordering::SeqCst), 1);
    // Private memory keeps its words apart per space.
    let b = f.register(&memory(), DATA, false, 0, u32::MAX).unwrap();
    assert_eq!(f.wake(&memory(), DATA, false, 1, u32::MAX), Ok(0));
    assert_eq!(f.finish(&b, 2), 2);
}
#[test]
fn futex_wake_before_host_wait_retained() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    f.wake(&m, DATA, true, 1, 1).unwrap();
    assert_eq!(a.token.value(), 1);
    assert_eq!(f.finish(&a, 2), 1);
}
#[test]
fn futex_timeout_wins_once() {
    let m = memory();
    let f = futex::Futexes::default();
    let a = f.register(&m, DATA, true, 0, 1).unwrap();
    assert_eq!(f.finish(&a, 2), 2);
    assert_eq!(f.wake(&m, DATA, true, 1, 1), Ok(0));
    assert_eq!(f.finish(&a, 3), 2);
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
    inbox.send_thread(36, 0).unwrap();
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
#[test]
fn a_waiting_thread_sees_a_handler_set_after_it_began_waiting() {
    let group = ThreadGroup::default();
    // The waiter's copy of the actions predates the handler.
    let mut waiter = ThreadState::default();
    group.set_action(
        signals::SIGCHLD,
        SignalAction {
            handler: 0x1000,
            ..SignalAction::default()
        },
    );
    group.send_process_from(signals::SIGCHLD, 2, 0).unwrap();
    group.drain_process(&mut waiter);
    assert!(signals::next_pending(&waiter, true).is_some());
}
#[test]
fn every_thread_learns_of_a_process_signal_another_took() {
    let group = ThreadGroup::default();
    let (mut taker, mut other) = (ThreadState::default(), ThreadState::default());
    // Nothing sent yet.
    assert!(!group.drain_process(&mut taker));
    assert!(!group.drain_process(&mut other));
    group.send_process_from(signals::SIGCHLD, 2, 0).unwrap();
    // One thread takes the ignored SIGCHLD in; the other still learns that
    // a signal came, which is what woke it, so that its wait goes on.
    assert!(group.drain_process(&mut taker));
    assert!(group.drain_process(&mut other));
    assert!(signals::next_pending(&other, true).is_none());
    assert!(signals::next_pending(&taker, true).is_none());
    // Once each, until another comes.
    assert!(!group.drain_process(&mut taker));
    assert!(!group.drain_process(&mut other));
}
#[test]
fn futex_wake_counts_before_it_compares() {
    let m = memory();
    let f = futex::Futexes::default();
    let waiters: Vec<_> = (0..3)
        .map(|_| f.register(&m, DATA, true, 0, u32::MAX).unwrap())
        .collect();
    // Linux's `++ret >= nr_wake`: 0 and -1 wake one each.
    assert_eq!(f.wake(&m, DATA, true, 0, u32::MAX), Ok(1));
    assert_eq!(f.wake(&m, DATA, true, -1, u32::MAX), Ok(1));
    // futex2's strict wake of 0 wakes none.
    assert_eq!(f.wake_word(&m, DATA, true, false, 0, u32::MAX, true), Ok(0));
    assert_eq!(waiters[2].state.load(Ordering::SeqCst), 0);
    assert_eq!(f.wake(&m, DATA, true, 5, u32::MAX), Ok(1));
    // A private wake does not look at the page; a shared one does.
    assert_eq!(f.wake(&m, 0x7000_0000, true, 1, u32::MAX), Ok(0));
    assert_eq!(
        f.wake(&m, 0x7000_0000, false, 1, u32::MAX),
        Err(Errno::EFAULT)
    );
    // Past TASK_SIZE_MAX, and not aligned.
    assert_eq!(
        f.wake(&m, (1 << 47) - 4096, true, 1, u32::MAX),
        Err(Errno::EFAULT)
    );
    assert_eq!(f.wake(&m, DATA + 2, true, 1, u32::MAX), Err(Errno::EINVAL));
}
#[test]
fn futex_register_all_checks_every_key_before_any_value() {
    let m = memory();
    let f = futex::Futexes::default();
    let word = |addr, value| futex::Word {
        addr,
        private: true,
        numa: false,
        value,
        mask: u32::MAX,
    };
    // The first differs, but the second's key is bad.
    let misaligned = [word(DATA, 1), word(DATA + 2, 0)];
    assert!(matches!(
        f.register_all(&m, &misaligned),
        Err(Errno::EINVAL)
    ));
    let unmapped_shared = [
        word(DATA, 1),
        futex::Word {
            private: false,
            ..word(0x7000_0000, 0)
        },
    ];
    assert!(matches!(
        f.register_all(&m, &unmapped_shared),
        Err(Errno::EFAULT)
    ));
    // Values next, in order: a private word's page only now.
    assert!(matches!(
        f.register_all(&m, &[word(DATA, 1), word(0x7000_0000, 0)]),
        Err(Errno::EAGAIN)
    ));
    assert!(matches!(
        f.register_all(&m, &[word(DATA, 0), word(0x7000_0000, 0)]),
        Err(Errno::EFAULT)
    ));
    // Nothing stays queued after a failure.
    assert_eq!(f.wake(&m, DATA, true, 9, u32::MAX), Ok(0));
    // Queued, they share a token, and a wake of one leaves the other.
    let waiters = f
        .register_all(&m, &[word(DATA, 0), word(DATA + 4, 0)])
        .unwrap();
    assert!(Arc::ptr_eq(&waiters[0].token, &waiters[1].token));
    assert_eq!(f.wake(&m, DATA + 4, true, 1, u32::MAX), Ok(1));
    assert_eq!(waiters[0].state.load(Ordering::SeqCst), 0);
    assert_eq!(waiters[1].state.load(Ordering::SeqCst), 1);
    assert_eq!(waiters[1].token.value(), 1);
}
#[test]
fn futex_numa_word_names_node_zero() {
    let m = memory();
    let f = futex::Futexes::default();
    let numa = futex::Word {
        addr: DATA + 8,
        private: true,
        numa: true,
        value: 0,
        mask: u32::MAX,
    };
    // Doubled, the word is aligned to 8.
    let odd = futex::Word {
        addr: DATA + 4,
        ..numa
    };
    assert!(matches!(f.register_all(&m, &[odd]), Err(Errno::EINVAL)));
    // No node becomes node 0; another node is not possible.
    m.write(GuestAddr(DATA + 12), &u32::MAX.to_le_bytes())
        .unwrap();
    assert_eq!(
        f.wake_word(&m, DATA + 8, true, true, 1, u32::MAX, true),
        Ok(0)
    );
    assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap(), 0);
    m.write(GuestAddr(DATA + 12), &1u32.to_le_bytes()).unwrap();
    assert!(matches!(f.register_all(&m, &[numa]), Err(Errno::EINVAL)));
    m.write(GuestAddr(DATA + 12), &0u32.to_le_bytes()).unwrap();
    let waiter = f.register_all(&m, &[numa]).unwrap();
    assert_eq!(
        f.wake_word(&m, DATA + 8, true, true, 1, u32::MAX, true),
        Ok(1)
    );
    assert_eq!(waiter[0].state.load(Ordering::SeqCst), 1);
}
#[test]
fn futex_requeue_wakes_then_moves_in_order() {
    let m = memory();
    let f = futex::Futexes::default();
    let (from, to) = ((DATA, true, false), (DATA + 4, true, false));
    // Four at `from` (one with a bitset no wake would match), one at `to`.
    let at_from: Vec<_> = [1, 2, 1, 1]
        .into_iter()
        .map(|mask| f.register(&m, DATA, true, 0, mask).unwrap())
        .collect();
    let at_to = f.register(&m, DATA + 4, true, 0, u32::MAX).unwrap();
    assert_eq!(f.requeue(&m, from, to, -1, 0, None), Err(Errno::EINVAL));
    assert_eq!(f.requeue(&m, from, to, 0, -1, None), Err(Errno::EINVAL));
    // Both keys before the value; the value then (EAGAIN).
    assert_eq!(
        f.requeue(&m, from, (DATA + 2, true, false), 0, 0, Some(1)),
        Err(Errno::EINVAL)
    );
    assert_eq!(f.requeue(&m, from, to, 0, 0, Some(1)), Err(Errno::EAGAIN));
    assert_eq!(f.requeue(&m, from, to, 0, 0, Some(0)), Ok(0));
    // One woken, two moved, whatever their bitsets; the last stays.
    assert_eq!(f.requeue(&m, from, to, 1, 2, Some(0)), Ok(3));
    let states: Vec<_> = at_from
        .iter()
        .map(|w| w.state.load(Ordering::SeqCst))
        .collect();
    assert_eq!(states, [1, 0, 0, 0]);
    // The moved ones wait at `to` after the one already there.
    assert_eq!(f.wake(&m, DATA + 4, true, 2, u32::MAX), Ok(2));
    assert_eq!(at_to.state.load(Ordering::SeqCst), 1);
    assert_eq!(at_from[1].state.load(Ordering::SeqCst), 1);
    assert_eq!(at_from[2].state.load(Ordering::SeqCst), 0);
    // A moved waiter that ends leaves its new queue.
    assert_eq!(f.finish(&at_from[2], 2), 2);
    assert_eq!(f.wake(&m, DATA + 4, true, 9, u32::MAX), Ok(0));
    assert_eq!(f.wake(&m, DATA, true, 9, u32::MAX), Ok(1));
}
/// `FUTEX_WAKE_OP`'s `val3`: the operation, its argument, the comparison
/// and its argument.
fn wake_op(op: u32, oparg: i32, cmp: u32, cmparg: i32) -> u32 {
    op << 28 | cmp << 24 | (oparg as u32 & 0xfff) << 12 | cmparg as u32 & 0xfff
}
#[test]
fn futex_wake_op_changes_the_word_then_wakes() {
    let m = memory();
    m.map_shared(
        Some(GuestAddr(DATA + 0x1000)),
        4096,
        Prot::READ,
        MappingKind::Anonymous,
    )
    .unwrap();
    let f = futex::Futexes::default();
    let read = |addr| {
        let mut bytes = [0; 4];
        m.read(GuestAddr(addr), &mut bytes).unwrap();
        i32::from_le_bytes(bytes)
    };
    let (first, second, rom) = (DATA, DATA + 4, DATA + 0x1000);
    m.write(GuestAddr(second), &7u32.to_le_bytes()).unwrap();
    let set = wake_op(0, 5, 0, 7);
    // Both keys first; an unknown operation then, before the word is
    // touched, so a read-only word gives ENOSYS when private and EFAULT
    // when shared, which needs it writable.
    assert_eq!(
        f.wake_op(&m, first + 2, second, true, 1, 1, set),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        f.wake_op(&m, first, second + 2, true, 1, 1, set),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        f.wake_op(&m, first, second, true, 1, 1, wake_op(5, 0, 0, 0)),
        Err(Errno::ENOSYS)
    );
    assert_eq!(
        f.wake_op(&m, first, rom, true, 1, 1, wake_op(5, 0, 0, 0)),
        Err(Errno::ENOSYS)
    );
    assert_eq!(
        f.wake_op(&m, first, rom, false, 1, 1, wake_op(5, 0, 0, 0)),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        f.wake_op(&m, first, rom, true, 1, 1, set),
        Err(Errno::EFAULT)
    );
    assert_eq!(read(second), 7);
    // An unknown comparison is ENOSYS after the word has changed, and
    // nothing wakes.
    let waiters: Vec<_> = [1, 2, 1]
        .into_iter()
        .map(|mask| f.register(&m, first, true, 0, mask).unwrap())
        .chain((0..2).map(|_| f.register(&m, second, true, 7, u32::MAX).unwrap()))
        .collect();
    assert_eq!(
        f.wake_op(&m, first, second, true, 1, 1, wake_op(0, 9, 6, 0)),
        Err(Errno::ENOSYS)
    );
    assert_eq!(read(second), 9);
    let states = || -> Vec<u32> {
        waiters
            .iter()
            .map(|w| w.state.load(Ordering::SeqCst))
            .collect()
    };
    assert_eq!(states(), [0; 5]);
    m.write(GuestAddr(second), &7u32.to_le_bytes()).unwrap();
    // The old value 7 compares equal: one of each woken, a count of 0 too,
    // whatever their bitsets.
    assert_eq!(f.wake_op(&m, first, second, true, 0, 1, set), Ok(2));
    assert_eq!(states(), [1, 0, 0, 1, 0]);
    assert_eq!(read(second), 5);
    // 5 is not greater than 5: only the first word's.
    assert_eq!(
        f.wake_op(&m, first, second, true, 1, 9, wake_op(1, 1, 4, 5)),
        Ok(1)
    );
    assert_eq!(states(), [1, 1, 0, 1, 0]);
    assert_eq!(read(second), 6);
    // Or, and-not and xor, and arguments as shifts (taken modulo 32).
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(2 | 8, 4, 1, 6)),
        Ok(0)
    );
    assert_eq!(read(second), 22);
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(3, 6, 0, 0)),
        Ok(0)
    );
    assert_eq!(read(second), 16);
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(4 | 8, 33, 0, 0)),
        Ok(0)
    );
    assert_eq!(read(second), 18);
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(8, -1, 0, 0)),
        Ok(0)
    );
    assert_eq!(read(second), i32::MIN);
    // The old value and the argument compare as signed: `i32::MIN` is not
    // greater than or equal to 0, and -1 is less than or equal to -1.
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(0, -1, 5, 0)),
        Ok(0)
    );
    assert_eq!(
        f.wake_op(&m, first + 8, second, true, 1, 1, wake_op(0, -1, 3, -1)),
        Ok(1)
    );
    assert_eq!(states(), [1, 1, 0, 1, 1]);
    // Onto the same word, each count in turn.
    assert_eq!(
        f.wake_op(&m, first, first, true, 1, 1, wake_op(0, 0, 0, 0)),
        Ok(1)
    );
    let more = f.register(&m, first, true, 0, u32::MAX).unwrap();
    let last = f.register(&m, first, true, 0, u32::MAX).unwrap();
    assert_eq!(
        f.wake_op(&m, first, first, true, 1, 1, wake_op(0, 0, 3, 0)),
        Ok(2)
    );
    assert_eq!(states(), [1; 5]);
    assert_eq!(more.state.load(Ordering::SeqCst), 1);
    assert_eq!(last.state.load(Ordering::SeqCst), 1);
}
#[test]
fn futex_requeue_onto_its_own_word_leaves_waiters_in_place() {
    let m = memory();
    let f = futex::Futexes::default();
    let word = (DATA, true, false);
    let waiters: Vec<_> = (0..2)
        .map(|_| f.register(&m, DATA, true, 0, u32::MAX).unwrap())
        .collect();
    // Each is counted once, and their order stays, as native gives.
    assert_eq!(f.requeue(&m, word, word, 0, 3, None), Ok(2));
    assert_eq!(f.requeue(&m, word, word, 0, 1, None), Ok(1));
    assert_eq!(f.wake(&m, DATA, true, 1, u32::MAX), Ok(1));
    assert_eq!(waiters[0].state.load(Ordering::SeqCst), 1);
    assert_eq!(waiters[1].state.load(Ordering::SeqCst), 0);
    // Woken first, up to the wake count.
    assert_eq!(f.requeue(&m, word, word, 1, 5, None), Ok(1));
    assert_eq!(waiters[1].state.load(Ordering::SeqCst), 1);
}
