#[test]
fn u4_memory_shared_anonymous_rounds_length() {
    let mut f = fixture();
    let at = 0x6000_0000;
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[at, 4097, 3, 0x31, u64::MAX, 0]),
        at
    );
    f.mem.write(GuestAddr(at + 4096), &[42]).unwrap();
    let mut byte = [0];
    f.mem.read(GuestAddr(at + 4096), &mut byte).unwrap();
    assert_eq!(byte, [42]);
}
#[test]
fn u4_memory_hint_rounds_down() {
    let mut f = fixture();
    assert_eq!(
        f.ret(
            syscalls::nr::MMAP,
            &[0x6000_007b, 4096, 3, 0x22, u64::MAX, 0]
        ),
        0x6000_0000
    );
}
#[test]
fn u4_memory_prot_sem_accepted() {
    let mut f = fixture();
    assert_eq!(f.ret(syscalls::nr::MPROTECT, &[DATA, 4096, 8]), 0);
    assert!(f.mem.read(GuestAddr(DATA), &mut [0]).is_err());
}
#[test]
fn u4_memory_noreplace_preserves_bytes() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), &[41]).unwrap();
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[DATA, 4096, 3, 0x100022, u64::MAX, 0]),
        errno(Errno::EEXIST)
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(DATA), &mut byte).unwrap();
    assert_eq!(byte, [41]);
}
#[test]
fn u4_memory_fixed_overflow_preserves_bytes() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), &[41]).unwrap();
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[DATA, u64::MAX, 3, 0x32, u64::MAX, 0]),
        errno(Errno::ENOMEM)
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(DATA), &mut byte).unwrap();
    assert_eq!(byte, [41]);
}
#[test]
fn u4_memory_zero_length_rejected() {
    let mut f = fixture();
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 0, 3, 0x22, u64::MAX, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(syscalls::nr::MUNMAP, &[DATA, 0]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn u4_memory_fixed_replacement_zero_fills() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), &[41]).unwrap();
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[DATA, 4096, 3, 0x32, u64::MAX, 0]),
        DATA
    );
    let mut byte = [99];
    f.mem.read(GuestAddr(DATA), &mut byte).unwrap();
    assert_eq!(byte, [0]);
}
#[test]
fn u4_memory_brk_failure_returns_current() {
    let mut f = fixture();
    assert_eq!(f.ret(syscalls::nr::BRK, &[u64::MAX]), 0x20_0000);
}

fn timespec(f: &mut Fixture, sec: i64, nsec: i64) {
    f.mem.write(GuestAddr(DATA), &sec.to_le_bytes()).unwrap();
    f.mem
        .write(GuestAddr(DATA + 8), &nsec.to_le_bytes())
        .unwrap();
}
#[test]
fn u4_time_clock_serialization() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 2_000_000_007);
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[1, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 2);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 7);
}
#[test]
fn u4_time_bad_clock() {
    let mut f = fixture();
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_GETTIME, &[u64::MAX, DATA]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn u4_time_bad_pointer() {
    let mut f = fixture();
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_GETTIME, &[1, 1]),
        errno(Errno::EFAULT)
    );
}
#[test]
fn u4_time_negative_seconds() {
    let mut f = fixture();
    timespec(&mut f, -1, 0);
    assert_eq!(
        f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn u4_time_nanoseconds_range() {
    let mut f = fixture();
    timespec(&mut f, 0, 1_000_000_000);
    assert_eq!(
        f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn u4_time_relative_deadline() {
    let mut f = fixture();
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 100);
    timespec(&mut f, 0, 42);
    assert_eq!(f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]), 0);
    assert_eq!(f.host.clock(paludarium_host::ClockId::Monotonic), Ok(142));
}
#[test]
fn u4_time_absolute_deadline() {
    let mut f = fixture();
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 100);
    timespec(&mut f, 0, 42);
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[1, 1, DATA, DATA + 16]),
        0
    );
    assert_eq!(f.host.clock(paludarium_host::ClockId::Monotonic), Ok(100));
}
#[test]
fn u4_time_interrupt_remaining() {
    let mut f = fixture();
    timespec(&mut f, 2, 42);
    f.host.interrupt_next_wait();
    assert_eq!(
        f.ret(syscalls::nr::NANOSLEEP, &[DATA, DATA + 16]),
        errno(Errno(4))
    );
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 16)).unwrap(), 2);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 24)).unwrap(), 42);
}
struct InterruptedWriteHost;
impl paludarium_host::Host for InterruptedWriteHost {
    fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno(4))
    }
    fn write_stdout(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno(4))
    }
    fn write_stderr(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno(4))
    }
    fn random_bytes(&self, bytes: &mut [u8]) -> Result<(), paludarium_types::Error> {
        bytes.fill(0);
        Ok(())
    }
}

#[test]
fn u4_signal_write_restart_frame_matches_native_context() {
    // Native write-restart-oracle: no restart (-4, after); restart (1, site).
    for (flags, expected_rax, expected_rip) in
        [(0, (-4i64) as u64, 0x400002), (0x10000000, 1, 0x400000)]
    {
        let mut f = fixture();
        f.kernel = Kernel::new(Arc::new(InterruptedWriteHost));
        f.thread.cpu.rip = GuestAddr(0x400002);
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x2000;
        f.thread.state.signal_actions.insert(
            10,
            SignalAction {
                handler: 0x400100,
                flags,
                restorer: 0x400200,
                mask: 0,
            },
        );
        f.kernel.queue_signal(&mut f.thread, 10).unwrap();
        assert_eq!(f.call(nr::WRITE, &[1, DATA, 1]), Next::Resume);
        let mut bytes = [0; 8];
        let base = f.thread.cpu.gpr[reg::RSP];
        f.mem
            .read(GuestAddr(base + 48 + 13 * 8), &mut bytes)
            .unwrap();
        assert_eq!(u64::from_le_bytes(bytes), expected_rax);
        f.mem
            .read(GuestAddr(base + 48 + 16 * 8), &mut bytes)
            .unwrap();
        assert_eq!(u64::from_le_bytes(bytes), expected_rip);
    }
}

fn signal_fixture() -> Fixture {
    let mut f = fixture();
    f.thread.cpu.rip = GuestAddr(0x400000);
    f.thread.cpu.gpr[reg::RSP] = DATA + 0x2000;
    f.thread.state.signal_actions.insert(
        10,
        SignalAction {
            handler: 0x400100,
            flags: 0,
            restorer: 0x400200,
            mask: 0,
        },
    );
    f
}
#[test]
fn u4_signal_blocked_queue_delivers_after_unmask() {
    let mut f = signal_fixture();
    f.thread.state.signal_mask = 1 << 9;
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
    assert_eq!(f.thread.cpu.rip, GuestAddr(0x400000));
    f.thread.state.signal_mask = 0;
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
    assert_eq!(f.thread.cpu.rip, GuestAddr(0x400100));
}
#[test]
fn u4_signal_standard_queue_coalesces() {
    let mut f = signal_fixture();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(f.thread.state.pending.len(), 1);
}
#[test]
fn u4_signal_frame_fault_does_not_change_registers_or_memory() {
    let mut f = signal_fixture();
    f.thread.cpu.gpr[reg::RSP] = 0x70000000;
    let before = f.thread.cpu.clone();
    f.mem.write(GuestAddr(DATA), &[41]).unwrap();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(
        f.kernel.checkpoint(&mut f.thread, &f.mem),
        Next::Exit(ExitStatus::Signaled(11))
    );
    assert_eq!(f.thread.cpu, before);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 41);
}
#[test]
fn u4_signal_return_preserves_registers_sse_and_mask() {
    let mut f = signal_fixture();
    f.thread.cpu.gpr[reg::R12] = 77;
    f.thread.cpu.xmm[3] = 0x123456789;
    f.thread.cpu.fs_base = 0x100;
    f.thread.cpu.gs_base = 0x200;
    f.thread.state.signal_mask = 1 << 11;
    let before = f.thread.cpu.clone();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
    f.thread.cpu.gpr[reg::RSP] += 8;
    assert_eq!(f.call(nr::RT_SIGRETURN, &[]), Next::Resume);
    assert_eq!(f.thread.cpu, before);
    assert_eq!(f.thread.state.signal_mask, 1 << 11);
}
#[test]
fn u4_signal_frame_ignores_privileged_flag_edits() {
    let mut f = signal_fixture();
    let flags = f.thread.cpu.rflags;
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    let base = f.thread.cpu.gpr[reg::RSP];
    f.mem
        .write_u64(GuestAddr(base + 48 + 17 * 8), flags | (3 << 12))
        .unwrap();
    f.thread.cpu.gpr[reg::RSP] += 8;
    f.call(nr::RT_SIGRETURN, &[]);
    assert_eq!(f.thread.cpu.rflags & (3 << 12), flags & (3 << 12));
}
#[test]
fn u4_signal_bad_fp_pointer_rejects_context() {
    let mut f = signal_fixture();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    let base = f.thread.cpu.gpr[reg::RSP];
    f.mem
        .write_u64(GuestAddr(base + 48 + 184), 0x70000001)
        .unwrap();
    f.thread.cpu.gpr[reg::RSP] += 8;
    assert_eq!(
        f.call(nr::RT_SIGRETURN, &[]),
        Next::Exit(ExitStatus::Signaled(11))
    );
}
#[test]
fn u4_signal_timer_periodic_coalesces_and_advances() {
    let mut f = signal_fixture();
    f.thread.state.timer = signals::RealTimer {
        deadline: Some(10),
        interval: 5,
    };
    signals::expire_timer(&mut f.thread.state, 26);
    assert_eq!(f.thread.state.timer.deadline, Some(30));
    assert_eq!(f.thread.state.pending.len(), 1);
    signals::expire_timer(&mut f.thread.state, 31);
    assert_eq!(f.thread.state.pending.len(), 1);
}
#[test]
fn u4_signal_realtime_queue_has_no_invented_quota() {
    let mut f = signal_fixture();
    for _ in 0..2048 {
        f.kernel.queue_signal(&mut f.thread, 32).unwrap();
    }
    assert_eq!(f.thread.state.pending.len(), 2048);
    f.kernel.queue_signal(&mut f.thread, 9).unwrap();
    assert_eq!(
        f.kernel.checkpoint(&mut f.thread, &f.mem),
        Next::Exit(ExitStatus::Signaled(9))
    );
}

#[test]
fn u4_signal_realtime_selection_keeps_fifo_and_masks() {
    let mut f = signal_fixture();
    // Native same-process kill then sigqueue yielded si_code 0 then -1.
    signals::queue(&mut f.thread.state, signals::PendingSignal::user(36, 0));
    signals::queue(&mut f.thread.state, signals::PendingSignal::user(35, 0));
    signals::queue(&mut f.thread.state, signals::PendingSignal::user(35, -1));
    f.thread.state.signal_mask = 1 << 34;
    assert_eq!(signals::next_pending(&f.thread.state, false), Some(0));
    f.thread.state.signal_mask = 0;
    let first = signals::next_pending(&f.thread.state, false).unwrap();
    assert_eq!(f.thread.state.pending.remove(first).code, 0);
    let second = signals::next_pending(&f.thread.state, false).unwrap();
    assert_eq!(f.thread.state.pending.remove(second).code, -1);
    assert_eq!(f.thread.state.pending[0].number, 36);
}

#[test]
fn u4_signal_pending_targets_keep_number_order_fifo_and_coalescing() {
    let mut f = signal_fixture();
    for pending in [
        signals::PendingSignal::user(35, 0),
        signals::PendingSignal::thread(36, -6),
        signals::PendingSignal::thread(35, -6),
        signals::PendingSignal::thread(35, -1),
    ] {
        signals::queue(&mut f.thread.state, pending);
    }
    for code in [-6, -1] {
        let index = signals::next_pending(&f.thread.state, false).unwrap();
        let selected = f.thread.state.pending.remove(index);
        assert_eq!(
            (selected.target, selected.number, selected.code),
            (signals::PendingTarget::Thread, 35, code)
        );
    }
    f.thread.state.signal_mask = 1 << 35;
    let index = signals::next_pending(&f.thread.state, false).unwrap();
    assert_eq!(
        f.thread.state.pending[index].target,
        signals::PendingTarget::Process
    );
    f.thread.state.pending.clear();
    for _ in 0..2 {
        signals::queue(&mut f.thread.state, signals::PendingSignal::user(10, 0));
        signals::queue(
            &mut f.thread.state,
            signals::PendingSignal::thread(10, -6),
        );
    }
    assert_eq!(f.thread.state.pending.len(), 2);
    assert_eq!(
        f.thread.state.pending[signals::next_pending(&f.thread.state, false).unwrap()].code,
        -6
    );
    signals::queue(&mut f.thread.state, signals::PendingSignal::user(9, 0));
    assert_eq!(
        f.thread.state.pending[signals::next_pending(&f.thread.state, false).unwrap()].number,
        9
    );
}

#[test]
fn u4_signal_synchronous_fault_selects_thread_pending_queue() {
    let mut f = signal_fixture();
    let action = f.thread.state.signal_actions[&10];
    f.thread.state.signal_actions.insert(8, action);
    // An unmasked synchronous fault is thread-pending; blocked synchronous
    // faults terminate under the separately native-checked fault policy.
    f.thread.state.signal_mask = 0;
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(
        f.kernel.handle(
            &mut f.thread,
            &f.mem,
            ExitReason::ArithmeticFault {
                rip: GuestAddr(0x400000)
            }
        ),
        Next::Resume
    );
    assert_eq!(f.thread.cpu.gpr[reg::RDI], 8);
    assert_eq!(f.thread.state.pending.len(), 1);
    assert_eq!(
        f.thread.state.pending[0].target,
        signals::PendingTarget::Process
    );
    assert_eq!(f.thread.state.pending[0].number, 10);
}

#[test]
fn u4_signal_thread_target_restart_preview_matches_delivery() {
    for restart in [false, true] {
        let mut f = fixture();
        f.kernel = Kernel::new(Arc::new(InterruptedWriteHost));
        f.thread.cpu.rip = GuestAddr(0x400002);
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x2000;
        for number in [35, 36] {
            f.thread.state.signal_actions.insert(
                number,
                SignalAction {
                    handler: 0x400100,
                    restorer: 0x400200,
                    flags: if (number == 36) == restart {
                        0x10000000
                    } else {
                        0
                    },
                    mask: (1 << 34) | (1 << 35),
                },
            );
        }
        signals::queue(&mut f.thread.state, signals::PendingSignal::user(35, 0));
        signals::queue(
            &mut f.thread.state,
            signals::PendingSignal::thread(36, -6),
        );
        assert_eq!(f.call(nr::WRITE, &[1, DATA, 1]), Next::Resume);
        assert_eq!(f.thread.cpu.gpr[reg::RDI], 36);
        let base = f.thread.cpu.gpr[reg::RSP];
        assert_eq!(
            f.mem.read_u64(GuestAddr(base + 48 + 13 * 8)).unwrap(),
            if restart { 1 } else { (-4i64) as u64 }
        );
        assert_eq!(
            f.mem.read_u64(GuestAddr(base + 48 + 16 * 8)).unwrap(),
            if restart { 0x400000 } else { 0x400002 }
        );
    }
}

#[test]
fn u4_signal_restart_preview_uses_selected_realtime_handler() {
    for restart in [false, true] {
        let mut f = fixture();
        f.kernel = Kernel::new(Arc::new(InterruptedWriteHost));
        f.thread.cpu.rip = GuestAddr(0x400002);
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x2000;
        for number in [35, 36] {
            f.thread.state.signal_actions.insert(
                number,
                SignalAction {
                    handler: 0x400100,
                    restorer: 0x400200,
                    flags: if (number == 35) == restart {
                        0x10000000
                    } else {
                        0
                    },
                    mask: (1 << 34) | (1 << 35),
                },
            );
        }
        f.kernel.queue_signal(&mut f.thread, 36).unwrap();
        f.kernel.queue_signal(&mut f.thread, 35).unwrap();
        assert_eq!(f.call(nr::WRITE, &[1, DATA, 1]), Next::Resume);
        assert_eq!(f.thread.cpu.gpr[reg::RDI], 35);
        let base = f.thread.cpu.gpr[reg::RSP];
        assert_eq!(
            f.mem.read_u64(GuestAddr(base + 48 + 13 * 8)).unwrap(),
            if restart { 1 } else { (-4i64) as u64 }
        );
        assert_eq!(
            f.mem.read_u64(GuestAddr(base + 48 + 16 * 8)).unwrap(),
            if restart { 0x400000 } else { 0x400002 }
        );
    }
}
#[test]
fn u4_signal_rep_budget_context_roundtrip() {
    let mut f = signal_fixture();
    f.mem
        .map(
            Some(GuestAddr(0x400000)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .unwrap();
    f.mem
        .write_initial(GuestAddr(0x400000), &[0xf3, 0xa6])
        .unwrap();
    f.thread.cpu.gpr[reg::RCX] = 4097;
    f.thread.cpu.gpr[reg::RSI] = DATA;
    f.thread.cpu.gpr[reg::RDI] = DATA;
    let reason = paludarium_cpu::run(&mut f.thread.cpu, &f.mem, 1);
    assert!(matches!(reason, ExitReason::BudgetExhausted { .. }));
    assert!(f.thread.cpu.repeat_continuation.is_some());
    let before = f.thread.cpu.clone();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.handle(&mut f.thread, &f.mem, reason);
    assert!(f.thread.cpu.repeat_continuation.is_none());
    f.thread.cpu.gpr[reg::RSP] += 8;
    f.call(nr::RT_SIGRETURN, &[]);
    assert_eq!(f.thread.cpu, before);
}
#[test]
fn u4_signal_changed_rep_return_discards_continuation() {
    let mut f = signal_fixture();
    f.mem
        .map(
            Some(GuestAddr(0x400000)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .unwrap();
    f.mem
        .write_initial(GuestAddr(0x400000), &[0xf3, 0xa6])
        .unwrap();
    f.thread.cpu.gpr[reg::RCX] = 4097;
    f.thread.cpu.gpr[reg::RSI] = DATA;
    f.thread.cpu.gpr[reg::RDI] = DATA;
    let reason = paludarium_cpu::run(&mut f.thread.cpu, &f.mem, 1);
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.handle(&mut f.thread, &f.mem, reason);
    let base = f.thread.cpu.gpr[reg::RSP];
    f.mem
        .write_u64(GuestAddr(base + 48 + 14 * 8), DATA + 65)
        .unwrap();
    f.thread.cpu.gpr[reg::RSP] += 8;
    f.call(nr::RT_SIGRETURN, &[]);
    assert!(f.thread.cpu.repeat_continuation.is_none());
}
#[test]
fn u4_signal_nested_altstack_frames_do_not_overlap() {
    let mut f = signal_fixture();
    f.thread.state.alt_stack = AltStack {
        sp: DATA,
        size: 8192,
        flags: 0,
    };
    f.thread.state.signal_actions.get_mut(&10).unwrap().flags =
        signals::SA_ONSTACK | signals::SA_NODEFER;
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    let first = f.thread.cpu.gpr[reg::RSP];
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    let second = f.thread.cpu.gpr[reg::RSP];
    assert!(second + 1024 < first);
    assert_eq!(first & 15, 8);
    assert_eq!(second & 15, 8);
    f.thread.cpu.gpr[reg::RSP] += 8;
    f.call(nr::RT_SIGRETURN, &[]);
    assert_eq!(f.thread.cpu.gpr[reg::RSP], first);
    f.thread.cpu.gpr[reg::RSP] += 8;
    f.call(nr::RT_SIGRETURN, &[]);
    assert_eq!(f.thread.cpu.gpr[reg::RSP], DATA + 8192);
}
#[test]
fn u4_default_stop_is_not_process_termination() {
    for number in [19, 20] {
        let mut f = fixture();
        let before = f.thread.cpu.clone();
        f.kernel.queue_signal(&mut f.thread, number).unwrap();
        let next = f.kernel.checkpoint(&mut f.thread, &f.mem);
        assert!(
            !matches!(next, Next::Exit(_)),
            "native reports a stopped child, not exit"
        );
        assert_eq!(f.thread.cpu, before);
        f.thread.state.signal_mask = 1 << 17;
        f.kernel.queue_signal(&mut f.thread, 18).unwrap();
        assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
        assert_eq!(f.thread.cpu, before);
    }
}
#[test]
fn u4_blocked_tstp_defers_stop_until_unmask() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 19;
    f.kernel.queue_signal(&mut f.thread, 20).unwrap();
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
    assert!(!f.thread.state.stopped);
    assert_eq!(f.thread.state.pending.len(), 1);
    f.thread.state.signal_mask = 0;
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Stopped);
}
