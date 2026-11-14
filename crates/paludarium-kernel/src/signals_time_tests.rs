#[test]
fn memory_shared_anonymous_rounds_length() {
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
fn memory_hint_rounds_down() {
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
fn memory_prot_sem_accepted() {
    let mut f = fixture();
    assert_eq!(f.ret(syscalls::nr::MPROTECT, &[DATA, 4096, 8]), 0);
    assert!(f.mem.read(GuestAddr(DATA), &mut [0]).is_err());
}
#[test]
fn memory_noreplace_preserves_bytes() {
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
fn memory_fixed_overflow_preserves_bytes() {
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
fn memory_zero_length_rejected() {
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
fn memory_fixed_replacement_zero_fills() {
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
fn memory_brk_failure_returns_current() {
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
fn gettimeofday_and_time_read_the_real_time_clock() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 5_000_123_456);
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 7);
    f.mem.write(GuestAddr(DATA + 16), &[0xff; 8]).unwrap();
    assert_eq!(f.ret(syscalls::nr::GETTIMEOFDAY, &[DATA, DATA + 16]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 5);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 123);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 16)).unwrap(), 0);
    assert_eq!(f.ret(syscalls::nr::GETTIMEOFDAY, &[0, 0]), 0);
    let fault = Errno::EFAULT.to_syscall_return();
    assert_eq!(f.ret(syscalls::nr::GETTIMEOFDAY, &[8, 0]), fault);
    assert_eq!(f.ret(syscalls::nr::GETTIMEOFDAY, &[0, 8]), fault);
    assert_eq!(f.ret(syscalls::nr::TIME, &[DATA + 32]), 5);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 32)).unwrap(), 5);
    assert_eq!(f.ret(syscalls::nr::TIME, &[0]), 5);
    assert_eq!(f.ret(syscalls::nr::TIME, &[8]), fault);
}
#[test]
fn coarse_clocks_and_time_give_the_latest_tick() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 5_999_999_999);
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 2_000_500_000);
    // CLOCK_MONOTONIC_COARSE: the latest of the host's ticks, on whole
    // multiples of it; CLOCK_REALTIME_COARSE: the real time at that same
    // instant, whatever its own phase.
    let tick = syscalls::scheduler_slice(&*f.host).tick;
    let since = 2_000_500_000 % tick;
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[5, DATA]), 0);
    let coarse = 5_999_999_999 - since;
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), coarse / 1_000_000_000);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), coarse % 1_000_000_000);
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[6, DATA]), 0);
    let coarse = 2_000_500_000 - since;
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), coarse / 1_000_000_000);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), coarse % 1_000_000_000);
    // The precise clocks are not cut.
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[0, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 999_999_999);
    // time() gives CLOCK_REALTIME_COARSE's seconds.
    assert_eq!(f.ret(syscalls::nr::TIME, &[0]), 5);
    // A real time nearer its start than the monotonic clock is to its tick
    // stops at 0.
    f.host.set_clock(paludarium_host::ClockId::Realtime, since / 2);
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[5, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 0);
}
#[test]
fn time_clock_serialization() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 2_000_000_007);
    assert_eq!(f.ret(syscalls::nr::CLOCK_GETTIME, &[1, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 2);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 7);
}
#[test]
fn time_bad_clock() {
    let mut f = fixture();
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_GETTIME, &[u64::MAX, DATA]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn time_bad_pointer() {
    let mut f = fixture();
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_GETTIME, &[1, 1]),
        errno(Errno::EFAULT)
    );
}
#[test]
fn time_negative_seconds() {
    let mut f = fixture();
    timespec(&mut f, -1, 0);
    assert_eq!(
        f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn time_nanoseconds_range() {
    let mut f = fixture();
    timespec(&mut f, 0, 1_000_000_000);
    assert_eq!(
        f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn time_relative_deadline() {
    let mut f = fixture();
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 100);
    timespec(&mut f, 0, 42);
    assert_eq!(f.ret(syscalls::nr::NANOSLEEP, &[DATA, 0]), 0);
    assert_eq!(f.host.clock(paludarium_host::ClockId::Monotonic), Ok(142));
}
#[test]
fn time_absolute_deadline() {
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
fn clock_nanosleep_clocks_and_flags() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 1_000);
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 100);
    timespec(&mut f, 0, 42);
    // BOOTTIME sleeps on the monotonic clock, TAI on the real-time one, and
    // flags other than TIMER_ABSTIME are not looked at.
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[7, 2, DATA, 0]), 0);
    assert_eq!(f.host.clock(paludarium_host::ClockId::Monotonic), Ok(142));
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[11, !1, DATA, 0]), 0);
    // Clocks that cannot sleep, before the request is read; unknown ones.
    for clock in [3, 4, 5, 6] {
        assert_eq!(
            f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[clock, 0, 8, 0]),
            errno(Errno::EOPNOTSUPP)
        );
    }
    for clock in [10, 12, u64::from(u32::MAX)] {
        assert_eq!(
            f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[clock, 0, DATA, 0]),
            errno(Errno::EINVAL)
        );
    }
}
/// Linux's `make_process_cpuclock` and `make_thread_cpuclock`.
fn cpu_clock_id(pid: u32, thread: bool, which: i32) -> u64 {
    u64::from(((!(pid as i32)) << 3 | if thread { 4 } else { 0 } | which) as u32)
}
#[test]
fn cpu_clocks_of_tasks_by_number() {
    let mut f = fixture();
    let (einval, enotsup) = (errno(Errno::EINVAL), errno(Errno::EOPNOTSUPP));
    let pid = f.ret(39, &[]) as u32;
    let gettime = |f: &mut Fixture, id: u64| f.ret(syscalls::nr::CLOCK_GETTIME, &[id, DATA]);
    let getres = |f: &mut Fixture, id: u64| {
        let r = f.ret(syscalls::nr::CLOCK_GETRES, &[id, DATA]);
        (r, f.mem.read_u64(GuestAddr(DATA + 8)).unwrap())
    };
    // The caller's own clocks: by 0, by its number, and its thread's number
    // as a process clock too, which only clock_gettime takes.
    for which in 0..3 {
        assert_eq!(gettime(&mut f, cpu_clock_id(0, false, which)), 0);
        assert_eq!(gettime(&mut f, cpu_clock_id(pid, false, which)), 0);
        assert_eq!(gettime(&mut f, cpu_clock_id(pid, true, which)), 0);
    }
    // A tick for the clocks Linux counts by ticks, 1 ns for the run time.
    assert_eq!(getres(&mut f, cpu_clock_id(pid, false, 0)), (0, 1_000_000));
    assert_eq!(getres(&mut f, cpu_clock_id(pid, true, 1)), (0, 1_000_000));
    assert_eq!(getres(&mut f, cpu_clock_id(0, false, 2)), (0, 1));
    // No such task, a dynamic clock (no file here is one), the fourth kind.
    assert_eq!(gettime(&mut f, cpu_clock_id(0x0fff_fff0, false, 2)), einval);
    assert_eq!(getres(&mut f, cpu_clock_id(0x0fff_fff0, true, 2)).0, einval);
    assert_eq!(gettime(&mut f, cpu_clock_id(3, false, 3)), einval);
    assert_eq!(gettime(&mut f, cpu_clock_id(pid, true, 3)), einval);
    // A clockid_t is an int.
    assert_eq!(gettime(&mut f, 1 << 32 | 1), 0);
    assert_eq!(getres(&mut f, 1 << 32 | 6).0, 0);
    // Sleeps: none on a dynamic clock; a CPU clock reads the request first.
    timespec(&mut f, 0, 42);
    let nsleep = |f: &mut Fixture, id: u64, req: u64| {
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[id, 0, req, 0])
    };
    assert_eq!(nsleep(&mut f, cpu_clock_id(3, false, 3), 8), enotsup);
    assert_eq!(nsleep(&mut f, 2, 8), errno(Errno::EFAULT));
    assert_eq!(nsleep(&mut f, cpu_clock_id(pid, true, 2), 8), errno(Errno::EFAULT));
    assert_eq!(nsleep(&mut f, cpu_clock_id(pid, true, 2), DATA), einval);
    // No such task; on the process's clock by number, a time that has come
    // returns at once.
    assert_eq!(nsleep(&mut f, cpu_clock_id(0x0fff_fff0, false, 2), DATA), einval);
    timespec(&mut f, 0, 0);
    assert_eq!(nsleep(&mut f, 2, DATA), 0);
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[cpu_clock_id(pid, false, 0), 1, DATA, 0]),
        0
    );
    timespec(&mut f, 0, 42);
    // Timers: on the thread's clock by its number; none on a dynamic clock,
    // and a task not found after the ID is out, which is then used up.
    let id = DATA + 64;
    let create = |f: &mut Fixture, clock: u64| f.ret(syscalls::nr::TIMER_CREATE, &[clock, 0, id]);
    assert_eq!(create(&mut f, cpu_clock_id(pid, true, 2)), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(id)).unwrap() as u32, 0);
    assert_eq!(create(&mut f, cpu_clock_id(3, false, 3)), enotsup);
    assert_eq!(create(&mut f, cpu_clock_id(0x0fff_fff0, false, 2)), einval);
    assert_eq!(f.mem.read_u64(GuestAddr(id)).unwrap() as u32, 1);
    assert_eq!(create(&mut f, cpu_clock_id(0, false, 0)), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(id)).unwrap() as u32, 2);
}
/// The process's CPU clock sleeps until the process has used the time; this
/// host counts wall time as CPU time.
#[test]
fn clock_nanosleep_on_the_process_cpu_clock() {
    let mut f = fixture();
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 1_000_000_000);
    // A time that has passed, and nothing to sleep: at once.
    timespec(&mut f, 0, 0);
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 1, DATA, 0]), 0);
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 0, DATA, 0]), 0);
    assert_eq!(
        f.host.clock(paludarium_host::ClockId::Monotonic),
        Ok(1_000_000_000)
    );
    // A relative sleep ends once the time is used, by the tick.
    timespec(&mut f, 0, 2_500_000);
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 0, DATA, 0]), 0);
    assert_eq!(
        f.host.clock(paludarium_host::ClockId::Monotonic),
        Ok(1_003_000_000)
    );
    // Bad requests.
    timespec(&mut f, -1, 0);
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 0, DATA, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 0, 8, 0]),
        errno(Errno::EFAULT)
    );
    // A signal ends it with the time left, and restart_syscall resumes it
    // on the same clock.
    timespec(&mut f, 2, 42);
    f.host.interrupt_next_wait();
    assert_eq!(
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[2, 0, DATA, DATA + 16]),
        errno(Errno(4))
    );
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 16)).unwrap(), 2);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 24)).unwrap(), 42);
    assert!(matches!(
        f.thread.state.restart_block,
        Some(signals::RestartBlock::Sleep {
            clock: signals::SleepClock::ProcessCpu,
            ..
        })
    ));
    // The other threads account their CPU time only while it sleeps.
    assert!(!f.kernel.group.cpu_timers_armed());
}
#[test]
fn alarm_clocks_sleep_and_time_with_cap_wake_alarm() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 1_000);
    f.host.set_clock(paludarium_host::ClockId::Monotonic, 100);
    timespec(&mut f, 0, 42);
    // REALTIME_ALARM sleeps on the real-time clock, BOOTTIME_ALARM on the
    // monotonic one.
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[8, 0, DATA, 0]), 0);
    assert_eq!(f.host.clock(paludarium_host::ClockId::Realtime), Ok(1_042));
    assert_eq!(f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[9, 0, DATA, 0]), 0);
    assert_eq!(f.host.clock(paludarium_host::ClockId::Monotonic), Ok(184));
    // The request first, then any flag but TIMER_ABSTIME, then the
    // capability.
    let nsleep = |f: &mut Fixture, clock: u64, flags: u64, req: u64| {
        f.ret(syscalls::nr::CLOCK_NANOSLEEP, &[clock, flags, req, 0])
    };
    assert_eq!(nsleep(&mut f, 8, 2, 8), errno(Errno::EFAULT));
    assert_eq!(nsleep(&mut f, 8, 2, DATA), errno(Errno::EINVAL));
    let root = f.thread.state.credentials.clone();
    f.thread.state.credentials = root.setresuid(1000, 1000, 1000).unwrap();
    assert_eq!(nsleep(&mut f, 9, 2, DATA), errno(Errno::EINVAL));
    assert_eq!(nsleep(&mut f, 9, 1, DATA), errno(Errno::EPERM));
    // timer_create writes the ID out, then refuses, and the ID is used up.
    assert_eq!(f.ret(syscalls::nr::TIMER_CREATE, &[8, 0, DATA + 64]), errno(Errno::EPERM));
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64)).unwrap() as u32, 0);
    assert_eq!(f.ret(syscalls::nr::TIMER_CREATE, &[8, 0, 8]), errno(Errno::EFAULT));
    f.thread.state.credentials = root;
    assert_eq!(f.ret(syscalls::nr::TIMER_CREATE, &[9, 0, DATA + 64]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64)).unwrap() as u32, 2);
}
#[test]
fn time_interrupt_remaining() {
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
fn signal_write_restart_frame_matches_native_context() {
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
fn signal_blocked_queue_delivers_after_unmask() {
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
fn signal_standard_queue_coalesces() {
    let mut f = signal_fixture();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    f.kernel.queue_signal(&mut f.thread, 10).unwrap();
    assert_eq!(f.thread.state.pending.len(), 1);
}
#[test]
fn signal_frame_fault_does_not_change_registers_or_memory() {
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
fn signal_return_preserves_registers_sse_and_mask() {
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
fn signal_frame_ignores_privileged_flag_edits() {
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
fn signal_bad_fp_pointer_rejects_context() {
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
fn signal_timer_periodic_coalesces_and_advances() {
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
fn signal_realtime_queue_has_no_invented_quota() {
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
fn signal_realtime_selection_keeps_fifo_and_masks() {
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
fn signal_pending_targets_keep_number_order_fifo_and_coalescing() {
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
fn signal_synchronous_fault_selects_thread_pending_queue() {
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
fn signal_thread_target_restart_preview_matches_delivery() {
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
fn signal_restart_preview_uses_selected_realtime_handler() {
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
fn signal_rep_budget_context_roundtrip() {
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
fn signal_changed_rep_return_discards_continuation() {
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
fn signal_nested_altstack_frames_do_not_overlap() {
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
fn default_stop_is_not_process_termination() {
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
fn blocked_tstp_defers_stop_until_unmask() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 19;
    f.kernel.queue_signal(&mut f.thread, 20).unwrap();
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Resume);
    assert!(!f.thread.state.stopped);
    assert_eq!(f.thread.state.pending.len(), 1);
    f.thread.state.signal_mask = 0;
    assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), Next::Stopped);
}
/// The `struct itimerval` at `at`: interval, then value, each as seconds and
/// microseconds.
fn itimerval_at(f: &Fixture, at: u64) -> [u64; 4] {
    std::array::from_fn(|i| f.mem.read_u64(GuestAddr(at + 8 * i as u64)).unwrap())
}
fn set_monotonic(f: &Fixture, ns: u64) {
    f.host.set_clock(paludarium_host::ClockId::Monotonic, ns);
}
#[test]
fn itimer_getitimer_reports_the_real_timer() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 13; // SIGALRM blocked, to stay pending
    set_monotonic(&f, 1_000_000_000);
    // Interval 2.5 s, first expiry in 1.000_000_7 s.
    for (i, word) in [2, 500_000, 1, 7].into_iter().enumerate() {
        f.mem
            .write_u64(GuestAddr(DATA + 8 * i as u64), word)
            .unwrap();
    }
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA, 0]), 0);
    set_monotonic(&f, 1_250_000_000);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    // The microseconds are cut down: 0.750_007 s left.
    assert_eq!(itimerval_at(&f, DATA + 64), [2, 500_000, 0, 750_007]);
    // Past the expiry the timer has gone on by its interval, and SIGALRM is
    // pending.
    set_monotonic(&f, 3_000_007_000);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [2, 500_000, 1, 500_000]);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0); // rt_sigpending
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 13);
}
#[test]
fn itimer_getitimer_checks_as_linux() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::GETITIMER, &[3, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::GETITIMER, &[u64::MAX, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::GETITIMER, &[0, 0]), errno(Errno::EFAULT));
    // Only the low 32 bits name the timer.
    assert_eq!(f.ret(nr::GETITIMER, &[1 << 32, DATA]), 0);
    // The CPU-time timers start disarmed.
    for which in [1, 2] {
        f.mem.write_u64(GuestAddr(DATA), 9).unwrap();
        assert_eq!(f.ret(nr::GETITIMER, &[which, DATA]), 0);
        assert_eq!(itimerval_at(&f, DATA), [0; 4]);
    }
}
fn write_itimerval(f: &Fixture, at: u64, words: [u64; 4]) {
    for (i, word) in words.into_iter().enumerate() {
        f.mem.write_u64(GuestAddr(at + 8 * i as u64), word).unwrap();
    }
}
/// The fixture's host measures no thread CPU time, so a thread's CPU time
/// is the monotonic clock since its first system call.
#[test]
fn itimer_cpu_timers_count_cpu_time_and_send_their_signals() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 25 | 1 << 26; // SIGVTALRM, SIGPROF
    set_monotonic(&f, 1_000_000_000);
    // ITIMER_PROF: 10 ms, then every 5 ms. It is set a tick (1 ms) later.
    write_itimerval(&f, DATA, [0, 5_000, 0, 10_000]);
    assert_eq!(f.ret(nr::SETITIMER, &[2, DATA, DATA + 32]), 0);
    assert_eq!(itimerval_at(&f, DATA + 32), [0; 4]);
    set_monotonic(&f, 1_004_000_000);
    assert_eq!(f.ret(nr::GETITIMER, &[2, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 5_000, 0, 7_000]);
    // ITIMER_VIRTUAL is apart: it is still disarmed.
    assert_eq!(f.ret(nr::GETITIMER, &[1, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0; 4]);
    // At its expiry a checkpoint sends SIGPROF and sets it again by its
    // interval, once however far past.
    set_monotonic(&f, 1_030_000_000);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0); // rt_sigpending
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 26);
    // Its expiry (16 ms) has come: a tick left.
    assert_eq!(f.ret(nr::GETITIMER, &[2, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 5_000, 0, 1_000]);
    // A value of 0 disarms it but keeps the interval, unlike ITIMER_REAL.
    write_itimerval(&f, DATA, [3, 0, 0, 0]);
    assert_eq!(f.ret(nr::SETITIMER, &[2, DATA, DATA + 32]), 0);
    assert_eq!(itimerval_at(&f, DATA + 32), [0, 5_000, 0, 1_000]);
    assert_eq!(f.ret(nr::GETITIMER, &[2, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [3, 0, 0, 0]);
    // A value clamped to KTIME_MAX, a tick later, is past what a signed
    // time holds, so it shows negative seconds as on Linux.
    write_itimerval(&f, DATA, [0, 0, u64::MAX >> 1, 0]);
    assert_eq!(f.ret(nr::SETITIMER, &[1, DATA, 0]), 0);
    assert_eq!(f.ret(nr::GETITIMER, &[1, DATA + 64]), 0);
    assert_eq!(
        itimerval_at(&f, DATA + 64),
        [0, 0, (-9_223_372_037i64) as u64, 146_224]
    );
    // ITIMER_VIRTUAL sends SIGVTALRM, once with no interval.
    write_itimerval(&f, DATA, [0, 0, 0, 2_000]);
    assert_eq!(f.ret(nr::SETITIMER, &[1, DATA, 0]), 0);
    set_monotonic(&f, 1_040_000_000);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 25 | 1 << 26);
    assert_eq!(f.ret(nr::GETITIMER, &[1, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0; 4]);
}
/// The fixture's host measures no thread CPU time, so the CPU time is the
/// monotonic clock since the thread's first system call.
#[test]
fn rlimit_cpu_sends_sigxcpu_each_second_then_sigkill() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 23; // SIGXCPU blocked, to stay pending
    set_monotonic(&f, 1_000_000_000);
    write_itimerval(&f, DATA, [1, 3, 0, 0]); // soft 1 s, hard 3 s
    assert_eq!(f.ret(160, &[0, DATA]), 0); // setrlimit
    set_monotonic(&f, 1_900_000_000);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0); // rt_sigpending
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 0);
    // At the soft limit SIGXCPU comes, and the soft limit goes up a second.
    set_monotonic(&f, 2_000_000_000);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 23);
    assert_eq!(f.ret(97, &[0, DATA + 64]), 0); // getrlimit
    assert_eq!(itimerval_at(&f, DATA + 64)[..2], [2, 3]);
    // At the hard limit, SIGKILL.
    set_monotonic(&f, 4_000_000_000);
    assert_eq!(
        f.kernel.checkpoint(&mut f.thread, &f.mem),
        Next::Exit(ExitStatus::Signaled(9))
    );
}
/// Linux takes the limits to nanoseconds by a `u64` product, which wraps:
/// a soft limit of 2^55 s is 0 ns, so SIGXCPU comes at once.
#[test]
fn rlimit_cpu_limit_wraps_as_linux() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 23;
    set_monotonic(&f, 1_000_000_000);
    write_itimerval(&f, DATA, [1 << 55, u64::MAX, 0, 0]);
    assert_eq!(f.ret(160, &[0, DATA]), 0);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 23);
    assert_eq!(f.ret(97, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64)[..2], [(1 << 55) + 1, u64::MAX]);
}
#[test]
fn itimer_setitimer_checks_in_linux_order() {
    let mut f = fixture();
    set_monotonic(&f, 1_000);
    // The new value is read before the timer is checked.
    assert_eq!(f.ret(nr::SETITIMER, &[7, 8, 0]), errno(Errno::EFAULT));
    // And its times before the timer too.
    f.mem.write_u64(GuestAddr(DATA + 8), 1_000_000).unwrap();
    assert_eq!(f.ret(nr::SETITIMER, &[7, DATA, 0]), errno(Errno::EINVAL));
    f.mem.write_u64(GuestAddr(DATA + 8), 0).unwrap();
    f.mem.write_u64(GuestAddr(DATA + 16), 3).unwrap();
    assert_eq!(f.ret(nr::SETITIMER, &[7, DATA, 0]), errno(Errno::EINVAL));
    // An old value that cannot be written gives EFAULT with the timer set.
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA, 8]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 0, 3, 0]);
    // A value of 0 disarms it and drops its interval.
    for (i, word) in [4, 0, 0, 0].into_iter().enumerate() {
        f.mem
            .write_u64(GuestAddr(DATA + 32 + 8 * i as u64), word)
            .unwrap();
    }
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA + 32, 0]), 0);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0; 4]);
    // Seconds past KTIME_MAX are clamped, not refused.
    f.mem.write_u64(GuestAddr(DATA + 48), u64::MAX >> 1).unwrap();
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA + 32, 0]), 0);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    let left = itimerval_at(&f, DATA + 64);
    assert_eq!(left[..2], [4, 0]);
    assert_eq!(left[2], (i64::MAX as u64 - 1_000) / 1_000_000_000);
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA, 0]), 0);
    // No new value disarms it, and the old one is written out.
    assert_eq!(f.ret(nr::SETITIMER, &[0, 0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 0, 3, 0]);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0; 4]);
}
#[test]
fn itimer_alarm_rounds_what_was_left() {
    let mut f = fixture();
    set_monotonic(&f, 1_000);
    assert_eq!(f.ret(nr::ALARM, &[5]), 0);
    // 3.6 s left: rounded up.
    set_monotonic(&f, 1_400_001_000);
    assert_eq!(f.ret(nr::ALARM, &[10]), 4);
    // 3.4 s left: rounded down.
    set_monotonic(&f, 8_000_001_000);
    assert_eq!(f.ret(nr::ALARM, &[3]), 3);
    // Less than a second left is still 1.
    set_monotonic(&f, 10_999_999_000);
    assert_eq!(f.ret(nr::ALARM, &[0]), 1);
    // alarm(0) disarmed it.
    assert_eq!(f.ret(nr::ALARM, &[0]), 0);
    // alarm takes an unsigned int and clears the interval.
    for (i, word) in [1, 0, 1, 0].into_iter().enumerate() {
        f.mem
            .write_u64(GuestAddr(DATA + 8 * i as u64), word)
            .unwrap();
    }
    assert_eq!(f.ret(nr::SETITIMER, &[0, DATA, 0]), 0);
    assert_eq!(f.ret(nr::ALARM, &[(1 << 32) | 7]), 1);
    assert_eq!(f.ret(nr::GETITIMER, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 0, 7, 0]);
}
/// A POSIX timer on the process's CPU clock counts the process's CPU time
/// (here the monotonic clock since the thread's first account) and sends
/// its signal at the checkpoint that finds it due, then runs on by its
/// interval.
#[test]
fn posix_timer_on_the_process_cpu_clock_sends_its_signal() {
    let mut f = fixture();
    f.thread.state.signal_mask = 1 << 9; // SIGUSR1 blocked, to stay pending
    set_monotonic(&f, 1_000_000_000);
    f.mem.write_u64(GuestAddr(DATA + 256), 42).unwrap();
    f.mem.write_u64(GuestAddr(DATA + 264), 10).unwrap(); // SIGEV_SIGNAL, SIGUSR1
    assert_eq!(f.ret(nr::TIMER_CREATE, &[2, DATA + 256, DATA + 320]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 320)).unwrap() as u32, 0);
    write_itimerval(&f, DATA, [1, 0, 2, 0]); // every 1 s, from 2 s on
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 0, DATA, 0]), 0);
    set_monotonic(&f, 2_000_000_000);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [1, 0, 1, 0]);
    set_monotonic(&f, 2_999_999_999);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0); // rt_sigpending
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 0);
    set_monotonic(&f, 3_000_000_000);
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(127, &[DATA + 128, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 1 << 9);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [1, 0, 1, 0]);
    // The process's own clock by number 0; a task that is not there.
    let own = (!0u64 << 3) | 2;
    assert_eq!(f.ret(nr::TIMER_CREATE, &[own, DATA + 256, DATA + 320]), 0);
    assert_eq!(
        f.ret(nr::TIMER_CREATE, &[cpu_clock_id(0x0fff_fff0, false, 2), DATA + 256, DATA + 320]),
        errno(Errno::EINVAL)
    );
}
/// A SIGEV_NONE timer on the thread's CPU clock is never armed: reading it
/// moves its interval on past the clock, as Linux's `bump_cpu_timer`, and a
/// disarmed one shows no interval either.
#[test]
fn posix_timer_on_the_thread_cpu_clock_reads_as_linux() {
    let mut f = fixture();
    set_monotonic(&f, 1_000_000_000);
    f.mem.write_u64(GuestAddr(DATA + 264), 1 << 32).unwrap(); // SIGEV_NONE
    assert_eq!(f.ret(nr::TIMER_CREATE, &[3, DATA + 256, DATA + 320]), 0);
    write_itimerval(&f, DATA + 64, [7, 7, 7, 7]);
    // Absolute: at 0.5 s of the thread's CPU time, then every 0.25 s.
    write_itimerval(&f, DATA, [0, 250_000_000, 0, 500_000_000]);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 1, DATA, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 0, 0, 0]);
    set_monotonic(&f, 3_000_000_000); // 2 s of CPU time
    f.kernel.checkpoint(&mut f.thread, &f.mem);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[0, DATA + 64]), 0);
    assert_eq!(
        itimerval_at(&f, DATA + 64),
        [0, 250_000_000, 0, 250_000_000]
    );
    // Disarming gives the old value; then nothing shows, the interval
    // included.
    write_itimerval(&f, DATA, [5, 0, 0, 0]);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 0, DATA, DATA + 64]), 0);
    assert_eq!(
        itimerval_at(&f, DATA + 64),
        [0, 250_000_000, 0, 250_000_000]
    );
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[0, DATA + 64]), 0);
    assert_eq!(itimerval_at(&f, DATA + 64), [0, 0, 0, 0]);
    // A value past KTIME_MAX is clamped to it, not refused.
    write_itimerval(&f, DATA, [0, 0, i64::MAX as u64, 0]);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 0, DATA, 0]), 0);
}
/// The time is never set: what Linux takes gives EPERM, after Linux's
/// checks.
#[test]
fn setting_the_time_is_refused_after_linux_checks() {
    let mut f = fixture();
    let set = |f: &mut Fixture, words: [u64; 2]| {
        f.mem.write_u64(GuestAddr(DATA), words[0]).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), words[1]).unwrap();
    };
    // settimeofday: a bad pointer, bad microseconds, a bad time zone
    // pointer, a time too late, and then EPERM even with nothing to set.
    assert_eq!(f.ret(164, &[1, 0]), errno(Errno::EFAULT));
    set(&mut f, [5, 1_000_000]);
    assert_eq!(f.ret(164, &[DATA, 0]), errno(Errno::EINVAL));
    set(&mut f, [5, 0]);
    assert_eq!(f.ret(164, &[DATA, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(164, &[DATA, DATA]), errno(Errno::EPERM));
    set(&mut f, [8_277_292_036, 0]);
    assert_eq!(f.ret(164, &[DATA, 0]), errno(Errno::EINVAL));
    set(&mut f, [-1i64 as u64, 0]);
    assert_eq!(f.ret(164, &[DATA, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(164, &[0, 0]), errno(Errno::EPERM));
    // clock_settime: only CLOCK_REALTIME, before the time is read.
    for clock in [1, 2, 3, 4, 7, 8, 11, 12] {
        assert_eq!(f.ret(227, &[clock, 1]), errno(Errno::EINVAL));
    }
    assert_eq!(f.ret(227, &[0, 1]), errno(Errno::EFAULT));
    set(&mut f, [5, 1_000_000_000]);
    assert_eq!(f.ret(227, &[0, DATA]), errno(Errno::EINVAL));
    set(&mut f, [8_277_292_035, 999_999_999]);
    assert_eq!(f.ret(227, &[0, DATA]), errno(Errno::EPERM));
}
/// iopl, ioperm and acct check their arguments as Linux does, then refuse
/// what would need the host: ports even to root, accounting to a file.
#[test]
fn port_access_and_accounting_are_refused_after_linux_checks() {
    let mut f = fixture();
    let ports = syscalls::nr::IOPERM;
    for (level, expected) in [(0, 0), (1 << 32, 0), (1, errno(Errno::EPERM)), (3, errno(Errno::EPERM))] {
        assert_eq!(f.ret(syscalls::nr::IOPL, &[level]), expected);
    }
    for level in [4, u64::from(u32::MAX), (1 << 32) | 4] {
        assert_eq!(f.ret(syscalls::nr::IOPL, &[level]), errno(Errno::EINVAL));
    }
    // ioperm: the range first, even when turning off; then turning on.
    for (from, num) in [(0, 0), (65_535, 2), (65_536, 1), (u64::MAX, 2)] {
        assert_eq!(f.ret(ports, &[from, num, 0]), errno(Errno::EINVAL));
    }
    assert_eq!(f.ret(ports, &[0, 65_536, 0]), 0);
    assert_eq!(f.ret(ports, &[0x80, 1, 1 << 32]), 0);
    assert_eq!(f.ret(ports, &[65_535, 1, 1]), errno(Errno::EPERM));
    // acct: root may turn accounting off, but not on.
    assert_eq!(f.ret(syscalls::nr::ACCT, &[0]), 0);
    assert_eq!(f.ret(syscalls::nr::ACCT, &[1]), errno(Errno::EPERM));
    let root = f.thread.state.credentials.clone();
    f.thread.state.credentials = root.setresuid(1000, 1000, 1000).unwrap();
    assert_eq!(f.ret(syscalls::nr::ACCT, &[0]), errno(Errno::EPERM));
    assert_eq!(f.ret(syscalls::nr::IOPL, &[0]), 0);
    assert_eq!(f.ret(ports, &[0, 1, 0]), 0);
    assert_eq!(f.ret(ports, &[0, 1, 1]), errno(Errno::EPERM));
}
/// adjtimex reads Linux's state at boot and refuses to change it.
#[test]
fn adjtimex_reads_an_unsynchronised_clock() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 1_700_000_000_123_456_789);
    let timex = DATA + 0x100;
    f.mem.write(GuestAddr(timex), &[0x5a; 208]).unwrap();
    f.mem.write(GuestAddr(timex), &[0; 4]).unwrap(); // modes
    assert_eq!(f.ret(159, &[timex]), 5); // TIME_ERROR
    let word = |f: &Fixture, at: u64| f.mem.read_u64(GuestAddr(timex + at)).unwrap();
    let fields: Vec<u64> = [8, 16, 24, 32, 48, 56, 64, 72, 80, 88, 96, 104, 120, 152]
        .iter()
        .map(|&at| word(&f, at))
        .collect();
    assert_eq!(
        fields,
        [
            0, 0, 16_000_000, 16_000_000, 2, 1, 32_768_000, 1_700_000_000, 123_456,
            10_000, 0, 0, 0, 0
        ]
    );
    assert_eq!(word(&f, 40) as u32, 0x40); // STA_UNSYNC
    assert_eq!(word(&f, 160) as u32, 0); // tai
    // The modes and the padding are left as they were.
    assert_eq!(word(&f, 0), 0x5a5a_5a5a_0000_0000);
    assert_eq!(word(&f, 200), 0x5a5a_5a5a_5a5a_5a5a);
    // adjtime's read is taken; a change, or a single shot without its
    // bit, is not.
    f.mem.write_u64(GuestAddr(timex), 0xa001).unwrap();
    assert_eq!(f.ret(159, &[timex]), 5);
    f.mem.write_u64(GuestAddr(timex), 0x8000).unwrap();
    assert_eq!(f.ret(159, &[timex]), errno(Errno::EINVAL));
    for modes in [0x0001, 0x8001, 0x4000, 0xa101] {
        f.mem.write_u64(GuestAddr(timex), modes).unwrap();
        assert_eq!(f.ret(159, &[timex]), errno(Errno::EPERM));
    }
    // A read with a frequency past Linux's range.
    f.mem.write_u64(GuestAddr(timex), 0xa003).unwrap();
    f.mem.write_u64(GuestAddr(timex + 16), i64::MAX as u64).unwrap();
    assert_eq!(f.ret(159, &[timex]), errno(Errno::EINVAL));
    assert_eq!(f.ret(159, &[1]), errno(Errno::EFAULT));
    // clock_adjtime: the buffer first, then the clock.
    f.mem.write_u64(GuestAddr(timex), 0).unwrap();
    assert_eq!(f.ret(305, &[99, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(305, &[0, timex]), 5);
    for (clock, e) in [
        (1, Errno::EOPNOTSUPP),
        (11, Errno::EOPNOTSUPP),
        (10, Errno::EINVAL),
        (12, Errno::EINVAL),
        (u64::from(u32::MAX), Errno::EOPNOTSUPP),
        (u64::from(!0u32 << 3 | 3), Errno::EINVAL),
    ] {
        assert_eq!(f.ret(305, &[clock, timex]), errno(e));
    }
}
