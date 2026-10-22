use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr, InstructionBytes, USER_ADDRESS_LIMIT};

const DATA: u64 = 0x10_0000;

struct Fixture {
    host: Arc<RecordingHost>,
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
}

fn fixture() -> Fixture {
    let host = Arc::new(RecordingHost::new());
    let kernel = Kernel::new(host.clone());
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(DATA)),
        0x2000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    mem.set_initial_break(GuestAddr(0x20_0000));
    let thread = Thread {
        tid: 1,
        state: ThreadState {
            pid: 1,
            ..ThreadState::default()
        },
        cpu: CpuState::default(),
    };
    Fixture {
        host,
        kernel,
        thread,
        mem,
    }
}

impl Fixture {
    fn call(&mut self, number: u64, args: &[u64]) -> Next {
        self.thread.cpu.gpr[reg::RAX] = number;
        let regs = [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9];
        for (r, v) in regs.iter().zip(args) {
            self.thread.cpu.gpr[*r] = *v;
        }
        let reason = ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        };
        self.kernel.handle(&mut self.thread, &self.mem, reason)
    }

    fn ret(&mut self, number: u64, args: &[u64]) -> u64 {
        assert_eq!(self.call(number, args), Next::Resume);
        self.thread.cpu.gpr[reg::RAX]
    }
}

fn errno(e: Errno) -> u64 {
    e.to_syscall_return()
}

struct ShortWriteHost {
    first: usize,
    calls: std::sync::atomic::AtomicUsize,
}

impl ShortWriteHost {
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if call == 0 {
            Ok(self.first)
        } else if self.first == 0 {
            // Bound the regression: the old retry loop fails rather than hangs.
            Err(Errno::EIO)
        } else {
            Ok(buf.len())
        }
    }
}

impl paludarium_host::Host for ShortWriteHost {
    fn read_stdin(&self, _buf: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EIO)
    }

    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.write(buf)
    }

    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.write(buf)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), paludarium_types::Error> {
        buf.fill(0);
        Ok(())
    }
}

#[test]
fn write_returns_zero_without_retrying_host() {
    for fd in [1, 2] {
        let host = Arc::new(ShortWriteHost {
            first: 0,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut f = fixture();
        f.kernel = Kernel::new(host.clone());
        f.mem.write(GuestAddr(DATA), b"hello").unwrap();
        assert_eq!(f.ret(nr::WRITE, &[fd, DATA, 5]), 0);
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[test]
fn write_returns_partial_count_without_filling_remainder() {
    for fd in [1, 2] {
        let host = Arc::new(ShortWriteHost {
            first: 1,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut f = fixture();
        f.kernel = Kernel::new(host.clone());
        f.mem.write(GuestAddr(DATA), b"hello").unwrap();
        assert_eq!(f.ret(nr::WRITE, &[fd, DATA, 5]), 1);
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[test]
fn write_goes_to_host_streams_only_for_fd_1_and_2() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"hello").unwrap();
    assert_eq!(f.ret(nr::WRITE, &[1, DATA, 5]), 5);
    assert_eq!(f.ret(nr::WRITE, &[2, DATA, 2]), 2);
    assert_eq!(f.host.stdout(), b"hello");
    assert_eq!(f.host.stderr(), b"he");
    assert_eq!(f.ret(nr::WRITE, &[0, DATA, 5]), errno(Errno::EBADF));
    assert_eq!(f.ret(nr::WRITE, &[3, DATA, 5]), errno(Errno::EBADF));
    // A bad buffer is EFAULT; a buffer running off the mapping is partial.
    assert_eq!(f.ret(nr::WRITE, &[1, 0x1000, 5]), errno(Errno::EFAULT));
    assert_eq!(
        f.ret(nr::WRITE, &[1, DATA + 0x2000 - 3, 1 << 20]),
        errno(Errno::EFAULT)
    );
    assert_eq!(f.ret(nr::WRITE, &[1, DATA, 0]), 0);
}

#[test]
fn unknown_syscalls_are_enosys_and_network_is_rejected() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::SOCKET, &[2, 1, 0]), errno(Errno(97)));
    assert_eq!(f.ret(0, &[0, DATA, 1]), 0); // files: stdin EOF
    assert_eq!(f.ret(u64::MAX, &[]), errno(Errno::ENOSYS));
    assert_eq!(f.ret(1_000_000, &[]), errno(Errno::ENOSYS));
    assert!(SyscallTable::u1().contains(nr::SOCKET));
}

#[test]
fn madvise_drops_private_pages_and_checks_its_arguments() {
    let mut f = fixture();
    f.mem.write_u64(GuestAddr(DATA), 5).unwrap();
    f.mem.write_u64(GuestAddr(DATA + 0x1000), 6).unwrap();
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 1, 4]), 0); // MADV_DONTNEED
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 0x1000)).unwrap(), 6);
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x2000, 8]), 0); // MADV_FREE
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 0x1000)).unwrap(), 6);
    f.mem.write_u64(GuestAddr(DATA), 7).unwrap();
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x2000, 2]), 0); // MADV_SEQUENTIAL
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 7);
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0, 4]), 0);
    assert_eq!(
        f.ret(nr::MADVISE, &[DATA, 0x2000, 99]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::MADVISE, &[DATA + 1, 1, 4]), errno(Errno::EINVAL));
    assert_eq!(
        f.ret(nr::MADVISE, &[DATA, u64::MAX, 4]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x3000, 0]), errno(Errno::ENOMEM));
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x3000, 4]), errno(Errno::ENOMEM));
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x3000, 8]), errno(Errno::ENOMEM));
    f.mem.mark_shared(GuestAddr(DATA), 0x2000).unwrap();
    assert_eq!(f.ret(nr::MADVISE, &[DATA, 0x2000, 8]), errno(Errno::EINVAL));
}

#[test]
fn uname_names_linux_x86_64_and_ids_are_root() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::UNAME, &[DATA]), 0);
    let mut fields = [0u8; 390];
    f.mem.read(GuestAddr(DATA), &mut fields).unwrap();
    let field = |i: usize| {
        let bytes = &fields[i * 65..(i + 1) * 65];
        bytes[..bytes.iter().position(|&b| b == 0).unwrap()].to_vec()
    };
    assert_eq!(field(0), b"Linux");
    assert_eq!(field(4), b"x86_64");
    assert_eq!(field(5), b"(none)");
    assert_eq!(f.ret(nr::UNAME, &[0]), errno(Errno::EFAULT));
    for number in [nr::GETUID, nr::GETGID, nr::GETEUID, nr::GETEGID] {
        assert_eq!(f.ret(number, &[]), 0);
    }
}

#[test]
fn sched_getaffinity_reports_every_host_cpu() {
    let mut f = fixture();
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let size = cpus.div_ceil(64) as u64 * 8;
    assert_eq!(f.ret(nr::SCHED_GETAFFINITY, &[0, 128, DATA]), size);
    let mut mask = vec![0u8; size as usize];
    f.mem.read(GuestAddr(DATA), &mut mask).unwrap();
    let ones: u32 = mask.iter().map(|b| b.count_ones()).sum();
    assert_eq!(ones as usize, cpus);
    assert_eq!(f.ret(nr::SCHED_GETAFFINITY, &[1, 8, DATA]), 8.min(size));
    assert_eq!(
        f.ret(nr::SCHED_GETAFFINITY, &[0, 12, DATA]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::SCHED_GETAFFINITY, &[0, 0, DATA]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::SCHED_GETAFFINITY, &[99, 8, DATA]),
        errno(Errno(3))
    );
    assert_eq!(
        f.ret(nr::SCHED_GETAFFINITY, &[0, 8, 0]),
        errno(Errno::EFAULT)
    );
}

#[test]
fn exit_and_exit_group_keep_low_eight_bits() {
    let mut f = fixture();
    assert_eq!(
        f.call(nr::EXIT_GROUP, &[0x1_2345]),
        Next::Exit(ExitStatus::Exited(0x45))
    );
    assert_eq!(f.thread.state.exit_status, Some(ExitStatus::Exited(0x45)));
    let mut f = fixture();
    assert_eq!(
        f.call(nr::EXIT, &[u64::MAX]),
        Next::Exit(ExitStatus::Exited(255))
    );
}

#[test]
fn guest_exceptions_end_the_process_with_signals() {
    let mut f = fixture();
    let rip = GuestAddr(0x1000);
    let mut handle = |reason| fixture().kernel.handle(&mut f.thread, &f.mem, reason);
    assert_eq!(
        handle(ExitReason::PageFault {
            rip,
            addr: GuestAddr(0),
            write: false,
            fetch: false,
            mapped: false,
            present: false
        }),
        Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
    );
    assert_eq!(
        handle(ExitReason::InvalidOpcode {
            rip,
            bytes: InstructionBytes::new(&[0x0f, 0x0b])
        }),
        Next::Exit(ExitStatus::Signaled(signal::SIGILL))
    );
    assert_eq!(
        handle(ExitReason::Halt { rip }),
        Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
    );
    assert_eq!(
        handle(ExitReason::ArithmeticFault { rip }),
        Next::Exit(ExitStatus::Signaled(signal::SIGFPE))
    );
    assert_eq!(handle(ExitReason::BudgetExhausted { rip }), Next::Resume);
}

#[test]
fn arithmetic_fault_terminates_with_sigfpe() {
    let mut f = fixture();
    assert_eq!(
        f.kernel.handle(
            &mut f.thread,
            &f.mem,
            ExitReason::ArithmeticFault {
                rip: GuestAddr(0x1000)
            }
        ),
        Next::Exit(ExitStatus::Signaled(signal::SIGFPE))
    );
}

#[test]
fn floating_point_fault_codes_terminate_with_sigfpe() {
    for code in [3, 4, 5, 6, 7] {
        let mut f = fixture();
        assert_eq!(
            f.kernel.handle(
                &mut f.thread,
                &f.mem,
                ExitReason::FloatingPointFault {
                    rip: GuestAddr(0x1000),
                    code
                }
            ),
            Next::Exit(ExitStatus::Signaled(signal::SIGFPE))
        );
    }
}

#[test]
fn signal_registration_is_recorded_but_not_delivered() {
    let mut f = fixture();
    // act = { handler 0x1234, flags 0x04000000, restorer 0x5678, mask 0x100 }
    let act = [0x1234u64, 0x0400_0000, 0x5678, 0x100 | (1 << 8)];
    for (i, w) in act.iter().enumerate() {
        f.mem.write_u64(GuestAddr(DATA + 8 * i as u64), *w).unwrap();
    }
    assert_eq!(f.ret(nr::RT_SIGACTION, &[11, DATA, DATA + 0x100, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap(), 0); // old = SIG_DFL
    assert_eq!(f.ret(nr::RT_SIGACTION, &[11, 0, DATA + 0x100, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap(), 0x1234);
    assert_eq!(f.thread.state.signal_actions[&11].handler, 0x1234);
    assert_eq!(
        f.ret(nr::RT_SIGACTION, &[9, DATA, 0, 8]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::RT_SIGACTION, &[11, DATA, 0, 4]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::RT_SIGACTION, &[65, 0, 0, 8]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::RT_SIGACTION, &[11, 0x1000, 0, 8]),
        errno(Errno::EFAULT)
    );
    // rt_sigprocmask: block, then unblock; SIGKILL can never be blocked.
    f.mem
        .write_u64(GuestAddr(DATA), (1 << 8) | (1 << 9))
        .unwrap();
    assert_eq!(f.ret(nr::RT_SIGPROCMASK, &[0, DATA, 0, 8]), 0);
    assert_eq!(f.thread.state.signal_mask, 1 << 9);
    assert_eq!(f.ret(nr::RT_SIGPROCMASK, &[1, DATA, DATA + 8, 8]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 1 << 9);
    assert_eq!(f.thread.state.signal_mask, 0);
    assert_eq!(
        f.ret(nr::RT_SIGPROCMASK, &[7, DATA, 0, 8]),
        errno(Errno::EINVAL)
    );
}

#[test]
fn memory_syscalls_map_protect_unmap_and_brk() {
    let mut f = fixture();
    let anon_private = 0x22;
    let a = f.ret(nr::MMAP, &[0, 12288, 3, anon_private, u64::MAX, 0]);
    assert!(a < USER_ADDRESS_LIMIT && a.is_multiple_of(4096));
    f.mem.write_u64(GuestAddr(a), 1).unwrap();
    assert_eq!(f.ret(nr::MPROTECT, &[a, 4096, 0]), 0);
    assert!(f.mem.read_u64(GuestAddr(a)).is_err());
    // MAP_FIXED replaces the existing page.
    let fixed = f.ret(nr::MMAP, &[a, 4096, 3, anon_private | 0x10, u64::MAX, 0]);
    assert_eq!(fixed, a);
    assert_eq!(f.mem.read_u64(GuestAddr(a)).unwrap(), 0);
    assert_eq!(f.ret(nr::MUNMAP, &[a, 12288]), 0);
    // The signals/time native memory CASE1 verifies shared anonymous mappings are valid.
    let shared = f.ret(nr::MMAP, &[0, 4096, 3, 0x21, u64::MAX, 0]);
    assert!(shared < USER_ADDRESS_LIMIT && shared.is_multiple_of(4096));
    assert_eq!(f.mem.read_u64(GuestAddr(shared)).unwrap(), 0);
    assert_eq!(f.ret(nr::MUNMAP, &[shared, 4096]), 0);
    // File-backed forms belong to the files tests.
    assert_eq!(
        f.ret(nr::MMAP, &[0, 4096, 3, 0x02, 3, 0]),
        errno(Errno::EBADF)
    );
    assert_eq!(
        f.ret(nr::MMAP, &[0, 0, 3, anon_private, u64::MAX, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::MMAP, &[0, 4096, 8, anon_private, u64::MAX, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::MPROTECT, &[a + 1, 4096, 1]), errno(Errno::EINVAL));
    // brk.
    assert_eq!(f.ret(nr::BRK, &[0]), 0x20_0000);
    assert_eq!(f.ret(nr::BRK, &[0x20_2000]), 0x20_2000);
    assert_eq!(f.ret(nr::BRK, &[0x1000]), 0x20_2000);
}

#[test]
fn process_setup_syscalls() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::ARCH_PRCTL, &[0x1002, 0x7000_0000]), 0);
    assert_eq!(f.thread.cpu.fs_base, 0x7000_0000);
    assert_eq!(f.ret(nr::ARCH_PRCTL, &[0x1003, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 0x7000_0000);
    assert_eq!(
        f.ret(nr::ARCH_PRCTL, &[0x1002, u64::MAX]),
        errno(Errno::EPERM)
    );
    assert_eq!(f.ret(nr::ARCH_PRCTL, &[0x9999, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::SET_TID_ADDRESS, &[DATA]), 1);
    assert_eq!(f.thread.state.clear_child_tid, DATA);
    assert_eq!(f.ret(nr::IOCTL, &[1, 0x5413, DATA]), errno(Errno::ENOTTY));
    assert_eq!(f.ret(nr::IOCTL, &[5, 0x5413, DATA]), errno(Errno::EBADF));
}

#[test]
fn poll_and_sigaltstack() {
    let mut f = fixture();
    // { fd 0, events 0 }, { fd 1, events POLLOUT }, { fd 9, events POLLIN }
    let fds: [(i32, u16); 3] = [(0, 0), (1, 4), (9, 1)];
    for (i, (fd, ev)) in fds.iter().enumerate() {
        let at = DATA + 8 * i as u64;
        f.mem.write(GuestAddr(at), &fd.to_le_bytes()).unwrap();
        f.mem.write(GuestAddr(at + 4), &ev.to_le_bytes()).unwrap();
    }
    assert_eq!(f.ret(nr::POLL, &[DATA, 3, 0]), 2);
    let mut rev = [0u8; 2];
    f.mem.read(GuestAddr(DATA + 14), &mut rev).unwrap();
    assert_eq!(u16::from_le_bytes(rev), 4);
    f.mem.read(GuestAddr(DATA + 22), &mut rev).unwrap();
    assert_eq!(u16::from_le_bytes(rev), 0x20);
    assert_eq!(f.ret(nr::POLL, &[DATA, 2000, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::POLL, &[0x1000, 1, 0]), errno(Errno::EFAULT));

    // sigaltstack: query (disabled), set, query again, too small.
    assert_eq!(f.ret(nr::SIGALTSTACK, &[0, DATA + 0x200]), 0);
    assert_eq!(
        f.mem.read_u64(GuestAddr(DATA + 0x208)).unwrap(),
        u64::from(SS_DISABLE)
    );
    for (i, w) in [0x7000u64, 0, 8192].iter().enumerate() {
        f.mem
            .write_u64(GuestAddr(DATA + 0x300 + 8 * i as u64), *w)
            .unwrap();
    }
    assert_eq!(f.ret(nr::SIGALTSTACK, &[DATA + 0x300, 0]), 0);
    assert_eq!(f.thread.state.alt_stack.size, 8192);
    f.mem.write_u64(GuestAddr(DATA + 0x310), 100).unwrap();
    assert_eq!(
        f.ret(nr::SIGALTSTACK, &[DATA + 0x300, 0]),
        errno(Errno::ENOMEM)
    );
}

mod signals_time_tests {
    use super::*;
    include!("signals_time_tests.rs");
}

#[test]
fn syscall_huge_bad_read_buffer() {
    let mut f = fixture();
    assert_eq!(f.ret(0, &[0, 1, u64::MAX]), errno(Errno::EFAULT));
}
#[test]
fn syscall_huge_bad_write_buffer() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, 1, u64::MAX]), errno(Errno::EFAULT));
}
fn stat_mode_and_mtime(f: &mut Fixture, path: u64, lstat: bool) -> (u32, i64, u64) {
    let out = DATA + 0x100;
    assert_eq!(f.ret(if lstat { 6 } else { 4 }, &[path, out]), 0);
    let mut st = [0u8; 144];
    f.mem.read(GuestAddr(out), &mut st).unwrap();
    (
        u32::from_le_bytes(st[24..28].try_into().unwrap()),
        i64::from_le_bytes(st[88..96].try_into().unwrap()),
        u64::from_le_bytes(st[96..104].try_into().unwrap()),
    )
}
#[test]
fn umask_and_the_chmod_family_set_permission_bits() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x10), b"/link\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x20), b"/none\0").unwrap();
    assert_eq!(f.ret(95, &[0o1077]), 0o022); // umask returns the old mask
    assert_eq!(f.ret(95, &[0o022]), 0o077); // and keeps only 0777
    assert_eq!(f.ret(95, &[0o077]), 0o022);
    let fd = f.ret(2, &[DATA, 66, 0o666]);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).0, 0o100_600);
    assert_eq!(f.ret(88, &[DATA, DATA + 0x10]), 0); // symlink /link -> /file
    assert_eq!(f.ret(90, &[DATA + 0x10, 0o4751]), 0); // chmod follows the link
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).0, 0o104_751);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA + 0x10, true).0, 0o120_777);
    assert_eq!(f.ret(91, &[fd, 0o640]), 0); // fchmod
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).0, 0o100_640);
    assert_eq!(f.ret(268, &[(-100i64) as u64, DATA, 0o604]), 0); // fchmodat
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).0, 0o100_604);
    assert_eq!(f.ret(90, &[DATA + 0x20, 0o600]), errno(Errno::ENOENT));
    assert_eq!(f.ret(91, &[99, 0o600]), errno(Errno::EBADF));
    assert_eq!(f.ret(90, &[0, 0o600]), errno(Errno::EFAULT));
}
#[test]
fn utimensat_sets_modification_times_as_linux_checks_them() {
    let mut f = fixture();
    let (cwd, times) = ((-100i64) as u64, DATA + 0x300);
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x10), b"/link\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x20), b"\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(88, &[DATA, DATA + 0x10]), 0);
    let set = |f: &mut Fixture, a: (i64, u64), m: (i64, u64)| {
        let mut b = Vec::new();
        for v in [a.0 as u64, a.1, m.0 as u64, m.1] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        f.mem.write(GuestAddr(times), &b).unwrap();
    };
    set(&mut f, (1, 2), (1000, 500));
    assert_eq!(f.ret(280, &[cwd, DATA + 0x10, times, 0]), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).1, 1000);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).2, 500);
    // UTIME_OMIT keeps the time; AT_SYMLINK_NOFOLLOW changes the link.
    set(&mut f, (0, (1 << 30) - 2), (0, (1 << 30) - 2));
    assert_eq!(f.ret(280, &[cwd, DATA, times, 0]), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).1, 1000);
    set(&mut f, (0, 0), (-3, 7));
    assert_eq!(f.ret(280, &[cwd, DATA + 0x10, times, 0x100]), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA + 0x10, true).1, -3);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).1, 1000);
    // A null path with a descriptor, and AT_EMPTY_PATH, are futimens.
    set(&mut f, (0, 0), (2000, 0));
    assert_eq!(f.ret(280, &[fd, 0, times, 0]), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).1, 2000);
    set(&mut f, (0, 0), (3000, 0));
    assert_eq!(f.ret(280, &[fd, DATA + 0x20, times, 0x1000]), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA, false).1, 3000);
    // A null times pointer means now.
    assert_eq!(f.ret(280, &[cwd, DATA, 0, 0]), 0);
    assert!(stat_mode_and_mtime(&mut f, DATA, false).1 > 3000);
    // Errors.
    set(&mut f, (0, 1_000_000_000), (0, 0));
    assert_eq!(f.ret(280, &[cwd, DATA, times, 0]), errno(Errno::EINVAL));
    set(&mut f, (0, 0), (0, 0));
    assert_eq!(f.ret(280, &[cwd, DATA, times, 0x2]), errno(Errno::EINVAL));
    assert_eq!(f.ret(280, &[fd, 0, times, 0x100]), errno(Errno::EINVAL));
    assert_eq!(f.ret(280, &[cwd, 0, times, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(280, &[cwd, DATA, 8, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(280, &[99, 0, times, 0]), errno(Errno::EBADF));
    // With both times omitted Linux does not even look at the path or flags.
    set(&mut f, (0, (1 << 30) - 2), (0, (1 << 30) - 2));
    f.mem.write(GuestAddr(DATA + 0x20), b"/none\0").unwrap();
    assert_eq!(f.ret(280, &[cwd, DATA + 0x20, times, 0]), 0);
    assert_eq!(f.ret(280, &[99, 0, times, 0x2]), 0);
    set(&mut f, (0, 0), (0, 0));
    assert_eq!(
        f.ret(280, &[cwd, DATA + 0x20, times, 0]),
        errno(Errno::ENOENT)
    );
}
#[test]
fn fsync_sync_and_fadvise_check_the_descriptor() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(22, &[DATA + 0x400]), 0);
    let mut pipe = [0u8; 4];
    f.mem.read(GuestAddr(DATA + 0x400), &mut pipe).unwrap();
    let pipe = u64::from(u32::from_le_bytes(pipe));
    for number in [74, 75] {
        assert_eq!(f.ret(number, &[fd]), 0);
        assert_eq!(f.ret(number, &[pipe]), errno(Errno::EINVAL));
        assert_eq!(f.ret(number, &[99]), errno(Errno::EBADF));
    }
    assert_eq!(f.ret(162, &[]), 0);
    assert_eq!(f.ret(221, &[fd, 0, 0, 2]), 0);
    assert_eq!(f.ret(221, &[pipe, 0, 0, 2]), errno(Errno(29)));
    assert_eq!(f.ret(221, &[fd, 0, 0, 6]), errno(Errno::EINVAL));
    assert_eq!(f.ret(221, &[fd, 0, u64::MAX, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(221, &[99, 0, 0, 0]), errno(Errno::EBADF));
}
#[test]
fn access_grants_root_reading_and_writing_but_execution_needs_a_bit() {
    let mut f = fixture();
    let cwd = (-100i64) as u64;
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x10), b"/tmp\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x20), b"\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x30), b"/none\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(21, &[DATA, 0]), 0);
    assert_eq!(f.ret(21, &[DATA, 6]), 0);
    assert_eq!(f.ret(21, &[DATA, 1]), errno(Errno(13)));
    assert_eq!(f.ret(90, &[DATA, 0o700]), 0);
    assert_eq!(f.ret(21, &[DATA, 7]), 0);
    assert_eq!(f.ret(269, &[cwd, DATA + 0x10, 1]), 0);
    assert_eq!(f.ret(439, &[fd, DATA + 0x20, 4, 0x1000]), 0);
    assert_eq!(f.ret(21, &[DATA + 0x30, 0]), errno(Errno::ENOENT));
    assert_eq!(f.ret(21, &[DATA, 8]), errno(Errno::EINVAL));
    assert_eq!(f.ret(439, &[cwd, DATA, 0, 0x400]), errno(Errno::EINVAL));
    assert_eq!(f.ret(21, &[0, 0]), errno(Errno::EFAULT));
}
#[test]
fn sysinfo_getgroups_and_sched_yield() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::SYSINFO, &[DATA]), 0);
    let mut info = [0u8; 112];
    f.mem.read(GuestAddr(DATA), &mut info).unwrap();
    let word = |i: usize| u64::from_le_bytes(info[i..i + 8].try_into().unwrap());
    assert_eq!((word(32), word(40)), (4 << 30, 4 << 30)); // totalram, freeram
    assert_eq!(u32::from_le_bytes(info[104..108].try_into().unwrap()), 1);
    assert!(u16::from_le_bytes([info[80], info[81]]) >= 1);
    assert_eq!(f.ret(nr::SYSINFO, &[1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::GETGROUPS, &[0, 0]), 0);
    assert_eq!(f.ret(nr::GETGROUPS, &[u64::MAX, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::SCHED_YIELD, &[]), 0);
}
#[test]
fn resource_limits_are_recorded_in_linux_order() {
    let mut f = fixture();
    let (new, old) = (DATA, DATA + 0x10);
    assert_eq!(f.ret(97, &[7, old]), 0); // getrlimit(NOFILE)
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 1024);
    assert_eq!(f.mem.read_u64(GuestAddr(old + 8)).unwrap(), 4096);
    f.mem.write_u64(GuestAddr(new), 256).unwrap();
    f.mem.write_u64(GuestAddr(new + 8), 4096).unwrap();
    assert_eq!(f.ret(160, &[7, new]), 0); // setrlimit
    assert_eq!(f.ret(302, &[0, 7, 0, old]), 0); // prlimit64
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 256);
    // The limit is set before a bad output buffer is reported.
    f.mem.write_u64(GuestAddr(new), 128).unwrap();
    assert_eq!(f.ret(302, &[0, 7, new, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(97, &[7, old]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 128);
    f.mem.write_u64(GuestAddr(new), 5000).unwrap();
    assert_eq!(f.ret(160, &[7, new]), errno(Errno::EINVAL)); // soft > hard
    f.mem.write_u64(GuestAddr(new + 8), 1 << 21).unwrap();
    assert_eq!(f.ret(160, &[7, new]), errno(Errno::EPERM)); // above nr_open
    assert_eq!(f.ret(97, &[16, old]), errno(Errno::EINVAL));
    assert_eq!(f.ret(302, &[99, 7, 0, old]), errno(Errno(3)));
    assert_eq!(f.ret(302, &[0, 7, 1, old]), errno(Errno::EFAULT));
    assert_eq!(f.ret(97, &[3, old]), 0); // STACK: 8 MiB, unlimited
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 8 << 20);
    assert_eq!(f.mem.read_u64(GuestAddr(old + 8)).unwrap(), u64::MAX);
}
#[test]
fn process_groups_start_at_the_first_process() {
    let mut f = fixture();
    assert_eq!(f.ret(111, &[]), 1); // getpgrp
    assert_eq!(f.ret(121, &[0]), 1); // getpgid
    assert_eq!(f.ret(109, &[0, 0]), 0); // setpgid
    assert_eq!(f.ret(109, &[1, 1]), 0);
    assert_eq!(f.ret(109, &[0, 77]), errno(Errno::EPERM));
    assert_eq!(f.ret(109, &[0, u64::MAX]), errno(Errno::EINVAL));
    assert_eq!(f.ret(109, &[99, 0]), errno(Errno(3)));
    assert_eq!(f.ret(121, &[99]), errno(Errno(3)));
    assert_eq!(f.ret(121, &[u64::MAX]), errno(Errno(3)));
}
#[test]
fn posix_timer_signal_reaches_sigtimedwait() {
    let mut f = fixture();
    let (id, set, info, spec) = (DATA, DATA + 0x10, DATA + 0x100, DATA + 0x200);
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 0, id]), 0);
    let timer = u64::from(u32::from_le_bytes({
        let mut b = [0; 4];
        f.mem.read(GuestAddr(id), &mut b).unwrap();
        b
    }));
    assert_eq!(timer, 0);
    // Arm it for 20 ms, block nothing, and wait for SIGALRM.
    for (i, v) in [0u64, 0, 0, 20_000_000].iter().enumerate() {
        f.mem.write_u64(GuestAddr(spec + 8 * i as u64), *v).unwrap();
    }
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[timer, 0, spec, 0]), 0);
    f.mem.write_u64(GuestAddr(set), 1 << 13).unwrap(); // SIGALRM
    assert_eq!(f.ret(nr::RT_SIGTIMEDWAIT, &[set, info, 0, 8]), 14);
    let mut siginfo = [0u8; 32];
    f.mem.read(GuestAddr(info), &mut siginfo).unwrap();
    assert_eq!(i32::from_le_bytes(siginfo[8..12].try_into().unwrap()), -2); // SI_TIMER
    assert_eq!(i32::from_le_bytes(siginfo[16..20].try_into().unwrap()), 0); // si_timerid
    assert_eq!(u64::from_le_bytes(siginfo[24..32].try_into().unwrap()), 0); // si_value
    assert_eq!(f.ret(nr::TIMER_DELETE, &[timer]), 0);
    assert_eq!(f.ret(nr::TIMER_DELETE, &[timer]), errno(Errno::EINVAL));
}
fn timer_spec(f: &mut Fixture, at: u64, interval: u64, value: u64) {
    let words = [
        interval / 1_000_000_000,
        interval % 1_000_000_000,
        value / 1_000_000_000,
        value % 1_000_000_000,
    ];
    for (i, v) in words.iter().enumerate() {
        f.mem.write_u64(GuestAddr(at + 8 * i as u64), *v).unwrap();
    }
}
#[test]
fn posix_timers_check_arguments_and_report_their_state() {
    let mut f = fixture();
    let (id, sev, spec, old) = (DATA, DATA + 0x40, DATA + 0x100, DATA + 0x140);
    // sigevent: value 42, SIGUSR1, SIGEV_SIGNAL
    f.mem.write_u64(GuestAddr(sev), 42).unwrap();
    f.mem.write_u64(GuestAddr(sev + 8), 10).unwrap();
    assert_eq!(f.ret(nr::TIMER_CREATE, &[0, sev, id]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(id)).unwrap() as u32, 0);
    f.mem.write_u64(GuestAddr(sev + 8), 1 << 32).unwrap(); // SIGEV_NONE
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(id)).unwrap() as u32, 1);
    timer_spec(&mut f, spec, 5_000_000_000, 10_000_000_000);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[1, 0, spec, old]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(old + 16)).unwrap(), 0); // was disarmed
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[1, old]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 5); // interval
    assert!(f.mem.read_u64(GuestAddr(old + 16)).unwrap() >= 9); // seconds left
    assert_eq!(f.ret(nr::TIMER_GETOVERRUN, &[1]), 0);
    // Errors: clocks, signals and notifications that are not supported.
    assert_eq!(f.ret(nr::TIMER_CREATE, &[2, 0, id]), errno(Errno::EINVAL));
    f.mem.write_u64(GuestAddr(sev + 8), 99).unwrap();
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), errno(Errno::EINVAL));
    f.mem.write_u64(GuestAddr(sev + 8), 4 << 32 | 10).unwrap(); // SIGEV_THREAD_ID
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 1, id]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 0, 1]), errno(Errno::EFAULT));
    assert_eq!(
        f.ret(nr::TIMER_SETTIME, &[1, 2, spec, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::TIMER_SETTIME, &[1, 0, 0, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::TIMER_SETTIME, &[9, 0, spec, 0]),
        errno(Errno::EINVAL)
    );
    timer_spec(&mut f, spec, 0, 0);
    f.mem
        .write_u64(GuestAddr(spec + 24), 1_000_000_000)
        .unwrap();
    assert_eq!(
        f.ret(nr::TIMER_SETTIME, &[1, 0, spec, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[9, old]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::TIMER_GETOVERRUN, &[9]), errno(Errno::EINVAL));
    // Disarming reports the old setting.
    timer_spec(&mut f, spec, 0, 0);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[1, 0, spec, old]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(old)).unwrap(), 5);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[1, old]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(old + 16)).unwrap(), 0);
}
#[test]
fn sigtimedwait_takes_blocked_process_signals_and_times_out() {
    let mut f = fixture();
    let (set, info, spec, id) = (DATA, DATA + 0x100, DATA + 0x200, DATA + 0x300);
    f.thread.state.signal_mask = 1 << 13; // SIGALRM blocked, as timeout does
    f.mem.write_u64(GuestAddr(set), 1 << 13).unwrap();
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 0, id]), 0);
    timer_spec(&mut f, spec, 0, 1_000_000);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 0, spec, 0]), 0);
    assert_eq!(f.ret(nr::RT_SIGTIMEDWAIT, &[set, info, 0, 8]), 14);
    // Nothing pending: a zero timeout is EAGAIN at once.
    f.mem.write_u64(GuestAddr(spec), 0).unwrap();
    f.mem.write_u64(GuestAddr(spec + 8), 0).unwrap();
    assert_eq!(
        f.ret(nr::RT_SIGTIMEDWAIT, &[set, info, spec, 8]),
        errno(Errno::EAGAIN)
    );
    assert_eq!(
        f.ret(nr::RT_SIGTIMEDWAIT, &[set, info, spec, 4]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(nr::RT_SIGTIMEDWAIT, &[1, info, spec, 8]),
        errno(Errno::EFAULT)
    );
    f.mem.write_u64(GuestAddr(spec + 8), 1_000_000_000).unwrap();
    assert_eq!(
        f.ret(nr::RT_SIGTIMEDWAIT, &[set, info, spec, 8]),
        errno(Errno::EINVAL)
    );
}
#[test]
fn prctl_keeps_death_signal_dumpable_and_no_new_privs() {
    let mut f = fixture();
    assert_eq!(f.ret(157, &[2, DATA]), 0); // PR_GET_PDEATHSIG
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap() as u32, 0);
    assert_eq!(f.ret(157, &[1, 10]), 0);
    assert_eq!(f.ret(157, &[2, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap() as u32, 10);
    assert_eq!(f.ret(157, &[1, 65]), errno(Errno::EINVAL));
    assert_eq!(f.ret(157, &[2, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(157, &[3]), 1); // PR_GET_DUMPABLE
    assert_eq!(f.ret(157, &[4, 0]), 0);
    assert_eq!(f.ret(157, &[3]), 0);
    assert_eq!(f.ret(157, &[4, 2]), errno(Errno::EINVAL));
    assert_eq!(f.ret(157, &[39, 0, 0, 0, 0]), 0); // PR_GET_NO_NEW_PRIVS
    assert_eq!(f.ret(157, &[38, 0, 0, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(157, &[38, 1, 0, 0, 0]), 0);
    assert_eq!(f.ret(157, &[39, 0, 0, 0, 0]), 1);
    assert_eq!(f.ret(157, &[9999]), errno(Errno::EINVAL));
}
#[test]
fn syscall_bad_path() {
    let mut f = fixture();
    assert_eq!(f.ret(2, &[1, 0, 0]), errno(Errno::EFAULT));
}
#[test]
fn syscall_stat_null() {
    let mut f = fixture();
    assert_eq!(f.ret(4, &[0, DATA]), errno(Errno::EFAULT));
}
#[test]
fn syscall_empty_path() {
    let mut f = fixture();
    assert_eq!(f.ret(4, &[DATA, DATA + 100]), errno(Errno::ENOENT));
}
#[test]
fn syscall_stat_buffer() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(5, &[fd, 1]), errno(Errno::EFAULT));
}
#[test]
fn syscall_fcntl_owner() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    let dup = f.ret(72, &[fd, 1030, 10]);
    assert_eq!(dup, 10);
    assert_eq!(f.ret(72, &[dup, 1]), 1);
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(5, &[dup, DATA + 100]), 0);
}
#[test]
fn syscall_flock_cancel() {
    let mut f = fixture();
    let fs = paludarium_vfs::MemFs::new();
    use paludarium_host::HostFs;
    let owner = fs.open(b"/file", 66, 0o600).unwrap();
    owner.flock(2).unwrap();
    f.kernel = f.kernel.with_file_system(Arc::new(fs));
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 2, 0]);
    f.kernel
        .cancellation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(f.ret(73, &[fd, 2]), errno(Errno(4)));
}
