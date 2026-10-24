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
    // rt_sigpending: only blocked signals are pending, from either queue.
    f.mem.write_u64(GuestAddr(DATA), 1 << 9 | 1 << 16).unwrap();
    assert_eq!(f.ret(nr::RT_SIGPROCMASK, &[0, DATA, 0, 8]), 0);
    let pid = u64::from(f.thread.state.pid);
    assert_eq!(f.ret(62, &[pid, 17]), 0);
    assert_eq!(f.ret(nr::TKILL, &[u64::from(f.thread.tid), 10]), 0);
    assert_eq!(f.ret(nr::RT_SIGPENDING, &[DATA + 8, 8]), 0);
    assert_eq!(
        f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(),
        1 << 9 | 1 << 16
    );
    f.mem.write_u64(GuestAddr(DATA + 8), u64::MAX).unwrap();
    assert_eq!(f.ret(nr::RT_SIGPENDING, &[DATA + 8, 1]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), u64::MAX << 8);
    assert_eq!(
        f.ret(nr::RT_SIGPENDING, &[DATA + 8, 9]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::RT_SIGPENDING, &[0x1000, 8]), errno(Errno::EFAULT));
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
fn copies_between_files_keep_the_file_size_limit() {
    let mut f = fixture();
    let (limit, buf, offset) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
    f.mem.write(GuestAddr(DATA), b"/a\0/b\0").unwrap();
    f.mem.write(GuestAddr(buf), b"0123456789").unwrap();
    let input = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[input, buf, 10]), 10);
    let output = f.ret(2, &[DATA + 3, 66, 0o600]);
    f.mem.write_u64(GuestAddr(limit), 6).unwrap();
    f.mem.write_u64(GuestAddr(limit + 8), u64::MAX).unwrap();
    assert_eq!(f.ret(160, &[1, limit]), 0); // setrlimit(FSIZE, 6)
    f.mem.write_u64(GuestAddr(limit), 1 << 24).unwrap();
    assert_eq!(f.ret(14, &[0, limit, 0, 8]), 0); // block SIGXFSZ
    f.mem.write_u64(GuestAddr(offset), 0).unwrap();
    // copy_file_range stops at the limit, then fails from it.
    assert_eq!(f.ret(326, &[input, offset, output, 0, 10, 0]), 6);
    assert_eq!(f.mem.read_u64(GuestAddr(offset)).unwrap(), 6);
    assert_eq!(
        f.ret(326, &[input, offset, output, 0, 10, 0]),
        errno(Errno(27))
    );
    // Even with nothing left to copy, as generic_write_check_limits.
    f.mem.write_u64(GuestAddr(offset), 10).unwrap();
    assert_eq!(
        f.ret(326, &[input, offset, output, 0, 10, 0]),
        errno(Errno(27))
    );
    assert_eq!(
        f.thread
            .state
            .pending
            .iter()
            .filter(|s| s.number == 25)
            .count(),
        1
    );
    // sendfile into a regular file too.
    assert_eq!(f.ret(77, &[output, 0]), 0);
    assert_eq!(f.ret(8, &[output, 0, 0]), 0);
    f.mem.write_u64(GuestAddr(offset), 0).unwrap();
    assert_eq!(f.ret(40, &[output, input, offset, 10]), 6);
    assert_eq!(f.mem.read_u64(GuestAddr(offset)).unwrap(), 6);
    assert_eq!(f.ret(40, &[output, input, offset, 10]), errno(Errno(27)));
}
#[test]
fn sendfile_sends_a_large_file_in_pieces() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/a\0/dev/null\0").unwrap();
    let input = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(77, &[input, 3 << 20]), 0);
    let null = f.ret(2, &[DATA + 3, 1, 0]);
    // More than one 1 MiB piece, all of it in one call.
    assert_eq!(f.ret(40, &[null, input, 0, 4 << 20]), 3 << 20);
    assert_eq!(f.ret(8, &[input, 0, 1]), 3 << 20);
}
#[test]
fn statx_fills_the_stat_fields() {
    let mut f = fixture();
    let (out, buf) = (DATA + 0x100, DATA + 0x80);
    f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
    f.mem.write(GuestAddr(buf), b"hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o640]);
    assert_eq!(f.ret(1, &[fd, buf, 5]), 5);
    let word = |f: &Fixture, at: u64| f.mem.read_u64(GuestAddr(out + at)).unwrap();
    // A null path with AT_EMPTY_PATH names the descriptor (Linux 6.11).
    assert_eq!(f.ret(332, &[fd, 0, 0x1000, 0x7ff, out]), 0);
    assert_eq!(word(&f, 0) as u32, 0x7ff); // stx_mask
    assert_eq!(word(&f, 0) >> 32, 4096); // stx_blksize
    assert_eq!(word(&f, 16) as u32, 1); // stx_nlink
    assert_eq!((word(&f, 24) >> 32) as u16, 0o100640); // stx_mode
    assert_eq!(word(&f, 40), 5); // stx_size
    assert_eq!(word(&f, 48), 1); // stx_blocks
    // The same file through its path, and the root's device numbers.
    let inode = word(&f, 32);
    assert_eq!(f.ret(332, &[(-100i64) as u64, DATA, 0, 0x7ff, out]), 0);
    assert_eq!(word(&f, 32), inode);
    assert_eq!(word(&f, 136), 1 << 32); // major 0, minor 1
    assert_eq!(f.ret(332, &[fd, 0, 0, 0x7ff, out]), errno(Errno::EFAULT));
    assert_eq!(f.ret(332, &[fd, 0, 0x1000, 0x7ff, 1]), errno(Errno::EFAULT));
}
#[test]
fn close_range_marks_closes_and_unshares_the_table() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    let (a, b) = (f.ret(32, &[fd]), f.ret(32, &[fd]));
    // A CLONE_FILES sibling, which sees every change to a shared table.
    let sibling = f.kernel.files.for_clone(true, false);
    assert_eq!(f.ret(436, &[b, b, 4]), 0); // CLOSE_RANGE_CLOEXEC
    assert_eq!((f.ret(72, &[b, 1]), f.ret(72, &[a, 1])), (1, 0)); // F_GETFD
    // CLOSE_RANGE_UNSHARE: the copy loses `a`, the sibling's table keeps it,
    // and later changes no longer reach the sibling.
    assert_eq!(f.ret(436, &[a, a, 2]), 0);
    assert!(f.kernel.files.descriptor(a).is_err());
    assert!(sibling.descriptor(a).is_ok());
    assert_eq!(f.ret(436, &[fd, u64::from(u32::MAX), 0]), 0);
    assert!(f.kernel.files.descriptor(b).is_err());
    assert!(sibling.descriptor(fd).is_ok() && sibling.descriptor(b).is_ok());
    assert_eq!(f.ret(436, &[1, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(436, &[0, 1, 1]), errno(Errno::EINVAL));
}
#[test]
fn fallocate_grows_punches_and_keeps_the_size_limit() {
    let mut f = fixture();
    let (limit, buf) = (DATA + 0x100, DATA + 0x200);
    f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
    f.mem.write(GuestAddr(buf), b"abcdef").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, buf, 6]), 6);
    let size = |f: &mut Fixture| f.ret(8, &[fd, 0, 2]);
    assert_eq!(f.ret(285, &[fd, 0, 4, 8]), 0);
    assert_eq!(size(&mut f), 12);
    assert_eq!(f.ret(285, &[fd, 3, 1, 2]), 0); // PUNCH_HOLE | KEEP_SIZE
    assert_eq!(f.ret(17, &[fd, buf, 6, 0]), 6);
    assert_eq!(
        f.mem.read_u64(GuestAddr(buf)).unwrap() & 0xffff_ffff_ffff,
        0x6665_6400_0061
    );
    // A mode that tmpfs does not have.
    assert_eq!(f.ret(285, &[fd, 0x10, 0, 1]), errno(Errno(95)));
    // RLIMIT_FSIZE: growing past it raises SIGXFSZ; KEEP_SIZE does not grow.
    f.mem.write_u64(GuestAddr(limit), 16).unwrap();
    f.mem.write_u64(GuestAddr(limit + 8), u64::MAX).unwrap();
    assert_eq!(f.ret(160, &[1, limit]), 0);
    f.mem.write_u64(GuestAddr(limit), 1 << 24).unwrap();
    assert_eq!(f.ret(14, &[0, limit, 0, 8]), 0); // block SIGXFSZ
    assert_eq!(f.ret(285, &[fd, 1, 0, 100]), 0);
    assert!(!f.thread.state.pending.iter().any(|s| s.number == 25));
    assert_eq!(f.ret(285, &[fd, 0, 10, 7]), errno(Errno(27)));
    assert!(f.thread.state.pending.iter().any(|s| s.number == 25));
    assert_eq!(size(&mut f), 12);
}
#[test]
fn memfd_grow_seal_stops_a_write_at_the_last_whole_page() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"grow\0").unwrap();
    let fd = f.ret(319, &[DATA, 2]); // MFD_ALLOW_SEALING
    assert_eq!(f.ret(77, &[fd, 5000]), 0);
    assert_eq!(f.ret(72, &[fd, 1033, 4]), 0); // F_SEAL_GROW
    // From 0, 7000 bytes: the first page fits, the second would grow it.
    assert_eq!(f.ret(1, &[fd, DATA + 0x100, 7000]), 4096);
    // From 4096, past 5000 within the page that would grow it: nothing.
    assert_eq!(f.ret(1, &[fd, DATA + 0x100, 1000]), errno(Errno::EPERM));
    assert_eq!(f.ret(18, &[fd, DATA + 0x100, 900, 4000]), 900); // within
    assert_eq!(f.ret(8, &[fd, 0, 2]), 5000);
    // A memfd is a tmpfs file: KEEP_SIZE past RLIMIT_FSIZE still fails.
    f.mem.write_u64(GuestAddr(DATA + 0x40), 6000).unwrap();
    f.mem.write_u64(GuestAddr(DATA + 0x48), u64::MAX).unwrap();
    assert_eq!(f.ret(160, &[1, DATA + 0x40]), 0);
    f.mem.write_u64(GuestAddr(DATA + 0x40), 1 << 24).unwrap();
    assert_eq!(f.ret(14, &[0, DATA + 0x40, 0, 8]), 0); // block SIGXFSZ
    assert_eq!(f.ret(285, &[fd, 1, 0, 7000]), errno(Errno(27)));
    assert_eq!(f.ret(285, &[fd, 1, 0, 5500]), errno(Errno::EPERM)); // then GROW
    assert_eq!(f.ret(319, &[DATA, 4]), errno(Errno::ENOSYS)); // MFD_HUGETLB
    assert_eq!(f.ret(319, &[1, 0]), errno(Errno::EFAULT));
}
#[test]
fn file_size_limit_is_enforced_as_linux_does() {
    let mut f = fixture();
    let (limit, buf, pair) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
    f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
    f.mem.write_u64(GuestAddr(limit), 10).unwrap();
    f.mem.write_u64(GuestAddr(limit + 8), u64::MAX).unwrap();
    assert_eq!(f.ret(160, &[1, limit]), 0); // setrlimit(FSIZE, 10)
    // Block SIGXFSZ so that it stays pending instead of ending the process.
    f.mem.write_u64(GuestAddr(limit), 1 << 24).unwrap();
    assert_eq!(f.ret(14, &[0, limit, 0, 8]), 0);
    // Takes the pending SIGXFSZ, which a standard signal has at most once.
    let xfsz = |f: &mut Fixture| {
        let before = f.thread.state.pending.len();
        f.thread.state.pending.retain(|s| s.number != 25);
        before - f.thread.state.pending.len()
    };
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, buf, 4]), 4);
    assert_eq!(f.ret(1, &[fd, buf, 10]), 6); // cut at the limit
    assert_eq!(f.ret(1, &[fd, buf, 0]), 0); // empty: no check
    assert_eq!(xfsz(&mut f), 0);
    assert_eq!(f.ret(1, &[fd, buf, 1]), errno(Errno(27)));
    assert_eq!(xfsz(&mut f), 1);
    assert_eq!(f.ret(18, &[fd, buf, 5, 9]), 1); // pwrite
    assert_eq!(xfsz(&mut f), 0);
    assert_eq!(f.ret(18, &[fd, buf, 5, 10]), errno(Errno(27)));
    assert_eq!(xfsz(&mut f), 1);
    // Growing past the limit fails; shrinking and growing to it do not.
    assert_eq!(f.ret(77, &[fd, 11]), errno(Errno(27)));
    assert_eq!(xfsz(&mut f), 1);
    assert_eq!(f.ret(77, &[fd, 4]), 0);
    assert_eq!(f.ret(77, &[fd, 10]), 0);
    assert_eq!(xfsz(&mut f), 0);
    // O_APPEND writes at the end, which is the limit.
    let append = f.ret(2, &[DATA, 0o2001, 0]);
    assert_eq!(f.ret(1, &[append, buf, 1]), errno(Errno(27)));
    assert_eq!(xfsz(&mut f), 1);
    // So does its pwrite, whatever the offset.
    assert_eq!(f.ret(18, &[append, buf, 1, 0]), errno(Errno(27)));
    assert_eq!(xfsz(&mut f), 1);
    // A pipe is no regular file.
    assert_eq!(f.ret(22, &[pair]), 0);
    let writer = f.mem.read_u64(GuestAddr(pair)).unwrap() >> 32;
    assert_eq!(f.ret(1, &[writer, buf, 20]), 20);
    assert_eq!(xfsz(&mut f), 0);
}
#[test]
fn descriptor_limit_is_enforced_as_linux_does() {
    let mut f = fixture();
    let (limit, stat) = (DATA + 0x100, DATA + 0x200);
    f.mem.write(GuestAddr(DATA), b"/a\0/b\0/c\0").unwrap();
    f.mem.write_u64(GuestAddr(limit), 5).unwrap();
    f.mem.write_u64(GuestAddr(limit + 8), 4096).unwrap();
    assert_eq!(f.ret(160, &[7, limit]), 0); // setrlimit(NOFILE, 5)
    assert_eq!(f.ret(2, &[DATA, 66, 0o600]), 3);
    assert_eq!(f.ret(2, &[DATA + 3, 66, 0o600]), 4);
    // No descriptor is free, so open creates nothing.
    assert_eq!(f.ret(2, &[DATA + 6, 66, 0o600]), errno(Errno::EMFILE));
    assert_eq!(f.ret(4, &[DATA + 6, stat]), errno(Errno::ENOENT));
    assert_eq!(f.ret(32, &[3]), errno(Errno::EMFILE)); // dup
    assert_eq!(f.ret(22, &[stat]), errno(Errno::EMFILE)); // pipe
    assert_eq!(f.ret(33, &[3, 5]), errno(Errno::EBADF)); // dup2 past the limit
    assert_eq!(f.ret(72, &[3, 0, 5]), errno(Errno::EINVAL)); // F_DUPFD from it
    assert_eq!(f.ret(72, &[3, 0, 4]), errno(Errno::EMFILE));
    // dup2 reads an unsigned int, and onto itself keeps FD_CLOEXEC.
    assert_eq!(f.ret(33, &[3, 1 << 32 | 4]), 4);
    assert_eq!(f.ret(72, &[3, 2, 1]), 0); // F_SETFD
    assert_eq!(f.ret(33, &[3, 3]), 3);
    assert_eq!(f.ret(72, &[3, 1]), 1); // F_GETFD
    // With one descriptor free, pipe takes neither.
    assert_eq!(f.ret(3, &[4]), 0);
    assert_eq!(f.ret(22, &[stat]), errno(Errno::EMFILE));
    assert_eq!(f.ret(32, &[3]), 4);
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
fn statfs_and_the_generated_mount_table() {
    let mut f = fixture();
    let (path, buf, mounts, empty) = (DATA, DATA + 0x100, DATA + 0x200, DATA + 0x240);
    f.mem.write(GuestAddr(path), b"/tmp\0").unwrap();
    f.mem
        .write(GuestAddr(mounts), b"/proc/self/mountinfo\0")
        .unwrap();
    f.mem.write(GuestAddr(empty), b"/none\0").unwrap();
    assert_eq!(f.ret(137, &[path, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x0102_1994); // TMPFS_MAGIC
    assert_eq!(f.mem.read_u64(GuestAddr(buf + 8)).unwrap(), 4096);
    assert_eq!(f.mem.read_u64(GuestAddr(buf + 64)).unwrap(), 255);
    assert_eq!(f.ret(137, &[empty, buf]), errno(Errno::ENOENT));
    assert_eq!(f.ret(137, &[path, 1]), errno(Errno::EFAULT));
    let fd = f.ret(2, &[path, 0x10000, 0]);
    assert_eq!(f.ret(138, &[fd, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x0102_1994);
    assert_eq!(f.ret(22, &[DATA + 0x300]), 0);
    let pipe = u64::from(f.mem.read_u64(GuestAddr(DATA + 0x300)).unwrap() as u32);
    assert_eq!(f.ret(138, &[pipe, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x5049_5045); // PIPEFS_MAGIC
    assert_eq!(f.ret(138, &[99, buf]), errno(Errno::EBADF));
    // The mount table: readable whole, a regular 0444 file, never writable.
    let table = b"21 1 0:1 / / rw,relatime - tmpfs tmpfs rw\n";
    let fd = f.ret(2, &[mounts, 0, 0]);
    assert_eq!(f.ret(0, &[fd, buf, 0x100]), table.len() as u64);
    let mut read = vec![0; table.len()];
    f.mem.read(GuestAddr(buf), &mut read).unwrap();
    assert_eq!(read, table);
    assert_eq!(f.ret(4, &[mounts, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 1); // st_dev 0:1
    assert_eq!(
        f.mem.read_u64(GuestAddr(buf + 24)).unwrap() as u32,
        0o100_444
    );
    assert_eq!(
        f.mem.read_u64(GuestAddr(buf + 48)).unwrap(),
        table.len() as u64
    );
    // Root may open it for writing; the write itself is EINVAL.
    let fd = f.ret(2, &[mounts, 1, 0]);
    assert_eq!(f.ret(1, &[fd, buf, 1]), errno(Errno::EINVAL));
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
#[test]
fn memory_file_private_copy() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
    let at = f.ret(syscalls::nr::MMAP, &[0, 8192, 3, 2, fd, 0]);
    let mut bytes = [0; 6];
    f.mem.read(GuestAddr(at), &mut bytes).unwrap();
    assert_eq!(&bytes, b"hello\0");
    // The copy leaves the file position, and its writes the file, alone.
    assert_eq!(f.ret(8, &[fd, 0, 1]), 5);
    f.mem.write(GuestAddr(at), b"j").unwrap();
    assert_eq!(f.ret(8, &[fd, 0, 0]), 0);
    assert_eq!(f.ret(0, &[fd, DATA + 0x1000, 1]), 1);
    f.mem
        .read(GuestAddr(DATA + 0x1000), &mut bytes[..1])
        .unwrap();
    assert_eq!(bytes[0], b'h');
    assert_eq!(f.ret(28, &[at, 4096, 8]), errno(Errno::EINVAL));
}
#[test]
fn memory_file_shared_stays_read_only() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    // Nothing would write a writable shared mapping back to the file.
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, fd, 0]),
        errno(Errno::ENODEV)
    );
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 1, fd, 0]);
    assert_eq!(f.ret(10, &[at, 4096, 3]), errno(Errno::EACCES));
    assert_eq!(f.ret(10, &[at, 4096, 5]), 0);
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let fd = f.ret(2, &[DATA, 1, 0]);
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 2, fd, 0]),
        errno(Errno::EACCES)
    );
}
#[test]
fn mremap_flags_and_msync_arguments() {
    let mut f = fixture();
    let (at, einval) = (0x6000_0000, errno(Errno::EINVAL));
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[at, 4096, 3, 0x32, u64::MAX, 0]),
        at
    );
    for flags in [8, 2, 4, 6] {
        assert_eq!(
            f.ret(syscalls::nr::MREMAP, &[at, 4096, 4096, flags, 0]),
            einval
        );
    }
    // DONTUNMAP keeps the size, comparing the rounded lengths.
    assert_eq!(f.ret(syscalls::nr::MREMAP, &[at, 4096, 8192, 5, 0]), einval);
    assert_eq!(
        f.ret(syscalls::nr::MREMAP, &[at, 4096, 4095, 5, at + 0x10_0000]),
        at + 0x10_0000
    );
    assert_eq!(
        f.ret(syscalls::nr::MREMAP, &[at + 0x10_0000, 4096, 4096, 3, at]),
        at
    );
    assert_eq!(f.ret(syscalls::nr::MREMAP, &[at, 4096, 8192, 0, 0]), at);
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[at, 8192, 4]), 0);
    assert_eq!(
        f.ret(syscalls::nr::MSYNC, &[at, 3 * 4096, 4]),
        errno(Errno::ENOMEM)
    );
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[at, 4096, 5]), einval);
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[at, 4096, 8]), einval);
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[at + 1, 4096, 4]), einval);
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[at, u64::MAX, 1]), 0);
    assert_eq!(
        f.ret(syscalls::nr::MSYNC, &[!4095, 8192, 1]),
        errno(Errno::ENOMEM)
    );
}
#[test]
fn clone3_arguments_follow_linux() {
    let f = fixture();
    let put = |words: &[u64]| {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        f.mem.write(GuestAddr(DATA), &bytes).unwrap();
    };
    let args = |size| crate::processes::clone3_args(&f.mem, DATA, size);
    // flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls.
    put(&[
        0x10_0000, 0, 0x200, 0x300, 17, 0x1000, 0x800, 0x400, 0, 0, 0,
    ]);
    assert_eq!(args(64), Ok([0x10_0011, 0x1800, 0x300, 0x200, 0x400, 0]));
    assert_eq!(args(63), Err(Errno::EINVAL));
    assert_eq!(args(4097), Err(Errno(7)));
    assert_eq!(args(96), Ok([0x10_0011, 0x1800, 0x300, 0x200, 0x400, 0]));
    f.mem.write(GuestAddr(DATA + 90), &[1]).unwrap();
    assert_eq!(args(96), Err(Errno(7)));
    for words in [
        [0, 0, 0, 0, 0x100, 0, 0, 0],          // exit_signal above CSIGNAL
        [0x40_0000, 0, 0, 0, 17, 0, 0, 0],     // CLONE_DETACHED
        [0x11, 0, 0, 0, 0, 0, 0, 0],           // a CSIGNAL bit in the flags
        [0x1_0000_0800, 0, 0, 0, 0, 0, 0, 0],  // SIGHAND with CLEAR_SIGHAND
        [0x1_0900, 0, 0, 0, 17, 0, 0, 0],      // THREAD with an exit signal
        [0, 0, 0, 0, 17, 0, 0x800, 0],         // a size without a stack
        [0, 0, 0, 0, 17, 0x1000, 0, 0],        // a stack without a size
        [0, 0, 0, 0, 65, 0, 0, 0],             // not a signal
        [0x2_0000_0000, 0, 0, 0, 17, 0, 0, 0], // CLONE_INTO_CGROUP
    ] {
        put(&[&words[..], &[0, 0, 0]].concat());
        assert_eq!(args(88), Err(Errno::EINVAL), "{words:x?}");
    }
    // set_tid and its size come together, and are not supported.
    put(&[0, 0, 0, 0, 17, 0, 0, 0, 0, 1, 0]);
    assert_eq!(args(88), Err(Errno::EINVAL));
    put(&[0, 0, 0, 0, 17, 0, 0, 0, DATA, 1, 0]);
    assert_eq!(args(88), Err(Errno::EINVAL));
    assert_eq!(
        crate::processes::clone3_args(&f.mem, 0x10, 64),
        Err(Errno::EFAULT)
    );
}
#[test]
fn thread_name_from_path() {
    let mut state = ThreadState::default();
    state.name_after(b"/usr/bin/a-very-long-program-name");
    assert_eq!(&state.name, b"a-very-long-pro\0");
    state.name_after(b"plain");
    assert_eq!(&state.name[..6], b"plain\0");
}
#[test]
fn getrusage_checks_who_and_the_pointer() {
    let mut f = fixture();
    for who in [0, u64::MAX, 1] {
        assert_eq!(f.ret(98, &[who, DATA]), 0);
    }
    assert_eq!(f.ret(98, &[2, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(98, &[0, 0x10]), errno(Errno::EFAULT));
}
#[test]
fn poll_waits_for_its_timeout_and_dup2_replaces_stdin() {
    let mut f = fixture();
    assert_eq!(f.ret(22, &[DATA + 0x100]), 0);
    let mut fds = [0u8; 8];
    f.mem.read(GuestAddr(DATA + 0x100), &mut fds).unwrap();
    let (reader, writer) = (
        u64::from(u32::from_le_bytes(fds[..4].try_into().unwrap())),
        u64::from(u32::from_le_bytes(fds[4..].try_into().unwrap())),
    );
    let set = |f: &mut Fixture, fd: u64| {
        f.mem
            .write(GuestAddr(DATA), &(fd as i32).to_le_bytes())
            .unwrap();
        f.mem.write(GuestAddr(DATA + 4), &[1, 0, 0, 0]).unwrap();
    };
    let revents = |f: &Fixture| {
        let mut b = [0u8; 2];
        f.mem.read(GuestAddr(DATA + 6), &mut b).unwrap();
        u16::from_le_bytes(b)
    };
    // An empty pipe: the 50 ms pass (on the recording host's clock) with nothing ready.
    set(&mut f, reader);
    assert_eq!(f.ret(nr::POLL, &[DATA, 1, 50]), 0);
    assert_eq!(revents(&f), 0);
    f.mem.write(GuestAddr(DATA + 0x200), b"x").unwrap();
    assert_eq!(f.ret(1, &[writer, DATA + 0x200, 1]), 1);
    assert_eq!(f.ret(nr::POLL, &[DATA, 1, u64::MAX]), 1);
    assert_eq!(revents(&f), 1);
    assert_eq!(f.ret(0, &[reader, DATA + 0x200, 1]), 1);
    // Once a pipe replaces stdin, fd 0 is that pipe, not the host's stream.
    assert_eq!(f.ret(33, &[reader, 0]), 0);
    set(&mut f, 0);
    assert_eq!(f.ret(nr::POLL, &[DATA, 1, 0]), 0);
}
#[test]
fn cpu_clocks_count_the_threads_time() {
    let mut f = fixture();
    let read = |f: &mut Fixture, clock: u64| {
        assert_eq!(f.ret(nr::CLOCK_GETTIME, &[clock, DATA]), 0);
        let [s, ns] = [
            f.mem.read_u64(GuestAddr(DATA)).unwrap(),
            f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(),
        ];
        s * 1_000_000_000 + ns
    };
    let start = read(&mut f, 3);
    // The recording host measures no CPU time, so wall time counts instead.
    f.mem.write_u64(GuestAddr(DATA + 0x100), 2).unwrap();
    f.mem.write_u64(GuestAddr(DATA + 0x108), 0).unwrap();
    assert_eq!(f.ret(nr::NANOSLEEP, &[DATA + 0x100, 0]), 0);
    let thread = read(&mut f, 3);
    assert!(thread >= start + 2_000_000_000, "{start} {thread}");
    assert!(read(&mut f, 2) >= thread);
    for clock in [0, 1, 4, 5, 6, 7, 8, 9, 11] {
        read(&mut f, clock);
    }
    assert_eq!(f.ret(nr::CLOCK_GETTIME, &[10, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(229, &[2, DATA]), 0);
    assert_eq!(
        (
            f.mem.read_u64(GuestAddr(DATA)).unwrap(),
            f.mem.read_u64(GuestAddr(DATA + 8)).unwrap()
        ),
        (0, 1)
    );
    assert_eq!(f.ret(229, &[6, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 4_000_000);
    assert_eq!(f.ret(229, &[3, 0]), 0);
    assert_eq!(f.ret(229, &[12, DATA]), errno(Errno::EINVAL));
    // getrusage and times report the same time; no child has been waited for.
    assert_eq!(f.ret(98, &[0, DATA]), 0);
    assert!(f.mem.read_u64(GuestAddr(DATA)).unwrap() >= 2);
    assert_eq!(f.ret(98, &[u64::MAX, DATA]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 0);
    assert!(f.ret(100, &[DATA]) as i64 >= 200);
    assert!(f.mem.read_u64(GuestAddr(DATA)).unwrap() >= 200);
    assert_eq!(f.ret(100, &[0x10]), errno(Errno::EFAULT));
}

#[test]
fn timerfd_counts_expirations() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_000_000_000);
    assert_eq!(f.ret(283, &[2, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(283, &[1, 1]), errno(Errno::EINVAL));
    assert_eq!(f.ret(283, &[8, 0]), errno(Errno::EPERM));
    let fd = f.ret(283, &[1, 0x800]);
    assert_eq!(f.ret(0, &[fd, DATA, 8]), errno(Errno::EAGAIN));
    // 5 ms, then every 2 ms: by 10 ms it has expired at 5, 7 and 9 ms.
    f.mem
        .write(
            GuestAddr(DATA),
            &[0, 2_000_000, 0, 5_000_000].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(f.ret(286, &[fd, 0, DATA, 0]), 0);
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_010_000_000);
    assert_eq!(f.ret(287, &[fd, DATA + 64]), 0);
    assert_eq!(
        f.mem.read_u64(GuestAddr(DATA + 64 + 24)).unwrap(),
        1_000_000
    );
    assert_eq!(f.ret(0, &[fd, DATA + 128, 8]), 8);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 128)).unwrap(), 3);
    assert_eq!(f.ret(0, &[fd, DATA + 128, 8]), errno(Errno::EAGAIN));
    assert_eq!(f.ret(0, &[fd, DATA + 128, 7]), errno(Errno::EINVAL));
    assert_eq!(f.ret(1, &[fd, DATA + 128, 8]), errno(Errno::EINVAL));
    // Rearming clears the count and reports the old setting.
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_020_000_000);
    f.mem
        .write(GuestAddr(DATA), &[0u64; 4].map(u64::to_le_bytes).concat())
        .unwrap();
    assert_eq!(f.ret(286, &[fd, 0, DATA, DATA + 64]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64 + 8)).unwrap(), 2_000_000);
    // A zero value disarms but keeps the interval, as Linux reports it.
    f.mem.write_u64(GuestAddr(DATA + 8), 3_000_000).unwrap();
    assert_eq!(f.ret(286, &[fd, 0, DATA, 0]), 0);
    assert_eq!(f.ret(287, &[fd, DATA + 64]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64 + 8)).unwrap(), 3_000_000);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64 + 24)).unwrap(), 0);
    assert_eq!(f.ret(0, &[fd, DATA + 128, 8]), errno(Errno::EAGAIN));
    // Linux's order: the value, then flags and times, then the descriptor.
    assert_eq!(f.ret(286, &[fd, 0, 0, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(286, &[fd, 4, DATA, 0]), errno(Errno::EINVAL));
    // A huge time saturates to KTIME_MAX instead of failing, as on Linux.
    f.mem
        .write(
            GuestAddr(DATA),
            &[i64::MAX as u64, 0, i64::MAX as u64, 0]
                .map(u64::to_le_bytes)
                .concat(),
        )
        .unwrap();
    assert_eq!(f.ret(286, &[fd, 0, DATA, 0]), 0);
    assert_eq!(f.ret(287, &[fd, DATA + 64]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64)).unwrap(), 9_223_372_036);
    f.mem
        .write(GuestAddr(DATA), &[0u64; 4].map(u64::to_le_bytes).concat())
        .unwrap();
    assert_eq!(f.ret(286, &[99, 0, DATA, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(287, &[99, DATA]), errno(Errno::EBADF));
    assert_eq!(f.ret(286, &[fd, 0, DATA, 0x1000]), errno(Errno::EFAULT));
}

#[test]
fn select_family_timeouts_and_errors() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_000_000_000);
    // An empty pipe: select times out and writes back no time left.
    assert_eq!(f.ret(22, &[DATA]), 0);
    let read_end = f.mem.read_u64(GuestAddr(DATA)).unwrap() & 0xffff_ffff;
    f.mem
        .write_u64(GuestAddr(DATA + 64), 1 << read_end)
        .unwrap();
    f.mem
        .write(
            GuestAddr(DATA + 128),
            &[0u64, 30_000].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(f.ret(23, &[read_end + 1, DATA + 64, 0, 0, DATA + 128]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 64)).unwrap(), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 136)).unwrap(), 0);
    // A zero timeout is not written back; a closed descriptor is EBADF.
    f.mem.write_u64(GuestAddr(DATA + 64), 1 << 40).unwrap();
    f.mem
        .write(
            GuestAddr(DATA + 128),
            &[0u64, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(
        f.ret(23, &[41, DATA + 64, 0, 0, DATA + 128]),
        errno(Errno::EBADF)
    );
    assert_eq!(
        f.ret(23, &[u64::MAX, 0, 0, 0, DATA + 128]),
        errno(Errno::EINVAL)
    );
    // pselect6 reads its {ss, len} pair first: EFAULT before a bad timespec.
    f.mem
        .write(
            GuestAddr(DATA + 192),
            &[0u64, 1_000_000_000].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(
        f.ret(270, &[0, 0, 0, 0, DATA + 192, 0x10]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        f.ret(270, &[0, 0, 0, 0, DATA + 192, 0]),
        errno(Errno::EINVAL)
    );
    // ppoll: the timespec before the mask size, the mask size before nfds.
    f.mem
        .write(
            GuestAddr(DATA + 256),
            &[1u64, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(
        f.ret(271, &[0, 5000, DATA + 192, DATA, 8]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(271, &[0, 5000, DATA + 256, DATA, 7]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(271, &[0, 5000, DATA + 256, 0, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 256)).unwrap(), 1);
}

#[test]
fn select_timeval_carries_microseconds() {
    let mut f = fixture();
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_000_000_000);
    // A second of microseconds: the wait ends on the carried deadline.
    f.mem
        .write(
            GuestAddr(DATA),
            &[0u64, 1_000_000].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    assert_eq!(f.ret(23, &[0, 0, 0, 0, DATA]), 0);
    assert_eq!(
        f.host.clock(paludarium_host::ClockId::Monotonic).unwrap(),
        2_000_000_000
    );
    for bad in [[0u64, u64::MAX], [u64::MAX, 0]] {
        f.mem
            .write(GuestAddr(DATA), &bad.map(u64::to_le_bytes).concat())
            .unwrap();
        assert_eq!(f.ret(23, &[0, 0, 0, 0, DATA]), errno(Errno::EINVAL));
    }
    // A huge timespec saturates instead of failing: with a readable pipe,
    // ppoll returns at once.
    assert_eq!(f.ret(22, &[DATA + 192]), 0);
    let fds = f.mem.read_u64(GuestAddr(DATA + 192)).unwrap();
    assert_eq!(f.ret(1, &[fds >> 32, DATA + 200, 1]), 1);
    f.mem
        .write(
            GuestAddr(DATA + 64),
            &[i64::MAX as u64, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
    f.mem
        .write(
            GuestAddr(DATA + 128),
            &(fds & 0xffff_ffff | 1 << 32).to_le_bytes(),
        )
        .unwrap();
    assert_eq!(f.ret(271, &[DATA + 128, 1, DATA + 64, 0, 0]), 1);
}

#[test]
fn ppoll_stop_restarts_unless_the_timeout_is_read_only() {
    for read_only in [false, true] {
        let mut f = fixture();
        let at = if read_only {
            f.mem
                .map(
                    Some(GuestAddr(0x30_0000)),
                    0x1000,
                    Prot::READ_WRITE,
                    MappingKind::Anonymous,
                )
                .unwrap();
            f.mem
                .write(
                    GuestAddr(0x30_0000),
                    &[10u64, 0].map(u64::to_le_bytes).concat(),
                )
                .unwrap();
            f.mem
                .protect(GuestAddr(0x30_0000), 0x1000, Prot::READ)
                .unwrap();
            0x30_0000
        } else {
            f.mem
                .write(GuestAddr(DATA), &[10u64, 0].map(u64::to_le_bytes).concat())
                .unwrap();
            DATA
        };
        f.kernel.queue_signal(&mut f.thread, 19).unwrap();
        f.thread.cpu.rip = GuestAddr(0x1002);
        // Stopped in ppoll: with the time left written back it runs again;
        // with a read-only timeout it gives EINTR, as Linux does.
        assert_eq!(f.call(271, &[0, 0, at, 0, 0]), Next::Stopped);
        if read_only {
            assert_eq!(f.thread.cpu.gpr[reg::RAX], errno(Errno(4)));
        } else {
            assert_eq!(f.thread.cpu.gpr[reg::RAX], 271);
            assert_eq!(f.thread.cpu.rip, GuestAddr(0x1000));
        }
    }
}
