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
    assert_eq!(f.ret(0, &[0, DATA, 1]), 0); // U7 stdin EOF
    assert_eq!(f.ret(u64::MAX, &[]), errno(Errno::ENOSYS));
    assert_eq!(f.ret(1_000_000, &[]), errno(Errno::ENOSYS));
    assert!(SyscallTable::u1().contains(nr::SOCKET));
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
    // U4 native memory CASE1 verifies shared anonymous mappings are valid.
    let shared = f.ret(nr::MMAP, &[0, 4096, 3, 0x21, u64::MAX, 0]);
    assert!(shared < USER_ADDRESS_LIMIT && shared.is_multiple_of(4096));
    assert_eq!(f.mem.read_u64(GuestAddr(shared)).unwrap(), 0);
    assert_eq!(f.ret(nr::MUNMAP, &[shared, 4096]), 0);
    // File-backed forms remain U7.
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
