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
fn getcpu_reports_the_lowest_allowed_cpu_and_node_0() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), &[0xff; 8]).unwrap();
    assert_eq!(f.ret(nr::GETCPU, &[DATA, DATA + 4, 0]), 0);
    let mut bytes = [0u8; 8];
    f.mem.read(GuestAddr(DATA), &mut bytes).unwrap();
    assert_eq!(bytes, [0; 8]);
    assert_eq!(f.ret(nr::GETCPU, &[0, 0, 0]), 0);
    assert_eq!(f.ret(nr::GETCPU, &[1, 0, 0]), errno(Errno::EFAULT));
    // The node is written even when the CPU cannot be.
    f.mem.write(GuestAddr(DATA), &[0xff; 4]).unwrap();
    assert_eq!(f.ret(nr::GETCPU, &[1, DATA, 0]), errno(Errno::EFAULT));
    f.mem.read(GuestAddr(DATA), &mut bytes[..4]).unwrap();
    assert_eq!(bytes[..4], [0; 4]);
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    if cpus > 1 {
        // Pinned to CPU 1, the thread is on CPU 1.
        f.mem.write(GuestAddr(DATA), &2u64.to_le_bytes()).unwrap();
        assert_eq!(f.ret(nr::SCHED_SETAFFINITY, &[0, 8, DATA]), 0);
        assert_eq!(f.ret(nr::GETCPU, &[DATA, 0, 0]), 0);
        f.mem.read(GuestAddr(DATA), &mut bytes[..4]).unwrap();
        assert_eq!(bytes[..4], 1u32.to_le_bytes());
    }
}

#[test]
fn personality_is_kept_and_changes_uname_and_mappings() {
    let mut f = fixture();
    assert_eq!(f.ret(nr::PERSONALITY, &[0xffff_ffff]), 0);
    // Any value is stored; the upper half of the register is not read.
    assert_eq!(f.ret(nr::PERSONALITY, &[0xffff_ffff_8000_0001]), 0);
    assert_eq!(f.ret(nr::PERSONALITY, &[u64::MAX]), 0x8000_0001);
    let field = |f: &mut Fixture, index: u64| {
        let mut bytes = [0u8; 65];
        f.mem
            .read(GuestAddr(DATA + 65 * index), &mut bytes)
            .unwrap();
        bytes.split(|&b| b == 0).next().unwrap().to_vec()
    };
    // PER_LINUX32 | UNAME26.
    assert_eq!(f.ret(nr::PERSONALITY, &[0x2_0008]), 0x8000_0001);
    assert_eq!(f.ret(nr::UNAME, &[DATA]), 0);
    assert_eq!(field(&mut f, 2), b"2.6.72-paludarium");
    assert_eq!(field(&mut f, 4), b"i686");
    // READ_IMPLIES_EXEC makes readable mappings executable.
    assert_eq!(f.ret(nr::PERSONALITY, &[0x40_0000]), 0x2_0008);
    assert_eq!(f.ret(nr::UNAME, &[DATA]), 0);
    assert_eq!(field(&mut f, 4), b"x86_64");
    let exec_of = |f: &mut Fixture, at: u64| {
        f.mem
            .mappings()
            .find(|m| m.start.0 <= at && at < m.start.0 + m.length)
            .unwrap()
            .prot
            .contains(Prot::EXEC)
    };
    let at = f.ret(nr::MMAP, &[0, 4096, 1, 0x22, u64::MAX, 0]);
    assert!(exec_of(&mut f, at));
    assert_eq!(f.ret(nr::MPROTECT, &[at, 4096, 0]), 0);
    assert!(!exec_of(&mut f, at));
    assert_eq!(f.ret(nr::MPROTECT, &[at, 4096, 3]), 0);
    assert!(exec_of(&mut f, at));
    assert_eq!(f.ret(nr::PERSONALITY, &[0]), 0x40_0000);
    assert_eq!(f.ret(nr::MPROTECT, &[at, 4096, 1]), 0);
    assert!(!exec_of(&mut f, at));
}

#[test]
fn sched_queries_report_the_normal_policy() {
    let mut f = fixture();
    let (einval, esrch) = (errno(Errno::EINVAL), errno(Errno(3)));
    for pid in [0, 1] {
        assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[pid]), 0);
        f.mem.write(GuestAddr(DATA), &[0xff; 4]).unwrap();
        assert_eq!(f.ret(nr::SCHED_GETPARAM, &[pid, DATA]), 0);
        assert_eq!(f.mem.read_value(GuestAddr(DATA), 4).unwrap(), 0);
    }
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[99]), esrch);
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[u64::MAX]), einval);
    // A NULL parameter is EINVAL before the thread is looked for.
    assert_eq!(f.ret(nr::SCHED_GETPARAM, &[99, 0]), einval);
    assert_eq!(f.ret(nr::SCHED_GETPARAM, &[99, DATA]), esrch);
    assert_eq!(f.ret(nr::SCHED_GETPARAM, &[0, 1]), errno(Errno::EFAULT));
    for (policy, max, min) in [
        (0, 0, 0),
        (1, 99, 1),
        (2, 99, 1),
        (3, 0, 0),
        (5, 0, 0),
        (6, 0, 0),
        (7, 0, 0),
    ] {
        assert_eq!(
            f.ret(nr::SCHED_GET_PRIORITY_MAX, &[policy]),
            max,
            "{policy}"
        );
        assert_eq!(
            f.ret(nr::SCHED_GET_PRIORITY_MIN, &[policy]),
            min,
            "{policy}"
        );
    }
    for policy in [4, 8, u64::MAX, 0x1_0000_0000 - 1] {
        assert_eq!(f.ret(nr::SCHED_GET_PRIORITY_MAX, &[policy]), einval);
        assert_eq!(f.ret(nr::SCHED_GET_PRIORITY_MIN, &[policy]), einval);
    }
    // The upper half is not read: 0x1_0000_0001 is SCHED_FIFO.
    assert_eq!(f.ret(nr::SCHED_GET_PRIORITY_MAX, &[0x1_0000_0001]), 99);
    // The host's slice in whole ticks, or where it does not tell (macOS)
    // Linux's default at 1000 Hz: 0.75 ms times 1 + log2 of the CPUs.
    assert_eq!(f.ret(nr::SCHED_RR_GET_INTERVAL, &[0, DATA]), 0);
    let host = crate::syscalls::scheduler_slice(&*f.host);
    if paludarium_host::Host::scheduler_slice(&*f.host).is_none() {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        assert_eq!(host.slice, 750_000 * (1 + cpus.min(8).ilog2() as u64));
        assert_eq!(host.tick, 1_000_000);
    }
    let slice = host.slice / host.tick * host.tick;
    assert_eq!(f.mem.read_value(GuestAddr(DATA), 8).unwrap(), 0);
    assert_eq!(f.mem.read_value(GuestAddr(DATA + 8), 8).unwrap(), slice);
    assert_eq!(f.ret(nr::SCHED_RR_GET_INTERVAL, &[99, DATA]), esrch);
    assert_eq!(f.ret(nr::SCHED_RR_GET_INTERVAL, &[u64::MAX, DATA]), einval);
    assert_eq!(
        f.ret(nr::SCHED_RR_GET_INTERVAL, &[0, 1]),
        errno(Errno::EFAULT)
    );
}

/// The attributes `sched_getattr` reports: policy, flags, nice, priority,
/// runtime, deadline, period and the clamps.
fn sched_attributes(f: &mut Fixture, pid: u64) -> (u32, u64, i32, u32, [u64; 3], [u32; 2]) {
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[pid, DATA, 56, 0]), 0);
    let mut b = [0u8; 56];
    f.mem.read(GuestAddr(DATA), &mut b).unwrap();
    let w = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let d = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    assert_eq!(w(0), 56);
    (
        w(4),
        d(8),
        w(16) as i32,
        w(20),
        [d(24), d(32), d(40)],
        [w(48), w(52)],
    )
}

/// Writes a `struct sched_attr` at `DATA + 0x100`.
fn write_attr(
    f: &mut Fixture,
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    times: [u64; 3],
) {
    let mut b = Vec::new();
    b.extend_from_slice(&size.to_le_bytes());
    b.extend_from_slice(&policy.to_le_bytes());
    b.extend_from_slice(&flags.to_le_bytes());
    b.extend_from_slice(&nice.to_le_bytes());
    b.extend_from_slice(&priority.to_le_bytes());
    for t in times {
        b.extend_from_slice(&t.to_le_bytes());
    }
    b.extend_from_slice(&[0; 8]);
    f.mem.write(GuestAddr(DATA + 0x100), &b).unwrap();
}

#[test]
fn scheduling_policies_are_kept_and_reported() {
    let mut f = fixture();
    let (einval, esrch, efault) = (errno(Errno::EINVAL), errno(Errno(3)), errno(Errno::EFAULT));
    let host = crate::syscalls::scheduler_slice(&*f.host);
    let param = |f: &mut Fixture, value: u32| {
        f.mem
            .write(GuestAddr(DATA + 0x80), &value.to_le_bytes())
            .unwrap()
    };
    let interval = |f: &mut Fixture| {
        assert_eq!(f.ret(nr::SCHED_RR_GET_INTERVAL, &[0, DATA + 0x40]), 0);
        f.mem.read_value(GuestAddr(DATA + 0x48), 8).unwrap()
            + f.mem.read_value(GuestAddr(DATA + 0x40), 8).unwrap() * 1_000_000_000
    };
    // A buffer larger than the structure gets zeros after it, as Linux
    // 6.13's copy_struct_to_user.
    f.mem.write(GuestAddr(DATA), &[0xee; 64]).unwrap();
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[0, DATA, 64, 0]), 0);
    let mut tail = [0xffu8; 8];
    f.mem.read(GuestAddr(DATA + 56), &mut tail).unwrap();
    assert_eq!(tail, [0; 8]);
    assert_eq!(f.mem.read_value(GuestAddr(DATA), 4).unwrap(), 56);
    // The defaults: SCHED_OTHER, nice 0, the host's slice and no clamps.
    assert_eq!(
        sched_attributes(&mut f, 0),
        (0, 0, 0, 0, [host.slice, 0, 0], [0, 1024])
    );
    // SCHED_FIFO 10: a real-time task's minimum clamp is 1024.
    param(&mut f, 10);
    assert_eq!(f.ret(144, &[0, 1, DATA + 0x80]), 0);
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[0]), 1);
    assert_eq!(f.ret(nr::SCHED_GETPARAM, &[0, DATA]), 0);
    assert_eq!(f.mem.read_value(GuestAddr(DATA), 4).unwrap(), 10);
    assert_eq!(interval(&mut f), 0);
    assert_eq!(
        sched_attributes(&mut f, 0),
        (1, 0, 0, 10, [0, 0, 0], [1024, 1024])
    );
    // SCHED_RR with SCHED_RESET_ON_FORK, through sched_setparam.
    assert_eq!(f.ret(144, &[0, 2 | 0x4000_0000, DATA + 0x80]), 0);
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[0]), 0x4000_0002);
    assert_eq!(interval(&mut f), 100_000_000);
    param(&mut f, 20);
    assert_eq!(f.ret(142, &[0, DATA + 0x80]), 0);
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[0]), 0x4000_0002);
    assert_eq!(sched_attributes(&mut f, 0).3, 20);
    param(&mut f, 0);
    assert_eq!(f.ret(142, &[0, DATA + 0x80]), einval);
    // The checks, in order.
    assert_eq!(f.ret(144, &[0, u64::from(u32::MAX), DATA + 0x80]), einval);
    assert_eq!(f.ret(144, &[0, 4, DATA + 0x80]), einval);
    assert_eq!(f.ret(144, &[0, 0, 0]), einval);
    assert_eq!(f.ret(144, &[u64::MAX, 0, DATA + 0x80]), einval);
    assert_eq!(f.ret(144, &[0, 0, 1]), efault);
    assert_eq!(f.ret(144, &[99, 0, DATA + 0x80]), esrch);
    param(&mut f, 100);
    assert_eq!(f.ret(144, &[0, 1, DATA + 0x80]), einval);
    param(&mut f, 1);
    assert_eq!(f.ret(144, &[0, 0, DATA + 0x80]), einval);
    param(&mut f, 0);
    assert_eq!(f.ret(144, &[0, 3, DATA + 0x80]), 0);
    assert_eq!(f.ret(nr::SCHED_GETSCHEDULER, &[0]), 3);
    assert_eq!(sched_attributes(&mut f, 0).5, [0, 1024]);
    // sched_setattr: a normal policy's nice value and slice.
    write_attr(&mut f, 48, 0, 0, 5, 0, [3_000_000, 0, 0]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(f.ret(140, &[0, 0]), 15);
    assert_eq!(
        sched_attributes(&mut f, 0),
        (0, 0, 5, 0, [3_000_000, 0, 0], [0, 1024])
    );
    assert_eq!(interval(&mut f), 3_000_000 / host.tick * host.tick);
    write_attr(&mut f, 48, 0, 0, 5, 0, [1, 0, 0]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(sched_attributes(&mut f, 0).4[0], 100_000);
    // SCHED_DEADLINE: 10 ms every 100 ms, by 30 ms; no forks.
    write_attr(
        &mut f,
        48,
        6,
        0,
        0,
        0,
        [10_000_000, 30_000_000, 100_000_000],
    );
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(
        sched_attributes(&mut f, 0),
        (
            6,
            0,
            0,
            0,
            [10_000_000, 30_000_000, 100_000_000],
            // A deadline task's minimum is not raised as a real-time one's.
            [0, 1024]
        )
    );
    assert_eq!(interval(&mut f), 0);
    assert_eq!(f.ret(57, &[]), errno(Errno(11)));
    write_attr(
        &mut f,
        48,
        6,
        0,
        0,
        0,
        [40_000_000, 30_000_000, 100_000_000],
    );
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), einval);
    write_attr(&mut f, 48, 6, 0, 0, 0, [10_000_000, 30_000_000, 50_000]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), einval);
    // Sizes: 0 is 48; below 48, or nonzero bytes past 56, is E2BIG with 56.
    write_attr(&mut f, 0, 0, 0, 0, 0, [0; 3]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    write_attr(&mut f, 40, 0, 0, 0, 0, [0; 3]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), errno(Errno(7)));
    assert_eq!(f.mem.read_value(GuestAddr(DATA + 0x100), 4).unwrap(), 56);
    write_attr(&mut f, 64, 0, 0, 0, 0, [0; 3]);
    f.mem.write(GuestAddr(DATA + 0x100 + 60), &[1]).unwrap();
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), errno(Errno(7)));
    f.mem.write(GuestAddr(DATA + 0x100 + 60), &[0]).unwrap();
    write_attr(&mut f, 64, 0, 0, 0, 0, [0; 3]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(f.ret(314, &[0, 0, 0]), einval);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 1]), einval);
    // The clamps need all 56 bytes; -1 is the default again.
    write_attr(&mut f, 48, 0, 0x60, 0, 0, [0; 3]);
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), einval);
    write_attr(&mut f, 56, 0, 0x60, 0, 0, [0; 3]);
    f.mem
        .write(GuestAddr(DATA + 0x100 + 48), &[100, 0, 0, 0, 200, 0, 0, 0])
        .unwrap();
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(sched_attributes(&mut f, 0).5, [100, 200]);
    f.mem
        .write(GuestAddr(DATA + 0x100 + 48), &[0xff; 4])
        .unwrap();
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), 0);
    assert_eq!(sched_attributes(&mut f, 0).5, [0, 200]);
    f.mem
        .write(GuestAddr(DATA + 0x100 + 48), &[0, 1, 0, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(f.ret(314, &[0, DATA + 0x100, 0]), einval);
    // sched_getattr's checks, and a size cut to 48.
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[0, 0, 56, 0]), einval);
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[0, DATA, 47, 0]), einval);
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[0, DATA, 56, 1]), einval);
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[99, DATA, 56, 0]), esrch);
    assert_eq!(f.ret(nr::SCHED_GETATTR, &[0, DATA, 48, 0]), 0);
    assert_eq!(f.mem.read_value(GuestAddr(DATA), 4).unwrap(), 48);
    // Without CAP_SYS_NICE, a real-time policy needs RLIMIT_RTPRIO.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    param(&mut f, 1);
    assert_eq!(f.ret(144, &[0, 1, DATA + 0x80]), errno(Errno::EPERM));
}

#[test]
fn ioprio_set_is_kept_and_reported() {
    let mut f = fixture();
    let (einval, eperm) = (errno(Errno::EINVAL), errno(Errno::EPERM));
    assert_eq!(f.ret(252, &[1, 0]), 0);
    // Best-effort level 3, with a hint.
    assert_eq!(f.ret(251, &[1, 0, 2 << 13 | 1 << 3 | 3]), 0);
    assert_eq!(f.ret(252, &[1, 0]), 2 << 13 | 1 << 3 | 3);
    // The class none is reported as 0, whatever the nice value.
    assert_eq!(f.ret(251, &[1, 0, 0]), 0);
    assert_eq!(f.ret(252, &[1, 0]), 0);
    assert_eq!(f.ret(141, &[0, 0, 10]), 0);
    assert_eq!(f.ret(252, &[1, 0]), 0);
    // Real-time and idle classes.
    assert_eq!(f.ret(251, &[1, 0, 1 << 13 | 7]), 0);
    assert_eq!(f.ret(252, &[2, 0]), 1 << 13 | 7);
    assert_eq!(f.ret(251, &[3, 0, 3 << 13]), 0);
    assert_eq!(f.ret(252, &[3, 0]), 3 << 13);
    for bad in [4 << 13, 7 << 13, 1, u64::from(u32::MAX)] {
        assert_eq!(f.ret(251, &[1, 0, bad]), einval, "{bad:#x}");
    }
    assert_eq!(f.ret(251, &[0, 0, 0]), einval);
    assert_eq!(f.ret(251, &[1, 99, 0]), errno(Errno(3)));
    // Real-time needs CAP_SYS_NICE (or CAP_SYS_ADMIN), checked first.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    assert_eq!(f.ret(251, &[1, 99, 1 << 13]), eperm);
    assert_eq!(f.ret(251, &[1, 0, 2 << 13]), 0);
}

#[test]
fn membarrier_needs_registrations_and_reports_them() {
    let mut f = fixture();
    let (einval, eperm) = (errno(Errno::EINVAL), errno(Errno::EPERM));
    let call = |f: &mut Fixture, cmd: u64, flags: u64| f.ret(nr::MEMBARRIER, &[cmd, flags, 0]);
    assert_eq!(call(&mut f, 0, 0), 0x3ff);
    assert_eq!(call(&mut f, 0, 1), einval);
    assert_eq!(call(&mut f, 3, 0), einval);
    assert_eq!(call(&mut f, 1024, 0), einval);
    assert_eq!(call(&mut f, 1, 0), 0);
    assert_eq!(call(&mut f, 2, 0), 0);
    // The private commands need their registration.
    for cmd in [8, 32, 128] {
        assert_eq!(call(&mut f, cmd, 0), eperm, "{cmd}");
    }
    assert_eq!(call(&mut f, 512, 0), 0);
    assert_eq!(call(&mut f, 64, 0), 0);
    // SYNC_CORE's registration marks the space private too (Linux's
    // set_state), which GET_REGISTRATIONS reports, but is not PRIVATE's.
    assert_eq!(call(&mut f, 512, 0), 64 | 16);
    assert_eq!(call(&mut f, 32, 0), 0);
    assert_eq!(call(&mut f, 8, 0), eperm);
    assert_eq!(call(&mut f, 16, 0), 0);
    assert_eq!(call(&mut f, 16, 0), 0);
    assert_eq!(call(&mut f, 8, 0), 0);
    // FLAG_CPU is for PRIVATE_EXPEDITED_RSEQ alone.
    assert_eq!(call(&mut f, 8, 1), einval);
    assert_eq!(call(&mut f, 128, 1), eperm);
    assert_eq!(call(&mut f, 256, 0), 0);
    assert_eq!(f.ret(nr::MEMBARRIER, &[128, 1, 12345]), 0);
    assert_eq!(call(&mut f, 128, 2), einval);
    assert_eq!(call(&mut f, 4, 0), 0);
    assert_eq!(call(&mut f, 512, 0), 4 | 16 | 64 | 256);
    // A fork's copy of the space keeps them, and a new one has none.
    let copy = f.mem.fork();
    assert_eq!(
        copy.membarrier_state()
            .load(std::sync::atomic::Ordering::SeqCst),
        0xff
    );
    f.mem = AddressSpace::new();
    f.mem
        .map(
            Some(GuestAddr(DATA)),
            0x2000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    assert_eq!(call(&mut f, 512, 0), 0);
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
        handle(ExitReason::BusError {
            rip,
            addr: GuestAddr(0x5000),
            write: true,
            fetch: false,
            present: true
        }),
        Next::Exit(ExitStatus::Signaled(signal::SIGBUS))
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
fn openat2_tail_in_the_last_page_is_efault() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    // A `struct open_how` whose later-version tail ends at the top of the
    // address space: the zero check reads it (EFAULT), without overflowing.
    let how = u64::MAX - 64;
    assert_eq!(
        f.ret(437, &[(-100i64) as u64, DATA, how, 64]),
        errno(Errno::EFAULT)
    );
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
fn linkat_follows_a_link_with_at_symlink_follow_and_links_a_descriptor_with_at_empty_path() {
    let mut f = fixture();
    let cwd = (-100i64) as u64;
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x10), b"/link\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x20), b"/new\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x30), b"\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x40), b"/none\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x50), b"/dangling\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(88, &[DATA, DATA + 0x10]), 0);
    let link = |f: &mut Fixture, dir, old, flags| f.ret(265, &[dir, old, cwd, DATA + 0x20, flags]);
    assert_eq!(link(&mut f, cwd, DATA + 0x10, 0x800), errno(Errno::EINVAL));
    // Without the flag the symbolic link itself is linked.
    assert_eq!(link(&mut f, cwd, DATA + 0x10, 0), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA + 0x20, true).0, 0o120_777);
    assert_eq!(f.ret(87, &[DATA + 0x20]), 0);
    assert_eq!(link(&mut f, cwd, DATA + 0x10, 0x400), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA + 0x20, true).0, 0o100_600);
    assert_eq!(f.ret(87, &[DATA + 0x20]), 0);
    assert_eq!(link(&mut f, fd, DATA + 0x30, 0), errno(Errno::ENOENT));
    assert_eq!(link(&mut f, fd, DATA + 0x30, 0x1000), 0);
    assert_eq!(stat_mode_and_mtime(&mut f, DATA + 0x20, true).0, 0o100_600);
    assert_eq!(link(&mut f, fd, DATA + 0x30, 0x1000), errno(Errno::EEXIST));
    assert_eq!(f.ret(87, &[DATA + 0x20]), 0);
    assert_eq!(link(&mut f, 99, DATA + 0x30, 0x1000), errno(Errno::EBADF));
    // A dangling link leads nowhere, and a removed file has no name.
    assert_eq!(f.ret(88, &[DATA + 0x40, DATA + 0x50]), 0);
    assert_eq!(link(&mut f, cwd, DATA + 0x50, 0x400), errno(Errno::ENOENT));
    assert_eq!(f.ret(87, &[DATA]), 0);
    assert_eq!(link(&mut f, fd, DATA + 0x30, 0x1000), errno(Errno::ENOENT));
}
/// The owner, group and mode `stat` (or `lstat`) gives for the path at `at`.
fn stat_owner(f: &mut Fixture, at: u64, nofollow: bool) -> (u32, u32, u32) {
    assert_eq!(f.ret(if nofollow { 6 } else { 4 }, &[at, DATA + 0x200]), 0);
    let mut st = [0; 144];
    f.mem.read(GuestAddr(DATA + 0x200), &mut st).unwrap();
    let field = |i: usize| u32::from_le_bytes(st[i..i + 4].try_into().unwrap());
    (field(28), field(32), field(24))
}
#[test]
fn the_chown_family_sets_owners_and_clears_set_id_bits() {
    let mut f = fixture();
    let cwd = (-100i64) as u64;
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x10), b"/link\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x20), b"/none\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x30), b"/dir\0").unwrap();
    f.mem.write(GuestAddr(DATA + 0x40), b"\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(88, &[DATA, DATA + 0x10]), 0); // symlink /link -> /file
    assert_eq!(f.ret(83, &[DATA + 0x30, 0o755]), 0);
    assert_eq!(stat_owner(&mut f, DATA, false), (0, 0, 0o100_600));
    // chown follows the link, lchown changes the link; -1 keeps an ID.
    assert_eq!(f.ret(92, &[DATA + 0x10, 1000, 100]), 0);
    assert_eq!(stat_owner(&mut f, DATA, false), (1000, 100, 0o100_600));
    assert_eq!(f.ret(94, &[DATA + 0x10, 7, u32::MAX as u64]), 0);
    assert_eq!(stat_owner(&mut f, DATA + 0x10, true), (7, 0, 0o120_777));
    assert_eq!(f.ret(93, &[fd, u32::MAX as u64, 5]), 0); // fchown
    assert_eq!(stat_owner(&mut f, DATA, false), (1000, 5, 0o100_600));
    // A file loses set-user-ID, and set-group-ID with group execution,
    // even when nothing changes.
    assert_eq!(f.ret(90, &[DATA, 0o6755]), 0);
    assert_eq!(f.ret(92, &[DATA, u32::MAX as u64, u32::MAX as u64]), 0);
    assert_eq!(stat_owner(&mut f, DATA, false).2, 0o100_755);
    assert_eq!(f.ret(90, &[DATA, 0o6745]), 0);
    assert_eq!(f.ret(93, &[fd, 0, 0]), 0);
    assert_eq!(stat_owner(&mut f, DATA, false), (0, 0, 0o102_745));
    // A directory keeps both.
    assert_eq!(f.ret(90, &[DATA + 0x30, 0o6755]), 0);
    assert_eq!(f.ret(260, &[cwd, DATA + 0x30, 3, 4, 0]), 0);
    assert_eq!(stat_owner(&mut f, DATA + 0x30, false), (3, 4, 0o046_755));
    // fchownat: AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH on a descriptor or the
    // working directory, and other flags.
    assert_eq!(f.ret(260, &[cwd, DATA + 0x10, 8, 9, 0x100]), 0);
    assert_eq!(stat_owner(&mut f, DATA + 0x10, true).0, 8);
    assert_eq!(f.ret(260, &[fd, DATA + 0x40, 11, 12, 0x1000]), 0);
    assert_eq!(stat_owner(&mut f, DATA, false).0, 11);
    assert_eq!(f.ret(260, &[cwd, DATA + 0x40, 13, 14, 0x1000]), 0);
    f.mem.write(GuestAddr(DATA + 0x50), b"/\0").unwrap();
    assert_eq!(stat_owner(&mut f, DATA + 0x50, false).0, 13);
    assert_eq!(
        f.ret(260, &[cwd, DATA + 0x40, 1, 1, 0]),
        errno(Errno::ENOENT)
    );
    assert_eq!(f.ret(260, &[cwd, DATA, 1, 1, 0x200]), errno(Errno::EINVAL));
    assert_eq!(f.ret(260, &[cwd, 0, 1, 1, 0x200]), errno(Errno::EINVAL));
    assert_eq!(f.ret(92, &[DATA + 0x20, 1, 1]), errno(Errno::ENOENT));
    assert_eq!(f.ret(93, &[99, 1, 1]), errno(Errno::EBADF));
    assert_eq!(f.ret(92, &[0, 1, 1]), errno(Errno::EFAULT));
    // statx reports them too.
    assert_eq!(f.ret(332, &[cwd, DATA, 0, 0x7ff, DATA + 0x300]), 0);
    let mut sx = [0; 8];
    f.mem.read(GuestAddr(DATA + 0x300 + 20), &mut sx).unwrap();
    assert_eq!(sx, [11, 0, 0, 0, 12, 0, 0, 0]);
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
    // sync_file_range: the descriptor, then the flags and the range, then
    // the file's type.
    assert_eq!(f.ret(277, &[fd, 0, 0, 7]), 0);
    assert_eq!(f.ret(277, &[fd, 4096, 4096, 2]), 0);
    for (offset, nbytes, flags) in [
        (0, 0, 8),
        (u64::MAX, 0, 0),
        (1, (-2i64) as u64, 0),
        (10, (-5i64) as u64, 0),
        (i64::MAX as u64, 1, 0),
    ] {
        assert_eq!(
            f.ret(277, &[fd, offset, nbytes, flags]),
            errno(Errno::EINVAL),
            "{offset} {nbytes} {flags}"
        );
    }
    assert_eq!(f.ret(277, &[pipe, 0, 0, 2]), errno(Errno(29)));
    assert_eq!(f.ret(277, &[pipe, 0, 0, 8]), errno(Errno::EINVAL));
    assert_eq!(f.ret(277, &[99, 0, 0, 8]), errno(Errno::EBADF));
    // An `O_PATH` descriptor is EBADF to them, as to every call that takes
    // its descriptor as Linux's `fdget` does; `fstat` and `F_GETFL` take it.
    let path = f.ret(2, &[DATA, 0o10000000, 0]);
    for (number, args) in [
        (74, [path, 0, 0]),
        (75, [path, 0, 0]),
        (221, [path, 0, 0]),
        (277, [path, 0, 0]),
        (0, [path, DATA + 0x400, 1]),
        (8, [path, 0, 0]),
        (73, [path, 1, 0]),
        (72, [path, 4, 0]),
    ] {
        assert_eq!(f.ret(number, &args), errno(Errno::EBADF), "{number}");
    }
    assert_eq!(f.ret(5, &[path, DATA + 0x400]), 0);
    assert_eq!(f.ret(72, &[path, 3, 0]), 0o10000000);
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
fn capget_and_capset_check_their_header() {
    const V1: u32 = 0x1998_0330;
    const V2: u32 = 0x2007_1026;
    const V3: u32 = 0x2008_0522;
    const DATA_AT: u64 = DATA + 0x100;
    let mut f = fixture();
    let header = |f: &mut _, version: u32, pid: i32| {
        let f: &mut Fixture = f;
        let bytes = [version.to_le_bytes(), pid.to_le_bytes()].concat();
        f.mem.write(GuestAddr(DATA), &bytes).unwrap();
    };
    let version = |f: &Fixture| f.mem.read_u64(GuestAddr(DATA)).unwrap() as u32;
    let words = |f: &Fixture| {
        let mut raw = [0; 24];
        f.mem.read(GuestAddr(DATA_AT), &mut raw).unwrap();
        raw.chunks(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect::<Vec<_>>()
    };
    // An unknown version is written back; with no data it only asks.
    header(&mut f, 1, 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, 0]), 0);
    assert_eq!(version(&f), V3);
    header(&mut f, 1, 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), errno(Errno::EINVAL));
    assert_eq!(version(&f), V3);
    header(&mut f, 1, 0);
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), errno(Errno::EINVAL));
    assert_eq!(version(&f), V3);
    assert_eq!(f.ret(nr::CAPGET, &[8, DATA_AT]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::CAPGET, &[8, 0]), errno(Errno::EFAULT));
    // The first version has one word of each set, the others two.
    f.mem.write(GuestAddr(DATA_AT), &[0x55; 24]).unwrap();
    header(&mut f, V1, 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), 0);
    let filler = 0x5555_5555;
    assert_eq!(words(&f), [u32::MAX, u32::MAX, 0, filler, filler, filler]);
    for v in [V2, V3] {
        header(&mut f, v, 0);
        assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), 0);
        assert_eq!(words(&f), [u32::MAX, u32::MAX, 0, 0x1ff, 0x1ff, 0]);
    }
    // Whom it names.
    header(&mut f, V3, -1);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), errno(Errno::EINVAL));
    header(&mut f, V3, 0x3f_ffff);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), errno(Errno(3)));
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), errno(Errno::EPERM));
    header(&mut f, V3, -1);
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), errno(Errno::EPERM));
    header(&mut f, V3, 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, 8]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::CAPSET, &[DATA, 8]), errno(Errno::EFAULT));
    // Bits past the last capability do not count, and dropping counts.
    let high = [0x7u32, 0xf, 0x1, u32::MAX, u32::MAX, 0]
        .map(u32::to_le_bytes)
        .concat();
    f.mem.write(GuestAddr(DATA_AT), &high).unwrap();
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), 0);
    assert_eq!(words(&f), [0x7, 0xf, 0x1, 0x1ff, 0x1ff, 0]);
    // The first version clears the high words.
    header(&mut f, V1, 0);
    let low = [0x3u32, 0x7, 0x1].map(u32::to_le_bytes).concat();
    f.mem.write(GuestAddr(DATA_AT), &low).unwrap();
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), 0);
    header(&mut f, V3, 0);
    assert_eq!(f.ret(nr::CAPGET, &[DATA, DATA_AT]), 0);
    assert_eq!(words(&f), [0x3, 0x7, 0x1, 0, 0, 0]);
    // Growing is refused.
    let more = [0x3u32, 0xf, 0x1, 0, 0, 0].map(u32::to_le_bytes).concat();
    f.mem.write(GuestAddr(DATA_AT), &more).unwrap();
    assert_eq!(f.ret(nr::CAPSET, &[DATA, DATA_AT]), errno(Errno::EPERM));
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
    assert_eq!(word(&f, 0) as u32, 0x17ff); // stx_mask, with STATX_MNT_ID
    assert_eq!(word(&f, 144), 21); // stx_mnt_id: the root's in mountinfo
    assert_eq!(word(&f, 0) >> 32, 4096); // stx_blksize
    assert_eq!(word(&f, 16) as u32, 1); // stx_nlink
    assert_eq!((word(&f, 24) >> 32) as u16, 0o100640); // stx_mode
    assert_eq!(word(&f, 40), 5); // stx_size
    assert_eq!(word(&f, 48), 8); // stx_blocks: one page, as tmpfs counts it
    // The same file through its path, and the root's device numbers.
    let inode = word(&f, 32);
    assert_eq!(f.ret(332, &[(-100i64) as u64, DATA, 0, 0x7ff, out]), 0);
    assert_eq!(word(&f, 32), inode);
    assert_eq!(word(&f, 136), 1 << 32); // major 0, minor 1
    // STATX_MNT_ID_UNIQUE asked for gives the unique ID in its place.
    assert_eq!(f.ret(332, &[fd, 0, 0x1000, 0x4000, out]), 0);
    assert_eq!(word(&f, 0) as u32, 0x47ff);
    assert_eq!(word(&f, 144), 1 << 31 | 21);
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
fn proc_fd_links_open_again_or_refuse() {
    let mut f = fixture();
    let (pair, path, buf) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
    assert_eq!(f.ret(22, &[pair]), 0);
    let read_end = f.mem.read_u64(GuestAddr(pair)).unwrap() & 0xffff_ffff;
    let link = format!("/proc/1/fd/{read_end}\0");
    f.mem.write(GuestAddr(path), link.as_bytes()).unwrap();
    // Every access opens the pipe through its read end: a reader, a writer,
    // or both (O_RDWR).
    for access in 0..3 {
        let fd = f.ret(2, &[path, access]);
        assert!(fd < 1 << 32, "{access}: {fd:#x}");
    }
    assert_eq!(
        f.ret(89, &[path, buf, 64]),
        f.ret(89, &[path, buf + 64, 64])
    );
    let event = f.ret(290, &[0, 0]);
    f.mem
        .write(
            GuestAddr(path),
            format!("/proc/self/fd/{event}\0").as_bytes(),
        )
        .unwrap();
    assert_eq!(f.ret(2, &[path, 2]), errno(Errno(6)));
    // A closed descriptor's link is gone.
    assert_eq!(f.ret(3, &[event]), 0);
    assert_eq!(f.ret(89, &[path, buf, 64]), errno(Errno::ENOENT));
    assert_eq!(f.ret(2, &[path, 0]), errno(Errno::ENOENT));
}
#[test]
fn set_and_get_robust_list_check_their_arguments() {
    let mut f = fixture();
    let (head, length) = (DATA, DATA + 8);
    assert_eq!(
        f.ret(nr::SET_ROBUST_LIST, &[DATA + 0x100, 23]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::SET_ROBUST_LIST, &[DATA + 0x100, 24]), 0);
    assert_eq!(f.ret(nr::GET_ROBUST_LIST, &[0, head, length]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(head)), Ok(DATA + 0x100));
    assert_eq!(f.mem.read_u64(GuestAddr(length)), Ok(24));
    assert_eq!(
        f.ret(nr::GET_ROBUST_LIST, &[99_999, head, length]),
        errno(Errno(3))
    );
    assert_eq!(
        f.ret(nr::GET_ROBUST_LIST, &[0, 0, length]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        f.ret(nr::GET_ROBUST_LIST, &[0, head, 0]),
        errno(Errno::EFAULT)
    );
}

#[test]
fn memory_locks_check_their_range_and_flags() {
    let mut f = fixture();
    let page = 4096;
    let anon_private = 0x22;
    let base = f.ret(nr::MMAP, &[0, 8 * page, 0, anon_private, u64::MAX, 0]);
    assert_eq!(f.ret(nr::MPROTECT, &[base + page, 2 * page, 3]), 0);
    let readable = base + page;
    let enomem = errno(Errno::ENOMEM);
    let einval = errno(Errno::EINVAL);

    assert_eq!(f.ret(nr::MLOCK, &[readable, 2 * page]), 0);
    assert_eq!(f.ret(nr::MLOCK, &[readable + 1, 2 * page - 1]), 0);
    assert_eq!(f.ret(nr::MLOCK, &[readable, 0]), 0);
    assert_eq!(f.ret(nr::MLOCK, &[page, 0]), 0);
    assert_eq!(f.ret(nr::MLOCK, &[page + 1, 0]), enomem);
    // Bringing pages in fails without access; only a lock does that.
    assert_eq!(f.ret(nr::MLOCK, &[base, page]), enomem);
    assert_eq!(f.ret(nr::MLOCK2, &[base, page, 0]), enomem);
    assert_eq!(f.ret(nr::MLOCK2, &[base, page, 1]), 0);
    assert_eq!(f.ret(nr::MUNLOCK, &[base, page]), 0);
    assert_eq!(f.ret(nr::MLOCK2, &[readable, page, 2]), einval);
    // Lengths round up, and may wrap to nothing or past the end of addresses.
    assert_eq!(f.ret(nr::MLOCK, &[readable + 1, u64::MAX]), 0);
    assert_eq!(f.ret(nr::MLOCK, &[readable, u64::MAX - 4095]), einval);
    assert_eq!(f.ret(nr::MUNLOCK, &[base + 7 * page, 2 * page]), enomem);
    assert_eq!(f.ret(nr::MUNMAP, &[base + 2 * page, page]), 0);
    assert_eq!(f.ret(nr::MUNLOCK, &[base, 4 * page]), enomem);

    for (flags, expected) in [
        (0, einval),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, einval),
        (5, 0),
        (7, 0),
        (8, einval),
        (1 << 32, einval),
        ((1 << 32) | 1, 0),
    ] {
        assert_eq!(f.ret(nr::MLOCKALL, &[flags]), expected, "flags {flags}");
    }
    assert_eq!(f.ret(nr::MUNLOCKALL, &[]), 0);
}

#[test]
fn xattrs_ask_for_permission_and_capabilities() {
    let mut f = fixture();
    let (path, buffer) = (DATA + 0x100, DATA + 0x800);
    let name = |f: &mut Fixture, n: &[u8]| {
        f.mem.write(GuestAddr(DATA + 0x200), n).unwrap();
        DATA + 0x200
    };
    f.mem.write(GuestAddr(path), b"/xattr-file\0").unwrap();
    let fd = f.ret(2, &[path, 0o102, 0o644]);
    assert!(fd < 1024, "{fd}");
    let (eperm, eacces, enodata) = (errno(Errno::EPERM), errno(Errno::EACCES), errno(Errno(61)));

    // Root has them all, and a name of the trusted namespace shows in the list.
    for n in [&b"user.a\0"[..], b"trusted.a\0", b"security.a\0"] {
        let a = name(&mut f, n);
        assert_eq!(f.ret(188, &[path, a, buffer, 1, 0]), 0);
    }
    assert_eq!(f.ret(194, &[path, 0, 0]), 28);

    // Group and others have read access only.
    assert_eq!(f.ret(nr::SETUID, &[1000]), 0);
    let user = name(&mut f, b"user.a\0");
    assert_eq!(f.ret(191, &[path, user, 0, 0]), 1);
    assert_eq!(f.ret(188, &[path, user, buffer, 1, 0]), eacces);
    assert_eq!(f.ret(197, &[path, user]), eacces);
    let trusted = name(&mut f, b"trusted.a\0");
    assert_eq!(f.ret(191, &[path, trusted, 0, 0]), enodata);
    assert_eq!(f.ret(188, &[path, trusted, buffer, 1, 0]), eperm);
    assert_eq!(f.ret(197, &[path, trusted]), eperm);
    let security = name(&mut f, b"security.a\0");
    assert_eq!(f.ret(191, &[path, security, 0, 0]), 1);
    assert_eq!(f.ret(188, &[path, security, buffer, 1, 0]), eacces);
    // The list hides what cannot be read.
    assert_eq!(f.ret(194, &[path, 0, 0]), 18);
}

#[test]
fn an_xattr_list_longer_than_linux_copies_is_too_big() {
    let mut f = fixture();
    let (path, wanted) = (DATA + 0x100, DATA + 0x200);
    f.mem.write(GuestAddr(path), b"/xattr-list\0").unwrap();
    assert!(f.ret(2, &[path, 0o102, 0o644]) < 1024);
    // 300 names of 240 bytes and a terminator each.
    for i in 0..300 {
        let name = format!("user.{i:0>235}\0");
        f.mem.write(GuestAddr(wanted), name.as_bytes()).unwrap();
        assert_eq!(f.ret(188, &[path, wanted, wanted, 1, 0]), 0);
    }
    let length = 300 * 241;
    let start = f.ret(nr::MMAP, &[0, 1 << 20, 3, 0x22, u64::MAX, 0]);
    assert_eq!(f.ret(194, &[path, 0, 0]), length);
    assert_eq!(f.ret(194, &[path, start, 65535]), errno(Errno(34)));
    assert_eq!(f.ret(194, &[path, start, 65536]), errno(Errno(7)));
    assert_eq!(f.ret(194, &[path, start, length]), errno(Errno(7)));
    assert_eq!(f.ret(194, &[path, start, 1 << 20]), errno(Errno(7)));
}

#[test]
fn mincore_reports_what_was_touched_up_to_what_is_not_mapped() {
    let mut f = fixture();
    let (vec, page) = (DATA + 0x800, 4096);
    let base = f.ret(nr::MMAP, &[0, 3 * page, 3, 0x22, u64::MAX, 0]);
    f.mem.write_u64(GuestAddr(base + page), 1).unwrap();
    f.mem.write(GuestAddr(vec), &[9; 4]).unwrap();
    assert_eq!(f.ret(nr::MINCORE, &[base, 3 * page, vec]), 0);
    let mut seen = [9; 4];
    f.mem.read(GuestAddr(vec), &mut seen).unwrap();
    assert_eq!(seen, [0, 1, 0, 9]);
    // Reading a page brings it in too, and a length rounds up.
    f.mem.read_u64(GuestAddr(base)).unwrap();
    assert_eq!(f.ret(nr::MINCORE, &[base, 1, vec]), 0);
    f.mem.read(GuestAddr(vec), &mut seen).unwrap();
    assert_eq!(seen[0], 1);
    assert_eq!(f.ret(nr::MADVISE, &[base, page, 4]), 0);
    assert_eq!(f.ret(nr::MINCORE, &[base, page, vec]), 0);
    f.mem.read(GuestAddr(vec), &mut seen).unwrap();
    assert_eq!(seen[0], 0);
    assert_eq!(
        f.ret(nr::MINCORE, &[base + 1, page, vec]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(nr::MINCORE, &[base, 0, 0]), 0);
    assert_eq!(f.ret(nr::MINCORE, &[base, page, 0]), errno(Errno::EFAULT));
    assert_eq!(
        f.ret(nr::MINCORE, &[base, u64::MAX, vec]),
        errno(Errno::ENOMEM)
    );
    // What is before the gap is written, then the gap is ENOMEM.
    assert_eq!(f.ret(nr::MUNMAP, &[base + 2 * page, page]), 0);
    f.mem.write(GuestAddr(vec), &[9; 4]).unwrap();
    assert_eq!(
        f.ret(nr::MINCORE, &[base, 3 * page, vec]),
        errno(Errno::ENOMEM)
    );
    f.mem.read(GuestAddr(vec), &mut seen).unwrap();
    assert_eq!(seen, [0, 1, 9, 9]);
}
#[test]
fn proc_maps_reads_through_the_system_calls_though_its_size_is_zero() {
    let mut f = fixture();
    let (path, buf, stat) = (DATA, DATA + 0x400, DATA + 0xe00);
    f.mem.write(GuestAddr(path), b"/proc/self/maps\0").unwrap();
    let fd = f.ret(2, &[path, 0]);
    assert_eq!(f.ret(5, &[fd, stat]), 0);
    let mut size = [0; 8];
    f.mem.read(GuestAddr(stat + 48), &mut size).unwrap();
    assert_eq!(u64::from_le_bytes(size), 0);
    // read, then pread and sendfile from the start, each past the size.
    let count = f.ret(0, &[fd, buf, 512]);
    assert!(count > 0 && count <= 512, "{count:#x}");
    let mut line = vec![0; count as usize];
    f.mem.read(GuestAddr(buf), &mut line).unwrap();
    assert!(line.contains(&b'-') && line.contains(&b'\n'));
    assert_eq!(f.ret(17, &[fd, buf + 0x800, 8, 0]), 8);
    let mut again = [0; 8];
    f.mem.read(GuestAddr(buf + 0x800), &mut again).unwrap();
    assert_eq!(again, line[..8]);
    let memfd_name = DATA + 0x300;
    f.mem.write(GuestAddr(memfd_name), b"out\0").unwrap();
    let out = f.ret(319, &[memfd_name, 0]);
    assert_eq!(f.ret(8, &[fd, 0, 0]), 0);
    assert_eq!(f.ret(40, &[out, fd, 0, 16]), 16);
    assert_eq!(f.ret(3, &[fd]), 0);
}
#[test]
fn proc_fd_links_resolve_at_most_forty_symbolic_links() {
    let mut f = fixture();
    let (name, buf) = (DATA, DATA + 0x400);
    let put = |f: &mut Fixture, at: u64, text: &str| {
        f.mem
            .write(GuestAddr(at), format!("{text}\0").as_bytes())
            .unwrap();
    };
    put(&mut f, name, "/t");
    assert_eq!(f.ret(2, &[name, 0o101, 0o600]), 3);
    assert_eq!(f.ret(3, &[3]), 0);
    // /l1 -> /l2 -> ... -> /l40 -> /t: forty links, which open follows too.
    for i in 1..=40 {
        let target = if i == 40 {
            "/t".to_owned()
        } else {
            format!("/l{}", i + 1)
        };
        put(&mut f, name, &target);
        put(&mut f, name + 0x100, &format!("/l{i}"));
        assert_eq!(f.ret(88, &[name, name + 0x100]), 0);
    }
    put(&mut f, name, "/l1");
    let fd = f.ret(2, &[name, 0]);
    put(&mut f, name + 0x100, &format!("/proc/self/fd/{fd}"));
    let link = |f: &mut Fixture| {
        let n = f.ret(89, &[name + 0x100, buf, 64]);
        let mut b = vec![0; usize::try_from(n).unwrap()];
        f.mem.read(GuestAddr(buf), &mut b).unwrap();
        b
    };
    assert_eq!(link(&mut f), b"/t");
    // One link more: the path no longer resolves, so it shows as deleted,
    // but the link still opens its file again, as Linux's does.
    put(&mut f, name, "/l40");
    assert_eq!(f.ret(87, &[name]), 0);
    put(&mut f, name, "/l41");
    put(&mut f, name + 0x200, "/l40");
    assert_eq!(f.ret(88, &[name, name + 0x200]), 0);
    put(&mut f, name, "/t");
    put(&mut f, name + 0x200, "/l41");
    assert_eq!(f.ret(88, &[name, name + 0x200]), 0);
    assert_eq!(link(&mut f), b"/l1 (deleted)");
    assert!(f.ret(2, &[name + 0x100, 0]) < 1 << 31);
}
#[test]
fn dev_reports_its_devices_and_lists_them() {
    let mut f = fixture();
    let (name, out) = (DATA, DATA + 0x100);
    f.mem.write(GuestAddr(name), b"/dev/urandom\0").unwrap();
    assert_eq!(f.ret(332, &[(-100i64) as u64, name, 0, 0x7ff, out]), 0);
    let word = |f: &Fixture, at: u64| f.mem.read_u64(GuestAddr(out + at)).unwrap();
    assert_eq!(word(&f, 128), 9 << 32 | 1); // stx_rdev_major 1, minor 9
    f.mem.write(GuestAddr(name), b"/dev\0").unwrap();
    let dir = f.ret(2, &[name, 0o200000]);
    let n = f.ret(217, &[dir, out, 0x1000]);
    let mut b = vec![0; usize::try_from(n).unwrap()];
    f.mem.read(GuestAddr(out), &mut b).unwrap();
    let mut names = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let size = usize::from(u16::from_le_bytes([b[at + 16], b[at + 17]]));
        let end = b[at + 19..].iter().position(|&c| c == 0).unwrap();
        names.push(String::from_utf8(b[at + 19..at + 19 + end].to_vec()).unwrap());
        at += size;
    }
    assert_eq!(
        names,
        [
            ".", "..", "fd", "full", "null", "ptmx", "pts", "random", "stderr", "stdin", "stdout",
            "urandom", "zero"
        ]
    );
    assert_eq!(f.ret(217, &[dir, out, 0x1000]), 0); // the end
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
fn process_groups_start_outside_the_emulator() {
    let mut f = fixture();
    // The first process's group is outside, shown as 0 as Linux shows an ID
    // outside a PID namespace, so the process may start a session.
    assert_eq!(f.ret(111, &[]), 0); // getpgrp
    assert_eq!(f.ret(121, &[0]), 0); // getpgid
    assert_eq!(f.ret(121, &[1]), 0);
    assert_eq!(f.ret(109, &[0, 0]), 0); // setpgid
    assert_eq!(f.ret(111, &[]), 1);
    assert_eq!(f.ret(109, &[1, 1]), 0);
    assert_eq!(f.ret(109, &[0, 77]), errno(Errno::EPERM));
    assert_eq!(f.ret(109, &[0, u64::MAX]), errno(Errno::EINVAL));
    assert_eq!(f.ret(109, &[99, 0]), errno(Errno(3)));
    assert_eq!(f.ret(121, &[99]), errno(Errno(3)));
    assert_eq!(f.ret(121, &[u64::MAX]), errno(Errno(3)));
}
#[test]
fn the_first_process_may_start_a_session() {
    let mut f = fixture();
    assert_eq!(f.ret(124, &[0]), 0); // getsid
    assert_eq!(f.ret(112, &[]), 1); // setsid
    assert_eq!((f.ret(124, &[0]), f.ret(111, &[])), (1, 1));
    assert_eq!(f.ret(112, &[]), errno(Errno::EPERM));
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
/// What the file `fd` holds from `offset`, read with `pread`.
fn file_bytes(f: &mut Fixture, fd: u64, offset: u64, len: usize) -> Vec<u8> {
    let n = f.ret(17, &[fd, DATA + 0x1000, len as u64, offset]);
    let mut bytes = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x1000), &mut bytes).unwrap();
    bytes
}
fn memory_bytes(f: &Fixture, at: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    f.mem.read(GuestAddr(at), &mut bytes).unwrap();
    bytes
}
#[test]
fn memory_file_shared_mapping_shows_the_file() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
    let at = f.ret(syscalls::nr::MMAP, &[0, 8192, 3, 1, fd, 0]);
    assert_eq!(memory_bytes(&f, at, 6), b"hello\0");
    // A store reaches the file, and a write to the file the mapping.
    f.mem.write(GuestAddr(at), b"J").unwrap();
    assert_eq!(file_bytes(&mut f, fd, 0, 8), b"Jello");
    f.mem.write(GuestAddr(DATA + 0x100), b"xy").unwrap();
    assert_eq!(f.ret(18, &[fd, DATA + 0x100, 2, 3]), 2);
    assert_eq!(memory_bytes(&f, at, 5), b"Jelxy");
    // Another mapping shows the same pages; a private one copies them.
    let other = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, fd, 0]);
    f.mem.write(GuestAddr(other + 1), b"E").unwrap();
    assert_eq!(memory_bytes(&f, at, 2), b"JE");
    let private = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2, fd, 0]);
    assert_eq!(memory_bytes(&f, private, 5), b"JElxy");
    // Truncating clears what lies past the end; a store there stays out
    // of the file, which keeps its size.
    assert_eq!(f.ret(77, &[fd, 2]), 0);
    assert_eq!(memory_bytes(&f, at, 3), b"JE\0");
    f.mem.write(GuestAddr(at + 2), b"!").unwrap();
    assert_eq!(f.ret(5, &[fd, DATA + 0x200]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 0x200 + 48)).unwrap(), 2);
    assert_eq!(f.ret(77, &[fd, 4]), 0);
    assert_eq!(file_bytes(&mut f, fd, 0, 8), b"JE\0\0");
    assert_eq!(memory_bytes(&f, at, 4), b"JE\0\0");
    // msync writes back; after the last unmap the stores are in the file.
    f.mem.write(GuestAddr(other + 3), b"z").unwrap();
    assert_eq!(f.ret(syscalls::nr::MSYNC, &[other, 4096, 4]), 0);
    f.mem.write(GuestAddr(at), b"q").unwrap();
    assert_eq!(f.ret(11, &[at, 8192]), 0);
    assert_eq!(f.ret(11, &[other, 4096]), 0);
    assert_eq!(file_bytes(&mut f, fd, 0, 8), b"qE\0z");
}
#[test]
fn file_mappings_end_where_their_file_does() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
    let mut b = [0];
    for flags in [1, 2] {
        // A page wholly past the end is a bus error; the size the file's
        // handles give is the one that counts.
        let at = f.ret(syscalls::nr::MMAP, &[0, 2 * 4096, 3, flags, fd, 0]);
        assert_eq!(memory_bytes(&f, at, 6), b"hello\0");
        assert!(f.mem.read(GuestAddr(at + 4096), &mut b).unwrap_err().bus);
        assert_eq!(f.ret(77, &[fd, 4097]), 0);
        assert_eq!(memory_bytes(&f, at + 4096, 1), [0]);
        // Grown with mremap, the mapping reads the file further on.
        assert_eq!(f.ret(18, &[fd, DATA + 6, 5, 2 * 4096]), 5);
        let grown = f.ret(syscalls::nr::MREMAP, &[at, 2 * 4096, 3 * 4096, 1, 0]);
        assert_eq!(memory_bytes(&f, grown + 2 * 4096, 5), b"hello");
        assert_eq!(f.ret(77, &[fd, 5]), 0);
        assert!(f.mem.read(GuestAddr(grown + 4096), &mut b).unwrap_err().bus);
        assert_eq!(f.ret(11, &[grown, 3 * 4096]), 0);
    }
}
#[test]
fn private_file_mappings_show_the_file_until_they_write_it() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
    assert_eq!(f.ret(77, &[fd, 2 * 4096]), 0);
    let at = f.ret(syscalls::nr::MMAP, &[0, 2 * 4096, 3, 2, fd, 0]);
    assert_eq!(memory_bytes(&f, at, 5), b"hello");
    // A page the mapping has not written shows later writes to the file.
    f.mem.write(GuestAddr(DATA), b"HELLOworld").unwrap();
    assert_eq!(f.ret(18, &[fd, DATA, 5, 0]), 5);
    assert_eq!(memory_bytes(&f, at, 5), b"HELLO");
    // Its first write copies it: the file keeps its bytes, and the copy
    // does not show the file's later changes.
    f.mem.write(GuestAddr(at), b"j").unwrap();
    assert_eq!(file_bytes(&mut f, fd, 0, 5), b"HELLO");
    assert_eq!(f.ret(18, &[fd, DATA + 5, 5, 0]), 5);
    assert_eq!(memory_bytes(&f, at, 5), b"jELLO");
    assert_eq!(f.ret(18, &[fd, DATA + 5, 5, 4096]), 5);
    assert_eq!(memory_bytes(&f, at + 4096, 5), b"world");
    // A truncation drops the copies it leaves wholly past the end of the
    // file, even when the file grows again; the others stay.
    f.mem.write(GuestAddr(at + 4096), b"x").unwrap();
    assert_eq!(f.ret(77, &[fd, 4096]), 0);
    let mut b = [0];
    assert!(f.mem.read(GuestAddr(at + 4096), &mut b).unwrap_err().bus);
    assert_eq!(f.ret(77, &[fd, 2 * 4096]), 0);
    assert_eq!(memory_bytes(&f, at + 4096, 5), [0; 5]);
    assert_eq!(memory_bytes(&f, at, 5), b"jELLO");
    // MADV_DONTNEED gives a copy back: the page shows the file again.
    assert_eq!(f.ret(28, &[at, 4096, 4]), 0);
    assert_eq!(memory_bytes(&f, at, 5), b"world");
    assert_eq!(f.ret(11, &[at, 2 * 4096]), 0);
}
#[test]
fn memory_file_shared_mapping_needs_a_writable_file() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    // Open for writing, a read-only shared mapping may become writable.
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 1, fd, 0]);
    assert_eq!(f.ret(10, &[at, 4096, 3]), 0);
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let read_only = f.ret(2, &[DATA, 0, 0]);
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, read_only, 0]),
        errno(Errno::EACCES)
    );
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 1, read_only, 0]);
    assert_eq!(f.ret(10, &[at, 4096, 3]), errno(Errno::EACCES));
    assert_eq!(f.ret(10, &[at, 4096, 5]), 0);
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let write_only = f.ret(2, &[DATA, 1, 0]);
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 2, write_only, 0]),
        errno(Errno::EACCES)
    );
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, write_only, 0]),
        errno(Errno::EACCES)
    );
}
#[test]
fn memfd_shared_mapping_and_the_write_seal() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"m\0").unwrap();
    let fd = f.ret(319, &[DATA, 2]); // MFD_ALLOW_SEALING
    assert_eq!(f.ret(77, &[fd, 4096]), 0);
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, fd, 0]);
    f.mem.write(GuestAddr(at), b"seal").unwrap();
    assert_eq!(file_bytes(&mut f, fd, 0, 4), b"seal");
    // F_SEAL_WRITE waits for the writable mapping to go, and so does
    // F_SEAL_EXEC, which seals writes too on an executable memfd.
    assert_eq!(f.ret(72, &[fd, 1033, 8]), errno(Errno(16)));
    assert_eq!(f.ret(72, &[fd, 1033, 0x20]), errno(Errno(16)));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    assert_eq!(f.ret(72, &[fd, 1033, 8]), 0);
    assert_eq!(
        f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 1, fd, 0]),
        errno(Errno::EPERM)
    );
    // A read-only shared mapping of a sealed memfd stays read-only.
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 1, fd, 0]);
    assert_eq!(memory_bytes(&f, at, 4), b"seal");
    assert_eq!(f.ret(10, &[at, 4096, 3]), errno(Errno::EACCES));
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
    let legacy = [0x10_0011, 0x1800, 0x300, 0x200, 0x400, 0];
    assert_eq!(args(64), Ok((legacy, vec![])));
    assert_eq!(args(63), Err(Errno::EINVAL));
    assert_eq!(args(4097), Err(Errno(7)));
    assert_eq!(args(96), Ok((legacy, vec![])));
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
    // set_tid and its size come together, at most 32 numbers, which are
    // read before the flags are looked at.
    put(&[0, 0, 0, 0, 17, 0, 0, 0, 0, 1, 0]);
    assert_eq!(args(88), Err(Errno::EINVAL));
    put(&[0, 0, 0, 0, 17, 0, 0, 0, DATA, 0, 0]);
    assert_eq!(args(88), Err(Errno::EINVAL));
    put(&[0, 0, 0, 0, 17, 0, 0, 0, DATA, 33, 0]);
    assert_eq!(args(88), Err(Errno::EINVAL));
    put(&[0x11, 0, 0, 0, 17, 0, 0, 0, 0x10, 2, 0]);
    assert_eq!(args(88), Err(Errno::EFAULT));
    put(&[0, 0, 0, 0, 17, 0, 0, 0, DATA + 88, 2, 0, 7 | 3 << 32]);
    assert_eq!(args(88), Ok(([17, 0, 0, 0, 0, 0], vec![7, 3])));
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
#[test]
fn fallocate_allocates_the_pages_of_a_memfd() {
    let mut f = fixture();
    let out = DATA + 0x100;
    f.mem.write(GuestAddr(DATA), b"m\0").unwrap();
    let fd = f.ret(319, &[DATA, 0]);
    assert_eq!(f.ret(285, &[fd, 0, 0, 8192]), 0);
    assert_eq!(f.ret(5, &[fd, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 48)).unwrap(), 8192); // st_size
    assert_eq!(f.mem.read_u64(GuestAddr(out + 64)).unwrap(), 16); // st_blocks
    // Past the 4 GiB the file system has, tmpfs's ENOSPC.
    assert_eq!(
        f.ret(285, &[fd, 1, 0, 1 << 40]),
        Errno(28).to_syscall_return()
    );
}
mod stdin_readiness {
    use super::*;
    use paludarium_host::Host;
    const POLLIN: u64 = 1;
    /// `poll` of standard input for POLLIN with `timeout` ms: the result,
    /// `revents` and the virtual milliseconds it waited.
    fn poll(f: &mut Fixture, timeout: u64) -> (u64, u16, u64) {
        f.mem.write(GuestAddr(DATA), &0i32.to_le_bytes()).unwrap();
        f.mem
            .write(GuestAddr(DATA + 4), &1u16.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(DATA + 6), &0u16.to_le_bytes())
            .unwrap();
        let start = f.host.clock(paludarium_host::ClockId::Monotonic).unwrap();
        let ready = f.ret(7, &[DATA, 1, timeout]);
        let end = f.host.clock(paludarium_host::ClockId::Monotonic).unwrap();
        let mut revents = [0u8; 2];
        f.mem.read(GuestAddr(DATA + 6), &mut revents).unwrap();
        (
            ready,
            u16::from_le_bytes(revents),
            (end - start) / 1_000_000,
        )
    }
    /// `select` of standard input for reading, without waiting.
    fn select(f: &mut Fixture) -> u64 {
        f.mem.write_u64(GuestAddr(DATA + 64), 1).unwrap();
        f.mem.write(GuestAddr(DATA + 128), &[0u8; 16]).unwrap();
        f.ret(23, &[1, DATA + 64, 0, 0, DATA + 128])
    }
    #[test]
    fn standard_input_is_readable_only_with_bytes_or_at_its_end() {
        let mut f = fixture();
        f.host.open_stdin();
        // Idle: nothing to read, so poll waits out its timeout.
        assert_eq!(poll(&mut f, 0), (0, 0, 0));
        assert_eq!(poll(&mut f, 50), (0, 0, 50));
        assert_eq!(select(&mut f), 0);
        // One byte pending: ready at once.
        f.host.push_stdin(b"a");
        assert_eq!(poll(&mut f, 0), (1, POLLIN as u16, 0));
        assert_eq!(poll(&mut f, 50), (1, POLLIN as u16, 0));
        assert_eq!(select(&mut f), 1);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 1);
        // Drained: idle again.
        assert_eq!(poll(&mut f, 0), (0, 0, 0));
        assert_eq!(poll(&mut f, 50), (0, 0, 50));
        assert_eq!(select(&mut f), 0);
        // Closed: readable and hung up, as a pipe whose writer is gone, and
        // read gives its end.
        f.host.close_stdin();
        assert_eq!(poll(&mut f, 50), (1, (POLLIN | 0x10) as u16, 0));
        assert_eq!(select(&mut f), 1);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 0);
    }
    #[test]
    fn f_setfl_keeps_the_standard_streams_flags() {
        let mut f = fixture();
        f.host.open_stdin();
        // O_NONBLOCK: a read finding nothing is EAGAIN, not a wait.
        assert_eq!(f.ret(72, &[0, 4, 0x800]), 0);
        assert_eq!(f.ret(72, &[0, 3]), 0x800);
        assert_eq!(
            f.ret(0, &[0, DATA + 256, 16]),
            Errno::EAGAIN.to_syscall_return()
        );
        f.host.push_stdin(b"a");
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 1);
        // FIONBIO clears it again; the output keeps its access mode.
        f.mem
            .write(GuestAddr(DATA + 64), &0u32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(16, &[0, 0x5421, DATA + 64]), 0);
        assert_eq!(f.ret(72, &[0, 3]), 0);
        assert_eq!(f.ret(72, &[1, 4, 0o2000]), 0);
        assert_eq!(f.ret(72, &[1, 3]), 0o2001);
    }
    #[test]
    fn standard_input_signals_its_owner_with_o_async() {
        // A preset input stands for a file without fasync, as /dev/null:
        // O_ASYNC is dropped, and FIOASYNC is ENOTTY.
        let mut f = fixture();
        assert_eq!(f.ret(72, &[0, 4, 0o20000]), 0);
        assert_eq!(f.ret(72, &[0, 3]), 0);
        f.mem
            .write(GuestAddr(DATA + 64), &1u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            f.ret(16, &[0, 0x5452, DATA + 64]),
            Errno::ENOTTY.to_syscall_return()
        );
        // A live one, as a pipe or terminal, keeps it, and input coming
        // where there was none sends SIGIO to the owner.
        let mut f = fixture();
        f.host.open_stdin();
        let pid = f.ret(39, &[]);
        assert_eq!(f.ret(72, &[0, 8, pid]), 0);
        // SIGIO blocked, so that it stays pending.
        f.mem.write_u64(GuestAddr(DATA + 64), 1 << 28).unwrap();
        assert_eq!(f.ret(14, &[0, DATA + 64, 0, 8]), 0);
        assert_eq!(f.ret(72, &[0, 4, 0o20000]), 0);
        assert_eq!(f.ret(72, &[0, 3]), 0o20000);
        let pending = |f: &mut Fixture| {
            assert_eq!(f.ret(127, &[DATA + 72, 8]), 0);
            f.mem.read_u64(GuestAddr(DATA + 72)).unwrap() & 1 << 28 != 0
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!pending(&mut f));
        f.host.push_stdin(b"x");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !pending(&mut f) {
            assert!(std::time::Instant::now() < deadline, "no SIGIO");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Off again: the watcher stops.
        assert_eq!(f.ret(72, &[0, 4, 0]), 0);
        assert_eq!(f.ret(72, &[0, 3]), 0);
    }
    #[test]
    fn a_read_of_standard_input_waits_in_the_kernel() {
        // Nothing to read: the read waits in the kernel, not on the host, so
        // what ends a kernel wait ends it (EINTR), as a signal does on Linux.
        let mut f = fixture();
        f.host.open_stdin();
        // An empty read reads nothing at once, blocking or not.
        assert_eq!(f.ret(0, &[0, DATA + 256, 0]), 0);
        assert_eq!(f.ret(72, &[0, 4, 0x800]), 0);
        assert_eq!(f.ret(0, &[0, DATA + 256, 0]), 0);
        assert_eq!(f.ret(72, &[0, 4, 0]), 0);
        f.kernel
            .cancellation
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), errno(Errno(4)));
        f.kernel
            .cancellation
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // With input, it reads at once; at the end, it reads the end.
        f.host.push_stdin(b"ok");
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 2);
        f.host.close_stdin();
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 0);
    }
    #[test]
    fn a_nonblocking_write_with_no_room_on_the_host_is_eagain() {
        let mut f = fixture();
        f.mem.write(GuestAddr(DATA + 256), b"hi").unwrap();
        // writev's iovec: the two bytes at DATA + 256.
        f.mem.write_u64(GuestAddr(DATA + 300), DATA + 256).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 308), 2).unwrap();
        f.host.set_output_full(1, true);
        // Blocking, a write goes as before.
        assert_eq!(f.ret(1, &[1, DATA + 256, 2]), 2);
        assert_eq!(f.ret(72, &[1, 4, 0x800]), 0);
        assert_eq!(
            f.ret(1, &[1, DATA + 256, 2]),
            Errno::EAGAIN.to_syscall_return()
        );
        assert_eq!(
            f.ret(20, &[1, DATA + 300, 1]),
            Errno::EAGAIN.to_syscall_return()
        );
        // An empty write writes nothing, full or not.
        assert_eq!(f.ret(1, &[1, DATA + 256, 0]), 0);
        // Standard error is a stream of its own.
        assert_eq!(f.ret(1, &[2, DATA + 256, 2]), 2);
        f.host.set_output_full(1, false);
        assert_eq!(f.ret(1, &[1, DATA + 256, 2]), 2);
        assert_eq!(f.ret(20, &[1, DATA + 300, 1]), 2);
        assert_eq!(f.host.stdout(), b"hihihi");
    }
    #[test]
    fn standard_output_signals_its_owner_when_it_has_room_again() {
        // The recorded output stands for a pipe: it keeps O_ASYNC, and
        // FIOASYNC takes it, as on Linux.
        let mut f = fixture();
        let pid = f.ret(39, &[]);
        assert_eq!(f.ret(72, &[1, 8, pid]), 0);
        f.mem.write_u64(GuestAddr(DATA + 64), 1 << 28).unwrap();
        assert_eq!(f.ret(14, &[0, DATA + 64, 0, 8]), 0);
        f.mem
            .write(GuestAddr(DATA + 80), &1u32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(16, &[1, 0x5452, DATA + 80]), 0);
        assert_eq!(f.ret(72, &[1, 3]), 0o20001);
        let pending = |f: &mut Fixture| {
            assert_eq!(f.ret(127, &[DATA + 72, 8]), 0);
            f.mem.read_u64(GuestAddr(DATA + 72)).unwrap() & 1 << 28 != 0
        };
        // Room all along: nothing. Full, then room again: SIGIO. The guest
        // told EAGAIN waits for it, however soon the room comes, and the
        // watcher looks only now and then.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!pending(&mut f));
        f.host.set_output_full(1, true);
        assert_eq!(f.ret(72, &[1, 4, 0o24001]), 0);
        assert_eq!(
            f.ret(1, &[1, DATA + 80, 1]),
            Errno::EAGAIN.to_syscall_return()
        );
        assert!(!pending(&mut f));
        f.host.set_output_full(1, false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !pending(&mut f) {
            assert!(std::time::Instant::now() < deadline, "no SIGIO");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(f.ret(72, &[1, 4, 0]), 0);
        assert_eq!(f.ret(72, &[1, 3]), 1);
    }
    #[test]
    fn standard_input_signals_a_reader_it_told_to_wait() {
        // Ready when the watcher starts, so it never saw it not ready: input
        // right after the guest was told EAGAIN still sends SIGIO.
        let mut f = fixture();
        f.host.open_stdin();
        f.host.push_stdin(b"x");
        let pid = f.ret(39, &[]);
        assert_eq!(f.ret(72, &[0, 8, pid]), 0);
        f.mem.write_u64(GuestAddr(DATA + 64), 1 << 28).unwrap();
        assert_eq!(f.ret(14, &[0, DATA + 64, 0, 8]), 0);
        assert_eq!(f.ret(72, &[0, 4, 0o24000]), 0);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 1);
        assert_eq!(
            f.ret(0, &[0, DATA + 256, 16]),
            Errno::EAGAIN.to_syscall_return()
        );
        f.host.push_stdin(b"y");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            assert_eq!(f.ret(127, &[DATA + 72, 8]), 0);
            if f.mem.read_u64(GuestAddr(DATA + 72)).unwrap() & 1 << 28 != 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "no SIGIO");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(f.ret(72, &[0, 4, 0]), 0);
    }
    #[test]
    fn a_host_that_cannot_tell_keeps_standard_input_ready() {
        // A preset buffer that has ended, as before: always ready.
        let mut f = fixture();
        assert_eq!(poll(&mut f, 50), (1, POLLIN as u16, 0));
    }
    /// `epoll_wait` for one event, without waiting.
    fn epoll_wait(f: &mut Fixture, epfd: u64) -> u64 {
        f.ret(232, &[epfd, DATA + 512, 1, 0])
    }
    #[test]
    fn epoll_watches_standard_input() {
        let mut f = fixture();
        f.host.open_stdin();
        let level = f.ret(291, &[0]);
        let edge = f.ret(291, &[0]);
        // EPOLLIN, and EPOLLIN | EPOLLET.
        for (epfd, events) in [(level, 1u32), (edge, 1 | 1 << 31)] {
            f.mem
                .write(GuestAddr(DATA + 448), &events.to_le_bytes())
                .unwrap();
            f.mem.write_u64(GuestAddr(DATA + 452), 7).unwrap();
            assert_eq!(f.ret(233, &[epfd, 1, 0, DATA + 448]), 0);
        }
        assert_eq!(epoll_wait(&mut f, level), 0);
        assert_eq!(epoll_wait(&mut f, edge), 0);
        f.host.push_stdin(b"ab");
        assert_eq!(epoll_wait(&mut f, level), 1);
        assert_eq!(epoll_wait(&mut f, level), 1);
        // Edge-triggered: once per time it becomes ready.
        assert_eq!(epoll_wait(&mut f, edge), 1);
        assert_eq!(epoll_wait(&mut f, edge), 0);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 2);
        assert_eq!(epoll_wait(&mut f, level), 0);
        f.host.push_stdin(b"c");
        assert_eq!(epoll_wait(&mut f, edge), 1);
        assert_eq!(f.ret(0, &[0, DATA + 256, 16]), 1);
        // At its end: EPOLLIN | EPOLLHUP.
        f.host.close_stdin();
        assert_eq!(epoll_wait(&mut f, level), 1);
        let mut events = [0u8; 4];
        f.mem.read(GuestAddr(DATA + 512), &mut events).unwrap();
        assert_eq!(u32::from_le_bytes(events), 1 | 0x10);
    }
}

/// A thread that leaves root meets Linux's permission checks on the files
/// root laid out, and owns what it makes.
#[test]
fn a_thread_that_is_not_root_is_checked_on_files() {
    let mut f = fixture();
    let put = |f: &mut Fixture, at: u64, path: &[u8]| {
        f.mem.write(GuestAddr(DATA + at), path).unwrap();
        f.mem
            .write(GuestAddr(DATA + at + path.len() as u64), b"\0")
            .unwrap();
        DATA + at
    };
    let closed = put(&mut f, 0, b"/closed");
    let inside = put(&mut f, 0x100, b"/closed/f");
    let link = put(&mut f, 0x200, b"/link");
    let target = put(&mut f, 0x300, b"closed/f");
    let mine = put(&mut f, 0x400, b"/tmp/mine");
    let stat = DATA + 0x1000;
    // As root: a closed directory with a file, and a link into it.
    assert_eq!(f.ret(83, &[closed, 0o700]), 0);
    let fd = f.ret(2, &[inside, 0o101, 0o644]);
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(88, &[target, link]), 0);
    // Executing a file with no execute bit is EACCES even for root.
    assert_eq!(f.ret(59, &[inside, 0, 0]), errno(Errno::EACCES));
    f.thread.state.credentials = f
        .thread
        .state
        .credentials
        .setresuid(1000, 1000, 1000)
        .unwrap();
    assert_eq!(f.ret(4, &[inside, stat]), errno(Errno::EACCES));
    assert_eq!(f.ret(4, &[link, stat]), errno(Errno::EACCES));
    assert_eq!(f.ret(6, &[link, stat]), 0);
    assert_eq!(f.ret(2, &[closed, 0, 0]), errno(Errno::EACCES));
    assert_eq!(f.ret(80, &[closed]), errno(Errno::EACCES));
    assert_eq!(f.ret(87, &[link]), errno(Errno::EACCES));
    assert_eq!(f.ret(90, &[closed, 0o777]), errno(Errno::EPERM));
    assert_eq!(f.ret(21, &[closed, 4]), errno(Errno::EACCES));
    // /tmp is sticky and open to all: a file made there is the thread's,
    // and root's closed directory is not its to remove.
    let fd = f.ret(2, &[mine, 0o101, 0o600]);
    assert_eq!(f.ret(5, &[fd, stat]), 0);
    let mut owner = [0; 8];
    f.mem.read(GuestAddr(stat + 28), &mut owner).unwrap();
    assert_eq!(owner, [0xe8, 3, 0, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(84, &[closed]), errno(Errno::EACCES));
}

/// Landlock through its system calls: rulesets and their errors, then a
/// domain that allows reading and making files only under `/tmp/ll/a`.
#[test]
fn landlock_restricts_access_beneath_its_rules() {
    const READ_FILE: u64 = 1 << 2;
    const WRITE_FILE: u64 = 1 << 1;
    const READ_DIR: u64 = 1 << 3;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13;
    const TRUNCATE: u64 = 1 << 14;
    let mut f = fixture();
    let mut at = DATA + 0x1000;
    let mut text = |f: &mut Fixture, s: &str| {
        let address = at;
        f.mem.write(GuestAddr(address), s.as_bytes()).unwrap();
        f.mem
            .write(GuestAddr(address + s.len() as u64), &[0])
            .unwrap();
        at += s.len() as u64 + 1;
        address
    };
    let tmp = text(&mut f, "/tmp/ll");
    let a = text(&mut f, "/tmp/ll/a");
    let b = text(&mut f, "/tmp/ll/b");
    let af = text(&mut f, "/tmp/ll/a/f");
    let bf = text(&mut f, "/tmp/ll/b/f");
    let ag = text(&mut f, "/tmp/ll/a/g");
    let bg = text(&mut f, "/tmp/ll/b/g");
    let bd = text(&mut f, "/tmp/ll/b/d");
    let bs = text(&mut f, "/tmp/ll/b/s");
    let target = text(&mut f, "x");
    for dir in [tmp, a, b] {
        assert_eq!(f.ret(83, &[dir, 0o755]), 0);
    }
    for file in [af, bf] {
        let fd = f.ret(2, &[file, 0o1101, 0o644]);
        assert_eq!(f.ret(3, &[fd]), 0);
    }
    // The version, and the attribute's checks.
    assert_eq!(f.ret(444, &[0, 0, 1]), 8);
    assert_eq!(f.ret(444, &[0, 0, 2]), 15);
    assert_eq!(f.ret(444, &[0, 0, 4]), errno(Errno::EINVAL));
    assert_eq!(f.ret(444, &[DATA, 8, 1]), errno(Errno::EINVAL));
    assert_eq!(f.ret(444, &[0, 8, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(444, &[DATA, 4, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(444, &[DATA, 4097, 0]), errno(Errno(7)));
    f.mem.write(GuestAddr(DATA), &[0; 32]).unwrap();
    assert_eq!(f.ret(444, &[DATA, 8, 0]), errno(Errno(42)));
    f.mem.write(GuestAddr(DATA + 24), &[1]).unwrap();
    assert_eq!(f.ret(444, &[DATA, 32, 0]), errno(Errno(7)));
    f.mem.write(GuestAddr(DATA + 24), &[0]).unwrap();
    f.mem.write(GuestAddr(DATA + 16), &[4]).unwrap();
    assert_eq!(f.ret(444, &[DATA, 24, 0]), errno(Errno::EINVAL));
    f.mem.write(GuestAddr(DATA + 16), &[0]).unwrap();
    f.mem
        .write(GuestAddr(DATA), &(1u64 << 40).to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(444, &[DATA, 8, 0]), errno(Errno::EINVAL));
    let handled = READ_FILE | WRITE_FILE | READ_DIR | MAKE_REG | MAKE_DIR | MAKE_SYM;
    let handled = handled | REMOVE_FILE | REFER | TRUNCATE;
    f.mem
        .write(GuestAddr(DATA), &handled.to_le_bytes())
        .unwrap();
    f.mem.write(GuestAddr(DATA + 8), &[0; 24]).unwrap();
    let ruleset = f.ret(444, &[DATA, 8, 0]);
    assert!(ruleset < 1024);
    assert_eq!(f.ret(0, &[ruleset, DATA + 64, 1]), errno(Errno::EINVAL));
    // Rules: the descriptor, the type, the rights and the parent.
    let rule = DATA + 0x200;
    let put_rule = |f: &mut Fixture, allowed: u64, parent: u64| {
        f.mem
            .write(GuestAddr(rule), &allowed.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(rule + 8), &(parent as u32).to_le_bytes())
            .unwrap();
    };
    let dir_a = f.ret(2, &[a, 0o10000000, 0]);
    let file_af = f.ret(2, &[af, 0o10000000, 0]);
    put_rule(&mut f, READ_FILE, dir_a);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 1]), errno(Errno::EINVAL));
    assert_eq!(f.ret(445, &[999, 1, rule, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(445, &[dir_a, 1, rule, 0]), errno(Errno(77)));
    assert_eq!(f.ret(445, &[ruleset, 3, rule, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(445, &[ruleset, 1, 0, 0]), errno(Errno::EFAULT));
    put_rule(&mut f, 0, dir_a);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), errno(Errno(42)));
    put_rule(&mut f, 1, dir_a);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), errno(Errno::EINVAL));
    put_rule(&mut f, READ_FILE, 999);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), errno(Errno::EBADF));
    put_rule(&mut f, READ_FILE, ruleset);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), errno(Errno(77)));
    put_rule(&mut f, MAKE_REG, file_af);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), errno(Errno::EINVAL));
    put_rule(&mut f, READ_FILE | WRITE_FILE | READ_DIR | MAKE_REG, dir_a);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), 0);
    put_rule(&mut f, REFER | MAKE_REG | REMOVE_FILE | TRUNCATE, dir_a);
    assert_eq!(f.ret(445, &[ruleset, 1, rule, 0]), 0);
    let before = f.ret(2, &[bf, 1, 0]);
    // Enforcing: flags, then a descriptor that is no ruleset.
    assert_eq!(f.ret(446, &[ruleset, 1 << 4]), errno(Errno::EINVAL));
    // LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF, with or without
    // LANDLOCK_RESTRICT_SELF_TSYNC, needs no ruleset; with another flag, -1
    // is no descriptor.
    assert_eq!(f.ret(446, &[u64::MAX, 4]), 0);
    assert_eq!(f.ret(446, &[u64::MAX, 4 | 8]), 0);
    assert_eq!(f.ret(446, &[u64::MAX, 5]), errno(Errno::EBADF));
    assert_eq!(f.ret(446, &[dir_a, 0]), errno(Errno(77)));
    assert_eq!(f.ret(446, &[ruleset, 0]), 0);
    let eacces = errno(Errno::EACCES);
    let open = |f: &mut Fixture, path: u64, flags: u64| {
        let fd = f.ret(2, &[path, flags, 0o644]);
        if fd < 1024 {
            f.ret(3, &[fd]);
            0
        } else {
            fd
        }
    };
    assert_eq!(open(&mut f, af, 0), 0);
    assert_eq!(open(&mut f, af, 2), 0);
    assert_eq!(open(&mut f, bf, 0), eacces);
    assert_eq!(open(&mut f, bf, 1), eacces);
    assert_eq!(open(&mut f, b, 0o200000), eacces);
    assert_eq!(open(&mut f, bf, 0o10000000), 0);
    assert_eq!(open(&mut f, af, 0o1001), 0);
    assert_eq!(open(&mut f, ag, 0o101), 0);
    assert_eq!(open(&mut f, bg, 0o101), eacces);
    // Truncation: by path, by a descriptor from before and from after.
    assert_eq!(f.ret(76, &[af, 0]), 0);
    assert_eq!(f.ret(76, &[bf, 0]), eacces);
    assert_eq!(f.ret(77, &[before, 0]), 0);
    // Making and removing names.
    assert_eq!(f.ret(83, &[bd, 0o755]), eacces);
    assert_eq!(f.ret(88, &[target, bs]), eacces);
    assert_eq!(f.ret(87, &[bf]), eacces);
    assert_eq!(f.ret(87, &[ag]), 0);
    // b has no rule, so making a name there is missing: EACCES, not EXDEV.
    assert_eq!(f.ret(82, &[af, bg]), eacces);
    assert_eq!(f.ret(86, &[af, bg]), eacces);
    assert_eq!(f.ret(82, &[af, ag]), 0);
    // A second layer narrows the first.
    let second = f.ret(444, &[DATA, 8, 0]);
    put_rule(&mut f, READ_FILE, dir_a);
    f.mem
        .write(GuestAddr(DATA), &READ_FILE.to_le_bytes())
        .unwrap();
    let narrow = f.ret(444, &[DATA, 8, 0]);
    let file_ag = f.ret(2, &[ag, 0o10000000, 0]);
    put_rule(&mut f, READ_FILE, file_ag);
    assert_eq!(f.ret(445, &[narrow, 1, rule, 0]), 0);
    assert_eq!(f.ret(446, &[narrow, 0]), 0);
    assert_eq!(open(&mut f, ag, 0), 0);
    let ah = text(&mut f, "/tmp/ll/a/h");
    assert_eq!(open(&mut f, ah, 0o101), 0);
    assert_eq!(open(&mut f, ah, 0), eacces);
    f.ret(3, &[second]);
}

mod rseq {
    use super::*;

    const SIGNATURE: u64 = 0x5305_3053;

    #[test]
    fn rseq_checks_its_arguments_as_linux_does() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // Nothing to unregister, flags, a length or an alignment Linux refuses.
        assert_eq!(f.ret(334, &[DATA, 32, 1, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA, 32, 2, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA, 31, 0, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA + 16, 32, 0, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA + 16, 64, 0, SIGNATURE]), einval);
        // Past user space, or where nothing is mapped.
        let efault = errno(Errno::EFAULT);
        assert_eq!(
            f.ret(334, &[USER_ADDRESS_LIMIT - 32, 32, 0, SIGNATURE]),
            efault
        );
        assert_eq!(f.ret(334, &[0x40_0000, 32, 0, SIGNATURE]), efault);
        // A registration clears rseq_cs.
        f.mem
            .write(GuestAddr(DATA + 8), &0x1234u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(334, &[DATA, 32, 0, SIGNATURE]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 0);
        assert!(f.thread.state.rseq_notify);
        // Once registered: EBUSY for the same, else what differs.
        assert_eq!(f.ret(334, &[DATA, 32, 0, SIGNATURE]), errno(Errno(16)));
        assert_eq!(f.ret(334, &[DATA + 32, 32, 0, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA, 64, 0, SIGNATURE]), einval);
        assert_eq!(
            f.ret(334, &[DATA, 32, 0, SIGNATURE + 1]),
            errno(Errno::EPERM)
        );
        assert_eq!(
            f.ret(334, &[DATA, 32, 1, SIGNATURE + 1]),
            errno(Errno::EPERM)
        );
        assert_eq!(f.ret(334, &[DATA, 64, 1, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA + 32, 32, 1, SIGNATURE]), einval);
        assert_eq!(f.ret(334, &[DATA, 32, 3, SIGNATURE]), einval);
        // Unregistering leaves the area showing no CPU.
        f.mem.write(GuestAddr(DATA), &[0xff; 32]).unwrap();
        assert_eq!(f.ret(334, &[DATA, 32, 1, SIGNATURE]), 0);
        let mut area = [0; 28];
        f.mem.read(GuestAddr(DATA), &mut area).unwrap();
        assert_eq!(area[..8], [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(area[20..], [0; 8]);
        assert_eq!(f.thread.state.rseq, None);
        assert_eq!(f.ret(334, &[DATA, 32, 1, SIGNATURE]), einval);
    }

    #[test]
    fn a_registered_thread_runs_on_a_virtual_cpu_that_getcpu_reports() {
        let mut f = fixture();
        f.mem.write(GuestAddr(DATA), &[0xff; 32]).unwrap();
        f.mem.write(GuestAddr(DATA + 8), &[0; 8]).unwrap();
        assert_eq!(f.ret(334, &[DATA, 32, 0, SIGNATURE]), 0);
        assert_eq!(f.kernel.enter_cpu(&mut f.thread, &f.mem), Next::Resume);
        let on = f.thread.state.on_cpu.expect("on a CPU");
        assert!(!f.thread.state.rseq_notify);
        let mut area = [0; 28];
        f.mem.read(GuestAddr(DATA), &mut area).unwrap();
        let cpu = on.cpu.to_le_bytes();
        assert_eq!(area[..8], [cpu, cpu].concat()[..]);
        assert_eq!(area[20..], [0, 0, 0, 0, 0, 0, 0, 0]);
        // A system call leaves the CPU; getcpu still reports it.
        assert_eq!(f.ret(nr::GETCPU, &[DATA + 0x100, 0, 0]), 0);
        assert_eq!(
            f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap() as u32,
            on.cpu
        );
        // Taken back, untouched, the CPU is the same and nothing is written.
        f.mem.write(GuestAddr(DATA), &[0xee; 8]).unwrap();
        assert_eq!(f.kernel.enter_cpu(&mut f.thread, &f.mem), Next::Resume);
        assert_eq!(f.thread.state.on_cpu, Some(on));
        assert_eq!(
            f.mem.read_u64(GuestAddr(DATA)).unwrap(),
            u64::MAX / 0xff * 0xee
        );
        // Unregistered, the thread leaves the virtual CPUs.
        assert_eq!(f.ret(334, &[DATA, 32, 1, SIGNATURE]), 0);
        assert_eq!(f.kernel.enter_cpu(&mut f.thread, &f.mem), Next::Resume);
        assert!(f.kernel.seat.is_none() && f.thread.state.on_cpu.is_none());
    }

    #[test]
    fn an_area_the_kernel_cannot_write_sends_sigsegv() {
        let mut f = fixture();
        assert_eq!(f.ret(334, &[DATA, 32, 0, SIGNATURE]), 0);
        f.mem.protect(GuestAddr(DATA), 0x1000, Prot::READ).unwrap();
        assert_eq!(
            f.kernel.enter_cpu(&mut f.thread, &f.mem),
            Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
        );
    }

    #[test]
    fn a_signal_aborts_the_critical_section_before_its_handler_runs() {
        let mut f = fixture();
        // A section at 0x10_1100..0x10_1120 aborting to 0x10_1200.
        let (descriptor, start, abort) = (DATA + 0x40, DATA + 0x1100, DATA + 0x1200);
        let mut bytes = vec![0; 8];
        bytes.extend(start.to_le_bytes());
        bytes.extend(0x20u64.to_le_bytes());
        bytes.extend(abort.to_le_bytes());
        f.mem.write(GuestAddr(descriptor), &bytes).unwrap();
        f.mem
            .write(GuestAddr(abort - 4), &(SIGNATURE as u32).to_le_bytes())
            .unwrap();
        f.mem.write(GuestAddr(DATA + 8), &[0; 8]).unwrap();
        assert_eq!(f.ret(334, &[DATA, 32, 0, SIGNATURE]), 0);
        assert_eq!(f.kernel.enter_cpu(&mut f.thread, &f.mem), Next::Resume);
        f.mem
            .write(GuestAddr(DATA + 8), &descriptor.to_le_bytes())
            .unwrap();
        f.thread.cpu.rip = GuestAddr(start + 8);
        assert!(Kernel::rseq_signal(&mut f.thread, &f.mem));
        assert_eq!(f.thread.cpu.rip, GuestAddr(abort));
        assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 0);
        // A handler runs with the section aborted; with a signature that
        // differs, the thread gets SIGSEGV instead, which a thread with no
        // handler for it dies of.
        f.thread.state.signal_actions.insert(
            10,
            SignalAction {
                handler: 0x10_1300,
                ..SignalAction::default()
            },
        );
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x1800;
        for (signature, next) in [
            (SIGNATURE as u32, Next::Resume),
            (0, Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))),
        ] {
            f.mem
                .write(GuestAddr(DATA + 8), &descriptor.to_le_bytes())
                .unwrap();
            f.mem
                .write(GuestAddr(abort - 4), &signature.to_le_bytes())
                .unwrap();
            f.thread.cpu.rip = GuestAddr(start + 8);
            // As after the first handler returned.
            f.thread.state.signal_mask = 0;
            signals::queue(&mut f.thread.state, signals::PendingSignal::user(10, 0));
            assert_eq!(f.kernel.checkpoint(&mut f.thread, &f.mem), next);
            // Aborted, the section's descriptor is cleared; refused, it stays.
            let cleared = f.mem.read_u64(GuestAddr(DATA + 8)).unwrap() == 0;
            assert_eq!(cleared, next == Next::Resume);
        }
    }
}

mod pkeys {
    use super::*;

    #[test]
    fn pkey_alloc_has_no_key_to_give_as_on_a_cpu_without_them() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // No flag exists; the rights are PKEY_DISABLE_ACCESS and _WRITE.
        assert_eq!(f.ret(330, &[1, 0]), einval);
        assert_eq!(f.ret(330, &[0, 4]), einval);
        assert_eq!(f.ret(330, &[0, 1 << 32]), einval);
        for rights in 0..4 {
            assert_eq!(f.ret(330, &[0, rights]), errno(Errno::ENOSPC));
        }
    }

    #[test]
    fn pkey_free_finds_no_key_allocated_not_even_0() {
        let mut f = fixture();
        for key in [0, 1, 15, 16, u64::MAX] {
            assert_eq!(f.ret(331, &[key]), errno(Errno::EINVAL));
        }
    }

    #[test]
    fn pkey_mprotect_accepts_only_no_key_which_is_mprotect() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // -1 is mprotect: the page becomes read-only, then writable again.
        assert_eq!(f.ret(329, &[DATA, 4096, 1, u64::MAX]), 0);
        assert!(f.mem.write(GuestAddr(DATA), b"x").is_err());
        // Only the low 32 bits are the key.
        assert_eq!(f.ret(329, &[DATA, 4096, 3, u64::from(u32::MAX)]), 0);
        f.mem.write(GuestAddr(DATA), b"x").unwrap();
        // Any other key, the default 0 too, is not allocated.
        for key in [0, 1, 16, (-2i64) as u64] {
            assert_eq!(f.ret(329, &[DATA, 4096, 1, key]), einval);
        }
        f.mem.write(GuestAddr(DATA), b"x").unwrap();
        // What Linux checks first still comes first.
        assert_eq!(f.ret(329, &[DATA + 1, 4096, 1, 0]), einval);
        assert_eq!(f.ret(329, &[DATA, 0, 1, 0]), 0);
        assert_eq!(f.ret(329, &[DATA, 0, 0xff, 0]), 0);
        assert_eq!(f.ret(329, &[DATA, 0, 0x0300_0000, 0]), einval);
        assert_eq!(f.ret(329, &[DATA, u64::MAX, 1, 0]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(329, &[DATA, 0x1000, 0xff, 0]), einval);
    }
}

mod mprotect_order {
    use super::*;

    const GROWSDOWN: u64 = 0x0100_0000;
    const GROWSUP: u64 = 0x0200_0000;

    fn prot_at(f: &Fixture, at: u64) -> Prot {
        f.mem
            .mappings()
            .find(|m| m.start.0 <= at && at < m.end())
            .unwrap()
            .prot
    }

    #[test]
    fn mprotect_checks_in_linux_order() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // An empty range succeeds before the bits are looked at.
        assert_eq!(f.ret(10, &[DATA, 0, 0xff]), 0);
        assert_eq!(f.ret(10, &[DATA + 1, 0, 1]), einval);
        assert_eq!(f.ret(10, &[DATA, 0, GROWSDOWN | GROWSUP]), einval);
        // The end's overflow before the bits.
        assert_eq!(f.ret(10, &[DATA, u64::MAX, 0xff]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(10, &[DATA, 4096, 0x10]), einval);
        assert_eq!(f.ret(10, &[DATA, 4096, 1 | 8]), 0);
        assert_eq!(prot_at(&f, DATA), Prot::READ);
    }

    #[test]
    fn grows_flags_need_a_vma_that_grows() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // No VMA grows up on x86-64; none at all is ENOMEM.
        assert_eq!(f.ret(10, &[DATA, 4096, 1 | GROWSUP]), einval);
        assert_eq!(
            f.ret(10, &[0x50_0000, 4096, 1 | GROWSUP]),
            errno(Errno::ENOMEM)
        );
        // An anonymous mapping does not grow down.
        assert_eq!(f.ret(10, &[DATA, 4096, 1 | GROWSDOWN]), einval);
        assert_eq!(
            f.ret(10, &[0x50_0000, 4096, 1 | GROWSDOWN]),
            errno(Errno::ENOMEM)
        );
        assert_eq!(prot_at(&f, DATA), Prot::READ_WRITE);
        // A stack does: the range reaches down to its start.
        let stack = 0x40_0000;
        f.mem
            .map(
                Some(GuestAddr(stack)),
                0x4000,
                Prot::READ_WRITE,
                MappingKind::Stack,
            )
            .unwrap();
        assert_eq!(f.ret(10, &[stack + 0x2000, 4096, 7 | GROWSDOWN]), 0);
        let all = Prot::from_bits(7).unwrap();
        assert_eq!(prot_at(&f, stack), all);
        assert_eq!(prot_at(&f, stack + 0x2000), all);
        assert_eq!(prot_at(&f, stack + 0x3000), Prot::READ_WRITE);
        // From below it, the first VMA in the range is the one that grows.
        assert_eq!(f.ret(10, &[stack - 0x1000, 0x2000, 3 | GROWSDOWN]), 0);
        assert_eq!(prot_at(&f, stack), Prot::READ_WRITE);
        assert_eq!(prot_at(&f, stack + 0x1000), all);
        // pkey_mprotect with no key is the same.
        assert_eq!(f.ret(329, &[stack, 4096, 1 | GROWSDOWN, u64::MAX]), 0);
        assert_eq!(prot_at(&f, stack), Prot::READ);
    }
}

mod io_uring {
    use super::*;

    const MAP_SHARED: u64 = 1;
    const OFF_SQES: u64 = 0x1000_0000;
    const GETEVENTS: u64 = 1;

    /// A ring of 4 entries with its rings and entries mapped: the
    /// descriptor and where both are.
    struct Ring {
        fd: u64,
        rings: u64,
        sqes: u64,
        array: u64,
    }

    fn params(f: &mut Fixture, flags: u32) -> u64 {
        let p = DATA + 0x1000;
        f.mem.write(GuestAddr(p), &[0; 120]).unwrap();
        f.mem.write(GuestAddr(p + 8), &flags.to_le_bytes()).unwrap();
        p
    }

    fn u32_at(f: &Fixture, at: u64) -> u32 {
        let mut b = [0; 4];
        f.mem.read(GuestAddr(at), &mut b).unwrap();
        u32::from_le_bytes(b)
    }

    fn ring(f: &mut Fixture) -> Ring {
        let p = params(f, 0);
        let fd = f.ret(425, &[4, p]);
        assert!(fd < 1024, "{fd:#x}");
        let array = u64::from(u32_at(f, p + 64));
        let rings = f.ret(9, &[0, array + 16, 3, MAP_SHARED, fd, 0]);
        let sqes = f.ret(9, &[0, 4096, 3, MAP_SHARED, fd, OFF_SQES]);
        Ring {
            fd,
            rings,
            sqes,
            array,
        }
    }

    /// Puts an entry in slot `slot` and moves the tail past it.
    fn push(f: &mut Fixture, r: &Ring, slot: u32, sqe: &[u8; 64]) {
        f.mem
            .write(GuestAddr(r.sqes + 64 * u64::from(slot)), sqe)
            .unwrap();
        f.mem
            .write(
                GuestAddr(r.array + r.rings + 4 * u64::from(slot)),
                &slot.to_le_bytes(),
            )
            .unwrap();
        let tail = u32_at(f, r.rings + 4) + 1;
        f.mem
            .write(GuestAddr(r.rings + 4), &tail.to_le_bytes())
            .unwrap();
    }

    fn sqe(opcode: u8, user_data: u64) -> [u8; 64] {
        let mut sqe = [0; 64];
        sqe[0] = opcode;
        sqe[32..40].copy_from_slice(&user_data.to_le_bytes());
        sqe
    }

    /// The completions not yet consumed, which it consumes.
    fn reap(f: &mut Fixture, r: &Ring) -> Vec<(u64, i32)> {
        let (mut head, tail) = (u32_at(f, r.rings + 8), u32_at(f, r.rings + 12));
        let mut out = Vec::new();
        while head != tail {
            let at = r.rings + 64 + 16 * u64::from(head & 7);
            let mut cqe = [0; 16];
            f.mem.read(GuestAddr(at), &mut cqe).unwrap();
            out.push((
                u64::from_le_bytes(cqe[..8].try_into().unwrap()),
                i32::from_le_bytes(cqe[8..12].try_into().unwrap()),
            ));
            head += 1;
        }
        f.mem
            .write(GuestAddr(r.rings + 8), &head.to_le_bytes())
            .unwrap();
        out
    }

    #[test]
    fn setup_gives_linux_sizes_offsets_and_features() {
        let mut f = fixture();
        let p = params(&mut f, 0);
        let fd = f.ret(425, &[3, p]);
        assert!(fd < 1024);
        assert_eq!((u32_at(&f, p), u32_at(&f, p + 4)), (4, 8));
        assert_eq!(u32_at(&f, p + 20), 0xffff);
        // sq_off: head, tail, ring_mask, ring_entries, flags, dropped, array.
        let sq_off: Vec<u32> = (0..7).map(|i| u32_at(&f, p + 40 + 4 * i)).collect();
        assert_eq!(sq_off, [0, 4, 16, 24, 36, 32, 192]);
        // cq_off: head, tail, ring_mask, ring_entries, overflow, cqes, flags.
        let cq_off: Vec<u32> = (0..7).map(|i| u32_at(&f, p + 80 + 4 * i)).collect();
        assert_eq!(cq_off, [8, 12, 20, 28, 44, 64, 40]);
        // The rings hold the masks and entries.
        let rings = f.ret(9, &[0, 4096, 1, MAP_SHARED, fd, 0]);
        assert_eq!(
            (0..4)
                .map(|i| u32_at(&f, rings + 16 + 4 * i))
                .collect::<Vec<_>>(),
            [3, 7, 4, 8]
        );
        // The descriptor closes on exec and is named as Linux's.
        assert_eq!(f.ret(72, &[fd, 1]), 1);
        // A size the CQ ring gives, clamped, and without the array.
        let p = params(&mut f, 1 << 3 | 1 << 4 | 1 << 16);
        f.mem
            .write(GuestAddr(p + 4), &100_000u32.to_le_bytes())
            .unwrap();
        f.mem.write(GuestAddr(p + 64), &[9, 0, 0, 0]).unwrap();
        let fd = f.ret(425, &[40_000, p]);
        assert!(fd < 1024);
        assert_eq!((u32_at(&f, p), u32_at(&f, p + 4)), (32768, 65536));
        assert_eq!(u32_at(&f, p + 64), 9, "the array offset stays as given");
    }

    #[test]
    fn setup_refuses_what_linux_does_and_what_is_not_implemented() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        let p = params(&mut f, 0);
        assert_eq!(f.ret(425, &[0, p]), einval);
        assert_eq!(f.ret(425, &[32769, p]), einval);
        assert_eq!(f.ret(425, &[4, 0]), errno(Errno::EFAULT));
        f.mem.write(GuestAddr(p + 32), &[1]).unwrap();
        assert_eq!(f.ret(425, &[4, p]), einval);
        // Unknown, and SQPOLL, IOPOLL, SQE128, CQE32 and NO_MMAP.
        for flag in [1 << 17, 1 << 1, 1, 1 << 10, 1 << 11, 1 << 14] {
            let p = params(&mut f, flag);
            assert_eq!(f.ret(425, &[4, p]), einval, "{flag:#x}");
        }
        // TASKRUN_FLAG needs COOP_TASKRUN or DEFER_TASKRUN, which needs
        // SINGLE_ISSUER; a CQ ring smaller than the SQ ring.
        for flags in [1 << 9, 1 << 13] {
            let p = params(&mut f, flags);
            assert_eq!(f.ret(425, &[4, p]), einval);
        }
        let p = params(&mut f, 1 << 3);
        f.mem.write(GuestAddr(p + 4), &2u32.to_le_bytes()).unwrap();
        assert_eq!(f.ret(425, &[4, p]), einval);
    }

    #[test]
    fn mmap_takes_the_offsets_linux_does() {
        let mut f = fixture();
        let p = params(&mut f, 0);
        let fd = f.ret(425, &[4, p]);
        // No address, no other region, no private mapping.
        assert_eq!(
            f.ret(9, &[0x30_0000, 4096, 3, MAP_SHARED, fd, 0]),
            errno(Errno::EINVAL)
        );
        assert_eq!(
            f.ret(9, &[0, 4096, 3, MAP_SHARED, fd, 0x8000_0000]),
            errno(Errno::ENOMEM)
        );
        assert_eq!(f.ret(9, &[0, 4096, 3, 2, fd, 0]), errno(Errno::EINVAL));
        // The CQ ring's offset, or a page into the region, maps the rings.
        let rings = f.ret(9, &[0, 4096, 1, MAP_SHARED, fd, 0x0800_0000]);
        assert_eq!(u32_at(&f, rings + 24), 4);
        let rings = f.ret(9, &[0, 4096, 1, MAP_SHARED, fd, 0x1000]);
        assert_eq!(u32_at(&f, rings + 24), 4);
        // Past the rings' page a mapping raises SIGBUS.
        let wide = f.ret(9, &[0, 8192, 1, MAP_SHARED, fd, 0]);
        let mut b = [0; 1];
        assert!(f.mem.read(GuestAddr(wide + 4096), &mut b).is_err());
    }

    #[test]
    fn enter_runs_nops_and_epoll_ctl() {
        let mut f = fixture();
        let r = ring(&mut f);
        push(&mut f, &r, 0, &sqe(0, 7));
        assert_eq!(f.ret(426, &[r.fd, 1, 1, GETEVENTS]), 1);
        assert_eq!(reap(&mut f, &r), [(7, 0)]);
        assert_eq!(u32_at(&f, r.rings), 1, "the SQ head moved");
        // A NOP that injects its result.
        let mut nop = sqe(0, 8);
        nop[28] = 1;
        nop[24..28].copy_from_slice(&(-5i32).to_le_bytes());
        push(&mut f, &r, 1, &nop);
        assert_eq!(f.ret(426, &[r.fd, 1, 0, 0]), 1);
        assert_eq!(reap(&mut f, &r), [(8, -5)]);
        // EPOLL_CTL_ADD of an eventfd, twice.
        let epfd = f.ret(291, &[0]);
        let efd = f.ret(290, &[0, 0]);
        f.mem.write(GuestAddr(DATA), &[1, 0, 0, 0]).unwrap();
        f.mem
            .write(GuestAddr(DATA + 4), &42u64.to_le_bytes())
            .unwrap();
        let mut ctl = sqe(29, 9);
        ctl[4..8].copy_from_slice(&(epfd as i32).to_le_bytes());
        ctl[8..16].copy_from_slice(&efd.to_le_bytes());
        ctl[16..24].copy_from_slice(&DATA.to_le_bytes());
        ctl[24..28].copy_from_slice(&1u32.to_le_bytes());
        push(&mut f, &r, 2, &ctl);
        push(&mut f, &r, 3, &ctl);
        assert_eq!(f.ret(426, &[r.fd, 2, 2, GETEVENTS]), 2);
        assert_eq!(reap(&mut f, &r), [(9, 0), (9, -17)]);
        // The event's data reaches epoll_wait.
        f.mem
            .write(GuestAddr(DATA + 0x10), &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(1, &[efd, DATA + 0x10, 8]), 8);
        assert_eq!(f.ret(232, &[epfd, DATA + 0x100, 1, 0]), 1);
        let mut out = [0; 12];
        f.mem.read(GuestAddr(DATA + 0x100), &mut out).unwrap();
        assert_eq!(crate::epoll::event_from(&out), (1, 42));
        // A bad event pointer fails its preparation.
        ctl[16..24].copy_from_slice(&8u64.to_le_bytes());
        push(&mut f, &r, 0, &ctl);
        assert_eq!(f.ret(426, &[r.fd, 1, 0, 0]), 1);
        assert_eq!(reap(&mut f, &r), [(9, -14)]);
    }

    #[test]
    fn a_failed_preparation_ends_the_submission_and_links_cancel() {
        let mut f = fixture();
        let r = ring(&mut f);
        // An operation 6.12 lacks, then one it has but is not implemented:
        // each ends the submission after itself.
        push(&mut f, &r, 0, &sqe(200, 1));
        push(&mut f, &r, 1, &sqe(1, 2));
        push(&mut f, &r, 2, &sqe(0, 3));
        assert_eq!(f.ret(426, &[r.fd, 3, 0, 0]), 1);
        assert_eq!(f.ret(426, &[r.fd, 2, 0, 0]), 1);
        assert_eq!(f.ret(426, &[r.fd, 1, 0, 0]), 1);
        assert_eq!(reap(&mut f, &r), [(1, -22), (2, -95), (3, 0)]);
        // A soft link: a failure cancels the rest; a hard one goes on.
        let mut fail = sqe(0, 4);
        fail[1] = 1 << 2;
        fail[28] = 1;
        fail[24..28].copy_from_slice(&(-1i32).to_le_bytes());
        push(&mut f, &r, 3, &fail);
        push(&mut f, &r, 0, &sqe(0, 5));
        assert_eq!(f.ret(426, &[r.fd, 2, 0, 0]), 2);
        assert_eq!(reap(&mut f, &r), [(4, -1), (5, -125)]);
        fail[1] = 1 << 3;
        push(&mut f, &r, 1, &fail);
        push(&mut f, &r, 2, &sqe(0, 6));
        assert_eq!(f.ret(426, &[r.fd, 2, 0, 0]), 2);
        assert_eq!(reap(&mut f, &r), [(4, -1), (6, 0)]);
        // A link member that fails to prepare fails the link, which goes on.
        let mut first = sqe(0, 7);
        first[1] = 1 << 2;
        let mut bad = sqe(200, 8);
        bad[1] = 1 << 2;
        push(&mut f, &r, 3, &first);
        push(&mut f, &r, 0, &bad);
        push(&mut f, &r, 1, &sqe(0, 9));
        assert_eq!(f.ret(426, &[r.fd, 3, 0, 0]), 3);
        assert_eq!(reap(&mut f, &r), [(7, -125), (8, -22), (9, -125)]);
        // A success that skips its completion.
        let mut skip = sqe(0, 10);
        skip[1] = 1 << 6;
        push(&mut f, &r, 2, &skip);
        assert_eq!(f.ret(426, &[r.fd, 1, 0, 0]), 1);
        assert_eq!(reap(&mut f, &r), []);
        // An index past the entries is dropped and ends the submission.
        f.mem
            .write(GuestAddr(r.array + r.rings + 12), &9u32.to_le_bytes())
            .unwrap();
        let tail = u32_at(&f, r.rings + 4) + 1;
        f.mem
            .write(GuestAddr(r.rings + 4), &tail.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(426, &[r.fd, 1, 0, 0]), 0);
        assert_eq!(u32_at(&f, r.rings + 32), 1, "sq_dropped");
    }

    #[test]
    fn a_full_completion_queue_keeps_completions_in_order() {
        let mut f = fixture();
        let r = ring(&mut f);
        // 12 NOPs for a queue of 8: four wait in the kernel.
        for round in 0..3u64 {
            for slot in 0..4 {
                push(&mut f, &r, slot, &sqe(0, round * 4 + u64::from(slot)));
            }
            assert_eq!(f.ret(426, &[r.fd, 4, 0, 0]), 4);
        }
        assert_eq!(u32_at(&f, r.rings + 36) & 2, 2, "IORING_SQ_CQ_OVERFLOW");
        let first: Vec<u64> = reap(&mut f, &r).into_iter().map(|(u, _)| u).collect();
        assert_eq!(first, (0..8).collect::<Vec<_>>());
        // A wait moves them in.
        assert_eq!(f.ret(426, &[r.fd, 0, 1, GETEVENTS]), 0);
        let rest: Vec<u64> = reap(&mut f, &r).into_iter().map(|(u, _)| u).collect();
        assert_eq!(rest, (8..12).collect::<Vec<_>>());
        assert_eq!(u32_at(&f, r.rings + 36) & 2, 0);
    }

    #[test]
    fn enter_and_register_check_their_arguments() {
        let mut f = fixture();
        let r = ring(&mut f);
        assert_eq!(f.ret(426, &[r.fd, 0, 0, 1 << 6]), errno(Errno::EINVAL));
        assert_eq!(f.ret(426, &[99, 0, 0, 0]), errno(Errno::EBADF));
        assert_eq!(f.ret(426, &[0, 0, 0, 0]), errno(Errno(95)));
        assert_eq!(f.ret(426, &[3, 0, 0, 1 << 4]), errno(Errno::EBADF));
        assert_eq!(f.ret(426, &[16, 0, 0, 1 << 4]), errno(Errno::EINVAL));
        // Nothing to submit gives 0 and skips the wait.
        assert_eq!(f.ret(426, &[r.fd, 4, 1, GETEVENTS]), 0);
        // A wait with a timeout ends with ETIME; a bad argument size EINVAL.
        let ts = DATA + 0x200;
        f.mem.write(GuestAddr(ts), &[0; 16]).unwrap();
        f.mem
            .write(GuestAddr(ts + 8), &1_000_000u64.to_le_bytes())
            .unwrap();
        let arg = DATA + 0x300;
        f.mem.write(GuestAddr(arg), &[0; 24]).unwrap();
        f.mem.write(GuestAddr(arg + 16), &ts.to_le_bytes()).unwrap();
        assert_eq!(
            f.ret(426, &[r.fd, 0, 1, GETEVENTS | 1 << 3, arg, 24]),
            errno(Errno(62))
        );
        assert_eq!(
            f.ret(426, &[r.fd, 0, 1, GETEVENTS | 1 << 3, arg, 16]),
            errno(Errno::EINVAL)
        );
        // The probe: NOP and EPOLL_CTL only, of 58 operations.
        let probe = DATA + 0x400;
        f.mem.write(GuestAddr(probe), &[0; 16 + 8 * 64]).unwrap();
        assert_eq!(f.ret(427, &[r.fd, 8, probe, 64]), 0);
        let mut head = [0; 2];
        f.mem.read(GuestAddr(probe), &mut head).unwrap();
        assert_eq!(head, [57, 58]);
        let supported: Vec<u64> = (0..58)
            .filter(|op| u32_at(&f, probe + 16 + 8 * op) >> 16 & 1 == 1)
            .collect();
        assert_eq!(supported, [0, 29]);
        // A probe that is not zeroed, another operation, another file.
        assert_eq!(f.ret(427, &[r.fd, 8, probe, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 0, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 31, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[0, 8, probe, 1]), errno(Errno(95)));
    }
}

mod multiple_messages {
    use super::*;
    const RECVMMSG: u64 = 299;
    const SENDMMSG: u64 = 307;
    /// `count` mmsghdrs at `at`, each with one iovec of `len` bytes at
    /// `buffers + 0x10 * i`; the iovecs are at `at + 0x800`.
    fn vector(f: &Fixture, at: u64, buffers: u64, count: u64, len: u64) {
        for i in 0..count {
            let entry = at + 64 * i;
            let iov = at + 0x100 + 16 * i;
            for offset in (0..64).step_by(8) {
                f.mem.write_u64(GuestAddr(entry + offset), 0).unwrap();
            }
            f.mem.write_u64(GuestAddr(entry + 16), iov).unwrap();
            f.mem.write_u64(GuestAddr(entry + 24), 1).unwrap();
            f.mem.write_u64(GuestAddr(iov), buffers + 0x10 * i).unwrap();
            f.mem.write_u64(GuestAddr(iov + 8), len).unwrap();
        }
    }
    fn msg_len(f: &Fixture, at: u64, i: u64) -> u32 {
        (f.mem.read_u64(GuestAddr(at + 64 * i + 56)).unwrap() & 0xffff_ffff) as u32
    }
    fn datagram_pair(f: &mut Fixture) -> (u64, u64) {
        assert_eq!(f.ret(53, &[1, 2, 0, DATA + 0x100]), 0);
        let fds = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap();
        (fds & 0xffff_ffff, fds >> 32)
    }
    #[test]
    fn sendmmsg_and_recvmmsg_move_one_datagram_per_entry() {
        let mut f = fixture();
        let (a, b) = datagram_pair(&mut f);
        let (send, receive, out, into) = (DATA + 0x400, DATA + 0x800, DATA + 0x600, DATA + 0xa00);
        for i in 0..3 {
            f.mem
                .write(GuestAddr(out + 0x10 * i), &[b'a' + i as u8; 5])
                .unwrap();
        }
        vector(&f, send, out, 3, 5);
        assert_eq!(f.ret(SENDMMSG, &[a, send, 3, 0]), 3);
        assert_eq!([0, 1, 2].map(|i| msg_len(&f, send, i)), [5, 5, 5]);
        // Four asked, three there: MSG_DONTWAIT stops at the empty queue.
        vector(&f, receive, into, 4, 8);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 4, 0x40, 0]), 3);
        assert_eq!([0, 1, 2].map(|i| msg_len(&f, receive, i)), [5, 5, 5]);
        let mut got = [0; 5];
        f.mem.read(GuestAddr(into + 0x20), &mut got).unwrap();
        assert_eq!(&got, b"ccccc");
        // MSG_WAITFORONE waits only for the first.
        assert_eq!(f.ret(SENDMMSG, &[a, send, 2, 0]), 2);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 4, 0x10000, 0]), 2);
        // Nothing asked is nothing done, on a socket.
        assert_eq!(f.ret(SENDMMSG, &[a, send, 0, 0]), 0);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 0, 0, 0]), 0);
        // vlen is an unsigned int.
        assert_eq!(f.ret(SENDMMSG, &[a, send, (1 << 32) | 1, 0]), 1);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 4, 0x40, 0]), 1);
    }
    #[test]
    fn they_check_as_linux_does() {
        let mut f = fixture();
        let (a, b) = datagram_pair(&mut f);
        let (vec, timeout) = (DATA + 0x400, DATA + 0xc00);
        vector(&f, vec, DATA + 0x600, 2, 4);
        // MSG_CMSG_COMPAT first, then (recvmmsg) the timeout, then the
        // descriptor.
        assert_eq!(
            f.ret(SENDMMSG, &[99, vec, 1, 0x8000_0000]),
            errno(Errno::EINVAL)
        );
        assert_eq!(
            f.ret(RECVMMSG, &[99, vec, 1, 0x8000_0000, 0]),
            errno(Errno::EINVAL)
        );
        assert_eq!(f.ret(RECVMMSG, &[99, vec, 1, 0, 8]), errno(Errno::EFAULT));
        f.mem.write_u64(GuestAddr(timeout), 0).unwrap();
        f.mem
            .write_u64(GuestAddr(timeout + 8), 1_000_000_000)
            .unwrap();
        assert_eq!(
            f.ret(RECVMMSG, &[99, vec, 1, 0, timeout]),
            errno(Errno::EINVAL)
        );
        assert_eq!(f.ret(SENDMMSG, &[99, vec, 0, 0]), errno(Errno::EBADF));
        assert_eq!(f.ret(293, &[DATA + 0x100, 0]), 0);
        let pipe = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap() & 0xffff_ffff;
        assert_eq!(f.ret(SENDMMSG, &[pipe, vec, 0, 0]), errno(Errno(88)));
        assert_eq!(f.ret(RECVMMSG, &[pipe, vec, 0, 0, 0]), errno(Errno(88)));
        // An error after a message is not given: the count is.
        f.mem.write_u64(GuestAddr(vec + 64 + 16), 8).unwrap(); // a bad iovec
        assert_eq!(f.ret(SENDMMSG, &[a, vec, 2, 0]), 1);
        assert_eq!(f.ret(SENDMMSG, &[a, vec + 64, 1, 0]), errno(Errno::EFAULT));
        // The time left is written back once a message came.
        f.mem.write_u64(GuestAddr(timeout), 5).unwrap();
        f.mem.write_u64(GuestAddr(timeout + 8), 0).unwrap();
        vector(&f, vec, DATA + 0x600, 2, 4);
        assert_eq!(f.ret(RECVMMSG, &[b, vec, 2, 0x40, timeout]), 1);
        let left = f.mem.read_u64(GuestAddr(timeout)).unwrap() * 1_000_000_000
            + f.mem.read_u64(GuestAddr(timeout + 8)).unwrap();
        assert!(left <= 5_000_000_000 && left > 0, "{left}");
        // With none there, the error is given.
        assert_eq!(f.ret(RECVMMSG, &[b, vec, 2, 0x40, 0]), errno(Errno::EAGAIN));
    }
}

mod old_time_calls {
    use super::*;
    /// The modification time (`st_mtime`, `st_mtime_nsec`) of `path`, from
    /// `stat`, which reports no other.
    fn times(f: &mut Fixture, path: u64) -> [u64; 2] {
        let at = DATA + 0x800;
        assert_eq!(f.ret(4, &[path, at]), 0);
        [88, 96].map(|offset| f.mem.read_u64(GuestAddr(at + offset)).unwrap())
    }
    #[test]
    fn utime_utimes_and_futimesat_set_the_times_as_utimensat() {
        let mut f = fixture();
        let (path, tv) = (DATA, DATA + 0x100);
        f.mem.write(GuestAddr(path), b"/t\0").unwrap();
        let fd = f.ret(2, &[path, 0o102, 0o600]);
        // utimes: microseconds.
        for (i, word) in [10, 5, 20, 7].into_iter().enumerate() {
            f.mem.write_u64(GuestAddr(tv + 8 * i as u64), word).unwrap();
        }
        assert_eq!(f.ret(235, &[path, tv]), 0);
        assert_eq!(times(&mut f, path), [20, 7000]);
        // futimesat with a null path sets the descriptor's.
        f.mem.write_u64(GuestAddr(tv + 16), 30).unwrap();
        assert_eq!(f.ret(261, &[fd, 0, tv]), 0);
        assert_eq!(times(&mut f, path), [30, 7000]);
        // futimesat from a directory.
        f.mem.write(GuestAddr(path + 0x40), b"t\0").unwrap();
        f.mem.write(GuestAddr(path + 0x50), b"/\0").unwrap();
        let root = f.ret(2, &[path + 0x50, 0o200000, 0]);
        f.mem.write_u64(GuestAddr(tv + 16), 40).unwrap();
        assert_eq!(f.ret(261, &[root, path + 0x40, tv]), 0);
        assert_eq!(times(&mut f, path)[0], 40);
        // utime: whole seconds.
        f.mem.write_u64(GuestAddr(tv), 50).unwrap();
        f.mem.write_u64(GuestAddr(tv + 8), 60).unwrap();
        assert_eq!(f.ret(132, &[path, tv]), 0);
        assert_eq!(times(&mut f, path), [60, 0]);
        // No times is now.
        f.host
            .set_clock(paludarium_host::ClockId::Realtime, 70_000_000_123);
        assert_eq!(f.ret(132, &[path, 0]), 0);
        assert_eq!(times(&mut f, path), [70, 123]);
        assert_eq!(f.ret(235, &[path, 0]), 0);
    }
    #[test]
    fn they_check_as_linux_does() {
        let mut f = fixture();
        let (path, tv) = (DATA, DATA + 0x100);
        f.mem.write(GuestAddr(path), b"/t\0").unwrap();
        f.ret(2, &[path, 0o102, 0o600]);
        assert_eq!(f.ret(235, &[path, 8]), errno(Errno::EFAULT));
        assert_eq!(f.ret(132, &[path, 8]), errno(Errno::EFAULT));
        // Microseconds of a million or more (UTIME_NOW among them) or negative.
        for micros in [1_000_000, (1 << 30) - 1, u64::MAX] {
            for (i, word) in [1, micros, 1, 0].into_iter().enumerate() {
                f.mem.write_u64(GuestAddr(tv + 8 * i as u64), word).unwrap();
            }
            assert_eq!(f.ret(235, &[path, tv]), errno(Errno::EINVAL));
            assert_eq!(f.ret(261, &[99, path, tv]), errno(Errno::EINVAL));
        }
        // The times are checked before the path.
        assert_eq!(f.ret(235, &[0, tv]), errno(Errno::EINVAL));
        f.mem.write_u64(GuestAddr(tv + 8), 0).unwrap();
        assert_eq!(f.ret(235, &[0, tv]), errno(Errno::EFAULT));
        f.mem.write(GuestAddr(path + 0x40), b"/missing\0").unwrap();
        assert_eq!(f.ret(132, &[path + 0x40, 0]), errno(Errno::ENOENT));
        assert_eq!(f.ret(261, &[99, 0, tv]), errno(Errno::EBADF));
    }
    #[test]
    fn syncfs_and_readahead_check_their_descriptor() {
        let mut f = fixture();
        f.mem.write(GuestAddr(DATA), b"/t\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        assert_eq!(f.ret(306, &[fd]), 0);
        assert_eq!(f.ret(306, &[99]), errno(Errno::EBADF));
        let path_only = f.ret(2, &[DATA, 0o10000000, 0]);
        assert_eq!(f.ret(306, &[path_only]), errno(Errno::EBADF));
        assert_eq!(f.ret(187, &[fd, 0, 4096]), 0);
        assert_eq!(f.ret(187, &[fd, -1i64 as u64, 4096]), 0);
        assert_eq!(f.ret(187, &[fd, 0, u64::MAX]), errno(Errno::EINVAL));
        assert_eq!(f.ret(187, &[path_only, 0, 1]), errno(Errno::EBADF));
        let write_only = f.ret(2, &[DATA, 0o1, 0]);
        assert_eq!(f.ret(187, &[write_only, 0, 1]), errno(Errno::EBADF));
        assert_eq!(f.ret(293, &[DATA + 0x100, 0]), 0);
        let pipe = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap() & 0xffff_ffff;
        assert_eq!(f.ret(187, &[pipe, 0, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(187, &[99, 0, 1]), errno(Errno::EBADF));
    }
}
