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
            present: true,
            poison: false,
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
    // A refused segment load: #GP is SIGSEGV, #NP and #SS SIGBUS.
    for (trap, number) in [
        (13, signal::SIGSEGV),
        (11, signal::SIGBUS),
        (12, signal::SIGBUS),
    ] {
        assert_eq!(
            handle(ExitReason::SegmentFault {
                rip,
                trap,
                error: 0x14
            }),
            Next::Exit(ExitStatus::Signaled(number))
        );
    }
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
        let mut f = fixture();
        assert_eq!(
            f.kernel.handle(
                &mut f.thread,
                &f.mem,
                ExitReason::MathFault {
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
    // A selector loaded from the LDT is nulled, as Linux's loadseg(FS, 0).
    f.thread.cpu.segments[paludarium_cpu::segments::FS] = 0xf;
    f.thread.cpu.segments[paludarium_cpu::segments::GS] = 0xf;
    assert_eq!(f.ret(nr::ARCH_PRCTL, &[0x1002, 0x7000_0000]), 0);
    assert_eq!(f.thread.cpu.fs_base, 0x7000_0000);
    assert_eq!(f.thread.cpu.segments[paludarium_cpu::segments::FS], 0);
    assert_eq!(f.thread.cpu.segments[paludarium_cpu::segments::GS], 0xf);
    assert_eq!(f.ret(nr::ARCH_PRCTL, &[0x1001, 0x7000_1000]), 0);
    assert_eq!(f.thread.cpu.segments[paludarium_cpu::segments::GS], 0);
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
fn splice_tee_and_vmsplice_move_bytes_through_pipes() {
    let mut f = fixture();
    let (pipes, buf, offset, iov) = (DATA + 0x100, DATA + 0x200, DATA + 0x300, DATA + 0x400);
    f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
    f.mem.write(GuestAddr(buf), b"0123456789").unwrap();
    let file = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[file, buf, 10]), 10);
    let pipe = |f: &mut Fixture, at: u64| {
        assert_eq!(f.ret(22, &[at]), 0);
        let fds = f.mem.read_u64(GuestAddr(at)).unwrap();
        (fds & 0xffff_ffff, fds >> 32)
    };
    let (r, w) = pipe(&mut f, pipes);
    let (r2, w2) = pipe(&mut f, pipes + 8);
    // A file at an offset into a pipe; tee leaves it there, splice takes it.
    f.mem.write_u64(GuestAddr(offset), 2).unwrap();
    assert_eq!(f.ret(275, &[file, offset, w, 0, 5, 0]), 5);
    assert_eq!(f.mem.read_u64(GuestAddr(offset)).unwrap(), 7);
    assert_eq!(f.ret(276, &[r, w2, 100, 0]), 5);
    assert_eq!(f.ret(275, &[r, 0, w2, 0, 100, 0]), 5);
    assert_eq!(f.ret(275, &[r, 0, w2, 0, 100, 2]), errno(Errno::EAGAIN));
    // vmsplice gives a pipe's bytes to the guest, and takes the guest's.
    f.mem.write_u64(GuestAddr(iov), buf + 0x40).unwrap();
    f.mem.write_u64(GuestAddr(iov + 8), 16).unwrap();
    assert_eq!(f.ret(278, &[r2, iov, 1, 0]), 10);
    let mut out = [0; 10];
    f.mem.read(GuestAddr(buf + 0x40), &mut out).unwrap();
    assert_eq!(&out, b"2345623456");
    f.mem.write(GuestAddr(buf), b"xyz").unwrap();
    f.mem.write_u64(GuestAddr(iov), buf).unwrap();
    f.mem.write_u64(GuestAddr(iov + 8), 3).unwrap();
    assert_eq!(f.ret(278, &[w, iov, 1, 0]), 3);
    // A pipe into the file at its position, which moves on.
    assert_eq!(f.ret(8, &[file, 1, 0]), 1);
    assert_eq!(f.ret(275, &[r, 0, file, 0, 100, 0]), 3);
    assert_eq!(f.ret(8, &[file, 0, 1]), 4);
    assert_eq!(f.ret(17, &[file, buf + 0x40, 5, 0]), 5);
    f.mem.read(GuestAddr(buf + 0x40), &mut out[..5]).unwrap();
    assert_eq!(&out[..5], b"0xyz4");
    // The checks: two ends of one pipe, an offset for a pipe, no pipe.
    assert_eq!(f.ret(275, &[r, 0, w, 0, 1, 0]), errno(Errno::EINVAL));
    assert_eq!(
        f.ret(275, &[r, offset, file, 0, 1, 0]),
        errno(Errno::ESPIPE)
    );
    assert_eq!(f.ret(275, &[file, 0, file, 0, 1, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(276, &[file, w, 1, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(278, &[file, iov, 1, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(275, &[w, 0, file, 0, 1, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(275, &[99, 0, 99, 0, 0, 0]), 0);
    // A pipe no one reads: EPIPE, with SIGPIPE (blocked).
    f.mem.write_u64(GuestAddr(iov), 1 << 12).unwrap();
    assert_eq!(f.ret(14, &[0, iov, 0, 8]), 0);
    assert_eq!(f.ret(3, &[r2]), 0);
    assert_eq!(f.ret(275, &[file, offset, w2, 0, 1, 0]), errno(Errno(32)));
    assert!(f.thread.state.pending.iter().any(|s| s.number == 13));
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
    // STATX_MNT_ID_UNIQUE asked for gives the unique ID in its place: the
    // root's, the first after the mount below it.
    assert_eq!(f.ret(332, &[fd, 0, 0x1000, 0x4000, out]), 0);
    assert_eq!(word(&f, 0) as u32, 0x47ff);
    assert_eq!(word(&f, 144), paludarium_vfs::UNIQUE_OFFSET + 2);
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
    // The file's access is not asked of security.*, but CAP_SYS_ADMIN is
    // of a change (`cap_inode_setxattr`).
    assert_eq!(f.ret(188, &[path, security, buffer, 1, 0]), eperm);
    assert_eq!(f.ret(197, &[path, security]), eperm);
    // The list hides what cannot be read.
    assert_eq!(f.ret(194, &[path, 0, 0]), 18);
}

#[test]
fn file_capabilities_are_checked_converted_and_killed_as_linux_does() {
    let mut f = fixture();
    let (path, caps, value, out) = (DATA + 0x100, DATA + 0x200, DATA + 0x300, DATA + 0x400);
    f.mem.write(GuestAddr(path), b"/caps-file\0").unwrap();
    f.mem
        .write(GuestAddr(caps), b"security.capability\0")
        .unwrap();
    let fd = f.ret(2, &[path, 0o102, 0o755]);
    assert!(fd < 1024, "{fd}");
    let einval = errno(Errno::EINVAL);
    // magic, then permitted and inheritable twice, then a v3's root.
    let cap = |f: &mut Fixture, revision: u32, root: u32| {
        let mut v = (revision | 1).to_le_bytes().to_vec();
        v.extend_from_slice(&(1u32 << 10).to_le_bytes());
        v.extend_from_slice(&[0; 12]);
        if revision == 0x0300_0000 {
            v.extend_from_slice(&root.to_le_bytes());
        }
        f.mem.write(GuestAddr(value), &v).unwrap();
        v.len() as u64
    };
    let read = |f: &mut Fixture| -> (u64, u32) {
        let n = f.ret(191, &[path, caps, out, 64]);
        let mut magic = [0; 4];
        f.mem.read(GuestAddr(out), &mut magic).unwrap();
        (n, u32::from_le_bytes(magic))
    };
    // Neither revision 2 nor 3, or not of its size.
    let n = cap(&mut f, 0x0100_0000, 0);
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), einval);
    let n = cap(&mut f, 0x0200_0000, 0);
    assert_eq!(f.ret(188, &[path, caps, value, n + 1, 0]), einval);
    // Root of the first namespace keeps a revision 2 value.
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), 0);
    assert_eq!(read(&mut f), (20, 0x0200_0001));
    // A revision 3 value of root reads as revision 2 for root, one of
    // another root as itself; too small a buffer is ERANGE.
    let n = cap(&mut f, 0x0300_0000, 0);
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), 0);
    assert_eq!(read(&mut f), (20, 0x0200_0001));
    let n = cap(&mut f, 0x0300_0000, 1000);
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), 0);
    assert_eq!(read(&mut f), (24, 0x0300_0001));
    assert_eq!(f.ret(191, &[path, caps, out, 20]), errno(Errno(34)));
    assert_eq!(f.ret(191, &[path, caps, 0, 0]), 24);
    // A write takes them away, and so does a chown that changes nothing.
    f.mem.write(GuestAddr(out), b"x").unwrap();
    assert_eq!(f.ret(1, &[fd, out, 1]), 1);
    assert_eq!(f.ret(191, &[path, caps, 0, 0]), errno(Errno(61)));
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), 0);
    assert_eq!(f.ret(92, &[path, u64::MAX, u64::MAX]), 0);
    assert_eq!(f.ret(191, &[path, caps, 0, 0]), errno(Errno(61)));
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), 0);
    // Without CAP_SETFCAP neither a change nor a removal; anyone reads them,
    // whatever the file's access.
    assert_eq!(f.ret(90, &[path, 0]), 0);
    assert_eq!(f.ret(nr::SETUID, &[1000]), 0);
    assert_eq!(f.ret(188, &[path, caps, value, n, 0]), errno(Errno::EPERM));
    assert_eq!(f.ret(197, &[path, caps]), errno(Errno::EPERM));
    assert_eq!(read(&mut f), (24, 0x0300_0001));
}

#[test]
fn only_its_owner_changes_the_user_attributes_of_a_sticky_directory() {
    let mut f = fixture();
    let (path, name, value) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
    f.mem.write(GuestAddr(path), b"/sticky\0").unwrap();
    f.mem.write(GuestAddr(name), b"user.a\0").unwrap();
    assert_eq!(f.ret(83, &[path, 0o1777]), 0);
    assert_eq!(f.ret(90, &[path, 0o1777]), 0);
    assert_eq!(f.ret(188, &[path, name, value, 1, 0]), 0);
    assert_eq!(f.ret(nr::SETUID, &[1000]), 0);
    // It may write the directory, but not its attributes; it reads them.
    assert_eq!(f.ret(188, &[path, name, value, 1, 0]), errno(Errno::EPERM));
    assert_eq!(f.ret(197, &[path, name]), errno(Errno::EPERM));
    assert_eq!(f.ret(191, &[path, name, 0, 0]), 1);
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
fn xattrat_calls_take_a_directory_flags_and_struct_xattr_args() {
    let mut f = fixture();
    let (dir, file, name, value, args, out) = (
        DATA + 0x100,
        DATA + 0x140,
        DATA + 0x180,
        DATA + 0x1c0,
        DATA + 0x200,
        DATA + 0x800,
    );
    let (einval, ebadf, e2big) = (errno(Errno::EINVAL), errno(Errno::EBADF), errno(Errno(7)));
    let (efault, erange) = (errno(Errno::EFAULT), errno(Errno(34)));
    f.mem.write(GuestAddr(dir), b"/\0").unwrap();
    f.mem.write(GuestAddr(file), b"xattrat-file\0").unwrap();
    f.mem.write(GuestAddr(name), b"user.k\0").unwrap();
    f.mem.write(GuestAddr(value), b"abc").unwrap();
    let set_args = |f: &mut Fixture, value: u64, size: u32, flags: u32| {
        f.mem.write_u64(GuestAddr(args), value).unwrap();
        f.mem
            .write(GuestAddr(args + 8), &size.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(args + 12), &flags.to_le_bytes())
            .unwrap();
    };
    let root = f.ret(2, &[dir, 0o200000, 0]);
    let path_fd = f.ret(2, &[dir, 0o10000000, 0]);
    let fd = f.ret(257, &[root, file, 0o102, 0o644]);
    assert!(fd < 1024, "{fd}");

    // setxattrat from a directory descriptor, and getxattrat back.
    set_args(&mut f, value, 3, 0);
    assert_eq!(f.ret(463, &[root, file, 0, name, args, 16]), 0);
    set_args(&mut f, out, 16, 0);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 16]), 3);
    let mut got = [0; 3];
    f.mem.read(GuestAddr(out), &mut got).unwrap();
    assert_eq!(&got, b"abc");
    // A larger struct is fine if what it adds is zero.
    f.mem.write_u64(GuestAddr(args + 16), 0).unwrap();
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 24]), 3);
    f.mem.write_u64(GuestAddr(args + 16), 1).unwrap();
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 24]), e2big);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 15]), einval);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 4097]), e2big);
    assert_eq!(f.ret(464, &[root, file, 0, name, 0, 16]), efault);
    // getxattrat takes no flags; neither call takes other at_flags.
    set_args(&mut f, out, 16, 1);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 16]), einval);
    set_args(&mut f, value, 3, 4);
    assert_eq!(f.ret(463, &[root, file, 0, name, args, 16]), einval);
    set_args(&mut f, out, 16, 0);
    assert_eq!(f.ret(464, &[root, file, 0x400, name, args, 16]), einval);
    assert_eq!(f.ret(465, &[root, file, 0x400, 0, 0]), einval);
    assert_eq!(f.ret(466, &[root, file, 0x400, name]), einval);
    // A size of 0 asks for the length only.
    set_args(&mut f, out, 0, 0);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 16]), 3);
    set_args(&mut f, out, 2, 0);
    assert_eq!(f.ret(464, &[root, file, 0, name, args, 16]), erange);

    // AT_EMPTY_PATH: a null or empty path is the descriptor's file.
    set_args(&mut f, out, 16, 0);
    assert_eq!(f.ret(464, &[fd, 0, 0x1000, name, args, 16]), 3);
    f.mem.write(GuestAddr(DATA + 0x300), b"\0").unwrap();
    assert_eq!(f.ret(465, &[fd, DATA + 0x300, 0x1000, out, 64]), 7);
    // Without it, an empty path is ENOENT.
    assert_eq!(
        f.ret(465, &[fd, DATA + 0x300, 0, out, 64]),
        errno(Errno::ENOENT)
    );
    // An O_PATH descriptor names no file this way, but walks from one do.
    assert_eq!(f.ret(465, &[path_fd, 0, 0x1000, out, 64]), ebadf);
    assert_eq!(f.ret(465, &[path_fd, file, 0, out, 64]), 7);
    // AT_FDCWD with an empty path: the working directory for set and get,
    // EBADF for list and remove.
    assert_eq!(
        f.ret(464, &[(-100i64) as u64, 0, 0x1000, name, args, 16]),
        errno(Errno(61))
    );
    assert_eq!(f.ret(465, &[(-100i64) as u64, 0, 0x1000, out, 64]), ebadf);
    assert_eq!(f.ret(466, &[(-100i64) as u64, 0, 0x1000, name]), ebadf);
    assert_eq!(
        f.ret(464, &[(-1i64) as u64, 0, 0x1000, name, args, 16]),
        ebadf
    );

    // The name is read before the file is found.
    f.mem.write(GuestAddr(DATA + 0x340), b"\0").unwrap();
    assert_eq!(
        f.ret(466, &[(-1i64) as u64, 0, 0x1000, DATA + 0x340]),
        erange
    );
    assert_eq!(f.ret(193, &[999, DATA + 0x340, 0, 0]), erange);
    assert_eq!(f.ret(199, &[999, name]), ebadf);

    // removexattrat, then it is gone.
    assert_eq!(f.ret(466, &[root, file, 0, name]), 0);
    assert_eq!(f.ret(466, &[root, file, 0, name]), errno(Errno(61)));
    assert_eq!(f.ret(465, &[root, file, 0, out, 64]), 0);
}

#[test]
fn inode_flags_read_back_and_refuse_what_linux_refuses() {
    let mut f = fixture();
    let (file, dir, inner, other, attr, out) = (
        DATA + 0x100,
        DATA + 0x140,
        DATA + 0x180,
        DATA + 0x1c0,
        DATA + 0x400,
        DATA + 0x800,
    );
    let (eperm, einval, eopnotsupp) = (
        errno(Errno::EPERM),
        errno(Errno::EINVAL),
        errno(Errno::EOPNOTSUPP),
    );
    f.mem.write(GuestAddr(file), b"/flags-file\0").unwrap();
    f.mem.write(GuestAddr(dir), b"/flags-dir\0").unwrap();
    f.mem
        .write(GuestAddr(inner), b"/flags-dir/inner\0")
        .unwrap();
    f.mem.write(GuestAddr(other), b"/flags-other\0").unwrap();
    // struct file_attr: xflags, extsize, nextents, projid, cowextsize.
    let set_attr = |f: &mut Fixture, xflags: u64, extsize: u32, projid: u32| {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&xflags.to_le_bytes());
        b[8..12].copy_from_slice(&extsize.to_le_bytes());
        b[16..20].copy_from_slice(&projid.to_le_bytes());
        f.mem.write(GuestAddr(attr), &b).unwrap();
    };
    let at = (-100i64) as u64;
    let fd = f.ret(2, &[file, 0o102, 0o644]);
    assert!(fd < 1024, "{fd}");
    let getflags = |f: &mut Fixture, fd: u64| {
        assert_eq!(f.ret(16, &[fd, 0x8008_6601, out]), 0);
        f.mem.read_u64(GuestAddr(out)).unwrap() as u32
    };
    assert_eq!(getflags(&mut f, fd), 0);
    assert_eq!(f.ret(468, &[at, file, attr, 24, 0]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(attr)).unwrap(), 0);

    // FS_XFLAG_NODUMP is FS_NODUMP_FL, and statx shows it.
    set_attr(&mut f, 0x80, 0, 0);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), 0);
    assert_eq!(getflags(&mut f, fd), 0x40);
    assert_eq!(f.ret(332, &[at, file, 0, 0x7ff, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 8)).unwrap(), 0x40);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 56)).unwrap(), 0x70);
    // What tmpfs does not keep, and what Linux does not know.
    set_attr(&mut f, 0x20, 0, 0);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), eopnotsupp);
    set_attr(&mut f, 1 << 40, 0, 0);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), einval);
    set_attr(&mut f, 0x800, 4096, 0);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), eopnotsupp);
    set_attr(&mut f, 0, 0, u32::MAX);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), einval);
    set_attr(&mut f, 0, 0, 5);
    assert_eq!(f.ret(469, &[at, file, attr, 24, 0]), eopnotsupp);
    // FS_IOC_FSSETXATTR refuses an unknown flag with EOPNOTSUPP.
    f.mem.write(GuestAddr(out), &[0; 28]).unwrap();
    f.mem
        .write(GuestAddr(out), &(1u32 << 22).to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(16, &[fd, 0x401c_5820, out]), eopnotsupp);
    // A symbolic link keeps none.
    f.mem
        .write(GuestAddr(DATA + 0x300), b"/flags-link\0")
        .unwrap();
    assert_eq!(f.ret(88, &[file, DATA + 0x300]), 0);
    assert_eq!(f.ret(468, &[at, DATA + 0x300, attr, 24, 0x100]), eopnotsupp);

    // Immutable: nothing writes it, renames, links or removes it.
    f.mem.write(GuestAddr(out), &0x50u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[fd, 0x4008_6602, out]), 0);
    assert_eq!(getflags(&mut f, fd), 0x50);
    assert_eq!(f.ret(2, &[file, 1, 0]), eperm);
    assert!(f.ret(2, &[file, 0, 0]) < 1024);
    assert_eq!(f.ret(76, &[file, 0]), eperm);
    assert_eq!(f.ret(90, &[file, 0o600]), eperm);
    assert_eq!(f.ret(87, &[file]), eperm);
    assert_eq!(f.ret(86, &[file, other]), eperm);
    assert_eq!(f.ret(82, &[file, other]), eperm);
    assert_eq!(f.ret(280, &[at, file, 0, 0]), eperm);
    assert_eq!(f.ret(21, &[file, 2]), eperm);
    f.mem.write(GuestAddr(DATA + 0x340), b"user.a\0").unwrap();
    assert_eq!(f.ret(188, &[file, DATA + 0x340, out, 1, 0]), eperm);
    assert_eq!(f.ret(285, &[fd, 0, 0, 1]), eperm);
    // A description open before writes on.
    assert_eq!(f.ret(1, &[fd, out, 1]), 1);

    // Append-only: opened to write only with O_APPEND, never truncated.
    f.mem.write(GuestAddr(out), &0x20u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[fd, 0x4008_6602, out]), 0);
    assert_eq!(f.ret(2, &[file, 1, 0]), eperm);
    let appending = f.ret(2, &[file, 0o2001, 0]);
    assert!(appending < 1024, "{appending}");
    assert_eq!(f.ret(2, &[file, 0o3001, 0]), eperm);
    assert_eq!(f.ret(77, &[appending, 0]), eperm);
    assert_eq!(f.ret(72, &[appending, 4, 1]), eperm);
    assert_eq!(f.ret(285, &[appending, 0, 0, 1]), 0);
    assert_eq!(f.ret(285, &[appending, 3, 0, 1]), eperm);
    assert_eq!(f.ret(87, &[file]), eperm);
    assert_eq!(f.ret(280, &[at, file, 0, 0]), 0);
    // Cleared, it goes.
    f.mem.write(GuestAddr(out), &0u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[fd, 0x4008_6602, out]), 0);
    assert_eq!(f.ret(87, &[file]), 0);

    // A directory: its flags go to what is made in it, but for these two;
    // an immutable one takes no new name, an append-only one loses none.
    assert_eq!(f.ret(83, &[dir, 0o755]), 0);
    let d = f.ret(2, &[dir, 0o200000, 0]);
    f.mem.write(GuestAddr(out), &0xc0u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[d, 0x4008_6602, out]), 0);
    let child = f.ret(2, &[inner, 0o102, 0o644]);
    assert_eq!(getflags(&mut f, child), 0xc0);
    f.mem.write(GuestAddr(out), &0x20u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[d, 0x4008_6602, out]), 0);
    assert_eq!(f.ret(87, &[inner]), eperm);
    f.mem.write(GuestAddr(out), &0x10u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[d, 0x4008_6602, out]), 0);
    f.mem
        .write(GuestAddr(DATA + 0x380), b"/flags-dir/new\0")
        .unwrap();
    assert_eq!(f.ret(83, &[DATA + 0x380, 0o755]), eperm);
    f.mem.write(GuestAddr(out), &0u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(16, &[d, 0x4008_6602, out]), 0);

    // Only the owner changes flags, and the two need CAP_LINUX_IMMUTABLE.
    let fd2 = f.ret(2, &[other, 0o102, 0o644]);
    assert_eq!(f.ret(92, &[other, 1000, 1000]), 0);
    assert_eq!(f.ret(nr::SETUID, &[1000]), 0);
    set_attr(&mut f, 0x80, 0, 0);
    assert_eq!(f.ret(469, &[at, other, attr, 24, 0]), 0);
    set_attr(&mut f, 0x8, 0, 0);
    assert_eq!(f.ret(469, &[at, other, attr, 24, 0]), eperm);
    assert_eq!(f.ret(469, &[at, inner, attr, 24, 0]), eperm);
    assert_eq!(getflags(&mut f, fd2), 0x40);
}

#[test]
fn cachestat_counts_a_files_allocated_pages_in_a_range() {
    let mut f = fixture();
    let (path, range, out) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
    let data = f.ret(nr::MMAP, &[0, 3 * 4096, 3, 0x22, u64::MAX, 0]);
    f.mem.write(GuestAddr(path), b"/cachestat-file\0").unwrap();
    let fd = f.ret(2, &[path, 0o102, 0o644]);
    // Three pages, a hole, and the eleventh page.
    assert_eq!(f.ret(1, &[fd, data, 3 * 4096]), 3 * 4096);
    assert_eq!(f.ret(18, &[fd, data, 1, 10 * 4096]), 1);
    let stat = |f: &mut Fixture, fd: u64, off: u64, len: u64, flags: u64| {
        f.mem.write_u64(GuestAddr(range), off).unwrap();
        f.mem.write_u64(GuestAddr(range + 8), len).unwrap();
        f.mem.write(GuestAddr(out), &[0xff; 40]).unwrap();
        let r = f.ret(451, &[fd, range, out, flags]);
        (
            r,
            f.mem.read_u64(GuestAddr(out)).unwrap(),
            f.mem.read_u64(GuestAddr(out + 32)).unwrap(),
        )
    };
    assert_eq!(stat(&mut f, fd, 0, 0, 0), (0, 4, 0));
    assert_eq!(stat(&mut f, fd, 4096, 4096, 0).1, 1);
    assert_eq!(stat(&mut f, fd, 4095, 2, 0).1, 2);
    assert_eq!(stat(&mut f, fd, 5 * 4096, 4096, 0).1, 0);
    assert_eq!(stat(&mut f, fd, 4096, u64::MAX, 0).1, 0);
    assert_eq!(stat(&mut f, fd, 0, 0, 1).0, errno(Errno::EINVAL));
    assert_eq!(f.ret(451, &[fd, 0, out, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(451, &[fd, range, 0, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(451, &[999, range, out, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(77, &[fd, 4096]), 0);
    assert_eq!(stat(&mut f, fd, 0, 0, 0).1, 1);
    // A pipe keeps none; another user's file, opened to read, is EPERM
    // before the flags are looked at.
    let pipe = DATA + 0x400;
    assert_eq!(f.ret(22, &[pipe]), 0);
    let reader = f.mem.read_u64(GuestAddr(pipe)).unwrap() & 0xffff_ffff;
    assert_eq!(stat(&mut f, reader, 0, 0, 0), (0, 0, 0));
    assert_eq!(f.ret(nr::SETUID, &[1000]), 0);
    let read_only = f.ret(2, &[path, 0, 0]);
    assert_eq!(stat(&mut f, read_only, 0, 0, 1).0, errno(Errno::EPERM));
    assert_eq!(stat(&mut f, fd, 0, 0, 0).1, 1);
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
fn proc_pagemap_reads_through_the_system_calls_and_opens_for_writing_for_root_only() {
    let mut f = fixture();
    let (path, buf) = (DATA, DATA + 0x400);
    f.mem
        .write(GuestAddr(path), b"/proc/self/pagemap\0")
        .unwrap();
    let fd = f.ret(2, &[path, 0]);
    // The entry of the page `buf` is on: written, so present.
    let at = buf / 4096 * 8;
    assert_eq!(f.ret(17, &[fd, buf + 0x800, 8, at]), 8);
    let mut entry = [0; 8];
    f.mem.read(GuestAddr(buf + 0x800), &mut entry).unwrap();
    assert_ne!(u64::from_le_bytes(entry) & 1 << 63, 0);
    let root = f.ret(2, &[path, 2]);
    assert!(root < 1 << 32, "{root:#x}");
    // Without CAP_DAC_OVERRIDE: EACCES for writing, as its mode is 0400.
    // The change of IDs makes the process undumpable, whose files root owns:
    // PR_SET_DUMPABLE gives them back.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    assert_eq!(f.ret(157, &[4, 1]), 0);
    assert_eq!(f.ret(2, &[path, 2]), errno(Errno::EACCES));
    assert!(f.ret(2, &[path, 0]) < 1 << 32);
}
#[test]
fn own_proc_files_are_the_process_owners_and_open_as_their_modes_let() {
    let mut f = fixture();
    let (status, environ, buf) = (DATA, DATA + 0x100, DATA + 0x400);
    f.mem
        .write(GuestAddr(status), b"/proc/self/status\0")
        .unwrap();
    f.mem
        .write(GuestAddr(environ), b"/proc/self/environ\0")
        .unwrap();
    // st_mode at 24, st_uid at 28 and st_gid at 32 of a struct stat.
    let ids = |f: &mut Fixture, n: u64, a: u64| {
        assert_eq!(f.ret(n, &[a, buf]), 0);
        let mut b = [0; 12];
        f.mem.read(GuestAddr(buf + 24), &mut b).unwrap();
        let word = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        (word(0), word(4), word(8))
    };
    // Root may open even a 0444 file for writing.
    let fd = f.ret(2, &[status, 1]);
    assert!(fd < 1 << 32, "{fd:#x}");
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(119, &[2000, 2000, 2000]), 0);
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    // Undumpable after the change of IDs: root's.
    assert_eq!(ids(&mut f, 4, status), (0o100444, 0, 0));
    assert_eq!(f.ret(2, &[environ, 0]), errno(Errno::EACCES));
    assert_eq!(f.ret(157, &[4, 1]), 0);
    assert_eq!(ids(&mut f, 4, status), (0o100444, 1000, 2000));
    assert_eq!(ids(&mut f, 4, environ), (0o100400, 1000, 2000));
    // Its files open as their modes let it: none for writing.
    for (path, access) in [(status, 1), (status, 2), (environ, 1), (environ, 2)] {
        assert_eq!(f.ret(2, &[path, access]), errno(Errno::EACCES));
    }
    let fd = f.ret(2, &[environ, 0]);
    assert!(fd < 1 << 32, "{fd:#x}");
    assert_eq!(ids(&mut f, 5, fd), (0o100400, 1000, 2000));
    let fd = f.ret(2, &[status, 0]);
    assert_eq!(ids(&mut f, 5, fd), (0o100444, 1000, 2000));
}
#[test]
fn a_pidfds_fdinfo_names_its_process() {
    let mut f = fixture();
    let pid = f.ret(39, &[]);
    let fd = f.ret(434, &[pid, 0]);
    assert!(fd < 1 << 32, "{fd:#x}");
    let (path, buf) = (DATA, DATA + 0x400);
    f.mem
        .write(
            GuestAddr(path),
            format!("/proc/self/fdinfo/{fd}\0").as_bytes(),
        )
        .unwrap();
    let info = f.ret(2, &[path, 0]);
    let count = f.ret(0, &[info, buf, 512]);
    let mut text = vec![0; count as usize];
    f.mem.read(GuestAddr(buf), &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.ends_with(&format!("Pid:\t{pid}\nNSpid:\t{pid}\n")),
        "{text}"
    );
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
            ".", "..", "fd", "full", "mqueue", "null", "ptmx", "pts", "random", "shm", "stderr",
            "stdin", "stdout", "urandom", "zero"
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
    assert_eq!(f.ret(nr::TIMER_CREATE, &[10, 0, id]), errno(Errno::EINVAL));
    f.mem.write_u64(GuestAddr(sev + 8), 99).unwrap();
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), errno(Errno::EINVAL));
    f.mem.write_u64(GuestAddr(sev + 8), 4 << 32 | 10).unwrap(); // SIGEV_THREAD_ID
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), errno(Errno::EINVAL));
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 1, id]), errno(Errno::EFAULT));
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, 0, 1]), errno(Errno::EFAULT));
    // The sigevent is copied before the clock is looked at; the clocks
    // that can only be read give EOPNOTSUPP.
    assert_eq!(f.ret(nr::TIMER_CREATE, &[99, 1, id]), errno(Errno::EFAULT));
    for clock in [4, 5, 6] {
        assert_eq!(
            f.ret(nr::TIMER_CREATE, &[clock, 0, id]),
            errno(Errno::EOPNOTSUPP)
        );
    }
    assert_eq!(f.ret(nr::TIMER_CREATE, &[99, 0, id]), errno(Errno::EINVAL));
    // Linux looks at no flag but TIMER_ABSTIME.
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[1, !1, spec, 0]), 0);
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
/// Times past `KTIME_MAX` are taken up to it, and a relative expiry past it
/// stops there, as Linux's `timespec64_to_ktime` and `ktime_add_safe` do.
#[test]
fn posix_timers_take_times_up_to_ktime_max() {
    const KTIME_MAX: u64 = i64::MAX as u64;
    let mut f = fixture();
    let (id, sev, spec, old) = (DATA, DATA + 0x40, DATA + 0x100, DATA + 0x140);
    f.host
        .set_clock(paludarium_host::ClockId::Monotonic, 1_000_000_000);
    f.host
        .set_clock(paludarium_host::ClockId::Realtime, 5_000_000_000);
    f.mem.write_u64(GuestAddr(sev + 8), 1 << 32).unwrap(); // SIGEV_NONE
    assert_eq!(f.ret(nr::TIMER_CREATE, &[1, sev, id]), 0);
    assert_eq!(f.ret(nr::TIMER_CREATE, &[0, sev, id]), 0);
    let words = |f: &Fixture| -> [u64; 4] {
        std::array::from_fn(|i| f.mem.read_u64(GuestAddr(old + 8 * i as u64)).unwrap())
    };
    // Seconds past u64 nanoseconds, and i64::MAX seconds.
    for (i, v) in [20_000_000_000, 0, i64::MAX as u64, 0].iter().enumerate() {
        f.mem.write_u64(GuestAddr(spec + 8 * i as u64), *v).unwrap();
    }
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[0, 0, spec, 0]), 0);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[0, old]), 0);
    let left = KTIME_MAX - 1_000_000_000;
    assert_eq!(
        words(&f),
        [
            KTIME_MAX / 1_000_000_000,
            KTIME_MAX % 1_000_000_000,
            left / 1_000_000_000,
            left % 1_000_000_000
        ]
    );
    // A relative CLOCK_REALTIME timer runs on the monotonic clock, an
    // absolute one on its own.
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[1, 0, spec, 0]), 0);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[1, old]), 0);
    assert_eq!(words(&f)[2..], [left / 1_000_000_000, left % 1_000_000_000]);
    assert_eq!(f.ret(nr::TIMER_SETTIME, &[1, 1, spec, 0]), 0);
    assert_eq!(f.ret(nr::TIMER_GETTIME, &[1, old]), 0);
    let left = KTIME_MAX - 5_000_000_000;
    assert_eq!(words(&f)[2..], [left / 1_000_000_000, left % 1_000_000_000]);
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
    let table = b"21 1 0:1 / / rw,relatime - tmpfs tmpfs rw\n\
22 21 0:1 / /dev rw,nosuid,noexec,relatime - devtmpfs devtmpfs rw\n\
23 22 0:2 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw,inode64\n";
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
    // Of size 0, as Linux's, whatever a read gives; `/proc/mounts` too.
    assert_eq!(f.mem.read_u64(GuestAddr(buf + 48)).unwrap(), 0);
    f.mem.write(GuestAddr(empty), b"/proc/mounts\0").unwrap();
    assert_eq!(f.ret(4, &[empty, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf + 48)).unwrap(), 0);
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
fn populating_a_writable_private_file_mapping_copies_its_pages() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
    assert_eq!(f.ret(77, &[fd, 4096]), 0);
    f.mem.write(GuestAddr(DATA), b"HELLO").unwrap();
    // Whether the page at `at` still shows the file: a write to the file
    // after the call is seen only by a page the call did not copy.
    let shows_the_file = |f: &mut Fixture, at: u64| {
        assert_eq!(f.ret(18, &[fd, DATA, 5, 0]), 5);
        let seen = memory_bytes(f, at, 5) == b"HELLO";
        f.mem.write(GuestAddr(DATA + 16), b"hello").unwrap();
        assert_eq!(f.ret(18, &[fd, DATA + 16, 5, 0]), 5);
        seen
    };
    // `mlock` writes a writable private page in (`FOLL_WRITE`).
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2, fd, 0]);
    assert_eq!(f.ret(149, &[at, 4096]), 0);
    assert!(!shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    // Not one that is only readable, nor with MLOCK_ONFAULT.
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 2, fd, 0]);
    assert_eq!(f.ret(149, &[at, 4096]), 0);
    assert!(shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2, fd, 0]);
    assert_eq!(f.ret(325, &[at, 4096, 1]), 0);
    assert!(shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    // `mlockall(MCL_CURRENT)` populates as `mlock` does.
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2, fd, 0]);
    assert_eq!(f.ret(151, &[1]), 0);
    assert_eq!(f.ret(152, &[]), 0);
    assert!(!shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    // So do MAP_POPULATE and MAP_LOCKED.
    for flag in [0x8000, 0x2000] {
        let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2 | flag, fd, 0]);
        assert!(!shows_the_file(&mut f, at), "{flag:#x}");
        assert_eq!(f.ret(11, &[at, 4096]), 0);
    }
    // A locked private mapping made writable is written in
    // (`mprotect_fixup`), unless it is locked on fault.
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 2, fd, 0]);
    assert_eq!(f.ret(149, &[at, 4096]), 0);
    assert_eq!(f.ret(10, &[at, 4096, 3]), 0);
    assert!(!shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 1, 2, fd, 0]);
    assert_eq!(f.ret(325, &[at, 4096, 1]), 0);
    assert_eq!(f.ret(10, &[at, 4096, 3]), 0);
    assert!(shows_the_file(&mut f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    // A page past the end of the file cannot be brought in (`ENOMEM`), but
    // its write fault gave the mapping an `anon_vma` first
    // (`vmf_anon_prepare` in `do_cow_fault`), as MAP_POPULATE's does.
    let written = |f: &Fixture, at: u64| {
        f.mem
            .mappings()
            .find(|m| m.start.0 == at)
            .is_some_and(|m| m.written)
    };
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2, fd, 4096]);
    assert!(!written(&f, at));
    assert_eq!(f.ret(149, &[at, 4096]), errno(Errno::ENOMEM));
    assert!(written(&f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
    let at = f.ret(syscalls::nr::MMAP, &[0, 4096, 3, 2 | 0x8000, fd, 4096]);
    assert!(written(&f, at));
    assert_eq!(f.ret(11, &[at, 4096]), 0);
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
fn memfd_pages_faults_bring_in_count_in_its_blocks() {
    let mut f = fixture();
    let (name, stat) = (DATA + 0x100, DATA + 0x200);
    f.mem.write(GuestAddr(name), b"faults\0").unwrap();
    let fd = f.ret(319, &[name, 0]);
    assert!(fd < 1 << 32);
    assert_eq!(f.ret(77, &[fd, 4 * 4096]), 0);
    let blocks = |f: &mut Fixture| {
        assert_eq!(f.ret(5, &[fd, stat]), 0);
        f.mem.read_u64(GuestAddr(stat + 64)).unwrap()
    };
    assert_eq!(blocks(&mut f), 0);
    // A shared mapping's read fault and write fault, a page each.
    let mmap = syscalls::nr::MMAP;
    let shared = f.ret(mmap, &[0, 4 * 4096, 3, 1, fd, 0]);
    let mut byte = [0];
    f.mem.read(GuestAddr(shared), &mut byte).unwrap();
    assert_eq!(blocks(&mut f), 8);
    f.mem.write(GuestAddr(shared + 4096), b"x").unwrap();
    assert_eq!(blocks(&mut f), 16);
    // A private mapping's read fault and copy-on-write fault bring the
    // file's page in too; a page the file holds costs nothing more.
    let private = f.ret(mmap, &[0, 4 * 4096, 3, 2, fd, 0]);
    f.mem
        .read(GuestAddr(private + 2 * 4096), &mut byte)
        .unwrap();
    assert_eq!(blocks(&mut f), 24);
    f.mem.write(GuestAddr(private + 3 * 4096), b"y").unwrap();
    assert_eq!(blocks(&mut f), 32);
    f.mem.write(GuestAddr(private), b"z").unwrap();
    assert_eq!(blocks(&mut f), 32);
    assert_eq!(memory_bytes(&f, shared + 3 * 4096, 1), [0]);
}
#[test]
fn memfd_secret_maps_shared_only_and_refuses_reads_and_writes() {
    let mut f = fixture();
    let (einval, espipe, eopnotsupp) = (
        errno(Errno::EINVAL),
        errno(Errno::ESPIPE),
        errno(Errno::EOPNOTSUPP),
    );
    let (stat, path, buf) = (DATA + 0x100, DATA + 0x300, DATA + 0x400);
    assert_eq!(f.ret(447, &[1]), einval);
    assert_eq!(f.ret(447, &[0o2000001]), einval);
    let fd = f.ret(447, &[0o2000000]);
    assert!(fd < 1 << 32);
    assert_eq!(f.ret(72, &[fd, 1, 0]), 1); // FD_CLOEXEC
    assert_eq!(f.ret(72, &[fd, 3, 0]), 0o100002); // O_RDWR | O_LARGEFILE
    assert_eq!(f.ret(5, &[fd, stat]), 0);
    let word = |f: &Fixture, at: u64| f.mem.read_u64(GuestAddr(stat + at)).unwrap();
    assert_eq!(word(&f, 16), 1); // st_nlink
    assert_eq!(word(&f, 24) & 0xffff_ffff, 0o100600); // st_mode
    assert_eq!(word(&f, 48), 0); // st_size
    // No reads, writes, seeks, syncs, allocation or seals.
    assert_eq!(f.ret(0, &[fd, buf, 1]), einval);
    assert_eq!(f.ret(1, &[fd, buf, 1]), einval);
    assert_eq!(f.ret(19, &[fd, 8, 1]), einval); // before the iovecs
    // No FMODE_PREAD or FMODE_PWRITE either, after a negative offset.
    assert_eq!(f.ret(17, &[fd, buf, 1, u64::MAX]), einval);
    assert_eq!(f.ret(17, &[fd, buf, 1, 0]), espipe);
    assert_eq!(f.ret(18, &[fd, buf, 1, 0]), espipe);
    assert_eq!(f.ret(8, &[fd, 0, 0]), espipe);
    assert_eq!(f.ret(74, &[fd]), einval);
    assert_eq!(f.ret(285, &[fd, 0, 0, 4096]), eopnotsupp);
    assert_eq!(f.ret(72, &[fd, 1034, 0]), einval);
    assert_eq!(f.ret(72, &[fd, 1033, 1]), einval);
    assert_eq!(f.ret(138, &[fd, buf]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x5345_434d);
    // The size, once.
    assert_eq!(f.ret(77, &[fd, 8192]), 0);
    assert_eq!(f.ret(77, &[fd, 8192]), einval);
    assert_eq!(f.ret(77, &[fd, 4096]), einval);
    // Shared mappings only, which keep its pages.
    let mmap = syscalls::nr::MMAP;
    assert_eq!(f.ret(mmap, &[0, 4096, 3, 2, fd, 0]), einval);
    let at = f.ret(mmap, &[0, 8192, 3, 1, fd, 0]);
    f.mem.write(GuestAddr(at + 4096), b"secret").unwrap();
    assert_eq!(f.ret(11, &[at, 8192]), 0);
    let again = f.ret(mmap, &[0, 8192, 1, 1, fd, 0]);
    assert_eq!(memory_bytes(&f, again + 4096, 6), b"secret");
    // Its name, and no open of its own.
    f.mem
        .write(GuestAddr(path), format!("/proc/self/fd/{fd}\0").as_bytes())
        .unwrap();
    let n = f.ret(89, &[path, buf, 64]);
    assert_eq!(memory_bytes(&f, buf, n as usize), b"/secretmem (deleted)");
    assert_eq!(f.ret(2, &[path, 2]), errno(Errno(6))); // ENXIO
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
fn getrusage_gives_the_peak_resident_size_of_the_process_and_of_its_children() {
    let mut f = fixture();
    let maxrss = |f: &mut Fixture, who: u64| {
        assert_eq!(f.ret(98, &[who, DATA]), 0);
        let mut bytes = [0u8; 8];
        f.mem.read(GuestAddr(DATA + 32), &mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    };
    // The address space's own peak, in KiB, for the process and the thread,
    // once the first call has written the page it fills.
    maxrss(&mut f, 0);
    let (peak, _) = f.mem.resident_pages();
    assert!(peak > 0);
    assert_eq!(maxrss(&mut f, 0), peak * 4);
    assert_eq!(maxrss(&mut f, 1), peak * 4);
    assert_eq!(maxrss(&mut f, u64::MAX), 0);
    // A peak kept from an address space it left counts while larger.
    f.kernel.group.keep_peak(peak + 100);
    assert_eq!(maxrss(&mut f, 0), (peak + 100) * 4);
    // The children's is the largest reaped one.
    f.kernel.group.reaped_peak(7);
    f.kernel.group.reaped_peak(5);
    assert_eq!(maxrss(&mut f, u64::MAX), 28);
    assert_eq!(f.kernel.group.waited_peak(), peak + 100);
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
    // The coarse clocks' resolution is the host's tick (1 ms where it does
    // not tell).
    let tick = crate::syscalls::scheduler_slice(&*f.host).tick;
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), tick);
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
    // The alarm clocks need CAP_WAKE_ALARM, looked at after the flags.
    let alarm = f.ret(283, &[8, 0]);
    assert!(alarm < 1 << 32, "{alarm}");
    assert_eq!(f.ret(3, &[alarm]), 0);
    let root = f.thread.state.credentials.clone();
    f.thread.state.credentials = root.setresuid(1000, 1000, 1000).unwrap();
    assert_eq!(f.ret(283, &[9, 1]), errno(Errno::EINVAL));
    assert_eq!(f.ret(283, &[9, 0]), errno(Errno::EPERM));
    f.thread.state.credentials = root;
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

    #[test]
    fn a_map_growsdown_mapping_grows_down_at_a_fault() {
        const MAP_GROWSDOWN: u64 = 0x100;
        const PRIVATE_FIXED: u64 = 0x02 | 0x10 | 0x20;
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // Only private anonymous memory grows down.
        assert_eq!(
            f.ret(9, &[0, 4096, 3, 0x01 | 0x20 | MAP_GROWSDOWN, u64::MAX, 0]),
            einval
        );
        let at = 0x60_0000;
        let flags = PRIVATE_FIXED | MAP_GROWSDOWN;
        assert_eq!(f.ret(9, &[at, 0x2000, 3, flags, u64::MAX, 0]), at);
        // A fault two pages below takes both pages, and the access runs again.
        let rip = GuestAddr(0x1234);
        let fault = |addr| ExitReason::PageFault {
            rip,
            addr: GuestAddr(addr),
            write: true,
            fetch: false,
            mapped: false,
            present: false,
        };
        assert_eq!(
            f.kernel.handle(&mut f.thread, &f.mem, fault(at - 0x1ff8)),
            Next::Resume
        );
        assert_eq!(f.thread.cpu.rip, rip);
        assert_eq!(
            f.mem.vma_at(GuestAddr(at)),
            Some((GuestAddr(at - 0x2000), 0x4000))
        );
        f.mem.write(GuestAddr(at - 0x2000), &[1]).unwrap();
        // PROT_GROWSDOWN reaches the new start.
        assert_eq!(f.ret(10, &[at, 4096, 1 | GROWSDOWN]), 0);
        assert_eq!(prot_at(&f, at - 0x2000), Prot::READ);
        assert_eq!(prot_at(&f, at + 0x1000), Prot::READ_WRITE);
        // Another thread grew it first: the access is made again, as a read
        // of it can be made now (a write, to read-only memory, cannot).
        let read = ExitReason::PageFault {
            rip,
            addr: GuestAddr(at - 0x1ff8),
            write: false,
            fetch: false,
            mapped: false,
            present: false,
        };
        assert_eq!(f.kernel.handle(&mut f.thread, &f.mem, read), Next::Resume);
        // What the access still meets there is the signal's, not a retry: a
        // guard page, or a page that cannot be executed.
        f.mem
            .guard(GuestAddr(at - 0x2000), at - 0x1000, true)
            .unwrap();
        let fetch = ExitReason::PageFault {
            rip,
            addr: GuestAddr(at),
            write: false,
            fetch: true,
            mapped: false,
            present: false,
        };
        let mut other = fixture();
        assert_eq!(other.ret(9, &[at, 0x2000, 3, flags, u64::MAX, 0]), at);
        assert_eq!(
            other.kernel.handle(&mut other.thread, &other.mem, fetch),
            Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
        );
        assert_eq!(
            f.kernel.handle(&mut f.thread, &f.mem, fault(at - 0x1ff8)),
            Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
        );
        let mut f = fixture();
        // Below memory that does not grow down, a fault is still SIGSEGV.
        let plain = 0x70_0000;
        assert_eq!(
            f.ret(9, &[plain, 4096, 3, PRIVATE_FIXED, u64::MAX, 0]),
            plain
        );
        assert_eq!(
            f.kernel.handle(&mut f.thread, &f.mem, fault(plain - 8)),
            Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
        );
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
    fn mremap_neither_grows_nor_keeps_behind_a_ring() {
        let mut f = fixture();
        let r = ring(&mut f);
        // A fixed mapping (`VM_DONTEXPAND`): no growth, no MREMAP_DONTUNMAP.
        assert_eq!(f.ret(25, &[r.sqes, 4096, 8192, 1]), errno(Errno::EFAULT));
        assert_eq!(
            f.ret(25, &[r.sqes, 4096, 4096, 1 | 4]),
            errno(Errno::EINVAL)
        );
        // It moves: `io_uring` has no `mremap` of its own.
        let to = 0x4000_0000;
        assert_eq!(f.ret(25, &[r.sqes, 4096, 4096, 1 | 2, to]), to);
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
        push(&mut f, &r, 1, &sqe(6, 2));
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
        // The probe: NOP, the transfers and EPOLL_CTL, of 58 operations.
        let probe = DATA + 0x400;
        f.mem.write(GuestAddr(probe), &[0; 16 + 8 * 64]).unwrap();
        assert_eq!(f.ret(427, &[r.fd, 8, probe, 64]), 0);
        let mut head = [0; 2];
        f.mem.read(GuestAddr(probe), &mut head).unwrap();
        assert_eq!(head, [57, 58]);
        let supported: Vec<u64> = (0..58)
            .filter(|op| u32_at(&f, probe + 16 + 8 * op) >> 16 & 1 == 1)
            .collect();
        assert_eq!(supported, [0, 1, 2, 3, 4, 5, 20, 22, 23, 29, 31, 32]);
        // A probe that is not zeroed, buffers without an argument, another
        // operation, another file.
        assert_eq!(f.ret(427, &[r.fd, 8, probe, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 0, 0, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(427, &[r.fd, 31, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[0, 8, probe, 1]), errno(Errno(95)));
    }

    /// Submits one entry, waits for it, and gives its result.
    fn one(f: &mut Fixture, r: &Ring, sqe: &[u8; 64]) -> i32 {
        let slot = u32_at(f, r.rings + 4) & 3;
        push(f, r, slot, sqe);
        assert_eq!(f.ret(426, &[r.fd, 1, 1, GETEVENTS]), 1);
        let done = reap(f, r);
        assert_eq!(done.len(), 1, "{done:?}");
        done[0].1
    }

    /// A transfer entry: `opcode` on `fd` at `offset`, `addr` and `len`.
    fn rw(opcode: u8, fd: u64, offset: u64, addr: u64, len: u32) -> [u8; 64] {
        let mut e = sqe(opcode, 1);
        e[4..8].copy_from_slice(&(fd as i32).to_le_bytes());
        e[8..16].copy_from_slice(&offset.to_le_bytes());
        e[16..24].copy_from_slice(&addr.to_le_bytes());
        e[24..28].copy_from_slice(&len.to_le_bytes());
        e
    }

    fn bytes(f: &Fixture, at: u64, len: usize) -> Vec<u8> {
        let mut b = vec![0; len];
        f.mem.read(GuestAddr(at), &mut b).unwrap();
        b
    }

    const READV: u8 = 1;
    const WRITEV: u8 = 2;
    const FSYNC: u8 = 3;
    const READ: u8 = 22;
    const WRITE: u8 = 23;
    const HERE: u64 = u64::MAX;

    #[test]
    fn transfers_move_bytes_at_an_offset_or_the_position() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (put, got, iov) = (DATA + 0x100, DATA + 0x200, DATA + 0x300);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        f.mem.write(GuestAddr(put), b"hello world").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        assert_eq!(f.ret(1, &[fd, put, 11]), 11);
        // At an offset: the position stays.
        f.mem.write(GuestAddr(put), b"HE").unwrap();
        assert_eq!(one(&mut f, &r, &rw(WRITE, fd, 0, put, 2)), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 11);
        assert_eq!(one(&mut f, &r, &rw(READ, fd, 0, got, 5)), 5);
        assert_eq!(bytes(&f, got, 5), b"HEllo");
        // -1 is the position, which moves past what was read.
        assert_eq!(f.ret(8, &[fd, 6, 0]), 6);
        assert_eq!(one(&mut f, &r, &rw(READ, fd, HERE, got, 64)), 5);
        assert_eq!(bytes(&f, got, 5), b"world");
        assert_eq!(f.ret(8, &[fd, 0, 1]), 11);
        // Vectors: two buffers written at the position, read at an offset.
        f.mem.write(GuestAddr(put), b"!?").unwrap();
        for (i, (base, len)) in [(put, 1u64), (put + 1, 1)].iter().enumerate() {
            f.mem
                .write_u64(GuestAddr(iov + 16 * i as u64), *base)
                .unwrap();
            f.mem
                .write_u64(GuestAddr(iov + 16 * i as u64 + 8), *len)
                .unwrap();
        }
        assert_eq!(one(&mut f, &r, &rw(WRITEV, fd, HERE, iov, 2)), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 13);
        f.mem.write_u64(GuestAddr(iov), got).unwrap();
        f.mem.write_u64(GuestAddr(iov + 16), got + 1).unwrap();
        assert_eq!(one(&mut f, &r, &rw(READV, fd, 11, iov, 2)), 2);
        assert_eq!(bytes(&f, got, 2), b"!?");
        // Past the end, nothing; a negative offset but -1 is EINVAL.
        assert_eq!(one(&mut f, &r, &rw(READ, fd, 100, got, 5)), 0);
        assert_eq!(one(&mut f, &r, &rw(READ, fd, -2i64 as u64, got, 5)), -22);
        // An O_APPEND file's write at the position starts at its end.
        f.mem.write(GuestAddr(DATA), b"/b\0").unwrap();
        let append = f.ret(2, &[DATA, 0o2102, 0o600]);
        assert_eq!(f.ret(1, &[append, put, 2]), 2);
        assert_eq!(f.ret(8, &[append, 0, 0]), 0);
        assert_eq!(one(&mut f, &r, &rw(WRITE, append, HERE, put, 2)), 2);
        assert_eq!(f.ret(8, &[append, 0, 1]), 4);
        // FSYNC, whose only flag is IORING_FSYNC_DATASYNC.
        let mut sync = rw(FSYNC, fd, 0, 0, 0);
        assert_eq!(one(&mut f, &r, &sync), 0);
        sync[28] = 1;
        assert_eq!(one(&mut f, &r, &sync), 0);
        sync[28] = 2;
        assert_eq!(one(&mut f, &r, &sync), -22);
    }

    #[test]
    fn transfers_fail_where_linux_does() {
        let mut f = fixture();
        let r = ring(&mut f);
        let buf = DATA + 0x100;
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o101, 0o600]);
        // The file at issue: none, a registered one, the access mode.
        assert_eq!(one(&mut f, &r, &rw(READ, 99, 0, buf, 1)), -9);
        let mut fixed = rw(READ, fd, 0, buf, 1);
        fixed[1] = 1;
        assert_eq!(one(&mut f, &r, &fixed), -9);
        assert_eq!(one(&mut f, &r, &rw(READ, fd, 0, buf, 1)), -9);
        // No buffer is provided, which a read finds before its access
        // mode; a write selects none.
        let mut select = rw(READ, fd, 0, 0, 1);
        select[1] = 1 << 5;
        assert_eq!(one(&mut f, &r, &select), -105);
        let mut select = rw(WRITE, fd, 0, 0, 1);
        select[1] = 1 << 5;
        assert_eq!(one(&mut f, &r, &select), -95);
        // The flags: an unknown one, polled I/O.
        let mut flags = rw(WRITE, fd, 0, buf, 1);
        flags[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        assert_eq!(one(&mut f, &r, &flags), -95);
        flags[28..32].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(one(&mut f, &r, &flags), -22);
        // The preparation: a buffer or vector outside the user half, an
        // unknown attribute, a priority of no class.
        assert_eq!(one(&mut f, &r, &rw(WRITE, fd, 0, 1 << 63, 1)), -14);
        assert_eq!(one(&mut f, &r, &rw(WRITEV, fd, 0, 8, 1)), -14);
        assert_eq!(one(&mut f, &r, &rw(WRITEV, fd, 0, buf, 1025)), -22);
        let mut attr = rw(WRITE, fd, 0, buf, 1);
        attr[56] = 2;
        assert_eq!(one(&mut f, &r, &attr), -22);
        let mut prio = rw(WRITE, fd, 0, buf, 1);
        prio[2..4].copy_from_slice(&(7u16 << 13).to_le_bytes());
        assert_eq!(one(&mut f, &r, &prio), -22);
        let mut prio = rw(FSYNC, fd, 0, 0, 0);
        prio[2] = 1;
        assert_eq!(one(&mut f, &r, &prio), -22);
        // A directory reads EISDIR, an epoll instance nothing.
        f.mem.write(GuestAddr(DATA), b"/\0").unwrap();
        let dir = f.ret(2, &[DATA, 0o200000, 0]);
        assert_eq!(one(&mut f, &r, &rw(READ, dir, 0, buf, 1)), -21);
        let epfd = f.ret(291, &[0]);
        assert_eq!(one(&mut f, &r, &rw(READ, epfd, 0, buf, 1)), -22);
        // An empty pipe would wait: EAGAIN here.
        assert_eq!(f.ret(22, &[DATA + 0x500]), 0);
        let ends = bytes(&f, DATA + 0x500, 8);
        let reader = u64::from(u32::from_le_bytes(ends[..4].try_into().unwrap()));
        let writer = u64::from(u32::from_le_bytes(ends[4..].try_into().unwrap()));
        assert_eq!(one(&mut f, &r, &rw(READ, reader, 0, buf, 4)), -11);
        f.mem.write(GuestAddr(buf), b"pipe").unwrap();
        assert_eq!(one(&mut f, &r, &rw(WRITE, writer, 5, buf, 4)), 4);
        assert_eq!(one(&mut f, &r, &rw(READ, reader, HERE, buf + 8, 8)), 4);
        assert_eq!(bytes(&f, buf + 8, 4), b"pipe");
    }

    const READ_FIXED: u8 = 4;
    const WRITE_FIXED: u8 = 5;
    const ENXIO: Errno = Errno(6);
    const EBUSY: Errno = Errno(16);
    const EOVERFLOW: Errno = Errno(75);

    /// `iovec`s of `(base, len)` at `at`.
    fn iovecs(f: &Fixture, at: u64, buffers: &[(u64, u64)]) {
        for (i, &(base, len)) in buffers.iter().enumerate() {
            let entry = at + 16 * i as u64;
            f.mem.write_u64(GuestAddr(entry), base).unwrap();
            f.mem.write_u64(GuestAddr(entry + 8), len).unwrap();
        }
    }

    fn fixed(opcode: u8, fd: u64, offset: u64, addr: u64, len: u32, index: u16) -> [u8; 64] {
        let mut e = rw(opcode, fd, offset, addr, len);
        e[40..42].copy_from_slice(&index.to_le_bytes());
        e
    }

    #[test]
    fn registered_buffers_transfer_within_themselves() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (vec, buf) = (DATA + 0x100, DATA + 0x800);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        // Unregistered: a fixed transfer finds no buffer.
        assert_eq!(one(&mut f, &r, &fixed(READ_FIXED, fd, 0, buf, 1, 0)), -14);
        assert_eq!(f.ret(427, &[r.fd, 1, 0, 0]), errno(ENXIO));
        // The registration's own checks.
        assert_eq!(f.ret(427, &[r.fd, 0, 0, 1]), errno(Errno::EFAULT));
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 16385]), errno(Errno::EINVAL));
        for (buffer, e) in [
            ((0, 1), Errno::EFAULT),
            ((buf, 0), Errno::EFAULT),
            ((buf, (1 << 30) + 1), Errno::EFAULT),
            ((buf, -1i64 as u64), Errno::EINVAL),
            ((-4096i64 as u64, 4096), EOVERFLOW),
            ((0x40_0000, 4096), Errno::EFAULT),
        ] {
            iovecs(&f, vec, &[buffer]);
            assert_eq!(f.ret(427, &[r.fd, 0, vec, 1]), errno(e), "{buffer:x?}");
        }
        // A failure registers none; then one buffer and an empty slot.
        iovecs(&f, vec, &[(buf, 0x100), (0x40_0000, 1)]);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 2]), errno(Errno::EFAULT));
        assert_eq!(f.ret(427, &[r.fd, 1, 0, 0]), errno(ENXIO));
        iovecs(&f, vec, &[(buf, 0x100), (0, 0)]);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 2]), 0);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 2]), errno(EBUSY));
        // Within the buffer, at any address in it.
        f.mem.write(GuestAddr(buf + 0x10), b"fixed").unwrap();
        let w = fixed(WRITE_FIXED, fd, 0, buf + 0x10, 5, 0);
        assert_eq!(one(&mut f, &r, &w), 5);
        let rd = fixed(READ_FIXED, fd, 1, buf + 0x80, 4, 0);
        assert_eq!(one(&mut f, &r, &rd), 4);
        assert_eq!(bytes(&f, buf + 0x80, 4), b"ixed");
        // Outside it, past its end, the empty slot, a slot past the last.
        for (addr, len, index) in [
            (buf - 1, 1, 0),
            (buf + 0xff, 2, 0),
            (buf, 0x101, 0),
            (buf, 1, 1),
            (buf, 1, 2),
        ] {
            let e = fixed(READ_FIXED, fd, 0, addr, len, index);
            assert_eq!(one(&mut f, &r, &e), -14, "{addr:x} {len} {index}");
        }
        // The file comes first; no buffer is selected.
        assert_eq!(one(&mut f, &r, &fixed(READ_FIXED, 99, 0, buf, 1, 5)), -9);
        let mut select = fixed(READ_FIXED, fd, 0, buf, 1, 0);
        select[1] = 1 << 5;
        assert_eq!(one(&mut f, &r, &select), -95);
        // Unregistering takes arguments of none, then they are gone.
        assert_eq!(f.ret(427, &[r.fd, 1, vec, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 1, 0, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 1, 0, 0]), 0);
        assert_eq!(one(&mut f, &r, &rd), -14);
    }

    #[test]
    fn a_write_that_would_wait_is_heard_of_only_with_nowait() {
        let mut f = fixture();
        let r = ring(&mut f);
        f.mem.write(GuestAddr(DATA), b"/tmp/q\0").unwrap();
        assert_eq!(f.ret(133, &[DATA, 0o010644, 0]), 0);
        // A FIFO of one page, full.
        let fifo = f.ret(2, &[DATA, 0o4002, 0]);
        assert_eq!(f.ret(72, &[fifo, 1031, 4096]), 4096);
        assert_eq!(f.ret(1, &[fifo, DATA + 0x800, 4096]), 4096);
        let ifd = f.ret(294, &[0o4000]);
        assert!(f.ret(254, &[ifd, DATA, 2]) < 1024);
        // Linux keeps it in flight: no event yet.
        assert_eq!(one(&mut f, &r, &rw(WRITE, fifo, HERE, DATA, 1)), -11);
        assert_eq!(f.ret(0, &[ifd, DATA + 0x100, 64]), errno(Errno::EAGAIN));
        // With RWF_NOWAIT it ends, and IN_MODIFY says so.
        let mut nowait = rw(WRITE, fifo, HERE, DATA, 1);
        nowait[28] = 8;
        assert_eq!(one(&mut f, &r, &nowait), -11);
        assert_eq!(f.ret(0, &[ifd, DATA + 0x100, 64]), 16);
        assert_eq!(u32_at(&f, DATA + 0x104), 2);
    }

    #[test]
    fn registered_buffers_charge_memlock_until_they_go() {
        let mut f = fixture();
        // RLIMIT_MEMLOCK of one page, for a user without CAP_IPC_LOCK.
        f.mem.write_u64(GuestAddr(DATA), 4096).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), 4096).unwrap();
        assert_eq!(f.ret(160, &[8, DATA]), 0);
        assert_eq!(f.ret(105, &[1000]), 0);
        let r = ring(&mut f);
        let (vec, buf) = (DATA + 0x100, DATA + 0x800);
        // Two pages: past the limit.
        iovecs(&f, vec, &[(buf + 0x7ff, 2)]);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 1]), errno(Errno::ENOMEM));
        iovecs(&f, vec, &[(buf, 0x10), (buf + 0x100, 0x10)]);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 2]), errno(Errno::ENOMEM));
        iovecs(&f, vec, &[(buf, 0x10)]);
        assert_eq!(f.ret(427, &[r.fd, 0, vec, 1]), 0);
        // Another ring of the user finds the page taken until it goes.
        let other = ring(&mut f);
        assert_eq!(f.ret(427, &[other.fd, 0, vec, 1]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(427, &[r.fd, 1, 0, 0]), 0);
        assert_eq!(f.ret(427, &[other.fd, 0, vec, 1]), 0);
        assert_eq!(f.ret(3, &[other.fd]), 0);
    }

    const FILES_UPDATE: u8 = 20;
    const EMFILE: Errno = Errno(24);
    const ENFILE: Errno = Errno(23);

    fn fds(f: &Fixture, at: u64, fds: &[i32]) {
        for (i, fd) in fds.iter().enumerate() {
            f.mem
                .write(GuestAddr(at + 4 * i as u64), &fd.to_le_bytes())
                .unwrap();
        }
    }

    /// A transfer on registered file `slot`.
    fn on_slot(opcode: u8, slot: i32, offset: u64, addr: u64, len: u32) -> [u8; 64] {
        let mut e = rw(opcode, slot as u64, offset, addr, len);
        e[1] = 1;
        e
    }

    /// An `IORING_OP_FILES_UPDATE` of `count` descriptors at `addr` from `offset`.
    fn files_update(offset: u32, addr: u64, count: u32) -> [u8; 64] {
        rw(FILES_UPDATE, 0, u64::from(offset), addr, count)
    }

    #[test]
    fn registered_files_stand_for_their_descriptors() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (list, buf) = (DATA + 0x100, DATA + 0x800);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]) as i32;
        f.mem.write(GuestAddr(DATA), b"/b\0").unwrap();
        let other = f.ret(2, &[DATA, 0o102, 0o600]) as i32;
        // None registered: a fixed transfer finds no file.
        assert_eq!(one(&mut f, &r, &on_slot(READ, 0, 0, buf, 1)), -9);
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), errno(ENXIO));
        // The registration's own checks, then each descriptor's.
        assert_eq!(f.ret(427, &[r.fd, 2, 0, 1]), errno(Errno::EFAULT));
        assert_eq!(f.ret(427, &[r.fd, 2, list, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 2, list, (1 << 20) + 1]), errno(EMFILE));
        assert_eq!(f.ret(427, &[r.fd, 2, 0x40_0000, 1]), errno(Errno::EFAULT));
        for bad in [99, -2, r.fd as i32] {
            fds(&f, list, &[fd, -1, bad]);
            assert_eq!(
                f.ret(427, &[r.fd, 2, list, 3]),
                errno(Errno::EBADF),
                "{bad}"
            );
        }
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), errno(ENXIO));
        // Above RLIMIT_NOFILE.
        f.mem.write_u64(GuestAddr(DATA + 0x400), 8).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 0x408), 8).unwrap();
        assert_eq!(f.ret(160, &[7, DATA + 0x400]), 0);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 9]), errno(EMFILE));
        fds(&f, list, &[fd, -1]);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 2]), 0);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 2]), errno(EBUSY));
        // The slot holds the file once its descriptor is closed.
        f.mem.write(GuestAddr(buf), b"hi").unwrap();
        assert_eq!(one(&mut f, &r, &on_slot(WRITE, 0, 0, buf, 2)), 2);
        assert_eq!(f.ret(3, &[fd as u64]), 0);
        assert_eq!(one(&mut f, &r, &on_slot(READ, 0, 0, buf + 0x10, 8)), 2);
        assert_eq!(bytes(&f, buf + 0x10, 2), b"hi");
        assert_eq!(one(&mut f, &r, &on_slot(FSYNC, 0, 0, 0, 0)), 0);
        for slot in [1, 2, -1] {
            assert_eq!(
                one(&mut f, &r, &on_slot(READ, slot, 0, buf, 1)),
                -9,
                "{slot}"
            );
        }
        // IORING_REGISTER_FILES_UPDATE.
        let update = DATA + 0x200;
        let set = |f: &Fixture, offset: u32, resv: u32| {
            f.mem
                .write(GuestAddr(update), &offset.to_le_bytes())
                .unwrap();
            f.mem
                .write(GuestAddr(update + 4), &resv.to_le_bytes())
                .unwrap();
            f.mem.write_u64(GuestAddr(update + 8), list).unwrap();
        };
        fds(&f, list, &[other]);
        set(&f, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 6, 0, 1]), errno(Errno::EFAULT));
        set(&f, 1, 1);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 1]), errno(Errno::EINVAL));
        set(&f, 2, 0);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 1]), errno(Errno::EINVAL));
        set(&f, u32::MAX, 0);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 2]), errno(EOVERFLOW));
        set(&f, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 1]), 1);
        assert_eq!(one(&mut f, &r, &on_slot(READ, 1, 0, buf, 1)), 0);
        // Skipped, emptied; a bad descriptor empties its slot first.
        fds(&f, list, &[-2, -1]);
        set(&f, 0, 0);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 2]), 2);
        assert_eq!(one(&mut f, &r, &on_slot(READ, 0, 0, buf, 2)), 2);
        assert_eq!(one(&mut f, &r, &on_slot(READ, 1, 0, buf, 1)), -9);
        fds(&f, list, &[99]);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 1]), errno(Errno::EBADF));
        assert_eq!(one(&mut f, &r, &on_slot(READ, 0, 0, buf, 2)), -9);
        fds(&f, list, &[other, 99]);
        assert_eq!(f.ret(427, &[r.fd, 6, update, 2]), 1);
        // Unregistering takes arguments of none, then they are gone.
        assert_eq!(f.ret(427, &[r.fd, 3, list, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), 0);
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), errno(ENXIO));
        assert_eq!(one(&mut f, &r, &on_slot(READ, 0, 0, buf, 1)), -9);
    }

    #[test]
    fn files_update_puts_files_in_slots_or_free_ones() {
        let mut f = fixture();
        let r = ring(&mut f);
        let list = DATA + 0x100;
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]) as i32;
        let alloc = u32::MAX;
        // Preparation's checks, then none registered.
        fds(&f, list, &[fd]);
        let mut e = files_update(0, list, 1);
        e[1] = 1;
        assert_eq!(one(&mut f, &r, &e), -22);
        let mut e = files_update(0, list, 1);
        e[28] = 1;
        assert_eq!(one(&mut f, &r, &e), -22);
        let mut e = files_update(0, list, 1);
        e[44] = 1;
        assert_eq!(one(&mut f, &r, &e), -22);
        assert_eq!(one(&mut f, &r, &files_update(0, list, 0)), -22);
        assert_eq!(one(&mut f, &r, &files_update(0, list, 1)), -6);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), -6);
        // Three empty slots, filled in order from the first.
        fds(&f, list, &[-1, -1, -1]);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 3]), 0);
        fds(&f, list, &[fd, fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 2)), 2);
        assert_eq!((u32_at(&f, list), u32_at(&f, list + 4)), (0, 1));
        fds(&f, list, &[fd, fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 2)), 1);
        assert_eq!((u32_at(&f, list), u32_at(&f, list + 4)), (2, fd as u32));
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), -(ENFILE.0));
        // An emptied slot is the next one.
        fds(&f, list, &[-1]);
        assert_eq!(one(&mut f, &r, &files_update(1, list, 1)), 1);
        fds(&f, list, &[fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), 1);
        assert_eq!(u32_at(&f, list), 1);
        // No ring, no unknown descriptor; at an offset, within the table.
        for bad in [r.fd as i32, 99] {
            fds(&f, list, &[-1]);
            assert_eq!(one(&mut f, &r, &files_update(0, list, 1)), 1);
            fds(&f, list, &[bad]);
            assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), -9, "{bad}");
        }
        assert_eq!(one(&mut f, &r, &files_update(3, list, 1)), -22);
        assert_eq!(
            one(&mut f, &r, &files_update(alloc - 1, list, 2)),
            -(EOVERFLOW.0)
        );
        // IORING_REGISTER_FILE_ALLOC_RANGE: only slot 2, which is taken.
        let range = DATA + 0x200;
        let set = |f: &Fixture, off: u32, len: u32, resv: u64| {
            f.mem.write(GuestAddr(range), &off.to_le_bytes()).unwrap();
            f.mem
                .write(GuestAddr(range + 4), &len.to_le_bytes())
                .unwrap();
            f.mem.write_u64(GuestAddr(range + 8), resv).unwrap();
        };
        // No argument, or a count, then one that cannot be read.
        assert_eq!(f.ret(427, &[r.fd, 25, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 25, range, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 25, 8, 0]), errno(Errno::EFAULT));
        set(&f, u32::MAX, 2, 0);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), errno(EOVERFLOW));
        set(&f, 2, 2, 0);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), errno(Errno::EINVAL));
        set(&f, 2, 1, 1);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), errno(Errno::EINVAL));
        set(&f, 2, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), 0);
        fds(&f, list, &[fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), -(ENFILE.0));
        fds(&f, list, &[-1]);
        assert_eq!(one(&mut f, &r, &files_update(2, list, 1)), 1);
        fds(&f, list, &[fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), 1);
        assert_eq!(u32_at(&f, list), 2);
        // Unregistered, the range is the whole of the next table.
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), 0);
        set(&f, 0, 0, 0);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), 0);
        set(&f, 0, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 25, range, 0]), errno(Errno::EINVAL));
        fds(&f, list, &[-1, -1]);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 2]), 0);
        fds(&f, list, &[fd]);
        assert_eq!(one(&mut f, &r, &files_update(alloc, list, 1)), 1);
        assert_eq!(u32_at(&f, list), 0);
    }

    #[test]
    fn a_registered_pipe_end_holds_the_pipe_open() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (ends, list) = (DATA + 0x300, DATA + 0x100);
        assert_eq!(f.ret(293, &[ends, 0o4000]), 0);
        let (read, write) = (u32_at(&f, ends), u32_at(&f, ends + 4));
        fds(&f, list, &[write as i32]);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 1]), 0);
        assert_eq!(f.ret(3, &[u64::from(write)]), 0);
        // A writer is left: no end of file.
        assert_eq!(f.ret(0, &[u64::from(read), DATA, 1]), errno(Errno::EAGAIN));
        f.mem.write(GuestAddr(DATA), b"x").unwrap();
        assert_eq!(one(&mut f, &r, &on_slot(WRITE, 0, HERE, DATA, 1)), 1);
        assert_eq!(f.ret(0, &[u64::from(read), DATA + 8, 4]), 1);
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), 0);
        assert_eq!(f.ret(0, &[u64::from(read), DATA, 1]), 0);
    }

    const PROVIDE_BUFFERS: u8 = 31;
    const REMOVE_BUFFERS: u8 = 32;
    const BUFFER: u32 = 1;
    const BUF_MORE: u32 = 1 << 4;
    const ENOBUFS: i32 = -105;

    /// Submits one entry, waits for it, and gives its result and flags.
    fn one_flags(f: &mut Fixture, r: &Ring, sqe: &[u8; 64]) -> (i32, u32) {
        let slot = u32_at(f, r.rings + 4) & 3;
        push(f, r, slot, sqe);
        assert_eq!(f.ret(426, &[r.fd, 1, 1, GETEVENTS]), 1);
        let head = u32_at(f, r.rings + 8);
        let at = r.rings + 64 + 16 * u64::from(head & 7);
        let done = (u32_at(f, at + 8) as i32, u32_at(f, at + 12));
        assert_eq!(reap(f, r).len(), 1);
        done
    }

    /// `count` buffers of `len` bytes at `addr` for group `bgid`, from ID
    /// `bid`.
    fn provide(count: i32, addr: u64, len: u32, bgid: u16, bid: u64) -> [u8; 64] {
        let mut e = rw(PROVIDE_BUFFERS, count as u64, bid, addr, len);
        e[40..42].copy_from_slice(&bgid.to_le_bytes());
        e
    }

    /// The entry `e` as another operation.
    fn as_op(mut e: [u8; 64], opcode: u8) -> [u8; 64] {
        e[0] = opcode;
        e
    }

    fn remove(count: i32, bgid: u16) -> [u8; 64] {
        as_op(provide(count, 0, 0, bgid, 0), REMOVE_BUFFERS)
    }

    /// A read of `len` bytes at `offset` of `fd` into a buffer of group
    /// `bgid`.
    fn select(opcode: u8, fd: u64, offset: u64, len: u32, bgid: u16) -> [u8; 64] {
        let mut e = rw(opcode, fd, offset, 0, len);
        e[1] = 1 << 5;
        e[40..42].copy_from_slice(&bgid.to_le_bytes());
        e
    }

    /// A file holding `contents`, open for reading.
    fn file(f: &mut Fixture, name: &[u8], contents: &[u8]) -> u64 {
        f.mem.write(GuestAddr(DATA), name).unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        f.mem.write(GuestAddr(DATA + 0x700), contents).unwrap();
        assert_eq!(
            f.ret(1, &[fd, DATA + 0x700, contents.len() as u64]),
            contents.len() as u64
        );
        fd
    }

    #[test]
    fn provided_buffers_are_chosen_first_first() {
        let mut f = fixture();
        let r = ring(&mut f);
        let buf = DATA + 0x800;
        let fd = file(&mut f, b"/b\0", b"hello world");
        // The preparation.
        for (e, res) in [
            (provide(0, buf, 4, 7, 0), -7),
            (provide(-1, buf, 4, 7, 0), -7),
            (provide(65537, buf, 4, 7, 0), -7),
            (provide(1, buf, 0, 7, 0), -22),
            (provide(2, u64::MAX - 4, 4, 7, 0), -75),
            (provide(1, 1 << 63, 4, 7, 0), -14),
            (provide(1, buf, 4, 7, 65536), -7),
            (provide(2, buf, 4, 7, 65535), -22),
            (remove(0, 7), -22),
            (remove(65537, 7), -22),
            (as_op(provide(1, buf, 0, 7, 0), REMOVE_BUFFERS), -22),
            (remove(1, 7), -2),
        ] {
            assert_eq!(one_flags(&mut f, &r, &e), (res, 0), "{:?}", &e[..30]);
        }
        let mut flagged = provide(1, buf, 4, 7, 0);
        flagged[28] = 1;
        assert_eq!(one(&mut f, &r, &flagged), -22);
        // Two of 4 bytes, IDs 10 and 11, used first first.
        assert_eq!(one(&mut f, &r, &provide(2, buf, 4, 7, 10)), 0);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 7)),
            (4, BUFFER | 10 << 16)
        );
        assert_eq!(bytes(&f, buf, 4), b"hell");
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 4, 2, 7)),
            (2, BUFFER | 11 << 16)
        );
        assert_eq!(bytes(&f, buf + 4, 2), b"o ");
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 7)),
            (ENOBUFS, 0)
        );
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 8)),
            (ENOBUFS, 0)
        );
        // A read that fails once it chose one uses it.
        let iov = DATA + 0x600;
        assert_eq!(one(&mut f, &r, &provide(1, buf, 4, 7, 3)), 0);
        f.mem.write_u64(GuestAddr(iov), 0).unwrap();
        f.mem.write_u64(GuestAddr(iov + 8), 3).unwrap();
        let mut vectored = select(READV, fd, 6, 1, 7);
        vectored[16..24].copy_from_slice(&iov.to_le_bytes());
        assert_eq!(
            one_flags(&mut f, &r, &vectored),
            (3, BUFFER | 3 << 16),
            "the vector's length"
        );
        assert_eq!(bytes(&f, buf, 3), b"wor");
        f.mem.write(GuestAddr(DATA), b"/b\0").unwrap();
        let wronly = f.ret(2, &[DATA, 1]);
        assert_eq!(one(&mut f, &r, &provide(1, buf, 4, 7, 4)), 0);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, wronly, 0, 0, 7)),
            (-9, BUFFER | 4 << 16)
        );
        // Removing takes what there is, and the group stays.
        assert_eq!(one(&mut f, &r, &provide(3, buf, 4, 7, 0)), 0);
        assert_eq!(one(&mut f, &r, &remove(2, 7)), 2);
        assert_eq!(one(&mut f, &r, &remove(5, 7)), 1);
        assert_eq!(one(&mut f, &r, &remove(5, 7)), 0);
    }

    /// Registers a ring of `entries` buffers for group `bgid` at `addr`.
    fn pbuf(f: &mut Fixture, r: &Ring, addr: u64, entries: u32, bgid: u16, flags: u16) -> u64 {
        let reg = DATA + 0x500;
        f.mem.write(GuestAddr(reg), &[0; 40]).unwrap();
        f.mem.write_u64(GuestAddr(reg), addr).unwrap();
        f.mem
            .write(GuestAddr(reg + 8), &entries.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(reg + 12), &bgid.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(reg + 14), &flags.to_le_bytes())
            .unwrap();
        f.ret(427, &[r.fd, 22, reg, 1])
    }

    /// Puts buffer `bid` of `len` bytes at `addr` in entry `index` of the
    /// ring at `ring`.
    fn entry(f: &Fixture, ring: u64, index: u64, addr: u64, len: u32, bid: u16) {
        let at = ring + 16 * index;
        f.mem.write_u64(GuestAddr(at), addr).unwrap();
        f.mem.write(GuestAddr(at + 8), &len.to_le_bytes()).unwrap();
        f.mem.write(GuestAddr(at + 12), &bid.to_le_bytes()).unwrap();
    }

    fn tail(f: &Fixture, ring: u64, tail: u16) {
        f.mem
            .write(GuestAddr(ring + 14), &tail.to_le_bytes())
            .unwrap();
    }

    fn head(f: &mut Fixture, r: &Ring, bgid: u32) -> u64 {
        let status = DATA + 0x500;
        f.mem.write(GuestAddr(status), &[0; 40]).unwrap();
        f.mem.write(GuestAddr(status), &bgid.to_le_bytes()).unwrap();
        let done = f.ret(427, &[r.fd, 26, status, 1]);
        if done != 0 {
            return done;
        }
        u64::from(u32_at(f, status + 4))
    }

    #[test]
    fn buffer_rings_register_as_linux_checks_them() {
        let mut f = fixture();
        let r = ring(&mut f);
        let einval = errno(Errno::EINVAL);
        let page = f.ret(9, &[0, 4096, 3, 0x22, u64::MAX, 0]);
        assert_eq!(f.ret(427, &[r.fd, 22, 0, 1]), einval);
        assert_eq!(f.ret(427, &[r.fd, 22, DATA, 2]), einval);
        assert_eq!(f.ret(427, &[r.fd, 26, 0, 1]), einval);
        for (entries, flags) in [(3, 0), (0, 0), (65536, 0), (2, 4)] {
            assert_eq!(pbuf(&mut f, &r, page, entries, 1, flags), einval);
        }
        assert_eq!(pbuf(&mut f, &r, 0, 2, 1, 0), errno(Errno::EFAULT));
        assert_eq!(pbuf(&mut f, &r, page + 8, 2, 1, 0), einval);
        assert_eq!(pbuf(&mut f, &r, 0x7000_0000, 2, 1, 0), errno(Errno::EFAULT));
        assert_eq!(pbuf(&mut f, &r, page, 2, 1, 0), 0);
        assert_eq!(pbuf(&mut f, &r, page, 2, 1, 0), errno(Errno(17)));
        // The kernel's pages, whose address is not looked at, map at
        // their offset; a ring in the program's memory does not.
        assert_eq!(pbuf(&mut f, &r, 8, 1, 2, 1), 0);
        let mapped = f.ret(9, &[0, 4096, 3, MAP_SHARED, r.fd, 0x8000_0000 | 2 << 16]);
        assert!(mapped < 1 << 47, "{mapped:#x}");
        assert_eq!(
            f.ret(9, &[0, 4096, 3, MAP_SHARED, r.fd, 0x8000_0000 | 1 << 16]),
            errno(Errno::ENOMEM)
        );
        assert_eq!(
            f.ret(9, &[0, 4096, 3, MAP_SHARED, r.fd, 0x8000_0000 | 3 << 16]),
            errno(Errno::ENOMEM)
        );
        // An empty group of provided buffers gives way; one with some, not.
        assert_eq!(one(&mut f, &r, &provide(1, DATA, 4, 3, 0)), 0);
        assert_eq!(pbuf(&mut f, &r, page, 2, 3, 0), errno(Errno(17)));
        assert_eq!(one(&mut f, &r, &remove(1, 3)), 1);
        assert_eq!(pbuf(&mut f, &r, page, 2, 3, 0), 0);
        // Provided buffers do not go in a ring.
        assert_eq!(one(&mut f, &r, &provide(1, DATA, 4, 3, 0)), -22);
        assert_eq!(one(&mut f, &r, &remove(1, 3)), -22);
        // The status, and unregistering.
        assert_eq!(head(&mut f, &r, 1), 0);
        assert_eq!(head(&mut f, &r, 9), errno(Errno::ENOENT));
        assert_eq!(head(&mut f, &r, 65536 + 1), errno(Errno::ENOENT));
        let reg = DATA + 0x500;
        f.mem.write(GuestAddr(reg), &[0; 40]).unwrap();
        f.mem
            .write(GuestAddr(reg + 12), &1u16.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(reg + 14), &1u16.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(427, &[r.fd, 23, reg, 1]), einval);
        f.mem
            .write(GuestAddr(reg + 14), &0u16.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(427, &[r.fd, 23, reg, 1]), 0);
        assert_eq!(f.ret(427, &[r.fd, 23, reg, 1]), errno(Errno::ENOENT));
        assert_eq!(one(&mut f, &r, &provide(1, DATA, 4, 4, 0)), 0);
        f.mem
            .write(GuestAddr(reg + 12), &4u16.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(427, &[r.fd, 23, reg, 1]), einval);
        assert_eq!(head(&mut f, &r, 4), einval);
    }

    #[test]
    fn reads_take_buffers_from_rings() {
        let mut f = fixture();
        let r = ring(&mut f);
        let buf = DATA + 0x800;
        let fd = file(&mut f, b"/c\0", b"abcdefghij");
        let page = f.ret(9, &[0, 4096, 3, 0x22, u64::MAX, 0]);
        assert_eq!(pbuf(&mut f, &r, page, 2, 1, 0), 0);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 1)),
            (ENOBUFS, 0)
        );
        entry(&f, page, 0, buf, 4, 5);
        entry(&f, page, 1, buf + 4, 4, 6);
        tail(&f, page, 2);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 1)),
            (4, BUFFER | 5 << 16)
        );
        assert_eq!(bytes(&f, buf, 4), b"abcd");
        assert_eq!(head(&mut f, &r, 1), 1);
        // A regular file cannot be polled: its buffer goes as it is chosen,
        // even if the read then fails.
        f.mem.write(GuestAddr(DATA), b"/c\0").unwrap();
        let wronly = f.ret(2, &[DATA, 1]);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, wronly, 0, 0, 1)),
            (-9, BUFFER | 6 << 16)
        );
        assert_eq!(head(&mut f, &r, 1), 2);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 0, 1)),
            (ENOBUFS, 0)
        );
        // With IOU_PBUF_RING_INC a read uses what it may take of one.
        assert_eq!(pbuf(&mut f, &r, 8, 1, 2, 1 | 2), 0);
        let mapped = f.ret(9, &[0, 4096, 3, MAP_SHARED, r.fd, 0x8000_0000 | 2 << 16]);
        entry(&f, mapped, 0, buf, 10, 9);
        tail(&f, mapped, 1);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 0, 4, 2)),
            (4, BUFFER | BUF_MORE | 9 << 16)
        );
        assert_eq!(f.mem.read_u64(GuestAddr(mapped)).unwrap(), buf + 4);
        assert_eq!(u32_at(&f, mapped + 8), 6);
        assert_eq!(head(&mut f, &r, 2), 0);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, fd, 4, 0, 2)),
            (6, BUFFER | 9 << 16)
        );
        assert_eq!(bytes(&f, buf + 4, 6), b"efghij");
        assert_eq!(head(&mut f, &r, 2), 1);
    }

    #[test]
    fn a_pipe_uses_its_ring_buffer_once_the_read_is_done() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (ends, buf) = (DATA + 0x300, DATA + 0x800);
        assert_eq!(f.ret(293, &[ends, 0o4000]), 0);
        let (read, write) = (u64::from(u32_at(&f, ends)), u64::from(u32_at(&f, ends + 4)));
        let page = f.ret(9, &[0, 4096, 3, 0x22, u64::MAX, 0]);
        assert_eq!(pbuf(&mut f, &r, page, 1, 1, 2), 0);
        entry(&f, page, 0, buf, 8, 3);
        tail(&f, page, 1);
        // A read that would wait leaves the buffer.
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, read, HERE, 0, 1)),
            (-11, 0)
        );
        assert_eq!(head(&mut f, &r, 1), 0);
        f.mem.write(GuestAddr(DATA), b"xyz").unwrap();
        assert_eq!(f.ret(1, &[write, DATA, 3]), 3);
        // It uses what it read.
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, read, HERE, 0, 1)),
            (3, BUFFER | BUF_MORE | 3 << 16)
        );
        assert_eq!(bytes(&f, buf, 3), b"xyz");
        assert_eq!(u32_at(&f, page + 8), 5);
        assert_eq!(head(&mut f, &r, 1), 0);
        // Provided buffers go as they are chosen.
        assert_eq!(one(&mut f, &r, &provide(1, buf, 4, 2, 0)), 0);
        assert_eq!(
            one_flags(&mut f, &r, &select(READ, read, HERE, 0, 2)),
            (-11, BUFFER)
        );
        assert_eq!(one(&mut f, &r, &remove(1, 2)), 0);
    }

    /// Submits `entries` at once, waiting for none, and gives every
    /// completion.
    fn batch(f: &mut Fixture, r: &Ring, entries: &[[u8; 64]]) -> Vec<(u64, i32)> {
        for e in entries {
            let slot = u32_at(f, r.rings + 4) & 3;
            push(f, r, slot, e);
        }
        let n = entries.len() as u64;
        assert_eq!(f.ret(426, &[r.fd, n, 0, GETEVENTS]), n);
        reap(f, r)
    }

    /// An `IORING_OP_NOP` with `nop_flags`, a file, a registered buffer's
    /// index and a result.
    fn nop(user_data: u64, flags: u32, fd: i32, index: u16, result: i32) -> [u8; 64] {
        let mut e = sqe(0, user_data);
        e[4..8].copy_from_slice(&fd.to_le_bytes());
        e[24..28].copy_from_slice(&result.to_le_bytes());
        e[28..32].copy_from_slice(&flags.to_le_bytes());
        e[40..42].copy_from_slice(&index.to_le_bytes());
        e
    }

    #[test]
    fn nops_look_for_files_and_buffers_as_linux_7_does() {
        const INJECT: u32 = 1;
        const FILE: u32 = 1 << 1;
        const FIXED_FILE: u32 = 1 << 2;
        const FIXED_BUFFER: u32 = 1 << 3;
        const TW: u32 = 1 << 4;
        const SKIP: u8 = 1 << 6;
        let skip = |mut e: [u8; 64]| {
            e[1] = SKIP;
            e
        };
        let mut f = fixture();
        let r = ring(&mut f);
        let (list, iov) = (DATA + 0x100, DATA + 0x200);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]) as i32;
        fds(&f, list, &[-1, fd]);
        assert_eq!(f.ret(427, &[r.fd, 2, list, 2]), 0);
        iovecs(&f, iov, &[(DATA + 0x800, 16)]);
        assert_eq!(f.ret(427, &[r.fd, 0, iov, 1]), 0);
        // Unknown flags, and 32-byte completions no ring has.
        assert_eq!(batch(&mut f, &r, &[nop(1, 1 << 6, 0, 0, 0)]), [(1, -22)]);
        assert_eq!(batch(&mut f, &r, &[nop(2, 1 << 5, 0, 0, 0)]), [(2, -22)]);
        assert_eq!(batch(&mut f, &r, &[nop(3, TW | INJECT, 0, 0, 3)]), [(3, 3)]);
        // A file it does not find is EBADF, which fails it.
        let file = FILE | INJECT;
        assert_eq!(batch(&mut f, &r, &[nop(4, file, fd, 0, 5)]), [(4, 5)]);
        assert_eq!(batch(&mut f, &r, &[nop(5, file, 99, 0, 5)]), [(5, -9)]);
        let fixed = FILE | FIXED_FILE;
        assert_eq!(batch(&mut f, &r, &[skip(nop(6, fixed, 1, 0, 0))]), []);
        assert_eq!(
            batch(&mut f, &r, &[skip(nop(7, fixed, 0, 0, 0))]),
            [(7, -9)]
        );
        assert_eq!(
            batch(&mut f, &r, &[skip(nop(8, fixed, 2, 0, 0))]),
            [(8, -9)]
        );
        assert_eq!(batch(&mut f, &r, &[skip(nop(9, FIXED_FILE, 0, 0, 0))]), []);
        // IOSQE_FIXED_FILE names a registered one too.
        let mut e = nop(14, file, fd, 0, 5);
        e[1] = 1;
        assert_eq!(batch(&mut f, &r, &[e]), [(14, -9)]);
        let mut e = nop(15, file, 1, 0, 5);
        e[1] = 1;
        assert_eq!(batch(&mut f, &r, &[e]), [(15, 5)]);
        // A registered buffer it does not find is EFAULT.
        let buffer = FIXED_BUFFER;
        assert_eq!(batch(&mut f, &r, &[skip(nop(10, buffer, 0, 0, 0))]), []);
        assert_eq!(
            batch(&mut f, &r, &[skip(nop(11, buffer, 0, 1, 0))]),
            [(11, -14)]
        );
        // A failed one ends its link.
        let mut head = nop(12, FILE, 99, 0, 0);
        head[1] = 1 << 2;
        assert_eq!(
            batch(&mut f, &r, &[head, nop(13, 0, 0, 0, 0)]),
            [(12, -9), (13, -125)]
        );
    }

    #[test]
    fn tagged_files_post_their_tags_once_let_go() {
        let mut f = fixture();
        let r = ring(&mut f);
        let (list, tags, arg, buf) = (DATA + 0x100, DATA + 0x200, DATA + 0x300, DATA + 0x800);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]) as i32;
        let set_tags = |f: &Fixture, values: &[u64]| {
            for (i, &tag) in values.iter().enumerate() {
                f.mem
                    .write_u64(GuestAddr(tags + 8 * i as u64), tag)
                    .unwrap();
            }
        };
        // struct io_uring_rsrc_register.
        let register = |f: &Fixture, nr: u32, flags: u32, resv: u64, data: u64, tags: u64| {
            f.mem.write(GuestAddr(arg), &nr.to_le_bytes()).unwrap();
            f.mem
                .write(GuestAddr(arg + 4), &flags.to_le_bytes())
                .unwrap();
            f.mem.write_u64(GuestAddr(arg + 8), resv).unwrap();
            f.mem.write_u64(GuestAddr(arg + 16), data).unwrap();
            f.mem.write_u64(GuestAddr(arg + 24), tags).unwrap();
        };
        fds(&f, list, &[fd, -1, fd]);
        set_tags(&f, &[7, 0, 9]);
        register(&f, 3, 0, 0, list, tags);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 24]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 13, 0, 32]), errno(Errno::EFAULT));
        for (nr, flags, resv, data) in [
            (0, 0, 0, list),
            (3, 0, 1, list),
            (3, 2, 0, list),
            (3, 1, 0, list),
        ] {
            register(&f, nr, flags, resv, data, tags);
            assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), errno(Errno::EINVAL));
        }
        register(&f, 3, 0, 0, list, 8);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), errno(Errno::EFAULT));
        // A tag for an empty slot fails it, and no tag is posted.
        set_tags(&f, &[7, 5, 9]);
        register(&f, 3, 0, 0, list, tags);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), errno(Errno::EINVAL));
        assert_eq!(reap(&mut f, &r), []);
        set_tags(&f, &[7, 0, 9]);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), 0);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), errno(EBUSY));
        // struct io_uring_rsrc_update2.
        let update = |f: &Fixture, offset: u32, resv: u32, tags: u64, nr: u32, resv2: u32| {
            f.mem.write(GuestAddr(arg), &offset.to_le_bytes()).unwrap();
            f.mem
                .write(GuestAddr(arg + 4), &resv.to_le_bytes())
                .unwrap();
            f.mem.write_u64(GuestAddr(arg + 8), list).unwrap();
            f.mem.write_u64(GuestAddr(arg + 16), tags).unwrap();
            f.mem.write(GuestAddr(arg + 24), &nr.to_le_bytes()).unwrap();
            f.mem
                .write(GuestAddr(arg + 28), &resv2.to_le_bytes())
                .unwrap();
        };
        update(&f, 0, 0, tags, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 14, arg, 24]), errno(Errno::EINVAL));
        assert_eq!(f.ret(427, &[r.fd, 14, 0, 32]), errno(Errno::EFAULT));
        for (resv, nr, resv2) in [(0, 0, 0), (1, 1, 0), (0, 1, 1)] {
            update(&f, 0, resv, tags, nr, resv2);
            assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), errno(Errno::EINVAL));
        }
        update(&f, u32::MAX, 0, tags, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), errno(EOVERFLOW));
        update(&f, 0, 0, tags, 1, 0);
        set_tags(&f, &[3]);
        for skip_or_clear in [-2, -1] {
            fds(&f, list, &[skip_or_clear]);
            assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), errno(Errno::EINVAL));
        }
        fds(&f, list, &[fd]);
        update(&f, 0, 0, 8, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), errno(Errno::EFAULT));
        assert_eq!(reap(&mut f, &r), []);
        // Slot 0's file goes: its tag at once.
        set_tags(&f, &[11]);
        update(&f, 0, 0, tags, 1, 0);
        assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), 1);
        assert_eq!(reap(&mut f, &r), [(7, 0)]);
        // Within a submission, before its completions.
        fds(&f, list, &[-1]);
        assert_eq!(
            batch(&mut f, &r, &[sqe(0, 30), files_update(2, list, 1)]),
            [(9, 0), (30, 0), (1, 1)]
        );
        // After them while a request of it holds the file.
        assert_eq!(
            batch(
                &mut f,
                &r,
                &[on_slot(READ, 0, 0, buf, 1), files_update(0, list, 1)]
            ),
            [(1, 0), (1, 1), (11, 0)]
        );
        // Unregistering lets go of the last slot first.
        fds(&f, list, &[fd, -1, fd]);
        set_tags(&f, &[13, 0, 14]);
        update(&f, 0, 0, tags, 3, 0);
        assert_eq!(f.ret(427, &[r.fd, 14, arg, 32]), 3);
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), 0);
        assert_eq!(reap(&mut f, &r), [(14, 0), (13, 0)]);
        // Sparse, with IORING_RSRC_REGISTER_SPARSE or no descriptors.
        register(&f, 2, 1, 0, 0, tags);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), errno(Errno::EINVAL));
        set_tags(&f, &[0, 0]);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), 0);
        assert_eq!(f.ret(427, &[r.fd, 3, 0, 0]), 0);
        register(&f, 2, 0, 0, 0, tags);
        assert_eq!(f.ret(427, &[r.fd, 13, arg, 32]), 0);
        assert_eq!(one(&mut f, &r, &on_slot(READ, 1, 0, buf, 1)), -9);
    }
}

mod vectored_flags {
    use super::*;
    const PREADV2: u64 = 327;
    const PWRITEV2: u64 = 328;
    const HERE: u64 = u64::MAX;
    /// One iovec at `at` for `len` bytes at `buffer`.
    fn iovec(f: &Fixture, at: u64, buffer: u64, len: u64) {
        f.mem.write_u64(GuestAddr(at), buffer).unwrap();
        f.mem.write_u64(GuestAddr(at + 8), len).unwrap();
    }
    fn contents(f: &mut Fixture, fd: u64) -> Vec<u8> {
        let size = f.ret(5, &[fd, DATA + 0xf00]);
        assert_eq!(size, 0);
        let size = f.mem.read_u64(GuestAddr(DATA + 0xf00 + 48)).unwrap();
        let mut bytes = vec![0; size as usize];
        assert_eq!(f.ret(17, &[fd, DATA + 0xe00, size, 0]), size);
        f.mem.read(GuestAddr(DATA + 0xe00), &mut bytes).unwrap();
        bytes
    }
    #[test]
    fn preadv2_and_pwritev2_take_an_offset_or_the_position() {
        let mut f = fixture();
        let (iov, put, got) = (DATA + 0x300, DATA + 0x400, DATA + 0x500);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        f.mem.write(GuestAddr(put), b"abcdefXYZ").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        assert_eq!(f.ret(1, &[fd, put, 6]), 6);
        // At an offset: the position stays.
        iovec(&f, iov, put + 6, 3);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 1, 0, 0]), 3);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 6);
        assert_eq!(contents(&mut f, fd), b"aXYZef");
        iovec(&f, iov, got, 4);
        assert_eq!(f.ret(PREADV2, &[fd, iov, 1, 2, 0, 0]), 4);
        let mut read = [0; 4];
        f.mem.read(GuestAddr(got), &mut read).unwrap();
        assert_eq!(&read, b"YZef");
        // -1 is the position, which moves; the high word is shifted out.
        assert_eq!(f.ret(8, &[fd, 3, 0]), 3);
        assert_eq!(f.ret(PREADV2, &[fd, iov, 1, HERE, 7, 0]), 3);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 6);
        iovec(&f, iov, put, 2);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, HERE, 0, 0]), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 8);
        // Any other negative offset is EINVAL.
        assert_eq!(
            f.ret(PREADV2, &[fd, iov, 1, -2i64 as u64, 0, 0]),
            errno(Errno::EINVAL)
        );
    }
    #[test]
    fn dontcache_needs_a_file_system_with_it_and_nosignal_spares_sigpipe() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        f.mem.write(GuestAddr(buf), b"ab").unwrap();
        iovec(&f, iov, buf, 2);
        assert_eq!(f.ret(22, &[DATA + 0x500]), 0);
        let mut ends = [0; 8];
        f.mem.read(GuestAddr(DATA + 0x500), &mut ends).unwrap();
        let reader = u64::from(u32::from_le_bytes(ends[..4].try_into().unwrap()));
        let writer = u64::from(u32::from_le_bytes(ends[4..].try_into().unwrap()));
        // A pipe and a memfd (shmem) have no FOP_DONTCACHE.
        assert_eq!(
            f.ret(PWRITEV2, &[writer, iov, 1, HERE, 0, 0x80]),
            errno(Errno::EOPNOTSUPP)
        );
        f.mem.write(GuestAddr(DATA), b"m\0").unwrap();
        let memfd = f.ret(319, &[DATA, 0]);
        assert_eq!(
            f.ret(PWRITEV2, &[memfd, iov, 1, 0, 0, 0x80]),
            errno(Errno::EOPNOTSUPP)
        );
        assert_eq!(f.ret(PWRITEV2, &[memfd, iov, 1, 0, 0, 0x100]), 2);
        // Nor has a file the kernel makes.
        f.mem
            .write(GuestAddr(DATA), b"/proc/self/status\0")
            .unwrap();
        let status = f.ret(2, &[DATA, 0, 0]);
        assert_eq!(
            f.ret(PREADV2, &[status, iov, 1, 0, 0, 0x80]),
            errno(Errno::EOPNOTSUPP)
        );
        assert_eq!(f.ret(PREADV2, &[status, iov, 1, 0, 0, 0]), 2);
        // With no reader, NOSIGNAL gives EPIPE without SIGPIPE.
        assert_eq!(f.ret(3, &[reader]), 0);
        f.thread.state.signal_mask = 1 << 12;
        let sigpipe = |f: &Fixture| f.thread.state.pending.iter().any(|s| s.number == 13);
        assert_eq!(
            f.ret(PWRITEV2, &[writer, iov, 1, HERE, 0, 0x100]),
            errno(Errno(32))
        );
        assert!(!sigpipe(&f));
        assert_eq!(
            f.ret(PWRITEV2, &[writer, iov, 1, HERE, 0, 0]),
            errno(Errno(32))
        );
        assert!(sigpipe(&f));
    }
    /// A regular file of the file system `fs`, as a handle names it.
    struct OnFileSystem {
        fs: Option<u64>,
    }
    impl paludarium_host::FileHandle for OnFileSystem {
        fn file_system(&self) -> Option<u64> {
            self.fs
        }
        fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
            Ok(0)
        }
        fn write(&self, b: &[u8]) -> Result<usize, Errno> {
            Ok(b.len())
        }
        fn read_at(&self, _: u64, b: &mut [u8]) -> Result<usize, Errno> {
            b.fill(b'x');
            Ok(b.len())
        }
        fn write_at(&self, _: u64, b: &[u8]) -> Result<usize, Errno> {
            Ok(b.len())
        }
        fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
            Ok(0)
        }
        fn stat(&self) -> Result<paludarium_host::FileStat, Errno> {
            Ok(paludarium_host::FileStat {
                mode: 0o100_600,
                size: 8,
                ..Default::default()
            })
        }
        fn truncate(&self, _: u64) -> Result<(), Errno> {
            Ok(())
        }
        fn flock(&self, _: u32) -> Result<(), Errno> {
            Ok(())
        }
        fn flags(&self) -> u32 {
            2
        }
        fn set_flags(&self, _: u32) -> Result<(), Errno> {
            Ok(())
        }
    }
    #[test]
    fn file_systems_decide_nowait_and_dontcache() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        iovec(&f, iov, buf, 2);
        let refused = errno(Errno::EOPNOTSUPP);
        // (file system, NOWAIT read, NOWAIT write, DONTCACHE), as Linux
        // master's: 0 is a host's file system with no Linux number.
        for (fs, read, write, dontcache) in [
            (Some(0xef53), 2, refused, 2),                  // ext4
            (Some(0), 2, refused, 2),                       // a macOS or Windows host's
            (Some(0x5846_5342), 2, 2, 2),                   // xfs
            (Some(0x9123_683e), 2, 2, refused),             // btrfs
            (Some(0xf2f5_2010), 2, 2, refused),             // f2fs
            (Some(0x0102_1994), refused, refused, refused), // tmpfs
            (Some(0x794c_7630), refused, refused, refused), // overlayfs
            (None, refused, refused, refused),              // a file the kernel makes
        ] {
            let fd = u64::from(
                f.kernel
                    .files
                    .install(Arc::new(OnFileSystem { fs }), false, 1024)
                    .unwrap(),
            );
            let got = [
                f.ret(PREADV2, &[fd, iov, 1, 0, 0, 0x8]),
                f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x8]),
                f.ret(PREADV2, &[fd, iov, 1, 0, 0, 0x80]),
            ];
            assert_eq!(got, [read, write, dontcache], "{fs:x?}");
        }
        // A timerfd and /dev/null take NOWAIT too.
        let timer = f.ret(283, &[1, 0]);
        iovec(&f, iov + 16, buf, 8);
        assert_eq!(
            f.ret(PREADV2, &[timer, iov + 16, 1, HERE, 0, 0x8]),
            errno(Errno::EAGAIN)
        );
        f.mem.write(GuestAddr(DATA), b"/dev/null\0").unwrap();
        let null = f.ret(2, &[DATA, 2, 0]);
        assert_eq!(f.ret(PREADV2, &[null, iov, 1, HERE, 0, 0x8]), 0);
    }
    #[test]
    fn the_flags_are_checked_as_kiocb_set_rw_flags_checks_them() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        f.mem.write(GuestAddr(buf), b"abcdef").unwrap();
        let fd = f.ret(2, &[DATA, 0o102, 0o600]);
        assert_eq!(f.ret(1, &[fd, buf, 6]), 6);
        iovec(&f, iov, buf, 2);
        let read = |f: &mut Fixture, flags: u64| f.ret(PREADV2, &[fd, iov, 1, 0, 0, flags]);
        assert_eq!(read(&mut f, 0x200), errno(Errno::EOPNOTSUPP));
        assert_eq!(read(&mut f, 0x30), errno(Errno::EINVAL));
        // Any file takes NOSIGNAL. This in-memory file has no DONTCACHE nor
        // NOWAIT, as tmpfs has neither (see
        // `file_systems_decide_nowait_and_dontcache`).
        assert_eq!(read(&mut f, 0x100), 2);
        assert_eq!(read(&mut f, 0x80), errno(Errno::EOPNOTSUPP));
        assert_eq!(read(&mut f, 0x40), errno(Errno::EOPNOTSUPP)); // RWF_ATOMIC
        // HIPRI, DSYNC and SYNC read a regular file; tmpfs refuses NOWAIT.
        assert_eq!(read(&mut f, 0x7), 2);
        assert_eq!(read(&mut f, 0x8), errno(Errno::EOPNOTSUPP));
        // Only the low 32 bits are the flags (rwf_t is an int).
        assert_eq!(read(&mut f, 1 << 32), 2);
        // A transfer of nothing checks no flags.
        iovec(&f, iov + 16, buf, 0);
        assert_eq!(f.ret(PREADV2, &[fd, iov + 16, 1, 0, 0, 0x80]), 0);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov + 16, 1, HERE, 0, 0x80]), 0);
        // So does a write of it.
        assert_eq!(
            f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x8]),
            errno(Errno::EOPNOTSUPP)
        );
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x6]), 2); // DSYNC | SYNC
        // RWF_APPEND writes at the end; at an offset the position stays, at
        // the position it ends after what was written.
        assert_eq!(f.ret(8, &[fd, 1, 0]), 1);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x10]), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 1);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, HERE, 0, 0x10]), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 10);
        assert_eq!(contents(&mut f, fd), b"abcdefabab");
        // One that fails leaves the position where it was: past
        // RLIMIT_FSIZE it is EFBIG (with SIGXFSZ, ignored here).
        f.thread.state.signal_actions.insert(
            25,
            crate::SignalAction {
                handler: 1,
                ..Default::default()
            },
        );
        f.mem.write_u64(GuestAddr(DATA + 0x200), 4).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 0x208), 4).unwrap();
        assert_eq!(f.ret(160, &[1, DATA + 0x200]), 0); // setrlimit(RLIMIT_FSIZE)
        assert_eq!(f.ret(8, &[fd, 1, 0]), 1);
        assert_eq!(
            f.ret(PWRITEV2, &[fd, iov, 1, HERE, 0, 0x10]),
            errno(Errno(27))
        );
        assert_eq!(f.ret(8, &[fd, 0, 1]), 1);
        f.mem.write_u64(GuestAddr(DATA + 0x200), u64::MAX).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 0x208), u64::MAX).unwrap();
        assert_eq!(f.ret(160, &[1, DATA + 0x200]), 0);
        // NOAPPEND changes nothing for a file without O_APPEND.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x20]), 2);
    }
    #[test]
    fn noappend_writes_an_appending_file_at_the_offset_or_its_position() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        f.mem.write(GuestAddr(buf), b"abcdef").unwrap();
        let fd = f.ret(2, &[DATA, 0o2102, 0o600]);
        assert_eq!(f.ret(1, &[fd, buf, 6]), 6);
        f.mem.write(GuestAddr(buf), b"XY").unwrap();
        iovec(&f, iov, buf, 2);
        // At an offset: there, and the position stays.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 1, 0, 0x20]), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 6);
        assert_eq!(contents(&mut f, fd), b"aXYdef");
        // Past the end: the file grows to it.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 8, 0, 0x20]), 2);
        assert_eq!(contents(&mut f, fd), b"aXYdef\0\0XY");
        // At the position, which moves past it.
        assert_eq!(f.ret(8, &[fd, 2, 0]), 2);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, HERE, 0, 0x20]), 2);
        assert_eq!(f.ret(8, &[fd, 0, 1]), 4);
        assert_eq!(contents(&mut f, fd), b"aXXYef\0\0XY");
        // Without it, O_APPEND appends wherever asked.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0]), 2);
        assert_eq!(contents(&mut f, fd), b"aXXYef\0\0XYXY");
        // A read takes it too.
        assert_eq!(f.ret(PREADV2, &[fd, iov, 1, 0, 0, 0x20]), 2);
        // With RWF_APPEND too, no path is taken: kiocb_set_rw_flags refuses
        // the pair first.
        for at in [0, HERE] {
            assert_eq!(
                f.ret(PWRITEV2, &[fd, iov, 1, at, 0, 0x30]),
                errno(Errno::EINVAL)
            );
        }
        // An append-only file always appends: EPERM, for a read too.
        f.mem
            .write(GuestAddr(DATA + 0x500), &0x20u32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(16, &[fd, 0x4008_6602, DATA + 0x500]), 0);
        assert_eq!(
            f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0x20]),
            errno(Errno::EPERM)
        );
        assert_eq!(
            f.ret(PREADV2, &[fd, iov, 1, 0, 0, 0x20]),
            errno(Errno::EPERM)
        );
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0]), 2);
    }
    #[test]
    fn noappend_measures_rlimit_fsize_from_where_it_writes() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        f.mem.write(GuestAddr(DATA), b"/a\0").unwrap();
        f.mem.write(GuestAddr(buf), b"abcdef").unwrap();
        let fd = f.ret(2, &[DATA, 0o2102, 0o600]);
        assert_eq!(f.ret(1, &[fd, buf, 6]), 6);
        iovec(&f, iov, buf, 2);
        f.thread.state.signal_actions.insert(
            25,
            crate::SignalAction {
                handler: 1,
                ..Default::default()
            },
        );
        f.mem.write_u64(GuestAddr(DATA + 0x200), 4).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 0x208), 4).unwrap();
        assert_eq!(f.ret(160, &[1, DATA + 0x200]), 0); // setrlimit(RLIMIT_FSIZE)
        // Appending starts at the end, past the limit: EFBIG.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 0, 0, 0]), errno(Errno(27)));
        // NOAPPEND starts at the offset: all of it, then what is left.
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 1, 0, 0x20]), 2);
        assert_eq!(f.ret(PWRITEV2, &[fd, iov, 1, 3, 0, 0x20]), 1);
        assert_eq!(contents(&mut f, fd), b"aabaef");
    }
    #[test]
    fn nowait_needs_a_file_that_has_it_and_does_not_wait() {
        let mut f = fixture();
        let (iov, buf) = (DATA + 0x300, DATA + 0x400);
        iovec(&f, iov, buf, 8);
        // A pipe has FMODE_NOWAIT and reads only at -1; once empty, NOWAIT
        // gives EAGAIN.
        assert_eq!(f.ret(293, &[DATA + 0x100, 0]), 0);
        let fds = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap();
        let (r, w) = (fds & 0xffff_ffff, fds >> 32);
        f.mem.write(GuestAddr(buf), b"pipe").unwrap();
        assert_eq!(f.ret(1, &[w, buf, 4]), 4);
        assert_eq!(f.ret(PREADV2, &[r, iov, 1, 0, 0, 0]), errno(Errno::ESPIPE));
        assert_eq!(f.ret(PREADV2, &[r, iov, 1, HERE, 0, 0x8]), 4);
        assert_eq!(
            f.ret(PREADV2, &[r, iov, 1, HERE, 0, 0x8]),
            errno(Errno::EAGAIN)
        );
        // A terminal has no FMODE_NOWAIT.
        f.mem.write(GuestAddr(DATA), b"/dev/ptmx\0").unwrap();
        let terminal = f.ret(2, &[DATA, 0o2, 0]);
        if (terminal as i64) >= 0 {
            assert_eq!(
                f.ret(PREADV2, &[terminal, iov, 1, HERE, 0, 0x8]),
                errno(Errno::EOPNOTSUPP)
            );
        }
        // A socket and an eventfd have it: an empty one gives EAGAIN.
        assert_eq!(f.ret(53, &[1, 1, 0, DATA + 0x100]), 0);
        let socket = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap() & 0xffff_ffff;
        assert_eq!(
            f.ret(PREADV2, &[socket, iov, 1, HERE, 0, 0x8]),
            errno(Errno::EAGAIN)
        );
        let counter = f.ret(290, &[0, 0]);
        assert_eq!(
            f.ret(PREADV2, &[counter, iov, 1, HERE, 0, 0x8]),
            errno(Errno::EAGAIN)
        );
    }
    #[test]
    fn epoll_pwait2_reads_its_timeout_first_and_waits_as_epoll_pwait() {
        let mut f = fixture();
        let (events, timeout, event) = (DATA + 0x300, DATA + 0x400, DATA + 0x500);
        let epoll = f.ret(291, &[0]);
        let counter = f.ret(290, &[0, 0]);
        f.mem.write(GuestAddr(event), &1u32.to_le_bytes()).unwrap(); // EPOLLIN
        f.mem.write_u64(GuestAddr(event + 4), 77).unwrap();
        assert_eq!(f.ret(233, &[epoll, 1, counter, event]), 0);
        f.mem.write_u64(GuestAddr(timeout), 0).unwrap();
        f.mem.write_u64(GuestAddr(timeout + 8), 0).unwrap();
        assert_eq!(f.ret(441, &[epoll, events, 4, timeout, 0, 0]), 0);
        f.mem
            .write(GuestAddr(DATA + 0x600), &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(1, &[counter, DATA + 0x600, 8]), 8);
        // No timeout waits for ever; one is ready.
        assert_eq!(f.ret(441, &[epoll, events, 4, 0, 0, 0]), 1);
        assert_eq!(f.mem.read_u64(GuestAddr(events + 4)).unwrap(), 77);
        // The timeout comes first, then the mask, then the descriptor and
        // maxevents.
        assert_eq!(f.ret(441, &[99, events, 0, 8, 0, 0]), errno(Errno::EFAULT));
        f.mem
            .write_u64(GuestAddr(timeout + 8), 1_000_000_000)
            .unwrap();
        assert_eq!(
            f.ret(441, &[99, events, 0, timeout, 0, 0]),
            errno(Errno::EINVAL)
        );
        f.mem.write_u64(GuestAddr(timeout), -1i64 as u64).unwrap();
        f.mem.write_u64(GuestAddr(timeout + 8), 0).unwrap();
        assert_eq!(
            f.ret(441, &[99, events, 0, timeout, 0, 0]),
            errno(Errno::EINVAL)
        );
        f.mem.write_u64(GuestAddr(timeout), 0).unwrap();
        assert_eq!(
            f.ret(441, &[99, events, 1, timeout, event, 4]),
            errno(Errno::EINVAL)
        );
        assert_eq!(
            f.ret(441, &[99, events, 0, timeout, 0, 0]),
            errno(Errno::EBADF)
        );
        assert_eq!(
            f.ret(441, &[epoll, events, 0, timeout, 0, 0]),
            errno(Errno::EINVAL)
        );
        // epoll_wait and epoll_pwait check the descriptor before maxevents,
        // after the mask; a file that is no epoll is EINVAL after maxevents.
        assert_eq!(f.ret(232, &[99, events, 0, 0]), errno(Errno::EBADF));
        assert_eq!(f.ret(232, &[counter, events, 1, 0]), errno(Errno::EINVAL));
        assert_eq!(
            f.ret(281, &[99, events, 1, 0, event, 4]),
            errno(Errno::EINVAL)
        );
        // A huge timeout saturates rather than fails.
        f.mem.write_u64(GuestAddr(timeout), u64::MAX >> 1).unwrap();
        assert_eq!(f.ret(441, &[epoll, events, 4, timeout, 0, 0]), 1);
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
    fn so_error(f: &mut Fixture, fd: u64) -> u64 {
        f.mem.write_u64(GuestAddr(DATA + 0x308), 4).unwrap();
        assert_eq!(f.ret(55, &[fd, 1, 4, DATA + 0x300, DATA + 0x308]), 0);
        f.mem.read_u64(GuestAddr(DATA + 0x300)).unwrap() & 0xffff_ffff
    }
    #[test]
    fn an_error_after_a_message_is_kept_for_the_next_call() {
        let mut f = fixture();
        let (a, b) = datagram_pair(&mut f);
        let (send, receive, out, into) = (DATA + 0x400, DATA + 0x800, DATA + 0x600, DATA + 0xa00);
        vector(&f, send, out, 3, 5);
        assert_eq!(f.ret(SENDMMSG, &[a, send, 3, 0]), 3);
        // The third entry's iovec cannot be read: two came, and the fault
        // is the socket's, which SO_ERROR takes once.
        vector(&f, receive, into, 3, 8);
        f.mem.write_u64(GuestAddr(receive + 128 + 16), 8).unwrap();
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 3, 0x40, 0]), 2);
        assert_eq!(so_error(&mut f, b), 14);
        assert_eq!(so_error(&mut f, b), 0);
        // Kept, it comes before the message still queued, and only once.
        f.mem.write_u64(GuestAddr(receive + 64 + 16), 8).unwrap();
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 3, 0x40, 0]), 1);
        assert_eq!(f.ret(SENDMMSG, &[a, send, 1, 0]), 1);
        assert_eq!(
            f.ret(RECVMMSG, &[b, receive, 1, 0x40, 0]),
            errno(Errno::EFAULT)
        );
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 1, 0x40, 0]), 1);
        // MSG_ERRQUEUE skips that check, but a datagram's receive takes
        // the error first all the same (`__skb_try_recv_datagram`).
        assert_eq!(f.ret(SENDMMSG, &[a, send, 1, 0]), 1);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 3, 0x40, 0]), 1);
        assert_eq!(
            f.ret(RECVMMSG, &[b, receive, 1, 0x2040, 0]),
            errno(Errno::EFAULT)
        );
        assert_eq!(so_error(&mut f, b), 0);
        // An empty queue after a message (EAGAIN) is no error.
        assert_eq!(f.ret(SENDMMSG, &[a, send, 1, 0]), 1);
        vector(&f, receive, into, 3, 8);
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 3, 0x40, 0]), 1);
        assert_eq!(so_error(&mut f, b), 0);
    }
    #[test]
    fn a_stream_gives_a_kept_error_once_nothing_is_queued() {
        let mut f = fixture();
        assert_eq!(f.ret(53, &[1, 1, 0, DATA + 0x100]), 0);
        let fds = f.mem.read_u64(GuestAddr(DATA + 0x100)).unwrap();
        let (a, b) = (fds & 0xffff_ffff, fds >> 32);
        let (receive, into) = (DATA + 0x800, DATA + 0xa00);
        f.mem.write(GuestAddr(DATA + 0x200), b"hello").unwrap();
        assert_eq!(f.ret(1, &[a, DATA + 0x200, 5]), 5);
        vector(&f, receive, into, 2, 8);
        f.mem.write_u64(GuestAddr(receive + 64 + 16), 8).unwrap();
        assert_eq!(f.ret(RECVMMSG, &[b, receive, 2, 0x40, 0]), 1);
        assert_eq!(msg_len(&f, receive, 0), 5);
        // Data queued since comes first; then the error, before more waits.
        assert_eq!(f.ret(1, &[a, DATA + 0x200, 3]), 3);
        assert_eq!(f.ret(45, &[b, DATA + 0x300, 8, 0x40, 0, 0]), 3);
        assert_eq!(
            f.ret(45, &[b, DATA + 0x300, 8, 0x40, 0, 0]),
            errno(Errno::EFAULT)
        );
        assert_eq!(
            f.ret(45, &[b, DATA + 0x300, 8, 0x40, 0, 0]),
            errno(Errno::EAGAIN)
        );
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

mod old_forms {
    use super::*;
    /// The names and types of the `linux_dirent`s `getdents` wrote.
    fn entries(f: &Fixture, at: u64, len: u64) -> Vec<(String, u8)> {
        let mut b = vec![0; usize::try_from(len).unwrap()];
        f.mem.read(GuestAddr(at), &mut b).unwrap();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let size = usize::from(u16::from_le_bytes([b[i + 16], b[i + 17]]));
            let end = b[i + 18..].iter().position(|&c| c == 0).unwrap();
            let name = String::from_utf8(b[i + 18..i + 18 + end].to_vec()).unwrap();
            out.push((name, b[i + size - 1]));
            i += size;
        }
        out
    }
    #[test]
    fn getdents_writes_the_old_dirent() {
        let mut f = fixture();
        let (path, out) = (DATA, DATA + 0x100);
        f.mem.write(GuestAddr(path), b"/d\0").unwrap();
        assert_eq!(f.ret(83, &[path, 0o755]), 0);
        f.mem.write(GuestAddr(path), b"/d/abc\0").unwrap();
        let file = f.ret(2, &[path, 0o102, 0o600]);
        assert_eq!(f.ret(3, &[file]), 0);
        f.mem.write(GuestAddr(path), b"/d\0").unwrap();
        let dir = f.ret(2, &[path, 0o200000]);
        // Too small for the first entry, and a count Linux's `int` makes
        // negative: neither fits one.
        assert_eq!(f.ret(78, &[dir, out, 23]), errno(Errno::EINVAL));
        assert_eq!(f.ret(78, &[dir, out, 0x8000_0000]), errno(Errno::EINVAL));
        assert_eq!(f.ret(217, &[dir, out, 0x8000_0000]), errno(Errno::EINVAL));
        // ".", ".." and "abc" take 24 bytes each: 18, the name, its NUL and
        // the type, rounded up to 8.
        assert_eq!(f.ret(78, &[dir, out, 0x7fff_ffff]), 72);
        assert_eq!(
            entries(&f, out, 72),
            [(".".into(), 4), ("..".into(), 4), ("abc".into(), 8)]
        );
        // d_off of the last leads past it.
        assert_eq!(f.mem.read_u64(GuestAddr(out + 56)).unwrap(), 3);
        assert_eq!(f.ret(78, &[dir, out, 0x1000]), 0);
        // A file is not a directory, and an `O_PATH` one is refused first.
        f.mem.write(GuestAddr(path), b"/d/abc\0").unwrap();
        let file = f.ret(2, &[path, 0]);
        assert_eq!(f.ret(78, &[file, out, 0x1000]), errno(Errno::ENOTDIR));
        f.mem.write(GuestAddr(path), b"/d\0").unwrap();
        let only = f.ret(2, &[path, 0o10000000]);
        assert_eq!(f.ret(78, &[only, out, 0x1000]), errno(Errno::EBADF));
        assert_eq!(f.ret(78, &[99, out, 0x1000]), errno(Errno::EBADF));
    }
    #[test]
    fn eventfd_is_eventfd2_without_flags() {
        let mut f = fixture();
        let fd = f.ret(284, &[5]);
        assert_eq!(f.ret(72, &[fd, 3]), 2); // F_GETFL: O_RDWR
        assert_eq!(f.ret(72, &[fd, 1]), 0); // F_GETFD: no FD_CLOEXEC
        assert_eq!(f.ret(0, &[fd, DATA, 8]), 8);
        assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 5);
        // The register's upper half is not the count's.
        let fd = f.ret(284, &[1 << 32 | 7]);
        assert_eq!(f.ret(0, &[fd, DATA, 8]), 8);
        assert_eq!(f.mem.read_u64(GuestAddr(DATA)).unwrap(), 7);
    }
    #[test]
    fn ustat_counts_a_mounts_free_blocks_and_inodes() {
        let mut f = fixture();
        let (path, stat, fs, out) = (DATA, DATA + 0x100, DATA + 0x200, DATA + 0x300);
        f.mem.write(GuestAddr(path), b"/\0").unwrap();
        assert_eq!(f.ret(4, &[path, stat]), 0);
        let device = f.mem.read_u64(GuestAddr(stat)).unwrap();
        assert_eq!(device, 1);
        f.mem.write(GuestAddr(out), &[0xff; 32]).unwrap();
        assert_eq!(f.ret(136, &[device, out]), 0);
        assert_eq!(f.ret(137, &[path, fs]), 0);
        let word = |f: &Fixture, at: u64| f.mem.read_u64(GuestAddr(at)).unwrap();
        let free = word(&f, fs + 24);
        assert_eq!(word(&f, out) & 0xffff_ffff, free & 0xffff_ffff);
        assert_eq!(word(&f, out + 8), word(&f, fs + 48));
        assert_eq!([word(&f, out + 16), word(&f, out + 24)], [0, 0]);
        // No mount is 0:0 or 0:3 (`/dev/shm` is 0:2), nor 1:1; the minor's
        // high bits are above the major's.
        for dev in [0, 3, 0x101, 1 << 20 | 1] {
            assert_eq!(f.ret(136, &[dev, out]), errno(Errno::EINVAL));
        }
        // The register's upper half is not the device's.
        assert_eq!(f.ret(136, &[1 << 32 | 1, out]), 0);
        assert_eq!(f.ret(136, &[1, 0]), errno(Errno::EFAULT));
    }
    #[test]
    fn internal_file_systems_have_devices_of_their_own_with_nothing_free() {
        let mut f = fixture();
        let (name, stat, out) = (DATA, DATA + 0x100, DATA + 0x300);
        assert_eq!(f.ret(293, &[DATA + 0x80, 0]), 0);
        let pipe = f.mem.read_u64(GuestAddr(DATA + 0x80)).unwrap() & 0xffff_ffff;
        let socket = f.ret(41, &[1, 1, 0]);
        let eventfd = f.ret(290, &[0, 0]);
        let pid = f.ret(39, &[]);
        let pidfd = f.ret(434, &[pid, 0]);
        f.mem.write(GuestAddr(name), b"m\0").unwrap();
        let memfd = f.ret(319, &[name, 0]);
        f.mem
            .write(GuestAddr(name), b"/proc/self/ns/net\0")
            .unwrap();
        let namespace = f.ret(2, &[name, 0]);
        let secret = f.ret(447, &[0]);
        let mut devices = vec![1];
        for fd in [pipe, socket, eventfd, pidfd, memfd, namespace, secret] {
            assert_eq!(f.ret(5, &[fd, stat]), 0, "fd {fd}");
            let device = f.mem.read_u64(GuestAddr(stat)).unwrap();
            assert!(!devices.contains(&device), "fd {fd}: {device:#x}");
            devices.push(device);
            f.mem.write(GuestAddr(out), &[0xff; 32]).unwrap();
            assert_eq!(f.ret(136, &[device, out]), 0, "fd {fd}");
            let mut b = [0xffu8; 32];
            f.mem.read(GuestAddr(out), &mut b).unwrap();
            assert_eq!(b, [0; 32], "fd {fd}");
        }
        // Through /proc/self/fd too.
        f.mem
            .write(
                GuestAddr(name),
                format!("/proc/self/fd/{pipe}\0").as_bytes(),
            )
            .unwrap();
        assert_eq!(f.ret(4, &[name, stat]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(stat)).unwrap(), devices[1]);
        // statx's mount ID: a small one below mountinfo's, from 21.
        f.mem.write(GuestAddr(name), b"\0").unwrap();
        let statx = DATA + 0x400;
        assert_eq!(f.ret(332, &[pipe, name, 0x1000, 0x1000, statx]), 0);
        let id = f.mem.read_u64(GuestAddr(statx + 144)).unwrap();
        assert!((1..21).contains(&id), "{id}");
    }
    const MAP_SHARED: u64 = 1;
    const MAP_PRIVATE: u64 = 2;
    const MAP_ANONYMOUS: u64 = 0x20;
    #[test]
    fn remap_file_pages_maps_other_pages_of_shared_memory() {
        let mut f = fixture();
        let at = f.ret(9, &[0, 0x3000, 3, MAP_SHARED | MAP_ANONYMOUS, u64::MAX, 0]);
        for page in 0..3 {
            f.mem
                .write(GuestAddr(at + page * 0x1000), &[b'a' + page as u8])
                .unwrap();
        }
        // The first page shows the third; `start` and `size` are taken down
        // to whole pages and `flags` is not looked at.
        assert_eq!(f.ret(216, &[at + 5, 0x1fff, 0, 2, 0xffff]), 0);
        let read = |f: &Fixture, addr: u64| {
            let mut b = [0];
            f.mem.read(GuestAddr(addr), &mut b).unwrap();
            b[0]
        };
        assert_eq!(read(&f, at), b'c');
        f.mem.write(GuestAddr(at), b"z").unwrap();
        assert_eq!(read(&f, at + 0x2000), b'z');
        assert_eq!(read(&f, at + 0x1000), b'b');
        // Across both mappings of the same memory now.
        assert_eq!(f.ret(216, &[at, 0x2000, 0, 0, 0]), 0);
        assert_eq!([read(&f, at), read(&f, at + 0x1000)], [b'a', b'b']);
        // Linux's checks, in its order.
        assert_eq!(f.ret(216, &[at, 0x1000, 1, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(216, &[at, 0xfff, 0, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(
            f.ret(216, &[at, 0x1000, 0, u64::MAX, 0]),
            errno(Errno::EINVAL)
        );
        assert_eq!(f.ret(216, &[at, 0x4000, 0, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(
            f.ret(216, &[at, 0x1000, 0, 1 << 60, 0]),
            errno(Errno::EOVERFLOW)
        );
        assert_eq!(
            f.ret(216, &[0x4000_0000, 0x1000, 0, 0, 0]),
            errno(Errno::EINVAL)
        );
        let private = f.ret(9, &[0, 0x1000, 3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert_eq!(
            f.ret(216, &[private, 0x1000, 0, 0, 0]),
            errno(Errno::EINVAL)
        );
        // A different protection is another VMA.
        assert_eq!(f.ret(10, &[at + 0x1000, 0x1000, 1]), 0);
        assert_eq!(f.ret(216, &[at, 0x2000, 0, 0, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(216, &[at + 0x1000, 0x1000, 0, 2, 0]), 0);
        assert_eq!(read(&f, at + 0x1000), b'z');
    }
    #[test]
    fn remap_file_pages_of_a_file_reads_and_writes_its_pages() {
        let mut f = fixture();
        let path = DATA;
        f.mem.write(GuestAddr(path), b"/f\0").unwrap();
        let fd = f.ret(2, &[path, 0o102, 0o600]);
        for page in 0..3u8 {
            f.mem
                .write(GuestAddr(DATA + 0x100), &[b'0' + page])
                .unwrap();
            assert_eq!(
                f.ret(18, &[fd, DATA + 0x100, 1, u64::from(page) * 0x1000]),
                1
            );
        }
        assert_eq!(f.ret(77, &[fd, 0x3000]), 0);
        let at = f.ret(9, &[0, 0x1000, 3, MAP_SHARED, fd, 0]);
        assert_eq!(f.ret(216, &[at, 0x1000, 0, 2, 0]), 0);
        let mut b = [0];
        f.mem.read(GuestAddr(at), &mut b).unwrap();
        assert_eq!(&b, b"2");
        f.mem.write(GuestAddr(at + 1), b"w").unwrap();
        assert_eq!(f.ret(26, &[at, 0x1000, 4]), 0); // msync(MS_SYNC)
        assert_eq!(f.ret(17, &[fd, DATA + 0x100, 2, 0x2000]), 2);
        let mut b = [0; 2];
        f.mem.read(GuestAddr(DATA + 0x100), &mut b).unwrap();
        assert_eq!(&b, b"2w");
        // A file open only for reading gives no VM_SHARED.
        let only = f.ret(2, &[path, 0]);
        let read_only = f.ret(9, &[0, 0x1000, 1, MAP_SHARED, only, 0]);
        assert_eq!(
            f.ret(216, &[read_only, 0x1000, 0, 1, 0]),
            errno(Errno::EINVAL)
        );
    }
}

mod inotify {
    use super::*;
    const INIT1: u64 = 294;
    const ADD: u64 = 254;
    const RM: u64 = 255;
    const IN_NONBLOCK: u64 = 0x800;
    const BUF: u64 = DATA + 0x1000;
    /// The NUL-terminated `path`, at `at`.
    fn put(f: &Fixture, at: u64, path: &[u8]) -> u64 {
        f.mem.write(GuestAddr(at), path).unwrap();
        f.mem
            .write(GuestAddr(at + path.len() as u64), &[0])
            .unwrap();
        at
    }
    /// The events a read of `fd` gives: (wd, mask, cookie, name).
    fn events(f: &mut Fixture, fd: u64) -> Vec<(i32, u32, u32, Vec<u8>)> {
        let n = f.ret(0, &[fd, BUF, 0x1000]);
        if n == errno(Errno::EAGAIN) {
            return Vec::new();
        }
        let mut bytes = vec![0; n as usize];
        f.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let word = |i: usize| u32::from_le_bytes(bytes[at + i..at + i + 4].try_into().unwrap());
            let len = word(12) as usize;
            let name = bytes[at + 16..at + 16 + len]
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect();
            out.push((word(0) as i32, word(4), word(8), name));
            at += 16 + len;
        }
        out
    }
    fn masks(events: &[(i32, u32, u32, Vec<u8>)]) -> Vec<(i32, u32, &[u8])> {
        events
            .iter()
            .map(|(wd, mask, _, name)| (*wd, *mask, &name[..]))
            .collect()
    }
    /// The bytes of the file at `path`, read from its start.
    fn contents(f: &mut Fixture, path: &[u8]) -> Vec<u8> {
        let fd = f.ret(2, &[put(f, DATA + 0x800, path), 0, 0]);
        assert!((fd as i64) >= 0, "{}", String::from_utf8_lossy(path));
        let n = f.ret(0, &[fd, BUF, 0x800]);
        assert_eq!(f.ret(3, &[fd]), 0);
        let mut bytes = vec![0; n as usize];
        f.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        bytes
    }
    /// Writes `text` to the file at `path`: what the write returns.
    fn write_to(f: &mut Fixture, path: &[u8], text: &[u8]) -> u64 {
        let fd = f.ret(2, &[put(f, DATA + 0x800, path), 1, 0]);
        f.mem.write(GuestAddr(BUF), text).unwrap();
        let n = f.ret(1, &[fd, BUF, text.len() as u64]);
        assert_eq!(f.ret(3, &[fd]), 0);
        n
    }
    #[test]
    fn an_async_instance_signals_its_owner_for_each_event_it_queues() {
        let mut f = fixture();
        // Blocked, the signals stay pending to be looked at.
        f.thread.state.signal_mask = 1 << 39;
        let taken = |f: &Fixture| -> Vec<(i32, i64, i32)> {
            std::iter::from_fn(|| f.kernel.group.take_process_signal(1 << 39))
                .filter_map(|signal| signal.queued)
                .map(|info| {
                    let word = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
                    (
                        word(8),
                        i64::from_le_bytes(info[16..24].try_into().unwrap()),
                        word(24),
                    )
                })
                .collect()
        };
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        assert_eq!(f.ret(72, &[fd, 8, 1]), 0);
        assert_eq!(f.ret(72, &[fd, 9]), 1);
        assert_eq!(f.ret(72, &[fd, 10, 40]), 0);
        assert_eq!(f.ret(72, &[fd, 4, 0o20000 | 0o4000]), 0);
        assert_eq!(f.ret(72, &[fd, 3]), 0o20000 | 0o4000);
        let tmp = put(&f, DATA, b"/tmp");
        let wd = f.ret(ADD, &[fd, tmp, 0x104]);
        assert_eq!(wd, 1);
        let a = put(&f, DATA + 0x40, b"/tmp/a");
        let d = f.ret(2, &[a, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        // POLL_IN with its band, through the descriptor it was set on.
        assert_eq!(taken(&f), [(1, 0x41, fd as i32)]);
        // An event merged into the one before it queues nothing new.
        assert_eq!(f.ret(90, &[a, 0o600]), 0);
        assert_eq!(f.ret(90, &[a, 0o600]), 0);
        assert_eq!(taken(&f), [(1, 0x41, fd as i32)]);
        // Removing the watch queues its IN_IGNORED.
        assert_eq!(f.ret(RM, &[fd, wd]), 0);
        assert_eq!(taken(&f), [(1, 0x41, fd as i32)]);
        // Without O_ASYNC nothing comes; FIOASYNC turns it on again.
        assert_eq!(f.ret(72, &[fd, 4, 0o4000]), 0);
        let wd = f.ret(ADD, &[fd, tmp, 0x100]);
        let b = put(&f, DATA + 0x40, b"/tmp/b");
        let d = f.ret(2, &[b, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert!(taken(&f).is_empty());
        f.mem
            .write(GuestAddr(DATA + 0x300), &1i32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(16, &[fd, 0x5452, DATA + 0x300]), 0);
        assert_eq!(f.ret(72, &[fd, 3]) & 0o20000, 0o20000);
        // IN_DELETE is not watched, and IN_IGNORED is queued.
        assert_eq!(f.ret(87, &[b]), 0);
        assert!(taken(&f).is_empty());
        assert_eq!(f.ret(RM, &[fd, wd]), 0);
        assert_eq!(taken(&f), [(1, 0x41, fd as i32)]);
    }
    /// The lines of `/proc/self/fdinfo/<fd>` after the four every
    /// descriptor has.
    fn extra(f: &mut Fixture, fd: u64) -> Vec<String> {
        let path = format!("/proc/self/fdinfo/{fd}");
        let text = String::from_utf8(contents(f, path.as_bytes())).unwrap();
        text.lines().skip(4).map(str::to_owned).collect()
    }
    #[test]
    fn fdinfo_shows_what_each_kind_of_file_adds() {
        let mut f = fixture();
        // An eventfd: its count, a number, and whether it is a semaphore.
        let counter = f.ret(290, &[5, 1]);
        let lines = extra(&mut f, counter);
        assert_eq!(lines[0], format!("eventfd-count: {:>16}", "5"));
        assert!(lines[1].starts_with("eventfd-id: "));
        assert_eq!(lines[2], "eventfd-semaphore: 1");
        // A signalfd: the signals it takes, never SIGKILL.
        f.mem
            .write(
                GuestAddr(DATA),
                &(1u64 << 9 | 1 << 8 | 1 << 34).to_le_bytes(),
            )
            .unwrap();
        let signals = f.ret(289, &[u64::MAX, DATA, 8, 0]);
        assert_eq!(extra(&mut f, signals), ["sigmask:\t0000000400000200"]);
        // A timerfd, disarmed.
        let timer = f.ret(283, &[1, 0]);
        assert_eq!(
            extra(&mut f, timer),
            [
                "clockid: 1",
                "ticks: 0",
                "settime flags: 00",
                "it_value: (0, 0)",
                "it_interval: (0, 0)"
            ]
        );
        // An epoll: each target, with EPOLLERR and EPOLLHUP.
        let epoll = f.ret(291, &[0]);
        f.mem
            .write(GuestAddr(DATA), &0x8000_0001u32.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(DATA + 4), &0x1234u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(233, &[epoll, 1, counter, DATA]), 0);
        let lines = extra(&mut f, epoll);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with(&format!(
                "tfd: {counter:8} events: 80000019 data:             1234  pos:0 ino:"
            )),
            "{}",
            lines[0]
        );
        // Record locks: those set through the description, numbered.
        let path = put(&f, DATA + 0x100, b"/tmp/locked");
        let file = f.ret(2, &[path, 0o102, 0o600]);
        let other = f.ret(2, &[path, 0o2, 0]);
        let lock = |f: &mut Fixture, fd: u64, cmd: u64, kind: i16, start: i64, len: i64| {
            let mut raw = [0u8; 32];
            raw[0..2].copy_from_slice(&kind.to_le_bytes());
            raw[8..16].copy_from_slice(&start.to_le_bytes());
            raw[16..24].copy_from_slice(&len.to_le_bytes());
            f.mem.write(GuestAddr(DATA + 0x200), &raw).unwrap();
            f.ret(72, &[fd, cmd, DATA + 0x200])
        };
        assert_eq!(lock(&mut f, file, 6, 1, 0, 10), 0);
        assert_eq!(lock(&mut f, file, 6, 0, 20, 30), 0);
        // Merged into the first, the lock stays with its description.
        assert_eq!(lock(&mut f, other, 6, 1, 10, 5), 0);
        assert_eq!(lock(&mut f, other, 37, 1, 100, 1), 0);
        let fs = &f.kernel.files.fs();
        let device = paludarium_vfs::mount_device(&fs.mounts(), b"/tmp");
        let (major, minor) = paludarium_types::device_numbers(device);
        let ino = fs.metadata(b"/tmp/locked", true).unwrap().inode;
        let at = format!("{major:02x}:{minor:02x}:{ino}");
        assert_eq!(
            extra(&mut f, file),
            [
                format!("lock:\t1: POSIX  ADVISORY  WRITE 1 {at} 0 14"),
                format!("lock:\t2: POSIX  ADVISORY  READ 1 {at} 20 49"),
            ]
        );
        assert_eq!(
            extra(&mut f, other),
            [format!("lock:\t1: OFDLCK ADVISORY  WRITE -1 {at} 100 100")]
        );
    }
    #[test]
    fn fdinfo_shows_a_descriptions_flock_lock_before_its_record_locks() {
        let mut f = fixture();
        let path = put(&f, DATA, b"/tmp/flocked");
        let a = f.ret(2, &[path, 0o102, 0o600]);
        let b = f.ret(2, &[path, 0o2, 0]);
        let fs = &f.kernel.files.fs();
        let device = paludarium_vfs::mount_device(&fs.mounts(), b"/tmp");
        let (major, minor) = paludarium_types::device_numbers(device);
        let ino = fs.metadata(b"/tmp/flocked", true).unwrap().inode;
        let at = format!("{major:02x}:{minor:02x}:{ino}");
        let flock = |kind: &str| format!("lock:\t1: FLOCK  ADVISORY  {kind} 1 {at} 0 EOF");
        assert_eq!(f.ret(73, &[a, 1]), 0);
        let mut raw = [0u8; 32];
        raw[8..16].copy_from_slice(&5i64.to_le_bytes());
        raw[16..24].copy_from_slice(&5i64.to_le_bytes());
        f.mem.write(GuestAddr(DATA + 0x100), &raw).unwrap();
        assert_eq!(f.ret(72, &[a, 6, DATA + 0x100]), 0);
        assert_eq!(
            extra(&mut f, a),
            [
                flock("READ"),
                format!("lock:\t2: POSIX  ADVISORY  READ 1 {at} 5 9"),
            ]
        );
        // A shared lock of the other description, and asking again for the
        // kind it has, leave the first as it was.
        assert_eq!(f.ret(73, &[b, 1 | 4]), 0);
        assert_eq!(f.ret(73, &[a, 1]), 0);
        assert_eq!(extra(&mut f, a)[0], flock("READ"));
        assert_eq!(extra(&mut f, b), [flock("READ")]);
        // A change of kind that conflicts drops the lock it had.
        assert_eq!(f.ret(73, &[a, 2 | 4]), errno(Errno::EAGAIN));
        assert_eq!(
            extra(&mut f, a),
            [format!("lock:\t1: POSIX  ADVISORY  READ 1 {at} 5 9")]
        );
        assert_eq!(f.ret(73, &[b, 2]), 0);
        assert_eq!(extra(&mut f, b), [flock("WRITE")]);
        // A duplicate shares the description, and its lock.
        let c = f.ret(32, &[b]);
        assert_eq!(extra(&mut f, c), [flock("WRITE")]);
        assert_eq!(f.ret(73, &[c, 8]), 0);
        assert!(extra(&mut f, b).is_empty());
        // An invalid operation changes nothing.
        assert_eq!(f.ret(73, &[b, 2]), 0);
        assert_eq!(f.ret(73, &[b, 3]), errno(Errno::EINVAL));
        assert_eq!(extra(&mut f, b), [flock("WRITE")]);
        // Closed, the description's lock goes with it.
        assert_eq!(f.ret(3, &[b]), 0);
        assert_eq!(f.ret(3, &[c]), 0);
        assert_eq!(f.ret(73, &[a, 2 | 4]), 0);
        assert_eq!(extra(&mut f, a)[0], flock("WRITE"));
    }
    #[test]
    fn name_to_handle_at_gives_tmpfs_handles_and_others_identifiers() {
        let mut f = fixture();
        let file = put(&f, DATA, b"/tmp/handled");
        let fd = f.ret(2, &[file, 0o102, 0o600]);
        let link = put(&f, DATA + 0x40, b"/tmp/handled-link");
        assert_eq!(f.ret(88, &[file, link]), 0);
        let (handle, mount) = (DATA + 0x200, DATA + 0x300);
        let ask = |f: &mut Fixture, dir: u64, path: u64, size: u32, flags: u64| {
            f.mem.write(GuestAddr(handle), &[0xaa; 32]).unwrap();
            f.mem.write(GuestAddr(handle), &size.to_le_bytes()).unwrap();
            f.mem.write(GuestAddr(mount), &[0xbb; 8]).unwrap();
            f.ret(303, &[dir, path, handle, mount, flags])
        };
        let header = |f: &mut Fixture| {
            let mut b = [0u8; 20];
            f.mem.read(GuestAddr(handle), &mut b).unwrap();
            b
        };
        let fs = &f.kernel.files.fs();
        let device = paludarium_vfs::mount_device(&fs.mounts(), b"/tmp");
        let id = 20 + u64::from(paludarium_types::device_numbers(device).1);
        let ino = fs.metadata(b"/tmp/handled", true).unwrap().inode;
        let link_ino = fs.metadata(b"/tmp/handled-link", false).unwrap().inode;
        let tmpfs = |ino: u64| {
            let mut b = [0u8; 20];
            b[0..4].copy_from_slice(&12u32.to_le_bytes());
            b[4..8].copy_from_slice(&1u32.to_le_bytes());
            b[12..16].copy_from_slice(&(ino as u32).to_le_bytes());
            b[16..20].copy_from_slice(&((ino >> 32) as u32).to_le_bytes());
            b
        };
        let cwd = (-100i64) as u64;
        // Flags: unknown ones, and a connectable handle with FID or an
        // empty path.
        assert_eq!(ask(&mut f, cwd, file, 128, 0x4), errno(Errno::EINVAL));
        assert_eq!(ask(&mut f, cwd, file, 128, 0x202), errno(Errno::EINVAL));
        assert_eq!(ask(&mut f, cwd, file, 128, 0x1002), errno(Errno::EINVAL));
        // Too little room: EOVERFLOW, with the size needed, FILEID_INVALID
        // and the mount's ID written back; too much asked: EINVAL.
        assert_eq!(ask(&mut f, cwd, file, 11, 0), errno(Errno::EOVERFLOW));
        let b = header(&mut f);
        assert_eq!(&b[0..8], &[12, 0, 0, 0, 0xff, 0, 0, 0]);
        assert_eq!(&b[8..12], &[0xaa; 4]);
        assert_eq!(
            f.mem.read_u64(GuestAddr(mount)).unwrap(),
            0xbbbb_bbbb_0000_0000 | id
        );
        assert_eq!(ask(&mut f, cwd, file, 129, 0), errno(Errno::EINVAL));
        // A tmpfs file's handle; the link itself unless it is followed.
        assert_eq!(ask(&mut f, cwd, file, 12, 0), 0);
        assert_eq!(header(&mut f), tmpfs(ino));
        assert_eq!(ask(&mut f, cwd, link, 128, 0), 0);
        assert_eq!(header(&mut f), tmpfs(link_ino));
        assert_eq!(ask(&mut f, cwd, link, 128, 0x400), 0);
        assert_eq!(header(&mut f), tmpfs(ino));
        // By descriptor, with the unique 64-bit mount ID.
        let empty = put(&f, DATA + 0x80, b"");
        assert_eq!(ask(&mut f, fd, empty, 128, 0x1001), 0);
        assert_eq!(header(&mut f), tmpfs(ino));
        assert_eq!(id, 21);
        assert_eq!(
            f.mem.read_u64(GuestAddr(mount)).unwrap(),
            paludarium_vfs::UNIQUE_OFFSET + 2
        );
        assert_eq!(ask(&mut f, fd, empty, 128, 0), errno(Errno::ENOENT));
        // tmpfs cannot give a connectable handle.
        assert_eq!(ask(&mut f, cwd, file, 128, 0x2), errno(Errno::EOPNOTSUPP));
        // /proc has no NFS export: only an identifier, of the inode.
        let status = put(&f, DATA + 0xc0, b"/proc/self/status");
        assert_eq!(ask(&mut f, cwd, status, 128, 0), errno(Errno::EOPNOTSUPP));
        assert_eq!(ask(&mut f, cwd, status, 128, 0x200), 0);
        let b = header(&mut f);
        assert_eq!(&b[0..8], &[12, 0, 0, 0, 0x81, 0, 0, 0]);
        assert_eq!(&b[16..20], &[0; 4]);
        // A memfd is shmem's.
        let name = put(&f, DATA + 0x100, b"handled");
        let memfd = f.ret(319, &[name, 0]);
        assert_eq!(ask(&mut f, memfd, empty, 128, 0x1000), 0);
        assert_eq!(&header(&mut f)[0..8], &[12, 0, 0, 0, 1, 0, 0, 0]);
        // What cannot be read or written, and what is not there.
        assert_eq!(f.ret(303, &[cwd, file, 8, mount, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(303, &[cwd, file, handle, 8, 0]), errno(Errno::EFAULT));
        assert_eq!(
            f.ret(303, &[cwd, 8, handle, mount, 0]),
            errno(Errno::EFAULT)
        );
        let missing = put(&f, DATA + 0x140, b"/tmp/missing");
        assert_eq!(ask(&mut f, cwd, missing, 128, 0), errno(Errno::ENOENT));
    }
    #[test]
    fn open_by_handle_at_opens_tmpfs_files_with_the_capability() {
        let mut f = fixture();
        let file = put(&f, DATA, b"/tmp/opened");
        let fd = f.ret(2, &[file, 0o102, 0o600]);
        let text = put(&f, DATA + 0x40, b"abc");
        assert_eq!(f.ret(1, &[fd, text, 3]), 3);
        let tmp = put(&f, DATA + 0x80, b"/tmp");
        let (handle, mount, buf) = (DATA + 0x200, DATA + 0x300, DATA + 0x400);
        let cwd = (-100i64) as u64;
        let encode = |f: &mut Fixture, path: u64, at: u64| {
            f.mem.write(GuestAddr(at), &128u32.to_le_bytes()).unwrap();
            assert_eq!(f.ret(303, &[cwd, path, at, mount, 0]), 0);
        };
        encode(&mut f, file, handle);
        let dir_handle = DATA + 0x600;
        encode(&mut f, tmp, dir_handle);
        // The file it names, opened as asked.
        let opened = f.ret(304, &[cwd, handle, 0]);
        assert!(opened > fd, "{opened}");
        assert_eq!(f.ret(17, &[opened, buf, 8, 0]), 3);
        assert_eq!(f.ret(72, &[opened, 3]), 0o100000);
        let dir = f.ret(304, &[cwd, dir_handle, 0o200000]);
        assert!(dir > opened, "{dir}");
        // From the file's own descriptor too, which is on the same mount.
        assert!(f.ret(304, &[fd, handle, 0o2000000]) > dir);
        // `O_CREAT` finds the file: EEXIST with `O_EXCL`, EISDIR for a
        // directory.
        assert_eq!(f.ret(304, &[cwd, handle, 0o300]), errno(Errno::EEXIST));
        assert_eq!(f.ret(304, &[cwd, dir_handle, 0o100]), errno(Errno::EISDIR));
        assert!(f.ret(304, &[cwd, handle, 0o102]) < 1 << 32);
        // A file's handle marked as a directory's.
        let header = |f: &mut Fixture, at: u64, size: u32, kind: u32| {
            f.mem.write(GuestAddr(at), &size.to_le_bytes()).unwrap();
            f.mem.write(GuestAddr(at + 4), &kind.to_le_bytes()).unwrap();
        };
        header(&mut f, handle, 12, 0x2_0001);
        assert_eq!(f.ret(304, &[cwd, handle, 0]), errno(crate::files::ESTALE));
        header(&mut f, dir_handle, 12, 0x2_0001);
        assert!(f.ret(304, &[cwd, dir_handle, 0]) < 1 << 32);
        // Connectable: only below the mount's directory.
        header(&mut f, handle, 12, 0x1_0001);
        assert!(f.ret(304, &[dir, handle, 0]) < 1 << 32);
        let proc = put(&f, DATA + 0xc0, b"/tmp/sub");
        assert_eq!(f.ret(83, &[proc, 0o700]), 0);
        let sub = f.ret(2, &[proc, 0o200000]);
        assert_eq!(f.ret(304, &[sub, handle, 0]), errno(crate::files::ESTALE));
        header(&mut f, handle, 12, 1);
        // The header: its size and the flags of its type.
        header(&mut f, buf, 0, 1);
        assert_eq!(f.ret(304, &[cwd, buf, 0]), errno(Errno::EINVAL));
        header(&mut f, buf, 129, 1);
        assert_eq!(f.ret(304, &[cwd, buf, 0]), errno(Errno::EINVAL));
        header(&mut f, buf, 12, 0x8000_0001);
        assert_eq!(f.ret(304, &[cwd, buf, 0]), errno(Errno::EINVAL));
        header(&mut f, buf, 12, 0x4_0001);
        assert_eq!(f.ret(304, &[cwd, buf, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(304, &[cwd, 8, 0]), errno(Errno::EFAULT));
        // Its bytes, read only once the mount and the permission are known.
        header(&mut f, DATA + 0x1ff8, 12, 1);
        assert_eq!(f.ret(304, &[cwd, DATA + 0x1ff8, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(304, &[99, DATA + 0x1ff8, 0]), errno(Errno::EBADF));
        assert_eq!(
            f.ret(304, &[(-5i64) as u64, handle, 0]),
            errno(Errno::EBADF)
        );
        // Another generation, a short handle, another file system, and a
        // file no name links any more.
        let mut copy = [0u8; 20];
        f.mem.read(GuestAddr(handle), &mut copy).unwrap();
        copy[8] = 1;
        f.mem.write(GuestAddr(buf), &copy).unwrap();
        assert_eq!(f.ret(304, &[cwd, buf, 0]), errno(crate::files::ESTALE));
        header(&mut f, handle, 8, 1);
        assert_eq!(f.ret(304, &[cwd, handle, 0]), errno(crate::files::ESTALE));
        header(&mut f, handle, 12, 1);
        let status = put(&f, DATA + 0x100, b"/proc/self/status");
        let in_proc = f.ret(2, &[status, 0]);
        assert_eq!(
            f.ret(304, &[in_proc, handle, 0]),
            errno(crate::files::ESTALE)
        );
        assert_eq!(f.ret(87, &[file]), 0);
        assert_eq!(f.ret(304, &[cwd, handle, 0]), errno(crate::files::ESTALE));
        // Without CAP_DAC_READ_SEARCH no handle decodes there.
        assert_eq!(f.ret(105, &[1000]), 0);
        assert_eq!(f.ret(304, &[cwd, dir_handle, 0]), errno(Errno::EPERM));
    }
    #[test]
    fn pidfds_have_pidfs_handles_that_anyone_opens() {
        const PIDFS: u64 = (-10002i64) as u64;
        let mut f = fixture();
        assert_eq!(f.ret(105, &[1000]), 0);
        let pidfd = f.ret(434, &[1, 0]);
        let (handle, mount, buf) = (DATA + 0x200, DATA + 0x300, DATA + 0x400);
        let empty = put(&f, DATA, b"");
        // pidfs's handle holds the inode, which fstat gives.
        f.mem.write(GuestAddr(handle), &7u32.to_le_bytes()).unwrap();
        assert_eq!(
            f.ret(303, &[pidfd, empty, handle, mount, 0x1000]),
            errno(Errno::EOVERFLOW)
        );
        assert_eq!(f.mem.read_u64(GuestAddr(handle)).unwrap(), 0xff_0000_0008);
        f.mem.write(GuestAddr(handle), &8u32.to_le_bytes()).unwrap();
        assert_eq!(f.ret(303, &[pidfd, empty, handle, mount, 0x1000]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(handle)).unwrap(), 0xfe_0000_0008);
        let inode = f.mem.read_u64(GuestAddr(handle + 8)).unwrap();
        assert_eq!(f.ret(5, &[pidfd, buf]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(buf + 8)).unwrap(), inode);
        assert_eq!(inode, 1);
        // No connectable one, as pidfs's files have no parents.
        let link = put(&f, DATA + 0x40, format!("/proc/self/fd/{pidfd}").as_bytes());
        assert_eq!(
            f.ret(303, &[(-100i64) as u64, link, handle, mount, 0x402]),
            errno(Errno::EOPNOTSUPP)
        );
        // fstatfs: pidfs, and the anonymous inodes' for an eventfd.
        assert_eq!(f.ret(138, &[pidfd, buf]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x5049_4446);
        let eventfd = f.ret(290, &[0, 0]);
        assert_eq!(f.ret(138, &[eventfd, buf]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(buf)).unwrap(), 0x0904_1934);
        f.mem.write(GuestAddr(buf), &128u32.to_le_bytes()).unwrap();
        assert_eq!(
            f.ret(303, &[eventfd, empty, buf, mount, 0x1000]),
            errno(Errno::EOPNOTSUPP)
        );
        // Opened from pidfs's root or a pidfd without any capability: read
        // and write, with the descriptor flags asked for.
        let opened = f.ret(304, &[PIDFS, handle, 0o4000 | 0o2000000]);
        assert!(opened > eventfd, "{opened}");
        assert_eq!(f.ret(72, &[opened, 3]), 0o2004002);
        assert_eq!(f.ret(72, &[opened, 1]), 1);
        assert_eq!(f.ret(5, &[opened, buf]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(buf + 8)).unwrap(), inode);
        let thread = f.ret(304, &[pidfd, handle, 0o200]);
        assert!(thread > opened, "{thread}");
        assert_eq!(f.ret(72, &[thread, 3]), 2);
        let own = f.ret(434, &[1, 0x80]);
        assert_eq!(f.ret(72, &[own, 3]), 0o202);
        assert_eq!(f.ret(72, &[own, 4, 0]), 0);
        assert_eq!(f.ret(72, &[own, 3]), 0o202);
        // Flags a pidfd does not open with, a directory's or connectable
        // handle, and a process that is not there.
        assert_eq!(f.ret(304, &[PIDFS, handle, 0o100]), errno(Errno::EINVAL));
        f.mem
            .write(GuestAddr(handle + 4), &0x2_00feu32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(304, &[PIDFS, handle, 0]), errno(crate::files::ESTALE));
        f.mem
            .write(GuestAddr(handle + 4), &0x1_00feu32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(304, &[PIDFS, handle, 0]), errno(crate::files::ESTALE));
        assert!(f.ret(304, &[pidfd, handle, 0]) < 1 << 32);
        f.mem
            .write(GuestAddr(handle + 4), &0xfeu32.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(handle + 8), &99u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(304, &[PIDFS, handle, 0]), errno(crate::files::ESTALE));
        f.mem
            .write(GuestAddr(handle + 4), &1u32.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(handle + 8), &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(304, &[PIDFS, handle, 0]), errno(crate::files::ESTALE));
        // nsfs decodes none of them.
        assert_eq!(
            f.ret(304, &[(-10003i64) as u64, handle, 0]),
            errno(crate::files::ESTALE)
        );
    }
    #[test]
    fn fdinfo_lists_the_watches_the_newest_first() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK | 0o2000000]);
        let tmp = put(&f, DATA, b"/tmp");
        let a = put(&f, DATA + 0x40, b"/tmp/a");
        let d = f.ret(2, &[a, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(f.ret(ADD, &[fd, tmp, 0x100]), 1);
        assert_eq!(f.ret(ADD, &[fd, a, 0x8000_0004]), 2);
        // A changed mask keeps the watch where it was.
        assert_eq!(f.ret(ADD, &[fd, tmp, 0x0400_0300]), 1);
        let fs = &f.kernel.files.fs();
        let device = paludarium_vfs::mount_device(&fs.mounts(), b"/tmp");
        let (major, minor) = paludarium_types::device_numbers(device);
        let sdev = u64::from(major) << 20 | u64::from(minor);
        let ino = |path: &[u8]| fs.metadata(path, true).unwrap().inode;
        let (tmp_ino, a_ino) = (ino(b"/tmp"), ino(b"/tmp/a"));
        let path = format!("/proc/self/fdinfo/{fd}");
        let text = String::from_utf8(contents(&mut f, path.as_bytes())).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("pos:\t0"));
        assert_eq!(lines.next(), Some("flags:\t02004000"));
        assert!(lines.next().unwrap().starts_with("mnt_id:\t"));
        assert!(lines.next().unwrap().starts_with("ino:\t"));
        // Then tmpfs's handle: the generation, and the inode in halves.
        let handle = |ino: u64| {
            format!(
                "fhandle-bytes:c fhandle-type:1 f_handle:00000000{:08x}{:08x}",
                (ino as u32).swap_bytes(),
                ((ino >> 32) as u32).swap_bytes()
            )
        };
        assert_eq!(
            lines.collect::<Vec<_>>(),
            [
                format!(
                    "inotify wd:2 ino:{a_ino:x} sdev:{sdev:x} mask:80000004 ignored_mask:0 {}",
                    handle(a_ino)
                ),
                format!(
                    "inotify wd:1 ino:{tmp_ino:x} sdev:{sdev:x} mask:4000300 ignored_mask:0 {}",
                    handle(tmp_ino)
                ),
            ]
        );
        // A /proc file's is the identifier of a file system without NFS
        // export: the inode, then the generation.
        let proc = put(&f, DATA + 0x80, b"/proc/self/status");
        assert_eq!(f.ret(ADD, &[fd, proc, 0x2]), 3);
        let path = format!("/proc/self/fdinfo/{fd}");
        let text = String::from_utf8(contents(&mut f, path.as_bytes())).unwrap();
        let line = text.lines().nth(4).unwrap();
        let ino = u64::from_str_radix(
            line.split("ino:")
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap(),
            16,
        )
        .unwrap();
        assert!(
            line.ends_with(&format!(
                "fhandle-bytes:c fhandle-type:81 f_handle:{:016x}00000000",
                ino.swap_bytes()
            )),
            "{line}"
        );
        // The directory lists the descriptors as regular files.
        let dir = f.ret(2, &[put(&f, DATA, b"/proc/self/fdinfo"), 0o200000]);
        let n = f.ret(217, &[dir, BUF, 0x800]);
        let mut bytes = vec![0; n as usize];
        f.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        let name = fd.to_string();
        let at = bytes
            .windows(name.len() + 1)
            .position(|w| w[..name.len()] == *name.as_bytes() && w[name.len()] == 0)
            .unwrap();
        assert_eq!(bytes[at - 1], 8);
        // A descriptor that is not open has none.
        assert_eq!(
            f.ret(2, &[put(&f, DATA, b"/proc/self/fdinfo/99"), 0]),
            errno(Errno::ENOENT)
        );
    }
    #[test]
    fn proc_sys_fs_inotify_holds_the_limits() {
        let mut f = fixture();
        let dir: &[u8] = b"/proc/sys/fs/inotify/";
        let file = |name: &str| [dir, name.as_bytes()].concat();
        assert_eq!(contents(&mut f, &file("max_queued_events")), b"16384\n");
        assert_eq!(contents(&mut f, &file("max_user_instances")), b"128\n");
        let watches = String::from_utf8(contents(&mut f, &file("max_user_watches"))).unwrap();
        let watches: u64 = watches.trim_end().parse().unwrap();
        assert!((8192..=1_048_576).contains(&watches));
        // Out of bounds, or not a number, is EINVAL.
        for (name, text) in [
            ("max_user_instances", &b"-1"[..]),
            ("max_user_instances", b"2147483648"),
            ("max_queued_events", b"-1"),
            ("max_user_watches", b"x"),
        ] {
            assert_eq!(write_to(&mut f, &file(name), text), errno(Errno::EINVAL));
        }
        // An instance made after max_queued_events changes queues that many.
        assert_eq!(write_to(&mut f, &file("max_queued_events"), b"1\n"), 2);
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let tmp = put(&f, DATA, b"/tmp");
        let wd = f.ret(ADD, &[fd, tmp, 0x100]) as i32;
        for name in [&b"/tmp/a"[..], b"/tmp/b"] {
            let d = f.ret(2, &[put(&f, DATA + 0x40, name), 0o101, 0o600]);
            assert_eq!(f.ret(3, &[d]), 0);
        }
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x100, &b"a"[..]), (-1, 0x4000, b"")]
        );
        // The users' limits count what each already has.
        assert_eq!(write_to(&mut f, &file("max_user_instances"), b"1"), 1);
        assert_eq!(f.ret(INIT1, &[0]), errno(Errno::EMFILE));
        assert_eq!(write_to(&mut f, &file("max_user_watches"), b"1"), 1);
        let a = put(&f, DATA + 0x40, b"/tmp/a");
        assert_eq!(f.ret(ADD, &[fd, a, 0x4]), errno(Errno::ENOSPC));
        assert_eq!(contents(&mut f, &file("max_user_watches")), b"1\n");
        // Only root may open them to write.
        f.thread.state.credentials.euid = 1000;
        assert_eq!(
            f.ret(2, &[put(&f, DATA, &file("max_user_watches")), 1]),
            errno(Errno::EACCES)
        );
    }
    #[test]
    fn the_files_exec_opens_are_heard_of() {
        let mut f = fixture();
        let files: [(&[u8], u32, &[u8]); 6] = [
            (b"/tmp/x/shut", 0o644, b"#!/tmp/x/prog\n"),
            (b"/tmp/x/empty", 0o755, b""),
            (b"/tmp/x/junk", 0o755, b"junk"),
            (b"/tmp/x/bad", 0o755, b"#!/tmp/x/junk\n"),
            (b"/tmp/x/s", 0o755, b"#!/tmp/x/prog\n"),
            (
                b"/tmp/x/prog",
                0o755,
                &paludarium_loader::testing::tiny_exec(&[0x90], b""),
            ),
        ];
        assert_eq!(f.ret(83, &[put(&f, DATA, b"/tmp/x"), 0o755]), 0);
        for (path, mode, bytes) in files {
            let file = f.kernel.files.fs().open(path, 0o101, mode).unwrap();
            assert_eq!(file.write_at(0, bytes).unwrap(), bytes.len());
        }
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let wd = f.ret(ADD, &[fd, put(&f, DATA, b"/tmp/x"), 0xfff]) as i32;
        let exec = |f: &mut Fixture, path: &[u8]| f.ret(59, &[put(f, DATA, path), 0, 0]);
        // Exec opens no file it may not run, and closes one it cannot run
        // after reading what of it there is.
        assert_eq!(exec(&mut f, b"/tmp/x/shut"), errno(Errno::EACCES));
        assert_eq!(masks(&events(&mut f, fd)), []);
        assert_eq!(exec(&mut f, b"/tmp/x/empty"), errno(Errno(8)));
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x20, &b"empty"[..]), (wd, 0x10, b"empty")]
        );
        assert_eq!(exec(&mut f, b"/tmp/x/junk"), errno(Errno(8)));
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (wd, 0x20, &b"junk"[..]),
                (wd, 1, b"junk"),
                (wd, 0x10, b"junk")
            ]
        );
        // A script's interpreter is opened while the script is, and the
        // last opened closes first.
        assert_eq!(exec(&mut f, b"/tmp/x/bad"), errno(Errno(8)));
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (wd, 0x20, &b"bad"[..]),
                (wd, 1, b"bad"),
                (wd, 0x20, b"junk"),
                (wd, 1, b"junk"),
                (wd, 0x10, b"junk"),
                (wd, 0x10, b"bad"),
            ]
        );
        // The script closes at the end of the exec, and the program once
        // no process runs it.
        assert_eq!(exec(&mut f, b"/tmp/x/s"), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (wd, 0x20, &b"s"[..]),
                (wd, 1, b"s"),
                (wd, 0x20, b"prog"),
                (wd, 1, b"prog"),
                (wd, 0x10, b"s"),
            ]
        );
        f.kernel.group.set_exe_file(None);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x10, &b"prog"[..])]);
    }
    #[test]
    fn a_fifo_a_path_opened_and_splices_are_heard_of() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let q = put(&f, DATA, b"/tmp/q");
        let p = put(&f, DATA + 0x20, b"/tmp/q/p");
        let lone = put(&f, DATA + 0x40, b"/tmp/q/l");
        let file = put(&f, DATA + 0x60, b"/tmp/q/f");
        let bytes = put(&f, DATA + 0x80, b"xy");
        let iov = DATA + 0xa0;
        f.mem.write(GuestAddr(iov), &bytes.to_le_bytes()).unwrap();
        f.mem
            .write(GuestAddr(iov + 8), &1u64.to_le_bytes())
            .unwrap();
        let off = DATA + 0xc0;
        f.mem.write(GuestAddr(off), &0u64.to_le_bytes()).unwrap();
        let pipe = DATA + 0xd0;
        assert_eq!(f.ret(83, &[q, 0o700]), 0);
        assert_eq!(f.ret(133, &[p, 0o010644, 0]), 0);
        assert_eq!(f.ret(133, &[lone, 0o010644, 0]), 0);
        let reg = f.ret(2, &[file, 0o102, 0o600]);
        assert_eq!(f.ret(1, &[reg, bytes, 2]), 2);
        assert_eq!(f.ret(22, &[pipe]), 0);
        let mut ends = [0; 8];
        f.mem.read(GuestAddr(pipe), &mut ends).unwrap();
        let pipe_w = u64::from(u32::from_le_bytes(ends[4..].try_into().unwrap()));
        let wd = f.ret(ADD, &[fd, q, 0xfff]) as i32;
        let own = f.ret(ADD, &[fd, p, 0xfff]) as i32;
        // IN_OPEN once the open is done, for the directory and the FIFO; a
        // writer with no reader (ENXIO) opens nothing.
        assert_eq!(f.ret(2, &[lone, 0o4001, 0]), errno(Errno(6)));
        let r = f.ret(2, &[p, 0o4002, 0]);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x20, &b"p"[..]), (own, 0x20, b"")]
        );
        // Reads and writes are the FIFO's own (`d_is_special`).
        assert_eq!(f.ret(1, &[r, bytes, 1]), 1);
        assert_eq!(f.ret(0, &[r, DATA + 0x100, 1]), 1);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(own, 0x2, &b""[..]), (own, 0x1, b"")]
        );
        // splice tells the output first, then the input.
        assert_eq!(f.ret(275, &[reg, off, r, 0, 2, 0]), 2);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(own, 0x2, &b""[..]), (wd, 0x1, b"f")]
        );
        assert_eq!(f.ret(275, &[r, 0, reg, off, 1, 0]), 1);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x2, &b"f"[..]), (own, 0x1, b"")]
        );
        // tee the input, then the output (a pipe, which has no watches).
        assert_eq!(f.ret(276, &[r, pipe_w, 1, 0]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(own, 0x1, &b""[..])]);
        // vmsplice into a description open for writing modifies it.
        assert_eq!(f.ret(278, &[r, iov, 1, 0]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(own, 0x2, &b""[..])]);
        // One that moves nothing is no event.
        assert_eq!(f.ret(275, &[reg, off, r, 0, 0, 0]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        // The last close of the description: IN_CLOSE_WRITE, as O_RDWR.
        let dup = f.ret(32, &[r]);
        assert_eq!(f.ret(3, &[r]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        assert_eq!(f.ret(3, &[dup]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x8, &b"p"[..]), (own, 0x8, b"")]
        );
        // A reader's is IN_CLOSE_NOWRITE.
        let reader = f.ret(2, &[p, 0o4000, 0]);
        assert_eq!(f.ret(3, &[reader]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (wd, 0x20, &b"p"[..]),
                (own, 0x20, b""),
                (wd, 0x10, b"p"),
                (own, 0x10, b"")
            ]
        );
    }
    #[test]
    fn the_calls_are_checked_in_linuxs_order() {
        let mut f = fixture();
        assert_eq!(f.ret(INIT1, &[1]), errno(Errno::EINVAL));
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let tmp = put(&f, DATA, b"/tmp");
        assert_eq!(f.ret(ADD, &[fd, tmp, 0]), errno(Errno::EINVAL));
        assert_eq!(f.ret(ADD, &[fd, tmp, 0x800_0000]), errno(Errno::EINVAL));
        assert_eq!(f.ret(ADD, &[99, tmp, 1]), errno(Errno::EBADF));
        assert_eq!(f.ret(ADD, &[fd, tmp, 0x3000_0001]), errno(Errno::EINVAL));
        // Another file is EINVAL.
        assert_eq!(f.ret(ADD, &[1, tmp, 1]), errno(Errno::EINVAL));
        let missing = put(&f, DATA + 0x40, b"/tmp/none");
        assert_eq!(f.ret(ADD, &[fd, missing, 1]), errno(Errno::ENOENT));
        let wd = f.ret(ADD, &[fd, tmp, 1]);
        assert_eq!(wd, 1);
        // The same file has the same watch; IN_MASK_CREATE refuses it.
        assert_eq!(f.ret(ADD, &[fd, tmp, 2]), 1);
        assert_eq!(f.ret(ADD, &[fd, tmp, 0x1000_0002]), errno(Errno::EEXIST));
        assert_eq!(f.ret(RM, &[fd, 7]), errno(Errno::EINVAL));
        assert_eq!(f.ret(RM, &[fd, wd]), 0);
        assert_eq!(masks(&events(&mut f, fd)), [(1, 0x8000, &b""[..])]);
        // The cursor goes on: the next watch is 2.
        assert_eq!(f.ret(ADD, &[fd, tmp, 1]), 2);
        // A buffer too small for the next record is EINVAL.
        assert_eq!(f.ret(RM, &[fd, 2]), 0);
        assert_eq!(f.ret(0, &[fd, BUF, 15]), errno(Errno::EINVAL));
        assert_eq!(f.ret(0, &[fd, BUF, 16]), 16);
        assert_eq!(f.ret(0, &[fd, BUF, 16]), errno(Errno::EAGAIN));
        // FIONREAD, and pread is ESPIPE.
        assert_eq!(f.ret(16, &[fd, 0x541b, BUF]), 0);
        assert_eq!((f.mem.read_u64(GuestAddr(BUF)).unwrap() as u32), 0);
        assert_eq!(f.ret(17, &[fd, BUF, 16, 0]), errno(Errno::ESPIPE));
    }
    #[test]
    fn changes_in_a_directory_are_its_events() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        put(&f, DATA, b"/tmp/w");
        assert_eq!(f.ret(83, &[DATA, 0o755]), 0);
        let wd = f.ret(ADD, &[fd, DATA, 0xfff]) as i32;
        let file = put(&f, DATA + 0x40, b"/tmp/w/a");
        let fresh = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(90, &[file, 0o640]), 0);
        let other = put(&f, DATA + 0x80, b"/tmp/w/b");
        assert_eq!(f.ret(82, &[file, other]), 0);
        let sub = put(&f, DATA + 0xc0, b"/tmp/w/s");
        assert_eq!(f.ret(83, &[sub, 0o755]), 0);
        assert_eq!(f.ret(84, &[sub]), 0);
        assert_eq!(f.ret(87, &[other]), 0);
        let got = events(&mut f, fd);
        assert_eq!(
            masks(&got),
            [
                (wd, 0x100, &b"a"[..]),
                (wd, 0x20, b"a"),
                (wd, 0x4, b"a"),
                (wd, 0x40, b"a"),
                (wd, 0x80, b"b"),
                (wd, 0x4000_0100, b"s"),
                (wd, 0x4000_0200, b"s"),
                (wd, 0x200, b"b"),
            ]
        );
        // A rename's two events share a cookie.
        assert_ne!(got[3].2, 0);
        assert_eq!(got[3].2, got[4].2);
        let _ = fresh;
    }
    #[test]
    fn a_watched_file_hears_of_itself_and_goes() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let file = put(&f, DATA, b"/tmp/x");
        let d = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, file, 0xfff]) as i32;
        let moved = put(&f, DATA + 0x40, b"/tmp/y");
        assert_eq!(f.ret(82, &[file, moved]), 0);
        assert_eq!(f.ret(76, &[moved, 3]), 0);
        assert_eq!(f.ret(87, &[moved]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (wd, 0x800, &b""[..]),
                (wd, 0x2, b""),
                (wd, 0x4, b""),
                (wd, 0x400, b""),
                (wd, 0x8000, b""),
            ]
        );
        // A one-shot watch goes after its first event.
        let d = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, file, 0x8000_0004]) as i32;
        assert_eq!(f.ret(90, &[file, 0o600]), 0);
        assert_eq!(f.ret(90, &[file, 0o644]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x4, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn opening_reading_writing_and_closing_are_events() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let file = put(&f, DATA, b"/tmp/c");
        let d = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, file, 0xfff]) as i32;
        let d = f.ret(2, &[file, 2, 0]);
        f.mem.write(GuestAddr(DATA + 0x40), b"abc").unwrap();
        assert_eq!(f.ret(1, &[d, DATA + 0x40, 3]), 3);
        assert_eq!(f.ret(17, &[d, DATA + 0x40, 3, 0]), 3);
        // Nothing moved, no event.
        assert_eq!(f.ret(0, &[d, DATA + 0x40, 3]), 0);
        let copy = f.ret(32, &[d]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x20, &b""[..]), (wd, 0x2, b""), (wd, 0x1, b""),]
        );
        // The last close of the description is the close.
        assert_eq!(f.ret(3, &[copy]), 0);
        // truncate(2) opens nothing.
        assert_eq!(f.ret(76, &[file, 1]), 0);
        let d = f.ret(2, &[file, 0o10_000_000, 0]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x8, &b""[..]), (wd, 0x2, b"")]
        );
    }
    #[test]
    fn a_removed_open_file_ends_with_its_last_close() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let file = put(&f, DATA, b"/tmp/held");
        let d = f.ret(2, &[file, 0o101, 0o600]);
        let wd = f.ret(ADD, &[fd, file, 0x4 | 0x400]) as i32;
        let copy = f.ret(32, &[d]);
        assert_eq!(f.ret(87, &[file]), 0);
        // The link count now; the end waits for every description.
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x4, &b""[..])]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        assert_eq!(f.ret(3, &[copy]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
        // A file no description holds goes at once.
        let d = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, file, 0x400]) as i32;
        assert_eq!(f.ret(87, &[file]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    /// The superblock's last mount going, as Linux's `fsnotify_sb_delete`:
    /// each watch on its files hears `IN_UNMOUNT` (with `IN_ISDIR` for a
    /// directory) whatever it asked for, then goes with `IN_IGNORED`. A
    /// bind mount left keeps the superblock, and a detached mount goes
    /// with its last open file.
    #[test]
    fn a_watch_hears_its_superblock_go() {
        let mut f = fixture();
        let none = put(&f, DATA, b"none");
        let tmpfs = put(&f, DATA + 0x10, b"tmpfs");
        let m = put(&f, DATA + 0x20, b"/tmp/m");
        let b = put(&f, DATA + 0x40, b"/tmp/b");
        let file = put(&f, DATA + 0x60, b"/tmp/m/f");
        let other = put(&f, DATA + 0x80, b"/tmp/o");
        assert_eq!(f.ret(83, &[m, 0o755]), 0);
        assert_eq!(f.ret(83, &[b, 0o755]), 0);
        assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
        let d = f.ret(2, &[file, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        let d = f.ret(2, &[other, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(f.ret(165, &[m, b, 0, 0x1000, 0]), 0);
        let one = f.ret(INIT1, &[IN_NONBLOCK]);
        let two = f.ret(INIT1, &[IN_NONBLOCK]);
        let root = f.ret(ADD, &[one, m, 0x2]) as i32;
        let watched = f.ret(ADD, &[one, file, 0x2]) as i32;
        let kept = f.ret(ADD, &[one, other, 0x2]) as i32;
        let also = f.ret(ADD, &[two, file, 0x1]) as i32;
        // The bind mount at b keeps the superblock.
        assert_eq!(f.ret(166, &[m, 0]), 0);
        assert_eq!(masks(&events(&mut f, one)), []);
        assert_eq!(f.ret(166, &[b, 0]), 0);
        assert_eq!(
            masks(&events(&mut f, one)),
            [
                (watched, 0x2000, &b""[..]),
                (watched, 0x8000, b""),
                (root, 0x4000_2000, b""),
                (root, 0x8000, b""),
            ]
        );
        assert_eq!(
            masks(&events(&mut f, two)),
            [(also, 0x2000, &b""[..]), (also, 0x8000, b"")]
        );
        // Gone: removing them is EINVAL; the watch elsewhere stays.
        assert_eq!(f.ret(RM, &[one, watched as u64]), errno(Errno::EINVAL));
        assert_eq!(f.ret(RM, &[one, kept as u64]), 0);
        assert_eq!(masks(&events(&mut f, one)), [(kept, 0x8000, &b""[..])]);
        // A detached mount goes with its last open file.
        assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
        let held = f.ret(2, &[file, 0o101, 0o600]);
        let wd = f.ret(ADD, &[one, file, 0x400]) as i32;
        assert_eq!(f.ret(166, &[m, 2]), 0);
        assert_eq!(masks(&events(&mut f, one)), []);
        assert_eq!(f.ret(3, &[held]), 0);
        assert_eq!(
            masks(&events(&mut f, one)),
            [(wd, 0x2000, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn a_descriptor_is_heard_of_where_renames_took_its_file() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let a = put(&f, DATA, b"/tmp/a");
        let b = put(&f, DATA + 0x20, b"/tmp/b");
        let c = put(&f, DATA + 0x40, b"/tmp/c");
        let old = put(&f, DATA + 0x60, b"/tmp/a/f");
        let new = put(&f, DATA + 0x80, b"/tmp/b/g");
        let g = put(&f, DATA + 0xa0, b"/tmp/c/g");
        let h = put(&f, DATA + 0xc0, b"/tmp/c/h");
        let byte = put(&f, DATA + 0xe0, b"x");
        assert_eq!(f.ret(83, &[a, 0o700]), 0);
        assert_eq!(f.ret(83, &[b, 0o700]), 0);
        let d = f.ret(2, &[old, 0o102, 0o600]);
        // IN_MODIFY | IN_CLOSE_WRITE on the directory the file goes to, and
        // the same with IN_EXCL_UNLINK, which a linked name passes.
        let wd = f.ret(ADD, &[fd, b, 0xa]) as i32;
        let excl = f.ret(INIT1, &[IN_NONBLOCK]);
        let wd_excl = f.ret(ADD, &[excl, b, 0x0400_000a]) as i32;
        assert_eq!(f.ret(82, &[old, new]), 0);
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x2, &b"g"[..])]);
        assert_eq!(masks(&events(&mut f, excl)), [(wd_excl, 0x2, &b"g"[..])]);
        assert_eq!(f.ret(3, &[excl]), 0);
        // The directory's own rename leaves the file in it.
        assert_eq!(f.ret(82, &[b, c]), 0);
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x2, &b"g"[..])]);
        // Unlinked while another name links the file, its dentry keeps the
        // name it had.
        assert_eq!(f.ret(86, &[g, h]), 0);
        assert_eq!(f.ret(87, &[g]), 0);
        // A new file at that name, renamed and unlinked, leaves it there.
        let n = put(&f, DATA + 0x100, b"/tmp/c/n");
        let made = f.ret(2, &[g, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[made]), 0);
        assert_eq!(f.ret(82, &[g, n]), 0);
        assert_eq!(f.ret(87, &[n]), 0);
        drop(events(&mut f, fd));
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x2, &b"g"[..])]);
        // With no name left, /proc opens the same dentry again, whose place
        // both descriptions share: RENAME_EXCHANGE of its directory moves
        // it once.
        assert_eq!(f.ret(87, &[h]), 0);
        let link = put(&f, DATA + 0x120, format!("/proc/self/fd/{d}").as_bytes());
        let again = f.ret(2, &[link, 0o2, 0]);
        assert!((again as i64) >= 0, "reopen: {}", again as i64);
        let e = put(&f, DATA + 0x140, b"/tmp/e");
        assert_eq!(f.ret(83, &[e, 0o700]), 0);
        assert_eq!(
            f.ret(316, &[(-100i64) as u64, c, (-100i64) as u64, e, 2]),
            0
        );
        drop(events(&mut f, fd));
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(f.ret(3, &[again]), 0);
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x2, &b"g"[..]), (wd, 0x8, b"g")]
        );
    }
    #[test]
    fn a_read_that_meets_an_unwritable_page_takes_the_record_there() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let dir = put(&f, DATA, b"/tmp");
        let wd = f.ret(ADD, &[fd, dir, 0x100]) as i32;
        let create = |f: &mut Fixture, name: &[u8]| {
            let path = put(f, DATA + 0x40, &[b"/tmp/", name].concat());
            let d = f.ret(2, &[path, 0o101, 0o600]);
            assert_eq!(f.ret(3, &[d]), 0);
        };
        for name in [b"a", b"b", b"c"] {
            create(&mut f, name);
        }
        // The page after DATA + 0x2000 is not mapped: the first record fits
        // before it, the second does not.
        let edge = DATA + 0x2000 - 40;
        assert_eq!(f.ret(0, &[fd, edge, 96]), errno(Errno::EFAULT));
        let mut first = [0; 32];
        f.mem.read(GuestAddr(edge), &mut first).unwrap();
        assert_eq!(&first[16..17], b"a");
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x100, &b"c"[..])]);
        // None of it writable: the first record goes.
        create(&mut f, b"d");
        create(&mut f, b"e");
        assert_eq!(f.ret(0, &[fd, DATA + 0x2000, 64]), errno(Errno::EFAULT));
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x100, &b"e"[..])]);
        // An address past the user half takes nothing.
        create(&mut f, b"f");
        assert_eq!(f.ret(0, &[fd, (-4096i64) as u64, 64]), errno(Errno::EFAULT));
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x100, &b"f"[..])]);
        // readv reads each buffer as one read, and stops at one it does not
        // fill; a later buffer's fault leaves the count read.
        for name in [b"g", b"h", b"i"] {
            create(&mut f, name);
        }
        let vector = DATA + 0x200;
        let iov = [
            (DATA + 0x400, 32u64),
            (DATA + 0x500, 40),
            (DATA + 0x600, 64),
        ];
        for (i, (base, len)) in iov.iter().enumerate() {
            f.mem
                .write(GuestAddr(vector + i as u64 * 16), &base.to_le_bytes())
                .unwrap();
            f.mem
                .write(GuestAddr(vector + i as u64 * 16 + 8), &len.to_le_bytes())
                .unwrap();
        }
        assert_eq!(f.ret(19, &[fd, vector, 3]), 64);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x100, &b"i"[..])]);
        create(&mut f, b"j");
        create(&mut f, b"k");
        f.mem
            .write(GuestAddr(vector + 16), &(DATA + 0x2000).to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(vector + 24), &64u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(19, &[fd, vector, 2]), 32);
        assert_eq!(masks(&events(&mut f, fd)), []);
        // No bytes is no read; a flag but RWF_HIPRI is EOPNOTSUPP.
        create(&mut f, b"l");
        f.mem
            .write(GuestAddr(vector + 8), &0u64.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(19, &[fd, vector, 1]), 0);
        f.mem
            .write(GuestAddr(vector + 8), &32u64.to_le_bytes())
            .unwrap();
        let minus_one = u64::MAX;
        assert_eq!(
            f.ret(327, &[fd, vector, 1, minus_one, minus_one, 2]),
            errno(Errno::EOPNOTSUPP)
        );
        assert_eq!(f.ret(327, &[fd, vector, 1, minus_one, minus_one, 1]), 32);
    }
    #[test]
    fn a_memfd_ends_with_its_last_close() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let name = put(&f, DATA, b"m");
        let memfd = f.ret(319, &[name, 0]);
        let link = put(&f, DATA + 0x20, format!("/proc/self/fd/{memfd}").as_bytes());
        let wd = f.ret(ADD, &[fd, link, 0xfff]) as i32;
        assert!(wd > 0, "{}", wd as i64);
        let copy = f.ret(32, &[memfd]);
        // memfd_create's own description is no open, and has no close.
        assert_eq!(f.ret(3, &[memfd]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        assert_eq!(f.ret(3, &[copy]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn a_fifo_is_heard_of_at_its_dentry() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let one = put(&f, DATA, b"/tmp/one");
        let two = put(&f, DATA + 0x20, b"/tmp/two");
        let p = put(&f, DATA + 0x40, b"/tmp/one/p");
        let q = put(&f, DATA + 0x60, b"/tmp/two/q");
        assert_eq!(f.ret(83, &[one, 0o700]), 0);
        assert_eq!(f.ret(83, &[two, 0o700]), 0);
        assert_eq!(f.ret(133, &[p, 0o010_644, 0]), 0);
        let w1 = f.ret(ADD, &[fd, one, 0xfff]) as i32;
        let w2 = f.ret(ADD, &[fd, two, 0xfff]) as i32;
        let own = f.ret(ADD, &[fd, p, 0xfff]) as i32;
        let d = f.ret(2, &[p, 0o4002, 0]);
        assert!((d as i64) >= 0);
        assert_eq!(f.ret(82, &[p, q]), 0);
        drop(events(&mut f, fd));
        // The rename moved the close.
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(w2, 0x8, &b"q"[..]), (own, 0x8, b"")]
        );
        // With no name left, /proc opens its pipe again: IN_OPEN there, and
        // its end waits for the last close.
        let d = f.ret(2, &[q, 0o4002, 0]);
        assert_eq!(f.ret(87, &[q]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (w2, 0x20, &b"q"[..]),
                (own, 0x20, b""),
                (own, 0x4, b""),
                (w2, 0x200, b"q"),
            ]
        );
        let link = put(&f, DATA + 0x80, format!("/proc/self/fd/{d}").as_bytes());
        let again = f.ret(2, &[link, 0o4000, 0]);
        assert!((again as i64) >= 0, "reopen: {}", again as i64);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(w2, 0x20, &b"q"[..]), (own, 0x20, b"")]
        );
        let byte = put(&f, DATA + 0xa0, b"x");
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(f.ret(0, &[again, DATA + 0xc0, 1]), 1);
        drop(events(&mut f, fd));
        assert_eq!(f.ret(3, &[d]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(w2, 0x8, &b"q"[..]), (own, 0x8, b"")]
        );
        assert_eq!(f.ret(3, &[again]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [
                (w2, 0x10, &b"q"[..]),
                (own, 0x10, b""),
                (own, 0x400, b""),
                (own, 0x8000, b""),
            ]
        );
        assert_ne!(w1, w2);
    }
    #[test]
    fn a_descriptor_opened_through_a_link_stays_where_the_link_led() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let a = put(&f, DATA, b"/tmp/a");
        let b = put(&f, DATA + 0x20, b"/tmp/b");
        let l = put(&f, DATA + 0x40, b"/tmp/l");
        let m = put(&f, DATA + 0x60, b"/tmp/m");
        let at = put(&f, DATA + 0x80, b"/tmp/l/f");
        let in_b = put(&f, DATA + 0xa0, b"/tmp/b/f");
        let byte = put(&f, DATA + 0xc0, b"x");
        assert_eq!(f.ret(83, &[a, 0o700]), 0);
        assert_eq!(f.ret(83, &[b, 0o700]), 0);
        assert_eq!(f.ret(88, &[a, l]), 0);
        let d = f.ret(2, &[at, 0o102, 0o600]);
        let made = f.ret(2, &[in_b, 0o101, 0o600]);
        assert_eq!(f.ret(3, &[made]), 0);
        let wd_a = f.ret(ADD, &[fd, a, 0x2]) as i32;
        let wd_b = f.ret(ADD, &[fd, b, 0x2]) as i32;
        drop(events(&mut f, fd));
        // The link now leads to b, but the dentry is a's.
        assert_eq!(f.ret(87, &[l]), 0);
        assert_eq!(f.ret(88, &[b, l]), 0);
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(wd_a, 0x2, &b"f"[..])]);
        // A rename of the link, and one onto it, change nothing either.
        assert_eq!(f.ret(82, &[l, m]), 0);
        assert_eq!(f.ret(88, &[b, l]), 0);
        assert_eq!(f.ret(82, &[l, m]), 0);
        assert_eq!(f.ret(1, &[d, byte, 1]), 1);
        assert_eq!(masks(&events(&mut f, fd)), [(wd_a, 0x2, &b"f"[..])]);
        assert_ne!(wd_a, wd_b);
    }
    #[test]
    fn a_removed_working_directory_ends_when_no_process_is_in_it() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let home = put(&f, DATA, b"/tmp/home");
        let tmp = put(&f, DATA + 0x40, b"/tmp");
        assert_eq!(f.ret(83, &[home, 0o700]), 0);
        assert_eq!(f.ret(80, &[home]), 0);
        let wd = f.ret(ADD, &[fd, home, 0x400]) as i32;
        // A copy of the working directory, as a child without CLONE_FS
        // gets, holds it too.
        let child = f.kernel.files.for_clone(true, false);
        assert_eq!(f.ret(84, &[home]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        assert_eq!(f.ret(80, &[tmp]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        drop(child);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
        // One no process is in goes at once.
        assert_eq!(f.ret(83, &[home, 0o700]), 0);
        let wd = f.ret(ADD, &[fd, home, 0x400]) as i32;
        assert_eq!(f.ret(84, &[home]), 0);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn a_removed_program_ends_when_no_process_runs_it() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let prog = put(&f, DATA, b"/tmp/prog");
        let d = f.ret(2, &[prog, 0o101, 0o700]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, prog, 0x400]) as i32;
        // What exec keeps while the program runs (`exe_file`).
        let running = crate::processes::deny_writes(&f.kernel.files, b"/tmp/prog")
            .unwrap()
            .unwrap();
        assert_eq!(f.ret(87, &[prog]), 0);
        assert_eq!(masks(&events(&mut f, fd)), []);
        drop(running);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn a_removed_interpreter_ends_when_nothing_maps_it() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let ld = put(&f, DATA, b"/tmp/ld.so");
        let d = f.ret(2, &[ld, 0o101, 0o755]);
        assert_eq!(f.ret(3, &[d]), 0);
        let wd = f.ret(ADD, &[fd, ld, 0x400]) as i32;
        // What the interpreter's mappings keep, which a fork's copy of them
        // shares.
        let mapped = f.kernel.files.interpreter_keep(b"/tmp/ld.so").unwrap();
        let forked = Arc::clone(&mapped);
        assert_eq!(f.ret(87, &[ld]), 0);
        drop(mapped);
        assert_eq!(masks(&events(&mut f, fd)), []);
        drop(forked);
        assert_eq!(
            masks(&events(&mut f, fd)),
            [(wd, 0x400, &b""[..]), (wd, 0x8000, b"")]
        );
    }
    #[test]
    fn the_queue_merges_repeats_and_overflows_once() {
        let mut f = fixture();
        let fd = f.ret(INIT1, &[IN_NONBLOCK]);
        let tmp = put(&f, DATA, b"/tmp");
        let wd = f.ret(ADD, &[fd, tmp, 0x4]) as i32;
        let a = put(&f, DATA + 0x40, b"/tmp/a");
        let b = put(&f, DATA + 0x80, b"/tmp/b");
        for path in [a, b] {
            let d = f.ret(2, &[path, 0o101, 0o600]);
            assert_eq!(f.ret(3, &[d]), 0);
        }
        assert_eq!(f.ret(90, &[a, 0o600]), 0);
        assert_eq!(f.ret(90, &[a, 0o600]), 0);
        assert_eq!(masks(&events(&mut f, fd)), [(wd, 0x4, &b"a"[..])]);
        for i in 0..16400 {
            assert_eq!(f.ret(90, &[if i % 2 == 0 { a } else { b }, 0o600]), 0);
        }
        assert_eq!(f.ret(16, &[fd, 0x541b, BUF]), 0);
        assert_eq!(
            (f.mem.read_u64(GuestAddr(BUF)).unwrap() as u32),
            16384 * 32 + 16
        );
        let mut last = Vec::new();
        loop {
            let got = events(&mut f, fd);
            if got.is_empty() {
                break;
            }
            last = got;
        }
        assert_eq!(masks(&last).last(), Some(&(-1, 0x4000, &b""[..])));
    }
}

mod futex2 {
    use super::*;
    const LIST: u64 = DATA + 0x100;
    const WORDS: u64 = DATA + 0x800;
    const TIMEOUT: u64 = DATA + 0x900;
    const U32_PRIVATE: u64 = 2 | 128;
    /// Writes `struct futex_waitv` `index` of the list.
    fn entry(f: &Fixture, index: u64, value: u64, addr: u64, flags: u64) {
        let at = LIST + 24 * index;
        f.mem.write_u64(GuestAddr(at), value).unwrap();
        f.mem.write_u64(GuestAddr(at + 8), addr).unwrap();
        f.mem.write_u64(GuestAddr(at + 16), flags).unwrap();
    }
    fn timeout(f: &Fixture, seconds: u64, ns: u64) {
        f.mem.write_u64(GuestAddr(TIMEOUT), seconds).unwrap();
        f.mem.write_u64(GuestAddr(TIMEOUT + 8), ns).unwrap();
    }
    #[test]
    fn futex_waitv_checks_as_linux_does() {
        let mut f = fixture();
        entry(&f, 0, 0, WORDS, U32_PRIVATE);
        let einval = errno(Errno::EINVAL);
        // flags, then the count and the list.
        assert_eq!(f.ret(449, &[LIST, 1, 1, 0, 0]), einval);
        for (list, count) in [(LIST, 0), (LIST, 129), (0, 1)] {
            assert_eq!(f.ret(449, &[list, count, 0, 0, 0]), einval);
        }
        // The timeout: its clock, then reading it, then its value.
        assert_eq!(f.ret(449, &[LIST, 1, 0, TIMEOUT, 2]), einval);
        assert_eq!(f.ret(449, &[LIST, 1, 0, 8, 1]), errno(Errno::EFAULT));
        timeout(&f, 0, 1_000_000_000);
        assert_eq!(f.ret(449, &[LIST, 1, 0, TIMEOUT, 1]), einval);
        // Each entry: readable, its flags, `__reserved` and its value.
        assert_eq!(
            f.ret(449, &[DATA + 0x2000 - 8, 1, 0, 0, 0]),
            errno(Errno::EFAULT)
        );
        for (value, flags) in [
            (0, 128),
            (0, 3 | 128),
            (0, 2 | 0x100),
            (0, U32_PRIVATE | 1 << 32),
            (1 << 32, U32_PRIVATE),
        ] {
            entry(&f, 0, value, WORDS, flags);
            assert_eq!(
                f.ret(449, &[LIST, 1, 0, 0, 0]),
                einval,
                "{value:#x} {flags:#x}"
            );
        }
        // Every key before any value: the second is misaligned.
        entry(&f, 0, 1, WORDS, U32_PRIVATE);
        entry(&f, 1, 0, WORDS + 2, U32_PRIVATE);
        assert_eq!(f.ret(449, &[LIST, 2, 0, 0, 0]), einval);
        entry(&f, 1, 0, WORDS + 4, U32_PRIVATE);
        assert_eq!(f.ret(449, &[LIST, 2, 0, 0, 0]), errno(Errno::EAGAIN));
        // A deadline passed already: ETIMEDOUT, on either clock.
        entry(&f, 0, 0, WORDS, U32_PRIVATE);
        timeout(&f, 0, 0);
        assert_eq!(f.ret(449, &[LIST, 2, 0, TIMEOUT, 1]), errno(Errno(110)));
        assert_eq!(f.ret(449, &[LIST, 2, 0, TIMEOUT, 0]), errno(Errno(110)));
        // The clock is looked at only with a timeout.
        entry(&f, 0, 1, WORDS, U32_PRIVATE);
        assert_eq!(f.ret(449, &[LIST, 1, 0, 0, 99]), errno(Errno::EAGAIN));
    }
    #[test]
    fn futex_wake_and_wait_check_as_linux_does() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // futex_wake(uaddr, mask, nr, flags)
        for flags in [128, 3 | 128, 2 | 0x200] {
            assert_eq!(f.ret(454, &[WORDS, 1, 1, flags]), einval);
        }
        assert_eq!(f.ret(454, &[WORDS, 1 << 32, 1, U32_PRIVATE]), einval);
        assert_eq!(f.ret(454, &[WORDS, 0, 1, U32_PRIVATE]), einval);
        assert_eq!(f.ret(454, &[WORDS + 2, 1, 1, U32_PRIVATE]), einval);
        assert_eq!(f.ret(454, &[WORDS, 1, 0, U32_PRIVATE]), 0);
        assert_eq!(f.ret(454, &[WORDS, 1, 1, U32_PRIVATE]), 0);
        // FUTEX2_NUMA: aligned to 8, and node -1 becomes 0.
        f.mem
            .write_u64(GuestAddr(WORDS), 0xffff_ffff_0000_0000)
            .unwrap();
        assert_eq!(f.ret(454, &[WORDS + 4, 1, 1, U32_PRIVATE | 4]), einval);
        assert_eq!(f.ret(454, &[WORDS, 1, 1, U32_PRIVATE | 4 | 8]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(WORDS)).unwrap(), 0);
        // futex_wait(uaddr, val, mask, flags, timeout, clockid): the value
        // and mask fit, the timeout comes before the mask's 0.
        assert_eq!(f.ret(455, &[WORDS, 1 << 32, 1, U32_PRIVATE, 0, 0]), einval);
        assert_eq!(f.ret(455, &[WORDS, 0, 1 << 32, U32_PRIVATE, 0, 0]), einval);
        assert_eq!(
            f.ret(455, &[WORDS, 0, 0, U32_PRIVATE, 8, 1]),
            errno(Errno::EFAULT)
        );
        assert_eq!(f.ret(455, &[WORDS, 0, 0, U32_PRIVATE, 0, 0]), einval);
        assert_eq!(
            f.ret(455, &[WORDS, 1, 1, U32_PRIVATE, 0, 0]),
            errno(Errno::EAGAIN)
        );
        timeout(&f, 0, 0);
        assert_eq!(
            f.ret(455, &[WORDS, 0, 1, U32_PRIVATE, TIMEOUT, 1]),
            errno(Errno(110))
        );
        // A timeout past KTIME_MAX is taken, as by FUTEX_WAIT_BITSET.
        timeout(&f, i64::MAX as u64, 0);
        assert_eq!(
            f.ret(455, &[WORDS, 1, 1, U32_PRIVATE, TIMEOUT, 1]),
            errno(Errno::EAGAIN)
        );
        assert_eq!(
            f.ret(202, &[WORDS, 9 | 128, 1, TIMEOUT, 0, u64::from(u32::MAX)]),
            errno(Errno::EAGAIN)
        );
        assert_eq!(
            f.ret(202, &[WORDS, 128, 1, TIMEOUT, 0, 0]),
            errno(Errno::EAGAIN)
        );
    }
}

mod futex_requeue {
    use super::*;
    const LIST: u64 = DATA + 0x100;
    const WORDS: u64 = DATA + 0x800;
    #[test]
    fn requeue_calls_check_as_linux_does() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // FUTEX_REQUEUE_PRIVATE, FUTEX_CMP_REQUEUE_PRIVATE: val, val2 (the
        // timeout argument) and val3, each an `int` or `u32`.
        assert_eq!(
            f.ret(202, &[WORDS, 3 | 128, u64::from(u32::MAX), 0, WORDS + 4, 0]),
            einval
        );
        assert_eq!(
            f.ret(202, &[WORDS, 3 | 128, 1, u64::from(u32::MAX), WORDS + 4, 0]),
            einval
        );
        assert_eq!(f.ret(202, &[WORDS, 3 | 128, 1, 1 << 32, WORDS + 4, 0]), 0);
        assert_eq!(f.ret(202, &[WORDS, 3 | 128, 1, 1, WORDS + 2, 0]), einval);
        assert_eq!(
            f.ret(202, &[WORDS, 4 | 128, 1, 1, WORDS + 4, 1]),
            errno(Errno::EAGAIN)
        );
        assert_eq!(f.ret(202, &[WORDS, 4 | 128, 1, 1, WORDS + 4, 1 << 32]), 0);
        // Not with FUTEX_CLOCK_REALTIME.
        assert_eq!(
            f.ret(202, &[WORDS, 4 | 128 | 256, 1, 1, WORDS + 4, 0]),
            errno(Errno::ENOSYS)
        );
        // FUTEX_WAKE_OP_PRIVATE: val2 is the timeout argument's low 32
        // bits and val3 an encoded `u32`; FUTEX_SET of 3 compared with
        // FUTEX_OP_CMP_EQ 0.
        let set = 3 << 12;
        assert_eq!(f.ret(202, &[WORDS, 5 | 128, 1, 1 << 32, WORDS + 4, set]), 0);
        assert_eq!(f.mem.read_u64(GuestAddr(WORDS)).unwrap(), 3 << 32);
        assert_eq!(
            f.ret(
                202,
                &[WORDS, 5 | 128, 1, 1, WORDS + 4, set | 5 << 28 | 1 << 32]
            ),
            errno(Errno::ENOSYS)
        );
        assert_eq!(
            f.ret(202, &[WORDS, 5 | 128 | 256, 1, 1, WORDS + 4, set]),
            errno(Errno::ENOSYS)
        );
        f.mem.write_u64(GuestAddr(WORDS), 0).unwrap();
        // futex_requeue(waiters, flags, nr_wake, nr_requeue)
        let entry = |f: &Fixture, i: u64, value: u64, addr: u64, flags: u64| {
            let at = LIST + 24 * i;
            f.mem.write_u64(GuestAddr(at), value).unwrap();
            f.mem.write_u64(GuestAddr(at + 8), addr).unwrap();
            f.mem.write_u64(GuestAddr(at + 16), flags).unwrap();
        };
        entry(&f, 0, 0, WORDS, 2 | 128);
        entry(&f, 1, 0, WORDS + 4, 2 | 128);
        assert_eq!(f.ret(456, &[LIST, 1, 1, 1]), einval);
        assert_eq!(f.ret(456, &[0, 0, 1, 1]), einval);
        assert_eq!(f.ret(456, &[LIST, 0, 1, 1]), 0);
        assert_eq!(f.ret(456, &[LIST, 0, u64::MAX, 1]), einval);
        // The second entry is read and checked too; then both must agree.
        entry(&f, 1, 1 << 32, WORDS + 4, 2 | 128);
        assert_eq!(f.ret(456, &[LIST, 0, 1, 1]), einval);
        entry(&f, 1, 0, WORDS + 4, 2);
        assert_eq!(f.ret(456, &[LIST, 0, 1, 1]), einval);
        entry(&f, 1, 0, WORDS + 4, 2 | 128);
        entry(&f, 0, 1, WORDS, 2 | 128);
        assert_eq!(f.ret(456, &[LIST, 0, 1, 1]), errno(Errno::EAGAIN));
        // The first entry is checked before the second is read.
        let last = DATA + 0x2000 - 24;
        assert_eq!(f.ret(456, &[last, 0, 1, 1]), einval);
        f.mem.write_u64(GuestAddr(last + 16), 2 | 128).unwrap();
        assert_eq!(f.ret(456, &[last, 0, 1, 1]), errno(Errno::EFAULT));
    }
}
mod kcmp {
    use super::*;
    const SLOT: u64 = DATA + 0x20;
    fn slot(f: &Fixture, efd: u64, tfd: u64, toff: u32) {
        let mut bytes = [0; 12];
        bytes[..4].copy_from_slice(&(efd as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&(tfd as u32).to_le_bytes());
        bytes[8..].copy_from_slice(&toff.to_le_bytes());
        f.mem.write(GuestAddr(SLOT), &bytes).unwrap();
    }
    #[test]
    fn kcmp_checks_and_compares_as_linux_does() {
        let mut f = fixture();
        let (esrch, einval, ebadf) = (errno(Errno(3)), errno(Errno::EINVAL), errno(Errno::EBADF));
        let pid = f.ret(39, &[]);
        // The numbers are `int`s, and a thread must have one.
        assert_eq!(f.ret(312, &[0, pid, 1, 0, 0]), esrch);
        assert_eq!(f.ret(312, &[pid, u64::MAX, 1, 0, 0]), esrch);
        assert_eq!(f.ret(312, &[pid, 999, 1, 0, 0]), esrch);
        assert_eq!(f.ret(312, &[pid | 1 << 32, pid, 1, 0, 0]), 0);
        // A thread shares everything with itself, the I/O context and the
        // undo list it does not have included; the type is an `int`.
        for kind in 1..=6 {
            assert_eq!(f.ret(312, &[pid, pid, kind, 0, 0]), 0, "type {kind}");
        }
        assert_eq!(f.ret(312, &[pid, pid, 1 | 1 << 32, 0, 0]), 0);
        assert_eq!(f.ret(312, &[pid, pid, 8, 0, 0]), einval);
        assert_eq!(f.ret(312, &[pid, pid, u64::MAX, 0, 0]), einval);
        // KCMP_FILE: a dup is the same description, another eventfd is not,
        // in one order each way; the indices are `unsigned int`s.
        let (a, b) = (f.ret(290, &[0, 0]), f.ret(290, &[0, 0]));
        let dup = f.ret(32, &[a]);
        assert_eq!(f.ret(312, &[pid, pid, 0, a, dup]), 0);
        let order = f.ret(312, &[pid, pid, 0, a, b]);
        assert!(order == 1 || order == 2, "{order}");
        assert_eq!(f.ret(312, &[pid, pid, 0, b, a]), 3 - order);
        assert_eq!(f.ret(312, &[pid, pid, 0, a, 99]), ebadf);
        assert_eq!(f.ret(312, &[pid, pid, 0, 99, a]), ebadf);
        assert_eq!(f.ret(312, &[pid, pid, 0, a | 1 << 32, dup]), 0);
        // KCMP_EPOLL_TFD: the slot first, then the first file, the epoll
        // file, that it is one, and the watched file, counted by `toff`.
        let epoll = f.ret(291, &[0]);
        f.mem.write(GuestAddr(DATA), &1u32.to_le_bytes()).unwrap();
        assert_eq!(f.ret(233, &[epoll, 1, b, DATA]), 0);
        slot(&f, epoll, b, 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, b, SLOT]), 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), order);
        assert_eq!(f.ret(312, &[99, pid, 7, a, 8]), esrch);
        assert_eq!(f.ret(312, &[pid, pid, 7, 99, 8]), errno(Errno::EFAULT));
        assert_eq!(f.ret(312, &[pid, pid, 7, 99, SLOT]), ebadf);
        slot(&f, 99, b, 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), ebadf);
        slot(&f, a, b, 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), einval);
        slot(&f, epoll, b, 1);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), errno(Errno::ENOENT));
        slot(&f, epoll, a, 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), errno(Errno::ENOENT));
        // Closing the watched file's last descriptor takes it out.
        assert_eq!(f.ret(3, &[b]), 0);
        slot(&f, epoll, b, 0);
        assert_eq!(f.ret(312, &[pid, pid, 7, a, SLOT]), errno(Errno::ENOENT));
    }
}
mod madvise_advice {
    use super::*;
    const AREA: u64 = DATA + 0x10_0000;
    const PAGE: u64 = 4096;
    #[test]
    fn remove_frees_shared_memory_and_punches_its_file() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        // Shared anonymous memory reads as zeros again, past the range not.
        let shared = f.ret(mmap, &[0, 2 * PAGE, 3, 0x21, u64::MAX, 0]);
        f.mem.write(GuestAddr(shared), b"ab").unwrap();
        f.mem.write(GuestAddr(shared + PAGE), b"c").unwrap();
        assert_eq!(f.ret(28, &[shared, PAGE, 9]), 0);
        assert_eq!(memory_bytes(&f, shared, 2), b"\0\0");
        assert_eq!(memory_bytes(&f, shared + PAGE, 1), b"c");
        // A shared file mapping punches a hole in the file.
        f.mem.write(GuestAddr(DATA), b"/file\0hello").unwrap();
        let fd = f.ret(2, &[DATA, 66, 0o600]);
        assert_eq!(f.ret(1, &[fd, DATA + 6, 5]), 5);
        assert_eq!(f.ret(77, &[fd, 2 * PAGE]), 0);
        let at = f.ret(mmap, &[0, 2 * PAGE, 3, 1, fd, 0]);
        f.mem.write(GuestAddr(at + PAGE), b"x").unwrap();
        assert_eq!(f.ret(28, &[at, PAGE, 9]), 0);
        assert_eq!(memory_bytes(&f, at, 5), b"\0\0\0\0\0");
        assert_eq!(file_bytes(&mut f, fd, 0, 5), b"\0\0\0\0\0");
        assert_eq!(memory_bytes(&f, at + PAGE, 1), b"x");
        // Memory of no file, and a file's memory not shared or not
        // writable through its file, are refused.
        let private = f.ret(mmap, &[0, PAGE, 3, 0x22, u64::MAX, 0]);
        assert_eq!(f.ret(28, &[private, PAGE, 9]), errno(Errno::EINVAL));
        let copy = f.ret(mmap, &[0, PAGE, 3, 2, fd, 0]);
        assert_eq!(f.ret(28, &[copy, PAGE, 9]), errno(Errno::EACCES));
        let read_only = f.ret(2, &[DATA, 0, 0]);
        let seen = f.ret(mmap, &[0, PAGE, 1, 1, read_only, 0]);
        assert_eq!(f.ret(28, &[seen, PAGE, 9]), errno(Errno::EACCES));
        // A hole is ENOMEM once the rest is freed.
        f.mem.write(GuestAddr(shared + PAGE), b"d").unwrap();
        assert_eq!(f.ret(11, &[shared, PAGE]), 0);
        assert_eq!(f.ret(28, &[shared, 2 * PAGE, 9]), errno(Errno::ENOMEM));
        assert_eq!(memory_bytes(&f, shared + PAGE, 1), b"\0");
    }
    #[test]
    fn a_secret_files_pages_are_not_populated_locked_or_synced() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        let fd = f.ret(447, &[0]);
        assert_eq!(f.ret(77, &[fd, 2 * PAGE]), 0);
        let at = f.ret(mmap, &[0, 2 * PAGE, 3, 1, fd, 0]);
        f.mem.write(GuestAddr(at), b"s").unwrap();
        // `get_user_pages` refuses its pages, which both populates and a
        // lock need: `mlock_fixup` gives its VMA no `VM_LOCKONFAULT`, so
        // even `MLOCK_ONFAULT` tries to bring them in. Unlocking is fine.
        assert_eq!(f.ret(28, &[at, 2 * PAGE, 22]), errno(Errno::EINVAL));
        assert_eq!(f.ret(28, &[at + PAGE, PAGE, 23]), errno(Errno::EINVAL));
        assert_eq!(f.ret(149, &[at, 2 * PAGE]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(325, &[at, 2 * PAGE, 1]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(150, &[at, 2 * PAGE]), 0);
        // Its file has no `fsync`, which only `MS_SYNC` makes, even past a
        // hole that `MS_ASYNC` stops at; a range that wraps is `ENOMEM`.
        assert_eq!(f.ret(26, &[at, 2 * PAGE, 4]), errno(Errno::EINVAL));
        assert_eq!(f.ret(26, &[at, 2 * PAGE, 1]), 0);
        assert_eq!(f.ret(26, &[at, 2 * PAGE, 0]), 0);
        assert_eq!(f.ret(11, &[at, PAGE]), 0);
        assert_eq!(f.ret(26, &[at, 2 * PAGE, 4]), errno(Errno::EINVAL));
        assert_eq!(f.ret(26, &[at, 2 * PAGE, 1]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(26, &[at, !(2 * PAGE - 1), 4]), errno(Errno::ENOMEM));
        // Beside it, the pages of a memfd are none of that.
        let plain = f.ret(319, &[DATA, 0]);
        assert_eq!(f.ret(77, &[plain, PAGE]), 0);
        let other = f.ret(mmap, &[0, PAGE, 3, 1, plain, 0]);
        assert_eq!(f.ret(28, &[other, PAGE, 23]), 0);
        assert_eq!(f.ret(149, &[other, PAGE]), 0);
        assert_eq!(f.ret(325, &[other, PAGE, 1]), 0);
        assert_eq!(f.ret(26, &[other, PAGE, 4]), 0);
    }
    #[test]
    fn guards_fault_until_removed_and_refuse_what_linux_refuses() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        let at = f.ret(mmap, &[0, 4 * PAGE, 3, 0x22, u64::MAX, 0]);
        for n in 0..4 {
            f.mem.write(GuestAddr(at + n * PAGE), b"a").unwrap();
        }
        assert_eq!(f.ret(28, &[at + PAGE, 2 * PAGE, 102]), 0);
        // A system call's copy faults on a guard page.
        assert_eq!(f.ret(79, &[at + PAGE, 64]), errno(Errno::EFAULT));
        assert_eq!(f.ret(79, &[at + 3 * PAGE, 64]), 2);
        // A populating mlock cannot fault it in; MLOCK_ONFAULT need not.
        assert_eq!(f.ret(149, &[at, 4 * PAGE]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(325, &[at, 4 * PAGE, 1]), 0);
        assert_eq!(f.ret(149, &[at + 3 * PAGE, PAGE]), 0);
        assert_eq!(f.ret(28, &[at, 4 * PAGE, 22]), errno(Errno::EFAULT));
        // Removing it leaves a page without contents.
        assert_eq!(f.ret(28, &[at + 2 * PAGE, PAGE, 103]), 0);
        assert_eq!(memory_bytes(&f, at + 2 * PAGE, 1), b"\0");
        assert_eq!(memory_bytes(&f, at, 1), b"a");
        assert!(f.mem.read(GuestAddr(at + PAGE), &mut [0]).is_err());
        // Sealed memory that may not be written takes none; it may lose
        // those it has.
        assert_eq!(f.ret(10, &[at, PAGE, 1]), 0);
        assert_eq!(f.ret(462, &[at, PAGE, 0]), 0);
        assert_eq!(f.ret(28, &[at, PAGE, 102]), errno(Errno::EPERM));
        assert_eq!(f.ret(28, &[at, PAGE, 103]), 0);
        // An AIO ring takes neither.
        assert_eq!(f.ret(206, &[1, DATA + 0x400]), 0);
        let ring = f.mem.read_u64(GuestAddr(DATA + 0x400)).unwrap();
        assert_eq!(f.ret(28, &[ring, PAGE, 102]), errno(Errno::EINVAL));
        assert_eq!(f.ret(28, &[ring, PAGE, 103]), errno(Errno::EINVAL));
    }
    #[test]
    fn secret_pages_count_against_memlock_until_the_file_goes() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        // RLIMIT_MEMLOCK of two pages.
        f.mem.write_u64(GuestAddr(DATA), 2 * PAGE).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), u64::MAX).unwrap();
        assert_eq!(f.ret(160, &[8, DATA]), 0);
        let fd = f.ret(447, &[0]);
        assert_eq!(f.ret(77, &[fd, 4 * PAGE]), 0);
        // The mapping may be larger than the limit; a fault past it is a
        // bus error.
        let at = f.ret(mmap, &[0, 4 * PAGE, 3, 1, fd, 0]);
        f.mem.write(GuestAddr(at), b"s").unwrap();
        f.mem.read(GuestAddr(at + PAGE), &mut [0]).unwrap();
        let fault = f.mem.read(GuestAddr(at + 2 * PAGE), &mut [0]).unwrap_err();
        assert!(fault.bus, "{fault:?}");
        // MS_SYNC fsyncs a file that has none; MS_ASYNC does nothing; GUP
        // refuses secret memory.
        assert_eq!(f.ret(26, &[at, 4 * PAGE, 4]), errno(Errno::EINVAL));
        assert_eq!(f.ret(26, &[at, 4 * PAGE, 1]), 0);
        assert_eq!(f.ret(28, &[at, PAGE, 22]), errno(Errno::EINVAL));
        // Unmapped, the pages stay charged; once the file goes they do not.
        assert_eq!(f.ret(11, &[at, 4 * PAGE]), 0);
        let other = f.ret(447, &[0]);
        assert_eq!(f.ret(77, &[other, PAGE]), 0);
        let o = f.ret(mmap, &[0, PAGE, 1, 1, other, 0]);
        assert!(f.mem.read(GuestAddr(o), &mut [0]).unwrap_err().bus);
        assert_eq!(f.ret(3, &[fd]), 0);
        f.mem.read(GuestAddr(o), &mut [0]).unwrap();
    }
    #[test]
    fn locked_memory_is_counted_and_refused_what_linux_refuses() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        let at = f.ret(mmap, &[0, 4 * PAGE, 3, 0x22, u64::MAX, 0]);
        // A lock splits the VMA off.
        assert_eq!(f.ret(149, &[at + PAGE, PAGE]), 0);
        let locked = f.mem.first_locked(GuestAddr(at), at + 4 * PAGE).unwrap();
        assert_eq!((locked.start.0, locked.length), (at + PAGE, PAGE));
        assert_eq!(f.mem.locked_pages(), 1);
        // Advice that drops or ages pages stops at it; what came before took
        // it. MADV_DONTNEED_LOCKED takes it.
        f.mem.write(GuestAddr(at), b"x").unwrap();
        assert_eq!(f.ret(28, &[at, 4 * PAGE, 4]), errno(Errno::EINVAL));
        assert_eq!(memory_bytes(&f, at, 1), b"\0");
        for advice in [8, 9, 20, 21, 102] {
            assert_eq!(
                f.ret(28, &[at, 4 * PAGE, advice]),
                errno(Errno::EINVAL),
                "{advice}"
            );
        }
        assert_eq!(f.ret(28, &[at + PAGE, PAGE, 24]), 0);
        // MADV_GUARD_INSTALL put a guard on the page before the locked one.
        assert_eq!(f.ret(28, &[at, PAGE, 103]), 0);
        // MS_INVALIDATE of locked memory is EBUSY.
        assert_eq!(f.ret(26, &[at, 4 * PAGE, 2]), errno(Errno(16)));
        assert_eq!(f.ret(150, &[at, 4 * PAGE]), 0);
        assert_eq!(f.mem.locked_pages(), 0);
        // Secret memory is locked by MAP_LOCKED, which only `mlock_fixup`
        // passes over: a later mlock leaves it as it is.
        let fd = f.ret(447, &[0]);
        assert_eq!(f.ret(77, &[fd, PAGE]), 0);
        let secret = f.ret(mmap, &[0, PAGE, 3, 0x2001, fd, 0]);
        assert!(
            f.mem
                .first_locked(GuestAddr(secret), secret + PAGE)
                .is_some()
        );
        assert_eq!(f.ret(11, &[secret, PAGE]), 0);
        let plain = f.ret(mmap, &[0, PAGE, 3, 1, fd, 0]);
        assert_eq!(f.ret(149, &[plain, PAGE]), errno(Errno::ENOMEM));
        assert!(f.mem.first_locked(GuestAddr(plain), plain + PAGE).is_none());
        assert_eq!(f.ret(11, &[plain, PAGE]), 0);
        assert_eq!(f.mem.locked_pages(), 0);
        // Without CAP_IPC_LOCK, RLIMIT_MEMLOCK bounds what is locked.
        f.mem.write_u64(GuestAddr(DATA), PAGE).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), u64::MAX).unwrap();
        assert_eq!(f.ret(160, &[8, DATA]), 0);
        let all = crate::credentials::ALL_CAPABILITIES;
        f.thread.state.credentials = f
            .thread
            .state
            .credentials
            .capset(!(1 << 14) & all, all, 0)
            .unwrap();
        assert_eq!(f.ret(149, &[at, 2 * PAGE]), errno(Errno::ENOMEM));
        assert_eq!(f.ret(149, &[at, PAGE]), 0);
        // What is locked already does not count again.
        assert_eq!(f.ret(149, &[at, PAGE]), 0);
        assert_eq!(
            f.ret(mmap, &[0, PAGE, 3, 0x2022, u64::MAX, 0]),
            errno(Errno::EAGAIN)
        );
        assert_eq!(f.ret(151, &[1]), errno(Errno::ENOMEM));
        // MCL_FUTURE locks what comes next, and needs room for it too.
        assert_eq!(f.ret(151, &[2]), 0);
        assert_eq!(
            f.ret(mmap, &[0, PAGE, 3, 0x22, u64::MAX, 0]),
            errno(Errno::EAGAIN)
        );
        assert_eq!(f.ret(152, &[]), 0);
        assert_eq!(f.mem.locked_pages(), 0);
        let new = f.ret(mmap, &[0, PAGE, 3, 0x22, u64::MAX, 0]);
        assert!(new < u64::MAX - 4095, "{new:#x}");
        // No RLIMIT_MEMLOCK at all is EPERM.
        f.mem.write_u64(GuestAddr(DATA), 0).unwrap();
        assert_eq!(f.ret(160, &[8, DATA]), 0);
        assert_eq!(f.ret(149, &[at, PAGE]), errno(Errno::EPERM));
        assert_eq!(f.ret(151, &[1]), errno(Errno::EPERM));
    }
    fn status(f: &mut Fixture, at: u64) -> i32 {
        f.mem.write_u64(GuestAddr(DATA + 0x200), at).unwrap();
        assert_eq!(f.ret(279, &[0, 1, DATA + 0x200, 0, DATA + 0x300, 0]), 0);
        f.mem.read_u64(GuestAddr(DATA + 0x300)).unwrap() as i32
    }
    #[test]
    fn hints_need_only_a_mapping() {
        let mut f = fixture();
        f.mem
            .map(
                Some(GuestAddr(AREA)),
                2 * PAGE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        f.mem.write(GuestAddr(AREA), &[7]).unwrap();
        for advice in [12, 13, 14, 15, 20, 21] {
            assert_eq!(f.ret(28, &[AREA, 2 * PAGE, advice]), 0, "{advice}");
            assert_eq!(f.ret(28, &[AREA, 3 * PAGE, advice]), errno(Errno::ENOMEM));
        }
        let mut byte = [0];
        f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
        assert_eq!(byte, [7]);
        // The fork and dump flags take a mapping too; a hole is ENOMEM.
        for advice in [10, 11, 16, 17, 18, 19] {
            assert_eq!(f.ret(28, &[AREA, 2 * PAGE, advice]), 0, "{advice}");
            assert_eq!(f.ret(28, &[AREA, 3 * PAGE, advice]), errno(Errno::ENOMEM));
        }
        // MADV_COLLAPSE refuses a VMA with no room for a 2 MiB extent.
        assert_eq!(f.ret(28, &[AREA, PAGE, 25]), errno(Errno::EINVAL));
        // Unknown advice is refused.
        for advice in [26, 104] {
            assert_eq!(
                f.ret(28, &[AREA, PAGE, advice]),
                errno(Errno::EINVAL),
                "{advice}"
            );
        }
        // The memory failure advice checks the range's arguments, then
        // CAP_SYS_ADMIN (EPERM) before the address limit or any mapping.
        let root = f.thread.state.credentials.clone();
        f.thread.state.credentials = root.setresuid(1000, 1000, 1000).unwrap();
        for advice in [100, 101] {
            assert_eq!(f.ret(28, &[AREA + 1, PAGE, advice]), errno(Errno::EINVAL));
            assert_eq!(f.ret(28, &[AREA, u64::MAX, advice]), errno(Errno::EINVAL));
            assert_eq!(f.ret(28, &[!4095, 2 * PAGE, advice]), errno(Errno::EINVAL));
            assert_eq!(f.ret(28, &[AREA, 0, advice]), 0);
            for addr in [AREA, AREA + 64 * PAGE, 1 << 47] {
                assert_eq!(f.ret(28, &[addr, PAGE, advice]), errno(Errno::EPERM));
            }
        }
        f.thread.state.credentials = root;
        let mut byte = [0];
        f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
        assert_eq!(byte, [7]);
        // MADV_DONTNEED_LOCKED discards.
        assert_eq!(f.ret(28, &[AREA, PAGE, 24]), 0);
        assert_eq!(status(&mut f, AREA), -2);
    }
    #[test]
    fn collapse_takes_written_private_anonymous_memory_an_extent_at_a_time() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        const HUGE: u64 = 2 << 20;
        const BASE: u64 = 0x4000_0000;
        // Private anonymous memory, fixed: four extents.
        assert_eq!(f.ret(mmap, &[BASE, 4 * HUGE, 3, 0x32, u64::MAX, 0]), BASE);
        // No page of it was written: no anon_vma.
        assert_eq!(f.ret(28, &[BASE, HUGE, 25]), errno(Errno::EINVAL));
        f.mem.write(GuestAddr(BASE + HUGE + 5), &[9]).unwrap();
        // No whole extent in the range: nothing to do.
        assert_eq!(f.ret(28, &[BASE + PAGE, HUGE, 25]), 0);
        assert_eq!(f.mem.resident(GuestAddr(BASE + 2 * PAGE)), Some(false));
        // The second extent has a page table and is collapsed whole; the
        // first has none (EINVAL), which does not stop the third.
        f.mem.read(GuestAddr(BASE + 2 * HUGE), &mut [0]).unwrap();
        assert_eq!(f.ret(28, &[BASE, 3 * HUGE, 25]), errno(Errno::EINVAL));
        assert_eq!(f.mem.resident(GuestAddr(BASE)), Some(false));
        for at in [
            BASE + HUGE,
            BASE + 2 * HUGE - PAGE,
            BASE + 2 * HUGE,
            BASE + 3 * HUGE - PAGE,
        ] {
            assert_eq!(f.mem.resident(GuestAddr(at)), Some(true), "{at:#x}");
        }
        assert_eq!(memory_bytes(&f, BASE + HUGE + 5, 1), [9]);
        assert_eq!(f.mem.resident(GuestAddr(BASE + 3 * HUGE)), Some(false));
        // Both done, again: 0.
        assert_eq!(f.ret(28, &[BASE + HUGE, 2 * HUGE, 25]), 0);
        // A poisoned page (an injected memory failure) fails its extent.
        f.mem
            .write(GuestAddr(BASE + 3 * HUGE + PAGE), &[1])
            .unwrap();
        assert_eq!(
            inject(&f, BASE + 3 * HUGE + PAGE, PAGE, 100),
            (Ok(()), Some(BASE + 3 * HUGE + PAGE))
        );
        assert_eq!(
            f.ret(28, &[BASE + 3 * HUGE, HUGE, 25]),
            errno(Errno::EINVAL)
        );
        // A hole after the VMA is ENOMEM once the walk is done.
        assert_eq!(
            f.ret(28, &[BASE + HUGE, 4 * HUGE, 25]),
            errno(Errno::EINVAL)
        );
        assert_eq!(
            f.ret(28, &[BASE + 4 * HUGE - PAGE, 2 * PAGE, 25]),
            errno(Errno::ENOMEM)
        );
        // MADV_NOHUGEPAGE refuses its VMA, which it splits off.
        assert_eq!(f.ret(28, &[BASE, HUGE, 15]), 0);
        assert_eq!(f.ret(28, &[BASE, PAGE, 25]), errno(Errno::EINVAL));
        assert_eq!(f.ret(28, &[BASE + HUGE, PAGE, 25]), 0);
        // Too small a VMA is refused, and shared memory whose address is
        // out of step with its file offsets (0 at its start).
        let small = f.ret(mmap, &[0, HUGE, 3, 0x22, u64::MAX, 0]);
        f.mem.write(GuestAddr(small), &[1]).unwrap();
        let aligned = small & (HUGE - 1) == 0;
        assert_eq!(
            f.ret(28, &[small, PAGE, 25]),
            if aligned { 0 } else { errno(Errno::EINVAL) }
        );
        let shared = f.ret(mmap, &[0, 2 * HUGE, 3, 0x21, u64::MAX, 0]);
        f.mem.write(GuestAddr(shared), &[1]).unwrap();
        let aligned = shared & (HUGE - 1) == 0;
        assert_eq!(
            f.ret(28, &[shared, PAGE, 25]),
            if aligned { 0 } else { errno(Errno::EINVAL) }
        );
    }
    #[test]
    fn collapse_of_a_registered_range_wants_every_page() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        const HUGE: u64 = 2 << 20;
        const BASE: u64 = 0x4000_0000;
        assert_eq!(f.ret(mmap, &[BASE, HUGE, 3, 0x32, u64::MAX, 0]), BASE);
        f.mem.write(GuestAddr(BASE), &[1]).unwrap();
        let uffd = f.ret(323, &[0]);
        f.mem.write_u64(GuestAddr(DATA), 0xAA).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), 0).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 16), 0).unwrap();
        assert_eq!(f.ret(16, &[uffd, 0xC018_AA3F, DATA]), 0);
        f.mem.write_u64(GuestAddr(DATA), BASE).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 8), HUGE).unwrap();
        f.mem.write_u64(GuestAddr(DATA + 16), 1).unwrap();
        assert_eq!(f.ret(16, &[uffd, 0xC020_AA00, DATA]), 0);
        assert_eq!(f.ret(28, &[BASE, HUGE, 25]), errno(Errno(16)));
        assert_eq!(f.mem.resident(GuestAddr(BASE + PAGE)), Some(false));
    }
    /// `madvise(addr, len, advice)` of the fixture's memory as root, and the
    /// page whose poisoning would SIGBUS the caller.
    fn inject(f: &Fixture, addr: u64, len: u64, advice: u64) -> (Result<(), Errno>, Option<u64>) {
        let mut poisoned = None;
        let result = syscalls::advise(
            &f.mem,
            &f.thread.state.credentials,
            addr,
            len,
            advice,
            &mut |_, _| {},
            &mut poisoned,
        );
        (result, poisoned)
    }
    #[test]
    fn memory_failure_advice_poisons_or_offlines_with_cap_sys_admin() {
        let mut f = fixture();
        let mmap = syscalls::nr::MMAP;
        let p = f.ret(mmap, &[0, 4 * PAGE, 3, 0x22, u64::MAX, 0]);
        f.mem.write(GuestAddr(p), b"a").unwrap();
        f.mem.write(GuestAddr(p + PAGE), b"b").unwrap();
        // MADV_SOFT_OFFLINE moves a page: its contents stay. The zero page
        // is the kernel's (ENOTRECOVERABLE), after the pages before it.
        assert_eq!(f.ret(28, &[p, 2 * PAGE, 101]), 0);
        assert_eq!(memory_bytes(&f, p, 1), b"a");
        assert_eq!(f.ret(28, &[p, 3 * PAGE, 101]), errno(Errno(131)));
        // MADV_HWPOISON poisons each page; the first is where the caller's
        // SIGBUS points, and each access faults on it (BUS_MCEERR_AR) until
        // a discard drops it.
        assert_eq!(inject(&f, p + 1 - 1, 2 * PAGE - 1, 100), (Ok(()), Some(p)));
        for at in [p, p + PAGE] {
            let fault = f.mem.read(GuestAddr(at), &mut [0]).unwrap_err();
            assert!(fault.poison && fault.bus, "{at:#x}");
        }
        // Again: the page cannot be brought in (EHWPOISON).
        assert_eq!(inject(&f, p, PAGE, 100), (Err(Errno(133)), None));
        assert_eq!(inject(&f, p, PAGE, 101), (Err(Errno(133)), None));
        // The zero page is the kernel's (EBUSY); a hole, a page that may not
        // be read and shared memory's are not poisoned.
        assert_eq!(inject(&f, p + 2 * PAGE, PAGE, 100), (Err(Errno(16)), None));
        assert_eq!(
            inject(&f, p + 4 * PAGE, PAGE, 100),
            (Err(Errno::EFAULT), None)
        );
        let none = f.ret(mmap, &[0, PAGE, 0, 0x22, u64::MAX, 0]);
        assert_eq!(inject(&f, none, PAGE, 100), (Err(Errno::EFAULT), None));
        let shared = f.ret(mmap, &[0, PAGE, 3, 0x21, u64::MAX, 0]);
        f.mem.write(GuestAddr(shared), b"s").unwrap();
        assert_eq!(inject(&f, shared, PAGE, 100), (Err(Errno::EIO), None));
        assert_eq!(memory_bytes(&f, shared, 1), b"s");
        // MADV_DONTNEED drops the poison: zeros again.
        assert_eq!(f.ret(28, &[p, 2 * PAGE, 4]), 0);
        assert_eq!(memory_bytes(&f, p + PAGE, 1), b"\0");
        // The SIGBUS is forced on the caller at once: by default it ends it.
        f.mem.write(GuestAddr(p + 3 * PAGE), b"c").unwrap();
        assert_eq!(
            f.call(28, &[p + 3 * PAGE, PAGE, 100]),
            Next::Exit(ExitStatus::Signaled(7))
        );
    }
    #[test]
    fn populate_faults_pages_in_until_one_cannot_be() {
        let mut f = fixture();
        let m = &mut f.mem;
        m.map(
            Some(GuestAddr(AREA)),
            3 * PAGE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.map(
            Some(GuestAddr(AREA + 4 * PAGE)),
            PAGE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.map(
            Some(GuestAddr(AREA + 6 * PAGE)),
            PAGE,
            Prot::READ,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.map(
            Some(GuestAddr(AREA + 8 * PAGE)),
            PAGE,
            Prot::NONE,
            MappingKind::Anonymous,
        )
        .unwrap();
        // A read maps the zero page, a write a page of its own.
        assert_eq!(f.ret(28, &[AREA, PAGE, 22]), 0);
        assert_eq!(status(&mut f, AREA), -14);
        f.mem.write(GuestAddr(AREA + 2 * PAGE), &[5]).unwrap();
        assert_eq!(f.ret(28, &[AREA + PAGE, 2 * PAGE, 23]), 0);
        assert_eq!(status(&mut f, AREA + PAGE), 0);
        let mut byte = [0];
        f.mem.read(GuestAddr(AREA + 2 * PAGE), &mut byte).unwrap();
        assert_eq!(byte, [5]);
        // A hole after a page: that page, then ENOMEM.
        assert_eq!(
            f.ret(28, &[AREA + 4 * PAGE, 2 * PAGE, 22]),
            errno(Errno::ENOMEM)
        );
        assert_eq!(status(&mut f, AREA + 4 * PAGE), -14);
        // A mapping that may not be read, or written.
        assert_eq!(
            f.ret(28, &[AREA + 8 * PAGE, PAGE, 22]),
            errno(Errno::EINVAL)
        );
        assert_eq!(
            f.ret(28, &[AREA + 6 * PAGE, PAGE, 23]),
            errno(Errno::EINVAL)
        );
        assert_eq!(f.ret(28, &[AREA + 6 * PAGE, PAGE, 22]), 0);
    }
}
mod page_nodes {
    use super::*;
    const AREA: u64 = DATA + 0x10_0000;
    const MASKS: u64 = DATA + 0x100;
    const ARRAY: u64 = DATA + 0x200;
    const STATUS: u64 = DATA + 0x400;
    /// Four read-write pages at `AREA`, and the masks {0} and {1} at
    /// `MASKS` and `MASKS + 8`.
    fn area(f: &mut Fixture) {
        f.mem
            .map(
                Some(GuestAddr(AREA)),
                0x4000,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        f.mem.write_u64(GuestAddr(MASKS), 1).unwrap();
        f.mem.write_u64(GuestAddr(MASKS + 8), 2).unwrap();
    }
    fn statuses(f: &Fixture, n: usize) -> Vec<i32> {
        let mut bytes = vec![0u8; n * 4];
        f.mem.read(GuestAddr(STATUS), &mut bytes).unwrap();
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| i32::from_le_bytes(*b))
            .collect()
    }
    #[test]
    fn home_node_needs_a_bind_or_preferred_many_policy() {
        let mut f = fixture();
        area(&mut f);
        let (einval, enoent, eopnotsupp) = (
            errno(Errno::EINVAL),
            errno(Errno::ENOENT),
            errno(Errno::EOPNOTSUPP),
        );
        assert_eq!(f.ret(450, &[AREA + 1, 0x1000, 0, 0]), einval);
        assert_eq!(f.ret(450, &[AREA, 0x1000, 0, 1]), einval);
        assert_eq!(f.ret(450, &[AREA, 0x1000, 1, 0]), einval);
        assert_eq!(f.ret(450, &[AREA, 0, 1, 0]), einval);
        assert_eq!(f.ret(450, &[AREA, 0, 0, 0]), 0);
        assert_eq!(
            f.ret(450, &[0u64.wrapping_sub(0x1000), 0x2000, 0, 0]),
            einval
        );
        assert_eq!(f.ret(450, &[AREA, 0x4000, 0, 0]), enoent);
        assert_eq!(f.ret(450, &[AREA + 0x10_0000, 0x1000, 0, 0]), enoent);
        // mbind: bind, interleave, nothing, preferred-many.
        assert_eq!(f.ret(237, &[AREA, 0x1000, 2, MASKS, 65, 0]), 0);
        assert_eq!(f.ret(237, &[AREA + 0x1000, 0x1000, 3, MASKS, 65, 0]), 0);
        assert_eq!(f.ret(237, &[AREA + 0x3000, 0x1000, 5, MASKS, 65, 0]), 0);
        assert_eq!(f.ret(450, &[AREA, 1, 0, 0]), 0);
        assert_eq!(f.ret(450, &[AREA + 0x1000, 0x1000, 0, 0]), eopnotsupp);
        assert_eq!(f.ret(450, &[AREA, 0x2000, 0, 0]), eopnotsupp);
        assert_eq!(f.ret(450, &[AREA + 0x2000, 0x2000, 0, 0]), 0);
        assert_eq!(f.ret(237, &[AREA, 0x1000, 0, 0, 0, 0]), 0);
        assert_eq!(f.ret(450, &[AREA, 0x1000, 0, 0]), enoent);
    }
    #[test]
    fn migrate_pages_reads_both_masks_then_the_task() {
        let mut f = fixture();
        area(&mut f);
        let pid = f.ret(39, &[]);
        let (einval, efault, esrch) = (errno(Errno::EINVAL), errno(Errno::EFAULT), errno(Errno(3)));
        assert_eq!(f.ret(256, &[0, 65, MASKS, MASKS]), 0);
        assert_eq!(f.ret(256, &[pid, 65, MASKS, MASKS]), 0);
        assert_eq!(f.ret(256, &[0, 65, 0, MASKS]), 0);
        assert_eq!(f.ret(256, &[0, 65, MASKS, 0]), einval);
        assert_eq!(f.ret(256, &[0, 0, MASKS, MASKS]), einval);
        assert_eq!(f.ret(256, &[0, 4096 * 8 + 2, MASKS, MASKS]), einval);
        assert_eq!(f.ret(256, &[0, 65, 8, MASKS]), efault);
        assert_eq!(f.ret(256, &[u64::MAX, 65, MASKS, 8]), efault);
        assert_eq!(f.ret(256, &[u64::MAX, 65, MASKS, MASKS]), esrch);
        assert_eq!(f.ret(256, &[999, 65, MASKS, MASKS]), esrch);
        // Node 1 is past the nodes the task may use, which root may ask
        // for: none of it is left for the caller.
        assert_eq!(f.ret(256, &[0, 65, MASKS, MASKS + 8]), einval);
    }
    #[test]
    fn move_pages_reports_each_page_on_node_zero() {
        let mut f = fixture();
        area(&mut f);
        let (einval, efault, enodev) = (
            errno(Errno::EINVAL),
            errno(Errno::EFAULT),
            errno(Errno::ENODEV),
        );
        f.mem.write(GuestAddr(AREA), &[1]).unwrap();
        let mut byte = [0u8];
        f.mem.read(GuestAddr(AREA + 0x1000), &mut byte).unwrap();
        let pages = [AREA, AREA + 0x1005, AREA + 0x2000, AREA + 0x10_0000, 0];
        for (i, page) in pages.iter().enumerate() {
            f.mem
                .write_u64(GuestAddr(ARRAY + i as u64 * 8), *page)
                .unwrap();
        }
        let nodes = ARRAY + 0x100;
        f.mem.write(GuestAddr(nodes), &[0; 20]).unwrap();
        assert_eq!(f.ret(279, &[0, 5, ARRAY, 0, STATUS, 0]), 0);
        assert_eq!(statuses(&f, 5), [0, -14, -2, -14, -14]);
        f.mem.write(GuestAddr(STATUS), &[0x55; 20]).unwrap();
        assert_eq!(f.ret(279, &[0, 5, ARRAY, nodes, STATUS, 2]), 0);
        assert_eq!(statuses(&f, 5), [0, -14, -2, -14, -14]);
        f.mem.write(GuestAddr(STATUS), &[0x55; 20]).unwrap();
        f.mem
            .write(GuestAddr(nodes + 8), &1i32.to_le_bytes())
            .unwrap();
        assert_eq!(f.ret(279, &[0, 5, ARRAY, nodes, STATUS, 0]), enodev);
        assert_eq!(statuses(&f, 3), [0, -14, 0x5555_5555]);
        assert_eq!(f.ret(279, &[0, 1, ARRAY, 0, STATUS, 1]), einval);
        assert_eq!(f.ret(279, &[0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(f.ret(279, &[0, 1, 8, 0, STATUS, 0]), efault);
        assert_eq!(f.ret(279, &[0, 1, ARRAY, 0, 8, 0]), efault);
        assert_eq!(f.ret(279, &[0, 1, ARRAY, 8, STATUS, 0]), efault);
        assert_eq!(f.ret(279, &[999, 1, ARRAY, 0, STATUS, 0]), errno(Errno(3)));
        // Discarded, a page is gone again.
        assert_eq!(f.ret(28, &[AREA, 0x1000, 4]), 0);
        assert_eq!(f.ret(279, &[0, 1, ARRAY, 0, STATUS, 0]), 0);
        assert_eq!(statuses(&f, 1), [-2]);
    }
    #[test]
    fn process_madvise_advises_the_callers_ranges_in_turn() {
        let mut f = fixture();
        area(&mut f);
        let (einval, ebadf, enomem, efault) = (
            errno(Errno::EINVAL),
            errno(Errno::EBADF),
            errno(Errno::ENOMEM),
            errno(Errno::EFAULT),
        );
        let pid = f.ret(39, &[]);
        let pidfd = f.ret(434, &[pid, 0]);
        let iov = [
            (AREA, 0x1000),
            (AREA + 0x1000, 100),
            (AREA + 0x10_0000, 0x1000),
        ];
        for (i, (base, len)) in iov.iter().enumerate() {
            f.mem
                .write_u64(GuestAddr(ARRAY + i as u64 * 16), *base)
                .unwrap();
            f.mem
                .write_u64(GuestAddr(ARRAY + i as u64 * 16 + 8), *len)
                .unwrap();
        }
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 1, 3, 0]), 0x1000);
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 2, 3, 0]), 0x1000 + 100);
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 3, 3, 0]), 0x1000 + 100);
        assert_eq!(f.ret(440, &[pidfd, ARRAY + 32, 1, 3, 0]), enomem);
        assert_eq!(f.ret(440, &[(-10000i64) as u64, ARRAY, 1, 3, 0]), 0x1000);
        assert_eq!(f.ret(440, &[(-10001i64) as u64, ARRAY, 1, 3, 0]), 0x1000);
        assert_eq!(f.ret(440, &[(-20000i64) as u64, ARRAY, 1, 3, 0]), ebadf);
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 1, 3, 1]), einval);
        assert_eq!(f.ret(440, &[pidfd, 0, 0, 3, 0]), 0);
        assert_eq!(f.ret(440, &[pidfd, 0, 0, 999, 0]), einval);
        assert_eq!(f.ret(440, &[u64::MAX, ARRAY, 1, 999, 0]), ebadf);
        assert_eq!(f.ret(440, &[0, ARRAY, 1, 3, 0]), ebadf);
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 1025, 3, 0]), einval);
        assert_eq!(f.ret(440, &[pidfd, 8, 1, 3, 0]), efault);
        // The count is an `unsigned int` to import_iovec.
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 1 | 1 << 32, 3, 0]), 0x1000);
        // A misaligned range stops the call, after the ones before it.
        f.mem.write_u64(GuestAddr(ARRAY + 16), AREA + 1).unwrap();
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 2, 3, 0]), 0x1000);
        assert_eq!(f.ret(440, &[pidfd, ARRAY + 16, 1, 3, 0]), einval);
        // MADV_DONTNEED empties the caller's page.
        f.mem.write(GuestAddr(AREA), &[7]).unwrap();
        assert_eq!(f.ret(440, &[pidfd, ARRAY, 1, 4, 0]), 0x1000);
        let mut byte = [9u8];
        f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
        assert_eq!(byte, [0]);
    }
    #[test]
    fn map_shadow_stack_is_not_supported() {
        let mut f = fixture();
        assert_eq!(f.ret(453, &[0, 0x1000, 0]), errno(Errno::EOPNOTSUPP));
        assert_eq!(f.ret(453, &[0, 0x1000, 99]), errno(Errno::EOPNOTSUPP));
    }
}
mod process_vm {
    use super::*;
    const LOCAL: u64 = DATA + 0x40;
    const REMOTE: u64 = DATA + 0x80;
    /// Writes the iovec array `segments` at `at`.
    fn iovecs(f: &Fixture, at: u64, segments: &[(u64, u64)]) {
        for (index, &(base, length)) in segments.iter().enumerate() {
            let entry = at + index as u64 * 16;
            f.mem.write_u64(GuestAddr(entry), base).unwrap();
            f.mem.write_u64(GuestAddr(entry + 8), length).unwrap();
        }
    }
    #[test]
    fn process_vm_checks_in_linux_order() {
        let mut f = fixture();
        let (esrch, einval, efault) = (errno(Errno(3)), errno(Errno::EINVAL), errno(Errno::EFAULT));
        let pid = f.ret(39, &[]);
        iovecs(&f, LOCAL, &[(DATA + 0x800, 8)]);
        iovecs(&f, REMOTE, &[(DATA + 0x900, 8)]);
        for number in [310, 311] {
            // flags, then the local array, before anything else.
            assert_eq!(f.ret(number, &[999, LOCAL, 1, REMOTE, 1, 1]), einval);
            assert_eq!(f.ret(number, &[999, LOCAL, 1025, REMOTE, 1, 0]), einval);
            assert_eq!(f.ret(number, &[999, 8, 1, REMOTE, 1, 0]), efault);
            // No local bytes: nothing more is looked at.
            assert_eq!(f.ret(number, &[999, LOCAL, 0, 8, 1, 0]), 0);
            // The remote array: its count, that it can be read, its lengths.
            assert_eq!(f.ret(number, &[999, LOCAL, 1, REMOTE, 1025, 0]), einval);
            assert_eq!(f.ret(number, &[999, LOCAL, 1, 8, 1, 0]), efault);
            // No remote bytes: the task is not looked for.
            assert_eq!(f.ret(number, &[999, LOCAL, 1, REMOTE, 0, 0]), 0);
            // Then the task, by an `int`.
            assert_eq!(f.ret(number, &[999, LOCAL, 1, REMOTE, 1, 0]), esrch);
            assert_eq!(f.ret(number, &[0, LOCAL, 1, REMOTE, 1, 0]), esrch);
            assert_eq!(f.ret(number, &[u64::MAX, LOCAL, 1, REMOTE, 1, 0]), esrch);
            assert_eq!(f.ret(number, &[pid | 1 << 32, LOCAL, 1, REMOTE, 1, 0]), 8);
        }
        iovecs(&f, REMOTE, &[(DATA + 0x900, 1 << 63)]);
        assert_eq!(f.ret(310, &[999, LOCAL, 1, REMOTE, 1, 0]), einval);
        iovecs(&f, REMOTE, &[(DATA + 0x900, 0), (DATA + 0x900, 0)]);
        assert_eq!(f.ret(310, &[999, LOCAL, 1, REMOTE, 2, 0]), 0);
    }
    #[test]
    fn process_vm_copies_and_stops_at_a_fault() {
        let mut f = fixture();
        let efault = errno(Errno::EFAULT);
        let pid = f.ret(39, &[]);
        // A read-only page after the data, and a page mapped write-only,
        // which has no VM_READ for the remote side to read.
        f.mem
            .map(
                Some(GuestAddr(DATA + 0x2000)),
                0x1000,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        const ONLY_WRITE: u64 = 0x40_0000;
        f.mem
            .map(
                Some(GuestAddr(ONLY_WRITE)),
                0x1000,
                Prot::WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        f.mem
            .write(GuestAddr(DATA + 0x800), b"hello, world")
            .unwrap();
        // Two local buffers take one remote one in turn.
        iovecs(&f, LOCAL, &[(DATA + 0xa00, 5), (DATA + 0xb00, 7)]);
        iovecs(&f, REMOTE, &[(DATA + 0x800, 12)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 2, REMOTE, 1, 0]), 12);
        let mut out = [0; 7];
        f.mem.read(GuestAddr(DATA + 0xa00), &mut out[..5]).unwrap();
        assert_eq!(&out[..5], b"hello");
        f.mem.read(GuestAddr(DATA + 0xb00), &mut out).unwrap();
        assert_eq!(&out, b", world");
        // A remote buffer that runs into a page that is not mapped gives the
        // bytes before it; one that starts there is EFAULT, and so ends the
        // copy, the bytes before it the result.
        iovecs(&f, LOCAL, &[(DATA + 0xa00, 64)]);
        iovecs(&f, REMOTE, &[(DATA + 0x2ff8, 16)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 1, 0]), 8);
        iovecs(&f, REMOTE, &[(DATA + 0x3000, 16)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 1, 0]), efault);
        iovecs(
            &f,
            REMOTE,
            &[(DATA + 0x800, 4), (DATA + 0x3000, 4), (DATA + 0x800, 4)],
        );
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 3, 0]), 4);
        // The local buffers stop at a page that cannot take the bytes.
        iovecs(&f, LOCAL, &[(DATA + 0x1ffc, 8)]);
        iovecs(&f, REMOTE, &[(DATA + 0x800, 8)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 1, 0]), 4);
        iovecs(&f, LOCAL, &[(DATA + 0x2000, 8)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 1, 0]), efault);
        // Only as much as the local buffers hold, whatever lies beyond.
        iovecs(&f, LOCAL, &[(DATA + 0xa00, 4)]);
        iovecs(&f, REMOTE, &[(DATA + 0x2ffc, 4), (DATA + 0x3000, 4)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 2, 0]), 4);
        // A write-only page cannot be read from, but can be written.
        iovecs(&f, LOCAL, &[(DATA + 0xa00, 4)]);
        iovecs(&f, REMOTE, &[(ONLY_WRITE, 4)]);
        assert_eq!(f.ret(310, &[pid, LOCAL, 1, REMOTE, 1, 0]), efault);
        assert_eq!(f.ret(311, &[pid, LOCAL, 1, REMOTE, 1, 0]), 4);
        // A write needs the remote page writable; the local one need only
        // be readable, and one that is not ends the copy.
        iovecs(&f, LOCAL, &[(DATA + 0x2000, 4)]);
        iovecs(&f, REMOTE, &[(DATA + 0x2000, 4)]);
        assert_eq!(f.ret(311, &[pid, LOCAL, 1, REMOTE, 1, 0]), efault);
        iovecs(&f, REMOTE, &[(DATA + 0xc00, 4)]);
        assert_eq!(f.ret(311, &[pid, LOCAL, 1, REMOTE, 1, 0]), 4);
        f.mem.write(GuestAddr(DATA + 0xa00), b"hell").unwrap();
        iovecs(&f, LOCAL, &[(DATA + 0xa00, 4), (DATA + 0x5000, 4)]);
        iovecs(&f, REMOTE, &[(DATA + 0xc00, 8)]);
        assert_eq!(f.ret(311, &[pid, LOCAL, 2, REMOTE, 1, 0]), 4);
        f.mem.read(GuestAddr(DATA + 0xc00), &mut out[..4]).unwrap();
        assert_eq!(&out[..4], b"hell");
    }
    #[test]
    fn pr_set_ptracer_takes_a_task_or_any() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        let pid = f.ret(39, &[]);
        const PR_SET_PTRACER: u64 = 0x5961_6d61;
        // 0 clears it, -1 (as an int too) lets any process in, and the
        // other arguments are not read.
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, 0, 9, 9, 9]), 0);
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, u64::MAX, 0, 0, 0]), 0);
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, 0xffff_ffff, 0, 0, 0]), 0);
        // A task, by an int: none with this number, 0 or a negative one.
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, pid, 0, 0, 0]), 0);
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, pid | 1 << 32, 0, 0, 0]), 0);
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, 0x3fff_fff0, 0, 0, 0]), einval);
        assert_eq!(f.ret(157, &[PR_SET_PTRACER, 1 << 32, 0, 0, 0]), einval);
        assert_eq!(
            f.ret(157, &[PR_SET_PTRACER, (-5i64) as u64, 0, 0, 0]),
            einval
        );
    }
    #[test]
    fn pidfd_getfd_copies_a_descriptor() {
        let mut f = fixture();
        let (einval, ebadf) = (errno(Errno::EINVAL), errno(Errno::EBADF));
        let pid = f.ret(39, &[]);
        let pidfd = f.ret(434, &[pid, 0]);
        let event = f.ret(290, &[0, 0]);
        assert_eq!(f.ret(438, &[pidfd, event, 1]), einval);
        assert_eq!(f.ret(438, &[99, event, 0]), ebadf);
        assert_eq!(f.ret(438, &[event, event, 0]), ebadf);
        assert_eq!(f.ret(438, &[pidfd, 99, 0]), ebadf);
        assert_eq!(f.ret(438, &[pidfd, u64::MAX, 0]), ebadf);
        let copy = f.ret(438, &[pidfd, event | 1 << 32, 0]);
        assert!(copy > event, "{copy}");
        // Close-on-exec, and the same open file description: a count
        // written through one reads through the other.
        assert_eq!(f.ret(72, &[copy, 1]), 1);
        f.mem.write_u64(GuestAddr(DATA), 5).unwrap();
        assert_eq!(f.ret(1, &[event, DATA, 8]), 8);
        assert_eq!(f.ret(0, &[copy, DATA + 8, 8]), 8);
        assert_eq!(f.mem.read_u64(GuestAddr(DATA + 8)).unwrap(), 5);
    }
}
/// Writes `program` (code, jt, jf, k) at `DATA + 0x100` and its
/// `sock_fprog` at `DATA`.
fn seccomp_program(f: &Fixture, program: &[(u16, u8, u8, u32)]) {
    for (i, &(code, jt, jf, k)) in program.iter().enumerate() {
        let mut insn = [0u8; 8];
        insn[0..2].copy_from_slice(&code.to_le_bytes());
        insn[2] = jt;
        insn[3] = jf;
        insn[4..8].copy_from_slice(&k.to_le_bytes());
        f.mem
            .write(GuestAddr(DATA + 0x100 + i as u64 * 8), &insn)
            .unwrap();
    }
    f.mem
        .write_u64(GuestAddr(DATA), program.len() as u64)
        .unwrap();
    f.mem.write_u64(GuestAddr(DATA + 8), DATA + 0x100).unwrap();
}
#[test]
fn seccomp_filters_refuse_calls_by_their_action() {
    let mut f = fixture();
    // getpid is ERRNO(EACCES), gettid TRAP, the rest allowed.
    seccomp_program(
        &f,
        &[
            (0x20, 0, 0, 0),
            (0x15, 0, 1, 39),
            (0x06, 0, 0, 0x0005_000d),
            (0x15, 0, 1, 186),
            (0x06, 0, 0, 0x0003_0005),
            (0x06, 0, 0, 0x7fff_0000),
        ],
    );
    // Without no_new_privs, only CAP_SYS_ADMIN may install one.
    let root = f.thread.state.credentials.clone();
    f.thread.state.credentials = root.setresuid(1000, 1000, 1000).unwrap();
    assert_eq!(f.ret(317, &[1, 0, DATA]), errno(Errno::EACCES));
    f.thread.state.credentials = root;
    assert_eq!(f.ret(317, &[1, 128, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(317, &[1, 8 | 1, DATA]), errno(Errno::EINVAL));
    // SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV and, in Linux master,
    // SECCOMP_FILTER_FLAG_RESTART_BEFORE_RECV need a listener.
    assert_eq!(f.ret(317, &[1, 32, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(317, &[1, 64, DATA]), errno(Errno::EINVAL));
    // With one, they are known flags: the filter is checked first.
    assert_eq!(f.ret(317, &[1, 64 | 8, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(317, &[0, 0, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(317, &[4, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(317, &[1, 0, 1]), errno(Errno::EFAULT));
    // SECCOMP_GET_ACTION_AVAIL and SECCOMP_GET_NOTIF_SIZES.
    f.mem
        .write(GuestAddr(DATA + 0x400), &0x7fc0_0000u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(317, &[2, 0, DATA + 0x400]), 0);
    f.mem
        .write(GuestAddr(DATA + 0x400), &0x0001_0000u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(317, &[2, 0, DATA + 0x400]), errno(Errno::EOPNOTSUPP));
    assert_eq!(f.ret(317, &[3, 0, DATA + 0x400]), 0);
    let mut sizes = [0u8; 6];
    f.mem.read(GuestAddr(DATA + 0x400), &mut sizes).unwrap();
    assert_eq!(sizes, [80, 0, 24, 0, 64, 0]);
    assert_eq!(f.ret(157, &[21]), 0); // PR_GET_SECCOMP
    assert_eq!(f.ret(317, &[1, 0, DATA]), 0);
    assert_eq!(f.ret(157, &[21]), 2);
    // Strict mode is not for a thread with filters.
    assert_eq!(f.ret(157, &[22, 1]), errno(Errno::EINVAL));
    assert_eq!(f.ret(39, &[]), errno(Errno::EACCES));
    // A second filter through prctl; the lowest action wins.
    seccomp_program(&f, &[(0x06, 0, 0, 0x7ffc_0000)]);
    assert_eq!(f.ret(157, &[22, 2, DATA]), 0);
    assert_eq!(f.ret(39, &[]), errno(Errno::EACCES));
    let state = f.kernel.group.seccomp_of_state(1, &f.thread.state.seccomp);
    assert_eq!((state.mode, state.filters()), (2, 2));
    // gettid: SIGSYS, which ends the process as nothing handles it.
    assert_eq!(f.call(186, &[]), Next::Exit(ExitStatus::Signaled(31)));
}
#[test]
fn seccomp_listener_answers_a_waiting_call() {
    let mut f = fixture();
    // getpid goes to the listener, the rest is allowed.
    seccomp_program(
        &f,
        &[
            (0x20, 0, 0, 0),
            (0x15, 0, 1, 39),
            (0x06, 0, 0, 0x7fc0_0000),
            (0x06, 0, 0, 0x7fff_0000),
        ],
    );
    let fd = f.ret(317, &[1, 8, DATA]);
    assert!((3..1024).contains(&fd), "{fd}");
    // Close-on-exec, and one listener to a list of filters.
    assert_eq!(f.ret(72, &[fd, 1]), 1);
    assert_eq!(f.ret(317, &[1, 8, DATA]), errno(Errno(16)));
    let file = f.kernel.files.descriptor(fd).unwrap().file;
    let helper = std::thread::spawn(move || {
        for _ in 0..10_000 {
            if crate::seccomp::answer_oldest(&file, 77) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        false
    });
    assert_eq!(f.ret(39, &[]), 77);
    assert!(helper.join().unwrap());
    // A receive into a buffer that is not zeroed, and a request the
    // listener does not know, are EINVAL.
    f.mem.write(GuestAddr(DATA + 0x400), &[1u8; 80]).unwrap();
    assert_eq!(
        f.ret(16, &[fd, 0xc050_2100, DATA + 0x400]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(16, &[fd, 0x4008_2109, DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(0, &[fd, DATA, 8]), errno(Errno::EINVAL));
    // An ADDFD argument longer than 24 bytes whose tail runs past the top
    // of the address space is EFAULT.
    assert_eq!(
        f.ret(16, &[fd, 0x4020_2103, u64::MAX - 8]),
        errno(Errno::EFAULT)
    );
    // Once the listener is closed, the filter has none: ENOSYS.
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(39, &[]), errno(Errno::ENOSYS));
}
#[test]
fn seccomp_strict_mode_allows_four_calls_and_kills_for_the_rest() {
    let mut f = fixture();
    assert_eq!(f.ret(317, &[0, 1, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(157, &[22, 1, 99]), 0);
    assert_eq!(f.ret(1, &[1, DATA, 0]), 0);
    assert_eq!(f.call(231, &[0]), Next::Exit(ExitStatus::Signaled(9)));
}

mod kernel_info {
    use super::*;
    const BUF: u64 = DATA + 0x100;
    const SIZE: u64 = DATA + 0x80;
    fn write_u32(f: &Fixture, at: u64, value: u32) {
        f.mem.write(GuestAddr(at), &value.to_le_bytes()).unwrap();
    }
    fn read_u32(f: &Fixture, at: u64) -> u32 {
        let mut bytes = [0; 4];
        f.mem.read(GuestAddr(at), &mut bytes).unwrap();
        u32::from_le_bytes(bytes)
    }
    #[test]
    fn syslog_reads_an_empty_log_with_cap_syslog() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        assert_eq!(f.ret(103, &[10, 0, 0]), 1 << 18);
        assert_eq!(f.ret(103, &[9, 0, 0]), 0);
        assert_eq!(f.ret(103, &[3, BUF, 64]), 0);
        assert_eq!(f.ret(103, &[4, BUF, 64]), 0);
        assert_eq!(f.ret(103, &[3, BUF, 0]), 0);
        assert_eq!(f.ret(103, &[3, 0, 64]), einval);
        assert_eq!(f.ret(103, &[3, BUF, u64::MAX]), einval);
        assert_eq!(f.ret(103, &[2, 0, 64]), einval);
        // The user half's end, not whether the buffer is mapped.
        assert_eq!(f.ret(103, &[3, 0x7000_0000, 64]), 0);
        assert_eq!(
            f.ret(103, &[3, USER_ADDRESS_LIMIT - 8, 64]),
            errno(Errno::EFAULT)
        );
        assert_eq!(f.ret(103, &[8, 0, 0]), einval);
        assert_eq!(f.ret(103, &[8, 0, 9]), einval);
        assert_eq!(f.ret(103, &[8, 0, 8]), 0);
        for kind in [0, 1, 5, 6, 7] {
            assert_eq!(f.ret(103, &[kind, 0, 0]), 0);
        }
        assert_eq!(f.ret(103, &[11, 0, 0]), einval);
        assert_eq!(f.ret(103, &[u64::MAX, 0, 0]), einval);
        assert!(crate::signals::restarts_without_handler(
            103,
            &[2, 0, 0, 0, 0, 0]
        ));
        assert!(!crate::signals::restarts_without_handler(
            103,
            &[3, 0, 0, 0, 0, 0]
        ));
    }
    #[test]
    fn syslog_needs_cap_syslog_for_every_action() {
        let mut f = fixture();
        assert_eq!(f.ret(105, &[1000]), 0);
        for kind in [0, 2, 3, 10, 11] {
            assert_eq!(f.ret(103, &[kind, BUF, 64]), errno(Errno::EPERM));
        }
    }
    #[test]
    fn sysfs_numbers_the_file_system_types() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        let count = f.ret(139, &[3, 0, 0]);
        assert_eq!(count, 7);
        f.mem.write(GuestAddr(BUF), b"proc\0").unwrap();
        let proc = f.ret(139, &[1, BUF, 0]);
        assert_eq!(proc, 1);
        assert_eq!(f.ret(139, &[2, proc, BUF + 0x40]), 0);
        let mut name = [0; 5];
        f.mem.read(GuestAddr(BUF + 0x40), &mut name).unwrap();
        assert_eq!(&name, b"proc\0");
        assert_eq!(f.ret(139, &[2, count, BUF]), einval);
        assert_eq!(f.ret(139, &[2, 1 << 32, BUF]), 0);
        assert_eq!(f.ret(139, &[2, 0, 0]), errno(Errno::EFAULT));
        f.mem.write(GuestAddr(BUF), b"nosuchfs\0").unwrap();
        assert_eq!(f.ret(139, &[1, BUF, 0]), einval);
        assert_eq!(f.ret(139, &[1, 0, 0]), errno(Errno::EFAULT));
        // No NUL within PATH_MAX bytes.
        f.mem.write(GuestAddr(DATA), &[b'x'; 0x1000]).unwrap();
        assert_eq!(f.ret(139, &[1, DATA, 0]), einval);
        // A name that runs into the end of the mapping.
        f.mem.write(GuestAddr(DATA + 0x1ffe), b"xy").unwrap();
        assert_eq!(f.ret(139, &[1, DATA + 0x1ffe, 0]), errno(Errno::EFAULT));
        for option in [0, 4, u64::MAX] {
            assert_eq!(f.ret(139, &[option, 0, 0]), einval);
        }
    }
    #[test]
    fn lsm_list_modules_gives_lockdown_capability_landlock_and_yama() {
        let mut f = fixture();
        let e2big = errno(Errno(7));
        assert_eq!(f.ret(461, &[BUF, SIZE, 1]), errno(Errno::EINVAL));
        assert_eq!(f.ret(461, &[BUF, 0, 0]), errno(Errno::EFAULT));
        write_u32(&f, SIZE, 8);
        assert_eq!(f.ret(461, &[BUF, SIZE, 0]), e2big);
        assert_eq!(read_u32(&f, SIZE), 32);
        assert_eq!(f.ret(461, &[BUF, SIZE, 0]), 4);
        let ids: Vec<u64> = (0..4)
            .map(|i| f.mem.read_u64(GuestAddr(BUF + i * 8)).unwrap())
            .collect();
        assert_eq!(ids, [108, 100, 110, 105]);
        assert_eq!(f.ret(461, &[0, SIZE, 0]), errno(Errno::EFAULT));
    }
    #[test]
    fn lsm_self_attributes_have_no_module() {
        let mut f = fixture();
        let (einval, eopnotsupp) = (errno(Errno::EINVAL), errno(Errno::EOPNOTSUPP));
        // lsm_get_self_attr(attr, ctx, size, flags)
        write_u32(&f, SIZE, 64);
        assert_eq!(f.ret(459, &[0, BUF, SIZE, 0]), einval);
        assert_eq!(f.ret(459, &[100, BUF, 0, 0]), einval);
        assert_eq!(f.ret(459, &[100, BUF, 8, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(459, &[100, BUF, SIZE, 2]), einval);
        assert_eq!(f.ret(459, &[100, 0, SIZE, 1]), einval);
        f.mem.write_u64(GuestAddr(BUF), 0).unwrap();
        assert_eq!(f.ret(459, &[100, BUF, SIZE, 1]), einval);
        f.mem.write_u64(GuestAddr(BUF), 104).unwrap();
        assert_eq!(f.ret(459, &[100, BUF, SIZE, 1]), eopnotsupp);
        assert_eq!(read_u32(&f, SIZE), 0);
        write_u32(&f, SIZE, 64);
        assert_eq!(f.ret(459, &[999, 0, SIZE, 0]), eopnotsupp);
        assert_eq!(read_u32(&f, SIZE), 0);
        // lsm_set_self_attr(attr, ctx, size, flags)
        let header = |f: &Fixture, id: u64, len: u64, ctx_len: u64| {
            for (i, word) in [id, 0, len, ctx_len].into_iter().enumerate() {
                f.mem
                    .write_u64(GuestAddr(BUF + i as u64 * 8), word)
                    .unwrap();
            }
        };
        header(&f, 100, 40, 8);
        assert_eq!(f.ret(460, &[100, BUF, 40, 1]), einval);
        assert_eq!(f.ret(460, &[100, BUF, 31, 0]), einval);
        assert_eq!(f.ret(460, &[100, BUF, 4097, 0]), errno(Errno(7)));
        assert_eq!(f.ret(460, &[100, 0, 40, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(460, &[100, BUF, 40, 0]), eopnotsupp);
        assert_eq!(f.ret(460, &[100, BUF, 39, 0]), einval);
        header(&f, 100, 40, 9);
        assert_eq!(f.ret(460, &[100, BUF, 40, 0]), einval);
        header(&f, 100, 40, u64::MAX);
        assert_eq!(f.ret(460, &[100, BUF, 40, 0]), einval);
    }
    #[test]
    fn probes_have_no_trampoline() {
        let mut f = fixture();
        f.thread.state.signal_mask = 1 << 3;
        assert_eq!(f.ret(336, &[]), errno(Errno(71)));
        assert!(f.thread.state.pending.is_empty());
        assert_eq!(f.call(335, &[]), Next::Exit(ExitStatus::Signaled(4)));
    }
}

mod admin {
    use super::*;
    const NAME: u64 = DATA + 0x100;
    const BUF: u64 = DATA + 0x400;
    fn put(f: &Fixture, at: u64, bytes: &[u8]) -> u64 {
        f.mem.write(GuestAddr(at), bytes).unwrap();
        f.mem
            .write(GuestAddr(at + bytes.len() as u64), &[0])
            .unwrap();
        at
    }
    /// A file `/tmp/<name>` holding `bytes`, and its path at `NAME`.
    fn file(f: &mut Fixture, name: &[u8], bytes: &[u8]) -> u64 {
        let mut path = b"/tmp/".to_vec();
        path.extend_from_slice(name);
        let at = put(f, NAME, &path);
        let fd = f.ret(2, &[at, 0o102, 0o600]);
        f.mem.write(GuestAddr(BUF), bytes).unwrap();
        assert_eq!(f.ret(1, &[fd, BUF, bytes.len() as u64]), bytes.len() as u64);
        assert_eq!(f.ret(3, &[fd]), 0);
        at
    }
    const MAGIC: [u64; 2] = [0xfee1_dead, 672_274_793];
    #[test]
    fn reboot_checks_the_capability_magic_and_command() {
        let mut f = fixture();
        let (einval, eperm) = (errno(Errno::EINVAL), errno(Errno::EPERM));
        assert_eq!(f.ret(169, &[0, 0, 0x89AB_CDEF, 0]), einval);
        assert_eq!(f.ret(169, &[MAGIC[0], 1, 0x89AB_CDEF, 0]), einval);
        for magic2 in [672_274_793, 85_072_278, 369_367_448, 537_993_216] {
            assert_eq!(f.ret(169, &[MAGIC[0], magic2, 0x89AB_CDEF, 0]), 0);
        }
        // The magic numbers are `int`s: only the low 32 bits count.
        assert_eq!(f.ret(169, &[MAGIC[0] | 1 << 32, MAGIC[1], 0, 0]), 0);
        assert_eq!(f.ret(169, &[MAGIC[0], MAGIC[1], 0x4558_4543, 0]), einval);
        assert_eq!(f.ret(169, &[MAGIC[0], MAGIC[1], 0xD000_FCE2, 0]), eperm);
        assert_eq!(f.ret(169, &[MAGIC[0], MAGIC[1], 7, 0]), einval);
        assert_eq!(
            f.ret(169, &[MAGIC[0], MAGIC[1], 0xA1B2_C3D4, 0]),
            errno(Errno::EFAULT)
        );
        assert_eq!(f.ret(105, &[1000]), 0);
        assert_eq!(f.ret(169, &[0, 0, 0, 0]), eperm);
    }
    #[test]
    fn reboot_halts_the_first_namespace() {
        let mut f = fixture();
        assert_eq!(
            f.call(169, &[MAGIC[0], MAGIC[1], 0xCDEF_0123, 0]),
            Next::Exit(ExitStatus::Exited(0))
        );
        assert_eq!(f.kernel.pid_space(1).reboot(), Some(2));
    }
    #[test]
    fn swap_needs_cap_sys_admin_and_opens_the_file() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        let swap = file(&mut f, b"swap", &[0; 16]);
        assert_eq!(f.ret(167, &[swap, 1 << 19]), einval);
        assert_eq!(f.ret(167, &[swap, 0x7_ffff]), einval);
        assert_eq!(f.ret(168, &[swap]), einval);
        let missing = put(&f, NAME, b"/tmp/missing");
        assert_eq!(f.ret(167, &[missing, 0]), errno(Errno::ENOENT));
        assert_eq!(f.ret(168, &[missing]), errno(Errno::ENOENT));
        let tmp = put(&f, NAME, b"/tmp");
        assert_eq!(f.ret(167, &[tmp, 0]), errno(Errno::EISDIR));
        assert_eq!(f.ret(167, &[0, 0]), errno(Errno::EFAULT));
        // No descriptor is left open.
        assert_eq!(f.ret(32, &[3]), errno(Errno::EBADF));
        assert_eq!(f.ret(105, &[1000]), 0);
        assert_eq!(f.ret(167, &[tmp, 1 << 19]), einval);
        assert_eq!(f.ret(167, &[tmp, 0]), errno(Errno::EPERM));
        assert_eq!(f.ret(168, &[tmp]), errno(Errno::EPERM));
    }
    #[test]
    fn modules_are_refused_unsigned_and_none_is_loaded() {
        let mut f = fixture();
        let eperm = errno(Errno::EPERM);
        f.mem.write(GuestAddr(BUF), &[0x7f; 64]).unwrap();
        assert_eq!(f.ret(175, &[BUF, 63, 0]), errno(Errno(8)));
        assert_eq!(f.ret(175, &[BUF, 64, 0]), eperm);
        assert_eq!(f.ret(175, &[0x4000_0000, 64, 0]), errno(Errno::EFAULT));
        // A length past what is mapped is EFAULT, and nothing of that size
        // is allocated (the fuzzer's out-of-memory case).
        assert_eq!(f.ret(175, &[BUF, 0xff00_0000, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(175, &[BUF, 1 << 32, 0]), errno(Errno::EFAULT));
        // A signature whose description Linux refuses.
        let mut module = vec![0u8; 64];
        let signed = |module: &mut Vec<u8>, info: [u8; 12]| {
            let mut m = module.clone();
            m.extend_from_slice(&info);
            m.extend_from_slice(b"~Module signature appended~\n");
            m
        };
        let cases: [([u8; 12], Errno); 4] = [
            ([0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8], Errno::EPERM),
            ([0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 8], Errno(65)),
            ([1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8], Errno(74)),
            ([0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 64], Errno(74)),
        ];
        for (info, expected) in cases {
            let image = signed(&mut module, info);
            f.mem.write(GuestAddr(BUF), &image).unwrap();
            assert_eq!(f.ret(175, &[BUF, image.len() as u64, 0]), errno(expected));
        }
        module.clear();
        // finit_module(fd, params, flags)
        let path = file(&mut f, b"module", &[0x7f; 64]);
        let fd = f.ret(2, &[path, 0]);
        assert_eq!(f.ret(313, &[fd, 0, 8]), errno(Errno::EINVAL));
        assert_eq!(f.ret(313, &[fd, 0, 0]), eperm);
        assert_eq!(f.ret(313, &[fd, 0, 4]), errno(Errno::EINVAL));
        assert_eq!(f.ret(313, &[99, 0, 0]), errno(Errno::EBADF));
        let tmp = put(&f, NAME, b"/tmp");
        let dir = f.ret(2, &[tmp, 0o200000]);
        assert_eq!(f.ret(313, &[dir, 0, 0]), errno(Errno::EINVAL));
        // delete_module(name, flags)
        let name = put(&f, NAME, b"ext4");
        assert_eq!(f.ret(176, &[name, 0]), errno(Errno::ENOENT));
        assert_eq!(f.ret(176, &[0, 0]), errno(Errno::EFAULT));
        assert_eq!(f.ret(105, &[1000]), 0);
        assert_eq!(f.ret(175, &[BUF, 1, 0]), eperm);
        assert_eq!(f.ret(313, &[99, 0, 8]), eperm);
        assert_eq!(f.ret(176, &[0, 0]), eperm);
    }
    #[test]
    fn kexec_is_locked_down() {
        let mut f = fixture();
        let eperm = errno(Errno::EPERM);
        assert_eq!(f.ret(246, &[0, 0, 0, 0]), eperm);
        assert_eq!(f.ret(320, &[0, 0, 0, 0, 1 << 6]), errno(Errno::EINVAL));
        assert_eq!(f.ret(320, &[99, 99, 0, 0, 1]), 0);
        assert_eq!(f.ret(320, &[99, 0, 0, 0, 4]), errno(Errno::EBADF));
        let path = file(&mut f, b"vmlinuz", &[0; 2048]);
        let fd = f.ret(2, &[path, 0]);
        assert_eq!(f.ret(320, &[fd, 0, 0, 0, 4]), errno(Errno(8)));
        let mut kernel = vec![0u8; 2048];
        kernel[0x1fe..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x206..0x208].copy_from_slice(&0x020Fu16.to_le_bytes());
        kernel[0x211] = 1;
        kernel[0x236] = 3;
        let path = file(&mut f, b"bzimage", &kernel);
        let fd = f.ret(2, &[path, 0]);
        assert_eq!(f.ret(320, &[fd, 0, 0, 0, 4]), eperm);
        assert_eq!(f.ret(105, &[1000]), 0);
        assert_eq!(f.ret(320, &[fd, 0, 0, 0, 1 << 6]), eperm);
    }
    #[test]
    fn quotas_are_on_no_device_or_file_system() {
        let mut f = fixture();
        let einval = errno(Errno::EINVAL);
        // QCMD(Q_SYNC, USRQUOTA), QCMD(Q_GETINFO, GRPQUOTA).
        let (sync, info) = (0x8000_0100u64, 0x8000_0501u64);
        assert_eq!(f.ret(179, &[sync, 0, 0, 0]), 0);
        assert_eq!(f.ret(179, &[sync | 3, 0, 0, 0]), einval);
        assert_eq!(f.ret(179, &[info, 0, 0, 0]), errno(Errno::ENODEV));
        let tmp = put(&f, NAME, b"/tmp");
        assert_eq!(f.ret(179, &[info, tmp, 0, 0]), errno(Errno(15)));
        let missing = put(&f, NAME, b"/tmp/missing");
        assert_eq!(f.ret(179, &[info, missing, 0, 0]), errno(Errno::ENOENT));
        assert_eq!(f.ret(179, &[info, 0x4000_0000, 0, 0]), errno(Errno::EFAULT));
        // quotactl_fd(fd, cmd, id, addr)
        let tmp = put(&f, NAME, b"/tmp");
        let dir = f.ret(2, &[tmp, 0o10_000_000]);
        assert_eq!(f.ret(443, &[dir, info, 0, 0]), errno(Errno::ENOSYS));
        assert_eq!(f.ret(443, &[dir, info | 3, 0, 0]), einval);
        assert_eq!(f.ret(443, &[99, info, 0, 0]), errno(Errno::EBADF));
    }
}
/// Writes `text` and a 0 at `DATA + at`, for a call's string argument.
fn put(f: &mut Fixture, at: u64, text: &[u8]) -> u64 {
    let mut bytes = text.to_vec();
    bytes.push(0);
    f.mem.write(GuestAddr(DATA + at), &bytes).unwrap();
    DATA + at
}
/// The whole of the file at `path`, read through a descriptor.
fn whole(f: &mut Fixture, path: &[u8]) -> Vec<u8> {
    let p = put(f, 0x1800, path);
    let fd = f.ret(2, &[p, 0, 0]);
    let mut out = Vec::new();
    loop {
        let n = f.ret(0, &[fd, DATA + 0x1000, 0x400]);
        if n == 0 || n as i64 <= 0 {
            break;
        }
        let mut chunk = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut chunk).unwrap();
        out.extend(chunk);
    }
    f.ret(3, &[fd]);
    out
}
/// mount(2)'s checks come in Linux's order: the strings and options are
/// copied, the target looked up, then the flags, the capability and the
/// type and options of a new mount.
#[test]
fn mount_checks_in_linux_order() {
    let mut f = fixture();
    let (none, tmpfs, dir) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"), 0x40);
    let target = put(&mut f, dir, b"/tmp/m");
    assert_eq!(f.ret(83, &[target, 0o755]), 0);
    let missing = put(&mut f, 0x80, b"/tmp/none");
    let file = put(&mut f, 0xc0, b"/tmp/file");
    f.ret(2, &[file, 0o101, 0o644]);
    let mount = |f: &mut Fixture, a: [u64; 5]| f.ret(165, &a);
    // The type, the source, then the options, before the target.
    assert_eq!(
        mount(&mut f, [none, missing, 8, 0, 0]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        mount(&mut f, [8, missing, tmpfs, 0, 0]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        mount(&mut f, [none, missing, tmpfs, 0, 8]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        mount(&mut f, [none, missing, tmpfs, 0, 0]),
        errno(Errno::ENOENT)
    );
    assert_eq!(mount(&mut f, [none, 0, tmpfs, 0, 0]), errno(Errno::EFAULT));
    // A string ends within PATH_MAX bytes, its 0 included (strndup_user).
    let long = put(&mut f, 0x800, &[b'a'; 4095]);
    assert_eq!(
        mount(&mut f, [none, missing, long, 0, 0]),
        errno(Errno::ENOENT)
    );
    let long = put(&mut f, 0x800, &[b'a'; 4096]);
    assert_eq!(
        mount(&mut f, [none, missing, long, 0, 0]),
        errno(Errno::EINVAL)
    );
    // The magic number goes; MS_NOUSER is EINVAL.
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 1 << 31, 0]),
        errno(Errno::EINVAL)
    );
    // A new mount: a type, a known one, its options.
    assert_eq!(mount(&mut f, [none, target, 0, 0, 0]), errno(Errno::EINVAL));
    let ext4 = put(&mut f, 0x100, b"ext4");
    assert_eq!(mount(&mut f, [none, target, ext4, 0, 0]), errno(Errno(19)));
    for bad in [
        &b"bogus"[..],
        b"size",
        b"size=",
        b"size=1q",
        b"mode=8",
        b"inode64=1",
        b"casefold",
        b"uid=-1",
    ] {
        let data = put(&mut f, 0x140, bad);
        assert_eq!(
            mount(&mut f, [none, target, tmpfs, 0, data]),
            errno(Errno::EINVAL),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        mount(&mut f, [none, file, tmpfs, 0, 0]),
        errno(Errno::ENOTDIR)
    );
    // A bind mount looks its source up (`none` is not there).
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 4096, 0]),
        errno(Errno::ENOENT)
    );
    // A move needs a source, which it looks up, and the source's root.
    assert_eq!(
        mount(&mut f, [0, target, tmpfs, 8192, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 8192, 0]),
        errno(Errno::ENOENT)
    );
    assert_eq!(
        mount(&mut f, [target, target, tmpfs, 8192, 0]),
        errno(Errno::EINVAL)
    );
    // What is not supported yet, after the checks before it:
    // MS_NOSYMFOLLOW.
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 256, 0]),
        errno(Errno::EOPNOTSUPP)
    );
    // A remount is of a mount's root.
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 32, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 32 | 4096, 0]),
        errno(Errno::EINVAL)
    );
    // Propagation: of a mount's root, one type, which every mount has.
    let root = put(&mut f, 0x180, b"/");
    assert_eq!(mount(&mut f, [0, root, 0, 1 << 14 | 1 << 18, 0]), 0);
    assert_eq!(mount(&mut f, [0, root, 0, 1 << 19, 0]), 0);
    assert_eq!(
        mount(&mut f, [0, target, 0, 1 << 18, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        mount(&mut f, [0, root, 0, 1 << 18 | 1 << 19, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        mount(&mut f, [0, root, 0, 1 << 18 | 1, 0]),
        errno(Errno::EINVAL)
    );
    // Without CAP_SYS_ADMIN: EPERM, after the lookup.
    f.thread.state.credentials.effective = 0;
    assert_eq!(
        mount(&mut f, [none, missing, tmpfs, 0, 0]),
        errno(Errno::ENOENT)
    );
    assert_eq!(
        mount(&mut f, [none, target, tmpfs, 0, 0]),
        errno(Errno::EPERM)
    );
    assert_eq!(f.ret(166, &[target, 0]), errno(Errno::EPERM));
}
/// A tmpfs mount: its own device, size and mode, a line in mountinfo, and
/// `umount2` in Linux's order.
#[test]
fn a_tmpfs_mount_and_its_umount() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (tmp, target) = (put(&mut f, 0x20, b"/tmp"), put(&mut f, 0x40, b"/tmp/m"));
    assert_eq!(f.ret(83, &[target, 0o755]), 0);
    let stat = DATA + 0x400;
    assert_eq!(f.ret(4, &[tmp, stat]), 0);
    let outer = f.mem.read_u64(GuestAddr(stat)).unwrap();
    let data = put(&mut f, 0x80, b"size=1m,mode=0750,nr_inodes=100");
    assert_eq!(f.ret(165, &[none, target, tmpfs, 2 | 8, data]), 0);
    assert_eq!(f.ret(4, &[target, stat]), 0);
    let device = f.mem.read_u64(GuestAddr(stat)).unwrap();
    assert_ne!(device, outer);
    assert_eq!(f.mem.read_u64(GuestAddr(stat + 8)).unwrap(), 1);
    assert_eq!(
        f.mem.read_u64(GuestAddr(stat + 24)).unwrap() as u32,
        0o040_750
    );
    assert_eq!(f.ret(137, &[target, stat]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(stat)).unwrap(), 0x0102_1994);
    assert_eq!(f.mem.read_u64(GuestAddr(stat + 16)).unwrap(), 256);
    assert_eq!(f.mem.read_u64(GuestAddr(stat + 40)).unwrap(), 100);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(&format!(
            " 21 0:{device} / /tmp/m rw,nosuid,noexec,relatime - tmpfs none rw,size=1024k,nr_inodes=100,mode=750,inode64\n"
        )),
        "{info}"
    );
    let mounts = String::from_utf8(whole(&mut f, b"/proc/self/mounts")).unwrap();
    assert!(mounts.ends_with("none /tmp/m tmpfs rw,nosuid,noexec,relatime,size=1024k,nr_inodes=100,mode=750,inode64 0 0\n"), "{mounts}");
    // A file in it, and what umount2 checks first.
    let inside = put(&mut f, 0xc0, b"/tmp/m/f");
    let fd = f.ret(2, &[inside, 0o102, 0o600]);
    assert_eq!(f.ret(1, &[fd, none, 4]), 4);
    assert_eq!(f.ret(166, &[target, 0x10]), errno(Errno::EINVAL));
    let missing = put(&mut f, 0x100, b"/tmp/none");
    assert_eq!(f.ret(166, &[missing, 0]), errno(Errno::ENOENT));
    assert_eq!(f.ret(166, &[tmp, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(166, &[target, 4 | 2]), errno(Errno::EINVAL));
    // The caller's root stays, its superblock remounted read-only
    // (`do_umount_root`).
    let root = put(&mut f, 0x100, b"/");
    assert_eq!(f.ret(166, &[root, 0]), 0);
    let made = put(&mut f, 0x100, b"/tmp/made");
    assert_eq!(f.ret(83, &[made, 0o755]), errno(Errno(30)));
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.starts_with("21 1 0:1 / / rw,relatime - tmpfs tmpfs ro\n"),
        "{info}"
    );
    // In use by the open file: EBUSY; MNT_EXPIRE too.
    assert_eq!(f.ret(166, &[target, 0]), errno(Errno(16)));
    assert_eq!(f.ret(166, &[target, 4]), errno(Errno(16)));
    // Through a working directory in it, then gone.
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(80, &[target]), 0);
    assert_eq!(f.ret(166, &[target, 0]), errno(Errno(16)));
    assert_eq!(f.ret(80, &[tmp]), 0);
    let fd = f.ret(2, &[inside, 0, 0]);
    // Detached, the open file stays readable, and the directory is back.
    assert_eq!(f.ret(166, &[target, 2]), 0);
    assert_eq!(f.ret(0, &[fd, DATA + 0x600, 16]), 4);
    assert_eq!(f.ret(4, &[target, stat]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(stat)).unwrap(), outer);
    assert_eq!(f.ret(4, &[inside, stat]), errno(Errno::ENOENT));
    assert_eq!(f.ret(166, &[target, 0]), errno(Errno::EINVAL));
    // MNT_EXPIRE marks a mount in use by nothing, then unmounts it.
    assert_eq!(f.ret(165, &[none, target, tmpfs, 0, 0]), 0);
    assert_eq!(f.ret(166, &[target, 4]), errno(Errno::EAGAIN));
    assert_eq!(f.ret(166, &[target, 4]), 0);
}

/// A tmpfs mount's size and inodes hold its files: a write stops at the
/// size (`ENOSPC` once nothing fits), `fallocate` allocates all or none,
/// each new inode and name takes one of the inodes, a long symbolic link a
/// page, and a remount to a larger size lets writes go on.
#[test]
fn a_tmpfs_mount_holds_its_files_to_its_size_and_inodes() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let target = put(&mut f, 0x40, b"/tmp/m");
    assert_eq!(f.ret(83, &[target, 0o755]), 0);
    let data = put(&mut f, 0x80, b"size=8k,nr_inodes=4,huge=never");
    assert_eq!(f.ret(165, &[none, target, tmpfs, 0, data]), 0);
    let stat = DATA + 0x400;
    let statfs = |f: &mut Fixture| {
        assert_eq!(f.ret(137, &[target, stat]), 0);
        let at = |i: u64| f.mem.read_u64(GuestAddr(stat + 8 * i)).unwrap();
        (at(2), at(3), at(4), at(5), at(6))
    };
    assert_eq!(statfs(&mut f), (2, 2, 2, 4, 3));
    let (a, b) = (
        put(&mut f, 0xc0, b"/tmp/m/a"),
        put(&mut f, 0xe0, b"/tmp/m/b"),
    );
    let fd = f.ret(2, &[a, 0o102, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA, 4096]), 4096);
    // Of two more pages one fits: a short write, then ENOSPC.
    assert_eq!(f.ret(1, &[fd, DATA, 8192]), 4096);
    assert_eq!(f.ret(1, &[fd, DATA, 1]), errno(Errno(28)));
    assert_eq!(f.ret(5, &[fd, stat]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(stat + 48)).unwrap(), 8192);
    assert_eq!(statfs(&mut f), (2, 0, 0, 4, 2));
    // A page it has takes no more.
    assert_eq!(f.ret(18, &[fd, DATA, 4096, 0]), 4096);
    // fallocate: none of the range when it does not all fit.
    assert_eq!(f.ret(77, &[fd, 4096]), 0);
    assert_eq!(f.ret(285, &[fd, 0, 0, 12288]), errno(Errno(28)));
    assert_eq!(statfs(&mut f), (2, 1, 1, 4, 2));
    assert_eq!(f.ret(285, &[fd, 0, 4096, 4096]), 0);
    assert_eq!(statfs(&mut f).1, 0);
    // Inodes: a directory and a short link take the last two.
    let (d, s) = (
        put(&mut f, 0x100, b"/tmp/m/d"),
        put(&mut f, 0x120, b"/tmp/m/s"),
    );
    assert_eq!(f.ret(83, &[d, 0o755]), 0);
    assert_eq!(f.ret(88, &[a, s]), 0);
    assert_eq!(statfs(&mut f), (2, 0, 0, 4, 0));
    assert_eq!(f.ret(2, &[b, 0o102, 0o600]), errno(Errno(28)));
    assert_eq!(f.ret(83, &[b, 0o755]), errno(Errno(28)));
    assert_eq!(f.ret(86, &[a, b]), errno(Errno(28)));
    // An existing name is still EEXIST.
    assert_eq!(f.ret(83, &[d, 0o755]), errno(Errno::EEXIST));
    // A second name takes an inode, and gives it back.
    assert_eq!(f.ret(87, &[s]), 0);
    assert_eq!(f.ret(86, &[a, b]), 0);
    assert_eq!(statfs(&mut f).4, 0);
    // A rename between two names of one file does nothing.
    assert_eq!(f.ret(82, &[a, b]), 0);
    assert_eq!(statfs(&mut f).4, 0);
    assert_eq!(f.ret(87, &[b]), 0);
    assert_eq!(statfs(&mut f).4, 1);
    // A long symbolic link needs a page, which there is not.
    let long = put(&mut f, 0x200, &[b'x'; 200]);
    assert_eq!(f.ret(88, &[long, s]), errno(Errno(28)));
    assert_eq!(f.ret(6, &[s, stat]), errno(Errno::ENOENT));
    assert_eq!(statfs(&mut f), (2, 0, 0, 4, 1));
    // An unlinked file keeps its pages and inode while it is open.
    assert_eq!(f.ret(87, &[a]), 0);
    assert_eq!(statfs(&mut f), (2, 0, 0, 4, 1));
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(statfs(&mut f), (2, 2, 2, 4, 2));
    // A remount to more room: the long link fits, and a write goes on.
    let more = put(&mut f, 0x80, b"size=16k");
    assert_eq!(f.ret(165, &[none, target, 0, 32, more]), 0);
    assert_eq!(f.ret(88, &[long, s]), 0);
    assert_eq!(statfs(&mut f), (4, 3, 3, 4, 1));
    let fd = f.ret(2, &[a, 0o102, 0o600]);
    assert_eq!(f.ret(1, &[fd, DATA, 8192]), 8192);
    assert_eq!(statfs(&mut f), (4, 1, 1, 4, 0));
    // A remount below what the files use is EINVAL (`shmem_reconfigure`).
    let small = put(&mut f, 0x80, b"size=8k");
    assert_eq!(
        f.ret(165, &[none, target, 0, 32, small]),
        errno(Errno::EINVAL)
    );
    let few = put(&mut f, 0x80, b"nr_inodes=3");
    assert_eq!(
        f.ret(165, &[none, target, 0, 32, few]),
        errno(Errno::EINVAL)
    );
    assert_eq!(statfs(&mut f), (4, 1, 1, 4, 0));
}

/// The files the kernel generates are on `noexec` mounts, as Linux's
/// `/proc` and `/dev` are: an executable mapping of `/dev/zero` is `EPERM`
/// and `mprotect` to one `EACCES`, while a file reached through a link in
/// `/dev/fd` is on its own mount; the exec checks find them `noexec` too.
#[test]
fn the_kernels_own_files_are_on_noexec_mounts() {
    let mut f = fixture();
    let zero = put(&mut f, 0, b"/dev/zero");
    let fd = f.ret(2, &[zero, 2, 0]);
    // PROT_READ | PROT_EXEC, MAP_PRIVATE; then MAP_SHARED.
    assert_eq!(f.ret(9, &[0, 4096, 5, 2, fd, 0]), errno(Errno::EPERM));
    assert_eq!(f.ret(9, &[0, 4096, 5, 1, fd, 0]), errno(Errno::EPERM));
    let at = f.ret(9, &[0, 4096, 1, 2, fd, 0]);
    assert!(at < u64::MAX - 4095, "{at:#x}");
    assert_eq!(f.ret(10, &[at, 4096, 5]), errno(Errno::EACCES));
    assert_eq!(f.ret(10, &[at, 4096, 3]), 0);
    // A file in /tmp, through /dev/fd, maps executable.
    let file = put(&mut f, 0x40, b"/tmp/x");
    let made = f.ret(2, &[file, 0o102, 0o700]);
    assert_eq!(f.ret(1, &[made, DATA, 4096]), 4096);
    let link = put(&mut f, 0x80, format!("/dev/fd/{made}").as_bytes());
    let again = f.ret(2, &[link, 0, 0]);
    let mapped = f.ret(9, &[0, 4096, 5, 2, again, 0]);
    assert!(mapped < u64::MAX - 4095, "{mapped:#x}");
    // What the exec checks ask (`path_noexec`): no generated file is a
    // regular file with an execute bit, so only the mount can say it here.
    use crate::files::{ST_NODEV, ST_NOEXEC, ST_NOSUID, mount_says};
    for path in [
        &b"/proc/self/status"[..],
        b"/proc/1/stat",
        b"/dev/null",
        b"/dev/pts/ptmx",
    ] {
        assert!(mount_says(&f.kernel.files, path, ST_NOEXEC), "{path:?}");
        assert!(!mount_says(&f.kernel.files, path, ST_NOSUID), "{path:?}");
        assert!(!mount_says(&f.kernel.files, path, ST_NODEV), "{path:?}");
    }
    assert!(!mount_says(&f.kernel.files, b"/tmp/x", ST_NOEXEC));
}

/// `statfs`'s `f_flags` for the kernel's own mounts are those Linux mounts
/// them with; a link in `/proc/self/fd` gives its file's, and a pipe's
/// internal mount `ST_VALID` alone.
#[test]
fn the_kernels_own_mounts_give_their_statfs_flags() {
    let mut f = fixture();
    let out = DATA + 0x400;
    let flags = |f: &mut Fixture, path: &[u8]| {
        let p = put(f, 0, path);
        assert_eq!(
            f.ret(137, &[p, out]),
            0,
            "{}",
            String::from_utf8_lossy(path)
        );
        f.mem.read_u64(GuestAddr(out + 80)).unwrap()
    };
    assert_eq!(flags(&mut f, b"/proc"), 0x102e);
    assert_eq!(flags(&mut f, b"/proc/self/status"), 0x102e);
    assert_eq!(flags(&mut f, b"/dev/pts"), 0x102a);
    assert_eq!(flags(&mut f, b"/dev/mqueue"), 0x102e);
    assert_eq!(flags(&mut f, b"/dev/null"), 0x102a);
    assert_eq!(flags(&mut f, b"/dev"), 0x102a);
    let tmp = flags(&mut f, b"/tmp");
    assert_eq!(f.ret(22, &[DATA + 0x300]), 0);
    let read = f.mem.read_u64(GuestAddr(DATA + 0x300)).unwrap() as u32;
    assert_eq!(
        flags(&mut f, format!("/proc/self/fd/{read}").as_bytes()),
        0x20
    );
    let file = put(&mut f, 0x200, b"/tmp/f");
    let fd = f.ret(2, &[file, 0o102, 0o600]);
    assert_eq!(flags(&mut f, format!("/proc/self/fd/{fd}").as_bytes()), tmp);
    let status = put(&mut f, 0x200, b"/proc/self/status");
    let fd = f.ret(2, &[status, 0, 0]);
    assert_eq!(f.ret(138, &[fd, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 80)).unwrap(), 0x102e);
}

/// `/dev/shm` is a tmpfs from start-up, as systemd mounts it (`mode=01777`,
/// `nosuid`, `nodev`), on a device of its own: files are made, written and
/// removed there, `/dev` lists it, and mountinfo shows it on `/dev`.
#[test]
fn dev_shm_is_a_tmpfs_from_start_up() {
    const ENOENT: u64 = -2i64 as u64;
    let mut f = fixture();
    let out = DATA + 0x400;
    let shm = put(&mut f, 0, b"/dev/shm");
    let shm_path = put(&mut f, 0x180, b"/dev/shm");
    assert_eq!(f.ret(137, &[shm, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out)).unwrap(), 0x0102_1994);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 80)).unwrap(), 0x26);
    assert_eq!(f.ret(4, &[shm, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 24)).unwrap() as u32, 0o41777);
    let device = f.mem.read_u64(GuestAddr(out)).unwrap();
    let root = put(&mut f, 0x10, b"/tmp");
    assert_eq!(f.ret(4, &[root, out]), 0);
    assert_ne!(f.mem.read_u64(GuestAddr(out)).unwrap(), device);
    let file = put(&mut f, 0x20, b"/dev/shm/sem.x");
    let fd = f.ret(2, &[file, 0o102, 0o600]);
    assert!(fd < 1024, "{fd:#x}");
    let data = put(&mut f, 0x40, b"hi");
    assert_eq!(f.ret(1, &[fd, data, 2]), 2);
    assert_eq!(f.ret(4, &[file, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out)).unwrap(), device);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 48)).unwrap(), 2);
    // The same file through `..` and a link from elsewhere.
    let back = put(&mut f, 0x60, b"/dev/shm/../shm/sem.x");
    assert_eq!(f.ret(4, &[back, out]), 0);
    let (target, link) = (
        put(&mut f, 0x80, b"/dev/shm"),
        put(&mut f, 0xa0, b"/tmp/shm"),
    );
    assert_eq!(f.ret(88, &[target, link]), 0);
    let linked = put(&mut f, 0xc0, b"/tmp/shm/sem.x");
    assert_eq!(f.ret(4, &[linked, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out)).unwrap(), device);
    // Extended attributes through the link reach the file too.
    let (key, value) = (put(&mut f, 0x100, b"user.k"), put(&mut f, 0x120, b"v"));
    assert_eq!(f.ret(188, &[linked, key, value, 1, 0]), 0);
    assert_eq!(f.ret(191, &[file, key, out, 16]), 1);
    assert_eq!(f.ret(87, &[file]), 0);
    assert_eq!(f.ret(4, &[file, out]), ENOENT);
    // A link to `/dev` itself leads to the kernel's: a descriptor of it
    // reads the links there.
    let (to_dev, dev_link) = (put(&mut f, 0x1a0, b"/dev"), put(&mut f, 0x1c0, b"/tmp/d"));
    assert_eq!(f.ret(88, &[to_dev, dev_link]), 0);
    let dfd = f.ret(2, &[dev_link, 0o10_200_000, 0]);
    assert!(dfd < 1024, "{dfd:#x}");
    let fd_name = put(&mut f, 0x1e0, b"fd");
    assert_eq!(f.ret(267, &[dfd, fd_name, out, 64]), 13);
    // Another name in `/dev` is still not there.
    let other = put(&mut f, 0xe0, b"/dev/nothing/x");
    assert_eq!(f.ret(4, &[other, out]), ENOENT);
    let listed = String::from_utf8_lossy(&whole(&mut f, b"/proc/self/mountinfo")).into_owned();
    let line = |point: &str| {
        listed
            .lines()
            .find(|l| l.split(' ').nth(4) == Some(point))
            .unwrap_or_else(|| panic!("{point} in {listed}"))
            .to_owned()
    };
    let (dev, shm) = (line("/dev"), line("/dev/shm"));
    assert!(
        dev.contains(" rw,nosuid,noexec,relatime ") && dev.contains(" - devtmpfs "),
        "{dev}"
    );
    assert!(
        shm.contains(" rw,nosuid,nodev ") && shm.contains(" - tmpfs tmpfs rw"),
        "{shm}"
    );
    // `/dev/shm`'s parent is `/dev`.
    assert_eq!(shm.split(' ').nth(1), dev.split(' ').next());
    // Once unmounted, it is neither there nor listed.
    let listed = |f: &mut Fixture| {
        let dev = put(f, 0x140, b"/dev");
        let dir = f.ret(2, &[dev, 0o200000]);
        let n = f.ret(217, &[dir, DATA + 0x1000, 0x1000]);
        let mut b = vec![0; usize::try_from(n).unwrap()];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut b).unwrap();
        assert_eq!(f.ret(3, &[dir]), 0);
        b.windows(4).any(|w| w == b"shm\0")
    };
    assert!(listed(&mut f));
    // Busy while a file on it is open, as on Linux.
    assert_eq!(f.ret(166, &[shm_path, 0]), -16i64 as u64);
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(166, &[shm_path, 0]), 0);
    assert_eq!(f.ret(4, &[shm_path, out]), ENOENT);
    assert!(!listed(&mut f));
}

/// A read-only mount refuses what writes, in Linux's order; remounts and
/// propagation types show in mountinfo.
#[test]
fn read_only_mounts_remounts_and_propagation() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let target = put(&mut f, 0x40, b"/tmp/m");
    assert_eq!(f.ret(83, &[target, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, target, tmpfs, 0, 0]), 0);
    let file = put(&mut f, 0x80, b"/tmp/m/f");
    let fd = f.ret(2, &[file, 0o101, 0o644]);
    // Busy while the file is open for writing.
    let (remount, bind, rdonly) = (32, 4096, 1);
    assert_eq!(
        f.ret(165, &[0, target, 0, remount | bind | rdonly, 0]),
        errno(Errno(16))
    );
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(165, &[0, target, 0, remount | bind | rdonly, 0]), 0);
    let erofs = errno(Errno(30));
    let (missing, deep) = (
        put(&mut f, 0xc0, b"/tmp/m/g"),
        put(&mut f, 0x100, b"/tmp/m/x/y"),
    );
    assert_eq!(f.ret(83, &[missing, 0o755]), erofs);
    assert_eq!(f.ret(83, &[file, 0o755]), errno(Errno::EEXIST));
    assert_eq!(f.ret(83, &[deep, 0o755]), errno(Errno::ENOENT));
    assert_eq!(f.ret(2, &[missing, 0o101, 0o644]), erofs);
    assert_eq!(f.ret(2, &[file, 1, 0]), erofs);
    assert_eq!(f.ret(2, &[file, 0o1000, 0]), erofs);
    let fd = f.ret(2, &[file, 0, 0]);
    assert_eq!(f.ret(91, &[fd, 0o600]), erofs);
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(87, &[missing]), erofs);
    assert_eq!(f.ret(87, &[file]), erofs);
    assert_eq!(f.ret(90, &[file, 0o600]), erofs);
    assert_eq!(f.ret(90, &[missing, 0o600]), errno(Errno::ENOENT));
    assert_eq!(f.ret(76, &[file, 0]), erofs);
    assert_eq!(f.ret(21, &[file, 2]), erofs);
    assert_eq!(f.ret(21, &[file, 4]), 0);
    let dot = put(&mut f, 0x140, b"/tmp/m/.");
    assert_eq!(f.ret(84, &[dot]), errno(Errno::EINVAL));
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" /tmp/m ro,relatime - tmpfs none rw,"),
        "{info}"
    );
    // The superblock, with tmpfs's options, then writable again.
    let size = put(&mut f, 0x180, b"size=2m");
    assert_eq!(f.ret(165, &[0, target, 0, remount | rdonly, size]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" /tmp/m ro,relatime - tmpfs none ro,size=2048k,"),
        "{info}"
    );
    let dirsync = put(&mut f, 0x180, b"dirsync");
    assert_eq!(
        f.ret(165, &[0, target, 0, remount, dirsync]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(165, &[0, target, 0, remount, 0]), 0);
    assert_eq!(f.ret(83, &[missing, 0o755]), 0);
    // Propagation: a peer group, and a mount on a shared one.
    let (shared, private, rec) = (1 << 20, 1 << 18, 1 << 14);
    assert_eq!(f.ret(165, &[0, target, 0, shared, 0]), 0);
    assert_eq!(f.ret(165, &[none, missing, tmpfs, 0, 0]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" /tmp/m rw,relatime shared:1 - tmpfs"),
        "{info}"
    );
    assert!(
        info.contains(" /tmp/m/g rw,relatime shared:2 - tmpfs"),
        "{info}"
    );
    assert_eq!(f.ret(165, &[0, target, 0, private | rec, 0]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(!info.contains("shared:"), "{info}");
}

/// A moved mount takes the working directory in it along, and
/// `pivot_root` puts the old root under the new one, the working
/// directory at the new root with it.
#[test]
fn a_move_and_pivot_root_take_the_working_directory_along() {
    let mut f = fixture();
    let cwd = |f: &mut Fixture| -> Vec<u8> {
        let n = f.ret(79, &[DATA + 0x1000, 256]);
        let mut out = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut out).unwrap();
        out.pop();
        out
    };
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (m, n) = (put(&mut f, 0x40, b"/tmp/m"), put(&mut f, 0x60, b"/tmp/n"));
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    assert_eq!(f.ret(83, &[n, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
    let d = put(&mut f, 0x80, b"/tmp/m/d");
    assert_eq!(f.ret(83, &[d, 0o755]), 0);
    assert_eq!(f.ret(80, &[d]), 0);
    let r#move = 8192;
    assert_eq!(f.ret(165, &[m, n, 0, r#move, 0]), 0);
    assert_eq!(cwd(&mut f), b"/tmp/n/d");
    // Onto a file, and into itself.
    let file = put(&mut f, 0xc0, b"/tmp/file");
    assert!(f.ret(2, &[file, 0o101, 0o644]) as i64 >= 0);
    assert_eq!(f.ret(165, &[n, file, 0, r#move, 0]), errno(Errno::EINVAL));
    let inside = put(&mut f, 0x100, b"/tmp/n/d");
    assert_eq!(f.ret(165, &[n, inside, 0, r#move, 0]), errno(Errno(40)));
    // pivot_root: directories (the new root first), then the checks.
    let (dot, old, missing) = (
        put(&mut f, 0x140, b"."),
        put(&mut f, 0x150, b"old"),
        put(&mut f, 0x160, b"/missing"),
    );
    assert_eq!(f.ret(155, &[missing, file]), errno(Errno::ENOENT));
    assert_eq!(f.ret(155, &[file, missing]), errno(Errno::ENOTDIR));
    assert_eq!(f.ret(155, &[n, missing]), errno(Errno::ENOENT));
    assert_eq!(f.ret(155, &[inside, inside]), errno(Errno::EINVAL));
    let old_dir = put(&mut f, 0x180, b"/tmp/n/old");
    assert_eq!(f.ret(83, &[old_dir, 0o755]), 0);
    assert_eq!(f.ret(80, &[n]), 0);
    assert_eq!(f.ret(155, &[dot, old]), 0);
    assert_eq!(cwd(&mut f), b"/");
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(info.contains(" / / rw,relatime - tmpfs none "), "{info}");
    assert!(info.contains(" / /old rw,relatime - "), "{info}");
    let tmp = put(&mut f, 0x1a0, b"/old/tmp/file");
    assert_eq!(f.ret(21, &[tmp, 0]), 0);
    // The old root goes with what is on it.
    let gone = put(&mut f, 0x1c0, b"/old");
    assert_eq!(f.ret(166, &[gone, 2]), 0);
    assert_eq!(f.ret(21, &[tmp, 0]), errno(Errno::ENOENT));
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert_eq!(info.lines().count(), 1, "{info}");
    // `pivot_root(".", ".")` stacks the old root on the new, and an
    // unmount of `.` takes it off.
    let next = put(&mut f, 0x1e0, b"/next");
    assert_eq!(f.ret(83, &[next, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, next, tmpfs, 0, 0]), 0);
    assert_eq!(f.ret(80, &[next]), 0);
    assert_eq!(f.ret(155, &[dot, dot]), 0);
    assert_eq!(cwd(&mut f), b"/");
    assert_eq!(f.ret(166, &[dot, 2]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert_eq!(info.lines().count(), 1, "{info}");
    assert!(info.contains(" / / rw,relatime - tmpfs none "), "{info}");
}

/// A path from a directory's descriptor on a tmpfs mount starts at that
/// directory, by the path it was opened at, not its path in the tmpfs.
#[test]
fn a_path_from_a_directory_descriptor_on_a_mount() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let m = put(&mut f, 0x40, b"/tmp/m");
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
    let d = put(&mut f, 0x60, b"/tmp/m/d");
    assert_eq!(f.ret(83, &[d, 0o755]), 0);
    let fd = f.ret(2, &[m, 0o200000, 0]);
    let rel = put(&mut f, 0x80, b"d");
    assert!((f.ret(257, &[fd, rel, 0o200000, 0]) as i64) >= 0);
}

/// `fsopen`, `fsconfig` and `fsmount` make and mount a tmpfs, logging why a
/// parameter is refused; `fspick` reconfigures a mounted one.
#[test]
fn a_file_system_context_makes_and_reconfigures_a_tmpfs() {
    let mut f = fixture();
    let message = |f: &mut Fixture, fd: u64| -> Result<String, u64> {
        let n = f.ret(0, &[fd, DATA + 0x1000, 256]);
        if (n as i64) < 0 {
            return Err(n);
        }
        let mut out = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut out).unwrap();
        Ok(String::from_utf8(out).unwrap())
    };
    let (tmpfs, nope) = (put(&mut f, 0x10, b"tmpfs"), put(&mut f, 0x20, b"nope"));
    assert_eq!(f.ret(430, &[tmpfs, 2]), errno(Errno::EINVAL));
    assert_eq!(f.ret(430, &[nope, 0]), errno(Errno(19)));
    let fd = f.ret(430, &[tmpfs, 0]);
    assert!((fd as i64) >= 0);
    let (size, two_m, bogus, inode32, x, source) = (
        put(&mut f, 0x40, b"size"),
        put(&mut f, 0x50, b"1m"),
        put(&mut f, 0x60, b"bogus"),
        put(&mut f, 0x70, b"inode32"),
        put(&mut f, 0x80, b"x"),
        put(&mut f, 0x90, b"source"),
    );
    // The arguments first, then the descriptor.
    assert_eq!(f.ret(431, &[u64::MAX, 0, size, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 99, 0, 0, 0]), errno(Errno::EOPNOTSUPP));
    assert_eq!(f.ret(431, &[fd, 0, size, two_m, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[99, 0, size, 0, 0]), errno(Errno::EBADF));
    assert_eq!(f.ret(431, &[0, 0, size, 0, 0]), errno(Errno::EINVAL));
    // Each refused parameter logs a message.
    assert_eq!(f.ret(431, &[fd, 0, size, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 1, inode32, x, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 0, bogus, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 0, source, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 1, source, x, 0]), 0);
    assert_eq!(f.ret(431, &[fd, 1, source, x, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 1, size, two_m, 0]), 0);
    assert_eq!(
        message(&mut f, fd).unwrap(),
        "e tmpfs: Bad value for 'size'\n"
    );
    assert_eq!(
        message(&mut f, fd).unwrap(),
        "e tmpfs: Unexpected value for 'inode32'\n"
    );
    assert_eq!(
        message(&mut f, fd).unwrap(),
        "e tmpfs: Unknown parameter 'bogus'\n"
    );
    assert_eq!(message(&mut f, fd).unwrap(), "e Non-string source\n");
    assert_eq!(message(&mut f, fd).unwrap(), "e Multiple sources\n");
    assert_eq!(message(&mut f, fd), Err(errno(Errno(61))));
    // Nothing to mount before the superblock is made, nor twice.
    assert_eq!(f.ret(432, &[fd, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(431, &[fd, 7, 0, 0, 0]), errno(Errno(16)));
    assert_eq!(f.ret(431, &[fd, 6, 0, 0, 0]), 0);
    assert_eq!(f.ret(431, &[fd, 6, 0, 0, 0]), errno(Errno(16)));
    assert_eq!(f.ret(431, &[fd, 1, size, two_m, 0]), errno(Errno(16)));
    assert_eq!(f.ret(432, &[fd, 4, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(432, &[fd, 0, 0x40]), errno(Errno::EINVAL));
    let mounted = f.ret(432, &[fd, 0, 0x10]);
    assert!((mounted as i64) >= 0);
    assert_eq!(f.ret(432, &[fd, 0, 0]), errno(Errno(16)));
    let (m, nothing) = (put(&mut f, 0xa0, b"/tmp/m"), put(&mut f, 0xb0, b""));
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    let fdcwd = (-100i64) as u64;
    assert_eq!(f.ret(429, &[mounted, nothing, fdcwd, m, 4]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" / /tmp/m rw,noatime - tmpfs x rw,size=1024k"),
        "{info}"
    );
    // The context now reconfigures the mounted one.
    let four_m = put(&mut f, 0xc0, b"4m");
    assert_eq!(f.ret(431, &[fd, 1, size, four_m, 0]), 0);
    assert_eq!(f.ret(431, &[fd, 7, 0, 0, 0]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(info.contains(" - tmpfs x rw,size=4096k"), "{info}");
    // fspick of a mount's root.
    let tmp = put(&mut f, 0xd0, b"/tmp");
    assert_eq!(f.ret(433, &[fdcwd, tmp, 16]), errno(Errno::EINVAL));
    assert_eq!(f.ret(433, &[fdcwd, tmp, 0]), errno(Errno::EINVAL));
    let picked = f.ret(433, &[fdcwd, m, 0]);
    assert!((picked as i64) >= 0);
    let ro = put(&mut f, 0xe0, b"ro");
    assert_eq!(f.ret(431, &[picked, 0, ro, 0, 0]), 0);
    assert_eq!(f.ret(431, &[picked, 6, 0, 0, 0]), errno(Errno(16)));
    assert_eq!(f.ret(431, &[picked, 7, 0, 0, 0]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(info.contains(" - tmpfs x ro,size=4096k"), "{info}");
}

/// `mount_setattr` sets and clears a mount's flags and its propagation, and
/// `open_tree_attr` a new copy's.
#[test]
fn mount_setattr_changes_flags_and_propagation() {
    let mut f = fixture();
    let attr = |f: &mut Fixture, at: u64, words: [u64; 5]| -> u64 {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        f.mem.write(GuestAddr(DATA + at), &bytes).unwrap();
        DATA + at
    };
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (m, inner) = (
        put(&mut f, 0x40, b"/tmp/m"),
        put(&mut f, 0x60, b"/tmp/m/in"),
    );
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
    assert_eq!(f.ret(83, &[inner, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, inner, tmpfs, 0, 0]), 0);
    let fdcwd = (-100i64) as u64;
    let (ro, recursive) = (1, 0x8000);
    let set_ro = attr(&mut f, 0x200, [ro, 0, 0, 0, 0]);
    // The flags, then the size, then the attributes.
    assert_eq!(f.ret(442, &[fdcwd, m, 1, set_ro, 32]), errno(Errno::EINVAL));
    assert_eq!(f.ret(442, &[fdcwd, m, 0, set_ro, 16]), errno(Errno::EINVAL));
    assert_eq!(f.ret(442, &[fdcwd, m, 0, set_ro, 8192]), errno(Errno(7)));
    let tail = attr(&mut f, 0x240, [ro, 0, 0, 0, 1]);
    assert_eq!(f.ret(442, &[fdcwd, m, 0, tail, 40]), errno(Errno(7)));
    let nothing = attr(&mut f, 0x280, [0, 0, 0, 0, 0]);
    let missing = put(&mut f, 0x80, b"/missing");
    assert_eq!(f.ret(442, &[fdcwd, missing, 0, nothing, 32]), 0);
    let two = attr(&mut f, 0x2c0, [0, 0, (1 << 18) | (1 << 20), 0, 0]);
    assert_eq!(f.ret(442, &[fdcwd, m, 0, two, 32]), errno(Errno::EINVAL));
    let atime_alone = attr(&mut f, 0x300, [0x10, 0, 0, 0, 0]);
    assert_eq!(
        f.ret(442, &[fdcwd, m, 0, atime_alone, 32]),
        errno(Errno::EINVAL)
    );
    let atime_part = attr(&mut f, 0x340, [0x10, 0x10, 0, 0, 0]);
    assert_eq!(
        f.ret(442, &[fdcwd, m, 0, atime_part, 32]),
        errno(Errno::EINVAL)
    );
    let tmp = put(&mut f, 0xa0, b"/tmp");
    assert_eq!(
        f.ret(442, &[fdcwd, tmp, 0, set_ro, 32]),
        errno(Errno::EINVAL)
    );
    // Busy while a file is open for writing, then read-only.
    let file = put(&mut f, 0xc0, b"/tmp/m/f");
    let fd = f.ret(2, &[file, 0o101, 0o644]);
    assert_eq!(f.ret(442, &[fdcwd, m, 0, set_ro, 32]), errno(Errno(16)));
    assert_eq!(f.ret(3, &[fd]), 0);
    // NOSYMFOLLOW, on the mount below too, is not supported.
    let nosymfollow = attr(&mut f, 0x3c0, [0x0020_0000, 0, 0, 0, 0]);
    assert_eq!(
        f.ret(442, &[fdcwd, m, recursive, nosymfollow, 32]),
        errno(Errno::EOPNOTSUPP)
    );
    assert_eq!(f.ret(442, &[fdcwd, m, recursive, set_ro, 32]), 0);
    let deep = put(&mut f, 0xe0, b"/tmp/m/in/g");
    assert_eq!(f.ret(83, &[deep, 0o755]), errno(Errno(30)));
    // Clear it again, take noatime, and a peer group.
    let rw_noatime_shared = attr(&mut f, 0x380, [0x10, ro | 0x70, 1 << 20, 0, 0]);
    assert_eq!(f.ret(442, &[fdcwd, m, 0, rw_noatime_shared, 32]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" / /tmp/m rw,noatime shared:1 - tmpfs"),
        "{info}"
    );
    assert!(info.contains(" / /tmp/m/in ro,relatime - tmpfs"), "{info}");
    // open_tree_attr: a size without attributes, then a copy made read-only.
    assert_eq!(f.ret(467, &[fdcwd, m, 1, 0, 32]), errno(Errno::EINVAL));
    let tree = f.ret(467, &[fdcwd, m, 1, set_ro, 32]);
    assert!((tree as i64) >= 0);
    let (n, empty) = (put(&mut f, 0x100, b"/tmp/n"), put(&mut f, 0x120, b""));
    assert_eq!(f.ret(83, &[n, 0o755]), 0);
    assert_eq!(f.ret(429, &[tree, empty, fdcwd, n, 4]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" / /tmp/n ro,noatime shared:1 - tmpfs"),
        "{info}"
    );
    // A failure takes the descriptor away.
    let before = f.ret(32, &[0]);
    assert_eq!(f.ret(3, &[before]), 0);
    assert_eq!(
        f.ret(467, &[fdcwd, tmp, 0, set_ro, 32]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(32, &[0]), before);
}

/// A file on a `noexec` mount does not run (`EACCES`), `access` does not
/// let it, and it maps for no execution: `mmap` with `PROT_EXEC` is
/// `EPERM` and `mprotect` to it `EACCES`.
#[test]
fn a_noexec_mount_runs_nothing() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (n, x) = (put(&mut f, 0x40, b"/tmp/n"), put(&mut f, 0x60, b"/tmp/x"));
    assert_eq!(f.ret(83, &[n, 0o755]), 0);
    assert_eq!(f.ret(83, &[x, 0o755]), 0);
    let noexec = 8;
    assert_eq!(f.ret(165, &[none, n, tmpfs, noexec, 0]), 0);
    assert_eq!(f.ret(165, &[none, x, tmpfs, 0, 0]), 0);
    let (np, xp) = (
        put(&mut f, 0x80, b"/tmp/n/prog"),
        put(&mut f, 0xa0, b"/tmp/x/prog"),
    );
    for p in [np, xp] {
        let fd = f.ret(2, &[p, 0o101, 0o755]);
        assert_eq!(f.ret(1, &[fd, DATA, 4096]), 4096);
        assert_eq!(f.ret(3, &[fd]), 0);
    }
    // Not run, before its format is looked at.
    let argv = DATA + 0x400;
    f.mem.write(GuestAddr(argv), &np.to_le_bytes()).unwrap();
    f.mem
        .write(GuestAddr(argv + 8), &0u64.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(59, &[np, argv, 0]), errno(Errno::EACCES));
    assert_eq!(f.ret(59, &[xp, argv, 0]), errno(Errno(8)));
    assert_eq!(f.ret(21, &[np, 1]), errno(Errno::EACCES));
    assert_eq!(f.ret(21, &[xp, 1]), 0);
    assert_eq!(f.ret(21, &[np, 4]), 0);
    // Mapped for reading only.
    let (read, exec) = (1, 4);
    let fd = f.ret(2, &[np, 0, 0]);
    assert_eq!(
        f.ret(9, &[0, 4096, read | exec, 2, fd, 0]),
        errno(Errno::EPERM)
    );
    let at = f.ret(9, &[0, 4096, read, 2, fd, 0]);
    assert!((at as i64) > 0);
    assert_eq!(f.ret(10, &[at, 4096, read | exec]), errno(Errno::EACCES));
    let xfd = f.ret(2, &[xp, 0, 0]);
    let xat = f.ret(9, &[0, 4096, read | exec, 2, xfd, 0]);
    assert!((xat as i64) > 0);
}

/// `listmount` gives the unique IDs of the mounts reachable from the root
/// or from a mount, and `statmount` what one of them is.
#[test]
fn statmount_and_listmount_by_unique_ids() {
    let mut f = fixture();
    let req = |f: &mut Fixture, at: u64, words: [u64; 4]| -> u64 {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        f.mem.write(GuestAddr(DATA + at), &bytes).unwrap();
        DATA + at
    };
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (m, inner) = (
        put(&mut f, 0x40, b"/tmp/m"),
        put(&mut f, 0x60, b"/tmp/m/in"),
    );
    let size = put(&mut f, 0x80, b"size=1m");
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, m, tmpfs, 0, size]), 0);
    assert_eq!(f.ret(83, &[inner, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, inner, tmpfs, 0, 0]), 0);
    let ids = DATA + 0x1800;
    let read_ids = |f: &mut Fixture, n: u64| -> Vec<u64> {
        (0..n)
            .map(|i| f.mem.read_u64(GuestAddr(ids + 8 * i)).unwrap())
            .collect()
    };
    // From the root: the root, `/dev` and `/dev/shm` from start-up, and
    // both, in order.
    let all = req(&mut f, 0x100, [32, u64::MAX, 0, 0]);
    assert_eq!(f.ret(458, &[all, ids, 10, 0]), 5);
    let every = read_ids(&mut f, 5);
    assert!(every.windows(2).all(|w| w[0] < w[1]));
    let listed = [every[0], every[3], every[4]];
    assert_eq!(listed[0], paludarium_vfs::UNIQUE_OFFSET + 2);
    assert_eq!(f.ret(458, &[all, ids, 10, 1]), 5);
    assert_eq!(read_ids(&mut f, 1)[0], listed[2]);
    // After the last one given, and from a mount.
    let after = req(&mut f, 0x120, [32, u64::MAX, listed[0], 0]);
    assert_eq!(f.ret(458, &[after, ids, 10, 0]), 4);
    let below = req(&mut f, 0x140, [32, listed[1], 0, 0]);
    assert_eq!(f.ret(458, &[below, ids, 10, 0]), 1);
    assert_eq!(read_ids(&mut f, 1)[0], listed[2]);
    // The checks.
    assert_eq!(f.ret(458, &[all, ids, 10, 2]), errno(Errno::EINVAL));
    assert_eq!(f.ret(458, &[all, ids, 2_000_000, 0]), errno(Errno(75)));
    let small = req(&mut f, 0x160, [16, u64::MAX, 0, 0]);
    assert_eq!(f.ret(458, &[small, ids, 10, 0]), errno(Errno::EINVAL));
    let low = req(&mut f, 0x180, [32, 21, 0, 0]);
    assert_eq!(f.ret(458, &[low, ids, 10, 0]), errno(Errno::EINVAL));
    let missing = req(&mut f, 0x1a0, [32, u64::MAX - 1, 0, 0]);
    assert_eq!(f.ret(458, &[missing, ids, 10, 0]), errno(Errno::ENOENT));
    // statmount of /tmp/m: all it has.
    let buf = DATA + 0x1000;
    let stat = req(&mut f, 0x1c0, [32, listed[1], 0x7fff, 0]);
    assert_eq!(f.ret(457, &[stat, buf, 4096, 0]), 0);
    let word = |f: &mut Fixture, at: u64| f.mem.read_u64(GuestAddr(buf + at)).unwrap();
    let half = |f: &mut Fixture, at: u64| word(f, at) as u32;
    let string = |f: &mut Fixture, field: u64| -> Vec<u8> {
        let at = u64::from(half(f, field));
        let mut out = Vec::new();
        let mut byte = [0];
        loop {
            f.mem
                .read(GuestAddr(buf + 512 + at + out.len() as u64), &mut byte)
                .unwrap();
            if byte[0] == 0 {
                return out;
            }
            out.push(byte[0]);
        }
    };
    // All but the subtype, security options and ID mappings, which it has none of.
    assert_eq!(word(&mut f, 8), 0x16ff);
    assert_eq!(word(&mut f, 40), listed[1]);
    assert_eq!(word(&mut f, 48), listed[0]);
    assert_eq!(word(&mut f, 24), 0x0102_1994);
    assert_eq!(word(&mut f, 72), 1 << 18);
    assert_eq!(word(&mut f, 112), paludarium_vfs::FIRST_NAMESPACE_ID);
    assert_eq!(word(&mut f, 144), 0x7fff);
    assert_eq!(string(&mut f, 36), b"tmpfs");
    assert_eq!(string(&mut f, 104), b"/");
    assert_eq!(string(&mut f, 108), b"/tmp/m");
    assert_eq!(string(&mut f, 124), b"none");
    assert!(string(&mut f, 4).starts_with(b"size=1024k"));
    assert!(half(&mut f, 128) >= 1);
    // Too small for its strings, then a mount that is not there.
    assert_eq!(f.ret(457, &[stat, buf, 512, 0]), errno(Errno(75)));
    let basic = req(&mut f, 0x1e0, [32, listed[1], 2, 0]);
    assert_eq!(f.ret(457, &[basic, buf, 64, 0]), 0);
    assert_eq!(half(&mut f, 0), 64);
    let gone = req(&mut f, 0x200, [32, u64::MAX - 1, 2, 0]);
    assert_eq!(f.ret(457, &[gone, buf, 4096, 0]), errno(Errno::ENOENT));
    assert_eq!(f.ret(457, &[stat, buf, 4096, 2]), errno(Errno::EINVAL));
    // statx's STATX_MNT_ID_UNIQUE is the same ID.
    let out = DATA + 0x1c00;
    assert_eq!(f.ret(332, &[(-100i64) as u64, inner, 0, 0x4000, out]), 0);
    assert_eq!(f.mem.read_u64(GuestAddr(out + 144)).unwrap(), listed[2]);
}

/// `open_tree` gives a descriptor of a file or of a detached copy of its
/// mount, which `move_mount` attaches; a copy no one attached goes with
/// its descriptor.
#[test]
fn open_tree_and_move_mount_attach_a_detached_copy() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let (m, n) = (put(&mut f, 0x40, b"/tmp/m"), put(&mut f, 0x60, b"/tmp/n"));
    assert_eq!(f.ret(83, &[m, 0o755]), 0);
    assert_eq!(f.ret(83, &[n, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, m, tmpfs, 0, 0]), 0);
    let (inner, y) = (
        put(&mut f, 0x80, b"/tmp/m/in"),
        put(&mut f, 0xa0, b"/tmp/m/in/y"),
    );
    assert_eq!(f.ret(83, &[inner, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, inner, tmpfs, 0, 0]), 0);
    assert!((f.ret(2, &[y, 0o101, 0o644]) as i64) >= 0);
    let listed = whole(&mut f, b"/proc/self/mountinfo");
    let fdcwd = (-100i64) as u64;
    let (clone, recursive) = (1, 0x8000);
    // The flags first.
    assert_eq!(f.ret(428, &[fdcwd, m, 8]), errno(Errno::EINVAL));
    assert_eq!(f.ret(428, &[fdcwd, m, recursive]), errno(Errno::EINVAL));
    assert_eq!(f.ret(428, &[fdcwd, m, 4 | clone]), errno(Errno::EINVAL));
    assert_eq!(f.ret(428, &[fdcwd, m, 2 | clone]), errno(Errno::EINVAL));
    let fd = f.ret(428, &[fdcwd, m, clone]);
    assert!((fd as i64) >= 0);
    // Without recursion the mount below is not in the copy.
    let (rel_y, nothing) = (put(&mut f, 0xc0, b"in/y"), put(&mut f, 0xd0, b""));
    assert_eq!(f.ret(257, &[fd, rel_y, 0, 0]), errno(Errno::ENOENT));
    assert_eq!(whole(&mut f, b"/proc/self/mountinfo"), listed);
    assert_eq!(f.ret(3, &[fd]), 0);
    let fd = f.ret(428, &[fdcwd, m, clone | recursive]);
    let opened = f.ret(257, &[fd, rel_y, 0, 0]);
    assert!((opened as i64) >= 0, "{}", opened as i64);
    assert_eq!(f.ret(3, &[opened]), 0);
    // Attached, it stays after the descriptor goes.
    let (from_empty, to_empty) = (4, 0x40);
    assert_eq!(
        f.ret(429, &[fd, nothing, fdcwd, n, 8]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(429, &[fd, nothing, fdcwd, n, 0]),
        errno(Errno::ENOENT)
    );
    assert_eq!(
        f.ret(429, &[99, nothing, fdcwd, n, from_empty]),
        errno(Errno::EBADF)
    );
    assert_eq!(
        f.ret(429, &[fd, rel_y, fd, nothing, from_empty | to_empty]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(429, &[fd, nothing, fdcwd, n, from_empty]), 0);
    assert_eq!(f.ret(3, &[fd]), 0);
    let moved = put(&mut f, 0xe0, b"/tmp/n/in/y");
    assert_eq!(f.ret(21, &[moved, 0]), 0);
    let info = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        info.contains(" / /tmp/n rw,relatime - tmpfs none "),
        "{info}"
    );
    assert!(
        info.contains(" / /tmp/n/in rw,relatime - tmpfs none "),
        "{info}"
    );
    // A plain one is an O_PATH descriptor of the file.
    let fd = f.ret(428, &[fdcwd, m, 0]);
    assert_eq!(f.ret(72, &[fd, 3, 0]) & 0o10000000, 0o10000000);
    assert_eq!(f.ret(3, &[fd]), 0);
    // A mount moved as MS_MOVE moves it, and its peer group by
    // MOVE_MOUNT_SET_GROUP.
    let o = put(&mut f, 0x100, b"/tmp/o");
    assert_eq!(f.ret(83, &[o, 0o755]), 0);
    assert_eq!(f.ret(429, &[fdcwd, n, fdcwd, o, 0]), 0);
    assert_eq!(
        f.ret(429, &[fdcwd, o, fdcwd, m, 0x300]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(429, &[fdcwd, o, fdcwd, m, 0x100]),
        errno(Errno::EINVAL)
    );
}

/// A new mount namespace has copies of the mounts, with new IDs, on the
/// same file systems, and mounts of its own; the first keeps its own.
#[test]
fn unshare_newns_copies_the_mounts() {
    let mut f = fixture();
    let (none, tmpfs) = (put(&mut f, 0, b"none"), put(&mut f, 0x10, b"tmpfs"));
    let target = put(&mut f, 0x40, b"/tmp/m");
    assert_eq!(f.ret(83, &[target, 0o755]), 0);
    assert_eq!(f.ret(165, &[none, target, tmpfs, 0, 0]), 0);
    let inside = put(&mut f, 0x80, b"/tmp/m/f");
    let fd = f.ret(2, &[inside, 0o102, 0o600]);
    assert_eq!(f.ret(3, &[fd]), 0);
    let first = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(first.starts_with("21 1 0:1 / / ") && first.contains("\n24 21 0:3 / /tmp/m "));
    assert_eq!(f.ret(272, &[0x2_0000]), 0);
    let copy = String::from_utf8(whole(&mut f, b"/proc/self/mountinfo")).unwrap();
    assert!(
        copy.starts_with("25 1 0:1 / / ") && copy.contains("\n28 25 0:3 / /tmp/m "),
        "{copy}"
    );
    let stat = DATA + 0x400;
    assert_eq!(f.ret(4, &[inside, stat]), 0);
    // Gone from the copy, it is still in the first namespace.
    assert_eq!(f.ret(166, &[target, 0]), 0);
    assert_eq!(f.ret(4, &[inside, stat]), errno(Errno::ENOENT));
    let first_table = Arc::clone(f.kernel.files.first_mounts());
    assert!(!Arc::ptr_eq(&first_table, &f.kernel.files.mount_table()));
    let lower =
        paludarium_vfs::NamespacedFs::new(Arc::new(paludarium_vfs::MemFs::new()), first_table);
    assert_eq!(paludarium_vfs::FileSystem::mounts(&lower).len(), 4);
}

/// chroot keeps absolute paths, links and `..` inside the new root, and
/// leaves the working directory where it was.
#[test]
fn chroot_keeps_paths_to_the_new_root() {
    let mut f = fixture();
    let s = |f: &mut Fixture, at: u64, text: &[u8]| -> u64 {
        let mut bytes = text.to_vec();
        bytes.push(0);
        f.mem.write(GuestAddr(DATA + at), &bytes).unwrap();
        DATA + at
    };
    let cwd = |f: &mut Fixture| -> Vec<u8> {
        let n = f.ret(79, &[DATA + 0x1000, 256]);
        let mut out = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut out).unwrap();
        out.pop();
        out
    };
    for dir in [&b"/jail"[..], b"/jail/d", b"/jail/d/e"] {
        let p = s(&mut f, 0, dir);
        assert_eq!(f.ret(83, &[p, 0o755]), 0);
    }
    let p = s(&mut f, 0, b"/jail/f");
    let fd = f.ret(2, &[p, 0o101, 0o644]);
    let data = s(&mut f, 0x100, b"in");
    assert_eq!(f.ret(1, &[fd, data, 2]), 2);
    let p = s(&mut f, 0, b"/f");
    let fd = f.ret(2, &[p, 0o101, 0o644]);
    let data = s(&mut f, 0x100, b"out");
    assert_eq!(f.ret(1, &[fd, data, 3]), 3);
    let (target, link) = (s(&mut f, 0, b"/f"), s(&mut f, 0x80, b"/jail/d/abs"));
    assert_eq!(f.ret(88, &[target, link]), 0);
    let (target, link) = (s(&mut f, 0, b"../../../f"), s(&mut f, 0x80, b"/jail/d/up"));
    assert_eq!(f.ret(88, &[target, link]), 0);
    // Lookups first: missing, not a directory.
    let p = s(&mut f, 0, b"/none");
    assert_eq!(f.ret(161, &[p]), errno(Errno::ENOENT));
    let p = s(&mut f, 0, b"/jail/f");
    assert_eq!(f.ret(161, &[p]), errno(Errno::ENOTDIR));
    let p = s(&mut f, 0, b"/jail");
    assert_eq!(f.ret(80, &[p]), 0);
    let p = s(&mut f, 0, b"d");
    assert_eq!(f.ret(80, &[p]), 0);
    let p = s(&mut f, 0, b"/jail");
    assert_eq!(f.ret(161, &[p]), 0);
    // The working directory stayed: /jail/d is /d from the new root.
    assert_eq!(cwd(&mut f), b"/d");
    let read = |f: &mut Fixture, path: &[u8]| -> Vec<u8> {
        let p = s(f, 0, path);
        let fd = f.ret(2, &[p, 0, 0]);
        if (fd as i64) < 0 {
            return format!("errno {}", -(fd as i64)).into_bytes();
        }
        let n = f.ret(0, &[fd, DATA + 0x200, 16]);
        let mut out = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x200), &mut out).unwrap();
        f.ret(3, &[fd]);
        out
    };
    assert_eq!(read(&mut f, b"/f"), b"in");
    assert_eq!(read(&mut f, b"/../../f"), b"in");
    assert_eq!(read(&mut f, b"../../../f"), b"in");
    assert_eq!(read(&mut f, b"abs"), b"in");
    assert_eq!(read(&mut f, b"up"), b"in");
    assert_eq!(read(&mut f, b"/d/e/../../f"), b"in");
    // No proc filesystem under the new root.
    assert_eq!(read(&mut f, b"/proc/self/status"), b"errno 2");
    // chdir("/") is the new root; a root inside it moves again.
    let p = s(&mut f, 0, b"/");
    assert_eq!(f.ret(80, &[p]), 0);
    assert_eq!(cwd(&mut f), b"/");
    let p = s(&mut f, 0, b"/d");
    assert_eq!(f.ret(161, &[p]), 0);
    assert_eq!(cwd(&mut f), b"(unreachable)/jail");
    // Outside the root, `..` goes up as ever.
    assert_eq!(read(&mut f, b"../f"), b"out");
    assert_eq!(read(&mut f, b"/f"), b"errno 2");
    assert_eq!(read(&mut f, b"/../abs"), b"errno 2");
    // Without CAP_SYS_CHROOT, after the lookup and the permission check.
    f.thread.state.credentials = f
        .thread
        .state
        .credentials
        .setresuid(1000, 1000, 1000)
        .unwrap();
    let p = s(&mut f, 0, b"/e");
    assert_eq!(f.ret(161, &[p]), errno(Errno::EPERM));
    let p = s(&mut f, 0, b"/none");
    assert_eq!(f.ret(161, &[p]), errno(Errno::ENOENT));
}
/// `/proc/self/root` is the root, and the links read from the reader's
/// root, as Linux's `d_path` gives them.
#[test]
fn proc_links_read_from_the_root() {
    let mut f = fixture();
    let s = |f: &mut Fixture, at: u64, text: &[u8]| -> u64 {
        let mut bytes = text.to_vec();
        bytes.push(0);
        f.mem.write(GuestAddr(DATA + at), &bytes).unwrap();
        DATA + at
    };
    let link = |f: &mut Fixture, dir: u64, name: &[u8]| -> Vec<u8> {
        let p = s(f, 0, name);
        let n = f.ret(267, &[dir, p, DATA + 0x1000, 256]);
        if (n as i64) < 0 {
            return format!("errno {}", -(n as i64)).into_bytes();
        }
        let mut out = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x1000), &mut out).unwrap();
        out
    };
    const AT_FDCWD: u64 = -100i64 as u64;
    for dir in [&b"/jail"[..], b"/jail/d", b"/out"] {
        let p = s(&mut f, 0, dir);
        assert_eq!(f.ret(83, &[p, 0o755]), 0);
    }
    assert_eq!(link(&mut f, AT_FDCWD, b"/proc/self/root"), b"/");
    let p = s(&mut f, 0, b"/out");
    let out = f.ret(2, &[p, 0o200000, 0]);
    let p = s(&mut f, 0, b"/proc/self");
    let proc = f.ret(2, &[p, 0o200000, 0]);
    let p = s(&mut f, 0, b"/jail/d");
    assert_eq!(f.ret(80, &[p]), 0);
    let p = s(&mut f, 0, b"/jail");
    assert_eq!(f.ret(161, &[p]), 0);
    // Through the /proc opened before: the root and the working directory
    // from the new root; the new root has no /proc of its own.
    assert_eq!(link(&mut f, proc, b"root"), b"/");
    assert_eq!(link(&mut f, proc, b"cwd"), b"/d");
    assert_eq!(link(&mut f, AT_FDCWD, b"/proc/self/root"), b"errno 2");
    let p = s(&mut f, 0, b"/d");
    let d = f.ret(2, &[p, 0o200000, 0]);
    assert_eq!(link(&mut f, proc, format!("fd/{d}").as_bytes()), b"/d");
    // A working directory outside the root reads from the machine's root,
    // unmarked.
    assert_eq!(f.ret(81, &[out]), 0);
    assert_eq!(link(&mut f, proc, b"cwd"), b"/out");
}
/// `bpf(BPF_MAP_CREATE)` of a map of `kind`, `key`, `value`, `entries` and
/// `flags`, in the fixture.
fn create_map(f: &mut Fixture, kind: u32, key: u32, value: u32, entries: u32, flags: u32) -> u64 {
    let mut attr = [0u8; 72];
    for (i, field) in [kind, key, value, entries, flags].iter().enumerate() {
        attr[i * 4..i * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    f.mem.write(GuestAddr(DATA), &attr).unwrap();
    f.ret(321, &[0, DATA, 72])
}
#[test]
fn bpf_follows_linux_master_where_the_ci_kernel_differs() {
    let mut f = fixture();
    let (hash, array, rdonly_wronly) = (1, 2, 1 << 3 | 1 << 4);
    // A hash's key and value: E2BIG from KMALLOC_MAX_SIZE less 64, as
    // master's `htab_map_alloc_check` has it (Linux 7.0 takes 16 more).
    let limit = (1 << 22) - 64;
    assert_eq!(
        create_map(&mut f, hash, 4, limit - 4, 1, 0),
        errno(Errno(7))
    );
    assert!(create_map(&mut f, hash, 4, limit - 5, 1, 0) < 1 << 20);
    // BPF_F_RDONLY with BPF_F_WRONLY is checked after the map is made, as
    // master's `map_create` does (Linux 7.0 checks it before the type).
    assert_eq!(
        create_map(&mut f, hash, 4, limit, 1, rdonly_wronly),
        errno(Errno(7))
    );
    assert_eq!(
        create_map(&mut f, array, 4, 1 << 30, 1 << 20, rdonly_wronly),
        errno(Errno::ENOMEM)
    );
    assert_eq!(
        create_map(&mut f, array, 4, 8, 1, rdonly_wronly),
        errno(Errno::EINVAL)
    );
}
#[test]
fn prctl_task_perf_events_take_any_arguments() {
    let mut f = fixture();
    assert_eq!(f.ret(157, &[31, 0, 0, 0, 0]), 0); // PR_TASK_PERF_EVENTS_DISABLE
    assert_eq!(f.ret(157, &[32, 1, 2, 3, 4]), 0); // PR_TASK_PERF_EVENTS_ENABLE
}

/// A bind mount of `/proc` or `/dev`, which the kernel generates, shows
/// what it generates below them; a working directory there is the mount's
/// place, which `getcwd` names and paths from it go through.
#[test]
fn a_bind_mount_of_a_generated_directory_shows_its_files() {
    let mut f = fixture();
    let (p, d) = (put(&mut f, 0, b"/tmp/p"), put(&mut f, 0x10, b"/tmp/d"));
    let (proc_dir, dev) = (put(&mut f, 0x20, b"/proc"), put(&mut f, 0x30, b"/dev"));
    let null = put(&mut f, 0x40, b"/tmp/d/null");
    let comm = put(&mut f, 0x60, b"/tmp/p/self/comm");
    let relative = put(&mut f, 0x80, b"self/comm");
    let missing = put(&mut f, 0xa0, b"/tmp/p/nosuch");
    let root = put(&mut f, 0xc0, b"/");
    assert_eq!(f.ret(83, &[p, 0o755]), 0);
    assert_eq!(f.ret(83, &[d, 0o755]), 0);
    // MS_BIND, and MS_BIND | MS_REC: no mount below either is locked.
    assert_eq!(f.ret(165, &[proc_dir, p, 0, 4096, 0]), 0);
    assert_eq!(f.ret(165, &[dev, d, 0, 4096 | 16384, 0]), 0);
    let fd = f.ret(2, &[null, 2, 0]);
    assert!(fd < 1024);
    assert_eq!(f.ret(1, &[fd, DATA + 0x100, 3]), 3);
    assert_eq!(f.ret(3, &[fd]), 0);
    let fd = f.ret(2, &[comm, 0, 0]);
    assert!(fd < 1024);
    assert!(f.ret(0, &[fd, DATA + 0x100, 64]) > 0);
    assert_eq!(f.ret(3, &[fd]), 0);
    // A missing name there is the kernel's ENOENT, also to chdir.
    assert_eq!(f.ret(2, &[missing, 0, 0]), errno(Errno::ENOENT));
    assert_eq!(f.ret(80, &[missing]), errno(Errno::ENOENT));
    assert_eq!(f.ret(80, &[p]), 0);
    let cwd = DATA + 0x200;
    assert_eq!(f.ret(79, &[cwd, 64]), 7);
    let mut name = [0; 7];
    f.mem.read(GuestAddr(cwd), &mut name).unwrap();
    assert_eq!(&name, b"/tmp/p\0");
    let fd = f.ret(257, &[(-100i64) as u64, relative, 0, 0]);
    assert!(fd < 1024);
    assert_eq!(f.ret(3, &[fd]), 0);
    // `self` there is the link it is: the working directory is the
    // process's own directory, through the bind mount.
    let own = put(&mut f, 0xe0, b"/tmp/p/self");
    assert_eq!(f.ret(80, &[own]), 0);
    let expected = format!("/tmp/p/{}\0", f.ret(39, &[]));
    let got = f.ret(79, &[cwd, 64]);
    assert_eq!(got, expected.len() as u64);
    let mut name = vec![0; expected.len()];
    f.mem.read(GuestAddr(cwd), &mut name).unwrap();
    assert_eq!(name, expected.as_bytes());
    // `thread-self` is the thread's own directory there.
    let own_thread = put(&mut f, 0x300, b"/tmp/p/thread-self");
    assert_eq!(f.ret(80, &[own_thread]), 0);
    let pid = f.ret(39, &[]);
    let expected = format!("/tmp/p/{pid}/task/{}\0", f.ret(186, &[]));
    assert_eq!(f.ret(79, &[cwd, 64]), expected.len() as u64);
    let mut name = vec![0; expected.len()];
    f.mem.read(GuestAddr(cwd), &mut name).unwrap();
    assert_eq!(name, expected.as_bytes());
    assert_eq!(f.ret(80, &[p]), 0);
    // A descriptor opened there names the same place in /proc/self/fd,
    // with `open` and with `openat2` and `RESOLVE_NO_SYMLINKS`.
    let how = DATA + 0x340;
    f.mem.write(GuestAddr(how), &[0u8; 24]).unwrap();
    f.mem
        .write(GuestAddr(how), &0o200000u64.to_le_bytes())
        .unwrap();
    f.mem
        .write(GuestAddr(how + 16), &4u64.to_le_bytes())
        .unwrap();
    for fd in [
        f.ret(2, &[own, 0o200000, 0]),
        f.ret(437, &[(-100i64) as u64, own, how, 24]),
    ] {
        assert!(fd < 1024);
        let link = put(&mut f, 0x380, format!("/proc/self/fd/{fd}").as_bytes());
        let got = f.ret(89, &[link, cwd, 64]);
        let mut name = vec![0; got as usize];
        f.mem.read(GuestAddr(cwd), &mut name).unwrap();
        assert_eq!(name, format!("/tmp/p/{pid}").as_bytes());
        assert_eq!(f.ret(3, &[fd]), 0);
    }
    // Not followed at the end, `self` is the link, as `/proc/self` is.
    let unbound = put(&mut f, 0x3c0, b"/proc/self");
    for path in [own, unbound] {
        assert_eq!(f.ret(2, &[path, 0o400000, 0]), errno(Errno(40)));
    }
    // In use while it is the working directory.
    assert_eq!(f.ret(166, &[p, 0]), errno(Errno(16)));
    assert_eq!(f.ret(80, &[root]), 0);
    assert_eq!(f.ret(166, &[p, 0]), 0);
    assert_eq!(f.ret(166, &[d, 0]), 0);
    assert_eq!(f.ret(2, &[null, 2, 0]), errno(Errno::ENOENT));
}

#[test]
fn a_symbolic_link_leads_into_the_files_the_kernel_generates() {
    let mut f = fixture();
    let null = put(&mut f, 0, b"/dev/null");
    let link = put(&mut f, 0x20, b"/tmp/l");
    let dev = put(&mut f, 0x40, b"/dev");
    let to_dev = put(&mut f, 0x60, b"/tmp/ld");
    let through = put(&mut f, 0x80, b"/tmp/ld/null");
    let nowhere = put(&mut f, 0xa0, b"/nosuch");
    let dangling = put(&mut f, 0xc0, b"/tmp/x");
    let relative = put(&mut f, 0xe0, b"../dev/null");
    let up = put(&mut f, 0x400, b"/tmp/r");
    assert_eq!(f.ret(88, &[null, link]), 0);
    assert_eq!(f.ret(88, &[dev, to_dev]), 0);
    assert_eq!(f.ret(88, &[nowhere, dangling]), 0);
    assert_eq!(f.ret(88, &[relative, up]), 0);
    // `stat` follows each to the device, `lstat` stays on the link.
    for path in [link, through, up] {
        assert_eq!(
            stat_mode_and_mtime(&mut f, path, false).0 & 0o170000,
            0o020000
        );
    }
    assert_eq!(
        stat_mode_and_mtime(&mut f, link, true).0 & 0o170000,
        0o120000
    );
    // `open` writes to the device, and a link to nothing is still ENOENT.
    let fd = f.ret(2, &[through, 1, 0]);
    assert!(fd < 1024);
    assert_eq!(f.ret(1, &[fd, DATA + 0x200, 3]), 3);
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(f.ret(2, &[link, 0o400001, 0]), errno(Errno(40)));
    assert_eq!(f.ret(4, &[dangling, DATA + 0x300]), errno(Errno::ENOENT));
    assert_eq!(f.ret(2, &[dangling, 0, 0]), errno(Errno::ENOENT));
    // A trailing slash asks for a directory: ENOTDIR for the device, and
    // `/dev` itself through its link.
    let slashed = put(&mut f, 0x420, b"/tmp/l/");
    let dev_slashed = put(&mut f, 0x440, b"/tmp/ld/");
    assert_eq!(f.ret(4, &[slashed, DATA + 0x300]), errno(Errno::ENOTDIR));
    assert_eq!(f.ret(2, &[slashed, 0, 0]), errno(Errno::ENOTDIR));
    for path in [to_dev, dev_slashed] {
        assert_eq!(
            stat_mode_and_mtime(&mut f, path, false).0 & 0o170000,
            0o040000
        );
    }
    // `/proc/self` through a link to `/proc`, and `statx` and `access`.
    let proc_dir = put(&mut f, 0x460, b"/proc");
    let to_proc = put(&mut f, 0x480, b"/tmp/lp");
    let comm = put(&mut f, 0x4a0, b"/tmp/lp/self/comm");
    assert_eq!(f.ret(88, &[proc_dir, to_proc]), 0);
    assert_eq!(
        stat_mode_and_mtime(&mut f, comm, false).0 & 0o170000,
        0o100000
    );
    let statx = DATA + 0x500;
    assert_eq!(f.ret(332, &[(-100i64) as u64, link, 0, 0x7ff, statx]), 0);
    let mut mode = [0u8; 2];
    f.mem.read(GuestAddr(statx + 28), &mut mode).unwrap();
    assert_eq!(u32::from(u16::from_le_bytes(mode)) & 0o170000, 0o020000);
    assert_eq!(f.ret(21, &[link, 2]), 0);
    assert_eq!(f.ret(21, &[comm, 4]), 0);
}

/// The calls that take a path go on through a symbolic link into `/dev`
/// or `/proc` as they do for the path it leads to: `readlink` reads the
/// generated link, and each other call gives what it gives there, those
/// that make a name there too.
#[test]
fn the_path_calls_go_through_a_link_into_the_generated_files() {
    let mut f = fixture();
    let dev = put(&mut f, 0, b"/dev");
    let ld = put(&mut f, 0x10, b"/tmp/ld");
    let proc_dir = put(&mut f, 0x20, b"/proc");
    let lp = put(&mut f, 0x30, b"/tmp/lp");
    assert_eq!(f.ret(88, &[dev, ld]), 0);
    assert_eq!(f.ret(88, &[proc_dir, lp]), 0);
    let name = put(&mut f, 0x40, b"user.x");
    let other = put(&mut f, 0x60, b"/tmp/other");
    let root = put(&mut f, 0x80, b"/");
    let buf = DATA + 0x1000;
    // `readlink` of a link the kernel generates, through a link to it.
    let fd_link = put(&mut f, 0x100, b"/tmp/ld/fd");
    assert_eq!(f.ret(89, &[fd_link, buf, 64]), 13);
    let mut got = [0; 13];
    f.mem.read(GuestAddr(buf), &mut got).unwrap();
    assert_eq!(&got, b"/proc/self/fd");
    let own = put(&mut f, 0x100, b"/tmp/lp/self");
    let pid = f.ret(39, &[]).to_string();
    assert_eq!(f.ret(89, &[own, buf, 64]), pid.len() as u64);
    let pairs: [(&[u8], &[u8]); 5] = [
        (b"/dev/null", b"/tmp/ld/null"),
        (b"/dev/fd", b"/tmp/ld/fd"),
        (b"/proc/self", b"/tmp/lp/self"),
        (b"/proc/self/comm", b"/tmp/lp/self/comm"),
        (b"/dev/nosuch", b"/tmp/ld/nosuch"),
    ];
    for (direct, through) in pairs {
        let mut results = Vec::new();
        for path in [direct, through] {
            let p = put(&mut f, 0x100, path);
            let call = |f: &mut Fixture, n: u64, args: &[u64]| f.ret(n, args) as i64;
            results.push([
                call(&mut f, 89, &[p, buf, 64]),
                call(&mut f, 267, &[(-100i64) as u64, p, buf, 64]),
                call(&mut f, 80, &[p]),
                call(&mut f, 80, &[root]),
                call(&mut f, 90, &[p, 0o666]),
                call(&mut f, 92, &[p, 0, 0]),
                call(&mut f, 94, &[p, 0, 0]),
                call(&mut f, 76, &[p, 0]),
                call(&mut f, 280, &[(-100i64) as u64, p, 0, 0]),
                call(&mut f, 235, &[p, 0]),
                call(&mut f, 191, &[p, name, buf, 0]),
                call(&mut f, 192, &[p, name, buf, 0]),
                call(&mut f, 194, &[p, buf, 0]),
                call(&mut f, 188, &[p, name, name, 1, 0]),
                call(&mut f, 137, &[p, buf]),
                call(&mut f, 86, &[p, other]),
                // The calls that make a name there.
                call(&mut f, 83, &[p, 0o755]),
                call(&mut f, 133, &[p, 0o10644, 0]),
                call(&mut f, 88, &[other, p]),
            ]);
            let _ = f.ret(87, &[other]);
        }
        assert_eq!(
            results[0],
            results[1],
            "{}",
            String::from_utf8_lossy(direct)
        );
    }
}

/// The path calls that change a file the kernel generates in `/dev` or
/// `/proc`, by its own path, as `notify_change` makes them there: root may
/// keep a mode or owner as it is but gets `EPERM` for a new one, which no
/// file here keeps; procfs refuses a new mode of a process's file; another
/// user is held to the owner's checks; `chdir` goes there and `statfs`
/// gives devtmpfs's type.
#[test]
fn the_path_calls_change_the_generated_files() {
    let mut f = fixture();
    let dev = put(&mut f, 0, b"/dev");
    let null = put(&mut f, 0x10, b"/dev/null");
    let comm = put(&mut f, 0x20, b"/proc/self/comm");
    let proc_dir = put(&mut f, 0x40, b"/proc");
    let buf = DATA + 0x800;
    assert_eq!(f.ret(80, &[dev]), 0);
    assert_eq!(f.ret(79, &[buf, 64]), 5);
    let mut got = [0; 5];
    f.mem.read(GuestAddr(buf), &mut got).unwrap();
    assert_eq!(&got, b"/dev\0");
    assert_eq!(f.ret(80, &[null]), errno(Errno::ENOTDIR));
    assert_eq!(f.ret(80, &[proc_dir]), 0);
    assert_eq!(f.ret(90, &[null, 0o666]), 0);
    assert_eq!(f.ret(90, &[null, 0o600]), errno(Errno::EPERM));
    assert_eq!(f.ret(90, &[comm, 0o644]), errno(Errno::EPERM));
    assert_eq!(f.ret(92, &[null, 0, 0]), 0);
    assert_eq!(
        f.ret(92, &[null, 1, u64::from(u32::MAX)]),
        errno(Errno::EPERM)
    );
    assert_eq!(f.ret(92, &[comm, 1, 1]), 0);
    assert_eq!(f.ret(76, &[null, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(76, &[dev, 0]), errno(Errno::EISDIR));
    assert_eq!(f.ret(76, &[comm, 0]), 0);
    assert_eq!(f.ret(76, &[comm, u64::MAX]), errno(Errno::EINVAL));
    assert_eq!(f.ret(137, &[null, buf]), 0);
    let mut kind = [0; 8];
    f.mem.read(GuestAddr(buf), &mut kind).unwrap();
    assert_eq!(u64::from_le_bytes(kind), 0x0102_1994);
    let missing = put(&mut f, 0x60, b"/dev/nosuch");
    assert_eq!(f.ret(137, &[missing, buf]), errno(Errno::ENOENT));
    let long = put(
        &mut f,
        0x100,
        &[b"/dev/mqueue/".as_slice(), &[b'a'; 256]].concat(),
    );
    assert_eq!(f.ret(90, &[long, 0o600]), errno(Errno::ENAMETOOLONG));
    // Another user: the owner's checks of root's files.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    assert_eq!(f.ret(90, &[null, 0o666]), errno(Errno::EPERM));
    assert_eq!(f.ret(92, &[null, u64::MAX, u64::MAX]), 0);
    assert_eq!(f.ret(92, &[null, 1000, u64::MAX]), errno(Errno::EPERM));
    let times = DATA + 0x900;
    f.mem.write(GuestAddr(times), &[0; 32]).unwrap();
    assert_eq!(f.ret(280, &[(-100i64) as u64, null, 0, 0]), 0);
    assert_eq!(
        f.ret(280, &[(-100i64) as u64, null, times, 0]),
        errno(Errno::EPERM)
    );
    assert_eq!(f.ret(80, &[proc_dir]), 0);
}

/// A bind of `/proc`, `/dev` or a directory in them onto a directory of a
/// new root shows the files the kernel generates there after `chroot`, as
/// on Linux.
#[test]
fn a_bind_of_proc_shows_its_files_in_a_new_root() {
    let mut f = fixture();
    let root = put(&mut f, 0, b"/tmp/r");
    let proc_place = put(&mut f, 0x10, b"/tmp/r/proc");
    let dev_place = put(&mut f, 0x20, b"/tmp/r/dev");
    let own_place = put(&mut f, 0x30, b"/tmp/r/own");
    let proc_dir = put(&mut f, 0x40, b"/proc");
    let dev = put(&mut f, 0x50, b"/dev");
    let own = put(&mut f, 0x60, b"/proc/self");
    for place in [root, proc_place, dev_place, own_place] {
        assert_eq!(f.ret(83, &[place, 0o755]), 0);
    }
    assert_eq!(f.ret(165, &[proc_dir, proc_place, 0, 4096, 0]), 0);
    assert_eq!(f.ret(165, &[dev, dev_place, 0, 4096, 0]), 0);
    assert_eq!(f.ret(165, &[own, own_place, 0, 4096, 0]), 0);
    assert_eq!(f.ret(161, &[root]), 0);
    let comm = put(&mut f, 0x80, b"/proc/self/comm");
    let own_comm = put(&mut f, 0xa0, b"/own/comm");
    for path in [comm, own_comm] {
        let fd = f.ret(2, &[path, 0, 0]);
        assert!(fd < 1024);
        assert!(f.ret(0, &[fd, DATA + 0x100, 64]) > 0);
        assert_eq!(f.ret(3, &[fd]), 0);
    }
    let null = put(&mut f, 0xc0, b"/dev/null");
    let fd = f.ret(2, &[null, 2, 0]);
    assert!(fd < 1024);
    assert_eq!(f.ret(1, &[fd, DATA + 0x100, 3]), 3);
    assert_eq!(f.ret(3, &[fd]), 0);
    let missing = put(&mut f, 0xe0, b"/proc/nosuch");
    assert_eq!(f.ret(2, &[missing, 0, 0]), errno(Errno::ENOENT));
}
