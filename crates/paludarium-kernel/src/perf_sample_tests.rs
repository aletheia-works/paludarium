//! Samples of a software event through the system call interface: the
//! page faults a thread takes while a sampling event is enabled, each a
//! `PERF_RECORD_SAMPLE` of the fields `sample_type` asks for in Linux's
//! order, a full buffer's lost samples and the `PERF_RECORD_LOST` after
//! them, `PERF_EVENT_IOC_PAUSE_OUTPUT`, a read-only buffer that overwrites,
//! a backward one, and a user callchain; and the wakeups of a buffer, the
//! `O_ASYNC` signals of each overflow, `PERF_EVENT_IOC_REFRESH` and
//! `sigtrap`'s `SIGTRAP`. The expected values are Linux's
//! (`kernel/events/core.c`, `ring_buffer.c`): they are the lines of the
//! perf-sample and perf-wakeup cases of `tests/guests/processes/perf.c`,
//! which the differential tests compare with Linux. The guest's writes to
//! fresh pages are this test's writes to them, which the next system call
//! counts as the thread's faults, as the guest's do; a signal its handlers
//! take is this test's look at the frame the kernel builds, then the
//! handler's return through `rt_sigreturn`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
/// A `struct perf_event_attr`, and what a call reads or writes.
const ATTR: u64 = DATA;
const ARG: u64 = DATA + 0x200;

const READ: u64 = 0;
const CLOSE: u64 = 3;
const MMAP: u64 = 9;
const MUNMAP: u64 = 11;
const IOCTL: u64 = 16;
const PERF_EVENT_OPEN: u64 = 298;
const POLL: u64 = 7;
const RT_SIGACTION: u64 = 13;
const RT_SIGPROCMASK: u64 = 14;
const RT_SIGRETURN: u64 = 15;
const GETPID: u64 = 39;
const FCNTL: u64 = 72;
const RT_SIGTIMEDWAIT: u64 = 128;

/// Where the guest's handlers are: never run, but taken as the guest's
/// `on_io` and `on_trap` when a signal returns to it.
const HANDLER: u64 = 0x40_1000;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_BLOCK: u64 = 0;
const SIG_SETMASK: u64 = 2;
const SIGTRAP: u64 = 5;
/// musl's `SIGRTMIN`.
const SIGRTMIN: u64 = 35;
const TRAP_PERF: i32 = 6;
const POLL_IN: i32 = 1;
const POLL_HUP: i32 = 6;
const POLLIN: u64 = 1;
const POLLRDNORM: u64 = 0x40;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_SETOWN: u64 = 8;
const F_SETSIG: u64 = 10;
const O_ASYNC: u64 = 0x2000;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;

const DISABLED: u64 = 1 << 0;
const INHERIT: u64 = 1 << 1;
const WATERMARK: u64 = 1 << 14;
const REMOVE_ON_EXEC: u64 = 1 << 36;
const ATTR_SIGTRAP: u64 = 1 << 37;
const EXCLUDE_KERNEL: u64 = 1 << 5;
const EXCLUDE_HV: u64 = 1 << 6;
const SAMPLE_ID_ALL: u64 = 1 << 18;
const EXCLUDE_CALLCHAIN_KERNEL: u64 = 1 << 21;
const WRITE_BACKWARD: u64 = 1 << 27;
const SAMPLE_TID: u64 = 1 << 1;
const SAMPLE_CALLCHAIN: u64 = 1 << 5;
const SAMPLE_ID: u64 = 1 << 6;
const SAMPLE_PERIOD: u64 = 1 << 8;
const SAMPLE_STREAM_ID: u64 = 1 << 9;
const SAMPLE_IDENTIFIER: u64 = 1 << 16;
const FORMAT_LOST: u64 = 1 << 4;

const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;
const IOC_REFRESH: u64 = 0x2402;
const IOC_ID: u64 = 0x8008_2407;
const IOC_PAUSE_OUTPUT: u64 = 0x4004_2409;
const RECORD_LOST: u32 = 2;
const RECORD_SAMPLE: u32 = 9;
const CONTEXT_USER: u64 = -512i64 as u64;

/// The guest's `struct attr`, `PERF_ATTR_SIZE_VER8`'s 136 bytes.
#[derive(Clone, Copy, Default)]
struct Attr {
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    sample_max_stack: u16,
    aux_action: u32,
    sig_data: u64,
}

impl Attr {
    /// The guest's `software`: a software event counting user time only.
    fn software(config: u64) -> Self {
        Self {
            config,
            flags: EXCLUDE_KERNEL | EXCLUDE_HV,
            ..Self::default()
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0; 136];
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        b[4..8].copy_from_slice(&136u32.to_le_bytes());
        for (at, v) in [
            (8, self.config),
            (16, self.sample_period),
            (24, self.sample_type),
            (32, self.read_format),
            (40, self.flags),
        ] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[48..52].copy_from_slice(&self.wakeup_events.to_le_bytes());
        b[108..110].copy_from_slice(&self.sample_max_stack.to_le_bytes());
        b[116..120].copy_from_slice(&self.aux_action.to_le_bytes());
        b[120..128].copy_from_slice(&self.sig_data.to_le_bytes());
        b
    }
}

/// A kernel whose thread runs the first process, as root, and the lines it
/// prints.
struct Env {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    lines: Vec<String>,
    /// What the guest's handlers saw: `on_io`'s and `on_trap`'s counts.
    caught: Caught,
}

/// The guest's `io_count`, `io_in`, `io_hup`, `io_alike`, `io_fd`,
/// `trap_count` and `trap_alike`.
#[derive(Default)]
struct Caught {
    io_count: u32,
    io_in: u32,
    io_hup: u32,
    io_alike: bool,
    io_fd: i64,
    trap_count: u32,
    trap_alike: bool,
}

impl Env {
    fn new() -> Self {
        let k = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + 0x10000)),
        );
        let m = AddressSpace::new();
        m.map_shared(
            Some(GuestAddr(DATA)),
            0x10000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        Self {
            k,
            t,
            m,
            lines: Vec::new(),
            caught: Caught::default(),
        }
    }

    /// A call's result, or `-errno`: the guest's `TRY`.
    fn call(&mut self, n: u64, a: [u64; 6]) -> i64 {
        let t = &mut self.t;
        t.cpu.gpr[reg::RAX] = n;
        t.cpu.gpr[reg::RDI] = a[0];
        t.cpu.gpr[reg::RSI] = a[1];
        t.cpu.gpr[reg::RDX] = a[2];
        t.cpu.gpr[reg::R10] = a[3];
        t.cpu.gpr[reg::R8] = a[4];
        t.cpu.gpr[reg::R9] = a[5];
        self.k
            .handle(t, &self.m, ExitReason::Syscall { rip: t.cpu.rip });
        self.handlers();
        self.t.cpu.gpr[reg::RAX] as i64
    }

    /// A signal the kernel returns to runs the guest's handler, which
    /// returns through the restorer's rt_sigreturn.
    fn handlers(&mut self) {
        while self.t.cpu.rip == GuestAddr(HANDLER) {
            let number = self.t.cpu.gpr[reg::RDI];
            let mut info = [0; 40];
            self.m
                .read(GuestAddr(self.t.cpu.gpr[reg::RSI]), &mut info)
                .unwrap();
            self.handler(number, &info);
            let t = &mut self.t;
            t.cpu.gpr[reg::RSP] += 8;
            t.cpu.gpr[reg::RAX] = RT_SIGRETURN;
            self.k
                .handle(t, &self.m, ExitReason::Syscall { rip: t.cpu.rip });
        }
    }

    /// A store of the guest's code at `at`, whose fault the kernel sees
    /// where an event samples it, as an instruction's that then runs again.
    /// How many faults it took so.
    fn store(&mut self, at: u64) -> u32 {
        for taken in 0.. {
            let Err(fault) = self.m.write(GuestAddr(at), &[1]) else {
                return taken;
            };
            assert!(taken < 3 && fault.mapped && fault.write, "{fault:?}");
            let gpr = self.t.cpu.gpr;
            let rip = self.t.cpu.rip;
            let reason = ExitReason::PageFault {
                rip,
                addr: fault.addr,
                write: true,
                fetch: false,
                mapped: true,
                present: fault.present,
            };
            self.k.handle(&mut self.t, &self.m, reason);
            self.handlers();
            assert_eq!((self.t.cpu.gpr, self.t.cpu.rip), (gpr, rip));
        }
        unreachable!()
    }

    /// The guest's `on_io` and `on_trap`.
    fn handler(&mut self, number: u64, info: &[u8; 40]) {
        let int = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
        let long = |at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap());
        let c = &mut self.caught;
        let code = int(8);
        if number == SIGRTMIN {
            c.io_count += 1;
            c.io_in += u32::from(code == POLL_IN);
            c.io_hup += u32::from(code == POLL_HUP);
            c.io_alike &= i64::from(int(24)) == c.io_fd
                && (code == POLL_HUP || long(16) == POLLIN | POLLRDNORM);
        } else {
            assert_eq!(number, SIGTRAP);
            c.trap_count += 1;
            c.trap_alike &= code == TRAP_PERF && long(24) == 0x1234 && int(32) == 1 && int(36) == 0;
        }
    }

    /// `sigaction` of the guest's handler for `number`, `SA_SIGINFO`.
    fn catch(&mut self, number: u64) {
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&HANDLER.to_le_bytes());
        act[8..16].copy_from_slice(&(SA_SIGINFO | SA_RESTORER).to_le_bytes());
        self.m.write(GuestAddr(ARG), &act).unwrap();
        assert_eq!(self.call(RT_SIGACTION, [number, ARG, 0, 8, 0, 0]), 0);
    }

    /// The guest's `polled`: what `poll` gives for `POLLIN`, at once.
    fn polled(&mut self, fd: i64) -> i64 {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(fd as i32).to_le_bytes());
        p[4..6].copy_from_slice(&1u16.to_le_bytes());
        self.m.write(GuestAddr(ARG), &p).unwrap();
        if self.call(POLL, [ARG, 1, 0, 0, 0, 0]) < 0 {
            return -1;
        }
        self.m.read(GuestAddr(ARG), &mut p).unwrap();
        i64::from(i16::from_le_bytes([p[6], p[7]]))
    }

    fn fcntl(&mut self, fd: i64, command: u64, arg: u64) -> i64 {
        self.call(FCNTL, [fd as u64, command, arg, 0, 0, 0])
    }

    /// The guest's `own_signals`: signal-driven I/O to this process with
    /// SIGRTMIN.
    fn own_signals(&mut self, fd: i64) {
        self.catch(SIGRTMIN);
        let pid = self.call(GETPID, [0; 6]) as u64;
        self.fcntl(fd, F_SETOWN, pid);
        self.fcntl(fd, F_SETSIG, SIGRTMIN);
        let flags = self.fcntl(fd, F_GETFL, 0) as u64;
        self.fcntl(fd, F_SETFL, flags | O_ASYNC);
        self.caught.io_fd = fd;
        self.caught.io_count = 0;
        self.caught.io_in = 0;
        self.caught.io_hup = 0;
        self.caught.io_alike = true;
    }

    fn say(&mut self, line: String) {
        self.lines.push(line);
    }

    fn long(&self, at: u64) -> u64 {
        self.m.read_u64(GuestAddr(at)).unwrap()
    }

    fn open(&mut self, attr: &Attr) -> i64 {
        self.m.write(GuestAddr(ATTR), &attr.bytes()).unwrap();
        self.call(PERF_EVENT_OPEN, [ATTR, 0, -1i64 as u64, -1i64 as u64, 0, 0])
    }

    /// The guest's `attempt`: an event opened and closed, or its error.
    fn attempt(&mut self, name: &str, attr: &Attr) {
        let fd = self.open(attr);
        if fd >= 0 {
            self.close(fd);
            self.say(format!("{name} fd"));
        } else {
            self.say(format!("{name} {fd}"));
        }
    }

    /// The guest's `open_sampling`: a disabled page-fault event sampling
    /// every fault, its read giving the lost samples.
    fn open_sampling(&mut self, sample_type: u64, flags: u64) -> i64 {
        let mut a = Attr::software(2);
        a.sample_period = 1;
        a.sample_type = sample_type;
        a.read_format = FORMAT_LOST;
        a.flags |= DISABLED | flags;
        self.open(&a)
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// The guest's `map_event`: the mapping's address, or `-errno`.
    fn map(&mut self, fd: i64, pages: u64, prot: u64) -> i64 {
        self.call(MMAP, [0, pages * 4096, prot, MAP_SHARED, fd as u64, 0])
    }

    fn unmap(&mut self, at: i64, pages: u64) {
        assert_eq!(self.call(MUNMAP, [at as u64, pages * 4096, 0, 0, 0, 0]), 0);
    }

    fn id(&mut self, fd: i64) -> u64 {
        assert_eq!(self.call(IOCTL, [fd as u64, IOC_ID, ARG, 0, 0, 0]), 0);
        self.long(ARG)
    }

    fn ioctl(&mut self, fd: i64, request: u64, arg: u64) -> i64 {
        self.call(IOCTL, [fd as u64, request, arg, 0, 0, 0])
    }

    /// The guest's `touch`: a private mapping of `pages`, each written once,
    /// which takes a fault each.
    fn touch(&mut self, pages: u64) {
        let p = self.call(
            MMAP,
            [
                0,
                pages * 4096,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE_ANONYMOUS,
                u64::MAX,
                0,
            ],
        );
        assert!(p > 0, "{p}");
        for i in 0..pages {
            self.store(p as u64 + i * 4096);
        }
    }

    /// The guest's `faults_while_enabled`.
    fn faults_while_enabled(&mut self, fd: i64, pages: u64) {
        self.ioctl(fd, IOC_ENABLE, 0);
        self.touch(pages);
        self.ioctl(fd, IOC_DISABLE, 0);
    }

    /// The guest's `lost_samples`: the second word of the event's read.
    fn lost_samples(&mut self, fd: i64) -> u64 {
        self.m.write(GuestAddr(ARG), &[0; 8]).unwrap();
        self.m
            .write(GuestAddr(ARG + 8), &u64::MAX.to_le_bytes())
            .unwrap();
        if self.call(READ, [fd as u64, ARG, 16, 0, 0, 0]) != 16 {
            return u64::MAX;
        }
        self.long(ARG + 8)
    }

    /// The guest's `copy_record`: `words` words of the data area of
    /// `size` bytes after the user page at `page`, from `at`.
    fn record(&self, page: i64, size: u64, at: u64, words: usize) -> Vec<u64> {
        let data = page as u64 + 4096;
        let bytes: Vec<u8> = (0..words as u64 * 8)
            .map(|i| {
                let mut b = [0];
                self.m
                    .read(GuestAddr(data + ((at + i) & (size - 1))), &mut b)
                    .unwrap();
                b[0]
            })
            .collect();
        bytes
            .chunks(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect()
    }

    fn head(&self, page: i64) -> u64 {
        self.long(page as u64 + 1024)
    }

    fn set_tail(&self, page: i64, tail: u64) {
        self.m
            .write(GuestAddr(page as u64 + 1032), &tail.to_le_bytes())
            .unwrap();
    }
}

/// Compares the lines a case printed with Linux's, printing them all when
/// one differs.
fn check(lines: &[String], expected: &[&str]) {
    if lines != expected {
        for line in lines {
            println!("{line}");
        }
    }
    assert_eq!(lines, expected);
}

/// perf-sample: each fault a sample of the fields asked for, a full
/// buffer's lost samples, pausing, overwriting, writing backward and a user
/// callchain, and the attributes Linux refuses.
#[test]
fn perf_sample_records_faults_loses_pauses_and_writes_backward() {
    let mut e = Env::new();
    let (pid, tid) = (1u64, 1u64);
    // Each fault is a sample of the fields asked for, in Linux's order.
    let fd = e.open_sampling(
        SAMPLE_IDENTIFIER | SAMPLE_TID | SAMPLE_PERIOD | SAMPLE_ID | SAMPLE_STREAM_ID,
        0,
    );
    let page = e.map(fd, 3, PROT_READ | PROT_WRITE);
    let mapped = page.min(0);
    let id = e.id(fd);
    e.say(format!("open {} mapped {mapped}", (fd >= 0) as i32));
    e.faults_while_enabled(fd, 5);
    let head = e.head(page);
    let (mut samples, mut alike) = (0, true);
    let mut at = 0;
    while at < head {
        let r = e.record(page, 8192, at, 6);
        let kind = r[0] as u32;
        let (misc, size) = ((r[0] >> 32) as u16, (r[0] >> 48) as u16);
        alike &= kind == RECORD_SAMPLE && misc == 2 && size == 48 && r[1] == id;
        alike &= r[2] & 0xffff_ffff == pid && r[2] >> 32 == tid;
        // PERF_SAMPLE_PERIOD comes after the IDs.
        alike &= r[3] == id && r[4] == id && r[5] == 1;
        samples += 1;
        at += 48;
    }
    e.say(format!(
        "samples>=5 {} alike {} whole {}",
        (samples >= 5) as i32,
        alike as i32,
        head.is_multiple_of(48) as i32
    ));
    let lost = e.lost_samples(fd);
    e.say(format!("lost {lost}"));
    e.unmap(page, 3);
    e.close(fd);
    // A full buffer loses samples, and the next record after room is made
    // tells how many, with its sample_id.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, SAMPLE_ID_ALL);
    let id = e.id(fd);
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    let mapped = page.min(0);
    e.faults_while_enabled(fd, 400);
    let head = e.head(page);
    let lost = e.lost_samples(fd);
    e.say(format!(
        "full: mapped {mapped} fits {} lost>0 {}",
        (head == 4080) as i32,
        (lost > 0 && lost != u64::MAX) as i32
    ));
    e.set_tail(page, head);
    e.faults_while_enabled(fd, 1);
    let r = e.record(page, 4096, head, 4);
    e.say(format!(
        "lost record {} size {} id {} count {}",
        (r[0] as u32 == RECORD_LOST) as i32,
        r[0] >> 48,
        (r[1] == id) as i32,
        (r[2] == lost) as i32
    ));
    e.say(format!("pid {}", (r[3] & 0xffff_ffff == pid) as i32));
    let r = e.record(page, 4096, head + 32, 1);
    e.say(format!(
        "then sample {}",
        (r[0] as u32 == RECORD_SAMPLE) as i32
    ));
    // Paused, it takes nothing and counts it lost.
    let head = e.head(page);
    e.set_tail(page, head);
    let paused = e.ioctl(fd, IOC_PAUSE_OUTPUT, 1);
    e.faults_while_enabled(fd, 3);
    let kept = e.head(page) == head;
    let more = e.lost_samples(fd) >= lost + 3;
    e.say(format!(
        "paused {paused} kept {} lost more {}",
        kept as i32, more as i32
    ));
    let resumed = e.ioctl(fd, IOC_PAUSE_OUTPUT, 0);
    e.faults_while_enabled(fd, 1);
    let r = e.record(page, 4096, head, 1);
    e.say(format!(
        "resumed {resumed} lost record {}",
        (r[0] as u32 == RECORD_LOST) as i32
    ));
    e.unmap(page, 2);
    let r = e.ioctl(fd, IOC_PAUSE_OUTPUT, 1);
    e.say(format!("pause unmapped {r}"));
    e.close(fd);
    // Read-only, the buffer overwrites what it holds and loses nothing.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    let page = e.map(fd, 2, PROT_READ);
    e.faults_while_enabled(fd, 400);
    let head = e.head(page);
    let lost = e.lost_samples(fd);
    e.say(format!(
        "overwrite past {} whole {} lost {lost}",
        (head > 4096) as i32,
        head.is_multiple_of(24) as i32
    ));
    e.unmap(page, 2);
    e.close(fd);
    // Backward, the head goes down from 0.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, WRITE_BACKWARD);
    let page = e.map(fd, 2, PROT_READ);
    e.faults_while_enabled(fd, 3);
    let head = e.head(page);
    let r = e.record(page, 4096, head, 1);
    e.say(format!(
        "backward below {} whole {} sample {}",
        ((head as i64) < 0) as i32,
        0u64.wrapping_sub(head).is_multiple_of(24) as i32,
        (r[0] as u32 == RECORD_SAMPLE) as i32
    ));
    e.unmap(page, 2);
    e.close(fd);
    // The callchain of user mode starts with its context.
    let fd = e.open_sampling(SAMPLE_CALLCHAIN, EXCLUDE_CALLCHAIN_KERNEL);
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    e.faults_while_enabled(fd, 1);
    let r = e.record(page, 4096, 0, 3);
    e.say(format!(
        "callchain sample {} context {} frames {}",
        (r[0] as u32 == RECORD_SAMPLE) as i32,
        (r[2] == CONTEXT_USER) as i32,
        (2..=128).contains(&r[1]) as i32
    ));
    e.unmap(page, 2);
    e.close(fd);
    let mut a = Attr::software(2);
    a.sample_period = 1;
    a.sample_type = SAMPLE_CALLCHAIN;
    a.flags |= EXCLUDE_CALLCHAIN_KERNEL;
    a.sample_max_stack = 128;
    e.attempt("max stack 128", &a);
    a.sample_max_stack = 127;
    e.attempt("max stack 127", &a);
    let mut a = Attr::software(2);
    a.aux_action = 7;
    e.attempt("aux start paused pause resume", &a);
    a.aux_action = 1;
    e.attempt("aux start paused", &a);
    check(
        &e.lines,
        &[
            "open 1 mapped 0",
            "samples>=5 1 alike 1 whole 1",
            "lost 0",
            "full: mapped 0 fits 1 lost>0 1",
            "lost record 1 size 32 id 1 count 1",
            "pid 1",
            "then sample 1",
            "paused 0 kept 1 lost more 1",
            "resumed 0 lost record 1",
            "pause unmapped -22",
            "overwrite past 1 whole 1 lost 0",
            "backward below 1 whole 1 sample 1",
            "callchain sample 1 context 1 frames 1",
            "max stack 128 -75",
            "max stack 127 fd",
            "aux start paused pause resume -22",
            "aux start paused -95",
        ],
    );
}

/// An event of a CPU counts and samples what any thread does there while it
/// is enabled, and nothing of another CPU.
#[test]
fn an_event_of_a_cpu_counts_and_samples_what_runs_there() {
    let mut e = Env::new();
    e.m.write(GuestAddr(ARG), &1u64.to_le_bytes()).unwrap();
    assert_eq!(e.call(203, [0, 8, ARG, 0, 0, 0]), 0);
    let mut fds = Vec::new();
    for cpu in 0..2 {
        let mut a = Attr::software(2);
        a.sample_period = 1;
        a.sample_type = SAMPLE_TID | 1 << 3;
        a.flags |= DISABLED;
        e.m.write(GuestAddr(ATTR), &a.bytes()).unwrap();
        let fd = e.call(PERF_EVENT_OPEN, [ATTR, u64::MAX, cpu, u64::MAX, 0, 0]);
        assert!(fd >= 0, "{fd}");
        let page = e.map(fd, 3, PROT_READ | PROT_WRITE);
        fds.push((fd, page));
    }
    // What the thread did before it was enabled is none of its.
    e.touch(4);
    let count = |e: &mut Env, fd: i64| {
        assert_eq!(e.call(READ, [fd as u64, ARG, 8, 0, 0, 0]), 8);
        e.long(ARG)
    };
    for &(fd, _) in &fds {
        e.ioctl(fd, IOC_ENABLE, 0);
    }
    e.touch(5);
    for &(fd, _) in &fds {
        e.ioctl(fd, IOC_DISABLE, 0);
    }
    e.touch(3);
    let counts: Vec<u64> = fds.iter().map(|&(fd, _)| count(&mut e, fd)).collect();
    assert_eq!(counts, [5, 0]);
    let samples = |e: &Env, page: i64| {
        (0..e.head(page) / 24)
            .map(|i| e.record(page, 8192, i * 24, 3))
            .collect::<Vec<_>>()
    };
    let (_, here) = fds[0];
    let seen = samples(&e, here);
    assert_eq!(seen.len(), 5);
    for (i, sample) in seen.iter().enumerate() {
        assert_eq!(sample[0] as u32, RECORD_SAMPLE);
        assert_eq!(sample[1], 1 | 1 << 32);
        assert_eq!(sample[2], seen[0][2] + i as u64 * 4096);
    }
    assert!(samples(&e, fds[1].1).is_empty());
    // Enabled again, it takes only what comes then; a reaped process's
    // counts stay the CPU's.
    e.ioctl(fds[0].0, IOC_ENABLE, 0);
    e.touch(2);
    e.ioctl(fds[0].0, IOC_DISABLE, 0);
    assert_eq!(count(&mut e, fds[0].0), 7);
    assert_eq!(samples(&e, here).len(), 7);
}

/// perf-wakeup up to its child: poll without a buffer and with one,
/// `wakeup_events` and `wakeup_watermark`, `O_ASYNC` signals of each
/// overflow, `PERF_EVENT_IOC_REFRESH`, and `sigtrap`'s `SIGTRAP`, taken
/// and blocked. The child whose event hangs up when it ends stays with the
/// differential tests.
#[test]
fn perf_wakeup_polls_signals_refreshes_and_traps() {
    let mut e = Env::new();
    // Without a buffer, poll finds the event hung up.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    let r = e.polled(fd);
    e.say(format!("no buffer {r}"));
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    let r = e.polled(fd);
    e.say(format!("empty {r}"));
    e.unmap(page, 2);
    e.close(fd);
    // Each wakeup_events-th sample makes it readable once.
    let mut a = Attr::software(2);
    a.sample_period = 1;
    a.sample_type = SAMPLE_TID | SAMPLE_PERIOD;
    a.flags |= DISABLED;
    a.wakeup_events = 1;
    let fd = e.open(&a);
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    e.faults_while_enabled(fd, 1);
    let (first, second) = (e.polled(fd), e.polled(fd));
    e.say(format!("wakeup events: readable {first} then {second}"));
    e.unmap(page, 2);
    e.close(fd);
    // With watermark, once wakeup_watermark bytes are written.
    a.flags |= WATERMARK;
    a.wakeup_events = 4 * 24;
    let fd = e.open(&a);
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    e.faults_while_enabled(fd, 6);
    let first = e.polled(fd);
    let past = e.head(page) > 96;
    e.say(format!(
        "watermark: readable {first} head>96 {}",
        past as i32
    ));
    e.unmap(page, 2);
    e.close(fd);
    // O_ASYNC signals each overflow, with or without a buffer.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    e.own_signals(fd);
    e.faults_while_enabled(fd, 3);
    let c = &e.caught;
    let line = format!(
        "signals>=3 {} in {} alike {} hup {}",
        (c.io_count >= 3) as i32,
        (c.io_in == c.io_count) as i32,
        c.io_alike as i32,
        c.io_hup
    );
    e.say(line);
    let flags = e.fcntl(fd, F_GETFL, 0) as u64;
    e.fcntl(fd, F_SETFL, flags & !O_ASYNC);
    e.caught.io_count = 0;
    e.faults_while_enabled(fd, 2);
    let line = format!("off {}", e.caught.io_count);
    e.say(line);
    e.close(fd);
    // REFRESH allows that many overflows, the last hanging up.
    let fd = e.open_sampling(SAMPLE_TID | SAMPLE_PERIOD, 0);
    let page = e.map(fd, 2, PROT_READ | PROT_WRITE);
    e.own_signals(fd);
    let refreshed = e.ioctl(fd, IOC_REFRESH, 2);
    e.touch(5);
    e.ioctl(fd, IOC_ID, ARG);
    let records = e.head(page) / 24;
    let c = &e.caught;
    let line = format!(
        "refresh {refreshed}: signals {} in {} hup {} records {records}",
        c.io_count, c.io_in, c.io_hup
    );
    e.say(line);
    e.touch(2);
    e.ioctl(fd, IOC_ID, ARG);
    let line = format!("after: signals {}", e.caught.io_count);
    e.say(line);
    let counting = e.open(&Attr::software(2));
    let r = e.ioctl(counting, IOC_REFRESH, 1);
    e.say(format!("refresh counting {r}"));
    let mut inherited = Attr::software(2);
    inherited.sample_period = 1;
    inherited.flags |= INHERIT;
    let inherited = e.open(&inherited);
    let r = e.ioctl(inherited, IOC_REFRESH, 1);
    e.say(format!("refresh inherit {r}"));
    e.unmap(page, 2);
    e.close(fd);
    // sigtrap: SIGTRAP of TRAP_PERF with sig_data and the type.
    e.catch(SIGTRAP);
    let mut a = Attr::software(2);
    a.sample_period = 1;
    a.flags |= DISABLED | ATTR_SIGTRAP | REMOVE_ON_EXEC;
    a.sig_data = 0x1234;
    let fd = e.open(&a);
    e.caught.trap_alike = true;
    e.faults_while_enabled(fd, 2);
    let c = &e.caught;
    let line = format!(
        "sigtrap>=1 {} alike {}",
        (c.trap_count >= 1) as i32,
        c.trap_alike as i32
    );
    e.say(line);
    // Blocked, it waits, flagged as late.
    let (set, old, info, none) = (ARG + 0x40, ARG + 0x48, ARG + 0x80, ARG + 0x50);
    e.m.write(GuestAddr(set), &(1u64 << (SIGTRAP - 1)).to_le_bytes())
        .unwrap();
    e.m.write(GuestAddr(none), &[0; 16]).unwrap();
    assert_eq!(e.call(RT_SIGPROCMASK, [SIG_BLOCK, set, old, 8, 0, 0]), 0);
    e.faults_while_enabled(fd, 1);
    let got = e.call(RT_SIGTIMEDWAIT, [set, info, none, 8, 0, 0]);
    let code = e.long(info + 8) as u32;
    let late = (e.long(info + 32) >> 32) as u32;
    e.say(format!("blocked {got} code {code} async {late}"));
    assert_eq!(e.call(RT_SIGPROCMASK, [SIG_SETMASK, old, 0, 8, 0, 0]), 0);
    e.close(fd);
    check(
        &e.lines,
        &[
            "no buffer 16",
            "empty 0",
            "wakeup events: readable 1 then 0",
            "watermark: readable 1 head>96 1",
            "signals>=3 1 in 1 alike 1 hup 0",
            "off 0",
            "refresh 0: signals 2 in 1 hup 1 records 2",
            "after: signals 2",
            "refresh counting -22",
            "refresh inherit -22",
            "sigtrap>=1 1 alike 1",
            "blocked 5 code 6 async 1",
        ],
    );
}
