//! Samples of a software event through the system call interface: the
//! page faults a thread takes while a sampling event is enabled, each a
//! `PERF_RECORD_SAMPLE` of the fields `sample_type` asks for in Linux's
//! order, a full buffer's lost samples and the `PERF_RECORD_LOST` after
//! them, `PERF_EVENT_IOC_PAUSE_OUTPUT`, a read-only buffer that overwrites,
//! a backward one, and a user callchain. The expected values are Linux's
//! (`kernel/events/core.c`, `ring_buffer.c`): they are the lines of the
//! perf-sample case of `tests/guests/processes/perf.c`, which the
//! differential tests compare with Linux. The guest's writes to fresh pages
//! are this test's writes to them, which the next system call counts as
//! the thread's faults, as the guest's do.
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

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;

const DISABLED: u64 = 1 << 0;
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
    sample_max_stack: u16,
    aux_action: u32,
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
        b[108..110].copy_from_slice(&self.sample_max_stack.to_le_bytes());
        b[116..120].copy_from_slice(&self.aux_action.to_le_bytes());
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
        t.cpu.gpr[reg::RAX] as i64
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
            self.m.write(GuestAddr(p as u64 + i * 4096), &[1]).unwrap();
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
