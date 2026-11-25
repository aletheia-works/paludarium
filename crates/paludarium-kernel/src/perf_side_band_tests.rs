//! Side-band records through the system call interface: the `MMAP`,
//! `MMAP2`, `COMM`, `FORK` and `EXIT` records Linux's
//! `kernel/events/core.c` writes to the buffers of the events that ask for
//! them, for `mmap`, `mprotect`, `brk`, `shmat`, `PR_SET_NAME`, writes to
//! `comm`, and a child's `fork` and exit. The expected values are the lines
//! of the perf-side-band and perf-side-band-comm cases of
//! `tests/guests/processes/perf.c`, which the differential tests compare
//! with Linux. The tests make the guest's calls in its order and check its
//! records as it does, but for what musl's `fopen` maps (see
//! `maps_identity`). perf-side-band-exec, which needs an `execve`, stays
//! with the differential tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
const SIZE: u64 = 0x10000;
/// A `struct perf_event_attr`, a path, and what a call reads or writes.
const ATTR: u64 = DATA;
const PATH: u64 = DATA + 0x200;
const ARG: u64 = DATA + 0x400;
const BUF: u64 = DATA + 0x1000;
/// The zeros the guest writes to its file.
const ZEROS: u64 = DATA + 0x4000;
/// Where the process's break starts.
const BREAK: u64 = 0x80_0000;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const FSTAT: u64 = 5;
const MMAP: u64 = 9;
const MPROTECT: u64 = 10;
const BRK: u64 = 12;
const IOCTL: u64 = 16;
const SHMGET: u64 = 29;
const SHMAT: u64 = 30;
const SHMCTL: u64 = 31;
const FORK: u64 = 57;
const CLONE: u64 = 56;
const WAIT4: u64 = 61;
const SHMDT: u64 = 67;
const UNLINK: u64 = 87;
const PRCTL: u64 = 157;
const GETTID: u64 = 186;
const SCHED_SETAFFINITY: u64 = 203;
const PERF_EVENT_OPEN: u64 = 298;
const GETPID: u64 = 39;

const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_ANONYMOUS: u64 = 0x20;
const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_RMID: u64 = 0;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const EINVAL: i64 = 22;

const EXCLUDE_KERNEL: u64 = 1 << 5;
const EXCLUDE_HV: u64 = 1 << 6;
const DISABLED: u64 = 1 << 0;
const INHERIT: u64 = 1 << 1;
const SAMPLE_ID_ALL: u64 = 1 << 18;
const ATTR_MMAP: u64 = 1 << 8;
const ATTR_COMM: u64 = 1 << 9;
const ATTR_TASK: u64 = 1 << 13;
const ATTR_MMAP_DATA: u64 = 1 << 17;
const ATTR_MMAP2: u64 = 1 << 23;
const SAMPLE_TID: u64 = 1 << 1;

const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;

const RECORD_MMAP: u32 = 1;
const RECORD_COMM: u32 = 3;
const RECORD_EXIT: u32 = 4;
const RECORD_FORK: u32 = 7;
const RECORD_MMAP2: u32 = 10;
const MISC_DATA: u64 = 1 << 13;

/// The guest's `open_side_band`'s attributes: a dummy software event of
/// user time that takes the side-band records of `flags`, with the
/// thread's IDs after each (`sample_id_all`).
fn side_band_attr(flags: u64) -> Vec<u8> {
    let mut b = vec![0; 136];
    b[0..4].copy_from_slice(&1u32.to_le_bytes());
    b[4..8].copy_from_slice(&136u32.to_le_bytes());
    // `PERF_COUNT_SW_DUMMY`.
    b[8..16].copy_from_slice(&9u64.to_le_bytes());
    b[24..32].copy_from_slice(&SAMPLE_TID.to_le_bytes());
    let flags = EXCLUDE_KERNEL | EXCLUDE_HV | DISABLED | SAMPLE_ID_ALL | flags;
    b[40..48].copy_from_slice(&flags.to_le_bytes());
    b
}

/// What the guest's `say_record` compares the records with (its `struct
/// expected`).
#[derive(Default)]
struct Expected {
    pid: u32,
    tid: u32,
    child: u32,
    parent: u32,
    anon: u64,
    anon_len: u64,
    exec_at: u64,
    heap: u64,
    shared: u64,
    path: Vec<u8>,
    st_dev: u64,
    st_ino: u64,
    shared_major: u32,
    shared_minor: u32,
    shared_inode: u64,
    ring: u64,
    ring_major: u32,
    ring_minor: u32,
    ring_inode: u64,
    mmap_records: u32,
}

/// A process's thread, as root, and the lines it prints.
struct Env {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
    lines: Vec<String>,
}

impl Env {
    fn new() -> Self {
        let k = Box::new(Kernel::new(Arc::new(
            paludarium_host::testing::RecordingHost::new(),
        )));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + SIZE)),
        );
        let mut m = AddressSpace::new();
        m.set_initial_break(GuestAddr(BREAK));
        let m = Arc::new(m);
        m.map_shared(
            Some(GuestAddr(DATA)),
            SIZE,
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

    /// A call's result, or `-errno`.
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

    fn put(&self, at: u64, bytes: &[u8]) {
        self.m.write(GuestAddr(at), bytes).unwrap();
    }

    fn get(&self, at: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.m.read(GuestAddr(at), &mut bytes).unwrap();
        bytes
    }

    fn long(&self, at: u64) -> u64 {
        self.m.read_u64(GuestAddr(at)).unwrap()
    }

    fn path(&self, path: &[u8]) -> u64 {
        let mut bytes = path.to_vec();
        bytes.push(0);
        self.put(PATH, &bytes);
        PATH
    }

    fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> i64 {
        let at = self.path(path);
        self.call(OPEN, [at, flags, mode, 0, 0, 0])
    }

    /// `write` of `text` to `fd`.
    fn write(&mut self, fd: i64, text: &[u8]) -> i64 {
        self.put(BUF, text);
        self.call(WRITE, [fd as u64, BUF, text.len() as u64, 0, 0, 0])
    }

    fn ioctl(&mut self, fd: i64, request: u64) -> i64 {
        self.call(IOCTL, [fd as u64, request, 0, 0, 0, 0])
    }

    /// The guest's pinning to CPU 0.
    fn pin(&mut self) {
        self.put(ARG, &1u64.to_le_bytes());
        assert_eq!(self.call(SCHED_SETAFFINITY, [0, 8, ARG, 0, 0, 0]), 0);
    }

    /// The guest's `open_side_band`: the event of `pid` on `cpu` and its
    /// buffer of 8 data pages, or `None`.
    fn open_side_band(&mut self, pid: i64, cpu: i64, flags: u64) -> Option<(i64, u64)> {
        self.put(ATTR, &side_band_attr(flags));
        let fd = self.call(
            PERF_EVENT_OPEN,
            [ATTR, pid as u64, cpu as u64, u64::MAX, 0, 0],
        );
        if fd < 0 {
            return None;
        }
        let page = self.call(
            MMAP,
            [
                0,
                9 * 4096,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd as u64,
                0,
            ],
        );
        (page >= 0).then_some((fd, page as u64))
    }

    fn mmap(&mut self, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> u64 {
        let at = self.call(MMAP, [0, len, prot, flags, fd as u64, offset]);
        assert!(at > 0, "{at}");
        at as u64
    }

    /// The guest's `maps_identity`: the device and inode of the mapping at
    /// `at` in `/proc/self/maps`, and (its `maps_names`) its name.
    fn maps_identity(&mut self, at: u64) -> Option<(u32, u32, u64, String)> {
        let fd = self.open(b"/proc/self/maps", 0, 0);
        assert!(fd >= 0, "{fd}");
        let mut text = Vec::new();
        loop {
            let n = self.call(READ, [fd as u64, BUF, 4096, 0, 0, 0]);
            if n <= 0 {
                break;
            }
            text.extend_from_slice(&self.get(BUF, n as usize));
        }
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
        String::from_utf8(text).unwrap().lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let start = u64::from_str_radix(range.split('-').next()?, 16).ok()?;
            let (_, _, device, inode) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            let (major, minor) = device.split_once(':')?;
            (start == at).then_some((
                u32::from_str_radix(major, 16).ok()?,
                u32::from_str_radix(minor, 16).ok()?,
                inode.parse().ok()?,
                fields.collect::<Vec<_>>().join(" "),
            ))
        })
    }

    /// The guest's `fork` of a child that only exits: its number.
    fn fork_and_exit(&mut self, code: i32) -> i64 {
        let pid = self.call(FORK, [0; 6]);
        let (mut k, mut t) = self.k.take_child().unwrap();
        assert_eq!(pid, i64::from(t.tid));
        let m = k.take_spawn_memory().unwrap();
        let _ = &mut t;
        k.finish_thread(&t, &m);
        k.complete_process(ExitStatus::Exited(code));
        pid
    }

    /// `waitpid` of `pid`: its status.
    fn wait(&mut self, pid: i64) -> u32 {
        assert_eq!(self.call(WAIT4, [pid as u64, ARG, 0, 0, 0, 0]), pid);
        u32::from_le_bytes(self.get(ARG, 4).try_into().unwrap())
    }

    /// The guest's `copy_record`: `words` words of the 8 data pages after
    /// the user page at `page`, from `at`.
    fn record(&self, page: u64, at: u64, words: u64) -> Vec<u64> {
        let size = 8 * 4096;
        (0..words)
            .map(|w| {
                let bytes: Vec<u8> = (0..8)
                    .map(|i| self.get(page + 4096 + ((at + w * 8 + i) & (size - 1)), 1)[0])
                    .collect();
                u64::from_le_bytes(bytes.try_into().unwrap())
            })
            .collect()
    }

    /// The guest's `each_record`: the records from the start of the
    /// buffer, each passed to `seen`.
    fn each_record(&mut self, page: u64, mut seen: impl FnMut(&mut Self, &[u64])) {
        let head = self.long(page + 1024);
        let mut tail = 0;
        while tail < head {
            let size = self.record(page, tail, 1)[0] >> 48;
            if !(8..=4096).contains(&size) {
                break;
            }
            let record = self.record(page, tail, size / 8);
            seen(self, &record);
            tail += size;
        }
        self.put(page + 1032, &tail.to_le_bytes());
    }
}

/// The two `u32`s of a record's word.
fn halves(word: u64) -> [u32; 2] {
    [word as u32, (word >> 32) as u32]
}

/// The NUL-terminated name from word `at` of `record`.
fn name_at(record: &[u64], at: usize) -> Vec<u8> {
    let bytes: Vec<u8> = record[at..].iter().flat_map(|w| w.to_le_bytes()).collect();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end].to_vec()
}

/// The guest's `say_record`.
fn say_record(env: &mut Env, e: &mut Expected, record: &[u64]) {
    let kind = record[0] as u32;
    let misc = (record[0] >> 32) & 0xffff;
    let ids = halves(record[1]);
    let ours = |ids: [u32; 2]| (ids[0] == e.pid && ids[1] == e.tid) as i32;
    if kind == RECORD_MMAP || kind == RECORD_MMAP2 {
        let mmap2 = kind == RECORD_MMAP2;
        let (start, len, pgoff) = (record[2], record[3], record[4]);
        let name = name_at(record, if mmap2 { 9 } else { 5 });
        let what = if !e.path.is_empty() && name == e.path {
            "file".to_string()
        } else if name == b"//anon" {
            "anon".to_string()
        } else if name == b"/dev/zero (deleted)"
            || name.starts_with(b"/SYSV")
            || name == b"anon_inode:[perf_event]"
            || name.starts_with(b"[")
        {
            String::from_utf8(name).unwrap()
        } else {
            "other".to_string()
        };
        env.say(format!(
            "{} {what} data {} ids {}",
            if mmap2 { "mmap2" } else { "mmap" },
            (misc & MISC_DATA != 0) as i32,
            ours(ids)
        ));
        if start <= e.anon && start + len > e.anon {
            env.say(format!(
                "  anon covers {} offset is address {} len {}",
                (start + len >= e.anon + e.anon_len) as i32,
                (pgoff == start) as i32,
                (len == 4096 || len >= e.anon_len) as i32
            ));
        }
        if start == e.exec_at {
            env.say(format!("  exec offset {pgoff} len {len}"));
        }
        if e.heap != 0 && start <= e.heap && start + len > e.heap {
            env.say("  heap covers the new break".to_string());
        }
        if mmap2 {
            let [major, minor] = halves(record[5]);
            let inode = record[6];
            let [prot, flags] = halves(record[8]);
            env.say(format!("  prot {prot} flags {flags}"));
            if start == e.exec_at {
                let (dev_major, dev_minor) = paludarium_types::device_numbers(e.st_dev);
                env.say(format!(
                    "  device {} inode {}",
                    (major == dev_major && minor == dev_minor) as i32,
                    (inode == e.st_ino) as i32
                ));
            }
            if e.shared != 0 && start == e.shared {
                env.say(format!(
                    "  shared device {} inode {}",
                    (major == e.shared_major && minor == e.shared_minor) as i32,
                    (inode == e.shared_inode) as i32
                ));
            }
            if e.ring != 0 && start == e.ring {
                env.say(format!(
                    "  ring offset {pgoff} len {len} device {} inode {}",
                    (major == e.ring_major && minor == e.ring_minor) as i32,
                    (inode == e.ring_inode) as i32
                ));
            }
        }
        e.mmap_records += 1;
    } else if kind == RECORD_COMM {
        let name = String::from_utf8(name_at(record, 2)).unwrap();
        env.say(format!(
            "comm exec {} ids {} name {name}",
            (misc & MISC_DATA != 0) as i32,
            ours(ids)
        ));
    } else if kind == RECORD_FORK || kind == RECORD_EXIT {
        let parent = halves(record[2]);
        let trailer = halves(record[4]);
        let fork = kind == RECORD_FORK;
        env.say(format!(
            "{} child {} parent {} by {}",
            if fork { "fork" } else { "exit" },
            (ids[0] == e.child && parent[0] == e.child) as i32,
            if fork {
                ids[1] == e.pid && parent[1] == e.tid
            } else {
                ids[1] == e.parent && parent[1] == e.parent
            } as i32,
            if trailer[1] == e.child {
                "child"
            } else if trailer[1] == e.tid {
                "parent"
            } else {
                "other"
            }
        ));
    } else {
        env.say(format!("record {kind}"));
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

/// perf-side-band: the records of an inherited event of CPU 0 that asks
/// for all of them, and of one that asks for `MMAP` only, of each kind of
/// mapping, `mprotect`, `brk`, `shmat`, `PR_SET_NAME` and a child.
#[test]
fn perf_side_band_records_mappings_names_and_a_child() {
    let mut env = Env::new();
    let mut e = Expected {
        pid: env.call(GETPID, [0; 6]) as u32,
        tid: env.call(GETTID, [0; 6]) as u32,
        ..Expected::default()
    };
    e.parent = e.pid;
    let path = b"/tmp/perf-side-band-0".to_vec();
    let file = env.open(&path, O_RDWR | O_CREAT | O_EXCL, 0o600);
    assert!(file >= 0, "{file}");
    env.put(ZEROS, &[0; 2 * 4096]);
    assert_eq!(
        env.call(WRITE, [file as u64, ZEROS, 2 * 4096, 0, 0, 0]),
        2 * 4096
    );
    assert_eq!(env.call(FSTAT, [file as u64, ARG, 0, 0, 0, 0]), 0);
    e.st_dev = env.long(ARG);
    e.st_ino = env.long(ARG + 8);
    e.path = path.clone();
    env.pin();
    let all = env.open_side_band(
        0,
        0,
        ATTR_MMAP2 | ATTR_MMAP_DATA | ATTR_COMM | ATTR_TASK | INHERIT,
    );
    let exec_only = env.open_side_band(0, -1, ATTR_MMAP);
    env.say(format!(
        "open {} {}",
        all.is_some() as i32,
        exec_only.is_some() as i32
    ));
    let ((fd, all), (exec_fd, exec_only)) = (all.unwrap(), exec_only.unwrap());
    let id = env.call(SHMGET, [IPC_PRIVATE, 8192, IPC_CREAT | 0o600, 0, 0, 0]);
    assert!(id >= 0, "{id}");
    // musl's allocator has grown the heap by the time the guest grows it
    // (its `fopen` in `maps_identity`), so that the break is above the
    // heap's start.
    assert_eq!(
        env.call(BRK, [BREAK + 4096, 0, 0, 0, 0, 0]) as u64,
        BREAK + 4096
    );
    let old_break = env.call(BRK, [0; 6]) as u64;
    env.ioctl(fd, IOC_ENABLE);
    env.ioctl(exec_fd, IOC_ENABLE);
    e.anon_len = 3 * 4096;
    e.anon = env.mmap(
        e.anon_len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    e.exec_at = env.mmap(4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, file, 4096);
    e.shared = env.mmap(
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    // The guest reads /proc/self/maps with `fopen`, whose allocation makes
    // the three MMAP2 records it prints here (two of anonymous memory and
    // one of the heap); this reads it with `read` into its own memory.
    let identity = env.maps_identity(e.shared);
    if let Some((major, minor, inode, _)) = identity {
        (e.shared_major, e.shared_minor, e.shared_inode) = (major, minor, inode);
    }
    env.say(format!("shared in maps {}", identity.is_some() as i32));
    for _ in 0..2 {
        assert_eq!(env.call(MPROTECT, [e.anon, 4096, PROT_READ, 0, 0, 0]), 0);
    }
    let new_break = old_break + 3 * 4096;
    if env.call(BRK, [new_break, 0, 0, 0, 0, 0]) as u64 == new_break {
        e.heap = new_break - 1;
    }
    let shm = env.call(SHMAT, [id as u64, 0, 0, 0, 0, 0]);
    assert!(shm > 0, "{shm}");
    let name = env.path(b"side-band");
    assert_eq!(env.call(PRCTL, [PR_SET_NAME, name, 0, 0, 0, 0]), 0);
    let child = env.fork_and_exit(0);
    env.wait(child);
    e.child = child as u32;
    // Another event's ring buffer, a shared mapping of its file.
    env.put(ATTR, &side_band_attr(0));
    let ring = env.call(PERF_EVENT_OPEN, [ATTR, 0, u64::MAX, u64::MAX, 0, 0]);
    assert!(ring >= 0, "{ring}");
    e.ring = env.mmap(2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ring, 0);
    env.ioctl(fd, IOC_DISABLE);
    env.ioctl(exec_fd, IOC_DISABLE);
    // Its line in /proc/self/maps: the anonymous inode `fstat` gives.
    let identity = env.maps_identity(e.ring);
    let found = identity.is_some() as i32;
    assert_eq!(env.call(FSTAT, [ring as u64, ARG, 0, 0, 0, 0]), 0);
    let (dev_major, dev_minor) = paludarium_types::device_numbers(env.long(ARG));
    let ring_ino = env.long(ARG + 8);
    let (as_fstat, named) = match identity {
        Some((major, minor, inode, name)) => {
            (e.ring_major, e.ring_minor, e.ring_inode) = (major, minor, inode);
            (
                (major, minor, inode) == (dev_major, dev_minor, ring_ino),
                name == "anon_inode:[perf_event]",
            )
        }
        None => (false, false),
    };
    env.say(format!(
        "ring in maps {found} as fstat {} named {}",
        as_fstat as i32, named as i32
    ));
    assert_eq!(env.call(SHMDT, [shm as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(env.call(SHMCTL, [id as u64, IPC_RMID, 0, 0, 0, 0]), 0);
    let at = env.path(&path);
    assert_eq!(env.call(UNLINK, [at, 0, 0, 0, 0, 0]), 0);
    env.say("all:".to_string());
    env.each_record(all, |env, record| say_record(env, &mut e, record));
    env.say("exec only:".to_string());
    e.mmap_records = 0;
    env.each_record(exec_only, |env, record| say_record(env, &mut e, record));
    let records = e.mmap_records;
    env.say(format!("exec only records {records}"));
    check(
        &env.lines,
        &[
            "open 1 1",
            "shared in maps 1",
            "ring in maps 1 as fstat 1 named 1",
            "all:",
            "mmap2 anon data 1 ids 1",
            "  anon covers 1 offset is address 1 len 1",
            "  prot 3 flags 2",
            "mmap2 file data 0 ids 1",
            "  exec offset 4096 len 4096",
            "  prot 5 flags 2",
            "  device 1 inode 1",
            "mmap2 /dev/zero (deleted) data 1 ids 1",
            "  prot 3 flags 1",
            "  shared device 1 inode 1",
            "mmap2 anon data 1 ids 1",
            "  anon covers 0 offset is address 1 len 1",
            "  prot 1 flags 2",
            "mmap2 [heap] data 1 ids 1",
            "  heap covers the new break",
            "  prot 3 flags 2",
            "mmap2 /SYSV00000000 (deleted) data 1 ids 1",
            "  prot 3 flags 1",
            "comm exec 0 ids 1 name side-band",
            "fork child 1 parent 1 by parent",
            "exit child 1 parent 1 by child",
            "mmap2 anon_inode:[perf_event] data 1 ids 1",
            "  prot 3 flags 1",
            "  ring offset 0 len 8192 device 1 inode 1",
            "exec only:",
            "mmap file data 0 ids 1",
            "  exec offset 4096 len 4096",
            "fork child 1 parent 1 by parent",
            "exec only records 1",
        ],
    );
}

/// perf-side-band-cpu: an event of a CPU takes the records of what runs
/// there, and one of another CPU or not enabled takes none.
#[test]
fn an_event_of_a_cpu_takes_the_records_of_what_runs_there() {
    let mut env = Env::new();
    let mut e = Expected {
        pid: env.call(GETPID, [0; 6]) as u32,
        tid: env.call(GETTID, [0; 6]) as u32,
        ..Expected::default()
    };
    e.parent = e.pid;
    env.pin();
    let flags = ATTR_MMAP2 | ATTR_COMM | ATTR_TASK;
    let (fd, here) = env.open_side_band(-1, 0, flags).unwrap();
    let (other_fd, other) = env.open_side_band(-1, 1, flags).unwrap();
    let (_, off) = env.open_side_band(-1, 0, flags).unwrap();
    env.ioctl(fd, IOC_ENABLE);
    env.ioctl(other_fd, IOC_ENABLE);
    // `mmap2` alone has no mapping recorded, but with an event with `mmap`
    // open, enabled or not.
    let anonymous = MAP_PRIVATE | MAP_ANONYMOUS;
    env.mmap(4096, PROT_READ | PROT_EXEC, anonymous, -1, 0);
    let (counted, unused) = env.open_side_band(0, -1, ATTR_MMAP).unwrap();
    env.mmap(3 * 4096, PROT_READ | PROT_EXEC, anonymous, -1, 0);
    assert_eq!(env.call(11, [unused, 9 * 4096, 0, 0, 0, 0]), 0);
    assert_eq!(env.call(CLOSE, [counted as u64, 0, 0, 0, 0, 0]), 0);
    env.mmap(4096, PROT_READ | PROT_EXEC, anonymous, -1, 0);
    let name = env.path(b"side-band-cpu");
    assert_eq!(env.call(PRCTL, [PR_SET_NAME, name, 0, 0, 0, 0]), 0);
    let child = env.fork_and_exit(0);
    env.wait(child);
    e.child = child as u32;
    env.ioctl(fd, IOC_DISABLE);
    for page in [here, other, off] {
        env.say("buffer:".to_string());
        env.each_record(page, |env, record| say_record(env, &mut e, record));
    }
    check(
        &env.lines,
        &[
            "buffer:",
            "mmap2 anon data 0 ids 1",
            "  prot 5 flags 2",
            "comm exec 0 ids 1 name side-band-cpu",
            "fork child 1 parent 1 by parent",
            "exit child 1 parent 1 by child",
            "buffer:",
            "buffer:",
        ],
    );
}

/// `mprotect` writes a record of each VMA it changes, as merged so far:
/// with those before it, and with the next if that has the protection
/// already.
#[test]
fn mprotect_writes_a_record_of_each_vma_it_changes() {
    let mut env = Env::new();
    env.pin();
    // Three pages that merge with nothing around them.
    let anonymous = MAP_PRIVATE | MAP_ANONYMOUS;
    let three = env.mmap(5 * 4096, 0, anonymous, -1, 0) + 4096;
    let protect = |env: &mut Env, page: u64, pages: u64, prot: u64| {
        let call = [three + page * 4096, pages * 4096, prot, 0, 0, 0];
        assert_eq!(env.call(MPROTECT, call), 0);
    };
    protect(&mut env, 0, 3, PROT_READ | PROT_WRITE);
    let (fd, page) = env
        .open_side_band(0, 0, ATTR_MMAP2 | ATTR_MMAP_DATA)
        .unwrap();
    env.ioctl(fd, IOC_ENABLE);
    protect(&mut env, 1, 1, PROT_READ);
    protect(&mut env, 0, 3, PROT_READ);
    protect(&mut env, 0, 3, PROT_READ);
    protect(&mut env, 0, 1, PROT_READ | PROT_EXEC);
    protect(&mut env, 0, 3, PROT_READ | PROT_WRITE);
    let mut seen = Vec::new();
    env.each_record(page, |_, record| {
        let from = (record[2] - three) / 4096;
        seen.push((from, record[3] / 4096, halves(record[8])[0]));
    });
    let expected = [
        (1, 1, 1),
        (0, 2, 1),
        (0, 3, 1),
        (0, 1, 5),
        (0, 1, 3),
        (0, 3, 3),
    ];
    assert_eq!(seen, expected);
}

/// A COMM record of each write to `comm`, as the guest's `say_comm` gives
/// it.
fn say_comm(env: &mut Env, (pid, tid): (u32, u32), record: &[u64]) {
    let kind = record[0] as u32;
    if kind != RECORD_COMM {
        env.say(format!("record {kind}"));
        return;
    }
    let misc = (record[0] >> 32) & 0xffff;
    let size = (record[0] >> 48) as usize;
    let renamed = halves(record[1]);
    let writer = halves(record[size / 8 - 1]);
    let name = String::from_utf8(name_at(record, 2)).unwrap();
    env.say(format!(
        "comm exec {} leader {} name {name} by {}",
        (misc & MISC_DATA != 0) as i32,
        (renamed[0] == pid && renamed[1] == tid) as i32,
        if writer[0] != pid {
            "other"
        } else if writer[1] == tid {
            "leader"
        } else {
            "thread"
        }
    ));
}

/// perf-side-band-comm: a write to the leader's `comm`, by itself or by
/// another of its threads, is a COMM record to an inherited event of CPU 0
/// and to one of the leader, and another process may not rename it.
#[test]
fn perf_side_band_comm_records_writes_to_comm() {
    let mut env = Env::new();
    let ids = (
        env.call(GETPID, [0; 6]) as u32,
        env.call(GETTID, [0; 6]) as u32,
    );
    env.pin();
    let all = env.open_side_band(0, 0, ATTR_COMM | INHERIT);
    let leader = env.open_side_band(0, -1, ATTR_COMM);
    env.say(format!(
        "open {} {}",
        all.is_some() as i32,
        leader.is_some() as i32
    ));
    let ((fd, all), (leader_fd, leader)) = (all.unwrap(), leader.unwrap());
    env.ioctl(fd, IOC_ENABLE);
    env.ioctl(leader_fd, IOC_ENABLE);
    let own = env.open(b"/proc/self/comm", O_WRONLY, 0);
    let wrote = env.write(own, b"by-proc");
    env.say(format!("leader write {wrote}"));
    assert_eq!(env.call(CLOSE, [own as u64, 0, 0, 0, 0, 0]), 0);
    // The guest's `pthread_create` of `rename_leader`: CLONE_VM, CLONE_FS,
    // CLONE_FILES, CLONE_SIGHAND, CLONE_THREAD and CLONE_SYSVSEM.
    let tid = env.call(CLONE, [0x5_0f00, DATA + SIZE - 0x100, 0, 0, 0, 0]);
    let (k, t) = env.k.take_child().unwrap();
    assert_eq!(tid, i64::from(t.tid));
    let mut thread = Env {
        k,
        t,
        m: env.m.clone(),
        lines: Vec::new(),
    };
    let at = format!("/proc/{}/task/{}/comm", ids.0, ids.1);
    let to = thread.open(at.as_bytes(), O_WRONLY, 0);
    let wrote = thread.write(to, b"by-thread");
    env.say(format!("thread write {wrote}"));
    assert_eq!(thread.call(CLOSE, [to as u64, 0, 0, 0, 0, 0]), 0);
    thread.k.finish_thread(&thread.t, &thread.m);
    // Another process may not rename this one's threads: no record.
    let pid = env.call(FORK, [0; 6]);
    let (mut k, t) = env.k.take_child().unwrap();
    let m = k.take_spawn_memory().unwrap();
    let mut child = Env {
        k,
        t,
        m,
        lines: Vec::new(),
    };
    let to = child.open(format!("/proc/{}/comm", ids.0).as_bytes(), O_WRONLY, 0);
    let wrote = child.write(to, b"by-child");
    let code = if wrote == -EINVAL { 0 } else { 1 };
    child.k.finish_thread(&child.t, &child.m);
    child.k.complete_process(ExitStatus::Exited(code));
    let status = env.wait(pid);
    env.say(format!("child status {status}"));
    env.ioctl(fd, IOC_DISABLE);
    env.ioctl(leader_fd, IOC_DISABLE);
    assert_eq!(env.call(PRCTL, [PR_GET_NAME, ARG, 0, 0, 0, 0]), 0);
    let name = name_at(&[env.long(ARG), env.long(ARG + 8)], 0);
    env.say(format!("name {}", String::from_utf8(name).unwrap()));
    env.say("all:".to_string());
    env.each_record(all, |env, record| say_comm(env, ids, record));
    env.say("leader only:".to_string());
    env.each_record(leader, |env, record| say_comm(env, ids, record));
    check(
        &env.lines,
        &[
            "open 1 1",
            "leader write 7",
            "thread write 9",
            "child status 0",
            "name by-thread",
            "all:",
            "comm exec 0 leader 1 name by-proc by leader",
            "record 7",
            "comm exec 0 leader 1 name by-thread by thread",
            "record 4",
            "record 7",
            "record 4",
            "leader only:",
            "comm exec 0 leader 1 name by-proc by leader",
            "record 7",
            "record 7",
        ],
    );
}

/// A 64-bit ELF executable whose one `PT_NOTE` holds the GNU build ID
/// `id`.
fn elf_with_build_id(id: &[u8; 20]) -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&4u32.to_le_bytes());
    b[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    b[96..104].copy_from_slice(&36u64.to_le_bytes());
    b.extend(4u32.to_le_bytes());
    b.extend(20u32.to_le_bytes());
    b.extend(3u32.to_le_bytes());
    b.extend(b"GNU\0");
    b.extend(id);
    b.resize(2 * 4096, 0);
    b
}

/// With `build_id`, an `MMAP2` record of an ELF file gives the file's GNU
/// build ID in place of its device and inode (`PERF_RECORD_MISC_MMAP_BUILD_ID`),
/// as Linux's `perf_event_mmap_output` does; one of another file gives the
/// device and inode, and so does an event without `build_id`.
#[test]
fn mmap2_records_give_the_build_id_an_event_asks_for() {
    const ATTR_BUILD_ID: u64 = 1 << 34;
    const MISC_MMAP_BUILD_ID: u64 = 1 << 14;
    let mut env = Env::new();
    let id: [u8; 20] = std::array::from_fn(|i| i as u8 + 0xa0);
    let files: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b"/tmp/build-id-elf".to_vec(), elf_with_build_id(&id)),
        (b"/tmp/build-id-text".to_vec(), vec![b'x'; 4096]),
    ];
    let mut fds = Vec::new();
    for (path, bytes) in &files {
        let fd = env.open(path, O_RDWR | O_CREAT | O_EXCL, 0o600);
        assert!(fd >= 0, "{fd}");
        for chunk in bytes.chunks(4096) {
            assert_eq!(env.write(fd, chunk), chunk.len() as i64);
        }
        fds.push(fd);
    }
    let (with, with_page) = env
        .open_side_band(0, -1, ATTR_MMAP2 | ATTR_MMAP_DATA | ATTR_BUILD_ID)
        .unwrap();
    let (without, without_page) = env
        .open_side_band(0, -1, ATTR_MMAP2 | ATTR_MMAP_DATA)
        .unwrap();
    env.ioctl(with, IOC_ENABLE);
    env.ioctl(without, IOC_ENABLE);
    let elf = env.mmap(4096, PROT_READ, MAP_PRIVATE, fds[0], 0);
    let text = env.mmap(4096, PROT_READ, MAP_PRIVATE, fds[1], 0);
    env.ioctl(with, IOC_DISABLE);
    env.ioctl(without, IOC_DISABLE);
    for (page, asks) in [(with_page, true), (without_page, false)] {
        let mut seen = Vec::new();
        env.each_record(page, |_, record| {
            if record[0] as u32 == RECORD_MMAP2 && (record[2] == elf || record[2] == text) {
                seen.push(record.to_vec());
            }
        });
        assert_eq!(seen.len(), 2, "{asks}");
        for record in seen {
            let misc = (record[0] >> 32) & 0xffff;
            let is_elf = record[2] == elf;
            if asks && is_elf {
                assert_ne!(misc & MISC_MMAP_BUILD_ID, 0);
                // Its size, three zeros, then the 20 bytes.
                let bytes: Vec<u8> = record[5..8].iter().flat_map(|w| w.to_le_bytes()).collect();
                assert_eq!(bytes[..4], [20, 0, 0, 0]);
                assert_eq!(bytes[4..], id[..]);
            } else {
                assert_eq!(misc & MISC_MMAP_BUILD_ID, 0, "{asks} {is_elf}");
            }
        }
    }
}
