//! Signal files through the system call interface: `signalfd4`'s checks
//! in Linux's order, what a signal file does as a file, which signals a
//! read takes and the records it gives (a `kill` and two `sigqueue`
//! values), and a new mask for the same file. The calls are those of the
//! signalfd-calls case of `tests/guests/processes/signalfd.c`, made in the
//! same order as musl makes them; `records` reads as its `records` does.
//! The expected lines are what that case printed on native x86-64 Linux in
//! the differential tests (the CI run of main at fb9a1ff3), which compare
//! it with Linux on every run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
/// Signal sets, a path, a `struct stat`, a `siginfo_t`, and what reads
/// and writes use.
const SET: u64 = DATA;
const PENDING: u64 = DATA + 0x80;
const PATH: u64 = DATA + 0x100;
const LINK: u64 = DATA + 0x180;
const STAT: u64 = DATA + 0x200;
const INFO: u64 = DATA + 0x300;
const BUFFER: u64 = DATA + 0x400;
const SIZE: u64 = 0x2000;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const FSTAT: u64 = 5;
const POLL: u64 = 7;
const LSEEK: u64 = 8;
const RT_SIGPROCMASK: u64 = 14;
const PREAD64: u64 = 17;
const PWRITE64: u64 = 18;
const GETPID: u64 = 39;
const KILL: u64 = 62;
const FCNTL: u64 = 72;
const READLINK: u64 = 89;
const GETUID: u64 = 102;
const RT_SIGPENDING: u64 = 127;
const RT_SIGQUEUEINFO: u64 = 129;
const SIGNALFD4: u64 = 289;

const SIG_BLOCK: u64 = 0;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const O_NONBLOCK: u64 = 0o4000;
const FD_CLOEXEC: u64 = 1;
const SFD_NONBLOCK: u64 = 0o4000;
const SFD_CLOEXEC: u64 = 0o2000000;
const SEEK_SET: u64 = 0;
const SEEK_END: u64 = 2;
const SIGKILL: u32 = 9;
const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;
const SIGSTOP: u32 = 19;
/// musl's `SIGRTMIN`.
const SIGRTMIN: u32 = 35;
const SI_QUEUE: i32 = -1;
/// A `struct signalfd_siginfo`.
const RECORD: usize = 128;

/// What the case printed on native Linux.
const EXPECTED: &str = "size 4 -22
size 16 -22
fault -14
flags -22
bad fd -9
other file -22
fd -2 -9
created 1
flags nonblock 1 cloexec 1
access 2
empty read -11
short read -22
zero read -22
write -22
lseek 0
pread -29
pwrite -29
lseek end 0
mode 600
link anon_inode:[signalfd]
poll empty 0
poll pending 1
read 128 bytes
  signo 10 errno 0 code 0 pid-match 1 uid-match 1 status 0 int 0 tid 0 overrun 0
poll taken 0
still pending 0
same fd 1
poll other 0
read 384 bytes
  signo 12 errno 0 code 0 pid-match 1 uid-match 1 status 0 int 0 tid 0 overrun 0
  signo 36 errno 0 code -1 pid-match 1 uid-match 1 status 0 int 7 tid 0 overrun 0
  signo 36 errno 0 code -1 pid-match 1 uid-match 1 status 0 int 8 tid 0 overrun 0
usr1 left 1
read 128 bytes
  signo 10 errno 0 code 0 pid-match 1 uid-match 1 status 0 int 0 tid 0 overrun 0
";

/// A kernel whose thread runs the first process, and the lines it prints.
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
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + SIZE)),
        );
        let m = AddressSpace::new();
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

    fn put(&self, at: u64, bytes: &[u8]) {
        self.m.write(GuestAddr(at), bytes).unwrap();
    }

    fn get(&self, at: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.m.read(GuestAddr(at), &mut bytes).unwrap();
        bytes
    }

    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(self.get(at, 4).try_into().unwrap())
    }

    /// The guest's `set_of`, at `SET`.
    fn set(&self, signals: &[u32]) {
        let set = signals.iter().fold(0u64, |set, &s| set | 1 << (s - 1));
        self.put(SET, &set.to_le_bytes());
    }

    /// The guest's `block`, of the set at `SET`.
    fn block(&mut self) {
        assert_eq!(self.call(RT_SIGPROCMASK, [SIG_BLOCK, SET, 0, 8, 0, 0]), 0);
    }

    /// musl's `signalfd`: `signalfd4` with its mask's 8 bytes.
    fn signalfd(&mut self, fd: i64, flags: u64) -> i64 {
        self.call(SIGNALFD4, [fd as u64, SET, 8, flags, 0, 0])
    }

    /// The guest's `readable`: `poll` for POLLIN with no wait.
    fn readable(&mut self, fd: i64) -> i64 {
        let mut p = (fd as i32).to_le_bytes().to_vec();
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        self.put(BUFFER, &p);
        let n = self.call(POLL, [BUFFER, 1, 0, 0, 0, 0]);
        if n < 0 {
            n
        } else if n == 1 {
            i64::from(u16::from_le_bytes(
                self.get(BUFFER + 6, 2).try_into().unwrap(),
            ))
        } else {
            0
        }
    }

    /// The guest's `records`: a read of up to `count` records, and each
    /// one's fields that do not name a process.
    fn records(&mut self, fd: i64, count: u64) {
        let n = self.call(READ, [fd as u64, BUFFER, RECORD as u64 * count, 0, 0, 0]);
        if n < 0 {
            self.say(format!("read {n}"));
            return;
        }
        self.say(format!("read {n} bytes"));
        let pid = self.call(GETPID, [0; 6]) as u32;
        let uid = self.call(GETUID, [0; 6]) as u32;
        for i in 0..n as u64 / RECORD as u64 {
            let at = BUFFER + i * RECORD as u64;
            let s = |off: u64| self.word(at + off);
            self.say(format!(
                "  signo {} errno {} code {} pid-match {} uid-match {} status {} int {} tid {} overrun {}",
                s(0),
                s(4) as i32,
                s(8) as i32,
                u8::from(s(12) == pid),
                u8::from(s(16) == uid),
                s(40) as i32,
                s(44) as i32,
                s(24),
                s(32)
            ));
        }
    }

    /// musl's `sigqueue`: a `siginfo_t` of `SI_QUEUE`, the caller's pid
    /// and uid and `value`, to `rt_sigqueueinfo`.
    fn sigqueue(&mut self, signal: u32, value: i32) {
        let pid = self.call(GETPID, [0; 6]);
        let uid = self.call(GETUID, [0; 6]);
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&signal.to_le_bytes());
        info[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
        info[16..20].copy_from_slice(&(pid as u32).to_le_bytes());
        info[20..24].copy_from_slice(&(uid as u32).to_le_bytes());
        info[24..28].copy_from_slice(&value.to_le_bytes());
        self.put(INFO, &info);
        let r = self.call(
            RT_SIGQUEUEINFO,
            [pid as u64, u64::from(signal), INFO, 0, 0, 0],
        );
        assert_eq!(r, 0);
    }

    fn kill_self(&mut self, signal: u32) {
        let pid = self.call(GETPID, [0; 6]);
        assert_eq!(
            self.call(KILL, [pid as u64, u64::from(signal), 0, 0, 0, 0]),
            0
        );
    }

    /// Whether `signal` is pending: `sigpending` and `sigismember`.
    fn pending(&mut self, signal: u32) -> u8 {
        assert_eq!(self.call(RT_SIGPENDING, [PENDING, 8, 0, 0, 0, 0]), 0);
        let set = u64::from_le_bytes(self.get(PENDING, 8).try_into().unwrap());
        u8::from(set & 1 << (signal - 1) != 0)
    }

    fn path(&self, path: &str) {
        let mut b = path.as_bytes().to_vec();
        b.push(0);
        self.put(PATH, &b);
    }
}

#[test]
fn signalfd_calls_as_linux() {
    let mut e = Env::new();
    e.set(&[SIGUSR1]);
    for (label, fd, mask, size, flags) in [
        ("size 4", -1i64, SET, 4, 0),
        ("size 16", -1, SET, 16, 0),
        ("fault", -1, 0, 8, 0),
        ("flags", -1, SET, 8, 1),
        ("bad fd", 999, SET, 8, 0),
    ] {
        let r = e.call(SIGNALFD4, [fd as u64, mask, size, flags, 0, 0]);
        e.say(format!("{label} {r}"));
    }
    e.path("/dev/null");
    let other = e.call(OPEN, [PATH, 0, 0, 0, 0, 0]);
    assert!(other >= 0);
    let r = e.call(SIGNALFD4, [other as u64, SET, 8, 0, 0, 0]);
    e.say(format!("other file {r}"));
    let r = e.call(SIGNALFD4, [-2i64 as u64, SET, 8, 0, 0, 0]);
    e.say(format!("fd -2 {r}"));
    e.call(CLOSE, [other as u64, 0, 0, 0, 0, 0]);

    let fd = e.signalfd(-1, SFD_NONBLOCK | SFD_CLOEXEC);
    e.say(format!("created {}", u8::from(fd >= 0)));
    let fl = e.call(FCNTL, [fd as u64, F_GETFL, 0, 0, 0, 0]) as u64;
    let fdfl = e.call(FCNTL, [fd as u64, F_GETFD, 0, 0, 0, 0]) as u64;
    e.say(format!(
        "flags nonblock {} cloexec {}",
        u8::from(fl & O_NONBLOCK != 0),
        u8::from(fdfl & FD_CLOEXEC != 0)
    ));
    e.say(format!("access {}", fl & 3));
    let f = fd as u64;
    for (label, n, a) in [
        ("empty read", READ, [f, BUFFER, 256, 0, 0, 0]),
        ("short read", READ, [f, BUFFER, 127, 0, 0, 0]),
        ("zero read", READ, [f, BUFFER, 0, 0, 0, 0]),
        ("write", WRITE, [f, BUFFER, 128, 0, 0, 0]),
        ("lseek", LSEEK, [f, 0, SEEK_SET, 0, 0, 0]),
        ("pread", PREAD64, [f, BUFFER, 128, 0, 0, 0]),
        ("pwrite", PWRITE64, [f, BUFFER, 128, 0, 0, 0]),
        ("lseek end", LSEEK, [f, 5, SEEK_END, 0, 0, 0]),
    ] {
        let r = e.call(n, a);
        e.say(format!("{label} {r}"));
    }
    assert_eq!(e.call(FSTAT, [f, STAT, 0, 0, 0, 0]), 0);
    let mode = e.word(STAT + 24);
    e.say(format!("mode {mode:o}"));
    e.path(&format!("/proc/self/fd/{fd}"));
    let length = e.call(READLINK, [PATH, LINK, 63, 0, 0, 0]);
    let link = String::from_utf8(e.get(LINK, length.max(0) as usize)).unwrap();
    e.say(format!("link {link}"));
    let r = e.readable(fd);
    e.say(format!("poll empty {r}"));

    // A pending signal that is not blocked is delivered, not read; a
    // blocked one waits for the file.
    e.block();
    e.kill_self(SIGUSR1);
    let r = e.readable(fd);
    e.say(format!("poll pending {r}"));
    e.records(fd, 2);
    let r = e.readable(fd);
    e.say(format!("poll taken {r}"));
    let r = e.pending(SIGUSR1);
    e.say(format!("still pending {r}"));

    // A new mask for the same file, which SIGKILL and SIGSTOP leave.
    e.set(&[SIGUSR2, SIGRTMIN + 1, SIGKILL, SIGSTOP]);
    e.block();
    let same = e.signalfd(fd, 0);
    e.say(format!("same fd {}", u8::from(same == fd)));
    e.kill_self(SIGUSR1);
    let r = e.readable(fd);
    e.say(format!("poll other {r}"));
    e.sigqueue(SIGRTMIN + 1, 7);
    e.sigqueue(SIGRTMIN + 1, 8);
    e.kill_self(SIGUSR2);
    e.records(fd, 4);
    let r = e.pending(SIGUSR1);
    e.say(format!("usr1 left {r}"));
    // SIGUSR1 is not in the mask, so another file takes it.
    e.set(&[SIGUSR1]);
    let second = e.signalfd(-1, SFD_NONBLOCK);
    e.records(second, 1);
    e.call(CLOSE, [second as u64, 0, 0, 0, 0, 0]);
    e.call(CLOSE, [f, 0, 0, 0, 0, 0]);

    assert_eq!(e.lines, EXPECTED.lines().collect::<Vec<_>>());
}
