//! Pseudo-terminals through the system call interface: `/dev/ptmx` and
//! `/dev/pts`, the slave's termios through either side, the line
//! discipline's editing, echoes and conversions, non-canonical reads,
//! packet mode, the old `struct termio`, the controlling terminal and its
//! foreground group, the signals it sends, `O_ASYNC`, and the hang-ups of
//! either side, `vhangup` and `TIOCCONS`. The expected values are Linux's
//! (`drivers/tty/pty.c`, `n_tty.c`, `tty_io.c`, `tty_jobctrl.c`): they are
//! the lines of `tests/guests/processes/pty.c`'s cases, which the
//! differential tests compare with Linux. Where the guest polls for 100 ms
//! to let Linux's work queue run, these poll without waiting, as this line
//! discipline takes what a side writes before the write returns; where its
//! handlers write each signal to a pipe, these processes block the signals
//! and take or read the pending ones. The lines that wait (for `VTIME`, or
//! for a job a background read or write stops, or for a signal's default
//! action) and `pty-proc-stat`'s `/proc` fields stay with the differential
//! tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{ExitStatus, GuestAddr, PAGE_SIZE};

const DATA: u64 = 0x600000;
/// A path.
const PATH: u64 = DATA;
/// What a call writes, and what it reads.
const TEXT: u64 = DATA + 0x100;
const BUF: u64 = DATA + 0x1000;
/// An ioctl's argument.
const ARG: u64 = DATA + 0x200;
/// A `struct stat` or `struct statfs`.
const STAT: u64 = DATA + 0x300;
/// A `struct pollfd`.
const POLLFD: u64 = DATA + 0x400;
/// A `struct termios` kept for later.
const SAVED: u64 = DATA + 0x500;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const STAT_CALL: u64 = 4;
const FSTAT: u64 = 5;
const POLL: u64 = 7;
const RT_SIGACTION: u64 = 13;
const RT_SIGPROCMASK: u64 = 14;
const IOCTL: u64 = 16;
const FORK: u64 = 57;
const WAIT4: u64 = 61;
const KILL: u64 = 62;
const FCNTL: u64 = 72;
const GETPGRP: u64 = 111;
const SETUID: u64 = 105;
const SETPGID: u64 = 109;
const SETSID: u64 = 112;
const READLINK: u64 = 89;
const SETRESUID: u64 = 117;
const RT_SIGPENDING: u64 = 127;
const RT_SIGTIMEDWAIT: u64 = 128;
const FSTATFS: u64 = 138;
const VHANGUP: u64 = 153;
const PRCTL: u64 = 157;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const GETDENTS64: u64 = 217;

const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_NOCTTY: u64 = 0o400;
const O_DIRECTORY: u64 = 0o200000;
const O_CLOEXEC: u64 = 0o2000000;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_SETOWN: u64 = 8;
const F_GETOWN: u64 = 9;
const F_SETSIG: u64 = 10;
const F_GETOWN_EX: u64 = 16;
const O_ASYNC: u64 = 0o20000;
const SIGHUP: u64 = 1;
const SIGUSR1: u64 = 10;
const SIGCONT: u64 = 18;
const SIGIO: u64 = 29;
const SIGTTOU: u64 = 22;
const POLLIN: u64 = 1;
const POLLPRI: u64 = 2;
const POLLOUT: u64 = 4;
const POLLHUP: u16 = 0x10;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSF: u64 = 0x5404;
const TCGETA: u64 = 0x5405;
const TCSETA: u64 = 0x5406;
const TCSETAF: u64 = 0x5408;
const TCSBRK: u64 = 0x5409;
const TCXONC: u64 = 0x540a;
const TCFLSH: u64 = 0x540b;
const TIOCEXCL: u64 = 0x540c;
const TIOCNXCL: u64 = 0x540d;
const TIOCSCTTY: u64 = 0x540e;
const TIOCGPGRP: u64 = 0x540f;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCMGET: u64 = 0x5415;
const FIONREAD: u64 = 0x541b;
const TIOCCONS: u64 = 0x541d;
const TIOCPKT: u64 = 0x5420;
const FIOASYNC: u64 = 0x5452;
const TIOCNOTTY: u64 = 0x5422;
const TIOCSETD: u64 = 0x5423;
const TIOCGETD: u64 = 0x5424;
const TIOCGSID: u64 = 0x5429;
const TIOCSIG: u64 = 0x40045436;
const TIOCVHANGUP: u64 = 0x5437;
const TCGETS2: u64 = 0x802c542a;
const TCSETS2: u64 = 0x402c542b;
const TIOCGPTN: u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;
const TIOCGDEV: u64 = 0x80045432;
const TIOCGPKT: u64 = 0x80045438;
const TIOCGPTLCK: u64 = 0x80045439;
const TIOCGEXCL: u64 = 0x80045440;
const TIOCGPTPEER: u64 = 0x5441;
const TIOCGLCKTRMIOS: u64 = 0x5456;
const TIOCSLCKTRMIOS: u64 = 0x5457;

// The flags of `struct termios`.
const ICRNL: u32 = 0o400;
const IGNCR: u32 = 0o200;
const INLCR: u32 = 0o100;
const ISTRIP: u32 = 0o40;
const IUCLC: u32 = 0o1000;
const IXON: u32 = 0o2000;
const IXANY: u32 = 0o4000;
const OPOST: u32 = 0o1;
const OLCUC: u32 = 0o2;
const ONLCR: u32 = 0o4;
const OCRNL: u32 = 0o10;
const ONOCR: u32 = 0o20;
const ONLRET: u32 = 0o40;
const XTABS: u32 = 0o14000;
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const TOSTOP: u32 = 0o400;
const NOFLSH: u32 = 0o200;
const ECHONL: u32 = 0o100;
const ECHOCTL: u32 = 0o1000;
const ECHOPRT: u32 = 0o2000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
const EXTPROC: u32 = 0o200000;
const CBAUD: u32 = 0o10017;
const CSIZE: u32 = 0o60;
const CS7: u32 = 0o40;
const PARENB: u32 = 0o400;
const B1200: u32 = 0o11;
const B9600: u32 = 0o15;
const B38400: u32 = 0o17;
const BOTHER: u32 = 0o10000;
const VINTR: usize = 0;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSTOP: usize = 9;
const VEOL: usize = 11;
const VERASE: usize = 2;
const VEOL2: usize = 16;

/// The kernel's `struct termios2`: the four flags, the line, 19 control
/// characters and the speeds.
#[derive(Clone, Copy, PartialEq)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
    ispeed: u32,
    ospeed: u32,
}

impl Termios {
    fn from(bytes: &[u8]) -> Self {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        Self {
            iflag: word(0),
            oflag: word(4),
            cflag: word(8),
            lflag: word(12),
            line: bytes[16],
            cc: bytes[17..36].try_into().unwrap(),
            ispeed: word(36),
            ospeed: word(40),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [self.iflag, self.oflag, self.cflag, self.lflag] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(self.line);
        out.extend_from_slice(&self.cc);
        out.extend_from_slice(&self.ispeed.to_le_bytes());
        out.extend_from_slice(&self.ospeed.to_le_bytes());
        out
    }
}

/// A kernel whose thread runs the first process, as root, with the page at
/// `DATA` and the three after it mapped, and the lines a case prints.
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
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + 4 * PAGE_SIZE)),
        );
        let m = Arc::new(AddressSpace::new());
        m.map_shared(
            Some(GuestAddr(DATA)),
            4 * PAGE_SIZE,
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

    /// `fork`: the child, whose lines are its own.
    fn fork(&mut self) -> Env {
        let pid = self.call(FORK, [0; 6]);
        let (k, t) = self.k.take_child().unwrap();
        assert_eq!(pid, i64::from(t.tid));
        let mut k = k;
        let m = k.take_spawn_memory().unwrap();
        Env {
            k,
            t,
            m,
            lines: Vec::new(),
        }
    }

    /// `_exit(code)`: the process's files are closed, and its lines are
    /// the parent's next.
    fn exit(mut self, parent: &mut Env, code: i32) {
        self.k.finish_thread(&self.t, &self.m);
        self.k.complete_process(ExitStatus::Exited(code));
        parent.lines.append(&mut self.lines);
    }

    /// `waitpid(pid, &status, WUNTRACED)` of a child that has exited: the
    /// status.
    fn wait(&mut self, pid: i64) -> i32 {
        let r = self.call(WAIT4, [pid as u64, ARG, 2, 0, 0, 0]);
        assert_eq!(r, pid);
        self.int(ARG)
    }

    fn pid(&self) -> i64 {
        i64::from(self.t.tid)
    }

    /// Sets `signal`'s disposition to `SIG_IGN` (1) or `SIG_DFL` (0).
    fn disposition(&mut self, signal: u64, handler: u64) {
        self.put(ARG, &[0; 32]);
        self.put(ARG, &handler.to_le_bytes());
        assert_eq!(self.call(RT_SIGACTION, [signal, ARG, 0, 8, 0, 0]), 0);
    }

    fn say(&mut self, line: String) {
        self.lines.push(line);
    }

    /// The guest's `TRY`: the result, and errno when it is negative.
    fn tried(&mut self, label: &str, r: i64) {
        let (r, errno) = if r < 0 { (-1, -r) } else { (r, 0) };
        self.say(format!("{label} {r} {errno}"));
    }

    fn put(&self, at: u64, bytes: &[u8]) {
        self.m.write(GuestAddr(at), bytes).unwrap();
    }

    fn get(&self, at: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.m.read(GuestAddr(at), &mut bytes).unwrap();
        bytes
    }

    fn int(&self, at: u64) -> i32 {
        i32::from_le_bytes(self.get(at, 4).try_into().unwrap())
    }

    fn put_int(&self, at: u64, value: i32) {
        self.put(at, &value.to_le_bytes());
    }

    fn path(&self, path: &str) -> u64 {
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        self.put(PATH, &bytes);
        PATH
    }

    fn open(&mut self, path: &str, flags: u64) -> i64 {
        let at = self.path(path);
        self.call(OPEN, [at, flags, 0, 0, 0, 0])
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    fn ioctl(&mut self, fd: i64, request: u64, arg: u64) -> i64 {
        self.call(IOCTL, [fd as u64, request, arg, 0, 0, 0])
    }

    /// An ioctl that reads or writes the `int` at `ARG`, set to `value`
    /// first.
    fn ioctl_int(&mut self, fd: i64, request: u64, value: i32) -> (i64, i32) {
        self.put_int(ARG, value);
        let r = self.ioctl(fd, request, ARG);
        (r, self.int(ARG))
    }

    fn fcntl(&mut self, fd: i64, command: u64, arg: u64) -> i64 {
        self.call(FCNTL, [fd as u64, command, arg, 0, 0, 0])
    }

    fn write(&mut self, fd: i64, bytes: &[u8]) -> i64 {
        self.put(TEXT, bytes);
        self.call(WRITE, [fd as u64, TEXT, bytes.len() as u64, 0, 0, 0])
    }

    /// A read of up to `len` bytes: its result and the bytes.
    fn read(&mut self, fd: i64, len: u64) -> (i64, Vec<u8>) {
        let n = self.call(READ, [fd as u64, BUF, len, 0, 0, 0]);
        let bytes = if n > 0 {
            self.get(BUF, n as usize)
        } else {
            Vec::new()
        };
        (n, bytes)
    }

    /// The `revents` of a poll for `events` that does not wait.
    fn polled(&mut self, fd: i64, events: u64) -> u16 {
        let mut p = (fd as u32).to_le_bytes().to_vec();
        p.extend_from_slice(&(events as u16).to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        self.put(POLLFD, &p);
        assert!(self.call(POLL, [POLLFD, 1, 0, 0, 0, 0]) >= 0);
        u16::from_le_bytes(self.get(POLLFD + 6, 2).try_into().unwrap())
    }

    /// The guest's `drain`: reads while a poll says there is something, each
    /// read's bytes kept with `|` after each when `reads`, and `<0>` for a
    /// read of 0. The count, or `-errno` of a read that failed first.
    fn drain(&mut self, fd: i64, reads: bool) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        loop {
            let revents = self.polled(fd, POLLIN);
            if revents & (POLLIN as u16 | POLLHUP) == 0 {
                break;
            }
            let (n, bytes) = self.read(fd, 4095 - out.len() as u64);
            if n < 0 {
                return if out.is_empty() { Err(n) } else { Ok(out) };
            }
            if n == 0 {
                if reads {
                    out.extend_from_slice(b"<0>");
                }
                if !reads {
                    break;
                }
                // A canonical end of file reads 0; at a hang-up every read
                // does.
                if self.polled(fd, POLLIN) & POLLHUP != 0 {
                    break;
                }
                continue;
            }
            out.extend_from_slice(&bytes);
            if reads {
                out.push(b'|');
            }
        }
        Ok(out)
    }

    /// The guest's `show`: the label, the count and the bytes, escaped.
    fn show(&mut self, label: &str, bytes: &[u8]) {
        let mut text = String::new();
        for &c in bytes {
            if (0x20..0x7f).contains(&c) && c != b'\\' && c != b'"' {
                text.push(c as char);
            } else {
                text.push_str(&format!("\\x{c:02x}"));
            }
        }
        self.say(format!("{label} {} \"{text}\"", bytes.len()));
    }

    fn show_drained(&mut self, label: &str, fd: i64, reads: bool) {
        match self.drain(fd, reads) {
            Ok(bytes) => self.show(label, &bytes),
            Err(e) => self.say(format!("{label} error {}", -e)),
        }
    }

    fn get_termios(&mut self, fd: i64) -> (i64, Termios) {
        self.put(ARG, &[0; 44]);
        let r = self.ioctl(fd, TCGETS2, ARG);
        (r, Termios::from(&self.get(ARG, 44)))
    }

    fn set_termios_with(&mut self, fd: i64, request: u64, t: &Termios) -> i64 {
        self.put(ARG, &t.bytes());
        self.ioctl(fd, request, ARG)
    }

    fn set_termios(&mut self, fd: i64, t: &Termios) -> i64 {
        self.set_termios_with(fd, TCSETS2, t)
    }

    /// The guest's `set_flags`: `tcgetattr`, three flags, `tcsetattr`.
    fn set_flags(&mut self, fd: i64, iflag: u32, oflag: u32, lflag: u32) {
        let (_, mut t) = self.get_termios(fd);
        t.iflag = iflag;
        t.oflag = oflag;
        t.lflag = lflag;
        self.put(ARG, &t.bytes()[..36]);
        assert_eq!(self.ioctl(fd, TCSETS, ARG), 0);
    }

    /// `openpty`: the master, unlocked, and its slave, both without
    /// becoming the controlling terminal.
    fn openpty(&mut self) -> (i64, i64) {
        let m = self.open("/dev/ptmx", O_RDWR | O_NOCTTY);
        assert!(m >= 0, "{m}");
        assert_eq!(self.ioctl_int(m, TIOCSPTLCK, 0).0, 0);
        let (r, number) = self.ioctl_int(m, TIOCGPTN, -1);
        assert_eq!(r, 0);
        let s = self.open(&format!("/dev/pts/{number}"), O_RDWR | O_NOCTTY);
        assert!(s >= 0, "{s}");
        (m, s)
    }

    /// The `struct winsize` at `ARG`.
    fn window(&self) -> String {
        let bytes = self.get(ARG, 8);
        let half = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]).to_string();
        [0, 2, 4, 6].map(half).join(" ")
    }

    /// The names `getdents64` lists in the directory at `path`.
    fn listed(&mut self, path: &str) -> Vec<Vec<u8>> {
        let fd = self.open(path, O_DIRECTORY | O_CLOEXEC);
        assert!(fd >= 0, "{fd}");
        let mut names = Vec::new();
        loop {
            let n = self.call(GETDENTS64, [fd as u64, BUF, 0x1000, 0, 0, 0]);
            assert!(n >= 0, "{n}");
            if n == 0 {
                break;
            }
            let bytes = self.get(BUF, n as usize);
            let mut at = 0;
            while at < bytes.len() {
                let length = u16::from_le_bytes([bytes[at + 16], bytes[at + 17]]) as usize;
                let name = &bytes[at + 19..at + length];
                let end = name.iter().position(|&c| c == 0).unwrap();
                names.push(name[..end].to_vec());
                at += length;
            }
        }
        self.close(fd);
        names
    }

    /// Types `input` at the master and shows each read of the slave, then
    /// the echo.
    fn type_in(&mut self, m: i64, s: i64, label: &str, input: &[u8]) {
        self.write(m, input);
        self.show_drained(&format!("{label} reads"), s, true);
        self.show_drained(&format!("{label} echo"), m, false);
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

/// C's `%#o`.
fn octal(value: i64) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("0{value:o}")
    }
}

/// C's `%#x`.
fn hex(value: u16) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

/// `stat`'s mode, inode, device and special device at `STAT`.
fn stat_fields(e: &Env) -> (u32, u64, u64, u64) {
    let long = |at: u64| e.m.read_u64(GuestAddr(STAT + at)).unwrap();
    (e.int(STAT + 24) as u32, long(8), long(0), long(40))
}

fn major(device: u64) -> u64 {
    ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff)
}

fn minor(device: u64) -> u64 {
    (device & 0xff) | ((device >> 12) & !0xff)
}

const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o20000;

/// pty-open: the pair, its numbering and locking, the slave's files and
/// names, and what each side sees as the other closes.
#[test]
fn pty_open_numbers_locks_names_and_hangs_up_either_side() {
    let mut e = Env::new();
    let m = e.open("/dev/ptmx", O_RDWR | O_NOCTTY);
    e.say(format!("posix_openpt {}", (m >= 0) as i32));
    let (r, number) = e.ioctl_int(m, TIOCGPTN, 0);
    e.say(format!("TIOCGPTN {r}"));
    let name = format!("/dev/pts/{number}");
    e.say("ptsname 1".into());
    let (r, locked) = e.ioctl_int(m, TIOCGPTLCK, -1);
    e.tried("TIOCGPTLCK", r);
    e.say(format!("locked {locked}"));
    let r = e.open(&name, O_RDWR | O_NOCTTY);
    e.tried("open locked", r);
    let r = e.ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    e.tried("TIOCGPTPEER locked", r);
    let r = e.write(m, b"x");
    e.tried("write without a slave", r);
    // musl's grantpt does nothing; unlockpt is TIOCSPTLCK.
    let (unlock, _) = e.ioctl_int(m, TIOCSPTLCK, 0);
    e.say(format!("grantpt 0 unlockpt {unlock}"));
    let (r, locked) = e.ioctl_int(m, TIOCGPTLCK, -1);
    e.tried("TIOCGPTLCK", r);
    e.say(format!("locked {locked}"));
    let at = e.path(&name);
    let r = e.call(STAT_CALL, [at, STAT, 0, 0, 0, 0]);
    e.say(format!("stat slave {r}"));
    let (mode, path_ino, path_dev, path_rdev) = stat_fields(&e);
    let uid = e.int(STAT + 28);
    e.say(format!(
        "slave {} {} {} {}",
        (mode & S_IFMT == S_IFCHR) as i32,
        (major(path_rdev) == 136) as i32,
        (minor(path_rdev) == number as u64) as i32,
        (uid == 0) as i32
    ));
    let s = e.open(&name, O_RDWR | O_NOCTTY);
    e.say(format!("open slave {}", (s >= 0) as i32));
    e.call(FSTAT, [s as u64, STAT, 0, 0, 0, 0]);
    let (_, ino, dev, rdev) = stat_fields(&e);
    e.say(format!(
        "same inode {} {} {}",
        (ino == path_ino) as i32,
        (dev == path_dev) as i32,
        (rdev == path_rdev) as i32
    ));
    // isatty is TIOCGWINSZ.
    let tty_m = e.ioctl(m, TIOCGWINSZ, ARG) == 0;
    let tty_s = e.ioctl(s, TIOCGWINSZ, ARG) == 0;
    e.say(format!("isatty {} {}", tty_m as i32, tty_s as i32));
    let link = e.path(&format!("/proc/self/fd/{s}"));
    let n = e.call(READLINK, [link, BUF, 255, 0, 0, 0]);
    let target = e.get(BUF, n.max(0) as usize);
    e.say(format!("ttyname {}", (target == name.as_bytes()) as i32));
    let r = e.call(FSTATFS, [s as u64, STAT, 0, 0, 0, 0]);
    e.tried("fstatfs", r);
    let kind = e.m.read_u64(GuestAddr(STAT)).unwrap();
    e.say(format!("f_type {kind:#x}"));
    e.call(FSTAT, [m as u64, STAT, 0, 0, 0, 0]);
    let (mode, _, _, rdev) = stat_fields(&e);
    e.say(format!(
        "master {} {} {}",
        (mode & S_IFMT == S_IFCHR) as i32,
        (major(rdev) == 5) as i32,
        (minor(rdev) == 2) as i32
    ));
    let (r, device) = e.ioctl_int(m, TIOCGDEV, 0);
    e.tried("TIOCGDEV", r);
    e.say(format!(
        "device {}",
        (device as u32 == (136 << 8) | number as u32) as i32
    ));
    let (r, _) = e.ioctl_int(s, TIOCGPTN, 0);
    e.tried("TIOCGPTN of the slave", r);
    let r = e.ioctl(s, TIOCGPTPEER, O_RDWR);
    e.tried("TIOCGPTPEER of the slave", r);
    let peer = e.ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    e.call(FSTAT, [peer as u64, STAT, 0, 0, 0, 0]);
    let (_, peer_ino, _, _) = stat_fields(&e);
    let cloexec = e.fcntl(peer, F_GETFD, 0);
    e.say(format!(
        "TIOCGPTPEER {} {} {}",
        (peer >= 0) as i32,
        (peer_ino == path_ino) as i32,
        (cloexec == 1) as i32
    ));
    let link = e.path(&format!("/proc/self/fd/{peer}"));
    let n = e.call(READLINK, [link, BUF, 63, 0, 0, 0]);
    let target = e.get(BUF, n.max(0) as usize);
    e.say(format!("peer link {}", (target == name.as_bytes()) as i32));
    let names = e.listed("/dev/pts");
    let listed = names.iter().any(|n| *n == name.as_bytes()[9..]);
    let ptmx = names.iter().any(|n| n == b"ptmx");
    e.say(format!("listed {} {}", listed as i32, ptmx as i32));
    let at = e.path("/dev/pts/ptmx");
    let r = e.call(STAT_CALL, [at, STAT, 0, 0, 0, 0]);
    e.tried("stat ptmx", r);
    let (_, _, _, rdev) = stat_fields(&e);
    e.say(format!("ptmx {}", (rdev == (5 << 8) | 2) as i32));
    let at = e.path("/dev/pts/4294967");
    let r = e.call(STAT_CALL, [at, STAT, 0, 0, 0, 0]);
    e.tried("stat a missing slave", r);
    let r = e.open("/dev/pts/x1", O_RDWR);
    e.tried("open a bad name", r);
    let revents = e.polled(s, POLLIN | POLLOUT);
    e.say(format!("poll the slave {}", hex(revents)));
    // Through, and back with the echo.
    let r = e.write(m, b"in\n");
    e.say(format!("write {r}"));
    let (r, _) = e.read(s, 256);
    e.say(format!("read {r}"));
    let r = e.write(s, b"out\n");
    e.say(format!("write {r}"));
    e.show_drained("master reads", m, false);
    // Every slave description closed: the master reads what is left, then
    // EIO, and is hung up; a write is EIO.
    e.write(s, b"left");
    e.close(s);
    e.close(peer);
    e.show_drained("after the slave", m, false);
    let (r, _) = e.read(m, 1);
    e.tried("read", r);
    let revents = e.polled(m, POLLIN | POLLOUT);
    e.say(format!("poll {}", hex(revents)));
    let r = e.write(m, b"x");
    e.tried("write", r);
    let at = e.path(&name);
    let r = e.call(STAT_CALL, [at, STAT, 0, 0, 0, 0]);
    e.say(format!("still named {r}"));
    let s = e.open(&name, O_RDWR | O_NOCTTY);
    let revents = e.polled(m, POLLOUT);
    e.say(format!(
        "open again {} poll {}",
        (s >= 0) as i32,
        hex(revents)
    ));
    // The master closed: the slave is hung up.
    e.close(m);
    let at = e.path(&name);
    let r = e.call(STAT_CALL, [at, STAT, 0, 0, 0, 0]);
    e.tried("unnamed", r);
    let (r, _) = e.read(s, 1);
    e.say(format!("read {r}"));
    let r = e.write(s, b"x");
    e.tried("write", r);
    let r = e.ioctl(s, TCGETS, ARG);
    e.tried("tcgetattr", r);
    e.put_int(ARG, 1);
    let r = e.ioctl(s, TIOCSPGRP, ARG);
    e.tried("TIOCSPGRP", r);
    let revents = e.polled(s, POLLIN | POLLOUT);
    e.say(format!("poll {}", hex(revents)));
    let flags = e.fcntl(s, F_GETFL, 0);
    e.say(format!("F_GETFL {}", octal(flags & 3)));
    e.close(s);
    check(
        &e.lines,
        &[
            "posix_openpt 1",
            "TIOCGPTN 0",
            "ptsname 1",
            "TIOCGPTLCK 0 0",
            "locked 1",
            "open locked -1 5",
            "TIOCGPTPEER locked -1 5",
            "write without a slave 1 0",
            "grantpt 0 unlockpt 0",
            "TIOCGPTLCK 0 0",
            "locked 0",
            "stat slave 0",
            "slave 1 1 1 1",
            "open slave 1",
            "same inode 1 1 1",
            "isatty 1 1",
            "ttyname 1",
            "fstatfs 0 0",
            "f_type 0x1cd1",
            "master 1 1 1",
            "TIOCGDEV 0 0",
            "device 1",
            "TIOCGPTN of the slave -1 25",
            "TIOCGPTPEER of the slave -1 5",
            "TIOCGPTPEER 1 1 1",
            "peer link 1",
            "listed 1 1",
            "stat ptmx 0 0",
            "ptmx 1",
            "stat a missing slave -1 2",
            "open a bad name -1 2",
            "poll the slave 0x4",
            "write 3",
            "read 4",
            "write 4",
            "master reads 10 \"xin\\x0d\\x0aout\\x0d\\x0a\"",
            "after the slave 4 \"left\"",
            "read -1 5",
            "poll 0x14",
            "write 1 0",
            "still named 0",
            "open again 1 poll 0x4",
            "unnamed -1 2",
            "read 0",
            "write -1 5",
            "tcgetattr -1 5",
            "TIOCSPGRP -1 25",
            "poll 0x1d",
            "F_GETFL 02",
        ],
    );
}

/// pty-termios: the slave's termios through either side, its speeds and
/// fixed control flags, the window size, what the queues hold, flushes,
/// flow control and the other requests.
#[test]
fn pty_termios_through_either_side_speeds_window_queues_and_flow() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let (r, mut t) = e.get_termios(s);
    e.say(format!("TCGETS2 {r}"));
    e.say(format!(
        "flags {} {} {} {} line {} speeds {} {}",
        octal(t.iflag.into()),
        octal(t.oflag.into()),
        octal(t.cflag.into()),
        octal(t.lflag.into()),
        t.line,
        t.ispeed,
        t.ospeed
    ));
    let cc: Vec<String> = t.cc.iter().map(u8::to_string).collect();
    e.say(format!("cc {}", cc.join(" ")));
    let (_, from_master) = e.get_termios(m);
    e.say(format!(
        "the master's are the slave's {}",
        (from_master == t) as i32
    ));
    // B9600 with parity and 7 bits, through the master: a pseudo-terminal
    // keeps 8 bits and no parity.
    t.cflag = (t.cflag & !(CBAUD | CSIZE)) | B9600 | PARENB | CS7;
    t.line = 3;
    let r = e.set_termios(m, &t);
    e.say(format!("TCSETS2 {r}"));
    let (_, mut t) = e.get_termios(s);
    e.say(format!(
        "cflag {} line {} speeds {} {}",
        octal(t.cflag.into()),
        t.line,
        t.ispeed,
        t.ospeed
    ));
    t.cflag |= B1200 << 16;
    e.set_termios(s, &t);
    let (_, mut t) = e.get_termios(s);
    e.say(format!("input speed {} {}", t.ispeed, t.ospeed));
    t.cflag = (t.cflag & !(CBAUD | (CBAUD << 16))) | BOTHER;
    t.ospeed = 12345;
    t.ispeed = 777;
    e.set_termios(s, &t);
    let (_, mut t) = e.get_termios(s);
    e.say(format!(
        "other speed {} {} {}",
        octal((t.cflag & CBAUD).into()),
        t.ispeed,
        t.ospeed
    ));
    e.ioctl(s, TCGETS, ARG);
    let cflag = e.int(ARG + 8) as u32;
    e.say(format!("cfgetospeed {}", (cflag & CBAUD == BOTHER) as i32));
    t.cflag = (t.cflag & !CBAUD) | B38400;
    t.line = 0;
    e.set_termios(s, &t);
    e.put(ARG, &[0; 8]);
    let r = e.ioctl(s, TIOCGWINSZ, ARG);
    e.tried("TIOCGWINSZ", r);
    e.say(format!("window {}", e.window()));
    let mut set = Vec::new();
    for v in [24u16, 80, 640, 480] {
        set.extend_from_slice(&v.to_le_bytes());
    }
    e.put(ARG, &set);
    let r = e.ioctl(m, TIOCSWINSZ, ARG);
    e.say(format!("TIOCSWINSZ {r}"));
    e.ioctl(s, TIOCGWINSZ, ARG);
    e.say(format!("from the slave {}", e.window()));
    let r = e.ioctl(m, TIOCGWINSZ, 8);
    e.tried("TIOCGWINSZ bad address", r);
    // A canonical slave counts whole lines; a raw one every byte.
    e.write(m, b"ab\ncd");
    let (r, count) = e.ioctl_int(s, FIONREAD, -1);
    e.tried("FIONREAD", r);
    e.say(format!("unread {count}"));
    let (r, count) = e.ioctl_int(s, TIOCOUTQ, -1);
    e.tried("TIOCOUTQ", r);
    e.say(format!("unwritten {count}"));
    e.show_drained("echo", m, false);
    e.set_flags(s, ICRNL, OPOST | ONLCR, ISIG | ECHO);
    let (_, count) = e.ioctl_int(s, FIONREAD, -1);
    e.say(format!("raw FIONREAD {count}"));
    e.set_flags(
        s,
        ICRNL | IXON,
        OPOST | ONLCR,
        ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
    );
    // TCSETSF discards the input.
    e.ioctl(s, TCGETS, ARG);
    let r = e.ioctl(s, TCSETSF, ARG);
    e.say(format!("TCSETSF {r}"));
    let (_, count) = e.ioctl_int(s, FIONREAD, -1);
    e.say(format!("flushed {count}"));
    e.write(s, b"out");
    let (_, count) = e.ioctl_int(m, FIONREAD, -1);
    e.say(format!("master FIONREAD {count}"));
    let r = e.ioctl(m, TCFLSH, 0);
    e.say(format!("TCFLSH {r}"));
    let (_, count) = e.ioctl_int(m, FIONREAD, -1);
    let revents = e.polled(m, POLLIN);
    e.say(format!("master flushed {count} poll {}", hex(revents)));
    let r = e.ioctl(s, TCFLSH, 3);
    e.tried("TCFLSH 3", r);
    // TCOOFF stops the slave's output; TCOON starts it.
    let r = e.ioctl(s, TCXONC, 0);
    e.say(format!("TCOOFF {r}"));
    e.fcntl(s, F_SETFL, O_NONBLOCK);
    let r = e.write(s, b"x");
    e.tried("write stopped", r);
    let revents = e.polled(s, POLLOUT);
    e.say(format!("poll stopped {}", hex(revents)));
    let r = e.ioctl(s, TCXONC, 1);
    e.say(format!("TCOON {r}"));
    let r = e.write(s, b"y");
    e.say(format!("write {r}"));
    e.fcntl(s, F_SETFL, 0);
    e.show_drained("started", m, false);
    let r = e.ioctl(s, TCXONC, 2);
    e.say(format!("TCIOFF {r}"));
    e.show_drained("stop character", m, false);
    let drain = e.ioctl(s, TCSBRK, 1);
    let brk = e.ioctl(s, TCSBRK, 0);
    e.say(format!("tcdrain {drain} tcsendbreak {brk}"));
    let (r, discipline) = e.ioctl_int(s, TIOCGETD, -1);
    e.tried("TIOCGETD", r);
    e.say(format!("discipline {discipline}"));
    let (r, _) = e.ioctl_int(s, TIOCSETD, 0);
    e.say(format!("TIOCSETD {r}"));
    let (r, _) = e.ioctl_int(s, TIOCSETD, 31);
    e.tried("TIOCSETD 31", r);
    e.ioctl(s, TIOCEXCL, 0);
    let (r, exclusive) = e.ioctl_int(s, TIOCGEXCL, -1);
    e.tried("TIOCGEXCL", r);
    e.say(format!("exclusive {exclusive}"));
    e.ioctl(s, TIOCNXCL, 0);
    let (_, exclusive) = e.ioctl_int(s, TIOCGEXCL, -1);
    e.say(format!("TIOCNXCL {exclusive}"));
    let r = e.ioctl(s, 0x54ff, 0);
    e.tried("unknown request", r);
    let r = e.ioctl(s, TIOCMGET, ARG);
    e.tried("TIOCMGET", r);
    check(
        &e.lines,
        &[
            "TCGETS2 0",
            "flags 02400 05 0277 0105073 line 0 speeds 38400 38400",
            "cc 3 28 127 21 4 0 1 0 17 19 26 0 18 15 23 22 0 0 0",
            "the master's are the slave's 1",
            "TCSETS2 0",
            "cflag 0275 line 3 speeds 9600 9600",
            "input speed 1200 9600",
            "other speed 010000 12345 12345",
            "cfgetospeed 1",
            "TIOCGWINSZ 0 0",
            "window 0 0 0 0",
            "TIOCSWINSZ 0",
            "from the slave 24 80 640 480",
            "TIOCGWINSZ bad address -1 14",
            "FIONREAD 0 0",
            "unread 3",
            "TIOCOUTQ 0 0",
            "unwritten 0",
            "echo 6 \"ab\\x0d\\x0acd\"",
            "raw FIONREAD 5",
            "TCSETSF 0",
            "flushed 0",
            "master FIONREAD 3",
            "TCFLSH 0",
            "master flushed 0 poll 0",
            "TCFLSH 3 -1 22",
            "TCOOFF 0",
            "write stopped -1 11",
            "poll stopped 0",
            "TCOON 0",
            "write 1",
            "started 1 \"y\"",
            "TCIOFF 0",
            "stop character 1 \"\\x13\"",
            "tcdrain 0 tcsendbreak 0",
            "TIOCGETD 0 0",
            "discipline 0",
            "TIOCSETD 0",
            "TIOCSETD 31 -1 22",
            "TIOCGEXCL 0 0",
            "exclusive 1",
            "TIOCNXCL 0",
            "unknown request -1 25",
            "TIOCMGET -1 25",
        ],
    );
}

/// pty-canonical: editing, the echoes each flag asks for, line ends, the
/// input and output conversions, and flow control typed at the master.
#[test]
fn pty_canonical_edits_echoes_ends_lines_and_converts() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let iflag = ICRNL | IXON;
    let oflag = OPOST | ONLCR;
    let lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
    for (label, text) in [
        ("lines", &b"hello\rwor\x7fld\n"[..]),
        ("kill", b"abc\x15x\x04"),
        ("word", b"one two\x17three\n"),
        ("literal", b"\x16\x03\x16\x7f\n"),
        ("end of file", b"\x04"),
        ("reprint", b"abc\x12\n"),
        ("tab", b"a\tb\x7f\x7f\n"),
        ("control", b"\x01\x7fx\n"),
        ("kill control", b"a\x02\x15\n"),
    ] {
        e.type_in(m, s, label, text);
    }
    e.write(m, b"abcdef\n");
    for _ in 0..2 {
        let (_, bytes) = e.read(s, 4);
        e.show("small read", &bytes);
    }
    e.show_drained("small echo", m, false);
    for (label, lflag, text) in [
        ("echoprt", lflag | ECHOPRT, &b"abc\x7f\x7fd\n"[..]),
        ("echok", lflag & !ECHOKE, b"ab\x15c\n"),
        ("no echoe", lflag & !(ECHOE | ECHOKE), b"ab\x7fc\n"),
        ("echonl", (lflag & !ECHO) | ECHONL, b"secret\n"),
        ("no echoctl", lflag & !ECHOCTL, b"a\x01\x7f\n"),
    ] {
        e.set_flags(s, iflag, oflag, lflag);
        e.type_in(m, s, label, text);
    }
    e.set_flags(s, iflag, oflag, lflag);
    let set_cc = |e: &mut Env, pairs: &[(usize, u8)]| {
        e.ioctl(s, TCGETS, ARG);
        for &(index, c) in pairs {
            e.put(ARG + 17 + index as u64, &[c]);
        }
        assert_eq!(e.ioctl(s, TCSETS, ARG), 0);
    };
    set_cc(&mut e, &[(VEOL, b';'), (VEOL2, b'#')]);
    e.type_in(m, s, "eol", b"a;b#c\n");
    set_cc(&mut e, &[(VEOL, 0), (VEOL2, 0), (VERASE, 0)]);
    e.type_in(m, s, "disabled", b"a\0\x7f\n");
    set_cc(&mut e, &[(VERASE, 0o177)]);
    for (label, iflag, lflag, text) in [
        ("igncr", iflag | IGNCR, lflag, &b"a\rb\n"[..]),
        ("inlcr", INLCR, lflag, b"a\n\x04"),
        ("iuclc", iflag | IUCLC, lflag, b"AbC\n"),
        ("istrip", iflag | ISTRIP, lflag, b"\xe1\n"),
        ("raw echo", iflag, lflag & !ICANON, b"a\rb\n\x01"),
    ] {
        e.set_flags(s, iflag, oflag, lflag);
        e.type_in(m, s, label, text);
    }
    // What the slave writes, as c_oflag says.
    for (label, oflag, text) in [
        ("onlcr", OPOST | ONLCR, &b"a\nb\r\n"[..]),
        ("olcuc xtabs", OPOST | ONLCR | OLCUC | XTABS, b"ab\tc\td\n"),
        ("onocr", OPOST | ONOCR, b"\rx\r\r"),
        ("ocrnl", OPOST | OCRNL, b"a\rb\n"),
        ("onlret", OPOST | ONLRET | OCRNL, b"ab\rc"),
        ("no opost", ONLCR | OLCUC, b"a\nb"),
    ] {
        e.set_flags(s, iflag, oflag, lflag);
        e.write(s, text);
        e.show_drained(label, m, false);
    }
    e.set_flags(s, iflag, oflag, lflag);
    // ^S stops the output, ^Q starts it, and with IXANY any character
    // does.
    e.write(m, b"\x13");
    e.fcntl(s, F_SETFL, O_NONBLOCK);
    let r = e.write(s, b"x");
    e.tried("stopped write", r);
    e.write(m, b"q\x11");
    let r = e.write(s, b"y");
    e.say(format!("started write {r}"));
    e.show_drained("flow", m, false);
    e.show_drained("flow reads", s, true);
    e.set_flags(s, iflag | IXANY, oflag, lflag);
    e.write(m, b"\x13");
    let r = e.write(s, b"x");
    e.tried("stopped write", r);
    e.write(m, b"z");
    let r = e.write(s, b"w");
    e.say(format!("any character {r}"));
    e.show_drained("ixany", m, false);
    e.fcntl(s, F_SETFL, 0);
    check(
        &e.lines,
        &[
            "lines reads 13 \"hello\\x0a|wold\\x0a|\"",
            "lines echo 17 \"hello\\x0d\\x0awor\\x08 \\x08ld\\x0d\\x0a\"",
            "kill reads 2 \"x|\"",
            "kill echo 13 \"abc\\x08 \\x08\\x08 \\x08\\x08 \\x08x\"",
            "word reads 11 \"one three\\x0a|\"",
            "word echo 23 \"one two\\x08 \\x08\\x08 \\x08\\x08 \\x08three\\x0d\\x0a\"",
            "literal reads 4 \"\\x03\\x7f\\x0a|\"",
            "literal echo 10 \"^\\x08^C^\\x08^?\\x0d\\x0a\"",
            "end of file reads 3 \"<0>\"",
            "end of file echo 0 \"\"",
            "reprint reads 5 \"abc\\x0a|\"",
            "reprint echo 12 \"abc^R\\x0d\\x0aabc\\x0d\\x0a\"",
            "tab reads 3 \"a\\x0a|\"",
            "tab echo 15 \"a\\x09b\\x08 \\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x0d\\x0a\"",
            "control reads 3 \"x\\x0a|\"",
            "control echo 11 \"^A\\x08 \\x08\\x08 \\x08x\\x0d\\x0a\"",
            "kill control reads 2 \"\\x0a|\"",
            "kill control echo 14 \"a^B\\x08 \\x08\\x08 \\x08\\x08 \\x08\\x0d\\x0a\"",
            "small read 4 \"abcd\"",
            "small read 3 \"ef\\x0a\"",
            "small echo 8 \"abcdef\\x0d\\x0a\"",
            "echoprt reads 4 \"ad\\x0a|\"",
            "echoprt echo 10 \"abc\\x5ccb/d\\x0d\\x0a\"",
            "echok reads 3 \"c\\x0a|\"",
            "echok echo 9 \"ab^U\\x0d\\x0ac\\x0d\\x0a\"",
            "no echoe reads 4 \"ac\\x0a|\"",
            "no echoe echo 7 \"ab^?c\\x0d\\x0a\"",
            "echonl reads 8 \"secret\\x0a|\"",
            "echonl echo 2 \"\\x0d\\x0a\"",
            "no echoctl reads 3 \"a\\x0a|\"",
            "no echoctl echo 4 \"a\\x01\\x0d\\x0a\"",
            "eol reads 9 \"a;|b#|c\\x0a|\"",
            "eol echo 7 \"a;b#c\\x0d\\x0a\"",
            "disabled reads 5 \"a\\x00\\x7f\\x0a|\"",
            "disabled echo 7 \"a^@^?\\x0d\\x0a\"",
            "igncr reads 4 \"ab\\x0a|\"",
            "igncr echo 4 \"ab\\x0d\\x0a\"",
            "inlcr reads 3 \"a\\x0d|\"",
            "inlcr echo 3 \"a^M\"",
            "iuclc reads 5 \"abc\\x0a|\"",
            "iuclc echo 5 \"abc\\x0d\\x0a\"",
            "istrip reads 3 \"a\\x0a|\"",
            "istrip echo 3 \"a\\x0d\\x0a\"",
            "raw echo reads 6 \"a\\x0ab\\x0a\\x01|\"",
            "raw echo echo 8 \"a\\x0d\\x0ab^J^A\"",
            "onlcr 7 \"a\\x0d\\x0ab\\x0d\\x0d\\x0a\"",
            "olcuc xtabs 19 \"AB      C       D\\x0d\\x0a\"",
            "onocr 2 \"x\\x0d\"",
            "ocrnl 4 \"a\\x0ab\\x0a\"",
            "onlret 4 \"ab\\x0ac\"",
            "no opost 3 \"a\\x0ab\"",
            "stopped write -1 11",
            "started write 1",
            "flow 2 \"qy\"",
            "flow reads 0 \"\"",
            "stopped write -1 11",
            "any character 1",
            "ixany 2 \"zw\"",
        ],
    );
}

/// pty-raw: non-canonical reads by `VMIN` without waiting for `VTIME`, and
/// switching modes with input waiting.
#[test]
fn pty_raw_reads_by_vmin_and_switches_modes_with_input_waiting() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    e.ioctl(s, TCGETS, SAVED);
    let (_, mut t) = e.get_termios(s);
    t.iflag = 0;
    t.oflag = 0;
    t.lflag = 0;
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
    e.set_termios(s, &t);
    e.write(m, b"a\rb\x03\x04\n");
    e.show_drained("raw reads", s, false);
    e.show_drained("raw echo", m, false);
    e.write(s, b"x\ny");
    e.show_drained("raw output", m, false);
    t.cc[VMIN] = 0;
    e.set_termios(s, &t);
    let (r, _) = e.read(s, 16);
    e.say(format!("min 0 time 0 {r}"));
    // Linux's "min 0 time 2" line waits 200 ms for nothing: left to the
    // differential tests.
    t.cc[VTIME] = 2;
    e.set_termios(s, &t);
    e.write(m, b"q");
    let (r, _) = e.read(s, 16);
    e.say(format!("min 0 time 2 with input {r}"));
    t.cc[VMIN] = 3;
    t.cc[VTIME] = 0;
    e.set_termios(s, &t);
    e.write(m, b"12");
    let revents = e.polled(s, POLLIN);
    e.say(format!("min 3 poll {}", hex(revents)));
    e.fcntl(s, F_SETFL, O_NONBLOCK);
    let (r, _) = e.read(s, 16);
    e.say(format!("min 3 nonblocking {r}"));
    let (r, _) = e.read(s, 16);
    e.tried("again", r);
    e.fcntl(s, F_SETFL, 0);
    e.write(m, b"345");
    let revents = e.polled(s, POLLIN);
    e.say(format!("min 3 poll {}", hex(revents)));
    let (r, _) = e.read(s, 16);
    e.say(format!("min 3 read {r}"));
    e.write(m, b"67");
    let (r, _) = e.read(s, 1);
    e.say(format!("min 3 short buffer {r}"));
    e.write(m, b"89");
    let (r, _) = e.read(s, 16);
    e.say(format!("min 3 rest {r}"));
    // Linux's "min 2 time 1" line waits out VTIME after one byte: left to
    // the differential tests.
    // Raw input becomes one line in canonical mode; a canonical end of file
    // reads as a 0 byte in raw mode.
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
    e.set_termios(s, &t);
    e.write(m, b"x\ny");
    assert_eq!(e.ioctl(s, TCSETS, SAVED), 0);
    e.show_drained("to canonical", s, true);
    e.show_drained("to canonical echo", m, false);
    e.write(m, b"ab\x04");
    e.set_termios(s, &t);
    e.show_drained("to raw", s, true);
    check(
        &e.lines,
        &[
            "raw reads 6 \"a\\x0db\\x03\\x04\\x0a\"",
            "raw echo 0 \"\"",
            "raw output 3 \"x\\x0ay\"",
            "min 0 time 0 0",
            "min 0 time 2 with input 1",
            "min 3 poll 0",
            "min 3 nonblocking 2",
            "again -1 11",
            "min 3 poll 0x1",
            "min 3 read 3",
            "min 3 short buffer 1",
            "min 3 rest 3",
            "to canonical 4 \"x\\x0ay|\"",
            "to canonical echo 0 \"\"",
            "to raw 4 \"ab\\x00|\"",
        ],
    );
}

/// pty-packet: `TIOCPKT`'s status bytes for flushes, flow control, the
/// stop characters and `EXTPROC`, and data after a 0 byte.
#[test]
fn pty_packet_reports_flushes_flow_and_mode_changes() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let (r, _) = e.ioctl_int(s, TIOCPKT, 1);
    e.tried("TIOCPKT slave", r);
    let (r, _) = e.ioctl_int(s, TIOCGPKT, -1);
    e.tried("TIOCGPKT slave", r);
    let (r, mode) = e.ioctl_int(m, TIOCGPKT, -1);
    e.tried("TIOCGPKT", r);
    e.say(format!("mode {mode}"));
    let r = e.ioctl(m, TIOCPKT, 0);
    e.tried("TIOCPKT fault", r);
    // Events before packet mode are not kept.
    e.ioctl(s, TCFLSH, 0);
    let (r, _) = e.ioctl_int(m, TIOCPKT, 1);
    e.tried("TIOCPKT", r);
    let (r, mode) = e.ioctl_int(m, TIOCGPKT, -1);
    e.tried("TIOCGPKT", r);
    e.say(format!("mode {mode}"));
    let revents = e.polled(m, POLLIN | POLLPRI);
    e.say(format!("poll empty {}", hex(revents)));
    e.write(s, b"hi");
    e.show_drained("data", m, true);
    e.ioctl(s, TCFLSH, 0);
    let revents = e.polled(m, POLLIN | POLLPRI);
    e.say(format!("poll flush {}", hex(revents)));
    e.show_drained("flush input", m, true);
    e.ioctl(s, TCFLSH, 1);
    e.show_drained("flush output", m, true);
    e.ioctl(s, TCFLSH, 2);
    e.show_drained("flush both", m, true);
    // The master's own flushes are not events.
    e.ioctl(m, TCFLSH, 2);
    e.show_drained("master flush", m, true);
    e.ioctl(s, TCXONC, 0);
    e.show_drained("tcoff", m, true);
    e.ioctl(s, TCXONC, 0);
    e.show_drained("tcoff again", m, true);
    e.ioctl(s, TCXONC, 1);
    e.show_drained("tcon", m, true);
    // Two events before a read: a start forgets the stop.
    e.ioctl(s, TCXONC, 0);
    e.ioctl(s, TCXONC, 1);
    e.show_drained("stop then start", m, true);
    e.ioctl(s, TCGETS, SAVED);
    let set = |e: &mut Env, fd: i64, request: u64, change: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = e.get(SAVED, 36);
        change(&mut bytes);
        e.put(SAVED, &bytes);
        assert_eq!(e.ioctl(fd, request, SAVED), 0);
    };
    let flag = |bytes: &mut Vec<u8>, at: usize, f: &dyn Fn(u32) -> u32| {
        let v = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&f(v).to_le_bytes());
    };
    set(&mut e, s, TCSETS, &|b| flag(b, 0, &|v| v & !IXON));
    e.show_drained("no ixon", m, true);
    set(&mut e, m, TCSETS, &|b| flag(b, 0, &|v| v | IXON));
    e.show_drained("ixon from master", m, true);
    set(&mut e, s, TCSETS, &|b| b[17 + VSTOP] = 1);
    e.show_drained("other stop char", m, true);
    set(&mut e, s, TCSETSF, &|b| b[17 + VSTOP] = 0o23);
    e.show_drained("tcsaflush", m, true);
    set(&mut e, s, TCSETS, &|b| flag(b, 12, &|v| v | EXTPROC));
    e.show_drained("extproc", m, true);
    set(&mut e, s, TCSETS, &|b| flag(b, 12, &|v| v & !EXTPROC));
    e.show_drained("extproc off", m, true);
    // ^S and ^Q typed, and ^C, which flushes both ways and echoes.
    e.write(m, b"\x13");
    e.show_drained("typed stop", m, true);
    e.write(m, b"\x11");
    e.show_drained("typed start", m, true);
    e.write(m, b"ab\x03");
    e.show_drained("interrupt", m, true);
    // A one-byte read of data gives the 0 byte alone.
    e.write(s, b"xy");
    let (r, bytes) = e.read(m, 1);
    e.tried("short read", r);
    e.say(format!("short byte {}", bytes[0]));
    e.show_drained("rest", m, true);
    let (r, _) = e.ioctl_int(m, TIOCPKT, 0);
    e.tried("TIOCPKT off", r);
    e.ioctl(s, TCFLSH, 0);
    e.write(s, b"z");
    e.show_drained("off", m, true);
    e.close(s);
    e.close(m);
    check(
        &e.lines,
        &[
            "TIOCPKT slave -1 25",
            "TIOCGPKT slave -1 25",
            "TIOCGPKT 0 0",
            "mode 0",
            "TIOCPKT fault -1 14",
            "TIOCPKT 0 0",
            "TIOCGPKT 0 0",
            "mode 1",
            "poll empty 0",
            "data 4 \"\\x00hi|\"",
            "poll flush 0x3",
            "flush input 2 \"\\x01|\"",
            "flush output 2 \"\\x02|\"",
            "flush both 2 \"\\x03|\"",
            "master flush 0 \"\"",
            "tcoff 2 \"\\x04|\"",
            "tcoff again 0 \"\"",
            "tcon 2 \"\\x08|\"",
            "stop then start 2 \"\\x08|\"",
            "no ixon 2 \"\\x10|\"",
            "ixon from master 2 \" |\"",
            "other stop char 2 \"\\x10|\"",
            "tcsaflush 2 \"!|\"",
            "extproc 2 \"@|\"",
            "extproc off 2 \"@|\"",
            "typed stop 2 \"\\x04|\"",
            "typed start 2 \"\\x08|\"",
            "interrupt 6 \"\\x03|\\x00^C|\"",
            "short read 1 0",
            "short byte 0",
            "rest 4 \"\\x00xy|\"",
            "TIOCPKT off 0 0",
            "off 2 \"z|\"",
        ],
    );
}

/// The kernel's `struct termio` at `ARG`, as the guest's `show_termio`
/// prints it.
fn show_termio(e: &mut Env, label: &str) {
    let bytes = e.get(ARG, 17);
    let half = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
    let cc: Vec<String> = bytes[9..17].iter().map(u8::to_string).collect();
    e.say(format!(
        "{label} {:04x} {:04x} {:04x} {:04x} {} {}",
        half(0),
        half(2),
        half(4),
        half(6),
        bytes[8],
        cc.join(" ")
    ));
}

/// pty-termio: the old `struct termio`, which keeps the flags' high bits
/// and the other characters, and the slave's locked termios.
#[test]
fn pty_termio_keeps_the_rest_and_the_locked_termios_is_empty() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    e.put(ARG, &[0xff; 18]);
    let r = e.ioctl(s, TCGETA, ARG);
    e.tried("TCGETA", r);
    show_termio(&mut e, "slave");
    let r = e.ioctl(m, TCGETA, ARG);
    e.tried("TCGETA master", r);
    show_termio(&mut e, "master");
    let r = e.ioctl(s, TCGETA, 0);
    e.tried("TCGETA fault", r);
    let r = e.ioctl(s, TCSETA, 0);
    e.tried("TCSETA fault", r);
    // The high bits of the flags and the other characters stay.
    let termio = e.get(ARG, 18);
    let (_, mut full) = e.get_termios(s);
    full.lflag |= EXTPROC;
    full.cc[VEOL2] = 7;
    e.set_termios(s, &full);
    let mut termio = termio;
    let lflag = u16::from_le_bytes([termio[6], termio[7]]) & !(ECHO as u16);
    termio[6..8].copy_from_slice(&lflag.to_le_bytes());
    termio[9 + VINTR] = 1;
    let cflag = u16::from_le_bytes([termio[4], termio[5]]);
    let cflag = (cflag & !(CBAUD as u16)) | B9600 as u16 | PARENB as u16;
    termio[4..6].copy_from_slice(&cflag.to_le_bytes());
    e.put(ARG, &termio);
    let r = e.ioctl(m, TCSETA, ARG);
    e.tried("TCSETA", r);
    let (_, mut full) = e.get_termios(s);
    e.say(format!(
        "after {:o} {:o} {:o} {} {} speed {} {}",
        full.lflag,
        full.cflag,
        full.iflag,
        full.cc[VINTR],
        full.cc[VEOL2],
        full.cflag & CBAUD,
        full.cflag & CBAUD
    ));
    // musl's cfmakeraw.
    full.iflag &= !(0o1 | 0o2 | 0o10 | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    full.oflag &= !OPOST;
    full.lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    full.cflag = (full.cflag & !(CSIZE | PARENB)) | CSIZE;
    full.cc[VMIN] = 1;
    full.cc[VTIME] = 0;
    e.set_termios(s, &full);
    e.write(m, b"abc");
    let (_, count) = e.ioctl_int(s, FIONREAD, -1);
    e.say(format!("queued {count}"));
    e.ioctl(s, TCGETA, ARG);
    let r = e.ioctl(s, TCSETAF, ARG);
    e.tried("TCSETAF", r);
    let (_, count) = e.ioctl_int(s, FIONREAD, -1);
    e.say(format!("queued after {count}"));
    e.put(ARG, &[0xff; 60]);
    let r = e.ioctl(s, TIOCGLCKTRMIOS, ARG);
    e.tried("TIOCGLCKTRMIOS", r);
    let nonzero = e.get(ARG, 36).iter().filter(|&&b| b != 0).count();
    e.say(format!("locked nonzero {nonzero}"));
    let r = e.ioctl(m, TIOCGLCKTRMIOS, ARG);
    e.tried("TIOCGLCKTRMIOS master", r);
    let r = e.ioctl(s, TIOCGLCKTRMIOS, 0);
    e.tried("TIOCGLCKTRMIOS fault", r);
    // Only CAP_SYS_ADMIN locks, which is checked before the address: the
    // guest's line as Linux gives it to a user without it.
    assert_eq!(e.call(SETRESUID, [1000, 1000, 1000, 0, 0, 0]), 0);
    let r = e.ioctl(s, TIOCSLCKTRMIOS, 0);
    e.tried("TIOCSLCKTRMIOS", r);
    e.close(s);
    e.close(m);
    check(
        &e.lines,
        &[
            "TCGETA 0 0",
            "slave 0500 0005 00bf 8a3b 0 3 28 127 21 4 0 1 0",
            "TCGETA master 0 0",
            "master 0500 0005 00bf 8a3b 0 3 28 127 21 4 0 1 0",
            "TCGETA fault -1 14",
            "TCSETA fault -1 14",
            "TCSETA 0 0",
            "after 305063 275 2400 1 7 speed 13 13",
            "queued 3",
            "TCSETAF 0 0",
            "queued after 0",
            "TIOCGLCKTRMIOS 0 0",
            "locked nonzero 0",
            "TIOCGLCKTRMIOS master 0 0",
            "TIOCGLCKTRMIOS fault -1 14",
            "TIOCSLCKTRMIOS -1 1",
        ],
    );
}

/// pty-session: taking the controlling terminal, `/dev/tty`, the
/// foreground group, an orphaned background group's reads and writes, and
/// letting the terminal go. The jobs a background read or write stops wait
/// for the stop, so they stay with the differential tests.
#[test]
fn pty_session_takes_the_terminal_sets_the_foreground_and_lets_it_go() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let (_, number) = e.ioctl_int(m, TIOCGPTN, -1);
    let name = format!("/dev/pts/{number}");
    let mut c = e.fork();
    e.close(s);
    c.close(m);
    let r = c.ioctl(s, TIOCSCTTY, 0);
    c.tried("TIOCSCTTY before setsid", r);
    let r = c.call(SETSID, [0; 6]);
    c.say(format!("setsid {}", (r == c.pid()) as i32));
    let (r, _) = c.ioctl_int(s, TIOCGSID, 0);
    c.tried("tcgetsid", r);
    let (r, _) = c.ioctl_int(s, TIOCGPGRP, 0);
    c.tried("tcgetpgrp", r);
    let r = c.open("/dev/tty", O_RDWR);
    c.tried("open /dev/tty", r);
    let r = c.ioctl(s, TIOCSCTTY, 0);
    c.say(format!("TIOCSCTTY {r}"));
    let (_, sid) = c.ioctl_int(s, TIOCGSID, 0);
    let (_, pgrp) = c.ioctl_int(s, TIOCGPGRP, 0);
    c.say(format!(
        "tcgetsid {} tcgetpgrp {}",
        (i64::from(sid) == c.pid()) as i32,
        (i64::from(pgrp) == c.pid()) as i32
    ));
    let r = c.ioctl(s, TIOCSCTTY, 0);
    c.say(format!("TIOCSCTTY again {r}"));
    let (other_m, other_s) = c.openpty();
    let r = c.ioctl(other_s, TIOCSCTTY, 0);
    c.tried("TIOCSCTTY of another", r);
    c.close(other_s);
    c.close(other_m);
    let tty = c.open("/dev/tty", O_RDWR);
    c.call(FSTAT, [tty as u64, STAT, 0, 0, 0, 0]);
    let (_, _, _, rdev) = stat_fields(&c);
    c.say(format!(
        "/dev/tty {} {} {}",
        (tty >= 0) as i32,
        (major(rdev) == 5) as i32,
        (minor(rdev) == 0) as i32
    ));
    c.write(tty, b"through /dev/tty\n");
    c.close(tty);
    let ppid = e.pid() as i32;
    for (label, pgrp) in [
        ("tcsetpgrp missing", 0x3fff_fff0),
        ("tcsetpgrp other session", ppid),
        ("tcsetpgrp negative", -1),
        ("tcsetpgrp zero", 0),
    ] {
        let (r, _) = c.ioctl_int(s, TIOCSPGRP, pgrp);
        c.tried(label, r);
    }
    // A job in the foreground.
    let mut job = c.fork();
    assert_eq!(job.call(SETPGID, [0; 6]), 0);
    let job_pid = job.pid();
    assert_eq!(
        c.call(SETPGID, [job_pid as u64, job_pid as u64, 0, 0, 0, 0]),
        0
    );
    let (r, _) = c.ioctl_int(s, TIOCSPGRP, job_pid as i32);
    c.tried("tcsetpgrp", r);
    let (_, pgrp) = c.ioctl_int(s, TIOCGPGRP, 0);
    c.say(format!(
        "foreground {}",
        (i64::from(pgrp) == job_pid) as i32
    ));
    // The leader is in the background now, its group orphaned.
    let (r, _) = c.read(s, 1);
    c.tried("background read", r);
    let r = c.write(s, b"bg\n");
    c.say(format!("background write {r}"));
    c.ioctl(s, TCGETS, SAVED);
    let r = c.ioctl(s, TCSETS, SAVED);
    c.tried("background tcsetattr", r);
    c.disposition(SIGTTOU, 1);
    let lflag = c.int(SAVED + 12) as u32 | TOSTOP;
    c.put_int(SAVED + 12, lflag as i32);
    let r = c.ioctl(s, TCSETS, SAVED);
    c.say(format!("tcsetattr ignoring SIGTTOU {r}"));
    let r = c.write(s, b"ok\n");
    c.say(format!("TOSTOP write ignoring SIGTTOU {r}"));
    c.disposition(SIGTTOU, 0);
    let r = c.write(s, b"no\n");
    c.tried("TOSTOP write", r);
    c.disposition(SIGTTOU, 1);
    let own = c.pid() as i32;
    let (r, _) = c.ioctl_int(s, TIOCSPGRP, own);
    c.tried("tcsetpgrp back", r);
    let (_, pgrp) = c.ioctl_int(s, TIOCGPGRP, 0);
    c.say(format!("foreground {}", (pgrp == own) as i32));
    c.disposition(SIGTTOU, 0);
    job.exit(&mut c, 0);
    c.wait(job_pid);
    // A process other than the leader lets the terminal go alone.
    let mut member = c.fork();
    let r = member.ioctl(s, TIOCNOTTY, 0);
    member.say(format!("member TIOCNOTTY {r}"));
    let r = member.open("/dev/tty", O_RDWR);
    member.tried("member /dev/tty", r);
    let member_pid = member.pid();
    member.exit(&mut c, 0);
    c.wait(member_pid);
    let (_, sid) = c.ioctl_int(s, TIOCGSID, 0);
    c.say(format!("leader still has it {}", (sid == own) as i32));
    // The leader's TIOCNOTTY hangs up its foreground group.
    c.disposition(SIGHUP, 1);
    let r = c.ioctl(s, TIOCNOTTY, 0);
    c.say(format!("TIOCNOTTY {r}"));
    let (r, _) = c.ioctl_int(s, TIOCGSID, 0);
    c.tried("after TIOCNOTTY", r);
    let r = c.ioctl(s, TIOCNOTTY, 0);
    c.tried("TIOCNOTTY again", r);
    // Opening it without O_NOCTTY takes it again, not for writing only.
    let again = c.open(&name, O_WRONLY);
    let (r, _) = c.ioctl_int(again, TIOCGSID, 0);
    c.tried("write-only open", r);
    c.close(again);
    let again = c.open(&name, O_RDWR);
    let (_, sid) = c.ioctl_int(again, TIOCGSID, 0);
    c.say(format!("open takes it {}", (sid == own) as i32));
    let child = c.pid();
    c.exit(&mut e, 7);
    let status = e.wait(child);
    // The guest's show_to_end: the master reads until its end.
    let mut all = Vec::new();
    let end = loop {
        let (n, bytes) = e.read(m, 0x1000);
        if n <= 0 {
            break n;
        }
        all.extend_from_slice(&bytes);
    };
    e.show("master", &all);
    let (n, errno) = if end < 0 { (-1, -end) } else { (end, 0) };
    e.say(format!("master end {n} {errno}"));
    e.say(format!("child {}", (status >> 8) & 0xff));
    check(
        &e.lines,
        &[
            "TIOCSCTTY before setsid -1 1",
            "setsid 1",
            "tcgetsid -1 25",
            "tcgetpgrp -1 25",
            "open /dev/tty -1 6",
            "TIOCSCTTY 0",
            "tcgetsid 1 tcgetpgrp 1",
            "TIOCSCTTY again 0",
            "TIOCSCTTY of another -1 1",
            "/dev/tty 1 1 1",
            "tcsetpgrp missing -1 3",
            "tcsetpgrp other session -1 1",
            "tcsetpgrp negative -1 22",
            "tcsetpgrp zero -1 3",
            "tcsetpgrp 0 0",
            "foreground 1",
            "background read -1 5",
            "background write 3",
            "background tcsetattr -1 5",
            "tcsetattr ignoring SIGTTOU 0",
            "TOSTOP write ignoring SIGTTOU 3",
            "TOSTOP write -1 5",
            "tcsetpgrp back 0 0",
            "foreground 1",
            "member TIOCNOTTY 0",
            "member /dev/tty -1 6",
            "leader still has it 1",
            "TIOCNOTTY 0",
            "after TIOCNOTTY -1 25",
            "TIOCNOTTY again -1 25",
            "write-only open -1 25",
            "open takes it 1",
            "master 26 \"through /dev/tty\\x0d\\x0abg\\x0d\\x0aok\\x0d\\x0a\"",
            "master end -1 5",
            "child 7",
        ],
    );
}

/// The signals a pty-signals child handles: SIGINT, SIGQUIT, SIGTSTP,
/// SIGWINCH and SIGUSR1.
const HANDLED: u64 = 1 << 1 | 1 << 2 | 1 << 19 | 1 << 27 | 1 << 9;

/// The signal a pty-signals child takes next, which the guest's handler
/// writes to its pipe: this one blocks them, so it takes it with a
/// `sigtimedwait` that does not wait.
fn taken(c: &mut Env) -> i64 {
    c.put(SAVED, &HANDLED.to_le_bytes());
    c.put(SAVED + 8, &[0; 16]);
    c.call(RT_SIGTIMEDWAIT, [SAVED, 0, SAVED + 8, 8, 0, 0])
}

/// pty-signals: the signals the terminal sends its foreground group, as
/// typed, through `TIOCSIG` and as the window changes, and `NOFLSH`.
/// Linux's line for the child's death by SIGTERM stays with the
/// differential tests.
#[test]
fn pty_signals_go_to_the_foreground_group() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let mut c = e.fork();
    c.close(m);
    c.call(SETSID, [0; 6]);
    assert_eq!(c.ioctl(s, TIOCSCTTY, 0), 0);
    c.put(ARG, &HANDLED.to_le_bytes());
    assert_eq!(c.call(RT_SIGPROCMASK, [0, ARG, 0, 8, 0, 0]), 0);
    let child = c.pid();
    c.call(KILL, [child as u64, SIGUSR1, 0, 0, 0, 0]);
    let byte = taken(&mut c);
    e.say(format!("ready {byte}"));
    let (_, pgrp) = e.ioctl_int(m, TIOCGPGRP, 0);
    let (_, sid) = e.ioctl_int(m, TIOCGSID, 0);
    e.say(format!(
        "tcgetpgrp of the master {} tcgetsid {}",
        (i64::from(pgrp) == child) as i32,
        (i64::from(sid) == child) as i32
    ));
    for (label, text) in [
        ("intr", b"ab\x03"),
        ("quit", b"cd\x1c"),
        ("susp", b"ef\x1a"),
    ] {
        e.write(m, text);
        let byte = taken(&mut c);
        let (_, count) = e.ioctl_int(s, FIONREAD, -1);
        e.say(format!("{label} {byte} unread {count}"));
    }
    e.show_drained("echo", m, false);
    e.ioctl(m, TCGETS, SAVED);
    let lflag = e.int(SAVED + 12) as u32 | NOFLSH;
    e.put_int(SAVED + 12, lflag as i32);
    assert_eq!(e.ioctl(m, TCSETS, SAVED), 0);
    e.write(m, b"gh\x03");
    let byte = taken(&mut c);
    e.write(m, b"\n");
    let (_, line) = e.read(s, 16);
    e.say(format!("noflsh {byte}"));
    e.show("kept", &line);
    e.show_drained("noflsh echo", m, false);
    let r = e.ioctl(m, TIOCSIG, 3);
    e.say(format!("TIOCSIG {r}"));
    let byte = taken(&mut c);
    e.say(format!("signal {byte}"));
    let r = e.ioctl(m, TIOCSIG, 9);
    e.tried("TIOCSIG 9", r);
    let r = e.ioctl(s, TIOCSIG, 2);
    e.tried("TIOCSIG of the slave", r);
    let mut w = Vec::new();
    for v in [10u16, 20, 0, 0] {
        w.extend_from_slice(&v.to_le_bytes());
    }
    e.put(ARG, &w);
    let r = e.ioctl(m, TIOCSWINSZ, ARG);
    e.say(format!("TIOCSWINSZ {r}"));
    let byte = taken(&mut c);
    e.say(format!("signal {byte}"));
    // The same size again sends nothing.
    e.ioctl(s, TIOCSWINSZ, ARG);
    e.ioctl(m, TIOCSIG, 2);
    let byte = taken(&mut c);
    e.say(format!("next signal {byte}"));
    let lflag = lflag & !ISIG;
    e.put_int(SAVED + 12, lflag as i32);
    assert_eq!(e.ioctl(m, TCSETS, SAVED), 0);
    e.write(m, b"\x03\n");
    let (_, line) = e.read(s, 16);
    e.show("no isig", &line);
    e.show_drained("echo", m, false);
    check(
        &e.lines,
        &[
            "ready 10",
            "tcgetpgrp of the master 1 tcgetsid 1",
            "intr 2 unread 0",
            "quit 3 unread 0",
            "susp 20 unread 0",
            "echo 6 \"^C^\\x5c^Z\"",
            "noflsh 2",
            "kept 3 \"gh\\x0a\"",
            "noflsh echo 6 \"gh^C\\x0d\\x0a\"",
            "TIOCSIG 0",
            "signal 3",
            "TIOCSIG 9 -1 22",
            "TIOCSIG of the slave -1 25",
            "TIOCSWINSZ 0",
            "signal 28",
            "next signal 2",
            "no isig 2 \"\\x03\\x0a\"",
            "echo 4 \"^C\\x0d\\x0a\"",
        ],
    );
}

/// The signals pending for the process, as a mask of `1 << (number - 1)`.
fn pending(c: &mut Env) -> u64 {
    assert_eq!(c.call(RT_SIGPENDING, [ARG, 8, 0, 0, 0, 0]), 0);
    c.m.read_u64(GuestAddr(ARG)).unwrap()
}

/// pty-hangup: the master's close hangs up the slave and tells the
/// session's leader; the leader's exit tells its foreground group. The
/// guest's handlers write each signal to a pipe; these processes block
/// every signal and read which are pending.
#[test]
fn pty_hangup_tells_the_leader_and_the_foreground_group() {
    let mut e = Env::new();
    assert_eq!(e.call(PRCTL, [PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0]), 0);
    let (m, s) = e.openpty();
    let (_, number) = e.ioctl_int(m, TIOCGPTN, -1);
    let name = format!("/dev/pts/{number}");
    let mut c = e.fork();
    c.close(m);
    c.close(s);
    c.call(SETSID, [0; 6]);
    let tty = c.open(&name, O_RDWR);
    let (_, sid) = c.ioctl_int(tty, TIOCGSID, 0);
    c.say(format!(
        "taken on open {}",
        (i64::from(sid) == c.pid()) as i32
    ));
    c.put(ARG, &u64::MAX.to_le_bytes());
    assert_eq!(c.call(RT_SIGPROCMASK, [0, ARG, 0, 8, 0, 0]), 0);
    e.close(s);
    e.close(m);
    let signals = pending(&mut c);
    let hup = (signals >> (SIGHUP - 1)) & 1;
    let cont = (signals >> (SIGCONT - 1)) & 1;
    c.say(format!("hangup {hup} {cont}"));
    let (r, _) = c.read(tty, 4);
    c.say(format!("read {r}"));
    let r = c.write(tty, b"x");
    c.tried("write", r);
    let (r, _) = c.ioctl_int(tty, TIOCGSID, 0);
    c.tried("tcgetsid", r);
    let r = c.open("/dev/tty", O_RDWR);
    c.tried("/dev/tty", r);
    let revents = c.polled(tty, POLLIN | POLLOUT);
    c.say(format!("poll {}", hex(revents)));
    let child = c.pid();
    c.exit(&mut e, 0);
    let status = e.wait(child);
    let numbers: Vec<String> = (1..=64)
        .filter(|n| signals >> (n - 1) & 1 != 0)
        .map(|n: u64| n.to_string())
        .collect();
    e.say(format!("signals {}", numbers.join(" ")));
    e.say(format!("child {}", (status >> 8) & 0xff));
    // A leader's exit hangs up its foreground job.
    let (m, s) = e.openpty();
    let mut c = e.fork();
    c.close(m);
    c.call(SETSID, [0; 6]);
    assert_eq!(c.ioctl(s, TIOCSCTTY, 0), 0);
    let mut job = c.fork();
    assert_eq!(job.call(SETPGID, [0; 6]), 0);
    job.put(ARG, &(1u64 << (SIGHUP - 1)).to_le_bytes());
    assert_eq!(job.call(RT_SIGPROCMASK, [0, ARG, 0, 8, 0, 0]), 0);
    let job_pid = job.pid();
    c.call(SETPGID, [job_pid as u64, job_pid as u64, 0, 0, 0, 0]);
    assert_eq!(c.ioctl_int(s, TIOCSPGRP, job_pid as i32).0, 0);
    e.close(s);
    let leader = c.pid();
    c.exit(&mut e, 4);
    let status = e.wait(leader);
    e.say(format!("leader {}", (status >> 8) & 0xff));
    let got = (pending(&mut job) >> (SIGHUP - 1)) & 1;
    e.say(format!("job got {}", if got != 0 { SIGHUP } else { 0 }));
    let (r, _) = job.ioctl_int(s, TIOCGSID, 0);
    job.exit(&mut e, if r < 0 { -r as i32 } else { 0 });
    let r = e.call(WAIT4, [u64::MAX, ARG, 0, 0, 0, 0]);
    let status = e.int(ARG);
    e.say(format!(
        "job {} sees {}",
        (r > 0) as i32,
        (status >> 8) & 0xff
    ));
    let mut all = Vec::new();
    let end = loop {
        let (n, bytes) = e.read(m, 0x1000);
        if n <= 0 {
            break n;
        }
        all.extend_from_slice(&bytes);
    };
    e.show("master", &all);
    let (n, errno) = if end < 0 { (-1, -end) } else { (end, 0) };
    e.say(format!("master end {n} {errno}"));
    check(
        &e.lines,
        &[
            "taken on open 1",
            "hangup 1 1",
            "read 0",
            "write -1 5",
            "tcgetsid -1 5",
            "/dev/tty -1 6",
            "poll 0x1d",
            "signals 1 18",
            "child 0",
            "leader 4",
            "job got 1",
            "job 1 sees 25",
            "master 0 \"\"",
            "master end -1 5",
        ],
    );
}

/// The guest's `collect`: the queued signals of `number`, each as its
/// code, band and whether its descriptor is `fd`, the same in a row once.
fn collect(e: &mut Env, label: &str, number: u64, fd: i64) {
    let mut line = label.to_owned();
    let mut count = 0;
    let mut last = (0, 0);
    loop {
        e.put(SAVED, &(1u64 << (number - 1)).to_le_bytes());
        e.put(SAVED + 8, &[0; 16]);
        let info = SAVED + 0x40;
        if e.call(RT_SIGTIMEDWAIT, [SAVED, info, SAVED + 8, 8, 0, 0]) != number as i64 {
            break;
        }
        let code = e.int(info + 8);
        let band = e.m.read_u64(GuestAddr(info + 16)).unwrap();
        let from = e.int(info + 24);
        count += 1;
        if count > 1 && (code, band) == last {
            continue;
        }
        last = (code, band);
        line.push_str(&format!(
            " {code}/{band:#x}/{}",
            (i64::from(from) == fd) as i32
        ));
    }
    if count == 0 {
        line.push_str(" none");
    }
    e.say(line);
}

fn show_owner(e: &mut Env, label: &str, fd: i64) {
    e.put(ARG, &[0xff; 8]);
    e.fcntl(fd, F_GETOWN_EX, ARG);
    let kind = e.int(ARG);
    let own = e.fcntl(fd, F_GETOWN, 0);
    let pid = e.pid();
    let pgrp = e.call(GETPGRP, [0; 6]);
    e.say(format!(
        "{label} type {kind} self {} group {}",
        (own == pid) as i32,
        (own < 0 && -own == pgrp) as i32
    ));
}

/// pty-async: `O_ASYNC` on either side, who owns the file, which input
/// signals, the room after a short write, and the hang-up that turns it
/// off.
#[test]
fn pty_async_signals_input_output_and_room_until_the_hang_up() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let (input, output) = (36, 37);
    let block = 1u64 << (input - 1) | 1 << (output - 1) | 1 << (SIGIO - 1);
    e.put(ARG, &block.to_le_bytes());
    assert_eq!(e.call(RT_SIGPROCMASK, [0, ARG, 0, 8, 0, 0]), 0);
    show_owner(&mut e, "before", s);
    let r = e.fcntl(s, F_SETFL, O_ASYNC);
    e.tried("F_SETFL", r);
    let on = e.fcntl(s, F_GETFL, 0) as u64 & O_ASYNC != 0;
    e.say(format!("O_ASYNC {}", on as i32));
    show_owner(&mut e, "slave", s);
    e.fcntl(s, F_SETSIG, input);
    // Canonical input signals at the end of a line.
    e.write(m, b"ab");
    collect(&mut e, "partial line", input, s);
    e.write(m, b"c\n");
    collect(&mut e, "line", input, s);
    e.read(s, 0x2000);
    e.write(m, b"\x04");
    collect(&mut e, "end of file", input, s);
    e.read(s, 0x2000);
    let (_, mut t) = e.get_termios(s);
    t.iflag &= !(0o1 | 0o2 | 0o10 | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.oflag &= !OPOST;
    t.lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.cflag = (t.cflag & !(CSIZE | PARENB)) | CSIZE;
    t.cc[VMIN] = 1;
    t.cc[VTIME] = 0;
    e.set_termios(s, &t);
    collect(&mut e, "raw", input, s);
    e.write(m, b"x");
    collect(&mut e, "raw byte", input, s);
    e.read(s, 0x2000);
    // The master: an owner set before stays.
    let pid = e.pid() as u64;
    let r = e.fcntl(m, F_SETOWN, pid);
    e.tried("F_SETOWN master", r);
    let (r, _) = e.ioctl_int(m, FIOASYNC, 1);
    e.tried("FIOASYNC master", r);
    let on = e.fcntl(m, F_GETFL, 0) as u64 & O_ASYNC != 0;
    e.say(format!("master O_ASYNC {}", on as i32));
    show_owner(&mut e, "master", m);
    e.fcntl(m, F_SETSIG, output);
    e.write(s, b"out");
    collect(&mut e, "slave output", output, m);
    e.read(m, 0x2000);
    collect(&mut e, "master read", output, m);
    // Packet events wake the master but do not signal.
    e.ioctl_int(m, TIOCPKT, 1);
    e.ioctl(s, TCXONC, 0);
    let revents = e.polled(m, POLLPRI);
    e.say(format!("packet poll {}", hex(revents)));
    collect(&mut e, "packet stop", output, m);
    e.ioctl(s, TCXONC, 1);
    e.read(m, 0x2000);
    collect(&mut e, "packet start", output, m);
    e.ioctl_int(m, TIOCPKT, 0);
    // A master that fills the slave's input gets POLL_OUT for room once
    // the slave reads; a write that went whole does not.
    e.fcntl(m, F_SETFL, O_ASYNC | O_NONBLOCK);
    e.fcntl(s, F_SETFL, O_ASYNC | O_NONBLOCK);
    let mut written = 0;
    let last = loop {
        let n = e.call(WRITE, [m as u64, BUF, 0x2000, 0, 0, 0]);
        if n <= 0 {
            break n;
        }
        written += n;
    };
    e.say(format!("filled {} {}", (written > 4096) as i32, -last));
    collect(&mut e, "full", output, m);
    collect(&mut e, "slave input", input, s);
    let mut taken = 0;
    let mut quiet = 0;
    while quiet < 3 {
        let (n, _) = e.read(s, 0x2000);
        if n > 0 {
            taken += n;
            quiet = 0;
        } else {
            quiet += 1;
        }
    }
    e.say(format!("drained {}", (taken == written) as i32));
    let room = (pending(&mut e) >> (output - 1)) & 1;
    e.say(format!("room {room}"));
    collect(&mut e, "room", output, m);
    // The slave's descriptions lose O_ASYNC with the master's close, and
    // cannot take it again.
    e.close(m);
    let on = e.fcntl(s, F_GETFL, 0) as u64 & O_ASYNC != 0;
    e.say(format!("hung up O_ASYNC {}", on as i32));
    let r = e.fcntl(s, F_SETFL, O_ASYNC);
    e.tried("F_SETFL hung up", r);
    let (r, _) = e.ioctl_int(s, FIOASYNC, 1);
    e.tried("FIOASYNC hung up", r);
    let r = e.fcntl(s, F_SETFL, O_NONBLOCK);
    e.tried("F_SETFL hung up other", r);
    e.close(s);
    // The slave's foreground group owns a file that had no owner.
    let (m, s) = e.openpty();
    let (_, number) = e.ioctl_int(m, TIOCGPTN, -1);
    let mut c = e.fork();
    c.close(m);
    c.call(SETSID, [0; 6]);
    c.ioctl(s, TIOCSCTTY, 0);
    let r = c.fcntl(s, F_SETFL, O_ASYNC);
    c.tried("F_SETFL controlling", r);
    show_owner(&mut c, "controlling", s);
    let again = c.open(&format!("/dev/pts/{number}"), O_RDWR);
    let r = c.fcntl(again, F_SETOWN, 0);
    c.tried("F_SETOWN 0", r);
    c.fcntl(again, F_SETFL, O_ASYNC);
    show_owner(&mut c, "no owner", again);
    let child = c.pid();
    c.exit(&mut e, 0);
    e.wait(child);
    e.close(s);
    e.close(m);
    check(
        &e.lines,
        &[
            "before type 0 self 0 group 0",
            "F_SETFL 0 0",
            "O_ASYNC 1",
            "slave type 1 self 1 group 0",
            "partial line none",
            "line 1/0x41/1",
            "end of file 1/0x41/1",
            "raw none",
            "raw byte 1/0x41/1",
            "F_SETOWN master 0 0",
            "FIOASYNC master 0 0",
            "master O_ASYNC 1",
            "master type 1 self 1 group 0",
            "slave output 1/0x41/1",
            "master read none",
            "packet poll 0x2",
            "packet stop none",
            "packet start none",
            "filled 1 11",
            "full none",
            "slave input 1/0x41/1",
            "drained 1",
            "room 1",
            "room 2/0x304/1",
            "hung up O_ASYNC 0",
            "F_SETFL hung up -1 25",
            "FIOASYNC hung up -1 25",
            "F_SETFL hung up other 0 0",
            "F_SETFL controlling 0 0",
            "controlling type 2 self 0 group 1",
            "F_SETOWN 0 0 0",
            "no owner type 2 self 0 group 1",
        ],
    );
}

/// The guest's `show_hung_up`: what a hung-up file of either side answers.
fn show_hung_up(e: &mut Env, label: &str, fd: i64) {
    let (r, _) = e.read(fd, 8);
    e.tried(label, r);
    let r = e.write(fd, b"x");
    e.tried("  write", r);
    let (r, _) = e.ioctl_int(fd, TIOCGPGRP, 0);
    e.tried("  TIOCGPGRP", r);
    let (r, _) = e.ioctl_int(fd, TIOCSPGRP, 0);
    e.tried("  TIOCSPGRP", r);
    let revents = e.polled(fd, POLLIN | POLLOUT);
    e.say(format!("  poll {}", hex(revents)));
}

/// Blocks SIGHUP and SIGCONT, which the guest's handlers count: the
/// pending ones are what they would have counted.
fn block_hangups(c: &mut Env) {
    let set = 1u64 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
    c.put(ARG, &set.to_le_bytes());
    assert_eq!(c.call(RT_SIGPROCMASK, [0, ARG, 0, 8, 0, 0]), 0);
}

fn told(c: &mut Env) -> String {
    let signals = pending(c);
    format!(
        "{} {}",
        (signals >> (SIGHUP - 1)) & 1,
        (signals >> (SIGCONT - 1)) & 1
    )
}

/// pty-vhangup: `TIOCVHANGUP` of the slave and of the master, `vhangup`
/// and `TIOCCONS`, and what a process without the capabilities gets.
#[test]
fn pty_vhangup_hangs_up_either_side_and_tioccons_takes_one_terminal() {
    let mut e = Env::new();
    let (m, s) = e.openpty();
    let (_, number) = e.ioctl_int(m, TIOCGPTN, -1);
    let name = format!("/dev/pts/{number}");
    let mut c = e.fork();
    assert_eq!(c.call(SETUID, [65534, 0, 0, 0, 0, 0]), 0);
    for (label, fd, request) in [
        ("TIOCVHANGUP user", s, TIOCVHANGUP),
        ("TIOCVHANGUP user master", m, TIOCVHANGUP),
        ("TIOCCONS user", s, TIOCCONS),
        ("TIOCCONS user master", m, TIOCCONS),
    ] {
        let r = c.ioctl(fd, request, 0);
        c.tried(label, r);
    }
    let r = c.call(VHANGUP, [0; 6]);
    c.tried("vhangup user", r);
    let child = c.pid();
    c.exit(&mut e, 0);
    e.wait(child);
    // Only without a controlling terminal, which it would hang up.
    let own = e.open("/dev/tty", 0);
    assert!(own < 0);
    let r = e.call(VHANGUP, [0; 6]);
    e.tried("vhangup without a terminal", r);
    // The slave hangs up with the master open; the session it controls
    // loses it, its leader told.
    let (_, mut t) = e.get_termios(s);
    t.lflag &= !ECHO;
    e.set_termios(s, &t);
    e.disposition(SIGIO, 1);
    e.fcntl(s, F_SETFL, O_ASYNC);
    e.write(m, b"ab\n");
    let mut c = e.fork();
    c.close(m);
    c.close(s);
    c.call(SETSID, [0; 6]);
    let tty = c.open(&name, O_RDWR);
    block_hangups(&mut c);
    let hung = e.ioctl(s, TIOCVHANGUP, 0);
    let line = format!("leader told {}", told(&mut c));
    c.say(line);
    let (r, _) = c.ioctl_int(tty, TIOCGSID, 0);
    c.tried("leader tcgetsid", r);
    let r = c.open("/dev/tty", O_RDWR);
    c.tried("leader /dev/tty", r);
    let child = c.pid();
    c.exit(&mut e, 0);
    e.wait(child);
    e.tried("TIOCVHANGUP", hung);
    show_hung_up(&mut e, "slave read", s);
    let on = e.fcntl(s, F_GETFL, 0) as u64 & O_ASYNC != 0;
    e.say(format!("O_ASYNC {}", on as i32));
    let r = e.fcntl(s, F_SETFL, O_ASYNC);
    e.tried("F_SETFL", r);
    // The line discipline is gone: the master's input waits, unechoed,
    // until an open brings it back and the master writes again.
    e.show_drained("echo before", m, true);
    e.write(m, b"cd");
    e.show_drained("echo gone", m, true);
    let again = e.open(&name, O_RDWR | O_NOCTTY);
    e.say(format!("reopened {}", (again >= 0) as i32));
    let (_, t) = e.get_termios(again);
    e.say(format!("termios reset {}", (t.lflag & ECHO != 0) as i32));
    e.show_drained("echo on open", m, true);
    e.show_drained("input on open", again, true);
    e.write(m, b"e\n");
    e.show_drained("echo after", m, true);
    e.show_drained("input after", again, true);
    e.close(s);
    // The master hangs up alone: its file reads nothing, while the slave
    // still writes.
    let r = e.ioctl(m, TIOCVHANGUP, 0);
    e.tried("TIOCVHANGUP master", r);
    show_hung_up(&mut e, "master read", m);
    let (r, _) = e.ioctl_int(m, TIOCGPTN, 0);
    e.tried("  TIOCGPTN", r);
    let r = e.write(again, b"y");
    e.tried("slave write", r);
    let (r, _) = e.ioctl_int(again, TIOCGPGRP, 0);
    e.tried("slave TIOCGPGRP", r);
    let revents = e.polled(again, POLLIN | POLLOUT);
    e.say(format!("slave poll {}", hex(revents)));
    e.close(m);
    let revents = e.polled(again, POLLIN | POLLOUT);
    e.say(format!("slave poll closed {}", hex(revents)));
    e.close(again);
    // vhangup hangs up the caller's controlling terminal.
    let (m, s) = e.openpty();
    let mut c = e.fork();
    c.close(m);
    c.call(SETSID, [0; 6]);
    c.ioctl(s, TIOCSCTTY, 0);
    block_hangups(&mut c);
    let r = c.call(VHANGUP, [0; 6]);
    c.tried("vhangup", r);
    let line = format!("vhangup told {}", told(&mut c));
    c.say(line);
    let (r, _) = c.ioctl_int(s, TIOCGSID, 0);
    c.tried("vhangup tcgetsid", r);
    let r = c.ioctl(s, TIOCSCTTY, 0);
    c.tried("vhangup TIOCSCTTY", r);
    let child = c.pid();
    c.exit(&mut e, 0);
    e.wait(child);
    e.close(s);
    e.close(m);
    // One terminal takes the console's output at a time, until it hangs
    // up.
    let (m, s) = e.openpty();
    let (m2, s2) = e.openpty();
    let (_, number) = e.ioctl_int(m, TIOCGPTN, -1);
    let reader = e.open(&format!("/dev/pts/{number}"), O_NOCTTY);
    for (label, fd) in [
        ("TIOCCONS master", m),
        ("TIOCCONS read only", reader),
        ("TIOCCONS", s),
        ("TIOCCONS again", s),
        ("TIOCCONS other", s2),
    ] {
        let r = e.ioctl(fd, TIOCCONS, 0);
        e.tried(label, r);
    }
    e.ioctl(s, TIOCVHANGUP, 0);
    let r = e.ioctl(s2, TIOCCONS, 0);
    e.tried("TIOCCONS after hang-up", r);
    e.ioctl(s2, TIOCVHANGUP, 0);
    let r = e.ioctl(s, TIOCCONS, 0);
    e.tried("TIOCCONS free", r);
    for fd in [reader, s, s2, m2, m] {
        e.close(fd);
    }
    check(
        &e.lines,
        &[
            "TIOCVHANGUP user -1 1",
            "TIOCVHANGUP user master -1 1",
            "TIOCCONS user -1 1",
            "TIOCCONS user master -1 22",
            "vhangup user -1 1",
            "vhangup without a terminal 0 0",
            "leader told 1 1",
            "leader tcgetsid -1 5",
            "leader /dev/tty -1 6",
            "TIOCVHANGUP 0 0",
            "slave read 0 0",
            "  write -1 5",
            "  TIOCGPGRP -1 5",
            "  TIOCSPGRP -1 25",
            "  poll 0x1d",
            "O_ASYNC 0",
            "F_SETFL -1 25",
            "echo before 0 \"\"",
            "echo gone 0 \"\"",
            "reopened 1",
            "termios reset 1",
            "echo on open 0 \"\"",
            "input on open 0 \"\"",
            "echo after 6 \"cde\\x0d\\x0a|\"",
            "input after 5 \"cde\\x0a|\"",
            "TIOCVHANGUP master 0 0",
            "master read 0 0",
            "  write -1 5",
            "  TIOCGPGRP -1 5",
            "  TIOCSPGRP -1 25",
            "  poll 0x1d",
            "  TIOCGPTN -1 5",
            "slave write 1 0",
            "slave TIOCGPGRP -1 25",
            "slave poll 0x4",
            "slave poll closed 0x1d",
            "vhangup 0 0",
            "vhangup told 1 1",
            "vhangup tcgetsid -1 5",
            "vhangup TIOCSCTTY -1 5",
            "TIOCCONS master -1 22",
            "TIOCCONS read only -1 9",
            "TIOCCONS 0 0",
            "TIOCCONS again -1 16",
            "TIOCCONS other -1 16",
            "TIOCCONS after hang-up 0 0",
            "TIOCCONS free -1 5",
        ],
    );
}
