//! POSIX message queues through the system call interface: `mq_open`,
//! `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify` and
//! `mq_getsetattr`, their checks in Linux's order, priorities, the queue's
//! file, the limits and `/proc/sys/fs/mqueue`, poll, select and epoll on a
//! queue, a `SIGEV_SIGNAL` notification, and `/dev/mqueue`'s paths. The
//! expected values are Linux's (`ipc/mqueue.c`): they are the lines of the
//! cases of `tests/guests/processes/mqueue.c` that run in one thread without
//! waiting, which the differential tests compare with Linux. The rest (the
//! waits, other processes, `SIGEV_THREAD`'s cookies, user namespaces and
//! the times) stay with the differential tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{GuestAddr, PAGE_SIZE};

const DATA: u64 = 0x600000;
/// A name, or a path.
const NAME: u64 = DATA;
/// A `struct mq_attr`, and the one `mq_getsetattr` gives back.
const ATTR: u64 = DATA + 0x200;
const OLD: u64 = DATA + 0x240;
/// A `struct timespec`.
const TIME: u64 = DATA + 0x280;
/// The priority a receive gives back.
const PRIO: u64 = DATA + 0x2f0;
/// A message to send, and what a call reads.
const TEXT: u64 = DATA + 0x300;
const BUF: u64 = DATA + 0x400;
/// A `struct stat`.
const STAT: u64 = DATA + 0x800;
/// Descriptors for `pipe2`, `poll` and the sets of `select`.
const FDS: u64 = DATA + 0x900;
/// An `epoll_event`.
const EVENT: u64 = DATA + 0xa00;
/// A `struct rlimit`.
const LIMIT: u64 = DATA + 0xb00;
/// An address no mapping covers.
const BAD: u64 = 8;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const FSTAT: u64 = 5;
const POLL: u64 = 7;
const LSEEK: u64 = 8;
const SELECT: u64 = 23;
const FCNTL: u64 = 72;
const READLINK: u64 = 89;
const FCHMOD: u64 = 91;
const FCHOWN: u64 = 93;
const UMASK: u64 = 95;
const SETGROUPS: u64 = 116;
const SETRESUID: u64 = 117;
const SETRESGID: u64 = 119;
const SETRLIMIT: u64 = 160;
const EPOLL_WAIT: u64 = 232;
const EPOLL_CTL: u64 = 233;
const MQ_OPEN: u64 = 240;
const MQ_UNLINK: u64 = 241;
const MQ_TIMEDSEND: u64 = 242;
const MQ_TIMEDRECEIVE: u64 = 243;
const MQ_NOTIFY: u64 = 244;
const MQ_GETSETATTR: u64 = 245;
const EPOLL_CREATE1: u64 = 291;
const PIPE2: u64 = 293;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const RLIMIT_MSGQUEUE: u64 = 12;

/// A kernel whose thread runs the first process, as root, with the page at
/// `DATA` and the three after it mapped.
struct Env {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
}

impl Env {
    fn new() -> Self {
        let k = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + PAGE_SIZE)),
        );
        let m = AddressSpace::new();
        m.map_shared(
            Some(GuestAddr(DATA)),
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        Self { k, t, m }
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

    fn put(&self, at: u64, bytes: &[u8]) {
        self.m.write(GuestAddr(at), bytes).unwrap();
    }

    fn get(&self, at: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.m.read(GuestAddr(at), &mut bytes).unwrap();
        bytes
    }

    fn long(&self, at: u64) -> i64 {
        self.m.read_u64(GuestAddr(at)).unwrap() as i64
    }

    /// Puts `name` and its NUL at `NAME`.
    fn name(&self, name: &[u8]) -> u64 {
        let mut bytes = name.to_vec();
        bytes.push(0);
        self.put(NAME, &bytes);
        NAME
    }

    /// A `struct mq_attr` at `ATTR`.
    fn attr(&self, flags: i64, maxmsg: i64, msgsize: i64) -> u64 {
        let mut bytes = Vec::new();
        for v in [flags, maxmsg, msgsize, 0, 0, 0, 0, 0] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        self.put(ATTR, &bytes);
        ATTR
    }

    fn open(&mut self, name: &[u8], flags: u64, mode: u64, attr: u64) -> i64 {
        let at = self.name(name);
        self.call(MQ_OPEN, [at, flags, mode, attr, 0, 0])
    }

    /// Opens a queue of `maxmsg` messages of `msgsize` bytes.
    fn open_with(&mut self, name: &[u8], flags: u64, mode: u64, maxmsg: i64, msgsize: i64) -> i64 {
        let attr = self.attr(0, maxmsg, msgsize);
        self.open(name, flags, mode, attr)
    }

    fn unlink(&mut self, name: &[u8]) -> i64 {
        let at = self.name(name);
        self.call(MQ_UNLINK, [at, 0, 0, 0, 0, 0])
    }

    fn send(&mut self, fd: i64, text: &[u8], prio: u64, time: u64) -> i64 {
        self.put(TEXT, text);
        self.call(
            MQ_TIMEDSEND,
            [fd as u64, TEXT, text.len() as u64, prio, time, 0],
        )
    }

    /// A receive's result, and its priority and text as `r:prio:text`.
    fn receive(&mut self, fd: i64, len: u64, time: u64) -> String {
        self.put(BUF, &[0; 64]);
        self.put(PRIO, &99u32.to_le_bytes());
        let r = self.call(MQ_TIMEDRECEIVE, [fd as u64, BUF, len, PRIO, time, 0]);
        if r < 0 {
            return r.to_string();
        }
        let prio = u32::from_le_bytes(self.get(PRIO, 4).try_into().unwrap());
        let text = self.get(BUF, r as usize);
        format!("{r}:{prio}:{}", String::from_utf8_lossy(&text))
    }

    /// `mq_getsetattr`'s result and the attributes it gives back.
    fn getattr(&mut self, fd: i64) -> String {
        self.put(OLD, &[0x55; 64]);
        let r = self.call(MQ_GETSETATTR, [fd as u64, 0, OLD, 0, 0, 0]);
        let reserved = (4..8).fold(0, |all, i| all | self.long(OLD + 8 * i));
        format!(
            "getattr={r} flags={} maxmsg={} msgsize={} curmsgs={} reserved={reserved}",
            self.long(OLD),
            self.long(OLD + 8),
            self.long(OLD + 16),
            self.long(OLD + 24),
        )
    }

    fn timespec(&self, sec: i64, nsec: i64) -> u64 {
        self.put(TIME, &sec.to_le_bytes());
        self.put(TIME + 8, &nsec.to_le_bytes());
        TIME
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// `fstat`'s result, mode, size, links, user and group.
    fn stat(&mut self, fd: i64) -> (i64, u32, i64, u64, u32, u32) {
        let r = self.call(FSTAT, [fd as u64, STAT, 0, 0, 0, 0]);
        let word = |at: u64| u32::from_le_bytes(self.get(STAT + at, 4).try_into().unwrap());
        (
            r,
            word(24),
            self.long(STAT + 48),
            self.long(STAT + 16) as u64,
            word(28),
            word(32),
        )
    }

    /// What the descriptor's link in `/proc/self/fd` reads.
    fn link(&mut self, fd: i64) -> String {
        let path = self.name(format!("/proc/self/fd/{fd}").as_bytes());
        let n = self.call(READLINK, [path, BUF, 299, 0, 0, 0]);
        if n < 0 {
            return n.to_string();
        }
        String::from_utf8(self.get(BUF, n as usize)).unwrap()
    }

    /// Reads up to `len` bytes of `fd` as text, or `-errno`.
    fn read(&mut self, fd: i64, len: u64) -> String {
        let n = self.call(READ, [fd as u64, BUF, len, 0, 0, 0]);
        if n < 0 {
            return n.to_string();
        }
        String::from_utf8(self.get(BUF, n as usize)).unwrap()
    }

    fn write(&mut self, fd: i64, text: &[u8]) -> i64 {
        self.put(TEXT, text);
        self.call(WRITE, [fd as u64, TEXT, text.len() as u64, 0, 0, 0])
    }

    fn set_msgqueue_limit(&mut self, limit: u64) -> i64 {
        self.put(LIMIT, &limit.to_le_bytes());
        self.put(LIMIT + 8, &limit.to_le_bytes());
        self.call(SETRLIMIT, [RLIMIT_MSGQUEUE, LIMIT, 0, 0, 0, 0])
    }

    /// Becomes user 2000, without capabilities.
    fn unprivileged(&mut self) {
        assert_eq!(self.call(SETRESGID, [2000, 2000, 2000, 0, 0, 0]), 0);
        assert_eq!(self.call(SETGROUPS, [0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(self.call(SETRESUID, [2000, 2000, 2000, 0, 0, 0]), 0);
    }

    /// Opens `/proc/sys/fs/mqueue/<name>`.
    fn sysctl_open(&mut self, name: &str, flags: u64) -> i64 {
        let path = self.name(format!("/proc/sys/fs/mqueue/{name}").as_bytes());
        self.call(OPEN, [path, flags | O_CLOEXEC, 0, 0, 0, 0])
    }

    fn sysctl_value(&mut self, name: &str) -> i64 {
        let fd = self.sysctl_open(name, O_RDONLY);
        if fd < 0 {
            return fd;
        }
        let text = self.read(fd, 63);
        self.close(fd);
        text.trim().parse().unwrap()
    }

    /// A write of `text` to a newly opened file: its result, or the open's.
    fn sysctl_write(&mut self, name: &str, text: &str) -> i64 {
        let fd = self.sysctl_open(name, O_WRONLY);
        if fd < 0 {
            return fd;
        }
        let n = self.write(fd, text.as_bytes());
        self.close(fd);
        n
    }

    fn limits(&mut self) -> String {
        [
            "queues_max",
            "msg_max",
            "msgsize_max",
            "msg_default",
            "msgsize_default",
        ]
        .map(|name| format!("{name}={}", self.sysctl_value(name)))
        .join(" ")
    }

    /// Makes queues `<prefix><n>` of one 1-byte message until one fails or
    /// `most` are made: how many, and the error.
    fn make_tiny(&mut self, prefix: &str, most: usize) -> (usize, i64) {
        for made in 0..most {
            let fd = self.open_with(
                format!("{prefix}{made}").as_bytes(),
                O_RDWR | O_CREAT,
                0o600,
                1,
                1,
            );
            if fd < 0 {
                return (made, fd);
            }
            self.close(fd);
        }
        (most, 0)
    }
}

/// Compares the lines a case printed with Linux's, printing them all when
/// one differs.
fn check(lines: &[String], expected: &[&str]) {
    if lines != expected {
        for line in lines {
            println!("{line}");
        }
        panic!("the lines differ from Linux's");
    }
}

/// `calls_case`: the calls' checks in Linux's order, the defaults, the
/// queue's descriptor and file, priorities, and unlinking.
#[test]
fn the_calls_check_their_arguments_in_linux_s_order_and_keep_priorities() {
    let mut e = Env::new();
    let mut out = Vec::new();
    // Room for the largest queues root may make.
    assert_eq!(e.set_msgqueue_limit(64 << 20), 0);
    let long = vec![b'n'; 256];
    let longest = vec![b'n'; 255];
    let missing = e.open(b"missing", O_RDWR, 0, 0);
    let empty = e.open(b"", O_RDWR | O_CREAT, 0o600, 0);
    let slash = e.open(b"a/b", O_RDWR | O_CREAT, 0o600, 0);
    let dot = e.open(b".", O_RDWR | O_CREAT, 0o600, 0);
    let dotdot = e.open(b"..", O_RDONLY, 0, 0);
    let too_long = e.open(&long, O_RDWR | O_CREAT, 0o600, 0);
    let longest_missing = e.open(&longest, O_RDWR, 0, 0);
    let fault = e.call(MQ_OPEN, [BAD, O_RDWR | O_CREAT, 0o600, 0, 0, 0]);
    out.push(format!(
        "open: missing={missing} empty={empty} slash={slash} dot={dot} dotdot={dotdot} \
         long={too_long} longest={longest_missing} fault={fault}"
    ));
    // The attributes are read first, whatever the name and flags.
    let attr_fault = e.open(b"q", O_RDWR | O_CREAT, 0o600, BAD);
    let attr_fault_bad_name = e.call(MQ_OPEN, [BAD, O_RDWR, 0, BAD, 0, 0]);
    let no_messages = e.open_with(b"q", O_RDWR | O_CREAT, 0o600, 0, 8);
    let negative_size = e.open_with(b"q", O_RDWR | O_CREAT, 0o600, 2, -1);
    out.push(format!(
        "open: attr-fault={attr_fault} attr-fault-bad-name={attr_fault_bad_name} \
         no-messages={no_messages} negative-size={negative_size}"
    ));
    // As root, CAP_SYS_RESOURCE allows up to 65536 messages of 16 MiB.
    let many = e.open_with(b"many", O_RDWR | O_CREAT, 0o600, 65536, 1);
    let huge = e.open_with(b"huge", O_RDWR | O_CREAT, 0o600, 1, 16 << 20);
    let too_many = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 65537, 1);
    let too_huge = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 1, (16 << 20) + 1);
    out.push(format!(
        "root: many={} too-many={too_many} huge={} too-huge={too_huge}",
        u8::from(many >= 0),
        u8::from(huge >= 0)
    ));
    out.push(format!("many: {}", e.getattr(many)));
    e.close(many);
    e.close(huge);
    e.unlink(b"many");
    e.unlink(b"huge");

    // The defaults, the descriptor and its file.
    e.call(UMASK, [0o027, 0, 0, 0, 0, 0]);
    let d = e.open(b"default", O_WRONLY | O_CREAT | O_NONBLOCK, 0o7666, 0);
    e.call(UMASK, [0o022, 0, 0, 0, 0, 0]);
    out.push(format!("default: {}", e.getattr(d)));
    let cloexec = e.call(FCNTL, [d as u64, 1, 0, 0, 0, 0]);
    let flags = e.call(FCNTL, [d as u64, 3, 0, 0, 0, 0]) as u64 & (3 | O_NONBLOCK);
    let (stated, mode, size, links, uid, _) = e.stat(d);
    out.push(format!(
        "default: cloexec={cloexec} flags={flags:o} stat={stated} mode={mode:o} size={size} \
         links={links} uid={uid}"
    ));
    out.push(format!("default: readlink [{}]", e.link(d)));
    let fchmod = e.call(FCHMOD, [d as u64, 0o604, 0, 0, 0, 0]);
    let fchown = e.call(FCHOWN, [d as u64, 5, 6, 0, 0, 0]);
    let (stated, mode, _, _, uid, gid) = e.stat(d);
    out.push(format!(
        "default: fchmod={fchmod} fchown={fchown} stat={stated} mode={mode:o} uid={uid} gid={gid}"
    ));
    let exclusive = e.open(b"default", O_RDWR | O_CREAT | O_EXCL, 0o600, 0);
    let both_modes = e.open(b"default", O_RDWR | 3, 0, 0);
    let again = e.open_with(b"default", O_RDONLY | O_CREAT, 0o600, 0, 8);
    out.push(format!(
        "default: exclusive={exclusive} both-modes={both_modes} again={}",
        u8::from(again >= 0)
    ));
    e.close(d);

    // Priorities: highest first, the order sent within one.
    let q = e.open_with(b"q", O_RDWR | O_CREAT, 0o640, 4, 16);
    let r = e.open(b"q", O_RDONLY, 0, 0);
    let w = e.open(b"q", O_WRONLY, 0, 0);
    let sent: Vec<String> = [(&b"one"[..], 1), (b"five", 5), (b"uno", 1), (b"zero", 0)]
        .iter()
        .map(|&(text, prio)| e.send(w, text, prio, 0).to_string())
        .collect();
    out.push(format!("send {}", sent.join(" ")));
    out.push(format!("four: {}", e.getattr(q)));
    e.call(LSEEK, [q as u64, 0, 0, 0, 0, 0]);
    out.push(format!("four: [{}]", e.read(q, 199).replace('\n', "|")));
    let past = e.timespec(0, 0);
    out.push(format!("full: timed-out={}", e.send(w, b"x", 0, past)));
    let nonblocking = e.attr(O_NONBLOCK as i64, 0, 0);
    e.put(OLD, &[0x55; 64]);
    let set = e.call(MQ_GETSETATTR, [w as u64, nonblocking, OLD, 0, 0, 0]);
    let fcntl = e.call(FCNTL, [w as u64, 3, 0, 0, 0, 0]) as u64 & O_NONBLOCK;
    out.push(format!(
        "setattr={set} old-flags={} fcntl={fcntl:o}",
        e.long(OLD)
    ));
    out.push(format!("full: nonblocking={}", e.send(w, b"x", 0, 0)));
    let got: Vec<String> = (0..4).map(|_| e.receive(r, 16, 0)).collect();
    let past = e.timespec(0, 0);
    out.push(format!(
        "receive {} empty-past={}",
        got.join(" "),
        e.receive(r, 16, past)
    ));
    let nonblocking = e.attr(O_NONBLOCK as i64, 0, 0);
    e.call(MQ_GETSETATTR, [r as u64, nonblocking, 0, 0, 0, 0]);
    out.push(format!("empty: nonblocking={}", e.receive(r, 16, 0)));

    // Sends' checks, in order: the timeout, the priority, the queue, its
    // mode, the size, the message.
    assert_eq!(e.call(PIPE2, [FDS, 0, 0, 0, 0, 0]), 0);
    let pipe = i64::from(u32::from_le_bytes(e.get(FDS, 4).try_into().unwrap()));
    let pipe_write = i64::from(u32::from_le_bytes(e.get(FDS + 4, 4).try_into().unwrap()));
    let timeout_fault = e.send(-1, b"x", 32768, BAD);
    let bad_nanos = e.timespec(0, 1_000_000_000);
    let bad_nanos = e.send(-1, b"x", 32768, bad_nanos);
    let negative = e.timespec(-1, 0);
    let negative = e.send(-1, b"x", 0, negative);
    out.push(format!(
        "send: timeout-fault={timeout_fault} bad-nanos={bad_nanos} negative={negative} prio={} \
         prio-bad-fd={} pipe={} closed={}",
        e.send(w, b"x", 32768, 0),
        e.send(-1, b"x", 32768, 0),
        e.send(pipe, b"x", 0, 0),
        e.send(-1, b"x", 0, 0),
    ));
    let read_only = e.send(r, b"x", 0, 0);
    let read_only_big = e.send(r, &[b'x'; 17], 0, 0);
    let big = e.send(w, &[0; 17], 0, 0);
    let send_fault = e.call(MQ_TIMEDSEND, [w as u64, BAD, 16, 0, 0, 0]);
    let largest = e.send(w, b"0123456789abcdef", 0, 0);
    let top_prio = e.send(w, b"", 32767, 0);
    out.push(format!(
        "send: read-only={read_only} read-only-big={read_only_big} big={big} fault={send_fault} \
         largest={largest} top-prio={top_prio}"
    ));
    let timeout_fault = e.call(MQ_TIMEDRECEIVE, [u64::MAX, BUF, 16, 0, BAD, 0]);
    out.push(format!(
        "receive: timeout-fault={timeout_fault} pipe={} write-only={} small={}",
        e.receive(pipe, 16, 0),
        e.receive(w, 16, 0),
        e.receive(r, 15, 0),
    ));
    // A bad priority or buffer loses the message.
    let prio_fault = e.call(MQ_TIMEDRECEIVE, [r as u64, BUF, 16, BAD, 0, 0]);
    let text_fault = e.call(MQ_TIMEDRECEIVE, [r as u64, BAD, 16, PRIO, 0, 0]);
    let none_left = e.call(MQ_TIMEDRECEIVE, [r as u64, BUF, 16, 0, 0, 0]);
    out.push(format!(
        "receive: prio-fault={prio_fault} text-fault={text_fault} none-left={none_left}"
    ));
    out.push(format!("drained: {}", e.getattr(q)));

    // The file: read shows the state line from the position; it has no
    // write.
    e.call(LSEEK, [q as u64, 0, 0, 0, 0, 0]);
    let first = e.read(q, 6);
    let rest = e.read(q, 200).len();
    let end = e.read(q, 8).len();
    let seek_end = e.call(LSEEK, [q as u64, 0, 2, 0, 0, 0]);
    out.push(format!(
        "file: first=[{first}] rest={rest} end={end} seek-end={seek_end} write={} read-wo={} \
         write-ro={}",
        e.write(q, b"x"),
        e.read(w, 8),
        e.write(r, b"x"),
    ));

    // getsetattr's checks: the new flags, then the queue.
    let bad_flags = e.attr(1, 0, 0);
    out.push(format!(
        "attr: bad-flags={} bad-flags-bad-fd={} new-fault={} old-fault={} pipe={}",
        e.call(MQ_GETSETATTR, [q as u64, bad_flags, 0, 0, 0, 0]),
        e.call(MQ_GETSETATTR, [u64::MAX, bad_flags, 0, 0, 0, 0]),
        e.call(MQ_GETSETATTR, [q as u64, BAD, 0, 0, 0, 0]),
        e.call(MQ_GETSETATTR, [q as u64, 0, BAD, 0, 0, 0]),
        e.call(MQ_GETSETATTR, [pipe as u64, 0, 0, 0, 0, 0]),
    ));

    // No access mode: made all the same, but neither sends nor receives.
    let neither = e.open_with(b"neither", 3 | O_CREAT, 0o600, 4, 16);
    out.push(format!(
        "no-mode: open={} send={} receive={}",
        u8::from(neither >= 0),
        e.send(neither, b"x", 0, 0),
        e.receive(neither, 16, 0),
    ));
    e.close(neither);
    e.unlink(b"neither");

    // Unlinked, the queue lasts while open.
    out.push(format!(
        "unlink: first={} again={} reopen={} bad={} empty={} slash={} long={}",
        e.unlink(b"q"),
        e.unlink(b"q"),
        e.open(b"q", O_RDWR, 0, 0),
        e.call(MQ_UNLINK, [BAD, 0, 0, 0, 0, 0]),
        e.unlink(b""),
        e.unlink(b"a/b"),
        e.unlink(&long),
    ));
    out.push(format!("unlinked: readlink [{}]", e.link(r)));
    out.push(format!(
        "unlinked: send={} got={}",
        e.send(w, b"late", 3, 0),
        e.receive(r, 16, 0)
    ));
    for fd in [q, r, w, pipe, pipe_write] {
        e.close(fd);
    }
    e.unlink(b"default");
    check(
        &out,
        &[
            "open: missing=-2 empty=-2 slash=-13 dot=-13 dotdot=-13 long=-36 longest=-2 fault=-14",
            "open: attr-fault=-14 attr-fault-bad-name=-14 no-messages=-22 negative-size=-22",
            "root: many=1 too-many=-22 huge=1 too-huge=-22",
            "many: getattr=0 flags=0 maxmsg=65536 msgsize=1 curmsgs=0 reserved=0",
            "default: getattr=0 flags=2048 maxmsg=10 msgsize=8192 curmsgs=0 reserved=0",
            "default: cloexec=1 flags=4001 stat=0 mode=107640 size=80 links=1 uid=0",
            "default: readlink [/default]",
            "default: fchmod=0 fchown=0 stat=0 mode=100604 uid=5 gid=6",
            "default: exclusive=-17 both-modes=-22 again=1",
            "send 0 0 0 0",
            "four: getattr=0 flags=0 maxmsg=4 msgsize=16 curmsgs=4 reserved=0",
            "four: [QSIZE:14         NOTIFY:0     SIGNO:0     NOTIFY_PID:0     |]",
            "full: timed-out=-110",
            "setattr=0 old-flags=0 fcntl=4000",
            "full: nonblocking=-11",
            "receive 4:5:five 3:1:one 3:1:uno 4:0:zero empty-past=-110",
            "empty: nonblocking=-11",
            "send: timeout-fault=-14 bad-nanos=-22 negative=-22 prio=-22 prio-bad-fd=-22 pipe=-9 closed=-9",
            "send: read-only=-9 read-only-big=-9 big=-90 fault=-14 largest=0 top-prio=0",
            "receive: timeout-fault=-14 pipe=-9 write-only=-9 small=-90",
            "receive: prio-fault=-14 text-fault=-14 none-left=-11",
            "drained: getattr=0 flags=0 maxmsg=4 msgsize=16 curmsgs=0 reserved=0",
            "file: first=[QSIZE:] rest=54 end=0 seek-end=80 write=-22 read-wo=-9 write-ro=-9",
            "attr: bad-flags=-22 bad-flags-bad-fd=-22 new-fault=-14 old-fault=-14 pipe=-9",
            "no-mode: open=1 send=-9 receive=-9",
            "unlink: first=0 again=-2 reopen=-2 bad=-14 empty=-2 slash=-13 long=-36",
            "unlinked: readlink [/q (deleted)]",
            "unlinked: send=0 got=4:3:late",
        ],
    );
}

/// `limits_case`: what user 2000 may make without `CAP_SYS_RESOURCE`, the
/// permissions of root's queues, and `RLIMIT_MSGQUEUE`.
#[test]
fn a_user_s_queues_keep_to_the_limits_and_the_queues_permissions() {
    let mut e = Env::new();
    let mut out = Vec::new();
    assert!(e.open_with(b"roots", O_RDWR | O_CREAT, 0o600, 1, 1) >= 0);
    assert!(e.open_with(b"open", O_RDWR | O_CREAT, 0o644, 1, 1) >= 0);
    // RLIMIT_MSGQUEUE's default.
    assert_eq!(e.set_msgqueue_limit(819200), 0);
    e.unprivileged();
    let eleven = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 11, 8);
    let large = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 1, 8193);
    let ten = e.open_with(b"ten", O_RDWR | O_CREAT, 0o600, 10, 8192);
    out.push(format!(
        "user: eleven={eleven} large={large} ten={}",
        u8::from(ten >= 0)
    ));
    e.close(ten);
    e.unlink(b"ten");
    let read_roots = e.open(b"roots", O_RDONLY, 0, 0);
    let write_open = e.open(b"open", O_WRONLY, 0, 0);
    let read_open = e.open(b"open", O_RDONLY, 0, 0);
    out.push(format!(
        "user: read-roots={read_roots} write-open={write_open} read-open={} unlink-roots={}",
        u8::from(read_open >= 0),
        e.unlink(b"roots"),
    ));
    // The default queue charges 10 * (8192 + 48 + 48) bytes, of
    // RLIMIT_MSGQUEUE's 819200.
    let mut fds = Vec::new();
    let mut error = 0;
    while fds.len() < 20 {
        let fd = e.open(
            format!("d{}", fds.len()).as_bytes(),
            O_RDWR | O_CREAT,
            0o600,
            0,
        );
        if fd < 0 {
            error = fd;
            break;
        }
        fds.push(fd);
    }
    out.push(format!("user: default-queues={} then={error}", fds.len()));
    // An unlinked queue charges until it is closed.
    e.unlink(b"d0");
    out.push(format!(
        "user: after-unlink={}",
        e.open(b"again", O_RDWR | O_CREAT, 0o600, 0)
    ));
    e.close(fds[0]);
    let again = e.open(b"again", O_RDWR | O_CREAT, 0o600, 0);
    out.push(format!("user: after-close={}", u8::from(again >= 0)));
    e.close(again);
    e.unlink(b"again");
    for (i, &fd) in fds.iter().enumerate().skip(1) {
        e.close(fd);
        e.unlink(format!("d{i}").as_bytes());
    }
    // A smaller limit: 97 bytes a queue of one 1-byte message.
    out.push(format!("user: setrlimit={}", e.set_msgqueue_limit(1000)));
    let mut fds = Vec::new();
    let mut error = 0;
    while fds.len() < 20 {
        let fd = e.open_with(
            format!("s{}", fds.len()).as_bytes(),
            O_RDWR | O_CREAT,
            0o600,
            1,
            1,
        );
        if fd < 0 {
            error = fd;
            break;
        }
        fds.push(fd);
    }
    out.push(format!("user: small-queues={} then={error}", fds.len()));
    check(
        &out,
        &[
            "user: eleven=-22 large=-22 ten=1",
            "user: read-roots=-13 write-open=-13 read-open=1 unlink-roots=-1",
            "user: default-queues=9 then=-24",
            "user: after-unlink=-24",
            "user: after-close=1",
            "user: setrlimit=0",
            "user: small-queues=10 then=-24",
        ],
    );
}

/// `limits_case`'s `queues_max`: 256 queues in the namespace, counting
/// root's two, then `ENOSPC` for a user.
#[test]
fn a_user_may_not_make_more_queues_than_queues_max() {
    let mut e = Env::new();
    assert!(e.open_with(b"roots", O_RDWR | O_CREAT, 0o600, 1, 1) >= 0);
    assert!(e.open_with(b"open", O_RDWR | O_CREAT, 0o644, 1, 1) >= 0);
    e.unprivileged();
    let (made, then) = e.make_tiny("m", 300);
    check(
        &[format!("queues: user-made={made} then={then}")],
        &["queues: user-made=254 then=-28"],
    );
}

/// `sysctl_case`: `/proc/sys/fs/mqueue`'s files, what a write takes, and
/// what the limits change.
#[test]
fn proc_sys_fs_mqueue_sets_the_limits_as_linux_s_writes_take_them() {
    let mut e = Env::new();
    let mut out = Vec::new();
    out.push(format!("defaults: {}", e.limits()));
    let at = e.name(b"/proc/sys/fs/mqueue/msg_max");
    let stated = e.call(4, [at, STAT, 0, 0, 0, 0]);
    let word = |e: &Env, at: u64| u32::from_le_bytes(e.get(STAT + at, 4).try_into().unwrap());
    let (mode, uid, gid) = (word(&e, 24), word(&e, 28), word(&e, 32));
    let at = e.name(b"/proc/sys/fs/mqueue");
    let dir = e.call(4, [at, STAT, 0, 0, 0, 0]);
    let dir_mode = word(&e, 24);
    out.push(format!(
        "stat: file={stated} mode={mode:o} uid={uid} gid={gid} dir={dir} directory={} perms={:o}",
        u8::from(dir_mode & 0o170000 == 0o040000),
        dir_mode & 0o7777
    ));
    let at = e.name(b"/proc/sys/fs/mqueue");
    out.push(format!(
        "open: dir-write={} missing={}",
        e.call(OPEN, [at, O_WRONLY, 0, 0, 0, 0]),
        e.sysctl_open("missing", O_RDONLY)
    ));

    // What a write takes, and what it consumes.
    let mut line = format!("msg_max: set={}", e.sysctl_write("msg_max", "20\n"));
    line += &format!(" now={}", e.sysctl_value("msg_max"));
    for bad in [
        "0",
        "65537",
        "-1",
        "abc",
        "5x",
        "09",
        "0x",
        " \n",
        "2147483648",
        "99999999999999999999999",
        "000000000000000000001",
    ] {
        let label = if bad.starts_with(' ') { "spaces" } else { bad };
        line += &format!(" {label}={}", e.sysctl_write("msg_max", bad));
    }
    line += &format!(" still={}", e.sysctl_value("msg_max"));
    out.push(line);
    let mut line = String::from("msg_max:");
    for (label, text) in [
        ("padded", "  30  \n"),
        ("two", "5 6\n"),
        ("hex", "0x10"),
        ("octal", "010"),
    ] {
        line += &format!(" {label}={}", e.sysctl_write("msg_max", text));
        line += &format!(" now={}", e.sysctl_value("msg_max"));
    }
    line += &format!(" empty={}", e.sysctl_write("msg_max", ""));
    line += &format!(" highest={}", e.sysctl_write("msg_max", "65536"));
    line += &format!(" now={}", e.sysctl_value("msg_max"));
    out.push(line);
    // A second write goes past the start, and changes nothing; a read past
    // the start gives nothing.
    let fd = e.sysctl_open("msg_default", O_RDWR);
    let first = e.write(fd, b"7");
    let second = e.write(fd, b"9");
    e.call(LSEEK, [fd as u64, 0, 0, 0, 0, 0]);
    let one = e.read(fd, 1);
    let rest = e.read(fd, 8);
    let seek_end = e.call(LSEEK, [fd as u64, 0, 2, 0, 0, 0]);
    out.push(format!(
        "position: first={first} second={second} read-one=[{one}] read-rest=[{}] seek-end={seek_end}",
        rest.replace('\n', "|")
    ));
    e.close(fd);
    out.push(format!(
        "msgsize_max: below={} least={} above={} highest={}",
        e.sysctl_write("msgsize_max", "127"),
        e.sysctl_write("msgsize_max", "128"),
        e.sysctl_write("msgsize_max", "16777217"),
        e.sysctl_write("msgsize_max", "16777216"),
    ));
    let negative = e.sysctl_write("queues_max", "-5");
    let now = e.sysctl_value("queues_max");
    let huge = e.sysctl_write("queues_max", "2147483647");
    out.push(format!(
        "queues_max: negative={negative} now={now} huge={huge} now={}",
        e.sysctl_value("queues_max")
    ));

    // What the limits change: the defaults a queue without attributes
    // takes, the smaller of each default and its limit.
    e.sysctl_write("msg_max", "20");
    e.sysctl_write("msgsize_max", "1000");
    e.sysctl_write("msg_default", "5");
    e.sysctl_write("msgsize_default", "300");
    out.push(format!("set: {}", e.limits()));
    let q = e.open(b"d", O_RDWR | O_CREAT, 0o600, 0);
    out.push(format!("defaults-5-300: {}", e.getattr(q)));
    e.close(q);
    e.unlink(b"d");
    e.sysctl_write("msg_default", "30");
    e.sysctl_write("msgsize_default", "5000");
    let q = e.open(b"d", O_RDWR | O_CREAT, 0o600, 0);
    out.push(format!("defaults-above-limits: {}", e.getattr(q)));
    e.close(q);
    e.unlink(b"d");
    // Root passes the limits up to the hard ones.
    let q = e.open_with(b"root", O_RDWR | O_CREAT, 0o600, 21, 1001);
    out.push(format!("root: above-limits={}", u8::from(q >= 0)));
    e.close(q);
    e.unlink(b"root");
    e.sysctl_write("queues_max", "3");

    e.unprivileged();
    let open_write = e.sysctl_open("msg_max", O_WRONLY);
    let open_read_write = e.sysctl_open("msg_max", O_RDWR);
    let read = e.sysctl_value("msg_max");
    let most = e.open_with(b"most", O_RDWR | O_CREAT, 0o600, 20, 1000);
    let more = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 21, 1000);
    let larger = e.open_with(b"x", O_RDWR | O_CREAT, 0o600, 20, 1001);
    e.close(most);
    e.unlink(b"most");
    let (made, then) = e.make_tiny("u", 10);
    out.push(format!(
        "user: open-write={open_write} open-read-write={open_read_write} read={read} most={} \
         more={more} larger={larger} made={made} then={then}",
        u8::from(most >= 0)
    ));
    check(
        &out,
        &[
            "defaults: queues_max=256 msg_max=10 msgsize_max=8192 msg_default=10 msgsize_default=8192",
            "stat: file=0 mode=100644 uid=0 gid=0 dir=0 directory=1 perms=555",
            "open: dir-write=-21 missing=-2",
            "msg_max: set=3 now=20 0=-22 65537=-22 -1=-22 abc=-22 5x=-22 09=-22 0x=-22 spaces=-22 2147483648=-22 99999999999999999999999=-22 000000000000000000001=-22 still=20",
            "msg_max: padded=7 now=30 two=2 now=5 hex=4 now=16 octal=3 now=8 empty=0 highest=5 now=65536",
            "position: first=1 second=1 read-one=[7] read-rest=[] seek-end=0",
            "msgsize_max: below=-22 least=3 above=-22 highest=8",
            "queues_max: negative=2 now=-5 huge=10 now=2147483647",
            "set: queues_max=2147483647 msg_max=20 msgsize_max=1000 msg_default=5 msgsize_default=300",
            "defaults-5-300: getattr=0 flags=0 maxmsg=5 msgsize=300 curmsgs=0 reserved=0",
            "defaults-above-limits: getattr=0 flags=0 maxmsg=20 msgsize=1000 curmsgs=0 reserved=0",
            "root: above-limits=1",
            "user: open-write=-13 open-read-write=-13 read=20 most=1 more=-22 larger=-22 made=3 then=-28",
        ],
    );
}

/// `sysctl_case`'s last lines: a new IPC namespace starts from the defaults
/// again, and the old one keeps its own.
#[test]
fn a_new_ipc_namespace_starts_from_the_default_limits() {
    const UNSHARE: u64 = 272;
    const CLONE_NEWIPC: u64 = 0x0800_0000;
    let mut e = Env::new();
    e.sysctl_write("msg_max", "20");
    e.sysctl_write("queues_max", "3");
    let this = e.limits();
    assert_eq!(e.call(UNSHARE, [CLONE_NEWIPC, 0, 0, 0, 0, 0]), 0);
    check(
        &[
            format!("this-namespace: {this}"),
            format!("new-namespace: {}", e.limits()),
        ],
        &[
            "this-namespace: queues_max=3 msg_max=20 msgsize_max=8192 msg_default=10 msgsize_default=8192",
            "new-namespace: queues_max=256 msg_max=10 msgsize_max=8192 msg_default=10 msgsize_default=8192",
        ],
    );
}

/// `poll_case`: poll, select and epoll on a queue, which is readable with
/// messages and writable with room.
#[test]
fn poll_select_and_epoll_see_a_queue_s_messages_and_room() {
    const IN: u64 = FDS + 0x20;
    const OUT: u64 = FDS + 0xa0;
    let mut e = Env::new();
    let mut out = Vec::new();
    let q = e.open_with(b"p", O_RDWR | O_CREAT, 0o600, 2, 8);
    let ro = e.open(b"p", O_RDONLY, 0, 0);
    assert!(q >= 0 && ro >= 0);
    for round in 0..3 {
        let mut fds = Vec::new();
        for fd in [q, ro] {
            fds.extend_from_slice(&(fd as i32).to_le_bytes());
            fds.extend_from_slice(&5u16.to_le_bytes());
            fds.extend_from_slice(&0u16.to_le_bytes());
        }
        e.put(FDS, &fds);
        let n = e.call(POLL, [FDS, 2, 0, 0, 0, 0]);
        let revents =
            |e: &Env, i: u64| u16::from_le_bytes(e.get(FDS + 8 * i + 6, 2).try_into().unwrap());
        let (r0, r1) = (revents(&e, 0), revents(&e, 1));
        let mut set = [0u8; 128];
        set[q as usize / 8] |= 1 << (q % 8);
        e.put(IN, &set);
        e.put(OUT, &set);
        let zero = e.timespec(0, 0);
        let s = e.call(SELECT, [q as u64 + 1, IN, OUT, 0, zero, 0]);
        let is_set =
            |e: &Env, at: u64| u8::from(e.get(at + q as u64 / 8, 1)[0] & (1 << (q % 8)) != 0);
        out.push(format!(
            "poll-{round}: n={n} revents={r0:x},{r1:x} select={s} in={} out={}",
            is_set(&e, IN),
            is_set(&e, OUT)
        ));
        if round < 2 {
            e.send(q, b"m", 0, 0);
        }
    }
    e.receive(q, 8, 0);
    e.receive(q, 8, 0);

    // epoll, level- and edge-triggered: each send wakes the edge again.
    let level = e.call(EPOLL_CREATE1, [O_CLOEXEC, 0, 0, 0, 0, 0]);
    let edge = e.call(EPOLL_CREATE1, [O_CLOEXEC, 0, 0, 0, 0, 0]);
    let mut event = 1u32.to_le_bytes().to_vec();
    event.extend_from_slice(&1u64.to_le_bytes());
    e.put(EVENT, &event);
    let added = e.call(EPOLL_CTL, [level as u64, 1, q as u64, EVENT, 0, 0]);
    e.put(EVENT, &(1u32 | 1 << 31).to_le_bytes());
    let added_edge = e.call(EPOLL_CTL, [edge as u64, 1, q as u64, EVENT, 0, 0]);
    let wait = |e: &mut Env, fd: i64| e.call(EPOLL_WAIT, [fd as u64, EVENT + 0x40, 4, 0, 0, 0]);
    let empty = (wait(&mut e, level), wait(&mut e, edge));
    out.push(format!(
        "epoll: add={added},{added_edge} empty={},{}",
        empty.0, empty.1
    ));
    e.send(q, b"1", 0, 0);
    let l1 = wait(&mut e, level);
    let events = u32::from_le_bytes(e.get(EVENT + 0x40, 4).try_into().unwrap());
    let e1 = wait(&mut e, edge);
    let e2 = wait(&mut e, edge);
    e.send(q, b"2", 0, 0);
    let e3 = wait(&mut e, edge);
    let level_again = wait(&mut e, level);
    out.push(format!(
        "epoll: level={l1} events={events:x} level-again={level_again} edge={e1},{e2},{e3}"
    ));
    e.receive(q, 8, 0);
    e.receive(q, 8, 0);
    let drained = (wait(&mut e, level), wait(&mut e, edge));
    out.push(format!("epoll: drained={},{}", drained.0, drained.1));
    check(
        &out,
        &[
            "poll-0: n=2 revents=4,4 select=1 in=0 out=1",
            "poll-1: n=2 revents=5,5 select=2 in=1 out=1",
            "poll-2: n=2 revents=1,1 select=1 in=1 out=0",
            "epoll: add=0,0 empty=0,0",
            "epoll: level=1 events=1 level-again=1 edge=1,0,1",
            "epoll: drained=0,0",
        ],
    );
}

/// A `struct sigevent` at `SIGEV`.
const SIGEV: u64 = DATA + 0xc00;
/// A signal set, and a `siginfo_t`.
const SIGSET: u64 = DATA + 0xd00;
const SIGINFO: u64 = DATA + 0xe00;
/// 32 zero bytes, a `SIGEV_THREAD` cookie.
const ZEROS: u64 = DATA + 0xf00;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_THREAD: i32 = 2;
const SIGUSR1: u64 = 10;

impl Env {
    fn sigevent(&self, notify: i32, signo: i32, value: u64) -> u64 {
        let mut bytes = value.to_le_bytes().to_vec();
        bytes.extend_from_slice(&signo.to_le_bytes());
        bytes.extend_from_slice(&notify.to_le_bytes());
        bytes.resize(64, 0);
        self.put(SIGEV, &bytes);
        SIGEV
    }

    fn notify(&mut self, fd: i64, event: u64) -> i64 {
        self.call(MQ_NOTIFY, [fd as u64, event, 0, 0, 0, 0])
    }

    /// The state line from the start, with the registered process shown as
    /// whether it is this one, as `show_line` shows it.
    fn line(&mut self, fd: i64) -> String {
        self.call(LSEEK, [fd as u64, 0, 0, 0, 0, 0]);
        let mut line = self.read(fd, 199);
        let n = line.len();
        let owner = match line.find("NOTIFY_PID:") {
            Some(at) => {
                let pid: String = line[at + 11..]
                    .chars()
                    .take_while(|c| !c.is_whitespace())
                    .collect();
                line.truncate(at + 11);
                i32::from(pid == "1")
            }
            None => -1,
        };
        format!("read={n} [{}] owner={owner}", line.replace('\n', "|"))
    }

    /// `rt_sigtimedwait` for `SIGUSR1` without waiting.
    fn take_signal(&mut self) -> i64 {
        self.put(SIGSET, &(1u64 << (SIGUSR1 - 1)).to_le_bytes());
        self.put(SIGINFO, &[0; 128]);
        let none = self.timespec(0, 0);
        self.call(128, [SIGSET, SIGINFO, none, 8, 0, 0])
    }
}

/// `notify_case`, the part in one process: `mq_notify`'s checks in Linux's
/// order, and a `SIGEV_SIGNAL` registration that a message to the empty
/// queue sends once.
#[test]
fn mq_notify_checks_its_event_then_the_queue_and_signals_once() {
    let mut e = Env::new();
    let mut out = Vec::new();
    let q = e.open_with(b"n", O_RDWR | O_CREAT, 0o600, 4, 8);
    assert!(q >= 0);
    e.put(SIGSET, &(1u64 << (SIGUSR1 - 1)).to_le_bytes());
    assert_eq!(e.call(14, [0, SIGSET, 0, 8, 0, 0]), 0);
    assert_eq!(e.call(PIPE2, [FDS, 0, 0, 0, 0, 0]), 0);
    let pipe = u64::from(u32::from_le_bytes(e.get(FDS, 4).try_into().unwrap()));
    let unix_socket = e.call(41, [1, 2, 0, 0, 0, 0]);
    assert!(unix_socket >= 0);

    // The checks: the notification, then the queue.
    let bad_kind = e.sigevent(3, 0, 0);
    let kind = e.notify(q, bad_kind);
    let kind_bad_fd = e.notify(-1, bad_kind);
    let bad_signal = e.sigevent(SIGEV_SIGNAL, 65, 0);
    let signal = e.notify(q, bad_signal);
    out.push(format!(
        "checks: kind={kind} kind-bad-fd={kind_bad_fd} signal={signal} fault={} bad-fd={} pipe={}",
        e.notify(q, BAD),
        e.notify(-1, 0),
        e.notify(pipe as i64, 0),
    ));
    let to_pipe = e.sigevent(SIGEV_THREAD, pipe as i32, ZEROS);
    let thread_pipe = e.notify(q, to_pipe);
    let to_unix = e.sigevent(SIGEV_THREAD, unix_socket as i32, ZEROS);
    let thread_unix = e.notify(q, to_unix);
    let to_nothing = e.sigevent(SIGEV_THREAD, 999, ZEROS);
    let thread_no_fd = e.notify(q, to_nothing);
    let bad_cookie = e.sigevent(SIGEV_THREAD, pipe as i32, BAD);
    let cookie_fault = e.notify(q, bad_cookie);
    out.push(format!(
        "checks: thread-pipe={thread_pipe} thread-unix={thread_unix} thread-no-fd={thread_no_fd} \
         cookie-fault={cookie_fault}"
    ));
    let no_signal = e.sigevent(SIGEV_SIGNAL, 0, 0);
    out.push(format!(
        "checks: signal-zero={} busy={} unregister={} unregister-again={}",
        e.notify(q, no_signal),
        e.notify(q, no_signal),
        e.notify(q, 0),
        e.notify(q, 0),
    ));

    // SIGEV_SIGNAL: a message to the empty queue sends it, once.
    let by_signal = e.sigevent(SIGEV_SIGNAL, SIGUSR1 as i32, 4242);
    out.push(format!("signal: register={}", e.notify(q, by_signal)));
    out.push(format!("signal-registered: {}", e.line(q)));
    e.send(q, b"hello", 3, 0);
    let number = e.take_signal();
    let word = |e: &Env, at: u64| i32::from_le_bytes(e.get(SIGINFO + at, 4).try_into().unwrap());
    out.push(format!(
        "signal: number={number} code={} value={} pid={} uid={} errno={}",
        word(&e, 8),
        word(&e, 24),
        i32::from(word(&e, 16) == 1),
        word(&e, 20),
        word(&e, 4),
    ));
    out.push(format!("signal-sent: {}", e.line(q)));
    // A message to a queue that is not empty tells no one.
    let by_signal = e.sigevent(SIGEV_SIGNAL, SIGUSR1 as i32, 4242);
    out.push(format!("signal: again={}", e.notify(q, by_signal)));
    e.send(q, b"more", 3, 0);
    out.push(format!("signal: not-empty={}", e.take_signal()));
    e.receive(q, 8, 0);
    e.receive(q, 8, 0);
    // Closing any descriptor of the queue drops the owner's registration.
    out.push(format!("registered: {}", e.line(q)));
    let copy = e.call(32, [q as u64, 0, 0, 0, 0, 0]);
    e.close(copy);
    out.push(format!("closed-dup: {}", e.line(q)));
    check(
        &out,
        &[
            "checks: kind=-22 kind-bad-fd=-22 signal=-22 fault=-14 bad-fd=-9 pipe=-9",
            "checks: thread-pipe=-88 thread-unix=-22 thread-no-fd=-9 cookie-fault=-14",
            "checks: signal-zero=0 busy=-16 unregister=0 unregister-again=0",
            "signal: register=0",
            "signal-registered: read=60 [QSIZE:0          NOTIFY:0     SIGNO:10    NOTIFY_PID:] owner=1",
            "signal: number=10 code=-3 value=4242 pid=1 uid=0 errno=0",
            "signal-sent: read=60 [QSIZE:5          NOTIFY:0     SIGNO:0     NOTIFY_PID:] owner=0",
            "signal: again=0",
            "signal: not-empty=-11",
            "registered: read=60 [QSIZE:0          NOTIFY:0     SIGNO:10    NOTIFY_PID:] owner=1",
            "closed-dup: read=60 [QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:] owner=0",
        ],
    );
}

/// `dev_case`, the part in one namespace: a queue through `/dev/mqueue`'s
/// paths, and one made there.
#[test]
fn dev_mqueue_s_paths_reach_the_namespace_s_queues() {
    const STAT_PATH: u64 = 4;
    const ACCESS: u64 = 21;
    const UNLINK: u64 = 87;
    const RMDIR: u64 = 84;
    const O_DIRECTORY: u64 = 0o200000;
    let mut e = Env::new();
    let mut out = Vec::new();
    let mode = |e: &Env| u32::from_le_bytes(e.get(STAT + 24, 4).try_into().unwrap());
    let path = e.name(b"/dev/mqueue");
    let stated = e.call(STAT_PATH, [path, STAT, 0, 0, 0, 0]);
    let dir = mode(&e);
    out.push(format!(
        "dev-mqueue: stat={stated} directory={} perms={:o}",
        u8::from(dir & 0o170000 == 0o040000),
        dir & 0o7777
    ));
    let q = e.open_with(
        b"paludarium-mqueue-dev",
        O_RDWR | O_CREAT | O_EXCL,
        0o640,
        3,
        16,
    );
    assert!(q >= 0);
    e.send(q, b"abc", 4, 0);
    let path = e.name(b"/dev/mqueue/paludarium-mqueue-dev");
    let stated = e.call(STAT_PATH, [path, STAT, 0, 0, 0, 0]);
    out.push(format!(
        "queue: stat={stated} mode={:o} size={}",
        mode(&e),
        e.long(STAT + 48)
    ));
    let path = e.name(b"/dev/mqueue/paludarium-mqueue-dev");
    let d = e.call(OPEN, [path, O_RDWR | O_CLOEXEC, 0, 0, 0, 0]);
    let line = e.read(d, 99);
    out.push(format!(
        "opened: open={} [{}]",
        u8::from(d >= 0),
        line.split(' ').next().unwrap()
    ));
    out.push(format!("opened: {}", e.getattr(d)));
    out.push(format!("opened: got={}", e.receive(d, 16, 0)));
    out.push(format!("opened: readlink [{}]", e.link(d)));
    out.push(format!("mq_open: readlink [{}]", e.link(q)));
    let open = |e: &mut Env, path: &[u8], flags: u64| {
        let at = e.name(path);
        e.call(OPEN, [at, flags, 0o600, 0, 0, 0])
    };
    let exclusive = open(
        &mut e,
        b"/dev/mqueue/paludarium-mqueue-dev",
        O_RDWR | O_CREAT | O_EXCL,
    );
    let missing = open(&mut e, b"/dev/mqueue/none", O_RDONLY);
    let directory = open(
        &mut e,
        b"/dev/mqueue/paludarium-mqueue-dev",
        O_RDONLY | O_DIRECTORY,
    );
    let dir_write = open(&mut e, b"/dev/mqueue", O_WRONLY);
    let path = e.name(b"/dev/mqueue/paludarium-mqueue-dev");
    let access = e.call(ACCESS, [path, 6, 0, 0, 0, 0]);
    let path = e.name(b"/dev/mqueue/none");
    let access_missing = e.call(ACCESS, [path, 0, 0, 0, 0, 0]);
    out.push(format!(
        "open: exclusive={exclusive} missing={missing} directory={directory} \
         dir-write={dir_write} access={access} access-missing={access_missing}"
    ));
    // A queue made through it has the namespace's default attributes.
    e.call(UMASK, [0o022, 0, 0, 0, 0, 0]);
    let path = e.name(b"/dev/mqueue/made");
    let made = e.call(OPEN, [path, O_WRONLY | O_CREAT | O_EXCL, 0o666, 0, 0, 0]);
    let path = e.name(b"/dev/mqueue/made");
    let stated = e.call(STAT_PATH, [path, STAT, 0, 0, 0, 0]);
    out.push(format!(
        "made: open={} stat={stated} mode={:o}",
        u8::from(made >= 0),
        mode(&e)
    ));
    out.push(format!("made: {}", e.getattr(made)));
    let by_name = e.open(b"made", O_RDONLY, 0, 0);
    out.push(format!("made: mq_open={}", u8::from(by_name >= 0)));
    e.close(by_name);
    e.close(made);
    let path_call = |e: &mut Env, n: u64, path: &[u8]| {
        let at = e.name(path);
        e.call(n, [at, 0, 0, 0, 0, 0])
    };
    let unlinked = path_call(&mut e, UNLINK, b"/dev/mqueue/made");
    let again = path_call(&mut e, UNLINK, b"/dev/mqueue/made");
    let after = e.open(b"made", O_RDONLY, 0, 0);
    let rmdir = path_call(&mut e, RMDIR, b"/dev/mqueue/paludarium-mqueue-dev");
    let rmdir_missing = path_call(&mut e, RMDIR, b"/dev/mqueue/none");
    let unlink_missing = path_call(&mut e, UNLINK, b"/dev/mqueue/none");
    let queue = path_call(&mut e, UNLINK, b"/dev/mqueue/paludarium-mqueue-dev");
    out.push(format!(
        "unlink: made={unlinked} again={again} mq_open-after={after} rmdir={rmdir} \
         rmdir-missing={rmdir_missing} unlink-missing={unlink_missing} queue={queue}"
    ));
    out.push(format!("unlinked: readlink [{}]", e.link(d)));
    check(
        &out,
        &[
            "dev-mqueue: stat=0 directory=1 perms=1777",
            "queue: stat=0 mode=100640 size=80",
            "opened: open=1 [QSIZE:3]",
            "opened: getattr=0 flags=0 maxmsg=3 msgsize=16 curmsgs=1 reserved=0",
            "opened: got=3:4:abc",
            "opened: readlink [/dev/mqueue/paludarium-mqueue-dev]",
            "mq_open: readlink [/paludarium-mqueue-dev]",
            "open: exclusive=-17 missing=-2 directory=-20 dir-write=-21 access=0 access-missing=-2",
            "made: open=1 stat=0 mode=100644",
            "made: getattr=0 flags=0 maxmsg=10 msgsize=8192 curmsgs=0 reserved=0",
            "made: mq_open=1",
            "unlink: made=0 again=-2 mq_open-after=-2 rmdir=-20 rmdir-missing=-2 unlink-missing=-2 queue=0",
            "unlinked: readlink [/dev/mqueue/paludarium-mqueue-dev (deleted)]",
        ],
    );
}
