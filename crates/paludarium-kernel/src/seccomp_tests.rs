//! Seccomp through the system call interface: `seccomp`'s operations and
//! flags, the programs Linux refuses, a filter's actions on the number, an
//! argument and the length, stacked filters, and user notifications: the
//! listener, receiving and answering a call, its checks, `ADDFD`, and the
//! listener's close and hang-up. The expected values are Linux's
//! (`kernel/seccomp.c`): they are the lines of the seccomp and
//! seccomp-notify cases of `tests/guests/processes/process.c`, which the
//! differential tests compare with Linux. Each process's lines are compared
//! in the order it prints them; how the guest's two processes' lines
//! interleave is its stdout's buffering. The lines of a call a signal
//! handler interrupts or restarts, and those after the seccomp case's
//! SIGSYS trap, stay with the differential tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{ExitStatus, GuestAddr};

const DATA: u64 = 0x600000;
/// A path, a `struct sock_fprog` and its program.
const PATH: u64 = DATA;
const FPROG: u64 = DATA + 0x100;
const PROGRAM: u64 = DATA + 0x200;
/// An ioctl's or a call's argument.
const ARG: u64 = DATA + 0x2000;
/// What a read reads.
const BUF: u64 = DATA + 0x2200;
/// A `struct msghdr`, its `struct iovec` and its control message.
const HEADER: u64 = DATA + 0x2400;
const IOV: u64 = DATA + 0x2480;
const CONTROL: u64 = DATA + 0x24c0;
/// A `struct pollfd`, and a `struct rlimit`.
const POLLFD: u64 = DATA + 0x2500;
const LIMIT: u64 = DATA + 0x2540;
/// A program longer than Linux takes, and mapped zeros after it.
const HUGE: u64 = DATA + 0x4000;
const SIZE: u64 = 0x20000;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const POLL: u64 = 7;
const IOCTL: u64 = 16;
const PIPE: u64 = 22;
const DUP: u64 = 32;
const GETPID: u64 = 39;
const SENDMSG: u64 = 46;
const RECVMSG: u64 = 47;
const SOCKETPAIR: u64 = 53;
const FORK: u64 = 57;
const WAIT4: u64 = 61;
const FCNTL: u64 = 72;
const GETUID: u64 = 102;
const GETGID: u64 = 104;
const GETEUID: u64 = 107;
const GETEGID: u64 = 108;
const GETPPID: u64 = 110;
const PRCTL: u64 = 157;
const SETRLIMIT: u64 = 160;
const SECCOMP: u64 = 317;

const PR_GET_SECCOMP: u64 = 21;
const PR_SET_SECCOMP: u64 = 22;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const RLIMIT_NOFILE: u64 = 7;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const O_CLOEXEC: u32 = 0o2000000;
const O_NONBLOCK: u32 = 0o4000;
const ALLOW: u32 = 0x7fff_0000;
const NOTIFY: u32 = 0x7fc0_0000;

const RECV: u64 = 0xc050_2100;
const SEND: u64 = 0xc018_2101;
const ID_VALID: u64 = 0x4008_2102;
const ADDFD: u64 = 0x4018_2103;
const SET_FLAGS: u64 = 0x4008_2104;

/// A classic BPF instruction.
type Insn = (u16, u8, u8, u32);

/// Loads the call's number.
const NR: Insn = (0x20, 0, 0, 0);

fn ret(k: u32) -> Insn {
    (0x06, 0, 0, k)
}

/// The number is `x`: return `k`, else the next instruction.
fn if_nr(x: u64, k: u32) -> [Insn; 2] {
    [(0x15, 0, 1, x as u32), ret(k)]
}

fn errno_action(e: u32) -> u32 {
    0x0005_0000 | e
}

/// A process's kernel, thread and memory, and the lines it prints.
struct Env {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
    lines: Vec<String>,
}

impl Env {
    /// The first process, as root, whose standard descriptors are open as
    /// the guest's are.
    fn new() -> Self {
        let k = Box::new(Kernel::new(Arc::new(
            paludarium_host::testing::RecordingHost::new(),
        )));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + SIZE)),
        );
        let m = Arc::new(AddressSpace::new());
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

    /// A call's result, or `-errno`: the guest's `sc_err`.
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

    fn call0(&mut self, n: u64) -> i64 {
        self.call(n, [0; 6])
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

    fn long(&self, at: u64) -> u64 {
        self.m.read_u64(GuestAddr(at)).unwrap()
    }

    fn open(&mut self, path: &str, flags: u64) -> i64 {
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        self.put(PATH, &bytes);
        self.call(OPEN, [PATH, flags, 0, 0, 0, 0])
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// Two descriptors a call writes at `ARG`.
    fn pair(&mut self, n: u64, a: [u64; 6]) -> (i64, i64) {
        assert_eq!(self.call(n, a), 0);
        (i64::from(self.word(ARG)), i64::from(self.word(ARG + 4)))
    }

    /// Puts `program` at `PROGRAM` and its `struct sock_fprog` at `FPROG`.
    fn fprog(&self, program: &[Insn]) -> u64 {
        let mut bytes = Vec::new();
        for &(code, jt, jf, k) in program {
            bytes.extend_from_slice(&code.to_le_bytes());
            bytes.extend_from_slice(&[jt, jf]);
            bytes.extend_from_slice(&k.to_le_bytes());
        }
        self.put(PROGRAM, &bytes);
        self.raw_fprog(program.len() as u16, PROGRAM)
    }

    fn raw_fprog(&self, len: u16, filter: u64) -> u64 {
        let mut bytes = len.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&filter.to_le_bytes());
        self.put(FPROG, &bytes);
        FPROG
    }

    /// The guest's `sc_set`: `SECCOMP_SET_MODE_FILTER` with `flags`.
    fn set(&mut self, flags: u64, program: &[Insn]) -> i64 {
        let fprog = self.fprog(program);
        self.call(SECCOMP, [1, flags, fprog, 0, 0, 0])
    }

    /// The guest's `sc_status`: `PR_GET_SECCOMP` and the status file's
    /// fields.
    fn status(&mut self, who: &str) {
        let fd = self.open("/proc/self/status", 0);
        let mut text = Vec::new();
        loop {
            let n = self.call(READ, [fd as u64, BUF, 512, 0, 0, 0]);
            if n <= 0 {
                break;
            }
            text.extend_from_slice(&self.get(BUF, n as usize));
        }
        self.close(fd);
        let text = String::from_utf8(text).unwrap();
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .map_or(-1, |v| v.trim().parse::<i64>().unwrap())
        };
        let (mode, filters) = (field("Seccomp:"), field("Seccomp_filters:"));
        let prctl = self.call(PRCTL, [PR_GET_SECCOMP, 0, 0, 0, 0, 0]);
        self.say(format!(
            "seccomp {who} prctl={prctl} status={mode} filters={filters}"
        ));
    }

    /// `fork`, as the guest's `sc_child` makes it: the child sets
    /// `PR_SET_NO_NEW_PRIVS`.
    fn fork(&mut self) -> Env {
        let pid = self.call0(FORK);
        let (mut k, t) = self.k.take_child().unwrap();
        assert_eq!(pid, i64::from(t.tid));
        let m = k.take_spawn_memory().unwrap();
        let mut child = Env {
            k,
            t,
            m,
            lines: Vec::new(),
        };
        assert_eq!(child.call(PRCTL, [PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0]), 0);
        child
    }

    fn exit(mut self, code: i32) -> Vec<String> {
        self.k.finish_thread(&self.t, &self.m);
        self.k.complete_process(ExitStatus::Exited(code));
        self.lines
    }

    /// The guest's `sc_wait` of a child that has exited.
    fn wait(&mut self, what: &str, pid: i64) {
        assert_eq!(self.call(WAIT4, [pid as u64, ARG, 0, 0, 0, 0]), pid);
        let status = self.word(ARG);
        self.say(format!("seccomp {what} exit={}", (status >> 8) & 0xff));
    }

    /// The `revents` of a poll for `POLLIN | POLLOUT` that does not wait.
    fn revents(&mut self, fd: i64) -> u16 {
        let mut p = (fd as u32).to_le_bytes().to_vec();
        p.extend_from_slice(&5u16.to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        self.put(POLLFD, &p);
        assert!(self.call(POLL, [POLLFD, 1, 0, 0, 0, 0]) >= 0);
        u16::from_le_bytes(self.get(POLLFD + 6, 2).try_into().unwrap())
    }

    /// The guest's `sc_revents(fd, -1)`: polls until a notification is
    /// ready, the other process's thread making its call meanwhile.
    fn ready(&mut self, fd: i64) -> u16 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let revents = self.revents(fd);
            if revents != 0 {
                return revents;
            }
            assert!(std::time::Instant::now() < deadline, "no notification");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn ioctl(&mut self, fd: i64, request: u64, arg: u64) -> i64 {
        self.call(IOCTL, [fd as u64, request, arg, 0, 0, 0])
    }

    /// An ioctl on the `u64` id at `ARG`.
    fn id_ioctl(&mut self, fd: i64, request: u64, id: u64) -> i64 {
        self.put(ARG, &id.to_le_bytes());
        self.ioctl(fd, request, ARG)
    }

    /// The guest's `sc_receive`: a `struct seccomp_notif` at `ARG`.
    fn receive(&mut self, fd: i64) -> (i64, Notif) {
        self.put(ARG, &[0; 80]);
        let r = self.ioctl(fd, RECV, ARG);
        let word = |at: u64| self.word(ARG + at);
        let notif = Notif {
            id: self.long(ARG),
            pid: word(8),
            flags: word(12),
            nr: word(16) as i32,
            arch: word(20),
            ip: self.long(ARG + 24),
            arg0: self.long(ARG + 32),
        };
        (r, notif)
    }

    /// The guest's `sc_answer`: a `struct seccomp_notif_resp`.
    fn answer(&mut self, fd: i64, id: u64, val: i64, error: i32, flags: u32) -> i64 {
        let mut b = id.to_le_bytes().to_vec();
        b.extend_from_slice(&val.to_le_bytes());
        b.extend_from_slice(&error.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        self.put(ARG, &b);
        self.ioctl(fd, SEND, ARG)
    }

    /// The guest's `sc_add`: a `struct seccomp_notif_addfd`, and what
    /// follows it for a larger size.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        fd: i64,
        request: u64,
        id: u64,
        flags: u32,
        src: i64,
        newfd: u32,
        newfd_flags: u32,
        more: u64,
    ) -> i64 {
        let mut b = id.to_le_bytes().to_vec();
        for v in [flags, src as u32, newfd, newfd_flags] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&more.to_le_bytes());
        self.put(ARG, &b);
        self.ioctl(fd, request, ARG)
    }

    /// Sends `fd` over the unix socket `sock` (SCM_RIGHTS), as the guest's
    /// `send_fds`.
    fn send_fd(&mut self, sock: i64, fd: i64) {
        self.put(BUF, b"l");
        self.put(IOV, &BUF.to_le_bytes());
        self.put(IOV + 8, &1u64.to_le_bytes());
        let mut control = 20u64.to_le_bytes().to_vec();
        control.extend_from_slice(&1i32.to_le_bytes());
        control.extend_from_slice(&1i32.to_le_bytes());
        control.extend_from_slice(&(fd as i32).to_le_bytes());
        control.extend_from_slice(&[0; 4]);
        self.put(CONTROL, &control);
        self.header(24);
        assert_eq!(self.call(SENDMSG, [sock as u64, HEADER, 0, 0, 0, 0]), 1);
    }

    /// The descriptor a message on `sock` carries.
    fn receive_fd(&mut self, sock: i64) -> i64 {
        self.put(IOV, &BUF.to_le_bytes());
        self.put(IOV + 8, &1u64.to_le_bytes());
        self.put(CONTROL, &[0; 24]);
        self.header(24);
        assert_eq!(self.call(RECVMSG, [sock as u64, HEADER, 0, 0, 0, 0]), 1);
        i64::from(self.word(CONTROL + 16))
    }

    fn header(&self, controllen: u64) {
        let mut header = Vec::new();
        for v in [0, 0, IOV, 1, CONTROL, controllen, 0] {
            header.extend_from_slice(&v.to_le_bytes());
        }
        self.put(HEADER, &header);
    }
}

/// The fields of a `struct seccomp_notif` the guest prints.
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    nr: i32,
    arch: u32,
    ip: u64,
    arg0: u64,
}

/// C's `%#x`.
fn hex(value: u64) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

/// Compares the lines a process printed with Linux's, printing them all
/// when one differs.
fn check(lines: &[String], expected: &[&str]) {
    if lines != expected {
        for line in lines {
            println!("{line}");
        }
    }
    assert_eq!(lines, expected);
}

/// seccomp: the operations and flags, the programs Linux refuses, a
/// filter's actions, and stacked filters, up to the SIGSYS trap.
#[test]
fn seccomp_checks_operations_programs_and_stacks_filters() {
    let mut e = Env::new();
    let allow = [ret(ALLOW)];
    e.status("none");
    // Operations and flags.
    let mut line = "seccomp avail".to_owned();
    for action in [
        0x8000_0000u32,
        0,
        0x30000,
        0x50000,
        0x7fc0_0000,
        0x7ff0_0000,
        0x7ffc_0000,
        ALLOW,
        0x10000,
        0x7fff_0001,
    ] {
        e.put(ARG, &action.to_le_bytes());
        let r = e.call(SECCOMP, [2, 0, ARG, 0, 0, 0]);
        line.push_str(&format!(" {r}"));
    }
    e.put(BUF, &[0; 6]);
    let got = e.call(SECCOMP, [3, 0, BUF, 0, 0, 0]);
    let sizes = e.get(BUF, 6);
    let half = |i: usize| u16::from_le_bytes([sizes[i], sizes[i + 1]]);
    e.put(ARG, &0x8000_0000u32.to_le_bytes());
    let flags = e.call(SECCOMP, [2, 1, ARG, 0, 0, 0]);
    let fault = e.call(SECCOMP, [2, 0, 0, 0, 0, 0]);
    let sizes_flags = e.call(SECCOMP, [3, 1, BUF, 0, 0, 0]);
    line.push_str(&format!(
        " flags={flags} fault={fault} sizes={got}:{},{},{} sizes-flags={sizes_flags}",
        half(0),
        half(2),
        half(4)
    ));
    e.say(line);
    let one = e.fprog(&allow);
    let mut args = Vec::new();
    for (op, flags, arg) in [
        (9, 0, one),
        (0, 1, 0),
        (0, 0, one),
        (1, 128, one),
        (1, 1 | 8, one),
        (1, 32, one),
        (1, 64, one),
        (1, 0, 8),
    ] {
        args.push(e.call(SECCOMP, [op, flags, arg, 0, 0, 0]));
    }
    let empty = e.raw_fprog(0, PROGRAM);
    args.push(e.call(SECCOMP, [1, 0, empty, 0, 0, 0]));
    let huge = e.raw_fprog(4097, HUGE);
    args.push(e.call(SECCOMP, [1, 0, huge, 0, 0, 0]));
    e.say(format!(
        "seccomp args op={} strict-flags={} strict-args={} unknown-flag={} tsync-listener={} \
         killable={} restart={} fprog={} empty={} huge={}",
        args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]
    ));
    let r = e.call(PRCTL, [PR_SET_SECCOMP, 3, 0, 0, 0, 0]);
    e.say(format!("seccomp prctl mode={r}"));
    let mut c = e.fork();
    // Programs Linux refuses, each EINVAL.
    let a = ret(ALLOW);
    let refused: [&[Insn]; 13] = [
        &[(0x00, 0, 0, 0)],
        &[(0x05, 0, 0, 1), a],
        &[(0x15, 1, 0, 0), a],
        &[(0x34, 0, 0, 0), a],
        &[(0x64, 0, 0, 32), a],
        &[(0x94, 0, 0, 2), a],
        &[(0x28, 0, 0, 0), a],
        &[(0x20, 0, 0, 2), a],
        &[(0x20, 0, 0, 64), a],
        &[(0x60, 0, 0, 0), a],
        &[(0x15, 0, 1, 0), (0x02, 0, 0, 1), (0x60, 0, 0, 1), a],
        &[(0x40, 0, 0, 0), a],
        &[(0xff, 0, 0, 0), a],
    ];
    let mut line = "seccomp refused".to_owned();
    for program in refused {
        let r = c.set(0, program);
        line.push_str(&format!(" {r}"));
    }
    let null = c.raw_fprog(1, 0);
    let r = c.call(SECCOMP, [1, 0, null, 0, 0, 0]);
    let fault = c.raw_fprog(1, 8);
    let f = c.call(SECCOMP, [1, 0, fault, 0, 0, 0]);
    line.push_str(&format!(" null={r} fault={f}"));
    c.say(line);
    c.status("refused");
    // A filter on the number, an argument's upper half and LEN.
    let mut first = vec![
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xc000_003e),
        ret(0x8000_0000),
        NR,
    ];
    first.extend(if_nr(GETPID, errno_action(1)));
    first.extend(if_nr(GETPPID, errno_action(5000)));
    first.push((0x15, 0, 3, DUP as u32));
    first.extend([(0x20, 0, 0, 20), (0x15, 0, 1, 1), ret(errno_action(77))]);
    first.extend(if_nr(GETUID, 0x7ff0_0000));
    first.extend(if_nr(GETGID, NOTIFY));
    first.extend(if_nr(GETEUID, 0x7ffc_0000));
    first.push((0x15, 0, 3, GETEGID as u32));
    first.extend([(0x80, 0, 0, 0), (0x15, 1, 0, 64), ret(errno_action(9))]);
    first.push(ret(ALLOW));
    let set = c.set(0, &first);
    let fd = c.call(DUP, [1, 0, 0, 0, 0, 0]);
    if fd > 0 {
        c.close(fd);
    }
    let getpid = c.call0(GETPID);
    let getppid = c.call0(GETPPID);
    let dup_high = c.call(DUP, [1 | 1 << 32, 0, 0, 0, 0, 0]);
    let trace = c.call0(GETUID);
    let notify = c.call0(GETGID);
    let log = c.call0(GETEUID) >= 0;
    let len = c.call0(GETEGID) >= 0;
    c.say(format!(
        "seccomp filter set={set} getpid={getpid} getppid={getppid} dup-high={dup_high} \
         dup={} trace={trace} notify={notify} log={} len={}",
        (fd > 0) as i32,
        log as i32,
        len as i32
    ));
    c.status("one");
    // Strict mode is not for a thread with filters.
    let r = c.call(SECCOMP, [0, 0, 0, 0, 0, 0]);
    c.say(format!("seccomp strict-after={r}"));
    // More filters: equal actions take the newest's data, a lower one wins
    // whatever the order.
    let mut second = vec![NR];
    second.extend(if_nr(GETPID, errno_action(2)));
    second.push(ret(ALLOW));
    let mut third = vec![NR];
    third.extend(if_nr(GETPPID, 0x30005));
    third.push(ret(ALLOW));
    let second_set = c.set(0, &second);
    let third_set = c.set(2, &third);
    let one = c.fprog(&allow);
    let prctl_set = c.call(PRCTL, [PR_SET_SECCOMP, 2, one, 0, 0, 0]);
    let getpid = c.call0(GETPID);
    c.say(format!(
        "seccomp stack second={second_set} third={third_set} prctl={prctl_set} getpid={getpid}"
    ));
    c.status("four");
    let mut lines = std::mem::take(&mut e.lines);
    lines.extend(c.exit(0));
    check(
        &lines,
        &[
            "seccomp none prctl=0 status=0 filters=0",
            "seccomp avail 0 0 0 0 0 0 0 0 -95 -95 flags=-22 fault=-14 sizes=0:80,24,64 sizes-flags=-22",
            "seccomp args op=-22 strict-flags=-22 strict-args=-22 unknown-flag=-22 tsync-listener=-22 killable=-22 restart=-22 fprog=-14 empty=-22 huge=-22",
            "seccomp prctl mode=-22",
            "seccomp refused -22 -22 -22 -22 -22 -22 -22 -22 -22 -22 -22 -22 -22 null=-22 fault=-14",
            "seccomp refused prctl=0 status=0 filters=0",
            "seccomp filter set=0 getpid=-1 getppid=-4095 dup-high=-77 dup=1 trace=-38 notify=-38 log=1 len=1",
            "seccomp one prctl=2 status=2 filters=1",
            "seccomp strict-after=-22",
            "seccomp stack second=0 third=0 prctl=0 getpid=-2",
            "seccomp four prctl=2 status=2 filters=4",
        ],
    );
}

/// A seccomp-notify child's turn: the argument of its `getppid` and how
/// it prints what that returns.
type Turn = (u64, fn(&mut Env, i64, i64, i64) -> String);

/// The child's side of seccomp-notify, which the guest's turn bytes drive:
/// `getppid(k)` on a thread of its own for each turn, its line, then
/// `done`.
fn notify_child(
    mut c: Env,
    turns: std::sync::mpsc::Receiver<Turn>,
    done: std::sync::mpsc::SyncSender<()>,
    parent: i64,
    lowest: i64,
) -> Env {
    for (k, show) in turns {
        let r = c.call(GETPPID, [k, 0, 0, 0, 0, 0]);
        let line = show(&mut c, r, parent, lowest);
        c.say(line);
        done.send(()).unwrap();
    }
    c
}

/// seccomp-notify: a listener's descriptor, receiving and answering the
/// calls its filter sends, the checks of each request, `ADDFD`, the
/// listener's close, and `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`'s
/// listener once its child is gone.
#[test]
fn seccomp_notify_receives_answers_and_adds_descriptors() {
    let mut e = Env::new();
    let mut notify = vec![NR];
    notify.extend(if_nr(GETPPID, NOTIFY));
    notify.push(ret(ALLOW));
    let allow = [ret(ALLOW)];
    let (sock, child_sock) = e.pair(SOCKETPAIR, [1, 1, 0, ARG, 0, 0]);
    let mut c = e.fork();
    let pid: u64 = c.t.tid.into();
    c.close(sock);
    let parent = c.call0(GETPPID);
    // The descriptor is taken first: EMFILE leaves no filter.
    let lowest = c.call(DUP, [0; 6]);
    c.close(lowest);
    c.put(LIMIT, &(lowest as u64).to_le_bytes());
    c.put(LIMIT + 8, &4096u64.to_le_bytes());
    assert_eq!(c.call(SETRLIMIT, [RLIMIT_NOFILE, LIMIT, 0, 0, 0, 0]), 0);
    let emfile = c.set(8, &notify);
    c.put(LIMIT, &1024u64.to_le_bytes());
    assert_eq!(c.call(SETRLIMIT, [RLIMIT_NOFILE, LIMIT, 0, 0, 0, 0]), 0);
    c.status("no-listener");
    c.say(format!("seccomp listener emfile={emfile}"));
    let fd = c.set(8, &notify);
    let link = format!("/proc/self/fd/{fd}");
    c.put(PATH, format!("{link}\0").as_bytes());
    let n = c.call(89, [PATH, BUF, 63, 0, 0, 0]);
    let link = String::from_utf8(c.get(BUF, n.max(0) as usize)).unwrap();
    c.call(5, [fd as u64, ARG, 0, 0, 0, 0]);
    let mode = c.word(ARG + 24);
    let cloexec = c.call(FCNTL, [fd as u64, F_GETFD, 0, 0, 0, 0]);
    let fl = c.call(FCNTL, [fd as u64, F_GETFL, 0, 0, 0, 0]);
    let read = c.call(READ, [fd as u64, BUF, 1, 0, 0, 0]);
    c.put(BUF, b"x");
    let write = c.call(WRITE, [fd as u64, BUF, 1, 0, 0, 0]);
    let seek = c.call(8, [fd as u64, 0, 0, 0, 0, 0]);
    let revents = c.revents(fd);
    c.say(format!(
        "seccomp listener fd={} cloexec={cloexec} fl={} mode={mode:o} link={link} read={read} \
         write={write} seek={seek} revents={}",
        (fd == lowest) as i32,
        hex(fl as u64),
        hex(revents.into())
    ));
    // One listener to a list of filters.
    let again = c.set(8, &allow);
    let plain = c.set(0, &allow);
    let above = c.set(8, &allow);
    c.say(format!(
        "seccomp listener again={again} plain={plain} above={above}"
    ));
    c.status("listener");
    c.send_fd(child_sock, fd);
    c.close(fd);
    e.close(child_sock);
    let fd = e.receive_fd(sock);
    let (turns, turns_rx) = std::sync::mpsc::sync_channel::<Turn>(1);
    let (done_tx, done) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || notify_child(c, turns_rx, done_tx, parent, lowest));
    // The parent's side of turn `k`: the call it receives.
    let turn = |e: &mut Env, k: u64, show: fn(&mut Env, i64, i64, i64) -> String| {
        turns.send((k, show)).unwrap();
        let ready = e.ready(fd);
        let (r, n) = e.receive(fd);
        let after = e.revents(fd);
        e.say(format!(
            "seccomp turn {k} ready={} recv={r} nr={} arch={:#x} arg={} pid={} flags={} ip={} \
             revents={}",
            hex(ready.into()),
            n.nr,
            n.arch,
            n.arg0,
            (u64::from(n.pid) == pid) as i32,
            n.flags,
            (n.ip != 0) as i32,
            hex(after.into())
        ));
        n
    };
    // 1: a value. Wrong requests meanwhile.
    let n = turn(&mut e, 1, |_, r, _, _| format!("seccomp notify value={r}"));
    let id = n.id;
    let valid = e.id_ioctl(fd, ID_VALID, id);
    let other = e.id_ioctl(fd, ID_VALID, id + 1000);
    let send_other = e.answer(fd, id + 1000, 0, 0, 0);
    let send_flags = e.answer(fd, id, 0, 0, 2);
    let continue_value = e.answer(fd, id, 1, 0, 1);
    e.say(format!(
        "seccomp ioctl id-valid={valid} other={other} send-other={send_other} \
         send-flags={send_flags} continue-value={continue_value}"
    ));
    e.put(BUF, &[0; 80]);
    e.put(BUF, &[1]);
    let dirty = e.ioctl(fd, RECV, BUF);
    let recv_fault = e.ioctl(fd, RECV, 0);
    let send_fault = e.ioctl(fd, SEND, 0);
    let flags = e.ioctl(fd, SET_FLAGS, 1);
    let bad_flags = e.ioctl(fd, SET_FLAGS, 2);
    let unknown = e.id_ioctl(fd, 0x4008_2109, id);
    e.say(format!(
        "seccomp ioctl recv-dirty={dirty} recv-fault={recv_fault} send-fault={send_fault} \
         flags={flags} bad-flags={bad_flags} unknown={unknown}"
    ));
    let adds = [
        e.add(fd, 0x4010_2103, id, 0, sock, 0, 0, 0),
        e.add(fd, ADDFD, id, 4, sock, 0, 0, 0),
        e.add(fd, ADDFD, id, 0, sock, 9, 0, 0),
        e.add(fd, ADDFD, id, 0, sock, 0, O_NONBLOCK, 0),
        e.add(fd, ADDFD, id, 0, -1, 0, 0, 0),
        e.add(fd, ADDFD, id + 1000, 0, sock, 0, 0, 0),
        e.add(fd, 0xc020_2103, id + 1000, 0, sock, 0, 0, 0),
        e.add(fd, 0x4020_2103, id, 0, sock, 0, 0, 1),
    ];
    e.say(format!(
        "seccomp addfd small={} flags={} newfd={} newfd-flags={} src={} other={} big={} \
         big-dirty={}",
        adds[0], adds[1], adds[2], adds[3], adds[4], adds[5], adds[6], adds[7]
    ));
    let answered = e.answer(fd, id, 42, 0, 0);
    let valid_after = e.id_ioctl(fd, ID_VALID, id);
    e.say(format!(
        "seccomp answer={answered} valid-after={valid_after}"
    ));
    done.recv().unwrap();
    // 2: an error. A call not received yet takes no answer.
    turns
        .send((2, |_, r, _, _| {
            let (r, errno) = if r < 0 { (-1, -r) } else { (r, 0) };
            format!("seccomp notify error={r} errno={errno}")
        }))
        .unwrap();
    e.ready(fd);
    let next = id + 1;
    let send = e.answer(fd, next, 0, 0, 0);
    let addfd = e.add(fd, ADDFD, next, 0, sock, 0, 0, 0);
    let valid = e.id_ioctl(fd, ID_VALID, next);
    e.say(format!(
        "seccomp unreceived send={send} addfd={addfd} id-valid={valid}"
    ));
    let (r, n) = e.receive(fd);
    let answer = e.answer(fd, n.id, 99, -1, 0);
    e.say(format!(
        "seccomp turn 2 recv={r} arg={} next={} answer={answer}",
        n.arg0,
        (n.id == next) as i32
    ));
    let id = n.id;
    done.recv().unwrap();
    // 3: the call itself.
    let n = turn(&mut e, 3, |_, r, parent, _| {
        format!("seccomp notify continue={}", (r == parent) as i32)
    });
    let answer = e.answer(fd, n.id, 0, 0, 1);
    e.say(format!(
        "seccomp turn 3 next={} answer={answer}",
        (n.id == id + 1) as i32
    ));
    done.recv().unwrap();
    // 4: a descriptor that answers the call.
    let (p0, p1) = e.pair(PIPE, [ARG, 0, 0, 0, 0, 0]);
    e.put(BUF, b"four");
    e.call(WRITE, [p1 as u64, BUF, 4, 0, 0, 0]);
    let n = turn(&mut e, 4, |c, r, _, lowest| {
        let n = c.call(READ, [r as u64, BUF, 7, 0, 0, 0]);
        let got = String::from_utf8(c.get(BUF, n.max(0) as usize)).unwrap();
        let cloexec = c.call(FCNTL, [r as u64, F_GETFD, 0, 0, 0, 0]);
        c.close(r);
        format!(
            "seccomp notify addfd-send fd={} cloexec={cloexec} read={got}",
            (r == lowest) as i32
        )
    });
    let added = e.add(fd, ADDFD, n.id, 2, p0, 0, 0, 0);
    let revents = e.revents(fd);
    e.say(format!(
        "seccomp turn 4 addfd={} revents={}",
        (added >= 3) as i32,
        hex(revents.into())
    ));
    done.recv().unwrap();
    // 5: a descriptor at 40, close-on-exec, then a value.
    e.put(BUF, b"five");
    e.call(WRITE, [p1 as u64, BUF, 4, 0, 0, 0]);
    let n = turn(&mut e, 5, |c, r, _, _| {
        let n = c.call(READ, [40, BUF, 7, 0, 0, 0]);
        let got = String::from_utf8(c.get(BUF, n.max(0) as usize)).unwrap();
        let cloexec = c.call(FCNTL, [40, F_GETFD, 0, 0, 0, 0]);
        c.close(40);
        format!("seccomp notify addfd-setfd ret={r} cloexec={cloexec} read={got}")
    });
    let added = e.add(fd, ADDFD, n.id, 1, p0, 40, O_CLOEXEC, 0);
    let answer = e.answer(fd, n.id, 40, 0, 0);
    e.say(format!("seccomp turn 5 addfd={added} answer={answer}"));
    e.close(p0);
    e.close(p1);
    done.recv().unwrap();
    // Turns 6 and 7, which a signal handler interrupts, stay with the
    // differential tests. 8: closing the listener answers ENOSYS, and the
    // filter has none.
    turns
        .send((8, |c, r, _, _| {
            let after = c.call(GETPPID, [9, 0, 0, 0, 0, 0]);
            format!(
                "seccomp notify closed=-1 errno={} after=-1 errno={}",
                -r, -after
            )
        }))
        .unwrap();
    e.ready(fd);
    e.close(fd);
    done.recv().unwrap();
    drop(turns);
    let c = worker.join().unwrap();
    let child_lines = c.exit(0);
    e.wait("notify", pid as i64);
    e.close(sock);
    // A listener with SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, once its
    // child is gone, hangs up and a receive finds nothing. The handled
    // signal it waits through stays with the differential tests.
    let (sock, child_sock) = e.pair(SOCKETPAIR, [1, 1, 0, ARG, 0, 0]);
    let mut c = e.fork();
    let pid: u64 = c.t.tid.into();
    c.close(sock);
    let listener = c.set(8 | 32, &notify);
    c.send_fd(child_sock, listener);
    c.close(listener);
    e.close(child_sock);
    let fd = e.receive_fd(sock);
    let (turns, turns_rx) = std::sync::mpsc::sync_channel::<Turn>(1);
    let (done_tx, done) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || notify_child(c, turns_rx, done_tx, 0, 0));
    let turns_for = turns.clone();
    let n = {
        turns_for
            .send((7, |_, r, _, _| format!("killable {r}")))
            .unwrap();
        let ready = e.ready(fd);
        let (r, n) = e.receive(fd);
        let after = e.revents(fd);
        e.say(format!(
            "seccomp turn 7 ready={} recv={r} nr={} arch={:#x} arg={} pid={} flags={} ip={} \
             revents={}",
            hex(ready.into()),
            n.nr,
            n.arch,
            n.arg0,
            (u64::from(n.pid) == pid) as i32,
            n.flags,
            (n.ip != 0) as i32,
            hex(after.into())
        ));
        n
    };
    assert_eq!(e.answer(fd, n.id, 7, 0, 0), 0);
    done.recv().unwrap();
    drop(turns);
    drop(turns_for);
    let c = worker.join().unwrap();
    assert_eq!(c.exit(0), ["killable 7"]);
    e.wait("killable", pid as i64);
    let gone = e.revents(fd);
    let (r, _) = e.receive(fd);
    e.say(format!(
        "seccomp killable gone revents={} recv={r}",
        hex(gone.into())
    ));
    e.close(fd);
    e.close(sock);
    check(
        &child_lines,
        &[
            "seccomp no-listener prctl=0 status=0 filters=0",
            "seccomp listener emfile=-24",
            "seccomp listener fd=1 cloexec=1 fl=0x2 mode=600 link=anon_inode:seccomp notify read=-22 write=-22 seek=-29 revents=0",
            "seccomp listener again=-16 plain=0 above=-16",
            "seccomp listener prctl=2 status=2 filters=2",
            "seccomp notify value=42",
            "seccomp notify error=-1 errno=1",
            "seccomp notify continue=1",
            "seccomp notify addfd-send fd=1 cloexec=0 read=four",
            "seccomp notify addfd-setfd ret=40 cloexec=1 read=five",
            "seccomp notify closed=-1 errno=38 after=-1 errno=38",
        ],
    );
    check(
        &e.lines,
        &[
            "seccomp turn 1 ready=0x1 recv=0 nr=110 arch=0xc000003e arg=1 pid=1 flags=0 ip=1 revents=0x4",
            "seccomp ioctl id-valid=0 other=-2 send-other=-2 send-flags=-22 continue-value=-22",
            "seccomp ioctl recv-dirty=-22 recv-fault=-14 send-fault=-14 flags=0 bad-flags=-22 unknown=-22",
            "seccomp addfd small=-22 flags=-22 newfd=-22 newfd-flags=-22 src=-9 other=-2 big=-2 big-dirty=-7",
            "seccomp answer=0 valid-after=-2",
            "seccomp unreceived send=-115 addfd=-115 id-valid=-2",
            "seccomp turn 2 recv=0 arg=2 next=1 answer=0",
            "seccomp turn 3 ready=0x1 recv=0 nr=110 arch=0xc000003e arg=3 pid=1 flags=0 ip=1 revents=0x4",
            "seccomp turn 3 next=1 answer=0",
            "seccomp turn 4 ready=0x1 recv=0 nr=110 arch=0xc000003e arg=4 pid=1 flags=0 ip=1 revents=0x4",
            "seccomp turn 4 addfd=1 revents=0",
            "seccomp turn 5 ready=0x1 recv=0 nr=110 arch=0xc000003e arg=5 pid=1 flags=0 ip=1 revents=0x4",
            "seccomp turn 5 addfd=40 answer=0",
            "seccomp notify exit=0",
            "seccomp turn 7 ready=0x1 recv=0 nr=110 arch=0xc000003e arg=7 pid=1 flags=0 ip=1 revents=0x4",
            "seccomp killable exit=0",
            "seccomp killable gone revents=0x10 recv=-2",
        ],
    );
}
