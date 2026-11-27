//! `BPF_PROG_LOAD` and socket filters through the system call interface:
//! the checks of the load's arguments, the verifier's decisions and the
//! line of its log that says why, a loaded program's file and fdinfo, the
//! log's own arguments, and filters attached to AF_UNIX datagram sockets
//! with `SO_ATTACH_BPF`, run on what they receive. The expected values are
//! the lines of the bpf-prog-load case of `tests/guests/processes/bpf.c`
//! and of the bpf-prog-verify and bpf-prog-attach cases of
//! `tests/guests/processes/bpf-prog.c`, which the differential tests
//! compare with Linux. The tests make the guests' calls in their order;
//! bpf-prog-attach's sends after a shutdown and to a socket connected
//! elsewhere stay with the differential tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
const SIZE: u64 = 0x40000;
/// A `union bpf_attr`, a path, what a call reads or writes, a message and
/// what is received.
const ATTR: u64 = DATA;
const PATH: u64 = DATA + 0x200;
const ARG: u64 = DATA + 0x300;
const OUT: u64 = DATA + 0x400;
const IN: u64 = DATA + 0x500;
const LINK: u64 = DATA + 0x600;
const TEXT: u64 = DATA + 0x800;
/// The licenses, and the instructions of a program.
const GPL: u64 = DATA + 0xc00;
const MIT: u64 = DATA + 0xc10;
const INSNS: u64 = DATA + 0x1000;
/// The guests' `log_text`, of 65536 bytes.
const LOG: u64 = DATA + 0x10000;
const LOG_SIZE: u32 = 0x10000;

const READ: u64 = 0;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const PIPE: u64 = 22;
const SENDTO: u64 = 44;
const RECVFROM: u64 = 45;
const SOCKETPAIR: u64 = 53;
const SETSOCKOPT: u64 = 54;
const GETSOCKOPT: u64 = 55;
const FORK: u64 = 57;
const WAIT4: u64 = 61;
const FCNTL: u64 = 72;
const READLINK: u64 = 89;
const SETRESUID: u64 = 117;
const BPF: u64 = 321;

const PROG_LOAD: u64 = 5;
const PROG_SOCKET_FILTER: u32 = 1;
const PROG_TOKEN_FD: u32 = 1 << 16;
const F_SLEEPABLE: u32 = 1 << 4;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const SOL_SOCKET: u64 = 1;
const SO_GET_FILTER: u64 = 26;
const SO_DETACH_FILTER: u64 = 27;
const SO_LOCK_FILTER: u64 = 44;
const SO_BPF_EXTENSIONS: u64 = 48;
const SO_ATTACH_BPF: u64 = 50;
const LOOKUP: i32 = 1;
const LOAD_BYTES: i32 = 26;
const LOAD_BYTES_RELATIVE: i32 = 68;

/// A `struct bpf_insn`.
type Insn = [u8; 8];

fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    let mut b = [0; 8];
    b[0] = code;
    b[1] = dst | src << 4;
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}
fn mov(dst: u8, imm: i32) -> Insn {
    i(0xb7, dst, 0, 0, imm)
}
fn mov_reg(dst: u8, src: u8) -> Insn {
    i(0xbf, dst, src, 0, 0)
}
fn exit() -> Insn {
    i(0x95, 0, 0, 0, 0)
}
fn stx_dw(dst: u8, src: u8, off: i16) -> Insn {
    i(0x7b, dst, src, off, 0)
}
fn stx_w(dst: u8, src: u8, off: i16) -> Insn {
    i(0x63, dst, src, off, 0)
}
fn ldx_dw(dst: u8, src: u8, off: i16) -> Insn {
    i(0x79, dst, src, off, 0)
}
fn ldx_w(dst: u8, src: u8, off: i16) -> Insn {
    i(0x61, dst, src, off, 0)
}
fn ldx_b(dst: u8, src: u8, off: i16) -> Insn {
    i(0x71, dst, src, off, 0)
}
fn st_b(dst: u8, off: i16, imm: i32) -> Insn {
    i(0x72, dst, 0, off, imm)
}
fn st_w(dst: u8, off: i16, imm: i32) -> Insn {
    i(0x62, dst, 0, off, imm)
}
fn add(dst: u8, imm: i32) -> Insn {
    i(0x07, dst, 0, 0, imm)
}
fn call(id: i32) -> Insn {
    i(0x85, 0, 0, 0, id)
}
fn jeq(dst: u8, imm: i32, off: i16) -> Insn {
    i(0x15, dst, 0, off, imm)
}
/// The guest's `LD64`: `dst = v`, in two instructions.
fn ld64(dst: u8, v: i64) -> [Insn; 2] {
    [
        i(0x18, dst, 0, 0, v as i32),
        i(0, 0, 0, 0, ((v as u64) >> 32) as i32),
    ]
}
/// The guest's `KEY4`: a key of 0 at fp-4, the map of `fd` in R1 and R2
/// pointing at the key.
fn key4(fd: i64) -> [Insn; 5] {
    [
        st_w(10, -4, 0),
        i(0x18, 1, 1, 0, fd as i32),
        i(0, 0, 0, 0, 0),
        mov_reg(2, 10),
        add(2, -4),
    ]
}

/// The guests' `struct prog_attr`, 168 bytes.
#[derive(Clone)]
struct ProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
    prog_token_fd: i32,
}

impl ProgAttr {
    /// bpf.c's `prog`: a socket filter of 2 instructions, GPL, no log.
    fn new(count: u32) -> Self {
        Self {
            prog_type: PROG_SOCKET_FILTER,
            insn_cnt: count,
            insns: INSNS,
            license: GPL,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            prog_flags: 0,
            prog_name: [0; 16],
            prog_ifindex: 0,
            expected_attach_type: 0,
            attach_btf_id: 0,
            attach_prog_fd: 0,
            prog_token_fd: 0,
        }
    }

    /// bpf-prog.c's `attr`: the same with the log of level 1 in
    /// `log_text`.
    fn logged(count: u32) -> Self {
        Self {
            log_level: 1,
            log_buf: LOG,
            log_size: LOG_SIZE,
            ..Self::new(count)
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0; 168];
        let mut put32 = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put32(0, self.prog_type);
        put32(4, self.insn_cnt);
        put32(24, self.log_level);
        put32(28, self.log_size);
        put32(44, self.prog_flags);
        put32(64, self.prog_ifindex);
        put32(68, self.expected_attach_type);
        put32(108, self.attach_btf_id);
        put32(112, self.attach_prog_fd);
        put32(144, self.prog_token_fd as u32);
        b[8..16].copy_from_slice(&self.insns.to_le_bytes());
        b[16..24].copy_from_slice(&self.license.to_le_bytes());
        b[32..40].copy_from_slice(&self.log_buf.to_le_bytes());
        b[48..64].copy_from_slice(&self.prog_name);
        b
    }
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
        let m = Arc::new(AddressSpace::new());
        m.map_shared(
            Some(GuestAddr(DATA)),
            SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write(GuestAddr(GPL), b"GPL\0").unwrap();
        m.write(GuestAddr(MIT), b"MIT\0").unwrap();
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

    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(self.get(at, 4).try_into().unwrap())
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

    /// `BPF_PROG_LOAD` of `p` with `insns` at `INSNS`.
    fn load_with(&mut self, insns: &[Insn], p: &ProgAttr) -> i64 {
        self.put(INSNS, &insns.concat());
        self.put(ATTR, &p.bytes());
        self.call(BPF, [PROG_LOAD, ATTR, 168, 0, 0, 0])
    }

    /// bpf.c's `load`: r0 = 0; exit, as `p` gives it.
    fn load(&mut self, name: &str, p: &ProgAttr) {
        let r = self.load_with(&[mov(0, 0), exit()], p);
        self.say(format!("{name} {r}"));
    }

    /// bpf-prog.c's `map`.
    fn map(&mut self, kind: u32, key: u32, value: u32, entries: u32, flags: u32) -> i64 {
        let mut a = [0u8; 128];
        for (n, v) in [kind, key, value, entries, flags].into_iter().enumerate() {
            a[n * 4..n * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.put(ATTR, &a);
        self.call(BPF, [0, ATTR, 128, 0, 0, 0])
    }

    /// bpf-prog.c's `reason`: the log's line before "processed ".
    fn reason(&mut self) {
        let log = self.get(LOG, LOG_SIZE as usize);
        let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
        let text = &log[..end];
        let found = text
            .windows(10)
            .position(|w| w == b"processed ")
            .filter(|&at| at == 0 || text[at - 1] == b'\n');
        let Some(at) = found else {
            self.say("  log -".to_string());
            return;
        };
        let end = at.saturating_sub(1);
        let start = text[..end]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |n| n + 1);
        let line = String::from_utf8_lossy(&text[start..end]).into_owned();
        self.say(format!("  log {line}"));
    }

    /// bpf-prog.c's `fdinfo`.
    fn fdinfo(&mut self, fd: i64) {
        let f = self.open(&format!("/proc/self/fdinfo/{fd}"), 0);
        let n = if f < 0 {
            -1
        } else {
            self.call(READ, [f as u64, TEXT, 1023, 0, 0, 0])
        };
        if f >= 0 {
            self.close(f);
        }
        if n < 0 {
            self.say("  fdinfo unreadable".to_string());
            return;
        }
        let text = String::from_utf8(self.get(TEXT, n as usize)).unwrap();
        for line in text.split('\n').filter(|l| !l.is_empty()) {
            if line.starts_with("prog_type:")
                || line.starts_with("prog_tag:")
                || line.starts_with("memlock:")
            {
                self.say(format!("  {line}"));
            }
        }
        let mut path = format!("/proc/self/fd/{fd}").into_bytes();
        path.push(0);
        self.put(PATH, &path);
        let n = self.call(READLINK, [PATH, LINK, 63, 0, 0, 0]);
        let link = if n < 0 {
            "?".to_string()
        } else {
            String::from_utf8(self.get(LINK, n as usize)).unwrap()
        };
        let fl = self.call(FCNTL, [fd as u64, 3, 0, 0, 0, 0]) & 3;
        let fd_flags = self.call(FCNTL, [fd as u64, 1, 0, 0, 0, 0]);
        self.say(format!("  link {link} flags {fl:#x} fd flags {fd_flags}"));
    }

    /// bpf-prog.c's `run`.
    fn run(&mut self, name: &str, insns: &[Insn], p: &ProgAttr) {
        self.put(LOG, &vec![0; LOG_SIZE as usize]);
        let fd = self.load_with(insns, p);
        if fd < 0 {
            self.say(format!("{name}: {fd}"));
            self.reason();
            return;
        }
        self.say(format!("{name}: loaded"));
        self.fdinfo(fd);
        self.close(fd);
    }

    /// bpf-prog.c's `LOAD`.
    fn verify(&mut self, name: &str, insns: &[Insn]) {
        self.run(name, insns, &ProgAttr::logged(insns.len() as u32));
    }

    /// bpf-prog.c's `load` and `PROGRAM`: a descriptor, or the error.
    fn program(&mut self, insns: &[Insn]) -> i64 {
        self.load_with(insns, &ProgAttr::logged(insns.len() as u32))
    }

    fn pair(&mut self) -> (i64, i64) {
        // AF_UNIX, SOCK_DGRAM.
        assert_eq!(self.call(SOCKETPAIR, [1, 2, 0, ARG, 0, 0]), 0);
        (i64::from(self.word(ARG)), i64::from(self.word(ARG + 4)))
    }

    /// `setsockopt` at `SOL_SOCKET` of `value`, its `len` bytes.
    fn set(&mut self, sock: i64, name: u64, value: &[u8]) -> i64 {
        self.put(ARG, value);
        self.call(
            SETSOCKOPT,
            [sock as u64, SOL_SOCKET, name, ARG, value.len() as u64, 0],
        )
    }

    /// bpf-prog.c's `attach`.
    fn attach(&mut self, sock: i64, prog: i64) -> i64 {
        self.set(sock, SO_ATTACH_BPF, &(prog as i32).to_le_bytes())
    }

    /// bpf-prog.c's `option`.
    fn option(&mut self, sock: i64, name: u64, value: i32) -> i64 {
        self.set(sock, name, &value.to_le_bytes())
    }

    /// bpf-prog.c's `get`.
    fn get_option(&mut self, name: &str, sock: i64, option: u64) {
        self.put(ARG, &(-1i32).to_le_bytes());
        self.put(ARG + 8, &4u32.to_le_bytes());
        let r = self.call(
            GETSOCKOPT,
            [sock as u64, SOL_SOCKET, option, ARG, ARG + 8, 0],
        );
        if r < 0 {
            self.say(format!("{name} {r}"));
        } else {
            let value = self.word(ARG) as i32;
            let len = self.word(ARG + 8);
            self.say(format!("{name} value {value} len {len}"));
        }
    }

    fn send(&mut self, sock: i64, at: u64, len: u64, flags: u64) -> i64 {
        self.call(SENDTO, [sock as u64, at, len, flags, 0, 0])
    }

    fn recv(&mut self, sock: i64) -> i64 {
        self.call(RECVFROM, [sock as u64, IN, 64, MSG_DONTWAIT, 0, 0])
    }

    /// bpf-prog.c's `through`.
    fn through(&mut self, name: &str, a: i64, b: i64, len: u64) {
        let out: Vec<u8> = (0..64).collect();
        self.put(OUT, &out);
        let sent = self.send(a, OUT, len, MSG_DONTWAIT | MSG_NOSIGNAL);
        let got = self.recv(b);
        let mut line = format!("{name} sent {sent}");
        if got < 0 {
            line += &format!(" received {got}");
        } else {
            line += &format!(" received {got}:");
            for byte in self.get(IN, got as usize) {
                line += &format!(" {byte}");
            }
        }
        self.say(line);
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

/// bpf-prog-load: each argument wrong in one way, and a process without
/// `CAP_BPF`.
#[test]
fn bpf_prog_load_checks_its_arguments() {
    let mut e = Env::new();
    let null = e.open("/dev/null", 0);
    let mut p = ProgAttr::new(2);
    p.prog_flags = 1 << 8;
    e.load("unknown flag", &p);
    let mut p = ProgAttr::new(2);
    p.prog_flags = PROG_TOKEN_FD;
    p.prog_token_fd = 1000;
    e.load("token flag without a descriptor", &p);
    p.prog_token_fd = null as i32;
    e.load("token flag with another file", &p);
    let mut p = ProgAttr::new(0);
    e.load("no instructions", &p);
    p.insn_cnt = 1_000_001;
    e.load("more than the complexity limit", &p);
    let mut p = ProgAttr::new(2);
    p.attach_prog_fd = null as u32;
    e.load("attach to another file", &p);
    let mut p = ProgAttr::new(2);
    p.attach_btf_id = 1;
    e.load("attach BTF ID", &p);
    let mut p = ProgAttr::new(2);
    p.insns = 8;
    e.load("instructions at no memory", &p);
    let mut p = ProgAttr::new(2);
    p.license = 8;
    e.load("license at no memory", &p);
    let mut p = ProgAttr::new(2);
    p.prog_type = 1000;
    e.load("unknown type", &p);
    let mut p = ProgAttr::new(2);
    p.prog_name[..9].copy_from_slice(b"bad-name\0");
    e.load("name with a dash", &p);
    let mut p = ProgAttr::new(2);
    p.log_buf = LOG;
    p.log_level = 1;
    e.load("log buffer without a size", &p);
    e.close(null);

    // Without CAP_BPF, kernel.unprivileged_bpf_disabled (2) keeps every
    // load out, before its size is looked at.
    let pid = e.call(FORK, [0; 6]);
    let (mut k, t) = e.k.take_child().unwrap();
    let m = k.take_spawn_memory().unwrap();
    let mut child = Env {
        k,
        t,
        m,
        lines: Vec::new(),
    };
    assert_eq!(child.call(SETRESUID, [65534, 65534, 65534, 0, 0, 0]), 0);
    child.load("unprivileged socket filter", &ProgAttr::new(2));
    child.load("unprivileged no instructions", &ProgAttr::new(0));
    e.lines.append(&mut child.lines);
    child.k.finish_thread(&child.t, &child.m);
    child.k.complete_process(ExitStatus::Exited(0));
    assert_eq!(e.call(WAIT4, [pid as u64, ARG, 0, 0, 0, 0]), pid);
    let status = e.word(ARG);
    e.say(format!("child status {status}"));
    check(
        &e.lines,
        &[
            "unknown flag -22",
            "token flag without a descriptor -9",
            "token flag with another file -22",
            "no instructions -7",
            "more than the complexity limit -7",
            "attach to another file -22",
            "attach BTF ID -22",
            "instructions at no memory -14",
            "license at no memory -14",
            "unknown type -22",
            "name with a dash -22",
            "log buffer without a size -22",
            "unprivileged socket filter -1",
            "unprivileged no instructions -1",
            "child status 0",
        ],
    );
}

/// bpf-prog-verify: programs of registers, jumps and the stack that the
/// verifier takes or refuses, and the log's arguments.
#[test]
fn bpf_prog_verify_takes_and_refuses_programs() {
    let mut e = Env::new();
    let [first, second] = ld64(0, 1 << 32 | 2);
    // Programs it takes.
    e.verify("return 0", &[mov(0, 0), exit()]);
    e.verify("return the frame pointer", &[mov_reg(0, 10), exit()]);
    e.verify("64-bit constant", &[first, second, exit()]);
    e.verify(
        "pointer spilled and filled",
        &[stx_dw(10, 10, -8), ldx_dw(0, 10, -8), exit()],
    );
    e.verify("stack never written", &[ldx_dw(0, 10, -512), exit()]);
    e.verify(
        "byte at an odd offset",
        &[st_b(10, -3, 1), ldx_b(0, 10, -3), exit()],
    );
    e.verify(
        "moved stack pointer",
        &[
            mov_reg(1, 10),
            add(1, -16),
            mov(2, 7),
            stx_dw(1, 2, 8),
            ldx_dw(0, 10, -8),
            exit(),
        ],
    );
    e.verify(
        "known scalar plus frame pointer",
        &[
            mov(1, -8),
            i(0x0f, 1, 10, 0, 0),
            mov(0, 0),
            stx_dw(1, 0, 0),
            exit(),
        ],
    );
    e.verify(
        "pointer less pointer",
        &[mov_reg(0, 10), i(0x1f, 0, 1, 0, 0), exit()],
    );
    // The jump is known not to be taken, so the read through R0 is never
    // reached.
    e.verify(
        "known branch",
        &[mov(0, 0), i(0x15, 0, 0, 1, 0), ldx_dw(1, 0, 0), exit()],
    );
    e.verify(
        "unknown branch",
        &[ldx_dw(0, 10, -8), i(0x25, 0, 0, 1, 5), mov(0, 1), exit()],
    );
    e.verify(
        "arithmetic",
        &[
            mov(1, 3),
            i(0x27, 1, 0, 0, 4),
            i(0x17, 1, 0, 0, 2),
            i(0x67, 1, 0, 0, 1),
            i(0xb4, 2, 0, 0, -1),
            i(0x74, 2, 0, 0, 28),
            i(0x3f, 1, 2, 0, 0),
            i(0x9f, 1, 2, 0, 0),
            i(0x87, 1, 0, 0, 0),
            i(0xdc, 1, 0, 0, 16),
            i(0xbc, 0, 1, 0, 0),
            exit(),
        ],
    );

    // Programs it refuses.
    e.verify("no return value", &[exit()]);
    e.verify("unknown opcode", &[i(0x8c, 0, 0, 0, 0), exit()]);
    e.verify("jump out of range", &[mov(0, 0), i(0x05, 0, 0, 5, 0)]);
    e.verify("no exit at the end", &[mov(0, 0)]);
    e.verify("unreachable", &[mov(0, 0), exit(), exit()]);
    e.verify(
        "bad second half",
        &[i(0x18, 0, 0, 0, 0), i(0, 1, 0, 0, 0), exit()],
    );
    e.verify("exit with a source", &[mov(0, 0), i(0x95, 0, 1, 0, 0)]);
    e.verify(
        "division by zero",
        &[mov(0, 0), i(0x37, 0, 0, 0, 0), exit()],
    );
    e.verify("shift by 64", &[mov(0, 0), i(0x67, 0, 0, 0, 64), exit()]);
    e.verify(
        "32-bit shift by 32",
        &[mov(0, 0), i(0x64, 0, 0, 0, 32), exit()],
    );
    e.verify("write the frame pointer", &[mov(10, 0), mov(0, 0), exit()]);
    e.verify("read an unwritten register", &[mov_reg(0, 3), exit()]);
    e.verify("below the stack", &[mov(0, 0), stx_dw(10, 0, -520), exit()]);
    e.verify("at the frame pointer", &[ldx_dw(0, 10, 0), exit()]);
    e.verify("misaligned", &[mov(0, 0), stx_dw(10, 0, -4), exit()]);
    e.verify(
        "misaligned through a moved pointer",
        &[mov_reg(1, 10), add(1, -6), ldx_w(0, 1, 0), exit()],
    );
    e.verify(
        "part of a spilled pointer",
        &[stx_dw(10, 10, -8), ldx_w(0, 10, -8), exit()],
    );
    e.verify(
        "pointer spilled in part",
        &[stx_w(10, 10, -8), mov(0, 0), exit()],
    );
    e.verify(
        "subtract from the stack pointer",
        &[mov_reg(1, 10), i(0x17, 1, 0, 0, 8), mov(0, 0), exit()],
    );
    e.verify(
        "multiply a pointer",
        &[mov_reg(1, 10), i(0x27, 1, 0, 0, 2), mov(0, 0), exit()],
    );
    e.verify(
        "and a pointer",
        &[mov_reg(1, 10), i(0x57, 1, 0, 0, 2), mov(0, 0), exit()],
    );
    e.verify(
        "32-bit pointer addition",
        &[mov_reg(1, 10), i(0x04, 1, 0, 0, 2), mov(0, 0), exit()],
    );
    e.verify(
        "pointer plus pointer",
        &[mov_reg(1, 10), i(0x0f, 1, 10, 0, 0), mov(0, 0), exit()],
    );
    e.verify(
        "scalar less pointer",
        &[mov(1, 8), i(0x1f, 1, 10, 0, 0), mov(0, 0), exit()],
    );
    e.verify(
        "pointer far out",
        &[mov_reg(1, 10), add(1, 1 << 29), mov(0, 0), exit()],
    );
    e.verify(
        "read through a scalar",
        &[mov(1, 0), ldx_dw(0, 1, 0), exit()],
    );
    e.verify(
        "unknown branch to a bad read",
        &[
            ldx_dw(0, 10, -8),
            i(0x15, 0, 0, 1, 0),
            ldx_dw(1, 0, 0),
            exit(),
        ],
    );

    let ret0 = [mov(0, 0), exit()];
    let mut p = ProgAttr::logged(2);
    p.prog_flags = F_SLEEPABLE;
    e.run("sleepable", &ret0, &p);
    let mut p = ProgAttr::logged(2);
    p.prog_name[..9].copy_from_slice(b"filter.1\0");
    p.license = MIT;
    p.expected_attach_type = 5;
    e.run("named, not GPL, an attach type", &ret0, &p);

    // The log's arguments.
    let mut p = ProgAttr::logged(1);
    p.log_size = 8;
    e.run("log too small for a refusal", &[exit()], &p);
    let mut p = ProgAttr::logged(2);
    p.log_size = 8;
    e.run("log too small for a load", &ret0, &p);
    let mut p = ProgAttr::logged(2);
    p.log_buf = 8;
    p.log_size = 64;
    e.run("log at no memory", &ret0, &p);
    let mut p = ProgAttr::logged(2);
    p.log_level = 16;
    e.run("log level 16", &ret0, &p);
    let mut p = ProgAttr::logged(2);
    p.log_level = 0;
    p.log_buf = 0;
    p.log_size = 0;
    e.run("no log", &ret0, &p);
    let mut p = ProgAttr::logged(2);
    p.prog_ifindex = 1;
    e.run("bound to a device", &ret0, &p);
    check(
        &e.lines,
        &[
            "return 0: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t59f4a931744dcdc6",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "return the frame pointer: loaded",
            "  prog_type:\t1",
            "  prog_tag:\tcd22247f2f07e227",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "64-bit constant: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t95d83d83f6d7ecff",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "pointer spilled and filled: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t137a457292c80233",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "stack never written: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t8b93d1e6d6af1176",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "byte at an odd offset: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t3914695aa6f2bc8f",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "moved stack pointer: loaded",
            "  prog_type:\t1",
            "  prog_tag:\tbfdb37b0074af6ca",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "known scalar plus frame pointer: loaded",
            "  prog_type:\t1",
            "  prog_tag:\tff4620337629143a",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "pointer less pointer: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t30d6a86fc2162cc0",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "known branch: loaded",
            "  prog_type:\t1",
            "  prog_tag:\te4ac7b399c188c2b",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "unknown branch: loaded",
            "  prog_type:\t1",
            "  prog_tag:\td57f029543dc1d78",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "arithmetic: loaded",
            "  prog_type:\t1",
            "  prog_tag:\tdfaea350a3b69e36",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "no return value: -13",
            "  log R0 !read_ok",
            "unknown opcode: -22",
            "  log unknown opcode 8c",
            "jump out of range: -22",
            "  log jump out of range from insn 1 to 7",
            "no exit at the end: -22",
            "  log last insn is not an exit or jmp",
            "unreachable: -22",
            "  log unreachable insn 2",
            "bad second half: -22",
            "  log invalid bpf_ld_imm64 insn",
            "exit with a source: -22",
            "  log BPF_EXIT uses reserved fields",
            "division by zero: -22",
            "  log div by zero",
            "shift by 64: -22",
            "  log invalid shift 64",
            "32-bit shift by 32: -22",
            "  log invalid shift 32",
            "write the frame pointer: -13",
            "  log frame pointer is read only",
            "read an unwritten register: -13",
            "  log R3 !read_ok",
            "below the stack: -13",
            "  log invalid write to stack R10 off=-520 size=8",
            "at the frame pointer: -13",
            "  log invalid read from stack R10 off=0 size=8",
            "misaligned: -13",
            "  log misaligned stack access off 0+0+-4 size 8",
            "misaligned through a moved pointer: -13",
            "  log misaligned stack access off 0+-6+0 size 4",
            "part of a spilled pointer: -13",
            "  log invalid size of register fill",
            "pointer spilled in part: -13",
            "  log invalid size of register spill",
            "subtract from the stack pointer: -13",
            "  log R1 subtraction from stack pointer prohibited",
            "multiply a pointer: -13",
            "  log R1 pointer arithmetic with *= operator prohibited",
            "and a pointer: -13",
            "  log R1 bitwise operator &= on pointer prohibited",
            "32-bit pointer addition: -13",
            "  log R1 32-bit pointer arithmetic prohibited",
            "pointer plus pointer: -13",
            "  log R1 pointer += pointer prohibited",
            "scalar less pointer: -13",
            "  log R1 tried to subtract pointer from scalar",
            "pointer far out: -22",
            "  log math between fp pointer and 536870912 is not allowed",
            "read through a scalar: -13",
            "  log R1 invalid mem access 'scalar'",
            "unknown branch to a bad read: -13",
            "  log R0 invalid mem access 'scalar'",
            "sleepable: -22",
            "  log Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and struct_ops programs can be sleepable",
            "named, not GPL, an attach type: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t59f4a931744dcdc6",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "log too small for a refusal: -28",
            "  log -",
            "log too small for a load: -28",
            "  log -",
            "log at no memory: -14",
            "  log -",
            "log level 16: -22",
            "  log -",
            "no log: loaded",
            "  prog_type:\t1",
            "  prog_tag:\t59f4a931744dcdc6",
            "  memlock:\t4096",
            "  link anon_inode:bpf-prog flags 0x2 fd flags 1",
            "bound to a device: -22",
            "  log -",
        ],
    );
}

/// bpf-prog-attach, to its division and remainder: `SO_ATTACH_BPF` and the
/// other filter options' errors, filters that drop, keep part of or read a
/// datagram, a locked filter, a map that counts, and the results of
/// division and remainder by 0 and -1.
#[test]
fn bpf_prog_attach_filters_datagrams() {
    let mut e = Env::new();
    let (a, b) = e.pair();
    let drop = e.program(&[mov(0, 0), exit()]);
    let keep3 = e.program(&[mov(0, 3), exit()]);
    let all = e.program(&[mov(0, -1), exit()]);
    let loaded = drop >= 0 && keep3 >= 0 && all >= 0;
    e.say(format!("loaded {}", loaded as i32));
    let m = e.map(2, 4, 8, 1, 0);
    assert_eq!(e.call(PIPE, [ARG, 0, 0, 0, 0, 0]), 0);
    let pipe = i64::from(e.word(ARG));

    let r = e.set(b, SO_ATTACH_BPF, &(drop as u64).to_le_bytes());
    e.say(format!("attach len 8 {r}"));
    let r = e.set(b, SO_ATTACH_BPF, &(drop as i32).to_le_bytes()[..2]);
    e.say(format!("attach len 2 {r}"));
    let r = e.attach(b, 1000);
    e.say(format!("attach no fd {r}"));
    let r = e.attach(b, -1);
    e.say(format!("attach -1 {r}"));
    let r = e.attach(b, m);
    e.say(format!("attach map {r}"));
    let r = e.attach(b, pipe);
    e.say(format!("attach pipe {r}"));
    let r = e.option(b, SO_DETACH_FILTER, 0);
    e.say(format!("detach none {r}"));
    e.get_option("get filter none", b, SO_GET_FILTER);
    e.get_option("lock filter", b, SO_LOCK_FILTER);
    e.get_option("bpf extensions", b, SO_BPF_EXTENSIONS);

    e.through("no filter", a, b, 5);
    let r = e.attach(b, drop);
    e.say(format!("attach drop {r}"));
    e.get_option("get filter bpf", b, SO_GET_FILTER);
    e.through("drop", a, b, 5);
    e.through("drop empty", a, b, 0);
    e.through("other way", b, a, 5);
    let r = e.attach(b, keep3);
    e.say(format!("attach keep 3 {r}"));
    e.through("keep 3", a, b, 5);
    e.through("keep 3 of 2", a, b, 2);
    let r = e.attach(b, all);
    e.say(format!("attach all {r}"));
    e.through("keep all", a, b, 5);
    // The descriptor may go: the socket keeps the program.
    e.close(all);
    e.through("closed program", a, b, 4);

    let r = e.option(b, SO_LOCK_FILTER, 1);
    e.say(format!("lock {r}"));
    e.get_option("lock filter locked", b, SO_LOCK_FILTER);
    let r = e.attach(b, drop);
    e.say(format!("attach locked {r}"));
    let r = e.option(b, SO_DETACH_FILTER, 0);
    e.say(format!("detach locked {r}"));
    let r = e.option(b, SO_LOCK_FILTER, 0);
    e.say(format!("unlock locked {r}"));
    let r = e.option(b, SO_LOCK_FILTER, 1);
    e.say(format!("lock again {r}"));
    e.through("still all", a, b, 4);

    let (c, d) = e.pair();
    e.attach(d, keep3);
    let r = e.option(d, SO_DETACH_FILTER, 0);
    e.say(format!("detach {r}"));
    let r = e.option(d, SO_DETACH_FILTER, 0);
    e.say(format!("detach twice {r}"));
    e.through("detached", c, d, 5);

    // R0 = the first byte of the message: its length kept.
    let first = e.program(&[
        mov_reg(6, 1),
        mov(2, 0),
        mov_reg(3, 10),
        add(3, -8),
        mov(4, 1),
        call(LOAD_BYTES),
        jeq(0, 0, 2),
        mov(0, 1),
        exit(),
        ldx_b(0, 10, -8),
        exit(),
    ]);
    let r = e.attach(d, first);
    e.say(format!("attach first byte {r}"));
    e.put(OUT, &[4, 9, 8, 7, 6, 5]);
    let sent = e.send(c, OUT, 6, 0);
    let got = e.recv(d);
    e.say(format!("first byte sent {sent} received {got}"));
    // Past the end: EFAULT, and 1 byte kept.
    let past = e.program(&[
        mov_reg(6, 1),
        mov(2, 4),
        mov_reg(3, 10),
        add(3, -8),
        mov(4, 4),
        call(LOAD_BYTES),
        jeq(0, 0, 2),
        mov(0, 1),
        exit(),
        mov(0, 2),
        exit(),
    ]);
    let r = e.attach(d, past);
    e.say(format!("attach past {r}"));
    e.through("past the end", c, d, 6);
    e.through("not past the end", c, d, 8);
    // The relative form: from the network header, the message's start; the
    // MAC header is not set, EFAULT. R0 = the byte at 2, or 1.
    let relative = |e: &mut Env, base: i32| {
        e.program(&[
            mov(2, 2),
            mov_reg(3, 10),
            add(3, -8),
            mov(4, 1),
            mov(5, base),
            call(LOAD_BYTES_RELATIVE),
            jeq(0, 0, 2),
            mov(0, 1),
            exit(),
            ldx_b(0, 10, -8),
            exit(),
        ])
    };
    let net = relative(&mut e, 1);
    let mac = relative(&mut e, 0);
    let r = e.attach(d, net);
    e.say(format!("attach net {r}"));
    e.through("network header", c, d, 6);
    let r = e.attach(d, mac);
    e.say(format!("attach mac {r}"));
    e.through("mac header", c, d, 6);
    // The context: len, and cb[0] written then read.
    let len = e.program(&[ldx_w(0, 1, 0), add(0, -1), exit()]);
    let r = e.attach(d, len);
    e.say(format!("attach len {r}"));
    e.through("len less 1", c, d, 6);
    let cb = e.program(&[st_w(1, 48, 2), ldx_w(0, 1, 48), exit()]);
    let r = e.attach(d, cb);
    e.say(format!("attach cb {r}"));
    e.through("cb", c, d, 6);

    // A map counts the messages: value[0] += 1 each time; keep all.
    let counter = e.map(2, 4, 8, 1, 0);
    let mut count = key4(counter).to_vec();
    count.extend([
        call(LOOKUP),
        jeq(0, 0, 3),
        ldx_dw(1, 0, 0),
        add(1, 1),
        stx_dw(0, 1, 0),
        mov(0, -1),
        exit(),
    ]);
    let count = e.program(&count);
    let r = e.attach(d, count);
    e.say(format!("attach count {r}"));
    for _ in 0..3 {
        e.through("counted", c, d, 1);
    }
    // BPF_MAP_LOOKUP_ELEM of key 0.
    e.put(TEXT, &0u32.to_le_bytes());
    e.put(TEXT + 8, &0u64.to_le_bytes());
    let mut a = (counter as u32).to_le_bytes().to_vec();
    a.extend([0; 4]);
    a.extend(TEXT.to_le_bytes());
    a.extend((TEXT + 8).to_le_bytes());
    a.extend(0u64.to_le_bytes());
    e.put(ATTR, &a);
    let r = e.call(BPF, [1, ATTR, 32, 0, 0, 0]);
    let value = e.m.read_u64(GuestAddr(TEXT + 8)).unwrap();
    e.say(format!("count lookup {r} value {value}"));

    // Division and remainder, as the bytes kept (of 64) show.
    let ops: [(&str, u8, i16, i64, i64); 14] = [
        ("div 0", 0x3f, 0, 7, 0),
        ("mod 0", 0x9f, 0, 7, 0),
        ("div32 0", 0x3c, 0, 7, 0),
        ("mod32 0", 0x9c, 0, 0x1_0000_0007, 0),
        ("sdiv -1", 0x3f, 1, -7, -1),
        ("smod -1", 0x9f, 1, 7, -1),
        ("sdiv 0", 0x3f, 1, 7, 0),
        ("smod 0", 0x9f, 1, 7, 0),
        ("sdiv32 -7 2", 0x3c, 1, -7, 2),
        ("smod32 -7 -2", 0x9c, 1, 7, -2),
        ("sdiv32 -1", 0x3c, 1, -9, -1),
        ("smod32 0", 0x9c, 1, 0x1_0000_0009, 0),
        ("div large", 0x3f, 0, -1, 0x100_0000_0000),
        ("lsh 65", 0x6f, 0, 1, 65),
    ];
    for (name, op, off, x, y) in ops {
        let (s, r) = e.pair();
        let mut insns = ld64(0, x).to_vec();
        insns.extend(ld64(2, y));
        insns.extend([i(op, 0, 2, off, 0), exit()]);
        let prog = e.program(&insns);
        if prog < 0 {
            e.say(format!("{name} load {prog}"));
            continue;
        }
        e.attach(r, prog);
        e.put(OUT, &[0; 64]);
        e.send(s, OUT, 64, 0);
        let got = e.recv(r);
        e.say(format!("{name} kept {got}"));
        e.close(prog);
        e.close(s);
        e.close(r);
    }
    check(
        &e.lines,
        &[
            "loaded 1",
            "attach len 8 -22",
            "attach len 2 -22",
            "attach no fd -9",
            "attach -1 -9",
            "attach map -22",
            "attach pipe -22",
            "detach none -2",
            "get filter none value -1 len 0",
            "lock filter value 0 len 4",
            "bpf extensions value 64 len 4",
            "no filter sent 5 received 5: 0 1 2 3 4",
            "attach drop 0",
            "get filter bpf -13",
            "drop sent 5 received -11",
            "drop empty sent 0 received -11",
            "other way sent 5 received 5: 0 1 2 3 4",
            "attach keep 3 0",
            "keep 3 sent 5 received 3: 0 1 2",
            "keep 3 of 2 sent 2 received 2: 0 1",
            "attach all 0",
            "keep all sent 5 received 5: 0 1 2 3 4",
            "closed program sent 4 received 4: 0 1 2 3",
            "lock 0",
            "lock filter locked value 1 len 4",
            "attach locked -1",
            "detach locked -1",
            "unlock locked -1",
            "lock again 0",
            "still all sent 4 received 4: 0 1 2 3",
            "detach 0",
            "detach twice -2",
            "detached sent 5 received 5: 0 1 2 3 4",
            "attach first byte 0",
            "first byte sent 6 received 4",
            "attach past 0",
            "past the end sent 6 received 1: 0",
            "not past the end sent 8 received 2: 0 1",
            "attach net 0",
            "network header sent 6 received 2: 0 1",
            "attach mac 0",
            "mac header sent 6 received 1: 0",
            "attach len 0",
            "len less 1 sent 6 received 5: 0 1 2 3 4",
            "attach cb 0",
            "cb sent 6 received 2: 0 1",
            "attach count 0",
            "counted sent 1 received 1: 0",
            "counted sent 1 received 1: 0",
            "counted sent 1 received 1: 0",
            "count lookup 0 value 3",
            "div 0 kept -11",
            "mod 0 kept 7",
            "div32 0 kept -11",
            "mod32 0 kept 7",
            "sdiv -1 kept 7",
            "smod -1 kept -11",
            "sdiv 0 kept -11",
            "smod 0 kept 7",
            "sdiv32 -7 2 kept 64",
            "smod32 -7 -2 kept 1",
            "sdiv32 -1 kept 9",
            "smod32 0 kept 9",
            "div large kept 64",
            "lsh 65 kept 2",
        ],
    );
}

/// Where `BPF_PROG_TEST_RUN`'s packet and context go in and out.
const PACKET_IN: u64 = DATA + 0x20000;
const PACKET_OUT: u64 = DATA + 0x30000;
const CTX_IN: u64 = DATA + 0x700;
const CTX_OUT: u64 = DATA + 0x900;
const PROG_TEST_RUN: u64 = 10;

/// `attr->test`, 80 bytes.
#[derive(Clone, Copy, Default)]
struct TestRun {
    prog_fd: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
}

impl TestRun {
    /// A run of `fd` on `size` bytes at `PACKET_IN`, out to `PACKET_OUT`.
    fn of(fd: i64, size: u32) -> Self {
        Self {
            prog_fd: fd as u32,
            data_size_in: size,
            data_in: PACKET_IN,
            data_out: PACKET_OUT,
            ..Self::default()
        }
    }

    /// With a context of 192 bytes at `CTX_IN` and `CTX_OUT`.
    fn with_context(self) -> Self {
        Self {
            ctx_size_in: 192,
            ctx_size_out: 192,
            ctx_in: CTX_IN,
            ctx_out: CTX_OUT,
            ..self
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0; 80];
        let mut put32 = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put32(0, self.prog_fd);
        put32(8, self.data_size_in);
        put32(12, self.data_size_out);
        put32(32, self.repeat);
        put32(40, self.ctx_size_in);
        put32(44, self.ctx_size_out);
        put32(64, self.flags);
        put32(68, self.cpu);
        b[16..24].copy_from_slice(&self.data_in.to_le_bytes());
        b[24..32].copy_from_slice(&self.data_out.to_le_bytes());
        b[48..56].copy_from_slice(&self.ctx_in.to_le_bytes());
        b[56..64].copy_from_slice(&self.ctx_out.to_le_bytes());
        b
    }
}

/// What a run gave: its result, `retval`, `data_size_out` and
/// `ctx_size_out`.
#[derive(Debug, PartialEq, Eq)]
struct Ran {
    result: i64,
    retval: u32,
    size_out: u32,
    ctx_size_out: u32,
}

impl Env {
    fn test_run(&mut self, run: &TestRun) -> Ran {
        self.put(ATTR, &run.bytes());
        let result = self.call(BPF, [PROG_TEST_RUN, ATTR, 80, 0, 0, 0]);
        Ran {
            result,
            retval: self.word(ATTR + 4),
            size_out: self.word(ATTR + 12),
            ctx_size_out: self.word(ATTR + 44),
        }
    }

    /// A packet of `size` bytes to `destination`, of Ethernet type `kind`,
    /// whose byte `n` past the Ethernet header is `n`.
    fn packet(&self, destination: [u8; 6], kind: u16, size: usize) {
        let mut b: Vec<u8> = destination.to_vec();
        b.extend([0x02, 0, 0, 0, 0, 1]);
        b.extend(kind.to_be_bytes());
        b.extend((0..size - 14).map(|n| n as u8));
        self.put(PACKET_IN, &b);
    }
}

/// `r0 = *(u32 *)(r1 + off); exit`: a program that gives a context field.
fn field(off: i16) -> [Insn; 2] {
    [ldx_w(0, 1, off), exit()]
}

/// `BPF_PROG_TEST_RUN` of a socket filter runs it on the packet after its
/// Ethernet header, as the loopback receives it, and gives back its
/// result, the packet with that header zeroed, and its size.
#[test]
fn a_test_run_runs_a_filter_on_a_packet_after_its_ethernet_header() {
    let mut e = Env::new();
    let len = e.program(&field(0));
    assert!(len >= 0, "{len}");
    e.packet([0; 6], 0x0800, 64);
    let ran = e.test_run(&TestRun::of(len, 64));
    assert_eq!(
        ran,
        Ran {
            result: 0,
            retval: 50,
            size_out: 64,
            ctx_size_out: 0
        }
    );
    let mut expected = vec![0; 14];
    expected.extend(0..50);
    assert_eq!(e.get(PACKET_OUT, 64), expected);
    // The loopback's address is all zeros, and so is its broadcast
    // address: every group's address is a multicast one.
    let pkt_type = e.program(&field(4));
    for (destination, kind) in [
        ([0; 6], 0),
        ([0xff; 6], 2),
        ([0x01, 0, 0x5e, 0, 0, 1], 2),
        ([0x02, 0, 0, 0, 0, 2], 3),
    ] {
        e.packet(destination, 0x0800, 34);
        assert_eq!(e.test_run(&TestRun::of(pkt_type, 34)).retval, kind);
    }
    // The protocol, in network order; a length in the type is 802.2's.
    let protocol = e.program(&field(16));
    for (kind, expected) in [
        (0x0800, 0x0008),
        (0x86dd, 0xdd86),
        (0x0600, 0x0006),
        (0x05ff, 0x0400),
        (0xffff, 0xffff),
    ] {
        e.packet([0; 6], kind, 60);
        assert_eq!(e.test_run(&TestRun::of(protocol, 60)).retval, expected);
    }
}

/// The checks of `bpf_prog_test_run` and `bpf_prog_test_run_skb`, in their
/// order.
#[test]
fn a_test_run_checks_its_arguments() {
    let mut e = Env::new();
    let fd = e.program(&[mov(0, 1), exit()]);
    let map = e.map(2, 4, 8, 1, 0);
    e.packet([0; 6], 0x0800, 64);
    let ok = TestRun::of(fd, 64);
    let result = |e: &mut Env, run: TestRun| e.test_run(&run).result;
    assert_eq!(result(&mut e, ok), 0);
    // A context's size without its address, or the other way.
    for run in [
        TestRun {
            ctx_size_in: 4,
            ..ok
        },
        TestRun {
            ctx_in: CTX_IN,
            ..ok
        },
        TestRun {
            ctx_size_out: 4,
            ..ok
        },
        TestRun {
            ctx_out: CTX_OUT,
            ..ok
        },
    ] {
        assert_eq!(result(&mut e, run), -22);
    }
    assert_eq!(result(&mut e, TestRun { prog_fd: 99, ..ok }), -9);
    assert_eq!(
        result(
            &mut e,
            TestRun {
                prog_fd: map as u32,
                ..ok
            }
        ),
        -22
    );
    // Flags other than BPF_F_TEST_SKB_CHECKSUM_COMPLETE, a processor, and
    // fewer bytes than an Ethernet header.
    for run in [
        TestRun { flags: 1, ..ok },
        TestRun { flags: 2, ..ok },
        TestRun { cpu: 1, ..ok },
        TestRun {
            data_size_in: 13,
            ..ok
        },
    ] {
        assert_eq!(result(&mut e, run), -22);
    }
    assert_eq!(result(&mut e, TestRun { flags: 4, ..ok }), 0);
    // An IPv4 or IPv6 packet shorter than its header (master), and an ARP
    // one, which has no header to check.
    assert_eq!(
        result(
            &mut e,
            TestRun {
                data_size_in: 14,
                ..ok
            }
        ),
        -22
    );
    e.packet([0; 6], 0x0806, 14);
    assert_eq!(result(&mut e, TestRun::of(fd, 14)), 0);
    e.packet([0; 6], 0x0800, 33);
    assert_eq!(result(&mut e, TestRun::of(fd, 33)), -22);
    e.packet([0; 6], 0x86dd, 53);
    assert_eq!(result(&mut e, TestRun::of(fd, 53)), -22);
    e.packet([0; 6], 0x86dd, 54);
    assert_eq!(result(&mut e, TestRun::of(fd, 54)), 0);
    // More pages than MAX_SKB_FRAGS: a page less its head and tailroom,
    // then 17 more.
    let most = 3712 + 17 * 4096;
    assert_eq!(result(&mut e, TestRun::of(fd, most + 1)), -12);
    // Data that cannot be read.
    assert_eq!(
        result(
            &mut e,
            TestRun {
                data_in: 0x1000,
                ..ok
            }
        ),
        -14
    );
    // A context past struct __sk_buff must be zeros there (E2BIG); of its
    // fields only some may be set; wire_len must not be shorter than the
    // packet; a device must be there.
    e.packet([0; 6], 0x0800, 64);
    let with = ok.with_context();
    let context = |e: &mut Env, at: usize, value: u32, run: TestRun| {
        let mut ctx = [0u8; 200];
        ctx[at..at + 4].copy_from_slice(&value.to_le_bytes());
        e.put(CTX_IN, &ctx);
        result(e, run)
    };
    assert_eq!(
        context(
            &mut e,
            196,
            1,
            TestRun {
                ctx_size_in: 200,
                ..with
            }
        ),
        -7
    );
    assert_eq!(
        context(
            &mut e,
            196,
            0,
            TestRun {
                ctx_size_in: 200,
                ..with
            }
        ),
        0
    );
    assert_eq!(context(&mut e, 0, 1, with), -22);
    assert_eq!(context(&mut e, 68, 1, with), -22);
    assert_eq!(context(&mut e, 8, 1, with), 0);
    assert_eq!(context(&mut e, 160, 49, with), -22);
    assert_eq!(context(&mut e, 160, 50, with), 0);
    assert_eq!(context(&mut e, 160, 65537, with), -22);
    assert_eq!(context(&mut e, 164, 65536, with), -22);
    assert_eq!(context(&mut e, 40, 5, with), -19);
    assert_eq!(context(&mut e, 76, 1, with), -22);
    assert_eq!(context(&mut e, 80, 65, with), -22);
    // Too little room for the packet or the context: ENOSPC, with the
    // sizes written.
    e.put(CTX_IN, &[0; 200]);
    let ran = e.test_run(&TestRun {
        data_size_out: 20,
        ..ok
    });
    assert_eq!((ran.result, ran.size_out), (-28, 64));
    let ran = e.test_run(&TestRun {
        ctx_size_out: 100,
        ..with
    });
    assert_eq!((ran.result, ran.ctx_size_out), (-28, 192));
}

/// The context's `cb[]` reaches the program, which may change it for the
/// next of `repeat` runs and for the context that comes back, with the
/// other fields Linux gives back.
#[test]
fn a_test_run_s_context_goes_in_and_comes_back() {
    let mut e = Env::new();
    // cb[0] += 1; r0 = cb[0]
    let fd = e.program(&[
        ldx_w(2, 1, 48),
        add(2, 1),
        stx_w(1, 2, 48),
        mov_reg(0, 2),
        exit(),
    ]);
    e.packet([0; 6], 0x0800, 64);
    let mut ctx = [0u8; 192];
    let mut put = |at: usize, v: u32| ctx[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put(8, 7); // mark
    put(48, 5); // cb[0]
    put(176, 9); // gso_size
    e.put(CTX_IN, &ctx);
    let ran = e.test_run(&TestRun {
        repeat: 3,
        ..TestRun::of(fd, 64).with_context()
    });
    assert_eq!((ran.result, ran.retval, ran.ctx_size_out), (0, 8, 192));
    let out = e.get(CTX_OUT, 192);
    let at = |n: usize| u32::from_le_bytes(out[n..n + 4].try_into().unwrap());
    // mark, ifindex (the loopback's), cb[0], wire_len and gso_size.
    assert_eq!([at(8), at(40), at(48), at(160), at(176)], [7, 1, 8, 50, 9]);
}

/// A packet past what its linear part takes goes in pages, and comes back
/// whole, or as much as `data_size_out` takes, its linear part first.
#[test]
fn a_test_run_s_packet_may_be_in_pages() {
    let mut e = Env::new();
    let len = e.program(&field(0));
    e.packet([0; 6], 0x0800, 5000);
    let ran = e.test_run(&TestRun::of(len, 5000));
    assert_eq!((ran.result, ran.retval, ran.size_out), (0, 4986, 5000));
    let mut expected = vec![0; 14];
    expected.extend((0..4986).map(|n| n as u8));
    assert_eq!(e.get(PACKET_OUT, 5000), expected);
    // data_end makes the linear part 34 bytes long; 40 bytes come back.
    let mut ctx = [0u8; 192];
    ctx[80..84].copy_from_slice(&34u32.to_le_bytes());
    e.put(CTX_IN, &ctx);
    e.put(PACKET_OUT, &[0xee; 64]);
    let ran = e.test_run(&TestRun {
        data_size_out: 40,
        ..TestRun::of(len, 64).with_context()
    });
    assert_eq!((ran.result, ran.retval, ran.size_out), (-28, 50, 64));
    let out = e.get(PACKET_OUT, 41);
    assert_eq!(out[..14], [0; 14]);
    assert_eq!(out[14..40], (0..26).collect::<Vec<u8>>()[..]);
    assert_eq!(out[40], 0xee);
}
