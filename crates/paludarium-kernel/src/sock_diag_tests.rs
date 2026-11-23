//! `NETLINK_SOCK_DIAG`'s AF_UNIX handler through the system call
//! interface, in a network namespace of its own: dumps by state with every
//! attribute `udiag_show` asks for and with none, one socket by its inode
//! and cookie, and the requests it refuses (`TCPDIAG_GETSOCK`'s neighbours,
//! a short request, a family past `AF_MAX` or with no handler,
//! `SOCK_DESTROY`, a stale cookie, a second dump while one runs). The calls
//! are those of the sock-diag case of `tests/guests/processes/process.c`,
//! made in the same order, and `ask` and `print` read the answers as its
//! `diag_ask` and `diag_print` do. The expected lines are what that case
//! printed on native x86-64 Linux in the differential tests (the CI run of
//! main at fb9a1ff3), which compare it with Linux on every run; the case's
//! last line, the parent's `maker=0`, is left to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
/// A path, a `struct sockaddr_un` or `sockaddr_nl`, and an option's value
/// with its length.
const PATH: u64 = DATA;
const NAME: u64 = DATA + 0x100;
const VALUE: u64 = DATA + 0x200;
const LEN: u64 = DATA + 0x220;
/// A `socketpair`'s descriptors, and a `struct stat`.
const PAIR: u64 = DATA + 0x240;
const STAT: u64 = DATA + 0x300;
/// A request, and what a receive reads.
const REQUEST: u64 = DATA + 0x400;
const BUFFER: u64 = DATA + 0x1000;
/// The guest's receive buffer.
const BUFFER_LEN: u64 = 32768;
const SIZE: u64 = 0x10000;

const WRITE: u64 = 1;
const CLOSE: u64 = 3;
const STAT_PATH: u64 = 4;
const FSTAT: u64 = 5;
const SOCKET: u64 = 41;
const CONNECT: u64 = 42;
const ACCEPT: u64 = 43;
const SENDTO: u64 = 44;
const RECVFROM: u64 = 45;
const SHUTDOWN: u64 = 48;
const BIND: u64 = 49;
const LISTEN: u64 = 50;
const SOCKETPAIR: u64 = 53;
const SETSOCKOPT: u64 = 54;
const GETSOCKOPT: u64 = 55;
const MKDIR: u64 = 83;
const RMDIR: u64 = 84;
const UNLINK: u64 = 87;
const UNSHARE: u64 = 272;

const AF_UNIX: u64 = 1;
const AF_NETLINK: u64 = 16;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_SEQPACKET: u64 = 5;
const NETLINK_SOCK_DIAG: u64 = 4;
const CLONE_NEWNET: u64 = 0x4000_0000;
const SOL_SOCKET: u64 = 1;
const SOL_NETLINK: u64 = 270;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PROTOCOL: u64 = 38;
const SHUT_WR: u64 = 1;
const MSG_DONTWAIT: u64 = 0x40;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NONE: [u32; 2] = [u32::MAX, u32::MAX];

/// What the case printed on native Linux.
const EXPECTED: &str = r"unshare=0
socket: diag=1 protocol=4
all: type=3 flags=0x2 seq=1 error=0
all: listener family=1 type=1 state=10 name=<path> vfs=ino:1,dev:1 icons=waiting 4=1,5 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: waiting family=1 type=1 state=1 peer=0 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: client family=1 type=1 state=1 peer=accepted 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: accepted family=1 type=1 state=1 name=<path> vfs=ino:1,dev:1 peer=client 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: named family=1 type=1 state=7 name=\0paludarium-diag 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: pair0 family=1 type=1 state=1 peer=pair1 4=0,768 5=0,rcvbuf,768,sndbuf,0,0,0,0,0 6=01 uid=0
all: pair1 family=1 type=1 state=1 peer=pair0 4=5,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=02 uid=0
all: seq0 family=1 type=5 state=1 peer=seq1 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: seq1 family=1 type=5 state=1 peer=seq0 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: orphan family=1 type=1 state=1 peer=0 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=03 uid=0
all: target family=1 type=2 state=1 name=\0paludarium-dgram 4=3,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: sender family=1 type=2 state=1 peer=target 4=0,768 5=0,rcvbuf,768,sndbuf,0,0,0,0,0 6=00 uid=0
all: left family=1 type=2 state=7 name=\0paludarium-left 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: mover family=1 type=2 state=1 peer=target 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: auto family=1 type=2 state=7 name=<auto> 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: unbound family=1 type=1 state=7 4=0,0 5=0,rcvbuf,0,sndbuf,0,0,0,0,0 6=00 uid=0
all: unknown=0
bare: type=3 flags=0x2 seq=1 error=0
bare: listener family=1 type=1 state=10 6=00
bare: waiting family=1 type=1 state=1 6=00
bare: client family=1 type=1 state=1 6=00
bare: accepted family=1 type=1 state=1 6=00
bare: named family=1 type=1 state=7 6=00
bare: pair0 family=1 type=1 state=1 6=01
bare: pair1 family=1 type=1 state=1 6=02
bare: seq0 family=1 type=5 state=1 6=00
bare: seq1 family=1 type=5 state=1 6=00
bare: orphan family=1 type=1 state=1 6=03
bare: target family=1 type=2 state=1 6=00
bare: sender family=1 type=2 state=1 6=00
bare: left family=1 type=2 state=7 6=00
bare: mover family=1 type=2 state=1 6=00
bare: auto family=1 type=2 state=7 6=00
bare: unbound family=1 type=1 state=7 6=00
bare: unknown=0
listening: type=3 flags=0x2 seq=1 error=0
listening: listener family=1 type=1 state=10 6=00
listening: unknown=0
closed: type=3 flags=0x2 seq=1 error=0
closed: named family=1 type=1 state=7 6=00
closed: left family=1 type=2 state=7 6=00
closed: auto family=1 type=2 state=7 6=00
closed: unbound family=1 type=1 state=7 6=00
closed: unknown=0
nothing: type=3 flags=0x2 seq=1 error=0
nothing: unknown=0
exact: flags=0 seq=1
exact: listener family=1 type=1 state=10 name=<path> vfs=ino:1,dev:1 icons=waiting 4=1,5 6=00
exact cookie: flags=0 seq=1
exact cookie: listener family=1 type=1 state=10 6=00
exact cookie: type=2 flags=0x100 seq=1 error=0
exact cookie: unknown=0
exact stale: type=2 flags=0 seq=1 error=-116
exact stale: unknown=0
exact other: type=2 flags=0 seq=1 error=-2
exact other: unknown=0
exact zero: type=2 flags=0 seq=1 error=-22
exact zero: unknown=0
short: type=2 flags=0 seq=1 error=-22
short: unknown=0
tiny: type=2 flags=0 seq=1 error=-22
tiny: unknown=0
past families: type=2 flags=0 seq=1 error=-22
past families: unknown=0
no handler: type=2 flags=0 seq=1 error=-2
no handler: unknown=0
destroy: type=2 flags=0 seq=1 error=-95
destroy: unknown=0
other type: type=2 flags=0 seq=1 error=-22
other type: unknown=0
busy: type=2 flags=0 seq=1 error=-16
busy: listener family=1 type=1 state=10 6=00
busy: waiting family=1 type=1 state=1 6=00
busy: client family=1 type=1 state=1 6=00
busy: accepted family=1 type=1 state=1 6=00
busy: named family=1 type=1 state=7 6=00
busy: pair0 family=1 type=1 state=1 6=01
busy: pair1 family=1 type=1 state=1 6=02
busy: seq0 family=1 type=5 state=1 6=00
busy: seq1 family=1 type=5 state=1 6=00
busy: orphan family=1 type=1 state=1 6=03
busy: target family=1 type=2 state=1 6=00
busy: sender family=1 type=2 state=1 6=00
busy: left family=1 type=2 state=7 6=00
busy: mover family=1 type=2 state=1 6=00
busy: auto family=1 type=2 state=7 6=00
busy: unbound family=1 type=1 state=7 6=00
busy: unknown=0
after busy: type=3 flags=0x2 seq=0 error=0
after busy: unknown=0
join: one=0 five=0
";

/// A socket the case made: its label, descriptor and inode.
struct Made {
    label: &'static str,
    fd: u64,
    ino: u32,
}

/// A kernel whose thread runs the first process, as root, the sockets it
/// made, and the lines it prints.
struct Env {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    made: Vec<Made>,
    path: Vec<u8>,
    seq: u32,
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
            made: Vec::new(),
            path: Vec::new(),
            seq: 0,
            lines: Vec::new(),
        }
    }

    /// A call's result, or `-errno`: the guest's `netns_result`.
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

    /// A call that must succeed: its result.
    fn ok(&mut self, n: u64, a: [u64; 6]) -> u64 {
        let r = self.call(n, a);
        assert!(r >= 0, "call {n} {a:x?}: {r}");
        r as u64
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

    fn socket(&mut self, kind: u64) -> u64 {
        self.ok(SOCKET, [AF_UNIX, kind, 0, 0, 0, 0])
    }

    /// A `sockaddr_un` of `path` (a NUL-led name is abstract) at `NAME`.
    fn name(&self, path: &[u8]) {
        let mut b = (AF_UNIX as u16).to_le_bytes().to_vec();
        b.extend_from_slice(path);
        b.resize(110, 0);
        self.put(NAME, &b);
    }

    fn pair(&mut self, kind: u64) -> [u64; 2] {
        self.ok(SOCKETPAIR, [AF_UNIX, kind, 0, PAIR, 0, 0]);
        [u64::from(self.word(PAIR)), u64::from(self.word(PAIR + 4))]
    }

    /// The guest's `diag_add`: `fd` and its inode, by `label`.
    fn add(&mut self, label: &'static str, fd: u64) {
        self.ok(FSTAT, [fd, STAT, 0, 0, 0, 0]);
        let ino = self.word(STAT + 8);
        self.made.push(Made { label, fd, ino });
    }

    /// The guest's `diag_label`.
    fn label(&self, ino: u32) -> &'static str {
        if ino == 0 {
            return "0";
        }
        self.made
            .iter()
            .find(|s| s.ino == ino)
            .map_or("?", |s| s.label)
    }

    /// The guest's `nl_send`: a request of `kind` and `flags` to the
    /// kernel, and its sequence number.
    fn send(&mut self, fd: u64, kind: u16, flags: u16, payload: &[u8]) -> u32 {
        self.seq += 1;
        let len = 16 + payload.len();
        let mut b = (len as u32).to_le_bytes().to_vec();
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(payload);
        self.put(REQUEST, &b);
        let mut kernel = (AF_NETLINK as u16).to_le_bytes().to_vec();
        kernel.resize(12, 0);
        self.put(NAME, &kernel);
        self.ok(SENDTO, [fd, REQUEST, len as u64, 0, NAME, 12]);
        self.seq
    }

    /// A `unix_diag_req` of `family`, `states`, `ino`, `show` and
    /// `cookie`, the first `len` bytes of it.
    fn request(
        family: u8,
        states: u32,
        ino: u32,
        show: u32,
        cookie: [u32; 2],
        len: usize,
    ) -> Vec<u8> {
        let mut b = vec![family, 0, 0, 0];
        b.extend_from_slice(&states.to_le_bytes());
        b.extend_from_slice(&ino.to_le_bytes());
        b.extend_from_slice(&show.to_le_bytes());
        b.extend_from_slice(&cookie[0].to_le_bytes());
        b.extend_from_slice(&cookie[1].to_le_bytes());
        b.truncate(len);
        b
    }

    /// The guest's `diag_ask`: sends the request and prints the answer, a
    /// dump's messages in the order the sockets were made in.
    #[allow(clippy::too_many_arguments)]
    fn ask(
        &mut self,
        fd: u64,
        label: &str,
        kind: u16,
        flags: u16,
        family: u8,
        states: u32,
        ino: u32,
        show: u32,
        cookie: [u32; 2],
        len: usize,
    ) {
        let request = Self::request(family, states, ino, show, cookie, len);
        let seq = self.send(fd, kind, flags, &request);
        let mut found: Vec<Option<Vec<u8>>> = vec![None; self.made.len()];
        let mut unknown = 0;
        let mut done = false;
        while !done {
            let n = self.call(RECVFROM, [fd, BUFFER, BUFFER_LEN, MSG_DONTWAIT, 0, 0]);
            if n <= 0 {
                break;
            }
            let buf = self.get(BUFFER, n as usize);
            let mut at = 0;
            while at + 16 <= buf.len() {
                let h = &buf[at..];
                let hlen = u32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
                if hlen < 16 || at + hlen > buf.len() {
                    break;
                }
                let htype = u16::from_le_bytes([h[4], h[5]]);
                let hflags = u16::from_le_bytes([h[6], h[7]]);
                let hseq = u32::from_le_bytes(h[8..12].try_into().unwrap());
                let body = h[16..hlen].to_vec();
                at += (hlen + 3) & !3;
                if htype == 2 || htype == 3 {
                    let error = i32::from_le_bytes(body[..4].try_into().unwrap());
                    self.lines.push(format!(
                        "{label}: type={htype} flags={} seq={} error={error}",
                        hex(hflags),
                        u8::from(hseq == seq)
                    ));
                    done = true;
                    break;
                }
                let got = u32::from_le_bytes(body[4..8].try_into().unwrap());
                let Some(i) = self.made.iter().position(|s| s.ino == got) else {
                    unknown += 1;
                    continue;
                };
                if body.len() > 512 {
                    unknown += 1;
                    continue;
                }
                if flags & NLM_F_DUMP == 0 {
                    self.lines.push(format!(
                        "{label}: flags={} seq={}",
                        hex(hflags),
                        u8::from(hseq == seq)
                    ));
                    self.print(label, &body);
                    if flags & NLM_F_ACK == 0 {
                        return;
                    }
                    found[i] = None;
                } else {
                    found[i] = Some(body);
                }
            }
        }
        for body in found.into_iter().flatten() {
            self.print(label, &body);
        }
        self.lines.push(format!("{label}: unknown={unknown}"));
    }

    /// The guest's `diag_print`: a `unix_diag_msg` and its attributes as
    /// one line.
    fn print(&mut self, label: &str, body: &[u8]) {
        let ino = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let mut line = format!(
            "{label}: {} family={} type={} state={}",
            self.label(ino),
            body[0],
            body[1],
            body[2]
        );
        let mut rest = &body[16..];
        while rest.len() >= 4 {
            let alen = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
            let kind = u16::from_le_bytes([rest[2], rest[3]]);
            if alen < 4 || alen > rest.len() {
                break;
            }
            let v = &rest[4..alen];
            let words: Vec<u32> = v
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&w| u32::from_le_bytes(w))
                .collect();
            let word = words.first().copied().unwrap_or(0);
            match kind {
                0 => {
                    let mut path = self.path.clone();
                    path.push(0);
                    if v.first() == Some(&b'/') {
                        line += if v == path.as_slice() {
                            " name=<path>"
                        } else {
                            " name=<other>"
                        };
                    } else if v.len() == 6 && v[0] == 0 {
                        line += " name=<auto>";
                    } else {
                        line += " name=";
                        for &c in v {
                            if (32..127).contains(&c) {
                                line.push(char::from(c));
                            } else {
                                line += &format!("\\{c:o}");
                            }
                        }
                    }
                }
                1 => {
                    let mut path = self.path.clone();
                    path.push(0);
                    self.put(PATH, &path);
                    self.ok(STAT_PATH, [PATH, STAT, 0, 0, 0, 0]);
                    let st_dev = u64::from_le_bytes(self.get(STAT, 8).try_into().unwrap());
                    let st_ino = self.word(STAT + 8);
                    let major = ((st_dev >> 32) & 0xffff_f000) | ((st_dev >> 8) & 0xfff);
                    let minor = ((st_dev >> 12) & 0xffff_ff00) | (st_dev & 0xff);
                    let kdev = (major << 20 | minor) as u32;
                    line += &format!(
                        " vfs=ino:{},dev:{}",
                        u8::from(word == st_ino),
                        u8::from(words[1] == kdev)
                    );
                }
                2 => line += &format!(" peer={}", self.label(word)),
                3 => {
                    let icons: Vec<_> = words.iter().map(|&w| self.label(w)).collect();
                    line += &format!(" icons={}", icons.join(","));
                }
                5 => {
                    // SO_RCVBUF and SO_SNDBUF as the socket's own
                    // getsockopt gives them.
                    let fd = self
                        .made
                        .iter()
                        .find(|s| s.ino == ino)
                        .map(|s| s.fd)
                        .unwrap();
                    let mut buffers = [0u32; 2];
                    for (b, option) in buffers.iter_mut().zip([SO_RCVBUF, SO_SNDBUF]) {
                        self.put(LEN, &4u32.to_le_bytes());
                        self.ok(GETSOCKOPT, [fd, SOL_SOCKET, option, VALUE, LEN, 0]);
                        *b = self.word(VALUE);
                    }
                    line += " 5=";
                    for (i, &w) in words.iter().enumerate() {
                        if i == 1 && w == buffers[0] {
                            line += ",rcvbuf";
                        } else if i == 3 && w == buffers[1] {
                            line += ",sndbuf";
                        } else {
                            line += &format!("{}{w}", if i > 0 { "," } else { "" });
                        }
                    }
                }
                7 => line += &format!(" uid={word}"),
                _ => {
                    line += &format!(" {kind}=");
                    let shown: Vec<_> = words.iter().map(u32::to_string).collect();
                    line += &shown.join(",");
                    if v.len() < 4 {
                        for c in v {
                            line += &format!("{c:02x}");
                        }
                    }
                }
            }
            let step = (alen + 3) & !3;
            rest = &rest[step.min(rest.len())..];
        }
        self.lines.push(line);
    }
}

/// `%#x`, which prints 0 bare.
fn hex(value: u16) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

#[test]
fn sock_diag_dumps_answers_and_refuses_as_linux() {
    let mut e = Env::new();
    let r = e.call(UNSHARE, [CLONE_NEWNET, 0, 0, 0, 0, 0]);
    e.lines.push(format!("unshare={r}"));
    let d = e.call(SOCKET, [AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG, 0, 0, 0]);
    e.put(LEN, &4u32.to_le_bytes());
    e.ok(
        GETSOCKOPT,
        [d as u64, SOL_SOCKET, SO_PROTOCOL, VALUE, LEN, 0],
    );
    let protocol = e.word(VALUE);
    e.lines.push(format!(
        "socket: diag={} protocol={protocol}",
        u8::from(d >= 0)
    ));
    let d = d as u64;

    // The guest's mkdtemp, at a name of its own.
    let dir = b"/tmp/paludarium-diag-replay".to_vec();
    let mut at = dir.clone();
    at.push(0);
    e.put(PATH, &at);
    e.ok(MKDIR, [PATH, 0o700, 0, 0, 0, 0]);
    e.path = [dir.as_slice(), b"/listener"].concat();
    let path = e.path.clone();

    e.name(&path);
    let listener = e.socket(SOCK_STREAM);
    e.ok(BIND, [listener, NAME, 110, 0, 0, 0]);
    e.ok(LISTEN, [listener, 5, 0, 0, 0, 0]);
    e.add("listener", listener);
    let waiting = e.socket(SOCK_STREAM);
    let client = e.socket(SOCK_STREAM);
    e.ok(CONNECT, [client, NAME, 110, 0, 0, 0]);
    e.ok(CONNECT, [waiting, NAME, 110, 0, 0, 0]);
    e.add("waiting", waiting);
    e.add("client", client);
    // The first to connect, `client`, is accepted; `waiting` is left.
    let accepted = e.ok(ACCEPT, [listener, 0, 0, 0, 0, 0]);
    e.add("accepted", accepted);
    e.name(b"\0paludarium-diag");
    let named = e.socket(SOCK_STREAM);
    e.ok(BIND, [named, NAME, 2 + 16, 0, 0, 0]);
    e.add("named", named);
    let pair = e.pair(SOCK_STREAM);
    e.add("pair0", pair[0]);
    e.add("pair1", pair[1]);
    e.put(VALUE, b"hello");
    e.ok(WRITE, [pair[0], VALUE, 5, 0, 0, 0]);
    e.ok(SHUTDOWN, [pair[1], SHUT_WR, 0, 0, 0, 0]);
    let seq = e.pair(SOCK_SEQPACKET);
    e.add("seq0", seq[0]);
    e.add("seq1", seq[1]);
    let closed = e.pair(SOCK_STREAM);
    e.add("orphan", closed[0]);
    e.ok(CLOSE, [closed[1], 0, 0, 0, 0, 0]);
    let target = e.socket(SOCK_DGRAM);
    let sender = e.socket(SOCK_DGRAM);
    e.name(b"\0paludarium-dgram");
    e.ok(BIND, [target, NAME, 2 + 17, 0, 0, 0]);
    e.ok(CONNECT, [sender, NAME, 2 + 17, 0, 0, 0]);
    e.put(VALUE, b"abc");
    e.ok(SENDTO, [sender, VALUE, 3, 0, 0, 0]);
    e.add("target", target);
    e.add("sender", sender);
    // One that connects to `left` and then elsewhere leaves it TCP_CLOSE,
    // as it has no peer of its own.
    let left = e.socket(SOCK_DGRAM);
    let mover = e.socket(SOCK_DGRAM);
    e.name(b"\0paludarium-left");
    e.ok(BIND, [left, NAME, 2 + 16, 0, 0, 0]);
    e.ok(CONNECT, [mover, NAME, 2 + 16, 0, 0, 0]);
    e.name(b"\0paludarium-dgram");
    e.ok(CONNECT, [mover, NAME, 2 + 17, 0, 0, 0]);
    e.add("left", left);
    e.add("mover", mover);
    let lone = e.socket(SOCK_DGRAM);
    e.name(b"");
    e.ok(BIND, [lone, NAME, 2, 0, 0, 0]);
    e.add("auto", lone);
    let unbound = e.socket(SOCK_STREAM);
    e.add("unbound", unbound);

    let dump = NLM_F_REQUEST | NLM_F_DUMP;
    e.ask(
        d,
        "all",
        SOCK_DIAG_BY_FAMILY,
        dump,
        1,
        !0,
        0,
        0x7f,
        NONE,
        24,
    );
    e.ask(d, "bare", SOCK_DIAG_BY_FAMILY, dump, 1, !0, 0, 0, NONE, 24);
    e.ask(
        d,
        "listening",
        SOCK_DIAG_BY_FAMILY,
        dump,
        1,
        1 << 10,
        0,
        0,
        NONE,
        24,
    );
    e.ask(
        d,
        "closed",
        SOCK_DIAG_BY_FAMILY,
        dump,
        1,
        1 << 7,
        0,
        0,
        NONE,
        24,
    );
    e.ask(
        d,
        "nothing",
        SOCK_DIAG_BY_FAMILY,
        dump,
        1,
        1 << 2,
        0,
        0,
        NONE,
        24,
    );
    // One socket by its inode, with no cookie, its own and another.
    let ino = e.made[0].ino;
    let one = NLM_F_REQUEST;
    e.ask(
        d,
        "exact",
        SOCK_DIAG_BY_FAMILY,
        one,
        1,
        0,
        ino,
        0x1f,
        NONE,
        24,
    );
    let request = Env::request(1, 0, ino, 0, NONE, 24);
    e.send(d, SOCK_DIAG_BY_FAMILY, one, &request);
    let mut cookie = [0u32; 2];
    if e.call(RECVFROM, [d, BUFFER, 512, 0, 0, 0]) >= 32 {
        cookie = [e.word(BUFFER + 24), e.word(BUFFER + 28)];
    }
    let ack = NLM_F_REQUEST | NLM_F_ACK;
    e.ask(
        d,
        "exact cookie",
        SOCK_DIAG_BY_FAMILY,
        ack,
        1,
        0,
        ino,
        0,
        cookie,
        24,
    );
    cookie[0] = cookie[0].wrapping_add(1);
    e.ask(
        d,
        "exact stale",
        SOCK_DIAG_BY_FAMILY,
        one,
        1,
        0,
        ino,
        0,
        cookie,
        24,
    );
    e.ok(FSTAT, [d, STAT, 0, 0, 0, 0]);
    let own = e.word(STAT + 8);
    e.ask(
        d,
        "exact other",
        SOCK_DIAG_BY_FAMILY,
        one,
        1,
        0,
        own,
        0,
        NONE,
        24,
    );
    e.ask(
        d,
        "exact zero",
        SOCK_DIAG_BY_FAMILY,
        one,
        1,
        0,
        0,
        0,
        NONE,
        24,
    );
    e.ask(d, "short", SOCK_DIAG_BY_FAMILY, dump, 1, !0, 0, 0, NONE, 8);
    e.ask(d, "tiny", SOCK_DIAG_BY_FAMILY, dump, 1, !0, 0, 0, NONE, 1);
    e.ask(
        d,
        "past families",
        SOCK_DIAG_BY_FAMILY,
        dump,
        46,
        !0,
        0,
        0,
        NONE,
        24,
    );
    e.ask(
        d,
        "no handler",
        SOCK_DIAG_BY_FAMILY,
        dump,
        3,
        !0,
        0,
        0,
        NONE,
        24,
    );
    e.ask(d, "destroy", SOCK_DESTROY, one, 1, 0, ino, 0, NONE, 24);
    e.ask(d, "other type", 22, one, 1, 0, ino, 0, NONE, 24);
    // A second dump while one runs is EBUSY.
    let mut running = [0u8; 24];
    running[4..8].fill(0xff);
    running[0] = 1;
    e.send(d, SOCK_DIAG_BY_FAMILY, dump, &running);
    e.ask(d, "busy", SOCK_DIAG_BY_FAMILY, dump, 1, !0, 0, 0, NONE, 24);
    e.ask(
        d,
        "after busy",
        SOCK_DIAG_BY_FAMILY,
        dump,
        1,
        1 << 10,
        0,
        0,
        NONE,
        24,
    );
    let mut joins = [0i64; 2];
    for (r, group) in joins.iter_mut().zip([1u32, 5]) {
        e.put(VALUE, &group.to_le_bytes());
        *r = e.call(
            SETSOCKOPT,
            [d, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, VALUE, 4, 0],
        );
    }
    e.lines
        .push(format!("join: one={} five={}", joins[0], joins[1]));
    let mut at = path.clone();
    at.push(0);
    e.put(PATH, &at);
    e.ok(UNLINK, [PATH, 0, 0, 0, 0, 0]);
    let mut at = dir.clone();
    at.push(0);
    e.put(PATH, &at);
    e.ok(RMDIR, [PATH, 0, 0, 0, 0, 0]);

    assert_eq!(e.lines, EXPECTED.lines().collect::<Vec<_>>());
}
