//! AF_MCTP sockets through the system call interface, in a network
//! namespace of their own: the calls a datagram socket does not have, its
//! binds and connects, `MCTP_OPT_ADDR_EXT`, the local IDs' routes and a
//! gateway's route in packets of its MTU, a full receive buffer, out of lo
//! by its hardware address, the keys of owned tags and the tags
//! `SIOCMCTPALLOCTAG` keeps. The expected values are Linux's
//! (`net/mctp/af_mctp.c`, `route.c`): they are the lines of the
//! mctp-sockets case of `tests/guests/processes/process.c`, which the
//! differential tests compare with Linux.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
/// A `struct sockaddr_mctp_ext`, or a socket option's value.
const NAME: u64 = DATA;
const VALUE: u64 = DATA + 0x80;
const LEN: u64 = DATA + 0xc0;
/// A netlink request, and its answer.
const REQUEST: u64 = DATA + 0x100;
const ANSWER: u64 = DATA + 0x400;
/// A `struct msghdr` and its `struct iovec`.
const HEADER: u64 = DATA + 0x1400;
const IOV: u64 = DATA + 0x1480;
/// What a send writes, and what a receive reads.
const RECEIVED: u64 = DATA + 0x2000;
const SENT: u64 = DATA + 0x20000;
/// The mapping, which takes a 5 MiB message.
const SIZE: u64 = 0x800000;

const WRITE: u64 = 1;
const CLOSE: u64 = 3;
const IOCTL: u64 = 16;
const SOCKET: u64 = 41;
const ACCEPT: u64 = 43;
const SENDTO: u64 = 44;
const RECVFROM: u64 = 45;
const RECVMSG: u64 = 47;
const SHUTDOWN: u64 = 48;
const BIND: u64 = 49;
const LISTEN: u64 = 50;
const GETSOCKNAME: u64 = 51;
const GETPEERNAME: u64 = 52;
const SOCKETPAIR: u64 = 53;
const SETSOCKOPT: u64 = 54;
const GETSOCKOPT: u64 = 55;
const CONNECT: u64 = 42;
const UNSHARE: u64 = 272;

const AF_MCTP: u64 = 45;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOL_SOCKET: u64 = 1;
const SOL_MCTP: u64 = 285;
const MSG_OOB: u64 = 1;
const MSG_PEEK: u64 = 2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

/// A `struct sockaddr_mctp`.
fn mctp_name(net: u32, eid: u8, kind: u8, tag: u8) -> Vec<u8> {
    let mut b = vec![45, 0, 0, 0];
    b.extend_from_slice(&net.to_le_bytes());
    b.extend_from_slice(&[eid, kind, tag, 0]);
    b
}

/// A `struct sockaddr_mctp_ext` of lo's index and `halen`, with `pad1` as
/// the second byte of its padding.
fn mctp_ext(eid: u8, ifindex: i32, halen: u8, pad1: u8) -> Vec<u8> {
    let mut b = mctp_name(0, eid, 1, 8);
    b.extend_from_slice(&ifindex.to_le_bytes());
    b.extend_from_slice(&[halen, 0, pad1, 0]);
    b.extend_from_slice(&[0; 32]);
    b
}

/// A kernel whose thread runs the first process, as root, and the lines it
/// prints.
struct Env {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    lines: Vec<String>,
    seq: u32,
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
            seq: 100,
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

    fn socket(&mut self, kind: u64, protocol: u64) -> i64 {
        self.call(SOCKET, [AF_MCTP, kind, protocol, 0, 0, 0])
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// `bind` or `connect` (`n`) to the first `len` bytes of `name`.
    fn address(&mut self, n: u64, fd: i64, name: &[u8], len: u64) -> i64 {
        self.put(NAME, name);
        self.call(n, [fd as u64, NAME, len, 0, 0, 0])
    }

    fn setsockopt(&mut self, fd: i64, level: u64, option: u64, value: i32, len: u64) -> i64 {
        self.put(VALUE, &value.to_le_bytes());
        self.call(SETSOCKOPT, [fd as u64, level, option, VALUE, len, 0])
    }

    /// `getsockopt`'s result, value and length, the length set to `len`.
    fn getsockopt(&mut self, fd: i64, level: u64, option: u64, len: u32) -> (i64, i32, u32) {
        self.put(VALUE, &0i32.to_le_bytes());
        self.put(LEN, &len.to_le_bytes());
        let r = self.call(GETSOCKOPT, [fd as u64, level, option, VALUE, LEN, 0]);
        (r, self.word(VALUE) as i32, self.word(LEN))
    }

    /// The guest's `mctp_send`: `len` bytes of the alphabet to the first
    /// `size` bytes of `name` (zeros for a message longer than 70000).
    fn send(&mut self, fd: i64, name: &[u8], size: u64, len: u64, label: &str) {
        if len <= 70000 {
            let bytes: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            self.put(SENT, &bytes);
        } else {
            self.put(SENT, &vec![0; 70000]);
        }
        self.put(NAME, name);
        let r = self.call(SENDTO, [fd as u64, SENT, len, 0, NAME, size]);
        self.say(format!("{label}: send={r}"));
    }

    /// The guest's `mctp_receive`: a `recvmsg` of `room` bytes that does
    /// not wait, its flags, name and bytes.
    fn receive(&mut self, fd: i64, flags: u64, room: u64, label: &str) {
        self.put(NAME, &[0x5a; 52]);
        self.put(IOV, &RECEIVED.to_le_bytes());
        self.put(IOV + 8, &room.to_le_bytes());
        let mut header = Vec::new();
        for v in [NAME, 52, IOV, 1, 0, 0, 0] {
            header.extend_from_slice(&v.to_le_bytes());
        }
        self.put(HEADER, &header);
        let n = self.call(RECVMSG, [fd as u64, HEADER, flags | MSG_DONTWAIT, 0, 0, 0]);
        if n < 0 {
            self.say(format!("{label}: recv={n}"));
            return;
        }
        let got = (n as u64).min(room) as usize;
        let bytes = self.get(RECEIVED, got);
        let sum = bytes
            .iter()
            .fold(0u32, |sum, &b| sum.wrapping_mul(31).wrapping_add(b.into()));
        let msg_flags = self.word(HEADER + 48);
        let namelen = self.word(HEADER + 8);
        let name = self.get(NAME, 52);
        let half = |i: usize| u16::from_le_bytes([name[i], name[i + 1]]);
        let net = u32::from_le_bytes(name[4..8].try_into().unwrap());
        let mut line = format!(
            "{label}: recv={n} flags={} namelen={namelen} family={} pad={} net={net} eid={} \
             type={:#x} owned={} high={} pad={}",
            hex(msg_flags),
            half(0),
            half(2),
            name[8],
            name[9],
            (name[10] & 8 != 0) as i32,
            name[10] >> 4,
            name[11]
        );
        if namelen == 52 {
            let ifindex = i32::from_le_bytes(name[12..16].try_into().unwrap());
            line.push_str(&format!(" ifindex={ifindex} halen={}", name[16]));
        }
        let shown = String::from_utf8_lossy(&bytes[..got.min(16)]).into_owned();
        line.push_str(&format!(" bytes='{shown}' sum={sum}"));
        self.say(line);
    }

    /// The guest's `nl_quiet`: sends a NETLINK_ROUTE request of `type`
    /// with `body`, asking for an ack, and gives its error.
    fn netlink(&mut self, ctl: i64, kind: u16, flags: u16, body: &[u8]) -> i32 {
        self.seq += 1;
        let mut b = Vec::new();
        b.extend_from_slice(&(16 + body.len() as u32).to_le_bytes());
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&(1 | 4 | flags).to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(body);
        self.put(REQUEST, &b);
        self.put(NAME, &[16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let sent = self.call(SENDTO, [ctl as u64, REQUEST, b.len() as u64, 0, NAME, 12]);
        assert_eq!(sent, b.len() as i64);
        let n = self.call(RECVFROM, [ctl as u64, ANSWER, 4096, 0, 0, 0]);
        if n < 0 {
            return n as i32;
        }
        let answer = self.get(ANSWER, n as usize);
        if n >= 20 && u16::from_le_bytes([answer[4], answer[5]]) == 2 {
            i32::from_le_bytes(answer[16..20].try_into().unwrap())
        } else {
            1
        }
    }

    /// The guest's `mctp_address`: gives lo the endpoint ID `eid`.
    fn mctp_address(&mut self, ctl: i64, eid: u8) {
        let mut body = vec![45, 0, 0, 0];
        body.extend_from_slice(&1u32.to_le_bytes());
        put_attribute(&mut body, 2, &[eid]);
        let error = self.netlink(ctl, 20, 0, &body);
        self.say(format!("address {eid}: error={error}"));
    }

    /// The guest's `nl_mctp_route` for a unicast route of `extent` from
    /// `dst` through the gateway `gw` of net 1, with an MTU when `mtu`.
    fn mctp_route(&mut self, ctl: i64, extent: u8, dst: u8, gw: u8, mtu: u32, label: &str) {
        let mut body = vec![45, extent, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        put_attribute(&mut body, 1, &[dst]);
        let mut gateway = 1u32.to_le_bytes().to_vec();
        gateway.extend_from_slice(&[gw, 0, 0, 0]);
        put_attribute(&mut body, 5, &gateway);
        if mtu != 0 {
            let mut metrics = vec![8, 0, 2, 0];
            metrics.extend_from_slice(&mtu.to_le_bytes());
            put_attribute(&mut body, 8 | 0x8000, &metrics);
        }
        let error = self.netlink(ctl, 24, 0, &body);
        self.say(format!("{label}: error={error}"));
    }

    /// An ioctl on the `struct mctp_tag_ctl` (4 bytes) or `mctp_tag_ctl2`
    /// (12 bytes) `request`: its result and what it gives back.
    fn tag_ioctl(&mut self, fd: i64, number: u64, request: &[u8]) -> (i64, Vec<u8>) {
        self.put(VALUE, request);
        let r = self.call(IOCTL, [fd as u64, number, VALUE, 0, 0, 0]);
        (r, self.get(VALUE, request.len()))
    }
}

/// A netlink attribute, padded to 4 bytes.
fn put_attribute(body: &mut Vec<u8>, kind: u16, value: &[u8]) {
    body.extend_from_slice(&(4 + value.len() as u16).to_le_bytes());
    body.extend_from_slice(&kind.to_le_bytes());
    body.extend_from_slice(value);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
}

/// C's `%#x`.
fn hex(value: u32) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

/// A `struct mctp_tag_ctl`.
fn tag_ctl(peer: u8, tag: u8, flags: u16) -> Vec<u8> {
    let mut b = vec![peer, tag];
    b.extend_from_slice(&flags.to_le_bytes());
    b
}

/// A `struct mctp_tag_ctl2`.
fn tag_ctl2(net: u32, peer: u8, local: u8) -> Vec<u8> {
    let mut b = net.to_le_bytes().to_vec();
    b.extend_from_slice(&[peer, local, 0, 0, 0, 0, 0, 0]);
    b
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

/// mctp-sockets: AF_MCTP datagram sockets bind to a message type, an ID
/// and a network, and messages reach them through the IDs' local routes,
/// a gateway's route in packets of its MTU, or out of lo by its hardware
/// address. A tag the sender owns has a key, which the answer to it finds;
/// SIOCMCTPALLOCTAG keeps one.
#[test]
fn mctp_sockets_bind_route_tag_and_keep_tags() {
    let mut e = Env::new();
    let r = e.call(UNSHARE, [0x4000_0000, 0, 0, 0, 0, 0]);
    e.say(format!("unshare={r}"));
    let r = e.socket(SOCK_STREAM, 0);
    e.say(format!("stream={r}"));
    let r = e.socket(SOCK_STREAM, 1);
    e.say(format!("stream protocol 1={r}"));
    let r = e.socket(SOCK_DGRAM, 1);
    e.say(format!("dgram protocol 1={r}"));
    let r = e.call(SOCKETPAIR, [AF_MCTP, SOCK_DGRAM, 0, VALUE, 0, 0]);
    e.say(format!("socketpair={r}"));
    let a = e.socket(SOCK_DGRAM, 0);
    let b = e.socket(SOCK_DGRAM, 0);
    let c = e.socket(SOCK_DGRAM, 0);
    let d = e.socket(SOCK_DGRAM | SOCK_NONBLOCK, 0);
    let s5 = e.socket(SOCK_DGRAM, 0);
    let all = [a, b, c, d, s5].iter().all(|&fd| fd >= 0);
    e.say(format!("sockets={}", all as i32));
    e.put(LEN, &12u32.to_le_bytes());
    let r = e.call(GETSOCKNAME, [a as u64, NAME, LEN, 0, 0, 0]);
    e.say(format!("getsockname={r}"));
    let r = e.call(GETPEERNAME, [a as u64, NAME, LEN, 0, 0, 0]);
    e.say(format!("getpeername={r}"));
    let r = e.call(LISTEN, [a as u64, 1, 0, 0, 0, 0]);
    e.say(format!("listen={r}"));
    let r = e.call(ACCEPT, [a as u64, 0, 0, 0, 0, 0]);
    e.say(format!("accept={r}"));
    let r = e.call(SHUTDOWN, [a as u64, 0, 0, 0, 0, 0]);
    e.say(format!("shutdown={r}"));
    let (r1, v1, _) = e.getsockopt(a, SOL_SOCKET, 3, 4);
    let (r2, v2, _) = e.getsockopt(a, SOL_SOCKET, 39, 4);
    let (r3, v3, _) = e.getsockopt(a, SOL_SOCKET, 38, 4);
    e.say(format!(
        "type={r1} {v1} domain={r2} {v2} protocol={r3} {v3}"
    ));
    let r = e.call(IOCTL, [a as u64, 0x541b, VALUE, 0, 0, 0]);
    e.say(format!("fionread={r}"));
    let r = e.call(IOCTL, [a as u64, 0x89e5, VALUE, 0, 0, 0]);
    e.say(format!("ioctl other={r}"));
    // Sends that go nowhere: no address, or none to reach.
    e.put(SENT, b"x");
    let r = e.call(SENDTO, [c as u64, SENT, 1, 0, 0, 0]);
    e.say(format!("send no address={r}"));
    let r = e.call(WRITE, [c as u64, SENT, 1, 0, 0, 0]);
    e.say(format!("write={r}"));
    let name = mctp_name(0, 9, 1, 8);
    e.send(c, &name, 12, 5, "unreachable");
    e.send(c, &name, 8, 5, "short name");
    let mut bad = name.clone();
    bad[0] = 2;
    e.send(c, &bad, 12, 5, "family");
    let mut bad = name.clone();
    bad[11] = 1;
    e.send(c, &bad, 12, 5, "padding");
    let mut bad = name.clone();
    bad[10] = 0x20;
    e.send(c, &bad, 12, 5, "tag bits");
    bad[10] = 0x10;
    e.send(c, &bad, 12, 5, "prealloc unowned");
    let ctl = e.call(SOCKET, [16, SOCK_RAW, 0, 0, 0, 0]);
    e.address(BIND, ctl, &[16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 12);
    e.mctp_address(ctl, 8);
    e.mctp_address(ctl, 9);
    // IDs 30 to 60 through 9, whose tags no other part takes.
    e.mctp_route(ctl, 30, 30, 9, 0, "route 30-60 by 9");
    // Binds.
    let name = mctp_name(0, 0xff, 1, 0);
    let r = e.address(BIND, a, &name, 8);
    e.say(format!("bind short={r}"));
    let mut bad = name.clone();
    bad[0] = 2;
    let r = e.address(BIND, a, &bad, 12);
    e.say(format!("bind family={r}"));
    let mut bad = name.clone();
    bad[2] = 1;
    let r = e.address(BIND, a, &bad, 12);
    e.say(format!("bind padding={r}"));
    let r = e.address(BIND, a, &name, 12);
    e.say(format!("bind any={r}"));
    let r = e.address(BIND, a, &name, 12);
    e.say(format!("bind again={r}"));
    let r = e.address(BIND, b, &mctp_name(1, 9, 1, 0), 12);
    e.say(format!("bind 9={r}"));
    let r = e.address(BIND, d, &mctp_name(0, 9, 0x81, 0), 12);
    e.say(format!("bind 9 taken={r}"));
    let name = mctp_name(0, 8, 2, 0);
    let r = e.address(CONNECT, d, &name, 11);
    e.say(format!("connect short={r}"));
    let mut bad = name.clone();
    bad[10] = 1;
    let r = e.address(CONNECT, d, &bad, 12);
    e.say(format!("connect tag={r}"));
    let mut bad = name.clone();
    bad[9] = 0x82;
    let r = e.address(CONNECT, d, &bad, 12);
    e.say(format!("connect ic={r}"));
    let r = e.address(CONNECT, d, &name, 12);
    e.say(format!("connect={r}"));
    let r = e.address(CONNECT, d, &name, 12);
    e.say(format!("connect again={r}"));
    let r = e.address(BIND, d, &mctp_name(0, 0xff, 3, 0), 12);
    e.say(format!("bind other type={r}"));
    let r = e.address(BIND, d, &mctp_name(0, 0xff, 2, 0), 12);
    e.say(format!("bind connected={r}"));
    // MCTP_OPT_ADDR_EXT.
    let (r, value, len) = e.getsockopt(c, SOL_MCTP, 1, 4);
    e.say(format!("ext get={r} {value} {len}"));
    let (r, _, _) = e.getsockopt(c, SOL_MCTP, 1, 8);
    e.say(format!("ext get long={r}"));
    let r = e.setsockopt(c, SOL_MCTP, 1, 1, 2);
    e.say(format!("ext set short={r}"));
    let r = e.setsockopt(c, 0, 1, 1, 4);
    e.say(format!("ext set other level={r}"));
    let r = e.setsockopt(c, SOL_MCTP, 2, 1, 4);
    e.say(format!("set other option={r}"));
    // Messages, each to the bind of its type and ID, else of any.
    e.send(c, &mctp_name(0, 9, 1, 8), 12, 5, "to 9");
    e.receive(b, 0, 100, "9 got");
    e.receive(a, 0, 100, "any got");
    e.send(c, &mctp_name(1, 8, 1, 8), 12, 3, "to 8");
    e.receive(a, 0, 100, "any got");
    let mut name = mctp_name(0, 9, 2, 8);
    e.send(c, &name, 12, 4, "type 2");
    e.receive(d, 0, 100, "connected got");
    name[9] = 3;
    e.send(c, &name, 12, 4, "type 3");
    name[9] = 0x81;
    e.send(c, &name, 12, 6, "integrity check");
    e.receive(b, MSG_PEEK, 100, "9 peeked");
    e.receive(b, MSG_OOB, 100, "9 oob");
    e.receive(b, 0, 2, "9 short");
    e.receive(b, 0, 100, "9 empty");
    name[9] = 1;
    e.send(c, &name, 12, 7, "to 9 again");
    e.receive(b, MSG_TRUNC, 2, "9 truncated");
    // The answer to an owned tag finds its key, once.
    let name = mctp_name(0, 8, 1, 0);
    e.send(b, &name, 12, 5, "answer");
    e.receive(c, 0, 100, "answer got");
    e.send(b, &name, 12, 5, "answer again");
    e.send(c, &mctp_name(0, 9, 1, 0), 12, 5, "unowned");
    // A full receive buffer.
    let r = e.setsockopt(s5, SOL_SOCKET, 8, 1, 4);
    e.say(format!("rcvbuf={r}"));
    let mut name = mctp_name(0, 8, 5, 0);
    let r = e.address(BIND, s5, &name, 12);
    e.say(format!("bind 8 type 5={r}"));
    name[10] = 8;
    for _ in 0..5 {
        e.send(c, &name, 12, 1, "to full");
    }
    for _ in 0..4 {
        e.receive(s5, 0, 100, "full got");
    }
    // Through a gateway's route of MTU 68, in packets; the longest message
    // lo's MTU takes; one longer; one too long to make.
    e.mctp_route(ctl, 0, 20, 9, 68, "route 20 by 9");
    e.send(c, &mctp_name(0, 20, 1, 8), 12, 200, "through 9");
    e.receive(a, 0, 1000, "any got");
    let name = mctp_name(0, 31, 1, 8);
    e.send(c, &name, 12, 65535, "longest");
    e.receive(a, 0, 70000, "any got");
    e.send(c, &name, 12, 65536, "longer");
    e.receive(a, 0, 70000, "any got");
    e.send(c, &name, 12, 5 << 20, "too long");
    // Out of lo by its hardware address, which loses it: while it is down,
    // its noop qdisc drops it, and while it is up, it comes back as an
    // 802.2 frame.
    let r = e.setsockopt(c, SOL_MCTP, 1, 1, 4);
    e.say(format!("ext set={r}"));
    e.setsockopt(a, SOL_MCTP, 1, 1, 4);
    let (r, value, _) = e.getsockopt(c, SOL_MCTP, 1, 4);
    e.say(format!("ext get={r} {value}"));
    e.send(c, &mctp_ext(32, 1, 6, 0), 52, 5, "ext down");
    e.receive(a, 0, 100, "any got");
    e.send(c, &mctp_ext(32, 2, 6, 0), 52, 5, "ext index 2");
    e.send(c, &mctp_ext(32, 1, 5, 0), 52, 5, "ext halen 5");
    e.send(c, &mctp_ext(32, 1, 33, 0), 52, 5, "ext halen 33");
    e.send(c, &mctp_ext(32, 1, 6, 1), 52, 5, "ext padding");
    let mut link = vec![0, 0, 0, 0];
    link.extend_from_slice(&1i32.to_le_bytes());
    link.extend_from_slice(&1u32.to_le_bytes());
    link.extend_from_slice(&1u32.to_le_bytes());
    let up = e.netlink(ctl, 16, 0, &link);
    e.say(format!("up={up}"));
    e.send(c, &mctp_ext(32, 1, 6, 0), 52, 5, "ext up");
    e.receive(a, 0, 100, "any got");
    e.send(c, &mctp_name(0, 33, 1, 8), 12, 5, "routed");
    e.receive(a, 0, 100, "any got");
    e.send(c, &mctp_ext(70, 1, 6, 0), 52, 5, "ext nowhere");
    // Tags made by hand.
    let (r, tag) = e.tag_ioctl(c, 0x89e0, &tag_ctl(8, 0, 0));
    let tag = tag[1];
    e.say(format!("alloc={r} flags={}", hex(u32::from(tag & !7))));
    let (r, _) = e.tag_ioctl(c, 0x89e0, &tag_ctl(8, 1, 0));
    e.say(format!("alloc tagged={r}"));
    let (r, _) = e.tag_ioctl(c, 0x89e0, &tag_ctl(8, 0, 1));
    e.say(format!("alloc flags={r}"));
    let (r, _) = e.tag_ioctl(c, 0x89e2, &tag_ctl2(1, 8, 5));
    e.say(format!("alloc2 local={r}"));
    let (r, v2) = e.tag_ioctl(c, 0x89e2, &tag_ctl2(1, 8, 0));
    let net = u32::from_le_bytes(v2[0..4].try_into().unwrap());
    e.say(format!(
        "alloc2={r} flags={} net={net}",
        hex(u32::from(v2[8] & !7))
    ));
    let mut name = mctp_name(0, 8, 5, tag);
    e.send(c, &name, 12, 3, "preallocated");
    e.receive(s5, 0, 100, "8 got");
    name[10] = tag & 7;
    e.send(s5, &name, 12, 3, "answer");
    e.receive(c, 0, 100, "answer got");
    e.send(s5, &name, 12, 3, "answer again");
    e.receive(c, 0, 100, "answer got");
    name[10] = 0x1f;
    e.send(c, &name, 12, 3, "not preallocated");
    let (r, _) = e.tag_ioctl(c, 0x89e1, &tag_ctl(8, tag, 0));
    e.say(format!("drop={r}"));
    let (r, _) = e.tag_ioctl(c, 0x89e1, &tag_ctl(8, tag, 0));
    e.say(format!("drop again={r}"));
    let (r, _) = e.tag_ioctl(c, 0x89e1, &tag_ctl(8, 0x10, 0));
    e.say(format!("drop unowned={r}"));
    let (r, _) = e.tag_ioctl(c, 0x89e3, &v2);
    e.say(format!("drop2={r}"));
    // A tag of MCTP_NET_ANY is that network's, which no message is in: a
    // send with it finds none, and only net 0 drops it.
    let (r, mut any_net) = e.tag_ioctl(c, 0x89e2, &tag_ctl2(0, 8, 0));
    e.say(format!(
        "alloc2 net 0={r} flags={}",
        hex(u32::from(any_net[8] & !7))
    ));
    e.send(
        c,
        &mctp_name(0, 8, 5, any_net[8]),
        12,
        3,
        "net 0 preallocated",
    );
    any_net[0] = 1;
    let (r, _) = e.tag_ioctl(c, 0x89e3, &any_net);
    e.say(format!("drop2 net 1={r}"));
    any_net[0] = 0;
    let (r, _) = e.tag_ioctl(c, 0x89e3, &any_net);
    e.say(format!("drop2 net 0={r}"));
    // Closed, its bind goes, and any's takes what it took.
    e.close(b);
    e.send(c, &mctp_name(0, 9, 1, 8), 12, 2, "after close");
    e.receive(a, 0, 100, "any got");
    // Owned tags for a peer no other part sends to run out after eight, in
    // a burst.
    let name = mctp_name(0, 40, 1, 8);
    for _ in 0..9 {
        e.send(c, &name, 12, 1, "owned");
    }
    for _ in 0..9 {
        e.receive(a, 0, 100, "any got");
    }
    // A close drops its keys. A new socket then sends out of lo to
    // MCTP_ADDR_NULL, which is lost as well.
    e.close(c);
    let f = e.socket(SOCK_DGRAM, 0);
    e.setsockopt(f, SOL_MCTP, 1, 1, 4);
    e.send(f, &mctp_ext(0, 1, 6, 0), 52, 5, "ext null");
    e.receive(a, 0, 100, "any got");
    check(
        &e.lines,
        &[
            "unshare=0",
            "stream=-94",
            "stream protocol 1=-93",
            "dgram protocol 1=-93",
            "socketpair=-95",
            "sockets=1",
            "getsockname=-95",
            "getpeername=-95",
            "listen=-95",
            "accept=-95",
            "shutdown=-95",
            "type=0 2 domain=0 45 protocol=0 0",
            "fionread=-22",
            "ioctl other=-22",
            "send no address=-89",
            "write=-89",
            "unreachable: send=-113",
            "short name: send=-22",
            "family: send=-22",
            "padding: send=-22",
            "tag bits: send=-22",
            "prealloc unowned: send=-22",
            "address 8: error=0",
            "address 9: error=0",
            "route 30-60 by 9: error=0",
            "bind short=-22",
            "bind family=-97",
            "bind padding=-22",
            "bind any=0",
            "bind again=-98",
            "bind 9=0",
            "bind 9 taken=-98",
            "connect short=-22",
            "connect tag=-22",
            "connect ic=-22",
            "connect=0",
            "connect again=-98",
            "bind other type=-22",
            "bind connected=0",
            "ext get=0 0 4",
            "ext get long=-22",
            "ext set short=-22",
            "ext set other level=-22",
            "set other option=-92",
            "to 9: send=5",
            "9 got: recv=5 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 bytes='abcde' sum=92599395",
            "any got: recv=-11",
            "to 8: send=3",
            "any got: recv=3 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 bytes='abc' sum=96354",
            "type 2: send=4",
            "connected got: recv=4 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x2 owned=1 high=0 pad=0 bytes='abcd' sum=2987074",
            "type 3: send=-2",
            "integrity check: send=6",
            "9 peeked: recv=6 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x81 owned=1 high=0 pad=0 bytes='abcdef' sum=2870581347",
            "9 oob: recv=-95",
            "9 short: recv=2 flags=0x20 namelen=12 family=45 pad=0 net=1 eid=8 type=0x81 owned=1 high=0 pad=0 bytes='ab' sum=3105",
            "9 empty: recv=-11",
            "to 9 again: send=7",
            "9 truncated: recv=7 flags=0x20 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 bytes='ab' sum=3105",
            "answer: send=5",
            "answer got: recv=5 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=0 high=0 pad=0 bytes='abcde' sum=92599395",
            "answer again: send=-2",
            "unowned: send=-2",
            "rcvbuf=0",
            "bind 8 type 5=0",
            "to full: send=1",
            "to full: send=1",
            "to full: send=1",
            "to full: send=-12",
            "to full: send=-12",
            "full got: recv=1 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x5 owned=1 high=0 pad=0 bytes='a' sum=97",
            "full got: recv=1 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x5 owned=1 high=0 pad=0 bytes='a' sum=97",
            "full got: recv=1 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x5 owned=1 high=0 pad=0 bytes='a' sum=97",
            "full got: recv=-11",
            "route 20 by 9: error=0",
            "through 9: send=200",
            "any got: recv=200 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 bytes='abcdefghijklmnop' sum=569114852",
            "longest: send=65535",
            "any got: recv=65535 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 bytes='abcdefghijklmnop' sum=583398256",
            "longer: send=-22",
            "any got: recv=-11",
            "too long: send=-105",
            "ext set=0",
            "ext get=0 1",
            "ext down: send=5",
            "any got: recv=-11",
            "ext index 2: send=-2",
            "ext halen 5: send=-22",
            "ext halen 33: send=-22",
            "ext padding: send=-22",
            "up=0",
            "ext up: send=5",
            "any got: recv=-11",
            "routed: send=5",
            "any got: recv=5 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='abcde' sum=92599395",
            "ext nowhere: send=5",
            "alloc=0 flags=0x18",
            "alloc tagged=-22",
            "alloc flags=-22",
            "alloc2 local=-22",
            "alloc2=0 flags=0x18 net=1",
            "preallocated: send=3",
            "8 got: recv=3 flags=0 namelen=12 family=45 pad=0 net=1 eid=8 type=0x5 owned=1 high=0 pad=0 bytes='abc' sum=96354",
            "answer: send=3",
            "answer got: recv=3 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x5 owned=0 high=0 pad=0 ifindex=0 halen=0 bytes='abc' sum=96354",
            "answer again: send=3",
            "answer got: recv=3 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x5 owned=0 high=0 pad=0 ifindex=0 halen=0 bytes='abc' sum=96354",
            "not preallocated: send=-2",
            "drop=0",
            "drop again=-22",
            "drop unowned=-22",
            "drop2=0",
            "alloc2 net 0=0 flags=0x18",
            "net 0 preallocated: send=-2",
            "drop2 net 1=-22",
            "drop2 net 0=0",
            "after close: send=2",
            "any got: recv=2 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='ab' sum=3105",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=1",
            "owned: send=-16",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=1 flags=0 namelen=52 family=45 pad=0 net=1 eid=8 type=0x1 owned=1 high=0 pad=0 ifindex=0 halen=0 bytes='a' sum=97",
            "any got: recv=-11",
            "ext null: send=5",
            "any got: recv=-11",
        ],
    );
}
