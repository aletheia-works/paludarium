//! What a netlink request's extended acknowledgement carries
//! (`netlink/extack.rs`) through the system call interface: the message,
//! the offset of the attribute at fault and its policy, as
//! `NLMSGERR_ATTR_POLICY` gives it for a string, a `u16`, a `u32` and an
//! `s32`, in the `NLMSG_ERROR` of a request and the `NLMSG_DONE` of a dump.
//! The calls are those of the ext-ack-netlink-strict case of
//! `tests/guests/processes/process.c` (netlink-strict with
//! `NETLINK_EXT_ACK` on): its setup, a strict `NETLINK_ROUTE` socket in a
//! network namespace of its own with lo up, and then its attribute-policy
//! requests, made in the same order, whose answers `answer` and `quiet`
//! read as its `nl_answer` and `nl_quiet` do and `show` prints as its
//! `nl_ext_show` does. The expected lines are what that case printed on
//! native x86-64 Linux in the differential tests (the CI run of main at
//! b1641852), which compare the whole case with Linux on every run: its
//! first two lines and those of the policy section, from its link dump
//! with a long name to its route with a short gateway.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x600000;
/// A `struct sockaddr_nl` and its length, and an option's value with its
/// length.
const NAME: u64 = DATA;
const NAME_LEN: u64 = DATA + 0x20;
const VALUE: u64 = DATA + 0x40;
const VALUE_LEN: u64 = DATA + 0x60;
/// A `struct msghdr` and its `struct iovec`.
const MSG: u64 = DATA + 0x80;
const IOV: u64 = DATA + 0xc0;
/// A request, and what a receive reads.
const REQUEST: u64 = DATA + 0x100;
const BUFFER: u64 = DATA + 0x1000;
/// `nl_answer`'s buffer, and `nl_quiet`'s.
const ANSWER_LEN: u64 = 16384;
const QUIET_LEN: u64 = 4096;
const SIZE: u64 = 0x10000;

const SOCKET: u64 = 41;
const SENDTO: u64 = 44;
const RECVFROM: u64 = 45;
const RECVMSG: u64 = 47;
const BIND: u64 = 49;
const GETSOCKNAME: u64 = 51;
const SETSOCKOPT: u64 = 54;
const GETSOCKOPT: u64 = 55;
const GETPID: u64 = 39;
const UNSHARE: u64 = 272;

const AF_NETLINK: u16 = 16;
const SOCK_RAW: u64 = 3;
const NETLINK_ROUTE: u64 = 0;
const CLONE_NEWNET: u64 = 0x4000_0000;
const SOL_SOCKET: u64 = 1;
const SO_DOMAIN: u64 = 39;
const SOL_NETLINK: u64 = 270;
const NETLINK_EXT_ACK: u64 = 11;
const NETLINK_GET_STRICT_CHK: u64 = 12;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE_EXCL: u16 = 0x600;
const IFF_UP: u32 = 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// What the case printed on native Linux.
const EXPECTED: &str = r#"unshare=0
strict: up=0 set=0 got=1
  ext done error=-34: msg="Attribute failed policy validation" offs=32 policy{ 7=15 1=11 }
policy link dump long name: type=3 flags=0x202 seq=1 port=1 len=88 done=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 4=0 5=4294967295 1=4 }
policy get short mtu: type=2 flags=0x200 seq=1 port=1 len=144 error=-34 echo=124
policy get long alt name: type=2 flags=0 seq=1 port=1 len=76 error=-19 echo=56
  ext done error=-34: msg="Attribute failed policy validation" offs=24 policy{ 4=0 5=4294967295 1=4 }
policy addr0 short flags: type=3 flags=0x202 seq=1 port=1 len=104 done=-34
  ext done error=-22: msg="ipv4: Unsupported attribute in dump request"
policy addr0 4-byte address: type=3 flags=0x202 seq=1 port=1 len=68 done=-22
  ext done error=-34: msg="Attribute failed policy validation" offs=28 policy{ 4=0 5=4294967295 1=4 }
policy route0 short priority: type=3 flags=0x202 seq=1 port=1 len=104 done=-34
  ext done error=-34: msg="Attribute failed policy validation" offs=24 policy{ 4=0 5=4294967295 1=4 }
policy addr2 short flags: type=3 flags=0x202 seq=1 port=1 len=104 done=-34
  ext done error=-22: msg="ipv4: Unsupported attribute in dump request"
policy addr2 4-byte address: type=3 flags=0x202 seq=1 port=1 len=68 done=-22
  ext done error=-34: msg="Attribute failed policy validation" offs=28 policy{ 4=0 5=4294967295 1=4 }
policy route2 short priority: type=3 flags=0x202 seq=1 port=1 len=104 done=-34
  ext done error=-34: msg="Attribute failed policy validation" offs=24
policy addr10 short flags: type=3 flags=0x202 seq=1 port=1 len=68 done=-34
  ext done error=-34: msg="Attribute failed policy validation" offs=24
policy addr10 4-byte address: type=3 flags=0x202 seq=1 port=1 len=68 done=-34
  ext done error=-34: msg="Attribute failed policy validation" offs=28 policy{ 4=0 5=4294967295 1=4 }
policy route10 short priority: type=3 flags=0x202 seq=1 port=1 len=104 done=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=28 policy{ 4=0 5=4294967295 1=4 }
policy get4 short table: type=2 flags=0x200 seq=1 port=1 len=140 error=-34 echo=120
  ext error error=-22: msg="Unsupported attribute" offs=28
policy get4 flow label: type=2 flags=0x200 seq=1 port=1 len=92 error=-22 echo=72
  ext error error=-22: msg="invalid attribute length" offs=28
policy get6 short flow label: type=2 flags=0x200 seq=1 port=1 len=96 error=-22 echo=76
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 4=0 5=4294967295 1=4 }
policy set short mtu: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 4=0 5=4294967295 1=4 }
policy new short mtu: error=-34
  ext error error=-22: msg="Attribute failed policy validation" offs=32
policy set perm address: error=-22
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 7=15 1=11 }
policy set long name: error=-34
policy set unknown type: error=0
  ext error error=-22: msg="Unsupported attribute" offs=32
policy set dpll pin: error=-22
  ext error error=-22: msg="multiple netns identifying attributes specified"
policy set pid and fd: error=-22
policy new empty kind: error=-34
policy addr6 long label: error=0
policy del addr6 long label: error=0
  ext error error=-34: msg="Attribute failed policy validation" offs=44
policy addr6 short flags: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32
policy addr4 short cacheinfo: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 4=0 5=4294967295 1=4 }
policy addr4 short priority: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 7=15 1=11 }
policy addr4 long label: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=32 policy{ 2=-2147483648 3=2147483647 1=8 }
policy del addr4 short netnsid: error=-34
  ext error error=-22: msg="Unsupported attribute" offs=36
policy route4 flow label: error=-22
  ext error error=-34: msg="Attribute failed policy validation" offs=36 policy{ 4=0 5=65535 1=3 }
policy route4 short encap type: error=-34
  ext error error=-22: msg="invalid attribute length" offs=36 policy{ 4=0 5=4294967295 1=4 }
policy route4 long nexthop: error=-22
  ext error error=-34: msg="Attribute failed policy validation" offs=48 policy{ 4=0 5=4294967295 1=4 }
policy route6 short expires: error=-34
  ext error error=-34: msg="Attribute failed policy validation" offs=48
policy route6 short gateway: error=-34
"#;

/// The guest's `struct nl_body`: a fixed header, then the attributes
/// `put` adds, each padded.
#[derive(Clone)]
struct Body(Vec<u8>);

impl Body {
    /// `nl_body`: `len` bytes, the first of them `family`.
    fn new(family: u8, len: usize) -> Self {
        let mut bytes = vec![0; len];
        bytes[0] = family;
        Self(bytes)
    }
    /// A link's `struct ifinfomsg`, of index 1 with `flags` and `change`.
    fn link(flags: u32, change: u32) -> Self {
        let mut b = Self::new(0, 16);
        b.0[4..8].copy_from_slice(&1i32.to_le_bytes());
        b.0[8..12].copy_from_slice(&flags.to_le_bytes());
        b.0[12..16].copy_from_slice(&change.to_le_bytes());
        b
    }
    /// `nl_put`.
    fn put(&mut self, kind: u16, value: &[u8]) {
        let len = 4 + value.len();
        self.0.extend_from_slice(&(len as u16).to_le_bytes());
        self.0.extend_from_slice(&kind.to_le_bytes());
        self.0.extend_from_slice(value);
        self.0
            .resize(self.0.len() + (len.next_multiple_of(4) - len), 0);
    }
    /// `nl_put32`.
    fn put32(&mut self, kind: u16, value: u32) {
        self.put(kind, &value.to_le_bytes());
    }
    /// `nl_put` on a copy, as `nl_policy` takes its body by value.
    fn with(&self, kind: u16, value: &[u8]) -> Self {
        let mut b = self.clone();
        b.put(kind, value);
        b
    }
}

struct Env {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    /// The guest's `nl_seq`.
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
            seq: 100,
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

    /// A `struct sockaddr_nl` of `pid` at `NAME`.
    fn name(&self, pid: u32) {
        let mut name = [0u8; 12];
        name[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
        name[4..8].copy_from_slice(&pid.to_le_bytes());
        self.put(NAME, &name);
    }

    /// `nl_ext_socket`: a netlink socket, with `NETLINK_EXT_ACK` on.
    fn socket(&mut self) -> u64 {
        let fd = self.call(
            SOCKET,
            [u64::from(AF_NETLINK), SOCK_RAW, NETLINK_ROUTE, 0, 0, 0],
        );
        assert!(fd >= 0, "socket: {fd}");
        self.option(fd as u64, NETLINK_EXT_ACK);
        fd as u64
    }

    /// `setsockopt` of `SOL_NETLINK` option `name` to 1: 0 or `-errno`.
    fn option(&mut self, fd: u64, name: u64) -> i64 {
        self.put(VALUE, &1i32.to_le_bytes());
        self.call(SETSOCKOPT, [fd, SOL_NETLINK, name, VALUE, 4, 0])
    }

    /// `nl_ext_netlink`: whether `fd` is a netlink socket, by `SO_DOMAIN`.
    fn netlink(&mut self, fd: u64) -> bool {
        self.put(VALUE, &0i32.to_le_bytes());
        self.put(VALUE_LEN, &4u32.to_le_bytes());
        let r = self.call(GETSOCKOPT, [fd, SOL_SOCKET, SO_DOMAIN, VALUE, VALUE_LEN, 0]);
        r == 0 && self.word(VALUE) == u32::from(AF_NETLINK)
    }

    /// `nl_send`: request `kind` with `flags` and `body`; its sequence
    /// number.
    fn send(&mut self, fd: u64, kind: u16, flags: u16, body: &Body) -> u32 {
        self.seq += 1;
        let len = 16 + body.0.len();
        let mut request = Vec::with_capacity(len);
        request.extend_from_slice(&(len as u32).to_le_bytes());
        request.extend_from_slice(&kind.to_le_bytes());
        request.extend_from_slice(&flags.to_le_bytes());
        request.extend_from_slice(&self.seq.to_le_bytes());
        request.extend_from_slice(&0u32.to_le_bytes());
        request.extend_from_slice(&body.0);
        self.put(REQUEST, &request);
        self.name(0);
        let r = self.call(SENDTO, [fd, REQUEST, len as u64, 0, NAME, 12]);
        assert_eq!(r, len as i64, "sendto");
        self.seq
    }

    /// `nl_quiet`: request `kind` with an acknowledgement and `flags`;
    /// the error it gets, or 1 for none.
    fn quiet(&mut self, fd: u64, kind: u16, flags: u16, body: &Body) -> i32 {
        self.send(fd, kind, NLM_F_REQUEST | NLM_F_ACK | flags, body);
        let n = self.call(RECVFROM, [fd, BUFFER, QUIET_LEN, 0, 0, 0]);
        if n < 0 {
            return n as i32;
        }
        let bytes = self.get(BUFFER, n as usize);
        if self.netlink(fd) {
            self.show(&bytes);
        }
        if bytes.len() >= 20 && u16::from_le_bytes([bytes[4], bytes[5]]) == 2 {
            i32::from_le_bytes(bytes[16..20].try_into().unwrap())
        } else {
            1
        }
    }

    /// `nl_policy`: `body` with attribute `kind` of `value`, by `nl_quiet`.
    fn policy(&mut self, fd: u64, kind: u16, flags: u16, body: &Body, label: &str) {
        let error = self.quiet(fd, kind, flags, body);
        self.lines.push(format!("{label}: error={error}"));
    }

    /// `nl_strict`: request `kind`, a dump when `dump`, and its answer.
    fn strict(&mut self, fd: u64, port: u32, kind: u16, dump: bool, body: &Body, label: &str) {
        let flags = NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 };
        let seq = self.send(fd, kind, flags, body);
        self.answer(fd, seq, port, label);
    }

    /// `nl_answer`, for the answers of these requests: an `NLMSG_ERROR`
    /// or an `NLMSG_DONE`, one message, which ends it.
    fn answer(&mut self, fd: u64, seq: u32, port: u32, label: &str) {
        let peeked = self.call(
            RECVFROM,
            [fd, BUFFER, 1, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT, 0, 0],
        );
        if peeked < 0 {
            return;
        }
        self.put(NAME, &[0; 12]);
        let mut header = [0u8; 56];
        header[0..8].copy_from_slice(&NAME.to_le_bytes());
        header[8..12].copy_from_slice(&12u32.to_le_bytes());
        header[16..24].copy_from_slice(&IOV.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        self.put(MSG, &header);
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&BUFFER.to_le_bytes());
        iov[8..16].copy_from_slice(&ANSWER_LEN.to_le_bytes());
        self.put(IOV, &iov);
        let n = self.call(RECVMSG, [fd, MSG, MSG_DONTWAIT, 0, 0, 0]);
        if n < 0 {
            return;
        }
        let bytes = self.get(BUFFER, n as usize);
        if self.netlink(fd) {
            self.show(&bytes);
        }
        let from = self.get(NAME, 12);
        let family = u16::from_le_bytes([from[0], from[1]]);
        let pid = u32::from_le_bytes(from[4..8].try_into().unwrap());
        let name_len = self.word(MSG + 8);
        let msg_flags = self.word(MSG + 48);
        if n != peeked || family != AF_NETLINK || pid != 0 || name_len != 12 || msg_flags != 0 {
            self.lines.push(format!(
                "{label}: datagram n={n} peeked={peeked} from={pid} namelen={name_len} flags={}",
                hex(msg_flags)
            ));
        }
        // Each answer here is one message, its first.
        let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        assert!((16..=bytes.len()).contains(&len), "{label}: length {len}");
        let kind = u16::from_le_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        let mseq = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mport = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let body = &bytes[16..len];
        let mut line = format!(
            "{label}: type={kind} flags={} seq={} port={} len={len}",
            hex(u32::from(flags)),
            i32::from(mseq == seq),
            i32::from(mport == port)
        );
        let value = i32::from_le_bytes(body[0..4].try_into().unwrap());
        match kind {
            2 => line += &format!(" error={value} echo={}", body.len() - 4),
            3 => line += &format!(" done={value}"),
            _ => panic!("{label}: message {kind}"),
        }
        self.lines.push(line);
    }

    /// `nl_ext_show`: the extended attributes of each `NLMSG_ERROR` and
    /// `NLMSG_DONE` with `NLM_F_ACK_TLVS` in `bytes`.
    fn show(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 16 {
            let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
            let kind = u16::from_le_bytes([bytes[4], bytes[5]]);
            let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
            if len < 16 || len > bytes.len() {
                break;
            }
            if (kind == 2 || kind == 3) && flags & 0x200 != 0 {
                let error = i32::from_le_bytes(bytes[16..20].try_into().unwrap());
                let mut at = 20;
                if kind == 2 {
                    let mut inner = 16;
                    if flags & 0x100 == 0 && len >= 24 {
                        inner = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
                    }
                    at += if flags & 0x100 != 0 {
                        16
                    } else {
                        inner.next_multiple_of(4)
                    };
                }
                let mut line = format!(
                    "  ext {} error={error}:",
                    if kind == 2 { "error" } else { "done" }
                );
                while at + 4 <= len {
                    let alen = usize::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
                    let akind = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) & 0x3fff;
                    if alen < 4 || at + alen > len {
                        break;
                    }
                    let v = &bytes[at + 4..at + alen];
                    let word = if v.len() >= 4 {
                        u32::from_le_bytes(v[0..4].try_into().unwrap())
                    } else {
                        0
                    };
                    match akind {
                        1 => {
                            let text = &v[..v.len().saturating_sub(1)];
                            let text = text.split(|&c| c == 0).next().unwrap_or_default();
                            line += &format!(" msg=\"{}\"", String::from_utf8_lossy(text));
                        }
                        2 => line += &format!(" offs={word}"),
                        4 => line += &format!(" policy{{{} }}", policy(v)),
                        5 => line += &format!(" miss-type={word}"),
                        _ => line += &format!(" {akind}:{}", v.len()),
                    }
                    at += alen.next_multiple_of(4);
                }
                self.lines.push(line);
            }
            let step = len.next_multiple_of(4).min(bytes.len());
            bytes = &bytes[step..];
        }
    }
}

/// `nl_ext_policy`: each attribute of a policy by type, a 4-byte value
/// unsigned and an 8-byte one signed.
fn policy(mut at: &[u8]) -> String {
    let mut out = String::new();
    while at.len() >= 4 {
        let alen = usize::from(u16::from_le_bytes([at[0], at[1]]));
        let kind = u16::from_le_bytes([at[2], at[3]]) & 0x3fff;
        if alen < 4 || alen > at.len() {
            break;
        }
        let value = match alen - 4 {
            4 => i64::from(u32::from_le_bytes(at[4..8].try_into().unwrap())),
            8 => i64::from_le_bytes(at[4..12].try_into().unwrap()),
            _ => 0,
        };
        out += &format!(" {kind}={value}");
        at = &at[alen.next_multiple_of(4).min(at.len())..];
    }
    out
}

/// `%#x`, which prints 0 bare.
fn hex(value: u32) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

#[test]
fn ext_ack_reports_attribute_policies_as_linux() {
    let mut e = Env::new();
    let r = e.call(UNSHARE, [CLONE_NEWNET, 0, 0, 0, 0, 0]);
    e.lines.push(format!("unshare={r}"));
    let fd = e.socket();
    e.name(0);
    assert_eq!(e.call(BIND, [fd, NAME, 12, 0, 0, 0]), 0);
    e.put(NAME, &[0; 12]);
    e.put(NAME_LEN, &12u32.to_le_bytes());
    assert_eq!(e.call(GETSOCKNAME, [fd, NAME, NAME_LEN, 0, 0, 0]), 0);
    let port = e.word(NAME + 4);
    let set = e.option(fd, NETLINK_GET_STRICT_CHK);
    e.put(VALUE, &(-1i32).to_le_bytes());
    e.put(VALUE_LEN, &4u32.to_le_bytes());
    e.call(
        GETSOCKOPT,
        [fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, VALUE, VALUE_LEN, 0],
    );
    let got = e.word(VALUE) as i32;
    let up = e.quiet(fd, 16, 0, &Body::link(IFF_UP, IFF_UP));
    e.lines.push(format!("strict: up={up} set={set} got={got}"));

    // The attribute policies.
    let long_name = b"looooooooooooooooon\0";
    let two = [1u8, 2];
    let mut b = Body::new(0, 16);
    b.put(3, long_name);
    e.strict(fd, port, 18, true, &b, "policy link dump long name");
    let mut b = Body::link(0, 0);
    b.put(4, &two);
    e.strict(fd, port, 18, false, &b, "policy get short mtu");
    let mut b = Body::new(0, 16);
    b.put(53, long_name);
    e.strict(fd, port, 18, false, &b, "policy get long alt name");
    for family in [0, AF_INET, AF_INET6] {
        let mut b = Body::new(family, 8);
        b.put(8, &two);
        e.strict(
            fd,
            port,
            22,
            true,
            &b,
            &format!("policy addr{family} short flags"),
        );
        let mut b = Body::new(family, 8);
        b.put32(1, 0);
        e.strict(
            fd,
            port,
            22,
            true,
            &b,
            &format!("policy addr{family} 4-byte address"),
        );
        let mut b = Body::new(family, 12);
        b.put(6, &two);
        e.strict(
            fd,
            port,
            26,
            true,
            &b,
            &format!("policy route{family} short priority"),
        );
    }
    let mut b = Body::new(AF_INET, 12);
    b.put(15, &two);
    e.strict(fd, port, 26, false, &b, "policy get4 short table");
    let mut b = Body::new(AF_INET, 12);
    b.put32(31, 0);
    e.strict(fd, port, 26, false, &b, "policy get4 flow label");
    let mut b = Body::new(AF_INET6, 12);
    b.put(31, &two[..1]);
    e.strict(fd, port, 26, false, &b, "policy get6 short flow label");

    // Link changes, which check ifla_policy whatever the socket.
    let b = Body::link(IFF_UP, IFF_UP);
    e.policy(fd, 19, 0, &b.with(4, &two), "policy set short mtu");
    e.policy(fd, 16, 0, &b.with(4, &two), "policy new short mtu");
    e.policy(fd, 19, 0, &b.with(54, &[]), "policy set perm address");
    e.policy(fd, 19, 0, &b.with(3, long_name), "policy set long name");
    e.policy(
        fd,
        19,
        0,
        &b.with(200, &0u32.to_le_bytes()),
        "policy set unknown type",
    );
    e.policy(fd, 19, 0, &b.with(65, &[]), "policy set dpll pin");
    let pid = e.call(GETPID, [0; 6]) as u32;
    let mut both = b.clone();
    both.put32(19, pid);
    e.policy(
        fd,
        19,
        0,
        &both.with(28, &1u32.to_le_bytes()),
        "policy set pid and fd",
    );
    // IFLA_LINKINFO with an empty IFLA_INFO_KIND.
    let kind = [4u8, 0, 1, 0];
    e.policy(fd, 16, 0, &b.with(18, &kind), "policy new empty kind");

    // Addresses: IPv6 has no label, so a long one is taken.
    let doc6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let doc4 = [10u8, 9, 9, 9];
    let label40 = [b'a'; 40];
    let mut a6 = Body::new(AF_INET6, 8);
    a6.0[1] = 128;
    a6.0[4..8].copy_from_slice(&1u32.to_le_bytes());
    a6.put(1, &doc6);
    e.policy(
        fd,
        20,
        NLM_F_CREATE_EXCL,
        &a6.with(3, &label40),
        "policy addr6 long label",
    );
    e.policy(
        fd,
        21,
        0,
        &a6.with(3, &label40),
        "policy del addr6 long label",
    );
    e.policy(
        fd,
        20,
        NLM_F_CREATE_EXCL,
        &a6.with(8, &two),
        "policy addr6 short flags",
    );
    let mut a4 = Body::new(AF_INET, 8);
    a4.0[1] = 32;
    a4.0[4..8].copy_from_slice(&1u32.to_le_bytes());
    a4.put(2, &doc4);
    e.policy(
        fd,
        20,
        NLM_F_CREATE_EXCL,
        &a4.with(6, &two),
        "policy addr4 short cacheinfo",
    );
    e.policy(
        fd,
        20,
        NLM_F_CREATE_EXCL,
        &a4.with(9, &two),
        "policy addr4 short priority",
    );
    e.policy(
        fd,
        20,
        NLM_F_CREATE_EXCL,
        &a4.with(3, long_name),
        "policy addr4 long label",
    );
    e.policy(
        fd,
        21,
        0,
        &a4.with(10, &two),
        "policy del addr4 short netnsid",
    );

    // Routes: rtm_ipv4_policy names no flow label.
    let mut r4 = Body::new(AF_INET, 12);
    r4.0[1] = 16;
    r4.0[4] = 254;
    r4.0[5] = 3;
    r4.0[7] = 6;
    r4.put(1, &[10, 8, 0, 0]);
    let zero = 0u32.to_le_bytes();
    e.policy(
        fd,
        24,
        NLM_F_CREATE_EXCL,
        &r4.with(31, &zero),
        "policy route4 flow label",
    );
    e.policy(
        fd,
        24,
        NLM_F_CREATE_EXCL,
        &r4.with(21, &two[..1]),
        "policy route4 short encap type",
    );
    e.policy(
        fd,
        24,
        NLM_F_CREATE_EXCL,
        &r4.with(30, &[0; 5]),
        "policy route4 long nexthop",
    );
    let mut r6 = Body::new(AF_INET6, 12);
    r6.0[1] = 48;
    r6.0[4] = 254;
    r6.0[5] = 3;
    r6.0[7] = 6;
    r6.put(1, &doc6);
    e.policy(
        fd,
        24,
        NLM_F_CREATE_EXCL,
        &r6.with(23, &two),
        "policy route6 short expires",
    );
    e.policy(
        fd,
        24,
        NLM_F_CREATE_EXCL,
        &r6.with(5, &doc4),
        "policy route6 short gateway",
    );

    assert_eq!(e.lines, EXPECTED.lines().collect::<Vec<_>>());
}
