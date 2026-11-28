//! Classic BPF socket filters (`SO_ATTACH_FILTER`): [`check`] refuses
//! what Linux refuses, and [`convert`] turns the program into the eBPF
//! instructions that [`crate::bpf_interp`] runs, as Linux runs a classic
//! program after it converts it.
//!
//! What a program can see of the conversion is what Linux's gives: each
//! classic instruction converts to as many instructions as Linux's does,
//! with its jumps to other instructions in the same places, so that the
//! program has Linux's length, which the socket is charged for, and the
//! same jumps reach; and it returns what Linux's returns. The instructions
//! themselves are this file's own:
//! - packet loads are eBPF's `BPF_LD | BPF_ABS` and `BPF_IND`, and
//!   comparisons 32-bit jumps;
//! - the `sk_buff` fields are read from the context (`struct __sk_buff`)
//!   where it has them, and from the fields the interpreter keeps after it
//!   ([`crate::bpf_interp::classic`]), `dev` among them, which an AF_UNIX
//!   message has none of;
//! - the netlink attribute searches and the rest are helpers with numbers
//!   of the interpreter's own, which no eBPF program can call;
//! - a block shorter than Linux's ends with no-ops.
use paludarium_types::Errno;

use crate::bpf_interp::classic::{self as helper, field};
use crate::bpf_verifier::Insn;

/// `BPF_MAXINSNS`.
pub(crate) const MAX_INSNS: usize = 4096;
/// `BPF_MEMWORDS`.
pub(crate) const MEMWORDS: u32 = 16;
/// `SKF_AD_OFF`, where the ancillary loads start.
const AD_OFF: u32 = -0x1000i32 as u32;
/// The ancillary loads (`SKF_AD_*`), from [`AD_OFF`].
mod ad {
    pub const PROTOCOL: u32 = 0;
    pub const PKTTYPE: u32 = 4;
    pub const IFINDEX: u32 = 8;
    pub const NLATTR: u32 = 12;
    pub const NLATTR_NEST: u32 = 16;
    pub const MARK: u32 = 20;
    pub const QUEUE: u32 = 24;
    pub const HATYPE: u32 = 28;
    pub const RXHASH: u32 = 32;
    pub const CPU: u32 = 36;
    pub const ALU_XOR_X: u32 = 40;
    pub const VLAN_TAG: u32 = 44;
    pub const VLAN_TAG_PRESENT: u32 = 48;
    pub const PAY_OFFSET: u32 = 52;
    pub const RANDOM: u32 = 56;
    pub const VLAN_TPID: u32 = 60;
}

/// A classic instruction, `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SockFilter {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

impl SockFilter {
    pub(crate) fn decode(b: [u8; 8]) -> SockFilter {
        SockFilter {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// The classic codes: classes, sizes, modes and operations.
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;
const K: u16 = 0x00;
const X: u16 = 0x08;
const RET_A: u16 = 0x10;
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;

/// Which of the two classic registers an instruction uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    A,
    X,
}

/// What a classic instruction does, decoded from its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// `ld[bhw] [k]`, or `[x + k]` when `indirect`; an ancillary load when
    /// `k` is one and the load is not indirect.
    Packet { size: u16, indirect: bool },
    /// `ldxb 4 * ([k] & 0xf)`.
    HeaderLength,
    /// `ld #k` and `ldx #k`.
    Immediate(Reg),
    /// `ld M[k]` and `ldx M[k]`.
    Scratch(Reg),
    /// `ld #len` and `ldx #len`.
    Length(Reg),
    /// `st M[k]` (from A) and `stx M[k]` (from X).
    Store(Reg),
    /// An operation on A with k or, when `x`, X.
    Alu { op: u16, x: bool },
    /// `neg`.
    Neg,
    /// `ja k`.
    Always,
    /// A conditional jump on A against k or, when `x`, X.
    Conditional { op: u16, x: bool },
    /// `ret #k`, or `ret a` when `a`.
    Return { a: bool },
    /// `tax`.
    Tax,
    /// `txa`.
    Txa,
}

/// The operations on A, all with k or X but `neg`.
const ALU_OPS: [u16; 10] = [ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, LSH, RSH];
/// The conditional jumps, all with k or X.
const CONDITIONS: [u16; 4] = [JEQ, JGT, JGE, JSET];

/// The operation of a classic code, or `None` for one Linux refuses. A code
/// has a class in its low 3 bits; loads add a size (`0x18`) and a mode
/// (`0xe0`), operations and jumps a source (`0x08`) and an operation
/// (`0xf0`), and a return what it returns (`0x18`).
fn decode(code: u16) -> Option<Op> {
    let class = code & 0x07;
    let (size, mode) = (code & 0x18, code & 0xe0);
    let (x, operation) = (code & X != 0, code & 0xf0);
    if code > 0xff {
        return None;
    }
    let to = if class == LD { Reg::A } else { Reg::X };
    match class {
        LD | LDX => match (mode, size) {
            (IMM, W) => Some(Op::Immediate(to)),
            (MEM, W) => Some(Op::Scratch(to)),
            (LEN, W) => Some(Op::Length(to)),
            (ABS | IND, W | H | B) if class == LD => Some(Op::Packet {
                size,
                indirect: mode == IND,
            }),
            (MSH, B) if class == LDX => Some(Op::HeaderLength),
            _ => None,
        },
        ST if code == ST => Some(Op::Store(Reg::A)),
        STX if code == STX => Some(Op::Store(Reg::X)),
        ALU if code == ALU | NEG => Some(Op::Neg),
        ALU if ALU_OPS.contains(&operation) => Some(Op::Alu { op: operation, x }),
        JMP if code == JMP | JA => Some(Op::Always),
        JMP if CONDITIONS.contains(&operation) => Some(Op::Conditional { op: operation, x }),
        RET if code == RET | K || code == RET | RET_A => Some(Op::Return { a: code != RET | K }),
        MISC if code == MISC | TAX => Some(Op::Tax),
        MISC if code == MISC | TXA => Some(Op::Txa),
        _ => None,
    }
}

/// Whether `k` of an `ld[bhw] [k]` is one of the 16 ancillary loads, the
/// words from [`AD_OFF`] to [`ad::VLAN_TPID`].
fn ancillary(k: u32) -> bool {
    k.wrapping_sub(AD_OFF) <= ad::VLAN_TPID && k.wrapping_sub(AD_OFF).is_multiple_of(4)
}

/// Where the classic instruction `f` at `pc` goes next: the instructions
/// it jumps to, and whether it goes on to `pc + 1`. A return goes on too:
/// what Linux knows of the scratch words after it carries into the
/// instruction after it, which only a jump reaches.
fn next(pc: usize, op: Op, f: SockFilter) -> ([Option<usize>; 2], bool) {
    match op {
        Op::Always => ([Some(pc + 1 + f.k as usize), None], false),
        Op::Conditional { .. } => (
            [
                Some(pc + 1 + usize::from(f.jt)),
                Some(pc + 1 + usize::from(f.jf)),
            ],
            false,
        ),
        _ => ([None; 2], true),
    }
}

/// The checks of `SO_ATTACH_FILTER` and `SO_ATTACH_REUSEPORT_CBPF`: EINVAL
/// for no instructions or more than [`MAX_INSNS`], a code Linux does not
/// know, a division by a constant 0, a constant shift of 32 or more, a
/// scratch word past the 16th, a jump past the end, an `ld[bhw] [k]` at or
/// past [`AD_OFF`] that is no ancillary load, a last instruction that does
/// not return, and a scratch word read where some path has not written it.
pub(crate) fn check(filter: &[SockFilter]) -> Result<(), Errno> {
    let len = filter.len();
    if len == 0 || len > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    for (pc, &f) in filter.iter().enumerate() {
        let op = decode(f.code).ok_or(Errno::EINVAL)?;
        let after = len - pc - 1;
        let valid = match op {
            Op::Alu {
                op: DIV | MOD,
                x: false,
            } => f.k != 0,
            Op::Alu {
                op: LSH | RSH,
                x: false,
            } => f.k < 32,
            Op::Scratch(_) | Op::Store(_) => f.k < MEMWORDS,
            Op::Always => (f.k as usize) < after,
            Op::Conditional { .. } => usize::from(f.jt.max(f.jf)) < after,
            Op::Packet {
                indirect: false, ..
            } => f.k < AD_OFF || ancillary(f.k),
            _ => true,
        };
        if !valid {
            return Err(Errno::EINVAL);
        }
    }
    match decode(filter[len - 1].code) {
        Some(Op::Return { .. }) => loads_after_stores(filter),
        _ => Err(Errno::EINVAL),
    }
}

/// EINVAL for a scratch word read where some path to the read has not
/// written it. Classic jumps only go forward, so one walk in order sees
/// every path into an instruction before the instruction: each keeps the
/// words that every path into it has written.
fn loads_after_stores(filter: &[SockFilter]) -> Result<(), Errno> {
    let mut written = vec![u16::MAX; filter.len() + 1];
    written[0] = 0;
    for (pc, &f) in filter.iter().enumerate() {
        let op = decode(f.code).ok_or(Errno::EINVAL)?;
        let mut known = written[pc];
        match op {
            Op::Store(_) => known |= 1 << f.k,
            Op::Scratch(_) if known & 1 << f.k == 0 => return Err(Errno::EINVAL),
            _ => {}
        }
        let (targets, on) = next(pc, op, f);
        for to in targets.into_iter().flatten().chain(on.then_some(pc + 1)) {
            written[to] &= known;
        }
    }
    Ok(())
}

/// The registers of the converted program. A is R0, where packet loads and
/// helpers leave what they give; the context is R6, where a packet load
/// finds it; X is R7, and R8 keeps A while a header length is loaded,
/// both kept across calls; R1 to R3 are a helper's arguments.
mod reg {
    pub const A: u8 = 0;
    pub const ARG1: u8 = 1;
    pub const ARG2: u8 = 2;
    pub const ARG3: u8 = 3;
    pub const TMP: u8 = 2;
    pub const CTX: u8 = 6;
    pub const X: u8 = 7;
    pub const SAVED: u8 = 8;
    pub const FP: u8 = 10;
}

/// The eBPF codes the conversion writes.
mod op {
    pub const ALU32: u8 = 0x04;
    pub const ALU64: u8 = 0x07;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const X: u8 = 0x08;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const END_BE: u8 = 0xd8;
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JNE: u8 = 0x50;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    /// `BPF_LD | BPF_ABS` and `BPF_LD | BPF_IND`, the packet loads, which
    /// take the context from R6, give the bytes in host order in R0, and
    /// return 0 from the program where the packet has none.
    pub const LD_ABS: u8 = 0x20;
    pub const LD_IND: u8 = 0x40;
    /// `BPF_LDX | BPF_MEM` and `BPF_STX | BPF_MEM`, and the sizes.
    pub const LDX_MEM: u8 = 0x61;
    pub const STX_MEM: u8 = 0x63;
    pub const W: u8 = 0x00;
    pub const H: u8 = 0x08;
    pub const B: u8 = 0x10;
    pub const DW: u8 = 0x18;
}

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        dst,
        src,
        off,
        imm,
    }
}
const fn mov64_reg(dst: u8, src: u8) -> Insn {
    insn(op::ALU64 | op::MOV | op::X, dst, src, 0, 0)
}
const fn mov32_reg(dst: u8, src: u8) -> Insn {
    insn(op::ALU32 | op::MOV | op::X, dst, src, 0, 0)
}
const fn mov32_imm(dst: u8, imm: i32) -> Insn {
    insn(op::ALU32 | op::MOV, dst, 0, 0, imm)
}
const fn alu32_imm(o: u8, dst: u8, imm: i32) -> Insn {
    insn(op::ALU32 | o, dst, 0, 0, imm)
}
const fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
    insn(op::LDX_MEM | size, dst, src, off, 0)
}
/// A jump on the low 32 bits of `dst` against `imm`, which is how classic
/// programs compare.
const fn jmp32_imm(o: u8, dst: u8, imm: i32, off: i16) -> Insn {
    insn(op::JMP32 | o, dst, 0, off, imm)
}
const fn exit() -> Insn {
    insn(op::JMP | op::EXIT, 0, 0, 0, 0)
}
const fn call(id: i32) -> Insn {
    insn(op::JMP | op::CALL, 0, 0, 0, id)
}
const fn from_be(dst: u8, bits: i32) -> Insn {
    insn(op::ALU32 | op::END_BE, dst, 0, 0, bits)
}
/// A jump to the next instruction, which fills a block to its length.
const fn nop() -> Insn {
    insn(op::JMP | op::JA, 0, 0, 0, 0)
}

/// An instruction of the converted program, or a jump whose `off` goes to
/// the start of a classic instruction's block.
#[derive(Clone, Copy)]
enum Piece {
    Insn(Insn),
    Jump(Insn, usize),
}

/// The converted block of one classic instruction.
#[derive(Default)]
struct Block(Vec<Piece>);

impl Block {
    fn push(&mut self, i: Insn) {
        self.0.push(Piece::Insn(i));
    }
    fn extend(&mut self, insns: impl IntoIterator<Item = Insn>) {
        for i in insns {
            self.push(i);
        }
    }
    fn jump(&mut self, i: Insn, target: usize) {
        self.0.push(Piece::Jump(i, target));
    }
    /// No-ops after the instructions, up to `length`.
    fn pad(&mut self, length: usize) {
        debug_assert!(self.0.len() <= length, "{} > {length}", self.0.len());
        while self.0.len() < length {
            self.push(nop());
        }
    }
}

/// The classic register's register in the converted program.
const fn register(r: Reg) -> u8 {
    match r {
        Reg::A => reg::A,
        Reg::X => reg::X,
    }
}

/// How many instructions Linux converts a packet load of `size` bytes at
/// `k`, or `X + k` when `indirect`, to: 8, or 9 for an indirect one with a
/// `k`, through its helper; one at a constant offset from the start has 4
/// more, 2 more again past what an `off` holds, one more for a `k` that is
/// not 0, and one more for more than a byte.
fn packet_length(size: u16, indirect: bool, k: u32) -> usize {
    if indirect || (k as i32) < 0 {
        return 8 + usize::from(indirect && k != 0);
    }
    let far = i16::try_from(k).is_err();
    12 + usize::from(k != 0) + 2 * usize::from(far) + usize::from(size != B)
}

/// How many instructions Linux converts the ancillary load `which` (from
/// [`AD_OFF`]) to.
fn ancillary_length(which: u32) -> usize {
    match which {
        ad::PROTOCOL | ad::VLAN_TPID | ad::PKTTYPE => 2,
        ad::VLAN_TAG_PRESENT => 3,
        ad::IFINDEX | ad::HATYPE => 4,
        ad::PAY_OFFSET | ad::NLATTR | ad::NLATTR_NEST | ad::CPU | ad::RANDOM => 4,
        _ => 1,
    }
}

/// How many instructions Linux converts the classic instruction `f`,
/// which is `op`, to: the converted program's length, which the socket is
/// charged for and which decides whether a jump reaches, is theirs sum.
fn length(op: Op, f: SockFilter) -> usize {
    match op {
        Op::Packet {
            indirect: false, ..
        } if ancillary(f.k) => ancillary_length(f.k.wrapping_sub(AD_OFF)),
        Op::Packet { size, indirect } => packet_length(size, indirect, f.k),
        Op::HeaderLength => 6 + packet_length(B, false, f.k),
        Op::Alu {
            op: DIV | MOD,
            x: true,
        } => 5,
        Op::Return { a: false } => 2,
        Op::Conditional { op: o, x } => {
            let constant = usize::from(!x && (f.k as i32) < 0);
            let one = f.jf == 0 || f.jt == 0 && o != JSET;
            constant + if one { 1 } else { 2 }
        }
        _ => 1,
    }
}

/// The ancillary load `which` (from [`AD_OFF`]) into A. The protocol and
/// the VLAN protocol are in network order in the `sk_buff`; the packet
/// type is its 3 bits; the interface's index and type come from its
/// device, and without one the program returns A as it is; whether there
/// is a VLAN tag is 0 or 1; the netlink attribute searches take the
/// context, A and X, the payload offset the context, and the CPU and a
/// random number nothing.
fn ancillary_load(which: u32) -> Vec<Insn> {
    let field = |size, at| vec![ldx(size, reg::A, reg::CTX, at)];
    match which {
        ad::MARK => field(op::W, field::MARK),
        ad::QUEUE => field(op::H, field::QUEUE_MAPPING),
        ad::VLAN_TAG => field(op::H, field::VLAN_TCI),
        ad::RXHASH => field(op::W, field::HASH),
        ad::PROTOCOL | ad::VLAN_TPID => {
            let at = if which == ad::PROTOCOL {
                field::PROTOCOL
            } else {
                field::VLAN_PROTO
            };
            vec![ldx(op::H, reg::A, reg::CTX, at), from_be(reg::A, 16)]
        }
        ad::PKTTYPE => vec![
            ldx(op::B, reg::A, reg::CTX, field::PKT_TYPE),
            alu32_imm(op::AND, reg::A, 7),
        ],
        ad::VLAN_TAG_PRESENT => vec![
            ldx(op::W, reg::A, reg::CTX, field::VLAN_ALL),
            jmp32_imm(op::JEQ, reg::A, 0, 1),
            mov32_imm(reg::A, 1),
        ],
        ad::IFINDEX | ad::HATYPE => {
            // `dev->ifindex` is the device's first word.
            let (size, at) = if which == ad::IFINDEX {
                (op::W, 0)
            } else {
                (op::H, field::DEV_TYPE)
            };
            vec![
                ldx(op::DW, reg::TMP, reg::CTX, field::DEV),
                // The device's address is 64 bits.
                insn(op::JMP | op::JNE, reg::TMP, 0, 1, 0),
                exit(),
                ldx(size, reg::A, reg::TMP, at),
            ]
        }
        ad::ALU_XOR_X => vec![insn(op::ALU32 | op::XOR | op::X, reg::A, reg::X, 0, 0)],
        ad::NLATTR | ad::NLATTR_NEST => {
            let id = if which == ad::NLATTR {
                helper::NLATTR
            } else {
                helper::NLATTR_NEST
            };
            vec![
                mov64_reg(reg::ARG1, reg::CTX),
                mov32_reg(reg::ARG2, reg::A),
                mov32_reg(reg::ARG3, reg::X),
                call(id),
            ]
        }
        ad::PAY_OFFSET => vec![mov64_reg(reg::ARG1, reg::CTX), call(helper::PAY_OFFSET)],
        ad::CPU => vec![call(helper::CPU)],
        ad::RANDOM => vec![call(helper::RANDOM)],
        // [`ancillary`] takes no other.
        _ => Vec::new(),
    }
}

/// A load of the packet's `size` bytes at `k`, or at `X + k` (in 32 bits)
/// when `indirect`, into A: eBPF's own packet load, which does what a
/// classic one does.
fn packet_load(size: u16, indirect: bool, k: u32) -> Insn {
    let width = match size {
        W => op::W,
        H => op::H,
        _ => op::B,
    };
    if indirect {
        insn(op::LD_IND | width, 0, reg::X, 0, k as i32)
    } else {
        insn(op::LD_ABS | width, 0, 0, 0, k as i32)
    }
}

/// The converted block of the classic instruction `f` at `pc`, which is
/// `op`: its instructions, and no-ops after them up to [`length`].
fn block(pc: usize, op: Op, f: SockFilter) -> Block {
    let mut out = Block::default();
    let k = f.k as i32;
    match op {
        Op::Packet {
            indirect: false, ..
        } if ancillary(f.k) => {
            out.extend(ancillary_load(f.k.wrapping_sub(AD_OFF)));
        }
        Op::Packet { size, indirect } => out.push(packet_load(size, indirect, f.k)),
        Op::HeaderLength => out.extend([
            mov64_reg(reg::SAVED, reg::A),
            packet_load(B, false, f.k),
            alu32_imm(op::AND, reg::A, 0xf),
            alu32_imm(op::LSH, reg::A, 2),
            mov32_reg(reg::X, reg::A),
            mov32_reg(reg::A, reg::SAVED),
        ]),
        Op::Immediate(to) => out.push(mov32_imm(register(to), k)),
        Op::Scratch(to) => out.push(ldx(op::W, register(to), reg::FP, scratch(f.k))),
        Op::Length(to) => out.push(ldx(op::W, register(to), reg::CTX, field::LEN)),
        Op::Store(from) => out.push(insn(
            op::STX_MEM | op::W,
            reg::FP,
            register(from),
            scratch(f.k),
            0,
        )),
        Op::Alu { op: o, x } => {
            if x && (o == DIV || o == MOD) {
                // A division by 0 returns 0.
                out.extend([
                    jmp32_imm(op::JNE, reg::X, 0, 2),
                    mov32_imm(reg::A, 0),
                    exit(),
                ]);
            }
            // A classic operation's code is eBPF's 32-bit one.
            let src = if x { reg::X } else { 0 };
            out.push(insn(f.code as u8, reg::A, src, 0, k));
        }
        Op::Neg => out.push(insn(f.code as u8, reg::A, 0, 0, 0)),
        Op::Always => out.jump(insn(op::JMP | op::JA, 0, 0, 0, 0), pc + 1 + f.k as usize),
        Op::Conditional { op: o, x } => {
            let (jt, jf) = (pc + 1 + usize::from(f.jt), pc + 1 + usize::from(f.jf));
            // A 32-bit jump compares as a classic one does, a k above
            // i32::MAX too; Linux has one more instruction there.
            if !x && k < 0 {
                out.push(nop());
            }
            let source = if x { op::X } else { 0 };
            let src = if x { reg::X } else { 0 };
            let jump = |o: u8| {
                insn(
                    op::JMP32 | o | source,
                    reg::A,
                    src,
                    0,
                    if x { 0 } else { k },
                )
            };
            // A true case that is the next instruction takes the opposite
            // jump to the false one, where there is one.
            let opposite = match o {
                JEQ => Some(op::JNE),
                JGT => Some(op::JLE),
                JGE => Some(op::JLT),
                _ => None,
            };
            match (f.jt, f.jf, opposite) {
                (_, 0, _) => out.jump(jump(o as u8), jt),
                (0, _, Some(opposite)) => out.jump(jump(opposite), jf),
                _ => {
                    out.jump(jump(o as u8), jt);
                    out.jump(insn(op::JMP | op::JA, 0, 0, 0, 0), jf);
                }
            }
        }
        Op::Return { a } => {
            if !a {
                out.push(mov32_imm(reg::A, k));
            }
            out.push(exit());
        }
        Op::Tax => out.push(mov32_reg(reg::X, reg::A)),
        Op::Txa => out.push(mov32_reg(reg::A, reg::X)),
    }
    out.pad(length(op, f));
    out
}

/// Where scratch word `k` is on the converted program's stack.
const fn scratch(k: u32) -> i16 {
    -(k as i16 * 4 + 4)
}

/// Whether `op` with `k` reads the packet, which gives Linux's converted
/// program 4 more instructions at its start.
fn reads_packet(op: Op, k: u32) -> bool {
    match op {
        Op::Packet { indirect, .. } => indirect || !ancillary(k),
        Op::HeaderLength => true,
        _ => false,
    }
}

/// The eBPF program a checked classic one runs as. Its instructions are
/// this file's own, but each classic instruction's block has as many as
/// Linux's, and the jumps to other instructions are where Linux has them:
/// the program's length is what the socket is charged for, and it and
/// the jumps' places decide whether a jump reaches. It starts by clearing
/// A and X and keeping the context, with no-ops for Linux's 4 more when
/// the program reads the packet; then each classic instruction's block
/// follows.
///
/// EINVAL for a jump an `off` cannot hold, and for any jump placed past
/// 32,767, however near it goes: Linux places the jumps once with every
/// target taken to be at 0 before it places them where they go.
pub(crate) fn convert(filter: &[SockFilter]) -> Result<Vec<Insn>, Errno> {
    let ops = filter
        .iter()
        .map(|f| decode(f.code).ok_or(Errno::EINVAL))
        .collect::<Result<Vec<_>, _>>()?;
    let mut program = vec![
        mov32_imm(reg::A, 0),
        mov32_imm(reg::X, 0),
        mov64_reg(reg::CTX, reg::ARG1),
    ];
    if ops.iter().zip(filter).any(|(&op, f)| reads_packet(op, f.k)) {
        program.extend([nop(); 4]);
    }
    let blocks: Vec<Block> = ops
        .iter()
        .zip(filter)
        .enumerate()
        .map(|(pc, (&op, &f))| block(pc, op, f))
        .collect();
    let mut starts = Vec::with_capacity(blocks.len());
    let mut at = program.len();
    for b in &blocks {
        starts.push(at);
        at += b.0.len();
    }
    for piece in blocks.iter().flat_map(|b| &b.0) {
        let i = match *piece {
            Piece::Insn(i) => i,
            Piece::Jump(mut j, target) => {
                let here = program.len();
                let to = *starts.get(target).ok_or(Errno::EINVAL)?;
                if i16::try_from(here).is_err() {
                    return Err(Errno::EINVAL);
                }
                j.off = i16::try_from(to as i64 - here as i64 - 1).map_err(|_| Errno::EINVAL)?;
                j
            }
        };
        program.push(i);
    }
    Ok(program)
}

/// A classic socket filter as `SO_ATTACH_FILTER` attaches it: the program
/// as given, which `SO_GET_FILTER` gives back, and the converted one.
pub(crate) struct Classic {
    pub(crate) original: Vec<u8>,
    pub(crate) insns: Vec<Insn>,
}

impl Classic {
    /// `bpf_prog_size` of the converted program, which the socket is
    /// charged.
    pub(crate) fn filter_size(&self) -> u64 {
        crate::bpf_prog::prog_size(self.insns.len())
    }

    /// The number of instructions as given (`fprog->len`).
    pub(crate) fn blocks(&self) -> usize {
        self.original.len() / 8
    }
}

/// `__get_filter` after the copy: [`check`] and [`convert`] of `raw`, a
/// `struct sock_filter` array.
pub(crate) fn prepare(raw: Vec<u8>) -> Result<Classic, Errno> {
    let filter: Vec<SockFilter> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| SockFilter::decode(*c))
        .collect();
    check(&filter)?;
    let insns = convert(&filter)?;
    Ok(Classic {
        original: raw,
        insns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_interp::{Fault, Packet, tests::Quiet};
    use std::collections::BTreeMap;

    /// Runs `filter`, checked and converted, on `data` with `linear` bytes
    /// of it in the linear part: what it returns.
    fn run(filter: &[SockFilter], data: &[u8], linear: usize) -> Result<u64, Fault> {
        check(filter).expect("checked");
        let insns = convert(filter).expect("converted");
        let program = crate::bpf_interp::Program {
            insns: &insns,
            maps: &[],
            loads: &BTreeMap::new(),
        };
        let packet = Packet::message(data, linear);
        crate::bpf_interp::run(&program, &packet, &mut Quiet).map(|r| r & 0xffff_ffff)
    }

    #[test]
    fn converted_programs_compute_what_linux_s_do() {
        let data: Vec<u8> = (0..40).collect();
        let ret_a = f(RET | RET_A, 0, 0, 0);
        let a = |code: &[SockFilter]| {
            let mut p = code.to_vec();
            p.push(ret_a);
            run(&p, &data, data.len())
        };
        assert_eq!(a(&[f(LD | W | ABS, 0, 0, 1)]), Ok(0x0102_0304));
        assert_eq!(a(&[f(LD | H | ABS, 0, 0, 38)]), Ok(0x2627));
        // Past the end, the program returns 0.
        assert_eq!(a(&[f(LD | IMM, 0, 0, 9), f(LD | H | ABS, 0, 0, 39)]), Ok(0));
        // From the network header, the start; from the MAC header, none.
        assert_eq!(
            a(&[f(LD | B | ABS, 0, 0, (-0x10_0000i32 + 5) as u32)]),
            Ok(5)
        );
        assert_eq!(
            a(&[
                f(LD | IMM, 0, 0, 9),
                f(LD | B | ABS, 0, 0, -0x20_0000i32 as u32)
            ]),
            Ok(0)
        );
        // X + k wraps in 32 bits.
        assert_eq!(
            a(&[f(LDX | IMM, 0, 0, u32::MAX), f(LD | B | IND, 0, 0, 3)]),
            Ok(2)
        );
        assert_eq!(
            a(&[f(LDX | B | MSH, 0, 0, 13), f(MISC | TXA, 0, 0, 0)]),
            Ok(4 * 13)
        );
        // Division by an X of 0 returns 0; a shift by X is modulo 32.
        let div0 = [f(LD | IMM, 0, 0, 7), f(ALU | DIV | X, 0, 0, 0)];
        assert_eq!(a(&div0), Ok(0));
        let shift = [
            f(LD | IMM, 0, 0, 3),
            f(LDX | IMM, 0, 0, 33),
            f(ALU | LSH | X, 0, 0, 0),
        ];
        assert_eq!(a(&shift), Ok(6));
        // Unsigned comparison with a constant above i32::MAX.
        let jgt = [
            f(LD | IMM, 0, 0, u32::MAX),
            f(JMP | JGT | K, 0, 1, 0x8000_0000),
            f(RET | K, 0, 0, 1),
            f(RET | K, 0, 0, 2),
        ];
        assert_eq!(run(&jgt, &data, data.len()), Ok(1));
        // No device: ifindex returns A as it is.
        let ifindex = [
            f(LD | IMM, 0, 0, 0x99),
            f(LD | W | ABS, 0, 0, AD_OFF + ad::IFINDEX),
        ];
        assert_eq!(a(&ifindex), Ok(0x99));
        // A datagram in pages: loads reach past the linear part.
        assert_eq!(run(&[f(LD | B | ABS, 0, 0, 30), ret_a], &data, 20), Ok(30));
        assert_eq!(
            run(&[f(LD | W | ABS, 0, 0, 18), ret_a], &data, 20),
            Ok(0x1213_1415)
        );
        // Netlink attributes: one of type 1 (8 bytes), and one of type 2
        // with NLA_F_NET_BYTEORDER.
        let mut nl = vec![8, 0, 1, 0, 0, 0, 0, 0, 6, 0, 2, 0x40, 0, 0, 0, 0];
        nl.resize(24, 0);
        let find = |x: u32, nested: bool| {
            let k = AD_OFF + if nested { ad::NLATTR_NEST } else { ad::NLATTR };
            let p = [
                f(LD | IMM, 0, 0, 0),
                f(LDX | IMM, 0, 0, x),
                f(LD | W | ABS, 0, 0, k),
                ret_a,
            ];
            run(&p, &nl, nl.len())
        };
        assert_eq!(find(2, false), Ok(8));
        assert_eq!(find(3, false), Ok(0));
        assert_eq!(find(2, true), Ok(0));
    }

    #[test]
    fn classic_programs_the_checks_take_never_fault() {
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let codes: Vec<u16> = (0..=u16::from(u8::MAX)).filter(|&c| allowed(c)).collect();
        const EDGES: [u32; 12] = [
            0,
            1,
            3,
            15,
            31,
            32,
            39,
            40,
            0xffff_f000,
            0xffef_ffff,
            0x8000_0000,
            u32::MAX,
        ];
        let data: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(7)).collect();
        let mut taken = 0;
        for _ in 0..20_000 {
            let len = 1 + next() as usize % 12;
            let filter: Vec<SockFilter> = (0..len)
                .map(|i| {
                    let r = next();
                    let mut code = codes[r as usize % codes.len()];
                    if i == len - 1 {
                        code = if r & 1 == 0 { RET | K } else { RET | RET_A };
                    }
                    let k = if r >> 8 & 3 == 0 {
                        AD_OFF + (r >> 16) as u32 % 16 * 4
                    } else {
                        EDGES[(r >> 16) as usize % EDGES.len()]
                    };
                    f(code, (r >> 32) as u8 % 3, (r >> 40) as u8 % 3, k)
                })
                .collect();
            if check(&filter).is_err() || convert(&filter).is_err() {
                continue;
            }
            taken += 1;
            for linear in [40, 20, 0] {
                assert!(run(&filter, &data, linear).is_ok(), "{filter:?}");
            }
            assert!(run(&filter, &[], 0).is_ok(), "{filter:?}");
        }
        // 8,620 of the seed's 20,000 pass the checks.
        assert!(taken >= 8_000, "{taken}");
    }

    /// FNV-1a over `bytes`, folded into `hash`.
    fn fnv(hash: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *hash ^= u64::from(b);
            *hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }

    /// `count` programs of up to `max_len` instructions from `seed`, most of
    /// them ones the checks take: every code, each with a `k` that is valid
    /// for it, jumps that stay in the program, scratch words that are often
    /// read and, in seven programs of eight, written first, and, `far` times
    /// in eight, a load that converts to 16 instructions, so that jumps go
    /// far. One program in eight has one instruction that may be refused.
    fn programs(seed: u64, count: usize, max_len: usize, far: u64) -> Vec<Vec<SockFilter>> {
        let mut seed = seed;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let codes: Vec<u16> = (0..=u16::from(u8::MAX)).filter(|&c| allowed(c)).collect();
        const EDGES: [u32; 16] = [
            0,
            1,
            2,
            3,
            4,
            15,
            16,
            31,
            32,
            39,
            40,
            0x7fff,
            0x8000,
            0xffef_ffff,
            0x8000_0000,
            u32::MAX,
        ];
        (0..count)
            .map(|_| {
                let len = 1 + next() as usize % max_len;
                let shape = next();
                let wild_at = shape.is_multiple_of(8).then(|| (shape >> 8) as usize % len);
                let stores = shape >> 4 & 7 != 0;
                (0..len)
                    .map(|i| {
                        let r = next();
                        let left = (len - i - 1) as u64;
                        let wild = wild_at == Some(i);
                        if stores && i < 4 && i + 1 < len {
                            return f(ST, 0, 0, i as u32);
                        }
                        let mut code = codes[r as usize % codes.len()];
                        if wild && r & 0x100 != 0 {
                            code = (r >> 16) as u16 & 0xff;
                        } else if r >> 56 & 7 < 2 {
                            code = [ST, STX, LD | MEM, LDX | MEM][(r >> 4) as usize % 4];
                        } else if (r >> 20) % 8 < far {
                            return f(LD | W | ABS, 0, 0, 40_000);
                        }
                        if i == len - 1 && !wild {
                            code = if r & 1 == 0 { RET | K } else { RET | RET_A };
                        }
                        let any = (r >> 24) as u32;
                        let k = if wild {
                            EDGES[(r >> 24) as usize % EDGES.len()]
                        } else {
                            match code {
                                c if c == ST || c == STX || c == LD | MEM || c == LDX | MEM => {
                                    any % 4
                                }
                                c if c == ALU | DIV | K || c == ALU | MOD | K => any | 1,
                                c if c == ALU | LSH | K || c == ALU | RSH | K => any % 32,
                                c if c == JMP | JA => (any as u64 % (left.min(300) + 1)) as u32,
                                c if c & 0x07 == LD && (c & 0xe0 == ABS || c & 0xe0 == IND) => {
                                    match any % 4 {
                                        0 => AD_OFF + any / 4 % 16 * 4,
                                        1 => EDGES[(any / 4) as usize % (EDGES.len() - 1)],
                                        _ => any % 64,
                                    }
                                }
                                _ if any.is_multiple_of(3) => {
                                    EDGES[(any / 3) as usize % EDGES.len()]
                                }
                                _ => any,
                            }
                        };
                        let reach = left.clamp(1, 256);
                        let (jt, jf) = ((r >> 40) % reach, (r >> 48) % reach);
                        let (jt, jf) = if wild { (jt + 1, jf) } else { (jt, jf) };
                        f(code, jt as u8, jf as u8, k)
                    })
                    .collect()
            })
            .collect()
    }

    /// Digests of what a guest can see of `programs`: what [`check`]
    /// decides; for the programs it takes, each instruction's block length
    /// and where its jumps to other instructions are in it, and the
    /// converted length or the conversion's error; and what the converted
    /// programs return on a linear packet, a paged one and an empty one.
    /// With how many the checks take and how many convert.
    fn conversion_digests(programs: &[Vec<SockFilter>]) -> ([u64; 3], [usize; 2]) {
        let mut digests = [0xcbf2_9ce4_8422_2325u64; 3];
        let mut counts = [0; 2];
        let data: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(7)).collect();
        for filter in programs {
            let checked = check(filter);
            let len = (filter.len() as u16).to_le_bytes();
            fnv(&mut digests[0], &len);
            fnv(
                &mut digests[0],
                &[checked.map_or_else(|e| 100 + e.0 as u8, |()| 0)],
            );
            if checked.is_err() {
                continue;
            }
            counts[0] += 1;
            for (pc, &f) in filter.iter().enumerate() {
                let Some(op) = decode(f.code) else {
                    continue;
                };
                let pieces = block(pc, op, f).0;
                fnv(&mut digests[1], &(pieces.len() as u16).to_le_bytes());
                for (at, piece) in pieces.iter().enumerate() {
                    if let Piece::Jump(..) = piece {
                        fnv(&mut digests[1], &[0xaa, at as u8]);
                    }
                }
            }
            let insns = match convert(filter) {
                Ok(insns) => insns,
                Err(e) => {
                    fnv(&mut digests[1], &[0xff, e.0 as u8]);
                    continue;
                }
            };
            counts[1] += 1;
            fnv(&mut digests[1], &(insns.len() as u32).to_le_bytes());
            let program = crate::bpf_interp::Program {
                insns: &insns,
                maps: &[],
                loads: &BTreeMap::new(),
            };
            for (bytes, linear) in [(&data[..], 40), (&data[..], 20), (&[][..], 0)] {
                let packet = Packet::message(bytes, linear);
                match crate::bpf_interp::run(&program, &packet, &mut Quiet) {
                    Ok(r) => fnv(&mut digests[2], &r.to_le_bytes()),
                    Err(_) => fnv(&mut digests[2], &[0xfa]),
                }
            }
        }
        (digests, counts)
    }

    #[test]
    fn checks_and_conversions_give_what_they_did() {
        // Digests of what a guest sees of the checks and the converted
        // programs, made before the blocks' instructions were written anew:
        // it must change none of them.
        // A seed, how many programs, their longest, `far`, and the digests
        // and counts.
        type Case = (u64, usize, usize, u64, [u64; 3], [usize; 2]);
        let cases: [Case; 5] = [
            (
                0x2545_f491_4f6c_dd1d,
                40_000,
                12,
                0,
                [
                    0x93ae_fd66_3e5b_0f9a,
                    0x80a9_d1bb_6001_9afe,
                    0xf9d3_2d19_e23d_ae96,
                ],
                [35_225, 35_225],
            ),
            (
                0x9e37_79b9_7f4a_7c15,
                20_000,
                60,
                0,
                [
                    0xbf80_2ed8_ef94_b283,
                    0xe5bd_ae8f_0a0c_2df7,
                    0x56e8_0945_78e1_d741,
                ],
                [16_386, 16_386],
            ),
            (
                0xd1b5_4a32_d192_ed03,
                1_000,
                600,
                0,
                [
                    0xcdd7_f1ae_52a9_ac49,
                    0x62be_01c1_16f4_c69a,
                    0xb84b_f427_58e4_2bd8,
                ],
                [738, 738],
            ),
            (
                0x6a09_e667_f3bc_c909,
                300,
                MAX_INSNS,
                4,
                [
                    0x0aec_efeb_423c_668f,
                    0x79c8_280e_73cc_ccf8,
                    0x25c2_a163_e090_5856,
                ],
                [128, 128],
            ),
            (
                0x510e_527f_ade6_82d1,
                300,
                MAX_INSNS,
                6,
                [
                    0xd5d0_1baf_752d_8944,
                    0x9974_442b_073a_b3f0,
                    0x73be_dd9e_a6a9_a825,
                ],
                [101, 88],
            ),
        ];
        for (seed, count, max_len, far, digests, counts) in cases {
            let got = conversion_digests(&programs(seed, count, max_len, far));
            assert_eq!(got, (digests, counts), "{seed:#x}");
        }
    }

    /// Whether Linux takes the classic `code` at all.
    fn allowed(code: u16) -> bool {
        decode(code).is_some()
    }

    fn f(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    #[test]
    fn the_checks_are_bpf_check_classic_s() {
        let ret = f(RET | K, 0, 0, 0);
        assert_eq!(check(&[]), Err(Errno::EINVAL));
        assert_eq!(check(&[ret]), Ok(()));
        assert_eq!(check(&vec![ret; MAX_INSNS]), Ok(()));
        assert_eq!(check(&vec![ret; MAX_INSNS + 1]), Err(Errno::EINVAL));
        let refused = [
            // Unknown codes: a 16-bit immediate load, ret X, seccomp's ldx abs.
            f(LD | H | IMM, 0, 0, 0),
            f(RET | X, 0, 0, 0),
            f(LDX | W | ABS, 0, 0, 0),
            f(ALU | DIV | K, 0, 0, 0),
            f(ALU | MOD | K, 0, 0, 0),
            f(ALU | LSH | K, 0, 0, 32),
            f(ALU | RSH | K, 0, 0, 40),
            f(ST, 0, 0, 16),
            f(LDX | MEM, 0, 0, 16),
            f(JMP | JA, 0, 0, 1),
            f(JMP | JEQ | K, 1, 0, 0),
            f(JMP | JSET | X, 0, 1, 0),
            // An ancillary offset Linux does not know, and one off by one.
            f(LD | W | ABS, 0, 0, AD_OFF + 64),
            f(LD | B | ABS, 0, 0, AD_OFF + 1),
            f(LD | H | ABS, 0, 0, u32::MAX),
        ];
        for r in refused {
            assert_eq!(check(&[r, ret]), Err(Errno::EINVAL), "{r:?}");
        }
        let taken = [
            f(ALU | DIV | K, 0, 0, 1),
            f(ALU | LSH | K, 0, 0, 31),
            f(ST, 0, 0, 15),
            f(JMP | JA, 0, 0, 0),
            f(JMP | JGT | X, 0, 0, 0),
            f(LD | B | ABS, 0, 0, AD_OFF - 1),
            f(LD | W | ABS, 0, 0, AD_OFF + ad::VLAN_TPID),
            f(LD | W | IND, 0, 0, u32::MAX),
            f(LDX | B | MSH, 0, 0, AD_OFF + 1),
        ];
        for t in taken {
            assert_eq!(check(&[t, ret]), Ok(()), "{t:?}");
        }
        // The last instruction returns.
        assert_eq!(check(&[ret, f(LD | IMM, 0, 0, 0)]), Err(Errno::EINVAL));
        // A scratch word is written on every path before it is read.
        let store = f(ST, 0, 0, 3);
        let load = f(LD | MEM, 0, 0, 3);
        assert_eq!(check(&[store, load, ret]), Ok(()));
        assert_eq!(check(&[load, ret]), Err(Errno::EINVAL));
        let one_path = [f(JMP | JEQ | K, 1, 0, 0), store, load, ret];
        assert_eq!(check(&one_path), Err(Errno::EINVAL));
        let both = [store, f(JMP | JEQ | K, 1, 0, 0), store, load, ret];
        assert_eq!(check(&both), Ok(()));
        // What is known after a return carries into the next instruction,
        // which only a jump reaches: there, nothing is written.
        assert_eq!(check(&[ret, load, ret]), Err(Errno::EINVAL));
        // The path through the return writes nothing; the path that jumps
        // to the load writes the word.
        let jumped = [
            f(JMP | JEQ | K, 0, 1, 0),
            f(JMP | JA, 0, 0, 2),
            store,
            f(JMP | JA, 0, 0, 1),
            ret,
            load,
            ret,
        ];
        assert_eq!(check(&jumped), Err(Errno::EINVAL));
    }

    #[test]
    fn the_conversion_has_linux_s_lengths() {
        let ret = f(RET | K, 0, 0, 0);
        // The prologue of three, and ret k of two.
        assert_eq!(convert(&[ret]).map(|p| p.len()), Ok(5));
        // With a packet load the prologue has four more; ldb [0] is 4 and
        // then 8 through the helper, ld [40000] 16 with the swap, ldh
        // [x + 0] only the helper's 8.
        let ld = |code, k| [f(code, 0, 0, k), ret];
        assert_eq!(
            convert(&ld(LD | B | ABS, 0)).map(|p| p.len()),
            Ok(7 + 12 + 2)
        );
        assert_eq!(
            convert(&ld(LD | W | ABS, 40000)).map(|p| p.len()),
            Ok(7 + 16 + 2)
        );
        assert_eq!(
            convert(&ld(LD | H | IND, 0)).map(|p| p.len()),
            Ok(7 + 8 + 2)
        );
        assert_eq!(
            convert(&ld(LD | H | IND, 2)).map(|p| p.len()),
            Ok(7 + 9 + 2)
        );
        // A negative offset goes to the helper only.
        assert_eq!(
            convert(&ld(LD | B | ABS, AD_OFF - 1)).map(|p| p.len()),
            Ok(7 + 8 + 2)
        );
        // Jumps: jf 0 one, jt 0 one (but jset), both two, a negative
        // constant one more.
        let j = |code, jt, jf, k| [f(code, jt, jf, k), ret, ret];
        assert_eq!(
            convert(&j(JMP | JEQ | K, 0, 1, 5)).map(|p| p.len()),
            Ok(3 + 1 + 4)
        );
        assert_eq!(
            convert(&j(JMP | JSET | K, 0, 1, 5)).map(|p| p.len()),
            Ok(3 + 2 + 4)
        );
        assert_eq!(
            convert(&j(JMP | JGT | K, 0, 1, u32::MAX)).map(|p| p.len()),
            Ok(3 + 2 + 4)
        );
        // Division by X checks it first.
        assert_eq!(
            convert(&ld(ALU | DIV | X, 0)).map(|p| p.len()),
            Ok(3 + 5 + 2)
        );
    }

    #[test]
    fn a_jump_past_what_an_offset_holds_is_einval() {
        // ld [40000] is 16 instructions after a prologue of 7: past 2,047 of
        // them a jump is at 32,775, where the first writing pass, which
        // takes every target to be at 0, sees it go too far back.
        let ld = f(LD | W | ABS, 0, 0, 40000);
        let ret = f(RET | K, 0, 0, 0);
        let mut far = vec![ld; 2048];
        far.extend([f(JMP | JA, 0, 0, 0), ret]);
        assert_eq!(convert(&far), Err(Errno::EINVAL));
        far.remove(0);
        assert_eq!(convert(&far).map(|p| p.len()), Ok(7 + 2047 * 16 + 1 + 2));
        // A jump over 2,048 of them goes 32,768 forward, one too far.
        let mut over = vec![f(JMP | JA, 0, 0, 2048)];
        over.extend(vec![ld; 2048]);
        over.push(ret);
        assert_eq!(convert(&over), Err(Errno::EINVAL));
        over.remove(1);
        over[0].k = 2047;
        assert!(convert(&over).is_ok());
    }
}
