//! Classic BPF socket filters (`SO_ATTACH_FILTER`), as Linux's
//! `net/core/filter.c` takes them: [`check`] is `bpf_check_classic`, and
//! [`convert`] is `bpf_convert_filter`, which turns the program into eBPF
//! instructions that [`crate::bpf_interp`] runs as Linux runs the converted
//! program.
//!
//! The instructions are Linux's, one for one, so that the program has its
//! length on Linux, which the socket is charged for and which decides
//! whether a jump reaches. Only what they read differs:
//! - the `sk_buff` fields are read from the context (`struct __sk_buff`)
//!   where it has them, and from the fields the interpreter keeps after it
//!   ([`crate::bpf_interp::classic`]): the data's address, `data_len`, and
//!   `dev`, which an AF_UNIX message has none of;
//! - Linux's internal helpers (`bpf_skb_load_helper_*`,
//!   `bpf_skb_get_nlattr` and the rest) are numbers of the interpreter's
//!   own, which no eBPF program can call.
use paludarium_types::Errno;

use crate::bpf_interp::classic::{self as helper, field};
use crate::bpf_verifier::Insn;

/// `BPF_MAXINSNS`.
pub(crate) const MAX_INSNS: usize = 4096;
/// `BPF_MEMWORDS`.
const MEMWORDS: u32 = 16;
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

/// The conditional jumps, with K or X.
fn conditional(code: u16) -> bool {
    [JEQ, JGT, JGE, JSET]
        .iter()
        .any(|&op| code == JMP | op | K || code == JMP | op | X)
}

/// `chk_code_allowed`: the codes a classic program may use.
fn allowed(code: u16) -> bool {
    let alu = [ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, LSH, RSH]
        .iter()
        .any(|&op| code == ALU | op | K || code == ALU | op | X);
    alu || conditional(code)
        || [
            ALU | NEG,
            LD | W | ABS,
            LD | H | ABS,
            LD | B | ABS,
            LD | W | LEN,
            LD | W | IND,
            LD | H | IND,
            LD | B | IND,
            LD | IMM,
            LD | MEM,
            LDX | W | LEN,
            LDX | B | MSH,
            LDX | IMM,
            LDX | MEM,
            ST,
            STX,
            MISC | TAX,
            MISC | TXA,
            RET | K,
            RET | RET_A,
            JMP | JA,
        ]
        .contains(&code)
}

/// Whether `k` of a `BPF_LD | BPF_ABS` is an ancillary load Linux knows
/// (`bpf_anc_helper`).
fn ancillary(k: u32) -> bool {
    k.wrapping_sub(AD_OFF) <= ad::VLAN_TPID && k.wrapping_sub(AD_OFF).is_multiple_of(4)
}

/// `bpf_check_basics_ok` and `bpf_check_classic`: EINVAL for no
/// instructions or more than [`MAX_INSNS`], a code Linux does not know, a
/// division by a constant 0, a constant shift of 32 or more, a scratch word
/// past the 16th, a jump past the end, an unknown ancillary load, a last
/// instruction that does not return, and a scratch word read where some
/// path has not written it.
pub(crate) fn check(filter: &[SockFilter]) -> Result<(), Errno> {
    let len = filter.len();
    if len == 0 || len > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    for (pc, f) in filter.iter().enumerate() {
        if !allowed(f.code) {
            return Err(Errno::EINVAL);
        }
        let bad = match f.code {
            c if c == ALU | DIV | K || c == ALU | MOD | K => f.k == 0,
            c if c == ALU | LSH | K || c == ALU | RSH | K => f.k >= 32,
            c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => f.k >= MEMWORDS,
            c if c == JMP | JA => f.k as usize >= len - pc - 1,
            c if conditional(c) => {
                pc + usize::from(f.jt) + 1 >= len || pc + usize::from(f.jf) + 1 >= len
            }
            c if c == LD | W | ABS || c == LD | H | ABS || c == LD | B | ABS => {
                !ancillary(f.k) && f.k >= AD_OFF
            }
            _ => false,
        };
        if bad {
            return Err(Errno::EINVAL);
        }
    }
    if ![RET | K, RET | RET_A].contains(&filter[len - 1].code) {
        return Err(Errno::EINVAL);
    }
    loads_after_stores(filter)
}

/// `check_load_and_stores`: a scratch word is read only where every path to
/// the read has written it.
fn loads_after_stores(filter: &[SockFilter]) -> Result<(), Errno> {
    let mut masks = vec![u16::MAX; filter.len()];
    let mut valid: u16 = 0;
    for (pc, f) in filter.iter().enumerate() {
        valid &= masks[pc];
        match f.code {
            c if c == ST || c == STX => valid |= 1 << f.k,
            c if (c == LD | MEM || c == LDX | MEM) && valid & (1 << f.k) == 0 => {
                return Err(Errno::EINVAL);
            }
            c if c == JMP | JA => {
                masks[pc + 1 + f.k as usize] &= valid;
                valid = u16::MAX;
            }
            c if conditional(c) => {
                masks[pc + 1 + usize::from(f.jt)] &= valid;
                masks[pc + 1 + usize::from(f.jf)] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// The registers of the converted program (`BPF_REG_A` and the rest).
mod reg {
    pub const A: u8 = 0;
    pub const ARG1: u8 = 1;
    pub const ARG2: u8 = 2;
    pub const ARG3: u8 = 3;
    pub const ARG4: u8 = 4;
    pub const TMP: u8 = 2;
    pub const CTX: u8 = 6;
    pub const X: u8 = 7;
    pub const D: u8 = 8;
    pub const H: u8 = 9;
    pub const FP: u8 = 10;
}

/// The eBPF codes the conversion writes.
mod op {
    pub const ALU32: u8 = 0x04;
    pub const ALU64: u8 = 0x07;
    pub const JMP: u8 = 0x05;
    pub const X: u8 = 0x08;
    pub const SUB: u8 = 0x10;
    pub const ADD: u8 = 0x00;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const END_BE: u8 = 0xd8;
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JNE: u8 = 0x50;
    pub const JSGE: u8 = 0x70;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
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
const fn mov32_imm(dst: u8, imm: i32) -> Insn {
    insn(op::ALU32 | op::MOV, dst, 0, 0, imm)
}
const fn alu32_reg(o: u8, dst: u8, src: u8) -> Insn {
    insn(op::ALU32 | o | op::X, dst, src, 0, 0)
}
const fn alu32_imm(o: u8, dst: u8, imm: i32) -> Insn {
    insn(op::ALU32 | o, dst, 0, 0, imm)
}
const fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
    insn(op::LDX_MEM | size, dst, src, off, 0)
}
const fn jmp_imm(o: u8, dst: u8, imm: i32, off: i16) -> Insn {
    insn(op::JMP | o, dst, 0, off, imm)
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

/// `convert_skb_access`: an `sk_buff` field into `A`.
fn skb_access(field: u32, out: &mut Vec<Insn>) {
    match field {
        ad::MARK => out.push(ldx(op::W, reg::A, reg::CTX, field::MARK)),
        ad::PKTTYPE => {
            out.push(ldx(op::B, reg::A, reg::CTX, field::PKT_TYPE));
            // PKT_TYPE_MAX.
            out.push(alu32_imm(op::AND, reg::A, 7));
        }
        ad::QUEUE => out.push(ldx(op::H, reg::A, reg::CTX, field::QUEUE_MAPPING)),
        ad::VLAN_TAG => out.push(ldx(op::H, reg::A, reg::CTX, field::VLAN_TCI)),
        _ => {
            out.push(ldx(op::W, reg::A, reg::CTX, field::VLAN_ALL));
            out.push(jmp_imm(op::JEQ, reg::A, 0, 1));
            out.push(alu32_imm(op::MOV, reg::A, 1));
        }
    }
}

/// `convert_bpf_extensions`: an ancillary load, or `false` for a `k` that
/// is none.
fn extension(k: u32, out: &mut Vec<Insn>) -> bool {
    let Some(which) = k.checked_sub(AD_OFF).filter(|_| ancillary(k)) else {
        return false;
    };
    match which {
        ad::PROTOCOL | ad::VLAN_TPID => {
            let at = if which == ad::PROTOCOL {
                field::PROTOCOL
            } else {
                field::VLAN_PROTO
            };
            out.push(ldx(op::H, reg::A, reg::CTX, at));
            out.push(from_be(reg::A, 16));
        }
        ad::PKTTYPE | ad::MARK | ad::QUEUE | ad::VLAN_TAG | ad::VLAN_TAG_PRESENT => {
            skb_access(which, out);
        }
        ad::IFINDEX | ad::HATYPE => {
            out.push(ldx(op::DW, reg::TMP, reg::CTX, field::DEV));
            out.push(jmp_imm(op::JNE, reg::TMP, 0, 1));
            out.push(exit());
            // `dev->ifindex` and `dev->type`, which no AF_UNIX message
            // reaches.
            let size = if which == ad::IFINDEX { op::W } else { op::H };
            out.push(ldx(size, reg::A, reg::TMP, 0));
        }
        ad::RXHASH => out.push(ldx(op::W, reg::A, reg::CTX, field::HASH)),
        ad::ALU_XOR_X => out.push(alu32_reg(op::XOR, reg::A, reg::X)),
        _ => {
            let id = match which {
                ad::PAY_OFFSET => helper::PAY_OFFSET,
                ad::NLATTR => helper::NLATTR,
                ad::NLATTR_NEST => helper::NLATTR_NEST,
                ad::CPU => helper::CPU,
                ad::RANDOM => helper::RANDOM,
                _ => return false,
            };
            out.push(mov64_reg(reg::ARG1, reg::CTX));
            out.push(mov64_reg(reg::ARG2, reg::A));
            out.push(mov64_reg(reg::ARG3, reg::X));
            out.push(call(id));
        }
    }
    true
}

/// `convert_bpf_ld_abs`: a load of the packet's `size` bytes at `k`, or at
/// `X + k` when `indirect`, through the data when it is in the linear part
/// and else through a helper; the program returns 0 where neither has the
/// bytes.
fn ld_abs(size: u16, indirect: bool, k: u32, out: &mut Vec<Insn>) {
    let (bytes, width, helper) = match size {
        W => (4, op::W, helper::LOAD_WORD),
        H => (2, op::H, helper::LOAD_HALF),
        _ => (1, op::B, helper::LOAD_BYTE),
    };
    let endian = size != B;
    let offset = k as i32;
    // An x86-64 kernel has efficient unaligned access.
    if !indirect && offset >= 0 {
        let off_ok = offset <= i32::from(i16::MAX);
        out.push(mov64_reg(reg::TMP, reg::H));
        if offset != 0 {
            out.push(insn(op::ALU64 | op::SUB, reg::TMP, 0, 0, offset));
        }
        let skip = 2 + i16::from(endian) + i16::from(!off_ok) * 2;
        out.push(jmp_imm(op::JSLT, reg::TMP, bytes, skip));
        if off_ok {
            out.push(ldx(width, reg::A, reg::D, offset as i16));
        } else {
            out.push(mov64_reg(reg::TMP, reg::D));
            out.push(insn(op::ALU64 | op::ADD, reg::TMP, 0, 0, offset));
            out.push(ldx(width, reg::A, reg::TMP, 0));
        }
        if endian {
            out.push(from_be(reg::A, bytes * 8));
        }
        out.push(jmp_imm(op::JA, 0, 0, 8));
    }
    out.push(mov64_reg(reg::ARG1, reg::CTX));
    out.push(mov64_reg(reg::ARG2, reg::D));
    out.push(mov64_reg(reg::ARG3, reg::H));
    if indirect {
        out.push(mov64_reg(reg::ARG4, reg::X));
        if k != 0 {
            out.push(insn(op::ALU64 | op::ADD, reg::ARG4, 0, 0, offset));
        }
    } else {
        out.push(insn(op::ALU64 | op::MOV, reg::ARG4, 0, 0, offset));
    }
    out.push(call(helper));
    out.push(jmp_imm(op::JSGE, reg::A, 0, 2));
    out.push(alu32_reg(op::XOR, reg::A, reg::A));
    out.push(exit());
}

/// One pass of `bpf_convert_filter`. Without `addrs` it only counts, and
/// every jump goes nowhere; with them it writes the program, each
/// instruction's place in `addrs`, and a jump goes to its target's place as
/// the previous pass left it, 0 on the first, as Linux's zeroed array has
/// it. EINVAL for a jump that goes further than an `off` reaches.
fn pass(
    filter: &[SockFilter],
    mut addrs: Option<&mut [i32]>,
    seen_ld_abs: &mut bool,
) -> Result<Vec<Insn>, Errno> {
    let len = filter.len();
    let mut program = Vec::new();
    if addrs.is_some() {
        program.push(alu32_reg(op::XOR, reg::A, reg::A));
        program.push(alu32_reg(op::XOR, reg::X, reg::X));
        program.push(mov64_reg(reg::CTX, reg::ARG1));
        if *seen_ld_abs {
            program.push(ldx(op::DW, reg::D, reg::CTX, field::DATA));
            program.push(ldx(op::W, reg::H, reg::CTX, field::LEN));
            program.push(ldx(op::W, reg::TMP, reg::CTX, field::DATA_LEN));
            program.push(alu32_reg(op::SUB, reg::H, reg::TMP));
        }
    } else {
        program.resize(3, exit());
    }
    for (i, f) in filter.iter().enumerate() {
        let here = program.len() as i32;
        if let Some(addrs) = addrs.as_deref_mut() {
            addrs[i] = here;
        }
        let mut out = Vec::new();
        // BPF_EMIT_JMP: the next instruction of `out` jumps to `target`.
        let jump = |out: &mut Vec<Insn>, mut j: Insn, target: usize, addrs: Option<&[i32]>| {
            if target >= len {
                return Err(Errno::EINVAL);
            }
            let mut off = addrs.map_or(0, |a| a[target] - a[i] - 1);
            off -= out.len() as i32;
            j.off = i16::try_from(off).map_err(|_| Errno::EINVAL)?;
            out.push(j);
            Ok(())
        };
        let a = addrs.as_deref();
        match f.code {
            c if c & 0x07 == ALU || c & 0x07 == LD && (c & 0xe0 == ABS || c & 0xe0 == IND) => {
                let class = c & 0x07;
                let extended = class == LD && c & 0xe0 == ABS && extension(f.k, &mut out);
                if extended {
                    // An ancillary load.
                } else if class == LD {
                    ld_abs(c & 0x18, c & 0xe0 == IND, f.k, &mut out);
                    *seen_ld_abs = true;
                } else {
                    if c == ALU | DIV | X || c == ALU | MOD | X {
                        out.push(insn(op::ALU32 | op::MOV | op::X, reg::X, reg::X, 0, 0));
                        out.push(jmp_imm(op::JNE, reg::X, 0, 2));
                        out.push(alu32_reg(op::XOR, reg::A, reg::A));
                        out.push(exit());
                    }
                    out.push(insn(c as u8, reg::A, reg::X, 0, f.k as i32));
                }
            }
            c if c == JMP | JA => {
                jump(
                    &mut out,
                    insn(op::JMP | op::JA, 0, 0, 0, 0),
                    i + f.k as usize + 1,
                    a,
                )?;
            }
            c if conditional(c) => {
                let o = (c & 0xf0) as u8;
                let mut j = insn(0, reg::A, 0, 0, 0);
                let src = if c & X == K && (f.k as i32) < 0 {
                    // Immediates are signed: the constant goes into TMP,
                    // zero-extended.
                    out.push(mov32_imm(reg::TMP, f.k as i32));
                    j.src = reg::TMP;
                    op::X
                } else {
                    j.imm = f.k as i32;
                    if c & X != 0 {
                        j.src = reg::X;
                    }
                    (c & X) as u8
                };
                let (jt, jf) = (i + usize::from(f.jt) + 1, i + usize::from(f.jf) + 1);
                // When the true case is next, the inverse jump, which jset
                // has none of.
                let inverse = match u16::from(o) {
                    JEQ => Some(op::JNE),
                    JGT => Some(op::JLE),
                    JGE => Some(op::JLT),
                    _ => None,
                };
                if f.jf == 0 {
                    j.code = op::JMP | o | src;
                    jump(&mut out, j, jt, a)?;
                } else if let (0, Some(inverse)) = (f.jt, inverse) {
                    j.code = op::JMP | inverse | src;
                    jump(&mut out, j, jf, a)?;
                } else {
                    j.code = op::JMP | o | src;
                    jump(&mut out, j, jt, a)?;
                    jump(&mut out, insn(op::JMP | op::JA, 0, 0, 0, 0), jf, a)?;
                }
            }
            c if c == LDX | B | MSH => {
                *seen_ld_abs = true;
                out.push(mov64_reg(reg::X, reg::A));
                ld_abs(B, false, f.k, &mut out);
                out.push(alu32_imm(op::AND, reg::A, 0xf));
                out.push(alu32_imm(op::LSH, reg::A, 2));
                out.push(mov64_reg(reg::TMP, reg::X));
                out.push(mov64_reg(reg::X, reg::A));
                out.push(mov64_reg(reg::A, reg::TMP));
            }
            c if c == RET | K || c == RET | RET_A => {
                if c == RET | K {
                    out.push(mov32_imm(reg::A, f.k as i32));
                }
                out.push(exit());
            }
            c if c == ST || c == STX => {
                let from = if c == ST { reg::A } else { reg::X };
                let at = -(f.k as i16 * 4 + 4);
                out.push(insn(op::STX_MEM | op::W, reg::FP, from, at, 0));
            }
            c if c == LD | MEM || c == LDX | MEM => {
                let to = if c == LD | MEM { reg::A } else { reg::X };
                out.push(ldx(op::W, to, reg::FP, -(f.k as i16 * 4 + 4)));
            }
            c if c == LD | IMM || c == LDX | IMM => {
                let to = if c == LD | IMM { reg::A } else { reg::X };
                out.push(mov32_imm(to, f.k as i32));
            }
            c if c == MISC | TAX => out.push(mov64_reg(reg::X, reg::A)),
            c if c == MISC | TXA => out.push(mov64_reg(reg::A, reg::X)),
            c if c == LD | W | LEN || c == LDX | W | LEN => {
                let to = if c == LD | W | LEN { reg::A } else { reg::X };
                out.push(ldx(op::W, to, reg::CTX, field::LEN));
            }
            _ => return Err(Errno::EINVAL),
        }
        program.append(&mut out);
    }
    Ok(program)
}

/// `bpf_convert_filter`, as `bpf_migrate_filter` calls it: a pass that
/// counts, and then passes that write the program until two in a row give
/// it the same length, three at most. EINVAL for a jump that an `off`
/// cannot hold, which on the first of them is any jump placed past 32,767,
/// since that pass takes every target to be at 0.
pub(crate) fn convert(filter: &[SockFilter]) -> Result<Vec<Insn>, Errno> {
    let mut seen_ld_abs = false;
    let counted = pass(filter, None, &mut seen_ld_abs)?.len() + if seen_ld_abs { 4 } else { 0 };
    let mut addrs = vec![0; filter.len()];
    let mut length = 0;
    for round in 1.. {
        let program = pass(filter, Some(&mut addrs), &mut seen_ld_abs)?;
        if program.len() == length {
            debug_assert_eq!(program.len(), counted);
            return Ok(program);
        }
        length = program.len();
        if round > 2 {
            break;
        }
    }
    Err(Errno::EINVAL)
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
        let packet = Packet { data, linear };
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
