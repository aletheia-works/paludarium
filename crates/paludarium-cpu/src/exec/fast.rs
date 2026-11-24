//! Instruction forms worked out when they are decoded.
//!
//! [`Fast::of`] picks the operation of the most frequent register, memory and
//! branch forms once, so that running them needs neither the mnemonic `match`
//! of [`super::execute`] nor the generic operand handling. Each form means
//! exactly what [`super::execute`] does with it. A form changes the state only
//! after the last thing that can fail: when it fails, nothing has changed, and
//! the instruction runs again in [`super::execute`], which gives the fault.

use paludarium_decoder::{
    Condition, Instruction, MemoryOperand, Mnemonic, Operand, Register, RepPrefix, Segment,
};
use paludarium_mmu::AddressSpace;
use paludarium_types::GuestAddr;

use paludarium_mmu::AtomicOp;

use super::{Exec, Result, Stop, atomic_width};
use crate::alu::{self, sign_extend, size_mask};
use crate::state::{CpuState, flag};

/// An arithmetic or logic operation of [`Fast`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alu {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Cmp,
    Test,
}

impl Alu {
    fn of(m: Mnemonic) -> Option<Self> {
        Some(match m {
            Mnemonic::Add => Self::Add,
            Mnemonic::Sub => Self::Sub,
            Mnemonic::And => Self::And,
            Mnemonic::Or => Self::Or,
            Mnemonic::Xor => Self::Xor,
            Mnemonic::Cmp => Self::Cmp,
            Mnemonic::Test => Self::Test,
            _ => return None,
        })
    }

    /// Whether the operation writes its result to the destination
    /// (`cmp` and `test` only set the flags).
    #[must_use]
    pub fn writes(self) -> bool {
        !matches!(self, Self::Cmp | Self::Test)
    }

    /// The result and the status flags, as [`Exec::alu`] has them.
    #[inline]
    fn apply(self, a: u64, b: u64, size: u8) -> (u64, u64) {
        match self {
            Self::Add => alu::add(a, b, false, size),
            Self::Sub | Self::Cmp => alu::sub(a, b, false, size),
            Self::And | Self::Test => (a & b, alu::logic(a & b, size)),
            Self::Or => (a | b, alu::logic(a | b, size)),
            Self::Xor => (a ^ b, alu::logic(a ^ b, size)),
        }
    }
}

/// An operation of [`Fast`] on one operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unary {
    Inc,
    Dec,
    Neg,
    Not,
}

impl Unary {
    fn of(m: Mnemonic) -> Option<Self> {
        Some(match m {
            Mnemonic::Inc => Self::Inc,
            Mnemonic::Dec => Self::Dec,
            Mnemonic::Neg => Self::Neg,
            Mnemonic::Not => Self::Not,
            _ => return None,
        })
    }

    /// The result of the operation on `a`, the flags it changes and their
    /// values, as [`Exec::unary`] has them.
    #[inline]
    fn apply(self, a: u64, size: u8) -> (u64, u64, u64) {
        match self {
            Self::Inc => {
                let (r, f) = alu::add(a, 1, false, size);
                (r, flag::STATUS & !flag::CF, f)
            }
            Self::Dec => {
                let (r, f) = alu::sub(a, 1, false, size);
                (r, flag::STATUS & !flag::CF, f)
            }
            Self::Neg => {
                let (r, f) = alu::sub(0, a, false, size);
                (r, flag::STATUS, f)
            }
            Self::Not => (!a & size_mask(size), 0, 0),
        }
    }
}

/// A shift or rotate of [`Fast`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shift {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

impl Shift {
    fn of(m: Mnemonic) -> Option<Self> {
        Some(match m {
            Mnemonic::Shl => Self::Shl,
            Mnemonic::Shr => Self::Shr,
            Mnemonic::Sar => Self::Sar,
            Mnemonic::Rol => Self::Rol,
            Mnemonic::Ror => Self::Ror,
            _ => return None,
        })
    }

    /// The result, the flags it changes and their values, of shifting or
    /// rotating `a` by `count`, already masked, as [`Exec::shift`] and
    /// [`Exec::rotate`] have them.
    #[inline]
    fn apply(self, a: u64, count: u8, size: u8) -> (u64, u64, u64) {
        let kind = match self {
            Self::Shl => alu::ShiftKind::Shl,
            Self::Shr => alu::ShiftKind::Shr,
            Self::Sar => alu::ShiftKind::Sar,
            Self::Rol | Self::Ror => return self.rotate(a, count, size),
        };
        match alu::shift(kind, a, u64::from(count), size) {
            Some((r, f)) => (r, flag::STATUS, f),
            None => (a, 0, 0),
        }
    }

    fn rotate(self, a: u64, count: u8, size: u8) -> (u64, u64, u64) {
        if count == 0 {
            return (a, 0, 0);
        }
        let width = alu::bits(size);
        let c = u32::from(count) % width;
        let left = self == Self::Rol;
        let r = if c == 0 {
            a
        } else if left {
            ((a << c) | (a >> (width - c))) & size_mask(size)
        } else {
            ((a >> c) | (a << (width - c))) & size_mask(size)
        };
        let top = 1u64 << (width - 1);
        let cf = if left { r & 1 != 0 } else { r & top != 0 };
        let of = if left {
            (r & top != 0) != cf
        } else {
            ((r >> (width - 1)) ^ (r >> (width - 2))) & 1 != 0
        };
        let update = flag::CF | if count == 1 { flag::OF } else { 0 };
        let flags = if cf { flag::CF } else { 0 } | if of { flag::OF } else { 0 };
        (r, update, flags)
    }
}

/// A count of bits of [`Fast`]: `tzcnt`, `lzcnt`, `popcnt`, `bsf` or `bsr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Count {
    Tzcnt,
    Lzcnt,
    Popcnt,
    Bsf,
    Bsr,
}

impl Count {
    fn of(m: Mnemonic) -> Option<Self> {
        Some(match m {
            Mnemonic::Tzcnt => Self::Tzcnt,
            Mnemonic::Lzcnt => Self::Lzcnt,
            Mnemonic::Popcnt => Self::Popcnt,
            Mnemonic::Bsf => Self::Bsf,
            Mnemonic::Bsr => Self::Bsr,
            _ => return None,
        })
    }

    /// The result of the count of `value`, already masked to `size`, or
    /// `None` where `bsf` and `bsr` leave the destination as it was, the
    /// flags it changes and their values, as [`Exec::count_bits`] and
    /// [`Exec::scan`] have them.
    #[inline]
    fn apply(self, value: u64, size: u8) -> (Option<u64>, u64, u64) {
        let width = alu::bits(size);
        let zero = value == 0;
        let zf = |z: bool| if z { flag::ZF } else { 0 };
        match self {
            Self::Bsf | Self::Bsr => {
                let index = (!zero).then(|| {
                    u64::from(if self == Self::Bsr {
                        63 - value.leading_zeros()
                    } else {
                        value.trailing_zeros()
                    })
                });
                (index, flag::ZF, zf(zero))
            }
            Self::Popcnt => (Some(u64::from(value.count_ones())), flag::STATUS, zf(zero)),
            Self::Tzcnt | Self::Lzcnt => {
                let count = if self == Self::Lzcnt {
                    value.leading_zeros() - (64 - width)
                } else if zero {
                    width
                } else {
                    value.trailing_zeros()
                };
                let cf = if zero { flag::CF } else { 0 };
                (
                    Some(u64::from(count)),
                    flag::CF | flag::ZF,
                    cf | zf(count == 0),
                )
            }
        }
    }
}

/// A second operand of [`Fast`]: a register or an immediate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Register(Register),
    Immediate(u64),
}

/// A memory operand of [`Fast`]: a [`MemoryOperand`] whose base and index
/// are general-purpose registers read whole, kept in 16 bytes instead of 24.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    /// Added to the base and the scaled index.
    pub displacement: u64,
    /// The base register, read whole.
    pub base: Option<u8>,
    /// The index register, read whole.
    pub index: Option<u8>,
    /// What the index is multiplied by: 1, 2, 4 or 8.
    pub scale: u8,
    /// Size of the accessed value in bytes.
    pub size: u8,
    /// The segment whose base is added (`fs` or `gs`).
    pub segment: Segment,
    /// Whether the address is truncated to 32 bits (a `0x67` prefix).
    pub address_size_32: bool,
}

impl Address {
    /// `m` as an [`Address`], when [`super::Exec::address`] reads its base
    /// and index whole: 64-bit registers, or 32-bit ones of an address that
    /// is truncated to 32 bits anyway.
    fn of(m: MemoryOperand) -> Option<Self> {
        let whole = |r: Option<Register>| match r {
            None => Some(None),
            Some(Register::Gpr { index, size: 8 }) => Some(Some(index & 15)),
            Some(Register::Gpr { index, size: 4 }) if m.address_size_32 => Some(Some(index & 15)),
            Some(_) => None,
        };
        Some(Address {
            displacement: m.displacement,
            base: whole(m.base)?,
            index: whole(m.index)?,
            scale: m.scale,
            size: m.size,
            segment: m.segment,
            address_size_32: m.address_size_32,
        })
    }
}

/// The operation of a decoded instruction, if it has one of these forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fast {
    /// Every other form, run by [`super::execute`].
    None,
    Nop,
    /// `mov r, r/imm`.
    Move {
        dst: Register,
        src: Source,
    },
    /// `mov r, [m]`.
    Load {
        dst: Register,
        mem: Address,
    },
    /// `mov [m], r/imm`.
    Store {
        mem: Address,
        src: Source,
    },
    /// `movzx r, [m]`.
    LoadZeroExtended {
        dst: Register,
        mem: Address,
    },
    /// `lea r64, [m]`.
    Lea {
        dst: u8,
        mem: Address,
    },
    /// `push r64`.
    Push(u8),
    /// `push imm`, the immediate sign-extended to 64 bits.
    PushImmediate(u64),
    /// `push [m]` of 8 bytes. The address is taken before rsp moves.
    PushLoad(Address),
    /// `mul r` or `imul r`: rax times `src` into rdx:rax (ax for a byte).
    MulWide {
        src: Register,
        signed: bool,
    },
    /// `movaps`, `movups`, `movdqa`, `movdqu`, `movapd` or `movupd` of an
    /// xmm register into another.
    XmmMove {
        dst: u8,
        src: u8,
    },
    /// The same of 16 bytes of memory into an xmm register. `aligned`
    /// for the moves that require a 16-byte aligned address.
    XmmLoad {
        dst: u8,
        mem: Address,
        aligned: bool,
    },
    /// The same of an xmm register into 16 bytes of memory.
    XmmStore {
        mem: Address,
        src: u8,
        aligned: bool,
    },
    /// `pxor` or `xorps` of an xmm register into another.
    XmmXor {
        dst: u8,
        src: u8,
    },
    /// `punpckl` or `punpckh` of bytes, words, dwords or quadwords,
    /// `packuswb`, `packsswb`, `packssdw`, `paddd`, `psubd`, `paddq`,
    /// `psubq`, `pmuludq`, `pand`, `por`, `pandn`, `pcmpeqb`, `pcmpeqw` or
    /// `pcmpeqd` of xmm register `src` into `dst`, `pshufd`, `pshuflw` or
    /// `pshufhw` of `src` into `dst` by `imm`, or `pslld` or `psrld` of
    /// `dst` by `imm` (`src` is `dst`), as [`crate::sse::packed`] has
    /// them.
    XmmPacked {
        op: Mnemonic,
        dst: u8,
        src: u8,
        imm: u8,
    },
    /// `pmovmskb r, xmm`: the top bit of each byte of `src`.
    Pmovmskb {
        dst: Register,
        src: u8,
    },
    /// `movd` (`size` 4) or `movq` (8) between an xmm register and a
    /// general one, or `movq` between xmm registers: the low `size` bytes,
    /// zero-extended into the whole destination.
    MoveScalar {
        dst: Register,
        src: Register,
        size: u8,
    },
    /// `movd` (`size` 4), or `movq` or `movsd` (8), of memory into an xmm
    /// register: the bytes zero-extended into the whole register.
    XmmLoadScalar {
        dst: u8,
        mem: Address,
        size: u8,
    },
    /// `movd` (`size` 4), or `movq` or `movsd` (8), of an xmm register into
    /// memory: its low `size` bytes.
    XmmStoreScalar {
        mem: Address,
        src: u8,
        size: u8,
    },
    /// `cmpxchg [m], r`, with `lock` or without: one atomic compare and
    /// exchange of memory with rax, as [`Exec::cmpxchg`] does.
    CmpxchgStore {
        mem: Address,
        src: Register,
    },
    /// `xchg [m], r` or `xchg r, [m]`, always locked: one atomic exchange,
    /// as [`Exec::xchg`] does.
    XchgStore {
        mem: Address,
        src: Register,
    },
    /// `imul r, r` (`a` is `dst`) or `imul r, r, imm`.
    Imul {
        dst: Register,
        a: Register,
        b: Source,
    },
    /// `pop r64`.
    Pop(u8),
    Jcc {
        condition: Condition,
        target: u64,
    },
    Jmp(u64),
    /// `jmp r64`.
    JmpRegister(u8),
    /// `jmp [m]` of 8 bytes.
    JmpLoad(Address),
    Call(u64),
    /// `call r64`.
    CallRegister(u8),
    /// `call [m]` of 8 bytes.
    CallLoad(Address),
    /// `ret` without an immediate.
    Ret,
    /// `op r, r/imm`.
    Alu {
        op: Alu,
        dst: Register,
        src: Source,
    },
    /// `cmp`/`test [m], r/imm`.
    Compare {
        op: Alu,
        mem: Address,
        src: Source,
    },
    /// `movzx`, `movsx` or `movsxd r, r`, and `cbw`, `cwde` and `cdqe`.
    Extend {
        dst: Register,
        src: Register,
        signed: bool,
    },
    /// `movsx` or `movsxd r, [m]`.
    LoadSignExtended {
        dst: Register,
        mem: Address,
    },
    /// `lea r32, [m]` or `lea r16, [m]`.
    LeaTruncated {
        dst: Register,
        mem: Address,
    },
    /// `setcc r8`.
    Set {
        condition: Condition,
        dst: Register,
    },
    /// `setcc [m8]`.
    SetStore {
        condition: Condition,
        mem: Address,
    },
    /// `cmovcc r, r`.
    Cmov {
        condition: Condition,
        dst: Register,
        src: Register,
    },
    /// `cmovcc r, [m]`: the memory is read whatever the condition.
    CmovLoad {
        condition: Condition,
        dst: Register,
        mem: Address,
    },
    /// `inc`, `dec`, `neg` or `not` of a register.
    Unary {
        op: Unary,
        dst: Register,
    },
    /// `inc`, `dec`, `neg` or `not` of memory, without `lock`.
    UnaryStore {
        op: Unary,
        mem: Address,
    },
    /// `op r, [m]`.
    AluLoad {
        op: Alu,
        dst: Register,
        mem: Address,
    },
    /// `op [m], r/imm` for an operation that writes its result (no `lock`).
    AluStore {
        op: Alu,
        mem: Address,
        src: Source,
    },
    /// `shl`, `shr`, `sar`, `rol` or `ror` of a register by an immediate
    /// (or 1), masked as the instruction masks it.
    Shift {
        op: Shift,
        dst: Register,
        count: u8,
    },
    /// `shl`, `shr` or `sar` of a register by `cl`, masked as the
    /// instruction masks it.
    ShiftByCl {
        op: Shift,
        dst: Register,
    },
    /// `adc` (`sub` false) or `sbb` (`sub` true) of a register and a
    /// register or an immediate, which takes CF as the carry in.
    Carry {
        sub: bool,
        dst: Register,
        src: Source,
    },
    /// `tzcnt`, `lzcnt`, `popcnt`, `bsf` or `bsr` of a register into one of
    /// its size.
    Count {
        op: Count,
        dst: Register,
        src: Register,
    },
    /// `bt` of a register by a register of its size or by an immediate,
    /// which is masked as the instruction masks it.
    BitTest {
        dst: Register,
        bit: Source,
    },
    /// `bswap r32` or `bswap r64`.
    Bswap(Register),
    /// `div r` or `idiv r`: rdx:rax (ax for a byte) by `src`, the quotient
    /// into rax (al) and the remainder into rdx (ah). It faults (#DE) when
    /// `src` is 0 or the quotient does not fit.
    Divide {
        src: Register,
        signed: bool,
    },
    /// `movsb`, `movsw`, `movsd` or `movsq`, with `rep` when `repeat`:
    /// `size` bytes from `[rsi]` (at the base of `segment`) to `[rdi]`, both
    /// stepping by `size` up or, with DF set, down. Repeated, it runs at most
    /// [`super::REP_CHUNK`] iterations a step, and a fault after the first of
    /// a step ends the step there, as `Exec::string` has it. The addresses are
    /// 64 bits wide.
    MoveString {
        size: u8,
        repeat: bool,
        segment: Segment,
    },
    /// `stosb`, `stosw`, `stosd` or `stosq`, with `rep` when `repeat`: the
    /// low `size` bytes of rax to `[rdi]`, which steps by `size` up or, with
    /// DF set, down. It repeats and stops as [`Fast::MoveString`] does. The
    /// address is 64 bits wide; a segment override does not apply to it.
    StoreString {
        size: u8,
        repeat: bool,
    },
}

/// A general register, or one of the high-byte registers ah, ch, dh and bh.
fn gpr(o: Option<Operand>) -> Option<Register> {
    match o {
        Some(Operand::Register(r @ (Register::Gpr { .. } | Register::GprHigh8 { .. }))) => Some(r),
        _ => None,
    }
}

fn gpr64(o: Option<Operand>) -> Option<u8> {
    match o {
        Some(Operand::Register(Register::Gpr { index, size: 8 })) => Some(index & 15),
        _ => None,
    }
}

/// A register of `size` bytes, or an immediate.
fn source(o: Option<Operand>, size: u8) -> Option<Source> {
    match o {
        Some(Operand::Register(r @ (Register::Gpr { .. } | Register::GprHigh8 { .. })))
            if r.size() == size =>
        {
            Some(Source::Register(r))
        }
        Some(Operand::Immediate(v)) => Some(Source::Immediate(v)),
        _ => None,
    }
}

fn memory(o: Option<Operand>) -> Option<MemoryOperand> {
    match o {
        Some(Operand::Memory(m)) => Some(m),
        _ => None,
    }
}

fn xmm(o: Option<Operand>) -> Option<u8> {
    match o {
        Some(Operand::Register(Register::Xmm(n))) => Some(n & 15),
        _ => None,
    }
}

fn address(o: Option<Operand>) -> Option<Address> {
    Address::of(memory(o)?)
}

/// The 8 bytes in memory that an indirect `jmp` or `call` goes to.
fn target(o: Option<Operand>) -> Option<Address> {
    address(o).filter(|mem| mem.size == 8)
}

fn branch(o: Option<Operand>) -> Option<u64> {
    match o {
        Some(Operand::Branch(t)) => Some(t.0),
        _ => None,
    }
}

impl Fast {
    /// The form of `i`, or [`Fast::None`].
    #[must_use]
    pub fn of(i: &Instruction) -> Self {
        // Of the locked instructions, only these have a form: their memory
        // access is one atomic operation either way.
        let lockable = matches!(i.mnemonic, Mnemonic::Cmpxchg | Mnemonic::Xchg);
        // Of the repeated instructions, only the string moves and stores
        // have a form.
        let repeatable = is_move_string(i.mnemonic) || is_store_string(i.mnemonic);
        if (i.lock && !lockable) || (i.rep != RepPrefix::None && !repeatable) {
            return Self::None;
        }
        Self::form(i).unwrap_or(Self::None)
    }

    fn form(i: &Instruction) -> Option<Self> {
        let (a, b) = (i.operand(0), i.operand(1));
        if i.mnemonic == Mnemonic::Imul && b.is_some() {
            let dst = gpr(a)?;
            let src = gpr(b)?;
            if src.size() != dst.size() {
                return None;
            }
            let (a, b) = match i.operand(2) {
                None => (dst, Source::Register(src)),
                Some(Operand::Immediate(v)) => (src, Source::Immediate(v)),
                Some(_) => return None,
            };
            return Some(Self::Imul { dst, a, b });
        }
        if matches!(
            i.mnemonic,
            Mnemonic::Pshufd | Mnemonic::Pshuflw | Mnemonic::Pshufhw
        ) {
            let Some(Operand::Immediate(imm)) = i.operand(2) else {
                return None;
            };
            return Some(Self::XmmPacked {
                op: i.mnemonic,
                dst: xmm(a)?,
                src: xmm(b)?,
                imm: imm as u8,
            });
        }
        if i.operand(2).is_some() {
            return None;
        }
        Some(match i.mnemonic {
            Mnemonic::Punpcklbw
            | Mnemonic::Punpcklwd
            | Mnemonic::Punpckldq
            | Mnemonic::Punpcklqdq
            | Mnemonic::Punpckhbw
            | Mnemonic::Punpckhwd
            | Mnemonic::Punpckhdq
            | Mnemonic::Punpckhqdq
            | Mnemonic::Packuswb
            | Mnemonic::Packsswb
            | Mnemonic::Packssdw
            | Mnemonic::Paddd
            | Mnemonic::Psubd
            | Mnemonic::Paddq
            | Mnemonic::Psubq
            | Mnemonic::Pmuludq
            | Mnemonic::Pand
            | Mnemonic::Por
            | Mnemonic::Pandn
            | Mnemonic::Pcmpeqb
            | Mnemonic::Pcmpeqw
            | Mnemonic::Pcmpeqd => Self::XmmPacked {
                op: i.mnemonic,
                dst: xmm(a)?,
                src: xmm(b)?,
                imm: 0,
            },
            Mnemonic::Pslld | Mnemonic::Psrld => {
                let dst = xmm(a)?;
                let Some(Operand::Immediate(count)) = b else {
                    return None;
                };
                Self::XmmPacked {
                    op: i.mnemonic,
                    dst,
                    src: dst,
                    imm: count.min(255) as u8,
                }
            }
            Mnemonic::Pmovmskb => match a {
                Some(Operand::Register(dst @ Register::Gpr { size: 4 | 8, .. })) => {
                    Self::Pmovmskb { dst, src: xmm(b)? }
                }
                _ => return None,
            },
            Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Movapd
            | Mnemonic::Movupd => {
                let aligned = matches!(
                    i.mnemonic,
                    Mnemonic::Movaps | Mnemonic::Movdqa | Mnemonic::Movapd
                );
                match (xmm(a), xmm(b)) {
                    (Some(dst), Some(src)) => Self::XmmMove { dst, src },
                    (Some(dst), None) => Self::XmmLoad {
                        dst,
                        mem: address(b).filter(|m| m.size == 16)?,
                        aligned,
                    },
                    (None, Some(src)) => Self::XmmStore {
                        mem: address(a).filter(|m| m.size == 16)?,
                        src,
                        aligned,
                    },
                    (None, None) => return None,
                }
            }
            Mnemonic::Pxor | Mnemonic::Xorps => Self::XmmXor {
                dst: xmm(a)?,
                src: xmm(b)?,
            },
            Mnemonic::Movd | Mnemonic::Movq => {
                let size = if i.mnemonic == Mnemonic::Movd { 4 } else { 8 };
                let scalar = |o: Option<Operand>| match o {
                    Some(Operand::Register(r @ Register::Xmm(_))) => Some(r),
                    Some(Operand::Register(r @ Register::Gpr { size: s, .. })) if s == size => {
                        Some(r)
                    }
                    _ => None,
                };
                let sized = |o: Option<Operand>| address(o).filter(|mem| mem.size == size);
                match (xmm(a), sized(b), sized(a), xmm(b)) {
                    (Some(dst), Some(mem), _, _) => {
                        return Some(Self::XmmLoadScalar { dst, mem, size });
                    }
                    (_, _, Some(mem), Some(src)) => {
                        return Some(Self::XmmStoreScalar { mem, src, size });
                    }
                    _ => {}
                }
                let (dst, src) = (scalar(a)?, scalar(b)?);
                if !matches!(dst, Register::Xmm(_)) && !matches!(src, Register::Xmm(_)) {
                    return None;
                }
                Self::MoveScalar { dst, src, size }
            }
            // `movsd` between xmm registers keeps the destination's high
            // half, so only its memory forms are scalar moves.
            Mnemonic::MovsdSse => {
                let sized = |o: Option<Operand>| address(o).filter(|mem| mem.size == 8);
                match (xmm(a), sized(b), sized(a), xmm(b)) {
                    (Some(dst), Some(mem), _, _) => Self::XmmLoadScalar { dst, mem, size: 8 },
                    (_, _, Some(mem), Some(src)) => Self::XmmStoreScalar { mem, src, size: 8 },
                    _ => return None,
                }
            }
            Mnemonic::Cmpxchg => {
                let mem = address(a)?;
                let src = gpr(b)?;
                if src.size() != mem.size || !matches!(mem.size, 1 | 2 | 4 | 8) {
                    return None;
                }
                Self::CmpxchgStore { mem, src }
            }
            Mnemonic::Xchg => {
                let (mem, src) = match (address(a), gpr(b)) {
                    (Some(mem), Some(src)) => (mem, src),
                    _ => (address(b)?, gpr(a)?),
                };
                if src.size() != mem.size || !matches!(mem.size, 1 | 2 | 4 | 8) {
                    return None;
                }
                Self::XchgStore { mem, src }
            }
            Mnemonic::Mul | Mnemonic::Imul if b.is_none() => Self::MulWide {
                src: gpr(a)?,
                signed: i.mnemonic == Mnemonic::Imul,
            },
            Mnemonic::Div | Mnemonic::Idiv if b.is_none() => Self::Divide {
                src: gpr(a)?,
                signed: i.mnemonic == Mnemonic::Idiv,
            },
            m if is_move_string(m) && !i.string_address_size_32 => Self::MoveString {
                size: i.implicit_size,
                repeat: i.rep != RepPrefix::None,
                segment: i.string_segment,
            },
            m if is_store_string(m) && !i.string_address_size_32 => Self::StoreString {
                size: i.implicit_size,
                repeat: i.rep != RepPrefix::None,
            },
            Mnemonic::Nop | Mnemonic::Endbr64 => Self::Nop,
            Mnemonic::Mov => {
                if let Some(dst) = gpr(a) {
                    match address(b) {
                        Some(mem) if mem.size == dst.size() => Self::Load { dst, mem },
                        Some(_) => return None,
                        None => Self::Move {
                            dst,
                            src: source(b, dst.size())?,
                        },
                    }
                } else {
                    let mem = address(a)?;
                    Self::Store {
                        mem,
                        src: source(b, mem.size)?,
                    }
                }
            }
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                let dst = gpr(a)?;
                let signed = i.mnemonic != Mnemonic::Movzx;
                if let Some(src) = gpr(b) {
                    if src.size() > dst.size() {
                        return None;
                    }
                    return Some(Self::Extend { dst, src, signed });
                }
                let mem = address(b)?;
                if signed {
                    if mem.size > dst.size() {
                        return None;
                    }
                    Self::LoadSignExtended { dst, mem }
                } else {
                    if !matches!(mem.size, 1 | 2) || dst.size() <= mem.size {
                        return None;
                    }
                    Self::LoadZeroExtended { dst, mem }
                }
            }
            Mnemonic::Cbw | Mnemonic::Cwde | Mnemonic::Cdqe if a.is_none() => {
                let size = match i.mnemonic {
                    Mnemonic::Cbw => 2,
                    Mnemonic::Cwde => 4,
                    _ => 8,
                };
                Self::Extend {
                    dst: Register::Gpr { index: 0, size },
                    src: Register::Gpr {
                        index: 0,
                        size: size / 2,
                    },
                    signed: true,
                }
            }
            Mnemonic::Lea => match gpr64(a) {
                Some(dst) => Self::Lea {
                    dst,
                    mem: address(b)?,
                },
                None => {
                    let dst = gpr(a)?;
                    if !matches!(dst.size(), 2 | 4) {
                        return None;
                    }
                    Self::LeaTruncated {
                        dst,
                        mem: address(b)?,
                    }
                }
            },
            Mnemonic::Push if i.implicit_size == 8 && b.is_none() => match a {
                Some(Operand::Immediate(v)) => Self::PushImmediate(v),
                Some(Operand::Memory(_)) => Self::PushLoad(target(a)?),
                _ => Self::Push(gpr64(a)?),
            },
            Mnemonic::Pop if i.implicit_size == 8 && b.is_none() => Self::Pop(gpr64(a)?),
            Mnemonic::Jcc(condition) => Self::Jcc {
                condition,
                target: branch(a)?,
            },
            Mnemonic::Jmp if b.is_none() => match (branch(a), gpr64(a)) {
                (Some(target), _) => Self::Jmp(target),
                (None, Some(r)) => Self::JmpRegister(r),
                (None, None) => Self::JmpLoad(target(a)?),
            },
            Mnemonic::Setcc(condition) => {
                if b.is_some() {
                    return None;
                }
                match gpr(a) {
                    Some(dst) if dst.size() == 1 => Self::Set { condition, dst },
                    Some(_) => return None,
                    None => {
                        let mem = address(a)?;
                        if mem.size != 1 {
                            return None;
                        }
                        Self::SetStore { condition, mem }
                    }
                }
            }
            Mnemonic::Cmovcc(condition) => {
                let dst = gpr(a)?;
                match gpr(b) {
                    Some(src) if src.size() == dst.size() => Self::Cmov {
                        condition,
                        dst,
                        src,
                    },
                    Some(_) => return None,
                    None => {
                        let mem = address(b)?;
                        if mem.size != dst.size() {
                            return None;
                        }
                        Self::CmovLoad {
                            condition,
                            dst,
                            mem,
                        }
                    }
                }
            }
            Mnemonic::Call if b.is_none() => match (branch(a), gpr64(a)) {
                (Some(target), _) => Self::Call(target),
                (None, Some(r)) => Self::CallRegister(r),
                (None, None) => Self::CallLoad(target(a)?),
            },
            Mnemonic::Ret if a.is_none() => Self::Ret,
            Mnemonic::Adc | Mnemonic::Sbb => {
                let dst = gpr(a)?;
                Self::Carry {
                    sub: i.mnemonic == Mnemonic::Sbb,
                    dst,
                    src: source(b, dst.size())?,
                }
            }
            m if Count::of(m).is_some() => {
                let (dst, src) = (gpr(a)?, gpr(b)?);
                if src.size() != dst.size() || dst.size() == 1 {
                    return None;
                }
                Self::Count {
                    op: Count::of(m)?,
                    dst,
                    src,
                }
            }
            Mnemonic::Bt => {
                let dst = gpr(a)?;
                if dst.size() == 1 {
                    return None;
                }
                let bit = match b {
                    // The width divides the size's range, so masking the
                    // immediate to the size first, as `Exec::bit` does,
                    // changes nothing.
                    Some(Operand::Immediate(v)) => {
                        Source::Immediate(v % u64::from(alu::bits(dst.size())))
                    }
                    _ => match gpr(b)? {
                        src if src.size() == dst.size() => Source::Register(src),
                        _ => return None,
                    },
                };
                Self::BitTest { dst, bit }
            }
            Mnemonic::Bswap if b.is_none() => match gpr(a)? {
                dst @ Register::Gpr { size: 4 | 8, .. } => Self::Bswap(dst),
                _ => return None,
            },
            m if Unary::of(m).is_some() => {
                if b.is_some() {
                    return None;
                }
                let op = Unary::of(m)?;
                match gpr(a) {
                    Some(dst) => Self::Unary { op, dst },
                    None => Self::UnaryStore {
                        op,
                        mem: address(a)?,
                    },
                }
            }
            m if Shift::of(m).is_some() => {
                let dst = gpr(a)?;
                let op = Shift::of(m)?;
                let count = match b {
                    None => 1,
                    Some(Operand::Immediate(v)) => v,
                    Some(Operand::Register(Register::Gpr { index: 1, size: 1 }))
                        if matches!(op, Shift::Shl | Shift::Shr | Shift::Sar) =>
                    {
                        return Some(Self::ShiftByCl { op, dst });
                    }
                    Some(_) => return None,
                } & if dst.size() == 8 { 63 } else { 31 };
                Self::Shift {
                    op,
                    dst,
                    count: count as u8,
                }
            }
            m => {
                let op = Alu::of(m)?;
                if let Some(dst) = gpr(a) {
                    match address(b) {
                        Some(mem) if mem.size == dst.size() => Self::AluLoad { op, dst, mem },
                        Some(_) => return None,
                        None => Self::Alu {
                            op,
                            dst,
                            src: source(b, dst.size())?,
                        },
                    }
                } else {
                    let mem = address(a)?;
                    let src = source(b, mem.size)?;
                    if op.writes() {
                        Self::AluStore { op, mem, src }
                    } else {
                        Self::Compare { op, mem, src }
                    }
                }
            }
        })
    }
}

impl Exec<'_> {
    /// [`Exec::linear`] of `m`.
    #[inline]
    fn fast_linear(&self, m: &Address) -> GuestAddr {
        GuestAddr(self.fast_address(m).0.wrapping_add(match m.segment {
            Segment::Fs => self.s.fs_base,
            Segment::Gs => self.s.gs_base,
            Segment::None => 0,
        }))
    }

    /// [`Exec::address`] of `m`.
    #[inline]
    fn fast_address(&self, m: &Address) -> GuestAddr {
        let mut ea = m.displacement;
        if let Some(b) = m.base {
            ea = ea.wrapping_add(self.s.gpr[usize::from(b)]);
        }
        if let Some(x) = m.index {
            ea = ea.wrapping_add(self.s.gpr[usize::from(x)].wrapping_mul(u64::from(m.scale)));
        }
        if m.address_size_32 {
            ea &= 0xffff_ffff;
        }
        GuestAddr(ea)
    }

    #[inline]
    fn source(&self, src: Source, size: u8) -> u64 {
        match src {
            Source::Register(r) => self.read_reg(r) & size_mask(size),
            Source::Immediate(v) => v & size_mask(size),
        }
    }
}

/// Runs `f`, the form of `i`, which is not [`Fast::None`], where the next
/// instruction is at `next`. When it fails, the state is as it was. `i` is
/// not read, so that running a form touches only the small part of a
/// decoded instruction that holds it.
#[inline]
pub(crate) fn execute(
    s: &mut CpuState,
    mem: &AddressSpace,
    i: &Instruction,
    f: &Fast,
    next: u64,
) -> Result<()> {
    let mut x = Exec { s, mem, i };
    let target = match *f {
        Fast::None | Fast::Nop => next,
        Fast::Move { dst, src } => {
            let v = x.source(src, dst.size());
            x.write_reg(dst, v);
            next
        }
        Fast::Load { dst, mem } => {
            let v = x.load(x.fast_linear(&mem), mem.size)?;
            x.write_reg(dst, v & size_mask(dst.size()));
            next
        }
        Fast::Store { mem, src } => {
            let v = x.source(src, mem.size);
            x.store(x.fast_linear(&mem), mem.size, v)?;
            next
        }
        Fast::LoadZeroExtended { dst, mem } => {
            let v = x.load(x.fast_linear(&mem), mem.size)?;
            x.write_reg(dst, v & size_mask(dst.size()));
            next
        }
        Fast::Lea { dst, mem } => {
            x.s.gpr[usize::from(dst)] = x.fast_address(&mem).0;
            next
        }
        Fast::Push(r) => {
            let v = x.s.gpr[usize::from(r)];
            x.push(v, 8)?;
            next
        }
        Fast::PushImmediate(v) => {
            x.push(v, 8)?;
            next
        }
        Fast::PushLoad(mem) => {
            let v = x.load(x.fast_linear(&mem), 8)?;
            x.push(v, 8)?;
            next
        }
        Fast::MulWide { src, signed } => {
            let size = src.size();
            let b = x.read_reg(src) & size_mask(size);
            let a = x.s.gpr[0] & size_mask(size);
            let (full, overflow) = if signed {
                let full = i128::from(sign_extend(a, size) as i64)
                    * i128::from(sign_extend(b, size) as i64);
                (full as u128, alu::imul(a, b, size).1)
            } else {
                let full = u128::from(a) * u128::from(b);
                (full, full >> alu::bits(size) != 0)
            };
            x.write_wide(size, full)?;
            let f = if overflow { flag::CF | flag::OF } else { 0 };
            x.set_status(flag::CF | flag::OF, f);
            next
        }
        Fast::CmpxchgStore { mem, src } => {
            let size = mem.size;
            let acc = Register::Gpr { index: 0, size };
            let expected = x.read_reg(acc) & size_mask(size);
            let new = x.read_reg(src) & size_mask(size);
            let current = x
                .mem
                .atomic(
                    x.fast_linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::CompareExchange {
                        expected: u128::from(expected),
                        replacement: u128::from(new),
                    },
                )?
                .old as u64;
            let (_, f) = alu::sub(expected, current, false, size);
            if expected != current {
                x.write_reg(acc, current);
            }
            x.set_status(flag::STATUS, f);
            next
        }
        Fast::XchgStore { mem, src } => {
            let size = mem.size;
            let value = x.read_reg(src) & size_mask(size);
            let old = x
                .mem
                .atomic(
                    x.fast_linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::Exchange(u128::from(value)),
                )?
                .old as u64;
            x.write_reg(src, old & size_mask(size));
            next
        }
        Fast::XmmMove { dst, src } => {
            x.s.xmm[usize::from(dst)] = x.s.xmm[usize::from(src)];
            next
        }
        Fast::XmmLoad { dst, mem, aligned } => {
            let address = x.fast_linear(&mem);
            if aligned && !address.0.is_multiple_of(16) {
                return Err(Stop::GeneralProtection);
            }
            let mut bytes = [0; 16];
            x.mem.read(address, &mut bytes)?;
            x.s.xmm[usize::from(dst)] = u128::from_le_bytes(bytes);
            next
        }
        Fast::XmmStore { mem, src, aligned } => {
            let address = x.fast_linear(&mem);
            if aligned && !address.0.is_multiple_of(16) {
                return Err(Stop::GeneralProtection);
            }
            x.mem
                .write(address, &x.s.xmm[usize::from(src)].to_le_bytes())?;
            next
        }
        Fast::XmmXor { dst, src } => {
            x.s.xmm[usize::from(dst)] ^= x.s.xmm[usize::from(src)];
            next
        }
        Fast::XmmPacked { op, dst, src, imm } => {
            let a = x.s.xmm[usize::from(dst)];
            let b = if matches!(op, Mnemonic::Pslld | Mnemonic::Psrld) {
                u128::from(imm)
            } else {
                x.s.xmm[usize::from(src)]
            };
            let Some(v) = crate::sse::packed(op, a, b, imm, x.s.xmm[0]) else {
                return Err(Stop::Invalid);
            };
            x.s.xmm[usize::from(dst)] = v;
            next
        }
        Fast::Pmovmskb { dst, src } => {
            let v = x.s.xmm[usize::from(src)];
            let mut mask = 0;
            for n in 0..16 {
                mask |= ((v >> (n * 8 + 7)) as u64 & 1) << n;
            }
            x.write_reg(dst, mask);
            next
        }
        Fast::MoveScalar { dst, src, size } => {
            let v = x.read_reg(src) & size_mask(size);
            x.write_reg(dst, v);
            next
        }
        Fast::XmmLoadScalar { dst, mem, size } => {
            let v = x.load(x.fast_linear(&mem), size)?;
            x.s.xmm[usize::from(dst)] = u128::from(v & size_mask(size));
            next
        }
        Fast::XmmStoreScalar { mem, src, size } => {
            let v = x.s.xmm[usize::from(src)] as u64 & size_mask(size);
            x.store(x.fast_linear(&mem), size, v)?;
            next
        }
        Fast::Imul { dst, a, b } => {
            let size = dst.size();
            let a = x.read_reg(a) & size_mask(size);
            let b = x.source(b, size);
            let (r, overflow) = alu::imul(a, b, size);
            x.write_reg(dst, r);
            let f = if overflow { flag::CF | flag::OF } else { 0 };
            x.set_status(flag::CF | flag::OF, f);
            next
        }
        Fast::Pop(r) => {
            let v = x.pop(8)?;
            x.s.gpr[usize::from(r)] = v;
            next
        }
        Fast::Jcc { condition, target } => {
            if alu::condition(x.s.rflags, condition) {
                target
            } else {
                next
            }
        }
        Fast::Jmp(target) => target,
        Fast::JmpRegister(r) => x.s.gpr[usize::from(r)],
        Fast::JmpLoad(mem) => x.load(x.fast_linear(&mem), 8)?,
        Fast::Call(target) => {
            x.push(next, 8)?;
            target
        }
        Fast::CallRegister(r) => {
            let target = x.s.gpr[usize::from(r)];
            x.push(next, 8)?;
            target
        }
        Fast::CallLoad(mem) => {
            let target = x.load(x.fast_linear(&mem), 8)?;
            x.push(next, 8)?;
            target
        }
        Fast::Ret => x.pop(8)?,
        Fast::Alu { op, dst, src } => {
            let size = dst.size();
            let b = x.source(src, size);
            let a = x.read_reg(dst) & size_mask(size);
            let (r, flags) = op.apply(a, b, size);
            if op.writes() {
                x.write_reg(dst, r & size_mask(size));
            }
            x.set_status(flag::STATUS, flags);
            next
        }
        Fast::Compare { op, mem, src } => {
            let size = mem.size;
            let b = x.source(src, size);
            let a = x.load(x.fast_linear(&mem), size)?;
            let (_, flags) = op.apply(a, b, size);
            x.set_status(flag::STATUS, flags);
            next
        }
        Fast::Extend { dst, src, signed } => {
            let v = x.read_reg(src) & size_mask(src.size());
            let v = if signed {
                sign_extend(v, src.size())
            } else {
                v
            };
            x.write_reg(dst, v & size_mask(dst.size()));
            next
        }
        Fast::LoadSignExtended { dst, mem } => {
            let v = x.load(x.fast_linear(&mem), mem.size)?;
            x.write_reg(dst, sign_extend(v, mem.size) & size_mask(dst.size()));
            next
        }
        Fast::LeaTruncated { dst, mem } => {
            let ea = x.fast_address(&mem).0;
            x.write_reg(dst, ea & size_mask(dst.size()));
            next
        }
        Fast::Set { condition, dst } => {
            x.write_reg(dst, u64::from(alu::condition(x.s.rflags, condition)));
            next
        }
        Fast::SetStore { condition, mem } => {
            let v = u64::from(alu::condition(x.s.rflags, condition));
            x.store(x.fast_linear(&mem), 1, v)?;
            next
        }
        Fast::Cmov {
            condition,
            dst,
            src,
        } => {
            let size = dst.size();
            let v = if alu::condition(x.s.rflags, condition) {
                x.read_reg(src)
            } else {
                x.read_reg(dst)
            };
            x.write_reg(dst, v & size_mask(size));
            next
        }
        Fast::CmovLoad {
            condition,
            dst,
            mem,
        } => {
            let size = dst.size();
            let v = x.load(x.fast_linear(&mem), size)?;
            let v = if alu::condition(x.s.rflags, condition) {
                v
            } else {
                x.read_reg(dst)
            };
            x.write_reg(dst, v & size_mask(size));
            next
        }
        Fast::Unary { op, dst } => {
            let size = dst.size();
            let a = x.read_reg(dst) & size_mask(size);
            let (r, update, flags) = op.apply(a, size);
            x.write_reg(dst, r);
            x.set_status(update, flags);
            next
        }
        Fast::UnaryStore { op, mem } => {
            let size = mem.size;
            let address = x.fast_linear(&mem);
            let a = x.load(address, size)?;
            let (r, update, flags) = op.apply(a, size);
            x.store(address, size, r)?;
            x.set_status(update, flags);
            next
        }
        Fast::AluLoad { op, dst, mem } => {
            let size = dst.size();
            let b = x.load(x.fast_linear(&mem), size)?;
            let a = x.read_reg(dst) & size_mask(size);
            let (r, flags) = op.apply(a, b, size);
            if op.writes() {
                x.write_reg(dst, r & size_mask(size));
            }
            x.set_status(flag::STATUS, flags);
            next
        }
        Fast::AluStore { op, mem, src } => {
            let size = mem.size;
            let b = x.source(src, size);
            let address = x.fast_linear(&mem);
            let a = x.load(address, size)?;
            let (r, flags) = op.apply(a, b, size);
            x.store(address, size, r & size_mask(size))?;
            x.set_status(flag::STATUS, flags);
            next
        }
        Fast::Shift { op, dst, count } => {
            let size = dst.size();
            let a = x.read_reg(dst) & size_mask(size);
            let (r, update, flags) = op.apply(a, count, size);
            x.write_reg(dst, r);
            x.set_status(update, flags);
            next
        }
        Fast::ShiftByCl { op, dst } => {
            let size = dst.size();
            let a = x.read_reg(dst) & size_mask(size);
            let count = x.s.gpr[1] as u8 & if size == 8 { 63 } else { 31 };
            let (r, update, flags) = op.apply(a, count, size);
            x.write_reg(dst, r);
            x.set_status(update, flags);
            next
        }
        Fast::Carry { sub, dst, src } => {
            carry(&mut x, sub, dst, src);
            next
        }
        Fast::Count { op, dst, src } => {
            count(&mut x, op, dst, src);
            next
        }
        Fast::BitTest { dst, bit } => {
            bit_test(&mut x, dst, bit);
            next
        }
        Fast::Bswap(dst) => {
            bswap(&mut x, dst);
            next
        }
        Fast::Divide { signed, .. } => {
            divide(&mut x, signed)?;
            next
        }
        Fast::MoveString { .. } | Fast::StoreString { .. } => {
            if string(&mut x)? {
                next
            } else {
                // Not finished: the same instruction runs again next step.
                x.s.rip.0
            }
        }
    };
    x.s.rip = GuestAddr(target);
    Ok(())
}

// The forms below run out of line, so that the arms of `execute` that most
// instructions take stay as they are.

/// [`Fast::Carry`], as [`Exec::alu`] has it.
#[inline(never)]
fn carry(x: &mut Exec<'_>, sub: bool, dst: Register, src: Source) {
    let size = dst.size();
    let b = x.source(src, size);
    let a = x.read_reg(dst) & size_mask(size);
    let cf = x.s.flag(flag::CF);
    let (r, flags) = if sub {
        alu::sub(a, b, cf, size)
    } else {
        alu::add(a, b, cf, size)
    };
    x.write_reg(dst, r);
    x.set_status(flag::STATUS, flags);
}

/// [`Fast::Count`].
#[inline(never)]
fn count(x: &mut Exec<'_>, op: Count, dst: Register, src: Register) {
    let value = x.read_reg(src) & size_mask(src.size());
    let (r, update, flags) = op.apply(value, dst.size());
    if let Some(r) = r {
        x.write_reg(dst, r);
    }
    x.set_status(update, flags);
}

/// [`Fast::BitTest`], as [`Exec::bit`] has it.
#[inline(never)]
fn bit_test(x: &mut Exec<'_>, dst: Register, bit: Source) {
    let size = dst.size();
    let n = x.source(bit, size) % u64::from(alu::bits(size));
    let set = x.read_reg(dst) >> n & 1 != 0;
    x.set_status(flag::CF, if set { flag::CF } else { 0 });
}

/// [`Fast::Bswap`].
#[inline(never)]
fn bswap(x: &mut Exec<'_>, dst: Register) {
    let v = x.read_reg(dst);
    let r = if dst.size() == 8 {
        v.swap_bytes()
    } else {
        u64::from((v as u32).swap_bytes())
    };
    x.write_reg(dst, r);
}

/// [`Fast::Divide`], which [`Exec::divide`] runs: it reads the instruction's
/// register.
#[inline(never)]
fn divide(x: &mut Exec<'_>, signed: bool) -> Result<()> {
    x.divide(signed)
}

/// [`Fast::MoveString`] and [`Fast::StoreString`], which [`Exec::string`]
/// runs: it reads the instruction. False when the instruction is to run
/// again.
#[inline(never)]
fn string(x: &mut Exec<'_>) -> Result<bool> {
    x.string(x.i.mnemonic)
}

fn is_move_string(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq
    )
}

fn is_store_string(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq
    )
}
