//! Execution of one decoded instruction.

use paludarium_decoder::{
    Instruction, MemoryOperand, Mnemonic, Operand, Register, RepPrefix, Segment,
};
use paludarium_mmu::{AddressSpace, AtomicOp, AtomicWidth, Fault};
use paludarium_types::GuestAddr;

use crate::alu::{self, ShiftKind, sign_extend, size_mask};
use crate::softfloat::{F32, F64};
use crate::state::{CpuState, FX_WRITTEN, flag, reg};
use crate::x87::{
    Arithmetic, ENVIRONMENT, LN_2, LOG2_10, LOG2_E, LOG10_2, PI, float_operand, integer_value,
};
use core::cmp::Ordering;

/// Why executing an instruction did not simply continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Fault(Fault),
    /// Not implemented / not valid in this form (SIGILL).
    Invalid,
    Halt,
    GeneralProtection,
    ArithmeticFault,
    FloatingPointFault(u8),
    /// `syscall` executed; the state already points past it.
    Syscall,
}

impl From<Fault> for Stop {
    fn from(f: Fault) -> Self {
        Stop::Fault(f)
    }
}

/// The whole area, all of which must be there for either instruction.
const FX_AREA: usize = 512;
type Result<T> = core::result::Result<T, Stop>;

mod fast;
pub(crate) use fast::{Fast, execute as execute_fast};

fn atomic_width(size: u8) -> Result<AtomicWidth> {
    match size {
        1 => Ok(AtomicWidth::W8),
        2 => Ok(AtomicWidth::W16),
        4 => Ok(AtomicWidth::W32),
        8 => Ok(AtomicWidth::W64),
        16 => Ok(AtomicWidth::W128),
        _ => Err(Stop::Invalid),
    }
}

/// Upper bound of `rep` iterations per step, so that a huge `rcx` cannot
/// keep one step running forever (the instruction is resumed next step, as
/// on hardware where `rep` is interruptible).
const REP_CHUNK: u64 = 4096;

pub(crate) fn is_comparison_string(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
    )
}
/// Whether `i` leaves the vector state (`xmm` and `mxcsr`) alone: a
/// general-purpose instruction, whose handler below never reaches the
/// vector code, without an `xmm` operand, which is the only way it could
/// write one. Anything else may change it.
pub(crate) fn keeps_vector_state(i: &Instruction) -> bool {
    let general = matches!(
        i.mnemonic,
        Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Shld
            | Mnemonic::Shrd
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Tzcnt
            | Mnemonic::Lzcnt
            | Mnemonic::Popcnt
            | Mnemonic::Movbe
            | Mnemonic::Bswap
            | Mnemonic::Mov
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Movzx
            | Mnemonic::Cdqe
            | Mnemonic::Cdq
            | Mnemonic::Cqo
            | Mnemonic::Lea
            | Mnemonic::Xchg
            | Mnemonic::Cmpxchg
            | Mnemonic::Xadd
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Jmp
            | Mnemonic::Jcc(_)
            | Mnemonic::Setcc(_)
            | Mnemonic::Cmovcc(_)
            | Mnemonic::Leave
            | Mnemonic::Nop
            | Mnemonic::Endbr64
    );
    general
        && !i
            .operands()
            .any(|o| matches!(o, Operand::Register(Register::Xmm(_))))
}

/// Whether `i` changes no register before the last thing that can make it
/// fail, so that a failure leaves nothing to put back: its handler below
/// reads, then writes its one destination, and sets the flags, the stack
/// pointer or the instruction pointer only after that. A `pop` to memory
/// moves the stack pointer first, so only one to a register qualifies.
pub(crate) fn fails_cleanly(i: &Instruction) -> bool {
    match i.mnemonic {
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Xor
        | Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Inc
        | Mnemonic::Dec
        | Mnemonic::Neg
        | Mnemonic::Not
        | Mnemonic::Mov
        | Mnemonic::Movsx
        | Mnemonic::Movsxd
        | Mnemonic::Movzx
        | Mnemonic::Lea
        | Mnemonic::Push
        | Mnemonic::Call
        | Mnemonic::Ret
        | Mnemonic::Jmp
        | Mnemonic::Jcc(_)
        | Mnemonic::Setcc(_)
        | Mnemonic::Cmovcc(_)
        | Mnemonic::Nop
        | Mnemonic::Endbr64 => true,
        Mnemonic::Pop => matches!(i.operand(0), Some(Operand::Register(_))),
        _ => false,
    }
}

pub(crate) fn is_string(m: Mnemonic) -> bool {
    is_comparison_string(m)
        || matches!(
            m,
            Mnemonic::Movsb
                | Mnemonic::Movsw
                | Mnemonic::Movsd
                | Mnemonic::Movsq
                | Mnemonic::Stosb
                | Mnemonic::Stosw
                | Mnemonic::Stosd
                | Mnemonic::Stosq
                | Mnemonic::Lodsb
                | Mnemonic::Lodsw
                | Mnemonic::Lodsd
                | Mnemonic::Lodsq
        )
}

struct Exec<'a> {
    s: &'a mut CpuState,
    mem: &'a AddressSpace,
    i: &'a Instruction,
}

/// An x87 instruction's operation, and whether it takes its operands the other
/// way around.
fn x87_arithmetic(m: Mnemonic) -> (Arithmetic, bool) {
    use Mnemonic as M;
    match m {
        M::Fadd | M::Faddp | M::Fiadd => (Arithmetic::Add, false),
        M::Fsub | M::Fsubp | M::Fisub => (Arithmetic::Subtract, false),
        M::Fsubr | M::Fsubrp | M::Fisubr => (Arithmetic::Subtract, true),
        M::Fmul | M::Fmulp | M::Fimul => (Arithmetic::Multiply, false),
        M::Fdiv | M::Fdivp | M::Fidiv => (Arithmetic::Divide, false),
        _ => (Arithmetic::Divide, true),
    }
}

fn op(i: &Instruction, n: usize) -> Result<Operand> {
    i.operand(n).ok_or(Stop::Invalid)
}

impl Exec<'_> {
    fn read_reg(&self, r: Register) -> u64 {
        match r {
            Register::Gpr { index, size } => self.s.gpr[usize::from(index & 15)] & size_mask(size),
            Register::GprHigh8 { index } => (self.s.gpr[usize::from(index & 3)] >> 8) & 0xff,
            Register::Xmm(n) => self.s.xmm[usize::from(n & 15)] as u64,
            // Only `Exec::x87` has these, and it reads them itself.
            Register::St(_) => 0,
        }
    }

    fn write_reg(&mut self, r: Register, value: u64) {
        match r {
            Register::Gpr { index, size } => {
                let slot = &mut self.s.gpr[usize::from(index & 15)];
                *slot = match size {
                    8 => value,
                    // 32-bit writes zero the upper half.
                    4 => value & 0xffff_ffff,
                    _ => (*slot & !size_mask(size)) | (value & size_mask(size)),
                };
            }
            Register::GprHigh8 { index } => {
                let slot = &mut self.s.gpr[usize::from(index & 3)];
                *slot = (*slot & !0xff00) | ((value & 0xff) << 8);
            }
            Register::Xmm(n) => self.s.xmm[usize::from(n & 15)] = u128::from(value),
            Register::St(_) => {}
        }
    }

    fn address(&self, m: &MemoryOperand) -> GuestAddr {
        let reg_value = |r: Register| match r {
            Register::Gpr { index, size } => self.s.gpr[usize::from(index & 15)] & size_mask(size),
            _ => 0,
        };
        let mut ea = m.displacement;
        if let Some(b) = m.base {
            ea = ea.wrapping_add(reg_value(b));
        }
        if let Some(x) = m.index {
            ea = ea.wrapping_add(reg_value(x).wrapping_mul(u64::from(m.scale)));
        }
        if m.address_size_32 {
            ea &= 0xffff_ffff;
        }
        GuestAddr(ea)
    }

    fn linear(&self, m: &MemoryOperand) -> GuestAddr {
        let ea = self.address(m);
        match m.segment {
            Segment::Fs => ea.wrapping_add(self.s.fs_base),
            Segment::Gs => ea.wrapping_add(self.s.gs_base),
            Segment::None => ea,
        }
    }

    fn load(&self, addr: GuestAddr, size: u8) -> Result<u64> {
        Ok(self.mem.read_value(addr, usize::from(size.min(8)))?)
    }

    fn store(&self, addr: GuestAddr, size: u8, value: u64) -> Result<()> {
        self.mem
            .write_value(addr, usize::from(size.min(8)), value)?;
        Ok(())
    }

    /// Size of an operand in bytes (immediates take the size of `other`).
    fn size_of(o: Operand, other: Option<Operand>) -> u8 {
        match o {
            Operand::Register(r) => r.size(),
            Operand::Memory(m) => m.size,
            Operand::Immediate(_) | Operand::Branch(_) => match other {
                Some(x) => Self::size_of(x, None),
                None => 8,
            },
        }
    }

    fn read(&self, o: Operand, size: u8) -> Result<u64> {
        match o {
            Operand::Register(r) => Ok(self.read_reg(r) & size_mask(size)),
            Operand::Immediate(v) => Ok(v & size_mask(size)),
            Operand::Memory(m) => self.load(self.linear(&m), size),
            Operand::Branch(t) => Ok(t.0),
        }
    }

    fn write(&mut self, o: Operand, size: u8, value: u64) -> Result<()> {
        match o {
            Operand::Register(r) => {
                self.write_reg(r, value & size_mask(size));
                Ok(())
            }
            Operand::Memory(m) => self.store(self.linear(&m), size, value),
            Operand::Immediate(_) | Operand::Branch(_) => Err(Stop::Invalid),
        }
    }

    fn set_status(&mut self, update: u64, value: u64) {
        self.s.rflags = (self.s.rflags & !update) | (value & update);
    }

    fn push(&mut self, value: u64, size: u8) -> Result<()> {
        let rsp = self.s.gpr[reg::RSP].wrapping_sub(u64::from(size));
        self.store(GuestAddr(rsp), size, value)?;
        self.s.gpr[reg::RSP] = rsp;
        Ok(())
    }

    fn pop(&mut self, size: u8) -> Result<u64> {
        let rsp = self.s.gpr[reg::RSP];
        let value = self.load(GuestAddr(rsp), size)?;
        self.s.gpr[reg::RSP] = rsp.wrapping_add(u64::from(size));
        Ok(value)
    }

    fn enter(&mut self) -> Result<()> {
        let size = self.i.implicit_size;
        let allocation = self.read(op(self.i, 0)?, 2)?;
        let nesting = self.read(op(self.i, 1)?, 1)? & 31;
        let old_bp = self.s.gpr[reg::RBP];
        self.push(old_bp, size)?;
        let frame = self.s.gpr[reg::RSP];
        let mut cursor = old_bp;
        if nesting != 0 {
            for _ in 1..nesting {
                cursor = cursor.wrapping_sub(u64::from(size));
                // Native ENTERW retains the full chain address even when
                // decrementing crosses the low 16-bit boundary.
                let value = self.load(GuestAddr(cursor), size)?;
                self.push(value, size)?;
            }
            self.push(frame, size)?;
        }
        self.s.gpr[reg::RBP] = if size == 2 {
            (old_bp & !0xffff) | (frame & 0xffff)
        } else {
            frame
        };
        let stack = self.s.gpr[reg::RSP].wrapping_sub(allocation);
        self.mem.check_write(GuestAddr(stack), 1)?;
        self.s.gpr[reg::RSP] = stack;
        Ok(())
    }

    fn binary(&self) -> Result<(Operand, Operand, u8)> {
        let dst = op(self.i, 0)?;
        let src = op(self.i, 1)?;
        Ok((dst, src, Self::size_of(dst, None)))
    }

    fn alu(&mut self, m: Mnemonic) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let b = self.read(src, size)?;
        let cf = self.s.flag(flag::CF);
        let locked = self.i.lock && matches!(dst, Operand::Memory(_));
        let a = if locked {
            let Operand::Memory(mem) = dst else {
                return Err(Stop::Invalid);
            };
            let operation = match m {
                Mnemonic::Add => AtomicOp::Add(u128::from(b)),
                Mnemonic::Adc => AtomicOp::Add(u128::from(b) + u128::from(cf)),
                Mnemonic::Sub => AtomicOp::Sub(u128::from(b)),
                Mnemonic::Sbb => AtomicOp::Sub(u128::from(b) + u128::from(cf)),
                Mnemonic::And => AtomicOp::And(u128::from(b)),
                Mnemonic::Or => AtomicOp::Or(u128::from(b)),
                Mnemonic::Xor => AtomicOp::Xor(u128::from(b)),
                _ => return Err(Stop::Invalid),
            };
            self.mem
                .atomic(self.linear(&mem), atomic_width(size)?, operation)?
                .old as u64
        } else {
            self.read(dst, size)?
        };
        let ((r, f), writes) = match m {
            Mnemonic::Add => (alu::add(a, b, false, size), true),
            Mnemonic::Adc => (alu::add(a, b, cf, size), true),
            Mnemonic::Sub => (alu::sub(a, b, false, size), true),
            Mnemonic::Sbb => (alu::sub(a, b, cf, size), true),
            Mnemonic::Cmp => (alu::sub(a, b, false, size), false),
            Mnemonic::And => ((a & b, alu::logic(a & b, size)), true),
            Mnemonic::Or => ((a | b, alu::logic(a | b, size)), true),
            Mnemonic::Xor => ((a ^ b, alu::logic(a ^ b, size)), true),
            Mnemonic::Test => ((a & b, alu::logic(a & b, size)), false),
            _ => return Err(Stop::Invalid),
        };
        if writes && !locked {
            self.write(dst, size, r)?;
        }
        self.set_status(flag::STATUS, f);
        Ok(())
    }

    fn unary(&mut self, m: Mnemonic) -> Result<()> {
        let dst = op(self.i, 0)?;
        let size = Self::size_of(dst, None);
        let locked = self.i.lock && matches!(dst, Operand::Memory(_));
        let a = if locked {
            let Operand::Memory(mem) = dst else {
                return Err(Stop::Invalid);
            };
            let operation = match m {
                Mnemonic::Inc => AtomicOp::Add(1),
                Mnemonic::Dec => AtomicOp::Sub(1),
                Mnemonic::Neg => AtomicOp::Neg,
                Mnemonic::Not => AtomicOp::Not,
                _ => return Err(Stop::Invalid),
            };
            self.mem
                .atomic(self.linear(&mem), atomic_width(size)?, operation)?
                .old as u64
        } else {
            self.read(dst, size)?
        };
        match m {
            Mnemonic::Inc | Mnemonic::Dec => {
                let (r, f) = if m == Mnemonic::Inc {
                    alu::add(a, 1, false, size)
                } else {
                    alu::sub(a, 1, false, size)
                };
                if !locked {
                    self.write(dst, size, r)?;
                }
                self.set_status(flag::STATUS & !flag::CF, f);
            }
            Mnemonic::Neg => {
                let (r, f) = alu::sub(0, a, false, size);
                if !locked {
                    self.write(dst, size, r)?;
                }
                self.set_status(flag::STATUS, f);
            }
            Mnemonic::Not => {
                if !locked {
                    self.write(dst, size, !a)?;
                }
            }
            _ => return Err(Stop::Invalid),
        }
        Ok(())
    }

    fn shift(&mut self, kind: ShiftKind) -> Result<()> {
        let dst = op(self.i, 0)?;
        let size = Self::size_of(dst, None);
        let count = match self.i.operand(1) {
            Some(o) => self.read(o, 1)?,
            None => 1,
        };
        let a = self.read(dst, size)?;
        match alu::shift(kind, a, count, size) {
            Some((r, f)) => {
                self.write(dst, size, r)?;
                self.set_status(flag::STATUS, f);
            }
            // A zero count leaves the flags alone, but the destination is
            // still written: a 32-bit register is zero-extended.
            None => self.write(dst, size, a)?,
        }
        Ok(())
    }

    fn imul(&mut self) -> Result<()> {
        match self.i.operand_count() {
            1 => {
                let src = op(self.i, 0)?;
                let size = Self::size_of(src, None);
                let b = self.read(src, size)?;
                let a = self.s.gpr[reg::RAX] & size_mask(size);
                let full = i128::from(sign_extend(a, size) as i64)
                    * i128::from(sign_extend(b, size) as i64);
                self.write_wide(size, full as u128)?;
                let (_, overflow) = alu::imul(a, b, size);
                self.set_status(
                    flag::CF | flag::OF,
                    if overflow { flag::CF | flag::OF } else { 0 },
                );
                Ok(())
            }
            n => {
                let dst = op(self.i, 0)?;
                let size = Self::size_of(dst, None);
                let (a, b) = if n == 2 {
                    (self.read(dst, size)?, self.read(op(self.i, 1)?, size)?)
                } else {
                    (
                        self.read(op(self.i, 1)?, size)?,
                        self.read(op(self.i, 2)?, size)?,
                    )
                };
                let (r, overflow) = alu::imul(a, b, size);
                self.write(dst, size, r)?;
                self.set_status(
                    flag::CF | flag::OF,
                    if overflow { flag::CF | flag::OF } else { 0 },
                );
                Ok(())
            }
        }
    }

    /// Writes a double-width result to rdx:rax (ax for 8-bit operands).
    fn write_wide(&mut self, size: u8, value: u128) -> Result<()> {
        let bits = alu::bits(size);
        let low = value as u64 & size_mask(size);
        let high = (value >> bits) as u64 & size_mask(size);
        let rax = Register::Gpr { index: 0, size };
        if size == 1 {
            self.write_reg(Register::Gpr { index: 0, size: 2 }, (high << 8) | low);
        } else {
            self.write_reg(rax, low);
            self.write_reg(Register::Gpr { index: 2, size }, high);
        }
        Ok(())
    }

    fn mul(&mut self) -> Result<()> {
        let src = op(self.i, 0)?;
        let size = Self::size_of(src, None);
        let b = self.read(src, size)?;
        let a = self.s.gpr[reg::RAX] & size_mask(size);
        let full = u128::from(a) * u128::from(b);
        self.write_wide(size, full)?;
        let overflow = full >> alu::bits(size) != 0;
        self.set_status(
            flag::CF | flag::OF,
            if overflow { flag::CF | flag::OF } else { 0 },
        );
        Ok(())
    }

    fn divide(&mut self, signed: bool) -> Result<()> {
        let src = op(self.i, 0)?;
        let size = Self::size_of(src, None);
        let divisor = self.read(src, size)?;
        if divisor == 0 {
            return Err(Stop::ArithmeticFault);
        }
        let bits = alu::bits(size);
        let (high, low) = if size == 1 {
            let ax = self.s.gpr[reg::RAX] & 0xffff;
            (ax >> 8, ax & 0xff)
        } else {
            (
                self.s.gpr[reg::RDX] & size_mask(size),
                self.s.gpr[reg::RAX] & size_mask(size),
            )
        };
        let dividend = (u128::from(high) << bits) | u128::from(low);
        let (q, r) = if signed {
            let shift = 128 - 2 * bits;
            let n = ((dividend << shift) as i128) >> shift;
            let d = i128::from(sign_extend(divisor, size) as i64);
            let q = n.checked_div(d).ok_or(Stop::ArithmeticFault)?;
            let r = n.checked_rem(d).ok_or(Stop::ArithmeticFault)?;
            let lo = -(1i128 << (bits - 1));
            let hi = (1i128 << (bits - 1)) - 1;
            if q < lo || q > hi {
                return Err(Stop::ArithmeticFault);
            }
            (q as u64 & size_mask(size), r as u64 & size_mask(size))
        } else {
            let q = dividend / u128::from(divisor);
            if q > u128::from(size_mask(size)) {
                return Err(Stop::ArithmeticFault);
            }
            (q as u64, (dividend % u128::from(divisor)) as u64)
        };
        if size == 1 {
            self.write_reg(Register::Gpr { index: 0, size: 2 }, (r << 8) | q);
        } else {
            self.write_reg(Register::Gpr { index: 0, size }, q);
            self.write_reg(Register::Gpr { index: 2, size }, r);
        }
        Ok(())
    }

    fn bit(&mut self, mnemonic: Mnemonic) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let offset = self.read(src, size)?;
        let (dst, bit) = match (dst, src) {
            (Operand::Memory(m), Operand::Register(_)) => {
                let signed = sign_extend(offset, size) as i64;
                let width = i64::from(alu::bits(size));
                let mut adjusted = m;
                adjusted.displacement = adjusted
                    .displacement
                    .wrapping_add(signed.div_euclid(width).wrapping_mul(i64::from(size)) as u64);
                (Operand::Memory(adjusted), signed.rem_euclid(width) as u64)
            }
            _ => (dst, offset % u64::from(alu::bits(size))),
        };
        let mask = 1u64 << bit;
        let old = if self.i.lock {
            let Operand::Memory(memory) = dst else {
                return Err(Stop::Invalid);
            };
            let operation = match mnemonic {
                Mnemonic::Bts => AtomicOp::Or(u128::from(mask)),
                Mnemonic::Btr => AtomicOp::And(u128::from(!mask)),
                Mnemonic::Btc => AtomicOp::Xor(u128::from(mask)),
                _ => return Err(Stop::Invalid),
            };
            self.mem
                .atomic(self.linear(&memory), atomic_width(size)?, operation)?
                .old as u64
        } else {
            let old = self.read(dst, size)?;
            let updated = match mnemonic {
                Mnemonic::Bts => Some(old | mask),
                Mnemonic::Btr => Some(old & !mask),
                Mnemonic::Btc => Some(old ^ mask),
                _ => None,
            };
            if let Some(value) = updated {
                self.write(dst, size, value)?;
            }
            old
        };
        self.set_status(flag::CF, if old & mask != 0 { flag::CF } else { 0 });
        Ok(())
    }

    fn rotate(&mut self, mnemonic: Mnemonic) -> Result<()> {
        let dst = op(self.i, 0)?;
        let size = Self::size_of(dst, None);
        let masked =
            self.i.operand(1).map_or(Ok(1), |o| self.read(o, 1))? & if size == 8 { 63 } else { 31 };
        let width = alu::bits(size);
        let through = matches!(mnemonic, Mnemonic::Rcl | Mnemonic::Rcr);
        let period = width + u32::from(through);
        let count = u32::try_from(masked).map_err(|_| Stop::Invalid)? % period;
        let value = self.read(dst, size)?;
        if masked == 0 || (through && count == 0) {
            return self.write(dst, size, value);
        }
        let wide = u128::from(value)
            | if through {
                u128::from(self.s.flag(flag::CF)) << width
            } else {
                0
            };
        let mask = (1u128 << period) - 1;
        let left = matches!(mnemonic, Mnemonic::Rol | Mnemonic::Rcl);
        let rotated = if count == 0 {
            wide
        } else if left {
            ((wide << count) | (wide >> (period - count))) & mask
        } else {
            ((wide >> count) | (wide << (period - count))) & mask
        };
        let result = rotated as u64 & size_mask(size);
        let cf = if through {
            rotated & (1u128 << width) != 0
        } else if left {
            result & 1 != 0
        } else {
            result & (1u64 << (width - 1)) != 0
        };
        let overflow = if left {
            (result & (1u64 << (width - 1)) != 0) != cf
        } else {
            ((result >> (width - 1)) ^ (result >> (width - 2))) & 1 != 0
        };
        self.write(dst, size, result)?;
        let flag_mask = flag::CF | if masked == 1 { flag::OF } else { 0 };
        self.set_status(
            flag_mask,
            if cf { flag::CF } else { 0 } | if overflow { flag::OF } else { 0 },
        );
        Ok(())
    }

    fn scan(&mut self, reverse: bool) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let value = self.read(src, size)?;
        if value != 0 {
            let index = if reverse {
                63 - value.leading_zeros()
            } else {
                value.trailing_zeros()
            };
            self.write(dst, size, u64::from(index))?;
        }
        self.set_status(flag::ZF, if value == 0 { flag::ZF } else { 0 });
        Ok(())
    }

    fn extend(&mut self, signed: bool) -> Result<()> {
        let (dst, src, _) = self.binary()?;
        let src_size = Self::size_of(src, None);
        let dst_size = Self::size_of(dst, None);
        let v = self.read(src, src_size)?;
        let v = if signed { sign_extend(v, src_size) } else { v };
        self.write(dst, dst_size, v)
    }

    fn double_shift(&mut self, right: bool) -> Result<()> {
        let dst = op(self.i, 0)?;
        let size = Self::size_of(dst, None);
        let width = u32::from(size) * 8;
        let a = self.read(dst, size)?;
        let b = self.read(op(self.i, 1)?, size)?;
        let count = self.read(op(self.i, 2)?, 1)? as u32 & if size == 8 { 63 } else { 31 };
        if count == 0 {
            return self.write(dst, size, a);
        }
        // Results/flags above the operand width are architecturally undefined.
        let n = count.min(width);
        let joined = if right {
            u128::from(a) | (u128::from(b) << width)
        } else {
            (u128::from(a) << width) | u128::from(b)
        };
        let result = if right {
            (joined >> n) as u64
        } else {
            ((joined << n) >> width) as u64
        } & size_mask(size);
        let cf = if right {
            (a >> (n - 1)) & 1
        } else {
            (a >> (width - n)) & 1
        };
        let mut flags = alu::zf_sf_pf(result, size) | cf;
        if count == 1 && (a ^ result) & (1u64 << (width - 1)) != 0 {
            flags |= flag::OF;
        }
        self.write(dst, size, result)?;
        self.set_status(
            flag::CF | flag::ZF | flag::SF | flag::PF | if count == 1 { flag::OF } else { 0 },
            flags,
        );
        Ok(())
    }

    fn adx(&mut self, overflow_chain: bool) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let a = self.read(dst, size)?;
        let b = self.read(src, size)?;
        let bit = if overflow_chain { flag::OF } else { flag::CF };
        let (value, flags) = alu::add(a, b, self.s.flag(bit), size);
        self.write(dst, size, value)?;
        self.s.set_flag(bit, flags & flag::CF != 0);
        Ok(())
    }

    fn bmi(&mut self, mnemonic: Mnemonic) -> Result<()> {
        let dst = op(self.i, 0)?;
        let size = Self::size_of(dst, None);
        let width = u32::from(size) * 8;
        let a = self.read(op(self.i, 1)?, size)?;
        let b = self.read(op(self.i, 2)?, size)?;
        let count = b as u32 & (width - 1);
        let value = match mnemonic {
            Mnemonic::Andn => !a & b,
            Mnemonic::Bzhi => {
                let n = b & 0xff;
                if n >= u64::from(width) {
                    a
                } else if n == 0 {
                    0
                } else {
                    a & ((1u64 << n) - 1)
                }
            }
            Mnemonic::Shlx => a.wrapping_shl(count),
            Mnemonic::Shrx => a >> count,
            Mnemonic::Rorx => {
                if size == 4 {
                    u64::from((a as u32).rotate_right(count))
                } else {
                    a.rotate_right(count)
                }
            }
            Mnemonic::Pext => {
                let mut mask = b;
                let mut result = 0u64;
                let mut out = 1u64;
                while mask != 0 {
                    let bit = 1u64 << mask.trailing_zeros();
                    if a & bit != 0 {
                        result |= out;
                    }
                    mask &= mask - 1;
                    out = out.wrapping_shl(1);
                }
                result
            }
            _ => return Err(Stop::Invalid),
        } & size_mask(size);
        self.write(dst, size, value)?;
        if matches!(mnemonic, Mnemonic::Andn | Mnemonic::Bzhi) {
            let flags = alu::zf_sf_pf(value, size) & (flag::ZF | flag::SF)
                | if mnemonic == Mnemonic::Bzhi && b & 0xff >= u64::from(width) {
                    flag::CF
                } else {
                    0
                };
            self.set_status(flag::CF | flag::OF | flag::ZF | flag::SF, flags);
        }
        Ok(())
    }

    fn mulx(&mut self) -> Result<()> {
        let high = op(self.i, 0)?;
        let low = op(self.i, 1)?;
        let size = Self::size_of(high, None);
        let a = self.s.gpr[reg::RDX] & size_mask(size);
        let b = self.read(op(self.i, 2)?, size)?;
        let product = u128::from(a) * u128::from(b);
        self.write(low, size, product as u64)?;
        self.write(high, size, (product >> (u32::from(size) * 8)) as u64)
    }

    fn movbe(&mut self) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        if !matches!(dst, Operand::Memory(_)) && !matches!(src, Operand::Memory(_)) {
            return Err(Stop::Invalid);
        }
        let value = self.read(src, size)?;
        let swapped = match size {
            2 => u64::from((value as u16).swap_bytes()),
            4 => u64::from((value as u32).swap_bytes()),
            8 => value.swap_bytes(),
            _ => return Err(Stop::Invalid),
        };
        self.write(dst, size, swapped)
    }

    fn count_bits(&mut self, mnemonic: Mnemonic) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let value = self.read(src, size)? & size_mask(size);
        let width = u32::from(size) * 8;
        let count = match mnemonic {
            Mnemonic::Tzcnt => {
                if value == 0 {
                    width
                } else {
                    value.trailing_zeros()
                }
            }
            Mnemonic::Lzcnt => value.leading_zeros() - (64 - width),
            Mnemonic::Popcnt => value.count_ones(),
            _ => return Err(Stop::Invalid),
        };
        self.write(dst, size, u64::from(count))?;
        if mnemonic == Mnemonic::Popcnt {
            self.set_status(flag::STATUS, if value == 0 { flag::ZF } else { 0 });
        } else {
            self.set_status(
                flag::CF | flag::ZF,
                if value == 0 { flag::CF } else { 0 } | if count == 0 { flag::ZF } else { 0 },
            );
        }
        Ok(())
    }

    fn cmpxchg(&mut self) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let acc = Register::Gpr { index: 0, size };
        let expected = self.read_reg(acc);
        let new = self.read(src, size)?;
        let current = if let Operand::Memory(mem) = dst {
            self.mem
                .atomic(
                    self.linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::CompareExchange {
                        expected: u128::from(expected),
                        replacement: u128::from(new),
                    },
                )?
                .old as u64
        } else {
            self.read(dst, size)?
        };
        let (_, f) = alu::sub(expected, current, false, size);
        if expected == current {
            if !matches!(dst, Operand::Memory(_)) {
                self.write(dst, size, new)?;
            }
        } else {
            self.write_reg(acc, current);
        }
        self.set_status(flag::STATUS, f);
        Ok(())
    }

    fn xchg(&mut self) -> Result<()> {
        let (a, b, size) = self.binary()?;
        if let Operand::Memory(mem) = a {
            let value = self.read(b, size)?;
            let old = self
                .mem
                .atomic(
                    self.linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::Exchange(u128::from(value)),
                )?
                .old;
            return self.write(b, size, old as u64);
        }
        if let Operand::Memory(mem) = b {
            let value = self.read(a, size)?;
            let old = self
                .mem
                .atomic(
                    self.linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::Exchange(u128::from(value)),
                )?
                .old;
            return self.write(a, size, old as u64);
        }
        let va = self.read(a, size)?;
        let vb = self.read(b, size)?;
        // Write memory first so a fault leaves the registers untouched.
        if matches!(a, Operand::Memory(_)) {
            self.write(a, size, vb)?;
            self.write(b, size, va)
        } else {
            self.write(b, size, va)?;
            self.write(a, size, vb)
        }
    }

    fn xadd(&mut self) -> Result<()> {
        let (dst, src, size) = self.binary()?;
        let b = self.read(src, size)?;
        let a = if let Operand::Memory(mem) = dst {
            self.mem
                .atomic(
                    self.linear(&mem),
                    atomic_width(size)?,
                    AtomicOp::Add(u128::from(b)),
                )?
                .old as u64
        } else {
            self.read(dst, size)?
        };
        let (sum, flags) = alu::add(a, b, false, size);
        self.write(src, size, a)?;
        if !matches!(dst, Operand::Memory(_)) {
            self.write(dst, size, sum)?;
        }
        self.set_status(flag::STATUS, flags);
        Ok(())
    }

    fn cmpxchg_pair(&mut self, wide: bool) -> Result<()> {
        let Operand::Memory(mem) = op(self.i, 0)? else {
            return Err(Stop::Invalid);
        };
        let address = self.linear(&mem);
        if wide && address.0 & 15 != 0 {
            return Err(Stop::GeneralProtection);
        }
        let bits = if wide { 64 } else { 32 };
        let mask = if wide { u64::MAX } else { 0xffff_ffff };
        let expected = u128::from(self.s.gpr[reg::RAX] & mask)
            | (u128::from(self.s.gpr[reg::RDX] & mask) << bits);
        let replacement = u128::from(self.s.gpr[reg::RBX] & mask)
            | (u128::from(self.s.gpr[reg::RCX] & mask) << bits);
        let result = self.mem.atomic(
            address,
            if wide {
                AtomicWidth::W128
            } else {
                AtomicWidth::W64
            },
            AtomicOp::CompareExchange {
                expected,
                replacement,
            },
        )?;
        if !result.exchanged {
            self.s.gpr[reg::RAX] = result.old as u64 & mask;
            self.s.gpr[reg::RDX] = (result.old >> bits) as u64 & mask;
        }
        self.s.set_flag(flag::ZF, result.exchanged);
        Ok(())
    }

    fn string(&mut self, m: Mnemonic) -> Result<bool> {
        let size = self.i.implicit_size;
        let step = if self.s.flag(flag::DF) {
            0u64.wrapping_sub(u64::from(size))
        } else {
            u64::from(size)
        };
        let repeat = self.i.rep != RepPrefix::None;
        let address_mask = if self.i.string_address_size_32 {
            0xffff_ffff
        } else {
            u64::MAX
        };
        let mut budget = REP_CHUNK;
        loop {
            if repeat {
                if self.s.gpr[reg::RCX] & address_mask == 0 {
                    return Ok(true);
                }
                if budget == 0 {
                    return Ok(false);
                }
                budget -= 1;
            }
            let rdi = GuestAddr(self.s.gpr[reg::RDI] & address_mask);
            let source_index = self.s.gpr[reg::RSI] & address_mask;
            let source_base = match self.i.string_segment {
                Segment::Fs => self.s.fs_base,
                Segment::Gs => self.s.gs_base,
                Segment::None => 0,
            };
            let source = GuestAddr(source_index.wrapping_add(source_base));
            let uses_source = matches!(
                m,
                Mnemonic::Movsb
                    | Mnemonic::Movsw
                    | Mnemonic::Movsd
                    | Mnemonic::Movsq
                    | Mnemonic::Lodsb
                    | Mnemonic::Lodsw
                    | Mnemonic::Lodsd
                    | Mnemonic::Lodsq
                    | Mnemonic::Cmpsb
                    | Mnemonic::Cmpsw
                    | Mnemonic::Cmpsd
                    | Mnemonic::Cmpsq
            );
            let uses_destination = !matches!(
                m,
                Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq
            );
            match m {
                Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => {
                    let v = self.load(source, size)?;
                    self.store(rdi, size, v)?;
                }
                Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
                    let v = self.s.gpr[reg::RAX] & size_mask(size);
                    self.store(rdi, size, v)?;
                }
                Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq => {
                    let value = self.load(source, size)?;
                    self.write_reg(Register::Gpr { index: 0, size }, value);
                }
                _ => {
                    let a = if uses_source {
                        self.load(source, size)?
                    } else {
                        self.s.gpr[reg::RAX] & size_mask(size)
                    };
                    let b = self.load(rdi, size)?;
                    let (_, flags) = alu::sub(a, b, false, size);
                    self.set_status(flag::STATUS, flags);
                }
            }
            if uses_source {
                self.s.gpr[reg::RSI] = (source_index.wrapping_add(step)) & address_mask;
            }
            if uses_destination {
                self.s.gpr[reg::RDI] = (rdi.0.wrapping_add(step)) & address_mask;
            }
            if !repeat {
                return Ok(true);
            }
            self.s.gpr[reg::RCX] = self.s.gpr[reg::RCX].wrapping_sub(1) & address_mask;
            if is_comparison_string(m)
                && ((self.i.rep == RepPrefix::Rep && !self.s.flag(flag::ZF))
                    || (self.i.rep == RepPrefix::Repne && self.s.flag(flag::ZF)))
            {
                return Ok(true);
            }
        }
    }

    fn read128(&self, o: Operand, aligned: bool) -> Result<u128> {
        match o {
            Operand::Register(Register::Xmm(n)) => Ok(self.s.xmm[usize::from(n & 15)]),
            Operand::Memory(m) => {
                let addr = self.linear(&m);
                if aligned && !addr.0.is_multiple_of(16) {
                    return Err(Stop::GeneralProtection);
                }
                let mut b = [0u8; 16];
                self.mem.read(addr, &mut b)?;
                Ok(u128::from_le_bytes(b))
            }
            _ => Err(Stop::Invalid),
        }
    }

    fn write128(&mut self, o: Operand, value: u128, aligned: bool) -> Result<()> {
        match o {
            Operand::Register(Register::Xmm(n)) => {
                self.s.xmm[usize::from(n & 15)] = value;
                Ok(())
            }
            Operand::Memory(m) => {
                let addr = self.linear(&m);
                if aligned && !addr.0.is_multiple_of(16) {
                    return Err(Stop::GeneralProtection);
                }
                self.mem.write(addr, &value.to_le_bytes())?;
                Ok(())
            }
            _ => Err(Stop::Invalid),
        }
    }

    fn sse_move(&mut self, aligned: bool) -> Result<()> {
        let dst = op(self.i, 0)?;
        let v = self.read128(op(self.i, 1)?, aligned)?;
        self.write128(dst, v, aligned)
    }

    /// MASKMOVDQU: the bytes whose mask byte has its top bit set go to the
    /// implicit `[rdi]`, in order. With no mask bit this makes no access, where
    /// a CPU may still fault: AMD EPYC does on a page it cannot reach.
    fn sse_masked_store(&mut self) -> Result<()> {
        let Operand::Memory(target) = op(self.i, 0)? else {
            return Err(Stop::Invalid);
        };
        let address = self.linear(&target).0;
        // With `0x67` the offsets wrap in 32 bits, as the effective address does.
        let wrap = if target.address_size_32 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let data = self.read128(op(self.i, 1)?, false)?.to_le_bytes();
        let mask = self.read128(op(self.i, 2)?, false)?.to_le_bytes();
        for n in 0..16 {
            if mask[n] & 0x80 != 0 {
                self.mem.write(
                    GuestAddr(address.wrapping_add(n as u64) & wrap),
                    &data[n..=n],
                )?;
            }
        }
        Ok(())
    }

    fn sse_xor(&mut self) -> Result<()> {
        let dst = op(self.i, 0)?;
        // Legacy-SSE memory operands must be 16-byte aligned.
        let v = self.read128(dst, true)? ^ self.read128(op(self.i, 1)?, true)?;
        self.write128(dst, v, true)
    }

    fn sse_movq(&mut self) -> Result<()> {
        let dst = op(self.i, 0)?;
        let src = op(self.i, 1)?;
        let value = self.read(src, 8)?;
        // Legacy MOVQ writes only a qword to GPR/memory, but clears the
        // upper qword when its destination is an XMM register.
        self.write(dst, 8, value)
    }

    fn sse_unpack_low_qwords(&mut self) -> Result<()> {
        let dst = op(self.i, 0)?;
        let low = self.read128(dst, true)? as u64;
        let high = self.read128(op(self.i, 1)?, true)? as u64;
        self.write128(dst, u128::from(low) | (u128::from(high) << 64), true)
    }

    fn branch_target(&self) -> Result<u64> {
        let o = op(self.i, 0)?;
        self.read(o, 8)
    }

    fn sse_operand(&self, o: Operand) -> Result<u128> {
        match o {
            Operand::Register(Register::Xmm(n)) => Ok(self.s.xmm[usize::from(n)]),
            Operand::Memory(m) if m.size <= 16 => {
                let address = self.linear(&m);
                // Legacy packed arithmetic requires alignment before page access.
                if m.size == 16 && !address.0.is_multiple_of(16) {
                    return Err(Stop::GeneralProtection);
                }
                let mut bytes = [0; 16];
                self.mem.read(address, &mut bytes[..usize::from(m.size)])?;
                Ok(u128::from_le_bytes(bytes))
            }
            Operand::Immediate(v) => Ok(u128::from(v)),
            _ => Err(Stop::Invalid),
        }
    }

    fn packed(&mut self) -> Result<()> {
        let dst = op(self.i, 0)?;
        let Operand::Register(Register::Xmm(n)) = dst else {
            return Err(Stop::Invalid);
        };
        let a = self.s.xmm[usize::from(n)];
        // Check membership before reading memory for an unsupported instruction.
        if crate::sse::packed(self.i.mnemonic, 0, 0, 0, 0).is_none()
            && crate::crypto::execute(self.i.mnemonic, 0, 0, 0, 0).is_none()
        {
            return Err(Stop::Invalid);
        }
        let b = self.sse_operand(op(self.i, 1)?)?;
        let imm = match self.i.operand(2) {
            Some(Operand::Immediate(v)) => v as u8,
            _ => match self.i.operand(1) {
                Some(Operand::Immediate(v)) => v as u8,
                _ => 0,
            },
        };
        let value = crate::sse::packed(self.i.mnemonic, a, b, imm, self.s.xmm[0])
            .or_else(|| crate::crypto::execute(self.i.mnemonic, a, b, self.s.xmm[0], imm))
            .ok_or(Stop::Invalid)?;
        self.s.xmm[usize::from(n)] = value;
        Ok(())
    }

    /// Where `fxsave` and `fxrstor` work: 16-byte aligned, or a general
    /// protection fault.
    fn fx_area(&self) -> Result<GuestAddr> {
        let Operand::Memory(m) = op(self.i, 0)? else {
            return Err(Stop::Invalid);
        };
        let at = self.linear(&m);
        if !at.0.is_multiple_of(16) {
            return Err(Stop::GeneralProtection);
        }
        Ok(at)
    }
    /// `fxsave`: the x87 state, MXCSR and its mask, and the XMM registers. The
    /// area past them is not written, but faults like the rest if it cannot be.
    fn fxsave(&mut self) -> Result<()> {
        let at = self.fx_area()?;
        self.mem.check_write(at, FX_AREA)?;
        self.mem.write(at, &self.s.fx_image())?;
        Ok(())
    }
    /// `fxrstor`: what `fxsave` writes. MXCSR's reserved bits are a general
    /// protection fault.
    fn fxrstor(&mut self) -> Result<()> {
        let at = self.fx_area()?;
        self.mem.check_read(at, FX_AREA)?;
        let mut area = [0u8; FX_WRITTEN];
        self.mem.read(at, &mut area)?;
        if !self.s.restore_fx_image(&area) {
            return Err(Stop::GeneralProtection);
        }
        Ok(())
    }
    /// An x87 instruction. What it writes to memory is written first, so a
    /// fault leaves the unit as it was.
    fn x87(&mut self) -> Result<()> {
        use Mnemonic as M;
        let m = self.i.mnemonic;
        let memory = match self.i.operand(0) {
            Some(Operand::Memory(memory)) => Some(memory),
            _ => None,
        };
        // Where two are named, the first is st(0).
        let register = self.i.operands().find_map(|o| match o {
            Operand::Register(Register::St(n)) if n != 0 => Some(n),
            _ => None,
        });
        let register = register.unwrap_or(0);
        let mut unit = self.s.x87;
        match (m, memory) {
            (M::Fld, Some(memory)) => match memory.size {
                4 => unit.load_float(F32, self.load(self.linear(&memory), 4)?),
                8 => unit.load_float(F64, self.load(self.linear(&memory), 8)?),
                10 => unit.load_extended(self.load_extended(&memory)?),
                _ => return Err(Stop::Invalid),
            },
            (M::Fld, None) => unit.load_register(register),
            (M::Fild, Some(memory)) => {
                let bits = self.load(self.linear(&memory), memory.size)?;
                unit.load_integer(sign_extend(bits, memory.size) as i64);
            }
            (M::Fst | M::Fstp, Some(memory)) => {
                match memory.size {
                    4 => {
                        let bits = unit.store_float(F32);
                        self.store(self.linear(&memory), 4, bits)?;
                    }
                    8 => {
                        let bits = unit.store_float(F64);
                        self.store(self.linear(&memory), 8, bits)?;
                    }
                    10 => {
                        let value = unit.store_extended();
                        let at = self.linear(&memory);
                        self.mem.check_write(at, 10)?;
                        self.mem.write(at, &value.to_le_bytes()[..10])?;
                    }
                    _ => return Err(Stop::Invalid),
                }
                if m == M::Fstp {
                    unit.pop();
                }
            }
            (M::Fst | M::Fstp, None) => {
                unit.store_register(register);
                if m == M::Fstp {
                    unit.pop();
                }
            }
            (M::Fist | M::Fistp, Some(memory)) => {
                let bits = unit.store_integer(u32::from(memory.size) * 8);
                self.store(self.linear(&memory), memory.size, bits)?;
                if m == M::Fistp {
                    unit.pop();
                }
            }
            (M::Fcomi | M::Fcomip | M::Fucomi | M::Fucomip, None) => {
                let order = unit.compare(register, matches!(m, M::Fucomi | M::Fucomip));
                let value = match order {
                    Some(Ordering::Greater) => 0,
                    Some(Ordering::Less) => flag::CF,
                    Some(Ordering::Equal) => flag::ZF,
                    None => flag::ZF | flag::PF | flag::CF,
                };
                self.set_status(flag::STATUS, value);
                if matches!(m, M::Fcomip | M::Fucomip) {
                    unit.pop();
                }
            }
            (M::Fcom | M::Fcomp, Some(memory)) => {
                let format = match memory.size {
                    4 => F32,
                    8 => F64,
                    _ => return Err(Stop::Invalid),
                };
                let bits = self.load(self.linear(&memory), memory.size)?;
                let (value, denormal) = float_operand(format, bits);
                unit.compare_value(value, denormal);
                if m == M::Fcomp {
                    unit.pop();
                }
            }
            (M::Ficom | M::Ficomp, Some(memory)) => {
                let bits = self.load(self.linear(&memory), memory.size)?;
                let value = integer_value(sign_extend(bits, memory.size) as i64);
                unit.compare_value(value, false);
                if m == M::Ficomp {
                    unit.pop();
                }
            }
            (M::Fcom | M::Fcomp | M::Fucom | M::Fucomp, None) => {
                unit.compare_register(register, matches!(m, M::Fucom | M::Fucomp));
                if matches!(m, M::Fcomp | M::Fucomp) {
                    unit.pop();
                }
            }
            (M::Fcompp | M::Fucompp, None) => {
                unit.compare_register(1, m == M::Fucompp);
                unit.pop();
                unit.pop();
            }
            (M::Ftst, None) => unit.compare_value(0, false),
            (M::Fadd | M::Fsub | M::Fsubr | M::Fmul | M::Fdiv | M::Fdivr, Some(memory)) => {
                let format = match memory.size {
                    4 => F32,
                    8 => F64,
                    _ => return Err(Stop::Invalid),
                };
                let bits = self.load(self.linear(&memory), memory.size)?;
                let (value, denormal) = float_operand(format, bits);
                unit.calculate_memory(x87_arithmetic(m), value, denormal);
            }
            (M::Fiadd | M::Fisub | M::Fisubr | M::Fimul | M::Fidiv | M::Fidivr, Some(memory)) => {
                let bits = self.load(self.linear(&memory), memory.size)?;
                let value = integer_value(sign_extend(bits, memory.size) as i64);
                unit.calculate_memory(x87_arithmetic(m), value, false);
            }
            (
                M::Fadd
                | M::Faddp
                | M::Fsub
                | M::Fsubp
                | M::Fsubr
                | M::Fsubrp
                | M::Fmul
                | M::Fmulp
                | M::Fdiv
                | M::Fdivp
                | M::Fdivr
                | M::Fdivrp,
                None,
            ) => {
                let stack = |n| match self.i.operand(n) {
                    Some(Operand::Register(Register::St(index))) => Ok(index),
                    _ => Err(Stop::Invalid),
                };
                unit.calculate_registers(x87_arithmetic(m), stack(0)?, stack(1)?);
                if matches!(
                    m,
                    M::Faddp | M::Fsubp | M::Fsubrp | M::Fmulp | M::Fdivp | M::Fdivrp
                ) {
                    unit.pop();
                }
            }
            (M::Fsqrt, None) => unit.square_root(),
            (M::Frndint, None) => unit.round_to_whole(),
            (M::Fscale, None) => unit.scale(),
            (M::Fprem, None) => unit.remainder(false),
            (M::Fprem1, None) => unit.remainder(true),
            (M::Fxtract, None) => unit.extract(),
            (
                M::Fcmovb
                | M::Fcmove
                | M::Fcmovbe
                | M::Fcmovu
                | M::Fcmovnb
                | M::Fcmovne
                | M::Fcmovnbe
                | M::Fcmovnu,
                None,
            ) => {
                let flags = self.s.rflags;
                let on = |bit: u64| flags & bit != 0;
                let taken = match m {
                    M::Fcmovb => on(flag::CF),
                    M::Fcmove => on(flag::ZF),
                    M::Fcmovbe => on(flag::CF) || on(flag::ZF),
                    M::Fcmovu => on(flag::PF),
                    M::Fcmovnb => !on(flag::CF),
                    M::Fcmovne => !on(flag::ZF),
                    M::Fcmovnbe => !on(flag::CF) && !on(flag::ZF),
                    _ => !on(flag::PF),
                };
                unit.conditional_move(register, taken);
            }
            (M::Fxch, None) => unit.exchange(register),
            (M::Fchs, None) => unit.negate(),
            (M::Fabs, None) => unit.absolute(),
            (M::Fxam, None) => unit.examine(),
            (M::Fldz, None) => unit.load_zero(),
            (M::Fld1, None) => unit.load_one(),
            (M::Fldpi, None) => unit.load_constant(PI),
            (M::Fldln2, None) => unit.load_constant(LN_2),
            (M::Fldlg2, None) => unit.load_constant(LOG10_2),
            (M::Fldl2e, None) => unit.load_constant(LOG2_E),
            (M::Fldl2t, None) => unit.load_constant(LOG2_10),
            (M::Ffree, None) => unit.free(register),
            (M::Fincstp, None) => unit.increment_top(),
            (M::Fdecstp, None) => unit.decrement_top(),
            (M::Fnop | M::Wait, None) => {}
            (M::Fnclex, None) => unit.clear_exceptions(),
            (M::Fninit, None) => unit.initialize(),
            (M::Fnstcw, Some(memory)) => {
                let word = u64::from(unit.control_word());
                self.store(self.linear(&memory), 2, word)?;
            }
            (M::Fldcw, Some(memory)) => {
                unit.set_control(self.load(self.linear(&memory), 2)? as u16);
            }
            (M::Fnstsw, Some(memory)) => {
                let word = u64::from(unit.status_word());
                self.store(self.linear(&memory), 2, word)?;
            }
            (M::Fnstsw, None) => {
                self.write(op(self.i, 0)?, 2, u64::from(unit.status_word()))?;
            }
            (M::Fnstenv, Some(memory)) if usize::from(memory.size) == ENVIRONMENT => {
                let image = unit.store_environment();
                let at = self.linear(&memory);
                self.mem.check_write(at, ENVIRONMENT)?;
                self.mem.write(at, &image)?;
            }
            (M::Fldenv, Some(memory)) if usize::from(memory.size) == ENVIRONMENT => {
                let mut image = [0; ENVIRONMENT];
                self.mem.read(self.linear(&memory), &mut image)?;
                unit.load_environment(&image);
            }
            _ => return Err(Stop::Invalid),
        }
        self.s.x87 = unit;
        Ok(())
    }
    /// The 80-bit format in memory.
    fn load_extended(&self, memory: &MemoryOperand) -> Result<u128> {
        let mut bytes = [0; 16];
        self.mem.read(self.linear(memory), &mut bytes[..10])?;
        Ok(u128::from_le_bytes(bytes))
    }
    fn sse_misc(&mut self) -> Result<()> {
        use Mnemonic as M;
        let m = self.i.mnemonic;
        let dst = op(self.i, 0)?;
        if m == M::Ldmxcsr {
            let value = self.read(dst, 4)? as u32;
            if value & !0xffff != 0 {
                return Err(Stop::GeneralProtection);
            }
            self.s.mxcsr = value;
            return Ok(());
        }
        if m == M::Stmxcsr {
            return self.write(dst, 4, u64::from(self.s.mxcsr));
        }
        let src = op(self.i, 1)?;
        if matches!(m, M::Movapd | M::Movupd | M::Lddqu) {
            return self.sse_move(m == M::Movapd);
        }
        if m == M::Movd {
            let value = self.read(src, 4)?;
            return self.write(dst, 4, value);
        }
        if matches!(
            m,
            M::Movss
                | M::MovsdSse
                | M::Movlps
                | M::Movlpd
                | M::Movhps
                | M::Movhpd
                | M::Movhlps
                | M::Movlhps
                | M::Movddup
        ) {
            let width = if m == M::Movss { 4 } else { 8 };
            let mut value = self.read(src, width)?;
            if m == M::Movhlps {
                value = (self.read128(src, false)? >> 64) as u64;
            }
            let high = matches!(m, M::Movhps | M::Movhpd | M::Movlhps);
            if let Operand::Register(Register::Xmm(n)) = dst {
                let old = self.s.xmm[usize::from(n)];
                let mask = u128::from(size_mask(width));
                let value = u128::from(value);
                self.s.xmm[usize::from(n)] = if m == M::Movddup {
                    value | (value << 64)
                } else if high {
                    (old & u128::from(u64::MAX)) | (value << 64)
                } else if matches!(m, M::Movss | M::MovsdSse) && matches!(src, Operand::Memory(_)) {
                    value
                } else {
                    (old & !mask) | value
                };
                return Ok(());
            }
            if high {
                value = (self.read128(src, false)? >> 64) as u64;
            }
            return self.write(dst, width, value);
        }
        if matches!(m, M::Movmskps | M::Movmskpd | M::Pmovmskb) {
            let value = self.read128(src, false)?;
            let bits = match m {
                M::Movmskps => 32,
                M::Movmskpd => 64,
                _ => 8,
            };
            let mut mask = 0;
            for n in 0..128 / bits {
                mask |= ((value >> (n * bits + bits - 1)) as u64 & 1) << n;
            }
            return self.write(dst, 4, mask);
        }
        if m == M::Ptest {
            let a = self.sse_operand(dst)?;
            let b = self.sse_operand(src)?;
            let flags =
                if a & b == 0 { flag::ZF } else { 0 } | if !a & b == 0 { flag::CF } else { 0 };
            self.set_status(flag::STATUS, flags);
            return Ok(());
        }
        if matches!(
            m,
            M::Pextrb
                | M::Pextrw
                | M::Pextrd
                | M::Pextrq
                | M::Pinsrb
                | M::Pinsrw
                | M::Pinsrd
                | M::Pinsrq
        ) {
            let bits = match m {
                M::Pextrb | M::Pinsrb => 8,
                M::Pextrw | M::Pinsrw => 16,
                M::Pextrd | M::Pinsrd => 32,
                _ => 64,
            };
            let Operand::Immediate(imm) = op(self.i, 2)? else {
                return Err(Stop::Invalid);
            };
            let shift = (imm & (128 / bits - 1)) * bits;
            let mask = (1u128 << bits) - 1;
            if matches!(m, M::Pextrb | M::Pextrw | M::Pextrd | M::Pextrq) {
                let value = ((self.read128(src, false)? >> shift) & mask) as u64;
                let width = if matches!(dst, Operand::Register(_)) {
                    if bits == 64 { 8 } else { 4 }
                } else {
                    (bits / 8) as u8
                };
                return self.write(dst, width, value);
            }
            let value = u128::from(self.read(src, (bits / 8) as u8)?);
            let old = self.read128(dst, false)?;
            return self.write128(
                dst,
                (old & !(mask << shift)) | ((value & mask) << shift),
                false,
            );
        }
        if crate::sse::packed(m, 0, 0, 0, 0).is_some()
            || crate::crypto::execute(m, 0, 0, 0, 0).is_some()
        {
            self.packed()
        } else {
            self.floating()
        }
    }

    fn fp_status(&mut self, flags: u32) -> Result<()> {
        let unmasked = flags & !(self.s.mxcsr >> 7) & 63;
        // Input-class exceptions precede numeric-result exceptions, including
        // precision from another packed lane.
        let flags = if unmasked & 7 != 0 { flags & 7 } else { flags };
        self.s.mxcsr |= flags;
        if unmasked == 0 {
            return Ok(());
        }
        let code = if unmasked & 1 != 0 {
            7
        } else if unmasked & 2 != 0 {
            5
        } else if unmasked & 4 != 0 {
            3
        } else if unmasked & 8 != 0 {
            4
        } else if unmasked & 16 != 0 {
            5
        } else {
            6
        };
        Err(Stop::FloatingPointFault(code))
    }

    fn floating(&mut self) -> Result<()> {
        use crate::softfloat::{self as fp, F32, F64, Operation as O};
        use Mnemonic as M;
        let m = self.i.mnemonic;
        let supported = matches!(
            m,
            M::Addpd
                | M::Addps
                | M::Addsd
                | M::Subps
                | M::Mulps
                | M::Divps
                | M::Minps
                | M::Maxps
                | M::Minpd
                | M::Maxpd
                | M::Sqrtpd
                | M::Cmpps
                | M::Cmppd
                | M::Cvtps2pd
                | M::Cvtpd2ps
                | M::Cvtps2dq
                | M::Cvtpd2dq
                | M::Cvttpd2dq
                | M::Cvtdq2pd
                | M::Cvtsd2si
                | M::Cvtss2si
                | M::Rcpps
                | M::Rcpss
                | M::Rsqrtps
                | M::Rsqrtss
                | M::Subpd
                | M::Subsd
                | M::Mulpd
                | M::Mulsd
                | M::Divpd
                | M::Divsd
                | M::Divss
                | M::Sqrtps
                | M::Sqrtsd
                | M::Minsd
                | M::Maxsd
                | M::CmpsdSse
                | M::Comisd
                | M::Ucomisd
                | M::Ucomiss
                | M::Cvtdq2ps
                | M::Cvtsi2sd
                | M::Cvtss2sd
                | M::Cvttps2dq
                | M::Cvttsd2si
                | M::Cvttss2si
                | M::Addss
                | M::Subss
                | M::Mulss
                | M::Minss
                | M::Maxss
                | M::Sqrtss
                | M::Cmpss
                | M::Comiss
                | M::Cvtsi2ss
                | M::Cvtsd2ss
        );
        if !supported {
            return Err(Stop::Invalid);
        }
        let dst = op(self.i, 0)?;
        let src = op(self.i, 1)?;
        let single = matches!(
            m,
            M::Addps
                | M::Subps
                | M::Mulps
                | M::Divps
                | M::Minps
                | M::Maxps
                | M::Cmpps
                | M::Cvtps2dq
                | M::Cvtss2si
                | M::Rcpps
                | M::Rcpss
                | M::Rsqrtps
                | M::Rsqrtss
                | M::Addss
                | M::Subss
                | M::Mulss
                | M::Divss
                | M::Minss
                | M::Maxss
                | M::Sqrtps
                | M::Sqrtss
                | M::Cmpss
                | M::Comiss
                | M::Ucomiss
                | M::Cvtsi2ss
                | M::Cvtsd2ss
                | M::Cvttss2si
                | M::Cvttps2dq
                | M::Cvtdq2ps
        );
        let format = if single { F32 } else { F64 };
        let width = format.fraction + if single { 9 } else { 12 };
        let scalar = !matches!(
            m,
            M::Addpd
                | M::Addps
                | M::Subps
                | M::Mulps
                | M::Divps
                | M::Minps
                | M::Maxps
                | M::Minpd
                | M::Maxpd
                | M::Sqrtpd
                | M::Cvtps2dq
                | M::Rcpps
                | M::Rsqrtps
                | M::Subpd
                | M::Mulpd
                | M::Divpd
                | M::Sqrtps
                | M::Cvtdq2ps
                | M::Cvttps2dq
        );
        let b = if matches!(m, M::Cvtsi2sd | M::Cvtsi2ss) {
            u128::from(self.read(src, Self::size_of(src, None))?)
        } else {
            self.sse_operand(src)?
        };
        if matches!(m, M::Cvttsd2si | M::Cvttss2si | M::Cvtsd2si | M::Cvtss2si) {
            let size = Self::size_of(dst, None);
            let convert = if matches!(m, M::Cvttsd2si | M::Cvttss2si) {
                fp::to_integer
            } else {
                fp::to_rounded_integer
            };
            let (result, flags) = convert(format, b as u64, u32::from(size) * 8, self.s.mxcsr);
            self.fp_status(flags)?;
            return self.write(dst, size, result);
        }
        // Two lanes of one width to two of another; what is left is zero.
        if matches!(
            m,
            M::Cvtps2pd | M::Cvtdq2pd | M::Cvtpd2ps | M::Cvtpd2dq | M::Cvttpd2dq
        ) {
            let mxcsr = self.s.mxcsr;
            let mut result = 0;
            let mut flags = 0;
            for lane in 0..2 {
                let narrow = (b >> (lane * 32)) as u32;
                let wide = (b >> (lane * 64)) as u64;
                let (value, status, to) = match m {
                    M::Cvtps2pd => {
                        let (value, status) = fp::convert(F32, F64, u64::from(narrow), mxcsr);
                        (value, status, 64)
                    }
                    M::Cvtdq2pd => {
                        let (value, status) =
                            fp::from_integer(F64, i64::from(narrow as i32), mxcsr);
                        (value, status, 64)
                    }
                    M::Cvtpd2ps => {
                        let (value, status) = fp::convert(F64, F32, wide, mxcsr);
                        (value, status, 32)
                    }
                    M::Cvtpd2dq => {
                        let (value, status) = fp::to_rounded_integer(F64, wide, 32, mxcsr);
                        (value, status, 32)
                    }
                    _ => {
                        let (value, status) = fp::to_integer(F64, wide, 32, mxcsr);
                        (value, status, 32)
                    }
                };
                flags |= status;
                result |= u128::from(value & (u64::MAX >> (64 - to))) << (lane * to);
            }
            self.fp_status(flags)?;
            return self.write128(dst, result, false);
        }
        let a = self.read128(dst, false)?;
        // The low element: all of a 64-bit lane, or the low half for single precision.
        let lane = u64::MAX >> (64 - width);
        if matches!(m, M::Comisd | M::Comiss | M::Ucomisd | M::Ucomiss) {
            let (order, status) = fp::compare(
                format,
                a as u64 & lane,
                b as u64 & lane,
                self.s.mxcsr,
                matches!(m, M::Comisd | M::Comiss),
            );
            self.fp_status(status)?;
            self.set_status(
                flag::STATUS,
                match order {
                    None => flag::CF | flag::ZF | flag::PF,
                    Some(-1) => flag::CF,
                    Some(0) => flag::ZF,
                    _ => 0,
                },
            );
            return Ok(());
        }
        if matches!(m, M::CmpsdSse | M::Cmpss | M::Cmpps | M::Cmppd) {
            let Operand::Immediate(predicate) = op(self.i, 2)? else {
                return Err(Stop::Invalid);
            };
            let predicate = predicate & 7;
            let count = if matches!(m, M::Cmpps | M::Cmppd) {
                128 / width
            } else {
                1
            };
            let mut result = a;
            let mut flags = 0;
            for n in 0..count {
                let shift = n * width;
                let (order, status) = fp::compare(
                    format,
                    (a >> shift) as u64 & lane,
                    (b >> shift) as u64 & lane,
                    self.s.mxcsr,
                    matches!(predicate, 1 | 2 | 5 | 6),
                );
                let yes = match predicate {
                    0 => order == Some(0),
                    1 => order == Some(-1),
                    2 => matches!(order, Some(-1 | 0)),
                    3 => order.is_none(),
                    4 => order != Some(0),
                    5 => order != Some(-1),
                    6 => !matches!(order, Some(-1 | 0)),
                    _ => order.is_some(),
                };
                flags |= status;
                result &= !(u128::from(lane) << shift);
                if yes {
                    result |= u128::from(lane) << shift;
                }
            }
            self.fp_status(flags)?;
            return self.write128(dst, result, false);
        }
        let count = if scalar { 1 } else { 128 / width };
        let mut result = if scalar { a } else { 0 };
        let mask = (1u128 << width) - 1;
        let mut flags = 0;
        for lane in 0..count {
            let av = ((a >> (lane * width)) & mask) as u64;
            let bv = ((b >> (lane * width)) & mask) as u64;
            let (value, status) = match m {
                M::Cvtsi2sd => {
                    let size = Self::size_of(src, None);
                    fp::from_integer(F64, sign_extend(b as u64, size) as i64, self.s.mxcsr)
                }
                M::Cvtsi2ss => {
                    let size = Self::size_of(src, None);
                    fp::from_integer(F32, sign_extend(b as u64, size) as i64, self.s.mxcsr)
                }
                M::Cvtss2sd => fp::convert(F32, F64, b as u32 as u64, self.s.mxcsr),
                M::Cvtsd2ss => fp::convert(F64, F32, b as u64, self.s.mxcsr),
                M::Cvtdq2ps => fp::from_integer(F32, i64::from(bv as u32 as i32), self.s.mxcsr),
                M::Cvttps2dq => fp::to_integer(F32, bv, 32, self.s.mxcsr),
                M::Cvtps2dq => fp::to_rounded_integer(F32, bv, 32, self.s.mxcsr),
                M::Rcpps | M::Rcpss => (u64::from(fp::approximate(bv as u32, false)), 0),
                M::Rsqrtps | M::Rsqrtss => (u64::from(fp::approximate(bv as u32, true)), 0),
                M::Sqrtps | M::Sqrtpd | M::Sqrtsd | M::Sqrtss => {
                    fp::arithmetic(format, O::Sqrt, bv, 0, self.s.mxcsr)
                }
                _ => fp::arithmetic(
                    format,
                    match m {
                        M::Addpd | M::Addps | M::Addsd | M::Addss => O::Add,
                        M::Subpd | M::Subps | M::Subsd | M::Subss => O::Sub,
                        M::Mulpd | M::Mulps | M::Mulsd | M::Mulss => O::Mul,
                        M::Divpd | M::Divps | M::Divsd | M::Divss => O::Div,
                        M::Minpd | M::Minps | M::Minsd | M::Minss => O::Min,
                        M::Maxpd | M::Maxps | M::Maxsd | M::Maxss => O::Max,
                        _ => return Err(Stop::Invalid),
                    },
                    av,
                    bv,
                    self.s.mxcsr,
                ),
            };
            flags |= status;
            result = (result & !(mask << (lane * width)))
                | ((u128::from(value) & mask) << (lane * width));
        }
        self.fp_status(flags)?;
        self.write128(dst, result, false)
    }
}

/// Executes `i` on `s`. On success `s.rip` points at the next instruction to
/// run. On any [`Stop`] other than `Syscall`, `s.rip` is left at `i`.
// Every instruction without a form of `Fast`, and every form that fails,
// comes through here from `execute_decoded`, its only caller outside the
// tests. It has grown past what the compiler inlines by itself, and
// the call costs a guest about 4% in the wasm build.
#[inline(always)]
pub(crate) fn execute(s: &mut CpuState, mem: &AddressSpace, i: &Instruction) -> Result<()> {
    let next = i.next_rip();
    let mut x = Exec { s, mem, i };
    let mut target: Option<u64> = None;
    match i.mnemonic {
        m @ (Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Xor
        | Mnemonic::Cmp
        | Mnemonic::Test) => x.alu(m)?,
        m @ (Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not) => x.unary(m)?,
        Mnemonic::Shl => x.shift(ShiftKind::Shl)?,
        Mnemonic::Shr => x.shift(ShiftKind::Shr)?,
        Mnemonic::Sar => x.shift(ShiftKind::Sar)?,
        Mnemonic::Shld => x.double_shift(false)?,
        Mnemonic::Shrd => x.double_shift(true)?,
        Mnemonic::Imul => x.imul()?,
        Mnemonic::Mul => x.mul()?,
        Mnemonic::Div => x.divide(false)?,
        Mnemonic::Idiv => x.divide(true)?,
        m @ (Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc) => x.bit(m)?,
        m @ (Mnemonic::Rol | Mnemonic::Ror | Mnemonic::Rcl | Mnemonic::Rcr) => x.rotate(m)?,
        Mnemonic::Bsf => x.scan(false)?,
        Mnemonic::Bsr => x.scan(true)?,
        m @ (Mnemonic::Tzcnt | Mnemonic::Lzcnt | Mnemonic::Popcnt) => x.count_bits(m)?,
        Mnemonic::Adcx => x.adx(false)?,
        Mnemonic::Adox => x.adx(true)?,
        m @ (Mnemonic::Andn
        | Mnemonic::Bzhi
        | Mnemonic::Pext
        | Mnemonic::Rorx
        | Mnemonic::Shlx
        | Mnemonic::Shrx) => x.bmi(m)?,
        Mnemonic::Mulx => x.mulx()?,
        Mnemonic::Movbe => x.movbe()?,
        Mnemonic::Enter => x.enter()?,
        Mnemonic::Xlatb => {
            let value = x.read(op(i, 0)?, 1)?;
            x.s.gpr[reg::RAX] = (x.s.gpr[reg::RAX] & !0xff) | value;
        }
        Mnemonic::Bswap => {
            let dst = op(i, 0)?;
            let size = Exec::size_of(dst, None);
            let value = x.read(dst, size)?;
            let result = match size {
                8 => value.swap_bytes(),
                4 => u64::from((value as u32).swap_bytes()),
                _ => return Err(Stop::Invalid),
            };
            x.write(dst, size, result)?;
        }
        Mnemonic::Mov => {
            let (dst, src, size) = x.binary()?;
            let v = x.read(src, size)?;
            x.write(dst, size, v)?;
        }
        Mnemonic::Movsx | Mnemonic::Movsxd => x.extend(true)?,
        Mnemonic::Movzx => x.extend(false)?,
        Mnemonic::Cdqe => {
            x.s.gpr[reg::RAX] = sign_extend(x.s.gpr[reg::RAX] & 0xffff_ffff, 4);
        }
        Mnemonic::Cbw => {
            let value = sign_extend(x.s.gpr[reg::RAX] & 0xff, 1);
            x.write_reg(Register::Gpr { index: 0, size: 2 }, value);
        }
        Mnemonic::Cwde => {
            let value = sign_extend(x.s.gpr[reg::RAX] & 0xffff, 2);
            x.write_reg(Register::Gpr { index: 0, size: 4 }, value);
        }
        Mnemonic::Cwd => {
            let value = if x.s.gpr[reg::RAX] & 0x8000 != 0 {
                0xffff
            } else {
                0
            };
            x.write_reg(Register::Gpr { index: 2, size: 2 }, value);
        }
        Mnemonic::Clc => x.s.set_flag(flag::CF, false),
        Mnemonic::Stc => x.s.set_flag(flag::CF, true),
        Mnemonic::Cmc => x.s.set_flag(flag::CF, !x.s.flag(flag::CF)),
        Mnemonic::Lahf => {
            let value = (x.s.rflags & 0xd5) | 2;
            x.write_reg(Register::GprHigh8 { index: 0 }, value);
        }
        Mnemonic::Sahf => {
            let value = (x.s.gpr[reg::RAX] >> 8) & 0xd5;
            x.set_status(0xd5, value);
        }
        Mnemonic::Cdq => {
            let negative = x.s.gpr[reg::RAX] & 0x8000_0000 != 0;
            x.s.gpr[reg::RDX] = if negative { 0xffff_ffff } else { 0 };
        }
        Mnemonic::Cqo => {
            let negative = x.s.gpr[reg::RAX] & (1 << 63) != 0;
            x.s.gpr[reg::RDX] = if negative { u64::MAX } else { 0 };
        }
        Mnemonic::Lea => {
            let dst = op(i, 0)?;
            let Operand::Memory(m) = op(i, 1)? else {
                return Err(Stop::Invalid);
            };
            let size = Exec::size_of(dst, None);
            let ea = x.address(&m);
            x.write(dst, size, ea.0)?;
        }
        Mnemonic::Xchg => x.xchg()?,
        Mnemonic::Cmpxchg => x.cmpxchg()?,
        Mnemonic::Xadd => x.xadd()?,
        Mnemonic::Cmpxchg8b => x.cmpxchg_pair(false)?,
        Mnemonic::Cmpxchg16b => x.cmpxchg_pair(true)?,
        Mnemonic::Push => {
            let size = i.implicit_size;
            let v = x.read(op(i, 0)?, size)?;
            x.push(v, size)?;
        }
        Mnemonic::Pop => {
            let size = i.implicit_size;
            let v = x.pop(size)?;
            x.write(op(i, 0)?, size, v)?;
        }
        Mnemonic::Pushfq | Mnemonic::Pushf => {
            let v = x.s.rflags & !(flag::RF | flag::VM);
            x.push(v, i.implicit_size)?;
        }
        Mnemonic::Popfq | Mnemonic::Popf => {
            let v = x.pop(i.implicit_size)?;
            let writable = flag::USER_WRITABLE & size_mask(i.implicit_size);
            let keep = x.s.rflags & !writable;
            x.s.rflags = keep | (v & writable) | flag::RESERVED1;
        }
        Mnemonic::Call => {
            let t = x.branch_target()?;
            x.push(next.0, 8)?;
            target = Some(t);
        }
        Mnemonic::Ret => {
            let t = x.pop(8)?;
            if let Some(Operand::Immediate(extra)) = i.operand(0) {
                x.s.gpr[reg::RSP] = x.s.gpr[reg::RSP].wrapping_add(extra & 0xffff);
            }
            target = Some(t);
        }
        Mnemonic::Jmp => target = Some(x.branch_target()?),
        Mnemonic::Jrcxz | Mnemonic::Jecxz => {
            let count = x.s.gpr[reg::RCX]
                & if i.mnemonic == Mnemonic::Jecxz {
                    0xffff_ffff
                } else {
                    u64::MAX
                };
            if count == 0 {
                target = Some(x.branch_target()?);
            }
        }
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => {
            let size = if i.string_address_size_32 { 4 } else { 8 };
            let count = x.s.gpr[reg::RCX].wrapping_sub(1) & size_mask(size);
            x.write_reg(Register::Gpr { index: 1, size }, count);
            let condition = match i.mnemonic {
                Mnemonic::Loope => x.s.flag(flag::ZF),
                Mnemonic::Loopne => !x.s.flag(flag::ZF),
                _ => true,
            };
            if count != 0 && condition {
                target = Some(x.branch_target()?);
            }
        }
        Mnemonic::Jcc(c) => {
            if alu::condition(x.s.rflags, c) {
                target = Some(x.branch_target()?);
            }
        }
        Mnemonic::Setcc(c) => {
            let v = u64::from(alu::condition(x.s.rflags, c));
            x.write(op(i, 0)?, 1, v)?;
        }
        Mnemonic::Cmovcc(c) => {
            let (dst, src, size) = x.binary()?;
            // The source is read (and may fault) whatever the condition.
            let v = x.read(src, size)?;
            let v = if alu::condition(x.s.rflags, c) {
                v
            } else {
                x.read(dst, size)?
            };
            // A 32-bit cmov zero-extends the destination even when false.
            x.write(dst, size, v)?;
        }
        Mnemonic::Leave => {
            x.s.gpr[reg::RSP] = x.s.gpr[reg::RBP];
            let v = x.pop(i.implicit_size)?;
            let mask = size_mask(i.implicit_size);
            x.s.gpr[reg::RBP] = (x.s.gpr[reg::RBP] & !mask) | (v & mask);
        }
        Mnemonic::Nop | Mnemonic::Endbr64 => {}
        // Guest threads share memory across host threads, so the fences order
        // the emulator's own accesses as well.
        Mnemonic::Mfence | Mnemonic::Lfence | Mnemonic::Sfence => {
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        Mnemonic::Syscall => {
            x.s.gpr[reg::RCX] = next.0;
            x.s.gpr[reg::R11] = x.s.rflags & !flag::RF;
            x.s.rip = next;
            return Err(Stop::Syscall);
        }
        Mnemonic::Hlt => return Err(Stop::Halt),
        Mnemonic::Cld => x.s.set_flag(flag::DF, false),
        Mnemonic::Std => x.s.set_flag(flag::DF, true),
        m @ (Mnemonic::Movsb
        | Mnemonic::Movsd
        | Mnemonic::Movsq
        | Mnemonic::Stosb
        | Mnemonic::Stosd
        | Mnemonic::Stosq) => {
            if !x.string(m)? {
                // Not finished: run the same instruction again next step.
                return Ok(());
            }
        }
        m if is_string(m) => {
            if !x.string(m)? {
                return Ok(());
            }
        }
        Mnemonic::Movaps
        | Mnemonic::Movdqa
        | Mnemonic::Movntps
        | Mnemonic::Movntpd
        | Mnemonic::Movntdq => x.sse_move(true)?,
        Mnemonic::Maskmovdqu => x.sse_masked_store()?,
        // There is no cache to flush. It faults as a read of its byte does.
        Mnemonic::Clflush => {
            let Operand::Memory(m) = op(i, 0)? else {
                return Err(Stop::Invalid);
            };
            x.mem.read(x.linear(&m), &mut [0])?;
        }
        Mnemonic::Movups | Mnemonic::Movdqu => x.sse_move(false)?,
        Mnemonic::Pxor | Mnemonic::Xorps => x.sse_xor()?,
        Mnemonic::Movq => x.sse_movq()?,
        Mnemonic::Punpcklqdq => x.sse_unpack_low_qwords()?,
        Mnemonic::Rdtsc | Mnemonic::Rdtscp => {
            let [low, high] = crate::cpuid::time_stamp();
            x.s.gpr[reg::RAX] = u64::from(low);
            x.s.gpr[reg::RDX] = u64::from(high);
            // `IA32_TSC_AUX`: the only CPU there is.
            if x.i.mnemonic == Mnemonic::Rdtscp {
                x.s.gpr[reg::RCX] = 0;
            }
        }
        Mnemonic::Fxsave | Mnemonic::Fxsave64 => x.fxsave()?,
        Mnemonic::Fxrstor | Mnemonic::Fxrstor64 => x.fxrstor()?,
        Mnemonic::Fld
        | Mnemonic::Fild
        | Mnemonic::Fst
        | Mnemonic::Fstp
        | Mnemonic::Fist
        | Mnemonic::Fistp
        | Mnemonic::Fcomi
        | Mnemonic::Fcomip
        | Mnemonic::Fucomi
        | Mnemonic::Fucomip
        | Mnemonic::Fxch
        | Mnemonic::Fchs
        | Mnemonic::Fabs
        | Mnemonic::Fxam
        | Mnemonic::Fldz
        | Mnemonic::Fld1
        | Mnemonic::Fldpi
        | Mnemonic::Fldln2
        | Mnemonic::Fldlg2
        | Mnemonic::Fldl2e
        | Mnemonic::Fldl2t
        | Mnemonic::Fadd
        | Mnemonic::Faddp
        | Mnemonic::Fiadd
        | Mnemonic::Fsub
        | Mnemonic::Fsubp
        | Mnemonic::Fisub
        | Mnemonic::Fsubr
        | Mnemonic::Fsubrp
        | Mnemonic::Fisubr
        | Mnemonic::Fmul
        | Mnemonic::Fmulp
        | Mnemonic::Fimul
        | Mnemonic::Fdiv
        | Mnemonic::Fdivp
        | Mnemonic::Fidiv
        | Mnemonic::Fdivr
        | Mnemonic::Fdivrp
        | Mnemonic::Fidivr
        | Mnemonic::Fsqrt
        | Mnemonic::Fprem
        | Mnemonic::Fprem1
        | Mnemonic::Frndint
        | Mnemonic::Fscale
        | Mnemonic::Fxtract
        | Mnemonic::Fcom
        | Mnemonic::Fcomp
        | Mnemonic::Fcompp
        | Mnemonic::Fucom
        | Mnemonic::Fucomp
        | Mnemonic::Fucompp
        | Mnemonic::Ficom
        | Mnemonic::Ficomp
        | Mnemonic::Ftst
        | Mnemonic::Fcmovb
        | Mnemonic::Fcmove
        | Mnemonic::Fcmovbe
        | Mnemonic::Fcmovu
        | Mnemonic::Fcmovnb
        | Mnemonic::Fcmovne
        | Mnemonic::Fcmovnbe
        | Mnemonic::Fcmovnu
        | Mnemonic::Fnop
        | Mnemonic::Ffree
        | Mnemonic::Fincstp
        | Mnemonic::Fdecstp
        | Mnemonic::Fnstcw
        | Mnemonic::Fldcw
        | Mnemonic::Fnstsw
        | Mnemonic::Fnclex
        | Mnemonic::Fninit
        | Mnemonic::Fnstenv
        | Mnemonic::Fldenv
        | Mnemonic::Wait => x.x87()?,
        Mnemonic::Cpuid => {
            let values = crate::cpuid::values(x.s.gpr[reg::RAX] as u32, x.s.gpr[reg::RCX] as u32);
            for (index, value) in [reg::RAX, reg::RBX, reg::RCX, reg::RDX]
                .into_iter()
                .zip(values)
            {
                x.s.gpr[index] = u64::from(value);
            }
        }
        _ => x.sse_misc()?,
    }
    x.s.rip = GuestAddr(target.unwrap_or(next.0));
    Ok(())
}
