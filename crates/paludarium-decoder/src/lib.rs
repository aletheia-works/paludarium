//! x86-64 instruction decoder for paludarium (contract C3).
//!
//! Wraps the `iced-x86` crate (MIT). None of its types appear in this
//! crate's API (ADR-006): callers get [`Instruction`], [`Operand`] and
//! [`Mnemonic`] defined here, so the decoder can be replaced or partly
//! re-implemented without touching the CPU.
//!
//! Only the mnemonics paludarium knows are mapped. VEX is accepted only for
//! the supported scalar BMI instructions; SIMD VEX, EVEX and XOP are reported
//! as [`DecodeError::Unsupported`]. Later units extend [`Mnemonic`].
#![forbid(unsafe_code)]
#[cfg(test)]
mod encodings_tests;

use iced_x86 as iced;
use paludarium_types::GuestAddr;

/// Why an instruction could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes are not a valid x86-64 instruction.
    Invalid,
    /// A valid instruction outside paludarium's supported set.
    Unsupported,
    /// The bytes end before the instruction does.
    NeedMoreBytes,
}

/// Condition codes of `jcc`, `setcc` and `cmovcc`, in encoding order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Condition {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
}

macro_rules! mnemonics {
    ($($name:ident),* $(,)?) => {
        /// Instruction mnemonics known to paludarium. Conditional forms
        /// carry their [`Condition`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Mnemonic {
            $($name,)*
            /// Legacy scalar-double move (distinct from string MOVSD).
            MovsdSse,
            /// Legacy scalar-double compare (distinct from string CMPSD).
            CmpsdSse,
            Jcc(Condition),
            Setcc(Condition),
            Cmovcc(Condition),
        }

        fn map_plain(m: iced::Mnemonic) -> Option<Mnemonic> {
            match m {
                $(iced::Mnemonic::$name => Some(Mnemonic::$name),)*
                _ => None,
            }
        }
    };
}

mnemonics!(
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Cmp,
    Test,
    Inc,
    Dec,
    Neg,
    Not,
    Shl,
    Shr,
    Sar,
    Imul,
    Mul,
    Div,
    Idiv,
    Bt,
    Mov,
    Movsx,
    Movsxd,
    Movzx,
    Cdqe,
    Cdq,
    Cqo,
    Lea,
    Xchg,
    Cmpxchg,
    Push,
    Pop,
    Pushfq,
    Popfq,
    Call,
    Ret,
    Jmp,
    Leave,
    Nop,
    Endbr64,
    Syscall,
    Hlt,
    Movsb,
    Movsd,
    Movsq,
    Stosb,
    Stosd,
    Stosq,
    Movsw,
    Stosw,
    Lodsb,
    Lodsw,
    Lodsd,
    Lodsq,
    Cmpsb,
    Cmpsw,
    Cmpsd,
    Cmpsq,
    Scasb,
    Scasw,
    Scasd,
    Scasq,
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shld,
    Shrd,
    Bsf,
    Bsr,
    Tzcnt,
    Lzcnt,
    Popcnt,
    Bswap,
    Bts,
    Btr,
    Btc,
    Xadd,
    Cmpxchg8b,
    Cmpxchg16b,
    Cbw,
    Cwde,
    Cwd,
    Clc,
    Stc,
    Cmc,
    Cld,
    Std,
    Lahf,
    Sahf,
    Jrcxz,
    Jecxz,
    Loop,
    Loope,
    Loopne,
    Ud2,
    Adcx,
    Adox,
    Andn,
    Bzhi,
    Movbe,
    Mulx,
    Pext,
    Rorx,
    Shlx,
    Shrx,
    Enter,
    Xlatb,
    Pushf,
    Popf,
    Movaps,
    Movups,
    Movdqa,
    Movdqu,
    Movq,
    Punpcklqdq,
    Pxor,
    Xorps,
    Addpd,
    Addps,
    Addsd,
    Andnpd,
    Andpd,
    Andps,
    Blendvps,
    Comisd,
    Cvtdq2ps,
    Cvtsi2sd,
    Cvtss2sd,
    Cvttps2dq,
    Cvttsd2si,
    Cvttss2si,
    Divpd,
    Divsd,
    Divss,
    Lddqu,
    Ldmxcsr,
    Maxsd,
    Minsd,
    Movapd,
    Movd,
    Movddup,
    Movhlps,
    Movhpd,
    Movhps,
    Movlhps,
    Movlpd,
    Movlps,
    Movmskpd,
    Movmskps,
    Movss,
    Movupd,
    Mulpd,
    Mulsd,
    Orpd,
    Orps,
    Packssdw,
    Packsswb,
    Packuswb,
    Paddb,
    Paddd,
    Paddq,
    Paddusw,
    Paddw,
    Palignr,
    Pand,
    Pandn,
    Pblendw,
    Pcmpeqb,
    Pcmpeqd,
    Pcmpeqw,
    Pcmpgtb,
    Pcmpgtd,
    Pcmpgtw,
    Pextrb,
    Pextrd,
    Pextrq,
    Pextrw,
    Pinsrb,
    Pinsrd,
    Pinsrq,
    Pinsrw,
    Pmaddubsw,
    Pmaddwd,
    Pmaxub,
    Pminub,
    Pmovmskb,
    Pmovzxdq,
    Pmulhuw,
    Pmulhw,
    Pmullw,
    Pmuludq,
    Por,
    Psadbw,
    Pshufb,
    Pshufd,
    Pshufhw,
    Pshuflw,
    Pslld,
    Pslldq,
    Psllq,
    Psllw,
    Psrad,
    Psraw,
    Psrld,
    Psrldq,
    Psrlq,
    Psrlw,
    Psubb,
    Psubd,
    Psubq,
    Psubusb,
    Psubusw,
    Psubw,
    Ptest,
    Punpckhbw,
    Punpckhdq,
    Punpckhqdq,
    Punpckhwd,
    Punpcklbw,
    Punpckldq,
    Punpcklwd,
    Shufpd,
    Shufps,
    Sqrtps,
    Sqrtsd,
    Subpd,
    Subsd,
    Ucomisd,
    Ucomiss,
    Unpckhpd,
    Unpcklpd,
    Unpcklps,
    Xorpd,
    Sha256rnds2,
    Sha256msg1,
    Sha256msg2,
    Aesenc,
    Aesenclast,
    Pclmulqdq,
    Cpuid,
    Stmxcsr,
);

fn condition(code: iced::ConditionCode) -> Option<Condition> {
    use iced::ConditionCode as C;
    Some(match code {
        C::o => Condition::O,
        C::no => Condition::No,
        C::b => Condition::B,
        C::ae => Condition::Ae,
        C::e => Condition::E,
        C::ne => Condition::Ne,
        C::be => Condition::Be,
        C::a => Condition::A,
        C::s => Condition::S,
        C::ns => Condition::Ns,
        C::p => Condition::P,
        C::np => Condition::Np,
        C::l => Condition::L,
        C::ge => Condition::Ge,
        C::le => Condition::Le,
        C::g => Condition::G,
        _ => return None,
    })
}

fn map_mnemonic(insn: &iced::Instruction) -> Option<Mnemonic> {
    use iced::Mnemonic as M;
    let m = insn.mnemonic();
    if matches!(
        insn.code(),
        iced::Code::Movsd_xmm_xmmm64 | iced::Code::Movsd_xmmm64_xmm
    ) {
        return Some(Mnemonic::MovsdSse);
    }
    if insn.code() == iced::Code::Cmpsd_xmm_xmmm64_imm8 {
        return Some(Mnemonic::CmpsdSse);
    }
    if m == M::Pause {
        return Some(Mnemonic::Nop);
    }
    let conditional = match m {
        M::Jo
        | M::Jno
        | M::Jb
        | M::Jae
        | M::Je
        | M::Jne
        | M::Jbe
        | M::Ja
        | M::Js
        | M::Jns
        | M::Jp
        | M::Jnp
        | M::Jl
        | M::Jge
        | M::Jle
        | M::Jg => Some(Mnemonic::Jcc(condition(insn.condition_code())?)),
        M::Seto
        | M::Setno
        | M::Setb
        | M::Setae
        | M::Sete
        | M::Setne
        | M::Setbe
        | M::Seta
        | M::Sets
        | M::Setns
        | M::Setp
        | M::Setnp
        | M::Setl
        | M::Setge
        | M::Setle
        | M::Setg => Some(Mnemonic::Setcc(condition(insn.condition_code())?)),
        M::Cmovo
        | M::Cmovno
        | M::Cmovb
        | M::Cmovae
        | M::Cmove
        | M::Cmovne
        | M::Cmovbe
        | M::Cmova
        | M::Cmovs
        | M::Cmovns
        | M::Cmovp
        | M::Cmovnp
        | M::Cmovl
        | M::Cmovge
        | M::Cmovle
        | M::Cmovg => Some(Mnemonic::Cmovcc(condition(insn.condition_code())?)),
        _ => None,
    };
    conditional.or_else(|| map_plain(m))
}

/// A general-purpose or SSE register as an operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Register {
    /// General-purpose register `index` (0 = rax ... 15 = r15) accessed with
    /// `size` bytes (8, 4, 2 or 1; size 1 is the low byte: al, spl, r8b ...).
    Gpr { index: u8, size: u8 },
    /// The legacy high-byte registers ah, ch, dh, bh (`index` 0..=3 is the
    /// register they belong to).
    GprHigh8 { index: u8 },
    /// xmm0 ..= xmm15.
    Xmm(u8),
}

impl Register {
    /// Operand size in bytes.
    #[must_use]
    pub const fn size(self) -> u8 {
        match self {
            Register::Gpr { size, .. } => size,
            Register::GprHigh8 { .. } => 1,
            Register::Xmm(_) => 16,
        }
    }
}

/// Segment override of a memory operand. Only fs and gs have a base in
/// 64-bit mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Segment {
    #[default]
    None,
    Fs,
    Gs,
}

/// A memory operand: `segment:[base + index*scale + displacement]`.
/// RIP-relative operands are resolved: `base` is `None` and `displacement`
/// holds the absolute address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryOperand {
    pub segment: Segment,
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8,
    pub displacement: u64,
    /// Size of the accessed value in bytes (0 for `lea` and `nop`).
    pub size: u8,
    /// The 0x67 prefix: the effective address is truncated to 32 bits.
    pub address_size_32: bool,
}

/// One operand of a decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operand {
    Register(Register),
    /// Immediate, sign-extended to 64 bits where the encoding sign-extends.
    Immediate(u64),
    Memory(MemoryOperand),
    /// Absolute target of a relative branch.
    Branch(GuestAddr),
}

/// `rep`/`repne` prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RepPrefix {
    #[default]
    None,
    Rep,
    Repne,
}

/// Maximum number of explicit operands kept (x86 has at most four; the
/// U1 instruction set needs three).
pub const MAX_OPERANDS: usize = 3;

/// A decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub mnemonic: Mnemonic,
    /// Length in bytes (1..=15).
    pub len: u8,
    /// Address of the instruction.
    pub rip: GuestAddr,
    operands: [Option<Operand>; MAX_OPERANDS],
    pub rep: RepPrefix,
    pub lock: bool,
    /// Element size in bytes for string instructions and the operand size
    /// of `push`/`pop`/`cqo` style instructions with implicit operands.
    pub implicit_size: u8,
    /// Address-size override for implicit RSI/RDI/RCX string operands.
    pub string_address_size_32: bool,
    /// Segment override of the implicit string source (destination is ES).
    pub string_segment: Segment,
}

impl Instruction {
    /// Explicit operands in Intel order (destination first).
    pub fn operands(&self) -> impl Iterator<Item = Operand> + '_ {
        self.operands.iter().map_while(|o| *o)
    }

    /// Operand `n`, if present.
    #[must_use]
    pub fn operand(&self, n: usize) -> Option<Operand> {
        self.operands.get(n).copied().flatten()
    }

    /// Number of explicit operands.
    #[must_use]
    pub fn operand_count(&self) -> usize {
        self.operands().count()
    }

    /// Address of the next instruction.
    #[must_use]
    pub fn next_rip(&self) -> GuestAddr {
        self.rip.wrapping_add(u64::from(self.len))
    }
}

fn map_register(r: iced::Register) -> Option<Register> {
    let number = u8::try_from(r.number()).ok()?;
    if r.is_gpr64() {
        Some(Register::Gpr {
            index: number,
            size: 8,
        })
    } else if r.is_gpr32() {
        Some(Register::Gpr {
            index: number,
            size: 4,
        })
    } else if r.is_gpr16() {
        Some(Register::Gpr {
            index: number,
            size: 2,
        })
    } else if r.is_gpr8() {
        // iced numbering: al cl dl bl ah ch dh bh spl bpl sil dil r8b..r15b.
        match number {
            0..=3 => Some(Register::Gpr {
                index: number,
                size: 1,
            }),
            4..=7 => Some(Register::GprHigh8 { index: number - 4 }),
            8..=19 => Some(Register::Gpr {
                index: number - 4,
                size: 1,
            }),
            _ => None,
        }
    } else if r.is_xmm() && number < 16 {
        Some(Register::Xmm(number))
    } else {
        None
    }
}

fn map_memory(insn: &iced::Instruction) -> Option<MemoryOperand> {
    let segment = match insn.memory_segment() {
        iced::Register::FS => Segment::Fs,
        iced::Register::GS => Segment::Gs,
        _ => Segment::None,
    };
    let base_reg = insn.memory_base();
    let (base, address_size_32) = match base_reg {
        iced::Register::None => (None, false),
        iced::Register::RIP => (None, false),
        iced::Register::EIP => (None, true),
        r => (Some(map_register(r)?), r.is_gpr32()),
    };
    let index = match insn.memory_index() {
        iced::Register::None => None,
        r => Some(map_register(r)?),
    };
    let size = u8::try_from(insn.memory_size().size()).ok()?;
    Some(MemoryOperand {
        segment,
        base,
        index,
        scale: u8::try_from(insn.memory_index_scale()).ok()?,
        displacement: insn.memory_displacement64(),
        size,
        address_size_32: address_size_32 || index.is_some_and(|i| i.size() == 4),
    })
}

fn map_operand(insn: &iced::Instruction, n: u32) -> Option<Operand> {
    use iced::OpKind as K;
    Some(match insn.op_kind(n) {
        K::Register => Operand::Register(map_register(insn.op_register(n))?),
        K::NearBranch64 | K::NearBranch32 | K::NearBranch16 => {
            Operand::Branch(GuestAddr(insn.near_branch_target()))
        }
        K::Immediate8
        | K::Immediate16
        | K::Immediate32
        | K::Immediate64
        | K::Immediate8to16
        | K::Immediate8to32
        | K::Immediate8to64
        | K::Immediate32to64
        | K::Immediate8_2nd => Operand::Immediate(insn.immediate(n)),
        K::Memory => Operand::Memory(map_memory(insn)?),
        _ => return None,
    })
}

fn is_string(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Movsb
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Movsw
            | Mnemonic::Stosw
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
    )
}

/// Decodes the instruction at the start of `bytes`, located at `rip`.
pub fn decode(bytes: &[u8], rip: GuestAddr) -> Result<Instruction, DecodeError> {
    // iced-x86 1.21.0 subtracts truncated host pointers when calculating an
    // instruction's length. Keep the maximum x86 instruction (15 bytes) in a
    // 16-byte-aligned buffer so that read cannot cross a 4 GiB boundary.
    #[repr(align(16))]
    struct AlignedInstruction([u8; 15]);
    let mut input = AlignedInstruction([0; 15]);
    let len = bytes.len().min(input.0.len());
    input.0[..len].copy_from_slice(&bytes[..len]);
    let mut decoder =
        iced::Decoder::with_ip(64, &input.0[..len], rip.0, iced::DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() {
        return Err(match decoder.last_error() {
            iced::DecoderError::NoMoreBytes => DecodeError::NeedMoreBytes,
            _ => DecodeError::Invalid,
        });
    }
    let mnemonic = map_mnemonic(&insn).ok_or(DecodeError::Unsupported)?;
    // Same-half selectors are assigned; ignored immediate bits stay ignored.
    if mnemonic == Mnemonic::Pclmulqdq && !matches!(insn.immediate8() & 0x11, 0 | 0x11) {
        return Err(DecodeError::Unsupported);
    }
    let integer_vex = insn.encoding() == iced::EncodingKind::VEX
        && matches!(
            mnemonic,
            Mnemonic::Andn
                | Mnemonic::Bzhi
                | Mnemonic::Mulx
                | Mnemonic::Pext
                | Mnemonic::Rorx
                | Mnemonic::Shlx
                | Mnemonic::Shrx
        );
    if insn.encoding() != iced::EncodingKind::Legacy && !integer_vex {
        return Err(DecodeError::Unsupported);
    }
    let len = u8::try_from(insn.len()).map_err(|_| DecodeError::Invalid)?;

    let mut operands = [None; MAX_OPERANDS];
    let count = usize::try_from(insn.op_count()).map_err(|_| DecodeError::Invalid)?;
    let implicit_size = if is_string(mnemonic) {
        // `movsd` is also the SSE scalar-double move; only the string form
        // (implicit rdi destination) is a string instruction.
        if !(0..insn.op_count()).any(|n| {
            matches!(
                insn.op_kind(n),
                iced::OpKind::MemorySegRSI
                    | iced::OpKind::MemorySegESI
                    | iced::OpKind::MemoryESRDI
                    | iced::OpKind::MemoryESEDI
            )
        }) {
            return Err(DecodeError::Unsupported);
        }
        // The memory operands of string instructions are implicit
        // (rsi/rdi); keep only the element size.
        u8::try_from(insn.memory_size().size()).map_err(|_| DecodeError::Invalid)?
    } else {
        if count > MAX_OPERANDS {
            return Err(DecodeError::Unsupported);
        }
        for (n, slot) in operands.iter_mut().enumerate().take(count) {
            let index = u32::try_from(n).map_err(|_| DecodeError::Invalid)?;
            *slot = Some(map_operand(&insn, index).ok_or(DecodeError::Unsupported)?);
        }
        match mnemonic {
            Mnemonic::Push | Mnemonic::Pop => match operands[0] {
                Some(Operand::Register(r)) => r.size(),
                Some(Operand::Memory(m)) => m.size,
                // push imm: 8 bytes unless a 0x66 prefix makes it 2.
                _ => {
                    if insn.code() == iced::Code::Pushq_imm8
                        || insn.code() == iced::Code::Pushq_imm32
                    {
                        8
                    } else {
                        2
                    }
                }
            },
            Mnemonic::Pushfq | Mnemonic::Popfq => 8,
            Mnemonic::Pushf | Mnemonic::Popf => 2,
            Mnemonic::Leave => {
                if insn.code() == iced::Code::Leavew {
                    2
                } else {
                    8
                }
            }
            Mnemonic::Cmpxchg8b => 8,
            Mnemonic::Cmpxchg16b => 16,
            Mnemonic::Enter => {
                if insn.code() == iced::Code::Enterq_imm16_imm8 {
                    8
                } else {
                    2
                }
            }
            _ => 0,
        }
    };

    let rep = if insn.has_rep_prefix() {
        RepPrefix::Rep
    } else if insn.has_repne_prefix() {
        RepPrefix::Repne
    } else {
        RepPrefix::None
    };

    Ok(Instruction {
        mnemonic,
        len,
        rip,
        operands,
        rep,
        lock: insn.has_lock_prefix(),
        implicit_size,
        string_address_size_32: (is_string(mnemonic)
            && (0..insn.op_count()).any(|n| {
                matches!(
                    insn.op_kind(n),
                    iced::OpKind::MemorySegESI | iced::OpKind::MemoryESEDI
                )
            }))
            || matches!(
                insn.code(),
                iced::Code::Loop_rel8_64_ECX
                    | iced::Code::Loope_rel8_64_ECX
                    | iced::Code::Loopne_rel8_64_ECX
            ),
        string_segment: match insn.segment_prefix() {
            iced::Register::FS => Segment::Fs,
            iced::Register::GS => Segment::Gs,
            _ => Segment::None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_fuzz_reproducer_and_instruction_length_boundaries() {
        // jit_compile's crash input: the first eight bytes are its guest RIP.
        let bytes = [
            0x4a, 0x48, 0x05, 0xff, 0x4a, 0x4a, 0xe1, 0x4a, 0x48, 0x05, 0x6e, 0x3b, 0x27, 0x4a,
            0x4a, 0x05, 0xff, 0x93, 0x3f, 0x93, 0x93, 0x93, 0x93, 0x93,
        ];
        let rip = GuestAddr(0xe14a_4ae1_e100_e100);
        for len in [0, 1, 14, 15, 16, bytes.len()] {
            let result = decode(&bytes[..len], rip);
            if len > 15 {
                assert_eq!(result, decode(&bytes[..15], rip));
            }
        }
        let nop = [0x90; 16];
        assert_eq!(decode(&nop, rip), decode(&nop[..15], rip));
    }

    #[test]
    fn u2_cmps_repe_keeps_implicit_width() {
        let i = decode(&[0xf3, 0xa6], GuestAddr(0x1000)).unwrap();
        assert_eq!(
            (i.mnemonic, i.rep, i.implicit_size),
            (Mnemonic::Cmpsb, RepPrefix::Rep, 1)
        );
    }
    #[test]
    fn u2_scas_repne_and_address32() {
        let i = decode(&[0x67, 0xf2, 0xae], GuestAddr(0)).unwrap();
        assert_eq!(
            (i.mnemonic, i.rep, i.implicit_size),
            (Mnemonic::Scasb, RepPrefix::Repne, 1)
        );
        assert!(i.string_address_size_32);
    }
    #[test]
    fn u2_string_16bit_and_source_segment() {
        let i = decode(&[0x64, 0x66, 0xf3, 0xa5], GuestAddr(0)).unwrap();
        assert_eq!(
            (i.mnemonic, i.implicit_size, i.string_segment),
            (Mnemonic::Movsw, 2, Segment::Fs)
        );
    }
    #[test]
    fn u2_lods_has_implicit_accumulator() {
        let i = decode(&[0x48, 0xad], GuestAddr(0)).unwrap();
        assert_eq!((i.mnemonic, i.implicit_size), (Mnemonic::Lodsq, 8));
    }
    #[test]
    fn u2_cmpxchg16b_is_integer_memory_pair() {
        let i = decode(&[0xf0, 0x48, 0x0f, 0xc7, 0x0f], GuestAddr(0)).unwrap();
        assert!(i.lock);
        assert_eq!((i.mnemonic, i.implicit_size), (Mnemonic::Cmpxchg16b, 16));
        assert!(matches!(i.operand(0),Some(Operand::Memory(m)) if m.size == 16));
    }
    #[test]
    fn u2_invalid_lock_and_truncated_form_are_distinct() {
        assert_eq!(
            decode(&[0xf0, 0x48, 0x01, 0xc0], GuestAddr(0)),
            Err(DecodeError::Invalid)
        );
        assert_eq!(
            decode(&[0xf0, 0x48, 0x0f, 0xc7], GuestAddr(0)),
            Err(DecodeError::NeedMoreBytes)
        );
    }
    #[test]
    fn u2_rotate_and_xadd_expose_scalar_operands() {
        let r = decode(&[0x48, 0xd3, 0xc0], GuestAddr(0)).unwrap();
        assert_eq!(r.mnemonic, Mnemonic::Rol);
        let a = decode(&[0xf0, 0x48, 0x0f, 0xc1, 0x07], GuestAddr(0)).unwrap();
        assert_eq!(a.mnemonic, Mnemonic::Xadd);
        assert!(a.lock);
    }

    const RIP: GuestAddr = GuestAddr(0x401000);

    fn gpr(index: u8, size: u8) -> Operand {
        Operand::Register(Register::Gpr { index, size })
    }

    #[test]
    fn decodes_register_and_immediate_operands() {
        // add rsp, 8 (48 83 c4 08)
        let i = decode(&[0x48, 0x83, 0xc4, 0x08], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Add);
        assert_eq!(i.len, 4);
        assert_eq!(i.operand(0), Some(gpr(4, 8)));
        assert_eq!(i.operand(1), Some(Operand::Immediate(8)));
        assert_eq!(i.next_rip(), GuestAddr(0x401004));
        // and rsp, -16 sign-extends the immediate.
        let i = decode(&[0x48, 0x83, 0xe4, 0xf0], RIP).unwrap();
        assert_eq!(
            i.operand(1),
            Some(Operand::Immediate(0xffff_ffff_ffff_fff0))
        );
    }

    #[test]
    fn resolves_rip_relative_and_fs_memory() {
        // mov rax, [rip+0x10] at 0x401000, length 7 -> 0x401017
        let i = decode(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0], RIP).unwrap();
        let Some(Operand::Memory(m)) = i.operand(1) else {
            panic!("memory")
        };
        assert_eq!(m.base, None);
        assert_eq!(m.displacement, 0x401017);
        assert_eq!(m.size, 8);
        // mov rax, fs:[0] (64 48 8b 04 25 00 00 00 00)
        let i = decode(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0], RIP).unwrap();
        let Some(Operand::Memory(m)) = i.operand(1) else {
            panic!("memory")
        };
        assert_eq!(m.segment, Segment::Fs);
        assert_eq!(m.index, None);
    }

    #[test]
    fn maps_byte_registers_including_high_and_rex_forms() {
        // mov ah, al (88 c4); mov sil, al (40 88 c6); mov r9b, al (41 88 c1)
        let i = decode(&[0x88, 0xc4], RIP).unwrap();
        assert_eq!(
            i.operand(0),
            Some(Operand::Register(Register::GprHigh8 { index: 0 }))
        );
        assert_eq!(i.operand(1), Some(gpr(0, 1)));
        let i = decode(&[0x40, 0x88, 0xc6], RIP).unwrap();
        assert_eq!(i.operand(0), Some(gpr(6, 1)));
        let i = decode(&[0x41, 0x88, 0xc1], RIP).unwrap();
        assert_eq!(i.operand(0), Some(gpr(9, 1)));
    }

    #[test]
    fn decodes_conditions_and_branches() {
        // je +2 (74 02) at 0x401000 -> 0x401004
        let i = decode(&[0x74, 0x02], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Jcc(Condition::E));
        assert_eq!(i.operand(0), Some(Operand::Branch(GuestAddr(0x401004))));
        // setne al (0f 95 c0); cmovns rax, rbx (48 0f 49 c3)
        assert_eq!(
            decode(&[0x0f, 0x95, 0xc0], RIP).unwrap().mnemonic,
            Mnemonic::Setcc(Condition::Ne)
        );
        assert_eq!(
            decode(&[0x48, 0x0f, 0x49, 0xc3], RIP).unwrap().mnemonic,
            Mnemonic::Cmovcc(Condition::Ns)
        );
    }

    #[test]
    fn string_and_prefixed_instructions() {
        // rep stosq (f3 48 ab); lock cmpxchg [rbx], edx (f0 0f b1 13)
        let i = decode(&[0xf3, 0x48, 0xab], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Stosq);
        assert_eq!(i.rep, RepPrefix::Rep);
        assert_eq!(i.implicit_size, 8);
        assert_eq!(i.operand_count(), 0);
        let i = decode(&[0xf0, 0x0f, 0xb1, 0x13], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Cmpxchg);
        assert!(i.lock);
        // push rbp (55) and push imm8 (6a ff)
        assert_eq!(decode(&[0x55], RIP).unwrap().implicit_size, 8);
        let i = decode(&[0x6a, 0xff], RIP).unwrap();
        assert_eq!(i.implicit_size, 8);
        assert_eq!(i.operand(0), Some(Operand::Immediate(u64::MAX)));
    }

    #[test]
    fn reports_errors() {
        assert_eq!(decode(&[], RIP), Err(DecodeError::NeedMoreBytes));
        // Truncated mov rax, imm64.
        assert_eq!(
            decode(&[0x48, 0xb8, 1, 2], RIP),
            Err(DecodeError::NeedMoreBytes)
        );
        // 0x06 (push es) is invalid in 64-bit mode.
        assert_eq!(decode(&[0x06, 0, 0, 0], RIP), Err(DecodeError::Invalid));
        // vpxor xmm0, xmm0, xmm0 (VEX) is outside the supported set.
        assert_eq!(
            decode(&[0xc5, 0xf9, 0xef, 0xc0], RIP),
            Err(DecodeError::Unsupported)
        );
        // XGETBV remains outside the explicitly assigned virtual CPU profile.
        assert_eq!(
            decode(&[0x0f, 0x01, 0xd0], RIP),
            Err(DecodeError::Unsupported)
        );
    }

    #[test]
    fn u2_integer_vex_does_not_enable_simd_vex() {
        assert_eq!(
            decode(&[0xc4, 0x42, 0x50, 0xf2, 0xc7], RIP)
                .unwrap()
                .mnemonic,
            Mnemonic::Andn
        );
        assert_eq!(
            decode(&[0xc5, 0xf9, 0xef, 0xc0], RIP),
            Err(DecodeError::Unsupported)
        );
    }

    #[test]
    fn u2_word_stack_forms_keep_two_byte_operand_width() {
        for bytes in [
            &[0x66, 0x9c][..],
            &[0x66, 0x9d][..],
            &[0x66, 0xc9][..],
            &[0x66, 0xc8, 24, 0, 6][..],
        ] {
            assert_eq!(decode(bytes, RIP).unwrap().implicit_size, 2);
        }
        // REX.W after 66 selects the qword form, as observed by native POPF.
        let popf = decode(&[0x66, 0x49, 0x9d], RIP).unwrap();
        assert_eq!(popf.implicit_size, 8);
    }

    #[test]
    fn decodes_sse_moves() {
        // movaps [rbp-0x70], xmm0 (0f 29 45 90); pxor xmm0, xmm0 (66 0f ef c0)
        let i = decode(&[0x0f, 0x29, 0x45, 0x90], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Movaps);
        let Some(Operand::Memory(m)) = i.operand(0) else {
            panic!("memory")
        };
        assert_eq!(m.size, 16);
        assert_eq!(m.displacement, (-0x70i64) as u64);
        let i = decode(&[0x66, 0x0f, 0xef, 0xc0], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Pxor);
        assert_eq!(i.operand(1), Some(Operand::Register(Register::Xmm(0))));
    }

    #[test]
    fn decodes_legacy_movq_and_low_qword_unpack() {
        let i = decode(&[0x66, 0x48, 0x0f, 0x6e, 0xc0], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Movq);
        assert_eq!(i.operand(0), Some(Operand::Register(Register::Xmm(0))));
        assert_eq!(
            i.operand(1),
            Some(Operand::Register(Register::Gpr { index: 0, size: 8 }))
        );
        let i = decode(&[0x66, 0x0f, 0x6c, 0xc1], RIP).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::Punpcklqdq);
        assert_eq!(i.operand(1), Some(Operand::Register(Register::Xmm(1))));
        // MMX and AVX remain outside the supported legacy XMM forms.
        assert_eq!(
            decode(&[0x0f, 0x6f, 0xc0], RIP),
            Err(DecodeError::Unsupported)
        );
        assert_eq!(
            decode(&[0xc5, 0xf9, 0x6c, 0xc1], RIP),
            Err(DecodeError::Unsupported)
        );
    }

    #[test]
    fn never_panics_on_arbitrary_prefix_bytes() {
        for first in 0..=255u8 {
            let bytes = [first, 0x0f, 0x38, 0xff, 0xff, 0xff, 0xff, 0xff];
            let _ = decode(&bytes, GuestAddr(u64::MAX));
        }
    }
}
