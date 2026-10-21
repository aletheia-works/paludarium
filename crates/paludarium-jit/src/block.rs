//! Register-only subset, observed before implementation on real Linux.
//!
//! This file is the single place that decides which instruction forms the
//! JIT accepts: [`operation`] checks the decoded form and [`extract`] adds
//! the raw-encoding check for the integer-SSE forms. Everything else
//! (memory operands, VEX, lock/rep/segment prefixes, other mnemonics) ends
//! the block and stays with the interpreter.
use paludarium_decoder::{Condition, Mnemonic, Operand, Register, RepPrefix, decode};
use paludarium_types::GuestAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arithmetic {
    Add,
    Sub,
    Compare,
}

/// Integer-SSE register forms (all operands XMM0..15, legacy 0x66 encoding).
/// None of them reads or writes RFLAGS or guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Vector {
    /// MOVDQA xmm, xmm (0F 6F and 0F 7F register forms).
    Move,
    /// PAND.
    And,
    /// POR.
    Or,
    /// PXOR.
    Xor,
    /// PADDD (each dword wraps around).
    AddDwords,
    /// PSUBD (each dword wraps around).
    SubDwords,
    /// PMULUDQ: dwords 0 and 2 multiplied into two unsigned qwords.
    MultiplyUnsignedDwords,
    /// PUNPCKLDQ.
    UnpackLowDwords,
    /// PACKUSWB: signed words saturated to unsigned bytes.
    PackUnsignedBytes,
    /// PSHUFD with its imm8 selector.
    ShuffleDwords(u8),
    /// PSLLD xmm, imm8 (counts of 32 or more clear every dword).
    ShiftLeftDwords(u64),
    /// PSRLD xmm, imm8 (counts of 32 or more clear every dword).
    ShiftRightDwords(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Move {
        register: u8,
        value: u64,
    },
    Arithmetic {
        kind: Arithmetic,
        register: u8,
        value: u64,
    },
    Branch {
        equal: bool,
        target: u64,
        fallthrough: u64,
    },
    /// `destination = destination <kind> source`; shifts use only `destination`.
    Vector {
        kind: Vector,
        destination: u8,
        source: u8,
    },
}

fn xmm(operand: Option<Operand>) -> Option<u8> {
    match operand {
        Some(Operand::Register(Register::Xmm(index))) if index < 16 => Some(index),
        _ => None,
    }
}

/// Decoded-form check of the integer-SSE register forms. The raw encoding
/// is checked separately by [`legacy_sse_encoding`] during extraction.
fn vector(instruction: &paludarium_decoder::Instruction) -> Option<Operation> {
    let destination = xmm(instruction.operand(0))?;
    let third = instruction.operand(2);
    let kind = match (instruction.mnemonic, instruction.operand(1), third) {
        (Mnemonic::Pslld, Some(Operand::Immediate(count)), None) => Vector::ShiftLeftDwords(count),
        (Mnemonic::Psrld, Some(Operand::Immediate(count)), None) => Vector::ShiftRightDwords(count),
        (Mnemonic::Pshufd, Some(source), Some(Operand::Immediate(selector))) => {
            xmm(Some(source))?;
            Vector::ShuffleDwords(selector as u8)
        }
        (mnemonic, Some(source), None) => {
            xmm(Some(source))?;
            match mnemonic {
                Mnemonic::Movdqa => Vector::Move,
                Mnemonic::Pand => Vector::And,
                Mnemonic::Por => Vector::Or,
                Mnemonic::Pxor => Vector::Xor,
                Mnemonic::Paddd => Vector::AddDwords,
                Mnemonic::Psubd => Vector::SubDwords,
                Mnemonic::Pmuludq => Vector::MultiplyUnsignedDwords,
                Mnemonic::Punpckldq => Vector::UnpackLowDwords,
                Mnemonic::Packuswb => Vector::PackUnsignedBytes,
                _ => return None,
            }
        }
        _ => return None,
    };
    let source = match kind {
        Vector::ShiftLeftDwords(_) | Vector::ShiftRightDwords(_) => destination,
        _ => xmm(instruction.operand(1))?,
    };
    Some(Operation::Vector {
        kind,
        destination,
        source,
    })
}

/// Raw-byte check for an accepted vector form: exactly one 0x66 prefix, an
/// optional REX, the two-byte 0x0F opcode and a register ModRM (mod = 3),
/// plus one imm8 for PSHUFD/PSLLD/PSRLD. Segment, 0x67, F2/F3, lock and
/// repeated prefixes therefore fall back to the interpreter.
fn legacy_sse_encoding(bytes: &[u8], length: usize, kind: Vector) -> bool {
    let Some(encoding) = bytes.get(..length) else {
        return false;
    };
    let rex = usize::from(encoding.get(1).is_some_and(|byte| byte & 0xf0 == 0x40));
    let immediate = usize::from(matches!(
        kind,
        Vector::ShuffleDwords(_) | Vector::ShiftLeftDwords(_) | Vector::ShiftRightDwords(_)
    ));
    encoding.first() == Some(&0x66)
        && encoding.get(1 + rex) == Some(&0x0f)
        && encoding.get(3 + rex).is_some_and(|modrm| modrm >> 6 == 3)
        && length == 4 + rex + immediate
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    pub entry: u64,
    pub end: u64,
    pub operations: Vec<Operation>,
}

pub(crate) fn operation(instruction: &paludarium_decoder::Instruction) -> Option<Operation> {
    if instruction.lock || instruction.rep != RepPrefix::None {
        return None;
    }
    Some(
        match (
            instruction.mnemonic,
            instruction.operand(0),
            instruction.operand(1),
        ) {
            (
                Mnemonic::Mov,
                Some(Operand::Register(Register::Gpr { index, size: 4 | 8 })),
                Some(Operand::Immediate(value)),
            ) => {
                if index >= 16 {
                    return None;
                }
                Operation::Move {
                    register: index,
                    value: if instruction.operand(0).is_some_and(|o| {
                        matches!(o, Operand::Register(Register::Gpr { size: 4, .. }))
                    }) {
                        value & 0xffff_ffff
                    } else {
                        value
                    },
                }
            }
            (
                mnemonic @ (Mnemonic::Add | Mnemonic::Sub | Mnemonic::Cmp),
                Some(Operand::Register(Register::Gpr { index, size: 8 })),
                Some(Operand::Immediate(value)),
            ) => {
                if index >= 16 {
                    return None;
                }
                let kind = match mnemonic {
                    Mnemonic::Add => Arithmetic::Add,
                    Mnemonic::Sub => Arithmetic::Sub,
                    _ => Arithmetic::Compare,
                };
                Operation::Arithmetic {
                    kind,
                    register: index,
                    value,
                }
            }
            (
                Mnemonic::Jcc(condition @ (Condition::E | Condition::Ne)),
                Some(Operand::Branch(target)),
                None,
            ) => Operation::Branch {
                equal: condition == Condition::E,
                target: target.0,
                fallthrough: instruction.next_rip().0,
            },
            _ => return vector(instruction),
        },
    )
}

/// The complete acceptance predicate for one instruction at the start of
/// `bytes`: the decoded form and, for vector forms, the raw encoding.
fn accepted(instruction: &paludarium_decoder::Instruction, bytes: &[u8]) -> Option<Operation> {
    let operation = operation(instruction)?;
    if let Operation::Vector { kind, .. } = operation
        && !legacy_sse_encoding(bytes, usize::from(instruction.len), kind)
    {
        return None;
    }
    Some(operation)
}

pub(crate) fn extract(bytes: &[u8], entry: u64) -> Option<Block> {
    let mut block = Block {
        entry,
        end: entry,
        operations: Vec::new(),
    };
    let mut offset = 0;
    while offset < bytes.len() && block.operations.len() < 64 {
        let Ok(instruction) = decode(&bytes[offset..], GuestAddr(block.end)) else {
            break;
        };
        let Some(operation) = accepted(&instruction, &bytes[offset..]) else {
            break;
        };
        offset += usize::from(instruction.len);
        block.end = block.end.checked_add(u64::from(instruction.len))?;
        block.operations.push(operation);
        if matches!(operation, Operation::Branch { .. }) {
            break;
        }
    }
    if block.operations.is_empty() {
        None
    } else {
        Some(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_extracts_observed_mov64() {
        let block = extract(
            &[
                0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1, 0xc3,
            ],
            4096,
        )
        .unwrap();
        assert_eq!(
            block.operations,
            [Operation::Move {
                register: 0,
                value: 0x0123_4567_89ab_cdef
            }]
        );
        assert_eq!(block.end, 4106);
    }
    #[test]
    fn block_stops_before_guest_memory() {
        assert!(extract(&[0x48, 0x8b, 7], 4096).is_none());
        let block = extract(&[0xb8, 42, 0, 0, 0, 0x48, 0x8b, 7], 4096).unwrap();
        assert_eq!(block.end, 4101);
    }
    #[test]
    fn block_stops_before_syscall() {
        assert!(extract(&[0x0f, 5], 4096).is_none());
        assert_eq!(
            extract(&[0xb8, 42, 0, 0, 0, 0x0f, 5], 4096).unwrap().end,
            4101
        );
    }
    #[test]
    fn block_rejects_partial_decode() {
        assert!(extract(&[0x48, 0xb8, 1], 4096).is_none());
    }
    #[test]
    fn block_observed_arithmetic_and_branch_terminate_block() {
        let block = extract(&[0x48, 0x83, 0xf8, 7, 0x75, 6, 0xb8, 42, 0, 0, 0], 4096).unwrap();
        assert_eq!(block.operations.len(), 2);
        assert_eq!(
            block.operations[1],
            Operation::Branch {
                equal: false,
                target: 4108,
                fallthrough: 4102
            }
        );
    }
    #[test]
    fn block_bounds_instruction_count() {
        let code = [0xb8, 42, 0, 0, 0].repeat(100);
        let block = extract(&code, 4096).unwrap();
        assert_eq!(block.operations.len(), 64);
        assert_eq!(block.end - block.entry, 320);
    }
    #[test]
    fn block_unsupported_sse_is_clean_fallback() {
        // PXOR xmm0, [rdi] (memory operand) and VEX VPXOR stay interpreted.
        assert!(extract(&[0x66, 0x0f, 0xef, 0x07], 4096).is_none());
        assert!(extract(&[0xc5, 0xf9, 0xef, 0xc0], 4096).is_none());
    }

    fn vector_of(bytes: &[u8]) -> Option<Operation> {
        let block = extract(bytes, 4096)?;
        assert_eq!(block.operations.len(), 1);
        assert_eq!(block.end - block.entry, bytes.len() as u64);
        Some(block.operations[0])
    }
    fn vector(kind: Vector, destination: u8, source: u8) -> Option<Operation> {
        Some(Operation::Vector {
            kind,
            destination,
            source,
        })
    }

    #[test]
    fn block_sse_binary_register_forms_are_accepted() {
        let forms: [(&[u8], Vector); 9] = [
            (&[0x66, 0x0f, 0x6f, 0xc1], Vector::Move),
            (&[0x66, 0x0f, 0xdb, 0xc1], Vector::And),
            (&[0x66, 0x0f, 0xeb, 0xc1], Vector::Or),
            (&[0x66, 0x0f, 0xef, 0xc1], Vector::Xor),
            (&[0x66, 0x0f, 0xfe, 0xc1], Vector::AddDwords),
            (&[0x66, 0x0f, 0xfa, 0xc1], Vector::SubDwords),
            (&[0x66, 0x0f, 0xf4, 0xc1], Vector::MultiplyUnsignedDwords),
            (&[0x66, 0x0f, 0x62, 0xc1], Vector::UnpackLowDwords),
            (&[0x66, 0x0f, 0x67, 0xc1], Vector::PackUnsignedBytes),
        ];
        for (bytes, kind) in forms {
            assert_eq!(vector_of(bytes), vector(kind, 0, 1), "{bytes:02x?}");
        }
    }
    #[test]
    fn block_sse_movdqa_store_register_form_keeps_intel_order() {
        // 66 0F 7F /r with mod=3: ModRM.rm (xmm2) is the destination.
        assert_eq!(
            vector_of(&[0x66, 0x0f, 0x7f, 0xda]),
            vector(Vector::Move, 2, 3)
        );
    }
    #[test]
    fn block_sse_rex_selects_high_registers() {
        assert_eq!(
            vector_of(&[0x66, 0x45, 0x0f, 0xdb, 0xd7]),
            vector(Vector::And, 10, 15)
        );
        assert_eq!(
            vector_of(&[0x66, 0x45, 0x0f, 0x70, 0xce, 0x1b]),
            vector(Vector::ShuffleDwords(0x1b), 9, 14)
        );
    }
    #[test]
    fn block_sse_every_pshufd_imm8_is_kept() {
        for selector in 0..=255u8 {
            assert_eq!(
                vector_of(&[0x66, 0x0f, 0x70, 0xc1, selector]),
                vector(Vector::ShuffleDwords(selector), 0, 1)
            );
        }
    }
    #[test]
    fn block_sse_shift_immediates_include_large_counts() {
        for count in [0u8, 1, 31, 32, 255] {
            assert_eq!(
                vector_of(&[0x66, 0x0f, 0x72, 0xf3, count]),
                vector(Vector::ShiftLeftDwords(u64::from(count)), 3, 3)
            );
            assert_eq!(
                vector_of(&[0x66, 0x41, 0x0f, 0x72, 0xd5, count]),
                vector(Vector::ShiftRightDwords(u64::from(count)), 13, 13)
            );
        }
    }
    #[test]
    fn block_sse_non_register_and_prefixed_forms_fall_back() {
        let rejected: [&[u8]; 12] = [
            &[0x66, 0x0f, 0xfe, 0x07],       // PADDD xmm0, [rdi]
            &[0x66, 0x0f, 0x70, 0x07, 0x1b], // PSHUFD xmm0, [rdi], imm8
            &[0x66, 0x0f, 0x7f, 0x07],       // MOVDQA [rdi], xmm0
            &[0x66, 0x0f, 0xf2, 0xc1],       // PSLLD xmm0, xmm1 (count register)
            &[0x66, 0x0f, 0xd2, 0xc1],       // PSRLD xmm0, xmm1 (count register)
            &[0x0f, 0xfe, 0xc1],             // MMX PADDD
            &[0xf3, 0x0f, 0x6f, 0xc1],       // MOVDQU
            &[0xc5, 0xf9, 0xfe, 0xc1],       // VEX VPADDD
            &[0x2e, 0x66, 0x0f, 0xfe, 0xc1], // segment prefix
            &[0x66, 0x2e, 0x0f, 0xfe, 0xc1], // segment prefix after 0x66
            &[0x66, 0x66, 0x0f, 0xfe, 0xc1], // repeated 0x66
            &[0x66, 0x67, 0x0f, 0xfe, 0xc1], // address-size prefix
        ];
        for bytes in rejected {
            assert!(extract(bytes, 4096).is_none(), "{bytes:02x?}");
        }
        for bytes in [
            &[0xf0, 0x66, 0x0f, 0xfe, 0xc1][..],
            &[0xf3, 0x66, 0x0f, 0xfe, 0xc1],
            &[0xf2, 0x66, 0x0f, 0xfe, 0xc1],
        ] {
            assert!(extract(bytes, 4096).is_none(), "{bytes:02x?}");
        }
    }
    #[test]
    fn block_sse_mixes_with_gpr_forms_and_stops_at_unsupported() {
        // mov ecx,4; paddd; pshufd; sub ecx,1 (32-bit, unsupported)
        let block = extract(
            &[
                0xb9, 4, 0, 0, 0, 0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0x70, 0xc9, 0x93, 0x83, 0xe9,
                1,
            ],
            4096,
        )
        .unwrap();
        assert_eq!(block.operations.len(), 3);
        assert_eq!(block.end, 4096 + 14);
        assert_eq!(
            block.operations[2],
            Operation::Vector {
                kind: Vector::ShuffleDwords(0x93),
                destination: 1,
                source: 1
            }
        );
    }
    #[test]
    fn block_sse_encoding_check_rejects_truncated_lengths() {
        assert!(!legacy_sse_encoding(
            &[0x66, 0x0f, 0xfe],
            4,
            Vector::AddDwords
        ));
        assert!(!legacy_sse_encoding(
            &[0x66, 0x0f, 0x70, 0xc1],
            4,
            Vector::ShuffleDwords(0)
        ));
        assert!(legacy_sse_encoding(
            &[0x66, 0x0f, 0x70, 0xc1, 0],
            5,
            Vector::ShuffleDwords(0)
        ));
    }

    #[test]
    fn block_saved_jit_compile_crash_translates_without_panic() {
        // Original jit_compile crash 4dabc170d4fa7cd3…: eight-byte RIP
        // header followed by decoder input. This finite regression checks
        // the saved input, not a replacement for the sanitizer campaign.
        let input = [
            0x00, 0xe1, 0x00, 0xe1, 0xe1, 0x4a, 0x4a, 0xe1, 0x4a, 0x48, 0x05, 0xff, 0x4a, 0x4a,
            0xe1, 0x4a, 0x48, 0x05, 0x6e, 0x3b, 0x27, 0x4a, 0x4a, 0x05, 0xff, 0x93, 0x3f, 0x93,
            0x93, 0x93, 0x93, 0x93,
        ];
        let rip = u64::from_le_bytes(input[..8].try_into().unwrap());
        for prefix in 0..16 {
            let mut bytes = vec![0; prefix];
            bytes.extend_from_slice(&input[8..]);
            let block = extract(&bytes[prefix..], rip).unwrap();
            let wasm = crate::emit::emit(&block).unwrap();
            assert!(wasm.starts_with(b"\0asm\x01\0\0\0"));
            assert!(wasm.len() <= 65536);
        }
    }
}
