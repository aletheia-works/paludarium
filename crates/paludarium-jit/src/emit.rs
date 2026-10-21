//! Small deterministic wasm encoder; guest memory is never imported as pointers.
use crate::block::{Arithmetic, Block, Operation, Vector};
use crate::bridge::XMM_OFFSET;

fn unsigned(output: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn constant(output: &mut Vec<u8>, value: u64) {
    output.push(0x42);
    let mut value = value as i64;
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        let last = (value == 0 && byte & 64 == 0) || (value == -1 && byte & 64 != 0);
        output.push(byte | if last { 0 } else { 128 });
        if last {
            break;
        }
    }
}
fn section(output: &mut Vec<u8>, id: u8, bytes: &[u8]) {
    output.push(id);
    unsigned(output, bytes.len());
    output.extend(bytes);
}
fn get(output: &mut Vec<u8>, local: u8) {
    output.extend([0x20, local]);
}
fn set(output: &mut Vec<u8>, local: u8) {
    output.extend([0x21, local]);
}
fn load(output: &mut Vec<u8>, index: u8) {
    get(output, 0);
    output.extend([0x29, 3]);
    unsigned(output, usize::from(index) * 8);
}
fn store(output: &mut Vec<u8>, index: u8) {
    output.extend([0x37, 3]);
    unsigned(output, usize::from(index) * 8);
}
fn flag(output: &mut Vec<u8>, bit: u8, expression: impl FnOnce(&mut Vec<u8>)) {
    get(output, 4);
    expression(output);
    output.push(0xad); // i64.extend_i32_u
    constant(output, u64::from(bit));
    output.extend([0x86, 0x84]); // shl, or
    set(output, 4);
}
fn arithmetic(output: &mut Vec<u8>, kind: Arithmetic, register: u8, value: u64) {
    load(output, register);
    set(output, 1);
    constant(output, value);
    set(output, 2);
    get(output, 1);
    get(output, 2);
    output.push(if kind == Arithmetic::Add { 0x7c } else { 0x7d });
    set(output, 3);
    load(output, 16);
    constant(output, !0x8d5);
    output.push(0x83);
    set(output, 4);
    flag(output, 0, |out| {
        if kind == Arithmetic::Add {
            get(out, 3);
            get(out, 1);
        } else {
            get(out, 1);
            get(out, 2);
        }
        out.push(0x54);
    });
    flag(output, 2, |out| {
        get(out, 3);
        constant(out, 255);
        out.extend([0x83, 0x7b]);
        constant(out, 1);
        out.extend([0x83, 0x50]);
    });
    flag(output, 4, |out| {
        get(out, 1);
        get(out, 2);
        out.push(0x85);
        get(out, 3);
        out.push(0x85);
        constant(out, 16);
        out.extend([0x83, 0x50, 0x45]);
    });
    flag(output, 6, |out| {
        get(out, 3);
        out.push(0x50);
    });
    flag(output, 7, |out| {
        get(out, 3);
        constant(out, 0);
        out.push(0x53);
    });
    flag(output, 11, |out| {
        get(out, 1);
        get(out, 2);
        out.push(0x85);
        if kind == Arithmetic::Add {
            constant(out, u64::MAX);
            out.push(0x85);
        }
        get(out, 1);
        get(out, 3);
        out.extend([0x85, 0x83]);
        constant(out, 0);
        out.push(0x53);
    });
    get(output, 0);
    get(output, 4);
    store(output, 16);
    if kind != Arithmetic::Compare {
        get(output, 0);
        get(output, 3);
        store(output, register);
    }
}

/// SIMD (0xFD-prefixed) instruction with its LEB128 sub-opcode.
fn simd(output: &mut Vec<u8>, opcode: usize) {
    output.push(0xfd);
    unsigned(output, opcode);
}
const V128_LOAD: usize = 0x00;
const V128_STORE: usize = 0x0b;
const V128_CONST: usize = 0x0c;
const I8X16_SHUFFLE: usize = 0x0d;
const V128_AND: usize = 0x4e;
const V128_OR: usize = 0x50;
const V128_XOR: usize = 0x51;
const I8X16_NARROW_I16X8_U: usize = 0x66;
const I32X4_SHL: usize = 0xab;
const I32X4_SHR_U: usize = 0xad;
const I32X4_ADD: usize = 0xae;
const I32X4_SUB: usize = 0xb1;
const I64X2_MUL: usize = 0xd5;

/// Memory argument of XMM `index` in the scratch block (8-byte alignment hint;
/// the scratch is a Rust `[u64]`).
fn xmm_memarg(output: &mut Vec<u8>, index: u8) {
    output.push(3);
    unsigned(output, XMM_OFFSET + usize::from(index) * 16);
}
fn load_xmm(output: &mut Vec<u8>, index: u8) {
    get(output, 0);
    simd(output, V128_LOAD);
    xmm_memarg(output, index);
}
fn vector_constant(output: &mut Vec<u8>, value: u128) {
    simd(output, V128_CONST);
    output.extend(value.to_le_bytes());
}
/// Byte lanes for `i8x16.shuffle` selecting whole dwords; lanes 4..7 name
/// dwords of the second operand.
fn dword_lanes(dwords: [u8; 4]) -> [u8; 16] {
    let mut lanes = [0; 16];
    for (dword, source) in dwords.into_iter().enumerate() {
        for byte in 0..4 {
            lanes[dword * 4 + byte] = source * 4 + byte as u8;
        }
    }
    lanes
}
fn shuffle(output: &mut Vec<u8>, dwords: [u8; 4]) {
    simd(output, I8X16_SHUFFLE);
    output.extend(dword_lanes(dwords));
}
const LOW_DWORDS: u128 = 0x0000_0000_ffff_ffff_0000_0000_ffff_ffff;

/// `destination = destination <kind> source` on the scratch XMM slots. The
/// value stack only; RFLAGS, GPRs and guest memory are untouched.
fn vector(output: &mut Vec<u8>, kind: Vector, destination: u8, source: u8) -> Option<()> {
    if destination >= 16 || source >= 16 {
        return None;
    }
    get(output, 0);
    match kind {
        Vector::Move => load_xmm(output, source),
        Vector::ShuffleDwords(selector) => {
            load_xmm(output, source);
            load_xmm(output, source);
            shuffle(output, std::array::from_fn(|n| (selector >> (n * 2)) & 3));
        }
        Vector::ShiftLeftDwords(count) | Vector::ShiftRightDwords(count) => {
            if count >= 32 {
                // x86 clears every dword; wasm would take the count modulo 32.
                vector_constant(output, 0);
            } else {
                load_xmm(output, destination);
                output.push(0x41); // i32.const count (< 32)
                unsigned(output, usize::try_from(count).ok()?);
                let left = matches!(kind, Vector::ShiftLeftDwords(_));
                simd(output, if left { I32X4_SHL } else { I32X4_SHR_U });
            }
        }
        Vector::MultiplyUnsignedDwords => {
            for register in [destination, source] {
                load_xmm(output, register);
                vector_constant(output, LOW_DWORDS);
                simd(output, V128_AND);
            }
            simd(output, I64X2_MUL);
        }
        Vector::UnpackLowDwords => {
            load_xmm(output, destination);
            load_xmm(output, source);
            shuffle(output, [0, 4, 1, 5]);
        }
        Vector::And
        | Vector::Or
        | Vector::Xor
        | Vector::AddDwords
        | Vector::SubDwords
        | Vector::PackUnsignedBytes => {
            load_xmm(output, destination);
            load_xmm(output, source);
            simd(
                output,
                match kind {
                    Vector::And => V128_AND,
                    Vector::Or => V128_OR,
                    Vector::Xor => V128_XOR,
                    Vector::AddDwords => I32X4_ADD,
                    Vector::SubDwords => I32X4_SUB,
                    _ => I8X16_NARROW_I16X8_U,
                },
            );
        }
    }
    simd(output, V128_STORE);
    xmm_memarg(output, destination);
    Some(())
}

pub(crate) fn emit(block: &Block) -> Option<Vec<u8>> {
    if block.operations.is_empty() || block.operations.len() > 64 {
        return None;
    }
    let mut output = vec![0, 97, 115, 109, 1, 0, 0, 0];
    section(&mut output, 1, &[1, 0x60, 1, 0x7f, 1, 0x7f]);
    // env.memory: shared memory, minimum 1 and maximum 65536 pages. The
    // production shared Rust memory must satisfy these limits.
    section(
        &mut output,
        2,
        &[
            1, 3, b'e', b'n', b'v', 6, b'm', b'e', b'm', b'o', b'r', b'y', 2, 3, 1, 0x80, 0x80, 4,
        ],
    );
    section(&mut output, 3, &[1, 0]);
    section(&mut output, 7, &[1, 3, b'r', b'u', b'n', 0, 0]);
    let mut body = vec![1, 4, 0x7e]; // Four i64 locals; local 0 is state pointer.
    for operation in &block.operations {
        match *operation {
            Operation::Move { register, value } => {
                if register >= 16 {
                    return None;
                }
                get(&mut body, 0);
                constant(&mut body, value);
                store(&mut body, register);
            }
            Operation::Arithmetic {
                kind,
                register,
                value,
            } => {
                if register >= 16 {
                    return None;
                }
                arithmetic(&mut body, kind, register, value);
            }
            Operation::Branch {
                equal,
                target,
                fallthrough,
            } => {
                get(&mut body, 0);
                constant(&mut body, target);
                constant(&mut body, fallthrough);
                load(&mut body, 16);
                constant(&mut body, 64);
                body.extend([0x83, 0x50]);
                if equal {
                    body.push(0x45);
                }
                body.push(0x1b);
                store(&mut body, 17);
            }
            Operation::Vector {
                kind,
                destination,
                source,
            } => vector(&mut body, kind, destination, source)?,
        }
    }
    if !matches!(block.operations.last(), Some(Operation::Branch { .. })) {
        get(&mut body, 0);
        constant(&mut body, block.end);
        store(&mut body, 17);
    }
    body.extend([0x41, 0, 0x0b]);
    let mut code = vec![1];
    unsigned(&mut code, body.len());
    code.extend(body);
    section(&mut output, 10, &code);
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(operation: Operation) -> Block {
        Block {
            entry: 4096,
            end: 4106,
            operations: vec![operation],
        }
    }
    #[test]
    fn emit_mov_module_has_real_wasm_header() {
        assert_eq!(
            &emit(&block(Operation::Move {
                register: 0,
                value: 42
            }))
            .unwrap()[..8],
            b"\0asm\x01\0\0\0"
        );
    }
    #[test]
    fn emit_signed_integer_extremes_are_bounded() {
        for value in [0, 63, 64, 127, 128, u64::MAX, 1 << 63] {
            let mut bytes = Vec::new();
            constant(&mut bytes, value);
            assert!(bytes.len() <= 11);
            assert_eq!(bytes.last().unwrap() & 128, 0);
        }
    }
    #[test]
    fn emit_rejects_empty_and_unbounded_blocks() {
        let mut block = block(Operation::Move {
            register: 0,
            value: 42,
        });
        block.operations.clear();
        assert!(emit(&block).is_none());
        block.operations = vec![
            Operation::Move {
                register: 0,
                value: 42
            };
            65
        ];
        assert!(emit(&block).is_none());
    }
    #[test]
    fn emit_rejects_invalid_register_scratch_offsets() {
        assert!(
            emit(&block(Operation::Move {
                register: 16,
                value: 42
            }))
            .is_none()
        );
    }
    #[test]
    fn emit_add_and_sub_are_distinct_modules() {
        let add = emit(&block(Operation::Arithmetic {
            kind: Arithmetic::Add,
            register: 0,
            value: 1,
        }))
        .unwrap();
        let sub = emit(&block(Operation::Arithmetic {
            kind: Arithmetic::Sub,
            register: 0,
            value: 1,
        }))
        .unwrap();
        assert_ne!(add, sub);
    }
    #[test]
    fn emit_conditional_branch_preserves_two_targets() {
        let equal = emit(&block(Operation::Branch {
            equal: true,
            target: 8192,
            fallthrough: 4098,
        }))
        .unwrap();
        let unequal = emit(&block(Operation::Branch {
            equal: false,
            target: 8192,
            fallthrough: 4098,
        }))
        .unwrap();
        assert_ne!(equal, unequal);
    }
    fn vector_block(kind: Vector, destination: u8, source: u8) -> Block {
        block(Operation::Vector {
            kind,
            destination,
            source,
        })
    }
    fn contains(code: &[u8], needle: &[u8]) -> bool {
        code.windows(needle.len()).any(|window| window == needle)
    }
    #[test]
    fn emit_vector_shift_counts_of_32_or_more_store_zero() {
        for count in [32, 33, 255, u64::MAX] {
            for kind in [
                Vector::ShiftLeftDwords(count),
                Vector::ShiftRightDwords(count),
            ] {
                let code = emit(&vector_block(kind, 3, 3)).unwrap();
                let mut zero = vec![0xfd, 0x0c];
                zero.extend([0; 16]);
                assert!(contains(&code, &zero), "{kind:?}");
                assert!(!contains(&code, &[0xfd, 0xab, 1]) && !contains(&code, &[0xfd, 0xad, 1]));
            }
        }
        let code = emit(&vector_block(Vector::ShiftLeftDwords(31), 3, 3)).unwrap();
        assert!(contains(&code, &[0x41, 31, 0xfd, 0xab, 1]));
        let code = emit(&vector_block(Vector::ShiftRightDwords(0), 3, 3)).unwrap();
        assert!(contains(&code, &[0x41, 0, 0xfd, 0xad, 1]));
    }
    #[test]
    fn emit_vector_rejects_out_of_range_registers() {
        assert!(emit(&vector_block(Vector::Xor, 16, 0)).is_none());
        assert!(emit(&vector_block(Vector::Xor, 0, 16)).is_none());
        assert!(emit(&vector_block(Vector::ShiftLeftDwords(1), 255, 255)).is_none());
    }
    #[test]
    fn emit_pshufd_lanes_select_whole_dwords_for_every_imm8() {
        for selector in 0..=255u8 {
            let dwords: [u8; 4] = std::array::from_fn(|n| (selector >> (n * 2)) & 3);
            let lanes = dword_lanes(dwords);
            for (n, source) in dwords.into_iter().enumerate() {
                assert_eq!(
                    lanes[n * 4..n * 4 + 4],
                    [source * 4, source * 4 + 1, source * 4 + 2, source * 4 + 3]
                );
            }
            let code = emit(&vector_block(Vector::ShuffleDwords(selector), 1, 2)).unwrap();
            let mut shuffle = vec![0xfd, 0x0d];
            shuffle.extend(lanes);
            assert!(contains(&code, &shuffle), "selector {selector:#04x}");
        }
    }
    #[test]
    fn emit_punpckldq_interleaves_low_dwords_of_both_operands() {
        assert_eq!(
            dword_lanes([0, 4, 1, 5]),
            [0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23]
        );
    }
    #[test]
    fn emit_pmuludq_masks_odd_dwords_before_64_bit_multiply() {
        let code = emit(&vector_block(Vector::MultiplyUnsignedDwords, 0, 1)).unwrap();
        let mut mask = vec![0xfd, 0x0c];
        mask.extend(LOW_DWORDS.to_le_bytes());
        mask.extend([0xfd, 0x4e]);
        assert_eq!(code.windows(mask.len()).filter(|w| *w == mask).count(), 2);
        assert!(contains(&code, &[0xfd, 0xd5, 1]));
    }
    #[test]
    fn emit_each_vector_kind_is_a_distinct_deterministic_module() {
        let kinds = [
            Vector::Move,
            Vector::And,
            Vector::Or,
            Vector::Xor,
            Vector::AddDwords,
            Vector::SubDwords,
            Vector::MultiplyUnsignedDwords,
            Vector::UnpackLowDwords,
            Vector::PackUnsignedBytes,
            Vector::ShuffleDwords(0x1b),
            Vector::ShiftLeftDwords(3),
            Vector::ShiftRightDwords(3),
        ];
        let modules: Vec<_> = kinds
            .iter()
            .map(|kind| emit(&vector_block(*kind, 2, 5)).unwrap())
            .collect();
        for (index, module) in modules.iter().enumerate() {
            assert_eq!(
                Some(module),
                emit(&vector_block(kinds[index], 2, 5)).as_ref()
            );
            assert_eq!(modules.iter().filter(|other| *other == module).count(), 1);
        }
    }
    #[test]
    fn emit_gpr_only_blocks_use_no_simd_instructions() {
        let code = emit(&block(Operation::Arithmetic {
            kind: Arithmetic::Add,
            register: 1,
            value: 7,
        }))
        .unwrap();
        assert!(!code.contains(&0xfd));
        let code = emit(&vector_block(Vector::AddDwords, 0, 1)).unwrap();
        assert!(contains(&code, &[0xfd, 0xae, 1]));
    }
    #[test]
    fn emit_is_deterministic_for_worker_compilation() {
        let block = block(Operation::Move {
            register: 0,
            value: 42,
        });
        assert_eq!(emit(&block), emit(&block));
    }
}
