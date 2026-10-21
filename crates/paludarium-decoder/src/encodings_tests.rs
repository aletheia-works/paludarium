//! U3 runner bootstrap, using an already implemented encoding.
use super::{Mnemonic, decode};
use paludarium_types::GuestAddr;

#[test]
fn runner_bootstrap_decodes_existing_pxor() {
    let instruction = decode(&[0x66, 0x0f, 0xef, 0xc0], GuestAddr(0x400000));
    assert!(matches!(instruction, Ok(i) if i.mnemonic == Mnemonic::Pxor));
}
#[test]
fn scalar_movsd_is_distinct_from_string_movsd() {
    use crate::{Mnemonic, decode};
    use paludarium_types::GuestAddr;
    assert_eq!(
        decode(&[0xf2, 0x0f, 0x10, 0xc1], GuestAddr(0))
            .unwrap()
            .mnemonic,
        Mnemonic::MovsdSse
    );
    let string = decode(&[0xa5], GuestAddr(0)).unwrap();
    assert_eq!(string.mnemonic, Mnemonic::Movsd);
    assert_eq!(string.implicit_size, 4);
}

#[test]
fn scalar_compare_keeps_immediate_and_not_string_operands() {
    use crate::{Mnemonic, Operand, decode};
    use paludarium_types::GuestAddr;
    let i = decode(&[0xf2, 0x0f, 0xc2, 0xc1, 3], GuestAddr(0)).unwrap();
    assert_eq!(i.mnemonic, Mnemonic::CmpsdSse);
    assert_eq!(i.operand(2), Some(Operand::Immediate(3)));
    assert_eq!(
        decode(&[0xa7], GuestAddr(0)).unwrap().mnemonic,
        Mnemonic::Cmpsd
    );
}

#[test]
fn high_xmm_and_legacy_memory_width_are_retained() {
    use crate::{Operand, Register, decode};
    use paludarium_types::GuestAddr;
    let i = decode(&[0x66, 0x45, 0x0f, 0xef, 0xc1], GuestAddr(0)).unwrap();
    assert_eq!(i.operand(0), Some(Operand::Register(Register::Xmm(8))));
    assert_eq!(i.operand(1), Some(Operand::Register(Register::Xmm(9))));
    let i = decode(&[0xf2, 0x0f, 0x10, 0x00], GuestAddr(0)).unwrap();
    assert!(matches!(i.operand(1),Some(Operand::Memory(m)) if m.size==8));
}

#[test]
fn assigned_crypto_and_ignored_selector_bits_decode() {
    use crate::{Mnemonic, decode};
    use paludarium_types::GuestAddr;
    assert_eq!(
        decode(&[0x0f, 0x38, 0xcb, 0xc1], GuestAddr(0))
            .unwrap()
            .mnemonic,
        Mnemonic::Sha256rnds2
    );
    assert_eq!(
        decode(&[0x66, 0x0f, 0x38, 0xdc, 0xc1], GuestAddr(0))
            .unwrap()
            .mnemonic,
        Mnemonic::Aesenc
    );
    for imm in [0, 0x11, 0x80, 0xee] {
        assert_eq!(
            decode(&[0x66, 0x0f, 0x3a, 0x44, 0xc1, imm], GuestAddr(0))
                .unwrap()
                .mnemonic,
            Mnemonic::Pclmulqdq
        );
    }
}

#[test]
fn unassigned_crypto_and_cross_selectors_remain_unsupported() {
    use crate::{DecodeError, decode};
    use paludarium_types::GuestAddr;
    for imm in [1, 0x10] {
        assert_eq!(
            decode(&[0x66, 0x0f, 0x3a, 0x44, 0xc1, imm], GuestAddr(0)),
            Err(DecodeError::Unsupported)
        );
    }
    assert_eq!(
        decode(&[0x66, 0x0f, 0x38, 0xde, 0xc1], GuestAddr(0)),
        Err(DecodeError::Unsupported)
    );
    assert_eq!(
        decode(&[0x0f, 0xfd, 0xc1], GuestAddr(0)),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn cpuid_is_legacy_and_xgetbv_remains_unsupported() {
    use crate::{DecodeError, Mnemonic, decode};
    use paludarium_types::GuestAddr;
    assert_eq!(
        decode(&[0x0f, 0xa2], GuestAddr(0)).unwrap().mnemonic,
        Mnemonic::Cpuid
    );
    assert_eq!(
        decode(&[0x0f, 0x01, 0xd0], GuestAddr(0)),
        Err(DecodeError::Unsupported)
    );
    assert_eq!(
        decode(&[0xc5, 0xf9, 0xef, 0xc0], GuestAddr(0)),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn truncated_crypto_and_illegal_lock_are_distinct() {
    use crate::{DecodeError, decode};
    use paludarium_types::GuestAddr;
    assert_eq!(
        decode(&[0x66, 0x0f, 0x38, 0xdc], GuestAddr(0)),
        Err(DecodeError::NeedMoreBytes)
    );
    assert_eq!(
        decode(&[0xf0, 0x66, 0x0f, 0x38, 0xdc, 0xc1], GuestAddr(0)),
        Err(DecodeError::Invalid)
    );
}
include!("u3_native_encodings.rs");

#[test]
fn all_native_observer_input_encodings_connect() {
    assert_eq!(NATIVE_ENCODINGS.len(), 577);
    for bytes in NATIVE_ENCODINGS {
        assert!(
            crate::decode(bytes, paludarium_types::GuestAddr(0)).is_ok(),
            "encoding: {bytes:02x?}"
        );
    }
}

#[test]
fn every_native_encoding_requires_its_complete_length() {
    for bytes in NATIVE_ENCODINGS {
        for length in 0..bytes.len() {
            assert!(
                crate::decode(&bytes[..length], GuestAddr(0)).is_err(),
                "{bytes:02x?} prefix {length}"
            );
        }
        let decoded = crate::decode(bytes, GuestAddr(0x12340)).unwrap();
        assert_eq!(usize::from(decoded.len), bytes.len());
        assert_eq!(decoded.next_rip(), GuestAddr(0x12340 + bytes.len() as u64));
    }
}

#[test]
fn lock_is_rejected_for_native_simd_register_encodings() {
    for bytes in NATIVE_ENCODINGS {
        let mut locked = vec![0xf0];
        locked.extend_from_slice(bytes);
        assert!(
            crate::decode(&locked, GuestAddr(0)).is_err(),
            "locked {bytes:02x?}"
        );
    }
}

#[test]
fn public_operand_iterator_retains_scalar_width_and_high_register() {
    use crate::{Operand, Register};
    let instruction = decode(&[0xf2, 0x44, 0x0f, 0x10, 0x48, 0x08], GuestAddr(0)).unwrap();
    let operands: Vec<_> = instruction.operands().collect();
    assert_eq!(instruction.operand_count(), 2);
    assert_eq!(operands.len(), 2);
    assert_eq!(operands[0], Operand::Register(Register::Xmm(9)));
    assert_eq!(Register::Xmm(9).size(), 16);
    assert!(matches!(operands[1], Operand::Memory(m) if m.size == 8 && m.displacement == 8));
    assert_eq!(instruction.operand(2), None);
}
