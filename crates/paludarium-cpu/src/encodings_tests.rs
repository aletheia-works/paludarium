//! U3 runner bootstrap. Semantic cases follow native observations.
#![allow(unexpected_cfgs)]
use super::{CpuState, INITIAL_MXCSR};
use paludarium_types::GuestAddr;
#[path = "../../../tests/guests/u3/native-contract.rs"]
mod native_contract;

fn sha_memory_contract(opcode: u8, crossing: bool) {
    use paludarium_mmu::{AddressSpace, MappingKind, Prot};
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(0x40000)),
            8192,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    let address = if crossing { 0x40fe8 } else { 0x40001 };
    let initial_memory = [0xa5; 8192];
    memory.write(GuestAddr(0x40000), &initial_memory).unwrap();
    if crossing {
        memory
            .protect(GuestAddr(0x41000), 4096, Prot::NONE)
            .unwrap();
    }
    let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x80000));
    for (n, value) in state.gpr.iter_mut().enumerate() {
        *value = 0x1234_5678_0000_0000 + n as u64;
    }
    state.gpr[2] = address;
    for (n, value) in state.xmm.iter_mut().enumerate() {
        *value = u128::MAX - n as u128;
    }
    state.rflags = 0x8d7;
    let before = state.clone();
    let instruction =
        paludarium_decoder::decode(&[0x0f, 0x38, opcode, 0x42, 0x10], state.rip).unwrap();
    assert!(matches!(
        super::exec::execute(&mut state, &memory, &instruction),
        Err(super::exec::Stop::GeneralProtection)
    ));
    assert_eq!(state.gpr, before.gpr);
    assert_eq!(state.xmm, before.xmm);
    assert_eq!(state.rip, before.rip);
    assert_eq!(state.mxcsr, before.mxcsr);
    assert_eq!(state.rflags, before.rflags);
    memory
        .protect(GuestAddr(0x40000), 8192, Prot::READ_WRITE)
        .unwrap();
    let mut after = [0; 8192];
    memory.read(GuestAddr(0x40000), &mut after).unwrap();
    assert_eq!(after, initial_memory);
}

#[test]
fn sha_memory_contract_rnds2_accessible() {
    sha_memory_contract(0xcb, false);
}
#[test]
fn sha_memory_contract_rnds2_crossing() {
    sha_memory_contract(0xcb, true);
}
#[test]
fn sha_memory_contract_msg1_accessible() {
    sha_memory_contract(0xcc, false);
}
#[test]
fn sha_memory_contract_msg1_crossing() {
    sha_memory_contract(0xcc, true);
}
#[test]
fn sha_memory_contract_msg2_accessible() {
    sha_memory_contract(0xcd, false);
}
#[test]
fn sha_memory_contract_msg2_crossing() {
    sha_memory_contract(0xcd, true);
}

#[test]
fn runner_bootstrap_preserves_existing_state_layout() {
    let state = CpuState::new(GuestAddr(0x400000), GuestAddr(0x800000));
    assert_eq!(state.xmm.len(), 16);
    assert_eq!(state.xmm, [0; 16]);
    assert_eq!(state.mxcsr, INITIAL_MXCSR);
}

/// Diagnostic replay accepts an explicitly supplied, freshly generated native
/// observation file. Expected states are never checked into the test sources.
#[test]
#[cfg_attr(
    not(coverage),
    ignore = "requires PALUDARIUM_U3_NATIVE_OBSERVATIONS from the native runner"
)]
fn packed_and_crypto_native_replay() {
    use paludarium_decoder::{Mnemonic as M, decode};
    use paludarium_mmu::{AddressSpace, MappingKind, Prot};
    fn bytes(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        (0..value.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
            .collect()
    }
    let path = std::env::var("PALUDARIUM_U3_NATIVE_OBSERVATIONS").expect("native observation path");
    let observations = std::fs::read_to_string(path).unwrap();
    let full = std::env::var_os("PALUDARIUM_U3_FULL_REPLAY").is_some();
    let mut count = 0;
    for row in observations.lines() {
        let fields: Vec<_> = row.split('|').collect();
        assert_eq!(fields.len(), 7);
        let instruction = decode(&bytes(fields[3]), GuestAddr(0x10000)).unwrap();
        if !full
            && crate::sse::packed(instruction.mnemonic, 0, 0, 0, 0).is_none()
            && crate::crypto::execute(instruction.mnemonic, 0, 0, 0, 0).is_none()
            && !matches!(
                instruction.mnemonic,
                M::Movaps
                    | M::Movapd
                    | M::Movups
                    | M::Movupd
                    | M::Movdqu
                    | M::Movdqa
                    | M::Lddqu
                    | M::Movd
                    | M::Movq
                    | M::Movss
                    | M::MovsdSse
                    | M::Movlps
                    | M::Movlpd
                    | M::Movhps
                    | M::Movhpd
                    | M::Movhlps
                    | M::Movlhps
                    | M::Movddup
                    | M::Movmskps
                    | M::Movmskpd
                    | M::Pmovmskb
                    | M::Ptest
                    | M::Pextrb
                    | M::Pextrw
                    | M::Pextrd
                    | M::Pextrq
                    | M::Pinsrb
                    | M::Pinsrw
                    | M::Pinsrd
                    | M::Pinsrq
                    | M::Ldmxcsr
                    | M::Stmxcsr
            )
        {
            continue;
        }
        let input = bytes(fields[4]);
        let output = bytes(fields[5]);
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x80000));
        for n in 0..16 {
            state.xmm[n] = u128::from_le_bytes(input[n * 16..n * 16 + 16].try_into().unwrap());
        }
        state.mxcsr = u32::from_le_bytes(input[256..260].try_into().unwrap());
        state.gpr[0] = 0x8000_0001_7fff_0011;
        state.gpr[2] = 0x40000;
        state.rflags = 0x8d7;
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x40000)),
                4096,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory.write(GuestAddr(0x40000), &input).unwrap();
        // Exercise the public fetch/decode/transaction boundary against the
        // same independently observed native result, not a second oracle.
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_EXEC,
                MappingKind::ElfSegment,
            )
            .unwrap();
        memory
            .write_initial(GuestAddr(0x10000), &bytes(fields[3]))
            .unwrap();
        super::step(&mut state, &memory).unwrap();
        for n in 0..16 {
            assert_eq!(
                state.xmm[n].to_le_bytes(),
                output[n * 16..n * 16 + 16],
                "{} XMM{}",
                fields[0],
                n
            );
        }
        assert_eq!(
            state.gpr[0].to_le_bytes(),
            output[256..264],
            "{} RAX",
            fields[0]
        );
        assert_eq!(
            state.rflags & 0xcd5,
            u64::from_le_bytes(output[264..272].try_into().unwrap()) & 0xcd5,
            "{} flags",
            fields[0]
        );
        assert_eq!(
            state.mxcsr.to_le_bytes(),
            output[272..276],
            "{} pattern{} mode{} MXCSR",
            fields[0],
            fields[1],
            fields[2]
        );
        let mut observed_memory = [0; 512];
        memory
            .read(GuestAddr(0x40000), &mut observed_memory)
            .unwrap();
        assert_eq!(
            observed_memory.as_slice(),
            bytes(fields[6]),
            "{} memory",
            fields[0]
        );
        count += 1;
    }
    assert!(
        count >= 400,
        "nonzero broad native coverage required, got {count}"
    );
    println!("native packed/crypto/movement register and memory cases compared: {count}");
}

fn cpuid_state(leaf: u32, subleaf: u32) -> CpuState {
    let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x80000));
    state.gpr[0] = 0xffff_ffff_0000_0000 | u64::from(leaf);
    state.gpr[1] = 0xffff_ffff_0000_0000 | u64::from(subleaf);
    state.rflags = 0x8d7;
    state.xmm = [u128::MAX; 16];
    let instruction = paludarium_decoder::decode(&[0x0f, 0xa2], state.rip).unwrap();
    super::exec::execute(
        &mut state,
        &paludarium_mmu::AddressSpace::new(),
        &instruction,
    )
    .unwrap();
    state
}

#[test]
fn cpuid_vendor_order_and_max_leaf() {
    let s = cpuid_state(0, 0);
    let mut vendor = Vec::new();
    for n in [3, 2, 1] {
        vendor.extend_from_slice(&(s.gpr[n] as u32).to_le_bytes());
    }
    assert_eq!(vendor, b"PaludariumVM");
    assert_eq!(s.gpr[0], 7);
}
#[test]
fn cpuid_partial_families_are_not_advertised() {
    for leaf in [1, 7] {
        let s = cpuid_state(leaf, 0);
        assert_eq!(&s.gpr[..4], &[0; 4]);
    }
}
#[test]
fn cpuid_extended_long_mode_only() {
    let s = cpuid_state(0x8000_0001, 0);
    assert_eq!(&s.gpr[..4], &[0, 0, 1 << 29, 0]);
}
#[test]
fn cpuid_extended_maximum() {
    assert_eq!(cpuid_state(0x8000_0000, 0).gpr[0], 0x8000_0001);
}
#[test]
fn cpuid_nonzero_structured_subleaf_is_zero() {
    assert_eq!(&cpuid_state(7, 1).gpr[..4], &[0; 4]);
}
#[test]
fn cpuid_unknown_and_reserved_leaves_are_zero() {
    for leaf in [2, 3, 4, 5, 6, 8, 0xd, 0x4000_0000, 0x8000_0002, u32::MAX] {
        assert_eq!(&cpuid_state(leaf, 0).gpr[..4], &[0; 4]);
    }
}
#[test]
fn cpuid_preserves_flags_xmm_and_mxcsr() {
    let s = cpuid_state(0, 0);
    assert_eq!(s.rflags, 0x8d7);
    assert_eq!(s.xmm, [u128::MAX; 16]);
    assert_eq!(s.mxcsr, INITIAL_MXCSR);
}
#[test]
fn cpuid_zero_extends_all_outputs_and_advances_rip() {
    let s = cpuid_state(0, 0);
    assert!(s.gpr[..4].iter().all(|v| v >> 32 == 0));
    assert_eq!(s.rip, GuestAddr(0x10002));
}

#[test]
#[cfg_attr(
    not(coverage),
    ignore = "requires PALUDARIUM_U3_NATIVE_FAULTS from the native runner"
)]
fn packed_crypto_movement_fault_replay() {
    use super::exec::Stop;
    use paludarium_decoder::{Mnemonic as M, decode};
    use paludarium_mmu::{AddressSpace, MappingKind, Prot};
    fn bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
            .collect()
    }
    let path = std::env::var("PALUDARIUM_U3_NATIVE_FAULTS").expect("native fault path");
    let cpuid = std::fs::read_to_string(
        std::env::var("PALUDARIUM_U3_NATIVE_CPUID").expect("native CPU profile path"),
    )
    .unwrap();
    let amd = native_contract::amd_profile(&cpuid);
    let mut differences = std::collections::BTreeSet::new();
    let full = std::env::var_os("PALUDARIUM_U3_FULL_REPLAY").is_some();
    let mut count = 0;
    for row in std::fs::read_to_string(path).unwrap().lines() {
        let f: Vec<_> = row.split('|').collect();
        assert_eq!(f.len(), 13);
        let instruction = decode(&bytes(f[8]), GuestAddr(0x10000)).unwrap();
        if !full
            && crate::sse::packed(instruction.mnemonic, 0, 0, 0, 0).is_none()
            && crate::crypto::execute(instruction.mnemonic, 0, 0, 0, 0).is_none()
            && !matches!(
                instruction.mnemonic,
                M::Movaps
                    | M::Movapd
                    | M::Movups
                    | M::Movupd
                    | M::Movdqu
                    | M::Movdqa
                    | M::Lddqu
                    | M::Movd
                    | M::Movq
                    | M::Movss
                    | M::MovsdSse
                    | M::Movlps
                    | M::Movlpd
                    | M::Movhps
                    | M::Movhpd
                    | M::Movhlps
                    | M::Movlhps
                    | M::Movddup
                    | M::Movmskps
                    | M::Movmskpd
                    | M::Pmovmskb
                    | M::Ptest
                    | M::Pextrb
                    | M::Pextrw
                    | M::Pextrd
                    | M::Pextrq
                    | M::Pinsrb
                    | M::Pinsrw
                    | M::Pinsrd
                    | M::Pinsrq
                    | M::Ldmxcsr
                    | M::Stmxcsr
            )
        {
            continue;
        }
        let scenario: u32 = f[1].parse().unwrap();
        let offset = match scenario {
            2 => 4096 - 24,
            3 => 1,
            _ => 0,
        };
        let input = bytes(f[9]);
        let before = bytes(f[10]);
        let output = bytes(f[11]);
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x40000)),
                8192,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        let address = GuestAddr(0x40000 + offset);
        memory.write(address, &before).unwrap();
        match scenario {
            0 => memory
                .protect(GuestAddr(0x40000), 8192, Prot::NONE)
                .unwrap(),
            1 => memory
                .protect(GuestAddr(0x40000), 8192, Prot::READ)
                .unwrap(),
            2 => memory
                .protect(GuestAddr(0x41000), 4096, Prot::NONE)
                .unwrap(),
            _ => (),
        }
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x80000));
        for n in 0..16 {
            state.xmm[n] = u128::from_le_bytes(input[n * 16..n * 16 + 16].try_into().unwrap());
        }
        state.mxcsr = u32::from_le_bytes(input[256..260].try_into().unwrap());
        state.gpr[0] = 0x8000_0001_7fff_0011;
        state.gpr[2] = address.0;
        state.rflags = 0x8d7;
        let original = state.clone();
        let result = super::exec::execute(&mut state, &memory, &instruction);
        if native_contract::amd_sha_difference(&f, amd) {
            assert!(differences.insert((f[0].to_owned(), scenario)));
            assert!(matches!(result, Err(Stop::GeneralProtection)));
            assert_eq!(state.gpr, original.gpr);
            assert_eq!(state.xmm, original.xmm);
            assert_eq!(state.rip, original.rip);
            assert_eq!(state.mxcsr, original.mxcsr);
            assert_eq!(state.rflags, original.rflags);
            memory
                .protect(GuestAddr(0x40000), 8192, Prot::READ_WRITE)
                .unwrap();
            let mut after = [0; 512];
            memory.read(address, &mut after).unwrap();
            assert_eq!(after.as_slice(), before);
            count += 1;
            continue;
        }
        let signal: u32 = f[2].parse().unwrap();
        let trap: u32 = f[5].parse().unwrap();
        match (signal, trap, result) {
            (0, 0, Ok(())) => assert_eq!(state.rip, instruction.next_rip()),
            (11, 13, Err(Stop::GeneralProtection)) => assert_eq!(state.rip, GuestAddr(0x10000)),
            (11, 14, Err(Stop::Fault(fault))) => {
                let delta: i64 = f[7].parse().unwrap();
                assert_eq!(
                    fault.addr.0.wrapping_sub(address.0) as i64,
                    delta,
                    "{} scenario{} fault address",
                    f[0],
                    scenario
                );
                let native_error: u32 = f[6].parse().unwrap();
                assert_eq!(fault.write, native_error & 2 != 0);
                assert_eq!(state.rip, GuestAddr(0x10000));
            }
            (8, 19, Err(Stop::FloatingPointFault(code))) => {
                assert_eq!(
                    u32::from(code),
                    f[4].parse::<u32>().unwrap(),
                    "{} scenario{} signal code",
                    f[0],
                    scenario
                );
                assert_eq!(state.rip, GuestAddr(0x10000));
            }
            other => panic!("{} scenario{} mismatch {:?}", f[0], scenario, other),
        }
        for n in 0..16 {
            assert_eq!(
                state.xmm[n].to_le_bytes(),
                output[n * 16..n * 16 + 16],
                "{} scenario{} XMM{}",
                f[0],
                scenario,
                n
            );
        }
        assert_eq!(state.gpr[0].to_le_bytes(), output[256..264], "{} RAX", f[0]);
        assert_eq!(
            state.rflags & 0xcd5,
            u64::from_le_bytes(output[264..272].try_into().unwrap()) & 0xcd5
        );
        assert_eq!(
            state.mxcsr.to_le_bytes(),
            output[272..276],
            "{} scenario{} MXCSR",
            f[0],
            scenario
        );
        memory
            .protect(GuestAddr(0x40000), 8192, Prot::READ_WRITE)
            .unwrap();
        let mut after = [0; 512];
        memory.read(address, &mut after).unwrap();
        assert_eq!(
            after.as_slice(),
            bytes(f[12]),
            "{} scenario{} memory",
            f[0],
            scenario
        );
        count += 1;
    }
    assert!(count > 500, "fault boundary case count {count}");
    if amd {
        assert_eq!(differences.len(), 6);
    }
    println!("native packed/crypto/movement fault boundary cases compared: {count}");
}

#[test]
fn floating_rounding_modes_distinguish_halfway_integer() {
    use super::softfloat::{F32, from_integer};
    let results: Vec<_> = (0..4)
        .map(|mode| from_integer(F32, 16_777_217, 0x1f80 | (mode << 13)))
        .collect();
    assert_eq!(
        results,
        [
            (0x4b80_0000, 32),
            (0x4b80_0000, 32),
            (0x4b80_0001, 32),
            (0x4b80_0000, 32)
        ]
    );
}
#[test]
fn floating_daz_preserves_zero_sign() {
    use super::softfloat::{F64, Operation as O, arithmetic};
    assert_eq!(
        arithmetic(
            F64,
            O::Mul,
            0x8000_0000_0000_0001,
            0x3ff0_0000_0000_0000,
            0x1fc0
        ),
        (0x8000_0000_0000_0000, 0)
    );
}
#[test]
fn floating_ftz_reports_underflow_and_precision() {
    use super::softfloat::{F64, Operation as O, arithmetic};
    assert_eq!(
        arithmetic(
            F64,
            O::Mul,
            0x0010_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x9f80
        ),
        (0, 48)
    );
}
#[test]
fn floating_exact_subnormal_division_keeps_nonzero_result() {
    use super::softfloat::{F64, Operation as O, arithmetic};
    assert_eq!(
        arithmetic(F64, O::Div, 2, 0x4000_0000_0000_0000, 0x1f80),
        (1, 2)
    );
}
#[test]
fn floating_sqrt_and_negative_invalid_are_distinct() {
    use super::softfloat::{F64, Operation as O, arithmetic};
    assert_eq!(
        arithmetic(F64, O::Sqrt, 0x4010_0000_0000_0000, 0, 0x1f80),
        (0x4000_0000_0000_0000, 0)
    );
    assert_eq!(
        arithmetic(F64, O::Sqrt, 0xbff0_0000_0000_0000, 0, 0x1f80),
        (0xfff8_0000_0000_0000, 1)
    );
}
#[test]
fn floating_nan_payload_quieting_is_explicit() {
    use super::softfloat::{F64, Operation as O, arithmetic};
    assert_eq!(
        arithmetic(
            F64,
            O::Add,
            0x7ff0_0000_0000_0042,
            0x3ff0_0000_0000_0000,
            0x1f80
        ),
        (0x7ff8_0000_0000_0042, 1)
    );
}
#[test]
fn floating_integer_range_invalid_suppresses_precision() {
    use super::softfloat::{F64, to_integer};
    assert_eq!(
        to_integer(F64, 0x43e0_0000_0000_0000, 64, 0x1f80),
        (1 << 63, 1)
    );
    assert_eq!(
        to_integer(F64, 0xc3e0_0000_0000_0000, 64, 0x1f80),
        (1 << 63, 0)
    );
}
#[test]
fn floating_comparison_distinguishes_qnan_and_snan() {
    use super::softfloat::{F64, compare};
    assert_eq!(
        compare(F64, 0x7ff8_0000_0000_0001, 0, 0x1f80, false),
        (None, 0)
    );
    assert_eq!(
        compare(F64, 0x7ff0_0000_0000_0001, 0, 0x1f80, false),
        (None, 1)
    );
    assert_eq!(
        compare(F64, 0, 0x8000_0000_0000_0000, 0x1f80, false),
        (Some(0), 0)
    );
}

fn public_machine(code: &[u8]) -> (CpuState, paludarium_mmu::AddressSpace) {
    use paludarium_mmu::{AddressSpace, MappingKind, Prot};
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(0x10000)),
            4096,
            Prot::from_bits(7).unwrap(),
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write(GuestAddr(0x10000), code).unwrap();
    (
        CpuState::new(GuestAddr(0x10000), GuestAddr(0x80000)),
        memory,
    )
}

#[test]
fn public_cached_sse_sees_code_changes_and_budget() {
    use paludarium_types::ExitReason;
    let (mut state, memory) = public_machine(&[0x66, 0x0f, 0xef, 0xc0]);
    let mut cache = super::DecodeCache::new();
    state.xmm[0] = u128::MAX;
    assert!(matches!(
        super::run_cached(&mut state, &memory, 1, &mut cache),
        ExitReason::BudgetExhausted { .. }
    ));
    assert_eq!(state.xmm[0], 0);
    memory.write(GuestAddr(0x10003), &[0xc1]).unwrap();
    state.rip = GuestAddr(0x10000);
    state.xmm[0] = 0xaa;
    state.xmm[1] = 0x55;
    super::step_cached(&mut state, &memory, &mut cache).unwrap();
    assert_eq!(state.xmm[0], 0xff);
    assert_eq!(super::current_rip(&state), GuestAddr(0x10004));
}

#[test]
fn public_sse_fetch_permission_and_truncation_preserve_state() {
    use paludarium_mmu::Prot;
    use paludarium_types::ExitReason;
    let (mut state, mut memory) = public_machine(&[0x66, 0x0f, 0xef, 0xc0]);
    memory
        .protect(GuestAddr(0x10000), 4096, Prot::READ)
        .unwrap();
    assert!(matches!(
        super::step(&mut state, &memory),
        Err(ExitReason::PageFault { fetch: true, .. })
    ));
    memory
        .protect(GuestAddr(0x10000), 4096, Prot::from_bits(7).unwrap())
        .unwrap();
    memory.write(GuestAddr(0x10fff), &[0x66]).unwrap();
    state.rip = GuestAddr(0x10fff);
    let before = state.clone();
    assert!(matches!(
        super::step(&mut state, &memory),
        Err(ExitReason::PageFault {
            fetch: true,
            addr: GuestAddr(0x11000),
            ..
        })
    ));
    assert_eq!(state.rip, before.rip);
    assert_eq!(state.xmm, before.xmm);
}

#[test]
fn public_sse_alignment_fault_is_transactional() {
    use paludarium_types::ExitReason;
    let (mut state, memory) = public_machine(&[0x0f, 0x28, 0x02]);
    state.gpr[2] = 0x10001;
    state.xmm = [u128::MAX; 16];
    let before = state.clone();
    assert!(matches!(
        super::run(&mut state, &memory, 1),
        ExitReason::GeneralProtection { .. }
    ));
    assert_eq!(state.xmm, before.xmm);
    assert_eq!(state.rip, before.rip);
    assert_eq!(state.mxcsr, before.mxcsr);
}

#[test]
fn public_unsupported_simd_reports_original_encoding() {
    use paludarium_types::ExitReason;
    for code in [
        &[0xc5, 0xf9, 0xef, 0xc0][..],
        &[0x66, 0x0f, 0x38, 0xde, 0xc1][..],
    ] {
        let (mut state, memory) = public_machine(code);
        match super::step(&mut state, &memory) {
            Err(ExitReason::InvalidOpcode { rip, bytes }) => {
                assert_eq!(rip, GuestAddr(0x10000));
                assert_eq!(&bytes.as_slice()[..code.len()], code);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn public_cached_sse_observes_unmapping_and_zero_budget() {
    use paludarium_types::ExitReason;
    let (mut state, mut memory) = public_machine(&[0x66, 0x0f, 0xef, 0xc0]);
    let mut cache = super::DecodeCache::new();
    state.xmm[0] = u128::MAX;
    assert!(matches!(
        super::run_cached(&mut state, &memory, 0, &mut cache),
        ExitReason::BudgetExhausted { .. }
    ));
    assert_eq!(state.xmm[0], u128::MAX);
    super::step_cached(&mut state, &memory, &mut cache).unwrap();
    state.rip = GuestAddr(0x10000);
    memory.unmap(GuestAddr(0x10000), 4096).unwrap();
    assert!(matches!(
        super::step_cached(&mut state, &memory, &mut cache),
        Err(ExitReason::PageFault {
            fetch: true,
            mapped: false,
            ..
        })
    ));
}

#[test]
fn public_unmasked_simd_exception_keeps_destination_and_commits_status() {
    use paludarium_types::ExitReason;
    // DIVSS zero/zero with invalid unmasked: #XM leaves the destination intact.
    let (mut state, memory) = public_machine(&[0xf3, 0x0f, 0x5e, 0xc1]);
    state.mxcsr = INITIAL_MXCSR & !(1 << 7);
    state.xmm[0] = 0x1122_3344_5566_7788_0000_0000_0000_0000;
    let before = state.clone();
    assert!(matches!(
        super::step(&mut state, &memory),
        Err(ExitReason::FloatingPointFault { .. })
    ));
    assert_eq!(state.xmm, before.xmm);
    assert_eq!(state.gpr, before.gpr);
    assert_eq!(state.rip, before.rip);
    assert_eq!(state.rflags, before.rflags);
    assert_eq!(state.mxcsr, before.mxcsr | 1);
}
