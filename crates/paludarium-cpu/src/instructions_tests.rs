#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
fn fixture(code: &[u8]) -> (CpuState, AddressSpace) {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(0x10000)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory
        .map(
            Some(GuestAddr(0x40000000)),
            8192,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write_initial(GuestAddr(0x10000), code).unwrap();
    (CpuState::new(GuestAddr(0x10000), GuestAddr(0)), memory)
}
#[test]
fn u2_zero_rep_count_does_not_touch_invalid_memory() {
    let (mut s, m) = fixture(&[0xf3, 0xa6]);
    s.gpr[reg::RSI] = u64::MAX;
    s.gpr[reg::RDI] = u64::MAX;
    let flags = s.rflags;
    step(&mut s, &m).unwrap();
    assert_eq!(s.rip, GuestAddr(0x10002));
    assert_eq!(s.rflags, flags);
    assert!(s.repeat_continuation.is_none());
}
#[test]
fn u2_address32_string_wraps_count_and_indices() {
    let (mut s, m) = fixture(&[0x67, 0xf3, 0xa4]);
    s.gpr[reg::RSI] = 0x123440000000;
    s.gpr[reg::RDI] = 0xabcd40000010;
    s.gpr[reg::RCX] = 0x777700000001;
    m.write(GuestAddr(0x40000000), &[0x42]).unwrap();
    step(&mut s, &m).unwrap();
    assert_eq!(s.gpr[reg::RCX], 0);
    assert_eq!(s.gpr[reg::RSI], 0x40000001);
    assert_eq!(s.gpr[reg::RDI], 0x40000011);
    let mut byte = [0];
    m.read(GuestAddr(0x40000010), &mut byte).unwrap();
    assert_eq!(byte, [0x42]);
}
#[test]
fn u2_string_source_segment_does_not_apply_to_destination() {
    let (mut s, m) = fixture(&[0x64, 0xa4]);
    s.fs_base = 0x40000000;
    s.gpr[reg::RSI] = 3;
    s.gpr[reg::RDI] = 0x40000010;
    m.write(GuestAddr(0x40000003), &[0x71]).unwrap();
    step(&mut s, &m).unwrap();
    let mut byte = [0];
    m.read(GuestAddr(0x40000010), &mut byte).unwrap();
    assert_eq!(byte, [0x71]);
}
fn continuation() -> (CpuState, AddressSpace) {
    let (mut s, m) = fixture(&[0xf3, 0xa6, 0x90]);
    m.write(GuestAddr(0x40000000), &[0x31; 8192]).unwrap();
    s.rflags = 0x8d7;
    s.gpr[reg::RSI] = 0x40000000;
    s.gpr[reg::RDI] = 0x40000000;
    s.gpr[reg::RCX] = 4097;
    assert!(matches!(
        run(&mut s, &m, 1),
        ExitReason::BudgetExhausted { .. }
    ));
    assert!(s.repeat_continuation.is_some());
    (s, m)
}
#[test]
fn u2_repeat_context_clears_on_different_instruction() {
    let (mut s, m) = continuation();
    s.rip = GuestAddr(0x10002);
    step(&mut s, &m).unwrap();
    assert!(s.repeat_continuation.is_none());
}
#[test]
fn u2_repeat_fetch_fault_applies_explicit_flags_model_and_clears_context() {
    for policy in [
        RepFaultFlags::RestoreInitial,
        RepFaultFlags::PreserveCompleted,
    ] {
        let (mut s, mut m) = continuation();
        s.rep_fault_flags = policy;
        let flags = s.rflags;
        m.unmap(GuestAddr(0x10000), 4096).unwrap();
        assert!(matches!(
            step(&mut s, &m),
            Err(ExitReason::PageFault { write: false, .. })
        ));
        assert_eq!(
            s.rflags,
            if policy == RepFaultFlags::RestoreInitial {
                0x8d7
            } else {
                flags
            }
        );
        assert!(s.repeat_continuation.is_none());
        assert_eq!(s.gpr[reg::RCX], 1);
    }
}

#[test]
fn u2_repeat_data_fault_applies_explicit_flags_model() {
    assert_eq!(
        CpuState::default().rep_fault_flags,
        RepFaultFlags::RestoreInitial
    );
    for policy in [
        RepFaultFlags::RestoreInitial,
        RepFaultFlags::PreserveCompleted,
    ] {
        for (code, expected) in [([0xf3, 0xa6], 0x44), ([0xf2, 0xae], 0)] {
            for completed in [0, 17, 4096] {
                let (mut state, memory) = fixture(&code);
                state.rep_fault_flags = policy;
                memory.write(GuestAddr(0x40000000), &[0x31; 8192]).unwrap();
                state.rflags = 0x8d7;
                state.gpr[reg::RAX] = 0x32;
                state.gpr[reg::RCX] = completed + 1;
                state.gpr[reg::RSI] = 0x40002000 - completed;
                state.gpr[reg::RDI] = 0x40002000 - completed;
                if completed == 4096 {
                    assert!(matches!(
                        run(&mut state, &memory, 1),
                        ExitReason::BudgetExhausted { .. }
                    ));
                    assert_eq!(state.rflags & 0xcd5, expected);
                    assert_eq!(state.gpr[reg::RCX], 1);
                }
                assert!(matches!(
                    run(&mut state, &memory, 1),
                    ExitReason::PageFault { .. }
                ));
                assert_eq!(
                    state.rflags & 0xcd5,
                    if completed == 0 || policy == RepFaultFlags::RestoreInitial {
                        0x8d5
                    } else {
                        expected
                    }
                );
                assert_eq!(state.gpr[reg::RCX], 1);
                assert_eq!(state.gpr[reg::RDI], 0x40002000);
                assert_eq!(state.rip, GuestAddr(0x10000));
                assert!(state.repeat_continuation.is_none());
            }
        }
    }
}
#[test]
fn u2_code_change_invalidates_cached_repeat_context() {
    let (mut s, m) = continuation();
    m.write_initial(GuestAddr(0x10000), &[0x90]).unwrap();
    let flags = s.rflags;
    step_cached(&mut s, &m, &mut DecodeCache::new()).unwrap();
    assert!(s.repeat_continuation.is_none());
    assert_eq!(s.rflags, flags);
    assert_eq!(s.rip, GuestAddr(0x10001));
}
#[test]
fn u2_failed_cmpxchg16b_preflights_all_write_permissions() {
    let (mut s, mut m) = fixture(&[0xf0, 0x48, 0x0f, 0xc7, 0x0f]);
    s.gpr[reg::RDI] = 0x40000000;
    m.write_u64(GuestAddr(0x40000000), 7).unwrap();
    m.protect(GuestAddr(0x40000000), 4096, Prot::READ).unwrap();
    let before = s.clone();
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault { write: true, .. })
    ));
    assert_eq!(s, before);
    assert_eq!(m.read_u64(GuestAddr(0x40000000)).unwrap(), 7);
}
#[test]
fn u2_address32_loop_zero_extends_ecx_without_modifying_flags() {
    let (mut s, m) = fixture(&[0x67, 0xe2, 0]);
    s.gpr[reg::RCX] = 0x123400000000;
    let flags = s.rflags;
    step(&mut s, &m).unwrap();
    assert_eq!(s.gpr[reg::RCX], 0xffff_ffff);
    assert_eq!(s.rflags, flags);
}

fn segmented_fixture(code: &[u8], fs: bool) -> (CpuState, AddressSpace) {
    let mut bytes = vec![if fs { 0x64 } else { 0x65 }, 0x67];
    bytes.extend_from_slice(code);
    let (mut state, mut memory) = fixture(&bytes);
    memory
        .map(
            Some(GuestAddr(0x1_40000000)),
            4096,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write_u64(GuestAddr(0x40000000), 99).unwrap();
    memory.write_u64(GuestAddr(0x40000008), 88).unwrap();
    memory.write_u64(GuestAddr(0x1_40000000), 41).unwrap();
    state.gpr[reg::RDI] = 0xdeadbeef40000000;
    state.gpr[reg::RSI] = 3;
    state.gpr[reg::RAX] = 41;
    state.gpr[reg::RBX] = 5;
    state.gpr[reg::RCX] = 6;
    state.rflags = 0x8d7;
    if fs {
        state.fs_base = 0x1_00000000;
    } else {
        state.gs_base = 0x1_00000000;
    }
    (state, memory)
}

#[test]
fn u2_segment_atomic_paths_truncate_offset_before_adding_base() {
    let cases: &[(&[u8], u64, u64, bool)] = &[
        (&[0xf0, 0x48, 0x01, 0x37], 44, 0, false),
        (&[0xf0, 0x48, 0x11, 0x37], 45, 0, false),
        (&[0xf0, 0x48, 0x29, 0x37], 38, 0, false),
        (&[0xf0, 0x48, 0x19, 0x37], 37, 0, false),
        (&[0xf0, 0x48, 0x21, 0x37], 1, 0, false),
        (&[0xf0, 0x48, 0x09, 0x37], 43, 0, false),
        (&[0xf0, 0x48, 0x31, 0x37], 42, 0, false),
        (&[0xf0, 0x48, 0xff, 0x07], 42, 0, false),
        (&[0xf0, 0x48, 0xff, 0x0f], 40, 0, false),
        (&[0xf0, 0x48, 0xf7, 0x1f], 41u64.wrapping_neg(), 0, false),
        (&[0xf0, 0x48, 0xf7, 0x17], !41, 0, false),
        (&[0xf0, 0x48, 0x0f, 0xab, 0x37], 41, 0, false),
        (&[0xf0, 0x48, 0x0f, 0xb3, 0x37], 33, 0, false),
        (&[0xf0, 0x48, 0x0f, 0xbb, 0x37], 33, 0, false),
        (&[0x48, 0x87, 0x37], 3, 0, true),
        (&[0xf0, 0x48, 0x0f, 0xc1, 0x37], 44, 0, true),
        (&[0xf0, 0x48, 0x0f, 0xb1, 0x37], 3, 0, false),
        (&[0xf0, 0x0f, 0xc7, 0x0f], 0x6_00000005, 0, false),
        (&[0xf0, 0x48, 0x0f, 0xc7, 0x0f], 5, 6, false),
    ];
    for fs in [true, false] {
        for &(code, low, high, old_source) in cases {
            let (mut state, memory) = segmented_fixture(code, fs);
            step(&mut state, &memory).unwrap();
            assert_eq!(
                memory.read_u64(GuestAddr(0x1_40000000)).unwrap(),
                low,
                "{code:x?}"
            );
            assert_eq!(
                memory.read_u64(GuestAddr(0x1_40000008)).unwrap(),
                high,
                "{code:x?}"
            );
            assert_eq!(memory.read_u64(GuestAddr(0x40000000)).unwrap(), 99);
            assert_eq!(memory.read_u64(GuestAddr(0x40000008)).unwrap(), 88);
            if old_source {
                assert_eq!(state.gpr[reg::RSI], 41);
            }
        }
    }
}

#[test]
fn u2_segment_pair_alignment_uses_final_linear_address() {
    let code = [0xf0, 0x48, 0x0f, 0xc7, 0x0f];
    let (mut state, memory) = segmented_fixture(&code, false);
    state.gs_base += 1;
    let before = state.clone();
    assert!(matches!(
        step(&mut state, &memory),
        Err(ExitReason::GeneralProtection { .. })
    ));
    assert_eq!(state, before);
    assert_eq!(memory.read_u64(GuestAddr(0x1_40000000)).unwrap(), 41);
    state.gs_base = 0xffff_ffff;
    state.gpr[reg::RDI] += 1;
    step(&mut state, &memory).unwrap();
    assert_eq!(memory.read_u64(GuestAddr(0x1_40000000)).unwrap(), 5);
    assert_eq!(memory.read_u64(GuestAddr(0x40000000)).unwrap(), 99);
}

#[test]
fn u2_segment_failed_compare_preflights_final_write_permissions() {
    for fs in [true, false] {
        let (mut state, mut memory) = segmented_fixture(&[0xf0, 0x48, 0x0f, 0xb1, 0x37], fs);
        state.gpr[reg::RAX] = 0;
        memory
            .protect(GuestAddr(0x1_40000000), 4096, Prot::READ)
            .unwrap();
        let before = state.clone();
        assert!(matches!(
            step(&mut state, &memory),
            Err(ExitReason::PageFault {
                addr: GuestAddr(0x1_40000000),
                write: true,
                ..
            })
        ));
        assert_eq!(state, before);
        assert_eq!(memory.read_u64(GuestAddr(0x1_40000000)).unwrap(), 41);
        assert_eq!(memory.read_u64(GuestAddr(0x40000000)).unwrap(), 99);
    }
}

#[test]
fn u2_segment_unmapped_atomic_fault_reports_final_address() {
    let (mut state, memory) = fixture(&[0x65, 0xf0, 0x48, 0xff, 0x07]);
    state.gpr[reg::RDI] = 0x40000000;
    state.gs_base = 0x1_00000000;
    let before = state.clone();
    assert!(matches!(
        step(&mut state, &memory),
        Err(ExitReason::PageFault {
            addr: GuestAddr(0x1_40000000),
            write: true,
            ..
        })
    ));
    assert_eq!(state, before);
}

#[test]
fn u2_segment_pair_failed_compare_zero_extends_registers() {
    let (mut state, memory) = segmented_fixture(&[0xf0, 0x0f, 0xc7, 0x0f], false);
    memory
        .write_u64(GuestAddr(0x1_40000000), 0x1122334455667788)
        .unwrap();
    state.gpr[reg::RAX] = 0xaaaa000000000000;
    state.gpr[reg::RDX] = 0xbbbb000000000000;
    step(&mut state, &memory).unwrap();
    assert_eq!(state.gpr[reg::RAX], 0x55667788);
    assert_eq!(state.gpr[reg::RDX], 0x11223344);
    assert_eq!(memory.read_u64(GuestAddr(0x40000000)).unwrap(), 99);
}
#[path = "signals_time_tests.rs"]
mod signals_time_tests;
