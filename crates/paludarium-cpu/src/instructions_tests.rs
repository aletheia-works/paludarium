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
fn zero_rep_count_does_not_touch_invalid_memory() {
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
fn address32_string_wraps_count_and_indices() {
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
fn string_source_segment_does_not_apply_to_destination() {
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
fn repeat_context_clears_on_different_instruction() {
    let (mut s, m) = continuation();
    s.rip = GuestAddr(0x10002);
    step(&mut s, &m).unwrap();
    assert!(s.repeat_continuation.is_none());
}
#[test]
fn repeat_fetch_fault_applies_explicit_flags_model_and_clears_context() {
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
fn repeat_data_fault_applies_explicit_flags_model() {
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
fn code_change_invalidates_cached_repeat_context() {
    let (mut s, m) = continuation();
    m.write_initial(GuestAddr(0x10000), &[0x90]).unwrap();
    let flags = s.rflags;
    step_cached(&mut s, &m, &mut DecodeCache::new()).unwrap();
    assert!(s.repeat_continuation.is_none());
    assert_eq!(s.rflags, flags);
    assert_eq!(s.rip, GuestAddr(0x10001));
}
#[test]
fn failed_cmpxchg16b_preflights_all_write_permissions() {
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
fn address32_loop_zero_extends_ecx_without_modifying_flags() {
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
fn segment_atomic_paths_truncate_offset_before_adding_base() {
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
fn segment_pair_alignment_uses_final_linear_address() {
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
fn segment_failed_compare_preflights_final_write_permissions() {
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
fn segment_unmapped_atomic_fault_reports_final_address() {
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
fn segment_pair_failed_compare_zero_extends_registers() {
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

#[test]
fn popf_setting_the_trap_flag_ends_the_run_and_the_next_instruction_traps() {
    // push 0x302 (TF | IF | reserved); popfq; nop; nop
    let (mut s, mem) = fixture(&[0x68, 0x02, 0x03, 0, 0, 0x9d, 0x90, 0x90]);
    s.gpr[reg::RSP] = 0x4000_1000;
    let mut cache = DecodeCache::new();
    // The popf runs, and the run ends right after it, with no trap.
    assert_eq!(
        run_cached(&mut s, &mem, 100, &mut cache),
        ExitReason::BudgetExhausted {
            rip: GuestAddr(0x10006)
        }
    );
    assert_ne!(s.rflags & flag::TF, 0);
    // Then each instruction runs alone and traps after itself.
    assert_eq!(
        step_traced(&mut s, &mem, &mut cache),
        ExitReason::SingleStep {
            rip: GuestAddr(0x10007)
        }
    );
    assert_eq!(
        step_traced(&mut s, &mem, &mut cache),
        ExitReason::SingleStep {
            rip: GuestAddr(0x10008)
        }
    );
}

#[test]
fn a_stepped_syscall_or_int3_gives_no_single_step_trap() {
    // syscall; int3
    let (mut s, mem) = fixture(&[0x0f, 0x05, 0xcc]);
    s.rflags |= flag::TF;
    let mut cache = DecodeCache::new();
    assert_eq!(
        step_traced(&mut s, &mem, &mut cache),
        ExitReason::Syscall {
            rip: GuestAddr(0x10002)
        }
    );
    assert_eq!(
        step_traced(&mut s, &mem, &mut cache),
        ExitReason::Breakpoint {
            rip: GuestAddr(0x10003)
        }
    );
}

#[test]
fn popf_clearing_the_trap_flag_still_traps_after_itself() {
    // push 0x202; popfq
    let (mut s, mem) = fixture(&[0x68, 0x02, 0x02, 0, 0, 0x9d]);
    s.gpr[reg::RSP] = 0x4000_1000;
    s.rflags |= flag::TF;
    let mut cache = DecodeCache::new();
    step_traced(&mut s, &mem, &mut cache);
    assert_eq!(
        step_traced(&mut s, &mem, &mut cache),
        ExitReason::SingleStep {
            rip: GuestAddr(0x10006)
        }
    );
    assert_eq!(s.rflags & flag::TF, 0);
}

#[test]
fn an_execute_breakpoint_faults_before_its_instruction_once() {
    use crate::breakpoints::{BreakOn, Breakpoint, Breakpoints, run_watched};
    // nop; nop
    let (mut s, mem) = fixture(&[0x90, 0x90]);
    let mut cache = DecodeCache::new();
    let mut set = Breakpoints::default();
    set.0[2] = Some(Breakpoint {
        address: 0x10001,
        length: 1,
        on: BreakOn::Execute,
    });
    assert_eq!(
        run_watched(&mut s, &mem, 10, &mut cache, &set),
        ExitReason::HardwareBreakpoint {
            rip: GuestAddr(0x10001),
            hits: 0b100,
            step: false
        }
    );
    assert_ne!(s.rflags & flag::RF, 0);
    // Resumed with RF, the instruction runs.
    assert_eq!(
        run_watched(&mut s, &mem, 1, &mut cache, &set),
        ExitReason::BudgetExhausted {
            rip: GuestAddr(0x10002)
        }
    );
    assert_eq!(s.rflags & flag::RF, 0);
}

#[test]
fn a_data_breakpoint_traps_after_the_access_it_watches() {
    use crate::breakpoints::{BreakOn, Breakpoint, Breakpoints, run_watched};
    // mov [0x40000008], ecx (disp32 absolute); mov edx, [0x40000008]; push rax
    let code = [
        0x89, 0x0c, 0x25, 0x08, 0, 0, 0x40, //
        0x8b, 0x14, 0x25, 0x08, 0, 0, 0x40, //
        0x50,
    ];
    let (mut s, mem) = fixture(&code);
    s.gpr[reg::RSP] = 0x4000_1000;
    let mut cache = DecodeCache::new();
    let mut set = Breakpoints::default();
    set.0[1] = Some(Breakpoint {
        address: 0x4000_0008,
        length: 8,
        on: BreakOn::Write,
    });
    let hit = |rip| ExitReason::HardwareBreakpoint {
        rip: GuestAddr(rip),
        hits: 0b10,
        step: false,
    };
    assert_eq!(
        run_watched(&mut s, &mem, 10, &mut cache, &set),
        hit(0x10007)
    );
    // A read does not hit a write breakpoint; a read or write one, it does.
    set.0[1].as_mut().unwrap().on = BreakOn::Access;
    let mut writes_only = set;
    writes_only.0[1].as_mut().unwrap().on = BreakOn::Write;
    let mut probe = s.clone();
    assert_eq!(
        run_watched(&mut probe, &mem, 1, &mut cache, &writes_only),
        ExitReason::BudgetExhausted {
            rip: GuestAddr(0x1000e)
        }
    );
    assert_eq!(
        run_watched(&mut s, &mem, 10, &mut cache, &set),
        hit(0x1000e)
    );
    // A push writes the stack under rsp.
    set.0[1] = Some(Breakpoint {
        address: 0x4000_0ff8,
        length: 8,
        on: BreakOn::Write,
    });
    assert_eq!(
        run_watched(&mut s, &mem, 10, &mut cache, &set),
        hit(0x1000f)
    );
}

#[test]
fn a_string_instruction_without_a_repeat_hits_a_data_breakpoint() {
    use crate::breakpoints::{BreakOn, Breakpoint, Breakpoints, run_watched};
    // stosq; rep stosq
    let (mut s, mem) = fixture(&[0x48, 0xab, 0xf3, 0x48, 0xab]);
    s.gpr[reg::RDI] = 0x4000_0010;
    s.gpr[reg::RCX] = 1;
    let mut cache = DecodeCache::new();
    let mut set = Breakpoints::default();
    set.0[3] = Some(Breakpoint {
        address: 0x4000_0010,
        length: 8,
        on: BreakOn::Write,
    });
    assert_eq!(
        run_watched(&mut s, &mem, 10, &mut cache, &set),
        ExitReason::HardwareBreakpoint {
            rip: GuestAddr(0x10002),
            hits: 0b1000,
            step: false
        }
    );
    // A repeated one is not looked at yet.
    set.0[3].as_mut().unwrap().address = 0x4000_0018;
    assert_eq!(
        run_watched(&mut s, &mem, 1, &mut cache, &set),
        ExitReason::BudgetExhausted {
            rip: GuestAddr(0x10005)
        }
    );
}
