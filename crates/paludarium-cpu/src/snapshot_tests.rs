#![allow(clippy::unwrap_used, clippy::panic)]
//! What a failed instruction puts back ([`Snapshot`]), and which
//! instructions keep the vector state out of it.
use super::*;
use paludarium_mmu::{MappingKind, Prot};

/// `code` at 0x10000 (readable and executable, not writable), and a stack
/// page at 0x40000000.
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
            Some(GuestAddr(0x4000_0000)),
            4096,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write_initial(GuestAddr(0x10000), code).unwrap();
    (
        CpuState::new(GuestAddr(0x10000), GuestAddr(0x4000_0800)),
        memory,
    )
}

fn decoded(bytes: &[u8]) -> Instruction {
    decode(bytes, GuestAddr(0x10000)).unwrap()
}

#[test]
fn a_leave_that_faults_puts_the_stack_pointer_back() {
    // leave: rsp = rbp, then a pop from an unmapped page.
    let (mut s, m) = fixture(&[0xc9]);
    s.gpr[reg::RBP] = 0x7000;
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault { .. })
    ));
    assert_eq!(s.gpr[reg::RSP], 0x4000_0800);
    assert_eq!(s.gpr[reg::RBP], 0x7000);
    assert_eq!(s.rip, GuestAddr(0x10000));
}

#[test]
fn an_add_to_read_only_memory_puts_the_flags_back() {
    // add [rip-6], al: the first code byte (0x00) plus 0x80 sets SF, but
    // the code page cannot be written.
    let (mut s, m) = fixture(&[0x00, 0x05, 0xfa, 0xff, 0xff, 0xff]);
    s.gpr[reg::RAX] = 0x80;
    let flags = s.rflags;
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault { write: true, .. })
    ));
    assert_eq!(s.rflags, flags);
}

#[test]
fn general_instructions_without_xmm_operands_keep_the_vector_state() {
    for bytes in [
        &[0x48, 0x89, 0xd8][..],   // mov rax, rbx
        &[0xff, 0xd0],             // call rax
        &[0xf3, 0x0f, 0xb8, 0xc0], // popcnt eax, eax
        &[0x48, 0x0f, 0x44, 0xc3], // cmove rax, rbx
        &[0xc9],                   // leave
    ] {
        assert!(exec::keeps_vector_state(&decoded(bytes)), "{bytes:02x?}");
    }
}

#[test]
fn anything_else_may_change_the_vector_state() {
    for bytes in [
        &[0x66, 0x48, 0x0f, 0x6e, 0xc0][..], // movq xmm0, rax
        &[0x0f, 0x28, 0xc1],                 // movaps xmm0, xmm1
        &[0x0f, 0xae, 0x10],                 // ldmxcsr [rax]
        &[0x66, 0x0f, 0xef, 0xc0],           // pxor xmm0, xmm0
        &[0xf2, 0x48, 0x0f, 0x2a, 0xc0],     // cvtsi2sd xmm0, rax
    ] {
        let insn = decoded(bytes);
        assert!(!exec::keeps_vector_state(&insn), "{bytes:02x?}");
        let state = CpuState::default();
        assert!(
            Snapshot::of(&state, Decoded::new(insn).keeps_vector_state)
                .vector
                .is_some()
        );
    }
}
