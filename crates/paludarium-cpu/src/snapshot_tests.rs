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

/// A snapshot-free instruction that fails: nothing in the state may change.
fn fails_with_nothing_changed(code: &[u8], set: impl Fn(&mut CpuState)) {
    assert!(exec::fails_cleanly(&decoded(code)), "{code:02x?}");
    let (mut s, m) = fixture(code);
    set(&mut s);
    // Values that would change the flags if an instruction got that far.
    s.gpr[reg::RAX] = 0x8000_0000_0000_0001;
    s.gpr[reg::RCX] = 0x7fff_ffff_ffff_ffff;
    s.xmm[3] = 7;
    let before = s.clone();
    assert!(step(&mut s, &m).is_err(), "{code:02x?}");
    assert_eq!(s, before, "{code:02x?}");
}

#[test]
fn instructions_that_fail_cleanly_change_nothing_on_a_bad_read() {
    for code in [
        &[0x48, 0x8b, 0x03][..],   // mov rax, [rbx]
        &[0x0f, 0xb6, 0x03],       // movzx eax, byte [rbx]
        &[0x0f, 0xbe, 0x03],       // movsx eax, byte [rbx]
        &[0x48, 0x63, 0x03],       // movsxd rax, dword [rbx]
        &[0x48, 0x03, 0x03],       // add rax, [rbx]
        &[0x48, 0x13, 0x03],       // adc rax, [rbx]
        &[0x48, 0x2b, 0x03],       // sub rax, [rbx]
        &[0x48, 0x1b, 0x03],       // sbb rax, [rbx]
        &[0x48, 0x23, 0x03],       // and rax, [rbx]
        &[0x48, 0x0b, 0x03],       // or rax, [rbx]
        &[0x48, 0x33, 0x03],       // xor rax, [rbx]
        &[0x48, 0x3b, 0x03],       // cmp rax, [rbx]
        &[0x48, 0x85, 0x03],       // test [rbx], rax
        &[0x48, 0xff, 0x03],       // inc qword [rbx]
        &[0x48, 0xff, 0x0b],       // dec qword [rbx]
        &[0x48, 0xf7, 0x1b],       // neg qword [rbx]
        &[0x48, 0xf7, 0x13],       // not qword [rbx]
        &[0xf0, 0x48, 0x01, 0x03], // lock add [rbx], rax
        &[0xf0, 0x48, 0xff, 0x03], // lock inc qword [rbx]
        &[0xff, 0x33],             // push qword [rbx]
        &[0xff, 0x13],             // call [rbx]
        &[0xff, 0x23],             // jmp [rbx]
        &[0x48, 0x0f, 0x44, 0x03], // cmove rax, [rbx]
    ] {
        fails_with_nothing_changed(code, |s| s.gpr[reg::RBX] = 0x7000);
    }
}

#[test]
fn instructions_that_fail_cleanly_change_nothing_on_a_bad_write() {
    for code in [
        &[0x48, 0x89, 0x03][..],   // mov [rbx], rax
        &[0x48, 0x01, 0x03],       // add [rbx], rax
        &[0x48, 0x31, 0x03],       // xor [rbx], rax
        &[0x48, 0xff, 0x03],       // inc qword [rbx]
        &[0x48, 0xf7, 0x1b],       // neg qword [rbx]
        &[0x48, 0xf7, 0x13],       // not qword [rbx]
        &[0xf0, 0x48, 0x01, 0x03], // lock add [rbx], rax
        &[0x0f, 0x94, 0x03],       // sete [rbx]
    ] {
        // The code page can be read but not written.
        fails_with_nothing_changed(code, |s| s.gpr[reg::RBX] = 0x10000);
    }
}

#[test]
fn instructions_that_fail_cleanly_change_nothing_on_a_bad_stack() {
    for code in [
        &[0x50][..],                     // push rax
        &[0x58],                         // pop rax
        &[0xc3],                         // ret
        &[0xc2, 0x08, 0x00],             // ret 8
        &[0xe8, 0x00, 0x00, 0x00, 0x00], // call next
    ] {
        fails_with_nothing_changed(code, |s| s.gpr[reg::RSP] = 0x7000);
    }
}

#[test]
fn a_pop_to_read_only_memory_puts_the_stack_pointer_back() {
    // pop [rbx]: the stack pointer has moved when the write fails.
    let code = [0x8f, 0x03];
    assert!(!exec::fails_cleanly(&decoded(&code)));
    let (mut s, m) = fixture(&code);
    s.gpr[reg::RBX] = 0x10000;
    let before = s.clone();
    assert!(step(&mut s, &m).is_err());
    assert_eq!(s, before);
}

#[test]
fn a_leave_needs_its_snapshot() {
    assert!(!exec::fails_cleanly(&decoded(&[0xc9])));
}
