//! The forms of [`exec::Fast`] mean what [`exec::execute`] does.
use super::*;
use paludarium_mmu::{MappingKind, Prot};

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;
const DATA_LEN: usize = 0x2000;
const DATA_BYTES: u64 = DATA_LEN as u64;
const STACK: u64 = 0x80_0000;
const STACK_LEN: usize = 0x2000;

/// Instructions that have a form, with registers that point at data, the
/// stack, unmapped memory or anywhere.
const FORMS: &[&[u8]] = &[
    &[0x90],
    &[0xf3, 0x0f, 0x1e, 0xfa],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    // mov r, r/imm
    &[0x48, 0x89, 0xd8],
    &[0x89, 0xd8],
    &[0x88, 0xd8],
    &[0x40, 0x88, 0xe7],
    &[0x66, 0x89, 0xd8],
    &[0x45, 0x89, 0xc8],
    &[0x48, 0xc7, 0xc0, 0xf0, 0xff, 0xff, 0xff],
    &[0xb8, 0x78, 0x56, 0x34, 0x12],
    &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 0x88],
    &[0xb0, 0x80],
    // mov r, [m]
    &[0x48, 0x8b, 0x03],
    &[0x8b, 0x43, 0x08],
    &[0x48, 0x8b, 0x04, 0xcb],
    &[0x8a, 0x03],
    &[0x66, 0x8b, 0x43, 0xff],
    &[0x64, 0x48, 0x8b, 0x03],
    &[0x67, 0x8b, 0x03],
    &[0x48, 0x8b, 0x05, 0x00, 0x00, 0x20, 0x00],
    // mov [m], r/imm
    &[0x48, 0x89, 0x03],
    &[0x89, 0x43, 0x04],
    &[0x88, 0x03],
    &[0x66, 0x89, 0x03],
    &[0x48, 0xc7, 0x03, 0x80, 0xff, 0xff, 0xff],
    &[0xc6, 0x03, 0x7f],
    &[0x48, 0x89, 0x44, 0xcb, 0xf9],
    // movzx r, [m]
    &[0x0f, 0xb6, 0x03],
    &[0x48, 0x0f, 0xb7, 0x03],
    &[0x66, 0x0f, 0xb6, 0x03],
    // lea
    &[0x48, 0x8d, 0x44, 0xcb, 0x10],
    &[0x67, 0x48, 0x8d, 0x03],
    &[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00],
    // push, pop
    &[0x53],
    &[0x54],
    &[0x41, 0x50],
    &[0x5b],
    &[0x5c],
    &[0x41, 0x58],
    // branches
    &[0x74, 0x05],
    &[0x75, 0xfb],
    &[0x0f, 0x8c, 0x00, 0x01, 0x00, 0x00],
    &[0x76, 0x05],
    &[0x7f, 0x05],
    &[0x7a, 0x05],
    &[0xeb, 0x05],
    &[0xe9, 0x00, 0x10, 0x00, 0x00],
    &[0xe8, 0x00, 0x10, 0x00, 0x00],
    &[0xc3],
    // op r, r/imm
    &[0x48, 0x01, 0xd8],
    &[0x48, 0x29, 0xd8],
    &[0x21, 0xd8],
    &[0x09, 0xd8],
    &[0x31, 0xc0],
    &[0x66, 0x31, 0xd8],
    &[0x00, 0xd8],
    &[0x48, 0x39, 0xd8],
    &[0x48, 0x85, 0xc0],
    &[0x48, 0x83, 0xc0, 0xf0],
    &[0x83, 0xe0, 0x0f],
    &[0x48, 0x83, 0xf8, 0x7f],
    &[0xf6, 0xc3, 0x01],
    &[0x3c, 0x05],
    &[0x48, 0x3d, 0x00, 0x00, 0x00, 0x80],
    &[0x83, 0xe8, 0x01],
    &[0x48, 0x83, 0xec, 0x18],
    &[0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff],
    // cmp/test [m], r/imm
    &[0x48, 0x39, 0x03],
    &[0x80, 0x3b, 0x2f],
    &[0x48, 0x83, 0x3b, 0x00],
    &[0xf6, 0x03, 0x01],
    &[0x48, 0x85, 0x03],
    &[0x66, 0x83, 0x7b, 0x02, 0xff],
];

/// Instructions that must keep running in [`exec::execute`].
const OTHERS: &[&[u8]] = &[
    &[0xf0, 0x48, 0x01, 0x03],
    &[0x48, 0x01, 0x03],
    &[0x48, 0x11, 0xd8],
    &[0x88, 0xe0],
    &[0x0f, 0xb6, 0xc3],
    &[0x66, 0x53],
    &[0x6a, 0x01],
    &[0xff, 0xd0],
    &[0xff, 0xe0],
    &[0xc2, 0x08, 0x00],
    &[0xf3, 0xc3],
    &[0x8d, 0x03],
    &[0x48, 0xf7, 0xd8],
    &[0x0f, 0x05],
];

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn space(code: &[u8], data: &[u8]) -> AddressSpace {
    let mut mem = AddressSpace::new();
    for (at, len, prot, kind) in [
        (CODE, 0x1000, Prot::READ_EXEC, MappingKind::ElfSegment),
        (DATA, DATA_BYTES, Prot::READ_WRITE, MappingKind::Anonymous),
        (
            STACK - STACK_LEN as u64,
            STACK_LEN as u64,
            Prot::READ_WRITE,
            MappingKind::Stack,
        ),
    ] {
        mem.map(Some(GuestAddr(at)), len, prot, kind).unwrap();
    }
    mem.write_initial(GuestAddr(CODE), code).unwrap();
    mem.write_initial(GuestAddr(DATA), data).unwrap();
    mem
}

fn contents(mem: &AddressSpace) -> (Vec<u8>, Vec<u8>) {
    let mut data = vec![0; DATA_LEN];
    let mut stack = vec![0; STACK_LEN];
    mem.read(GuestAddr(DATA), &mut data).unwrap();
    mem.read(GuestAddr(STACK - STACK_LEN as u64), &mut stack)
        .unwrap();
    (data, stack)
}

/// A value for a register: an address in the data, near the end of the stack
/// or of the data (where accesses run off it), unmapped, or anything.
fn value(random: &mut Random) -> u64 {
    let r = random.next();
    match r % 6 {
        0 | 1 => DATA + (r >> 8) % DATA_LEN as u64,
        2 => STACK - (r >> 8) % 64,
        3 => DATA + DATA_LEN as u64 - (r >> 8) % 16,
        4 => 0x1000 + (r >> 8) % 0x1000,
        _ => random.next(),
    }
}

fn state(random: &mut Random) -> CpuState {
    let mut s = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    for gpr in &mut s.gpr {
        *gpr = value(random);
    }
    // The index registers are small, so that scaled addresses stay near.
    s.gpr[reg::RCX] = random.next() % 64;
    s.rflags = (random.next() & flag::STATUS) | flag::RESERVED1;
    s.fs_base = random.next() % 0x100;
    s
}

#[test]
fn every_form_does_what_the_interpreter_does() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut faults = 0;
    for code in FORMS {
        let instruction = decode(code, GuestAddr(CODE)).unwrap();
        let fast = exec::Fast::of(&instruction);
        assert_ne!(fast, exec::Fast::None, "{code:02x?} has no form");
        for _ in 0..400 {
            let data: Vec<u8> = (0..DATA_LEN).map(|_| random.next() as u8).collect();
            let before = state(&mut random);
            let (fast_memory, slow_memory) = (space(code, &data), space(code, &data));
            let mut fast_state = before.clone();
            let mut slow_state = before.clone();
            let slow = exec::execute(&mut slow_state, &slow_memory, &instruction);
            match exec::execute_fast(
                &mut fast_state,
                &fast_memory,
                &instruction,
                &fast,
                instruction.next_rip().0,
            ) {
                Ok(()) => {
                    assert_eq!(slow, Ok(()), "{code:02x?} from {before:x?}");
                    assert_eq!(fast_state, slow_state, "{code:02x?} from {before:x?}");
                    assert_eq!(
                        contents(&fast_memory),
                        contents(&slow_memory),
                        "{code:02x?}"
                    );
                }
                Err(_) => {
                    faults += 1;
                    assert!(slow.is_err(), "{code:02x?} from {before:x?}");
                    assert_eq!(fast_state, before, "{code:02x?} changed the state");
                    assert_eq!(contents(&fast_memory), contents(&space(code, &data)));
                }
            }
        }
    }
    assert!(faults > 0);
}

#[test]
fn other_instructions_have_no_form() {
    for code in OTHERS {
        let instruction = decode(code, GuestAddr(CODE)).unwrap();
        assert_eq!(
            exec::Fast::of(&instruction),
            exec::Fast::None,
            "{code:02x?}"
        );
    }
}

/// A form that faults runs again in the interpreter, which reports it.
#[test]
fn a_form_that_faults_stops_as_the_interpreter_does() {
    // mov rax, [rbx]; push rbx with rsp unmapped
    for (code, setup) in [
        (&[0x48, 0x8b, 0x03][..], (reg::RBX, 0x1000)),
        (&[0x53][..], (reg::RSP, 0x1008)),
        (&[0x48, 0x89, 0x03][..], (reg::RBX, CODE)),
    ] {
        let memory = space(code, &[]);
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
        state.gpr[setup.0] = setup.1;
        let mut cache = DecodeCache::new();
        let fast = step_cached(&mut state.clone(), &memory, &mut cache);
        let slow = step(&mut state, &memory);
        assert!(
            matches!(fast, Err(ExitReason::PageFault { .. })),
            "{fast:?}"
        );
        assert_eq!(fast, slow);
    }
}
