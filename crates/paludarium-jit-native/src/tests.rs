//! Compiled code does what the interpreter does: each form, and runs of
//! forms, from random states, compared with `paludarium_cpu::step`.
use paludarium_cpu::compile::{Compiler, Fast, Form};
use paludarium_cpu::{CpuState, flag, reg, step};
use paludarium_decoder::decode;
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::GuestAddr;

use crate::native::NativeCompiler;

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;
const DATA_LEN: usize = 0x2000;
const STACK: u64 = 0x80_0000;
const STACK_LEN: usize = 0x2000;

/// Instructions that have a form, run with registers that point at data,
/// the stack, past the end of the data, unmapped memory or anywhere.
const FORMS: &[&[u8]] = &[
    &[0x90],
    &[0xf3, 0x0f, 0x1e, 0xfa],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
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
    &[0x48, 0x8b, 0x03],
    &[0x8b, 0x43, 0x08],
    &[0x48, 0x8b, 0x04, 0xcb],
    &[0x8a, 0x03],
    &[0x66, 0x8b, 0x43, 0xff],
    &[0x64, 0x48, 0x8b, 0x03],
    &[0x67, 0x8b, 0x03],
    &[0x48, 0x8b, 0x05, 0x00, 0x00, 0x20, 0x00],
    &[0x48, 0x89, 0x03],
    &[0x89, 0x43, 0x04],
    &[0x88, 0x03],
    &[0x66, 0x89, 0x03],
    &[0x48, 0xc7, 0x03, 0x80, 0xff, 0xff, 0xff],
    &[0xc6, 0x03, 0x7f],
    &[0x48, 0x89, 0x44, 0xcb, 0xf9],
    &[0x0f, 0xb6, 0x03],
    &[0x48, 0x0f, 0xb7, 0x03],
    &[0x66, 0x0f, 0xb6, 0x03],
    &[0x48, 0x8d, 0x44, 0xcb, 0x10],
    &[0x67, 0x48, 0x8d, 0x03],
    &[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00],
    &[0x53],
    &[0x54],
    &[0x41, 0x50],
    &[0x5b],
    &[0x5c],
    &[0x41, 0x58],
    &[0x74, 0x05],
    &[0x75, 0xfb],
    &[0x0f, 0x8c, 0x00, 0x01, 0x00, 0x00],
    &[0x72, 0x05],
    &[0x73, 0x05],
    &[0x76, 0x05],
    &[0x77, 0x05],
    &[0x78, 0x05],
    &[0x79, 0x05],
    &[0x7a, 0x05],
    &[0x7b, 0x05],
    &[0x7c, 0x05],
    &[0x7d, 0x05],
    &[0x7e, 0x05],
    &[0x7f, 0x05],
    &[0x70, 0x05],
    &[0x71, 0x05],
    &[0xeb, 0x05],
    &[0xe9, 0x00, 0x10, 0x00, 0x00],
    &[0xe8, 0x00, 0x10, 0x00, 0x00],
    &[0xc3],
    &[0x48, 0x01, 0xd8],
    &[0x48, 0x29, 0xd8],
    &[0x21, 0xd8],
    &[0x09, 0xd8],
    &[0x31, 0xc0],
    &[0x66, 0x31, 0xd8],
    &[0x00, 0xd8],
    &[0x28, 0xd8],
    &[0x66, 0x01, 0xd8],
    &[0x01, 0xd8],
    &[0x29, 0xd8],
    &[0x48, 0x39, 0xd8],
    &[0x39, 0xd8],
    &[0x38, 0xd8],
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
    &[0x48, 0x39, 0x03],
    &[0x80, 0x3b, 0x2f],
    &[0x48, 0x83, 0x3b, 0x00],
    &[0xf6, 0x03, 0x01],
    &[0x48, 0x85, 0x03],
    &[0x66, 0x83, 0x7b, 0x02, 0xff],
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
        (
            DATA,
            DATA_LEN as u64,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        ),
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

fn value(random: &mut Random) -> u64 {
    let r = random.next();
    match r % 7 {
        0 | 1 => DATA + (r >> 8) % DATA_LEN as u64,
        2 => STACK - (r >> 8) % 64,
        3 => DATA + DATA_LEN as u64 - (r >> 8) % 16,
        4 => 0x1000 + (r >> 8) % 0x1000,
        5 => (r >> 8) % 4,
        _ => random.next(),
    }
}

fn state(random: &mut Random) -> CpuState {
    let mut s = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    for gpr in &mut s.gpr {
        *gpr = value(random);
    }
    s.gpr[reg::RCX] = random.next() % 64;
    s.rflags = (random.next() & flag::STATUS) | flag::RESERVED1;
    s.fs_base = random.next() % 0x100;
    s
}

/// The forms of `code`, instructions placed one after another at `CODE`.
fn forms(code: &[u8]) -> Vec<Form> {
    let mut forms = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let i = decode(&code[offset..], GuestAddr(CODE + offset as u64)).unwrap();
        let fast = Fast::of(&i);
        assert_ne!(fast, Fast::None, "{:02x?} has no form", &code[offset..]);
        forms.push(Form {
            rip: i.rip.0,
            next: i.next_rip().0,
            fast,
        });
        offset += usize::from(i.len);
    }
    forms
}

/// Runs `code` compiled and in the interpreter from random states.
fn compare(compiler: &NativeCompiler, code: &[u8], random: &mut Random, rounds: usize) -> usize {
    let forms = forms(code);
    let compiled = compiler
        .compile(&forms)
        .unwrap_or_else(|| panic!("{code:02x?} did not compile"));
    let mut stopped = 0;
    for _ in 0..rounds {
        let data: Vec<u8> = (0..DATA_LEN).map(|_| random.next() as u8).collect();
        let before = state(random);
        let (fast_memory, slow_memory) = (space(code, &data), space(code, &data));
        let generation = fast_memory.code_generation_cached();
        let mut fast = before.clone();
        let ran = compiled.run(&mut fast, &fast_memory, generation);
        assert!(ran <= forms.len());
        let mut slow = before.clone();
        for _ in 0..ran {
            step(&mut slow, &slow_memory).unwrap_or_else(|e| {
                panic!("{code:02x?} from {before:x?}: the interpreter stopped: {e:?}")
            });
        }
        assert_eq!(fast, slow, "{code:02x?} from {before:x?}, {ran} ran");
        assert_eq!(
            contents(&fast_memory),
            contents(&slow_memory),
            "{code:02x?} from {before:x?}"
        );
        // Stopping before an instruction of the block means it fails.
        if let Some(form) = forms.iter().find(|f| f.rip == fast.rip.0)
            && ran < forms.len()
            && forms[ran].rip == form.rip
        {
            stopped += 1;
            assert!(
                step(&mut slow.clone(), &slow_memory).is_err(),
                "{code:02x?} from {before:x?} stopped before {:#x}, which runs",
                form.rip
            );
        }
    }
    stopped
}

#[test]
fn every_form_does_what_the_interpreter_does() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut stopped = 0;
    for code in FORMS {
        stopped += compare(&compiler, code, &mut random, 300);
    }
    assert!(stopped > 0, "no form failed");
}

#[test]
fn runs_of_forms_do_what_the_interpreter_does() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for _ in 0..400 {
        let len = 2 + random.next() % 10;
        let mut code = Vec::new();
        for _ in 0..len {
            let form = FORMS[(random.next() % FORMS.len() as u64) as usize];
            code.extend_from_slice(form);
        }
        compare(&compiler, &code, &mut random, 20);
    }
}

#[test]
fn a_form_that_faults_runs_nothing() {
    let compiler = NativeCompiler::new(1, false).unwrap();
    // mov rax, [rbx] with rbx unmapped.
    let code = [0x48, 0x8b, 0x03];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    state.gpr[reg::RBX] = 0x1000;
    let before = state.clone();
    assert_eq!(
        compiled.run(&mut state, &memory, memory.code_generation_cached()),
        0
    );
    assert_eq!(state, before);
}

/// How long compiling takes, for measuring: `cargo test --release -p
/// paludarium-jit-native -- --ignored --nocapture compile_time`.
#[test]
#[ignore = "measures; prints only"]
fn compile_time() {
    let variants: [&[(&str, &str)]; 4] = [
        &[("opt_level", "none")],
        &[("opt_level", "speed")],
        &[("opt_level", "none"), ("regalloc_algorithm", "single_pass")],
        &[
            ("opt_level", "speed"),
            ("regalloc_algorithm", "single_pass"),
        ],
    ];
    for set in variants {
        let compiler = NativeCompiler::with_settings(1, false, set).unwrap();
        for len in [1, 7, 20] {
            let mut random = Random(0x1234_5678_9abc_def1);
            let blocks: Vec<Vec<Form>> = (0..300)
                .map(|_| {
                    let mut code = Vec::new();
                    for _ in 0..len {
                        let form = FORMS[(random.next() % FORMS.len() as u64) as usize];
                        code.extend_from_slice(form);
                    }
                    forms(&code)
                })
                .collect();
            let started = std::time::Instant::now();
            let mut bytes = 0;
            for forms in &blocks {
                bytes += compiler.machine_code(forms).unwrap().len();
            }
            let elapsed = started.elapsed();
            println!(
                "{set:?} len {len}: {:.1} us per block, {} bytes per block",
                elapsed.as_secs_f64() * 1e6 / blocks.len() as f64,
                bytes / blocks.len()
            );
        }
    }
}

#[test]
fn a_block_compiled_in_the_background_runs_once_it_is_ready() {
    let compiler = NativeCompiler::new(1, true).unwrap();
    // mov eax, 0x12345678; add rax, rbx
    let code = [0xb8, 0x78, 0x56, 0x34, 0x12, 0x48, 0x01, 0xd8];
    let compiled = compiler.compile(&forms(&code)).unwrap();
    let memory = space(&code, &[]);
    let generation = memory.code_generation_cached();
    let started = std::time::Instant::now();
    loop {
        let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
        state.gpr[reg::RBX] = 1;
        let before = state.clone();
        match compiled.run(&mut state, &memory, generation) {
            0 => {
                assert_eq!(state, before, "a block not yet compiled changed the state");
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(60),
                    "the block was never compiled"
                );
                std::thread::yield_now();
            }
            ran => {
                assert_eq!(ran, 2);
                assert_eq!(state.gpr[reg::RAX], 0x1234_5679);
                break;
            }
        }
    }
    // The same forms again reuse the code.
    let again = compiler.compile(&forms(&code)).unwrap();
    let mut state = CpuState::new(GuestAddr(CODE), GuestAddr(STACK - 0x100));
    assert_eq!(again.run(&mut state, &memory, generation), 2);
}
