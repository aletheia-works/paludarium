//! Arbitrary instruction bytes and registers: the native JIT's code for the
//! leading instructions with forms does what the interpreter does.
#![no_main]
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use paludarium_cpu::compile::{Compiler, Fast, Form};
use paludarium_cpu::{CpuState, step};
use paludarium_decoder::decode;
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::GuestAddr;

const CODE: u64 = 0x10000;
const DATA: u64 = 0x4000_0000;
const DATA_LEN: usize = 8192;

/// One compiler for every input: making one sets up Cranelift.
static COMPILER: OnceLock<Option<Arc<dyn Compiler>>> = OnceLock::new();

fn space(code: &[u8], data: &[u8]) -> Option<AddressSpace> {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(CODE)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .ok()?;
    memory
        .map(
            Some(GuestAddr(DATA)),
            DATA_LEN as u64,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .ok()?;
    memory.write_initial(GuestAddr(CODE), code).ok()?;
    memory.write_initial(GuestAddr(DATA), data).ok()?;
    Some(memory)
}

fn contents(memory: &AddressSpace) -> Vec<u8> {
    let mut data = vec![0; DATA_LEN];
    let _ = memory.read(GuestAddr(DATA), &mut data);
    data
}

fuzz_target!(|data: &[u8]| {
    // 16 registers, then RFLAGS, then the code; the data page is the input
    // again.
    if data.len() < 17 * 8 + 1 {
        return;
    }
    let Some(compiler) = COMPILER.get_or_init(|| paludarium_jit_native::compiler_with(1, false))
    else {
        return;
    };
    let (registers, code) = data.split_at(17 * 8);
    let code = &code[..code.len().min(4096)];
    let mut forms = Vec::new();
    let mut offset = 0;
    while offset < code.len() && forms.len() < 32 {
        let Ok(i) = decode(&code[offset..], GuestAddr(CODE + offset as u64)) else {
            break;
        };
        let fast = Fast::of(&i);
        if fast == Fast::None {
            break;
        }
        forms.push(Form {
            rip: i.rip.0,
            next: i.next_rip().0,
            fast,
        });
        offset += usize::from(i.len);
    }
    if forms.is_empty() {
        return;
    }
    let Some(compiled) = compiler.compile(&forms) else {
        return;
    };
    let fill: Vec<u8> = data.iter().copied().cycle().take(DATA_LEN).collect();
    let (Some(fast_memory), Some(slow_memory)) = (space(code, &fill), space(code, &fill)) else {
        return;
    };
    let mut before = CpuState::new(GuestAddr(CODE), GuestAddr(DATA + DATA_LEN as u64));
    for (slot, bytes) in before.gpr.iter_mut().zip(registers.chunks_exact(8)) {
        let value = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
        // Half the registers point into the data page, so that loads and
        // stores mostly succeed.
        *slot = if value & 1 == 0 {
            DATA + (value >> 1) % DATA_LEN as u64
        } else {
            value
        };
    }
    before.rflags =
        u64::from_le_bytes(registers[128..136].try_into().unwrap_or([0; 8])) & 0xcd5 | 2;
    let mut fast = before.clone();
    let ran = compiled.run(
        &mut fast,
        &fast_memory,
        fast_memory.code_generation_cached(),
    );
    assert!(ran <= forms.len());
    let mut slow = before.clone();
    for _ in 0..ran {
        assert!(
            step(&mut slow, &slow_memory).is_ok(),
            "the interpreter stopped"
        );
    }
    assert_eq!(fast, slow, "compiled code and the interpreter differ");
    assert_eq!(
        contents(&fast_memory),
        contents(&slow_memory),
        "memory differs"
    );
});
