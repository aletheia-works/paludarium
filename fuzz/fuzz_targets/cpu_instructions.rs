//! Arbitrary instruction bytes and architectural inputs, with bounded CPU work.
#![no_main]
use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, run};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::GuestAddr;
fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let mut memory = AddressSpace::new();
    if memory
        .map(
            Some(GuestAddr(0x10000)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .is_err()
    {
        return;
    }
    if memory
        .map(
            Some(GuestAddr(0x40000000)),
            8192,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .is_err()
    {
        return;
    }
    let end = data.len().min(4096);
    let _ = memory.write_initial(GuestAddr(0x10000), &data[..end]);
    let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x40002000));
    for (slot, bytes) in state.gpr.iter_mut().zip(data.chunks_exact(8)) {
        *slot = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
    }
    state.rflags = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8])) & 0xcd5 | 2;
    for (slot, bytes) in state.xmm.iter_mut().zip(data.chunks_exact(16)) {
        *slot = u128::from_le_bytes(bytes.try_into().unwrap_or([0; 16]));
    }
    // All architecturally valid rounding/mask/DAZ/FTZ combinations participate;
    // instruction bytes and XMM inputs remain arbitrary libFuzzer inputs.
    state.mxcsr = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) & 0xffff;
    // Eight instructions, each REP chunk capped at 4096 iterations.
    let _ = run(&mut state, &memory, 8);
});
