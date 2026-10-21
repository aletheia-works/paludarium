#![no_main]
use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, reg};
use paludarium_kernel::{Kernel, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use std::sync::Arc;
fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let mem = AddressSpace::new();
    if mem
        .map_shared(
            Some(GuestAddr(0x600000)),
            4096,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .is_err()
    {
        return;
    }
    let _ = mem.write(GuestAddr(0x600000), &data[..4]);
    let mut kernel = Kernel::new(Arc::new(paludarium_host::NativeHost));
    let mut thread = Thread::new(1, CpuState::default());
    thread.cpu.gpr[reg::RAX] = 202;
    thread.cpu.gpr[reg::RDI] = 0x600000 + u64::from(data[4] & 3);
    thread.cpu.gpr[reg::RSI] = u64::from(data[5]);
    thread.cpu.gpr[reg::RDX] = u64::from(u32::from_le_bytes(data[6..10].try_into().unwrap()));
    // Always supply a zero/expired timespec so accepted WAITs are finite.
    thread.cpu.gpr[reg::R10] = 0x600010;
    thread.cpu.gpr[reg::R9] = u64::from(data[10]);
    let _ = kernel.handle(
        &mut thread,
        &mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x400000),
        },
    );
});
