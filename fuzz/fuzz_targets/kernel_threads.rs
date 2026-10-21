#![no_main]
use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, reg};
use paludarium_kernel::{Kernel, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use std::sync::Arc;
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
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
    let mut kernel = Kernel::new(Arc::new(paludarium_host::NativeHost));
    let mut thread = Thread::new(1, CpuState::default());
    thread.cpu.gpr[reg::RAX] = 56;
    thread.cpu.gpr[reg::RDI] = u64::from_le_bytes(data[..8].try_into().unwrap());
    thread.cpu.gpr[reg::RSI] = 0x601000;
    thread.cpu.gpr[reg::RDX] = 0x600000;
    thread.cpu.gpr[reg::R10] = 0x600004;
    thread.cpu.gpr[reg::R8] = 0x600008;
    let _ = kernel.handle(
        &mut thread,
        &mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x400000),
        },
    );
    if let Some((mut child, t)) = kernel.take_child() {
        child.finish_thread(&t, &mem);
    }
    kernel.finish_thread(&thread, &mem);
    assert_eq!(kernel.thread_group().active_threads(), 0);
});
