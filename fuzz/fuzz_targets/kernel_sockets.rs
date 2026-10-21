#![no_main]
use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, reg};
use paludarium_kernel::{Kernel, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use std::sync::Arc;
fn call(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, n: u64, args: [u64; 6]) -> u64 {
    t.cpu.gpr[reg::RAX] = n;
    for (r, v) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
        .into_iter()
        .zip(args)
    {
        t.cpu.gpr[r] = v;
    }
    let _ = k.handle(
        t,
        m,
        ExitReason::Syscall {
            rip: GuestAddr(0x400000),
        },
    );
    t.cpu.gpr[reg::RAX]
}
fuzz_target!(|data: &[u8]| {
    let m = AddressSpace::new();
    if m.map_shared(
        Some(GuestAddr(0x600000)),
        4096,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .is_err()
    {
        return;
    }
    let mut k = Kernel::new(Arc::new(paludarium_host::NativeHost));
    let mut t = Thread::new(1, CpuState::default());
    call(&mut k, &mut t, &m, 53, [1, 0x80801, 0, 0x600000, 0, 0]);
    let mut bytes = [0; 8];
    if m.read(GuestAddr(0x600000), &mut bytes).is_err() {
        return;
    }
    let fds = [
        u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
        u64::from(u32::from_le_bytes(bytes[4..].try_into().unwrap())),
    ];
    for chunk in data.chunks(4).take(64) {
        if chunk.len() != 4 {
            break;
        }
        let fd = fds[usize::from(chunk[1] & 1)];
        let ptr = if chunk[2] & 1 == 0 { 0x600100 } else { 1 };
        let len = u64::from(chunk[3] % 65);
        let _ = m.write(GuestAddr(0x600100), chunk);
        match chunk[0] % 8 {
            0 => {
                call(&mut k, &mut t, &m, 1, [fd, ptr, len, 0, 0, 0]);
            }
            1 => {
                call(&mut k, &mut t, &m, 0, [fd, ptr, len, 0, 0, 0]);
            }
            2 => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    48,
                    [fd, u64::from(chunk[2] % 4), 0, 0, 0, 0],
                );
            }
            3 => {
                call(&mut k, &mut t, &m, 44, [fd, ptr, len, 0x4000, 0, 0]);
            }
            4 => {
                call(&mut k, &mut t, &m, 45, [fd, ptr, len, 0, 0, 0]);
            }
            5 => {
                call(&mut k, &mut t, &m, 32, [fd, 0, 0, 0, 0, 0]);
            }
            6 => {
                call(&mut k, &mut t, &m, 3, [fd, 0, 0, 0, 0, 0]);
            }
            _ => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    53,
                    [
                        u64::from(chunk[1]),
                        0x80801 | u64::from(chunk[2]),
                        0,
                        ptr,
                        0,
                        0,
                    ],
                );
            }
        }
    }
});
