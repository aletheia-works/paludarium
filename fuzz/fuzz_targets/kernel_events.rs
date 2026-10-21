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
    let fd = call(
        &mut k,
        &mut t,
        &m,
        290,
        [
            0,
            0x800 | u64::from(data.first().copied().unwrap_or(0) & 1),
            0,
            0,
            0,
            0,
        ],
    );
    let e = call(&mut k, &mut t, &m, 291, [0; 6]);
    for chunk in data.chunks(4).take(64) {
        if chunk.len() != 4 {
            break;
        }
        let ptr = if chunk[1] & 1 == 0 { 0x600000 } else { 1 };
        let value = u64::from(chunk[2]) | (u64::from(chunk[3]) << 56);
        let _ = m.write_u64(GuestAddr(0x600000), value);
        match chunk[0] % 8 {
            0 => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    1,
                    [fd, ptr, u64::from(chunk[1] % 17), 0, 0, 0],
                );
            }
            1 => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    0,
                    [fd, ptr, u64::from(chunk[1] % 17), 0, 0, 0],
                );
            }
            2 => {
                let mask =
                    1 | ((u32::from(chunk[2] & 1)) << 31) | ((u32::from(chunk[3] & 1)) << 30);
                let mut bytes = mask.to_le_bytes().to_vec();
                bytes.extend_from_slice(&value.to_le_bytes());
                let _ = m.write(GuestAddr(0x600000), &bytes);
                call(
                    &mut k,
                    &mut t,
                    &m,
                    233,
                    [e, u64::from(chunk[1] % 5), fd, ptr, 0, 0],
                );
            }
            3 => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    232,
                    [e, ptr, u64::from(chunk[1] % 5), 0, 0, 0],
                );
            }
            4 => {
                call(&mut k, &mut t, &m, 32, [fd, 0, 0, 0, 0, 0]);
            }
            5 => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    3,
                    [u64::from(chunk[1] % 10), 0, 0, 0, 0, 0],
                );
            }
            6 => {
                call(&mut k, &mut t, &m, 72, [fd, 3, 0, 0, 0, 0]);
            }
            _ => {
                call(
                    &mut k,
                    &mut t,
                    &m,
                    281,
                    [e, ptr, 1, 0, ptr, u64::from(chunk[1])],
                );
            }
        }
    }
});
