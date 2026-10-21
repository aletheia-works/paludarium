//! Any system call number with any arguments must be handled without a
//! panic: implemented calls validate their arguments, the rest return
//! -ENOSYS.
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, reg};
#[path = "support/syscall_host.rs"]
mod syscall_host;
use paludarium_kernel::{Kernel, SyscallTable, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use paludarium_vfs::{GuestFile, MemFs};
use syscall_host::BoundedHost;

const AREA: u64 = 0x10_0000;
const AREA_LEN: u64 = 0x4000;

fuzz_target!(|data: &[u8]| {
    let numbers: Vec<u64> = SyscallTable::u1().numbers().collect();
    let mut mem = AddressSpace::new();
    if mem
        .map(
            Some(GuestAddr(AREA)),
            AREA_LEN,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .is_err()
    {
        return;
    }
    mem.set_initial_break(GuestAddr(0x20_0000));
    // Fuzz argument/frame bytes as well as pointers. Virtual timer sequences
    // get a finite wait quota even when the requested deadline is enormous.
    let _ = mem.write(GuestAddr(AREA), &data[..data.len().min(AREA_LEN as usize)]);
    let mut fs = MemFs::new();
    let _ = fs.add_file(GuestFile::new(b"/u7".to_vec(), b"data".to_vec()));
    let mut kernel = Kernel::new(Arc::new(BoundedHost::new())).with_file_system(Arc::new(fs));
    let mut thread = Thread::new(1, CpuState::default());
    thread.cpu.gpr[reg::RSP] = AREA + AREA_LEN;
    // Keep one valid file description reachable by the subsequent sequence.
    let _ = mem.write(GuestAddr(AREA + 0x3000), b"/u7\0");
    thread.cpu.gpr[reg::RAX] = 2;
    thread.cpu.gpr[reg::RDI] = AREA + 0x3000;
    thread.cpu.gpr[reg::RSI] = 2;
    let _ = kernel.handle(
        &mut thread,
        &mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        },
    );
    for call in data.chunks_exact(57).take(64) {
        let selector = call[0];
        let number = if selector < 200 {
            numbers[usize::from(selector) % numbers.len()]
        } else {
            u64::from_le_bytes(call[1..9].try_into().unwrap_or([0; 8]))
        };
        let regs = [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9];
        for (i, r) in regs.iter().enumerate() {
            let at = 9 + i * 8;
            let raw = u64::from_le_bytes(call[at..at + 8].try_into().unwrap_or([0; 8]));
            // Half of the arguments point into mapped memory; the rest are
            // raw values, including huge sizes and addresses.
            thread.cpu.gpr[*r] = if raw & 1 == 0 {
                AREA + (raw >> 1) % (AREA_LEN + 64)
            } else {
                raw
            };
        }
        // A finite input budget bounds copied bytes and file growth in this
        // harness only; the product has no guest file-size quota.
        if matches!(number, 0 | 1 | 89 | 267 | 217) {
            thread.cpu.gpr[reg::RDX] %= AREA_LEN;
        }
        if matches!(number, 76 | 77) {
            thread.cpu.gpr[reg::RSI] %= AREA_LEN;
        }
        if number == 8 {
            thread.cpu.gpr[reg::RSI] =
                ((thread.cpu.gpr[reg::RSI] as i64) % (AREA_LEN as i64)) as u64;
        }
        thread.cpu.gpr[reg::RAX] = number;
        let _ = kernel.handle(
            &mut thread,
            &mem,
            ExitReason::Syscall {
                rip: GuestAddr(0x1000),
            },
        );
    }
    // A syscall/handler context is also finite when fuzzed bytes decode as
    // loops or repeated strings. No host wait occurs inside CPU execution.
    thread.cpu.rip = GuestAddr(AREA);
    if !thread.state.stopped && thread.state.exit_status.is_none() {
        let _ = paludarium_cpu::run(&mut thread.cpu, &mem, 64);
    }
});
