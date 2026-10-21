//! Typed atomics interacting with ordinary accesses and mapping changes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use paludarium_mmu::{AddressSpace, AtomicOp, AtomicWidth, MappingKind, Prot};
use paludarium_types::GuestAddr;
fuzz_target!(|data: &[u8]| {
    let memory = AddressSpace::new();
    let _ = memory.map_shared(
        Some(GuestAddr(0x10000)),
        8192,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    );
    for bytes in data.chunks_exact(18).take(256) {
        let address =
            GuestAddr(0x10000 + u64::from(u16::from_le_bytes([bytes[1], bytes[2]])) % 0x3000);
        let value = u64::from_le_bytes(bytes[3..11].try_into().unwrap_or([0; 8]));
        let width = match bytes[11] % 5 {
            0 => AtomicWidth::W8,
            1 => AtomicWidth::W16,
            2 => AtomicWidth::W32,
            3 => AtomicWidth::W64,
            _ => AtomicWidth::W128,
        };
        let operation = match bytes[12] % 9 {
            0 => AtomicOp::Exchange(u128::from(value)),
            1 => AtomicOp::CompareExchange {
                expected: u128::from(value),
                replacement: u128::from(!value),
            },
            2 => AtomicOp::Add(u128::from(value)),
            3 => AtomicOp::Sub(u128::from(value)),
            4 => AtomicOp::And(u128::from(value)),
            5 => AtomicOp::Or(u128::from(value)),
            6 => AtomicOp::Xor(u128::from(value)),
            7 => AtomicOp::Not,
            _ => AtomicOp::Neg,
        };
        match bytes[0] % 6 {
            0 => {
                let _ = memory.atomic(address, width, operation);
            }
            1 => {
                let _ = memory.write_u64(address, value);
            }
            2 => {
                let _ = memory.read_u64(address);
            }
            3 => {
                let _ = memory.protect_shared(
                    GuestAddr(address.0 & !4095),
                    4096,
                    if bytes[13] & 1 == 0 {
                        Prot::READ
                    } else {
                        Prot::READ_WRITE
                    },
                );
            }
            4 => {
                let _ = memory.unmap_shared(GuestAddr(address.0 & !4095), 4096);
            }
            _ => {
                let _ = memory.map_shared(
                    Some(GuestAddr(address.0 & !4095)),
                    4096,
                    Prot::READ_WRITE,
                    MappingKind::Anonymous,
                );
            }
        }
    }
});
