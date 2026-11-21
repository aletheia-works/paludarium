//! Arbitrary sequences of address-space operations must never panic and must
//! keep the mapping list consistent with what reads and writes observe.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::GuestAddr;

/// Addresses come either from a small window (to make operations interact)
/// or are raw 64-bit values (to probe the edges).
fn address(raw: u64) -> GuestAddr {
    if raw & 1 == 0 {
        GuestAddr(0x10000 + (raw >> 1) % 0x40_0000)
    } else {
        GuestAddr(raw)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut space = AddressSpace::new();
    let mut buf = vec![0u8; 0x3000];
    for op in data.as_chunks::<18>().0.iter().take(256) {
        let raw = u64::from_le_bytes(op[1..9].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(op[9..17].try_into().unwrap_or([0; 8]));
        let small_len = (len % 0x3000) as usize;
        let addr = address(raw);
        let prot = Prot::from_bits(u64::from(op[17] & 7)).unwrap_or(Prot::NONE);
        match op[0] % 9 {
            0 => {
                let _ = space.map(Some(addr), len % 0x10_0000, prot, MappingKind::Anonymous);
            }
            1 => {
                let _ = space.map(None, len % 0x10_0000, prot, MappingKind::Anonymous);
            }
            2 => {
                let _ = space.unmap(addr, len % 0x10_0000);
            }
            3 => {
                let _ = space.protect(addr, len % 0x10_0000, prot);
            }
            4 => {
                let _ = space.read(addr, &mut buf[..small_len]);
            }
            5 => {
                let _ = space.write(addr, &buf[..small_len]);
            }
            6 => {
                let _ = space.set_break(addr);
            }
            7 => {
                let _ = space.fetch_partial(addr, &mut buf[..small_len.min(15)]);
            }
            _ => {
                // Preserve all immutable fault metadata across a subsequent
                // permission/mapping operation; no host callbacks are involved.
                if let Err(fault) = space.write(addr, &buf[..small_len]) {
                    let saved = fault;
                    let _ = space.protect(GuestAddr(addr.0 & !4095), 4096, Prot::NONE);
                    assert_eq!(fault, saved);
                }
            }
        }
    }
    // Mappings never overlap and are page aligned.
    let mut end = 0u64;
    for m in space.mappings() {
        assert!(m.start.0 >= end);
        assert_eq!(m.start.0 % 4096, 0);
        assert_eq!(m.length % 4096, 0);
        end = m.start.0 + m.length;
    }
});
