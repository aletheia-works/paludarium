//! The decoder wrapper must accept any byte sequence at any address without
//! panicking. The first 8 bytes choose the instruction address.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paludarium_decoder::decode;
use paludarium_types::GuestAddr;

fuzz_target!(
    init: {
        // iced-x86 builds its decoder tables once per process (lazy_static).
        // Build them before fuzzing so LeakSanitizer does not report that
        // process-lifetime allocation as a per-input leak.
        let _ = decode(&[0x90], GuestAddr(0));
    },
    |data: &[u8]| {
    let (rip, bytes) = match data.split_first_chunk::<8>() {
        Some((rip, rest)) => (u64::from_le_bytes(*rip), rest),
        None => (0, data),
    };
    if let Ok(insn) = decode(bytes, GuestAddr(rip)) {
        assert!(usize::from(insn.len) <= bytes.len());
        let _ = insn.next_rip();
        let _ = insn.operands().count();
    }
    }
);
