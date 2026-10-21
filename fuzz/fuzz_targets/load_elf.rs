//! ELF loading must reject or load any file without panicking and must
//! never accept more than 4 GiB of segments.
//!
//! Inputs whose first byte is odd are used as the whole file. Otherwise a
//! valid tiny executable is built in code and the rest of the input is a
//! list of (offset, value) patches, so the fuzzer reaches the checks behind
//! the ELF magic (program headers, segment sizes and addresses) quickly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paludarium_loader::testing::tiny_exec;
use paludarium_loader::{MAX_LOAD_SIZE, STACK_SIZE, StartInfo, load_bytes};
use paludarium_mmu::AddressSpace;

fn input_file(data: &[u8]) -> Vec<u8> {
    match data.split_first() {
        Some((mode, rest)) if mode & 1 == 0 => {
            let mut file = tiny_exec(&[0x90; 32], b"data");
            for patch in rest.chunks_exact(3) {
                let at = usize::from(u16::from_le_bytes([patch[0], patch[1]])) % file.len();
                file[at] = patch[2];
            }
            file
        }
        _ => data.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    let file = input_file(data);
    let argv = [b"prog".to_vec()];
    let envp = [b"A=1".to_vec()];
    let start = StartInfo {
        argv: &argv,
        envp: &envp,
        execfn: b"/prog",
        random: [0; 16],
    };
    let mut mem = AddressSpace::new();
    if load_bytes(&file, &start, &mut mem).is_ok() {
        // Segments (each rounded out to whole pages) plus the stack.
        let loaded: u64 = mem.mappings().map(|m| m.length).sum();
        let segments = u64::try_from(mem.mappings().count()).unwrap_or(u64::MAX);
        assert!(loaded <= MAX_LOAD_SIZE + STACK_SIZE + 2 * 4096 * segments);
    }
});
