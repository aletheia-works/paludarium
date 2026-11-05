//! What the virtual CPU says of itself, never forwarding the host's: its
//! identity, which is deterministic, and its time stamp counter, which is not.
use std::sync::atomic::{AtomicU64, Ordering};

/// The time stamp counter of the virtual CPU, as `rdtsc` splits it into its low
/// and high 32 bits: it never forwards the host's either. It moves on by each
/// read, so a program that waits for it to change does not wait forever, and it
/// is shared by every thread, as a synchronized counter is, and by every guest
/// in the host process, so its values are not the same from run to run.
pub(crate) fn time_stamp() -> [u32; 2] {
    /// Far from 0, as a counter that has run for a while, and past 32 bits.
    static COUNTER: AtomicU64 = AtomicU64::new(1 << 32);
    /// About what a read takes on real CPUs.
    const STEP: u64 = 32;
    let value = COUNTER.fetch_add(STEP, Ordering::Relaxed);
    [value as u32, (value >> 32) as u32]
}

pub(crate) fn values(leaf: u32, _subleaf: u32) -> [u32; 4] {
    match leaf {
        0 => [
            7,
            u32::from_le_bytes(*b"Palu"),
            u32::from_le_bytes(*b"umVM"),
            u32::from_le_bytes(*b"dari"),
        ],
        0x8000_0000 => [0x8000_0001, 0, 0, 0],
        0x8000_0001 => [0, 0, 0, 1 << 29],
        // Partial target subsets never advertise a complete feature family.
        _ => [0; 4],
    }
}
