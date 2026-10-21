//! wasm thread spike: wait on an address in shared memory in
//! one Worker and wake it from another.
//!
//! The exported functions only touch the shared flag and never use the
//! shadow stack, so two instances (one per Worker) can share the memory
//! without per-instance stack setup.
#![no_std]
// memory.atomic.wait32 / notify intrinsics are still unstable (nightly only).
#![feature(stdarch_wasm_atomic_wait)]

use core::sync::atomic::{AtomicI32, Ordering};

/// The word both Workers use. Lives in the shared linear memory.
static FLAG: AtomicI32 = AtomicI32::new(0);

/// Address of the shared word.
#[unsafe(no_mangle)]
pub extern "C" fn flag_address() -> *const AtomicI32 {
    &FLAG
}

/// Current value of the shared word.
#[unsafe(no_mangle)]
pub extern "C" fn flag_value() -> i32 {
    FLAG.load(Ordering::SeqCst)
}

/// Sets the shared word to 0 (before a new round).
#[unsafe(no_mangle)]
pub extern "C" fn reset() {
    FLAG.store(0, Ordering::SeqCst);
}

/// Waits while the shared word equals `expected`, at most `timeout_ns`
/// nanoseconds. Returns 0 when woken, 1 when the value already differed,
/// 2 on timeout (the `memory.atomic.wait32` result).
#[unsafe(no_mangle)]
pub extern "C" fn wait_while_equal(expected: i32, timeout_ns: i64) -> i32 {
    // SAFETY: FLAG is a valid, 4-byte aligned i32 in this module's linear
    // memory; `memory_atomic_wait32` only reads it atomically.
    unsafe { core::arch::wasm32::memory_atomic_wait32(FLAG.as_ptr(), expected, timeout_ns) }
}

/// Stores `value` into the shared word and wakes every waiter. Returns the
/// number of waiters woken.
#[unsafe(no_mangle)]
pub extern "C" fn store_and_notify(value: i32) -> u32 {
    FLAG.store(value, Ordering::SeqCst);
    // SAFETY: FLAG is a valid, 4-byte aligned i32 in the shared memory.
    unsafe { core::arch::wasm32::memory_atomic_notify(FLAG.as_ptr(), u32::MAX) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
