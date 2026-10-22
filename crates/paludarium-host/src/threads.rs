//! Native worker and ticket lifetime boundary. No guest pointer reaches the OS.
use crate::{ClockId, Host, WaitOutcome};
use paludarium_types::Errno;
use std::sync::{
    Mutex, PoisonError,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

pub trait ThreadHandle: Send {
    /// Reclaims the worker. Panic is reported as a host error.
    fn join(self: Box<Self>) -> Result<(), Errno>;
}

#[derive(Default)]
pub struct WaitToken {
    state: AtomicU32,
    gate: Mutex<()>,
    #[cfg(not(target_arch = "wasm32"))]
    changed: std::sync::Condvar,
}
impl WaitToken {
    #[must_use]
    pub fn value(&self) -> u32 {
        self.state.load(Ordering::SeqCst)
    }
    pub fn notify(&self) {
        let _gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        self.state.fetch_add(1, Ordering::SeqCst);
        #[cfg(not(target_arch = "wasm32"))]
        self.changed.notify_all();
        #[cfg(target_arch = "wasm32")]
        // SAFETY: this host-owned AtomicU32 remains aligned and live for the
        // whole call. It is a retained ticket, never a guest address.
        unsafe {
            core::arch::wasm32::memory_atomic_notify(self.state.as_ptr().cast(), u32::MAX);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeThread(std::thread::JoinHandle<()>);
#[cfg(not(target_arch = "wasm32"))]
impl ThreadHandle for NativeThread {
    fn join(self: Box<Self>) -> Result<(), Errno> {
        self.0.join().map_err(|_| Errno::EIO)
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(task: Box<dyn FnOnce() + Send>) -> Result<Box<dyn ThreadHandle>, Errno> {
    std::thread::Builder::new()
        .spawn(task)
        .map(|h| Box::new(NativeThread(h)) as Box<dyn ThreadHandle>)
        .map_err(|_| Errno::EAGAIN)
}
#[cfg(target_arch = "wasm32")]
pub fn spawn(_task: Box<dyn FnOnce() + Send>) -> Result<Box<dyn ThreadHandle>, Errno> {
    Err(Errno::ENOSYS)
}

/// Waits in real time, at most `nanos`, for `token` to leave `expected`.
pub(crate) fn wait_briefly(token: &WaitToken, expected: u32, nanos: u64) {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: as in `wait`, the borrowed token pins its aligned AtomicU32.
    unsafe {
        core::arch::wasm32::memory_atomic_wait32(
            token.state.as_ptr().cast(),
            expected as i32,
            nanos as i64,
        );
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let gate = token.gate.lock().unwrap_or_else(PoisonError::into_inner);
        if token.value() == expected {
            let _ = token
                .changed
                .wait_timeout(gate, std::time::Duration::from_nanos(nanos))
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}
pub fn wait<H: Host + ?Sized>(
    host: &H,
    token: &WaitToken,
    expected: u32,
    deadline: Option<(ClockId, u64)>,
    cancel: &AtomicBool,
) -> Result<WaitOutcome, Errno> {
    #[cfg(target_arch = "wasm32")]
    {
        loop {
            if token.value() != expected {
                return Ok(WaitOutcome::Complete);
            }
            if cancel.load(Ordering::SeqCst) {
                return Ok(WaitOutcome::Interrupted);
            }
            let remaining = match deadline {
                Some((clock, end)) => {
                    let now = host.clock(clock)?;
                    if now >= end {
                        return Ok(WaitOutcome::Complete);
                    }
                    end - now
                }
                None => 10_000_000,
            };
            // SAFETY: borrowed WaitToken pins its host-owned aligned AtomicU32.
            // No Rust lock is held during the bounded wait. Only atomics
            // access the word; cancellation is checked every ten milliseconds.
            unsafe {
                core::arch::wasm32::memory_atomic_wait32(
                    token.state.as_ptr().cast(),
                    expected as i32,
                    remaining.min(10_000_000) as i64,
                );
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut gate = token.gate.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if token.value() != expected {
                return Ok(WaitOutcome::Complete);
            }
            if cancel.load(Ordering::SeqCst) {
                return Ok(WaitOutcome::Interrupted);
            }
            let remaining = match deadline {
                Some((clock, end)) => {
                    let now = host.clock(clock)?;
                    if now >= end {
                        return Ok(WaitOutcome::Complete);
                    }
                    end - now
                }
                None => 10_000_000,
            };
            // Bounded polling also observes signal/kill cancellation without a ticket wake.
            gate = token
                .changed
                .wait_timeout(
                    gate,
                    std::time::Duration::from_nanos(remaining.min(10_000_000)),
                )
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}
