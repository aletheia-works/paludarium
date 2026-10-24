#[cfg(not(target_arch = "wasm32"))]
use paludarium_types::Errno;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Clocks required by the guest ABI; values are not host syscall numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockId {
    Realtime,
    Monotonic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    Complete,
    Interrupted,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn native_clock(clock: ClockId) -> Result<u64, Errno> {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let duration = match clock {
        ClockId::Realtime => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Errno::EIO)?,
        ClockId::Monotonic => EPOCH.get_or_init(Instant::now).elapsed(),
    };
    u64::try_from(duration.as_nanos()).map_err(|_| Errno::ERANGE)
}
/// The calling thread's CPU time (user and system together).
#[cfg(unix)]
pub(crate) fn native_thread_cpu_time() -> Result<u64, Errno> {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    u64::try_from(t.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|ns| ns.checked_add(u64::try_from(t.tv_nsec).ok()?))
        .ok_or(Errno::ERANGE)
}
#[cfg(windows)]
pub(crate) fn native_thread_cpu_time() -> Result<u64, Errno> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThread() -> *mut core::ffi::c_void;
        fn GetThreadTimes(
            thread: *mut core::ffi::c_void,
            creation: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
    }
    let (mut creation, mut exit, mut kernel, mut user) = (0, 0, 0, 0);
    // SAFETY: GetCurrentThread returns a pseudo-handle that needs no
    // closing, and each out pointer is a live, aligned u64 (a FILETIME).
    let ok = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return Err(Errno::EIO);
    }
    // FILETIME counts 100-nanosecond intervals.
    kernel
        .checked_add(user)
        .and_then(|t| t.checked_mul(100))
        .ok_or(Errno::ERANGE)
}
#[cfg(not(any(unix, windows, target_arch = "wasm32")))]
pub(crate) fn native_thread_cpu_time() -> Result<u64, Errno> {
    Err(Errno::ENOSYS)
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn native_wait(
    clock: ClockId,
    deadline: u64,
    cancel: &AtomicBool,
) -> Result<WaitOutcome, Errno> {
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        let now = native_clock(clock)?;
        if now >= deadline {
            return Ok(WaitOutcome::Complete);
        }
        std::thread::sleep(Duration::from_nanos((deadline - now).min(10_000_000)));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    #[test]
    fn thread_cpu_time_grows_with_work_and_not_past_wall_time() {
        let (wall, start) = (Instant::now(), native_thread_cpu_time().unwrap());
        // Spin for 30 ms, and on until the clock moves (at most 2 s): Windows
        // charges CPU time at the scheduler ticks (about 15.6 ms) that find
        // the thread running, which a busy machine can let pass without one.
        let (mut x, mut used) = (0u64, 0);
        while wall.elapsed() < Duration::from_millis(30)
            || used == 0 && wall.elapsed() < Duration::from_secs(2)
        {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
            used = native_thread_cpu_time().unwrap() - start;
        }
        let elapsed = u64::try_from(wall.elapsed().as_nanos()).unwrap();
        assert!(used > 0, "{used}");
        // Windows counts in 100 ns ticks of a coarser scheduler clock.
        assert!(used <= elapsed + 20_000_000, "{used} > {elapsed}");
        // Sleeping uses (almost) no CPU time.
        let before = native_thread_cpu_time().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert!(native_thread_cpu_time().unwrap() - before < 20_000_000);
    }
}
