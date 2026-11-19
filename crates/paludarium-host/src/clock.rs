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
/// The calling thread's slice from `sched_getattr` (Linux 6.12 and later
/// report `se.slice` as `sched_runtime`), and the tick from the resolution
/// of `CLOCK_MONOTONIC_COARSE`.
#[cfg(target_os = "linux")]
pub(crate) fn native_scheduler_slice() -> Option<crate::SchedulerSlice> {
    // struct sched_attr: size, policy, flags, nice, priority, runtime, ...
    let mut attr = [0u64; 7];
    // SAFETY: `attr` is a live, aligned 56-byte buffer, the size passed.
    let r = unsafe { libc::syscall(libc::SYS_sched_getattr, 0, attr.as_mut_ptr(), 56u32, 0u32) };
    let mut resolution = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `resolution` is a live, aligned timespec the call writes.
    let ticked = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC_COARSE, &raw mut resolution) };
    let tick = u64::try_from(resolution.tv_nsec).ok()?;
    (r == 0 && ticked == 0 && attr[3] != 0 && resolution.tv_sec == 0 && tick != 0).then_some(
        crate::SchedulerSlice {
            slice: attr[3],
            tick,
        },
    )
}
#[cfg(not(any(target_os = "linux", target_arch = "wasm32")))]
pub(crate) fn native_scheduler_slice() -> Option<crate::SchedulerSlice> {
    None
}
/// The host's NTP state, from `adjtimex` with no mode, which only reads
/// and needs no privilege. The kernel's `struct __kernel_timex` is read
/// as the bytes it is, so the C library's `struct timex` plays no part.
#[cfg(target_os = "linux")]
pub(crate) fn native_ntp_state() -> Option<crate::NtpState> {
    // 208 bytes, aligned for its longs; `modes` (the first four) is 0.
    let mut timex = [0i64; 26];
    // SAFETY: `timex` is a live, aligned buffer of the 208 bytes the call
    // reads and writes.
    let result = unsafe { libc::syscall(libc::SYS_adjtimex, timex.as_mut_ptr()) };
    let result = i32::try_from(result).ok().filter(|r| *r >= 0)?;
    let word = |at: usize| timex[at / 8];
    // An int field is the low half of its long-sized slot.
    let int = |at: usize| word(at) as i32;
    Some(crate::NtpState {
        result,
        offset: word(8),
        freq: word(16),
        maxerror: word(24),
        esterror: word(32),
        status: int(40),
        constant: word(48),
        precision: word(56),
        tolerance: word(64),
        tick: word(88),
        ppsfreq: word(96),
        jitter: word(104),
        shift: int(112),
        stabil: word(120),
        jitcnt: word(128),
        calcnt: word(136),
        errcnt: word(144),
        stbcnt: word(152),
        tai: int(160),
    })
}
#[cfg(not(any(target_os = "linux", target_arch = "wasm32")))]
pub(crate) fn native_ntp_state() -> Option<crate::NtpState> {
    None
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn native_wait(
    clock: ClockId,
    deadline: u64,
    cancel: &AtomicBool,
) -> Result<WaitOutcome, Errno> {
    let mut slept = false;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        let now = native_clock(clock)?;
        if now >= deadline {
            return Ok(WaitOutcome::Complete);
        }
        crate::switches::sleep(&mut slept);
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
