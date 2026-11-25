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
    }
    // SAFETY: GetCurrentThread returns a pseudo-handle that needs no closing.
    thread_times(unsafe { GetCurrentThread() })
}
/// The CPU time of the thread `thread` is a handle to.
#[cfg(windows)]
fn thread_times(thread: *mut core::ffi::c_void) -> Result<u64, Errno> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetThreadTimes(
            thread: *mut core::ffi::c_void,
            creation: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
    }
    let (mut creation, mut exit, mut kernel, mut user) = (0, 0, 0, 0);
    // SAFETY: each out pointer is a live, aligned u64 (a FILETIME); a handle
    // that is not a thread's fails the call.
    let ok = unsafe {
        GetThreadTimes(
            thread,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
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
/// The CPU time of one host thread, the one that made it
/// ([`crate::Host::thread_cpu_clock`]), which any thread may read.
pub trait ThreadCpuClock: Send + Sync {
    /// The thread's CPU time in nanoseconds (user and system together);
    /// `None` when the host no longer knows the thread. Only for as long as
    /// the thread lives is the time sure to be its own: a host may give its
    /// number to a new thread, so whoever reads the clock lets go of it
    /// before the thread ends.
    fn read(&self) -> Option<u64>;
}
/// The calling thread's clock. The clock ID names the thread by its ID, not
/// by its `pthread_t`, so that nothing here points at a thread that ended,
/// and `clock_gettime` then gives `EINVAL`.
#[cfg(target_os = "linux")]
pub(crate) fn native_thread_cpu_clock() -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
    struct Clock(libc::clockid_t);
    impl ThreadCpuClock for Clock {
        fn read(&self) -> Option<u64> {
            let mut time = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `time` is a live, aligned timespec the call writes;
            // any clock ID may be passed.
            let r = unsafe { libc::clock_gettime(self.0, &raw mut time) };
            let seconds = u64::try_from(time.tv_sec).ok().filter(|_| r == 0)?;
            seconds
                .checked_mul(1_000_000_000)?
                .checked_add(u64::try_from(time.tv_nsec).ok()?)
        }
    }
    let mut clock = 0;
    // SAFETY: `pthread_self` is the calling thread, which lives, and `clock`
    // a live clock ID the call writes.
    let r = unsafe { libc::pthread_getcpuclockid(libc::pthread_self(), &raw mut clock) };
    (r == 0).then(|| std::sync::Arc::new(Clock(clock)) as _)
}
/// The calling thread's clock: a send right to its port, which names no
/// other thread while it is held (the port of a thread that ended is a dead
/// name, and `thread_info` fails on it).
#[cfg(target_os = "macos")]
pub(crate) fn native_thread_cpu_clock() -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
    // Deprecated in libc, for the `mach2` crate.
    unsafe extern "C" {
        static mach_task_self_: libc::mach_port_t;
        fn mach_thread_self() -> libc::mach_port_t;
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;
    }
    struct Clock(libc::mach_port_t);
    impl ThreadCpuClock for Clock {
        fn read(&self) -> Option<u64> {
            let mut info = core::mem::MaybeUninit::<libc::thread_extended_info>::zeroed();
            let mut count = libc::THREAD_EXTENDED_INFO_COUNT;
            // SAFETY: the buffer holds the `count` words the call may write.
            let r = unsafe {
                libc::thread_info(
                    self.0,
                    libc::THREAD_EXTENDED_INFO as libc::thread_flavor_t,
                    info.as_mut_ptr().cast(),
                    &raw mut count,
                )
            };
            if r != libc::KERN_SUCCESS {
                return None;
            }
            // SAFETY: zeroed, which is valid for its integers, and then
            // filled by the call.
            let info = unsafe { info.assume_init() };
            info.pth_user_time.checked_add(info.pth_system_time)
        }
    }
    impl Drop for Clock {
        fn drop(&mut self) {
            // SAFETY: the right is this value's own, let go of once.
            let _ = unsafe { mach_port_deallocate(mach_task_self_, self.0) };
        }
    }
    // SAFETY: the call has no preconditions, and gives a right to let go of.
    let port = unsafe { mach_thread_self() };
    (port != 0).then(|| std::sync::Arc::new(Clock(port)) as _)
}
/// The calling thread's clock: a handle of its own to it, which names no
/// other thread while it is held, and gives the final times of one that
/// ended.
#[cfg(windows)]
pub(crate) fn native_thread_cpu_clock() -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetCurrentThread() -> *mut core::ffi::c_void;
        fn DuplicateHandle(
            source_process: *mut core::ffi::c_void,
            source: *mut core::ffi::c_void,
            target_process: *mut core::ffi::c_void,
            target: *mut *mut core::ffi::c_void,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
    }
    struct Clock(OwnedHandle);
    impl ThreadCpuClock for Clock {
        fn read(&self) -> Option<u64> {
            thread_times(self.0.as_raw_handle()).ok()
        }
    }
    let mut handle = core::ptr::null_mut();
    // SAFETY: the pseudo-handles need no closing, and `handle` is a live
    // pointer the call writes.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &raw mut handle,
            THREAD_QUERY_LIMITED_INFORMATION,
            0,
            0,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: the new handle is this value's own, closed once by its drop.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    Some(std::sync::Arc::new(Clock(handle)))
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_arch = "wasm32"
)))]
pub(crate) fn native_thread_cpu_clock() -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
    None
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
    let mut waiting = crate::blocked::Waiting::new();
    let mut slept = false;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        let now = native_clock(clock)?;
        if now >= deadline {
            return Ok(WaitOutcome::Complete);
        }
        waiting.sleep();
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

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn a_thread_s_cpu_clock_is_read_by_another_thread_while_it_runs() {
        use std::sync::{Arc, mpsc};
        let stop = Arc::new(AtomicBool::new(false));
        let (send, receive) = mpsc::channel();
        let spinner = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                send.send(native_thread_cpu_clock().unwrap()).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
                native_thread_cpu_time().unwrap()
            }
        });
        let clock = receive.recv().unwrap();
        // It makes no call meanwhile, and its time grows past 50 ms, never
        // back (at most 10 s, for a busy machine).
        let (wall, mut last) = (Instant::now(), clock.read().unwrap());
        let first = last;
        while last - first < 50_000_000 {
            let now = clock.read().unwrap();
            assert!(now >= last, "{now} < {last}");
            last = now;
            assert!(wall.elapsed() < Duration::from_secs(10), "{first} {last}");
            std::thread::sleep(Duration::from_millis(1));
        }
        // This thread's is another.
        let own = native_thread_cpu_clock().unwrap().read().unwrap();
        let time = native_thread_cpu_time().unwrap();
        assert!(time >= own && time - own < 20_000_000, "{own} {time}");
        stop.store(true, Ordering::Relaxed);
        let end = spinner.join().unwrap();
        // Its own last reading is no earlier, but for what the two round
        // (1 us on macOS, a scheduler's tick on Windows).
        assert!(end + 20_000_000 >= last, "{end} {last}");
        // Once it has gone, macOS knows it no more, which a join may be just
        // before, and Windows keeps its last time. Linux may have given its
        // number to another thread already, so it tells nothing then.
        #[cfg(target_os = "macos")]
        while clock.read().is_some() {
            assert!(wall.elapsed() < Duration::from_secs(60));
            std::thread::sleep(Duration::from_millis(1));
        }
        #[cfg(windows)]
        assert!(clock.read().unwrap() >= last);
    }
}
