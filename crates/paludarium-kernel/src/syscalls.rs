//! System-call handlers of the core emulator (plus `mprotect`, which the Rust
//! hello world calls natively).
//!
//! Every handler validates its arguments and reads or writes guest memory
//! only through the MMU; bad pointers give `-EFAULT`.

use std::collections::BTreeMap;

use paludarium_cpu::CpuState;
use paludarium_host::{ClockId, FileHandle, Host, WaitOutcome};
use paludarium_mmu::{AddressSpace, MappingKind, Prot, Remap};
use paludarium_types::{Errno, GuestAddr, USER_ADDRESS_LIMIT};

use crate::{AltStack, SS_DISABLE, SignalAction, ThreadState, credentials, signals};

/// Linux x86-64 system-call numbers used by the core emulator.
pub mod nr {
    pub const SETITIMER: u64 = 38;
    pub const RT_SIGRETURN: u64 = 15;
    pub const GETPID: u64 = 39;
    pub const KILL: u64 = 62;
    pub const GETTID: u64 = 186;
    pub const TKILL: u64 = 200;
    pub const TGKILL: u64 = 234;
    pub const WRITE: u64 = 1;
    pub const POLL: u64 = 7;
    pub const RESTART_SYSCALL: u64 = 219;
    pub const SELECT: u64 = 23;
    pub const PSELECT6: u64 = 270;
    pub const PPOLL: u64 = 271;
    pub const NANOSLEEP: u64 = 35;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const GETTIMEOFDAY: u64 = 96;
    pub const TIME: u64 = 201;
    pub const CLOCK_NANOSLEEP: u64 = 230;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const SOCKET: u64 = 41;
    pub const EXIT: u64 = 60;
    pub const SIGALTSTACK: u64 = 131;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const EXIT_GROUP: u64 = 231;
    pub const MREMAP: u64 = 25;
    pub const GETRUSAGE: u64 = 98;
    pub const TIMES: u64 = 100;
    pub const CLOCK_GETRES: u64 = 229;
    pub const MSYNC: u64 = 26;
    pub const MADVISE: u64 = 28;
    pub const MINCORE: u64 = 27;
    pub const MLOCK: u64 = 149;
    pub const MUNLOCK: u64 = 150;
    pub const MLOCKALL: u64 = 151;
    pub const MUNLOCKALL: u64 = 152;
    pub const MLOCK2: u64 = 325;
    pub const SET_ROBUST_LIST: u64 = 273;
    pub const GET_ROBUST_LIST: u64 = 274;
    pub const UNAME: u64 = 63;
    pub const GETUID: u64 = 102;
    pub const SETUID: u64 = 105;
    pub const SETGID: u64 = 106;
    pub const SETREUID: u64 = 113;
    pub const SETREGID: u64 = 114;
    pub const SETGROUPS: u64 = 116;
    pub const CAPGET: u64 = 125;
    pub const CAPSET: u64 = 126;
    pub const SETRESUID: u64 = 117;
    pub const GETRESUID: u64 = 118;
    pub const SETRESGID: u64 = 119;
    pub const GETRESGID: u64 = 120;
    pub const SETFSUID: u64 = 122;
    pub const SETFSGID: u64 = 123;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const SCHED_SETAFFINITY: u64 = 203;
    pub const MBIND: u64 = 237;
    pub const SET_MEMPOLICY: u64 = 238;
    pub const GET_MEMPOLICY: u64 = 239;
    pub const SCHED_GETAFFINITY: u64 = 204;
    pub const GETCPU: u64 = 309;
    pub const PERSONALITY: u64 = 135;
    pub const SCHED_GETPARAM: u64 = 143;
    pub const SCHED_GETSCHEDULER: u64 = 145;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 146;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 147;
    pub const SCHED_RR_GET_INTERVAL: u64 = 148;
    pub const MEMBARRIER: u64 = 324;
    pub const SCHED_YIELD: u64 = 24;
    pub const SYSINFO: u64 = 99;
    pub const GETGROUPS: u64 = 115;
    pub const TIMER_CREATE: u64 = 222;
    pub const TIMER_SETTIME: u64 = 223;
    pub const TIMER_GETTIME: u64 = 224;
    pub const TIMER_GETOVERRUN: u64 = 225;
    pub const TIMER_DELETE: u64 = 226;
    pub const RT_SIGTIMEDWAIT: u64 = 128;
    pub const PAUSE: u64 = 34;
    pub const RT_SIGSUSPEND: u64 = 130;
    pub const RT_SIGPENDING: u64 = 127;
    pub const TIMERFD_CREATE: u64 = 283;
    pub const TIMERFD_SETTIME: u64 = 286;
    pub const TIMERFD_GETTIME: u64 = 287;
}

pub(crate) struct Context<'a> {
    /// The system call's number, from the low 32 bits of `rax`: handlers
    /// that serve several numbers read it here, never from the register.
    pub number: u64,
    pub files: &'a mut crate::files::Files,
    pub host: &'a dyn Host,
    /// The same host, for files that keep it (a timerfd reads its clock).
    pub shared_host: &'a std::sync::Arc<dyn Host>,
    pub process: &'a mut ThreadState,
    /// The calling thread's ID.
    pub tid: u32,
    pub cpu: &'a mut CpuState,
    pub mem: &'a AddressSpace,
    pub cancellation: &'a std::sync::atomic::AtomicBool,
    pub inbox: &'a crate::SignalInbox,
    pub group: &'a crate::ThreadGroup,
    pub processes: &'a std::sync::Arc<crate::processes::Processes>,
}

pub(crate) enum Outcome {
    Return(u64),
    Exit(i32),
    Restored,
    BadFrame,
}

type Handler = fn(&mut Context<'_>, [u64; 6]) -> Outcome;

/// The explicit dispatch table. Numbers missing from it get `-ENOSYS`.
pub struct SyscallTable {
    handlers: BTreeMap<u64, Handler>,
}

impl SyscallTable {
    /// The core table.
    #[must_use]
    pub fn u1() -> Self {
        let entries: [(u64, Handler); 76] = [
            (nr::SETITIMER, sys_setitimer),
            (nr::RT_SIGRETURN, sys_rt_sigreturn),
            (nr::GETPID, sys_getpid),
            (nr::GETTID, sys_getpid),
            (nr::TKILL, sys_tkill),
            (nr::TGKILL, sys_tgkill),
            (nr::CLOCK_GETTIME, sys_clock_gettime),
            (nr::GETTIMEOFDAY, sys_gettimeofday),
            (nr::TIME, sys_time),
            (nr::NANOSLEEP, sys_nanosleep),
            (nr::CLOCK_NANOSLEEP, sys_clock_nanosleep),
            (nr::WRITE, sys_write),
            (nr::POLL, sys_poll),
            (nr::RESTART_SYSCALL, sys_restart_syscall),
            (nr::PPOLL, sys_ppoll),
            (nr::SELECT, sys_select),
            (nr::PSELECT6, sys_pselect6),
            (nr::MMAP, sys_mmap),
            (nr::MPROTECT, sys_mprotect),
            (nr::MUNMAP, sys_munmap),
            (nr::BRK, sys_brk),
            (nr::RT_SIGACTION, sys_rt_sigaction),
            (nr::RT_SIGPROCMASK, sys_rt_sigprocmask),
            (nr::IOCTL, sys_ioctl),
            (nr::EXIT, sys_exit),
            (nr::SIGALTSTACK, sys_sigaltstack),
            (nr::ARCH_PRCTL, sys_arch_prctl),
            (nr::SET_TID_ADDRESS, sys_set_tid_address),
            (nr::EXIT_GROUP, sys_exit_group),
            (nr::MREMAP, sys_mremap),
            (nr::MSYNC, sys_msync),
            (nr::MADVISE, sys_madvise),
            (nr::MINCORE, sys_mincore),
            (nr::MLOCK, sys_mlock),
            (nr::MUNLOCK, sys_munlock),
            (nr::MLOCK2, sys_mlock2),
            (nr::MLOCKALL, sys_mlockall),
            (nr::MUNLOCKALL, sys_munlockall),
            (nr::SET_ROBUST_LIST, sys_set_robust_list),
            (nr::GET_ROBUST_LIST, sys_get_robust_list),
            (nr::UNAME, sys_uname),
            (nr::GETUID, credentials::sys_getuid),
            (nr::GETGID, credentials::sys_getgid),
            (nr::GETEUID, credentials::sys_geteuid),
            (nr::GETEGID, credentials::sys_getegid),
            (nr::SCHED_SETAFFINITY, sys_sched_setaffinity),
            (nr::SCHED_GETAFFINITY, sys_sched_getaffinity),
            (nr::GETCPU, sys_getcpu),
            (nr::PERSONALITY, sys_personality),
            (nr::SCHED_GETPARAM, sys_sched_getparam),
            (nr::SCHED_GETSCHEDULER, sys_sched_getscheduler),
            (nr::SCHED_GET_PRIORITY_MAX, sys_sched_get_priority),
            (nr::SCHED_GET_PRIORITY_MIN, sys_sched_get_priority),
            (nr::SCHED_RR_GET_INTERVAL, sys_sched_rr_get_interval),
            (nr::MEMBARRIER, sys_membarrier),
            (nr::MBIND, crate::mempolicy::sys_mbind),
            (nr::SET_MEMPOLICY, crate::mempolicy::sys_set_mempolicy),
            (nr::GET_MEMPOLICY, crate::mempolicy::sys_get_mempolicy),
            (nr::SCHED_YIELD, sys_sched_yield),
            (nr::SYSINFO, sys_sysinfo),
            (nr::GETRUSAGE, sys_getrusage),
            (nr::TIMES, sys_times),
            (nr::CLOCK_GETRES, sys_clock_getres),
            (nr::GETGROUPS, credentials::sys_getgroups),
            (nr::TIMER_CREATE, sys_timer_create),
            (nr::TIMER_SETTIME, sys_timer_settime),
            (nr::TIMER_GETTIME, sys_timer_gettime),
            (nr::TIMER_GETOVERRUN, sys_timer_getoverrun),
            (nr::TIMER_DELETE, sys_timer_delete),
            (nr::RT_SIGTIMEDWAIT, sys_rt_sigtimedwait),
            (nr::PAUSE, sys_pause),
            (nr::RT_SIGSUSPEND, sys_rt_sigsuspend),
            (nr::RT_SIGPENDING, sys_rt_sigpending),
            (nr::TIMERFD_CREATE, crate::timerfd::sys_timerfd_create),
            (nr::TIMERFD_SETTIME, crate::timerfd::sys_timerfd_settime),
            (nr::TIMERFD_GETTIME, crate::timerfd::sys_timerfd_gettime),
        ];
        let mut handlers: BTreeMap<u64, Handler> = entries.into_iter().collect();
        for number in crate::files::NUMBERS {
            handlers.insert(*number, crate::files::dispatch);
        }
        let ids: [(u64, Handler); 13] = [
            (nr::SETUID, credentials::sys_setuid),
            (nr::SETGID, credentials::sys_setgid),
            (nr::SETREUID, credentials::sys_setreuid),
            (nr::SETREGID, credentials::sys_setregid),
            (nr::SETGROUPS, credentials::sys_setgroups),
            (nr::CAPGET, credentials::sys_capget),
            (nr::CAPSET, credentials::sys_capset),
            (nr::SETRESUID, credentials::sys_setresuid),
            (nr::GETRESUID, credentials::sys_getresuid),
            (nr::SETRESGID, credentials::sys_setresgid),
            (nr::GETRESGID, credentials::sys_getresgid),
            (nr::SETFSUID, credentials::sys_setfsuid),
            (nr::SETFSGID, credentials::sys_setfsgid),
        ];
        handlers.extend(ids);
        handlers.insert(290, crate::events::dispatch);
        handlers.insert(153, crate::pty::sys_vhangup);
        handlers.insert(282, crate::signalfd::sys_signalfd);
        handlers.insert(289, crate::signalfd::sys_signalfd4);
        // Tokio's current Linux std uses GRND_INSECURE to seed its scheduler;
        // the Host random boundary supplies secure bytes without OS passthrough.
        handlers.insert(318, sys_getrandom);
        handlers.insert(444, |c, a| {
            Outcome::Return(
                crate::landlock::sys_create_ruleset(c, a).unwrap_or_else(Errno::to_syscall_return),
            )
        });
        handlers.insert(445, |c, a| {
            Outcome::Return(
                crate::landlock::sys_add_rule(c, a).unwrap_or_else(Errno::to_syscall_return),
            )
        });
        handlers.insert(446, |c, a| {
            Outcome::Return(
                crate::landlock::sys_restrict_self(c, a).unwrap_or_else(Errno::to_syscall_return),
            )
        });
        for number in [213, 233, 232, 281, 291] {
            handlers.insert(number, crate::epoll::dispatch);
        }
        for number in [
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288,
        ] {
            handlers.insert(number, crate::sockets::dispatch);
        }
        SyscallTable { handlers }
    }

    pub(crate) fn get(&self, number: u64) -> Option<Handler> {
        self.handlers.get(&number).copied()
    }

    /// Whether `number` is implemented.
    #[must_use]
    pub fn contains(&self, number: u64) -> bool {
        self.handlers.contains_key(&number)
    }

    /// The implemented numbers in ascending order.
    pub fn numbers(&self) -> impl Iterator<Item = u64> + '_ {
        self.handlers.keys().copied()
    }
}

pub(crate) fn ok(value: u64) -> Outcome {
    Outcome::Return(value)
}

fn sys_getrandom(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| {
        if a[2] & !7 != 0 {
            return Err(Errno::EINVAL);
        }
        let len = usize::try_from(a[1].min(0x7fff_f000)).map_err(|_| Errno::EINVAL)?;
        c.mem
            .check_write(GuestAddr(a[0]), len)
            .map_err(|_| Errno::EFAULT)?;
        let mut bytes = [0u8; 256];
        let mut done = 0;
        while done < len {
            let count = bytes.len().min(len - done);
            c.host
                .random_bytes(&mut bytes[..count])
                .map_err(|_| Errno::EIO)?;
            c.mem
                .write(
                    GuestAddr(a[0].checked_add(done as u64).ok_or(Errno::EFAULT)?),
                    &bytes[..count],
                )
                .map_err(|_| Errno::EFAULT)?;
            done += count;
        }
        Ok(done as u64)
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

pub(crate) fn err(e: Errno) -> Outcome {
    Outcome::Return(e.to_syscall_return())
}

fn clock_id(id: u64) -> Result<ClockId, Errno> {
    match id {
        0 => Ok(ClockId::Realtime),
        1 => Ok(ClockId::Monotonic),
        _ => Err(Errno::EINVAL),
    }
}
fn read_timespec(mem: &AddressSpace, addr: u64) -> Result<u64, Errno> {
    let words = read_words::<2>(mem, addr)?;
    let sec = words[0] as i64;
    let nsec = words[1] as i64;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64)
        .min(i64::MAX as u64))
}
fn write_timespec(mem: &AddressSpace, addr: u64, nanos: u64) -> Result<(), Errno> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    bytes[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    mem.write(GuestAddr(addr), &bytes)
        .map_err(|_| Errno::EFAULT)
}
/// What a `clockid_t` reads: a host clock, or this process's or thread's
/// CPU time. MONOTONIC_RAW, the coarse clocks, BOOTTIME (this host never
/// suspends), the two alarm clocks and TAI (with a TAI offset of 0, as
/// Linux has until NTP sets one) read the monotonic and real-time clocks.
enum GuestClock {
    Host(ClockId),
    ProcessCpu,
    ThreadCpu,
}
fn guest_clock(id: u64) -> Result<GuestClock, Errno> {
    Ok(match id {
        0 | 5 | 8 | 11 => GuestClock::Host(ClockId::Realtime),
        1 | 4 | 6 | 7 | 9 => GuestClock::Host(ClockId::Monotonic),
        2 => GuestClock::ProcessCpu,
        3 => GuestClock::ThreadCpu,
        _ => return Err(Errno::EINVAL),
    })
}
fn read_clock(c: &mut Context<'_>, clock: GuestClock) -> Result<u64, Errno> {
    let thread = crate::account_cpu(c.host, c.group, c.process);
    match clock {
        GuestClock::Host(id) => c.host.clock(id),
        GuestClock::ProcessCpu => Ok(c.group.process_cpu()),
        GuestClock::ThreadCpu => Ok(thread),
    }
}
fn sys_clock_gettime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = guest_clock(a[0])
        .and_then(|clock| read_clock(c, clock))
        .and_then(|value| write_timespec(c.mem, a[1], value));
    match result {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}
/// `gettimeofday(tv, tz)`: the real time clock in microseconds, and a time zone
/// of UTC, as nothing sets another; either may be null.
fn sys_gettimeofday(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = read_clock(c, GuestClock::Host(ClockId::Realtime)).and_then(|now| {
        if a[0] != 0 {
            let seconds = now / 1_000_000_000;
            let micros = now % 1_000_000_000 / 1000;
            let bytes = [seconds.to_le_bytes(), micros.to_le_bytes()].concat();
            c.mem
                .write(GuestAddr(a[0]), &bytes)
                .map_err(|_| Errno::EFAULT)?;
        }
        if a[1] != 0 {
            c.mem
                .write(GuestAddr(a[1]), &[0; 8])
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(())
    });
    match result {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}
/// `time(t)`: the real time clock in seconds, also at `t` if it is not null.
fn sys_time(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = read_clock(c, GuestClock::Host(ClockId::Realtime)).and_then(|now| {
        let seconds = now / 1_000_000_000;
        if a[0] != 0 {
            c.mem
                .write(GuestAddr(a[0]), &seconds.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(seconds)
    });
    match result {
        Ok(seconds) => ok(seconds),
        Err(e) => err(e),
    }
}
/// `clock_getres`: 1 ns for every clock, as Linux's high-resolution timers
/// give, except the coarse ones, which tick with the scheduler (4 ms here).
fn sys_clock_getres(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = guest_clock(a[0]).and_then(|_| {
        if a[1] == 0 {
            return Ok(());
        }
        let resolution = if matches!(a[0], 5 | 6) { 4_000_000 } else { 1 };
        write_timespec(c.mem, a[1], resolution)
    });
    match result {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}
fn sleep(c: &mut Context<'_>, clock: ClockId, absolute: bool, req: u64, rem: u64) -> Outcome {
    let request = match read_timespec(c.mem, req) {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let now = match c.host.clock(clock) {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let deadline = if absolute {
        request
    } else {
        now.saturating_add(request).min(i64::MAX as u64)
    };
    sleep_until(c, clock, absolute, deadline, rem)
}

/// Sleeps on `clock` until `deadline`. A signal ends it with EINTR, writing
/// the time left to `rem` for a relative sleep; a stop then resumes it, as
/// Linux does: a relative sleep through `restart_syscall` with the same
/// deadline, an absolute one by running the call again.
fn sleep_until(
    c: &mut Context<'_>,
    clock: ClockId,
    absolute: bool,
    deadline: u64,
    rem: u64,
) -> Outcome {
    loop {
        let timer_generation = c.group.timer_generation();
        let clock_now = match c.host.clock(clock) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        let mono_now = match c.host.clock(ClockId::Monotonic) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        // Expiring the timers also takes in the process's signals, which
        // clears the wake the wait watches: a signal already taken in ends
        // the sleep before it starts, as Linux's do_nanosleep finds it
        // pending when it schedules.
        c.group.expire_timer(c.process, mono_now);
        let result = if ends_sleep(c.process) || c.group.status().is_some() {
            Ok(WaitOutcome::Interrupted)
        } else {
            let timer_deadline = signals::next_deadline(c.process)
                .and_then(|d| clock_now.checked_add(d.saturating_sub(mono_now)));
            let next = timer_deadline.map_or(deadline, |t| deadline.min(t));
            c.host.wait_until(clock, next, c.cancellation)
        };
        let received = c.inbox.drain(c.process);
        c.group.drain_process(c.process);
        let interrupted = received.interrupted
            || (!c.inbox.owns_wake(c.cancellation)
                && c.cancellation.load(std::sync::atomic::Ordering::SeqCst));
        if let Ok(now) = c.host.clock(ClockId::Monotonic) {
            c.group.expire_timer(c.process, now);
        }
        let pending = ends_sleep(c.process);
        match result {
            Ok(_)
                if !pending
                    && c.group.status().is_none()
                    && !interrupted
                    && (received.timer_changed
                        || c.group.timer_generation() != timer_generation) =>
            {
                continue;
            }
            Ok(WaitOutcome::Interrupted)
                if received.signals && !pending && !interrupted && c.group.status().is_none() =>
            {
                continue;
            }
            Ok(WaitOutcome::Complete) if !pending && !interrupted && c.group.status().is_none() => {
                if c.host.clock(clock).is_ok_and(|now| now < deadline) {
                    continue;
                }
                return ok(0);
            }
            Ok(WaitOutcome::Complete) | Ok(WaitOutcome::Interrupted) => {
                if !absolute && rem != 0 {
                    let now = c.host.clock(clock).unwrap_or(deadline);
                    if let Err(e) = write_timespec(c.mem, rem, deadline.saturating_sub(now)) {
                        return err(e);
                    }
                }
                if absolute {
                    // ERESTARTNOHAND: the same call, with the same deadline.
                    c.process.restart = Some(nr::CLOCK_NANOSLEEP);
                } else {
                    c.process.restart = Some(nr::RESTART_SYSCALL);
                    c.process.restart_block = Some(signals::RestartBlock::Sleep {
                        clock,
                        deadline,
                        rem,
                    });
                }
                return err(Errno(4));
            }
            Err(e) => return err(e),
        }
    }
}
/// Whether a signal pending for the thread ends a sleep: one it does not
/// block and does not ignore, by its action or by default.
fn ends_sleep(process: &ThreadState) -> bool {
    process.pending.iter().any(|s| {
        process.signal_mask & (1u64 << (s.number - 1)) == 0
            && process.signal_actions.get(&s.number).is_none_or(|a| {
                a.handler != 1 && (a.handler != 0 || !matches!(s.number, 17 | 18 | 23 | 28))
            })
            && (process.signal_actions.contains_key(&s.number)
                || !matches!(s.number, 17 | 18 | 23 | 28))
    })
}
fn read_timeval(sec: u64, usec: u64) -> Result<u64, Errno> {
    if (sec as i64) < 0 || usec >= 1_000_000 {
        return Err(Errno::EINVAL);
    }
    sec.checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(usec * 1000))
        .ok_or(Errno::EINVAL)
}
fn sys_setitimer(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[0] != 0 {
        return err(Errno::EINVAL);
    }
    let words = if a[1] == 0 {
        [0; 4]
    } else {
        match read_words::<4>(c.mem, a[1]) {
            Ok(w) => w,
            Err(e) => return err(e),
        }
    };
    let interval = match read_timeval(words[0], words[1]) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let value = match read_timeval(words[2], words[3]) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let now = match c.host.clock(ClockId::Monotonic) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let deadline = if value == 0 {
        None
    } else {
        match now.checked_add(value) {
            Some(v) => Some(v),
            None => return err(Errno::EINVAL),
        }
    };
    if a[2] != 0 {
        let old = c.process.timer;
        let remaining = old.deadline.unwrap_or(now).saturating_sub(now);
        if let Err(e) = write_words(
            c.mem,
            a[2],
            &[
                old.interval / 1_000_000_000,
                old.interval % 1_000_000_000 / 1000,
                remaining / 1_000_000_000,
                remaining % 1_000_000_000 / 1000,
            ],
        ) {
            return err(e);
        }
    }
    c.process.timer = signals::RealTimer { deadline, interval };
    ok(0)
}
const SIGEV_SIGNAL: u32 = 0;
const SIGEV_NONE: u32 = 1;
const SIGEV_THREAD: u32 = 2;
const SIGEV_THREAD_ID: u32 = 4;
const TIMER_ABSTIME: u64 = 1;

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// `timer_create(clock, sevp, timerid)`. CLOCK_REALTIME and CLOCK_MONOTONIC
/// (and CLOCK_BOOTTIME, which never sleeps here) are supported, notified by
/// a signal to the process or (SIGEV_THREAD_ID) to one of its threads, or not
/// at all; CPU-time clocks give EINVAL. The kernel treats SIGEV_THREAD, which
/// the C library implements itself, as SIGEV_SIGNAL.
fn sys_timer_create(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let realtime = match a[0] {
            0 => true,
            1 | 7 => false,
            _ => return Err(Errno::EINVAL),
        };
        let (signal, value, thread) = if a[1] == 0 {
            (Some(14), None, None) // SIGALRM, with the timer ID as its value
        } else {
            // Linux copies the whole 64-byte struct sigevent.
            c.mem
                .check_read(GuestAddr(a[1]), 64)
                .map_err(|_| Errno::EFAULT)?;
            let [value, word, tid] = read_words::<3>(c.mem, a[1])?;
            let (number, notify) = (word as u32 as i32, (word >> 32) as u32);
            // good_sigevent: the thread must be in this thread group, then the
            // signal must be valid.
            let thread = (notify == SIGEV_THREAD_ID)
                .then(|| u32::try_from(tid as u32 as i32).ok())
                .map(|tid| {
                    tid.filter(|&tid| c.group.has_member(tid))
                        .ok_or(Errno::EINVAL)
                })
                .transpose()?;
            match notify {
                SIGEV_SIGNAL | SIGEV_THREAD | SIGEV_THREAD_ID if (1..=64).contains(&number) => {
                    (Some(number), Some(value), thread)
                }
                SIGEV_NONE => (None, Some(value), None),
                _ => return Err(Errno::EINVAL),
            }
        };
        c.mem
            .check_write(GuestAddr(a[2]), 4)
            .map_err(|_| Errno::EFAULT)?;
        let id = c.group.with_timers(c.process, |timers| {
            timers.create(crate::timers::PosixTimer {
                realtime,
                signal,
                thread,
                ..Default::default()
            })
        })?;
        c.group.with_timers(c.process, |timers| {
            if let Ok(timer) = timers.get_mut(id) {
                timer.value = value.unwrap_or(id as u32 as u64);
            }
        });
        c.mem
            .write(GuestAddr(a[2]), &id.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
        Ok(0)
    })())
}

/// `struct timespec` as nanoseconds, rejecting what Linux rejects.
pub(crate) fn timespec_ns(seconds: u64, nanos: u64) -> Result<u64, Errno> {
    if (seconds as i64) < 0 || nanos >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or(Errno::EINVAL)
}

/// `struct itimerspec` words for an interval and the time left.
fn itimerspec(interval: u64, remaining: u64) -> [u64; 4] {
    [
        interval / 1_000_000_000,
        interval % 1_000_000_000,
        remaining / 1_000_000_000,
        remaining % 1_000_000_000,
    ]
}

/// What `timer_gettime` reports: the interval and the time to the next expiry.
fn timer_state(timer: &crate::timers::PosixTimer, now: u64) -> [u64; 4] {
    let remaining = timer.deadline.map_or(0, |d| d.saturating_sub(now).max(1));
    itimerspec(timer.interval, remaining)
}

fn timer_id(value: u64) -> i32 {
    value as u32 as i32
}

/// `timer_settime(id, flags, new, old)`, in Linux's order: read and check the
/// new value, find the timer, set it, then write the old value out.
fn sys_timer_settime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[2] == 0 {
            return Err(Errno::EINVAL);
        }
        let [i_sec, i_nsec, v_sec, v_nsec] = read_words::<4>(c.mem, a[2])?;
        let (interval, value) = (timespec_ns(i_sec, i_nsec)?, timespec_ns(v_sec, v_nsec)?);
        if a[1] & !TIMER_ABSTIME != 0 {
            return Err(Errno::EINVAL);
        }
        let mono = c.host.clock(ClockId::Monotonic)?;
        let real = c.host.clock(ClockId::Realtime)?;
        let old = c.group.with_timers(c.process, |timers| {
            let timer = timers.get_mut(timer_id(a[0]))?;
            let old = timer_state(timer, mono);
            let now = if timer.realtime { real } else { mono };
            timer.deadline = (value != 0).then(|| {
                let delay = if a[1] & TIMER_ABSTIME != 0 {
                    value.saturating_sub(now)
                } else {
                    value
                };
                mono.saturating_add(delay)
            });
            timer.interval = if value == 0 { 0 } else { interval };
            timer.overrun = 0;
            Ok::<_, Errno>(old)
        })?;
        if a[3] != 0 {
            write_words(c.mem, a[3], &old)?;
        }
        Ok(0)
    })())
}

fn sys_timer_gettime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let mono = c.host.clock(ClockId::Monotonic)?;
        let state = c.group.with_timers(c.process, |timers| {
            timers.get_mut(timer_id(a[0])).map(|t| timer_state(t, mono))
        })?;
        write_words(c.mem, a[1], &state)?;
        Ok(0)
    })())
}

fn sys_timer_getoverrun(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(c.group.with_timers(c.process, |timers| {
        timers
            .get_mut(timer_id(a[0]))
            .map(|t| t.overrun as u32 as u64)
    }))
}

fn sys_timer_delete(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(
        c.group
            .with_timers(c.process, |timers| timers.delete(timer_id(a[0])))
            .map(|()| 0),
    )
}

/// `pause()`: waits until a signal is delivered, then gives EINTR (once the
/// handler has run). Ignored and blocked signals do not end it.
fn sys_pause(c: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    outcome(wait_for_signal(c))
}

/// `rt_sigsuspend(mask, sigsetsize)`: waits as `pause` with `mask` in place of
/// the signal mask (SIGKILL and SIGSTOP stay unblocked). The original mask
/// comes back after the handler, which runs with `mask`, as on Linux.
fn sys_rt_sigsuspend(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[1] != SIGSET_SIZE {
            return Err(Errno::EINVAL);
        }
        let mask = c.mem.read_u64(GuestAddr(a[0])).map_err(|_| Errno::EFAULT)?;
        let old_mask = c.process.signal_mask;
        c.process.signal_mask = mask & !unblockable();
        let result = wait_for_signal(c);
        // The checkpoint installs the signal's frame (saving the original
        // mask) and then restores it, also when no handler runs.
        c.process.wait_restore_mask = Some(old_mask);
        result
    })())
}

/// Waits until a signal can be delivered, the process exits, or the wait is
/// cancelled; the result is always EINTR.
fn wait_for_signal(c: &mut Context<'_>) -> Result<u64, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        crate::events::wait(c, ticket, None)?;
    }
}

/// `rt_sigtimedwait(set, info, timeout, sigsetsize)`: takes the lowest
/// pending signal in `set`, blocked or not, and returns its number; EAGAIN
/// once `timeout` passes, EINTR when another signal can be delivered.
fn sys_rt_sigtimedwait(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[3] != 8 {
            return Err(Errno::EINVAL);
        }
        // SIGKILL and SIGSTOP cannot be waited for.
        let set = c.mem.read_u64(GuestAddr(a[0])).map_err(|_| Errno::EFAULT)? & !(1 << 8 | 1 << 18);
        let timeout = if a[2] == 0 {
            None
        } else {
            let [seconds, nanos] = read_words::<2>(c.mem, a[2])?;
            Some(timespec_ns(seconds, nanos)?)
        };
        let start = c.host.clock(ClockId::Monotonic)?;
        let deadline = timeout.map(|t| start.saturating_add(t));
        loop {
            c.group.drain_process(c.process);
            let now = c.host.clock(ClockId::Monotonic)?;
            c.group.expire_timer(c.process, now);
            // After the timers, so a SIGEV_THREAD_ID signal to this thread is seen.
            c.inbox.drain(c.process);
            // The thread's own queue first, then the process's shared one.
            let found = signals::lowest_in(&c.process.pending, set)
                .map(|index| c.process.pending.remove(index))
                .or_else(|| c.group.take_process_signal(set));
            if let Some(signal) = found {
                if a[1] != 0 {
                    c.mem
                        .write(GuestAddr(a[1]), &signals::siginfo(c.process, &signal))
                        .map_err(|_| Errno::EFAULT)?;
                }
                return Ok(signal.number as u64);
            }
            if c.group.status().is_some()
                || signals::next_pending(c.process, true).is_some()
                || (!c.inbox.owns_wake(c.cancellation)
                    && c.cancellation.load(std::sync::atomic::Ordering::SeqCst))
            {
                return Err(Errno(4)); // EINTR
            }
            if deadline.is_some_and(|d| now >= d) {
                return Err(Errno::EAGAIN);
            }
            let end = deadline
                .unwrap_or(u64::MAX)
                .min(now.saturating_add(10_000_000))
                .min(signals::next_deadline(c.process).unwrap_or(u64::MAX));
            c.host.wait_until(ClockId::Monotonic, end, c.cancellation)?;
        }
    })())
}

fn sys_nanosleep(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    sleep(c, ClockId::Monotonic, false, a[0], a[1])
}
fn sys_clock_nanosleep(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let id = match clock_id(a[0]) {
        Ok(id) => id,
        Err(e) => return err(e),
    };
    if a[1] & !1 != 0 {
        return err(Errno::EINVAL);
    }
    sleep(c, id, a[1] & 1 != 0, a[2], a[3])
}
fn sys_rt_sigreturn(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    if signals::restore(c.process, c.cpu, c.mem).is_ok() {
        Outcome::Restored
    } else {
        Outcome::BadFrame
    }
}
fn sys_getpid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.process.pid))
}
fn send_signal(c: &mut Context<'_>, target: u64, signal: signals::PendingSignal) -> Outcome {
    let number = signal.number;
    if !(0..=64).contains(&number) {
        return err(Errno::EINVAL);
    }
    if target != u64::from(c.process.pid) {
        return err(Errno(3));
    }
    if number == 0 {
        return ok(0);
    }
    signals::queue(c.process, signal);
    ok(0)
}
fn sys_tkill(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    send_signal(
        c,
        a[0],
        signals::PendingSignal::thread(i32::try_from(a[1]).unwrap_or(-1), -6),
    )
}
fn sys_tgkill(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[0] != u64::from(c.process.pid) {
        return err(Errno(3));
    }
    send_signal(
        c,
        a[1],
        signals::PendingSignal::thread(i32::try_from(a[2]).unwrap_or(-1), -6),
    )
}

/// Linux caps one read/write at this many bytes.
const MAX_RW_COUNT: u64 = 0x7fff_f000;
const WRITE_CHUNK: usize = 64 * 1024;

fn sys_write(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if !c.files.uses_original_stdio(a[0]) {
        return crate::files::dispatch(c, a);
    }
    let (fd, buf, count) = (a[0], a[1], a[2].min(MAX_RW_COUNT));
    // Only stdout and stderr are connected in the core emulator.
    let write: fn(&dyn Host, &[u8]) -> Result<usize, Errno> = match fd {
        1 => |h, b| h.write_stdout(b),
        2 => |h, b| h.write_stderr(b),
        _ => return err(Errno::EBADF),
    };
    // With O_NONBLOCK, no room on the host is EAGAIN (an empty write still
    // writes nothing, as Linux's pipe_write).
    if count > 0
        && c.files.descriptor(fd).is_ok_and(|d| {
            crate::files::standard(&d.file).is_some_and(crate::files::StandardFile::would_block)
        })
    {
        return err(Errno::EAGAIN);
    }
    let mut done: u64 = 0;
    let mut chunk = vec![0u8; WRITE_CHUNK.min(usize::try_from(count).unwrap_or(WRITE_CHUNK))];
    while done < count {
        let n = (count - done).min(chunk.len() as u64);
        let n = usize::try_from(n).unwrap_or(0);
        let addr = GuestAddr(buf.wrapping_add(done));
        if c.mem.read(addr, &mut chunk[..n]).is_err() {
            return if done == 0 {
                err(Errno::EFAULT)
            } else {
                ok(done)
            };
        }
        match write(c.host, &chunk[..n]) {
            Ok(w) => {
                done += w as u64;
                // A short host write ends this guest write, including Ok(0).
                if w < n {
                    return ok(done);
                }
            }
            Err(e) => return if done == 0 { err(e) } else { ok(done) },
        }
    }
    ok(done)
}

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;
const POLLPRI: u16 = 0x2;
const MAX_POLL_FDS: u64 = 1024;

/// `poll(fds, nfds, timeout)`: waits until a descriptor is ready, the
/// timeout in milliseconds passes (a negative one never does, 0 polls once)
/// or a signal arrives (`EINTR`), as `epoll_wait` does.
fn sys_poll(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (fds, nfds, timeout) = (a[0], a[1], a[2] as i32);
    if nfds > MAX_POLL_FDS {
        return err(Errno::EINVAL);
    }
    let result = (|| {
        let deadline = if timeout < 0 {
            None
        } else {
            Some(
                c.host
                    .clock(ClockId::Monotonic)?
                    .saturating_add(timeout as u64 * 1_000_000),
            )
        };
        poll_until(c, fds, nfds, deadline)
    })();
    outcome(result)
}

/// poll's wait. Interrupted with a timeout, a stop resumes it through
/// `restart_syscall` with the same deadline, as Linux's `do_restart_poll`.
fn poll_until(
    c: &mut Context<'_>,
    fds: u64,
    nfds: u64,
    deadline: Option<u64>,
) -> Result<u64, Errno> {
    let result = wait_ready(c, deadline, |c| poll_once(c, fds, nfds));
    if result == Err(Errno(4))
        && let Some(deadline) = deadline
    {
        c.process.restart = Some(nr::RESTART_SYSCALL);
        c.process.restart_block = Some(signals::RestartBlock::Poll {
            fds,
            nfds,
            deadline,
        });
    }
    result
}

/// `restart_syscall()`: resumes the wait a stop interrupted, with the deadline
/// it had. Without one (a handler ran, or the guest called it) it gives
/// EINTR, as Linux's `do_no_restart_syscall`.
fn sys_restart_syscall(c: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    match c.process.restart_block.take() {
        Some(signals::RestartBlock::Sleep {
            clock,
            deadline,
            rem,
        }) => sleep_until(c, clock, false, deadline, rem),
        Some(signals::RestartBlock::Poll {
            fds,
            nfds,
            deadline,
        }) => outcome(poll_until(c, fds, nfds, Some(deadline))),
        // A futex wait resumes in the thread code, which takes the block first.
        Some(signals::RestartBlock::Futex { .. }) | None => err(Errno(4)),
    }
}

/// Runs `check` until it finds something ready or `deadline` passes, waiting
/// for readiness changes in between; EINTR when a signal can be delivered.
fn wait_ready(
    c: &mut Context<'_>,
    deadline: Option<u64>,
    mut check: impl FnMut(&mut Context<'_>) -> Result<u64, Errno>,
) -> Result<u64, Errno> {
    loop {
        // Sample the ticket before inspecting readiness, so no change is lost.
        let ticket = c.files.readiness.token.value();
        let ready = check(c)?;
        if ready != 0
            || deadline
                .is_some_and(|end| c.host.clock(ClockId::Monotonic).is_ok_and(|now| now >= end))
        {
            return Ok(ready);
        }
        crate::events::wait(c, ticket, deadline)?;
    }
}

/// The length of a `struct timespec` timeout at `at` (`None` without one),
/// as Linux's `poll_select_set_timeout` takes it: a negative part is EINVAL,
/// and a time past what nanoseconds hold saturates. With `micros` it is a
/// `struct timeval`, whose whole seconds of microseconds carry into its
/// seconds, as `kern_select` does.
fn timeout_delay(c: &Context<'_>, at: u64, micros: bool) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    let [seconds, fraction] = read_words::<2>(c.mem, at)?;
    if (seconds as i64) < 0 || (fraction as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let (seconds, nanos) = if micros {
        (
            seconds
                .checked_add(fraction / 1_000_000)
                .filter(|&s| (s as i64) >= 0)
                .ok_or(Errno::EINVAL)?,
            fraction % 1_000_000 * 1000,
        )
    } else if fraction >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    } else {
        (seconds, fraction)
    };
    Ok(Some(
        seconds.saturating_mul(1_000_000_000).saturating_add(nanos),
    ))
}

/// A wait's deadline: `delay` after `start`.
fn deadline_after(start: u64, delay: Option<u64>) -> Option<u64> {
    delay.map(|delay| start.saturating_add(delay))
}

/// Writes the time left until `deadline` back to the timeout at `at`, as
/// Linux does for ppoll, select and pselect6 unless the timeout was zero; a
/// stopped call then restarts with what is left. A timeout that cannot be
/// written keeps the result but, as Linux's `poll_select_finish` does, the
/// call is not restarted then: it gives EINTR.
fn write_back_timeout(c: &mut Context<'_>, at: u64, delay: Option<u64>, start: u64, micros: bool) {
    let Some(deadline) = deadline_after(start, delay.filter(|&delay| delay != 0)) else {
        return;
    };
    let left = c
        .host
        .clock(ClockId::Monotonic)
        .map_or(0, |now| deadline.saturating_sub(now));
    let fraction = if micros {
        left % 1_000_000_000 / 1000
    } else {
        left % 1_000_000_000
    };
    if write_words(c.mem, at, &[left / 1_000_000_000, fraction]).is_err() {
        c.process.restart = None;
    }
}

/// Puts a call's temporary signal mask in place, and on return takes it away
/// as epoll_pwait does: after the handler when a signal interrupted it.
fn with_wait_mask(
    c: &mut Context<'_>,
    mask: Option<u64>,
    call: impl FnOnce(&mut Context<'_>) -> Result<u64, Errno>,
) -> Result<u64, Errno> {
    let old_mask = c.process.signal_mask;
    if let Some(mask) = mask {
        c.process.signal_mask = mask & !unblockable();
    }
    let result = call(c);
    if mask.is_some() {
        if result == Err(Errno(4)) && signals::next_pending(c.process, true).is_some() {
            c.process.wait_restore_mask = Some(old_mask);
        } else {
            c.process.signal_mask = old_mask;
        }
    }
    result
}

/// A signal mask argument: `None` for a null pointer, EINVAL unless the size
/// is a sigset_t's, EFAULT when it cannot be read.
fn read_sigmask(c: &Context<'_>, at: u64, size: u64) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    if size != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    c.mem
        .read_u64(GuestAddr(at))
        .map(Some)
        .map_err(|_| Errno::EFAULT)
}

/// `ppoll(fds, nfds, timeout, sigmask, sigsetsize)`: poll with a `timespec`
/// timeout, which is written back with the time left, and a temporary mask.
fn sys_ppoll(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let delay = timeout_delay(c, a[2], false)?;
        let mask = read_sigmask(c, a[3], a[4])?;
        let start = c.host.clock(ClockId::Monotonic)?;
        let deadline = deadline_after(start, delay);
        let result = if a[1] > MAX_POLL_FDS {
            Err(Errno::EINVAL)
        } else {
            with_wait_mask(c, mask, |c| {
                wait_ready(c, deadline, |c| poll_once(c, a[0], a[1]))
            })
        };
        write_back_timeout(c, a[2], delay, start, false);
        result
    })())
}

/// `select(nfds, readfds, writefds, exceptfds, timeout)` with a `timeval`.
fn sys_select(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let delay = timeout_delay(c, a[4], true)?;
        let start = c.host.clock(ClockId::Monotonic)?;
        let result = select(c, a[0], [a[1], a[2], a[3]], deadline_after(start, delay));
        write_back_timeout(c, a[4], delay, start, true);
        result
    })())
}

/// `pselect6(nfds, readfds, writefds, exceptfds, timeout, sig)`: select with
/// a `timespec` and `sig` pointing to `{ const sigset_t *ss; size_t len; }`.
fn sys_pselect6(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        // Linux reads the {ss, len} pair before anything else.
        let [ss, len] = if a[5] == 0 {
            [0, 0]
        } else {
            read_words::<2>(c.mem, a[5])?
        };
        let delay = timeout_delay(c, a[4], false)?;
        let mask = read_sigmask(c, ss, len)?;
        let start = c.host.clock(ClockId::Monotonic)?;
        let deadline = deadline_after(start, delay);
        let result = with_wait_mask(c, mask, |c| select(c, a[0], [a[1], a[2], a[3]], deadline));
        write_back_timeout(c, a[4], delay, start, false);
        result
    })())
}

/// The descriptors select looks at: `nfds` is cut to FD_SETSIZE (Linux cuts
/// it to the descriptor table's size, which grows past 1024 only on demand).
const FD_SETSIZE: u64 = 1024;

/// The work of select and pselect6: read the three sets, fail with EBADF for
/// a set bit of a closed descriptor, wait until one is ready, and write the
/// sets back holding only the ready ones; returns how many bits are set.
fn select(
    c: &mut Context<'_>,
    nfds: u64,
    sets: [u64; 3],
    deadline: Option<u64>,
) -> Result<u64, Errno> {
    if (nfds as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let n = u64::from(nfds as u32).min(FD_SETSIZE);
    let words = n.div_ceil(64) as usize;
    let mut wanted = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    for (set, at) in wanted.iter_mut().zip(sets) {
        if at == 0 {
            continue;
        }
        for (index, word) in set.iter_mut().enumerate() {
            *word = c
                .mem
                .read_u64(GuestAddr(at.wrapping_add(index as u64 * 8)))
                .map_err(|_| Errno::EFAULT)?;
        }
        if n % 64 != 0
            && let Some(last) = set.last_mut()
        {
            *last &= (1u64 << (n % 64)) - 1;
        }
    }
    for fd in 0..n {
        let bit = 1u64 << (fd % 64);
        if wanted.iter().any(|set| set[(fd / 64) as usize] & bit != 0)
            && revents(c, fd as i32, 0) == POLLNVAL
        {
            return Err(Errno::EBADF);
        }
    }
    let mut found = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    let count = wait_ready(c, deadline, |c| {
        let mut count = 0;
        for fd in 0..n {
            let (word, bit) = ((fd / 64) as usize, 1u64 << (fd % 64));
            if wanted.iter().all(|set| set[word] & bit == 0) {
                continue;
            }
            // Only a descriptor in the write set asks whether it takes a
            // write, which a full datagram socket notes (`polled_full`).
            let events = [POLLIN, POLLOUT, POLLPRI]
                .into_iter()
                .enumerate()
                .filter(|&(kind, _)| wanted[kind][word] & bit != 0)
                .fold(0, |events, (_, event)| events | event);
            let mask = revents(c, fd as i32, events);
            for (kind, ready) in [POLLIN | 0x18, POLLOUT | 0x8, POLLPRI]
                .into_iter()
                .enumerate()
            {
                if wanted[kind][word] & bit != 0 && mask & ready != 0 {
                    found[kind][word] |= bit;
                    count += 1;
                }
            }
        }
        Ok(count)
    })?;
    for (set, at) in found.iter().zip(sets) {
        if at != 0 {
            write_words(c.mem, at, set)?;
        }
    }
    Ok(count)
}

/// The poll events of descriptor `fd` among `events` (with POLLERR and
/// POLLHUP always), POLLNVAL for one that is not open, 0 for a negative fd.
/// Asking for POLLOUT of a full datagram socket notes it (`polled_full`).
fn revents(c: &Context<'_>, fd: i32, events: u16) -> u16 {
    match fd {
        fd if fd < 0 => 0,
        // The host's standard input is readable with bytes to read, and at
        // its end readable and hung up, as a pipe or terminal whose other
        // side is gone; where the host cannot tell, always readable. Its
        // output streams always take a write.
        0 if c.files.uses_original_stdio(0) => match c.host.stdin_state() {
            Some(paludarium_host::StdinState::Waiting) => 0,
            Some(paludarium_host::StdinState::Ended) => (events & POLLIN) | POLLHUP,
            _ => events & POLLIN,
        },
        1 | 2 if c.files.uses_original_stdio(fd as u64) => events & POLLOUT,
        _ => match c.files.descriptor(fd as u64) {
            Ok(d) => match d.file.readiness() {
                Ok((mask, _, _)) => {
                    if events & POLLOUT != 0 && mask as u16 & POLLOUT == 0 {
                        crate::sockets::polled_full(&d.file);
                    }
                    (mask as u16) & (events | 0x18)
                }
                Err(_) => d.file.stat().map_or(POLLNVAL, |stat| {
                    if stat.mode & 0o170000 == 0o100000 {
                        events & (POLLIN | POLLOUT)
                    } else {
                        0
                    }
                }),
            },
            Err(_) => POLLNVAL,
        },
    }
}

/// One pass over the `pollfd` array, writing each `revents`; returns how
/// many descriptors have any.
fn poll_once(c: &mut Context<'_>, fds: u64, nfds: u64) -> Result<u64, Errno> {
    let mut ready = 0u64;
    for n in 0..nfds {
        let at = GuestAddr(fds.wrapping_add(n * 8));
        let mut entry = [0u8; 8];
        c.mem.read(at, &mut entry).map_err(|_| Errno::EFAULT)?;
        let fd = i32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let events = u16::from_le_bytes([entry[4], entry[5]]);
        // `poll` takes the descriptor as Linux's `fdget` does, which refuses
        // an `O_PATH` one (POLLNVAL); `select` finds it open, and ready.
        let path_only = fd >= 0
            && c.files
                .descriptor(fd as u64)
                .is_ok_and(|d| d.file.flags() & O_PATH != 0);
        let revents = if path_only {
            POLLNVAL
        } else {
            revents(c, fd, events)
        };
        c.mem
            .write(at.wrapping_add(6), &revents.to_le_bytes())
            .map_err(|_| Errno::EFAULT)?;
        if revents != 0 {
            ready += 1;
        }
    }
    Ok(ready)
}

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MAP_LOCKED: u64 = 0x2000;
const MAP_POPULATE: u64 = 0x8000;

fn sys_mmap(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (addr, len, prot, flags, fd, offset) = (a[0], a[1], a[2], a[3], a[4] as i32, a[5]);
    let Some(prot) = Prot::from_bits(prot) else {
        return err(Errno::EINVAL);
    };
    let prot = read_implies_exec(c.process, prot);
    if offset & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    let descriptor = if flags & MAP_ANONYMOUS == 0 {
        match u64::try_from(fd).map_or(Err(Errno::EBADF), |fd| c.files.descriptor(fd)) {
            Ok(d) if d.file.flags() & O_PATH == 0 => Some(d),
            _ => return err(Errno::EBADF),
        }
    } else {
        None
    };
    let file = descriptor.as_ref().map(|d| d.file.clone());
    if len == 0 || !matches!(flags & (MAP_SHARED | MAP_PRIVATE), MAP_SHARED | MAP_PRIVATE) {
        return err(Errno::EINVAL);
    }
    if let Some(file) = &file
        && let Err(e) = check_mappable(file.as_ref(), prot, flags, offset, len)
    {
        return err(e);
    }
    // A mapping of /dev/zero is anonymous memory (shared with MAP_SHARED),
    // as Linux's mmap_zero makes it.
    let file = file.filter(|f| !is_zero_device(f.as_ref()));
    let kind = if file.is_some() {
        MappingKind::File
    } else {
        MappingKind::Anonymous
    };
    let at = GuestAddr(addr);
    let result = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        if at.page_offset() != 0 {
            return err(Errno::EINVAL);
        }
        if flags & MAP_FIXED_NOREPLACE == 0
            && let Err(e) = c.mem.unmap_shared(at, len)
        {
            return err(e);
        }
        c.mem.map_shared(Some(at), len, prot, kind)
    } else {
        // Linux rounds a non-fixed hint down to its page boundary.
        let hint = GuestAddr(addr & !4095);
        let hinted = (hint.0 != 0)
            .then(|| c.mem.map_shared(Some(hint), len, prot, kind).ok())
            .flatten();
        match hinted {
            Some(a) => Ok(a),
            None => c.mem.map_shared(None, len, prot, kind),
        }
    };
    match result {
        Ok(a) => {
            if let Some(file) = &file
                && let Some(d) = &descriptor
                && flags & MAP_SHARED != 0
            {
                // The mapping shows the file's page cache.
                if let Err(error) = share_file(c, d, file, a, len, offset, prot) {
                    let _ = c.mem.unmap_shared(a, len);
                    return err(error);
                }
                c.group.numa().forget(a.0, len);
                return ok(a.0);
            }
            // A private mapping shows the file's page cache until it writes
            // a page, which copies it.
            if let Some(file) = &file
                && let Some(d) = &descriptor
                && let Err(error) = file_cache(c, d, file).and_then(|cache| {
                    c.mem.back_with_cache(
                        a,
                        len,
                        &cache.map_private(file, crate::files::mapped_path(c, d)),
                        offset,
                    )
                })
            {
                let _ = c.mem.unmap_shared(a, len);
                return err(error);
            }
            if flags & MAP_SHARED != 0
                && let Err(error) = c.mem.mark_shared(a, len)
            {
                return err(error);
            }
            // Linux populates a writable private mapping by writing it, which
            // gives it an anon_vma (a core then writes it whole).
            if flags & (MAP_POPULATE | MAP_LOCKED) != 0
                && flags & MAP_SHARED == 0
                && prot.contains(Prot::WRITE)
            {
                c.mem.mark_written(a, len);
            }
            // A new VMA has no memory policy.
            c.group.numa().forget(a.0, len);
            ok(a.0)
        }
        Err(e) => err(e),
    }
}

const O_PATH: u32 = 0o10000000;

/// The `mmap` checks of a file, in Linux's order: a shared mapping that
/// writes needs a file open for reading and writing, any mapping one open
/// for reading, and a memfd sealed against writes refuses a shared mapping
/// that writes (seal_check_write).
fn check_mappable(
    file: &dyn FileHandle,
    prot: Prot,
    flags: u64,
    offset: u64,
    len: u64,
) -> Result<(), Errno> {
    let regular = file.stat()?.mode & 0o170000 == 0o100000;
    // A regular file's mapping must end within the largest file size.
    if regular && i64::MAX as u64 - len.min(i64::MAX as u64) < offset {
        return Err(Errno::EOVERFLOW);
    }
    let access = file.flags() & 3;
    let shared_write = flags & MAP_SHARED != 0 && prot.contains(Prot::WRITE);
    if shared_write && access != 2 || access == 1 {
        return Err(Errno::EACCES);
    }
    // Neither a file that is not regular nor one that /proc generates can
    // be read at an offset, which a mapping needs.
    let readable = regular && file.read_at(0, &mut []) != Err(Errno::ENODEV);
    if !readable && !is_zero_device(file) {
        return Err(Errno::ENODEV);
    }
    if shared_write && write_sealed(file) {
        return Err(Errno::EPERM);
    }
    Ok(())
}
/// Whether `file` is a memfd sealed against writes, whose shared mappings
/// may not write.
fn write_sealed(file: &dyn FileHandle) -> bool {
    file.as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
        .is_some_and(|m| {
            m.seals() & (crate::memfd::F_SEAL_WRITE | crate::memfd::F_SEAL_FUTURE_WRITE) != 0
        })
}
/// Makes the new mapping `[at, at+len)` show the page cache of the file `d`
/// holds from `offset`, as a Linux `MAP_SHARED` mapping of a file. It may
/// become writable when the file is open for writing and not sealed
/// against it (Linux's `VM_MAYWRITE`).
fn share_file(
    c: &Context<'_>,
    d: &crate::files::Descriptor,
    file: &std::sync::Arc<dyn FileHandle>,
    at: GuestAddr,
    len: u64,
    offset: u64,
    prot: Prot,
) -> Result<(), Errno> {
    let len = GuestAddr(len).page_align_up().ok_or(Errno::ENOMEM)?.0;
    // A memfd's seals stay as they are until the mapping counts among the
    // writable ones; one added since `check_mappable` refuses it now.
    let memfd = file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
    let _sealing = memfd.map(crate::memfd::Memfd::lock_seals);
    if prot.contains(Prot::WRITE) && write_sealed(file.as_ref()) {
        return Err(Errno::EPERM);
    }
    let may_write = file.flags() & 3 == 2 && !write_sealed(file.as_ref());
    let pages = file_cache(c, d, file)?.map(
        file,
        crate::files::mapped_path(c, d),
        offset,
        len,
        may_write,
    )?;
    c.mem.share_pages(at, len, &pages, offset, may_write)
}
/// The page cache of the file `d` holds, which keeps its size.
fn file_cache(
    c: &Context<'_>,
    d: &crate::files::Descriptor,
    file: &std::sync::Arc<dyn FileHandle>,
) -> Result<std::sync::Arc<crate::page_cache::FileCache>, Errno> {
    let stat = file.stat()?;
    let key = (crate::files::descriptor_device(c, d), stat.inode);
    Ok(c.files.caches.cache(key, c.mem.memory_meter(), stat.size))
}
fn is_zero_device(file: &dyn FileHandle) -> bool {
    file.as_any()
        .and_then(|v| v.downcast_ref::<crate::devices::Device>())
        .is_some_and(|d| d.kind() == crate::devices::Kind::Zero)
}

const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;

/// `mincore(addr, length, vec)`, as Linux's: each byte of `vec` says whether
/// its page is in memory, up to the first page that is not mapped, which is
/// `ENOMEM` after the bytes before it are written.
fn sys_mincore(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (addr, length, vec) = (a[0], a[1], a[2]);
    if addr & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    if addr
        .checked_add(length)
        .is_none_or(|end| end > USER_ADDRESS_LIMIT)
    {
        return err(Errno::ENOMEM);
    }
    let pages = length.div_ceil(4096);
    if vec
        .checked_add(pages)
        .is_none_or(|end| end > USER_ADDRESS_LIMIT)
    {
        return err(Errno::EFAULT);
    }
    let mut done = 0;
    while done < pages {
        let mut piece = Vec::with_capacity(4096);
        let mut mapped = true;
        while mapped && piece.len() < 4096 && done + (piece.len() as u64) < pages {
            let page = addr + (done + piece.len() as u64) * 4096;
            match c.mem.resident(GuestAddr(page)) {
                Some(resident) => piece.push(u8::from(resident)),
                None => mapped = false,
            }
        }
        if c.mem.write(GuestAddr(vec + done), &piece).is_err() {
            return err(Errno::EFAULT);
        }
        if !mapped {
            return err(Errno::ENOMEM);
        }
        done += piece.len() as u64;
    }
    ok(0)
}

const MLOCK_ONFAULT: u32 = 1;
const MCL_CURRENT: u32 = 1;
const MCL_FUTURE: u32 = 2;
const MCL_ONFAULT: u32 = 4;

/// Whether `mlock` and its kin may take `[addr, addr + len)`, as Linux's
/// `do_mlock` and `do_munlock` decide. Nothing is ever swapped out here, so
/// that is all there is to do. `populate` is a lock that brings its pages in,
/// which a page without access fails, as `__mm_populate` does.
fn lock_range(c: &Context<'_>, addr: u64, len: u64, populate: bool) -> Outcome {
    // Rounded as Linux's PAGE_ALIGN is, so a huge length may wrap to none.
    let length = len.wrapping_add(addr & 4095).wrapping_add(4095) & !4095;
    let start = addr & !4095;
    let Some(end) = start.checked_add(length) else {
        return err(Errno::EINVAL);
    };
    if length == 0 {
        return ok(0);
    }
    let mut mappings: Vec<_> = c
        .mem
        .mappings()
        .filter(|m| m.start.0 < end && m.end() > start)
        .collect();
    mappings.sort_by_key(|m| m.start.0);
    let mut covered = start;
    for m in &mappings {
        if m.start.0 > covered || populate && m.prot == Prot::NONE {
            return err(Errno::ENOMEM);
        }
        covered = m.end();
    }
    if covered < end {
        return err(Errno::ENOMEM);
    }
    ok(0)
}

/// `mlock(addr, len)`.
fn sys_mlock(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    lock_range(c, a[0], a[1], true)
}

/// `munlock(addr, len)`.
fn sys_munlock(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    lock_range(c, a[0], a[1], false)
}

/// `mlock2(addr, len, flags)`: `MLOCK_ONFAULT` brings no page in.
fn sys_mlock2(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let flags = a[2] as u32;
    if flags & !MLOCK_ONFAULT != 0 {
        return err(Errno::EINVAL);
    }
    lock_range(c, a[0], a[1], flags & MLOCK_ONFAULT == 0)
}

/// `mlockall(flags)`: it covers what is mapped, so only the flags can be wrong.
fn sys_mlockall(_: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let flags = a[0] as u32;
    if flags == 0 || flags == MCL_ONFAULT || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
    {
        return err(Errno::EINVAL);
    }
    ok(0)
}

/// `munlockall()`.
fn sys_munlockall(_: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    ok(0)
}

/// `set_robust_list(head, length)`: the list Linux walks when the thread ends.
fn sys_set_robust_list(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[1] != crate::futex::ROBUST_LIST_HEAD {
        return err(Errno::EINVAL);
    }
    c.group.set_robust_list(c.tid, a[0]);
    ok(0)
}

/// `get_robust_list(tid, head, length)` of a thread of this process, or
/// `ESRCH` for any other (Linux gives another process's if it may trace it).
fn sys_get_robust_list(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let tid = a[0] as u32;
    let tid = if tid == 0 { c.tid } else { tid };
    let Some(head) = c.group.robust_list(tid) else {
        return err(Errno(3));
    };
    if c.mem
        .write_u64(GuestAddr(a[2]), crate::futex::ROBUST_LIST_HEAD)
        .is_err()
        || c.mem.write_u64(GuestAddr(a[1]), head).is_err()
    {
        return err(Errno::EFAULT);
    }
    ok(0)
}

fn sys_madvise(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (addr, len, advice) = (a[0], a[1], a[2]);
    // Of the advice values, only the access-pattern hints and the two that
    // give memory back are implemented; the others are rejected rather than
    // ignored, so that a guest relying on one of them notices.
    if !matches!(advice, 0..=3 | MADV_DONTNEED | MADV_FREE) {
        return err(Errno::EINVAL);
    }
    if addr & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    let Some(length) = len.checked_add(4095).map(|l| l & !4095) else {
        return err(Errno::EINVAL);
    };
    if length == 0 {
        return ok(0);
    }
    let Some(end) = addr.checked_add(length) else {
        return err(Errno::EINVAL);
    };
    if end > USER_ADDRESS_LIMIT {
        return err(Errno::ENOMEM);
    }
    if advice == MADV_DONTNEED {
        return match c.mem.discard_shared(GuestAddr(addr), length) {
            Ok(()) => ok(0),
            Err(e) => err(e),
        };
    }
    if advice == MADV_FREE {
        // Linux frees such pages only under memory pressure, which the
        // emulator never has, so their contents stay as they are.
        return match c.mem.check_private_anonymous(GuestAddr(addr), length) {
            Ok(()) => ok(0),
            Err(e) => err(e),
        };
    }
    let mapped = c
        .mem
        .mappings()
        .filter(|m| m.start.0 < end && m.end() > addr);
    let covered = mapped.fold(addr, |covered, m| {
        if m.start.0 <= covered {
            covered.max(m.end())
        } else {
            covered
        }
    });
    if covered < end {
        err(Errno::ENOMEM)
    } else {
        ok(0)
    }
}

fn sys_mprotect(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // PROT_SEM (0x8) has no effect on x86-64, but Linux accepts it.
    let Some(prot) = Prot::from_bits(a[2] & !8) else {
        return err(Errno::EINVAL);
    };
    let prot = read_implies_exec(c.process, prot);
    if a[1] == 0 {
        return if GuestAddr(a[0]).page_offset() == 0 {
            ok(0)
        } else {
            err(Errno::EINVAL)
        };
    }
    match c.mem.protect_shared(GuestAddr(a[0]), a[1], prot) {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;

fn sys_mremap(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (addr, old_len, new_len, flags, new_addr) = (a[0], a[1], a[2], a[3], a[4]);
    // The other flag rules depend on the rounded lengths (see `remap`).
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return err(Errno::EINVAL);
    }
    let how = Remap {
        may_move: flags & MREMAP_MAYMOVE != 0,
        fixed: flags & MREMAP_FIXED != 0,
        keep_old: flags & MREMAP_DONTUNMAP != 0,
        new_addr: GuestAddr(new_addr),
    };
    let keep_old = how.keep_old;
    match c.mem.remap_shared(GuestAddr(addr), old_len, new_len, how) {
        Ok(at) => {
            c.group.numa().moved(addr, old_len, at.0, new_len, keep_old);
            ok(at.0)
        }
        Err(e) => err(e),
    }
}

const MS_ASYNC: u64 = 1;
const MS_INVALIDATE: u64 = 2;
const MS_SYNC: u64 = 4;

/// `msync`: checks its arguments and the range, then writes the stores of
/// shared file mappings back to their files (all of them, which the next
/// read of a file would do anyway).
fn sys_msync(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (addr, len, flags) = (a[0], a[1], a[2]);
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || addr & 4095 != 0
        || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
    {
        return err(Errno::EINVAL);
    }
    // Linux rounds the length up with wrapping arithmetic, so a length near
    // the top of the range becomes 0.
    let len = len.wrapping_add(4095) & !4095;
    if len == 0 {
        return ok(0);
    }
    match c.mem.covers(GuestAddr(addr), len) {
        Ok(true) if flags & (MS_ASYNC | MS_SYNC) != 0 => match c.files.caches.write_back_all() {
            Ok(()) => ok(0),
            Err(e) => err(e),
        },
        Ok(true) => ok(0),
        Ok(false) | Err(_) => err(Errno::ENOMEM),
    }
}

fn sys_munmap(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match c.mem.unmap_shared(GuestAddr(a[0]), a[1]) {
        Ok(()) => {
            c.group.numa().forget(a[0], a[1]);
            ok(0)
        }
        Err(e) => err(e),
    }
}

fn sys_brk(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // brk(0) and invalid requests return the current break.
    let old = c.mem.set_break_shared(GuestAddr(0)).0;
    let new = c.mem.set_break_shared(GuestAddr(a[0])).0;
    // The pages it gives back, or a new VMA it grows into, have no memory
    // policy (Linux expands the heap's VMA only when it has none).
    // set_break maps and unmaps whole pages between the two breaks rounded
    // up, so the page that holds an unaligned break keeps its policy.
    let up = |n: u64| n.saturating_add(4095) & !4095;
    let (low, high) = (up(old.min(new)), up(old.max(new)));
    if high > low {
        c.group.numa().forget(low, high - low);
    }
    ok(new)
}

const SIGKILL: u64 = 9;
const SIGSTOP: u64 = 19;
const NSIG: u64 = 64;
const SIGSET_SIZE: u64 = 8;

fn unblockable() -> u64 {
    (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1))
}

pub(crate) fn read_words<const N: usize>(mem: &AddressSpace, at: u64) -> Result<[u64; N], Errno> {
    let mut out = [0u64; N];
    for (i, w) in out.iter_mut().enumerate() {
        *w = mem
            .read_u64(GuestAddr(at.wrapping_add(8 * i as u64)))
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(out)
}

pub(crate) fn write_words(mem: &AddressSpace, at: u64, words: &[u64]) -> Result<(), Errno> {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    mem.write(GuestAddr(at), &bytes).map_err(|_| Errno::EFAULT)
}

fn sys_rt_sigaction(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (sig, act, oldact, size) = (a[0], a[1], a[2], a[3]);
    if size != SIGSET_SIZE || sig == 0 || sig > NSIG {
        return err(Errno::EINVAL);
    }
    if act != 0 && (sig == SIGKILL || sig == SIGSTOP) {
        return err(Errno::EINVAL);
    }
    let key = i32::try_from(sig).unwrap_or(0);
    let new = if act != 0 {
        match read_words::<4>(c.mem, act) {
            Ok(w) => Some(SignalAction {
                handler: w[0],
                flags: w[1],
                restorer: w[2],
                mask: w[3] & !unblockable(),
            }),
            Err(e) => return err(e),
        }
    } else {
        None
    };
    if oldact != 0 {
        let old = c
            .process
            .signal_actions
            .get(&key)
            .copied()
            .unwrap_or_default();
        if let Err(e) = write_words(
            c.mem,
            oldact,
            &[old.handler, old.flags, old.restorer, old.mask],
        ) {
            return err(e);
        }
    }
    if let Some(new) = new {
        c.process.signal_actions.insert(key, new);
        // An ignored signal's pending instances go, as in Linux's
        // do_sigaction: SIG_IGN, or SIG_DFL for one whose default is to
        // ignore it (SIGCHLD, SIGCONT, SIGURG, SIGWINCH).
        if new.handler == 1 || new.handler == 0 && matches!(key, 17 | 18 | 23 | 28) {
            c.group.discard_pending(key, c.process);
        }
    }
    ok(0)
}

/// The blocked signals waiting for this thread or its process. As in Linux,
/// a set smaller than eight bytes gets its first bytes.
fn sys_rt_sigpending(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[1] > SIGSET_SIZE {
        return err(Errno::EINVAL);
    }
    c.inbox.drain(c.process);
    let pending = c
        .process
        .pending
        .iter()
        .fold(c.group.process_pending_set().0, |set, signal| {
            set | 1 << (signal.number - 1)
        })
        & c.process.signal_mask;
    match c
        .mem
        .write(GuestAddr(a[0]), &pending.to_le_bytes()[..a[1] as usize])
    {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}
fn sys_rt_sigprocmask(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (how, set, oldset, size) = (a[0], a[1], a[2], a[3]);
    if size != SIGSET_SIZE {
        return err(Errno::EINVAL);
    }
    let new = if set != 0 {
        match c.mem.read_u64(GuestAddr(set)) {
            Ok(v) => Some(v),
            Err(_) => return err(Errno::EFAULT),
        }
    } else {
        None
    };
    if new.is_some() && how > 2 {
        return err(Errno::EINVAL);
    }
    if oldset != 0
        && c.mem
            .write_u64(GuestAddr(oldset), c.process.signal_mask)
            .is_err()
    {
        return err(Errno::EFAULT);
    }
    if let Some(v) = new {
        let mask = c.process.signal_mask;
        c.process.signal_mask = match how {
            0 => mask | v,
            1 => mask & !v,
            _ => v,
        } & !unblockable();
    }
    ok(0)
}

/// Only known terminal queries are interpreted, never forwarded to Host.
fn sys_ioctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let mut run = || -> Result<u64, Errno> {
        // Linux's `do_vfs_ioctl` answers these for every file, and an
        // `O_PATH` descriptor for none.
        let descriptor = c.files.descriptor(a[0])?;
        if descriptor.file.flags() & O_PATH != 0 {
            return Err(Errno::EBADF);
        }
        let file = descriptor.file;
        let read_int = |c: &Context<'_>| {
            let mut bytes = [0; 4];
            c.mem
                .read(GuestAddr(a[2]), &mut bytes)
                .map_err(|_| Errno::EFAULT)
                .map(|()| i32::from_le_bytes(bytes))
        };
        match a[1] {
            // FIONCLEX and FIOCLEX.
            0x5450 | 0x5451 => {
                c.files.set_cloexec(a[0], a[1] == 0x5451)?;
                return Ok(0);
            }
            // FIONBIO.
            0x5421 => {
                let enabled = read_int(c)? != 0;
                let flags = (file.flags() & !crate::events::NONBLOCK)
                    | if enabled { crate::events::NONBLOCK } else { 0 };
                file.set_flags(flags)?;
                return Ok(0);
            }
            // FIOASYNC, ENOTTY for a file without `fasync` only if it would
            // change `O_ASYNC`.
            0x5452 => {
                let async_flag = crate::fasync::O_ASYNC;
                let flags =
                    (file.flags() & !async_flag) | if read_int(c)? != 0 { async_flag } else { 0 };
                if (flags ^ file.flags()) & async_flag != 0 {
                    if !crate::fasync::has_fasync(&file) {
                        return Err(Errno::ENOTTY);
                    }
                    crate::fasync::set_flags(c, &file, a[0], flags)?;
                }
                return Ok(0);
            }
            // FIGETBSZ: the block size of the file's file system, as an int
            // (Linux's `EINVAL` for one without, such as overlayfs, is not
            // given).
            0x2 => {
                let block_size = crate::files::descriptor_block_size(c, &c.files.descriptor(a[0])?);
                c.mem
                    .write(GuestAddr(a[2]), &block_size.to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
                return Ok(0);
            }
            // FIOQSIZE: the bytes a regular file or directory takes, as a
            // loff_t (Linux's `inode_get_bytes`, `st_blocks` in bytes).
            0x5460 => {
                let stat = file.stat()?;
                if !matches!(stat.mode & 0o170000, 0o100000 | 0o040000) {
                    return Err(Errno::ENOTTY);
                }
                let bytes = crate::files::blocks(&stat) * 512;
                c.mem
                    .write(GuestAddr(a[2]), &bytes.to_le_bytes())
                    .map_err(|_| Errno::EFAULT)?;
                return Ok(0);
            }
            _ => {}
        }
        // A pseudo-terminal's own requests.
        if let Some(result) = crate::pty::ioctl(c, &file, a[1], a[2]) {
            return result;
        }
        // SIOCATMARK: whether a socket's next read is at its out-of-band mark.
        if a[1] == 0x8905 {
            let at_mark = match crate::inet::of(&file) {
                Some(socket) => socket.at_mark(),
                None => file
                    .as_any()
                    .and_then(|v| v.downcast_ref::<crate::sockets::SocketPairEnd>())
                    .ok_or(Errno::ENOTTY)?
                    .at_mark(),
            };
            let at_mark = i32::from(at_mark);
            c.mem
                .write(GuestAddr(a[2]), &at_mark.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            return Ok(0);
        }
        // FIONREAD (SIOCINQ) and SIOCOUTQ of a pipe, a socket or a regular
        // file, which Linux's `do_vfs_ioctl` answers with the size past the
        // offset, cut to an int. The host's standard streams are not read.
        if matches!(a[1], 0x541b | 0x5411) && c.files.stdio_channel(a[0])?.is_none() {
            let count = match crate::sockets::queued(&file, a[1] == 0x5411) {
                Some(count) => count? as i64,
                None => match file.stat() {
                    Ok(stat) if a[1] == 0x541b && stat.mode & 0o170000 == 0o100000 => {
                        stat.size as i64 - file.seek(0, 1)? as i64
                    }
                    _ => return Err(Errno::ENOTTY),
                },
            };
            c.mem
                .write(GuestAddr(a[2]), &(count as i32).to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            return Ok(0);
        }
        let stream = match c.files.stdio_channel(a[0])? {
            Some(0) => paludarium_host::StreamId::Stdin,
            Some(1) => paludarium_host::StreamId::Stdout,
            Some(2) => paludarium_host::StreamId::Stderr,
            _ => return Err(Errno::ENOTTY),
        };
        if !matches!(a[1], 0x5401 | 0x5413) {
            return Err(Errno::ENOTTY);
        }
        let host_info = c.host.terminal_info(stream)?;
        let info = if let Some((columns, rows)) = c.files.terminal_size {
            let mut info = host_info.unwrap_or_default();
            info.columns = columns;
            info.rows = rows;
            info
        } else {
            host_info.ok_or(Errno::ENOTTY)?
        };
        let mut bytes = [0u8; 36];
        let len = if a[1] == 0x5401 {
            for (i, flag) in [
                info.attributes.input_flags,
                info.attributes.output_flags,
                info.attributes.control_flags,
                info.attributes.local_flags,
            ]
            .into_iter()
            .enumerate()
            {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&flag.to_le_bytes());
            }
            bytes[16] = info.attributes.line;
            bytes[17..36].copy_from_slice(&info.attributes.control_chars);
            36
        } else {
            for (i, value) in [info.rows, info.columns, info.x_pixels, info.y_pixels]
                .into_iter()
                .enumerate()
            {
                bytes[i * 2..i * 2 + 2].copy_from_slice(&value.to_le_bytes());
            }
            8
        };
        c.mem
            .write(GuestAddr(a[2]), &bytes[..len])
            .map_err(|_| Errno::EFAULT)?;
        Ok(0)
    };
    match run() {
        Ok(v) => ok(v),
        Err(e) => err(e),
    }
}

fn exit_code(value: u64) -> i32 {
    (value & 0xff) as i32
}

fn sys_exit(_: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // One thread in the core emulator: exit ends the process like exit_group.
    Outcome::Exit(exit_code(a[0]))
}

fn sys_exit_group(_: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    Outcome::Exit(exit_code(a[0]))
}

const SS_ONSTACK: u32 = 1;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;

fn sys_sigaltstack(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (ss, old) = (a[0], a[1]);
    let on_stack = signals::on_altstack(c.cpu, c.process.alt_stack);
    if ss != 0 && on_stack {
        return err(Errno::EPERM);
    }
    let new = if ss != 0 {
        let w = match read_words::<3>(c.mem, ss) {
            Ok(w) => w,
            Err(e) => return err(e),
        };
        let flags = w[1] as u32;
        if flags & !(SS_DISABLE | SS_AUTODISARM) != 0 {
            return err(Errno::EINVAL);
        }
        if flags & SS_DISABLE == 0 && w[2] < MINSIGSTKSZ {
            return err(Errno::ENOMEM);
        }
        Some(if flags & SS_DISABLE != 0 {
            AltStack::default()
        } else {
            AltStack {
                sp: w[0],
                flags,
                size: w[2],
            }
        })
    } else {
        None
    };
    if old != 0 {
        let cur = c.process.alt_stack;
        let flags = u64::from((cur.flags & !SS_ONSTACK) | u32::from(on_stack));
        if let Err(e) = write_words(c.mem, old, &[cur.sp, flags, cur.size]) {
            return err(e);
        }
    }
    if let Some(new) = new {
        c.process.alt_stack = new;
    }
    ok(0)
}

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

fn sys_arch_prctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (code, addr) = (a[0], a[1]);
    match code {
        ARCH_SET_FS | ARCH_SET_GS => {
            if addr >= USER_ADDRESS_LIMIT {
                return err(Errno::EPERM);
            }
            if code == ARCH_SET_FS {
                c.cpu.fs_base = addr;
            } else {
                c.cpu.gs_base = addr;
            }
            ok(0)
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            let v = if code == ARCH_GET_FS {
                c.cpu.fs_base
            } else {
                c.cpu.gs_base
            };
            match c.mem.write_u64(GuestAddr(addr), v) {
                Ok(()) => ok(0),
                Err(_) => err(Errno::EFAULT),
            }
        }
        _ => err(Errno::EINVAL),
    }
}

/// Linux's `struct utsname`: six NUL-terminated fields of 65 bytes. The host's
/// name and kernel are not revealed, as with `CPUID`.
///
/// `uname`, with the release and machine a personality asks for, as
/// Linux's `override_release` and `override_architecture`: `UNAME26` makes
/// the release a 2.6 one, its patch level 60 more than the minor version,
/// and `PER_LINUX32` the machine `i686`.
fn sys_uname(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    const FIELD: usize = 65;
    let personality = c.process.personality;
    let release: &[u8] = if personality & UNAME26 != 0 {
        b"2.6.72-paludarium"
    } else {
        b"6.12.0-paludarium"
    };
    let machine: &[u8] = if personality & 0xff == PER_LINUX32 {
        b"i686"
    } else {
        b"x86_64"
    };
    let fields: [&[u8]; 6] = [
        b"Linux",
        b"paludarium",
        release,
        b"#1 SMP PREEMPT_DYNAMIC",
        machine,
        b"(none)",
    ];
    let mut bytes = [0u8; FIELD * 6];
    for (i, field) in fields.iter().enumerate() {
        bytes[i * FIELD..i * FIELD + field.len()].copy_from_slice(field);
    }
    match c.mem.write(GuestAddr(a[0]), &bytes) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

fn sys_sched_yield(_c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    std::thread::yield_now();
    ok(0)
}

/// Memory a guest is told it has; like `uname`, the host's is not revealed.
pub(crate) const SYSINFO_RAM: u64 = 4 << 30;

/// A `struct rusage` with `cpu` nanoseconds as user time. The emulator's
/// own work for the guest's system calls happens in user space on the host,
/// so the system time is 0, and memory use is not measured.
pub(crate) fn rusage(cpu: u64) -> [u8; 144] {
    let mut bytes = [0u8; 144];
    bytes[..8].copy_from_slice(&(cpu / 1_000_000_000).to_le_bytes());
    bytes[8..16].copy_from_slice(&(cpu % 1_000_000_000 / 1000).to_le_bytes());
    bytes
}

/// `getrusage(who, usage)`: the CPU time of the process (RUSAGE_SELF), the
/// thread (RUSAGE_THREAD) or the children waited for (RUSAGE_CHILDREN), as
/// [`rusage`] lays it out; any other `who` is `EINVAL`.
fn sys_getrusage(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let thread = crate::account_cpu(c.host, c.group, c.process);
    let cpu = match a[0] as i32 {
        0 => c.group.process_cpu(),
        1 => thread,
        -1 => c.processes.children_cpu(c.process.pid),
        _ => return err(Errno::EINVAL),
    };
    match c.mem.write(GuestAddr(a[1]), &rusage(cpu)) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

/// `times(buf)`: the same CPU times in clock ticks (USER_HZ is 100), and the
/// monotonic clock in ticks as the return value.
fn sys_times(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| {
        crate::account_cpu(c.host, c.group, c.process);
        let ticks = |ns: u64| ns / 10_000_000;
        if a[0] != 0 {
            let words = [
                ticks(c.group.process_cpu()),
                0,
                ticks(c.processes.children_cpu(c.process.pid)),
                0,
            ];
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            c.mem
                .write(GuestAddr(a[0]), &bytes)
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(ticks(c.host.clock(ClockId::Monotonic)?))
    })();
    outcome(result)
}

/// `struct sysinfo` (112 bytes): the uptime is the monotonic clock's, the
/// memory is a fixed [`SYSINFO_RAM`] with nothing used and no swap, the load
/// averages are 0 and `procs` counts this process's threads.
fn sys_sysinfo(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // Rounded up to a whole second, as Linux's do_sysinfo rounds it.
    let uptime = match c.host.clock(ClockId::Monotonic) {
        Ok(ns) => ns.div_ceil(1_000_000_000),
        Err(e) => return err(e),
    };
    let mut info = [0u8; 112];
    info[0..8].copy_from_slice(&uptime.to_le_bytes());
    info[32..40].copy_from_slice(&SYSINFO_RAM.to_le_bytes()); // totalram
    info[40..48].copy_from_slice(&SYSINFO_RAM.to_le_bytes()); // freeram
    let procs = u16::try_from(c.group.active_threads())
        .unwrap_or(u16::MAX)
        .max(1);
    info[80..82].copy_from_slice(&procs.to_le_bytes());
    info[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    match c.mem.write(GuestAddr(a[0]), &info) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

/// The thread `pid` names for the affinity calls, and its thread group when
/// that is another process's: 0 is the caller, and any live thread of any
/// process is found by its ID, as root may set another's mask (`ESRCH` when
/// none has it).
fn affinity_target(
    c: &Context<'_>,
    pid: i32,
) -> Result<(u32, Option<std::sync::Arc<crate::ThreadGroup>>), Errno> {
    match u32::try_from(pid) {
        Ok(0) => Ok((c.tid, None)),
        Ok(p) if p == c.process.pid || c.group.has_member(p) => Ok((p, None)),
        Ok(p) => c
            .processes
            .group_of(p)
            .map(|group| (p, Some(group)))
            .ok_or(Errno(3)),
        Err(_) => Err(Errno(3)), // ESRCH
    }
}

/// The host's CPUs, numbered from 0, as Linux's `cpu_active_mask`.
fn active_cpus(c: &Context<'_>) -> usize {
    c.host.cpu_count().clamp(1, 8192)
}

/// The CPU mask of thread `pid`: the one `sched_setaffinity` gave it, or
/// every CPU. Linux copies its whole CPU mask, a whole number of 64-bit
/// words.
fn sys_sched_getaffinity(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (pid, len) = (a[0] as u32 as i32, a[1] as u32);
    let cpus = active_cpus(c);
    if (len as usize) * 8 < cpus || len % 8 != 0 {
        return err(Errno::EINVAL);
    }
    let (tid, other) = match affinity_target(c, pid) {
        Ok(target) => target,
        Err(e) => return err(e),
    };
    let words = cpus.div_ceil(64);
    let set = other.as_deref().unwrap_or(c.group).affinity(tid);
    let mut mask = vec![0u8; words * 8];
    for cpu in 0..cpus {
        let allowed = set.as_ref().is_none_or(|set| {
            set.get(cpu / 64)
                .is_some_and(|word| word >> (cpu % 64) & 1 != 0)
        });
        if allowed {
            mask[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    let copied = mask.len().min(len as usize);
    match c.mem.write(GuestAddr(a[2]), &mask[..copied]) {
        Ok(()) => ok(copied as u64),
        Err(_) => err(Errno::EFAULT),
    }
}

/// `sched_setaffinity`, as Linux's: the mask is read up to the size of a CPU
/// mask (a shorter one counts the rest as clear, `EFAULT` if it cannot be
/// read), keeps only the host's CPUs, and an empty result is `EINVAL`. The
/// mask is kept for `sched_getaffinity` and inherited by new threads and
/// processes; the host still runs the thread on any of its CPUs.
fn sys_sched_setaffinity(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (pid, len) = (a[0] as u32 as i32, a[1] as usize);
    let cpus = active_cpus(c);
    let words = cpus.div_ceil(64);
    let mut bytes = vec![0u8; words * 8];
    let read = len.min(bytes.len());
    if c.mem.read(GuestAddr(a[2]), &mut bytes[..read]).is_err() {
        return err(Errno::EFAULT);
    }
    let mut mask: Vec<u64> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| u64::from_le_bytes(*word))
        .collect();
    // Only the CPUs the host has.
    if cpus % 64 != 0
        && let Some(last) = mask.last_mut()
    {
        *last &= (1u64 << (cpus % 64)) - 1;
    }
    // The mask is read first (EFAULT), then the thread found (ESRCH), and
    // only then is an empty mask refused (EINVAL), as in Linux.
    let (tid, other) = match affinity_target(c, pid) {
        Ok(target) => target,
        Err(e) => return err(e),
    };
    if mask.iter().all(|&word| word == 0) {
        return err(Errno::EINVAL);
    }
    other.as_deref().unwrap_or(c.group).set_affinity(tid, mask);
    ok(0)
}

/// `getcpu(cpu, node, cache)`: the CPU the thread runs on, the lowest its
/// mask allows, and NUMA node 0, each written where its pointer is not NULL;
/// `EFAULT` when one cannot be written, as Linux, which still writes the
/// other. The cache is ignored, as on Linux.
fn sys_getcpu(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let cpu = c.group.affinity(c.tid).map_or(0, |set| {
        set.iter()
            .enumerate()
            .find(|(_, word)| **word != 0)
            .map_or(0, |(index, word)| {
                index * 64 + word.trailing_zeros() as usize
            })
    }) as u32;
    let mut failed = false;
    for (address, value) in [(a[0], cpu), (a[1], 0)] {
        if address != 0 {
            failed |= c
                .mem
                .write(GuestAddr(address), &value.to_le_bytes())
                .is_err();
        }
    }
    if failed { err(Errno::EFAULT) } else { ok(0) }
}

/// `READ_IMPLIES_EXEC`, which makes readable mappings executable.
pub(crate) const READ_IMPLIES_EXEC: u32 = 0x40_0000;
/// The personality flags a set-ID exec clears (`PER_CLEAR_ON_SETID`):
/// `READ_IMPLIES_EXEC`, `ADDR_NO_RANDOMIZE`, `ADDR_COMPAT_LAYOUT` and
/// `MMAP_PAGE_ZERO`.
pub(crate) const PER_CLEAR_ON_SETID: u32 = 0x40_0000 | 0x4_0000 | 0x20_0000 | 0x10_0000;
const UNAME26: u32 = 0x2_0000;
const PER_LINUX32: u32 = 0x8;

/// A readable mapping is also executable under `READ_IMPLIES_EXEC`, as
/// Linux's `do_mmap` and `mprotect` make it.
fn read_implies_exec(state: &ThreadState, prot: Prot) -> Prot {
    if state.personality & READ_IMPLIES_EXEC != 0 && prot.contains(Prot::READ) {
        prot.union(Prot::EXEC)
    } else {
        prot
    }
}

/// `personality(persona)`: the thread's personality, which becomes
/// `persona` unless that is `0xffffffff`, as Linux stores it whatever it
/// is. `PER_LINUX32` and `UNAME26` change what `uname` reports and
/// `READ_IMPLIES_EXEC` what `mmap` and `mprotect` map; the other flags are
/// kept and reported only (the layout does not change, and is not
/// randomized to begin with).
fn sys_personality(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let old = c.process.personality;
    let persona = a[0] as u32;
    if persona != u32::MAX {
        c.process.personality = persona;
    }
    ok(u64::from(old))
}

/// The thread `pid` names for the `sched_get*` calls (Linux's
/// `find_process_by_pid`): 0 is the caller, a negative one is `EINVAL`, and
/// one of no live thread `ESRCH`.
fn sched_target(c: &Context<'_>, pid: u64) -> Result<(), Errno> {
    let pid = pid as u32 as i32;
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    affinity_target(c, pid).map(drop)
}

/// `sched_getscheduler(pid)`: every thread runs under `SCHED_OTHER` (0), as
/// `sched_setscheduler` is not offered.
fn sys_sched_getscheduler(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match sched_target(c, a[0]) {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}

/// `sched_getparam(pid, param)`: a `struct sched_param` whose priority is
/// 0, as for every thread not under a real-time policy. A NULL `param` is
/// `EINVAL` before the thread is looked for, as in Linux.
fn sys_sched_getparam(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[1] == 0 {
        return err(Errno::EINVAL);
    }
    if let Err(e) = sched_target(c, a[0]) {
        return err(e);
    }
    match c.mem.write(GuestAddr(a[1]), &0i32.to_le_bytes()) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

/// `sched_get_priority_max(policy)` and `sched_get_priority_min(policy)`:
/// 99 and 1 for `SCHED_FIFO` and `SCHED_RR`, 0 for `SCHED_OTHER`,
/// `SCHED_BATCH`, `SCHED_IDLE`, `SCHED_DEADLINE` and `SCHED_EXT`, and
/// `EINVAL` for anything else, as Linux.
fn sys_sched_get_priority(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let maximum = c.number == nr::SCHED_GET_PRIORITY_MAX;
    match a[0] as u32 as i32 {
        1 | 2 => ok(if maximum { 99 } else { 1 }),
        0 | 3 | 5 | 6 | 7 => ok(0),
        _ => err(Errno::EINVAL),
    }
}

/// `sched_rr_get_interval(pid, interval)`: the time slice of a thread
/// under `SCHED_OTHER`, as Linux's `get_rr_interval_fair` gives it in
/// whole jiffies: the host's own where it can tell ([`Host::time_slice`]),
/// or else Linux's default at 1000 Hz, the base slice of 0.75 ms times
/// 1 + log2 of the CPUs (at most 8).
fn sys_sched_rr_get_interval(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if let Err(e) = sched_target(c, a[0]) {
        return err(e);
    }
    let slice = c.host.time_slice().unwrap_or_else(|| {
        let factor = 1 + u64::from(active_cpus(c).min(8).ilog2());
        750_000 * factor / 1_000_000 * 1_000_000
    });
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(slice / 1_000_000_000).to_le_bytes());
    bytes[8..].copy_from_slice(&(slice % 1_000_000_000).to_le_bytes());
    match c.mem.write(GuestAddr(a[1]), &bytes) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

/// `membarrier(cmd, flags, cpu_id)`, as Linux's on x86-64 with `CONFIG_RSEQ`
/// and no `nohz_full` CPUs: the commands, the `MEMBARRIER_CMD_FLAG_CPU`
/// flag only for `PRIVATE_EXPEDITED_RSEQ`, the registrations each private
/// command needs (`EPERM` without), and `GET_REGISTRATIONS` reporting them
/// with Linux's bits of state, one set for the address space, which a
/// fork copies and an exec starts without. Each barrier is a host fence:
/// every guest memory access already takes its address space's lock,
/// which orders it with the other threads' accesses as a barrier on each
/// would.
fn sys_membarrier(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    use std::sync::atomic::{Ordering, fence};
    const QUERY: i32 = 0;
    const GLOBAL: i32 = 1;
    const GLOBAL_EXPEDITED: i32 = 1 << 1;
    const REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
    const PRIVATE_EXPEDITED: i32 = 1 << 3;
    const REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
    const PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
    const REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
    const PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
    const REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
    const GET_REGISTRATIONS: i32 = 1 << 9;
    const FLAG_CPU: u32 = 1;
    // Linux's MEMBARRIER_STATE_* bits: each registration's "ready" bit is
    // the one below its own.
    const PRIVATE_READY: u32 = 1;
    const PRIVATE: u32 = 1 << 1;
    const GLOBAL_READY: u32 = 1 << 2;
    const GLOBAL_STATE: u32 = 1 << 3;
    const SYNC_CORE_READY: u32 = 1 << 4;
    const SYNC_CORE: u32 = 1 << 5;
    const RSEQ_READY: u32 = 1 << 6;
    const RSEQ: u32 = 1 << 7;
    let (cmd, flags) = (a[0] as u32 as i32, a[1] as u32);
    let allowed = if cmd == PRIVATE_EXPEDITED_RSEQ {
        FLAG_CPU
    } else {
        0
    };
    if flags & !allowed != 0 {
        return err(Errno::EINVAL);
    }
    let state = c.mem.membarrier_state();
    let register = |set: u32, ready: u32| {
        if state.load(Ordering::SeqCst) & ready != ready {
            state.fetch_or(set, Ordering::SeqCst);
            state.fetch_or(ready, Ordering::SeqCst);
        }
        ok(0)
    };
    let barrier = |ready: u32| {
        if state.load(Ordering::SeqCst) & ready == 0 {
            return err(Errno::EPERM);
        }
        fence(Ordering::SeqCst);
        ok(0)
    };
    match cmd {
        QUERY => ok(0x3ff),
        GLOBAL | GLOBAL_EXPEDITED => {
            fence(Ordering::SeqCst);
            ok(0)
        }
        REGISTER_GLOBAL_EXPEDITED => register(GLOBAL_STATE, GLOBAL_READY),
        PRIVATE_EXPEDITED => barrier(PRIVATE_READY),
        REGISTER_PRIVATE_EXPEDITED => register(PRIVATE, PRIVATE_READY),
        PRIVATE_EXPEDITED_SYNC_CORE => barrier(SYNC_CORE_READY),
        REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => register(PRIVATE | SYNC_CORE, SYNC_CORE_READY),
        PRIVATE_EXPEDITED_RSEQ => barrier(RSEQ_READY),
        REGISTER_PRIVATE_EXPEDITED_RSEQ => register(PRIVATE | RSEQ, RSEQ_READY),
        GET_REGISTRATIONS => {
            let state = state.load(Ordering::SeqCst);
            let registrations = [
                (GLOBAL_STATE | GLOBAL_READY, REGISTER_GLOBAL_EXPEDITED),
                (PRIVATE | PRIVATE_READY, REGISTER_PRIVATE_EXPEDITED),
                (
                    SYNC_CORE | SYNC_CORE_READY,
                    REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                ),
                (RSEQ | RSEQ_READY, REGISTER_PRIVATE_EXPEDITED_RSEQ),
            ];
            let mask = registrations
                .iter()
                .filter(|(bits, _)| state & bits != 0)
                .fold(0, |mask, (_, command)| mask | command);
            ok(mask as u64)
        }
        _ => err(Errno::EINVAL),
    }
}

fn sys_set_tid_address(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    c.process.clear_child_tid = a[0];
    ok(u64::from(c.process.pid))
}
