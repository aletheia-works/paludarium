//! System-call handlers of the core emulator (plus `mprotect`, which the Rust
//! hello world calls natively).
//!
//! Every handler validates its arguments and reads or writes guest memory
//! only through the MMU; bad pointers give `-EFAULT`.

use std::collections::BTreeMap;

use paludarium_cpu::CpuState;
use paludarium_host::{ClockId, FileHandle, Host, WaitOutcome};
use paludarium_mmu::{AddressSpace, Backing, MappingKind, Placement, Prot, Remap};
use paludarium_types::{Errno, GuestAddr, USER_ADDRESS_LIMIT};

use crate::signals::SleepClock;
use crate::{AltStack, SS_DISABLE, SignalAction, ThreadState, credentials, signals};

/// Linux x86-64 system-call numbers used by the core emulator.
pub mod nr {
    pub const GETITIMER: u64 = 36;
    pub const ALARM: u64 = 37;
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
    pub const ADJTIMEX: u64 = 159;
    pub const SETTIMEOFDAY: u64 = 164;
    pub const CLOCK_SETTIME: u64 = 227;
    pub const CLOCK_ADJTIME: u64 = 305;
    pub const TIME: u64 = 201;
    pub const CLOCK_NANOSLEEP: u64 = 230;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const PKEY_MPROTECT: u64 = 329;
    pub const PKEY_ALLOC: u64 = 330;
    pub const PKEY_FREE: u64 = 331;
    pub const MSEAL: u64 = 462;
    pub const SET_MEMPOLICY_HOME_NODE: u64 = 450;
    pub const MAP_SHADOW_STACK: u64 = 453;
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
    pub const SETHOSTNAME: u64 = 170;
    pub const SETDOMAINNAME: u64 = 171;
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
    pub const SCHED_GETATTR: u64 = 315;
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
        let entries: [(u64, Handler); 90] = [
            (nr::GETITIMER, sys_getitimer),
            (nr::ALARM, sys_alarm),
            (nr::SETITIMER, sys_setitimer),
            (nr::RT_SIGRETURN, sys_rt_sigreturn),
            (nr::GETPID, sys_getpid),
            (nr::GETTID, sys_getpid),
            (nr::TKILL, sys_tkill),
            (nr::TGKILL, sys_tgkill),
            (nr::CLOCK_GETTIME, sys_clock_gettime),
            (nr::GETTIMEOFDAY, sys_gettimeofday),
            (nr::SETTIMEOFDAY, sys_settimeofday),
            (nr::CLOCK_SETTIME, sys_clock_settime),
            (nr::ADJTIMEX, sys_adjtimex),
            (nr::CLOCK_ADJTIME, sys_clock_adjtime),
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
            (nr::PKEY_MPROTECT, sys_pkey_mprotect),
            (nr::PKEY_ALLOC, sys_pkey_alloc),
            (nr::PKEY_FREE, sys_pkey_free),
            (nr::MUNMAP, sys_munmap),
            (nr::MSEAL, sys_mseal),
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
            (nr::UNAME, sys_uname),
            (nr::SETHOSTNAME, sys_sethostname),
            (nr::SETDOMAINNAME, sys_setdomainname),
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
            (nr::SCHED_GETATTR, sys_sched_getattr),
            (nr::MBIND, crate::mempolicy::sys_mbind),
            (nr::SET_MEMPOLICY, crate::mempolicy::sys_set_mempolicy),
            (nr::GET_MEMPOLICY, crate::mempolicy::sys_get_mempolicy),
            (
                nr::SET_MEMPOLICY_HOME_NODE,
                crate::mempolicy::sys_set_mempolicy_home_node,
            ),
            (nr::MAP_SHADOW_STACK, sys_map_shadow_stack),
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
        handlers.insert(284, crate::events::sys_eventfd);
        handlers.insert(216, sys_remap_file_pages);
        handlers.insert(153, crate::pty::sys_vhangup);
        handlers.insert(282, crate::signalfd::sys_signalfd);
        handlers.insert(289, crate::signalfd::sys_signalfd4);
        handlers.insert(253, crate::inotify::sys_inotify_init);
        handlers.insert(254, crate::inotify::sys_inotify_add_watch);
        handlers.insert(255, crate::inotify::sys_inotify_rm_watch);
        handlers.insert(294, crate::inotify::sys_inotify_init1);
        // Tokio's current Linux std uses GRND_INSECURE to seed its scheduler;
        // the Host random boundary supplies secure bytes without OS passthrough.
        handlers.insert(318, sys_getrandom);
        handlers.insert(29, crate::shm::sys_shmget);
        handlers.insert(30, crate::shm::sys_shmat);
        handlers.insert(31, crate::shm::sys_shmctl);
        handlers.insert(67, crate::shm::sys_shmdt);
        handlers.insert(64, crate::sem::sys_semget);
        handlers.insert(65, crate::sem::sys_semop);
        handlers.insert(66, crate::sem::sys_semctl);
        handlers.insert(220, crate::sem::sys_semtimedop);
        handlers.insert(68, crate::msg::sys_msgget);
        handlers.insert(69, crate::msg::sys_msgsnd);
        handlers.insert(70, crate::msg::sys_msgrcv);
        handlers.insert(71, crate::msg::sys_msgctl);
        handlers.insert(240, crate::mqueue::sys_mq_open);
        handlers.insert(241, crate::mqueue::sys_mq_unlink);
        handlers.insert(242, crate::mqueue::sys_mq_timedsend);
        handlers.insert(243, crate::mqueue::sys_mq_timedreceive);
        handlers.insert(244, crate::mqueue::sys_mq_notify);
        handlers.insert(245, crate::mqueue::sys_mq_getsetattr);
        handlers.insert(334, crate::rseq::sys_rseq);
        handlers.insert(317, crate::seccomp::sys_seccomp);
        handlers.insert(206, crate::aio::sys_setup);
        handlers.insert(207, crate::aio::sys_destroy);
        handlers.insert(208, crate::aio::sys_getevents);
        handlers.insert(209, crate::aio::sys_submit);
        handlers.insert(210, crate::aio::sys_cancel);
        handlers.insert(333, crate::aio::sys_pgetevents);
        handlers.insert(425, crate::io_uring::sys_setup);
        handlers.insert(426, crate::io_uring::sys_enter);
        handlers.insert(427, crate::io_uring::sys_register);
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
        for number in [213, 233, 232, 281, 291, 441] {
            handlers.insert(number, crate::epoll::dispatch);
        }
        for number in [
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307,
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

/// The clock a `clock_nanosleep` sleeps on or a `timer_create` timer runs
/// on, as Linux's `k_clock`s give them: TAI and REALTIME_ALARM on the
/// real-time clock (TAI's offset is 0), BOOTTIME and BOOTTIME_ALARM on the
/// monotonic one (this host never suspends); an alarm clock also needs
/// CAP_WAKE_ALARM ([`may_use_alarm`]). MONOTONIC_RAW and the coarse clocks
/// can only be read (`EOPNOTSUPP`), as can the thread's CPU clock for a
/// sleep (`thread`). Unknown clocks are `EINVAL`; [`posix_timer_clock`]
/// adds the CPU clocks for timers, and [`sys_clock_nanosleep`] the
/// process's and, by number, other tasks' ([`cpu_sleep`]) for a sleep.
fn timer_clock(id: u64, thread: Errno) -> Result<ClockId, Errno> {
    match id as u32 as i32 {
        0 | 8 | 11 => Ok(ClockId::Realtime),
        1 | 7 | 9 => Ok(ClockId::Monotonic),
        3 => Err(thread),
        4..=6 => Err(Errno::EOPNOTSUPP),
        _ => Err(Errno::EINVAL),
    }
}
/// Whether `id` is an alarm clock, `CLOCK_REALTIME_ALARM` or
/// `CLOCK_BOOTTIME_ALARM`.
fn is_alarm(id: u64) -> bool {
    matches!(id as u32 as i32, 8 | 9)
}
/// Whether the caller may sleep or set a timer on an alarm clock, which
/// can wake the machine: CAP_WAKE_ALARM, as Linux's `alarm_timer_create`
/// and `alarm_timer_nsleep` ask (`EPERM`). Linux gives `EOPNOTSUPP` first
/// with no RTC that can wake it; the CI runners have one (`rtc_cmos`), and
/// so does the machine here.
pub(crate) fn may_use_alarm(c: &Context<'_>) -> Result<(), Errno> {
    if c.process
        .credentials
        .capable(crate::credentials::CAP_WAKE_ALARM)
    {
        Ok(())
    } else {
        Err(Errno::EPERM)
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
/// What a `clockid_t` reads: a host clock, the time of its latest tick, or
/// the CPU time of this process or thread or of another. MONOTONIC_RAW,
/// BOOTTIME (this host never suspends), the two alarm clocks and TAI (with a
/// TAI offset of 0, as Linux has until NTP sets one) read the monotonic and
/// real-time clocks.
enum GuestClock {
    Host(ClockId),
    /// `CLOCK_REALTIME_COARSE` and `CLOCK_MONOTONIC_COARSE`: the time Linux's
    /// timekeeping took at the latest tick, which the vDSO and `time()`
    /// give without reading the clock source. The tick is Linux's
    /// `TICK_NSEC`, the host's ([`scheduler_slice`]).
    Coarse(ClockId),
    ProcessCpu,
    ThreadCpu,
    /// Another process's CPU time, its threads' together.
    OtherProcessCpu(std::sync::Arc<crate::ThreadGroup>),
    /// The CPU time of another thread of this process.
    OtherThreadCpu(u32),
}
/// The clock `id`, a `clockid_t` (an `int`, as Linux's system calls take
/// it), for `clock_gettime` (`gettime`) or another call.
fn guest_clock(c: &Context<'_>, id: u64, gettime: bool) -> Result<GuestClock, Errno> {
    Ok(match id as u32 as i32 {
        0 | 8 | 11 => GuestClock::Host(ClockId::Realtime),
        1 | 4 | 7 | 9 => GuestClock::Host(ClockId::Monotonic),
        5 => GuestClock::Coarse(ClockId::Realtime),
        6 => GuestClock::Coarse(ClockId::Monotonic),
        2 => GuestClock::ProcessCpu,
        3 => GuestClock::ThreadCpu,
        id if id < 0 => cpu_clock(c, id, gettime)?,
        _ => return Err(Errno::EINVAL),
    })
}
/// Linux's `CPUCLOCK_WHICH` of a CPU clock that is `CPUCLOCK_SCHED`, the
/// time a task has run, which `clock_getres` gives to the nanosecond.
const CPUCLOCK_SCHED: i32 = 2;
/// A negative `clockid_t`, as Linux's `pid_for_clock` takes it apart: the
/// task's number in the caller's PID namespace (`~id >> 3`, 0 for the
/// caller), a thread's clock (bit 2) or a process's, and which time (the
/// low two bits: `CPUCLOCK_PROF`, `CPUCLOCK_VIRT` or `CPUCLOCK_SCHED`, all
/// the same time here, which counts it all as user time). `EINVAL` for a
/// dynamic clock (`CLOCKFD`, 3: no file here is one), the fourth kind,
/// no such task, a thread of another process, or a task that is not a
/// process, except the caller's own thread as a process clock for
/// `clock_gettime`.
fn cpu_clock(c: &Context<'_>, id: i32, gettime: bool) -> Result<GuestClock, Errno> {
    if id & 3 == 3 {
        return Err(Errno::EINVAL);
    }
    let thread = id & 4 != 0;
    let number = !(id >> 3) as u32;
    if number == 0 {
        return Ok(if thread {
            GuestClock::ThreadCpu
        } else {
            GuestClock::ProcessCpu
        });
    }
    let tid = c.pid_space().task(number).ok_or(Errno::EINVAL)?;
    if thread {
        return match tid {
            tid if tid == c.tid => Ok(GuestClock::ThreadCpu),
            tid if c.group.has_member(tid) => Ok(GuestClock::OtherThreadCpu(tid)),
            _ => Err(Errno::EINVAL),
        };
    }
    if tid == c.process.pid || gettime && tid == c.tid {
        return Ok(GuestClock::ProcessCpu);
    }
    c.processes
        .view(tid)
        .map(|view| GuestClock::OtherProcessCpu(view.group))
        .ok_or(Errno::EINVAL)
}
fn read_clock(c: &mut Context<'_>, clock: GuestClock) -> Result<u64, Errno> {
    let thread = crate::account_cpu(c.host, c.group, c.process, c.tid);
    match clock {
        GuestClock::Host(id) => c.host.clock(id),
        // The ticks fall on whole multiples of the tick on the monotonic
        // clock, and the real-time clock takes its time at the same instant,
        // as Linux's timekeeping updates both at each tick.
        GuestClock::Coarse(id) => {
            let tick = scheduler_slice(c.host).tick;
            let mono = c.host.clock(ClockId::Monotonic)?;
            let since = mono % tick;
            match id {
                ClockId::Monotonic => Ok(mono - since),
                ClockId::Realtime => c.host.clock(id).map(|now| now.saturating_sub(since)),
            }
        }
        GuestClock::ProcessCpu => Ok(c.group.process_cpu()),
        GuestClock::ThreadCpu => Ok(thread),
        GuestClock::OtherProcessCpu(group) => Ok(group.process_cpu()),
        // A thread that has exited since is no task (`EINVAL`).
        GuestClock::OtherThreadCpu(tid) => c.group.thread_cpu(tid).ok_or(Errno::EINVAL),
    }
}
fn sys_clock_gettime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = guest_clock(c, a[0], true)
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
/// The latest seconds `settimeofday` and `clock_settime` take, as Linux's
/// `TIME_SETTOD_SEC_MAX`: 30 years short of `KTIME_SEC_MAX`.
const TIME_SETTOD_SEC_MAX: u64 = i64::MAX as u64 / 1_000_000_000 - 30 * 365 * 24 * 3600;

/// Checks a time to set the real-time clock to, as Linux's
/// `do_sys_settimeofday64`: `EINVAL` for one it does not take, and else
/// `EPERM`. The session never sets the time, as a container whose
/// capabilities leave out `CAP_SYS_TIME` cannot, whatever the caller's
/// capabilities.
fn set_time_of_day(time: Option<(u64, u64)>) -> Errno {
    match time {
        Some((seconds, nanos))
            if (seconds as i64) < 0 || nanos >= 1_000_000_000 || seconds >= TIME_SETTOD_SEC_MAX =>
        {
            Errno::EINVAL
        }
        _ => Errno::EPERM,
    }
}

/// `settimeofday(tv, tz)`, in Linux's order: the time is read and its
/// microseconds checked, then the time zone read, then the time checked
/// ([`set_time_of_day`]); the time zone is not looked at. 1,000,000
/// microseconds is refused at once, as Linux master has since
/// ce4abda5e126 (2026-06); earlier kernels read the time zone first.
fn sys_settimeofday(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let time = if a[0] == 0 {
            None
        } else {
            let [seconds, micros] = read_words::<2>(c.mem, a[0])?;
            if micros >= 1_000_000 {
                return Err(Errno::EINVAL);
            }
            Some((seconds, micros * 1000))
        };
        if a[1] != 0 {
            read_words::<1>(c.mem, a[1])?;
        }
        Err(set_time_of_day(time))
    })())
}

/// `clock_settime(clock, tp)`: only `CLOCK_REALTIME` can be set, as on
/// Linux, and the time is then checked as `settimeofday`'s; the other
/// clocks give `EINVAL` before the time is read.
fn sys_clock_settime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[0] as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        let [seconds, nanos] = read_words::<2>(c.mem, a[1])?;
        Err(set_time_of_day(Some((seconds, nanos))))
    })())
}

/// The size of Linux's `struct __kernel_timex`.
const TIMEX_SIZE: usize = 208;

/// Reads the real-time clock's NTP state into `timex`, as Linux's
/// `do_adjtimex`, after checking its `modes` as `timekeeping_validate_timex`
/// does: only reads are taken (no mode, or `ADJ_OFFSET_SS_READ`), and the
/// others give `EPERM` ([`set_time_of_day`]). The state is the one Linux
/// starts with, as nothing here disciplines the clock and the host's is not
/// revealed: unsynchronised (`STA_UNSYNC`, so the result is `TIME_ERROR`),
/// with the errors at `NTP_PHASE_LIMIT`, no offset or frequency correction,
/// a time constant of 2, a tick of `USER_TICK_USEC`, no PPS and no TAI
/// offset. The time is the real-time clock's, in microseconds.
fn read_timex(c: &Context<'_>, timex: &mut [u8; TIMEX_SIZE]) -> Result<u64, Errno> {
    const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
    const ADJ_FREQUENCY: u32 = 0x0002;
    const ADJ_SETOFFSET: u32 = 0x0100;
    const ADJ_OFFSET_READONLY: u32 = 0x2000;
    const ADJ_ADJTIME: u32 = 0x8000;
    // Linux's PPM_SCALE: 1000 << (NTP_SCALE_SHIFT - SHIFT_USEC).
    const PPM_SCALE: i64 = 1000 << 16;
    let word = |at: usize| i64::from_le_bytes(timex[at..at + 8].try_into().unwrap_or_default());
    let modes = u32::from_le_bytes(timex[..4].try_into().unwrap_or_default());
    if modes & ADJ_ADJTIME != 0 {
        if modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return Err(Errno::EINVAL);
        }
        if modes & ADJ_OFFSET_READONLY == 0 {
            return Err(Errno::EPERM);
        }
    } else if modes != 0 {
        return Err(Errno::EPERM);
    }
    if modes & ADJ_SETOFFSET != 0 {
        return Err(Errno::EPERM);
    }
    let freq = word(16);
    if modes & ADJ_FREQUENCY != 0 && !(i64::MIN / PPM_SCALE..=i64::MAX / PPM_SCALE).contains(&freq)
    {
        return Err(Errno::EINVAL);
    }
    let now = c.host.clock(ClockId::Realtime)?;
    let mut put = |at: usize, value: i64| timex[at..at + 8].copy_from_slice(&value.to_le_bytes());
    let longs: [(usize, i64); 16] = [
        (8, 0),           // offset
        (16, 0),          // freq
        (24, 16_000_000), // maxerror: NTP_PHASE_LIMIT
        (32, 16_000_000), // esterror
        (48, 2),          // constant
        (56, 1),          // precision
        (64, 32_768_000), // tolerance: MAXFREQ_SCALED / PPM_SCALE
        (72, (now / 1_000_000_000) as i64),
        (80, (now % 1_000_000_000 / 1000) as i64),
        (88, 10_000), // tick: USER_TICK_USEC
        (96, 0),      // ppsfreq
        (104, 0),     // jitter
        (120, 0),     // stabil
        (128, 0),     // jitcnt
        (136, 0),     // calcnt
        (144, 0),     // errcnt
    ];
    for (at, value) in longs {
        put(at, value);
    }
    put(152, 0); // stbcnt
    timex[40..44].copy_from_slice(&0x40i32.to_le_bytes()); // status: STA_UNSYNC
    timex[112..116].fill(0); // shift
    timex[160..164].fill(0); // tai
    Ok(5) // TIME_ERROR
}

/// `adjtimex(buf)` ([`read_timex`]). As Linux's, it writes the structure
/// back whatever the result, so a buffer it cannot write gives `EFAULT`.
fn sys_adjtimex(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let mut timex = [0u8; TIMEX_SIZE];
        c.mem
            .read(GuestAddr(a[0]), &mut timex)
            .map_err(|_| Errno::EFAULT)?;
        let result = read_timex(c, &mut timex);
        c.mem
            .write(GuestAddr(a[0]), &timex)
            .map_err(|_| Errno::EFAULT)?;
        result
    })())
}

/// `clock_adjtime(clock, buf)`: the structure is read first, then the
/// clock looked at. `CLOCK_REALTIME` is [`read_timex`], written back
/// unless it fails; the other clocks Linux knows give `EOPNOTSUPP`, as do
/// the CPU clocks of other processes and threads, and a clock file
/// descriptor (none is a PTP clock here, and Linux's `get_clock_desc` gives
/// `EINVAL` for a closed one too) and unknown clocks `EINVAL`.
fn sys_clock_adjtime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let mut timex = [0u8; TIMEX_SIZE];
        c.mem
            .read(GuestAddr(a[1]), &mut timex)
            .map_err(|_| Errno::EFAULT)?;
        match a[0] as u32 as i32 {
            0 => {}
            // CLOCKFD.
            id if id < 0 && id & 7 == 3 => return Err(Errno::EINVAL),
            id if id < 0 => return Err(Errno::EOPNOTSUPP),
            1..=9 | 11 => return Err(Errno::EOPNOTSUPP),
            _ => return Err(Errno::EINVAL),
        }
        let result = read_timex(c, &mut timex)?;
        c.mem
            .write(GuestAddr(a[1]), &timex)
            .map_err(|_| Errno::EFAULT)?;
        Ok(result)
    })())
}

/// `time(t)`: the seconds of the real time clock as of the latest tick, as
/// Linux's `ktime_get_real_seconds` gives the timekeeper's `xtime_sec`
/// (`CLOCK_REALTIME_COARSE`'s), also at `t` if it is not null.
fn sys_time(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = read_clock(c, GuestClock::Coarse(ClockId::Realtime)).and_then(|now| {
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
/// give, except the coarse ones, which move by the host's tick
/// ([`scheduler_slice`]), and the CPU clocks Linux counts by ticks
/// (`CPUCLOCK_PROF`, `CPUCLOCK_VIRT`), a tick; a `CPUCLOCK_SCHED` one, as
/// `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID`, 1 ns.
/// A CPU clock of another task must name a process, or a thread of the
/// caller's ([`cpu_clock`]).
fn sys_clock_getres(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = guest_clock(c, a[0], false).and_then(|clock| {
        if a[1] == 0 {
            return Ok(());
        }
        // A CPU clock that counts by ticks (CPUCLOCK_PROF, CPUCLOCK_VIRT)
        // gives a tick, as Linux's `posix_cpu_clock_getres` does.
        let id = a[0] as u32 as i32;
        let resolution = if matches!(clock, GuestClock::Coarse(_)) {
            scheduler_slice(c.host).tick
        } else if id < 0 && id & 3 != CPUCLOCK_SCHED {
            crate::threads::TICK_NSEC
        } else {
            1
        };
        write_timespec(c.mem, a[1], resolution)
    });
    match result {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}
fn sleep(c: &mut Context<'_>, clock: SleepClock, absolute: bool, req: u64, rem: u64) -> Outcome {
    let request = match read_timespec(c.mem, req) {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let now = match sleep_clock_now(c, clock) {
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

/// The time of the clock a sleep counts on; the process's CPU time takes
/// in the caller's first.
fn sleep_clock_now(c: &mut Context<'_>, clock: SleepClock) -> Result<u64, Errno> {
    match clock {
        SleepClock::Host(id) => c.host.clock(id),
        SleepClock::ProcessCpu => {
            crate::account_cpu(c.host, c.group, c.process, c.tid);
            Ok(c.group.process_cpu())
        }
    }
}

/// Sleeps on `clock` until `deadline`. A signal ends it with EINTR, writing
/// the time left to `rem` for a relative sleep; a stop then resumes it, as
/// Linux does: a relative sleep through `restart_syscall` with the same
/// deadline, an absolute one by running the call again.
///
/// On the process's CPU clock the other threads account their CPU time at
/// each checkpoint while the sleep lasts, and the sleep looks at the total
/// every tick ([`scheduler_slice`]), as Linux's tick checks the timer its
/// `do_cpu_nanosleep` arms. A signal that comes once the deadline has
/// passed ends the sleep with 0, as Linux finds its timer fired.
fn sleep_until(
    c: &mut Context<'_>,
    clock: SleepClock,
    absolute: bool,
    deadline: u64,
    rem: u64,
) -> Outcome {
    let group = c.group;
    let _sleeping = (clock == SleepClock::ProcessCpu).then(|| group.cpu_sleep());
    loop {
        let timer_generation = c.group.timer_generation();
        let clock_now = match sleep_clock_now(c, clock) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        // Linux fires a CPU timer set to a time that has passed at once.
        if clock == SleepClock::ProcessCpu && clock_now >= deadline {
            return ok(0);
        }
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
            match clock {
                SleepClock::Host(id) => {
                    let timer_deadline = signals::next_deadline(c.process)
                        .and_then(|d| clock_now.checked_add(d.saturating_sub(mono_now)));
                    let next = timer_deadline.map_or(deadline, |t| deadline.min(t));
                    c.host.wait_until(id, next, c.cancellation)
                }
                SleepClock::ProcessCpu => {
                    let tick = mono_now.saturating_add(scheduler_slice(c.host).tick);
                    let next = signals::next_deadline(c.process).map_or(tick, |t| tick.min(t));
                    // A wait the tick ends is complete, and the deadline is
                    // checked below.
                    c.host.wait_until(ClockId::Monotonic, next, c.cancellation)
                }
            }
        };
        let received = c.inbox.drain(c.process);
        let sent = c.group.drain_process(c.process);
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
                if (received.signals || sent)
                    && !pending
                    && !interrupted
                    && c.group.status().is_none() =>
            {
                continue;
            }
            Ok(WaitOutcome::Complete) if !pending && !interrupted && c.group.status().is_none() => {
                if sleep_clock_now(c, clock).is_ok_and(|now| now < deadline) {
                    continue;
                }
                return ok(0);
            }
            Ok(WaitOutcome::Complete) | Ok(WaitOutcome::Interrupted) => {
                let now = sleep_clock_now(c, clock).unwrap_or(deadline);
                if clock == SleepClock::ProcessCpu && now >= deadline {
                    return ok(0);
                }
                if !absolute
                    && rem != 0
                    && let Err(e) = write_timespec(c.mem, rem, deadline.saturating_sub(now))
                {
                    return err(e);
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
/// Linux's `KTIME_MAX`, where its times stop.
const KTIME_MAX: u64 = i64::MAX as u64;
/// A `struct timeval` as nanoseconds: `EINVAL` where Linux's `timeval_valid`
/// refuses it, and `KTIME_MAX` for one past it, as `ktime_set` clamps.
fn read_timeval(sec: u64, usec: u64) -> Result<u64, Errno> {
    if (sec as i64) < 0 || usec >= 1_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(if sec >= KTIME_MAX / 1_000_000_000 {
        KTIME_MAX
    } else {
        sec * 1_000_000_000 + usec * 1000
    })
}
/// `ITIMER_REAL`, the interval timer of the process's real time.
const ITIMER_REAL: i32 = 0;
/// `ITIMER_VIRTUAL` and `ITIMER_PROF`, of its CPU time (user time, and user
/// and system time, which are the same here).
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;

/// `struct itimerval` words for an interval and the time left, the
/// microseconds cut down as Linux's `put_itimerval` does.
fn itimerval(interval: u64, remaining: u64) -> [u64; 4] {
    [
        interval / 1_000_000_000,
        interval % 1_000_000_000 / 1000,
        remaining / 1_000_000_000,
        remaining % 1_000_000_000 / 1000,
    ]
}

/// A CPU-time interval timer's interval and time left as `struct
/// itimerval` words. The time left is taken as signed, as Linux's
/// `ns_to_timespec64` takes it: one set past `KTIME_MAX` shows negative
/// seconds, and nanoseconds since then.
fn cpu_itimerval(interval: u64, remaining: u64) -> [u64; 4] {
    let [interval_sec, interval_usec, ..] = itimerval(interval, 0);
    let remaining = remaining as i64;
    let (sec, nsec) = if remaining >= 0 {
        (remaining / 1_000_000_000, remaining % 1_000_000_000)
    } else {
        let before = -(remaining + 1);
        (
            -(before / 1_000_000_000) - 1,
            999_999_999 - before % 1_000_000_000,
        )
    };
    [
        interval_sec,
        interval_usec,
        sec as u64,
        (nsec / 1000) as u64,
    ]
}

/// The CPU-time interval timer `which` names, as of the caller's CPU time
/// now, replaced by `new` (a value and an interval) when there is one.
fn swap_cpu_timer(c: &mut Context<'_>, which: i32, new: Option<(u64, u64)>) -> [u64; 4] {
    crate::account_cpu(c.host, c.group, c.process, c.tid);
    let index = usize::from(which == ITIMER_PROF);
    let (interval, remaining) = c.group.swap_cpu_timer(index, new);
    cpu_itimerval(interval, remaining)
}

/// The process's interval timer as of now, once what is due has expired,
/// replaced by `new` when there is one; what it was, as the interval and the
/// time left (Linux's `itimer_get_remtime`).
fn swap_real_timer(c: &mut Context<'_>, new: Option<(u64, u64)>) -> Result<(u64, u64), Errno> {
    let now = c.host.clock(ClockId::Monotonic)?;
    let timer = new.map(|(interval, value)| {
        // A disarmed timer keeps no interval, and an expiry is no later
        // than KTIME_MAX, as Linux's `ktime_add_safe` makes it.
        match value {
            0 => signals::RealTimer::default(),
            value => signals::RealTimer {
                deadline: Some(now.saturating_add(value).min(KTIME_MAX)),
                interval,
            },
        }
    });
    let old = c.group.swap_timer(c.process, now, timer);
    Ok((
        old.interval,
        // An armed timer whose time is up has 1 µs left, as Linux's
        // `itimer_get_remtime`; less than 1 µs left is cut down to 0 later.
        old.deadline
            .map_or(0, |deadline| match deadline.saturating_sub(now) {
                0 => 1000,
                left => left,
            }),
    ))
}

/// `getitimer(which, value)`, as Linux's: `EINVAL` for a timer that is none
/// of the three, then `EFAULT` for `value`.
fn sys_getitimer(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let words = match a[0] as i32 {
            ITIMER_REAL => {
                let (interval, remaining) = swap_real_timer(c, None)?;
                itimerval(interval, remaining)
            }
            which @ (ITIMER_VIRTUAL | ITIMER_PROF) => swap_cpu_timer(c, which, None),
            _ => return Err(Errno::EINVAL),
        };
        write_words(c.mem, a[1], &words)?;
        Ok(0)
    })())
}

/// `setitimer(which, new, old)`, in Linux's order: read the new value
/// (`EFAULT`; none disarms), check its times, then the timer (`EINVAL`),
/// set it, and only then write the old value out (`EFAULT`, the timer being
/// set already).
fn sys_setitimer(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let words = if a[1] == 0 {
            [0; 4]
        } else {
            read_words::<4>(c.mem, a[1])?
        };
        let interval = read_timeval(words[0], words[1])?;
        let value = read_timeval(words[2], words[3])?;
        let old = match a[0] as i32 {
            ITIMER_REAL => {
                let (old_interval, remaining) = swap_real_timer(c, Some((interval, value)))?;
                itimerval(old_interval, remaining)
            }
            which @ (ITIMER_VIRTUAL | ITIMER_PROF) => {
                swap_cpu_timer(c, which, Some((value, interval)))
            }
            _ => return Err(Errno::EINVAL),
        };
        if a[2] != 0 {
            write_words(c.mem, a[2], &old)?;
        }
        Ok(0)
    })())
}

/// `alarm(seconds)`: Linux's `alarm_setitimer`, which sets the real-time
/// timer to `seconds` with no interval (0 disarms it) and returns the
/// seconds that were left, rounded to the nearest and at least 1 while the
/// timer was armed.
fn sys_alarm(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        let seconds = a[0] as u32;
        let (_, remaining) = swap_real_timer(c, Some((0, u64::from(seconds) * 1_000_000_000)))?;
        let (whole, nanos) = (remaining / 1_000_000_000, remaining % 1_000_000_000);
        Ok(if (whole == 0 && nanos != 0) || nanos >= 500_000_000 {
            whole + 1
        } else {
            whole
        })
    })())
}
const SIGEV_SIGNAL: u32 = 0;
const SIGEV_NONE: u32 = 1;
const SIGEV_THREAD: u32 = 2;
const SIGEV_THREAD_ID: u32 = 4;
const TIMER_ABSTIME: u64 = 1;

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// The clock of a `timer_create` timer: those of [`timer_clock`], and the
/// CPU-time clocks of the calling process and of its threads, by number
/// too ([`cpu_clock`], Linux's `posix_cpu_timer_create`). A dynamic clock
/// has no timers (`EOPNOTSUPP`). A timer on another process's CPU time is
/// expired by that process's checkpoints
/// ([`crate::ThreadGroup::watch_cpu`]).
fn posix_timer_clock(c: &Context<'_>, id: u64) -> Result<crate::timers::TimerClock, Errno> {
    use crate::timers::TimerClock;
    match id as u32 as i32 {
        2 => Ok(TimerClock::Process),
        3 => Ok(TimerClock::Thread(c.tid)),
        // A dynamic clock has no timers (`EOPNOTSUPP`).
        id if id < 0 && id & 7 == 3 => Err(Errno::EOPNOTSUPP),
        id if id < 0 => match cpu_clock(c, id, false)? {
            GuestClock::ProcessCpu => Ok(TimerClock::Process),
            GuestClock::ThreadCpu => Ok(TimerClock::Thread(c.tid)),
            GuestClock::OtherThreadCpu(tid) => Ok(TimerClock::Thread(tid)),
            // cpu_clock found the process by this number.
            GuestClock::OtherProcessCpu(_) => c
                .pid_space()
                .task(!(id >> 3) as u32)
                .map(TimerClock::OtherProcess)
                .ok_or(Errno::EINVAL),
            _ => Err(Errno::EINVAL),
        },
        _ => timer_clock(id, Errno::EINVAL).map(|clock| match clock {
            ClockId::Realtime => TimerClock::Realtime,
            ClockId::Monotonic => TimerClock::Monotonic,
        }),
    }
}

/// `timer_create(clock, sevp, timerid)`, on the clocks
/// [`posix_timer_clock`] gives, notified by a signal to the
/// process or (SIGEV_THREAD_ID) to one of its threads, or not at all. The
/// kernel treats SIGEV_THREAD, which the C library implements itself, as
/// SIGEV_SIGNAL. Linux copies the whole 64-byte struct sigevent before it
/// looks at the clock.
fn sys_timer_create(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[1] != 0 {
            c.mem
                .check_read(GuestAddr(a[1]), 64)
                .map_err(|_| Errno::EFAULT)?;
        }
        // The task of another task's CPU clock is looked for by the
        // clock's own check (`posix_cpu_timer_create`), after the ID is
        // out; every other clock is known or not first.
        let id_value = a[0] as u32 as i32;
        let clock = match posix_timer_clock(c, a[0]) {
            Err(e) if !(id_value < 0 && id_value & 7 != 3) => return Err(e),
            clock => clock,
        };
        let (signal, value, thread) = if a[1] == 0 {
            (Some(14), None, None) // SIGALRM, with the timer ID as its value
        } else {
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
        let id = c.group.with_timers(c.process, |timers| {
            timers.create(crate::timers::PosixTimer {
                clock: clock.unwrap_or_default(),
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
        // The ID is written out before the clock's own check, and a timer
        // that fails either has used its ID up, as Linux's
        // `do_timer_create` has.
        let created = c
            .mem
            .write(GuestAddr(a[2]), &id.to_le_bytes())
            .map_err(|_| Errno::EFAULT)
            .and_then(|()| {
                if is_alarm(a[0]) {
                    may_use_alarm(c)
                } else {
                    clock.map(|_| ())
                }
            });
        if let Err(e) = created {
            c.group.with_timers(c.process, |timers| timers.delete(id))?;
            return Err(e);
        }
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

/// A CPU-time timer's interval and time left at `now`, as Linux's
/// `__posix_cpu_timer_get`: an expiry that has come shows 1 ns left while
/// its signal is to come, and none for `SIGEV_NONE`, whose interval timer,
/// never armed, is moved on past `now` here instead (`bump_cpu_timer`).
fn cpu_timer_left(timer: &mut crate::timers::PosixTimer, now: u64) -> u64 {
    let Some(expires) = timer.deadline else {
        return 0;
    };
    let expires = match timer.interval {
        interval if interval != 0 && timer.signal.is_none() && now >= expires => {
            let n = (now - expires) / interval + 1;
            let next = n
                .checked_mul(interval)
                .and_then(|delta| expires.checked_add(delta))
                .unwrap_or(u64::MAX);
            timer.deadline = Some(next);
            next
        }
        _ => expires,
    };
    if now < expires {
        expires - now
    } else {
        u64::from(timer.signal.is_some())
    }
}

/// `struct timespec` as Linux's `timespec64_to_ktime` takes it to
/// nanoseconds, clamped to `KTIME_MAX`.
fn timespec_ktime(seconds: u64, nanos: u64) -> Result<u64, Errno> {
    const KTIME_SEC_MAX: u64 = i64::MAX as u64 / 1_000_000_000;
    if (seconds as i64) < 0 || nanos >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(if seconds >= KTIME_SEC_MAX {
        i64::MAX as u64
    } else {
        seconds * 1_000_000_000 + nanos
    })
}

fn timer_id(value: u64) -> i32 {
    value as u32 as i32
}

/// The time of a POSIX timer's clock ([`crate::ThreadGroup::timer_clock_now`]),
/// another process's CPU time too: `ESRCH` once that process is reaped, as
/// Linux's `timer_lock_sighand` finds no task.
fn timer_clock_now(
    c: &Context<'_>,
    clock: crate::timers::TimerClock,
    mono: u64,
) -> Result<u64, Errno> {
    match clock {
        crate::timers::TimerClock::OtherProcess(pid) => c
            .processes
            .view(pid)
            .map(|view| view.group.process_cpu())
            .ok_or(Errno(3)),
        clock => c.group.timer_clock_now(clock, mono),
    }
}
/// The clock of timer `id`, which a CPU-time timer's time is sampled on
/// before the timers are locked.
fn timer_clock_of(c: &Context<'_>, id: i32) -> Result<crate::timers::TimerClock, Errno> {
    c.group
        .timers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(id)
        .map(|timer| timer.clock)
}

/// `timer_settime` on a CPU-time clock, as Linux's `posix_cpu_timer_set`:
/// the value is taken in the clock's time, relative to `now` unless
/// TIMER_ABSTIME is given, and the old value is what
/// `__posix_cpu_timer_get` gives, with the interval the timer had. An
/// expiry that has already come sends the signal at the next checkpoint.
fn set_cpu_timer(
    timer: &mut crate::timers::PosixTimer,
    flags: u64,
    [i_sec, i_nsec, v_sec, v_nsec]: [u64; 4],
    now: u64,
) -> Result<[u64; 4], Errno> {
    let (interval, value) = (
        timespec_ktime(i_sec, i_nsec)?,
        timespec_ktime(v_sec, v_nsec)?,
    );
    let old = itimerspec(timer.interval, cpu_timer_left(timer, now));
    timer.deadline = (value != 0).then(|| {
        if flags & TIMER_ABSTIME != 0 {
            value
        } else {
            value.saturating_add(now)
        }
    });
    timer.interval = if value == 0 { 0 } else { interval };
    timer.overrun = 0;
    Ok(old)
}

/// `timer_settime(id, flags, new, old)`, in Linux's order: read and check the
/// new value, find the timer, set it, then write the old value out. As
/// Linux's `common_timer_set`, it looks at no flag but `TIMER_ABSTIME`, takes
/// the value and the interval up to `KTIME_MAX`, and a relative expiry past
/// it stops there (`ktime_add_safe`), on the monotonic clock for both clocks.
fn sys_timer_settime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome((|| {
        if a[2] == 0 {
            return Err(Errno::EINVAL);
        }
        let new = read_words::<4>(c.mem, a[2])?;
        let [i_sec, i_nsec, v_sec, v_nsec] = new;
        let interval = timespec_ktime(i_sec, i_nsec)?;
        let value = timespec_ktime(v_sec, v_nsec)?;
        let mono = c.host.clock(ClockId::Monotonic)?;
        let real = c.host.clock(ClockId::Realtime)?;
        let clock = timer_clock_of(c, timer_id(a[0]))?;
        if clock.is_cpu() {
            crate::account_cpu(c.host, c.group, c.process, c.tid);
            let now = timer_clock_now(c, clock, mono)?;
            let old = c.group.with_timers(c.process, |timers| {
                set_cpu_timer(timers.get_mut(timer_id(a[0]))?, a[1], new, now)
            })?;
            // Another process's checkpoints expire a timer on its CPU time.
            if let crate::timers::TimerClock::OtherProcess(pid) = clock
                && value != 0
                && let (Some(target), Some(own)) =
                    (c.processes.view(pid), c.processes.view(c.process.pid))
            {
                target.group.watch_cpu(pid, &own.group);
            }
            if a[3] != 0 {
                write_words(c.mem, a[3], &old)?;
            }
            return Ok(0);
        }
        let old = c.group.with_timers(c.process, |timers| {
            let timer = timers.get_mut(timer_id(a[0]))?;
            let old = timer_state(timer, mono);
            let now = if timer.clock == crate::timers::TimerClock::Realtime {
                real
            } else {
                mono
            };
            timer.deadline = (value != 0).then(|| {
                let delay = if a[1] & TIMER_ABSTIME != 0 {
                    value.saturating_sub(now)
                } else {
                    value.min((i64::MAX as u64).saturating_sub(mono))
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
        let clock = timer_clock_of(c, timer_id(a[0]))?;
        // A CPU-time timer shows nothing once it is disarmed, or once the
        // thread whose clock it is has gone (Linux's `posix_cpu_timer_get`).
        let now = if clock.is_cpu() {
            crate::account_cpu(c.host, c.group, c.process, c.tid);
            timer_clock_now(c, clock, mono).ok()
        } else {
            Some(mono)
        };
        let state = c.group.with_timers(c.process, |timers| {
            timers.get_mut(timer_id(a[0])).map(|t| match now {
                _ if !clock.is_cpu() => timer_state(t, mono),
                Some(now) if t.deadline.is_some() => {
                    let left = cpu_timer_left(t, now);
                    itimerspec(t.interval, left)
                }
                _ => [0; 4],
            })
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
    sleep(c, SleepClock::Host(ClockId::Monotonic), false, a[0], a[1])
}
/// A sleep on a CPU clock named by a negative ID, as Linux's
/// `posix_cpu_nsleep` checks it: the request is read first, then the
/// caller's own thread's clock is refused (`EINVAL`), then the clock's
/// task is looked for ([`cpu_clock`], `EINVAL`). The caller's process's
/// clock sleeps as `CLOCK_PROCESS_CPUTIME_ID` does. On another task's, a
/// sleep whose time has already come (a relative 0, or an absolute time
/// the clock has reached) returns at once, as Linux's does; one that would
/// wait for that task's CPU time is not modelled (`EINVAL`).
fn cpu_sleep(c: &mut Context<'_>, id: i32, a: [u64; 6]) -> Outcome {
    let absolute = a[1] & 1 != 0;
    let request = match read_timespec(c.mem, a[2]) {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let clock = match cpu_clock(c, id, false) {
        Ok(GuestClock::ThreadCpu) | Err(_) => return err(Errno::EINVAL),
        Ok(GuestClock::ProcessCpu) => {
            return sleep(c, SleepClock::ProcessCpu, absolute, a[2], a[3]);
        }
        Ok(clock) => clock,
    };
    let due = match read_clock(c, clock) {
        Ok(now) if absolute => request <= now,
        Ok(_) => request == 0,
        Err(e) => return err(e),
    };
    if due { ok(0) } else { err(Errno::EINVAL) }
}
/// `clock_nanosleep(clock, flags, request, remain)`: on the clocks
/// [`timer_clock`] gives, looking at no flag but `TIMER_ABSTIME` (an alarm
/// clock refuses the others), on the process's CPU clock, and on the CPU
/// clocks of tasks by number ([`cpu_sleep`]). A dynamic clock cannot sleep
/// (`EOPNOTSUPP`), and neither can `CLOCK_THREAD_CPUTIME_ID`.
fn sys_clock_nanosleep(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // A dynamic clock cannot sleep (`EOPNOTSUPP`).
    let id_value = a[0] as u32 as i32;
    if id_value < 0 && id_value & 7 == 3 {
        return err(Errno::EOPNOTSUPP);
    }
    if id_value < 0 {
        return cpu_sleep(c, id_value, a);
    }
    let clock = match id_value {
        2 => SleepClock::ProcessCpu,
        id => match timer_clock(u64::from(id as u32), Errno::EOPNOTSUPP) {
            Ok(id) => SleepClock::Host(id),
            Err(e) => return err(e),
        },
    };
    // An alarm clock reads the request first, as the system call does,
    // then refuses any flag but TIMER_ABSTIME (`alarm_timer_nsleep`).
    if is_alarm(a[0]) {
        let checked = read_timespec(c.mem, a[2]).and_then(|_| {
            if a[1] as u32 & !1 != 0 {
                return Err(Errno::EINVAL);
            }
            may_use_alarm(c)
        });
        if let Err(e) = checked {
            return err(e);
        }
    }
    sleep(c, clock, a[1] & 1 != 0, a[2], a[3])
}
fn sys_rt_sigreturn(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    if signals::restore(c.process, c.cpu, c.mem).is_ok() {
        Outcome::Restored
    } else {
        Outcome::BadFrame
    }
}
impl Context<'_> {
    /// The PID namespace of the calling thread, which numbers the tasks it
    /// names and sees.
    pub(crate) fn pid_space(&self) -> std::sync::Arc<crate::namespaces::Namespace> {
        self.group.namespaces(self.tid).pid.clone()
    }
    /// The network the caller's sockets are made in: its network
    /// namespace's own, or for the first one the session's, if it has one.
    pub(crate) fn network(&self) -> Option<std::sync::Arc<crate::inet::Network>> {
        let namespaces = self.group.namespaces(self.tid);
        namespaces
            .net
            .sockets
            .network
            .get()
            .cloned()
            .or_else(|| self.files.network.clone())
    }
    /// The names a unix socket the caller makes binds abstract names among:
    /// its network namespace's, for the first one the session's. A socket
    /// file is found by its inode in every namespace, as in Linux.
    pub(crate) fn unix_names(&self) -> std::sync::Arc<crate::unix::Names> {
        let namespaces = self.group.namespaces(self.tid);
        let sockets = &namespaces.net.sockets;
        if sockets.network.get().is_none() {
            return std::sync::Arc::clone(&self.files.unix);
        }
        std::sync::Arc::clone(
            sockets
                .unix
                .get_or_init(|| std::sync::Arc::new(self.files.unix.nested())),
        )
    }
    /// The task the caller names by `number`, or nobody.
    pub(crate) fn named(&self, number: u32) -> u32 {
        self.pid_space()
            .task(number)
            .unwrap_or(crate::processes::NOBODY)
    }
}
/// `getpid`, and `gettid` of a process's only thread, as the caller's PID
/// namespace numbers it.
fn sys_getpid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.pid_space().number(c.process.pid)))
}
fn send_signal(c: &mut Context<'_>, target: u64, signal: signals::PendingSignal) -> Outcome {
    let number = signal.number;
    if !(0..=64).contains(&number) {
        return err(Errno::EINVAL);
    }
    let own = c.pid_space().number(c.process.pid);
    if target != u64::from(own) {
        return err(Errno(3));
    }
    // The init of a nested PID namespace drops what it has no handler for.
    if number == 0 || c.group.drops_as_init(number, false, c.process.signal_mask) {
        return ok(0);
    }
    let signal = signals::PendingSignal {
        sender: Some(own),
        ..signal
    };
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
    if a[0] != u64::from(c.pid_space().number(c.process.pid)) {
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
        if !n.is_multiple_of(64)
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
const MAP_NORESERVE: u64 = 0x4000;
const MAP_STACK: u64 = 0x2_0000;

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
    // A ring of io_uring maps its own pages.
    if let Some(file) = &file
        && file
            .as_any()
            .is_some_and(|v| v.is::<crate::io_uring::Ring>())
    {
        return match crate::io_uring::mmap(
            c,
            file,
            addr,
            len,
            prot,
            flags & MAP_SHARED != 0,
            offset,
        ) {
            Ok(at) => ok(at),
            Err(e) => err(e),
        };
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
    let placement = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        if at.page_offset() != 0 {
            return err(Errno::EINVAL);
        }
        if flags & MAP_FIXED_NOREPLACE == 0 {
            Placement::Replacing(at)
        } else {
            // Linux refuses a range in use before it asks the file.
            let end = addr.saturating_add(len);
            if c.mem.mappings().any(|m| m.start.0 < end && m.end() > addr) {
                return err(Errno::EEXIST);
            }
            Placement::Exactly(at)
        }
    } else {
        // Linux rounds a non-fixed hint down to its page boundary.
        let hint = GuestAddr(addr & !4095);
        Placement::Near((hint.0 != 0).then_some(hint))
    };
    // A locked mapping, by MAP_LOCKED or `mlockall`'s MCL_FUTURE, needs
    // `can_do_mlock` (EPERM, for MAP_LOCKED) and room under RLIMIT_MEMLOCK
    // (`mlock_future_ok`, EAGAIN).
    let future = c.mem.future_lock();
    let lock = match (flags & MAP_LOCKED != 0, future) {
        (true, Some(paludarium_mmu::Lock::OnFault)) => Some(paludarium_mmu::Lock::OnFault),
        (true, _) => Some(paludarium_mmu::Lock::Populated),
        (false, future) => future,
    };
    if flags & MAP_LOCKED != 0 && !can_do_mlock(c) {
        return err(Errno::EPERM);
    }
    if lock.is_some() && !lock_fits(c, len.div_ceil(4096)) {
        return err(Errno::EAGAIN);
    }
    // What the mapping shows is made first, outside the address space's
    // lock, as it may read the file. The mapping and what it shows then go
    // in under one hold of the lock, so that no other thread sees the
    // mapping without it, or maps the range in between.
    let result = match (&file, &descriptor) {
        (Some(file), Some(d)) if flags & MAP_SHARED != 0 => {
            // The mapping shows the file's page cache.
            shared_file(c, d, file, len, offset, prot, |pages, writes| {
                c.mem.map_backed(
                    placement,
                    len,
                    prot,
                    kind,
                    Backing::Shared {
                        pages,
                        offset,
                        writes,
                    },
                )
            })
        }
        // A private mapping shows the file's page cache until it writes a
        // page, which copies it.
        (Some(file), Some(d)) => file_cache(c, d, file).and_then(|cache| {
            c.mem.map_backed(
                placement,
                len,
                prot,
                kind,
                Backing::Cache {
                    pages: &cache.map_private(file, crate::files::mapped_path(c, d)),
                    offset,
                },
            )
        }),
        _ if flags & MAP_SHARED != 0 => {
            c.mem
                .map_backed(placement, len, prot, kind, Backing::SharedAnonymous)
        }
        _ => c.mem.map_backed(placement, len, prot, kind, Backing::None),
    };
    match result {
        Ok(a) => {
            let end = a.0.saturating_add(len.next_multiple_of(4096));
            if flags & MAP_LOCKED != 0
                && let Some(lock) = lock
            {
                c.mem.lock_new(a, end, lock);
            }
            // Overcommit is never strict here, so MAP_NORESERVE always
            // counts (`do_mmap`).
            if flags & (MAP_NORESERVE | MAP_STACK) != 0 {
                c.mem
                    .flag_new(a, end, flags & MAP_NORESERVE != 0, flags & MAP_STACK != 0);
            }
            // Linux populates a writable private mapping by writing it, which
            // gives it an anon_vma (a core then writes it whole), with
            // MAP_POPULATE or a lock that is not on fault.
            if (flags & MAP_POPULATE != 0 || lock == Some(paludarium_mmu::Lock::Populated))
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

/// `remap_file_pages(start, size, prot, pgoff, flags)`, as Linux's, which
/// makes it a `MAP_SHARED | MAP_FIXED` `mmap` of the VMA's own file: `prot`
/// must be 0, `start` and `size` are taken down to whole pages and may not
/// wrap or be empty, nor may `pgoff` with the pages (`EINVAL`), and `flags`
/// is not looked at. What the range must be is
/// [`paludarium_mmu::AddressSpace::remap_shared_pages`]'s; then the file
/// must reach `pgoff`'s pages, which `mmap`'s `file_mmap_ok` limits to
/// `MAX_LFS_FILESIZE` (`EOVERFLOW`).
fn sys_remap_file_pages(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (start, size, prot, pgoff) = (a[0] & !4095, a[1] & !4095, a[2], a[3]);
    if prot != 0
        || start.checked_add(size).is_none_or(|end| end <= start)
        || pgoff.checked_add(size >> 12).is_none()
    {
        return err(Errno::EINVAL);
    }
    let reach = (i64::MAX as u64).saturating_sub(size) >> 12;
    let offset = if pgoff <= reach {
        Ok(pgoff << 12)
    } else {
        Err(Errno::EOVERFLOW)
    };
    match c.mem.remap_shared_pages(GuestAddr(start), size, offset) {
        Ok(()) => {
            // A new VMA has no memory policy.
            c.group.numa().forget(start, size);
            ok(0)
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
    // Nor does an append-only file open for writing map shared, whatever
    // the protection.
    if flags & MAP_SHARED != 0
        && access == 2
        && file
            .stat()
            .is_ok_and(|stat| crate::files::attributes::append_only(&stat))
    {
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
    // A secret file maps shared only (secretmem_mmap_prepare).
    if flags & MAP_SHARED == 0
        && file
            .as_any()
            .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
            .is_some_and(crate::memfd::Memfd::is_secret)
    {
        return Err(Errno::EINVAL);
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
/// Makes the pages of a `MAP_SHARED` mapping of `file` and gives them to
/// `map`, which maps them, while the seals of a memfd stay as they are.
fn shared_file(
    c: &Context<'_>,
    d: &crate::files::Descriptor,
    file: &std::sync::Arc<dyn FileHandle>,
    len: u64,
    offset: u64,
    prot: Prot,
    map: impl FnOnce(
        &paludarium_mmu::SharedPages,
        paludarium_mmu::SharedWrites,
    ) -> Result<GuestAddr, Errno>,
) -> Result<GuestAddr, Errno> {
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
    let writes = match (file.flags() & 3 == 2, write_sealed(file.as_ref())) {
        (false, _) => paludarium_mmu::SharedWrites::ReadOnly,
        (true, true) => paludarium_mmu::SharedWrites::Sealed,
        (true, false) => paludarium_mmu::SharedWrites::Allowed,
    };
    let may_write = writes == paludarium_mmu::SharedWrites::Allowed;
    let pages = file_cache(c, d, file)?.map(
        &crate::memfd::pages_source(file),
        crate::files::mapped_path(c, d),
        offset,
        len,
        may_write,
        crate::memfd::secret_charge(file),
    )?;
    map(&pages, writes)
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
/// Whether a mapping of a `memfd_secret` file meets `[start, end)`: Linux's
/// `get_user_pages` refuses its pages (`check_vma_flags`), and its file has
/// no `fsync`.
fn maps_secret(mem: &AddressSpace, start: u64, end: u64) -> bool {
    mem.shared_fragments()
        .iter()
        .any(|f| f.secret && f.start < end && start < f.end)
}
fn is_zero_device(file: &dyn FileHandle) -> bool {
    file.as_any()
        .and_then(|v| v.downcast_ref::<crate::devices::Device>())
        .is_some_and(|d| d.kind() == crate::devices::Kind::Zero)
}

const MADV_DONTNEED: u64 = 4;
const MADV_REMOVE: u64 = 9;
const MADV_GUARD_INSTALL: u64 = 102;
const MADV_GUARD_REMOVE: u64 = 103;
const MADV_FREE: u64 = 8;
const MADV_POPULATE_READ: u64 = 22;
const MADV_POPULATE_WRITE: u64 = 23;
const MADV_DONTNEED_LOCKED: u64 = 24;
const MADV_COLD: u64 = 20;
const MADV_PAGEOUT: u64 = 21;

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

/// The capability that locks memory past RLIMIT_MEMLOCK.
const CAP_IPC_LOCK: u64 = 1 << 14;
const RLIMIT_MEMLOCK: usize = 8;

/// The caller's RLIMIT_MEMLOCK soft limit in pages, and whether it may
/// lock past it (`CAP_IPC_LOCK`).
fn lock_limit(c: &Context<'_>) -> (u64, bool) {
    let limit = c.processes.soft_limit(c.process.pid, RLIMIT_MEMLOCK) >> 12;
    (limit, c.process.credentials.capable(CAP_IPC_LOCK))
}

/// Whether the caller may lock memory at all (`can_do_mlock`): a
/// RLIMIT_MEMLOCK above 0, or `CAP_IPC_LOCK`.
fn can_do_mlock(c: &Context<'_>) -> bool {
    c.processes.soft_limit(c.process.pid, RLIMIT_MEMLOCK) != 0
        || c.process.credentials.capable(CAP_IPC_LOCK)
}

/// Whether `pages` more pages may be locked (`mlock_future_ok`): within
/// RLIMIT_MEMLOCK with what is locked, or with `CAP_IPC_LOCK`.
pub(crate) fn lock_fits(c: &Context<'_>, pages: u64) -> bool {
    let (limit, capable) = lock_limit(c);
    capable || pages.saturating_add(c.mem.locked_pages()) <= limit
}

/// `mlock`, `mlock2` and `munlock` of the pages `[addr, addr+len)`
/// touches, as Linux's `do_mlock` and `apply_vma_lock_flags`: a lock needs
/// `can_do_mlock` (`EPERM`) and room under RLIMIT_MEMLOCK for the pages
/// not locked yet (`ENOMEM`), unless the caller has `CAP_IPC_LOCK`. The
/// VMAs from `addr` take the new state up to a hole (`ENOMEM`). A lock that
/// is not `MLOCK_ONFAULT` then brings each page in (`__mm_populate`), and a
/// page that cannot be (no access, a guard page, past the end of its file)
/// gives `ENOMEM`, the VMAs locked.
fn lock_range(c: &Context<'_>, addr: u64, len: u64, lock: Option<paludarium_mmu::Lock>) -> Outcome {
    if lock.is_some() && !can_do_mlock(c) {
        return err(Errno::EPERM);
    }
    // Rounded as Linux's PAGE_ALIGN is, so a huge length may wrap to none.
    let length = len.wrapping_add(addr & 4095).wrapping_add(4095) & !4095;
    let start = addr & !4095;
    let Some(end) = start.checked_add(length) else {
        return err(Errno::EINVAL);
    };
    if length == 0 {
        return ok(0);
    }
    if lock.is_some() {
        let (limit, capable) = lock_limit(c);
        let mut locked = (length >> 12).saturating_add(c.mem.locked_pages());
        if locked > limit && !capable {
            locked -= c.mem.locked_pages_in(GuestAddr(start), end);
        }
        if locked > limit && !capable {
            return err(Errno::ENOMEM);
        }
    }
    if let Err(e) = c.mem.lock(GuestAddr(start), end, lock) {
        return err(e);
    }
    // Linux's `__mm_populate` fails to fault a page of a `memfd_secret`
    // file in (`EFAULT`, which `mlock` gives as `ENOMEM`), as GUP refuses
    // secret memory; `mlock_fixup` leaves its VMA unlocked.
    if lock == Some(paludarium_mmu::Lock::Populated) && maps_secret(c.mem, start, end) {
        return err(Errno::ENOMEM);
    }
    if lock == Some(paludarium_mmu::Lock::Populated) {
        let mut mappings: Vec<_> = c
            .mem
            .mappings()
            .filter(|m| m.start.0 < end && m.end() > start)
            .collect();
        mappings.sort_by_key(|m| m.start.0);
        for m in mappings {
            if m.prot == Prot::NONE {
                return err(Errno::ENOMEM);
            }
            let mut page = m.start.0.max(start);
            while page < m.end().min(end) {
                if c.mem.read_for_dump(GuestAddr(page), &mut [0]).is_err() {
                    return err(Errno::ENOMEM);
                }
                page += 4096;
            }
        }
    }
    ok(0)
}

/// `mlock(addr, len)`.
fn sys_mlock(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    lock_range(c, a[0], a[1], Some(paludarium_mmu::Lock::Populated))
}

/// `munlock(addr, len)`.
fn sys_munlock(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    lock_range(c, a[0], a[1], None)
}

/// `mlock2(addr, len, flags)`: `MLOCK_ONFAULT` brings no page in, except
/// in a mapping of a `memfd_secret` file, which Linux's `mlock_fixup`
/// leaves without `VM_LOCKONFAULT`, so that `__mm_populate` still tries
/// to fault its pages in and fails (`ENOMEM`), as for `mlock`.
fn sys_mlock2(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let flags = a[2] as u32;
    if flags & !MLOCK_ONFAULT != 0 {
        return err(Errno::EINVAL);
    }
    let lock = if flags & MLOCK_ONFAULT != 0 {
        paludarium_mmu::Lock::OnFault
    } else {
        paludarium_mmu::Lock::Populated
    };
    let locked = lock_range(c, a[0], a[1], Some(lock));
    if matches!(locked, Outcome::Return(0)) && flags & MLOCK_ONFAULT != 0 {
        let start = a[0] & !4095;
        let length = a[1].wrapping_add(a[0] & 4095).wrapping_add(4095) & !4095;
        if maps_secret(c.mem, start, start.wrapping_add(length)) {
            return err(Errno::ENOMEM);
        }
    }
    locked
}

/// `mlockall(flags)`, as Linux's: the flags (`EINVAL`), `can_do_mlock`
/// (`EPERM`), then with `MCL_CURRENT` room for every mapped page under
/// RLIMIT_MEMLOCK (`ENOMEM`) unless the caller has `CAP_IPC_LOCK`. Every
/// mapping is locked with `MCL_CURRENT`, and every new one with
/// `MCL_FUTURE`; without `MCL_CURRENT` the mappings are left as they are.
fn sys_mlockall(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let flags = a[0] as u32;
    if flags == 0 || flags == MCL_ONFAULT || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
    {
        return err(Errno::EINVAL);
    }
    if !can_do_mlock(c) {
        return err(Errno::EPERM);
    }
    let lock = if flags & MCL_ONFAULT != 0 {
        paludarium_mmu::Lock::OnFault
    } else {
        paludarium_mmu::Lock::Populated
    };
    if flags & MCL_CURRENT != 0 {
        let (limit, capable) = lock_limit(c);
        let total: u64 = c.mem.mappings().map(|m| m.length >> 12).sum();
        if total > limit && !capable {
            return err(Errno::ENOMEM);
        }
    }
    c.mem.lock_all(
        (flags & MCL_CURRENT != 0).then_some(Some(lock)),
        (flags & MCL_FUTURE != 0).then_some(lock),
    );
    ok(0)
}

/// `munlockall()`: no mapping stays locked, and new ones are not.
fn sys_munlockall(c: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    c.mem.lock_all(Some(None), None);
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

fn sys_madvise(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match advise(c.mem, &c.process.credentials, a[0], a[1], a[2]) {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}

/// `madvise(addr, len, advice)` on `mem`, which `process_madvise` gives
/// each of its ranges of the caller's own memory too. Implemented are
/// `MADV_WILLNEED`; `MADV_COLD` and `MADV_PAGEOUT`, which nothing to
/// reclaim makes hints; the access-pattern hints, KSM's `MADV_MERGEABLE`
/// and `MADV_UNMERGEABLE` and THP's `MADV_HUGEPAGE` and `MADV_NOHUGEPAGE`,
/// which change only the flags of the VMAs (`/proc/<pid>/smaps` shows
/// them), as no page here depends on them; the discards `MADV_DONTNEED`,
/// `MADV_DONTNEED_LOCKED` (which takes locked VMAs too) and `MADV_FREE`;
/// and `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE` ([`populate`]); and the flags `fork` and core
/// dumps look at, `MADV_DONTFORK`, `MADV_DOFORK`, `MADV_WIPEONFORK`,
/// `MADV_KEEPONFORK`, `MADV_DONTDUMP` and `MADV_DODUMP`
/// ([`AddressSpace::advise_flags`]); and `MADV_REMOVE`, which frees shared
/// memory as a hole punched in its file ([`remove`]). The others are
/// rejected rather than ignored, so that a guest relying on one of them
/// notices.
pub(crate) fn advise(
    mem: &AddressSpace,
    credentials: &credentials::Credentials,
    addr: u64,
    len: u64,
    advice: u64,
) -> Result<(), Errno> {
    if !matches!(advice, 0..=4 | 8..=24 | MADV_GUARD_INSTALL | MADV_GUARD_REMOVE) {
        return Err(Errno::EINVAL);
    }
    if addr & 4095 != 0 {
        return Err(Errno::EINVAL);
    }
    let Some(length) = len.checked_add(4095).map(|l| l & !4095) else {
        return Err(Errno::EINVAL);
    };
    if length == 0 {
        return Ok(());
    }
    let Some(end) = addr.checked_add(length) else {
        return Err(Errno::EINVAL);
    };
    if end > USER_ADDRESS_LIMIT {
        return Err(Errno::ENOMEM);
    }
    if advice == MADV_DONTNEED_LOCKED {
        return mem.discard_shared(GuestAddr(addr), length);
    }
    if advice == MADV_DONTNEED {
        return short_of_locked(mem, addr, end, true, |to| {
            mem.discard_shared(GuestAddr(addr), to - addr)
        });
    }
    if advice == MADV_REMOVE {
        return short_of_locked(mem, addr, end, true, |to| {
            let (removals, hole) = mem.removals(GuestAddr(addr), to);
            for removal in removals {
                remove(credentials, &removal?)?;
            }
            if hole { Err(Errno::ENOMEM) } else { Ok(()) }
        });
    }
    if advice == MADV_GUARD_INSTALL {
        return short_of_locked(mem, addr, end, true, |to| {
            mem.guard(GuestAddr(addr), to, true)
        });
    }
    if advice == MADV_GUARD_REMOVE {
        return mem.guard(GuestAddr(addr), end, false);
    }
    let flag = match advice {
        0 => Some(paludarium_mmu::FlagAdvice::Read(None)),
        1 => Some(paludarium_mmu::FlagAdvice::Read(Some(
            paludarium_mmu::ReadHint::Random,
        ))),
        2 => Some(paludarium_mmu::FlagAdvice::Read(Some(
            paludarium_mmu::ReadHint::Sequential,
        ))),
        12 => Some(paludarium_mmu::FlagAdvice::Mergeable(true)),
        13 => Some(paludarium_mmu::FlagAdvice::Mergeable(false)),
        14 => Some(paludarium_mmu::FlagAdvice::HugePages(true)),
        15 => Some(paludarium_mmu::FlagAdvice::HugePages(false)),
        10 => Some(paludarium_mmu::FlagAdvice::DontFork),
        11 => Some(paludarium_mmu::FlagAdvice::DoFork),
        16 => Some(paludarium_mmu::FlagAdvice::DontDump),
        17 => Some(paludarium_mmu::FlagAdvice::DoDump),
        18 => Some(paludarium_mmu::FlagAdvice::WipeOnFork),
        19 => Some(paludarium_mmu::FlagAdvice::KeepOnFork),
        _ => None,
    };
    if let Some(flag) = flag {
        return mem.advise_flags(GuestAddr(addr), end, flag);
    }
    if advice == MADV_POPULATE_READ || advice == MADV_POPULATE_WRITE {
        return populate(mem, addr, end, advice == MADV_POPULATE_WRITE);
    }
    if advice == MADV_FREE {
        // Linux frees such pages only under memory pressure, which the
        // emulator never has, so their contents stay as they are.
        return short_of_locked(mem, addr, end, true, |to| {
            mem.check_private_anonymous(GuestAddr(addr), to - addr)
        });
    }
    // MADV_COLD and MADV_PAGEOUT take no locked VMA (`can_madv_lru_vma`).
    if advice == MADV_COLD || advice == MADV_PAGEOUT {
        return short_of_locked(mem, addr, end, false, |to| covered(mem, addr, to));
    }
    covered(mem, addr, end)
}

/// Whether `[addr, end)` is mapped through (`ENOMEM` for a hole).
fn covered(mem: &AddressSpace, addr: u64, end: u64) -> Result<(), Errno> {
    let mapped = mem.mappings().filter(|m| m.start.0 < end && m.end() > addr);
    let covered = mapped.fold(addr, |covered, m| {
        if m.start.0 <= covered {
            covered.max(m.end())
        } else {
            covered
        }
    });
    if covered < end {
        Err(Errno::ENOMEM)
    } else {
        Ok(())
    }
}

/// `op` over `[addr, end)` up to the first locked VMA, which refuses the
/// advice as Linux's `madvise_walk_vmas` meets it: `EINVAL`, or first
/// `EPERM` for advice that `discards` the pages of sealed memory
/// (`can_madvise_modify`). An error before it stands, but not the `ENOMEM`
/// of a hole, which Linux gives only once the walk is done.
fn short_of_locked(
    mem: &AddressSpace,
    addr: u64,
    end: u64,
    discards: bool,
    op: impl FnOnce(u64) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let Some(locked) = mem.first_locked(GuestAddr(addr), end) else {
        return op(end);
    };
    let at = locked.start.0.max(addr);
    if at > addr {
        match op(at) {
            Ok(()) | Err(Errno::ENOMEM) => {}
            Err(e) => return Err(e),
        }
    }
    if discards && mem.refuses_discard_at(GuestAddr(at)) {
        return Err(Errno::EPERM);
    }
    Err(Errno::EINVAL)
}

/// Frees what `MADV_REMOVE` found in a VMA, as Linux's `madvise_remove`
/// punches a hole in the VMA's file: in a file's page cache as `fallocate`
/// would ([`crate::files::punch_hole`]); in shared anonymous memory and a
/// System V segment, whose files are tmpfs's, by zeroing its pages. Any
/// other file has no `fallocate` (`EOPNOTSUPP`).
fn remove(
    credentials: &credentials::Credentials,
    removal: &paludarium_mmu::Removal,
) -> Result<(), Errno> {
    let Some(source) = removal.pages.source() else {
        removal
            .pages
            .zero(removal.offset, removal.offset.wrapping_add(removal.len));
        return Ok(());
    };
    let any = source.as_any().ok_or(Errno::EOPNOTSUPP)?;
    if let Some(pages) = any.downcast_ref::<crate::page_cache::FilePages>() {
        return crate::files::punch_hole(credentials, pages.file(), removal.offset, removal.len);
    }
    if any.is::<crate::shm::Attachment>() {
        removal
            .pages
            .zero(removal.offset, removal.offset.wrapping_add(removal.len));
        return Ok(());
    }
    Err(Errno::EOPNOTSUPP)
}

/// `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE` of `[addr, end)`, as
/// Linux's `madvise_populate` faults the pages in a page at a time: a page
/// no mapping holds ends it with `ENOMEM`, one whose mapping may not be read
/// (or, with `write`, written), or that maps a `memfd_secret` file, with
/// `EINVAL`, and one that cannot be brought in (past the end of its file,
/// `SIGBUS`) with `EFAULT`, after the pages before it. A read maps what a read would (the zero page of
/// private anonymous memory); a write breaks copy-on-write as a write
/// would, and leaves the bytes as they are.
fn populate(mem: &AddressSpace, addr: u64, end: u64, write: bool) -> Result<(), Errno> {
    let mut at = addr;
    while at < end {
        let Some(mapping) = mem.mappings().find(|m| m.start.0 <= at && at < m.end()) else {
            return Err(Errno::ENOMEM);
        };
        let needed = if write { Prot::WRITE } else { Prot::READ };
        let stop = mapping.end().min(end);
        if !mapping.prot.contains(needed) || maps_secret(mem, at, stop) {
            return Err(Errno::EINVAL);
        }
        while at < stop {
            let faulted = if write {
                mem.atomic(
                    GuestAddr(at),
                    paludarium_mmu::AtomicWidth::W8,
                    paludarium_mmu::AtomicOp::Add(0),
                )
                .is_ok()
            } else {
                mem.read(GuestAddr(at), &mut [0]).is_ok()
            };
            if !faulted {
                return Err(Errno::EFAULT);
            }
            if write {
                mem.mark_written(GuestAddr(at), 1);
            }
            at += 4096;
        }
    }
    Ok(())
}

/// `map_shadow_stack(addr, size, flags)`, as Linux's on a CPU without
/// user shadow stacks, which the virtual CPU is (`CPUID` reports no
/// `CET_SS`): `EOPNOTSUPP` before anything is looked at.
fn sys_map_shadow_stack(_: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    err(Errno::EOPNOTSUPP)
}

fn sys_mprotect(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    mprotect_with_key(c, a, true)
}

/// `pkey_mprotect(addr, len, prot, pkey)`, as Linux's on a CPU without
/// protection keys, which the virtual CPU is (`CPUID` reports no PKU): no key
/// is ever allocated there, not even the default key 0, so only `-1` (no key)
/// is accepted, and that is `mprotect`. Any other key is `EINVAL` once the
/// checks Linux makes before it pass (see [`mprotect_with_key`]).
fn sys_pkey_mprotect(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    // An `int`, sign-extended when the arguments were read.
    mprotect_with_key(c, a, a[3] == u64::MAX)
}

/// Linux's `do_mprotect_pkey`, in its order: `PROT_GROWSDOWN` with
/// `PROT_GROWSUP`, a misaligned start, an empty range (which succeeds even
/// with bad bits), an end that overflows (`ENOMEM`), unknown bits, and only
/// then the key (`allocated` is false for a key that is not) and the
/// mappings. `PROT_GROWSDOWN` extends the range down to the start of the
/// first VMA in it, which must be a stack, as only the main thread's stack is
/// a VMA that grows down here; `PROT_GROWSUP` is `EINVAL` where a VMA holds
/// the start, as no VMA grows up on x86-64.
fn mprotect_with_key(c: &mut Context<'_>, a: [u64; 6], allocated: bool) -> Outcome {
    const PROT_SEM: u64 = 0x8;
    const PROT_GROWSDOWN: u64 = 0x0100_0000;
    const PROT_GROWSUP: u64 = 0x0200_0000;
    let (start, len) = (a[0], a[1]);
    let grows = a[2] & (PROT_GROWSDOWN | PROT_GROWSUP);
    if grows == PROT_GROWSDOWN | PROT_GROWSUP || start & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    if len == 0 {
        return ok(0);
    }
    let end = start.wrapping_add(len.wrapping_add(4095) & !4095);
    if end <= start {
        return err(Errno::ENOMEM);
    }
    // PROT_SEM has no effect on x86-64, but Linux accepts it.
    let Some(prot) = Prot::from_bits(a[2] & !(grows | PROT_SEM)) else {
        return err(Errno::EINVAL);
    };
    if !allocated {
        return err(Errno::EINVAL);
    }
    let prot = read_implies_exec(c.process, prot);
    let mut start = start;
    if grows != 0 {
        let Some(first) = c
            .mem
            .mappings()
            .find(|m| m.end() > start && m.start.0 < end)
        else {
            return err(Errno::ENOMEM);
        };
        if grows == PROT_GROWSUP {
            return err(if first.start.0 > start {
                Errno::ENOMEM
            } else {
                Errno::EINVAL
            });
        }
        if first.kind != MappingKind::Stack {
            return err(Errno::EINVAL);
        }
        start = c
            .mem
            .vma_at(first.start)
            .map_or(first.start.0, |(at, _)| at.0);
    }
    match c.mem.protect_shared(GuestAddr(start), end - start, prot) {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}

/// `pkey_alloc(flags, access_rights)`: `EINVAL` for a flag (none exists) or
/// rights other than `PKEY_DISABLE_ACCESS` and `PKEY_DISABLE_WRITE`, else
/// `ENOSPC`, as Linux on a CPU without protection keys has none to give.
fn sys_pkey_alloc(_: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    const PKEY_ACCESS_MASK: u64 = 1 | 2;
    if a[0] != 0 || a[1] & !PKEY_ACCESS_MASK != 0 {
        return err(Errno::EINVAL);
    }
    err(Errno::ENOSPC)
}

/// `pkey_free(pkey)`: `EINVAL`, as no key is allocated (see
/// [`sys_pkey_mprotect`]).
fn sys_pkey_free(_: &mut Context<'_>, _: [u64; 6]) -> Outcome {
    err(Errno::EINVAL)
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
    // A locked VMA that grows must fit under RLIMIT_MEMLOCK
    // (`mlock_future_ok` in `remap_is_valid`'s resize, EAGAIN).
    let align = |len: u64| len.wrapping_add(4095) & !4095;
    let grows = align(new_len).saturating_sub(align(old_len));
    if addr & 4095 == 0
        && grows > 0
        && c.mem
            .first_locked(GuestAddr(addr), addr.saturating_add(1))
            .is_some_and(|m| m.start.0 <= addr)
        && !lock_fits(c, grows >> 12)
    {
        return err(Errno::EAGAIN);
    }
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
/// read of a file would do anyway). With `MS_SYNC`, a shared mapping of a
/// `memfd_secret` file in the range gives `EINVAL`, as Linux's walk of the
/// range reaches it before it can run out of VMAs and its file has no
/// `fsync` (`vfs_fsync_range`), whatever holes the range has.
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
    // MS_INVALIDATE of a locked VMA is EBUSY.
    if flags & MS_INVALIDATE != 0
        && c.mem
            .first_locked(GuestAddr(addr), addr.saturating_add(len))
            .is_some()
    {
        return err(Errno(16));
    }
    // A range that wraps past the top is Linux's `ENOMEM` before any VMA is
    // looked at, so it skips this check and `covers` below refuses it.
    if flags & MS_SYNC != 0
        && addr
            .checked_add(len)
            .is_some_and(|end| maps_secret(c.mem, addr, end))
    {
        return err(Errno::EINVAL);
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

/// `mseal(addr, len, flags)`, as Linux's: no flags (EINVAL), a page-aligned
/// start, a length rounded up to pages that neither wraps to 0 nor runs
/// past the top (EINVAL), nothing to do for none, then a range every page
/// of which is mapped (ENOMEM), whose mappings are sealed
/// ([`paludarium_mmu::Mapping::sealed`]).
fn sys_mseal(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (start, len, flags) = (a[0], a[1], a[2]);
    if flags != 0 || start & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    let aligned = len.wrapping_add(4095) & !4095;
    if len != 0 && aligned == 0 {
        return err(Errno::EINVAL);
    }
    let Some(end) = start.checked_add(aligned) else {
        return err(Errno::EINVAL);
    };
    if end == start {
        return ok(0);
    }
    match c.mem.seal_shared(GuestAddr(start), aligned) {
        Ok(()) => ok(0),
        Err(e) => err(e),
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
    // Under `mlockall`'s MCL_FUTURE the heap it grows into is locked, and
    // must fit under RLIMIT_MEMLOCK (`mlock_future_ok`).
    let grows =
        (a[0].saturating_add(4095) & !4095).saturating_sub(old.saturating_add(4095) & !4095);
    if grows > 0 && c.mem.future_lock().is_some() && !lock_fits(c, grows >> 12) {
        return ok(old);
    }
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
        // security_file_ioctl: Landlock's device right, before any command.
        if descriptor.landlock & crate::landlock::IOCTL_DEV == 0
            && let Ok(stat) = descriptor.file.stat()
        {
            crate::landlock::ioctl(descriptor.landlock, &stat, a[1] as u32)?;
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
        // FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_FSGETXATTR and
        // FS_IOC_FSSETXATTR, which `do_vfs_ioctl` answers for a file whose
        // file system keeps inode flags.
        if let Some(result) = crate::files::attributes::ioctl(c, &*file, a[1] as u32, a[2]) {
            return result;
        }
        // A pseudo-terminal's own requests.
        if let Some(result) = crate::pty::ioctl(c, &file, a[1], a[2]) {
            return result;
        }
        // An inotify instance's.
        if let Some(result) = crate::inotify::ioctl(c, &file, a[1], a[2]) {
            return result;
        }
        // A seccomp listener's.
        if let Some(result) = crate::seccomp::ioctl(c, &file, a[1], a[2]) {
            return result;
        }
        // SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCGIFINDEX and SIOCGIFNAME of a
        // socket's network, whose interface is its loopback: a `struct ifreq`
        // of 40 bytes, read whole and written back, as Linux's `dev_ioctl`
        // does for a socket of any family. The network is that of the
        // namespace the socket was made in (`sock_net`), and setting flags
        // needs CAP_NET_ADMIN in the user namespace that owns it.
        let unix_network;
        let network = if let Some(socket) = crate::inet::of(&file) {
            Some(socket.network())
        } else if let Some(socket) = crate::netlink::of(&file) {
            Some(socket.network())
        } else if let Some(end) = file
            .as_any()
            .and_then(|v| v.downcast_ref::<crate::sockets::SocketPairEnd>())
        {
            unix_network = end.unix().and_then(|socket| socket.network().cloned());
            unix_network.as_deref()
        } else {
            None
        };
        if let Some(network) = network
            && matches!(
                a[1],
                crate::inet::SIOCGIFFLAGS
                    | crate::inet::SIOCSIFFLAGS
                    | crate::inet::SIOCGIFINDEX
                    | crate::inet::SIOCGIFNAME
            )
        {
            const CAP_NET_ADMIN: u64 = 1 << 12;
            let mut request = [0; 40];
            c.mem
                .read(GuestAddr(a[2]), &mut request)
                .map_err(|_| Errno::EFAULT)?;
            // SIOCGIFNAME: the name of the interface `ifr_ifindex` names.
            if a[1] == crate::inet::SIOCGIFNAME {
                let index =
                    i32::from_le_bytes([request[16], request[17], request[18], request[19]]);
                if index != 1 {
                    return Err(Errno(19));
                }
                request[..16].fill(0);
                request[..2].copy_from_slice(b"lo");
                c.mem
                    .write(GuestAddr(a[2]), &request)
                    .map_err(|_| Errno::EFAULT)?;
                return Ok(0);
            }
            request[15] = 0;
            let flags = u16::from_le_bytes([request[16], request[17]]);
            let admin = c
                .process
                .credentials
                .capable_in(CAP_NET_ADMIN, network.owner());
            let value = network.interface(&request[..16], a[1], flags, admin)?;
            match a[1] {
                crate::inet::SIOCGIFFLAGS => {
                    request[16..18].copy_from_slice(&(value as u16).to_le_bytes());
                }
                crate::inet::SIOCGIFINDEX => {
                    request[16..20].copy_from_slice(&value.to_le_bytes());
                }
                _ => return Ok(0),
            }
            c.mem
                .write(GuestAddr(a[2]), &request)
                .map_err(|_| Errno::EFAULT)?;
            return Ok(0);
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
/// name and kernel are not revealed, as with `CPUID`: the host and domain
/// names are the thread's UTS namespace's ([`crate::namespaces`]).
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
    let names = c.group.namespaces(c.tid).uts.names();
    let fields: [&[u8]; 6] = [
        b"Linux",
        &names.host,
        release,
        b"#1 SMP PREEMPT_DYNAMIC",
        machine,
        &names.domain,
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

/// `sethostname(name, len)` and `setdomainname`, as Linux's: CAP_SYS_ADMIN
/// over the thread's UTS namespace (`EPERM`), then a length of at most 64
/// (`EINVAL`), then the name, which may hold any bytes, into it.
fn set_uts_name(c: &mut Context<'_>, a: [u64; 6], host: bool) -> Outcome {
    let namespaces = c.group.namespaces(c.tid);
    if !c
        .process
        .credentials
        .capable_in(crate::credentials::CAP_SYS_ADMIN, namespaces.uts.owner())
    {
        return err(Errno::EPERM);
    }
    let Ok(length) = usize::try_from(a[1] as i64) else {
        return err(Errno::EINVAL);
    };
    if length > crate::namespaces::NAME_LENGTH {
        return err(Errno::EINVAL);
    }
    let mut name = vec![0; length];
    if c.mem.read(GuestAddr(a[0]), &mut name).is_err() {
        return err(Errno::EFAULT);
    }
    let uts = c.group.namespaces(c.tid).uts.clone();
    if host {
        uts.set_host(&name);
    } else {
        uts.set_domain(&name);
    }
    ok(0)
}
fn sys_sethostname(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    set_uts_name(c, a, true)
}
fn sys_setdomainname(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    set_uts_name(c, a, false)
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
    let thread = crate::account_cpu(c.host, c.group, c.process, c.tid);
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
        crate::account_cpu(c.host, c.group, c.process, c.tid);
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
    match u32::try_from(pid).map(|p| if p == 0 { 0 } else { c.named(p) }) {
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
pub(crate) fn active_cpus(c: &Context<'_>) -> usize {
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
/// processes; the host still runs the thread on any of its CPUs. A
/// `SCHED_DEADLINE` thread's mask must keep every CPU (`EBUSY`).
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
    if !cpus.is_multiple_of(64)
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
    // dl_task_check_affinity: a deadline thread keeps every CPU (EBUSY).
    let group = other.as_deref().unwrap_or(c.group);
    if group.sched(tid).deadline_policy()
        && !(0..cpus).all(|cpu| {
            mask.get(cpu / 64)
                .is_some_and(|word| word >> (cpu % 64) & 1 != 0)
        })
    {
        return err(Errno(16)); // EBUSY
    }
    if mask.iter().all(|&word| word == 0) {
        return err(Errno::EINVAL);
    }
    other.as_deref().unwrap_or(c.group).set_affinity(tid, mask);
    ok(0)
}

/// `getcpu(cpu, node, cache)`: the CPU the thread runs on, and NUMA node 0,
/// each written where its pointer is not NULL; `EFAULT` when one cannot be
/// written, as Linux, which still writes the other. The cache is ignored,
/// as on Linux. A thread with `rseq` runs on a virtual CPU, the one its area
/// shows; another on none, so it reports the lowest its mask allows.
fn sys_getcpu(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let cpu = c.process.on_cpu.map(|on| on.cpu);
    let cpu = cpu.unwrap_or_else(|| {
        c.group.affinity(c.tid).map_or(0, |set| {
            set.iter()
                .enumerate()
                .find(|(_, word)| **word != 0)
                .map_or(0, |(index, word)| {
                    index * 64 + word.trailing_zeros() as usize
                })
        }) as u32
    });
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
/// `ADDR_COMPAT_LAYOUT` and `MMAP_PAGE_ZERO`, which the next exec applies.
pub(crate) const ADDR_COMPAT_LAYOUT: u32 = 0x20_0000;
pub(crate) const MMAP_PAGE_ZERO: u32 = 0x10_0000;
const PER_LINUX32: u32 = 0x8;

/// A readable mapping is also executable under `READ_IMPLIES_EXEC`, as
/// Linux's `do_mmap` and `mprotect` make it.
pub(crate) fn read_implies_exec(state: &ThreadState, prot: Prot) -> Prot {
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
/// `find_process_by_pid`), with its scheduling attributes and nice value:
/// 0 is the caller, a negative one is `EINVAL`, and one of no live thread
/// `ESRCH`.
fn sched_target(c: &Context<'_>, pid: u64) -> Result<(crate::scheduling::Sched, i32), Errno> {
    let pid = pid as u32 as i32;
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    let (tid, other) = affinity_target(c, pid)?;
    let group = other.as_deref().unwrap_or(c.group);
    Ok((group.sched(tid), group.nice(tid).unwrap_or(0)))
}

/// `sched_getscheduler(pid)`: the thread's policy, with
/// `SCHED_RESET_ON_FORK` when it is set.
fn sys_sched_getscheduler(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match sched_target(c, a[0]) {
        Ok((sched, _)) => ok(u64::from(sched.reported_policy())),
        Err(e) => err(e),
    }
}

/// `sched_getparam(pid, param)`: a `struct sched_param` with the thread's
/// real-time priority, 0 under any other policy. A NULL `param` is
/// `EINVAL` before the thread is looked for, as in Linux.
fn sys_sched_getparam(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if a[1] == 0 {
        return err(Errno::EINVAL);
    }
    let priority = match sched_target(c, a[0]) {
        Ok((sched, _)) if crate::scheduling::rt_policy(sched.policy) => sched.priority,
        Ok(_) => 0,
        Err(e) => return err(e),
    };
    match c.mem.write(GuestAddr(a[1]), &priority.to_le_bytes()) {
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

/// The normal policy's slice and the tick: the host's where it tells
/// ([`Host::scheduler_slice`]), or else Linux 6.12's default at 1000 Hz,
/// the base slice of 0.75 ms times 1 + log2 of the CPUs (at most 8).
pub(crate) fn scheduler_slice(host: &dyn Host) -> paludarium_host::SchedulerSlice {
    host.scheduler_slice().unwrap_or_else(|| {
        let cpus = host.cpu_count().clamp(1, 8192);
        paludarium_host::SchedulerSlice {
            slice: 750_000 * (1 + u64::from(cpus.min(8).ilog2())),
            tick: 1_000_000,
        }
    })
}

/// `sched_rr_get_interval(pid, interval)`, as Linux's classes give it:
/// 100 ms under `SCHED_RR` (`sched_rr_timeslice_ms`), 0 under `SCHED_FIFO`
/// and `SCHED_DEADLINE`, and else the thread's slice (the one
/// `sched_setattr` asked for, or [`scheduler_slice`]'s) in whole ticks.
fn sys_sched_rr_get_interval(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    use crate::scheduling::{SCHED_DEADLINE, SCHED_FIFO, SCHED_RR};
    let sched = match sched_target(c, a[0]) {
        Ok((sched, _)) => sched,
        Err(e) => return err(e),
    };
    let interval = match sched.policy {
        SCHED_RR => 100_000_000,
        SCHED_FIFO | SCHED_DEADLINE => 0,
        _ => {
            let host = scheduler_slice(c.host);
            sched.slice.unwrap_or(host.slice) / host.tick * host.tick
        }
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(interval / 1_000_000_000).to_le_bytes());
    bytes[8..].copy_from_slice(&(interval % 1_000_000_000).to_le_bytes());
    match c.mem.write(GuestAddr(a[1]), &bytes) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}

/// `sched_getattr(pid, attr, size, flags)`, as Linux's: `EINVAL` for a
/// NULL `attr`, a negative `pid`, a size outside 48 (`SCHED_ATTR_SIZE_VER0`)
/// to a page or any flag; then the thread (`ESRCH`); and the attributes,
/// cut to `size` with `size` written as what was copied (at most 56) and
/// zeros after them in a larger buffer, as Linux 6.13's
/// `copy_struct_to_user`. A normal policy reports its nice value and its slice as `sched_runtime`.
fn sys_sched_getattr(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    use crate::scheduling::{FLAG_ALL, FLAG_RESET_ON_FORK, rt_policy};
    let (pid, size, flags) = (a[0] as u32 as i32, a[2] as u32, a[3] as u32);
    if a[1] == 0 || pid < 0 || !(48..=4096).contains(&size) || flags != 0 {
        return err(Errno::EINVAL);
    }
    let (sched, nice) = match sched_target(c, a[0]) {
        Ok(target) => target,
        Err(e) => return err(e),
    };
    let mut sched_flags = if sched.reset_on_fork {
        FLAG_RESET_ON_FORK
    } else {
        0
    };
    let (mut attr_nice, mut priority, mut runtime, mut deadline, mut period) = (0, 0, 0, 0, 0);
    if sched.deadline_policy() {
        priority = sched.priority;
        runtime = sched.runtime;
        deadline = sched.deadline;
        period = sched.period;
        sched_flags |= sched.dl_flags;
    } else if rt_policy(sched.policy) {
        priority = sched.priority;
    } else {
        attr_nice = nice;
        runtime = sched.slice.unwrap_or_else(|| scheduler_slice(c.host).slice);
    }
    sched_flags &= FLAG_ALL;
    let copied = size.min(56);
    let mut bytes = Vec::with_capacity(56);
    bytes.extend_from_slice(&copied.to_le_bytes());
    bytes.extend_from_slice(&sched.policy.to_le_bytes());
    bytes.extend_from_slice(&sched_flags.to_le_bytes());
    bytes.extend_from_slice(&attr_nice.to_le_bytes());
    bytes.extend_from_slice(&priority.to_le_bytes());
    for value in [runtime, deadline, period] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&sched.clamps[0].value.to_le_bytes());
    bytes.extend_from_slice(&sched.clamps[1].value.to_le_bytes());
    // copy_struct_to_user (since Linux 6.13): a larger buffer gets zeros
    // after the structure.
    bytes.resize(size as usize, 0);
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
/// fork copies and an exec starts without. Each barrier is one on every
/// thread of the address space ([`AddressSpace::barrier`]). Other processes
/// share only shared memory, whose every access takes the session's
/// serialization lock, which the barrier takes too. `PRIVATE_EXPEDITED_RSEQ`
/// also aborts the `rseq` critical sections of the space's other threads
/// (of the one on the CPU `cpu_id` names, with the flag, and of none for a
/// CPU past the machine's), as Linux's interrupts do, and returns once those
/// that were running guest code have stopped since.
fn sys_membarrier(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    use std::sync::atomic::Ordering;
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
        c.mem.barrier();
        ok(0)
    };
    match cmd {
        QUERY => ok(0x3ff),
        GLOBAL | GLOBAL_EXPEDITED => {
            c.mem.barrier();
            ok(0)
        }
        REGISTER_GLOBAL_EXPEDITED => register(GLOBAL_STATE, GLOBAL_READY),
        PRIVATE_EXPEDITED => barrier(PRIVATE_READY),
        REGISTER_PRIVATE_EXPEDITED => register(PRIVATE, PRIVATE_READY),
        PRIVATE_EXPEDITED_SYNC_CORE => barrier(SYNC_CORE_READY),
        REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => register(PRIVATE | SYNC_CORE, SYNC_CORE_READY),
        PRIVATE_EXPEDITED_RSEQ => {
            if state.load(Ordering::SeqCst) & RSEQ_READY == 0 {
                return err(Errno::EPERM);
            }
            // A negative CPU is every CPU, as Linux's
            // membarrier_private_expedited takes it.
            let cpu = (flags & FLAG_CPU != 0).then_some(a[2] as u32 as i32);
            let cpus = &c.processes.cpus;
            if let Some(cpu) = cpu.filter(|&cpu| cpu >= 0)
                && cpu as usize >= c.host.cpu_count().clamp(1, 8192)
            {
                return ok(0);
            }
            c.mem.barrier();
            crate::rseq::restart_others(
                cpus,
                c.host,
                c.cancellation,
                std::ptr::from_ref(c.mem).addr(),
                c.process.on_cpu.map(|on| on.runner),
                cpu.filter(|&cpu| cpu >= 0).map(|cpu| cpu as u32),
            );
            ok(0)
        }
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
