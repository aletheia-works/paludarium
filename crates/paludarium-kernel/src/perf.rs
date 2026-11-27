//! `perf_event_open`, as Linux's `kernel/events/core.c` checks its
//! arguments, for the software events the emulator can count: `cpu-clock`
//! and `task-clock` (the thread's CPU time, or for an event of a CPU the
//! time that passes); `page-faults`, `minor-faults`, `major-faults`,
//! `context-switches` and `cpu-migrations` of a thread, from what it used
//! ([`crate::Usage`]); and `alignment-faults`, `emulation-faults`, `dummy`
//! and `bpf-output`, which never count here (on x86-64 Linux neither). Hardware, cache and raw events find no
//! PMU (`ENOENT`), as on a machine without one; `cgroup-switches`,
//! tracepoints and breakpoints are not there (`ENOENT`) either.
//!
//! An event is read (`read`), enabled, disabled and reset (the `ioctl`s,
//! with `PERF_IOC_FLAG_GROUP`), and grouped; `enable_on_exec` enables it
//! when its task runs `execve`, and `prctl`'s `PR_TASK_PERF_EVENTS_DISABLE`
//! and `ENABLE` disable and enable those the calling thread opened. The
//! machine keeps both lists ([`Events`]). An event of a task maps its
//! ring buffer ([`buffer`]), whose user page shows the count and times as
//! of the event's `mmap`, its enabling and its reset. A sampling event
//! writes its samples there ([`sample`]), taken as its thread makes a
//! system call; its wakeups make the buffer readable for `poll`, and its
//! overflows signal through `O_ASYNC` and `sigtrap`. `SET_OUTPUT` and
//! `PERF_FLAG_FD_OUTPUT` make an event write to another's buffer
//! ([`buffer::set_output`]).
mod buffer;
mod build_id;
mod sample;
mod side_band;

pub(crate) use sample::{Task, Who, clock_due, overflow, samples_faults, sampling};
pub(crate) use side_band::{Space, comm, wanted};

use crate::ThreadGroup;
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, FileHandle, FileStat, Host};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

/// `kernel.perf_event_mlock_kb`'s default, Linux's: 512 KiB and a page.
pub(crate) const MLOCK_KB: i32 = 512 + 4;

/// `kernel.perf_event_paranoid`'s default, Linux's, which the machine's
/// starts with ([`crate::sysctl::Machine`]).
pub(crate) const PARANOID: i32 = 2;
/// `kernel.perf_event_max_sample_rate`'s default, Linux's
/// (`DEFAULT_MAX_SAMPLE_RATE`), which the machine's starts with.
pub(crate) const MAX_SAMPLE_RATE: i32 = 100_000;
/// `kernel.perf_cpu_time_max_percent`'s default, Linux's
/// (`DEFAULT_CPU_TIME_MAX_PERCENT`).
pub(crate) const CPU_TIME_MAX_PERCENT: i32 = 25;

const CAP_PERFMON: u64 = 1 << 38;
const EACCES: Errno = Errno::EACCES;
const ESRCH: Errno = Errno(3);
const ECHILD: Errno = Errno(10);
const E2BIG: Errno = Errno(7);
const ENOSPC: Errno = Errno::ENOSPC;
const EBADF: Errno = Errno::EBADF;
const O_RDWR: u32 = 2;

const PERF_FLAG_FD_NO_GROUP: u64 = 1;
const PERF_FLAG_FD_OUTPUT: u64 = 2;
const PERF_FLAG_PID_CGROUP: u64 = 4;
const PERF_FLAG_FD_CLOEXEC: u64 = 8;
const PERF_FLAG_ALL: u64 =
    PERF_FLAG_FD_NO_GROUP | PERF_FLAG_FD_OUTPUT | PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_CLOEXEC;

/// `PERF_ATTR_SIZE_VER0`, and `sizeof(struct perf_event_attr)` in Linux
/// master (`PERF_ATTR_SIZE_VER10`).
const SIZE_VER0: usize = 64;
const SIZE: usize = 176;
const PAGE: usize = 4096;

const TYPE_HARDWARE: u32 = 0;
const TYPE_SOFTWARE: u32 = 1;
const TYPE_HW_CACHE: u32 = 3;

const SW_CPU_CLOCK: u64 = 0;
const SW_TASK_CLOCK: u64 = 1;
const SW_PAGE_FAULTS: u64 = 2;
const SW_CONTEXT_SWITCHES: u64 = 3;
const SW_CPU_MIGRATIONS: u64 = 4;
const SW_PAGE_FAULTS_MIN: u64 = 5;
const SW_PAGE_FAULTS_MAJ: u64 = 6;
const SW_ALIGNMENT_FAULTS: u64 = 7;
const SW_EMULATION_FAULTS: u64 = 8;
const SW_DUMMY: u64 = 9;
const SW_BPF_OUTPUT: u64 = 10;
const SW_MAX: u64 = 12;

const SAMPLE_CALLCHAIN: u64 = 1 << 5;
const SAMPLE_READ: u64 = 1 << 4;
const SAMPLE_TID: u64 = 1 << 1;
const SAMPLE_BRANCH_STACK: u64 = 1 << 11;
const SAMPLE_REGS_USER: u64 = 1 << 12;
const SAMPLE_STACK_USER: u64 = 1 << 13;
const SAMPLE_WEIGHT: u64 = 1 << 14;
const SAMPLE_REGS_INTR: u64 = 1 << 18;
const SAMPLE_PHYS_ADDR: u64 = 1 << 19;
const SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;
const SAMPLE_MAX: u64 = 1 << 25;
/// `PERF_SAMPLE_BRANCH_MAX`, and the privilege-level bits
/// (`PERF_SAMPLE_BRANCH_PLM_ALL`) and those that need privilege
/// (`PERF_SAMPLE_BRANCH_PERM_PLM`, kernel and hypervisor).
const BRANCH_MAX: u64 = 1 << 20;
const BRANCH_USER: u64 = 1;
const BRANCH_KERNEL: u64 = 2;
const BRANCH_HV: u64 = 4;
const BRANCH_PLM_ALL: u64 = BRANCH_USER | BRANCH_KERNEL | BRANCH_HV;

const FORMAT_TOTAL_TIME_ENABLED: u64 = 1;
const FORMAT_TOTAL_TIME_RUNNING: u64 = 2;
const FORMAT_ID: u64 = 4;
const FORMAT_GROUP: u64 = 8;
const FORMAT_LOST: u64 = 16;
const FORMAT_MAX: u64 = 32;

/// What x86-64's `perf_reg_validate` refuses in a register mask: DS, ES,
/// FS and GS (`REG_NOSUPPORT`), and the bits between R15 and XMM0
/// (`PERF_REG_X86_RESERVED`). The XMM registers, from bit 32, are the
/// extended registers no software event takes.
const REGS_REFUSED: u64 = 0xf << 12 | 0xff << 24;
const REGS_EXTENDED: u64 = 0xffff_ffff << 32;
/// With SIMD registers, `perf_reg_validate` refuses DS, ES, FS and GS
/// (`REG_NOSUPPORT`) and the bits from `PERF_REG_MISC_MAX` (41) on
/// (`PERF_REG_X86_EXT_RESERVED`): the mask then names the general
/// registers, the extended ones (R16 to R31) and SSP.
const REGS_SIMD_REFUSED: u64 = 0xf << 12 | !((1 << 41) - 1);

/// The bits of the flags word, by position.
mod bit {
    pub const DISABLED: u32 = 0;
    pub const INHERIT: u32 = 1;
    pub const PINNED: u32 = 2;
    pub const EXCLUSIVE: u32 = 3;
    pub const EXCLUDE_USER: u32 = 4;
    pub const EXCLUDE_KERNEL: u32 = 5;
    pub const MMAP: u32 = 8;
    pub const COMM: u32 = 9;
    pub const FREQ: u32 = 10;
    pub const INHERIT_STAT: u32 = 11;
    pub const TASK: u32 = 13;
    pub const WATERMARK: u32 = 14;
    pub const MMAP_DATA: u32 = 17;
    pub const MMAP2: u32 = 23;
    pub const SAMPLE_ID_ALL: u32 = 18;
    pub const ENABLE_ON_EXEC: u32 = 12;
    pub const EXCLUDE_CALLCHAIN_KERNEL: u32 = 21;
    pub const EXCLUDE_CALLCHAIN_USER: u32 = 22;
    pub const USE_CLOCKID: u32 = 25;
    pub const WRITE_BACKWARD: u32 = 27;
    pub const NAMESPACES: u32 = 28;
    pub const AUX_OUTPUT: u32 = 31;
    pub const TEXT_POKE: u32 = 33;
    pub const BUILD_ID: u32 = 34;
    pub const INHERIT_THREAD: u32 = 35;
    pub const REMOVE_ON_EXEC: u32 = 36;
    pub const SIGTRAP: u32 = 37;
    /// `__reserved_1`, from bit 40.
    pub const RESERVED: u32 = 40;
}

/// What of a `struct perf_event_attr` the checks and the event read.
#[derive(Clone, Copy, Debug, Default)]
struct Attr {
    kind: u32,
    config: u64,
    period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    /// `wakeup_events`, or with `watermark` `wakeup_watermark`.
    wakeup: u32,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    /// `sample_max_stack`, which `perf_event_open` makes
    /// `kernel.perf_event_max_stack` for a callchain without one.
    sample_max_stack: u16,
    aux_action: u32,
    /// `sig_data`, which a `sigtrap` signal carries.
    sig_data: u64,
    reserved_2: u16,
    simd_enabled: u16,
    /// `sample_simd_pred_reg_qwords` and `sample_simd_vec_reg_qwords`.
    pred_qwords: u16,
    vec_qwords: u16,
    reserved_4: u16,
    /// `sample_simd_pred_reg_intr`, `_user`, and `sample_simd_vec_reg_intr`,
    /// `_user`.
    pred_intr: u32,
    pred_user: u32,
    vec_intr: u64,
    vec_user: u64,
}

impl Attr {
    fn flag(&self, bit: u32) -> bool {
        self.flags >> bit & 1 != 0
    }
    fn sampling(&self) -> bool {
        self.period != 0
    }
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}
fn half(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}
fn quarter(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap_or([0; 2]))
}

fn perfmon_capable(c: &Context<'_>) -> bool {
    let credentials = &c.process.credentials;
    credentials.capable(CAP_PERFMON) || credentials.capable(crate::credentials::CAP_SYS_ADMIN)
}

/// `perf_allow_kernel`: `EACCES` with `perf_event_paranoid` above 1,
/// unless `perfmon_capable`.
fn allow_kernel(c: &Context<'_>) -> Result<(), Errno> {
    if c.processes.sysctls.perf_event_paranoid() > 1 && !perfmon_capable(c) {
        return Err(EACCES);
    }
    Ok(())
}

/// `perf_allow_cpu`: `EACCES` with `perf_event_paranoid` above 0, unless
/// `perfmon_capable`.
fn allow_cpu(c: &Context<'_>) -> Result<(), Errno> {
    if c.processes.sysctls.perf_event_paranoid() > 0 && !perfmon_capable(c) {
        return Err(EACCES);
    }
    Ok(())
}

/// Linux's `perf_copy_attr`: the size (0 is `PERF_ATTR_SIZE_VER0`, less
/// than that or more than a page `E2BIG`, which writes the size Linux
/// knows back; bytes past it must be 0), the reserved fields, the sample
/// and read formats, the branch, register and stack sampling, and the
/// flags that go together.
fn copy_attr(c: &Context<'_>, at: u64) -> Result<Attr, Errno> {
    let mut size_bytes = [0; 4];
    c.mem
        .read(GuestAddr(at.wrapping_add(4)), &mut size_bytes)
        .map_err(|_| Errno::EFAULT)?;
    let mut size = u32::from_le_bytes(size_bytes) as usize;
    if size == 0 {
        size = SIZE_VER0;
    }
    let too_big = |c: &Context<'_>| {
        let _ = c
            .mem
            .write(GuestAddr(at.wrapping_add(4)), &(SIZE as u32).to_le_bytes());
        Err(E2BIG)
    };
    if !(SIZE_VER0..=PAGE).contains(&size) {
        return too_big(c);
    }
    let mut b = vec![0; size.max(SIZE)];
    c.mem
        .read(GuestAddr(at), &mut b[..size])
        .map_err(|_| Errno::EFAULT)?;
    if b.get(SIZE..size)
        .is_some_and(|tail| tail.iter().any(|&byte| byte != 0))
    {
        return too_big(c);
    }
    let attr = Attr {
        kind: half(&b, 0),
        config: word(&b, 8),
        period: word(&b, 16),
        sample_type: word(&b, 24),
        read_format: word(&b, 32),
        flags: word(&b, 40),
        wakeup: half(&b, 48),
        branch_sample_type: word(&b, 72),
        sample_regs_user: word(&b, 80),
        sample_stack_user: half(&b, 88),
        clockid: half(&b, 92) as i32,
        sample_regs_intr: word(&b, 96),
        sample_max_stack: quarter(&b, 108),
        reserved_2: quarter(&b, 110),
        aux_action: half(&b, 116),
        sig_data: word(&b, 120),
        simd_enabled: quarter(&b, 144),
        pred_qwords: quarter(&b, 146),
        vec_qwords: quarter(&b, 148),
        reserved_4: quarter(&b, 150),
        pred_intr: half(&b, 152),
        pred_user: half(&b, 156),
        vec_intr: word(&b, 160),
        vec_user: word(&b, 168),
    };
    if attr.flags >> bit::RESERVED != 0
        || attr.reserved_2 != 0
        || attr.aux_action >> 3 != 0
        || attr.reserved_4 != 0
    {
        return Err(Errno::EINVAL);
    }
    if attr.sample_type & !(SAMPLE_MAX - 1) != 0 || attr.read_format & !(FORMAT_MAX - 1) != 0 {
        return Err(Errno::EINVAL);
    }
    if attr.sample_type & SAMPLE_BRANCH_STACK != 0 {
        let mut mask = attr.branch_sample_type;
        if mask & !(BRANCH_MAX - 1) != 0 || mask & !BRANCH_PLM_ALL == 0 {
            return Err(Errno::EINVAL);
        }
        if mask & BRANCH_PLM_ALL == 0 {
            if !attr.flag(bit::EXCLUDE_KERNEL) {
                mask |= BRANCH_KERNEL;
            }
            // exclude_user and exclude_hv.
            if !attr.flag(4) {
                mask |= BRANCH_USER;
            }
            if !attr.flag(6) {
                mask |= BRANCH_HV;
            }
        }
        if mask & (BRANCH_KERNEL | BRANCH_HV) != 0 {
            allow_kernel(c)?;
        }
    }
    if attr.sample_type & SAMPLE_REGS_USER != 0 {
        regs(&attr, attr.sample_regs_user, attr.vec_user, attr.pred_user)?;
    }
    if attr.sample_type & SAMPLE_STACK_USER != 0
        && (attr.sample_stack_user >= u32::from(u16::MAX)
            || !attr.sample_stack_user.is_multiple_of(8))
    {
        return Err(Errno::EINVAL);
    }
    let mut attr = attr;
    if attr.sample_max_stack == 0 {
        attr.sample_max_stack = sample::MAX_STACK;
    }
    if attr.sample_type & SAMPLE_REGS_INTR != 0 {
        regs(&attr, attr.sample_regs_intr, attr.vec_intr, attr.pred_intr)?;
    }
    if attr.sample_type & SAMPLE_WEIGHT != 0 && attr.sample_type & SAMPLE_WEIGHT_STRUCT != 0 {
        return Err(Errno::EINVAL);
    }
    if !attr.flag(bit::INHERIT) && attr.flag(bit::INHERIT_THREAD) {
        return Err(Errno::EINVAL);
    }
    if attr.flag(bit::REMOVE_ON_EXEC) && attr.flag(bit::ENABLE_ON_EXEC) {
        return Err(Errno::EINVAL);
    }
    if attr.flag(bit::SIGTRAP) && !attr.flag(bit::REMOVE_ON_EXEC) {
        return Err(Errno::EINVAL);
    }
    Ok(attr)
}

/// x86-64's `perf_reg_validate` of a register mask and, with SIMD
/// registers (`sample_simd_regs_enabled`), `perf_simd_reg_validate` of the
/// vector and predicate ones (`EINVAL`).
fn regs(attr: &Attr, mask: u64, vector: u64, predicate: u32) -> Result<(), Errno> {
    if attr.simd_enabled == 0 {
        return if mask == 0 || mask & REGS_REFUSED != 0 {
            Err(Errno::EINVAL)
        } else {
            Ok(())
        };
    }
    // The mask may be 0 when only the SIMD registers are asked for.
    if mask & REGS_SIMD_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    simd_regs(attr.vec_qwords, vector, attr.pred_qwords, predicate)
}

/// x86's `perf_simd_reg_validate`: vector registers of XMM (2 quadwords),
/// YMM (4) or ZMM (8) size, all 16, 16 or 32 of them or none, and the
/// opmask registers (1 quadword), all 8 or none, for no more than half of
/// a 64 KiB sample with the 4 quadwords before them.
fn simd_regs(vec_qwords: u16, vector: u64, pred_qwords: u16, predicate: u32) -> Result<(), Errno> {
    /// Whether the first `n` registers of `mask` are all there, or none is
    /// (`bitmap_full(&mask, n)`, which looks at those bits alone: more of
    /// them, up to the 32 vector registers, are let through, as on Linux).
    fn whole(mask: u64, n: u32) -> bool {
        let first = (1u64 << n) - 1;
        mask == 0 || mask & first == first
    }
    if vec_qwords == 0 && pred_qwords == 0 && (vector != 0 || predicate != 0) {
        return Err(Errno::EINVAL);
    }
    if vec_qwords != 0 {
        let registers = match vec_qwords {
            2 | 4 => 16,
            8 => 32,
            _ => return Err(Errno::EINVAL),
        };
        if vector >> 32 != 0 || !whole(vector, registers) {
            return Err(Errno::EINVAL);
        }
    }
    if pred_qwords != 0 && (pred_qwords != 1 || predicate >> 8 != 0 || !whole(predicate.into(), 8))
    {
        return Err(Errno::EINVAL);
    }
    let qwords = 4
        + u64::from(vector.count_ones()) * u64::from(vec_qwords)
        + u64::from(predicate.count_ones()) * u64::from(pred_qwords);
    if qwords * 8 >= u64::from(u16::MAX) / 2 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// What an event counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Counter {
    /// `cpu-clock` and `task-clock`: nanoseconds.
    Clock,
    /// `page-faults`, `minor-faults` and `major-faults`: the faults the
    /// thread's accesses took ([`crate::Usage::faults`]) of a
    /// [`crate::FaultKind`]. A major one is of the kernel's accesses alone.
    Faults(crate::FaultKind),
    /// `context-switches`: the times the thread went to sleep.
    Switches,
    /// `cpu-migrations`: the times it moved to another CPU.
    Migrations,
    /// An event that never happens here.
    Zero,
}

/// Whose an event is.
#[derive(Clone)]
enum Target {
    /// A thread, of the thread group that holds it.
    Thread { group: Arc<ThreadGroup>, tid: u32 },
    /// A CPU, as an event of no task is: the time that passes, and what
    /// any thread counts there.
    Cpu,
}

#[derive(Default)]
struct State {
    /// Enabled (Linux's state above `OFF`), and kept from counting by a
    /// leader that is not (the group is not scheduled in).
    enabled: bool,
    paused: bool,
    count: u64,
    /// `total_time_enabled` and `total_time_running`.
    enabled_time: u64,
    running_time: u64,
    /// The clock when these were last brought up to date.
    since: u64,
    /// The time on its CPU then, which only runs and counts: less than the
    /// clock's for an event of a thread on one CPU.
    since_on: u64,
    /// For a counter of the thread's [`crate::Usage`], its values then, in
    /// the thread's own code and in system calls.
    tally: (u64, u64),
    /// What it has counted in each of those, and for a clock the time,
    /// in the first: the occurrences its samples are taken of
    /// ([`sample`]), which a reset leaves.
    occurred: [u64; 2],
    /// What inherited events of tasks that have ended gave back
    /// (`child_count`, `child_total_time_enabled`, `_running`).
    child_count: u64,
    child_enabled: u64,
    child_running: u64,
    /// In Linux's `PERF_EVENT_STATE_EXIT`: `remove_on_exec` took it out of
    /// its task and its group at the task's `execve`, or its task ended. It
    /// counts no more, is not enabled again, and its last count and times
    /// stay to be read.
    removed: bool,
}

/// One event: Linux's `struct perf_event`.
pub(crate) struct Event {
    /// The opened event's ID, which those inherited from it share
    /// (`primary_event_id`), and its own (`id`, a sample's `stream_id`).
    id: u64,
    stream_id: u64,
    /// The PID namespace of the task that opened it (`ns`), which numbers
    /// the tasks its samples show.
    ns: Arc<crate::namespaces::Namespace>,
    attr: Attr,
    counter: Counter,
    target: Target,
    cpu: i32,
    /// The machine's processes, whose threads an event of a CPU counts.
    machine: Erased,
    /// What a sampling event of a CPU has seen of each thread
    /// ([`sample`]).
    looks: Mutex<Vec<sample::Look>>,
    clockid: Option<i32>,
    host: Arc<dyn Host>,
    /// The group's leader, `None` for one that leads its own: taken away
    /// when either leaves the group (`perf_group_detach`). It and the
    /// events below are held by no particular type ([`Held`], [`Erased`]).
    leader: Mutex<Option<Held>>,
    siblings: Mutex<Vec<Erased>>,
    state: Mutex<State>,
    /// For one a new task inherited (`inherit`), the event it comes from,
    /// the one opened, as Linux keeps `parent` at the top of the tree.
    parent: Option<Erased>,
    /// The opened event's inherited ones, of the tasks that still run
    /// (`child_list`).
    children: Mutex<Vec<Held>>,
    /// The ring buffer it writes to (`rb`), while one is mapped.
    rb: Mutex<Option<Arc<buffer::Buffer>>>,
    /// What the mappings of the buffer it made hold (`mmap_count`).
    mapped: Mutex<Weak<buffer::Mapped>>,
    /// Held while the event's buffer is mapped (`mmap_mutex`).
    mmap_mutex: Mutex<()>,
    /// Its period and where it is in it, and the samples it lost.
    sampler: Mutex<sample::Sampler>,
    /// What wakes those who wait in `poll` or `epoll` for it (`waitq`): the
    /// readiness of the files of the process that opened it.
    hub: Arc<crate::events::ReadinessHub>,
    /// Where `O_ASYNC` sends its signals (`fasync`), and its file, whose
    /// owner `F_SETOWN` gave.
    fasync: Mutex<Option<sample::Fasync>>,
    /// `event_limit`: the overflows `PERF_EVENT_IOC_REFRESH` allows before
    /// it is disabled, 0 for no limit.
    event_limit: std::sync::atomic::AtomicI32,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The machine's events by the thread that opened them (each task's
/// `perf_event_list`, for `PR_TASK_PERF_EVENTS_DISABLE` and `ENABLE`), and
/// those that wait for their task's `execve` (`enable_on_exec` and
/// `remove_on_exec`), each matched by its task's thread group as well as
/// its thread ID.
#[derive(Default)]
pub(crate) struct Events {
    lists: Mutex<Lists>,
    /// What users and address spaces have locked of ring buffers.
    accounts: Arc<buffer::Accounts>,
    /// Whether an event of a task has sampled, so that the system calls
    /// look for samples to take ([`sample::overflow`]) only then.
    sampling: std::sync::atomic::AtomicBool,
    /// Whether an event has asked for side-band records, so that
    /// the hooks look for those that take them only then ([`side_band`]).
    side_band: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct Lists {
    owned: Vec<Owned>,
    on_exec: Vec<Erased>,
    /// The events that count a thread, for its exit.
    counting: Vec<Erased>,
    /// Those of a CPU that ask for side-band records (`pmu_sb_events`).
    side_band: Vec<Erased>,
    /// Those of a CPU that sample.
    cpu_sampling: Vec<Erased>,
    /// The opened ones that ask for side-band records, of a thread or a
    /// CPU, enabled or not, while they are open (`account_event`).
    asking: Vec<Erased>,
}

/// A reference that holds an [`Event`] or a [`ThreadGroup`] by no
/// particular type. `Processes` keeps these lists, and an event holds its
/// task's group, which leads back to `Processes`: kept by their own types,
/// the compiler's checks of what may be sent between threads would go
/// round that loop past their limit.
type Erased = Weak<dyn std::any::Any + Send + Sync>;

fn erase<T: Send + Sync + 'static>(value: &Arc<T>) -> Erased {
    let value: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(value) as _;
    Arc::downgrade(&value)
}

/// The event an [`Erased`] holds, while it is there.
fn event(erased: &Erased) -> Option<Arc<Event>> {
    erased.upgrade()?.downcast::<Event>().ok()
}

/// An [`Event`] another holds (its group's leader, or an inherited one),
/// by no particular type as [`Erased`] is: an event's leader, members,
/// parent and children are events, and kept by their own type the
/// compiler's checks of what may be sent between threads would go round
/// them past their limit.
#[derive(Clone)]
struct Held(Arc<dyn std::any::Any + Send + Sync>);

impl Held {
    fn new(event: &Arc<Event>) -> Self {
        Self(Arc::clone(event) as _)
    }
    /// The event it holds.
    fn get(&self) -> Option<Arc<Event>> {
        Arc::clone(&self.0).downcast::<Event>().ok()
    }
    /// Whether it holds `event`.
    fn is(&self, event: &Event) -> bool {
        std::ptr::addr_eq(Arc::as_ptr(&self.0), event)
    }
}

/// An event and the thread that opened it (`event->owner`).
struct Owned {
    group: Erased,
    tid: u32,
    event: Erased,
}

impl Owned {
    fn of(&self, group: &ThreadGroup) -> bool {
        std::ptr::addr_eq(self.group.as_ptr(), group)
    }
}

impl Events {
    /// A new event, opened by thread `tid` of `group`; those of events that
    /// are gone go first.
    fn add(&self, event: &Arc<Event>, group: &Arc<ThreadGroup>, tid: u32) {
        let mut lists = lock(&self.lists);
        lists.owned.retain(|owned| owned.event.strong_count() > 0);
        lists.on_exec.retain(|event| event.strong_count() > 0);
        lists.counting.retain(|event| event.strong_count() > 0);
        lists.side_band.retain(|event| event.strong_count() > 0);
        lists.asking.retain(|event| event.strong_count() > 0);
        lists.cpu_sampling.retain(|event| event.strong_count() > 0);
        if side_band::asks(&event.attr) {
            self.side_band.store(true, Ordering::Relaxed);
            lists.asking.push(erase(event));
            if matches!(event.target, Target::Cpu) {
                lists.side_band.push(erase(event));
            }
        }
        if event.attr.sampling() {
            self.sampling.store(true, Ordering::Relaxed);
            if event.shows_address() {
                paludarium_mmu::faults::trace_addresses();
            }
        }
        match event.target {
            Target::Thread { .. } => lists.counting.push(erase(event)),
            Target::Cpu if event.attr.sampling() => lists.cpu_sampling.push(erase(event)),
            Target::Cpu => {}
        }
        lists.owned.push(Owned {
            group: erase(group),
            tid,
            event: erase(event),
        });
        let attr = &event.attr;
        if attr.flag(bit::DISABLED) && attr.flag(bit::ENABLE_ON_EXEC)
            || attr.flag(bit::REMOVE_ON_EXEC)
        {
            lists.on_exec.push(erase(event));
        }
    }

    /// The events thread `tid` of `group` opened.
    fn owned_by(&self, group: &ThreadGroup, tid: u32) -> Vec<Arc<Event>> {
        lock(&self.lists)
            .owned
            .iter()
            .filter(|owned| owned.tid == tid && owned.of(group))
            .filter_map(|owned| event(&owned.event))
            .collect()
    }
}

/// `PR_TASK_PERF_EVENTS_DISABLE` and `ENABLE` (`perf_event_task_disable`,
/// `perf_event_task_enable`): every event the calling thread opened,
/// whatever task it counts, is disabled or enabled, as its ioctl without
/// `PERF_IOC_FLAG_GROUP` does; the other arguments are not read.
pub(crate) fn prctl_task_events(events: &Events, group: &ThreadGroup, tid: u32, enable: bool) {
    for event in events.owned_by(group, tid) {
        if enable {
            event.enable();
        } else {
            event.disable();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Event {
    /// The event's clock: the thread's CPU time, or the time that passes;
    /// and how much of it was on the event's CPU, all of it but for an
    /// event of a thread on one. A thread that runs is looked at now, as
    /// `perf_event_read` has its CPU bring the event up to date.
    fn now(&self, state: &State) -> (u64, u64) {
        let Target::Thread { group, tid } = &self.target else {
            let now = self.host.clock(ClockId::Monotonic).unwrap_or(0);
            return (now, now);
        };
        let Some(usage) = group.last_thread_usage(*tid) else {
            return (state.since, state.since_on);
        };
        usage.sample();
        match u32::try_from(self.cpu) {
            Ok(cpu) => usage.time_on(cpu),
            Err(_) => {
                let now = usage.cpu_time();
                (now, now)
            }
        }
    }
    /// The state brought up to now: the time since the last update counts
    /// as enabled while it is, and as running and counted while it runs.
    fn settle(&self) -> MutexGuard<'_, State> {
        // Before the state is locked, as it looks at the machine's threads.
        let used = self.used();
        let mut state = lock(&self.state);
        let (now, on) = self.now(&state);
        let passed = now.saturating_sub(state.since);
        state.since = now;
        // An event of a thread on one CPU is scheduled in only while the
        // thread runs there (`event_filter_match`): its time enabled is
        // the thread's, and its time running and count only that CPU's.
        let ran = on.saturating_sub(state.since_on);
        state.since_on = on;
        // Another may have looked later than this did.
        let tallied = used.map_or((0, 0), |(user, kernel)| {
            let tally = (user.max(state.tally.0), kernel.max(state.tally.1));
            let more = (tally.0 - state.tally.0, tally.1 - state.tally.1);
            state.tally = tally;
            more
        });
        if state.enabled {
            state.enabled_time += passed;
            if !state.paused {
                state.running_time += ran;
                let (user, kernel) = if self.counter == Counter::Clock {
                    (ran, 0)
                } else {
                    tallied
                };
                state.count += user + kernel;
                state.occurred[0] += user;
                state.occurred[1] += kernel;
            }
        }
        state
    }
    /// What the thread's [`crate::Usage`] counts for a counter of it (its
    /// faults as they are taken, its switches and migrations as of its
    /// latest system call), and kept once it is gone, or for an event of a
    /// CPU what every thread of the machine counts there; `None` for the
    /// other counters, and a thread that has made no
    /// system call yet. As Linux's `perf_exclude_event` has it, the faults
    /// of the thread's code are left out with `exclude_user` and those of
    /// system calls with `exclude_kernel`, which leaves out the switches and
    /// migrations too, as the kernel makes them.
    fn used(&self) -> Option<(u64, u64)> {
        if !matches!(
            self.counter,
            Counter::Faults(_) | Counter::Switches | Counter::Migrations
        ) {
            return None;
        }
        let cpu = u32::try_from(self.cpu);
        let Target::Thread { group, tid } = &self.target else {
            return Some(self.of_counts(self.machine()?.counts_on(cpu.ok()?)));
        };
        let usage = group.last_thread_usage(*tid)?;
        // Of an event of one CPU, what the thread counted there alone.
        Some(self.of_counts(match cpu {
            Ok(cpu) => usage.counts_on(cpu),
            Err(_) => usage.counts(),
        }))
    }
    /// The machine's processes.
    fn machine(&self) -> Option<Arc<crate::processes::Processes>> {
        self.machine.upgrade()?.downcast().ok()
    }
    /// What of `counts` ([`crate::CpuCounts`]'s) its counter counts, in
    /// user mode and in the kernel, of what is not left out.
    fn of_counts(&self, counts: crate::Counts) -> (u64, u64) {
        let (user, kernel) = self.of_all_counts(counts);
        let user = if self.attr.flag(bit::EXCLUDE_USER) {
            0
        } else {
            user
        };
        let kernel = if self.attr.flag(bit::EXCLUDE_KERNEL) {
            0
        } else {
            kernel
        };
        (user, kernel)
    }
    /// What of `counts` its counter counts, in user mode and in the kernel,
    /// with nothing left out.
    fn of_all_counts(&self, counts: crate::Counts) -> (u64, u64) {
        let [
            faults,
            kernel_faults,
            switches,
            migrations,
            major_faults,
            unfinished_faults,
        ] = counts;
        match self.counter {
            Counter::Faults(crate::FaultKind::All) => (
                faults.saturating_add(unfinished_faults),
                kernel_faults.saturating_add(major_faults),
            ),
            Counter::Faults(crate::FaultKind::Minor) => (faults, kernel_faults),
            Counter::Faults(crate::FaultKind::Major) => (0, major_faults),
            Counter::Switches => (0, switches),
            _ => (0, migrations),
        }
    }
    /// The count, the time enabled and the time running now.
    fn values(&self) -> (u64, u64, u64) {
        let state = self.settle();
        (state.count, state.enabled_time, state.running_time)
    }
    /// Whether it is enabled.
    fn enabled(&self) -> bool {
        lock(&self.state).enabled
    }
    fn set_paused(&self, paused: bool) {
        let was = std::mem::replace(&mut self.settle().paused, paused);
        if was && !paused {
            self.look_at_all();
        }
    }
    /// The group's members but the leader.
    fn members(&self) -> Vec<Arc<Event>> {
        lock(&self.siblings).iter().filter_map(event).collect()
    }
    fn set_enabled(&self, enabled: bool) {
        {
            let mut state = self.settle();
            if state.removed {
                return;
            }
            let was = std::mem::replace(&mut state.enabled, enabled);
            drop(state);
            // `event_sched_in` unthrottles an event it takes in.
            if enabled && !was {
                lock(&self.sampler).scheduled_in();
                self.look_at_all();
            }
        }
        // A leader takes its group in and out with it.
        if lock(&self.leader).is_none() {
            for member in self.members() {
                member.set_paused(!enabled);
            }
        }
    }
    /// Whether it counts thread `tid` of `group`.
    fn counts(&self, group: &ThreadGroup, tid: u32) -> bool {
        matches!(&self.target, Target::Thread { group: target, tid: target_tid }
            if *target_tid == tid && std::ptr::eq(Arc::as_ptr(target), group))
    }
    /// `inherit_event`: the event a new task gets from this one, counting
    /// `target`, a member of `leader`'s group or a leader. It comes from the
    /// opened event, at the top, and is enabled as this one is; none comes
    /// once the opened event's file is closed.
    fn inherit(
        self: &Arc<Self>,
        target: Target,
        leader: Option<&Arc<Event>>,
    ) -> Option<Arc<Event>> {
        let top = match &self.parent {
            Some(parent) => event(parent)?,
            None => Arc::clone(self),
        };
        let enabled = {
            let state = lock(&self.state);
            state.enabled && !state.removed
        };
        let sampler = lock(&top.sampler).inherited(top.counter);
        let child = Arc::new(Event {
            id: top.id,
            stream_id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            ns: Arc::clone(&top.ns),
            attr: top.attr,
            counter: top.counter,
            target,
            cpu: top.cpu,
            machine: top.machine.clone(),
            looks: Mutex::default(),
            clockid: top.clockid,
            host: Arc::clone(&top.host),
            leader: Mutex::new(leader.map(Held::new)),
            siblings: Mutex::default(),
            state: Mutex::new(State {
                enabled,
                paused: leader.is_some_and(|leader| !leader.enabled()),
                ..State::default()
            }),
            parent: Some(erase(&top)),
            children: Mutex::default(),
            rb: Mutex::default(),
            mapped: Mutex::default(),
            mmap_mutex: Mutex::default(),
            sampler: Mutex::new(sampler),
            hub: Arc::clone(&top.hub),
            fasync: Mutex::default(),
            event_limit: Default::default(),
        });
        if let Some(leader) = leader {
            lock(&leader.siblings).push(erase(&child));
        }
        lock(&top.children).push(Held::new(&child));
        Some(child)
    }
    /// The inherited events, of the tasks that still run.
    fn children(&self) -> Vec<Arc<Event>> {
        lock(&self.children).iter().filter_map(Held::get).collect()
    }
    /// `_perf_event_enable` and `_disable` through
    /// `perf_event_for_each_child`: the event and those inherited from it.
    fn enable(&self) {
        self.set_enabled(true);
        self.update_user_page();
        for child in self.children() {
            child.set_enabled(true);
        }
    }
    fn disable(&self) {
        self.set_enabled(false);
        for child in self.children() {
            child.set_enabled(false);
        }
    }
    /// Linux's reset clears the count, the inherited events' too, and
    /// leaves the times and what ended children gave back.
    fn reset(&self) {
        self.settle().count = 0;
        self.update_user_page();
        for child in self.children() {
            child.settle().count = 0;
        }
    }
    /// `__perf_event_read_value`: the count and times of the event, of what
    /// ended children gave back, and of the inherited events still running.
    fn totals(&self) -> (u64, u64, u64) {
        let (mut count, mut enabled, mut running) = {
            let state = self.settle();
            (
                state.count + state.child_count,
                state.enabled_time + state.child_enabled,
                state.running_time + state.child_running,
            )
        };
        for child in self.children() {
            let (c, e, r) = child.values();
            count += c;
            enabled += e;
            running += r;
        }
        (count, enabled, running)
    }
    /// `sync_child_event`: an inherited event's task ends, and the event
    /// it comes from takes its count and times.
    /// With `inherit_stat`, first `PERF_RECORD_READ` of them, written by the
    /// task `who`, which it is (`perf_event_read_event`).
    fn give_back(self: &Arc<Self>, who: &Who) {
        if self.attr.flag(bit::INHERIT_STAT) {
            let mut body = self.pid_tid_of(who.pid, who.tid).to_vec();
            for value in self.sample_read() {
                body.extend(value.to_le_bytes());
            }
            self.side_band(RECORD_READ, 0, &body, who);
        }
        let Some(parent) = self.parent.as_ref().and_then(event) else {
            return;
        };
        let (count, enabled, running) = self.values();
        {
            let mut state = lock(&parent.state);
            state.child_count += count;
            state.child_enabled += enabled;
            state.child_running += running;
        }
        lock(&parent.children).retain(|child| !child.is(self));
    }
    /// The group's leader: the event itself or the one it joined.
    fn leader(self: &Arc<Self>) -> Arc<Event> {
        lock(&self.leader)
            .as_ref()
            .and_then(Held::get)
            .unwrap_or_else(|| Arc::clone(self))
    }
    /// `perf_group_detach`: a member leaves its leader's group, and a
    /// leader's members each lead a group of their own, counting while they
    /// are enabled.
    fn detach(self: &Arc<Self>) {
        let leader = lock(&self.leader).take();
        if let Some(leader) = leader {
            if let Some(leader) = leader.get() {
                lock(&leader.siblings)
                    .retain(|member| !std::ptr::addr_eq(member.as_ptr(), Arc::as_ptr(self)));
            }
            return;
        }
        let members: Vec<Arc<Event>> = std::mem::take(&mut *lock(&self.siblings))
            .iter()
            .filter_map(event)
            .collect();
        for member in members {
            *lock(&member.leader) = None;
            member.set_paused(false);
        }
    }
    /// The group's events, the leader first.
    fn group(self: &Arc<Self>) -> Vec<Arc<Event>> {
        let leader = self.leader();
        let mut events = vec![Arc::clone(&leader)];
        events.extend(lock(&leader.siblings).iter().filter_map(event));
        events
    }
    /// `perf_event__read_size`.
    fn read_size(self: &Arc<Self>) -> usize {
        let format = self.attr.read_format;
        let mut entry = 8;
        let mut size = 0;
        if format & FORMAT_TOTAL_TIME_ENABLED != 0 {
            size += 8;
        }
        if format & FORMAT_TOTAL_TIME_RUNNING != 0 {
            size += 8;
        }
        if format & FORMAT_ID != 0 {
            entry += 8;
        }
        if format & FORMAT_LOST != 0 {
            entry += 8;
        }
        if format & FORMAT_GROUP != 0 {
            size += 8;
            entry *= self.group().len();
        }
        size + entry
    }
    /// What a read gives (`perf_read_one`, `perf_read_group`), with the
    /// inherited events added in; `ECHILD` for a group whose members are no
    /// longer those it had when a task inherited it.
    fn read_values(self: &Arc<Self>) -> Result<Vec<u64>, Errno> {
        let format = self.attr.read_format;
        let mut values = Vec::new();
        let times = |values: &mut Vec<u64>, enabled: u64, running: u64| {
            if format & FORMAT_TOTAL_TIME_ENABLED != 0 {
                values.push(enabled);
            }
            if format & FORMAT_TOTAL_TIME_RUNNING != 0 {
                values.push(running);
            }
        };
        let entry = |values: &mut Vec<u64>, event: &Event, count: u64| {
            values.push(count);
            if format & FORMAT_ID != 0 {
                values.push(event.id);
            }
            if format & FORMAT_LOST != 0 {
                values.push(lock(&event.sampler).lost);
            }
        };
        if format & FORMAT_GROUP != 0 {
            let group = self.group();
            let members = group.len() - 1;
            if group[0]
                .children()
                .iter()
                .any(|child| child.members().len() != members)
            {
                return Err(ECHILD);
            }
            values.push(group.len() as u64);
            // The members' times are the leader's, as they run together.
            let (_, enabled, running) = group[0].totals();
            times(&mut values, enabled, running);
            for event in &group {
                entry(&mut values, event, event.totals().0);
            }
        } else {
            let (count, enabled, running) = self.totals();
            values.push(count);
            times(&mut values, enabled, running);
            if format & FORMAT_ID != 0 {
                values.push(self.id);
            }
            if format & FORMAT_LOST != 0 {
                values.push(lock(&self.sampler).lost);
            }
        }
        Ok(values)
    }
}

/// The open file: Linux's `[perf_event]`.
pub(crate) struct EventFile {
    event: Arc<Event>,
    /// What `F_SETFL` set of `O_NONBLOCK` and `O_ASYNC`.
    status: std::sync::atomic::AtomicU32,
}

impl EventFile {
    fn new(event: Arc<Event>) -> Self {
        Self {
            event,
            status: Default::default(),
        }
    }
}

fn of(file: &Arc<dyn FileHandle>) -> Option<&Arc<Event>> {
    Some(&file.as_any()?.downcast_ref::<EventFile>()?.event)
}

pub(crate) fn sys_perf_event_open(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    Outcome::Return(open(c, a).unwrap_or_else(Errno::to_syscall_return))
}

/// The task `pid` names for an event (`find_lively_task_by_vpid`): the
/// caller for 0, else the thread the caller's PID namespace numbers so
/// (`ESRCH`), which must be one the caller may read
/// (`perf_check_permission`: `perfmon_capable`, or `ptrace_may_access` with
/// `PTRACE_MODE_READ_REALCREDS`, `EACCES`), which Linux checks once the
/// event is made.
fn task(c: &Context<'_>, pid: i32) -> Result<(Arc<ThreadGroup>, u32, bool), Errno> {
    let own = |tid: u32| {
        c.processes
            .view(c.process.pid)
            .map(|view| (view.group, tid, true))
            .ok_or(ESRCH)
    };
    if pid == 0 {
        return own(c.tid);
    }
    let number = u32::try_from(pid).map_err(|_| ESRCH)?;
    let tid = c.pid_space().task(number).ok_or(ESRCH)?;
    if tid == c.tid || c.group.has_member(tid) {
        return own(tid);
    }
    let leader = match c.processes.view(tid) {
        Some(_) => tid,
        None => c.processes.thread_leader(tid).ok_or(ESRCH)?,
    };
    let view = c.processes.view(leader).ok_or(ESRCH)?;
    if view.zombie {
        return Err(ESRCH);
    }
    let public = view.group.public(tid).ok_or(ESRCH)?;
    let readable = perfmon_capable(c)
        || c.process.credentials.may_read_task(
            &public.credentials,
            (view.dumpable, &view.exec_user),
            true,
        );
    Ok((view.group, tid, readable))
}

/// `perf_event_open(attr, pid, cpu, group_fd, flags)`, in the order of
/// Linux's `sys_perf_event_open`.
fn open(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (pid, cpu, group_fd, flags) = (a[1] as i32, a[2] as i32, a[3] as i32, a[4]);
    if flags & !PERF_FLAG_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let attr = copy_attr(c, a[0])?;
    if !attr.flag(bit::EXCLUDE_KERNEL)
        || attr.flag(bit::TEXT_POKE)
        || attr.sample_type & SAMPLE_CALLCHAIN != 0 && !attr.flag(bit::EXCLUDE_CALLCHAIN_KERNEL)
    {
        allow_kernel(c)?;
    }
    if attr.flag(bit::NAMESPACES) && !perfmon_capable(c) {
        return Err(EACCES);
    }
    if attr.flag(bit::FREQ) {
        if attr.period > c.processes.sysctls.perf_event_max_sample_rate() {
            return Err(Errno::EINVAL);
        }
    } else if attr.period >> 63 != 0 {
        return Err(Errno::EINVAL);
    }
    if attr.sample_type & SAMPLE_PHYS_ADDR != 0 {
        allow_kernel(c)?;
    }
    if flags & PERF_FLAG_PID_CGROUP != 0 && (pid == -1 || cpu == -1) {
        return Err(Errno::EINVAL);
    }
    // The descriptor is taken here; an error after this frees it.
    let mut leader = None;
    let mut output = None;
    if group_fd != -1 {
        let file = c
            .files
            .descriptor(u64::from(group_fd as u32))
            .map_err(|_| EBADF)?
            .file;
        let event = Arc::clone(of(&file).ok_or(EBADF)?);
        // One `remove_on_exec` took out, or whose task ended, is in Linux's
        // `EXIT` state, which no group may be led by (`ENODEV`, as Linux
        // master since 7.2's fa091f46c383; the test machines' 7.0 takes it).
        if lock(&event.state).removed {
            return Err(Errno::ENODEV);
        }
        if flags & PERF_FLAG_FD_OUTPUT != 0 {
            output = Some(Arc::clone(&event));
        }
        if flags & PERF_FLAG_FD_NO_GROUP == 0 {
            leader = Some(event);
        }
    }
    let cgroup = flags & PERF_FLAG_PID_CGROUP != 0;
    let task = if pid == -1 || cgroup {
        None
    } else {
        Some(task(c, pid)?)
    };
    if task.is_some()
        && let Some(leader) = &leader
        && leader.attr.flag(bit::INHERIT) != attr.flag(bit::INHERIT)
    {
        return Err(Errno::EINVAL);
    }
    // perf_event_alloc.
    let cpus = c.host.cpu_count().max(1);
    if (cpu < 0 || cpu as usize >= cpus) && (task.is_none() || cpu != -1) {
        return Err(Errno::EINVAL);
    }
    if attr.flag(bit::SIGTRAP) && task.is_none() {
        return Err(Errno::EINVAL);
    }
    if attr.flag(bit::INHERIT)
        && attr.sample_type & SAMPLE_READ != 0
        && attr.sample_type & SAMPLE_TID == 0
    {
        return Err(Errno::EINVAL);
    }
    let counter = init(&attr)?;
    // No software PMU takes AUX output or `aux_start_paused`, and an event
    // may not both pause and resume AUX output.
    if attr.flag(bit::AUX_OUTPUT) {
        return Err(Errno::EOPNOTSUPP);
    }
    if attr.aux_action & 6 == 6 {
        return Err(Errno::EINVAL);
    }
    if attr.aux_action & 1 != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    // `perf_cgroup_connect` needs a cgroup directory, which there is none
    // of.
    if cgroup {
        return Err(EBADF);
    }
    // `get_callchain_buffers`: no more frames than
    // `kernel.perf_event_max_stack`.
    if attr.sample_type & SAMPLE_CALLCHAIN != 0 && attr.sample_max_stack > sample::MAX_STACK {
        return Err(Errno::EOVERFLOW);
    }
    let clockid = if attr.flag(bit::USE_CLOCKID) {
        // perf_event_set_clock.
        match attr.clockid {
            1 | 4 | 0 | 7 | 11 => Some(attr.clockid),
            _ => return Err(Errno::EINVAL),
        }
    } else {
        None
    };
    let target = match task {
        Some((group, tid, readable)) => {
            if !readable {
                return Err(EACCES);
            }
            Target::Thread { group, tid }
        }
        None => {
            allow_cpu(c)?;
            Target::Cpu
        }
    };
    if let Some(leader) = &leader {
        let same_target = match (&leader.target, &target) {
            (Target::Thread { tid: a, .. }, Target::Thread { tid: b, .. }) => a == b,
            (Target::Cpu, Target::Cpu) => true,
            _ => false,
        };
        if lock(&leader.leader).is_some()
            || leader.clockid != clockid
            || leader.cpu != cpu
            || !same_target
            || attr.flag(bit::EXCLUSIVE)
            || attr.flag(bit::PINNED)
        {
            return Err(Errno::EINVAL);
        }
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let event = Arc::new(Event {
        id,
        stream_id: id,
        ns: c.pid_space(),
        attr,
        counter,
        target,
        cpu,
        machine: erase(c.processes),
        looks: Mutex::default(),
        clockid,
        host: Arc::clone(c.shared_host),
        leader: Mutex::new(leader.as_ref().map(Held::new)),
        siblings: Mutex::default(),
        state: Mutex::default(),
        parent: None,
        children: Mutex::default(),
        rb: Mutex::default(),
        mapped: Mutex::default(),
        mmap_mutex: Mutex::default(),
        sampler: Mutex::new(sample::Sampler::new(&attr, counter)),
        hub: Arc::clone(&c.files.readiness),
        fasync: Mutex::default(),
        event_limit: Default::default(),
    });
    // `PERF_FLAG_FD_OUTPUT`: it writes to the group's event's buffer.
    if let Some(output) = &output {
        buffer::set_output(&event, Some(output))?;
    }
    if let Some(leader) = &leader {
        event.set_paused(!leader.enabled());
        lock(&leader.siblings).push(erase(&event));
    }
    if !attr.flag(bit::DISABLED) {
        event.enable();
    }
    // The caller's own group, which owns the event.
    let own = c.processes.view(c.process.pid).ok_or(ESRCH)?.group;
    c.processes.perf_events.add(&event, &own, c.tid);
    let cloexec = flags & PERF_FLAG_FD_CLOEXEC != 0;
    c.files
        .install(Arc::new(EventFile::new(event)), cloexec, c.group.nofile())
        .map(u64::from)
}

/// The PMU that takes `attr` (`perf_init_event`): the software events that
/// count here, `EOPNOTSUPP` for branch sampling of one, and `ENOENT` for
/// every other type and event, as no PMU takes them.
fn init(attr: &Attr) -> Result<Counter, Errno> {
    match (attr.kind, attr.config) {
        (TYPE_SOFTWARE, config) if config < SW_MAX => {
            if attr.sample_type & SAMPLE_BRANCH_STACK != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            let counter = match config {
                SW_CPU_CLOCK | SW_TASK_CLOCK => Counter::Clock,
                SW_PAGE_FAULTS => Counter::Faults(crate::FaultKind::All),
                SW_PAGE_FAULTS_MIN => Counter::Faults(crate::FaultKind::Minor),
                SW_PAGE_FAULTS_MAJ => Counter::Faults(crate::FaultKind::Major),
                SW_CONTEXT_SWITCHES => Counter::Switches,
                SW_CPU_MIGRATIONS => Counter::Migrations,
                SW_ALIGNMENT_FAULTS | SW_EMULATION_FAULTS | SW_DUMMY | SW_BPF_OUTPUT => {
                    Counter::Zero
                }
                _ => return Err(Errno::ENOENT),
            };
            // `perf_try_init_event`: a software PMU takes neither SIMD nor
            // extended registers.
            let extended =
                |kind: u64, mask: u64| attr.sample_type & kind != 0 && mask & REGS_EXTENDED != 0;
            if attr.simd_enabled != 0
                || extended(SAMPLE_REGS_USER, attr.sample_regs_user)
                || extended(SAMPLE_REGS_INTR, attr.sample_regs_intr)
            {
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(counter)
        }
        (TYPE_HARDWARE | TYPE_HW_CACHE, _) => Err(Errno::ENOENT),
        _ => Err(Errno::ENOENT),
    }
}

/// `perf_event_exit_task`: thread `tid` of `group` ends without an
/// `execve`. The events it opened have no owner any more, so that
/// `PR_TASK_PERF_EVENTS_DISABLE` and `ENABLE` of a later thread of that
/// number do not reach them, and those that count it go to Linux's `EXIT`
/// state (`perf_event_exit_task_context`, `DETACH_EXIT`): they count no
/// more, keep their last count and times to be read, stay in their group,
/// are not enabled again and lead no new group (`ENODEV`). First the
/// events that count it take `PERF_RECORD_EXIT` of it, a thread of a
/// process whose parent is `ppid` (`perf_event_exit_task_context`).
pub(crate) fn exit_thread(events: &Events, group: &ThreadGroup, who: &Who, ppid: u32) {
    side_band::exit(events, group, who, ppid);
    let tid = who.tid;
    let counting: Vec<Arc<Event>> = {
        let mut lists = lock(&events.lists);
        lists
            .owned
            .retain(|owned| owned.tid != tid || !owned.of(group));
        let mut gone = Vec::new();
        lists.counting.retain(|erased| {
            let Some(event) = event(erased) else {
                return false;
            };
            match &event.target {
                Target::Thread {
                    group: target,
                    tid: target_tid,
                } if *target_tid == tid && std::ptr::eq(Arc::as_ptr(target), group) => {
                    gone.push(event);
                    false
                }
                _ => true,
            }
        });
        gone
    };
    // `task_ctx_sched_out`, and then one by one, the latest first, as
    // `list_add_event` puts each before the others.
    for event in counting.iter().filter(|event| event.parent.is_some()) {
        event.set_enabled(false);
    }
    for event in counting.into_iter().rev() {
        if event.parent.is_some() {
            // An inherited event goes, giving back what it counted
            // (`perf_event_exit_event` with a parent, `DETACH_GROUP`).
            event.give_back(who);
            event.detach();
        } else {
            event.disable();
            event.settle().removed = true;
            // `perf_event_wakeup`: its readers see it hung up.
            event.wake_readers();
        }
    }
    // And then to the events of its CPU (`perf_event_task` again, with no
    // context of the task's left).
    side_band::exit_on_cpu(events, who, ppid);
}

const RECORD_READ: u32 = 8;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;

/// `perf_event_init_task`: thread `child_tid` of `child_group`, which
/// thread `tid` of `group` made with clone flags `flags`, inherits the
/// groups that count that thread and have `inherit` (and, with
/// `inherit_thread`, only by `CLONE_THREAD`; and not with `sigtrap` and
/// `CLONE_CLEAR_SIGHAND`): each event of them gets one of its own, of the
/// opened event's attributes, enabled as the one it is made from is
/// (`inherit_event`). An event `remove_on_exec` or the end of its task took
/// out is not inherited. Then the events that count the thread `who`
/// take `PERF_RECORD_FORK` of the new one (`perf_event_fork`).
pub(crate) fn clone(
    events: &Events,
    group: &ThreadGroup,
    who: &Who,
    child_group: &Arc<ThreadGroup>,
    child_tid: u32,
    flags: u64,
) {
    inherit(events, group, who.tid, child_group, child_tid, flags);
    let child_pid = if std::ptr::eq(Arc::as_ptr(child_group), group) {
        who.pid
    } else {
        child_tid
    };
    side_band::fork(events, group, who, child_pid, child_tid);
}

fn inherit(
    events: &Events,
    group: &ThreadGroup,
    tid: u32,
    child_group: &Arc<ThreadGroup>,
    child_tid: u32,
    flags: u64,
) {
    let leaders: Vec<Arc<Event>> = lock(&events.lists)
        .counting
        .iter()
        .filter_map(event)
        .filter(|event| event.counts(group, tid) && lock(&event.leader).is_none())
        .collect();
    let mut made = Vec::new();
    for leader in leaders {
        let attr = &leader.attr;
        if !attr.flag(bit::INHERIT)
            || attr.flag(bit::INHERIT_THREAD) && flags & CLONE_THREAD == 0
            || attr.flag(bit::SIGTRAP) && flags & CLONE_CLEAR_SIGHAND != 0
            || lock(&leader.state).removed
        {
            continue;
        }
        let target = || Target::Thread {
            group: Arc::clone(child_group),
            tid: child_tid,
        };
        let Some(child_leader) = leader.inherit(target(), None) else {
            continue;
        };
        made.push(Arc::clone(&child_leader));
        for member in leader.members() {
            if let Some(child) = member.inherit(target(), Some(&child_leader)) {
                made.push(child);
            }
        }
    }
    let mut lists = lock(&events.lists);
    for child in &made {
        lists.counting.push(erase(child));
        let attr = &child.attr;
        if attr.flag(bit::DISABLED) && attr.flag(bit::ENABLE_ON_EXEC)
            || attr.flag(bit::REMOVE_ON_EXEC)
        {
            lists.on_exec.push(erase(child));
        }
    }
}

/// What an `execve` by thread `tid` (its number before the exec, `new_tid`
/// after it) of thread group `group` does to the machine's events: one
/// with `enable_on_exec` that waits for it is enabled
/// (`perf_event_enable_on_exec`), one with `remove_on_exec` is disabled for
/// good (`perf_event_remove_on_exec`); the events the thread opened stay
/// its own under its new number, and those the group's other threads, which
/// the exec ends, opened have no owner any more (`perf_event_exit_task`).
/// Then the events that count the thread take the side-band records of the
/// new program (`PERF_RECORD_COMM` of its `name` and its mappings) from
/// `image`, as `begin_new_exec` and the loader write them.
pub(crate) fn exec(
    events: &Events,
    group: &ThreadGroup,
    tid: u32,
    new_tid: u32,
    image: Option<(&Space<'_>, &[u8])>,
) {
    let who = image.map_or(
        Who {
            pid: new_tid,
            tid: new_tid,
            cpu: 0,
        },
        |(space, _)| space.who,
    );
    exec_events(events, group, tid, &who);
    if let Some((space, name)) = image {
        side_band::exec(events, space, tid, name);
    }
}

fn exec_events(events: &Events, group: &ThreadGroup, tid: u32, who: &Who) {
    let mut lists = lock(&events.lists);
    lists
        .owned
        .retain(|owned| !owned.of(group) || owned.tid == tid);
    for owned in &mut lists.owned {
        if owned.of(group) {
            owned.tid = who.tid;
        }
    }
    let mut removed = Vec::new();
    let mut inherited = Vec::new();
    lists.on_exec.retain(|waiting| {
        let Some(event) = event(waiting) else {
            return false;
        };
        match &event.target {
            Target::Thread {
                group: target,
                tid: target_tid,
            } if *target_tid == tid && std::ptr::eq(Arc::as_ptr(target), group) => {
                if event.attr.flag(bit::REMOVE_ON_EXEC) && event.parent.is_some() {
                    inherited.push(event);
                } else if event.attr.flag(bit::REMOVE_ON_EXEC) {
                    // `perf_event_exit_event` with `DETACH_GROUP`, after
                    // `perf_remove_from_owner`, as Linux master since 7.2's
                    // 037a3c43edfb; the test machines' 7.0 leaves the event
                    // in its group.
                    event.disable();
                    event.settle().removed = true;
                    event.detach();
                    event.wake_readers();
                    removed.push(Arc::as_ptr(&event));
                } else {
                    event.enable();
                }
                false
            }
            _ => true,
        }
    });
    // An event removed so has no owner any more.
    lists.owned.retain(|owned| {
        !removed
            .iter()
            .any(|&gone| std::ptr::addr_eq(owned.event.as_ptr(), gone))
    });
    drop(lists);
    // An inherited one goes, giving back what it counted.
    for event in inherited.into_iter().rev() {
        event.set_enabled(false);
        event.give_back(who);
        event.detach();
    }
}

/// The thread of system call `c` that writes a record.
fn who(c: &Context<'_>) -> Who {
    Who {
        pid: c.process.pid,
        tid: c.tid,
        cpu: c.process.cpu.on.map_or(0, |(cpu, _)| cpu),
    }
}

/// Runs `f` with the address space, root and thread of system call `c`
/// once an event wants side-band records, and does nothing otherwise.
fn with_space<T>(c: &Context<'_>, f: impl FnOnce(&Space<'_>) -> T) -> Option<T> {
    if !wanted(&c.processes.perf_events) {
        return None;
    }
    let root = c.files.root();
    Some(f(&Space {
        group: c.group,
        who: who(c),
        mem: c.mem,
        root: &root,
    }))
}

/// `perf_event_mmap` of the VMA that holds `addr` after system call `c`
/// mapped it (`mmap`, `brk`, `shmat`, `remap_file_pages`).
pub(crate) fn mapped(c: &Context<'_>, addr: u64) {
    with_space(c, |space| {
        side_band::mapped(&c.processes.perf_events, space, addr, None);
    });
}

/// The same for `brk`'s growth from `old_break`, which is still the break
/// when Linux writes the record.
pub(crate) fn grew_break(c: &Context<'_>, addr: u64, old_break: u64) {
    with_space(c, |space| {
        side_band::mapped(&c.processes.perf_events, space, addr, Some(old_break));
    });
}

/// What `mprotect` of `start..end` by system call `c` changes, taken
/// before it does ([`reprotected`]).
pub(crate) fn protections(c: &Context<'_>, start: u64, end: u64) -> Option<Vec<(u64, u64, u64)>> {
    with_space(c, |space| {
        side_band::protections(&c.processes.perf_events, space, start, end)
    })
    .flatten()
}

/// `mprotect_fixup`'s records of the VMAs over `start..end` that system
/// call `c` gave another protection than `before`.
pub(crate) fn reprotected(
    c: &Context<'_>,
    start: u64,
    end: u64,
    before: Option<Vec<(u64, u64, u64)>>,
) {
    if before.is_some() {
        with_space(c, |space| {
            side_band::reprotected(&c.processes.perf_events, space, start, end, before);
        });
    }
}

const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;
const IOC_REFRESH: u64 = 0x2402;
const IOC_RESET: u64 = 0x2403;
const IOC_PERIOD: u64 = 0x4008_2404;
const IOC_SET_OUTPUT: u64 = 0x2405;
const IOC_ID: u64 = 0x8008_2407;
const IOC_PAUSE_OUTPUT: u64 = 0x4004_2409;
const IOC_FLAG_GROUP: u64 = 1;

/// `mmap` of an event's file: its ring buffer ([`buffer`]), at
/// `placement`, once `mmap`'s own checks have passed.
pub(crate) fn mmap(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    placement: paludarium_mmu::Placement,
    len: u64,
    prot: paludarium_mmu::Prot,
    shared: bool,
    offset: u64,
) -> Option<Result<u64, Errno>> {
    of(file)?;
    Some(buffer::mmap(c, file, placement, len, prot, shared, offset))
}

/// An event's ioctls, as Linux's `_perf_ioctl`: `ENABLE`, `DISABLE` and
/// `RESET` of the event or, with `PERF_IOC_FLAG_GROUP`, its whole group;
/// `ID`; `PERIOD`, which only a sampling event takes (`EINVAL`), a new
/// period or frequency; `REFRESH`, `EINVAL` for one that does not sample
/// or that new tasks inherit, more overflows for one that does
/// ([`Event::refresh`]); `SET_OUTPUT` to
/// another event's buffer ([`buffer::set_output`]), whose descriptor must
/// be an event's (`EBADF`), or to none for -1; `PAUSE_OUTPUT` of the
/// event's buffer (`EINVAL` without one); every other request is `ENOTTY`
/// here.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    request: u64,
    argument: u64,
) -> Option<Result<u64, Errno>> {
    let event = Arc::clone(of(file)?);
    let request = request & 0xffff_ffff;
    let each = |f: fn(&Event)| {
        if argument as u32 as u64 & IOC_FLAG_GROUP != 0 {
            for event in event.group() {
                f(&event);
            }
        } else {
            f(&event);
        }
        Ok(0)
    };
    Some(match request {
        IOC_ENABLE => each(Event::enable),
        IOC_DISABLE => each(Event::disable),
        IOC_RESET => each(Event::reset),
        IOC_REFRESH => event.refresh(argument as i32).map(|()| 0),
        IOC_PERIOD => (|| {
            let mut value = [0; 8];
            c.mem
                .read(GuestAddr(argument), &mut value)
                .map_err(|_| Errno::EFAULT)?;
            let value = u64::from_le_bytes(value);
            if !event.attr.sampling() || value == 0 {
                return Err(Errno::EINVAL);
            }
            let enabled = lock(&event.state).enabled;
            // A clock's `freq` is a period from its start.
            let mut sampler = lock(&event.sampler);
            let rate = c.processes.sysctls.perf_event_max_sample_rate();
            if sampler.freq() && value > rate || !sampler.freq() && value >> 63 != 0 {
                return Err(Errno::EINVAL);
            }
            // A period that starts over unthrottles the event, while it is
            // enabled (`__perf_event_period`).
            sampler.set_period(value, event.counter, enabled);
            Ok(0)
        })(),
        IOC_SET_OUTPUT => (|| {
            if argument == u64::MAX {
                return buffer::set_output(&event, None).map(|()| 0);
            }
            // Linux's `fdget` takes an `unsigned int`.
            let file = c
                .files
                .descriptor(u64::from(argument as u32))
                .map_err(|_| EBADF)?
                .file;
            let output = Arc::clone(of(&file).ok_or(EBADF)?);
            buffer::set_output(&event, Some(&output)).map(|()| 0)
        })(),
        IOC_PAUSE_OUTPUT => lock(&event.rb)
            .clone()
            .ok_or(Errno::EINVAL)
            .and_then(|rb| rb.pause(argument as u32 != 0))
            .map(|()| 0),
        IOC_ID => c
            .mem
            .write(GuestAddr(argument), &event.id.to_le_bytes())
            .map(|()| 0)
            .map_err(|_| Errno::EFAULT),
        _ => Err(Errno::ENOTTY),
    })
}

/// Whether `file` is an event's (`perf_fops`), which takes `O_ASYNC`.
pub(crate) fn is_event(file: &Arc<dyn FileHandle>) -> bool {
    of(file).is_some()
}

/// `perf_fasync`: `F_SETFL` turning `O_ASYNC` on for `file`, with its
/// registration, or off.
pub(crate) fn set_async(
    file: &Arc<dyn FileHandle>,
    registration: Option<crate::fasync::Registration>,
) {
    if let Some(event) = of(file) {
        *lock(&event.fasync) = registration.map(|to| sample::Fasync {
            to,
            file: Arc::downgrade(file),
        });
    }
}

impl FileHandle for EventFile {
    /// Linux's `perf_poll`: `POLLHUP` without a buffer, or for an event
    /// whose task has ended and that has no inherited events left; else
    /// what the buffer's last wakeup left (`POLLIN`), which this takes.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Ok(self.event.poll())
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// Linux's `__perf_read`: `ENOSPC` for a buffer smaller than what the
    /// read format gives.
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let event = &self.event;
        let size = event.read_size();
        if buf.len() < size {
            return Err(ENOSPC);
        }
        let values = event.read_values()?;
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    /// No `write` (`EINVAL`).
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(crate::files::anon_inode_stat())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Open for reading and writing, with what `F_SETFL` set.
    fn flags(&self) -> u32 {
        O_RDWR | self.status.load(Ordering::Relaxed)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.store(
            flags & (crate::events::NONBLOCK | crate::fasync::O_ASYNC),
            Ordering::Relaxed,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Thread `tid` of a process of its own number, on CPU 0.
    fn thread_on(tid: u32) -> Who {
        Who {
            pid: tid,
            tid,
            cpu: 0,
        }
    }

    #[test]
    fn the_requests_are_linuxs_numbers() {
        // _IOW('$', 4, __u64) and _IOR('$', 7, __u64 *).
        assert_eq!(IOC_PERIOD, 1 << 30 | 8 << 16 | 0x24 << 8 | 4);
        assert_eq!(IOC_ID, 2 << 30 | 8 << 16 | 0x24 << 8 | 7);
    }

    #[test]
    fn only_the_software_events_that_count_here_are_taken() {
        let attr = |kind, config| Attr {
            kind,
            config,
            ..Attr::default()
        };
        assert_eq!(init(&attr(1, 0)), Ok(Counter::Clock));
        assert_eq!(init(&attr(1, 1)), Ok(Counter::Clock));
        assert_eq!(init(&attr(1, 9)), Ok(Counter::Zero));
        assert_eq!(
            init(&attr(1, 2)),
            Ok(Counter::Faults(crate::FaultKind::All))
        );
        assert_eq!(init(&attr(1, 3)), Ok(Counter::Switches));
        assert_eq!(init(&attr(1, 4)), Ok(Counter::Migrations));
        assert_eq!(
            init(&attr(1, 5)),
            Ok(Counter::Faults(crate::FaultKind::Minor))
        );
        assert_eq!(
            init(&attr(1, 6)),
            Ok(Counter::Faults(crate::FaultKind::Major))
        );
        assert_eq!(init(&attr(1, 11)), Err(Errno::ENOENT));
        assert_eq!(init(&attr(1, 12)), Err(Errno::ENOENT));
        assert_eq!(init(&attr(0, 0)), Err(Errno::ENOENT));
        let branch = Attr {
            sample_type: SAMPLE_BRANCH_STACK,
            ..attr(1, 0)
        };
        assert_eq!(init(&branch), Err(Errno::EOPNOTSUPP));
    }

    pub(super) fn event(leader: Option<&Arc<Event>>) -> Arc<Event> {
        counting(leader, Target::Cpu)
    }

    fn counting(leader: Option<&Arc<Event>>, target: Target) -> Arc<Event> {
        with_flags(leader, target, 0)
    }

    pub(super) fn with_flags(
        leader: Option<&Arc<Event>>,
        target: Target,
        flags: u64,
    ) -> Arc<Event> {
        with_attr(
            leader,
            target,
            Attr {
                flags,
                ..Attr::default()
            },
        )
    }

    fn with_attr(leader: Option<&Arc<Event>>, target: Target, attr: Attr) -> Arc<Event> {
        of_counter(leader, target, attr, Counter::Zero)
    }

    fn of_counter(
        leader: Option<&Arc<Event>>,
        target: Target,
        attr: Attr,
        counter: Counter,
    ) -> Arc<Event> {
        // Any CPU, as `perf_event_open`'s -1.
        of_counter_on(leader, target, attr, counter, -1)
    }

    fn of_counter_on(
        leader: Option<&Arc<Event>>,
        target: Target,
        attr: Attr,
        counter: Counter,
        cpu: i32,
    ) -> Arc<Event> {
        let event = Arc::new(Event {
            id: 0,
            stream_id: 0,
            ns: crate::namespaces::Namespaces::default().pid,
            attr,
            counter,
            target,
            cpu,
            machine: std::sync::Weak::<crate::processes::Processes>::new(),
            looks: Mutex::default(),
            clockid: None,
            host: Arc::new(paludarium_host::testing::RecordingHost::default()),
            leader: Mutex::new(leader.map(Held::new)),
            siblings: Mutex::default(),
            state: Mutex::default(),
            parent: None,
            children: Mutex::default(),
            rb: Mutex::default(),
            mapped: Mutex::default(),
            mmap_mutex: Mutex::default(),
            sampler: Mutex::new(sample::Sampler::new(&attr, counter)),
            hub: Arc::default(),
            fasync: Mutex::default(),
            event_limit: Default::default(),
        });
        if let Some(leader) = leader {
            lock(&leader.siblings).push(erase(&event));
        }
        event
    }

    fn ids(events: &[Arc<Event>]) -> Vec<*const Event> {
        events.iter().map(Arc::as_ptr).collect()
    }

    #[test]
    fn the_software_events_count_what_the_thread_used_while_they_are_enabled() {
        let host = paludarium_host::testing::RecordingHost::default();
        let group = Arc::new(ThreadGroup::default());
        let mut state = crate::ThreadState::default();
        // Its faults count as they are taken, the rest at a system call.
        paludarium_mmu::faults::bind(Arc::clone(&state.cpu.used) as _);
        let account = |state: &mut crate::ThreadState| {
            crate::account_cpu(&host, &group, state, 5);
        };
        let excluding = |counter, bit: u32| {
            let target = Target::Thread {
                group: Arc::clone(&group),
                tid: 5,
            };
            let attr = Attr {
                flags: 1 << bit,
                ..Attr::default()
            };
            of_counter(None, target, attr, counter)
        };
        // Bit 63 is no exclusion.
        let of = |counter| excluding(counter, 63);
        // Before the thread's first system call there is nothing to count.
        let switches = of(Counter::Switches);
        switches.enable();
        assert_eq!(switches.values().0, 0);
        let _ = paludarium_host::switches::take();
        account(&mut state);
        let (faults, migrations) = (
            of(Counter::Faults(crate::FaultKind::All)),
            of(Counter::Migrations),
        );
        let user_switches = excluding(Counter::Switches, bit::EXCLUDE_KERNEL);
        let user_faults = excluding(Counter::Faults(crate::FaultKind::All), bit::EXCLUDE_KERNEL);
        let kernel_faults = excluding(Counter::Faults(crate::FaultKind::All), bit::EXCLUDE_USER);
        let minor = of(Counter::Faults(crate::FaultKind::Minor));
        let major = of(Counter::Faults(crate::FaultKind::Major));
        let user_major = excluding(
            Counter::Faults(crate::FaultKind::Major),
            bit::EXCLUDE_KERNEL,
        );
        for event in [
            &faults,
            &migrations,
            &user_switches,
            &user_faults,
            &kernel_faults,
            &minor,
            &major,
            &user_major,
        ] {
            event.enable();
        }
        // Two sleeps, accounted at the next call, and a page's first write.
        paludarium_host::switches::sleep(&mut false);
        paludarium_host::switches::sleep(&mut false);
        let mut space = paludarium_mmu::AddressSpace::new();
        let page = space
            .map(
                None,
                4096,
                paludarium_mmu::Prot::READ_WRITE,
                paludarium_mmu::MappingKind::Anonymous,
            )
            .unwrap();
        space.write_u64(page, 1).unwrap();
        assert_eq!(switches.values().0, 0);
        account(&mut state);
        assert_eq!((switches.values().0, faults.values().0), (2, 1));
        // The kernel makes the switches; the fault was the thread's own.
        assert_eq!(user_switches.values().0, 0);
        assert_eq!((user_faults.values().0, kernel_faults.values().0), (1, 0));
        // A fault of the kernel's access for it.
        let copy = space
            .map(
                None,
                4096,
                paludarium_mmu::Prot::READ_WRITE,
                paludarium_mmu::MappingKind::Anonymous,
            )
            .unwrap();
        {
            let _kernel = crate::KernelFaults::enter(&state);
            space.write_u64(copy, 1).unwrap();
        }
        account(&mut state);
        assert_eq!((user_faults.values().0, kernel_faults.values().0), (1, 1));
        // A major one, of the kernel's: `page-faults` and `major-faults`
        // count it, `minor-faults` does not.
        state.cpu.used.major_faults.fetch_add(1, Ordering::SeqCst);
        account(&mut state);
        assert_eq!(
            (faults.values().0, minor.values().0, major.values().0),
            (3, 2, 1)
        );
        assert_eq!((kernel_faults.values().0, user_major.values().0), (2, 0));
        // A disabled event leaves out what comes meanwhile.
        switches.disable();
        paludarium_host::switches::sleep(&mut false);
        account(&mut state);
        switches.enable();
        paludarium_host::switches::sleep(&mut false);
        account(&mut state);
        assert_eq!(switches.values().0, 3);
        // A new mask that leaves out its CPU moves the thread; one that keeps
        // the lowest CPU, or another call on the same, does not.
        assert_eq!(migrations.values().0, 0);
        group.set_affinity(5, vec![0b110]);
        account(&mut state);
        account(&mut state);
        group.set_affinity(5, vec![0b1110]);
        account(&mut state);
        assert_eq!(migrations.values().0, 1);
        // The thread's virtual CPU with `rseq` is the one it runs on.
        state.on_cpu = Some(crate::rseq::OnCpu {
            cpu: 3,
            cid: 0,
            runner: 0,
        });
        account(&mut state);
        assert_eq!(migrations.values().0, 2);
        // Without `rseq` again, it is on the lowest CPU its mask allows,
        // though the mask has not changed since.
        state.on_cpu = None;
        account(&mut state);
        assert_eq!(migrations.values().0, 3);
        // An event of a CPU counts none of these.
        let cpu = of_counter(
            None,
            Target::Cpu,
            Attr::default(),
            Counter::Faults(crate::FaultKind::All),
        );
        cpu.enable();
        let more = space
            .map(
                None,
                4096,
                paludarium_mmu::Prot::READ_WRITE,
                paludarium_mmu::MappingKind::Anonymous,
            )
            .unwrap();
        space.write_u64(more, 1).unwrap();
        account(&mut state);
        // Its two faults and the major one above, and then this.
        assert_eq!((cpu.values().0, faults.values().0), (0, 4));
    }

    #[test]
    fn a_thread_s_clock_sample_is_due_at_the_first_of_its_enabled_sampling_clocks() {
        let group = Arc::new(ThreadGroup::default());
        let of = |tid| Target::Thread {
            group: Arc::clone(&group),
            tid,
        };
        let clock = |target, period, flags, cpu| {
            let attr = Attr {
                kind: 1,
                period,
                flags,
                ..Attr::default()
            };
            of_counter_on(None, target, attr, Counter::Clock, cpu)
        };
        let events = Events::default();
        let list = |event: &Arc<Event>, enabled: bool| {
            lock(&event.state).enabled = enabled;
            let mut lists = lock(&events.lists);
            match event.target {
                Target::Thread { .. } => lists.counting.push(erase(event)),
                Target::Cpu => lists.cpu_sampling.push(erase(event)),
            }
        };
        let due = || sample::clock_due(&events, &group, 1, 0);
        assert_eq!(due(), None);
        let slow = clock(of(1), 300_000, 0, -1);
        list(&slow, false);
        assert_eq!(due(), None);
        lock(&slow.state).enabled = true;
        assert_eq!(due(), Some(300_000));
        // Faster ones that sample none of its code's time: of its kernel
        // alone, of another thread, on another CPU, a clock that counts
        // alone, and samples of another counter.
        let faults = Attr {
            kind: 1,
            period: 1,
            ..Attr::default()
        };
        let others = [
            clock(of(1), 100_000, 1 << bit::EXCLUDE_USER, -1),
            clock(of(2), 100_000, 0, -1),
            clock(of(1), 100_000, 0, 1),
            clock(Target::Cpu, 100_000, 0, 1),
            clock(of(1), 0, 0, -1),
            of_counter_on(
                None,
                of(1),
                faults,
                Counter::Faults(crate::FaultKind::All),
                -1,
            ),
        ];
        for other in &others {
            list(other, true);
        }
        assert_eq!(due(), Some(300_000));
        // One of its CPU.
        let cpu = clock(Target::Cpu, 200_000, 0, 0);
        list(&cpu, true);
        assert_eq!(due(), Some(200_000));
        lock(&cpu.state).paused = true;
        assert_eq!(due(), Some(300_000));
    }

    #[test]
    fn an_event_of_a_thread_on_one_cpu_counts_what_it_did_there() {
        let host = paludarium_host::testing::RecordingHost::default();
        let group = Arc::new(ThreadGroup::default());
        let mut state = crate::ThreadState::default();
        paludarium_mmu::faults::bind(Arc::clone(&state.cpu.used) as _);
        let account = |state: &mut crate::ThreadState| {
            crate::account_cpu(&host, &group, state, 5);
        };
        let on = |counter, cpu| {
            let target = Target::Thread {
                group: Arc::clone(&group),
                tid: 5,
            };
            let event = of_counter_on(None, target, Attr::default(), counter, cpu);
            event.enable();
            event
        };
        let mut space = paludarium_mmu::AddressSpace::new();
        let mut fault = || {
            let page = space
                .map(
                    None,
                    4096,
                    paludarium_mmu::Prot::READ_WRITE,
                    paludarium_mmu::MappingKind::Anonymous,
                )
                .unwrap();
            space.write_u64(page, 1).unwrap();
        };
        // The thread starts on CPU 0, the lowest its mask allows.
        account(&mut state);
        let faults = [-1, 0, 1].map(|cpu| on(Counter::Faults(crate::FaultKind::All), cpu));
        let migrations = [-1, 0, 1].map(|cpu| on(Counter::Migrations, cpu));
        let switches = [-1, 0, 1].map(|cpu| on(Counter::Switches, cpu));
        let counts = |events: &[Arc<Event>; 3]| events.each_ref().map(|e| e.values().0);
        let _ = paludarium_host::switches::take();
        fault();
        paludarium_host::switches::sleep(&mut false);
        account(&mut state);
        assert_eq!(counts(&faults), [1, 1, 0]);
        assert_eq!(counts(&switches), [1, 1, 0]);
        // A new mask moves it to CPU 1: the sleep before it was on CPU 0,
        // and the migration counts on CPU 1.
        paludarium_host::switches::sleep(&mut false);
        group.set_affinity(5, vec![0b10]);
        account(&mut state);
        assert_eq!(counts(&switches), [2, 2, 0]);
        assert_eq!(counts(&migrations), [1, 0, 1]);
        fault();
        fault();
        account(&mut state);
        assert_eq!(counts(&faults), [3, 1, 2]);
        // Back on CPU 0, CPU 1 keeps what it counted.
        group.set_affinity(5, vec![0b1]);
        account(&mut state);
        fault();
        assert_eq!(counts(&faults), [4, 2, 2]);
        assert_eq!(counts(&migrations), [2, 1, 1]);
        // Each runs only for the time on its CPU, and is enabled for all.
        for [any, zero, one] in [faults, migrations, switches] {
            let (_, enabled, running) = any.values();
            assert_eq!(enabled, running);
            for event in [zero, one] {
                let (_, mine, ran) = event.values();
                assert_eq!(mine, enabled);
                assert!(ran <= enabled);
            }
        }
    }

    #[test]
    fn another_thread_s_new_mask_moves_what_the_thread_counts_at_once() {
        let host = paludarium_host::testing::RecordingHost::default();
        let group = Arc::new(ThreadGroup::default());
        let mut state = crate::ThreadState::default();
        paludarium_mmu::faults::bind(Arc::clone(&state.cpu.used) as _);
        let on = |counter, cpu| {
            let target = Target::Thread {
                group: Arc::clone(&group),
                tid: 5,
            };
            let event = of_counter_on(None, target, Attr::default(), counter, cpu);
            event.enable();
            event
        };
        let mut space = paludarium_mmu::AddressSpace::new();
        let mut fault = || {
            let page = space
                .map(
                    None,
                    4096,
                    paludarium_mmu::Prot::READ_WRITE,
                    paludarium_mmu::MappingKind::Anonymous,
                )
                .unwrap();
            space.write_u64(page, 1).unwrap();
        };
        crate::account_cpu(&host, &group, &mut state, 5);
        let faults = [0, 1].map(|cpu| on(Counter::Faults(crate::FaultKind::All), cpu));
        let switches = [0, 1].map(|cpu| on(Counter::Switches, cpu));
        let migrations = [0, 1].map(|cpu| on(Counter::Migrations, cpu));
        let counts = |events: &[Arc<Event>; 2]| events.each_ref().map(|e| e.values().0);
        let _ = paludarium_host::switches::take();
        // A fault and a sleep on CPU 0; then another thread moves it to
        // CPU 1, before it makes a system call.
        fault();
        paludarium_host::switches::sleep(&mut false);
        group.set_affinity(5, vec![0b10]);
        fault();
        assert_eq!(counts(&faults), [1, 1]);
        // Its next account counts the sleep where it slept and the
        // migration where it came.
        crate::account_cpu(&host, &group, &mut state, 5);
        assert_eq!(counts(&switches), [1, 0]);
        assert_eq!(counts(&migrations), [0, 1]);
        assert_eq!(counts(&faults), [1, 1]);
        // A thread on a virtual CPU of `rseq` stays where it is.
        state.on_cpu = Some(crate::rseq::OnCpu {
            cpu: 1,
            cid: 0,
            runner: 0,
        });
        crate::account_cpu(&host, &group, &mut state, 5);
        group.set_affinity(5, vec![0b1]);
        fault();
        assert_eq!(counts(&faults), [1, 2]);
    }

    #[test]
    fn a_new_task_inherits_groups_with_inherit_and_gives_them_back_at_its_end() {
        let events = Events::default();
        let (group, child_group) = (
            Arc::new(ThreadGroup::default()),
            Arc::new(ThreadGroup::default()),
        );
        let on = |tid| Target::Thread {
            group: Arc::clone(&group),
            tid,
        };
        let inherit = 1 << bit::INHERIT;
        let leader = with_flags(None, on(5), inherit);
        let member = with_flags(Some(&leader), on(5), inherit);
        let alone = counting(None, on(5));
        for event in [&leader, &member, &alone] {
            events.add(event, &group, 5);
        }
        leader.enable();
        clone(&events, &group, &thread_on(5), &child_group, 9, 0);
        assert_eq!(leader.children().len(), 1);
        assert_eq!(member.children().len(), 1);
        assert!(alone.children().is_empty());
        let (child_leader, child_member) =
            (leader.children()[0].clone(), member.children()[0].clone());
        assert!(child_leader.counts(&child_group, 9) && child_leader.enabled());
        assert_eq!(
            ids(&child_leader.group()),
            ids(&[Arc::clone(&child_leader), Arc::clone(&child_member)])
        );
        // The opened event's ioctls reach the inherited ones.
        leader.disable();
        assert!(!child_leader.enabled());
        leader.enable();
        lock(&child_leader.state).count = 7;
        lock(&child_member.state).count = 3;
        assert_eq!(leader.totals().0, 7);
        exit_thread(&events, &child_group, &thread_on(9), 1);
        assert!(leader.children().is_empty() && member.children().is_empty());
        assert_eq!((leader.totals().0, member.totals().0), (7, 3));
        // A reset leaves what ended children gave back.
        leader.reset();
        assert_eq!(leader.totals().0, 7);
    }

    #[test]
    fn inherit_thread_is_inherited_by_threads_alone() {
        let events = Events::default();
        let group = Arc::new(ThreadGroup::default());
        let event = with_flags(
            None,
            Target::Thread {
                group: Arc::clone(&group),
                tid: 5,
            },
            1 << bit::INHERIT | 1 << bit::INHERIT_THREAD,
        );
        events.add(&event, &group, 5);
        clone(
            &events,
            &group,
            &thread_on(5),
            &Arc::new(ThreadGroup::default()),
            9,
            0,
        );
        assert!(event.children().is_empty());
        clone(&events, &group, &thread_on(5), &group, 6, CLONE_THREAD);
        assert_eq!(event.children().len(), 1);
    }

    #[test]
    fn a_group_that_changed_since_it_was_inherited_is_echild_to_read() {
        let events = Events::default();
        let group = Arc::new(ThreadGroup::default());
        let on = || Target::Thread {
            group: Arc::clone(&group),
            tid: 5,
        };
        let attr = Attr {
            flags: 1 << bit::INHERIT,
            read_format: FORMAT_GROUP,
            ..Attr::default()
        };
        let leader = with_attr(None, on(), attr);
        events.add(&leader, &group, 5);
        assert!(leader.read_values().is_ok());
        clone(&events, &group, &thread_on(5), &group, 6, CLONE_THREAD);
        assert!(leader.read_values().is_ok());
        let _late = with_attr(Some(&leader), on(), attr);
        assert_eq!(leader.read_values(), Err(ECHILD));
    }

    #[test]
    fn a_member_that_leaves_its_group_leads_its_own() {
        let leader = event(None);
        let (gone, stays) = (event(Some(&leader)), event(Some(&leader)));
        gone.detach();
        assert_eq!(
            ids(&leader.group()),
            ids(&[Arc::clone(&leader), Arc::clone(&stays)])
        );
        assert_eq!(ids(&gone.group()), ids(&[Arc::clone(&gone)]));
        assert_eq!(ids(&stays.group()), ids(&leader.group()));
    }

    #[test]
    fn a_leader_that_leaves_lets_its_members_count_alone() {
        let leader = event(None);
        let member = event(Some(&leader));
        member.enable();
        member.set_paused(true);
        leader.detach();
        assert_eq!(ids(&leader.group()), ids(&[Arc::clone(&leader)]));
        assert_eq!(ids(&member.group()), ids(&[Arc::clone(&member)]));
        assert!(!lock(&member.state).paused);
    }

    #[test]
    fn a_thread_that_ends_owns_its_events_no_more() {
        let events = Events::default();
        let group = Arc::new(ThreadGroup::default());
        let (mine, other) = (event(None), event(None));
        events.add(&mine, &group, 5);
        events.add(&other, &group, 6);
        exit_thread(&events, &group, &thread_on(5), 1);
        assert!(events.owned_by(&group, 5).is_empty());
        assert_eq!(ids(&events.owned_by(&group, 6)), ids(&[other]));
    }

    #[test]
    fn the_events_that_count_a_thread_that_ends_are_in_the_exit_state() {
        let events = Events::default();
        let group = Arc::new(ThreadGroup::default());
        let of = |tid| Target::Thread {
            group: Arc::clone(&group),
            tid,
        };
        let leader = counting(None, of(5));
        let member = counting(Some(&leader), of(5));
        let other = counting(None, of(6));
        for event in [&leader, &member, &other] {
            event.enable();
            events.add(event, &group, 1);
        }
        exit_thread(&events, &group, &thread_on(5), 1);
        for event in [&leader, &member] {
            let state = lock(&event.state);
            assert!(state.removed && !state.enabled);
        }
        // They stay in their group, and are not enabled again.
        assert_eq!(
            ids(&leader.group()),
            ids(&[Arc::clone(&leader), Arc::clone(&member)])
        );
        leader.enable();
        assert!(!leader.enabled());
        let state = lock(&other.state);
        assert!(!state.removed && state.enabled);
    }

    #[test]
    fn the_latest_faults_keep_their_addresses_by_their_numbers() {
        use paludarium_mmu::faults::{At, Sink};
        let at = |addr| At {
            addr,
            present: addr & 0x1000 != 0,
        };
        let addresses = |usage: &crate::Usage, kernel, counted, n| {
            let found = usage.fault_addresses(kernel, crate::FaultKind::All, counted, n);
            assert!(found.iter().all(|&f| f.addr == 0 || f == at(f.addr)));
            found.iter().map(|f| f.addr).collect::<Vec<_>>()
        };
        let usage = crate::Usage::default();
        for nth in 1..=5 {
            usage.fault(false, false, nth, at(0x1000 * nth));
        }
        usage.fault(true, false, 1, at(0xf000));
        // The last three of the first four, and those of the kernel's.
        assert_eq!(addresses(&usage, false, 4, 3), [0x2000, 0x3000, 0x4000]);
        assert_eq!(addresses(&usage, true, 1, 1), [0xf000]);
        // One that came before any was told, and those long gone.
        assert_eq!(addresses(&usage, true, 2, 2), [0xf000, 0]);
        for nth in 6..=6000 {
            usage.fault(false, false, nth, at(0x1000 * nth));
        }
        let all = addresses(&usage, false, 6000, 6000);
        assert_eq!((all.len(), all[0], all[5999]), (6000, 0, 6000 * 0x1000));
    }

    #[test]
    fn a_major_fault_keeps_its_address_among_the_kernel_s_by_each_number() {
        use crate::FaultKind::{All, Major, Minor};
        use paludarium_mmu::faults::{At, Sink};
        let at = |addr| At {
            addr,
            present: false,
        };
        let usage = crate::Usage::default();
        // Minor, major, minor: counted as the mmu counts them, then told.
        usage.kernel_faults.store(1, Ordering::SeqCst);
        usage.fault(true, false, 1, at(0xa000));
        usage.major_faults.store(1, Ordering::SeqCst);
        usage.fault(true, true, 1, at(0xb000));
        usage.kernel_faults.store(2, Ordering::SeqCst);
        usage.fault(true, false, 2, at(0xc000));
        let addresses = |kind, counted, n| {
            usage
                .fault_addresses(true, kind, counted, n)
                .iter()
                .map(|f| f.addr)
                .collect::<Vec<_>>()
        };
        assert_eq!(addresses(All, 3, 3), [0xa000, 0xb000, 0xc000]);
        assert_eq!(addresses(Minor, 2, 2), [0xa000, 0xc000]);
        assert_eq!(addresses(Major, 1, 1), [0xb000]);
        assert_eq!(addresses(All, 2, 1), [0xb000]);
        // None of the thread's own code's is major.
        assert!(usage.fault_addresses(false, Major, 1, 1)[0] == At::default());
    }

    #[test]
    fn an_unfinished_fault_is_a_page_fault_and_no_minor_one() {
        use crate::FaultKind::{All, Minor};
        use paludarium_mmu::faults::{At, Sink};
        paludarium_mmu::faults::trace_addresses();
        let at = |addr| At {
            addr,
            present: false,
        };
        let usage = crate::Usage::default();
        // Minor, unfinished (a wait a signal ended), minor.
        usage.faults.store(1, Ordering::SeqCst);
        usage.fault(false, false, 1, at(0x1000));
        usage.unfinished_fault(at(0x2000));
        usage.faults.store(2, Ordering::SeqCst);
        usage.fault(false, false, 2, at(0x3000));
        let addresses = |kind, counted, n| {
            usage
                .fault_addresses(false, kind, counted, n)
                .iter()
                .map(|f| f.addr)
                .collect::<Vec<_>>()
        };
        assert_eq!(addresses(All, 3, 3), [0x1000, 0x2000, 0x3000]);
        assert_eq!(addresses(Minor, 2, 2), [0x1000, 0x3000]);
        assert_eq!(usage.counts(), [2, 0, 0, 0, 0, 1]);
        assert_eq!(usage.fault_counts().minor, 2);
    }

    #[test]
    fn simd_registers_are_checked_as_x86_checks_them() {
        let simd = |vec_qwords, pred_qwords| Attr {
            simd_enabled: 1,
            vec_qwords,
            pred_qwords,
            ..Attr::default()
        };
        // Without SIMD registers, a mask is needed, without DS to GS.
        assert_eq!(regs(&Attr::default(), 0, 0, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&Attr::default(), 1 << 12, 0, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&Attr::default(), 1, 0, 0), Ok(()));
        // With them, the mask may be 0 and may name R16 to R31 and SSP.
        assert_eq!(regs(&simd(0, 0), 0, 0, 0), Ok(()));
        assert_eq!(regs(&simd(0, 0), 1 << 40, 0, 0), Ok(()));
        assert_eq!(regs(&simd(0, 0), 1 << 41, 0, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(0, 0), 1 << 15, 0, 0), Err(Errno::EINVAL));
        // Registers without a size.
        assert_eq!(regs(&simd(0, 0), 0, 0xffff, 0), Err(Errno::EINVAL));
        // All 16 XMM or YMM registers, all 32 ZMM ones, or none.
        assert_eq!(regs(&simd(2, 0), 0, 0xffff, 0), Ok(()));
        assert_eq!(regs(&simd(4, 0), 0, 0xffff, 0), Ok(()));
        assert_eq!(regs(&simd(2, 0), 0, 0xff, 0), Err(Errno::EINVAL));
        // `bitmap_full` looks at the first 16 bits alone, and only bits past
        // the 32 vector registers are refused, so more registers pass.
        assert_eq!(regs(&simd(2, 0), 0, 0x1_ffff, 0), Ok(()));
        assert_eq!(regs(&simd(4, 0), 0, 0xffff_ffff, 0), Ok(()));
        assert_eq!(regs(&simd(8, 0), 0, 0xffff, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(8, 0), 0, 0xffff_ffff, 0), Ok(()));
        assert_eq!(regs(&simd(8, 0), 0, 1 << 32, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(3, 0), 0, 0, 0), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(2, 0), 0, 0, 0), Ok(()));
        // The 8 opmask registers, of 1 quadword.
        assert_eq!(regs(&simd(0, 1), 0, 0, 0xff), Ok(()));
        assert_eq!(regs(&simd(0, 1), 0, 0, 0x7f), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(0, 1), 0, 0, 0x1ff), Err(Errno::EINVAL));
        assert_eq!(regs(&simd(0, 2), 0, 0, 0xff), Err(Errno::EINVAL));
        // 4 + 32 * 8 + 8 quadwords fit in half of 64 KiB.
        assert_eq!(regs(&simd(8, 1), 0, 0xffff_ffff, 0xff), Ok(()));
    }
}
