//! `perf_event_open`, as Linux's `kernel/events/core.c` checks its
//! arguments, for the software events the emulator can count: `cpu-clock`
//! and `task-clock` (the thread's CPU time, or for an event of a CPU the
//! time that passes), and `alignment-faults`, `emulation-faults`, `dummy`
//! and `bpf-output`, which never count on x86-64 here or there. Hardware,
//! cache and raw events find no PMU (`ENOENT`), as on a machine without
//! one; the other software events (page faults, context switches, CPU
//! migrations, cgroup switches), tracepoints and breakpoints are not there
//! (`ENOENT`) either.
//!
//! An event is read (`read`), enabled, disabled and reset (the `ioctl`s,
//! with `PERF_IOC_FLAG_GROUP`), and grouped; `enable_on_exec` enables it
//! when its task runs `execve`, and `prctl`'s `PR_TASK_PERF_EVENTS_DISABLE`
//! and `ENABLE` disable and enable those the calling thread opened. The
//! machine keeps both lists ([`Events`]). There is no ring buffer: `mmap`
//! of an event is `ENODEV`, and a sampling event takes no samples.
use crate::ThreadGroup;
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, FileHandle, FileStat, Host};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

/// `kernel.perf_event_paranoid`'s default, Linux's, which the machine's
/// starts with ([`crate::sysctl::Machine`]).
pub(crate) const PARANOID: i32 = 2;
/// `kernel.perf_event_max_sample_rate`, Linux's default
/// (`DEFAULT_MAX_SAMPLE_RATE`).
const MAX_SAMPLE_RATE: u64 = 100_000;

const CAP_PERFMON: u64 = 1 << 38;
const EACCES: Errno = Errno::EACCES;
const ESRCH: Errno = Errno(3);
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
    pub const EXCLUDE_KERNEL: u32 = 5;
    pub const FREQ: u32 = 10;
    pub const ENABLE_ON_EXEC: u32 = 12;
    pub const EXCLUDE_CALLCHAIN_KERNEL: u32 = 21;
    pub const USE_CLOCKID: u32 = 25;
    pub const NAMESPACES: u32 = 28;
    pub const AUX_OUTPUT: u32 = 31;
    pub const TEXT_POKE: u32 = 33;
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
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_action: u32,
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
        branch_sample_type: word(&b, 72),
        sample_regs_user: word(&b, 80),
        sample_stack_user: half(&b, 88),
        clockid: half(&b, 92) as i32,
        sample_regs_intr: word(&b, 96),
        reserved_2: quarter(&b, 110),
        aux_action: half(&b, 116),
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
    /// An event that never happens here.
    Zero,
}

/// Whose an event is.
#[derive(Clone)]
enum Target {
    /// A thread, of the thread group that holds it.
    Thread { group: Arc<ThreadGroup>, tid: u32 },
    /// A CPU, as an event of no task is: the time that passes.
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
    /// The task is gone: its last time stays.
    last: u64,
    /// `remove_on_exec` took it out of its task and its group at the task's
    /// `execve` (Linux's `PERF_EVENT_STATE_EXIT`): it counts no more, is not
    /// enabled again, and its last count and times stay to be read.
    removed: bool,
}

/// One event: Linux's `struct perf_event`.
pub(crate) struct Event {
    id: u64,
    attr: Attr,
    counter: Counter,
    target: Target,
    cpu: i32,
    clockid: Option<i32>,
    host: Arc<dyn Host>,
    /// The group's leader, `None` for one that leads its own: taken away
    /// when either leaves the group (`perf_group_detach`).
    leader: Mutex<Option<Arc<Event>>>,
    siblings: Mutex<Vec<Weak<Event>>>,
    state: Mutex<State>,
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
}

#[derive(Default)]
struct Lists {
    owned: Vec<Owned>,
    on_exec: Vec<Erased>,
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
    /// The event's clock: the thread's CPU time, or the time that passes.
    fn now(&self, state: &mut State) -> u64 {
        match &self.target {
            Target::Thread { group, tid } => {
                if let Some(time) = group.last_thread_cpu(*tid) {
                    state.last = time;
                }
                state.last
            }
            Target::Cpu => self.host.clock(ClockId::Monotonic).unwrap_or(0),
        }
    }
    /// The state brought up to now: the time since the last update counts
    /// as enabled while it is, and as running and counted while it runs.
    fn settle(&self) -> MutexGuard<'_, State> {
        let mut state = lock(&self.state);
        let now = self.now(&mut state);
        let passed = now.saturating_sub(state.since);
        state.since = now;
        if state.enabled {
            state.enabled_time += passed;
            if !state.paused {
                state.running_time += passed;
                if self.counter == Counter::Clock {
                    state.count += passed;
                }
            }
        }
        state
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
        self.settle().paused = paused;
    }
    /// The group's members but the leader.
    fn members(&self) -> Vec<Arc<Event>> {
        lock(&self.siblings)
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    fn set_enabled(&self, enabled: bool) {
        {
            let mut state = self.settle();
            if state.removed {
                return;
            }
            state.enabled = enabled;
        }
        // A leader takes its group in and out with it.
        if lock(&self.leader).is_none() {
            for member in self.members() {
                member.set_paused(!enabled);
            }
        }
    }
    fn enable(&self) {
        self.set_enabled(true);
    }
    fn disable(&self) {
        self.set_enabled(false);
    }
    /// Linux's reset clears the count and leaves the times.
    fn reset(&self) {
        self.settle().count = 0;
    }
    /// The group's leader: the event itself or the one it joined.
    fn leader(self: &Arc<Self>) -> Arc<Event> {
        lock(&self.leader)
            .clone()
            .unwrap_or_else(|| Arc::clone(self))
    }
    /// `perf_group_detach`: a member leaves its leader's group, and a
    /// leader's members each lead a group of their own, counting while they
    /// are enabled.
    fn detach(self: &Arc<Self>) {
        let leader = lock(&self.leader).take();
        if let Some(leader) = leader {
            lock(&leader.siblings)
                .retain(|member| !std::ptr::eq(member.as_ptr(), Arc::as_ptr(self)));
            return;
        }
        let members: Vec<Arc<Event>> = std::mem::take(&mut *lock(&self.siblings))
            .iter()
            .filter_map(Weak::upgrade)
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
        events.extend(lock(&leader.siblings).iter().filter_map(Weak::upgrade));
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
    /// What a read gives (`perf_read_one`, `perf_read_group`).
    fn read_values(self: &Arc<Self>) -> Vec<u64> {
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
                values.push(0);
            }
        };
        if format & FORMAT_GROUP != 0 {
            let group = self.group();
            values.push(group.len() as u64);
            // The members' times are the leader's, as they run together.
            let (_, enabled, running) = group[0].values();
            times(&mut values, enabled, running);
            for event in &group {
                entry(&mut values, event, event.values().0);
            }
        } else {
            let (count, enabled, running) = self.values();
            values.push(count);
            times(&mut values, enabled, running);
            if format & FORMAT_ID != 0 {
                values.push(self.id);
            }
            if format & FORMAT_LOST != 0 {
                values.push(0);
            }
        }
        values
    }
}

/// The open file: Linux's `[perf_event]`.
pub(crate) struct EventFile {
    event: Arc<Event>,
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
        || c.process
            .credentials
            .may_read_task(&public.credentials, view.dumpable, true);
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
        if attr.period > MAX_SAMPLE_RATE {
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
    if group_fd != -1 {
        let file = c
            .files
            .descriptor(u64::from(group_fd as u32))
            .map_err(|_| EBADF)?
            .file;
        let event = Arc::clone(of(&file).ok_or(EBADF)?);
        // One `remove_on_exec` took out is in Linux's `EXIT` state, which
        // no group may be led by (`ENODEV`, as Linux master since 7.2's
        // fa091f46c383; the test machines' 7.0 takes it).
        if lock(&event.state).removed {
            return Err(Errno::ENODEV);
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
    // `perf_cgroup_connect` needs a cgroup directory, which there is none
    // of.
    if cgroup {
        return Err(EBADF);
    }
    if attr.flag(bit::AUX_OUTPUT) || attr.aux_action & 1 != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if attr.aux_action & 6 == 6 {
        return Err(Errno::EINVAL);
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
    let event = Arc::new(Event {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        attr,
        counter,
        target,
        cpu,
        clockid,
        host: Arc::clone(c.shared_host),
        leader: Mutex::new(leader.clone()),
        siblings: Mutex::default(),
        state: Mutex::default(),
    });
    if let Some(leader) = &leader {
        event.set_paused(!leader.enabled());
        lock(&leader.siblings).push(Arc::downgrade(&event));
    }
    if !attr.flag(bit::DISABLED) {
        event.enable();
    }
    // The caller's own group, which owns the event.
    let own = c.processes.view(c.process.pid).ok_or(ESRCH)?.group;
    c.processes.perf_events.add(&event, &own, c.tid);
    let cloexec = flags & PERF_FLAG_FD_CLOEXEC != 0;
    c.files
        .install(Arc::new(EventFile { event }), cloexec, c.group.nofile())
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
/// `execve`, and the events it opened have no owner any more, so that
/// `PR_TASK_PERF_EVENTS_DISABLE` and `ENABLE` of a later thread of that
/// number do not reach them. They go on counting what they count.
pub(crate) fn exit_thread(events: &Events, group: &ThreadGroup, tid: u32) {
    lock(&events.lists)
        .owned
        .retain(|owned| owned.tid != tid || !owned.of(group));
}

/// What an `execve` by thread `tid` (its number before the exec, `new_tid`
/// after it) of thread group `group` does to the machine's events: one
/// with `enable_on_exec` that waits for it is enabled
/// (`perf_event_enable_on_exec`), one with `remove_on_exec` is disabled for
/// good (`perf_event_remove_on_exec`); the events the thread opened stay
/// its own under its new number, and those the group's other threads, which
/// the exec ends, opened have no owner any more (`perf_event_exit_task`).
pub(crate) fn exec(events: &Events, group: &ThreadGroup, tid: u32, new_tid: u32) {
    let mut lists = lock(&events.lists);
    lists
        .owned
        .retain(|owned| !owned.of(group) || owned.tid == tid);
    for owned in &mut lists.owned {
        if owned.of(group) {
            owned.tid = new_tid;
        }
    }
    let mut removed = Vec::new();
    lists.on_exec.retain(|waiting| {
        let Some(event) = event(waiting) else {
            return false;
        };
        match &event.target {
            Target::Thread {
                group: target,
                tid: target_tid,
            } if *target_tid == tid && std::ptr::eq(Arc::as_ptr(target), group) => {
                if event.attr.flag(bit::REMOVE_ON_EXEC) {
                    // `perf_event_exit_event` with `DETACH_GROUP`, after
                    // `perf_remove_from_owner`, as Linux master since 7.2's
                    // 037a3c43edfb; the test machines' 7.0 leaves the event
                    // in its group.
                    event.disable();
                    event.settle().removed = true;
                    event.detach();
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
}

const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;
const IOC_REFRESH: u64 = 0x2402;
const IOC_RESET: u64 = 0x2403;
const IOC_PERIOD: u64 = 0x4008_2404;
const IOC_ID: u64 = 0x8008_2407;
const IOC_FLAG_GROUP: u64 = 1;

/// An event's ioctls, as Linux's `_perf_ioctl`: `ENABLE`, `DISABLE` and
/// `RESET` of the event or, with `PERF_IOC_FLAG_GROUP`, its whole group;
/// `ID`; `PERIOD` and `REFRESH`, which only a sampling event takes
/// (`EINVAL`); every other request is `ENOTTY` here.
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
        IOC_REFRESH => Err(Errno::EINVAL),
        IOC_PERIOD => (|| {
            let mut value = [0; 8];
            c.mem
                .read(GuestAddr(argument), &mut value)
                .map_err(|_| Errno::EFAULT)?;
            let value = u64::from_le_bytes(value);
            if !event.attr.sampling() || value == 0 {
                return Err(Errno::EINVAL);
            }
            if event.attr.flag(bit::FREQ) && value > MAX_SAMPLE_RATE || value >> 63 != 0 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        })(),
        IOC_ID => c
            .mem
            .write(GuestAddr(argument), &event.id.to_le_bytes())
            .map(|()| 0)
            .map_err(|_| Errno::EFAULT),
        _ => Err(Errno::ENOTTY),
    })
}

impl FileHandle for EventFile {
    /// Linux's `perf_poll` finds nothing in a ring buffer there is none of.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Ok((0, 0, 0))
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
        let values = event.read_values();
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
        Ok(FileStat {
            mode: 0o600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        O_RDWR
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(init(&attr(1, 2)), Err(Errno::ENOENT));
        assert_eq!(init(&attr(1, 12)), Err(Errno::ENOENT));
        assert_eq!(init(&attr(0, 0)), Err(Errno::ENOENT));
        let branch = Attr {
            sample_type: SAMPLE_BRANCH_STACK,
            ..attr(1, 0)
        };
        assert_eq!(init(&branch), Err(Errno::EOPNOTSUPP));
    }

    fn event(leader: Option<&Arc<Event>>) -> Arc<Event> {
        let event = Arc::new(Event {
            id: 0,
            attr: Attr::default(),
            counter: Counter::Zero,
            target: Target::Cpu,
            cpu: 0,
            clockid: None,
            host: Arc::new(paludarium_host::testing::RecordingHost::default()),
            leader: Mutex::new(leader.cloned()),
            siblings: Mutex::default(),
            state: Mutex::default(),
        });
        if let Some(leader) = leader {
            lock(&leader.siblings).push(Arc::downgrade(&event));
        }
        event
    }

    fn ids(events: &[Arc<Event>]) -> Vec<*const Event> {
        events.iter().map(Arc::as_ptr).collect()
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
        exit_thread(&events, &group, 5);
        assert!(events.owned_by(&group, 5).is_empty());
        assert_eq!(ids(&events.owned_by(&group, 6)), ids(&[other]));
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
