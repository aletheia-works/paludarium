//! Each thread's scheduling attributes and I/O priority, as Linux keeps them
//! in `task_struct`: the policy and real-time priority `sched_setscheduler`,
//! `sched_setparam` and `sched_setattr` set (with `SCHED_DEADLINE`'s
//! parameters, the normal policy's custom slice and the utilization clamps),
//! `SCHED_RESET_ON_FORK`, and the I/O priority `ioprio_set` gives the task's
//! I/O context. They are kept and reported, and inherited as Linux's
//! `sched_fork` and `copy_io` pass them on; the host still schedules every
//! guest thread as a normal one.

use paludarium_types::Errno;

pub(crate) const SCHED_NORMAL: u32 = 0;
pub(crate) const SCHED_FIFO: u32 = 1;
pub(crate) const SCHED_RR: u32 = 2;
pub(crate) const SCHED_BATCH: u32 = 3;
pub(crate) const SCHED_IDLE: u32 = 5;
pub(crate) const SCHED_DEADLINE: u32 = 6;
pub(crate) const SCHED_EXT: u32 = 7;
/// The legacy flag of `sched_setscheduler`'s policy and
/// `sched_getscheduler`'s answer.
pub(crate) const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

pub(crate) const FLAG_RESET_ON_FORK: u64 = 0x01;
const FLAG_RECLAIM: u64 = 0x02;
const FLAG_DL_OVERRUN: u64 = 0x04;
pub(crate) const FLAG_KEEP_POLICY: u64 = 0x08;
pub(crate) const FLAG_KEEP_PARAMS: u64 = 0x10;
pub(crate) const FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
pub(crate) const FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
const FLAG_UTIL_CLAMP: u64 = FLAG_UTIL_CLAMP_MIN | FLAG_UTIL_CLAMP_MAX;
/// `SCHED_FLAG_ALL`.
pub(crate) const FLAG_ALL: u64 = 0x7f;
const FLAG_SUGOV: u64 = 0x1000_0000;
/// The flags a `SCHED_DEADLINE` task keeps (`SCHED_DL_FLAGS`).
const DL_FLAGS: u64 = FLAG_RECLAIM | FLAG_DL_OVERRUN | FLAG_SUGOV;
/// `SCHED_CAPACITY_SCALE`: the largest utilization clamp.
const CAPACITY: u32 = 1024;
/// `MAX_RT_PRIO - 1`.
pub(crate) const MAX_RT_PRIORITY: u32 = 99;

/// One utilization clamp (`uclamp_se`): its value, and whether the task
/// asked for it (`user_defined`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Clamp {
    pub value: u32,
    pub user: bool,
}

/// A thread's scheduling attributes and I/O priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sched {
    pub policy: u32,
    /// `rt_priority`: 1 to 99 under `SCHED_FIFO` and `SCHED_RR`, else 0.
    pub priority: u32,
    pub reset_on_fork: bool,
    /// `SCHED_DEADLINE`'s runtime, relative deadline and period (the
    /// deadline when 0 was asked for), in nanoseconds, and its flags.
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub dl_flags: u64,
    /// The normal policy's slice `sched_setattr` asked for (`custom_slice`).
    pub slice: Option<u64>,
    /// `uclamp_req`: the minimum and the maximum.
    pub clamps: [Clamp; 2],
    /// The I/O priority of the thread's I/O context, which it has once
    /// `ioprio_set` gives it one.
    pub io: Option<u16>,
    /// That I/O context (Linux's `io_context`), told apart by a number from
    /// [`new_io_context`]; 0 while it has none.
    pub io_context: u64,
}

impl Default for Sched {
    fn default() -> Self {
        Self {
            policy: SCHED_NORMAL,
            priority: 0,
            reset_on_fork: false,
            runtime: 0,
            deadline: 0,
            period: 0,
            dl_flags: 0,
            slice: None,
            clamps: [
                Clamp {
                    value: 0,
                    user: false,
                },
                Clamp {
                    value: CAPACITY,
                    user: false,
                },
            ],
            io: None,
            io_context: 0,
        }
    }
}

/// A number for a new I/O context, which no other has had.
pub(crate) fn new_io_context() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn rt_policy(policy: u32) -> bool {
    policy == SCHED_FIFO || policy == SCHED_RR
}
pub(crate) fn fair_policy(policy: u32) -> bool {
    policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_EXT
}
fn valid_policy(policy: u32) -> bool {
    fair_policy(policy) || rt_policy(policy) || policy == SCHED_IDLE || policy == SCHED_DEADLINE
}

impl Sched {
    pub(crate) fn deadline_policy(&self) -> bool {
        self.policy == SCHED_DEADLINE
    }
    /// What `sched_getscheduler` reports.
    pub(crate) fn reported_policy(&self) -> u32 {
        self.policy
            | if self.reset_on_fork {
                SCHED_RESET_ON_FORK
            } else {
                0
            }
    }
    /// The bandwidth of a deadline task, as Linux's `to_ratio` (20 bits).
    pub(crate) fn bandwidth(&self) -> u64 {
        if self.deadline_policy() {
            ratio(self.period, self.runtime)
        } else {
            0
        }
    }
    /// The attributes a new thread or process starts with, as Linux's
    /// `sched_fork`, `uclamp_fork` and `copy_io`: with the reset flag, a
    /// real-time or deadline task's child is a normal one and the flag is
    /// gone; an I/O priority is kept when it has a class. Also whether the
    /// child's nice value goes back to 0 (a reset child whose parent was
    /// real-time, deadline or negatively niced); a deadline child that
    /// stays one is `EAGAIN`.
    pub(crate) fn forked(&self, nice: i32) -> Result<(Self, bool), Errno> {
        let mut child = *self;
        let mut reset_nice = false;
        if self.reset_on_fork {
            if self.deadline_policy() || rt_policy(self.policy) {
                child.policy = SCHED_NORMAL;
                child.priority = 0;
                child.runtime = 0;
                child.deadline = 0;
                child.period = 0;
                child.dl_flags = 0;
                reset_nice = true;
            } else if nice < 0 {
                reset_nice = true;
            }
            child.slice = None;
            child.reset_on_fork = false;
            child.clamps = Self::default().clamps;
        }
        if child.deadline_policy() {
            return Err(Errno(11)); // EAGAIN
        }
        // copy_io: without CLONE_IO, which clone refuses, a context with a
        // class is copied into a new one.
        child.io = self.io.filter(|&io| io_class(io) != 0);
        child.io_context = if child.io.is_some() {
            new_io_context()
        } else {
            0
        };
        Ok((child, reset_nice))
    }
}

/// Linux's `to_ratio(period, runtime)`: runtime over period in 20 bits.
pub(crate) fn ratio(period: u64, runtime: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    ((u128::from(runtime) << 20) / u128::from(period)) as u64
}

/// `struct sched_attr` as `sched_setattr` reads it (`sched_copy_attr`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attr {
    /// `None` keeps the policy (`SETPARAM_POLICY`).
    pub policy: Option<u32>,
    pub flags: u64,
    pub nice: i32,
    pub priority: u32,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub util_min: u32,
    pub util_max: u32,
}

/// Linux's `__checkparam_dl`, with the default `sched_deadline_period_min_us`
/// (100) and `sched_deadline_period_max_us` (1 << 22).
fn check_deadline(attr: &Attr) -> bool {
    if attr.flags & FLAG_SUGOV != 0 {
        return true;
    }
    if attr.deadline == 0 || attr.runtime < 1 << 10 {
        return false;
    }
    if attr.deadline & 1 << 63 != 0 || attr.period & 1 << 63 != 0 {
        return false;
    }
    let period = if attr.period == 0 {
        attr.deadline
    } else {
        attr.period
    };
    if period < attr.deadline || attr.deadline < attr.runtime {
        return false;
    }
    (100_000..=(1 << 22) * 1000).contains(&period)
}

/// What deciding a change needs to know of the target thread.
pub(crate) struct Target {
    pub sched: Sched,
    pub nice: i32,
    /// Its RLIMIT_NICE and RLIMIT_RTPRIO soft limits.
    pub nice_limit: u64,
    pub rtprio_limit: u64,
    /// The caller may act on its priorities (`check_same_owner`).
    pub same_owner: bool,
    /// Its CPU mask lets it run on every CPU (`cpumask_subset`).
    pub every_cpu: bool,
    /// The normal policy's slice when it asked for none (`se.slice`).
    pub base_slice: u64,
}

/// The change [`set`] decided on: the new attributes, and the new nice
/// value for a normal policy.
pub(crate) struct Change {
    pub sched: Sched,
    pub nice: Option<i32>,
}

/// Linux's `__sched_setscheduler` for a caller with or without
/// CAP_SYS_NICE, in its order: the policy, the flags, the priority and the
/// deadline parameters (`EINVAL`), the permission (`EPERM`), the clamps
/// (`EINVAL`), then, for a change of anything, the deadline admission:
/// `EPERM` for a thread that may not run on every CPU and `EBUSY` when the
/// bandwidth of every deadline task would pass `capacity` (the deadline
/// servers' share and the others' already taken off).
pub(crate) fn set(
    target: &Target,
    attr: &Attr,
    may_nice: bool,
    others_bandwidth: u64,
    capacity: u64,
) -> Result<Change, Errno> {
    let current = target.sched;
    let (policy, reset_on_fork) = match attr.policy {
        None => (current.policy, current.reset_on_fork),
        Some(policy) => {
            if !valid_policy(policy) {
                return Err(Errno::EINVAL);
            }
            (policy, attr.flags & FLAG_RESET_ON_FORK != 0)
        }
    };
    if attr.flags & !(FLAG_ALL | FLAG_SUGOV) != 0 || attr.priority > MAX_RT_PRIORITY {
        return Err(Errno::EINVAL);
    }
    if policy == SCHED_DEADLINE && !check_deadline(attr)
        || rt_policy(policy) != (attr.priority != 0)
    {
        return Err(Errno::EINVAL);
    }
    if !may_nice && !permitted(target, attr, policy, reset_on_fork) {
        return Err(Errno::EPERM);
    }
    if attr.flags & FLAG_SUGOV != 0 {
        return Err(Errno::EINVAL);
    }
    if attr.flags & FLAG_UTIL_CLAMP != 0 {
        validate_clamps(&current, attr)?;
    }
    let slice = current.slice.unwrap_or(target.base_slice);
    let unchanged = policy == current.policy
        && !(fair_policy(policy) && (attr.nice != target.nice || attr.runtime != slice))
        && !(rt_policy(policy) && attr.priority != current.priority)
        && !(policy == SCHED_DEADLINE
            && (attr.runtime != current.runtime
                || attr.deadline != current.deadline
                || attr.period != current.period
                || attr.flags & DL_FLAGS != current.dl_flags))
        && attr.flags & FLAG_UTIL_CLAMP == 0;
    if unchanged {
        return Ok(Change {
            sched: Sched {
                reset_on_fork,
                ..current
            },
            nice: None,
        });
    }
    if !may_nice && policy == SCHED_DEADLINE && !target.every_cpu {
        return Err(Errno::EPERM);
    }
    if policy == SCHED_DEADLINE && attr.flags & FLAG_SUGOV == 0 {
        let period = if attr.period == 0 {
            attr.deadline
        } else {
            attr.period
        };
        let wanted = ratio(period, attr.runtime);
        let unchanged_bandwidth = current.deadline_policy() && wanted == current.bandwidth();
        if !unchanged_bandwidth && others_bandwidth + wanted > capacity {
            return Err(Errno(16)); // EBUSY
        }
    }
    let mut sched = current;
    sched.policy = policy;
    sched.reset_on_fork = reset_on_fork;
    sched.priority = attr.priority;
    let mut nice = None;
    if policy == SCHED_DEADLINE {
        sched.runtime = attr.runtime;
        sched.deadline = attr.deadline;
        sched.period = if attr.period == 0 {
            attr.deadline
        } else {
            attr.period
        };
        sched.dl_flags = attr.flags & DL_FLAGS;
    } else if fair_policy(policy) {
        nice = Some(attr.nice);
        // Linux 6.12's custom slice, from 0.1 ms to 100 ms.
        sched.slice = (attr.runtime != 0).then(|| attr.runtime.clamp(100_000, 100_000_000));
    }
    // __setscheduler_uclamp: a clamp the task did not ask for follows the
    // class (a FIFO or RR task's minimum is 1024, as 6.12's rt_task, which
    // leaves deadline tasks out), and -1 asks for that.
    for (index, (flag, value)) in [
        (FLAG_UTIL_CLAMP_MIN, attr.util_min),
        (FLAG_UTIL_CLAMP_MAX, attr.util_max),
    ]
    .into_iter()
    .enumerate()
    {
        let clamp = &mut sched.clamps[index];
        let reset = attr.flags & FLAG_UTIL_CLAMP == 0 && !clamp.user
            || attr.flags & flag != 0 && value == u32::MAX;
        if reset {
            *clamp = Clamp {
                value: if index == 0 && rt_policy(policy) {
                    CAPACITY
                } else {
                    [0, CAPACITY][index]
                },
                user: false,
            };
        }
        if attr.flags & flag != 0 && value != u32::MAX {
            // uclamp_se's value is 11 bits wide.
            *clamp = Clamp {
                value: value & 0x7ff,
                user: true,
            };
        }
    }
    Ok(Change { sched, nice })
}

/// Linux's `user_check_sched_setscheduler` without CAP_SYS_NICE.
fn permitted(target: &Target, attr: &Attr, policy: u32, reset_on_fork: bool) -> bool {
    let current = &target.sched;
    let nice_reduction = |nice: i32| (20 - nice) as u64 <= target.nice_limit;
    if fair_policy(policy) && attr.nice < target.nice && !nice_reduction(attr.nice) {
        return false;
    }
    if rt_policy(policy) {
        if policy != current.policy && target.rtprio_limit == 0 {
            return false;
        }
        if attr.priority > current.priority && u64::from(attr.priority) > target.rtprio_limit {
            return false;
        }
    }
    if policy == SCHED_DEADLINE {
        return false;
    }
    if current.policy == SCHED_IDLE && policy != SCHED_IDLE && !nice_reduction(target.nice) {
        return false;
    }
    target.same_owner && !(current.reset_on_fork && !reset_on_fork)
}

/// Linux's `uclamp_validate`.
fn validate_clamps(current: &Sched, attr: &Attr) -> Result<(), Errno> {
    let mut low = i64::from(current.clamps[0].value);
    let mut high = i64::from(current.clamps[1].value);
    if attr.flags & FLAG_UTIL_CLAMP_MIN != 0 {
        low = i64::from(attr.util_min as i32);
        if low + 1 > i64::from(CAPACITY) + 1 {
            return Err(Errno::EINVAL);
        }
    }
    if attr.flags & FLAG_UTIL_CLAMP_MAX != 0 {
        high = i64::from(attr.util_max as i32);
        if high + 1 > i64::from(CAPACITY) + 1 {
            return Err(Errno::EINVAL);
        }
    }
    if low != -1 && high != -1 && low > high {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The class of an I/O priority (`IOPRIO_PRIO_CLASS`).
pub(crate) fn io_class(ioprio: u16) -> u16 {
    ioprio >> 13 & 7
}

/// Linux's `ioprio_check_cap`: a known class (none, real-time, best-effort,
/// idle), real-time only with CAP_SYS_NICE or CAP_SYS_ADMIN, and no level
/// for the class none. The hint bits are kept.
pub(crate) fn check_ioprio(ioprio: i32, may_realtime: bool) -> Result<(), Errno> {
    let class = (ioprio >> 13) & 7;
    let level = ioprio & 7;
    match class {
        1 if !may_realtime => Err(Errno::EPERM),
        1..=3 => Ok(()),
        0 if level == 0 => Ok(()),
        _ => Err(Errno::EINVAL),
    }
}

/// The I/O priority `ioprio_get` reports for a thread: the one it was
/// given, the class none (0) included, and 0 without one, as Linux does
/// (a class-none priority is not turned into one from the nice value).
pub(crate) fn reported_ioprio(sched: &Sched) -> u16 {
    sched.io.unwrap_or(0)
}

/// Linux's `ioprio_best`, which counts a priority without a class as
/// best-effort level 4.
pub(crate) fn best_ioprio(a: u16, b: u16) -> u16 {
    let normal = |io: u16| if io_class(io) == 0 { 2 << 13 | 4 } else { io };
    normal(a).min(normal(b))
}
