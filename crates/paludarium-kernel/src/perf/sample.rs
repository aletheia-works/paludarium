//! Samples of the software events, as Linux's `kernel/events/core.c` takes
//! them: a sampling event overflows every `sample_period` occurrences
//! (`perf_swevent_event`, `perf_swevent_set_period`), or for `cpu-clock`
//! and `task-clock` every `sample_period` nanoseconds of its count, as its
//! hrtimer fires (`perf_swevent_hrtimer`, at least every 10 µs). With
//! `freq`, a clock's period is a second over the frequency
//! (`perf_swevent_init_hrtimer`), and another event's starts at 1 and
//! follows the rate it counts at (`perf_adjust_period`).
//!
//! Each overflow writes a `PERF_RECORD_SAMPLE` of the fields `sample_type`
//! asks for, in `perf_output_sample`'s order, to the ring buffer the event
//! writes to (its own, its output's, or for an inherited event the one it
//! comes from); a sample that finds no room is lost and counted, and the
//! next record that fits follows a `PERF_RECORD_LOST` of them
//! ([`super::buffer::Buffer::output`]).
//!
//! The emulator counts what a thread did as of its system calls
//! ([`crate::Usage`]), so the samples are taken there too ([`overflow`]),
//! of the thread as it makes the call: its registers, its stack and the
//! frames its `rbp` chain leads to. An occurrence in the thread's own code
//! and the passing of its time are samples of user mode; a fault in a
//! system call, a switch and a migration are of the kernel, whose address
//! and frames are not known here (0, and no frames after
//! `PERF_CONTEXT_KERNEL`).
use super::{Counter, Event, Events, bit, lock};
use crate::fasync::{Reason, Registration};
use crate::namespaces::Namespace;
use crate::signals::PendingSignal;
use paludarium_cpu::{CpuState, reg};
use paludarium_host::ClockId;
use paludarium_host::FileHandle;
use paludarium_mmu::AddressSpace;
use paludarium_types::{GuestAddr, USER_ADDRESS_LIMIT};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

pub(super) const IP: u64 = 1;
pub(super) const TID: u64 = 1 << 1;
pub(super) const TIME: u64 = 1 << 2;
pub(super) const ADDR: u64 = 1 << 3;
pub(super) const READ: u64 = 1 << 4;
pub(super) const CALLCHAIN: u64 = 1 << 5;
pub(super) const ID: u64 = 1 << 6;
pub(super) const CPU: u64 = 1 << 7;
pub(super) const PERIOD: u64 = 1 << 8;
pub(super) const STREAM_ID: u64 = 1 << 9;
pub(super) const RAW: u64 = 1 << 10;
pub(super) const BRANCH_STACK: u64 = 1 << 11;
pub(super) const REGS_USER: u64 = 1 << 12;
pub(super) const STACK_USER: u64 = 1 << 13;
pub(super) const WEIGHT: u64 = 1 << 14;
pub(super) const DATA_SRC: u64 = 1 << 15;
pub(super) const IDENTIFIER: u64 = 1 << 16;
pub(super) const TRANSACTION: u64 = 1 << 17;
pub(super) const REGS_INTR: u64 = 1 << 18;
pub(super) const PHYS_ADDR: u64 = 1 << 19;
pub(super) const AUX: u64 = 1 << 20;
pub(super) const CGROUP: u64 = 1 << 21;
pub(super) const DATA_PAGE_SIZE: u64 = 1 << 22;
pub(super) const CODE_PAGE_SIZE: u64 = 1 << 23;
pub(super) const WEIGHT_STRUCT: u64 = 1 << 24;

const RECORD_LOST: u32 = 2;
const RECORD_THROTTLE: u32 = 5;
const RECORD_UNTHROTTLE: u32 = 6;
const RECORD_SAMPLE: u32 = 9;
const MISC_KERNEL: u16 = 1;
const MISC_USER: u16 = 2;
/// `PERF_CONTEXT_KERNEL` and `PERF_CONTEXT_USER`.
const CONTEXT_KERNEL: u64 = -128i64 as u64;
const CONTEXT_USER: u64 = -512i64 as u64;
/// `kernel.perf_event_max_stack` and `perf_event_max_contexts_per_stack`,
/// Linux's defaults.
pub(super) const MAX_STACK: u16 = 127;
const MAX_CONTEXTS: u32 = 8;
/// `PERF_SAMPLE_REGS_ABI_64`.
const ABI_64: u64 = 2;
/// `PERF_MEM_NA`: the operation, level, snoop, lock and TLB not available.
const MEM_NA: u64 = 1 | 1 << 5 | 1 << 19 | 1 << 24 | 1 << 26;
/// The root cgroup's ID on cgroup v2, which every task here is in.
const ROOT_CGROUP: u64 = 1;
/// `TASK_SIZE` for a 64-bit task.
const TASK_SIZE: u64 = USER_ADDRESS_LIMIT - 4096;
const NSEC_PER_SEC: u64 = 1_000_000_000;
/// The shortest period of a clock's hrtimer.
const HRTIMER_MIN: u64 = 10_000;
/// Linux's `TICK_NSEC` on the CI runners' kernels (`CONFIG_HZ=1000`).
const TICK_NSEC: u64 = crate::threads::TICK_NSEC;
const PAGE: u64 = 4096;

/// What Linux's `struct hw_perf_event` keeps for sampling.
#[derive(Debug, Default)]
pub(super) struct Sampler {
    /// `sample_period` and `last_period`, and for an event that is not a
    /// clock the frequency `freq` asks for (`sample_freq`), else 0.
    period: u64,
    frequency: u64,
    last_period: u64,
    /// `period_left`: for a clock, the nanoseconds of its count until its
    /// hrtimer fires; for another event, kept from `-period` to 0, where it
    /// overflows.
    left: i64,
    /// What the event had counted in user mode and in the kernel when its
    /// samples were last taken.
    seen: [u64; 2],
    /// For `freq`, the count and the time of the last adjustment of the
    /// period (`freq_count_stamp`, `freq_time_stamp`).
    freq_count: u64,
    freq_time: u64,
    /// `lost_samples`: the samples that found no room in the buffer.
    pub(super) lost: u64,
    /// For a clock, the nanoseconds of its count its hrtimer has gone
    /// through, the tick of them its last interrupt came in
    /// (`interrupts_seq`, a tick being `TICK_NSEC` of them) and the
    /// interrupts in that tick (`interrupts`); whether that throttled it
    /// (`interrupts` at `MAX_INTERRUPTS`), its hrtimer stopped until the
    /// next tick; and whether it was unthrottled outside a tick, its
    /// `PERF_RECORD_UNTHROTTLE` yet to be written.
    at: u64,
    seq: u64,
    interrupts: u64,
    throttled: bool,
    unthrottled: bool,
}

/// What a clock's hrtimer gives as its count goes on ([`Sampler::ticks`]):
/// samples of a period, and its throttling and unthrottling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fire {
    Samples(u64, u64),
    Throttle,
    Unthrottle,
}

impl Sampler {
    /// `perf_event_alloc`'s period, and the first `pmu->add`: a clock's
    /// with `freq` is a second over the frequency; another's starts at 1.
    pub(super) fn new(attr: &super::Attr, counter: Counter) -> Self {
        if !attr.sampling() {
            return Self::default();
        }
        let freq = attr.flag(bit::FREQ);
        let period = match (freq, counter) {
            (true, Counter::Clock) => (NSEC_PER_SEC / attr.period).max(1),
            (true, _) => 1,
            (false, _) => attr.period,
        };
        Self {
            frequency: if freq && counter != Counter::Clock {
                attr.period
            } else {
                0
            },
            ..Self::of_period(period, counter)
        }
    }
    /// One that inherits `period` (`inherit_event`).
    pub(super) fn inherited(&self, counter: Counter) -> Self {
        Self {
            frequency: self.frequency,
            ..Self::of_period(self.period, counter)
        }
    }
    /// Whether it follows a frequency (`attr.freq`, which a clock's
    /// `perf_swevent_init_hrtimer` has cleared).
    pub(super) fn freq(&self) -> bool {
        self.frequency != 0
    }
    fn of_period(period: u64, counter: Counter) -> Self {
        let left = if counter == Counter::Clock {
            period as i64
        } else {
            // `perf_swevent_set_period` from `period_left` = the period.
            -(period as i64)
        };
        Self {
            period,
            last_period: period,
            left,
            ..Self::default()
        }
    }
    /// `PERF_EVENT_IOC_PERIOD` (`__perf_event_period`): the period, or
    /// with `freq` the frequency, which starts over (`period_left` 0); an
    /// event that is `enabled` is unthrottled by it.
    pub(super) fn set_period(&mut self, value: u64, counter: Counter, enabled: bool) {
        if enabled {
            self.scheduled_in();
        }
        if self.freq() {
            self.frequency = value;
        } else {
            self.period = value;
        }
        let period = self.period;
        self.left = if counter == Counter::Clock {
            period.max(HRTIMER_MIN) as i64
        } else {
            0
        };
    }
    /// `perf_event_unthrottle` of a throttled event that is scheduled in
    /// (`event_sched_in`) or whose period starts over: its record is
    /// written with its next samples, and its hrtimer starts again with a
    /// whole period.
    pub(super) fn scheduled_in(&mut self) {
        if self.throttled {
            self.throttled = false;
            self.interrupts = 0;
            self.unthrottled = true;
            self.left = self.period.max(HRTIMER_MIN) as i64;
        }
    }
    /// The overflows of `n` more occurrences of a software event:
    /// `perf_swevent_event`, one at a time, with `perf_swevent_overflow`
    /// and `perf_swevent_set_period`, as runs of samples of a period.
    fn occurrences(&mut self, mut n: u64, period_field: bool, freq: bool, out: &mut Runs) {
        // With PERF_SAMPLE_PERIOD and no `freq`, each occurrence is a
        // sample, of a period of 1; so it is with a period of 1.
        if period_field && !freq {
            run(out, 1, n);
            return;
        }
        if self.period == 1 && !freq {
            run(out, self.last_period, n);
            return;
        }
        while n > 0 {
            if self.left < -1 {
                let step = n.min((-1 - self.left) as u64);
                self.left += step as i64;
                n -= step;
                continue;
            }
            self.left += 1;
            n -= 1;
            if self.left < 0 {
                continue;
            }
            // The sample shows the last period, which the overflows are
            // counted in too.
            let period = self.last_period;
            self.last_period = self.period;
            let nr = (period + self.left as u64) / period;
            self.left -= (nr * period) as i64;
            run(out, period, nr);
        }
    }
    /// The times a clock's hrtimer fires in `ns` more nanoseconds of its
    /// count, each a sample of the last period, as `perf_swevent_hrtimer`
    /// and `__perf_event_account_interrupt` take them: the interrupt that
    /// brings those of one tick to `per_tick` (`max_samples_per_tick`)
    /// throttles the event before its sample is written, its hrtimer
    /// stopped, and the next tick unthrottles it (`perf_event_task_tick`),
    /// its hrtimer started with a whole period. With an UNTHROTTLE that is
    /// to be written first ([`Self::scheduled_in`]), into `out`; the
    /// nanoseconds the event was throttled in, which its count leaves out,
    /// as `cpu_clock_event_stop` stops it.
    fn ticks(&mut self, ns: u64, per_tick: u64, out: &mut Vec<Fire>) -> u64 {
        if std::mem::take(&mut self.unthrottled) {
            out.push(Fire::Unthrottle);
        }
        let end = self.at.saturating_add(ns);
        let step = self.period.max(HRTIMER_MIN);
        let per_tick = per_tick.max(1);
        // No tick can hold that many: none throttles.
        let never = TICK_NSEC.div_ceil(step) < per_tick;
        let mut stopped = 0;
        loop {
            if self.throttled {
                let tick = self.seq.saturating_add(1).saturating_mul(TICK_NSEC);
                if tick > end {
                    stopped += end - self.at;
                    break;
                }
                stopped += tick - self.at;
                self.at = tick;
                self.throttled = false;
                self.interrupts = 0;
                self.left = step as i64;
                out.push(Fire::Unthrottle);
                continue;
            }
            let first = self.at + self.left.max(0) as u64;
            if first > end {
                self.left = (first - end) as i64;
                break;
            }
            let jiffy = first / TICK_NSEC;
            let before = if jiffy == self.seq {
                self.interrupts
            } else {
                0
            };
            let until_end = (end - first) / step + 1;
            let n = if never {
                until_end
            } else {
                // Up to the end of this tick, and up to the one that
                // throttles the event.
                let in_tick = ((jiffy + 1) * TICK_NSEC - first - 1) / step + 1;
                until_end
                    .min(in_tick)
                    .min(per_tick.saturating_sub(before).max(1))
            };
            let last = first + (n - 1) * step;
            let last_jiffy = last / TICK_NSEC;
            self.interrupts = if last_jiffy == jiffy {
                before + n
            } else {
                (last - last_jiffy * TICK_NSEC) / step + 1
            };
            self.seq = last_jiffy;
            self.at = last;
            if !never && self.interrupts >= per_tick {
                if n > 1 {
                    push(out, Fire::Samples(self.last_period, n - 1));
                }
                out.push(Fire::Throttle);
                push(out, Fire::Samples(self.last_period, 1));
                self.throttled = true;
                self.left = 0;
                continue;
            }
            push(out, Fire::Samples(self.last_period, n));
            self.left = step as i64;
        }
        self.at = end;
        stopped
    }
    /// `perf_adjust_period`: the period moves an eighth of the way to the
    /// one that gives the frequency, at `count` occurrences in `nsec`.
    fn adjust(&mut self, nsec: u64, count: u64) {
        // `perf_calculate_period`, which gives the dividend for a divisor
        // of 0.
        let divisor = u128::from(nsec) * u128::from(self.frequency);
        let dividend = u128::from(count) * u128::from(NSEC_PER_SEC);
        let period = dividend.checked_div(divisor).unwrap_or(dividend);
        let period = i64::try_from(period).unwrap_or(i64::MAX);
        let delta = period.saturating_sub(self.period as i64);
        // A low-pass filter, rounding away from 0 before C's division.
        let delta = (if delta >= 0 { delta + 7 } else { delta - 7 }) / 8;
        let mut period = (self.period as i64).saturating_add(delta);
        if period == 0 {
            period = 1;
        }
        self.period = period as u64;
        if self.left > 8 * period {
            self.left = 0;
        }
    }
}

/// Samples as runs of a period and how many have it.
type Runs = Vec<(u64, u64)>;

/// `fire` after the others, samples of the period of the last ones with
/// them.
fn push(out: &mut Vec<Fire>, fire: Fire) {
    if let (Some(Fire::Samples(last, count)), Fire::Samples(period, n)) = (out.last_mut(), fire)
        && *last == period
    {
        *count += n;
        return;
    }
    out.push(fire);
}

fn run(out: &mut Runs, period: u64, n: u64) {
    if n == 0 {
        return;
    }
    match out.last_mut() {
        Some((last, count)) if *last == period => *count += n,
        _ => out.push((period, n)),
    }
}

/// Where an event's `O_ASYNC` signals go: the registration `F_SETFL`
/// made, and the file, whose owner (`F_SETOWN`, `F_SETSIG`) the machine
/// keeps.
#[derive(Clone)]
pub(crate) struct Fasync {
    pub(super) to: Registration,
    pub(super) file: Weak<dyn FileHandle>,
}

const SIGTRAP: i32 = 5;
/// `TRAP_PERF`, and `TRAP_PERF_FLAG_ASYNC` for a SIGTRAP the thread blocks.
const TRAP_PERF: i32 = 6;
const TRAP_PERF_FLAG_ASYNC: u32 = 1;
/// `EPOLLHUP`.
const POLL_HUP: u32 = 0x10;

/// The thread a sample is of, at its system call.
pub(crate) struct Task<'a> {
    /// Its process and thread, by their IDs in the emulator.
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    /// The CPU it runs on.
    pub(crate) cpu: u32,
    pub(crate) regs: &'a CpuState,
    pub(crate) mem: &'a AddressSpace,
    /// Whether it blocks SIGTRAP.
    pub(crate) blocks_sigtrap: bool,
}

/// The thread that writes a record: its process, its own ID and its CPU,
/// by their numbers in the emulator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Who {
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) cpu: u32,
}

impl Task<'_> {
    fn who(&self) -> Who {
        Who {
            pid: self.pid,
            tid: self.tid,
            cpu: self.cpu,
        }
    }
}

/// The samples the events that count thread `task` of `group` have to
/// take as of now, which its system call brought its counts up to, and the
/// signals of `sigtrap` the thread is to get.
///
/// A clock is throttled at `per_tick` interrupts in a tick
/// ([`crate::sysctl::Machine::perf_max_samples_per_tick`]).
pub(crate) fn overflow(
    events: &Events,
    group: &crate::ThreadGroup,
    task: &Task<'_>,
    per_tick: u64,
) -> Vec<PendingSignal> {
    if !events.sampling.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let sampling: Vec<Arc<Event>> = lock(&events.lists)
        .counting
        .iter()
        .filter_map(super::event)
        .filter(|event| event.attr.sampling() && event.counts(group, task.tid))
        .collect();
    sampling
        .into_iter()
        .filter_map(|event| event.take_samples(task, per_tick))
        .collect()
}

/// Whether any event of the machine samples, for the checkpoints that
/// bring a thread's counts up to date only then.
pub(crate) fn sampling(events: &Events) -> bool {
    events.sampling.load(Ordering::Relaxed)
}

impl Event {
    /// The event whose buffer it writes to and which counts what is lost:
    /// for an inherited one, the one it comes from.
    pub(super) fn top(self: &Arc<Self>) -> Option<Arc<Event>> {
        match &self.parent {
            Some(parent) => parent.upgrade(),
            None => Some(Arc::clone(self)),
        }
    }
    /// Its overflows since they were last taken, their samples and the
    /// signals they send, and its `sigtrap`.
    fn take_samples(self: &Arc<Self>, task: &Task<'_>, per_tick: u64) -> Option<PendingSignal> {
        let occurred = {
            let state = self.settle();
            if state.removed {
                return None;
            }
            state.occurred
        };
        let period_field = self.attr.sample_type & PERIOD != 0;
        // What it gives in order, each in user mode or in the kernel.
        let mut fires: Vec<(Fire, bool)> = Vec::new();
        let stopped = {
            let mut sampler = lock(&self.sampler);
            let freq = sampler.freq();
            let new = [
                occurred[0].saturating_sub(sampler.seen[0]),
                occurred[1].saturating_sub(sampler.seen[1]),
            ];
            sampler.seen = occurred;
            if new == [0, 0] && !sampler.unthrottled {
                return None;
            }
            if self.counter == Counter::Clock {
                // The hrtimer interrupts the thread's own code: a sample of
                // user mode, which `exclude_user` leaves out with the
                // interrupt itself (`perf_exclude_event`), which then
                // throttles nothing.
                let exclude = self.attr.flag(bit::EXCLUDE_USER);
                let mut ticks = Vec::new();
                let per_tick = if exclude { u64::MAX } else { per_tick };
                let stopped = sampler.ticks(new[0] + new[1], per_tick, &mut ticks);
                if !exclude {
                    fires.extend(ticks.into_iter().map(|fire| (fire, true)));
                }
                stopped
            } else {
                if freq {
                    let now = self.clock_now();
                    let count = occurred[0] + occurred[1];
                    let nsec = now.saturating_sub(sampler.freq_time);
                    let more = count.saturating_sub(sampler.freq_count);
                    if sampler.freq_time != 0 && nsec > 0 && more > 0 {
                        sampler.adjust(nsec, more);
                    }
                    sampler.freq_time = now;
                    sampler.freq_count = count;
                }
                let mut user = Runs::new();
                let mut kernel = Runs::new();
                sampler.occurrences(new[0], period_field, freq, &mut user);
                sampler.occurrences(new[1], period_field, freq, &mut kernel);
                let samples = |runs: Runs, user_mode| {
                    runs.into_iter()
                        .map(move |(period, n)| (Fire::Samples(period, n), user_mode))
                };
                fires.extend(samples(user, true).chain(samples(kernel, false)));
                0
            }
        };
        if stopped > 0 {
            let mut state = lock(&self.state);
            state.count = state.count.saturating_sub(stopped);
        }
        if fires.is_empty() {
            return None;
        }
        let top = self.top()?;
        let rb = lock(&top.rb).clone();
        let wakeup_events = if self.attr.flag(bit::WATERMARK) {
            0
        } else {
            self.attr.wakeup
        };
        let mut overflows = 0;
        let mut hung_up = false;
        let mut woken = false;
        // The samples of one period are alike: written together.
        'runs: for (fire, user_mode) in fires {
            let (period, mut copies) = match fire {
                Fire::Samples(period, copies) => (period, copies),
                Fire::Throttle | Fire::Unthrottle => {
                    self.log_throttle(fire == Fire::Unthrottle, &task.who());
                    continue;
                }
            };
            // `event_limit`: the overflow that brings it to 0 is the
            // last, and disables the event (`POLL_HUP`).
            let limit = self.event_limit.load(Ordering::Relaxed);
            if limit > 0 && copies >= limit as u64 {
                copies = limit as u64;
                self.event_limit.store(0, Ordering::Relaxed);
                hung_up = true;
            } else if limit != 0 {
                self.event_limit
                    .store(limit.wrapping_sub(copies as i32), Ordering::Relaxed);
            }
            overflows += copies;
            if let Some(rb) = &rb {
                let (record, spill) = self.sample(task, user_mode, period);
                let trailer = top.id_sample(task);
                woken |= rb.output(&top, &record, &spill, copies, &trailer, wakeup_events);
            }
            if hung_up {
                break 'runs;
            }
        }
        if overflows == 0 {
            return None;
        }
        if hung_up {
            self.set_enabled(false);
        }
        // An inherited event's wakeup of the buffer signals for the event
        // it writes through too.
        let extra = woken && self.parent.is_some();
        top.signal_owner(overflows, hung_up, extra);
        self.attr.flag(bit::SIGTRAP).then(|| self.sigtrap(task))
    }
    /// `perf_log_throttle`: `PERF_RECORD_THROTTLE`, or `UNTHROTTLE`, of the
    /// group's leader, which throttles and unthrottles with its group
    /// (`perf_event_throttle_group`), written by thread `who`: the
    /// leader's time, its ID and its own (`stream_id`).
    fn log_throttle(self: &Arc<Self>, unthrottle: bool, who: &Who) {
        let leader = lock(&self.leader)
            .clone()
            .unwrap_or_else(|| Arc::clone(self));
        let mut body = Vec::with_capacity(24);
        body.extend(leader.clock_now().to_le_bytes());
        body.extend(leader.id.to_le_bytes());
        body.extend(leader.stream_id.to_le_bytes());
        let kind = if unthrottle {
            RECORD_UNTHROTTLE
        } else {
            RECORD_THROTTLE
        };
        leader.side_band(kind, 0, &body, who);
    }
    /// `kill_fasync` for `overflows`, each `POLL_IN` but the last that
    /// hung the event up (`POLL_HUP`), and one more `POLL_IN` for `extra`:
    /// to the owner of the event's file once `O_ASYNC` registered it. Plain
    /// SIGIO, not queued, is sent once.
    pub(super) fn signal_owner(&self, overflows: u64, hung_up: bool, extra: bool) {
        let Some(fasync) = lock(&self.fasync).clone() else {
            return;
        };
        let (Some(processes), Some(file)) = (fasync.to.processes.upgrade(), fasync.file.upgrade())
        else {
            return;
        };
        let owner = processes.file_owner(&file);
        let mut ins = overflows - u64::from(hung_up) + u64::from(extra);
        if owner.signal == 0 {
            ins = ins.min(1);
        }
        for _ in 0..ins {
            processes.send_io(owner, fasync.to.fd, Reason::In);
        }
        if hung_up && (owner.signal != 0 || ins == 0) {
            processes.send_io(owner, fasync.to.fd, Reason::HangUp);
        }
    }
    /// `send_sig_perf`: SIGTRAP of `TRAP_PERF` for the thread, with
    /// `sig_data` and the event's type, and the flag that it came late if
    /// the thread blocks it. A fault's address is not known here (0).
    fn sigtrap(&self, task: &Task<'_>) -> PendingSignal {
        let mut info = [0; 48];
        info[0..4].copy_from_slice(&SIGTRAP.to_le_bytes());
        info[8..12].copy_from_slice(&TRAP_PERF.to_le_bytes());
        info[24..32].copy_from_slice(&self.attr.sig_data.to_le_bytes());
        info[32..36].copy_from_slice(&self.attr.kind.to_le_bytes());
        let flags = if task.blocks_sigtrap {
            TRAP_PERF_FLAG_ASYNC
        } else {
            0
        };
        info[36..40].copy_from_slice(&flags.to_le_bytes());
        PendingSignal {
            queued: Some(info),
            ..PendingSignal::thread(SIGTRAP, TRAP_PERF)
        }
    }
    /// `perf_poll` ([`super::EventFile`]'s readiness).
    pub(super) fn poll(&self) -> (u32, u64, u64) {
        let removed = lock(&self.state).removed;
        if removed && self.children().is_empty() {
            return (POLL_HUP, 0, 0);
        }
        let _guard = lock(&self.mmap_mutex);
        match lock(&self.rb).clone() {
            Some(rb) => {
                let (mask, wakeups) = rb.take_poll();
                (mask, wakeups, 0)
            }
            None => (POLL_HUP, 0, 0),
        }
    }
    /// `perf_event_wakeup` of the buffer it writes to, if any.
    pub(super) fn wake_readers(&self) {
        if let Some(rb) = lock(&self.rb).clone() {
            rb.wake();
        }
    }
    /// `_perf_event_refresh`: `refresh` more overflows, and the event
    /// enabled; `EINVAL` for one that does not sample or that new tasks
    /// inherit.
    pub(super) fn refresh(&self, refresh: i32) -> Result<(), paludarium_types::Errno> {
        if self.attr.flag(bit::INHERIT) || !self.attr.sampling() {
            return Err(paludarium_types::Errno::EINVAL);
        }
        self.event_limit.fetch_add(refresh, Ordering::Relaxed);
        self.set_enabled(true);
        self.update_user_page();
        Ok(())
    }
    /// `perf_event_clock`: the event's clock, `local_clock` for none.
    pub(super) fn clock_now(&self) -> u64 {
        let id = match self.clockid {
            Some(0 | 11) => ClockId::Realtime,
            _ => ClockId::Monotonic,
        };
        self.host.clock(id).unwrap_or(0)
    }
    /// The PID namespace's numbers of `task`'s process and thread.
    fn pid_tid(&self, task: &Task<'_>) -> [u8; 8] {
        self.pid_tid_of(task.pid, task.tid)
    }
    /// The PID namespace's numbers of process `pid` and thread `tid`
    /// (`perf_event_pid` and `perf_event_tid`).
    pub(super) fn pid_tid_of(&self, pid: u32, tid: u32) -> [u8; 8] {
        let ns: &Namespace = &self.ns;
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&ns.number(pid).to_le_bytes());
        bytes[4..].copy_from_slice(&ns.number(tid).to_le_bytes());
        bytes
    }
    /// `perf_event__id_header_size`.
    fn id_header_size(&self) -> usize {
        let st = self.attr.sample_type;
        [TID, TIME, IDENTIFIER, ID, STREAM_ID, CPU]
            .iter()
            .filter(|&&kind| st & kind != 0)
            .count()
            * 8
    }
    /// The `sample_id` that `sample_id_all` puts after a record but a
    /// sample (`__perf_event__output_id_sample`), empty without it.
    pub(super) fn id_sample(&self, task: &Task<'_>) -> Vec<u8> {
        self.id_sample_of(&task.who())
    }
    /// The same, of the thread `who` that writes the record.
    pub(super) fn id_sample_of(&self, who: &Who) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.attr.flag(bit::SAMPLE_ID_ALL) {
            return out;
        }
        let st = self.attr.sample_type;
        if st & TID != 0 {
            out.extend(self.pid_tid_of(who.pid, who.tid));
        }
        if st & TIME != 0 {
            put(&mut out, self.clock_now());
        }
        if st & ID != 0 {
            put(&mut out, self.id);
        }
        if st & STREAM_ID != 0 {
            put(&mut out, self.stream_id);
        }
        if st & CPU != 0 {
            put(&mut out, u64::from(who.cpu));
        }
        if st & IDENTIFIER != 0 {
            put(&mut out, self.id);
        }
        out
    }
    /// `PERF_RECORD_LOST` of `lost` samples (`__perf_output_begin`).
    pub(super) fn lost_record(&self, lost: u64, trailer: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        header(&mut out, RECORD_LOST, 0, 24 + trailer.len());
        put(&mut out, self.id);
        put(&mut out, lost);
        out.extend_from_slice(trailer);
        out
    }
    /// The size of a lost record and its `sample_id`.
    pub(super) fn lost_size(&self) -> usize {
        24 + if self.attr.flag(bit::SAMPLE_ID_ALL) {
            self.id_header_size()
        } else {
            0
        }
    }
    /// `perf_prepare_sample` and `perf_output_sample`: a sample of `task`,
    /// in user mode or in the kernel, of `period`. Past the record come
    /// the bytes Linux writes beyond the size it gave it: a user stack's
    /// dump of nothing still ends with its dynamic size.
    fn sample(self: &Arc<Self>, task: &Task<'_>, user: bool, period: u64) -> (Vec<u8>, Vec<u8>) {
        let st = self.attr.sample_type;
        let regs = task.regs;
        let ip = if user { regs.rip.0 } else { 0 };
        let mut out = Vec::new();
        header(
            &mut out,
            RECORD_SAMPLE,
            if user { MISC_USER } else { MISC_KERNEL },
            0,
        );
        if st & IDENTIFIER != 0 {
            put(&mut out, self.id);
        }
        if st & IP != 0 {
            put(&mut out, ip);
        }
        if st & TID != 0 {
            out.extend(self.pid_tid(task));
        }
        if st & TIME != 0 {
            put(&mut out, self.clock_now());
        }
        if st & ADDR != 0 {
            put(&mut out, 0);
        }
        if st & ID != 0 {
            put(&mut out, self.id);
        }
        if st & STREAM_ID != 0 {
            put(&mut out, self.stream_id);
        }
        if st & CPU != 0 {
            put(&mut out, u64::from(task.cpu));
        }
        if st & PERIOD != 0 {
            put(&mut out, period);
        }
        if st & READ != 0 {
            for value in self.sample_read() {
                put(&mut out, value);
            }
        }
        if st & CALLCHAIN != 0 {
            let chain = self.callchain(task, user);
            put(&mut out, chain.len() as u64);
            for ip in chain {
                put(&mut out, ip);
            }
        }
        if st & RAW != 0 {
            // No raw data: a size of 4 and 4 bytes of 0.
            put(&mut out, 4);
        }
        if st & BRANCH_STACK != 0 {
            put(&mut out, 0);
        }
        if st & REGS_USER != 0 {
            put(&mut out, ABI_64);
            for value in registers(self.attr.sample_regs_user, regs) {
                put(&mut out, value);
            }
        }
        let mut spill = Vec::new();
        if st & STACK_USER != 0 {
            // The size so far, with the fixed fields still to come.
            let fixed_after = [WEIGHT | WEIGHT_STRUCT, DATA_SRC, TRANSACTION, PHYS_ADDR]
                .iter()
                .chain(&[CGROUP, DATA_PAGE_SIZE, CODE_PAGE_SIZE])
                .filter(|&&kind| st & kind != 0)
                .count()
                * 8;
            let header_size = (out.len() + fixed_after) as u16;
            let size = ustack_size(self.attr.sample_stack_user as u16, header_size, regs);
            put(&mut out, u64::from(size));
            if size == 0 {
                // Linux gave this 8 bytes and writes the dynamic size too.
                put(&mut spill, 0);
            } else {
                let copied = read_user(task.mem, regs.gpr[reg::RSP], usize::from(size));
                let dumped = copied.len();
                out.extend(copied);
                out.resize(out.len() + usize::from(size) - dumped, 0);
                put(&mut out, dumped as u64);
            }
        }
        if st & (WEIGHT | WEIGHT_STRUCT) != 0 {
            put(&mut out, 0);
        }
        if st & DATA_SRC != 0 {
            put(&mut out, MEM_NA);
        }
        if st & TRANSACTION != 0 {
            put(&mut out, 0);
        }
        if st & REGS_INTR != 0 {
            // `perf_sample_regs_intr`: none for a sample of the kernel of
            // an event that excludes it; the kernel's are not known here.
            if !user && self.attr.flag(bit::EXCLUDE_KERNEL) {
                put(&mut out, 0);
            } else {
                put(&mut out, ABI_64);
                let kernel_regs = CpuState::default();
                let at = if user { regs } else { &kernel_regs };
                for value in registers(self.attr.sample_regs_intr, at) {
                    put(&mut out, value);
                }
            }
        }
        if st & PHYS_ADDR != 0 {
            put(&mut out, 0);
        }
        if st & CGROUP != 0 {
            put(&mut out, ROOT_CGROUP);
        }
        if st & DATA_PAGE_SIZE != 0 {
            put(&mut out, 0);
        }
        if st & CODE_PAGE_SIZE != 0 {
            let present = ip != 0 && task.mem.resident(GuestAddr(ip)) == Some(true);
            put(&mut out, if present { PAGE } else { 0 });
        }
        if st & AUX != 0 {
            put(&mut out, 0);
        }
        let size = out.len() as u16;
        out[6..8].copy_from_slice(&size.to_le_bytes());
        (out, spill)
    }
    /// `perf_output_read`: the values a sample reads, the event's own
    /// count with what ended children gave back (but only its own with
    /// `inherit`), and its times as of now.
    fn sample_read(self: &Arc<Self>) -> Vec<u64> {
        use super::FORMAT_TOTAL_TIME_RUNNING;
        use super::{FORMAT_GROUP, FORMAT_ID, FORMAT_LOST, FORMAT_TOTAL_TIME_ENABLED};
        let format = self.attr.read_format;
        let own = self.attr.flag(bit::INHERIT);
        let count = |event: &Event| {
            let state = event.settle();
            if own {
                state.count
            } else {
                state.count + state.child_count
            }
        };
        let lost = |event: &Event| lock(&event.sampler).lost;
        let (enabled, running, child_enabled, child_running) = {
            let state = self.settle();
            (
                state.enabled_time,
                state.running_time,
                state.child_enabled,
                state.child_running,
            )
        };
        let mut values = Vec::new();
        if format & FORMAT_GROUP != 0 {
            let group = self.group();
            values.push(group.len() as u64);
            if format & FORMAT_TOTAL_TIME_ENABLED != 0 {
                values.push(enabled);
            }
            if format & FORMAT_TOTAL_TIME_RUNNING != 0 {
                values.push(running);
            }
            for event in &group {
                values.push(count(event));
                if format & FORMAT_ID != 0 {
                    values.push(event.id);
                }
                if format & FORMAT_LOST != 0 {
                    values.push(lost(event));
                }
            }
        } else {
            values.push(count(self));
            if format & FORMAT_TOTAL_TIME_ENABLED != 0 {
                values.push(enabled + child_enabled);
            }
            if format & FORMAT_TOTAL_TIME_RUNNING != 0 {
                values.push(running + child_running);
            }
            if format & FORMAT_ID != 0 {
                values.push(self.id);
            }
            if format & FORMAT_LOST != 0 {
                values.push(lost(self));
            }
        }
        values
    }
    /// `perf_callchain`: `PERF_CONTEXT_KERNEL` for a sample of the kernel
    /// (whose frames are not known here), then `PERF_CONTEXT_USER`, the
    /// thread's address and the return addresses its `rbp` chain holds
    /// (`perf_callchain_user`), up to `sample_max_stack` of them and
    /// `perf_event_max_contexts_per_stack` contexts.
    fn callchain(&self, task: &Task<'_>, user: bool) -> Vec<u64> {
        let mut chain = Chain {
            ips: Vec::new(),
            nr: 0,
            max: u32::from(self.attr.sample_max_stack),
            contexts: 0,
            maxed: false,
        };
        if !self.attr.flag(bit::EXCLUDE_CALLCHAIN_KERNEL) && !user {
            chain.context(CONTEXT_KERNEL);
        }
        if self.attr.flag(bit::EXCLUDE_CALLCHAIN_USER) {
            return chain.ips;
        }
        chain.context(CONTEXT_USER);
        chain.store(task.regs.rip.0);
        let mut fp = task.regs.gpr[reg::RBP];
        while chain.nr < chain.max {
            let frame = read_user(task.mem, fp, 16);
            let (Some(next), Some(ret)) = (frame.get(..8), frame.get(8..16)) else {
                break;
            };
            chain.store(u64::from_le_bytes(ret.try_into().unwrap_or_default()));
            fp = u64::from_le_bytes(next.try_into().unwrap_or_default());
        }
        chain.ips
    }
}

/// `struct perf_callchain_entry_ctx`: the addresses so far, of which
/// `nr` are not contexts, and the contexts, past whose limit (`maxed`)
/// nothing more is stored.
struct Chain {
    ips: Vec<u64>,
    nr: u32,
    max: u32,
    contexts: u32,
    maxed: bool,
}

impl Chain {
    /// `perf_callchain_store_context`.
    fn context(&mut self, marker: u64) {
        if self.contexts < MAX_CONTEXTS {
            self.ips.push(marker);
            self.contexts += 1;
        } else {
            self.maxed = true;
        }
    }
    /// `perf_callchain_store`.
    fn store(&mut self, ip: u64) {
        if self.nr < self.max && !self.maxed {
            self.ips.push(ip);
            self.nr += 1;
        }
    }
}

/// The registers of `mask`, in Linux's numbering of x86-64's
/// (`perf_reg_value`): AX, BX, CX, DX, SI, DI, BP, SP, IP, FLAGS, CS, SS,
/// then (DS to GS refused) R8 to R15.
fn registers(mask: u64, regs: &CpuState) -> Vec<u64> {
    (0..64)
        .filter(|bit| mask >> bit & 1 != 0)
        .map(|bit| match bit {
            0 => regs.gpr[reg::RAX],
            1 => regs.gpr[reg::RBX],
            2 => regs.gpr[reg::RCX],
            3 => regs.gpr[reg::RDX],
            4 => regs.gpr[reg::RSI],
            5 => regs.gpr[reg::RDI],
            6 => regs.gpr[reg::RBP],
            7 => regs.gpr[reg::RSP],
            8 => regs.rip.0,
            9 => regs.rflags,
            10 => 0x33,
            11 => 0x2b,
            16..=23 => regs.gpr[reg::R8 + (bit - 16) as usize],
            _ => 0,
        })
        .collect()
}

/// `perf_sample_ustack_size`: what of `stack_size` bytes of the user stack
/// fits below `TASK_SIZE` and in a sample of `header_size` so far.
fn ustack_size(stack_size: u16, header_size: u16, regs: &CpuState) -> u16 {
    let sp = regs.gpr[reg::RSP];
    let task_size = if sp == 0 || sp >= TASK_SIZE {
        0
    } else {
        (TASK_SIZE - sp).min(u64::from(u16::MAX))
    };
    let mut size = stack_size.min(task_size as u16);
    let header_size = header_size.wrapping_add(16);
    if header_size.wrapping_add(size) < header_size {
        size = (u16::MAX - header_size - 8).next_multiple_of(8);
    }
    size
}

/// Up to `len` bytes of user memory from `at`, as far as the pages there
/// are in memory and readable (`copy_from_user` with page faults off).
fn read_user(mem: &AddressSpace, at: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut addr = at;
    while out.len() < len {
        if addr >= TASK_SIZE || mem.resident(GuestAddr(addr)) != Some(true) {
            break;
        }
        let in_page = (PAGE - addr % PAGE) as usize;
        let n = in_page.min(len - out.len());
        let mut chunk = vec![0; n];
        if mem.read(GuestAddr(addr), &mut chunk).is_err() {
            break;
        }
        out.extend(chunk);
        addr += n as u64;
    }
    out
}

pub(super) fn put(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_le_bytes());
}

/// `struct perf_event_header`.
pub(super) fn header(out: &mut Vec<u8>, kind: u32, misc: u16, size: usize) {
    out.extend(kind.to_le_bytes());
    out.extend(misc.to_le_bytes());
    out.extend((size as u16).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_period_overflows_at_its_last_occurrence() {
        let mut sampler = Sampler::of_period(3, Counter::Faults);
        let mut out = Runs::new();
        sampler.occurrences(2, false, false, &mut out);
        assert!(out.is_empty());
        sampler.occurrences(1, false, false, &mut out);
        assert_eq!(out, [(3, 1)]);
        sampler.occurrences(7, false, false, &mut out);
        assert_eq!(out, [(3, 3)]);
        assert_eq!(sampler.left, -2);
    }

    #[test]
    fn the_period_field_makes_each_occurrence_a_sample() {
        let mut sampler = Sampler::of_period(1000, Counter::Faults);
        let mut out = Runs::new();
        sampler.occurrences(3, true, false, &mut out);
        assert_eq!(out, [(1, 3)]);
    }

    #[test]
    fn a_new_period_overflows_at_the_next_occurrence() {
        let mut sampler = Sampler::of_period(4, Counter::Faults);
        sampler.set_period(4, Counter::Faults, true);
        let mut out = Runs::new();
        sampler.occurrences(1, false, false, &mut out);
        assert_eq!(out, [(4, 1)]);
        // `period_left` is 1 - 4 then: three more overflow again.
        sampler.occurrences(2, false, false, &mut out);
        assert_eq!(out, [(4, 1)]);
        sampler.occurrences(1, false, false, &mut out);
        assert_eq!(out, [(4, 2)]);
    }

    /// Linux's default `max_samples_per_tick` (100000 a second at
    /// `HZ` 1000).
    const PER_TICK: u64 = 100;
    const MS: u64 = 1_000_000;

    #[test]
    fn a_clock_fires_first_after_its_period_then_every_10_us_at_least() {
        let mut sampler = Sampler::of_period(1000, Counter::Clock);
        let mut out = Vec::new();
        assert_eq!(sampler.ticks(999, PER_TICK, &mut out), 0);
        assert!(out.is_empty());
        sampler.ticks(1, PER_TICK, &mut out);
        assert_eq!(out, [Fire::Samples(1000, 1)]);
        sampler.ticks(25_000, PER_TICK, &mut out);
        assert_eq!(out, [Fire::Samples(1000, 3)]);
        assert_eq!(sampler.left, 5000);
    }

    #[test]
    fn the_interrupt_that_fills_a_tick_throttles_a_clock_until_the_next() {
        // Every 10 us from 10 us: 99 in the first tick, then 100 in the
        // second, the last of which throttles it before its sample.
        let mut sampler = Sampler::of_period(10_000, Counter::Clock);
        let mut out = Vec::new();
        // Its count stops from that interrupt, at 1990 us.
        assert_eq!(sampler.ticks(2 * MS - 1, PER_TICK, &mut out), 9999);
        assert_eq!(
            out,
            [
                Fire::Samples(10_000, 198),
                Fire::Throttle,
                Fire::Samples(10_000, 1)
            ]
        );
        // The third tick unthrottles it, its hrtimer started again then.
        out.clear();
        assert_eq!(sampler.ticks(1, PER_TICK, &mut out), 1);
        assert_eq!(out, [Fire::Unthrottle]);
        out.clear();
        sampler.ticks(10_000, PER_TICK, &mut out);
        assert_eq!(out, [Fire::Samples(10_000, 1)]);
    }

    #[test]
    fn one_interrupt_a_tick_throttles_each_sample_and_stops_the_count() {
        // `perf_event_max_sample_rate` 1: one interrupt a tick at most.
        let mut sampler = Sampler::of_period(100_000, Counter::Clock);
        let mut out = Vec::new();
        let stopped = sampler.ticks(3 * MS + MS / 2, 1, &mut out);
        let once = [Fire::Throttle, Fire::Samples(100_000, 1)];
        let mut wanted = Vec::new();
        for _ in 0..3 {
            wanted.extend(once);
            wanted.push(Fire::Unthrottle);
        }
        wanted.extend(once);
        assert_eq!(out, wanted);
        // From each interrupt, 100 us into its tick, to the next tick, and
        // to the end in the last.
        assert_eq!(stopped, 3 * (MS - 100_000) + MS / 2 - 100_000);
    }

    #[test]
    fn a_clock_that_no_tick_can_fill_is_never_throttled() {
        let mut sampler = Sampler::of_period(100_000, Counter::Clock);
        let mut out = Vec::new();
        assert_eq!(sampler.ticks(1000 * MS, PER_TICK, &mut out), 0);
        assert_eq!(out, [Fire::Samples(100_000, 10_000)]);
    }

    #[test]
    fn a_throttled_clock_taken_in_again_is_unthrottled_with_a_whole_period() {
        let mut sampler = Sampler::of_period(100_000, Counter::Clock);
        let mut out = Vec::new();
        sampler.ticks(200_000, 1, &mut out);
        assert_eq!(out, [Fire::Throttle, Fire::Samples(100_000, 1)]);
        // Enabled again, or its period set, before the next tick.
        sampler.scheduled_in();
        out.clear();
        sampler.ticks(100_000, 1, &mut out);
        // Its next interrupt is in the same tick as the one that throttled
        // it: the second in it, which throttles it again.
        assert_eq!(
            out,
            [Fire::Unthrottle, Fire::Throttle, Fire::Samples(100_000, 1)]
        );
        // Not throttled, it is not unthrottled either.
        let mut free = Sampler::of_period(100_000, Counter::Clock);
        free.scheduled_in();
        out.clear();
        free.ticks(1, 1, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn the_frequency_pulls_the_period_an_eighth_of_the_way() {
        let mut sampler = Sampler {
            frequency: 100,
            ..Sampler::of_period(1, Counter::Faults)
        };
        // 1000 a second at 100 a second wants a period of 10: 1 and
        // (9 + 7) / 8.
        sampler.adjust(NSEC_PER_SEC, 1000);
        assert_eq!(sampler.period, 3);
    }

    #[test]
    fn a_stack_dump_fits_below_task_size_and_in_the_sample() {
        let mut regs = CpuState::default();
        regs.gpr[reg::RSP] = TASK_SIZE - 64;
        assert_eq!(ustack_size(4096, 64, &regs), 64);
        regs.gpr[reg::RSP] = 0x1000;
        assert_eq!(ustack_size(65528, 64, &regs), 65528 - 88 + 8);
        regs.gpr[reg::RSP] = 0;
        assert_eq!(ustack_size(4096, 64, &regs), 0);
    }
}
