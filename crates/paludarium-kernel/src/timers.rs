//! POSIX per-process timers (`timer_create` and family). Deadlines of the
//! wall clocks are kept on the monotonic clock; a `CLOCK_REALTIME` timer is
//! converted when armed. Those of the CPU-time clocks are kept in that CPU
//! time, as Linux's `cpu_timer` expiry is.
use std::collections::BTreeMap;

use paludarium_types::Errno;

use crate::ThreadState;
use crate::signals::{PendingSignal, SI_TIMER, TimerSignal};

/// The clock a timer runs on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TimerClock {
    #[default]
    Monotonic,
    Realtime,
    /// `CLOCK_PROCESS_CPUTIME_ID`: the process's CPU time.
    Process,
    /// `CLOCK_THREAD_CPUTIME_ID`: the CPU time of the thread that created
    /// the timer.
    Thread(u32),
    /// Another process's CPU time, by its ID in the emulator; that
    /// process's checkpoints expire it ([`Timers::expire_foreign`]).
    OtherProcess(u32),
}
impl TimerClock {
    pub(crate) fn is_cpu(self) -> bool {
        matches!(
            self,
            Self::Process | Self::Thread(_) | Self::OtherProcess(_)
        )
    }
}

/// One timer. `signal` is `None` for `SIGEV_NONE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PosixTimer {
    pub clock: TimerClock,
    pub signal: Option<i32>,
    /// SIGEV_THREAD_ID: the thread the signal goes to.
    pub thread: Option<u32>,
    pub value: u64,
    pub deadline: Option<u64>,
    pub interval: u64,
    /// Expirations missed while the previous signal was still pending.
    pub overrun: i32,
}

/// The timers of one process: not inherited by `fork`, deleted by `exec`.
#[derive(Debug, Default)]
pub(crate) struct Timers {
    next: i32,
    table: BTreeMap<i32, PosixTimer>,
}

impl Timers {
    /// Linux hands out IDs from 0 upward.
    pub(crate) fn create(&mut self, timer: PosixTimer) -> Result<i32, Errno> {
        let id = self.next;
        self.next = self.next.checked_add(1).ok_or(Errno::EAGAIN)?;
        self.table.insert(id, timer);
        Ok(id)
    }
    pub(crate) fn get_mut(&mut self, id: i32) -> Result<&mut PosixTimer, Errno> {
        self.table.get_mut(&id).ok_or(Errno::EINVAL)
    }
    pub(crate) fn delete(&mut self, id: i32) -> Result<(), Errno> {
        self.table.remove(&id).map(|_| ()).ok_or(Errno::EINVAL)
    }
    pub(crate) fn clear(&mut self) {
        self.table.clear();
    }
    pub(crate) fn get(&self, id: i32) -> Result<&PosixTimer, Errno> {
        self.table.get(&id).ok_or(Errno::EINVAL)
    }
    /// The next deadline on the monotonic clock.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.table
            .values()
            .filter(|t| !t.clock.is_cpu())
            .filter_map(|t| t.deadline)
            .min()
    }
    /// Whether a timer on a CPU-time clock is armed to send a signal, so
    /// that checkpoints have to bring the CPU time up to date for it
    /// (Linux never arms a `SIGEV_NONE` one).
    pub(crate) fn cpu_armed(&self) -> bool {
        self.table.values().any(|t| {
            matches!(t.clock, TimerClock::Process | TimerClock::Thread(_))
                && t.signal.is_some()
                && t.deadline.is_some()
        })
    }
    /// Whether a timer on process `pid`'s CPU time is armed to send a
    /// signal, so that that process's checkpoints have to look at it.
    pub(crate) fn foreign_armed(&self, pid: u32) -> bool {
        self.table.values().any(|t| {
            t.clock == TimerClock::OtherProcess(pid) && t.signal.is_some() && t.deadline.is_some()
        })
    }
    /// As [`Self::expire`], for the timers on process `pid`'s CPU time,
    /// which is `cpu`: Linux's tick of that process expires them.
    pub(crate) fn expire_foreign(
        &mut self,
        pending: &mut ThreadState,
        pid: u32,
        cpu: u64,
    ) -> Vec<(u32, PendingSignal)> {
        self.expire_by(pending, |timer| {
            (timer.clock == TimerClock::OtherProcess(pid) && timer.signal.is_some()).then_some(cpu)
        })
    }
    /// Queues the signal of every timer due at `now` into `pending`. An
    /// expiry while the timer's last signal is still pending counts as an
    /// overrun of that signal instead, as on Linux. The signals of
    /// SIGEV_THREAD_ID timers are returned with their thread instead, for
    /// that thread's inbox.
    pub(crate) fn expire(
        &mut self,
        pending: &mut ThreadState,
        now: u64,
    ) -> Vec<(u32, PendingSignal)> {
        self.expire_by(pending, |timer| (!timer.clock.is_cpu()).then_some(now))
    }
    /// As [`Self::expire`], for the timers on the CPU-time clocks: the
    /// process's CPU time is `process`, and `thread` gives a live thread's
    /// (the timers of a thread that has exited never expire, as Linux
    /// removes them from their queue). A `SIGEV_NONE` timer is never armed
    /// on Linux, and is only moved on when it is read.
    pub(crate) fn expire_cpu(
        &mut self,
        pending: &mut ThreadState,
        process: u64,
        thread: impl Fn(u32) -> Option<u64>,
    ) -> Vec<(u32, PendingSignal)> {
        self.expire_by(pending, |timer| match timer.clock {
            _ if timer.signal.is_none() => None,
            TimerClock::Process => Some(process),
            TimerClock::Thread(tid) => thread(tid),
            TimerClock::Monotonic | TimerClock::Realtime | TimerClock::OtherProcess(_) => None,
        })
    }
    /// Expires the timers for which `now` gives the time of their clock.
    fn expire_by(
        &mut self,
        pending: &mut ThreadState,
        now: impl Fn(&PosixTimer) -> Option<u64>,
    ) -> Vec<(u32, PendingSignal)> {
        let mut directed = Vec::new();
        for (&id, timer) in &mut self.table {
            let Some(now) = now(timer) else {
                continue;
            };
            let Some(deadline) = timer.deadline.filter(|&d| now >= d) else {
                continue;
            };
            // A one-shot timer (interval 0) expires once and disarms.
            let expirations = match (now - deadline).checked_div(timer.interval) {
                None => {
                    timer.deadline = None;
                    1
                }
                Some(missed) => {
                    let n = missed + 1;
                    timer.deadline = n
                        .checked_mul(timer.interval)
                        .and_then(|delta| deadline.checked_add(delta));
                    n
                }
            };
            let Some(number) = timer.signal else {
                continue;
            };
            let missed = i32::try_from(expirations - 1).unwrap_or(i32::MAX);
            if let Some(tid) = timer.thread {
                timer.overrun = missed;
                directed.push((
                    tid,
                    PendingSignal {
                        timer: Some(TimerSignal {
                            id,
                            overrun: missed,
                            value: timer.value,
                        }),
                        ..PendingSignal::thread(number, SI_TIMER)
                    },
                ));
                continue;
            }
            if let Some(queued) = pending
                .pending
                .iter_mut()
                .find_map(|s| s.timer.as_mut().filter(|t| t.id == id))
            {
                queued.overrun = queued.overrun.saturating_add(missed).saturating_add(1);
                timer.overrun = queued.overrun;
                continue;
            }
            timer.overrun = missed;
            pending.pending.push(PendingSignal {
                timer: Some(TimerSignal {
                    id,
                    overrun: missed,
                    value: timer.value,
                }),
                ..PendingSignal::user(number, SI_TIMER)
            });
        }
        directed
    }
    /// Records the overrun the signal of timer `id` ended up with.
    pub(crate) fn set_overrun(&mut self, id: i32, overrun: i32) {
        if let Some(timer) = self.table.get_mut(&id) {
            timer.overrun = overrun;
        }
    }
}
