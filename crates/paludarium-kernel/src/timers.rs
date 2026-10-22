//! POSIX per-process timers (`timer_create` and family). Deadlines are kept
//! on the monotonic clock; a `CLOCK_REALTIME` timer is converted when armed.
use std::collections::BTreeMap;

use paludarium_types::Errno;

use crate::ThreadState;
use crate::signals::{PendingSignal, SI_TIMER, TimerSignal};

/// One timer. `signal` is `None` for `SIGEV_NONE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PosixTimer {
    pub realtime: bool,
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
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.table.values().filter_map(|t| t.deadline).min()
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
        let mut directed = Vec::new();
        for (&id, timer) in &mut self.table {
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
