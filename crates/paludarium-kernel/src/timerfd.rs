//! `timerfd_create`, `timerfd_settime` and `timerfd_gettime`. A timer file
//! counts its expirations lazily from the host clock whenever it is read or
//! polled, so blocking reads, `poll` and `epoll` see it through their usual
//! bounded waits.
use crate::events::{CLOEXEC, IN, NONBLOCK};
use crate::syscalls::{Context, Outcome, read_words, write_words};
use paludarium_host::{ClockId, FileHandle, FileStat, Host};
use paludarium_types::Errno;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

const TIMER_ABSTIME: u64 = 1;
const TIMER_CANCEL_ON_SET: u64 = 2;
/// Linux's largest time, which a later time saturates to.
const KTIME_MAX: u64 = i64::MAX as u64;

/// A `struct timespec` as nanoseconds: any non-negative time is valid, and
/// one past `KTIME_MAX` saturates to it, as Linux's `timespec64_to_ktime` does.
fn ktime(seconds: u64, nanos: u64) -> Result<u64, Errno> {
    if (seconds as i64) < 0 || nanos >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanos)
        .min(KTIME_MAX))
}

pub(crate) fn sys_timerfd_create(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(create(c, a))
}
pub(crate) fn sys_timerfd_settime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(settime(c, a))
}
pub(crate) fn sys_timerfd_gettime(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(gettime(c, a))
}
fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// `timerfd_create(clockid, flags)`. CLOCK_BOOTTIME runs as CLOCK_MONOTONIC,
/// as the guest never suspends; the alarm clocks need CAP_WAKE_ALARM.
fn create(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let clock = match a[0] as i32 {
        0 => ClockId::Realtime,
        1 | 7 => ClockId::Monotonic,
        8 | 9 => return Err(Errno::EPERM),
        _ => return Err(Errno::EINVAL),
    };
    let flags = a[1] as i32 as u32;
    if flags & !(NONBLOCK | CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let timer = Arc::new(TimerFile {
        host: Arc::clone(c.shared_host),
        clock,
        state: Mutex::new(State::default()),
        flags: AtomicU32::new(2 | flags & NONBLOCK),
    });
    c.files.install(timer, flags & CLOEXEC != 0).map(u64::from)
}

/// The timer file `fd` names: EBADF for no descriptor, EINVAL for another file.
fn timer(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    file.as_any()
        .is_some_and(|any| any.is::<TimerFile>())
        .then_some(file)
        .ok_or(Errno::EINVAL)
}

fn as_timer(file: &Arc<dyn FileHandle>) -> &TimerFile {
    file.as_any()
        .and_then(|any| any.downcast_ref::<TimerFile>())
        .unwrap_or_else(|| unreachable!("checked by timer()"))
}

/// `timerfd_settime(fd, flags, new, old)`, in Linux's order: read `new`, check
/// the flags and times, find the timer, set it (clearing its count), then
/// write the old setting out.
fn settime(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let [i_sec, i_nsec, v_sec, v_nsec] = read_words::<4>(c.mem, a[2])?;
    if a[1] as u32 as u64 & !(TIMER_ABSTIME | TIMER_CANCEL_ON_SET) != 0 {
        return Err(Errno::EINVAL);
    }
    let (interval, value) = (ktime(i_sec, i_nsec)?, ktime(v_sec, v_nsec)?);
    let file = timer(c, a[0])?;
    let timer = as_timer(&file);
    let now = timer.host.clock(timer.clock)?;
    let old = {
        let mut state = timer.lock(now);
        let old = state.setting(now);
        state.ticks = 0;
        state.deadline = (value != 0).then(|| {
            if a[1] & TIMER_ABSTIME != 0 {
                value
            } else {
                now.saturating_add(value).min(KTIME_MAX)
            }
        });
        // Linux keeps the interval even when the zero value disarms the timer.
        state.interval = interval;
        old
    };
    if a[3] != 0 {
        write_words(c.mem, a[3], &old)?;
    }
    Ok(0)
}

fn gettime(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = timer(c, a[0])?;
    let timer = as_timer(&file);
    let now = timer.host.clock(timer.clock)?;
    let setting = timer.lock(now).setting(now);
    write_words(c.mem, a[1], &setting)?;
    Ok(0)
}

#[derive(Default)]
struct State {
    /// The next expiry on the timer's clock; `None` when disarmed.
    deadline: Option<u64>,
    interval: u64,
    /// Expirations not yet read.
    ticks: u64,
    /// Bumped on every expiry, so edge-triggered epoll sees each one.
    input_epoch: u64,
}
impl State {
    /// Counts the expirations up to `now`, rearming a periodic timer.
    fn advance(&mut self, now: u64) {
        let Some(deadline) = self.deadline.filter(|&d| now >= d) else {
            return;
        };
        let expirations = match (now - deadline).checked_div(self.interval) {
            None => {
                self.deadline = None;
                1
            }
            Some(missed) => {
                let n = missed + 1;
                // Saturating at KTIME_MAX, as hrtimer_forward does: a period
                // that would pass it leaves the timer armed but never due.
                self.deadline = Some(
                    deadline
                        .saturating_add(n.saturating_mul(self.interval))
                        .min(KTIME_MAX),
                );
                n
            }
        };
        self.ticks = self.ticks.saturating_add(expirations);
        self.input_epoch = self.input_epoch.wrapping_add(1);
    }
    /// `struct itimerspec`: the interval and the time to the next expiry.
    fn setting(&self, now: u64) -> [u64; 4] {
        let remaining = self.deadline.map_or(0, |d| d.saturating_sub(now).max(1));
        [
            self.interval / 1_000_000_000,
            self.interval % 1_000_000_000,
            remaining / 1_000_000_000,
            remaining % 1_000_000_000,
        ]
    }
}

pub(crate) struct TimerFile {
    host: Arc<dyn Host>,
    clock: ClockId,
    state: Mutex<State>,
    flags: AtomicU32,
}
impl TimerFile {
    /// The state with its expirations counted up to `now`.
    fn lock(&self, now: u64) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.advance(now);
        state
    }
    fn current(&self) -> Result<std::sync::MutexGuard<'_, State>, Errno> {
        Ok(self.lock(self.host.clock(self.clock)?))
    }
}
impl FileHandle for TimerFile {
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let state = self.current()?;
        Ok((u32::from(state.ticks != 0) * IN, state.input_epoch, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let mut state = self.current()?;
        if state.ticks == 0 {
            return Err(Errno::EAGAIN);
        }
        buf[..8].copy_from_slice(&state.ticks.to_le_bytes());
        state.ticks = 0;
        Ok(8)
    }
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
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(2 | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn timer() -> TimerFile {
        TimerFile {
            host: Arc::new(paludarium_host::testing::RecordingHost::new()),
            clock: ClockId::Realtime,
            state: Mutex::new(State::default()),
            flags: AtomicU32::new(2),
        }
    }
    #[test]
    fn file_operations() {
        let t = timer();
        assert_eq!(t.readiness(), Ok((0, 0, 0)));
        assert_eq!(t.seek(0, 0), Err(Errno::ESPIPE));
        assert_eq!(t.stat().unwrap().mode, 0o600);
        assert_eq!(t.truncate(0), Err(Errno::EINVAL));
        assert_eq!(t.flock(0), Err(Errno::ENOSYS));
        t.set_flags(NONBLOCK | 1).unwrap();
        assert_eq!(t.flags(), 2 | NONBLOCK);
    }
    #[test]
    fn periodic_expiry_rearms() {
        let mut state = State {
            deadline: Some(10),
            interval: 4,
            ..State::default()
        };
        state.advance(9);
        assert_eq!(state.ticks, 0);
        state.advance(19);
        assert_eq!(
            (state.ticks, state.deadline, state.input_epoch),
            (3, Some(22), 1)
        );
        assert_eq!(state.setting(21), [0, 4, 0, 1]);
        let mut huge = State {
            deadline: Some(KTIME_MAX - 1),
            interval: KTIME_MAX,
            ..State::default()
        };
        huge.advance(KTIME_MAX);
        assert_eq!((huge.ticks, huge.deadline), (1, Some(KTIME_MAX)));
        state.interval = 0;
        state.advance(22);
        assert_eq!((state.ticks, state.deadline), (4, None));
        assert_eq!(state.setting(30), [0, 0, 0, 0]);
    }
}
