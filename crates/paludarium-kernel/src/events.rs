//! Kernel-owned event counters and readiness tickets. No host epoll is used.
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat, WaitToken};
use paludarium_types::Errno;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| {
        let flags = u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?;
        let event = Arc::new(EventCounter::new(
            a[0] as u32,
            flags,
            Arc::clone(&c.files.readiness),
        )?);
        c.files
            .install(event, flags & CLOEXEC != 0, c.group.nofile())
            .map(u64::from)
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// Sample the ticket before readiness inspection to prevent lost writes.
pub(crate) fn wait(c: &mut Context<'_>, ticket: u32, deadline: Option<u64>) -> Result<(), Errno> {
    let receipt = c.inbox.drain(c.process);
    c.group.drain_process(c.process);
    let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
    c.group.expire_timer(c.process, now);
    if c.group.status().is_some()
        || crate::signals::next_pending(c.process, true).is_some()
        || receipt.interrupted
        || (!c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst))
    {
        return Err(Errno(4));
    }
    // Owner receipts distinguish metadata from actual interruption, including
    // notifications that precede entry. Bounded waits also observe group exit.
    let end = deadline
        .unwrap_or(u64::MAX)
        .min(now.saturating_add(10_000_000))
        .min(crate::signals::next_deadline(c.process).unwrap_or(u64::MAX));
    let generation = c.group.timer_generation();
    let outcome = match c.host.wait_on(
        &c.files.readiness.token,
        ticket,
        Some((paludarium_host::ClockId::Monotonic, end)),
        c.cancellation,
    ) {
        Err(e) if e == Errno::ENOSYS => {
            c.host
                .wait_until(paludarium_host::ClockId::Monotonic, end, c.cancellation)?
        }
        result => result?,
    };
    let receipt = c.inbox.drain(c.process);
    c.group.drain_process(c.process);
    c.group.expire_timer(
        c.process,
        c.host.clock(paludarium_host::ClockId::Monotonic)?,
    );
    if c.group.status().is_some()
        || crate::signals::next_pending(c.process, true).is_some()
        || receipt.interrupted
        || (!c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst))
        || (outcome == paludarium_host::WaitOutcome::Interrupted
            && !receipt.timer_changed
            && !receipt.signals
            && c.group.timer_generation() == generation)
    {
        Err(Errno(4))
    } else {
        Ok(())
    }
}

pub(crate) const IN: u32 = 1;
/// `POLLPRI`: a stream's out-of-band byte waits.
pub(crate) const PRI: u32 = 2;
pub(crate) const OUT: u32 = 4;
pub(crate) const NONBLOCK: u32 = 0x800;
pub(crate) const CLOEXEC: u32 = 0x80000;

#[derive(Default)]
pub(crate) struct ReadinessHub {
    pub token: WaitToken,
    pub graph: Mutex<()>,
}
impl ReadinessHub {
    pub fn changed(&self) {
        self.token.notify();
    }
}
struct Counter {
    value: u64,
    input_epoch: u64,
    output_epoch: u64,
}
pub(crate) struct EventCounter {
    state: Mutex<Counter>,
    semaphore: bool,
    flags: AtomicU32,
    hub: Arc<ReadinessHub>,
}
impl EventCounter {
    pub fn new(value: u32, flags: u32, hub: Arc<ReadinessHub>) -> Result<Self, Errno> {
        if flags & !(1 | NONBLOCK | CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            state: Mutex::new(Counter {
                value: u64::from(value),
                input_epoch: u64::from(value != 0),
                output_epoch: 1,
            }),
            semaphore: flags & 1 != 0,
            flags: AtomicU32::new(2 | flags & NONBLOCK),
            hub,
        })
    }
}
impl FileHandle for EventCounter {
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Ok((
            (u32::from(s.value != 0) * IN) | (u32::from(s.value < u64::MAX - 1) * OUT),
            s.input_epoch,
            s.output_epoch,
        ))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if s.value == 0 {
            return Err(Errno::EAGAIN);
        }
        let value = if self.semaphore {
            s.value -= 1;
            1
        } else {
            let v = s.value;
            s.value = 0;
            v
        };
        s.output_epoch = s.output_epoch.wrapping_add(1);
        buf[..8].copy_from_slice(&value.to_le_bytes());
        self.hub.changed();
        Ok(8)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let value = u64::from_le_bytes(buf[..8].try_into().map_err(|_| Errno::EINVAL)?);
        if value == u64::MAX {
            return Err(Errno::EINVAL);
        }
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let next = s
            .value
            .checked_add(value)
            .filter(|v| *v != u64::MAX)
            .ok_or(Errno::EAGAIN)?;
        // Linux eventfd wakes its poll callbacks for a successful write even
        // when the counter was already readable; ET consumes each callback.
        s.input_epoch = s.input_epoch.wrapping_add(1);
        s.value = next;
        self.hub.changed();
        Ok(8)
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
mod events_tests {
    use super::*;
    fn counter(value: u32, flags: u32) -> EventCounter {
        EventCounter::new(value, flags, Arc::default()).unwrap()
    }
    fn take(c: &EventCounter) -> Result<u64, Errno> {
        let mut b = [0; 8];
        c.read(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    #[test]
    fn events_event_initial() {
        assert_eq!(take(&counter(7, 0)), Ok(7));
    }
    #[test]
    fn event_accumulate() {
        let c = counter(0, 0);
        c.write(&2u64.to_le_bytes()).unwrap();
        c.write(&3u64.to_le_bytes()).unwrap();
        assert_eq!(take(&c), Ok(5));
    }
    #[test]
    fn events_event_semaphore() {
        let c = counter(2, 1);
        assert_eq!(take(&c), Ok(1));
        assert_eq!(take(&c), Ok(1));
        assert_eq!(take(&c), Err(Errno::EAGAIN));
    }
    #[test]
    fn event_zero() {
        let c = counter(0, 0);
        c.write(&0u64.to_le_bytes()).unwrap();
        assert_eq!(take(&c), Err(Errno::EAGAIN));
    }
    #[test]
    fn event_maximum() {
        let c = counter(0, 0);
        assert_eq!(c.write(&u64::MAX.to_le_bytes()), Err(Errno::EINVAL));
        c.write(&(u64::MAX - 1).to_le_bytes()).unwrap();
        assert_eq!(c.write(&1u64.to_le_bytes()), Err(Errno::EAGAIN));
        assert_eq!(take(&c), Ok(u64::MAX - 1));
    }
    #[test]
    fn event_short_abi() {
        let c = counter(1, 0);
        assert_eq!(c.read(&mut [0; 7]), Err(Errno::EINVAL));
        assert_eq!(c.write(&[0; 7]), Err(Errno::EINVAL));
    }
    #[test]
    fn event_edges() {
        let c = counter(0, 0);
        let before = c.readiness().unwrap();
        c.write(&1u64.to_le_bytes()).unwrap();
        let ready = c.readiness().unwrap();
        c.write(&1u64.to_le_bytes()).unwrap();
        assert_eq!(c.readiness().unwrap().1, ready.1 + 1);
        take(&c).unwrap();
        c.write(&1u64.to_le_bytes()).unwrap();
        assert_eq!(c.readiness().unwrap().1, before.1 + 3);
    }
    #[test]
    fn event_flags() {
        let c = counter(0, NONBLOCK | CLOEXEC);
        assert_eq!(c.flags(), 2 | NONBLOCK);
        c.set_flags(0).unwrap();
        assert_eq!(c.flags(), 2);
        assert!(EventCounter::new(0, 4, Arc::default()).is_err());
    }
}
