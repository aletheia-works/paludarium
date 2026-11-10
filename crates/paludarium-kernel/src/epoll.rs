//! Kernel epoll interests use (descriptor number, open-description identity).
//! Weak description references do not prolong a guest's last open descriptor.
use crate::events::{IN, OUT, ReadinessHub};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};

/// `O_PATH`: only a path, not an open file.
const O_PATH: u32 = 0o10000000;

const ET: u32 = 1 << 31;
const ONESHOT: u32 = 1 << 30;
struct Interest {
    file: Weak<dyn FileHandle>,
    events: u32,
    data: u64,
    input_epoch: u64,
    output_epoch: u64,
    previous: u32,
    enabled: bool,
    /// On Linux's ready list (`rdllist`), whose items `epoll_wait` polls:
    /// put there by `epoll_ctl` finding the file ready, by a wakeup of the
    /// file, and again after a level-triggered report.
    listed: bool,
    /// The file's generations when this interest last looked, so that a
    /// change since stands for the wakeup that would have listed it.
    seen: (u64, u64),
}
impl Interest {
    fn ready(&self) -> Option<(u32, u64, u64)> {
        if !self.enabled {
            return None;
        }
        let file = self.file.upgrade()?;
        let (mask, input, output) = file.readiness().ok()?;
        let mask = mask & (self.events | 0x18) & !(ET | ONESHOT);
        let edges = (mask & IN != 0 && input != self.input_epoch)
            || (mask & OUT != 0 && output != self.output_epoch)
            || mask & !self.previous & !5 != 0;
        (mask != 0 && (self.events & ET == 0 || edges)).then_some((mask, input, output))
    }
}
#[derive(Default)]
struct State {
    interests: BTreeMap<(u32, usize), Interest>,
    cursor: usize,
}
pub(crate) struct EpollInstance {
    state: Mutex<State>,
    hub: Arc<ReadinessHub>,
}
impl EpollInstance {
    pub fn new(hub: Arc<ReadinessHub>) -> Self {
        Self {
            state: Mutex::default(),
            hub,
        }
    }
    fn identity(file: &Arc<dyn FileHandle>) -> usize {
        Arc::as_ptr(file) as *const () as usize
    }
    fn reaches(&self, target: usize, seen: &mut HashSet<usize>) -> bool {
        let identity = self as *const Self as usize;
        if identity == target {
            return true;
        }
        if !seen.insert(identity) {
            return false;
        }
        let children: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .interests
            .values()
            .filter_map(|i| i.file.upgrade())
            .collect();
        children.iter().any(|f| {
            f.as_any()
                .and_then(|a| a.downcast_ref::<Self>())
                .is_some_and(|e| e.reaches(target, seen))
        })
    }
    pub fn control(
        &self,
        op: u64,
        fd: u32,
        file: Arc<dyn FileHandle>,
        events: u32,
        data: u64,
    ) -> Result<(), Errno> {
        let _graph = self
            .hub
            .graph
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !matches!(op, 1..=3) {
            return Err(Errno::EINVAL);
        }
        let identity = Self::identity(&file);
        if identity == self as *const Self as usize {
            return Err(Errno::EINVAL);
        }
        if op != 2 {
            file.readiness()?;
            if file
                .as_any()
                .and_then(|a| a.downcast_ref::<Self>())
                .is_some_and(|e| e.reaches(self as *const Self as usize, &mut HashSet::new()))
            {
                return Err(Errno(40));
            }
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.interests.retain(|_, i| i.file.strong_count() != 0);
        let key = (fd, identity);
        match op {
            1 if state.interests.contains_key(&key) => return Err(Errno::EEXIST),
            2 => {
                state.interests.remove(&key).ok_or(Errno::ENOENT)?;
            }
            3 if !state.interests.contains_key(&key) => return Err(Errno::ENOENT),
            _ => {
                // Linux's `ep_insert` and `ep_modify` poll the file once,
                // and list it if it is ready.
                let (mask, input, output) = file.readiness()?;
                if events & OUT != 0 && mask & OUT == 0 {
                    crate::sockets::polled_full(&file);
                }
                let listed = mask & (events | 0x18) & !(ET | ONESHOT) != 0;
                state.interests.insert(
                    key,
                    Interest {
                        file: Arc::downgrade(&file),
                        events,
                        data,
                        input_epoch: 0,
                        output_epoch: 0,
                        previous: 0,
                        enabled: true,
                        listed,
                        seen: (input, output),
                    },
                );
            }
        }
        self.hub.changed();
        Ok(())
    }
    pub fn collect(&self, max: usize) -> Vec<(u32, u64)> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.interests.retain(|_, i| i.file.strong_count() != 0);
        let keys: Vec<_> = state.interests.keys().copied().collect();
        let mut out = Vec::new();
        if keys.is_empty() {
            return out;
        }
        let start = state.cursor % keys.len();
        for offset in 0..keys.len() {
            let index = (start + offset) % keys.len();
            let Some(i) = state.interests.get_mut(&keys[index]) else {
                continue;
            };
            // Linux's `ep_send_events` polls only what its ready list
            // holds; one asked to take a write that cannot is noted as full
            // (`polled_full`), so that a read frees room with POLL_OUT.
            if let Some(file) = i.file.upgrade()
                && let Ok((mask, input, output)) = file.readiness()
            {
                let woken = (input, output) != i.seen;
                i.seen = (input, output);
                if (i.listed || woken) && i.enabled && i.events & OUT != 0 && mask & OUT == 0 {
                    crate::sockets::polled_full(&file);
                }
                i.listed = false;
            }
            if let Some((mask, input, output)) = i.ready() {
                // A level-triggered report goes back on the list.
                i.listed = i.events & (ET | ONESHOT) == 0;
                out.push((mask, i.data));
                i.previous = mask;
                i.input_epoch = input;
                i.output_epoch = output;
                if i.events & ONESHOT != 0 {
                    i.enabled = false;
                }
                state.cursor = index + 1;
                if out.len() == max {
                    break;
                }
            }
        }
        out
    }
}
impl FileHandle for EpollInstance {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Ok((
            u32::from(state.interests.values().any(|i| i.ready().is_some())) * IN,
            u64::from(self.hub.token.value()) + 1,
            0,
        ))
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
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
        2
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}
/// An `epoll_event` as x86-64 packs it: the events, then the data.
pub(crate) fn event_from(bytes: &[u8; 12]) -> (u32, u64) {
    let (events, data) = bytes.split_at(4);
    (
        u32::from_le_bytes(events.try_into().unwrap_or_default()),
        u64::from_le_bytes(data.try_into().unwrap_or_default()),
    )
}

/// `epoll_ctl(epfd, op, fd, event)`: the epoll descriptor, then the target,
/// as `fdget` takes them (`EBADF` for `O_PATH`), then the event unless `op`
/// is `EPOLL_CTL_DEL`. io_uring's `IORING_OP_EPOLL_CTL` read its event
/// already, so its `event` gives what it read.
pub(crate) fn control(
    c: &mut Context<'_>,
    epfd: u64,
    op: u64,
    fd: u64,
    event: impl FnOnce(&Context<'_>) -> Result<(u32, u64), Errno>,
) -> Result<(), Errno> {
    let d = c.files.descriptor(epfd)?;
    if d.file.flags() & O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    let epoll = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<EpollInstance>())
        .ok_or(Errno::EINVAL)?;
    let target = c.files.descriptor(fd)?;
    if target.file.flags() & O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    let (events, data) = if op == 2 { (0, 0) } else { event(c)? };
    epoll.control(op, fd as u32, target.file, events, data)
}

pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| {
        let number = c.number;
        if number == 213 || number == 291 {
            if (number == 213 && a[0] as i32 <= 0) || (number == 291 && a[0] & !0x80000 != 0) {
                return Err(Errno::EINVAL);
            }
            return c
                .files
                .install(
                    Arc::new(EpollInstance::new(Arc::clone(&c.files.readiness))),
                    number == 291 && a[0] & 0x80000 != 0,
                    c.group.nofile(),
                )
                .map(u64::from);
        }
        if number == 233 {
            let at = a[3];
            control(c, a[0], a[1], a[2], |c| {
                let mut bytes = [0; 12];
                c.mem
                    .read(GuestAddr(at), &mut bytes)
                    .map_err(|_| Errno::EFAULT)?;
                Ok(event_from(&bytes))
            })?;
            return Ok(0);
        }
        // The order of the kernels after 6.12 (CI's native one): epoll_pwait2
        // reads and checks its timeout, the signal mask is set, then the
        // descriptor (EBADF, `CLASS(fd, f)`) and maxevents are checked, and
        // last that it is an epoll (`do_epoll_pwait`, `do_epoll_wait`,
        // `ep_check_params`). 6.12 itself checked maxevents before the
        // descriptor. The deadline is taken at entry.
        let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
        let deadline = if number == 441 {
            if a[3] == 0 {
                None
            } else {
                let [seconds, nanos] = crate::syscalls::read_words::<2>(c.mem, a[3])?;
                // `timespec64_valid`, then `timespec64_add_safe`, which
                // saturates.
                if (seconds as i64) < 0 || nanos >= 1_000_000_000 {
                    return Err(Errno::EINVAL);
                }
                Some(
                    now.saturating_add(seconds.saturating_mul(1_000_000_000).saturating_add(nanos)),
                )
            }
        } else {
            let timeout = a[3] as i32;
            (timeout >= 0).then(|| now.saturating_add(timeout as u64 * 1_000_000))
        };
        let old_mask = c.process.signal_mask;
        let masked = number != 232 && a[4] != 0;
        if masked {
            if a[5] != 8 {
                return Err(Errno::EINVAL);
            }
            c.process.signal_mask = c.mem.read_u64(GuestAddr(a[4])).map_err(|_| Errno::EFAULT)?
                & !((1 << 8) | (1 << 18));
        }
        let result = (|| {
            // The epoll descriptor too, as `fdget` takes it (EBADF for `O_PATH`).
            let d = c.files.descriptor(a[0])?;
            if d.file.flags() & O_PATH != 0 {
                return Err(Errno::EBADF);
            }
            let max = a[2] as i32;
            if max <= 0 || max > i32::MAX / 12 {
                return Err(Errno::EINVAL);
            }
            let epoll = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<EpollInstance>())
                .ok_or(Errno::EINVAL)?;
            loop {
                let ticket = c.files.readiness.token.value();
                // Validate before consuming ET/ONESHOT state.
                c.mem
                    .check_write(GuestAddr(a[1]), max as usize * 12)
                    .map_err(|_| Errno::EFAULT)?;
                let events = epoll.collect(max as usize);
                if !events.is_empty() {
                    let mut bytes = Vec::with_capacity(events.len() * 12);
                    for (mask, data) in &events {
                        bytes.extend_from_slice(&mask.to_le_bytes());
                        bytes.extend_from_slice(&data.to_le_bytes());
                    }
                    c.mem
                        .write(GuestAddr(a[1]), &bytes)
                        .map_err(|_| Errno::EFAULT)?;
                    return Ok(events.len() as u64);
                }
                if deadline.is_some_and(|end| {
                    c.host
                        .clock(paludarium_host::ClockId::Monotonic)
                        .is_ok_and(|now| now >= end)
                }) {
                    return Ok(0);
                }
                crate::events::wait(c, ticket, deadline)?;
            }
        })();
        if masked
            && result == Err(Errno(4))
            && crate::signals::next_pending(c.process, true).is_some()
        {
            // Defer original-mask restoration until the eligible signal is
            // installed at the syscall checkpoint. Its frame saves old_mask.
            c.process.wait_restore_mask = Some(old_mask);
        } else {
            c.process.signal_mask = old_mask;
        }
        result
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}
#[cfg(test)]
mod events_tests {
    use super::*;
    use crate::events::EventCounter;
    fn setup() -> (EpollInstance, Arc<dyn FileHandle>) {
        let hub = Arc::default();
        (
            EpollInstance::new(Arc::clone(&hub)),
            Arc::new(EventCounter::new(0, 0, hub).unwrap()),
        )
    }
    #[test]
    fn events_epoll_lt() {
        let (e, f) = setup();
        e.control(1, 3, Arc::clone(&f), IN, 7).unwrap();
        f.write(&1u64.to_le_bytes()).unwrap();
        assert_eq!(e.collect(1), vec![(IN, 7)]);
        assert_eq!(e.collect(1), vec![(IN, 7)]);
    }
    #[test]
    fn events_epoll_et() {
        let (e, f) = setup();
        e.control(1, 3, Arc::clone(&f), IN | ET, 7).unwrap();
        f.write(&1u64.to_le_bytes()).unwrap();
        assert_eq!(e.collect(1).len(), 1);
        assert!(e.collect(1).is_empty());
        f.read(&mut [0; 8]).unwrap();
        f.write(&1u64.to_le_bytes()).unwrap();
        assert_eq!(e.collect(1).len(), 1);
    }
    #[test]
    fn epoll_event_output_read_callback() {
        let hub = Arc::default();
        let e = EpollInstance::new(Arc::clone(&hub));
        let f: Arc<dyn FileHandle> = Arc::new(EventCounter::new(2, 1, hub).unwrap());
        e.control(1, 3, Arc::clone(&f), OUT | ET, 79).unwrap();
        assert_eq!(e.collect(1), vec![(OUT, 79)]);
        f.read(&mut [0; 8]).unwrap();
        assert_eq!(e.collect(1), vec![(OUT, 79)]);
        assert!(e.collect(1).is_empty());
    }
    #[test]
    fn epoll_socket_output_consumed_write_callbacks() {
        let hub = Arc::default();
        let e = EpollInstance::new(Arc::clone(&hub));
        let [writer, reader] = crate::sockets::SocketPairEnd::pair(0x801, hub).unwrap();
        e.control(1, 3, writer.clone(), OUT | ET, 81).unwrap();
        assert_eq!(e.collect(1), vec![(OUT, 81)]);
        writer.write(b"abc").unwrap();
        writer.write(b"de").unwrap();
        assert!(e.collect(1).is_empty());
        reader.read(&mut [0; 3]).unwrap();
        assert_eq!(e.collect(1), vec![(OUT, 81)]);
        assert!(e.collect(1).is_empty());
        reader.read(&mut [0; 1]).unwrap();
        assert!(e.collect(1).is_empty());
        reader.read(&mut [0; 1]).unwrap();
        assert_eq!(e.collect(1), vec![(OUT, 81)]);
    }
    #[test]
    fn events_epoll_oneshot() {
        let (e, f) = setup();
        f.write(&1u64.to_le_bytes()).unwrap();
        e.control(1, 3, Arc::clone(&f), IN | ONESHOT, 1).unwrap();
        assert_eq!(e.collect(1).len(), 1);
        assert!(e.collect(1).is_empty());
        e.control(3, 3, Arc::clone(&f), IN | ONESHOT, 2).unwrap();
        assert_eq!(e.collect(1), vec![(IN, 2)]);
    }
    #[test]
    fn epoll_errors() {
        let (e, f) = setup();
        assert_eq!(e.control(3, 3, Arc::clone(&f), IN, 0), Err(Errno::ENOENT));
        e.control(1, 3, Arc::clone(&f), IN, 0).unwrap();
        assert_eq!(e.control(1, 3, Arc::clone(&f), IN, 0), Err(Errno::EEXIST));
        assert_eq!(e.control(4, 3, f, 0, 0), Err(Errno::EINVAL));
    }
    #[test]
    fn epoll_delete() {
        let (e, f) = setup();
        e.control(1, 3, Arc::clone(&f), IN, 0).unwrap();
        e.control(2, 3, Arc::clone(&f), 0, 0).unwrap();
        f.write(&1u64.to_le_bytes()).unwrap();
        assert!(e.collect(1).is_empty());
    }
    #[test]
    fn epoll_last_close() {
        let (e, f) = setup();
        f.write(&1u64.to_le_bytes()).unwrap();
        e.control(1, 3, Arc::clone(&f), IN, 0).unwrap();
        drop(f);
        assert!(e.collect(1).is_empty());
    }
    #[test]
    fn epoll_dup_entries() {
        let (e, f) = setup();
        f.write(&1u64.to_le_bytes()).unwrap();
        e.control(1, 3, Arc::clone(&f), IN, 1).unwrap();
        e.control(1, 4, Arc::clone(&f), IN, 2).unwrap();
        assert_eq!(e.collect(2), vec![(IN, 1), (IN, 2)]);
    }
    #[test]
    fn events_epoll_fairness() {
        let (e, f) = setup();
        f.write(&1u64.to_le_bytes()).unwrap();
        e.control(1, 3, Arc::clone(&f), IN, 1).unwrap();
        e.control(1, 4, Arc::clone(&f), IN, 2).unwrap();
        assert_eq!(e.collect(1), vec![(IN, 1)]);
        assert_eq!(e.collect(1), vec![(IN, 2)]);
    }
}
