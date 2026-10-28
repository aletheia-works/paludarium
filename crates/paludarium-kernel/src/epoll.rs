//! Kernel epoll interests use (descriptor number, open-description identity).
//! Weak description references do not prolong a guest's last open descriptor.
use crate::events::{IN, OUT, ReadinessHub};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};

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
                // Linux's `ep_insert` and `ep_modify` poll the file once.
                if events & OUT != 0 && file.readiness().is_ok_and(|(mask, ..)| mask & OUT == 0) {
                    crate::sockets::polled_full(&file);
                }
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
            if let Some((mask, input, output)) = i.ready() {
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
pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| {
        let number = c.cpu.gpr[paludarium_cpu::reg::RAX];
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
        let d = c.files.descriptor(a[0])?;
        let epoll = d
            .file
            .as_any()
            .and_then(|v| v.downcast_ref::<EpollInstance>())
            .ok_or(Errno::EINVAL)?;
        if number == 233 {
            let target = c.files.descriptor(a[2])?;
            let (events, data) = if a[1] == 2 {
                (0, 0)
            } else {
                let mut bytes = [0; 12];
                c.mem
                    .read(GuestAddr(a[3]), &mut bytes)
                    .map_err(|_| Errno::EFAULT)?;
                (
                    u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Errno::EFAULT)?),
                    u64::from_le_bytes(bytes[4..].try_into().map_err(|_| Errno::EFAULT)?),
                )
            };
            epoll.control(a[1], a[2] as u32, target.file, events, data)?;
            return Ok(0);
        }
        let max = a[2] as i32;
        if max <= 0 || max > i32::MAX / 12 {
            return Err(Errno::EINVAL);
        }
        let old_mask = c.process.signal_mask;
        if number == 281 && a[4] != 0 {
            if a[5] != 8 {
                return Err(Errno::EINVAL);
            }
            c.process.signal_mask = c.mem.read_u64(GuestAddr(a[4])).map_err(|_| Errno::EFAULT)?
                & !((1 << 8) | (1 << 18));
        }
        let result = (|| {
            let timeout = a[3] as i32;
            let deadline = if timeout < 0 {
                None
            } else {
                Some(
                    c.host
                        .clock(paludarium_host::ClockId::Monotonic)?
                        .saturating_add(timeout as u64 * 1_000_000),
                )
            };
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
        if number == 281
            && a[4] != 0
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
