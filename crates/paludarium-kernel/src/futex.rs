//! Compare/register and wake share a queue lock; MMU is always acquired second.
use paludarium_host::WaitToken;
use paludarium_mmu::{AddressSpace, AtomicOp, AtomicWidth};
use paludarium_types::{Errno, GuestAddr};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, LazyLock, Mutex, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
};
/// What a futex word is told apart by, as Linux's `futex_key`: a word in
/// shared memory by that memory and its offset in it, so that every process
/// mapping it finds the same queue; any other by the address space and the
/// address, with private and shared operations apart.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Space {
        space: u64,
        addr: u64,
        private: bool,
    },
    Memory {
        memory: u64,
        offset: u64,
    },
}
fn key(mem: &AddressSpace, addr: u64, private: bool) -> Key {
    if !private && let Some((memory, offset)) = mem.shared_offset(GuestAddr(addr)) {
        return Key::Memory { memory, offset };
    }
    Key::Space {
        space: mem.id(),
        addr,
        private,
    }
}
/// The queues every process waits in: the keys of words in shared memory
/// are the same in every process, and the others name their address space.
static MACHINE: LazyLock<Futexes> = LazyLock::new(Futexes::default);
pub(crate) struct Waiter {
    pub token: WaitToken,
    pub state: AtomicU32,
    mask: u32,
    /// The queue it waits in.
    key: Key,
}
#[derive(Default, Clone)]
pub(crate) struct Futexes {
    queues: Arc<Mutex<BTreeMap<Key, Vec<Arc<Waiter>>>>>,
}
impl Futexes {
    /// The queues shared by every process ([`MACHINE`]).
    pub fn machine() -> Self {
        MACHINE.clone()
    }
    pub fn register(
        &self,
        mem: &AddressSpace,
        addr: u64,
        private: bool,
        value: u32,
        mask: u32,
    ) -> Result<Arc<Waiter>, Errno> {
        if addr & 3 != 0 || mask == 0 {
            return Err(Errno::EINVAL);
        }
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        let key = key(mem, addr, private);
        let mut bytes = [0; 4];
        mem.read(GuestAddr(addr), &mut bytes)
            .map_err(|_| Errno::EFAULT)?;
        if u32::from_le_bytes(bytes) != value {
            return Err(Errno::EAGAIN);
        }
        let waiter = Arc::new(Waiter {
            token: WaitToken::default(),
            state: AtomicU32::new(0),
            mask,
            key,
        });
        queues.entry(key).or_default().push(waiter.clone());
        Ok(waiter)
    }
    pub fn finish(&self, waiter: &Arc<Waiter>, result: u32) -> u32 {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        if waiter.state.load(Ordering::SeqCst) == 0 {
            waiter.state.store(result, Ordering::SeqCst);
            if let Some(queue) = queues.get_mut(&waiter.key) {
                queue.retain(|w| !Arc::ptr_eq(w, waiter));
                if queue.is_empty() {
                    queues.remove(&waiter.key);
                }
            }
        }
        waiter.state.load(Ordering::SeqCst)
    }
    pub fn wake(
        &self,
        mem: &AddressSpace,
        addr: u64,
        private: bool,
        count: u32,
        mask: u32,
    ) -> Result<u64, Errno> {
        if addr & 3 != 0 || mask == 0 {
            return Err(Errno::EINVAL);
        }
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        // Validate before consulting queues, including when no waiter exists.
        mem.check_read(GuestAddr(addr), 4)
            .map_err(|_| Errno::EFAULT)?;
        let key = key(mem, addr, private);
        let mut woke = 0;
        if let Some(queue) = queues.get_mut(&key) {
            queue.retain(|waiter| {
                if woke < count && waiter.mask & mask != 0 {
                    waiter.state.store(1, Ordering::SeqCst);
                    waiter.token.notify();
                    woke += 1;
                    false
                } else {
                    true
                }
            });
            if queue.is_empty() {
                queues.remove(&key);
            }
        }
        Ok(u64::from(woke))
    }
}

/// `struct robust_list_head`'s size, the only length `set_robust_list` takes.
pub(crate) const ROBUST_LIST_HEAD: u64 = 24;
/// How many entries Linux follows, so that a list made into a ring ends.
const ROBUST_LIST_LIMIT: u32 = 2048;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

/// An entry of a robust list and whether its low bit marks a PI futex.
fn robust_entry(mem: &AddressSpace, at: u64) -> Option<(u64, bool)> {
    let value = mem.read_u64(GuestAddr(at)).ok()?;
    Some((value & !1, value & 1 != 0))
}

/// Marks the robust futex at `addr` as Linux's `handle_futex_death` does when
/// its owner `tid` ends: `None` when the word cannot be used, which ends the
/// walk. The wake is shared, as Linux's, so a private waiter is not woken.
fn futex_death(
    futexes: &Futexes,
    mem: &AddressSpace,
    addr: u64,
    tid: u32,
    pi: bool,
    pending: bool,
) -> Option<()> {
    if addr & 3 != 0 {
        return None;
    }
    loop {
        let mut word = [0; 4];
        mem.read(GuestAddr(addr), &mut word).ok()?;
        let value = u32::from_le_bytes(word);
        // The owner had released it and died before it woke the next.
        if pending && !pi && value == 0 {
            let _ = futexes.wake(mem, addr, false, 1, u32::MAX);
            return Some(());
        }
        if value & FUTEX_TID_MASK != tid {
            return Some(());
        }
        let result = mem
            .atomic(
                GuestAddr(addr),
                AtomicWidth::W32,
                AtomicOp::CompareExchange {
                    expected: u128::from(value),
                    replacement: u128::from(value & FUTEX_WAITERS | FUTEX_OWNER_DIED),
                },
            )
            .ok()?;
        if result.exchanged {
            if !pi && value & FUTEX_WAITERS != 0 {
                let _ = futexes.wake(mem, addr, false, 1, u32::MAX);
            }
            return Some(());
        }
    }
}

/// Walks the robust list at `head` of the ending thread `tid`, as Linux's
/// `exit_robust_list`: anything unreadable ends the walk where it is.
pub(crate) fn exit_robust_list(futexes: &Futexes, mem: &AddressSpace, tid: u32, head: u64) {
    let Some((mut entry, mut pi)) = robust_entry(mem, head) else {
        return;
    };
    let Ok(offset) = mem.read_u64(GuestAddr(head.wrapping_add(8))) else {
        return;
    };
    let Some((pending, pending_pi)) = robust_entry(mem, head.wrapping_add(16)) else {
        return;
    };
    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head {
        let next = robust_entry(mem, entry);
        if entry != pending
            && futex_death(futexes, mem, entry.wrapping_add(offset), tid, pi, false).is_none()
        {
            return;
        }
        let Some((following, following_pi)) = next else {
            return;
        };
        entry = following;
        pi = following_pi;
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    if pending != 0 {
        let _ = futex_death(
            futexes,
            mem,
            pending.wrapping_add(offset),
            tid,
            pending_pi,
            true,
        );
    }
}
