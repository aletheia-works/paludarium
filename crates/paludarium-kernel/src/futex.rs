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
    /// What wakes the thread; every word of one `futex_waitv` shares it.
    pub token: Arc<WaitToken>,
    pub state: AtomicU32,
    mask: u32,
    /// The queue it waits in, which a requeue changes; read and written
    /// only under the queues' lock.
    key: Mutex<Key>,
}
impl Waiter {
    fn key(&self) -> Key {
        *self.key.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
/// One futex word to wait on: where, whether its key is the process's own
/// (`FUTEX_PRIVATE_FLAG`), whether it is followed by a NUMA node word
/// (`FUTEX2_NUMA`), the value it must hold, and the bits a wake must share.
#[derive(Clone, Copy)]
pub(crate) struct Word {
    pub addr: u64,
    pub private: bool,
    pub numa: bool,
    pub value: u32,
    pub mask: u32,
}
/// Linux's `TASK_SIZE_MAX`, where `access_ok` stops.
const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;
/// `FUTEX_NO_NODE`, a node word that asks for the thread's own node.
const NO_NODE: u32 = u32::MAX;
/// The key of the futex word at `addr`, after Linux's `get_futex_key`
/// checks in its order: the word is aligned to its size, doubled by a node
/// word (`EINVAL`), and lies below `TASK_SIZE_MAX` (`EFAULT`); a node word
/// names node 0, the only one here, or none, which becomes node 0 (`EINVAL`,
/// and `EFAULT` when it cannot be read or written); and a shared word's page
/// is there (`EFAULT`), where a private one's is not looked at.
fn checked_key(mem: &AddressSpace, addr: u64, private: bool, numa: bool) -> Result<Key, Errno> {
    let size = if numa { 8 } else { 4 };
    if !addr.is_multiple_of(size) {
        return Err(Errno::EINVAL);
    }
    if addr.checked_add(size).is_none_or(|end| end > TASK_SIZE_MAX) {
        return Err(Errno::EFAULT);
    }
    if numa {
        let at = GuestAddr(addr + 4);
        let mut node = [0; 4];
        mem.read(at, &mut node).map_err(|_| Errno::EFAULT)?;
        match u32::from_le_bytes(node) {
            0 => {}
            NO_NODE => mem
                .write(at, &0u32.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?,
            _ => return Err(Errno::EINVAL),
        }
    }
    if !private {
        mem.check_read(GuestAddr(addr), 4)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(key(mem, addr, private))
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
        if mask == 0 {
            return Err(Errno::EINVAL);
        }
        let word = Word {
            addr,
            private,
            numa: false,
            value,
            mask,
        };
        let mut waiters = self.register_all(mem, &[word])?;
        Ok(waiters.remove(0))
    }
    /// Queues a waiter on each of `words`, which then share one token, as
    /// Linux's `futex_wait_multiple_setup` does: every key is checked first
    /// ([`checked_key`]), then each word is compared in turn, `EFAULT` when
    /// it cannot be read and `EAGAIN` when it differs, which takes the
    /// waiters queued before it away again. They go in under one hold of the
    /// queues, so no wake comes between them.
    pub fn register_all(
        &self,
        mem: &AddressSpace,
        words: &[Word],
    ) -> Result<Vec<Arc<Waiter>>, Errno> {
        let keys = words
            .iter()
            .map(|w| checked_key(mem, w.addr, w.private, w.numa))
            .collect::<Result<Vec<_>, _>>()?;
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        for word in words {
            let mut bytes = [0; 4];
            mem.read(GuestAddr(word.addr), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            if u32::from_le_bytes(bytes) != word.value {
                return Err(Errno::EAGAIN);
            }
        }
        let token = Arc::new(WaitToken::default());
        let waiters = words
            .iter()
            .zip(keys)
            .map(|(word, key)| {
                let waiter = Arc::new(Waiter {
                    token: Arc::clone(&token),
                    state: AtomicU32::new(0),
                    mask: word.mask,
                    key: Mutex::new(key),
                });
                queues.entry(key).or_default().push(waiter.clone());
                waiter
            })
            .collect();
        Ok(waiters)
    }
    pub fn finish(&self, waiter: &Arc<Waiter>, result: u32) -> u32 {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        if waiter.state.load(Ordering::SeqCst) == 0 {
            waiter.state.store(result, Ordering::SeqCst);
            let key = waiter.key();
            if let Some(queue) = queues.get_mut(&key) {
                queue.retain(|w| !Arc::ptr_eq(w, waiter));
                if queue.is_empty() {
                    queues.remove(&key);
                }
            }
        }
        waiter.state.load(Ordering::SeqCst)
    }
    /// Wakes up to `count` waiters of the word at `addr` whose bits meet
    /// `mask`, as Linux's `futex_wake`: `EINVAL` for no bits, then
    /// [`checked_key`]'s checks. One is woken even for a count that is not
    /// positive (Linux counts a wake before it compares), but a `strict`
    /// one (futex2's `FLAGS_STRICT`) of 0 wakes none.
    #[allow(clippy::too_many_arguments)]
    pub fn wake_word(
        &self,
        mem: &AddressSpace,
        addr: u64,
        private: bool,
        numa: bool,
        count: i32,
        mask: u32,
        strict: bool,
    ) -> Result<u64, Errno> {
        if mask == 0 {
            return Err(Errno::EINVAL);
        }
        let key = checked_key(mem, addr, private, numa)?;
        if strict && count == 0 {
            return Ok(0);
        }
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        let mut woke = 0i32;
        let mut done = false;
        if let Some(queue) = queues.get_mut(&key) {
            queue.retain(|waiter| {
                if !done && waiter.mask & mask != 0 {
                    waiter.state.store(1, Ordering::SeqCst);
                    waiter.token.notify();
                    woke += 1;
                    done = woke >= count;
                    false
                } else {
                    true
                }
            });
            if queue.is_empty() {
                queues.remove(&key);
            }
        }
        Ok(woke as u64)
    }
    /// Wakes up to `wake` waiters of the word `from` and moves up to
    /// `requeue` more to the queue of the word `to`, giving how many it took,
    /// as Linux's `futex_requeue` without PI: `EINVAL` for a negative count,
    /// then each word's [`checked_key`], then, with `compare`, `from`'s value
    /// (`EFAULT`, and `EAGAIN` when it differs). Waiters are taken in the
    /// order they came, whatever their bits, and a moved one keeps its own
    /// and comes after those already waiting at `to`, as `requeue_futex`
    /// puts it at the end of the list. Onto its own word a waiter stays where
    /// it is, as Linux leaves one within its bucket, and is counted once.
    pub fn requeue(
        &self,
        mem: &AddressSpace,
        from: (u64, bool, bool),
        to: (u64, bool, bool),
        wake: i32,
        requeue: i32,
        compare: Option<u32>,
    ) -> Result<u64, Errno> {
        if wake < 0 || requeue < 0 {
            return Err(Errno::EINVAL);
        }
        let first = checked_key(mem, from.0, from.1, from.2)?;
        let second = checked_key(mem, to.0, to.1, to.2)?;
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(value) = compare {
            let mut bytes = [0; 4];
            mem.read(GuestAddr(from.0), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            if u32::from_le_bytes(bytes) != value {
                return Err(Errno::EAGAIN);
            }
        }
        let Some(queue) = queues.remove(&first) else {
            return Ok(0);
        };
        let (wake, requeue) = (i64::from(wake), i64::from(requeue));
        let mut taken = 0i64;
        let (mut kept, mut moved) = (Vec::new(), Vec::new());
        for waiter in queue {
            if taken - wake >= requeue {
                kept.push(waiter);
                continue;
            }
            taken += 1;
            if taken <= wake {
                waiter.state.store(1, Ordering::SeqCst);
                waiter.token.notify();
            } else if first == second {
                // `requeue_futex` leaves a waiter in place in its own bucket.
                kept.push(waiter);
            } else {
                *waiter.key.lock().unwrap_or_else(PoisonError::into_inner) = second;
                moved.push(waiter);
            }
        }
        if !kept.is_empty() {
            queues.insert(first, kept);
        }
        if !moved.is_empty() {
            queues.entry(second).or_default().extend(moved);
        }
        Ok(taken as u64)
    }
    /// [`Self::wake_word`] of a word without a node word, as the old
    /// `futex` calls wake one.
    pub fn wake(
        &self,
        mem: &AddressSpace,
        addr: u64,
        private: bool,
        count: i32,
        mask: u32,
    ) -> Result<u64, Errno> {
        self.wake_word(mem, addr, private, false, count, mask, false)
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
