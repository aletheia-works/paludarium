//! Restartable sequences (`rseq`), and the virtual CPUs that the threads
//! which register one run on.
//!
//! A critical section of `rseq` counts on no other thread running on its CPU
//! before it commits: Linux aborts it when its thread is preempted, migrated
//! or sent a signal. Emulated threads run truly in parallel on the host, so a
//! thread that has registered `rseq` runs on one of [`Cpus`]' virtual CPUs,
//! one for each CPU the machine reports, where no other such thread runs at
//! the same time. It takes one before it runs guest code
//! ([`Kernel::enter_cpu`]) and leaves it at every stop of the guest code (a
//! system call, a fault, the end of its budget), so that a thread waiting in
//! a system call holds none. Taking back the same CPU with no other thread
//! having run on it since means its critical section goes on, as on a Linux
//! that did not preempt it. Taking another, or the same one after another
//! thread had it, aborts the section, as a migration or a preemption does.
//! While threads wait for a CPU, one that has had its own for a time slice
//! lets them have it first, as Linux's scheduler preempts it.
//!
//! A thread that has not registered `rseq` runs as before, on no virtual CPU.
use crate::syscalls::{Context, Outcome, err, ok};
use crate::{Kernel, Next, Thread, signals};
use paludarium_host::{ClockId, Host, WaitToken};
// `AT_RSEQ_FEATURE_SIZE` and `AT_RSEQ_ALIGN`, which the loader gives the
// program: the fields this kernel keeps up to date (`cpu_id_start` to
// `mm_cid`), and the alignment of an area longer than the original.
use paludarium_loader::auxv::{RSEQ_ALIGN as ALIGNMENT, RSEQ_FEATURE_SIZE as FEATURE_SIZE};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr, USER_ADDRESS_LIMIT};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

/// The size of Linux's original `struct rseq`, and its alignment.
const ORIGINAL_SIZE: u32 = 32;
/// `RSEQ_FLAG_UNREGISTER`.
const UNREGISTER: u32 = 1;
/// `RSEQ_CPU_ID_UNINITIALIZED`, the `cpu_id` of an area no longer registered.
const UNINITIALIZED: u32 = u32::MAX;
/// x86-64's `TASK_SIZE_MAX` with four-level page tables: the end of the
/// addresses that user space has.
const TASK_SIZE: u64 = USER_ADDRESS_LIMIT - 4096;
/// How long a thread keeps its CPU while others wait for one, in
/// nanoseconds: about Linux's base slice.
const SLICE: u64 = 4_000_000;
/// The bit of a CPU's word ([`Cpus::slots`]) that says its thread runs
/// guest code on it now.
const RUNNING: u64 = 1 << 32;
/// No CPU, or no concurrency ID.
const NONE: u32 = u32::MAX;

/// A thread's `rseq` area, as Linux's `task_struct.rseq` and the length and
/// signature it was registered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Registration {
    pub address: u64,
    pub length: u32,
    pub signature: u32,
}

/// The virtual CPU a thread with `rseq` last ran on, the concurrency ID
/// (`mm_cid`) it had there, and which [`Runner`] it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OnCpu {
    pub cpu: u32,
    pub cid: u32,
    pub runner: u32,
}

/// The machine's virtual CPUs, which the threads that have registered
/// `rseq` run on, one at a time on each.
#[derive(Default)]
pub(crate) struct Cpus {
    /// One word for each CPU: the [`Runner`] that last ran on it (0 for
    /// none), with [`RUNNING`] while it runs guest code there. Only that
    /// runner changes a word with [`RUNNING`]; any runner may take a word
    /// without it.
    slots: OnceLock<Box<[AtomicU64]>>,
    /// How many threads wait: for a CPU, or for others to leave theirs.
    waiting: AtomicU32,
    /// Notified, while some thread waits, when a CPU is left or taken.
    changed: WaitToken,
    next: AtomicU32,
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    runners: BTreeMap<u32, Weak<Runner>>,
    /// The concurrency ID each runner has, and its address space: kept
    /// here rather than with the runner, so that the ID of one that is
    /// going away goes with its CPU too.
    holders: BTreeMap<u32, (usize, u32)>,
    /// The concurrency IDs given out in each address space.
    cids: BTreeMap<usize, BTreeSet<u32>>,
}

impl Table {
    /// Gives `runner` the lowest concurrency ID no other thread of `space`
    /// has, as Linux gives the lowest one free.
    fn allocate(&mut self, runner: u32, space: usize) -> u32 {
        let used = self.cids.entry(space).or_default();
        let cid = (0..).find(|cid| !used.contains(cid)).unwrap_or(0);
        used.insert(cid);
        self.holders.insert(runner, (space, cid));
        cid
    }

    /// Takes back the concurrency ID of `runner`, if it has one.
    fn free(&mut self, runner: u32) {
        let Some((space, cid)) = self.holders.remove(&runner) else {
            return;
        };
        if let Some(used) = self.cids.get_mut(&space) {
            used.remove(&cid);
            if used.is_empty() {
                self.cids.remove(&space);
            }
        }
    }
}

impl Cpus {
    fn slots(&self, host: &dyn Host) -> &[AtomicU64] {
        self.slots.get_or_init(|| {
            (0..host.cpu_count().clamp(1, 8192))
                .map(|_| AtomicU64::new(0))
                .collect()
        })
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self) {
        if self.waiting.load(Ordering::SeqCst) != 0 {
            self.changed.notify();
        }
    }

    /// A new runner for a thread of the address space `space`.
    fn runner(self: &Arc<Self>, space: usize) -> Arc<Runner> {
        let id = loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            if id != 0 && id != NONE && !self.table().runners.contains_key(&id) {
                break id;
            }
        };
        let runner = Arc::new(Runner {
            id,
            space,
            cpus: Arc::clone(self),
            cpu: AtomicU32::new(NONE),
            cid: AtomicU32::new(NONE),
            running: AtomicBool::new(false),
            stints: AtomicU64::new(0),
            requested: AtomicU64::new(0),
            since: AtomicU64::new(0),
        });
        self.table().runners.insert(id, Arc::downgrade(&runner));
        runner
    }

    /// Takes a CPU that `allowed` allows and no thread runs on, a free one
    /// first, for `runner`, and gives it a concurrency ID if it has none.
    fn take(&self, host: &dyn Host, runner: &Runner, allowed: &dyn Fn(usize) -> bool) -> bool {
        let slots = self.slots(host);
        let me = u64::from(runner.id);
        // The runners whose CPU is taken, dropped after the table's lock.
        let mut taken_from = Vec::new();
        let mut table = self.table();
        for free_only in [true, false] {
            for (index, slot) in slots.iter().enumerate() {
                if !allowed(index) {
                    continue;
                }
                let word = slot.load(Ordering::SeqCst);
                if word & RUNNING != 0 || free_only && word != 0 {
                    continue;
                }
                if slot
                    .compare_exchange(word, me | RUNNING, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    continue;
                }
                let previous = word as u32;
                if previous != 0 && previous != runner.id {
                    // The thread that had it gives up its concurrency ID
                    // with it, so that the IDs stay below the CPUs' count,
                    // even when it is going away.
                    table.free(previous);
                    if let Some(other) = table.runners.get(&previous).and_then(Weak::upgrade) {
                        other.cid.store(NONE, Ordering::SeqCst);
                        taken_from.push(other);
                    }
                }
                let old = runner.cpu.swap(index as u32, Ordering::SeqCst);
                if old != NONE
                    && old as usize != index
                    && let Some(slot) = slots.get(old as usize)
                {
                    let _ = slot.compare_exchange(me, 0, Ordering::SeqCst, Ordering::SeqCst);
                }
                if runner.cid.load(Ordering::SeqCst) == NONE {
                    let cid = table.allocate(runner.id, runner.space);
                    runner.cid.store(cid, Ordering::SeqCst);
                }
                runner.running.store(true, Ordering::SeqCst);
                drop(table);
                self.notify();
                return true;
            }
        }
        false
    }
}

/// A thread's place among the [`Cpus`], from when it first runs with `rseq`
/// in an address space to when it stops having it there.
pub(crate) struct Runner {
    id: u32,
    /// The address space it runs in.
    space: usize,
    cpus: Arc<Cpus>,
    /// The CPU it last took, or [`NONE`].
    cpu: AtomicU32,
    /// Its concurrency ID, or [`NONE`] after another thread took its CPU.
    cid: AtomicU32,
    /// It runs guest code now.
    running: AtomicBool,
    /// How many times it has left its CPU.
    stints: AtomicU64,
    /// How many times `membarrier` has asked it to abort its critical
    /// section.
    requested: AtomicU64,
    /// When it last started to keep its CPU from waiting threads, or 0.
    since: AtomicU64,
}

impl Runner {
    /// Leaves its CPU: the thread stops running guest code, and a thread
    /// that waits may take the CPU.
    pub(crate) fn leave(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        let cpu = self.cpu.load(Ordering::SeqCst);
        if let Some(slot) = self.cpus.slots.get().and_then(|s| s.get(cpu as usize)) {
            slot.store(u64::from(self.id), Ordering::SeqCst);
        }
        self.stints.fetch_add(1, Ordering::SeqCst);
        self.cpus.notify();
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let me = u64::from(self.id);
        let mut table = self.cpus.table();
        table.runners.remove(&self.id);
        table.free(self.id);
        let cpu = self.cpu.load(Ordering::SeqCst);
        if let Some(slot) = self.cpus.slots.get().and_then(|s| s.get(cpu as usize)) {
            for word in [me, me | RUNNING] {
                let _ = slot.compare_exchange(word, 0, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
        drop(table);
        self.cpus.notify();
    }
}

/// A [`Kernel`]'s runner, and the CPU mask it last read for its thread.
pub(crate) struct Seat {
    runner: Arc<Runner>,
    /// Shared, so that each entry takes it without copying it.
    mask: Option<Arc<[u64]>>,
    /// The [`crate::ThreadGroup::affinity_generation`] `mask` was read in.
    generation: Option<u64>,
    /// How many `membarrier` requests it has acted on.
    handled: u64,
}

impl Kernel {
    /// Leaves the thread's virtual CPU, as it stops running guest code.
    pub(crate) fn leave_cpu(&self) {
        if let Some(seat) = &self.seat {
            seat.runner.leave();
        }
    }

    /// Puts `thread`, when it has registered `rseq`, on a virtual CPU before
    /// it runs guest code, waiting for one when every CPU its mask allows
    /// runs another thread, and brings its area up to date when it has to:
    /// a new CPU or concurrency ID, a `membarrier` that asked it to, or a
    /// registration. Linux's `rseq_handle_notify_resume` on the way back to
    /// user space. An area it cannot bring up to date sends it `SIGSEGV`.
    pub fn enter_cpu(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        let Some(registration) = thread.state.rseq else {
            self.seat = None;
            thread.state.on_cpu = None;
            return Next::Resume;
        };
        let space = std::ptr::from_ref(mem).addr();
        if self
            .seat
            .as_ref()
            .is_none_or(|seat| seat.runner.space != space)
        {
            self.seat = None;
            self.seat = Some(Seat {
                runner: self.processes.cpus.runner(space),
                mask: None,
                generation: None,
                handled: 0,
            });
        }
        let Some(moved) = self.take_cpu(thread) else {
            // The thread is to end, or the process: the checkpoint says so.
            return self.checkpoint(thread, mem);
        };
        let Some(seat) = self.seat.as_mut() else {
            return Next::Resume;
        };
        let runner = &seat.runner;
        let requested = runner.requested.load(Ordering::SeqCst);
        let restart = moved || requested != seat.handled;
        seat.handled = requested;
        let on = OnCpu {
            cpu: runner.cpu.load(Ordering::SeqCst),
            cid: runner.cid.load(Ordering::SeqCst),
            runner: runner.id,
        };
        thread.state.on_cpu = Some(on);
        if !restart && !std::mem::take(&mut thread.state.rseq_notify) {
            return Next::Resume;
        }
        thread.state.rseq_notify = false;
        let mut rip = thread.cpu.rip.0;
        let result = fixup(mem, &registration, &mut rip, restart)
            .and_then(|()| update(mem, &registration, on));
        thread.cpu.rip = GuestAddr(rip);
        if result.is_err() {
            signals::queue(&mut thread.state, forced_sigsegv());
            let next = self.checkpoint(thread, mem);
            // A thread that stops (or ends) here runs no guest code, so it
            // must not keep the CPU while it waits.
            if next != Next::Resume {
                self.leave_cpu();
            }
            return next;
        }
        Next::Resume
    }

    /// Takes a CPU for the thread: its own when no other thread has run on
    /// it since, and the mask still allows it; another one, or the same
    /// after another thread, is a move (`Some(true)`). `None` when the
    /// thread or its process is to end while it waits.
    fn take_cpu(&mut self, thread: &Thread) -> Option<bool> {
        let generation = self.group.affinity_generation();
        let seat = self.seat.as_mut()?;
        if seat.generation != Some(generation) {
            seat.mask = self.group.affinity(thread.tid).map(Arc::from);
            seat.generation = Some(generation);
        }
        let runner = Arc::clone(&seat.runner);
        if runner.running.load(Ordering::SeqCst) {
            return Some(false);
        }
        let cpus = &self.processes.cpus;
        let count = cpus.slots(&*self.host).len();
        let mask = seat.mask.clone();
        let in_mask = |index: usize| {
            mask.as_ref().is_none_or(|mask| {
                mask.get(index / 64)
                    .is_some_and(|word| word >> (index % 64) & 1 != 0)
            })
        };
        // A mask with none of the machine's CPUs cannot be set; should one
        // be, the thread runs on any.
        let any = !(0..count).any(in_mask);
        let allowed = |index: usize| any || in_mask(index);
        // A thread that has kept its CPU for a slice while others wait lets
        // them have it first.
        if cpus.waiting.load(Ordering::SeqCst) == 0 {
            runner.since.store(0, Ordering::SeqCst);
        } else if let Ok(now) = self.host.clock(ClockId::Monotonic) {
            let since = runner.since.load(Ordering::SeqCst);
            if since == 0 {
                runner.since.store(now, Ordering::SeqCst);
            } else if now.saturating_sub(since) >= SLICE {
                runner.since.store(0, Ordering::SeqCst);
                let seen = cpus.changed.value();
                let _ = self.host.wait_on(
                    &cpus.changed,
                    seen,
                    Some((ClockId::Monotonic, now.saturating_add(SLICE))),
                    &self.cancellation,
                );
            }
        }
        let me = u64::from(runner.id);
        let mine = runner.cpu.load(Ordering::SeqCst);
        let slots = cpus.slots(&*self.host);
        if mine != NONE
            && allowed(mine as usize)
            && runner.cid.load(Ordering::SeqCst) != NONE
            && slots.get(mine as usize).is_some_and(|slot| {
                slot.compare_exchange(me, me | RUNNING, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })
        {
            runner.running.store(true, Ordering::SeqCst);
            return Some(false);
        }
        let mut waiting = false;
        let taken = loop {
            let seen = cpus.changed.value();
            if cpus.take(&*self.host, &runner, &allowed) {
                break true;
            }
            if self.group.status().is_some() || self.group.retired(thread.tid) {
                break false;
            }
            if !waiting {
                // Counted before looking again, so that a CPU left after
                // that look wakes this wait.
                cpus.waiting.fetch_add(1, Ordering::SeqCst);
                waiting = true;
                continue;
            }
            let deadline = self
                .host
                .clock(ClockId::Monotonic)
                .map_or(u64::MAX, |now| now.saturating_add(10_000_000));
            let _ = self.host.wait_on(
                &cpus.changed,
                seen,
                Some((ClockId::Monotonic, deadline)),
                &self.cancellation,
            );
        };
        if waiting {
            cpus.waiting.fetch_sub(1, Ordering::SeqCst);
        }
        taken.then_some(true)
    }

    /// Before a signal handler runs: Linux's `rseq_signal_deliver`, which
    /// aborts the critical section the thread is in and brings its area up
    /// to date. `false` when it cannot, which sends the thread `SIGSEGV`.
    pub(crate) fn rseq_signal(thread: &mut Thread, mem: &AddressSpace) -> bool {
        let Some(registration) = thread.state.rseq else {
            return true;
        };
        let mut rip = thread.cpu.rip.0;
        let result = fixup(mem, &registration, &mut rip, true).and_then(|()| {
            thread
                .state
                .on_cpu
                .map_or(Ok(()), |on| update(mem, &registration, on))
        });
        thread.cpu.rip = GuestAddr(rip);
        result.is_ok()
    }
}

/// The `SIGSEGV` Linux's `force_sigsegv` sends a thread whose `rseq` area
/// it cannot read, write or accept: from the kernel (`SI_KERNEL`), and
/// fatal when blocked or ignored.
pub(crate) fn forced_sigsegv() -> signals::PendingSignal {
    signals::PendingSignal {
        target: signals::PendingTarget::Thread,
        number: paludarium_types::signal::SIGSEGV,
        code: 0x80,
        addr: 0,
        trap: 0,
        error: 0,
        synchronous: true,
        timer: None,
        child: None,
        sender: None,
        sender_uid: None,
        queued: None,
        born: signals::generation(),
    }
}

fn read_u32(mem: &AddressSpace, address: u64) -> Result<u32, ()> {
    let mut bytes = [0; 4];
    mem.read(GuestAddr(address), &mut bytes).map_err(drop)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(mem: &AddressSpace, address: u64) -> Result<u64, ()> {
    let mut bytes = [0; 8];
    mem.read(GuestAddr(address), &mut bytes).map_err(drop)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u32(mem: &AddressSpace, address: u64, value: u32) -> Result<(), ()> {
    mem.write(GuestAddr(address), &value.to_le_bytes())
        .map_err(drop)
}

/// The area's `rseq_cs`, which the kernel clears once it has seen it.
fn clear(mem: &AddressSpace, area: u64) -> Result<(), ()> {
    mem.write(GuestAddr(area.wrapping_add(8)), &0u64.to_le_bytes())
        .map_err(drop)
}

/// Linux's `rseq_update_user_cs`, as its current kernels have it: the
/// descriptor the area's `rseq_cs` names, if any, is cleared once `rip` is
/// outside the section it describes, which is all that is read of it then.
/// A thread inside it goes on at the section's abort handler instead when
/// `restart`: it was preempted, moved or sent a signal. `Err` is what Linux
/// sends `SIGSEGV` for: an area or descriptor it cannot read or write, a
/// section past the end of user space, or, for a thread inside the section,
/// an abort handler past user space, inside the section or not after the
/// signature. The descriptor's version and flags are not read, as current
/// Linux no longer reads them.
pub(crate) fn fixup(
    mem: &AddressSpace,
    registration: &Registration,
    rip: &mut u64,
    restart: bool,
) -> Result<(), ()> {
    let area = registration.address;
    let descriptor = read_u64(mem, area.wrapping_add(8))?;
    if descriptor == 0 {
        return Ok(());
    }
    if descriptor >= TASK_SIZE {
        return Err(());
    }
    let start = read_u64(mem, descriptor.wrapping_add(8))?;
    if start >= TASK_SIZE {
        return Err(());
    }
    if *rip < start {
        return clear(mem, area);
    }
    let length = read_u64(mem, descriptor.wrapping_add(16))?;
    let end = start.wrapping_add(length);
    if end >= TASK_SIZE || end < start {
        return Err(());
    }
    if *rip >= end {
        return clear(mem, area);
    }
    let abort = read_u64(mem, descriptor.wrapping_add(24))?;
    if !(4..TASK_SIZE).contains(&abort) || abort.wrapping_sub(start) < length {
        return Err(());
    }
    if read_u32(mem, abort - 4)? != registration.signature {
        return Err(());
    }
    if !restart {
        return Ok(());
    }
    clear(mem, area)?;
    *rip = abort;
    Ok(())
}

/// Linux's `rseq_update_cpu_node_id`: the area shows the CPU (twice), NUMA
/// node 0 and the concurrency ID.
pub(crate) fn update(mem: &AddressSpace, registration: &Registration, on: OnCpu) -> Result<(), ()> {
    let area = registration.address;
    write_u32(mem, area, on.cpu)?;
    write_u32(mem, area.wrapping_add(4), on.cpu)?;
    write_u32(mem, area.wrapping_add(20), 0)?;
    write_u32(mem, area.wrapping_add(24), on.cid)
}

/// `rseq(rseq, rseq_len, flags, sig)`, as Linux's: registers the calling
/// thread's area, or unregisters it with `RSEQ_FLAG_UNREGISTER`, which
/// needs the same area, length and signature (`EINVAL`, `EPERM` for the
/// signature). Registering again is `EBUSY` with the same, else the same
/// errors. An area must be 32 bytes long and aligned on 32, or longer than
/// that and aligned on [`ALIGNMENT`] (`EINVAL`), and within user space
/// (`EFAULT`). A registration clears the area's `rseq_cs`, which old C
/// libraries leave set, and the area shows the CPU once the call returns.
/// Any other flag is `EINVAL`, `RSEQ_FLAG_SLICE_EXT_DEFAULT_ON` too: there
/// is no time slice extension, as on a Linux built without it.
pub(crate) fn sys_rseq(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (address, length, flags, signature) = (a[0], a[1] as u32, a[2] as u32, a[3] as u32);
    if flags & UNREGISTER != 0 {
        if flags & !UNREGISTER != 0 {
            return err(Errno::EINVAL);
        }
        let Some(current) = c.process.rseq else {
            return err(Errno::EINVAL);
        };
        if current.address != address || current.length != length {
            return err(Errno::EINVAL);
        }
        if current.signature != signature {
            return err(Errno::EPERM);
        }
        // Linux's rseq_reset_rseq_cpu_node_id.
        for (offset, value) in [(0, 0), (4, UNINITIALIZED), (20, 0), (24, 0)] {
            if write_u32(c.mem, address.wrapping_add(offset), value).is_err() {
                return err(Errno::EFAULT);
            }
        }
        c.process.rseq = None;
        c.process.on_cpu = None;
        return ok(0);
    }
    if flags != 0 {
        return err(Errno::EINVAL);
    }
    if let Some(current) = c.process.rseq {
        if current.address != address || current.length != length {
            return err(Errno::EINVAL);
        }
        if current.signature != signature {
            return err(Errno::EPERM);
        }
        // EBUSY: this area is registered already.
        return err(Errno(16));
    }
    let aligned = |alignment: u64| address % alignment == 0;
    if length < ORIGINAL_SIZE
        || length == ORIGINAL_SIZE && !aligned(u64::from(ORIGINAL_SIZE))
        || length != ORIGINAL_SIZE && (!aligned(ALIGNMENT) || u64::from(length) < FEATURE_SIZE)
    {
        return err(Errno::EINVAL);
    }
    if address
        .checked_add(u64::from(length))
        .is_none_or(|end| end > TASK_SIZE)
    {
        return err(Errno::EFAULT);
    }
    match read_u64(c.mem, address.wrapping_add(8)) {
        Err(()) => return err(Errno::EFAULT),
        Ok(0) => {}
        Ok(_) => {
            if clear(c.mem, address).is_err() {
                return err(Errno::EFAULT);
            }
        }
    }
    c.process.rseq = Some(Registration {
        address,
        length,
        signature,
    });
    c.process.rseq_notify = true;
    ok(0)
}

/// For `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ`: every other thread of
/// `space` with `rseq` (only the one on `cpu`, when given) aborts the
/// critical section it is in before it runs guest code again, as the
/// interrupt Linux sends the CPUs that run them makes them. Once this
/// returns, each of those that was running guest code has stopped since.
pub(crate) fn restart_others(
    cpus: &Cpus,
    host: &dyn Host,
    cancellation: &AtomicBool,
    space: usize,
    me: Option<u32>,
    cpu: Option<u32>,
) {
    // Declared before the table's lock, so dropped after it.
    let mut running = Vec::new();
    let table = cpus.table();
    for runner in table.runners.values().filter_map(Weak::upgrade) {
        if runner.space != space
            || Some(runner.id) == me
            || cpu.is_some_and(|cpu| runner.cpu.load(Ordering::SeqCst) != cpu)
        {
            running.push((runner, None));
            continue;
        }
        runner.requested.fetch_add(1, Ordering::SeqCst);
        if runner.running.load(Ordering::SeqCst) {
            let stints = runner.stints.load(Ordering::SeqCst);
            running.push((runner, Some(stints)));
        }
    }
    drop(table);
    running.retain(|(_, stints)| stints.is_some());
    if running.is_empty() {
        return;
    }
    cpus.waiting.fetch_add(1, Ordering::SeqCst);
    loop {
        let seen = cpus.changed.value();
        if running.iter().all(|(runner, stints)| {
            !runner.running.load(Ordering::SeqCst)
                || Some(runner.stints.load(Ordering::SeqCst)) != *stints
        }) {
            break;
        }
        let deadline = host
            .clock(ClockId::Monotonic)
            .map_or(u64::MAX, |now| now.saturating_add(10_000_000));
        let _ = host.wait_on(
            &cpus.changed,
            seen,
            Some((ClockId::Monotonic, deadline)),
            cancellation,
        );
    }
    cpus.waiting.fetch_sub(1, Ordering::SeqCst);
}

#[cfg(test)]
#[path = "rseq_tests.rs"]
mod tests;
