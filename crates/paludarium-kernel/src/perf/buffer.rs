//! An event's ring buffer, as Linux's `kernel/events/ring_buffer.c` makes
//! it and `perf_mmap` maps it: a first page, the user page Linux calls
//! `struct perf_event_mmap_page`, and a power of two of data pages after
//! it (none at all is allowed), which the kernel and every mapping of the
//! buffer share ([`SharedPages`]).
//!
//! The buffer lives while a mapping of it does. Each mapping holds a
//! [`Mapped`], and when the last mapping goes, the buffer leaves its event
//! and its pages are no longer charged, as in Linux's `perf_mmap_close`.
//! The pages are charged to the user who mapped them, up to
//! `kernel.perf_event_mlock_kb` per CPU (`user->perf_mlock`); the rest is
//! charged to the address space's pinned pages, which RLIMIT_MEMLOCK bounds
//! (`pinned_vm`, [`Accounts`]).
use super::{Erased, Event, erase, lock};
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_mmu::{
    Backing, MappingKind, PageSource, Placement, Prot, SharedPages, SharedWrites,
};
use paludarium_types::Errno;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const PAGE: u64 = 4096;
const EBUSY: Errno = Errno(16);

/// Where `struct perf_event_mmap_page` keeps its fields.
mod field {
    pub const LOCK: u64 = 8;
    pub const DATA_HEAD: u64 = 1024;
    pub const DATA_TAIL: u64 = 1032;
    pub const INDEX: u64 = 12;
    pub const OFFSET: u64 = 16;
    pub const TIME_ENABLED: u64 = 24;
    pub const TIME_RUNNING: u64 = 32;
    pub const CAPABILITIES: u64 = 40;
    /// `size`, the header's size up to `__reserved`, which starts at 96.
    pub const SIZE: u64 = 72;
    pub const RESERVED: u32 = 96;
    pub const DATA_OFFSET: u64 = 1040;
    pub const DATA_SIZE: u64 = 1048;
    pub const AUX_OFFSET: u64 = 1072;
    pub const AUX_SIZE: u64 = 1080;
}

/// `cap_bit0_is_deprecated`, which every user page has. On x86-64,
/// `arch_perf_update_userpage` gives no `cap_user_rdpmc` to a software
/// event, and `cap_user_time` and `cap_user_time_zero` only where
/// `sched_clock` is the TSC's and stable, which here it is not: the times
/// are left at zero, as is `pmc_width` without a PMU.
const CAP_BIT0_IS_DEPRECATED: u64 = 1 << 1;

/// What each user and address space has locked of ring buffers, kept for
/// the whole machine: Linux's `user->perf_mlock` by the user's ID, and
/// `mm->pinned_vm` by the address space's.
#[derive(Default)]
pub(crate) struct Accounts {
    users: Mutex<HashMap<u32, u64>>,
    pinned: Mutex<HashMap<u64, u64>>,
}

impl Accounts {
    fn user(&self, uid: u32) -> u64 {
        lock(&self.users).get(&uid).copied().unwrap_or(0)
    }
    fn pinned(&self, space: u64) -> u64 {
        lock(&self.pinned).get(&space).copied().unwrap_or(0)
    }
    /// `perf_mmap_account`.
    fn charge(&self, uid: u32, user: u64, space: u64, pinned: u64) {
        *lock(&self.users).entry(uid).or_default() += user;
        if pinned != 0 {
            *lock(&self.pinned).entry(space).or_default() += pinned;
        }
    }
    /// `perf_mmap_unaccount`.
    fn uncharge(&self, uid: u32, user: u64, space: u64, pinned: u64) {
        take(&self.users, uid, user);
        take(&self.pinned, space, pinned);
    }
}

/// Takes `n` from what `map` has for `key`, which goes once it is none.
fn take<K: std::hash::Hash + Eq>(map: &Mutex<HashMap<K, u64>>, key: K, n: u64) {
    let mut map = lock(map);
    if let Some(value) = map.get_mut(&key) {
        *value = value.saturating_sub(n);
        if *value == 0 {
            map.remove(&key);
        }
    }
}

/// Linux's `struct perf_buffer`.
pub(crate) struct Buffer {
    /// The user page and the data pages after it.
    pages: SharedPages,
    /// How many data pages it has.
    data_pages: u64,
    /// The first mapping could write (`RING_BUFFER_WRITABLE`): the reader
    /// says how far it has read (`data_tail`). Without, the buffer
    /// overwrites what it holds (`overwrite`).
    writable: bool,
    /// Where the next record goes, the records lost since the last that
    /// went in, and whether output is paused.
    out: Mutex<Out>,
    /// `watermark`: the bytes between wakeups, `wakeup_watermark` for an
    /// event with `watermark` (no more than the data), else half the data.
    watermark: u64,
    accounts: Arc<Accounts>,
    /// Who mapped it first (`mmap_user`), the address space it was in,
    /// and how much of it the address space's pinned pages took
    /// (`mmap_locked`).
    uid: u32,
    space: u64,
    pinned: u64,
    /// The events that write to it (`event_list`), held by no type for
    /// the reason [`Erased`] gives: the one that made it and those whose
    /// output goes to it ([`set_output`]). `None` once its last mapping
    /// has gone, when no event may join it (Linux's `rb->mmap_count` of
    /// 0).
    events: Mutex<Option<Vec<Erased>>>,
}

impl Buffer {
    /// A buffer of `data_pages` for `event`, whose user page is set up and
    /// whose pages are charged, and what its mappings hold.
    #[allow(clippy::too_many_arguments, reason = "what Linux's perf_buffer keeps")]
    fn make(
        event: &Arc<Event>,
        file: &Arc<dyn FileHandle>,
        pages: SharedPages,
        data_pages: u64,
        writable: bool,
        accounts: &Arc<Accounts>,
        (uid, space): (u32, u64),
        (user, pinned): (u64, u64),
    ) -> Arc<Mapped> {
        let buffer = Arc::new(Buffer {
            pages,
            data_pages,
            writable,
            accounts: Arc::clone(accounts),
            uid,
            space,
            pinned,
            watermark: {
                let size = data_pages * PAGE;
                let asked = if event.attr.flag(super::bit::WATERMARK) {
                    u64::from(event.attr.wakeup).min(size)
                } else {
                    0
                };
                if asked == 0 { size / 2 } else { asked }
            },
            // A buffer of no data pages takes nothing (`rb->paused`).
            out: Mutex::new(Out {
                paused: data_pages == 0,
                ..Out::default()
            }),
            events: Mutex::new(Some(vec![erase(event)])),
        });
        accounts.charge(uid, user, space, pinned);
        buffer.init_user_page();
        *lock(&event.rb) = Some(Arc::clone(&buffer));
        let mapped = Arc::new(Mapped {
            buffer,
            _file: Arc::clone(file),
        });
        *lock(&event.mapped) = Arc::downgrade(&mapped);
        event.update_user_page();
        mapped
    }
    fn store(&self, at: u64, value: &[u8]) {
        self.pages.store(at, value);
    }
    fn load(&self, at: u64) -> u64 {
        let mut bytes = [0; 8];
        self.pages.load(at, &mut bytes);
        u64::from_le_bytes(bytes)
    }
    /// `perf_data_size`.
    fn data_size(&self) -> u64 {
        self.data_pages * PAGE
    }
    /// `perf_event_init_userpage`.
    fn init_user_page(&self) {
        self.store(field::CAPABILITIES, &CAP_BIT0_IS_DEPRECATED.to_le_bytes());
        self.store(field::SIZE, &field::RESERVED.to_le_bytes());
        self.store(field::DATA_OFFSET, &PAGE.to_le_bytes());
        self.store(field::DATA_SIZE, &self.data_size().to_le_bytes());
    }
    /// `perf_event_update_userpage`: the event's count and times, between
    /// two bumps of the sequence lock. A software event has no counter to
    /// read in user mode (`index` 0).
    fn update_user_page(&self, count: u64, enabled: u64, running: u64) {
        let mut bytes = [0; 4];
        self.pages.load(field::LOCK, &mut bytes);
        let seq = u32::from_le_bytes(bytes);
        self.store(field::LOCK, &seq.wrapping_add(1).to_le_bytes());
        self.store(field::INDEX, &0u32.to_le_bytes());
        self.store(field::OFFSET, &count.to_le_bytes());
        self.store(field::TIME_ENABLED, &enabled.to_le_bytes());
        self.store(field::TIME_RUNNING, &running.to_le_bytes());
        self.store(field::LOCK, &seq.wrapping_add(2).to_le_bytes());
    }
}

/// What `struct perf_buffer` keeps of its output: `head`, `lost` and
/// `paused`; `wakeup`, where the next wakeup is due, and `events`, the
/// samples since the last of `wakeup_events`; and `poll`, what the last
/// wakeup left for `poll` to find, with how many wakeups there have been.
#[derive(Default)]
struct Out {
    head: u64,
    lost: u64,
    paused: bool,
    wakeup: u64,
    events: u32,
    poll: u32,
    wakeups: u64,
}

/// `EPOLLIN | EPOLLRDNORM`.
const POLL_IN: u32 = 0x41;

impl Out {
    /// How far the head has gone: back from 0 for `write_backward`.
    fn written(&self, backward: bool) -> u64 {
        if backward {
            self.head.wrapping_neg()
        } else {
            self.head
        }
    }
    /// `__perf_output_begin`'s watermark: a wakeup is due once the head
    /// is more than a watermark past the last.
    fn watermark(&mut self, backward: bool, watermark: u64, records: u64) {
        let lag = self.written(backward).wrapping_sub(self.wakeup);
        if watermark != 0 && lag > watermark {
            let due = (lag - watermark).div_ceil(watermark).min(records);
            self.wakeup = self.wakeup.wrapping_add(due * watermark);
        }
    }
    /// `perf_output_sample`'s `wakeup_events`, for `records` more samples.
    fn sampled(&mut self, wakeup_events: u32, records: u64) {
        if wakeup_events == 0 {
            return;
        }
        let total = u64::from(self.events) + records;
        let w = u64::from(wakeup_events);
        self.wakeup = self.wakeup.wrapping_add(total / w);
        self.events = (total % w) as u32;
    }
}

impl Buffer {
    /// `__perf_output_begin`, the copy and `perf_output_end`, for `copies`
    /// of `record` that `event` (the one the buffer is reached through,
    /// which counts what is lost) writes: each goes in where the reader
    /// has left room (`data_tail`) or, in a buffer that overwrites, where
    /// it is due, forward or for `write_backward` back from the head, and
    /// the first after lost ones follows a `PERF_RECORD_LOST` of them
    /// with `trailer`, its `sample_id`. A paused buffer counts what it does
    /// not take as lost. `spill` is written past the record, in the room it
    /// was not given. Each sample counts towards the sampling event's
    /// `wakeup_events` (0 for none, or with `watermark`), and the head
    /// towards the watermark; when either makes a wakeup due, the buffer
    /// is readable for `poll` and its readers are woken
    /// (`perf_output_wakeup`), which this returns.
    #[allow(clippy::too_many_arguments, reason = "a record and how it counts")]
    pub(super) fn output(
        &self,
        event: &Event,
        record: &[u8],
        spill: &[u8],
        copies: u64,
        trailer: &[u8],
        wakeup_events: u32,
    ) -> bool {
        let backward = event.attr.flag(super::bit::WRITE_BACKWARD);
        let size = self.data_size();
        let mut out = lock(&self.out);
        let due = out.wakeup;
        let mut copies = copies;
        // Of a buffer that overwrites, only the last that fit stay.
        if !self.writable && !out.paused && size != 0 && out.lost == 0 {
            let fit = size / record.len() as u64 + 1;
            if copies > fit {
                let records = copies - fit;
                let skipped = records * record.len() as u64;
                out.head = if backward {
                    out.head.wrapping_sub(skipped)
                } else {
                    out.head.wrapping_add(skipped)
                };
                out.watermark(backward, self.watermark, records);
                out.sampled(wakeup_events, records);
                copies = fit;
            }
        }
        for _ in 0..copies {
            if out.paused {
                if size != 0 {
                    out.lost += 1;
                    lock(&event.sampler).lost += 1;
                }
                continue;
            }
            let mut need = record.len() as u64;
            if out.lost != 0 {
                need += event.lost_size() as u64;
            }
            let head = out.head;
            if self.writable {
                let tail = self.load(field::DATA_TAIL);
                // CIRC_SPACE.
                let space = if backward {
                    head.wrapping_sub(tail.wrapping_add(1)) & (size - 1)
                } else {
                    tail.wrapping_sub(head.wrapping_add(1)) & (size - 1)
                };
                if space < need {
                    out.lost += 1;
                    lock(&event.sampler).lost += 1;
                    continue;
                }
            }
            let (mut at, new_head) = if backward {
                let new = head.wrapping_sub(need);
                (new, new)
            } else {
                (head, head.wrapping_add(need))
            };
            out.head = new_head;
            out.watermark(backward, self.watermark, 1);
            if out.lost != 0 {
                let lost = std::mem::take(&mut out.lost);
                let lost = event.lost_record(lost, trailer);
                self.copy_in(at, &lost);
                at = at.wrapping_add(lost.len() as u64);
            }
            self.copy_in(at, record);
            self.copy_in(at.wrapping_add(record.len() as u64), spill);
            out.sampled(wakeup_events, 1);
            self.store(field::DATA_HEAD, &new_head.to_le_bytes());
        }
        let woken = out.wakeup != due;
        if woken {
            out.poll = POLL_IN;
            out.wakeups += 1;
        }
        drop(out);
        if woken {
            self.wake();
        }
        woken
    }
    /// `ring_buffer_wakeup`: wakes those who wait for any event that writes
    /// to the buffer.
    pub(super) fn wake(&self) {
        let events: Vec<Arc<Event>> = lock(&self.events)
            .as_ref()
            .map(|list| list.iter().filter_map(super::event).collect())
            .unwrap_or_default();
        for event in events {
            event.hub.changed();
        }
    }
    /// What `perf_poll` takes of the buffer: what its last wakeup left,
    /// then nothing until the next (`atomic_xchg(&rb->poll, 0)`), with the
    /// count of wakeups for `epoll`'s edges.
    pub(super) fn take_poll(&self) -> (u32, u64) {
        let mut out = lock(&self.out);
        (std::mem::take(&mut out.poll), out.wakeups)
    }
    /// `PERF_EVENT_IOC_PAUSE_OUTPUT` (`rb_toggle_paused`): `EINVAL` for a
    /// buffer of no data pages.
    pub(super) fn pause(&self, paused: bool) -> Result<(), Errno> {
        if self.data_pages == 0 {
            return Err(Errno::EINVAL);
        }
        lock(&self.out).paused = paused;
        Ok(())
    }
    /// `bytes` into the data pages from `at`, round the end of them.
    fn copy_in(&self, at: u64, bytes: &[u8]) {
        let size = self.data_size();
        let mut done = 0;
        while done < bytes.len() {
            let offset = at.wrapping_add(done as u64) & (size - 1);
            let n = ((size - offset) as usize).min(bytes.len() - done);
            self.store(PAGE + offset, &bytes[done..done + n]);
            done += n;
        }
    }
}

/// What every mapping of a buffer holds: when the last one goes, so does
/// the buffer (`perf_mmap_close`). It holds the event's file too, as a
/// VMA does (`vm_file`), so that the event counts on while it is mapped
/// though its descriptors are closed.
pub(crate) struct Mapped {
    buffer: Arc<Buffer>,
    _file: Arc<dyn FileHandle>,
}

impl Drop for Mapped {
    /// The events that write to the buffer leave it, and its pages are no
    /// longer charged.
    fn drop(&mut self) {
        let buffer = &self.buffer;
        let events = lock(&buffer.events).take().unwrap_or_default();
        for event in events.iter().filter_map(super::event) {
            let mut rb = lock(&event.rb);
            if rb.as_ref().is_some_and(|rb| Arc::ptr_eq(rb, buffer)) {
                *rb = None;
            }
        }
        buffer.accounts.uncharge(
            buffer.uid,
            buffer.data_pages + 1 - buffer.pinned,
            buffer.space,
            buffer.pinned,
        );
    }
}

/// The pages' file: zero-filled, an anonymous inode's, a `VM_PFNMAP` of
/// `remap_pfn_range` that may not grow (`VM_IO | VM_DONTEXPAND`).
struct Pages;

impl PageSource for Pages {
    fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn fixed(&self) -> bool {
        true
    }
    fn vma_flags(&self, flags: u64) -> u64 {
        const VM_PFNMAP: u64 = 1 << 10;
        const VM_IO: u64 = 1 << 14;
        use paludarium_mmu::vm;
        (flags | VM_PFNMAP | VM_IO | vm::DONTEXPAND) & !vm::MAYEXEC
    }
    fn linked(&self) -> bool {
        false
    }
}

const CAP_IPC_LOCK: u64 = 1 << 14;
const RLIMIT_MEMLOCK: usize = 8;

/// `perf_mmap_calc_limits`: of `user_extra` pages to lock, what the user's
/// share takes (up to `perf_event_mlock_kb` for each CPU) and what is left
/// for the address space's pinned pages, or `None` if those would pass
/// RLIMIT_MEMLOCK, unless `perf_event_paranoid` is -1 or the caller has
/// `CAP_IPC_LOCK`.
fn limits(c: &Context<'_>, accounts: &Accounts, user_extra: u64) -> Option<(u64, u64)> {
    let kb = i64::from(c.processes.sysctls.perf_event_mlock_kb());
    let cpus = c.host.cpu_count().max(1) as i64;
    // An `int` of KiB in pages, as an `unsigned long` takes it.
    let user_limit = ((kb >> 2) as u64).wrapping_mul(cpus as u64);
    let uid = c.process.credentials.uid;
    let locked = accounts.user(uid).min(user_limit) + user_extra;
    let extra = locked.saturating_sub(user_limit);
    let lock_limit = c.processes.soft_limit(c.process.pid, RLIMIT_MEMLOCK) >> 12;
    let pinned = accounts.pinned(c.mem.id()) + extra;
    (pinned <= lock_limit
        || c.processes.sysctls.perf_event_paranoid() <= -1
        || c.process.credentials.capable(CAP_IPC_LOCK))
    .then_some((user_extra - extra, extra))
}

/// `perf_mmap`: a shared mapping (`EINVAL`) of the event's buffer, which
/// the first mapping makes, of the user page and `2^n` data pages
/// (`EINVAL`); none of an event of every CPU that new tasks inherit
/// (`EINVAL`). A later mapping must be as large (`EINVAL`), and comes
/// through the event that made the buffer (`EBUSY`). An offset past the
/// buffer asks for its AUX area, which no software event has
/// (`EOPNOTSUPP`, after Linux's checks of it). The mapping is not copied
/// to a `fork`ed child nor held in a core dump.
pub(super) fn mmap(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    placement: Placement,
    len: u64,
    prot: Prot,
    shared: bool,
    offset: u64,
) -> Result<u64, Errno> {
    let Some(event) = super::of(file) else {
        return Err(Errno::ENODEV);
    };
    if event.cpu == -1 && event.attr.flag(super::bit::INHERIT) {
        return Err(Errno::EINVAL);
    }
    if !shared {
        return Err(Errno::EINVAL);
    }
    let size = len.next_multiple_of(PAGE);
    let nr_pages = size / PAGE;
    if nr_pages > i32::MAX as u64 {
        return Err(Errno::ENOMEM);
    }
    let accounts = Arc::clone(&c.processes.perf_events.accounts);
    let uid = c.process.credentials.uid;
    let space = c.mem.id();
    let mapped = {
        let _guard = lock(&event.mmap_mutex);
        if offset != 0 {
            return aux(c, event, &accounts, offset, nr_pages);
        }
        let data_pages = nr_pages - 1;
        if data_pages != 0 && !data_pages.is_power_of_two() {
            return Err(Errno::EINVAL);
        }
        let existing = lock(&event.rb).clone();
        match existing {
            Some(rb) => {
                if rb.data_pages != data_pages {
                    return Err(Errno::EINVAL);
                }
                // A buffer another event's mapping made, which this one
                // writes to (`PERF_EVENT_IOC_SET_OUTPUT`).
                let Some(mapped) = lock(&event.mapped).upgrade() else {
                    return Err(EBUSY);
                };
                // Linux charges the user for each later mapping too, and
                // takes back only what the first was charged.
                accounts.charge(uid, nr_pages, space, 0);
                mapped
            }
            None => {
                let (user, pinned) = limits(c, &accounts, nr_pages).ok_or(Errno::EPERM)?;
                let pages = SharedPages::new().with_source(Arc::new(Pages));
                let meter = c.mem.memory_meter();
                for key in (0..size).step_by(PAGE as usize) {
                    pages.fill(key, &[], meter.as_ref())?;
                }
                Buffer::make(
                    event,
                    file,
                    pages,
                    data_pages,
                    prot.contains(Prot::WRITE),
                    &accounts,
                    (uid, space),
                    (user, pinned),
                )
            }
        }
    };
    let pages = mapped.buffer.pages.with_owner(Arc::clone(&mapped) as _);
    drop(mapped);
    let at = c.mem.map_backed(
        placement,
        len,
        prot,
        MappingKind::File,
        Backing::Shared {
            pages: &pages,
            offset: 0,
            writes: SharedWrites::Allowed,
        },
    )?;
    drop(pages);
    let end = at.0 + size;
    // `VM_DONTCOPY | VM_DONTDUMP`.
    for advice in [
        paludarium_mmu::FlagAdvice::DontFork,
        paludarium_mmu::FlagAdvice::DontDump,
    ] {
        c.mem.advise_flags(at, end, advice)?;
    }
    c.group.numa().forget(at.0, size);
    Ok(at.0)
}

/// `perf_mmap_aux`: the AUX area must lie past the buffer, where the user
/// page's `aux_offset` puts it, be `aux_size` large, and a power of two of
/// pages (`EINVAL`); and then within the limits (`EPERM`) no software
/// event has one (`rb_alloc_aux`'s `EOPNOTSUPP`).
fn aux(
    c: &Context<'_>,
    event: &Event,
    accounts: &Accounts,
    offset: u64,
    nr_pages: u64,
) -> Result<u64, Errno> {
    let Some(rb) = lock(&event.rb).clone() else {
        return Err(Errno::EINVAL);
    };
    let aux_offset = rb.load(field::AUX_OFFSET);
    let aux_size = rb.load(field::AUX_SIZE);
    if aux_offset < rb.data_size() + PAGE
        || aux_offset != offset
        || aux_size != nr_pages * PAGE
        || !nr_pages.is_power_of_two()
    {
        return Err(Errno::EINVAL);
    }
    limits(c, accounts, nr_pages).ok_or(Errno::EPERM)?;
    Err(Errno::EOPNOTSUPP)
}

/// `perf_event_set_output`: `event` writes to `output`'s buffer from now
/// on, or to none for `None`. `output` must be another event (`EINVAL`) of
/// the same CPU, of the same task for an event of every CPU, with the same
/// clock and the same direction of writing (`write_backward`), and have a
/// buffer, its own or one it writes to; and `event` may not have a
/// mapping of its own (`EINVAL`). No event here has an AUX area, which
/// Linux would also compare the PMUs of.
pub(super) fn set_output(event: &Arc<Event>, output: Option<&Arc<Event>>) -> Result<(), Errno> {
    let Some(output) = output else {
        let _guard = lock(&event.mmap_mutex);
        if lock(&event.mapped).upgrade().is_some() {
            return Err(Errno::EINVAL);
        }
        let old = lock(&event.rb).take();
        leave(event, old);
        return Ok(());
    };
    let same_task = || match (&event.target, &output.target) {
        (super::Target::Thread { tid: a, .. }, super::Target::Thread { tid: b, .. }) => a == b,
        (super::Target::Cpu, super::Target::Cpu) => true,
        _ => false,
    };
    let backward = |e: &Event| e.attr.flag(super::bit::WRITE_BACKWARD);
    if Arc::ptr_eq(event, output)
        || output.cpu != event.cpu
        || output.cpu == -1 && !same_task()
        || output.clockid != event.clockid
        || backward(output) != backward(event)
    {
        return Err(Errno::EINVAL);
    }
    // Both `mmap_mutex`es, the lower address's first (`mutex_lock_double`).
    let (first, second) = if Arc::as_ptr(event) < Arc::as_ptr(output) {
        (event, output)
    } else {
        (output, event)
    };
    let _first = lock(&first.mmap_mutex);
    let _second = lock(&second.mmap_mutex);
    if lock(&event.mapped).upgrade().is_some() {
        return Err(Errno::EINVAL);
    }
    let rb = lock(&output.rb).clone().ok_or(Errno::EINVAL)?;
    // `ring_buffer_attach`: the event joins the buffer's list and writes
    // to it under the list's lock, so that a last unmapping either finds
    // it there writing to the buffer, or has already left the buffer
    // taking no more events (`EINVAL`).
    let old = {
        let mut events = lock(&rb.events);
        let Some(list) = events.as_mut() else {
            return Err(Errno::EINVAL);
        };
        let mut current = lock(&event.rb);
        if current.as_ref().is_some_and(|old| Arc::ptr_eq(old, &rb)) {
            return Ok(());
        }
        list.push(erase(event));
        current.replace(Arc::clone(&rb))
    };
    leave(event, old);
    Ok(())
}

/// Takes `event` off the list of `old`, the buffer it wrote to, with no
/// other lock held: two events that change places between two buffers
/// would otherwise take the two lists' locks in opposite orders.
fn leave(event: &Arc<Event>, old: Option<Arc<Buffer>>) {
    if let Some(old) = old
        && let Some(list) = lock(&old.events).as_mut()
    {
        let me = Arc::as_ptr(event).cast::<()>();
        list.retain(|e| e.as_ptr().cast::<()>() != me);
    }
}

impl Event {
    /// `perf_event_update_userpage`, if the event has a buffer.
    pub(super) fn update_user_page(&self) {
        let Some(rb) = lock(&self.rb).clone() else {
            return;
        };
        let (count, enabled, running) = {
            let state = self.settle();
            (
                state.count + state.child_count,
                state.enabled_time + state.child_enabled,
                state.running_time + state.child_running,
            )
        };
        rb.update_user_page(count, enabled, running);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_page_is_linux_s_layout() {
        assert_eq!(field::RESERVED, 96);
        // `data_head` starts the second kilobyte.
        assert_eq!(field::DATA_OFFSET, 1024 + 16);
        assert_eq!(field::AUX_SIZE, 1024 + 56);
    }

    /// A buffer of `data_pages` for a new event, charged to user 1000.
    fn mapped(data_pages: u64, accounts: &Arc<Accounts>) -> (Arc<Event>, Arc<Mapped>) {
        let event = super::super::tests::event(None);
        let file: Arc<dyn FileHandle> = Arc::new(super::super::EventFile::new(Arc::clone(&event)));
        let pages = SharedPages::new();
        for key in (0..=data_pages).map(|page| page * PAGE) {
            pages.fill(key, &[], None).unwrap();
        }
        let mapped = Buffer::make(
            &event,
            &file,
            pages,
            data_pages,
            true,
            accounts,
            (1000, 7),
            ((data_pages + 1).saturating_sub(2), 2.min(data_pages + 1)),
        );
        (event, mapped)
    }

    #[test]
    fn the_user_page_shows_the_buffer_and_the_count() {
        let accounts = Arc::default();
        let (event, mapped) = mapped(8, &accounts);
        let rb = &mapped.buffer;
        let u32_at = |at| {
            let mut bytes = [0; 4];
            rb.pages.load(at, &mut bytes);
            u32::from_le_bytes(bytes)
        };
        assert_eq!(rb.load(field::DATA_OFFSET), PAGE);
        assert_eq!(rb.load(field::DATA_SIZE), 8 * PAGE);
        assert_eq!(rb.load(field::CAPABILITIES), CAP_BIT0_IS_DEPRECATED);
        assert_eq!(u32_at(field::SIZE), 96);
        // One update, between two bumps of the lock.
        assert_eq!(u32_at(field::LOCK), 2);
        event.reset();
        assert_eq!(u32_at(field::LOCK), 4);
        assert_eq!(rb.load(field::OFFSET), 0);
        assert_eq!(u32_at(field::INDEX), 0);
    }

    #[test]
    fn the_buffer_goes_with_its_last_mapping() {
        let accounts = Arc::default();
        let (event, mapped) = mapped(4, &accounts);
        assert_eq!((accounts.user(1000), accounts.pinned(7)), (3, 2));
        let again = Arc::clone(&mapped);
        drop(mapped);
        assert!(lock(&event.rb).is_some());
        drop(again);
        assert!(lock(&event.rb).is_none());
        assert!(lock(&event.mapped).upgrade().is_none());
        assert_eq!((accounts.user(1000), accounts.pinned(7)), (0, 0));
        // Without a buffer, the user page is not written.
        event.update_user_page();
    }

    #[test]
    fn a_full_buffer_loses_records_and_then_says_how_many() {
        let accounts = Arc::default();
        let (event, mapped) = mapped(1, &accounts);
        let rb = &mapped.buffer;
        let record: Vec<u8> = (0..24).collect();
        rb.output(&event, &record, &[], 200, &[], 0);
        // 170 fit: the head may not reach the tail.
        assert_eq!(rb.load(field::DATA_HEAD), 4080);
        assert_eq!(lock(&event.sampler).lost, 30);
        rb.store(field::DATA_TAIL, &4080u64.to_le_bytes());
        rb.output(&event, &record, &[], 1, &[], 0);
        assert_eq!(rb.load(field::DATA_HEAD), 4080 + 48);
        // PERF_RECORD_LOST, 24 bytes, round the end of the data page.
        assert_eq!(rb.load(PAGE + 4080), 2 | 24 << 48);
        assert_eq!(rb.load(PAGE + 4088), event.id);
        assert_eq!(rb.load(PAGE), 30);
        let mut copied = [0; 24];
        rb.pages.load(PAGE + 8, &mut copied);
        assert_eq!(copied.as_slice(), record.as_slice());
    }

    #[test]
    fn a_paused_buffer_takes_nothing_and_one_of_no_pages_cannot_pause() {
        let accounts = Arc::default();
        let (event, one) = mapped(1, &accounts);
        let rb = &one.buffer;
        rb.pause(true).unwrap();
        rb.output(&event, &[0; 8], &[], 3, &[], 0);
        assert_eq!(rb.load(field::DATA_HEAD), 0);
        assert_eq!(lock(&event.sampler).lost, 3);
        let (other, none) = mapped(0, &accounts);
        assert_eq!(none.buffer.pause(false), Err(Errno::EINVAL));
        none.buffer.output(&other, &[0; 8], &[], 1, &[], 0);
        assert_eq!(lock(&other.sampler).lost, 0);
    }

    #[test]
    fn wakeup_events_and_the_watermark_make_the_buffer_readable_once() {
        let accounts = Arc::default();
        let (event, one) = mapped(1, &accounts);
        let rb = &one.buffer;
        assert_eq!(rb.watermark, 2048);
        // Every second sample wakes.
        assert!(!rb.output(&event, &[0; 24], &[], 1, &[], 2));
        assert_eq!(rb.take_poll(), (0, 0));
        assert!(rb.output(&event, &[0; 24], &[], 1, &[], 2));
        assert_eq!(rb.take_poll(), (POLL_IN, 1));
        assert_eq!(rb.take_poll(), (0, 1));
        // Without wakeup_events, half the data: 86 of 24 bytes pass it.
        assert!(!rb.output(&event, &[0; 24], &[], 83, &[], 0));
        assert!(rb.output(&event, &[0; 24], &[], 1, &[], 0));
        assert_eq!(rb.take_poll().0, POLL_IN);
    }

    fn listed(rb: &Buffer) -> usize {
        lock(&rb.events).as_ref().map_or(0, |list| {
            list.iter().filter(|e| e.upgrade().is_some()).count()
        })
    }

    #[test]
    fn output_goes_to_a_mapped_buffer_of_another_event_alike() {
        let accounts = Arc::default();
        let (owner, mapped) = mapped(4, &accounts);
        let rb = Arc::clone(&mapped.buffer);
        let other = super::super::tests::event(None);
        let on = |event: &Arc<Event>| {
            lock(&event.rb)
                .as_ref()
                .is_some_and(|b| Arc::ptr_eq(b, &rb))
        };
        assert_eq!(set_output(&owner, Some(&owner)), Err(Errno::EINVAL));
        // One with a mapping of its own may not write elsewhere.
        assert_eq!(set_output(&owner, Some(&other)), Err(Errno::EINVAL));
        // Nor to an event without a buffer, nor one that writes backward.
        let third = super::super::tests::event(None);
        assert_eq!(set_output(&third, Some(&other)), Err(Errno::EINVAL));
        let backward = super::super::tests::with_flags(
            None,
            super::super::Target::Cpu,
            1 << super::super::bit::WRITE_BACKWARD,
        );
        assert_eq!(set_output(&backward, Some(&owner)), Err(Errno::EINVAL));

        assert_eq!(set_output(&other, Some(&owner)), Ok(()));
        assert!(on(&other));
        assert_eq!(set_output(&other, Some(&owner)), Ok(()));
        // Through an event that writes to it, to the same buffer.
        assert_eq!(set_output(&third, Some(&other)), Ok(()));
        assert!(on(&third));
        assert_eq!(listed(&rb), 3);
        assert_eq!(set_output(&third, None), Ok(()));
        assert!(lock(&third.rb).is_none());
        assert_eq!(listed(&rb), 2);
        // Its owner may not leave its own buffer while it maps it.
        assert_eq!(set_output(&owner, None), Err(Errno::EINVAL));

        // When the last mapping goes, every event leaves the buffer, which
        // takes no more.
        drop(mapped);
        assert!(lock(&owner.rb).is_none() && lock(&other.rb).is_none());
        assert_eq!(set_output(&third, Some(&owner)), Err(Errno::EINVAL));
        assert_eq!(set_output(&owner, None), Ok(()));
    }

    #[test]
    fn the_pinned_pages_go_back_when_they_are_uncharged() {
        let accounts = Accounts::default();
        accounts.charge(1000, 9, 7, 0);
        accounts.charge(1000, 3, 7, 2);
        assert_eq!((accounts.user(1000), accounts.pinned(7)), (12, 2));
        accounts.uncharge(1000, 3, 7, 2);
        assert_eq!((accounts.user(1000), accounts.pinned(7)), (9, 0));
        accounts.uncharge(1000, 20, 7, 0);
        assert_eq!(accounts.user(1000), 0);
        assert!(lock(&accounts.users).is_empty());
    }
}
