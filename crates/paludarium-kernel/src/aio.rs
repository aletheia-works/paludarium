//! Linux's native asynchronous I/O, as `fs/aio.c` has it: `io_setup`,
//! `io_destroy`, `io_submit`, `io_cancel`, `io_getevents` and
//! `io_pgetevents`.
//!
//! A context is a ring of completion events mapped into the process, whose
//! address is the context's ID (`aio_context_t`): a 32-byte header
//! (`struct aio_ring`: the context's index, the number of events, the
//! head the program or `io_getevents` moves, the tail the kernel moves, a
//! magic number and the header's size) and then the events, 32 bytes each.
//! A program (libaio) reads the header itself, and may take events from the
//! ring without a call, so the ring is pages the kernel shares with the
//! mapping, as Linux's are, and the call that finds a context reads its
//! index from them.
//!
//! A read, a write or a sync runs as `io_submit` takes it, and its event is
//! in the ring before the call returns: as Linux's buffered I/O, a read of a
//! pipe with nothing in it waits there. `IOCB_CMD_POLL` completes at once if
//! the file is ready; otherwise it waits in the context until the file is
//! ready or the request is cancelled, and whether it is ready is looked at
//! as the process makes a call and while it waits (see [`progress`]).
//!
//! The contexts belong to the address space, as Linux keeps them on the
//! `mm`: threads and `CLONE_VM` children share them, a fork's child has
//! none and not the rings either (Linux maps them `VM_DONTCOPY`), and the
//! end of the address space at `execve` or the last exit ends them.
//! `/proc/sys/fs/aio-max-nr` (65536) bounds the events the machine's
//! contexts are set up for, which `aio-nr` counts.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use paludarium_host::FileHandle;
use paludarium_mmu::{AddressSpace, PageSource, SharedPages};
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome, err, ok};

/// `struct aio_ring`: its fields, then the events after it.
const RING_ID: u64 = 0;
const RING_NR: u64 = 4;
const RING_HEAD: u64 = 8;
const RING_TAIL: u64 = 12;
const RING_MAGIC: u64 = 16;
const RING_COMPAT_FEATURES: u64 = 20;
const RING_INCOMPAT_FEATURES: u64 = 24;
const RING_HEADER_LENGTH: u64 = 28;
const HEADER_BYTES: u64 = 32;
const AIO_RING_MAGIC: u32 = 0xa10a_10a1;
/// `struct io_event`: `data`, `obj`, `res` and `res2`.
const EVENT_BYTES: u64 = 32;
const PAGE: u64 = 4096;
/// `AIO_EVENTS_PER_PAGE`; the header takes the place of the first event
/// (`AIO_EVENTS_OFFSET`).
const EVENTS_PER_PAGE: u32 = (PAGE / EVENT_BYTES) as u32;
/// The most events `io_setup` takes, before it doubles them (`0x8000000 /
/// sizeof(struct io_event)`).
const MAX_EVENTS: u32 = 0x800_0000 / EVENT_BYTES as u32;
/// `aio-max-nr`'s default.
const DEFAULT_MAX_NR: u64 = 0x10000;

/// `struct iocb`'s fields.
const IOCB_BYTES: usize = 64;
const IOCB_KEY: u64 = 8;
const CMD_PREAD: u16 = 0;
const CMD_PWRITE: u16 = 1;
const CMD_FSYNC: u16 = 2;
const CMD_FDSYNC: u16 = 3;
const CMD_POLL: u16 = 5;
const CMD_PREADV: u16 = 7;
const CMD_PWRITEV: u16 = 8;
/// `IOCB_FLAG_RESFD`: an eventfd counts the completions; `IOCB_FLAG_IOPRIO`:
/// `aio_reqprio` is an I/O priority.
const FLAG_RESFD: u32 = 1 << 0;
const FLAG_IOPRIO: u32 = 1 << 1;

const EINTR: Errno = Errno(4);
const EINPROGRESS: Errno = Errno(115);

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const POLLERR: u32 = 0x8;
const POLLHUP: u32 = 0x10;
const POLLRDNORM: u32 = 0x40;
const POLLWRNORM: u32 = 0x100;
/// What `vfs_poll` gives of a file without `poll` (`DEFAULT_POLLMASK`).
const DEFAULT_POLLMASK: u32 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFSOCK: u32 = 0o140000;
const O_PATH: u32 = 0o10000000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(b)
}

/// The machine's events that contexts were set up for (`aio_nr`), their
/// limit (`aio_max_nr`), and how many polls wait in any context, which lets
/// [`progress`] do nothing while none does.
pub(crate) struct Limits {
    nr: Mutex<u64>,
    max: AtomicU64,
    polls: AtomicUsize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            nr: Mutex::new(0),
            max: AtomicU64::new(DEFAULT_MAX_NR),
            polls: AtomicUsize::new(0),
        }
    }
}

impl Limits {
    /// `aio-nr`.
    pub(crate) fn nr(&self) -> u64 {
        *lock(&self.nr)
    }
    /// `aio-max-nr`.
    pub(crate) fn max(&self) -> u64 {
        self.max.load(Ordering::SeqCst)
    }
    /// A write of `aio-max-nr`, which the contexts there are keep to.
    pub(crate) fn set_max(&self, max: u64) {
        self.max.store(max, Ordering::SeqCst);
    }
    /// Counts `events` more, unless that takes the count past the limit or
    /// wraps it (`EAGAIN`).
    fn take(&self, events: u64) -> Result<(), Errno> {
        let mut nr = lock(&self.nr);
        let more = nr
            .checked_add(events)
            .filter(|&more| more <= self.max())
            .ok_or(Errno::EAGAIN)?;
        *nr = more;
        Ok(())
    }
    /// `aio_nr_sub`.
    fn give(&self, events: u64) {
        let mut nr = lock(&self.nr);
        *nr = nr.saturating_sub(events);
    }
}

/// The ring's pages, which a mapping cannot reach past (Linux's file of the
/// ring has as many pages as the ring), named as Linux's `/proc/<pid>/maps`
/// names its file.
struct RingPages {
    size: u64,
}

impl PageSource for RingPages {
    fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
    /// Linux's `aio_ring_mmap` makes the ring `VM_DONTEXPAND`.
    fn fixed(&self) -> bool {
        true
    }
    /// `aio_ring_mmap_prepare` adds `VM_DONTEXPAND` and `VM_DONTCOPY`; the
    /// ring's file lies on a pseudo file system, which runs nothing.
    fn vma_flags(&self, flags: u64) -> u64 {
        use paludarium_mmu::vm;
        (flags | vm::DONTEXPAND | vm::DONTCOPY) & !vm::MAYEXEC
    }
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
    fn linked(&self) -> bool {
        false
    }
    fn name(&self) -> Option<Vec<u8>> {
        Some(b"/[aio] (deleted)".to_vec())
    }
    fn open_file(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

/// A request that waits for its file to be ready (`IOCB_CMD_POLL`).
struct Poll {
    /// The `iocb`'s address and its `aio_data`, which the event gives back.
    obj: u64,
    data: u64,
    file: Arc<dyn FileHandle>,
    /// What it waits for, `POLLERR` and `POLLHUP` always among them.
    events: u32,
    eventfd: Option<Arc<dyn FileHandle>>,
}

#[derive(Default)]
struct State {
    /// The kernel's tail (`ctx->tail`), which the ring's copy shows.
    tail: u32,
    /// The requests taken and not completed: the reads, writes and syncs
    /// under way and the polls that wait.
    in_flight: u32,
    polls: Vec<Poll>,
}

/// A context (`struct kioctx`).
pub(crate) struct Ring {
    /// Its index in the address space's table (`ctx->id`).
    id: u32,
    /// The events `io_setup` was asked for, which `aio-nr` counts.
    max_reqs: u32,
    /// The events the ring holds (`ctx->nr_events`).
    nr_events: u32,
    /// Where the ring is mapped, its ID (`ctx->user_id`), and its length.
    base: AtomicU64,
    mmap_size: u64,
    pages: SharedPages,
    open_file: usize,
    _source: Arc<RingPages>,
    dead: AtomicBool,
    limits: Arc<Limits>,
    /// Held while events are taken from the ring (`ctx->ring_lock`).
    reading: Mutex<()>,
    state: Mutex<State>,
}

/// How many polls wait in all the contexts of the machine, counted down as
/// they leave a context.
fn polls_left(limits: &Limits, count: usize) {
    if count > 0 {
        limits.polls.fetch_sub(count, Ordering::SeqCst);
    }
}

impl Ring {
    fn load(&self, at: u64) -> u32 {
        let mut b = [0; 4];
        self.pages.load(at, &mut b);
        u32::from_le_bytes(b)
    }

    fn store(&self, at: u64, value: u32) {
        self.pages.store(at, &value.to_le_bytes());
    }

    /// `aio_get_req`'s `get_reqs_available`: a request takes a place in the
    /// ring, which `nr_events - 1` of are free while none are taken; an
    /// event in the ring keeps its place until the head passes it. `EAGAIN`
    /// when none is free.
    fn take_slot(&self) -> Result<(), Errno> {
        let mut state = lock(&self.state);
        let head = self.load(RING_HEAD) % self.nr_events;
        let tail = state.tail;
        let in_ring = if head <= tail {
            tail - head
        } else {
            self.nr_events - (head - tail)
        };
        if state.in_flight + in_ring >= self.nr_events - 1 {
            return Err(Errno::EAGAIN);
        }
        state.in_flight += 1;
        Ok(())
    }

    fn release_slot(&self) {
        let mut state = lock(&self.state);
        state.in_flight = state.in_flight.saturating_sub(1);
    }

    /// `aio_complete`: puts the event at the tail, moves the tail on, and
    /// counts it on the request's eventfd.
    fn complete(&self, obj: u64, data: u64, res: i64, eventfd: Option<&Arc<dyn FileHandle>>) {
        {
            let mut state = lock(&self.state);
            let mut event = [0; EVENT_BYTES as usize];
            event[..8].copy_from_slice(&data.to_le_bytes());
            event[8..16].copy_from_slice(&obj.to_le_bytes());
            event[16..24].copy_from_slice(&res.to_le_bytes());
            let pos = u64::from(state.tail) + 1;
            self.pages.store(pos * EVENT_BYTES, &event);
            state.tail = if state.tail + 1 >= self.nr_events {
                0
            } else {
                state.tail + 1
            };
            self.store(RING_TAIL, state.tail);
            state.in_flight = state.in_flight.saturating_sub(1);
        }
        if let Some(counter) = eventfd
            .and_then(|file| file.as_any())
            .and_then(|any| any.downcast_ref::<crate::events::EventCounter>())
        {
            counter.signal();
        }
    }

    /// `aio_read_events_ring`: copies up to `nr` events from the head to
    /// `events` and moves the head past them, or `-EFAULT` (the head stays)
    /// if they cannot be written there. The head and tail are the ring's,
    /// which the program may have changed, taken modulo the events.
    fn read_ring(&self, c: &Context<'_>, events: u64, nr: i64) -> i64 {
        let _reading = lock(&self.reading);
        let (head, tail) = (self.load(RING_HEAD), self.load(RING_TAIL));
        if head == tail {
            return 0;
        }
        let (mut head, tail) = (head % self.nr_events, tail % self.nr_events);
        let mut ret = 0i64;
        while ret < nr && head != tail {
            let end = if head <= tail { tail } else { self.nr_events };
            let pos = head + 1;
            let avail = i64::from(end - head)
                .min(nr - ret)
                .min(i64::from(EVENTS_PER_PAGE - pos % EVENTS_PER_PAGE));
            let mut bytes = vec![0; avail as usize * EVENT_BYTES as usize];
            self.pages.load(u64::from(pos) * EVENT_BYTES, &mut bytes);
            let to = events.wrapping_add(ret as u64 * EVENT_BYTES);
            if c.mem.write(GuestAddr(to), &bytes).is_err() {
                return -i64::from(Errno::EFAULT.0);
            }
            ret += avail;
            head = (head + avail as u32) % self.nr_events;
        }
        self.store(RING_HEAD, head);
        ret
    }

    /// Completes the polls whose files are ready, each with what is ready.
    fn check_polls(&self) -> bool {
        let ready: Vec<(Poll, u32)> = {
            let mut state = lock(&self.state);
            let mut ready = Vec::new();
            let mut index = 0;
            while index < state.polls.len() {
                let poll = &state.polls[index];
                let mask = woken(&poll.file, polled(&poll.file).0, poll.events);
                if mask == 0 {
                    index += 1;
                } else {
                    ready.push((state.polls.remove(index), mask));
                }
            }
            ready
        };
        polls_left(&self.limits, ready.len());
        let any = !ready.is_empty();
        for (poll, mask) in ready {
            self.complete(poll.obj, poll.data, i64::from(mask), poll.eventfd.as_ref());
        }
        any
    }

    /// `aio_poll_cancel`: the poll of the `iocb` at `obj` completes with no
    /// events. Whether there was one.
    fn cancel(&self, obj: u64) -> bool {
        let poll = {
            let mut state = lock(&self.state);
            let index = state.polls.iter().position(|poll| poll.obj == obj);
            index.map(|index| state.polls.remove(index))
        };
        let Some(poll) = poll else {
            return false;
        };
        polls_left(&self.limits, 1);
        self.complete(poll.obj, poll.data, 0, poll.eventfd.as_ref());
        true
    }

    /// `kill_ioctx`: the context is no more (`EINVAL` if it was not), its
    /// events stop counting in `aio-nr`, its polls are cancelled, and
    /// `unmap`, the address space of `io_destroy`, loses the ring.
    fn kill(
        &self,
        table: &Table,
        unmap: Option<(&AddressSpace, &crate::mempolicy::Numa)>,
    ) -> Result<(), Errno> {
        if self.dead.swap(true, Ordering::SeqCst) {
            return Err(Errno::EINVAL);
        }
        {
            let mut rings = lock(&table.rings);
            if let Some(slot) = rings.get_mut(self.id as usize)
                && slot
                    .as_ref()
                    .is_some_and(|ring| std::ptr::eq(&**ring, self))
            {
                *slot = None;
            }
        }
        self.limits.give(u64::from(self.max_reqs));
        if let Some((mem, numa)) = unmap {
            let base = self.base.load(Ordering::SeqCst);
            let _ = mem.unmap_shared(GuestAddr(base), self.mmap_size);
            numa.forget(base, self.mmap_size);
        }
        let polls = std::mem::take(&mut lock(&self.state).polls);
        polls_left(&self.limits, polls.len());
        for poll in polls {
            self.complete(poll.obj, poll.data, 0, poll.eventfd.as_ref());
        }
        Ok(())
    }
}

/// The contexts of an address space (`mm->ioctx_table`), by index.
#[derive(Default)]
pub(crate) struct Table {
    rings: Mutex<Vec<Option<Arc<Ring>>>>,
}

impl Table {
    fn live(&self) -> Vec<Arc<Ring>> {
        lock(&self.rings).iter().flatten().cloned().collect()
    }
}

impl Drop for Table {
    /// `exit_aio`: the end of the address space ends its contexts, whose
    /// rings go with it.
    fn drop(&mut self) {
        for ring in self.live() {
            let _ = ring.kill(self, None);
        }
    }
}

/// A process's address space's contexts, which `CLONE_VM` shares.
#[derive(Default)]
pub(crate) struct Contexts {
    table: Mutex<Arc<Table>>,
}

impl Contexts {
    fn table(&self) -> Arc<Table> {
        Arc::clone(&lock(&self.table))
    }

    /// A new process: with `CLONE_VM` (`child_mem` is none) it shares the
    /// contexts; otherwise it has none, and `child_mem`, the copy of the
    /// parent's memory, loses the rings, which Linux does not copy.
    pub(crate) fn new_process(
        &self,
        child: &Contexts,
        child_mem: Option<&AddressSpace>,
        child_numa: &crate::mempolicy::Numa,
    ) {
        let table = self.table();
        let Some(mem) = child_mem else {
            *lock(&child.table) = table;
            return;
        };
        for ring in table.live() {
            for fragment in mem.shared_fragments() {
                if fragment.open_file == ring.open_file {
                    let len = fragment.end - fragment.start;
                    let _ = mem.unmap_shared(GuestAddr(fragment.start), len);
                    child_numa.forget(fragment.start, len);
                }
            }
        }
    }

    /// `execve` or the last thread's exit: the address space is let go of,
    /// and its contexts end with the last process that used it.
    pub(crate) fn release(&self) {
        let old = std::mem::take(&mut *lock(&self.table));
        drop(old);
    }
}

/// The context `ctx_id` names (`lookup_ioctx`): the index in the ring's
/// header at that address picks it from the table, and it must be live and
/// mapped there. A ring `mremap` moved whole is found at its new address, as
/// Linux's `aio_ring_mremap` moves the ID with it.
fn lookup(c: &Context<'_>, ctx_id: u64) -> Option<Arc<Ring>> {
    let mut id = [0; 4];
    c.mem.read(GuestAddr(ctx_id), &mut id).ok()?;
    let id = u32::from_le_bytes(id) as usize;
    let table = c.group.aio().table();
    let ring = lock(&table.rings).get(id)?.clone()?;
    if ring.dead.load(Ordering::SeqCst) {
        return None;
    }
    if ring.base.load(Ordering::SeqCst) != ctx_id {
        let moved = c.mem.shared_fragments().iter().any(|fragment| {
            fragment.start == ctx_id
                && fragment.open_file == ring.open_file
                && fragment.offset == 0
                && fragment.end - fragment.start == ring.mmap_size
        });
        if !moved {
            return None;
        }
        ring.base.store(ctx_id, Ordering::SeqCst);
    }
    Some(ring)
}

/// Completes the polls of the caller's contexts that are ready: before each
/// call, and as a call waits ([`crate::events::wait`]). Nothing while no
/// poll waits anywhere.
pub(crate) fn progress(c: &Context<'_>) {
    if c.processes.aio.polls.load(Ordering::SeqCst) == 0 {
        return;
    }
    let mut any = false;
    for ring in c.group.aio().table().live() {
        any |= ring.check_polls();
    }
    if any {
        c.files.readiness.changed();
    }
}

/// What `vfs_poll` gives of `file`, and how many wait queues its poll adds
/// a waiter to: none for a file without `poll` (a regular file, a
/// directory), which gives `DEFAULT_POLLMASK`; two for a FIFO open to read
/// and write and for a terminal, which wait on a queue for each. A pipe or
/// socket that is readable is `POLLRDNORM` too, and one that takes a write
/// `POLLWRNORM`, as Linux's `pipe_poll` and `unix_poll` say.
fn polled(file: &Arc<dyn FileHandle>) -> (u32, u32) {
    let Ok((mut mask, _, _)) = file.readiness() else {
        return (DEFAULT_POLLMASK, 0);
    };
    let kind = file.stat().map_or(0, |stat| stat.mode & S_IFMT);
    if matches!(kind, S_IFIFO | S_IFSOCK) {
        if mask & POLLIN != 0 {
            mask |= POLLRDNORM;
        }
        if mask & POLLOUT != 0 {
            mask |= POLLWRNORM;
        }
    }
    let queues = if (kind == S_IFIFO && file.flags() & 3 == 2) || kind == S_IFCHR {
        2
    } else {
        1
    };
    (mask, queues)
}

/// What a poll that waits completes with once `file` is ready (`mask`)
/// for some of its `events`: Linux's `aio_poll_wake` takes the key of the
/// wake-up whole, so that a pipe becoming readable gives `POLLIN |
/// POLLRDNORM` (`pipe_write`'s key) and a socket `POLLIN | POLLPRI |
/// POLLRDNORM | POLLRDBAND` (`sock_def_readable`'s), whatever was asked
/// for; taking a write likewise gives the writer's key. A file whose
/// wake-ups carry no key (a hang-up, a timerfd, ...) is polled again, and
/// gives what is ready among `events`.
fn woken(file: &Arc<dyn FileHandle>, mask: u32, events: u32) -> u32 {
    const POLLPRI: u32 = 0x2;
    const POLLRDBAND: u32 = 0x80;
    const POLLWRBAND: u32 = 0x200;
    let ready = mask & events;
    let kind = file.stat().map_or(0, |stat| stat.mode & S_IFMT);
    let counter = file
        .as_any()
        .is_some_and(|any| any.is::<crate::events::EventCounter>());
    let keyed = matches!(kind, S_IFIFO | S_IFSOCK) || counter;
    if !keyed || ready & (POLLIN | POLLOUT) == 0 {
        return ready;
    }
    let (input, output) = match kind {
        S_IFIFO => (POLLIN | POLLRDNORM, POLLOUT | POLLWRNORM),
        S_IFSOCK => (
            POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND,
            POLLOUT | POLLWRNORM | POLLWRBAND,
        ),
        // eventfd's `wake_up_locked_poll` keys.
        _ => (POLLIN, POLLOUT),
    };
    if ready & POLLIN != 0 { input } else { output }
}

/// Whether `file` has the `read_iter` (or with `write`, `write_iter`)
/// operation an aio read or write needs (`EINVAL` without): a directory,
/// an epoll instance, an io_uring ring, a pidfd and an inotify instance
/// have neither, and an eventfd, a signalfd and a timerfd only reads.
fn transfers(file: &Arc<dyn FileHandle>, write: bool) -> bool {
    if file.stat().is_ok_and(|stat| stat.mode & S_IFMT == S_IFDIR) {
        return false;
    }
    let Some(any) = file.as_any() else {
        return true;
    };
    if any.is::<crate::epoll::EpollInstance>()
        || any.is::<crate::io_uring::Ring>()
        || any.is::<crate::processes::PidFd>()
        || any.is::<crate::inotify::Instance>()
    {
        return false;
    }
    !(write
        && (any.is::<crate::events::EventCounter>()
            || any.is::<crate::signalfd::SignalFile>()
            || any.is::<crate::timerfd::TimerFile>()))
}

/// What `__io_submit_one` makes of a request.
enum Started {
    /// It ran: its result, for the event.
    Done(i64),
    /// It waits for its file (`IOCB_CMD_POLL`).
    Waiting(Arc<dyn FileHandle>, u32),
}

/// `struct iocb`, as `io_submit` reads it.
struct Iocb {
    data: u64,
    rw_flags: u32,
    opcode: u16,
    reqprio: i16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

impl Iocb {
    fn parse(b: &[u8; IOCB_BYTES]) -> Self {
        Self {
            data: u64_at(b, 0),
            rw_flags: u32_at(b, 12),
            opcode: u16_at(b, 16),
            reqprio: u16_at(b, 18) as i16,
            fildes: u32_at(b, 20),
            buf: u64_at(b, 24),
            nbytes: u64_at(b, 32),
            offset: u64_at(b, 40) as i64,
            reserved2: u64_at(b, 48),
            flags: u32_at(b, 56),
            resfd: u32_at(b, 60),
        }
    }
}

/// A descriptor as Linux's `fget` finds it, which an `O_PATH` one is not
/// (`EBADF`).
fn fget(c: &Context<'_>, fd: u32) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(u64::from(fd))?.file;
    if file.flags() & O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}

/// `io_submit_one`: reads the `iocb` at `user_iocb` (`EFAULT`), checks it
/// (`EINVAL`), takes a place in the ring (`EAGAIN`), and starts it.
fn submit_one(c: &mut Context<'_>, ring: &Ring, user_iocb: u64) -> Result<(), Errno> {
    let mut bytes = [0; IOCB_BYTES];
    c.mem
        .read(GuestAddr(user_iocb), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let iocb = Iocb::parse(&bytes);
    if iocb.reserved2 != 0 || (iocb.nbytes as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    ring.take_slot()?;
    let mut eventfd = None;
    match start(c, &iocb, user_iocb, &mut eventfd) {
        Err(e) => {
            ring.release_slot();
            Err(e)
        }
        Ok(Started::Done(res)) => {
            ring.complete(user_iocb, iocb.data, res, eventfd.as_ref());
            c.files.readiness.changed();
            Ok(())
        }
        Ok(Started::Waiting(file, events)) => {
            let poll = Poll {
                obj: user_iocb,
                data: iocb.data,
                file,
                events,
                eventfd,
            };
            // A context another thread ended meanwhile cancels it, as
            // Linux's `free_ioctx_users` cancels what it finds waiting.
            let cancelled = {
                let mut state = lock(&ring.state);
                if ring.dead.load(Ordering::SeqCst) {
                    Some(poll)
                } else {
                    ring.limits.polls.fetch_add(1, Ordering::SeqCst);
                    state.polls.push(poll);
                    None
                }
            };
            if let Some(poll) = cancelled {
                ring.complete(poll.obj, poll.data, 0, poll.eventfd.as_ref());
            }
            Ok(())
        }
    }
}

/// `__io_submit_one`: the file (`EBADF`), the eventfd of `IOCB_FLAG_RESFD`
/// (`EBADF`, `EINVAL` for another file), the `iocb`'s `aio_key` cleared
/// (`EFAULT`), then the operation, `EINVAL` for one Linux does not have
/// (`IOCB_CMD_NOOP` too).
fn start(
    c: &mut Context<'_>,
    iocb: &Iocb,
    user_iocb: u64,
    eventfd: &mut Option<Arc<dyn FileHandle>>,
) -> Result<Started, Errno> {
    let file = fget(c, iocb.fildes)?;
    if iocb.flags & FLAG_RESFD != 0 {
        let counter = fget(c, iocb.resfd)?;
        if !counter
            .as_any()
            .is_some_and(|any| any.is::<crate::events::EventCounter>())
        {
            return Err(Errno::EINVAL);
        }
        *eventfd = Some(counter);
    }
    c.mem
        .write(GuestAddr(user_iocb + IOCB_KEY), &0u32.to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    match iocb.opcode {
        CMD_PREAD => transfer(c, &file, iocb, false, false),
        CMD_PWRITE => transfer(c, &file, iocb, true, false),
        CMD_PREADV => transfer(c, &file, iocb, false, true),
        CMD_PWRITEV => transfer(c, &file, iocb, true, true),
        CMD_FSYNC | CMD_FDSYNC => {
            if iocb.buf != 0 || iocb.offset != 0 || iocb.nbytes != 0 || iocb.rw_flags != 0 {
                return Err(Errno::EINVAL);
            }
            // A file that cannot be synchronised has no `fsync` (`EINVAL`);
            // nothing is cached, so fsync and fdatasync are alike.
            match file.sync() {
                Err(e) if e == Errno::EINVAL => Err(Errno::EINVAL),
                result => Ok(Started::Done(
                    result.map_or_else(|e| -i64::from(e.0), |()| 0),
                )),
            }
        }
        CMD_POLL => {
            if iocb.buf > u64::from(u16::MAX)
                || iocb.offset != 0
                || iocb.nbytes != 0
                || iocb.rw_flags != 0
            {
                return Err(Errno::EINVAL);
            }
            let events = iocb.buf as u32 | POLLERR | POLLHUP;
            let (mask, queues) = polled(&file);
            let mask = mask & events;
            // A file whose poll adds no waiter, or more than one, is
            // `EINVAL` unless it is ready (`aio_poll_queue_proc`).
            if mask != 0 {
                Ok(Started::Done(i64::from(mask)))
            } else if queues == 1 {
                Ok(Started::Waiting(file, events))
            } else {
                Err(Errno::EINVAL)
            }
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `aio_read` and `aio_write`: `aio_prep_rw` (the I/O priority of
/// `IOCB_FLAG_IOPRIO`, then `aio_rw_flags`), the access mode (`EBADF`), the
/// operation (`EINVAL`), the buffer (`aio_buf` and `aio_nbytes`, or with
/// `vectored` an `iovec` array and its length: `EFAULT`, `EINVAL`), and the
/// range (`rw_verify_area`: `EINVAL` for a negative offset or an end past
/// the largest), then the transfer at `aio_offset`, whose result the event
/// gets.
fn transfer(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    iocb: &Iocb,
    write: bool,
    vectored: bool,
) -> Result<Started, Errno> {
    if iocb.flags & FLAG_IOPRIO != 0 {
        let caller = c.process.credentials.task_ids();
        crate::scheduling::check_ioprio(
            i32::from(iocb.reqprio),
            caller.capable(crate::credentials::CAP_SYS_NICE)
                || c.process.credentials.may_administer(),
        )?;
    }
    let flags = crate::files::kiocb_rw_flags(file, iocb.rw_flags)?;
    if file.flags() & 3 == if write { 0 } else { 1 } {
        return Err(Errno::EBADF);
    }
    if !transfers(file, write) {
        return Err(Errno::EINVAL);
    }
    let segments = if vectored {
        // `aio_setup_rw` hands `aio_nbytes` to `import_iovec`, whose count is
        // an `unsigned` before Linux 965e5e451146 (2026-11-05, not yet in the
        // kernel CI runs): only the low 32 bits count.
        let count = u64::from(iocb.nbytes as u32);
        crate::files::iovecs_checked(c.mem, iocb.buf, count, |_, _| Ok(()))?
    } else {
        // `import_ubuf`: the length cut to `MAX_RW_COUNT`, in the user half.
        let len = iocb.nbytes.min(crate::files::MAX_RW_COUNT as u64);
        crate::sockets::access_ok_u64(iocb.buf, len)?;
        vec![(iocb.buf, len as usize)]
    };
    let total = segments.iter().map(|&(_, len)| len as u64).sum::<u64>();
    if iocb.offset < 0 || iocb.offset.checked_add(total as i64).is_none() {
        return Err(Errno::EINVAL);
    }
    // A transfer a signal interrupts fails with EINTR (`aio_rw_done`).
    Ok(Started::Done(crate::files::aio_transfer(
        c,
        file,
        write,
        &segments,
        iocb.offset as u64,
        flags,
    )))
}

fn result(r: Result<u64, Errno>) -> Outcome {
    match r {
        Ok(v) => ok(v),
        Err(e) => err(e),
    }
}

/// `io_setup(nr_events, ctxp)`: `*ctxp` must be 0 (`EFAULT`, `EINVAL`) and
/// `nr_events` not; it is made at least four for each CPU and doubled, past
/// `0x8000000 / 32` is `EINVAL` and past `aio-max-nr` (alone or with the
/// machine's other contexts) `EAGAIN`. The ring is mapped where `mmap`
/// would put it, holding as many events as its pages do, and `*ctxp` gets
/// its address (`EFAULT` ends the new context).
pub(crate) fn sys_setup(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(setup(c, a[0] as u32, a[1]))
}

fn setup(c: &mut Context<'_>, nr_events: u32, ctxp: u64) -> Result<u64, Errno> {
    let ctx = c.mem.read_u64(GuestAddr(ctxp)).map_err(|_| Errno::EFAULT)?;
    if ctx != 0 || nr_events == 0 {
        return Err(Errno::EINVAL);
    }
    let max_reqs = nr_events;
    let cpus = crate::syscalls::active_cpus(c) as u32;
    let events = nr_events.max(cpus.saturating_mul(4));
    if events > MAX_EVENTS {
        return Err(Errno::EINVAL);
    }
    let limits = Arc::clone(&c.processes.aio);
    if u64::from(max_reqs) > limits.max() {
        return Err(Errno::EAGAIN);
    }
    // `aio_setup_ring`: two more for the head and tail, and as many as fit
    // in the pages.
    let events = events * 2 + 2;
    let pages = (HEADER_BYTES + EVENT_BYTES * u64::from(events)).div_ceil(PAGE);
    let mmap_size = pages * PAGE;
    let nr_events = ((mmap_size - HEADER_BYTES) / EVENT_BYTES) as u32;
    let source = Arc::new(RingPages { size: mmap_size });
    let shared = SharedPages::new().with_source(source.clone());
    let meter = c.mem.memory_meter();
    for key in (0..mmap_size).step_by(PAGE as usize) {
        shared.fill(key, &[], meter.as_ref())?;
    }
    let at = c
        .mem
        .map_shared(
            None,
            mmap_size,
            paludarium_mmu::Prot::READ_WRITE,
            paludarium_mmu::MappingKind::File,
        )
        .map_err(|_| Errno::ENOMEM)?;
    if c.mem
        .share_pages(
            at,
            mmap_size,
            &shared,
            0,
            paludarium_mmu::SharedWrites::Allowed,
        )
        .is_err()
    {
        let _ = c.mem.unmap_shared(at, mmap_size);
        return Err(Errno::ENOMEM);
    }
    c.group.numa().forget(at.0, mmap_size);
    let header = [
        (RING_NR, nr_events),
        (RING_ID, u32::MAX),
        (RING_MAGIC, AIO_RING_MAGIC),
        (RING_COMPAT_FEATURES, 1),
        (RING_INCOMPAT_FEATURES, 0),
        (RING_HEADER_LENGTH, HEADER_BYTES as u32),
    ];
    for (at, value) in header {
        shared.store(at, &value.to_le_bytes());
    }
    if let Err(e) = limits.take(u64::from(max_reqs)) {
        let _ = c.mem.unmap_shared(at, mmap_size);
        c.group.numa().forget(at.0, mmap_size);
        return Err(e);
    }
    // `ioctx_add_table`: the lowest free index.
    let table = c.group.aio().table();
    let ring = {
        let mut rings = lock(&table.rings);
        let id = rings
            .iter()
            .position(Option::is_none)
            .unwrap_or(rings.len());
        let ring = Arc::new(Ring {
            id: id as u32,
            max_reqs,
            nr_events,
            base: AtomicU64::new(at.0),
            mmap_size,
            pages: shared,
            open_file: source.open_file(),
            _source: source,
            dead: AtomicBool::new(false),
            limits,
            reading: Mutex::default(),
            state: Mutex::default(),
        });
        if id == rings.len() {
            rings.push(Some(Arc::clone(&ring)));
        } else {
            rings[id] = Some(Arc::clone(&ring));
        }
        ring
    };
    ring.store(RING_ID, ring.id);
    if c.mem.write(GuestAddr(ctxp), &at.0.to_le_bytes()).is_err() {
        let _ = ring.kill(&table, Some((c.mem, c.group.numa())));
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// `io_destroy(ctx)`: `EINVAL` for no context; it ends, its ring is
/// unmapped, its polls are cancelled (their events go to the ring no
/// mapping shows any more), and the call waits for the reads and writes
/// under way in other threads to end.
pub(crate) fn sys_destroy(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(destroy(c, a[0]))
}

fn destroy(c: &mut Context<'_>, ctx: u64) -> Result<u64, Errno> {
    let ring = lookup(c, ctx).ok_or(Errno::EINVAL)?;
    let table = c.group.aio().table();
    ring.kill(&table, Some((c.mem, c.group.numa())))?;
    c.files.readiness.changed();
    // `wait_for_completion`, which no signal ends.
    while lock(&ring.state).in_flight > 0 {
        let ticket = c.files.readiness.token.value();
        if lock(&ring.state).in_flight == 0 {
            break;
        }
        let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
        if crate::events::wait(c, ticket, Some(now + 1_000_000)).is_err() {
            c.host.wait_until(
                paludarium_host::ClockId::Monotonic,
                now + 1_000_000,
                c.cancellation,
            )?;
        }
    }
    Ok(0)
}

/// `io_submit(ctx_id, nr, iocbpp)`: `EINVAL` for a negative `nr` or no
/// context; at most as many requests as the ring holds are taken, in order,
/// until one fails. It gives how many were, or the first one's error.
pub(crate) fn sys_submit(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(submit(c, a[0], a[1] as i64, a[2]))
}

fn submit(c: &mut Context<'_>, ctx_id: u64, nr: i64, iocbpp: u64) -> Result<u64, Errno> {
    if nr < 0 {
        return Err(Errno::EINVAL);
    }
    let ring = lookup(c, ctx_id).ok_or(Errno::EINVAL)?;
    let nr = nr.min(i64::from(ring.nr_events)) as u64;
    let mut error = Ok(());
    let mut done = 0;
    while done < nr {
        let error_here = c
            .mem
            .read_u64(GuestAddr(iocbpp.wrapping_add(8 * done)))
            .map_err(|_| Errno::EFAULT)
            .and_then(|iocb| submit_one(c, &ring, iocb));
        if let Err(e) = error_here {
            error = Err(e);
            break;
        }
        done += 1;
    }
    if done > 0 {
        return Ok(done);
    }
    error.map(|()| 0)
}

/// `io_cancel(ctx_id, iocb, result)`: the `iocb`'s `aio_key` must be 0
/// (`EFAULT`, `EINVAL`), and the context exist (`EINVAL`). Only a poll that
/// waits can be cancelled: its event (with no events) goes to the ring and
/// the call gives `EINPROGRESS`, as since Linux 6.8; for any other request
/// `EINVAL`. `result` is not written.
pub(crate) fn sys_cancel(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(cancel(c, a[0], a[1]))
}

fn cancel(c: &mut Context<'_>, ctx_id: u64, iocb: u64) -> Result<u64, Errno> {
    let mut key = [0; 4];
    c.mem
        .read(GuestAddr(iocb.wrapping_add(IOCB_KEY)), &mut key)
        .map_err(|_| Errno::EFAULT)?;
    if u32::from_le_bytes(key) != 0 {
        return Err(Errno::EINVAL);
    }
    let ring = lookup(c, ctx_id).ok_or(Errno::EINVAL)?;
    if ring.cancel(iocb) {
        c.files.readiness.changed();
        return Err(EINPROGRESS);
    }
    Err(Errno::EINVAL)
}

/// A timeout of `io_getevents`, as `timespec64_to_ktime` makes it: `None`
/// for none or one past `KTIME_SEC_MAX` seconds, else nanoseconds, which
/// may be 0 (no wait) or negative, which waits as none does (as Linux on
/// CI does: its sleeper's timer never ends the wait).
fn timeout(c: &Context<'_>, at: u64) -> Result<Option<Option<i64>>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    let sec = c.mem.read_u64(GuestAddr(at)).map_err(|_| Errno::EFAULT)? as i64;
    let nsec = c
        .mem
        .read_u64(GuestAddr(at.wrapping_add(8)))
        .map_err(|_| Errno::EFAULT)? as i64;
    const KTIME_SEC_MAX: i64 = i64::MAX / 1_000_000_000;
    Ok(Some(if sec >= KTIME_SEC_MAX {
        None
    } else {
        Some(sec.wrapping_mul(1_000_000_000).wrapping_add(nsec))
    }))
}

/// `aio_read_events`: takes what events it can after the `got` it has, and
/// says whether to stop: an error, `min_nr` reached, or a dead context
/// (`EINVAL` if it has none).
fn read_some(
    c: &Context<'_>,
    ring: &Ring,
    min_nr: i64,
    nr: i64,
    events: u64,
    got: &mut i64,
) -> bool {
    let mut ret = ring.read_ring(c, events.wrapping_add(*got as u64 * EVENT_BYTES), nr - *got);
    if ret > 0 {
        *got += ret;
    }
    if ring.dead.load(Ordering::SeqCst) {
        ret = -i64::from(Errno::EINVAL.0);
    }
    if *got == 0 {
        *got = ret;
    }
    ret < 0 || *got >= min_nr
}

/// `do_io_getevents` and `read_events`: `EINVAL` for no context or a
/// `min_nr` that is negative or past `nr`; then the events there are, and
/// unless that is `min_nr` or there is no time to wait, the call waits for
/// more until it has them, the time is up, a signal comes, or the context
/// ends. It gives how many it took, or an error if it took none.
fn get_events(
    c: &mut Context<'_>,
    ctx_id: u64,
    min_nr: i64,
    nr: i64,
    events: u64,
    until: Option<Option<i64>>,
) -> i64 {
    let Some(ring) = lookup(c, ctx_id) else {
        return -i64::from(Errno::EINVAL.0);
    };
    if !(min_nr <= nr && min_nr >= 0) {
        return -i64::from(Errno::EINVAL.0);
    }
    let until = until.unwrap_or(None);
    let mut got = 0;
    read_some(c, &ring, min_nr, nr, events, &mut got);
    if until == Some(0) || got < 0 || got >= min_nr {
        return got;
    }
    let Ok(now) = c.host.clock(paludarium_host::ClockId::Monotonic) else {
        return got;
    };
    let deadline = until
        .filter(|&nanos| nanos > 0)
        .map(|nanos| now.saturating_add(nanos as u64));
    let mut interrupted = false;
    loop {
        let ticket = c.files.readiness.token.value();
        progress(c);
        let over = deadline.is_some_and(|end| {
            c.host
                .clock(paludarium_host::ClockId::Monotonic)
                .is_ok_and(|now| now >= end)
        });
        let stop = interrupted || over || crate::events::signalled(c);
        if read_some(c, &ring, min_nr, nr, events, &mut got) || stop {
            break;
        }
        if crate::events::wait(c, ticket, deadline).is_err() {
            interrupted = true;
        }
    }
    got
}

/// `io_getevents(ctx_id, min_nr, nr, events, timeout)`: see
/// [`get_events`]; no event and a signal is `EINTR`, which is never
/// restarted.
pub(crate) fn sys_getevents(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let until = match timeout(c, a[4]) {
        Ok(until) => until,
        Err(e) => return err(e),
    };
    let got = get_events(c, a[0], a[1] as i64, a[2] as i64, a[3], until);
    if got == 0 && crate::events::signalled(c) {
        return err(EINTR);
    }
    if got < 0 {
        return err(Errno((-got) as i32));
    }
    ok(got as u64)
}

/// `io_pgetevents(ctx_id, min_nr, nr, events, timeout, usig)`:
/// [`sys_getevents`] with `usig`'s signal mask (`{ sigmask, sigsetsize }`:
/// `EFAULT`, and `EINVAL` for a size that is not a `sigset_t`'s) in place
/// while it runs. No event and a signal is `ERESTARTNOHAND`: `EINTR` for a
/// handler, else the call runs again. With a signal to handle the mask
/// stays for the handler, and the old one comes back after it.
pub(crate) fn sys_pgetevents(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(pgetevents(c, a))
}

fn pgetevents(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let until = timeout(c, a[4])?;
    let (sigmask, sigsetsize) = if a[5] == 0 {
        (0, 0)
    } else {
        let read = |at: u64| c.mem.read_u64(GuestAddr(at)).map_err(|_| Errno::EFAULT);
        (read(a[5])?, read(a[5].wrapping_add(8))?)
    };
    let mask = if sigmask == 0 {
        None
    } else {
        if sigsetsize != 8 {
            return Err(Errno::EINVAL);
        }
        Some(
            c.mem
                .read_u64(GuestAddr(sigmask))
                .map_err(|_| Errno::EFAULT)?,
        )
    };
    let old_mask = c.process.signal_mask;
    if let Some(mask) = mask {
        c.process.signal_mask = mask & !crate::signals::unblockable();
    }
    let got = get_events(c, a[0], a[1] as i64, a[2] as i64, a[3], until);
    let interrupted = crate::events::signalled(c);
    if mask.is_some() {
        if interrupted && crate::signals::next_pending(c.process, true).is_some() {
            c.process.wait_restore_mask = Some(old_mask);
        } else {
            c.process.signal_mask = old_mask;
        }
    }
    if interrupted && got == 0 {
        return Err(EINTR);
    }
    if got < 0 {
        return Err(Errno((-got) as i32));
    }
    Ok(got as u64)
}
