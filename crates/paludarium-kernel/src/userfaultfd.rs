//! `userfaultfd(2)`: a file through which a thread handles the faults of
//! others on the memory it registered, as Linux's `fs/userfaultfd.c` and
//! `mm/userfaultfd.c` have it.
//!
//! A context belongs to the address space it was made in (Linux's
//! `ctx->mm`), whoever holds its file. `UFFDIO_API` takes the features,
//! once; `UFFDIO_REGISTER` registers private anonymous memory and shmem
//! (shared memory of no file, a memfd) for missing pages and for write
//! protection ([`paludarium_mmu::Userfault`]). An instruction that
//! touches such a page, which has none, or that writes to a page
//! `UFFDIO_WRITEPROTECT` or `UFFDIO_COPY_MODE_WP` protected, stops: its
//! thread waits in the context, whose file reads the fault as a
//! `uffd_msg`, until `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` fills the page or
//! `UFFDIO_WRITEPROTECT` ends its protection, `UFFDIO_WAKE` or (for a
//! missing page) `UFFDIO_UNREGISTER` ends the wait, the file is closed, or
//! a signal comes; then the instruction runs again, as Linux's
//! `handle_userfault` gives `VM_FAULT_RETRY`. With `UFFD_FEATURE_SIGBUS`
//! the fault raises SIGBUS instead. A system call's own copy to or from
//! such a page waits as an instruction does ([`KernelCopies`]), unless the
//! context took `UFFD_USER_MODE_ONLY` (`EFAULT`).
//!
//! `UFFDIO_POISON` poisons pages that have none: an access to one raises
//! SIGBUS (`BUS_MCEERR_AR`), registered or not, as Linux's poison marker
//! gives `VM_FAULT_HWPOISON`, until a discard or an unmap drops it.
//!
//! `UFFDIO_MOVE` moves private anonymous pages, of the context's own
//! space, into a registered range that has none, as Linux's `move_pages`
//! does ([`paludarium_mmu::MemoryView::userfault_move`]).
//!
//! The minor mode registers shmem (shared memory, a memfd): an access to
//! a page its page cache has but the mapping has no entry for waits, as
//! Linux's `shmem_get_folio_gfp` gives `handle_userfault` with
//! `VM_UFFD_MINOR`, until `UFFDIO_CONTINUE` maps the page.
//!
//! `UFFDIO_WRITEPROTECT` protects the pages of shmem that have no entry
//! too, and with `UFFD_FEATURE_WP_UNPOPULATED` those of private anonymous
//! memory, with Linux's uffd-wp markers: the entry an access makes for
//! such a page is write-protected, and a discard of shmem keeps the
//! protection of its pages.
//!
//! With `UFFD_FEATURE_WP_ASYNC` (which brings `UFFD_FEATURE_WP_UNPOPULATED`)
//! a write to a write-protected page does not fault: it clears the
//! protection and goes on, as Linux's `do_wp_page` does, so that
//! `/proc/<pid>/pagemap`'s `PM_UFFD_WP` tells which pages were written.
//! Registered for write protection alone, any memory takes it, a file's
//! mapping too, whose discarded pages keep their protection.
//!
//! The events tell the context of changes to its space, as Linux's
//! non-cooperative mode does: with `UFFD_FEATURE_EVENT_FORK` a `fork`ed
//! child keeps the registrations, in a new context of its own that a read
//! of the old one hands over as a new file (`UFFD_EVENT_FORK`); with
//! `UFFD_FEATURE_EVENT_REMAP` a mapping `mremap` moves keeps them
//! (`UFFD_EVENT_REMAP`); `UFFD_FEATURE_EVENT_REMOVE` reports the ranges
//! `MADV_DONTNEED`, `MADV_DONTNEED_LOCKED`, `MADV_FREE` and `MADV_REMOVE`
//! are about to drop (`UFFD_EVENT_REMOVE`), and `UFFD_FEATURE_EVENT_UNMAP`
//! those `munmap`, `mremap`, `brk` and a `MAP_FIXED` `mmap` unmapped
//! (`UFFD_EVENT_UNMAP`). The thread that made the change waits until the
//! event is read, the file closed or a fatal signal comes, as Linux's
//! `userfaultfd_event_wait_completion` (`TASK_KILLABLE`); a read takes the
//! faults before the events, and until it does, the fills, moves and
//! changes of protection are `EAGAIN` (`mmap_changing`).

use crate::events::{IN, ReadinessHub};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{MemoryView, UserfaultReason};
use paludarium_types::{Errno, GuestAddr, USER_ADDRESS_LIMIT};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

/// `UFFD_API`, the only version of the interface.
const API: u64 = 0xaa;
/// `UFFD_USER_MODE_ONLY`: faults of the kernel's own accesses are not the
/// context's.
const USER_MODE_ONLY: u32 = 1;
const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u32 = 0o2000000;
const O_ASYNC: u32 = crate::fasync::O_ASYNC;
/// `POLLERR`.
const ERR: u32 = 8;
const CAP_SYS_PTRACE: u64 = 1 << 19;
const PAGE: u64 = 4096;

/// `UFFD_FEATURE_PAGEFAULT_FLAG_WP`: faults of write-protected pages are
/// reported, with [`PAGEFAULT_FLAG_WP`].
const FEATURE_PAGEFAULT_FLAG_WP: u64 = 1 << 0;
/// `UFFD_FEATURE_EVENT_FORK`, which needs `CAP_SYS_PTRACE`: a child keeps
/// the registrations, in a context of its own ([`fork`]).
const FEATURE_EVENT_FORK: u64 = 1 << 1;
/// `UFFD_FEATURE_EVENT_REMAP`: a mapping `mremap` moves keeps its
/// registration ([`remap`]).
const FEATURE_EVENT_REMAP: u64 = 1 << 2;
/// `UFFD_FEATURE_EVENT_REMOVE`: the discards are reported ([`remove`]).
const FEATURE_EVENT_REMOVE: u64 = 1 << 3;
const FEATURE_MISSING_HUGETLBFS: u64 = 1 << 4;
const FEATURE_MISSING_SHMEM: u64 = 1 << 5;
/// `UFFD_FEATURE_EVENT_UNMAP`: the unmaps are reported ([`unmap`]).
const FEATURE_EVENT_UNMAP: u64 = 1 << 6;
/// `UFFD_FEATURE_SIGBUS`: a fault raises SIGBUS rather than waiting.
const FEATURE_SIGBUS: u64 = 1 << 7;
/// `UFFD_FEATURE_THREAD_ID`: a fault's message names its thread.
const FEATURE_THREAD_ID: u64 = 1 << 8;
/// `UFFD_FEATURE_MINOR_HUGETLBFS` and `UFFD_FEATURE_MINOR_SHMEM`: the minor
/// mode is there, which works whether a context asked for them or not.
const FEATURE_MINOR_HUGETLBFS: u64 = 1 << 9;
const FEATURE_MINOR_SHMEM: u64 = 1 << 10;
/// `UFFD_FEATURE_EXACT_ADDRESS`: a fault's message has the address
/// itself, not its page's.
const FEATURE_EXACT_ADDRESS: u64 = 1 << 11;
/// `UFFD_FEATURE_WP_HUGETLBFS_SHMEM`: shmem takes the write-protect mode,
/// whether a context asked for it or not, as Linux's does.
const FEATURE_WP_HUGETLBFS_SHMEM: u64 = 1 << 12;
/// `UFFD_FEATURE_WP_UNPOPULATED`: `UFFDIO_WRITEPROTECT` protects the pages
/// of private anonymous memory that have none too
/// ([`paludarium_mmu::Userfault::WP_UNPOPULATED`]).
const FEATURE_WP_UNPOPULATED: u64 = 1 << 13;
/// `UFFD_FEATURE_POISON`: `UFFDIO_POISON` is there.
const FEATURE_POISON: u64 = 1 << 14;
/// `UFFD_FEATURE_WP_ASYNC`, which takes `UFFD_FEATURE_WP_UNPOPULATED`: a
/// write to a write-protected page clears the protection rather than
/// faulting ([`paludarium_mmu::Userfault::WP_ASYNC`]).
const FEATURE_WP_ASYNC: u64 = 1 << 15;
/// `UFFD_FEATURE_MOVE`: `UFFDIO_MOVE` is there, which works whether a
/// context asked for it or not, as Linux's does.
const FEATURE_MOVE: u64 = 1 << 16;
/// The features `UFFDIO_API` offers.
const FEATURES: u64 = FEATURE_PAGEFAULT_FLAG_WP
    | FEATURE_EVENT_FORK
    | FEATURE_EVENT_REMAP
    | FEATURE_EVENT_REMOVE
    | FEATURE_MISSING_HUGETLBFS
    | FEATURE_MISSING_SHMEM
    | FEATURE_EVENT_UNMAP
    | FEATURE_SIGBUS
    | FEATURE_THREAD_ID
    | FEATURE_MINOR_HUGETLBFS
    | FEATURE_MINOR_SHMEM
    | FEATURE_EXACT_ADDRESS
    | FEATURE_WP_HUGETLBFS_SHMEM
    | FEATURE_WP_UNPOPULATED
    | FEATURE_POISON
    | FEATURE_WP_ASYNC
    | FEATURE_MOVE;
/// The context's features once `UFFDIO_API` took them
/// (`UFFD_FEATURE_INITIALIZED`).
const INITIALIZED: u32 = 1 << 31;

/// The ioctls of a context (`UFFD_API_IOCTLS`): `UFFDIO_REGISTER`,
/// `UFFDIO_UNREGISTER` and `UFFDIO_API`, by their numbers.
const API_IOCTLS: u64 = 1 << 0 | 1 << 1 | 1 << 0x3f;
/// The ioctls of a registered range: `UFFDIO_WAKE`, `UFFDIO_COPY`,
/// `UFFDIO_ZEROPAGE`, `UFFDIO_MOVE` and `UFFDIO_POISON`, and
/// [`WRITEPROTECT_IOCTL`] for one registered for write protection.
const RANGE_IOCTLS: u64 = 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 8;
/// `UFFDIO_WRITEPROTECT`, by its number.
const WRITEPROTECT_IOCTL: u64 = 1 << 6;
/// `UFFDIO_CONTINUE`, by its number, for a range registered for minor
/// faults.
const CONTINUE_IOCTL: u64 = 1 << 7;

const UFFDIO_API: u32 = 0xc018_aa3f;
const UFFDIO_REGISTER: u32 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u32 = 0x8010_aa01;
const UFFDIO_WAKE: u32 = 0x8010_aa02;
const UFFDIO_COPY: u32 = 0xc028_aa03;
const UFFDIO_ZEROPAGE: u32 = 0xc020_aa04;
const UFFDIO_MOVE: u32 = 0xc028_aa05;
const UFFDIO_WRITEPROTECT: u32 = 0xc018_aa06;
const UFFDIO_POISON: u32 = 0xc020_aa08;
const UFFDIO_CONTINUE: u32 = 0xc020_aa07;

/// `UFFDIO_REGISTER_MODE_WP`.
const MODE_WP: u64 = 2;
/// `UFFDIO_REGISTER_MODE_MINOR`.
const MODE_MINOR: u64 = 4;
/// `UFFDIO_REGISTER_MODE_MISSING`, `_WP` and `_MINOR`.
const MODES: u64 = 7;
/// `UFFDIO_COPY_MODE_DONTWAKE`, which `UFFDIO_ZEROPAGE` and
/// `UFFDIO_POISON` have as well.
const DONTWAKE: u64 = 1;
/// `UFFDIO_COPY_MODE_WP`.
const COPY_MODE_WP: u64 = 2;
/// `UFFDIO_WRITEPROTECT_MODE_WP` and `_DONTWAKE`.
const WRITEPROTECT_MODE_WP: u64 = 1;
const WRITEPROTECT_MODE_DONTWAKE: u64 = 2;
/// `UFFDIO_MOVE_MODE_DONTWAKE` and `_ALLOW_SRC_HOLES`.
const MOVE_MODE_DONTWAKE: u64 = 1;
const MOVE_MODE_ALLOW_SRC_HOLES: u64 = 2;

/// `UFFD_EVENT_PAGEFAULT`.
const EVENT_PAGEFAULT: u8 = 0x12;
/// `UFFD_EVENT_FORK`, `UFFD_EVENT_REMAP`, `UFFD_EVENT_REMOVE` and
/// `UFFD_EVENT_UNMAP`.
const EVENT_FORK: u8 = 0x13;
const EVENT_REMAP: u8 = 0x14;
const EVENT_REMOVE: u8 = 0x15;
const EVENT_UNMAP: u8 = 0x16;
/// `UFFD_PAGEFAULT_FLAG_WRITE`.
const PAGEFAULT_FLAG_WRITE: u64 = 1;
/// `UFFD_PAGEFAULT_FLAG_WP`: the page was write-protected.
const PAGEFAULT_FLAG_WP: u64 = 2;
/// `UFFD_PAGEFAULT_FLAG_MINOR`: the page cache has the page.
const PAGEFAULT_FLAG_MINOR: u64 = 4;
/// The size of a `uffd_msg`.
const MESSAGE: usize = 32;

/// Where a read puts each message it takes: `read(2)`'s buffer, or the
/// guest's memory.
type Put<'a> = dyn FnMut(&mut Context<'_>, &[u8; MESSAGE]) -> Result<(), Errno> + 'a;

/// The contexts by number, which a registered mapping names
/// ([`paludarium_mmu::Userfault::context`]).
static CONTEXTS: Mutex<BTreeMap<u64, Weak<Userfaultfd>>> = Mutex::new(BTreeMap::new());
/// The number of the next context.
static NEXT: AtomicU64 = AtomicU64::new(1);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A context (Linux's `userfaultfd_ctx`), which its file and the threads
/// that wait in it hold.
pub(crate) struct Userfaultfd {
    id: u64,
    /// What `UFFDIO_API` took, with [`INITIALIZED`]; 0 until then.
    features: AtomicU32,
    /// The space it belongs to.
    memory: MemoryView,
    hub: Arc<ReadinessHub>,
    state: Mutex<State>,
    /// Its file was closed (`ctx->released`).
    released: AtomicBool,
    /// The flags `userfaultfd` took (`ctx->flags`), which the file a fork's
    /// event hands over takes too.
    flags: u32,
    /// The events made and not yet read (`mmap_changing`).
    changing: AtomicU32,
}

#[derive(Default)]
struct State {
    /// The faults not read yet, oldest first (`fault_pending_wqh`).
    pending: VecDeque<Arc<Waiting>>,
    /// The faults read whose threads still wait (`fault_wqh`).
    read: Vec<Arc<Waiting>>,
    /// The events not read yet, oldest first (`event_wqh`).
    events: VecDeque<Arc<Event>>,
    /// Moves on with each fault that comes, for `epoll`.
    epoch: u64,
}

/// A thread waiting for its event to be read (`userfaultfd_wait_queue` on
/// `event_wqh`).
struct Event {
    /// Its `uffd_msg`; a fork's file is not in it yet.
    message: [u8; MESSAGE],
    /// The child's context, which a fork's event hands over.
    child: Option<Arc<Userfaultfd>>,
    /// It was read, or its thread gave up on it, under [`State`]'s lock.
    done: AtomicBool,
    abandoned: AtomicBool,
    /// What the thread waits on.
    hub: Arc<ReadinessHub>,
}

/// What a read takes ([`Userfaultfd::take`]).
enum Taken {
    Message([u8; MESSAGE]),
    /// A fork's event, out of the queue while its file is made.
    Fork(Arc<Event>),
}

/// A thread waiting for a page (`userfaultfd_wait_queue`).
struct Waiting {
    /// The `uffd_msg`'s address and flags, and the thread's ID in its own
    /// PID namespace, or 0.
    address: u64,
    flags: u64,
    thread: u32,
    /// The wait has ended (`uwq->waken`).
    woken: AtomicBool,
    /// What the thread waits on.
    hub: Arc<ReadinessHub>,
}

impl Waiting {
    /// Its `uffd_msg`.
    fn message(&self) -> [u8; MESSAGE] {
        let mut message = [0; MESSAGE];
        message[0] = EVENT_PAGEFAULT;
        message[8..16].copy_from_slice(&self.flags.to_le_bytes());
        message[16..24].copy_from_slice(&self.address.to_le_bytes());
        message[24..28].copy_from_slice(&self.thread.to_le_bytes());
        message
    }
}

impl Userfaultfd {
    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }
    fn features(&self) -> u64 {
        u64::from(self.features.load(Ordering::SeqCst))
    }
    fn initialized(&self) -> bool {
        self.features.load(Ordering::SeqCst) & INITIALIZED != 0
    }
    /// An event of the context is not read yet (`mmap_changing`).
    fn changing(&self) -> bool {
        self.changing.load(Ordering::SeqCst) != 0
    }
    /// Ends the waits for the pages of `[start, start + len)`, or all of
    /// them for a `len` of 0, as Linux's `userfaultfd_wake_function` takes
    /// a fault whose message's address lies there.
    fn wake(&self, start: u64, len: u64) {
        let mut hubs = Vec::new();
        {
            let mut state = self.state();
            let mut take = |waiting: &Arc<Waiting>| {
                let inside =
                    len == 0 || (start <= waiting.address && waiting.address - start < len);
                if inside {
                    waiting.woken.store(true, Ordering::SeqCst);
                    hubs.push(Arc::clone(&waiting.hub));
                }
                !inside
            };
            state.pending.retain(&mut take);
            state.read.retain(&mut take);
        }
        for hub in hubs {
            hub.changed();
        }
    }
    /// Takes the oldest fault not read yet, which stays waiting, as
    /// Linux's `userfaultfd_ctx_read` moves it to `fault_wqh`; with none,
    /// the oldest event, whose thread goes on unless it is a fork's.
    fn take(&self) -> Option<Taken> {
        let mut state = self.state();
        if let Some(waiting) = state.pending.pop_front() {
            let message = waiting.message();
            state.read.push(waiting);
            return Some(Taken::Message(message));
        }
        let event = state.events.pop_front()?;
        if event.child.is_some() {
            return Some(Taken::Fork(event));
        }
        drop(state);
        event.done.store(true, Ordering::SeqCst);
        event.hub.changed();
        Some(Taken::Message(event.message))
    }
    /// Its file was closed: its mappings leave it and its waits end
    /// (`userfaultfd_release`).
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.memory.userfault_release(self.id);
        self.wake(0, 0);
        let hubs: Vec<_> = self
            .state()
            .events
            .iter()
            .map(|event| Arc::clone(&event.hub))
            .collect();
        for hub in hubs {
            hub.changed();
        }
        self.hub.changed();
    }
    /// What `/proc/<pid>/fdinfo` shows of it (`userfaultfd_show_fdinfo`).
    fn fdinfo(&self) -> Vec<u8> {
        let (pending, total) = {
            let state = self.state();
            (state.pending.len(), state.pending.len() + state.read.len())
        };
        format!(
            "pending:\t{pending}\ntotal:\t{total}\nAPI:\t{API:x}:{:x}:{:x}\n",
            self.features.load(Ordering::SeqCst),
            API_IOCTLS | RANGE_IOCTLS | WRITEPROTECT_IOCTL | CONTINUE_IOCTL
        )
        .into_bytes()
    }
}

impl Drop for Userfaultfd {
    fn drop(&mut self) {
        lock(&CONTEXTS).remove(&self.id);
    }
}

/// The context numbered `id`, while it lives.
pub(crate) fn find(id: u64) -> Option<Arc<Userfaultfd>> {
    lock(&CONTEXTS).get(&id)?.upgrade()
}

/// The file of a context (`[userfaultfd]`), whose last close releases it.
pub(crate) struct UserfaultFile {
    context: Arc<Userfaultfd>,
    /// `O_NONBLOCK` and `O_ASYNC`, which `fcntl` sets.
    status: AtomicU32,
    /// Its close releases the context: not so for a fork's file that found
    /// no room ([`hand_over`]).
    owns: AtomicBool,
    /// Its own anonymous inode's status (`anon_inode_create_getfile`).
    stat: FileStat,
}

impl Drop for UserfaultFile {
    fn drop(&mut self) {
        if self.owns.load(Ordering::SeqCst) {
            self.context.release();
        }
    }
}

/// The context `file` is the file of, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&UserfaultFile> {
    file.as_any()?.downcast_ref::<UserfaultFile>()
}

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// `userfaultfd(flags)`, as Linux checks it (`userfaultfd_syscall_allowed`):
/// one that also takes the kernel's own faults needs `CAP_SYS_PTRACE` unless
/// `vm.unprivileged_userfaultfd` is 1 (`EPERM`), before its flags are
/// checked (`EINVAL`).
pub(crate) fn sys_userfaultfd(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let flags = a[0] as u32;
    if flags & USER_MODE_ONLY == 0
        && !c.process.credentials.capable(CAP_SYS_PTRACE)
        && !c.processes.sysctls.unprivileged_userfaultfd()
    {
        return outcome(Err(Errno::EPERM));
    }
    outcome(create(c, flags))
}

/// `new_userfaultfd`: a context of `flags` (`EINVAL` for any other).
fn create(c: &mut Context<'_>, flags: u32) -> Result<u64, Errno> {
    if flags & !(O_CLOEXEC | O_NONBLOCK | USER_MODE_ONLY) != 0 {
        return Err(Errno::EINVAL);
    }
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    let context = Arc::new(Userfaultfd {
        id,
        features: AtomicU32::new(0),
        memory: c.mem.view(),
        hub: Arc::clone(&c.files.readiness),
        state: Mutex::default(),
        released: AtomicBool::new(false),
        flags,
        changing: AtomicU32::new(0),
    });
    lock(&CONTEXTS).insert(id, Arc::downgrade(&context));
    let file = Arc::new(UserfaultFile {
        context,
        status: AtomicU32::new(flags & O_NONBLOCK),
        owns: AtomicBool::new(true),
        stat: crate::files::own_anonymous_inode(&c.process.credentials),
    });
    c.files
        .install(file, flags & O_CLOEXEC != 0, c.group.nofile())
        .map(u64::from)
}

/// The access of an instruction that faults to a `userfaultfd`
/// ([`fault`]).
#[derive(Clone, Copy)]
pub(crate) struct Access {
    pub(crate) address: u64,
    pub(crate) write: bool,
    pub(crate) fetch: bool,
    /// Why it waits.
    pub(crate) reason: UserfaultReason,
}

impl Access {
    /// Whether the access still faults to the context numbered `id` as it
    /// did.
    fn faults(&self, c: &Context<'_>, id: u64) -> bool {
        c.mem
            .userfault_for(GuestAddr(self.address), self.write, self.fetch)
            == Some((id, self.reason))
    }
}

/// The fault of an instruction of the calling thread (`access`) on a page
/// the context numbered `id` registered, which has none or is
/// write-protected (Linux's `handle_userfault`): `Some(true)` when it
/// raises SIGBUS (`UFFD_FEATURE_SIGBUS`), `Some(false)` once the thread
/// has waited, and `None` when there is no such context any more. Either
/// way but SIGBUS the instruction runs again.
pub(crate) fn fault(c: &mut Context<'_>, id: u64, access: Access) -> Option<bool> {
    let context = find(id)?;
    // Linux decides under the mmap lock, where the page is still missing
    // or protected and the context not released; here the access failed
    // before, and a fill, an end of the protection or a close since leaves
    // it to run again, not to SIGBUS.
    if context.released.load(Ordering::SeqCst) || !access.faults(c, id) {
        return Some(false);
    }
    let address = access.address;
    let features = context.features();
    if features & FEATURE_SIGBUS != 0 {
        return Some(true);
    }
    let thread = if features & FEATURE_THREAD_ID != 0 {
        c.group.namespaces(c.tid).pid.number(c.tid)
    } else {
        0
    };
    let waiting = Arc::new(Waiting {
        address: if features & FEATURE_EXACT_ADDRESS != 0 {
            address
        } else {
            address & !(PAGE - 1)
        },
        flags: if access.write {
            PAGEFAULT_FLAG_WRITE
        } else {
            0
        } | match access.reason {
            UserfaultReason::Missing => 0,
            UserfaultReason::Minor => PAGEFAULT_FLAG_MINOR,
            UserfaultReason::Protected => PAGEFAULT_FLAG_WP,
        },
        thread,
        woken: AtomicBool::new(false),
        hub: Arc::clone(&c.files.readiness),
    });
    {
        let mut state = context.state();
        // Again under the context's lock, as `userfaultfd_must_wait` looks
        // at the page once the fault is queued: a fill or an end of the
        // protection that came first has left it writable, and one that
        // comes after will find the fault.
        if context.released.load(Ordering::SeqCst) || !access.faults(c, id) {
            return Some(false);
        }
        state.pending.push_back(Arc::clone(&waiting));
        state.epoch += 1;
    }
    context.hub.changed();
    // `TASK_INTERRUPTIBLE`: a signal ends the wait, and the instruction
    // runs again after it.
    loop {
        let ticket = c.files.readiness.token.value();
        if waiting.woken.load(Ordering::SeqCst)
            || context.released.load(Ordering::SeqCst)
            || crate::events::signalled(c)
            || crate::events::wait(c, ticket, None).is_err()
        {
            break;
        }
    }
    let mut state = context.state();
    state.pending.retain(|w| !Arc::ptr_eq(w, &waiting));
    state.read.retain(|w| !Arc::ptr_eq(w, &waiting));
    Some(false)
}

/// What a kernel access to user memory needs to resolve its fault with no
/// [`Context`] at hand ([`paludarium_mmu::faults::Resolver`]), as a system
/// call's copy to or from user memory meets one: Linux's
/// `do_user_addr_fault` serves it as it does an instruction's, growing a
/// mapping that grows down (`expand_stack`) and waiting for a `userfaultfd`
/// (`handle_userfault`), unless the context took `UFFD_USER_MODE_ONLY` or
/// `UFFD_FEATURE_SIGBUS` (`EFAULT`). Its wait goes on through a signal
/// that is not fatal, as `fault_signal_pending` ends a kernel fault's
/// retries only for a fatal one, and ends for a SIGKILL or the process's
/// exit, which fails the access too; an access whose context is released
/// is made again, of a page no longer registered. One through
/// `get_user_pages` waits alike (`FAULT_FLAG_KILLABLE`), but grows nothing.
pub(crate) struct KernelCopies {
    pub(crate) group: Arc<crate::ThreadGroup>,
    pub(crate) tid: u32,
    /// What the thread waits on: its files' readiness.
    pub(crate) hub: Arc<ReadinessHub>,
    pub(crate) host: Arc<dyn paludarium_host::Host>,
    /// The thread's inbox, for the signals that end the wait (with the
    /// call's signal mask, [`CALL`]); the wait cannot take them in, nor wake
    /// for them, as the inbox's wake token stays set until the call returns
    /// and takes them in.
    pub(crate) inbox: Arc<crate::inbox::SignalInbox>,
    /// Where `RLIMIT_STACK` and `RLIMIT_MEMLOCK` are, and whether the
    /// thread has `CAP_IPC_LOCK`, for a growth, as the kernel's
    /// `stack_limits` reads them for an instruction's.
    pub(crate) processes: Arc<crate::processes::Processes>,
    pub(crate) pid: u32,
}

thread_local! {
    /// The signal mask of the system call the host thread runs, as it is
    /// now (`ppoll`, `pselect6`, `epoll_pwait`, `io_pgetevents` and
    /// `io_uring_enter` set a temporary one, under which Linux's copies
    /// fault too), and whether its thread has `CAP_IPC_LOCK`.
    static CALL: core::cell::Cell<(u64, bool)> = const { core::cell::Cell::new((0, false)) };
}

/// A system call starts with `mask` and `ipc_lock`; what was there.
pub(crate) fn enter_call(mask: u64, ipc_lock: bool) -> (u64, bool) {
    CALL.with(|call| call.replace((mask, ipc_lock)))
}

/// What [`enter_call`] returned, back.
pub(crate) fn leave_call(was: (u64, bool)) {
    CALL.with(|call| call.set(was));
}

/// The call's signal mask is now `mask`.
pub(crate) fn mask_changed(mask: u64) {
    CALL.with(|call| call.set((mask, call.get().1)));
}

impl KernelCopies {
    /// Whether it serves a call of thread `tid` of process `pid`, with
    /// these files, group and inbox: it is kept from call to call.
    pub(crate) fn serves(
        &self,
        group: &Arc<crate::ThreadGroup>,
        hub: &Arc<ReadinessHub>,
        inbox: &Arc<crate::inbox::SignalInbox>,
        pid: u32,
        tid: u32,
    ) -> bool {
        Arc::ptr_eq(&self.group, group)
            && Arc::ptr_eq(&self.hub, hub)
            && Arc::ptr_eq(&self.inbox, inbox)
            && self.pid == pid
            && self.tid == tid
    }
}

impl paludarium_mmu::faults::Resolver for KernelCopies {
    fn resolve(&self, space: &MemoryView, addr: u64, write: bool, gup: bool) -> bool {
        let at = GuestAddr(addr);
        // `__get_user_pages` faults no page in with a fatal signal pending.
        if gup && self.fatal() {
            return false;
        }
        let Some((id, reason)) = space.userfault_for(at, write, false) else {
            return false;
        };
        self.wait(
            space,
            id,
            Access {
                address: addr,
                write,
                fetch: false,
                reason,
            },
        )
    }
    fn grow(&self, space: &MemoryView, addr: u64) -> bool {
        const RLIMIT_STACK: usize = 3;
        const RLIMIT_MEMLOCK: usize = 8;
        let stack = self.processes.soft_limit(self.pid, RLIMIT_STACK);
        let lock = if CALL.with(core::cell::Cell::get).1 {
            u64::MAX
        } else {
            self.processes.soft_limit(self.pid, RLIMIT_MEMLOCK) >> 12
        };
        space.grow_down(GuestAddr(addr), stack, lock)
    }
}

impl KernelCopies {
    /// `fatal_signal_pending`, with the signals of timers that have expired.
    fn fatal(&self) -> bool {
        if let Ok(now) = self.host.clock(paludarium_host::ClockId::Monotonic) {
            self.group.expire_due(now);
        }
        self.group
            .fatal_pending(&self.inbox, CALL.with(core::cell::Cell::get).0)
    }
    fn still_faults(space: &MemoryView, id: u64, access: &Access) -> bool {
        space.userfault_for(GuestAddr(access.address), access.write, false)
            == Some((id, access.reason))
    }
    /// `handle_userfault` for a kernel access: whether it may be tried
    /// again, once the page is filled, the protection ended, or the wait
    /// woken, or the context released, whose registrations are then about
    /// to end (`VM_FAULT_RETRY`); not when the context refuses the kernel's
    /// faults, or a fatal signal came.
    fn wait(&self, space: &MemoryView, id: u64, access: Access) -> bool {
        let Some(context) = find(id) else {
            // Released and gone, or its registration would still be there.
            return !Self::still_faults(space, id, &access);
        };
        if context.flags & USER_MODE_ONLY != 0 || context.features() & FEATURE_SIGBUS != 0 {
            return false;
        }
        if context.released.load(Ordering::SeqCst) {
            std::thread::yield_now();
            return !self.fatal();
        }
        if !Self::still_faults(space, id, &access) {
            return true;
        }
        let features = context.features();
        let thread = if features & FEATURE_THREAD_ID != 0 {
            self.group.namespaces(self.tid).pid.number(self.tid)
        } else {
            0
        };
        let waiting = Arc::new(Waiting {
            address: if features & FEATURE_EXACT_ADDRESS != 0 {
                access.address
            } else {
                access.address & !(PAGE - 1)
            },
            flags: if access.write {
                PAGEFAULT_FLAG_WRITE
            } else {
                0
            } | match access.reason {
                UserfaultReason::Missing => 0,
                UserfaultReason::Minor => PAGEFAULT_FLAG_MINOR,
                UserfaultReason::Protected => PAGEFAULT_FLAG_WP,
            },
            thread,
            woken: AtomicBool::new(false),
            hub: Arc::clone(&self.hub),
        });
        {
            let mut state = context.state();
            if context.released.load(Ordering::SeqCst) || !Self::still_faults(space, id, &access) {
                return true;
            }
            state.pending.push_back(Arc::clone(&waiting));
            state.epoch += 1;
        }
        context.hub.changed();
        // `TASK_INTERRUPTIBLE`, but a kernel fault is retried after a
        // signal that is not fatal, and waits again.
        // So it checks for them every 10 ms rather than being woken.
        let never = Arc::new(AtomicBool::new(false));
        let mut fatal = false;
        let _sleeps = self.inbox.tif().sleep_killable();
        loop {
            let ticket = self.hub.token.value();
            if waiting.woken.load(Ordering::SeqCst) || context.released.load(Ordering::SeqCst) {
                break;
            }
            if self.fatal() {
                fatal = true;
                break;
            }
            let now = self
                .host
                .clock(paludarium_host::ClockId::Monotonic)
                .unwrap_or(0);
            let end = Some((
                paludarium_host::ClockId::Monotonic,
                now.saturating_add(10_000_000),
            ));
            match self.host.wait_on(&self.hub.token, ticket, end, &never) {
                Err(e) if e == Errno::ENOSYS => {
                    let _ = self.host.wait_until(
                        paludarium_host::ClockId::Monotonic,
                        now.saturating_add(1_000_000),
                        &never,
                    );
                }
                _ => {}
            }
        }
        let mut state = context.state();
        state.pending.retain(|w| !Arc::ptr_eq(w, &waiting));
        state.read.retain(|w| !Arc::ptr_eq(w, &waiting));
        !fatal
    }
}

/// `read(2)` of a context into `out`, if `file` is one's.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    out: &mut [u8],
    nowait: bool,
) -> Option<Result<usize, Errno>> {
    let file = of(file)?;
    let mut done = 0;
    Some(read_messages(
        c,
        file,
        out.len(),
        nowait,
        &mut |_, message| {
            out[done..done + MESSAGE].copy_from_slice(message);
            done += MESSAGE;
            Ok(())
        },
    ))
}

/// `read(2)` of a context into the guest's `len` bytes at `at`.
pub(crate) fn read_guest(
    c: &mut Context<'_>,
    file: &UserfaultFile,
    at: u64,
    len: usize,
) -> Result<usize, Errno> {
    let mut done = 0u64;
    read_messages(c, file, len, false, &mut |c, message| {
        c.mem
            .write(GuestAddr(at + done), message)
            .map_err(|_| Errno::EFAULT)?;
        done += MESSAGE as u64;
        Ok(())
    })
}

/// Linux's `userfaultfd_read_iter`: `EINVAL` before `UFFDIO_API` or for
/// less than a message, then as many messages as fit, waiting for the
/// first unless the file is non-blocking (`EAGAIN`), until a signal
/// (`ERESTARTSYS`). A message that cannot be copied out is lost, and the
/// read is `EFAULT` if it is the first.
fn read_messages(
    c: &mut Context<'_>,
    file: &UserfaultFile,
    len: usize,
    nowait: bool,
    put: &mut Put<'_>,
) -> Result<usize, Errno> {
    let context = &file.context;
    if !context.initialized() {
        return Err(Errno::EINVAL);
    }
    let mut nowait = nowait || file.status.load(Ordering::SeqCst) & O_NONBLOCK != 0;
    let mut done = 0;
    loop {
        if len - done < MESSAGE {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::EINVAL)
            };
        }
        let message = loop {
            let ticket = c.files.readiness.token.value();
            match context.take() {
                Some(Taken::Message(message)) => break message,
                Some(Taken::Fork(event)) => match hand_over(c, context, &event) {
                    Ok(message) => break message,
                    Err(e) => return if done > 0 { Ok(done) } else { Err(e) },
                },
                None => {}
            }
            if crate::events::signalled(c) {
                return if done > 0 { Ok(done) } else { Err(Errno(4)) };
            }
            if nowait {
                return if done > 0 {
                    Ok(done)
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            if let Err(e) = crate::events::wait(c, ticket, None) {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
        };
        if let Err(e) = put(c, &message) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        done += MESSAGE;
        nowait = true;
    }
}

/// A fork's event, which a read took: the child's context gets a file of
/// the reader's, opened for reading with the `O_CLOEXEC` and `O_NONBLOCK`
/// the old one was made with, whose number the message has, and the
/// forking thread goes on, as Linux's `resolve_userfault_fork`. With no
/// room for the file, the event goes back to the queue, unless its thread
/// gave up on it, and the read fails.
fn hand_over(
    c: &mut Context<'_>,
    context: &Userfaultfd,
    event: &Arc<Event>,
) -> Result<[u8; MESSAGE], Errno> {
    let child = event.child.as_ref().map(Arc::clone).ok_or(Errno::EINVAL)?;
    let file = Arc::new(UserfaultFile {
        status: AtomicU32::new(child.flags & O_NONBLOCK),
        context: Arc::clone(&child),
        owns: AtomicBool::new(true),
        stat: crate::files::own_anonymous_inode(&c.process.credentials),
    });
    let installed = c.files.install(
        Arc::clone(&file) as Arc<dyn FileHandle>,
        child.flags & O_CLOEXEC != 0,
        c.group.nofile(),
    );
    if installed.is_err() {
        file.owns.store(false, Ordering::SeqCst);
    }
    drop(file);
    let mut state = context.state();
    let abandoned = event.abandoned.load(Ordering::SeqCst);
    match installed {
        Ok(fd) => {
            if !abandoned {
                event.done.store(true, Ordering::SeqCst);
            }
            drop(state);
            event.hub.changed();
            let mut message = event.message;
            message[8..12].copy_from_slice(&fd.to_le_bytes());
            Ok(message)
        }
        Err(e) => {
            if abandoned {
                drop(state);
                child.release();
            } else {
                state.events.push_front(Arc::clone(event));
            }
            Err(e)
        }
    }
}

/// `USERFAULTFD_IOC_NEW`, `_IO(0xAA, 0x00)`.
const IOC_NEW: u32 = 0xaa00;

/// An open `/dev/userfaultfd` (`userfaultfd_misc`), whose only operation is
/// its ioctl ([`ioctl`]): whoever may open it, as its mode allows, makes
/// contexts that take the kernel's faults too, with no capability. It has
/// no `read` or `write` (`EINVAL`), and seeks nowhere (`noop_llseek`).
pub(crate) struct Device {
    flags: AtomicU32,
}

impl Device {
    pub(crate) fn new(flags: u32) -> Self {
        Self {
            flags: AtomicU32::new(flags & !O_CLOEXEC),
        }
    }
}

impl FileHandle for Device {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn write_at(&self, _: u64, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(crate::devices::stat(crate::devices::Entry::Userfaultfd))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(
            (self.flags() & 3) | (flags & !3 & !O_CLOEXEC),
            Ordering::SeqCst,
        );
        Ok(())
    }
    /// No `poll`: `DEFAULT_POLLMASK`.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Ok((crate::events::IN | crate::events::OUT, 1, 1))
    }
}

/// An ioctl of a context, if `file` is one's (`userfaultfd_ioctl`): any but
/// `UFFDIO_API` is `EINVAL` before it, as is one it does not know. Of
/// `/dev/userfaultfd` (`userfaultfd_dev_ioctl`), `USERFAULTFD_IOC_NEW` makes
/// a context of the flags in the low 32 bits of `arg`, as `new_userfaultfd`
/// takes an `int`, and any other is `EINVAL`.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    cmd: u64,
    arg: u64,
) -> Option<Result<u64, Errno>> {
    if file.as_any().is_some_and(|any| any.is::<Device>()) {
        return Some(if cmd as u32 == IOC_NEW {
            create(c, arg as u32)
        } else {
            Err(Errno::EINVAL)
        });
    }
    let context = Arc::clone(&of(file)?.context);
    let cmd = cmd as u32;
    if cmd != UFFDIO_API && !context.initialized() {
        return Some(Err(Errno::EINVAL));
    }
    Some(match cmd {
        UFFDIO_API => api(c, &context, arg),
        UFFDIO_REGISTER => register(c, &context, arg),
        UFFDIO_UNREGISTER => unregister(c, &context, arg),
        UFFDIO_WAKE => wake(c, &context, arg),
        UFFDIO_COPY => fill(c, &context, arg, Fill::Copy),
        UFFDIO_ZEROPAGE => fill(c, &context, arg, Fill::Zeros),
        UFFDIO_POISON => fill(c, &context, arg, Fill::Poison),
        UFFDIO_CONTINUE => fill(c, &context, arg, Fill::Continue),
        UFFDIO_MOVE => move_pages(c, &context, arg),
        UFFDIO_WRITEPROTECT => write_protect(c, &context, arg),
        _ => Err(Errno::EINVAL),
    })
}

/// The `n` words at `arg`, read whole (`EFAULT`).
fn words<const N: usize>(c: &Context<'_>, arg: u64) -> Result<[u64; N], Errno> {
    let mut bytes = vec![0; N * 8];
    c.mem
        .read(GuestAddr(arg), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let mut words = [0; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    Ok(words)
}

fn put_word(c: &Context<'_>, at: u64, value: u64) -> Result<(), Errno> {
    c.mem
        .write(GuestAddr(at), &value.to_le_bytes())
        .map_err(|_| Errno::EFAULT)
}

/// Linux 7.0's `validate_unaligned_range`, which the CI runners have: a
/// whole number of pages, at least one, from at least `min`, the machine's
/// `vm.mmap_min_addr`, within the user half (`EINVAL`). Linux master no
/// longer asks for `mmap_min_addr`.
fn validate_unaligned(start: u64, len: u64, min: u64) -> Result<(), Errno> {
    if !len.is_multiple_of(PAGE)
        || len == 0
        || start < min
        || start >= USER_ADDRESS_LIMIT
        || len > USER_ADDRESS_LIMIT - start
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Linux's `validate_range`: the same, from a page's start.
fn validate(start: u64, len: u64, min: u64) -> Result<(), Errno> {
    if !start.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    validate_unaligned(start, len, min)
}

/// `UFFDIO_API` (`userfaultfd_api`): the version and the features asked
/// for, which must be ones it offers; the `struct uffdio_api` is written
/// back with them all and the context's ioctls, or with zeros when it
/// fails. A context takes its features once (`EINVAL`).
fn api(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [api, mut features, _] = words::<3>(c, arg)?;
    let fail = |c: &Context<'_>, error: Errno| {
        c.mem
            .write(GuestAddr(arg), &[0; 24])
            .map_err(|_| Errno::EFAULT)
            .and(Err(error))
    };
    if api != API {
        return fail(c, Errno::EINVAL);
    }
    if features & FEATURE_EVENT_FORK != 0 && !c.process.credentials.capable(CAP_SYS_PTRACE) {
        return fail(c, Errno::EPERM);
    }
    if features & FEATURE_WP_ASYNC != 0 {
        features |= FEATURE_WP_UNPOPULATED;
    }
    if features & !FEATURES != 0 {
        return fail(c, Errno::EINVAL);
    }
    let mut reply = [0; 24];
    reply[..8].copy_from_slice(&API.to_le_bytes());
    reply[8..16].copy_from_slice(&FEATURES.to_le_bytes());
    reply[16..].copy_from_slice(&API_IOCTLS.to_le_bytes());
    c.mem
        .write(GuestAddr(arg), &reply)
        .map_err(|_| Errno::EFAULT)?;
    if context
        .features
        .compare_exchange(
            0,
            features as u32 | INITIALIZED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return fail(c, Errno::EINVAL);
    }
    Ok(0)
}

/// `UFFDIO_REGISTER` (`userfaultfd_register`): modes it knows, a range
/// ([`validate`]), then the space's checks
/// ([`paludarium_mmu::MemoryView::userfault_register`]), which take the
/// minor mode for shmem only; once registered, the ioctls of the range are
/// written back (`EFAULT`), `UFFDIO_WRITEPROTECT` among them with the
/// write-protect mode and `UFFDIO_CONTINUE` with the minor mode.
fn register(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [start, len, mode] = words::<3>(c, arg)?;
    if mode == 0 || mode & !MODES != 0 {
        return Err(Errno::EINVAL);
    }
    validate(start, len, c.mem.min_addr())?;
    let mut modes = mode as u8;
    if context.features() & FEATURE_WP_UNPOPULATED != 0 {
        modes |= paludarium_mmu::Userfault::WP_UNPOPULATED;
    }
    if context.features() & FEATURE_WP_ASYNC != 0 {
        modes |= paludarium_mmu::Userfault::WP_ASYNC;
    }
    if context.features() & FEATURE_EVENT_FORK != 0 {
        modes |= paludarium_mmu::Userfault::EVENT_FORK;
    }
    if context.features() & FEATURE_EVENT_REMAP != 0 {
        modes |= paludarium_mmu::Userfault::EVENT_REMAP;
    }
    context
        .memory
        .userfault_register(start, start + len, context.id, modes)?;
    let mut ioctls = RANGE_IOCTLS;
    if mode & MODE_WP != 0 {
        ioctls |= WRITEPROTECT_IOCTL;
    }
    if mode & MODE_MINOR != 0 {
        ioctls |= CONTINUE_IOCTL;
    }
    put_word(c, arg + 24, ioctls)?;
    Ok(0)
}

/// `UFFDIO_UNREGISTER` (`userfaultfd_unregister`): the range leaves the
/// context, and the waits for its missing pages end.
fn unregister(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [start, len] = words::<2>(c, arg)?;
    validate(start, len, c.mem.min_addr())?;
    for (from, to) in context
        .memory
        .userfault_unregister(start, start + len, context.id)?
    {
        context.wake(from, to - from);
    }
    Ok(0)
}

/// `UFFDIO_WRITEPROTECT` (`userfaultfd_writeprotect`): `EAGAIN` while an
/// event is not read; a range ([`validate`]) and modes it knows, not both protecting and
/// `DONTWAKE` (`EINVAL`), of a space that lives (`ESRCH`); then the
/// space's change ([`paludarium_mmu::MemoryView::userfault_write_protect`]),
/// and an end of the protection wakes the range unless `DONTWAKE`.
fn write_protect(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    if context.changing() {
        return Err(Errno::EAGAIN);
    }
    let [start, len, mode] = words::<3>(c, arg)?;
    validate(start, len, c.mem.min_addr())?;
    if mode & !(WRITEPROTECT_MODE_WP | WRITEPROTECT_MODE_DONTWAKE) != 0 {
        return Err(Errno::EINVAL);
    }
    let protect = mode & WRITEPROTECT_MODE_WP != 0;
    let dont_wake = mode & WRITEPROTECT_MODE_DONTWAKE != 0;
    if protect && dont_wake {
        return Err(Errno::EINVAL);
    }
    context
        .memory
        .userfault_write_protect(start, start + len, protect)?;
    if !protect && !dont_wake {
        context.wake(start, len);
    }
    Ok(0)
}

/// `UFFDIO_WAKE` (`userfaultfd_wake`): ends the waits for the range.
fn wake(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [start, len] = words::<2>(c, arg)?;
    validate(start, len, c.mem.min_addr())?;
    context.wake(start, len);
    Ok(0)
}

/// What a fill puts in the pages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// `UFFDIO_COPY`: bytes from the caller's memory.
    Copy,
    /// `UFFDIO_ZEROPAGE`: zeros.
    Zeros,
    /// `UFFDIO_POISON`: poison ([`paludarium_mmu::MemoryView::userfault_poison`]).
    Poison,
    /// `UFFDIO_CONTINUE`: the page cache's page
    /// ([`paludarium_mmu::MemoryView::userfault_continue`]).
    Continue,
}

/// `UFFDIO_COPY`, `UFFDIO_ZEROPAGE`, `UFFDIO_POISON` or `UFFDIO_CONTINUE`
/// (`kind`), as Linux's `userfaultfd_copy`, `userfaultfd_zeropage`,
/// `userfaultfd_poison`, `userfaultfd_continue` and `mfill_atomic` have
/// them: page by page until one fails, which is the error if it is the
/// first; the bytes filled, or the error, are written to the struct's last
/// field (`EFAULT`), then the waits for them end unless `DONTWAKE`, and a
/// fill that stopped short is `EAGAIN`. `UFFDIO_CONTINUE_MODE_WP` needs
/// the write-protect mode, as `UFFDIO_COPY_MODE_WP` does. While an event
/// is not read, the fill is `EAGAIN`, written to that field first.
fn fill(c: &mut Context<'_>, context: &Userfaultfd, arg: u64, kind: Fill) -> Result<u64, Errno> {
    let copy = kind == Fill::Copy;
    if context.changing() {
        put_word(
            c,
            arg + if copy { 32 } else { 24 },
            Errno::EAGAIN.to_syscall_return(),
        )?;
        return Err(Errno::EAGAIN);
    }
    let (dst, src, len, mode, result_at) = if copy {
        let [dst, src, len, mode] = words::<4>(c, arg)?;
        validate_unaligned(src, len, c.mem.min_addr())?;
        validate(dst, len, c.mem.min_addr())?;
        if mode & !(DONTWAKE | COPY_MODE_WP) != 0 {
            return Err(Errno::EINVAL);
        }
        (dst, src, len, mode, arg + 32)
    } else {
        let [dst, len, mode] = words::<3>(c, arg)?;
        validate(dst, len, c.mem.min_addr())?;
        let modes = if kind == Fill::Continue {
            DONTWAKE | COPY_MODE_WP
        } else {
            DONTWAKE
        };
        if mode & !modes != 0 {
            return Err(Errno::EINVAL);
        }
        (dst, 0, len, mode, arg + 24)
    };
    let memory = &context.memory;
    if !memory.lives() {
        return Err(Errno(3)); // ESRCH
    }
    let end = dst + len;
    memory.userfault_prepare_fill(dst);
    let mut filled = 0;
    let mut error = memory
        .userfault_target(dst, end)
        .and_then(|modes| {
            // A copy that write-protects its pages needs the range
            // registered for it.
            if mode & COPY_MODE_WP != 0 && modes & paludarium_mmu::Userfault::WP == 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(())
            }
        })
        .err();
    let mut page = vec![0; PAGE as usize];
    while error.is_none() && filled < len {
        let bytes = if copy {
            if c.mem.read(GuestAddr(src + filled), &mut page).is_err() {
                error = Some(Errno::EFAULT);
                break;
            }
            Some(page.as_slice())
        } else {
            None
        };
        let done = match kind {
            Fill::Poison => memory.userfault_poison(dst, end, dst + filled),
            Fill::Continue => {
                memory.userfault_continue(dst, end, dst + filled, mode & COPY_MODE_WP != 0)
            }
            Fill::Copy | Fill::Zeros => {
                memory.userfault_fill(dst, end, dst + filled, bytes, mode & COPY_MODE_WP != 0)
            }
        };
        match done {
            Ok(()) => filled += PAGE,
            Err(e) => error = Some(e),
        }
    }
    let result = match error {
        Some(e) if filled == 0 => e.to_syscall_return(),
        _ => filled,
    };
    put_word(c, result_at, result)?;
    if filled == 0 {
        return Err(error.unwrap_or(Errno::EINVAL));
    }
    if mode & DONTWAKE == 0 {
        context.wake(dst, filled);
    }
    if filled == len {
        Ok(0)
    } else {
        Err(Errno::EAGAIN)
    }
}

/// `UFFDIO_MOVE` (`userfaultfd_move`): `EAGAIN` while an event is not
/// read, written to the last field first; the `struct uffdio_move` but its
/// last field (`EFAULT`), from a thread of the context's own space
/// (`EINVAL`), with page-aligned ranges ([`validate`]) and modes it knows
/// (`EINVAL`); then the space's move
/// ([`paludarium_mmu::MemoryView::userfault_move`]). The bytes moved, or
/// the error if none were, are written to the last field (`EFAULT`); the
/// waits for the moved pages end unless `DONTWAKE`, and a move that
/// stopped short is `EAGAIN`.
fn move_pages(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    if context.changing() {
        put_word(c, arg + 32, Errno::EAGAIN.to_syscall_return())?;
        return Err(Errno::EAGAIN);
    }
    let [dst, src, len, mode] = words::<4>(c, arg)?;
    if c.mem.view().identity() != context.memory.identity() {
        return Err(Errno::EINVAL);
    }
    validate(dst, len, c.mem.min_addr())?;
    validate(src, len, c.mem.min_addr())?;
    if mode & !(MOVE_MODE_DONTWAKE | MOVE_MODE_ALLOW_SRC_HOLES) != 0 {
        return Err(Errno::EINVAL);
    }
    let (moved, error) = context.memory.userfault_move(
        dst,
        src,
        len,
        context.id,
        mode & MOVE_MODE_ALLOW_SRC_HOLES != 0,
    );
    let result = match error {
        Some(e) if moved == 0 => e.to_syscall_return(),
        _ => moved,
    };
    put_word(c, arg + 32, result)?;
    if moved == 0 {
        return Err(error.unwrap_or(Errno::EINVAL));
    }
    if mode & MOVE_MODE_DONTWAKE == 0 {
        context.wake(dst, moved);
    }
    if moved == len {
        Ok(0)
    } else {
        Err(Errno::EAGAIN)
    }
}

/// The events an operation on a space makes, made before it and queued
/// once it is done ([`Events::deliver`]); each counts in its context's
/// `mmap_changing` until it is read. Dropped undelivered, as when the
/// operation fails, they count no more, and a fork's child context is
/// released.
#[derive(Default)]
#[must_use]
pub(crate) struct Events(Vec<Made>);

/// An event made: its context, its message, and a fork's child context.
type Made = (Arc<Userfaultfd>, [u8; MESSAGE], Option<Arc<Userfaultfd>>);

/// The parts of a range a context registered ([`registered`]).
type Parts = (Arc<Userfaultfd>, Vec<(u64, u64)>);

impl Events {
    fn push(
        &mut self,
        context: Arc<Userfaultfd>,
        message: [u8; MESSAGE],
        child: Option<Arc<Userfaultfd>>,
    ) {
        context.changing.fetch_add(1, Ordering::SeqCst);
        self.0.push((context, message, child));
    }
    /// Queues each event and waits until it is read, in their order.
    pub(crate) fn deliver(mut self, c: &mut Context<'_>) {
        for (context, message, child) in std::mem::take(&mut self.0) {
            wait_read(c, &context, message, child);
            context.changing.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        for (context, _, child) in self.0.drain(..) {
            context.changing.fetch_sub(1, Ordering::SeqCst);
            if let Some(child) = child {
                child.release();
            }
        }
    }
}

/// Queues an event of `context` and waits until it is read, the context's
/// file is closed or a fatal signal comes, as Linux's
/// `userfaultfd_event_wait_completion` waits `TASK_KILLABLE`. A fork's
/// event left unread takes the child out of its context
/// (`userfaultfd_release_new`).
fn wait_read(
    c: &mut Context<'_>,
    context: &Arc<Userfaultfd>,
    message: [u8; MESSAGE],
    child: Option<Arc<Userfaultfd>>,
) {
    let event = Arc::new(Event {
        message,
        child,
        done: AtomicBool::new(false),
        abandoned: AtomicBool::new(false),
        hub: Arc::clone(&c.files.readiness),
    });
    {
        let mut state = context.state();
        state.events.push_back(Arc::clone(&event));
        state.epoch += 1;
    }
    context.hub.changed();
    let _sleeps = c.inbox.tif().sleep_killable();
    let _shown = c.inbox.tif().sleep_uninterruptible();
    loop {
        let ticket = c.files.readiness.token.value();
        if event.done.load(Ordering::SeqCst)
            || context.released.load(Ordering::SeqCst)
            || crate::fanotify::fatal(c)
        {
            break;
        }
        let Ok(now) = c.host.clock(paludarium_host::ClockId::Monotonic) else {
            break;
        };
        c.group.expire_due(now);
        c.group.pass_process(c.process);
        let _ = c.inbox.drain(c.process);
        // A signal it does not take keeps its inbox's wake set.
        let never = AtomicBool::new(false);
        let end = Some((
            paludarium_host::ClockId::Monotonic,
            now.saturating_add(10_000_000),
        ));
        if let Err(e) = c
            .host
            .wait_on(&c.files.readiness.token, ticket, end, &never)
            && e == Errno::ENOSYS
        {
            let _ = c.host.wait_until(
                paludarium_host::ClockId::Monotonic,
                now.saturating_add(1_000_000),
                &never,
            );
        }
    }
    let queued = {
        let mut state = context.state();
        event.abandoned.store(true, Ordering::SeqCst);
        let before = state.events.len();
        state.events.retain(|e| !Arc::ptr_eq(e, &event));
        before != state.events.len()
    };
    if queued && let Some(child) = &event.child {
        child.release();
    }
}

/// The live contexts with `feature` that registered parts of
/// `[start, end)` of `mem`, each with the parts, joined where they meet.
fn registered(mem: &MemoryView, start: u64, end: u64, feature: u64) -> Vec<Parts> {
    let mut found: Vec<Parts> = Vec::new();
    for (from, to, userfault) in mem.userfault_registrations(start, end) {
        let Some(context) = find(userfault.context) else {
            continue;
        };
        if context.released.load(Ordering::SeqCst) || context.features() & feature == 0 {
            continue;
        }
        let at = match found.iter().position(|(c, _)| c.id == context.id) {
            Some(i) => i,
            None => {
                found.push((context, Vec::new()));
                found.len() - 1
            }
        };
        let parts = &mut found[at].1;
        match parts.last_mut() {
            Some(last) if last.1 == from => last.1 = to,
            _ => parts.push((from, to)),
        }
    }
    found
}

/// A message of `event` with the words `args` after its header.
fn event_message(event: u8, args: &[u64]) -> [u8; MESSAGE] {
    let mut message = [0; MESSAGE];
    message[0] = event;
    for (i, word) in args.iter().enumerate() {
        message[8 + i * 8..16 + i * 8].copy_from_slice(&word.to_le_bytes());
    }
    message
}

/// The `UFFD_EVENT_UNMAP` that an unmap of `[start, end)` of `mem` makes
/// for each context with `UFFD_FEATURE_EVENT_UNMAP` that registered some
/// of it, of the whole range, once (`userfaultfd_unmap_prep`).
pub(crate) fn unmap(mem: &MemoryView, start: u64, end: u64, events: &mut Events) {
    for (context, _) in registered(mem, start, end, FEATURE_EVENT_UNMAP) {
        let message = event_message(EVENT_UNMAP, &[start, end]);
        let known = events
            .0
            .iter()
            .any(|(c, m, _)| c.id == context.id && *m == message);
        if !known {
            events.push(context, message, None);
        }
    }
}

/// A discard of `[start, end)` of the caller's memory, VMA by VMA as
/// Linux's `madvise_walk_vmas` goes: `drop` drops the pages of a part,
/// and before the part a context with `UFFD_FEATURE_EVENT_REMOVE`
/// registered (its registered mappings that meet are one part, as Linux's
/// VMAs merge) is dropped, `check` looks at it and its `UFFD_EVENT_REMOVE`
/// is read (`userfaultfd_remove`). So the parts before it have lost their
/// pages, and the parts after it not yet. An error ends the walk, but for
/// `ENOMEM`, of a hole, which the walk gives once it is done.
pub(crate) fn remove(
    c: &mut Context<'_>,
    start: u64,
    end: u64,
    check: &mut crate::syscalls::Part<'_>,
    drop: &mut crate::syscalls::Part<'_>,
) -> Result<(), Errno> {
    let mut hole = false;
    let mut step = |result: Result<(), Errno>| match result {
        Err(Errno::ENOMEM) => {
            hole = true;
            Ok(())
        }
        result => result,
    };
    let mut at = start;
    // The next part is looked for afresh after each wait, as Linux looks
    // the VMA up again once `userfaultfd_remove` has dropped the lock:
    // another thread may have changed the range meanwhile.
    while let Some((context, from, to)) = next_removal(c, at, end) {
        if from > at {
            step(drop(at, from))?;
        }
        check(from, to)?;
        let mut events = Events::default();
        events.push(context, event_message(EVENT_REMOVE, &[from, to]), None);
        events.deliver(c);
        step(drop(from, to))?;
        at = to;
    }
    if at < end {
        step(drop(at, end))?;
    }
    if hole { Err(Errno::ENOMEM) } else { Ok(()) }
}

/// The first part of `[start, end)` a context with
/// `UFFD_FEATURE_EVENT_REMOVE` registered, and that context; none once
/// the range is empty.
fn next_removal(c: &Context<'_>, start: u64, end: u64) -> Option<(Arc<Userfaultfd>, u64, u64)> {
    if start >= end {
        return None;
    }
    registered(&c.mem.view(), start, end, FEATURE_EVENT_REMOVE)
        .into_iter()
        .filter_map(|(context, parts)| {
            parts
                .into_iter()
                .find(|&(from, to)| from < to)
                .map(|(from, to)| (context, from, to))
        })
        .min_by_key(|&(_, from, _)| from)
}

/// The contexts with `UFFD_FEATURE_EVENT_REMAP` of the mapping at `addr`
/// of `mem`, which a move by `mremap` keeps registered
/// (`mremap_userfaultfd_prep`).
pub(crate) fn remap_contexts(mem: &MemoryView, addr: u64) -> Vec<Arc<Userfaultfd>> {
    registered(mem, addr, addr.saturating_add(PAGE), FEATURE_EVENT_REMAP)
        .into_iter()
        .map(|(context, _)| context)
        .collect()
}

/// The `UFFD_EVENT_REMAP` of a move of `len` bytes from `from` to `to`,
/// for each of `contexts` (`mremap_userfaultfd_complete`).
pub(crate) fn remap(
    contexts: Vec<Arc<Userfaultfd>>,
    from: u64,
    to: u64,
    len: u64,
    events: &mut Events,
) {
    for context in contexts {
        events.push(context, event_message(EVENT_REMAP, &[from, to, len]), None);
    }
}

/// A `fork`ed child's registrations (`dup_userfaultfd`): those of a
/// context with `UFFD_FEATURE_EVENT_FORK`, which the child's space kept
/// ([`paludarium_mmu::Userfault::EVENT_FORK`]), move to a new context of
/// the child's, with the old one's flags and features; its
/// `UFFD_EVENT_FORK`, which `events` gets, hands it over to the reader.
pub(crate) fn fork(child: &MemoryView, events: &mut Events) {
    for (context, _) in registered(child, 0, USER_ADDRESS_LIMIT, FEATURE_EVENT_FORK) {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let new = Arc::new(Userfaultfd {
            id,
            features: AtomicU32::new(context.features.load(Ordering::SeqCst)),
            memory: child.clone(),
            hub: Arc::clone(&context.hub),
            state: Mutex::default(),
            released: AtomicBool::new(false),
            flags: context.flags,
            changing: AtomicU32::new(0),
        });
        lock(&CONTEXTS).insert(id, Arc::downgrade(&new));
        child.userfault_renumber(context.id, id);
        events.push(context, event_message(EVENT_FORK, &[]), Some(new));
    }
}

/// The lines `/proc/<pid>/fdinfo` adds for a context's file.
pub(crate) fn fdinfo(file: &UserfaultFile) -> Vec<u8> {
    file.context.fdinfo()
}

impl FileHandle for UserfaultFile {
    /// `userfaultfd_poll`: `POLLERR` before `UFFDIO_API` and for a file that
    /// blocks, whose `read` may wait though a fault was there; `POLLIN`
    /// while a fault or an event is not read yet.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let context = &self.context;
        if !context.initialized() || self.status.load(Ordering::SeqCst) & O_NONBLOCK == 0 {
            return Ok((ERR, 0, 0));
        }
        let state = context.state();
        let ready = !state.pending.is_empty() || !state.events.is_empty();
        Ok((u32::from(ready) * IN, state.epoch, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// Reads come through [`read`], which can wait.
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EAGAIN)
    }
    /// It is open only for reading (`vfs_write`'s `FMODE_WRITE`).
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    /// Linux's `noop_llseek`.
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Opened for reading.
    fn flags(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status
            .store(flags & (O_NONBLOCK | O_ASYNC), Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Queues a fault at `address` as a thread that waits would.
    pub(crate) fn queue(context: &Userfaultfd, address: u64, flags: u64, thread: u32) {
        context.state().pending.push_back(Arc::new(Waiting {
            address,
            flags,
            thread,
            woken: AtomicBool::new(false),
            hub: Arc::clone(&context.hub),
        }));
    }

    /// The faults not read yet, and all of them.
    pub(crate) fn counts(context: &Userfaultfd) -> (usize, usize) {
        let state = context.state();
        (state.pending.len(), state.pending.len() + state.read.len())
    }

    /// An event [`queue_events`] queued.
    pub(crate) struct Queued(Arc<Userfaultfd>, Arc<Event>);

    impl Queued {
        /// It was read.
        pub(crate) fn read(&self) -> bool {
            self.1.done.load(Ordering::SeqCst)
        }
        /// Its thread goes on, as [`Events::deliver`] once it was read.
        pub(crate) fn finish(self) {
            self.0.changing.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Queues `events` as their threads would, without waiting; they count
    /// in `mmap_changing` until [`Queued::finish`].
    pub(crate) fn queue_events(mut events: Events) -> Vec<Queued> {
        let mut queued = Vec::new();
        for (context, message, child) in std::mem::take(&mut events.0) {
            let event = Arc::new(Event {
                message,
                child,
                done: AtomicBool::new(false),
                abandoned: AtomicBool::new(false),
                hub: Arc::clone(&context.hub),
            });
            context.state().events.push_back(Arc::clone(&event));
            queued.push(Queued(context, event));
        }
        queued
    }

    /// An unmap's events ([`unmap`]), counted and still to be delivered.
    pub(crate) fn unmap_events(
        mem: &MemoryView,
        start: u64,
        end: u64,
    ) -> (Events, Vec<[u8; MESSAGE]>) {
        let mut events = Events::default();
        unmap(mem, start, end, &mut events);
        let messages = events.0.iter().map(|(_, m, _)| *m).collect();
        (events, messages)
    }

    /// The child contexts a fork's events hand over.
    pub(crate) fn children(events: &Events) -> Vec<u64> {
        events
            .0
            .iter()
            .filter_map(|(_, _, c)| c.as_ref().map(|c| c.id))
            .collect()
    }

    /// Whether an event of `context` is not read yet (`mmap_changing`).
    pub(crate) fn changing(context: &Userfaultfd) -> bool {
        context.changing()
    }

    /// Reads `n` messages of `context` from another thread, as its handler
    /// would, while the caller's thread waits for them; faults and events
    /// but a fork's.
    pub(crate) fn reader(
        context: Arc<Userfaultfd>,
        n: usize,
    ) -> std::thread::JoinHandle<Vec<[u8; MESSAGE]>> {
        std::thread::spawn(move || {
            let mut messages = Vec::new();
            while messages.len() < n {
                match context.take() {
                    Some(Taken::Message(message)) => messages.push(message),
                    Some(Taken::Fork(event)) => {
                        event.done.store(true, Ordering::SeqCst);
                        event.hub.changed();
                        let mut message = event.message;
                        let id = event.child.as_ref().map_or(0, |c| c.id);
                        message[8..16].copy_from_slice(&id.to_le_bytes());
                        messages.push(message);
                    }
                    None => std::thread::yield_now(),
                }
            }
            messages
        })
    }
}
