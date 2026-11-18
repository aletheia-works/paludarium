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
//! such a page is `EFAULT`, as with `UFFD_USER_MODE_ONLY`, where Linux
//! waits as for an instruction unless that flag was given.
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
//! Not offered: `UFFD_FEATURE_WP_ASYNC`, and the events of `fork`,
//! `mremap`, `madvise` and `munmap`. `UFFDIO_API` does not report their
//! features, which it refuses (`EINVAL`).

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
/// `mmap_min_addr`, below which no range lies.
const MIN_ADDRESS: u64 = paludarium_mmu::MMAP_MIN_ADDR;

/// `UFFD_FEATURE_PAGEFAULT_FLAG_WP`: faults of write-protected pages are
/// reported, with [`PAGEFAULT_FLAG_WP`].
const FEATURE_PAGEFAULT_FLAG_WP: u64 = 1 << 0;
/// `UFFD_FEATURE_EVENT_FORK`, which needs `CAP_SYS_PTRACE`.
const FEATURE_EVENT_FORK: u64 = 1 << 1;
const FEATURE_MISSING_HUGETLBFS: u64 = 1 << 4;
const FEATURE_MISSING_SHMEM: u64 = 1 << 5;
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
/// `UFFD_FEATURE_WP_ASYNC`, which takes `UFFD_FEATURE_WP_UNPOPULATED`.
const FEATURE_WP_ASYNC: u64 = 1 << 15;
/// `UFFD_FEATURE_MOVE`: `UFFDIO_MOVE` is there, which works whether a
/// context asked for it or not, as Linux's does.
const FEATURE_MOVE: u64 = 1 << 16;
/// The features `UFFDIO_API` offers.
const FEATURES: u64 = FEATURE_PAGEFAULT_FLAG_WP
    | FEATURE_MISSING_HUGETLBFS
    | FEATURE_MISSING_SHMEM
    | FEATURE_SIGBUS
    | FEATURE_THREAD_ID
    | FEATURE_MINOR_HUGETLBFS
    | FEATURE_MINOR_SHMEM
    | FEATURE_EXACT_ADDRESS
    | FEATURE_WP_HUGETLBFS_SHMEM
    | FEATURE_WP_UNPOPULATED
    | FEATURE_POISON
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
}

#[derive(Default)]
struct State {
    /// The faults not read yet, oldest first (`fault_pending_wqh`).
    pending: VecDeque<Arc<Waiting>>,
    /// The faults read whose threads still wait (`fault_wqh`).
    read: Vec<Arc<Waiting>>,
    /// Moves on with each fault that comes, for `epoll`.
    epoch: u64,
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
    /// Linux's `userfaultfd_ctx_read` moves it to `fault_wqh`.
    fn take(&self) -> Option<[u8; MESSAGE]> {
        let mut state = self.state();
        let waiting = state.pending.pop_front()?;
        let message = waiting.message();
        state.read.push(waiting);
        Some(message)
    }
    /// Its file was closed: its mappings leave it and its waits end
    /// (`userfaultfd_release`).
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.memory.userfault_release(self.id);
        self.wake(0, 0);
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
}

impl Drop for UserfaultFile {
    fn drop(&mut self) {
        self.context.release();
    }
}

/// The context `file` is the file of, if it is one.
pub(crate) fn of(file: &Arc<dyn FileHandle>) -> Option<&UserfaultFile> {
    file.as_any()?.downcast_ref::<UserfaultFile>()
}

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// `userfaultfd(flags)`, as Linux checks it: one that also takes the
/// kernel's own faults needs `CAP_SYS_PTRACE`, as
/// `vm.unprivileged_userfaultfd` is 0 (`EPERM`), before its flags are
/// checked (`EINVAL`).
pub(crate) fn sys_userfaultfd(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(create(c, a[0] as u32))
}

fn create(c: &mut Context<'_>, flags: u32) -> Result<u64, Errno> {
    if flags & USER_MODE_ONLY == 0 && !c.process.credentials.capable(CAP_SYS_PTRACE) {
        return Err(Errno::EPERM);
    }
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
    });
    lock(&CONTEXTS).insert(id, Arc::downgrade(&context));
    let file = Arc::new(UserfaultFile {
        context,
        status: AtomicU32::new(flags & O_NONBLOCK),
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
            if let Some(message) = context.take() {
                break message;
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

/// An ioctl of a context, if `file` is one's (`userfaultfd_ioctl`): any but
/// `UFFDIO_API` is `EINVAL` before it, as is one it does not know.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    cmd: u64,
    arg: u64,
) -> Option<Result<u64, Errno>> {
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
/// whole number of pages, at least one, from at least `mmap_min_addr`,
/// within the user half (`EINVAL`). Linux master no longer asks for
/// `mmap_min_addr`.
fn validate_unaligned(start: u64, len: u64) -> Result<(), Errno> {
    if !len.is_multiple_of(PAGE)
        || len == 0
        || !(MIN_ADDRESS..USER_ADDRESS_LIMIT).contains(&start)
        || len > USER_ADDRESS_LIMIT - start
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Linux's `validate_range`: the same, from a page's start.
fn validate(start: u64, len: u64) -> Result<(), Errno> {
    if !start.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    validate_unaligned(start, len)
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
    validate(start, len)?;
    let mut modes = mode as u8;
    if context.features() & FEATURE_WP_UNPOPULATED != 0 {
        modes |= paludarium_mmu::Userfault::WP_UNPOPULATED;
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
    validate(start, len)?;
    for (from, to) in context
        .memory
        .userfault_unregister(start, start + len, context.id)?
    {
        context.wake(from, to - from);
    }
    Ok(0)
}

/// `UFFDIO_WRITEPROTECT` (`userfaultfd_writeprotect`): a range
/// ([`validate`]) and modes it knows, not both protecting and
/// `DONTWAKE` (`EINVAL`), of a space that lives (`ESRCH`); then the
/// space's change ([`paludarium_mmu::MemoryView::userfault_write_protect`]),
/// and an end of the protection wakes the range unless `DONTWAKE`.
fn write_protect(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [start, len, mode] = words::<3>(c, arg)?;
    validate(start, len)?;
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
    validate(start, len)?;
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
/// the write-protect mode, as `UFFDIO_COPY_MODE_WP` does.
fn fill(c: &mut Context<'_>, context: &Userfaultfd, arg: u64, kind: Fill) -> Result<u64, Errno> {
    let copy = kind == Fill::Copy;
    let (dst, src, len, mode, result_at) = if copy {
        let [dst, src, len, mode] = words::<4>(c, arg)?;
        validate_unaligned(src, len)?;
        validate(dst, len)?;
        if mode & !(DONTWAKE | COPY_MODE_WP) != 0 {
            return Err(Errno::EINVAL);
        }
        (dst, src, len, mode, arg + 32)
    } else {
        let [dst, len, mode] = words::<3>(c, arg)?;
        validate(dst, len)?;
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

/// `UFFDIO_MOVE` (`userfaultfd_move`): the `struct uffdio_move` but its
/// last field (`EFAULT`), from a thread of the context's own space
/// (`EINVAL`), with page-aligned ranges ([`validate`]) and modes it knows
/// (`EINVAL`); then the space's move
/// ([`paludarium_mmu::MemoryView::userfault_move`]). The bytes moved, or
/// the error if none were, are written to the last field (`EFAULT`); the
/// waits for the moved pages end unless `DONTWAKE`, and a move that
/// stopped short is `EAGAIN`.
fn move_pages(c: &mut Context<'_>, context: &Userfaultfd, arg: u64) -> Result<u64, Errno> {
    let [dst, src, len, mode] = words::<4>(c, arg)?;
    if c.mem.view().identity() != context.memory.identity() {
        return Err(Errno::EINVAL);
    }
    validate(dst, len)?;
    validate(src, len)?;
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

/// The lines `/proc/<pid>/fdinfo` adds for a context's file.
pub(crate) fn fdinfo(file: &UserfaultFile) -> Vec<u8> {
    file.context.fdinfo()
}

impl FileHandle for UserfaultFile {
    /// `userfaultfd_poll`: `POLLERR` before `UFFDIO_API` and for a file that
    /// blocks, whose `read` may wait though a fault was there; `POLLIN`
    /// while a fault is not read yet.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let context = &self.context;
        if !context.initialized() || self.status.load(Ordering::SeqCst) & O_NONBLOCK == 0 {
            return Ok((ERR, 0, 0));
        }
        let state = context.state();
        Ok((u32::from(!state.pending.is_empty()) * IN, state.epoch, 0))
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
}
