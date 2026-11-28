//! io_uring, as Linux 6.12's (`io_uring/`) with these operations:
//! `IORING_OP_NOP`, `IORING_OP_EPOLL_CTL` (the one libuv batches its
//! `epoll_ctl` calls with) and `_EPOLL_WAIT`, the file transfers
//! `IORING_OP_READ`, `_WRITE`, `_READV`, `_WRITEV` and `_FSYNC`,
//! `IORING_OP_FILES_UPDATE`,
//! `IORING_OP_PROVIDE_BUFFERS` and `_REMOVE_BUFFERS`,
//! `IORING_OP_ASYNC_CANCEL` ([`cancel`]), the timeouts `IORING_OP_TIMEOUT`,
//! `_TIMEOUT_REMOVE` and `_LINK_TIMEOUT` ([`timeout`]), the polls
//! `IORING_OP_POLL_ADD` and `_POLL_REMOVE` ([`poll`]), the file requests
//! `IORING_OP_OPENAT`, `_OPENAT2`, `_CLOSE`, `_STATX`, `_FALLOCATE`,
//! `_FADVISE`, `_MADVISE`, `_RENAMEAT`, `_UNLINKAT`, `_MKDIRAT`,
//! `_SYMLINKAT`, `_LINKAT`, `_FTRUNCATE` and `_PIPE` ([`fs`]), and the socket
//! requests `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`,
//! `_SEND`, `_RECV`, `_SENDMSG` and `_RECVMSG`, with multishot accepts and
//! receives ([`net`]), and `IORING_OP_SPLICE` and `_TEE` ([`splice`]). The
//! others answer
//! `EOPNOTSUPP`, as on a Linux built without them, and
//! `IORING_REGISTER_PROBE` says so. `IORING_REGISTER_BUFFERS` registers
//! the buffers `IORING_OP_READ_FIXED`, `_WRITE_FIXED`, `_READV_FIXED` and
//! `_WRITEV_FIXED` transfer with,
//! `IORING_REGISTER_FILES` (or `_FILES2`, with tags) the files a request
//! with `IOSQE_FIXED_FILE` names by their index, and
//! `IORING_REGISTER_PBUF_RING` a ring of the buffers a read or a receive
//! with `IOSQE_BUFFER_SELECT` chooses from, as it does from provided ones. A
//! ring set up with `IORING_SETUP_R_DISABLED` takes no requests until
//! `IORING_REGISTER_ENABLE_RINGS`, `IORING_REGISTER_RESTRICTIONS` (while it
//! is disabled) limits the requests and registrations it takes after, and
//! `IORING_REGISTER_PERSONALITY` keeps credentials a request with
//! `personality` runs with ([`register`]). The registered files, their
//! updates and their allocation range are checked as Linux 7.0's
//! `io_uring/rsrc.c`, `register.c` and `filetable.c` check them, the
//! provided buffers and their rings as its `kbuf.c` does, and a NOP's flags
//! as its `nop.c` takes them (with Linux master's `IOSQE_FIXED_FILE`): the
//! kernel the differential tests run on.
//!
//! The rings are pages the kernel shares with the mappings of the ring's
//! descriptor ([`SharedPages`]). A request runs when `io_uring_enter` takes
//! it from the submission queue, and its completion goes in at the end of
//! the submission, or as task work ([`Deferred`]): an `IORING_NOP_TW`, a
//! link's next request and the rest of a failed link run after the
//! submission's completions, when the thread returns to its program, waits
//! or takes a signal, or with `IORING_SETUP_DEFER_TASKRUN` when it waits on
//! the ring, as Linux master's `tw.c` runs them. A transfer that would wait
//! for its file waits ([`arm`]), and goes on as task work of its submitter
//! once a call of any thread or process made the file ready
//! ([`complete_ready`]), waking the submitter's wait as a signal would.
//! `poll` and `epoll` watch the ring's descriptor as `io_uring_poll`
//! answers. The
//! setup flags that need a kernel thread, polled I/O or another layout of
//! the rings give `EINVAL`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{PageSource, SharedPages};
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome, err, ok};

mod fs;
mod net;
mod poll;
mod register;
mod splice;
mod timeout;

/// The most submission queue entries, and completion queue entries.
const MAX_ENTRIES: u32 = 32768;
const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

const SETUP_CQSIZE: u32 = 1 << 3;
const SETUP_CLAMP: u32 = 1 << 4;
const SETUP_R_DISABLED: u32 = 1 << 6;
const SETUP_SUBMIT_ALL: u32 = 1 << 7;
const SETUP_COOP_TASKRUN: u32 = 1 << 8;
const SETUP_TASKRUN_FLAG: u32 = 1 << 9;
const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const SETUP_NO_SQARRAY: u32 = 1 << 16;
/// Every flag Linux 7.0 knows: `IORING_SETUP_IOPOLL` to `_SQ_REWIND`.
const SETUP_KNOWN: u32 = (1 << 21) - 1;
/// The flags implemented. `IOPOLL`, `SQPOLL`, `SQ_AFF`, `ATTACH_WQ`,
/// `SQE128`, `CQE32`, `NO_MMAP`, `REGISTERED_FD_ONLY`, `HYBRID_IOPOLL`,
/// `CQE_MIXED`, `SQE_MIXED` and `SQ_REWIND` are not.
const SETUP_IMPLEMENTED: u32 = SETUP_CQSIZE
    | SETUP_CLAMP
    | SETUP_R_DISABLED
    | SETUP_SUBMIT_ALL
    | SETUP_COOP_TASKRUN
    | SETUP_TASKRUN_FLAG
    | SETUP_SINGLE_ISSUER
    | SETUP_DEFER_TASKRUN
    | SETUP_NO_SQARRAY;
/// The features Linux 6.12 reports, `IORING_FEAT_SINGLE_MMAP` to
/// `_MIN_TIMEOUT`.
const FEATURES: u32 = (1 << 16) - 1;

const ENTER_GETEVENTS: u32 = 1 << 0;
const ENTER_EXT_ARG: u32 = 1 << 3;
const ENTER_REGISTERED_RING: u32 = 1 << 4;
const ENTER_ABS_TIMER: u32 = 1 << 5;
const ENTER_EXT_ARG_REG: u32 = 1 << 6;
/// `IORING_ENTER_GETEVENTS` to `_NO_IOWAIT`, Linux 7.0's. A wait counts as
/// no I/O wait anyway, so `_NO_IOWAIT` changes nothing.
const ENTER_KNOWN: u32 = (1 << 8) - 1;
/// How many ring descriptors a task may register.
const RINGFD_REG_MAX: u32 = 16;

/// `struct io_rings`: the queues' heads and tails, then the rest, and the
/// completion queue entries from the next cache line.
const SQ_HEAD: u64 = 0;
const SQ_TAIL: u64 = 4;
const CQ_HEAD: u64 = 8;
const CQ_TAIL: u64 = 12;
const SQ_RING_MASK: u64 = 16;
const CQ_RING_MASK: u64 = 20;
const SQ_RING_ENTRIES: u64 = 24;
const CQ_RING_ENTRIES: u64 = 28;
const SQ_DROPPED: u64 = 32;
const SQ_FLAGS: u64 = 36;
const CQ_FLAGS: u64 = 40;
const CQ_OVERFLOW: u64 = 44;
const CQES: u64 = 64;
/// `IORING_SQ_CQ_OVERFLOW`: completions wait in the kernel for room.
const SQ_CQ_OVERFLOW: u32 = 1 << 1;
/// `IORING_SQ_TASKRUN`: with `IORING_SETUP_TASKRUN_FLAG`, task work of the
/// ring waits to run.
const SQ_TASKRUN: u32 = 1 << 2;
/// `IO_LOCAL_TW_DEFAULT_MAX`: the task work an `IORING_SETUP_DEFER_TASKRUN`
/// ring runs at once, unless a wait wants more completions.
const LOCAL_TW_DEFAULT_MAX: u32 = 20;

const SQE_BYTES: u64 = 64;
const CQE_BYTES: u64 = 16;

/// Where `mmap` finds the rings: `IORING_OFF_SQ_RING` and `_CQ_RING` the
/// rings, `IORING_OFF_SQES` the entries, chosen by these bits of the offset.
const OFF_MMAP_MASK: u64 = 0xf800_0000;
const OFF_CQ_RING: u64 = 0x0800_0000;
const OFF_SQES: u64 = 0x1000_0000;

const OP_NOP: u8 = 0;
const OP_READV: u8 = 1;
const OP_WRITEV: u8 = 2;
const OP_FSYNC: u8 = 3;
const OP_READ_FIXED: u8 = 4;
const OP_WRITE_FIXED: u8 = 5;
const OP_ASYNC_CANCEL: u8 = 14;
const OP_FILES_UPDATE: u8 = 20;
const OP_READ: u8 = 22;
const OP_WRITE: u8 = 23;
const OP_EPOLL_CTL: u8 = 29;
const OP_PROVIDE_BUFFERS: u8 = 31;
const OP_REMOVE_BUFFERS: u8 = 32;
const OP_EPOLL_WAIT: u8 = 59;
const OP_READV_FIXED: u8 = 60;
const OP_WRITEV_FIXED: u8 = 61;
/// The operations implemented.
const OPS: [u8; 31] = [
    OP_NOP,
    OP_READV,
    OP_WRITEV,
    OP_FSYNC,
    OP_READ_FIXED,
    OP_WRITE_FIXED,
    OP_ASYNC_CANCEL,
    OP_FILES_UPDATE,
    OP_READ,
    OP_WRITE,
    OP_EPOLL_CTL,
    OP_PROVIDE_BUFFERS,
    OP_REMOVE_BUFFERS,
    OP_EPOLL_WAIT,
    OP_READV_FIXED,
    OP_WRITEV_FIXED,
    net::OP_ACCEPT,
    net::OP_CONNECT,
    net::OP_SEND,
    net::OP_RECV,
    net::OP_SENDMSG,
    net::OP_RECVMSG,
    net::OP_SHUTDOWN,
    net::OP_SOCKET,
    timeout::OP_TIMEOUT,
    timeout::OP_TIMEOUT_REMOVE,
    timeout::OP_LINK_TIMEOUT,
    poll::OP_POLL_ADD,
    poll::OP_POLL_REMOVE,
    splice::OP_SPLICE,
    splice::OP_TEE,
];
/// Whether operation `opcode` runs.
fn supported(opcode: u8) -> bool {
    OPS.contains(&opcode) || fs::OPS.contains(&opcode)
}
/// `IORING_OP_LAST` of Linux 7.0, after `IORING_OP_URING_CMD128`.
const OP_LAST: u8 = 65;
/// `KMALLOC_MAX_SIZE` on x86-64: the most `kmalloc` gives at once, 4 MiB
/// (`MAX_PAGE_ORDER` 10).
const MAX_KMALLOC: u64 = 4 << 20;

/// `IOSQE_*`: what every operation takes, then what only some do.
const IOSQE_FIXED_FILE: u8 = 1 << 0;
const IOSQE_IO_DRAIN: u8 = 1 << 1;
const IOSQE_IO_LINK: u8 = 1 << 2;
const IOSQE_IO_HARDLINK: u8 = 1 << 3;
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;
const SQE_COMMON_FLAGS: u8 = 1 | IOSQE_IO_LINK | IOSQE_IO_HARDLINK | 1 << 4;
const SQE_VALID_FLAGS: u8 =
    SQE_COMMON_FLAGS | IOSQE_BUFFER_SELECT | IOSQE_IO_DRAIN | IOSQE_CQE_SKIP_SUCCESS;
const LINK_FLAGS: u8 = IOSQE_IO_LINK | IOSQE_IO_HARDLINK;
/// `IORING_NOP_INJECT_RESULT`: the NOP completes with its `len`.
const NOP_INJECT_RESULT: u32 = 1;
/// `IORING_NOP_FILE`: the NOP looks for the file of its `fd`, registered
/// with `IORING_NOP_FIXED_FILE`.
const NOP_FILE: u32 = 1 << 1;
const NOP_FIXED_FILE: u32 = 1 << 2;
/// `IORING_NOP_FIXED_BUFFER`: the NOP looks for registered buffer
/// `buf_index`.
const NOP_FIXED_BUFFER: u32 = 1 << 3;
/// `IORING_NOP_TW`: the NOP completes as task work.
const NOP_TW: u32 = 1 << 4;
/// `IORING_NOP_CQE32`: the NOP fills a 32-byte completion, which only an
/// `IORING_SETUP_CQE32` or `_CQE_MIXED` ring has.
const NOP_CQE32: u32 = 1 << 5;
/// Linux 7.0's `NOP_FLAGS`: `IORING_NOP_INJECT_RESULT` to `_CQE32`, with
/// `IORING_NOP_TW` (completing as task work).
const NOP_FLAGS: u32 = (1 << 6) - 1;
/// `IORING_ASYNC_CANCEL_*`: what an `IORING_OP_ASYNC_CANCEL` or
/// `IORING_REGISTER_SYNC_CANCEL` looks for. Every request that matches,
/// not only the first; any request; one of a file, `fd` registered with
/// `_FD_FIXED`; one of a `user_data` (without `_FD` or `_OP`, too); one of
/// an operation.
const CANCEL_ALL: u32 = 1 << 0;
const CANCEL_FD: u32 = 1 << 1;
const CANCEL_ANY: u32 = 1 << 2;
const CANCEL_FD_FIXED: u32 = 1 << 3;
const CANCEL_USERDATA: u32 = 1 << 4;
const CANCEL_OP: u32 = 1 << 5;
/// `CANCEL_FLAGS`, every flag a cancellation takes.
const CANCEL_FLAGS: u32 = (1 << 6) - 1;
/// `IORING_FSYNC_DATASYNC`, the only flag of `IORING_OP_FSYNC`.
const FSYNC_DATASYNC: u32 = 1;
/// `IORING_RW_ATTR_FLAG_PI`, the only attribute of a read or write.
const RW_ATTR_FLAG_PI: u64 = 1;
/// `RWF_HIPRI`, polled I/O, which only an `IORING_SETUP_IOPOLL` ring does.
const RWF_HIPRI: u32 = 1;
/// `RWF_NOWAIT`: the request may not wait.
const RWF_NOWAIT: u32 = 8;

const REGISTER_BUFFERS: u64 = 0;
const UNREGISTER_BUFFERS: u64 = 1;
const REGISTER_BUFFERS2: u64 = 15;
const REGISTER_BUFFERS_UPDATE: u64 = 16;
const REGISTER_FILES: u64 = 2;
const UNREGISTER_FILES: u64 = 3;
const REGISTER_FILES_UPDATE: u64 = 6;
const REGISTER_FILES2: u64 = 13;
const REGISTER_FILES_UPDATE2: u64 = 14;
const REGISTER_PROBE: u64 = 8;
const REGISTER_PBUF_RING: u64 = 22;
const UNREGISTER_PBUF_RING: u64 = 23;
const REGISTER_SYNC_CANCEL: u64 = 24;
const REGISTER_RING_FDS: u64 = 20;
const UNREGISTER_RING_FDS: u64 = 21;
const REGISTER_FILE_ALLOC_RANGE: u64 = 25;
const REGISTER_PBUF_STATUS: u64 = 26;
/// `IOU_PBUF_RING_MMAP`: the kernel gives the ring's pages, which the
/// ring's descriptor maps at `IORING_OFF_PBUF_RING`.
const PBUF_RING_MMAP: u16 = 1;
/// `IOU_PBUF_RING_INC`: a buffer is used up a part at a time.
const PBUF_RING_INC: u16 = 2;
const OFF_PBUF_RING: u64 = 0x8000_0000;
const OFF_PBUF_SHIFT: u64 = 16;
/// `MAX_BIDS_PER_BGID`: a buffer's ID is 16 bits of a completion.
const MAX_BIDS_PER_BGID: u64 = 1 << 16;
/// `IORING_CQE_F_MORE`: the request posts more completions.
const CQE_F_MORE: u32 = 1 << 1;
const CQE_F_BUFFER: u32 = 1;
const CQE_F_BUF_MORE: u32 = 1 << 4;
const CQE_BUFFER_SHIFT: u32 = 16;
/// `IORING_RSRC_REGISTER_SPARSE`: an `IORING_REGISTER_FILES2` with no
/// descriptors, its slots all empty.
const RSRC_REGISTER_SPARSE: u32 = 1;
/// `IORING_MAX_FIXED_FILES`.
const MAX_FIXED_FILES: u32 = 1 << 20;
/// `IORING_REGISTER_FILES_SKIP`: an update leaves the slot as it is.
const FILES_SKIP: i32 = -2;
/// `IORING_FILE_INDEX_ALLOC`: an `IORING_OP_FILES_UPDATE` that puts each
/// file in a free slot and gives back where.
const FILE_INDEX_ALLOC: u32 = u32::MAX;
/// `IORING_MAX_REG_BUFFERS`.
const MAX_REG_BUFFERS: u64 = 1 << 14;
/// The largest buffer one may register (`io_validate_user_buf_range`).
const MAX_BUFFER: u64 = 1 << 30;
/// `CAP_IPC_LOCK`, which spares a ring's buffers from RLIMIT_MEMLOCK.
const CAP_IPC_LOCK: u64 = 1 << 14;
/// `IORING_REGISTER_LAST` of Linux 7.0, after `_BPF_FILTER`.
const REGISTER_LAST: u64 = 38;
const REGISTER_USE_REGISTERED_RING: u64 = 1 << 31;
/// `IO_URING_OP_SUPPORTED`.
const OP_SUPPORTED: u16 = 1;

const ETIME: Errno = Errno(62);
const ECANCELED: Errno = Errno(125);
const EALREADY: Errno = Errno(114);
const EOPNOTSUPP: Errno = Errno(95);
const EEXIST: Errno = Errno(17);
const ENOBUFS: Errno = Errno(105);
const ENXIO: Errno = Errno(6);
const EBUSY: Errno = Errno(16);
const EOVERFLOW: Errno = Errno(75);
const ENFILE: Errno = Errno(23);
const E2BIG: Errno = Errno(7);

/// The pages of a ring, which a mapping cannot reach past: a page past
/// them raises `SIGBUS`, as Linux inserts only the ring's pages.
struct RingPages {
    size: u64,
}

impl PageSource for RingPages {
    fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
    /// Linux's `io_region_mmap` makes the rings `VM_DONTEXPAND`.
    fn fixed(&self) -> bool {
        true
    }
    /// `io_region_mmap` adds `VM_DONTEXPAND`, and `vm_insert_pages`
    /// `VM_MIXEDMAP`; the ring's anonymous inode runs nothing.
    fn vma_flags(&self, flags: u64) -> u64 {
        use paludarium_mmu::vm;
        (flags | vm::DONTEXPAND | vm::MIXEDMAP) & !vm::MAYEXEC
    }
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
    fn linked(&self) -> bool {
        false
    }
}

/// A ring and what the kernel keeps of it.
pub(crate) struct Ring {
    flags: u32,
    sq_entries: u32,
    cq_entries: u32,
    /// `struct io_rings`, and the submission queue's array after the
    /// completion queue entries unless `IORING_SETUP_NO_SQARRAY`.
    rings: SharedPages,
    sq_array: Option<u64>,
    sqes: SharedPages,
    sqes_len: u64,
    /// The thread that made it, or that enabled it, with
    /// `IORING_SETUP_SINGLE_ISSUER`: the only one that may submit and
    /// register, and wait with `IORING_SETUP_DEFER_TASKRUN`.
    submitter: std::sync::OnceLock<u32>,
    /// `IORING_SETUP_R_DISABLED`, until it is enabled.
    disabled: std::sync::atomic::AtomicBool,
    restrictions: Mutex<register::Restrictions>,
    personalities: Mutex<register::Personalities>,
    /// Held across a submission, as Linux's `uring_lock`: threads that
    /// submit at once take entries one after another, never the same ones.
    submitting: Mutex<()>,
    state: Mutex<State>,
    /// Who its registered buffers charge (`ctx->user`): the user that made
    /// it, unless it had `CAP_IPC_LOCK`.
    charged: Option<(Arc<crate::memfd::SecretPages>, u32)>,
    /// The registered buffers, once `IORING_REGISTER_BUFFERS` registered
    /// them (`ctx->buf_table`).
    buffers: Mutex<Option<Buffers>>,
    /// The registered files, once `IORING_REGISTER_FILES` registered them
    /// (`ctx->file_table`).
    files: Mutex<Option<Files>>,
    /// The buffer groups, by ID (`ctx->io_bl_xa`).
    buffer_lists: Mutex<std::collections::BTreeMap<u16, BufferList>>,
    /// The task work of an `IORING_SETUP_DEFER_TASKRUN` ring, which only
    /// its waits run (`ctx->work_list`).
    local: Mutex<VecDeque<Deferred>>,
    /// The requests that wait for their files, which a cancellation finds
    /// (`ctx->cancel_table`), and the bits of its hash.
    cancels: Mutex<Cancels>,
    hash_bits: u32,
    /// The timeouts that wait.
    timeouts: Mutex<timeout::Timeouts>,
    /// The readiness hub of the thread that made it, which a completion
    /// tells (`io_poll_wq_wake`), and how many times one went in: its
    /// descriptor's input generation for `poll` and `epoll`.
    hub: Arc<crate::events::ReadinessHub>,
    posted: std::sync::atomic::AtomicU64,
    /// Its own anonymous inode's status (`anon_inode_create_getfile`).
    stat: FileStat,
    /// What `F_SETFL` set on it ([`crate::files::StatusFlags`]).
    status: crate::files::StatusFlags,
}

/// A thread's task work for its rings without
/// `IORING_SETUP_DEFER_TASKRUN` (`tctx->task_list`), in order, which its
/// [`crate::SignalInbox`] keeps: it runs as the thread returns to its
/// program, which every such ring tells it to (`TWA_SIGNAL`, or
/// `TWA_SIGNAL_NO_IPI` with `IORING_SETUP_COOP_TASKRUN`, which only spares a
/// thread running its program an interrupt), and as any of its rings waits.
/// Work another thread or process adds, as a request that waited for its
/// file goes on, ends the thread's interruptible wait as a signal would
/// (`TIF_NOTIFY_SIGNAL`). A new thread has none of its maker's.
#[derive(Default)]
pub(crate) struct TaskWork {
    queue: VecDeque<(std::sync::Weak<dyn FileHandle>, Deferred)>,
    /// The thread exited (`PF_EXITING`): work added from then on runs at
    /// once as Linux's `io_fallback_tw` runs it ([`run_terminated`]).
    exited: bool,
    /// The thread has an io_uring context (`current->io_uring`), which
    /// making a ring, submitting to one or registering a ring descriptor
    /// gives it, neither `fork` nor `clone` copies, and `execve` takes away.
    context: bool,
    /// The rings it registered (`tctx->registered_rings`,
    /// `IORING_REGISTER_RING_FDS`), which `io_uring_enter` and
    /// `io_uring_register` find by index with `IORING_ENTER_REGISTERED_RING`
    /// and `IORING_REGISTER_USE_REGISTERED_RING`; `execve` and the thread's
    /// exit let go of them (`io_uring_unreg_ringfd`).
    rings: [Option<Arc<dyn FileHandle>>; RINGFD_REG_MAX as usize],
}

impl TaskWork {
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// The requests of every ring that wait for their file to be ready
/// (`io_arm_poll_handler`), in the order they began to.
#[derive(Default)]
pub(crate) struct Polls {
    armed: Mutex<Vec<Armed>>,
    count: std::sync::atomic::AtomicUsize,
    /// Task work that came for a thread that exited, which runs once no
    /// ring's lock is held (`io_fallback_tw` queuing it for a worker): at
    /// the next [`complete_ready`], which every call's checkpoint, every
    /// wait and every thread's exit runs, so before the call that queued it
    /// returns. Work of a ring another thread holds stays for that thread to
    /// run once it lets go ([`run_fallback`]).
    fallback: Mutex<Vec<(std::sync::Weak<dyn FileHandle>, Deferred)>>,
    /// Every ring, which a thread's `execve` or exit looks through for its
    /// requests (`tctx->xa`).
    rings: Mutex<Vec<std::sync::Weak<dyn FileHandle>>>,
    /// A ring may have a timer armed ([`timeout`]).
    timers: std::sync::atomic::AtomicBool,
}

/// A request that waits for its file (`struct async_poll`): the ring, the
/// thread that submitted it, whose task work it goes on as, and that
/// thread's readiness hub, the file and the events it waits for, the
/// request and the rest of its link, and the registered files it holds.
struct Armed {
    /// Its entry in the ring's [`Cancels`].
    id: u64,
    /// The ring, which a request does not keep open: once the ring's last
    /// descriptor and mapping go, its requests go too
    /// (`io_ring_ctx_wait_and_kill`).
    ring: std::sync::Weak<dyn FileHandle>,
    inbox: Arc<crate::SignalInbox>,
    hub: Arc<crate::events::ReadinessHub>,
    polled: Arc<dyn FileHandle>,
    mask: u32,
    chain: Vec<Request>,
    held: Vec<Arc<Node>>,
    /// How an `IORING_OP_POLL_ADD` waits; nothing for a request that runs
    /// again once its file is ready.
    watch: Option<poll::Watch>,
}

impl Armed {
    fn is(&self, ring: &Ring, id: u64) -> bool {
        self.id == id && std::ptr::addr_eq(self.ring.as_ptr(), std::ptr::from_ref(ring))
    }
    /// Its task work runs on its own, and sees that it was cancelled.
    fn queued(&self) -> bool {
        self.watch.as_ref().is_some_and(poll::Watch::queued)
    }
}

/// Task work: what is left of a request, or of its link, until it runs.
enum Deferred {
    /// `io_req_task_complete`: an `IORING_NOP_TW` that ran, or a timeout
    /// that did not expire, its completion, the registered files it holds,
    /// the rest of its link, and whether it failed.
    Complete {
        done: Done,
        held: Vec<Arc<Node>>,
        rest: Vec<Request>,
        flags: u8,
        failed: bool,
    },
    /// `io_req_task_submit`: a link's next request runs, and the rest wait
    /// for it; or a request whose file became ready runs again
    /// (`io_poll_task_func`), with the registered files it held.
    Submit(Vec<Request>, Vec<Arc<Node>>),
    /// `io_poll_task_func`: a request whose file became ready, or that a
    /// cancellation took from its wait ([`cancel`]), leaves the ring's
    /// [`Cancels`], and runs again or fails with `ECANCELED`, with the
    /// registered files it held.
    Poll {
        id: u64,
        chain: Vec<Request>,
        held: Vec<Arc<Node>>,
    },
    /// `io_poll_task_func`: a poll that waits no more ([`poll::finished`]).
    Polled(Box<Armed>),
    /// `io_poll_task_func`: a multishot poll that waits on has events
    /// ([`poll::more`]).
    PollMore { id: u64 },
    /// `io_req_tw_fail_links`: the rest of a link that failed completes,
    /// each with the error it failed to prepare with or `ECANCELED`, and
    /// none posts with `REQ_F_SKIP_LINK_CQES`.
    Fail { chain: Vec<Request>, skip: bool },
    /// `io_timeout_complete`: a timeout that expired, and its link.
    Timeout(Vec<Request>),
    /// `io_req_task_link_timeout`: a linked timeout that expired, and the
    /// `user_data` of the request it is for.
    LinkTimeout { request: Request, head: u64 },
}

/// The requests of a ring that wait for their files (`ctx->cancel_table`),
/// in the order they began to, from then until their task work runs
/// (`io_poll_task_func`), and the number of the last cancellation
/// (`ctx->cancel_seq`).
#[derive(Default)]
struct Cancels {
    hashed: Vec<Hashed>,
    seq: u32,
    next: u64,
}

/// A request in [`Cancels`]: what a cancellation matches it by, whether one
/// did, and the number of the last that matched it
/// (`req->work.cancel_seq`), which the same one does not again.
struct Hashed {
    id: u64,
    /// The [`crate::SignalInbox`] of the thread that submitted it
    /// (`req->tctx`), which its `execve` or its process's exit cancels it
    /// for.
    inbox: usize,
    user_data: u64,
    opcode: u8,
    file: usize,
    cancelled: bool,
    seq: Option<u32>,
}

/// What an `IORING_OP_ASYNC_CANCEL` or `IORING_REGISTER_SYNC_CANCEL` looks
/// for (`struct io_cancel_data`): the `user_data`, the flags, the descriptor
/// of `IORING_ASYNC_CANCEL_FD` and the operation of `_OP`.
#[derive(Clone, Copy)]
struct CancelKey {
    user_data: u64,
    flags: u32,
    fd: i32,
    opcode: u8,
}

/// A request that completed in a batch: its completion, whether it posts
/// one, and the task work its link goes on with.
struct Done {
    user_data: u64,
    res: i32,
    flags: u32,
    post: bool,
    /// Its linked timeout ([`Request::ltimeout`]), which is over with it
    /// (`io_disarm_next`).
    ltimeout: Option<u64>,
    next: Vec<Deferred>,
}

/// A buffer group (`struct io_buffer_list`): the buffers
/// `IORING_OP_PROVIDE_BUFFERS` gave, first first, or a ring of them that
/// `IORING_REGISTER_PBUF_RING` registered. A group of provided buffers
/// stays once they are all used.
enum BufferList {
    Provided(VecDeque<Provided>),
    Ring(BufferRing),
}

/// A provided buffer (`struct io_buffer`).
#[derive(Clone, Copy)]
struct Provided {
    addr: u64,
    len: u32,
    bid: u16,
}

/// A ring of buffers the program fills (`struct io_uring_buf_ring`): its
/// tail is the last 2 bytes of the first entry, and the kernel keeps the
/// head.
struct BufferRing {
    memory: RingMemory,
    mask: u16,
    head: u16,
    incremental: bool,
    /// Who its pages charge, as the registered buffers'.
    charged: Option<(Arc<crate::memfd::SecretPages>, u32)>,
    pages: u64,
}

/// Where a ring of buffers is: pages the kernel gave, of a size
/// (`IOU_PBUF_RING_MMAP`), or the program's memory at an address, which
/// is read and written through its mappings at each use.
enum RingMemory {
    Kernel(SharedPages, u64),
    User(u64),
}

impl Drop for BufferRing {
    fn drop(&mut self) {
        if let Some((pages, user)) = &self.charged {
            pages.release(*user, self.pages);
        }
    }
}

impl BufferRing {
    fn load(&self, c: &Context<'_>, at: u64, bytes: &mut [u8]) -> Result<(), Errno> {
        match &self.memory {
            RingMemory::Kernel(pages, _) => {
                pages.load(at, bytes);
                Ok(())
            }
            RingMemory::User(addr) => c
                .mem
                .read(GuestAddr(addr + at), bytes)
                .map_err(|_| Errno::EFAULT),
        }
    }

    fn store(&self, c: &Context<'_>, at: u64, bytes: &[u8]) -> Result<(), Errno> {
        match &self.memory {
            RingMemory::Kernel(pages, _) => {
                pages.store(at, bytes);
                Ok(())
            }
            RingMemory::User(addr) => c
                .mem
                .write(GuestAddr(addr + at), bytes)
                .map_err(|_| Errno::EFAULT),
        }
    }

    /// The tail the program moved to.
    fn tail(&self, c: &Context<'_>) -> Result<u16, Errno> {
        let mut tail = [0; 2];
        self.load(c, 14, &mut tail)?;
        Ok(u16::from_le_bytes(tail))
    }

    /// The entry at `index` (`io_ring_head_to_buf`): its address, length
    /// and buffer ID.
    fn entry(&self, c: &Context<'_>, index: u16) -> Result<(u64, u32, u16), Errno> {
        let mut entry = [0; 16];
        self.load(c, 16 * u64::from(index & self.mask), &mut entry)?;
        Ok((
            u64_at(&entry, 0),
            u32_at(&entry, 8),
            u16::from_le_bytes([entry[12], entry[13]]),
        ))
    }

    /// Uses `len` bytes of one buffer (`io_kbuf_commit`), and says whether
    /// that buffer is used up: a whole one moves the head, and with
    /// `IOU_PBUF_RING_INC` the bytes come off the buffer's start
    /// (`io_kbuf_inc_commit`), a buffer used up moving the head; no bytes,
    /// or a buffer of none, leaves it.
    fn commit(&mut self, c: &Context<'_>, mut len: u32) -> Result<bool, Errno> {
        if !self.incremental {
            self.head = self.head.wrapping_add(1);
            return Ok(true);
        }
        if len == 0 {
            return Ok(false);
        }
        while len != 0 {
            let (addr, buf_len, _) = self.entry(c, self.head)?;
            let at = 16 * u64::from(self.head & self.mask);
            let this_len = len.min(buf_len);
            let left = buf_len - this_len;
            if left != 0 || this_len == 0 {
                self.store(c, at, &addr.wrapping_add(u64::from(this_len)).to_le_bytes())?;
                self.store(c, at + 8, &left.to_le_bytes())?;
                return Ok(false);
            }
            self.store(c, at + 8, &0u32.to_le_bytes())?;
            self.head = self.head.wrapping_add(1);
            len -= this_len;
        }
        Ok(true)
    }
}

/// A buffer a read selected: its group and ID, the bytes it reads to,
/// and, for one of a ring, whether it was used already (a file that cannot
/// be polled) and whether that left some of it.
#[derive(Clone, Copy)]
struct Chosen {
    bgid: u16,
    bid: u16,
    addr: u64,
    len: u32,
    /// The provided buffer's whole length, which it has again if it goes
    /// back to its group.
    size: u32,
    ring: bool,
    committed: bool,
    more: bool,
}

/// A registered file (`struct io_rsrc_node`), held while a slot or a
/// request of the running submission has it, and the tag
/// `IORING_REGISTER_FILES2` or `_FILES_UPDATE2` gave it: once nothing
/// holds it, a tag that is not 0 is the `user_data` of a completion of 0
/// ([`Ring::put_nodes`]).
struct Node {
    held: Held,
    tag: u64,
}

/// What a [`Node`] holds: a registered file, or a registered buffer.
enum Held {
    File(crate::files::Descriptor),
    Buffer(RegisteredBuffer),
}

impl Node {
    fn file(&self) -> Option<&crate::files::Descriptor> {
        match &self.held {
            Held::File(file) => Some(file),
            Held::Buffer(_) => None,
        }
    }
    fn buffer(&self) -> Option<&RegisteredBuffer> {
        match &self.held {
            Held::Buffer(buffer) => Some(buffer),
            Held::File(_) => None,
        }
    }
}

/// A registered buffer (`struct io_mapped_ubuf`): its address and length,
/// its pages, pinned (`io_pin_pages`), and the pages of RLIMIT_MEMLOCK it
/// charges, which it gives back once nothing holds it (`io_buffer_unmap`).
struct RegisteredBuffer {
    base: u64,
    len: u64,
    pages: Arc<paludarium_mmu::Pinned>,
    charged: Option<(Arc<crate::memfd::SecretPages>, u32)>,
    count: u64,
}

impl Drop for RegisteredBuffer {
    fn drop(&mut self) {
        if let Some((pages, user)) = &self.charged {
            pages.release(*user, self.count);
        }
    }
}

/// A ring's registered files: the slots of its `count` that hold an open
/// file, each held as its descriptor was, and where
/// `IORING_FILE_INDEX_ALLOC` looks for a free one (`file_alloc_start` to
/// `file_alloc_end`, from the table's `alloc_hint`).
struct Files {
    count: u32,
    slots: std::collections::BTreeMap<u32, Arc<Node>>,
    alloc: (u32, u32),
    hint: u32,
}

impl Files {
    /// Empties `slot` (`io_reset_rsrc_node`), giving what it held; the
    /// next free one is looked for from there (`io_file_bitmap_clear`).
    fn clear(&mut self, slot: u32) -> Option<Arc<Node>> {
        let held = self.slots.remove(&slot);
        if held.is_some() {
            self.hint = slot;
        }
        held
    }

    /// Puts `file` in the empty `slot`; the next free one is looked for
    /// past it (`io_file_bitmap_set`).
    fn set(&mut self, slot: u32, file: crate::files::Descriptor, tag: u64) {
        self.slots.insert(
            slot,
            Arc::new(Node {
                held: Held::File(file),
                tag,
            }),
        );
        self.hint = slot + 1;
    }

    /// A free slot in the allocation range, as `io_file_bitmap_get`
    /// finds one: from the hint to the range's end, then from its start
    /// to the hint, else `ENFILE`.
    fn free(&mut self) -> Result<u32, Errno> {
        let (start, end) = self.alloc;
        if self.hint < start || self.hint >= end {
            self.hint = start;
        }
        let mut last = end;
        loop {
            if let Some(slot) = (self.hint..last).find(|slot| !self.slots.contains_key(slot)) {
                return Ok(slot);
            }
            if self.hint == start {
                return Err(ENFILE);
            }
            last = self.hint;
            self.hint = start;
        }
    }
}

/// The part of a registered buffer a request moves
/// ([`Ring::registered`]).
struct Registered {
    pages: Arc<paludarium_mmu::Pinned>,
    /// Each piece's offset into the pages, and its length.
    pieces: Vec<(u64, usize)>,
}

/// A ring's registered buffers (`ctx->buf_table`): each slot's buffer, or
/// none for a slot registered empty. A request holds the buffer it moves
/// while it runs (`io_req_assign_buf_node`).
struct Buffers {
    slots: Vec<Option<Arc<Node>>>,
}

#[derive(Default)]
struct State {
    /// The submission queue's head the kernel moved to, which it writes to
    /// the ring after each submission.
    sq_head: u32,
    /// The completion queue's tail, which only the kernel moves.
    cq_tail: u32,
    /// Completions that found the queue full (`IORING_FEAT_NODROP`), in
    /// order: they go in as the program makes room.
    overflow: VecDeque<(u64, i32, u32)>,
    /// A request asked to skip its completion: `IOSQE_IO_DRAIN` is
    /// `EOPNOTSUPP` from then on.
    drain_disabled: bool,
    /// While a submission runs, the completions of its requests, which
    /// Linux posts once it has issued them all (`compl_reqs`,
    /// `io_submit_flush_completions`); a registered file's tag goes in at
    /// once (`io_post_aux_cqe`).
    deferred: Option<Vec<Done>>,
    /// The registered files the requests of the running submission found,
    /// in order, which they hold until their completions are posted
    /// (`io_free_batch_list`).
    held: Vec<Arc<Node>>,
    /// Registered files and buffers no slot holds any more that a request
    /// still does: one of the running batch, or one that waits for its
    /// file ([`arm`]). Each posts its tag once nothing holds it, at the
    /// end of the batch it is let go of in ([`Ring::end`]).
    retired: Vec<Arc<Node>>,
}

/// A request taken from the submission queue and prepared.
struct Request {
    user_data: u64,
    opcode: u8,
    flags: u8,
    /// What it fails with if its preparation failed.
    failed: Option<Errno>,
    /// The timeout linked to it, once it was issued (`REQ_F_LINK_TIMEOUT`).
    ltimeout: Option<u64>,
    /// Its personality, which it runs with (`REQ_F_CREDS`).
    credentials: Option<Arc<dyn register::Personality>>,
    work: Work,
}

enum Work {
    /// `IORING_OP_NOP`: its result, and the registered or other file
    /// (`IORING_NOP_FILE`) and registered buffer
    /// (`IORING_NOP_FIXED_BUFFER`) it looks for.
    Nop {
        result: i32,
        file: Option<(i32, bool)>,
        buffer: Option<u16>,
        tw: bool,
    },
    EpollCtl {
        epfd: i32,
        op: i32,
        fd: i32,
        event: (u32, u64),
    },
    /// `IORING_OP_EPOLL_WAIT`: the epoll of `fd`, and where at most `max`
    /// of its events go; then the file it found before it waited for it.
    EpollWait {
        fd: i32,
        fixed: bool,
        at: u64,
        max: i32,
        found: Option<crate::files::Descriptor>,
    },
    Transfer(Box<Transfer>),
    /// A socket request ([`net`]).
    Net(Box<net::Net>),
    /// `IORING_OP_TIMEOUT` and `_LINK_TIMEOUT` ([`timeout`]).
    Timeout(Box<timeout::Timeout>),
    /// `IORING_OP_TIMEOUT_REMOVE`.
    TimeoutRemove(Box<timeout::Remove>),
    /// A file request ([`fs`]).
    Fs(Box<fs::Fs>),
    /// `IORING_OP_SPLICE` and `_TEE` ([`splice`]).
    Splice(Box<splice::Splice>),
    /// `IORING_OP_POLL_ADD` ([`poll`]).
    Poll(Box<poll::Poll>),
    /// `IORING_OP_POLL_REMOVE`.
    PollRemove(Box<poll::Remove>),
    /// `IORING_OP_ASYNC_CANCEL`: what it looks for, and whether its `fd` is
    /// a registered one (`IOSQE_FIXED_FILE`).
    Cancel {
        key: CancelKey,
        fixed: bool,
    },
    Fsync {
        fd: i32,
        fixed: bool,
    },
    /// `IORING_OP_FILES_UPDATE`: the `count` descriptors at `addr` go in
    /// the registered files from `offset`, or each in a free slot.
    FilesUpdate {
        offset: u32,
        addr: u64,
        count: u32,
    },
    /// `IORING_OP_PROVIDE_BUFFERS`: `count` buffers of `len` bytes from
    /// `addr`, with the IDs from `bid`, go in group `bgid`; or
    /// `IORING_OP_REMOVE_BUFFERS`: `count` of its buffers go.
    Buffers {
        provide: bool,
        count: u32,
        addr: u64,
        len: u32,
        bgid: u16,
        bid: u16,
    },
    None,
}

/// An `IORING_OP_READ`, `_WRITE`, `_READV`, `_WRITEV`, or one of their
/// registered forms: the entry's fields, then what its preparation found.
struct Transfer {
    fd: i32,
    /// `IOSQE_FIXED_FILE`: `fd` indexes the registered files.
    fixed: bool,
    write: bool,
    vectored: bool,
    /// `IORING_OP_READ_FIXED` or `_WRITE_FIXED`, or with `vectored`
    /// `_READV_FIXED` or `_WRITEV_FIXED`: the buffers are within the
    /// registered one of index `buf_index`.
    registered: bool,
    buf_index: u16,
    /// `IOSQE_BUFFER_SELECT`: a buffer of group `buf_index` is chosen at
    /// issue.
    select: bool,
    offset: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    ioprio: u16,
    attr_ptr: u64,
    attr_type_mask: u64,
    /// The buffers, as `io_import_rw_buffer` imported them; for a vector
    /// in a registered buffer, its entries as they were read, a length past
    /// `MAX_RW_COUNT` cut to one past it.
    segments: Vec<(u64, usize)>,
    /// For a vector in a registered buffer, the most pieces of pages its
    /// entries may take, from their whole lengths ([`within_vector`]).
    page_pieces: u64,
    /// Protection information came with it (`REQ_F_HAS_METADATA`), which
    /// no file here takes.
    metadata: bool,
    /// The provided buffer it chose before it waited for its file, which it
    /// reads to as it goes on.
    kept: Option<Chosen>,
    /// The file it found before it waited for it, and the registered buffer
    /// (`req->file`, `req->buf_node`): it goes on with them, whatever its
    /// descriptor or slots hold by then.
    found: Option<(crate::files::Descriptor, Option<Arc<Node>>)>,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    bytes
        .get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn int_at(bytes: &[u8], at: usize) -> i32 {
    u32_at(bytes, at) as i32
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

impl Ring {
    fn load_u32(&self, at: u64) -> u32 {
        let mut bytes = [0; 4];
        self.rings.load(at, &mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn store_u32(&self, at: u64, value: u32) {
        self.rings.store(at, &value.to_le_bytes());
    }
    /// Its lock, held across a submission or a run of its task work.
    fn submitting(&self) -> std::sync::MutexGuard<'_, ()> {
        self.submitting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// [`Self::submitting`], if no one holds it.
    fn try_submitting(&self) -> Option<std::sync::MutexGuard<'_, ()>> {
        match self.submitting.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps a request's completion for the end of the running batch
    /// ([`State::deferred`]).
    fn complete(&self, done: Done) {
        let mut state = self.state();
        match &mut state.deferred {
            Some(deferred) => deferred.push(done),
            None => {
                if done.post {
                    self.post(&mut state, done.user_data, done.res, done.flags);
                }
            }
        }
    }

    /// Sets or clears `IORING_SQ_TASKRUN`, with `IORING_SETUP_TASKRUN_FLAG`.
    fn mark_taskrun(&self, set: bool) {
        if self.flags & SETUP_TASKRUN_FLAG == 0 {
            return;
        }
        let flags = self.load_u32(SQ_FLAGS);
        let marked = if set {
            flags | SQ_TASKRUN
        } else {
            flags & !SQ_TASKRUN
        };
        if marked != flags {
            self.store_u32(SQ_FLAGS, marked);
        }
    }

    /// Lets go of registered files and buffers no slot holds
    /// (`io_put_rsrc_node`): one a request holds, of the running submission
    /// or one that waits for its file, waits for that request's completion
    /// ([`State::retired`]), and the others post their tags now, in order.
    fn put_nodes(&self, gone: impl IntoIterator<Item = Arc<Node>>) {
        let mut state = self.state();
        for node in gone {
            if Arc::strong_count(&node) > 1 {
                state.retired.push(node);
            } else if node.tag != 0 {
                self.post(&mut state, node.tag, 0, 0);
            }
        }
    }

    /// Starts a batch, a submission or a run of task work, whose
    /// completions wait for its end.
    fn begin(&self) {
        self.state().deferred = Some(Vec::new());
    }

    /// Ends a batch (`io_submit_flush_completions`): its completions go in,
    /// in order, then its requests go (`io_free_batch_list`): the task work
    /// their links go on with, which it gives, and the files they held,
    /// posting the tags of those no slot holds as each request lets go of
    /// them.
    fn end(&self) -> Vec<Deferred> {
        let mut state = self.state();
        let done = state.deferred.take().unwrap_or_default();
        for done in &done {
            if done.post {
                self.post(&mut state, done.user_data, done.res, done.flags);
            }
        }
        let mut next = Vec::new();
        for done in done {
            next.extend(done.ltimeout.and_then(|id| timeout::disarm(self, id)));
            next.extend(done.next);
        }
        for node in std::mem::take(&mut state.held) {
            if let Some(at) = state.retired.iter().position(|r| Arc::ptr_eq(r, &node))
                && Arc::strong_count(&node) == 2
            {
                let retired = state.retired.remove(at);
                if retired.tag != 0 {
                    self.post(&mut state, retired.tag, 0, 0);
                }
            }
        }
        // What nothing holds now posts its tag; what a request that waits
        // for its file holds waits on, for the batch its completion ends.
        for retired in std::mem::take(&mut state.retired) {
            if Arc::strong_count(&retired) > 1 {
                state.retired.push(retired);
            } else if retired.tag != 0 {
                self.post(&mut state, retired.tag, 0, 0);
            }
        }
        next
    }

    /// Puts a completion in the queue, or keeps it while the queue is full
    /// or completions wait already, which keeps them in order.
    fn post(&self, state: &mut State, user_data: u64, res: i32, flags: u32) {
        state.overflow.push_back((user_data, res, flags));
        if !self.flush(state) {
            self.posted();
        }
    }

    /// Posts a completion a request still goes on after
    /// (`io_req_post_cqe`), unless the queue is full.
    fn post_aux(&self, user_data: u64, res: i32, flags: u32) -> bool {
        let mut state = self.state();
        if !state.overflow.is_empty() || self.completions() >= self.cq_entries {
            return false;
        }
        self.post(&mut state, user_data, res, flags);
        true
    }

    /// Tells those that poll the ring's descriptor of a completion
    /// (`io_commit_cqring_flush` waking `ctx->poll_wq`).
    fn posted(&self) {
        self.posted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.hub.changed();
    }

    /// Moves the completions waiting in the kernel into the room the
    /// program made, and says whether any still wait in `sq_flags`, and
    /// whether it moved any.
    fn flush(&self, state: &mut State) -> bool {
        let head = self.load_u32(CQ_HEAD);
        let mut moved = false;
        while state.cq_tail.wrapping_sub(head) < self.cq_entries
            && let Some((user_data, res, flags)) = state.overflow.pop_front()
        {
            let slot = u64::from(state.cq_tail & (self.cq_entries - 1));
            let mut cqe = [0; CQE_BYTES as usize];
            cqe[..8].copy_from_slice(&user_data.to_le_bytes());
            cqe[8..12].copy_from_slice(&res.to_le_bytes());
            cqe[12..].copy_from_slice(&flags.to_le_bytes());
            self.rings.store(CQES + slot * CQE_BYTES, &cqe);
            state.cq_tail = state.cq_tail.wrapping_add(1);
            moved = true;
        }
        if moved {
            self.store_u32(CQ_TAIL, state.cq_tail);
            self.posted();
        }
        let flags = self.load_u32(SQ_FLAGS);
        let waiting = if state.overflow.is_empty() {
            flags & !SQ_CQ_OVERFLOW
        } else {
            flags | SQ_CQ_OVERFLOW
        };
        if waiting != flags {
            self.store_u32(SQ_FLAGS, waiting);
        }
        moved
    }

    /// How many completions the program has not consumed.
    fn completions(&self) -> u32 {
        self.load_u32(CQ_TAIL).wrapping_sub(self.load_u32(CQ_HEAD))
    }

    /// Linux's `io_init_req` and the operation's `prep`: the checks of the
    /// entry, then its operation's own.
    fn prepare(&self, state: &mut State, sqe: &[u8]) -> Request {
        let opcode = sqe[0];
        let flags = sqe[1];
        let mut request = Request {
            user_data: u64_at(sqe, 32),
            opcode,
            flags,
            failed: None,
            ltimeout: None,
            credentials: None,
            work: Work::None,
        };
        let fail = |mut request: Request, e: Errno| {
            request.failed = Some(e);
            request
        };
        if opcode >= OP_LAST {
            return fail(request, Errno::EINVAL);
        }
        if flags & !SQE_COMMON_FLAGS != 0 {
            if flags & !SQE_VALID_FLAGS != 0 {
                return fail(request, Errno::EINVAL);
            }
            // Only the reads, sends and receives, but no `IORING_OP_SENDMSG`,
            // select a buffer
            // (`buffer_select`).
            if flags & IOSQE_BUFFER_SELECT != 0
                && !matches!(
                    opcode,
                    OP_READ | OP_READV | net::OP_SEND | net::OP_RECV | net::OP_RECVMSG
                )
            {
                return fail(request, EOPNOTSUPP);
            }
            if flags & IOSQE_CQE_SKIP_SUCCESS != 0 {
                state.drain_disabled = true;
            }
            if flags & IOSQE_IO_DRAIN != 0 && state.drain_disabled {
                return fail(request, EOPNOTSUPP);
            }
        }
        if !self.allows_request(opcode, flags) {
            return fail(request, Errno::EACCES);
        }
        let transfer = matches!(
            opcode,
            OP_READ
                | OP_WRITE
                | OP_READV
                | OP_WRITEV
                | OP_READ_FIXED
                | OP_WRITE_FIXED
                | OP_READV_FIXED
                | OP_WRITEV_FIXED
        );
        // Only the transfers take a priority, and an accept, a send and a
        // receive their flags there (`ioprio`).
        let takes_ioprio = transfer
            || matches!(
                opcode,
                net::OP_ACCEPT | net::OP_SEND | net::OP_RECV | net::OP_SENDMSG | net::OP_RECVMSG
            );
        if supported(opcode) && !takes_ioprio && u16::from_le_bytes([sqe[2], sqe[3]]) != 0 {
            return fail(request, Errno::EINVAL);
        }
        let personality = u16::from_le_bytes([sqe[42], sqe[43]]);
        if personality != 0 {
            request.credentials = self.personality(personality);
            if request.credentials.is_none() {
                return fail(request, Errno::EINVAL);
            }
        }
        let int_at = |at: usize| int_at(sqe, at);
        let fixed = flags & IOSQE_FIXED_FILE != 0;
        request.work = match opcode {
            _ if transfer => Work::Transfer(Box::new(Transfer {
                fd: int_at(4),
                fixed,
                write: matches!(
                    opcode,
                    OP_WRITE | OP_WRITEV | OP_WRITE_FIXED | OP_WRITEV_FIXED
                ),
                vectored: matches!(
                    opcode,
                    OP_READV | OP_WRITEV | OP_READV_FIXED | OP_WRITEV_FIXED
                ),
                registered: matches!(
                    opcode,
                    OP_READ_FIXED | OP_WRITE_FIXED | OP_READV_FIXED | OP_WRITEV_FIXED
                ),
                buf_index: u16::from_le_bytes([sqe[40], sqe[41]]),
                select: flags & IOSQE_BUFFER_SELECT != 0,
                offset: u64_at(sqe, 8),
                addr: u64_at(sqe, 16),
                len: u32_at(sqe, 24),
                rw_flags: u32_at(sqe, 28),
                ioprio: u16::from_le_bytes([sqe[2], sqe[3]]),
                attr_ptr: u64_at(sqe, 48),
                attr_type_mask: u64_at(sqe, 56),
                segments: Vec::new(),
                page_pieces: 0,
                metadata: false,
                kept: None,
                found: None,
            })),
            OP_FSYNC => {
                // `io_fsync_prep`.
                if u64_at(sqe, 16) != 0
                    || u16::from_le_bytes([sqe[40], sqe[41]]) != 0
                    || int_at(44) != 0
                    || u32_at(sqe, 28) & !FSYNC_DATASYNC != 0
                    || (u64_at(sqe, 8) as i64) < 0
                {
                    return fail(request, Errno::EINVAL);
                }
                Work::Fsync {
                    fd: int_at(4),
                    fixed,
                }
            }
            OP_FILES_UPDATE => {
                // `io_files_update_prep`.
                if fixed || u32_at(sqe, 28) != 0 || int_at(44) != 0 || u32_at(sqe, 24) == 0 {
                    return fail(request, Errno::EINVAL);
                }
                Work::FilesUpdate {
                    offset: u64_at(sqe, 8) as u32,
                    addr: u64_at(sqe, 16),
                    count: u32_at(sqe, 24),
                }
            }
            OP_PROVIDE_BUFFERS | OP_REMOVE_BUFFERS => {
                match prepare_buffers(opcode == OP_PROVIDE_BUFFERS, sqe) {
                    Ok(work) => work,
                    Err(e) => return fail(request, e),
                }
            }
            OP_NOP => {
                // `io_nop_prep`: no ring has 32-byte completions.
                let nop_flags = u32_at(sqe, 28);
                if nop_flags & !NOP_FLAGS != 0 || nop_flags & NOP_CQE32 != 0 {
                    return fail(request, Errno::EINVAL);
                }
                let has = |flag: u32| nop_flags & flag != 0;
                Work::Nop {
                    result: if has(NOP_INJECT_RESULT) {
                        int_at(24)
                    } else {
                        0
                    },
                    // `IOSQE_FIXED_FILE` names a registered one too.
                    file: has(NOP_FILE).then(|| (int_at(4), fixed || has(NOP_FIXED_FILE))),
                    buffer: has(NOP_FIXED_BUFFER).then(|| u16::from_le_bytes([sqe[40], sqe[41]])),
                    tw: has(NOP_TW),
                }
            }
            OP_ASYNC_CANCEL => {
                // `io_async_cancel_prep`, as Linux 7.0 (the CI kernel) has it:
                // `IORING_ASYNC_CANCEL_ANY` matches any file and operation,
                // and the operation is the low byte of `len`. Linux master
                // also refuses one past `IORING_OP_LAST` (`EINVAL`), which
                // matches nothing here.
                let cancel_flags = u32_at(sqe, 28);
                let op = u32_at(sqe, 24);
                if u64_at(sqe, 8) != 0
                    || int_at(44) != 0
                    || cancel_flags & !CANCEL_FLAGS != 0
                    || cancel_flags & CANCEL_ANY != 0 && cancel_flags & (CANCEL_FD | CANCEL_OP) != 0
                {
                    return fail(request, Errno::EINVAL);
                }
                Work::Cancel {
                    key: CancelKey {
                        user_data: u64_at(sqe, 16),
                        flags: cancel_flags,
                        fd: int_at(4),
                        opcode: op as u8,
                    },
                    fixed,
                }
            }
            OP_EPOLL_CTL => {
                if u16::from_le_bytes([sqe[40], sqe[41]]) != 0 || int_at(44) != 0 {
                    return fail(request, Errno::EINVAL);
                }
                Work::EpollCtl {
                    epfd: int_at(4),
                    op: int_at(24),
                    fd: u64_at(sqe, 8) as i32,
                    event: (0, 0),
                }
            }
            // `io_epoll_wait_prep`.
            OP_EPOLL_WAIT => {
                if u64_at(sqe, 8) != 0
                    || u32_at(sqe, 28) != 0
                    || u16::from_le_bytes([sqe[40], sqe[41]]) != 0
                    || int_at(44) != 0
                {
                    return fail(request, Errno::EINVAL);
                }
                Work::EpollWait {
                    fd: int_at(4),
                    fixed,
                    at: u64_at(sqe, 16),
                    max: int_at(24),
                    found: None,
                }
            }
            net::OP_SHUTDOWN
            | net::OP_SOCKET
            | net::OP_ACCEPT
            | net::OP_CONNECT
            | net::OP_SEND
            | net::OP_RECV
            | net::OP_SENDMSG
            | net::OP_RECVMSG => match net::prepare(opcode, flags, sqe) {
                Ok(work) => work,
                Err(e) => return fail(request, e),
            },
            timeout::OP_TIMEOUT | timeout::OP_TIMEOUT_REMOVE | timeout::OP_LINK_TIMEOUT => {
                match timeout::prepare(opcode, fixed, sqe) {
                    Ok(work) => work,
                    Err(e) => return fail(request, e),
                }
            }
            _ if fs::OPS.contains(&opcode) => match fs::prepare(opcode, flags, sqe) {
                Ok(work) => work,
                Err(e) => return fail(request, e),
            },
            splice::OP_SPLICE | splice::OP_TEE => match splice::prepare(opcode, flags, sqe) {
                Ok(work) => work,
                Err(e) => return fail(request, e),
            },
            poll::OP_POLL_ADD | poll::OP_POLL_REMOVE => {
                match poll::prepare(opcode, flags, fixed, sqe) {
                    Ok(work) => work,
                    Err(e) => return fail(request, e),
                }
            }
            _ => return fail(request, EOPNOTSUPP),
        };
        request
    }
}

/// Linux's `io_provide_buffers_prep` and `io_remove_buffers_prep`. The
/// count is the entry's `fd`, a negative one as large.
///
/// - Providing: `rw_flags` or `splice_fd_in` set is `EINVAL`, a count of
///   0 or past `MAX_BIDS_PER_BGID` `E2BIG`, a length of 0 `EINVAL`, buffers
///   that wrap `EOVERFLOW`, or leave the user half `EFAULT`, a first ID
///   past 16 bits `E2BIG`, and IDs that would be `EINVAL`.
/// - Removing: any of `rw_flags`, `addr`, `len`, `off` or `splice_fd_in`
///   set, or a count of 0 or past `MAX_BIDS_PER_BGID`, is `EINVAL`.
fn prepare_buffers(provide: bool, sqe: &[u8]) -> Result<Work, Errno> {
    let count = i64::from(u32_at(sqe, 4) as i32) as u64;
    let (offset, addr, len) = (u64_at(sqe, 8), u64_at(sqe, 16), u32_at(sqe, 24));
    let bgid = u16::from_le_bytes([sqe[40], sqe[41]]);
    let unused = u32_at(sqe, 28) != 0 || u32_at(sqe, 44) != 0;
    if !provide {
        if unused || addr != 0 || len != 0 || offset != 0 {
            return Err(Errno::EINVAL);
        }
        if count == 0 || count > MAX_BIDS_PER_BGID {
            return Err(Errno::EINVAL);
        }
    } else {
        if unused {
            return Err(Errno::EINVAL);
        }
        if count == 0 || count > MAX_BIDS_PER_BGID {
            return Err(E2BIG);
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        let size = u64::from(len) * count;
        if addr.checked_add(size).is_none() {
            return Err(EOVERFLOW);
        }
        crate::sockets::access_ok_u64(addr, size)?;
        if offset > u64::from(u16::MAX) {
            return Err(E2BIG);
        }
        if offset + count > MAX_BIDS_PER_BGID {
            return Err(Errno::EINVAL);
        }
    }
    Ok(Work::Buffers {
        provide,
        count: count as u32,
        addr,
        len,
        bgid,
        bid: offset as u16,
    })
}

/// The rest of a request's `prep`, which reads the caller's memory: the
/// event of an `IORING_OP_EPOLL_CTL` that has one (`EFAULT`), and a
/// transfer's priority, attributes and buffers ([`prepare_transfer`]). Its
/// error fails the request.
fn prepare_memory(c: &Context<'_>, ring: &Ring, request: &mut Request, addr: u64) {
    let result = match &mut request.work {
        Work::EpollCtl { op, event, .. } if *op != 2 => {
            let mut bytes = [0; 12];
            c.mem
                .read(GuestAddr(addr), &mut bytes)
                .map(|()| *event = crate::epoll::event_from(&bytes))
                .map_err(|_| Errno::EFAULT)
        }
        Work::Transfer(transfer) => prepare_transfer(c, transfer),
        Work::Net(net) => net::prepare_memory(c, net),
        Work::Fs(fs) => fs::prepare_memory(c, fs),
        Work::Timeout(timeout) => timeout::prepare_memory(c, ring, timeout),
        Work::TimeoutRemove(remove) => timeout::prepare_update(c, remove),
        _ => Ok(()),
    };
    if let Err(e) = result {
        request.failed = Some(e);
    }
}

/// Linux's `io_prep_rw` and `io_prep_rwv`: the priority
/// (`ioprio_check_cap`), the attributes (only protection information,
/// whose `struct io_uring_attr_pi` is read, `EFAULT`, with its reserved
/// field zero, `EINVAL`, and its buffer in the user half, `EFAULT`), then
/// the buffer (`import_ubuf`: the length cut to `MAX_RW_COUNT`, in the
/// user half, `EFAULT`) or vector (`__import_iovec`: `EINVAL`, `EFAULT`).
/// A request that selects a buffer imports none, but a vectored one must
/// have one vector (`EINVAL`) that can be read (`EFAULT`), and one in a
/// registered buffer is looked for at issue (`io_prep_read_fixed`); a
/// vector in one is only read (`io_prep_reg_iovec`): more entries than
/// `kmalloc` gives room for at once (4 MiB of them) are `ENOMEM`, then as
/// [`crate::files::iovec_entries`] reads them.
///
/// The attributes are Linux 6.14's, which the kernel the differential
/// tests run on has; Linux 6.12 does not look at those fields.
fn prepare_transfer(c: &Context<'_>, transfer: &mut Transfer) -> Result<(), Errno> {
    if transfer.ioprio != 0 {
        let caller = c.process.credentials.task_ids();
        crate::scheduling::check_ioprio(
            i32::from(transfer.ioprio),
            caller.capable(crate::credentials::CAP_SYS_NICE)
                || c.process.credentials.may_administer(),
        )?;
    }
    match transfer.attr_type_mask {
        0 => {}
        RW_ATTR_FLAG_PI => {
            let mut pi = [0; 32];
            c.mem
                .read(GuestAddr(transfer.attr_ptr), &mut pi)
                .map_err(|_| Errno::EFAULT)?;
            if u64_at(&pi, 24) != 0 {
                return Err(Errno::EINVAL);
            }
            let len = u64::from(u32_at(&pi, 4)).min(crate::files::MAX_RW_COUNT as u64);
            crate::sockets::access_ok_u64(u64_at(&pi, 8), len)?;
            transfer.metadata = true;
        }
        _ => return Err(Errno::EINVAL),
    }
    if transfer.registered {
        if transfer.vectored {
            if u64::from(transfer.len) * 16 > MAX_KMALLOC {
                return Err(Errno::ENOMEM);
            }
            let entries =
                crate::files::iovec_entries(c.mem, transfer.addr, u64::from(transfer.len))?;
            // `io_estimate_bvec_size`: two more than the 4 KiB pages of
            // each.
            transfer.page_pieces = entries.iter().fold(0u64, |pieces, &(_, len)| {
                pieces.saturating_add((len >> 12) + 2)
            });
            let most = crate::files::MAX_RW_COUNT as u64 + 1;
            transfer.segments = entries
                .into_iter()
                .map(|(base, len)| (base, len.min(most) as usize))
                .collect();
        }
        return Ok(());
    }
    if transfer.select {
        if transfer.vectored {
            if transfer.len != 1 {
                return Err(Errno::EINVAL);
            }
            let mut iovec = [0; 16];
            c.mem
                .read(GuestAddr(transfer.addr), &mut iovec)
                .map_err(|_| Errno::EFAULT)?;
            // The vector's length is the most to read, cut to 32 bits as
            // `io_iov_buffer_select_prep` stores it in `struct io_rw`'s `len`.
            transfer.len = u64_at(&iovec, 8) as u32;
        }
        return Ok(());
    }
    transfer.segments = if transfer.vectored {
        crate::files::iovecs_checked(c.mem, transfer.addr, u64::from(transfer.len), |_, _| Ok(()))?
    } else {
        let len = u64::from(transfer.len).min(crate::files::MAX_RW_COUNT as u64);
        crate::sockets::access_ok_u64(transfer.addr, len)?;
        vec![(transfer.addr, len as usize)]
    };
    Ok(())
}

/// The file of a request, as `io_assign_file` finds it at issue: with
/// `IOSQE_FIXED_FILE` the registered one of index `fd` (`EBADF` for an
/// empty or missing slot, `io_file_get_fixed`), otherwise the descriptor
/// `fget` finds (`EBADF` for none, or an `O_PATH` one).
fn file_of(
    c: &Context<'_>,
    ring: &Ring,
    fd: i32,
    fixed: bool,
) -> Result<crate::files::Descriptor, Errno> {
    if fixed {
        let node = ring
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|files| files.slots.get(&(fd as u32)).cloned())
            .ok_or(Errno::EBADF)?;
        let file = node.file().cloned().ok_or(Errno::EBADF)?;
        let mut state = ring.state();
        if state.deferred.is_some() {
            state.held.push(node);
        }
        return Ok(file);
    }
    fget(c, fd)
}

/// The open file of descriptor `fd`, as `fget` finds it: `EBADF` for none,
/// or an `O_PATH` one.
fn fget(c: &Context<'_>, fd: i32) -> Result<crate::files::Descriptor, Errno> {
    if fd < 0 {
        return Err(Errno::EBADF);
    }
    let d = c.files.descriptor(fd as u64)?;
    if d.file.flags() & 0o10000000 != 0 {
        return Err(Errno::EBADF);
    }
    Ok(d)
}

/// Whether `d` is a ring, which none may register (`io_is_uring_fops`).
fn is_ring(d: &crate::files::Descriptor) -> bool {
    d.file.as_any().is_some_and(|v| v.is::<Ring>())
}

/// Linux's `io_read` and `io_write`, run inline, and the completion's
/// flags: the file, then the registered buffer of `IORING_OP_READ_FIXED`
/// and `_WRITE_FIXED` ([`Ring::registered`]), or a buffer a read selects
/// ([`select`]), whose length is cut to `MAX_RW_COUNT` and which must be
/// in the user half (`EFAULT`, `import_ubuf`), then the rest ([`issue`]).
/// The selected buffer goes as [`give_back`] says.
/// A transfer's result and completion flags, for one that would wait what
/// it waits for ([`arm`]), and the bytes it asked for (`req->cqe.res`, the
/// length of its buffers as imported).
type Transferred = (Result<u64, Errno>, u32, Option<Waits>, u64);

/// What a transfer that would wait waits for: its file's events, with the
/// provided buffer it chose, which it keeps (`REQ_F_BUFFER_SELECTED`).
struct Waits {
    file: Arc<dyn FileHandle>,
    mask: u32,
    kept: Option<Chosen>,
    found: (crate::files::Descriptor, Option<Arc<Node>>),
}

fn transfer(c: &mut Context<'_>, ring: &Ring, transfer: &Transfer) -> Transferred {
    let (opened, buffer) = match &transfer.found {
        Some((opened, buffer)) => (opened.clone(), buffer.clone()),
        None => match file_of(c, ring, transfer.fd, transfer.fixed) {
            Ok(opened) => (opened, None),
            Err(e) => return (Err(e), 0, None, 0),
        },
    };
    let buffer = if transfer.registered {
        buffer.or_else(|| ring.buffer_node(transfer.buf_index))
    } else {
        None
    };
    let asked = |segments: &[(u64, usize)]| segments.iter().map(|&(_, len)| len as u64).sum();
    let waits = |result: &Result<u64, Errno>, kept: Option<Chosen>| {
        waits_for(transfer, &opened.file, result).then(|| Waits {
            file: Arc::clone(&opened.file),
            mask: POLL_UNMASK
                | if transfer.write {
                    POLL_OUT_EVENTS
                } else {
                    POLL_IN_EVENTS
                },
            kept,
            found: (opened.clone(), buffer.clone()),
        })
    };
    if transfer.registered {
        let within = buffer.as_ref().ok_or(Errno::EFAULT).and_then(|node| {
            if transfer.vectored {
                within_vector(node, &transfer.segments, transfer.page_pieces)
            } else {
                within(node, transfer.addr, transfer.len)
            }
        });
        let wanted = within.as_ref().map_or(0, |within| asked(&within.pieces));
        let result = within.and_then(|within| {
            let memory = crate::files::Memory::Pinned {
                pages: &within.pages,
                pieces: &within.pieces,
            };
            issue(c, transfer, &opened, memory)
        });
        let poll = waits(&result, None);
        return (result, 0, poll, wanted);
    }
    if !transfer.select {
        let result = issue(
            c,
            transfer,
            &opened,
            crate::files::Memory::Guest(&transfer.segments),
        );
        let poll = waits(&result, None);
        return (result, 0, poll, asked(&transfer.segments));
    }
    let pollable = !crate::files::aio_positioned(&opened.file);
    let chosen = match transfer.kept {
        Some(kept) => kept,
        None => match select(c, ring, transfer.buf_index, transfer.len, pollable) {
            Ok(chosen) => chosen,
            Err(e) => return (Err(e), 0, None, 0),
        },
    };
    let len = u64::from(chosen.len).min(crate::files::MAX_RW_COUNT as u64);
    let result = crate::sockets::access_ok_u64(chosen.addr, len).and_then(|()| {
        let segment = [(chosen.addr, len as usize)];
        issue(c, transfer, &opened, crate::files::Memory::Guest(&segment))
    });
    // A read that waits keeps a provided buffer; a ring's stays at the
    // ring's head (`io_kbuf_recycle`, as a file that can be polled uses it
    // only once its read is done) and is chosen again as the read goes on.
    if let Some(poll) = waits(&result, (!chosen.ring).then_some(chosen)) {
        return (result, 0, Some(poll), len);
    }
    let flags = give_back(c, ring, &chosen, &result);
    (result, flags, None, len)
}

const POLL_RDNORM: u32 = 0x40;
const POLL_WRNORM: u32 = 0x100;
/// `POLLIN | POLLPRI | POLLRDNORM | POLLERR`, what a read waits for
/// (`io_arm_poll_handler`: urgent data is an event for a reader).
const POLL_IN_EVENTS: u32 = 0x1 | 0x2 | 0x40 | 0x8;
/// `POLLOUT | POLLWRNORM | POLLERR`, what a write waits for.
const POLL_OUT_EVENTS: u32 = 0x4 | 0x100 | 0x8;
/// `IO_POLL_UNMASK`: `POLLERR | POLLHUP | POLLNVAL | POLLRDHUP`, which end
/// any poll.
const POLL_UNMASK: u32 = 0x8 | 0x10 | 0x20 | 0x2000;

/// Whether a transfer that gave `result` waits for its file
/// (`io_queue_async` arming a poll): `EAGAIN` from a file that can be
/// polled, such as a pipe, a socket or an eventfd, unless it asked for
/// `RWF_NOWAIT` (`REQ_F_NOWAIT`). `O_NONBLOCK` does not stop it, as every
/// such file supports `FMODE_NOWAIT` (`REQ_F_SUPPORT_NOWAIT`). A
/// pseudo-terminal's read never gives `EAGAIN` here: it waits in
/// `io_uring_enter`, a limitation the guide lists.
fn waits_for(transfer: &Transfer, file: &Arc<dyn FileHandle>, result: &Result<u64, Errno>) -> bool {
    *result == Err(Errno::EAGAIN)
        && transfer.rw_flags & RWF_NOWAIT == 0
        && !crate::files::aio_positioned(file)
        && file.readiness().is_ok()
}

/// The rest of `io_read` and `io_write`: `io_rw_init_file` (the access
/// mode, `EBADF`; the flags, `kiocb_set_rw_flags`; polled I/O, `EINVAL` on
/// a ring without `IORING_SETUP_IOPOLL`; protection information, `EINVAL`),
/// then the transfer of `segments` ([`crate::files::ring_transfer`]). Once
/// the file's own read or write ran, its watches hear of it as
/// `io_req_io_end` tells them: `IN_ACCESS` for a read that did not fail,
/// `IN_MODIFY` for any write, no bytes too.
fn issue(
    c: &mut Context<'_>,
    transfer: &Transfer,
    opened: &crate::files::Descriptor,
    memory: crate::files::Memory<'_>,
) -> Result<u64, Errno> {
    let file = &opened.file;
    if file.flags() & 3 == if transfer.write { 0 } else { 1 } {
        return Err(Errno::EBADF);
    }
    let flags = crate::files::kiocb_rw_flags(file, transfer.rw_flags)?;
    if flags & RWF_HIPRI != 0 || transfer.metadata {
        return Err(Errno::EINVAL);
    }
    let result =
        crate::files::ring_transfer(c, file, transfer.write, memory, transfer.offset, flags)?;
    // A write that would wait waits for its file ([`arm`]), and its watches
    // hear of it only once it ends; one that asked for `RWF_NOWAIT` ends at
    // once, and they hear of it.
    let waited = result == Err(Errno::EAGAIN) && flags & RWF_NOWAIT == 0;
    if transfer.write && !waited {
        crate::files::notify_open(c, opened, crate::inotify::MODIFY);
    } else if result.is_ok() {
        crate::files::notify_open(c, opened, crate::inotify::ACCESS);
    }
    result
}

/// The buffer of group `bgid` a read of `len` bytes (0 for any) reads to,
/// as `io_buffer_select` chooses it: none, or a group with none left, is
/// `ENOBUFS`. The read is of `len` bytes at most, or the whole buffer.
///
/// - Provided buffers: the first goes from the group
///   (`io_provided_buffer_select`).
/// - A ring: the entry at its head, unless the tail is there
///   (`io_ring_buffer_select`). A file that cannot be polled uses it at once
///   (`io_should_commit`), all the bytes the read may take; one that can
///   uses it once the read is done.
fn select(
    c: &Context<'_>,
    ring: &Ring,
    bgid: u16,
    len: u32,
    pollable: bool,
) -> Result<Chosen, Errno> {
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let cut = |size: u32| if len == 0 || len > size { size } else { len };
    match lists.get_mut(&bgid) {
        None => Err(ENOBUFS),
        Some(BufferList::Provided(list)) => {
            let buffer = list.pop_front().ok_or(ENOBUFS)?;
            Ok(Chosen {
                bgid,
                bid: buffer.bid,
                addr: buffer.addr,
                len: cut(buffer.len),
                size: buffer.len,
                ring: false,
                committed: true,
                more: false,
            })
        }
        Some(BufferList::Ring(buffers)) => {
            if buffers.tail(c)? == buffers.head {
                return Err(ENOBUFS);
            }
            let (addr, size, bid) = buffers.entry(c, buffers.head)?;
            let mut chosen = Chosen {
                bgid,
                bid,
                addr,
                len: cut(size),
                size,
                ring: true,
                committed: false,
                more: false,
            };
            if !pollable {
                chosen.more = !buffers.commit(c, chosen.len)?;
                chosen.committed = true;
            }
            Ok(chosen)
        }
    }
}

/// The buffers a send with `IOSQE_BUFFER_SELECT` sends from
/// (`io_buffers_select`), which it keeps until it completes: the first's
/// ID, their bytes, whether a ring's last was left in part
/// (`REQ_F_BUF_MORE`) and whether the group has none left
/// (`REQ_F_BL_EMPTY`).
pub(super) struct Picked {
    pub(super) bid: u16,
    pub(super) pieces: Vec<(u64, usize)>,
    pub(super) more: bool,
    pub(super) emptied: bool,
}

impl Picked {
    /// The completion's flags (`io_put_kbufs`): `IORING_CQE_F_BUFFER` and
    /// the first buffer's ID, and `IORING_CQE_F_BUF_MORE` for a ring's left
    /// in part.
    pub(super) fn flags(&self) -> u32 {
        let flags = CQE_F_BUFFER | u32::from(self.bid) << CQE_BUFFER_SHIFT;
        if self.more {
            flags | CQE_F_BUF_MORE
        } else {
            flags
        }
    }
}

/// The buffers of group `bgid` a send of `len` bytes (0 for any) takes, as
/// Linux master's `io_buffers_select` has them: no group is `ENOENT`, and
/// one with none left `ENOBUFS`. A provided buffer is cut to `len`; a
/// ring's are as [`BufferRing::take_for_send`] takes them.
pub(super) fn select_send(
    c: &Context<'_>,
    ring: &Ring,
    bgid: u16,
    len: u32,
    bundle: bool,
) -> Result<Picked, Errno> {
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match lists.get_mut(&bgid) {
        None => Err(Errno::ENOENT),
        Some(BufferList::Provided(list)) => {
            let buffer = list.pop_front().ok_or(ENOBUFS)?;
            let size = if len == 0 {
                buffer.len
            } else {
                len.min(buffer.len)
            };
            Ok(Picked {
                bid: buffer.bid,
                pieces: vec![(buffer.addr, size as usize)],
                more: false,
                emptied: list.is_empty(),
            })
        }
        Some(BufferList::Ring(buffers)) => buffers.take_for_send(c, len, bundle),
    }
}

impl BufferRing {
    /// The buffers a send of up to `want` bytes (0 for any, and no more
    /// than `MAX_RW_COUNT`) takes from the head, which are used at once, as
    /// Linux master's `io_ring_buffers_peek` and `io_kbuf_commit` take them.
    /// None ready, or a first of no bytes, is `ENOBUFS`, and one outside the
    /// user half `EFAULT`.
    ///
    /// A send takes one; a bundle as many as are ready, but no more than
    /// 1024, 256, or what `want` needs at the first's length. Each gives
    /// what is left of `want` at most, its entry as it was. One cut short
    /// stays only as the first, unless the ring has `IOU_PBUF_RING_INC`,
    /// whose bytes come off the buffer instead. The group counts as emptied
    /// when every buffer ready was taken.
    fn take_for_send(&mut self, c: &Context<'_>, want: u32, bundle: bool) -> Result<Picked, Errno> {
        let ready = self.tail(c)?.wrapping_sub(self.head);
        if ready == 0 {
            return Err(ENOBUFS);
        }
        let (_, first_len, bid) = self.entry(c, self.head)?;
        if first_len == 0 {
            return Err(ENOBUFS);
        }
        let budget =
            (if want == 0 { i32::MAX as u32 } else { want }).min(crate::files::MAX_RW_COUNT as u32);
        let most = if bundle {
            u32::from(ready)
                .min(1024)
                .min(256)
                .min(budget.div_ceil(first_len))
        } else {
            1
        };
        let mut pieces = Vec::new();
        let mut left = budget;
        for offset in 0..most as u16 {
            let index = self.head.wrapping_add(offset);
            let (addr, size, _) = self.entry(c, index)?;
            let part = size.min(left);
            if part < size && !self.incremental && !pieces.is_empty() {
                break;
            }
            crate::sockets::access_ok_u64(addr, u64::from(part))?;
            pieces.push((addr, part as usize));
            left -= part;
            if left == 0 {
                break;
            }
        }
        let taken = pieces.len() as u16;
        let emptied = taken == ready;
        let more = if self.incremental {
            !self.commit(c, budget - left)?
        } else {
            self.head = self.head.wrapping_add(taken);
            false
        };
        Ok(Picked {
            bid,
            pieces,
            more,
            emptied,
        })
    }
}

/// What becomes of a selected buffer once its read ended, and the
/// completion's flags, as `io_put_kbuf` and `io_kbuf_recycle` leave them:
/// a provided buffer is used, and so is a ring's that was used at
/// selection, or that a read that did not fail used now (its bytes, with
/// `IOU_PBUF_RING_INC`); their completion has `IORING_CQE_F_BUFFER` and the
/// ID, and `IORING_CQE_F_BUF_MORE` for a buffer some of which is left. A
/// ring's buffer whose read failed before it was used stays in the ring.
/// (A read that waits for its file gives nothing back: [`transfer`].)
fn give_back(c: &Context<'_>, ring: &Ring, chosen: &Chosen, result: &Result<u64, Errno>) -> u32 {
    let flags = CQE_F_BUFFER | u32::from(chosen.bid) << CQE_BUFFER_SHIFT;
    let more = |more: bool| if more { CQE_F_BUF_MORE } else { 0 };
    if !chosen.ring {
        return flags;
    }
    if chosen.committed {
        return flags | more(chosen.more);
    }
    let Ok(count) = result else {
        return 0;
    };
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match lists.get_mut(&chosen.bgid) {
        Some(BufferList::Ring(buffers)) => {
            flags | more(!buffers.commit(c, *count as u32).unwrap_or(true))
        }
        _ => flags,
    }
}

/// Runs a request and gives its result, its completion's flags and
/// whether it failed (`req_set_fail`), which a negative result does, or
/// what a transfer that would wait waits for.
fn run(c: &mut Context<'_>, ring: &Ring, work: &mut Work) -> (i32, u32, bool, Option<Waits>) {
    let result = |r: Result<u64, Errno>| r.map_or_else(|e| -e.0, |v| v as i32);
    match work {
        Work::Net(net) => return net::run(c, ring, net),
        Work::Splice(splice) => return splice::run(c, ring, splice),
        &mut Work::EpollWait {
            fd,
            fixed,
            at,
            max,
            ref found,
        } => return epoll_wait(c, ring, (fd, fixed, found), at, max),
        Work::Fs(fs) => {
            let (res, failed) = fs::run(c, ring, fs);
            return (res, 0, failed, None);
        }
        // `io_fsync`: `vfs_fsync_range`, `EINVAL` for a file without
        // `fsync`; nothing is cached, so the range and `IORING_FSYNC_DATASYNC`
        // change nothing.
        // `io_fsync` fails no link but for a file it does not find.
        &mut Work::Fsync { fd, fixed } => {
            return match file_of(c, ring, fd, fixed) {
                Ok(found) => (result(found.file.sync().map(|()| 0)), 0, false, None),
                Err(e) => (-e.0, 0, true, None),
            };
        }
        Work::Transfer(work) => {
            // A transfer of fewer bytes than it asked for fails its link too
            // (`__io_complete_rw_common`), though its result is the count.
            let (r, flags, waits, asked) = transfer(c, ring, work);
            let short = r.as_ref().is_ok_and(|&count| count != asked);
            let res = result(r);
            return (res, flags, res < 0 || short, waits);
        }
        // `io_nop`, as Linux master has it: a file it does not find is
        // `EBADF`, then a registered buffer `EFAULT`, else its result.
        &mut Work::Nop {
            result,
            file,
            buffer,
            ..
        } => {
            let res = if file.is_some_and(|(fd, fixed)| file_of(c, ring, fd, fixed).is_err()) {
                -Errno::EBADF.0
            } else if buffer.is_some_and(|index| !ring.has_buffer(index)) {
                -Errno::EFAULT.0
            } else {
                result
            };
            return (res, 0, res < 0, None);
        }
        _ => {}
    }
    let res = match &*work {
        &Work::EpollCtl {
            epfd,
            op,
            fd,
            event,
        } => {
            let as_arg = |v: i32| i64::from(v) as u64;
            match crate::epoll::control(c, as_arg(epfd), as_arg(op), as_arg(fd), |_| Ok(event)) {
                Ok(()) => 0,
                Err(e) => -e.0,
            }
        }
        // `io_async_cancel`: the file of `IORING_ASYNC_CANCEL_FD`, which
        // `EBADF` fails without, then the requests.
        &Work::Cancel { key, fixed } => result((|| {
            let file = if key.flags & CANCEL_FD != 0 {
                let fixed = fixed || key.flags & CANCEL_FD_FIXED != 0;
                Some(file_identity(&file_of(c, ring, key.fd, fixed)?.file))
            } else {
                None
            };
            cancel(c, ring, &key, file)
        })()),
        &Work::FilesUpdate {
            offset,
            addr,
            count,
        } => result(if offset == FILE_INDEX_ALLOC {
            update_files_anywhere(c, ring, addr, count)
        } else {
            update_files(c, ring, offset, addr, count, 0)
        }),
        Work::TimeoutRemove(remove) => result(timeout::remove(c, ring, remove)),
        &Work::Buffers {
            provide,
            count,
            addr,
            len,
            bgid,
            bid,
        } => result(manage_buffers(ring, provide, count, addr, len, bgid, bid)),
        Work::Fs(_)
        | Work::Splice(_)
        | Work::EpollWait { .. }
        | Work::Fsync { .. }
        | Work::Transfer(_)
        | Work::Net(_)
        | Work::Timeout(_)
        | Work::Poll(_)
        | Work::PollRemove(_)
        | Work::Nop { .. }
        | Work::None => 0,
    };
    (res, 0, res < 0, None)
}

/// `IORING_OP_PROVIDE_BUFFERS` and `_REMOVE_BUFFERS`, as Linux's
/// `io_manage_buffers_legacy`: removing from a group there is not is
/// `ENOENT` (providing makes it), and from a ring `EINVAL`. Removing takes
/// up to `count` buffers from the group's start and gives how many it
/// took; providing adds them at its end, stopping at 65535 in a group,
/// which is `EOVERFLOW` if it added none (`io_add_buffers`).
fn manage_buffers(
    ring: &Ring,
    provide: bool,
    count: u32,
    addr: u64,
    len: u32,
    bgid: u16,
    bid: u16,
) -> Result<u64, Errno> {
    use std::collections::btree_map::Entry;
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let list = match lists.entry(bgid) {
        Entry::Occupied(list) => list.into_mut(),
        Entry::Vacant(_) if !provide => return Err(Errno::ENOENT),
        Entry::Vacant(list) => list.insert(BufferList::Provided(VecDeque::new())),
    };
    let BufferList::Provided(list) = list else {
        return Err(Errno::EINVAL);
    };
    if !provide {
        let taken = (count as usize).min(list.len());
        list.drain(..taken);
        return Ok(taken as u64);
    }
    let mut at = addr;
    for index in 0..count {
        if list.len() == usize::from(u16::MAX) {
            return if index == 0 { Err(EOVERFLOW) } else { Ok(0) };
        }
        list.push_back(Provided {
            addr: at,
            len: len.min(crate::files::MAX_RW_COUNT as u32),
            bid: bid.wrapping_add(index as u16),
        });
        at = at.wrapping_add(u64::from(len));
    }
    Ok(0)
}

/// Completes a chain of linked requests, as Linux runs a link once it is
/// whole. One that failed to prepare fails the chain
/// (`io_queue_sqe_fallback`): its first request completes with its error, or
/// `ECANCELED`, and the rest as task work ([`Deferred::Fail`]). Otherwise
/// the first runs ([`issue_link`]).
fn complete(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, mut chain: Vec<Request>) {
    if chain.is_empty() {
        return;
    }
    if chain.iter().any(|r| r.failed.is_some()) {
        let head = chain.remove(0);
        let skip = head.flags & IOSQE_CQE_SKIP_SUCCESS != 0;
        let mut next = Vec::new();
        // Its linked timeout is over with it (`REQ_F_ARM_LTIMEOUT`).
        if has_link_timeout(&chain) {
            next.push(timeout::canceled(chain.remove(0)));
        }
        if !chain.is_empty() {
            next.push(Deferred::Fail { chain, skip });
        }
        ring.complete(Done {
            user_data: head.user_data,
            res: -head.failed.unwrap_or(ECANCELED).0,
            flags: 0,
            post: true,
            ltimeout: None,
            next,
        });
        return;
    }
    issue_link(c, file, ring, chain, Vec::new());
}

/// Whether the request before `chain` in its link has a linked timeout
/// (`REQ_F_ARM_LTIMEOUT`).
fn has_link_timeout(chain: &[Request]) -> bool {
    chain
        .first()
        .is_some_and(|r| r.opcode == timeout::OP_LINK_TIMEOUT && r.failed.is_none())
}

/// Runs the first request of a link (`io_issue_sqe`): its completion goes
/// in the batch, or for an `IORING_NOP_TW` in task work with the
/// registered files it found; a transfer that would wait waits for its
/// file ([`arm`]). `held` is what it held as it waited.
fn issue_link(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    mut chain: Vec<Request>,
    held: Vec<Arc<Node>>,
) {
    // What it held as it waited, it holds still if it waits again.
    let mark = {
        let mut state = ring.state();
        let mark = state.held.len();
        state.held.extend(held);
        mark
    };
    let mut request = chain.remove(0);
    // Its linked timeout starts as it is issued (`__io_prep_linked_timeout`).
    if has_link_timeout(&chain) {
        let link = chain.remove(0);
        request.ltimeout = timeout::arm_link(c, ring, link, request.user_data);
    }
    if matches!(request.work, Work::Timeout(_)) {
        chain.insert(0, request);
        timeout::arm(c, ring, chain);
        return;
    }
    if matches!(request.work, Work::Poll(_)) {
        chain.insert(0, request);
        let held = {
            let mut state = ring.state();
            let at = mark.min(state.held.len());
            state.held.split_off(at)
        };
        poll::add(c, file, ring, chain, held);
        return;
    }
    let mut mark = mark;
    let split_held = |mark: usize| {
        let mut state = ring.state();
        let at = mark.min(state.held.len());
        state.held.split_off(at)
    };
    let (res, flags, failed, waits) = loop {
        // `io_issue_sqe` takes its personality for as long as it runs
        // (`override_creds`).
        let own = request.credentials.as_ref().map(|credentials| {
            std::mem::replace(
                &mut c.process.credentials,
                credentials.credentials().clone(),
            )
        });
        let done = match &mut request.work {
            Work::PollRemove(remove) => {
                let res = poll::remove(c, file, ring, remove).map_or_else(|e| -e.0, |v| v as i32);
                (res, 0, res < 0, None)
            }
            work => run(c, ring, work),
        };
        if let Some(own) = own {
            c.process.credentials = own;
        }
        if let (res, flags, _, None) = done
            && let Work::Net(net) = &mut request.work
            && net.goes_on(res)
        {
            // The completions of the batch go first (`io_req_post_cqe`),
            // and what it holds goes on with it.
            let held = split_held(mark);
            flush_batch(c, file, ring);
            ring.begin();
            let posted = ring.post_aux(request.user_data, res, flags | CQE_F_MORE);
            let mut state = ring.state();
            mark = state.held.len();
            state.held.extend(held);
            drop(state);
            if posted {
                if let Work::Net(net) = &mut request.work {
                    net.posted(flags);
                }
                continue;
            }
        }
        break done;
    };
    if let Some(waits) = waits {
        match &mut request.work {
            Work::Transfer(transfer) => {
                transfer.kept = waits.kept;
                transfer.found = Some(waits.found.clone());
            }
            Work::Net(net) => {
                net.polled = true;
                net.found = Some(waits.found.0.clone());
            }
            Work::EpollWait { found, .. } => *found = Some(waits.found.0.clone()),
            _ => {}
        }
        chain.insert(0, request);
        let held = split_held(mark);
        arm(c, file, ring, waits, chain, held);
        return;
    }
    let done = Done {
        user_data: request.user_data,
        res,
        flags,
        post: true,
        ltimeout: request.ltimeout,
        next: Vec::new(),
    };
    if matches!(request.work, Work::Nop { tw: true, .. }) {
        let held = split_held(mark);
        queue(
            c,
            file,
            ring,
            Deferred::Complete {
                done,
                held,
                rest: chain,
                flags: request.flags,
                failed,
            },
        );
        return;
    }
    ring.complete(finish(done, request.flags, failed, chain));
}

/// Makes a request wait for its file (`io_arm_poll_handler`), holding the
/// file and the registered files it found: it goes on as task work once
/// the file is ready ([`complete_ready`]), at once if it is now
/// (`IO_APOLL_READY`). The file is looked at again once the request is
/// among those that wait, so one that became ready in between, which
/// another thread's [`complete_ready`] could not see, goes on too, as Linux
/// arms under the wait queue's lock.
fn arm(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    waits: Waits,
    chain: Vec<Request>,
    held: Vec<Arc<Node>>,
) {
    if ready(&waits.file, waits.mask) {
        queue(c, file, ring, Deferred::Submit(chain, held));
        return;
    }
    let polls = &c.processes.io_uring;
    let (polled, mask) = (Arc::clone(&waits.file), waits.mask);
    // Its own file (`req->file`), by which a cancellation finds it.
    let id = ring.hash(&chain[0], &waits.found.0.file, c.inbox);
    polls
        .armed
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Armed {
            id,
            ring: Arc::downgrade(file),
            inbox: Arc::clone(c.inbox),
            hub: Arc::clone(&c.files.readiness),
            polled: waits.file,
            mask: waits.mask,
            chain,
            held,
            watch: None,
        });
    polls
        .count
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if ready(&polled, mask) {
        wake(polls);
    }
}

/// Whether `file` has any of the events of `mask` (`vfs_poll`).
fn ready(file: &Arc<dyn FileHandle>, mask: u32) -> bool {
    crate::aio::polled(file).0 & mask != 0
}

/// The requests that waited for files that are now ready go on, each as
/// task work of the thread that submitted it (`io_poll_wake` queuing
/// `io_poll_task_func`), which wakes that thread's wait as a signal would
/// ([`crate::SignalInbox::notify_signal`]).
///
/// The timeouts that are due expire first.
pub(crate) fn complete_ready(polls: &Polls, host: &dyn paludarium_host::Host) {
    timeout::expire(polls, host);
    wake(polls);
    run_fallback(polls);
}

/// Runs [`Polls::fallback`], but leaves the work of a ring whose lock is
/// held, as Linux's worker waits for it (`io_fallback_req_func`, master's
/// `io_tctx_fallback_work`) and no other task does: its holder may wait for a
/// page that this thread is to fill. The holder runs it after it lets go:
/// each holder then comes here, or to [`complete_ready`] at the end of its
/// call or as it waits. The work of a ring that closed is dropped, and with
/// it the files its requests hold: no one sees its completions.
fn run_fallback(polls: &Polls) {
    let queue = || {
        polls
            .fallback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    };
    loop {
        let work = std::mem::take(&mut *queue());
        let (mut busy, mut ran) = (Vec::new(), false);
        for (weak, work) in work {
            let Some(file) = weak.upgrade() else {
                continue;
            };
            let Ok(ring) = downcast(&file) else {
                continue;
            };
            match ring.try_submitting() {
                Some(_submitting) => {
                    run_terminated(polls, ring, work);
                    ran = true;
                }
                None => busy.push((weak, work)),
            }
        }
        let held: Vec<_> = busy.iter().filter_map(|(weak, _)| weak.upgrade()).collect();
        // Before what came meanwhile.
        queue().splice(0..0, busy);
        // A holder that let go before the work was back may not have seen it.
        let free = held
            .iter()
            .any(|file| downcast(file).is_ok_and(|ring| ring.try_submitting().is_some()));
        if !ran && !free {
            return;
        }
    }
}

/// Moves the requests whose files are ready to task work, as
/// [`complete_ready`] does, without running [`Polls::fallback`]: [`arm`]
/// calls it holding its ring's lock, which that work may need. What it
/// leaves there runs at the next [`complete_ready`], which the checkpoint
/// after the call that armed the request runs before the call returns.
fn wake(polls: &Polls) {
    if polls.count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        return;
    }
    // The requests that go on, and the multishot polls that have events, by
    // where their task work goes.
    let mut woken = Vec::new();
    {
        let mut armed = polls.armed.lock().unwrap_or_else(PoisonError::into_inner);
        let mut waiting = Vec::with_capacity(armed.len());
        for mut a in std::mem::take(&mut *armed) {
            // A ring that closed lets go of its requests and the files they
            // hold here, at the checkpoint of the `close` (or `munmap`) that
            // let go of it last, before that call returns.
            if a.ring.strong_count() == 0 {
                continue;
            }
            let ring = std::sync::Weak::clone(&a.ring);
            match poll::look(&mut a) {
                poll::Look::Waits => waiting.push(a),
                poll::Look::More => {
                    let work = Deferred::PollMore { id: a.id };
                    woken.push((ring, Arc::clone(&a.inbox), Arc::clone(&a.hub), work));
                    waiting.push(a);
                }
                poll::Look::Goes => {
                    let (inbox, hub) = (Arc::clone(&a.inbox), Arc::clone(&a.hub));
                    let work = if a.watch.is_some() {
                        Deferred::Polled(Box::new(a))
                    } else {
                        Deferred::Poll {
                            id: a.id,
                            chain: a.chain,
                            held: a.held,
                        }
                    };
                    woken.push((ring, inbox, hub, work));
                }
            }
        }
        *armed = waiting;
        polls
            .count
            .store(armed.len(), std::sync::atomic::Ordering::SeqCst);
    }
    for (ring, inbox, hub, work) in woken {
        if let Some(file) = ring.upgrade()
            && let Ok(ring) = downcast(&file)
        {
            add_work(polls, &file, ring, &inbox, Some(&hub), work);
        }
    }
}

/// [`complete_ready`] as a call waits.
pub(crate) fn progress(c: &Context<'_>) {
    complete_ready(&c.processes.io_uring, c.host);
}

/// When the next timeout expires, which ends a call's wait to run it.
pub(crate) fn next_deadline(c: &Context<'_>) -> Option<u64> {
    timeout::next_deadline(&c.processes.io_uring, c.host)
}

/// Cancels the requests the thread `inbox` belongs to submitted that wait
/// for their files, as it calls `execve` (`io_uring_task_cancel`, all of
/// them) or its whole process exits (Linux master's
/// `io_task_group_exiting`): each leaves its wait and fails with
/// `ECANCELED` as its task work runs ([`Deferred::Poll`]).
pub(crate) fn cancel_task(polls: &Polls, inbox: &Arc<crate::SignalInbox>) {
    // Every request of the thread in a ring's cancel table is cancelled
    // (`io_poll_remove_all`), one whose file became ready too: its task work,
    // queued already, fails it.
    let owner = Arc::as_ptr(inbox) as usize;
    for file in live_rings(polls) {
        if let Ok(ring) = downcast(&file) {
            let mut cancels = ring.cancels.lock().unwrap_or_else(PoisonError::into_inner);
            for hashed in cancels.hashed.iter_mut().filter(|h| h.inbox == owner) {
                hashed.cancelled = true;
            }
        }
    }
    let cancelled: Vec<Armed> = {
        let mut armed = polls.armed.lock().unwrap_or_else(PoisonError::into_inner);
        let (cancelled, kept) = std::mem::take(&mut *armed)
            .into_iter()
            .partition(|a| Arc::ptr_eq(&a.inbox, inbox) && !a.queued());
        *armed = kept;
        polls
            .count
            .store(armed.len(), std::sync::atomic::Ordering::SeqCst);
        cancelled
    };
    for armed in cancelled {
        let Some(file) = armed.ring.upgrade() else {
            continue;
        };
        let Ok(ring) = downcast(&file) else {
            continue;
        };
        add_work(
            polls,
            &file,
            ring,
            inbox,
            None,
            Deferred::Poll {
                id: armed.id,
                chain: armed.chain,
                held: armed.held,
            },
        );
    }
}

/// The rings still open, dropping those that closed.
fn live_rings(polls: &Polls) -> Vec<Arc<dyn FileHandle>> {
    let mut rings = polls.rings.lock().unwrap_or_else(PoisonError::into_inner);
    rings.retain(|r| r.strong_count() != 0);
    rings.iter().filter_map(std::sync::Weak::upgrade).collect()
}

/// The thread calls `execve` (`io_uring_task_cancel`, before the new image
/// replaces its memory): [`cancel_all_task`], after which its io_uring
/// context goes (`__io_uring_free`).
pub(crate) fn exec_task(c: &mut Context<'_>) {
    cancel_all_task(c);
    c.inbox.task_work().context = false;
}

/// `io_uring_cancel_generic` with `cancel_all`, which `execve` and a whole
/// process's exit run (Linux master's `io_task_group_exiting`) while the
/// thread still runs: as it loops, the task work of the
/// `IORING_SETUP_DEFER_TASKRUN` rings the thread submits to runs
/// (`io_run_local_work`), the requests it submitted that wait are
/// cancelled ([`cancel_task`]), its own task work runs, and the rings'
/// again. Its registered ring descriptors go first (`__io_uring_cancel`'s
/// `io_uring_unreg_ringfd`).
pub(crate) fn cancel_all_task(c: &mut Context<'_>) {
    unregister_all_rings(c.inbox);
    let own: Vec<Arc<dyn FileHandle>> = live_rings(&c.processes.io_uring)
        .into_iter()
        .filter(|file| {
            downcast(file).is_ok_and(|ring| {
                ring.flags & SETUP_DEFER_TASKRUN != 0 && ring.submitter.get() == Some(&c.tid)
            })
        })
        .collect();
    let run_own = |c: &mut Context<'_>| {
        for file in &own {
            if let Ok(ring) = downcast(file)
                && local_pending(ring)
            {
                run_local(c, file, ring, u32::MAX, u32::MAX);
            }
        }
    };
    run_own(c);
    cancel_task(&c.processes.io_uring, c.inbox);
    timeout::kill(&c.processes.io_uring, c.inbox);
    if task_work_due(c.inbox) {
        run_task_work(c);
    }
    run_own(c);
}

/// The thread `inbox` belongs to exits (`do_exit`, `PF_EXITING`): its
/// registered ring descriptors go (`io_uring_unreg_ringfd`), and the task
/// work it still has runs as an exiting task's does ([`run_terminated`]),
/// as will any added later. A whole process's exit ran
/// [`cancel_all_task`] first; a request of a thread that exits alone waits
/// on, and fails once its file is ready. Here the thread waits for a ring
/// another holds, as Linux's `exit_task_work` takes `uring_lock` in the
/// thread that exits: no worker runs this work.
pub(crate) fn exit_task(polls: &Polls, inbox: &Arc<crate::SignalInbox>) {
    unregister_all_rings(inbox);
    let work = {
        let mut task_work = inbox.task_work();
        task_work.exited = true;
        std::mem::take(&mut task_work.queue)
    };
    inbox.clear_notify_if_idle();
    for (file, work) in work {
        if let Some(file) = file.upgrade()
            && let Ok(ring) = downcast(&file)
        {
            let _submitting = ring.submitting();
            run_terminated(polls, ring, work);
        }
    }
}

/// Runs task work as a thread that exits, or a ring that closes, runs it,
/// and as Linux's `io_fallback_tw` runs what comes for a thread that has
/// exited (`io_should_terminate_tw`): a request that waited for its file
/// fails with `ECANCELED` (`io_poll_check_events`), a link's next request
/// or one that found its file ready with `EFAULT` (`io_req_task_submit`),
/// and the rest completes as it would. What it leaves runs so too. The
/// ring's lock is held.
fn run_terminated(polls: &Polls, ring: &Ring, work: Deferred) {
    let mut pending = vec![work];
    while !pending.is_empty() {
        ring.begin();
        for work in pending {
            match work {
                Deferred::Submit(chain, held) => {
                    ring.state().held.extend(held);
                    fail_request(ring, chain, Errno::EFAULT);
                }
                Deferred::Poll { id, chain, held } => {
                    ring.state().held.extend(held);
                    ring.unhash(id);
                    fail_request(ring, chain, ECANCELED);
                }
                Deferred::Polled(armed) => {
                    ring.unhash(armed.id);
                    poll::cancelled(ring, *armed);
                }
                Deferred::PollMore { id } => poll::end(polls, ring, id),
                Deferred::Complete {
                    done,
                    held,
                    rest,
                    flags,
                    failed,
                } => {
                    ring.state().held.extend(held);
                    ring.complete(finish(done, flags, failed, rest));
                }
                Deferred::Fail { chain, skip } => fail_rest(ring, chain, skip),
                Deferred::Timeout(chain) => timeout::complete_expired(ring, chain),
                Deferred::LinkTimeout { request, head } => {
                    timeout::run_link(None, ring, &request, head);
                }
            }
        }
        pending = ring.end();
    }
}

/// `io_req_defer_failed`: the first request of `chain` fails with `e`,
/// using a provided buffer it kept, or a send the buffers it selected
/// (`io_put_kbuf`), and so does its link. A
/// socket's gives what it moved instead ([`net::failed`]).
fn fail_request(ring: &Ring, mut chain: Vec<Request>, e: Errno) {
    let request = chain.remove(0);
    let flags = match &request.work {
        Work::Transfer(transfer) => transfer.kept.map_or(0, |kept| {
            CQE_F_BUFFER | u32::from(kept.bid) << CQE_BUFFER_SHIFT
        }),
        Work::Net(net) => net::kept(net),
        _ => 0,
    };
    let res = match &request.work {
        Work::Net(net) => net::failed(net, e),
        _ => -e.0,
    };
    let done = Done {
        user_data: request.user_data,
        res,
        flags,
        post: true,
        ltimeout: request.ltimeout,
        next: Vec::new(),
    };
    ring.complete(finish(done, request.flags, true, chain));
}

/// `io_req_tw_fail_links`: the rest of a link that failed.
fn fail_rest(ring: &Ring, chain: Vec<Request>, skip: bool) {
    for request in chain {
        ring.complete(Done {
            user_data: request.user_data,
            res: -request.failed.unwrap_or(ECANCELED).0,
            flags: 0,
            post: !skip,
            ltimeout: None,
            next: Vec::new(),
        });
    }
}

/// The identity of an open file, which a cancellation with
/// `IORING_ASYNC_CANCEL_FD` matches requests by (`req->file`).
fn file_identity(file: &Arc<dyn FileHandle>) -> usize {
    Arc::as_ptr(file).cast::<()>() as usize
}

/// `hash_long`: the bucket of `ctx->cancel_table` a `user_data` is in.
fn bucket(user_data: u64, bits: u32) -> u64 {
    user_data.wrapping_mul(0x61c8_8646_80b5_83eb) >> (64 - bits)
}

impl Ring {
    /// Puts a request that waits for `file` in the ring's [`Cancels`]
    /// (`io_poll_req_insert`), and gives its entry.
    fn hash(
        &self,
        request: &Request,
        file: &Arc<dyn FileHandle>,
        inbox: &Arc<crate::SignalInbox>,
    ) -> u64 {
        let mut cancels = self.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        let id = cancels.next;
        cancels.next += 1;
        cancels.hashed.push(Hashed {
            id,
            inbox: Arc::as_ptr(inbox) as usize,
            user_data: request.user_data,
            opcode: request.opcode,
            file: file_identity(file),
            cancelled: false,
            seq: None,
        });
        id
    }

    /// Takes a request's entry from the ring's [`Cancels`] as its task work
    /// runs, and says whether a cancellation found it.
    fn unhash(&self, id: u64) -> bool {
        let mut cancels = self.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        cancels
            .hashed
            .iter()
            .position(|h| h.id == id)
            .is_some_and(|at| cancels.hashed.remove(at).cancelled)
    }

    /// Whether a cancellation found a request whose task work is to run.
    fn is_cancelled(&self, id: u64) -> bool {
        let cancels = self.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        cancels.hashed.iter().any(|h| h.id == id && h.cancelled)
    }

    /// `io_poll_find`: the latest `IORING_OP_POLL_ADD` of `user_data`.
    fn find_poll(&self, user_data: u64) -> Option<u64> {
        let cancels = self.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        let found = |h: &&Hashed| h.opcode == poll::OP_POLL_ADD && h.user_data == user_data;
        cancels.hashed.iter().rev().find(found).map(|h| h.id)
    }
}

/// Whether `hashed` is what `key` looks for (`io_cancel_req_match`): any
/// request with `IORING_ASYNC_CANCEL_ANY`, else one of its file, operation
/// and `user_data` (that alone without the others, or with
/// `IORING_ASYNC_CANCEL_USERDATA`). With `IORING_ASYNC_CANCEL_ALL` or
/// `_ANY`, a request cancellation `seq` matched already does not match again
/// (`io_cancel_match_sequence`).
fn cancel_matches(hashed: &mut Hashed, key: &CancelKey, file: Option<usize>, seq: u32) -> bool {
    if key.flags & CANCEL_ANY == 0 {
        let by_data = key.flags & CANCEL_USERDATA != 0 || key.flags & (CANCEL_FD | CANCEL_OP) == 0;
        if key.flags & CANCEL_FD != 0 && file != Some(hashed.file)
            || key.flags & CANCEL_OP != 0 && hashed.opcode != key.opcode
            || by_data && hashed.user_data != key.user_data
        {
            return false;
        }
        if key.flags & CANCEL_ALL == 0 {
            return true;
        }
    }
    if hashed.seq == Some(seq) {
        return false;
    }
    hashed.seq = Some(seq);
    true
}

/// Linux's `__io_async_cancel`, which `IORING_OP_ASYNC_CANCEL` and
/// `IORING_REGISTER_SYNC_CANCEL` run: the requests of the ring that wait
/// for their files, then the timeouts, are the ones it can find (no request
/// runs in a worker, which it would look for first).
/// With `IORING_ASYNC_CANCEL_ALL` or `_ANY` it cancels every one that
/// matches and gives how many, else the first, giving 0, or `ENOENT` for
/// none.
fn cancel(
    c: &Context<'_>,
    ring: &Ring,
    key: &CancelKey,
    file: Option<usize>,
) -> Result<u64, Errno> {
    let all = key.flags & (CANCEL_ALL | CANCEL_ANY) != 0;
    let seq = {
        let mut cancels = ring.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        cancels.seq = cancels.seq.wrapping_add(1);
        cancels.seq
    };
    if !all {
        return try_cancel(c, ring, key, file, seq).map(|_| 0);
    }
    let mut count = 0;
    while let Ok(found) = try_cancel(c, ring, key, file, seq) {
        count += found.max(1);
    }
    Ok(count)
}

/// `io_try_cancel`: a request that waits for its file, else a timeout.
fn try_cancel(
    c: &Context<'_>,
    ring: &Ring,
    key: &CancelKey,
    file: Option<usize>,
    seq: u32,
) -> Result<u64, Errno> {
    match cancel_polls(c, ring, key, file, seq) {
        Err(Errno::ENOENT) => timeout::cancel_one(c, ring, key, seq),
        result => result,
    }
}

/// Linux's `io_poll_cancel`: marks the requests that match `key` cancelled,
/// in the order of `ctx->cancel_table` (by the bucket of their
/// `user_data`, the latest first in each), every one with
/// `IORING_ASYNC_CANCEL_ALL` or `_ANY`, else the first, and gives how many,
/// or `ENOENT` for none. Each that still waits for its file stops, and its
/// task work fails it ([`Deferred::Poll`], `io_poll_cancel_req`); one whose
/// file became ready already fails as its task work runs.
fn cancel_polls(
    c: &Context<'_>,
    ring: &Ring,
    key: &CancelKey,
    file: Option<usize>,
    seq: u32,
) -> Result<u64, Errno> {
    let all = key.flags & (CANCEL_ALL | CANCEL_ANY) != 0;
    let found: Vec<u64> = {
        let mut cancels = ring.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        let mut order: Vec<usize> = (0..cancels.hashed.len()).collect();
        order.sort_by_key(|&at| {
            (
                bucket(cancels.hashed[at].user_data, ring.hash_bits),
                std::cmp::Reverse(at),
            )
        });
        let mut found = Vec::new();
        for at in order {
            let hashed = &mut cancels.hashed[at];
            if cancel_matches(hashed, key, file, seq) {
                hashed.cancelled = true;
                found.push(hashed.id);
                if !all {
                    break;
                }
            }
        }
        found
    };
    if found.is_empty() {
        return Err(Errno::ENOENT);
    }
    // Their task work goes in the order they were found.
    let stopped: Vec<Armed> = {
        let polls = &c.processes.io_uring;
        let mut armed = polls.armed.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut stopped, waiting): (Vec<Armed>, Vec<Armed>) = std::mem::take(&mut *armed)
            .into_iter()
            .partition(|a| found.contains(&a.id) && a.is(ring, a.id) && !a.queued());
        *armed = waiting;
        polls
            .count
            .store(armed.len(), std::sync::atomic::Ordering::SeqCst);
        stopped.sort_by_key(|a| found.iter().position(|&id| id == a.id));
        stopped
    };
    for armed in stopped {
        let Some(file) = armed.ring.upgrade() else {
            continue;
        };
        let other = !std::ptr::eq(Arc::as_ptr(&armed.inbox), Arc::as_ptr(c.inbox));
        add_work(
            &c.processes.io_uring,
            &file,
            ring,
            &armed.inbox,
            other.then_some(&*armed.hub),
            Deferred::Poll {
                id: armed.id,
                chain: armed.chain,
                held: armed.held,
            },
        );
    }
    Ok(found.len() as u64)
}

/// `IORING_REGISTER_SYNC_CANCEL` (`io_sync_cancel`): `struct
/// io_uring_sync_cancel_reg` at `arg` (`EFAULT`), whose flags must be
/// known and padding zero (`EINVAL`), and whose descriptor must be open
/// (`EBADF`), registered with `IORING_ASYNC_CANCEL_FD_FIXED`. It gives what
/// the cancellation found: how many with `IORING_ASYNC_CANCEL_ALL` or
/// `_ANY`, else 0 or `ENOENT`. No request is ever running where it cannot
/// be cancelled at once, so it never waits, and its timeout is unused.
fn sync_cancel(c: &mut Context<'_>, ring: &Ring, arg: u64) -> Result<u64, Errno> {
    let mut sc = [0u8; 64];
    c.mem
        .read(GuestAddr(arg), &mut sc)
        .map_err(|_| Errno::EFAULT)?;
    let key = CancelKey {
        user_data: u64_at(&sc, 0),
        fd: u32_at(&sc, 8) as i32,
        flags: u32_at(&sc, 12),
        opcode: sc[32],
    };
    if key.flags & !CANCEL_FLAGS != 0 || sc[33..].iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let file = if key.flags & CANCEL_FD != 0 {
        let fixed = key.flags & CANCEL_FD_FIXED != 0;
        let file = if fixed {
            ring.files
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .and_then(|files| {
                    files
                        .slots
                        .get(&(key.fd as u32))
                        .and_then(|n| n.file().map(|d| Arc::clone(&d.file)))
                })
                .ok_or(Errno::EBADF)?
        } else {
            fget(c, key.fd)?.file
        };
        Some(file_identity(&file))
    } else {
        None
    };
    cancel(c, ring, &key, file)
}

/// What a request's completion does, after its flags: one that failed posts
/// even with `IOSQE_CQE_SKIP_SUCCESS` (`req_set_fail`), and so ends its soft
/// link, whose rest posts nothing if it had the flag
/// (`REQ_F_SKIP_LINK_CQES`); otherwise the link's next request runs
/// (`io_req_find_next`).
fn finish(mut done: Done, flags: u8, failed: bool, rest: Vec<Request>) -> Done {
    let skip = flags & IOSQE_CQE_SKIP_SUCCESS != 0;
    done.post = failed || !skip;
    if rest.is_empty() {
        return done;
    }
    done.next.push(if failed && flags & IOSQE_IO_HARDLINK == 0 {
        Deferred::Fail { chain: rest, skip }
    } else {
        Deferred::Submit(rest, Vec::new())
    });
    done
}

/// Runs a piece of task work in the ring's open batch.
fn run_deferred(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, work: Deferred) {
    match work {
        Deferred::Complete {
            done,
            held,
            rest,
            flags,
            failed,
        } => {
            ring.state().held.extend(held);
            ring.complete(finish(done, flags, failed, rest));
        }
        Deferred::Submit(chain, held) => {
            issue_link(c, file, ring, chain, held);
        }
        Deferred::Poll { id, chain, held } => {
            if ring.unhash(id) {
                ring.state().held.extend(held);
                fail_request(ring, chain, ECANCELED);
            } else {
                issue_link(c, file, ring, chain, held);
            }
        }
        Deferred::Polled(armed) => poll::finished(c, file, ring, *armed),
        Deferred::PollMore { id } => poll::more(c, file, ring, id),
        Deferred::Fail { chain, skip } => fail_rest(ring, chain, skip),
        Deferred::Timeout(chain) => timeout::run_expired(c, file, ring, chain),
        Deferred::LinkTimeout { request, head } => {
            timeout::run_link(Some(c), ring, &request, head);
        }
    }
}

/// Adds task work (`io_req_task_work_add`) of the running thread.
fn queue(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, work: Deferred) {
    add_work(&c.processes.io_uring, file, ring, c.inbox, None, work);
}

/// Adds task work to the ring's own list with `IORING_SETUP_DEFER_TASKRUN`
/// (`io_req_local_work_add`), else to the list of the thread `inbox`
/// belongs to (`io_req_normal_work_add`), which it tells to run it
/// (`task_work_add`). The work that starts a list sets `IORING_SQ_TASKRUN`.
/// Work another thread adds (`hub`, that of the thread the work is for)
/// wakes the thread's waits.
fn add_work(
    polls: &Polls,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    inbox: &crate::SignalInbox,
    hub: Option<&crate::events::ReadinessHub>,
    work: Deferred,
) {
    if ring.flags & SETUP_DEFER_TASKRUN != 0 {
        let first = {
            let mut local = ring.local.lock().unwrap_or_else(PoisonError::into_inner);
            local.push_back(work);
            local.len() == 1
        };
        if first {
            ring.mark_taskrun(true);
        }
        if let Some(hub) = hub {
            hub.changed();
        }
        return;
    }
    // The flag is set under the list's lock, so a run that empties the list
    // after this push clears it after it is set. A thread that exited runs
    // nothing more: the work runs at once (`io_fallback_tw`).
    let first = {
        let mut task_work = inbox.task_work();
        if task_work.exited {
            polls
                .fallback
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((Arc::downgrade(file), work));
            return;
        }
        task_work.queue.push_back((Arc::downgrade(file), work));
        inbox.notify_signal(hub.is_some());
        task_work.queue.len() == 1
    };
    if first {
        ring.mark_taskrun(true);
    }
    if let Some(hub) = hub {
        hub.changed();
    }
}

/// Ends a ring's batch and adds the task work its requests' links go on
/// with.
fn flush_batch(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring) {
    let next = ring.end();
    timeout::flush(&c.processes.io_uring, file, ring, Some(c.inbox));
    for work in next {
        queue(c, file, ring, work);
    }
}

/// Whether the thread has task work to run as it returns to its program
/// (`TIF_NOTIFY_SIGNAL`).
pub(crate) fn task_work_due(inbox: &crate::SignalInbox) -> bool {
    inbox.notified() || !inbox.task_work().is_empty()
}

/// Runs the thread's task work (`tctx_task_work_run`) in order, a batch for
/// each ring in turn, whose end clears `IORING_SQ_TASKRUN`
/// (`ctx_flush_and_put`), until none is left, then clears
/// `TIF_NOTIFY_SIGNAL`.
pub(crate) fn run_task_work(c: &mut Context<'_>) {
    let mut current: Option<Arc<dyn FileHandle>> = None;
    loop {
        let next = c.inbox.task_work().queue.pop_front();
        // The work of a ring that closed goes with it.
        let next = match next {
            Some((file, work)) => match file.upgrade() {
                Some(file) => Some((file, work)),
                None => continue,
            },
            None => None,
        };
        let Some((file, work)) = next else {
            match current.take() {
                Some(file) => {
                    end_task_work(c, &file);
                    continue;
                }
                None if c.inbox.clear_notify_if_idle() => break,
                None => continue,
            }
        };
        if !current
            .as_ref()
            .is_some_and(|f| std::ptr::addr_eq(Arc::as_ptr(f), Arc::as_ptr(&file)))
        {
            if let Some(previous) = current.take() {
                end_task_work(c, &previous);
            }
            if let Ok(ring) = downcast(&file) {
                ring.begin();
            }
            current = Some(Arc::clone(&file));
        }
        if let Ok(ring) = downcast(&file) {
            let _submitting = ring.submitting();
            run_deferred(c, &file, ring, work);
        }
    }
    run_fallback(&c.processes.io_uring);
}

fn end_task_work(c: &mut Context<'_>, file: &Arc<dyn FileHandle>) {
    if let Ok(ring) = downcast(file) {
        ring.mark_taskrun(false);
        let _submitting = ring.submitting();
        flush_batch(c, file, ring);
    }
}

/// Whether an `IORING_SETUP_DEFER_TASKRUN` ring has task work.
fn local_pending(ring: &Ring) -> bool {
    !ring
        .local
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_empty()
}

/// Linux's `__io_run_local_work`: runs up to `max_events` of the ring's own
/// task work at a time, and again while some is left and fewer than
/// `min_events` ran, ending the batch between; what it leaves sets
/// `IORING_SQ_TASKRUN` again.
fn run_local(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    min_events: u32,
    max_events: u32,
) {
    let carry_on = |events: u32, min: i64| {
        if !local_pending(ring) {
            return false;
        }
        if i64::from(events) < min {
            return true;
        }
        ring.mark_taskrun(true);
        false
    };
    let _submitting = ring.submitting();
    ring.mark_taskrun(false);
    let mut min = i64::from(min_events);
    let mut ran = 0;
    let mut open = false;
    loop {
        min -= i64::from(ran);
        if !open {
            ring.begin();
            open = true;
        }
        ran = 0;
        while ran < max_events {
            let Some(work) = ring
                .local
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
            else {
                break;
            };
            run_deferred(c, file, ring, work);
            ran += 1;
        }
        if carry_on(ran, min) {
            continue;
        }
        flush_batch(c, file, ring);
        open = false;
        if !carry_on(ran, min) {
            return;
        }
    }
}

/// Linux's `io_submit_sqes`: takes up to `wanted` entries from the
/// submission queue and gives how many it took. One that fails to prepare
/// outside a link ends the submission (after it) unless
/// `IORING_SETUP_SUBMIT_ALL`; an index past the entries in the queue's
/// array is dropped and ends it before it.
fn submit(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, wanted: u32) -> u32 {
    let mask = ring.sq_entries - 1;
    let (mut head, available) = {
        let state = ring.state();
        let tail = ring.load_u32(SQ_TAIL);
        (
            state.sq_head,
            tail.wrapping_sub(state.sq_head).min(ring.sq_entries),
        )
    };
    let total = wanted.min(available);
    let mut left = total;
    ring.begin();
    let mut chain: Vec<Request> = Vec::new();
    while left > 0 {
        let mut index = head & mask;
        head = head.wrapping_add(1);
        if let Some(array) = ring.sq_array {
            index = {
                let mut bytes = [0; 4];
                ring.rings.load(array + 4 * u64::from(index), &mut bytes);
                u32::from_le_bytes(bytes)
            };
            if index >= ring.sq_entries {
                let dropped = ring.load_u32(SQ_DROPPED);
                ring.store_u32(SQ_DROPPED, dropped.wrapping_add(1));
                break;
            }
        }
        let mut sqe = [0; SQE_BYTES as usize];
        ring.sqes.load(u64::from(index) * SQE_BYTES, &mut sqe);
        let mut request = ring.prepare(&mut ring.state(), &sqe);
        if request.failed.is_none() {
            prepare_memory(c, ring, &mut request, u64_at(&sqe, 16));
        }
        // A linked timeout is for the request before it in a link, and no
        // other linked timeout (`io_link_timeout_prep`).
        if request.failed.is_none()
            && request.opcode == timeout::OP_LINK_TIMEOUT
            && chain
                .last()
                .is_none_or(|last| last.opcode == timeout::OP_LINK_TIMEOUT)
        {
            request.failed = Some(Errno::EINVAL);
        }
        let failed = request.failed.is_some();
        let linked = request.flags & LINK_FLAGS != 0;
        chain.push(request);
        left -= 1;
        if !linked {
            complete(c, file, ring, std::mem::take(&mut chain));
            if failed && ring.flags & SETUP_SUBMIT_ALL == 0 {
                break;
            }
        }
    }
    // A link the submission left open runs as it is.
    if !chain.is_empty() {
        complete(c, file, ring, chain);
    }
    flush_batch(c, file, ring);
    ring.state().sq_head = head;
    ring.store_u32(SQ_HEAD, head);
    total - left
}

/// The ring `fd` names, as `io_uring_register_get_file` finds it: with
/// `registered`, the thread's registered ring of that index, which a thread
/// without an io_uring context or an index past the table is `EINVAL`, and
/// an empty one `EBADF`; else the ring of descriptor `fd` ([`ring_of`]).
fn ring_file(c: &Context<'_>, fd: u64, registered: bool) -> Result<Arc<dyn FileHandle>, Errno> {
    if !registered {
        return ring_of(c, fd);
    }
    let task = c.inbox.task_work();
    if !task.context || fd as u32 >= RINGFD_REG_MAX {
        return Err(Errno::EINVAL);
    }
    task.rings[fd as u32 as usize].clone().ok_or(Errno::EBADF)
}

/// Gives the running thread an io_uring context (`__io_uring_add_tctx_node`).
fn give_context(c: &Context<'_>) {
    c.inbox.task_work().context = true;
}

/// `IORING_REGISTER_RING_FDS`, as Linux's `io_ringfd_register`: 1 to 16
/// `struct io_uring_rsrc_update`s at `arg` (`EINVAL`), each in turn read
/// (`EFAULT`) with no reserved field (`EINVAL`): the ring of descriptor
/// `data` (`EBADF`, or `EOPNOTSUPP` for another file) goes in the slot
/// `offset` names, or the first free one for `u32::MAX` (`EINVAL` past the
/// table, `EBUSY` for none free), and the slot is written back to `offset`
/// (`EFAULT`, which lets go of it). It gives how many it registered, or the
/// first one's error.
fn register_ring_fds(c: &Context<'_>, arg: u64, count: u32) -> Result<u64, Errno> {
    if count == 0 || count > RINGFD_REG_MAX {
        return Err(Errno::EINVAL);
    }
    give_context(c);
    let mut done = 0;
    let failed = (|| -> Result<(), Errno> {
        while done < count {
            let at = GuestAddr(arg.wrapping_add(16 * u64::from(done)));
            let mut update = [0u8; 16];
            c.mem.read(at, &mut update).map_err(|_| Errno::EFAULT)?;
            let (offset, data) = (u32_at(&update, 0), u64_at(&update, 8));
            if u32_at(&update, 4) != 0 {
                return Err(Errno::EINVAL);
            }
            let (start, end) = match offset {
                u32::MAX => (0, RINGFD_REG_MAX),
                offset if offset >= RINGFD_REG_MAX => return Err(Errno::EINVAL),
                offset => (offset, offset + 1),
            };
            let d = fget(c, data as u32 as i32)?;
            if !is_ring(&d) {
                return Err(EOPNOTSUPP);
            }
            let slot = {
                let mut task = c.inbox.task_work();
                let slot = (start..end)
                    .find(|&slot| task.rings[slot as usize].is_none())
                    .ok_or(EBUSY)?;
                task.rings[slot as usize] = Some(d.file);
                slot
            };
            if c.mem.write(at, &slot.to_le_bytes()).is_err() {
                c.inbox.task_work().rings[slot as usize] = None;
                return Err(Errno::EFAULT);
            }
            done += 1;
        }
        Ok(())
    })();
    match failed {
        Err(e) if done == 0 => Err(e),
        _ => Ok(u64::from(done)),
    }
}

/// `IORING_UNREGISTER_RING_FDS`, as Linux's `io_ringfd_unregister`: 1 to 16
/// `struct io_uring_rsrc_update`s (`EINVAL`); nothing for a thread without
/// an io_uring context; each read in turn (`EFAULT`), with no reserved
/// field, no `data` and a slot in the table (`EINVAL`), empties its slot.
/// It gives how many it took, or the first one's error.
fn unregister_ring_fds(c: &Context<'_>, arg: u64, count: u32) -> Result<u64, Errno> {
    if count == 0 || count > RINGFD_REG_MAX {
        return Err(Errno::EINVAL);
    }
    if !c.inbox.task_work().context {
        return Ok(0);
    }
    let mut done = 0;
    let failed = (|| -> Result<(), Errno> {
        while done < count {
            let mut update = [0u8; 16];
            c.mem
                .read(
                    GuestAddr(arg.wrapping_add(16 * u64::from(done))),
                    &mut update,
                )
                .map_err(|_| Errno::EFAULT)?;
            let offset = u32_at(&update, 0);
            if u32_at(&update, 4) != 0 || u64_at(&update, 8) != 0 || offset >= RINGFD_REG_MAX {
                return Err(Errno::EINVAL);
            }
            c.inbox.task_work().rings[offset as usize] = None;
            done += 1;
        }
        Ok(())
    })();
    match failed {
        Err(e) if done == 0 => Err(e),
        _ => Ok(u64::from(done)),
    }
}

/// Lets go of the thread's registered rings (`io_uring_unreg_ringfd`), as
/// it calls `execve` or exits.
fn unregister_all_rings(inbox: &crate::SignalInbox) {
    let rings = std::mem::take(&mut inbox.task_work().rings);
    drop(rings);
}

/// The ring behind descriptor `fd`: `EBADF` without one (or for `O_PATH`),
/// `EOPNOTSUPP` for another file.
fn ring_of(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let d = c.files.descriptor(fd)?;
    if d.file.flags() & 0o10000000 != 0 {
        return Err(Errno::EBADF);
    }
    if !d.file.as_any().is_some_and(|v| v.is::<Ring>()) {
        return Err(EOPNOTSUPP);
    }
    Ok(d.file)
}

#[cfg(test)]
pub(crate) fn hold(file: &Arc<dyn FileHandle>) -> std::sync::MutexGuard<'_, ()> {
    downcast(file).unwrap().submitting()
}

fn downcast(file: &Arc<dyn FileHandle>) -> Result<&Ring, Errno> {
    file.as_any()
        .and_then(|v| v.downcast_ref::<Ring>())
        .ok_or(EOPNOTSUPP)
}

/// `io_uring_setup(entries, params)`.
pub(crate) fn sys_setup(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match setup(c, a[0] as u32, a[1]) {
        Ok(fd) => ok(u64::from(fd)),
        Err(e) => err(e),
    }
}

fn setup(c: &mut Context<'_>, entries: u32, params: u64) -> Result<u32, Errno> {
    let mut p = [0u8; 120];
    c.mem
        .read(GuestAddr(params), &mut p)
        .map_err(|_| Errno::EFAULT)?;
    if p[28..40].iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let flags = u32_at(&p, 8);
    if flags & !SETUP_KNOWN != 0 || flags & !SETUP_IMPLEMENTED != 0 {
        return Err(Errno::EINVAL);
    }
    if entries == 0 {
        return Err(Errno::EINVAL);
    }
    let entries = if entries > MAX_ENTRIES {
        if flags & SETUP_CLAMP == 0 {
            return Err(Errno::EINVAL);
        }
        MAX_ENTRIES
    } else {
        entries
    };
    let sq_entries = entries.next_power_of_two();
    let cq_entries = if flags & SETUP_CQSIZE != 0 {
        let mut cq = u32_at(&p, 4);
        if cq == 0 {
            return Err(Errno::EINVAL);
        }
        if cq > MAX_CQ_ENTRIES {
            if flags & SETUP_CLAMP == 0 {
                return Err(Errno::EINVAL);
            }
            cq = MAX_CQ_ENTRIES;
        }
        let cq = cq.next_power_of_two();
        if cq < sq_entries {
            return Err(Errno::EINVAL);
        }
        cq
    } else {
        2 * sq_entries
    };
    if flags & SETUP_COOP_TASKRUN == 0
        && flags & SETUP_TASKRUN_FLAG != 0
        && flags & SETUP_DEFER_TASKRUN == 0
    {
        return Err(Errno::EINVAL);
    }
    if flags & SETUP_DEFER_TASKRUN != 0 && flags & SETUP_SINGLE_ISSUER == 0 {
        return Err(Errno::EINVAL);
    }
    // The completion queue entries end on a cache line, and the
    // submission queue's array follows them.
    let cqes_end = (CQES + u64::from(cq_entries) * CQE_BYTES).next_multiple_of(64);
    let sq_array = (flags & SETUP_NO_SQARRAY == 0).then_some(cqes_end);
    let rings_len = cqes_end + sq_array.map_or(0, |_| 4 * u64::from(sq_entries));
    let sqes_len = u64::from(sq_entries) * SQE_BYTES;
    let pages = |len: u64| ring_pages(c, len);
    let ring = Ring {
        status: Default::default(),
        stat: crate::files::own_anonymous_inode(&c.process.credentials),
        flags,
        sq_entries,
        cq_entries,
        rings: pages(rings_len)?,
        sq_array,
        sqes: pages(sqes_len)?,
        sqes_len,
        submitter: if flags & (SETUP_SINGLE_ISSUER | SETUP_R_DISABLED) == SETUP_SINGLE_ISSUER {
            c.tid.into()
        } else {
            std::sync::OnceLock::new()
        },
        disabled: (flags & SETUP_R_DISABLED != 0).into(),
        restrictions: Mutex::default(),
        personalities: Mutex::default(),
        submitting: Mutex::default(),
        state: Mutex::default(),
        charged: (!c.process.credentials.capable(CAP_IPC_LOCK)).then(|| {
            (
                Arc::clone(&c.processes.secret_pages),
                c.process.credentials.uid,
            )
        }),
        buffers: Mutex::default(),
        files: Mutex::default(),
        buffer_lists: Mutex::default(),
        local: Mutex::default(),
        cancels: Mutex::default(),
        timeouts: Mutex::default(),
        // `io_ring_ctx_alloc`: `ilog2(cq_entries) - 5`, from 1 to 8.
        hash_bits: cq_entries.ilog2().saturating_sub(5).clamp(1, 8),
        hub: Arc::clone(&c.files.readiness),
        posted: std::sync::atomic::AtomicU64::new(0),
    };
    ring.store_u32(SQ_RING_MASK, sq_entries - 1);
    ring.store_u32(CQ_RING_MASK, cq_entries - 1);
    ring.store_u32(SQ_RING_ENTRIES, sq_entries);
    ring.store_u32(CQ_RING_ENTRIES, cq_entries);

    fn put(p: &mut [u8], at: usize, value: u32) {
        p[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    put(&mut p, 0, sq_entries);
    put(&mut p, 4, cq_entries);
    put(&mut p, 20, FEATURES);
    // struct io_sqring_offsets, from byte 40; the array stays as given
    // without one.
    let sq_off = [
        SQ_HEAD,
        SQ_TAIL,
        SQ_RING_MASK,
        SQ_RING_ENTRIES,
        SQ_FLAGS,
        SQ_DROPPED,
    ];
    for (i, off) in sq_off.iter().enumerate() {
        put(&mut p, 40 + 4 * i, *off as u32);
    }
    if let Some(array) = sq_array {
        put(&mut p, 64, array as u32);
    }
    put(&mut p, 68, 0);
    p[72..80].fill(0);
    // struct io_cqring_offsets, from byte 80.
    let cq_off = [
        CQ_HEAD,
        CQ_TAIL,
        CQ_RING_MASK,
        CQ_RING_ENTRIES,
        CQ_OVERFLOW,
        CQES,
        CQ_FLAGS,
    ];
    for (i, off) in cq_off.iter().enumerate() {
        put(&mut p, 80 + 4 * i, *off as u32);
    }
    put(&mut p, 108, 0);
    p[112..120].fill(0);
    c.mem
        .write(GuestAddr(params), &p)
        .map_err(|_| Errno::EFAULT)?;
    let file: Arc<dyn FileHandle> = Arc::new(ring);
    c.processes
        .io_uring
        .rings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Arc::downgrade(&file));
    let fd = c.files.install(file, true, c.group.nofile())?;
    // `io_uring_create` gives its thread a context.
    give_context(c);
    Ok(fd)
}

/// Zeroed pages the kernel gives for `len` bytes, which a mapping of the
/// ring's descriptor shares; a page past them raises `SIGBUS`.
fn ring_pages(c: &Context<'_>, len: u64) -> Result<SharedPages, Errno> {
    let size = len.next_multiple_of(4096);
    let pages = SharedPages::new().with_source(Arc::new(RingPages { size }));
    let meter = c.mem.memory_meter();
    for key in (0..size).step_by(4096) {
        pages.fill(key, &[], meter.as_ref())?;
    }
    Ok(pages)
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz)`: the
/// submission, then the wait for completions with `IORING_ENTER_GETEVENTS`,
/// which a submission that took fewer entries than asked skips. It gives
/// how many entries it took, or the wait's result if it took none.
pub(crate) fn sys_enter(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match enter(c, a) {
        Ok(n) => ok(n),
        Err(e) => err(e),
    }
}

fn enter(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (to_submit, min_complete, flags) = (a[1] as u32, a[2] as u32, a[3] as u32);
    if flags & !ENTER_KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    let file = ring_file(c, a[0], flags & ENTER_REGISTERED_RING != 0)?;
    let ring = downcast(&file)?;
    if ring.disabled() {
        return Err(register::EBADFD);
    }
    let mut submitted = 0;
    if to_submit != 0 {
        // `__io_uring_add_tctx_node_from_submit`: the submitter, then the
        // context, though no entry may be there to take.
        if ring.others(c.tid) {
            return Err(EEXIST);
        }
        give_context(c);
        {
            let _submitting = ring.submitting();
            ring.flush(&mut ring.state());
            submitted = submit(c, &file, ring, to_submit);
        }
        if submitted != to_submit {
            return Ok(u64::from(submitted));
        }
        // `io_run_local_work_locked`, before the wait.
        if flags & ENTER_GETEVENTS != 0
            && ring.flags & SETUP_DEFER_TASKRUN != 0
            && local_pending(ring)
        {
            run_local(
                c,
                &file,
                ring,
                at_least(min_complete),
                LOCAL_TW_DEFAULT_MAX.max(at_least(min_complete)),
            );
        }
    }
    if flags & ENTER_GETEVENTS != 0 {
        let waited = wait(
            c,
            &file,
            ring,
            (min_complete as i32).min(ring.cq_entries as i32) as u32,
            flags,
            a[4],
            a[5],
        );
        if submitted == 0 {
            return waited.map(|()| 0);
        }
    }
    Ok(u64::from(submitted))
}

/// The completions `min_complete` asks for, an `int` of which a negative one
/// asks for none.
fn at_least(min_complete: u32) -> u32 {
    (min_complete as i32).max(0) as u32
}

/// Linux's `struct ext_arg`: what a wait for completions is given
/// (`io_get_ext_arg`).
struct WaitArg {
    sigmask: u64,
    sigsz: u64,
    /// The least time to wait for all the completions, in nanoseconds
    /// (`min_wait_usec`).
    min_time: u64,
    /// The timeout, a `ktime_t`.
    timeout: Option<i64>,
}

fn wait_arg(c: &Context<'_>, flags: u32, argp: u64, argsz: u64) -> Result<WaitArg, Errno> {
    if flags & ENTER_EXT_ARG == 0 {
        return Ok(WaitArg {
            sigmask: argp,
            sigsz: argsz,
            min_time: 0,
            timeout: None,
        });
    }
    // A wait region's (`io_get_ext_arg_reg`): `IORING_REGISTER_MEM_REGION`
    // is not there, so the argument is never in one (`EFAULT`).
    if flags & ENTER_EXT_ARG_REG != 0 {
        // struct io_uring_reg_wait.
        return Err(if argsz != 64 {
            Errno::EINVAL
        } else {
            Errno::EFAULT
        });
    }
    // struct io_uring_getevents_arg.
    if argsz != 24 {
        return Err(Errno::EINVAL);
    }
    let mut arg = [0; 24];
    c.mem
        .read(GuestAddr(argp), &mut arg)
        .map_err(|_| Errno::EFAULT)?;
    let ts = u64_at(&arg, 16);
    let timeout = if ts == 0 {
        None
    } else {
        let mut timespec = [0; 16];
        c.mem
            .read(GuestAddr(ts), &mut timespec)
            .map_err(|_| Errno::EFAULT)?;
        let (sec, nsec) = (u64_at(&timespec, 0) as i64, u64_at(&timespec, 8) as i64);
        // `timespec64_to_ktime`.
        Some(sec.saturating_mul(1_000_000_000).saturating_add(nsec))
    };
    Ok(WaitArg {
        sigmask: u64_at(&arg, 0),
        sigsz: u64::from(u32_at(&arg, 8)),
        min_time: u64::from(u32_at(&arg, 12)) * 1000,
        timeout,
    })
}

/// Linux's `io_cqring_wait`: it runs the ring's own task work and the
/// thread's, then is done once the program has `min` completions to
/// consume, else it waits, with the signal mask it was given, for a signal
/// (`EINTR`) or the timeout (`ETIME`), running task work that comes. An
/// `IORING_OP_TIMEOUT` done as it waits ends it too, and once the
/// `min_wait_usec` passed, so does any completion. Completions in the
/// queue by then make it succeed whatever ended the wait.
fn wait(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    min: u32,
    flags: u32,
    argp: u64,
    argsz: u64,
) -> Result<(), Errno> {
    let arg = wait_arg(c, flags, argp, argsz)?;
    if ring.flags & SETUP_DEFER_TASKRUN != 0 && ring.others(c.tid) {
        return Err(EEXIST);
    }
    if local_pending(ring) {
        let min = at_least(min);
        run_local(c, file, ring, min, LOCAL_TW_DEFAULT_MAX.max(min));
    }
    if task_work_due(c.inbox) {
        run_task_work(c);
    }
    {
        let mut state = ring.state();
        ring.flush(&mut state);
    }
    if ring.completions() >= min {
        return Ok(());
    }
    let first = ring.load_u32(CQ_TAIL);
    // The queue's tail it waits for, and how much task work of the ring's
    // own it runs at a time meanwhile, as many completions as it lacks.
    let mut target = ring.load_u32(CQ_HEAD).wrapping_add(min);
    let mut wanted = target.wrapping_sub(first);
    let timeouts = timeout::done(ring);
    let start = c.host.clock(paludarium_host::ClockId::Monotonic)? as i64;
    // `KTIME_MAX` is no timeout.
    let deadline = arg
        .timeout
        .map(|time| {
            if flags & ENTER_ABS_TIMER != 0 {
                time
            } else {
                time.wrapping_add(start)
            }
        })
        .filter(|end| *end != i64::MAX);
    let mut least = (arg.min_time != 0).then(|| start.saturating_add(arg.min_time as i64));
    let old_mask = c.process.signal_mask;
    if arg.sigmask != 0 {
        if arg.sigsz != 8 {
            return Err(Errno::EINVAL);
        }
        c.process.signal_mask = c
            .mem
            .read_u64(GuestAddr(arg.sigmask))
            .map_err(|_| Errno::EFAULT)?
            & !((1 << 8) | (1 << 18));
        crate::userfaultfd::mask_changed(c.process.signal_mask);
    }
    // Whether it is to sleep anew, rather than sleeps on.
    let mut fresh = true;
    let mut ran = false;
    let result = loop {
        let ticket = c.files.readiness.token.value();
        if run_waiting(c, file, ring, wanted) {
            (fresh, ran) = (true, true);
            wanted = target.wrapping_sub(ring.load_u32(CQ_TAIL));
            continue;
        }
        // `io_should_wake`. A timeout of another thread's counts once that
        // thread posts its completion, which is what wakes Linux's wait.
        let tail = ring.load_u32(CQ_TAIL);
        if tail.wrapping_sub(target) as i32 >= 0
            || (timeout::done(ring) != timeouts && (ran || tail != first))
        {
            break Ok(());
        }
        let now = match c.host.clock(paludarium_host::ClockId::Monotonic) {
            Ok(now) => now as i64,
            Err(e) => break Err(e),
        };
        // Linux master looks at the timeout before it arms the timer of
        // either time, which then is the only one there is.
        if (fresh || least.is_none()) && deadline.is_some_and(|end| now >= end) {
            break Err(ETIME);
        }
        if least.is_some_and(|least| now >= least) {
            // `io_cqring_min_timer_wakeup`, which compares the time itself
            // with the timeout's end.
            if deadline.is_none_or(|end| arg.min_time as i64 >= end)
                || tail != first
                || ring.completions() != 0
            {
                break Err(ETIME);
            }
            least = None;
            target = first.wrapping_add(1);
            continue;
        }
        // Task work that comes as it waits runs here, and ends no wait
        // (`io_cqring_wait_schedule` checks `task_sigpending`).
        let end = least.or(deadline).map(|end| end.max(0) as u64);
        if let Err(e) = crate::events::wait_for(c, ticket, end, false) {
            break Err(e);
        }
        fresh = false;
    };
    // Whatever ends it, it runs the work that came.
    run_waiting(c, file, ring, wanted);
    if arg.sigmask != 0
        && result == Err(Errno(4))
        && crate::signals::next_pending(c.process, true).is_some()
    {
        // The handler's frame saves the mask from before the call, as
        // Linux's `restore_saved_sigmask_unless` keeps the one given.
        c.process.wait_restore_mask = Some(old_mask);
    } else {
        c.process.signal_mask = old_mask;
        crate::userfaultfd::mask_changed(c.process.signal_mask);
    }
    if ring.completions() != 0 {
        return Ok(());
    }
    result
}

/// Runs the ring's own task work, `wanted` of it at a time, and the
/// thread's, if there is any, and moves completions without room to the
/// queue.
fn run_waiting(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, wanted: u32) -> bool {
    let (local, task) = (local_pending(ring), task_work_due(c.inbox));
    if local {
        run_local(c, file, ring, wanted, wanted);
    }
    if task {
        run_task_work(c);
    }
    ring.flush(&mut ring.state());
    local || task
}

/// `io_uring_register(fd, opcode, arg, nr_args)`: only
/// `IORING_REGISTER_PROBE`, the buffers' and the files' registrations, the
/// files' tagged registrations, updates and allocation range, the rings of
/// buffers' registrations and status, `IORING_REGISTER_SYNC_CANCEL`, the
/// ring descriptors' registrations, the personalities, the restrictions and
/// `IORING_REGISTER_ENABLE_RINGS`; every other operation gives `EINVAL`.
pub(crate) fn sys_register(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    match register(c, a) {
        Ok(n) => ok(n),
        Err(e) => err(e),
    }
}

fn register(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let opcode = a[1] & 0xffff_ffff;
    let registered = opcode & REGISTER_USE_REGISTERED_RING != 0;
    let opcode = opcode & !REGISTER_USE_REGISTERED_RING;
    if opcode >= REGISTER_LAST {
        return Err(Errno::EINVAL);
    }
    let file = ring_file(c, a[0], registered)?;
    let ring = downcast(&file)?;
    if ring.others(c.tid) {
        return Err(EEXIST);
    }
    if !ring.allows_registration(opcode) {
        return Err(Errno::EACCES);
    }
    let done = run_registration(c, ring, opcode, a);
    // A tag it posted counts for the timeouts (`io_post_aux_cqe`).
    timeout::flush(&c.processes.io_uring, &file, ring, Some(c.inbox));
    done
}

fn run_registration(
    c: &mut Context<'_>,
    ring: &Ring,
    opcode: u64,
    a: [u64; 6],
) -> Result<u64, Errno> {
    match opcode {
        REGISTER_PROBE => probe(c, a),
        register::REGISTER_PERSONALITY | register::REGISTER_ENABLE_RINGS
            if a[2] != 0 || a[3] as u32 != 0 =>
        {
            Err(Errno::EINVAL)
        }
        register::REGISTER_PERSONALITY => register::register_personality(c, ring),
        register::UNREGISTER_PERSONALITY if a[2] != 0 => Err(Errno::EINVAL),
        register::UNREGISTER_PERSONALITY => register::unregister_personality(ring, a[3] as u32),
        register::REGISTER_ENABLE_RINGS => register::enable_rings(c, ring),
        register::REGISTER_RESTRICTIONS => {
            register::register_restrictions(c, ring, a[2], a[3] as u32)
        }
        REGISTER_BUFFERS if a[2] == 0 => Err(Errno::EFAULT),
        REGISTER_BUFFERS => register_buffers(c, ring, a[2], a[3] as u32, 0),
        REGISTER_BUFFERS2 => register_buffers2(c, ring, a[2], a[3] as u32),
        REGISTER_BUFFERS_UPDATE => register_buffers_update(c, ring, a[2], a[3] as u32),
        UNREGISTER_BUFFERS if a[2] != 0 || a[3] as u32 != 0 => Err(Errno::EINVAL),
        UNREGISTER_BUFFERS => {
            let gone = ring
                .buffers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or(ENXIO)?;
            // `io_rsrc_data_free` lets go of the last slot first.
            ring.put_nodes(gone.slots.into_iter().rev().flatten());
            Ok(0)
        }
        REGISTER_FILES if a[2] == 0 => Err(Errno::EFAULT),
        REGISTER_FILES => register_files(c, ring, a[2], a[3] as u32, 0),
        REGISTER_FILES2 => register_files2(c, ring, a[2], a[3] as u32),
        UNREGISTER_FILES if a[2] != 0 || a[3] as u32 != 0 => Err(Errno::EINVAL),
        UNREGISTER_FILES => {
            let gone = ring
                .files
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or(ENXIO)?;
            // `io_rsrc_data_free` lets go of the last slot first.
            ring.put_nodes(gone.slots.into_values().rev());
            Ok(0)
        }
        REGISTER_FILES_UPDATE => register_files_update(c, ring, a[2], a[3] as u32),
        REGISTER_FILES_UPDATE2 => register_files_update2(c, ring, a[2], a[3] as u32),
        REGISTER_FILE_ALLOC_RANGE if a[2] == 0 || a[3] as u32 != 0 => Err(Errno::EINVAL),
        REGISTER_FILE_ALLOC_RANGE => file_alloc_range(c, ring, a[2]),
        REGISTER_PBUF_RING | UNREGISTER_PBUF_RING | REGISTER_PBUF_STATUS
            if a[2] == 0 || a[3] as u32 != 1 =>
        {
            Err(Errno::EINVAL)
        }
        REGISTER_PBUF_RING => register_pbuf_ring(c, ring, a[2]),
        UNREGISTER_PBUF_RING => unregister_pbuf_ring(c, ring, a[2]),
        REGISTER_PBUF_STATUS => pbuf_status(c, ring, a[2]),
        REGISTER_SYNC_CANCEL if a[2] == 0 || a[3] as u32 != 1 => Err(Errno::EINVAL),
        REGISTER_SYNC_CANCEL => sync_cancel(c, ring, a[2]),
        REGISTER_RING_FDS => register_ring_fds(c, a[2], a[3] as u32),
        UNREGISTER_RING_FDS => unregister_ring_fds(c, a[2], a[3] as u32),
        _ => Err(Errno::EINVAL),
    }
}

/// Reads the descriptor number at `addr` (`EFAULT`).
fn read_fd(c: &Context<'_>, addr: u64) -> Result<i32, Errno> {
    let mut fd = [0; 4];
    c.mem
        .read(GuestAddr(addr), &mut fd)
        .map_err(|_| Errno::EFAULT)?;
    Ok(i32::from_le_bytes(fd))
}

/// `IORING_REGISTER_FILES`, as Linux's `io_sqe_files_register` once the
/// dispatcher found an argument (`EFAULT` for none, before all else): none
/// registered yet (`EBUSY`), 1 (`EINVAL`) to `IORING_MAX_FIXED_FILES` and
/// RLIMIT_NOFILE of them (`EMFILE`), then each tag at `tags` if there are
/// tags and each descriptor at `arg` in turn (`EFAULT`): -1, or every one
/// with no `arg`, leaves its slot empty, which a tag may not have
/// (`EINVAL`), and one `fget` does not find, or a ring, is `EBADF`. A
/// failure registers none of them, and posts no tag. The table is the
/// allocation range of `IORING_FILE_INDEX_ALLOC`.
fn register_files(
    c: &mut Context<'_>,
    ring: &Ring,
    arg: u64,
    count: u32,
    tags: u64,
) -> Result<u64, Errno> {
    let mut registered = ring.files.lock().unwrap_or_else(PoisonError::into_inner);
    if registered.is_some() {
        return Err(EBUSY);
    }
    if count == 0 {
        return Err(Errno::EINVAL);
    }
    if count > MAX_FIXED_FILES || u64::from(count) > c.processes.soft_limit(c.process.pid, 7) {
        return Err(Errno::EMFILE);
    }
    let mut files = Files {
        count,
        slots: std::collections::BTreeMap::new(),
        alloc: (0, count),
        hint: 0,
    };
    for index in 0..count {
        let tag = read_tag(c, tags, index)?;
        let fd = if arg == 0 {
            -1
        } else {
            read_fd(c, arg.wrapping_add(4 * u64::from(index)))?
        };
        if fd == -1 {
            if tag != 0 {
                return Err(Errno::EINVAL);
            }
            continue;
        }
        let d = fget(c, fd)?;
        if is_ring(&d) {
            return Err(Errno::EBADF);
        }
        files.slots.insert(
            index,
            Arc::new(Node {
                held: Held::File(d),
                tag,
            }),
        );
    }
    *registered = Some(files);
    Ok(0)
}

/// The tag at index `index` of `tags` (`EFAULT`), or 0 with no tags.
fn read_tag(c: &Context<'_>, tags: u64, index: u32) -> Result<u64, Errno> {
    if tags == 0 {
        return Ok(0);
    }
    let mut tag = [0; 8];
    c.mem
        .read(GuestAddr(tags.wrapping_add(8 * u64::from(index))), &mut tag)
        .map_err(|_| Errno::EFAULT)?;
    Ok(u64::from_le_bytes(tag))
}

/// `IORING_REGISTER_FILES2`, as Linux's `io_register_rsrc`: `size` is
/// that of a `struct io_uring_rsrc_register` (`EINVAL`), which is read
/// (`EFAULT`) and must have a count, no reserved field and no flag but
/// `IORING_RSRC_REGISTER_SPARSE`, which takes no descriptors (`EINVAL`);
/// then as [`register_files`] with its tags.
fn register_files2(c: &mut Context<'_>, ring: &Ring, arg: u64, size: u32) -> Result<u64, Errno> {
    if size != 32 {
        return Err(Errno::EINVAL);
    }
    let mut rr = [0; 32];
    c.mem
        .read(GuestAddr(arg), &mut rr)
        .map_err(|_| Errno::EFAULT)?;
    let (count, flags, data) = (u32_at(&rr, 0), u32_at(&rr, 4), u64_at(&rr, 16));
    if count == 0
        || u64_at(&rr, 8) != 0
        || flags & !RSRC_REGISTER_SPARSE != 0
        || flags & RSRC_REGISTER_SPARSE != 0 && data != 0
    {
        return Err(Errno::EINVAL);
    }
    register_files(c, ring, data, count, u64_at(&rr, 24))
}

/// `IORING_REGISTER_FILES_UPDATE2`, as `io_register_rsrc_update`: `size`
/// is that of a `struct io_uring_rsrc_update2` (`EINVAL`), which is read
/// (`EFAULT`) and must have a count and no reserved field (`EINVAL`); then
/// as [`update_files`] with its tags.
fn register_files_update2(
    c: &mut Context<'_>,
    ring: &Ring,
    arg: u64,
    size: u32,
) -> Result<u64, Errno> {
    if size != 32 {
        return Err(Errno::EINVAL);
    }
    let mut up = [0; 32];
    c.mem
        .read(GuestAddr(arg), &mut up)
        .map_err(|_| Errno::EFAULT)?;
    let count = u32_at(&up, 24);
    if count == 0 || u32_at(&up, 4) != 0 || u32_at(&up, 28) != 0 {
        return Err(Errno::EINVAL);
    }
    update_files(
        c,
        ring,
        u32_at(&up, 0),
        u64_at(&up, 8),
        count,
        u64_at(&up, 16),
    )
}

/// `IORING_REGISTER_FILES_UPDATE`, as `io_register_files_update`: `count`
/// slots (`EINVAL` for none) from a `struct io_uring_rsrc_update`
/// (`EFAULT`) whose reserved field is 0 (`EINVAL`).
fn register_files_update(
    c: &mut Context<'_>,
    ring: &Ring,
    arg: u64,
    count: u32,
) -> Result<u64, Errno> {
    if count == 0 {
        return Err(Errno::EINVAL);
    }
    let mut update = [0; 16];
    c.mem
        .read(GuestAddr(arg), &mut update)
        .map_err(|_| Errno::EFAULT)?;
    if u32_at(&update, 4) != 0 {
        return Err(Errno::EINVAL);
    }
    update_files(c, ring, u32_at(&update, 0), u64_at(&update, 8), count, 0)
}

/// Linux's `__io_sqe_files_update`, after `__io_register_rsrc_update`:
/// slots `offset` on must not wrap (`EOVERFLOW`), files must be registered
/// (`ENXIO`) and the slots within them (`EINVAL`). Each tag at `tags` if
/// there are tags and each descriptor at `fds` in turn (`EFAULT`) then
/// empties its slot and puts its file there with the tag, but
/// `IORING_REGISTER_FILES_SKIP` leaves the slot be and -1 leaves it empty,
/// which a tag may not go with (`EINVAL`); one `fget` does not find, or a
/// ring, is `EBADF` once the slot is empty. The files the slots let go of
/// post their tags ([`Ring::put_nodes`]). It gives how many it went
/// through, or the error if none.
fn update_files(
    c: &mut Context<'_>,
    ring: &Ring,
    offset: u32,
    fds: u64,
    count: u32,
    tags: u64,
) -> Result<u64, Errno> {
    let end = offset.checked_add(count).ok_or(EOVERFLOW)?;
    let mut gone = Vec::new();
    let mut registered = ring.files.lock().unwrap_or_else(PoisonError::into_inner);
    let files = registered.as_mut().ok_or(ENXIO)?;
    if end > files.count {
        return Err(Errno::EINVAL);
    }
    let mut done = 0;
    let mut error = Errno::EINVAL;
    while done < count {
        let read = read_tag(c, tags, done)
            .and_then(|tag| Ok((tag, read_fd(c, fds.wrapping_add(4 * u64::from(done)))?)));
        let (tag, fd) = match read {
            Ok((tag, fd)) if tag != 0 && (fd == FILES_SKIP || fd == -1) => {
                error = Errno::EINVAL;
                break;
            }
            Ok(read) => read,
            Err(e) => {
                error = e;
                break;
            }
        };
        if fd != FILES_SKIP {
            let slot = offset + done;
            gone.extend(files.clear(slot));
            if fd != -1 {
                match fget(c, fd) {
                    Ok(d) if !is_ring(&d) => files.set(slot, d, tag),
                    Ok(_) => {
                        error = Errno::EBADF;
                        break;
                    }
                    Err(e) => {
                        error = e;
                        break;
                    }
                }
            }
        }
        done += 1;
    }
    drop(registered);
    ring.put_nodes(gone);
    if done > 0 {
        Ok(u64::from(done))
    } else {
        Err(error)
    }
}

/// `IORING_OP_FILES_UPDATE` with `IORING_FILE_INDEX_ALLOC`, as
/// `io_files_update_with_index_alloc`: files must be registered (`ENXIO`);
/// each descriptor at `fds` in turn (`EFAULT`) that `fget` finds (`EBADF`)
/// goes in a free slot ([`Files::free`], `ENFILE`) unless it is a ring
/// (`EBADF`), and the slot's index is written over it (`EFAULT`, which
/// empties the slot again). It gives how many went in, or the error if
/// none.
fn update_files_anywhere(
    c: &mut Context<'_>,
    ring: &Ring,
    fds: u64,
    count: u32,
) -> Result<u64, Errno> {
    let mut gone = Vec::new();
    let mut registered = ring.files.lock().unwrap_or_else(PoisonError::into_inner);
    let files = registered.as_mut().ok_or(ENXIO)?;
    let mut done = 0;
    let mut error = Errno::EINVAL;
    while done < count {
        let at = fds.wrapping_add(4 * u64::from(done));
        let installed = read_fd(c, at).and_then(|fd| {
            let d = fget(c, fd)?;
            let slot = files.free()?;
            if is_ring(&d) {
                return Err(Errno::EBADF);
            }
            files.set(slot, d, 0);
            if c.mem.write(GuestAddr(at), &slot.to_le_bytes()).is_err() {
                gone.extend(files.clear(slot));
                return Err(Errno::EFAULT);
            }
            Ok(())
        });
        if let Err(e) = installed {
            error = e;
            break;
        }
        done += 1;
    }
    drop(registered);
    ring.put_nodes(gone);
    if done > 0 {
        Ok(u64::from(done))
    } else {
        Err(error)
    }
}

/// `IORING_REGISTER_FILE_ALLOC_RANGE`, as `io_register_file_alloc_range`
/// once the dispatcher found an argument and no count (`EINVAL`): a
/// `struct io_uring_file_index_range` (`EFAULT`) whose end does not wrap
/// (`EOVERFLOW`), with its reserved field 0 and its end within the
/// registered files (`EINVAL`), is where `IORING_FILE_INDEX_ALLOC` looks
/// from now on.
fn file_alloc_range(c: &mut Context<'_>, ring: &Ring, arg: u64) -> Result<u64, Errno> {
    let mut range = [0; 16];
    c.mem
        .read(GuestAddr(arg), &mut range)
        .map_err(|_| Errno::EFAULT)?;
    let (off, len) = (u32_at(&range, 0), u32_at(&range, 4));
    let end = off.checked_add(len).ok_or(EOVERFLOW)?;
    let mut registered = ring.files.lock().unwrap_or_else(PoisonError::into_inner);
    let count = registered.as_ref().map_or(0, |files| files.count);
    if u64_at(&range, 8) != 0 || end > count {
        return Err(Errno::EINVAL);
    }
    if let Some(files) = registered.as_mut() {
        files.alloc = (off, end);
        files.hint = off;
    }
    Ok(0)
}

/// The `iovec` at `at` (`EFAULT`), as `iovec_from_user` takes one: a
/// negative length is `EINVAL`.
fn read_iovec(c: &Context<'_>, at: u64) -> Result<(u64, u64), Errno> {
    let mut iovec = [0; 16];
    c.mem
        .read(GuestAddr(at), &mut iovec)
        .map_err(|_| Errno::EFAULT)?;
    let (base, len) = (u64_at(&iovec, 0), u64_at(&iovec, 8));
    if (len as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok((base, len))
}

/// A buffer as `io_sqe_buffer_register` registers one, tagged `tag`:
///
/// - A null address with no length is an empty slot, which a tag may not
///   have (`EINVAL`); one with a length is `EFAULT`.
/// - No length or more than 1 GiB is `EFAULT`, and an end past the address
///   space `EOVERFLOW` (`io_validate_user_buf_range`).
/// - Its pages are pinned for writing (`io_pin_pages`). The long-term pin
///   refuses (`EFAULT`) a page not mapped or not writable, and a shared
///   mapping of a disk file, of a `memfd_secret` or of a perf event's ring.
/// - They charge the ring's user, within RLIMIT_MEMLOCK (`ENOMEM`), unless
///   the ring's maker had `CAP_IPC_LOCK` (`io_buffer_account_pin`).
fn buffer_node(
    c: &Context<'_>,
    ring: &Ring,
    (base, len): (u64, u64),
    tag: u64,
) -> Result<Option<Arc<Node>>, Errno> {
    if base == 0 {
        if len != 0 {
            return Err(Errno::EFAULT);
        }
        return if tag == 0 {
            Ok(None)
        } else {
            Err(Errno::EINVAL)
        };
    }
    if len > MAX_BUFFER || len == 0 {
        return Err(Errno::EFAULT);
    }
    // The end, page-aligned, must not wrap, as `io_pin_pages` checks
    // again for the end of the last page.
    if base.checked_add(len.next_multiple_of(4096)).is_none()
        || base.checked_add(len + 4095).is_none()
    {
        return Err(EOVERFLOW);
    }
    let pinned = c.mem.pin(GuestAddr(base), len as usize).map_err(|e| {
        if e == EOVERFLOW {
            EOVERFLOW
        } else {
            Errno::EFAULT
        }
    })?;
    let count = (base % 4096 + len).div_ceil(4096);
    let limit = c.processes.soft_limit(c.process.pid, 8) >> 12;
    if let Some((charged, user)) = &ring.charged
        && !charged.charge(*user, count, limit)
    {
        return Err(Errno::ENOMEM);
    }
    Ok(Some(Arc::new(Node {
        held: Held::Buffer(RegisteredBuffer {
            base,
            len,
            pages: Arc::new(pinned),
            charged: ring.charged.clone(),
            count,
        }),
        tag,
    })))
}

/// `IORING_REGISTER_BUFFERS`, and `_BUFFERS2` with `tags`, as Linux 7.0's
/// `io_sqe_buffers_register`: none registered yet (`EBUSY`), 1 to
/// `IORING_MAX_REG_BUFFERS` of them (`EINVAL`), then each `iovec` in turn
/// ([`read_iovec`]; with no `iovec`s, as `_BUFFERS2` may ask, every slot
/// empty), its tag (`EFAULT`), and the buffer ([`buffer_node`]). A
/// failure registers none of them, and posts no tag.
fn register_buffers(
    c: &mut Context<'_>,
    ring: &Ring,
    arg: u64,
    count: u32,
    tags: u64,
) -> Result<u64, Errno> {
    let mut registered = ring.buffers.lock().unwrap_or_else(PoisonError::into_inner);
    if registered.is_some() {
        return Err(EBUSY);
    }
    if count == 0 || u64::from(count) > MAX_REG_BUFFERS {
        return Err(Errno::EINVAL);
    }
    let mut buffers = Buffers {
        slots: Vec::with_capacity(count as usize),
    };
    for index in 0..count {
        let iovec = if arg == 0 {
            (0, 0)
        } else {
            read_iovec(c, arg + 16 * u64::from(index))?
        };
        let tag = read_tag(c, tags, index)?;
        buffers.slots.push(buffer_node(c, ring, iovec, tag)?);
    }
    *registered = Some(buffers);
    Ok(0)
}

/// `IORING_REGISTER_BUFFERS2`, as Linux's `io_register_rsrc`: `size` is
/// that of a `struct io_uring_rsrc_register` (`EINVAL`), which is read
/// (`EFAULT`) and must have a count, no reserved field and no flag but
/// `IORING_RSRC_REGISTER_SPARSE`, which takes no `iovec`s (`EINVAL`); then
/// as [`register_buffers`] with its tags.
fn register_buffers2(c: &mut Context<'_>, ring: &Ring, arg: u64, size: u32) -> Result<u64, Errno> {
    if size != 32 {
        return Err(Errno::EINVAL);
    }
    let mut rr = [0; 32];
    c.mem
        .read(GuestAddr(arg), &mut rr)
        .map_err(|_| Errno::EFAULT)?;
    let (count, flags, data) = (u32_at(&rr, 0), u32_at(&rr, 4), u64_at(&rr, 16));
    if count == 0
        || u64_at(&rr, 8) != 0
        || flags & !RSRC_REGISTER_SPARSE != 0
        || flags & RSRC_REGISTER_SPARSE != 0 && data != 0
    {
        return Err(Errno::EINVAL);
    }
    register_buffers(c, ring, data, count, u64_at(&rr, 24))
}

/// `IORING_REGISTER_BUFFERS_UPDATE`, as Linux 7.0's
/// `io_register_rsrc_update` and `__io_sqe_buffers_update`: `size` is that
/// of a `struct io_uring_rsrc_update2` (`EINVAL`), which is read (`EFAULT`)
/// and must have a count and no reserved field (`EINVAL`; Linux master
/// takes `IORING_RSRC_UPDATE_EXTENDED` there); an offset and count that
/// wrap are `EOVERFLOW`, no buffers `ENXIO`, and slots past the last
/// `EINVAL`. Then each slot in turn: its `iovec`, its tag (both `EFAULT`;
/// master reads the tag first) and the buffer ([`buffer_node`]), an empty
/// `iovec` emptying it. What the slot held goes, and its tag posts once
/// nothing holds it ([`Ring::put_nodes`]). It gives how many it updated,
/// or the error of the first if none.
fn register_buffers_update(
    c: &mut Context<'_>,
    ring: &Ring,
    arg: u64,
    size: u32,
) -> Result<u64, Errno> {
    if size != 32 {
        return Err(Errno::EINVAL);
    }
    let mut up = [0; 32];
    c.mem
        .read(GuestAddr(arg), &mut up)
        .map_err(|_| Errno::EFAULT)?;
    let (offset, data, tags, count) = (
        u32_at(&up, 0),
        u64_at(&up, 8),
        u64_at(&up, 16),
        u32_at(&up, 24),
    );
    if count == 0 || u32_at(&up, 4) != 0 || u32_at(&up, 28) != 0 {
        return Err(Errno::EINVAL);
    }
    offset.checked_add(count).ok_or(EOVERFLOW)?;
    let mut registered = ring.buffers.lock().unwrap_or_else(PoisonError::into_inner);
    let buffers = registered.as_mut().ok_or(ENXIO)?;
    if (offset + count) as usize > buffers.slots.len() {
        return Err(Errno::EINVAL);
    }
    let mut done = 0;
    let mut gone = Vec::new();
    let failed = (|| -> Result<(), Errno> {
        while done < count {
            let iovec = read_iovec(c, data + 16 * u64::from(done))?;
            let tag = read_tag(c, tags, done)?;
            let node = buffer_node(c, ring, iovec, tag)?;
            let slot = &mut buffers.slots[(offset + done) as usize];
            gone.extend(std::mem::replace(slot, node));
            done += 1;
        }
        Ok(())
    })();
    drop(registered);
    ring.put_nodes(gone);
    match failed {
        Err(e) if done == 0 => Err(e),
        _ => Ok(u64::from(done)),
    }
}

/// `IORING_REGISTER_PBUF_RING`, as Linux's `io_register_pbuf_ring` reads
/// `struct io_uring_buf_reg` (`EFAULT`): reserved bytes set, an unknown
/// flag, or a count of entries not a power of two below 65536, is
/// `EINVAL`; a group of buffers, or a ring, there already is `EEXIST`,
/// though an empty group goes. Then its pages, as `io_create_region` makes
/// them: without `IOU_PBUF_RING_MMAP` the ring is at `ring_addr`, which
/// must be set (`EFAULT`), on a page (`EINVAL`), not wrap (`EOVERFLOW`) and
/// be writable (`EFAULT`, `io_pin_pages`); with it, the address is not
/// looked at and the kernel gives zeroed pages. They charge the ring's
/// user, as registered buffers do (`ENOMEM`).
fn register_pbuf_ring(c: &mut Context<'_>, ring: &Ring, arg: u64) -> Result<u64, Errno> {
    let mut reg = [0; 40];
    c.mem
        .read(GuestAddr(arg), &mut reg)
        .map_err(|_| Errno::EFAULT)?;
    let ring_addr = u64_at(&reg, 0);
    let entries = u32_at(&reg, 8);
    let bgid = u16::from_le_bytes([reg[12], reg[13]]);
    let flags = u16::from_le_bytes([reg[14], reg[15]]);
    if reg[16..].iter().any(|&b| b != 0)
        || flags & !(PBUF_RING_MMAP | PBUF_RING_INC) != 0
        || !entries.is_power_of_two()
        || entries >= 65536
    {
        return Err(Errno::EINVAL);
    }
    let mut lists = ring
        .buffer_lists
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match lists.get(&bgid) {
        Some(BufferList::Provided(list)) if list.is_empty() => {
            lists.remove(&bgid);
        }
        Some(_) => return Err(EEXIST),
        None => {}
    }
    let size = (16 * u64::from(entries)).next_multiple_of(4096);
    let user_addr = if flags & PBUF_RING_MMAP == 0 {
        if ring_addr == 0 {
            return Err(Errno::EFAULT);
        }
        ring_addr
    } else {
        0
    };
    if user_addr % 4096 != 0 {
        return Err(Errno::EINVAL);
    }
    if user_addr.checked_add(size).is_none() {
        return Err(EOVERFLOW);
    }
    let pages = size / 4096;
    let limit = c.processes.soft_limit(c.process.pid, 8) >> 12;
    if let Some((charged, user)) = &ring.charged
        && !charged.charge(*user, pages, limit)
    {
        return Err(Errno::ENOMEM);
    }
    let mut buffers = BufferRing {
        memory: RingMemory::User(user_addr),
        mask: (entries - 1) as u16,
        head: 0,
        incremental: flags & PBUF_RING_INC != 0,
        charged: ring.charged.clone(),
        pages,
    };
    if user_addr != 0 {
        c.mem
            .check_write(GuestAddr(user_addr), size as usize)
            .map_err(|_| Errno::EFAULT)?;
    } else {
        buffers.memory = RingMemory::Kernel(ring_pages(c, size)?, size);
    }
    lists.insert(bgid, BufferList::Ring(buffers));
    Ok(0)
}

/// `IORING_UNREGISTER_PBUF_RING`, as Linux's `io_unregister_pbuf_ring`
/// reads `struct io_uring_buf_reg` (`EFAULT`): reserved bytes or flags set
/// are `EINVAL`, no group `ENOENT`, and provided buffers `EINVAL`.
fn unregister_pbuf_ring(c: &mut Context<'_>, ring: &Ring, arg: u64) -> Result<u64, Errno> {
    let mut reg = [0; 40];
    c.mem
        .read(GuestAddr(arg), &mut reg)
        .map_err(|_| Errno::EFAULT)?;
    if reg[14..].iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let bgid = u16::from_le_bytes([reg[12], reg[13]]);
    let gone = {
        let mut lists = ring
            .buffer_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match lists.get(&bgid) {
            None => return Err(Errno::ENOENT),
            Some(BufferList::Provided(_)) => return Err(Errno::EINVAL),
            Some(BufferList::Ring(_)) => lists.remove(&bgid),
        }
    };
    drop(gone);
    Ok(0)
}

/// `IORING_REGISTER_PBUF_STATUS`, as Linux's `io_register_pbuf_status`:
/// `struct io_uring_buf_status` is read (`EFAULT`), reserved bytes set are
/// `EINVAL`, no group `ENOENT`, provided buffers `EINVAL`; then the ring's
/// head is written in it (`EFAULT`).
fn pbuf_status(c: &mut Context<'_>, ring: &Ring, arg: u64) -> Result<u64, Errno> {
    let mut status = [0; 40];
    c.mem
        .read(GuestAddr(arg), &mut status)
        .map_err(|_| Errno::EFAULT)?;
    if status[8..].iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let head = {
        let lists = ring
            .buffer_lists
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match u16::try_from(u32_at(&status, 0))
            .ok()
            .and_then(|bgid| lists.get(&bgid))
        {
            None => return Err(Errno::ENOENT),
            Some(BufferList::Provided(_)) => return Err(Errno::EINVAL),
            Some(BufferList::Ring(buffers)) => buffers.head,
        }
    };
    status[4..8].copy_from_slice(&u32::from(head).to_le_bytes());
    c.mem
        .write(GuestAddr(arg), &status)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

impl Ring {
    /// Whether registered buffer `index` is there (`io_find_buf_node`).
    fn has_buffer(&self, index: u16) -> bool {
        self.buffer_node(index).is_some()
    }

    /// The buffer of slot `index`, which the running request holds from
    /// now on (`io_find_buf_node`, `io_req_assign_buf_node`).
    fn buffer_node(&self, index: u16) -> Option<Arc<Node>> {
        let node = self
            .buffers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|buffers| buffers.slots.get(usize::from(index)).cloned().flatten())?;
        let mut state = self.state();
        if state.deferred.is_some() {
            state.held.push(Arc::clone(&node));
        }
        Some(node)
    }
}

/// The `len` bytes at `addr` of the registered buffer `node`, as
/// `io_import_reg_buf` finds them: a range that wraps or leaves the buffer,
/// or more than `MAX_RW_COUNT`, is `EFAULT` (`validate_fixed_range`).
fn within(node: &Node, addr: u64, len: u32) -> Result<Registered, Errno> {
    let buffer = node.buffer().ok_or(Errno::EFAULT)?;
    let (base, size, pages) = (buffer.base, buffer.len, Arc::clone(&buffer.pages));
    let end = addr.checked_add(u64::from(len)).ok_or(Errno::EFAULT)?;
    if addr < base || end > base + size || len as usize > crate::files::MAX_RW_COUNT {
        return Err(Errno::EFAULT);
    }
    Ok(Registered {
        pages,
        pieces: vec![(addr - base, len as usize)],
    })
}

/// The pieces of the registered buffer `node` that a vector's entries name,
/// in order, as `io_import_reg_vec` finds them. Before any entry is looked
/// at, room is made for the pieces of pages they may take (`page_pieces`,
/// 16 bytes each): more than `INT_MAX` of them are `EOVERFLOW`, and more
/// than `kmalloc` gives at once `ENOMEM`. Then each entry is found as
/// [`within`] finds one, but one of no bytes is `EFAULT` too, and more than
/// `MAX_RW_COUNT` in all is `EINVAL`.
fn within_vector(
    node: &Node,
    entries: &[(u64, usize)],
    page_pieces: u64,
) -> Result<Registered, Errno> {
    if page_pieces > i32::MAX as u64 {
        return Err(EOVERFLOW);
    }
    if page_pieces * 16 > MAX_KMALLOC {
        return Err(Errno::ENOMEM);
    }
    let mut pieces = Vec::with_capacity(entries.len());
    let mut pages = None;
    for &(addr, len) in entries {
        let len = u32::try_from(len).map_err(|_| Errno::EFAULT)?;
        let mut piece = within(node, addr, len)?;
        if len == 0 {
            return Err(Errno::EFAULT);
        }
        pieces.append(&mut piece.pieces);
        pages = Some(piece.pages);
    }
    if pieces.iter().map(|&(_, len)| len as u64).sum::<u64>() > crate::files::MAX_RW_COUNT as u64 {
        return Err(Errno::EINVAL);
    }
    let pages = match pages {
        Some(pages) => pages,
        None => Arc::clone(&node.buffer().ok_or(Errno::EFAULT)?.pages),
    };
    Ok(Registered { pages, pieces })
}

/// `io_epoll_wait`: the file (`EBADF`), then the events as
/// [`crate::epoll::send_events`] takes them; with none ready it waits for
/// the epoll to be readable (`pollin`) and looks again. A negative result
/// fails its link.
fn epoll_wait(
    c: &mut Context<'_>,
    ring: &Ring,
    (fd, fixed, found): (i32, bool, &Option<crate::files::Descriptor>),
    at: u64,
    max: i32,
) -> (i32, u32, bool, Option<Waits>) {
    let opened = match found {
        Some(opened) => opened.clone(),
        None => match file_of(c, ring, fd, fixed) {
            Ok(opened) => opened,
            Err(e) => return (-e.0, 0, true, None),
        },
    };
    match crate::epoll::send_events(c, &opened.file, at, max) {
        Ok(Some(count)) => (count as i32, 0, false, None),
        Err(e) => (-e.0, 0, true, None),
        Ok(None) => (
            0,
            0,
            false,
            Some(Waits {
                file: Arc::clone(&opened.file),
                mask: POLL_UNMASK | POLL_IN_EVENTS,
                kept: None,
                found: (opened, None),
            }),
        ),
    }
}

/// `IORING_REGISTER_PROBE`: what each operation is, and whether it runs.
fn probe(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    // struct io_uring_probe: last_op, ops_len, then 14 reserved bytes, then
    // an io_uring_probe_op of 8 bytes for each operation.
    let count = (a[3] as u32).min(u32::from(OP_LAST));
    let size = 16 + 8 * count as usize;
    let mut probe = vec![0; size];
    c.mem
        .read(GuestAddr(a[2]), &mut probe)
        .map_err(|_| Errno::EFAULT)?;
    if probe.iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    probe[0] = OP_LAST - 1;
    probe[1] = count as u8;
    for op in 0..count as usize {
        probe[16 + 8 * op] = op as u8;
        if supported(op as u8) {
            probe[16 + 8 * op + 2..16 + 8 * op + 4].copy_from_slice(&OP_SUPPORTED.to_le_bytes());
        }
    }
    c.mem
        .write(GuestAddr(a[2]), &probe)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// What a mapping of a ring descriptor shows: the pages of a region, and
/// the length it must hold, if it must hold them all.
pub(crate) struct Region {
    pages: SharedPages,
    whole: Option<u64>,
}

/// What `mmap` of a ring descriptor shows (`None` for another file), as
/// Linux's `io_uring_get_unmapped_area` looks before the mapping is placed:
/// no address may be asked for (`EINVAL`), and the offset's region picks
/// the rings, the entries, or the ring of buffers of a group
/// (`IORING_OFF_PBUF_RING`, the group's ID from bit 16 of the offset)
/// whose pages the kernel gave (another gives `ENOMEM`).
pub(crate) fn region(
    file: &dyn FileHandle,
    addr: u64,
    offset: u64,
) -> Option<Result<Region, Errno>> {
    let ring = file.as_any()?.downcast_ref::<Ring>()?;
    if addr != 0 {
        return Some(Err(Errno::EINVAL));
    }
    let (pages, whole) = match offset & OFF_MMAP_MASK {
        0 | OFF_CQ_RING => (ring.rings.clone(), None),
        OFF_SQES => (ring.sqes.clone(), Some(ring.sqes_len)),
        OFF_PBUF_RING => {
            // The ID is an `unsigned int` there.
            let id = ((offset & !OFF_MMAP_MASK) >> OFF_PBUF_SHIFT) as u32;
            let lists = ring
                .buffer_lists
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match u16::try_from(id).ok().and_then(|bgid| lists.get(&bgid)) {
                Some(BufferList::Ring(BufferRing {
                    memory: RingMemory::Kernel(pages, size),
                    ..
                })) => (pages.clone(), Some(*size)),
                _ => return Some(Err(Errno::ENOMEM)),
            }
        }
        _ => return Some(Err(Errno::ENOMEM)),
    };
    Some(Ok(Region { pages, whole }))
}

/// `mmap` of a ring descriptor's `region`, as Linux's `io_uring_mmap`: the
/// mapping shows from the start of the region however far into it the
/// offset is. A mapping of the rings shows what fits, and past the rings a
/// page raises `SIGBUS`; one of the entries or of a ring of buffers must
/// hold them all (`EFAULT`).
/// Only a shared mapping is implemented: a private one gives `EINVAL`.
pub(crate) fn mmap(
    c: &mut Context<'_>,
    region: &Region,
    placement: paludarium_mmu::Placement,
    len: u64,
    prot: paludarium_mmu::Prot,
    shared: bool,
) -> Result<u64, Errno> {
    if !shared {
        return Err(Errno::EINVAL);
    }
    let len = len.checked_next_multiple_of(4096).ok_or(Errno::ENOMEM)?;
    if region
        .whole
        .is_some_and(|size| len < size.next_multiple_of(4096))
    {
        return Err(Errno::EFAULT);
    }
    let at = c.mem.map_backed(
        placement,
        len,
        prot,
        paludarium_mmu::MappingKind::File,
        paludarium_mmu::Backing::Shared {
            pages: &region.pages,
            offset: 0,
            writes: paludarium_mmu::SharedWrites::Allowed,
        },
    )?;
    c.group.numa().forget(at.0, len);
    Ok(at.0)
}

impl FileHandle for Ring {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// A ring wakes its waiters only as completions go in, for input
    /// (`io_commit_cqring_flush` waking `ctx->poll_wq` with `EPOLLIN`).
    fn keyed_wakeups(&self) -> bool {
        true
    }
    /// `io_uring_poll`: writable while the submission queue has room,
    /// readable while completions wait in the queue or the kernel, or an
    /// `IORING_SETUP_DEFER_TASKRUN` ring has task work. Only a completion
    /// wakes a poll ([`Ring::posted`], with `EPOLLIN`), so the output
    /// generation never moves.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let mut mask = 0;
        if self.load_u32(SQ_TAIL).wrapping_sub(self.load_u32(SQ_HEAD)) != self.sq_entries {
            mask |= crate::events::OUT | POLL_WRNORM;
        }
        if self.completions() != 0 || !self.state().overflow.is_empty() || local_pending(self) {
            mask |= crate::events::IN | POLL_RDNORM;
        }
        Ok((
            mask,
            self.posted.load(std::sync::atomic::Ordering::SeqCst),
            1,
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
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.status.of(2)
    }
    /// `F_SETFL`, as Linux's `setfl`.
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.set(flags);
        Ok(())
    }
}
