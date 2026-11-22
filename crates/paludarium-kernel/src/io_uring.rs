//! io_uring, as Linux 6.12's (`io_uring/`) with these operations:
//! `IORING_OP_NOP`, `IORING_OP_EPOLL_CTL` (the one libuv batches its
//! `epoll_ctl` calls with), and the file transfers `IORING_OP_READ`,
//! `_WRITE`, `_READV`, `_WRITEV` and `_FSYNC`. The others answer
//! `EOPNOTSUPP`, as on a Linux built without them, and
//! `IORING_REGISTER_PROBE` says so. `IORING_REGISTER_BUFFERS` registers
//! the buffers `IORING_OP_READ_FIXED` and `_WRITE_FIXED` transfer with.
//!
//! The rings are pages the kernel shares with the mappings of the ring's
//! descriptor ([`SharedPages`]). A request runs when `io_uring_enter` takes
//! it from the submission queue, and its completion is in the completion
//! queue before the call returns, so no request is ever in flight: a wait for
//! more completions than there are ends only by a signal or a timeout. The
//! setup flags that need a kernel thread, polled I/O or another layout of the
//! rings give `EINVAL`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{PageSource, SharedPages};
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome, err, ok};

/// The most submission queue entries, and completion queue entries.
const MAX_ENTRIES: u32 = 32768;
const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

const SETUP_CQSIZE: u32 = 1 << 3;
const SETUP_CLAMP: u32 = 1 << 4;
const SETUP_SUBMIT_ALL: u32 = 1 << 7;
const SETUP_COOP_TASKRUN: u32 = 1 << 8;
const SETUP_TASKRUN_FLAG: u32 = 1 << 9;
const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const SETUP_NO_SQARRAY: u32 = 1 << 16;
/// Every flag Linux 6.12 knows: `IORING_SETUP_IOPOLL` to `_NO_SQARRAY`.
const SETUP_KNOWN: u32 = (1 << 17) - 1;
/// The flags implemented. `IOPOLL`, `SQPOLL`, `SQ_AFF`, `ATTACH_WQ`,
/// `R_DISABLED`, `SQE128`, `CQE32`, `NO_MMAP` and `REGISTERED_FD_ONLY` are
/// not.
const SETUP_IMPLEMENTED: u32 = SETUP_CQSIZE
    | SETUP_CLAMP
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
/// `IORING_ENTER_GETEVENTS` to `_ABS_TIMER`.
const ENTER_KNOWN: u32 = (1 << 6) - 1;
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
const OP_READ: u8 = 22;
const OP_WRITE: u8 = 23;
const OP_EPOLL_CTL: u8 = 29;
/// The operations implemented.
const OPS: [u8; 9] = [
    OP_NOP,
    OP_READV,
    OP_WRITEV,
    OP_FSYNC,
    OP_READ_FIXED,
    OP_WRITE_FIXED,
    OP_READ,
    OP_WRITE,
    OP_EPOLL_CTL,
];
/// `IORING_OP_LAST` of Linux 6.12, after `IORING_OP_LISTEN`.
const OP_LAST: u8 = 58;

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
const REGISTER_PROBE: u64 = 8;
/// `IORING_MAX_REG_BUFFERS`.
const MAX_REG_BUFFERS: u64 = 1 << 14;
/// The largest buffer one may register (`io_validate_user_buf_range`).
const MAX_BUFFER: u64 = 1 << 30;
/// `CAP_IPC_LOCK`, which spares a ring's buffers from RLIMIT_MEMLOCK.
const CAP_IPC_LOCK: u64 = 1 << 14;
/// `IORING_REGISTER_LAST` of Linux 6.12, after `_CLONE_BUFFERS`.
const REGISTER_LAST: u64 = 31;
const REGISTER_USE_REGISTERED_RING: u64 = 1 << 31;
/// `IO_URING_OP_SUPPORTED`.
const OP_SUPPORTED: u16 = 1;

const ETIME: Errno = Errno(62);
const ECANCELED: Errno = Errno(125);
const EOPNOTSUPP: Errno = Errno(95);
const EEXIST: Errno = Errno(17);
const ENOBUFS: Errno = Errno(105);
const ENXIO: Errno = Errno(6);
const EBUSY: Errno = Errno(16);
const EOVERFLOW: Errno = Errno(75);

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
    /// The thread that made it, with `IORING_SETUP_SINGLE_ISSUER`: the only
    /// one that may submit and register, and wait with
    /// `IORING_SETUP_DEFER_TASKRUN`.
    submitter: Option<u32>,
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
}

/// A ring's registered buffers: each slot's address and length, or none
/// for a slot registered empty, and the pages they charge, which they give
/// back as they go.
struct Buffers {
    slots: Vec<Option<(u64, u64)>>,
    charged: Option<(Arc<crate::memfd::SecretPages>, u32)>,
    pages: u64,
}

impl Drop for Buffers {
    fn drop(&mut self) {
        if let Some((pages, user)) = &self.charged {
            pages.release(*user, self.pages);
        }
    }
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
    overflow: VecDeque<(u64, i32)>,
    /// A request asked to skip its completion: `IOSQE_IO_DRAIN` is
    /// `EOPNOTSUPP` from then on.
    drain_disabled: bool,
}

/// A request taken from the submission queue and prepared.
struct Request {
    user_data: u64,
    flags: u8,
    /// What it fails with if its preparation failed.
    failed: Option<Errno>,
    work: Work,
}

enum Work {
    Nop(i32),
    EpollCtl {
        epfd: i32,
        op: i32,
        fd: i32,
        event: (u32, u64),
    },
    Transfer(Box<Transfer>),
    Fsync {
        fd: i32,
        fixed: bool,
    },
    None,
}

/// An `IORING_OP_READ`, `_WRITE`, `_READV` or `_WRITEV`: the entry's
/// fields, then what its preparation found.
struct Transfer {
    fd: i32,
    /// `IOSQE_FIXED_FILE`: `fd` indexes the registered files, of which
    /// there are none.
    fixed: bool,
    write: bool,
    vectored: bool,
    /// `IORING_OP_READ_FIXED` or `_WRITE_FIXED`: the buffer is within the
    /// registered one of index `buf_index`.
    registered: bool,
    buf_index: u16,
    /// `IOSQE_BUFFER_SELECT`: a provided buffer, of which there are none.
    select: bool,
    offset: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    ioprio: u16,
    attr_ptr: u64,
    attr_type_mask: u64,
    /// The buffers, as `io_import_rw_buffer` imported them.
    segments: Vec<(u64, usize)>,
    /// Protection information came with it (`REQ_F_HAS_METADATA`), which
    /// no file here takes.
    metadata: bool,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
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

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts a completion in the queue, or keeps it while the queue is full
    /// or completions wait already, which keeps them in order.
    fn post(&self, state: &mut State, user_data: u64, res: i32) {
        state.overflow.push_back((user_data, res));
        self.flush(state);
    }

    /// Moves the completions waiting in the kernel into the room the
    /// program made, and says whether any still wait in `sq_flags`.
    fn flush(&self, state: &mut State) {
        let head = self.load_u32(CQ_HEAD);
        let mut moved = false;
        while state.cq_tail.wrapping_sub(head) < self.cq_entries
            && let Some((user_data, res)) = state.overflow.pop_front()
        {
            let slot = u64::from(state.cq_tail & (self.cq_entries - 1));
            let mut cqe = [0; CQE_BYTES as usize];
            cqe[..8].copy_from_slice(&user_data.to_le_bytes());
            cqe[8..12].copy_from_slice(&res.to_le_bytes());
            self.rings.store(CQES + slot * CQE_BYTES, &cqe);
            state.cq_tail = state.cq_tail.wrapping_add(1);
            moved = true;
        }
        if moved {
            self.store_u32(CQ_TAIL, state.cq_tail);
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
            flags,
            failed: None,
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
            // Only the reads select a buffer (`buffer_select`).
            if flags & IOSQE_BUFFER_SELECT != 0 && !matches!(opcode, OP_READ | OP_READV) {
                return fail(request, EOPNOTSUPP);
            }
            if flags & IOSQE_CQE_SKIP_SUCCESS != 0 {
                state.drain_disabled = true;
            }
            if flags & IOSQE_IO_DRAIN != 0 && state.drain_disabled {
                return fail(request, EOPNOTSUPP);
            }
        }
        let transfer = matches!(
            opcode,
            OP_READ | OP_WRITE | OP_READV | OP_WRITEV | OP_READ_FIXED | OP_WRITE_FIXED
        );
        // Only the transfers take a priority (`ioprio`).
        if OPS.contains(&opcode) && !transfer && u16::from_le_bytes([sqe[2], sqe[3]]) != 0 {
            return fail(request, Errno::EINVAL);
        }
        // No personality is ever registered.
        if u16::from_le_bytes([sqe[42], sqe[43]]) != 0 {
            return fail(request, Errno::EINVAL);
        }
        let int_at = |at: usize| u32_at(sqe, at) as i32;
        let fixed = flags & IOSQE_FIXED_FILE != 0;
        request.work = match opcode {
            _ if transfer => Work::Transfer(Box::new(Transfer {
                fd: int_at(4),
                fixed,
                write: matches!(opcode, OP_WRITE | OP_WRITEV | OP_WRITE_FIXED),
                vectored: matches!(opcode, OP_READV | OP_WRITEV),
                registered: matches!(opcode, OP_READ_FIXED | OP_WRITE_FIXED),
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
                metadata: false,
            })),
            OP_FSYNC => {
                // `io_fsync_prep`.
                if u64_at(sqe, 16) != 0
                    || u16::from_le_bytes([sqe[40], sqe[41]]) != 0
                    || int_at(44) != 0
                    || u32_at(sqe, 28) & !FSYNC_DATASYNC != 0
                {
                    return fail(request, Errno::EINVAL);
                }
                Work::Fsync {
                    fd: int_at(4),
                    fixed,
                }
            }
            OP_NOP => {
                let nop_flags = u32_at(sqe, 28);
                if nop_flags & !NOP_INJECT_RESULT != 0 {
                    return fail(request, Errno::EINVAL);
                }
                Work::Nop(if nop_flags & NOP_INJECT_RESULT != 0 {
                    int_at(24)
                } else {
                    0
                })
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
            _ => return fail(request, EOPNOTSUPP),
        };
        request
    }
}

/// The rest of a request's `prep`, which reads the caller's memory: the
/// event of an `IORING_OP_EPOLL_CTL` that has one (`EFAULT`), and a
/// transfer's priority, attributes and buffers ([`prepare_transfer`]). Its
/// error fails the request.
fn prepare_memory(c: &Context<'_>, request: &mut Request, addr: u64) {
    let result = match &mut request.work {
        Work::EpollCtl { op, event, .. } if *op != 2 => {
            let mut bytes = [0; 12];
            c.mem
                .read(GuestAddr(addr), &mut bytes)
                .map(|()| *event = crate::epoll::event_from(&bytes))
                .map_err(|_| Errno::EFAULT)
        }
        Work::Transfer(transfer) => prepare_transfer(c, transfer),
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
/// registered buffer is looked for at issue (`io_prep_read_fixed`).
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

/// The file of a request, as `io_assign_file` finds it at issue: `EBADF`
/// for a registered one (there are none), or for a descriptor `fget` does
/// not find (an `O_PATH` one).
fn file_of(c: &Context<'_>, fd: i32, fixed: bool) -> Result<Arc<dyn FileHandle>, Errno> {
    if fixed || fd < 0 {
        return Err(Errno::EBADF);
    }
    let file = c.files.descriptor(fd as u64)?.file;
    if file.flags() & 0o10000000 != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}

/// Linux's `io_read` and `io_write`, run inline: the file, the registered
/// buffer of `IORING_OP_READ_FIXED` and `_WRITE_FIXED`
/// ([`Ring::registered`]), a provided buffer for a read that selects one (`ENOBUFS`, as none is ever
/// provided), then `io_rw_init_file` (the access mode, `EBADF`; the flags,
/// `kiocb_set_rw_flags`; polled I/O, `EINVAL` on a ring without
/// `IORING_SETUP_IOPOLL`; protection information, `EINVAL`), then the
/// transfer ([`crate::files::ring_transfer`]). Once the file's own read or
/// write ran, its watches hear of it as `io_req_io_end` tells them:
/// `IN_ACCESS` for a read that did not fail, `IN_MODIFY` for any write, no
/// bytes too.
fn transfer(c: &mut Context<'_>, ring: &Ring, transfer: &Transfer) -> Result<u64, Errno> {
    let file = file_of(c, transfer.fd, transfer.fixed)?;
    let within;
    let segments = if transfer.registered {
        within = [ring.registered(transfer.buf_index, transfer.addr, transfer.len)?];
        &within[..]
    } else {
        &transfer.segments[..]
    };
    if transfer.select {
        return Err(ENOBUFS);
    }
    if file.flags() & 3 == if transfer.write { 0 } else { 1 } {
        return Err(Errno::EBADF);
    }
    let flags = crate::files::kiocb_rw_flags(&file, transfer.rw_flags)?;
    if flags & RWF_HIPRI != 0 || transfer.metadata {
        return Err(Errno::EINVAL);
    }
    let result =
        crate::files::ring_transfer(c, &file, transfer.write, segments, transfer.offset, flags)?;
    let fd = transfer.fd as u64;
    // A write that would wait completes with `EAGAIN` here, where Linux
    // keeps it in flight and its watches hear of it only once it ends;
    // one that asked for `RWF_NOWAIT` ends at once, and they hear of it.
    let waited = result == Err(Errno::EAGAIN) && flags & RWF_NOWAIT == 0;
    if transfer.write && !waited {
        crate::files::notify_descriptor(c, fd, crate::inotify::MODIFY);
    } else if result.is_ok() {
        crate::files::notify_descriptor(c, fd, crate::inotify::ACCESS);
    }
    result
}

/// Runs a request and gives its result.
fn run(c: &mut Context<'_>, ring: &Ring, work: &Work) -> i32 {
    let result = |r: Result<u64, Errno>| r.map_or_else(|e| -e.0, |v| v as i32);
    match work {
        &Work::Nop(result) => result,
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
        Work::Transfer(work) => result(transfer(c, ring, work)),
        // `io_fsync`: `vfs_fsync_range`, `EINVAL` for a file without
        // `fsync`; nothing is cached, so the range and `IORING_FSYNC_DATASYNC`
        // change nothing.
        &Work::Fsync { fd, fixed } => result(file_of(c, fd, fixed).and_then(|file| {
            file.sync()?;
            Ok(0)
        })),
        Work::None => 0,
    }
}

/// Completes a chain of linked requests in order, as Linux runs a link once
/// it is whole: one that failed to prepare fails the chain, whose others
/// complete with `ECANCELED`; otherwise each runs, and a failure ends the
/// chain at a soft link (`IOSQE_IO_LINK`) but not at a hard one. A request
/// that succeeds with `IOSQE_CQE_SKIP_SUCCESS` posts nothing.
fn complete(c: &mut Context<'_>, ring: &Ring, chain: Vec<Request>) {
    let prepared = chain.iter().all(|r| r.failed.is_none());
    let mut cancelled = false;
    for request in chain {
        let res = if !prepared {
            -request.failed.unwrap_or(ECANCELED).0
        } else if cancelled {
            -ECANCELED.0
        } else {
            let res = run(c, ring, &request.work);
            if res < 0 && request.flags & IOSQE_IO_HARDLINK == 0 {
                cancelled = true;
            }
            res
        };
        if res >= 0 && request.flags & IOSQE_CQE_SKIP_SUCCESS != 0 {
            continue;
        }
        let mut state = ring.state();
        ring.post(&mut state, request.user_data, res);
    }
}

/// Linux's `io_submit_sqes`: takes up to `wanted` entries from the
/// submission queue and gives how many it took. One that fails to prepare
/// outside a link ends the submission (after it) unless
/// `IORING_SETUP_SUBMIT_ALL`; an index past the entries in the queue's
/// array is dropped and ends it before it.
fn submit(c: &mut Context<'_>, ring: &Ring, wanted: u32) -> u32 {
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
            prepare_memory(c, &mut request, u64_at(&sqe, 16));
        }
        let failed = request.failed.is_some();
        let linked = request.flags & LINK_FLAGS != 0;
        chain.push(request);
        left -= 1;
        if !linked {
            complete(c, ring, std::mem::take(&mut chain));
            if failed && ring.flags & SETUP_SUBMIT_ALL == 0 {
                break;
            }
        }
    }
    // A link the submission left open runs as it is.
    if !chain.is_empty() {
        complete(c, ring, chain);
    }
    ring.state().sq_head = head;
    ring.store_u32(SQ_HEAD, head);
    total - left
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
    let pages = |len: u64| -> Result<SharedPages, Errno> {
        let size = len.next_multiple_of(4096);
        let pages = SharedPages::new().with_source(Arc::new(RingPages { size }));
        let meter = c.mem.memory_meter();
        for key in (0..size).step_by(4096) {
            pages.fill(key, &[], meter.as_ref())?;
        }
        Ok(pages)
    };
    let ring = Ring {
        flags,
        sq_entries,
        cq_entries,
        rings: pages(rings_len)?,
        sq_array,
        sqes: pages(sqes_len)?,
        sqes_len,
        submitter: (flags & SETUP_SINGLE_ISSUER != 0).then_some(c.tid),
        submitting: Mutex::default(),
        state: Mutex::default(),
        charged: (!c.process.credentials.capable(CAP_IPC_LOCK)).then(|| {
            (
                Arc::clone(&c.processes.secret_pages),
                c.process.credentials.uid,
            )
        }),
        buffers: Mutex::default(),
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
    c.files.install(Arc::new(ring), true, c.group.nofile())
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
    // No ring descriptor is ever registered.
    if flags & ENTER_REGISTERED_RING != 0 {
        return Err(if a[0] as u32 >= RINGFD_REG_MAX {
            Errno::EINVAL
        } else {
            Errno::EBADF
        });
    }
    let file = ring_of(c, a[0])?;
    let ring = downcast(&file)?;
    let mut submitted = 0;
    if to_submit != 0 {
        if ring.submitter.is_some_and(|tid| tid != c.tid) {
            return Err(EEXIST);
        }
        let _submitting = ring
            .submitting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        ring.flush(&mut ring.state());
        submitted = submit(c, ring, to_submit);
        if submitted != to_submit {
            return Ok(u64::from(submitted));
        }
    }
    if flags & ENTER_GETEVENTS != 0 {
        let waited = wait(
            c,
            ring,
            min_complete.min(ring.cq_entries),
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

/// Linux's `io_cqring_wait`: done once the program has `min` completions
/// to consume, else it waits, with the signal mask it was given, for a
/// signal (`EINTR`) or the timeout (`ETIME`). Completions in the queue by
/// then make it succeed whatever ended the wait.
fn wait(
    c: &mut Context<'_>,
    ring: &Ring,
    min: u32,
    flags: u32,
    argp: u64,
    argsz: u64,
) -> Result<(), Errno> {
    let (sigmask, sigsz, ts) = if flags & ENTER_EXT_ARG != 0 {
        // struct io_uring_getevents_arg.
        if argsz != 24 {
            return Err(Errno::EINVAL);
        }
        let mut arg = [0; 24];
        c.mem
            .read(GuestAddr(argp), &mut arg)
            .map_err(|_| Errno::EFAULT)?;
        (
            u64_at(&arg, 0),
            u64::from(u32_at(&arg, 8)),
            u64_at(&arg, 16),
        )
    } else {
        (argp, argsz, 0)
    };
    if ring.flags & SETUP_DEFER_TASKRUN != 0 && ring.submitter.is_some_and(|t| t != c.tid) {
        return Err(EEXIST);
    }
    {
        let mut state = ring.state();
        ring.flush(&mut state);
    }
    if ring.completions() >= min {
        return Ok(());
    }
    let now = c.host.clock(paludarium_host::ClockId::Monotonic)?;
    let deadline = if ts == 0 {
        None
    } else {
        let mut timespec = [0; 16];
        c.mem
            .read(GuestAddr(ts), &mut timespec)
            .map_err(|_| Errno::EFAULT)?;
        let (sec, nsec) = (u64_at(&timespec, 0) as i64, u64_at(&timespec, 8) as i64);
        let nanos = sec
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec)
            .max(0) as u64;
        Some(if flags & ENTER_ABS_TIMER != 0 {
            nanos
        } else {
            now.saturating_add(nanos)
        })
    };
    let old_mask = c.process.signal_mask;
    if sigmask != 0 {
        if sigsz != 8 {
            return Err(Errno::EINVAL);
        }
        c.process.signal_mask = c
            .mem
            .read_u64(GuestAddr(sigmask))
            .map_err(|_| Errno::EFAULT)?
            & !((1 << 8) | (1 << 18));
    }
    let result = loop {
        let ticket = c.files.readiness.token.value();
        if ring.completions() >= min {
            break Ok(());
        }
        if deadline.is_some_and(|end| {
            c.host
                .clock(paludarium_host::ClockId::Monotonic)
                .is_ok_and(|now| now >= end)
        }) {
            break Err(ETIME);
        }
        if let Err(e) = crate::events::wait(c, ticket, deadline) {
            break Err(e);
        }
    };
    if sigmask != 0
        && result == Err(Errno(4))
        && crate::signals::next_pending(c.process, true).is_some()
    {
        // The handler's frame saves the mask from before the call, as
        // Linux's `restore_saved_sigmask_unless` keeps the one given.
        c.process.wait_restore_mask = Some(old_mask);
    } else {
        c.process.signal_mask = old_mask;
    }
    if ring.completions() != 0 {
        return Ok(());
    }
    result
}

/// `io_uring_register(fd, opcode, arg, nr_args)`: only
/// `IORING_REGISTER_PROBE`; every other operation gives `EINVAL`.
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
    if registered {
        return Err(if a[0] as u32 >= RINGFD_REG_MAX {
            Errno::EINVAL
        } else {
            Errno::EBADF
        });
    }
    let file = ring_of(c, a[0])?;
    let ring = downcast(&file)?;
    if ring.submitter.is_some_and(|tid| tid != c.tid) {
        return Err(EEXIST);
    }
    match opcode {
        REGISTER_PROBE => probe(c, a),
        REGISTER_BUFFERS if a[2] == 0 => Err(Errno::EFAULT),
        REGISTER_BUFFERS => register_buffers(c, ring, a[2], a[3] as u32),
        UNREGISTER_BUFFERS if a[2] != 0 || a[3] as u32 != 0 => Err(Errno::EINVAL),
        UNREGISTER_BUFFERS => ring
            .buffers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|_| 0)
            .ok_or(ENXIO),
        _ => Err(Errno::EINVAL),
    }
}

/// `IORING_REGISTER_BUFFERS`, as Linux's `io_sqe_buffers_register`: none
/// registered yet (`EBUSY`), 1 to `IORING_MAX_REG_BUFFERS` of them
/// (`EINVAL`), then each `iovec` in turn (`EFAULT`, `EINVAL` for a negative
/// length), as `io_sqe_buffer_register` takes it:
///
/// - A null address with no length registers an empty slot; one with a
///   length is `EFAULT`.
/// - No length or more than 1 GiB is `EFAULT`, and an end past the address
///   space `EOVERFLOW` (`io_validate_user_buf_range`).
/// - Its pages must be writable (`EFAULT`, as `pin_user_pages_fast` with
///   `FOLL_WRITE`).
/// - They charge the ring's user, within RLIMIT_MEMLOCK (`ENOMEM`), unless
///   the ring's maker had `CAP_IPC_LOCK` (`io_buffer_account_pin`).
///
/// A failure registers none of them.
fn register_buffers(c: &mut Context<'_>, ring: &Ring, arg: u64, count: u32) -> Result<u64, Errno> {
    let mut registered = ring.buffers.lock().unwrap_or_else(PoisonError::into_inner);
    if registered.is_some() {
        return Err(EBUSY);
    }
    if count == 0 || u64::from(count) > MAX_REG_BUFFERS {
        return Err(Errno::EINVAL);
    }
    let mut buffers = Buffers {
        slots: Vec::with_capacity(count as usize),
        charged: ring.charged.clone(),
        pages: 0,
    };
    let limit = c.processes.soft_limit(c.process.pid, 8) >> 12;
    for index in 0..u64::from(count) {
        let mut iovec = [0; 16];
        c.mem
            .read(GuestAddr(arg + 16 * index), &mut iovec)
            .map_err(|_| Errno::EFAULT)?;
        let (base, len) = (u64_at(&iovec, 0), u64_at(&iovec, 8));
        if (len as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        if base == 0 {
            if len != 0 {
                return Err(Errno::EFAULT);
            }
            buffers.slots.push(None);
            continue;
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
        c.mem
            .check_write(GuestAddr(base), len as usize)
            .map_err(|_| Errno::EFAULT)?;
        let pages = (base % 4096 + len).div_ceil(4096);
        if let Some((charged, user)) = &buffers.charged
            && !charged.charge(*user, pages, limit)
        {
            return Err(Errno::ENOMEM);
        }
        buffers.pages += pages;
        buffers.slots.push(Some((base, len)));
    }
    *registered = Some(buffers);
    Ok(0)
}

impl Ring {
    /// The `len` bytes at `addr` of a request's registered buffer `index`,
    /// as `io_import_reg_buf` finds them: none registered there, a range
    /// that wraps or leaves the buffer, or more than `MAX_RW_COUNT`, is
    /// `EFAULT` (`validate_fixed_range`).
    fn registered(&self, index: u16, addr: u64, len: u32) -> Result<(u64, usize), Errno> {
        let buffers = self.buffers.lock().unwrap_or_else(PoisonError::into_inner);
        let (base, size) = buffers
            .as_ref()
            .and_then(|buffers| buffers.slots.get(usize::from(index)).copied().flatten())
            .ok_or(Errno::EFAULT)?;
        let end = addr.checked_add(u64::from(len)).ok_or(Errno::EFAULT)?;
        if addr < base || end > base + size || len as usize > crate::files::MAX_RW_COUNT {
            return Err(Errno::EFAULT);
        }
        Ok((addr, len as usize))
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
        if OPS.contains(&(op as u8)) {
            probe[16 + 8 * op + 2..16 + 8 * op + 4].copy_from_slice(&OP_SUPPORTED.to_le_bytes());
        }
    }
    c.mem
        .write(GuestAddr(a[2]), &probe)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// `mmap` of a ring descriptor, as Linux's `io_uring_get_unmapped_area`
/// and `io_uring_mmap`: no address may be asked for (`EINVAL`), the offset's
/// region picks the rings or the entries (another gives `ENOMEM`), and the
/// mapping shows from the start of them however far into the region the
/// offset is. A mapping of the rings shows what fits, and past the rings a
/// page raises `SIGBUS`; one of the entries must hold them all (`EFAULT`).
/// Only a shared mapping is implemented: a private one gives `EINVAL`.
pub(crate) fn mmap(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    addr: u64,
    len: u64,
    prot: paludarium_mmu::Prot,
    shared: bool,
    offset: u64,
) -> Result<u64, Errno> {
    let ring = file
        .as_any()
        .and_then(|v| v.downcast_ref::<Ring>())
        .ok_or(Errno::ENODEV)?;
    if addr != 0 {
        return Err(Errno::EINVAL);
    }
    let (pages, entries) = match offset & OFF_MMAP_MASK {
        0 | OFF_CQ_RING => (&ring.rings, None),
        OFF_SQES => (&ring.sqes, Some(ring.sqes_len)),
        _ => return Err(Errno::ENOMEM),
    };
    if !shared {
        return Err(Errno::EINVAL);
    }
    let len = len.next_multiple_of(4096);
    if entries.is_some_and(|size| len < size.next_multiple_of(4096)) {
        return Err(Errno::EFAULT);
    }
    let at = c
        .mem
        .map_shared(None, len, prot, paludarium_mmu::MappingKind::File)?;
    if let Err(e) = c
        .mem
        .share_pages(at, len, pages, 0, paludarium_mmu::SharedWrites::Allowed)
    {
        let _ = c.mem.unmap_shared(at, len);
        return Err(e);
    }
    c.group.numa().forget(at.0, len);
    Ok(at.0)
}

impl FileHandle for Ring {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
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
        // The anonymous inode's: 0600, with its file type hidden.
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
        Ok(())
    }
    fn flags(&self) -> u32 {
        2
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}
