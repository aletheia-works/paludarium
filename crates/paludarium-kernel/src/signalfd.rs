//! `signalfd` and `signalfd4`. A signal file reads the signals of its mask
//! that are pending for the thread reading it, blocked or not, as Linux's
//! `signalfd_read` takes them with `dequeue_signal` from `current`: the
//! thread's own queue first, then the process's shared one. `poll` and
//! `epoll` see the same thread's signals, as `signalfd_poll` does, through
//! what [`observe`] last recorded for the calling thread.
use crate::events::{CLOEXEC, IN, NONBLOCK};
use crate::syscalls::{Context, Outcome};
use crate::{SignalInbox, ThreadGroup, ThreadState, signals};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// `sizeof(struct signalfd_siginfo)`.
const RECORD: usize = 128;
/// SIGKILL and SIGSTOP, which a signal file never takes.
const UNTAKEABLE: u64 = 1 << 8 | 1 << 18;

/// Signal files that exist; while there are none, [`observe`] does nothing.
static LIVE: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    /// The signals pending for the thread this host thread runs, how many
    /// have come for it and its process so far, and a count bumped whenever
    /// that grows: one for each signal queued, as Linux's `signalfd_notify`
    /// wakes the file for each (an edge for edge-triggered epoll).
    static VIEW: Cell<View> = const { Cell::new(View { thread: 0, set: 0, arrivals: 0, epoch: 0 }) };
}
#[derive(Clone, Copy)]
struct View {
    /// The guest thread it is of, by its inbox: a thread's first look only
    /// records, as nothing came since it last looked.
    thread: usize,
    set: u64,
    arrivals: u64,
    epoch: u64,
}

/// Records the signals pending for the calling thread: those in its own
/// queue or still in its inbox, and the process's. Called as a system call
/// starts and after every wait, so a file's readiness is the caller's.
pub(crate) fn observe(process: &ThreadState, inbox: &SignalInbox, group: &ThreadGroup) {
    if LIVE.load(Ordering::SeqCst) == 0 {
        return;
    }
    inbox.publish(process);
    let (shared, shared_arrivals) = group.process_pending_set();
    let (queued, coming) = inbox.queued_set(process);
    let set = set_of(&process.pending) | queued | shared;
    // Another thread's signal counts once that thread publishes it, as
    // Linux wakes every signal file of the process for each signal.
    let arrivals = process
        .arrivals
        .wrapping_add(coming)
        .wrapping_add(shared_arrivals)
        .wrapping_add(inbox.others_arrivals());
    let thread = std::ptr::from_ref(inbox) as usize;
    VIEW.with(|view| {
        let seen = view.get();
        let changed = set & !seen.set != 0 || arrivals != seen.arrivals;
        let epoch = if seen.thread == thread && changed {
            seen.epoch.wrapping_add(1)
        } else {
            seen.epoch
        };
        view.set(View {
            thread,
            set,
            arrivals,
            epoch,
        });
    });
}

fn set_of(pending: &[signals::PendingSignal]) -> u64 {
    pending
        .iter()
        .filter(|s| (1..=64).contains(&s.number))
        .fold(0, |set, s| set | 1 << (s.number - 1))
}

pub(crate) fn sys_signalfd(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(create(c, a[0], a[1], a[2], 0))
}
pub(crate) fn sys_signalfd4(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(create(c, a[0], a[1], a[2], a[3]))
}
fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// `signalfd4(fd, mask, sizemask, flags)`, in Linux's order: the size, the
/// mask, the flags; then a new file for fd -1, or the new mask for the
/// signal file `fd` names (EBADF for no descriptor, EINVAL for another file).
fn create(c: &mut Context<'_>, fd: u64, mask: u64, size: u64, flags: u64) -> Result<u64, Errno> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let mask = c.mem.read_u64(GuestAddr(mask)).map_err(|_| Errno::EFAULT)? & !UNTAKEABLE;
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(NONBLOCK | CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    if fd as i32 == -1 {
        let file = Arc::new(SignalFile::new(mask, flags));
        observe(c.process, c.inbox, c.group);
        return c
            .files
            .install(file, flags & CLOEXEC != 0, c.group.nofile())
            .map(u64::from);
    }
    let file = c.files.descriptor(fd)?.file;
    let signal = file
        .as_any()
        .and_then(|any| any.downcast_ref::<SignalFile>())
        .ok_or(Errno::EINVAL)?;
    signal.mask.store(mask, Ordering::SeqCst);
    // A waiter on the file looks again with the new mask, as Linux wakes
    // `signalfd_wqh`, which is an edge for edge-triggered epoll.
    signal.updates.fetch_add(1, Ordering::SeqCst);
    c.files.readiness.changed();
    Ok(fd as u32 as u64)
}

pub(crate) struct SignalFile {
    mask: AtomicU64,
    flags: AtomicU32,
    /// Changes of the mask, each a wakeup of the file.
    updates: AtomicU64,
}
impl SignalFile {
    /// What `/proc/self/fdinfo` adds for the file, as Linux's
    /// `signalfd_show_fdinfo`: the signals it takes.
    pub(crate) fn fdinfo(&self) -> Vec<u8> {
        format!("sigmask:\t{:016x}\n", self.mask.load(Ordering::SeqCst)).into_bytes()
    }
    fn new(mask: u64, flags: u32) -> Self {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Self {
            mask: AtomicU64::new(mask),
            flags: AtomicU32::new(2 | flags & NONBLOCK),
            updates: AtomicU64::new(0),
        }
    }
}
impl Drop for SignalFile {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A read of a signal file, which takes the caller's signals; `None` for
/// any other file.
pub(crate) fn read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    out: &mut [u8],
    nowait: bool,
) -> Option<Result<usize, Errno>> {
    let signal = file.as_any()?.downcast_ref::<SignalFile>()?;
    Some(read_signals(c, signal, out, nowait))
}

/// Linux's `signalfd_read`: as many whole records as fit, waiting for the
/// first unless the file is non-blocking; a signal that can be delivered
/// meanwhile ends the wait with EINTR (ERESTARTSYS, which SA_RESTART
/// restarts as any read).
fn read_signals(
    c: &mut Context<'_>,
    file: &SignalFile,
    out: &mut [u8],
    nowait: bool,
) -> Result<usize, Errno> {
    let records = out.len() / RECORD;
    if records == 0 {
        return Err(Errno::EINVAL);
    }
    let mut taken = 0;
    while taken < records {
        let mask = file.mask.load(Ordering::SeqCst);
        let ticket = c.files.readiness.token.value();
        if let Some(signal) = take(c, mask) {
            let record = siginfo(&signals::siginfo(c.process, &signal));
            out[taken * RECORD..][..RECORD].copy_from_slice(&record);
            taken += 1;
            continue;
        }
        if taken != 0 {
            break;
        }
        if nowait || file.flags.load(Ordering::SeqCst) & NONBLOCK != 0 {
            return Err(Errno::EAGAIN);
        }
        if crate::events::signalled(c) {
            return Err(Errno(4));
        }
        crate::events::wait(c, ticket, None)?;
    }
    observe(c.process, c.inbox, c.group);
    Ok(taken * RECORD)
}

/// Takes the lowest pending signal of `mask`: the thread's own first, then
/// the process's, as `rt_sigtimedwait` takes them.
fn take(c: &mut Context<'_>, mask: u64) -> Option<signals::PendingSignal> {
    c.group.drain_process(c.process);
    c.inbox.drain(c.process);
    signals::lowest_in(&c.process.pending, mask)
        .map(|index| c.process.pending.remove(index))
        .or_else(|| c.group.take_process_signal(mask))
}

/// How Linux's `siginfo_layout` reads a signal's union, which decides the
/// fields `signalfd_copyinfo` copies.
#[derive(PartialEq, Eq)]
enum Layout {
    Kill,
    Timer,
    Poll,
    Fault,
    Child,
    Rt,
    Sys,
}
fn layout(number: i32, code: i32) -> Layout {
    const SI_USER: i32 = 0;
    const SI_KERNEL: i32 = 0x80;
    const SI_TIMER: i32 = -2;
    const SI_SIGIO: i32 = -5;
    if code > SI_USER && code < SI_KERNEL {
        // The signals whose codes Linux defines, with the highest of them.
        match (number, code) {
            (4, ..=11) | (8, ..=15) | (11, ..=10) | (7, ..=5) | (5, ..=6) => Layout::Fault,
            (17, ..=6) => Layout::Child,
            (29, ..=6) => Layout::Poll,
            (31, ..=2) => Layout::Sys,
            _ => Layout::Kill,
        }
    } else if code == SI_TIMER {
        Layout::Timer
    } else if code == SI_SIGIO {
        Layout::Poll
    } else if code < 0 {
        Layout::Rt
    } else {
        Layout::Kill
    }
}

/// The `struct signalfd_siginfo` of a 128-byte `siginfo_t`, as Linux's
/// `signalfd_copyinfo` fills it.
fn siginfo(info: &[u8; 128]) -> [u8; RECORD] {
    let word = |at: usize| u32::from_le_bytes([info[at], info[at + 1], info[at + 2], info[at + 3]]);
    let quad = |at: usize| u64::from(word(at)) | u64::from(word(at + 4)) << 32;
    let mut out = [0u8; RECORD];
    let mut put = |at: usize, bytes: &[u8]| out[at..at + bytes.len()].copy_from_slice(bytes);
    let (number, code) = (word(0), word(8));
    put(0, &number.to_le_bytes());
    put(4, &word(4).to_le_bytes());
    put(8, &code.to_le_bytes());
    // ssi_pid 12, ssi_uid 16, ssi_fd 20, ssi_tid 24, ssi_band 28,
    // ssi_overrun 32, ssi_status 40, ssi_int 44, ssi_ptr 48, ssi_utime 56,
    // ssi_stime 64, ssi_addr 72, ssi_syscall 84, ssi_call_addr 88, ssi_arch 96.
    match layout(number as i32, code as i32) {
        Layout::Kill => {
            put(12, &word(16).to_le_bytes());
            put(16, &word(20).to_le_bytes());
        }
        Layout::Timer => {
            put(24, &word(16).to_le_bytes());
            put(32, &word(20).to_le_bytes());
            put(48, &quad(24).to_le_bytes());
            put(44, &word(24).to_le_bytes());
        }
        Layout::Poll => {
            put(28, &word(16).to_le_bytes());
            put(20, &word(24).to_le_bytes());
        }
        Layout::Fault => put(72, &quad(16).to_le_bytes()),
        Layout::Child => {
            put(12, &word(16).to_le_bytes());
            put(16, &word(20).to_le_bytes());
            put(40, &word(24).to_le_bytes());
            put(56, &quad(32).to_le_bytes());
            put(64, &quad(40).to_le_bytes());
        }
        Layout::Rt => {
            put(12, &word(16).to_le_bytes());
            put(16, &word(20).to_le_bytes());
            put(48, &quad(24).to_le_bytes());
            put(44, &word(24).to_le_bytes());
        }
        Layout::Sys => {
            put(88, &quad(16).to_le_bytes());
            put(84, &word(24).to_le_bytes());
            put(96, &word(28).to_le_bytes());
        }
    }
    out
}

impl FileHandle for SignalFile {
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let view = VIEW.with(Cell::get);
        let ready = view.set & self.mask.load(Ordering::SeqCst) != 0;
        let epoch = view.epoch.wrapping_add(self.updates.load(Ordering::SeqCst));
        Ok((u32::from(ready) * IN, epoch, 0))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// Reads come through [`read`], which knows the reading thread.
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.len() < RECORD {
            return Err(Errno::EINVAL);
        }
        Err(Errno::EAGAIN)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    /// Linux's `noop_llseek`: the position stays 0, whatever is asked.
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
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(2 | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn info(number: i32, code: i32, union: &[(usize, u32)]) -> [u8; 128] {
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&number.to_le_bytes());
        info[8..12].copy_from_slice(&code.to_le_bytes());
        for &(at, value) in union {
            info[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        info
    }
    fn field(record: &[u8; RECORD], at: usize) -> u32 {
        u32::from_le_bytes(record[at..at + 4].try_into().unwrap())
    }
    #[test]
    fn kill_and_child_records() {
        let kill = siginfo(&info(10, 0, &[(16, 42), (20, 1000)]));
        assert_eq!(
            (field(&kill, 0), field(&kill, 12), field(&kill, 16)),
            (10, 42, 1000)
        );
        let child = siginfo(&info(17, 1, &[(16, 7), (20, 0), (24, 3), (32, 5)]));
        assert_eq!(
            (field(&child, 12), field(&child, 40), field(&child, 56)),
            (7, 3, 5)
        );
        // A SIGCHLD from kill is a kill's record, without a status.
        let sent = siginfo(&info(17, 0, &[(16, 7), (24, 3)]));
        assert_eq!((field(&sent, 12), field(&sent, 40)), (7, 0));
    }
    #[test]
    fn queued_timer_fault_and_poll_records() {
        let queued = siginfo(&info(34, -1, &[(16, 9), (20, 0), (24, 77), (28, 1)]));
        assert_eq!((field(&queued, 12), field(&queued, 44)), (9, 77));
        assert_eq!(
            u64::from_le_bytes(queued[48..56].try_into().unwrap()),
            77 | 1 << 32
        );
        let timer = siginfo(&info(14, -2, &[(16, 3), (20, 2), (24, 5)]));
        assert_eq!(
            (field(&timer, 24), field(&timer, 32), field(&timer, 44)),
            (3, 2, 5)
        );
        let fault = siginfo(&info(11, 1, &[(16, 0x1000)]));
        assert_eq!((field(&fault, 72), field(&fault, 12)), (0x1000, 0));
        let poll = siginfo(&info(29, 1, &[(16, 1), (24, 4)]));
        assert_eq!((field(&poll, 28), field(&poll, 20)), (1, 4));
        let kernel = siginfo(&info(11, 0x80, &[(16, 5)]));
        assert_eq!(field(&kernel, 72), 0);
    }
    #[test]
    fn readiness_follows_the_view() {
        let file = SignalFile::new(1 << 9, NONBLOCK);
        let view = |set, epoch| View {
            thread: 0,
            set,
            arrivals: 0,
            epoch,
        };
        VIEW.with(|v| v.set(view(1 << 9, 4)));
        assert_eq!(file.readiness(), Ok((IN, 4, 0)));
        VIEW.with(|v| v.set(view(1 << 10, 5)));
        assert_eq!(file.readiness(), Ok((0, 5, 0)));
        assert_eq!(file.flags(), 2 | NONBLOCK);
        assert_eq!(file.read(&mut [0; 127]), Err(Errno::EINVAL));
        assert_eq!(file.read(&mut [0; 128]), Err(Errno::EAGAIN));
        assert_eq!(file.write(&[0; 128]), Err(Errno::EINVAL));
        assert_eq!(file.seek(5, 2), Ok(0));
        file.set_flags(0).unwrap();
        assert_eq!(file.flags(), 2);
    }
}
