//! `kcmp(pid1, pid2, type, idx1, idx2)`, as Linux's `kernel/kcmp.c`: whether
//! two tasks share a kernel object, and an order of the two when they do not,
//! which hides the objects' addresses behind random cookies.
use crate::credentials::Credentials;
use crate::files::FilesView;
use crate::threads::{PublicThread, ThreadGroup};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr};
use std::sync::Arc;

/// `KCMP_TYPES`: `KCMP_FILE` to `KCMP_EPOLL_TFD`.
pub(crate) const TYPES: usize = 8;

/// A task one of the numbers names, with what `kcmp` compares of it.
pub(crate) struct Task {
    pub tid: u32,
    pub group: Arc<ThreadGroup>,
    /// Ended and waiting to be reaped: Linux's `exit_mm`, `exit_files`,
    /// `exit_fs`, `exit_io_context` and `exit_sem` have left it none of
    /// those, though it keeps its dispositions until it is reaped.
    pub zombie: bool,
    pub dumpable: bool,
    pub credentials: Credentials,
    pub memory: Option<usize>,
    pub files: FilesView,
}

impl Task {
    pub(crate) fn new(
        tid: u32,
        group: Arc<ThreadGroup>,
        zombie: bool,
        dumpable: bool,
        public: PublicThread,
    ) -> Self {
        Self {
            tid,
            group,
            zombie,
            dumpable,
            memory: public
                .memory
                .as_ref()
                .map(paludarium_mmu::MemoryView::identity),
            credentials: public.credentials,
            files: public.files,
        }
    }
    fn files(&self) -> Option<&FilesView> {
        (!self.zombie).then_some(&self.files)
    }
    fn file(&self, fd: u32) -> Option<usize> {
        let file = self.files()?.file(fd)?;
        Some(Arc::as_ptr(&file) as *const () as usize)
    }
}

/// Linux's `kptr_obfuscate` and `kcmp_ptr`: 0 for the same object, else 1
/// or 2 as the two compare after each is xored with one cookie and
/// multiplied by another; none, a NULL pointer, is 0.
fn order(
    cookies: &[[u64; 2]; TYPES],
    kind: usize,
    first: Option<usize>,
    second: Option<usize>,
) -> u64 {
    let [xor, multiply] = cookies[kind];
    let hide = |v: Option<usize>| ((v.unwrap_or(0) as u64 ^ xor).wrapping_mul(multiply)) as i64;
    let (a, b) = (hide(first), hide(second));
    u64::from(a < b) | u64::from(a > b) << 1
}

/// Fills `random` from std's hasher, whose keys are random for each
/// process, for when the host gives no random bytes.
pub(crate) fn fallback_random(random: &mut [u8]) {
    use std::hash::{BuildHasher, Hasher};
    let keys = std::hash::RandomState::new();
    for (index, chunk) in random.chunks_mut(8).enumerate() {
        let mut hasher = keys.build_hasher();
        hasher.write_usize(index);
        let bytes = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// The cookies Linux's `kcmp_cookies_init` draws at boot: random, each
/// multiplier odd and with its top bit set.
pub(crate) fn cookies(random: &[u8; TYPES * 16]) -> [[u64; 2]; TYPES] {
    let word = |at: usize| u64::from_le_bytes(random[at..at + 8].try_into().unwrap_or_default());
    std::array::from_fn(|kind| [word(kind * 16), word(kind * 16 + 8) | 1 << 63 | 1])
}

/// `kcmp` once both tasks are found, as Linux checks them: the caller must
/// be able to read each (`ptrace_may_access` with
/// `PTRACE_MODE_READ_REALCREDS`, `EPERM`); then `type` picks what is
/// compared: an open file by each task's descriptor (`KCMP_FILE`, `EBADF`
/// unless both are open, the indices as Linux's `unsigned int`), the memory,
/// the descriptor table, the working directory and umask, the signal
/// dispositions, the I/O context, the System V semaphore undo list, or the
/// first task's file with one an epoll instance of the second's watches
/// (`KCMP_EPOLL_TFD`, ordered as `KCMP_FILE` orders them); any other is
/// `EINVAL`.
pub(crate) fn compare(
    cookies: &[[u64; 2]; TYPES],
    caller: (&ThreadGroup, &Credentials),
    mem: &AddressSpace,
    tasks: [&Task; 2],
    kind: i32,
    indices: [u64; 2],
) -> Result<u64, Errno> {
    let [first, second] = tasks;
    let readable = |task: &Task| {
        std::ptr::eq(Arc::as_ptr(&task.group), caller.0)
            || caller
                .1
                .may_read_task(&task.credentials, task.dumpable, true)
    };
    if !readable(first) || !readable(second) {
        return Err(Errno::EPERM);
    }
    let both = |f: &dyn Fn(&Task) -> Option<usize>| (f(first), f(second));
    let (a, b) = match kind {
        0 => match (
            first.file(indices[0] as u32),
            second.file(indices[1] as u32),
        ) {
            (Some(a), Some(b)) => (Some(a), Some(b)),
            _ => return Err(Errno::EBADF),
        },
        1 => both(&|t| t.memory.filter(|_| !t.zombie)),
        2 => both(&|t| t.files()?.table()),
        3 => both(&|t| t.files()?.fs()),
        4 => both(&|t| Some(Arc::as_ptr(&t.group.shared_actions()) as *const () as usize)),
        5 => both(&|t| {
            let context = t.group.sched(t.tid).io_context;
            (context != 0 && !t.zombie).then_some(context as usize)
        }),
        6 => both(&|t| t.group.sem_undo_identity(t.tid).filter(|_| !t.zombie)),
        7 => {
            // struct kcmp_epoll_slot { __u32 efd, tfd, toff; }
            let mut slot = [0; 12];
            mem.read(GuestAddr(indices[1]), &mut slot)
                .map_err(|_| Errno::EFAULT)?;
            let field = |at: usize| {
                u32::from_le_bytes([slot[at], slot[at + 1], slot[at + 2], slot[at + 3]])
            };
            let file = first.file(indices[0] as u32).ok_or(Errno::EBADF)?;
            let epoll = second
                .files()
                .and_then(|files| files.file(field(0)))
                .ok_or(Errno::EBADF)?;
            let epoll = epoll
                .as_any()
                .and_then(|any| any.downcast_ref::<crate::epoll::EpollInstance>())
                .ok_or(Errno::EINVAL)?;
            let target = epoll
                .target(field(4), u64::from(field(8)))
                .ok_or(Errno::ENOENT)?;
            (Some(file), Some(target))
        }
        _ => return Err(Errno::EINVAL),
    };
    Ok(order(cookies, cookie_kind(kind), a, b))
}

/// The cookies a type compares with: its own, except `KCMP_EPOLL_TFD`, which
/// `kcmp_epoll_target` compares as `KCMP_FILE` does, with that type's.
fn cookie_kind(kind: i32) -> usize {
    if kind == 7 { 0 } else { kind as usize }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn objects_order_by_their_types_cookies() {
        // Type 0 (and so 7) keeps the order; type 1 xors the top bit,
        // which reverses it for these two.
        let mut cookies = [[0, 1]; TYPES];
        cookies[1] = [1 << 63, 1];
        cookies[7] = [1 << 63, 1];
        let (low, high) = (Some(0x1000), Some(0x2000));
        assert_eq!(order(&cookies, 0, low, high), 1);
        assert_eq!(order(&cookies, 0, high, low), 2);
        assert_eq!(order(&cookies, 0, low, low), 0);
        assert_eq!(order(&cookies, 0, None, None), 0);
        assert_eq!(order(&cookies, 1, Some(0), Some(1 << 63)), 1);
        assert_eq!(order(&cookies, 0, Some(0), Some(1 << 63)), 2);
        assert_eq!(cookie_kind(7), 0);
        assert_eq!(cookie_kind(0), 0);
        assert_eq!(cookie_kind(5), 5);
        // Without the host's bytes they are not all zeros.
        let mut random = [0; TYPES * 16];
        fallback_random(&mut random);
        assert!(random.iter().any(|&b| b != 0));
        // The cookies Linux draws make each multiplier odd, top bit set.
        let drawn = super::cookies(&[0; TYPES * 16]);
        assert!(drawn.iter().all(|&[_, m]| m & 1 == 1 && m >> 63 == 1));
    }
}
