//! The counts of `/proc/<pid>/io`, as Linux's `task_io_accounting` keeps
//! them: the bytes the read and write system calls moved (`rchar`,
//! `wchar`) and how many of them ran (`syscr`, `syscw`). The storage counts
//! (`read_bytes`, `write_bytes`, `cancelled_write_bytes`) stay 0, as on a
//! Linux whose files are all in memory: there is no block device.

use crate::syscalls::Context;
use paludarium_types::Errno;

/// The counts of a thread, or of a process's threads together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Io {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
}
impl Io {
    /// `other` added, as `task_io_accounting_add`.
    pub(crate) fn add(&mut self, other: Io) {
        self.rchar = self.rchar.wrapping_add(other.rchar);
        self.wchar = self.wchar.wrapping_add(other.wchar);
        self.syscr = self.syscr.wrapping_add(other.syscr);
        self.syscw = self.syscw.wrapping_add(other.syscw);
    }
}

/// Counts system call `n` with `a`, which returned `ret`, for the calling
/// thread ([`counted`]).
pub(crate) fn account(c: &Context<'_>, n: u64, a: [u64; 6], ret: u64) {
    if let Some(io) = counted(n, a, ret) {
        c.group.account_io(c.tid, io);
    }
}

/// What system call `n` with `a`, which returned `ret`, adds to the counts,
/// as Linux's `vfs_read`, `vfs_write`, `do_readv`, `do_preadv`,
/// `do_sendfile` and `vfs_copy_file_range` add them: the bytes it moved,
/// and the call itself once it reached the file's read or write, failing
/// there or not. A call refused before that is not counted: in `read` and
/// `write`, a descriptor that is not open for it (`EBADF`), a file with no
/// such operation or a bad position (`EINVAL`), or a buffer outside user
/// memory (`EFAULT`); in `pread64` and `pwrite64` also a file with no
/// position (`ESPIPE`); in `preadv` and `pwritev` (and `preadv2`'s and
/// `pwritev2`'s other than at -1) only a negative position, as `do_preadv`
/// counts even a bad descriptor; `readv` and `writev` always count. Only the
/// errno tells where a failure came from here, so one that Linux gives both
/// before and in the file's operation (an eventfd's `EINVAL` for too small a
/// buffer) is taken as the early one. `splice`, `tee`, `vmsplice`, sockets'
/// `recv` and `send` families and `io_uring` count nothing, as on Linux.
pub(crate) fn counted(n: u64, a: [u64; 6], ret: u64) -> Option<Io> {
    let value = ret as i64;
    let error = (-4095..0).contains(&value).then(|| Errno(-value as i32));
    let moved = if value > 0 { value as u64 } else { 0 };
    let refused = |early: &[Errno]| error.is_some_and(|e| early.contains(&e));
    const EXDEV: Errno = Errno(18);
    const ETXTBSY: Errno = Errno(26);
    const EFBIG: Errno = Errno(27);
    let plain = [Errno::EBADF, Errno::EINVAL, Errno::EFAULT];
    let positioned = [Errno::EBADF, Errno::EINVAL, Errno::EFAULT, Errno::ESPIPE];
    let position = a[3] as i64;
    let read = |counts: bool| {
        counts.then_some(Io {
            rchar: moved,
            syscr: 1,
            ..Io::default()
        })
    };
    let write = |counts: bool| {
        counts.then_some(Io {
            wchar: moved,
            syscw: 1,
            ..Io::default()
        })
    };
    let both = |counts: bool| {
        counts.then_some(Io {
            rchar: moved,
            wchar: moved,
            syscr: 1,
            syscw: 1,
        })
    };
    match n {
        0 => read(!refused(&plain)),
        1 => write(!refused(&plain)),
        17 => read(!refused(&positioned)),
        18 => write(!refused(&positioned)),
        19 => read(true),
        20 => write(true),
        295 => read(position >= 0),
        296 => write(position >= 0),
        327 => read(position >= -1),
        328 => write(position >= -1),
        // `do_sendfile` counts once it has the files and their positions.
        40 => both(!refused(&[
            Errno::EBADF,
            Errno::EINVAL,
            Errno::EFAULT,
            Errno::ESPIPE,
            Errno::EOVERFLOW,
        ])),
        // `vfs_copy_file_range` returns before it counts for nothing to
        // copy and for what `generic_copy_file_checks` refuses.
        326 if value == 0 && a[4] == 0 => None,
        326 => both(!refused(&[
            Errno::EBADF,
            Errno::EINVAL,
            Errno::EFAULT,
            Errno::EISDIR,
            Errno::EOVERFLOW,
            Errno::EPERM,
            EXDEV,
            ETXTBSY,
            EFBIG,
        ])),
        _ => None,
    }
}

/// The text of `/proc/<pid>/io`, as Linux's `do_io_accounting` writes it.
pub(crate) fn render(io: Io) -> Vec<u8> {
    format!(
        "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: 0\nwrite_bytes: 0\n\
         cancelled_write_bytes: 0\n",
        io.rchar, io.wchar, io.syscr, io.syscw
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(e: Errno) -> u64 {
        e.to_syscall_return()
    }

    #[test]
    fn reads_and_writes_count_their_bytes_and_themselves() {
        let read = counted(0, [0; 6], 10).unwrap();
        assert_eq!(
            (read.rchar, read.syscr, read.wchar, read.syscw),
            (10, 1, 0, 0)
        );
        let write = counted(20, [0; 6], 7).unwrap();
        assert_eq!((write.wchar, write.syscw, write.rchar), (7, 1, 0));
        let both = counted(40, [0; 6], 6).unwrap();
        assert_eq!(
            (both.rchar, both.wchar, both.syscr, both.syscw),
            (6, 6, 1, 1)
        );
        // An empty read, and one that failed in the file, still count.
        assert_eq!(counted(0, [0; 6], 0).unwrap().syscr, 1);
        assert_eq!(counted(0, [0; 6], failed(Errno::EAGAIN)).unwrap().rchar, 0);
        assert_eq!(counted(39, [0; 6], 0), None);
    }

    #[test]
    fn calls_refused_before_the_file_do_not_count() {
        assert_eq!(counted(0, [0; 6], failed(Errno::EBADF)), None);
        assert_eq!(counted(17, [0; 6], failed(Errno::ESPIPE)), None);
        // readv counts a bad descriptor; preadv one without a position.
        assert!(counted(19, [0; 6], failed(Errno::EBADF)).is_some());
        assert!(counted(295, [0; 6], failed(Errno::ESPIPE)).is_some());
        let negative = [0, 0, 0, (-2_i64) as u64, 0, 0];
        assert_eq!(counted(295, negative, failed(Errno::EINVAL)), None);
        assert_eq!(counted(327, negative, failed(Errno::EINVAL)), None);
        let current = [0, 0, 0, u64::MAX, 0, 0];
        assert!(counted(327, current, 3).is_some());
        // copy_file_range of nothing returns before it counts.
        assert_eq!(counted(326, [0; 6], 0), None);
        assert!(counted(326, [0, 0, 0, 0, 5, 0], 0).is_some());
    }

    #[test]
    fn the_text_is_linuxs() {
        let io = Io {
            rchar: 1,
            wchar: 2,
            syscr: 3,
            syscw: 4,
        };
        assert_eq!(
            render(io),
            b"rchar: 1\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 0\nwrite_bytes: 0\n\
              cancelled_write_bytes: 0\n"
        );
    }
}
