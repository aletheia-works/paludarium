//! io_uring's file requests, as Linux's `io_uring/openclose.c`, `fs.c`,
//! `statx.c`, `sync.c`, `truncate.c` and `advise.c` have them:
//! `IORING_OP_OPENAT`, `_OPENAT2`, `_CLOSE`, `_STATX`, `_FALLOCATE`,
//! `_FADVISE`, `_MADVISE`, `_RENAMEAT`, `_UNLINKAT`, `_MKDIRAT`,
//! `_SYMLINKAT`, `_LINKAT`, `_FTRUNCATE` and `_PIPE`.
//!
//! Each runs as the call it stands for does. Linux runs most of them in a
//! worker, so there its completion may come after a later request's; here
//! it runs as its request is issued.

use paludarium_types::Errno;

use super::{IOSQE_FIXED_FILE, Ring, Work, file_of, int_at, u16_at, u32_at, u64_at};
use crate::files::Descriptor;
use crate::syscalls::Context;

pub(super) const OP_FALLOCATE: u8 = 17;
pub(super) const OP_OPENAT: u8 = 18;
pub(super) const OP_CLOSE: u8 = 19;
pub(super) const OP_STATX: u8 = 21;
pub(super) const OP_FADVISE: u8 = 24;
pub(super) const OP_MADVISE: u8 = 25;
pub(super) const OP_OPENAT2: u8 = 28;
pub(super) const OP_RENAMEAT: u8 = 35;
pub(super) const OP_UNLINKAT: u8 = 36;
pub(super) const OP_MKDIRAT: u8 = 37;
pub(super) const OP_SYMLINKAT: u8 = 38;
pub(super) const OP_LINKAT: u8 = 39;
pub(super) const OP_FTRUNCATE: u8 = 55;
pub(super) const OP_PIPE: u8 = 62;

pub(super) const OPS: [u8; 14] = [
    OP_FALLOCATE,
    OP_OPENAT,
    OP_CLOSE,
    OP_STATX,
    OP_FADVISE,
    OP_MADVISE,
    OP_OPENAT2,
    OP_RENAMEAT,
    OP_UNLINKAT,
    OP_MKDIRAT,
    OP_SYMLINKAT,
    OP_LINKAT,
    OP_FTRUNCATE,
    OP_PIPE,
];

const AT_REMOVEDIR: u32 = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000;
/// `VALID_OPEN_FLAGS`, and `O_PATH_FLAGS`.
const VALID_OPEN_FLAGS: u64 = 0o37777703;
const O_PATH_FLAGS: u64 = 0o200000 | 0o400000 | O_PATH | O_CLOEXEC;
/// What `IORING_OP_PIPE` takes, as `pipe2`: `O_CLOEXEC`, `O_NONBLOCK`,
/// `O_DIRECT` and `O_NOTIFICATION_PIPE`.
const PIPE_FLAGS: u32 = 0o2000000 | 0o4000 | 0o40000 | 0o200;

/// A file request, with the names its preparation read and where it read
/// them.
pub(super) struct Fs {
    op: Op,
    names: Vec<(u64, Vec<u8>)>,
}

enum Op {
    /// An open of the first name: how `struct open_how` is read, then what
    /// it says, and the registered slot it goes in, one past its index.
    Open {
        dir: i32,
        how: Option<(u64, u64)>,
        flags: u64,
        mode: u64,
        resolve: u64,
        slot: u32,
    },
    Close {
        fd: i32,
        slot: u32,
    },
    /// The call it runs as, and the addresses of its names among the
    /// arguments, the first of which may be empty with `empty`.
    Call {
        number: u64,
        a: [u64; 6],
        names: [Option<u64>; 2],
        empty: bool,
    },
    /// On an open file: the call, and its arguments after the descriptor.
    File {
        op: u8,
        fd: i32,
        fixed: bool,
        a: [u64; 3],
    },
    Madvise {
        addr: u64,
        len: u64,
        advice: u32,
    },
    /// A pipe, whose ends' numbers go to `at`, in descriptors or from
    /// registered slot `slot` (one past its index).
    Pipe {
        at: u64,
        flags: u32,
        slot: u32,
    },
}

/// The operations' `prep`, but for what they read of the caller's memory.
pub(super) fn prepare(opcode: u8, flags: u8, sqe: &[u8]) -> Result<Work, Errno> {
    let fixed = flags & IOSQE_FIXED_FILE != 0;
    let fd = int_at(sqe, 4);
    let dir = i64::from(fd) as u64;
    let (off, addr) = (u64_at(sqe, 8), u64_at(sqe, 16));
    let (len, rw_flags) = (u32_at(sqe, 24), u32_at(sqe, 28));
    let buf_index = u16_at(sqe, 40);
    let file_index = u32_at(sqe, 44);
    let (addr3, pad2) = (u64_at(sqe, 48), u64_at(sqe, 56));
    // `splice_fd_in` is `file_index`.
    let unused = |any: bool| {
        if buf_index != 0 || any {
            Err(Errno::EINVAL)
        } else {
            Ok(())
        }
    };
    let on_path = || if fixed { Err(Errno::EBADF) } else { Ok(()) };
    let call = |number, a, names, empty| Op::Call {
        number,
        a,
        names,
        empty,
    };
    let op = match opcode {
        // Their `buf_index` and `IOSQE_FIXED_FILE` are looked at once the
        // `struct open_how` is read ([`prepare_memory`]).
        OP_OPENAT | OP_OPENAT2 => {
            let plain = opcode == OP_OPENAT;
            // `build_open_how`.
            let mut open = u64::from(rw_flags) & VALID_OPEN_FLAGS;
            if open & O_PATH != 0 {
                open &= O_PATH_FLAGS;
            }
            let creates = open & (O_CREAT | O_TMPFILE) != 0;
            if plain {
                unused(false)?;
                on_path()?;
            }
            Op::Open {
                dir: fd,
                how: (!plain).then_some((off, u64::from(len))),
                flags: open,
                mode: if creates { u64::from(len) & 0o7777 } else { 0 },
                resolve: u64::from(buf_index) << 32 | u64::from(fixed),
                slot: file_index,
            }
        }
        OP_CLOSE => {
            unused(off != 0 || addr != 0 || len != 0 || rw_flags != 0)?;
            on_path()?;
            if file_index != 0 && fd != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Close {
                fd,
                slot: file_index,
            }
        }
        OP_STATX => {
            unused(file_index != 0)?;
            on_path()?;
            let a = [dir, addr, u64::from(rw_flags), u64::from(len), off, 0];
            call(332, a, [Some(addr), None], rw_flags & AT_EMPTY_PATH != 0)
        }
        OP_RENAMEAT => {
            unused(file_index != 0)?;
            on_path()?;
            let new_dir = i64::from(len as i32) as u64;
            let a = [dir, addr, new_dir, off, u64::from(rw_flags), 0];
            call(316, a, [Some(addr), Some(off)], false)
        }
        OP_UNLINKAT => {
            unused(off != 0 || len != 0 || file_index != 0 || addr3 != 0 || pad2 != 0)?;
            on_path()?;
            if rw_flags & !AT_REMOVEDIR != 0 {
                return Err(Errno::EINVAL);
            }
            let a = [dir, addr, u64::from(rw_flags), 0, 0, 0];
            call(263, a, [Some(addr), None], false)
        }
        OP_MKDIRAT => {
            unused(off != 0 || rw_flags != 0 || file_index != 0)?;
            on_path()?;
            let a = [dir, addr, u64::from(len as u16), 0, 0, 0];
            call(258, a, [Some(addr), None], false)
        }
        OP_SYMLINKAT => {
            unused(len != 0 || rw_flags != 0 || file_index != 0)?;
            on_path()?;
            call(
                266,
                [addr, dir, off, 0, 0, 0],
                [Some(addr), Some(off)],
                false,
            )
        }
        OP_LINKAT => {
            unused(file_index != 0)?;
            on_path()?;
            let new_dir = i64::from(len as i32) as u64;
            let a = [dir, addr, new_dir, off, u64::from(rw_flags), 0];
            let empty = rw_flags & AT_EMPTY_PATH != 0;
            call(265, a, [Some(addr), Some(off)], empty)
        }
        OP_MADVISE => {
            unused(file_index != 0)?;
            Op::Madvise {
                addr,
                len: if off != 0 { off } else { u64::from(len) },
                advice: rw_flags,
            }
        }
        OP_FALLOCATE => {
            unused(rw_flags != 0 || file_index != 0)?;
            Op::File {
                op: opcode,
                fd,
                fixed,
                a: [u64::from(len), off, addr],
            }
        }
        OP_FADVISE => {
            unused(file_index != 0)?;
            let length = if addr != 0 { addr } else { u64::from(len) };
            Op::File {
                op: opcode,
                fd,
                fixed,
                a: [off, length, u64::from(rw_flags)],
            }
        }
        // `io_pipe_prep`: its `buf_index` and `len` are not looked at.
        OP_PIPE => {
            if fd != 0 || off != 0 || addr3 != 0 || rw_flags & !PIPE_FLAGS != 0 {
                return Err(Errno::EINVAL);
            }
            Op::Pipe {
                at: addr,
                flags: rw_flags,
                slot: file_index,
            }
        }
        _ => {
            unused(rw_flags != 0 || addr != 0 || len != 0 || file_index != 0 || addr3 != 0)?;
            Op::File {
                op: opcode,
                fd,
                fixed,
                a: [off, 0, 0],
            }
        }
    };
    Ok(Work::Fs(Box::new(Fs {
        op,
        names: match opcode {
            OP_OPENAT | OP_OPENAT2 => vec![(addr, Vec::new())],
            _ => Vec::new(),
        },
    })))
}

/// The rest of their `prep`: the names (`delayed_getname`: `EFAULT`,
/// `ENAMETOOLONG`, `ENOENT` for an empty one), and before them an
/// `IORING_OP_OPENAT2`'s `struct open_how` (`copy_struct_from_user`).
pub(super) fn prepare_memory(c: &Context<'_>, fs: &mut Fs) -> Result<(), Errno> {
    match &mut fs.op {
        Op::Open {
            how,
            flags,
            mode,
            resolve,
            slot,
            ..
        } => {
            let checks = std::mem::take(resolve);
            if let Some((at, size)) = *how {
                let read = crate::files::copy_struct(c, at, size, 24)?;
                (*flags, *mode, *resolve) = (u64_at(&read, 0), u64_at(&read, 8), u64_at(&read, 16));
                if checks >> 32 != 0 {
                    return Err(Errno::EINVAL);
                }
                if checks & 1 != 0 {
                    return Err(Errno::EBADF);
                }
            }
            fs.names[0].1 = name(c, fs.names[0].0, false)?;
            if *slot != 0 && *flags & O_CLOEXEC != 0 {
                return Err(Errno::EINVAL);
            }
        }
        Op::Call { names, empty, .. } => {
            for (i, at) in names.iter().flatten().enumerate() {
                let read = name(c, *at, i == 0 && *empty)?;
                fs.names.push((*at, read));
            }
        }
        Op::Close { .. } | Op::File { .. } | Op::Madvise { .. } | Op::Pipe { .. } => {}
    }
    Ok(())
}

fn name(c: &Context<'_>, at: u64, empty: bool) -> Result<Vec<u8>, Errno> {
    let name = crate::files::string(c, at)?;
    if name.is_empty() && !empty {
        return Err(Errno::ENOENT);
    }
    Ok(name)
}

/// Runs a file request, and says whether it fails its link: only an open, a
/// close, an `IORING_OP_FADVISE`, a pipe and a file that is not found do
/// (`req_set_fail`).
pub(super) fn run(c: &mut Context<'_>, ring: &Ring, fs: &Fs) -> (i32, bool) {
    let res = |r: Result<u64, Errno>| r.map_or_else(|e| -e.0, |v| v as i32);
    match &fs.op {
        Op::Open {
            dir,
            how,
            flags,
            mode,
            resolve,
            slot,
        } => {
            let done = crate::files::with_names(&fs.names, || {
                let asked = (*flags, *mode, *resolve);
                open(c, *dir, fs.names[0].0, asked, how.is_some(), *slot, ring)
            });
            (done, done < 0)
        }
        Op::Close { fd, slot } => {
            let done = if *slot != 0 {
                res(remove_fixed(ring, *slot - 1))
            } else {
                res(close(c, *fd))
            };
            (done, done < 0)
        }
        Op::Call { number, a, .. } => {
            let done = crate::files::with_names(&fs.names, || crate::files::run(c, *number, *a));
            (res(done), false)
        }
        &Op::Pipe { at, flags, slot } => {
            let done = res(pipe(c, ring, at, flags, slot));
            (done, done < 0)
        }
        Op::Madvise { addr, len, advice } => {
            let a = [*addr, *len, u64::from(*advice), 0, 0, 0];
            (res(crate::syscalls::madvise(c, a)), false)
        }
        Op::File { op, fd, fixed, a } => {
            let found = match file_of(c, ring, *fd, *fixed) {
                Ok(found) => found,
                Err(e) => return (-e.0, true),
            };
            match *op {
                OP_FADVISE => {
                    let done = res(crate::files::fadvise(&found.file, a[0], a[1], a[2]));
                    (done, done < 0)
                }
                OP_FALLOCATE => {
                    let range = (a[1] as i64, a[2] as i64);
                    let done = crate::inotify::unnoticed(|| {
                        crate::files::fallocate_open(c, &found, a[0] as u32, range)
                    });
                    if done.is_ok() {
                        crate::files::notify_open(c, &found, crate::inotify::MODIFY);
                    }
                    (res(done), false)
                }
                _ => (res(crate::files::ftruncate_open(c, &found, a[0])), false),
            }
        }
    }
}

/// `io_openat2`: `build_open_flags`, then the open, which Linux tries
/// without waiting (`O_NONBLOCK`) unless it may create or cut a file, then
/// a descriptor, or a registered slot. `checked` has `openat2`'s checks.
fn open(
    c: &mut Context<'_>,
    dir: i32,
    at: u64,
    (flags, mode, resolve): (u64, u64, u64),
    checked: bool,
    slot: u32,
    ring: &Ring,
) -> i32 {
    let dir = i64::from(dir) as u64;
    let asked = flags;
    let opened: Result<_, Errno> = (|| {
        let (flags, resolve, raw) = if checked {
            crate::files::open_how(c, (flags, mode, resolve), at)?
        } else {
            (flags, 0, crate::files::path(c, at)?)
        };
        let waits = flags & (O_CREAT | O_TRUNC | O_TMPFILE | O_PATH) != 0;
        let nonblock = if waits { 0 } else { O_NONBLOCK };
        let opened = crate::files::open_with(
            c,
            dir,
            raw,
            flags | nonblock,
            mode as u32,
            resolve,
            slot == 0,
        )?;
        if nonblock & !asked != 0 {
            let file = &opened.1.file;
            let _ = file.set_flags(file.flags() & !(O_NONBLOCK as u32));
        }
        Ok(opened)
    })();
    match opened {
        Ok((Some(fd), opened)) => {
            c.files.fill(fd, opened);
            fd as i32
        }
        Ok((None, opened)) => super::net::install_fixed(ring, opened, slot),
        Err(e) => -e.0,
    }
}

/// `io_close`: a ring is `EBADF`.
fn close(c: &mut Context<'_>, fd: i32) -> Result<u64, Errno> {
    let found = c.files.descriptor(u64::from(fd as u32))?;
    if found.file.as_any().is_some_and(|any| any.is::<Ring>()) {
        return Err(Errno::EBADF);
    }
    drop(found);
    crate::files::run(c, 3, [u64::from(fd as u32), 0, 0, 0, 0, 0])
}

/// `io_fixed_fd_remove`: no registered files are `ENXIO`, a slot past them
/// `EINVAL` and an empty one `EBADF`.
fn remove_fixed(ring: &Ring, slot: u32) -> Result<u64, Errno> {
    let mut registered = ring
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let files = registered.as_mut().ok_or(super::ENXIO)?;
    if slot >= files.count {
        return Err(Errno::EINVAL);
    }
    let gone = files.clear(slot).ok_or(Errno::EBADF)?;
    drop(registered);
    ring.put_nodes([gone]);
    Ok(0)
}

/// `io_pipe`: a pipe as `pipe2` makes one ([`crate::files::new_pipe`]), whose
/// ends go in the two lowest free descriptors (`EMFILE`), or in registered
/// slots as [`super::net::install_fixed`] puts a file there: two free ones
/// with `IORING_FILE_INDEX_ALLOC`, otherwise `slot` and the one after it,
/// and `O_CLOEXEC` is `EINVAL` for them. The ends' numbers are written to
/// `at` last (`EFAULT`), which takes back the descriptors or empties the
/// slots, as a second slot that fails empties the first.
fn pipe(c: &mut Context<'_>, ring: &Ring, at: u64, flags: u32, slot: u32) -> Result<u64, Errno> {
    let [reader, writer] = crate::files::new_pipe(c, flags)?;
    let cloexec = flags & O_CLOEXEC as u32 != 0;
    let numbers = |first: u32, second: u32| {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&first.to_le_bytes());
        bytes[4..].copy_from_slice(&second.to_le_bytes());
        crate::files::output(c, at, &bytes)
    };
    if slot == 0 {
        let limit = c.group.nofile();
        let first = c.files.reserve(limit)?;
        let second = c
            .files
            .reserve(limit)
            .inspect_err(|_| c.files.unreserve(first))?;
        if let Err(e) = numbers(first, second) {
            c.files.unreserve(first);
            c.files.unreserve(second);
            return Err(e);
        }
        c.files.fill(first, Descriptor::unnamed(reader, cloexec));
        c.files.fill(second, Descriptor::unnamed(writer, cloexec));
        return Ok(0);
    }
    if cloexec {
        return Err(Errno::EINVAL);
    }
    let alloc = slot == super::FILE_INDEX_ALLOC;
    let installed = |file, slot: u32| {
        let index = super::net::install_fixed(ring, Descriptor::unnamed(file, false), slot);
        match index {
            ..0 => Err(Errno(-index)),
            _ if alloc => Ok(index as u32),
            _ => Ok(slot - 1),
        }
    };
    let first = installed(reader, slot)?;
    let second =
        installed(writer, if alloc { slot } else { slot.wrapping_add(1) }).inspect_err(|_| {
            let _ = remove_fixed(ring, first);
        })?;
    numbers(first, second).inspect_err(|_| {
        let _ = remove_fixed(ring, first);
        let _ = remove_fixed(ring, second);
    })?;
    Ok(0)
}
