//! `splice`, `tee` and `vmsplice`, as Linux's `fs/splice.c` has them: bytes
//! move between a pipe and another file, or between two pipes, without the
//! guest copying them. A pipe here is a queue of bytes and not of page
//! buffers, so one holds as many bytes as its size, however they came.
use super::{
    MAX_RW_COUNT, O_APPEND, O_PATH, REGULAR, buffer, iovecs_checked, offset_argument, read_at,
    read_limit, read_waiting, size_room, write_at, write_io,
};
use crate::sockets::PipeEnd;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};
use std::sync::Arc;

/// SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE and SPLICE_F_GIFT. Moving
/// and gifting pages are hints a copy needs not, and "more" only tells a
/// socket that more data comes.
const SPLICE_F_ALL: u32 = 0xf;
const SPLICE_F_NONBLOCK: u32 = 2;
const EPIPE: Errno = Errno(32);
const CHARACTER: u32 = 0o020000;
const BLOCK: u32 = 0o060000;
const SOCKET: u32 = 0o140000;

/// The file of descriptor `fd`, as Linux's `fdget`, which no `O_PATH`
/// descriptor passes.
fn file(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    if file.flags() & O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// `FMODE_READ`.
fn readable(file: &Arc<dyn FileHandle>) -> bool {
    file.flags() & 3 != 1
}
/// `FMODE_WRITE`.
fn writable(file: &Arc<dyn FileHandle>) -> bool {
    file.flags() & 3 != 0
}
/// `O_NONBLOCK` of the open file description.
fn nonblocking(file: &Arc<dyn FileHandle>) -> bool {
    file.flags() & crate::events::NONBLOCK != 0
}
/// The pipe, or FIFO, `file` is (Linux's `get_pipe_info`).
fn pipe(file: &Arc<dyn FileHandle>) -> Option<&PipeEnd> {
    crate::sockets::pipe(file)
}
/// Whether `file` has the `splice_read` and `splice_write` of its kind: a
/// regular file, a device, a socket or one of the host's standard streams,
/// but not a directory, nor an eventfd, a timerfd, a signalfd or another
/// file of no type.
fn spliceable(file: &Arc<dyn FileHandle>) -> Result<bool, Errno> {
    Ok(super::standard(file).is_some()
        || matches!(
            file.stat()?.mode & 0o170000,
            REGULAR | CHARACTER | BLOCK | SOCKET
        ))
}
/// Whether an offset for `file` is ESPIPE: a pipe's, or one of the host's
/// standard streams', which stand for the pipes a guest's are on Linux.
fn unpositioned(file: &Arc<dyn FileHandle>) -> bool {
    pipe(file).is_some() || super::standard(file).is_some()
}
/// Whether a file has a position that `pread` and `pwrite` use
/// (`FMODE_PREAD`, `FMODE_PWRITE`): not a socket nor a terminal.
fn positioned(file: &Arc<dyn FileHandle>) -> bool {
    file.seek(0, 1).is_ok()
}
/// `rw_verify_area` for `count` bytes from `position`: a count or an offset
/// that is negative, or an end past the largest offset, is EINVAL.
fn verify_area(position: u64, count: u64) -> Result<(), Errno> {
    if (count as i64) < 0 || (position as i64) < 0 || (position.wrapping_add(count) as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
/// SIGPIPE to the calling thread's process, as `send_sig(SIGPIPE, current,
/// 0)` gives it with the EPIPE of a pipe that no one reads.
fn broken_pipe(c: &mut Context<'_>) -> Errno {
    crate::signals::queue(c.process, crate::signals::PendingSignal::user(13, 0));
    EPIPE
}
/// Waits for some file to change, as `pipe_wait_readable` and
/// `pipe_wait_writable` sleep; a signal ends it with EINTR, which is
/// restarted as Linux's ERESTARTSYS is.
fn wait(c: &mut Context<'_>, ticket: u32) -> Result<(), Errno> {
    crate::events::wait(c, ticket, None)
}
/// Takes `count` bytes, already looked at, from the pipe `file` reads,
/// which tells its writers there is room.
fn consume(file: &Arc<dyn FileHandle>, count: usize) -> Result<(), Errno> {
    if count == 0 {
        return Ok(());
    }
    let mut taken = buffer(count)?;
    file.read(&mut taken)?;
    crate::sockets::pipe_read_ended(file);
    Ok(())
}
/// Waits until the pipe `output` has room, as `wait_for_space` does: no
/// reader is EPIPE with SIGPIPE, and a full pipe EAGAIN with `nonblock`.
fn wait_for_space(c: &mut Context<'_>, output: &PipeEnd, nonblock: bool) -> Result<(), Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        if !output.has_readers() {
            return Err(broken_pipe(c));
        }
        if output.room() > 0 {
            return Ok(());
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        wait(c, ticket)?;
    }
}
/// Waits until the pipe `input` has data, as `splice_from_pipe_next` does:
/// `false` when it has none to give, as no one writes it or `done` bytes
/// already went, and EAGAIN with `nonblock`.
fn wait_for_data(
    c: &mut Context<'_>,
    input: &PipeEnd,
    nonblock: bool,
    done: u64,
) -> Result<bool, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        if input.unread_bytes() > 0 {
            return Ok(true);
        }
        if !input.has_writers() || done > 0 {
            return Ok(false);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        wait(c, ticket)?;
    }
}

/// `splice(fd_in, off_in, fd_out, off_out, len, flags)`, in the order of
/// Linux's: no bytes is 0 before anything is looked at, then the flags, the
/// descriptors, an offset for a pipe (ESPIPE) and reading the offsets
/// (EFAULT), then [`do_splice`]. The offset used is written back once the
/// call succeeds.
pub(super) fn splice(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (len, flags) = (a[4], a[5] as u32);
    if len == 0 {
        return Ok(0);
    }
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let input = file(c, a[0])?;
    let output = file(c, a[2])?;
    if unpositioned(&input) && a[1] != 0 || unpositioned(&output) && a[3] != 0 {
        return Err(Errno::ESPIPE);
    }
    let off_out = offset_argument(c, a[3])?;
    let off_in = offset_argument(c, a[1])?;
    let (count, offset) = do_splice(c, &input, off_in, &output, off_out, len, flags)?;
    if let Some(offset) = offset {
        let at = if off_out.is_some() { a[3] } else { a[1] };
        c.mem
            .write_u64(GuestAddr(at), offset)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(count)
}
/// Linux's `do_splice`: the input must be readable and the output writable
/// (EBADF), and one of them a pipe (EINVAL); two pipes must differ. Returns
/// the bytes moved and the new value of the offset passed, if any.
fn do_splice(
    c: &mut Context<'_>,
    input: &Arc<dyn FileHandle>,
    off_in: Option<u64>,
    output: &Arc<dyn FileHandle>,
    off_out: Option<u64>,
    len: u64,
    flags: u32,
) -> Result<(u64, Option<u64>), Errno> {
    if !readable(input) || !writable(output) {
        return Err(Errno::EBADF);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    match (pipe(input), pipe(output)) {
        (Some(from), Some(to)) => {
            if from.same_pipe(to) {
                return Err(Errno::EINVAL);
            }
            let nonblock = nonblock || nonblocking(input) || nonblocking(output);
            Ok((pipe_to_pipe(c, input, from, to, len, nonblock)?, None))
        }
        (Some(from), None) => {
            let start = match off_out {
                Some(_) if !positioned(output) => return Err(Errno::EINVAL),
                Some(offset) => offset,
                None => output.seek(0, 1).unwrap_or(0),
            };
            if output.flags() & O_APPEND != 0 {
                return Err(Errno::EINVAL);
            }
            verify_area(start, len)?;
            if !spliceable(output)? {
                return Err(Errno::EINVAL);
            }
            let nonblock = nonblock || nonblocking(input);
            let sent = from_pipe(
                c,
                input,
                from,
                output,
                start,
                off_out.is_some(),
                len,
                nonblock,
            )?;
            let end = start + sent;
            if off_out.is_none() && positioned(output) {
                output.seek(end as i64, 0)?;
            }
            Ok((sent, off_out.map(|_| end)))
        }
        (None, Some(to)) => {
            let start = match off_in {
                Some(_) if !positioned(input) => return Err(Errno::EINVAL),
                Some(offset) => offset,
                None => input.seek(0, 1).unwrap_or(0),
            };
            verify_area(start, len)?;
            let nonblock = nonblock || nonblocking(output);
            let read = to_pipe(c, input, start, off_in.is_some(), output, to, len, nonblock)?;
            let end = start + read;
            if off_in.is_none() && input.stat()?.mode & 0o170000 == REGULAR {
                input.seek(end as i64, 0)?;
            }
            Ok((read, off_in.map(|_| end)))
        }
        (None, None) => Err(Errno::EINVAL),
    }
}
/// From the pipe `from` (the description `input`) to the file `output` at
/// `start`, as `iter_file_splice_write` and `splice_to_socket` take what
/// the pipe has, up to `len`, waiting for some; an error after some bytes
/// went ends the call with their count. A socket's send waits as its own
/// `O_NONBLOCK` says, not SPLICE_F_NONBLOCK, and a broken one raises SIGPIPE.
#[expect(clippy::too_many_arguments, reason = "both ends of the splice")]
fn from_pipe(
    c: &mut Context<'_>,
    input: &Arc<dyn FileHandle>,
    from: &PipeEnd,
    output: &Arc<dyn FileHandle>,
    start: u64,
    at_offset: bool,
    len: u64,
    nonblock: bool,
) -> Result<u64, Errno> {
    let kind = output.stat()?.mode & 0o170000;
    let mut done = 0;
    while done < len {
        if !wait_for_data(c, from, nonblock, done)? {
            break;
        }
        let want = usize::try_from(len - done)
            .unwrap_or(usize::MAX)
            .min(from.unread_bytes())
            .min(MAX_RW_COUNT);
        let mut piece = buffer(want)?;
        let count = from.peek(&mut piece);
        let piece = &piece[..count];
        let written = if kind == REGULAR {
            size_room(c, start + done).and_then(|room| {
                let room = usize::try_from(room).unwrap_or(usize::MAX);
                let written = write_at(output, start + done, &piece[..count.min(room)])?;
                if written > 0 {
                    crate::permissions::remove_set_ids(&c.process.credentials, &**output);
                }
                Ok(written as u64)
            })
        } else if at_offset {
            write_at(output, start + done, piece).map(|n| n as u64)
        } else {
            write_io(c, output, piece, false)
        };
        match written {
            Ok(0) => break,
            Ok(written) => {
                consume(input, usize::try_from(written).unwrap_or(usize::MAX))?;
                done += written;
            }
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}
/// From the file `input` at `start` to the pipe `to` (the description
/// `output`), as `splice_file_to_pipe`: once the pipe has room
/// ([`wait_for_space`]), at most what fits, which a regular file gives from
/// its offset up to its end. A unix stream socket's read does not wait with
/// `nonblock`; other files read as their own `O_NONBLOCK` says.
#[expect(clippy::too_many_arguments, reason = "both ends of the splice")]
fn to_pipe(
    c: &mut Context<'_>,
    input: &Arc<dyn FileHandle>,
    start: u64,
    at_offset: bool,
    output: &Arc<dyn FileHandle>,
    to: &PipeEnd,
    len: u64,
    nonblock: bool,
) -> Result<u64, Errno> {
    wait_for_space(c, to, nonblock)?;
    let len = len.min(to.room() as u64);
    verify_area(start, len)?;
    let len = len.min(MAX_RW_COUNT as u64);
    if !spliceable(input)? {
        return Err(Errno::EINVAL);
    }
    let metadata = input.stat()?;
    let read = if metadata.mode & 0o170000 == REGULAR {
        let len = len.min(read_limit(input, &metadata).saturating_sub(start));
        let mut piece = buffer(usize::try_from(len).unwrap_or(usize::MAX))?;
        let read = read_at(input, start, &mut piece)?;
        piece.truncate(read);
        piece
    } else {
        let mut piece = buffer(usize::try_from(len).unwrap_or(usize::MAX))?;
        let read = if at_offset {
            read_at(input, start, &mut piece)?
        } else {
            let stream = crate::sockets::endpoint(input)
                .is_some_and(crate::sockets::SocketPairEnd::raises_sigpipe);
            read_waiting(c, input, &mut piece, nonblock && stream)?
        };
        piece.truncate(read);
        piece
    };
    if read.is_empty() {
        return Ok(0);
    }
    Ok(output.write(&read)? as u64)
}
/// Two pipes, as `splice_pipe_to_pipe`: once the input has data and the
/// output room (`ipipe_prep`, `opipe_prep`), as much as both allow, up to
/// `len`, taken from the input.
fn pipe_to_pipe(
    c: &mut Context<'_>,
    input: &Arc<dyn FileHandle>,
    from: &PipeEnd,
    to: &PipeEnd,
    len: u64,
    nonblock: bool,
) -> Result<u64, Errno> {
    loop {
        let count = link(c, from, to, len, nonblock, true)?;
        if let Some(count) = count {
            consume(input, count)?;
            return Ok(count as u64);
        }
    }
}
/// `tee(fd_in, fd_out, len, flags)`, in the order of Linux's: the flags,
/// then no bytes is 0, the descriptors (EBADF), and `do_tee`, which copies
/// what the input pipe has to the output pipe, leaving it in the input.
pub(super) fn tee(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (len, flags) = (a[2], a[3] as u32);
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    let input = file(c, a[0])?;
    let output = file(c, a[1])?;
    if !readable(&input) || !writable(&output) {
        return Err(Errno::EBADF);
    }
    let (Some(from), Some(to)) = (pipe(&input), pipe(&output)) else {
        return Err(Errno::EINVAL);
    };
    if from.same_pipe(to) {
        return Err(Errno::EINVAL);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0 || nonblocking(&input) || nonblocking(&output);
    Ok(link(c, from, to, len, nonblock, false)?.unwrap_or(0) as u64)
}
/// What `ipipe_prep`, `opipe_prep` and then `link_pipe` or the loop of
/// `splice_pipe_to_pipe` do: wait for data in `from` (none, with no writer,
/// goes on) and room in `to`, then copy as much of `len` as both allow. A
/// pipe no one reads is EPIPE with SIGPIPE. With nothing to copy, a `tee`
/// gives 0 and a `splice` (`retry`) `None` to start again, unless no one
/// writes the input, which ends it with 0.
fn link(
    c: &mut Context<'_>,
    from: &PipeEnd,
    to: &PipeEnd,
    len: u64,
    nonblock: bool,
    retry: bool,
) -> Result<Option<usize>, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        if from.unread_bytes() > 0 || !from.has_writers() {
            break;
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        wait(c, ticket)?;
    }
    loop {
        let ticket = c.files.readiness.token.value();
        if to.room() > 0 {
            break;
        }
        if !to.has_readers() {
            return Err(broken_pipe(c));
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        wait(c, ticket)?;
    }
    if !to.has_readers() {
        return Err(broken_pipe(c));
    }
    let unread = from.unread_bytes();
    if unread == 0 && !from.has_writers() {
        return Ok(Some(0));
    }
    if unread == 0 || to.room() == 0 {
        return Ok((!retry).then_some(0));
    }
    let count = usize::try_from(len)
        .unwrap_or(usize::MAX)
        .min(unread)
        .min(to.room());
    let mut piece = buffer(count)?;
    let count = from.peek(&mut piece);
    let written = to.write(&piece[..count])?;
    Ok(Some(written))
}
/// `vmsplice(fd, iov, nr_segs, flags)`, in the order of Linux's: the flags,
/// the descriptor (EBADF, also with neither access), the vector as
/// `import_iovec` reads it, then the pipe (EBADF for any other file). A
/// pipe opened for writing takes the guest's bytes, one opened only for
/// reading gives them; either way only SPLICE_F_NONBLOCK keeps it from
/// waiting, not the pipe's `O_NONBLOCK`.
pub(super) fn vmsplice(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[3] as u32;
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let file = file(c, a[0])?;
    let write = writable(&file);
    if !write && !readable(&file) {
        return Err(Errno::EBADF);
    }
    let segments = iovecs_checked(c.mem, a[1], a[2], |_, _| Ok(()))?;
    if segments.iter().all(|&(_, length)| length == 0) {
        return Ok(0);
    }
    let pipe = pipe(&file).ok_or(Errno::EBADF)?;
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    if write {
        to_pipe_from_guest(c, &file, pipe, &segments, nonblock)
    } else {
        from_pipe_to_guest(c, &file, pipe, &segments, nonblock)
    }
}
/// `vmsplice_to_pipe`: once the pipe has room, the bytes of the guest's
/// buffers that fit, up to the first that cannot be read (EFAULT if that is
/// the first byte).
fn to_pipe_from_guest(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    to: &PipeEnd,
    segments: &[(u64, usize)],
    nonblock: bool,
) -> Result<u64, Errno> {
    wait_for_space(c, to, nonblock)?;
    let mut room = to.room();
    let mut bytes = Vec::new();
    for &(base, length) in segments {
        let mut piece = buffer(length.min(room))?;
        if c.mem.read(GuestAddr(base), &mut piece).is_err() {
            // What of the buffer can be read, page by page.
            let mut read = 0;
            while read < piece.len() {
                let page = (4096 - (base + read as u64) % 4096) as usize;
                let end = (read + page).min(piece.len());
                if c.mem
                    .read(GuestAddr(base + read as u64), &mut piece[read..end])
                    .is_err()
                {
                    break;
                }
                read = end;
            }
            bytes.extend_from_slice(&piece[..read]);
            break;
        }
        room -= piece.len();
        bytes.extend_from_slice(&piece);
        if room == 0 {
            break;
        }
    }
    if bytes.is_empty() {
        return Err(Errno::EFAULT);
    }
    Ok(file.write(&bytes)? as u64)
}
/// `vmsplice_to_user`: what the pipe has, up to the buffers' size, once it
/// has some, which only SPLICE_F_NONBLOCK stops it waiting for; a buffer
/// that cannot be written is EFAULT, or ends the call after some bytes.
fn from_pipe_to_guest(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    from: &PipeEnd,
    segments: &[(u64, usize)],
    nonblock: bool,
) -> Result<u64, Errno> {
    let mut done = 0;
    for &(base, length) in segments {
        let mut at = 0;
        while at < length {
            if !wait_for_data(c, from, nonblock, done)? {
                return Ok(done);
            }
            let mut piece = buffer((length - at).min(from.unread_bytes()))?;
            let count = from.peek(&mut piece);
            if c.mem
                .write(GuestAddr(base + at as u64), &piece[..count])
                .is_err()
            {
                return if done > 0 {
                    Ok(done)
                } else {
                    Err(Errno::EFAULT)
                };
            }
            consume(file, count)?;
            at += count;
            done += count as u64;
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::verify_area;
    use paludarium_types::Errno;

    #[test]
    fn areas_past_the_largest_offset_are_invalid() {
        assert_eq!(verify_area(0, 1), Ok(()));
        assert_eq!(verify_area(u64::MAX, 1), Err(Errno::EINVAL));
        assert_eq!(verify_area(0, 1 << 63), Err(Errno::EINVAL));
        assert_eq!(verify_area(i64::MAX as u64, 1), Err(Errno::EINVAL));
        assert_eq!(verify_area(i64::MAX as u64 - 1, 1), Ok(()));
    }
}
