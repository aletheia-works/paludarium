//! io_uring's `IORING_OP_SPLICE` and `IORING_OP_TEE`, as Linux's
//! `io_uring/splice.c` has them.
//!
//! Linux runs them in a worker, which waits. Here they run as their request
//! is issued, and one that would wait waits for its file, as the requests
//! Linux runs without waiting do ([`super::arm`]).

use std::sync::Arc;

use paludarium_host::FileHandle;
use paludarium_types::Errno;

use super::{
    IOSQE_FIXED_FILE, POLL_IN_EVENTS, POLL_OUT_EVENTS, POLL_UNMASK, Ring, Waits, Work, file_of,
    int_at, ready, u32_at, u64_at,
};
use crate::files::Descriptor;
use crate::syscalls::Context;

pub(super) const OP_SPLICE: u8 = 30;
pub(super) const OP_TEE: u8 = 33;

/// `SPLICE_F_*`, and io_uring's own `SPLICE_F_FD_IN_FIXED`.
const F_NONBLOCK: u32 = 2;
const F_ALL: u32 = 0xf;
const F_FD_IN_FIXED: u32 = 1 << 31;

/// `struct io_splice`, and the files it found, the output first.
pub(super) struct Splice {
    tee: bool,
    out: (i32, bool),
    input: i32,
    off_in: u64,
    off_out: u64,
    len: u32,
    flags: u32,
    found: Option<(Descriptor, Descriptor)>,
}

/// `io_splice_prep` and `io_tee_prep`.
pub(super) fn prepare(opcode: u8, sqe_flags: u8, sqe: &[u8]) -> Result<Work, Errno> {
    let tee = opcode == OP_TEE;
    let (off_out, off_in) = (u64_at(sqe, 8), u64_at(sqe, 16));
    let flags = u32_at(sqe, 28);
    if tee && (off_in != 0 || off_out != 0) || flags & !(F_ALL | F_FD_IN_FIXED) != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(Work::Splice(Box::new(Splice {
        tee,
        out: (int_at(sqe, 4), sqe_flags & IOSQE_FIXED_FILE != 0),
        input: int_at(sqe, 44),
        off_in,
        off_out,
        len: u32_at(sqe, 24),
        flags,
        found: None,
    })))
}

/// Runs one: its result, whether it failed, which moving fewer bytes than it
/// asked for is, and what it waits for.
pub(super) fn run(
    c: &mut Context<'_>,
    ring: &Ring,
    splice: &mut Splice,
) -> (i32, u32, bool, Option<Waits>) {
    let files = match &splice.found {
        Some(found) => Ok(found.clone()),
        None => file_of(c, ring, splice.out.0, splice.out.1).and_then(|out| {
            let fixed = splice.flags & F_FD_IN_FIXED != 0;
            Ok((out, file_of(c, ring, splice.input, fixed)?))
        }),
    };
    let (out, input) = match files {
        Ok(files) => files,
        Err(e) => return (-e.0, 0, true, None),
    };
    let result = issue(c, splice, &input, &out);
    match result {
        Ok(count) => (count as i32, 0, count != u64::from(splice.len), None),
        Err(Wait::Failed(e)) => (-e.0, 0, true, None),
        Err(wait) => {
            let (file, mask): (Arc<dyn FileHandle>, u32) = match wait {
                Wait::Held => {
                    let pipes = (Arc::clone(&input.file), Arc::clone(&out.file));
                    let unheld = crate::files::splice::Unheld(pipes.0, pipes.1);
                    (Arc::new(unheld), POLL_IN_EVENTS)
                }
                Wait::For(true) => (Arc::clone(&input.file), POLL_IN_EVENTS),
                _ => (Arc::clone(&out.file), POLL_OUT_EVENTS),
            };
            let waits = Waits {
                file,
                mask: POLL_UNMASK | mask,
                kept: None,
                found: (out.clone(), None),
            };
            splice.found = Some((out, input));
            (0, 0, false, Some(waits))
        }
    }
}

enum Wait {
    Failed(Errno),
    /// The input has nothing, or else the output no room.
    For(bool),
    /// Another call holds a pipe of it, which Linux's worker waits for.
    Held,
}

fn issue(
    c: &mut Context<'_>,
    splice: &Splice,
    input: &Descriptor,
    out: &Descriptor,
) -> Result<u64, Wait> {
    if splice.len == 0 {
        return Ok(0);
    }
    let offset = |at: u64| (at != u64::MAX).then_some(at);
    let (off_in, off_out) = if splice.tee {
        (None, None)
    } else {
        (offset(splice.off_in), offset(splice.off_out))
    };
    let files = (&input.file, &out.file);
    crate::files::splice::check(files.0, off_in, files.1, off_out, splice.tee)
        .map_err(Wait::Failed)?;
    let flags = splice.flags & F_ALL;
    let waits = crate::files::splice::waits(files.0, files.1, flags);
    let side = || {
        if !ready(files.0, POLL_IN_EVENTS | POLL_UNMASK) {
            Some(true)
        } else if !ready(files.1, POLL_OUT_EVENTS | POLL_UNMASK) {
            Some(false)
        } else {
            None
        }
    };
    if waits && let Some(input_side) = side() {
        return Err(Wait::For(input_side));
    }
    let len = u64::from(splice.len);
    let flags = flags | F_NONBLOCK | crate::files::splice::TRY_HOLD;
    let result = if splice.tee {
        crate::files::splice::do_tee(c, files.0, files.1, len, flags)
    } else {
        crate::files::splice::do_splice(c, files.0, off_in, files.1, off_out, len, flags)
            .map(|(count, _)| count)
    };
    match result {
        Err(Errno::EAGAIN) if waits && let Some(input_side) = side() => Err(Wait::For(input_side)),
        Err(crate::files::splice::HELD) => Err(Wait::Held),
        Err(e) => Err(Wait::Failed(e)),
        Ok(count) => {
            if count > 0 {
                // `fsnotify_modify(out)`, then `fsnotify_access(in)`.
                crate::files::notify_open(c, out, crate::inotify::MODIFY);
                crate::files::notify_open(c, input, crate::inotify::ACCESS);
            }
            Ok(count)
        }
    }
}
