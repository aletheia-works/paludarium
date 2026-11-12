//! `process_vm_readv` and `process_vm_writev`, as Linux's
//! `mm/process_vm_access.c`: the copy between the caller's buffers and
//! another task's memory, once [`crate::processes`] has found the task and
//! checked that the caller may reach it.
use paludarium_mmu::{AddressSpace, MemoryView};
use paludarium_types::{Errno, GuestAddr};

const PAGE: u64 = 4096;
/// Linux's `UIO_MAXIOV`.
const MAX_SEGMENTS: u64 = 1024;

/// The calls' checks before the task is looked up, in Linux's order:
/// `flags` must be 0 (`EINVAL`); the local iovec array is read as
/// `import_iovec` reads it ([`crate::files::iovecs_checked`]), and with no
/// bytes to copy the call does nothing; then the remote one as
/// `iovec_from_user` does: none for no entries, more than `UIO_MAXIOV`
/// `EINVAL`, an array outside the user half or not mapped `EFAULT`, and a
/// negative length `EINVAL`, its buffers not looked at. `None` when there is
/// nothing to copy: every remote length is 0, which Linux finds before it
/// looks for the task.
pub(crate) fn segments(mem: &AddressSpace, a: [u64; 6]) -> Result<Option<Segments>, Errno> {
    if a[5] != 0 {
        return Err(Errno::EINVAL);
    }
    let local = crate::files::iovecs_checked(mem, a[1], a[2], |_, _| Ok(()))?;
    if local.iter().all(|&(_, length)| length == 0) {
        return Ok(None);
    }
    let (at, count) = (a[3], a[4]);
    let mut remote = Vec::new();
    if count > MAX_SEGMENTS {
        return Err(Errno::EINVAL);
    }
    if count != 0 {
        crate::sockets::access_ok(at, (count * 16) as usize)?;
    }
    for index in 0..count {
        let addr = GuestAddr(at + index * 16);
        let base = mem.read_u64(addr).map_err(|_| Errno::EFAULT)?;
        let length = mem
            .read_u64(GuestAddr(addr.0 + 8))
            .map_err(|_| Errno::EFAULT)?;
        if (length as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        remote.push((base, length));
    }
    if remote.iter().all(|&(_, length)| length == 0) {
        return Ok(None);
    }
    Ok(Some(Segments { local, remote }))
}

/// The buffers of one call: the caller's, cut as `import_iovec` cuts them,
/// and the other task's.
pub(crate) struct Segments {
    local: Vec<(u64, usize)>,
    remote: Vec<(u64, u64)>,
}

/// The caller's buffers as Linux's `iov_iter` walks them: where the next
/// byte goes or comes from.
struct Local<'a> {
    mem: &'a AddressSpace,
    segments: &'a [(u64, usize)],
    index: usize,
    offset: usize,
    /// The bytes not yet copied, `iov_iter_count`.
    left: u64,
}

impl Local<'_> {
    /// The next stretch of at most `most` bytes that lies in one page of
    /// one segment, if any is left.
    fn next(&mut self, most: usize) -> Option<(u64, usize)> {
        while let Some(&(base, length)) = self.segments.get(self.index) {
            if self.offset < length {
                let at = base.wrapping_add(self.offset as u64);
                let in_page = (PAGE - at % PAGE) as usize;
                return Some((at, most.min(length - self.offset).min(in_page)));
            }
            self.index += 1;
            self.offset = 0;
        }
        None
    }
    /// Writes `bytes` to the caller's buffers, a page at a time as
    /// `copy_to_user` stops at the first that may not be written: how many
    /// were.
    fn put(&mut self, mut bytes: &[u8]) -> usize {
        let mut done = 0;
        while !bytes.is_empty() {
            let Some((at, n)) = self.next(bytes.len()) else {
                break;
            };
            if self.mem.write(GuestAddr(at), &bytes[..n]).is_err() {
                break;
            }
            self.offset += n;
            self.left -= n as u64;
            done += n;
            bytes = &bytes[n..];
        }
        done
    }
    /// Reads up to `buf.len()` bytes from the caller's buffers into `buf`,
    /// as `copy_from_user` stops at the first page that may not be read:
    /// how many were.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let mut done = 0;
        while done < buf.len() {
            let Some((at, n)) = self.next(buf.len() - done) else {
                break;
            };
            if self
                .mem
                .read(GuestAddr(at), &mut buf[done..done + n])
                .is_err()
            {
                break;
            }
            self.offset += n;
            self.left -= n as u64;
            done += n;
        }
        done
    }
}

/// Copies between the caller's memory `mem` and the task's `target`, as
/// Linux's `process_vm_rw_core`: each remote buffer in turn, a page of it
/// at a time, while the caller's buffers have room. A remote page that may
/// not be read (or, with `write`, written) ends the copy with `EFAULT`, as
/// does a local page that cannot take or give its bytes; the bytes copied
/// before are the result if there are any.
pub(crate) fn transfer(
    mem: &AddressSpace,
    target: &MemoryView,
    segments: &Segments,
    write: bool,
) -> Result<u64, Errno> {
    let mut local = Local {
        mem,
        segments: &segments.local,
        index: 0,
        offset: 0,
        left: segments
            .local
            .iter()
            .map(|&(_, length)| length as u64)
            .sum(),
    };
    let mut copied = 0u64;
    let mut failed = false;
    'remote: for &(base, length) in &segments.remote {
        let (mut at, mut left) = (base, length);
        while left > 0 {
            let room = local.left;
            if room == 0 {
                break 'remote;
            }
            let n = (PAGE - at % PAGE).min(left).min(room) as usize;
            let mut page = vec![0; n];
            let done = if write {
                let taken = local.take(&mut page);
                let written = target.write_pages(at, &page[..taken]).unwrap_or(0);
                if written < taken {
                    // The remote page would not be pinned: nothing of it.
                    failed = true;
                    break 'remote;
                }
                taken
            } else {
                if target.read_pages(at, &mut page).unwrap_or(0) < n {
                    failed = true;
                    break 'remote;
                }
                local.put(&page)
            };
            copied += done as u64;
            if done < n {
                failed = true;
                break 'remote;
            }
            left -= n as u64;
            let Some(next) = at.checked_add(n as u64) else {
                failed = true;
                break 'remote;
            };
            at = next;
        }
    }
    if copied == 0 && failed {
        return Err(Errno::EFAULT);
    }
    Ok(copied)
}
