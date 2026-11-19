//! `PAGEMAP_SCAN`, the ioctl of `/proc/<pid>/pagemap`, as Linux master's
//! `do_pagemap_scan` in `fs/proc/task_mmu.c` serves it: it finds the pages of
//! a range by their categories ([`paludarium_mmu::scan`]), reports them as
//! regions in the caller's buffer, and can write-protect the written ones for
//! a `userfaultfd` with `UFFD_FEATURE_WP_ASYNC`.
//!
//! The walk itself is [`MemoryView::pagemap_scan`]'s. This module reads and
//! checks the request, runs the walks, as Linux does with its bounce buffer of
//! at most 512 regions, and writes the regions and `walk_end` back.

use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_mmu::{MemoryView, Scan, ScanStop, scan};
use paludarium_types::{Errno, GuestAddr};
use std::sync::Arc;

/// `_IOWR('f', 16, struct pm_scan_arg)`.
pub(crate) const PAGEMAP_SCAN: u32 = 0xc060_6610;

/// `sizeof(struct pm_scan_arg)`: 12 words.
const ARG_SIZE: u64 = 96;

/// `sizeof(struct page_region)`: start, end and categories.
const REGION_SIZE: u64 = 24;

/// `PM_SCAN_WP_MATCHING`.
const WP_MATCHING: u64 = 1;

/// `PM_SCAN_CHECK_WPASYNC`.
const CHECK_WPASYNC: u64 = 2;

/// The regions one walk holds at most (`PAGEMAP_WALK_SIZE >> PAGE_SHIFT`).
const WALK_REGIONS: u64 = 512;

/// Linux's `TASK_SIZE_MAX` with 4-level page tables, where `access_ok` stops.
const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;

const PAGE: u64 = 4096;

/// `ESRCH`, which [`Errno`] does not name.
const ESRCH: Errno = Errno(3);

/// The ioctl of a `pagemap` file, if `file` is one (`do_pagemap_cmd`):
/// `PAGEMAP_SCAN`, and `ENOTTY` for any other, as Linux master's
/// `-ENOIOCTLCMD` gives it (Linux 7.0's is `EINVAL`).
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    cmd: u64,
    arg: u64,
) -> Option<Result<u64, Errno>> {
    let pagemap = file.as_any()?.downcast_ref::<crate::proc::PagemapFile>()?;
    Some(if cmd as u32 == PAGEMAP_SCAN {
        scan_pages(c, pagemap.memory(), arg)
    } else {
        Err(Errno::ENOTTY)
    })
}

/// Linux's `access_ok` of `size` bytes at `addr`: none past `TASK_SIZE_MAX`.
fn access_ok(addr: u64, size: u64) -> bool {
    addr.checked_add(size)
        .is_some_and(|end| end <= TASK_SIZE_MAX)
}

/// `do_pagemap_scan` of the `struct pm_scan_arg` at `arg` on `memory`.
///
/// The space must still live (`ESRCH`, as master's `mmget_not_zero`). The
/// request must be readable (`EFAULT`), of its size (`EINVAL`), with known
/// flags and categories (`EINVAL`, which takes master's
/// `PAGE_IS_ACCESSED`), from a page boundary (`EINVAL`) over a range of
/// user space (`EFAULT`), with a buffer if it has a length (`EINVAL`), in
/// user space (`EFAULT`) (`pagemap_scan_get_args`). Then walks run from the
/// start until one ends the range, fails, or stops for want of room with
/// room left in the buffer and pages left to report; each writes its
/// regions to the buffer (`EFAULT`). It gives the number of regions, and
/// writes where it stopped, or the end, to `walk_end` (`EFAULT`).
fn scan_pages(c: &Context<'_>, memory: &MemoryView, arg: u64) -> Result<u64, Errno> {
    if memory.pagemap(0, 0).is_none() {
        return Err(ESRCH);
    }
    let mut bytes = [0; ARG_SIZE as usize];
    c.mem
        .read(GuestAddr(arg), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let mut words = [0u64; 12];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    let [
        size,
        flags,
        start,
        end,
        _,
        vec,
        vec_len,
        max_pages,
        inverted,
        required,
        any_of,
        returned,
    ] = words;
    if size != ARG_SIZE
        || flags & !(WP_MATCHING | CHECK_WPASYNC) != 0
        || (inverted | required | any_of | returned) & !scan::ALL != 0
        || !start.is_multiple_of(PAGE)
    {
        return Err(Errno::EINVAL);
    }
    if !access_ok(start, end.wrapping_sub(start)) {
        return Err(Errno::EFAULT);
    }
    if vec == 0 && vec_len != 0 {
        return Err(Errno::EINVAL);
    }
    if vec != 0 && !access_ok(vec, vec_len.saturating_mul(REGION_SIZE)) {
        return Err(Errno::EFAULT);
    }
    let end = end.next_multiple_of(PAGE);
    let mut request = Scan {
        end,
        write_protect: flags & WP_MATCHING != 0,
        check_wp_async: flags & CHECK_WPASYNC != 0,
        inverted,
        required,
        any_of,
        returned,
        max_pages: if max_pages == 0 { u64::MAX } else { max_pages },
        found: 0,
        walk_end: 0,
    };
    let (mut out, mut room) = (vec, vec_len);
    // The bounce buffer, which shrinks to the room left.
    let mut capacity = (vec_len != 0).then(|| vec_len.min(WALK_REGIONS));
    let mut reported = 0;
    let mut result = Ok(());
    let mut walk_start = start;
    while walk_start < end {
        let walk = memory
            .pagemap_scan(
                walk_start,
                &mut request,
                capacity.and_then(|n| usize::try_from(n).ok()),
            )
            .unwrap_or_default();
        result = match walk.stop {
            None => Ok(()),
            Some(ScanStop::Full) => Err(Errno::ENOSPC),
            Some(ScanStop::Refused) => Err(Errno::EPERM),
        };
        if !walk.regions.is_empty() {
            let data: Vec<u8> = walk
                .regions
                .iter()
                .flatten()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            if c.mem.write(GuestAddr(out), &data).is_err() {
                result = Err(Errno::EFAULT);
            } else {
                let n = walk.regions.len() as u64;
                room -= n;
                out += n * REGION_SIZE;
                reported += n;
                capacity = capacity.map(|c| c.min(room));
            }
        }
        if result != Err(Errno::ENOSPC) || room == 0 || request.found == request.max_pages {
            break;
        }
        walk_start = request.walk_end;
    }
    let walk_end = if request.walk_end == 0 {
        end
    } else {
        request.walk_end
    };
    c.mem
        .write(GuestAddr(arg + 32), &walk_end.to_le_bytes())
        .map_err(|_| Errno::EFAULT)?;
    match result {
        Ok(()) | Err(Errno::ENOSPC) => Ok(reported),
        Err(e) => Err(e),
    }
}
