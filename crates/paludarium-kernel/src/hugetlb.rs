//! hugetlbfs with an empty pool of huge pages (`nr_hugepages` 0), as a
//! Linux that reserved none has: `mmap` with `MAP_HUGETLB` gives `ENOMEM`
//! (`hugetlb_reserve_pages`), but with `MAP_NORESERVE` it maps, and an
//! access raises `SIGBUS` as there is no page to fault in.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use paludarium_mmu::{Backing, MappingKind, PageSource, Placement, Prot, SharedPages, vm};
use paludarium_types::{Errno, GuestAddr};

use crate::syscalls::{Context, Outcome};

/// The one huge page size: the virtual CPU has no 1 GiB pages (`CPUID`'s
/// `PDPE1GB`).
pub(crate) const HUGE_PAGE: u64 = 2 << 20;
const HUGE_PAGE_LOG: u64 = HUGE_PAGE.trailing_zeros() as u64;
/// `MAP_HUGE_SHIFT` and `MAP_HUGE_MASK`: where a call gives its size.
const SIZE_SHIFT: u64 = 26;
const SIZE_MASK: u64 = 0x3f;
/// `MAX_LFS_FILESIZE`.
const MAX_OFFSET: u64 = i64::MAX as u64;

/// The file of a mapping (`hugetlb_file_setup`'s `anon_hugepage`), which
/// holds no page and can be given none.
struct HugePages {
    inode: u64,
}

impl PageSource for HugePages {
    fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    /// No page faults in, so an access to any is a bus error.
    fn size(&self) -> Option<u64> {
        Some(0)
    }
    fn linked(&self) -> bool {
        false
    }
    fn name(&self) -> Option<Vec<u8>> {
        Some(b"/anon_hugepage (deleted)".to_vec())
    }
    fn identity(&self) -> (u64, u64) {
        (0, self.inode)
    }
    fn open_file(&self) -> usize {
        std::ptr::from_ref(self).cast::<()>() as usize
    }
    /// `hugetlb_vm_ops` has a `close`.
    fn merges(&self) -> bool {
        false
    }
    /// `VM_DONTEXPAND`.
    fn fixed(&self) -> bool {
        true
    }
    fn page_size(&self) -> u64 {
        HUGE_PAGE
    }
    /// `hugetlb_get_unmapped_area`.
    fn huge_placement(&self) -> bool {
        true
    }
    /// `hugetlbfs_file_mmap_prepare`'s flags; hugetlb accounts for its own
    /// memory (`accountable_mapping`).
    fn vma_flags(&self, flags: u64) -> u64 {
        (flags | vm::HUGETLB | vm::DONTEXPAND) & !vm::ACCOUNT
    }
}

/// What an `mmap` with `MAP_HUGETLB` asks for.
pub(crate) struct Request {
    pub addr: u64,
    pub len: u64,
    pub prot: Prot,
    pub shared: bool,
    pub offset: u64,
    /// `MAP_FIXED`, or with `noreplace` `MAP_FIXED_NOREPLACE`.
    pub fixed: bool,
    pub noreplace: bool,
    pub low: bool,
    pub grows_down: bool,
    pub no_reserve: bool,
    pub stack: bool,
    /// What `do_mmap` says of a file's mapping type: `EOPNOTSUPP` for
    /// `MAP_SHARED_VALIDATE` with a flag it does not know, `EINVAL` for a
    /// type a file has not (`MAP_DROPPABLE`).
    pub refused_type: Option<Errno>,
}

/// `len` in whole huge pages of the size `flags` gives, the default 2 MiB
/// or that (`hstate_sizelog`): `EINVAL` for another, and for a length that
/// is none.
pub(crate) fn length(len: u64, flags: u64) -> Result<u64, Errno> {
    if !matches!((flags >> SIZE_SHIFT) & SIZE_MASK, 0 | HUGE_PAGE_LOG) {
        return Err(Errno::EINVAL);
    }
    match len.wrapping_add(HUGE_PAGE - 1) & !(HUGE_PAGE - 1) {
        0 => Err(Errno::EINVAL),
        len => Ok(len),
    }
}

/// `mmap` of huge pages, in the order of Linux's `do_mmap`: where it goes
/// (`hugetlb_get_unmapped_area`), what it may lock (`lock`), its file's
/// checks, and then, when a fixed mapping has unmapped what it replaces,
/// hugetlb's own (`hugetlbfs_file_mmap_prepare`).
pub(crate) fn mmap(
    c: &mut Context<'_>,
    r: &Request,
    lock: impl FnOnce(&Context<'_>) -> Result<(), Errno>,
) -> Outcome {
    match map(c, r, lock) {
        Ok(at) => Outcome::Return(at),
        Err(e) => Outcome::Return(e.to_syscall_return()),
    }
}

fn map(
    c: &mut Context<'_>,
    r: &Request,
    lock: impl FnOnce(&Context<'_>) -> Result<(), Errno>,
) -> Result<u64, Errno> {
    let (addr, len) = (r.addr, r.len);
    let placement = if r.fixed {
        if !addr.is_multiple_of(HUGE_PAGE) {
            return Err(Errno::EINVAL);
        }
        let end = addr
            .checked_add(len)
            .filter(|&end| end <= paludarium_types::USER_ADDRESS_LIMIT)
            .ok_or(Errno::ENOMEM)?;
        if crate::syscalls::below_min(c, addr, len) {
            return Err(Errno::EPERM);
        }
        if r.noreplace {
            if c.mem.mappings().any(|m| m.start.0 < end && m.end() > addr) {
                return Err(Errno::EEXIST);
            }
            Placement::Exactly(GuestAddr(addr))
        } else {
            Placement::Replacing(GuestAddr(addr))
        }
    } else {
        // A hint is rounded to its page and up to `mmap_min_addr`, then up
        // to a huge page.
        let hint = match addr & !4095 {
            0 => None,
            hint => hint
                .max(paludarium_mmu::MMAP_MIN_ADDR)
                .checked_next_multiple_of(HUGE_PAGE)
                .map(GuestAddr),
        };
        let (size, offset) = (HUGE_PAGE, 0);
        if r.low {
            Placement::Low {
                hint,
                fit: paludarium_mmu::Fit::Aligned { size, offset },
            }
        } else {
            Placement::Aligned { hint, size, offset }
        }
    };
    lock(c)?;
    if MAX_OFFSET
        .checked_sub(len)
        .is_none_or(|last| r.offset > last)
    {
        return Err(Errno::EOVERFLOW);
    }
    if let Some(e) = r.refused_type {
        return Err(e);
    }
    if r.grows_down {
        return Err(Errno::EINVAL);
    }
    let refused = if !r.offset.is_multiple_of(HUGE_PAGE) {
        Some(Errno::EINVAL)
    } else if !r.no_reserve {
        Some(Errno::ENOMEM)
    } else {
        None
    };
    let mut events = crate::userfaultfd::Events::default();
    if let Placement::Replacing(at) = placement {
        crate::userfaultfd::unmap(&c.mem.view(), at.0, at.0 + len, &mut events);
        // What it replaces is gone even if hugetlb then refuses it.
        if refused.is_some() {
            c.mem.unmap_shared(at, len)?;
            c.group.numa().forget(at.0, len);
        }
    }
    if let Some(e) = refused {
        events.deliver(c);
        return Err(e);
    }
    static INODES: AtomicU64 = AtomicU64::new(1);
    let pages = SharedPages::new().with_source(Arc::new(HugePages {
        inode: INODES.fetch_add(1, Ordering::Relaxed),
    }));
    let offset = r.offset;
    let backing = if r.shared {
        Backing::Shared {
            pages: &pages,
            offset,
            writes: paludarium_mmu::SharedWrites::Allowed,
        }
    } else {
        Backing::Cache {
            pages: &pages,
            offset,
        }
    };
    let at = c
        .mem
        .map_backed(placement, len, r.prot, MappingKind::File, backing)?;
    let end = at.0 + len;
    c.mem.flag_new(at, end, true, r.stack);
    c.mem.mapped(at, end);
    crate::perf::mapped(c, at.0);
    c.group.numa().forget(at.0, len);
    events.deliver(c);
    Ok(at.0)
}
