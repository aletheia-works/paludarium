//! A regular file's contents, kept as tmpfs keeps them: a size and the pages
//! that hold something. A write allocates the pages it touches, and so does
//! `fallocate`, whose pages read as zeros and count as a hole for
//! `SEEK_DATA` until they are written. Every other page is a hole: it reads
//! as zeros and takes no memory, so a file grown by `ftruncate` costs
//! nothing until it is written.
//!
//! A file system's [`Usage`] counts the pages and inodes its files take,
//! against the size and inodes it was mounted with, as tmpfs's
//! `shmem_inode_acct_blocks` and `shmem_reserve_inode` do.
//!
//! On a mount with `huge=` other than `never`, a page a fault, a write or
//! `fallocate` takes in comes with a large folio's others: the largest
//! aligned extent of up to 512 pages that the policy allows and in which
//! the file has no page yet, charged whole, or else the page alone, as
//! `shmem_alloc_and_add_folio` falls back to an order-0 folio when the
//! large one does not fit the mount's size (`shmem_get_folio_gfp`).
use paludarium_types::Errno;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError, Weak};

const PAGE: u64 = 4096;
const ENOSPC: Errno = Errno(28);
/// The largest folio's order, a PMD's 512 pages (`MAX_PAGECACHE_ORDER` on
/// x86-64).
const MAX_ORDER: u32 = 9;
/// The orders of a tmpfs file's large folios (`THP_ORDERS_ALL_FILE_DEFAULT`).
const FILE_ORDERS: u16 = ((1 << (MAX_ORDER + 1)) - 1) & !1;
/// The inodes a shrink of the large folios past their files' ends looks
/// at (`shmem_unused_huge_shrink`'s batch).
const SHRINK_BATCH: usize = 128;

/// A tmpfs mount's `huge=` option (`SHMEM_SB(sb)->huge`): when its files'
/// pages come in large folios.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Huge {
    /// Never (`SHMEM_HUGE_NEVER`).
    #[default]
    Never,
    /// Always (`SHMEM_HUGE_ALWAYS`).
    Always,
    /// Where the file's size, or the write's end, covers the folio
    /// (`SHMEM_HUGE_WITHIN_SIZE`), else as `Advise`.
    WithinSize,
    /// In a mapping `MADV_HUGEPAGE` advised (`SHMEM_HUGE_ADVISE`).
    Advise,
}

impl Huge {
    /// The `huge=` of a tmpfs's shown options (`shmem_show_options`, which
    /// leaves out `never`).
    pub(crate) fn shown_in(options: &str) -> Self {
        options
            .split(',')
            .find_map(|option| match option.strip_prefix("huge=")? {
                "always" => Some(Self::Always),
                "within_size" => Some(Self::WithinSize),
                "advise" => Some(Self::Advise),
                _ => None,
            })
            .unwrap_or_default()
    }
}

/// The mapping a fault takes a page in through, as `thp_vma_suitable_orders`
/// and `vma_thp_disabled` look at it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Vma {
    /// The largest order whose aligned extent around the page lies in the
    /// mapping at a file offset aligned as its address is; 0 for none.
    pub(crate) order: u8,
    /// `MADV_HUGEPAGE` (`true`, `VM_HUGEPAGE`) or `MADV_NOHUGEPAGE`.
    pub(crate) advised: Option<bool>,
}

/// A file whose large folio past its end a shrink may split: its inode.
pub(crate) trait Shrink: Send + Sync {
    /// Splits it ([`Contents::split_end`]): the pages freed, or `None` if
    /// its inode is busy.
    fn split_end(&self) -> Option<u64>;
}
impl Shrink for Mutex<crate::Node> {
    fn split_end(&self) -> Option<u64> {
        match self.try_lock() {
            Ok(mut node) => Some(node.split_end()),
            Err(TryLockError::Poisoned(node)) => Some(node.into_inner().split_end()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

/// What a page a file takes in reads as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// Zeros that are data, as a folio a fault or a write brings in is up
    /// to date.
    Data,
    /// Zeros that are a hole until written, as `fallocate`'s folio is not
    /// up to date.
    Hole,
}

/// What a file system's files take: the pages of every file (also of one
/// unlinked but still open) and of every long symbolic link, and its
/// inodes, each name of a file that has more than one counting as one, as
/// `shmem_link` reserves one for it. A limit of 0 is none.
#[derive(Default)]
pub(crate) struct Usage {
    pages: AtomicU64,
    inodes: AtomicU64,
    max_pages: AtomicU64,
    max_inodes: AtomicU64,
    /// The `huge=` option, a [`Huge`].
    huge: AtomicU8,
    /// The files whose large folio went past their end when it came in,
    /// oldest first (`sbinfo->shrinklist`).
    shrinklist: Mutex<Vec<Weak<dyn Shrink>>>,
}
impl Usage {
    /// Takes `n` of `count` unless that goes past `max` (`ENOSPC`).
    fn take(count: &AtomicU64, max: &AtomicU64, n: u64) -> Result<(), Errno> {
        let max = max.load(Ordering::SeqCst);
        count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                let after = used.checked_add(n)?;
                (max == 0 || after <= max).then_some(after)
            })
            .map(drop)
            .map_err(|_| ENOSPC)
    }
    /// Takes `n` pages, `ENOSPC` past the size.
    pub(crate) fn take_pages(&self, n: u64) -> Result<(), Errno> {
        Self::take(&self.pages, &self.max_pages, n)
    }
    pub(crate) fn free_pages(&self, n: u64) {
        self.pages.fetch_sub(n, Ordering::SeqCst);
    }
    /// Takes an inode, `ENOSPC` past the inodes.
    pub(crate) fn take_inode(&self) -> Result<(), Errno> {
        Self::take(&self.inodes, &self.max_inodes, 1)
    }
    /// Takes an inode whatever the limit.
    pub(crate) fn add_inode(&self) {
        self.inodes.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn free_inode(&self) {
        self.inodes.fetch_sub(1, Ordering::SeqCst);
    }
    pub(crate) fn pages(&self) -> u64 {
        self.pages.load(Ordering::SeqCst)
    }
    pub(crate) fn inodes(&self) -> u64 {
        self.inodes.load(Ordering::SeqCst)
    }
    /// The size in pages (0: none), which `fallocate` checks against.
    pub(crate) fn max_pages(&self) -> u64 {
        self.max_pages.load(Ordering::SeqCst)
    }
    pub(crate) fn max_inodes(&self) -> u64 {
        self.max_inodes.load(Ordering::SeqCst)
    }
    /// The size in pages and the inodes, 0 for no limit, as a mount or a
    /// remount sets them (`shmem_fill_super`, `shmem_reconfigure`).
    pub(crate) fn set_limits(&self, pages: u64, inodes: u64) {
        self.max_pages.store(pages, Ordering::SeqCst);
        self.max_inodes.store(inodes, Ordering::SeqCst);
    }
    /// The `huge=` option, as a mount or a remount sets it.
    pub(crate) fn set_huge(&self, huge: Huge) {
        self.huge.store(huge as u8, Ordering::SeqCst);
    }
    pub(crate) fn huge(&self) -> Huge {
        match self.huge.load(Ordering::SeqCst) {
            1 => Huge::Always,
            2 => Huge::WithinSize,
            3 => Huge::Advise,
            _ => Huge::Never,
        }
    }
}

enum Page {
    Written(Box<[u8; PAGE as usize]>),
    /// Allocated by `fallocate` and not written since.
    Allocated,
    /// Taken in by a fault, or with a write's page in its folio, and not
    /// written since: zeros that are data.
    Zero,
}

pub(crate) struct Contents {
    size: u64,
    pages: BTreeMap<u64, Page>,
    /// The large folios, by their first page and their pages, until a
    /// truncation or a shrink splits them.
    large: BTreeMap<u64, u64>,
    /// The page past the last one `fallocate` asked for, which a shrink
    /// keeps (`info->fallocend`).
    fallocend: u64,
    /// The pages every file of the file system holds, linked or not, which
    /// this file adds its own to while it has them.
    usage: Arc<Usage>,
    /// The inode it is the contents of, which the file system's
    /// [`Usage::shrinklist`] names.
    node: Weak<dyn Shrink>,
}

impl Drop for Contents {
    fn drop(&mut self) {
        self.usage.free_pages(self.pages());
    }
}

impl Contents {
    pub(crate) fn new(usage: &Arc<Usage>) -> Self {
        Self {
            size: 0,
            pages: BTreeMap::new(),
            large: BTreeMap::new(),
            fallocend: 0,
            usage: Arc::clone(usage),
            node: Weak::<Mutex<crate::Node>>::new(),
        }
    }
    /// The inode it belongs to, once that is made.
    pub(crate) fn set_node(&mut self, node: Weak<dyn Shrink>) {
        self.node = node;
    }
    /// A file of `bytes`, from start-up, which no limit holds back.
    pub(crate) fn with_bytes(usage: &Arc<Usage>, bytes: &[u8]) -> Self {
        let mut contents = Self::new(usage);
        contents.write_unlimited(0, bytes);
        contents
    }
    /// The page at `index`, taken in for a write ending at `write_end` if
    /// it has none ([`Self::take_in`]): `ENOSPC` when that goes past the
    /// size, unless `unlimited`.
    fn page(&mut self, index: u64, write_end: u64, unlimited: bool) -> Result<&mut Page, Errno> {
        if !self.pages.contains_key(&index) {
            if unlimited {
                self.usage.pages.fetch_add(1, Ordering::SeqCst);
                self.pages.insert(index, Page::Zero);
            } else {
                self.take_in(index, write_end, None, Fill::Data)?;
            }
        }
        self.up_to_date(index);
        // Taken in above: the entry is there.
        Ok(self.pages.entry(index).or_insert(Page::Zero))
    }
    /// The large folio that holds the page at `index`: its first page and
    /// its pages.
    fn folio_of(&self, index: u64) -> Option<(u64, u64)> {
        self.large
            .range(..=index)
            .next_back()
            .map(|(&start, &pages)| (start, pages))
            .filter(|&(start, pages)| index < start + pages)
    }
    /// The folio of the page at `index` becomes up to date: its pages
    /// `fallocate` allocated read as data then, as `shmem_write_end` and
    /// the clearing of a fault's folio mark the whole folio. A folio's
    /// pages are all up to date or none.
    fn up_to_date(&mut self, index: u64) {
        if !matches!(self.pages.get(&index), Some(Page::Allocated)) {
            return;
        }
        let (start, pages) = self.folio_of(index).unwrap_or((index, 1));
        for (_, page) in self.pages.range_mut(start..start + pages) {
            if let Page::Allocated = page {
                *page = Page::Zero;
            }
        }
    }
    /// The orders a new folio at `index` may have (`shmem_allowable_huge_orders`
    /// for a tmpfs file), by the mount's `huge=`, the end of a write
    /// (`write_end`, 0 for none) and the mapping of a fault (`vma`).
    fn orders(&self, index: u64, write_end: u64, vma: Option<Vma>) -> u16 {
        if vma.is_some_and(|vma| vma.advised == Some(false)) {
            return 0;
        }
        let advised = vma.is_some_and(|vma| vma.advised == Some(true));
        let orders = match self.usage.huge() {
            Huge::Never => 0,
            Huge::Always => FILE_ORDERS,
            Huge::WithinSize => match self.within_size(index, write_end) {
                0 if advised => FILE_ORDERS,
                orders => orders,
            },
            Huge::Advise if advised => FILE_ORDERS,
            Huge::Advise => 0,
        };
        match vma {
            Some(vma) => orders & ((2 << vma.order) - 1),
            None => orders,
        }
    }
    /// The orders whose aligned extent around `index` ends within the size,
    /// or the end of the write (`shmem_get_orders_within_size`).
    fn within_size(&self, index: u64, write_end: u64) -> u16 {
        let end = write_end.max(self.size).div_ceil(PAGE);
        let mut orders = FILE_ORDERS;
        while orders != 0 {
            let order = 15 - orders.leading_zeros();
            if (index + 1).next_multiple_of(1 << order) <= end {
                return orders;
            }
            orders &= !(1 << order);
        }
        0
    }
    /// The largest of `orders` whose aligned extent around `index` has no
    /// page of the file yet (`shmem_suitable_orders`), or 0.
    fn suitable(&self, index: u64, mut orders: u16) -> u32 {
        while orders != 0 {
            let order = 15 - orders.leading_zeros();
            let start = index & !((1 << order) - 1);
            if self
                .pages
                .range(start..start + (1 << order))
                .next()
                .is_none()
            {
                return order;
            }
            orders &= !(1 << order);
        }
        0
    }
    /// Takes in the page at `index`, which the file has not: in a large
    /// folio if the mount and `vma` allow one and it fits the size, else
    /// alone, `ENOSPC` when that does not fit either.
    fn take_in(
        &mut self,
        index: u64,
        write_end: u64,
        vma: Option<Vma>,
        fill: Fill,
    ) -> Result<(), Errno> {
        let page = || match fill {
            Fill::Data => Page::Zero,
            Fill::Hole => Page::Allocated,
        };
        let order = self.suitable(index, self.orders(index, write_end, vma));
        if order > 0 {
            let pages = 1 << order;
            let start = index & !(pages - 1);
            if self.charge(pages).is_ok() {
                for at in start..start + pages {
                    self.pages.insert(at, page());
                }
                self.large.insert(start, pages);
                // Part of it past the end: a shrink may give that back
                // (`shmem_get_folio_gfp` lists the inode).
                if self.size.div_ceil(PAGE) < start + pages {
                    self.list_for_shrink();
                }
                return Ok(());
            }
        }
        self.charge(1)?;
        self.pages.insert(index, page());
        Ok(())
    }
    /// Takes `pages` of the size, shrinking the large folios past their
    /// files' ends first if they do not fit (`shmem_alloc_and_add_folio`).
    fn charge(&mut self, pages: u64) -> Result<(), Errno> {
        if self.usage.take_pages(pages).is_ok() {
            return Ok(());
        }
        self.shrink(pages);
        self.usage.take_pages(pages)
    }
    fn list_for_shrink(&self) {
        let mut list = self
            .usage
            .shrinklist
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.node.strong_count() > 0 && !list.iter().any(|node| node.ptr_eq(&self.node)) {
            list.push(self.node.clone());
        }
    }
    /// Splits the large folios past the ends of the listed files, oldest
    /// first, until `wanted` pages are freed (`shmem_unused_huge_shrink`):
    /// each file leaves the list, but one that is busy (its inode locked)
    /// or not looked at.
    fn shrink(&mut self, wanted: u64) {
        let usage = Arc::clone(&self.usage);
        let mut list = usage.shrinklist.lock().unwrap_or_else(|e| e.into_inner());
        let batch = list.len().min(SHRINK_BATCH);
        let (mut freed, mut kept) = (0, Vec::new());
        for node in list.drain(..batch).collect::<Vec<_>>() {
            if freed >= wanted {
                kept.push(node);
            } else if node.ptr_eq(&self.node) {
                freed += self.split_end();
            } else if let Some(other) = node.upgrade() {
                match other.split_end() {
                    Some(pages) => freed += pages,
                    None => kept.push(node),
                }
            }
        }
        kept.append(&mut list);
        *list = kept;
    }
    /// Splits the large folio at the end of the file if part of it lies
    /// past both the end and `fallocate`'s, freeing that part: the pages
    /// freed.
    pub(crate) fn split_end(&mut self) -> u64 {
        let Some((start, pages)) = self.folio_of(self.size / PAGE) else {
            return 0;
        };
        let end = self.size.div_ceil(PAGE).max(self.fallocend);
        if end <= start || end >= start + pages {
            return 0;
        }
        self.large.remove(&start);
        self.free(|index| index < end || index >= start + pages);
        start + pages - end
    }
    /// Frees the pages `keep` rejects, splitting the large folios they
    /// were in.
    fn free(&mut self, keep: impl Fn(u64) -> bool) {
        let before = self.pages();
        self.pages.retain(|&index, _| keep(index));
        self.large
            .retain(|&start, &mut pages| (start..start + pages).all(&keep));
        self.usage.free_pages(before - self.pages());
    }
    pub(crate) fn len(&self) -> u64 {
        self.size
    }
    /// The 512-byte blocks the allocated pages take (`st_blocks`).
    pub(crate) fn blocks(&self) -> u64 {
        self.pages.len() as u64 * (PAGE / 512)
    }
    /// The pages allocated from index `first` to `last`, which tmpfs's page
    /// cache holds.
    pub(crate) fn resident(&self, first: u64, last: u64) -> u64 {
        if first > last {
            return 0;
        }
        self.pages.range(first..=last).count() as u64
    }
    /// The pages allocated, for `statfs`.
    pub(crate) fn pages(&self) -> u64 {
        self.pages.len() as u64
    }
    /// Reads from `offset` up to the end of the file; a hole reads as zeros.
    pub(crate) fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let count = (buf.len() as u64).min(self.size.saturating_sub(offset)) as usize;
        let mut done = 0;
        while done < count {
            let at = offset + done as u64;
            let (index, within) = (at / PAGE, (at % PAGE) as usize);
            let n = (PAGE as usize - within).min(count - done);
            match self.pages.get(&index) {
                Some(Page::Written(page)) => {
                    buf[done..done + n].copy_from_slice(&page[within..within + n]);
                }
                _ => buf[done..done + n].fill(0),
            }
            done += n;
        }
        count
    }
    /// Writes `data` at `offset`, growing the file past its end, as far as
    /// the pages it needs fit in the file system's size: the bytes written,
    /// as `generic_perform_write` stops at the first page `shmem_write_begin`
    /// cannot have, or `ENOSPC` if that is the first.
    pub(crate) fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        self.write_within(offset, data, false)
    }
    /// Writes a shared mapping's pages back at `offset`, taking in those
    /// the file has none of (`ENOSPC` past the size, also when only the
    /// first fit): one a fault took in has it.
    pub(crate) fn write_back(&mut self, offset: u64, data: &[u8]) -> Result<(), Errno> {
        match self.write_within(offset, data, false)? {
            done if done == data.len() => Ok(()),
            _ => Err(ENOSPC),
        }
    }
    /// Writes `data` at `offset` whatever the size: a start-up file.
    fn write_unlimited(&mut self, offset: u64, data: &[u8]) {
        let _ = self.write_within(offset, data, true);
    }
    fn write_within(&mut self, offset: u64, data: &[u8], unlimited: bool) -> Result<usize, Errno> {
        let mut done = 0;
        let write_end = offset + data.len() as u64;
        while done < data.len() {
            let at = offset + done as u64;
            let (index, within) = (at / PAGE, (at % PAGE) as usize);
            let n = (PAGE as usize - within).min(data.len() - done);
            let page = match self.page(index, write_end, unlimited) {
                Ok(page) => page,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            };
            if let Page::Allocated | Page::Zero = page {
                *page = Page::Written(Box::new([0; PAGE as usize]));
            }
            if let Page::Written(page) = page {
                page[within..within + n].copy_from_slice(&data[done..done + n]);
            }
            done += n;
        }
        self.size = self.size.max(offset + done as u64);
        Ok(done)
    }
    /// `ftruncate`: a smaller size frees the pages past it and clears the rest
    /// of the last one; a larger one leaves a hole.
    pub(crate) fn set_len(&mut self, size: u64) {
        if size < self.size {
            self.free(|index| index * PAGE < size);
            self.fallocend = self.fallocend.min(size.div_ceil(PAGE));
            if let Some(Page::Written(page)) = self.pages.get_mut(&(size / PAGE)) {
                page[(size % PAGE) as usize..].fill(0);
            }
        }
        self.size = size;
    }
    /// The pages of the range that have none allocated yet.
    pub(crate) fn missing(&self, offset: u64, len: u64) -> u64 {
        let end = offset.saturating_add(len);
        if end == 0 {
            return 0;
        }
        let (first, last) = (offset / PAGE, (end - 1) / PAGE);
        (last - first + 1) - self.pages.range(first..=last).count() as u64
    }
    /// `fallocate` without a mode: takes in the pages of the range that
    /// have none, in large folios as a write would, without changing what
    /// they read, or none of them with `ENOSPC` when they do not all fit,
    /// as `shmem_fallocate` undoes the folios it allocated.
    pub(crate) fn allocate(&mut self, offset: u64, len: u64) -> Result<(), Errno> {
        let end = offset.saturating_add(len);
        if end == 0 {
            return Ok(());
        }
        let (first, last) = (offset / PAGE, (end - 1) / PAGE);
        let undo_fallocend = self.fallocend;
        self.fallocend = self.fallocend.max(last + 1);
        let mut taken = Vec::new();
        let mut index = first;
        while index <= last {
            if self.pages.contains_key(&index) {
                index = self
                    .folio_of(index)
                    .map_or(index + 1, |(start, pages)| start + pages);
                continue;
            }
            if let Err(e) = self.take_in(index, end, None, Fill::Hole) {
                self.fallocend = undo_fallocend;
                self.free(|at| !taken.contains(&at));
                return Err(e);
            }
            let (start, pages) = self.folio_of(index).unwrap_or((index, 1));
            taken.extend(start..start + pages);
            index = start + pages;
        }
        Ok(())
    }
    /// Takes in the holes of the range as data, none of them with `ENOSPC`
    /// when they do not all fit: the pages `MADV_COLLAPSE` charges
    /// (`shmem_charge`), and the one a `userfaultfd` fills
    /// (`shmem_mfill_atomic_pte`).
    pub(crate) fn charge_holes(&mut self, offset: u64, len: u64) -> Result<(), Errno> {
        let end = offset.saturating_add(len);
        if end == 0 {
            return Ok(());
        }
        self.charge(self.missing(offset, len))?;
        for index in offset / PAGE..=(end - 1) / PAGE {
            self.pages.entry(index).or_insert(Page::Zero);
        }
        Ok(())
    }
    /// A fault's page at `offset`, taken in through `vma` if the file has
    /// none, and up to date (`shmem_get_folio_gfp` with `SGP_CACHE`).
    pub(crate) fn fault(&mut self, offset: u64, vma: Vma) -> Result<(), Errno> {
        let index = offset / PAGE;
        if !self.pages.contains_key(&index) {
            self.take_in(index, 0, Some(vma), Fill::Data)?;
        }
        self.up_to_date(index);
        Ok(())
    }
    /// `FALLOC_FL_PUNCH_HOLE`: frees the pages the range covers whole and
    /// clears its part of the others, as shmem_truncate_range does.
    pub(crate) fn punch(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        let first = offset.div_ceil(PAGE);
        let last = end / PAGE;
        self.free(|index| index < first || index >= last);
        if self.fallocend > first && self.fallocend <= last {
            self.fallocend = first;
        }
        // A folio the range cuts into is split (`truncate_inode_partial_folio`).
        let (from, to) = (offset / PAGE, end.div_ceil(PAGE));
        self.large
            .retain(|&start, &mut pages| start + pages <= from || start >= to);
        for at in [offset, end.saturating_sub(1)] {
            let index = at / PAGE;
            if (index < first || index >= last)
                && let Some(Page::Written(page)) = self.pages.get_mut(&index)
            {
                let start = offset.max(index * PAGE) - index * PAGE;
                let stop = end.min((index + 1) * PAGE) - index * PAGE;
                page[start as usize..stop as usize].fill(0);
            }
        }
    }
    /// `lseek` with `SEEK_DATA` (`data`) or `SEEK_HOLE`: the next written
    /// page at or after `offset`, or the next page that is not; the end of
    /// the file is a hole. `ENXIO` past the end or with no data after it.
    pub(crate) fn seek(&self, offset: u64, data: bool) -> Result<u64, Errno> {
        const ENXIO: Errno = Errno(6);
        if offset >= self.size {
            return Err(ENXIO);
        }
        let is_data = |page: &Page| matches!(page, Page::Written(_) | Page::Zero);
        let written = |index: u64| self.pages.get(&index).is_some_and(is_data);
        let mut index = offset / PAGE;
        if data {
            let found = self
                .pages
                .range(index..)
                .find(|(_, page)| is_data(page))
                .map(|(&found, _)| (found * PAGE).max(offset))
                .filter(|&at| at < self.size);
            return found.ok_or(ENXIO);
        }
        while written(index) {
            index += 1;
        }
        Ok((index * PAGE).max(offset).min(self.size))
    }
}
