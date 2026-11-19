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
use paludarium_types::Errno;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const PAGE: u64 = 4096;
const ENOSPC: Errno = Errno(28);

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
}

enum Page {
    Written(Box<[u8; PAGE as usize]>),
    /// Allocated by `fallocate` and not written since.
    Allocated,
}

pub(crate) struct Contents {
    size: u64,
    pages: BTreeMap<u64, Page>,
    /// The pages every file of the file system holds, linked or not, which
    /// this file adds its own to while it has them.
    usage: Arc<Usage>,
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
            usage: Arc::clone(usage),
        }
    }
    /// A file of `bytes`, from start-up, which no limit holds back.
    pub(crate) fn with_bytes(usage: &Arc<Usage>, bytes: &[u8]) -> Self {
        let mut contents = Self::new(usage);
        contents.write_unlimited(0, bytes);
        contents
    }
    /// The page at `index`, allocated (and counted) if it has none:
    /// `ENOSPC` when that goes past the size, unless `unlimited`.
    fn page(&mut self, index: u64, unlimited: bool) -> Result<&mut Page, Errno> {
        match self.pages.entry(index) {
            Entry::Occupied(page) => Ok(page.into_mut()),
            Entry::Vacant(page) => {
                if unlimited {
                    self.usage.pages.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.usage.take_pages(1)?;
                }
                Ok(page.insert(Page::Allocated))
            }
        }
    }
    /// Frees the pages `keep` rejects.
    fn free(&mut self, keep: impl Fn(u64) -> bool) {
        let before = self.pages();
        self.pages.retain(|&index, _| keep(index));
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
    /// Writes `data` at `offset` whatever the size: a mapping's pages going
    /// back to the file, which a fault already had.
    pub(crate) fn write_unlimited(&mut self, offset: u64, data: &[u8]) {
        let _ = self.write_within(offset, data, true);
    }
    fn write_within(&mut self, offset: u64, data: &[u8], unlimited: bool) -> Result<usize, Errno> {
        let mut done = 0;
        while done < data.len() {
            let at = offset + done as u64;
            let (index, within) = (at / PAGE, (at % PAGE) as usize);
            let n = (PAGE as usize - within).min(data.len() - done);
            let page = match self.page(index, unlimited) {
                Ok(page) => page,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            };
            if let Page::Allocated = page {
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
    /// `fallocate` without a mode: allocates the pages of the range that
    /// have none, without changing what they read, or none of them with
    /// `ENOSPC` when they do not all fit, as `shmem_fallocate` undoes the
    /// pages it allocated.
    pub(crate) fn allocate(&mut self, offset: u64, len: u64) -> Result<(), Errno> {
        let end = offset.saturating_add(len);
        if end == 0 {
            return Ok(());
        }
        self.usage.take_pages(self.missing(offset, len))?;
        for index in offset / PAGE..=(end - 1) / PAGE {
            self.pages.entry(index).or_insert(Page::Allocated);
        }
        Ok(())
    }
    /// `FALLOC_FL_PUNCH_HOLE`: frees the pages the range covers whole and
    /// clears its part of the others, as shmem_truncate_range does.
    pub(crate) fn punch(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        let first = offset.div_ceil(PAGE);
        let last = end / PAGE;
        self.free(|index| index < first || index >= last);
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
        let written = |index: u64| matches!(self.pages.get(&index), Some(Page::Written(_)));
        let mut index = offset / PAGE;
        if data {
            let found = self
                .pages
                .range(index..)
                .find(|(_, page)| matches!(page, Page::Written(_)))
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
