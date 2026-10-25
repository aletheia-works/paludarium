//! A regular file's contents, kept as tmpfs keeps them: a size and the pages
//! that hold something. A write allocates the pages it touches, and so does
//! `fallocate`, whose pages read as zeros and count as a hole for
//! `SEEK_DATA` until they are written. Every other page is a hole: it reads
//! as zeros and takes no memory, so a file grown by `ftruncate` costs
//! nothing until it is written.
use paludarium_types::Errno;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const PAGE: u64 = 4096;

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
    usage: Arc<AtomicU64>,
}

impl Drop for Contents {
    fn drop(&mut self) {
        self.usage.fetch_sub(self.pages(), Ordering::SeqCst);
    }
}

impl Contents {
    pub(crate) fn new(usage: &Arc<AtomicU64>) -> Self {
        Self {
            size: 0,
            pages: BTreeMap::new(),
            usage: Arc::clone(usage),
        }
    }
    pub(crate) fn with_bytes(usage: &Arc<AtomicU64>, bytes: &[u8]) -> Self {
        let mut contents = Self::new(usage);
        contents.write(0, bytes);
        contents
    }
    /// The page at `index`, allocated (and counted) if it has none.
    fn page(&mut self, index: u64) -> &mut Page {
        match self.pages.entry(index) {
            Entry::Occupied(page) => page.into_mut(),
            Entry::Vacant(page) => {
                self.usage.fetch_add(1, Ordering::SeqCst);
                page.insert(Page::Allocated)
            }
        }
    }
    /// Frees the pages `keep` rejects.
    fn free(&mut self, keep: impl Fn(u64) -> bool) {
        let before = self.pages();
        self.pages.retain(|&index, _| keep(index));
        self.usage
            .fetch_sub(before - self.pages(), Ordering::SeqCst);
    }
    pub(crate) fn len(&self) -> u64 {
        self.size
    }
    /// The 512-byte blocks the allocated pages take (`st_blocks`).
    pub(crate) fn blocks(&self) -> u64 {
        self.pages.len() as u64 * (PAGE / 512)
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
    /// Writes `data` at `offset`, growing the file past its end.
    pub(crate) fn write(&mut self, offset: u64, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let at = offset + done as u64;
            let (index, within) = (at / PAGE, (at % PAGE) as usize);
            let n = (PAGE as usize - within).min(data.len() - done);
            let page = self.page(index);
            if let Page::Allocated = page {
                *page = Page::Written(Box::new([0; PAGE as usize]));
            }
            if let Page::Written(page) = page {
                page[within..within + n].copy_from_slice(&data[done..done + n]);
            }
            done += n;
        }
        self.size = self.size.max(offset + data.len() as u64);
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
    /// have none, without changing what they read.
    pub(crate) fn allocate(&mut self, offset: u64, len: u64) {
        let end = offset.saturating_add(len);
        if end == 0 {
            return;
        }
        for index in offset / PAGE..=(end - 1) / PAGE {
            self.page(index);
        }
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
