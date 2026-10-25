//! Software MMU for paludarium.
//!
//! A guest address space is a two-level page table of 4 KiB pages: a sparse
//! directory (one entry per 512 pages) pointing at dense tables of 512 page
//! entries. Every access goes through checked guest addresses; a missing
//! page or a protection violation returns a [`Fault`] and never panics.
//!
//! Page contents are byte-wise atomics so that `read`/`write` work through a
//! shared reference without `unsafe` (the CPU writes guest memory while the
//! address space is shared, and later units add threads). Page entries are
//! created lazily on the first write, so the cost of a mapping does not
//! depend on its size.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

use paludarium_types::{Errno, GuestAddr, PAGE_SIZE, USER_ADDRESS_LIMIT};

/// Number of page entries in one lower-level page table.
pub const ENTRIES_PER_TABLE: u64 = 512;

/// Lowest address handed out for mappings without a fixed address.
pub const MMAP_MIN_ADDR: u64 = 0x10000;

/// Default top of the region searched for mappings without a fixed address.
pub const DEFAULT_MMAP_TOP: u64 = 0x7fff_0000_0000;

const PAGE_BYTES: usize = 4096;

/// Page protection, using the Linux `PROT_*` bit values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Prot(u8);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXEC: Prot = Prot(4);
    pub const READ_WRITE: Prot = Prot(3);
    pub const READ_EXEC: Prot = Prot(5);

    /// Builds a protection from `PROT_*` bits; unknown bits are rejected.
    #[must_use]
    pub fn from_bits(bits: u64) -> Option<Prot> {
        if bits & !7 != 0 {
            return None;
        }
        u8::try_from(bits).ok().map(Prot)
    }

    /// The `PROT_*` bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Prot) -> bool {
        self.0 & other.0 == other.0
    }

    /// Union of two protections.
    #[must_use]
    pub const fn union(self, other: Prot) -> Prot {
        Prot(self.0 | other.0)
    }

    /// x86 pages are readable whenever they are mapped with any access.
    const fn allows_read(self) -> bool {
        self.0 != 0
    }
}

/// What a mapping was created for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingKind {
    ElfSegment,
    Anonymous,
    Stack,
    Heap,
    /// A copy of a file made by `mmap`. When it is also shared it stands
    /// for a mapping that must stay read-only, as nothing writes it back.
    File,
}

/// A contiguous, page-aligned region of the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: GuestAddr,
    pub length: u64,
    pub prot: Prot,
    pub kind: MappingKind,
}

impl Mapping {
    /// Exclusive end address.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.0 + self.length
    }
}

/// A failed guest memory access: the faulting address and whether it was a
/// write. Becomes SIGSEGV for the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub addr: GuestAddr,
    pub write: bool,
    /// The failed access was instruction fetch.
    pub fetch: bool,
    /// The address belonged to a guest mapping at the time of the fault.
    pub mapped: bool,
    /// The software page entry was resident and accessible in user mode.
    pub present: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Fetch,
    /// Loader writes into read-only segments while preparing the image.
    Setup,
}

impl Access {
    fn permitted(self, prot: Prot) -> bool {
        match self {
            Access::Read => prot.allows_read(),
            Access::Write => prot.contains(Prot::WRITE),
            Access::Fetch => prot.contains(Prot::EXEC),
            Access::Setup => true,
        }
    }

    fn is_write(self) -> bool {
        matches!(self, Access::Write | Access::Setup)
    }
}

/// The guest memory of a session, as a cgroup's `memory.current` against
/// its `memory.max`: a page frame counts from its first write until the last
/// address space holding it lets it go, once however many share it.
#[derive(Debug)]
pub struct MemoryMeter {
    max: u64,
    used: AtomicU64,
}

impl MemoryMeter {
    /// A meter allowing `max` bytes of page frames.
    #[must_use]
    pub const fn new(max: u64) -> Self {
        MemoryMeter {
            max,
            used: AtomicU64::new(0),
        }
    }

    /// The bytes of page frames held now.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    fn charge(&self) -> bool {
        self.used
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(PAGE_SIZE).filter(|&used| used <= self.max)
            })
            .is_ok()
    }
}

/// The bytes of one page frame, charged to the meter while they exist.
struct FrameBytes {
    bytes: Box<[AtomicU8]>,
    meter: Option<Arc<MemoryMeter>>,
}

impl FrameBytes {
    /// A frame of `bytes`, or `None` when the meter has no room for it.
    fn new(
        meter: Option<&Arc<MemoryMeter>>,
        bytes: impl FnOnce() -> Box<[AtomicU8]>,
    ) -> Option<Self> {
        if meter.is_some_and(|meter| !meter.charge()) {
            return None;
        }
        Some(FrameBytes {
            bytes: bytes(),
            meter: meter.cloned(),
        })
    }
}

impl std::ops::Deref for FrameBytes {
    type Target = [AtomicU8];
    fn deref(&self) -> &[AtomicU8] {
        &self.bytes
    }
}

impl Drop for FrameBytes {
    fn drop(&mut self) {
        if let Some(meter) = &self.meter {
            meter.used.fetch_sub(PAGE_SIZE, Ordering::SeqCst);
        }
    }
}

/// One populated page: its protection and its contents. The contents are
/// allocated on the first write; until then the page reads as zeros.
struct Page {
    prot: Prot,
    frame: Frame,
}

impl Page {
    fn new(prot: Prot) -> Self {
        Page {
            prot,
            frame: Arc::new(OnceLock::new()),
        }
    }

    /// The contents to write, allocated now if need be; `None` when the
    /// meter has no room for them.
    fn frame_for_write(&self, meter: Option<&Arc<MemoryMeter>>) -> Option<&[AtomicU8]> {
        if self.frame.get().is_none() {
            let bytes = FrameBytes::new(meter, || {
                (0..PAGE_BYTES).map(|_| AtomicU8::new(0)).collect()
            })?;
            // A racing write to a shared frame may set it first: then this
            // one is dropped, and its charge with it.
            let _ = self.frame.set(bytes);
        }
        self.frame.get().map(|frame| &**frame)
    }
}

/// Lower level of the page table: 512 consecutive pages. Entries are populated lazily, on the first write to a page
/// of a mapping, so mapping a huge region costs nothing until it is used
/// (a guest `brk`/`mmap` of terabytes must not exhaust host memory).
struct PageTable {
    pages: Vec<Option<Page>>,
}

impl PageTable {
    fn new() -> Self {
        PageTable {
            pages: (0..ENTRIES_PER_TABLE).map(|_| None).collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.pages.iter().all(Option::is_none)
    }
}

/// The upper level: a sparse map from directory index to page table.
type Directory = BTreeMap<u64, PageTable>;

type Frame = Arc<OnceLock<FrameBytes>>;
#[derive(Clone)]
struct SharedMapping {
    end: u64,
    /// Frames are keyed by `page + shift` (wrapping): 0 where the mapping
    /// was made, and moved by `mremap`, so every process sharing the frames
    /// still finds the same ones wherever it has the mapping now.
    shift: u64,
    frames: Arc<Mutex<BTreeMap<u64, Frame>>>,
    generation: Arc<AtomicU64>,
}

/// The file a private file mapping was copied from, read at an offset, so
/// that pages given back with `MADV_DONTNEED` are read from it again, as
/// Linux faults them in from the file once their private copies are gone.
pub trait PageSource: Send + Sync {
    /// Reads from `offset`, filling `buf` unless the file ends first, and
    /// returns how much it read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno>;
}
/// The file behind `[start, end)` of a private file mapping: the page at
/// `page` holds the file from `page + shift` (wrapping), so that a move by
/// `mremap` only changes the shift.
#[derive(Clone)]
struct FileBacking {
    end: u64,
    shift: u64,
    source: Arc<dyn PageSource>,
}

/// Where `mremap` may put a mapping ([`AddressSpace::remap`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Remap {
    /// `MREMAP_MAYMOVE`: move the mapping when it cannot grow in place.
    pub may_move: bool,
    /// `MREMAP_FIXED`: move the mapping to exactly `new_addr`.
    pub fixed: bool,
    /// `MREMAP_DONTUNMAP`: leave the old range mapped. A private one is
    /// emptied, as its pages moved; a shared one keeps showing them.
    pub keep_old: bool,
    /// The target with `fixed`, or a hint with `keep_old` alone.
    pub new_addr: GuestAddr,
}

static NEXT_ADDRESS_SPACE_ID: AtomicU64 = AtomicU64::new(1);

/// One process's guest address space.
///
/// `mappings` is the source of truth for what is mapped and with which
/// protection; the two-level page table caches populated pages and holds
/// their contents.
struct AddressSpaceData {
    id: u64,
    directory: RwLock<Directory>,
    /// Bumped whenever executable memory or the mappings change; lets the
    /// CPU cache decoded instructions safely (see [`Self::code_generation`]).
    code_generation: AtomicU64,
    mappings: BTreeMap<u64, Mapping>,
    initial_break: GuestAddr,
    current_break: GuestAddr,
    mmap_top: u64,
    shared: BTreeMap<u64, SharedMapping>,
    /// The files of private file mappings, by range ([`FileBacking`]).
    backing: BTreeMap<u64, FileBacking>,
    /// What the frames are charged to; shared with the spaces forked from
    /// this one and the ones its exec starts.
    meter: Option<Arc<MemoryMeter>>,
    /// A write found no room under the meter since the last
    /// [`AddressSpace::take_out_of_memory`], which reads it without the
    /// locks.
    out_of_memory: Arc<AtomicBool>,
}

impl Default for AddressSpaceData {
    fn default() -> Self {
        Self::new()
    }
}

fn page_index(addr: u64) -> (u64, usize) {
    let page = addr / PAGE_SIZE;
    let dir = page / ENTRIES_PER_TABLE;
    // The remainder is below 512, so it always fits in usize.
    let slot = usize::try_from(page % ENTRIES_PER_TABLE).unwrap_or(0);
    (dir, slot)
}

fn page_offset(addr: u64) -> usize {
    usize::try_from(addr % PAGE_SIZE).unwrap_or(0)
}

/// Validates a page-aligned range and returns its exclusive end.
fn checked_range(addr: GuestAddr, len: u64) -> Result<u64, Errno> {
    if addr.page_offset() != 0 || len == 0 {
        return Err(Errno::EINVAL);
    }
    let len = GuestAddr(len).page_align_up().ok_or(Errno::ENOMEM)?.0;
    let end = addr.0.checked_add(len).ok_or(Errno::ENOMEM)?;
    if end > USER_ADDRESS_LIMIT {
        return Err(Errno::ENOMEM);
    }
    Ok(end)
}

fn lookup(directory: &Directory, addr: u64) -> Option<&Page> {
    let (dir, slot) = page_index(addr);
    directory
        .get(&dir)
        .and_then(|table| table.pages.get(slot))
        .and_then(Option::as_ref)
}

/// Splits `[addr, addr+len)` at page boundaries: (page address, offset in
/// the page, range in the buffer).
fn chunks(
    addr: GuestAddr,
    len: usize,
) -> impl Iterator<Item = (u64, usize, core::ops::Range<usize>)> {
    let mut done = 0usize;
    core::iter::from_fn(move || {
        if done >= len {
            return None;
        }
        let at = u64::try_from(done)
            .ok()
            .and_then(|d| addr.0.checked_add(d))?;
        let offset = page_offset(at);
        let chunk = (PAGE_BYTES - offset).min(len - done);
        let item = (at - at % PAGE_SIZE, offset, done..done + chunk);
        done += chunk;
        Some(item)
    })
}

impl AddressSpaceData {
    /// Creates an empty address space.
    #[must_use]
    pub fn new() -> Self {
        AddressSpaceData {
            id: NEXT_ADDRESS_SPACE_ID.fetch_add(1, Ordering::Relaxed),
            directory: RwLock::new(BTreeMap::new()),
            shared: BTreeMap::new(),
            backing: BTreeMap::new(),
            code_generation: AtomicU64::new(0),
            mappings: BTreeMap::new(),
            initial_break: GuestAddr(0),
            current_break: GuestAddr(0),
            mmap_top: DEFAULT_MMAP_TOP,
            meter: None,
            out_of_memory: Arc::default(),
        }
    }

    /// Identifier of this address space.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// A counter that changes whenever executable memory is written or the
    /// mappings change (map, unmap, protect). Decoded instructions cached
    /// under one value stay valid while the value is unchanged.
    #[must_use]
    pub fn code_generation(&self) -> u64 {
        self.shared.values().fold(
            self.code_generation.load(Ordering::Acquire),
            |value, shared| value.wrapping_add(shared.generation.load(Ordering::Acquire)),
        )
    }

    fn shared_at(&self, page: u64) -> Option<&SharedMapping> {
        self.shared
            .range(..=page)
            .next_back()
            .map(|(_, mapping)| mapping)
            .filter(|mapping| page < mapping.end)
    }
    fn backing_at(&self, page: u64) -> Option<&FileBacking> {
        self.backing
            .range(..=page)
            .next_back()
            .map(|(_, backing)| backing)
            .filter(|backing| page < backing.end)
    }
    /// Records that the private file mapping `[addr, addr+len)` was copied
    /// from `source` at `offset` ([`PageSource`]).
    pub fn back_with_file(
        &mut self,
        addr: GuestAddr,
        len: u64,
        source: Arc<dyn PageSource>,
        offset: u64,
    ) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        self.unback(addr.0, end);
        self.backing.insert(
            addr.0,
            FileBacking {
                end,
                shift: offset.wrapping_sub(addr.0),
                source,
            },
        );
        Ok(())
    }
    /// Forgets the files of `[start, end)`, keeping the rest of each range.
    fn unback(&mut self, start: u64, end: u64) {
        let affected: Vec<_> = self
            .backing
            .range(..end)
            .filter(|(_, backing)| backing.end > start)
            .map(|(&at, backing)| (at, backing.clone()))
            .collect();
        for (at, backing) in affected {
            self.backing.remove(&at);
            if at < start {
                self.backing.insert(
                    at,
                    FileBacking {
                        end: start,
                        ..backing.clone()
                    },
                );
            }
            if backing.end > end {
                self.backing.insert(end, backing);
            }
        }
    }
    /// Reads the file of every backed page of `[start, end)` into it, from
    /// emptied pages: what lies past the end of the file stays zero. A read
    /// that fails leaves the rest zero too, where Linux would raise SIGBUS
    /// on the access.
    fn refill(&mut self, start: u64, end: u64) {
        let ranges: Vec<_> = self
            .backing
            .range(..end)
            .filter(|(_, backing)| backing.end > start)
            .map(|(&at, backing)| (at.max(start), backing.end.min(end), backing.clone()))
            .collect();
        let mut buf = vec![0; PAGE_BYTES];
        for (from, to, backing) in ranges {
            let mut at = from;
            while at < to {
                let want = usize::try_from(to - at).map_or(PAGE_BYTES, |n| n.min(PAGE_BYTES));
                let read = backing
                    .source
                    .read_at(at.wrapping_add(backing.shift), &mut buf[..want]);
                let Ok(n @ 1..) = read else {
                    break;
                };
                if self.write_initial(GuestAddr(at), &buf[..n]).is_err() {
                    break;
                }
                at += n as u64;
            }
        }
    }
    fn page(&self, page: u64, prot: Prot) -> Page {
        let frame = self.shared_at(page).map(|mapping| {
            mapping
                .frames
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(page.wrapping_add(mapping.shift))
                .or_default()
                .clone()
        });
        Page {
            prot,
            frame: frame.unwrap_or_default(),
        }
    }
    fn fork(&self) -> Result<Self, Errno> {
        let mut copy = Self::new();
        copy.meter = self.meter.clone();
        copy.mappings = self.mappings.clone();
        copy.shared = self.shared.clone();
        copy.backing = self.backing.clone();
        copy.initial_break = self.initial_break;
        copy.current_break = self.current_break;
        copy.mmap_top = self.mmap_top;
        let mut directory = BTreeMap::new();
        for (&index, table) in self.read_directory().iter() {
            let mut cloned = PageTable::new();
            for (slot, page) in table.pages.iter().enumerate() {
                if let Some(page) = page {
                    let address = (index * ENTRIES_PER_TABLE + slot as u64) * PAGE_SIZE;
                    let new = if self.shared_at(address).is_some() {
                        Page {
                            prot: page.prot,
                            frame: page.frame.clone(),
                        }
                    } else {
                        let new = Page::new(page.prot);
                        if let Some(frame) = page.frame.get() {
                            let bytes = FrameBytes::new(self.meter.as_ref(), || {
                                frame
                                    .iter()
                                    .map(|byte| AtomicU8::new(byte.load(Ordering::Relaxed)))
                                    .collect()
                            })
                            .ok_or(Errno::ENOMEM)?;
                            let _ = new.frame.set(bytes);
                        }
                        new
                    };
                    cloned.pages[slot] = Some(new);
                }
            }
            directory.insert(index, cloned);
        }
        *copy
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = directory;
        Ok(copy)
    }

    fn bump_code_generation(&mut self) {
        *self.code_generation.get_mut() += 1;
    }

    /// The mappings in address order.
    pub fn mappings(&self) -> impl Iterator<Item = &Mapping> {
        self.mappings.values()
    }

    /// Sets the top of the region used for mappings without a fixed address.
    pub fn set_mmap_top(&mut self, top: GuestAddr) {
        self.mmap_top = top.page_align_down().0.min(USER_ADDRESS_LIMIT);
    }

    fn read_directory(&self) -> RwLockReadGuard<'_, Directory> {
        self.directory
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn write_directory(&self) -> RwLockWriteGuard<'_, Directory> {
        self.directory
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The mapping that contains `addr`.
    fn mapping_at(&self, addr: u64) -> Option<&Mapping> {
        self.mappings
            .range(..=addr)
            .next_back()
            .map(|(_, m)| m)
            .filter(|m| m.end() > addr)
    }

    fn prot_at(&self, directory: &Directory, addr: u64) -> Option<Prot> {
        lookup(directory, addr)
            .map(|p| p.prot)
            .or_else(|| self.mapping_at(addr).map(|m| m.prot))
    }

    /// Checks that `[addr, addr+len)` is accessible; returns the first
    /// faulting address otherwise.
    fn check(
        &self,
        directory: &Directory,
        addr: GuestAddr,
        len: usize,
        access: Access,
    ) -> Result<(), Fault> {
        let fault = |at: u64| Fault {
            addr: GuestAddr(at),
            write: access.is_write(),
            fetch: access == Access::Fetch,
            mapped: self.mapping_at(at).is_some(),
            present: lookup(directory, at).is_some()
                && self.prot_at(directory, at) != Some(Prot::NONE),
        };
        let wide = u64::try_from(len).map_err(|_| fault(addr.0))?;
        addr.0.checked_add(wide).ok_or(fault(addr.0))?;
        for (page, offset, _) in chunks(addr, len) {
            let at = page + offset as u64;
            if at >= USER_ADDRESS_LIMIT {
                return Err(fault(at));
            }
            match self.prot_at(directory, page) {
                Some(prot) if access.permitted(prot) => {}
                _ => return Err(fault(at)),
            }
        }
        Ok(())
    }

    fn read_with(&self, addr: GuestAddr, buf: &mut [u8], access: Access) -> Result<(), Fault> {
        let mut directory = self.write_directory();
        self.check(&directory, addr, buf.len(), access)?;
        // A successful lazy read installs the logical zero-page entry without
        // allocating its byte frame, matching subsequent Linux fault metadata.
        for (page, _, _) in chunks(addr, buf.len()) {
            if lookup(&directory, page).is_none()
                && let Some(prot) = self.mapping_at(page).map(|m| m.prot)
            {
                let (dir, slot) = page_index(page);
                let table = directory.entry(dir).or_insert_with(PageTable::new);
                if let Some(entry) = table.pages.get_mut(slot) {
                    *entry = Some(self.page(page, prot));
                }
            }
        }
        for (page, offset, range) in chunks(addr, buf.len()) {
            let dst = &mut buf[range];
            match lookup(&directory, page).and_then(|p| p.frame.get()) {
                Some(frame) => {
                    for (d, s) in dst.iter_mut().zip(&frame[offset..]) {
                        *d = s.load(Ordering::Relaxed);
                    }
                }
                None => dst.fill(0),
            }
        }
        Ok(())
    }

    /// Writes `buf`, which [`Self::check`] allowed, into populated pages. A
    /// page the meter has no room for faults, and marks the space out of
    /// memory.
    fn store(&self, directory: &Directory, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        for (page, offset, range) in chunks(addr, buf.len()) {
            if let Some(p) = lookup(directory, page) {
                if let Some(mapping) = self.shared_at(page) {
                    mapping.generation.fetch_add(1, Ordering::Release);
                }
                if p.prot.contains(Prot::EXEC) {
                    // Code may have changed: decoded instructions are stale.
                    self.code_generation.fetch_add(1, Ordering::Release);
                }
                let Some(frame) = p.frame_for_write(self.meter.as_ref()) else {
                    self.out_of_memory.store(true, Ordering::SeqCst);
                    return Err(Fault {
                        addr: GuestAddr(page),
                        write: true,
                        fetch: false,
                        mapped: true,
                        present: false,
                    });
                };
                for (s, d) in buf[range].iter().zip(&frame[offset..]) {
                    d.store(*s, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }

    fn write_with(&self, addr: GuestAddr, buf: &[u8], access: Access) -> Result<(), Fault> {
        {
            let directory = self.read_directory();
            self.check(&directory, addr, buf.len(), access)?;
            let populated =
                chunks(addr, buf.len()).all(|(page, _, _)| lookup(&directory, page).is_some());
            if populated {
                return self.store(&directory, addr, buf);
            }
        }
        // Populate the pages this write touches for the first time.
        let mut directory = self.write_directory();
        self.check(&directory, addr, buf.len(), access)?;
        for (page, _, _) in chunks(addr, buf.len()) {
            if lookup(&directory, page).is_some() {
                continue;
            }
            let Some(prot) = self.mapping_at(page).map(|m| m.prot) else {
                return Err(Fault {
                    addr: GuestAddr(page),
                    write: true,
                    fetch: false,
                    mapped: false,
                    present: false,
                });
            };
            let (dir, slot) = page_index(page);
            let table = directory.entry(dir).or_insert_with(PageTable::new);
            if let Some(entry) = table.pages.get_mut(slot) {
                *entry = Some(self.page(page, prot));
            }
        }
        self.store(&directory, addr, buf)
    }

    /// Reads guest memory (any mapped page is readable on x86).
    pub fn read(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.read_with(addr, buf, Access::Read)
    }

    /// Writes guest memory; requires `PROT_WRITE`.
    pub fn write(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.write_with(addr, buf, Access::Write)
    }

    /// Fetches instruction bytes; requires `PROT_EXEC`.
    pub fn fetch(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.read_with(addr, buf, Access::Fetch)
    }

    /// Fetches as many instruction bytes as are executable starting at
    /// `addr`, up to `buf.len()`. Returns the number of bytes fetched, or the
    /// fault when not even the first byte is executable.
    pub fn fetch_partial(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<usize, Fault> {
        let mut len = buf.len();
        while len > 0 {
            match self.fetch(addr, &mut buf[..len]) {
                Ok(()) => return Ok(len),
                Err(fault) if fault.addr.0 > addr.0 => {
                    len = usize::try_from(fault.addr.0 - addr.0).unwrap_or(0);
                }
                Err(fault) => return Err(fault),
            }
        }
        Ok(0)
    }

    /// Writes ignoring page protection (pages must be mapped). Used by the
    /// loader to fill read-only segments and the initial stack.
    pub fn write_initial(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.write_with(addr, buf, Access::Setup)
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&self, addr: GuestAddr) -> Result<u64, Fault> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&self, addr: GuestAddr, value: u64) -> Result<(), Fault> {
        self.write(addr, &value.to_le_bytes())
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        // The mapping that starts last before `end` is the only candidate,
        // because mappings never overlap each other.
        self.mappings
            .range(..end)
            .next_back()
            .is_some_and(|(_, m)| m.end() > start)
    }

    fn find_free(&self, len: u64) -> Option<u64> {
        let mut end = self.mmap_top;
        for (_, m) in self.mappings.range(..self.mmap_top).rev() {
            if m.end() <= end && end - m.end() >= len {
                break;
            }
            end = end.min(m.start.0);
        }
        let start = end.checked_sub(len)?;
        (start >= MMAP_MIN_ADDR).then_some(start)
    }

    /// Applies `f` to every populated page entry in `[start, end)`. Only the
    /// page tables that exist are visited, so huge ranges are cheap.
    fn for_populated(&mut self, start: u64, end: u64, mut f: impl FnMut(&mut Option<Page>)) {
        if end <= start {
            return;
        }
        let first_dir = start / PAGE_SIZE / ENTRIES_PER_TABLE;
        let last_dir = (end - 1) / PAGE_SIZE / ENTRIES_PER_TABLE;
        let directory = self
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let mut emptied = Vec::new();
        for (&dir, table) in directory.range_mut(first_dir..=last_dir) {
            for (slot, entry) in table.pages.iter_mut().enumerate() {
                let page = (dir * ENTRIES_PER_TABLE + slot as u64) * PAGE_SIZE;
                if page >= start && page < end && entry.is_some() {
                    f(entry);
                }
            }
            if table.is_empty() {
                emptied.push(dir);
            }
        }
        for dir in emptied {
            directory.remove(&dir);
        }
    }

    /// Maps zero-filled pages. With `Some(addr)` the region must be free
    /// (`EEXIST` otherwise); with `None` a free region is chosen below the
    /// mmap top. `len` is rounded up to whole pages. Pages are populated
    /// lazily, so the cost does not depend on `len`.
    pub fn map(
        &mut self,
        addr: Option<GuestAddr>,
        len: u64,
        prot: Prot,
        kind: MappingKind,
    ) -> Result<GuestAddr, Errno> {
        let start = match addr {
            Some(a) => a.0,
            None => {
                let rounded = GuestAddr(len).page_align_up().ok_or(Errno::ENOMEM)?.0;
                if rounded == 0 {
                    return Err(Errno::EINVAL);
                }
                self.find_free(rounded).ok_or(Errno::ENOMEM)?
            }
        };
        let end = checked_range(GuestAddr(start), len)?;
        if self.overlaps(start, end) {
            return Err(Errno::EEXIST);
        }
        self.bump_code_generation();
        self.mappings.insert(
            start,
            Mapping {
                start: GuestAddr(start),
                length: end - start,
                prot,
                kind,
            },
        );
        Ok(GuestAddr(start))
    }

    /// Splits mappings so that `at` is a mapping boundary.
    fn split_at(&mut self, at: u64) {
        let Some((&start, &m)) = self.mappings.range(..at).next_back() else {
            return;
        };
        if m.end() <= at || start == at {
            return;
        }
        let head = Mapping {
            length: at - start,
            ..m
        };
        let tail = Mapping {
            start: GuestAddr(at),
            length: m.end() - at,
            ..m
        };
        self.mappings.insert(start, head);
        self.mappings.insert(at, tail);
    }

    /// Unmaps `[addr, addr+len)`. Unmapped holes inside the range are fine.
    pub fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        let affected: Vec<_> = self
            .shared
            .iter()
            .filter(|(start, mapping)| **start < end && mapping.end > addr.0)
            .map(|(&start, mapping)| (start, mapping.clone()))
            .collect();
        for (start, mapping) in affected {
            self.shared.remove(&start);
            if start < addr.0 {
                self.shared.insert(
                    start,
                    SharedMapping {
                        end: addr.0,
                        ..mapping.clone()
                    },
                );
            }
            if mapping.end > end {
                self.shared.insert(end, mapping);
            }
        }
        self.unback(addr.0, end);
        self.split_at(addr.0);
        self.split_at(end);
        let doomed: Vec<u64> = self
            .mappings
            .range(addr.0..end)
            .map(|(&start, _)| start)
            .collect();
        for start in doomed {
            self.mappings.remove(&start);
        }
        self.for_populated(addr.0, end, |entry| *entry = None);
        self.bump_code_generation();
        Ok(())
    }

    /// Whether two mappings would be one Linux VMA when adjacent: the same
    /// protection and kind, and both private or both the same shared memory.
    fn mergeable(&self, a: &Mapping, b: &Mapping) -> bool {
        a.prot == b.prot
            && a.kind == b.kind
            && match (self.shared_at(a.start.0), self.shared_at(b.start.0)) {
                (None, None) => true,
                (Some(x), Some(y)) => Arc::ptr_eq(&x.frames, &y.frames) && x.shift == y.shift,
                _ => false,
            }
    }

    /// The `[start, end)` of the Linux VMA holding `addr`: the mapping there
    /// and the adjacent ones Linux would have merged with it.
    fn region_at(&self, addr: u64) -> Option<(u64, u64)> {
        let mut first = *self.mapping_at(addr)?;
        let mut last = first;
        while let Some((_, m)) = self.mappings.range(..first.start.0).next_back() {
            if m.end() != first.start.0 || !self.mergeable(m, &first) {
                break;
            }
            first = *m;
        }
        while let Some(m) = self.mappings.get(&last.end()) {
            if !self.mergeable(&last, m) {
                break;
            }
            last = *m;
        }
        Some((first.start.0, last.end()))
    }

    /// Takes the populated page entries of `[start, end)` with their
    /// addresses; with `keep` the entries stay and the pages are shared.
    fn take_pages(&mut self, start: u64, end: u64, keep: bool) -> Vec<(u64, Page)> {
        let mut pages = Vec::new();
        if end <= start {
            return pages;
        }
        let directory = self
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let (first, last) = (
            start / PAGE_SIZE / ENTRIES_PER_TABLE,
            (end - 1) / PAGE_SIZE / ENTRIES_PER_TABLE,
        );
        for (&dir, table) in directory.range_mut(first..=last) {
            for (slot, entry) in table.pages.iter_mut().enumerate() {
                let page = (dir * ENTRIES_PER_TABLE + slot as u64) * PAGE_SIZE;
                if page < start || page >= end {
                    continue;
                }
                let taken = if keep {
                    entry.as_ref().map(|p| Page {
                        prot: p.prot,
                        frame: p.frame.clone(),
                    })
                } else {
                    entry.take()
                };
                if let Some(taken) = taken {
                    pages.push((page, taken));
                }
            }
        }
        directory.retain(|_, table| !table.is_empty());
        pages
    }

    /// Moves `[old, old+old_len)` to a free `[to, to+new_len)`, carrying
    /// its pages (and its shared memory, under a new frame key shift).
    fn move_region(&mut self, old: u64, old_len: u64, to: u64, new_len: u64, keep_old: bool) {
        let Some(&mapping) = self.mapping_at(old) else {
            return;
        };
        let shared = self.shared_at(old).cloned();
        let backing = self.backing_at(old).cloned();
        let pages = self.take_pages(old, old + old_len, keep_old && shared.is_some());
        if !keep_old && old_len > 0 {
            let _ = self.unmap(GuestAddr(old), old_len);
        }
        if let Some(backing) = backing {
            self.backing.insert(
                to,
                FileBacking {
                    end: to + new_len,
                    shift: backing.shift.wrapping_add(old).wrapping_sub(to),
                    ..backing
                },
            );
            // MREMAP_DONTUNMAP left the old range empty: it reads its file.
            if keep_old && shared.is_none() {
                self.refill(old, old + old_len);
            }
        }
        if let Some(shared) = shared {
            self.shared.insert(
                to,
                SharedMapping {
                    end: to + new_len,
                    shift: shared.shift.wrapping_add(old).wrapping_sub(to),
                    ..shared
                },
            );
        }
        self.mappings.insert(
            to,
            Mapping {
                start: GuestAddr(to),
                length: new_len,
                ..mapping
            },
        );
        let directory = self
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for (page, entry) in pages {
            let (dir, slot) = page_index(page - old + to);
            directory.entry(dir).or_insert_with(PageTable::new).pages[slot] = Some(entry);
        }
        self.bump_code_generation();
    }

    /// `mremap`, with Linux's checks in Linux's order: resizes the mapping
    /// at `addr`, growing it in place when the pages after it are free, else
    /// moving it as `how` allows. A grown or moved range must lie in one
    /// Linux VMA (`EFAULT`). A file mapping cannot grow (`ENOMEM`), as
    /// nothing reads the rest of its file into it. Moving a range that spans
    /// several VMAs with `MREMAP_FIXED`, which recent Linux allows, gives
    /// `EFAULT`.
    pub fn remap(
        &mut self,
        addr: GuestAddr,
        old_len: u64,
        new_len: u64,
        how: Remap,
    ) -> Result<GuestAddr, Errno> {
        // PAGE_ALIGN wraps: a length in the last page becomes 0.
        let align = |len: u64| len.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let (old_len, new_len) = (align(old_len), align(new_len));
        if addr.page_offset() != 0 || new_len == 0 || new_len > USER_ADDRESS_LIMIT {
            return Err(Errno::EINVAL);
        }
        // MREMAP_FIXED and MREMAP_DONTUNMAP both name a new address: the
        // target, or a hint for DONTUNMAP alone.
        let new_addr = (how.fixed || how.keep_old).then_some(how.new_addr.0);
        if let Some(to) = new_addr
            && (to > USER_ADDRESS_LIMIT - new_len
                || to % PAGE_SIZE != 0
                || !how.may_move
                || (how.keep_old && old_len != new_len)
                || (to < addr.0.wrapping_add(old_len) && addr.0 < to + new_len))
        {
            return Err(Errno::EINVAL);
        }
        let mapping = *self.mapping_at(addr.0).ok_or(Errno::EFAULT)?;
        if new_addr.is_none() && new_len <= old_len {
            if new_len < old_len {
                self.unmap(GuestAddr(addr.0 + new_len), old_len - new_len)?;
            }
            return Ok(addr);
        }
        let shared = self.shared_at(addr.0).is_some();
        if old_len == 0 && !shared {
            return Err(Errno::EINVAL);
        }
        // A shrink may cross the end of the VMA: only what stays must not.
        let kept = old_len.min(new_len);
        let (_, region_end) = self.region_at(addr.0).ok_or(Errno::EFAULT)?;
        if kept > region_end - addr.0 {
            return Err(Errno::EFAULT);
        }
        if new_len > old_len && mapping.kind == MappingKind::File {
            return Err(Errno::ENOMEM);
        }
        let old_end = addr.0 + old_len;
        if let Some(hint) = new_addr {
            let to = if how.fixed {
                self.unmap(GuestAddr(hint), new_len)?;
                hint
            } else if hint != 0 && hint >= MMAP_MIN_ADDR && !self.overlaps(hint, hint + new_len) {
                hint
            } else {
                self.find_free(new_len).ok_or(Errno::ENOMEM)?
            };
            if old_len > new_len {
                self.unmap(GuestAddr(addr.0 + new_len), old_len - new_len)?;
            }
            self.move_region(addr.0, kept, to, new_len, how.keep_old);
            return Ok(GuestAddr(to));
        }
        let new_end = addr
            .0
            .checked_add(new_len)
            .filter(|&end| end <= USER_ADDRESS_LIMIT);
        if old_len > 0
            && old_end == region_end
            && let Some(new_end) = new_end
            && !self.overlaps(old_end, new_end)
        {
            let last = *self.mapping_at(old_end - 1).ok_or(Errno::EFAULT)?;
            self.mappings.insert(
                old_end,
                Mapping {
                    start: GuestAddr(old_end),
                    length: new_end - old_end,
                    ..last
                },
            );
            if let Some((_, entry)) = self.shared.range_mut(..old_end).next_back()
                && entry.end == old_end
            {
                entry.end = new_end;
            }
            self.bump_code_generation();
            return Ok(addr);
        }
        if !how.may_move {
            return Err(Errno::ENOMEM);
        }
        let to = self.find_free(new_len).ok_or(Errno::ENOMEM)?;
        self.move_region(addr.0, old_len, to, new_len, false);
        Ok(GuestAddr(to))
    }

    /// Whether every page of `[addr, addr+len)` is mapped (`msync`).
    pub fn covers(&self, addr: GuestAddr, len: u64) -> Result<bool, Errno> {
        let end = checked_range(addr, len)?;
        let mut covered = addr.0;
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= covered {
                continue;
            }
            if m.start.0 > covered {
                return Ok(false);
            }
            covered = m.end();
        }
        Ok(covered >= end)
    }

    /// Changes the protection of `[addr, addr+len)`; every page must be
    /// mapped (`ENOMEM` otherwise, as on Linux).
    pub fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        // The mappings must cover the range without holes.
        let mut covered = addr.0;
        let mut denied = false;
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= covered {
                continue;
            }
            if m.start.0 > covered {
                break;
            }
            // A shared file mapping cannot become writable (see `File`).
            if prot.contains(Prot::WRITE)
                && m.kind == MappingKind::File
                && self.shared_at(m.start.0).is_some()
            {
                denied = true;
                break;
            }
            covered = m.end();
        }
        if covered == addr.0 {
            return Err(if denied { Errno::EACCES } else { Errno::ENOMEM });
        }
        // Linux applies the mapped prefix before reporting a later hole or
        // a mapping that refuses the protection.
        let incomplete = covered < end;
        let end = end.min(covered);
        self.split_at(addr.0);
        self.split_at(end);
        self.bump_code_generation();
        for (_, m) in self.mappings.range_mut(addr.0..end) {
            m.prot = prot;
        }
        self.for_populated(addr.0, end, |entry| {
            if let Some(page) = entry {
                page.prot = prot;
            }
        });
        if denied {
            Err(Errno::EACCES)
        } else if incomplete {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Drops the contents of the private pages in `[addr, addr+len)`
    /// (`MADV_DONTNEED`): anonymous ones read as zeros again, and those of a
    /// file mapping or an ELF segment read their file again
    /// ([`Self::back_with_file`]), as Linux faults them in from the file.
    /// Shared pages keep theirs, as their memory outlives the mapping, and so
    /// do the ones without a recorded file (a read-only ELF segment), which
    /// have nothing to read again. Applies the
    /// mapped parts and returns `ENOMEM` when the range has a hole, as Linux
    /// does.
    pub fn discard(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        let mut covered = addr.0;
        let mut hole = false;
        let mut private = Vec::new();
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= addr.0 {
                continue;
            }
            hole |= m.start.0 > covered;
            covered = m.end();
            let start = m.start.0.max(addr.0);
            // An ELF segment or a file mapping without its file keeps its
            // contents: there is nothing to read it from again.
            let backed = matches!(m.kind, MappingKind::ElfSegment | MappingKind::File)
                && self.backing_at(start).is_some();
            if (backed || !matches!(m.kind, MappingKind::ElfSegment | MappingKind::File))
                && self.shared_at(start).is_none()
            {
                private.push((start, m.end().min(end)));
            }
        }
        hole |= covered < end;
        if !private.is_empty() {
            self.bump_code_generation();
        }
        for (start, end) in private {
            self.for_populated(start, end, |entry| *entry = None);
            self.refill(start, end);
        }
        if hole { Err(Errno::ENOMEM) } else { Ok(()) }
    }

    /// Whether `[addr, addr+len)` is all private anonymous memory, as
    /// `MADV_FREE` requires: `EINVAL` for a shared page, an ELF segment
    /// or a file mapping (file-backed on Linux), else `ENOMEM` for a hole.
    pub fn check_private_anonymous(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        let mut covered = addr.0;
        let mut hole = false;
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= addr.0 {
                continue;
            }
            hole |= m.start.0 > covered;
            covered = m.end();
            if matches!(m.kind, MappingKind::ElfSegment | MappingKind::File)
                || self.shared_at(m.start.0.max(addr.0)).is_some()
            {
                return Err(Errno::EINVAL);
            }
        }
        if hole || covered < end {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Sets the initial program break (end of the last loaded segment,
    /// page-aligned). Called once by the loader.
    pub fn set_initial_break(&mut self, addr: GuestAddr) {
        let aligned = addr.page_align_up().unwrap_or(addr);
        self.initial_break = aligned;
        self.current_break = aligned;
    }

    /// The initial program break.
    #[must_use]
    pub fn initial_break(&self) -> GuestAddr {
        self.initial_break
    }

    /// The current program break.
    #[must_use]
    pub fn current_break(&self) -> GuestAddr {
        self.current_break
    }

    /// `brk` semantics: requests below the initial break, or that
    /// would overlap another mapping, leave the break unchanged. Returns the
    /// resulting break.
    pub fn set_break(&mut self, addr: GuestAddr) -> GuestAddr {
        if addr < self.initial_break {
            return self.current_break;
        }
        let Some(new_top) = addr.page_align_up() else {
            return self.current_break;
        };
        let Some(old_top) = self.current_break.page_align_up() else {
            return self.current_break;
        };
        if new_top.0 > USER_ADDRESS_LIMIT {
            return self.current_break;
        }
        if new_top > old_top {
            if self
                .map(
                    Some(old_top),
                    new_top.0 - old_top.0,
                    Prot::READ_WRITE,
                    MappingKind::Heap,
                )
                .is_err()
            {
                return self.current_break;
            }
        } else if new_top < old_top && self.unmap(new_top, old_top.0 - new_top.0).is_err() {
            return self.current_break;
        }
        self.current_break = addr;
        addr
    }
}

/// Width of an indivisible integer memory operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicWidth {
    W8,
    W16,
    W32,
    W64,
    W128,
}
impl AtomicWidth {
    const fn bytes(self) -> usize {
        match self {
            Self::W8 => 1,
            Self::W16 => 2,
            Self::W32 => 4,
            Self::W64 => 8,
            Self::W128 => 16,
        }
    }
}
/// Closed set of updates: no caller-controlled callback runs under the lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp {
    Exchange(u128),
    CompareExchange { expected: u128, replacement: u128 },
    Add(u128),
    Sub(u128),
    And(u128),
    Or(u128),
    Xor(u128),
    Not,
    Neg,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicResult {
    pub old: u128,
    pub exchanged: bool,
}

/// A shared address space. Every memory and mapping operation serializes on
/// this one lock, including ordinary reads/writes/fetches. The private data
/// implementation never calls back through this public wrapper (no reentry).
pub struct AddressSpace {
    data: Mutex<AddressSpaceData>,
    serialization: Arc<Mutex<()>>,
    /// The data's `out_of_memory`, so that every checkpoint can read it
    /// without taking the session-wide serialization lock.
    out_of_memory: Arc<AtomicBool>,
}

/// Owned instruction bytes and their epoch, captured under one MMU lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSnapshot {
    pub address_space: u64,
    pub generation: u64,
    pub bytes: Vec<u8>,
}

struct AddressSpaceGuard<'a> {
    data: MutexGuard<'a, AddressSpaceData>,
    _serialization: MutexGuard<'a, ()>,
}
impl std::ops::Deref for AddressSpaceGuard<'_> {
    type Target = AddressSpaceData;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
impl std::ops::DerefMut for AddressSpaceGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

#[cfg(test)]
mod processes_tests;

#[cfg(test)]
mod jit_tests;
#[cfg(test)]
mod threads_tests;
impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}
impl AddressSpace {
    #[must_use]
    pub fn new() -> Self {
        Self::with_data(AddressSpaceData::new(), Arc::default())
    }
    fn with_data(data: AddressSpaceData, serialization: Arc<Mutex<()>>) -> Self {
        Self {
            out_of_memory: Arc::clone(&data.out_of_memory),
            data: Mutex::new(data),
            serialization,
        }
    }
    fn locked(&self) -> AddressSpaceGuard<'_> {
        let serialization = self
            .serialization
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        AddressSpaceGuard {
            data: self.data.lock().unwrap_or_else(PoisonError::into_inner),
            _serialization: serialization,
        }
    }
    /// Charges this space's frames to `meter`, and the frames of the spaces
    /// forked from it.
    #[must_use]
    pub fn with_memory_meter(mut self, meter: Arc<MemoryMeter>) -> Self {
        self.data
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .meter = Some(meter);
        self
    }
    /// The meter this space's frames are charged to.
    #[must_use]
    pub fn memory_meter(&self) -> Option<Arc<MemoryMeter>> {
        self.locked().meter.clone()
    }
    /// Whether a write found no room under the meter since the last call.
    pub fn take_out_of_memory(&self) -> bool {
        self.out_of_memory.swap(false, Ordering::SeqCst)
    }
    /// Private pages are copied; sparse MAP_SHARED pages retain backing. A shared
    /// serialization lock keeps cross-process memory operations indivisible.
    /// The copies fail with `ENOMEM` when the meter has no room for them.
    pub fn fork(&self) -> Result<Self, Errno> {
        Ok(Self::with_data(
            self.locked().fork()?,
            self.serialization.clone(),
        ))
    }
    /// Marks a newly created mapping as Linux MAP_SHARED, independently of VM sharing.
    pub fn mark_shared(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        let mut data = self.locked();
        if !data
            .mappings
            .values()
            .any(|mapping| mapping.start.0 == addr.0 && mapping.end() == end)
        {
            return Err(Errno::EINVAL);
        }
        let frames = data
            .read_directory()
            .iter()
            .flat_map(|(&index, table)| {
                table
                    .pages
                    .iter()
                    .enumerate()
                    .filter_map(move |(slot, page)| {
                        page.as_ref().map(|page| {
                            (
                                (index * ENTRIES_PER_TABLE + slot as u64) * PAGE_SIZE,
                                page.frame.clone(),
                            )
                        })
                    })
            })
            .filter(|(page, _)| *page >= addr.0 && *page < end)
            .collect();
        data.shared.insert(
            addr.0,
            SharedMapping {
                end,
                shift: 0,
                frames: Arc::new(Mutex::new(frames)),
                generation: Arc::default(),
            },
        );
        Ok(())
    }
    #[must_use]
    pub fn id(&self) -> u64 {
        self.locked().id()
    }
    #[must_use]
    pub fn code_generation(&self) -> u64 {
        self.locked().code_generation()
    }
    /// Reads cache identity and generation under the same serialization guard.
    #[must_use]
    pub fn code_epoch(&self) -> (u64, u64) {
        let data = self.locked();
        (data.id(), data.code_generation())
    }
    /// Captures executable bytes without a fetch/generation race. JIT blocks
    /// are bounded to 960 bytes; callers cannot request unbounded allocations.
    pub fn code_snapshot(&self, address: GuestAddr, maximum: usize) -> Result<CodeSnapshot, Fault> {
        let data = self.locked();
        let mut bytes = vec![0; maximum.min(960)];
        let count = data.fetch_partial(address, &mut bytes)?;
        bytes.truncate(count);
        Ok(CodeSnapshot {
            address_space: data.id(),
            generation: data.code_generation(),
            bytes,
        })
    }
    /// Checks the captured epoch and serializes translated execution with all
    /// memory and mapping changes, including another process's shared writes.
    /// The callback must not reenter this AddressSpace: it may only execute
    /// register-only translated code against its private CPU scratch buffer.
    pub fn with_code_epoch<T>(
        &self,
        address_space: u64,
        generation: u64,
        execute: impl FnOnce() -> T,
    ) -> Option<T> {
        let data = self.locked();
        if data.id() != address_space || data.code_generation() != generation {
            return None;
        }
        Some(execute())
    }
    /// A consistent mapping snapshot; borrowed entries cannot outlive the lock.
    pub fn mappings(&self) -> impl Iterator<Item = Mapping> {
        self.locked()
            .mappings()
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
    }
    pub fn set_mmap_top(&mut self, top: GuestAddr) {
        self.locked().set_mmap_top(top);
    }
    pub fn read(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.locked().read(addr, buf)
    }
    pub fn write(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.locked().write(addr, buf)
    }
    /// Checks a syscall buffer's read permission before allocating a copy.
    pub fn check_read(&self, addr: GuestAddr, len: usize) -> Result<(), Fault> {
        let data = self.locked();
        data.check(&data.read_directory(), addr, len, Access::Read)
    }
    /// Checks a stack allocation's write permission without changing bytes.
    pub fn check_write(&self, addr: GuestAddr, len: usize) -> Result<(), Fault> {
        let data = self.locked();
        data.check(&data.read_directory(), addr, len, Access::Write)
    }
    pub fn fetch(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.locked().fetch(addr, buf)
    }
    pub fn fetch_partial(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<usize, Fault> {
        self.locked().fetch_partial(addr, buf)
    }
    pub fn write_initial(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.locked().write_initial(addr, buf)
    }
    pub fn read_u64(&self, addr: GuestAddr) -> Result<u64, Fault> {
        self.locked().read_u64(addr)
    }
    pub fn write_u64(&self, addr: GuestAddr, value: u64) -> Result<(), Fault> {
        self.locked().write_u64(addr, value)
    }
    pub fn map(
        &mut self,
        addr: Option<GuestAddr>,
        len: u64,
        prot: Prot,
        kind: MappingKind,
    ) -> Result<GuestAddr, Errno> {
        self.map_shared(addr, len, prot, kind)
    }
    /// Mapping access for host workers sharing an address space (guest threads).
    pub fn map_shared(
        &self,
        addr: Option<GuestAddr>,
        len: u64,
        prot: Prot,
        kind: MappingKind,
    ) -> Result<GuestAddr, Errno> {
        self.locked().map(addr, len, prot, kind)
    }
    pub fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.unmap_shared(addr, len)
    }
    pub fn unmap_shared(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.locked().unmap(addr, len)
    }
    pub fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), Errno> {
        self.protect_shared(addr, len, prot)
    }
    /// See [`AddressSpaceData::discard`].
    pub fn discard_shared(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.locked().discard(addr, len)
    }
    /// See [`AddressSpaceData::back_with_file`].
    pub fn back_with_file(
        &self,
        addr: GuestAddr,
        len: u64,
        source: Arc<dyn PageSource>,
        offset: u64,
    ) -> Result<(), Errno> {
        self.locked().back_with_file(addr, len, source, offset)
    }
    /// See [`AddressSpaceData::check_private_anonymous`].
    pub fn check_private_anonymous(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.locked().check_private_anonymous(addr, len)
    }
    /// See [`AddressSpaceData::remap`].
    pub fn remap_shared(
        &self,
        addr: GuestAddr,
        old_len: u64,
        new_len: u64,
        how: Remap,
    ) -> Result<GuestAddr, Errno> {
        self.locked().remap(addr, old_len, new_len, how)
    }
    /// See [`AddressSpaceData::covers`].
    pub fn covers(&self, addr: GuestAddr, len: u64) -> Result<bool, Errno> {
        self.locked().covers(addr, len)
    }
    pub fn protect_shared(&self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), Errno> {
        self.locked().protect(addr, len, prot)
    }
    pub fn set_initial_break(&mut self, addr: GuestAddr) {
        self.locked().set_initial_break(addr);
    }
    #[must_use]
    pub fn initial_break(&self) -> GuestAddr {
        self.locked().initial_break()
    }
    #[must_use]
    pub fn current_break(&self) -> GuestAddr {
        self.locked().current_break()
    }
    pub fn set_break(&mut self, addr: GuestAddr) -> GuestAddr {
        self.locked().set_break(addr)
    }
    /// Adjusts the shared process break under the memory/mapping lock.
    pub fn set_break_shared(&self, addr: GuestAddr) -> GuestAddr {
        self.locked().set_break(addr)
    }
    /// Validate the whole write range even on failed comparison, then perform
    /// exactly one update under the same lock as all other address-space access.
    pub fn atomic(
        &self,
        addr: GuestAddr,
        width: AtomicWidth,
        operation: AtomicOp,
    ) -> Result<AtomicResult, Fault> {
        let data = self.locked();
        let len = width.bytes();
        data.check(&data.read_directory(), addr, len, Access::Write)?;
        let mut bytes = [0u8; 16];
        data.read(addr, &mut bytes[..len])?;
        let old = u128::from_le_bytes(bytes);
        let mask = if len == 16 {
            u128::MAX
        } else {
            (1u128 << (len * 8)) - 1
        };
        let (new, exchanged) = match operation {
            AtomicOp::Exchange(value) => (value, true),
            AtomicOp::CompareExchange {
                expected,
                replacement,
            } => {
                if old == expected & mask {
                    (replacement, true)
                } else {
                    (old, false)
                }
            }
            AtomicOp::Add(value) => (old.wrapping_add(value), true),
            AtomicOp::Sub(value) => (old.wrapping_sub(value), true),
            AtomicOp::And(value) => (old & value, true),
            AtomicOp::Or(value) => (old | value, true),
            AtomicOp::Xor(value) => (old ^ value, true),
            AtomicOp::Not => (!old, true),
            AtomicOp::Neg => (old.wrapping_neg(), true),
        };
        data.write(addr, &(new & mask).to_le_bytes()[..len])?;
        Ok(AtomicResult { old, exchanged })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space_with(addr: u64, len: u64, prot: Prot) -> AddressSpace {
        let mut space = AddressSpace::new();
        space
            .map(Some(GuestAddr(addr)), len, prot, MappingKind::Anonymous)
            .unwrap();
        space
    }

    #[test]
    fn write_then_read_across_page_boundary() {
        let space = space_with(0x10000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        let data: Vec<u8> = (0..32).collect();
        space.write(GuestAddr(0x10ff0), &data).unwrap();
        let mut back = vec![0u8; 32];
        space.read(GuestAddr(0x10ff0), &mut back).unwrap();
        assert_eq!(back, data);
        // Untouched memory reads as zero.
        assert_eq!(space.read_u64(GuestAddr(0x10000)).unwrap(), 0);
    }

    #[test]
    fn unmapped_access_faults_with_address() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE);
        let mut buf = [0u8; 16];
        let err = space.read(GuestAddr(0x10ff8), &mut buf).unwrap_err();
        assert_eq!(
            err,
            Fault {
                addr: GuestAddr(0x11000),
                write: false,
                fetch: false,
                mapped: false,
                present: false
            }
        );
        let err = space.write(GuestAddr(0x5000), &buf).unwrap_err();
        assert_eq!(
            err,
            Fault {
                addr: GuestAddr(0x5000),
                write: true,
                fetch: false,
                mapped: false,
                present: false
            }
        );
        // Addresses beyond the user range and overflowing ranges fault too.
        assert!(space.read(GuestAddr(u64::MAX - 3), &mut buf).is_err());
        assert!(space.read(GuestAddr(USER_ADDRESS_LIMIT), &mut buf).is_err());
    }

    #[test]
    fn protection_is_enforced() {
        let space = space_with(0x20000, PAGE_SIZE, Prot::READ);
        let mut buf = [0u8; 4];
        assert!(space.read(GuestAddr(0x20000), &mut buf).is_ok());
        assert!(space.write(GuestAddr(0x20000), &buf).is_err());
        assert!(space.fetch(GuestAddr(0x20000), &mut buf).is_err());
        // The loader may still fill it.
        space
            .write_initial(GuestAddr(0x20000), &[1, 2, 3, 4])
            .unwrap();
        space.read(GuestAddr(0x20000), &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn fetch_partial_stops_at_non_executable_page() {
        let mut space = space_with(0x30000, PAGE_SIZE, Prot::READ_EXEC);
        let mut buf = [0u8; 15];
        assert_eq!(space.fetch_partial(GuestAddr(0x30ffa), &mut buf), Ok(6));
        assert!(space.fetch_partial(GuestAddr(0x31000), &mut buf).is_err());
        space
            .protect(GuestAddr(0x30000), PAGE_SIZE, Prot::READ)
            .unwrap();
        assert!(space.fetch_partial(GuestAddr(0x30000), &mut buf).is_err());
    }

    #[test]
    fn map_rejects_overlap_and_bad_arguments() {
        let mut space = space_with(0x40000, 2 * PAGE_SIZE, Prot::READ);
        let anon = MappingKind::Anonymous;
        assert_eq!(
            space.map(Some(GuestAddr(0x41000)), PAGE_SIZE, Prot::READ, anon),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            space.map(Some(GuestAddr(0x40001)), PAGE_SIZE, Prot::READ, anon),
            Err(Errno::EINVAL)
        );
        assert_eq!(space.map(None, 0, Prot::READ, anon), Err(Errno::EINVAL));
        assert_eq!(
            space.map(
                Some(GuestAddr(USER_ADDRESS_LIMIT - PAGE_SIZE)),
                2 * PAGE_SIZE,
                Prot::READ,
                anon
            ),
            Err(Errno::ENOMEM)
        );
        assert!(space.map(None, u64::MAX, Prot::READ, anon).is_err());
    }

    #[test]
    fn map_without_address_picks_free_region_top_down() {
        let mut space = AddressSpace::new();
        space.set_mmap_top(GuestAddr(0x100000));
        let anon = MappingKind::Anonymous;
        let a = space.map(None, 100, Prot::READ_WRITE, anon).unwrap();
        assert_eq!(a, GuestAddr(0xff000));
        let b = space
            .map(None, 2 * PAGE_SIZE, Prot::READ_WRITE, anon)
            .unwrap();
        assert_eq!(b, GuestAddr(0xfd000));
        space.unmap(a, PAGE_SIZE).unwrap();
        let c = space.map(None, PAGE_SIZE, Prot::READ_WRITE, anon).unwrap();
        assert_eq!(c, a);
        assert_eq!(space.mappings().count(), 2);
    }

    #[test]
    fn unmap_splits_mappings() {
        let mut space = space_with(0x50000, 3 * PAGE_SIZE, Prot::READ_WRITE);
        space.unmap(GuestAddr(0x51000), PAGE_SIZE).unwrap();
        let regions: Vec<(u64, u64)> = space.mappings().map(|m| (m.start.0, m.length)).collect();
        assert_eq!(regions, vec![(0x50000, PAGE_SIZE), (0x52000, PAGE_SIZE)]);
        assert!(space.read_u64(GuestAddr(0x51000)).is_err());
        assert_eq!(
            space.unmap(GuestAddr(0x50001), PAGE_SIZE),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            space.protect(GuestAddr(0x50000), 3 * PAGE_SIZE, Prot::READ),
            Err(Errno::ENOMEM)
        );
    }

    #[test]
    fn code_generation_changes_on_code_writes_and_mapping_changes() {
        let mut space = space_with(0x10000, PAGE_SIZE, Prot::READ_EXEC);
        space
            .map(
                Some(GuestAddr(0x20000)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        let g0 = space.code_generation();
        space.write_u64(GuestAddr(0x20000), 1).unwrap();
        assert_eq!(
            space.code_generation(),
            g0,
            "data writes keep decoded code valid"
        );
        space.write_initial(GuestAddr(0x10000), &[0x90]).unwrap();
        let g1 = space.code_generation();
        assert_ne!(g1, g0);
        space
            .protect(GuestAddr(0x20000), PAGE_SIZE, Prot::READ_EXEC)
            .unwrap();
        assert_ne!(space.code_generation(), g1);
    }

    #[test]
    fn huge_mappings_are_populated_lazily() {
        // Found by the mmu_ops fuzz target: a terabyte brk/mmap must not
        // allocate host memory up front.
        let mut space = AddressSpace::new();
        space.set_initial_break(GuestAddr(0x10000));
        let top = space.set_break(GuestAddr(0x100_0000_0000));
        assert_eq!(top, GuestAddr(0x100_0000_0000));
        space.write_u64(GuestAddr(0xff_ffff_fff8), 5).unwrap();
        assert_eq!(space.read_u64(GuestAddr(0xff_ffff_fff8)).unwrap(), 5);
        assert_eq!(space.read_u64(GuestAddr(0x80_0000_0000)).unwrap(), 0);
        let anon = space
            .map(None, 1 << 44, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        assert!(space.write_u64(anon, 1).is_err());
        space.unmap(GuestAddr(0x10000), 0xff_ffff_0000).unwrap();
        assert!(space.read_u64(GuestAddr(0xff_ffff_fff8)).is_err());
    }

    #[test]
    fn break_grows_shrinks_and_never_goes_below_initial() {
        let mut space = AddressSpace::new();
        space.set_initial_break(GuestAddr(0x60123));
        assert_eq!(space.initial_break(), GuestAddr(0x61000));
        assert_eq!(space.set_break(GuestAddr(0x1000)), GuestAddr(0x61000));
        assert_eq!(space.set_break(GuestAddr(0x63010)), GuestAddr(0x63010));
        space.write_u64(GuestAddr(0x63000), 7).unwrap();
        assert_eq!(space.set_break(GuestAddr(0x62000)), GuestAddr(0x62000));
        assert!(space.read_u64(GuestAddr(0x63000)).is_err());
        // Growing into another mapping leaves the break unchanged.
        space
            .map(
                Some(GuestAddr(0x70000)),
                PAGE_SIZE,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert_eq!(space.set_break(GuestAddr(0x80000)), GuestAddr(0x62000));
        assert_eq!(space.current_break(), GuestAddr(0x62000));
    }

    #[test]
    fn discard_zeroes_private_pages_and_keeps_shared_and_elf_ones() {
        let space = space_with(0x10000, 2 * PAGE_SIZE, Prot::READ);
        space.write_initial(GuestAddr(0x10008), &[7]).unwrap();
        space.write_initial(GuestAddr(0x11008), &[8]).unwrap();
        space.discard_shared(GuestAddr(0x10000), PAGE_SIZE).unwrap();
        assert_eq!(space.read_u64(GuestAddr(0x10008)).unwrap(), 0);
        assert_eq!(space.read_u64(GuestAddr(0x11008)).unwrap(), 8);
        // The mapping and its protection stay.
        assert!(space.write_u64(GuestAddr(0x10008), 1).is_err());

        let shared = space
            .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        space.mark_shared(shared, PAGE_SIZE).unwrap();
        space.write_u64(shared, 9).unwrap();
        let elf = space
            .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::ElfSegment)
            .unwrap();
        space.write_u64(elf, 10).unwrap();
        space.discard_shared(shared, PAGE_SIZE).unwrap();
        space.discard_shared(elf, PAGE_SIZE).unwrap();
        assert_eq!(space.read_u64(shared).unwrap(), 9);
        assert_eq!(space.read_u64(elf).unwrap(), 10);
    }

    /// A file of `len` bytes, each its offset modulo 251.
    struct Pattern(u64);
    impl PageSource for Pattern {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
            let n = usize::try_from(self.0.saturating_sub(offset))
                .map_or(buf.len(), |n| n.min(buf.len()));
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = ((offset + i as u64) % 251) as u8;
            }
            Ok(n)
        }
    }

    #[test]
    fn discard_reads_a_private_file_mapping_from_its_file_again() {
        let space = AddressSpace::new();
        let file = space
            .map_shared(None, 3 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        // The mapping starts at file offset 4096, and the file ends 100
        // bytes into its third page.
        let source: Arc<dyn PageSource> = Arc::new(Pattern(3 * PAGE_SIZE + 100));
        space
            .back_with_file(file, 3 * PAGE_SIZE, Arc::clone(&source), PAGE_SIZE)
            .unwrap();
        let at = |page: u64, offset: u64| GuestAddr(file.0 + page * PAGE_SIZE + offset);
        for (page, offset) in [(0, 0), (1, 7), (2, 99), (2, 100)] {
            space.write(at(page, offset), &[0xee]).unwrap();
        }
        // Only the second page: the others keep what was written.
        space.discard_shared(at(1, 0), PAGE_SIZE).unwrap();
        assert_eq!(byte(&space, at(1, 7).0), ((2 * PAGE_SIZE + 7) % 251) as u8);
        assert_eq!(byte(&space, at(0, 0).0), 0xee);
        space.discard_shared(file, 3 * PAGE_SIZE).unwrap();
        assert_eq!(byte(&space, at(0, 0).0), (PAGE_SIZE % 251) as u8);
        assert_eq!(
            byte(&space, at(2, 99).0),
            ((3 * PAGE_SIZE + 99) % 251) as u8
        );
        assert_eq!(byte(&space, at(2, 100).0), 0); // past the end of the file
        // A fork, and a move by mremap, keep the file at the same offsets.
        let child = space.fork().unwrap();
        space.write(at(0, 1), &[0xee]).unwrap();
        let fixed = Remap {
            fixed: true,
            new_addr: GuestAddr(0x4000_0000),
            ..MOVE
        };
        let moved = space
            .remap_shared(file, 3 * PAGE_SIZE, 3 * PAGE_SIZE, fixed)
            .unwrap();
        assert_ne!(moved, file);
        space.discard_shared(moved, PAGE_SIZE).unwrap();
        assert_eq!(byte(&space, moved.0 + 1), ((PAGE_SIZE + 1) % 251) as u8);
        child.write(at(1, 3), &[0xee]).unwrap();
        child.discard_shared(at(1, 0), PAGE_SIZE).unwrap();
        assert_eq!(byte(&child, at(1, 3).0), ((2 * PAGE_SIZE + 3) % 251) as u8);
        // Unmapping the middle page forgets only its file.
        space
            .unmap_shared(GuestAddr(moved.0 + PAGE_SIZE), PAGE_SIZE)
            .unwrap();
        space
            .write(GuestAddr(moved.0 + 2 * PAGE_SIZE), &[0xee])
            .unwrap();
        space
            .discard_shared(GuestAddr(moved.0 + 2 * PAGE_SIZE), PAGE_SIZE)
            .unwrap();
        assert_eq!(
            byte(&space, moved.0 + 2 * PAGE_SIZE),
            ((3 * PAGE_SIZE) % 251) as u8
        );
    }

    #[test]
    fn discard_applies_the_mapped_part_of_a_range_with_a_hole() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE);
        space.write_u64(GuestAddr(0x10000), 1).unwrap();
        assert_eq!(
            space.discard_shared(GuestAddr(0x10000), 2 * PAGE_SIZE),
            Err(Errno::ENOMEM)
        );
        assert_eq!(space.read_u64(GuestAddr(0x10000)).unwrap(), 0);
        assert_eq!(
            space.discard_shared(GuestAddr(0xf000), 2 * PAGE_SIZE),
            Err(Errno::ENOMEM)
        );
    }

    fn byte(space: &AddressSpace, addr: u64) -> u8 {
        let mut b = [0];
        space.read(GuestAddr(addr), &mut b).unwrap();
        b[0]
    }

    const MOVE: Remap = Remap {
        may_move: true,
        fixed: false,
        keep_old: false,
        new_addr: GuestAddr(0),
    };

    #[test]
    fn remap_grows_in_place_shrinks_and_moves_with_contents() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE);
        space.write(GuestAddr(0x10000), &[7]).unwrap();
        // The pages after it are free: it grows in place.
        assert_eq!(
            space.remap_shared(GuestAddr(0x10000), 4096, 3 * 4096, Remap::default()),
            Ok(GuestAddr(0x10000))
        );
        space.write(GuestAddr(0x12000), &[8]).unwrap();
        space
            .map_shared(
                Some(GuestAddr(0x13000)),
                4096,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        // Blocked by the next mapping: only a move can grow it.
        assert_eq!(
            space.remap_shared(GuestAddr(0x10000), 3 * 4096, 4 * 4096, Remap::default()),
            Err(Errno::ENOMEM)
        );
        let moved = space
            .remap_shared(GuestAddr(0x10000), 3 * 4096, 4 * 4096, MOVE)
            .unwrap();
        assert_ne!(moved, GuestAddr(0x10000));
        assert_eq!(
            (byte(&space, moved.0), byte(&space, moved.0 + 0x2000)),
            (7, 8)
        );
        assert!(space.read(GuestAddr(0x10000), &mut [0]).is_err());
        assert_eq!(
            space.remap_shared(moved, 4 * 4096, 4096, Remap::default()),
            Ok(moved)
        );
        assert!(space.read(GuestAddr(moved.0 + 4096), &mut [0]).is_err());
    }

    #[test]
    fn remap_rejects_ranges_outside_one_region() {
        let space = space_with(0x10000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        let at = GuestAddr(0x10000);
        assert_eq!(
            space.remap_shared(GuestAddr(0x10001), 4096, 4096, MOVE),
            Err(Errno::EINVAL)
        );
        assert_eq!(space.remap_shared(at, 4096, 0, MOVE), Err(Errno::EINVAL));
        assert_eq!(
            space.remap_shared(GuestAddr(0x40000), 4096, 8192, MOVE),
            Err(Errno::EFAULT)
        );
        // Growing or moving needs the whole old range in one VMA; a shrink
        // may cross its end, as only what stays must not.
        let grow = |old, new| space.remap_shared(at, old, new, Remap::default());
        assert_eq!(grow(3 * 4096, 4 * 4096), Err(Errno::EFAULT));
        // Old length 0 duplicates only shared memory.
        assert_eq!(space.remap_shared(at, 0, 4096, MOVE), Err(Errno::EINVAL));
        // A protection change splits the mapping; the parts are separate VMAs.
        space
            .protect_shared(GuestAddr(0x11000), 4096, Prot::READ)
            .unwrap();
        assert_eq!(grow(8192, 3 * 4096), Err(Errno::EFAULT));
        // Splits Linux would have merged again stay one region.
        space
            .protect_shared(GuestAddr(0x11000), 4096, Prot::READ_WRITE)
            .unwrap();
        assert_eq!(grow(8192, 3 * 4096), Ok(at));
        assert_eq!(space.remap_shared(at, 5 * 4096, 4096, MOVE), Ok(at));
        assert!(space.read(GuestAddr(0x11000), &mut [0]).is_err());
        let fixed = Remap {
            fixed: true,
            new_addr: GuestAddr(0x10800),
            ..MOVE
        };
        assert_eq!(
            space.remap_shared(at, 4096, 4096, fixed),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn remap_fixed_replaces_the_target_and_dontunmap_empties_the_old_range() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE);
        space.write(GuestAddr(0x10000), &[5]).unwrap();
        space
            .map_shared(
                Some(GuestAddr(0x20000)),
                2 * 4096,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        space.write(GuestAddr(0x21000), &[6]).unwrap();
        let fixed = Remap {
            fixed: true,
            keep_old: true,
            new_addr: GuestAddr(0x20000),
            ..MOVE
        };
        assert_eq!(
            space.remap_shared(GuestAddr(0x10000), 4096, 4096, fixed),
            Ok(GuestAddr(0x20000))
        );
        // The pages moved; the old range is still mapped, but empty.
        assert_eq!(byte(&space, 0x20000), 5);
        assert_eq!(byte(&space, 0x10000), 0);
        // Only the target's length was replaced.
        assert_eq!(byte(&space, 0x21000), 6);
    }

    #[test]
    fn remap_keeps_shared_memory_shared_after_fork_and_on_duplicates() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE);
        space.mark_shared(GuestAddr(0x10000), 4096).unwrap();
        let child = space.fork().unwrap();
        let moved = space
            .remap_shared(
                GuestAddr(0x10000),
                4096,
                2 * 4096,
                Remap {
                    fixed: true,
                    new_addr: GuestAddr(0x30000),
                    ..MOVE
                },
            )
            .unwrap();
        // A page neither process had written yet is still the same memory.
        child.write(GuestAddr(0x10000), &[9]).unwrap();
        assert_eq!(byte(&space, moved.0), 9);
        space.write(GuestAddr(moved.0), &[10]).unwrap();
        assert_eq!(byte(&child, 0x10000), 10);
        // Old length 0 maps the same shared memory a second time.
        let duplicate = space.remap_shared(moved, 0, 4096, MOVE).unwrap();
        assert_ne!(duplicate, moved);
        space.write(duplicate, &[11]).unwrap();
        assert_eq!(byte(&child, 0x10000), 11);
        assert_eq!(byte(&space, moved.0), 11);
    }

    #[test]
    fn remap_does_not_grow_a_file_copy_and_covers_finds_holes() {
        let space = AddressSpace::new();
        space
            .map_shared(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ,
                MappingKind::File,
            )
            .unwrap();
        assert_eq!(
            space.remap_shared(GuestAddr(0x10000), 4096, 8192, MOVE),
            Err(Errno::ENOMEM)
        );
        assert!(
            space
                .remap_shared(GuestAddr(0x10000), 4096, 4096, MOVE)
                .is_ok()
        );
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ);
        space
            .map_shared(
                Some(GuestAddr(0x12000)),
                4096,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert_eq!(space.covers(GuestAddr(0x10000), 4096), Ok(true));
        assert_eq!(space.covers(GuestAddr(0x10000), 3 * 4096), Ok(false));
        assert_eq!(space.covers(GuestAddr(0x11000), 4096), Ok(false));
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod instructions_tests;
