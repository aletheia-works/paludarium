//! Software MMU for paludarium.
//!
//! A guest address space is a two-level page table of 4 KiB pages: a sparse
//! directory (one entry per 512 pages) pointing at dense tables of 512 page
//! entries. Every access goes through checked guest addresses; a missing
//! page or a protection violation returns a [`Fault`] and never panics.
//!
//! Page contents are atomic words so that `read`/`write` work through a
//! shared reference without `unsafe` (the CPU writes guest memory while the
//! address space is shared, and later units add threads). Page entries are
//! created lazily on the first write, so the cost of a mapping does not
//! depend on its size.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
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
    /// A file mapped by `mmap`: the pages of the file's page cache
    /// ([`SharedPages`]), which a private mapping copies on its first write
    /// to each.
    File,
}

/// A contiguous, page-aligned region of the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: GuestAddr,
    pub length: u64,
    pub prot: Prot,
    pub kind: MappingKind,
    /// A page of it was written, or of the Linux VMA it was part of then:
    /// Linux's `anon_vma`, which the VMA keeps through splits, `fork` and
    /// `mremap`, and which a core dump writes a private mapping whole for.
    pub written: bool,
    /// `mseal` sealed it (Linux's `VM_SEALED`): it is not unmapped, moved,
    /// resized or given another protection (EPERM), and its anonymous
    /// read-only pages are not discarded.
    pub sealed: bool,
    /// `MADV_DONTFORK` (Linux's `VM_DONTCOPY`): a `fork`ed child does not
    /// get it.
    pub dont_fork: bool,
    /// `MADV_WIPEONFORK` (Linux's `VM_WIPEONFORK`): a `fork`ed child gets it
    /// with none of its pages, as new zero-filled memory.
    pub wipe_on_fork: bool,
    /// `MADV_DONTDUMP` (Linux's `VM_DONTDUMP`): a core dump holds none of it.
    pub dont_dump: bool,
    /// `MADV_GUARD_INSTALL` put guards in its Linux VMA (`VM_MAYBE_GUARD`),
    /// which stays when they go, does not stop a merge, and makes `fork`
    /// copy the VMA's page tables.
    pub maybe_guard: bool,
    /// `mlock` locked it (Linux's `VM_LOCKED`), and with `MLOCK_ONFAULT`
    /// brings in only the pages something touches (`VM_LOCKONFAULT`).
    pub locked: Option<Lock>,
}

/// How a mapping is locked ([`Mapping::locked`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lock {
    /// Every page is brought in (`VM_LOCKED`).
    Populated,
    /// Pages are brought in as they are touched (`VM_LOCKONFAULT`).
    OnFault,
}

/// The `madvise` advice that sets or clears a flag of the VMAs of a range
/// ([`AddressSpace::advise_flags`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagAdvice {
    DontFork,
    DoFork,
    WipeOnFork,
    KeepOnFork,
    DontDump,
    DoDump,
}

/// What a page table holds for a mapped page, as Linux's `folio_walk`
/// finds it for `move_pages` ([`AddressSpace::page_state`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    /// Nothing touched the page since it was mapped or discarded: no page.
    Absent,
    /// Only read, in private anonymous memory: Linux's shared zero page.
    Zero,
    /// A page of its own, a file's, or shared memory's.
    Present,
}

/// What a core dump needs to know of the Linux VMA at an address
/// ([`AddressSpace::core_state`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreState {
    /// A page of the VMA was written ([`Mapping::written`]).
    pub written: bool,
    /// The VMA is a shared mapping.
    pub shared: bool,
    /// The VMA is a shared mapping of a file that a name links
    /// ([`PageSource::linked`]); a shared anonymous one maps none.
    pub linked: bool,
    /// Where in its file a file mapping starts.
    pub file_offset: Option<u64>,
}

/// The file a mapping maps ([`AddressSpace::mapped_file`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedFile {
    /// Its path ([`PageSource::name`]).
    pub name: Option<Vec<u8>>,
    /// Whether it has a file of its own: shared anonymous memory has none,
    /// where Linux gives it one of no name.
    pub source: bool,
    /// Where the mapping's address lies in it.
    pub offset: u64,
}

/// One shared mapping of an address space, as
/// [`AddressSpace::shared_fragments`] lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedFragment {
    pub start: u64,
    pub end: u64,
    /// Where `start` lies in the shared memory (a file's offset).
    pub offset: u64,
    /// The open file it maps ([`PageSource::open_file`]), or 0 for none.
    pub open_file: usize,
    /// It maps secret memory ([`PageSource::secret`]).
    pub secret: bool,
}

/// A Linux VMA as `/proc/<pid>/maps` shows it ([`MemoryView::vma_from`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    /// The mapping is shared (Linux's `VM_MAYSHARE`).
    pub shared: bool,
    /// Where in its file the VMA starts, or 0 without a file.
    pub offset: u64,
    /// Its file, if it has one: shared anonymous memory has one with no
    /// [`MappedFile::source`], as Linux gives it a file of no name.
    pub file: Option<MappedFile>,
    /// The device and inode of its file.
    pub identity: (u64, u64),
    /// It lies across the break's range (Linux's `vma_is_initial_heap`).
    pub heap: bool,
}

impl Mapping {
    /// Exclusive end address.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.0 + self.length
    }
}

/// A failed guest memory access: the faulting address and whether it was a
/// write. Becomes SIGSEGV for the guest, or SIGBUS when `bus` is set.
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
    /// The page of a file mapping lies wholly past the end of its file,
    /// where Linux raises SIGBUS.
    pub bus: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Fetch,
    /// Loader writes into read-only segments while preparing the image.
    Setup,
    /// A core dump reads any mapped page, as Linux's `get_dump_page` does
    /// with `FOLL_FORCE`.
    Dump,
}

impl Access {
    fn permitted(self, prot: Prot) -> bool {
        match self {
            Access::Read => prot.allows_read(),
            Access::Write => prot.contains(Prot::WRITE),
            Access::Fetch => prot.contains(Prot::EXEC),
            Access::Setup | Access::Dump => true,
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

    /// The bytes of page frames it allows.
    #[must_use]
    pub const fn max(&self) -> u64 {
        self.max
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

/// The bytes of one page frame ([`FrameData`]), charged to the meter while
/// the page tables or shared memory hold them: a thread's [`Tlb`] holds only
/// the bytes, so the frames of a page that is gone leave the meter at once,
/// though a thread that has not run since may still hold their bytes.
struct FrameBytes {
    data: Arc<FrameData>,
    meter: Option<Arc<MemoryMeter>>,
}

impl std::ops::Deref for FrameBytes {
    type Target = FrameData;
    fn deref(&self) -> &FrameData {
        &self.data
    }
}

/// The contents of a page frame.
///
/// The words are read with `Acquire` and written with `Release` (a piece of
/// a word with an `AcqRel` read-modify-write), which keeps the orders x86
/// keeps between a thread's accesses (TSO): load to load, load to store and
/// store to store. Only a store followed by a load may be reordered, as on
/// x86. They are what orders the accesses of a thread's TLB, which take no
/// lock ([`ThreadTlb`]). On an x86-64 host they cost nothing.
///
/// Threads of one space (`CLONE_VM`) share a private page's frame, and may
/// write other bytes of one word at once, so a piece of a word is always
/// written with a read-modify-write of the word, which keeps the others'.
/// A locked instruction within one word is one too ([`Self::update`]).
struct FrameData {
    /// The bytes as little-endian words, so that an aligned word of a guest
    /// takes one atomic access, where each byte would take its own.
    words: Box<[AtomicU64]>,
    /// A guest store changed the bytes since [`SharedPages::write_back`]
    /// last took them.
    dirty: AtomicBool,
    /// How many writes of more than one word have started and finished, so
    /// that an aligned 16-byte read sees one of them whole, as it does on an
    /// x86-64 CPU ([`Self::read_16`]). They are a ticket lock as well, which
    /// such writes take one at a time ([`Self::write_with`]).
    spanning_started: AtomicU64,
    spanning_finished: AtomicU64,
}

impl FrameBytes {
    /// A frame of `bytes`, or `None` when the meter has no room for it.
    fn new(
        meter: Option<&Arc<MemoryMeter>>,
        words: impl FnOnce() -> Box<[AtomicU64]>,
    ) -> Option<Self> {
        if meter.is_some_and(|meter| !meter.charge()) {
            return None;
        }
        Some(FrameBytes {
            data: Arc::new(FrameData {
                words: words(),
                dirty: AtomicBool::new(false),
                spanning_started: AtomicU64::new(0),
                spanning_finished: AtomicU64::new(0),
            }),
            meter: meter.cloned(),
        })
    }
}

/// The bytes in one word of a frame.
const WORD_BYTES: usize = 8;

/// The bits of a value of `size` bytes, 1 to 8.
#[inline]
const fn value_mask(size: usize) -> u64 {
    u64::MAX >> (64 - 8 * size)
}

/// The words of a page that starts with `bytes` and is otherwise zero.
fn page_words(bytes: &[u8]) -> Box<[AtomicU64]> {
    (0..PAGE_BYTES / WORD_BYTES)
        .map(|word| {
            let mut value = [0; WORD_BYTES];
            if let Some(piece) = bytes.get(word * WORD_BYTES..) {
                let n = piece.len().min(WORD_BYTES);
                value[..n].copy_from_slice(&piece[..n]);
            }
            AtomicU64::new(u64::from_le_bytes(value))
        })
        .collect()
}

impl FrameData {
    /// Copies the bytes from `offset`, which must stay inside the page, to
    /// `buf`.
    #[inline]
    fn read(&self, offset: usize, buf: &mut [u8]) {
        if let Ok(value) = <&mut [u8; 16]>::try_from(&mut *buf)
            && offset.is_multiple_of(16)
        {
            *value = self.read_16(offset).to_le_bytes();
            return;
        }
        self.read_words(offset, buf);
    }

    /// The aligned 16 bytes at `offset` as no write of more than one word
    /// leaves them halfway, though a load takes no lock: an x86-64 CPU reads
    /// them in one access (`MOVDQA`, `MOVAPS` and the like), so a thread
    /// sees a `CMPXCHG16B` or a 16-byte store of another one whole. The two
    /// words are read again while such a write may have come between them.
    #[inline]
    fn read_16(&self, offset: usize) -> u128 {
        let words = &self.words[offset / WORD_BYTES..][..2];
        let mut spins = 0u32;
        loop {
            // Each write adds to `spanning_started` before its stores, which
            // release it, and to `spanning_finished` after them. A word read
            // from a write therefore shows the write started, and the same
            // count of both shows that no write had started and not finished.
            let finished = self.spanning_finished.load(Ordering::Acquire);
            let started = self.spanning_started.load(Ordering::Relaxed);
            if started == finished {
                let low = words[0].load(Ordering::Acquire);
                let high = words[1].load(Ordering::Acquire);
                if self.spanning_started.load(Ordering::Relaxed) == started {
                    return u128::from(high) << 64 | u128::from(low);
                }
            }
            // Writes may be queued for their turn as well as under way.
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }

    /// [`Self::read`] a word at a time, each word as one access.
    #[inline]
    fn read_words(&self, offset: usize, buf: &mut [u8]) {
        let mut at = offset;
        let mut left = buf;
        while !left.is_empty() {
            let within = at % WORD_BYTES;
            let n = left.len().min(WORD_BYTES - within);
            let mut word = self.words[at / WORD_BYTES].load(Ordering::Acquire) >> (8 * within);
            let (now, rest) = left.split_at_mut(n);
            for byte in now {
                *byte = word as u8;
                word >>= 8;
            }
            left = rest;
            at += n;
        }
    }

    /// Copies `data` to the bytes from `offset`, which must stay inside the
    /// page. A piece of a word leaves the other bytes as another thread may
    /// be writing them.
    fn write(&self, offset: usize, data: &[u8]) {
        self.write_with(offset, data, |word, kept, value| {
            let _ = word.try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some(old & kept | value)
            });
        });
    }

    /// Writes `value`, which lies in one word, as [`Self::write`] does.
    #[inline]
    fn write_value(&self, offset: usize, size: usize, value: u64) {
        let word = &self.words[offset / WORD_BYTES];
        if size == WORD_BYTES {
            word.store(value, Ordering::Release);
        } else {
            let shift = 8 * (offset % WORD_BYTES);
            let mask = value_mask(size) << shift;
            let _ = word.try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some(old & !mask | value << shift & mask)
            });
        }
    }

    /// A locked instruction on the `size` bytes at `offset`, which lie in
    /// one word: one compare-and-swap of the word, so that it is atomic
    /// against every other access to it, with a lock or without. A failed
    /// compare writes the old value back, as `CMPXCHG` does.
    fn update(&self, offset: usize, size: usize, operation: AtomicOp) -> AtomicResult {
        let word = &self.words[offset / WORD_BYTES];
        let shift = 8 * (offset % WORD_BYTES);
        let mask = value_mask(size);
        let mut result = AtomicResult {
            old: 0,
            exchanged: false,
        };
        let _ = word.try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            let old = u128::from(current >> shift & mask);
            let (new, exchanged) = operation.apply(old, u128::from(mask));
            result = AtomicResult { old, exchanged };
            // `apply` masks `new` to `size` bytes, of which 8 are the most.
            let new = u64::try_from(new).unwrap_or(0);
            Some(current & !(mask << shift) | new << shift)
        });
        result
    }

    #[inline]
    fn write_with(&self, offset: usize, data: &[u8], piece: impl Fn(&AtomicU64, u64, u64)) {
        // A write within one word is one access already ([`Self::read_16`]).
        if offset % WORD_BYTES + data.len() <= WORD_BYTES {
            self.write_words(offset, data, piece);
            return;
        }
        // One at a time, in the order they start: a store takes no lock, and
        // two that wrote their words in turn could leave the low one of one
        // and the high one of the other, which neither wrote. On x86-64 an
        // aligned 16-byte store is whole against the other stores too.
        let ticket = self.spanning_started.fetch_add(1, Ordering::Relaxed);
        let mut spins = 0u32;
        // `Acquire`: the writes before this one come before its words.
        while self.spanning_finished.load(Ordering::Acquire) != ticket {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
        // Finished when it ends however it does, so that a panic in the
        // middle leaves no read or later write waiting for it.
        let _finished = SpanningWrite {
            finished: &self.spanning_finished,
            ticket,
        };
        self.write_words(offset, data, piece);
    }

    #[inline]
    fn write_words(&self, offset: usize, data: &[u8], piece: impl Fn(&AtomicU64, u64, u64)) {
        let mut at = offset;
        let mut left = data;
        while !left.is_empty() {
            let within = at % WORD_BYTES;
            let n = left.len().min(WORD_BYTES - within);
            let (now, rest) = left.split_at(n);
            let word = &self.words[at / WORD_BYTES];
            let value = now
                .iter()
                .rev()
                .fold(0, |value, byte| value << 8 | u64::from(*byte))
                << (8 * within);
            if n == WORD_BYTES {
                word.store(value, Ordering::Release);
            } else {
                piece(word, !((u64::MAX >> (64 - 8 * n)) << (8 * within)), value);
            }
            left = rest;
            at += n;
            #[cfg(test)]
            if !left.is_empty()
                && let Some(stall) = WORD_STALL.get()
            {
                std::thread::sleep(stall);
            }
        }
    }
}

/// The turn of a write of more than one word ([`FrameBytes::read_16`]),
/// which ends when it drops: the next write's turn comes.
struct SpanningWrite<'a> {
    finished: &'a AtomicU64,
    ticket: u64,
}

impl Drop for SpanningWrite<'_> {
    #[inline]
    fn drop(&mut self) {
        self.finished.store(self.ticket + 1, Ordering::Release);
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
    /// The page belongs to a file mapping, which may end before it.
    file: bool,
    /// The first write to the page copies its frame first: the frame is
    /// the file's page-cache page, which a private mapping shows, or one
    /// that `fork` shares between the spaces until either writes it.
    cow: bool,
    /// The frame is the file's page-cache page.
    cache: bool,
    /// How many times the file had shrunk ([`PageSource::shrinks`]) when
    /// a private mapping copied the page.
    shrinks: u64,
}

impl Page {
    /// The same entry, showing the same frame.
    fn share(&self) -> Self {
        Page {
            prot: self.prot,
            frame: self.frame.clone(),
            file: self.file,
            cow: self.cow,
            cache: self.cache,
            shrinks: self.shrinks,
        }
    }

    /// The contents to write, allocated now if need be; `None` when the
    /// meter has no room for them.
    fn frame_for_write(&self, meter: Option<&Arc<MemoryMeter>>) -> Option<&FrameBytes> {
        allocated(&self.frame, meter)
    }
}

/// A frame with a copy of the contents of `frame`, which has none if `frame`
/// has none; `None` when the meter has no room for them.
fn copied(frame: &Frame, meter: Option<&Arc<MemoryMeter>>) -> Option<Frame> {
    let copy = Arc::new(frame.successor());
    if let Some(bytes) = frame.get() {
        let bytes = FrameBytes::new(meter, || {
            bytes
                .words
                .iter()
                .map(|word| AtomicU64::new(word.load(Ordering::Acquire)))
                .collect()
        })?;
        let _ = copy.set(bytes);
    }
    Some(copy)
}

/// The contents of `frame`, allocated as zeros now if need be; `None` when
/// the meter has no room for them.
fn allocated<'a>(frame: &'a Frame, meter: Option<&Arc<MemoryMeter>>) -> Option<&'a FrameBytes> {
    if frame.get().is_none() {
        let bytes = FrameBytes::new(meter, || page_words(&[]))?;
        // A racing write to a shared frame may set it first: then this one
        // is dropped, and its charge with it.
        let _ = frame.set(bytes);
    }
    frame.get()
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

type Frame = Arc<FrameCell>;

/// The contents of a page, which its entry, the [`ThreadTlb`]s that hold
/// it and a [`SharedPages`] share, and whether an instruction was fetched
/// from it.
#[derive(Default)]
struct FrameCell {
    bytes: OnceLock<FrameBytes>,
    /// An instruction was fetched from the page: from then on a store to it
    /// while it is executable bumps the code generation, as decoded
    /// instructions of the page may be cached. A store to code nothing
    /// fetched leaves the generation, so that one to data on a page that is
    /// also executable (the heap of SBCL, of a JIT) does not make every
    /// decoded instruction stale. Set under the space's locks after the
    /// epoch moved on ([`AddressSpaceData::mark_fetched`]), and never
    /// cleared: a page that holds data again costs decodes, not
    /// correctness. The [`TlbEntry`]s of the page share it, as they hold
    /// the bytes and not the cell ([`TlbFrame`]).
    fetched: Arc<AtomicBool>,
}

impl FrameCell {
    #[inline]
    fn get(&self) -> Option<&FrameBytes> {
        self.bytes.get()
    }
    fn set(&self, bytes: FrameBytes) -> Result<(), FrameBytes> {
        self.bytes.set(bytes)
    }
    /// Whether an instruction was fetched from the page. `Acquire`: a
    /// fetch that sees it set sees every store that did not see it
    /// ([`AddressSpaceData::mark_fetched`]).
    #[inline]
    fn fetched(&self) -> bool {
        self.fetched.load(Ordering::Acquire)
    }
    /// A cell without contents that keeps this one's mark, for a frame that
    /// takes the place of this one: an instruction decoded from this one
    /// is as stale after a store to that one.
    fn successor(&self) -> Self {
        FrameCell {
            bytes: OnceLock::new(),
            fetched: Arc::new(AtomicBool::new(self.fetched())),
        }
    }
}

/// Where [`AddressSpace::map_backed`] puts a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// At this address, in place of what is mapped there (`MAP_FIXED`).
    Replacing(GuestAddr),
    /// At this address, which must be free (`MAP_FIXED_NOREPLACE`).
    Exactly(GuestAddr),
    /// At the hint if it is free, else wherever there is room.
    Near(Option<GuestAddr>),
}

/// What a mapping [`AddressSpace::map_backed`] makes shows.
#[derive(Clone, Copy)]
pub enum Backing<'a> {
    /// Its own zero-filled pages.
    None,
    /// Zero-filled pages that `fork` shares (`MAP_SHARED | MAP_ANONYMOUS`),
    /// as [`AddressSpace::mark_shared`] makes them.
    SharedAnonymous,
    /// `pages` from key `offset` on ([`AddressSpace::share_pages`]).
    Shared {
        pages: &'a SharedPages,
        offset: u64,
        may_write: bool,
    },
    /// The page cache `pages` from `offset`, until a page is written
    /// ([`AddressSpace::back_with_cache`]).
    Cache { pages: &'a SharedPages, offset: u64 },
}

/// Memory that every mapping of it shows, in every address space: shared
/// anonymous memory, or the page cache of a file, whose frames are keyed by
/// their offset in the file. The page cache's owner (a kernel object that
/// writes it back) lives as long as a mapping or a clone of it does.
#[derive(Clone)]
pub struct SharedPages {
    /// Tells this memory from any other, as the inode of the file Linux
    /// gives shared anonymous memory does.
    id: u64,
    frames: Arc<Mutex<BTreeMap<u64, Frame>>>,
    /// Bumped by every store to the frames, before and after it: one
    /// through a mapping, and those of the kernel ([`Self::store`],
    /// [`Self::zero`]).
    generation: Arc<AtomicU64>,
    /// The code generations of the spaces that may run code from the
    /// frames ([`Self::watch`]), which every bump of `generation` bumps too.
    watchers: Arc<Watchers>,
    /// Held only to keep the owner alive.
    _owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// The file of a page cache, which a page without contents is read
    /// from and whose end a mapping cannot reach past.
    source: Option<Arc<dyn PageSource>>,
}

impl Default for SharedPages {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedPages {
    /// Memory without frames yet.
    #[must_use]
    pub fn new() -> Self {
        Self::with_frames(BTreeMap::new())
    }
    fn with_frames(frames: BTreeMap<u64, Frame>) -> Self {
        SharedPages {
            id: NEXT_SHARED_PAGES_ID.fetch_add(1, Ordering::Relaxed),
            frames: Arc::new(Mutex::new(frames)),
            generation: Arc::default(),
            watchers: Arc::default(),
            _owner: None,
            source: None,
        }
    }
    /// The same memory, keeping `owner` alive while the clone lives.
    #[must_use]
    pub fn with_owner(&self, owner: Arc<dyn std::any::Any + Send + Sync>) -> Self {
        SharedPages {
            _owner: Some(owner),
            ..self.clone()
        }
    }
    /// The file of a page cache, if these pages are one.
    #[must_use]
    pub fn source(&self) -> Option<&Arc<dyn PageSource>> {
        self.source.as_ref()
    }
    /// The same memory, read from `source` where a page has no contents and
    /// ending where the file does.
    #[must_use]
    pub fn with_source(&self, source: Arc<dyn PageSource>) -> Self {
        SharedPages {
            source: Some(source),
            ..self.clone()
        }
    }
    /// Tells this memory from any other: its clones share it.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }
    /// How many of its pages have contents (Linux's resident pages of a
    /// shared memory file).
    #[must_use]
    pub fn resident(&self) -> u64 {
        self.lock()
            .values()
            .filter(|frame| frame.get().is_some())
            .count() as u64
    }
    /// Changes whenever the contents may have changed.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    /// Bumps the generation, and the code generation of every space that
    /// watches the frames, after a store to them (and, for one through a
    /// mapping, before it too).
    fn changed(&self) {
        self.stores().changed();
    }
    /// What a store moves on, for a [`Tlb`] to hold.
    fn stores(&self) -> SharedStores {
        SharedStores {
            generation: Arc::clone(&self.generation),
            watchers: Arc::clone(&self.watchers),
        }
    }
    /// Makes every later store to the frames bump `code`'s generation, as a
    /// space that may run code from them needs.
    ///
    /// A store whose bump after it found no watcher comes before the
    /// [`Watchers::add`] in the single order of `SeqCst` operations, and so
    /// does that bump. The load of the generation after the `add` therefore
    /// reads it, and synchronizes with it: the stored bytes are visible to
    /// every fetch the space makes afterwards, which caches them under a
    /// generation read later still.
    fn watch(&self, code: &Arc<CodeCounters>) {
        self.watchers.add(code);
        self.generation.load(Ordering::SeqCst);
    }
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Frame>> {
        self.frames.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The frames whose page starts in `[start, end)`, by key.
    fn frames_in(&self, start: u64, end: u64) -> Vec<(u64, Frame)> {
        let first = start - start % PAGE_SIZE;
        self.lock()
            .range(first..end)
            .map(|(&key, frame)| (key, frame.clone()))
            .collect()
    }
    /// Whether the page at `key` has contents.
    #[must_use]
    pub fn contains(&self, key: u64) -> bool {
        self.lock()
            .get(&key)
            .is_some_and(|frame| frame.get().is_some())
    }
    /// Gives the page at `key` the contents `bytes` (zeros after them)
    /// unless it has some already; `ENOMEM` when the meter has no room.
    pub fn fill(
        &self,
        key: u64,
        bytes: &[u8],
        meter: Option<&Arc<MemoryMeter>>,
    ) -> Result<(), Errno> {
        let frame = self.lock().entry(key).or_default().clone();
        if frame.get().is_some() {
            return Ok(());
        }
        let contents = FrameBytes::new(meter, || page_words(bytes)).ok_or(Errno::ENOMEM)?;
        let _ = frame.set(contents);
        Ok(())
    }
    /// Stores `data` at offset `at` of the memory, as a write to the file
    /// does to its page cache. Pages without contents are left alone: a
    /// mapping reads them from the file when it first touches them. The pages
    /// do not become dirty.
    pub fn store(&self, at: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut done = 0;
        while done < data.len() {
            let offset = at + done as u64;
            let key = offset - offset % PAGE_SIZE;
            let within = page_offset(offset);
            let piece = (PAGE_BYTES - within).min(data.len() - done);
            let frame = self.lock().get(&key).cloned();
            if let Some(bytes) = frame.as_ref().and_then(|frame| frame.get()) {
                bytes.write(within, &data[done..done + piece]);
            }
            done += piece;
        }
        // After the bytes, as in `AddressSpaceData::store`.
        self.changed();
    }
    /// Copies the bytes from offset `at` of the memory to `buf`, as the
    /// kernel reads memory it shares with the mappings of it (an io_uring
    /// ring). Pages without contents read as zeros.
    pub fn load(&self, at: u64, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let offset = at + done as u64;
            let key = offset - offset % PAGE_SIZE;
            let within = page_offset(offset);
            let piece = (PAGE_BYTES - within).min(buf.len() - done);
            let frame = self.lock().get(&key).cloned();
            match frame.as_ref().and_then(|frame| frame.get()) {
                Some(bytes) => bytes.read(within, &mut buf[done..done + piece]),
                None => buf[done..done + piece].fill(0),
            }
            done += piece;
        }
    }
    /// Zeros `[start, end)` of the memory, as truncating or punching a hole
    /// in the file does to its page cache. The pages do not become dirty.
    pub fn zero(&self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        for (key, frame) in self.frames_in(start, end) {
            if let Some(bytes) = frame.get() {
                let from = usize::try_from(start.saturating_sub(key)).unwrap_or(PAGE_BYTES);
                let to = usize::try_from(end - key).map_or(PAGE_BYTES, |n| n.min(PAGE_BYTES));
                let zeros = [0; PAGE_BYTES];
                if let Some(zeros) = zeros.get(..to.saturating_sub(from)) {
                    bytes.write(from, zeros);
                }
            }
        }
        self.changed();
    }
    /// Hands each page a guest store changed since the last call to
    /// `write`, with its key, and marks it clean. A page whose `write`
    /// fails stays dirty, and the error ends the call.
    pub fn write_back(
        &self,
        mut write: impl FnMut(u64, &[u8]) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        let frames = self.frames_in(0, u64::MAX);
        let mut page = vec![0; PAGE_BYTES];
        for (key, frame) in frames {
            let Some(bytes) = frame.get() else {
                continue;
            };
            if !bytes.dirty.swap(false, Ordering::Acquire) {
                continue;
            }
            bytes.read(0, &mut page);
            if let Err(error) = write(key, &page) {
                bytes.dirty.store(true, Ordering::Release);
                return Err(error);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SharedMapping {
    end: u64,
    /// Frames are keyed by `page + shift` (wrapping): the offset from where
    /// shared anonymous memory was made (as in the file Linux gives it), or
    /// the file offset for a file's page cache, and moved by `mremap`, so
    /// every process sharing the frames still finds the same ones wherever
    /// it has the mapping now.
    shift: u64,
    pages: SharedPages,
    /// `mprotect` may make the mapping writable (Linux's `VM_MAYWRITE`).
    may_write: bool,
}

/// A file's size and how many times it has shrunk, which a [`PageSource`]
/// whose size changes keeps here ([`PageSource::file_size`]), so that a
/// thread's TLB can check the end of the file while holding only this, not
/// the file: holding the file would keep it open, and System V shared
/// memory, for one, counts its attachments by who holds them.
#[derive(Debug, Default)]
pub struct FileSize {
    size: AtomicU64,
    shrinks: AtomicU64,
}

impl FileSize {
    #[must_use]
    pub fn new(size: u64) -> Self {
        FileSize {
            size: AtomicU64::new(size),
            shrinks: AtomicU64::new(0),
        }
    }
    /// The size now.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.size.load(Ordering::SeqCst)
    }
    /// How many times the file has shrunk.
    #[must_use]
    pub fn shrinks(&self) -> u64 {
        self.shrinks.load(Ordering::SeqCst)
    }
    /// Makes the size at least `size`, as a write past the end does.
    pub fn grow_to(&self, size: u64) {
        self.size.fetch_max(size, Ordering::SeqCst);
    }
    /// Sets the size, and says whether it shrank. A shrink is counted with
    /// [`Self::count_shrink`] once the bytes past the new end read as zeros,
    /// so that whoever reads the new count sees both ([`PageSource::shrinks`]).
    pub fn set(&self, size: u64) -> bool {
        size < self.size.swap(size, Ordering::SeqCst)
    }
    /// Counts a shrink [`Self::set`] made, and gives the new count.
    pub fn count_shrink(&self) -> u64 {
        self.shrinks.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// The file of a file mapping, read at an offset: a page that has no
/// contents yet is read from it, and a private mapping without the file's
/// page cache reads the pages given back with `MADV_DONTNEED` from it again,
/// as Linux faults them in from the file once their private copies are gone.
pub trait PageSource: Send + Sync {
    /// Reads from `offset`, filling `buf` unless the file ends first, and
    /// returns how much it read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno>;
    /// The file's size now: a page of a file mapping wholly past it raises
    /// SIGBUS. `None` puts no end to the mapping.
    fn size(&self) -> Option<u64> {
        None
    }
    /// How many times the file has shrunk. A shrink is counted after
    /// [`Self::size`] gives the new size and the page cache reads as zeros
    /// past it, so that whoever reads the new count sees both: a page past
    /// the end as past it, and no bytes from before the shrink there.
    fn shrinks(&self) -> u64 {
        0
    }
    /// Where the file keeps its size and shrinks, which [`Self::size`] and
    /// [`Self::shrinks`] give: a thread's TLB holds the pages of a file
    /// mapping that has an end only if the source gives it. A source whose
    /// [`Self::size`] is `None` has no end, and needs none.
    fn file_size(&self) -> Option<Arc<FileSize>> {
        None
    }
    /// The smallest size the file shrank to after it had shrunk `count`
    /// times, or `None` if it has not shrunk since.
    fn shrunk_since(&self, count: u64) -> Option<u64> {
        let _ = count;
        None
    }
    /// Whether a name links the file: a core holds a shared mapping of one
    /// that none does (Linux's `i_nlink`), as of a memfd.
    fn linked(&self) -> bool {
        true
    }
    /// The file's path, as a core's `NT_FILE` note names it (Linux's
    /// `file_path`), or `None` if it has none to give.
    fn name(&self) -> Option<Vec<u8>> {
        None
    }
    /// The device and inode `stat` gives the file, which
    /// `/proc/<pid>/maps` shows.
    fn identity(&self) -> (u64, u64) {
        (0, 0)
    }
    /// What tells the open file behind this mapping from another (Linux's
    /// `vm_file`), which mappings must share to merge, or 0 if nothing does.
    fn open_file(&self) -> usize {
        0
    }
    /// Whether two VMAs of a shared mapping of the file may be one. Linux
    /// never merges those of a file whose VMAs have a `close` operation, as
    /// System V shared memory's count its attachments: each shared mapping
    /// of such a file is then a VMA of its own, which `mprotect` splits
    /// where it changes the protection of part of it.
    fn merges(&self) -> bool {
        true
    }
    /// Whether the memory's VMAs are fixed mappings that core mm does not
    /// back (Linux's `VM_DONTEXPAND`, as the rings of AIO and `io_uring`
    /// are): they take no guard regions.
    fn fixed(&self) -> bool {
        false
    }
    /// Whether the memory is a `memfd_secret` file's (Linux's
    /// `vma_is_secretmem`), whose pages the kernel may not reach: `get_user_pages`
    /// refuses them.
    fn secret(&self) -> bool {
        false
    }
    /// The source itself, for the kernel to tell its kinds apart.
    fn as_any(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        None
    }
}
/// The shared memory `MADV_REMOVE` frees in one VMA of its range
/// ([`AddressSpace::removals`]): `len` bytes of `pages` from `offset`, the
/// offset in its file for a file's page cache.
#[derive(Clone)]
pub struct Removal {
    pub pages: SharedPages,
    pub offset: u64,
    pub len: u64,
}
/// The file behind `[start, end)` of a private file mapping: the page at
/// `page` holds the file from `page + shift` (wrapping), so that a move by
/// `mremap` only changes the shift.
#[derive(Clone)]
struct FileBacking {
    end: u64,
    shift: u64,
    source: Arc<dyn PageSource>,
    /// The file's page cache, whose pages the mapping shows until it writes
    /// them; without it, as for an ELF segment, the mapping has its own copy.
    cache: Option<SharedPages>,
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

/// How many pages the [`Tlb`] remembers. An entry holds the bytes of its
/// frame, not its charge to the meter ([`TlbFrame`]), so more of them keep
/// no more guest memory.
const TLB_ENTRIES: usize = 1024;

/// A populated page, as the page table held it: an access that stays inside
/// it needs only its protection checked, as [`AddressSpaceData::check`]
/// would, and, for a page of a file mapping, its file ([`FileEnd`]).
struct TlbEntry {
    page: u64,
    prot: Prot,
    frame: TlbFrame,
    cow: bool,
    file: Option<FileEnd>,
    /// The page's mark that an instruction was fetched from it
    /// ([`FrameCell::fetched`]).
    fetched: Arc<AtomicBool>,
    /// The bookkeeping of the shared mapping's memory the page shows, whose
    /// generation a store moves on, as under the locks.
    shared: Option<SharedStores>,
}

/// What an access through a [`Tlb`] to a page of a file mapping checks
/// first, since the file can change without the space's lock, by
/// `ftruncate` from anywhere: that the page is not wholly past the end of
/// the file, which raises SIGBUS ([`AddressSpaceData::check`]), and, for a
/// copy of the page's own, that the file has not shrunk since the entry
/// was made, after which the copy may have to go
/// ([`AddressSpaceData::refresh`]). Otherwise the access takes the locks,
/// which do both.
///
/// Each access checks both itself, so it does not matter in which order a
/// truncation changes them. An access that saw neither change comes before
/// the truncation, like one already under way when it ran. A store of that
/// kind may still land after the truncation returns, but where it lands
/// gives the same result as a store just before it. A copy that the
/// truncation leaves wholly past the end is never seen again, as the next
/// access under the locks replaces it, so the store goes with it. A copy
/// that it leaves within the file stays, with the store in it.
struct FileEnd {
    size: Arc<FileSize>,
    /// The page's offset in the file.
    offset: u64,
    /// How many times the file had shrunk ([`PageSource::shrinks`]) when the
    /// copy was made or last checked, or `None` for a page that shows the
    /// file's page cache, which no shrink replaces.
    shrinks: Option<u64>,
}

impl FileEnd {
    /// Whether an access through the entry may go ahead without the locks.
    #[inline]
    fn holds(&self) -> bool {
        self.shrinks
            .is_none_or(|shrinks| self.size.shrinks() == shrinks)
            && self.offset < self.size.get().div_ceil(PAGE_SIZE) * PAGE_SIZE
    }
}

/// The frame a store through a [`Tlb`] writes, whether its page is
/// executable, and the shared mapping's memory it shows, if any.
struct StoreTarget<'a> {
    frame: &'a FrameData,
    code: bool,
    shared: Option<&'a SharedStores>,
}

/// What a store to [`SharedPages`] moves on, without the frames, the
/// source or the owner, which a thread's TLB must not keep alive.
struct SharedStores {
    generation: Arc<AtomicU64>,
    watchers: Arc<Watchers>,
}

impl SharedStores {
    /// [`SharedPages::changed`].
    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.watchers.changed();
    }
}

/// The frame of a [`TlbEntry`]: its bytes, which keep no charge to the
/// meter alive ([`FrameBytes`]), or, before it has any, the frame itself, as
/// another space that shares it may give it bytes without this one's lock.
enum TlbFrame {
    Bytes(Arc<FrameData>),
    Empty(Frame),
}

impl TlbFrame {
    fn of(frame: &Frame) -> Self {
        match frame.get() {
            Some(bytes) => TlbFrame::Bytes(Arc::clone(&bytes.data)),
            None => TlbFrame::Empty(Arc::clone(frame)),
        }
    }
    /// The bytes, or `None` while the page reads as zeros.
    #[inline]
    fn get(&self) -> Option<&FrameData> {
        match self {
            TlbFrame::Bytes(data) => Some(data),
            TlbFrame::Empty(frame) => frame.get().map(|bytes| &*bytes.data),
        }
    }
}

/// The pages the latest accesses used, so that the next ones skip the page
/// table, the mappings and the locks of the directory. It is emptied before
/// anything can change a page entry or a mapping: when the directory is
/// locked for writing, and whenever the space is borrowed mutably. Each host
/// thread has one, which it uses without a lock ([`ThreadTlb`]).
struct Tlb {
    entries: Box<[Option<TlbEntry>]>,
    /// Which entries are set, one bit each, so that emptying touches only
    /// those.
    used: [u64; TLB_ENTRIES / 64],
}

impl Default for Tlb {
    fn default() -> Self {
        Tlb {
            entries: std::iter::repeat_with(|| None).take(TLB_ENTRIES).collect(),
            used: [0; TLB_ENTRIES / 64],
        }
    }
}

impl Tlb {
    #[inline]
    fn slot(page: u64) -> usize {
        // The remainder is below TLB_ENTRIES, so it always fits in usize.
        usize::try_from((page / PAGE_SIZE) % TLB_ENTRIES as u64).unwrap_or(0)
    }

    #[inline]
    fn get(&self, page: u64) -> Option<&TlbEntry> {
        self.entries[Self::slot(page)]
            .as_ref()
            .filter(|entry| entry.page == page && entry.file.as_ref().is_none_or(FileEnd::holds))
    }

    fn insert(&mut self, entry: TlbEntry) {
        let slot = Self::slot(entry.page);
        self.entries[slot] = Some(entry);
        self.used[slot / 64] |= 1 << (slot % 64);
    }

    fn flush(&mut self) {
        for (word, used) in self.used.iter_mut().enumerate() {
            while *used != 0 {
                let slot = word * 64 + used.trailing_zeros() as usize;
                self.entries[slot] = None;
                *used &= *used - 1;
            }
        }
    }
}

/// The [`Tlb`] of one host thread, which runs one guest thread, for the
/// loads, stores, fetches and locked instructions that take no lock. Its
/// entries are those of the space whose epoch ([`CodeCounters::epoch`]) it
/// holds, and only while that space keeps the epoch: each access compares
/// the two, and empties the TLB when they differ. An entry holds the bytes
/// of its frame ([`TlbFrame`]), so they stay as long as an entry of another
/// thread shows them, until that thread's next access, though the meter no
/// longer counts them.
///
/// A load that read the epoch before another thread changed it may still
/// use the page it showed, as an x86 load already under way when another
/// processor changes the mapping does. But anything that happens after the
/// change and that this thread sees, the epoch's `Acquire` makes this thread
/// see the new epoch with.
///
/// A store may not land after the change, as Linux's TLB shootdown makes
/// sure: after `fork` or `mprotect` returns, no other thread of the space
/// writes through the page it had. So a store says which epoch it is under
/// in [`Self::storing`] while it is under way, and [`CodeCounters::bump_epoch`]
/// waits until no store is under the old one.
struct ThreadTlb {
    epoch: u64,
    tlb: Tlb,
    /// The epoch a store through this TLB is under, or [`NOT_STORING`].
    storing: Arc<AtomicU64>,
}

impl ThreadTlb {
    fn new() -> Self {
        let storing = Arc::new(AtomicU64::new(NOT_STORING));
        STORES
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&storing));
        ThreadTlb {
            // No space has epoch 0 (`NEXT_EPOCH` starts at 1).
            epoch: 0,
            tlb: Tlb::default(),
            storing,
        }
    }
}

impl Drop for ThreadTlb {
    fn drop(&mut self) {
        STORES
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|storing| !Arc::ptr_eq(storing, &self.storing));
    }
}

thread_local! {
    static THREAD_TLB: RefCell<ThreadTlb> = RefCell::new(ThreadTlb::new());
}

/// What [`ThreadTlb::storing`] holds while no store is under way: no space
/// has epoch 0.
const NOT_STORING: u64 = 0;

/// The [`ThreadTlb::storing`] of every host thread that has a TLB. Every
/// [`CodeCounters::bump_epoch`] reads it, so they share it.
static STORES: RwLock<Vec<Arc<AtomicU64>>> = RwLock::new(Vec::new());

#[cfg(test)]
thread_local! {
    /// How long a write of more than one word by this thread waits between
    /// the words, so that a test can come between them.
    static WORD_STALL: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
    /// How long a store through this thread's TLB waits while it is under
    /// way, so that a test can show the store was waited for.
    static STORE_STALL: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
}

/// The next epoch of any space: the values are unique in the process, so
/// that a space made where a dropped one was never takes the entries a
/// thread's TLB holds for that one.
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

static NEXT_ADDRESS_SPACE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_SHARED_PAGES_ID: AtomicU64 = AtomicU64::new(1);

/// Where the code generations of spaces start, each far from the others,
/// so that a value means one space's code ([`AddressSpaceData::code_generation`]).
/// The starts wrap after 2^24 spaces, and a space that is bumped 2^40 times
/// reaches the next one's. Nothing depends on it in the emulator: each
/// thread's decode cache serves one space, and is made anew when `execve`
/// replaces it (paludarium-runtime's `workers`). It keeps a cache that
/// someone does move to another space from finding its old entries.
static NEXT_CODE_GENERATION: AtomicU64 = AtomicU64::new(0);
const CODE_GENERATIONS_PER_SPACE: u64 = 1 << 40;

/// The counters of a space that [`AddressSpace::code_generation_cached`]
/// and the loads through a [`ThreadTlb`] read without the locks.
struct CodeCounters {
    /// Bumped whenever executable memory that was fetched from or the
    /// mappings change, and by every store to the shared mappings and page
    /// caches the space may run code from (which it [`SharedPages::watch`]es);
    /// lets the CPU cache decoded instructions safely (see
    /// [`AddressSpaceData::code_generation`]).
    generation: AtomicU64,
    /// Bumped whenever the space is borrowed mutably, which may change its
    /// shared mappings and page caches, and the protection of their pages.
    layout: AtomicU64,
    /// One more than the layout at which the space last watched every
    /// shared mapping and page cache it may run code from, or 0 before it
    /// first did.
    watched: AtomicU64,
    /// Set to a new value of [`NEXT_EPOCH`] before a page entry or a
    /// mapping changes, which empties the [`ThreadTlb`]s at their next
    /// access.
    epoch: AtomicU64,
}

impl Default for CodeCounters {
    fn default() -> Self {
        let start = NEXT_CODE_GENERATION.fetch_add(CODE_GENERATIONS_PER_SPACE, Ordering::Relaxed);
        CodeCounters {
            generation: AtomicU64::new(start),
            layout: AtomicU64::new(0),
            watched: AtomicU64::new(0),
            epoch: AtomicU64::new(NEXT_EPOCH.fetch_add(1, Ordering::Relaxed)),
        }
    }
}

impl CodeCounters {
    /// Moves the epoch on, before a page entry or a mapping changes, and
    /// waits until no store of another thread is under the old epoch: from
    /// then on the old entries take no more writes. This thread's own TLB is
    /// emptied at once, so that the frames it holds go now; the other
    /// threads' go at their next access.
    fn bump_epoch(&self) {
        self.move_epoch(false);
    }

    /// [`Self::bump_epoch`] when no page entry or mapping changes, only what
    /// a store reads from the frames ([`AddressSpaceData::mark_fetched`]):
    /// this thread's own TLB keeps its entries, which stay as valid, and
    /// moves to the new epoch with them, as its own later stores see what
    /// it did before. Only the other threads' TLBs are emptied.
    fn bump_epoch_keeping_own(&self) {
        self.move_epoch(true);
    }

    fn move_epoch(&self, keep_own: bool) {
        let new = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        let old = self.epoch.swap(new, Ordering::SeqCst);
        THREAD_TLB.with(|cell| {
            if let Ok(mut thread) = cell.try_borrow_mut() {
                if keep_own && thread.epoch == old {
                    thread.epoch = new;
                } else {
                    thread.tlb.flush();
                }
            }
        });
        // Each store sets its `storing` and then reads the epoch again, both
        // `SeqCst`, as this swap and these loads are: either it reads the new
        // epoch, and stores nothing, or this sees it under the old one. A store
        // takes no lock while it is under way, but one that spans words waits
        // for those to the same page ahead of it (`FrameBytes::write_with`),
        // so the wait is as long as that queue, usually one store.
        let stores = STORES.read().unwrap_or_else(PoisonError::into_inner);
        for storing in stores.iter() {
            let mut spins = 0u32;
            while storing.load(Ordering::SeqCst) == old {
                spins += 1;
                if spins < 64 {
                    std::hint::spin_loop();
                } else {
                    // Its host thread may have been preempted mid-store.
                    std::thread::yield_now();
                }
            }
        }
    }
}

/// The spaces that watch a [`SharedPages`]: once one does, every store to
/// the frames bumps their code generations.
#[derive(Default)]
struct Watchers {
    /// Whether `spaces` has ever had one, so that stores to memory no space
    /// runs code from take no lock.
    any: AtomicBool,
    spaces: Mutex<Vec<Weak<CodeCounters>>>,
}

impl Watchers {
    fn spaces(&self) -> MutexGuard<'_, Vec<Weak<CodeCounters>>> {
        self.spaces.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Bumps the watching spaces' code generations. A store that finds no
    /// space here is seen by one that adds itself later
    /// ([`SharedPages::watch`]).
    /// Once every watching space is gone, stores take no lock again.
    fn changed(&self) {
        if !self.any.load(Ordering::SeqCst) {
            return;
        }
        let mut spaces = self.spaces();
        spaces.retain(|space| match space.upgrade() {
            Some(space) => {
                space.generation.fetch_add(1, Ordering::SeqCst);
                true
            }
            None => false,
        });
        if spaces.is_empty() {
            // Under the lock, so that an `add` either comes after and sets
            // it again, or came before and kept `spaces` from being empty.
            self.any.store(false, Ordering::SeqCst);
        }
    }
    fn add(&self, code: &Arc<CodeCounters>) {
        let mut spaces = self.spaces();
        spaces.retain(|space| space.strong_count() > 0);
        if !spaces
            .iter()
            .any(|space| std::ptr::eq(space.as_ptr(), Arc::as_ptr(code)))
        {
            spaces.push(Arc::downgrade(code));
        }
        drop(spaces);
        self.any.store(true, Ordering::SeqCst);
    }
}

/// One process's guest address space.
///
/// `mappings` is the source of truth for what is mapped and with which
/// protection; the two-level page table caches populated pages and holds
/// their contents.
struct AddressSpaceData {
    id: u64,
    directory: RwLock<Directory>,
    /// The code generation and the layout ([`CodeCounters`]), shared with
    /// the [`AddressSpace`] so that it can read them without the locks.
    code: Arc<CodeCounters>,
    mappings: BTreeMap<u64, Mapping>,
    initial_break: GuestAddr,
    current_break: GuestAddr,
    mmap_top: u64,
    /// Where mappings without a fixed address start, upward, in Linux's
    /// legacy layout (`ADDR_COMPAT_LAYOUT`); else they go down from
    /// `mmap_top`.
    bottom_up: Option<u64>,
    shared: BTreeMap<u64, SharedMapping>,
    /// The files of private file mappings, by range ([`FileBacking`]).
    backing: BTreeMap<u64, FileBacking>,
    /// The guard regions `MADV_GUARD_INSTALL` put in, from start to end:
    /// Linux's guard PTE markers, a property of the page tables and not of
    /// the VMAs, so they neither split nor stop a merge. An access to one
    /// faults as one to no mapping would.
    guards: BTreeMap<u64, u64>,
    /// How a new mapping is locked: `mlockall` with `MCL_FUTURE` (Linux's
    /// `def_flags`), which neither `fork` nor `exec` keeps.
    future_lock: Option<Lock>,
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
            guards: BTreeMap::new(),
            future_lock: None,
            code: Arc::default(),
            mappings: BTreeMap::new(),
            initial_break: GuestAddr(0),
            current_break: GuestAddr(0),
            mmap_top: DEFAULT_MMAP_TOP,
            bottom_up: None,
            meter: None,
            out_of_memory: Arc::default(),
        }
    }

    /// Identifier of this address space.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// A counter that changes whenever executable memory that an instruction
    /// was fetched from is written ([`FrameCell::fetched`]) or the mappings
    /// change (map, unmap, protect), including a store by any space
    /// or the kernel to a shared mapping or page cache that this space maps
    /// executable. Decoded instructions cached under one value stay valid
    /// while the value is unchanged. Values of different spaces differ too,
    /// up to the bound of [`CODE_GENERATIONS_PER_SPACE`].
    #[must_use]
    pub fn code_generation(&self) -> u64 {
        let layout = self.code.layout.load(Ordering::Acquire);
        if self.code.watched.load(Ordering::Acquire) != layout.wrapping_add(1) {
            self.watch_code_sources();
            self.code
                .watched
                .store(layout.wrapping_add(1), Ordering::Release);
        }
        self.code.generation.load(Ordering::SeqCst)
    }

    /// Watches every shared mapping and page cache that has a page this
    /// space may run code from, so that their stores bump its generation.
    /// A shared mapping or page cache stays watched once it was, even when
    /// its pages are no longer executable: that costs decodes, not
    /// correctness.
    fn watch_code_sources(&self) {
        let shared = self
            .shared
            .iter()
            .map(|(&start, shared)| (start, shared.end, Some(&shared.pages)));
        let caches = self
            .backing
            .iter()
            .map(|(&start, backing)| (start, backing.end, backing.cache.as_ref()));
        for (start, end, pages) in shared.chain(caches) {
            if let Some(pages) = pages
                && self.executable(start, end)
            {
                pages.watch(&self.code);
            }
        }
    }

    /// Whether a mapping that overlaps `[start, end)` is executable.
    fn executable(&self, start: u64, end: u64) -> bool {
        // Mappings never overlap, so their ends rise with their starts.
        self.mappings
            .range(..end)
            .rev()
            .take_while(|(_, mapping)| mapping.end() > start)
            .any(|(_, mapping)| mapping.prot.contains(Prot::EXEC))
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
        self.back(addr, len, source, None, offset)
    }
    /// Marks a newly created mapping as Linux MAP_SHARED, independently of VM sharing.
    fn mark_shared(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        if !self
            .mappings
            .values()
            .any(|mapping| mapping.start.0 == addr.0 && mapping.end() == end)
        {
            return Err(Errno::EINVAL);
        }
        let frames = self
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
            .map(|(page, frame)| (page - addr.0, frame))
            .collect();
        self.shared.insert(
            addr.0,
            SharedMapping {
                end,
                shift: 0u64.wrapping_sub(addr.0),
                pages: SharedPages::with_frames(frames),
                may_write: true,
            },
        );
        Ok(())
    }
    /// Makes the newly created mapping `[addr, addr+len)` show `pages` from
    /// key `offset` on, a file's page cache from that file offset, as a
    /// Linux `MAP_SHARED` mapping of the file; `may_write` says whether
    /// `mprotect` may make it writable.
    fn share_pages(
        &mut self,
        addr: GuestAddr,
        len: u64,
        pages: &SharedPages,
        offset: u64,
        may_write: bool,
    ) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        if !self
            .mappings
            .values()
            .any(|mapping| mapping.start.0 == addr.0 && mapping.end() == end)
        {
            return Err(Errno::EINVAL);
        }
        self.for_populated(addr.0, end, |entry| *entry = None);
        self.bump_code_generation();
        // Linux's `mmap_region` does not lock a VMA `vma_supports_mlock`
        // refuses, as the rings of AIO and `io_uring` are.
        if pages.source().is_some_and(|source| source.fixed()) {
            for (_, mapping) in self.mappings.range_mut(addr.0..end) {
                mapping.locked = None;
            }
        }
        self.shared.insert(
            addr.0,
            SharedMapping {
                end,
                shift: offset.wrapping_sub(addr.0),
                pages: pages.clone(),
                may_write,
            },
        );
        Ok(())
    }
    /// Maps `[start, start+len)` again to show the shared memory it shows
    /// from key `offset` on, as Linux's `remap_file_pages` does with a
    /// `MAP_SHARED | MAP_FIXED` `mmap` of the VMA's file: the mapping at
    /// `start` must be shared and may write (`VM_SHARED`, which a file open
    /// only for reading does not give), and the range must lie in it and in
    /// mappings after it with no hole, of the same memory and protection
    /// (`EINVAL`). Only then is `offset` taken, which is `mmap`'s error when
    /// the file cannot reach it. The new mapping keeps that protection.
    fn remap_shared_pages(
        &mut self,
        start: u64,
        len: u64,
        offset: Result<u64, Errno>,
    ) -> Result<(), Errno> {
        let end = start.checked_add(len).ok_or(Errno::EINVAL)?;
        let first = *self.mapping_at(start).ok_or(Errno::EINVAL)?;
        let shared = self
            .shared_at(start)
            .filter(|shared| shared.may_write)
            .ok_or(Errno::EINVAL)?;
        let pages = shared.pages.clone();
        let mut last = first;
        while last.end() < end {
            let next = *self.mappings.get(&last.end()).ok_or(Errno::EINVAL)?;
            let same = self.shared_at(next.start.0).is_some_and(|shared| {
                shared.may_write && Arc::ptr_eq(&shared.pages.frames, &pages.frames)
            });
            if !same || next.prot != first.prot || next.kind != first.kind {
                return Err(Errno::EINVAL);
            }
            last = next;
        }
        let offset = offset?;
        self.unmap(GuestAddr(start), len)?;
        self.map(Some(GuestAddr(start)), len, first.prot, first.kind)?;
        self.share_pages(GuestAddr(start), len, &pages, offset, true)
    }
    /// Makes the private file mapping `[addr, addr+len)` show the page
    /// cache `pages` of the file from `offset`, which must have its file
    /// ([`SharedPages::with_source`]): a page reads the cache until the
    /// mapping writes it, which copies it, as a Linux `MAP_PRIVATE`
    /// mapping does.
    pub fn back_with_cache(
        &mut self,
        addr: GuestAddr,
        len: u64,
        pages: &SharedPages,
        offset: u64,
    ) -> Result<(), Errno> {
        let source = pages.source.clone().ok_or(Errno::EINVAL)?;
        self.back(addr, len, source, Some(pages.clone()), offset)
    }
    fn back(
        &mut self,
        addr: GuestAddr,
        len: u64,
        source: Arc<dyn PageSource>,
        cache: Option<SharedPages>,
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
                cache,
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
    /// Reads the file of every page of `[start, end)` backed without a page
    /// cache into it, from emptied pages: what lies past the end of the file
    /// stays zero. A read that fails leaves the rest zero too, where Linux
    /// would raise SIGBUS on the access. A page backed by a page cache shows
    /// it again on its own.
    fn refill(&mut self, start: u64, end: u64) {
        let ranges: Vec<_> = self
            .backing
            .range(..end)
            .filter(|(_, backing)| backing.end > start && backing.cache.is_none())
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
        let shared = self
            .shared_at(page)
            .map(|mapping| (&mapping.pages, mapping.shift));
        let cache = || {
            self.backing_at(page)
                .and_then(|backing| Some((backing.cache.as_ref()?, backing.shift)))
        };
        let frame = shared.or_else(cache).map(|(pages, shift)| {
            pages
                .lock()
                .entry(page.wrapping_add(shift))
                .or_default()
                .clone()
        });
        Page {
            prot,
            frame: frame.unwrap_or_default(),
            file: self
                .mapping_at(page)
                .is_some_and(|m| m.kind == MappingKind::File),
            cow: shared.is_none() && cache().is_some(),
            cache: shared.is_none() && cache().is_some(),
            // Made now, so no shrink so far can leave it past the end.
            shrinks: self.file_at(page).map_or(0, |(source, _)| source.shrinks()),
        }
    }
    /// A new entry for `page`, with its file read into it if need be.
    fn fresh(&self, page: u64, prot: Prot) -> Page {
        let new = self.page(page, prot);
        self.fill_from_file(page, &new);
        new
    }
    /// Whether `entry`, a private copy of the file mapping page at `page`,
    /// may be one that a truncation of its file since has left wholly past
    /// the end of the file ([`Self::refresh`]).
    fn may_be_truncated(&self, page: u64, entry: &Page) -> bool {
        entry.file
            && !entry.cache
            && self
                .file_at(page)
                .is_some_and(|(source, _)| source.shrinks() != entry.shrinks)
    }
    /// Brings the entry of the mapped page at `page` up to date before an
    /// access: a page without one gets one, and a private copy of a page
    /// that a truncation of its file has since left wholly past the end of
    /// the file shows the file again, as Linux drops such copies even when
    /// the file grows again. With `write`, a page-cache page of a private
    /// mapping, or a frame `fork` shared, becomes a copy of its own; `false`
    /// when the meter has no room for it.
    fn refresh(&self, entry: &mut Option<Page>, page: u64, prot: Prot, write: bool) -> bool {
        match entry {
            None => *entry = Some(self.fresh(page, prot)),
            Some(p) if self.may_be_truncated(page, p) => {
                let Some((source, offset)) = self.file_at(page) else {
                    return true;
                };
                let count = source.shrinks();
                let past = source
                    .shrunk_since(p.shrinks)
                    .is_some_and(|size| offset >= size.div_ceil(PAGE_SIZE) * PAGE_SIZE);
                if past {
                    let fetched = p.frame.fetched();
                    *entry = Some(self.fresh(page, p.prot));
                    if fetched {
                        // The page shows other bytes than the instructions
                        // decoded from it.
                        self.code.generation.fetch_add(1, Ordering::Release);
                    }
                } else {
                    p.shrinks = count;
                }
            }
            Some(_) => {}
        }
        let Some(p) = entry.as_mut() else {
            return true;
        };
        // A copy of a page-cache page records the shrinks counted before it
        // copies: a truncation counts a shrink only once the bytes past the
        // new end read as zeros, so a copy that took the bytes from before
        // it records an older count, and goes if the page is past the end.
        let shrinks = (write && p.cow && p.cache)
            .then(|| self.file_at(page).map_or(0, |(source, _)| source.shrinks()));
        // A forked frame that no other space holds any more is this one's
        // own: the space holds its lock, so no other can take it meanwhile.
        if write && p.cow && (p.cache || Arc::strong_count(&p.frame) > 1) {
            let Some(frame) = copied(&p.frame, self.meter.as_ref()) else {
                self.out_of_memory.store(true, Ordering::SeqCst);
                return false;
            };
            p.frame = frame;
        }
        if write && p.cow {
            p.cow = false;
            if p.cache {
                p.cache = false;
                p.shrinks = shrinks.unwrap_or_default();
            }
        }
        true
    }
    /// The file and the offset in it of the file mapping page at `page`.
    fn file_at(&self, page: u64) -> Option<(&Arc<dyn PageSource>, u64)> {
        match self.shared_at(page) {
            Some(shared) => shared
                .pages
                .source
                .as_ref()
                .map(|source| (source, page.wrapping_add(shared.shift))),
            None => self
                .backing_at(page)
                .map(|backing| (&backing.source, page.wrapping_add(backing.shift))),
        }
    }
    /// What `mincore` says of the page at `page`: `None` if it is not mapped,
    /// or whether it is in memory. A private page is once something touched
    /// it, shared anonymous memory once anything of it was, and a file's page
    /// when it is within the file, as what a guest reads or writes stays in
    /// Linux's page cache.
    fn resident(&self, page: u64) -> Option<bool> {
        self.mapping_at(page)?;
        if let Some((source, offset)) = self.file_at(page) {
            return Some(source.size().is_none_or(|size| offset < size));
        }
        if lookup(&self.read_directory(), page).is_some() {
            return Some(true);
        }
        Some(
            self.shared_at(page)
                .is_some_and(|shared| shared.pages.contains(page.wrapping_add(shared.shift))),
        )
    }
    /// What the page table holds for the page at `page` ([`PageState`]):
    /// `None` if it is not mapped. Any access gives a page its entry; a
    /// private anonymous one without contents was only read.
    fn page_state(&self, page: u64) -> Option<PageState> {
        self.mapping_at(page)?;
        let directory = self.read_directory();
        let Some(entry) = lookup(&directory, page) else {
            return Some(PageState::Absent);
        };
        if entry.frame.get().is_none() && !entry.file && self.shared_at(page).is_none() {
            return Some(PageState::Zero);
        }
        Some(PageState::Present)
    }
    /// Whether the file mapping page at `page` lies wholly past the end of
    /// its file.
    fn past_file_end(&self, page: u64) -> bool {
        self.file_at(page).is_some_and(|(source, offset)| {
            source
                .size()
                .is_some_and(|size| offset >= size.div_ceil(PAGE_SIZE) * PAGE_SIZE)
        })
    }
    /// Reads its file into the new file mapping page `entry` at `page`, which
    /// has no contents yet: one past the end of the file when the mapping
    /// was made, or one `mremap` added. What lies past the end stays zero.
    fn fill_from_file(&self, page: u64, entry: &Page) {
        if !entry.file || entry.frame.get().is_some() {
            return;
        }
        let Some((source, offset)) = self.file_at(page) else {
            return;
        };
        let mut buf = vec![0; PAGE_BYTES];
        let Ok(n @ 1..) = source.read_at(offset, &mut buf) else {
            return;
        };
        let bytes = FrameBytes::new(self.meter.as_ref(), || {
            page_words(&buf[..n.min(PAGE_BYTES)])
        });
        match bytes {
            // A racing fill of a shared frame may set it first.
            Some(bytes) => {
                let _ = entry.frame.set(bytes);
            }
            None => self.out_of_memory.store(true, Ordering::SeqCst),
        }
    }
    /// The space for a child `fork` makes: it shares every frame, a private
    /// one until either space writes it, as Linux shares the pages.
    fn fork(&mut self) -> Self {
        let mut copy = Self::new();
        copy.meter = self.meter.clone();
        copy.mappings = self.mappings.clone();
        copy.shared = self.shared.clone();
        copy.backing = self.backing.clone();
        // Linux's `VM_COPY_ON_FORK` has `VM_MAYBE_GUARD`: the child gets the
        // guard markers with the page tables.
        copy.guards = self.guards.clone();
        copy.initial_break = self.initial_break;
        copy.current_break = self.current_break;
        copy.mmap_top = self.mmap_top;
        copy.bottom_up = self.bottom_up;
        let mut directory = BTreeMap::new();
        let shared = &self.shared;
        let own = self
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for (&index, table) in own.iter_mut() {
            let mut cloned = PageTable::new();
            for (slot, page) in table.pages.iter_mut().enumerate() {
                if let Some(page) = page {
                    let address = (index * ENTRIES_PER_TABLE + slot as u64) * PAGE_SIZE;
                    let is_shared = shared
                        .range(..=address)
                        .next_back()
                        .is_some_and(|(_, mapping)| address < mapping.end);
                    // Shared memory and a page-cache page stay as they are. A
                    // private page with contents is copied by the first write
                    // in either space; one without contents gets a frame of
                    // its own in the child, so that neither space's first
                    // write fills the other's.
                    let mut child = page.share();
                    if !is_shared && !page.cache {
                        if page.frame.get().is_some() {
                            page.cow = true;
                            child.cow = true;
                        } else {
                            // Keeping the mark, as a copy does
                            // ([`FrameCell::successor`]).
                            child.frame = Arc::new(page.frame.successor());
                        }
                    }
                    cloned.pages[slot] = Some(child);
                }
            }
            directory.insert(index, cloned);
        }
        *copy
            .directory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = directory;
        copy.drop_refaultable_pages();
        // A child's VMAs are not locked (`dup_mmap` clears `VMA_LOCKED_MASK`).
        for mapping in copy.mappings.values_mut() {
            mapping.locked = None;
        }
        // MADV_DONTFORK leaves the child a hole; MADV_WIPEONFORK leaves it
        // the mapping with no page and no `anon_vma`, as Linux's `dup_mmap`
        // neither copies the one nor the other's page tables.
        let advised: Vec<Mapping> = copy
            .mappings
            .values()
            .filter(|m| m.dont_fork || m.wipe_on_fork)
            .copied()
            .collect();
        for m in advised {
            if m.dont_fork {
                copy.remove(m.start.0, m.end());
            } else {
                copy.for_populated(m.start.0, m.end(), |entry| *entry = None);
                copy.clear_guards(m.start.0, m.end());
                copy.bump_code_generation();
                if let Some(child) = copy.mappings.get_mut(&m.start.0) {
                    child.written = false;
                }
            }
        }
        copy
    }

    fn bump_code_generation(&mut self) {
        self.code.generation.fetch_add(1, Ordering::Release);
    }

    /// Drops the page entries of a forked child that Linux's `fork` does not
    /// copy (`vma_needs_copy`): those of a VMA with no `anon_vma`
    /// ([`Mapping::written`]) and no guards (`VM_MAYBE_GUARD`), which a
    /// fault fills again. Such an entry is one of shared memory, a page of
    /// the file's page cache, or one with no contents of private
    /// anonymous memory. An entry with contents of its own (an ELF
    /// segment's, which the loader wrote) stays, as nothing would give them
    /// back.
    fn drop_refaultable_pages(&mut self) {
        let mut regions = Vec::new();
        let mut at = self.mappings.keys().next().copied();
        while let Some(start) = at {
            let Some((first, last)) = self.region_at(start) else {
                break;
            };
            let copies = self
                .mappings
                .range(first..last)
                .any(|(_, m)| m.written || m.maybe_guard);
            if !copies {
                regions.push((first, last, self.shared_at(first).is_some()));
            }
            at = self.mappings.range(last..).next().map(|(&s, _)| s);
        }
        if regions.is_empty() {
            return;
        }
        for (first, last, shared) in regions {
            self.for_populated(first, last, |entry| {
                let refaults = entry
                    .as_ref()
                    .is_some_and(|p| shared || p.cache || (p.frame.get().is_none() && !p.file));
                if refaults {
                    *entry = None;
                }
            });
        }
        self.bump_code_generation();
    }

    /// The mappings in address order.
    pub fn mappings(&self) -> impl Iterator<Item = &Mapping> {
        self.mappings.values()
    }

    /// Sets the top of the region used for mappings without a fixed address.
    pub fn set_mmap_top(&mut self, top: GuestAddr) {
        self.mmap_top = top.page_align_down().0.min(USER_ADDRESS_LIMIT);
    }
    /// Places mappings without a fixed address upward from `base`, as
    /// Linux's legacy layout does, or (`None`) down from the top.
    pub fn set_bottom_up(&mut self, base: Option<GuestAddr>) {
        self.bottom_up = base.map(|base| base.page_align_down().0);
    }
    /// Where mappings without a fixed address start, upward, if they do.
    #[must_use]
    pub fn bottom_up(&self) -> Option<u64> {
        self.bottom_up
    }

    fn read_directory(&self) -> RwLockReadGuard<'_, Directory> {
        self.directory
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The directory, locked for writing: the epoch is moved on first for
    /// the [`ThreadTlb`]s, as the entries they copy may change.
    fn write_directory(&self) -> RwLockWriteGuard<'_, Directory> {
        self.code.bump_epoch();
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
            bus: false,
        };
        let wide = u64::try_from(len).map_err(|_| fault(addr.0))?;
        addr.0.checked_add(wide).ok_or_else(|| fault(addr.0))?;
        for (page, offset, _) in chunks(addr, len) {
            let at = page + offset as u64;
            if at >= USER_ADDRESS_LIMIT {
                return Err(fault(at));
            }
            // Linux's `handle_pte_marker` gives `VM_FAULT_SIGSEGV` for a
            // guard marker, which x86 reports as `SEGV_MAPERR` on a page
            // that is not present, and which GUP (a system call's copy, a
            // core dump) takes as `EFAULT`. The loader and the refill of a
            // discarded file page are not accesses.
            if access != Access::Setup && self.guarded(page) {
                return Err(Fault {
                    mapped: false,
                    present: false,
                    ..fault(at)
                });
            }
            match self.prot_at(directory, page) {
                Some(prot) if access.permitted(prot) => {}
                _ => return Err(fault(at)),
            }
            let file = lookup(directory, page).map_or_else(
                || {
                    self.mapping_at(page)
                        .is_some_and(|m| m.kind == MappingKind::File)
                },
                |p| p.file,
            );
            if file && self.past_file_end(page) {
                return Err(Fault {
                    bus: true,
                    ..fault(at)
                });
            }
        }
        Ok(())
    }

    /// Remembers the page at `page` in this thread's [`ThreadTlb`] when an
    /// access to it needs only its protection checked, its file if it has
    /// one ([`FileEnd`]), and, for a shared page, the memory whose
    /// bookkeeping a store does ([`AddressSpace::wrote`]): it is populated,
    /// and up to date with its file's shrinks.
    fn remember(&self, directory: &Directory, page: u64) {
        let Some(p) = lookup(directory, page) else {
            return;
        };
        if self.may_be_truncated(page, p) {
            return;
        }
        let shared = self.shared_at(page).map(|mapping| mapping.pages.stores());
        // A file mapping without a file, or whose file has no end, has no end
        // to check, as in `check`. One whose file does not say where it keeps
        // its size stays out.
        let file = match p.file.then(|| self.file_at(page)).flatten() {
            Some((source, offset)) if source.size().is_some() => {
                let Some(size) = source.file_size() else {
                    return;
                };
                Some(FileEnd {
                    size,
                    offset,
                    shrinks: (!p.cache).then_some(p.shrinks),
                })
            }
            _ => None,
        };
        // The lock is held, so the epoch is the one the entry is valid at.
        let epoch = self.code.epoch.load(Ordering::Acquire);
        THREAD_TLB.with(|cell| {
            let Ok(mut thread) = cell.try_borrow_mut() else {
                return;
            };
            if thread.epoch != epoch {
                thread.tlb.flush();
                thread.epoch = epoch;
            }
            thread.tlb.insert(TlbEntry {
                page,
                prot: p.prot,
                frame: TlbFrame::of(&p.frame),
                fetched: Arc::clone(&p.frame.fetched),
                cow: p.cow,
                file,
                shared,
            });
        });
    }

    /// The page of `[addr, addr+len)` when the access lies inside one page;
    /// `None` for an empty access or one that crosses pages.
    fn single_page(addr: GuestAddr, len: usize) -> Option<u64> {
        let offset = page_offset(addr.0);
        (len > 0 && offset + len <= PAGE_BYTES).then(|| addr.0 - offset as u64)
    }

    /// Copies `[addr, addr+buf.len())` out of its populated pages; a page
    /// without contents reads as zeros.
    fn copy_out(directory: &Directory, addr: GuestAddr, buf: &mut [u8]) {
        for (page, offset, range) in chunks(addr, buf.len()) {
            let dst = &mut buf[range];
            match lookup(directory, page).and_then(|p| p.frame.get()) {
                Some(frame) => frame.read(offset, dst),
                None => dst.fill(0),
            }
        }
    }

    fn read_with(&self, addr: GuestAddr, buf: &mut [u8], access: Access) -> Result<(), Fault> {
        let ready = |directory: &Directory, page: u64| {
            lookup(directory, page).is_some_and(|p| !self.may_be_truncated(page, p))
        };
        {
            let directory = self.read_directory();
            self.check(&directory, addr, buf.len(), access)?;
            if chunks(addr, buf.len()).all(|(page, _, _)| ready(&directory, page)) {
                if access == Access::Fetch {
                    self.mark_fetched(&directory, addr, buf.len());
                }
                Self::copy_out(&directory, addr, buf);
                if let Some(page) = Self::single_page(addr, buf.len()) {
                    self.remember(&directory, page);
                }
                return Ok(());
            }
        }
        let mut directory = self.write_directory();
        self.check(&directory, addr, buf.len(), access)?;
        // A successful lazy read installs the logical zero-page entry without
        // allocating its byte frame, matching subsequent Linux fault metadata.
        for (page, _, _) in chunks(addr, buf.len()) {
            if ready(&directory, page) {
                continue;
            }
            if let Some(prot) = self.mapping_at(page).map(|m| m.prot) {
                let (dir, slot) = page_index(page);
                let table = directory.entry(dir).or_insert_with(PageTable::new);
                if let Some(entry) = table.pages.get_mut(slot) {
                    self.refresh(entry, page, prot, false);
                }
            }
        }
        // Again, as a truncation may have come between the check and the
        // refresh: a page it left past the end of the file is a bus error.
        self.check(&directory, addr, buf.len(), access)?;
        if access == Access::Fetch {
            self.mark_fetched(&directory, addr, buf.len());
        }
        Self::copy_out(&directory, addr, buf);
        if let Some(page) = Self::single_page(addr, buf.len()) {
            self.remember(&directory, page);
        }
        Ok(())
    }

    /// Marks the pages of `[addr, addr+len)` fetched from ([`FrameCell`]),
    /// before a fetch reads them under the locks, so that a later store to
    /// them bumps the code generation.
    ///
    /// The epoch moves on before the first mark: that waits for each store
    /// under way through another thread's [`ThreadTlb`], which may not have
    /// seen the mark, and makes the bytes it stored visible to this fetch
    /// ([`CodeCounters::bump_epoch_keeping_own`]). Every later store of
    /// another thread either takes the locks or goes through an entry
    /// remembered under them after the mark was set, and so sees it; this
    /// thread's own TLB keeps its entries, and its stores come after the
    /// mark in its own order. A fetch without the locks uses a page only
    /// once it is marked, and its `Acquire` load of the mark makes the bytes
    /// of every store that missed the mark visible to it as well. Either the
    /// store sees the mark, and bumps the generation after its bytes, or the
    /// fetch sees the bytes.
    fn mark_fetched(&self, directory: &Directory, addr: GuestAddr, len: usize) {
        let mut waited = false;
        for (page, _, _) in chunks(addr, len) {
            let Some(p) = lookup(directory, page) else {
                continue;
            };
            if p.frame.fetched() {
                continue;
            }
            if !waited {
                self.code.bump_epoch_keeping_own();
                waited = true;
            }
            p.frame.fetched.store(true, Ordering::Release);
        }
    }

    /// The fault of a write to `page` that the meter has no room for, which
    /// marks the space out of memory.
    fn out_of_room(&self, page: u64) -> Fault {
        self.out_of_memory.store(true, Ordering::SeqCst);
        Fault {
            addr: GuestAddr(page),
            write: true,
            fetch: false,
            mapped: true,
            present: false,
            bus: false,
        }
    }

    /// Writes `buf`, which [`Self::check`] allowed, into populated pages. A
    /// page the meter has no room for faults, and marks the space out of
    /// memory.
    fn store(&self, directory: &Directory, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.store_with(directory, addr, buf.len(), |frame, offset, range| {
            frame.write(offset, &buf[range]);
        })
    }

    /// [`Self::store`] of `len` bytes, which `write` writes into each frame,
    /// at its offset, from that range of them.
    fn store_with(
        &self,
        directory: &Directory,
        addr: GuestAddr,
        len: usize,
        mut write: impl FnMut(&FrameBytes, usize, core::ops::Range<usize>),
    ) -> Result<(), Fault> {
        for (page, offset, range) in chunks(addr, len) {
            if let Some(p) = lookup(directory, page) {
                if let Some(mapping) = self.shared_at(page) {
                    mapping.pages.changed();
                }
                let Some(frame) = p.frame_for_write(self.meter.as_ref()) else {
                    return Err(self.out_of_room(page));
                };
                write(frame, offset, range);
                // Under the locks, which every mark is set under: `Relaxed`.
                if p.prot.contains(Prot::EXEC) && p.frame.fetched.load(Ordering::Relaxed) {
                    // Code that was fetched may have changed: decoded
                    // instructions are stale. After the bytes: a fetch that
                    // reads the new generation (Acquire) then reads the new
                    // bytes too, with or without the lock.
                    self.code.generation.fetch_add(1, Ordering::Release);
                }
                frame.dirty.store(true, Ordering::Release);
                // Again once the page is dirty, so that a write-back that ran
                // between the bumps sees the generation change after it.
                if let Some(mapping) = self.shared_at(page) {
                    mapping.pages.changed();
                }
            }
        }
        Ok(())
    }

    /// Writes `buf` at `addr`; `true` when a page took its first write,
    /// or the copy of a frame it shared.
    fn write_with(&self, addr: GuestAddr, buf: &[u8], access: Access) -> Result<bool, Fault> {
        let first = self.prepare_write(addr, buf.len(), access)?;
        self.store(&self.read_directory(), addr, buf)?;
        Ok(first)
    }

    /// Checks that `[addr, addr+len)` may be written, and gives each page
    /// it touches a frame of its own to write: populates the pages it
    /// touches for the first time, and copies the page-cache pages of a
    /// private mapping and the frames `fork` shares. `true` when a page took
    /// its first write, or the copy of a frame it shared.
    fn prepare_write(&self, addr: GuestAddr, len: usize, access: Access) -> Result<bool, Fault> {
        {
            let directory = self.read_directory();
            self.check(&directory, addr, len, access)?;
            let ready = |page: u64| {
                lookup(&directory, page).is_some_and(|p| {
                    !p.cow && p.frame.get().is_some() && !self.may_be_truncated(page, p)
                })
            };
            if chunks(addr, len).all(|(page, _, _)| ready(page)) {
                if let Some(page) = Self::single_page(addr, len) {
                    self.remember(&directory, page);
                }
                return Ok(false);
            }
        }
        let mut directory = self.write_directory();
        self.check(&directory, addr, len, access)?;
        for (page, _, _) in chunks(addr, len) {
            let Some(prot) = self.mapping_at(page).map(|m| m.prot) else {
                return Err(Fault {
                    addr: GuestAddr(page),
                    write: true,
                    fetch: false,
                    mapped: false,
                    present: false,
                    bus: false,
                });
            };
            let (dir, slot) = page_index(page);
            let table = directory.entry(dir).or_insert_with(PageTable::new);
            if let Some(entry) = table.pages.get_mut(slot)
                && !self.refresh(entry, page, prot, true)
            {
                return Err(Fault {
                    addr: GuestAddr(page),
                    write: true,
                    fetch: false,
                    mapped: true,
                    present: false,
                    bus: false,
                });
            }
            if let Some(p) = lookup(&directory, page)
                && p.frame_for_write(self.meter.as_ref()).is_none()
            {
                return Err(self.out_of_room(page));
            }
        }
        // Again, as a truncation may have come between the check and the
        // refresh, which read the shrinks after it: a page it left past the
        // end of the file must not take the write, in a copy that records
        // the shrink and so would stay.
        self.check(&directory, addr, len, access)?;
        if let Some(page) = Self::single_page(addr, len) {
            self.remember(&directory, page);
        }
        Ok(true)
    }

    /// A locked instruction on the `size` bytes at `addr`, which lie in one
    /// word of a page [`Self::prepare_write`] prepared: one compare-and-swap
    /// of the word ([`FrameBytes::update`]).
    fn update(
        &self,
        addr: GuestAddr,
        size: usize,
        operation: AtomicOp,
    ) -> Result<AtomicResult, Fault> {
        let mut result = None;
        self.store_with(&self.read_directory(), addr, size, |frame, offset, _| {
            result = Some(frame.update(offset, size, operation));
        })?;
        result.ok_or(Fault {
            addr,
            write: true,
            fetch: false,
            mapped: false,
            present: false,
            bus: false,
        })
    }

    /// Marks the private mappings `[addr, addr+len)` touches written, each
    /// with the whole Linux VMA it is part of ([`Mapping::written`]).
    pub fn mark_written(&mut self, addr: GuestAddr, len: u64) {
        let end = addr.0.saturating_add(len);
        let mut at = addr.0;
        while at < end {
            let Some(m) = self.mapping_at(at).copied() else {
                at = self
                    .mappings
                    .range(at..end)
                    .next()
                    .map_or(end, |(&start, _)| start);
                continue;
            };
            if self.shared_at(m.start.0).is_none()
                && let Some((first, last)) = self.region_at(m.start.0)
            {
                for (_, mapping) in self.mappings.range_mut(first..last) {
                    mapping.written = true;
                }
            }
            at = m.end();
        }
    }

    /// The core dump's view of the Linux VMA at `addr`: written when any
    /// mapping of it is, as Linux gives a merged VMA the `anon_vma` of the
    /// one that had it. [`CoreState::linked`] is left false: the file of a
    /// shared mapping there, returned with it, tells that once the lock is
    /// released.
    fn core_state(&self, addr: u64) -> (CoreState, Option<Arc<dyn PageSource>>) {
        let written = self
            .region_at(addr)
            .is_some_and(|(first, last)| self.mappings.range(first..last).any(|(_, m)| m.written));
        let shared = self.shared_at(addr).is_some();
        let file = self.file_at(addr);
        let state = CoreState {
            written,
            shared,
            linked: false,
            file_offset: file.map(|(_, offset)| offset),
        };
        (
            state,
            file.filter(|_| shared)
                .map(|(source, _)| Arc::clone(source)),
        )
    }

    /// The file of the mapping at `addr` and the offset of `addr` in it:
    /// a file mapping's own, or none ([`MappedFile::source`]) for shared
    /// anonymous memory, whose offset counts from where it was made.
    fn mapped_file(&self, addr: u64) -> Option<(Option<Arc<dyn PageSource>>, u64)> {
        if let Some((source, offset)) = self.file_at(addr) {
            return Some((Some(Arc::clone(source)), offset));
        }
        self.shared_at(addr)
            .map(|shared| (None, addr.wrapping_add(shared.shift)))
    }

    /// The first VMA that ends after `addr`, and the file to ask about it
    /// with no lock held.
    fn vma_from(&self, addr: u64) -> Option<(Vma, Option<Arc<dyn PageSource>>)> {
        let mapping = self
            .mapping_at(addr)
            .or_else(|| self.mappings.range(addr..).next().map(|(_, m)| m))?;
        let (start, end) = self.region_at(mapping.start.0)?;
        let found = self.mapped_file(start);
        let (offset, source) = match found.as_ref() {
            Some((source, offset)) => (*offset, source.clone()),
            None => (0, None),
        };
        let vma = Vma {
            start,
            end,
            prot: mapping.prot,
            shared: self.shared_at(start).is_some(),
            offset,
            file: found.map(|(source, offset)| MappedFile {
                name: None,
                source: source.is_some(),
                offset,
            }),
            identity: (0, self.shared_at(start).map_or(0, |shared| shared.pages.id)),
            heap: start < self.current_break.0 && end > self.initial_break.0,
        };
        Some((vma, source))
    }

    /// Reads guest memory (any mapped page is readable on x86).
    pub fn read(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.read_with(addr, buf, Access::Read)
    }

    /// Reads guest memory whatever its protection, for a core dump.
    pub fn read_for_dump(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.read_with(addr, buf, Access::Dump)
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
        self.write_with(addr, buf, Access::Setup).map(|_| ())
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        // The mapping that starts last before `end` is the only candidate,
        // because mappings never overlap each other.
        self.mappings
            .range(..end)
            .next_back()
            .is_some_and(|(_, m)| m.end() > start)
    }

    /// The lowest address from `from`, a multiple of `align` (a power of
    /// two), with `len` free bytes below TASK_SIZE.
    fn lowest_gap(&self, from: u64, len: u64, align: u64) -> Option<u64> {
        let limit = USER_ADDRESS_LIMIT - PAGE_SIZE;
        let mut start = from.checked_next_multiple_of(align)?;
        for (_, m) in self.mappings.range(..limit) {
            if m.end() <= start {
                continue;
            }
            if m.start.0 >= start.checked_add(len)? {
                break;
            }
            start = m.end().checked_next_multiple_of(align)?;
        }
        (start.checked_add(len)? <= limit).then_some(start)
    }
    fn find_free(&self, len: u64) -> Option<u64> {
        if let Some(base) = self.bottom_up {
            return self.lowest_gap(base, len, PAGE_SIZE);
        }
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
                written: false,
                sealed: false,
                dont_fork: false,
                wipe_on_fork: false,
                dont_dump: false,
                maybe_guard: false,
                locked: self.future_lock,
            },
        );
        Ok(GuestAddr(start))
    }

    /// Splits the shared mapping across `at` in two when its memory's VMAs
    /// never merge ([`PageSource::merges`]) and its protection is not
    /// `prot`, as Linux's `mprotect` splits a VMA whose flags it changes.
    fn split_unmergeable_shared(&mut self, at: u64, prot: Prot) {
        let Some((&start, shared)) = self.shared.range(..at).next_back() else {
            return;
        };
        if shared.end <= at
            || shared.pages.source.as_ref().is_none_or(|s| s.merges())
            || self.mapping_at(at).is_none_or(|m| m.prot == prot)
        {
            return;
        }
        let tail = shared.clone();
        if let Some(head) = self.shared.get_mut(&start) {
            head.end = at;
        }
        self.shared.insert(at, tail);
    }
    /// The shared mappings, by address.
    fn shared_fragments(&self) -> Vec<SharedFragment> {
        self.shared
            .iter()
            .map(|(&start, shared)| SharedFragment {
                start,
                end: shared.end,
                offset: start.wrapping_add(shared.shift),
                open_file: shared.pages.source.as_ref().map_or(0, |s| s.open_file()),
                secret: shared.pages.source.as_ref().is_some_and(|s| s.secret()),
            })
            .collect()
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

    /// Unmaps `[addr, addr+len)`. Unmapped holes inside the range are fine;
    /// a sealed mapping in it is EPERM, and nothing is unmapped
    /// (`vms_gather_munmap_vmas`).
    pub fn unmap(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        if self.sealed_in(addr.0, end) {
            return Err(Errno::EPERM);
        }
        self.remove(addr.0, end);
        Ok(())
    }

    /// Takes `[addr, end)` out of the space, its mappings, memory and pages,
    /// sealed or not.
    fn remove(&mut self, addr: u64, end: u64) {
        self.clear_guards(addr, end);
        let addr = GuestAddr(addr);
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
    }

    /// Whether two mappings would be one Linux VMA when adjacent: the same
    /// protection, kind and seal, and both the same shared memory, or both private
    /// and of no file or of the same file at contiguous offsets, as Linux's
    /// `vma_merge` asks for the same `vm_file` and following `vm_pgoff`.
    fn mergeable(&self, a: &Mapping, b: &Mapping) -> bool {
        a.prot == b.prot
            && a.kind == b.kind
            && a.sealed == b.sealed
            && a.dont_fork == b.dont_fork
            && a.wipe_on_fork == b.wipe_on_fork
            && a.dont_dump == b.dont_dump
            && a.locked == b.locked
            && match (self.shared_at(a.start.0), self.shared_at(b.start.0)) {
                (None, None) => match (self.backing_at(a.start.0), self.backing_at(b.start.0)) {
                    (None, None) => true,
                    (Some(x), Some(y)) => {
                        let opened = x.source.open_file();
                        x.shift == y.shift
                            && (Arc::ptr_eq(&x.source, &y.source)
                                || opened != 0 && opened == y.source.open_file())
                    }
                    _ => false,
                },
                (Some(x), Some(y)) => {
                    Arc::ptr_eq(&x.pages.frames, &y.pages.frames)
                        && x.shift == y.shift
                        && (x.end == y.end || x.pages.source.as_ref().is_none_or(|s| s.merges()))
                }
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
                    entry.as_ref().map(Page::share)
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
        // The guard markers move with the page tables, and leave the old
        // range even when `MREMAP_DONTUNMAP` keeps it.
        let guards = self.clear_guards(old, old + old_len);
        // MREMAP_DONTUNMAP leaves the old range unlocked (`VMA_LOCKED_MASK`).
        if keep_old {
            self.split_at(old);
            self.split_at(old + old_len);
            for (_, m) in self.mappings.range_mut(old..old + old_len) {
                m.locked = None;
            }
        }
        if !keep_old && old_len > 0 {
            // `remap` moves pages of one VMA only, whose mapping at `old` it
            // found not sealed, and sealed mappings make VMAs of their own:
            // nothing here is sealed, so the unmap cannot fail.
            let unmapped = self.unmap(GuestAddr(old), old_len);
            debug_assert!(unmapped.is_ok(), "{unmapped:?}");
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
        for (start, end) in guards {
            self.add_guards(start - old + to, end - old + to);
        }
        self.bump_code_generation();
    }

    /// `mremap`, with Linux's checks in Linux's order: resizes the mapping
    /// at `addr`, growing it in place when the pages after it are free, else
    /// moving it as `how` allows. A grown or moved range must lie in one
    /// Linux VMA (`EFAULT`). A file mapping grows over more of its file,
    /// whose pages it reads on first touch. Moving a range that spans
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
        // A sealed VMA is not remapped (`check_prep_vma`).
        if self.mapping_at(addr.0).ok_or(Errno::EFAULT)?.sealed {
            return Err(Errno::EPERM);
        }
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
            // A grown file mapping reads the file further on.
            if let Some((_, entry)) = self.backing.range_mut(..old_end).next_back()
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

    /// Whether a mapping in `[start, end)` is sealed.
    fn sealed_in(&self, start: u64, end: u64) -> bool {
        self.mappings
            .range(..end)
            .any(|(_, m)| m.sealed && m.end() > start)
    }

    /// `mseal(addr, len)` of a range that every page of which is mapped
    /// (else ENOMEM, and nothing is sealed): its mappings are split at its
    /// ends and sealed, as Linux's `mseal_range` seals its VMAs.
    pub fn seal(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        if !self.covers(addr, len)? {
            return Err(Errno::ENOMEM);
        }
        self.split_at(addr.0);
        self.split_at(end);
        for (_, m) in self.mappings.range_mut(addr.0..end) {
            m.sealed = true;
        }
        Ok(())
    }

    /// What `MADV_REMOVE` of `[addr, end)` frees, VMA by VMA as Linux's
    /// `madvise_walk_vmas` goes, as Linux's `madvise_remove` checks each:
    /// memory of no file is `EINVAL`, and a VMA that is not shared or may
    /// not be written (`VM_MAYWRITE`) `EACCES`; the walk stops at the first
    /// of those. Whether the range has a hole, which is `ENOMEM` after the
    /// rest, comes with them.
    fn removals(&self, addr: u64, end: u64) -> (Vec<Result<Removal, Errno>>, bool) {
        let mut found = Vec::new();
        let mut covered = addr;
        let mut hole = false;
        for (&start, m) in self.mappings.range(..end).filter(|(_, m)| m.end() > addr) {
            hole |= start > covered;
            covered = covered.max(m.end());
            let (from, to) = (start.max(addr), m.end().min(end));
            let removal = match self.shared_at(start) {
                Some(shared) if shared.may_write => Ok(Removal {
                    pages: shared.pages.clone(),
                    offset: from.wrapping_add(shared.shift),
                    len: to - from,
                }),
                Some(_) => Err(Errno::EACCES),
                None if matches!(m.kind, MappingKind::File | MappingKind::ElfSegment)
                    || self.backing_at(start).is_some() =>
                {
                    Err(Errno::EACCES)
                }
                None => Err(Errno::EINVAL),
            };
            let failed = removal.is_err();
            found.push(removal);
            if failed {
                return (found, false);
            }
        }
        (found, hole || covered < end)
    }

    /// `madvise` of `advice` over `[addr, end)`, as Linux's
    /// `madvise_walk_vmas` changes the flags of its VMAs in turn: a VMA that
    /// may not take the advice ends it with `EINVAL`, after those before
    /// it; a hole in the range is `ENOMEM` once the rest has it. Only
    /// private anonymous memory takes `MADV_WIPEONFORK` (Linux's VMA of no
    /// file and not shared).
    pub fn advise_flags(&mut self, addr: u64, end: u64, advice: FlagAdvice) -> Result<(), Errno> {
        let starts: Vec<u64> = self
            .mappings
            .range(..end)
            .filter(|(_, m)| m.end() > addr)
            .map(|(&start, _)| start)
            .collect();
        let mut covered = addr;
        let mut hole = false;
        for start in starts {
            let Some(&m) = self.mappings.get(&start) else {
                continue;
            };
            hole |= m.start.0 > covered;
            covered = covered.max(m.end());
            // A loaded program's segments have a file (Linux's `vm_file`).
            if advice == FlagAdvice::WipeOnFork
                && (matches!(m.kind, MappingKind::File | MappingKind::ElfSegment)
                    || self.shared_at(start).is_some()
                    || self.backing_at(start).is_some())
            {
                return Err(Errno::EINVAL);
            }
            let (from, to) = (start.max(addr), m.end().min(end));
            self.split_at(from);
            self.split_at(to);
            for (_, m) in self.mappings.range_mut(from..to) {
                match advice {
                    FlagAdvice::DontFork => m.dont_fork = true,
                    FlagAdvice::DoFork => m.dont_fork = false,
                    FlagAdvice::WipeOnFork => m.wipe_on_fork = true,
                    FlagAdvice::KeepOnFork => m.wipe_on_fork = false,
                    FlagAdvice::DontDump => m.dont_dump = true,
                    FlagAdvice::DoDump => m.dont_dump = false,
                }
            }
        }
        if hole || covered < end {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Locks or unlocks `[addr, end)` (`lock`), as Linux's
    /// `apply_vma_lock_flags`: VMA by VMA from the one at `addr`, which must
    /// exist, to a hole (`ENOMEM` once the VMAs before it took the new
    /// state). A VMA that cannot be locked (`vma_supports_mlock`: the rings
    /// of AIO and `io_uring`) keeps its state.
    pub fn lock(&mut self, addr: u64, end: u64, lock: Option<Lock>) -> Result<(), Errno> {
        if end <= addr {
            return Ok(());
        }
        if self.mapping_at(addr).is_none() {
            return Err(Errno::ENOMEM);
        }
        let mut at = addr;
        while at < end {
            let Some(&m) = self.mapping_at(at) else {
                return Err(Errno::ENOMEM);
            };
            let to = m.end().min(end);
            if !self.refuses_lock(at) {
                self.split_at(at);
                self.split_at(to);
                for (_, mapping) in self.mappings.range_mut(at..to) {
                    mapping.locked = lock;
                }
            }
            at = to;
        }
        Ok(())
    }

    /// Locks the new mapping `[addr, end)` as `mmap` with `MAP_LOCKED` does
    /// (`__mmap_complete`): only a VMA `vma_supports_mlock` refuses, the
    /// rings of AIO and `io_uring`, stays unlocked. Secret memory is locked
    /// here, as only `mlock_fixup` passes it over.
    pub fn lock_new(&mut self, addr: u64, end: u64, lock: Lock) {
        let fixed = self
            .shared_at(addr)
            .and_then(|shared| shared.pages.source())
            .is_some_and(|source| source.fixed());
        if fixed {
            return;
        }
        self.split_at(addr);
        self.split_at(end);
        for (_, mapping) in self.mappings.range_mut(addr..end) {
            mapping.locked = Some(lock);
        }
    }

    /// Whether the mapping at `addr` cannot be locked: the rings of AIO and
    /// `io_uring` (Linux's `vma_supports_mlock`), and secret memory, which
    /// `mlock_fixup` leaves as it is.
    fn refuses_lock(&self, addr: u64) -> bool {
        self.shared_at(addr)
            .and_then(|shared| shared.pages.source())
            .is_some_and(|source| source.fixed() || source.secret())
    }

    /// `mlockall` and `munlockall`: new mappings take `future`, and with
    /// `current` every mapping takes it; `None` leaves them as they are
    /// (`mlockall` with `MCL_FUTURE` alone).
    pub fn lock_all(&mut self, current: Option<Option<Lock>>, future: Option<Lock>) {
        self.future_lock = future;
        let Some(current) = current else {
            return;
        };
        let starts: Vec<u64> = self.mappings.keys().copied().collect();
        for start in starts {
            if !self.refuses_lock(start)
                && let Some(mapping) = self.mappings.get_mut(&start)
            {
                mapping.locked = current;
            }
        }
    }

    /// The first mapping of `[addr, end)` that is locked.
    pub fn first_locked(&self, addr: u64, end: u64) -> Option<Mapping> {
        self.mappings
            .range(..end)
            .map(|(_, m)| *m)
            .find(|m| m.end() > addr && m.locked.is_some())
    }

    /// Whether the mapping at `addr` refuses to have its pages discarded
    /// ([`Self::refuses_discard`]).
    pub fn refuses_discard_at(&self, addr: u64) -> bool {
        self.mapping_at(addr)
            .is_some_and(|m| self.refuses_discard(m))
    }

    /// How many pages are locked (Linux's `locked_vm`).
    pub fn locked_pages(&self) -> u64 {
        self.mappings
            .values()
            .filter(|m| m.locked.is_some())
            .map(|m| m.length / PAGE_SIZE)
            .sum()
    }

    /// How many pages of `[addr, end)` are locked
    /// (`count_mm_mlocked_page_nr`).
    pub fn locked_pages_in(&self, addr: u64, end: u64) -> u64 {
        self.mappings
            .values()
            .filter(|m| m.locked.is_some() && m.start.0 < end && m.end() > addr)
            .map(|m| (m.end().min(end) - m.start.0.max(addr)) / PAGE_SIZE)
            .sum()
    }

    /// How a new mapping is locked ([`Self::lock_all`]).
    pub fn future_lock(&self) -> Option<Lock> {
        self.future_lock
    }

    /// `MADV_GUARD_INSTALL` (with `install`) or `MADV_GUARD_REMOVE` of
    /// `[addr, end)`, VMA by VMA as Linux's `madvise_walk_vmas`, up to the
    /// first that refuses: a sealed one whose pages may not be discarded
    /// installs none (`EPERM`, `can_madvise_modify`), and the rings of AIO
    /// and `io_uring` take neither (`EINVAL`), as Linux's
    /// `is_valid_guard_vma` refuses a VMA that is not `vma_is_mm_backed`
    /// (`VM_DONTEXPAND`). An install drops the pages of the range, as
    /// Linux's `zap_vma_range` does, but keeps the guards already there,
    /// and gives private anonymous memory its `anon_vma`
    /// ([`Mapping::written`]). A hole gives `ENOMEM` once the rest is done.
    pub fn guard(&mut self, addr: u64, end: u64, install: bool) -> Result<(), Errno> {
        let fragments: Vec<Mapping> = self
            .mappings
            .range(..end)
            .filter(|(_, m)| m.end() > addr)
            .map(|(_, m)| *m)
            .collect();
        let mut covered = addr;
        let mut hole = false;
        for m in fragments {
            hole |= m.start.0 > covered;
            covered = covered.max(m.end());
            if install && self.refuses_discard(&m) {
                return Err(Errno::EPERM);
            }
            let fixed = self
                .shared_at(m.start.0)
                .and_then(|shared| shared.pages.source())
                .is_some_and(|source| source.fixed());
            if fixed {
                return Err(Errno::EINVAL);
            }
            let (from, to) = (m.start.0.max(addr), m.end().min(end));
            if install {
                self.install_guards(&m, from, to);
            } else {
                self.clear_guards(from, to);
            }
        }
        if hole || covered < end {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Puts guards on `[from, to)` of the mapping `m`: drops its pages as
    /// [`Self::discard`] would, and its entries of shared memory, which
    /// keeps its contents.
    fn install_guards(&mut self, m: &Mapping, from: u64, to: u64) {
        let shared = self.shared_at(from).is_some();
        let file = matches!(m.kind, MappingKind::ElfSegment | MappingKind::File);
        // As in `discard`: a file mapping without its file has nothing to
        // read its pages from again, and keeps them.
        if shared || !file || self.backing_at(from).is_some() {
            self.for_populated(from, to, |entry| *entry = None);
            self.refill(from, to);
        }
        if !shared && !file {
            self.mark_written(GuestAddr(from), to - from);
        }
        if let Some((first, last)) = self.region_at(from) {
            for (_, mapping) in self.mappings.range_mut(first..last) {
                mapping.maybe_guard = true;
            }
        }
        self.add_guards(from, to);
        self.bump_code_generation();
    }

    /// Whether the page at `page` is a guard page.
    fn guarded(&self, page: u64) -> bool {
        self.guards
            .range(..=page)
            .next_back()
            .is_some_and(|(_, &end)| page < end)
    }

    /// Adds `[start, end)` to the guards, merging it with those it touches.
    fn add_guards(&mut self, mut start: u64, mut end: u64) {
        if let Some((&before, &before_end)) = self.guards.range(..=start).next_back()
            && before_end >= start
        {
            start = before;
            end = end.max(before_end);
        }
        let touched: Vec<(u64, u64)> = self
            .guards
            .range(start..=end)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in touched {
            self.guards.remove(&s);
            end = end.max(e);
        }
        self.guards.insert(start, end);
    }

    /// Takes `[start, end)` out of the guards, and gives the parts of it
    /// that were guards.
    fn clear_guards(&mut self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut cleared = Vec::new();
        if end <= start || self.guards.is_empty() {
            return cleared;
        }
        let first = self
            .guards
            .range(..start)
            .next_back()
            .filter(|&(_, &e)| e > start)
            .map_or(start, |(&s, _)| s);
        let overlapping: Vec<(u64, u64)> = self
            .guards
            .range(first..end)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.guards.remove(&s);
            if s < start {
                self.guards.insert(s, start);
            }
            if e > end {
                self.guards.insert(end, e);
            }
            cleared.push((s.max(start), e.min(end)));
        }
        cleared
    }

    /// Whether `[start, end)` has a guard page.
    fn has_guards(&self, start: u64, end: u64) -> bool {
        self.guards
            .range(..end)
            .next_back()
            .is_some_and(|(_, &e)| e > start)
    }

    /// Whether `m`, sealed, refuses to have its pages discarded
    /// (`can_madvise_modify`): private anonymous memory that may not be
    /// written, whose contents a discard would lose.
    fn refuses_discard(&self, m: &Mapping) -> bool {
        m.sealed
            && !m.prot.contains(Prot::WRITE)
            && !matches!(m.kind, MappingKind::ElfSegment | MappingKind::File)
            && self.shared_at(m.start.0).is_none()
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
        let mut denied = None;
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= covered {
                continue;
            }
            if m.start.0 > covered {
                break;
            }
            // A shared file mapping may become writable only when its file
            // was open for writing.
            if prot.contains(Prot::WRITE)
                && m.kind == MappingKind::File
                && self
                    .shared_at(m.start.0)
                    .is_some_and(|shared| !shared.may_write)
            {
                denied = Some(Errno::EACCES);
                break;
            }
            // A sealed one keeps its protection, even the same one
            // (`mprotect_fixup`).
            if m.sealed {
                denied = Some(Errno::EPERM);
                break;
            }
            covered = m.end();
        }
        if covered == addr.0 {
            return Err(denied.unwrap_or(Errno::ENOMEM));
        }
        // Linux applies the mapped prefix before reporting a later hole or
        // a mapping that refuses the protection.
        let incomplete = covered < end;
        let end = end.min(covered);
        self.split_unmergeable_shared(addr.0, prot);
        self.split_unmergeable_shared(end, prot);
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
        if let Some(e) = denied {
            Err(e)
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
    /// do the ones without a recorded file, which have nothing to read
    /// again. Applies the mapped parts and returns `ENOMEM` when the range
    /// has a hole, as Linux does.
    pub fn discard(&mut self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        let end = checked_range(addr, len)?;
        let mut covered = addr.0;
        let mut hole = false;
        let mut private = Vec::new();
        let mut sealed = false;
        for (_, m) in self.mappings.range(..end) {
            if m.end() <= addr.0 {
                continue;
            }
            // Linux discards VMA by VMA, and stops at a sealed one.
            if self.refuses_discard(m) {
                sealed = true;
                break;
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
        hole |= !sealed && covered < end;
        if !private.is_empty() {
            self.bump_code_generation();
        }
        for (start, end) in private {
            self.for_populated(start, end, |entry| *entry = None);
            self.refill(start, end);
        }
        if sealed {
            Err(Errno::EPERM)
        } else if hole {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
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
            if self.refuses_discard(m) {
                return Err(Errno::EPERM);
            }
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
impl AtomicOp {
    /// The value it leaves in place of `old`, masked to `mask`, and whether
    /// it exchanged.
    fn apply(self, old: u128, mask: u128) -> (u128, bool) {
        let (new, exchanged) = match self {
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
        (new & mask, exchanged)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicResult {
    pub old: u128,
    pub exchanged: bool,
}

/// A shared address space. A load, a store, a fetch or a locked instruction
/// within one word, on a page this thread's TLB holds, takes no lock. Every
/// other memory and mapping operation takes the space's lock and the
/// session's serialization lock. The private data implementation never calls
/// back through this public wrapper (no reentry).
pub struct AddressSpace {
    data: Arc<Mutex<AddressSpaceData>>,
    /// The data's `code`, for [`Self::code_generation_cached`].
    code: Arc<CodeCounters>,
    serialization: Arc<Mutex<()>>,
    /// The data's `out_of_memory`, so that every checkpoint can read it
    /// without taking the session-wide serialization lock.
    out_of_memory: Arc<AtomicBool>,
    /// The kernel's `membarrier` registrations for this space, as Linux's
    /// `mm->membarrier_state`: a fork's copy keeps it, a new space (exec)
    /// has none.
    membarrier: AtomicU32,
}

/// An address space's VMAs for as long as a thread uses it, as Linux's
/// `/proc/<pid>/maps` holds the `mm` it was opened on: it keeps no memory
/// alive, and shows nothing once the space is gone.
#[derive(Clone)]
pub struct MemoryView {
    data: Weak<Mutex<AddressSpaceData>>,
    serialization: Arc<Mutex<()>>,
}

impl MemoryView {
    /// What tells the address space apart from every other while it lives,
    /// as Linux's `kcmp` compares `mm` pointers.
    #[must_use]
    pub fn identity(&self) -> usize {
        self.data.as_ptr() as *const () as usize
    }
    /// Whether this is a view of `space`, while it lives.
    #[must_use]
    pub fn is_of(&self, space: &AddressSpace) -> bool {
        std::ptr::eq(self.data.as_ptr(), Arc::as_ptr(&space.data))
    }
    /// The first VMA that ends after `addr`, if the space still lives and
    /// has one.
    #[must_use]
    pub fn vma_from(&self, addr: u64) -> Option<Vma> {
        let data = self.data.upgrade()?;
        let (mut vma, source) = {
            let _serialization = self
                .serialization
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            data.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .vma_from(addr)?
        };
        // Asked with the lock released: the file's own state may take time.
        if let (Some(file), Some(source)) = (vma.file.as_mut(), source) {
            file.name = source.name();
            vma.identity = source.identity();
        }
        Some(vma)
    }
    /// Runs `f` on the space, if it still lives, under its locks.
    fn with_data<T>(&self, f: impl FnOnce(&AddressSpaceData) -> T) -> Option<T> {
        let data = self.data.upgrade()?;
        let _serialization = self
            .serialization
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let data = data.lock().unwrap_or_else(PoisonError::into_inner);
        Some(f(&data))
    }
    /// Reads the space's memory, as another process's `/proc/<pid>/cmdline`
    /// does: false once the space is gone or where a page is not mapped.
    #[must_use]
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        self.with_data(|data| data.read(GuestAddr(addr), buf).is_ok())
            .unwrap_or(false)
    }
    /// Copies the space's memory at `addr` into `buf`, as Linux's
    /// `process_vm_readv` pins another task's pages: page by page, up to the
    /// first page that is not mapped with `PROT_READ` (`VM_READ`, which
    /// `PROT_WRITE` or `PROT_EXEC` alone does not give) or does not read.
    /// How many bytes were copied, or `None` once the space is gone.
    #[must_use]
    pub fn read_pages(&self, addr: u64, buf: &mut [u8]) -> Option<usize> {
        self.with_data(|data| {
            let mut copied = 0;
            for (page, offset, range) in chunks(GuestAddr(addr), buf.len()) {
                let readable = data
                    .mapping_at(page)
                    .is_some_and(|m| m.prot.contains(Prot::READ));
                if !readable
                    || data
                        .read(GuestAddr(page + offset as u64), &mut buf[range.clone()])
                        .is_err()
                {
                    break;
                }
                copied = range.end;
            }
            copied
        })
    }
    /// Copies `buf` into the space at `addr`, as Linux's
    /// `process_vm_writev` pins another task's pages for writing: page by
    /// page, up to the first page that may not be written. How many bytes
    /// were copied, or `None` once the space is gone.
    #[must_use]
    pub fn write_pages(&self, addr: u64, buf: &[u8]) -> Option<usize> {
        let data = self.data.upgrade()?;
        let serialization = lock_spinning(&self.serialization);
        let mut guard = AddressSpaceGuard {
            data: lock_spinning(&data),
            _serialization: serialization,
        };
        let mut copied = 0;
        for (page, offset, range) in chunks(GuestAddr(addr), buf.len()) {
            let at = GuestAddr(page + offset as u64);
            match guard.write_with(at, &buf[range.clone()], Access::Write) {
                Ok(first) => {
                    if first {
                        guard.mark_written(at, range.len() as u64);
                    }
                }
                Err(_) => break,
            }
            copied = range.end;
        }
        Some(copied)
    }
    /// The space's mappings, or `None` once it is gone.
    #[must_use]
    pub fn mappings(&self) -> Option<Vec<Mapping>> {
        self.with_data(|data| data.mappings().copied().collect())
    }
    /// What the page table holds for the page at `addr` ([`PageState`]):
    /// `None` if it is not mapped or the space is gone.
    #[must_use]
    pub fn page_state(&self, addr: u64) -> Option<PageState> {
        self.with_data(|data| data.page_state(GuestAddr(addr).page_align_down().0))
            .flatten()
    }
    /// The total length of the space's mappings and its initial break, or
    /// `None` once it is gone.
    #[must_use]
    pub fn size_and_break(&self) -> Option<(u64, u64)> {
        self.with_data(|data| {
            (
                data.mappings().map(|m| m.length).sum(),
                data.initial_break().0,
            )
        })
    }
}

/// Owned instruction bytes and their epoch, captured under one MMU lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSnapshot {
    pub address_space: u64,
    pub generation: u64,
    pub bytes: Vec<u8>,
}

/// Locks `mutex`, which guards each memory access of a space's threads
/// and is held only for that access. On macOS, where a contended
/// `pthread_mutex` sleeps in the kernel at once, it first tries again a few
/// times, pausing twice as long after each try so as not to fight the
/// holder for the lock's cache line: the threads of a multithreaded guest
/// (Go's compiler, for one) took it millions of times, and sleeping and
/// waking for each cost more than the emulation. Elsewhere `Mutex` spins
/// by itself before it sleeps.
fn lock_spinning<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    #[cfg(target_vendor = "apple")]
    for round in 0..TRIES {
        match mutex.try_lock() {
            Ok(guard) => return guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                for _ in 0..1u32 << round {
                    std::hint::spin_loop();
                }
            }
        }
    }
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
/// How many times [`lock_spinning`] tries before it sleeps: 1023 pauses in
/// all, a few microseconds.
#[cfg(target_vendor = "apple")]
const TRIES: u32 = 10;

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
    /// Empties the [`ThreadTlb`]s first, by the epoch, and moves the layout
    /// on ([`CodeCounters`]): a mutable borrow may change the mappings, the
    /// page entries the TLBs copy, and the shared mappings and page caches.
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.code.bump_epoch();
        self.data.code.layout.fetch_add(1, Ordering::Release);
        &mut self.data
    }
}

#[cfg(test)]
mod code_generation_tests;
#[cfg(test)]
mod processes_tests;

#[cfg(test)]
mod jit_tests;
#[cfg(test)]
mod threads_tests;
#[cfg(test)]
mod tlb_tests;
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
            code: Arc::clone(&data.code),
            data: Arc::new(Mutex::new(data)),
            serialization,
            membarrier: AtomicU32::new(0),
        }
    }
    fn locked(&self) -> AddressSpaceGuard<'_> {
        let serialization = lock_spinning(&self.serialization);
        AddressSpaceGuard {
            data: lock_spinning(&self.data),
            _serialization: serialization,
        }
    }
    /// Charges this space's frames to `meter`, and the frames of the spaces
    /// forked from it.
    #[must_use]
    pub fn with_memory_meter(self, meter: Arc<MemoryMeter>) -> Self {
        self.data
            .lock()
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
    /// Private pages are shared until either space writes them, which
    /// copies them; MAP_SHARED pages stay shared. A shared serialization lock
    /// keeps cross-process memory operations indivisible.
    pub fn fork(&self) -> Self {
        let child = Self::with_data(self.locked().fork(), self.serialization.clone());
        // Linux's dup_mm copies the mm whole, membarrier_state with it.
        child
            .membarrier
            .store(self.membarrier.load(Ordering::SeqCst), Ordering::SeqCst);
        child
    }
    /// Marks a newly created mapping as Linux MAP_SHARED, independently of VM sharing.
    pub fn mark_shared(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.locked().mark_shared(addr, len)
    }
    /// Makes the newly created mapping `[addr, addr+len)` show `pages` from
    /// key `offset` on, a file's page cache from that file offset, as a
    /// Linux `MAP_SHARED` mapping of the file; `may_write` says whether
    /// `mprotect` may make it writable.
    pub fn share_pages(
        &self,
        addr: GuestAddr,
        len: u64,
        pages: &SharedPages,
        offset: u64,
        may_write: bool,
    ) -> Result<(), Errno> {
        self.locked()
            .share_pages(addr, len, pages, offset, may_write)
    }
    /// See [`AddressSpaceData::remap_shared_pages`], under one hold of the
    /// locks, as Linux's `remap_file_pages` holds its `mmap_lock` for writing.
    pub fn remap_shared_pages(
        &self,
        start: GuestAddr,
        len: u64,
        offset: Result<u64, Errno>,
    ) -> Result<(), Errno> {
        self.locked().remap_shared_pages(start.0, len, offset)
    }
    /// Maps `len` bytes where `placement` says and attaches `backing` to
    /// them, under one hold of the locks, as Linux's `mmap` does under its
    /// `mmap_lock`: no other thread sees the mapping before it shows what it
    /// maps, nor maps the range in between. When the backing cannot be
    /// attached, the new mapping goes, and what it replaced stays gone.
    pub fn map_backed(
        &self,
        placement: Placement,
        len: u64,
        prot: Prot,
        kind: MappingKind,
        backing: Backing<'_>,
    ) -> Result<GuestAddr, Errno> {
        let mut data = self.locked();
        let at = match placement {
            Placement::Replacing(at) => {
                data.unmap(at, len)?;
                data.map(Some(at), len, prot, kind)?
            }
            Placement::Exactly(at) => data.map(Some(at), len, prot, kind)?,
            Placement::Near(hint) => {
                match hint.and_then(|hint| data.map(Some(hint), len, prot, kind).ok()) {
                    Some(at) => at,
                    None => data.map(None, len, prot, kind)?,
                }
            }
        };
        let attached = match backing {
            Backing::None => Ok(()),
            Backing::SharedAnonymous => data.mark_shared(at, len),
            Backing::Shared {
                pages,
                offset,
                may_write,
            } => data.share_pages(at, len, pages, offset, may_write),
            Backing::Cache { pages, offset } => data.back_with_cache(at, len, pages, offset),
        };
        if let Err(error) = attached {
            let _ = data.unmap(at, len);
            return Err(error);
        }
        Ok(at)
    }
    #[must_use]
    pub fn id(&self) -> u64 {
        self.locked().id()
    }
    #[must_use]
    pub fn code_generation(&self) -> u64 {
        self.locked().code_generation()
    }
    /// [`Self::code_generation`], taking the locks only when the space has
    /// been borrowed mutably since it last watched the shared mappings and
    /// page caches it may run code from: those change only then. One load
    /// otherwise, as the interpreter makes before every instruction.
    /// Reading the generation before fetching the instruction keeps a
    /// decoded instruction from outliving a change, as every store to code
    /// that was fetched bumps the generation after it.
    #[must_use]
    #[inline]
    pub fn code_generation_cached(&self) -> u64 {
        let layout = self.code.layout.load(Ordering::Acquire);
        if self.code.watched.load(Ordering::Acquire) != layout.wrapping_add(1) {
            return self.code_generation_locked();
        }
        self.code.generation.load(Ordering::SeqCst)
    }
    #[cold]
    #[inline(never)]
    fn code_generation_locked(&self) -> u64 {
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
    /// mapping changes and the writes that take the locks, including another
    /// process's shared writes. A store through a thread's [`ThreadTlb`]
    /// takes no lock, so it may land while the code runs: as the code touches
    /// no guest memory, that is as if it landed just after the check.
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
    /// Marks `[addr, addr+len)` written, as Linux's write faults do when it
    /// populates a writable private mapping ([`Mapping::written`]).
    pub fn mark_written(&self, addr: GuestAddr, len: u64) {
        self.locked().mark_written(addr, len);
    }
    /// The start and length of the Linux VMA holding `addr`: the mapping
    /// there and the adjacent ones Linux would have merged with it.
    pub fn vma_at(&self, addr: GuestAddr) -> Option<(GuestAddr, u64)> {
        self.locked()
            .region_at(addr.0)
            .map(|(start, end)| (GuestAddr(start), end - start))
    }
    /// The core dump's view of the Linux VMA at `addr` ([`CoreState`]).
    pub fn core_state(&self, addr: GuestAddr) -> CoreState {
        let (state, file) = self.locked().core_state(addr.0);
        // Asked with the lock released: the file's own state may take time.
        CoreState {
            linked: file.is_some_and(|source| source.linked()),
            ..state
        }
    }
    /// What `mincore` says of the page at `addr`: `None` if it is not mapped,
    /// or whether it is in memory.
    #[must_use]
    pub fn resident(&self, addr: GuestAddr) -> Option<bool> {
        self.locked().resident(addr.page_align_down().0)
    }
    /// What the page table holds for the page at `addr`, `None` if it is
    /// not mapped ([`PageState`]).
    #[must_use]
    pub fn page_state(&self, addr: GuestAddr) -> Option<PageState> {
        self.locked().page_state(addr.page_align_down().0)
    }
    /// Where `addr` lies in shared memory, if a shared mapping holds it: the
    /// memory's id and the offset in it. Every mapping of that memory, in
    /// any address space, gives the same pair, as the inode and page index of
    /// Linux's `get_futex_key` do.
    #[must_use]
    pub fn shared_offset(&self, addr: GuestAddr) -> Option<(u64, u64)> {
        self.locked()
            .shared_at(addr.0)
            .map(|shared| (shared.pages.id, addr.0.wrapping_add(shared.shift)))
    }
    /// The file the mapping at `addr` maps, for a core's `NT_FILE` note.
    pub fn mapped_file(&self, addr: GuestAddr) -> Option<MappedFile> {
        let (source, offset) = self.locked().mapped_file(addr.0)?;
        // Named with the lock released: the file's own state may take time.
        Some(MappedFile {
            name: source.as_ref().and_then(|source| source.name()),
            source: source.is_some(),
            offset,
        })
    }
    /// A full barrier on every thread of this space, as Linux's
    /// `membarrier` gives: when it returns, each other thread's accesses
    /// before some point during it are seen by this thread, and its accesses
    /// after that point see this thread's before the call. A host fence
    /// alone would not do, as most accesses take no lock. The locks wait for
    /// the accesses that take them, and moving the epoch on waits for the
    /// stores under way without them and sends the next accesses of each
    /// thread to the locks, after this thread's.
    pub fn barrier(&self) {
        std::sync::atomic::fence(Ordering::SeqCst);
        self.locked().code.bump_epoch();
        std::sync::atomic::fence(Ordering::SeqCst);
    }
    /// The kernel's `membarrier` state for this space, shared by every
    /// thread that runs in it.
    #[must_use]
    pub fn membarrier_state(&self) -> &AtomicU32 {
        &self.membarrier
    }
    /// This space's VMAs as `/proc/<pid>/maps` reads them ([`MemoryView`]).
    #[must_use]
    pub fn view(&self) -> MemoryView {
        MemoryView {
            data: Arc::downgrade(&self.data),
            serialization: Arc::clone(&self.serialization),
        }
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
    /// Places mappings without a fixed address upward from `base`, as
    /// Linux's legacy layout does, or (`None`) down from the top.
    pub fn set_bottom_up(&mut self, base: Option<GuestAddr>) {
        self.locked().set_bottom_up(base);
    }
    /// The lowest address from `from`, a multiple of `align` (a power of
    /// two), with `len` free bytes below TASK_SIZE.
    #[must_use]
    pub fn lowest_gap(&self, from: GuestAddr, len: u64, align: u64) -> Option<GuestAddr> {
        self.locked().lowest_gap(from.0, len, align).map(GuestAddr)
    }
    #[must_use]
    pub fn bottom_up(&self) -> Option<u64> {
        self.locked().bottom_up()
    }
    pub fn read(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        if self.read_unlocked(addr, buf, Access::Read) {
            return Ok(());
        }
        self.locked().read(addr, buf)
    }
    /// Runs `f` on this thread's [`ThreadTlb`] if it holds this space's
    /// pages; `None` otherwise, which empties it for the locked path to fill.
    #[inline]
    fn with_thread_tlb<T>(&self, f: impl FnOnce(&Tlb) -> Option<T>) -> Option<T> {
        let epoch = self.code.epoch.load(Ordering::Acquire);
        THREAD_TLB.with(|cell| {
            let mut thread = cell.try_borrow_mut().ok()?;
            if thread.epoch != epoch {
                thread.tlb.flush();
                thread.epoch = epoch;
                return None;
            }
            f(&thread.tlb)
        })
    }
    /// Reads `buf`, which lies in one page, through this thread's
    /// [`ThreadTlb`] without a lock; `false` when the TLB does not hold the
    /// page or the access is not permitted there.
    #[inline]
    fn read_unlocked(&self, addr: GuestAddr, buf: &mut [u8], access: Access) -> bool {
        let Some(page) = AddressSpaceData::single_page(addr, buf.len()) else {
            return false;
        };
        self.with_thread_tlb(|tlb| {
            let entry = tlb.get(page).filter(|e| access.permitted(e.prot))?;
            // The first fetch from a page marks it under the locks.
            if access == Access::Fetch && !entry.fetched.load(Ordering::Acquire) {
                return None;
            }
            match entry.frame.get() {
                Some(frame) => frame.read(page_offset(addr.0), buf),
                None => buf.fill(0),
            }
            Some(())
        })
        .is_some()
    }
    /// Reads guest memory whatever its protection, as Linux's core dump
    /// does: a page that is mapped at all reads.
    pub fn read_for_dump(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Fault> {
        self.locked().read_for_dump(addr, buf)
    }
    pub fn write(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        if self.write_unlocked(addr, buf) {
            return Ok(());
        }
        Self::write_locked(self.locked(), addr, buf)
    }
    /// Runs `f`, which stores, on this thread's [`ThreadTlb`] if it holds
    /// this space's pages, as [`Self::with_thread_tlb`] does, and says
    /// meanwhile that a store is under way ([`ThreadTlb::storing`]).
    #[inline]
    fn storing_through_thread_tlb<T>(&self, f: impl FnOnce(&Tlb) -> Option<T>) -> Option<T> {
        let epoch = self.code.epoch.load(Ordering::Acquire);
        THREAD_TLB.with(|cell| {
            let mut thread = cell.try_borrow_mut().ok()?;
            if thread.epoch != epoch {
                thread.tlb.flush();
                thread.epoch = epoch;
                return None;
            }
            // Read again after saying so, both `SeqCst`: a change that moved
            // the epoch on before this either shows here, or waits for this
            // store to end ([`CodeCounters::bump_epoch`]).
            thread.storing.store(epoch, Ordering::SeqCst);
            let result = if self.code.epoch.load(Ordering::SeqCst) == epoch {
                #[cfg(test)]
                if let Some(stall) = STORE_STALL.get() {
                    std::thread::sleep(stall);
                }
                f(&thread.tlb)
            } else {
                None
            };
            // `Release`: a change that sees the store ended sees its bytes.
            thread.storing.store(NOT_STORING, Ordering::Release);
            result
        })
    }
    /// Writes `buf`, which lies in one page, through this thread's
    /// [`ThreadTlb`] without a lock; `false` when the TLB does not hold the
    /// page, or the page has had no first write or shares its frame with
    /// `fork`, or may not be written.
    #[inline]
    fn write_unlocked(&self, addr: GuestAddr, buf: &[u8]) -> bool {
        let Some(page) = AddressSpaceData::single_page(addr, buf.len()) else {
            return false;
        };
        self.storing_through_thread_tlb(|tlb| {
            let target = Self::writable(tlb, page)?;
            target.frame.write(page_offset(addr.0), buf);
            self.wrote(&target);
            Some(())
        })
        .is_some()
    }
    /// What a store through `tlb` to `page` writes, which [`Self::wrote`]
    /// is given after the bytes; for a shared page, its memory's generation
    /// has moved on before them, as `store_with` does under the locks. A
    /// private page-cache page has `cow` set and is left out: it is copied
    /// under the locks first. `code` says whether the page is executable
    /// code that was fetched ([`FrameCell::fetched`]).
    #[inline]
    fn writable(tlb: &Tlb, page: u64) -> Option<StoreTarget<'_>> {
        let entry = tlb
            .get(page)
            .filter(|e| e.prot.contains(Prot::WRITE) && !e.cow)?;
        let target = StoreTarget {
            frame: entry.frame.get()?,
            // `Relaxed`: a mark set before this entry was remembered, under
            // the locks, is seen; one set since moved the epoch on first,
            // which waits for this store ([`AddressSpaceData::mark_fetched`]).
            code: entry.prot.contains(Prot::EXEC) && entry.fetched.load(Ordering::Relaxed),
            shared: entry.shared.as_ref(),
        };
        if let Some(shared) = target.shared {
            shared.changed();
        }
        Some(target)
    }
    /// After a store through a [`ThreadTlb`], as in `store_with`, after the
    /// bytes: a store to code that was fetched makes the decoded
    /// instructions stale, and a shared page becomes dirty, for write-back,
    /// and moves its memory's generation on again, so that a write-back that
    /// ran between the two bumps sees a change after it. A private page is
    /// never written back, so it need not be marked dirty.
    #[inline]
    fn wrote(&self, target: &StoreTarget<'_>) {
        if target.code {
            self.code.generation.fetch_add(1, Ordering::Release);
        }
        if let Some(shared) = target.shared {
            target.frame.dirty.store(true, Ordering::Release);
            shared.changed();
        }
    }
    /// Writes guest memory, which requires `PROT_WRITE`, through a shared
    /// borrow, so that the epoch stays and the [`ThreadTlb`]s survive, unless
    /// a page took its first write, which marks its mapping written.
    fn write_locked(
        mut data: AddressSpaceGuard<'_>,
        addr: GuestAddr,
        buf: &[u8],
    ) -> Result<(), Fault> {
        if data.write_with(addr, buf, Access::Write)? {
            data.mark_written(addr, buf.len() as u64);
        }
        Ok(())
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
        // A write to an executable page that was fetched from moves the code
        // generation on after its bytes, so a fetch here that follows a read
        // of the new generation reads the new bytes, as one under the lock
        // does. A page not fetched from yet is marked under the locks.
        if self.read_unlocked(addr, buf, Access::Fetch) {
            return Ok(buf.len());
        }
        self.locked().fetch_partial(addr, buf)
    }
    pub fn write_initial(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Fault> {
        self.locked().write_initial(addr, buf)
    }
    pub fn read_u64(&self, addr: GuestAddr) -> Result<u64, Fault> {
        self.read_value(addr, 8)
    }
    pub fn write_u64(&self, addr: GuestAddr, value: u64) -> Result<(), Fault> {
        self.write_value(addr, 8, value)
    }
    /// The little-endian value of `size` bytes, of which 8 are the most it
    /// takes, as [`Self::read`] gives them, with one atomic access where they
    /// lie in one word.
    #[inline]
    pub fn read_value(&self, addr: GuestAddr, size: usize) -> Result<u64, Fault> {
        if let Some(value) = self.read_value_unlocked(addr, size) {
            return Ok(value);
        }
        let mut bytes = [0; WORD_BYTES];
        self.read(addr, &mut bytes[..size.min(WORD_BYTES)])?;
        Ok(u64::from_le_bytes(bytes))
    }
    /// [`Self::read_unlocked`] of `size` bytes, 1 to 8, that lie in one word.
    #[inline]
    fn read_value_unlocked(&self, addr: GuestAddr, size: usize) -> Option<u64> {
        let offset = page_offset(addr.0);
        let within = offset % WORD_BYTES;
        if size == 0 || within + size > WORD_BYTES {
            return None;
        }
        self.with_thread_tlb(|tlb| {
            let entry = tlb
                .get(addr.0 - offset as u64)
                .filter(|e| e.prot.allows_read())?;
            let Some(frame) = entry.frame.get() else {
                return Some(0);
            };
            let word = frame.words[offset / WORD_BYTES].load(Ordering::Acquire);
            Some(word >> (8 * within) & value_mask(size))
        })
    }
    /// Writes the low `size` bytes of `value`, of which 8 are the most it
    /// takes, as [`Self::write`] does.
    #[inline]
    pub fn write_value(&self, addr: GuestAddr, size: usize, value: u64) -> Result<(), Fault> {
        if self.write_value_unlocked(addr, size, value) {
            return Ok(());
        }
        self.write(addr, &value.to_le_bytes()[..size.min(WORD_BYTES)])
    }
    /// [`Self::write_unlocked`] of `size` bytes, 1 to 8, that lie in one word.
    #[inline]
    fn write_value_unlocked(&self, addr: GuestAddr, size: usize, value: u64) -> bool {
        let offset = page_offset(addr.0);
        if size == 0 || offset % WORD_BYTES + size > WORD_BYTES {
            return false;
        }
        self.storing_through_thread_tlb(|tlb| {
            let target = Self::writable(tlb, addr.0 - offset as u64)?;
            target.frame.write_value(offset, size, value);
            self.wrote(&target);
            Some(())
        })
        .is_some()
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
    /// See [`AddressSpaceData::seal`].
    pub fn seal_shared(&self, addr: GuestAddr, len: u64) -> Result<(), Errno> {
        self.locked().seal(addr, len)
    }
    /// See [`AddressSpaceData::removals`]: the memory to free, which the
    /// kernel frees with the lock released, as its file may take time.
    #[must_use]
    pub fn removals(&self, addr: GuestAddr, end: u64) -> (Vec<Result<Removal, Errno>>, bool) {
        self.locked().removals(addr.0, end)
    }
    /// See [`AddressSpaceData::advise_flags`].
    pub fn advise_flags(&self, addr: GuestAddr, end: u64, advice: FlagAdvice) -> Result<(), Errno> {
        self.locked().advise_flags(addr.0, end, advice)
    }
    /// See [`AddressSpaceData::lock`].
    pub fn lock(&self, addr: GuestAddr, end: u64, lock: Option<Lock>) -> Result<(), Errno> {
        self.locked().lock(addr.0, end, lock)
    }
    /// See [`AddressSpaceData::lock_new`].
    pub fn lock_new(&self, addr: GuestAddr, end: u64, lock: Lock) {
        self.locked().lock_new(addr.0, end, lock);
    }
    /// See [`AddressSpaceData::lock_all`].
    pub fn lock_all(&self, current: Option<Option<Lock>>, future: Option<Lock>) {
        self.locked().lock_all(current, future);
    }
    /// See [`AddressSpaceData::first_locked`].
    pub fn first_locked(&self, addr: GuestAddr, end: u64) -> Option<Mapping> {
        self.locked().first_locked(addr.0, end)
    }
    /// See [`AddressSpaceData::refuses_discard_at`].
    pub fn refuses_discard_at(&self, addr: GuestAddr) -> bool {
        self.locked().refuses_discard_at(addr.0)
    }
    /// See [`AddressSpaceData::locked_pages`].
    pub fn locked_pages(&self) -> u64 {
        self.locked().locked_pages()
    }
    /// See [`AddressSpaceData::locked_pages_in`].
    pub fn locked_pages_in(&self, addr: GuestAddr, end: u64) -> u64 {
        self.locked().locked_pages_in(addr.0, end)
    }
    /// See [`AddressSpaceData::future_lock`].
    pub fn future_lock(&self) -> Option<Lock> {
        self.locked().future_lock()
    }
    /// See [`AddressSpaceData::guard`].
    pub fn guard(&self, addr: GuestAddr, end: u64, install: bool) -> Result<(), Errno> {
        self.locked().guard(addr.0, end, install)
    }
    /// Whether `[addr, end)` has a guard page (`MADV_GUARD_INSTALL`), where
    /// Linux's `mlock` fails to fault a page in.
    pub fn has_guards(&self, addr: GuestAddr, end: u64) -> bool {
        self.locked().has_guards(addr.0, end)
    }
    pub fn protect(&mut self, addr: GuestAddr, len: u64, prot: Prot) -> Result<(), Errno> {
        self.protect_shared(addr, len, prot)
    }
    /// The shared mappings of the space, by address.
    #[must_use]
    pub fn shared_fragments(&self) -> Vec<SharedFragment> {
        self.locked().shared_fragments()
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
    /// See [`AddressSpaceData::back_with_cache`].
    pub fn back_with_cache(
        &self,
        addr: GuestAddr,
        len: u64,
        pages: &SharedPages,
        offset: u64,
    ) -> Result<(), Errno> {
        self.locked().back_with_cache(addr, len, pages, offset)
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
    /// A locked instruction: one update of the bytes, atomic against every
    /// other access to them, that needs write access to them even when its
    /// compare fails. Within one word it is one compare-and-swap of the
    /// word ([`FrameBytes::update`]), through this thread's [`ThreadTlb`]
    /// without a lock when it holds the page.
    pub fn atomic(
        &self,
        addr: GuestAddr,
        width: AtomicWidth,
        operation: AtomicOp,
    ) -> Result<AtomicResult, Fault> {
        let size = width.bytes();
        let result = if page_offset(addr.0) % WORD_BYTES + size <= WORD_BYTES {
            match self.atomic_unlocked(addr, size, operation) {
                Some(result) => result,
                None => {
                    // Not a read and then a write under the locks: a store
                    // or a locked instruction of another thread, which takes
                    // none, could come between them.
                    let mut data = self.locked();
                    let first = data.prepare_write(addr, size, Access::Write)?;
                    let result = data.update(addr, size, operation)?;
                    if first {
                        data.mark_written(addr, size as u64);
                    }
                    result
                }
            }
        } else {
            self.atomic_spanning(addr, size, operation)?
        };
        // A locked instruction is a full fence. Earlier loads and stores
        // already come before its store, which releases them. But an
        // `Acquire` load after it may pass it on Arm, and Go's scheduler, for
        // one, depends on it not.
        std::sync::atomic::fence(Ordering::SeqCst);
        Ok(result)
    }
    /// [`Self::atomic`] within one word through this thread's [`ThreadTlb`];
    /// `None` when [`Self::write_unlocked`] would take the locks.
    #[inline]
    fn atomic_unlocked(
        &self,
        addr: GuestAddr,
        size: usize,
        operation: AtomicOp,
    ) -> Option<AtomicResult> {
        let offset = page_offset(addr.0);
        self.storing_through_thread_tlb(|tlb| {
            let target = Self::writable(tlb, addr.0 - offset as u64)?;
            let result = target.frame.update(offset, size, operation);
            self.wrote(&target);
            Some(result)
        })
    }
    /// [`Self::atomic`] on bytes in more than one word, which no one
    /// compare-and-swap covers: a split lock, or `CMPXCHG16B`. Under the
    /// locks, it moves the epoch on first, which waits for the stores under
    /// way without a lock and sends the next ones to the locks, and then
    /// reads and writes the bytes. A load that takes no lock may still see
    /// one word of the write before the other, except an aligned 16-byte
    /// one ([`FrameBytes::read`]).
    fn atomic_spanning(
        &self,
        addr: GuestAddr,
        size: usize,
        operation: AtomicOp,
    ) -> Result<AtomicResult, Fault> {
        let data = self.locked();
        // Checked first, so that one that faults leaves the TLBs: nothing
        // that takes no lock changes a protection.
        data.check(&data.read_directory(), addr, size, Access::Write)?;
        data.code.bump_epoch();
        let mut bytes = [0u8; 16];
        data.read(addr, &mut bytes[..size])?;
        let old = u128::from_le_bytes(bytes);
        let mask = if size == 16 {
            u128::MAX
        } else {
            (1u128 << (size * 8)) - 1
        };
        let (new, exchanged) = operation.apply(old, mask);
        Self::write_locked(data, addr, &new.to_le_bytes()[..size])?;
        Ok(AtomicResult { old, exchanged })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_of(bytes: &[u8]) -> FrameBytes {
        FrameBytes::new(None, || page_words(bytes)).unwrap()
    }

    #[test]
    fn a_frame_reads_and_writes_any_bytes_of_its_words() {
        let start: Vec<u8> = (0..=255).cycle().take(PAGE_BYTES).collect();
        let frame = frame_of(&start);
        for offset in 0..20 {
            for len in 0..20 {
                let mut buf = vec![0; len];
                frame.read(offset, &mut buf);
                assert_eq!(buf, start[offset..offset + len], "{offset}+{len}");
            }
        }
        for offset in 0..20 {
            for len in 0..20 {
                let frame = frame_of(&start);
                let data = vec![0xee; len];
                frame.write(offset, &data);
                let mut expected = start.clone();
                expected[offset..offset + len].fill(0xee);
                let mut page = vec![0; PAGE_BYTES];
                frame.read(0, &mut page);
                assert_eq!(page, expected, "{offset}+{len}");
                if len > 0 && offset % WORD_BYTES + len <= WORD_BYTES {
                    let frame = frame_of(&start);
                    frame.write_value(offset, len, 0xeeee_eeee_eeee_eeee);
                    frame.read(0, &mut page);
                    assert_eq!(page, expected, "value {offset}+{len}");
                }
            }
        }
    }

    #[test]
    fn a_locked_instruction_in_a_word_leaves_its_other_bytes() {
        let frame = frame_of(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let result = frame.update(2, 2, AtomicOp::Add(0x0101));
        assert_eq!(
            result,
            AtomicResult {
                old: 0x0403,
                exchanged: true
            }
        );
        let failed = frame.update(
            4,
            4,
            AtomicOp::CompareExchange {
                expected: 0,
                replacement: 9,
            },
        );
        assert_eq!(
            failed,
            AtomicResult {
                old: 0x0807_0605,
                exchanged: false
            }
        );
        frame.update(7, 1, AtomicOp::Neg);
        let mut word = [0; WORD_BYTES];
        frame.read(0, &mut word);
        assert_eq!(word, [1, 2, 4, 5, 5, 6, 7, 0xf8]);
    }

    #[test]
    fn a_frame_reaches_the_end_of_its_page_and_starts_short_of_it() {
        let frame = frame_of(&[1, 2, 3]);
        let mut buf = [9; 5];
        frame.read(0, &mut buf);
        assert_eq!(buf, [1, 2, 3, 0, 0]);
        frame.write(PAGE_BYTES - 3, &[7, 8, 9]);
        frame.read(PAGE_BYTES - 5, &mut buf);
        assert_eq!(buf, [0, 0, 7, 8, 9]);
    }

    #[test]
    fn threads_writing_bytes_of_one_word_keep_each_others() {
        let frame = Arc::new(frame_of(&[]));
        std::thread::scope(|scope| {
            for byte in 0..WORD_BYTES {
                let frame = Arc::clone(&frame);
                scope.spawn(move || {
                    for round in 0..20_000u32 {
                        frame.write(byte, &[(round % 251) as u8 + 1]);
                    }
                    frame.write(byte, &[byte as u8 + 1]);
                });
            }
        });
        let mut word = [0; WORD_BYTES];
        frame.read(0, &mut word);
        assert_eq!(word, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn an_aligned_word_is_written_whole_though_another_thread_reads_it() {
        let frame = Arc::new(frame_of(&[]));
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    let mut word = [0; WORD_BYTES];
                    frame.read(8, &mut word);
                    assert!(
                        word == [0; WORD_BYTES] || word == [0xff; WORD_BYTES],
                        "{word:?}"
                    );
                }
            });
            for round in 0..200_000 {
                frame.write(8, &[if round % 2 == 0 { 0xff } else { 0 }; WORD_BYTES]);
            }
            done.store(true, Ordering::Relaxed);
        });
    }

    #[test]
    fn aligned_16_bytes_are_read_whole_though_another_thread_writes_them() {
        let frame = Arc::new(frame_of(&[]));
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    let mut value = [0; 16];
                    frame.read(16, &mut value);
                    assert!(value == [0; 16] || value == [0xff; 16], "{value:?}");
                }
            });
            for round in 0..200_000 {
                frame.write(16, &[if round % 2 == 0 { 0xff } else { 0 }; 16]);
            }
            done.store(true, Ordering::Relaxed);
        });
    }

    #[test]
    fn a_write_that_panics_partway_leaves_reads_and_writes_free_to_go_on() {
        let frame = Arc::new(frame_of(&[]));
        // Past the page's end: the first word is written, then the index
        // panics, between the write's start and its end.
        let past = Arc::clone(&frame);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            past.write(PAGE_BYTES - 4, &[0xee; 16]);
        }));
        assert!(unwound.is_err());
        let (done, finished) = std::sync::mpsc::channel();
        let reader = Arc::clone(&frame);
        std::thread::spawn(move || {
            let mut value = [0xff; 16];
            reader.read(0, &mut value);
            let _ = done.send(value);
        });
        let value = finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read waits for a write that is gone");
        assert_eq!(value, [0; 16]);
        // And a later write of more than one word gets its turn.
        let writer = Arc::clone(&frame);
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            writer.write(16, &[0x55; 16]);
            let _ = done.send(());
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the write waits for one that is gone");
    }

    #[test]
    fn writes_of_16_bytes_from_two_threads_leave_one_of_them_whole() {
        let frame = frame_of(&[]);
        std::thread::scope(|scope| {
            let slow = scope.spawn(|| {
                WORD_STALL.set(Some(std::time::Duration::from_millis(100)));
                frame.write(16, &[0xaa; 16]);
            });
            // While the slow write waits between its words, unless it waits
            // for this one first.
            std::thread::sleep(std::time::Duration::from_millis(30));
            frame.write(16, &[0x55; 16]);
            slow.join().unwrap();
        });
        let mut value = [0; 16];
        frame.read(16, &mut value);
        assert!(value == [0xaa; 16] || value == [0x55; 16], "{value:?}");
    }

    #[test]
    fn values_read_and_write_as_their_bytes_do_at_any_offset() {
        let space = space_with(0x10000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        let start: Vec<u8> = (1..=255).cycle().take(2 * PAGE_BYTES).collect();
        space.write(GuestAddr(0x10000), &start).unwrap();
        // Twice each: the first takes the page table's path, the next the Tlb's.
        for at in (0..24).chain(PAGE_BYTES - 12..PAGE_BYTES + 4) {
            let addr = GuestAddr(0x10000 + at as u64);
            for size in 1..=8 {
                let mut bytes = [0; 8];
                bytes[..size].copy_from_slice(&start[at..at + size]);
                let expected = u64::from_le_bytes(bytes);
                assert_eq!(space.read_value(addr, size), Ok(expected), "{at}+{size}");
                assert_eq!(space.read_value(addr, size), Ok(expected), "{at}+{size}");
                space.write_value(addr, size, !0).unwrap();
                space.write_value(addr, size, !0).unwrap();
                let mut after = vec![0; 2 * PAGE_BYTES];
                space.read(GuestAddr(0x10000), &mut after).unwrap();
                let mut wanted = start.clone();
                wanted[at..at + size].fill(0xff);
                assert_eq!(after, wanted, "{at}+{size}");
                // Only the low bytes of the value count.
                space
                    .write_value(addr, size, expected | !value_mask(size))
                    .unwrap();
                space.read(GuestAddr(0x10000), &mut after).unwrap();
                assert_eq!(after, start, "{at}+{size}");
            }
        }
        assert_eq!(space.read_value(GuestAddr(0x10000), 0), Ok(0));
        space.write_value(GuestAddr(0x10000), 0, !0).unwrap();
        assert_eq!(space.read_value(GuestAddr(0x10000), 1), Ok(1));
        // More than a value holds takes the 8 bytes it can.
        let eight = space.read_value(GuestAddr(0x10000), 8);
        assert_eq!(space.read_value(GuestAddr(0x10000), 9), eight);
        space.write_value(GuestAddr(0x10000), 9, 5).unwrap();
        assert_eq!(space.read_value(GuestAddr(0x10000), 8), Ok(5));
        assert_eq!(space.read_value(GuestAddr(0x10008), 1), Ok(9));
    }

    #[test]
    fn values_fault_as_their_bytes_do() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ);
        // Past the mapping, whichever way the word lies.
        let past = space.read_value(GuestAddr(0x10ffc), 8).unwrap_err();
        assert_eq!(past.addr, GuestAddr(0x11000));
        assert_eq!(space.read_value(GuestAddr(0x10000), 8), Ok(0));
        // Reading put the page in the Tlb, which still refuses a write.
        let refused = space.write_value(GuestAddr(0x10000), 8, 1).unwrap_err();
        assert!(refused.write);
        assert_eq!(space.read_value(GuestAddr(0x10000), 8), Ok(0));
    }

    #[test]
    fn a_value_written_to_code_makes_decoded_instructions_stale() {
        let space = space_with(0x10000, PAGE_SIZE, Prot::READ_WRITE.union(Prot::EXEC));
        space.write_u64(GuestAddr(0x10000), 1).unwrap();
        space.fetch(GuestAddr(0x10000), &mut [0]).unwrap();
        // Twice, so that the second goes through the Tlb.
        space.write_value(GuestAddr(0x10000), 8, 2).unwrap();
        let before = space.code_generation();
        space.write_value(GuestAddr(0x10000), 4, 3).unwrap();
        assert_ne!(space.code_generation(), before);
    }

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
                present: false,
                bus: false,
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
                present: false,
                bus: false,
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
    fn a_core_dump_reads_a_page_whatever_its_protection() {
        let mut space = space_with(0x20000, PAGE_SIZE, Prot::READ_WRITE);
        space.write(GuestAddr(0x20000), &[1, 2, 3, 4]).unwrap();
        space
            .protect(GuestAddr(0x20000), PAGE_SIZE, Prot::NONE)
            .unwrap();
        let mut buf = [0u8; 4];
        assert!(space.read(GuestAddr(0x20000), &mut buf).is_err());
        space.read_for_dump(GuestAddr(0x20000), &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
        // An address mapped not at all still faults.
        assert!(space.read_for_dump(GuestAddr(0x30000), &mut buf).is_err());
    }

    #[test]
    fn a_core_dump_reads_an_unreadable_file_page_from_the_file() {
        let mut space = AddressSpace::new();
        let at = space
            .map(None, PAGE_SIZE, Prot::NONE, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(Arc::new(Pattern(PAGE_SIZE)));
        space.back_with_cache(at, PAGE_SIZE, &pages, 0).unwrap();
        let mut buf = [0u8; 4];
        space
            .read_for_dump(GuestAddr(at.0 + 300), &mut buf)
            .unwrap();
        assert_eq!(buf, [300, 301, 302, 303].map(pattern));
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
    fn a_sealed_mapping_refuses_changes_as_mseal_has_it() {
        let mut space = space_with(0x50000, 4 * PAGE_SIZE, Prot::READ_WRITE);
        let at = |n: u64| GuestAddr(0x50000 + n * PAGE_SIZE);
        // A hole is ENOMEM, and seals nothing.
        space.unmap(at(3), PAGE_SIZE).unwrap();
        assert_eq!(space.seal_shared(at(0), 4 * PAGE_SIZE), Err(Errno::ENOMEM));
        assert!(space.mappings().all(|m| !m.sealed));
        space.seal_shared(at(1), PAGE_SIZE).unwrap();
        let sealed: Vec<_> = space.mappings().map(|m| (m.start.0, m.sealed)).collect();
        assert_eq!(
            sealed,
            vec![(at(0).0, false), (at(1).0, true), (at(2).0, false)]
        );
        // mprotect changes what comes before it, then stops.
        assert_eq!(
            space.protect(at(0), 3 * PAGE_SIZE, Prot::READ),
            Err(Errno::EPERM)
        );
        let prots: Vec<_> = space.mappings().map(|m| m.prot).collect();
        assert_eq!(prots, vec![Prot::READ, Prot::READ_WRITE, Prot::READ_WRITE]);
        assert_eq!(
            space.protect(at(1), PAGE_SIZE, Prot::READ_WRITE),
            Err(Errno::EPERM)
        );
        // munmap unmaps nothing; mremap and MAP_FIXED do not touch it.
        assert_eq!(space.unmap(at(0), 3 * PAGE_SIZE), Err(Errno::EPERM));
        assert_eq!(space.mappings().count(), 3);
        let grow = Remap {
            may_move: true,
            fixed: false,
            keep_old: false,
            new_addr: GuestAddr(0),
        };
        assert_eq!(
            space.remap_shared(at(1), PAGE_SIZE, 2 * PAGE_SIZE, grow),
            Err(Errno::EPERM)
        );
        // Writable, it may be discarded; read-only and anonymous, not.
        space.write_u64(at(1), 7).unwrap();
        space.discard_shared(at(1), PAGE_SIZE).unwrap();
        assert_eq!(space.read_u64(at(1)).unwrap(), 0);
        space.seal_shared(at(0), PAGE_SIZE).unwrap();
        assert_eq!(space.discard_shared(at(0), PAGE_SIZE), Err(Errno::EPERM));
        assert_eq!(
            space.check_private_anonymous(at(0), PAGE_SIZE),
            Err(Errno::EPERM)
        );
        // Sealed and not sealed do not merge: the unsealed page goes alone.
        space.unmap(at(2), PAGE_SIZE).unwrap();
        assert_eq!(space.mappings().count(), 2);
        // A fork keeps the seal.
        let child = space.fork();
        assert!(child.mappings().all(|m| m.sealed));
    }

    #[test]
    fn fork_advice_leaves_a_hole_or_new_memory_in_the_child() {
        let space = space_with(0x50000, 4 * PAGE_SIZE, Prot::READ_WRITE);
        let at = |n: u64| GuestAddr(0x50000 + n * PAGE_SIZE);
        let end = |n: u64| 0x50000 + n * PAGE_SIZE;
        for n in 0..4 {
            space.write_u64(at(n), n + 1).unwrap();
        }
        space
            .advise_flags(at(1), end(2), FlagAdvice::DontFork)
            .unwrap();
        space
            .advise_flags(at(2), end(3), FlagAdvice::WipeOnFork)
            .unwrap();
        space
            .advise_flags(at(3), end(4), FlagAdvice::DontDump)
            .unwrap();
        // Each flag splits the VMA, and none merges with another.
        let flags: Vec<_> = space
            .mappings()
            .map(|m| (m.dont_fork, m.wipe_on_fork, m.dont_dump))
            .collect();
        assert_eq!(
            flags,
            vec![
                (false, false, false),
                (true, false, false),
                (false, true, false),
                (false, false, true)
            ]
        );
        assert_eq!(space.vma_at(at(1)), Some((at(1), PAGE_SIZE)));
        let child = space.fork();
        assert_eq!(child.read_u64(at(0)).unwrap(), 1);
        assert!(child.read_u64(at(1)).is_err());
        assert_eq!(child.page_state(at(2)), Some(PageState::Absent));
        assert_eq!(child.read_u64(at(2)).unwrap(), 0);
        assert_eq!(child.read_u64(at(3)).unwrap(), 4);
        // The parent keeps its pages; the child keeps MADV_WIPEONFORK and
        // MADV_DONTDUMP, and its wiped mapping has no `anon_vma` yet.
        assert_eq!(space.read_u64(at(2)).unwrap(), 3);
        let kept: Vec<_> = child
            .mappings()
            .map(|m| (m.start.0, m.wipe_on_fork, m.dont_dump, m.written))
            .collect();
        assert_eq!(
            kept,
            vec![
                (at(0).0, false, false, true),
                (at(2).0, true, false, false),
                (at(3).0, false, true, true)
            ]
        );
        // Clearing the flags lets the pieces be one VMA again.
        space
            .advise_flags(at(0), end(4), FlagAdvice::DoFork)
            .unwrap();
        space
            .advise_flags(at(0), end(4), FlagAdvice::KeepOnFork)
            .unwrap();
        space
            .advise_flags(at(0), end(4), FlagAdvice::DoDump)
            .unwrap();
        assert!(
            space
                .mappings()
                .all(|m| !m.dont_fork && !m.wipe_on_fork && !m.dont_dump)
        );
        assert_eq!(space.vma_at(at(2)), Some((at(0), 4 * PAGE_SIZE)));
    }

    #[test]
    fn locks_split_vmas_and_go_where_linux_drops_them() {
        let mut space = space_with(0x50000, 3 * PAGE_SIZE, Prot::READ_WRITE);
        space
            .lock(GuestAddr(0x51000), 0x52000, Some(Lock::Populated))
            .unwrap();
        assert_eq!(
            space.vma_at(GuestAddr(0x51000)),
            Some((GuestAddr(0x51000), PAGE_SIZE))
        );
        assert_eq!(space.locked_pages(), 1);
        // A hole stops it, after the VMAs before took it.
        assert_eq!(
            space.lock(GuestAddr(0x50000), 0x60000, Some(Lock::OnFault)),
            Err(Errno::ENOMEM)
        );
        assert_eq!(space.locked_pages(), 3);
        assert_eq!(
            space.vma_at(GuestAddr(0x50000)),
            Some((GuestAddr(0x50000), 3 * PAGE_SIZE))
        );
        // A child has none.
        assert_eq!(space.fork().locked_pages(), 0);
        // MREMAP_DONTUNMAP leaves the old range unlocked, the new locked.
        let how = Remap {
            may_move: true,
            fixed: true,
            keep_old: true,
            new_addr: GuestAddr(0x90000),
        };
        space
            .remap_shared(GuestAddr(0x50000), 3 * PAGE_SIZE, 3 * PAGE_SIZE, how)
            .unwrap();
        assert!(space.first_locked(GuestAddr(0x50000), 0x53000).is_none());
        assert_eq!(space.locked_pages_in(GuestAddr(0x90000), 0x93000), 3);
        // MCL_FUTURE locks what is mapped next; munlockall none.
        space.lock_all(None, Some(Lock::Populated));
        space
            .map(
                Some(GuestAddr(0xa0000)),
                PAGE_SIZE,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert_eq!(space.locked_pages(), 4);
        space.lock_all(Some(None), None);
        assert_eq!(space.locked_pages(), 0);
    }

    #[test]
    fn a_child_gets_the_page_tables_linux_copies() {
        let mut space = AddressSpace::new();
        let map = |space: &mut AddressSpace, at: u64, prot: Prot| {
            space
                .map(Some(GuestAddr(at)), PAGE_SIZE, prot, MappingKind::Anonymous)
                .unwrap();
        };
        // Written, only read, shared, and shared with guards once.
        map(&mut space, 0x50000, Prot::READ_WRITE);
        map(&mut space, 0x60000, Prot::READ_WRITE);
        map(&mut space, 0x70000, Prot::READ_WRITE);
        map(&mut space, 0x80000, Prot::READ_WRITE);
        for at in [0x70000, 0x80000] {
            space
                .share_pages(GuestAddr(at), PAGE_SIZE, &SharedPages::new(), 0, true)
                .unwrap();
        }
        space.write_u64(GuestAddr(0x50000), 1).unwrap();
        space.mark_written(GuestAddr(0x50000), 8);
        space.read_u64(GuestAddr(0x60000)).unwrap();
        space.write_u64(GuestAddr(0x70000), 3).unwrap();
        space.guard(GuestAddr(0x80000), 0x81000, true).unwrap();
        space.guard(GuestAddr(0x80000), 0x81000, false).unwrap();
        space.write_u64(GuestAddr(0x80000), 4).unwrap();
        assert_eq!(space.page_state(GuestAddr(0x60000)), Some(PageState::Zero));
        let child = space.fork();
        let states: Vec<_> = [0x50000, 0x60000, 0x70000, 0x80000]
            .map(|at| child.page_state(GuestAddr(at)))
            .into();
        assert_eq!(
            states,
            vec![
                Some(PageState::Present),
                Some(PageState::Absent),
                Some(PageState::Absent),
                Some(PageState::Present)
            ]
        );
        // What the child lost a fault brings back.
        assert_eq!(child.read_u64(GuestAddr(0x70000)).unwrap(), 3);
        assert_eq!(child.read_u64(GuestAddr(0x60000)).unwrap(), 0);
        assert_eq!(child.read_u64(GuestAddr(0x50000)).unwrap(), 1);
        // The parent keeps its own.
        assert_eq!(
            space.page_state(GuestAddr(0x70000)),
            Some(PageState::Present)
        );
    }

    #[test]
    fn guards_fault_and_follow_the_page_tables() {
        let space = space_with(0x50000, 6 * PAGE_SIZE, Prot::READ_WRITE);
        let at = |n: u64| GuestAddr(0x50000 + n * PAGE_SIZE);
        let end = |n: u64| 0x50000 + n * PAGE_SIZE;
        for n in 0..6 {
            space.write_u64(at(n), n + 1).unwrap();
        }
        space.guard(at(1), end(3), true).unwrap();
        // A guard page faults as no mapping would, for any access, and
        // splits no VMA.
        for n in [1, 2] {
            let fault = space.read_u64(at(n)).unwrap_err();
            assert!(!fault.mapped && !fault.present, "{fault:?}");
            assert!(space.write_u64(at(n), 9).is_err());
            assert!(space.fetch(at(n), &mut [0]).is_err());
        }
        assert_eq!(space.mappings().count(), 1);
        assert!(space.has_guards(at(2), end(3)));
        assert!(!space.has_guards(at(3), end(6)));
        // Installing again keeps them; MADV_DONTNEED leaves them.
        space.guard(at(2), end(4), true).unwrap();
        space.discard_shared(at(0), 6 * PAGE_SIZE).unwrap();
        assert!(space.read_u64(at(3)).is_err());
        assert_eq!(space.read_u64(at(0)).unwrap(), 0);
        // Removing one gives back a page without contents.
        space.guard(at(3), end(4), false).unwrap();
        assert_eq!(space.read_u64(at(3)).unwrap(), 0);
        assert!(space.read_u64(at(2)).is_err());
        // A fork copies them; a wiped mapping drops them in the child.
        let child = space.fork();
        assert!(child.read_u64(at(1)).is_err());
        assert_eq!(child.read_u64(at(3)).unwrap(), 0);
        space
            .advise_flags(at(0), end(3), FlagAdvice::WipeOnFork)
            .unwrap();
        let wiped = space.fork();
        assert_eq!(wiped.read_u64(at(1)).unwrap(), 0);
        assert!(space.read_u64(at(1)).is_err());
        // mremap moves them with the pages, and DONTUNMAP leaves none.
        let mut moving = space_with(0x80000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        moving.guard(GuestAddr(0x81000), 0x82000, true).unwrap();
        let how = Remap {
            may_move: true,
            fixed: true,
            keep_old: true,
            new_addr: GuestAddr(0x90000),
        };
        let to = moving
            .remap_shared(GuestAddr(0x80000), 2 * PAGE_SIZE, 2 * PAGE_SIZE, how)
            .unwrap();
        assert_eq!(to, GuestAddr(0x90000));
        assert!(moving.read_u64(GuestAddr(0x91000)).is_err());
        assert_eq!(moving.read_u64(GuestAddr(0x81000)).unwrap(), 0);
        // munmap takes them out: a new mapping there has none.
        moving.unmap(GuestAddr(0x90000), 2 * PAGE_SIZE).unwrap();
        moving
            .map(
                Some(GuestAddr(0x90000)),
                2 * PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert_eq!(moving.read_u64(GuestAddr(0x91000)).unwrap(), 0);
        // A hole is ENOMEM once the rest has its guards.
        moving.unmap(GuestAddr(0x90000), PAGE_SIZE).unwrap();
        assert_eq!(
            moving.guard(GuestAddr(0x90000), 0x92000, true),
            Err(Errno::ENOMEM)
        );
        assert!(moving.read_u64(GuestAddr(0x91000)).is_err());
    }

    #[test]
    fn flag_advice_stops_at_a_vma_that_refuses_it_and_reports_holes_last() {
        let mut space = space_with(0x50000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        let at = |n: u64| GuestAddr(0x50000 + n * PAGE_SIZE);
        space
            .map(Some(at(3)), PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        // The hole at page 2 is reported after the rest took the advice.
        assert_eq!(
            space.advise_flags(at(0), 0x50000 + 4 * PAGE_SIZE, FlagAdvice::DontDump),
            Err(Errno::ENOMEM)
        );
        assert!(space.mappings().all(|m| m.dont_dump));
        // A file's VMA refuses MADV_WIPEONFORK, after the ones before it.
        assert_eq!(
            space.advise_flags(at(0), 0x50000 + 4 * PAGE_SIZE, FlagAdvice::WipeOnFork),
            Err(Errno::EINVAL)
        );
        let wiped: Vec<_> = space.mappings().map(|m| m.wipe_on_fork).collect();
        assert_eq!(wiped, vec![true, false]);
        // So does a loaded program's segment.
        space
            .map(
                Some(at(8)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::ElfSegment,
            )
            .unwrap();
        assert_eq!(
            space.advise_flags(at(8), 0x50000 + 9 * PAGE_SIZE, FlagAdvice::WipeOnFork),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn mremap_of_a_range_whose_later_page_is_sealed_moves_nothing() {
        let space = space_with(0x50000, 2 * PAGE_SIZE, Prot::READ_WRITE);
        let at = |n: u64| GuestAddr(0x50000 + n * PAGE_SIZE);
        space.write_u64(at(0), 1).unwrap();
        space.write_u64(at(1), 2).unwrap();
        space.seal_shared(at(1), PAGE_SIZE).unwrap();
        let before: Vec<_> = space.mappings().collect();
        let how = |fixed: bool, to: u64| Remap {
            may_move: true,
            fixed,
            keep_old: false,
            new_addr: GuestAddr(to),
        };
        // The sealed page is a VMA of its own, so the range runs past the
        // first one (EFAULT, as Linux's `vma_lookup` finds the first).
        assert_eq!(
            space.remap_shared(at(0), 2 * PAGE_SIZE, 4 * PAGE_SIZE, how(false, 0)),
            Err(Errno::EFAULT)
        );
        // A shrink that moves cannot unmap the sealed tail (EPERM).
        assert_eq!(
            space.remap_shared(at(0), 2 * PAGE_SIZE, PAGE_SIZE, how(true, 0x80000)),
            Err(Errno::EPERM)
        );
        // Nothing moved, and nothing was emptied.
        let after: Vec<_> = space.mappings().filter(|m| m.start.0 < 0x60000).collect();
        assert_eq!(after, before);
        assert_eq!(space.read_u64(at(0)).unwrap(), 1);
        assert_eq!(space.read_u64(at(1)).unwrap(), 2);
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
        space.fetch(GuestAddr(0x10000), &mut [0]).unwrap();
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

    /// A file whose size can change, each byte its offset modulo 251.
    struct Resizable(Arc<AtomicU64>);
    impl PageSource for Resizable {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
            Pattern(self.0.load(Ordering::SeqCst)).read_at(offset, buf)
        }
        fn size(&self) -> Option<u64> {
            Some(self.0.load(Ordering::SeqCst))
        }
    }
    fn pattern(offset: u64) -> u8 {
        (offset % 251) as u8
    }

    #[test]
    fn a_private_file_mapping_shows_the_page_cache_until_it_writes() {
        let file: Arc<dyn PageSource> = Arc::new(Pattern(2 * PAGE_SIZE));
        let pages = SharedPages::new().with_source(Arc::clone(&file));
        let parent = AddressSpace::new();
        let at = parent
            .map_shared(
                None,
                2 * PAGE_SIZE,
                Prot::READ_WRITE.union(Prot::EXEC),
                MappingKind::File,
            )
            .unwrap();
        parent
            .back_with_cache(at, 2 * PAGE_SIZE, &pages, 0)
            .unwrap();
        assert_eq!(byte(&parent, at.0 + 3), 3);
        let child = parent.fork();
        // The cache's changes show in both, and change the code.
        let code = parent.code_generation();
        pages.store(3, b"c");
        assert_ne!(parent.code_generation(), code);
        assert_eq!(byte(&parent, at.0 + 3), b'c');
        assert_eq!(byte(&child, at.0 + 3), b'c');
        // A write copies the page for the space that made it alone.
        child.write(GuestAddr(at.0 + 4), b"w").unwrap();
        pages.store(3, b"d");
        assert_eq!(byte(&child, at.0 + 3), b'c');
        assert_eq!(byte(&child, at.0 + 4), b'w');
        assert_eq!(byte(&parent, at.0 + 3), b'd');
        assert_eq!(byte(&parent, at.0 + 4), 4);
        assert_eq!(byte(&child, at.0 + PAGE_SIZE), pattern(PAGE_SIZE));
        let mut written = Vec::new();
        pages
            .write_back(|key, _| {
                written.push(key);
                Ok(())
            })
            .unwrap();
        assert!(written.is_empty(), "the cache stays clean");
    }

    #[test]
    fn a_file_mapping_ends_with_its_file_and_reads_it_on_first_touch() {
        let size = Arc::new(AtomicU64::new(PAGE_SIZE + 10));
        let file: Arc<dyn PageSource> = Arc::new(Resizable(Arc::clone(&size)));
        let private = AddressSpace::new();
        let at = private
            .map_shared(None, 3 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        private
            .back_with_file(at, 3 * PAGE_SIZE, Arc::clone(&file), 0)
            .unwrap();
        let shared = AddressSpace::new();
        let pages = SharedPages::new().with_source(Arc::clone(&file));
        let other = shared
            .map_shared(None, 3 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        shared
            .share_pages(other, 3 * PAGE_SIZE, &pages, 0, true)
            .unwrap();
        let mut b = [0];
        for (space, at) in [(&private, at), (&shared, other)] {
            size.store(PAGE_SIZE + 10, Ordering::SeqCst);
            // Untouched pages are read from the file, the last one in part.
            assert_eq!(byte(space, at.0 + 7), 7);
            assert_eq!(byte(space, at.0 + PAGE_SIZE + 9), pattern(PAGE_SIZE + 9));
            assert_eq!(byte(space, at.0 + PAGE_SIZE + 10), 0);
            // A page wholly past the end is a bus error, also for a write.
            let past = GuestAddr(at.0 + 2 * PAGE_SIZE);
            let fault = space.read(past, &mut b).unwrap_err();
            assert!(fault.bus && fault.mapped && !fault.write);
            assert!(space.write(past, b"x").unwrap_err().bus);
            // Grown, the file shows there; shrunk, even a page read before
            // is past the end.
            size.store(3 * PAGE_SIZE, Ordering::SeqCst);
            assert_eq!(byte(space, past.0 + 1), pattern(2 * PAGE_SIZE + 1));
            size.store(PAGE_SIZE, Ordering::SeqCst);
            assert!(
                space
                    .read(GuestAddr(at.0 + PAGE_SIZE), &mut b)
                    .unwrap_err()
                    .bus
            );
            assert_eq!(byte(space, at.0 + 7), 7);
            // A mapping that mremap grows reads the file further on.
            size.store(4 * PAGE_SIZE, Ordering::SeqCst);
            let grown = space
                .remap_shared(at, 3 * PAGE_SIZE, 4 * PAGE_SIZE, MOVE)
                .unwrap();
            assert_eq!(grown, at, "grown in place");
            // So does one it moves to grow, with a mapping in the way.
            size.store(6 * PAGE_SIZE, Ordering::SeqCst);
            let after = GuestAddr(grown.0 + 4 * PAGE_SIZE);
            space
                .map_shared(Some(after), PAGE_SIZE, Prot::READ, MappingKind::Anonymous)
                .unwrap();
            let moved = space
                .remap_shared(grown, 4 * PAGE_SIZE, 6 * PAGE_SIZE, MOVE)
                .unwrap();
            assert_ne!(moved, grown, "moved to grow");
            assert_eq!(byte(space, moved.0 + 7), 7);
            assert_eq!(
                byte(space, moved.0 + 5 * PAGE_SIZE + 3),
                pattern(5 * PAGE_SIZE + 3)
            );
            size.store(5 * PAGE_SIZE, Ordering::SeqCst);
            assert!(
                space
                    .read(GuestAddr(moved.0 + 5 * PAGE_SIZE), &mut b)
                    .unwrap_err()
                    .bus
            );
            size.store(4 * PAGE_SIZE, Ordering::SeqCst);
            let grown = moved;
            assert_eq!(
                byte(space, grown.0 + 3 * PAGE_SIZE + 2),
                pattern(3 * PAGE_SIZE + 2)
            );
        }
        // Anonymous memory has no end.
        let anonymous = private
            .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        assert_eq!(byte(&private, anonymous.0), 0);
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
        let child = space.fork();
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
        let child = space.fork();
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
    fn shared_pages_are_one_memory_across_mappings_and_forks() {
        let pages = SharedPages::new();
        pages.fill(0x3000, b"file", None).unwrap();
        pages.fill(0x3000, b"kept", None).unwrap(); // has contents already
        let space = AddressSpace::new();
        let at = space
            .map_shared(None, 2 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        // The mapping shows the pages from key 0x2000 on.
        space
            .share_pages(at, 2 * PAGE_SIZE, &pages, 0x2000, true)
            .unwrap();
        assert_eq!(byte(&space, at.0 + PAGE_SIZE), b'f');
        let child = space.fork();
        child.write(GuestAddr(at.0 + PAGE_SIZE + 1), b"I").unwrap();
        assert_eq!(byte(&space, at.0 + PAGE_SIZE + 1), b'I');
        // Only stores make pages dirty, and taking them makes them clean.
        let mut taken = Vec::new();
        pages
            .write_back(|key, page| {
                taken.push((key, page[..4].to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(taken, [(0x3000, b"fIle".to_vec())]);
        pages.write_back(|_, _| panic!("nothing is dirty")).unwrap();
        // A store to the file reaches the frames, and so does a zeroing.
        pages.store(0x3002, b"LE");
        assert_eq!(byte(&child, at.0 + PAGE_SIZE + 3), b'E');
        pages.zero(0x3003, u64::MAX);
        assert_eq!(byte(&child, at.0 + PAGE_SIZE + 3), 0);
        assert_eq!(byte(&child, at.0 + PAGE_SIZE + 2), b'L');
        // A page without contents is left for the file to fill.
        pages.store(0x8000, b"x");
        assert!(!pages.contains(0x8000));
        pages.store(0x2000, b"y");
        assert_eq!(byte(&space, at.0), 0);
        // A failed write-back leaves the page dirty.
        space.write(at, b"z").unwrap();
        assert_eq!(pages.write_back(|_, _| Err(Errno::EIO)), Err(Errno::EIO));
        let mut keys = Vec::new();
        pages
            .write_back(|key, _| {
                keys.push(key);
                Ok(())
            })
            .unwrap();
        assert_eq!(keys, [0x2000]);
    }

    #[test]
    fn a_shared_file_mapping_becomes_writable_only_when_it_may() {
        let space = AddressSpace::new();
        let pages = SharedPages::new();
        for may_write in [true, false] {
            let at = space
                .map_shared(None, PAGE_SIZE, Prot::READ, MappingKind::File)
                .unwrap();
            space
                .share_pages(at, PAGE_SIZE, &pages, 0, may_write)
                .unwrap();
            let result = space.protect_shared(at, PAGE_SIZE, Prot::READ_WRITE);
            assert_eq!(
                result,
                if may_write {
                    Ok(())
                } else {
                    Err(Errno::EACCES)
                }
            );
        }
        // Only a whole new mapping can be shared.
        let at = space
            .map_shared(None, 2 * PAGE_SIZE, Prot::READ, MappingKind::File)
            .unwrap();
        assert_eq!(
            space.share_pages(at, PAGE_SIZE, &pages, 0, true),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn remap_grows_a_file_mapping_and_covers_finds_holes() {
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
            Ok(GuestAddr(0x10000))
        );
        assert!(
            space
                .remap_shared(GuestAddr(0x10000), 8192, 4096, MOVE)
                .is_ok()
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

    #[test]
    fn a_vma_is_written_once_a_page_of_it_is() {
        let written = |space: &AddressSpace, at: u64| space.core_state(GuestAddr(at)).written;
        let space = space_with(0x10000, 4 * PAGE_SIZE, Prot::READ_WRITE);
        let mut byte = [0u8];
        space.read(GuestAddr(0x11000), &mut byte).unwrap();
        assert!(!written(&space, 0x10000), "reading writes nothing");
        space.write_initial(GuestAddr(0x10000), &[1]).unwrap();
        assert!(
            !written(&space, 0x10000),
            "the loader's writes are not the process's"
        );
        space.write(GuestAddr(0x13000), &[1]).unwrap();
        assert!(written(&space, 0x10000), "the whole VMA");
        // A split keeps it in both parts, as Linux keeps the anon_vma.
        space
            .protect_shared(GuestAddr(0x10000), PAGE_SIZE, Prot::READ)
            .unwrap();
        assert!(written(&space, 0x10000) && written(&space, 0x13000));
        // So does fork.
        assert!(written(&space.fork(), 0x10000));
        // A new mapping that merges with a written VMA is part of it; one
        // that does not stays unwritten.
        space
            .map_shared(
                Some(GuestAddr(0x14000)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert!(written(&space, 0x14000));
        space
            .map_shared(
                Some(GuestAddr(0x16000)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        assert!(!written(&space, 0x16000));
        // A shared mapping is not marked.
        space
            .map_shared(
                Some(GuestAddr(0x20000)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        space.mark_shared(GuestAddr(0x20000), PAGE_SIZE).unwrap();
        space.write(GuestAddr(0x20000), &[1]).unwrap();
        assert!(!written(&space, 0x20000) && space.core_state(GuestAddr(0x20000)).shared);
        space.mark_written(GuestAddr(0x16000), PAGE_SIZE);
        assert!(written(&space, 0x16000));
    }

    #[test]
    fn a_vma_spans_the_adjacent_mappings_linux_merges() {
        let mut space = AddressSpace::new();
        for (at, prot) in [
            (0x10000, Prot::READ_WRITE),
            (0x11000, Prot::READ_WRITE),
            (0x12000, Prot::READ),
        ] {
            space
                .map(Some(GuestAddr(at)), PAGE_SIZE, prot, MappingKind::Anonymous)
                .unwrap();
        }
        let whole = Some((GuestAddr(0x10000), 2 * PAGE_SIZE));
        assert_eq!(space.vma_at(GuestAddr(0x10000)), whole);
        assert_eq!(space.vma_at(GuestAddr(0x11000)), whole);
        // Another protection is another VMA.
        assert_eq!(
            space.vma_at(GuestAddr(0x12000)),
            Some((GuestAddr(0x12000), PAGE_SIZE))
        );
        assert_eq!(space.vma_at(GuestAddr(0x13000)), None);
    }

    #[test]
    fn adjacent_private_file_mappings_are_one_vma_only_of_one_file_in_order() {
        let written = |space: &AddressSpace, at: u64| space.core_state(GuestAddr(at)).written;
        let one: Arc<dyn PageSource> = Arc::new(Pattern(8 * PAGE_SIZE));
        let other: Arc<dyn PageSource> = Arc::new(Pattern(8 * PAGE_SIZE));
        let space = AddressSpace::new();
        // At 0x10000 page 0 of `one`; after it page 1 of `one` (the same
        // VMA), page 3 of `one` (not in order) and page 4 of `other`.
        for (at, source, offset) in [
            (0x10000, &one, 0),
            (0x11000, &one, PAGE_SIZE),
            (0x12000, &one, 3 * PAGE_SIZE),
            (0x13000, &other, 4 * PAGE_SIZE),
        ] {
            space
                .map_shared(
                    Some(GuestAddr(at)),
                    PAGE_SIZE,
                    Prot::READ_WRITE,
                    MappingKind::File,
                )
                .unwrap();
            space
                .back_with_file(GuestAddr(at), PAGE_SIZE, Arc::clone(source), offset)
                .unwrap();
        }
        space.write(GuestAddr(0x10000), &[1]).unwrap();
        assert!(written(&space, 0x10000) && written(&space, 0x11000));
        assert!(!written(&space, 0x12000) && !written(&space, 0x13000));
        space.write(GuestAddr(0x12000), &[1]).unwrap();
        assert!(!written(&space, 0x13000));
    }

    /// A file that no name links, as a memfd or one unlinked since.
    struct Unlinked;
    impl PageSource for Unlinked {
        fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, Errno> {
            Ok(0)
        }
        fn linked(&self) -> bool {
            false
        }
    }

    #[test]
    fn a_shared_mapping_is_linked_only_by_a_file_with_a_name() {
        let mut space = AddressSpace::new();
        let map = |space: &mut AddressSpace, source: Option<Arc<dyn PageSource>>| {
            let kind = if source.is_some() {
                MappingKind::File
            } else {
                MappingKind::Anonymous
            };
            let at = space.map_shared(None, PAGE_SIZE, Prot::READ, kind).unwrap();
            match source {
                Some(source) => {
                    let pages = SharedPages::new().with_source(source);
                    space.share_pages(at, PAGE_SIZE, &pages, 0, false).unwrap();
                }
                None => space.mark_shared(at, PAGE_SIZE).unwrap(),
            }
            space.core_state(at)
        };
        let named = map(&mut space, Some(Arc::new(Pattern(PAGE_SIZE))));
        assert!(named.shared && named.linked);
        let unlinked = map(&mut space, Some(Arc::new(Unlinked)));
        assert!(unlinked.shared && !unlinked.linked);
        let anonymous = map(&mut space, None);
        assert!(anonymous.shared && !anonymous.linked);
        // A private file mapping is not shared, and so not linked either.
        let private = space
            .map(None, PAGE_SIZE, Prot::READ, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(Arc::new(Pattern(PAGE_SIZE)));
        space
            .back_with_cache(private, PAGE_SIZE, &pages, 0)
            .unwrap();
        assert!(!space.core_state(private).linked);
    }

    #[test]
    fn a_mapping_names_its_file_and_where_it_lies_in_it() {
        struct Named;
        impl PageSource for Named {
            fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
                Ok(buf.len())
            }
            fn name(&self) -> Option<Vec<u8>> {
                Some(b"/data".to_vec())
            }
        }
        let mut space = AddressSpace::new();
        let file = space
            .map(None, 2 * PAGE_SIZE, Prot::READ, MappingKind::File)
            .unwrap();
        space
            .back_with_file(file, 2 * PAGE_SIZE, Arc::new(Named), 3 * PAGE_SIZE)
            .unwrap();
        let found = space.mapped_file(GuestAddr(file.0 + PAGE_SIZE)).unwrap();
        assert_eq!(found.name.as_deref(), Some(&b"/data"[..]));
        assert!(found.source);
        assert_eq!(found.offset, 4 * PAGE_SIZE);
        // Shared anonymous memory counts from where it was made, through a
        // move, and keeps its contents.
        let shared = space
            .map_shared(
                None,
                2 * PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        space.mark_shared(shared, 2 * PAGE_SIZE).unwrap();
        space.write(GuestAddr(shared.0 + PAGE_SIZE), &[7]).unwrap();
        let moved = space
            .remap_shared(
                shared,
                2 * PAGE_SIZE,
                2 * PAGE_SIZE,
                Remap {
                    may_move: true,
                    fixed: true,
                    new_addr: GuestAddr(shared.0 - 16 * PAGE_SIZE),
                    ..Remap::default()
                },
            )
            .unwrap();
        let found = space.mapped_file(GuestAddr(moved.0 + PAGE_SIZE)).unwrap();
        assert_eq!(
            (found.name, found.source, found.offset),
            (None, false, PAGE_SIZE)
        );
        let mut byte = [0];
        space
            .read(GuestAddr(moved.0 + PAGE_SIZE), &mut byte)
            .unwrap();
        assert_eq!(byte, [7]);
        let private = space
            .map(None, PAGE_SIZE, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        assert_eq!(space.mapped_file(private), None);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod instructions_tests;
