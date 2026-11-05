//! ELF loader for paludarium.
//!
//! Loads x86-64 executables (`ET_EXEC` and `ET_DYN`), and the interpreter one
//! asks for with `PT_INTERP`, into a guest address space and builds the initial
//! stack with argc, argv, envp and the auxiliary vector exactly as Linux lays
//! them out. Static-pie images relocate themselves (musl's start code), so
//! the loader does not apply relocations.
#![forbid(unsafe_code)]

pub mod elf;
pub mod testing;

use paludarium_mmu::{AddressSpace, MappingKind, PageSource, Prot};
use paludarium_types::{Errno, Error, ErrorKind, GuestAddr, PAGE_SIZE, USER_ADDRESS_LIMIT};
use paludarium_vfs::FileSystem;
use std::sync::Arc;

pub use elf::{ElfInfo, MAX_LOAD_SIZE, ProgramHeader, parse};

/// Load base of static-pie (`ET_DYN`) programs.
pub const STATIC_PIE_BASE: u64 = 0x5555_5555_4000;

/// Exclusive top of the initial stack.
pub const STACK_TOP: u64 = 0x7fff_ffff_f000;

/// Size of the initial stack mapping: 8 MiB.
pub const STACK_SIZE: u64 = 8 << 20;

/// Lowest address a segment may occupy (Linux `mmap_min_addr`).
pub const MIN_SEGMENT_ADDR: u64 = 0x10000;

/// Space reserved for argument and environment strings: a quarter of the
/// stack, as Linux does.
pub const MAX_ARG_BYTES: u64 = STACK_SIZE / 4;

/// Values of the auxiliary vector entries the loader writes.
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_EXECFN: u64 = 31;
}

/// Why a program could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The path does not name a file.
    NotFound,
    /// The program's interpreter (`PT_INTERP`) cannot be run, for this reason.
    Interpreter(Errno),
    /// The file is not a valid x86-64 ELF executable; the reason is fixed text.
    Malformed(&'static str),
    /// The image or the arguments are too large.
    TooLarge,
    /// Mapping the image failed.
    Errno(Errno),
}

impl From<LoadError> for Error {
    fn from(e: LoadError) -> Self {
        let message = match e {
            LoadError::NotFound => "program not found",
            LoadError::Interpreter(_) => "the program's interpreter cannot be run",
            LoadError::Malformed(reason) => reason,
            LoadError::TooLarge => "program or arguments too large",
            LoadError::Errno(_) => "program segments cannot be mapped",
        };
        Error::new(ErrorKind::InvalidProgram, message)
    }
}

/// The result of loading a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    /// Where execution starts: the interpreter's entry if it has one.
    pub entry_point: GuestAddr,
    /// The program's own entry (`AT_ENTRY`).
    pub program_entry: GuestAddr,
    /// Where the interpreter is loaded (`AT_BASE`), or 0 with none.
    pub interpreter_base: u64,
    pub program_header_address: GuestAddr,
    pub program_header_count: u16,
    pub initial_stack_pointer: GuestAddr,
    pub initial_break: GuestAddr,
    pub load_base: GuestAddr,
}

/// Decides about the interpreter a program asks for by name: returns the path
/// to read it from, or why it cannot run.
pub type InterpreterCheck<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>, Errno>;

/// Inputs of the initial stack.
#[derive(Clone, Copy, Debug)]
pub struct StartInfo<'a> {
    pub argv: &'a [Vec<u8>],
    pub envp: &'a [Vec<u8>],
    /// The program path as the guest sees it (`AT_EXECFN`).
    pub execfn: &'a [u8],
    /// 16 bytes from the host's random source (`AT_RANDOM`).
    pub random: [u8; 16],
    /// The real and effective user and group IDs the program runs with
    /// (`AT_UID`, `AT_EUID`, `AT_GID`, `AT_EGID`).
    pub ids: [u32; 4],
    /// Whether the exec is secure (`AT_SECURE`): the program runs with
    /// other effective IDs than its real ones.
    pub secure: bool,
}

fn prot_of(flags: u32) -> Prot {
    let mut prot = Prot::NONE;
    if flags & elf::PF_R != 0 {
        prot = prot.union(Prot::READ);
    }
    if flags & elf::PF_W != 0 {
        prot = prot.union(Prot::WRITE);
    }
    if flags & elf::PF_X != 0 {
        prot = prot.union(Prot::EXEC);
    }
    prot
}

/// The file pages of a segment as the executable holds them, which
/// `MADV_DONTNEED` reads the segment's pages from again: a part of the
/// executable's loaded span ([`loaded_span`]), which its segments share, or
/// the segment's data alone.
enum SegmentImage {
    File(Arc<[u8]>, std::ops::Range<usize>),
    Data(Vec<u8>),
}
impl SegmentImage {
    fn bytes(&self) -> &[u8] {
        match self {
            SegmentImage::File(file, range) => file.get(range.clone()).unwrap_or_default(),
            SegmentImage::Data(data) => data,
        }
    }
}
/// A segment's file pages where they lie in the executable, which a core's
/// `NT_FILE` note names by its path.
struct SegmentFile {
    image: SegmentImage,
    /// The file offset of the segment's first page.
    offset: u64,
    name: Option<Arc<[u8]>>,
    /// The device and inode of the file.
    identity: (u64, u64),
}
impl PageSource for SegmentFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let rest = offset
            .checked_sub(self.offset)
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| self.image.bytes().get(at..))
            .unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn name(&self) -> Option<Vec<u8>> {
        self.name.as_deref().map(<[u8]>::to_vec)
    }
    fn identity(&self) -> (u64, u64) {
        self.identity
    }
}

/// Places the `PT_LOAD` segments, as Linux's binfmt_elf does: the pages that
/// hold file data are a private file mapping, and the rest of the segment
/// (bss) anonymous memory. A segment remembers its file pages, so that
/// `MADV_DONTNEED` reads them again, also a read-only one that `mprotect`
/// made writable and that was written, at its offset in the file `name`.
/// Returns the load base and the end of the highest segment.
fn map_segments(
    bytes: &[u8],
    name: Option<&[u8]>,
    identity: (u64, u64),
    info: &ElfInfo,
    mem: &mut AddressSpace,
    dynamic_base: u64,
) -> Result<(u64, u64), LoadError> {
    let base = if info.kind == elf::ET_DYN {
        dynamic_base
    } else {
        0
    };
    let mut highest = 0u64;
    let file = loaded_span(bytes, info);
    let name: Option<Arc<[u8]>> = name.map(Arc::from);
    for h in info.loads() {
        let start = base
            .checked_add(h.vaddr)
            .ok_or(LoadError::Malformed("segment address overflow"))?;
        let end = start
            .checked_add(h.memsz)
            .ok_or(LoadError::Malformed("segment address overflow"))?;
        if start < MIN_SEGMENT_ADDR || end > USER_ADDRESS_LIMIT {
            return Err(LoadError::Malformed("segment outside the address space"));
        }
        let page_start = GuestAddr(start).page_align_down();
        let page_end = GuestAddr(end)
            .page_align_up()
            .ok_or(LoadError::Malformed("segment address overflow"))?;
        // The pages holding file data; a segment without any is all bss.
        let file_end = if h.filesz == 0 {
            page_start
        } else {
            GuestAddr(start + h.filesz)
                .page_align_up()
                .ok_or(LoadError::Malformed("segment address overflow"))?
        };
        let map = |mem: &mut AddressSpace, from: GuestAddr, to: GuestAddr, kind| {
            if to.0 <= from.0 {
                return Ok(());
            }
            mem.map(Some(from), to.0 - from.0, prot_of(h.flags), kind)
                .map(|_| ())
                .map_err(|e| {
                    if e == Errno::EEXIST {
                        LoadError::Malformed("overlapping segments")
                    } else {
                        LoadError::Errno(e)
                    }
                })
        };
        map(mem, page_start, file_end, MappingKind::ElfSegment)?;
        map(mem, file_end, page_end, MappingKind::Anonymous)?;
        let data = if h.filesz == 0 {
            &[]
        } else {
            let from = usize::try_from(h.offset).map_err(|_| LoadError::TooLarge)?;
            let len = usize::try_from(h.filesz).map_err(|_| LoadError::TooLarge)?;
            bytes
                .get(from..from + len)
                .ok_or(LoadError::Malformed("segment out of range"))?
        };
        // The rest of the segment (bss) stays zero: fresh pages read as zero.
        mem.write_initial(GuestAddr(start), data)
            .map_err(|_| LoadError::Errno(Errno::EFAULT))?;
        if file_end.0 > page_start.0 {
            let head = start - page_start.0;
            // Where Linux maps the segment's first page from.
            let offset = h.offset.saturating_sub(head) & !(PAGE_SIZE - 1);
            let source = SegmentFile {
                image: file_pages(&file, h, head, data),
                offset,
                name: name.clone(),
                identity,
            };
            mem.back_with_file(
                page_start,
                file_end.0 - page_start.0,
                Arc::new(source),
                offset,
            )
            .map_err(LoadError::Errno)?;
        }
        highest = highest.max(end);
    }
    Ok((base, highest))
}

/// The part of the executable that its segments' file pages lie in, and its
/// offset in the file: the segments keep it to read again, without the
/// sections that no segment loads (symbols, debug information).
fn loaded_span(bytes: &[u8], info: &ElfInfo) -> (Arc<[u8]>, usize) {
    let page = PAGE_SIZE as usize;
    let (from, end) = info
        .loads()
        .filter(|h| h.filesz != 0)
        .filter_map(|h| {
            let offset = usize::try_from(h.offset).ok()?;
            let end = offset
                .checked_add(usize::try_from(h.filesz).ok()?)?
                .checked_next_multiple_of(page)?
                .min(bytes.len());
            Some((offset - offset % page, end))
        })
        .fold((usize::MAX, 0), |(from, end), (f, e)| {
            (from.min(f), end.max(e))
        });
    match bytes.get(from..end) {
        Some(span) => (Arc::from(span), from),
        None => (Arc::from(&[][..]), 0),
    }
}

/// What the file pages of a segment hold, from its first page: the file's own
/// pages when the segment starts as far into its page as into the file
/// (as `PT_LOAD` requires, and as Linux maps them, with what lies around the
/// data), else the data alone at its place.
fn file_pages(
    (span, at): &(Arc<[u8]>, usize),
    h: &ProgramHeader,
    head: u64,
    data: &[u8],
) -> SegmentImage {
    let head = usize::try_from(head).unwrap_or(0);
    // The file's pages, from the one the segment starts in to the one its
    // data ends in, cut at the end of the file.
    let own = (h.offset % PAGE_SIZE == head as u64)
        .then(|| usize::try_from(h.offset).ok())
        .flatten()
        .and_then(|offset| {
            let from = offset.checked_sub(head)?;
            let end = offset
                .checked_add(data.len())?
                .checked_next_multiple_of(PAGE_SIZE as usize)?
                .min(at + span.len());
            let range = from.checked_sub(*at)?..end.checked_sub(*at)?;
            span.get(range.clone()).map(|_| range)
        });
    match own {
        Some(range) => SegmentImage::File(Arc::clone(span), range),
        None => {
            let mut pages = vec![0; head + data.len()];
            pages[head..].copy_from_slice(data);
            SegmentImage::Data(pages)
        }
    }
}

/// Address of the program headers in guest memory (`AT_PHDR`).
fn phdr_address(info: &ElfInfo, base: u64) -> u64 {
    if let Some(h) = info.headers.iter().find(|h| h.kind == elf::PT_PHDR) {
        return base.wrapping_add(h.vaddr);
    }
    info.loads()
        .find(|h| info.phoff >= h.offset && info.phoff - h.offset < h.filesz)
        .map_or(0, |h| {
            base.wrapping_add(h.vaddr)
                .wrapping_add(info.phoff - h.offset)
        })
}

struct StackWriter<'a> {
    mem: &'a AddressSpace,
    sp: u64,
}

impl StackWriter<'_> {
    fn push_bytes(&mut self, data: &[u8]) -> Result<u64, LoadError> {
        let len = u64::try_from(data.len()).map_err(|_| LoadError::TooLarge)?;
        self.sp = self.sp.checked_sub(len).ok_or(LoadError::TooLarge)?;
        self.mem
            .write(GuestAddr(self.sp), data)
            .map_err(|_| LoadError::TooLarge)?;
        Ok(self.sp)
    }

    fn push_string(&mut self, s: &[u8]) -> Result<u64, LoadError> {
        self.push_bytes(&[0])?;
        self.push_bytes(s)
    }
}

/// Builds the initial stack. Returns the 16-byte aligned stack pointer,
/// which points at argc.
fn build_stack(
    mem: &mut AddressSpace,
    start: &StartInfo<'_>,
    image: &LoadedImage,
) -> Result<u64, LoadError> {
    let strings: u64 = start
        .argv
        .iter()
        .chain(start.envp)
        .map(|s| u64::try_from(s.len()).unwrap_or(u64::MAX).saturating_add(1))
        .fold(0u64, u64::saturating_add)
        .saturating_add(u64::try_from(start.execfn.len()).unwrap_or(u64::MAX));
    if strings > MAX_ARG_BYTES {
        return Err(LoadError::TooLarge);
    }
    let bottom = STACK_TOP - STACK_SIZE;
    mem.map(
        Some(GuestAddr(bottom)),
        STACK_SIZE,
        Prot::READ_WRITE,
        MappingKind::Stack,
    )
    .map_err(LoadError::Errno)?;

    let mut w = StackWriter {
        mem,
        sp: STACK_TOP - 8,
    };
    let execfn = w.push_string(start.execfn)?;
    let mut env_ptrs = Vec::with_capacity(start.envp.len());
    for s in start.envp.iter().rev() {
        env_ptrs.push(w.push_string(s)?);
    }
    env_ptrs.reverse();
    let mut arg_ptrs = Vec::with_capacity(start.argv.len());
    for s in start.argv.iter().rev() {
        arg_ptrs.push(w.push_string(s)?);
    }
    arg_ptrs.reverse();
    w.sp &= !15;
    let random = w.push_bytes(&start.random)?;

    use auxv::*;
    let aux: [(u64, u64); 17] = [
        (AT_PHDR, image.program_header_address.0),
        (AT_PHENT, elf::PHDR_SIZE),
        (AT_PHNUM, u64::from(image.program_header_count)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, image.interpreter_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, image.program_entry.0),
        (AT_UID, u64::from(start.ids[0])),
        (AT_EUID, u64::from(start.ids[1])),
        (AT_GID, u64::from(start.ids[2])),
        (AT_EGID, u64::from(start.ids[3])),
        (AT_SECURE, u64::from(start.secure)),
        (AT_CLKTCK, 100),
        (AT_HWCAP, 0),
        (AT_RANDOM, random),
        (AT_EXECFN, execfn),
        (AT_NULL, 0),
    ];
    let mut words: Vec<u64> = Vec::with_capacity(3 + arg_ptrs.len() + env_ptrs.len() + 34);
    words.push(u64::try_from(arg_ptrs.len()).map_err(|_| LoadError::TooLarge)?);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for (key, value) in aux {
        words.push(key);
        words.push(value);
    }
    w.sp &= !15;
    if words.len() % 2 == 1 {
        w.sp -= 8;
    }
    let bytes: Vec<u8> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
    w.push_bytes(&bytes)
}

/// Loads the program at `path` from `fs` into `mem` and builds its stack.
pub fn load(
    fs: &dyn FileSystem,
    path: &[u8],
    start: &StartInfo<'_>,
    mem: &mut AddressSpace,
) -> Result<LoadedImage, LoadError> {
    load_with(fs, path, start, mem, &mut |name| {
        paludarium_vfs::normalize_path(name)
    })
}

/// Loads the program at `path`, as [`load`], with `interpreter` deciding about
/// an interpreter it asks for by name: what may run it, and the path to read
/// it from, as Linux's `open_exec` of it from the caller's directory.
pub fn load_with(
    fs: &dyn FileSystem,
    path: &[u8],
    start: &StartInfo<'_>,
    mem: &mut AddressSpace,
    interpreter: InterpreterCheck<'_>,
) -> Result<LoadedImage, LoadError> {
    let bytes = fs.read_file(path).map_err(|e| {
        if e == Errno::ENOENT || e == Errno::EISDIR || e == Errno::ENOTDIR {
            LoadError::NotFound
        } else {
            LoadError::Errno(e)
        }
    })?;
    // Linux names the file by its plain absolute path.
    let name = paludarium_vfs::normalize_path(path).unwrap_or_else(|_| path.to_vec());
    load_image(&bytes, Some(&name), start, mem, Some((fs, interpreter)))
}

/// Loads an ELF image from memory.
pub fn load_bytes(
    bytes: &[u8],
    start: &StartInfo<'_>,
    mem: &mut AddressSpace,
) -> Result<LoadedImage, LoadError> {
    load_image(bytes, None, start, mem, None)
}

/// The file of an interpreter, as Linux's `load_elf_interp` takes it: a read
/// that fails is that error, one too short for an ELF header is EIO, and
/// anything but an x86-64 ELF program is `ELIBBAD`. Its own `PT_INTERP`, if
/// any, does not count.
fn read_interpreter(fs: &dyn FileSystem, path: &[u8]) -> Result<(Arc<[u8]>, ElfInfo), LoadError> {
    const EIO: Errno = Errno(5);
    const ELIBBAD: Errno = Errno(80);
    const ELF_HEADER: usize = 64;
    let bytes = fs.read_file(path).map_err(LoadError::Interpreter)?;
    if bytes.len() < ELF_HEADER {
        return Err(LoadError::Interpreter(EIO));
    }
    let info = elf::parse(&bytes).map_err(|_| LoadError::Interpreter(ELIBBAD))?;
    Ok((bytes, info))
}

/// Where a position-independent interpreter goes: right under `top`, at its
/// alignment.
fn interpreter_base(info: &ElfInfo, top: u64) -> Result<u64, LoadError> {
    let too_large = LoadError::Interpreter(Errno(12));
    let span = info
        .loads()
        .try_fold(0u64, |end, h| Some(end.max(h.vaddr.checked_add(h.memsz)?)))
        .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
        .ok_or(too_large)?;
    let align = info
        .loads()
        .map(|h| h.align)
        .fold(PAGE_SIZE, u64::max)
        .next_power_of_two();
    Ok(top.checked_sub(span).ok_or(too_large)? & !(align - 1))
}

/// Loads an ELF image, read from the file `name` if it has one.
fn load_image(
    bytes: &[u8],
    name: Option<&[u8]>,
    start: &StartInfo<'_>,
    mem: &mut AddressSpace,
    mut files: Option<(&dyn FileSystem, InterpreterCheck<'_>)>,
) -> Result<LoadedImage, LoadError> {
    let info = elf::parse(bytes)?;
    // All an interpreter can refuse comes before anything is mapped.
    let interpreter = match info.interpreter(bytes)? {
        Some(asked) => {
            let (fs, check) = files
                .as_mut()
                .ok_or(LoadError::Interpreter(Errno::ENOENT))?;
            let path = check(asked).map_err(LoadError::Interpreter)?;
            let (image, parsed) = read_interpreter(*fs, &path)?;
            Some((path, image, parsed))
        }
        None => None,
    };
    let identity = |path: &[u8]| {
        files.as_ref().map_or((0, 0), |(fs, _)| {
            let inode = fs.metadata(path, true).map_or(0, |stat| stat.inode);
            (paludarium_vfs::mount_device(&fs.mounts(), path), inode)
        })
    };
    let own = name.map_or((0, 0), identity);
    let (base, highest) = map_segments(bytes, name, own, &info, mem, STATIC_PIE_BASE)?;
    let initial_break = GuestAddr(highest)
        .page_align_up()
        .ok_or(LoadError::Malformed("segment address overflow"))?;
    mem.set_initial_break(initial_break);
    mem.set_mmap_top(GuestAddr(paludarium_mmu::DEFAULT_MMAP_TOP));
    let program_entry = GuestAddr(base.wrapping_add(info.entry));
    let mut entry_point = program_entry;
    let mut interpreter_at = 0;
    if let Some((path, file, parsed)) = interpreter {
        let top = paludarium_mmu::DEFAULT_MMAP_TOP;
        let wanted = interpreter_base(&parsed, top)?;
        let (at, _) = map_segments(&file, Some(&path), identity(&path), &parsed, mem, wanted)?;
        entry_point = GuestAddr(at.wrapping_add(parsed.entry));
        interpreter_at = at;
    }
    let mut image = LoadedImage {
        entry_point,
        program_entry,
        interpreter_base: interpreter_at,
        program_header_address: GuestAddr(phdr_address(&info, base)),
        program_header_count: info.phnum,
        initial_stack_pointer: GuestAddr(0),
        initial_break,
        load_base: GuestAddr(base),
    };
    image.initial_stack_pointer = GuestAddr(build_stack(mem, start, &image)?);
    Ok(image)
}

#[cfg(test)]
mod tests;
