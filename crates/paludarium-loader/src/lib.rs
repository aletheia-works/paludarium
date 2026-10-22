//! Static ELF loader for paludarium.
//!
//! Loads static x86-64 executables (`ET_EXEC`, and `ET_DYN` static-pie
//! without an interpreter) into a guest address space and builds the initial
//! stack with argc, argv, envp and the auxiliary vector exactly as Linux lays
//! them out. Static-pie images relocate themselves (musl's start code), so
//! the loader does not apply relocations.
#![forbid(unsafe_code)]

pub mod elf;
pub mod testing;

use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{Errno, Error, ErrorKind, GuestAddr, PAGE_SIZE, USER_ADDRESS_LIMIT};
use paludarium_vfs::FileSystem;

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
    /// The user and group id reported to the guest.
    pub const GUEST_ID: u64 = 1000;
}

/// Why a program could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The path does not name a file.
    NotFound,
    /// The program needs a dynamic linker (`PT_INTERP`).
    NotStaticMusl,
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
            LoadError::NotStaticMusl => "dynamically linked programs are not supported",
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
    pub entry_point: GuestAddr,
    pub program_header_address: GuestAddr,
    pub program_header_count: u16,
    pub initial_stack_pointer: GuestAddr,
    pub initial_break: GuestAddr,
    pub load_base: GuestAddr,
}

/// Inputs of the initial stack.
#[derive(Clone, Copy, Debug)]
pub struct StartInfo<'a> {
    pub argv: &'a [Vec<u8>],
    pub envp: &'a [Vec<u8>],
    /// The program path as the guest sees it (`AT_EXECFN`).
    pub execfn: &'a [u8],
    /// 16 bytes from the host's random source (`AT_RANDOM`).
    pub random: [u8; 16],
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

/// Places the `PT_LOAD` segments. Returns the load base and the end of the
/// highest segment.
fn map_segments(
    bytes: &[u8],
    info: &ElfInfo,
    mem: &mut AddressSpace,
) -> Result<(u64, u64), LoadError> {
    let base = if info.kind == elf::ET_DYN {
        STATIC_PIE_BASE
    } else {
        0
    };
    let mut highest = 0u64;
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
        mem.map(
            Some(page_start),
            page_end.0 - page_start.0,
            prot_of(h.flags),
            MappingKind::ElfSegment,
        )
        .map_err(|e| {
            if e == Errno::EEXIST {
                LoadError::Malformed("overlapping segments")
            } else {
                LoadError::Errno(e)
            }
        })?;
        let from = usize::try_from(h.offset).map_err(|_| LoadError::TooLarge)?;
        let len = usize::try_from(h.filesz).map_err(|_| LoadError::TooLarge)?;
        let data = bytes
            .get(from..from + len)
            .ok_or(LoadError::Malformed("segment out of range"))?;
        // The rest of the segment (bss) stays zero: fresh pages read as zero.
        mem.write_initial(GuestAddr(start), data)
            .map_err(|_| LoadError::Errno(Errno::EFAULT))?;
        highest = highest.max(end);
    }
    Ok((base, highest))
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
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, image.entry_point.0),
        (AT_UID, GUEST_ID),
        (AT_EUID, GUEST_ID),
        (AT_GID, GUEST_ID),
        (AT_EGID, GUEST_ID),
        (AT_SECURE, 0),
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
    let bytes = fs.read_file(path).map_err(|e| {
        if e == Errno::ENOENT || e == Errno::EISDIR || e == Errno::ENOTDIR {
            LoadError::NotFound
        } else {
            LoadError::Errno(e)
        }
    })?;
    load_bytes(&bytes, start, mem)
}

/// Loads an ELF image from memory.
pub fn load_bytes(
    bytes: &[u8],
    start: &StartInfo<'_>,
    mem: &mut AddressSpace,
) -> Result<LoadedImage, LoadError> {
    let info = elf::parse(bytes)?;
    let (base, highest) = map_segments(bytes, &info, mem)?;
    let initial_break = GuestAddr(highest)
        .page_align_up()
        .ok_or(LoadError::Malformed("segment address overflow"))?;
    mem.set_initial_break(initial_break);
    mem.set_mmap_top(GuestAddr(paludarium_mmu::DEFAULT_MMAP_TOP));
    let mut image = LoadedImage {
        entry_point: GuestAddr(base.wrapping_add(info.entry)),
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
