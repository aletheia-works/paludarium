//! Parsing and validation of ELF64 executables. Pure functions over
//! untrusted bytes: every offset and size is checked; nothing panics.

use crate::LoadError;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Size of an ELF64 program header.
pub const PHDR_SIZE: u64 = 56;
const EHDR_SIZE: usize = 64;

/// Upper bound of the summed `p_memsz` of all `PT_LOAD` segments: 4 GiB.
/// Keeps a crafted ELF from exhausting host memory (NFR review R-01).
pub const MAX_LOAD_SIZE: u64 = 4 << 30;

/// One program header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// The parts of an ELF file the loader needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfInfo {
    pub kind: u16,
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u16,
    pub headers: Vec<ProgramHeader>,
}

impl ElfInfo {
    /// The `PT_LOAD` segments that occupy memory.
    pub fn loads(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.headers
            .iter()
            .filter(|h| h.kind == PT_LOAD && h.memsz > 0)
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, LoadError> {
    let s = b
        .get(at..at + 2)
        .ok_or(LoadError::Malformed("truncated header"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, LoadError> {
    let s = b
        .get(at..at + 4)
        .ok_or(LoadError::Malformed("truncated header"))?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, LoadError> {
    let s = b
        .get(at..at + 8)
        .ok_or(LoadError::Malformed("truncated header"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// Parses and validates an ELF64 executable.
pub fn parse(bytes: &[u8]) -> Result<ElfInfo, LoadError> {
    if bytes.len() < EHDR_SIZE || bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err(LoadError::Malformed("not an ELF file"));
    }
    // EI_CLASS = ELFCLASS64, EI_DATA = little endian, EI_VERSION = 1.
    if bytes.get(4..7) != Some([2u8, 1, 1].as_slice()) {
        return Err(LoadError::Malformed("not a 64-bit little-endian ELF"));
    }
    let kind = u16_at(bytes, 16)?;
    if kind != ET_EXEC && kind != ET_DYN {
        return Err(LoadError::Malformed("not an executable"));
    }
    if u16_at(bytes, 18)? != EM_X86_64 {
        return Err(LoadError::Malformed("not an x86-64 program"));
    }
    let entry = u64_at(bytes, 24)?;
    let phoff = u64_at(bytes, 32)?;
    if u64::from(u16_at(bytes, 54)?) != PHDR_SIZE {
        return Err(LoadError::Malformed("unexpected program header size"));
    }
    let phnum = u16_at(bytes, 56)?;
    if phnum == 0 {
        return Err(LoadError::Malformed("no program headers"));
    }
    let table_len = u64::from(phnum) * PHDR_SIZE;
    let table_end = phoff
        .checked_add(table_len)
        .ok_or(LoadError::Malformed("program headers out of range"))?;
    let file_len = u64::try_from(bytes.len()).map_err(|_| LoadError::TooLarge)?;
    if table_end > file_len {
        return Err(LoadError::Malformed("program headers out of range"));
    }
    let start = usize::try_from(phoff).map_err(|_| LoadError::TooLarge)?;
    let mut headers = Vec::with_capacity(usize::from(phnum));
    let mut total: u64 = 0;
    for n in 0..usize::from(phnum) {
        let at = start + n * 56;
        let h = ProgramHeader {
            kind: u32_at(bytes, at)?,
            flags: u32_at(bytes, at + 4)?,
            offset: u64_at(bytes, at + 8)?,
            vaddr: u64_at(bytes, at + 16)?,
            filesz: u64_at(bytes, at + 32)?,
            memsz: u64_at(bytes, at + 40)?,
        };
        if h.kind == PT_INTERP {
            return Err(LoadError::NotStaticMusl);
        }
        if h.kind == PT_LOAD {
            let file_end = h
                .offset
                .checked_add(h.filesz)
                .ok_or(LoadError::Malformed("segment out of range"))?;
            if file_end > file_len {
                return Err(LoadError::Malformed("segment out of range"));
            }
            if h.filesz > h.memsz {
                return Err(LoadError::Malformed(
                    "segment file size exceeds memory size",
                ));
            }
            h.vaddr
                .checked_add(h.memsz)
                .ok_or(LoadError::Malformed("segment address overflow"))?;
            total = total.checked_add(h.memsz).ok_or(LoadError::TooLarge)?;
            if total > MAX_LOAD_SIZE {
                return Err(LoadError::TooLarge);
            }
        }
        headers.push(h);
    }
    let info = ElfInfo {
        kind,
        entry,
        phoff,
        phnum,
        headers,
    };
    if info.loads().next().is_none() {
        return Err(LoadError::Malformed("no loadable segments"));
    }
    Ok(info)
}
