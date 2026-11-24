//! The GNU build ID of a mapping's file, as Linux's `lib/buildid.c`
//! (`build_id_parse_nofault`) finds it for the `MMAP2` records of events
//! with `build_id`: an ELF executable or shared object, 32-bit or 64-bit,
//! whose first `MAX_PHDR_CNT` program headers are searched for a `PT_NOTE`
//! that holds an `NT_GNU_BUILD_ID` note named `GNU` of 1 to
//! `BUILD_ID_SIZE_MAX` bytes. As `nofault` reads only pages already in the
//! page cache, a page the file does not hold ([`PageSource::holds`]: a hole
//! of a tmpfs file or a memfd) gives none, and so does secret memory
//! (`secretmem_mapping`).
use paludarium_mmu::PageSource;

/// `BUILD_ID_SIZE_MAX`.
pub(crate) const SIZE_MAX: usize = 20;
/// `MAX_PHDR_CNT`.
const MAX_PHDR_CNT: u32 = 256;
/// `NT_GNU_BUILD_ID`.
const NT_GNU_BUILD_ID: u32 = 3;
const PT_NOTE: u32 = 4;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const PAGE: u64 = 4096;

/// A build ID: its size, and its bytes with zeros after them.
pub(crate) type BuildId = (u8, [u8; SIZE_MAX]);

/// `freader` over the file in nofault mode: `len` bytes at `at`, all from
/// pages the file holds, or none.
struct Reader<'a> {
    source: &'a dyn PageSource,
}

impl Reader<'_> {
    fn fetch(&self, at: u64, len: usize) -> Option<Vec<u8>> {
        let end = at.checked_add(len as u64)?;
        let first = at / PAGE;
        let last = end.saturating_sub(1) / PAGE;
        if len > 0 && !(first..=last).all(|page| self.source.holds(page * PAGE)) {
            return None;
        }
        let mut buf = vec![0; len];
        let n = self.source.read_at(at, &mut buf).ok()?;
        (n == len).then_some(buf)
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

/// `parse_build_id`: the build ID in the notes of `size` bytes at `off`.
fn parse_notes(r: &Reader<'_>, mut off: u64, size: u64) -> Option<BuildId> {
    const NAME: &[u8; 4] = b"GNU\0";
    // `Elf32_Nhdr` and the name, which the loop needs room for.
    const HEADER: u64 = 12;
    let end = off.checked_add(size)?;
    // Linux's offsets are `u32`s.
    let end = u32::try_from(end).ok().map(u64::from)?;
    while end - off > HEADER + NAME.len() as u64 {
        let nhdr = r.fetch(off, HEADER as usize + NAME.len())?;
        let (name_sz, desc_sz, kind) = (u32_at(&nhdr, 0), u32_at(&nhdr, 4), u32_at(&nhdr, 8));
        let align = |n: u32| (u64::from(n) + 3) & !3;
        let next = off + HEADER + align(name_sz) + align(desc_sz);
        if next > end || next > u64::from(u32::MAX) {
            break;
        }
        if kind == NT_GNU_BUILD_ID
            && name_sz as usize == NAME.len()
            && nhdr[12..16] == *NAME
            && desc_sz > 0
            && desc_sz as usize <= SIZE_MAX
        {
            let data = r.fetch(off + HEADER + align(name_sz), desc_sz as usize)?;
            let mut id = [0; SIZE_MAX];
            id[..data.len()].copy_from_slice(&data);
            return Some((desc_sz as u8, id));
        }
        off = next;
    }
    None
}

/// `__build_id_parse` of `source`, the VMA's file.
pub(crate) fn parse(source: &dyn PageSource) -> Option<BuildId> {
    if source.secret() {
        return None;
    }
    let r = Reader { source };
    // `offsetofend(Elf32_Ehdr, e_type)`.
    let ident = r.fetch(0, 18)?;
    if ident[..4] != *b"\x7fELF" {
        return None;
    }
    if !matches!(u16_at(&ident, 16), ET_EXEC | ET_DYN) {
        return None;
    }
    // Each class's `Elf_Ehdr` size, where `e_phoff` and `e_phnum` are, and
    // its `Elf_Phdr` size, with where `p_offset` and `p_filesz` are.
    let (ehdr, phdr) = match ident[4] {
        ELFCLASS32 => (52, 32),
        ELFCLASS64 => (64, 56),
        _ => return None,
    };
    let header = r.fetch(0, ehdr)?;
    let (phoff, phnum) = if ehdr == 64 {
        (u64_at(&header, 32), u16_at(&header, 56))
    } else {
        (u64::from(u32_at(&header, 28)), u16_at(&header, 44))
    };
    let phnum = u32::from(phnum).min(MAX_PHDR_CNT);
    phoff.checked_add(u64::from(phnum) * phdr as u64)?;
    (0..phnum).find_map(|i| {
        let at = phoff + u64::from(i) * phdr as u64;
        let ph = r.fetch(at, phdr)?;
        if u32_at(&ph, 0) != PT_NOTE {
            return None;
        }
        let (offset, size) = if ehdr == 64 {
            (u64_at(&ph, 8), u64::from(u32_at(&ph, 32)))
        } else {
            (u64::from(u32_at(&ph, 4)), u64::from(u32_at(&ph, 16)))
        };
        parse_notes(&r, offset, size)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_types::Errno;

    /// A file of `bytes`, holding the pages `held` says.
    struct File {
        bytes: Vec<u8>,
        held: fn(u64) -> bool,
    }
    impl PageSource for File {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
            let start = (offset as usize).min(self.bytes.len());
            let n = buf.len().min(self.bytes.len() - start);
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            Ok(n)
        }
        fn holds(&self, offset: u64) -> bool {
            (self.held)(offset)
        }
    }

    /// A note of `kind` named `name` with `desc`.
    fn note(kind: u32, name: &[u8], desc: &[u8]) -> Vec<u8> {
        let pad = |b: &[u8]| {
            let mut v = b.to_vec();
            v.resize(b.len().div_ceil(4) * 4, 0);
            v
        };
        let mut n = Vec::new();
        n.extend((name.len() as u32).to_le_bytes());
        n.extend((desc.len() as u32).to_le_bytes());
        n.extend(kind.to_le_bytes());
        n.extend(pad(name));
        n.extend(pad(desc));
        n
    }

    /// A 64-bit ELF of `kind` with one `PT_LOAD` and then a `PT_NOTE` of
    /// `notes`, which start at `notes_at`.
    fn elf64(kind: u16, notes: &[u8], notes_at: usize) -> Vec<u8> {
        let mut b = vec![0; notes_at.max(64 + 2 * 56)];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = ELFCLASS64;
        b[16..18].copy_from_slice(&kind.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        // PT_LOAD, then PT_NOTE.
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        let ph = 64 + 56;
        b[ph..ph + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        b[ph + 8..ph + 16].copy_from_slice(&(notes_at as u64).to_le_bytes());
        b[ph + 32..ph + 40].copy_from_slice(&(notes.len() as u64).to_le_bytes());
        b.resize(notes_at, 0);
        b.extend_from_slice(notes);
        b
    }

    fn all(_: u64) -> bool {
        true
    }

    #[test]
    fn the_gnu_note_after_others_is_the_build_id() {
        let id: Vec<u8> = (1..=20).collect();
        let notes = [
            note(1, b"GNU\0", &[0; 16]),
            note(3, b"Go\0\0", &[9; 8]),
            note(3, b"GNU\0", &id),
        ]
        .concat();
        let file = File {
            bytes: elf64(ET_DYN, &notes, 0x200),
            held: all,
        };
        let (size, got) = parse(&file).unwrap();
        assert_eq!((size, &got[..]), (20, &id[..]));
        // A shorter one has zeros after it.
        let notes = note(3, b"GNU\0", &[7; 8]);
        let file = File {
            bytes: elf64(ET_EXEC, &notes, 0x200),
            held: all,
        };
        let (size, got) = parse(&file).unwrap();
        assert_eq!(size, 8);
        assert_eq!(got[..8], [7; 8]);
        assert_eq!(got[8..], [0; 12]);
    }

    #[test]
    fn sizes_are_cut_to_linux_s_32_bits() {
        // A 64-bit `p_filesz` with high bits set is read as its low 32,
        // as Linux's `Elf32_Word note_size` takes it.
        let notes = note(3, b"GNU\0", &[4; 20]);
        let mut bytes = elf64(ET_DYN, &notes, 0x200);
        let filesz = 64 + 56 + 32;
        let size = (1u64 << 32) | notes.len() as u64;
        bytes[filesz..filesz + 8].copy_from_slice(&size.to_le_bytes());
        let file = File { bytes, held: all };
        assert_eq!(parse(&file), Some((20, [4; 20])));
        // Notes that end past 4 GiB, which Linux's `u32` `note_end` cannot
        // hold, are searched for none.
        let mut bytes = elf64(ET_DYN, &notes, 0x200);
        let offset = 64 + 56 + 8;
        bytes[offset..offset + 8].copy_from_slice(&(u64::from(u32::MAX) - 8).to_le_bytes());
        let file = File { bytes, held: all };
        assert_eq!(parse(&file), None);
    }

    #[test]
    fn a_32_bit_elf_has_one_too() {
        let mut b = vec![0; 0x100];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = ELFCLASS32;
        b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[28..32].copy_from_slice(&52u32.to_le_bytes());
        b[44..46].copy_from_slice(&1u16.to_le_bytes());
        b[52..56].copy_from_slice(&PT_NOTE.to_le_bytes());
        b[56..60].copy_from_slice(&0x100u32.to_le_bytes());
        let notes = note(3, b"GNU\0", &[5; 20]);
        b[68..72].copy_from_slice(&(notes.len() as u32).to_le_bytes());
        b.extend_from_slice(&notes);
        let file = File {
            bytes: b,
            held: all,
        };
        assert_eq!(parse(&file), Some((20, [5; 20])));
    }

    #[test]
    fn no_build_id_without_an_elf_a_note_or_the_pages() {
        let good = note(3, b"GNU\0", &[1; 20]);
        // An object file, a desc too large or empty, a cut-off note, text.
        for (bytes, why) in [
            (elf64(1, &good, 0x200), "relocatable"),
            (
                elf64(ET_DYN, &note(3, b"GNU\0", &[1; 24]), 0x200),
                "too large",
            ),
            (elf64(ET_DYN, &note(3, b"GNU\0", &[]), 0x200), "empty"),
            (elf64(ET_DYN, &good[..good.len() - 4], 0x200), "cut off"),
            (b"#!/bin/sh\n".to_vec(), "not an ELF"),
        ] {
            let file = File { bytes, held: all };
            assert_eq!(parse(&file), None, "{why}");
        }
        // The notes' page not in the page cache, as nofault reads none.
        let file = File {
            bytes: elf64(ET_DYN, &good, 0x1000),
            held: |offset| offset < 0x1000,
        };
        assert_eq!(parse(&file), None);
    }
}
