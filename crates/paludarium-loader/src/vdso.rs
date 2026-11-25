//! The vDSO each program gets at exec, `linux-vdso.so.1`, as Linux's
//! `map_vdso` maps it on x86-64 with the vDSO's data before it: `[vvar]`,
//! `[vvar_vclock]` and `[vdso]`, which `AT_SYSINFO_EHDR` names.
//!
//! The image is built here from tables. Its interface is Linux's: an
//! `ET_DYN` object of version `LINUX_2.6` whose functions a C library finds
//! through its dynamic symbols. Each function makes its system call, which
//! is what Linux's vDSO itself falls back to when no clock source can be
//! read from user space, so a program gets what the call gives.
//! `__vdso_getrandom` and `__vdso_sgx_enter_enclave` are not there: the
//! first's contract (its opaque state) is not a system call's, and SGX is
//! not emulated (see the limitations).

use paludarium_mmu::{PageSource, vm};
use paludarium_types::Errno;
use std::sync::{Arc, OnceLock};

/// The pages of `[vvar]`, `[vvar_vclock]` and `[vdso]`, as the runners' kernel
/// maps them.
pub const VVAR_PAGES: u64 = 4;
pub const VCLOCK_PAGES: u64 = 2;
pub const VDSO_PAGES: u64 = 2;
const PAGE: usize = 4096;

/// The functions: their names without `__vdso_`, and their system calls.
const FUNCTIONS: [(&str, u32); 5] = [
    ("clock_gettime", 228),
    ("gettimeofday", 96),
    ("time", 201),
    ("getcpu", 309),
    ("clock_getres", 229),
];
/// Each function's code: `mov eax, number; syscall; ret`, 16 bytes apart.
const FUNCTION_SIZE: u64 = 8;
const FUNCTION_STRIDE: usize = 16;
/// `LINUX_VERSION_CODE` of the release `uname` gives (6.12.0).
const VERSION_CODE: u32 = (6 << 16) | (12 << 8);

const SONAME: &str = "linux-vdso.so.1";
const VERSION: &str = "LINUX_2.6";

/// Linux's ELF hash, which `.hash` and the version definitions take.
fn elf_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &c in name.as_bytes() {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// The GNU hash `.gnu.hash` takes.
fn gnu_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |h, c| {
        h.wrapping_mul(33).wrapping_add(u32::from(c))
    })
}

/// A string table being built, with its offsets.
#[derive(Default)]
struct Strings(Vec<u8>);
impl Strings {
    fn add(&mut self, s: &str) -> u32 {
        if self.0.is_empty() {
            self.0.push(0);
        }
        let at = u32::try_from(self.0.len()).unwrap_or(0);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        at
    }
}

/// An image being laid out: its bytes, with sections appended at an
/// alignment.
#[derive(Default)]
struct Image(Vec<u8>);
impl Image {
    fn align(&mut self, to: usize) -> usize {
        self.0.resize(self.0.len().next_multiple_of(to), 0);
        self.0.len()
    }
    fn put(&mut self, align: usize, bytes: &[u8]) -> usize {
        let at = self.align(align);
        self.0.extend_from_slice(bytes);
        at
    }
    fn at(&mut self, offset: usize, bytes: &[u8]) {
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}

fn u16s(v: &[u16]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
fn u32s(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
fn u64s(v: &[u64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}
fn off(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(0)
}

/// A dynamic symbol: its name, binding, type, section index and value.
struct Symbol {
    name: u32,
    bind: u8,
    kind: u8,
    shndx: u16,
    value: u64,
    size: u64,
    hash: u32,
}

const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const SHN_ABS: u16 = 0xfff1;
/// The section index of `.text` in the section headers below.
const TEXT_SECTION: u16 = 11;

/// The offset from `from` to `to`, as the 4 bytes of a relative pointer.
fn rel32(to: usize, from: usize) -> [u8; 4] {
    let delta = i64::try_from(to).unwrap_or(0) - i64::try_from(from).unwrap_or(0);
    i32::try_from(delta).unwrap_or(0).to_le_bytes()
}

/// `.eh_frame_hdr` at `hdr_at` and `.eh_frame` at `eh_frame_at`, for the
/// functions at `text_at`: one CIE (the CFA `rsp` + 8 and the return
/// address at CFA - 8 throughout, as no function moves the stack) and an
/// FDE for each, which the header's table finds by address.
fn unwind_tables(text_at: usize, hdr_at: usize, eh_frame_at: usize) -> (Vec<u8>, Vec<u8>) {
    // Version 1, "zR", code alignment 1, data alignment -8, return address
    // register 16, the FDEs' pointers pc-relative 4-byte, then
    // `DW_CFA_def_cfa rsp, 8` and `DW_CFA_offset r16, 1`.
    let mut cie = vec![
        0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1,
    ];
    while (cie.len() + 4) % 8 != 0 {
        cie.push(0);
    }
    let mut eh = u32::try_from(cie.len()).unwrap_or(0).to_le_bytes().to_vec();
    eh.extend_from_slice(&cie);
    let mut table = Vec::new();
    for i in 0..FUNCTIONS.len() {
        let fde_at = eh_frame_at + eh.len();
        let target = text_at + i * FUNCTION_STRIDE;
        let mut fde = u32::try_from(fde_at + 4 - eh_frame_at)
            .unwrap_or(0)
            .to_le_bytes()
            .to_vec();
        fde.extend_from_slice(&rel32(target, fde_at + 8));
        fde.extend_from_slice(&u32::try_from(FUNCTION_SIZE).unwrap_or(0).to_le_bytes());
        fde.push(0);
        while (fde.len() + 4) % 8 != 0 {
            fde.push(0);
        }
        eh.extend_from_slice(&u32::try_from(fde.len()).unwrap_or(0).to_le_bytes());
        eh.extend_from_slice(&fde);
        table.push((target, fde_at));
    }
    eh.extend_from_slice(&[0; 4]);
    // Version 1; `.eh_frame`'s address pc-relative 4-byte, the count 4-byte,
    // the table relative to the header, 4-byte.
    let mut hdr = vec![1u8, 0x1b, 0x03, 0x3b];
    hdr.extend_from_slice(&rel32(eh_frame_at, hdr_at + 4));
    hdr.extend_from_slice(&u32::try_from(FUNCTIONS.len()).unwrap_or(0).to_le_bytes());
    for (target, fde_at) in table {
        hdr.extend_from_slice(&rel32(target, hdr_at));
        hdr.extend_from_slice(&rel32(fde_at, hdr_at));
    }
    (hdr, eh)
}

/// The vDSO's image: two pages, as the runners' is.
#[allow(clippy::too_many_lines)]
fn build() -> Vec<u8> {
    let mut img = Image::default();
    // The ELF header and five program headers, filled in at the end.
    img.0.resize(64 + 5 * 56, 0);
    let mut dynstr = Strings::default();
    let soname = dynstr.add(SONAME);
    let version = dynstr.add(VERSION);
    // The code first, at its final place, so the symbols can name it.
    let text_at = 0x800;
    let mut symbols = Vec::new();
    let mut names = Vec::new();
    for (i, (name, _)) in FUNCTIONS.iter().enumerate() {
        let value = off(text_at + i * FUNCTION_STRIDE);
        let full = format!("__vdso_{name}");
        names.push((full.clone(), STB_GLOBAL, value));
        names.push(((*name).to_owned(), STB_WEAK, value));
    }
    for (name, bind, value) in &names {
        symbols.push(Symbol {
            name: dynstr.add(name),
            bind: *bind,
            kind: STT_FUNC,
            shndx: TEXT_SECTION,
            value: *value,
            size: FUNCTION_SIZE,
            hash: gnu_hash(name),
        });
    }
    // The version's own symbol, as a linker defines it.
    symbols.push(Symbol {
        name: version,
        bind: STB_GLOBAL,
        kind: STT_OBJECT,
        shndx: SHN_ABS,
        value: 0,
        size: 0,
        hash: gnu_hash(VERSION),
    });
    let nsyms = u32::try_from(symbols.len() + 1).unwrap_or(0);

    // `.hash`: one bucket, every symbol on its chain.
    let mut hash = vec![1, nsyms, 1];
    hash.push(0);
    for i in 1..nsyms {
        hash.push(if i + 1 < nsyms { i + 1 } else { 0 });
    }
    let hash_at = img.put(8, &u32s(&hash));
    // `.gnu.hash`: one bucket from symbol 1, a one-word bloom filter.
    let shift = 6u32;
    let mut bloom = 0u64;
    for s in &symbols {
        bloom |= 1 << (s.hash % 64);
        bloom |= 1 << ((s.hash >> shift) % 64);
    }
    let mut gnu = u32s(&[1, 1, 1, shift]);
    gnu.extend_from_slice(&u64s(&[bloom]));
    gnu.extend_from_slice(&u32s(&[1]));
    let chain: Vec<u32> = symbols
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i + 1 == symbols.len() {
                s.hash | 1
            } else {
                s.hash & !1
            }
        })
        .collect();
    gnu.extend_from_slice(&u32s(&chain));
    let gnu_at = img.put(8, &gnu);
    // `.dynsym`.
    let mut dynsym = vec![0u8; 24];
    for s in &symbols {
        dynsym.extend_from_slice(&s.name.to_le_bytes());
        dynsym.push((s.bind << 4) | s.kind);
        dynsym.push(0);
        dynsym.extend_from_slice(&s.shndx.to_le_bytes());
        dynsym.extend_from_slice(&s.value.to_le_bytes());
        dynsym.extend_from_slice(&s.size.to_le_bytes());
    }
    let dynsym_at = img.put(8, &dynsym);
    let dynstr_at = img.put(1, &dynstr.0);
    // `.gnu.version`: every defined symbol is `LINUX_2.6`.
    let mut versym = vec![0u16];
    versym.extend(std::iter::repeat_n(2u16, symbols.len()));
    let versym_at = img.put(2, &u16s(&versym));
    // `.gnu.version_d`: the base (the object's name) and `LINUX_2.6`.
    let mut verdef = Vec::new();
    for (ndx, flags, name, at, next) in [
        (1u16, 1u16, SONAME, soname, 28u32),
        (2, 0, VERSION, version, 0),
    ] {
        verdef.extend_from_slice(&1u16.to_le_bytes());
        verdef.extend_from_slice(&flags.to_le_bytes());
        verdef.extend_from_slice(&ndx.to_le_bytes());
        verdef.extend_from_slice(&1u16.to_le_bytes());
        verdef.extend_from_slice(&elf_hash(name).to_le_bytes());
        verdef.extend_from_slice(&20u32.to_le_bytes());
        verdef.extend_from_slice(&next.to_le_bytes());
        verdef.extend_from_slice(&at.to_le_bytes());
        verdef.extend_from_slice(&0u32.to_le_bytes());
    }
    let verdef_at = img.put(8, &verdef);
    // `.dynamic`.
    const DT_FLAGS_SYMBOLIC: u64 = 2;
    let dynamic: Vec<u64> = vec![
        14, // DT_SONAME
        u64::from(soname),
        16, // DT_SYMBOLIC
        0,
        4, // DT_HASH
        off(hash_at),
        0x6fff_fef5, // DT_GNU_HASH
        off(gnu_at),
        5, // DT_STRTAB
        off(dynstr_at),
        6, // DT_SYMTAB
        off(dynsym_at),
        10, // DT_STRSZ
        off(dynstr.0.len()),
        11, // DT_SYMENT
        24,
        0x6fff_fffc, // DT_VERDEF
        off(verdef_at),
        0x6fff_fffd, // DT_VERDEFNUM
        2,
        0x1e, // DT_FLAGS
        DT_FLAGS_SYMBOLIC,
        0x6fff_fff0, // DT_VERSYM
        off(versym_at),
        0,
        0,
    ];
    let dynamic_at = img.put(8, &u64s(&dynamic));
    // `.note`: the kernel's version, as Linux's `Linux` note of type 0.
    let mut note = u32s(&[6, 4, 0]);
    note.extend_from_slice(b"Linux\0\0\0");
    note.extend_from_slice(&VERSION_CODE.to_le_bytes());
    let note_at = img.put(4, &note);
    // `.eh_frame_hdr`, then `.eh_frame`, as a linker lays them out.
    let hdr_at = img.align(4);
    let hdr_len = 12 + 8 * FUNCTIONS.len();
    let eh_frame_at = (hdr_at + hdr_len).next_multiple_of(8);
    let (hdr, eh) = unwind_tables(text_at, hdr_at, eh_frame_at);
    let eh_frame_len = eh.len();
    img.put(4, &hdr);
    let at = img.put(8, &eh);
    debug_assert_eq!(at, eh_frame_at);
    assert!(img.0.len() <= text_at, "the vDSO's tables overrun its code");
    // `.text`.
    img.0.resize(text_at, 0);
    for (i, (_, number)) in FUNCTIONS.iter().enumerate() {
        let at = text_at + i * FUNCTION_STRIDE;
        img.0.resize(at, 0xcc);
        img.0.push(0xb8);
        img.0.extend_from_slice(&number.to_le_bytes());
        img.0.extend_from_slice(&[0x0f, 0x05, 0xc3]);
    }
    let text_len = img.0.len() - text_at;
    let load_end = img.0.len();
    // `.shstrtab` and the section headers, after what is loaded.
    let mut shstr = Strings::default();
    let section_names = [
        "",
        ".hash",
        ".gnu.hash",
        ".dynsym",
        ".dynstr",
        ".gnu.version",
        ".gnu.version_d",
        ".dynamic",
        ".note",
        ".eh_frame_hdr",
        ".eh_frame",
        ".text",
        ".shstrtab",
    ];
    let name_at: Vec<u32> = section_names
        .iter()
        .map(|n| if n.is_empty() { 0 } else { shstr.add(n) })
        .collect();
    if shstr.0.is_empty() {
        shstr.0.push(0);
    }
    let shstr_at = img.put(1, &shstr.0);
    /// A section header's type, flags, offset, size, link, info, alignment
    /// and entry size.
    type Section = (u32, u64, usize, usize, u32, u32, u64, u64);
    let a = 2u64; // SHF_ALLOC
    let sections: [Section; 13] = [
        (0, 0, 0, 0, 0, 0, 0, 0),
        (5, a, hash_at, hash.len() * 4, 3, 0, 8, 4),
        (0x6fff_fff6, a, gnu_at, gnu.len(), 3, 0, 8, 0),
        (11, a, dynsym_at, dynsym.len(), 4, 1, 8, 24),
        (3, a, dynstr_at, dynstr.0.len(), 0, 0, 1, 0),
        (0x6fff_ffff, a, versym_at, versym.len() * 2, 3, 0, 2, 2),
        (0x6fff_fffd, a, verdef_at, verdef.len(), 4, 2, 8, 0),
        (6, a | 1, dynamic_at, dynamic.len() * 8, 4, 0, 8, 16),
        (7, a, note_at, note.len(), 0, 0, 4, 0),
        (1, a, hdr_at, hdr_len, 0, 0, 4, 0),
        (1, a, eh_frame_at, eh_frame_len, 0, 0, 8, 0),
        (1, a | 4, text_at, text_len, 0, 0, 16, 0),
        (3, 0, shstr_at, shstr.0.len(), 0, 0, 1, 0),
    ];
    let sh_at = img.align(8);
    for (i, (kind, flags, at, size, link, info, align, entsize)) in sections.iter().enumerate() {
        let addr = if flags & a != 0 { off(*at) } else { 0 };
        img.0.extend_from_slice(&name_at[i].to_le_bytes());
        img.0.extend_from_slice(&kind.to_le_bytes());
        img.0.extend_from_slice(&flags.to_le_bytes());
        img.0.extend_from_slice(&addr.to_le_bytes());
        img.0
            .extend_from_slice(&off(if i == 0 { 0 } else { *at }).to_le_bytes());
        img.0.extend_from_slice(&off(*size).to_le_bytes());
        img.0.extend_from_slice(&link.to_le_bytes());
        img.0.extend_from_slice(&info.to_le_bytes());
        img.0.extend_from_slice(&align.to_le_bytes());
        img.0.extend_from_slice(&entsize.to_le_bytes());
    }
    let size = PAGE * VDSO_PAGES as usize;
    assert!(img.0.len() <= size, "the vDSO is larger than its pages");
    // The ELF header.
    let mut eh_hdr = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    eh_hdr.resize(16, 0);
    eh_hdr.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
    eh_hdr.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    eh_hdr.extend_from_slice(&1u32.to_le_bytes());
    eh_hdr.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    eh_hdr.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    eh_hdr.extend_from_slice(&off(sh_at).to_le_bytes());
    eh_hdr.extend_from_slice(&0u32.to_le_bytes());
    eh_hdr.extend_from_slice(&64u16.to_le_bytes());
    eh_hdr.extend_from_slice(&56u16.to_le_bytes());
    eh_hdr.extend_from_slice(&5u16.to_le_bytes());
    eh_hdr.extend_from_slice(&64u16.to_le_bytes());
    eh_hdr.extend_from_slice(&13u16.to_le_bytes());
    eh_hdr.extend_from_slice(&12u16.to_le_bytes());
    img.at(0, &eh_hdr);
    // (type, flags, offset, size, align)
    let phdrs: [(u32, u32, usize, usize, u64); 5] = [
        (1, 5, 0, load_end, 0x1000),              // PT_LOAD R+X
        (2, 4, dynamic_at, dynamic.len() * 8, 8), // PT_DYNAMIC
        (4, 4, note_at, note.len(), 4),           // PT_NOTE
        (0x6474_e550, 4, hdr_at, hdr_len, 4),     // PT_GNU_EH_FRAME
        (0x6474_e551, 6, 0, 0, 8),                // PT_GNU_STACK
    ];
    for (i, (kind, flags, at, size, align)) in phdrs.iter().enumerate() {
        let mut ph = kind.to_le_bytes().to_vec();
        ph.extend_from_slice(&flags.to_le_bytes());
        ph.extend_from_slice(&u64s(&[
            off(*at),
            off(*at),
            off(*at),
            off(*size),
            off(*size),
            *align,
        ]));
        img.at(64 + i * 56, &ph);
    }
    img.0.resize(size, 0);
    img.0
}

/// The vDSO's image, built once.
#[must_use]
pub fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(build)
}

/// The memory of `[vdso]`: the image, in a special mapping that may not grow
/// (`VM_DONTEXPAND`) and is not charged.
pub(crate) struct VdsoPages;
impl PageSource for VdsoPages {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let image = image();
        let from = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(image.len());
        let n = buf.len().min(image.len() - from);
        buf[..n].copy_from_slice(&image[from..from + n]);
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(VDSO_PAGES * PAGE as u64)
    }
    fn name(&self) -> Option<Vec<u8>> {
        Some(b"[vdso]".to_vec())
    }
    fn fixed(&self) -> bool {
        true
    }
    /// Linux's `special_mapping_split`.
    fn splits(&self) -> bool {
        false
    }
    fn vma_flags(&self, flags: u64) -> u64 {
        (flags & !vm::ACCOUNT) | vm::DONTEXPAND
    }
}

/// The memory of `[vvar]` and `[vvar_vclock]`: pages of no memory of their own
/// (`VM_IO | VM_PFNMAP`), read-only for good (no `VM_MAYWRITE`). The pages
/// Linux fills read as zeros, as nothing here reads the time from them; the
/// others are a bus error, as Linux's are where its `vvar_fault` finds
/// nothing to map. This is Linux 7.0's `[vvar]`, the CI runners': 7.2 makes it
/// `VM_MIXEDMAP` and maps zeros for those pages (c27e727c9a60,
/// 43648f9f3a67).
pub(crate) struct VvarPages {
    pub(crate) name: &'static [u8],
    /// The pages that may be read, by index.
    pub(crate) readable: &'static [u64],
    pub(crate) pages: u64,
}
impl PageSource for VvarPages {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let end = self.pages * PAGE as u64;
        let n = usize::try_from(end.saturating_sub(offset))
            .unwrap_or(0)
            .min(buf.len());
        buf[..n].fill(0);
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.pages * PAGE as u64)
    }
    fn name(&self) -> Option<Vec<u8>> {
        Some(self.name.to_vec())
    }
    fn fixed(&self) -> bool {
        true
    }
    /// Linux's `special_mapping_split`.
    fn splits(&self) -> bool {
        false
    }
    fn admit(&self, offset: u64, _: paludarium_mmu::HugeFit) -> bool {
        self.readable.contains(&(offset / PAGE as u64))
    }
    fn writable(&self, _: u64) -> bool {
        false
    }
    fn vma_flags(&self, flags: u64) -> u64 {
        (flags & !(vm::ACCOUNT | vm::MAYWRITE | vm::MAYEXEC))
            | vm::IO
            | vm::PFNMAP
            | vm::DONTEXPAND
            | vm::DONTDUMP
    }
}

/// `[vvar]`: the time data's page and the random state's are filled;
/// the time namespace's and the architecture's are not.
pub(crate) fn vvar() -> Arc<dyn PageSource> {
    Arc::new(VvarPages {
        name: b"[vvar]",
        readable: &[0, 2],
        pages: VVAR_PAGES,
    })
}
/// `[vvar_vclock]`: the paravirtual and Hyper-V clocks' pages, neither
/// read here.
pub(crate) fn vvar_vclock() -> Arc<dyn PageSource> {
    Arc::new(VvarPages {
        name: b"[vvar_vclock]",
        readable: &[],
        pages: VCLOCK_PAGES,
    })
}
/// `[vdso]`.
pub(crate) fn vdso() -> Arc<dyn PageSource> {
    Arc::new(VdsoPages)
}

/// The address of the function `name` of version `version` in `image`,
/// looked up as a C library looks it up (musl's `__vdsosym`): by its
/// dynamic symbols and their versions.
#[must_use]
pub fn symbol(image: &[u8], name: &str, version: &str) -> Option<u64> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(image.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(image.get(at..at + 8)?.try_into().ok()?));
    let cstr = |at: usize| {
        let s = image.get(at..)?;
        let end = s.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&s[..end]).ok()
    };
    let phoff = usize::try_from(u64_at(32)?).ok()?;
    let phnum = usize::from(u16_at(56)?);
    let mut dynamic = None;
    for i in 0..phnum {
        let at = phoff + i * 56;
        if u32_at(at)? == 2 {
            dynamic = Some(usize::try_from(u64_at(at + 8)?).ok()?);
        }
    }
    let (mut strtab, mut symtab, mut hash, mut versym, mut verdef) = (None, None, None, None, None);
    let mut at = dynamic?;
    loop {
        let (tag, value) = (u64_at(at)?, usize::try_from(u64_at(at + 8)?).ok()?);
        match tag {
            0 => break,
            4 => hash = Some(value),
            5 => strtab = Some(value),
            6 => symtab = Some(value),
            0x6fff_fff0 => versym = Some(value),
            0x6fff_fffc => verdef = Some(value),
            _ => {}
        }
        at += 16;
    }
    let (strtab, symtab, hash) = (strtab?, symtab?, hash?);
    let nsyms = usize::try_from(u32_at(hash + 4)?).ok()?;
    for i in 1..nsyms {
        let sym = symtab + i * 24;
        let info = *image.get(sym + 4)?;
        if info & 0xf != STT_FUNC || info >> 4 == 0 {
            continue;
        }
        if cstr(strtab + usize::try_from(u32_at(sym)?).ok()?)? != name {
            continue;
        }
        let ndx = u16_at(versym? + i * 2)? & 0x7fff;
        let mut vd = verdef?;
        let matched = loop {
            if u16_at(vd + 4)? == ndx {
                let aux = vd + usize::try_from(u32_at(vd + 12)?).ok()?;
                break cstr(strtab + usize::try_from(u32_at(aux)?).ok()?)? == version;
            }
            let next = usize::try_from(u32_at(vd + 16)?).ok()?;
            if next == 0 {
                break false;
            }
            vd += next;
        };
        if matched {
            return u64_at(sym + 8);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_is_two_pages_of_an_elf_of_linux_s_interface() {
        let image = image();
        assert_eq!(image.len(), 2 * PAGE);
        assert_eq!(&image[..4], b"\x7fELF");
        assert_eq!(u16::from_le_bytes([image[16], image[17]]), 3, "ET_DYN");
        // Each function is found by name and version, as musl finds it, and
        // makes its system call.
        for (name, number) in FUNCTIONS {
            for symbol_name in [format!("__vdso_{name}"), name.to_owned()] {
                let at = symbol(image, &symbol_name, VERSION).unwrap();
                let at = usize::try_from(at).unwrap();
                assert_eq!(image[at], 0xb8, "{symbol_name}");
                assert_eq!(&image[at + 1..at + 5], &number.to_le_bytes());
                assert_eq!(&image[at + 5..at + 8], &[0x0f, 0x05, 0xc3]);
            }
        }
        assert_eq!(symbol(image, "__vdso_time", "LINUX_2.5"), None);
        assert_eq!(symbol(image, "__vdso_getrandom", VERSION), None);
        assert_eq!(symbol(image, "__vdso_sgx_enter_enclave", VERSION), None);
    }
}
