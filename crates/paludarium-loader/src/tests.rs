use super::*;
use paludarium_vfs::{GuestFile, MemFs};

struct Seg {
    kind: u32,
    flags: u32,
    vaddr: u64,
    data: Vec<u8>,
    memsz: u64,
}

fn load_seg(flags: u32, vaddr: u64, data: &[u8], memsz: u64) -> Seg {
    Seg {
        kind: elf::PT_LOAD,
        flags,
        vaddr,
        data: data.to_vec(),
        memsz,
    }
}

/// Builds a minimal ELF64 file: header, program headers, then segment data
/// each at a page-aligned file offset.
fn build_elf(kind: u16, entry: u64, segs: &[Seg]) -> Vec<u8> {
    let phnum = u16::try_from(segs.len()).unwrap();
    let mut out = vec![0u8; 64];
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&kind.to_le_bytes());
    out[18..20].copy_from_slice(&elf::EM_X86_64.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&64u64.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[54..56].copy_from_slice(&56u16.to_le_bytes());
    out[56..58].copy_from_slice(&phnum.to_le_bytes());
    let mut offsets = Vec::new();
    let mut next = 0x1000u64;
    for s in segs {
        offsets.push(next + (s.vaddr % 0x1000));
        next += 0x1000 * (1 + s.data.len() as u64 / 0x1000) + 0x1000;
    }
    for (s, &off) in segs.iter().zip(&offsets) {
        let mut ph = [0u8; 56];
        ph[0..4].copy_from_slice(&s.kind.to_le_bytes());
        ph[4..8].copy_from_slice(&s.flags.to_le_bytes());
        ph[8..16].copy_from_slice(&off.to_le_bytes());
        ph[16..24].copy_from_slice(&s.vaddr.to_le_bytes());
        ph[32..40].copy_from_slice(&(s.data.len() as u64).to_le_bytes());
        ph[40..48].copy_from_slice(&s.memsz.to_le_bytes());
        out.extend_from_slice(&ph);
    }
    for (s, &off) in segs.iter().zip(&offsets) {
        let off = usize::try_from(off).unwrap();
        if out.len() < off {
            out.resize(off, 0);
        }
        out.extend_from_slice(&s.data);
    }
    out
}

fn start<'a>(argv: &'a [Vec<u8>], envp: &'a [Vec<u8>]) -> StartInfo<'a> {
    StartInfo {
        argv,
        envp,
        execfn: b"/prog",
        random: [7; 16],
    }
}

fn simple_exec() -> Vec<u8> {
    build_elf(
        elf::ET_EXEC,
        0x401000,
        &[
            load_seg(elf::PF_R | elf::PF_X, 0x401000, &[0xf4; 16], 16),
            load_seg(elf::PF_R | elf::PF_W, 0x403010, &[1, 2, 3], 0x2000),
        ],
    )
}

#[test]
fn loads_exec_segments_with_permissions_and_bss() {
    let mut mem = AddressSpace::new();
    let image = load_bytes(&simple_exec(), &start(&[b"prog".to_vec()], &[]), &mut mem).unwrap();
    assert_eq!(image.entry_point, GuestAddr(0x401000));
    assert_eq!(image.load_base, GuestAddr(0));
    let mut code = [0u8; 16];
    mem.fetch(GuestAddr(0x401000), &mut code).unwrap();
    assert_eq!(code, [0xf4; 16]);
    assert!(mem.write(GuestAddr(0x401000), &[0]).is_err());
    let mut data = [9u8; 5];
    mem.read(GuestAddr(0x403010), &mut data).unwrap();
    assert_eq!(data, [1, 2, 3, 0, 0]);
    // Break = end of the last segment rounded up to a page.
    assert_eq!(image.initial_break, GuestAddr(0x406000));
    assert_eq!(mem.current_break(), GuestAddr(0x406000));
}

#[test]
fn madv_dontneed_reads_the_data_segment_again_and_zeroes_its_bss() {
    let mut mem = AddressSpace::new();
    load_bytes(&simple_exec(), &start(&[b"prog".to_vec()], &[]), &mut mem).unwrap();
    // The data page (file data at 0x403010) and two bss pages after it.
    mem.write(GuestAddr(0x403010), &[7, 7, 7, 7]).unwrap();
    mem.write(GuestAddr(0x404000), &[8]).unwrap();
    mem.discard_shared(GuestAddr(0x403000), 0x2000).unwrap();
    let mut data = [9u8; 4];
    mem.read(GuestAddr(0x403010), &mut data).unwrap();
    assert_eq!(data, [1, 2, 3, 0]);
    let mut bss = [9u8];
    mem.read(GuestAddr(0x404000), &mut bss).unwrap();
    assert_eq!(bss, [0]);
    // The bss is anonymous memory, as on Linux, so MADV_FREE takes it; the
    // pages that hold file data are a file mapping, which it refuses.
    assert_eq!(
        mem.check_private_anonymous(GuestAddr(0x404000), 0x1000),
        Ok(())
    );
    assert_eq!(
        mem.check_private_anonymous(GuestAddr(0x403000), 0x1000),
        Err(Errno::EINVAL)
    );
    // A read-only segment that mprotect made writable and that was written
    // reads the executable again too.
    mem.protect_shared(
        GuestAddr(0x401000),
        0x1000,
        Prot::READ_WRITE.union(Prot::EXEC),
    )
    .unwrap();
    mem.write(GuestAddr(0x401000), &[0x90, 0x90]).unwrap();
    mem.discard_shared(GuestAddr(0x401000), 0x1000).unwrap();
    let mut code = [0u8; 2];
    mem.fetch(GuestAddr(0x401000), &mut code).unwrap();
    assert_eq!(code, [0xf4; 2]);
}

#[test]
fn segments_keep_only_the_part_of_the_executable_they_load() {
    let mut file = crate::testing::tiny_exec(&[0x90; 32], b"data");
    let loaded = file.len();
    // Sections that no segment loads, such as debug information, follow.
    file.extend(std::iter::repeat_n(0xdb, 3 * PAGE_SIZE as usize));
    let info = elf::parse(&file).unwrap();
    let (span, at) = loaded_span(&file, &info);
    // The span ends with the page that the last data ends in, as the file
    // pages of a mapping do: the pages after it are left out.
    assert!(!span.is_empty());
    assert_eq!(at + span.len(), loaded.next_multiple_of(PAGE_SIZE as usize));
    assert!(at + span.len() < file.len());
}

#[test]
fn static_pie_is_placed_at_fixed_base() {
    let bytes = build_elf(
        elf::ET_DYN,
        0x1000,
        &[load_seg(elf::PF_R | elf::PF_X, 0x1000, &[0x90; 8], 8)],
    );
    let mut mem = AddressSpace::new();
    let image = load_bytes(&bytes, &start(&[], &[]), &mut mem).unwrap();
    assert_eq!(image.load_base, GuestAddr(STATIC_PIE_BASE));
    assert_eq!(image.entry_point, GuestAddr(STATIC_PIE_BASE + 0x1000));
    assert!(
        mem.fetch(GuestAddr(STATIC_PIE_BASE + 0x1000), &mut [0u8; 8])
            .is_ok()
    );
}

fn aux_value(mem: &AddressSpace, mut at: u64, key: u64) -> Option<u64> {
    loop {
        let k = mem.read_u64(GuestAddr(at)).ok()?;
        let v = mem.read_u64(GuestAddr(at + 8)).ok()?;
        if k == key {
            return Some(v);
        }
        if k == auxv::AT_NULL {
            return None;
        }
        at += 16;
    }
}

fn read_c_string(mem: &AddressSpace, at: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    let mut p = at;
    loop {
        mem.read(GuestAddr(p), &mut b).unwrap();
        if b[0] == 0 {
            return out;
        }
        out.push(b[0]);
        p += 1;
    }
}

#[test]
fn initial_stack_has_linux_layout() {
    let argv = [b"prog".to_vec(), b"arg one".to_vec()];
    let envp = [b"A=1".to_vec()];
    let mut mem = AddressSpace::new();
    let image = load_bytes(&simple_exec(), &start(&argv, &envp), &mut mem).unwrap();
    let sp = image.initial_stack_pointer.0;
    assert_eq!(sp % 16, 0);
    assert_eq!(mem.read_u64(GuestAddr(sp)).unwrap(), 2);
    let arg1 = mem.read_u64(GuestAddr(sp + 16)).unwrap();
    assert_eq!(read_c_string(&mem, arg1), b"arg one");
    assert_eq!(mem.read_u64(GuestAddr(sp + 24)).unwrap(), 0);
    let env0 = mem.read_u64(GuestAddr(sp + 32)).unwrap();
    assert_eq!(read_c_string(&mem, env0), b"A=1");
    assert_eq!(mem.read_u64(GuestAddr(sp + 40)).unwrap(), 0);
    let aux = sp + 48;
    assert_eq!(aux_value(&mem, aux, auxv::AT_PAGESZ), Some(4096));
    assert_eq!(aux_value(&mem, aux, auxv::AT_ENTRY), Some(0x401000));
    assert_eq!(aux_value(&mem, aux, auxv::AT_PHNUM), Some(2));
    assert_eq!(aux_value(&mem, aux, auxv::AT_UID), Some(1000));
    let random = aux_value(&mem, aux, auxv::AT_RANDOM).unwrap();
    let mut r = [0u8; 16];
    mem.read(GuestAddr(random), &mut r).unwrap();
    assert_eq!(r, [7; 16]);
    let execfn = aux_value(&mem, aux, auxv::AT_EXECFN).unwrap();
    assert_eq!(read_c_string(&mem, execfn), b"/prog");
}

#[test]
fn rejects_invalid_headers() {
    let mut mem = AddressSpace::new();
    let s = start(&[], &[]);
    assert!(matches!(
        load_bytes(b"not an elf", &s, &mut mem),
        Err(LoadError::Malformed(_))
    ));
    let mut wrong_class = simple_exec();
    wrong_class[4] = 1;
    assert!(matches!(
        load_bytes(&wrong_class, &s, &mut mem),
        Err(LoadError::Malformed(_))
    ));
    let mut wrong_machine = simple_exec();
    wrong_machine[18] = 3;
    assert!(matches!(
        load_bytes(&wrong_machine, &s, &mut mem),
        Err(LoadError::Malformed(_))
    ));
    let mut relocatable = simple_exec();
    relocatable[16] = 1;
    assert!(matches!(
        load_bytes(&relocatable, &s, &mut mem),
        Err(LoadError::Malformed(_))
    ));
}

#[test]
fn rejects_interpreter_and_bad_segments() {
    let mut mem = AddressSpace::new();
    let s = start(&[], &[]);
    let interp = build_elf(
        elf::ET_EXEC,
        0x401000,
        &[
            Seg {
                kind: elf::PT_INTERP,
                flags: 4,
                vaddr: 0x400000,
                data: b"/lib/ld".to_vec(),
                memsz: 7,
            },
            load_seg(elf::PF_R, 0x401000, &[0], 1),
        ],
    );
    assert_eq!(
        load_bytes(&interp, &s, &mut mem),
        Err(LoadError::NotStaticMusl)
    );
    let bad_size = build_elf(
        elf::ET_EXEC,
        0,
        &[load_seg(elf::PF_R, 0x401000, &[0; 8], 4)],
    );
    assert!(matches!(
        load_bytes(&bad_size, &s, &mut mem),
        Err(LoadError::Malformed(_))
    ));
    let low = build_elf(elf::ET_EXEC, 0, &[load_seg(elf::PF_R, 0x1000, &[0; 8], 8)]);
    assert!(matches!(
        load_bytes(&low, &s, &mut AddressSpace::new()),
        Err(LoadError::Malformed(_))
    ));
    let overlapping = build_elf(
        elf::ET_EXEC,
        0,
        &[
            load_seg(elf::PF_R, 0x401000, &[0; 8], 8),
            load_seg(elf::PF_R, 0x401800, &[0; 8], 8),
        ],
    );
    assert_eq!(
        load_bytes(&overlapping, &s, &mut AddressSpace::new()),
        Err(LoadError::Malformed("overlapping segments"))
    );
}

#[test]
fn rejects_images_larger_than_four_gib() {
    // R-01: a crafted ELF must not make the host allocate unbounded memory.
    let huge = build_elf(
        elf::ET_EXEC,
        0,
        &[
            load_seg(elf::PF_R, 0x401000, &[0], 3 << 30),
            load_seg(elf::PF_R, 0x10_0000_0000, &[0], 2 << 30),
        ],
    );
    assert_eq!(
        load_bytes(&huge, &start(&[], &[]), &mut AddressSpace::new()),
        Err(LoadError::TooLarge)
    );
}

#[test]
fn truncated_files_never_panic() {
    let bytes = simple_exec();
    for len in 0..bytes.len() {
        let _ = load_bytes(&bytes[..len], &start(&[], &[]), &mut AddressSpace::new());
    }
}

#[test]
fn loads_from_the_file_system_and_limits_arguments() {
    let mut fs = MemFs::new();
    fs.add_file(GuestFile::new("/prog", simple_exec())).unwrap();
    let s = start(&[], &[]);
    assert!(load(&fs, b"/prog", &s, &mut AddressSpace::new()).is_ok());
    assert_eq!(
        load(&fs, b"/missing", &s, &mut AddressSpace::new()),
        Err(LoadError::NotFound)
    );
    let big = vec![vec![b'x'; usize::try_from(MAX_ARG_BYTES).unwrap()]];
    assert_eq!(
        load(&fs, b"/prog", &start(&big, &[]), &mut AddressSpace::new()),
        Err(LoadError::TooLarge)
    );
    let err: Error = LoadError::NotStaticMusl.into();
    assert_eq!(err.kind, ErrorKind::InvalidProgram);
}

/// The `load_elf` fuzz input that found an overflow in `file_pages`: a
/// writable segment whose file offset sits in its page differently from its
/// address, and starts before that much of the file.
#[test]
fn a_misplaced_writable_segment_loads_or_fails_without_overflow() {
    let data: &[u8] = &[
        6, 122, 129, 192, 37, 171, 64, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
        130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
        130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
        130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 145, 145, 64, 6, 122,
        91, 153, 129, 0, 0,
    ];
    let mut file = crate::testing::tiny_exec(&[0x90; 32], b"data");
    for patch in data[1..].as_chunks::<3>().0 {
        let at = usize::from(u16::from_le_bytes([patch[0], patch[1]])) % file.len();
        file[at] = patch[2];
    }
    let mut mem = AddressSpace::new();
    let _ = load_bytes(&file, &start(&[b"prog".to_vec()], &[]), &mut mem);
}
