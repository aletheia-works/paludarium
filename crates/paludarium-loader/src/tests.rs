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
        ids: [1, 2, 3, 4],
        secure: true,
        program: None,
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
fn a_segment_of_bss_alone_may_name_an_offset_past_the_end_of_the_file() {
    let mut elf = build_elf(
        elf::ET_EXEC,
        0x401000,
        &[
            load_seg(elf::PF_R | elf::PF_X, 0x401000, &[0xf4; 16], 16),
            load_seg(elf::PF_R | elf::PF_W, 0x410000, &[], 0x2000),
        ],
    );
    // The second program header's p_offset, as GNU ld 2.46 aligns it.
    let past = elf.len() as u64 + 0x10000;
    elf[64 + 56 + 8..64 + 56 + 16].copy_from_slice(&past.to_le_bytes());
    let mut mem = AddressSpace::new();
    load_bytes(&elf, &start(&[b"prog".to_vec()], &[]), &mut mem).unwrap();
    let mut bss = [9u8; 4];
    mem.read(GuestAddr(0x410000), &mut bss).unwrap();
    assert_eq!(bss, [0; 4]);
    assert!(
        !load_bytes(&elf, &start(&[], &[]), &mut AddressSpace::new())
            .unwrap()
            .fails
    );
    // One that does take a file byte from there loads too, as Linux maps it,
    // but its bss starts in a page past the end, which `padzero` cannot
    // clear in a writable segment: the exec then fails (SIGSEGV).
    elf[64 + 56 + 32..64 + 56 + 40].copy_from_slice(&1u64.to_le_bytes());
    let mut mem = AddressSpace::new();
    let image = load_bytes(&elf, &start(&[], &[]), &mut mem).unwrap();
    assert!(image.fails);
    assert!(mem.read(GuestAddr(0x410000), &mut bss).unwrap_err().bus);
}

/// The simple program of three pages: text in the first, at 0x401000, and a
/// writable page of data with bss, at 0x403000, from offset 0x2000.
fn three_pages(data_flags: u32) -> Vec<u8> {
    build_elf(
        elf::ET_EXEC,
        0x401000,
        &[
            load_seg(elf::PF_R | elf::PF_X, 0x401000, &[0xf4; 0x1800], 0x1800),
            load_seg(data_flags, 0x404010, &[5; 16], 0x2000),
        ],
    )
}

#[test]
fn a_file_cut_short_maps_as_linux_maps_it() {
    let full = three_pages(elf::PF_R | elf::PF_W);
    let data_at = 0x4010;
    assert_eq!(full.len(), data_at + 16);
    let load = |bytes: &[u8]| {
        let mut mem = AddressSpace::new();
        let image = load_bytes(bytes, &start(&[], &[]), &mut mem).unwrap();
        (mem, image.fails)
    };
    // Cut within the data's page: what is left reads as it was, the rest
    // of the page as zero, and the bss is cleared.
    let (mem, fails) = load(&full[..data_at + 8]);
    assert!(!fails);
    let mut data = [9u8; 20];
    mem.read(GuestAddr(0x404010), &mut data).unwrap();
    assert_eq!(data[..8], [5; 8]);
    assert_eq!(data[8..], [0; 12]);
    // Cut before the data's page: its writable bss cannot be cleared.
    let (_, fails) = load(&full[..0x4000]);
    assert!(fails);
    // With the data read-only, that is no failure: the text's second page
    // is past the end too, and raises SIGBUS when touched, while its first
    // page still holds the code.
    let read_only = three_pages(elf::PF_R);
    let (mem, fails) = load(&read_only[..0x2000]);
    assert!(!fails);
    let mut code = [0u8; 4];
    mem.fetch(GuestAddr(0x401000), &mut code).unwrap();
    assert_eq!(code, [0xf4; 4]);
    let fault = mem.fetch(GuestAddr(0x402000), &mut code).unwrap_err();
    assert!(fault.bus && fault.fetch);
    assert!(mem.read(GuestAddr(0x404010), &mut code).unwrap_err().bus);
    // The program headers past the end are no program.
    assert!(matches!(
        load_bytes(&full[..64 + 56], &start(&[], &[]), &mut AddressSpace::new()),
        Err(LoadError::Malformed(_))
    ));
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
fn segments_map_the_executable_by_its_path_at_their_file_offsets() {
    let mut fs = MemFs::new();
    fs.add_file(GuestFile::new("/prog", simple_exec())).unwrap();
    let mut mem = AddressSpace::new();
    load(&fs, b"/./prog", &start(&[], &[]), &mut mem).unwrap();
    let file = |at: u64| mem.mapped_file(GuestAddr(at));
    let code = file(0x401000).unwrap();
    assert_eq!(code.name.as_deref(), Some(&b"/prog"[..]));
    assert_eq!(code.offset, 0x1000);
    // The data's page starts its page of the file, and the bss past it is
    // anonymous memory.
    assert_eq!(file(0x403000).unwrap().offset, 0x3000);
    assert_eq!(file(0x404000), None);
    // An image from memory has no path.
    let mut mem = AddressSpace::new();
    load_bytes(&simple_exec(), &start(&[], &[]), &mut mem).unwrap();
    assert_eq!(mem.mapped_file(GuestAddr(0x401000)).unwrap().name, None);
    // A `Named` keep names them as it is asked, each time.
    let deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&deleted);
    let keep: Keep = Arc::new(Named {
        name: Arc::new(move || {
            Some(if seen.load(std::sync::atomic::Ordering::SeqCst) {
                b"/real (deleted)".to_vec()
            } else {
                b"/real".to_vec()
            })
        }),
        keep: None,
    });
    let mut mem = AddressSpace::new();
    let named = StartInfo {
        program: Some(&keep),
        ..start(&[], &[])
    };
    load(&fs, b"/prog", &named, &mut mem).unwrap();
    let name = |mem: &AddressSpace| mem.view().vma_from(0x401000).unwrap().file.unwrap().name;
    assert_eq!(name(&mem).as_deref(), Some(&b"/real"[..]));
    deleted.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(name(&mem).as_deref(), Some(&b"/real (deleted)"[..]));
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
    // The vDSO comes first (`ARCH_DLINFO`).
    assert_eq!(mem.read_u64(GuestAddr(aux)).unwrap(), auxv::AT_SYSINFO_EHDR);
    let vdso = mem.read_u64(GuestAddr(aux + 8)).unwrap();
    assert_eq!(vdso, image.vdso);
    let mut magic = [0; 4];
    mem.read(GuestAddr(vdso), &mut magic).unwrap();
    assert_eq!(&magic, b"\x7fELF");
    assert_eq!(aux_value(&mem, aux, auxv::AT_PAGESZ), Some(4096));
    assert_eq!(aux_value(&mem, aux, auxv::AT_ENTRY), Some(0x401000));
    assert_eq!(aux_value(&mem, aux, auxv::AT_PHNUM), Some(2));
    // The IDs and the secure flag are those the exec gives.
    for (key, value) in [
        (auxv::AT_UID, 1),
        (auxv::AT_EUID, 2),
        (auxv::AT_GID, 3),
        (auxv::AT_EGID, 4),
        (auxv::AT_SECURE, 1),
    ] {
        assert_eq!(aux_value(&mem, aux, key), Some(value));
    }
    let random = aux_value(&mem, aux, auxv::AT_RANDOM).unwrap();
    let mut r = [0u8; 16];
    mem.read(GuestAddr(random), &mut r).unwrap();
    assert_eq!(r, [7; 16]);
    let execfn = aux_value(&mem, aux, auxv::AT_EXECFN).unwrap();
    assert_eq!(read_c_string(&mem, execfn), b"/prog");
}

/// `[vvar]`, `[vvar_vclock]` and `[vdso]` are three VMAs, one after the
/// other, right below the interpreter's.
#[test]
fn the_vdso_and_its_data_lie_together_below_the_interpreter() {
    let fs = files(&[
        ("/prog", asks_for(elf::ET_EXEC, 0x401000, b"/ld\0")),
        ("/ld", linker()),
    ]);
    let mut mem = AddressSpace::new();
    let image = load_with(&fs, b"/prog", &start(&[], &[]), &mut mem, &mut |name| {
        Ok((name.to_vec(), None))
    })
    .unwrap();
    let vvar = image.vdso - 6 * PAGE_SIZE;
    let mut at = vvar;
    for (name, pages, prot) in [
        (b"[vvar]".as_slice(), 4, Prot::READ),
        (b"[vvar_vclock]", 2, Prot::READ),
        (b"[vdso]", 2, Prot::READ_EXEC),
    ] {
        let vma = mem.view().vma_from(at).unwrap();
        assert_eq!((vma.start, vma.end), (at, at + pages * PAGE_SIZE));
        assert_eq!((vma.prot, vma.shared, vma.identity), (prot, false, (0, 0)));
        assert_eq!(vma.file.unwrap().name.as_deref(), Some(name));
        at = vma.end;
    }
    // The interpreter's first segment is at 0x1000.
    assert_eq!(at, image.interpreter_base + 0x1000);
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

/// A program of `kind` that asks for the interpreter `path`, bytes and all.
fn asks_for(kind: u16, entry: u64, path: &[u8]) -> Vec<u8> {
    build_elf(
        kind,
        entry,
        &[
            Seg {
                kind: elf::PT_INTERP,
                flags: 4,
                vaddr: 0x400000,
                data: path.to_vec(),
                memsz: path.len() as u64,
            },
            load_seg(elf::PF_R | elf::PF_X, 0x401000, &[0xf4; 16], 16),
        ],
    )
}
fn linker() -> Vec<u8> {
    build_elf(
        elf::ET_DYN,
        0x1000,
        &[load_seg(elf::PF_R | elf::PF_X, 0x1000, &[0x90; 16], 16)],
    )
}
fn files(entries: &[(&str, Vec<u8>)]) -> MemFs {
    let mut fs = MemFs::new();
    for (name, bytes) in entries {
        fs.add_file(GuestFile::new(*name, bytes.clone())).unwrap();
    }
    fs
}
#[test]
fn a_program_starts_in_its_interpreter_and_the_auxiliary_vector_says_so() {
    let fs = files(&[
        ("/prog", asks_for(elf::ET_EXEC, 0x401000, b"/ld\0")),
        ("/ld", linker()),
    ]);
    let mut mem = AddressSpace::new();
    let image = load(&fs, b"/prog", &start(&[], &[]), &mut mem).unwrap();
    let at = image.interpreter_base;
    assert_ne!(at, 0);
    assert!(at.is_multiple_of(PAGE_SIZE));
    assert!(at < paludarium_mmu::DEFAULT_MMAP_TOP);
    assert_eq!(image.entry_point, GuestAddr(at + 0x1000));
    assert_eq!(image.program_entry, GuestAddr(0x401000));
    // Its bytes are there, and the program's too.
    let mut byte = [0];
    mem.read(GuestAddr(at + 0x1000), &mut byte).unwrap();
    assert_eq!(byte, [0x90]);
    mem.read(GuestAddr(0x401000), &mut byte).unwrap();
    assert_eq!(byte, [0xf4]);
    // The break follows the program.
    assert_eq!(image.initial_break, GuestAddr(0x402000));
    // After argc and the two empty lists.
    let aux = image.initial_stack_pointer.0 + 24;
    assert_eq!(aux_value(&mem, aux, auxv::AT_BASE), Some(at));
    assert_eq!(aux_value(&mem, aux, auxv::AT_ENTRY), Some(0x401000));
}
#[test]
fn what_an_interpreter_check_keeps_lasts_as_long_as_the_interpreter_is_mapped() {
    let fs = files(&[
        ("/prog", asks_for(elf::ET_EXEC, 0x401000, b"/ld\0")),
        ("/ld", linker()),
    ]);
    let keep: Keep = Arc::new(());
    let kept = || Arc::strong_count(&keep) - 1;
    let mut mem = AddressSpace::new();
    let image = load_with(&fs, b"/prog", &start(&[], &[]), &mut mem, &mut |name| {
        Ok((name.to_vec(), Some(Arc::clone(&keep))))
    })
    .unwrap();
    assert_ne!(kept(), 0);
    // A fork's copy of the mappings keeps it too; the program's own
    // segments never did.
    let forked = mem.fork();
    mem.unmap(GuestAddr(0x401000), PAGE_SIZE).unwrap();
    let interpreter = GuestAddr(image.interpreter_base + 0x1000);
    mem.unmap(interpreter, PAGE_SIZE).unwrap();
    assert_ne!(kept(), 0);
    drop(forked);
    assert_eq!(kept(), 0);
}
#[test]
fn a_program_with_no_interpreter_has_no_base_and_starts_at_its_entry() {
    let fs = files(&[("/prog", simple_exec())]);
    let mut mem = AddressSpace::new();
    let image = load(&fs, b"/prog", &start(&[], &[]), &mut mem).unwrap();
    assert_eq!(image.interpreter_base, 0);
    assert_eq!(image.entry_point, image.program_entry);
}
#[test]
fn an_interpreter_path_and_file_are_checked_as_linux_does() {
    let try_load = |program: Vec<u8>, ld: &[u8]| {
        let fs = files(&[("/prog", program), ("/ld", ld.to_vec())]);
        load(&fs, b"/prog", &start(&[], &[]), &mut AddressSpace::new()).err()
    };
    let exec = |path: &[u8]| asks_for(elf::ET_EXEC, 0x401000, path);
    let linker = linker();
    let refused = |error| Some(LoadError::Interpreter(error));
    // The path: at least 2 bytes, ending in a zero; an inner zero ends it.
    assert!(matches!(
        try_load(exec(b"\0"), &linker),
        Some(LoadError::Malformed(_))
    ));
    assert!(matches!(
        try_load(exec(b"/ld"), &linker),
        Some(LoadError::Malformed(_))
    ));
    assert_eq!(try_load(exec(b"/ld\0xx\0"), &linker), None);
    assert_eq!(try_load(exec(b"/none\0"), &linker), refused(Errno::ENOENT));
    // The file: too short to read, or no x86-64 program.
    assert_eq!(try_load(exec(b"/ld\0"), b"short"), refused(Errno(5)));
    assert_eq!(try_load(exec(b"/ld\0"), &[b'#'; 200]), refused(Errno(80)));
    // A check that refuses comes before the file is read.
    let fs = files(&[("/prog", exec(b"/ld\0")), ("/ld", linker.clone())]);
    let mut mem = AddressSpace::new();
    assert_eq!(
        load_with(&fs, b"/prog", &start(&[], &[]), &mut mem, &mut |name| {
            assert_eq!(name, b"/ld");
            Err(Errno::EACCES)
        }),
        Err(LoadError::Interpreter(Errno::EACCES))
    );
    assert_eq!(mem.mappings().count(), 0, "nothing was mapped");
}
#[test]
fn a_position_dependent_interpreter_stays_where_it_says() {
    let ld = build_elf(
        elf::ET_EXEC,
        0x70_0000,
        &[load_seg(elf::PF_R | elf::PF_X, 0x70_0000, &[0x90; 16], 16)],
    );
    let fs = files(&[
        ("/prog", asks_for(elf::ET_EXEC, 0x401000, b"/ld\0")),
        ("/ld", ld),
    ]);
    let mut mem = AddressSpace::new();
    let image = load(&fs, b"/prog", &start(&[], &[]), &mut mem).unwrap();
    assert_eq!(image.entry_point, GuestAddr(0x70_0000));
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
                data: b"/lib/ld\0".to_vec(),
                memsz: 8,
            },
            load_seg(elf::PF_R, 0x401000, &[0], 1),
        ],
    );
    // Bytes in memory have no file system to find an interpreter in.
    assert_eq!(
        load_bytes(&interp, &s, &mut mem),
        Err(LoadError::Interpreter(Errno::ENOENT))
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
    let err: Error = LoadError::Interpreter(Errno::ENOENT).into();
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

#[test]
fn the_code_and_data_ranges_are_load_elf_binarys() {
    let header = |flags, vaddr, filesz| elf::ProgramHeader {
        kind: elf::PT_LOAD,
        flags,
        offset: 0,
        vaddr,
        filesz,
        memsz: filesz + 0x100,
        align: 0x1000,
    };
    let info = elf::ElfInfo {
        kind: 2,
        entry: 0,
        phoff: 0,
        phnum: 3,
        headers: vec![
            header(elf::PF_R, 0x40_0000, 0x200),
            header(elf::PF_R | elf::PF_X, 0x40_1000, 0x300),
            header(elf::PF_R | elf::PF_W, 0x40_3000, 0x40),
        ],
    };
    // Code: the executable segments; data: the highest start and end of
    // any, in the file (`p_filesz`), moved by the base.
    assert_eq!(code_range(&info, 0x1000), (0x40_2000, 0x40_2300));
    assert_eq!(data_range(&info, 0x1000), (0x40_4000, 0x40_4040));
    let none = elf::ElfInfo {
        headers: Vec::new(),
        ..info
    };
    assert_eq!(data_range(&none, 7), (7, 7));
}
