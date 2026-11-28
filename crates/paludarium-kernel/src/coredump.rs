//! Core dumps, as Linux's `do_coredump` writes them with the default
//! `core_pattern` (`core`): an ELF core file named `core` in the working
//! directory of a process that a core-dumping signal ends, when the process
//! is dumpable and its RLIMIT_CORE soft limit is at least one page. The core
//! has one `PT_NOTE` segment (each thread's registers, the process, the
//! fatal signal, the auxiliary vector and the mapped files) and one
//! `PT_LOAD` segment per VMA, whose contents follow the space's
//! `coredump_filter`, and the `vsyscall` page's, which holds zeros. It has
//! no `NT_X86_XSTATE` note, as Linux writes none on a CPU without XSAVE,
//! which the virtual CPU is. A core larger than the limit is cut there; it
//! still counts as dumped, as Linux's binfmt_elf reports a core once it has
//! started to write it.
use crate::signals;
use paludarium_cpu::segments;
use paludarium_cpu::{CpuState, FX_WRITTEN, reg};
use paludarium_mmu::{AddressSpace, Mapping, MappingKind, Prot, vm};
use paludarium_types::GuestAddr;

/// The signals whose default action dumps core (Linux's
/// `SIG_KERNEL_COREDUMP_MASK`): SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS,
/// SIGFPE, SIGSEGV, SIGXCPU, SIGXFSZ and SIGSYS.
pub(crate) fn dumps_core(signal: i32) -> bool {
    matches!(signal, 3..=8 | 11 | 24 | 25 | 31)
}
/// The smallest RLIMIT_CORE that lets a core be written: binfmt_elf's
/// `min_coredump`, one page.
pub(crate) const MIN_LIMIT: u64 = PAGE;
const PAGE: u64 = 4096;

/// A thread's state when it ended, for its `NT_PRSTATUS` note.
pub(crate) struct ThreadCore {
    pub tid: u32,
    pub cpu: CpuState,
    /// Its own pending signals and its blocked ones, as bit sets.
    pub pending: u64,
    pub blocked: u64,
    pub name: [u8; 16],
}

/// A core dump under way: started by the thread that took the fatal signal,
/// completed by the last thread of the process to end.
pub(crate) struct Dump {
    pub signal: i32,
    pub dumper: u32,
    pub siginfo: [u8; 128],
    pub limit: u64,
    pub threads: Vec<ThreadCore>,
    /// The credentials of the thread the signal ended, which make the file.
    pub credentials: crate::credentials::Credentials,
    /// The `clear_child_tid` words of the threads that have ended, which
    /// Linux clears only after the dump.
    pub clear_tids: Vec<u64>,
    /// The robust lists of those threads, with their IDs, which Linux walks
    /// only after the dump too.
    pub robust_lists: Vec<(u32, u64)>,
}

/// The process's identity and times, in `NT_PRSTATUS` and `NT_PRPSINFO`.
pub(crate) struct Identity {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub sid: u32,
    /// The real IDs of the process's leader, as Linux's `fill_psinfo` reads.
    pub uid: u32,
    pub gid: u32,
    /// CPU time of the process and of its waited-for children, in ns.
    pub cpu: u64,
    pub children_cpu: u64,
    /// The initial stack pointer, where argc, argv, envp and the
    /// auxiliary vector start.
    pub start_stack: u64,
    /// The auxiliary vector its exec saved, which `NT_AUXV` holds (Linux's
    /// `mm->saved_auxv`, whatever the program did to its stack).
    pub auxv: Vec<u8>,
    /// The process's PID namespace, which numbers the IDs the core shows
    /// (Linux's `task_pid_vnr` of the dumping task).
    pub space: std::sync::Arc<crate::namespaces::Namespace>,
}
impl Identity {
    fn number(&self, id: u32) -> u32 {
        self.space.number(id)
    }
}

/// Writes the core, of a process whose root is `root`, through `emit`, in
/// the pieces Linux writes it in, and
/// returns whether all of it fit under the limit and was written. A piece that would pass
/// the limit is not written, nor anything after it.
pub(crate) fn write(
    dump: &Dump,
    who: &Identity,
    mem: &AddressSpace,
    root: &[u8],
    emit: &mut dyn FnMut(&[u8]) -> bool,
) -> bool {
    let mappings: Vec<Mapping> = mem.mappings().collect();
    let first_elf = mappings
        .iter()
        .find(|m| m.kind == MappingKind::ElfSegment)
        .map(|m| m.start);
    // One segment for each Linux VMA, which may hold adjacent mappings
    // merged.
    let mut segments: Vec<(Mapping, u64)> = Vec::new();
    let filter = mem.dump_filter();
    for &m in &mappings {
        if segments
            .last()
            .is_some_and(|(vma, _)| m.start.0 < vma.end())
        {
            continue;
        }
        let (start, length) = mem.vma_at(m.start).unwrap_or((m.start, m.length));
        let vma = Mapping { start, length, ..m };
        segments.push((
            vma,
            dump_length(mem, &vma, first_elf == Some(start), filter),
        ));
    }
    let vmas: Vec<Mapping> = segments.iter().map(|&(vma, _)| vma).collect();
    let notes = notes(dump, who, mem, &files(mem, &vmas, root));
    let count = segments.len() + 2;
    let notes_offset = 64 + 56 * count as u64;
    let notes_size: u64 = notes.iter().map(|n| n.len() as u64).sum();
    // The memory starts at the next page, as Linux aligns it.
    let data_offset = (notes_offset + notes_size).next_multiple_of(PAGE);
    let mut written = 0u64;
    let mut put = |piece: &[u8]| {
        if written + piece.len() as u64 > dump.limit {
            return false;
        }
        written += piece.len() as u64;
        emit(piece)
    };
    if !put(&header(count)) {
        return false;
    }
    if !put(&program_header(4, 0, notes_offset, 0, notes_size, 0, 4)) {
        return false;
    }
    let mut offset = data_offset;
    for (mapping, length) in &segments {
        // PF_R, PF_W and PF_X.
        let flags = (u32::from(mapping.prot.contains(Prot::READ)) << 2)
            | (u32::from(mapping.prot.contains(Prot::WRITE)) << 1)
            | u32::from(mapping.prot.contains(Prot::EXEC));
        let header = program_header(
            1,
            flags,
            offset,
            mapping.start.0,
            *length,
            mapping.length,
            PAGE,
        );
        if !put(&header) {
            return false;
        }
        offset += length;
    }
    // The gate area, last and whole (`always_dump_vma`); with no page behind
    // it, its part of the file is a hole.
    let gate = program_header(1, 1, offset, crate::vsyscall::START, PAGE, PAGE, PAGE);
    if !put(&gate) {
        return false;
    }
    for note in &notes {
        if !put(note) {
            return false;
        }
    }
    let padding = vec![0; usize::try_from(data_offset - notes_offset - notes_size).unwrap_or(0)];
    if !padding.is_empty() && !put(&padding) {
        return false;
    }
    let mut page = vec![0u8; PAGE as usize];
    for (mapping, length) in &segments {
        let mut at = 0;
        while at < *length {
            let size = (*length - at).min(PAGE) as usize;
            // Read whatever the protection, as Linux reads with FOLL_FORCE;
            // a page that still cannot be read is written as zeros, as Linux
            // skips it in the file.
            page[..size].fill(0);
            let _ = mem.read_for_core(GuestAddr(mapping.start.0 + at), &mut page[..size]);
            if !put(&page[..size]) {
                return false;
            }
            at += size as u64;
        }
    }
    page.fill(0);
    put(&page)
}

/// The bits of `coredump_filter` (Linux's `MMF_DUMP_*`).
const ANON_PRIVATE: u32 = 1 << 0;
const ANON_SHARED: u32 = 1 << 1;
const MAPPED_PRIVATE: u32 = 1 << 2;
const MAPPED_SHARED: u32 = 1 << 3;
const ELF_HEADERS: u32 = 1 << 4;
const HUGETLB_PRIVATE: u32 = 1 << 5;
const HUGETLB_SHARED: u32 = 1 << 6;

/// How much of a mapping the core holds, by the space's `coredump_filter`
/// `filter`, as Linux's `vma_dump_size` asks in turn: a special mapping
/// whole; nothing of one `MADV_DONTDUMP` marked; a hugetlb mapping whole
/// for its hugetlb bit; nothing of an I/O mapping; a shared mapping whole
/// for its anonymous bit when no name links its file (an anonymous one, a
/// memfd, a file unlinked since), else for its file-backed one; a private
/// mapping whole for the anonymous bit once a page of its VMA was written
/// (its `anon_vma`), else, for a file mapping, whole for the file-backed
/// bit, else its first page with the ELF headers bit when it is readable,
/// starts at the file's start and the file is executable now or starts with
/// the ELF magic. Of a loaded program, the stack and a writable
/// segment count as written, and the first page of its image is its ELF
/// header. Only the ELF headers ask for a mapping that can be read
/// (`VM_READ`): Linux reads the rest whatever its protection.
fn dump_length(mem: &AddressSpace, mapping: &Mapping, first_elf: bool, filter: u32) -> u64 {
    // A special mapping, which names itself (the vDSO and its data), is
    // dumped whole, as Linux's `always_dump_vma` finds its `vm_ops->name`
    // before `vma_dump_size` looks at VM_DONTDUMP; its pages that cannot be
    // read are zeros.
    if special_mapping(mem, mapping.start) {
        return mapping.length;
    }
    // MADV_DONTDUMP leaves out what else is always dumped.
    if mapping.dont_dump {
        return 0;
    }
    let whole = |bit: u32| if filter & bit != 0 { mapping.length } else { 0 };
    let readable = mapping.prot.contains(Prot::READ);
    let writable = mapping.prot.contains(Prot::WRITE);
    let header = |at_start: bool| {
        if filter & ELF_HEADERS != 0 && at_start && readable {
            mapping.length.min(PAGE)
        } else {
            0
        }
    };
    match mapping.kind {
        MappingKind::Stack => whole(ANON_PRIVATE),
        MappingKind::ElfSegment if writable && filter & ANON_PRIVATE != 0 => mapping.length,
        MappingKind::ElfSegment if filter & MAPPED_PRIVATE != 0 => mapping.length,
        MappingKind::ElfSegment => header(first_elf),
        _ => {
            let flags = mem
                .view()
                .vma_source(mapping.start.0)
                .map_or(0, |source| source.vma_flags(0));
            let state = mem.core_state(mapping.start);
            if flags & vm::HUGETLB != 0 {
                whole(if state.shared {
                    HUGETLB_SHARED
                } else {
                    HUGETLB_PRIVATE
                })
            } else if flags & vm::IO != 0 {
                0
            } else if state.shared {
                whole(if state.linked {
                    MAPPED_SHARED
                } else {
                    ANON_SHARED
                })
            } else if state.written && filter & ANON_PRIVATE != 0 {
                mapping.length
            } else if mapping.kind != MappingKind::File {
                0
            } else if filter & MAPPED_PRIVATE != 0 {
                mapping.length
            } else {
                // `vma_dump_size` takes the page of a file with an execute
                // bit as it is; only of another one does `dump_vma_snapshot`
                // look for the magic, as an ELF library need not be
                // executable.
                header(
                    state.file_offset == Some(0)
                        && (state.executable || elf_header(mem, mapping.start)),
                )
            }
        }
    }
}
/// Whether the mapping at `at` is one of Linux's special mappings, whose
/// name is in brackets (`[vvar]`, `[vvar_vclock]`, `[vdso]`).
fn special_mapping(mem: &AddressSpace, at: GuestAddr) -> bool {
    mem.view()
        .vma_source(at.0)
        .and_then(|source| source.name())
        .is_some_and(|name| name.first() == Some(&b'['))
}
/// Whether the mapping at `at` starts with the ELF magic, as Linux's
/// `dump_vma_snapshot` checks a file mapping whose file is not executable,
/// which may be a library's.
fn elf_header(mem: &AddressSpace, at: GuestAddr) -> bool {
    let mut magic = [0u8; 4];
    mem.read(at, &mut magic).is_ok() && magic == *b"\x7fELF"
}

fn header(count: usize) -> [u8; 64] {
    let mut h = [0u8; 64];
    h[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    put16(&mut h, 16, 4); // ET_CORE
    put16(&mut h, 18, 62); // EM_X86_64
    put32(&mut h, 20, 1);
    put64(&mut h, 32, 64); // e_phoff
    put16(&mut h, 52, 64); // e_ehsize
    put16(&mut h, 54, 56); // e_phentsize
    put16(&mut h, 56, u16::try_from(count).unwrap_or(u16::MAX));
    put16(&mut h, 58, 64); // e_shentsize
    h
}

fn program_header(
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
) -> [u8; 56] {
    let mut p = [0u8; 56];
    put32(&mut p, 0, kind);
    put32(&mut p, 4, flags);
    put64(&mut p, 8, offset);
    put64(&mut p, 16, address);
    put64(&mut p, 32, file_size);
    put64(&mut p, 40, memory_size);
    put64(&mut p, 48, align);
    p
}

/// The notes, as Linux orders them: for each thread, the one that took the
/// signal first, its `NT_PRSTATUS`; after the first thread's, `NT_PRPSINFO`,
/// `NT_SIGINFO`, `NT_AUXV` and `NT_FILE` (`files`); then the thread's
/// `NT_FPREGSET`.
fn notes(dump: &Dump, who: &Identity, mem: &AddressSpace, files: &[u8]) -> Vec<Vec<u8>> {
    let mut threads: Vec<&ThreadCore> = dump.threads.iter().collect();
    threads.sort_by_key(|t| (t.tid != dump.dumper, t.tid));
    let mut notes = Vec::new();
    for (index, thread) in threads.iter().enumerate() {
        notes.push(note(b"CORE", 1, &prstatus(dump, who, thread)));
        if index == 0 {
            notes.push(note(b"CORE", 3, &prpsinfo(who, thread, mem)));
            notes.push(note(b"CORE", 0x5349_4749, &dump.siginfo));
            notes.push(note(b"CORE", 6, &who.auxv));
            notes.push(note(b"CORE", 0x4649_4c45, files));
        }
        notes.push(note(b"CORE", 2, &fpregset(&thread.cpu)));
    }
    notes
}

fn note(name: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
    let mut n = Vec::with_capacity(12 + 8 + desc.len() + 3);
    n.extend_from_slice(&u32::try_from(name.len() + 1).unwrap_or(0).to_le_bytes());
    n.extend_from_slice(&u32::try_from(desc.len()).unwrap_or(0).to_le_bytes());
    n.extend_from_slice(&kind.to_le_bytes());
    n.extend_from_slice(name);
    n.push(0);
    n.resize(n.len().next_multiple_of(4), 0);
    n.extend_from_slice(desc);
    n.resize(n.len().next_multiple_of(4), 0);
    n
}

/// `struct elf_prstatus` (336 bytes) of x86-64.
fn prstatus(dump: &Dump, who: &Identity, thread: &ThreadCore) -> [u8; 336] {
    let mut s = [0u8; 336];
    put32(&mut s, 0, dump.signal as u32); // pr_info.si_signo
    put16(&mut s, 12, dump.signal as u16); // pr_cursig
    put64(&mut s, 16, thread.pending);
    put64(&mut s, 24, thread.blocked);
    put32(&mut s, 32, who.number(thread.tid));
    put32(&mut s, 36, who.number(who.ppid));
    put32(&mut s, 40, who.number(who.pgrp));
    put32(&mut s, 44, who.number(who.sid));
    // The leader reports the whole process's time, as Linux does.
    if thread.tid == who.pid {
        put_time(&mut s, 48, who.cpu);
        put_time(&mut s, 80, who.children_cpu);
    }
    let c = &thread.cpu;
    let g = |r: usize| c.gpr[r];
    let sel = |n: usize| u64::from(c.segments[n]);
    let registers = [
        g(reg::R15),
        g(reg::R14),
        g(reg::R13),
        g(reg::R12),
        g(reg::RBP),
        g(reg::RBX),
        g(reg::R11),
        g(reg::R10),
        g(reg::R9),
        g(reg::R8),
        g(reg::RAX),
        g(reg::RCX),
        g(reg::RDX),
        g(reg::RSI),
        g(reg::RDI),
        u64::MAX, // orig_rax: not in a system call
        c.rip.0,
        sel(segments::CS),
        c.rflags,
        g(reg::RSP),
        sel(segments::SS),
        c.fs_base,
        c.gs_base,
        sel(segments::DS),
        sel(segments::ES),
        sel(segments::FS),
        sel(segments::GS),
    ];
    for (i, value) in registers.iter().enumerate() {
        put64(&mut s, 112 + 8 * i, *value);
    }
    put32(&mut s, 328, 1); // pr_fpvalid
    s
}

/// `struct elf_prpsinfo` (136 bytes): the process running, with its IDs,
/// its name and up to 79 bytes of its arguments, separated by spaces.
fn prpsinfo(who: &Identity, thread: &ThreadCore, mem: &AddressSpace) -> [u8; 136] {
    let mut s = [0u8; 136];
    s[1] = b'R';
    put32(&mut s, 16, who.uid);
    put32(&mut s, 20, who.gid);
    put32(&mut s, 24, who.number(who.pid));
    put32(&mut s, 28, who.number(who.ppid));
    put32(&mut s, 32, who.number(who.pgrp));
    put32(&mut s, 36, who.number(who.sid));
    s[40..56].copy_from_slice(&thread.name);
    let mut args = arguments(who, mem);
    args.truncate(79);
    for byte in &mut args {
        if *byte == 0 {
            *byte = b' ';
        }
    }
    s[56..56 + args.len()].copy_from_slice(&args);
    s
}

/// Where the arguments and the environment strings lie, as Linux's
/// `arg_start`..`arg_end` and `env_start`..`env_end`: from the first string's
/// address to past the last one's NUL, read from the vectors the initial
/// stack at `start_stack` holds, in a space that `memory` reads, which tells
/// whether it could. Empty ranges at 0 when they cannot be read.
pub(crate) fn string_ranges_in(
    memory: &dyn Fn(u64, &mut [u8]) -> bool,
    start_stack: u64,
) -> ((u64, u64), (u64, u64)) {
    let read = |at: u64| {
        let mut word = [0; 8];
        memory(at, &mut word).then(|| u64::from_le_bytes(word))
    };
    let end_of = |start: u64| {
        let mut end = start;
        let mut byte = [1u8];
        while byte[0] != 0 && end - start < 1 << 17 {
            if !memory(end, &mut byte) {
                return None;
            }
            end += 1;
        }
        Some(end)
    };
    // A vector of pointers from `at` to its NULL: its first and last string.
    let vector = |at: u64| -> Option<(u64, u64)> {
        let first = read(at)?;
        if first == 0 {
            return None;
        }
        let mut last = first;
        for i in 1..(1 << 16) {
            match read(at + 8 * i)? {
                0 => break,
                pointer => last = pointer,
            }
        }
        Some((first, end_of(last)?))
    };
    let Some(count) = read(start_stack).filter(|&count| count <= 1 << 20) else {
        return ((0, 0), (0, 0));
    };
    let arguments = vector(start_stack + 8).unwrap_or((0, 0));
    // With no environment, Linux's range is empty where the arguments end.
    let environment = vector(start_stack + 8 * (count + 2)).unwrap_or((arguments.1, arguments.1));
    (arguments, environment)
}

/// The bytes from the first argument to the end of the last one, each
/// ending in its NUL, as Linux's `arg_start` to `arg_end`.
fn arguments(who: &Identity, mem: &AddressSpace) -> Vec<u8> {
    let read = |at: u64| mem.read_u64(GuestAddr(at)).ok();
    let Some(count) = read(who.start_stack) else {
        return Vec::new();
    };
    if count == 0 || count > 1 << 20 {
        return Vec::new();
    }
    let (Some(first), Some(last)) = (read(who.start_stack + 8), read(who.start_stack + 8 * count))
    else {
        return Vec::new();
    };
    let mut end = last;
    let mut byte = [1u8];
    while byte[0] != 0 && end - last < 1 << 17 {
        if mem.read(GuestAddr(end), &mut byte).is_err() {
            return Vec::new();
        }
        end += 1;
    }
    let mut args = vec![
        0;
        usize::try_from(end.saturating_sub(first))
            .unwrap_or(0)
            .min(1 << 17)
    ];
    if mem.read(GuestAddr(first), &mut args).is_err() {
        return Vec::new();
    }
    args
}

/// The `NT_FILE` note of the VMAs that map a file, as Linux's
/// `fill_files_note` lists them: their count, the page size, the start,
/// end and page offset in its file of each, then their paths. Shared
/// anonymous memory maps the file Linux names `/dev/zero (deleted)`. A path
/// is as `d_path` gives it: from `root` when it is under it, else from the
/// machine's root.
fn files(mem: &AddressSpace, vmas: &[Mapping], root: &[u8]) -> Vec<u8> {
    let mut count = 0u64;
    let mut ranges = Vec::new();
    let mut names = Vec::new();
    for vma in vmas {
        let Some(file) = mem.mapped_file(vma.start) else {
            continue;
        };
        let name = match file.name {
            Some(name) => crate::files::seen_from(root, &name).unwrap_or(name),
            None if !file.source => b"/dev/zero (deleted)".to_vec(),
            None => continue,
        };
        for value in [vma.start.0, vma.end(), file.offset / PAGE] {
            ranges.extend_from_slice(&value.to_le_bytes());
        }
        names.extend_from_slice(&name);
        names.push(0);
        count += 1;
    }
    [
        &count.to_le_bytes()[..],
        &PAGE.to_le_bytes(),
        &ranges,
        &names,
    ]
    .concat()
}

/// `struct user_i387_struct` (512 bytes, the `fxsave` layout).
fn fpregset(cpu: &CpuState) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[..FX_WRITTEN].copy_from_slice(&cpu.fx_image());
    f
}

fn put_time(b: &mut [u8], at: usize, ns: u64) {
    put64(b, at, ns / 1_000_000_000);
    put64(b, at + 8, ns % 1_000_000_000 / 1000);
}
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The siginfo of a fatal signal that has none of its own: one the kernel
/// raises itself (`SI_KERNEL`).
pub(crate) fn kernel_siginfo(state: &crate::ThreadState, signal: i32) -> [u8; 128] {
    signals::siginfo(
        state,
        &signals::PendingSignal::user(signal, signals::SI_KERNEL),
    )
}

#[cfg(test)]
mod coredump_tests {
    use super::*;
    use paludarium_mmu::{PageSource, SharedPages};
    use paludarium_types::Errno;
    use std::sync::Arc;

    struct Named;
    impl PageSource for Named {
        fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
            Ok(buf.len())
        }
        fn name(&self) -> Option<Vec<u8>> {
            Some(b"/data".to_vec())
        }
    }

    #[test]
    fn each_mapping_is_dumped_as_its_filter_bit_says() {
        let mut mem = AddressSpace::new();
        let stack = mem
            .map(None, PAGE, Prot::READ_WRITE, MappingKind::Stack)
            .unwrap();
        let written = mem
            .map(None, PAGE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.write(written, &[1]).unwrap();
        // Read-only, so that it does not merge with the written one.
        let untouched = mem
            .map(None, PAGE, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        let shared = mem
            .map_shared(None, PAGE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.mark_shared(shared, PAGE).unwrap();
        let file = mem
            .map(None, 2 * PAGE, Prot::READ, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(Arc::new(Named));
        mem.back_with_cache(file, 2 * PAGE, &pages, 0).unwrap();
        let length = |at: GuestAddr, filter: u32| {
            let mapping = mem.mappings().find(|m| m.start == at).unwrap();
            dump_length(&mem, &mapping, false, filter)
        };
        // The default: written private memory and shared anonymous memory.
        let all = [stack, written, untouched, shared, file];
        let lengths = |filter| all.map(|at| length(at, filter));
        assert_eq!(lengths(0x33), [PAGE, PAGE, 0, PAGE, 0]);
        assert_eq!(lengths(0), [0; 5]);
        assert_eq!(lengths(ANON_PRIVATE), [PAGE, PAGE, 0, 0, 0]);
        assert_eq!(lengths(ANON_SHARED), [0, 0, 0, PAGE, 0]);
        // A private file mapping whole, whatever was written of it.
        assert_eq!(lengths(MAPPED_PRIVATE), [0, 0, 0, 0, 2 * PAGE]);
        assert_eq!(lengths(MAPPED_SHARED), [0; 5]);
        // The ELF header's page only of a file that starts with one, which
        // this one does not.
        assert_eq!(lengths(ELF_HEADERS), [0; 5]);
    }

    #[test]
    fn the_first_page_of_an_executable_file_is_its_header_without_the_magic() {
        struct Executable;
        impl PageSource for Executable {
            fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
                Ok(buf.len())
            }
            fn executable(&self) -> bool {
                true
            }
        }
        let mut mem = AddressSpace::new();
        let pages = SharedPages::new().with_source(Arc::new(Executable));
        let mut map = |prot: Prot, offset: u64| {
            let at = mem.map(None, 2 * PAGE, prot, MappingKind::File).unwrap();
            mem.back_with_cache(at, 2 * PAGE, &pages, offset).unwrap();
            at
        };
        let start = map(Prot::READ, 0);
        let later = map(Prot::READ, 2 * PAGE);
        let unreadable = map(Prot::NONE, 0);
        let length = |at: GuestAddr| {
            let mapping = mem.mappings().find(|m| m.start == at).unwrap();
            dump_length(&mem, &mapping, false, ELF_HEADERS)
        };
        // Zeros, no ELF magic: the file's execute bit is enough.
        assert_eq!(length(start), PAGE);
        // Only where the file starts, and only of a mapping that can be read.
        assert_eq!(length(later), 0);
        assert_eq!(length(unreadable), 0);
    }

    #[test]
    fn the_programs_segments_are_dumped_as_written_or_as_its_file() {
        let mut mem = AddressSpace::new();
        let text = mem
            .map(None, 2 * PAGE, Prot::READ, MappingKind::ElfSegment)
            .unwrap();
        let data = mem
            .map(None, PAGE, Prot::READ_WRITE, MappingKind::ElfSegment)
            .unwrap();
        let length = |at: GuestAddr, first: bool, filter: u32| {
            let mapping = mem.mappings().find(|m| m.start == at).unwrap();
            dump_length(&mem, &mapping, first, filter)
        };
        assert_eq!(length(text, true, 0x33), PAGE);
        assert_eq!(length(text, false, 0x33), 0);
        assert_eq!(length(text, true, MAPPED_PRIVATE), 2 * PAGE);
        assert_eq!(length(text, true, ANON_PRIVATE), 0);
        assert_eq!(length(data, false, 0x33), PAGE);
        assert_eq!(length(data, false, ELF_HEADERS), 0);
        assert_eq!(length(data, false, MAPPED_PRIVATE), PAGE);
    }

    #[test]
    fn the_files_note_lists_the_mappings_of_a_file() {
        let mut mem = AddressSpace::new();
        // Private anonymous memory maps no file.
        mem.map(None, PAGE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        let file = mem
            .map(None, 2 * PAGE, Prot::READ, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(Arc::new(Named));
        mem.back_with_cache(file, 2 * PAGE, &pages, 2 * PAGE)
            .unwrap();
        let shared = mem
            .map_shared(None, PAGE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.mark_shared(shared, PAGE).unwrap();
        let vmas: Vec<Mapping> = mem.mappings().collect();
        assert_eq!(vmas.len(), 3);
        let note = files(&mem, &vmas, b"/");
        let word = |i: usize| u64::from_le_bytes(note[8 * i..8 * i + 8].try_into().unwrap());
        assert_eq!((word(0), word(1)), (2, PAGE));
        // Lowest first: the shared memory was placed last, below the rest.
        assert_eq!((word(2), word(3), word(4)), (shared.0, shared.0 + PAGE, 0));
        assert_eq!((word(5), word(6), word(7)), (file.0, file.0 + 2 * PAGE, 2));
        assert_eq!(&note[64..], b"/dev/zero (deleted)\0/data\0");
    }

    #[test]
    fn the_files_note_names_a_file_under_the_root_from_it() {
        struct At(&'static [u8]);
        impl PageSource for At {
            fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
                Ok(buf.len())
            }
            fn name(&self) -> Option<Vec<u8>> {
                Some(self.0.to_vec())
            }
        }
        let mut mem = AddressSpace::new();
        let mut vmas = Vec::new();
        for (n, name) in [&b"/jail/file"[..], b"/jail/gone (deleted)", b"/jailed/file"]
            .into_iter()
            .enumerate()
        {
            let at = GuestAddr(0x10_0000 + 2 * PAGE * n as u64);
            mem.map(Some(at), PAGE, Prot::READ, MappingKind::File)
                .unwrap();
            let pages = SharedPages::new().with_source(Arc::new(At(name)));
            mem.back_with_cache(at, PAGE, &pages, 0).unwrap();
        }
        vmas.extend(mem.mappings());
        let names = |root: &[u8]| files(&mem, &vmas, root)[16 + 3 * 24..].to_vec();
        assert_eq!(names(b"/jail"), b"/file\0/gone (deleted)\0/jailed/file\0");
        assert_eq!(
            names(b"/"),
            b"/jail/file\0/jail/gone (deleted)\0/jailed/file\0"
        );
    }

    #[test]
    fn each_part_of_a_split_file_mapping_names_its_own_page() {
        let mut mem = AddressSpace::new();
        let file = mem
            .map(None, 2 * PAGE, Prot::READ, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(Arc::new(Named));
        mem.back_with_cache(file, 2 * PAGE, &pages, 2 * PAGE)
            .unwrap();
        mem.protect_shared(GuestAddr(file.0 + PAGE), PAGE, Prot::READ_WRITE)
            .unwrap();
        let vmas: Vec<Mapping> = mem.mappings().collect();
        assert_eq!(vmas.len(), 2);
        let note = files(&mem, &vmas, b"/");
        let word = |i: usize| u64::from_le_bytes(note[8 * i..8 * i + 8].try_into().unwrap());
        assert_eq!(word(0), 2);
        assert_eq!((word(2), word(3), word(4)), (file.0, file.0 + PAGE, 2));
        assert_eq!(
            (word(5), word(6), word(7)),
            (file.0 + PAGE, file.0 + 2 * PAGE, 3)
        );
    }

    #[test]
    fn a_merged_file_mapping_names_the_page_it_starts_at() {
        let mut mem = AddressSpace::new();
        let high = mem.map(None, PAGE, Prot::READ, MappingKind::File).unwrap();
        let low = mem
            .map(
                Some(GuestAddr(high.0 - PAGE)),
                PAGE,
                Prot::READ,
                MappingKind::File,
            )
            .unwrap();
        // The same file at the next page: Linux merges the two VMAs.
        let pages = SharedPages::new().with_source(Arc::new(Named));
        mem.back_with_cache(low, PAGE, &pages, PAGE).unwrap();
        mem.back_with_cache(high, PAGE, &pages, 2 * PAGE).unwrap();
        let (start, length) = mem.vma_at(high).unwrap();
        assert_eq!((start, length), (low, 2 * PAGE));
        let first = mem.mappings().next().unwrap();
        let vma = Mapping {
            start,
            length,
            ..first
        };
        let note = files(&mem, &[vma], b"/");
        let word = |i: usize| u64::from_le_bytes(note[8 * i..8 * i + 8].try_into().unwrap());
        assert_eq!(word(0), 1);
        assert_eq!((word(2), word(3), word(4)), (low.0, low.0 + 2 * PAGE, 1));
    }
}
