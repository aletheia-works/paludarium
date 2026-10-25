//! Core dumps, as Linux's `do_coredump` writes them with the default
//! `core_pattern` (`core`): an ELF core file named `core` in the working
//! directory of a process that a core-dumping signal ends, when the process
//! is dumpable and its RLIMIT_CORE soft limit is at least one page. The core
//! has one `PT_NOTE` segment (each thread's registers, the process, the
//! fatal signal and the auxiliary vector) and one `PT_LOAD` segment per
//! mapping, whose contents follow the default `coredump_filter`. A core
//! larger than the limit is cut there; it still counts as dumped, as Linux's
//! binfmt_elf reports a core once it has started to write it.
use crate::signals;
use paludarium_cpu::{CpuState, reg};
use paludarium_mmu::{AddressSpace, Mapping, MappingKind, Prot};
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
    /// The `clear_child_tid` words of the threads that have ended, which
    /// Linux clears only after the dump.
    pub clear_tids: Vec<u64>,
}

/// The process's identity and times, in `NT_PRSTATUS` and `NT_PRPSINFO`.
pub(crate) struct Identity {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub sid: u32,
    /// CPU time of the process and of its waited-for children, in ns.
    pub cpu: u64,
    pub children_cpu: u64,
    /// The initial stack pointer, where argc, argv, envp and the
    /// auxiliary vector start.
    pub start_stack: u64,
}

/// Writes the core through `emit`, in the pieces Linux writes it in, and
/// returns whether all of it fit under the limit and was written. A piece that would pass
/// the limit is not written, nor anything after it.
pub(crate) fn write(
    dump: &Dump,
    who: &Identity,
    mem: &AddressSpace,
    emit: &mut dyn FnMut(&[u8]) -> bool,
) -> bool {
    let mappings: Vec<Mapping> = mem.mappings().collect();
    let first_elf = mappings
        .iter()
        .find(|m| m.kind == MappingKind::ElfSegment)
        .map(|m| m.start);
    let segments: Vec<(Mapping, u64)> = mappings
        .iter()
        .map(|&m| (m, dump_length(&m, first_elf == Some(m.start))))
        .collect();
    let notes = notes(dump, who, mem);
    let count = segments.len() + 1;
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
            // A page that cannot be read is written as zeros, as Linux
            // skips it in the file.
            page[..size].fill(0);
            let _ = mem.read(GuestAddr(mapping.start.0 + at), &mut page[..size]);
            if !put(&page[..size]) {
                return false;
            }
            at += size as u64;
        }
    }
    true
}

/// How much of a mapping the core holds, by the default `coredump_filter`
/// (0x33): every anonymous mapping, a file mapping or ELF segment that is
/// writable (whose pages the process may have copied), and the first page
/// of the ELF image (its header); nothing of a mapping that cannot be read.
fn dump_length(mapping: &Mapping, first_elf: bool) -> u64 {
    if !mapping.prot.contains(Prot::READ) {
        return 0;
    }
    match mapping.kind {
        MappingKind::Anonymous | MappingKind::Stack | MappingKind::Heap => mapping.length,
        MappingKind::ElfSegment | MappingKind::File if mapping.prot.contains(Prot::WRITE) => {
            mapping.length
        }
        MappingKind::ElfSegment if first_elf => mapping.length.min(PAGE),
        _ => 0,
    }
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
/// `NT_SIGINFO` and `NT_AUXV`; then the thread's `NT_FPREGSET`.
fn notes(dump: &Dump, who: &Identity, mem: &AddressSpace) -> Vec<Vec<u8>> {
    let mut threads: Vec<&ThreadCore> = dump.threads.iter().collect();
    threads.sort_by_key(|t| (t.tid != dump.dumper, t.tid));
    let mut notes = Vec::new();
    for (index, thread) in threads.iter().enumerate() {
        notes.push(note(b"CORE", 1, &prstatus(dump, who, thread)));
        if index == 0 {
            notes.push(note(b"CORE", 3, &prpsinfo(who, thread, mem)));
            notes.push(note(b"CORE", 0x5349_4749, &dump.siginfo));
            notes.push(note(b"CORE", 6, &auxv(who, mem)));
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
    put32(&mut s, 32, thread.tid);
    put32(&mut s, 36, who.ppid);
    put32(&mut s, 40, who.pgrp);
    put32(&mut s, 44, who.sid);
    // The leader reports the whole process's time, as Linux does.
    if thread.tid == who.pid {
        put_time(&mut s, 48, who.cpu);
        put_time(&mut s, 80, who.children_cpu);
    }
    let c = &thread.cpu;
    let g = |r: usize| c.gpr[r];
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
        0x33, // cs
        c.rflags,
        g(reg::RSP),
        0x2b, // ss
        c.fs_base,
        c.gs_base,
        0,
        0,
        0,
        0, // ds, es, fs, gs
    ];
    for (i, value) in registers.iter().enumerate() {
        put64(&mut s, 112 + 8 * i, *value);
    }
    put32(&mut s, 328, 1); // pr_fpvalid
    s
}

/// `struct elf_prpsinfo` (136 bytes): the process running, as root, with
/// its name and up to 79 bytes of its arguments, separated by spaces.
fn prpsinfo(who: &Identity, thread: &ThreadCore, mem: &AddressSpace) -> [u8; 136] {
    let mut s = [0u8; 136];
    s[1] = b'R';
    put32(&mut s, 24, who.pid);
    put32(&mut s, 28, who.ppid);
    put32(&mut s, 32, who.pgrp);
    put32(&mut s, 36, who.sid);
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

/// The auxiliary vector from the initial stack, up to and with `AT_NULL`.
fn auxv(who: &Identity, mem: &AddressSpace) -> Vec<u8> {
    let read = |at: u64| mem.read_u64(GuestAddr(at)).ok();
    let mut at = who.start_stack;
    let Some(count) = read(at) else {
        return Vec::new();
    };
    at += 8 * (count + 2);
    // envp ends at a NULL.
    while let Some(pointer) = read(at) {
        at += 8;
        if pointer == 0 {
            break;
        }
    }
    let mut vector = Vec::new();
    while let (Some(kind), Some(value)) = (read(at), read(at + 8)) {
        vector.extend_from_slice(&kind.to_le_bytes());
        vector.extend_from_slice(&value.to_le_bytes());
        at += 16;
        if kind == 0 || vector.len() >= 64 * 16 {
            break;
        }
    }
    vector
}

/// `struct user_i387_struct` (512 bytes, the `fxsave` layout): the x87
/// unit at its initial state, as paludarium has none, and the SSE state.
fn fpregset(cpu: &CpuState) -> [u8; 512] {
    let mut f = [0u8; 512];
    put16(&mut f, 0, 0x037f); // control word
    put32(&mut f, 24, cpu.mxcsr);
    put32(&mut f, 28, 0xffff); // mxcsr_mask
    for (i, xmm) in cpu.xmm.iter().enumerate() {
        f[160 + 16 * i..176 + 16 * i].copy_from_slice(&xmm.to_le_bytes());
    }
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
