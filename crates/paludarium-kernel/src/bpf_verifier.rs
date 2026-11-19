//! The verifier of `BPF_PROG_LOAD`, for `BPF_PROG_TYPE_SOCKET_FILTER`, as
//! Linux's `kernel/bpf/verifier.c` and, in master, `cfg.c` check a
//! program: its structure first (`check_subprogs`, the checks of every
//! instruction's fields in `check_and_resolve_insns`, `check_cfg`), then
//! every path from the first instruction (`do_check`), with the state of
//! the registers and of the 512-byte stack along it.
//!
//! The rule is that a program Linux rejects is never accepted. "Linux" is
//! two kernels here: master, which the checks follow, and the x86-64 test
//! machines' Linux 7.0. Where they decide differently, the program is
//! rejected, so that the emulator accepts only what both accept:
//! - master takes a stack of up to `MAX_BPF_STACK_JIT` bytes where its JIT
//!   can, 7.0 512;
//! - with `allow_ptr_leaks`, master makes a number of a pointer that a
//!   multiplication, a shift or a bitwise operation is applied to, where
//!   7.0 refuses it;
//! - master takes an exit whose `src_reg` is `BPF_UNWIND_EXIT`.
//!
//! The log lines are 7.0's where the two kernels word them differently
//! (the misaligned stack access, a sleepable program), as the differential
//! tests compare them with it. Master also writes a diagnostic after some
//! errors at log level 1 or more; that is not written here.
//!
//! What the verifier here does not do is a gap of the safe direction: it
//! rejects programs Linux accepts, and never the other way round.
//! - A scalar register is a value the verifier knows or none at all,
//!   where Linux keeps bounds and a tnum: so a value Linux knows, from a
//!   division or a comparison, say, is not known here, and both sides of
//!   a conditional jump are walked unless both operands are known. A
//!   value known here is known to Linux too, with the same value.
//! - No state is pruned: every path is walked, against the same limit of
//!   1,000,000 instructions and 8,192 pending branches, which Linux's
//!   pruning only keeps it further from.
//! - A lookup's result is null until the program compares it with 0 in a
//!   64-bit `BPF_JEQ` or `BPF_JNE` of an immediate, where Linux also knows
//!   an array's element by a constant key is there, and compares two
//!   pointers.
//! - Rejected outright, with a line of the emulator's own ("paludarium:
//!   ..."; a helper call's starts "unknown func", which tells libbpf and
//!   bpftool the helper is not there): helpers other than
//!   `bpf_map_lookup_elem`, `bpf_map_update_elem` and `bpf_map_delete_elem`,
//!   those of maps of maps, queues, stacks and bloom filters, a helper's
//!   argument other than the stack or a map's value, bpf-to-bpf calls and
//!   kfuncs, the context's fields (`struct __sk_buff`) and a map's own
//!   (`struct bpf_map`), maps from `fd_array` and maps made with
//!   `excl_prog_hash`, BTF IDs and functions in `BPF_LD_IMM64`,
//!   `BPF_LD_ABS` and `BPF_LD_IND`, atomics, `may_goto`, indirect jumps, a
//!   back-edge (Linux takes a bounded loop from a privileged loader), a
//!   pointer with a variable offset, and `BPF_F_TEST_REG_INVARIANTS` with a
//!   conditional jump.
//! - The loader has `CAP_BPF` and `CAP_PERFMON` ([`crate::bpf_prog`]
//!   refuses others), so the verifier allows what Linux allows them:
//!   pointer leaks, uninitialized stack reads and no Spectre sanitizing.
use paludarium_types::Errno;

const EACCES: Errno = Errno(13);
const EPROTO: Errno = Errno(71);
/// The kernel's own `ENOTSUPP`, which reaches user space as it is.
const ENOTSUPP: Errno = Errno(524);
const E2BIG: Errno = Errno(7);

/// `BPF_COMPLEXITY_LIMIT_INSNS`.
const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// `BPF_COMPLEXITY_LIMIT_JMP_SEQ`.
const COMPLEXITY_LIMIT_JMP_SEQ: usize = 8192;
/// `MAX_BPF_STACK`.
const MAX_STACK: i64 = 512;
/// `BPF_MAX_VAR_OFF`.
const MAX_VAR_OFF: i64 = 1 << 29;
/// The largest number `tnum_strn` writes in decimal (`U16_MAX`).
const UNUM_MAX_DECIMAL: u64 = 0xffff;
/// `MAX_BPF_REG`: R0 to R10.
const REGS: usize = 11;
/// The frame pointer, R10.
const FP: usize = 10;

mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

mod size {
    pub const W: u8 = 0x00;
    pub const H: u8 = 0x08;
    pub const B: u8 = 0x10;
    pub const DW: u8 = 0x18;
}

mod mode {
    pub const IMM: u8 = 0x00;
    pub const ABS: u8 = 0x20;
    pub const IND: u8 = 0x40;
    pub const MEM: u8 = 0x60;
    pub const MEMSX: u8 = 0x80;
    pub const ATOMIC: u8 = 0xc0;
}

/// `BPF_K` and `BPF_X`, which for `BPF_END` are `BPF_TO_LE` and
/// `BPF_TO_BE`.
const X: u8 = 0x08;

mod alu {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0;
    /// The operations of two operands, with `BPF_K` and `BPF_X` both.
    pub const BINARY: [u8; 12] = [ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, MOD, XOR, MOV, ARSH];
}

mod jmp {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
    pub const JCOND: u8 = 0xe0;
    pub const CONDITIONS: [u8; 11] = [JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, JLT, JLE, JSLT, JSLE];
}

/// `BPF_PSEUDO_*`, in `src_reg`.
mod pseudo {
    pub const MAP_FD: u8 = 1;
    pub const MAP_VALUE: u8 = 2;
    pub const BTF_ID: u8 = 3;
    pub const FUNC: u8 = 4;
    pub const MAP_IDX: u8 = 5;
    pub const MAP_IDX_VALUE: u8 = 6;
    pub const CALL: u8 = 1;
    pub const KFUNC_CALL: u8 = 2;
}

/// `BPF_ADDR_SPACE_CAST`, in a 64-bit `BPF_MOV`'s `off`.
const ADDR_SPACE_CAST: i16 = 1;

/// One `struct bpf_insn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) code: u8,
    pub(crate) dst: u8,
    pub(crate) src: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

impl Insn {
    pub(crate) fn decode(b: [u8; 8]) -> Insn {
        Insn {
            code: b[0],
            dst: b[1] & 0x0f,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
    fn class(self) -> u8 {
        self.code & 0x07
    }
    fn op(self) -> u8 {
        self.code & 0xf0
    }
    fn mode(self) -> u8 {
        self.code & 0xe0
    }
    fn size(self) -> u8 {
        self.code & 0x18
    }
    fn x(self) -> bool {
        self.code & X != 0
    }
    fn jumps(self) -> bool {
        matches!(self.class(), class::JMP | class::JMP32)
    }
    /// `bpf_is_ldimm64`.
    fn ldimm64(self) -> bool {
        self.code == class::LD | mode::IMM | size::DW
    }
    /// `bpf_jmp_offset`: a 32-bit `BPF_JA` jumps by `imm`.
    fn jump(self) -> i64 {
        if self.code == class::JMP32 | jmp::JA {
            i64::from(self.imm)
        } else {
            i64::from(self.off)
        }
    }
}

/// What the loader asked for that the checks depend on.
#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    /// `BPF_F_SLEEPABLE`.
    pub(crate) sleepable: bool,
    /// `BPF_F_STRICT_ALIGNMENT` without `BPF_F_ANY_ALIGNMENT`.
    pub(crate) strict_alignment: bool,
    /// `BPF_F_TEST_REG_INVARIANTS`.
    pub(crate) test_reg_invariants: bool,
    /// Whether `fd_array` is given.
    pub(crate) fd_array: bool,
}

/// What the verifier needs of a map a program names by its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MapShape {
    /// The map's ID, which tells two descriptors of one map apart from two
    /// maps (`used_maps` holds each map once).
    pub(crate) id: u32,
    pub(crate) kind: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) flags: u32,
    /// Made with `excl_prog_hash`.
    pub(crate) exclusive: bool,
}

/// `__bpf_map_get` of a descriptor: the map's shape, or `EBADF` for no
/// descriptor and `EINVAL` for one of no map.
pub(crate) type Maps<'a> = dyn FnMut(i32) -> Result<MapShape, Errno> + 'a;

/// `MAX_USED_MAPS`.
const MAX_USED_MAPS: usize = 64;

mod map_type {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const LRU_HASH: u32 = 9;
    pub const LPM_TRIE: u32 = 11;
    pub const ARRAY_OF_MAPS: u32 = 12;
    pub const HASH_OF_MAPS: u32 = 13;
    pub const QUEUE: u32 = 22;
    pub const STACK: u32 = 23;
}

/// The map flags a program's access depends on (`bpf_map_flags_to_cap`).
const F_RDONLY_PROG: u32 = 1 << 7;
const F_WRONLY_PROG: u32 = 1 << 8;

/// The helpers in range, `enum bpf_func_id`.
mod func {
    pub const MAP_LOOKUP_ELEM: i32 = 1;
    pub const MAP_UPDATE_ELEM: i32 = 2;
    pub const MAP_DELETE_ELEM: i32 = 3;
}

/// A program that passed.
#[derive(Debug)]
pub(crate) struct Verified {
    /// `insn_processed`, which fdinfo's `verified_insns` gives.
    pub(crate) processed: u32,
    /// The stack the program uses, in bytes, rounded up to 8.
    pub(crate) stack_depth: u32,
    /// The maps the program uses (`used_maps`), by ID.
    pub(crate) maps: Vec<u32>,
}

/// Why a program is refused: the error and the line the log gets.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rejection {
    pub(crate) errno: Errno,
    pub(crate) line: String,
    /// `insn_processed` when it was refused.
    pub(crate) processed: u32,
    pub(crate) stack_depth: u32,
}

type Checked<T> = Result<T, (Errno, String)>;

fn refuse<T>(errno: Errno, line: impl Into<String>) -> Checked<T> {
    Err((errno, line.into()))
}

/// What the emulator does not verify yet, which Linux may take.
fn gap<T>(what: &str) -> Checked<T> {
    refuse(
        Errno::EINVAL,
        format!("paludarium: {what} are not verified yet"),
    )
}

/// `bpf_check`'s first check of the instructions, which comes before
/// `process_fd_array` and the rest ([`crate::bpf_prog`] makes it): the
/// last one may not be the first half of a BPF_LD_IMM64.
pub(crate) fn ends_in_half(insns: &[Insn]) -> bool {
    insns.last().is_some_and(|i| i.ldimm64())
}

/// `bpf_check` for a socket filter, from the checks of the instructions on,
/// for a program [`ends_in_half`] took. `BPF_PROG_LOAD` refuses no
/// instructions at all (`E2BIG`) before it gets here.
pub(crate) fn check(
    insns: &[Insn],
    options: Options,
    maps: &mut Maps<'_>,
) -> Result<Verified, Rejection> {
    debug_assert!(!insns.is_empty() && !ends_in_half(insns));
    let mut walk = Walk::default();
    let result = structure(insns, options, maps, &mut walk).and_then(|()| walk.run(insns, options));
    let stack_depth = walk.depth.div_ceil(8) * 8;
    match result {
        Ok(()) => Ok(Verified {
            processed: walk.processed,
            stack_depth,
            maps: walk.maps.iter().map(|m| m.id).collect(),
        }),
        Err((errno, line)) => Err(Rejection {
            errno,
            line,
            processed: walk.processed,
            stack_depth,
        }),
    }
}

/// The checks before any path is walked, in master's order.
fn structure(
    insns: &[Insn],
    options: Options,
    maps: &mut Maps<'_>,
    walk: &mut Walk,
) -> Checked<()> {
    // add_subprogs, add_kfuncs: one function, calling no other.
    for insn in insns {
        if insn.code == class::JMP | jmp::CALL
            && matches!(insn.src, pseudo::CALL | pseudo::KFUNC_CALL)
        {
            return gap("bpf-to-bpf calls and kfuncs");
        }
        if insn.ldimm64() && insn.src == pseudo::FUNC {
            return gap("references to functions");
        }
    }
    subprogs(insns)?;
    let mut i = 0;
    while i < insns.len() {
        // A BPF_LD_IMM64's second half is checked with its first.
        i += fields(insns, i, options, maps, walk)?;
    }
    cfg(insns)?;
    // check_attach_btf_id: a socket filter cannot sleep. 7.0's words.
    if options.sleepable {
        return refuse(
            Errno::EINVAL,
            "Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and struct_ops programs can be sleepable",
        );
    }
    if options.test_reg_invariants
        && insns
            .iter()
            .any(|i| i.jumps() && !matches!(i.op(), jmp::JA | jmp::CALL | jmp::EXIT))
    {
        return gap("register invariants (BPF_F_TEST_REG_INVARIANTS) of conditional jumps");
    }
    Ok(())
}

/// `check_subprogs` of the one function: jumps stay in it, and its last
/// instruction is an exit or a jump.
fn subprogs(insns: &[Insn]) -> Checked<()> {
    let n = insns.len() as i64;
    for (i, insn) in insns.iter().enumerate() {
        if insn.jumps() && !matches!(insn.op(), jmp::CALL | jmp::EXIT) {
            let to = i as i64 + insn.jump() + 1;
            if to < 0 || to >= n {
                return refuse(
                    Errno::EINVAL,
                    format!("jump out of range from insn {i} to {to}"),
                );
            }
        }
    }
    let last = insns[insns.len() - 1].code;
    if last != class::JMP | jmp::EXIT
        && last != class::JMP32 | jmp::JA
        && last != class::JMP | jmp::JA
    {
        return refuse(Errno::EINVAL, "last insn is not an exit or jmp");
    }
    Ok(())
}

/// `bpf_opcode_in_insntable`, master's (which also has `BPF_CALL|BPF_X`).
fn known(code: u8) -> bool {
    let op = code & 0xf0;
    match code & 0x07 {
        class::ALU => alu::BINARY.contains(&op) || code == class::ALU | alu::NEG || op == alu::END,
        class::ALU64 => {
            alu::BINARY.contains(&op)
                || code == class::ALU64 | alu::NEG
                || code == class::ALU64 | alu::END
        }
        class::JMP => {
            jmp::CONDITIONS.contains(&op)
                || code == class::JMP | jmp::CALL
                || code == class::JMP | jmp::EXIT
                || code == class::JMP | jmp::JA
                // UAPI-exposed: an indirect jump, may_goto, and master's
                // indirect call.
                || code == class::JMP | jmp::JA | X
                || code == class::JMP | jmp::JCOND
                || code == class::JMP | jmp::CALL | X
        }
        class::JMP32 => jmp::CONDITIONS.contains(&op) || code == class::JMP32 | jmp::JA,
        class::STX => matches!(code & 0xe0, mode::MEM | mode::ATOMIC),
        class::ST => code & 0xe0 == mode::MEM,
        class::LDX => {
            code & 0xe0 == mode::MEM || (code & 0xe0 == mode::MEMSX && code & 0x18 != size::DW)
        }
        _ => {
            code == class::LD | mode::IMM | size::DW
                || (matches!(code & 0xe0, mode::ABS | mode::IND) && code & 0x18 != size::DW)
        }
    }
}

/// `check_and_resolve_insns` for the instruction at `i`: its registers,
/// a BPF_LD_IMM64's second half, the opcode, and `check_insn_fields`.
/// Gives how many instructions it took.
fn fields(
    insns: &[Insn],
    i: usize,
    options: Options,
    maps: &mut Maps<'_>,
    walk: &mut Walk,
) -> Checked<usize> {
    let insn = insns[i];
    if usize::from(insn.dst) >= REGS {
        return refuse(Errno::EINVAL, format!("R{} is invalid", insn.dst));
    }
    if usize::from(insn.src) >= REGS {
        return refuse(Errno::EINVAL, format!("R{} is invalid", insn.src));
    }
    if insn.ldimm64() {
        let next = insns.get(i + 1);
        if next.is_none_or(|n| n.code != 0 || n.dst != 0 || n.src != 0 || n.off != 0) {
            return refuse(Errno::EINVAL, "invalid bpf_ld_imm64 insn");
        }
        // Master's place; 7.0 refuses it as it walks the instruction.
        if insn.off != 0 {
            return refuse(Errno::EINVAL, "BPF_LD_IMM64 uses reserved fields");
        }
        let second = next.map_or(0, |n| n.imm);
        match insn.src {
            0 => return Ok(2),
            pseudo::BTF_ID => return gap("BTF IDs in BPF_LD_IMM64"),
            pseudo::FUNC => return gap("references to functions"),
            pseudo::MAP_VALUE | pseudo::MAP_IDX_VALUE => {}
            pseudo::MAP_FD | pseudo::MAP_IDX if second == 0 => {}
            _ => return refuse(Errno::EINVAL, "unrecognized bpf_ld_imm64 insn"),
        }
        if matches!(insn.src, pseudo::MAP_IDX | pseudo::MAP_IDX_VALUE) {
            if !options.fd_array {
                return refuse(EPROTO, "fd_idx without fd_array is invalid");
            }
            return gap("maps from fd_array");
        }
        let map = walk.use_map(insn.imm, options, maps)?;
        let value = if insn.src == pseudo::MAP_VALUE {
            // map_direct_value_addr: an array of one element alone.
            let shape = walk.maps[usize::from(map)];
            let off = second as u32;
            if shape.kind != map_type::ARRAY {
                return refuse(
                    Errno::EINVAL,
                    "no direct value access support for this map type",
                );
            }
            let errno = if shape.max_entries != 1 {
                Some(ENOTSUPP)
            } else if off >= shape.value_size {
                Some(Errno::EINVAL)
            } else {
                None
            };
            if let Some(errno) = errno {
                return refuse(
                    errno,
                    format!(
                        "invalid access to map value pointer, value_size={} off={off}",
                        shape.value_size
                    ),
                );
            }
            Some(off)
        } else {
            None
        };
        walk.loads.insert(i, (map, value));
        return Ok(2);
    }
    if !known(insn.code) {
        return refuse(Errno::EINVAL, format!("unknown opcode {:02x}", insn.code));
    }
    insn_fields(insn).map(|()| 1)
}

/// `check_insn_fields`.
fn insn_fields(insn: Insn) -> Checked<()> {
    match insn.class() {
        class::ALU | class::ALU64 => alu_fields(insn),
        class::LDX => {
            if !matches!(insn.mode(), mode::MEM | mode::MEMSX) || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_LDX uses reserved fields");
            }
            Ok(())
        }
        class::STX => {
            if insn.mode() == mode::ATOMIC {
                return Ok(());
            }
            if insn.mode() != mode::MEM || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_STX uses reserved fields");
            }
            Ok(())
        }
        class::ST => {
            if insn.mode() != mode::MEM || insn.src != 0 {
                return refuse(Errno::EINVAL, "BPF_ST uses reserved fields");
            }
            Ok(())
        }
        class::JMP | class::JMP32 => jmp_fields(insn),
        _ => {
            // BPF_LD_ABS and BPF_LD_IND: BPF_LD_IMM64 was dealt with above.
            if insn.dst != 0
                || insn.off != 0
                || insn.size() == size::DW
                || (insn.mode() == mode::ABS && insn.src != 0)
            {
                return refuse(Errno::EINVAL, "BPF_LD_[ABS|IND] uses reserved fields");
            }
            Ok(())
        }
    }
}

/// `check_alu_fields`.
fn alu_fields(insn: Insn) -> Checked<()> {
    let op = insn.op();
    let wide = insn.class() == class::ALU64;
    match op {
        alu::NEG => {
            if insn.x() || insn.src != 0 || insn.off != 0 || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_NEG uses reserved fields");
            }
        }
        alu::END => {
            if insn.src != 0
                || insn.off != 0
                || !matches!(insn.imm, 16 | 32 | 64)
                || (wide && insn.x())
            {
                return refuse(Errno::EINVAL, "BPF_END uses reserved fields");
            }
        }
        alu::MOV => {
            if insn.x() {
                if !wide {
                    if !matches!(insn.off, 0 | 8 | 16) || insn.imm != 0 {
                        return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
                    }
                } else if insn.off == ADDR_SPACE_CAST {
                    if insn.imm != 1 && insn.imm != 1 << 16 {
                        return refuse(
                            Errno::EINVAL,
                            "addr_space_cast insn can only convert between address space 1 and 0",
                        );
                    }
                } else if !matches!(insn.off, 0 | 8 | 16 | 32) || insn.imm != 0 {
                    return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
                }
            } else if insn.src != 0 || insn.off != 0 {
                return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
            }
        }
        _ => {
            let signed = insn.off == 1 && matches!(op, alu::DIV | alu::MOD);
            let bad = if insn.x() {
                insn.imm != 0
            } else {
                insn.src != 0
            };
            if bad || (insn.off != 0 && !signed) {
                return refuse(Errno::EINVAL, "BPF_ALU uses reserved fields");
            }
        }
    }
    Ok(())
}

/// `check_jmp_fields`. An exit's `src_reg` is 0, as 7.0 has it.
fn jmp_fields(insn: Insn) -> Checked<()> {
    let wide = insn.class() == class::JMP;
    match insn.op() {
        jmp::CALL => {
            if insn.code == class::JMP | jmp::CALL | X {
                if insn.src != 0 || insn.imm != 0 || insn.off != 0 {
                    return refuse(Errno::EINVAL, "BPF_CALL|BPF_X uses reserved fields");
                }
                return Ok(());
            }
            if insn.x()
                || (insn.src != pseudo::KFUNC_CALL && insn.off != 0)
                || !matches!(insn.src, 0 | pseudo::CALL | pseudo::KFUNC_CALL)
                || insn.dst != 0
                || !wide
            {
                return refuse(Errno::EINVAL, "BPF_CALL uses reserved fields");
            }
        }
        jmp::JA => {
            if insn.x() {
                if insn.src != 0 || insn.imm != 0 || insn.off != 0 {
                    return refuse(Errno::EINVAL, "BPF_JA|BPF_X uses reserved fields");
                }
            } else if insn.src != 0
                || insn.dst != 0
                || (wide && insn.imm != 0)
                || (!wide && insn.off != 0)
            {
                return refuse(Errno::EINVAL, "BPF_JA uses reserved fields");
            }
        }
        jmp::EXIT => {
            if insn.x() || insn.imm != 0 || insn.src != 0 || insn.dst != 0 || !wide {
                return refuse(Errno::EINVAL, "BPF_EXIT uses reserved fields");
            }
        }
        jmp::JCOND => {
            if insn.code != class::JMP | jmp::JCOND
                || insn.src != 0
                || insn.dst != 0
                || insn.imm != 0
            {
                return refuse(Errno::EINVAL, format!("invalid may_goto imm {}", insn.imm));
            }
        }
        _ => {
            if (insn.x() && insn.imm != 0) || (!insn.x() && insn.src != 0) {
                return refuse(Errno::EINVAL, "BPF_JMP/JMP32 uses reserved fields");
            }
        }
    }
    Ok(())
}

/// `check_cfg`: a depth-first walk of the instructions' edges, which
/// finds jumps out of the program, back-edges, instructions no path
/// reaches and jumps into the middle of a BPF_LD_IMM64.
fn cfg(insns: &[Insn]) -> Checked<()> {
    const DISCOVERED: u8 = 0x10;
    const EXPLORED: u8 = 0x20;
    const FALLTHROUGH: u8 = 1;
    const BRANCH: u8 = 2;
    enum Next {
        Done,
        Keep,
    }
    let n = insns.len();
    let mut state = vec![0u8; n];
    let mut stack = vec![0usize];
    state[0] = DISCOVERED;
    let push =
        |state: &mut Vec<u8>, stack: &mut Vec<usize>, t: usize, w: i64, e: u8| -> Checked<Next> {
            if state[t] >= DISCOVERED | e {
                return Ok(Next::Done);
            }
            if w < 0 || w >= n as i64 {
                return refuse(
                    Errno::EINVAL,
                    format!("jump out of range from insn {t} to {w}"),
                );
            }
            let w = w as usize;
            if state[w] == 0 {
                state[t] = DISCOVERED | e;
                state[w] = DISCOVERED;
                stack.push(w);
                Ok(Next::Keep)
            } else if state[w] & 0xf0 == DISCOVERED {
                // Linux takes the back-edge from a privileged loader and checks
                // the loop as it walks it; it is not walked here.
                refuse(Errno::EINVAL, format!("back-edge from insn {t} to {w}"))
            } else {
                state[t] = DISCOVERED | e;
                Ok(Next::Done)
            }
        };
    while let Some(&t) = stack.last() {
        let insn = insns[t];
        let t64 = t as i64;
        let next = if !insn.jumps() {
            let width = if insn.ldimm64() { 2 } else { 1 };
            push(&mut state, &mut stack, t, t64 + width, FALLTHROUGH)?
        } else {
            match insn.op() {
                jmp::EXIT => Next::Done,
                jmp::CALL => push(&mut state, &mut stack, t, t64 + 1, FALLTHROUGH)?,
                jmp::JA if insn.x() => return gap("indirect jumps"),
                jmp::JA => push(
                    &mut state,
                    &mut stack,
                    t,
                    t64 + insn.jump() + 1,
                    FALLTHROUGH,
                )?,
                _ => match push(&mut state, &mut stack, t, t64 + 1, FALLTHROUGH)? {
                    Next::Keep => Next::Keep,
                    Next::Done => push(
                        &mut state,
                        &mut stack,
                        t,
                        t64 + i64::from(insn.off) + 1,
                        BRANCH,
                    )?,
                },
            }
        };
        if let Next::Done = next {
            state[t] = EXPLORED;
            stack.pop();
        }
    }
    let mut i = 0;
    while i < n {
        if state[i] != EXPLORED {
            return refuse(Errno::EINVAL, format!("unreachable insn {i}"));
        }
        if insns[i].ldimm64() {
            if state[i + 1] != 0 {
                return refuse(
                    Errno::EINVAL,
                    format!("jump into the middle of ldimm64 insn {i}"),
                );
            }
            i += 1;
        }
        i += 1;
    }
    Ok(())
}

/// What a register holds: Linux's `enum bpf_reg_type`, for the types in
/// range, with a pointer's fixed offset (`reg->off`) and a scalar's value
/// when the verifier knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    NotInit,
    Scalar(Option<u64>),
    Ptr(Ptr, i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ptr {
    /// `PTR_TO_CTX`, the `struct __sk_buff` R1 starts with.
    Ctx,
    /// `PTR_TO_STACK`, from the frame pointer.
    Stack,
    /// `CONST_PTR_TO_MAP`, the map of an index into `used_maps`.
    Map(u8),
    /// `PTR_TO_MAP_VALUE`, into a value of the map.
    Value(u8),
    /// `PTR_TO_MAP_VALUE | PTR_MAYBE_NULL`, a lookup's result before the
    /// program compares it with 0, with the ID every copy of it shares.
    MaybeNull(u8, u32),
}

impl Ptr {
    /// `reg_type_str`.
    fn name(self) -> &'static str {
        match self {
            Ptr::Ctx => "ctx",
            Ptr::Stack => "fp",
            Ptr::Map(_) => "map_ptr",
            Ptr::Value(_) => "map_value",
            Ptr::MaybeNull(..) => "map_value_or_null",
        }
    }
}

/// `reg_type_str` of a register.
fn reg_name(reg: Reg) -> &'static str {
    match reg {
        Reg::NotInit => "?",
        Reg::Scalar(_) => "scalar",
        Reg::Ptr(p, _) => p.name(),
    }
}

/// An 8-byte stack slot: a register spilled whole (`STACK_SPILL`), or
/// bytes a read takes as a scalar. A privileged loader may read slots
/// never written (`allow_uninit_stack`), so those are bytes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Bytes,
    Spill(Reg),
}

#[derive(Clone)]
struct State {
    insn: usize,
    regs: [Reg; REGS],
    stack: [Slot; (MAX_STACK / 8) as usize],
}

impl State {
    /// `mark_ptr_or_null_regs`: every copy of the lookup's result `id`, in
    /// a register or spilled, is 0 (a scalar) or a pointer to a value.
    fn null_check(&mut self, id: u32, null: bool) {
        let mark = |reg: &mut Reg| {
            if let Reg::Ptr(Ptr::MaybeNull(map, i), _) = *reg
                && i == id
            {
                *reg = if null {
                    Reg::Scalar(Some(0))
                } else {
                    Reg::Ptr(Ptr::Value(map), 0)
                };
            }
        };
        self.regs.iter_mut().for_each(mark);
        for slot in &mut self.stack {
            if let Slot::Spill(reg) = slot {
                mark(reg);
            }
        }
    }
}

/// `bpf_alu_string`.
fn alu_name(op: u8) -> &'static str {
    match op {
        alu::ADD => "+=",
        alu::SUB => "-=",
        alu::MUL => "*=",
        alu::DIV => "/=",
        alu::OR => "|=",
        alu::AND => "&=",
        alu::LSH => "<<=",
        alu::RSH => ">>=",
        alu::NEG => "neg",
        alu::MOD => "%=",
        alu::XOR => "^=",
        alu::MOV => "=",
        alu::ARSH => "s>>=",
        _ => "endian",
    }
}

/// What a store writes: a register, or a BPF_ST's immediate.
#[derive(Clone, Copy)]
enum Store {
    Reg(Reg),
    Imm(i32),
}

/// How an instruction leaves the walk.
enum Step {
    Next(usize),
    /// The fall-through, the target, and the ID of a lookup's result that
    /// the jump tells is 0 on the target's side (`true`) or the other.
    Branch(usize, usize, Option<(u32, bool)>),
    Exit,
}

#[derive(Default)]
struct Walk {
    /// `insn_processed`.
    processed: u32,
    /// The deepest stack byte accessed.
    depth: u32,
    /// `used_maps`.
    maps: Vec<MapShape>,
    /// Each BPF_LD_IMM64 of a map: its index in `maps`, and the offset in
    /// the value of a `BPF_PSEUDO_MAP_VALUE`.
    loads: std::collections::BTreeMap<usize, (u8, Option<u32>)>,
    /// `id_gen`.
    ids: u32,
}

impl Walk {
    /// `add_used_map`: the map of `fd`, once however many times the
    /// program names it, and `check_map_prog_compatibility`.
    fn use_map(&mut self, fd: i32, options: Options, maps: &mut Maps<'_>) -> Checked<u8> {
        let shape = match maps(fd) {
            Ok(shape) => shape,
            Err(errno) => {
                return refuse(errno, format!("fd {fd} is not pointing to valid bpf_map"));
            }
        };
        if let Some(i) = self.maps.iter().position(|m| m.id == shape.id) {
            return Ok(i as u8);
        }
        if self.maps.len() >= MAX_USED_MAPS {
            return refuse(
                E2BIG,
                format!(
                    "The total number of maps per program has reached the limit of {MAX_USED_MAPS}"
                ),
            );
        }
        // 7.0 refuses one whose hash is another program's here, and master
        // after all the instructions.
        if shape.exclusive {
            return gap("maps made with excl_prog_hash");
        }
        // A sleepable program, which is refused later anyway, uses only
        // the types 7.0 lists.
        if options.sleepable
            && !matches!(
                shape.kind,
                map_type::HASH
                    | map_type::LRU_HASH
                    | map_type::ARRAY
                    | map_type::ARRAY_OF_MAPS
                    | map_type::HASH_OF_MAPS
                    | map_type::QUEUE
                    | map_type::STACK
            )
        {
            return refuse(
                Errno::EINVAL,
                "Sleepable programs can only use array, hash, ringbuf and local storage maps",
            );
        }
        self.maps.push(shape);
        Ok((self.maps.len() - 1) as u8)
    }

    /// `do_check`: every path from the first instruction, the fall-through
    /// first and the jumps' targets after, last pushed first.
    fn run(&mut self, insns: &[Insn], options: Options) -> Checked<()> {
        let mut regs = [Reg::NotInit; REGS];
        regs[1] = Reg::Ptr(Ptr::Ctx, 0);
        regs[FP] = Reg::Ptr(Ptr::Stack, 0);
        let mut state = State {
            insn: 0,
            regs,
            stack: [Slot::Bytes; (MAX_STACK / 8) as usize],
        };
        let mut pending: Vec<State> = Vec::new();
        loop {
            self.processed += 1;
            if self.processed > COMPLEXITY_LIMIT_INSNS {
                return refuse(
                    E2BIG,
                    format!(
                        "BPF program is too large. Processed {} insn",
                        self.processed
                    ),
                );
            }
            match self.step(insns, &mut state, options)? {
                Step::Next(next) => state.insn = next,
                Step::Branch(fall, target, null) => {
                    let mut other = state.clone();
                    other.insn = target;
                    if let Some((id, on_target)) = null {
                        // mark_ptr_or_null_regs on both sides.
                        other.null_check(id, on_target);
                        state.null_check(id, !on_target);
                    }
                    pending.push(other);
                    if pending.len() > COMPLEXITY_LIMIT_JMP_SEQ {
                        return refuse(
                            E2BIG,
                            format!("The sequence of {} jumps is too complex.", pending.len()),
                        );
                    }
                    state.insn = fall;
                }
                Step::Exit => match pending.pop() {
                    Some(next) => state = next,
                    None => return Ok(()),
                },
            }
        }
    }

    fn step(&mut self, insns: &[Insn], s: &mut State, options: Options) -> Checked<Step> {
        let i = s.insn;
        let insn = insns[i];
        let next = Step::Next(i + 1);
        match insn.class() {
            class::ALU | class::ALU64 => {
                alu_op(s, insn)?;
                Ok(next)
            }
            class::LDX => {
                read_ok(s, insn.src)?;
                write_ok(insn.dst)?;
                let value = self.access(s, insn.src, insn.off, insn.size(), None, options)?;
                s.regs[usize::from(insn.dst)] = value;
                Ok(next)
            }
            class::STX => {
                if insn.mode() == mode::ATOMIC {
                    return gap("atomic operations");
                }
                read_ok(s, insn.src)?;
                read_ok(s, insn.dst)?;
                let value = Store::Reg(s.regs[usize::from(insn.src)]);
                self.access(s, insn.dst, insn.off, insn.size(), Some(value), options)?;
                Ok(next)
            }
            class::ST => {
                read_ok(s, insn.dst)?;
                let value = Store::Imm(insn.imm);
                self.access(s, insn.dst, insn.off, insn.size(), Some(value), options)?;
                Ok(next)
            }
            class::JMP | class::JMP32 => self.jmp_op(s, insn, i),
            _ => {
                if insn.mode() != mode::IMM {
                    return gap("BPF_LD_ABS and BPF_LD_IND");
                }
                // check_ld_imm: a 64-bit constant, a map or a map's value.
                write_ok(insn.dst)?;
                let low = u64::from(insn.imm as u32);
                let high = u64::from(insns[i + 1].imm as u32);
                s.regs[usize::from(insn.dst)] = match self.loads.get(&i) {
                    None => Reg::Scalar(Some(high << 32 | low)),
                    Some(&(map, None)) => Reg::Ptr(Ptr::Map(map), 0),
                    Some(&(map, Some(off))) => Reg::Ptr(Ptr::Value(map), off as i32),
                };
                Ok(Step::Next(i + 2))
            }
        }
    }

    /// `check_mem_access` through the register `ptr` at `off`: a read
    /// gives the value, a write stores `value`.
    fn access(
        &mut self,
        s: &mut State,
        ptr: u8,
        off: i16,
        width: u8,
        value: Option<Store>,
        options: Options,
    ) -> Checked<Reg> {
        let bytes: i64 = match width {
            size::B => 1,
            size::H => 2,
            size::W => 4,
            _ => 8,
        };
        let reg = s.regs[usize::from(ptr)];
        match reg {
            Reg::Ptr(Ptr::Stack, base) => {
                let total = i64::from(base) + i64::from(off);
                // check_ptr_alignment: stack accesses are always strict.
                if bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned stack access off 0+{base}+{off} size {bytes}"),
                    );
                }
                let what = if value.is_some() {
                    " write to"
                } else {
                    " read from"
                };
                if !(-MAX_STACK..=-1).contains(&total) {
                    return refuse(
                        EACCES,
                        format!("invalid{what} stack R{ptr} off={total} size={bytes}"),
                    );
                }
                if total + bytes > 0 {
                    return refuse(
                        Errno::EINVAL,
                        format!("invalid{what} stack R{ptr} off={total} size={bytes}"),
                    );
                }
                self.depth = self.depth.max((-total) as u32);
                let slot = ((-total - 1) / 8) as usize;
                let aligned = total % 8 == 0;
                match value {
                    Some(value) => {
                        stack_write(s, slot, aligned, bytes, value)?;
                        Ok(Reg::NotInit)
                    }
                    None => stack_read(s, slot, bytes),
                }
            }
            Reg::Ptr(Ptr::Ctx, _) => gap("the context's fields"),
            Reg::Ptr(Ptr::Map(_), _) => gap("the fields of struct bpf_map"),
            Reg::Ptr(p @ Ptr::MaybeNull(..), _) => {
                refuse(EACCES, format!("R{ptr} invalid mem access '{}'", p.name()))
            }
            Reg::Ptr(Ptr::Value(map), base) => {
                let total = i64::from(base) + i64::from(off);
                if options.strict_alignment && bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned value access off 0+{base}+{off} size {bytes}"),
                    );
                }
                let write = value.is_some();
                self.value_access(ptr, map, total, bytes, write)?;
                Ok(Reg::Scalar(None))
            }
            Reg::Scalar(known) => {
                if options.strict_alignment && bytes > 1 {
                    match known {
                        Some(v) if v.wrapping_add(off as i64 as u64) % bytes as u64 == 0 => {}
                        Some(v) => {
                            return refuse(
                                EACCES,
                                format!(
                                    "misaligned access off {}+0+{off} size {bytes}",
                                    known_value(v)
                                ),
                            );
                        }
                        None => {
                            return refuse(
                                EACCES,
                                format!(
                                    "misaligned access off (0x0; 0xffffffffffffffff)+0+{off} size {bytes}"
                                ),
                            );
                        }
                    }
                }
                refuse(EACCES, format!("R{ptr} invalid mem access 'scalar'"))
            }
            Reg::NotInit => refuse(EACCES, format!("R{ptr} !read_ok")),
        }
    }
}

impl Walk {
    /// `check_map_access_type` and `check_map_access` of `bytes` at `off`
    /// in a value of the map through the register `r`: what
    /// `BPF_F_RDONLY_PROG` and `BPF_F_WRONLY_PROG` forbid, and the value's
    /// bounds, for which `check_mem_region_access` writes a second line.
    fn value_access(&self, r: u8, map: u8, off: i64, bytes: i64, write: bool) -> Checked<()> {
        let shape = self.maps[usize::from(map)];
        let size = i64::from(shape.value_size);
        if write && shape.flags & F_RDONLY_PROG != 0 {
            return refuse(
                EACCES,
                format!("write into map forbidden, value_size={size} off={off} size={bytes}"),
            );
        }
        if !write && shape.flags & F_WRONLY_PROG != 0 {
            return refuse(
                EACCES,
                format!("read from map forbidden, value_size={size} off={off} size={bytes}"),
            );
        }
        if off < 0 || off + bytes > size {
            return refuse(
                EACCES,
                format!(
                    "invalid access to map value, value_size={size} off={off} size={bytes}\nR{r} min value is outside of the allowed memory range"
                ),
            );
        }
        Ok(())
    }

    /// `check_helper_mem_access` of a helper's argument in `r`, which
    /// reads `bytes`: a fixed place on the stack, or in a map's value.
    fn helper_read(&mut self, s: &State, r: u8, bytes: u32) -> Checked<()> {
        read_ok(s, r)?;
        let bytes = i64::from(bytes);
        match s.regs[usize::from(r)] {
            Reg::Ptr(Ptr::Stack, base) => {
                let base = i64::from(base);
                // check_stack_range_initialized: a privileged loader may
                // pass bytes it never wrote.
                if !(-MAX_STACK..=-1).contains(&base) {
                    return refuse(
                        EACCES,
                        format!("invalid read from stack R{r} off={base} size={bytes}"),
                    );
                }
                if base + bytes > 0 {
                    return refuse(
                        Errno::EINVAL,
                        format!("invalid read from stack R{r} off={base} size={bytes}"),
                    );
                }
                self.depth = self.depth.max((-base) as u32);
                Ok(())
            }
            Reg::Ptr(Ptr::Value(map), base) => {
                self.value_access(r, map, i64::from(base), bytes, false)
            }
            _ => gap("helper arguments of other types"),
        }
    }

    /// `check_helper_call` of the map helpers in range.
    fn helper(&mut self, s: &mut State, id: i32) -> Checked<()> {
        if !matches!(
            id,
            func::MAP_LOOKUP_ELEM | func::MAP_UPDATE_ELEM | func::MAP_DELETE_ELEM
        ) {
            // libbpf and bpftool take a helper as there unless the log
            // says "unknown func" (or Linux's other words for one a type
            // cannot use), so the line starts with Linux's for an unknown
            // helper.
            return refuse(
                Errno::EINVAL,
                format!("unknown func #{id} (paludarium: helper calls are not verified yet)"),
            );
        }
        // check_func_arg of ARG_CONST_MAP_PTR.
        read_ok(s, 1)?;
        let map = match s.regs[1] {
            Reg::Ptr(Ptr::Map(map), _) => map,
            reg => {
                return refuse(
                    EACCES,
                    format!("R1 type={} expected=map_ptr", reg_name(reg)),
                );
            }
        };
        let shape = self.maps[usize::from(map)];
        if !matches!(
            shape.kind,
            map_type::ARRAY | map_type::HASH | map_type::LRU_HASH | map_type::LPM_TRIE
        ) {
            return gap("map helpers of maps of maps, queues, stacks and bloom filters");
        }
        // ARG_PTR_TO_MAP_KEY, and ARG_PTR_TO_MAP_VALUE and ARG_ANYTHING.
        self.helper_read(s, 2, shape.key_size)?;
        if id == func::MAP_UPDATE_ELEM {
            self.helper_read(s, 3, shape.value_size)?;
            read_ok(s, 4)?;
        }
        // record_func_map.
        if id != func::MAP_LOOKUP_ELEM && shape.flags & F_RDONLY_PROG != 0 {
            return refuse(EACCES, "write into map forbidden");
        }
        // The caller-saved registers.
        s.regs[1..=5].fill(Reg::NotInit);
        s.regs[0] = if id == func::MAP_LOOKUP_ELEM {
            self.ids += 1;
            Reg::Ptr(Ptr::MaybeNull(map, self.ids), 0)
        } else {
            Reg::Scalar(None)
        };
        Ok(())
    }

    /// The jumps: `BPF_JA`, `BPF_EXIT`, a call, and `check_cond_jmp_op`.
    fn jmp_op(&mut self, s: &mut State, insn: Insn, i: usize) -> Checked<Step> {
        if insn.op() == jmp::CALL {
            self.helper(s, insn.imm)?;
            return Ok(Step::Next(i + 1));
        }
        jmp_op(s, insn, i)
    }
}

/// 7.0's `tnum_strn` of a known value: in decimal up to
/// `UNUM_MAX_DECIMAL`, else in hexadecimal (master writes negative ones in
/// decimal too). The kernel's `%#llx` writes 0 as `0x0`, unlike C's.
fn known_value(v: u64) -> String {
    if v <= UNUM_MAX_DECIMAL {
        v.to_string()
    } else {
        format!("{v:#x}")
    }
}

/// `check_reg_arg` of a source: the register has been written.
fn read_ok(s: &State, r: u8) -> Checked<()> {
    if s.regs[usize::from(r)] == Reg::NotInit {
        return refuse(EACCES, format!("R{r} !read_ok"));
    }
    Ok(())
}

/// `check_reg_arg` of a destination: not the frame pointer.
fn write_ok(r: u8) -> Checked<()> {
    if usize::from(r) == FP {
        return refuse(EACCES, "frame pointer is read only");
    }
    Ok(())
}

/// `check_stack_write_fixed_off`, for a privileged loader: a register
/// or an immediate that fills an aligned slot is spilled whole, a pointer
/// only so, and anything else leaves bytes. A narrower spill of a scalar,
/// which Linux keeps, is bytes here, so its value is unknown.
fn stack_write(s: &mut State, slot: usize, aligned: bool, bytes: i64, value: Store) -> Checked<()> {
    let stored = match value {
        Store::Reg(Reg::Ptr(..)) if bytes != 8 => {
            return refuse(EACCES, "invalid size of register spill");
        }
        Store::Reg(reg @ Reg::Ptr(..)) => Slot::Spill(reg),
        Store::Reg(reg @ Reg::Scalar(_)) if aligned && bytes == 8 => Slot::Spill(reg),
        Store::Imm(imm) if aligned && bytes == 8 => {
            Slot::Spill(Reg::Scalar(Some(i64::from(imm) as u64)))
        }
        _ => Slot::Bytes,
    };
    s.stack[slot] = stored;
    Ok(())
}

/// `check_stack_read_fixed_off`, for a privileged loader.
fn stack_read(s: &State, slot: usize, bytes: i64) -> Checked<Reg> {
    match s.stack[slot] {
        Slot::Spill(reg @ Reg::Ptr(..)) => {
            if bytes != 8 {
                return refuse(EACCES, "invalid size of register fill");
            }
            Ok(reg)
        }
        Slot::Spill(reg) if bytes == 8 => Ok(reg),
        _ => Ok(Reg::Scalar(None)),
    }
}

/// `check_alu_op`.
fn alu_op(s: &mut State, insn: Insn) -> Checked<()> {
    let op = insn.op();
    let wide = insn.class() == class::ALU64;
    let dst = usize::from(insn.dst);
    match op {
        alu::NEG | alu::END => {
            read_ok(s, insn.dst)?;
            match s.regs[dst] {
                Reg::Scalar(v) => {
                    write_ok(insn.dst)?;
                    s.regs[dst] = Reg::Scalar(if op == alu::NEG {
                        v.map(|v| {
                            if wide {
                                v.wrapping_neg()
                            } else {
                                u64::from((v as u32).wrapping_neg())
                            }
                        })
                    } else {
                        None
                    });
                }
                _ => {
                    // A pointer becomes an unknown scalar, or the frame
                    // pointer refuses the write.
                    write_ok(insn.dst)?;
                    s.regs[dst] = Reg::Scalar(None);
                }
            }
            Ok(())
        }
        alu::MOV => {
            if insn.x() {
                if wide && insn.off == ADDR_SPACE_CAST {
                    return refuse(
                        Errno::EINVAL,
                        "addr_space_cast insn can only be used in a program that has an associated arena",
                    );
                }
                read_ok(s, insn.src)?;
            }
            write_ok(insn.dst)?;
            let value = if insn.x() {
                let src = s.regs[usize::from(insn.src)];
                match (wide, insn.off, src) {
                    (true, 0, src) => src,
                    (false, 0, Reg::Scalar(v)) => Reg::Scalar(v.map(|v| u64::from(v as u32))),
                    // A sign extension, or a pointer's low half.
                    _ => Reg::Scalar(None),
                }
            } else if wide {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            } else {
                Reg::Scalar(Some(u64::from(insn.imm as u32)))
            };
            s.regs[dst] = value;
            Ok(())
        }
        _ => {
            if insn.x() {
                read_ok(s, insn.src)?;
            }
            read_ok(s, insn.dst)?;
            if matches!(op, alu::DIV | alu::MOD) && !insn.x() && insn.imm == 0 {
                return refuse(Errno::EINVAL, "div by zero");
            }
            if matches!(op, alu::LSH | alu::RSH | alu::ARSH) && !insn.x() {
                let bits = if wide { 64 } else { 32 };
                if insn.imm < 0 || insn.imm >= bits {
                    return refuse(Errno::EINVAL, format!("invalid shift {}", insn.imm));
                }
            }
            write_ok(insn.dst)?;
            let d = s.regs[dst];
            let src = if insn.x() {
                s.regs[usize::from(insn.src)]
            } else {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            };
            s.regs[dst] = match (d, src) {
                (Reg::Ptr(..), Reg::Ptr(..)) => {
                    if op == alu::SUB {
                        Reg::Scalar(None)
                    } else {
                        return refuse(
                            EACCES,
                            format!("R{dst} pointer {} pointer prohibited", alu_name(op)),
                        );
                    }
                }
                (Reg::Scalar(v), Reg::Ptr(p, off)) => pointer_math(insn, p, off, v, true)?,
                (Reg::Ptr(p, off), Reg::Scalar(v)) => pointer_math(insn, p, off, v, false)?,
                (Reg::Scalar(a), Reg::Scalar(b)) => Reg::Scalar(scalar_math(insn, a, b)),
                _ => Reg::Scalar(None),
            };
            Ok(())
        }
    }
}

/// `adjust_ptr_min_max_vals` of a pointer and a scalar (`scalar` is the
/// destination when `scalar_is_dst`), for a privileged loader, refusing
/// what 7.0 refuses.
fn pointer_math(
    insn: Insn,
    ptr: Ptr,
    base: i32,
    scalar: Option<u64>,
    scalar_is_dst: bool,
) -> Checked<Reg> {
    let op = insn.op();
    let dst = insn.dst;
    if insn.class() != class::ALU64 {
        if op == alu::SUB {
            return Ok(Reg::Scalar(None));
        }
        return refuse(
            EACCES,
            format!("R{dst} 32-bit pointer arithmetic prohibited"),
        );
    }
    if let Ptr::MaybeNull(..) = ptr {
        return refuse(
            EACCES,
            format!(
                "R{dst} pointer arithmetic on {} prohibited, null-check it first",
                ptr.name()
            ),
        );
    }
    if let Ptr::Map(_) = ptr
        && !(scalar == Some(0) && op == alu::ADD)
    {
        return refuse(
            EACCES,
            format!("R{dst} pointer arithmetic on {} prohibited", ptr.name()),
        );
    }
    // check_reg_sane_offset of the scalar, then of the pointer.
    let Some(value) = scalar else {
        return gap("pointers with a variable offset");
    };
    let value = value as i64;
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&value) {
        return refuse(
            Errno::EINVAL,
            format!(
                "math between {} pointer and {value} is not allowed",
                ptr.name()
            ),
        );
    }
    let base64 = i64::from(base);
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&base64) {
        return refuse(
            Errno::EINVAL,
            format!("{} pointer offset {base} is not allowed", ptr.name()),
        );
    }
    let off = match op {
        alu::ADD => base64 + value,
        alu::SUB => {
            if scalar_is_dst {
                return refuse(
                    EACCES,
                    format!("R{dst} tried to subtract pointer from scalar"),
                );
            }
            if ptr == Ptr::Stack {
                return refuse(
                    EACCES,
                    format!("R{dst} subtraction from stack pointer prohibited"),
                );
            }
            base64 - value
        }
        alu::AND | alu::OR | alu::XOR => {
            return refuse(
                EACCES,
                format!(
                    "R{dst} bitwise operator {} on pointer prohibited",
                    alu_name(op)
                ),
            );
        }
        _ => {
            return refuse(
                EACCES,
                format!(
                    "R{dst} pointer arithmetic with {} operator prohibited",
                    alu_name(op)
                ),
            );
        }
    };
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&off) {
        return refuse(
            Errno::EINVAL,
            format!("{} pointer offset {off} is not allowed", ptr.name()),
        );
    }
    Ok(Reg::Ptr(ptr, off as i32))
}

/// The value of an operation of two scalars, where Linux's tnum gives it
/// exactly; any other is unknown here.
fn scalar_math(insn: Insn, a: Option<u64>, b: Option<u64>) -> Option<u64> {
    let (a, b) = (a?, b?);
    let wide = insn.class() == class::ALU64;
    let bits = if wide { 64 } else { 32 };
    let op = insn.op();
    // is_safe_to_compute_dst_reg_range: a shift by a register is known
    // only when all of its 64 bits are below the width.
    if matches!(op, alu::LSH | alu::RSH | alu::ARSH) && b >= bits {
        return None;
    }
    if wide {
        Some(match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::AND => a & b,
            alu::OR => a | b,
            alu::XOR => a ^ b,
            alu::LSH => a << b,
            alu::RSH => a >> b,
            alu::ARSH => ((a as i64) >> b) as u64,
            _ => return None,
        })
    } else {
        let (a, b) = (a as u32, b as u32);
        Some(u64::from(match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::AND => a & b,
            alu::OR => a | b,
            alu::XOR => a ^ b,
            alu::LSH => a << b,
            alu::RSH => a >> b,
            alu::ARSH => ((a as i32) >> b) as u32,
            _ => return None,
        }))
    }
}

/// The jumps: `BPF_JA`, `BPF_EXIT`, a call, and `check_cond_jmp_op`.
fn jmp_op(s: &mut State, insn: Insn, i: usize) -> Checked<Step> {
    match insn.op() {
        jmp::CALL => unreachable!("Walk::jmp_op calls the helpers"),
        jmp::JA if insn.x() => gap("indirect jumps"),
        jmp::JA => Ok(Step::Next((i as i64 + insn.jump() + 1) as usize)),
        jmp::EXIT => {
            // check_return_code: R0 is readable; a socket filter's may be
            // any value, and a privileged loader's a pointer.
            read_ok(s, 0)?;
            Ok(Step::Exit)
        }
        jmp::JCOND => gap("may_goto"),
        op => {
            read_ok(s, insn.dst)?;
            let b = if insn.x() {
                read_ok(s, insn.src)?;
                s.regs[usize::from(insn.src)]
            } else {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            };
            let target = (i as i64 + i64::from(insn.off) + 1) as usize;
            let a = s.regs[usize::from(insn.dst)];
            match (a, b) {
                (Reg::Scalar(Some(a)), Reg::Scalar(Some(b))) => {
                    if taken(op, a, b, insn.class() == class::JMP32) {
                        Ok(Step::Next(target))
                    } else {
                        Ok(Step::Next(i + 1))
                    }
                }
                // A 64-bit comparison of a lookup's result with 0 tells
                // whether it is null.
                (Reg::Ptr(Ptr::MaybeNull(_, id), _), _)
                    if insn.class() == class::JMP
                        && !insn.x()
                        && insn.imm == 0
                        && matches!(op, jmp::JEQ | jmp::JNE) =>
                {
                    Ok(Step::Branch(i + 1, target, Some((id, op == jmp::JEQ))))
                }
                _ => Ok(Step::Branch(i + 1, target, None)),
            }
        }
    }
}

/// `is_branch_taken` of two known values.
fn taken(op: u8, a: u64, b: u64, narrow: bool) -> bool {
    let (a, b) = if narrow {
        (u64::from(a as u32), u64::from(b as u32))
    } else {
        (a, b)
    };
    let (sa, sb) = if narrow {
        (i64::from(a as u32 as i32), i64::from(b as u32 as i32))
    } else {
        (a as i64, b as i64)
    };
    match op {
        jmp::JEQ => a == b,
        jmp::JNE => a != b,
        jmp::JSET => a & b != 0,
        jmp::JGT => a > b,
        jmp::JGE => a >= b,
        jmp::JLT => a < b,
        jmp::JLE => a <= b,
        jmp::JSGT => sa > sb,
        jmp::JSGE => sa >= sb,
        jmp::JSLT => sa < sb,
        _ => sa <= sb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }
    /// `r = imm`, 64-bit.
    fn mov(dst: u8, imm: i32) -> Insn {
        i(0xb7, dst, 0, 0, imm)
    }
    /// `dst = src`, 64-bit.
    fn mov_reg(dst: u8, src: u8) -> Insn {
        i(0xbf, dst, src, 0, 0)
    }
    fn exit() -> Insn {
        i(0x95, 0, 0, 0, 0)
    }
    fn stx_dw(dst: u8, src: u8, off: i16) -> Insn {
        i(0x7b, dst, src, off, 0)
    }
    fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
        i(0x61 | size, dst, src, off, 0)
    }
    /// The maps of the tests, by descriptor: 3 an array of one 8-byte
    /// value with 4-byte keys, 4 a hash with 8-byte keys and values, 5 a
    /// read-only array, 6 a queue; any other is no map.
    fn maps(fd: i32) -> Result<MapShape, Errno> {
        let shape = |id, kind, key_size, value_size, max_entries, flags| MapShape {
            id,
            kind,
            key_size,
            value_size,
            max_entries,
            flags,
            exclusive: false,
        };
        match fd {
            3 => Ok(shape(30, map_type::ARRAY, 4, 8, 1, 0)),
            4 => Ok(shape(40, map_type::HASH, 8, 8, 16, 0)),
            5 => Ok(shape(50, map_type::ARRAY, 4, 8, 1, F_RDONLY_PROG)),
            6 => Ok(shape(60, map_type::QUEUE, 0, 8, 4, 0)),
            7 => Err(Errno::EINVAL),
            _ => Err(Errno::EBADF),
        }
    }
    fn verify(insns: &[Insn], options: Options) -> Result<Verified, Rejection> {
        check(insns, options, &mut maps)
    }
    fn ok(insns: &[Insn]) -> u32 {
        match verify(insns, Options::default()) {
            Ok(v) => v.processed,
            Err(r) => panic!("refused: {} ({:?})", r.line, r.errno),
        }
    }
    fn refused(insns: &[Insn]) -> (Errno, String) {
        let r = verify(insns, Options::default()).expect_err("accepted");
        (r.errno, r.line)
    }

    #[test]
    fn a_constant_return_loads() {
        assert_eq!(ok(&[mov(0, 0), exit()]), 2);
        // A 64-bit constant counts once.
        assert_eq!(ok(&[i(0x18, 0, 0, 0, 1), i(0, 0, 0, 0, 2), exit()]), 2);
    }

    #[test]
    fn r0_must_be_written_before_the_exit() {
        assert_eq!(refused(&[exit()]), (EACCES, "R0 !read_ok".into()));
        // A privileged loader may return a pointer.
        ok(&[mov_reg(0, 10), exit()]);
    }

    #[test]
    fn the_structure_is_checked_first() {
        let einval = |line: &str| (Errno::EINVAL, line.to_string());
        assert_eq!(
            refused(&[i(0x8c, 0, 0, 0, 0), exit()]),
            einval("unknown opcode 8c")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x05, 0, 0, 5, 0)]),
            einval("jump out of range from insn 1 to 7")
        );
        assert_eq!(
            refused(&[mov(0, 0)]),
            einval("last insn is not an exit or jmp")
        );
        assert_eq!(
            refused(&[mov(0, 0), exit(), exit()]),
            einval("unreachable insn 2")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x05, 0, 0, -2, 0)]),
            einval("back-edge from insn 1 to 0")
        );
        assert!(ends_in_half(&[mov(0, 0), i(0x18, 0, 0, 0, 0)]));
        assert!(!ends_in_half(&[i(0x18, 0, 0, 0, 0), i(0, 0, 0, 0, 0)]));
        assert_eq!(
            refused(&[i(0x18, 0, 0, 0, 0), i(0, 1, 0, 0, 0), exit()]),
            einval("invalid bpf_ld_imm64 insn")
        );
        assert_eq!(
            refused(&[i(0x18, 0, 0, 1, 0), i(0, 0, 0, 0, 0), exit()]),
            einval("BPF_LD_IMM64 uses reserved fields")
        );
        assert_eq!(
            refused(&[i(0x18, 0, 7, 0, 0), i(0, 0, 0, 0, 0), exit()]),
            einval("unrecognized bpf_ld_imm64 insn")
        );
        assert_eq!(
            refused(&[
                mov(0, 0),
                i(0x15, 0, 0, 1, 0),
                i(0x18, 0, 0, 0, 0),
                i(0, 0, 0, 0, 0),
                exit()
            ]),
            einval("jump into the middle of ldimm64 insn 2")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x95, 0, 1, 0, 0)]),
            einval("BPF_EXIT uses reserved fields")
        );
        assert_eq!(refused(&[mov(11, 0), exit()]), einval("R11 is invalid"));
        assert_eq!(
            refused(&[mov(0, 0), i(0x37, 0, 0, 0, 0), exit()]),
            einval("div by zero")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x67, 0, 0, 0, 64), exit()]),
            einval("invalid shift 64")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x64, 0, 0, 0, 32), exit()]),
            einval("invalid shift 32")
        );
    }

    #[test]
    fn the_frame_pointer_is_read_only() {
        assert_eq!(
            refused(&[mov(10, 0), mov(0, 0), exit()]),
            (EACCES, "frame pointer is read only".into())
        );
        assert_eq!(
            refused(&[i(0x07, 10, 0, 0, -8), mov(0, 0), exit()]),
            (EACCES, "frame pointer is read only".into())
        );
    }

    #[test]
    fn a_pointer_spilled_whole_comes_back() {
        ok(&[stx_dw(10, 10, -8), ldx(0x18, 0, 10, -8), exit()]);
        assert_eq!(
            refused(&[stx_dw(10, 10, -8), ldx(0x00, 0, 10, -8), exit()]),
            (EACCES, "invalid size of register fill".into())
        );
        assert_eq!(
            refused(&[i(0x63, 10, 10, -8, 0), mov(0, 0), exit()]),
            (EACCES, "invalid size of register spill".into())
        );
        // A scalar written over part of it leaves a number.
        ok(&[
            stx_dw(10, 10, -8),
            mov(1, 0),
            i(0x63, 10, 1, -4, 0),
            ldx(0x18, 0, 10, -8),
            i(0x27, 0, 0, 0, 3),
            exit(),
        ]);
        // So does a stack slot never written, for a privileged loader.
        ok(&[ldx(0x18, 0, 10, -512), exit()]);
    }

    #[test]
    fn the_stack_is_512_aligned_bytes_below_the_frame() {
        assert_eq!(
            refused(&[mov(0, 0), stx_dw(10, 0, -520), exit()]),
            (EACCES, "invalid write to stack R10 off=-520 size=8".into())
        );
        assert_eq!(
            refused(&[ldx(0x18, 0, 10, 0), exit()]),
            (EACCES, "invalid read from stack R10 off=0 size=8".into())
        );
        assert_eq!(
            refused(&[mov(0, 0), stx_dw(10, 0, -4), exit()]),
            (EACCES, "misaligned stack access off 0+0+-4 size 8".into())
        );
        assert_eq!(
            refused(&[
                mov_reg(1, 10),
                i(0x07, 1, 0, 0, -6),
                ldx(0x00, 0, 1, 0),
                exit()
            ]),
            (EACCES, "misaligned stack access off 0+-6+0 size 4".into())
        );
        // A pointer the program moves keeps its offset.
        ok(&[
            mov_reg(1, 10),
            i(0x07, 1, 0, 0, -16),
            mov(2, 7),
            stx_dw(1, 2, 8),
            ldx(0x18, 0, 10, -8),
            exit(),
        ]);
    }

    #[test]
    fn pointer_arithmetic_is_7_0s() {
        let eacces = |line: &str| (EACCES, line.to_string());
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x17, 1, 0, 0, 8), mov(0, 0), exit()]),
            eacces("R1 subtraction from stack pointer prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x27, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 pointer arithmetic with *= operator prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x57, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 bitwise operator &= on pointer prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x04, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 32-bit pointer arithmetic prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x0f, 1, 10, 0, 0), mov(0, 0), exit()]),
            eacces("R1 pointer += pointer prohibited")
        );
        assert_eq!(
            refused(&[mov(1, 8), i(0x1f, 1, 10, 0, 0), mov(0, 0), exit()]),
            eacces("R1 tried to subtract pointer from scalar")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x07, 1, 0, 0, 1 << 29), mov(0, 0), exit()]),
            (
                Errno::EINVAL,
                "math between fp pointer and 536870912 is not allowed".into()
            )
        );
        // Pointers less pointers, and 32-bit differences, are numbers.
        ok(&[mov_reg(0, 10), i(0x1f, 0, 1, 0, 0), exit()]);
        ok(&[mov_reg(0, 10), i(0x14, 0, 0, 0, 1), exit()]);
        // A known scalar plus the frame pointer is a stack pointer.
        ok(&[
            mov(1, -8),
            i(0x0f, 1, 10, 0, 0),
            mov(0, 0),
            stx_dw(1, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn a_scalar_is_no_pointer() {
        assert_eq!(
            refused(&[mov(1, 0), ldx(0x18, 0, 1, 0), exit()]),
            (EACCES, "R1 invalid mem access 'scalar'".into())
        );
    }

    #[test]
    fn a_branch_both_operands_know_goes_one_way() {
        // The fall-through would read through a scalar.
        ok(&[mov(0, 0), i(0x15, 0, 0, 1, 0), ldx(0x18, 1, 0, 0), exit()]);
        // Not knowing R0, both ways are walked.
        assert_eq!(
            refused(&[
                ldx(0x18, 0, 10, -8),
                i(0x15, 0, 0, 1, 0),
                ldx(0x18, 1, 0, 0),
                exit()
            ]),
            (EACCES, "R0 invalid mem access 'scalar'".into())
        );
        // A 32-bit jump compares the low halves.
        ok(&[
            i(0x18, 0, 0, 0, 5),
            i(0, 0, 0, 0, 1),
            i(0x16, 0, 0, 1, 5),
            ldx(0x18, 1, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn known_values_follow_the_operations() {
        // (3 * 4 - 2) << 1 == 20, 32-bit -1 >> 28 == 15.
        ok(&[
            mov(1, 3),
            i(0x27, 1, 0, 0, 4),
            i(0x17, 1, 0, 0, 2),
            i(0x67, 1, 0, 0, 1),
            i(0x55, 1, 0, 2, 20),
            i(0xb4, 2, 0, 0, -1),
            i(0x74, 2, 0, 0, 28),
            i(0x55, 2, 0, 1, 15),
            mov(0, 0),
            exit(),
        ]);
        // A division is not followed here, so both ways are walked.
        assert!(
            verify(
                &[
                    mov(1, 8),
                    i(0x37, 1, 0, 0, 2),
                    i(0x55, 1, 0, 1, 4),
                    ldx(0x18, 0, 1, 0),
                    mov(0, 0),
                    exit()
                ],
                Options::default()
            )
            .is_err()
        );
    }

    #[test]
    fn what_is_not_verified_yet_is_refused() {
        let gap = |insns: &[Insn]| {
            let (errno, line) = refused(insns);
            assert_eq!(errno, Errno::EINVAL);
            assert!(line.contains("paludarium: "), "{line}");
        };
        gap(&[i(0x85, 0, 0, 0, 7), exit()]);
        gap(&[i(0x85, 0, 1, 0, 1), exit(), mov(0, 0), exit()]);
        gap(&[ldx(0x10, 0, 1, 0), exit()]);
        // A queue's helpers are push, pop and peek.
        gap(&[
            i(0x18, 1, 1, 0, 6),
            i(0, 0, 0, 0, 0),
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -8),
            i(0x85, 0, 0, 0, 1),
            exit(),
        ]);
        gap(&[i(0x30, 0, 0, 0, 0), exit()]);
        gap(&[mov(0, 0), i(0xdb, 10, 0, -8, 0), exit()]);
        gap(&[
            mov(1, -8),
            ldx(0x18, 0, 10, -8),
            i(0x0f, 0, 10, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn a_sleepable_socket_filter_is_refused() {
        let options = Options {
            sleepable: true,
            ..Options::default()
        };
        let r = verify(&[mov(0, 0), exit()], options).expect_err("accepted");
        assert_eq!(r.errno, Errno::EINVAL);
        assert!(r.line.ends_with("can be sleepable"));
    }

    #[test]
    fn the_walk_stops_at_the_pending_branch_limit() {
        // Each unknown jump leaves its target to walk later.
        let mut insns = vec![ldx(0x18, 0, 10, -8)];
        for _ in 0..=COMPLEXITY_LIMIT_JMP_SEQ {
            insns.push(i(0x15, 0, 0, 0, 0));
        }
        insns.push(exit());
        let r = verify(&insns, Options::default()).expect_err("accepted");
        assert_eq!(r.errno, E2BIG);
        assert_eq!(r.line, "The sequence of 8193 jumps is too complex.");
    }

    /// `r = map fd`, two instructions.
    fn ld_map(dst: u8, fd: i32) -> [Insn; 2] {
        [i(0x18, dst, 1, 0, fd), i(0, 0, 0, 0, 0)]
    }
    fn call(id: i32) -> Insn {
        i(0x85, 0, 0, 0, id)
    }
    /// A lookup of the key 0 at fp-4 in the map of `fd`, leaving R0.
    fn lookup(fd: i32) -> Vec<Insn> {
        let mut v = vec![i(0x62, 10, 0, -4, 0)];
        v.extend(ld_map(1, fd));
        v.extend([mov_reg(2, 10), i(0x07, 2, 0, 0, -4), call(1)]);
        v
    }

    #[test]
    fn a_lookup_must_be_null_checked() {
        let mut p = lookup(3);
        p.extend([ldx(0x18, 0, 0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EACCES, "R0 invalid mem access 'map_value_or_null'".into())
        );
        // if r0 == 0 goto exit; r0 = *(u64 *)(r0 + 0)
        let mut p = lookup(3);
        p.extend([i(0x15, 0, 0, 1, 0), ldx(0x18, 0, 0, 0), exit()]);
        ok(&p);
        // A copy spilled before the check is checked with it.
        let mut p = lookup(3);
        p.extend([
            stx_dw(10, 0, -16),
            i(0x55, 0, 0, 2, 0),
            mov(0, 0),
            exit(),
            ldx(0x18, 1, 10, -16),
            ldx(0x18, 0, 1, 0),
            exit(),
        ]);
        ok(&p);
        // A 32-bit comparison does not tell.
        let mut p = lookup(3);
        p.extend([i(0x16, 0, 0, 1, 0), ldx(0x18, 0, 0, 0), exit()]);
        assert_eq!(refused(&p).1, "R0 invalid mem access 'map_value_or_null'");
        let mut p = lookup(3);
        p.extend([i(0x07, 0, 0, 0, 1), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "R0 pointer arithmetic on map_value_or_null prohibited, null-check it first".into()
            )
        );
    }

    #[test]
    fn a_maps_value_has_its_bounds_and_access() {
        let mut p = lookup(3);
        p.extend([i(0x15, 0, 0, 1, 0), ldx(0x18, 0, 0, 4), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "invalid access to map value, value_size=8 off=4 size=8\nR0 min value is outside of the allowed memory range".into()
            )
        );
        let mut p = lookup(5);
        p.extend([i(0x15, 0, 0, 1, 0), i(0x7a, 0, 0, 0, 1), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "write into map forbidden, value_size=8 off=0 size=8".into()
            )
        );
        // The direct value of an array of one element.
        let mut p = vec![i(0x18, 1, 2, 0, 3), i(0, 0, 0, 0, 4)];
        p.extend([ldx(0x00, 0, 1, 0), exit()]);
        ok(&p);
        let mut p = vec![i(0x18, 1, 2, 0, 3), i(0, 0, 0, 0, 8)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "invalid access to map value pointer, value_size=8 off=8".into()
            )
        );
        let mut p = vec![i(0x18, 1, 2, 0, 4), i(0, 0, 0, 0, 0)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "no direct value access support for this map type".into()
            )
        );
    }

    #[test]
    fn a_map_is_named_by_its_descriptor() {
        let mut p = ld_map(1, 9).to_vec();
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (Errno::EBADF, "fd 9 is not pointing to valid bpf_map".into())
        );
        let mut p = ld_map(1, 7).to_vec();
        p.extend([mov(0, 0), exit()]);
        assert_eq!(refused(&p).0, Errno::EINVAL);
        let mut p = vec![i(0x18, 1, 5, 0, 0), i(0, 0, 0, 0, 0)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EPROTO, "fd_idx without fd_array is invalid".into())
        );
        // The map pointer itself takes only += 0.
        let mut p = ld_map(1, 3).to_vec();
        p.extend([i(0x07, 1, 0, 0, 0), i(0x07, 1, 0, 0, 8), mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EACCES, "R1 pointer arithmetic on map_ptr prohibited".into())
        );
        // One map named twice is one map.
        let mut p = ld_map(1, 3).to_vec();
        p.extend(ld_map(2, 3));
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            verify(&p, Options::default()).map(|v| v.maps).ok(),
            Some(vec![30])
        );
    }

    #[test]
    fn the_map_helpers_check_their_arguments() {
        // update(map, key, value, flags), then the arguments are gone.
        let mut p = vec![stx_dw(10, 10, -8), i(0x62, 10, 0, -12, 0)];
        p.extend(ld_map(1, 3));
        p.extend([
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -12),
            mov_reg(3, 10),
            i(0x07, 3, 0, 0, -8),
            mov(4, 0),
            call(2),
            mov_reg(0, 1),
            exit(),
        ]);
        assert_eq!(refused(&p), (EACCES, "R1 !read_ok".into()));
        let n = p.len();
        p[n - 2] = mov(0, 0);
        ok(&p);
        // The key must be within the stack.
        let mut p = ld_map(1, 4).to_vec();
        p.extend([
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -4),
            call(1),
            mov(0, 0),
            exit(),
        ]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "invalid read from stack R2 off=-4 size=8".into()
            )
        );
        assert_eq!(
            refused(&[mov(1, 0), mov(2, 0), call(1), exit()]),
            (EACCES, "R1 type=scalar expected=map_ptr".into())
        );
        let mut p = vec![i(0x62, 10, 0, -4, 0)];
        p.extend(ld_map(1, 5));
        p.extend([mov_reg(2, 10), i(0x07, 2, 0, 0, -4), call(3), exit()]);
        assert_eq!(refused(&p), (EACCES, "write into map forbidden".into()));
    }
}
