//! Integer instructions the encodings oracle does not reach, each with only
//! its architecturally defined results checked. The expected values were
//! taken from the same instruction run under Rosetta on x86-64 macOS, or,
//! for POPCNT, LZCNT, BMI1/2, ADX and MOVBE, which Rosetta lacks, from the
//! instruction's definition (marked "definition").
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};

const CF: u64 = 1;
const PF: u64 = 4;
const AF: u64 = 0x10;
const ZF: u64 = 0x40;
const SF: u64 = 0x80;
const OF: u64 = 0x800;
const DATA: u64 = 0x4000_0000;
const CODE: u64 = 0x10000;

struct Case {
    name: &'static str,
    code: &'static [u8],
    regs: &'static [(usize, u64)],
    flags: u64,
    /// 16 bytes at `DATA`, which `base` points at.
    memory: Option<([u8; 16], usize)>,
    check: &'static [(usize, u64)],
    mask: u64,
    flags_out: u64,
    memory_out: Option<[u8; 16]>,
}

fn fixture(code: &[u8]) -> (CpuState, AddressSpace) {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(CODE)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory
        .map(
            Some(GuestAddr(DATA)),
            8192,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write_initial(GuestAddr(CODE), code).unwrap();
    (
        CpuState::new(GuestAddr(CODE), GuestAddr(DATA + 4096)),
        memory,
    )
}
const CASES: &[Case] = &[
    // shr rax, 4 (rosetta)
    Case {
        name: "shr",
        code: &[0x48, 0xc1, 0xe8, 0x04],
        regs: &[(reg::RAX, 0xf3)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xf)],
        mask: CF | PF | ZF | SF,
        flags_out: PF,
        memory_out: None,
    },
    // sar rax, 4 (rosetta)
    Case {
        name: "sar",
        code: &[0x48, 0xc1, 0xf8, 0x04],
        regs: &[(reg::RAX, 0x8000000000000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xf800000000000000)],
        mask: CF | PF | ZF | SF,
        flags_out: PF | SF,
        memory_out: None,
    },
    // sar ebx, cl (rosetta)
    Case {
        name: "sar_cl",
        code: &[0xd3, 0xfb],
        regs: &[(reg::RBX, 0x80000010), (reg::RCX, 0x21)],
        flags: 0,
        memory: None,
        check: &[(reg::RBX, 0xc0000008)],
        mask: CF | PF | ZF | SF,
        flags_out: SF,
        memory_out: None,
    },
    // shld rax, rbx, 4 (rosetta)
    Case {
        name: "shld",
        code: &[0x48, 0x0f, 0xa4, 0xd8, 0x04],
        regs: &[(reg::RAX, 0x1), (reg::RBX, 0xf000000000000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x1f)],
        mask: CF | PF | ZF | SF,
        flags_out: 0,
        memory_out: None,
    },
    // shld eax, ebx, cl (rosetta)
    Case {
        name: "shld_cl",
        code: &[0x0f, 0xa5, 0xd8],
        regs: &[
            (reg::RAX, 0x80000001),
            (reg::RBX, 0xc0000000),
            (reg::RCX, 0x2),
        ],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x7)],
        mask: CF | PF | ZF | SF,
        flags_out: 0,
        memory_out: None,
    },
    // shrd rax, rbx, 8 (rosetta)
    Case {
        name: "shrd",
        code: &[0x48, 0x0f, 0xac, 0xd8, 0x08],
        regs: &[(reg::RAX, 0x12b4), (reg::RBX, 0xab)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xab00000000000012)],
        mask: CF | PF | ZF | SF,
        flags_out: CF | PF | SF,
        memory_out: None,
    },
    // shrd ax, bx, 4 (rosetta)
    Case {
        name: "shrd_16",
        code: &[0x66, 0x0f, 0xac, 0xd8, 0x04],
        regs: &[(reg::RAX, 0x1238), (reg::RBX, 0xabcd)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xd123)],
        mask: CF | PF | ZF | SF,
        flags_out: CF | SF,
        memory_out: None,
    },
    // imul rax, rbx, 7 (rosetta)
    Case {
        name: "imul3",
        code: &[0x48, 0x6b, 0xc3, 0x07],
        regs: &[(reg::RBX, 0x6)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x2a)],
        mask: CF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // imul rax, rbx (rosetta)
    Case {
        name: "imul2_overflow",
        code: &[0x48, 0x0f, 0xaf, 0xc3],
        regs: &[(reg::RAX, 0x4000000000000000), (reg::RBX, 0x4)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // imul rbx (rosetta)
    Case {
        name: "imul1",
        code: &[0x48, 0xf7, 0xeb],
        regs: &[(reg::RAX, 0xfffffffffffffffd), (reg::RBX, 0x5)],
        flags: 0,
        memory: None,
        check: &[
            (reg::RAX, 0xfffffffffffffff1),
            (reg::RDX, 0xffffffffffffffff),
        ],
        mask: CF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // imul ebx (rosetta)
    Case {
        name: "imul1_32",
        code: &[0xf7, 0xeb],
        regs: &[(reg::RAX, 0x7fffffff), (reg::RBX, 0x2)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xfffffffe), (reg::RDX, 0x0)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // imul bl (rosetta)
    Case {
        name: "imul_byte",
        code: &[0xf6, 0xeb],
        regs: &[(reg::RAX, 0x80), (reg::RBX, 0xff)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x80)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // imul ax, bx, -2 (rosetta)
    Case {
        name: "imul3_16",
        code: &[0x66, 0x6b, 0xc3, 0xfe],
        regs: &[(reg::RBX, 0x4000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x8000)],
        mask: CF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // mul rbx (rosetta)
    Case {
        name: "mul",
        code: &[0x48, 0xf7, 0xe3],
        regs: &[(reg::RAX, 0x8000000000000000), (reg::RBX, 0x4)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x0), (reg::RDX, 0x2)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // mul ebx (rosetta)
    Case {
        name: "mul_32",
        code: &[0xf7, 0xe3],
        regs: &[(reg::RAX, 0xffffffff), (reg::RBX, 0xffffffff)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x1), (reg::RDX, 0xfffffffe)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // mul bl (rosetta)
    Case {
        name: "mul_byte",
        code: &[0xf6, 0xe3],
        regs: &[(reg::RAX, 0x10), (reg::RBX, 0x10)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x100)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // div rbx (rosetta)
    Case {
        name: "div",
        code: &[0x48, 0xf7, 0xf3],
        regs: &[(reg::RDX, 0x0), (reg::RAX, 0x64), (reg::RBX, 0x7)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xe), (reg::RDX, 0x2)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // idiv rbx (rosetta)
    Case {
        name: "idiv",
        code: &[0x48, 0xf7, 0xfb],
        regs: &[
            (reg::RDX, 0xffffffffffffffff),
            (reg::RAX, 0xffffffffffffff9c),
            (reg::RBX, 0x7),
        ],
        flags: 0,
        memory: None,
        check: &[
            (reg::RAX, 0xfffffffffffffff2),
            (reg::RDX, 0xfffffffffffffffe),
        ],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // idiv ebx (rosetta)
    Case {
        name: "idiv_32",
        code: &[0xf7, 0xfb],
        regs: &[
            (reg::RDX, 0xffffffff),
            (reg::RAX, 0xffffff9c),
            (reg::RBX, 0x7),
        ],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xfffffff2), (reg::RDX, 0xfffffffe)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // idiv bl (rosetta)
    Case {
        name: "idiv_byte",
        code: &[0xf6, 0xfb],
        regs: &[(reg::RAX, 0xff9c), (reg::RBX, 0x7)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xfef2)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // div bx (rosetta)
    Case {
        name: "div_16",
        code: &[0x66, 0xf7, 0xf3],
        regs: &[(reg::RDX, 0x1), (reg::RAX, 0x0), (reg::RBX, 0x100)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x100), (reg::RDX, 0x0)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // rol rax, 4 (rosetta)
    Case {
        name: "rol",
        code: &[0x48, 0xc1, 0xc0, 0x04],
        regs: &[(reg::RAX, 0xf000000000000001)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x1f)],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // ror rax, 4 (rosetta)
    Case {
        name: "ror",
        code: &[0x48, 0xc1, 0xc8, 0x04],
        regs: &[(reg::RAX, 0x1f)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xf000000000000001)],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // rol al, 1 (rosetta)
    Case {
        name: "rol1",
        code: &[0xd0, 0xc0],
        regs: &[(reg::RAX, 0x81)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x3)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // ror ebx, cl (rosetta)
    Case {
        name: "ror_cl",
        code: &[0xd3, 0xcb],
        regs: &[(reg::RBX, 0x80000001), (reg::RCX, 0x1)],
        flags: 0,
        memory: None,
        check: &[(reg::RBX, 0xc0000000)],
        mask: CF | OF,
        flags_out: CF,
        memory_out: None,
    },
    // rcl rax, 1 (rosetta)
    Case {
        name: "rcl",
        code: &[0x48, 0xd1, 0xd0],
        regs: &[(reg::RAX, 0x8000000000000000)],
        flags: CF,
        memory: None,
        check: &[(reg::RAX, 0x1)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // rcr rax, 1 (rosetta)
    Case {
        name: "rcr",
        code: &[0x48, 0xd1, 0xd8],
        regs: &[(reg::RAX, 0x1)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | OF,
        flags_out: CF,
        memory_out: None,
    },
    // rcl bx, 3 (rosetta)
    Case {
        name: "rcl_16",
        code: &[0x66, 0xc1, 0xd3, 0x03],
        regs: &[(reg::RBX, 0xa001)],
        flags: CF,
        memory: None,
        check: &[(reg::RBX, 0xe)],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // rcr bl, 2 (rosetta)
    Case {
        name: "rcr_byte",
        code: &[0xc0, 0xdb, 0x02],
        regs: &[(reg::RBX, 0x3)],
        flags: CF,
        memory: None,
        check: &[(reg::RBX, 0xc0)],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // bsf rax, rbx (rosetta)
    Case {
        name: "bsf",
        code: &[0x48, 0x0f, 0xbc, 0xc3],
        regs: &[(reg::RBX, 0x80)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x7)],
        mask: ZF,
        flags_out: 0,
        memory_out: None,
    },
    // bsr rax, rbx (rosetta)
    Case {
        name: "bsr",
        code: &[0x48, 0x0f, 0xbd, 0xc3],
        regs: &[(reg::RBX, 0x80)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x7)],
        mask: ZF,
        flags_out: 0,
        memory_out: None,
    },
    // bsr ax, bx (rosetta)
    Case {
        name: "bsr_16",
        code: &[0x66, 0x0f, 0xbd, 0xc3],
        regs: &[(reg::RBX, 0x100)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x8)],
        mask: ZF,
        flags_out: 0,
        memory_out: None,
    },
    // bsf rax, rbx (rosetta)
    Case {
        name: "bsf_zero",
        code: &[0x48, 0x0f, 0xbc, 0xc3],
        regs: &[(reg::RBX, 0x0)],
        flags: 0,
        memory: None,
        check: &[],
        mask: ZF,
        flags_out: ZF,
        memory_out: None,
    },
    // tzcnt rax, rbx (definition)
    Case {
        name: "tzcnt",
        code: &[0xf3, 0x48, 0x0f, 0xbc, 0xc3],
        regs: &[(reg::RBX, 0x10)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x4)],
        mask: CF | ZF,
        flags_out: 0,
        memory_out: None,
    },
    // tzcnt eax, ebx (definition)
    Case {
        name: "tzcnt_zero",
        code: &[0xf3, 0x0f, 0xbc, 0xc3],
        regs: &[(reg::RBX, 0x0)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x20)],
        mask: CF | ZF,
        flags_out: CF,
        memory_out: None,
    },
    // lzcnt rax, rbx (definition)
    Case {
        name: "lzcnt",
        code: &[0xf3, 0x48, 0x0f, 0xbd, 0xc3],
        regs: &[(reg::RBX, 0x1)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x3f)],
        mask: CF | ZF,
        flags_out: 0,
        memory_out: None,
    },
    // lzcnt ax, bx (definition)
    Case {
        name: "lzcnt_zero",
        code: &[0x66, 0xf3, 0x0f, 0xbd, 0xc3],
        regs: &[(reg::RBX, 0x0)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x10)],
        mask: CF | ZF,
        flags_out: CF,
        memory_out: None,
    },
    // popcnt rax, rbx (definition)
    Case {
        name: "popcnt",
        code: &[0xf3, 0x48, 0x0f, 0xb8, 0xc3],
        regs: &[(reg::RBX, 0xff0f)],
        flags: CF | PF | AF | ZF | SF | OF,
        memory: None,
        check: &[(reg::RAX, 0xc)],
        mask: CF | PF | AF | ZF | SF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // popcnt eax, ebx (definition)
    Case {
        name: "popcnt_zero",
        code: &[0xf3, 0x0f, 0xb8, 0xc3],
        regs: &[(reg::RBX, 0x0)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | PF | AF | ZF | SF | OF,
        flags_out: ZF,
        memory_out: None,
    },
    // adcx rax, rbx (definition)
    Case {
        name: "adcx",
        code: &[0x66, 0x48, 0x0f, 0x38, 0xf6, 0xc3],
        regs: &[(reg::RAX, 0xffffffffffffffff), (reg::RBX, 0x1)],
        flags: OF,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // adox rax, rbx (definition)
    Case {
        name: "adox",
        code: &[0xf3, 0x48, 0x0f, 0x38, 0xf6, 0xc3],
        regs: &[(reg::RAX, 0xffffffffffffffff), (reg::RBX, 0x0)],
        flags: CF | OF,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | OF,
        flags_out: CF | OF,
        memory_out: None,
    },
    // adcx eax, ebx (definition)
    Case {
        name: "adcx_32",
        code: &[0x66, 0x0f, 0x38, 0xf6, 0xc3],
        regs: &[(reg::RAX, 0xffffffff), (reg::RBX, 0x1)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x0)],
        mask: CF | OF,
        flags_out: CF,
        memory_out: None,
    },
    // andn rax, rbx, rcx (definition)
    Case {
        name: "andn",
        code: &[0xc4, 0xe2, 0xe0, 0xf2, 0xc1],
        regs: &[(reg::RBX, 0xff00), (reg::RCX, 0xffff)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xff)],
        mask: CF | ZF | SF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // bzhi rax, rbx, rcx (definition)
    Case {
        name: "bzhi",
        code: &[0xc4, 0xe2, 0xf0, 0xf5, 0xc3],
        regs: &[(reg::RBX, 0xffffffffffffffff), (reg::RCX, 0x8)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xff)],
        mask: CF | ZF | SF | OF,
        flags_out: 0,
        memory_out: None,
    },
    // bzhi rax, rbx, rcx (definition)
    Case {
        name: "bzhi_past",
        code: &[0xc4, 0xe2, 0xf0, 0xf5, 0xc3],
        regs: &[(reg::RBX, 0xffffffffffffffff), (reg::RCX, 0x46)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffffffffffffffff)],
        mask: CF | ZF | SF | OF,
        flags_out: CF | SF,
        memory_out: None,
    },
    // pext rax, rbx, rcx (definition)
    Case {
        name: "pext",
        code: &[0xc4, 0xe2, 0xe2, 0xf5, 0xc1],
        regs: &[(reg::RBX, 0xa), (reg::RCX, 0xa)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x3)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // pext eax, ebx, ecx (definition)
    Case {
        name: "pext_32",
        code: &[0xc4, 0xe2, 0x62, 0xf5, 0xc1],
        regs: &[(reg::RBX, 0xf0f0f0f0), (reg::RCX, 0xff00ff00)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xf0f0)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // rorx rax, rbx, 4 (definition)
    Case {
        name: "rorx",
        code: &[0xc4, 0xe3, 0xfb, 0xf0, 0xc3, 0x04],
        regs: &[(reg::RBX, 0x1f)],
        flags: CF | PF | AF | ZF | SF | OF,
        memory: None,
        check: &[(reg::RAX, 0xf000000000000001)],
        mask: CF | PF | AF | ZF | SF | OF,
        flags_out: CF | PF | AF | ZF | SF | OF,
        memory_out: None,
    },
    // shlx rax, rbx, rcx (definition)
    Case {
        name: "shlx",
        code: &[0xc4, 0xe2, 0xf1, 0xf7, 0xc3],
        regs: &[(reg::RBX, 0x1), (reg::RCX, 0x3f)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x8000000000000000)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // shrx eax, ebx, ecx (definition)
    Case {
        name: "shrx_32",
        code: &[0xc4, 0xe2, 0x73, 0xf7, 0xc3],
        regs: &[(reg::RBX, 0x80000000), (reg::RCX, 0x3f)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // mulx rax, rbx, rcx (definition)
    Case {
        name: "mulx",
        code: &[0xc4, 0xe2, 0xe3, 0xf6, 0xc1],
        regs: &[(reg::RDX, 0x8000000000000000), (reg::RCX, 0x4)],
        flags: CF | PF | AF | ZF | SF | OF,
        memory: None,
        check: &[(reg::RAX, 0x2), (reg::RBX, 0x0)],
        mask: CF | PF | AF | ZF | SF | OF,
        flags_out: CF | PF | AF | ZF | SF | OF,
        memory_out: None,
    },
    // mulx eax, ebx, ecx (definition)
    Case {
        name: "mulx_32",
        code: &[0xc4, 0xe2, 0x63, 0xf6, 0xc1],
        regs: &[(reg::RDX, 0xffffffff), (reg::RCX, 0xffffffff)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xfffffffe), (reg::RBX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // movbe rax, [rcx] (definition)
    Case {
        name: "movbe_load",
        code: &[0x48, 0x0f, 0x38, 0xf0, 0x01],
        regs: &[],
        flags: 0,
        memory: Some((
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            reg::RCX,
        )),
        check: &[(reg::RAX, 0x102030405060708)],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]),
    },
    // movbe [rcx+4], ebx (definition)
    Case {
        name: "movbe_store",
        code: &[0x0f, 0x38, 0xf1, 0x59, 0x04],
        regs: &[(reg::RBX, 0xa0b0c0d)],
        flags: 0,
        memory: Some((
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            reg::RCX,
        )),
        check: &[],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]),
    },
    // movbe ax, [rcx+2] (definition)
    Case {
        name: "movbe_16",
        code: &[0x66, 0x0f, 0x38, 0xf0, 0x41, 0x02],
        regs: &[(reg::RAX, 0xffffffffffffffff)],
        flags: 0,
        memory: Some((
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            reg::RCX,
        )),
        check: &[(reg::RAX, 0xffffffffffff0203)],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
    },
    // bswap rax (rosetta)
    Case {
        name: "bswap",
        code: &[0x48, 0x0f, 0xc8],
        regs: &[(reg::RAX, 0x102030405060708)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x807060504030201)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // bswap ebx (rosetta)
    Case {
        name: "bswap_32",
        code: &[0x0f, 0xcb],
        regs: &[(reg::RBX, 0xffffffff01020304)],
        flags: 0,
        memory: None,
        check: &[(reg::RBX, 0x4030201)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // xlatb (rosetta)
    Case {
        name: "xlat",
        code: &[0xd7],
        regs: &[(reg::RAX, 0xff03)],
        flags: 0,
        memory: Some((
            [
                0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            reg::RBX,
        )),
        check: &[(reg::RAX, 0xff77)],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]),
    },
    // cbw (rosetta)
    Case {
        name: "cbw",
        code: &[0x66, 0x98],
        regs: &[(reg::RAX, 0x80)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xff80)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cwde (rosetta)
    Case {
        name: "cwde",
        code: &[0x98],
        regs: &[(reg::RAX, 0xffffffff00008000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffff8000)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cdqe (rosetta)
    Case {
        name: "cdqe",
        code: &[0x48, 0x98],
        regs: &[(reg::RAX, 0x80000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffffffff80000000)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cwd (rosetta)
    Case {
        name: "cwd",
        code: &[0x66, 0x99],
        regs: &[(reg::RAX, 0x8000), (reg::RDX, 0x12345678)],
        flags: 0,
        memory: None,
        check: &[(reg::RDX, 0x1234ffff)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cdq (rosetta)
    Case {
        name: "cdq",
        code: &[0x99],
        regs: &[(reg::RAX, 0x80000000), (reg::RDX, 0x1234567800000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RDX, 0xffffffff)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cqo (rosetta)
    Case {
        name: "cqo",
        code: &[0x48, 0x99],
        regs: &[(reg::RAX, 0x8000000000000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RDX, 0xffffffffffffffff)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // clc (rosetta)
    Case {
        name: "clc",
        code: &[0xf8],
        regs: &[],
        flags: CF,
        memory: None,
        check: &[],
        mask: CF,
        flags_out: 0,
        memory_out: None,
    },
    // stc (rosetta)
    Case {
        name: "stc",
        code: &[0xf9],
        regs: &[],
        flags: 0,
        memory: None,
        check: &[],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // cmc (rosetta)
    Case {
        name: "cmc",
        code: &[0xf5],
        regs: &[],
        flags: CF,
        memory: None,
        check: &[],
        mask: CF,
        flags_out: 0,
        memory_out: None,
    },
    // lahf (rosetta)
    Case {
        name: "lahf",
        code: &[0x9f],
        regs: &[(reg::RAX, 0x0)],
        flags: CF | PF | ZF | SF,
        memory: None,
        check: &[(reg::RAX, 0xc700)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // sahf (rosetta)
    Case {
        name: "sahf",
        code: &[0x9e],
        regs: &[(reg::RAX, 0x4100)],
        flags: 0,
        memory: None,
        check: &[],
        mask: CF | PF | AF | ZF | SF,
        flags_out: CF | ZF,
        memory_out: None,
    },
    // sete bl (rosetta)
    Case {
        name: "sete",
        code: &[0x0f, 0x94, 0xc3],
        regs: &[(reg::RBX, 0xff00)],
        flags: ZF,
        memory: None,
        check: &[(reg::RBX, 0xff01)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // setl cl (rosetta)
    Case {
        name: "setl",
        code: &[0x0f, 0x9c, 0xc1],
        regs: &[(reg::RCX, 0x0)],
        flags: SF,
        memory: None,
        check: &[(reg::RCX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // setbe byte ptr [rcx] (rosetta)
    Case {
        name: "setbe_memory",
        code: &[0x0f, 0x96, 0x01],
        regs: &[],
        flags: CF,
        memory: Some((
            [
                0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                0x09, 0x09,
            ],
            reg::RCX,
        )),
        check: &[],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x01, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09,
        ]),
    },
    // cmovne rax, rbx (rosetta)
    Case {
        name: "cmovne_taken",
        code: &[0x48, 0x0f, 0x45, 0xc3],
        regs: &[(reg::RAX, 0x1), (reg::RBX, 0x2)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x2)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cmovne eax, ebx (rosetta)
    Case {
        name: "cmovne_not_taken_32",
        code: &[0x0f, 0x45, 0xc3],
        regs: &[(reg::RAX, 0xffffffff00000001), (reg::RBX, 0x2)],
        flags: ZF,
        memory: None,
        check: &[(reg::RAX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // cmovg ax, bx (rosetta)
    Case {
        name: "cmovg_16",
        code: &[0x66, 0x0f, 0x4f, 0xc3],
        regs: &[(reg::RAX, 0x11111111), (reg::RBX, 0x2222)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x11112222)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // xchg rax, rbx (rosetta)
    Case {
        name: "xchg",
        code: &[0x48, 0x93],
        regs: &[(reg::RAX, 0x1), (reg::RBX, 0x2)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x2), (reg::RBX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // xchg eax, ebx (rosetta)
    Case {
        name: "xchg_32",
        code: &[0x93],
        regs: &[(reg::RAX, 0xffffffff00000001), (reg::RBX, 0x2)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x2), (reg::RBX, 0x1)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // xchg [rcx+8], rbx (rosetta)
    Case {
        name: "xchg_memory",
        code: &[0x48, 0x87, 0x59, 0x08],
        regs: &[(reg::RBX, 0x1122)],
        flags: 0,
        memory: Some((
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            reg::RCX,
        )),
        check: &[(reg::RBX, 0xf0e0d0c0b0a0908)],
        mask: 0,
        flags_out: 0,
        memory_out: Some([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]),
    },
    // xchg bl, bh (rosetta)
    Case {
        name: "xchg_byte",
        code: &[0x86, 0xdf],
        regs: &[(reg::RBX, 0x1234)],
        flags: 0,
        memory: None,
        check: &[(reg::RBX, 0x3412)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // movsx rax, bl (rosetta)
    Case {
        name: "movsx",
        code: &[0x48, 0x0f, 0xbe, 0xc3],
        regs: &[(reg::RBX, 0x80)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffffffffffffff80)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // movsx eax, bx (rosetta)
    Case {
        name: "movsx_16",
        code: &[0x0f, 0xbf, 0xc3],
        regs: &[(reg::RAX, 0xffffffffffffffff), (reg::RBX, 0x8000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffff8000)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // movzx eax, bh (rosetta)
    Case {
        name: "movzx",
        code: &[0x0f, 0xb6, 0xc7],
        regs: &[(reg::RAX, 0xffffffffffffffff), (reg::RBX, 0xab00)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xab)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // movsxd rax, ebx (rosetta)
    Case {
        name: "movsxd",
        code: &[0x48, 0x63, 0xc3],
        regs: &[(reg::RBX, 0x80000000)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0xffffffff80000000)],
        mask: 0,
        flags_out: 0,
        memory_out: None,
    },
    // bt rax, 3 (rosetta)
    Case {
        name: "bt",
        code: &[0x48, 0x0f, 0xba, 0xe0, 0x03],
        regs: &[(reg::RAX, 0x8)],
        flags: 0,
        memory: None,
        check: &[],
        mask: CF,
        flags_out: CF,
        memory_out: None,
    },
    // bts rax, rbx (rosetta)
    Case {
        name: "bts",
        code: &[0x48, 0x0f, 0xab, 0xd8],
        regs: &[(reg::RAX, 0x0), (reg::RBX, 0x41)],
        flags: 0,
        memory: None,
        check: &[(reg::RAX, 0x2)],
        mask: CF,
        flags_out: 0,
        memory_out: None,
    },
    // btr dword ptr [rcx], 4 (rosetta)
    Case {
        name: "btr_memory",
        code: &[0x0f, 0xba, 0x31, 0x04],
        regs: &[],
        flags: 0,
        memory: Some((
            [
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            reg::RCX,
        )),
        check: &[],
        mask: CF,
        flags_out: CF,
        memory_out: Some([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]),
    },
    // btc ebx, 31 (rosetta)
    Case {
        name: "btc",
        code: &[0x0f, 0xba, 0xfb, 0x1f],
        regs: &[(reg::RBX, 0x0)],
        flags: 0,
        memory: None,
        check: &[(reg::RBX, 0x80000000)],
        mask: CF,
        flags_out: 0,
        memory_out: None,
    },
];

#[test]
fn integer_instructions_give_their_defined_results() {
    let mut failures = Vec::new();
    for case in CASES {
        let (mut s, m) = fixture(case.code);
        for &(r, v) in case.regs {
            s.gpr[r] = v;
        }
        s.rflags = case.flags | 2;
        if let Some((bytes, base)) = case.memory {
            m.write(GuestAddr(DATA), &bytes).unwrap();
            s.gpr[base] = DATA;
        }
        if let Err(stop) = step(&mut s, &m) {
            failures.push(format!("{}: stopped with {stop:?}", case.name));
            continue;
        }
        if s.rip != GuestAddr(CODE + case.code.len() as u64) {
            failures.push(format!("{}: rip {:#x}", case.name, s.rip.0));
        }
        for &(r, want) in case.check {
            if s.gpr[r] != want {
                failures.push(format!(
                    "{}: reg {r} {:#x}, want {want:#x}",
                    case.name, s.gpr[r]
                ));
            }
        }
        if s.rflags & case.mask != case.flags_out {
            failures.push(format!(
                "{}: flags {:#x}, want {:#x}",
                case.name,
                s.rflags & case.mask,
                case.flags_out
            ));
        }
        if let Some(want) = case.memory_out {
            let mut got = [0; 16];
            m.read(GuestAddr(DATA), &mut got).unwrap();
            if got != want {
                failures.push(format!("{}: memory {got:02x?}", case.name));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Instructions that use the stack or branch, with values from the Intel SDM's
// pseudo-code for each.
fn read_u64(m: &AddressSpace, at: u64) -> u64 {
    m.read_u64(GuestAddr(at)).unwrap()
}
#[test]
fn enter_builds_a_frame_and_leave_undoes_it() {
    // enter 16, 0; leave
    let (mut s, m) = fixture(&[0xc8, 0x10, 0x00, 0x00, 0xc9]);
    s.gpr[reg::RBP] = 0x1234;
    step(&mut s, &m).unwrap();
    assert_eq!(read_u64(&m, DATA + 0xff8), 0x1234);
    assert_eq!(s.gpr[reg::RBP], DATA + 0xff8);
    assert_eq!(s.gpr[reg::RSP], DATA + 0xfe8);
    step(&mut s, &m).unwrap();
    assert_eq!(s.gpr[reg::RBP], 0x1234);
    assert_eq!(s.gpr[reg::RSP], DATA + 0x1000);
}
#[test]
fn enter_copies_the_frame_pointers_of_its_nesting_level() {
    // enter 8, 1: the new frame pointer is pushed as well.
    let (mut s, m) = fixture(&[0xc8, 0x08, 0x00, 0x01]);
    s.gpr[reg::RBP] = 0x1234;
    step(&mut s, &m).unwrap();
    assert_eq!(read_u64(&m, DATA + 0xff8), 0x1234);
    assert_eq!(read_u64(&m, DATA + 0xff0), DATA + 0xff8);
    assert_eq!(s.gpr[reg::RBP], DATA + 0xff8);
    assert_eq!(s.gpr[reg::RSP], DATA + 0xfe8);
    // enter 8, 2: the outer frame's pointer is copied from [rbp - 8].
    let (mut s, m) = fixture(&[0xc8, 0x08, 0x00, 0x02]);
    s.gpr[reg::RBP] = DATA + 0x800;
    m.write_u64(GuestAddr(DATA + 0x7f8), 0xaaaa).unwrap();
    step(&mut s, &m).unwrap();
    assert_eq!(read_u64(&m, DATA + 0xff8), DATA + 0x800);
    assert_eq!(read_u64(&m, DATA + 0xff0), 0xaaaa);
    assert_eq!(read_u64(&m, DATA + 0xfe8), DATA + 0xff8);
    assert_eq!(s.gpr[reg::RBP], DATA + 0xff8);
    assert_eq!(s.gpr[reg::RSP], DATA + 0xfe0);
}
#[test]
fn pushf_and_popf_move_the_flags_through_the_stack() {
    const ARITH: u64 = CF | PF | AF | ZF | SF | OF;
    const DF: u64 = 0x400;
    // pushfq; popfq
    let (mut s, m) = fixture(&[0x9c, 0x9d]);
    s.rflags |= ARITH;
    step(&mut s, &m).unwrap();
    assert_eq!(s.gpr[reg::RSP], DATA + 0xff8);
    assert_eq!(read_u64(&m, DATA + 0xff8) & ARITH, ARITH);
    m.write_u64(GuestAddr(DATA + 0xff8), CF | OF | DF).unwrap();
    step(&mut s, &m).unwrap();
    assert_eq!(s.gpr[reg::RSP], DATA + 0x1000);
    assert_eq!(s.rflags & (ARITH | DF), CF | OF | DF);
    assert_eq!(s.rflags & 2, 2);
}
#[test]
fn ret_with_an_immediate_also_releases_the_arguments() {
    // ret 16
    let (mut s, m) = fixture(&[0xc2, 0x10, 0x00]);
    s.gpr[reg::RSP] = DATA + 0xf00;
    m.write_u64(GuestAddr(DATA + 0xf00), CODE + 0x10).unwrap();
    step(&mut s, &m).unwrap();
    assert_eq!(s.rip, GuestAddr(CODE + 0x10));
    assert_eq!(s.gpr[reg::RSP], DATA + 0xf18);
}
#[test]
fn jrcxz_and_jecxz_test_the_count_register_of_their_size() {
    for (rcx, taken) in [(0, true), (1, false)] {
        // jrcxz +2
        let (mut s, m) = fixture(&[0xe3, 0x02]);
        s.gpr[reg::RCX] = rcx;
        step(&mut s, &m).unwrap();
        assert_eq!(s.rip, GuestAddr(CODE + if taken { 4 } else { 2 }));
    }
    // jecxz +2 looks at ECX only.
    let (mut s, m) = fixture(&[0x67, 0xe3, 0x02]);
    s.gpr[reg::RCX] = 1 << 32;
    step(&mut s, &m).unwrap();
    assert_eq!(s.rip, GuestAddr(CODE + 5));
}
#[test]
fn loop_counts_down_and_its_forms_test_zf() {
    // (opcode, rcx, ZF, taken): loop, loop at 1, loope with ZF clear,
    // loopne with ZF clear.
    for (opcode, rcx, zf, taken) in [
        (0xe2, 2, false, true),
        (0xe2, 1, false, false),
        (0xe1, 5, false, false),
        (0xe0, 5, false, true),
        (0xe1, 5, true, true),
    ] {
        let (mut s, m) = fixture(&[opcode, 0x02]);
        s.gpr[reg::RCX] = rcx;
        if zf {
            s.rflags |= ZF;
        }
        step(&mut s, &m).unwrap();
        assert_eq!(s.gpr[reg::RCX], rcx - 1, "{opcode:#x}");
        assert_eq!(
            s.rip,
            GuestAddr(CODE + if taken { 4 } else { 2 }),
            "{opcode:#x}"
        );
    }
}
