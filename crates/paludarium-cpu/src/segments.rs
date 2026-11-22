//! Segment registers in 64-bit mode at privilege level 3: what loading a
//! selector into one checks, which descriptor it reads from the global or
//! the local descriptor table, and the fs and gs bases it takes, as the
//! Intel SDM's `MOV`, `POP` and `IRET` describe and Linux's tables hold.
//!
//! Only the fs and gs bases take part in addressing in 64-bit mode; the
//! selectors of the others are kept for `mov` from them, ptrace and the
//! signal frame.

/// `sreg` numbers, as the `reg` field of `mov` to and from a segment
/// register encodes them, and indices of [`crate::CpuState::segments`].
pub const ES: usize = 0;
pub const CS: usize = 1;
pub const SS: usize = 2;
pub const DS: usize = 3;
pub const FS: usize = 4;
pub const GS: usize = 5;

/// `__USER_CS`, the 64-bit code segment a task runs in.
pub const USER_CS: u16 = 0x33;
/// `__USER_DS`, the stack segment a task starts with and a system call
/// returns with.
pub const USER_DS: u16 = 0x2b;

/// The selectors a 64-bit task starts with (`start_thread_common`).
pub const INITIAL: [u16; 6] = [0, USER_CS, USER_DS, 0, 0, 0];

/// A load the CPU refuses, with its error code: the selector without its
/// RPL bits (index and table indicator), or 0 for a null SS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentFault {
    /// #GP (vector 13), which Linux gives as SIGSEGV.
    GeneralProtection(u16),
    /// #NP (vector 11): a segment not present, SIGBUS.
    NotPresent(u16),
    /// #SS (vector 12): a stack segment not present, SIGBUS.
    StackSegment(u16),
}

impl SegmentFault {
    /// The exception's vector, which Linux puts in `sigcontext.trapno`.
    #[must_use]
    pub const fn trap(self) -> u8 {
        match self {
            SegmentFault::GeneralProtection(_) => 13,
            SegmentFault::NotPresent(_) => 11,
            SegmentFault::StackSegment(_) => 12,
        }
    }

    /// The error code, which Linux puts in `sigcontext.err`.
    #[must_use]
    pub const fn error(self) -> u16 {
        match self {
            SegmentFault::GeneralProtection(e)
            | SegmentFault::NotPresent(e)
            | SegmentFault::StackSegment(e) => e,
        }
    }
}

/// Entries of Linux's 64-bit GDT (`GDT_ENTRIES`).
const GDT_ENTRIES: usize = 16;

/// Linux's 64-bit GDT (`gdt_page` in `arch/x86/kernel/cpu/common.c`), as a
/// task sees it: the kernel's code and data segments (privilege 0), the
/// user's 32-bit code, data and 64-bit code segments (`__USER32_CS` 0x23,
/// `__USER_DS` 0x2b, `__USER_CS` 0x33), the TSS and LDT system descriptors,
/// three thread-local entries that stay empty (`set_thread_area` is not
/// implemented), and the read-only, expand-down `GDT_ENTRY_CPUNODE` 0x7b of
/// `setup_getcpu` (its limit, the CPU and node, is left 0).
const GDT: [u64; GDT_ENTRIES] = [
    0,
    0x00cf_9b00_0000_ffff, // __KERNEL32_CS
    0x00af_9b00_0000_ffff, // __KERNEL_CS
    0x00cf_9300_0000_ffff, // __KERNEL_DS
    0x00cf_fb00_0000_ffff, // __USER32_CS
    0x00cf_f300_0000_ffff, // __USER_DS
    0x00af_fb00_0000_ffff, // __USER_CS
    0,
    0x0000_8b00_0000_0067, // the TSS, a system descriptor of two entries
    0,
    0x0000_8200_0000_0000, // the LDT, a system descriptor of two entries
    0,
    0, // GDT_ENTRY_TLS_MIN ..
    0,
    0,                     // .. GDT_ENTRY_TLS_MAX
    0x0040_f500_0000_0000, // GDT_ENTRY_CPUNODE
];

/// The descriptor `selector` names in the GDT or in `ldt` (the table
/// indicator bit), if its index is within the table's limit. An address
/// space without an LDT has a limit that no selector is within.
fn descriptor(selector: u16, ldt: &[u64]) -> Option<u64> {
    let index = usize::from(selector >> 3);
    if selector & 4 != 0 {
        ldt.get(index).copied()
    } else {
        GDT.get(index).copied()
    }
}

/// The parts of a descriptor the loads look at.
struct Descriptor {
    /// The type field: accessed, writable or readable, expand-down or
    /// conforming, code.
    kind: u8,
    /// A code or data segment rather than a system descriptor.
    user: bool,
    privilege: u8,
    present: bool,
    base: u32,
    /// The L bit: 64-bit code.
    long: bool,
    /// The D bit: 32-bit code or data.
    default_big: bool,
}

impl Descriptor {
    const fn of(d: u64) -> Self {
        Descriptor {
            kind: (d >> 40 & 0xf) as u8,
            user: d >> 44 & 1 != 0,
            privilege: (d >> 45 & 3) as u8,
            present: d >> 47 & 1 != 0,
            base: ((d >> 16 & 0xff_ffff) | (d >> 56 & 0xff) << 24) as u32,
            long: d >> 53 & 1 != 0,
            default_big: d >> 54 & 1 != 0,
        }
    }
    const fn code(&self) -> bool {
        self.kind & 8 != 0
    }
    /// Writable for data, readable for code.
    const fn writable_or_readable(&self) -> bool {
        self.kind & 2 != 0
    }
    const fn conforming(&self) -> bool {
        self.kind & 4 != 0
    }
}

/// The current privilege level of the code the CPU runs.
const CPL: u8 = 3;

/// Whether `selector` names no descriptor: index 0 of the GDT, whatever
/// its RPL.
const fn is_null(selector: u16) -> bool {
    selector & !3 == 0
}

/// What loading `selector` into SS checks, as `MOV` and `POP` to SS and the
/// return to user space (`IRET`) do: not null (`#GP(0)`), within its table,
/// of RPL 3, a writable data segment of privilege 3 (`#GP(selector)`), and
/// present (`#SS(selector)`).
///
/// # Errors
/// The fault the load raises.
pub fn check_stack(selector: u16, ldt: &[u64]) -> Result<(), SegmentFault> {
    if is_null(selector) {
        return Err(SegmentFault::GeneralProtection(0));
    }
    let error = selector & !3;
    let fault = SegmentFault::GeneralProtection(error);
    let d = Descriptor::of(descriptor(selector, ldt).ok_or(fault)?);
    if (selector & 3) as u8 != CPL
        || !d.user
        || d.code()
        || !d.writable_or_readable()
        || d.privilege != CPL
    {
        return Err(fault);
    }
    if !d.present {
        return Err(SegmentFault::StackSegment(error));
    }
    Ok(())
}

/// What loading `selector` into DS, ES, FS or GS checks: a null selector
/// loads as it is; any other must be within its table, a data segment or
/// a readable code segment, of a privilege no higher than the RPL and the
/// CPL unless it is conforming code (`#GP(selector)`), and present
/// (`#NP(selector)`). Gives the segment's base, 0 for null.
///
/// # Errors
/// The fault the load raises.
pub fn check_data(selector: u16, ldt: &[u64]) -> Result<u32, SegmentFault> {
    if is_null(selector) {
        return Ok(0);
    }
    let error = selector & !3;
    let fault = SegmentFault::GeneralProtection(error);
    let d = Descriptor::of(descriptor(selector, ldt).ok_or(fault)?);
    let rpl = (selector & 3) as u8;
    if !d.user
        || d.code() && !d.writable_or_readable()
        || !(d.code() && d.conforming()) && (rpl > d.privilege || CPL > d.privilege)
    {
        return Err(fault);
    }
    if !d.present {
        return Err(SegmentFault::NotPresent(error));
    }
    Ok(d.base)
}

/// The mode the code segment of a far transfer runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeMode {
    /// 64-bit code (the L bit), as `__USER_CS`.
    Long,
    /// 32-bit or 16-bit compatibility mode, as `__USER32_CS`.
    Compatibility,
}

/// What a far `jmp` or `call` (`returning` false) or a far `ret` (true) at
/// privilege 3 checks of the code segment it loads into CS, as the Intel
/// SDM gives them: not null (`#GP(0)`); within its table, a code segment
/// rather than data or a system descriptor (Linux's tables hold no call
/// gates), conforming of a privilege no higher than the CPL (for `ret`,
/// the RPL), or else non-conforming of exactly that privilege, and not both
/// L and D (`#GP(selector)`); a `ret` also needs an RPL no lower than the
/// CPL, and a higher one, a return to an outer level, is none at CPL 3.
/// Then present (`#NP(selector)`). Gives the mode it runs in.
///
/// # Errors
/// The fault the transfer raises.
pub fn check_code(selector: u16, ldt: &[u64], returning: bool) -> Result<CodeMode, SegmentFault> {
    if is_null(selector) {
        return Err(SegmentFault::GeneralProtection(0));
    }
    let error = selector & !3;
    let fault = SegmentFault::GeneralProtection(error);
    let d = Descriptor::of(descriptor(selector, ldt).ok_or(fault)?);
    let rpl = (selector & 3) as u8;
    let level = if returning { rpl } else { CPL };
    let privilege_ok = if d.conforming() {
        d.privilege <= level
    } else {
        d.privilege == level
    };
    if !d.user || !d.code() || !privilege_ok || d.long && d.default_big || returning && rpl < CPL {
        return Err(fault);
    }
    if !d.present {
        return Err(SegmentFault::NotPresent(error));
    }
    Ok(if d.long {
        CodeMode::Long
    } else {
        CodeMode::Compatibility
    })
}

/// Loads `selector` into segment register `sreg` (not CS) of `state`, as
/// `mov` and `pop` do, with the descriptor checks above, taking the 32-bit
/// base of a descriptor into fs or gs. A null selector clears the base, as
/// Intel's CPUs and AMD's since Zen 2 do (Linux's `X86_BUG_NULL_SEG` is the
/// older AMD ones, which keep it). Nothing changes if the load faults.
///
/// # Errors
/// The fault the load raises.
pub fn load(
    state: &mut crate::CpuState,
    sreg: usize,
    selector: u16,
    ldt: &[u64],
) -> Result<(), SegmentFault> {
    if sreg == SS {
        check_stack(selector, ldt)?;
    } else {
        let base = u64::from(check_data(selector, ldt)?);
        match sreg {
            FS => state.fs_base = base,
            GS => state.gs_base = base,
            _ => {}
        }
    }
    state.segments[sreg] = selector;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CpuState;

    /// A `fill_ldt` descriptor of privilege 3 with `kind`, base `base`,
    /// present or not.
    fn ldt_entry(kind: u64, base: u32, present: bool) -> u64 {
        let base = u64::from(base);
        0xffff
            | (base & 0xff_ffff) << 16
            | kind << 40
            | 1 << 44
            | 3 << 45
            | u64::from(present) << 47
            | 0xf << 48
            | 1 << 54
            | 1 << 55
            | (base >> 24) << 56
    }

    #[test]
    fn a_task_starts_with_linux_selectors() {
        assert_eq!(CpuState::default().segments, [0, 0x33, 0x2b, 0, 0, 0]);
    }

    #[test]
    fn user_gdt_segments_load_and_kernel_ones_fault() {
        let mut s = CpuState::default();
        for (sreg, selector) in [(DS, 0x2b), (ES, 0x33), (FS, 0x23), (GS, 0x7b), (SS, 0x2b)] {
            assert_eq!(load(&mut s, sreg, selector, &[]), Ok(()));
            assert_eq!(s.segments[sreg], selector);
        }
        // An RPL below the descriptor's privilege may load data, not SS.
        assert_eq!(load(&mut s, DS, 0x28, &[]), Ok(()));
        assert_eq!(s.segments[DS], 0x28);
        assert_eq!(
            load(&mut s, SS, 0x28, &[]),
            Err(SegmentFault::GeneralProtection(0x28))
        );
        for selector in [0x10, 0x18, 0x13, 0x40, 0x50, 0x63, 0x80, 0xfffb] {
            assert_eq!(
                load(&mut s, DS, selector, &[]),
                Err(SegmentFault::GeneralProtection(selector & !3)),
                "{selector:#x}"
            );
        }
        // Code and the read-only CPUNODE segment are no stack.
        for selector in [0x33, 0x23, 0x7b] {
            assert_eq!(
                load(&mut s, SS, selector, &[]),
                Err(SegmentFault::GeneralProtection(selector & !3))
            );
        }
        assert_eq!(
            load(&mut s, SS, 3, &[]),
            Err(SegmentFault::GeneralProtection(0))
        );
        assert_eq!(s.segments[SS], 0x2b);
    }

    #[test]
    fn far_transfers_check_the_code_segment() {
        let ldt = [
            (ldt_entry(0xb, 0, true) | 1 << 53) & !(1 << 54), // 64-bit code
            ldt_entry(0xb, 0, false),                         // not present
            ldt_entry(3, 0, true),                            // data
            ldt_entry(0xf, 0, true) & !(3 << 45),             // conforming, privilege 0
            ldt_entry(0xb, 0, true) | 1 << 53,                // both L and D
        ];
        assert_eq!(check_code(0x33, &[], false), Ok(CodeMode::Long));
        // A jump sets the RPL to the CPL; a return needs it.
        assert_eq!(check_code(0x30, &[], false), Ok(CodeMode::Long));
        assert_eq!(
            check_code(0x30, &[], true),
            Err(SegmentFault::GeneralProtection(0x30))
        );
        assert_eq!(check_code(0x23, &[], true), Ok(CodeMode::Compatibility));
        assert_eq!(check_code(0x7, &ldt, false), Ok(CodeMode::Long));
        assert_eq!(check_code(0x1f, &ldt, false), Ok(CodeMode::Compatibility));
        assert_eq!(
            check_code(0xf, &ldt, false),
            Err(SegmentFault::NotPresent(0xc))
        );
        for (selector, error) in [
            (0, 0),
            (3, 0),
            (0x10, 0x10),
            (0x2b, 0x28),
            (0x40, 0x40),
            (0x83, 0x80),
        ] {
            assert_eq!(
                check_code(selector, &[], false),
                Err(SegmentFault::GeneralProtection(error)),
                "{selector:#x}"
            );
        }
        for selector in [0x17, 0x27] {
            assert_eq!(
                check_code(selector, &ldt, false),
                Err(SegmentFault::GeneralProtection(selector & !3))
            );
        }
    }

    #[test]
    fn ldt_segments_give_fs_and_gs_their_base() {
        let ldt = [
            ldt_entry(3, 0x1234_5678, true), // read/write data
            ldt_entry(1, 0x4000, true),      // read-only data
            ldt_entry(3, 0x5000, false),     // not present
            ldt_entry(9, 0x6000, true),      // execute-only code
            ldt_entry(0xb, 0x7000, true),    // readable code
        ];
        let mut s = CpuState::default();
        assert_eq!(load(&mut s, FS, 0x7, &ldt), Ok(()));
        assert_eq!((s.segments[FS], s.fs_base), (7, 0x1234_5678));
        assert_eq!(load(&mut s, GS, 0xc, &ldt), Ok(()));
        assert_eq!((s.segments[GS], s.gs_base), (0xc, 0x4000));
        assert_eq!(load(&mut s, GS, 0x27, &ldt), Ok(()));
        assert_eq!(s.gs_base, 0x7000);
        assert_eq!(
            load(&mut s, GS, 0x17, &ldt),
            Err(SegmentFault::NotPresent(0x14))
        );
        assert_eq!(
            load(&mut s, SS, 0x17, &ldt),
            Err(SegmentFault::StackSegment(0x14))
        );
        assert_eq!(
            load(&mut s, GS, 0x1f, &ldt),
            Err(SegmentFault::GeneralProtection(0x1c))
        );
        assert_eq!(
            load(&mut s, SS, 0xf, &ldt),
            Err(SegmentFault::GeneralProtection(0xc))
        );
        assert_eq!(load(&mut s, SS, 0x7, &ldt), Ok(()));
        // Past the table, or with no table at all.
        assert_eq!(
            load(&mut s, FS, 0x2f, &ldt),
            Err(SegmentFault::GeneralProtection(0x2c))
        );
        assert_eq!(
            load(&mut s, FS, 0x7, &[]),
            Err(SegmentFault::GeneralProtection(0x4))
        );
        // An empty entry is a system descriptor of type 0.
        assert_eq!(
            load(&mut s, FS, 0x7, &[0]),
            Err(SegmentFault::GeneralProtection(0x4))
        );
        assert_eq!((s.segments[GS], s.gs_base), (0x27, 0x7000));
        // A null selector keeps its RPL and clears the base.
        assert_eq!(load(&mut s, GS, 2, &ldt), Ok(()));
        assert_eq!((s.segments[GS], s.gs_base), (2, 0));
    }

    #[test]
    fn faults_give_linux_vectors() {
        assert_eq!(SegmentFault::GeneralProtection(4).trap(), 13);
        assert_eq!(SegmentFault::NotPresent(4).trap(), 11);
        assert_eq!(SegmentFault::StackSegment(4).trap(), 12);
        assert_eq!(SegmentFault::StackSegment(0x1c).error(), 0x1c);
    }
}
