//! Hardware breakpoints, as the debug registers DR0–DR3 and DR7 set them.
//!
//! While any is enabled, [`run_watched`] runs the guest one instruction at
//! a time: an execute breakpoint faults before the instruction at its
//! address (`rip` stays, and RF lets that instruction run once it goes on),
//! and a data breakpoint traps after an instruction that accesses its
//! range, as the CPU raises #DB. An access is what the instruction's
//! explicit memory operands touch (the state `fxsave`, `fnsave` and
//! `fnstenv` write and their restores read, the bytes `maskmovdqu`'s mask
//! selects), its stack accesses (push, pop, call, return, `enter`,
//! `leave`), and a string instruction's element without a repeat; a write
//! breakpoint takes only what an instruction writes. A repeated string
//! instruction, which the CPU stops after the iteration that touched the
//! range, is not looked at yet.
use crate::{CpuState, DecodeCache, flag, reg, step_cached};
use paludarium_decoder::{
    Instruction, MemoryOperand, Mnemonic, Operand, Register, RepPrefix, Segment,
};
use paludarium_mmu::AddressSpace;
use paludarium_types::ExitReason;

/// What a breakpoint breaks on (DR7's R/W field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakOn {
    /// The instruction at the address is about to run (R/W 0).
    Execute,
    /// A write to the range (R/W 1).
    Write,
    /// A read or a write of the range (R/W 3).
    Access,
}

/// One enabled breakpoint: its address, its length (1, 2, 4 or 8, to which
/// the address is aligned) and what it breaks on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Breakpoint {
    pub address: u64,
    pub length: u8,
    pub on: BreakOn,
}

/// The thread's enabled breakpoints, by debug register.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Breakpoints(pub [Option<Breakpoint>; 4]);

impl Breakpoints {
    /// The DR6 `B0`–`B3` bits of the execute breakpoints at `rip`.
    fn execute_hits(&self, rip: u64) -> u8 {
        self.hits(|b| b.on == BreakOn::Execute && b.address == rip)
    }
    /// The bits of the data breakpoints whose range `accesses` touch.
    fn data_hits(&self, accesses: &[Access]) -> u8 {
        self.hits(|b| {
            b.on != BreakOn::Execute
                && accesses.iter().any(|a| {
                    (a.write || b.on == BreakOn::Access)
                        && a.address < b.address.wrapping_add(u64::from(b.length))
                        && b.address < a.address.wrapping_add(u64::from(a.length))
                })
        })
    }
    fn hits(&self, matches: impl Fn(&Breakpoint) -> bool) -> u8 {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, b)| b.as_ref().is_some_and(&matches))
            .fold(0, |bits, (n, _)| bits | 1 << n)
    }
    /// Whether any data breakpoint is enabled, so accesses are looked at.
    fn watches_data(&self) -> bool {
        self.0.iter().flatten().any(|b| b.on != BreakOn::Execute)
    }
}

/// A range an instruction reads or writes.
#[derive(Clone, Copy, Debug)]
struct Access {
    address: u64,
    length: u16,
    write: bool,
}

/// Instructions whose memory destination is only read.
fn reads_destination(m: Mnemonic) -> bool {
    use Mnemonic as M;
    matches!(
        m,
        M::Cmp
            | M::Test
            | M::Bt
            | M::Push
            | M::Jmp
            | M::Call
            | M::Ucomiss
            | M::Ucomisd
            | M::Comiss
            | M::Comisd
            | M::Ptest
            | M::Mul
            | M::Imul
            | M::Div
            | M::Idiv
            | M::Fld
            | M::Fild
            | M::Fbld
            | M::Fadd
            | M::Fsub
            | M::Fsubr
            | M::Fmul
            | M::Fdiv
            | M::Fdivr
            | M::Fiadd
            | M::Fisub
            | M::Fisubr
            | M::Fimul
            | M::Fidiv
            | M::Fidivr
            | M::Fcom
            | M::Fcomp
            | M::Ficom
            | M::Ficomp
            | M::Fldcw
            | M::Ldmxcsr
            | M::Clflush
            | M::Xlatb
            | M::Fldenv
            | M::Frstor
            | M::Fxrstor
            | M::Fxrstor64
    )
}

/// The linear address of a memory operand, as the interpreter takes it.
fn linear(state: &CpuState, m: &MemoryOperand) -> u64 {
    let value = |r: Register| match r {
        Register::Gpr { index, size } => {
            state.gpr[usize::from(index & 15)] & crate::size_mask(size)
        }
        _ => 0,
    };
    let mut ea = m.displacement;
    if let Some(b) = m.base {
        ea = ea.wrapping_add(value(b));
    }
    if let Some(x) = m.index {
        ea = ea.wrapping_add(value(x).wrapping_mul(u64::from(m.scale)));
    }
    if m.address_size_32 {
        ea &= 0xffff_ffff;
    }
    match m.segment {
        Segment::Fs => ea.wrapping_add(state.fs_base),
        Segment::Gs => ea.wrapping_add(state.gs_base),
        Segment::None => ea,
    }
}

/// What `insn` is to access, from the registers before it runs.
fn accesses(state: &CpuState, insn: &Instruction) -> Vec<Access> {
    let mut out = Vec::new();
    // `lea` takes no memory, and the hints (`nop`, which the prefetches
    // decode as) never access it.
    if matches!(insn.mnemonic, Mnemonic::Lea | Mnemonic::Nop) {
        return out;
    }
    // `maskmovdqu`: the bytes its mask selects, at rdi.
    if insn.mnemonic == Mnemonic::Maskmovdqu {
        if let (Some(Operand::Memory(m)), Some(Operand::Register(Register::Xmm(n)))) =
            (insn.operand(0), insn.operand(2))
        {
            let wrap = if m.address_size_32 {
                0xffff_ffff
            } else {
                u64::MAX
            };
            let base = linear(state, &m);
            let mask = state.xmm[usize::from(n & 15)].to_le_bytes();
            for (byte, selector) in mask.iter().enumerate() {
                if selector & 0x80 != 0 {
                    out.push(Access {
                        address: base.wrapping_add(byte as u64) & wrap,
                        length: 1,
                        write: true,
                    });
                }
            }
        }
        return out;
    }
    for (n, operand) in insn.operands().enumerate() {
        if let Operand::Memory(m) = operand {
            // `fxsave` writes, and `fxrstor` reads, the front of its
            // 512-byte area: the x87 state, MXCSR and the XMM registers,
            // not the bytes the CPU leaves to software. The x87 save
            // instructions have their area's length as their operand size.
            let length = match insn.mnemonic {
                Mnemonic::Fxsave | Mnemonic::Fxsave64 | Mnemonic::Fxrstor | Mnemonic::Fxrstor64 => {
                    crate::state::FX_WRITTEN as u16
                }
                _ => u16::from(m.size),
            };
            if length == 0 {
                continue;
            }
            out.push(Access {
                address: linear(state, &m),
                length,
                write: n == 0 && !reads_destination(insn.mnemonic)
                    || insn.mnemonic == Mnemonic::Xchg,
            });
        }
    }
    // A string instruction without a repeat: its element at rsi (in its
    // segment) and at rdi.
    if crate::exec::is_string(insn.mnemonic) && insn.rep == RepPrefix::None {
        use Mnemonic as M;
        let size = insn.implicit_size.max(1);
        let mask = if insn.string_address_size_32 {
            0xffff_ffff
        } else {
            u64::MAX
        };
        let source = (state.gpr[reg::RSI] & mask).wrapping_add(match insn.string_segment {
            Segment::Fs => state.fs_base,
            Segment::Gs => state.gs_base,
            Segment::None => 0,
        });
        let destination = state.gpr[reg::RDI] & mask;
        let (reads, writes) = match insn.mnemonic {
            M::Movsb | M::Movsw | M::Movsd | M::Movsq => (Some(source), Some(destination)),
            M::Stosb | M::Stosw | M::Stosd | M::Stosq => (None, Some(destination)),
            M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => (Some(source), None),
            M::Scasb | M::Scasw | M::Scasd | M::Scasq => (Some(destination), None),
            // cmps reads both.
            _ => {
                out.push(Access {
                    address: destination,
                    length: u16::from(size),
                    write: false,
                });
                (Some(source), None)
            }
        };
        for (address, write) in [(reads, false), (writes, true)] {
            if let Some(address) = address {
                out.push(Access {
                    address,
                    length: u16::from(size),
                    write,
                });
            }
        }
        return out;
    }
    let rsp = state.gpr[reg::RSP];
    let size = insn.implicit_size.max(1);
    let length = u16::from(size);
    let step = u64::from(size);
    match insn.mnemonic {
        Mnemonic::Push | Mnemonic::Pushf | Mnemonic::Pushfq => out.push(Access {
            address: rsp.wrapping_sub(step),
            length,
            write: true,
        }),
        // `enter`: rbp pushed, then for a nesting level the frame pointers
        // read below the old rbp and pushed, and the new frame pushed last.
        Mnemonic::Enter => {
            let nesting = match insn.operand(1) {
                Some(Operand::Immediate(level)) => level & 31,
                _ => 0,
            };
            let old_bp = state.gpr[reg::RBP];
            let mut pushed = 1;
            out.push(Access {
                address: rsp.wrapping_sub(step),
                length,
                write: true,
            });
            if nesting != 0 {
                for level in 1..nesting {
                    out.push(Access {
                        address: old_bp.wrapping_sub(level * step),
                        length,
                        write: false,
                    });
                    pushed += 1;
                    out.push(Access {
                        address: rsp.wrapping_sub(pushed * step),
                        length,
                        write: true,
                    });
                }
                out.push(Access {
                    address: rsp.wrapping_sub((pushed + 1) * step),
                    length,
                    write: true,
                });
            }
        }
        // `leave` pops rbp from where rbp points.
        Mnemonic::Leave => out.push(Access {
            address: state.gpr[reg::RBP],
            length,
            write: false,
        }),
        Mnemonic::Call => out.push(Access {
            address: rsp.wrapping_sub(8),
            length: 8,
            write: true,
        }),
        Mnemonic::Pop | Mnemonic::Popf | Mnemonic::Popfq => out.push(Access {
            address: rsp,
            length,
            write: false,
        }),
        Mnemonic::Ret => out.push(Access {
            address: rsp,
            length: 8,
            write: false,
        }),
        _ => {}
    }
    out
}

/// Runs at most `budget` instructions with `breakpoints` enabled, one at a
/// time: [`ExitReason::HardwareBreakpoint`] for a hit, with the DR6 bits of
/// the breakpoints hit, an execute one before its instruction (with RF set
/// so that it runs once resumed) and a data one after. With the trap flag
/// set it runs one instruction, which a data hit reports with the step.
// Kept out of the caller's loop, which runs the guest at full speed when no
// breakpoint is set.
#[inline(never)]
#[cold]
pub fn run_watched(
    state: &mut CpuState,
    mem: &AddressSpace,
    budget: u64,
    cache: &mut DecodeCache,
    breakpoints: &Breakpoints,
) -> ExitReason {
    let watches_data = breakpoints.watches_data();
    for _ in 0..budget.max(1) {
        let rip = state.rip.0;
        // RF holds back an execute breakpoint for the one instruction it
        // was set before.
        let resumed = state.rflags & flag::RF != 0;
        state.rflags &= !flag::RF;
        if !resumed {
            let hits = breakpoints.execute_hits(rip);
            if hits != 0 {
                state.rflags |= flag::RF;
                return ExitReason::HardwareBreakpoint {
                    rip: state.rip,
                    hits,
                    step: false,
                };
            }
        }
        let stepping = state.rflags & flag::TF != 0;
        let planned = if watches_data {
            match crate::fetch_cached(state, mem, cache) {
                Ok(insn) => accesses(state, &insn),
                Err(reason) => return reason,
            }
        } else {
            Vec::new()
        };
        match step_cached(state, mem, cache) {
            Ok(()) => {}
            // popf set the trap flag: the caller steps on.
            Err(ExitReason::BudgetExhausted { .. }) if !stepping => {
                return ExitReason::BudgetExhausted { rip: state.rip };
            }
            Err(ExitReason::BudgetExhausted { .. }) => {}
            Err(reason) => return reason,
        }
        let hits = breakpoints.data_hits(&planned);
        if hits != 0 || stepping {
            return if hits != 0 {
                ExitReason::HardwareBreakpoint {
                    rip: state.rip,
                    hits,
                    step: stepping,
                }
            } else {
                ExitReason::SingleStep { rip: state.rip }
            };
        }
    }
    ExitReason::BudgetExhausted { rip: state.rip }
}
