//! Architectural register state of one guest thread.

use paludarium_decoder::Instruction;
use paludarium_types::{GuestAddr, InstructionBytes};

use crate::x87::X87;

/// Internal architectural restart information retained across budget stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepeatContinuation {
    pub(crate) instruction: Instruction,
    pub(crate) bytes: InstructionBytes,
    pub(crate) initial_flags: u64,
}

/// CPU model choice for a fault during a repeated comparison instruction.
/// It is explicit guest state and never inferred from the host CPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RepFaultFlags {
    /// Intel SDM behavior: restore the flags from the start of the instruction.
    #[default]
    RestoreInitial,
    /// Observed AMD EPYC behavior: retain flags of completed comparisons.
    PreserveCompleted,
}

/// Indexes of the general-purpose registers in [`CpuState::gpr`].
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
}

/// `rflags` bits.
pub mod flag {
    pub const CF: u64 = 1 << 0;
    /// Bit 1 always reads as one.
    pub const RESERVED1: u64 = 1 << 1;
    pub const PF: u64 = 1 << 2;
    pub const AF: u64 = 1 << 4;
    pub const ZF: u64 = 1 << 6;
    pub const SF: u64 = 1 << 7;
    pub const TF: u64 = 1 << 8;
    pub const IF: u64 = 1 << 9;
    pub const DF: u64 = 1 << 10;
    pub const OF: u64 = 1 << 11;
    pub const NT: u64 = 1 << 14;
    pub const RF: u64 = 1 << 16;
    pub const VM: u64 = 1 << 17;
    pub const AC: u64 = 1 << 18;
    pub const ID: u64 = 1 << 21;
    /// The six arithmetic status flags.
    pub const STATUS: u64 = CF | PF | AF | ZF | SF | OF;
    /// Flags a user-mode `popfq` may change (TF is not emulated).
    pub const USER_WRITABLE: u64 = STATUS | DF | NT | AC | ID;
}

/// Initial `rflags` of a new thread (IF set, reserved bit 1 set).
pub const INITIAL_RFLAGS: u64 = flag::IF | flag::RESERVED1;

/// Initial `mxcsr`: all exceptions masked, round to nearest.
pub const INITIAL_MXCSR: u32 = 0x1f80;

/// The MXCSR bits that may be set, as `fxsave` reports them. AMD's CPUs add bit
/// 17 for misaligned SSE, which `CPUID` does not offer here.
const FX_MXCSR_MASK: u32 = 0xffff;
/// Where the XMM registers are in `fxsave`'s area, and where what it writes
/// ends: the 16 registers take it to 416 bytes.
const FX_XMM: usize = 160;
/// What `fxsave` writes of its 512-byte area.
pub const FX_WRITTEN: usize = 416;

/// Registers of one guest thread. Owned by the kernel's thread;
/// the CPU only executes on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuState {
    /// rax ..= r15, indexed by [`reg`].
    pub gpr: [u64; 16],
    pub rip: GuestAddr,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    /// xmm0 ..= xmm15.
    pub xmm: [u128; 16],
    pub mxcsr: u32,
    pub x87: X87,
    /// Repeated-comparison fault behavior. Defaults to Intel's documented model.
    pub rep_fault_flags: RepFaultFlags,
    /// Cleared on completion/fault/different instruction, retained on budget stop.
    pub repeat_continuation: Option<RepeatContinuation>,
}

impl Default for CpuState {
    fn default() -> Self {
        CpuState {
            gpr: [0; 16],
            rip: GuestAddr(0),
            rflags: INITIAL_RFLAGS,
            fs_base: 0,
            gs_base: 0,
            xmm: [0; 16],
            mxcsr: INITIAL_MXCSR,
            x87: X87::default(),
            rep_fault_flags: RepFaultFlags::default(),
            repeat_continuation: None,
        }
    }
}

impl CpuState {
    /// A thread state starting at `entry` with stack pointer `stack`.
    #[must_use]
    pub fn new(entry: GuestAddr, stack: GuestAddr) -> Self {
        let mut state = CpuState {
            rip: entry,
            ..CpuState::default()
        };
        state.gpr[reg::RSP] = stack.0;
        state
    }

    /// What `fxsave` writes, which is the layout Linux also uses for a signal
    /// frame and a core dump: the x87 state, MXCSR and its mask, and the XMM
    /// registers.
    #[must_use]
    pub fn fx_image(&self) -> [u8; FX_WRITTEN] {
        let mut area = [0u8; FX_WRITTEN];
        self.x87.write_image(&mut area[..FX_XMM]);
        area[24..28].copy_from_slice(&self.mxcsr.to_le_bytes());
        area[28..32].copy_from_slice(&FX_MXCSR_MASK.to_le_bytes());
        for (register, bytes) in self.xmm.iter().zip(area[FX_XMM..].as_chunks_mut::<16>().0) {
            *bytes = register.to_le_bytes();
        }
        area
    }

    /// What `fxrstor` reads from what [`CpuState::fx_image`] gives. False,
    /// with nothing changed, if MXCSR has a reserved bit.
    #[must_use]
    pub fn restore_fx_image(&mut self, area: &[u8; FX_WRITTEN]) -> bool {
        let mxcsr = u32::from_le_bytes([area[24], area[25], area[26], area[27]]);
        if mxcsr & !FX_MXCSR_MASK != 0 {
            return false;
        }
        self.mxcsr = mxcsr;
        self.x87.read_image(&area[..FX_XMM]);
        for (register, bytes) in self.xmm.iter_mut().zip(area[FX_XMM..].as_chunks::<16>().0) {
            *register = u128::from_le_bytes(*bytes);
        }
        true
    }

    /// Whether every flag in `mask` is set.
    #[must_use]
    pub fn flag(&self, mask: u64) -> bool {
        self.rflags & mask == mask
    }

    /// Sets or clears the flags in `mask`.
    pub fn set_flag(&mut self, mask: u64, on: bool) {
        if on {
            self.rflags |= mask;
        } else {
            self.rflags &= !mask;
        }
    }
}
