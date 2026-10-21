//! Shared types for the paludarium x86-64 Linux user-mode emulator (contract C1).
//!
//! Three kinds of failure are kept apart by type (team.md Code Style):
//! - [`Errno`]: an error returned to the guest by a system call;
//! - [`ExitReason`]: why the CPU stopped (system call, guest exception, budget);
//! - [`Error`]: a problem of the emulator itself (unimplemented, internal,
//!   invalid program, host failure).
#![forbid(unsafe_code)]

use core::fmt;

/// Size of a guest page in bytes (BR2.1).
pub const PAGE_SIZE: u64 = 4096;

/// Exclusive upper bound of the guest user address space: the lower half of
/// the 48-bit canonical space (entities.md AddressSpace).
pub const USER_ADDRESS_LIMIT: u64 = 1 << 47;

/// Longest possible x86-64 instruction in bytes.
pub const MAX_INSTRUCTION_LEN: usize = 15;

/// A guest virtual address. Never mixed with host `usize` values; conversions
/// are checked (team.md Code Style, BR2.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestAddr(pub u64);

impl GuestAddr {
    /// The null guest address.
    pub const NULL: GuestAddr = GuestAddr(0);

    /// Wraps a raw 64-bit guest address.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        GuestAddr(value)
    }

    /// Returns the raw 64-bit value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds an offset, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, offset: u64) -> Option<GuestAddr> {
        self.0.checked_add(offset).map(GuestAddr)
    }

    /// Subtracts an offset, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, offset: u64) -> Option<GuestAddr> {
        self.0.checked_sub(offset).map(GuestAddr)
    }

    /// Adds an offset with two's-complement wrap-around (address arithmetic
    /// performed by guest instructions wraps).
    #[must_use]
    pub const fn wrapping_add(self, offset: u64) -> GuestAddr {
        GuestAddr(self.0.wrapping_add(offset))
    }

    /// Converts to a host `usize`, failing when it does not fit (wasm32).
    #[must_use]
    pub fn to_usize(self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }

    /// Converts a host `usize` to a guest address.
    #[must_use]
    pub fn from_usize(value: usize) -> Option<GuestAddr> {
        u64::try_from(value).ok().map(GuestAddr)
    }

    /// Offset of the address inside its page.
    #[must_use]
    pub const fn page_offset(self) -> u64 {
        self.0 % PAGE_SIZE
    }

    /// Rounds down to the start of the page.
    #[must_use]
    pub const fn page_align_down(self) -> GuestAddr {
        GuestAddr(self.0 - self.0 % PAGE_SIZE)
    }

    /// Rounds up to the next page boundary, `None` on overflow.
    #[must_use]
    pub fn page_align_up(self) -> Option<GuestAddr> {
        let rem = self.0 % PAGE_SIZE;
        if rem == 0 {
            Some(self)
        } else {
            self.0.checked_add(PAGE_SIZE - rem).map(GuestAddr)
        }
    }

    /// Whether the address lies in the guest user address space.
    #[must_use]
    pub const fn is_user(self) -> bool {
        self.0 < USER_ADDRESS_LIMIT
    }
}

impl fmt::Display for GuestAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// A Linux errno value returned to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Errno(pub i32);

impl Errno {
    pub const EPERM: Errno = Errno(1);
    pub const ENOENT: Errno = Errno(2);
    pub const EIO: Errno = Errno(5);
    pub const EBADF: Errno = Errno(9);
    pub const EAGAIN: Errno = Errno(11);
    pub const ENOMEM: Errno = Errno(12);
    pub const EFAULT: Errno = Errno(14);
    pub const EEXIST: Errno = Errno(17);
    pub const ENODEV: Errno = Errno(19);
    pub const ENOTDIR: Errno = Errno(20);
    pub const EISDIR: Errno = Errno(21);
    pub const EINVAL: Errno = Errno(22);
    pub const ENOTTY: Errno = Errno(25);
    pub const ENOSPC: Errno = Errno(28);
    pub const ESPIPE: Errno = Errno(29);
    pub const EPIPE: Errno = Errno(32);
    pub const ERANGE: Errno = Errno(34);
    pub const ENAMETOOLONG: Errno = Errno(36);
    pub const ENOSYS: Errno = Errno(38);

    /// The value placed in `rax` for a failed system call (`-errno`).
    #[must_use]
    pub const fn to_syscall_return(self) -> u64 {
        (-(self.0 as i64)) as u64
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

/// Linux signal numbers used by U1.
pub mod signal {
    pub const SIGILL: i32 = 4;
    pub const SIGFPE: i32 = 8;
    pub const SIGKILL: i32 = 9;
    pub const SIGSEGV: i32 = 11;
}

/// Up to 15 raw instruction bytes, kept inline so [`ExitReason`] stays `Copy`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InstructionBytes {
    len: u8,
    bytes: [u8; MAX_INSTRUCTION_LEN],
}

impl InstructionBytes {
    /// Copies at most [`MAX_INSTRUCTION_LEN`] bytes from `bytes`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; MAX_INSTRUCTION_LEN];
        let len = bytes.len().min(MAX_INSTRUCTION_LEN);
        buf[..len].copy_from_slice(&bytes[..len]);
        InstructionBytes {
            // `len` is at most 15, so the conversion cannot truncate.
            len: u8::try_from(len).unwrap_or(0),
            bytes: buf,
        }
    }

    /// The stored bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for InstructionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", HexBytes(self.as_slice()))
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Why the CPU (or a JIT) stopped executing guest code (C1, ADR-004).
///
/// The system call number is not stored here; the kernel reads it from `rax`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitReason {
    /// A `syscall` instruction was executed. `rip` already points past it.
    Syscall { rip: GuestAddr },
    /// A memory access faulted (becomes SIGSEGV for the guest).
    PageFault {
        rip: GuestAddr,
        addr: GuestAddr,
        write: bool,
        /// Instruction fetch rather than operand access.
        fetch: bool,
        /// Mapping membership captured by the MMU when it faulted.
        mapped: bool,
        /// Resident user page captured by the MMU when it faulted.
        present: bool,
    },
    /// The instruction could not be decoded or is not implemented (SIGILL).
    InvalidOpcode {
        rip: GuestAddr,
        bytes: InstructionBytes,
    },
    /// A privileged instruction such as `hlt` (SIGSEGV, as on Linux).
    Halt { rip: GuestAddr },
    /// A general-protection exception, e.g. a misaligned `movaps` operand
    /// (SIGSEGV, as on Linux).
    GeneralProtection { rip: GuestAddr },
    /// A divide error: division by zero or quotient overflow (SIGFPE).
    ArithmeticFault { rip: GuestAddr },
    /// An unmasked SIMD floating-point exception (Linux SIGFPE, trap 19).
    FloatingPointFault { rip: GuestAddr, code: u8 },
    /// The instruction budget was used up; the loop may resume.
    BudgetExhausted { rip: GuestAddr },
}

impl ExitReason {
    /// The guest instruction pointer associated with the stop.
    #[must_use]
    pub const fn rip(&self) -> GuestAddr {
        match *self {
            ExitReason::Syscall { rip }
            | ExitReason::PageFault { rip, .. }
            | ExitReason::InvalidOpcode { rip, .. }
            | ExitReason::Halt { rip }
            | ExitReason::GeneralProtection { rip }
            | ExitReason::ArithmeticFault { rip }
            | ExitReason::FloatingPointFault { rip, .. }
            | ExitReason::BudgetExhausted { rip } => rip,
        }
    }
}

/// How the guest process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitStatus {
    /// `exit`/`exit_group` with the low 8 bits of the code (BR5.1).
    Exited(i32),
    /// Terminated by the signal with this number.
    Signaled(i32),
}

impl ExitStatus {
    /// The exit code a command reports for this status (BR5.2):
    /// the guest code, or 128 + signal number.
    #[must_use]
    pub const fn command_exit_code(self) -> i32 {
        match self {
            ExitStatus::Exited(code) => code,
            ExitStatus::Signaled(signal) => 128 + signal,
        }
    }
}

/// Category of an emulator error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A feature the emulator does not implement yet.
    Unimplemented,
    /// An internal inconsistency of the emulator.
    Internal,
    /// The guest program cannot be loaded.
    InvalidProgram,
    /// The host failed (I/O error, no randomness, ...).
    Host,
}

impl ErrorKind {
    /// Stable lower-case name used in messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Unimplemented => "unimplemented",
            ErrorKind::Internal => "internal",
            ErrorKind::InvalidProgram => "invalid-program",
            ErrorKind::Host => "host",
        }
    }
}

/// A problem of the emulator itself, distinct from the guest's exit (C1, Q4).
///
/// Its display is limited to the kind, a fixed message, the instruction
/// address and bytes and the system call number; it never contains host paths
/// or environment variables (NFR2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub rip: Option<GuestAddr>,
    pub bytes: Option<Vec<u8>>,
    pub syscall: Option<u64>,
    pub message: String,
}

impl Error {
    /// Creates an error with a message and no location.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            rip: None,
            bytes: None,
            syscall: None,
            message: message.into(),
        }
    }

    /// Attaches the guest instruction address.
    #[must_use]
    pub fn with_rip(mut self, rip: GuestAddr) -> Self {
        self.rip = Some(rip);
        self
    }

    /// Attaches the raw instruction bytes.
    #[must_use]
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.bytes = Some(bytes.to_vec());
        self
    }

    /// Attaches the system call number.
    #[must_use]
    pub fn with_syscall(mut self, number: u64) -> Self {
        self.syscall = Some(number);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)?;
        if let Some(rip) = self.rip {
            write!(f, " rip={rip}")?;
        }
        if let Some(bytes) = &self.bytes {
            write!(f, " bytes=[{}]", HexBytes(bytes))?;
        }
        if let Some(number) = self.syscall {
            write!(f, " syscall={number}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    mod signals_time_tests {
        use super::*;
        macro_rules! fault_case {
            ($name:ident,$write:literal,$fetch:literal,$mapped:literal,$present:literal) => {
                #[test]
                fn $name() {
                    let reason = ExitReason::PageFault {
                        rip: GuestAddr(0x400000),
                        addr: GuestAddr(0x70000000),
                        write: $write,
                        fetch: $fetch,
                        mapped: $mapped,
                        present: $present,
                    };
                    assert_eq!(reason.rip(), GuestAddr(0x400000));
                    let copied = reason;
                    assert!(matches!(
                        copied,
                        ExitReason::PageFault {
                            addr: GuestAddr(0x70000000),
                            write: $write,
                            fetch: $fetch,
                            mapped: $mapped,
                            present: $present,
                            ..
                        }
                    ));
                    assert_ne!(
                        copied,
                        ExitReason::PageFault {
                            rip: GuestAddr(0x400000),
                            addr: GuestAddr(0x70000000),
                            write: $write,
                            fetch: !$fetch,
                            mapped: $mapped,
                            present: $present
                        }
                    );
                }
            };
        }
        fault_case!(fault_maperr_read, false, false, false, false);
        fault_case!(fault_maperr_fetch, false, true, false, false);
        fault_case!(fault_accerr_resident_write, true, false, true, true);
        fault_case!(fault_accerr_virgin_write, true, false, true, false);
        fault_case!(fault_accerr_resident_fetch, false, true, true, true);
    }

    #[test]
    fn arithmetic_fault_retains_instruction_pointer() {
        let rip = GuestAddr(0x401123);
        assert_eq!(ExitReason::ArithmeticFault { rip }.rip(), rip);
    }

    #[test]
    fn guest_addr_checked_arithmetic_detects_overflow() {
        let top = GuestAddr(u64::MAX);
        assert_eq!(top.checked_add(1), None);
        assert_eq!(GuestAddr(0).checked_sub(1), None);
        assert_eq!(GuestAddr(10).checked_add(5), Some(GuestAddr(15)));
        assert_eq!(top.wrapping_add(2), GuestAddr(1));
    }

    #[test]
    fn guest_addr_page_alignment() {
        assert_eq!(GuestAddr(0x1234).page_align_down(), GuestAddr(0x1000));
        assert_eq!(GuestAddr(0x1234).page_align_up(), Some(GuestAddr(0x2000)));
        assert_eq!(GuestAddr(0x2000).page_align_up(), Some(GuestAddr(0x2000)));
        assert_eq!(GuestAddr(u64::MAX).page_align_up(), None);
        assert_eq!(GuestAddr(0x1234).page_offset(), 0x234);
    }

    #[test]
    fn guest_addr_usize_conversion_is_checked() {
        assert_eq!(GuestAddr(42).to_usize(), Some(42));
        assert_eq!(GuestAddr::from_usize(7), Some(GuestAddr(7)));
        if usize::BITS < 64 {
            assert_eq!(GuestAddr(u64::MAX).to_usize(), None);
        }
        assert!(GuestAddr(USER_ADDRESS_LIMIT - 1).is_user());
        assert!(!GuestAddr(USER_ADDRESS_LIMIT).is_user());
    }

    #[test]
    fn errno_becomes_negative_return_value() {
        assert_eq!(Errno::ENOSYS.to_syscall_return(), (-38i64) as u64);
        assert_eq!(Errno::EBADF.to_syscall_return(), u64::MAX - 8);
    }

    #[test]
    fn exit_status_maps_to_command_exit_code() {
        assert_eq!(ExitStatus::Exited(3).command_exit_code(), 3);
        assert_eq!(
            ExitStatus::Signaled(signal::SIGSEGV).command_exit_code(),
            139
        );
        assert_eq!(
            ExitStatus::Signaled(signal::SIGKILL).command_exit_code(),
            137
        );
    }

    #[test]
    fn instruction_bytes_truncate_to_fifteen() {
        let long = [0x90u8; 20];
        assert_eq!(InstructionBytes::new(&long).as_slice().len(), 15);
        assert_eq!(
            InstructionBytes::new(&[0x0f, 0x0b]).as_slice(),
            &[0x0f, 0x0b]
        );
        assert!(InstructionBytes::new(&[]).as_slice().is_empty());
    }

    #[test]
    fn exit_reason_reports_rip() {
        let reason = ExitReason::InvalidOpcode {
            rip: GuestAddr(0x401000),
            bytes: InstructionBytes::new(&[0x0f, 0x0b]),
        };
        assert_eq!(reason.rip(), GuestAddr(0x401000));
        assert_eq!(ExitReason::Halt { rip: GuestAddr(5) }.rip(), GuestAddr(5));
    }

    #[test]
    fn error_display_contains_only_location_fields() {
        let err = Error::new(ErrorKind::Unimplemented, "instruction")
            .with_rip(GuestAddr(0x401000))
            .with_bytes(&[0x0f, 0x0b])
            .with_syscall(999);
        assert_eq!(
            err.to_string(),
            "unimplemented: instruction rip=0x401000 bytes=[0f 0b] syscall=999"
        );
        let plain = Error::new(ErrorKind::InvalidProgram, "not an ELF file");
        assert_eq!(plain.to_string(), "invalid-program: not an ELF file");
    }
}
