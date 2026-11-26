//! Executable memory, calls into it, and the helpers that compiled code
//! calls back: the only `unsafe` code of the crate.
//!
//! Code is written into memory that is never writable and executable at
//! once (W^X): it is mapped readable and writable, filled, then made
//! readable and executable, and stays so until it is unmapped.
#![allow(unsafe_code)]

use std::ptr::NonNull;

use paludarium_cpu::CpuState;
use paludarium_mmu::{AddressSpace, AtomicOp, AtomicWidth, JitAccess};
use paludarium_types::GuestAddr;

use crate::emit::{CODE_CHANGED, DONE, FAILED, Helpers};

/// What compiled code reaches guest memory through: the address space,
/// the code generation the block was entered under, and where it finds the
/// thread's [`paludarium_mmu::JitSlot`]s, its `storing` and the space's
/// epoch, which it loads and stores through without a call ([`JitAccess`]).
#[repr(C)]
pub(crate) struct Context<'a> {
    pub mem: &'a AddressSpace,
    pub generation: u64,
    pub slots: u64,
    pub storing: u64,
    pub epoch: u64,
}

impl<'a> Context<'a> {
    pub(crate) fn new(mem: &'a AddressSpace, generation: u64) -> Self {
        let JitAccess {
            slots,
            storing,
            epoch,
        } = mem.jit_access();
        Context {
            mem,
            generation,
            slots,
            storing,
            epoch,
        }
    }
}

/// The value and status a load returns, in RAX and RDX.
#[repr(C)]
struct Loaded {
    value: u64,
    status: i64,
}

/// The status of a done access: [`CODE_CHANGED`] when the code changed.
fn done(context: &Context<'_>) -> i64 {
    if context.mem.code_generation_cached() == context.generation {
        DONE
    } else {
        CODE_CHANGED
    }
}

/// What a load gives compiled code: the value and [`done`]'s status, or
/// [`FAILED`].
fn loaded(context: &Context<'_>, value: Result<u64, paludarium_mmu::Fault>) -> Loaded {
    match value {
        Ok(value) => Loaded {
            value,
            status: done(context),
        },
        Err(_) => Loaded {
            value: 0,
            status: FAILED,
        },
    }
}

extern "sysv64" fn load(context: *const Context<'_>, address: u64, size: u64) -> Loaded {
    // SAFETY: compiled code passes on the context that `Code::run` gave
    // it, which lives for the call.
    let context = unsafe { &*context };
    let value = context
        .mem
        .jit_read_value(GuestAddr(address), usize::try_from(size).unwrap_or(8));
    loaded(context, value)
}

/// [`load`] of the destination of an instruction that then writes it.
extern "sysv64" fn load_for_write(context: *const Context<'_>, address: u64, size: u64) -> Loaded {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    let value = context
        .mem
        .jit_read_value_for_write(GuestAddr(address), usize::try_from(size).unwrap_or(8));
    loaded(context, value)
}

extern "sysv64" fn store(context: *const Context<'_>, address: u64, size: u64, value: u64) -> i64 {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    match context.mem.jit_write_value(
        GuestAddr(address),
        usize::try_from(size).unwrap_or(8),
        value,
    ) {
        Ok(()) => done(context),
        Err(_) => FAILED,
    }
}

extern "sysv64" fn load128(context: *const Context<'_>, address: u64, to: *mut u64) -> i64 {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    let mut bytes = [0; 16];
    if context.mem.read(GuestAddr(address), &mut bytes).is_err() {
        return FAILED;
    }
    let value = u128::from_le_bytes(bytes);
    // SAFETY: compiled code passes the address of an xmm register (a
    // `u128`, two words) in the `CpuState` it was given.
    unsafe {
        to.write(value as u64);
        to.add(1).write((value >> 64) as u64);
    }
    done(context)
}

extern "sysv64" fn store128(context: *const Context<'_>, address: u64, from: *const u64) -> i64 {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    // SAFETY: as in `load128`.
    let value = unsafe { u128::from(from.read()) | (u128::from(from.add(1).read()) << 64) };
    match context.mem.write(GuestAddr(address), &value.to_le_bytes()) {
        Ok(()) => done(context),
        Err(_) => FAILED,
    }
}

/// A locked instruction's memory access: an exchange with `a` when `kind`
/// is 0, a compare of `a` and exchange with `b` otherwise. Its result is the
/// old value, as [`AddressSpace::atomic`] gives it to the interpreter.
extern "sysv64" fn atomic(
    context: *const Context<'_>,
    address: u64,
    size: u64,
    kind: u64,
    a: u64,
    b: u64,
) -> Loaded {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    let width = match size {
        1 => AtomicWidth::W8,
        2 => AtomicWidth::W16,
        4 => AtomicWidth::W32,
        _ => AtomicWidth::W64,
    };
    let operation = if kind == 0 {
        AtomicOp::Exchange(u128::from(a))
    } else {
        AtomicOp::CompareExchange {
            expected: u128::from(a),
            replacement: u128::from(b),
        }
    };
    match context.mem.atomic(GuestAddr(address), width, operation) {
        Ok(result) => Loaded {
            value: result.old as u64,
            status: done(context),
        },
        Err(_) => Loaded {
            value: 0,
            status: FAILED,
        },
    }
}

/// `div` (`signed` 0) or `idiv` of rdx:rax by `divisor`, as the
/// interpreter's `Exec::divide` has it: the quotient into rax and the
/// remainder into rdx, or [`FAILED`] with both as they were when the
/// division faults (#DE): `divisor` is 0 or the quotient does not fit.
extern "sysv64" fn divide(registers: *mut u64, divisor: u64, signed: u64) -> i64 {
    // SAFETY: compiled code passes the address of the general registers
    // (rax, then rcx and rdx) in the `CpuState` it was given.
    let (low, high) = unsafe { (registers.read(), registers.add(2).read()) };
    let dividend = (u128::from(high) << 64) | u128::from(low);
    let result = if signed == 0 {
        let d = u128::from(divisor);
        dividend
            .checked_div(d)
            .and_then(|q| u64::try_from(q).ok())
            .map(|q| (q, (dividend % d) as u64))
    } else {
        let n = dividend as i128;
        let d = i128::from(divisor as i64);
        n.checked_div(d)
            .and_then(|q| i64::try_from(q).ok())
            .map(|q| (q as u64, (n % d) as u64))
    };
    let Some((q, r)) = result else {
        return FAILED;
    };
    // SAFETY: as above.
    unsafe {
        registers.write(q);
        registers.add(2).write(r);
    }
    DONE
}

/// The helpers' addresses, for [`crate::emit::function`].
pub(crate) fn helpers() -> Helpers {
    type Load = extern "sysv64" fn(*const Context<'static>, u64, u64) -> Loaded;
    type Store = extern "sysv64" fn(*const Context<'static>, u64, u64, u64) -> i64;
    type Load128 = extern "sysv64" fn(*const Context<'static>, u64, *mut u64) -> i64;
    type Atomic = extern "sysv64" fn(*const Context<'static>, u64, u64, u64, u64, u64) -> Loaded;
    type Store128 = extern "sysv64" fn(*const Context<'static>, u64, *const u64) -> i64;
    type Divide = extern "sysv64" fn(*mut u64, u64, u64) -> i64;
    Helpers {
        load: load as Load as usize as u64,
        load_for_write: load_for_write as Load as usize as u64,
        store: store as Store as usize as u64,
        load128: load128 as Load128 as usize as u64,
        store128: store128 as Store128 as usize as u64,
        atomic: atomic as Atomic as usize as u64,
        divide: divide as Divide as usize as u64,
    }
}

/// Compiled machine code in executable memory of its own.
pub(crate) struct Code {
    start: NonNull<u8>,
    len: usize,
}

// SAFETY: the memory is never written after `Code::new`, and the code only
// touches the registers and context it is passed.
unsafe impl Send for Code {}
// SAFETY: as for `Send`.
unsafe impl Sync for Code {}

impl Code {
    /// `bytes`, which must be code built by [`crate::emit::function`]
    /// with no relocations, in executable memory. `None` when the memory
    /// cannot be had.
    pub(crate) fn new(bytes: &[u8]) -> Option<Self> {
        let len = bytes.len().max(1);
        // SAFETY: an anonymous private mapping at no fixed address
        // touches no existing memory.
        let start = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if start == libc::MAP_FAILED {
            return None;
        }
        let code = Code {
            start: NonNull::new(start.cast())?,
            len,
        };
        // SAFETY: the mapping is `len` bytes, writable, and no one else
        // has it.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), code.start.as_ptr(), bytes.len());
        }
        // SAFETY: changes only the protection of this mapping.
        let protected =
            unsafe { libc::mprotect(start, len, libc::PROT_READ | libc::PROT_EXEC) } == 0;
        protected.then_some(code)
    }

    /// Runs the code on `state`, in place, and returns how many
    /// instructions it ran.
    pub(crate) fn run(&self, state: &mut CpuState, context: &Context<'_>) -> u64 {
        type Entry = extern "sysv64" fn(*mut CpuState, *const Context<'_>) -> u64;
        // SAFETY: the memory holds a function of this signature
        // ([`crate::emit::block_signature`]), compiled for this host, that
        // reads and writes only the `u64` and `u128` fields of `state` that
        // `emit::offset` places (the general and xmm registers, RFLAGS, RIP,
        // and the FS and GS bases, read only), and calls only the helpers
        // above with `context`. It also reads the counters of `context.mem`
        // and the thread's slots that `context` has the addresses of
        // ([`JitAccess`], valid on this thread while `mem` lives), and
        // loads and stores the bytes of a guest page where a slot shows
        // them, only while the slot holds and only as
        // [`AddressSpace::read_value`] and [`AddressSpace::write_value`]
        // would, each access within one aligned word, which the slot's
        // entry keeps alive until the slot is emptied, on this thread
        // only, by a helper. A store says it is under way at
        // `context.storing` first, as the MMU's own stores do.
        let entry: Entry = unsafe { std::mem::transmute(self.start.as_ptr()) };
        entry(state, context)
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: the mapping is this one's own, and the code is no longer
        // running: `run` borrows `self`.
        unsafe {
            libc::munmap(self.start.as_ptr().cast(), self.len);
        }
    }
}

/// The calling thread's CPU time in nanoseconds.
#[cfg(test)]
pub(crate) fn thread_cpu_time() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a timespec the call may write.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut time) };
    assert_eq!(result, 0);
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}
