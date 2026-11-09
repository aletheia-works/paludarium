//! Executable memory, calls into it, and the helpers that compiled code
//! calls back: the only `unsafe` code of the crate.
//!
//! Code is written into memory that is never writable and executable at
//! once (W^X): it is mapped readable and writable, filled, then made
//! readable and executable, and stays so until it is unmapped.
#![allow(unsafe_code)]

use std::ptr::NonNull;

use paludarium_mmu::AddressSpace;
use paludarium_types::GuestAddr;

use crate::emit::{CODE_CHANGED, DONE, FAILED, Helpers, WORDS};

/// What compiled code reaches guest memory through: the address space and
/// the code generation the block was entered under.
#[repr(C)]
pub(crate) struct Context<'a> {
    pub mem: &'a AddressSpace,
    pub generation: u64,
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

extern "sysv64" fn load(context: *const Context<'_>, address: u64, size: u64) -> Loaded {
    // SAFETY: compiled code passes on the context that `Code::run` gave
    // it, which lives for the call.
    let context = unsafe { &*context };
    match context
        .mem
        .read_value(GuestAddr(address), usize::try_from(size).unwrap_or(8))
    {
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

extern "sysv64" fn store(context: *const Context<'_>, address: u64, size: u64, value: u64) -> i64 {
    // SAFETY: as in `load`.
    let context = unsafe { &*context };
    match context.mem.write_value(
        GuestAddr(address),
        usize::try_from(size).unwrap_or(8),
        value,
    ) {
        Ok(()) => done(context),
        Err(_) => FAILED,
    }
}

/// The helpers' addresses, for [`crate::emit::function`].
pub(crate) fn helpers() -> Helpers {
    type Load = extern "sysv64" fn(*const Context<'static>, u64, u64) -> Loaded;
    type Store = extern "sysv64" fn(*const Context<'static>, u64, u64, u64) -> i64;
    Helpers {
        load: load as Load as usize as u64,
        store: store as Store as usize as u64,
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

    /// Runs the code on `registers` (laid out as in [`crate::emit`]) and
    /// returns how many instructions it ran.
    pub(crate) fn run(&self, registers: &mut [u64; WORDS], context: &Context<'_>) -> u64 {
        type Entry = extern "sysv64" fn(*mut u64, *const Context<'_>) -> u64;
        // SAFETY: the memory holds a function of this signature
        // ([`crate::emit::block_signature`]), compiled for this host, that
        // reads and writes only `WORDS` words of `registers` and calls only
        // the helpers above with `context`.
        let entry: Entry = unsafe { std::mem::transmute(self.start.as_ptr()) };
        entry(registers.as_mut_ptr(), context)
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
