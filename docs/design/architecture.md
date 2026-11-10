# Architecture

paludarium is split into crates by responsibility. Dependencies only point
downwards; there are no cycles.

| Layer | Uses |
|---|---|
| Entry points (the `paludarium` command, the Rust API, the WebAssembly launcher) | runtime, jit-native |
| runtime | cpu, jit, kernel, loader, host |
| jit-native | cpu, decoder, mmu |
| cpu, jit | decoder, mmu |
| kernel | mmu, vfs, loader, host |
| loader | mmu, vfs |
| vfs | host |

Every crate uses the shared types of `paludarium-types`.

## Crates

| Crate | Responsibility |
|---|---|
| `paludarium-types` | Shared types (`GuestAddr`, `Errno`, `ExitReason`, `ExitStatus`, `Error`) |
| `paludarium-decoder` | A decoder wrapping iced-x86; only its own instruction types are visible outside |
| `paludarium-mmu` | A software MMU: two-level page tables of 4 KiB pages |
| `paludarium-host` | The host boundary (the `Host` trait) and its Linux, macOS, Windows and WebAssembly implementations |
| `paludarium-vfs` | A safe in-memory filesystem and host directory mounts |
| `paludarium-loader` | Loading ELF files, with the interpreter they ask for, and building the initial stack (argv, envp, auxiliary vector) |
| `paludarium-cpu` | The x86-64 interpreter |
| `paludarium-jit` | The code cache interface and the WebAssembly JIT |
| `paludarium-jit-native` | The native JIT: hot blocks compiled to host code with Cranelift |
| `paludarium-kernel` | Linux system calls; owns the process and thread state |
| `paludarium-runtime` | `Session` and the per-thread execution loop |
| `paludarium` | The public API and the `paludarium` command |

Two crates are not published: `paludarium-harness`, the differential test
tool, and `paludarium-wasm`, the WebAssembly entry point that becomes
`paludarium.wasm` in the npm package.

## How a program runs

1. The loader reads the ELF file, maps it into memory and builds the initial
   stack.
2. The execution loop makes the CPU run instructions. With the JIT enabled, it
   first asks the code cache for a translated block and falls back to the
   interpreter otherwise.
3. On a system call or a guest exception, the CPU stops and returns the
   reason. The CPU does not know the kernel.
4. The execution loop calls the kernel to handle the system call, or delivers a
   signal to the guest.
5. Every 100,000 instructions, the loop checks whether it has been asked to
   stop.

The kernel owns the register state of each thread; the CPU only runs the state
it is given.

The interpreter keeps each thread's decoded instructions in a decode cache, so
an instruction is decoded once for each block it is in. A block holds the
instructions that follow each other in memory from its address, up to a `jmp`,
`call`, `ret`, `syscall`, `hlt` or `ud2`, or 32 instructions; a conditional
branch does not end a block. The interpreter looks up a block only when the
next instruction is not the next one of the current block: after a branch, a
system call or a fault, at the end of the block, or when the code generation
has moved on. Falling through from one instruction to the next needs no lookup.

The code generation is a counter of the address space. It moves on when the
mappings change (`mmap`, `munmap`, `mprotect`, `mremap`, `brk`, `shmat`,
`shmdt`), when `madvise` with `MADV_DONTNEED` discards private pages, when
any process or the kernel stores to a shared mapping or page cache the space
may run code from, and when the space stores to an executable page that an
instruction has been fetched from. Each page remembers whether an instruction
was fetched from it. The mark is never cleared, and the copy that copy-on-write or `fork` makes
of a page keeps it. A store to an executable page that nothing was fetched from
leaves the generation, so it makes no decoded instruction stale: SBCL's heap is
readable, writable and executable, and before this every store to it made the
interpreter decode everything again. The first fetch from a page sets the mark
under the address space's lock, after moving the TLB epoch on, which waits for
the stores under way without the lock. Either a store sees the mark and moves
the generation on after its bytes, or the fetch sees the bytes.

A block starts with its first instruction and grows as it runs. An instruction
that runs right after the last one of a block is decoded on its own, as it would
be without blocks, and added to that block unless another block was stored
after it. So an instruction is decoded only when it first runs, and one that
cannot be decoded faults only when it is reached, as without blocks.

The cache has room for as many instructions as it has slots, counting copies: a
branch into the middle of a block starts another block, which decodes the rest
of the first again. When the room is full, the cache doubles if the blocks of
the current code generation fill more than half of it, and drops every block
otherwise. It copies nothing either way: a program that changes its code often,
as a JIT does, fills the room with blocks of earlier generations again and again.

When an instruction is decoded, the most frequent simple
forms (`nop` and `endbr64`, moves between registers and memory, `movzx` from
memory, `lea`, `push` and `pop`, direct branches, `call`, `ret`, `add`, `sub`,
`and`, `or`, `xor`, `cmp` and `test` on a register, and `cmp` and `test` on
memory) are also worked out: their operands are taken out in advance,
so running them needs neither the general dispatch by mnemonic nor the general
operand handling. Such a form changes the state only after everything that can
fail. When it fails, nothing has changed, and the instruction runs again
through the general path, which reports the fault. Both paths therefore mean
the same thing, which a unit test checks for every form from random states. The
cache keeps the form, with the address of the next instruction and two flags
(within one 64-byte cache line), apart from the decoded instruction itself, which only the
general path reads. A run of such forms therefore reads little host memory.

## The native JIT

With `--jit`, the blocks of the decode cache that run often are compiled to
host code (`paludarium-jit-native`, Linux on x86-64 hosts only). Each block
counts how many times it is entered; at the threshold (100 by default), the
forms of its first instructions, up to the first instruction without one,
are handed to the compiler. A thread of the JIT's own builds Cranelift IR
for them, compiles it and maps the code into memory that is never writable
and executable at once. Until the code is ready, and when compiling fails,
the interpreter runs the block as before.

Compiled code means exactly what the interpreter's forms mean. It works on a
copy of the registers, reads and writes them in memory, and reaches guest
memory only through the MMU's own loads and stores, with their checks. It
stops before an instruction whose load or store fails, having changed nothing
for it, so that the interpreter runs it again and reports the fault, and
after a load or store that moved the code generation on. A taken branch,
`jmp`, `call` and `ret` end it. It returns how many instructions ran, and the
interpreter goes on from the next one.

When the code generation moves on, the interpreter decodes every block again,
mostly to the same forms. The JIT keeps the code it compiled by its forms (up
to 65536 blocks) and gives the same code to a block whose forms are the same,
so a program that maps memory often is not compiled again and again. The
code is shared by every thread and process of the session.
`PALUDARIUM_JIT_STATS` set in the environment prints, on standard error, how
many blocks and instructions it has compiled and in how long.

## The host boundary

All differences between native hosts and WebAssembly stay inside
`paludarium-host`. No other crate calls `std::thread`, `std::fs` or
`std::time` directly. The `Host` trait provides starting threads, waiting and
waking, clocks, waiting with a deadline, terminal information, standard input
and output, secure randomness, and mounting host directories.

Guest system call numbers, guest pointers and guest `ioctl` numbers never
cross this boundary.

## Three kinds of errors

Types keep them apart:

| Kind | Type | Goes to |
|---|---|---|
| A failed system call | `Errno` | the guest, as an errno |
| A guest exception | `ExitReason` | a signal to the guest (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, …) |
| A problem of the emulator itself | `Error` | a stop, with the instruction address, bytes and system call number |

A guest's exit (`ExitStatus`) is never mixed with an emulator error.

## Safety rules

- `unsafe` is allowed only in the host connection and the JITs; every other
  crate is `#![forbid(unsafe_code)]`. The WebAssembly JIT does not use
  `unsafe` today; the native JIT uses it only in one module, which maps the
  compiled code and calls it, and calls back into the MMU.
- `unwrap`, `expect` and `panic` are denied by clippy in product code.
- Guest addresses (`GuestAddr(u64)`) and host addresses are different types. In
  WebAssembly `usize` is 32 bits wide, so every conversion is checked.
