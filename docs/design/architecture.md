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
| `paludarium-vfs` | A safe in-memory filesystem, host directory mounts, and the mount namespaces' tables of mounts |
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
   stop. While a sampling `cpu-clock` or `task-clock` counts the thread, a
   run ends about when the clock is to fire next, and at least 5,000
   instructions in (`Kernel::run_budget`).

The kernel owns the register state of each thread; the CPU only runs the state
it is given.

The interpreter keeps each thread's decoded instructions in a decode cache, so
an instruction is decoded once for each block it is in. A block holds the
instructions that follow each other in memory from its address, up to a `jmp`,
`call`, `ret`, `syscall`, `hlt` or `ud2`, or 32 instructions; a conditional
branch does not end a block. The interpreter looks up a block only when the
next instruction is not the next one of the current block: after a branch, a
system call or a fault, at the end of the block, or when the code generation
has moved on. Falling through from one instruction to the next needs no
lookup. With the WebAssembly JIT the loop walks the blocks in the same way,
and offers each instruction to the JIT before running it, unless the JIT has
turned that instruction down while its block has been cached.

The code generation is a counter of the address space. It moves on when the
mappings change (`mmap`, `munmap`, `mprotect`, `mremap`, `brk`, `shmat`,
`shmdt`), when `madvise` with `MADV_DONTNEED` discards private pages or the
entries of shared ones, when any
process or the kernel stores to a shared mapping or page cache the space may run
code from, when the space stores to an executable page that an instruction has
been fetched from, and when pages change under it otherwise: a stack grows down,
`MADV_GUARD_INSTALL` puts guards on pages, `UFFDIO_MOVE` moves pages, a private
copy of a page that a truncation left past the end of its file shows the file
again, or `fork` leaves out of the child the areas advised `MADV_DONTFORK` or
`MADV_WIPEONFORK` and the pages that a fault fills again. Each page remembers
whether an instruction was fetched from it. The mark is never cleared, and the
copy that copy-on-write or `fork` makes of a page keeps it. A store to an
executable page that nothing was fetched from leaves the generation, so it makes
no decoded instruction stale: SBCL's heap is readable, writable and executable,
and before this every store to it made the interpreter decode everything again.
The first fetch from a page sets the mark under the address space's lock, after
moving the TLB epoch on, which waits for the stores under way without the lock.
Either a store sees the mark and moves the generation on after its bytes, or the
fetch sees the bytes.

The address space also counts the pages it holds (`VmRSS`), as Linux's RSS
counters do: the count changes with the page entry that changes, when a fault
gives a page an entry, a first write gives a private page bytes of its own, or
an unmap, `madvise` or `mremap` takes entries out or moves them. So the peak
(`VmHWM`), which is noted before each drop, costs the page tables of the range
dropped, not those of the whole space, and loads and stores cost nothing more.
A debug build checks the count against every entry whenever it is read and
when the space goes.

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

When an instruction is decoded, the most frequent simple forms are also worked
out:

- `nop` and `endbr64`;
- moves between registers and memory, and `movzx` from memory;
- `lea`, `push` of a register, an immediate or 8 bytes of memory, and `pop`;
- direct branches, `call` and `ret`, and `jmp` and `call` through a 64-bit
  register or 8 bytes of memory;
- `add`, `sub`, `and`, `or`, `xor`, `cmp` and `test` between registers,
  immediates and memory (without `lock`), and `adc` and `sbb` of a register and
  a register or an immediate;
- `shl`, `shr`, `sar`, `rol` and `ror` of a register by an immediate, and `shl`,
  `shr` and `sar` of a register by `cl`;
- `movzx` from a register, `movsx` and `movsxd` from a register or memory,
  `cbw`, `cwde` and `cdqe`, and `lea` into a 16- or 32-bit register;
- `inc`, `dec`, `neg` and `not` of a register, or of memory without `lock`;
- `setcc` and `cmovcc`;
- `tzcnt`, `lzcnt`, `popcnt`, `bsf` and `bsr` of a register into one of its
  size, `bt`, `bts`, `btr` and `btc` of a register by a register or an
  immediate, and `bswap` of a 32- or 64-bit register;
- `mul` and `imul` of a register into rdx:rax, `div` and `idiv` of rdx:rax by a
  register, and `imul` of two registers or of a register and an immediate;
- `movaps`, `movups`, `movdqa`, `movdqu`, `movapd` and `movupd` between xmm
  registers and memory, `pxor` and `xorps` of xmm registers, `movd` and `movq`
  between xmm registers and general ones or memory, `movq` between xmm
  registers, and the SSE2 `movsd` between xmm registers and memory;
- `pshufd`, `pshuflw`, `pshufhw`, the `punpckl` and `punpckh` unpacks,
  `packuswb`, `packsswb`, `packssdw`, `paddd`, `psubd`, `paddq`, `psubq`,
  `pmuludq`, `pand`, `por`, `pandn`, `pcmpeqb`, `pcmpeqw` and `pcmpeqd` of xmm
  registers, `pxor` and `pcmpeqb` of one and 16 bytes of memory, `pslld` and
  `psrld` of one by an immediate, and `pmovmskb`;
- the string moves `movsb`, `movsw`, `movsd` and `movsq`, and the string
  stores `stosb`, `stosw`, `stosd` and `stosq`, with `rep` or without, of 64-bit
  addresses;
- `cmpxchg` (with `lock` or without) and `xchg` between memory and a register,
  each as the one atomic access of memory that the interpreter makes.

A register in these forms may also be one of the high-byte registers `ah`, `ch`,
`dh` and `bh`.

The forms' operands are taken out in advance, so running them needs neither the
general dispatch by mnemonic nor the general operand handling. Such a form
changes the state only after everything that can fail. When it fails, nothing
has changed, and the instruction runs again through the general path, which
reports the fault. Both paths therefore mean the same thing, which a unit test
checks for every form from random states. A repeated string instruction runs at
most 4096 iterations in a step, and then runs again in the next. One that is
not a comparison and faults after an iteration of its step ends the step there,
with the iterations it made, and the next step reports the fault, as a CPU may
stop `rep` between two iterations. A repeated string move or store therefore
also changes nothing when its form fails. The cache keeps the form, with the
address of the next instruction and three flags (within one 64-byte cache line),
apart from the decoded instruction itself, which only the general path reads. A
run of such forms therefore reads little host memory.

## The native JIT

With `--jit`, the blocks of the decode cache that run often are compiled to
host code (`paludarium-jit-native`, Linux on x86-64 hosts only). Each block
counts how many times it is entered; at the threshold (300 by default), the
forms of its first instructions, up to the first instruction without one,
are handed to the compiler. A thread of the JIT's own builds Cranelift IR
for them, compiles it and maps the code into memory that is never writable
and executable at once. Until the code is ready, and when compiling fails,
the interpreter runs the block as before.

Compiled code means exactly what the interpreter's forms mean. It reads and
writes the thread's registers where the interpreter keeps them, in memory,
with nothing copied in or out. A load or store of up to 8 bytes within one
aligned word goes straight to the page's bytes when the thread's TLB holds
the page and the slot the MMU keeps for compiled code says the access may go
through it: the slot holds only at the epoch it was filled at, and allows a
store only where the MMU's own stores through the TLB would write, never to
a page an instruction was fetched from. A page that is also executable but
holds only data, as SBCL's heap does, is written through the slot until an
instruction is fetched from it. Every other access, and every one the slot
does not allow, such as a write to a page that `mprotect`,
`UFFDIO_WRITEPROTECT` or a clear soft-dirty bit protects, calls the MMU's
own loads and stores, with their checks, which fill the slot again; the load
of an instruction that then writes its operand asks for the page as a write,
so that it faults once, as the write, as in the interpreter. It stops
before an instruction whose load or store fails, having changed nothing for
it, so that the interpreter runs it again and reports the fault, and after a
call into the MMU that finds the code generation moved on. It stops the same
way before a `div` or `idiv` that faults (#DE). A `rep movs` or `rep stos`
runs as in the interpreter: after 4096 iterations, or when an iteration after
the first fails, it leaves at the instruction with the iterations made,
counting it as run, so that the instruction runs again. An access to a
page's bytes never moves it: a slot never allows a write to a page an
instruction was fetched from, nor to a shared or file page, whose stores the
MMU counts as code changes for the mappings and page caches it watches. A
change another thread makes meanwhile shows at the next call, or after the
block, when the interpreter reads the generation again. A taken branch,
`jmp`, `call` and `ret` end it. It returns how many instructions ran, and
the interpreter goes on from the next one.

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
  compiled code and calls it. That code calls back into the MMU, or reads and
  writes a guest page's bytes itself where the slot the MMU fills for it in
  the thread's TLB allows.
- `unwrap`, `expect` and `panic` are denied by clippy in product code.
- Guest addresses (`GuestAddr(u64)`) and host addresses are different types. In
  WebAssembly `usize` is 32 bits wide, so every conversion is checked.
