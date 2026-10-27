# Architecture

paludarium is split into crates by responsibility. Dependencies only point
downwards; there are no cycles.

| Layer | Uses |
|---|---|
| Entry points (the `paludarium` command, the Rust API, the WebAssembly launcher) | runtime |
| runtime | cpu, jit, kernel, loader, host |
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
| `paludarium-loader` | Loading static ELF files and building the initial stack (argv, envp, auxiliary vector) |
| `paludarium-cpu` | The x86-64 interpreter |
| `paludarium-jit` | The code cache interface and the WebAssembly JIT |
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

- `unsafe` is allowed only in the host connection and the JIT; every other
  crate is `#![forbid(unsafe_code)]` (and the JIT does not use `unsafe` today).
- `unwrap`, `expect` and `panic` are denied by clippy in product code.
- Guest addresses (`GuestAddr(u64)`) and host addresses are different types. In
  WebAssembly `usize` is 32 bits wide, so every conversion is checked.
