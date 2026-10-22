# What is paludarium?

paludarium is a user-mode x86-64 Linux emulator written in Rust. It runs
statically linked x86-64 Linux programs (such as static-musl binaries)
unchanged on Linux, macOS and Windows, and in WebAssembly (Node.js and
browsers).

*User mode* means that paludarium does not emulate a whole operating system.
It emulates only what programs ask the kernel for, the system calls. No kernel
boots, so programs start at once.

## What it does

- Runs x86-64 integer and SSE instructions in software.
- Implements, inside the guest, the Linux system calls programs commonly use:
  files, memory, threads and futexes, signals, time, eventfd, timerfd and
  epoll, AF_UNIX sockets, and starting other programs.
- Gives every run its own in-memory filesystem, and shows a host directory
  only when you ask for it, safely.
- In WebAssembly, runs each guest thread in its own Worker, and can translate
  x86-64 code to WebAssembly with a JIT.

There are three ways to use it:

| Use | For |
|---|---|
| [The `paludarium` command](./cli) | running one program on your machine |
| [The Rust library](./rust) | embedding the emulator in your program |
| [The npm package](./javascript) | running programs in the browser or Node.js |

## Why

[jart/blink](https://github.com/jart/blink) is a user-mode x86-64 Linux
emulator written in C. paludarium does the same job, rebuilt from scratch in
Rust for safety and maintainability. Its first user is the sibling project
[formicarium](https://github.com/aletheia-works/formicarium), which runs
command-line tools in the browser.

paludarium follows blink's behaviour and design as a reference; it does not
copy its code.

## Principles

- **The guest stays inside.** Guest system calls are never passed to the host
  by number. Only implemented calls are handled, through an explicit table;
  everything else returns `ENOSYS`. A shown host directory cannot be left
  through `..` or symbolic links.
- **No input stops the emulator.** Whatever instruction bytes, memory, system
  call arguments or ELF contents a guest brings, the emulator does not panic
  and has no undefined behaviour. Fuzzing checks this.
- **Same results as real Linux.** Correctness means the same results as a real
  x86-64 Linux. Differential tests run each program on both and compare
  ([Testing and verification](../design/quality)).
- **No network.** Guests cannot use the network (AF_INET and so on).
