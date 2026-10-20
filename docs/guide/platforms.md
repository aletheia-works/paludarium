# Supported platforms

## Guests

- x86-64 Linux programs only; 32-bit x86 is out of scope.
- Statically linked executables (`ET_EXEC`, and static-pie without an
  interpreter). Dynamically linked programs (using glibc shared libraries) are
  not supported yet.

## Hosts

| Host | Status |
|---|---|
| Linux | Supported; differential tests take their reference here |
| macOS | Supported; the same Linux ELF runs in software |
| Windows | Supported; the same Linux ELF runs in software |
| Node.js (`worker_threads`) | Supported (npm package) |
| Chromium-based browsers | Supported (npm package) |
| Firefox | Supported (npm package) |
| Safari | Supported (npm package); CI tests the real Safari |

On macOS and Windows, paludarium does not hand a Linux binary to the host to
execute: it handles the instructions and system calls itself. The same ELF
therefore runs the same way on every host.

Terminal information (whether a stream is a tty, and the window size) comes
from each host in its own way: `TCGETS` and `TIOCGWINSZ` on Linux, libc termios
on macOS, and the console API (read only) on Windows, converted to the Linux
form the guest expects.

## Verified versions

Before each release, the same code is checked to give the same results on all
of these ([Testing and verification](../design/quality)):

- Linux, macOS and Windows (GitHub Actions runners)
- Node.js 26.12.0
- Chromium, Firefox, and the real Safari (on a macOS runner)

## In the browser

- `SharedArrayBuffer` and module Workers.
- A cross-origin isolated page (`Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`); without it there is no
  `SharedArrayBuffer`.
- Browsers do not allow `Atomics.wait` on the main thread, so the emulator
  runs entirely in Workers.

## Rust toolchain

- Built and tested with a pinned nightly (now `nightly-2026-10-11`).
- The crates' MSRV is 1.101, so today's stable Rust cannot build them.
- The WebAssembly build also uses nightly `build-std` and atomics.
