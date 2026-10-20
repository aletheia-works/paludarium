# Supported features

paludarium aims to run real programs with the same results as real Linux.
Everything listed here is checked by differential tests against a real x86-64
Linux.

## Instructions

- **Integer instructions and flags**: arithmetic, logic, shifts, bit
  operations, `lock`-prefixed atomics, `REP` string instructions (including
  restart after an interruption), `CMPXCHG8B`/`CMPXCHG16B`, BMI
  (`ADCX`/`ADOX`, `ANDN`, `BZHI`, `MULX`, `PEXT`, `RORX`, `SHLX`/`SHRX`),
  `MOVBE`, `ENTER`/`LEAVE` and more.
- **SSE**: the 129 SSE-family instructions real programs (probe and aube) use,
  and cryptographic instructions such as AES, PCLMUL and SHA. Floating point is
  computed in software.
- Instructions are decoded with [iced-x86](https://github.com/icedland/iced).
- `CPUID` does not reveal the host's values and does not advertise features
  that are not implemented.
- AVX, AVX-512, x87 and MMX are out of scope.

When a guest reaches an instruction it cannot run, it gets `SIGILL`, as on real
Linux. Page faults raise `SIGSEGV`, and integer division by zero `SIGFPE`.

## System calls

Only implemented system calls are handled, through an explicit table.
Everything else returns `ENOSYS`; nothing is passed to the host.

| Group | Main system calls |
|---|---|
| Processes and threads | `clone`, `fork`, `vfork`, `execve`, `wait4`, `exit`, `exit_group`, `getpid`, `gettid`, `set_tid_address`, `futex` |
| Memory | `mmap` (anonymous), `munmap`, `mprotect`, `brk`, `arch_prctl` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `setitimer` |
| Time | `clock_gettime`, `nanosleep`, `clock_nanosleep` |
| Files | `open`/`openat`, `read`, `write`, `writev`, `close`, `lseek`, the `stat` family, `getdents64`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `readlink`, `truncate`, `flock`, `fcntl`, the `dup` family, `pipe`/`pipe2`, `chdir`, `getcwd` |
| I/O | `poll`, `ioctl` (`TCGETS`, `TIOCGWINSZ`) |
| Events | `eventfd2`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` |
| Sockets | `socketpair` (AF_UNIX), `sendto`, `recvfrom`, `shutdown` |
| Randomness | `getrandom` |

- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET` and `WAKE_BITSET`.
- `futex`, `epoll` and `eventfd` are implemented inside paludarium, not with the
  host's equivalents, so they behave the same on macOS, Windows and in
  WebAssembly.
- `socket()` always returns `EAFNOSUPPORT`: there is no network.
- Invalid pointers return `EFAULT`.

## Threads and processes

- Guest threads created with `clone` run on host threads natively, and on
  Workers in WebAssembly.
- `fork`/`vfork`-style `clone` with `execve` starts another program from the
  virtual filesystem, and `wait4` collects its exit. Rust's
  `std::process::Command` works.

## Signals

- Registration, masks, delivery (the Linux x86-64 signal frame and
  `rt_sigreturn`), `sigaltstack`, queued real-time signals, and stop and
  continue with `SIGSTOP`.

## Filesystem

- By default every run gets its own isolated in-memory filesystem, with `/tmp`.
- Creating, reading and writing files, hard links, symbolic links, `flock`,
  `rename`, directory listing and the `stat` family. Open files stay usable
  after `unlink`.
- Files can be placed before the start.
- A host directory can be mounted when you ask for it (`--mount` on the
  command line, `Config::mounts` in Rust). Every operation stays inside that
  directory; `..` and symbolic links cannot lead outside.

## Programs verified

- Hello world in C and Rust, and small test programs for each instruction.
- **probe**: a Rust program that checks eight thread and filesystem features
  (a tokio timer, a UNIX socket pair, rayon parallelism, Mutex and Condvar,
  file operations, hard links, symbolic links and `flock`).
- **aube**: a Node.js package manager written in Rust (v2.8.1). `--version`,
  `install`, `install --frozen-lockfile` and `list` give the same output and
  exit status as on real Linux.

All of them give the same results as a real x86-64 Linux on Linux, macOS and
Windows, and on Node.js, Chromium, Firefox and Safari.
