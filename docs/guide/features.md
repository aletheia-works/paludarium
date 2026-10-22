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
- **Hints**: `PAUSE` and the `PREFETCHNTA`/`PREFETCHT0`/`T1`/`T2` prefetches,
  which change nothing and never fault.
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
| Processes and threads | `clone`, `fork`, `vfork`, `execve`, `wait4`, `exit`, `exit_group`, `getpid`, `gettid`, `set_tid_address`, `futex`, `sched_getaffinity`, `sched_yield`, `setpgid`/`getpgid`/`getpgrp`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files as a copy), `munmap`, `mprotect`, `madvise`, `brk`, `arch_prctl` |
| System information | `uname`, `sysinfo`, `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `setitimer`, `rt_sigtimedwait` |
| Time | `clock_gettime`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete` |
| Files | `open`/`openat`, `read`, `write`, `writev`, `close`, `lseek`, the `stat` family, `getdents64`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `readlink`, `truncate`, `flock`, `fcntl`, the `dup` family, `pipe`/`pipe2`, `chdir`, `getcwd`, `umask`, `chmod`/`fchmod`/`fchmodat`, `utimensat`, `fsync`/`fdatasync`, `sync`, `fadvise64`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs` |
| I/O | `poll`, `ioctl` (`TCGETS`, `TIOCGWINSZ`) |
| Events | `eventfd2`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` |
| Sockets | `socketpair` (AF_UNIX, `SOCK_STREAM` and `SOCK_SEQPACKET`), `sendto`, `recvfrom`, `shutdown` |
| Randomness | `getrandom` |

- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET` and `WAKE_BITSET`.
- `futex`, `epoll` and `eventfd` are implemented inside paludarium, not with the
  host's equivalents, so they behave the same on macOS, Windows and in
  WebAssembly.
- `socket()` always returns `EAFNOSUPPORT`: there is no network.
- `madvise`: `MADV_DONTNEED` empties private pages, which then read as zeros;
  `MADV_FREE` keeps their contents, as Linux does without memory pressure.
  The access-pattern hints are accepted and other advice gives `EINVAL`.
- `sched_getaffinity` lets every guest thread run on each of the host's CPUs,
  so the guest sees as many CPUs as the host has (one in WebAssembly).
- `uname` reports Linux on x86_64 with the host name `paludarium`; like
  `CPUID`, it does not reveal the host. The guest runs as root (user and group
  0), the owner `stat` reports for every file.
- `chmod` and `utimensat` work in the in-memory filesystem and in mounted
  host directories; on a Windows host, `chmod` only sets or clears the
  read-only attribute. `stat` reports only the modification time, with access
  and change times of 0; the host still records both times it is given for a
  file in a mounted directory. The umask is shared by threads, as `CLONE_FS` shares it on
  Linux. `fsync` and `fdatasync` succeed on files and directories and give
  `EINVAL` on pipes, sockets and terminals; `fadvise64` is accepted as a hint.
- `statfs` reports the in-memory filesystem as a 4 GiB tmpfs whose used
  space and inodes are what it holds, and a mounted host directory with the
  host filesystem's own numbers. `/proc/self/mountinfo`, `/proc/self/mounts`
  and `/proc/mounts` list the mounts (`tmpfs` for the root, `hostfs` for each
  `--mount`, without host paths); they are the only `/proc` files. Each mount
  has its own `st_dev`, as its line in `mountinfo` says, so `df` lists every
  mount.
- As root, `access` allows reading and writing, and executing when the file
  has an execute bit or is a directory; `getgroups` returns no groups.
- `sysinfo` reports a fixed 4 GiB of free memory and no swap, without
  revealing the host's; the uptime is the monotonic clock's.
- POSIX timers run on `CLOCK_REALTIME` or `CLOCK_MONOTONIC` and notify with
  a signal (`SIGEV_SIGNAL`, with `SI_TIMER` siginfo and overruns) or not at all
  (`SIGEV_NONE`); `SIGEV_THREAD_ID` and CPU-time clocks give `EINVAL`. They are
  not inherited by `fork` and are deleted by `execve`. `rt_sigtimedwait` also
  takes blocked signals pending for the whole process.
- `prctl` supports `PR_SET_PDEATHSIG` (the signal is sent when the parent
  exits), `PR_SET_DUMPABLE` and `PR_SET_NO_NEW_PRIVS` with their `PR_GET_*`;
  other options give `EINVAL`.
- Resource limits start at Linux's defaults (`RLIMIT_NOFILE` 1024/4096,
  `RLIMIT_STACK` 8 MiB/unlimited, ...), are inherited on `fork` and can be
  read and changed, but paludarium does not enforce them. Process groups are
  kept the same way; `wait` cannot select by process group yet.
- Invalid pointers return `EFAULT`.

## Threads and processes

- Guest threads created with `clone` run on host threads natively, and on
  Workers in WebAssembly.
- `fork`/`vfork`-style `clone` with `execve` starts another program from the
  virtual filesystem, and `wait4` collects its exit. Rust's
  `std::process::Command` works, also when it forks instead of using
  `posix_spawn` (for example with `pre_exec`).

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
- **ripgrep**: a text search tool written in Rust (15.2.0), which runs its
  searches on several threads. Nine searches, including a regular expression
  replacement, a parallel search, one through a memory-mapped file and two
  errors, give the same output and exit status as on real Linux. `--version`
  is not compared, because it reports the SIMD features `CPUID` shows, which
  paludarium limits on purpose.

All of them give the same results as a real x86-64 Linux on Linux, macOS and
Windows, and on Node.js, Chromium, Firefox and Safari.
