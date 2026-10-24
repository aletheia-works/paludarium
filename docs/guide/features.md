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
- **SSE**: the 145 SSE-family instructions real programs (probe, aube and
  pitchfork) use, the `MFENCE`/`LFENCE`/`SFENCE` fences among them, and
  cryptographic instructions such as AES, PCLMUL and SHA. Floating point is
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
| Processes and threads | `clone`, `clone3`, `fork`, `vfork`, `execve`, `wait4`, `waitid`, `pidfd_open`, `pidfd_send_signal`, `exit`, `exit_group`, `getpid`, `gettid`, `set_tid_address`, `futex`, `sched_getaffinity`, `sched_yield`, `setpgid`/`getpgid`/`getpgrp`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files as a copy), `munmap`, `mremap`, `mprotect`, `madvise`, `msync`, `brk`, `arch_prctl` |
| System information | `uname`, `sysinfo`, `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups`, `getrusage`, `times` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `setitimer`, `rt_sigtimedwait`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete` |
| Files | `open`/`openat`, `read`, `write`, `readv`/`writev`, `pread64`/`pwrite64`, `preadv`/`pwritev`, `copy_file_range`, `sendfile`, `close`, `lseek`, the `stat` family and `statx`, `getdents64`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `readlink`, `truncate`, `flock`, `fcntl`, the `dup` family, `pipe`/`pipe2`, `chdir`, `getcwd`, `umask`, `chmod`/`fchmod`/`fchmodat`, `utimensat`, `fsync`/`fdatasync`, `sync`, `fadvise64`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs` |
| I/O | `poll`, `ppoll`, `select`, `pselect6`, `ioctl` (`TCGETS`, `TIOCGWINSZ`) |
| Events | `eventfd2`, `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` |
| Sockets | `socketpair` (AF_UNIX, `SOCK_STREAM`, `SOCK_SEQPACKET` and `SOCK_DGRAM`), `sendto`, `recvfrom`, `shutdown` |
| Randomness | `getrandom` |

- `pread64`, `pwrite64`, `preadv` and `pwritev` leave the file position
  where it was, and a pipe or socket gives `ESPIPE`; in an `O_APPEND` file a
  positioned write still appends, as on Linux.
- `copy_file_range` copies between two regular files on one mount (`EXDEV`
  across mounts), stopping at the input's end, with Linux's checks in order
  (`EISDIR`, `EINVAL`, `EBADF`, `EOVERFLOW`, and `EINVAL` for an overlap in
  one file). `sendfile` reads a regular file into any writable file, a pipe
  taking at most its capacity per call. Both update the given offsets or the
  file positions; `sendfile` writes its offset back even after an error.
- `statx` reports the fields a `stat` has (`STATX_BASIC_STATS`) and the
  mount's `st_dev` as its device numbers, with Linux's flag and mask checks
  (`EINVAL`). `AT_EMPTY_PATH` names the descriptor, or the working directory
  for `AT_FDCWD`, and as since Linux 6.11 a null path with it does too.
- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET` and `WAKE_BITSET`.
- `futex`, `epoll` and `eventfd` are implemented inside paludarium, not with the
  host's equivalents, so they behave the same on macOS, Windows and in
  WebAssembly.
- `socket()` always returns `EAFNOSUPPORT`: there is no network.
- `poll` waits like `epoll_wait`: until a descriptor is ready, the timeout
  in milliseconds passes (a negative one never does) or a signal arrives
  (`EINTR`). The host's standard streams are always ready until a descriptor
  replaces them. A pipe's read end is readable only with unread data, and
  only hung up once its writers are gone, as Linux's `pipe_poll` reports.
- `ppoll`, `select` and `pselect6` wait the same way. They write the time
  left back to their timeout (not a zero one), as Linux does, and `ppoll` and
  `pselect6` take a temporary signal mask, which a handler runs with.
  `select` fails with `EBADF` for a closed descriptor in its sets, and looks
  at no more than 1024 descriptors (`FD_SETSIZE`), where Linux cuts `nfds` to
  the size of its descriptor table.
- A pipe holds 64 KiB, as on Linux, and `fcntl`'s `F_SETPIPE_SZ` and
  `F_GETPIPE_SZ` resize and report it like `pipe_set_size`: a power of two of
  at least a page, `EBUSY` below the unread data and `EINVAL` past 2³¹.
- A `SOCK_DGRAM` pair keeps message boundaries like `SOCK_SEQPACKET`, but has
  no end of file: when the peer closes, reads wait and the next send gets
  `ECONNREFUSED`, then `ENOTCONN`. Only `SOCK_STREAM` raises `SIGPIPE` with
  `EPIPE`, as on Linux.
- `madvise`: `MADV_DONTNEED` empties private pages, which then read as zeros;
  `MADV_FREE` keeps their contents, as Linux does without memory pressure.
  The access-pattern hints are accepted and other advice gives `EINVAL`.
- `mremap` grows a mapping in place when the pages after it are free, and
  otherwise moves it with its contents under `MREMAP_MAYMOVE`; `MREMAP_FIXED`
  and `MREMAP_DONTUNMAP` work too. Shared memory stays shared with a `fork`ed
  process when it moves. A mapping copied from a file cannot grow (`ENOMEM`),
  as it cannot read the rest of the file, and moving a range that spans
  several mappings with `MREMAP_FIXED`, which recent Linux allows, gives
  `EFAULT`.
- `msync` checks its arguments and the range and succeeds: a shared file
  mapping is a read-only copy, so there is nothing to write back.
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
  `--mount`, without host paths). Each mount has its own `st_dev`, as its
  line in `mountinfo` says, so `df` lists every mount.
- The only other `/proc` entries are this process's own: `/proc/self` (also
  as `/proc/<pid>`), a directory that `readlink` resolves to the PID and that
  its entries can be opened relative to, and `/proc/self/status`. That file
  has Linux's fields in Linux's order (umask, IDs, threads, signal masks,
  capabilities and so on) without the memory and CPU ones, which nothing
  measures.
- CPU time is the host thread's CPU time (user and system together) from a
  guest thread's first system call, where the host can measure it (Linux,
  macOS, Windows); elsewhere, as in WebAssembly, it is wall time instead.
  `CLOCK_THREAD_CPUTIME_ID` reads the thread's, and `CLOCK_PROCESS_CPUTIME_ID`
  the sum of the process's threads, each as of its latest system call. A
  child starts from zero, and its time joins its parent's children's when it
  is waited for. `getrusage`, `times` and the rusage of `wait4` and `waitid`
  report it all as user time, as the emulator's work for system calls runs
  in the host's user space; memory use is not measured.
- `clock_gettime` also reads `CLOCK_MONOTONIC_RAW`, the coarse clocks,
  `CLOCK_BOOTTIME` (the host never suspends), the alarm clocks and
  `CLOCK_TAI` (with a TAI offset of 0). `clock_getres` gives 1 ns, and 4 ms
  for the coarse clocks.
- As root, `access` allows reading and writing, and executing when the file
  has an execute bit or is a directory; `getgroups` returns no groups.
- `sysinfo` reports a fixed 4 GiB of free memory and no swap, without
  revealing the host's; the uptime is the monotonic clock's.
- A timerfd runs on `CLOCK_REALTIME` or `CLOCK_MONOTONIC` (`CLOCK_BOOTTIME`
  as `CLOCK_MONOTONIC`), with absolute and periodic settings. A read returns
  the expirations since the last one, and `poll` and `epoll` see it readable
  once it has expired. `TFD_TIMER_CANCEL_ON_SET` is accepted, but the guest
  cannot set the clock, so it never cancels; the alarm clocks give `EPERM`.
- POSIX timers run on `CLOCK_REALTIME` or `CLOCK_MONOTONIC` and notify with
  a signal to the process (`SIGEV_SIGNAL`, with `SI_TIMER` siginfo and
  overruns), a signal to one of its threads (`SIGEV_THREAD_ID`), or not at all
  (`SIGEV_NONE`). The kernel takes `SIGEV_THREAD` as `SIGEV_SIGNAL`, as Linux
  does; the C library builds the thread on `SIGEV_THREAD_ID`. A thread's timer
  signal adds to its overrun only while the thread has not taken it yet, and
  is lost if the thread has exited. Timers on the CPU-time clocks give
  `EINVAL`. Timers are
  not inherited by `fork` and are deleted by `execve`. `rt_sigtimedwait` also
  takes blocked signals pending for the whole process.
- `clone3` checks its `struct clone_args` as Linux does (`E2BIG` for a
  longer struct whose extra part is not zero) and then runs as the `clone` it
  describes; `CLONE_CLEAR_SIGHAND` resets handled signals to their default.
  `set_tid` and `CLONE_INTO_CGROUP` give `EINVAL`. `clone` itself reads only
  the low 32 bits of its flags, as in Linux, so `CLONE_CLEAR_SIGHAND` is
  `clone3`'s alone.
- `prctl` supports `PR_SET_NAME`/`PR_GET_NAME` (a name of up to 15 bytes per
  thread, taken from the program's file name at `execve` and inherited by new
  threads and processes), `PR_SET_PDEATHSIG` (the signal is sent when the
  parent exits), `PR_SET_DUMPABLE` and `PR_SET_NO_NEW_PRIVS` with their
  `PR_GET_*`; other options give `EINVAL`.
- Resource limits start at Linux's defaults (`RLIMIT_NOFILE` 1024/4096,
  `RLIMIT_STACK` 8 MiB/unlimited, ...), are inherited on `fork` and can be
  read and changed. Two are enforced, as in Linux:
  - `RLIMIT_NOFILE`: a new descriptor past its soft limit gives `EMFILE` (and
    `open` creates nothing), `dup2`/`dup3` onto a number past it `EBADF`, and
    `F_DUPFD` from one past it `EINVAL`.
  - `RLIMIT_FSIZE`: a write to a regular file (`write`, `writev`, `pwrite` and
    `pwritev`, which with `O_APPEND` start at the end, and `copy_file_range`
    and `sendfile`) stops at the soft limit; one that
    starts at or past it, and a `truncate`/`ftruncate` that grows the file
    past it, raise `SIGXFSZ` and fail with `EFBIG`.

  Process groups are kept the same way, and `wait4` and `waitid` can wait for
  one.
- `waitid` follows Linux's checks and copy-out: its siginfo fields are zero
  when no child is reported, even on an error, and an exited child cannot be
  waited for without `WEXITED` or `WCONTINUED` (`ECHILD`). A stop and a
  continue are reported once each to a wait with `WUNTRACED` (`WSTOPPED`) or
  `WCONTINUED` (`WNOWAIT` leaves them), and `SIGCHLD` tells the parent unless
  it set `SA_NOCLDSTOP`. The siginfo of `SIGCHLD` carries the child's PID, its
  `CLD_*` code (`CLD_EXITED`, `CLD_KILLED`, `CLD_STOPPED`, `CLD_CONTINUED`), its
  status and its CPU time as `si_utime`; `si_uid` is 0, and a `SIGCHLD` sent
  while one is pending is dropped, as Linux does. A pidfd from `pidfd_open` becomes
  readable when its process exits (and hung up once it is reaped), so `epoll`
  can wait for it; `waitid(P_PIDFD)` on a nonblocking one gives `EAGAIN`.
  `pidfd_send_signal` takes no siginfo and no scope flags, and `PIDFD_THREAD`
  still names the whole process.
- Invalid pointers return `EFAULT`.

## Threads and processes

- Guest threads created with `clone` run on host threads natively, and on
  Workers in WebAssembly.
- `fork`/`vfork`-style `clone` with `execve` starts another program from the
  virtual filesystem, and `wait4` collects its exit. Rust's
  `std::process::Command` works, also when it forks instead of using
  `posix_spawn` (for example with `pre_exec`).
- A process made by `clone` with `CLONE_VM | CLONE_SIGHAND` but without
  `CLONE_THREAD` shares its signal dispositions with its parent: a
  `sigaction` in one is seen by the other. `execve` gives the process its own
  copy again, as in Linux.

## Signals

- Registration, masks, delivery (the Linux x86-64 signal frame and
  `rt_sigreturn`), `sigaltstack`, queued real-time signals, and stop and
  continue with `SIGSTOP`. A blocking call that a stop interrupts runs again
  after the continue, as Linux restarts it when no handler runs: `read`,
  `write`, `readv`, `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev`,
  `wait4`, `waitid`, `pause`, `rt_sigsuspend`, `flock`, `sendto`, `recvfrom`,
  `ppoll`, `select`, `pselect6`, `poll` with no timeout and a `futex` wait with
  none. `nanosleep`, a relative `clock_nanosleep`, `poll` with a timeout and a
  timed `futex` wait resume through `restart_syscall` with the deadline they had
  (the `futex` wait checks its word again first, `EAGAIN` once it changed), and
  an absolute `clock_nanosleep` runs again; a handler ends the restart, so they
  give `EINTR` then. `epoll_wait` and `rt_sigtimedwait` give `EINTR`, as on
  Linux. `rt_sigsuspend` waits with its mask in place of the signal mask until a
  handler has run, which runs with that mask; the original mask is back after
  it.

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
