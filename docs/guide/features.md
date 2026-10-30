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
Everything else returns `ENOSYS`; nothing is passed to the host. The table
below names every implemented call, which `lint:all` checks against the
kernel.

| Group | System calls |
|---|---|
| Processes and threads | `clone`, `clone3`, `fork`, `vfork`, `execve`, `wait4`, `waitid`, `pidfd_open`, `pidfd_send_signal`, `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `set_tid_address`, `futex`, `sched_getaffinity`, `sched_yield`, `setpgid`/`getpgid`/`getpgrp`, `setsid`/`getsid`, `getpriority`/`setpriority`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files private or shared), `munmap`, `mremap`, `mprotect`, `madvise`, `msync`, `brk`, `arch_prctl` |
| System information | `uname`, `sysinfo`, `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups`, `getrusage`, `times` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `setitimer`, `rt_sigtimedwait`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete` |
| Files | `open`/`openat`/`creat`, `read`, `write`, `readv`/`writev`, `pread64`/`pwrite64`, `preadv`/`pwritev`, `copy_file_range`, `sendfile`, `close`, `close_range`, `lseek`, `stat`/`fstat`/`lstat`/`newfstatat`, `statx`, `getdents64`, `mkdir`/`mkdirat`, `rmdir`, `unlink`/`unlinkat`, `rename`/`renameat`, `link`/`linkat`, `symlink`/`symlinkat`, `readlink`/`readlinkat`, `truncate`/`ftruncate`, `fallocate`, `memfd_create`, `flock`, `fcntl`, `dup`/`dup2`/`dup3`, `pipe`/`pipe2`, `chdir`/`fchdir`, `getcwd`, `umask`, `chmod`/`fchmod`/`fchmodat`, `chown`/`fchown`/`lchown`/`fchownat`, `utimensat`, `fsync`/`fdatasync`, `sync`, `fadvise64`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs` |
| I/O | `poll`, `ppoll`, `select`, `pselect6`, `ioctl` (`TCGETS`, `TIOCGWINSZ`, `FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, `FIOQSIZE`, `FIGETBSZ`, `SIOCATMARK`, `FIONREAD`/`SIOCINQ`, `SIOCOUTQ`) |
| Events | `eventfd2`, `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, `epoll_create`/`epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` |
| Sockets | `socket` (`AF_INET` and `AF_INET6` with a [network](#network), else `EAFNOSUPPORT`), `connect`, `getsockname`, `getpeername`, `bind`, `listen`, `accept` and `accept4` (on the guest's own [loopback](#loopback-servers); `listen` and `accept` for TCP), `socketpair` (AF_UNIX, `SOCK_STREAM`, `SOCK_SEQPACKET` and `SOCK_DGRAM`), `sendto`, `recvfrom`, `sendmsg` and `recvmsg` (passing descriptors with `SCM_RIGHTS`, credentials with `SCM_CREDENTIALS` and the sender's pidfd with `SCM_PIDFD`), `setsockopt` and `getsockopt` (`SOL_SOCKET`), `shutdown` |
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
- `fallocate` checks its arguments as Linux's `vfs_fallocate` does, in
  order (`EINVAL`, `EOPNOTSUPP`, `EBADF`, then `ESPIPE`, `EISDIR` or
  `ENODEV` for a file that is not regular, and `EFBIG`). Files then behave
  as on tmpfs: plain allocation allocates the pages of the range and grows
  the file unless `FALLOC_FL_KEEP_SIZE` is given, `FALLOC_FL_PUNCH_HOLE`
  frees the pages the range covers and sets the rest of it to zeros (also
  in an `O_APPEND` file), and the other modes give `EOPNOTSUPP`. Growing
  past `RLIMIT_FSIZE` raises `SIGXFSZ` and fails with `EFBIG`, and an
  `fallocate` past the 4 GiB the in-memory filesystem has fails with
  `ENOSPC` and allocates nothing (writes are not bounded this way; see
  [Limitations](./limitations)).
- Files of the in-memory filesystem keep their contents in 4 KiB pages, as
  tmpfs does: a write allocates the pages it touches, and the rest of a file
  is a hole that reads as zeros and takes no memory, so a file grown by
  `ftruncate` costs nothing until it is written. `st_blocks` counts the
  allocated pages, and shrinking a file frees the pages past its end.
  `lseek` with `SEEK_DATA` and `SEEK_HOLE` finds the written pages and the
  holes; a page `fallocate` allocated is a hole until it is written, and
  the end of the file is one. An offset at or past the end, or a negative
  one, gives `ENXIO`.
- Files of a mounted host directory take `SEEK_DATA`, `SEEK_HOLE` and
  `st_blocks` from the host on Linux and macOS (`st_blocks` on every Unix
  host). Where the host's filesystem cannot tell where its holes are, and on
  other hosts, the whole file is data, as Linux's `generic_file_llseek` has
  it for a filesystem without holes.
- `memfd_create` makes an unlinked in-memory file (mode 0777, or 0666 with
  `MFD_NOEXEC_SEAL`, and no links), with Linux's flag and name checks
  (`EINVAL`, `EFAULT`); `MFD_HUGETLB` gives `ENOSYS`, as from a kernel
  without hugetlbfs. Its seals, through `fcntl`'s `F_ADD_SEALS` and
  `F_GET_SEALS`, start as `F_SEAL_SEAL` unless `MFD_ALLOW_SEALING` is given
  (`F_SEAL_EXEC` with `MFD_NOEXEC_SEAL`), and restrict the file as tmpfs
  does: `F_SEAL_WRITE` and `F_SEAL_FUTURE_WRITE` refuse writes, punch holes
  and writable shared mappings, `F_SEAL_SHRINK` and `F_SEAL_GROW` the size
  (a write stops at the last page that ends within the file), and
  `F_SEAL_EXEC` the execute bits, all with `EPERM`. Memfds share a
  filesystem of their own, as Linux's internal tmpfs mount, so
  `copy_file_range` between one and a file on a mount gives `EXDEV`. Other
  files have no seals (`EINVAL`), even on the in-memory `/tmp`, where a real
  tmpfs file reports `F_SEAL_SEAL`. As on Linux, `F_SEAL_WRITE` gives `EBUSY`
  while a shared mapping that may write shows the memfd, and a shared mapping
  of a memfd sealed against writes cannot become writable (`EACCES`).
  `F_SEAL_EXEC` on an executable memfd, which seals writes too, gives `EBUSY`
  then as well, as since Linux 7.1; earlier kernels add the seals.
- `close_range` closes the open descriptors from `first` to `last`, or with
  `CLOSE_RANGE_CLOEXEC` marks them close-on-exec. `CLOSE_RANGE_UNSHARE` first
  gives the thread its own copy of a table it shares with `CLONE_FILES`
  threads, which keep their descriptors. Unknown flags and `first` above
  `last` give `EINVAL`.
- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET` and `WAKE_BITSET`.
- `futex`, `epoll` and `eventfd` are implemented inside paludarium, not with the
  host's equivalents, so they behave the same on macOS, Windows and in
  WebAssembly.
- Without a [network](#network), `socket()` returns `EAFNOSUPPORT` for
  `AF_INET` and `AF_INET6`.
- `poll` waits like `epoll_wait`: until a descriptor is ready, the timeout
  in milliseconds passes (a negative one never does) or a signal arrives
  (`EINTR`). The host's standard input is readable only with bytes to read
  or once it has ended (a closed `Guest.stdin` in WebAssembly, the end of
  the descriptor on a Unix host), as a Linux terminal or pipe is. At its end
  it is also hung up (`POLLHUP`), and `read` returns 0. `poll`, `ppoll`,
  `select`, `pselect6` and `epoll`, which can watch it, all see it so. A
  host that cannot tell (Windows) keeps it always readable. The output
  streams are always writable. A pipe's read end is readable only with unread data, and only hung up once
  its writers are gone, as Linux's `pipe_poll` reports.
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
- `recvmsg` and `recvfrom` take their flags as Linux's AF_UNIX sockets do:
  `MSG_PEEK` leaves the data, and gives copies of the descriptors it passes;
  `MSG_WAITALL` fills a stream's buffer, unless the stream ends, descriptors
  come or a signal arrives after some data, but a peek returns what it
  finds without waiting for more; `MSG_TRUNC` returns a message's
  whole length. `sendmsg` and `sendto` take `MSG_NOSIGNAL` and
  `MSG_DONTWAIT`. `MSG_OOB` on a datagram or packet socket is `EOPNOTSUPP`.
  The other flags have no effect, as on Linux.
- Sockets that only unread messages hold are closed, as Linux's garbage
  collector (`unix_gc`) closes them when a socket goes: a socket whose
  descriptor waits in its own queue, or sockets that hold each other so,
  once no descriptor holds them, with the descriptors in their queues.
  A socket held in the queue of one still open stays.
- A stream write goes in parts, as Linux's `unix_stream_sendmsg` sends it:
  each at most 36544 bytes (a page's head and 32 KiB of pages), or half the
  send buffer less 64 bytes: the doubled value `SO_SNDBUF` sets and reads
  back, so `SO_SNDBUF` 10000 makes parts of 9936 bytes. The descriptors go with the
  first part, so a read that takes them ends there, and each part signals
  the `O_ASYNC` owner. Datagram and packet messages go whole.
- A stream has out-of-band data as Linux 7.0's AF_UNIX keeps it. A `MSG_OOB`
  send makes its last byte the out-of-band byte (an empty one is
  `EOPNOTSUPP`), after the rest of its data, and an earlier byte not yet
  read becomes data. Reads stop before the mark, which `SIOCATMARK` reports,
  while `poll`, `select`'s exception set and `epoll` show `POLLPRI`.
  `recv` with `MSG_OOB` takes the byte (`EINVAL` when there is none), and
  `MSG_PEEK` leaves it; a read that reaches the mark with nothing read yet
  drops the byte and reads on, or, with `SO_OOBINLINE`, reads it as data
  (`recv` with `MSG_OOB` is then `EINVAL`). The descriptors a one-byte
  out-of-band send passes are closed, not delivered. The byte sends `SIGURG`
  to the receiving end's owner (see signal-driven I/O below).
- Signal-driven I/O, as on Linux. `fcntl`'s `F_SETOWN` gives any open file
  an owner:
  - a process or, negative, a process group;
  - with `F_SETOWN_EX`, also a single thread.

  `ESRCH` when the owner does not exist. `F_GETOWN` and `F_GETOWN_EX` read
  it back, and `F_SETSIG` picks the signal. Only pipes and sockets keep
  `O_ASYNC` (`F_SETFL` drops it on other files, and `FIOASYNC` setting it
  there is `ENOTTY`). With it, a pipe or socket
  sends its owner `SIGIO` from the kernel. With `F_SETSIG`, it sends that
  signal instead, with `si_code` (`POLL_IN`, `POLL_OUT`, `POLL_ERR`,
  `POLL_PRI` or `POLL_HUP`), `si_band`, and the descriptor `O_ASYNC` was set through as
  `si_fd`.
  - **Pipes.** Every write signals the reader as it ends, even one that
    finds the pipe full, and also before each wait. Every read signals the
    writer as it ends, with data or not. The close of either end signals
    the other.
  - **Sockets.** A send signals the peer. On a stream or packet socket, so
    do a write shutdown and the close, which hangs up; a datagram socket's
    do not. A send that found the buffer full signals once when reads leave
    three quarters of the buffer free, and so does a full datagram or packet
    socket that `poll`, `select` or `epoll_ctl` asked to take a write, or
    `epoll_wait` did, as Linux's asks only what is on its ready list: an
    interest it listed when added, after a wakeup, or after a
    level-triggered report (an edge-triggered one is not listed again). Only
    what happens while `O_ASYNC` is on counts. An out-of-band byte also sends a
    `POLL_PRI` signal.
  - **TCP and UDP sockets** ([Network](#network)), as Linux's TCP signals:
    `POLL_OUT` when a connection opens, `POLL_ERR` when it fails, `POLL_IN`
    when data arrives, and for the peer's end `POLL_IN` (`POLL_HUP` once
    this side has shut down too) and then `POLL_IN`. A send or `poll` that
    found the buffer full makes room signal `POLL_OUT` once. A DNS stub's
    answer signals `POLL_IN` when it is ready, and so does a datagram from a
    guest socket when it arrives; the loopback's ICMP answer to a connected
    UDP socket signals `POLL_ERR`. An urgent byte on the loopback signals
    `POLL_PRI` after its `SIGURG`.
  - **A waiting reader.** A stream whose read waits gets no signal for the
    data, end or hang-up that ends the wait, as Linux holds it back; of a
    send in parts, only the first. For the peer's shutdown or close Linux
    holds it back only when the reader has not run yet (it wakes the
    reader before it looks), so there it sometimes signals. A datagram or
    packet socket's reader gets it.
- `setsockopt` and `getsockopt` take the `SOL_SOCKET` options as Linux's
  `sk_setsockopt` and `sk_getsockopt` do, with their defaults and checks: an
  `int` value of fewer than 4 bytes is `EINVAL`, a value read back is cut to
  the given length, another level is `EOPNOTSUPP`, and an unknown option is
  `ENOPROTOOPT`. `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ERROR`,
  `SO_ACCEPTCONN`, `SO_PEERCRED` and `SO_PEERPIDFD` (the process that made
  the pair) can only be read. `SO_SNDBUF` and `SO_RCVBUF` are doubled and kept at Linux's
  floors and ceiling, and `SO_LINGER` takes a `struct linger`.
- `SO_PASSCRED` makes messages carry credentials, as Linux's AF_UNIX does.
  A message sent while either end has it carries the sender's process ID,
  user and group, or those `SCM_CREDENTIALS` gives. A receiver with it gets
  them in an `SCM_CREDENTIALS` message, before any descriptors; a message
  sent without them reads as process 0 with user and group 65534. Such a
  receiver's stream reads, `read` and `MSG_WAITALL` too, do not read writes
  of other credentials together. `SCM_CREDENTIALS` must hold one
  `struct ucred` (`EINVAL` otherwise), neither ID may be -1 (`EINVAL`), and
  only then is the process looked up (`ESRCH` when there is none).
- `SO_PASSPIDFD` makes messages carry credentials as `SO_PASSCRED` does,
  and a receiver with it gets a close-on-exec pidfd of the sending process
  in an `SCM_PIDFD` message, after any descriptors, as Linux 7.0 orders
  them. The pidfd is installed only when that whole message fits in the
  control buffer; otherwise the message is lost (`MSG_CTRUNC`) and no
  descriptor is taken. A message sent while neither end passed credentials
  carries none. `SO_PEERPIDFD` reads a new pidfd of the process that made
  the pair, installed even when the length given holds only part of its
  number; it can only be read (`setsockopt` is `ENOPROTOOPT`).
- `SO_RCVTIMEO` and `SO_SNDTIMEO` (and their `_NEW` forms) limit how long a
  blocking `recv`, `read`, `send` or `write` on the socket waits, as on
  Linux: past the limit it gives `EAGAIN`, or what it moved, and
  `MSG_WAITALL` stops there too. A zero `timeval` waits for ever and a
  negative one not at all; microseconds outside a second are `EDOM`. The
  value is kept in ticks of a 1000 Hz clock, so it reads back rounded up to
  a millisecond. A signal that ends such a wait gives `EINTR`, which no
  `SA_RESTART` restarts, as Linux's `sock_intr_errno`.
- `SO_RCVLOWAT` makes a blocking stream `recv` or `read` wait until it has
  that many bytes or its buffer is full, as Linux's `sock_rcvlowat` does. It
  returns less when the stream ends, its time is up, or descriptors come.
  Peeks, nonblocking reads, `poll`, and datagram and packet sockets are not
  held back. 0 counts as 1 and a negative value as `INT_MAX`.
- `SO_PEEK_OFF` sets where a `MSG_PEEK` starts, as Linux's `sk_peek_off`:
  each peek moves it on by what it read, and each read moves it back by what
  it took, not below 0. On a datagram or packet socket it passes over whole
  messages, and over an empty one already peeked at, and `MSG_TRUNC` gives
  what is left of the message from there. It takes any value; a negative one
  (by default -1) is none.
- `SO_TIMESTAMP` and `SO_TIMESTAMPNS`, and their `_NEW` forms, timestamp
  messages as Linux's AF_UNIX does. A datagram or packet socket with one
  gets each message's real time in a control message, before any
  credentials and descriptors: a `timeval` for `SO_TIMESTAMP`, a `timespec`
  for `SO_TIMESTAMPNS`, cut to the control buffer as other control messages
  are. That time is when the message was sent, if the receiver took
  timestamps then, or else when it is first read or peeked at. A stream gets
  none. `getsockopt` reads each one as set only by the form that set it, and
  turning any off keeps the `_NEW` choice until one is turned on again.
- A `MAP_SHARED` mapping of a file shows the file's page cache, as on Linux:
  every shared mapping of the file, in every process, has the same pages. A
  store to them is what `read` and the file's private mappings see, and
  `write`, `ftruncate` and punching a hole change what the mappings show; a
  store past the end of the file stays out of it. Such a mapping may write,
  and become writable with `mprotect`, only when the file is open for
  reading and writing (`EACCES` otherwise), as Linux has it.
- A `MAP_PRIVATE` mapping of a file shows the same page cache in the pages
  it has not written, so it sees later changes to the file there, and its
  first write to a page copies the page for its process alone, as on Linux;
  a `fork`ed child shares the pages neither process has written. A
  truncation drops the copies it leaves wholly past the end of the file, so
  that they read the file again when it grows, as Linux drops them.
- A page of a file mapping, private or shared, wholly past the end of the
  file raises `SIGBUS` (`BUS_ADRERR`, with the address) when it is touched,
  as on Linux; a system call given such memory fails with `EFAULT`. The end
  follows the file: a page past it becomes readable when the file grows, and
  a page read before raises `SIGBUS` once the file shrinks past it. A page
  the file only partly covers reads zeros after its end.
- `madvise`: `MADV_DONTNEED` empties private pages. Anonymous ones then read
  as zeros, and those of a file mapping read the file again, as it is then,
  as Linux faults them in from the file; this holds
  after `mremap` moves the mapping and in a `fork`ed child. The program's own
  segments are laid out as Linux lays them out: the pages that hold file
  data are a file mapping and read the executable again, also those of a
  read-only segment (code) that `mprotect` made writable and that was
  written, while the rest (`.bss`) is anonymous memory and reads as zeros.
  Shared memory keeps its own contents. `MADV_FREE` keeps the contents, as
  Linux does without memory pressure.
  The access-pattern hints are accepted and other advice gives `EINVAL`.
- `mremap` grows a mapping in place when the pages after it are free, and
  otherwise moves it with its contents under `MREMAP_MAYMOVE`; `MREMAP_FIXED`
  and `MREMAP_DONTUNMAP` work too. Shared memory stays shared with a `fork`ed
  process when it moves. A file mapping grows over more of the file, whose
  pages it reads when they are first touched, and moving a range that spans
  several mappings with `MREMAP_FIXED`, which recent Linux allows, gives
  `EFAULT`.
- `msync` checks its arguments and the range, and with `MS_SYNC` or
  `MS_ASYNC` writes the stores of shared file mappings back to their files.
- `sched_getaffinity` lets every guest thread run on each of the host's CPUs,
  so the guest sees as many CPUs as the host has (one in WebAssembly).
- `uname` reports Linux on x86_64 with the host name `paludarium`; like
  `CPUID`, it does not reveal the host. The guest runs as root (user and group
  0), and every file belongs to root until `chown` gives it another owner or
  group, which the in-memory filesystem keeps. As on Linux, `chown` takes the
  set-user-ID bit from a file that is not a directory, and the set-group-ID
  bit when the group may execute it, even when the owner and group stay.
  What is made in a set-group-ID directory takes the directory's group, and a
  new directory the bit as well. `fchmod` and `fchown` also change the mode
  and owner that `fstat` reports for a pipe made by `pipe` or `pipe2`, whose
  two ends share them, and for each end of a socket pair. Standard input,
  output and error, which the host provides, give `EPERM`.
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
  its entries can be opened relative to, `/proc/self/status` and
  `/proc/self/fd`. That file
  has Linux's fields in Linux's order (umask, IDs, threads, signal masks,
  capabilities and so on) without the memory and CPU ones, which nothing
  measures.
- `/proc/self/fd` (mode 0500) lists `.`, `..` and a link per open
  descriptor, named by its number as Linux reads one (no leading zero). Each
  link's `lstat` shows the descriptor's access in its user bits and size 64,
  and `stat` follows it to the file. `readlink` gives Linux's names: the
  file's path with `.`, `..` and symbolic links resolved (`/proc/<pid>/…`
  for this process's entries), followed by a space and `(deleted)` once
  nothing names it, `pipe:[<inode>]`, `socket:[<inode>]`,
  `anon_inode:[eventfd]`, `[eventpoll]`, `[timerfd]` or `[pidfd]` (which
  Linux 6.9 and later name from pidfs instead), and
  `/memfd:<name> (deleted)`; pipes and sockets have inode numbers of their
  own for it. Opening a link opens the file again by its path, or gives a
  memfd a new handle on the same file and seals; a pipe and the standard
  streams give the same handle for the access they have. A socket gives
  `ENXIO`, as on Linux; so do, here, a removed file, the other end of a pipe
  and the files of no type, which Linux can open again.
- `/dev` (mode 0755) holds the memory devices and the links Linux systems
  keep there, and lists only these: a file a guest makes under `/dev` can be
  opened and stat'ed but is not listed. Each entry has one inode number,
  which `stat` and `getdents` both report. `/dev` opens only for reading
  (`EISDIR`), and a device not with `O_DIRECTORY` (`ENOTDIR`). `null`, `zero`, `full`, `random` and
  `urandom` are character devices (mode 0666) with Linux's numbers in
  `st_rdev` (1:3, 1:5, 1:7, 1:8, 1:9): `null` reads nothing, `zero` and
  `full` read zeros, `random` and `urandom` read the host's random bytes,
  and `full` refuses writes with `ENOSPC` while the others take them. A
  mapping of `zero` is anonymous memory, shared with `MAP_SHARED`. `fd`,
  `stdin`, `stdout` and `stderr` are links (0777) to `/proc/self/fd` and its
  first three entries, followed by `open`, `stat` and paths through them
  (`/dev/fd/3`); `O_NOFOLLOW` on one gives `ELOOP`, also with `O_PATH`,
  where Linux opens the link itself (not supported here). Files on host
  mounts report no device number.
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
  parent exits), `PR_SET_DUMPABLE`, `PR_SET_CHILD_SUBREAPER` (not inherited
  on `fork`, kept on `execve`) and `PR_SET_NO_NEW_PRIVS` with their
  `PR_GET_*`; other options give `EINVAL`.
- When a process exits, its children go to the nearest ancestor that set
  `PR_SET_CHILD_SUBREAPER` and has not exited, or else to the first process,
  which acts as the init of a PID namespace, as Linux's
  `forget_original_parent` does. `getppid` then reports the new parent, which
  can wait for them, and their exit signal becomes `SIGCHLD`. A child that has
  already exited is reported to the new parent at once (and reaped at once if
  that parent ignores `SIGCHLD`).
- When the first process exits, every other process gets `SIGKILL` from the
  kernel, as when the init of a PID namespace exits (Linux's
  `zap_pid_ns_processes`), so the run ends with it.
- When an exit orphans a process group, so that no member keeps a parent in
  another group of the same session, and a member of the group is stopped,
  every member gets `SIGHUP` and then `SIGCONT` from the kernel (`SI_KERNEL`),
  as Linux's `kill_orphaned_pgrp` sends them. The first process's parent is
  outside the emulator and counts as such a parent while the first process
  runs. The first process itself links a group of its children as any parent
  does: Linux leaves out only the children of the global init, and the first
  process acts as the init of a PID namespace, as in a container.
- `kill` reaches a process by its PID or by the ID of one of its threads, the
  caller's process group with 0, another group with `-pgid`, and every
  process but the first one and the caller with -1, as Linux's
  `kill_something_info` does. A process that has exited counts until it is
  reaped. With no process to send to, `kill` gives `ESRCH`, even for an
  invalid signal; otherwise an invalid signal gives `EINVAL`. A signal from
  `kill` or `pidfd_send_signal` gives its sender's PID in `si_pid`, and the
  `PR_SET_PDEATHSIG` signal the PID of the parent that exited.
- `rt_sigqueueinfo` (behind `sigqueue`) sends a process the caller's siginfo
  as it is, and `rt_tgsigqueueinfo` sends it to one thread, so the signal
  carries its value; each realtime signal sent is kept. As in Linux, only a
  thread signalling itself may give a `si_code` that the kernel, `kill` or
  `tkill` would give (`EPERM`, checked before the target), and a `si_code`
  whose layout Linux does not know must leave the rest of the siginfo zero
  (`E2BIG`).
- Resource limits start at Linux's defaults (`RLIMIT_NOFILE` 1024/4096,
  `RLIMIT_STACK` 8 MiB/unlimited, ...), are inherited on `fork` and can be
  read and changed; the hard `RLIMIT_NOFILE` goes up to 1048576 (Linux's
  `fs.nr_open`), or to a lower ceiling the embedder sets. Three are enforced,
  as in Linux:
  - `RLIMIT_NOFILE`: a new descriptor past its soft limit gives `EMFILE` (and
    `open` creates nothing), `dup2`/`dup3` onto a number past it `EBADF`, and
    `F_DUPFD` from one past it `EINVAL`.
  - `RLIMIT_FSIZE`: a write to a regular file (`write`, `writev`, `pwrite` and
    `pwritev`, which with `O_APPEND` start at the end, and `copy_file_range`
    and `sendfile`) stops at the soft limit; one that
    starts at or past it, and a `truncate`/`ftruncate` or `fallocate` that
    grows the file past it, raise `SIGXFSZ` and fail with `EFBIG`.
  - `RLIMIT_CORE`: a process that a core-dumping signal (`SIGSEGV`,
    `SIGABRT`, ...) ends writes an ELF core named `core` in its working
    directory (mode 0600 less the umask, replacing an old one), as Linux's
    `do_coredump` does with the default `core_pattern`, when the soft limit
    is at least a page and `PR_SET_DUMPABLE` has not turned dumping off. The
    core has each thread's registers (`NT_PRSTATUS`), the process
    (`NT_PRPSINFO`), the fatal signal (`NT_SIGINFO`), the auxiliary vector
    and the memory. `wait` then reports `CLD_DUMPED` and the core flag. A
    core larger than the limit is cut there and still reported as dumped, as
    Linux reports a core once it has started to write it.

  Process groups and sessions are kept the same way, and `wait4` and
  `waitid` can wait for a group. The first process's session started outside
  the emulator, so `getsid` reports it as 0, as Linux reports an ID outside a
  PID namespace. `setsid` fails with `EPERM` in a process whose PID names a
  group, and makes any other process the leader of a new session and group.
  `setpgid` checks the session as Linux does: a session leader, a child in
  another session and a group in another session give `EPERM`, and a child
  that has run `execve` gives `EACCES`. A group exists while any member is
  left, an exited child not yet reaped included.
- Nice values are kept per thread, as on Linux: a new thread or process
  starts with its creator's, and `execve` keeps the caller's. `getpriority`
  reports the highest priority among the threads it finds, as `20 - nice`,
  and `setpriority` sets them all, cut to -20..19; the guest is root, so it
  may lower them too. `PRIO_PROCESS` names one thread (0 is the caller),
  `PRIO_PGRP` every thread of a process group and `PRIO_USER` every thread
  of user 0. An exited process not yet reaped is still found. No thread
  gives `ESRCH`, and an unknown `which` `EINVAL`. The values are reported
  but do not change scheduling.
- `waitid` follows Linux's checks and copy-out: its siginfo fields are zero
  when no child is reported, even on an error, and an exited child cannot be
  waited for without `WEXITED` or `WCONTINUED` (`ECHILD`). A stop and a
  continue are reported once each to a wait with `WUNTRACED` (`WSTOPPED`) or
  `WCONTINUED` (`WNOWAIT` leaves them), and `SIGCHLD` tells the parent unless
  it set `SA_NOCLDSTOP`. The siginfo of `SIGCHLD` carries the child's PID, its
  `CLD_*` code (`CLD_EXITED`, `CLD_KILLED`, `CLD_STOPPED`, `CLD_CONTINUED`), its
  status and its CPU time as `si_utime`; `si_uid` is 0, and a `SIGCHLD` sent
  while one is pending is dropped, as Linux does. A child of a process that
  ignores `SIGCHLD` or set `SA_NOCLDWAIT` is reaped as it exits, as Linux's
  `do_notify_parent` does when its exit signal is `SIGCHLD`: a wait blocks
  until such children have exited, then fails with `ECHILD`, their CPU time
  does not join the parent's children's, and with `SIGCHLD` ignored no
  `SIGCHLD` is queued, even while blocked. A zombie from before stays for a
  wait. A pidfd from `pidfd_open` becomes
  readable when its process exits (and hung up once it is reaped; an
  automatically reaped child shows both at once), so `epoll` can wait for it; `waitid(P_PIDFD)` on a nonblocking one gives `EAGAIN`.
  `pidfd_send_signal` takes no siginfo and no scope flags, and `PIDFD_THREAD`
  still names the whole process.
- Invalid pointers return `EFAULT`.

## Network

A guest has no network unless the embedder allows destinations
(`Config::with_network`, the command's `--allow-net`, or the JavaScript
`network` option, which in a browser goes through a [relay](./relay)). An allow-list entry
is a host name (`github.com`), every subdomain of one (`*.github.com`), an
IPv4 address or an IPv6 one (`[::1]`), each with a port or for every port
(`github.com:443`).

- **TCP client sockets**: `socket(AF_INET` or `AF_INET6, SOCK_STREAM)`,
  with `SOCK_NONBLOCK` and `SOCK_CLOEXEC`, connects through the host, or to
  a [server of the guest's own](#loopback-servers) on its loopback.
  - **`connect`**: a blocking one waits for the connection; a nonblocking one
    returns `EINPROGRESS`, the socket then becomes writable, and `SO_ERROR`
    gives the result once. A second call is `EALREADY`, 0 once connected,
    then `EISCONN`; a failed one gives its error, or `ECONNABORTED` once
    `SO_ERROR` took it. An IPv6 socket reaches IPv4 addresses as
    `::ffff:a.b.c.d`.
  - **A destination the policy does not allow** is `ENETUNREACH`, except
    port 53, which is the DNS stub (see below), and a loopback address
    where no guest socket listens, which is refused (`ECONNREFUSED`, or
    `EINPROGRESS` and then `SO_ERROR` for a nonblocking socket).
  - **Data**: `read`, `write`, `send`/`recv`, `sendto`/`recvfrom` and
    `sendmsg`/`recvmsg`, with `MSG_PEEK`, `MSG_WAITALL`, `MSG_DONTWAIT` and
    `MSG_NOSIGNAL`. A write goes on until all is sent. A connection the peer
    reset gives its error once, then the end of input. Sending on a socket
    that never connected, or after `shutdown(SHUT_WR)`, is `EPIPE` with
    `SIGPIPE`; receiving on one that never connected is `ENOTCONN`.
  - **Readiness**: `poll`, `select` and `epoll` see what Linux's `tcp_poll`
    reports: hung up and writable before connecting, nothing while
    connecting, `POLLIN` with data or at the end of input (with
    `POLLRDHUP`), `POLLOUT` while the send buffer has room, `POLLHUP` once
    both directions are shut, and `POLLERR` while an error waits.
  - **`shutdown`**, `getsockname` (the host's address and port once
    connected), `getpeername`, `bind`, `FIONREAD`/`SIOCINQ` and
    `SIOCOUTQ`.
  - **Options**: `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ERROR`,
    `SO_ACCEPTCONN`, `SO_KEEPALIVE`, `SO_REUSEADDR`, `SO_REUSEPORT`,
    `SO_SNDBUF`, `SO_RCVBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_LINGER`,
    `SO_PRIORITY`, `SO_BROADCAST`, `SO_OOBINLINE`, `TCP_NODELAY` (which reaches
    the host), `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_QUICKACK`,
    `TCP_USER_TIMEOUT`, `IP_TOS` and `IPV6_V6ONLY`, with Linux's defaults and
    range checks: `SO_SNDBUF` and `SO_RCVBUF` are at most the default
    `wmem_max` and `rmem_max` (212992), doubled.
- **Name resolution**: a built-in DNS stub answers the UDP queries a guest's
  resolver sends to port 53, at any address: the server of
  `/etc/resolv.conf`, or its default. It answers `A` and `AAAA` questions
  for an allowed name with the addresses the host resolves (for 60
  seconds), and `NXDOMAIN` for any other name. A connection to an address
  the stub gave for an allowed name is allowed as that name is, for 10
  minutes after it last gave it. A datagram answer holds at most 512
  bytes; one that cannot hold every address is marked truncated (`TC`),
  and the stub answers the query again over TCP: a TCP connection to port
  53, at any address, reaches the stub too, which takes queries framed
  with their two-byte lengths and answers each in turn, in full.
- **Only global addresses for names**: the stub leaves out, and a name
  rule does not reach, the loopback, private (RFC 1918 and unique local),
  link-local, shared (RFC 6598), multicast and reserved addresses (also as
  the IPv4 address in a NAT64 or 6to4 one), so that
  a name whose DNS points there (DNS rebinding) cannot reach the host's own
  machine or networks; a name left with none of its addresses is
  `NXDOMAIN`. `localhost` and its subdomains may reach the loopback. To
  reach another such address, allow the address itself (`127.0.0.1:8080`).

### Loopback servers {#loopback-servers}

A TCP socket binds, listens and accepts on the guest's own loopback as on
Linux, and a UDP socket binds and exchanges datagrams there. A connection from a guest socket to a loopback address where one
listens reaches it in the kernel, whatever the policy says, and never leaves
the guest: neither the host nor another machine reaches a guest's listener.
Where none listens, an allowed address goes to the host as before, and any
other is refused. Any network has its loopback, even one that allows nothing
(`allow: []` in JavaScript, `NetworkPolicy::new()` in Rust); the command makes
one only with an `--allow-net`.

- **`bind`** takes a loopback address (`127.0.0.0/8`, `::1`, or IPv4
  ones IPv4-mapped on an IPv6 socket) or the unspecified one, with a port
  or, for port 0, an ephemeral one from 32768–60999, with Linux's checks in
  its order: `EADDRNOTAVAIL` for another address, `EINVAL` once bound,
  `EADDRINUSE` for a port another socket holds on an address both cover (a
  listener's, a connection it accepted, a client's), unless both set
  `SO_REUSEADDR` and the other does not listen, or both set
  `SO_REUSEPORT`. An IPv6 socket on `::` holds the port for IPv4 too,
  unless `IPV6_V6ONLY`.
- **`listen`** keeps up to `backlog` + 1 connections waiting (at most
  4096, `net.core.somaxconn`); an unbound socket takes an ephemeral port on
  every address. A listener is readable while a connection waits (for
  `poll`, `select`, `epoll`, and `POLL_IN` with `O_ASYNC`), shows
  `SO_ACCEPTCONN`, is `EINVAL` to `FIONREAD`, `EISCONN` to `connect`, and
  stops listening on `shutdown(SHUT_RD)` or an `AF_UNSPEC` `connect`.
- **`connect`** to a listener returns once its queue has the connection,
  before any `accept`; a nonblocking one is `EINPROGRESS`, as on Linux.
  One that finds the queue full is dropped, and the client tries again 1,
  2, 3, 4, 5, 7, 11, 19, 35 and 67 seconds after it began, as Linux with
  its default `tcp_syn_linear_timeouts` (4) does: the try finds whatever
  listens there then, is dropped again while the queue is still full, is
  refused (`ECONNREFUSED`) where none listens, and at 131 seconds the
  client gives up with `ETIMEDOUT`. A blocking `connect` waits at most
  `SO_SNDTIMEO`, and is then `EINPROGRESS`, or `EALREADY` once one was in
  progress.
- **`accept`** and **`accept4`** (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`) give
  the first connection waiting and its peer's address; they wait unless
  the listener is nonblocking, until `SO_RCVTIMEO` (`EAGAIN`). The
  accepted socket takes the listener's options.
- **`SO_REUSEPORT`**: listeners that share a port with it, of one family
  and on one address, share its connections, as Linux's
  `reuseport_select_sock`: a hash of both ends' addresses and ports picks
  the one each connection reaches, though the hash is not Linux's (whose
  secret changes at each boot). A listener that stops or closes takes no
  more. UDP sockets sharing a port likewise share its datagrams.
- **`TIME_WAIT`**: the side that closes a connection first, a client or
  an accepted connection, holds its port as Linux does: while the bytes it
  sent are still on their way (`FIN_WAIT1`), then up to 60 seconds from its
  `close`, or from when those bytes have gone if later, for the other
  side's end (`FIN_WAIT2`, `tcp_fin_timeout`), and 60 seconds from that end
  (`TCP_TIMEWAIT_LEN`). A `bind` there is `EADDRINUSE`, also with
  `SO_REUSEADDR` unless the closed socket had it too (an accepted one has
  its listener's). The side that closes second holds nothing, and a reset
  (below), also one answering a send to the closed side, ends the hold. A
  socket that ended first by `shutdown` and stays open gives up a port it
  took itself 60 seconds after the other side's end, as Linux's `tcp_done`
  does, and keeps one the guest bound (`SOCK_BINDPORT_LOCK`; an accepted
  one has its listener's) until it closes.
- **Resets**, as on Linux: closing a socket with unread input or a zero
  `SO_LINGER` time, disconnecting with `AF_UNSPEC`, or closing a listener
  with connections it has not handed out resets the peer (`ECONNRESET`
  after the bytes it holds); bytes sent to a peer that has closed are
  answered with a reset, so the next send is `EPIPE`.
- **Urgent data**, as Linux's TCP keeps it: the last byte of a `MSG_OOB`
  send is urgent and reaches the peer with the bytes before it. Reads
  stop before its mark, which `SIOCATMARK` reports and `FIONREAD` counts
  up to, and `MSG_WAITALL` stops there too; `poll`, `select`'s
  exceptional set and `epoll` show `POLLPRI` while the byte waits, and a
  reader at the mark is readable only with a byte past it. `recv` with
  `MSG_OOB` takes the byte once (`EINVAL` when none waits, `MSG_TRUNC`
  with no room, `ENOTCONN` on a listener). A read that starts at the mark
  passes over the byte, which is then gone if `MSG_OOB` had not taken it,
  and a later urgent byte makes an earlier one ordinary data. With
  `SO_OOBINLINE` the byte is read as data, reads still stopping before it,
  and `MSG_OOB` is `EINVAL`. Each urgent byte sends the receiving socket's
  owner `SIGURG`. UDP ignores `MSG_OOB` on a receive, and a send with it is
  `EOPNOTSUPP`.
- **UDP** binds as TCP does, on ports of its own, where `SO_REUSEADDR` on
  both shares a port. A datagram to a loopback address reaches the guest
  socket bound there, as Linux's `compute_score` picks it: a connected one
  only from its peer, one bound to that address or connected, or of IPv4,
  first, and among equals the last to bind, or of those sharing the port
  with `SO_REUSEPORT` the one the same hash picks, past those connected; one
  that connects from another address leaves them. A socket that sends unbound
  takes an ephemeral port on every address; one that connects takes one
  first, even when the connect then fails (`ENETUNREACH` for an IPv4 peer
  of an `IPV6_V6ONLY` socket), on the loopback's source address for a
  loopback peer, on every address for another, and receives only from its
  peer, and
  `AF_UNSPEC` disconnects it, keeping only the port and address the guest
  bound itself. A datagram holds up to 65507 bytes over IPv4 and 65527 over
  IPv6 (`EMSGSIZE`), may be empty, and is cut to the reader's buffer
  (`MSG_TRUNC`); `FIONREAD` gives the first one's length. Each takes of the
  receive buffer what x86-64 Linux 7.0 counts as its `sk_buff`'s
  `truesize`, and one that would take it past `SO_RCVBUF` while another
  waits is dropped, as `__udp_enqueue_schedule_skb` drops it; an empty
  buffer takes one of any size. Where no socket takes it, the loopback's
  ICMP answer reaches a socket connected there: its next send or receive
  is `ECONNREFUSED`, once, as `SO_ERROR` and `POLLERR` show. A datagram to
  port 53 that no guest socket takes goes to the DNS stub, as before.
- **UDP `shutdown`** marks the socket, connected or not (one that is not is
  `ENOTCONN` all the same, as Linux's `inet_shutdown` gives it). Shut for
  reading, a receive that would wait ends at once with 0, while datagrams
  still come and are read first, and a nonblocking one is `EAGAIN`; shut for
  sending, a send is `EPIPE`, with no `SIGPIPE`. `poll` then shows `POLLIN`
  and `POLLRDHUP`, and `POLLHUP` once both ways are shut.

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
  `sendmsg`, `recvmsg`, `ppoll`, `select`, `pselect6`, `poll` with no timeout
  and a `futex` wait with none. `nanosleep`, a relative `clock_nanosleep`,
  `poll` with a timeout and a timed `futex` wait resume through
  `restart_syscall` with the deadline they had (the `futex` wait checks its word
  again first, `EAGAIN` once it changed), and
  an absolute `clock_nanosleep` runs again; a handler ends the restart, so they
  give `EINTR` then. A handler set with `SA_RESTART` runs the calls that a
  stop runs again (from `read` to the `futex` wait with no timeout) again when
  it returns, as on Linux, except `pause`,
  `rt_sigsuspend`, `poll`, `ppoll`, `select`, `pselect6` and a socket call
  whose wait `SO_RCVTIMEO` or `SO_SNDTIMEO` limits, which give `EINTR`.
  `epoll_wait` and `rt_sigtimedwait` give `EINTR`, as on
  Linux. `rt_sigsuspend` waits with its mask in place of the signal mask until a
  handler has run, which runs with that mask; the original mask is back after
  it.
- A `sigaction` that makes a signal ignored (`SIG_IGN`, or `SIG_DFL` for
  `SIGCHLD`, `SIGCONT`, `SIGURG` and `SIGWINCH`, which are ignored by
  default) discards its pending instances in the process and in every thread,
  as Linux's `do_sigaction` does. A blocked signal sent after that stays
  pending.

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
- **aube**: a Node.js package manager written in Rust (v2.8.3). `--version`,
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
