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
- **SSE**: every SSE and SSE2 instruction, except those that use MMX registers
  (a test runs each encoding), the `MFENCE`/`LFENCE`/`SFENCE` fences among them.
  Of the later sets, the instructions real programs (probe, aube and pitchfork)
  use, and cryptographic instructions such as AES, PCLMUL and SHA. Floating
  point is computed in software.
- Instructions are decoded with [iced-x86](https://github.com/icedland/iced).
- `CPUID` does not reveal the host's values. It names AMD as the vendor, because
  glibc reads the features only for a vendor it knows, and reports the features
  every x86-64 CPU has, because glibc requires them. Of those, the FPU and MMX
  are not implemented; it advertises no other feature that is not. The name
  changes nothing else: where vendors' CPUs differ, as in the flags after a
  `REP` faults, the virtual CPU keeps its own behaviour.
- `RDTSC` and `RDTSCP` read a counter of the virtual CPU, which moves on with
  each read rather than with time. Every guest in the host process shares that
  counter, so its values depend on what else has read it. `RDSSP` does nothing,
  as there are no shadow stacks. `FXSAVE` and `FXRSTOR` keep the x87 state,
  MXCSR and the XMM registers.
- x87 instructions move values, convert them, compare them and keep the unit's
  control and status words, environment and stack, in every rounding mode. They
  add, subtract, multiply, divide and take square roots in every rounding mode
  and precision, and do `FPREM`, `FPREM1`, `FSCALE`, `FRNDINT`, `FXTRACT`, the
  `FCOM` family, the `FLD` constants and `FCMOV`. The transcendental
  instructions and packed decimals are not implemented yet
  ([Limitations](./limitations)). A signal handler starts with the x87 and SSE
  state as after a reset, as on Linux.
- AVX, AVX-512 and MMX are out of scope: `CPUID` reports MMX because glibc
  requires it, but its instructions stop with `SIGILL`.

When a guest reaches an instruction it cannot run, it gets `SIGILL`, as on real
Linux. Page faults raise `SIGSEGV`, and integer division by zero `SIGFPE`.

## System calls

Only implemented system calls are handled, through an explicit table.
Everything else returns `ENOSYS`; nothing is passed to the host. The table
below names every implemented call, which `lint:all` checks against the
kernel.

| Group | System calls |
|---|---|
| Processes and threads | `clone`, `clone3`, `fork`, `vfork`, `execve`, `wait4`, `waitid`, `pidfd_open`, `pidfd_send_signal`, `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `set_tid_address`, `futex`, `set_robust_list`, `get_robust_list`, `sched_setaffinity`/`sched_getaffinity`, `sched_yield`, `setpgid`/`getpgid`/`getpgrp`, `setsid`/`getsid`, `getpriority`/`setpriority`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files private or shared), `munmap`, `mremap`, `mprotect`, `madvise`, `mincore`, `mlock`/`mlock2`/`munlock`/`mlockall`/`munlockall`, `msync`, `brk`, `arch_prctl` |
| System information | `uname`, `sysinfo`, `getrusage`, `times` |
| Credentials | `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`/`getresgid`, `setuid`/`setgid`, `setreuid`/`setregid`, `setresuid`/`setresgid`, `setfsuid`/`setfsgid`, `getgroups`/`setgroups`, `capget`/`capset` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `setitimer`, `rt_sigtimedwait`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete` |
| Files | `open`/`openat`/`creat`, `read`, `write`, `readv`/`writev`, `pread64`/`pwrite64`, `preadv`/`pwritev`, `copy_file_range`, `sendfile`, `setxattr`/`lsetxattr`/`fsetxattr`, `getxattr`/`lgetxattr`/`fgetxattr`, `listxattr`/`llistxattr`/`flistxattr`, `removexattr`/`lremovexattr`/`fremovexattr`, `close`, `close_range`, `lseek`, `stat`/`fstat`/`lstat`/`newfstatat`, `statx`, `getdents64`, `mkdir`/`mkdirat`, `mknod`/`mknodat`, `rmdir`, `unlink`/`unlinkat`, `rename`/`renameat`, `link`/`linkat`, `symlink`/`symlinkat`, `readlink`/`readlinkat`, `truncate`/`ftruncate`, `fallocate`, `memfd_create`, `flock`, `fcntl`, `dup`/`dup2`/`dup3`, `pipe`/`pipe2`, `chdir`/`fchdir`, `getcwd`, `umask`, `chmod`/`fchmod`/`fchmodat`/`fchmodat2`, `chown`/`fchown`/`lchown`/`fchownat`, `utimensat`, `fsync`/`fdatasync`, `sync`, `fadvise64`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs` |
| I/O | `poll`, `ppoll`, `select`, `pselect6`, `ioctl` (`TCGETS`, `TIOCGWINSZ`, `FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, `FIOQSIZE`, `FIGETBSZ`, `SIOCATMARK`, `FIONREAD`/`SIOCINQ`, `SIOCOUTQ`, and the pseudo-terminals' requests below) |
| Events | `eventfd2`, `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, `epoll_create`/`epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` |
| Sockets | `socket` (`AF_UNIX` streams, packet and datagram sockets; `AF_INET` and `AF_INET6` with a [network](#network), else `EAFNOSUPPORT`), `connect`, `getsockname`, `getpeername`, `bind`, `listen`, `accept` and `accept4` (AF_UNIX streams and packet sockets, and on the guest's own [loopback](#loopback-servers) TCP), `socketpair` (AF_UNIX, `SOCK_STREAM`, `SOCK_SEQPACKET` and `SOCK_DGRAM`), `sendto`, `recvfrom`, `sendmsg` and `recvmsg` (passing descriptors with `SCM_RIGHTS`, credentials with `SCM_CREDENTIALS` and the sender's pidfd with `SCM_PIDFD`), `setsockopt` and `getsockopt` (`SOL_SOCKET`), `shutdown` |
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
- `getdents64` goes on from what it has returned, so unlinking those entries
  skips nothing. `lseek` to a `d_off` leads to the same entry while the
  directory is unchanged, and `dup` and `fork` share the place.
- Extended attributes stay with a file in memory, through hard links and
  renames and after its last name is gone. As on Linux, `user.*` is for regular
  files and directories (on others, reading gives `ENODATA` and writing `EPERM`),
  `trusted.*` shows only with `CAP_SYS_ADMIN`, and `security.*` needs it to
  change. A name is from 1 to 255 bytes (`ERANGE`), a value at most 64 KiB
  (`E2BIG`), and any other namespace gives `EOPNOTSUPP`.
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
- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET` and `WAKE_BITSET`. A word is
  told apart as Linux's `get_futex_key` does: in a shared mapping (shared
  anonymous memory or a file's), a shared operation names the memory and the
  offset in it, so a wake reaches a waiter in any process that maps it,
  wherever it maps it. Any other word, and a private operation, names this
  process's address space and the address, so a private wake never reaches
  another process. Process-shared mutexes and semaphores (Python's
  `multiprocessing`) work this way, as does the wake of a robust futex whose
  owner ends.
- `set_robust_list` and `get_robust_list` keep each thread's list of robust
  futexes, which glibc's and musl's robust mutexes need. When a thread ends or
  calls `execve`, the list is walked as Linux's `exit_robust_list` walks it:
  a word the thread owned is marked `FUTEX_OWNER_DIED`, with a shared wake if
  it has `FUTEX_WAITERS`, the walk stops at what it cannot use and after 2048
  entries, and a core dump comes first. A new thread or process has no list.
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
  it is also hung up (`POLLHUP`), and `read` returns 0. A `read` with
  nothing to read waits in the kernel, so a signal ends it with `EINTR`,
  or restarts it with `SA_RESTART`, as on Linux. `poll`, `ppoll`,
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
- `fcntl`'s `F_GETFL` gives the status flags as Linux keeps them: the open
  flags less `O_CLOEXEC`, `O_CREAT`, `O_EXCL`, `O_NOCTTY` and `O_TRUNC`,
  with `O_LARGEFILE` for a file opened by a path or a memfd; an `O_PATH`
  file keeps only `O_DIRECTORY`, `O_NOFOLLOW` and `O_PATH`. Pipes, sockets
  and the kernel's own files have no `O_LARGEFILE`, unless opened by a path
  (a link in `/proc/self/fd`, `/dev/stdout`).
- `fcntl`'s byte-range locks, as Linux's `fs/locks.c` keeps them: record
  locks (`F_SETLK`, `F_SETLKW`, `F_GETLK`), which a process owns, and open
  file description locks (`F_OFD_SETLK`, `F_OFD_SETLKW`, `F_OFD_GETLK`),
  which a description owns, conflicting with each other. A lock on a range
  replaces, splits or merges the owner's own there, as `posix_lock_inode`
  does, and `F_GETLK` reports the first conflicting lock with its owner's PID
  (-1 for a description's), or `F_UNLCK`. The arguments are checked in the
  order of `fcntl_getlk` and `fcntl_setlk` (the whence, the range with
  `EINVAL` or `EOVERFLOW`, the type, `EBADF` for a type the descriptor's
  access does not allow, and an OFD lock's `l_pid`). A process's record locks
  on a file go when it closes any descriptor of the file or exits, not with
  `fork` or `execve`; a description's go when its last descriptor closes.
  `F_SETLKW` waits until the range is free, `EDEADLK` when the record locks
  of processes waiting for each other (up to 10) would close a cycle. The
  locks are the guest's own: a program on the host does not see them, nor
  they its.
- A pipe holds 64 KiB, as on Linux, and `fcntl`'s `F_SETPIPE_SZ` and
  `F_GETPIPE_SZ` resize and report it like `pipe_set_size`: a power of two of
  at least a page, `EBUSY` below the unread data and `EINVAL` past 2³¹.
- A `SOCK_DGRAM` pair keeps message boundaries like `SOCK_SEQPACKET`, but has
  no end of file: when the peer closes, reads wait and the next send gets
  `ECONNREFUSED`, then `ENOTCONN`; that send drops what the end has not
  read, as below. Only `SOCK_STREAM` raises `SIGPIPE` with
  `EPIPE`, as on Linux.
- `socket(AF_UNIX)` makes a `SOCK_STREAM` or `SOCK_SEQPACKET` socket that
  binds to a name in the abstract namespace (a `sun_path` starting with 0),
  or with only the family to a free one of five hex digits, listens and
  accepts, or connects to a listener of its type, as Linux's `af_unix.c`
  does: `EADDRINUSE` for a name in use, `ECONNREFUSED` where none listens,
  `EAGAIN` for a nonblocking connect to a full queue (a blocking one waits,
  at most `SO_SNDTIMEO`), `EINVAL` to `listen` with no name or once
  connected and to `accept` unless listening, `EISCONN` to connect again. Unconnected, it
  is writable and hung up to `poll` and sends nothing (`ENOTCONN`); a
  listener is readable while a connection waits, and shows
  `SO_ACCEPTCONN`. `getsockname` and `getpeername` give the names, and an
  accepted socket has the listener's. A connection not yet accepted already
  carries data; closing the listener resets it, so the client's next read
  is `ECONNRESET`. Connected, it is a socket pair end in all else. Names
  are kept per socket type, as Linux hashes them with the type, so a stream
  and a datagram socket may bind the same one.
- An AF_UNIX socket also binds to a path, as Linux's `unix_bind_bsd`: `bind`
  makes a socket file there (`S_IFSOCK`, mode 0777 less the umask), also
  in a directory mounted from a Linux host ([Limitations](./limitations)), so a
  path that exists, a dangling symbolic link too, is `EADDRINUSE`, and
  `getsockname` gives the path ended with a 0. A connect or send to a path
  finds the socket by its file's inode, as `unix_find_bsd`: through
  symbolic links and after a `rename`, not once the file is unlinked;
  `ECONNREFUSED` for a file that is no socket or whose socket has closed
  (the file stays), `EPROTOTYPE` for a socket of another type. A socket
  file opens nothing (`ENXIO`), and `readdir` gives it `DT_SOCK`.
- `socket(AF_UNIX, SOCK_DGRAM)` (and `SOCK_RAW`, which Linux makes one)
  makes a datagram socket that binds as above, and sends with `sendto` to
  the socket of a name, or to the one it connected to, as Linux's
  `unix_dgram_*` do: `ECONNREFUSED` where none has the name, `ENOTCONN`
  with no address unconnected, `EPERM` to a socket connected to another
  (even one gone), `EPIPE` once its writing or the receiver's reading is
  shut down. A receiver's queue is full past `net.unix.max_dgram_qlen`'s
  10 messages, unless it is the sender's own or connected to the sender:
  a nonblocking send is then `EAGAIN`, a blocking one waits, at most
  `SO_SNDTIMEO`, and the connected sender is not writable to `poll`.
  Each datagram that waits takes of its sender's send buffer what x86-64
  Linux 7.0 counts as its `sk_buff`'s `truesize` (`sk_wmem_alloc`), until
  it is read, dropped or its receiver goes; `SIOCOUTQ` gives that. While
  it takes the whole of `SO_SNDBUF`, a send is `EAGAIN` or waits. The
  sender is writable to `poll`, and a waiting send wakes, only once a
  quarter of it is free (`unix_writable`), or the wait's `SO_SNDTIMEO`
  is up, when the send looks once more; a datagram longer than `SO_SNDBUF`
  less 32 bytes is `EMSGSIZE`. The receiver's unread bytes bound nothing.
  A packet socket's messages (`SOCK_SEQPACKET`) take and wait the same,
  as Linux's `unix_seqpacket_sendmsg` sends them through
  `unix_dgram_sendmsg`: the size is checked before a shutdown (`EPIPE`).
  `connect` to an `AF_UNSPEC` address disconnects; a socket connects again
  at will. When the socket it is connected to goes, its next send is
  `ECONNREFUSED`, then `ENOTCONN`. Disconnecting, by connecting to another
  socket or `AF_UNSPEC` or by that refused send, drops the datagrams the
  socket has not read, closing the descriptors they pass, as Linux's
  `unix_dgram_disconnected`; if there were any and the old peer is
  connected back, the old peer gets `ECONNRESET`, which its next read
  (before what it has queued), send or `SO_ERROR` returns once, and
  `poll` shows as `POLLERR` until then. A socket that passes credentials is
  autobound as it connects or sends. `listen` and `accept` are
  `EOPNOTSUPP`, and `SO_PEERCRED` names no process (process 0, IDs -1),
  connected or not, as `unix_dgram_connect` records none, and
  `SO_PEERPIDFD` is `ENODATA`; a datagram socket pair's ends name their
  maker, as every pair's do. A socket pair's datagram end sends to names
  too.
- `socketpair(AF_UNIX)` makes two sockets as Linux's `unix_socketpair` does:
  unnamed and connected to each other, so each is a socket of its type in
  all else. Either may `bind`, as above, and its peer's `getpeername` and
  what it sends then give that name. A stream or packet socket of a pair
  connects no more (`EISCONN` once a listener has the name), and a
  datagram one connects elsewhere or to `AF_UNSPEC` as any datagram socket
  does, disconnecting from the other end as above.
- `recvmsg` and `recvfrom` take their flags as Linux's AF_UNIX sockets do:
  `MSG_PEEK` leaves the data, and gives copies of the descriptors it passes;
  `MSG_WAITALL` fills a stream's buffer, unless the stream ends, descriptors
  come or a signal arrives after some data, but a peek returns what it
  finds without waiting for more; `MSG_TRUNC` returns a message's
  whole length. `sendmsg` and `sendto` take `MSG_NOSIGNAL` and
  `MSG_DONTWAIT`. `MSG_OOB` on a datagram or packet socket is `EOPNOTSUPP`.
  The other flags have no effect, as on Linux. Their address is the name
  the sending socket has as it is read, even once that socket has gone, as
  Linux's `unix_copy_addr`, cut to the room given but with its whole
  length; an unnamed socket's has length 0.
- Sockets that only unread messages hold are closed, as Linux's garbage
  collector (`unix_gc`) closes them when a socket goes: a socket whose
  descriptor waits in its own queue, or sockets that hold each other so,
  once no descriptor holds them, with the descriptors in their queues.
  A socket held in the queue of one still open stays. What a listener's
  connections not yet accepted hold counts as the listener's, as Linux's
  `unix_edge_successor` counts it: a listener only they hold is garbage,
  and goes with what they hold, which resets their clients.
- A stream write goes in parts, as Linux's `unix_stream_sendmsg` sends it:
  each at most 36544 bytes (a page's head and 32 KiB of pages), or half the
  send buffer less 64 bytes: the doubled value `SO_SNDBUF` sets and reads
  back, so `SO_SNDBUF` 10000 makes parts of 9936 bytes. The descriptors go with the
  first part, so a read that takes them ends there, and each part signals
  the `O_ASYNC` owner. Datagram and packet messages go whole. Each part,
  and an out-of-band byte, takes of the sender's send buffer what x86-64
  Linux 7.0 counts as its `truesize` (a head of up to 3776 bytes, the rest
  in whole pages) until it is read whole, as a datagram does: parts go
  while the buffer has room, so a nonblocking send may send only some of
  them, and a full sender waits, is writable to `poll` and gives
  `SIOCOUTQ` as a datagram socket does. The peer's unread bytes bound
  nothing.
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
  it back, and `F_SETSIG` picks the signal. Only pipes and sockets, and the
  host's standard streams when they are a pipe, a socket or a terminal, keep
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
  - **The host's standard streams**, which change outside the emulator:
    while `O_ASYNC` is on, a thread looks at the stream every 10 ms and
    signals each time it becomes ready where it was not, or after a read or
    write told the guest `EAGAIN`, however soon: standard input `POLL_IN` for
    input, or its end, and standard output and standard error `POLL_OUT` for
    room after being full. Otherwise a stream full or empty for less time than
    that can go unseen, and no signal comes. `F_SETFL` keeps the standard
    streams' own status flags
    (`O_NONBLOCK`, `O_APPEND`, …), which never reach the host's descriptor;
    with `O_NONBLOCK`, a read of standard input that finds nothing is
    `EAGAIN`, and so is a write to standard output or standard error that
    the host has no room for.
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
  `SO_ACCEPTCONN`, `SO_PEERCRED` and `SO_PEERPIDFD` (the peer process,
  below) can only be read. `SO_SNDBUF` and `SO_RCVBUF` are doubled and kept at Linux's
  floors and ceiling, and `SO_LINGER` takes a `struct linger`.
- `SO_PASSCRED` makes messages carry credentials, as Linux's AF_UNIX does.
  A message sent while either end has it carries the sender's process ID and
  real user and group, or those `SCM_CREDENTIALS` gives. A receiver with it gets
  them in an `SCM_CREDENTIALS` message, before any descriptors; a message
  sent without them reads as process 0 with user and group 65534. Such a
  receiver's stream reads, `read` and `MSG_WAITALL` too, do not read writes
  of other credentials together. `SCM_CREDENTIALS` must hold one
  `struct ucred` (`EINVAL` otherwise), neither ID may be -1 (`EINVAL`). It
  names the caller's own process unless the caller has `CAP_SYS_ADMIN`, one of
  its real, effective and saved user IDs unless it has `CAP_SETUID`, and one of
  its group IDs unless it has `CAP_SETGID` (`EPERM`), and only then is the
  process looked up (`ESRCH` when there is none).
- `SO_PASSPIDFD` makes messages carry credentials as `SO_PASSCRED` does,
  and a receiver with it gets a close-on-exec pidfd of the sending process
  in an `SCM_PIDFD` message, after any descriptors, as Linux 7.0 orders
  them. The pidfd is installed only when that whole message fits in the
  control buffer; otherwise the message is lost (`MSG_CTRUNC`) and no
  descriptor is taken. A message sent while neither end passed credentials
  carries none. `SO_PEERCRED` and `SO_PEERPIDFD` name the peer process as
  Linux records it, and `SO_PEERCRED` the effective IDs it had then: for a
  pair, the process that made it, on both ends;
  for a socket from `socket()`, none (process 0, IDs -1, and
  `SO_PEERPIDFD` `ENODATA`) until it listens or connects; on a listener,
  the process that called `listen` (`init_peercred`); on an accepted
  socket, the connecting process; and on the client, the listener's
  (`copy_peercred`). `SO_PEERPIDFD` reads a new pidfd of that process,
  installed even when the length given holds only part of its number; it
  can only be read (`setsockopt` is `ENOPROTOOPT`).
- `SO_PASSSEC` is set and read back as on Linux, and with it a receiver
  with no control buffer finds `MSG_CTRUNC`; it gets no `SCM_SECURITY`
  message, as on a Linux whose security module gives AF_UNIX no sender's
  context (none, or AppArmor).
- `SO_PASSRIGHTS` is on for a new AF_UNIX socket, as on Linux 6.16 and
  later. Set to 0, the socket takes no descriptors: a send that passes some
  to it is `EPERM`, after a shutdown's `EPIPE` and before a full queue's
  `EAGAIN`, while a stream send of no bytes passes nothing and gives 0.
  Descriptors already waiting are still read.
- A socket a listener accepts takes the listener's `SO_PASSCRED`,
  `SO_PASSPIDFD`, `SO_PASSSEC` and `SO_PASSRIGHTS` as they were when the
  client connected. An inet socket refuses these four options both ways
  with `EOPNOTSUPP`, as Linux takes them only on AF_UNIX.
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
- `SO_TIMESTAMPING` and its `_NEW` form take the flags Linux knows, refusing
  as Linux's `sock_set_timestamping` does (`EINVAL` for an unknown flag,
  `SOF_TIMESTAMPING_OPT_ID_TCP` without `OPT_ID` or `OPT_STATS` without
  `OPT_TSONLY`, `EOPNOTSUPP` for a PTP clock, which binds only to a socket
  bound to a device), and `getsockopt` gives them back with no clock, the
  `_NEW` form only when set through it. Setting either chooses the `_NEW`
  form or not for `SO_TIMESTAMP` too. As on Linux's AF_UNIX, they add to
  what `SO_TIMESTAMP` or its kin stamp and stamp nothing alone: a
  `SCM_TIMESTAMPING` after that control message, whose first `timespec` is
  the same time when the flags report software stamps and do not filter
  received ones out; no hardware stamps a message between local sockets.
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
- `mincore` says which pages are in memory: a private page once it was read or
  written, shared anonymous memory once it was, and a file's page when it lies
  within the file. It writes the bytes up to the first page that is not mapped,
  which is `ENOMEM`, as Linux does.
- `mlock`, `mlock2` and `munlock` check their range as Linux does: the length
  rounds up to pages, a range past the end of addresses is `EINVAL`, and one
  with a page that is not mapped is `ENOMEM`. `mlock` and `mlock2` without
  `MLOCK_ONFAULT` also give `ENOMEM` for a page with `PROT_NONE`. Unknown flags
  of `mlock2` and `mlockall` give `EINVAL`. Nothing is ever swapped out, so
  memory stays in place without more being done.
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
  `sched_setaffinity` keeps a mask for a thread of the process, as Linux
  reads it: up to a CPU mask's size (a shorter one counts the rest as clear),
  only the host's CPUs, and `EINVAL` if none is left. `sched_getaffinity`
  then gives that mask, and new threads and processes inherit it, but the
  host still runs the thread on any of its CPUs. Both find a thread of
  another process too, as root may, and give `ESRCH` when no live thread
  has the ID.
- `uname` reports Linux on x86_64 with the host name `paludarium`; like
  `CPUID`, it does not reveal the host. The guest starts as root (user and
  group 0, with every capability). Each thread has its own credentials, as
  on Linux: the real, effective, saved and filesystem user and group IDs,
  the supplementary groups and the permitted, effective and inheritable
  capabilities.
  `capget` reads any thread's capabilities in all three header versions, and
  `capset` changes the calling thread's, within what it holds by Linux's rules.
  The `set*id` calls and `setgroups` change them by Linux's rules: an ID
  goes to one of the thread's own, or anywhere with `CAP_SETUID` or
  `CAP_SETGID`; leaving root in every user ID drops the capabilities (but
  for the permitted ones with `PR_SET_KEEPCAPS`), the effective ID leaving
  root drops the effective ones and coming back raises them, and the
  filesystem ID does the same for the filesystem capabilities. A change of
  an effective or filesystem ID makes the process undumpable
  (`fs.suid_dumpable` is 0) and clears its parent-death signal. `execve`
  of a set-user-ID program makes its owner the effective user ID, and of a
  set-group-ID program its group the effective group ID when the group may
  execute it. With `PR_SET_NO_NEW_PRIVS` it ignores those bits, and an exec
  that would still change the effective IDs (to an effective group the
  thread is not in by its filesystem or a supplementary group) or gain
  capabilities takes the real IDs as effective and keeps no more
  capabilities than the thread had. `execve` then makes the saved and
  filesystem IDs the effective ones, gives root (by its real or effective
  ID) every capability and anyone else none, and clears `PR_SET_KEEPCAPS`.
  It sets `AT_SECURE` when it changes the effective IDs, when they differ
  from the real ones before it, or when a user other than root keeps
  capabilities, and such a secure exec
  clears the parent-death signal and lowers the `RLIMIT_STACK` soft limit
  to 8 MiB. The process is dumpable again after `execve` unless its
  effective IDs differed from its real ones before it, it may not read the
  program, or the exec changed an effective or filesystem ID, which also
  clears its parent-death signal. The auxiliary vector and
  `/proc/self/status` show the IDs and capabilities. The files given at the
  start belong to root, and a file, directory, symbolic link or memfd a
  thread makes belongs to its filesystem user and group IDs, until `chown`
  gives it another owner or group, which the in-memory filesystem keeps.
- Files are checked as Linux checks them (`generic_permission`): the
  owner's permission bits apply to the owner, the group's to a member of the
  file's group (by the filesystem group ID or a supplementary group) and
  the others' to anyone else; `CAP_DAC_READ_SEARCH` reads any file and
  searches any directory, and `CAP_DAC_OVERRIDE` allows everything else
  but executing a file no one may execute. A path needs search permission
  on each directory a name is looked up in, from where the walk starts
  (the root, the working directory or `dirfd`, whose own ancestors are not
  checked) and through each symbolic link it follows. `open` needs reading
  or writing as its access mode and `O_TRUNC` ask, and a new file writing
  and searching its directory, as `mkdir`, `symlink` and the new name of
  `link` and `rename` do; removing a name (`unlink`, `rmdir`, `rename`)
  needs the same and, in a sticky directory, owning the file or the
  directory or `CAP_FOWNER` (`EPERM`), and a directory that moves to
  another one needs writing itself. `chmod` and setting a time need the
  owner or `CAP_FOWNER` (`EPERM`), and `chmod` drops the set-group-ID bit
  for a thread outside the file's group without `CAP_FSETID`; setting both
  times to now is also allowed to a thread that may write the file
  (`EACCES`). `chown` gives another owner only with `CAP_CHOWN`, and the
  owner may give a group it is a member of. `truncate` needs writing and
  `chdir` searching. `access` checks with the real IDs (root's with its
  permitted capabilities), and with `AT_EACCESS` the filesystem ones.
  `execve` needs a regular file the thread may execute (else `EACCES`, also
  for a directory and for root when no execute bit is set), and a program
  it may not read runs undumpable. A program with a `PT_INTERP` starts in that
  interpreter, as Linux's `load_elf_binary` does, with `AT_BASE` and `AT_ENTRY`
  to find the program. The interpreter needs the same permissions and counts the
  same for dumping, its set-ID bits do not count, and a file that is no x86-64
  program is `ELIBBAD`. A file that starts with `#!` runs its
  interpreter as Linux's `load_script` does: the first line, within 255 bytes,
  names it and may give it one argument, its arguments are that name, that
  argument and the script's path in place of `argv[0]`, and the interpreter's
  set-ID bits count, not the script's. An interpreter may be a script too, up
  to 5 levels below the first script (`ELOOP` past that). As on Linux, `chown`
  takes the set-user-ID bit from a file that is not a directory, and the set-group-ID
  bit when the group may execute it or the caller is neither in its group
  nor holds `CAP_FSETID`, even when the owner and group stay. A write or a
  truncation by a thread without `CAP_FSETID` takes the same from a regular
  file, but a set-group-ID bit without group execution stays for a member of
  its group. An `AF_UNIX` socket file needs what any new file needs and takes
  the caller's filesystem IDs, and `connect` or `sendto` to one needs permission
  to write the file the path names, before it looks at the file's type.
  What is made in a set-group-ID directory takes the directory's group, and a
  new directory the bit as well. `fchmod` and `fchown` also change the mode
  and owner that `fstat` reports for a pipe made by `pipe` or `pipe2`, whose
  two ends share them, and for each socket, which start as the filesystem IDs
  of the thread that made them, or that accepted a connection. Standard input,
  output and error, which the host provides, give `EPERM`.
- `chmod` and `utimensat` work in the in-memory filesystem and in mounted
  host directories; on a Windows host, `chmod` only sets or clears the
  read-only attribute. `fchmodat2` (Linux 6.6) takes `AT_SYMLINK_NOFOLLOW`,
  which gives a symbolic link `EOPNOTSUPP` since its mode cannot change, and
  `AT_EMPTY_PATH`; glibc's `lchmod` calls it first. `stat` reports only the modification time, with access
  and change times of 0; the host still records both times it is given for a
  file in a mounted directory. The umask is shared by threads, as `CLONE_FS` shares it on
  Linux. `fsync` and `fdatasync` succeed on files and directories and give
  `EINVAL` on pipes, sockets and terminals; `fadvise64` is accepted as a hint.
- `mknod` and `mknodat` make a FIFO, a socket node or an empty regular file
  (type 0 too), with the mode's permission bits less the umask, as Linux's
  `do_mknodat`: a directory's type is `EPERM` and an unknown one `EINVAL`.
  A character or block device is `EPERM`, as for a process without
  `CAP_MKNOD`, since there is no device for it to stand for. A FIFO opens as
  Linux's `fifo_open` opens it: every open of the node, in any process,
  joins one pipe while some description of it is open, and a new pipe starts
  once none is. A blocking reader waits for a writer and a blocking writer
  for a reader (a signal ends the wait with `EINTR`, or runs it again after
  an `SA_RESTART` handler or a stop); a nonblocking reader opens at once, and
  reads the end of the file while there is no writer, and a nonblocking
  writer without a reader gets `ENXIO`. `O_RDWR` opens both ends and waits
  for neither. `fstat` of an open FIFO gives its node's inode, mode and
  owner, and `/proc/self/fd` names its path. In a mounted host directory a
  FIFO is made on Linux hosts only (`EPERM` elsewhere), and it is the
  emulator's own pipe: a host program opening the same node does not reach
  it.
- `statfs` reports the in-memory filesystem as a 4 GiB tmpfs whose used
  space and inodes are what it holds, and a mounted host directory with the
  host filesystem's own numbers. `/proc/self/mountinfo`, `/proc/self/mounts`
  and `/proc/mounts` list the mounts (`tmpfs` for the root, `hostfs` for each
  `--mount`, without host paths). Each mount has its own `st_dev`, as its
  line in `mountinfo` says, so `df` lists every mount.
- A file's block size (`st_blksize`, `stx_blksize`, `FIGETBSZ`) is its
  filesystem's, as on Linux: 1024 for `/proc` (procfs), a pseudo-terminal's
  slave and a terminal on standard input, output or error (devpts), and 4096
  for the rest,
  pipes, sockets, `memfd` and `/dev` included. `statfs` there gives
  procfs's or devpts's type with a 4096 `f_bsize`, as Linux's
  `simple_statfs` does. A link in `/proc/self/fd` is procfs's, but `stat`,
  `statfs` and `open` through it reach its file.
- The other `/proc` entries are `/proc/loadavg`, `/proc/meminfo` and
  `/proc/uptime` (below), a directory per process, and this process's own: `/proc/<pid>`, a
  directory its entries can be opened relative to and that lists them, and `/proc/self`, a
  symbolic link to it (0777, size 0) that `readlink` resolves to the PID:
  `lstat`, and `fstatat` or `statx` with `AT_SYMLINK_NOFOLLOW`, give the
  link, `stat` and a trailing slash follow it, `O_NOFOLLOW` does not
  (`ELOOP`), and `O_PATH | O_NOFOLLOW` opens the link itself, which reads
  as the PID of the process reading it and names itself `/proc/self`; then
  `/proc/self/status`, `stat`, `cmdline`, `environ`, `comm`, `exe`, `cwd`,
  `maps`, `fd` and `task`. `status` has Linux's fields in Linux's order (umask, IDs, threads,
  signal masks, capabilities and so on) without the memory and CPU ones,
  which nothing measures. Any other path in this process's directory or
  elsewhere under `/proc` is looked up in the filesystem like any path, so with
  `--mount /:/` it reaches the host's own `/proc`.
- `/proc` lists what the filesystem has there that is not a process (with
  `--mount /:/`, the host's own entries except its processes), the files above,
  and then a directory for every process of the guest, zombies included, as
  Linux lists them, which is what `ps`, `pgrep` and `pidof` read. Another
  process's `/proc/<pid>` (0555, owned by its effective IDs) has `status`,
  `stat`, `cmdline`, `environ` (0400), `comm`, `exe`, `cwd` and `task`, made as
  `fs/proc/base.c` and `array.c` make them for root; any other name there is
  `ENOENT`, as is the directory of a process that was never there or was
  reaped, whatever a mounted host `/proc` holds. `task` lists the threads of
  the process, and `/proc/<pid>/task/<tid>` (the reader's own threads too)
  has the same files but `task`, of that thread: its name, its signal masks,
  and its ID as `Pid` with the process's as `Tgid`. `/proc/thread-self` is a
  link (0777) to the reading thread's, which reads as `<pid>/task/<tid>`. A
  thread's own ID names a directory of its process as that thread sees it,
  which `/proc` does not list, as on Linux. As Linux's `ptrace_may_access`
  decides, a reader that is not of the process and has no `CAP_SYS_PTRACE`
  gets `EACCES` for `environ` unless its real IDs, and for `exe` and `cwd`
  unless its filesystem IDs, are every user and group ID of a dumpable
  process; an undumpable process's directory is root's. What a process shows of
  another is what that process's threads published at their last system call
  or signal check: the name (`PR_SET_NAME`, `execve`), the blocked and pending
  signals and the credentials, with the process's dispositions, memory (for
  `cmdline`, `environ` and the sizes in `stat`), current directory, umask and
  descriptors as they are. Its state is `R` for the reader, `T (stopped)`
  during a job-control stop, `Z (zombie)` once it has ended and until it is
  reaped, `S (sleeping)` while its thread is in a system call, where it waits
  if it waits, and `R` otherwise. A zombie keeps its name and IDs, counts one
  thread, and has no memory, umask or descriptors: its `cmdline` and
  `environ` are empty and `exe` and `cwd` are `ENOENT`, as on Linux.
- `/proc/self/stat` has Linux's 52 fields after the name in parentheses:
  state `R` (the process is running, reading it; another process's as above), the parent, process group
  and session, no terminal, the CPU time of the process and of its waited-for
  children in `USER_HZ` (100) ticks, the priority and nice value, the threads,
  the size of the mappings, the `RLIMIT_RSS` limit, the start of the stack and
  of the heap, the signal sets as decimal numbers, `wchan` (1 for a task that
  waits, as Linux shows root, though not for a process of more than one thread
  as a whole), `exit_signal` (17 for the reader's own), and where
  the argument and environment strings lie. What nothing measures is 0: page
  faults, resident memory, the start time, the code range and the scheduler's
  figures. `cmdline` and `environ` are the argument and environment strings
  as they are in memory now, each ending in its NUL, and `comm` the name and a
  newline.
- `/proc/self/exe` and `/proc/self/cwd` are symbolic links (0777, size 0) to
  the program the process runs (the one `execve` loaded, with symbolic links
  resolved; for the first program, the path the CLI gives it, `/<file name>`)
  and to the current directory. `stat` and `open` follow them, and
  `O_NOFOLLOW` does not (`ELOOP`).
- `/proc/loadavg`, `/proc/meminfo` and `/proc/uptime` agree with `sysinfo`,
  in Linux's formats: load averages of 0 with the running and live tasks and
  the last ID handed out; 4 GiB of total, free and available memory and
  nothing else used, no swap and no huge pages; and the monotonic clock's
  uptime with no idle time.
- `/proc/self/maps` lists the VMAs in Linux's format, with adjacent mappings
  merged and split as Linux does: the range, the protection, `s` or `p`, the
  offset in the file, the file's device and inode as `stat` gives them, and
  the name in Linux's column: the file's path, with a newline in it as
  `\012`, followed by a space and `(deleted)` once nothing names it, `/memfd:<name> (deleted)`,
  `/dev/zero (deleted)` for shared anonymous memory, `[heap]` or `[stack]`.
  It is made as it is read, as Linux's `seq_file` makes it: a read gathers
  whole lines up to a page, goes on from the VMA it found next, and sees the
  mappings of that moment, `lseek` goes from the start or the current
  position only (`EINVAL` from the end), and its size is 0. A descriptor
  shows the address space it was opened on, which a forked child reading it
  sees too, and nothing once no thread uses that space, as after an `execve`.
  It cannot be mapped (`ENODEV`).
- `/proc/self/fd` (mode 0500) lists `.`, `..` and a link per open
  descriptor, named by its number as Linux reads one (no leading zero). Each
  link's `lstat` shows the descriptor's access in its user bits and size 64,
  and `stat` follows it to the file. `readlink` gives Linux's names: the
  file's path with `.`, `..` and symbolic links resolved (`/proc/<pid>/…`
  for this process's entries), followed by a space and `(deleted)` once
  nothing names it, `pipe:[<inode>]`, `socket:[<inode>]`,
  `anon_inode:[eventfd]`, `[eventpoll]`, `[timerfd]` or `[pidfd]` (an
  anonymous inode's name, which pidfs, from Linux 6.9, still gives), and
  `/memfd:<name> (deleted)`; pipes and sockets have inode numbers of their
  own for it. Opening a link opens the file again by its path, or, for a
  file no path names any more (removed, or renamed away), the same file
  through its handle, with an offset of its own; a memfd gets a new handle
  on the same file and seals. Either end of a pipe opens through the link of
  either, as Linux's `fifo_open` opens it: `O_RDONLY` a reader, `O_WRONLY` a
  writer and `O_RDWR` both, which reads what it writes and, being both,
  never sees the end of the pipe or `EPIPE`, each as a new open file
  description with its own status flags (`O_NONBLOCK`). An end all of whose
  descriptions closed opens again, so a pipe whose writers were gone has one
  again, and no open waits for the other end or refuses a writer without a
  reader, as a FIFO would. An end closes when its last description does.
  Each description has its own signal owner and `O_ASYNC`, as Linux keeps
  them for each file: data (`POLL_IN`) signals every reader description
  open with `O_ASYNC` and room (`POLL_OUT`) every writer one, an `O_RDWR`
  one being both, the one that turned it on last first, as Linux's
  `kill_fasync` goes through them. A standard stream opens, for the access
  it has, as a new description of it.
  `O_CREAT | O_EXCL` finds the link there (`EEXIST`), and `O_NOFOLLOW` does
  not follow it (`ELOOP`); with `O_PATH` too it opens the link itself, as on
  any symbolic link (`/dev`'s, or a filesystem's): a descriptor whose
  `fstat` (and `fstatat` with `AT_EMPTY_PATH`) and `fstatfs` are the
  link's, whose `readlinkat(fd, "")` reads where it points (`ENOENT` for an
  `O_PATH` descriptor of anything else), whose own link names the link, and
  that nothing reads through (`EBADF`); an open that follows its own link
  reaches the link (`ELOOP`). A socket gives `ENXIO`, as on Linux, and so
  do an eventfd, an epoll and a timerfd, whose anonymous inode Linux opens
  with `no_open`. A pidfd opens as another description of its process, as
  root opens it (pidfs has no `open` of its own): with the access it is
  opened with and `O_NONBLOCK` of its own, even after the process is
  reaped. Linux checks the inode's mode first, root's 0600 (0700 for a
  pidfd), so another user gets `EACCES`; paludarium opens it as for root.
  A removed file
  of a directory mounted from a host other than Linux, which Linux can
  open, gives `ENXIO` here.
- `/dev` (mode 0755) holds the memory devices, the links Linux systems
  keep there and the pseudo-terminals' `ptmx` and `pts` (below), and lists
  only these: a file a guest makes under `/dev` can be
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
  (`/dev/fd/3`); `O_NOFOLLOW` on one gives `ELOOP`, and with `O_PATH` opens
  the link itself, as in `/proc/self/fd`. Files on host mounts report no
  device number.
- **Pseudo-terminals**, as Linux's devpts, `pty.c` and N_TTY line discipline
  make them. Each open of `/dev/ptmx` (5:2, mode 0666; also devpts's own
  `/dev/pts/ptmx`) makes a pair whose slave is `/dev/pts/<n>`, the lowest
  free number: a character device (136:n, mode 0620, group 5, owned by
  the opener) that `/dev/pts` lists while the master is open. The slave is
  locked until `TIOCSPTLCK` unlocks it, which with `TIOCGPTN` and
  `TIOCGPTLCK` makes `posix_openpt`, `grantpt`, `unlockpt`, `ptsname` and
  `openpty` work, and `TIOCGPTPEER` opens it from the master; a locked
  slave, or one whose master closed, opens with `EIO`.
  - What the master writes is the slave's input, and what the slave writes
    the master reads. The slave's line discipline edits a canonical line
    (`VERASE`, `VWERASE`, `VKILL`, `VLNEXT`, `VREPRINT`, `VEOF`, `VEOL`,
    `VEOL2`) and echoes as `ECHO`, `ECHOE`, `ECHOK`, `ECHOKE`, `ECHONL`,
    `ECHOCTL` and `ECHOPRT` say; reads in non-canonical mode as `VMIN` and
    `VTIME` say; converts input (`ICRNL`, `INLCR`, `IGNCR`, `ISTRIP`,
    `IUCLC`) and output (`OPOST`, `ONLCR`, `OCRNL`, `ONOCR`, `ONLRET`,
    `OLCUC`, `XTABS`); stops and starts its output (`IXON`, `IXANY`); and
    with `ISIG` sends `SIGINT`, `SIGQUIT` and `SIGTSTP` to the foreground
    process group, dropping the input unless `NOFLSH`. The master's side
    passes bytes as they are.
  - `TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF` and their `termios2` forms
    (`TCGETS2` and so on) reach the slave's `termios` from either side;
    it keeps `CS8 | CREAD` without parity and takes its speeds from
    `CBAUD` or `BOTHER`. `TIOCGWINSZ` and `TIOCSWINSZ` (a change sends
    `SIGWINCH` to the foreground group), `FIONREAD`, `TIOCOUTQ`, `TCFLSH`,
    `TCXONC`, `TCSBRK`, `TIOCEXCL`, `TIOCGEXCL`, `TIOCGETD` and `TIOCSETD`
    (N_TTY only), `TIOCGDEV` and `TIOCSIG` work as on Linux, and so does
    `TIOCSTI` with `dev.tty.legacy_tiocsti` off: it pushes input only for
    `CAP_SYS_ADMIN`, and is `EIO` for anyone else.
  - A session leader without a controlling terminal takes one with
    `TIOCSCTTY` or by opening the slave for reading without `O_NOCTTY`;
    its children inherit it and `setsid` drops it. `/dev/tty` opens the
    controlling terminal (`ENXIO` without one; a process of the session
    outside the emulator keeps the host's `/dev/tty`). `TIOCSPGRP`,
    `TIOCGPGRP` and `TIOCGSID` set and give the foreground group and the
    session. A background group's read gets `SIGTTIN`, and its write with
    `TOSTOP` or its `termios` change `SIGTTOU`, which restarts the call
    once the group continues, or `EIO` when the signal is ignored,
    blocked (but `SIGTTOU` then lets it go) or the group orphaned.
    `TIOCNOTTY` lets the terminal go, a leader's whole session with
    `SIGHUP` and `SIGCONT` to its foreground group.
  - When every description of the slave has closed, the master reads what
    is left, then `EIO`, and polls as hung up. When the master closes, the
    slave hangs up (it reads nothing, and writes and requests are `EIO`),
    its name goes, the session it controls loses it and the session's
    leader gets `SIGHUP` and `SIGCONT`. A session leader's exit sends
    `SIGHUP` to its terminal's foreground group.
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
- `sysinfo` reports a fixed 4 GiB of free memory and no swap, without
  revealing the host's; the uptime is the monotonic clock's, rounded up to
  a whole second as Linux rounds it.
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
  parent exits), `PR_SET_DUMPABLE` (`execve` makes the process dumpable
  again, but for the cases above), `PR_SET_KEEPCAPS` (per thread, cleared
  by `execve`), `PR_SET_CHILD_SUBREAPER` (not inherited on `fork`, kept on
  `execve`) and `PR_SET_NO_NEW_PRIVS` with their `PR_GET_*`; other options
  give `EINVAL`.
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
  invalid signal; otherwise an invalid signal gives `EINVAL`. A thread may
  signal another process, as Linux's `check_kill_permission` decides, when its
  real or effective user ID is the target's real or saved one or it has
  `CAP_KILL`, and may send `SIGCONT` within its session; otherwise `kill`,
  `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and `pidfd_send_signal` give `EPERM`,
  also for signal 0 and for a zombie. The credentials checked are those of the
  thread the ID names, and a group succeeds if any member took the signal,
  while -1 does not report those it may not signal. A signal from `kill` or
  `pidfd_send_signal` gives its sender's PID in `si_pid` and real user ID in
  `si_uid`, as `tkill` and `tgkill` do, and the `PR_SET_PDEATHSIG` signal the
  PID and real user ID of the parent that exited, which needs the same
  permission.
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
  `fs.nr_open`), or to a lower ceiling the embedder sets. Raising a hard limit
  needs `CAP_SYS_RESOURCE` (`EPERM`). `prlimit64` on another thread, to read
  or to set, needs `CAP_SYS_RESOURCE`, or the caller's real user and group IDs
  to be all of that thread's real, effective and saved ones (`EPERM`, before
  an unknown resource is noticed); a thread's ID names its process. Three are
  enforced, as in Linux:
  - `RLIMIT_NOFILE`: a new descriptor past its soft limit gives `EMFILE` (and
    `open` creates nothing), `dup2`/`dup3` onto a number past it `EBADF`, and
    `F_DUPFD` from one past it `EINVAL`.
  - `RLIMIT_FSIZE`: a write to a regular file (`write`, `writev`, `pwrite` and
    `pwritev`, which with `O_APPEND` start at the end, and `copy_file_range`
    and `sendfile`) stops at the soft limit; one that
    starts at or past it, and a `truncate`/`ftruncate` or `fallocate` that
    grows the file past it, raise `SIGXFSZ` and fail with `EFBIG`.
  - `RLIMIT_CORE`: a process that a core-dumping signal (`SIGSEGV`, `SIGABRT`,
    ...) ends writes an ELF core named `core` in its working directory (mode
    0600 less the umask, replacing an old one), as Linux's `do_coredump` does
    with the default `core_pattern`, when the soft limit is at least a page
    and `PR_SET_DUMPABLE` has not turned dumping off. The thread the signal
    ended makes it with its own permissions and filesystem IDs, so nothing is
    written where it may not write or replace the file. The core has each
    thread's registers (`NT_PRSTATUS`), the process with its leader's real
    user and group (`NT_PRPSINFO`), the fatal
    signal (`NT_SIGINFO`), the auxiliary vector, the mapped files (`NT_FILE`:
    each VMA that maps a file, by its path, followed by `(deleted)` once
    unlinked, and shared anonymous memory as `/dev/zero (deleted)`, as Linux
    names it) and the memory. It has no `NT_X86_XSTATE` note, as Linux writes
    none on a CPU without XSAVE, which the virtual CPU is. The memory is
    chosen as Linux's `vma_dump_size` chooses it with the default
    `coredump_filter`: a private mapping is there whole once a page of its VMA
    was written (Linux's `anon_vma`, which a split, `MADV_DONTNEED` and `fork`
    keep, a mapping merging with the VMA shares, and `MAP_POPULATE` or
    `MAP_LOCKED` gives a writable one), and nothing of it otherwise, but the
    first page of a file mapping from the start of an ELF file; a shared
    mapping is there whole when no name links its file (an anonymous one, a
    memfd, a file unlinked since), and nothing of it otherwise. Whether a
    mapping can be read matters only for that ELF header's page: Linux reads
    the others whatever their protection. Each VMA is one segment, with the
    adjacent mappings merged into it. `wait` then reports `CLD_DUMPED` and the
    core flag. A core larger than the limit is cut there and still reported as
    dumped, as Linux reports a core once it has started to write it.

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
  and `setpriority` sets them all, cut to -20..19. `PRIO_PROCESS` names one
  thread (0 is the caller), `PRIO_PGRP` every thread of a process group and
  `PRIO_USER` every thread of a real user ID (0 is the caller's). An exited
  process not yet reaped is still found. No thread gives `ESRCH`, and an
  unknown `which` `EINVAL`. The values are reported but do not change
  scheduling.
- `setpriority` checks each thread as Linux's `set_one_prio` does. The
  caller's effective user ID must be the thread's real or effective one, or
  the caller must have `CAP_SYS_NICE`; otherwise it is `EPERM`. Lowering a
  nice value needs `CAP_SYS_NICE` or `20 - nice` within the thread's
  `RLIMIT_NICE` soft limit; otherwise it is `EACCES`. The threads it may
  change do change, and the call then reports the last refusal.
- `waitid` follows Linux's checks and copy-out: its siginfo fields are zero
  when no child is reported, even on an error, and an exited child cannot be
  waited for without `WEXITED` or `WCONTINUED` (`ECHILD`). A stop and a
  continue are reported once each to a wait with `WUNTRACED` (`WSTOPPED`) or
  `WCONTINUED` (`WNOWAIT` leaves them), and `SIGCHLD` tells the parent unless
  it set `SA_NOCLDSTOP`. The siginfo of `SIGCHLD` carries the child's PID, its
  `CLD_*` code (`CLD_EXITED`, `CLD_KILLED`, `CLD_STOPPED`, `CLD_CONTINUED`), its
  status and its CPU time as `si_utime`; `si_uid` and that of `waitid` are the
  child's real user ID, and a `SIGCHLD` sent
  while one is pending is dropped, as Linux does. A child of a process that
  ignores `SIGCHLD` or set `SA_NOCLDWAIT` is reaped as it exits, as Linux's
  `do_notify_parent` does when its exit signal is `SIGCHLD`: a wait blocks
  until such children have exited, then fails with `ECHILD`, their CPU time
  does not join the parent's children's, and with `SIGCHLD` ignored no
  `SIGCHLD` is queued, even while blocked. A zombie from before stays for a
  wait. A pidfd from `pidfd_open` has pidfs's mode 0700 in `fstat`, with
  no file type, and becomes readable when its process exits (and hung up
  once it is reaped; an automatically reaped child shows both at once), so
  `epoll` can wait for it; `waitid(P_PIDFD)` on a nonblocking one gives
  `EAGAIN`.
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
    `wmem_max` and `rmem_max` (212992), doubled. `SO_TIMESTAMP`, its kin
    and `SO_TIMESTAMPING` are set and read back as on AF_UNIX sockets, and
    `SOF_TIMESTAMPING_OPT_ID` needs a TCP socket's connection (`EINVAL`
    while it is closed or listening).
  - **Timestamps**: every UDP datagram is stamped as it comes, and
    `recvmsg` gives that time as Linux's `udp_recvmsg` does
    (`sock_recv_timestamp`), however late the receiver took the options:
    the control message of `SO_TIMESTAMP` or its kin, then, when
    `SO_TIMESTAMPING`'s flags report software stamps and do not filter
    received ones out, a `SCM_TIMESTAMPING`, which UDP gives alone too.
    Both are cut to the control buffer as on AF_UNIX. A DNS stub's answer
    is stamped when it is read. TCP bytes are stamped as they come too,
    on the loopback and through the host, and a read, a peek, or an empty
    read with bytes waiting gets the time of those it read, as Linux's
    `tcp_recvmsg` gives the segment's (`tcp_recv_timestamp`); the end of
    input gets none. Bytes that come while others wait unread give those
    their time, as Linux's `tcp_try_coalesce` gives a segment it joins to
    the one before it.
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
- **Lingering**, as Linux's `tcp_close`: with a nonzero `SO_LINGER` time,
  closing a socket's last descriptor (`close`, `close_range`, `dup2` over
  it, or `execve` with `FD_CLOEXEC`, before the new program starts) waits while the bytes it sent wait for room in the peer, until
  they have all gone, the time is up or a signal comes, nonblocking or
  not. The close succeeds all the same, and the bytes still go after it.
  A socket with unread input is reset instead, and a process that exits
  does not wait.
- **Buffers**: the `SO_SNDBUF` a sender set, and the `SO_RCVBUF` a
  receiver set (an accepted connection takes its listener's), bound a
  connection as Linux's do, roughly: what waits to be sent holds up to the
  doubled `SO_SNDBUF`, and what has arrived up to half of the doubled
  `SO_RCVBUF`, so a small one makes a sender wait or `EAGAIN` early. One
  not set holds 256 KiB. `SIOCOUTQ` and `FIONREAD` count the two.
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
  of an `IPV6_V6ONLY` socket, or the host's error when it has no route
  there), on the source address of the route to its peer: the loopback's
  for a loopback peer, else, for a peer the policy allows, the host's, as
  the host's routes pick it without sending anything (for any other, the
  port stays on every address). It receives only from its
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
- The threads of a process share its signal dispositions, as Linux's
  `sighand_struct` does. A thread that was already waiting (in `epoll_wait`,
  `poll` or a `futex` wait, say) when another thread called `sigaction` takes
  a process-directed signal in with the new handler. So a SIGCHLD handler
  set after a helper thread began to wait still runs, as Node.js's child
  processes need.

## Signals

- Registration, masks, delivery (the Linux x86-64 signal frame and
  `rt_sigreturn`), `sigaltstack`, queued real-time signals, and stop and
  continue with `SIGSTOP`. A blocking call that a stop interrupts runs again
  after the continue, as Linux restarts it when no handler runs: `read`,
  `write`, `readv`, `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev`,
  `wait4`, `waitid`, `pause`, `rt_sigsuspend`, `flock`, `fcntl`'s `F_SETLKW` and
  `F_OFD_SETLKW`, `sendto`, `recvfrom`,
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
  directory; `..` and symbolic links cannot lead outside. `getdents64` lists
  `.` and `..` in it too, with the inodes `stat` reports for them, and the
  rest in the order the host lists them.

## Programs verified

- Hello world in C and Rust, and small test programs for each instruction.
- **probe**: a Rust program that checks eight thread and filesystem features
  (a tokio timer, a UNIX socket pair, rayon parallelism, Mutex and Condvar,
  file operations, hard links, symbolic links and `flock`).
- **aube**: a Node.js package manager written in Rust (v2.8.5). `--version`,
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
