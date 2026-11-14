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
  every x86-64 CPU has, because glibc requires them, and `CLFLUSH` with its
  64-byte line, because HotSpot requires it. Of those, the FPU and MMX
  are not implemented; it advertises no other feature that is not. The name
  changes nothing else: where vendors' CPUs differ, as in the flags after a
  `REP` faults, the virtual CPU keeps its own behaviour.
- `RDTSC` and `RDTSCP` read a counter of the virtual CPU, which moves on with
  each read rather than with time. Every guest in the host process shares that
  counter, so its values depend on what else has read it. `RDSSP` does nothing
  and `map_shadow_stack` gives `EOPNOTSUPP`, as there are no shadow stacks. `FXSAVE` and `FXRSTOR` keep the x87 state,
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
| Processes and threads | `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `wait4`, `waitid`, `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, `kcmp`, `process_vm_readv`/`process_vm_writev`, `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `set_tid_address`, `futex`, `futex_waitv`, `futex_wake`/`futex_wait`/`futex_requeue`, `set_robust_list`, `get_robust_list`, `sched_setaffinity`/`sched_getaffinity`, `getcpu`, `sched_yield`, `sched_setscheduler`/`sched_getscheduler`, `sched_setparam`/`sched_getparam`, `sched_setattr`/`sched_getattr`, `sched_get_priority_max`/`sched_get_priority_min`, `sched_rr_get_interval`, `ioprio_set`/`ioprio_get`, `personality`, `unshare`, `setns`, `membarrier`, `rseq`, `setpgid`/`getpgid`/`getpgrp`, `setsid`/`getsid`, `getpriority`/`setpriority`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files private or shared), `munmap`, `mremap`, `mprotect`, `pkey_mprotect`/`pkey_alloc`/`pkey_free`, `mseal`, `madvise`, `process_madvise`, `process_mrelease`, `mincore`, `cachestat`, `mlock`/`mlock2`/`munlock`/`mlockall`/`munlockall`, `mbind`, `set_mempolicy`/`get_mempolicy`, `set_mempolicy_home_node`, `migrate_pages`, `move_pages`, `map_shadow_stack`, `msync`, `remap_file_pages`, `brk`, `arch_prctl` |
| System V IPC | `shmget`, `shmat`, `shmdt`, `shmctl` (shared memory); `semget`, `semop`, `semtimedop`, `semctl` (semaphores); `msgget`, `msgsnd`, `msgrcv`, `msgctl` (message queues) |
| POSIX message queues | `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr` |
| System information | `uname`, `sethostname`, `setdomainname`, `sysinfo`, `getrusage`, `times` |
| Credentials | `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`/`getresgid`, `setuid`/`setgid`, `setreuid`/`setregid`, `setresuid`/`setresgid`, `setfsuid`/`setfsgid`, `getgroups`/`setgroups`, `capget`/`capset` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `getitimer`/`setitimer`, `alarm`, `rt_sigtimedwait`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete` |
| Files | `open`/`openat`/`openat2`/`creat`, `read`, `write`, `readv`/`writev`, `pread64`/`pwrite64`, `preadv`/`pwritev`, `preadv2`/`pwritev2`, `copy_file_range`, `sendfile`, `splice`, `tee`, `vmsplice`, `setxattr`/`lsetxattr`/`fsetxattr`, `getxattr`/`lgetxattr`/`fgetxattr`, `listxattr`/`llistxattr`/`flistxattr`, `removexattr`/`lremovexattr`/`fremovexattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat`, `file_getattr`, `file_setattr`, `close`, `close_range`, `lseek`, `stat`/`fstat`/`lstat`/`newfstatat`, `statx`, `name_to_handle_at`, `open_by_handle_at`, `getdents`/`getdents64`, `mkdir`/`mkdirat`, `mknod`/`mknodat`, `rmdir`, `unlink`/`unlinkat`, `rename`/`renameat`/`renameat2`, `link`/`linkat`, `symlink`/`symlinkat`, `readlink`/`readlinkat`, `truncate`/`ftruncate`, `fallocate`, `memfd_create`, `memfd_secret`, `flock`, `fcntl`, `dup`/`dup2`/`dup3`, `pipe`/`pipe2`, `chdir`/`fchdir`, `getcwd`, `umask`, `chmod`/`fchmod`/`fchmodat`/`fchmodat2`, `chown`/`fchown`/`lchown`/`fchownat`, `utimensat`, `utime`/`utimes`/`futimesat`, `fsync`/`fdatasync`, `sync_file_range`, `sync`, `syncfs`, `fadvise64`, `readahead`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs`, `ustat` |
| Landlock | `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` |
| seccomp | `seccomp` (see below) |
| I/O | `poll`, `ppoll`, `select`, `pselect6`, `vhangup`, `ioctl` (`TCGETS`, `TIOCGWINSZ`, `FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, `FIOQSIZE`, `FIGETBSZ`, `SIOCATMARK`, `FIONREAD`/`SIOCINQ`, `SIOCOUTQ`, `SIOCGIFFLAGS`, `SIOCSIFFLAGS`, `SIOCGIFINDEX` and `SIOCGIFNAME` of the loopback, `INOTIFY_IOC_SETNEXTWD`, the seccomp listener's `SECCOMP_IOCTL_NOTIF_*` (see seccomp below), `FS_IOC_GETFLAGS`, `FS_IOC_SETFLAGS`, `FS_IOC_FSGETXATTR`, `FS_IOC_FSSETXATTR`, and the pseudo-terminals' requests below) |
| Events | `eventfd`/`eventfd2`, `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, `signalfd`/`signalfd4`, `inotify_init`/`inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`, `epoll_create`/`epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `io_uring_setup`, `io_uring_enter`, `io_uring_register` (see below) |
| Asynchronous I/O | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents` (see below) |
| Sockets | `socket` (`AF_UNIX` streams, packet and datagram sockets; `AF_INET`, `AF_INET6` and `AF_NETLINK` (`NETLINK_ROUTE`, `NETLINK_SOCK_DIAG` and `NETLINK_GENERIC`) with a [network](#network) or in a new network namespace, else `EAFNOSUPPORT`), `connect`, `getsockname`, `getpeername`, `bind`, `listen`, `accept` and `accept4` (AF_UNIX streams and packet sockets, and on the guest's own [loopback](#loopback-servers) TCP), `socketpair` (AF_UNIX, `SOCK_STREAM`, `SOCK_SEQPACKET` and `SOCK_DGRAM`), `sendto`, `recvfrom`, `sendmsg` and `recvmsg` (passing descriptors with `SCM_RIGHTS`, credentials with `SCM_CREDENTIALS` and the sender's pidfd with `SCM_PIDFD`), `sendmmsg` and `recvmmsg`, `setsockopt` and `getsockopt` (`SOL_SOCKET`), `shutdown` |
| Randomness | `getrandom` |

- The `struct iovec` array of `readv`, `writev`, their positioned forms,
  `vmsplice`, `sendmsg` and `recvmsg` is checked in the order of Linux's
  `import_iovec`: no entries move nothing, more than 1024 are `EINVAL`, an
  array past the user half is `EFAULT`, then every entry is read and a
  negative length is `EINVAL` before any buffer is looked at, and then each
  buffer must lie in the user half (`EFAULT`), with its whole length when
  there are several and at most `MAX_RW_COUNT` when there is one. The lengths
  are cut so that the total is at most `MAX_RW_COUNT`.
- `pread64`, `pwrite64`, `preadv` and `pwritev` leave the file position
  where it was, and a pipe or socket gives `ESPIPE`; in an `O_APPEND` file a
  positioned write still appends, as on Linux.
- `preadv2` and `pwritev2` read and write at an offset, or at the file
  position for an offset of -1, as `readv` and `writev` do. Their flags
  are checked as Linux's `kiocb_set_rw_flags` checks them, once the vector
  and the range are, and only when there are bytes to move: an unknown flag
  is `EOPNOTSUPP`, `RWF_APPEND` with `RWF_NOAPPEND` `EINVAL`, and
  `RWF_ATOMIC` `EOPNOTSUPP`, as no file here writes atomically.
  `RWF_NOWAIT` needs a file that can be read or written without waiting (a
  pipe, a socket, an eventfd, a signalfd, a timerfd, `/dev/null`,
  `/dev/zero`, `/dev/random`, `/dev/urandom`, or a regular file of a file
  system that has it; `EOPNOTSUPP` for the rest) and then gives `EAGAIN`
  where the call would wait. `RWF_DONTCACHE` needs a regular file of a file
  system with `FOP_DONTCACHE`, and changes nothing (nothing is cached). A
  regular file's file system is the one its file is on (as `fstatfs` names
  it), and decides both as Linux master's: ext4 takes NOWAIT, but refuses it
  for a write, and DONTCACHE; xfs takes both, a write's NOWAIT too; btrfs
  and f2fs take NOWAIT, for a write too, and not DONTCACHE; tmpfs (an
  in-memory file system, a memfd), overlayfs, `/proc` and any other file
  system take neither. On a macOS or Windows host, whose file systems Linux
  has no number for, a host file is taken as ext4's. `RWF_NOSIGNAL` spares a write to
  a pipe or socket with no reader its `SIGPIPE` (it still gives `EPIPE`), as
  since Linux 6.18. `RWF_NOAPPEND` turns an `O_APPEND` file's append off
  for the call: a write goes to the offset (growing the file past its end)
  or, at -1, to the position, which then moves past it; an append-only file
  (`FS_APPEND_FL`) gives `EPERM`, for a read too. `RWF_APPEND` writes a
  regular file at its end, `RWF_DSYNC` and `RWF_SYNC` write it through as
  `fdatasync`, and `RWF_HIPRI` changes nothing.
- `copy_file_range` copies between two regular files on one mount (`EXDEV`
  across mounts), stopping at the input's end, with Linux's checks in order
  (`EISDIR`, `EINVAL`, `EBADF`, `EOVERFLOW`, and `EINVAL` for an overlap in
  one file). `sendfile` reads a regular file into any writable file, a pipe
  taking at most its capacity per call. Both update the given offsets or the
  file positions; `sendfile` writes its offset back even after an error.
- `splice` moves bytes between a pipe (or FIFO) and a regular file, a
  device, a socket or another pipe, `tee` copies what one pipe holds into
  another without taking it, and `vmsplice` puts the guest's buffers into a
  pipe opened for writing or takes a pipe's bytes into them. They follow
  Linux's `fs/splice.c` in order: `splice` returns 0 for no bytes before
  anything else, and `tee` checks its flags first; then the flags
  (`EINVAL`), the descriptors (`EBADF`, `O_PATH` too), an offset for a pipe
  (`ESPIPE`), reading the offsets (`EFAULT`), the access modes (`EBADF`),
  an offset for a file without one, such as a socket, or an `O_APPEND`
  output (`EINVAL`), the range (`EINVAL`), and a file of no kind that
  splices (a directory, an eventfd, `EINVAL`). Two descriptions of one
  pipe are `EINVAL`, and `vmsplice` of a file that is no pipe is `EBADF`.
  A pipe with no reader is `EPIPE` with `SIGPIPE`, looked at before the
  input, even at its end. A call waits for data or room unless
  `SPLICE_F_NONBLOCK` or the pipe's `O_NONBLOCK` (`vmsplice`: only the
  flag) says not to (`EAGAIN`); a pipe whose writers are gone gives 0, and a
  call that moved some bytes returns them instead of waiting again. One call
  moves at most what the pipe holds or has room for. A unix stream socket's
  read does not wait with `SPLICE_F_NONBLOCK` either, while a socket's send,
  as `splice_to_socket` makes it, and other files read and write as their
  own `O_NONBLOCK` says. `SPLICE_F_MOVE`, `SPLICE_F_GIFT` and `SPLICE_F_MORE` change
  nothing, as the bytes are copied. A pipe here holds bytes, not Linux's
  page buffers: it takes as many bytes as its size, where Linux counts a
  buffer, even of one byte, as a whole page of the capacity (a partly full
  pipe, or the buffers of `vmsplice` that are not whole pages, may take
  more here than on Linux). One thread's call is not atomic against
  another's read of the same pipe, as Linux's pipe lock makes it.
  The host's standard streams, which stand for pipes, can be either end of
  a `splice` (an offset for one is `ESPIPE`), but not of `tee` or
  `vmsplice`, which take only the guest's own pipes.
- `getdents64` goes on from what it has returned, so unlinking those entries
  skips nothing. `lseek` to a `d_off` leads to the same entry while the
  directory is unchanged, and `dup` and `fork` share the place. `getdents`
  is the same with the old `linux_dirent`, whose last byte is the type. Both
  keep the count in an `int` as Linux does, so one of 2 GiB or more fits no
  entry (`EINVAL`).
- Extended attributes stay with a file in memory, through hard links and
  renames and after its last name is gone. As on Linux, `user.*` is for regular
  files and directories (on others, reading gives `ENODATA` and writing `EPERM`),
  `trusted.*` shows only with `CAP_SYS_ADMIN`, and `security.*` needs it to
  change. A name is from 1 to 255 bytes (`ERANGE`), a value at most 64 KiB
  (`E2BIG`), and any other namespace gives `EOPNOTSUPP`. The name is read
  before the file is found, as since Linux 6.13.
- `setxattrat`, `getxattrat`, `listxattrat` and `removexattrat` (Linux 6.13)
  find the file from a directory descriptor, and take `AT_SYMLINK_NOFOLLOW`
  and `AT_EMPTY_PATH` only (`EINVAL`). With `AT_EMPTY_PATH`, a null or empty
  path names the descriptor's file (`EBADF` for none or an `O_PATH` one);
  `setxattrat` and `getxattrat` take `AT_FDCWD` then as the working
  directory, and the other two give `EBADF`. The value, its size and the
  flags come in a `struct xattr_args`, checked as `copy_struct_from_user`
  checks one: below 16 bytes is `EINVAL`, above a page or with a nonzero
  byte past the 16 is `E2BIG`, and `getxattrat` takes no flags (`EINVAL`).
- A regular file or directory in memory keeps tmpfs's inode flags:
  `FS_IMMUTABLE_FL`, `FS_APPEND_FL`, `FS_NODUMP_FL` and `FS_NOATIME_FL`.
  `file_getattr` and `file_setattr` (Linux 6.17) and the `FS_IOC_GETFLAGS`,
  `FS_IOC_SETFLAGS`, `FS_IOC_FSGETXATTR` and `FS_IOC_FSSETXATTR` ioctls read
  and change them, as Linux's `vfs_fileattr_set` and tmpfs's
  `shmem_fileattr_set` do:
  - Only the owner or `CAP_FOWNER` changes them (`EPERM`), and the first two
    need `CAP_LINUX_IMMUTABLE` (`EPERM`).
  - A project ID of -1, and an extent size flag on the wrong type of file,
    are `EINVAL`. Any other flag, project ID or extent size is `EOPNOTSUPP`,
    as tmpfs keeps none.
  - `file_getattr` and `file_setattr` find the file as `setxattrat` does and
    take a `struct file_attr` of 24 bytes or more, checked as
    `copy_struct_from_user` checks one. A flag Linux does not know is
    `EINVAL` there and `EOPNOTSUPP` in `FS_IOC_FSSETXATTR`.
  - A new file or directory takes `FS_NODUMP_FL` and `FS_NOATIME_FL` from its
    directory, and `statx` reports `STATX_ATTR_IMMUTABLE`,
    `STATX_ATTR_APPEND` and `STATX_ATTR_NODUMP`.
  - A file in a mounted host directory, under `/proc`, a symbolic link or a
    special file keeps none: `EOPNOTSUPP` from the calls and `ENOTTY` from
    the ioctls.
  - Setting one generates `IN_ATTRIB`.
- The flags are enforced where Linux checks `IS_IMMUTABLE` and `IS_APPEND`,
  root included:
  - Writing an immutable file is `EPERM` before any other permission check
    (`inode_permission`): opening it to write or truncate, `truncate`,
    `access` with `W_OK`, and creating or removing a name in an immutable
    directory.
  - An immutable or append-only file is not removed, renamed over or away,
    or linked to, and its mode, owner, extended attributes and given times
    do not change (`EPERM`). An immutable one is not touched to now either.
  - Nothing is removed from an append-only directory.
  - An append-only file opens to write only with `O_APPEND` and never with
    `O_TRUNC`, and keeps `O_APPEND` (`F_SETFL`, `RWF_NOAPPEND`: `EPERM`). It
    is not `ftruncate`d, and only preallocated by `fallocate` (`EPERM`).
    Opened to write, it is not mapped shared (`EACCES`).
  - `copy_file_range` does not write an immutable file (`EPERM`).
  - A description opened before the flag was set still writes, as on tmpfs.
    `FS_NOATIME_FL` and `FS_NODUMP_FL` change nothing else, as no access
    time is kept.
- `statx` reports the fields a `stat` has (`STATX_BASIC_STATS`) and the
  mount's `st_dev` as its device numbers, with Linux's flag and mask checks
  (`EINVAL`). Whatever the mask asks for, it also gives the mount's ID, as
  Linux does: the one `/proc/self/mountinfo` shows (`STATX_MNT_ID`), or a
  64-bit one in its place when `STATX_MNT_ID_UNIQUE` is asked for.
  `AT_EMPTY_PATH` names the descriptor, or the working directory for
  `AT_FDCWD`, and as since Linux 6.11 a null path with it does too.
- `name_to_handle_at` gives a file's handle, checked in the order of
  Linux's (6.13 and later): the flags (`EINVAL`, also for
  `AT_HANDLE_CONNECTABLE` with `AT_HANDLE_FID` or `AT_EMPTY_PATH`), the path
  (the last link itself unless `AT_SYMLINK_FOLLOW`; the descriptor, or the
  working directory, with an empty one and `AT_EMPTY_PATH`), the file
  system, then the size given (`EINVAL` over 128 bytes; `EOVERFLOW` under the
  handle's, with its size and `FILEID_INVALID` written back), and the
  mount's ID as `statx` gives it (the 64-bit one with
  `AT_HANDLE_MNT_ID_UNIQUE`). A tmpfs file (and a memfd) has tmpfs's 12-byte
  handle of type `FILEID_INO32_GEN`: the generation, then the inode's low and
  high halves. A pidfd has pidfs's 8-byte handle of type `FILEID_KERNFS`, its
  inode. Any other file system, as one without NFS export (an eventfd's
  anonymous inode, a pipe's, `/proc`), refuses a handle (`EOPNOTSUPP`) but
  gives `AT_HANDLE_FID` its identifier of type `FILEID_INO64_GEN`: the inode,
  then the generation. A connectable handle is `EOPNOTSUPP`, as neither tmpfs
  nor pidfs can give one.
- `open_by_handle_at` opens the file a handle names, checked in the order of
  Linux's: the handle's header (`EFAULT`), its size (`EINVAL` for 0 or over
  128 bytes) and the flags of its type (`EINVAL`, but for a connectable
  handle's and a directory's), the mount to decode it on (`EBADF`; a
  descriptor's file system, the working directory's with `AT_FDCWD`, or
  `FD_PIDFS_ROOT` and `FD_NSFS_ROOT`), whether the caller may decode handles
  there, the handle's bytes (`EFAULT`), then the file, `ESTALE` where none is
  found or the handle is refused (a directory's handle of a file, or a
  connectable one of a file outside the mount's directory). Anyone may open
  a pidfs handle, from a pidfd or `FD_PIDFS_ROOT`, with only the flags a
  pidfd opens with (`EINVAL` for others): it is a pidfd of its process
  while that process is not reaped and the caller's PID namespace numbers
  it, always opened for reading and writing, with `O_NONBLOCK` and
  `O_CLOEXEC` as asked, which `F_GETFL` shows, and without `PIDFD_THREAD`,
  as Linux 7.0 opens it. Elsewhere decoding needs
  `CAP_DAC_READ_SEARCH` (`EPERM`). A tmpfs handle of the in-memory root
  opens its file, as an open of that file itself would: `O_CREAT` finds it
  (`EEXIST` with `O_EXCL`, `EISDIR` for a directory), and a symbolic link is
  not followed.
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
- `memfd_secret` makes a file as Linux's secretmem does: regular, empty,
  mode 0600 and one link, open for reading and writing, `/secretmem
  (deleted)` in `/proc/self/fd` and `/proc/self/maps`, and on a filesystem
  of its own (`SECRETMEM_MAGIC`); `O_CLOEXEC` is its only flag (`EINVAL`).
  `ftruncate` sets its size once (`EINVAL` after), and only a shared
  mapping shows it (`EINVAL`), past the end with `SIGBUS`. It has no
  `read`, `write` or positioned or vectored forms of them (`EINVAL`), no
  `lseek` (`ESPIPE`), `fsync` (`EINVAL`), `fallocate` (`EOPNOTSUPP`) or
  seals (`EINVAL`), and opening it again through `/proc/self/fd` gives
  `ENXIO`. The kernel may not reach the pages of its mapping, as Linux's
  `get_user_pages` refuses them: `MADV_POPULATE_READ` and
  `MADV_POPULATE_WRITE` give `EINVAL`, and `mlock` `ENOMEM`, with
  `MLOCK_ONFAULT` too, as `mlock_fixup` gives its VMA no `VM_LOCKONFAULT`.
  `msync` with `MS_SYNC` gives `EINVAL` for it, as its file has no `fsync`,
  even after a hole in the range. A fault brings a page in only while the
  pages of the files the user made stay within the faulting process's
  `RLIMIT_MEMLOCK` (else `SIGBUS`, `CAP_IPC_LOCK` or not), and they count
  until the file goes, mapped or not, as Linux master's secretmem charges
  the creator's `locked_vm`. Its pages are the emulator's, so they are as
  secret as any other memory of the guest.
- `openat2` opens as `openat` does (a FIFO too), with Linux's stricter
  checks of its `struct open_how`: a size below 24 bytes is `EINVAL`, above
  a page or with unknown nonzero bytes past the first version `E2BIG`; an
  unknown flag or `RESOLVE_*` flag, a mode without `O_CREAT` or `O_TMPFILE`
  or with more than the permission bits, `O_CREAT | O_DIRECTORY`, and
  `O_PATH` with other flags than `O_DIRECTORY`, `O_NOFOLLOW` and
  `O_CLOEXEC` are `EINVAL`. `RESOLVE_NO_SYMLINKS` follows no symbolic link
  and `RESOLVE_NO_MAGICLINKS` no link in `/proc/self/fd` or `exe` and `cwd`
  (`ELOOP`); `RESOLVE_NO_XDEV` crosses no mount, `/proc` and `/dev`
  included (`EXDEV`); `RESOLVE_BENEATH` gives `EXDEV` for an absolute path
  or link, `..` out of the directory and a magic link, and
  `RESOLVE_IN_ROOT` takes the directory as the root, where those stay but
  a magic link (`EXDEV`). With both scoping flags the call is `EINVAL`.
  `RESOLVE_CACHED` gives `EAGAIN` with `O_CREAT`, `O_TRUNC` or `O_TMPFILE`,
  and otherwise always finds the file, as if every name were cached.
- `close_range` closes the open descriptors from `first` to `last`, or with
  `CLOSE_RANGE_CLOEXEC` marks them close-on-exec. `CLOSE_RANGE_UNSHARE` first
  gives the thread its own copy of a table it shares with `CLONE_FILES`
  threads, which keep their descriptors. Unknown flags and `first` above
  `last` give `EINVAL`.
- Every system call reads its arguments at the width of the C type Linux
  declares them with, as Linux's syscall wrappers cast the registers before
  the call runs: an `int`, `pid_t` or `clockid_t` from the low 32 bits,
  sign-extended; an `unsigned int`, `uid_t` or `u32` from the low 32 bits; a
  `umode_t` from the low 16. A caller that leaves the rest of a register dirty
  (fish's `fcntl` does) gets what it would on Linux. Pointers and `long`,
  `unsigned long`, `size_t` and `loff_t` arguments are read whole, so
  `mprotect` with a bit set past 32 in `prot` is still `EINVAL`; the iovec
  count of `readv`, `writev` and their kin (`process_vm_readv`'s and
  `process_vm_writev`'s local one, `vmsplice`'s, and `aio_nbytes` of a
  vectored `io_submit` request) is the exception: the CI runner's kernel
  passes it to `import_iovec` as an `unsigned`, so a count of `0x100000001`
  is one entry. Linux master reads it whole since 965e5e451146 (2026-11-05)
  and gives such a count `EINVAL`; paludarium follows once the CI kernel
  does. The number
  itself is read from the low 32 bits of `rax` too, as Linux's
  `do_syscall_64` takes an `int`, and a negative one gives `ENOSYS`.
- `futex` handles `WAIT`, `WAKE`, `WAIT_BITSET`, `WAKE_BITSET`, `REQUEUE`,
  `CMP_REQUEUE` and `WAKE_OP`. A word is
  told apart as Linux's `get_futex_key` does: in a shared mapping (shared
  anonymous memory or a file's), a shared operation names the memory and the
  offset in it, so a wake reaches a waiter in any process that maps it,
  wherever it maps it. Any other word, and a private operation, names this
  process's address space and the address, so a private wake never reaches
  another process. Process-shared mutexes and semaphores (Python's
  `multiprocessing`) work this way, as does the wake of a robust futex whose
  owner ends. A wake wakes one waiter even when asked for 0 or fewer, as
  Linux counts before it compares, and a private one does not look at the
  word's page. A timeout too long for Linux's nanoseconds waits until
  `KTIME_MAX`. A requeue wakes `val` waiters and moves up to `val2` more (the
  timeout argument, as Linux reads it) to `uaddr2`'s queue, giving how many
  it took. Negative counts give `EINVAL`, and `CMP_REQUEUE` gives `EAGAIN`
  when the first word is not `val3`, after both words' checks. It takes the
  waiters in the order they came, whatever their bitsets. Onto its own word,
  a requeue leaves them where they are and counts each once, as Linux does
  within one hash bucket. `WAKE_OP` changes `uaddr2` atomically by the
  operation `val3` encodes (set, add, or, and-not or xor, its argument
  optionally a shift of 1), wakes up to `val` waiters of `uaddr`, then up to
  `val2` of `uaddr2` when its old value, as a signed `int`, compares true,
  and gives how many it woke. An unknown operation gives `ENOSYS` before the
  word is touched, an unknown comparison gives `ENOSYS` after it changed, and
  a word it cannot write gives `EFAULT`, as x86's Linux does.
- The futex2 calls take 32-bit words with `FUTEX2_PRIVATE`, `FUTEX2_NUMA`
  and `FUTEX2_MPOL`, checked in Linux's order. Other sizes and flags give
  `EINVAL`. `futex_wake` and `futex_wait` are `FUTEX_WAKE_BITSET` and
  `FUTEX_WAIT_BITSET` with an absolute timeout on `CLOCK_REALTIME` or
  `CLOCK_MONOTONIC`, and a `futex_wake` of 0 wakes none. `futex_waitv` waits
  on up to 128 words at once and gives the index of a woken one: it checks
  every word's address before it compares any value, then gives `EAGAIN` at
  the first that differs. `futex_requeue` is `CMP_REQUEUE` on the two words of
  a `struct futex_waitv` list, which must have the same flags, as kernels
  after 6.12 ask; the first's value is compared. A `FUTEX2_NUMA` word is followed by its node,
  which must be node 0, the only one, or `-1`, which becomes 0, as Linux
  writes the thread's node there. A signal interrupts the waits with
  `ERESTARTSYS`, so they run again after a stop or an `SA_RESTART` handler.
- `set_robust_list` and `get_robust_list` keep each thread's list of robust
  futexes, which glibc's and musl's robust mutexes need. When a thread ends or
  calls `execve`, the list is walked as Linux's `exit_robust_list` walks it:
  a word the thread owned is marked `FUTEX_OWNER_DIED`, with a shared wake if
  it has `FUTEX_WAITERS`, the walk stops at what it cannot use and after 2048
  entries, and a core dump comes first. A new thread or process has no list.
  `get_robust_list` gives another process's thread's head to a caller that may
  read it, as Linux's `ptrace_may_access` with `PTRACE_MODE_READ_REALCREDS`
  decides (`EPERM` before the addresses are written), and 0 for a zombie. A
  zombie keeps the dumpability it had for that check, and for `kcmp`,
  `pidfd_getfd`, `migrate_pages` and `move_pages`, as Linux 7.1 and later keep
  it (before, a process with no memory left skipped it).
- `futex`, `epoll` and `eventfd` are implemented inside paludarium, not with the
  host's equivalents, so they behave the same on macOS, Windows and in
  WebAssembly.
- Without a [network](#network), outside a new network namespace, `socket()` returns `EAFNOSUPPORT` for
  `AF_INET`, `AF_INET6` and `AF_NETLINK`.
- `epoll_wait`, `epoll_pwait` and `epoll_pwait2` check their arguments in
  the order of the kernels after Linux 6.12 (6.12 itself checked
  `maxevents` before the descriptor): `epoll_pwait2` reads its timeout (a `struct timespec`, none
  waiting for ever; `EFAULT`, then `EINVAL` for one Linux refuses, while a
  huge one saturates), the signal mask is set (`EINVAL` for a size other
  than 8), then the descriptor is checked (`EBADF`), then `maxevents`
  (`EINVAL`), and last that it is an epoll (`EINVAL`).
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
- An `O_PATH` descriptor holds only a path, as Linux's `fdget` refuses it:
  reading and writing it, `lseek`, `flock`, `getdents`, `getdents64`, `sendfile`,
  `copy_file_range`, `splice`, `tee`, `vmsplice`, `fsync`, `fdatasync`, `syncfs`, `sync_file_range`,
  `fadvise64`, `readahead`, `ftruncate`,
  `fallocate`, `mmap`, `ioctl`, the `f*xattr` calls, `epoll_ctl` (as the
  epoll descriptor or the target), `epoll_wait` and `fcntl`
  (but for `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_DUPFD_QUERY`, `F_GETFD`,
  `F_SETFD` and `F_GETFL`) are `EBADF`, and `poll` gives `POLLNVAL`, while
  `select` finds it ready. `fstat`, `fstatfs`, `fchdir`, `dup` and `close`
  take it, and it is a directory for the `*at` calls.
- `fcntl`'s byte-range locks, as Linux's `fs/locks.c` keeps them: record
  locks (`F_SETLK`, `F_SETLKW`, `F_GETLK`), which a descriptor table owns (a
  process's, which its threads and a child cloned with `CLONE_FILES` share,
  as Linux's `files_struct`), and open
  file description locks (`F_OFD_SETLK`, `F_OFD_SETLKW`, `F_OFD_GETLK`),
  which a description owns, conflicting with each other. A lock on a range
  replaces, splits or merges the owner's own there, as `posix_lock_inode`
  does, and `F_GETLK` reports the first conflicting lock with the PID of the
  process that set it (-1 for a description's), or `F_UNLCK`. The arguments are checked in the
  order of `fcntl_getlk` and `fcntl_setlk` (the whence, the range with
  `EINVAL` or `EOVERFLOW`, the type, `EBADF` for a type the descriptor's
  access does not allow, and an OFD lock's `l_pid`). A table's record locks
  on a file go when a task using it closes any descriptor of the file, or
  when the last task using it exits, not with `fork` or `execve`; an exec,
  `unshare(CLONE_FILES)` or `CLOSE_RANGE_UNSHARE` of a table another task
  shares gives the caller a copy that owns none of them. A description's go
  when its last descriptor closes. `F_SETLKW` waits until the range is free,
  `EDEADLK` when the record locks of tables waiting for each other (up to
  10) would close a cycle. A
  wait counts for that only while the lock it waits for stays as it was:
  unlocking, changing or closing it ends the wait there at once, as
  `locks_wake_up_blocks` does, even before the waiter runs again. The
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
- `sendmmsg` and `recvmmsg` send and receive each message of their vector
  as `sendmsg` and `recvmsg` do, on any socket, writing its byte count to
  its `msg_len`, as Linux's `__sys_sendmmsg` and `do_recvmmsg`.
  `MSG_CMSG_COMPAT` is `EINVAL`; `sendmmsg` sends at most 1024 and stops
  after a message only part of which went. Both stop at an error, which they
  give only when no message went, and give the count otherwise.
  `MSG_WAITFORONE` waits for the first message only, and `recvmmsg` stops
  after out-of-band data. Its timeout is read (`EFAULT`) and checked
  (`EINVAL`) before the descriptor, but, as on Linux, it is looked at only
  after each message, so the first is waited for without it; the time left
  is written back once a message came.
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

  `ESRCH` when no thread, process, group or session has the ID, whichever
  kind of owner it names, as Linux finds the ID. `F_GETOWN` and
  `F_GETOWN_EX` read it back, as 0 while nothing is there in that role
  (such as a group no process is in), and `F_SETSIG` picks the signal.
  Only pipes, sockets, pseudo-terminals and inotify instances, and the host's
  standard streams when they are a pipe, a socket or a terminal, keep
  `O_ASYNC` (`F_SETFL` drops it on other files, and `FIOASYNC` setting it
  there is `ENOTTY`). With it, a pipe, socket or pseudo-terminal (as the
  pseudo-terminals below say) sends its owner `SIGIO` from the kernel, and an
  inotify instance `POLL_IN` once for each event it queues (none for one
  merged into the event before it), as `fsnotify_insert_event`'s
  `kill_fasync` does. With `F_SETSIG`, it sends that
  signal instead, with `si_code` (`POLL_IN`, `POLL_OUT`, `POLL_ERR`,
  `POLL_PRI` or `POLL_HUP`), `si_band`, and the descriptor `O_ASYNC` was set
  through as `si_fd`.
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
    data, end or hang-up that ends the wait, as Linux holds it back
    (`SOCKWQ_ASYNC_WAITDATA`); of a send in parts, only the first. Linux
    holds it back only when the reader has not run yet, as it wakes the
    reader before it looks, so for a send, the peer's shutdown or its
    close Linux sometimes signals; the emulator never does. A datagram or
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
- `mmap` and `shmat` make a mapping and attach the file, the shared memory or
  the segment to it under one hold of the address space's lock, as Linux does
  under its `mmap_lock`. With `MAP_FIXED`, or `SHM_REMAP`, the unmap of what
  was in the range goes under the same hold. So another thread neither maps
  the range in between nor sees the new mapping before it shows what it maps.
  The page cache is read first, outside the lock. `MAP_FIXED_NOREPLACE` gives
  `EEXIST` when anything is mapped there, before the file is asked. When the
  backing cannot be attached, the new mapping goes and what it replaced stays
  gone.
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
- `cachestat` (Linux 6.5) counts the pages of a byte range (to the end of the
  file for a length of 0) that the file's page cache holds. A file in memory
  holds its allocated pages, as tmpfs does, none of them dirty or under
  writeback, as tmpfs tags none, and none evicted, as nothing is swapped out.
  A pipe, a directory, `/proc` and a file in a mounted host directory hold
  none here. As Linux checks, the descriptor must not be `O_PATH` (`EBADF`),
  both structs must be readable and writable (`EFAULT`), and a description
  open to read only needs a caller that owns or may write the file
  (`EPERM`) before an unknown flag is `EINVAL`.
- `mlock`, `mlock2` and `munlock` check their range as Linux does: the length
  rounds up to pages, a range past the end of addresses is `EINVAL`, and one
  with a page that is not mapped is `ENOMEM`, once the VMAs before it took
  the new state. A lock (`VM_LOCKED`, with `MLOCK_ONFAULT` also
  `VM_LOCKONFAULT`) makes VMAs of their own, as `/proc/<pid>/maps` shows.
  It needs a `RLIMIT_MEMLOCK` above 0 (`EPERM`) and room under it for the
  pages not locked yet (`ENOMEM`), unless the caller has `CAP_IPC_LOCK`.
  `mlock` and `mlock2` without `MLOCK_ONFAULT` then bring the pages in, and
  give `ENOMEM` for one that cannot be (`PROT_NONE`, a guard page, past the
  end of its file). `mlockall` locks every mapping with `MCL_CURRENT`
  (`ENOMEM` when all that is mapped does not fit) and every new one with
  `MCL_FUTURE`, which `mmap`, `brk` and a growing `mremap` then need room
  for (`EAGAIN`; `brk` keeps the break), as `MAP_LOCKED` does; `munlockall`
  undoes both. A locked VMA refuses `MADV_DONTNEED`, `MADV_FREE`,
  `MADV_COLD`, `MADV_PAGEOUT`, `MADV_REMOVE` and `MADV_GUARD_INSTALL`
  (`EINVAL`, after the VMAs before it took the advice) and `msync` with
  `MS_INVALIDATE` (`EBUSY`); `MADV_DONTNEED_LOCKED` takes it. A `fork`ed
  child has no lock, nor does the old range `MREMAP_DONTUNMAP` leaves, and
  the rings of AIO and `io_uring` are never locked. Unknown flags of
  `mlock2` and `mlockall` give `EINVAL`. Nothing is ever swapped out, so
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
  The access-pattern hints and `MADV_WILLNEED` are accepted, and so are
  `MADV_COLD` and `MADV_PAGEOUT` (with nothing to reclaim, hints too),
  `MADV_MERGEABLE`, `MADV_UNMERGEABLE`, `MADV_HUGEPAGE` and
  `MADV_NOHUGEPAGE`, whose flags no page here depends on: each needs only
  the range mapped (`ENOMEM`). `MADV_DONTNEED_LOCKED` discards as
  `MADV_DONTNEED` does. `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE`
  fault the pages in, as a read or a write would (the zero page, a page of
  its own), up to a page no mapping holds (`ENOMEM`), one its mapping may
  not read or write (`EINVAL`), or one past the end of its file (`EFAULT`).
  `MADV_DONTFORK` and `MADV_DOFORK`, `MADV_WIPEONFORK` and
  `MADV_KEEPONFORK`, and `MADV_DONTDUMP` and `MADV_DODUMP` set and clear
  flags of the VMAs of the range, which then split from and merge with
  their neighbours as Linux's do (`/proc/<pid>/maps`). They go VMA by VMA:
  one that refuses the advice stops it with `EINVAL` (`MADV_WIPEONFORK`
  takes only private anonymous memory), and a hole in the range gives
  `ENOMEM` after the rest has taken it. A `fork`ed child gets no mapping
  `MADV_DONTFORK` marked, and a mapping `MADV_WIPEONFORK` marked without
  its pages, as new zero-filled memory; it keeps that flag and
  `MADV_DONTDUMP`. A core dump holds nothing of a mapping `MADV_DONTDUMP`
  marked. `MADV_REMOVE` frees shared memory as a hole punched in its file
  (`fallocate` with `FALLOC_FL_PUNCH_HOLE`), so that the range reads as
  zeros in every mapping of it: shared anonymous memory, a System V
  segment, or a file mapped shared through a description that may write
  it, even read-only (`VM_MAYWRITE`). Memory of no file gives `EINVAL`, a
  private or read-only file mapping `EACCES`, and the file's own checks
  their errors, VMA by VMA as the other advice goes. `MADV_GUARD_INSTALL`
  makes the pages of the range guard pages, as Linux's guard PTE markers:
  their contents go (a file mapping's read the file again), and an access
  to one raises `SIGSEGV` with `SEGV_MAPERR`, as one to no mapping would,
  and a system call's copy gives `EFAULT`, as do `MADV_POPULATE_READ` and
  `MADV_POPULATE_WRITE`; `mlock`, which cannot bring one in, gives
  `ENOMEM`. Guards split no VMA, stay through `MADV_DONTNEED` and other
  installs, go to a `fork`ed child (not with `MADV_WIPEONFORK`), move with
  `mremap`, and go with `munmap`. `MADV_GUARD_REMOVE` takes them out,
  leaving pages without contents. Sealed memory whose pages may not be
  discarded takes none (`EPERM`), and the rings of AIO and `io_uring`,
  which Linux maps `VM_DONTEXPAND`, take neither advice (`EINVAL`). Other
  advice gives `EINVAL`.
- `process_madvise` advises each range of its iovecs in turn, of the caller's
  memory (`PIDFD_SELF_THREAD`, `PIDFD_SELF_THREAD_GROUP`, or a pidfd of its
  own process or of one sharing its memory) as `madvise` does, and gives the
  bytes of the ranges before the first that fails, or that one's error.
  Another process's memory takes only `MADV_COLD`, `MADV_PAGEOUT`,
  `MADV_WILLNEED` and `MADV_COLLAPSE` (`EINVAL`), with `CAP_SYS_NICE`
  (`EPERM`), and its ranges need only be mapped (`ENOMEM`). The checks come
  in Linux's order: `flags`, the iovecs, the pidfd (`EBADF`, `ESRCH`), the
  caller's right to read the process (`EACCES`), then the advice.
- `process_mrelease` finds its process as `process_madvise` does (`flags`
  must be 0, then `EBADF`, `ESRCH`); a process that has exited has no
  memory left (`ESRCH`, as a zombie). It succeeds when that memory is on
  its way to be freed: the process is dying (a fatal signal was sent to
  it, or it has begun to exit, and it is not writing a core dump), and so is
  every other process that runs in its memory. Otherwise it gives
  `EINVAL`, as for the caller itself. A signal is fatal as it is sent, as
  Linux's `complete_signal` starts the group exit then, when it is SIGKILL,
  or when its action is the default one, which ends the process without a
  core (not SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV,
  SIGXCPU, SIGXFSZ or SIGSYS, which their taker dumps), the thread it goes
  to (or one of the process's) does not block it, and the process is not
  stopped. The memory goes as the process's last thread ends, so there is
  nothing more to release early.
- `mremap` grows a mapping in place when the pages after it are free, and
  otherwise moves it with its contents under `MREMAP_MAYMOVE`; `MREMAP_FIXED`
  and `MREMAP_DONTUNMAP` work too. Shared memory stays shared with a `fork`ed
  process when it moves. A file mapping grows over more of the file, whose
  pages it reads when they are first touched, and moving a range that spans
  several mappings with `MREMAP_FIXED`, which recent Linux allows, gives
  `EFAULT`.
- `msync` checks its arguments and the range, and with `MS_SYNC` or
  `MS_ASYNC` writes the stores of shared file mappings back to their files.
- `remap_file_pages` maps a range of a shared mapping again at another page
  of its file or shared memory, as Linux's `mmap` of the mapping's own file
  does, keeping its protection. As on Linux, `prot` must be 0 and the range
  must lie in shared mappings of the same memory that may write, with no
  hole (`EINVAL`), and a page past what a file can reach is `EOVERFLOW`.
- System V shared memory (`shmget`, `shmat`, `shmdt`, `shmctl`) belongs to
  the thread's IPC namespace, with Linux's checks in Linux's order and its
  default limits; a new IPC namespace starts with no segments. A segment's ID is its index and a sequence number, given
  out in turn as Linux gives them, and `/proc/<pid>/maps` names an attachment
  `/SYSV<key> (deleted)` on device 00:01, with the ID as its inode. The count
  of attachments (`shm_nattch`) counts each VMA that shows the segment, in
  every process, as Linux does: a `fork` copies them, and `munmap` and an
  `mprotect` that changes part of one split them, and they never merge.
  `shmdt` takes every piece of the attachment that `munmap` and `mprotect`
  left. A segment removed with `IPC_RMID` while attached keeps its ID, is
  found by no key, and goes at its last detach. `SHM_LOCK` checks the owner
  and `RLIMIT_MEMLOCK` as Linux does, and `SHM_HUGETLB` gives `ENOSYS`, as
  from a kernel built without hugetlbfs.
- System V semaphores (`semget`, `semop`, `semtimedop`, `semctl`) belong to
  the thread's IPC namespace too, with Linux's checks in Linux's order (as
  `ipc/sem.c`) and its default limits (`SEMMSL` 32000, `SEMMNS`
  1024000000, `SEMOPM` 500, `SEMMNI` 32000, `SEMVMX` 32767); a set's IDs are
  given out as a segment's. `semctl` has `IPC_STAT`, `IPC_SET`, `IPC_RMID`,
  `IPC_INFO`, `SEM_INFO`, `SEM_STAT`, `SEM_STAT_ANY`, `GETVAL`, `SETVAL`,
  `GETALL`, `SETALL`, `GETPID` (in the caller's PID namespace), `GETNCNT`
  and `GETZCNT` (counted by the operation each wait waits on). The
  operations of one call are done all at once or not at all; one that
  cannot go through waits, unless the operation it would wait on has
  `IPC_NOWAIT` (`EAGAIN`), until a change lets it through, the set is
  removed (`EIDRM`), a signal comes (`EINTR`, never restarted, as Linux) or
  `semtimedop`'s timeout passes (`EAGAIN`). A change tries the waits as
  Linux's `do_smart_update`: the waits for zero first, then the others in
  the order they began. `SEM_UNDO` keeps the adjustments in the process's
  undo list, which `CLONE_SYSVSEM` shares (`pthread_create` passes it) and
  a `fork` does not; `SETVAL` and `SETALL` clear them. The last thread that
  shares the list applies it as it ends, or as it leaves it with `unshare`
  (`CLONE_SYSVSEM` or `CLONE_NEWIPC`) or `setns` to another IPC namespace,
  cut to 0 and `SEMVMX` as Linux cuts them.
- System V message queues (`msgget`, `msgsnd`, `msgrcv`, `msgctl`) belong to
  the thread's IPC namespace too, with Linux's checks in Linux's order (as
  `ipc/msg.c`) and its default limits (`MSGMAX` 8192, `MSGMNB` 16384,
  `MSGMNI` 32000). A queue holds as many bytes as its `msg_qbytes`, and as
  many messages; a send to a full one waits, unless `IPC_NOWAIT`
  (`EAGAIN`), until a receive or `IPC_SET` makes room, the queue is
  removed (`EIDRM`) or a signal comes. `msgrcv` takes the first message, the
  first of a type, the first of another type (`MSG_EXCEPT`) or the lowest
  type up to a bound (a negative `msgtyp`); one longer than the buffer is
  `E2BIG`, unless `MSG_NOERROR` cuts it, and `MSG_COPY` with `IPC_NOWAIT`
  copies the message at a position and leaves it. With none, it waits,
  unless `IPC_NOWAIT` (`ENOMSG`), in the queue's list of receivers: a
  message sent goes to the first that takes it, as Linux's
  `pipelined_send`, which tells one whose buffer is too small `E2BIG`. A
  signal ends either wait with `EINTR`, which a signal that runs no
  handler restarts (`ERESTARTNOHAND`). `msgctl` has `IPC_STAT`, `MSG_STAT`,
  `MSG_STAT_ANY` (the processes in the caller's PID namespace), `IPC_SET`
  (past `MSGMNB` with `CAP_SYS_RESOURCE`), `IPC_RMID`, `IPC_INFO` and
  `MSG_INFO`.
- POSIX message queues (`mq_open`, `mq_unlink`, `mq_timedsend`,
  `mq_timedreceive`, `mq_notify`, `mq_getsetattr`) are the files of the
  thread's IPC namespace's own `mqueue` filesystem, with Linux's checks in
  Linux's order (as `ipc/mqueue.c`). Its root is sticky and anyone may
  write to it: a name is looked up there (`EACCES` for `.`, `..` or one with
  a `/`, `ENAMETOOLONG` past 255 bytes), opening an existing queue checks
  its permissions, and only the queue's owner, the root's owner (whoever
  made the IPC namespace, as its filesystem IDs were) or `CAP_FOWNER`
  unlinks it (`EPERM`).
  The namespace's limits are its `/proc/sys/fs/mqueue` files, and a new
  one starts with Linux's defaults: 256 queues (`queues_max`, `ENOSPC`),
  at most 10 messages (`msg_max`) of at most 8192 bytes (`msgsize_max`),
  and the same defaults (`msg_default`, `msgsize_default`), of which a
  queue made without attributes takes the smaller of each and its limit;
  `CAP_SYS_RESOURCE` passes the limits and allows up to 65536 messages of
  16 MiB. Until it is unlinked and closed, a queue charges its bytes and
  Linux's bookkeeping of each message (48 + 48 bytes on x86-64) as Linux's
  `inc_rlimit_ucounts` does (`EMFILE` past any limit): to its creator's
  real user ID in the creator's user namespace, against the creator's
  `RLIMIT_MSGQUEUE`, and for each user namespace the creator is in, to the
  namespace's owner in its parent, against the `RLIMIT_MSGQUEUE` the owner
  had when it made the namespace. `mq_open` gives a close-on-exec
  descriptor, which `fork` shares with its `O_NONBLOCK` (which
  `mq_getsetattr` and `fcntl` both set): `poll`, `select` and `epoll` find
  it readable with a message and writable with room, whatever its access
  mode, and each message queued wakes an edge-triggered `epoll` again;
  `read` gives the state line Linux's does (`QSIZE`, `NOTIFY`, `SIGNO`,
  `NOTIFY_PID`) from the file position, `fstat` a regular file of 80 bytes
  whose modification time is that of the last send or receive (or its
  creation; not of a failed one, `mq_notify`, `mq_getsetattr` or `read`),
  in whole seconds, as the `mqueue` filesystem keeps its times (it sets no
  `s_time_gran`), `fchmod`, `fchown` and `futimens` change it (a time to
  the second), `ftruncate` sets the size it reports and its modification
  time, as Linux's `simple_setattr` does (`EINVAL` past 2^31 − 1 bytes,
  since `mq_open` gives no `O_LARGEFILE`, and without write access), the
  end `lseek` finds is that size, `fstatfs` reports the `mqueue`
  filesystem (`MQUEUE_MAGIC`, a page per block, 255-byte names), and its
  link in `/proc/self/fd` is
  `/<name>`, followed by a space and `(deleted)` once unlinked, which an
  open follows to the same queue, with its permissions for the access
  mode and `O_TRUNC` (`EACCES`, and `ENOTDIR` with `O_DIRECTORY`). Messages come highest
  priority first (below 32768, `EINVAL`), in the order sent within one. A
  receive into a buffer smaller than `mq_msgsize` is `EMSGSIZE`, and so is
  a longer send. A receive from an empty queue and a send to a full one
  give `EAGAIN` with `O_NONBLOCK`, else wait until the absolute
  `CLOCK_REALTIME` timeout (`ETIMEDOUT`, read and checked first: `EFAULT`,
  `EINVAL`) or a signal (`EINTR`, which `SA_RESTART` and a signal that runs
  no handler restart, as `ERESTARTSYS`). The waiting receivers take
  messages in the order they began, straight from the sender as Linux's
  `pipelined_send`, and a waiting sender's message takes the room a
  receive makes (`pipelined_receive`). `mq_notify` registers the calling
  process (`EBUSY` while another is registered; no notification drops only
  the caller's own) to hear of a message that comes to the empty queue
  while no receiver waits, once: `SIGEV_SIGNAL` sends its signal with
  `si_code` `SI_MESGQ`, the sender's process and real user ID and the
  `sigev_value` (signal 0 sends nothing), unless the process has run
  `execve` since; `SIGEV_NONE` only ends the registration; `SIGEV_THREAD`
  copies 32 bytes from `sigev_value` and sends them to the netlink socket
  `sigev_signo` names (`EBADF`, `ENOTSOCK`, or `EINVAL` for another
  socket) as a datagram whose last byte is 1 (`NOTIFY_WOKENUP`), or 2
  (`NOTIFY_REMOVED`) when the registration ends without a message, which is
  what the C libraries' helper threads read to start the
  `sigev_notify_function`. The cookie takes room in that socket's receive
  buffer from the registration on, as Linux's `netlink_attachskb` charges
  it, until it is received: while the socket holds something and has no
  room for it, or is held congested (`NETLINK_S_CONGESTED`, under the netlink socket below), `mq_notify` waits, before
  it looks the queue up, until a receive makes room or empties it (a
  signal ends the wait, `EINTR`, unless
  `SA_RESTART` restarts it), and gives the room back if it then fails.
  Closing any descriptor of the queue, or ending,
  drops its process's registration, as Linux's `mqueue_flush_file`.
- `/dev/mqueue` is the first IPC namespace's `mqueue` filesystem, as
  systemd mounts it when Linux boots, whatever IPC namespace the caller is
  in: a sticky directory anyone may write (01777, its maker's), which
  `/dev` lists and which lists the queues as regular files, the files
  `stat` as `mq_open` makes them. Opening one gives a descriptor the `mq_*`
  calls take, with the same checks (`EACCES`), `EEXIST` with
  `O_CREAT | O_EXCL`, `ENOENT` without `O_CREAT` and `ENOTDIR` with
  `O_DIRECTORY`; `O_CREAT` makes a queue of the namespace's default
  attributes (`mqueue_create`), and `O_TRUNC`, which needs write
  permission whatever the access mode, empties a queue that was there and
  stamps its modification time (`handle_truncate`). Its link in `/proc/self/fd` reads
  `/dev/mqueue/<name>`. `unlink` removes a queue as `mq_unlink` does
  (`rmdir` of one is `ENOTDIR`). A queue's path takes `chmod`, `chown`,
  `utimensat`, `utimes` and `truncate`, which change its file as its
  descriptor's calls do, with the same permission checks (`EPERM`,
  `EACCES`), except that a truncate of the path leaves the modification
  time and may reach 2^31 − 1 bytes (`EFBIG` past them, as the
  superblock's `s_maxbytes`), and `statfs` reports the `mqueue`
  filesystem. The root's size is 20 bytes for each entry (`.`, `..` and
  each queue, `DIRENT_SIZE`), and its modification time is when its
  namespace was made, or a queue was last made or unlinked there.
  `chmod`, `chown` and `utimensat` of `/dev/mqueue`, and `fchmod`,
  `fchown` and `futimens` of an open of it, change the root (a
  `truncate` is `EISDIR`), and its mode then rules what others may do:
  a lookup of a name there searches it (`EACCES`), opening it reads it,
  making a queue (`mq_open` too) and unlinking one write and search it
  (`may_create`, `may_delete`), the sticky bit limits unlinking to the
  queue's owner, the root's or `CAP_FOWNER`, and `mq_open` of a queue
  that is there does not search it (`lookup_noperm`). Landlock checks a
  `link` or `rename` within it (`EACCES`) before the root refuses it. The
  root has no operations but to look up, make a queue and unlink one: a
  new name there that is free (else `EEXIST`, as `/dev/mqueue` itself
  is) gives `mkdir`, `symlink` and
  `mknod` of anything but a regular file `EPERM`, after Landlock's check,
  and `mknod` of a regular file (or of type 0) makes a queue of the
  default attributes, as `vfs_create` does. `link` and `rename` look the
  names up as `do_linkat` and `do_renameat2` do (`ENOENT`, `EEXIST`, with
  `RENAME_NOREPLACE` and `RENAME_EXCHANGE` as there), give `EXDEV` to or
  from another mount once both paths are walked (searching each directory
  on the way, `EACCES`; `rename` before it looks the names up), and
  `EPERM` within it, but for a `rename` of a name onto itself, which does
  nothing.
- `sched_getaffinity` lets every guest thread run on each of the host's CPUs,
  so the guest sees as many CPUs as the host has (one in WebAssembly).
  `sched_setaffinity` keeps a mask for a thread of the process, as Linux
  reads it: up to a CPU mask's size (a shorter one counts the rest as clear),
  only the host's CPUs, and `EINVAL` if none is left. `sched_getaffinity`
  then gives that mask, and new threads and processes inherit it, but the
  host still runs the thread on any of its CPUs. Both find a thread of
  another process too, as root may, and give `ESRCH` when no live thread
  has the ID. `getcpu` gives NUMA node 0, and the virtual CPU of a thread
  that has registered `rseq`; for another thread, the lowest CPU its mask
  allows.
- Each thread has scheduling attributes, as on Linux: a policy
  (`SCHED_OTHER`, `SCHED_BATCH`, `SCHED_IDLE`, `SCHED_EXT`, `SCHED_FIFO`,
  `SCHED_RR`, `SCHED_DEADLINE`), a real-time priority, `SCHED_RESET_ON_FORK`,
  the deadline task's runtime, deadline and period, the normal policy's
  slice and the utilization clamps. `sched_setscheduler`, `sched_setparam` and
  `sched_setattr` set them with Linux's checks in its order (the arguments,
  the policy and priority, the deadline parameters, then the permission:
  without `CAP_SYS_NICE` a real-time policy needs `RLIMIT_RTPRIO`, a lower nice
  value `RLIMIT_NICE`, and no user may take `SCHED_DEADLINE`, leave `SCHED_IDLE`
  or clear the reset flag). `sched_setattr` reads `struct sched_attr` as Linux
  does (`E2BIG` with the size written back), keeps the policy or parameters
  for `SCHED_FLAG_KEEP_POLICY` and `SCHED_FLAG_KEEP_PARAMS`, and admits a
  deadline task as Linux 6.12 does: on every CPU of its mask (`EPERM`), within
  95% of each CPU less the 5% its fair server takes (`EBUSY`).
  `sched_getscheduler`, `sched_getparam` and `sched_getattr` report them, for a
  thread of any process; `sched_getattr` gives a normal policy's nice value
  and its slice as `sched_runtime`, and fills a buffer larger than the
  structure with zeros, as Linux 6.13 and later. New threads and processes inherit them, as
  Linux's `sched_fork` has it: with the reset flag a real-time or deadline
  task's child is a normal one with nice 0 and no flag, and a deadline task
  may not fork (`EAGAIN`); `sched_setaffinity` keeps every CPU for a
  deadline thread (`EBUSY`). The host still runs every guest thread as a
  normal one. `sched_get_priority_max` and `sched_get_priority_min` give
  Linux's 99 and 1 for `SCHED_FIFO` and `SCHED_RR` and 0 for the other
  policies. `sched_rr_get_interval` gives 100 ms under `SCHED_RR`, 0 under
  `SCHED_FIFO` and `SCHED_DEADLINE`, and otherwise the thread's slice in whole
  ticks: the slice `sched_setattr` asked for (0.1 ms to 100 ms), or the one
  the host's scheduler gives its threads on a Linux host, whose threads run
  the guest's; elsewhere Linux 6.12's default at 1000 Hz, 0.75 ms times 1 +
  log2 of the CPUs (at most 8).
- `ioprio_set` and `ioprio_get` find threads as `getpriority` does
  (`IOPRIO_WHO_PROCESS`, `IOPRIO_WHO_PGRP`, `IOPRIO_WHO_USER`). `ioprio_set`
  checks the priority first, as Linux's `ioprio_check_cap` (a known class, a
  real-time one only with `CAP_SYS_NICE` or `CAP_SYS_ADMIN`), then gives it to
  each thread whose real user ID is the caller's real or effective one
  (`EPERM` otherwise, without `CAP_SYS_NICE`). `ioprio_get` reports the
  priority a thread was given, and 0 for one that never had one or was given
  the class none, whatever its nice value; for several threads, the best as Linux's
  `ioprio_best` compares them (one without a class counts as best-effort
  level 4). A priority with a class passes to new threads and processes.
- `kcmp` finds each thread as the caller's PID namespace numbers it
  (`ESRCH`) and needs to be allowed to read both, as `ptrace_may_access` in
  read mode with the real IDs decides (`EPERM`). It then compares, as Linux's
  `kernel/kcmp.c`, an open file of each by descriptor (`EBADF`), the memory,
  the descriptor table, the working directory and umask (`CLONE_FS`), the
  signal dispositions, the I/O context `ioprio_set` gives, the System V
  semaphore undo list, or a file with one an epoll instance of the second
  thread watches (`KCMP_EPOLL_TFD`: `EFAULT`, `EBADF`, `EINVAL` for a file
  that is not epoll, `ENOENT`). It gives 0 for the same object, and 1 or 2
  for others in an order that random cookies make, as Linux hides the
  objects' addresses. A thread without one (an ended process, a thread with
  no I/O context or undo list) compares equal to another without.
- `process_vm_readv` and `process_vm_writev` check as Linux's
  `mm/process_vm_access.c` does: `flags` must be 0 (`EINVAL`), then the local
  iovec array as `readv` reads it, then the remote one (more than 1024
  entries or a negative length `EINVAL`, an array that cannot be read
  `EFAULT`, its buffers not looked at yet); with no bytes to copy on either
  side they return 0 before the thread is looked for. `pid` names a thread as
  the caller's PID namespace numbers it (`ESRCH`, also for a zombie), whose
  memory the caller must be allowed to attach to unless it is its own, as
  `ptrace_may_access` in attach mode with the real IDs decides (`EPERM`).
  They copy each remote buffer in turn while the local buffers have room: a
  remote page that is not mapped, is not mapped with `PROT_READ` (to read;
  `PROT_WRITE` or `PROT_EXEC` alone is not enough, as Linux's `VM_READ`) or
  without `PROT_WRITE` (to write), or a local byte that cannot be written or
  read, ends the copy, which gives the bytes copied before it, or `EFAULT`
  with none.
- `pidfd_getfd` takes no flags (`EINVAL`) and a pidfd (`EBADF`), and needs
  the caller to be allowed to attach to its process as above (`EPERM`); a
  process that has exited, reaped or not, is `ESRCH`, and a descriptor it
  does not have `EBADF`. The copy shares the open file description and
  gets the lowest free number, close-on-exec (`EMFILE` at
  `RLIMIT_NOFILE`).
- Whether a caller may read or attach to a thread of another process is
  decided as Linux's `__ptrace_may_access` with the capability module and
  Yama decides it. To read (`kcmp`, `get_robust_list`, `/proc/<pid>/environ`
  and the like, `move_pages`, `migrate_pages`, `setns` with a pidfd), it needs
  `CAP_SYS_PTRACE` in the target's user namespace, or a dumpable target whose
  user and group IDs all equal its own (real or filesystem ones, as the call
  asks), in the same user namespace, with its permitted capabilities (its
  effective ones for the filesystem ones) covering the target's permitted
  ones; Landlock then keeps a caller in a domain from a task outside it. To
  attach (`process_vm_readv`, `process_vm_writev`, `pidfd_getfd`), Yama's
  `ptrace_scope` is 1, as Debian's, Ubuntu's and the CI runners' is: the
  target must also be a descendant of the caller, or have let it in with
  `PR_SET_PTRACER`, or the caller must have `CAP_SYS_PTRACE` in the target's
  user namespace.
- `personality` keeps any value for the thread, as Linux stores it, and
  returns the old one (`0xffffffff` only asks). New threads and processes
  inherit it, and `execve` keeps it but for `READ_IMPLIES_EXEC`, and
  `PER_CLEAR_ON_SETID` for a set-ID program. Three settings change what the
  guest sees, as on Linux: `PER_LINUX32` makes `uname` report `i686`,
  `UNAME26` a 2.6 release (`2.6.72`), and `READ_IMPLIES_EXEC` makes what
  `mmap` and `mprotect` map readable executable too. Two more take effect at
  the next `execve`, as Linux's `load_elf_binary` applies them:
  `ADDR_COMPAT_LAYOUT` places mappings without a fixed address, the
  interpreter's too, upward from `TASK_UNMAPPED_BASE` (a third of the address
  space) instead of down from the top, and `MMAP_PAGE_ZERO` maps page 0
  readable and executable when the new credentials have `CAP_SYS_RAWIO`.
  `ADDR_NO_RANDOMIZE` is kept only, as nothing is randomized to begin with,
  and so are the flags that do nothing on x86-64 Linux either
  (`ADDR_LIMIT_32BIT`, `SHORT_INODE`, `WHOLE_SECONDS`, `STICKY_TIMEOUTS`,
  ...).
- `mprotect` checks its arguments in Linux's order: both `PROT_GROWSDOWN`
  and `PROT_GROWSUP`, a misaligned start, an empty range (which succeeds
  whatever the bits), an end that overflows (`ENOMEM`), then unknown bits.
  `PROT_GROWSDOWN` extends the range down to the start of the first VMA in
  it, which must grow down (the main stack), else `EINVAL`; `PROT_GROWSUP` is
  `EINVAL` on a mapped start, as no VMA grows up on x86-64. Where no VMA is
  in the range, both give `ENOMEM`.
- Protection keys answer as Linux does on a CPU without them, which the
  virtual CPU is (`CPUID` reports no PKU): no key is ever allocated, not even
  the default key 0. `pkey_alloc` gives `ENOSPC`, or `EINVAL` for a flag or
  for rights other than `PKEY_DISABLE_ACCESS` and `PKEY_DISABLE_WRITE`;
  `pkey_free` gives `EINVAL`; and `pkey_mprotect` with key `-1` is `mprotect`,
  while any other key gives `EINVAL` after the checks Linux makes first (an
  empty range succeeds, an overflowing one gives `ENOMEM`).
- `mseal` seals mappings as Linux's `mm/mseal.c` does. It takes no flags and a
  page-aligned start, and a length that wraps or runs past the top is
  `EINVAL`; a range with an unmapped page is `ENOMEM`, and seals nothing.
  Each refusal of a sealed mapping is `EPERM`:
  - `munmap` unmaps nothing of a range that holds one, and neither `mmap` with
    `MAP_FIXED`, `mremap` (of it, or with `MREMAP_FIXED` onto it),
    `remap_file_pages` nor a shrinking `brk` replaces it (`brk` keeps the
    break).
  - `mprotect` and `pkey_mprotect` change the mappings before the first
    sealed one in the range and stop there, as Linux's per-VMA loop does,
    even for the protection it already has.
  - `MADV_DONTNEED` and `MADV_FREE` do not discard a sealed private anonymous
    mapping that may not be written; a writable or file mapping may still be.
  - `shmdt` of a sealed attachment succeeds and leaves it mapped, as Linux
    ignores its failed unmap.
  - A child of `fork` keeps the seals; `exec` starts without any.
- io_uring is Linux 6.12's with two operations, `IORING_OP_NOP` and
  `IORING_OP_EPOLL_CTL` (which libuv batches its `epoll_ctl` calls with); the
  other operations complete with `EOPNOTSUPP`, as on a Linux built without
  them, and `IORING_REGISTER_PROBE` reports only those two. The rings are
  the sizes, offsets and features Linux gives, and `mmap` of the descriptor
  shows them. A request runs while `io_uring_enter` takes it, so its
  completion is in the queue when the call returns; links, completions that
  skip success, and completions kept while the queue is full
  (`IORING_FEAT_NODROP`) behave as on Linux.
- Linux's native asynchronous I/O (the calls libaio wraps) is `fs/aio.c`'s.
  `io_setup` makes the number of events at least four for each CPU and
  doubles it (`EINVAL` past `0x8000000 / 32`, `EAGAIN` past
  `/proc/sys/fs/aio-max-nr`, alone or with the machine's other contexts),
  and maps the ring where `mmap` would: its header (the context's index,
  the events it holds, the head, the tail, the magic `0xa10a10a1`, the
  features and the header's size of 32) and the events after it, which a
  program may read and take itself, as libaio does; `/proc/self/maps`
  names it `/[aio] (deleted)`. A context ID is the ring's address, and each
  call finds its context by the index in that header (`EINVAL` for none).
  `io_submit` takes at most as many requests as the ring holds, checks each
  as Linux's `io_submit_one` does, in its order (`aio_reserved2`, the
  length, a place in the ring, the file, the eventfd of `IOCB_FLAG_RESFD`,
  clearing `aio_key`, then the operation: `IOCB_CMD_PREAD`, `PWRITE`,
  `PREADV`, `PWRITEV`, `FSYNC`, `FDSYNC` and `POLL`, and `EINVAL` for
  another, `IOCB_CMD_NOOP` too), and gives the count taken before the
  first that fails. A read, write or sync runs as it is taken, at
  `aio_offset` (a pipe, socket or terminal as a stream), with the
  `IOCB_FLAG_IOPRIO` priority and `aio_rw_flags` checked as `preadv2`'s,
  and its event is in the ring before the call returns: a read of an empty
  pipe waits there, and a signal makes its result `EINTR`. A poll completes
  at once with what is ready among its events if its file is ready, else
  waits until it is and then gives the wake-up's whole key, as Linux's
  `aio_poll_wake` does (a pipe's `POLLIN | POLLRDNORM` even for `POLLIN`
  alone; a hang-up, which has no key, what is ready); `io_cancel` cancels
  only a poll that waits (`EINPROGRESS`, with an event of no events in the
  ring), and gives `EINVAL` for another request. `io_getevents` and
  `io_pgetevents` take events from the head and wait for `min_nr` of them
  as Linux's `read_events` does (a negative timeout waits as none does, as
  Linux's): until the timeout, a signal (`EINTR`, never
  restarted for `io_getevents`; `ERESTARTNOHAND` for `io_pgetevents`, whose
  signal mask is in place while it waits), or `io_destroy` from another
  thread (`EINVAL`). An eventfd counts every completion of a request that
  names it. The contexts belong to the address space: threads and
  `CLONE_VM` children share them, a fork's child has none and not their
  rings either (as `VM_DONTCOPY` since 2026), and `execve` or the last exit
  ends them, cancelling their polls.
- `membarrier` has Linux's commands on x86-64 with `CONFIG_RSEQ` and no
  `nohz_full` CPU (`MEMBARRIER_CMD_QUERY` gives `0x3ff`). The private
  commands give `EPERM` until the address space registers for them, a fork
  keeps the registrations and an exec starts with none, and `MEMBARRIER_CMD_GET_REGISTRATIONS`
  reports them with Linux's bits (registering `SYNC_CORE` marks the space
  private too). A barrier is one on every thread of the address space, as
  Linux's interrupts give: most accesses take no lock, so it takes the
  space's locks and moves the epoch of the threads' TLBs on, which waits for
  each store under way and sends each thread's next access to the locks.
  `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ` also aborts the `rseq` critical
  sections of the space's other threads (with `MEMBARRIER_CMD_FLAG_CPU`,
  of the one on that CPU, and of none for a CPU the machine does not have),
  and returns once each of them that was running guest code has stopped.
- `rseq` registers a thread's area as Linux does, with its checks and
  errors (`EINVAL`, `EPERM`, `EBUSY`, `EFAULT`), and clears the area's
  `rseq_cs` when it registers, as current Linux does. The auxiliary vector
  gives `AT_RSEQ_FEATURE_SIZE` 28 and `AT_RSEQ_ALIGN` 64, as current Linux
  does, so an area longer than 32 bytes is aligned on 64. A thread with
  `rseq` runs on one of the machine's virtual CPUs, one for each CPU it
  reports, where no other such thread runs at the same time, within its
  CPU mask; the area shows that CPU, NUMA node 0 and a concurrency ID
  (`mm_cid`) below the count of CPUs that no other running thread of the
  address space has. It takes the CPU before it runs guest code and leaves
  it at each system call, fault and end of its budget. When it comes back
  to another CPU, or to its own after another thread had it, or after a
  `membarrier`, or when a signal is delivered, a critical section it is in
  goes on at its abort handler, as after Linux's preemption, migration or
  signal. As current Linux, the kernel reads only where the section is
  while the thread is outside it, and then clears the area's `rseq_cs`, and
  reads neither a descriptor's version nor its flags. An abort handler a
  thread inside the section cannot use (inside the section, or without the
  signature before it), a section past user space and an area the kernel
  cannot write end the thread by `SIGSEGV`. While threads wait for
  a CPU, one that has kept its own for 4 ms lets them have it first. A
  fork keeps the registration; a new thread, a `CLONE_VM` child and an
  exec start without one.
- `unshare` with `CLONE_FILES` gives the thread its own descriptor table, and
  with `CLONE_FS` its own working directory and umask, as Linux. With
  `CLONE_THREAD`, `CLONE_SIGHAND` or `CLONE_VM` it succeeds where there is
  nothing to unshare and gives `EINVAL` where Linux does: another thread in
  the process, dispositions shared with another process (`CLONE_SIGHAND`), or
  memory shared with one (`CLONE_VM` without `CLONE_THREAD`). `CLONE_SYSVSEM`
  (and `CLONE_NEWIPC`) leaves the semaphore undo list, as an exit does. Its
  namespace flags give the thread new namespaces, as below.
- Each thread has its own namespaces, as Linux's `nsproxy`: UTS, IPC,
  mount, cgroup, time, PID, network and user ones of its own (the user
  namespace in its credentials). `unshare` with `CLONE_NEWUTS`,
  `CLONE_NEWIPC`, `CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWTIME`,
  `CLONE_NEWPID`, `CLONE_NEWNET` or `CLONE_NEWUSER` gives it new ones, and
  so does `clone` (`CLONE_NEWTIME` through `clone3`) for its child, a thread
  too (but not `CLONE_NEWPID` or `CLONE_NEWUSER`). A new user namespace
  needs no capability; the others need `CAP_SYS_ADMIN` (`EPERM` without
  it) in the user namespace the thread then has, so a new one with them
  gives it. A new UTS namespace starts
  with a copy of the host and domain names, which `sethostname` and
  `setdomainname` then change for it alone. A new time namespace is the one
  the thread's children enter: a child that does not share its memory
  enters it, and so does the thread when it runs a program. `clone` refuses
  `CLONE_NEWNS` with `CLONE_FS` and `CLONE_NEWIPC` with `CLONE_SYSVSEM`
  (`EINVAL`), as Linux does. `/proc/<pid>/ns` (and `/proc/thread-self/ns`
  and `/proc/<pid>/task/<tid>/ns`) has Linux's ten links, which read as
  `uts:[4026531838]`; the first namespaces have Linux's fixed numbers and new
  ones are numbered as they are made. A link opens the namespace's file, a
  handle that reads and writes as `EINVAL` and seeks as `ESPIPE`, whose
  inode is that number. `setns` enters the namespace of such a file (its
  kind or 0 for `nstype`), or the namespaces of a pidfd's process that
  `nstype` names, with Linux's checks in Linux's order: a user namespace
  must not be the thread's own, nor be entered by a thread that shares its
  memory or working directory (`EINVAL`), and needs `CAP_SYS_ADMIN` in it,
  which then gives the thread every capability there; a time namespace
  needs the thread alone in its memory (`EUSERS`), a mount namespace
  entered by itself a working directory no other thread shares (`EINVAL`)
  and `CAP_SYS_CHROOT`, and each one `CAP_SYS_ADMIN` in the user namespace
  that owns it and in the thread's own (`EPERM`), and a PID namespace must
  be the thread's own or one nested in it (`EINVAL`). Entering a mount namespace moves the working
  directory to its root, and entering a PID namespace makes it the one the
  thread's children are numbered in; entering a network namespace makes it
  the one the thread's new sockets are in. See [Limitations](./limitations.md)
  for the namespaces paludarium has no new ones of.
- A new user namespace, as Linux's `create_user_ns` makes it, is nested
  in the thread's and owned by its effective user (`EPERM` when that user
  or group has no ID in it, `ENOSPC` past 32 levels); the thread has every
  capability in it, and in the namespaces made with it, which it owns.
  The kernel keeps IDs as the first user namespace has them; a system call
  takes and gives them as the caller's namespace maps them, and an ID it
  does not map shows as 65534 (`overflowuid`) and is `EINVAL` given: the
  `get*id` and `set*id` calls and `setgroups`, `getgroups`, `stat` and
  `statx`, `chown` and its kin, the `si_uid` of a signal and `waitid`,
  `SCM_CREDENTIALS` and `SO_PEERCRED`, `shmctl` and `semctl`,
  `/proc/<pid>/status` and a core. Root is the ID the namespace maps as 0 for the capability rules of
  `set*id`, `access` and exec, and a set-user-ID program whose owner or
  group it does not map runs as the caller. A capability counts in the
  thread's own user namespace and in those nested in it that its
  effective user made (Linux's `cap_capable`): over a file only when the
  namespace maps the file's owner and group, over a namespace (setting
  its host name, entering it, `SIOCSIFFLAGS`, System V shared memory and
  semaphores) as
  the user namespace that owns it has it, over another process (`kill`,
  `ptrace` access, priorities, limits) as its user namespace has it, and
  over the machine (`RENAME_WHITEOUT`, real-time scheduling, `vhangup`, the
  `trusted.*` attributes and the like) only in the first user namespace.
  `/proc/<pid>/uid_map` and `gid_map` read the extents of the task's user
  namespace, the lower IDs as the reader's namespace has them (its parent's
  for its own), and take one write of up to 340 lines of three numbers, in
  Linux's order and with its checks (`proc_uid_map_write`, `map_write`,
  `new_idmap_permitted`): from a thread of the namespace or its parent that
  has `CAP_SYS_ADMIN` in it, its owner may map its own effective ID alone
  (a group only once `setgroups` is denied), and anything else needs
  `CAP_SETUID` or `CAP_SETGID` in the parent; mapping the parent's root needs
  `CAP_SETFCAP`. `/proc/<pid>/setgroups` reads `allow` or `deny`, which
  may be written before the gid map; `setgroups` needs it allowed and the
  gid map written.
- A new PID namespace, as Linux's, is the one the thread's children are
  numbered in; the thread stays in its own, and its `pid_for_children` link
  is `ENOENT` until the first child, the namespace's init, numbered 1. A
  second `CLONE_NEWPID` while the children have a new one is `EINVAL`, and so
  is a thread then, which would be numbered apart from its process; a
  namespace more than Linux's 32 levels below the first is
  `ENOSPC`. A process or thread has a number in its namespace and in each
  one that namespace is in, and a process sees the others as its namespace
  numbers them: a process outside it is 0, and a number it has not handed
  out names nothing. So it is for `getpid`, `gettid`, `getppid`, `getpgid`,
  `getpgrp`, `getsid`, `setsid`, `setpgid`, `kill`, `tkill`, `tgkill`,
  `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `wait4`, `waitid`, `pidfd_open`,
  `getpriority`, `setpriority`, `ioprio_get`, `ioprio_set`, the `sched_*`
  calls, `prlimit64`, `capget`, `capset` and `get_robust_list`; for what
  `clone` returns and stores, `set_tid_address` returns, and the `si_pid` of
  a signal (0 from outside); for `F_SETOWN`, `F_GETOWN`, `F_GETLK`'s `l_pid`,
  `TIOCGPGRP`, `TIOCSPGRP` and `TIOCGSID`; for `SCM_CREDENTIALS` and
  `SO_PEERCRED`; for `shmctl`'s process IDs and `semctl`'s `GETPID`; and
  for a core's. `kill(-1)`
  signals the processes of the caller's namespace but its init. `/proc`
  shows the first namespace's IDs, as Linux's `/proc` mounted in it does,
  and the `NStgid`, `NSpid`, `NSpgid` and `NSsid` lines of
  `/proc/<pid>/status` give a task's IDs there and in each namespace below
  it down to its own (0 for a group or session outside one). `clone3`'s
  `set_tid` gives the numbers a child takes, one for each namespace from
  its own out, as Linux's `alloc_pid` checks them: `EINVAL` for more numbers
  than namespaces, for one below 1 or from 4194304 (Linux's highest
  `pid_max`) on, and for one other than 1 in a namespace with no init yet;
  `EPERM` without `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE` in the user
  namespace that owns the namespace; and `EEXIST` for a number that is
  taken. The first namespace's numbers are the IDs paludarium knows tasks
  by, so there `set_tid` takes an ID no task has had yet.
  The init takes only the signals it has a handler for, and SIGKILL and
  SIGSTOP from outside its namespace or from the kernel (Linux's
  `SIGNAL_UNKILLABLE`); a fault still ends it. Orphans of the namespace come
  to it, or to a child subreaper within the namespace. When it exits, every
  other process of the namespace gets SIGKILL and none may join it any more
  (`ENOMEM`); its parent learns of the exit only once the rest is gone, its
  children reaped by the init, as Linux's `zap_pid_ns_processes`.
- A new network namespace, as Linux's `loopback_net_init` makes it, has a
  loopback alone, `lo` (index 1), which is down: a TCP or UDP socket there
  binds any IPv4 address until IPv4 has a route, but not `::1`
  (`EADDRNOTAVAIL`), and a connection or datagram goes nowhere
  (`ENETUNREACH`). `SIOCSIFFLAGS` with `IFF_UP` (CAP_NET_ADMIN, else
  `EPERM`) brings it up, with `::1`, which it has only while it is up:
  then it is a
  [loopback](#loopback-servers) of its own, whose ports, listeners and
  datagrams are apart from every other namespace's, and anything off it is
  still `ENETUNREACH`, port 53 too, as there is no DNS stub; a session with
  no network has one there all the same. A socket stays in the namespace it
  was made in. An abstract unix socket name (one starting with 0) is bound
  and looked for among the names of the socket's namespace, as Linux's
  `unix_find_abstract`, while a socket file on a path is reached from any
  namespace. `SIOCGIFFLAGS` and `SIOCGIFINDEX` on a socket of any family,
  an AF_UNIX one too (as glibc's and musl's `if_nametoindex` use), read the
  loopback of the namespace the socket was made in, as Linux's `dev_ioctl`
  takes `sock_net` (`IFF_UP | IFF_LOOPBACK | IFF_RUNNING` while it is up,
  in the first namespace too); an accepted AF_UNIX socket is in its
  client's. `SIOCSIFFLAGS` needs CAP_NET_ADMIN in the user namespace that
  owns that namespace, whichever the caller is in. An AF_UNIX socket of a
  first namespace without a network has none (`ENOTTY`). Another interface
  name is `ENODEV`. `SIOCGIFNAME` (`if_indextoname`) names index 1
  `lo` (`ENODEV` for another).
- A netlink socket (`AF_NETLINK`, `SOCK_RAW` or `SOCK_DGRAM`, protocol
  `NETLINK_ROUTE`) shows and changes the loopback of the network namespace
  it was made in, so glibc's and musl's `getifaddrs`, `ip link`, `ip addr`
  (with `ip addr add` and `del`), `ip route` (with `ip route add`, `del`,
  `replace` and `append`), `ip route get`, `ip link set lo up` and
  `ip monitor` work.
  - **The socket:** as Linux's `af_netlink`, `bind` takes a port ID
    (`EADDRINUSE` for one another socket has) or with 0 the process's ID,
    or a negative one when that is taken; `connect` or the first send binds
    an unbound socket the same way; `getsockname` and `getpeername` give
    the port and groups; a datagram to another socket's port reaches it
    (`ECONNREFUSED` for none). `recvmsg` gives the sender's `sockaddr_nl`,
    `MSG_PEEK` and `MSG_TRUNC` work, and `SO_RCVBUF`, `SO_SNDBUF`,
    `SO_RCVTIMEO`, `NETLINK_CAP_ACK`, `NETLINK_EXT_ACK` and
    `NETLINK_GET_STRICT_CHK` can be set. A message from the kernel that
    finds the receive buffer full is dropped, with `ENOBUFS` for the next
    receive, and the socket is then held congested, as Linux's
    `NETLINK_S_CONGESTED`: it drops the kernel's other messages too, with
    no other `ENOBUFS`, until a receive finds its queue empty. A dump's
    parts do not look at it. A datagram from another socket that finds no
    room, or the socket congested, waits for room instead, or is `EAGAIN`
    with `MSG_DONTWAIT` or `O_NONBLOCK`, and overruns nothing.
  - **Requests:** the kernel, port 0, takes each message of a datagram as
    `rtnetlink` does. A dump (`NLM_F_DUMP`) comes in parts as large as
    Linux's `netlink_dump` makes them (a page's worth, or as much as the
    longest receive so far asked for up to 32 KiB, the next as a receive
    makes room), and ends with `NLMSG_DONE` in a part of its own; an
    `AF_INET6` address or link dump's goes after its last message when
    that part has room, as `inet6_dump_ifaddr` and `inet6_dump_ifinfo` put
    it. An error, or a success with `NLM_F_ACK`, is answered with
    `NLMSG_ERROR`, which carries the whole request with an error unless
    `NETLINK_CAP_ACK` is set. Anything but a `GET` needs `CAP_NET_ADMIN` in
    the user namespace that owns the network namespace, for the sending
    thread and the socket's opener (`EPERM`).
  - **Strict checking:** with `NETLINK_GET_STRICT_CHK`, as iproute2 sets
    it, requests are checked as Linux checks them. A dump takes a whole
    header with nothing in it but what may narrow it, and of the
    attributes only those that narrow it, of known types, with no bytes
    left over; anything else ends it with `EINVAL` in `NLMSG_DONE`. An
    address dump's index shows `lo`'s addresses alone (`ENODEV` for
    another), and a route dump's table, protocol, type and `RTA_OIF` show
    the routes they name, all with `NLM_F_DUMP_FILTERED`, a table not made
    being `ENOENT` for a dump of that family alone. `RTM_GETLINK` for `lo`
    takes no flags and only its names, `IFLA_EXT_MASK` and
    `IFLA_TARGET_NETNSID`, and a route lookup only whole prefix lengths and
    the attributes that select a route, as `rtnl_valid_getlink_req`,
    `inet_rtm_valid_getroute_req` and `inet6_rtm_valid_getroute_req`.
    Checked or not, a link dump's `IFLA_MASTER` shows no device, as `lo`
    has no master, and `IFLA_TARGET_NETNSID` is `EINVAL`, as no other
    namespace has an ID; `RTM_F_PREFIX` dumps no route, as `lo` has no
    prefix route.
  - **Attribute policies:** each request's attributes are checked first,
    in their order, against the policy Linux has for it (`ifla_policy`,
    `ifa_ipv4_policy`, `ifa_ipv6_policy`, `rtm_ipv4_policy`,
    `rtm_ipv6_policy`, and `ifla_info_policy` inside a new link's
    `IFLA_LINKINFO`), after only the checks of the header that Linux
    makes before them: an integer shorter than its type, a string or
    binary longer than its policy's, an empty string or an integer out of
    its range is `ERANGE`, a rejected attribute (`IFLA_PERM_ADDRESS` and
    others) `EINVAL`, and so is an attribute of a type from the policy's
    `strict_start_type` on (`RTA_NH_ID`, `IFLA_DPLL_PIN`) that is of
    another length, marked nested or not, or not named. Strictly, a type
    of 0 or past the last and bytes left over are `EINVAL`; unchecked, they
    are passed over, and a link dump whose attributes break the policy
    takes none of them. A change of the link takes one of
    `IFLA_NET_NS_PID`, `IFLA_NET_NS_FD` and `IFLA_TARGET_NETNSID` at most
    (`EINVAL`).
  - **The link:** `RTM_GETLINK` answers with `lo` (index 1), in a dump or
    for its index or `IFLA_IFNAME` (`ENODEV` for another), with Linux
    7.0's attributes in its order: its flags, name, queue, state, MTU,
    queues, segment sizes, carrier, queueing discipline, zero statistics (left out
    with `RTEXT_FILTER_SKIP_STATS` in `IFLA_EXT_MASK`), XDP, map, and its
    MCTP, IPv4 and IPv6 settings (`IFLA_AF_SPEC`, as a kernel built with
    MCTP gives it), so `ip -d link` gives
    Linux's details. An `AF_INET6` dump answers as `inet6_dump_ifinfo`
    does: `lo` with an `AF_INET6` `ifinfomsg`, its name, hardware address,
    MTU and state, and its IPv6 settings with their statistics in
    `IFLA_PROTINFO`. An `RTNL_FAMILY_IPMR` dump answers as
    `ipmr_rtm_dumplink` does, with IPv4's multicast routing table
    (`RT_TABLE_DEFAULT`, the only one a namespace has) in `IFLA_AF_SPEC`:
    no register VIF, assert, PIM or whole-packet setting, nothing waiting
    to be resolved, and no VIFs. Strictly it takes an `ifinfomsg` alone with
    nothing in it, as `ipmr_valid_dumplink` does; an `RTNL_FAMILY_IP6MR`
    dump has no handler of its own, so it is the ordinary link dump.
    `RTM_NEWLINK` and `RTM_SETLINK` bring it up or down with `IFF_UP`. An
    index that is not positive names no link, so the name does, as
    `rtnl_getlink` and `rtnl_setlink` take it (`EINVAL` without one);
    `RTM_NEWLINK` takes no negative index (`EINVAL`).
  - **Addresses:** `RTM_GETADDR` dumps `lo`'s addresses in Linux's orders:
    IPv4's primaries after those of a scope as wide or wider, secondaries
    (an address in a primary's subnet, with `IFA_F_SECONDARY`) last; IPv6's
    global ones first, the newest first. `127.0.0.1/8` comes with each time
    `lo` comes up (should it have been removed) and `::1/128` too; taking
    `lo` down removes every IPv6 address (`keep_addr_on_down` is 0).
    `RTM_NEWADDR` adds one, as `inet_rtm_newaddr` and `inet6_rtm_newaddr`
    do: `EEXIST` for one `lo` has, unless `NLM_F_REPLACE` without
    `NLM_F_EXCL`; `EINVAL` for an IPv4 one without `IFA_LOCAL` or a prefix
    past 32 (128 for IPv6), an IPv6 one without `IFA_LOCAL` or
    `IFA_ADDRESS`, or a message shorter than an `ifaddrmsg`; `ENODEV` for
    another interface. `IFA_LABEL`, `IFA_BROADCAST`, `IFA_FLAGS` (with
    `IFA_F_NOPREFIXROUTE`) and `IFA_PROTO` are kept. `RTM_DELADDR` removes
    the first that has the `IFA_LOCAL`, `IFA_LABEL` and `IFA_ADDRESS` and
    prefix it names (`EADDRNOTAVAIL` for none), a primary with its
    secondaries; `127.0.0.1` and `::1` may go too. An `RTM_GETADDR` that
    is not a dump gets one IPv6 address, as `inet6_rtm_getaddr` does: the
    one `IFA_LOCAL` names, or else `IFA_ADDRESS`, on any index, with
    `EINVAL` for neither and `EADDRNOTAVAIL` for one `lo` has not; a socket
    that checks strictly names nothing else (`EINVAL`). IPv4 and MCTP have
    none to get, so theirs is `EOPNOTSUPP`, as on Linux.
  - **MCTP addresses:** `lo` takes MCTP endpoint IDs, as a kernel built
    with `CONFIG_MCTP` gives a loopback them. `RTM_NEWADDR` and
    `RTM_DELADDR` of `AF_MCTP` add and remove one, as `mctp_rtm_newaddr`
    and `mctp_rtm_deladdr` do. The request is parsed strictly whatever
    the socket: a whole `ifaddrmsg` and one byte of `IFA_LOCAL` or else of
    `IFA_ADDRESS`, with no other attribute (`EINVAL`), for `lo`'s index
    (`ENODEV`). Adding takes IDs 8 to 254 (`EINVAL`), each once
    (`EEXIST`); removing one `lo` has not is `ENOENT`. Each change goes to
    `RTNLGRP_MCTP_IFADDR` (34) with the request's sequence number and
    port, as `mctp_addr_notify` sends it. An `AF_MCTP` address dump has
    MCTP's own handler, as `mctp_dump_addrinfo`: the IDs, the first added
    first, each as `IFA_LOCAL` and `IFA_ADDRESS`; strictly it needs only a
    whole `ifaddrmsg` (`EINVAL`), whose index narrows it without
    `NLM_F_DUMP_FILTERED`. Each ID has a local route
    (`mctp_route_add_local`), unless a route of network 1 has that ID
    alone already, and loses it with the ID. The address and route dumps
    of every family (`rtnl_dump_all`) end with MCTP's.
  - **MCTP routes:** `RTM_NEWROUTE` of `AF_MCTP` adds a route through a
    gateway, as `mctp_newroute` does: `RTA_DST` and the `rtm_dst_len` IDs
    after it, through the `mctp_fq_addr` of `RTA_GATEWAY` (network 0 is
    the default one, 1), with an MTU in `RTA_METRICS` if it has one. The
    request is parsed strictly with `rta_mctp_policy` (`EINVAL`, or
    `ERANGE` for a gateway of other than eight bytes and for metrics of
    one to three); it needs `RTA_DST`, a
    unicast gateway ID and the type `RTN_UNICAST` (`EINVAL`), and takes no
    route through `lo` (`EINVAL`, "no routes to loopback") or other
    interface (`ENODEV`), a range from an ID below 8 or past 254
    (`EINVAL`), or a range of the network that a route already has
    (`EEXIST`). `RTM_DELROUTE` removes the `RTN_UNICAST` route of a
    network and range, the network being the gateway's or that of `lo`'s
    index (`ENOENT` for none), as `mctp_delroute` does. No notification
    goes out for either, as on Linux. An `AF_MCTP` route dump shows the
    local and gateway routes, the newest first, as `mctp_dump_rtinfo`
    does, taking no filter.
  - **Routes:** each family has its routing tables, as Linux's `fib_trie`
    and `ip6_fib` keep them; IPv4's local and main tables share one trie,
    as they do while there is no policy rule. The addresses' routes are the
    kernel's, as `fib_add_ifaddr` and `addrconf` make them: an IPv4 address
    has a `local` route in the local table from the start and, once `lo` is
    up, its prefix route (`local` too on a loopback, which stays when it
    goes down), its subnet's `broadcast` route and that of an
    `IFA_BROADCAST`; an IPv6 address has a `local` route in the local table
    and, from the first time `lo` is up with it, a unicast prefix route in
    the main table, metric 256, but for `::1`. `RTM_NEWROUTE` adds a route
    through `lo` or of a kind without a device (`blackhole`, `unreachable`,
    `prohibit`, `throw`) to any table, with its metric, protocol, scope,
    TOS, preferred source and an IPv4 gateway (on link too), as
    `inet_rtm_newroute` and `inet6_rtm_newroute` do: `NLM_F_EXCL`,
    `NLM_F_REPLACE`, `NLM_F_APPEND` and `NLM_F_CREATE` put it in Linux's
    place, or Linux's error refuses it (`EEXIST`, `ENOENT`; `EINVAL` for a
    bad prefix, scope, kind, gateway or preferred source; `ENODEV` for
    another device; `ENETDOWN` while `lo` is down, but for an IPv4 route of
    host scope). `RTM_DELROUTE` removes the first route that matches what it
    names (`ESRCH` for none), a kernel's too, which a change of an address
    or `lo` coming up brings back. Taking `lo` down removes IPv4's routes
    through it but those of host scope, and every IPv6 route. Removing an
    IPv4 address removes the main table's routes from it, and the last one
    every route through `lo`; removing an IPv6 address removes the first
    main table route to its prefix, whoever's, as `cleanup_prefix_route`
    does. `RTM_GETROUTE` with `NLM_F_DUMP` gives the routes table by table,
    in the order of Linux's table hash, IPv4's in their trie's order and
    IPv6's in a walk of its tree; `AF_INET` or `AF_INET6` alone gives that
    family's, and the multicast routing families none. Without a dump it
    looks up the route to the `RTA_DST` it names, as `inet_rtm_getroute`
    and `inet6_rtm_getroute` do: IPv4 by the longest prefix of the local
    and main tables, then the default table's where they have none or a
    `throw` route; IPv6 in the local table, then the main one, while `lo`
    is up. A rejecting route's error is the answer (`EINVAL`,
    `EHOSTUNREACH`, `EACCES`). An IPv4 answer names the main table (with
    `RTM_F_LOOKUP_TABLE`, the table it came from), the source
    `fib_select_path` picks, a gateway reached on link, the `RTA_MARK` the
    request names (none for 0), and the caller's
    `RTA_UID` (or the one the request names, as it is; none for -1, and
    `ERANGE` for one shorter than 4 bytes); `0.0.0.0` goes to the loopback
    from 127.0.0.1. An IPv6 answer names the source `ipv6_dev_get_saddr`
    picks. Where no route goes it is `ENETUNREACH`, and `AF_UNSPEC`
    `EOPNOTSUPP`; a destination shorter than its family's address is
    `ERANGE` for IPv4 and `EINVAL` for IPv6. With `RTM_F_FIB_MATCH` the
    answer is the table entry that matched (`EHOSTUNREACH` for `0.0.0.0`,
    which none is).
  - **Route metrics:** an IPv4 or IPv6 route keeps the metrics its
    `RTA_METRICS` holds (as `ip route add ... mtu 1400` sends them), as
    `ip_metrics_convert` reads them: each type in turn, one of 0 passed
    over; `RTAX_MTU` held to 65520, `RTAX_ADVMSS` to 65495 and
    `RTAX_HOPLIMIT` to 255; `EINVAL` for a type past `RTAX_MAX`, a value
    of other than four bytes, a congestion control (`RTAX_CC_ALGO`) other
    than `cubic` and `reno`, features past `RTAX_FEATURE_MASK`, and a
    locked congestion window of 0. Two IPv4 routes that differ by their
    metrics alone are two routes, as `fib_find_info` tells them apart. A
    dump, a notification and a lookup's answer give a route's metrics but
    those of 0, as `rtnetlink_put_metrics` does (none for the limited
    broadcast address, and for a multicast one through a route of a prefix
    shorter than 4, whose lookups drop them); an IPv4 removal that
    names metrics takes only a route that has them, as `fib_metrics_match`
    compares them (unheld, so an MTU of 70000 is not the 65520 kept), and
    IPv6's does not look.
  - **Sockets:** an address a local route has is the guest's own: a TCP or
    UDP socket binds to it and reaches it on the loopback, from the
    preferred source of its route. On a loopback an IPv4 address makes its
    whole subnet local, and an IPv4 local route (as `ip route add local`
    makes) every address of its prefix; IPv6 binds only to its addresses.
    Before IPv4 has a local table, a socket binds to any IPv4 address, as
    Linux's `inet_addr_type` takes each as broadcast then.
  - **Notifications:** a socket is a member of the groups `bind` names
    (they replace its first 32) and those `NETLINK_ADD_MEMBERSHIP` adds,
    of `RTNLGRP_*` 1 to 39 (`EINVAL` for 0 or one past them; the
    multicast routing groups 30 and 31 need `CAP_NET_ADMIN`, `EPERM`);
    `NETLINK_DROP_MEMBERSHIP` leaves one, and `NETLINK_LIST_MEMBERSHIPS`
    gives them all as two words. A change to `lo` is told to the members
    of its group in the namespace, each notification its own datagram,
    in Linux's order: bringing it up or down `RTM_NEWLINK` with `IFF_UP`
    in `ifi_change` (`RTNLGRP_LINK`); then the addresses that come or go
    (`RTNLGRP_IPV4_IFADDR`, `RTNLGRP_IPV6_IFADDR`) and the routes
    (`RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE`, a new one with the
    `NLM_F_CREATE`, `NLM_F_EXCL`, `NLM_F_APPEND` or `NLM_F_REPLACE` Linux
    gives it), as `inetdev_event`, `fib_add_ifaddr`, `fib_del_ifaddr`,
    `addrconf`, `rt6_disable_ip`, `rtmsg_fib` and `inet6_rt_notify` tell
    them; and, last when it comes up, IPv6's own `RTM_NEWLINK` for it, as an
    `AF_INET6` link dump gives it (`RTNLGRP_IPV6_IFINFO`, as
    `inet6_ifinfo_notify`). An IPv4 address's and a route request's carry the request's
    sequence number and port; an IPv6 address is told of twice when added,
    tentative and then not. An unbound socket hears nothing; the requester
    of an IPv4 address's or a route's change has the notification before
    its acknowledgement, and with `NLM_F_ECHO` as its own copy.
- A generic netlink socket (protocol `NETLINK_GENERIC`) has its own ports,
  so it binds to the process's ID as a `NETLINK_ROUTE` socket does too,
  and its one family is the controller, `nlctrl` (family ID 16), as in a
  kernel built with no other, so a program that looks a family up (as
  libnl's `genl_ctrl_resolve` or `genl ctrl list` do) finds that it is
  not there.
  - **Requests:** as `genl_rcv_msg`, a type that is no family is `ENOENT`,
    a message without a whole `genlmsghdr` `EINVAL`, and a command
    `nlctrl` does not have `EOPNOTSUPP`; from command 11 on, a reserved
    field or a flag other than `NLM_F_REQUEST`, `NLM_F_ACK`, `NLM_F_ECHO`
    and `NLM_F_DUMP` is `EINVAL`. The attributes are checked as Linux's
    policies say: liberally for a `CTRL_CMD_GETFAMILY` that is no dump
    (an unknown attribute is skipped, a short integer is `ERANGE`), and
    strictly for a dump (an unknown attribute, an integer of another
    length or bytes left over are `EINVAL`).
  - **Families:** `CTRL_CMD_GETFAMILY` answers with `nlctrl`'s
    `CTRL_CMD_NEWFAMILY` for `CTRL_ATTR_FAMILY_NAME` `nlctrl` or
    `CTRL_ATTR_FAMILY_ID` 16 (the name wins when both are given; `ENOENT`
    for another, `EINVAL` for neither), with its name, ID, version 2,
    header size, commands with their flags and its group, as
    `ctrl_fill_info` makes it; a dump lists it, its `NLMSG_DONE` in the
    same datagram. A dump of `CTRL_CMD_GETPOLICY` gives the policies of
    `nlctrl`'s commands, or of the one `CTRL_ATTR_OP` names (`ENOENT` for
    another), as `ctrl_dumppolicy` does: which policy each command's
    request and dump take, then each attribute's type and limits, a
    message each; a second dump while one runs is `EBUSY`.
  - **Groups:** a socket has 64 groups (`EINVAL` for 0 or one past them),
    any of which anyone may join; `nlctrl`'s `notify` is group 16, which
    hears nothing, as no family comes or goes.
- A socket-diagnostics netlink socket (protocol `NETLINK_SOCK_DIAG`)
  tells of the AF_UNIX, TCP and UDP sockets of the network namespace it was
  made in, as Linux's `sock_diag`, `unix_diag`, `inet_diag`, `tcp_diag` and
  `udp_diag` do, so `ss -x`, `ss -t` and `ss -u` list them.
  - **Requests:** `SOCK_DIAG_BY_FAMILY` for AF_UNIX dumps the sockets
    whose state (`TCP_ESTABLISHED`, `TCP_CLOSE` or `TCP_LISTEN`) is in
    `udiag_states`, in parts as large as Linux's `netlink_dump` makes
    them (a page's worth, or as much as the longest receive took, up to
    32 KiB, the next as a receive makes room), its `NLMSG_DONE` after
    them, or with no dump
    answers for the socket of inode `udiag_ino` (`EINVAL` for 0, `ENOENT`
    for none) whose cookie matches (`ESTALE` for another; all ones match
    any). A connection a listener has not accepted has no inode yet, and
    is not listed. A family but AF_UNIX, AF_INET and AF_INET6 has no
    handler (`ENOENT`), a family past `AF_MAX` or a request too short is
    `EINVAL`, `SOCK_DESTROY` is `EOPNOTSUPP`, and a type but
    `SOCK_DIAG_BY_FAMILY`, `SOCK_DESTROY` and `TCPDIAG_GETSOCK` is
    `EINVAL`. A second dump while one runs is `EBUSY`.
  - **What it tells:** each socket's type, state, inode and cookie, then
    as `udiag_show` asks, in `sk_diag_fill`'s order: its name, its socket
    file's inode and device, its peer's inode (0 once the peer has closed
    or while it waits to be accepted), a listener's waiting clients, its
    queues (what waits to be read and what it sent that waits, or a
    listener's waiting connections and backlog), its memory (`SO_RCVBUF`,
    `SO_SNDBUF` and what it sent that waits), then always its shutdown
    (a stream or packet socket's shows what its peer shut down too, and
    both once the peer has closed), and its owner as the user namespace of
    whoever made the netlink socket shows it. A datagram socket another
    connects to is `TCP_ESTABLISHED`, as on Linux.
  - **TCP and UDP requests:** `SOCK_DIAG_BY_FAMILY` for AF_INET or
    AF_INET6 names a protocol (`sdiag_protocol`, or the
    `INET_DIAG_REQ_PROTOCOL` attribute): TCP or UDP, as any other has no
    handler (`ENOENT`, which a dump's `NLMSG_DONE` carries). A dump lists
    the family's sockets whose state is in `idiag_states`, as Linux's
    tables hold them: for TCP the listeners first (unless a destination
    port is asked for), then the closed sockets that hold a port
    (`TCP_BOUND_INACTIVE`), then the connections, with the holds in
    `TIME_WAIT` (or `FIN_WAIT2`) that outlive their sockets; only those of
    the source and destination ports asked for, and those a filter takes
    (`INET_DIAG_REQ_BYTECODE`, as `ss` makes one of `sport = :80` and the
    like), which is checked as Linux's `inet_diag_bc_audit` checks it
    (`EINVAL`, and `EPERM` for a mark test without `CAP_NET_ADMIN`).
    Without a dump it answers for the one socket of its addresses and
    ports, as Linux looks it up: for TCP the connection, else the
    listener, `ENOENT` for none or for a cookie that does not match; for
    UDP the socket a datagram from the source to the destination reaches,
    `ESTALE` for a cookie that does not match. The old `TCPDIAG_GETSOCK`
    does the same for TCP of both families, and `SOCK_DESTROY` is
    `EOPNOTSUPP`, as in a kernel built without
    `CONFIG_INET_DIAG_DESTROY`. A request too short is `EINVAL`.
  - **What it tells of TCP and UDP:** each socket's state (`TCP_SYN_SENT`
    while a handshake waits for room in its listener, then that of the
    connection's end, or `TCP_LISTEN`), its addresses and ports (IPv4 ones
    mapped on an IPv6 socket), its cookie, its timer (a handshake's
    retransmission, keepalive, or `TIME_WAIT`'s), its queues (a listener's
    waiting connections and backlog), its owner as the user namespace of
    whoever made the netlink socket shows it, and its inode (0 for a
    connection not yet accepted); then, in `inet_sk_diag_fill`'s order,
    its shutdown, as `idiag_ext` asks its `IP_TOS`, an IPv6 socket's
    traffic class, and while listening or closed its `IPV6_V6ONLY`, its
    mark to `CAP_NET_ADMIN`, its priority as its class, its cgroup, its
    options (`inet_diag_sockopt`), its memory (a UDP socket's datagrams
    charged in pages, as `udp_rmem_schedule` does, its buffers, and a
    listener's handshakes that a full queue dropped), a TCP socket's
    `tcp_info` (`INET_DIAG_INFO`, which `ss -i` shows), and its
    congestion control (`cubic`). A hold in `TIME_WAIT` tells
    its addresses, state and timer alone.
  - **Groups:** a socket has 32 groups, as Linux makes the four of
    `sock_diag` 32, which anyone may join, and which hear nothing.
- The machine has one NUMA node, node 0. `set_mempolicy` and `mbind` take
  every mode Linux 6.9 has, with its flags, and check the node mask as Linux
  does: nodes past node 0 are dropped, a mask with none of them is `EINVAL`,
  and so is a bit past Linux's 1024 nodes. `get_mempolicy` reports the
  thread's policy, a range's (`MPOL_F_ADDR`), the allowed nodes
  (`MPOL_F_MEMS_ALLOWED`) and node 0 for a page or the next interleaved one
  (`MPOL_F_NODE`). A new thread or process takes its creator's policy and
  `execve` keeps it; a process's ranges keep theirs through `fork` and
  `mremap`, until the pages are unmapped or mapped anew. All memory is on
  node 0, so no policy moves a page.
  `set_mempolicy_home_node` checks its range, flags and node (only node 0)
  and needs a VMA there with a policy of its own, `ENOENT` without one and
  `EOPNOTSUPP` for one other than `MPOL_BIND` or `MPOL_PREFERRED_MANY`.
  `migrate_pages` and `move_pages` find the task as Linux does (`ESRCH`;
  `EPERM` unless the caller may read it; `EINVAL` for a zombie), and need
  `CAP_SYS_NICE` for nodes the task may not use or `MPOL_MF_MOVE_ALL`.
  `migrate_pages` moves nothing and leaves nothing behind. `move_pages`
  moves nothing either; each status is that of the page: 0 (node 0) for a
  page of its own, `-ENOENT` for one nothing touched yet, and `-EFAULT` for
  the zero page that only reading private anonymous memory maps, or where
  nothing is mapped. A node other than 0 is `ENODEV`. A `fork`ed child has
  the page tables of a VMA only when Linux's `vma_needs_copy` copies them:
  one with an `anon_vma` (private memory something wrote) or that had guard
  regions. The pages of any other VMA it faults in again, so they are
  `-ENOENT` until it touches them.
- `uname` reports Linux on x86_64 with the host name `paludarium` and the
  domain name `(none)` of the thread's UTS namespace, until `sethostname` or
  `setdomainname` changes them (`CAP_SYS_ADMIN`, else `EPERM`; at most 64
  bytes, else `EINVAL`); like `CPUID`, it does not reveal the host. The guest starts as root (user and
  group 0, with every capability) without supplementary groups, as Linux's
  first process does; a native program has its launcher's instead. Each
  thread has its own credentials, as on Linux: the real, effective, saved
  and filesystem user and group IDs, the supplementary groups and the
  permitted, effective and inheritable capabilities.
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
  A mounted host directory starts with every file root's and keeps the
  owners and groups for the run.
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
  to 5 levels below the first script (`ELOOP` past that). The first program
  may be a script too, which runs the same way. As on Linux, `chown`
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
- `execveat(dir, path, argv, envp, flags)` runs a program as `execve` does,
  from `dir` for a relative path, and takes `AT_EMPTY_PATH`, which with an
  empty path runs the file the descriptor holds (an `O_PATH` one's too), and
  `AT_SYMLINK_NOFOLLOW`, which refuses a symbolic link (`ELOOP`); other flags
  are `EINVAL`, and an empty path without `AT_EMPTY_PATH` is `ENOENT`. The
  program gets `/dev/fd/<dir>` or `/dev/fd/<dir>/<path>` as its `AT_EXECFN`
  and, for a script, as the script's path, as Linux's `alloc_bprm` names
  it; a script from a descriptor that closes on exec is `ENOENT`
  (`BINPRM_FLAGS_PATH_INACCESSIBLE`). A memfd or a removed file, which no
  path names, runs from its descriptor (`fexecve`), through `execveat` or
  a link in `/proc/self/fd`, and `/proc/self/exe` then reads the memfd's
  link or the path with `(deleted)`. Such a file is read whole, so one
  larger than the memory limit is `ENOMEM` even when its segments are small,
  and one that is neither an ELF program nor a script is `ENOEXEC` from its
  first bytes. Landlock checks a removed one for `EXECUTE` from where it
  was, as from its dentry on Linux; a memfd is in no hierarchy.
  `AT_EXECVE_CHECK` (Linux 6.14) is
  `EINVAL`.
- A program's file and writes to it exclude each other, as Linux's
  `i_writecount` does (`ETXTBSY`). Exec refuses a file that a description
  has open for writing: the program, each script and its interpreter, and an
  ELF program's interpreter. While a process runs a program, and a fork of
  it does, the file does not open for writing, `O_TRUNC` and `truncate` do
  not empty it, and it may be written again once the last of them ends or
  execs another. A script and an ELF interpreter are held only while they
  load. A memfd's own descriptor from `memfd_create` is no writer, so it runs
  and is written through as Linux allows, while opening it again for writing
  through `/proc/self/fd` counts. Only the emulator's own processes are
  counted: a host program writing a file in a mounted directory is not.
- `chmod` and `utimensat` work in the in-memory filesystem and in mounted
  host directories; on a Windows host, `chmod` only sets or clears the
  read-only attribute. `fchmodat2` (Linux 6.6) takes `AT_SYMLINK_NOFOLLOW`,
  which gives a symbolic link `EOPNOTSUPP` since its mode cannot change, and
  `AT_EMPTY_PATH`; glibc's `lchmod` calls it first. `stat` reports only the modification time, with access
  and change times of 0; the host still records both times it is given for a
  file in a mounted directory. The umask is shared by threads, as `CLONE_FS` shares it on
  Linux. `fsync` and `fdatasync` succeed on files and directories and give
  `EINVAL` on pipes, sockets and terminals; `fadvise64` is accepted as a hint.
  `utime`, `utimes` and `futimesat` are `utimensat`'s older forms, as
  Linux's `do_futimesat`: whole seconds, or two `struct timeval`s whose
  microseconds must be under a million (`EINVAL`, checked before the path),
  none meaning now, and `futimesat` with a null path sets its descriptor's.
  `syncfs` succeeds on any descriptor, as `sync` does. `readahead` takes a
  descriptor open for reading (`EBADF`) of a regular file or a block device
  (`EINVAL`), and a count that is not negative as a `loff_t` (`EINVAL`);
  there is no cache for it to fill.
  `sync_file_range` checks its flags and range (`EINVAL`) and then the file
  (`ESPIPE` unless it is a regular file, a directory or a block device), as
  Linux does, and writes the stores of shared mappings back to the file.
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
  line in `mountinfo` says, so `df` lists every mount. `ustat` of a mount's
  `st_dev` gives its free blocks and inodes, and of any other device
  `EINVAL`.
- A file's block size (`st_blksize`, `stx_blksize`, `FIGETBSZ`) is its
  filesystem's, as on Linux: 1024 for `/proc` (procfs), a pseudo-terminal's
  slave and a terminal on standard input, output or error (devpts), and 4096
  for the rest,
  pipes, sockets, `memfd` and `/dev` included. `statfs` there gives
  procfs's or devpts's type with a 4096 `f_bsize`, as Linux's
  `simple_statfs` does. A link in `/proc/self/fd` is procfs's, but a call
  that follows it reaches the descriptor's file, as Linux's magic link does,
  whatever its access (an `O_PATH` descriptor's too): `stat`, `statfs`,
  `open`, `access`, `chmod` and `fchmodat`, `chown` and `fchownat`,
  `utimensat`, `truncate`, `chdir`, the extended-attribute calls and
  `execve`, where `fchmod`, `fchown`, `futimens` and `ftruncate` of an
  `O_PATH` descriptor are `EBADF`. A removed file, a memfd or a pipe is reached through the
  descriptor itself (`execve` of a memfd or a removed file runs it, and
  of a pipe is `EACCES`); a symbolic link an
  `O_PATH | O_NOFOLLOW` descriptor holds is not followed again: its mode
  cannot change (`EOPNOTSUPP`), `chdir` finds no directory (`ENOTDIR`),
  `truncate` no regular file (`EINVAL`) and `execve` gives `ELOOP`.
- Inside a path, a link in `/proc/self/fd` (or `/dev/fd`), `/proc/self/cwd`
  and `/proc/self/exe` is jumped through as Linux's `nd_jump_link` does:
  `/proc/self/fd/3/name` is `name` in the directory descriptor 3 holds, by
  the path that names it now, even after a rename, and `..` goes on from
  there. A removed directory is `ENOENT`, a descriptor that is not open
  `ENOENT`, and a file that is not a directory `ENOTDIR`. The file calls
  that take an absolute path do this (`openat2` with `RESOLVE_*` flags in its
  own walk); a path relative to a descriptor of `/proc` or to a working
  directory there, one whose `..` or symbolic link leads into `/proc`,
  `execve` and a Unix socket's address do not.
- The other `/proc` entries are `/proc/loadavg`, `/proc/meminfo`,
  `/proc/stat` and `/proc/uptime` (below), `/proc/sys` with only
  `fs/mqueue` in it (below), a directory per process, and this process's own: `/proc/<pid>`, a
  directory its entries can be opened relative to and that lists them, and `/proc/self`, a
  symbolic link to it (0777, size 0) that `readlink` resolves to the PID:
  `lstat`, and `fstatat` or `statx` with `AT_SYMLINK_NOFOLLOW`, give the
  link, `stat` and a trailing slash follow it, `O_NOFOLLOW` does not
  (`ELOOP`), and `O_PATH | O_NOFOLLOW` opens the link itself, which reads
  as the PID of the process reading it and names itself `/proc/self`; then
  `/proc/self/status`, `stat`, `cmdline`, `environ`, `comm`, `exe`, `cwd`,
  `maps`, `fd`, `fdinfo`, `ns` and `task`. `status` has Linux's fields in Linux's order (umask, IDs, threads,
  signal masks, capabilities and so on) without the memory and CPU ones,
  which nothing measures. Any other path in this process's directory or
  elsewhere under `/proc` is looked up in the filesystem like any path, so with
  `--mount /:/` it reaches the host's own `/proc`.
- `/proc` lists what the filesystem has there that is not a process (with
  `--mount /:/`, the host's own entries except its processes), the files above,
  and then a directory for every process of the guest, zombies included, as
  Linux lists them, which is what `ps`, `pgrep` and `pidof` read. Another
  process's `/proc/<pid>` (0555, owned by its effective IDs) has `status`,
  `stat`, `cmdline`, `environ` (0400), `comm`, `exe`, `cwd`, `ns` (0511) and
  `task`, made as
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
  gets `EACCES` for `environ` unless its real IDs, and for `exe`, `cwd` and
  the links of `ns` unless its filesystem IDs, are every user and group ID of a dumpable
  process in its user namespace whose permitted capabilities its own cover
  (its effective ones for the filesystem IDs), as reading another process
  asks above; an undumpable process's directory is root's. What a process shows of
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
  and session, the controlling terminal's device and foreground group (0
  and -1 without one), the CPU time of the process and of its waited-for
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
  resolved; for the first program, the path the CLI gives it: its path in a
  `--mount`, else `/<file name>`)
  and to the current directory. `stat` and `open` follow them, and
  `O_NOFOLLOW` does not (`ELOOP`).
- `/proc/sys/fs/mqueue` has the POSIX message queue limits of the
  reader's IPC namespace, as Linux's `ipc/mq_sysctl.c`: `queues_max`,
  `msg_max` and `msg_default` (1 to 65536), `msgsize_max` and
  `msgsize_default` (128 to 16 MiB), regular files of mode 0644 that the
  root of the user namespace owning the IPC namespace owns, and only that
  root may open to write (`EACCES`). A read gives the value and a newline
  from the start, and nothing past it. A write at the start sets the value
  as Linux's `proc_dointvec_minmax` reads one `int`: spaces, an optional
  `-` and digits in base 10, or 16 after `0x`, or 8 after `0`, then a
  space, tab, newline or the end; it returns how much it read, the spaces
  after the value too, and is `EINVAL` for no value, garbage, one too long
  or one out of range (`queues_max` takes any `int`, compared as
  unsigned). A write past the start is taken and changes nothing, as
  `sysctl_writes_strict` has it.
- `/proc/sys/fs/aio-nr` (mode 0444) is how many events the machine's aio
  contexts were set up for, and `/proc/sys/fs/aio-max-nr` (0644, 65536 at
  first) their limit, which only root (user ID 0 outside any user namespace)
  may open to write. Both are unsigned longs, as Linux's
  `proc_doulongvec_minmax` reads and writes them: a write takes no `-`
  (`EINVAL`) and otherwise reads as the files of `/proc/sys/fs/mqueue` do.
  `/proc/sys/fs` lists only these, `inotify` and `mqueue`.
- `/proc/sys/fs/inotify` has the machine's inotify limits, root's regular
  files of mode 0644 that only root (user ID 0 outside any user namespace)
  may open to write, read and written as the files above:
  `max_user_instances` (128 at first) and `max_user_watches` (31956 at first,
  as the instances below say), unsigned longs from 0 to `INT_MAX`, are what
  each user may have from then on, and `max_queued_events` (16384 at first),
  an `int` from 0, is how many events an instance made from then on queues
  before `IN_Q_OVERFLOW`.
- `/proc/self/fdinfo` (0555) has a file (0444, of size 0) for each open
  descriptor, as Linux's `seq_show` writes it: `pos`, the description's
  position (0 for a pipe or socket), `flags` in octal (`F_GETFL`'s, and
  `O_CLOEXEC` for the descriptor), `mnt_id`, the ID `statx` gives, and `ino`,
  the inode `fstat` gives. An inotify instance's adds a line for each watch,
  the newest first, as `inotify_fdinfo`: `inotify wd:`, the watch descriptor,
  `ino:` and `sdev:`, the file's inode and its file system's device as the
  kernel numbers it (`MKDEV`), and `mask:`, the mask it was given, in
  hexadecimal, then `ignored_mask:0` and the file's handle as
  `show_mark_fhandle` writes it: `fhandle-bytes:` and `fhandle-type:` in
  hexadecimal, and `f_handle:`, its bytes, the identifier
  `name_to_handle_at` gives with `AT_HANDLE_FID`. The other kinds add Linux's lines
  too. After the first four come `lock:` lines (`show_fd_locks`): the
  description's `flock` lock, then each record lock set through it that the
  process's table or the description owns, by where they start, numbered from 1
  across both. Each has `FLOCK`, `POSIX` or `OFDLCK`, `READ` or `WRITE`, the
  ID of the process that set it (-1 for a description's record lock), the device and inode, and the range
  (`0 EOF` for a `flock` lock). Asking again for the kind of `flock` lock a
  description has keeps it as it was, and a change of kind drops the old
  one first, even when the new one conflicts, as `flock_lock_inode` does.
  A lock merged into another
  stays with the description of the lock it extended, as
  `posix_lock_inode` keeps it. Then an eventfd's `eventfd-count`
  (hexadecimal), `eventfd-id` (the lowest number no other eventfd has, as
  `ida_alloc` gives it) and `eventfd-semaphore`; a signalfd's `sigmask`; a
  timerfd's `clockid`, `ticks`, `settime flags`, `it_value` and
  `it_interval` (an expired timer stays at its expiry, with `it_value` 0 and
  the first expiry's tick, until a read or `timerfd_gettime` moves it on);
  and an epoll's `tfd:` line for each file it watches: the descriptor it was
  added with, the events (with `EPOLLERR` and `EPOLLHUP`, which `epoll_ctl`
  adds, and only the flags once a one-shot fired), the data, and the file's
  position, inode and device (that of a descriptor the process has of it,
  else 0).
- `/proc/loadavg`, `/proc/meminfo` and `/proc/uptime` agree with `sysinfo`,
  in Linux's formats: load averages of 0 with the running and live tasks and
  the last ID handed out; 4 GiB of total, free and available memory and
  nothing else used, no swap and no huge pages; and the monotonic clock's
  uptime with no idle time.
- `/proc/stat` is in the format of Linux's `show_stat`: a `cpu` line and one
  for each CPU `sched_getaffinity` reports, every time 0 as `/proc/uptime`
  counts no idle time; `intr 0`, `ctxt 0`; `btime`, the real-time clock less
  the monotonic one in seconds, so `ps` finds the boot time; `processes`, the
  IDs handed out; `procs_running 1`, `procs_blocked 0`; and a `softirq` line
  of zeros.
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
  `anon_inode:[eventfd]`, `[eventpoll]`, `[timerfd]`, `[signalfd]` or `[pidfd]` (an
  anonymous inode's name, which pidfs, from Linux 6.9, still gives),
  `anon_inode:inotify` (without brackets, as Linux names it), and
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
  do an eventfd, an epoll, a timerfd, a signalfd and an inotify instance, whose anonymous inode Linux opens
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
  - `TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF`, their `termios2` forms
    (`TCGETS2` and so on) and the old `struct termio` ones (`TCGETA`,
    `TCSETA`, `TCSETAW`, `TCSETAF`, which set the low 16 bits of each flag
    and the first 8 characters) reach the slave's `termios` from either
    side; it keeps `CS8 | CREAD` without parity, takes its speeds from
    `CBAUD` or `BOTHER`, and keeps what `TIOCSLCKTRMIOS` locked (which
    needs `CAP_SYS_ADMIN`; `TIOCGLCKTRMIOS` reads it). With `TIOCPKT` the
    master reads in packet mode: the slave's flushes, the stops and starts
    of its output, and changes to whether `^S` and `^Q` control it (or to
    `EXTPROC`) come as a status byte alone, which `poll` shows as
    `POLLPRI`, and data after a 0 byte; `TIOCGPKT` reads the mode. `TIOCGWINSZ` and `TIOCSWINSZ` (a change sends
    `SIGWINCH` to the foreground group), `FIONREAD`, `TIOCOUTQ`, `TCFLSH`,
    `TCXONC`, `TCSBRK`, `TIOCEXCL`, `TIOCGEXCL`, `TIOCGETD` and `TIOCSETD`
    (N_TTY only), `TIOCGDEV` and `TIOCSIG` work as on Linux, and so does
    `TIOCSTI` with `dev.tty.legacy_tiocsti` off: it pushes input only for
    `CAP_SYS_ADMIN`, and is `EIO` for anyone else.
  - With `O_ASYNC` (signal-driven I/O, below) the slave signals `POLL_IN`
    when a line can be read in canonical mode, or a byte otherwise, and
    the master when the slave's output (or an echo) reaches it; a write
    left short signals `POLL_OUT` once the other side reads its buffer
    down to 128 bytes, or its output starts again. Packet events do not
    signal. Turning `O_ASYNC` on gives a file without an owner one: the
    slave's foreground process group, else the calling process.
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
  - `TIOCVHANGUP` (`CAP_SYS_ADMIN`, else `EPERM`) hangs up the slave with
    the master still open, as the master's close does, and `vhangup`
    (`CAP_SYS_TTY_CONFIG`) the caller's controlling terminal. The slave's
    descriptions open then are hung up and lose `O_ASYNC` (which they cannot
    take again: `ENOTTY`); its input is dropped, its `termios` is a new
    slave's again, and its line discipline is gone until the slave is opened
    again, so what the master writes meanwhile waits, unechoed, for the
    master's next write after that open. `TIOCVHANGUP` on the master hangs up
    only the master's file, which then reads nothing, while the slave still
    writes. `TIOCCONS` (`CAP_SYS_ADMIN`; `EINVAL` on the master, `EBADF` for
    a slave not open for writing) makes the slave take the console's output,
    holding it open, until that slave hangs up; another while one has it is
    `EBUSY`.
- CPU time is the host thread's CPU time (user and system together) from a
  guest thread's first system call, where the host can measure it (Linux,
  macOS, Windows); elsewhere, as in WebAssembly, it is wall time instead.
  `CLOCK_THREAD_CPUTIME_ID` reads the thread's, and `CLOCK_PROCESS_CPUTIME_ID`
  the sum of the process's threads, each as of its latest system call. A
  child starts from zero, and its time joins its parent's children's when it
  is waited for. `getrusage`, `times` and the rusage of `wait4` and `waitid`
  report it all as user time, as the emulator's work for system calls runs
  in the host's user space; memory use is not measured.
- A negative clock ID names a task's CPU clock, as Linux's `pid_for_clock`
  takes it apart: the task's number in the caller's PID namespace
  (`~id >> 3`, 0 for the caller), a thread's clock (bit 2) or a process's,
  and the time in the low two bits (`CPUCLOCK_PROF`, `CPUCLOCK_VIRT` and
  `CPUCLOCK_SCHED`, all the same time here). `clock_gettime` reads any
  process's, a zombie's too, the caller's own thread's number as its
  process's, and the clock of a thread of the caller's process;
  `clock_getres` gives a tick (1 ms) for the first two kinds of time and
  1 ns for the third. Another task's thread, a thread's number as a
  process's (but the caller's own, to read), no such task, and the fourth
  kind give `EINVAL`, as does a dynamic clock (`3` in the low three bits),
  which needs a PTP device's file. Every clock ID is an `int`, as Linux's
  system calls take it, so the high 32 bits are not looked at.
- `clock_gettime` also reads `CLOCK_MONOTONIC_RAW`, the coarse clocks,
  `CLOCK_BOOTTIME` (the host never suspends), the alarm clocks and
  `CLOCK_TAI` (with a TAI offset of 0). The coarse clocks give the time of
  the latest tick, and `time` gives the seconds of `CLOCK_REALTIME_COARSE`,
  as Linux's do, so either can be up to a tick behind `CLOCK_REALTIME` and
  `gettimeofday`. The tick is the host's, the resolution of its
  `CLOCK_MONOTONIC_COARSE` (1 ms where the host does not tell, as on macOS,
  Windows and in WebAssembly), the one the scheduler calls use, and here the ticks
  fall on whole multiples of it on each clock. `clock_getres` gives 1 ns,
  and the tick for the coarse clocks.
- `clock_nanosleep` and `timer_create` run on `CLOCK_REALTIME`,
  `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`, `CLOCK_TAI` and the process's CPU
  clock, and `timer_create` on the thread's CPU clock too. As Linux's,
  `CLOCK_MONOTONIC_RAW` and the coarse clocks give `EOPNOTSUPP` (they can
  only be read), as does the thread's CPU clock for a sleep, and
  `clock_nanosleep` looks at no flag but `TIMER_ABSTIME`. They also run on
  the alarm clocks, `CLOCK_REALTIME_ALARM` on the real-time clock and
  `CLOCK_BOOTTIME_ALARM` on the monotonic one, with `CAP_WAKE_ALARM`, as
  Linux's `alarmtimer.c` with an RTC that can wake the machine, as the CI
  runners have: a sleep reads its request, then refuses any flag but
  `TIMER_ABSTIME` (`EINVAL`), then a caller without the capability
  (`EPERM`); `timer_create` writes the timer's ID out before it refuses
  one, and the ID is used up, as it is when it cannot be written
  (`EFAULT`). `timer_create` also runs on the CPU clocks of the caller's
  process and threads by number; it finds the task after the ID is out,
  as Linux's `posix_cpu_timer_create` does, so a task that is not there
  gives `EINVAL` with the ID used up. A dynamic clock has no timers and
  cannot sleep (`EOPNOTSUPP`). A sleep on a CPU clock by number reads its
  request, refuses the caller's own thread's clock (`EINVAL`) and then a
  task that is not there (`EINVAL`); on the caller's process's clock it
  sleeps as below, and on another task's it returns at once when its time
  has come (a relative 0, or an absolute time the clock has reached), as
  Linux's `posix_cpu_nsleep`, but one that would wait for that task's CPU
  time is not modelled (`EINVAL`), nor is a timer on another process's
  CPU time.
- A sleep on the process's CPU clock ends once the process's threads
  together have used the time, as Linux's `do_cpu_nanosleep`: a time that
  has passed, or none to sleep, returns at once, and the sleeping thread
  uses none itself, so a process with no other thread running sleeps until
  a signal comes (in WebAssembly, which cannot measure CPU time, the
  sleeper's wall time counts too). A signal with a handler ends it with `EINTR`, writing the
  time left for a relative sleep, unless the time has been used by then,
  when it returns 0; a stop resumes it as it does the other sleeps.
- The process's real-time interval timer (`ITIMER_REAL`) sends `SIGALRM`
  when it expires and goes on by its interval, as Linux's: `setitimer`
  reads and checks the new value before the timer, and writes the old one
  out after setting it, so an old value it cannot write gives `EFAULT` with
  the timer set. A value of 0 disarms it and drops its interval, and one
  past Linux's `KTIME_MAX` is clamped to it. `getitimer` gives the time left
  in microseconds, cut down, as Linux's `itimer_get_remtime`: an armed timer
  whose time is up shows 1 µs, and one with less than 1 µs left shows 0.
  `alarm` sets it to whole seconds with no interval and returns the seconds
  that were left, rounded to the nearest and at least 1 while it was armed,
  as Linux's `alarm_setitimer`.
- The interval timers of the process's CPU time, `ITIMER_VIRTUAL` and
  `ITIMER_PROF`, send `SIGVTALRM` and `SIGPROF` from the kernel
  (`SI_KERNEL`) when the process's threads together have used their time,
  as Linux's `check_cpu_itimer`: each expiry goes on by one interval, a new
  value starts a tick later, and an expiry that has come shows a tick left.
  A value of 0 disarms one but keeps its interval, and a value set past
  `KTIME_MAX` shows negative seconds, as Linux's `ns_to_timespec64` makes
  them. A child of `fork` starts with neither, and `execve` keeps them.
  They count CPU time as the CPU clocks do, so in WebAssembly, which cannot
  measure it, they count wall time.
- `sysinfo` reports a fixed 4 GiB of free memory and no swap, without
  revealing the host's; the uptime is the monotonic clock's, rounded up to
  a whole second as Linux rounds it.
- A timerfd runs on `CLOCK_REALTIME` or `CLOCK_MONOTONIC` (`CLOCK_BOOTTIME`
  as `CLOCK_MONOTONIC`), with absolute and periodic settings. A read returns
  the expirations since the last one, and `poll` and `epoll` see it readable
  once it has expired. `TFD_TIMER_CANCEL_ON_SET` is accepted, but the guest
  cannot set the clock, so it never cancels. The alarm clocks run as
  `CLOCK_REALTIME` and `CLOCK_MONOTONIC` and need `CAP_WAKE_ALARM`
  (`EPERM`, after unknown flags give `EINVAL`).
- A signalfd (`signalfd`, `signalfd4`) reads the signals of its mask that are
  pending for the thread reading it, blocked or not, as Linux's
  `dequeue_signal` takes them: the thread's own first, then the process's,
  the lowest number first. A read gives as many 128-byte
  `struct signalfd_siginfo` records as fit (`EINVAL` for less than one),
  each with the fields Linux copies for that kind of signal: the sender's
  process and user for `kill` and `sigqueue` (with the value), the child's
  process, status and CPU time for `SIGCHLD`, a timer's ID, overrun and
  value, and a fault's address. It waits for the first unless the file is
  non-blocking, and a signal that can be delivered ends the wait (`EINTR`,
  which `SA_RESTART` restarts). `poll`, `select` and `epoll` see the file
  readable while one of its signals is pending for the calling thread, as
  on Linux, so a thread's own signal is seen by that thread alone and a
  forked child's inherited file reads the child's signals. Edge-triggered
  `epoll` gets an edge for each signal queued to the process or any of its
  threads while one of the file's signals is pending for the waiter, as Linux's `signalfd_notify`
  wakes the file for each: another real-time signal of a number already
  waiting counts, a standard signal already pending or one ignored and
  unblocked does not; a new mask is an edge too. `signalfd` on a
  signalfd's descriptor gives it a new mask (`EINVAL` for another file);
  `SIGKILL` and `SIGSTOP` never enter one. A write gives `EINVAL`, `pread`
  and `pwrite` `ESPIPE`, and `lseek` 0, as Linux's `noop_llseek`.
- An inotify instance (`inotify_init`, `inotify_init1`, with `IN_NONBLOCK`
  and `IN_CLOEXEC`) watches files by their device and inode, which
  `inotify_add_watch` finds as Linux's `inotify_find_inode` does: the last
  symbolic link followed unless `IN_DONT_FOLLOW`, a directory with
  `IN_ONLYDIR` (`ENOTDIR`), and one the caller may read (`EACCES`). Its
  errors come in Linux's order: the mask (`EINVAL` for an unknown bit or
  none), the descriptor (`EBADF`, an `O_PATH` one too), `IN_MASK_ADD` with
  `IN_MASK_CREATE` (`EINVAL`), another kind of file (`EINVAL`), then the
  path. A file already watched keeps its watch descriptor, with the new
  mask, the old one and the new together with `IN_MASK_ADD`, or `EEXIST`
  with `IN_MASK_CREATE`. Watch descriptors are numbered from 1 and not
  reused until they wrap, as Linux's `idr_alloc_cyclic` gives them, and
  `INOTIFY_IOC_SETNEXTWD` sets the next one. `inotify_rm_watch` of a
  descriptor no watch has is `EINVAL`. A user may have 128 instances
  (`EMFILE`) and 31956 watches (`ENOSPC`), what Linux works out for the
  4 GiB `sysinfo` reports, and an instance queues 16384 events, until
  `/proc/sys/fs/inotify` changes them.
  The changes the guest's own system calls make are the events, in the order
  Linux's `fsnotify` hooks give them: `IN_CREATE` for a new file, directory,
  symbolic link, FIFO, socket or link (after `IN_ATTRIB` of a linked file);
  `IN_DELETE` for a removed one, after `IN_ATTRIB` of the file and, for its
  last link or a directory, `IN_DELETE_SELF` and `IN_IGNORED` of it, which
  wait for the last close of a description of it that is open (a mapping
  holds one until it is unmapped), until no process runs it as its
  program, for the ELF interpreter a program runs with until no process
  maps it (an unmap, an exec or an exit ends a mapping, and a fork copies
  it) and, for a directory, until no process has it as its working
  directory, as Linux's dentry waits;
  `IN_MOVED_FROM` and `IN_MOVED_TO` with one cookie for a rename, then
  `IN_ATTRIB` of a file it replaces, `IN_MOVE_SELF` of the file moved, and
  the replaced file's `IN_DELETE_SELF`, which waits in the same way (twice
  for `RENAME_EXCHANGE`, and
  nothing for a rename onto another link of the same file); `IN_ATTRIB` for
  a new mode, owner (a `chown` that names neither gives none), both times
  or extended attribute; `IN_ACCESS` and `IN_MODIFY` for setting only the
  access or only the modification time; `IN_MODIFY` for a truncation,
  `O_TRUNC` emptying a regular file too (after its `IN_OPEN`); `IN_OPEN` for
  an open (not `O_PATH`, and a link in `/proc/self/fd` too), and
  `IN_CLOSE_WRITE` or `IN_CLOSE_NOWRITE` as the open file description's last
  reference goes, which a mapping of it holds until it is unmapped; and
  `IN_ACCESS` or `IN_MODIFY` for a `read`, `write`, `pread64`, `pwrite64`,
  `readv`, `writev`, `preadv`, `pwritev`, `preadv2` or `pwritev2` that moved
  bytes, `sendfile` and `copy_file_range` (the input's, then the output's),
  `fallocate`, and each `getdents` and `getdents64`; a `splice` that moved
  bytes is the output's `IN_MODIFY`, then the input's `IN_ACCESS`, a `tee`
  the input's, then the output's, and a `vmsplice` a write end's `IN_MODIFY`
  or a read end's `IN_ACCESS`. A pipe has no watches, but a FIFO opened by
  its path is an open file like the others: `IN_OPEN` once the open is done
  (one that fails, such as a writer's `ENXIO`, is none), `IN_CLOSE_WRITE`
  or `IN_CLOSE_NOWRITE` at its description's last close, and its reads and
  writes for its own watches only, which Linux keeps from its directory's
  (`d_is_special`). Its events go where renames took its name, as a
  file's do, and an open of it through `/proc/self/fd` opens its pipe
  again at the same name (with `IN_OPEN`, waiting for the other end as an
  open by its path does), even once no name links it; a removed one's
  `IN_DELETE_SELF` waits for the last of them. A memfd, which no name
  links, has its `IN_DELETE_SELF` once nothing holds it (no description,
  mapping or process running it); `memfd_create`'s own description has no
  `IN_OPEN` and no close. The files exec runs are open
  files too: `IN_OPEN` as `execve` or `execveat` opens the program (one only
  a descriptor holds, a memfd or a removed file, too), each script and the
  ELF interpreter, `IN_ACCESS` as it reads their first bytes (none of an
  empty file), and `IN_CLOSE_NOWRITE` once nothing uses them: the program
  when no process runs it, the interpreter when no process maps it, and a
  script at the end of the call, after the program the exec replaced and
  its interpreter, as the `fput`s Linux defers run the newest first. An
  exec that fails closes the files it opened as it gives up, the last
  opened first: the program before the interpreter it found. A watch with
  `IN_EXCL_UNLINK` does not
  hear of the open, close, read or write of a file through a name unlinked
  since it was opened (by `unlink`, `rmdir` or a rename onto it), even while
  another link keeps the file; `truncate` and `mknod` open nothing. A file's change reaches the watch of
  its directory, with its name, before its own (for an open file, the name
  it was opened at as renames of it and of the directories above it moved
  it, or the unlinked name it last had), and `IN_ISDIR` marks a
  directory's (not with `IN_DELETE_SELF` or `IN_MOVE_SELF`, as Linux
  leaves it out). `IN_ONESHOT` removes the watch after its first event, with
  `IN_IGNORED`. Each instance queues its events, merging one into the same
  event (descriptor, mask and name) just before it unless that one is
  `IN_IGNORED` or a move, and after 16384 queues one `IN_Q_OVERFLOW` (with
  descriptor -1) until it is read. A read gives as many whole
  `struct inotify_event` records as fit, each name padded with NULs to a
  multiple of 16 bytes, `EINVAL` when the first does not fit; it waits for
  the first unless the file is non-blocking, and a signal ends the wait
  (`EINTR`, which `SA_RESTART` restarts). Each record is copied out as it
  is taken, as Linux's `inotify_read` does: the one that meets a page the
  process cannot write is taken too, its bytes up to that page written,
  and the read is `EFAULT`, whatever it read before (an address outside
  the user half is `EFAULT` with nothing taken). An instance has no
  `read_iter`, so `readv` and `preadv2` read each buffer in turn as such a
  read, until one is not filled or fails (`EFAULT` then only when it is the
  first), give 0 for no bytes, and take no flag but `RWF_HIPRI`
  (`EOPNOTSUPP`). `FIONREAD` gives the bytes queued,
  `poll`, `select` and `epoll` see the file readable while any event is
  queued, and each queued event is an edge for edge-triggered `epoll`.
  Closing the last descriptor of an instance removes its watches. A write
  gives `EBADF`, `pread` `ESPIPE`, and `lseek` 0.
- POSIX timers run on the clocks above and notify with
  a signal to the process (`SIGEV_SIGNAL`, with `SI_TIMER` siginfo and
  overruns), a signal to one of its threads (`SIGEV_THREAD_ID`), or not at all
  (`SIGEV_NONE`). The kernel takes `SIGEV_THREAD` as `SIGEV_SIGNAL`, as Linux
  does; the C library builds the thread on `SIGEV_THREAD_ID`. A thread's timer
  signal adds to its overrun only while the thread has not taken it yet, and
  is lost if the thread has exited. A timer on `CLOCK_PROCESS_CPUTIME_ID`
  counts the process's CPU time, and one on `CLOCK_THREAD_CPUTIME_ID` that
  of the thread that made it, as Linux's `posix_cpu_timer_*`: its value is
  in that time (absolute with `TIMER_ABSTIME`), clamped to `KTIME_MAX`; it
  shows nothing, its interval included, once disarmed; a `SIGEV_NONE` one
  is moved on by its interval when it is read; and once the thread whose
  clock it is has exited, `timer_settime` gives `ESRCH` and
  `timer_gettime` shows nothing. On the other clocks, as Linux's
  `common_timer_set`, `timer_settime` looks at no flag but `TIMER_ABSTIME`
  and takes the value and the interval up to `KTIME_MAX`, and a relative
  expiry past `KTIME_MAX` stops there; a relative `CLOCK_REALTIME` timer
  counts on the monotonic clock. Timers are
  not inherited by `fork` and are deleted by `execve`. `rt_sigtimedwait` also
  takes blocked signals pending for the whole process.
- `clone3` checks its `struct clone_args` as Linux does (`E2BIG` for a
  longer struct whose extra part is not zero) and then runs as the `clone` it
  describes; `CLONE_CLEAR_SIGHAND` resets handled signals to their default.
  `set_tid` is as under the PID namespaces above, and `CLONE_INTO_CGROUP`
  gives `EINVAL`. `clone` itself reads only
  the low 32 bits of its flags, as in Linux, so `CLONE_CLEAR_SIGHAND` is
  `clone3`'s alone.
- `prctl` supports `PR_SET_NAME`/`PR_GET_NAME` (a name of up to 15 bytes per
  thread, taken from the program's file name at `execve` and inherited by new
  threads and processes), `PR_SET_PDEATHSIG` (the signal is sent when the
  parent exits), `PR_SET_DUMPABLE` (`execve` makes the process dumpable
  again, but for the cases above), `PR_SET_KEEPCAPS` (per thread, cleared
  by `execve`), `PR_SET_CHILD_SUBREAPER` (not inherited on `fork`, kept on
  `execve`), `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECCOMP` (see seccomp below)
  with their `PR_GET_*`, and Yama's `PR_SET_PTRACER`, which reads no other
  argument: 0 clears it, `PR_SET_PTRACER_ANY` (or -1 as an `int`) lets any
  process attach, and another value, taken as an `int`, names a task in the
  caller's PID namespace (`EINVAL` for none) whose process, and its
  descendants, may attach while that task is there. It is the process's,
  whichever thread sets it, and a child does not inherit it. Other options
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
  an unknown resource is noticed); a thread's ID names its process. Four are
  enforced, as in Linux:
  - `RLIMIT_NOFILE`: a new descriptor past its soft limit gives `EMFILE` (and
    `open` creates nothing), `dup2`/`dup3` onto a number past it `EBADF`, and
    `F_DUPFD` from one past it `EINVAL`.
  - `RLIMIT_FSIZE`: a write to a regular file (`write`, `writev`, `pwrite` and
    `pwritev`, which with `O_APPEND` start at the end, and `copy_file_range`,
    `sendfile` and `splice`) stops at the soft limit; one that
    starts at or past it, and a `truncate`/`ftruncate` or `fallocate` that
    grows the file past it, raise `SIGXFSZ` and fail with `EFBIG`.
  - `RLIMIT_CPU`: when the process's CPU time reaches the hard limit it is
    sent `SIGKILL`; when it reaches the soft limit it is sent `SIGXCPU` and
    the soft limit goes up a second, so another comes each second, as
    Linux's `check_process_timers` does. The seconds are taken to
    nanoseconds by a 64-bit product that wraps, as on Linux, so a soft limit
    of 2^55 seconds or more can come at once. A child of `fork` keeps the
    limits, and its own CPU time is checked against them.
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
  `waitid` can wait for a group. The first process is like the first of a
  PID namespace: its group and session started outside the emulator, so
  `getpgrp` and `getsid` report them as 0, as Linux reports an ID outside a
  PID namespace, and it may start a session of its own. `setsid` fails
  with `EPERM` in a process whose PID names a group, and makes any other
  process the leader of a new session and group. `setpgid` checks the session
  as Linux does: a session leader, a child in another session and a group in
  another session give `EPERM`, and a child that has run `execve` gives
  `EACCES`. A group exists while any member is left, an exited child not yet
  reaped included.
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
  no file type, and an inode of its process's own (the process's ID, as IDs
  are never handed out twice here), as pidfs numbers each process once;
  `fstatfs` gives pidfs (`PID_FS_MAGIC`). It becomes readable when its process exits (and hung up
  once it is reaped; an automatically reaped child shows both at once), so
  `epoll` can wait for it; `waitid(P_PIDFD)` on a nonblocking one gives
  `EAGAIN`.
  `pidfd_send_signal` takes no siginfo and no scope flags, and `PIDFD_THREAD`
  still names the whole process, though `F_GETFL` shows it as `O_EXCL` as
  on Linux. It takes Linux's sentinels for no pidfd:
  `PIDFD_SELF_THREAD` (-10000) sends to the calling thread, as `tkill`
  does (`SI_TKILL`), and `PIDFD_SELF_THREAD_GROUP` (-10001) to its process,
  as `kill` does.
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
    `TCP_USER_TIMEOUT`, `TCP_INFO` (read only), `IP_TOS` and `IPV6_V6ONLY`,
    with Linux's defaults and
    range checks: `SO_SNDBUF` and `SO_RCVBUF` are at most the default
    `wmem_max` and `rmem_max` (212992), doubled; a new `IP_TOS` sets
    `SO_PRIORITY` from its TOS bits too (`rt_tos2priority`). `SO_TIMESTAMP`, its kin
    and `SO_TIMESTAMPING` are set and read back as on AF_UNIX sockets, and
    `SOF_TIMESTAMPING_OPT_ID` needs a TCP socket's connection (`EINVAL`
    while it is closed or listening).
  - **`TCP_INFO`** gives Linux's 280-byte `struct tcp_info`, as much of it
    as the room asks (`tcp_get_info`): a listener's state, connections
    waiting and backlog; a socket that has not connected, Linux's
    defaults; a handshake, its retries, with the timeout doubling past
    `tcp_syn_linear_timeouts`; a connection, its state, options
    (timestamps, SACK and window scaling), window scales (10, or less for a
    receive buffer the guest set), the bytes it sent, had acknowledged and
    received with its handshake and ends, those not sent yet, its data
    segments and the times since data went and came. A UDP socket has no
    TCP options (`EOPNOTSUPP`).
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
  unless `IPV6_V6ONLY`; binding to another IPv6 address that is not an
  IPv4 one sets `IPV6_V6ONLY`, as `__inet6_bind` does.
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
  `preadv2`, `pwritev2`,
  `wait4`, `waitid`, `pause`, `rt_sigsuspend`, `flock`, `fcntl`'s `F_SETLKW` and
  `F_OFD_SETLKW`, `open`, `openat` and `openat2` of a FIFO, `accept`,
  `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`,
  `recvmmsg`, `msgsnd`, `msgrcv`, `mq_timedsend`, `mq_timedreceive`,
  `sendfile`, `splice`, `tee`, `vmsplice`, `ppoll`, `select`, `pselect6`,
  `poll` with no timeout and a `futex` wait with none, and `futex_waitv` and
  futex2's `futex_wait` with or without one. `nanosleep`, a relative
  `clock_nanosleep`, `poll` with a timeout and a timed `futex` wait resume
  through `restart_syscall` with the deadline they had (the `futex` wait
  checks its word again first, `EAGAIN` once it changed), and an absolute
  `clock_nanosleep` runs again; a handler ends the restart, so they
  give `EINTR` then. A handler set with `SA_RESTART` runs the calls that a
  stop runs again (from `read` to the `futex` wait with no timeout) again when
  it returns, as on Linux, except `pause`, `rt_sigsuspend`, `msgsnd`,
  `msgrcv`, `poll`, `ppoll`, `select`, `pselect6` and a socket call, or a
  `sendfile` into a socket, whose wait `SO_RCVTIMEO` or `SO_SNDTIMEO` limits,
  which give `EINTR`.
  `epoll_wait`, `epoll_pwait`, `epoll_pwait2` and `rt_sigtimedwait` give
  `EINTR`, as on Linux. `rt_sigsuspend` waits with its mask in place of the signal mask until a
  handler has run, which runs with that mask; the original mask is back after
  it.
- A `sigaction` that makes a signal ignored (`SIG_IGN`, or `SIG_DFL` for
  `SIGCHLD`, `SIGCONT`, `SIGURG` and `SIGWINCH`, which are ignored by
  default) discards its pending instances in the process and in every thread,
  as Linux's `do_sigaction` does. A blocked signal sent after that stays
  pending. An unblocked ignored signal, such as the `SIGCHLD` of a child that
  ends, ends no wait in any thread: a blocked `read` stays blocked, as Linux
  drops the signal as it is sent (`sig_ignored`).

## Filesystem

- By default every run gets its own isolated in-memory filesystem, with `/tmp`.
- Creating, reading and writing files, hard links, symbolic links, `flock`,
  `rename`, directory listing and the `stat` family. Open files stay usable
  after `unlink`.
- `renameat2` takes `RENAME_NOREPLACE`, which refuses to replace a name
  (`EEXIST`), and `RENAME_EXCHANGE`, which swaps two names (`ENOENT` if one is
  missing), in memory and in a host directory mounted on Linux or macOS.
  `RENAME_WHITEOUT` needs `CAP_MKNOD` (`EPERM`), and then gives `EINVAL`, as
  on a Linux filesystem without whiteouts.
- `linkat` takes `AT_SYMLINK_FOLLOW`, which follows a symbolic link the old
  path ends in (a dangling one is `ENOENT`) and a link in `/proc/self/fd` to
  the descriptor's file, and `AT_EMPTY_PATH`, which with an empty old path
  links the file a descriptor holds, an `O_PATH` one's too (a directory is
  `EPERM`). A removed file has no name to link again (`ENOENT`), and a
  memfd, a pipe, a socket or a file of `/proc` is on a filesystem of its own
  (`EXDEV`). Linux 6.10 and later also refuse `AT_EMPTY_PATH` for a file
  opened with other credentials than the caller's, without
  `CAP_DAC_READ_SEARCH` (`ENOENT`); this is not checked.
- Landlock restricts a thread's access to file hierarchies and TCP ports and
  what it may reach outside its domain, at ABI version 8 with errata 1 to 4:
  `landlock_create_ruleset` (and its version and errata queries),
  `landlock_add_rule` with `LANDLOCK_RULE_PATH_BENEATH` and
  `LANDLOCK_RULE_NET_PORT`, and `landlock_restrict_self` (which needs
  `no_new_privs` or `CAP_SYS_ADMIN`), up to 16 layers. Each layer allows a
  right it handles only beneath the files and directories its rules name, by
  device and inode, so a rule follows a renamed directory. Opening a file
  checks `LANDLOCK_ACCESS_FS_READ_FILE`, `WRITE_FILE`, `READ_DIR` and, for
  `execve` and its interpreters, `EXECUTE`; making a name checks its
  directory for the `MAKE_*` right of its type, removing one `REMOVE_FILE` or
  `REMOVE_DIR`, and truncating `TRUNCATE`, which an open file description
  keeps from its open. An `ioctl` on a character or block device needs
  `IOCTL_DEV`, kept the same way, except for the commands every file answers
  (`FIOCLEX`, `FIONBIO`, `FIGETBSZ` and the like). A link or rename to another
  directory needs `REFER` and must not give the file more rights than it had
  (`EXDEV`). A TCP socket's `bind` needs `LANDLOCK_ACCESS_NET_BIND_TCP` and its
  `connect` `CONNECT_TCP` for the port, with Linux's checks of the address
  first; UDP and `connect` to `AF_UNSPEC` are not checked. A whiteout, which
  `mknod` makes as character device 0 and `RENAME_WHITEOUT` leaves, needs
  `MAKE_REG`. A ruleset's scopes keep the thread from what a thread outside
  its domain made or is: `LANDLOCK_SCOPE_SIGNAL` from signalling one
  (threads of one process may always signal each other) and
  `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` from connecting or sending to an
  abstract unix socket one made (`EPERM`). As for `ptrace`, a thread in a
  domain may not read `/proc/<pid>/environ` and the like of a task outside
  it. `landlock_restrict_self` takes the logging flags and
  `LANDLOCK_RESTRICT_SELF_TSYNC`, which gives every thread of the process
  the new domain in place of the one it had. With a descriptor of -1 it
  takes `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF`, alone or with TSYNC,
  which then gives the others the caller's own domain; any other flag with
  -1 is `EBADF`. Threads, processes and `execve` keep the domain; `O_PATH`,
  `stat` and descriptors opened before are not checked.
- seccomp limits the system calls a thread makes, as Linux's
  `kernel/seccomp.c` does. Strict mode (`SECCOMP_SET_MODE_STRICT`, or
  `PR_SET_SECCOMP` with 1) allows `read`, `write`, `exit` and `rt_sigreturn`;
  any other call ends the thread by `SIGKILL`, `exit_group` too. Filter mode
  (`SECCOMP_SET_MODE_FILTER`, which needs `no_new_privs` or `CAP_SYS_ADMIN`)
  adds a classic BPF program, checked as Linux checks one: up to 4096
  instructions, only the ones seccomp takes (32-bit loads of
  `struct seccomp_data`, no `mod`), forward jumps inside the program, scratch
  words written before they are read on every path, and a return at the end,
  else `EINVAL`; all of a thread's filters may hold 32768 instructions, each
  counting 4 more (`ENOMEM`). Before each call every filter runs over the
  call's number, `AUDIT_ARCH_X86_64`, the address after its `syscall`
  instruction and its six argument registers, whole, and the lowest action
  decides. `SECCOMP_RET_KILL_PROCESS` ends the process by `SIGSYS`, and
  `SECCOMP_RET_KILL_THREAD` the thread, or the process when it is the last
  thread (a division by an X of 0 returns 0, which is this action);
  `SECCOMP_RET_TRAP` forces a `SIGSYS` with `SYS_SECCOMP`, the data in
  `si_errno`, the call's address, number and architecture, and the call's
  number back in `rax`; `SECCOMP_RET_ERRNO` returns its data, at most 4095,
  as an error; `SECCOMP_RET_TRACE` gives `ENOSYS`, as with no tracer;
  `SECCOMP_RET_USER_NOTIF` waits for the filter's listener (below), or gives
  `ENOSYS` when the filter has none; `SECCOMP_RET_LOG` and
  `SECCOMP_RET_ALLOW` run the call. `SECCOMP_FILTER_FLAG_TSYNC` gives the new
  filter to every thread, unless one is in strict mode or has a filter the
  caller's is not built on: then it returns that thread's ID, or `ESRCH` with
  `SECCOMP_FILTER_FLAG_TSYNC_ESRCH`. `SECCOMP_GET_ACTION_AVAIL` and
  `SECCOMP_GET_NOTIF_SIZES` answer as Linux. New threads and processes take
  the mode and the filters, `execve` keeps them, and `/proc/<pid>/status`
  shows them in `Seccomp` and `Seccomp_filters`.
  `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns the new filter's listener,
  close-on-exec (`anon_inode:seccomp notify`; one to a thread's filters, else
  `EBUSY`). A call the filter sends there waits until
  `SECCOMP_IOCTL_NOTIF_RECV` takes it (the oldest not taken, with an id that
  starts at random, the thread's ID and its `seccomp_data`) and
  `SECCOMP_IOCTL_NOTIF_SEND` answers it with a value, an error or
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which runs it. Meanwhile
  `SECCOMP_IOCTL_NOTIF_ADDFD` has the waiting thread install one of the
  listener's files, at its lowest free descriptor or at the one asked for,
  and with `SECCOMP_ADDFD_FLAG_SEND` the call returns that descriptor;
  `SECCOMP_IOCTL_NOTIF_ID_VALID` and `SECCOMP_IOCTL_NOTIF_SET_FLAGS` answer as
  Linux. The listener polls readable while a call waits to be taken, writable
  while one taken waits for its answer, and hung up once no thread runs the
  filter. A signal takes a waiting call back with `EINTR`, which a
  `SA_RESTART` handler or a stop runs again as a new call (and any handler,
  for a call not taken yet, with Linux master's
  `SECCOMP_FILTER_FLAG_RESTART_BEFORE_RECV`); a receive it was counted for
  then finds nothing (`ENOENT`), as on Linux.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` keeps a call taken waiting through
  every signal but a fatal one. Closing the listener answers every waiting
  call with `ENOSYS`, as later calls get.
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
- **aube**: a Node.js package manager written in Rust (v2.9.0). `--version`,
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
