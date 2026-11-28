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
- **Segment registers**: `mov` to and from `%ds`, `%es`, `%fs`, `%gs` and
  `%ss`, and `push` and `pop` of `%fs` and `%gs`, load a selector with the
  checks of a 64-bit CPU at privilege level 3. It is looked up in Linux's
  GDT (`__USER32_CS` 0x23, `__USER_DS` 0x2b, `__USER_CS` 0x33 and the CPU
  number segment 0x7b load; the kernel's segments, the system descriptors
  and the empty thread-local entries do not) or in the table `modify_ldt`
  writes. A load the CPU refuses is `SIGSEGV` for #GP, or `SIGBUS` for #NP
  (#SS for `%ss`), with `SI_KERNEL`, the vector in `trapno` and the
  selector without its RPL in `err`, as Linux gives them; `mov` to `%cs` is
  `SIGILL`. A far `jmp` and `call` through an `m16:16`, `m16:32` or
  `m16:64` pointer and a far `ret` load `%cs` with the same checks of a code
  segment: `__USER_CS` runs, whatever RPL the selector has for a jump or
  call (a return needs RPL 3), and a call pushes `%cs` and the return
  address in slots of the offset's size; a null selector, data, a system
  descriptor, the kernel's code or a return to an offset that is not
  canonical is `SIGSEGV` for #GP, and a code segment not present `SIGBUS`
  for #NP, with nothing moved. A selector that is not null gives `%fs` or `%gs` the 32-bit
  base of its descriptor, and a null one clears it, as Intel's CPUs and
  AMD's since Zen 2 do; in 64-bit mode the other segments have no base.
  `arch_prctl`'s `ARCH_SET_FS` and `ARCH_SET_GS`, `PTRACE_ARCH_PRCTL` and
  `CLONE_SETTLS` make the selector of the base they set null. A system call
  gives back `__USER_CS` and `__USER_DS` in `%cs` and `%ss`. A signal frame
  shows the task's `%ss`, and its handler runs on it while it still loads
  (`force_valid_ss`); `rt_sigreturn` restores it, and a return to one that
  no longer loads faults there, as Linux's `iret` does. A fork keeps the
  selectors, an exec starts with Linux's, and ptrace and core dumps show
  them.
- **Hints**: `PAUSE` and the `PREFETCHNTA`/`PREFETCHT0`/`T1`/`T2` prefetches,
  which change nothing and never fault.
- **Traps**: the trap flag single-steps: with `TF` set, which `popf`,
  `rt_sigreturn` and a tracer may set, each instruction is followed by a
  `SIGTRAP` with `TRAP_TRACE` and its address past the instruction (trap
  1), except `syscall`, as the flag is masked off in the kernel and Linux
  returns with `iret`, and a `rep` string instruction traps after each
  iteration, with `rip` still on it until the last; a signal handler
  starts with the flag cleared.
  `int3` gives `SIGTRAP` from the kernel (`SI_KERNEL`, trap 3) with `rip`
  past it.
- **SSE**: every SSE and SSE2 instruction, except those that use MMX registers
  (a test runs each encoding), the `MFENCE`/`LFENCE`/`SFENCE` fences among them.
  Of the later sets, the instructions real programs (probe, aube, pitchfork,
  ripgrep and coreutils) use, and cryptographic instructions such as AES, PCLMUL
  and SHA. Floating
  point is computed in software.
- Instructions are decoded with [iced-x86](https://github.com/icedland/iced).
- `CPUID` does not reveal the host's values. It names AMD as the vendor, because
  glibc reads the features only for a vendor it knows, and reports the features
  every x86-64 CPU has, because glibc requires them, and `CLFLUSH` with its
  64-byte line, because HotSpot requires it. Of those, the FPU and MMX
  are not implemented; it advertises no other feature that is not. The name
  changes nothing else: where vendors' CPUs differ, as in the flags after a
  `REP` faults, the virtual CPU keeps its own behaviour. `/proc/cpuinfo`
  describes this CPU too.
- `RDTSC` and `RDTSCP` read a counter of the virtual CPU, which moves on with
  each read rather than with time. Every guest in the host process shares that
  counter, so its values depend on what else has read it. `RDSSP` does nothing
  and `map_shadow_stack` gives `EOPNOTSUPP`, as there are no shadow stacks. `FXSAVE` and `FXRSTOR` keep the x87 state,
  MXCSR and the XMM registers.
- x87 instructions move values, convert them, compare them and keep the unit's
  control and status words, environment and stack, in every rounding mode. They
  add, subtract, multiply, divide and take square roots in every rounding mode
  and precision, and do `FPREM`, `FPREM1`, `FSCALE`, `FRNDINT`, `FXTRACT`, the
  `FCOM` family, the `FLD` constants and `FCMOV`, and the transcendental
  instructions (`FSIN`, `FCOS`, `FSINCOS`, `FPTAN`, `FPATAN`, `F2XM1`, `FYL2X`,
  `FYL2XP1`) that the `long double` math of glibc and musl uses, correctly
  rounded, which is not always a real CPU's last bit
  ([Limitations](./limitations)). They load and store packed decimals (`FBLD`,
  `FBSTP`), and save and restore the unit with `FNSAVE`, `FRSTOR`, `FNSTENV` and
  `FLDENV`, also in their 16-bit forms (with a `0x66` prefix). A signal handler
  starts with the x87 and SSE state as after a reset, as on Linux.
- AVX, AVX-512 and MMX are out of scope: `CPUID` reports MMX because glibc
  requires it, but its instructions stop with `SIGILL`.

When a guest reaches an instruction it cannot run, it gets `SIGILL`, as on real
Linux. Page faults raise `SIGSEGV`, and integer division by zero `SIGFPE`, as
does an unmasked floating-point exception. An SSE one, which MXCSR unmasks,
raises it at the instruction itself: the destination is left as it was, and
MXCSR keeps the instruction's exception flags, as a signal handler sees them.
An x87 one raises it at the next x87 instruction that waits, which is where a
CPU raises it, and leaves its own instruction's result as on a CPU: an invalid
operation, a division by zero or an arithmetic denormal operand changes no
register, and an overflow or underflow rebiases a register's result by 2²⁴⁵⁷⁶
and stores nothing to memory.

## System calls

Only implemented system calls are handled, through an explicit table.
Everything else returns `ENOSYS`; nothing is passed to the host. The table
below names every implemented call, which `lint:all` checks against the
kernel.

| Group | System calls |
|---|---|
| Processes and threads | `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `wait4`, `waitid`, `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, `kcmp`, `process_vm_readv`/`process_vm_writev`, `ptrace` (see Threads and processes), `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `set_tid_address`, `futex`, `futex_waitv`, `futex_wake`/`futex_wait`/`futex_requeue`, `set_robust_list`, `get_robust_list`, `sched_setaffinity`/`sched_getaffinity`, `getcpu`, `sched_yield`, `sched_setscheduler`/`sched_getscheduler`, `sched_setparam`/`sched_getparam`, `sched_setattr`/`sched_getattr`, `sched_get_priority_max`/`sched_get_priority_min`, `sched_rr_get_interval`, `ioprio_set`/`ioprio_get`, `personality`, `unshare`, `setns`, `membarrier`, `rseq`, `setpgid`/`getpgid`/`getpgrp`, `setsid`/`getsid`, `getpriority`/`setpriority`, `prlimit64`/`getrlimit`/`setrlimit`, `prctl` |
| Memory | `mmap` (anonymous, and files private or shared), `munmap`, `mremap`, `mprotect`, `pkey_mprotect`/`pkey_alloc`/`pkey_free`, `mseal`, `madvise`, `process_madvise`, `process_mrelease`, `mincore`, `cachestat`, `mlock`/`mlock2`/`munlock`/`mlockall`/`munlockall`, `mbind`, `set_mempolicy`/`get_mempolicy`, `set_mempolicy_home_node`, `migrate_pages`, `move_pages`, `map_shadow_stack`, `msync`, `remap_file_pages`, `brk`, `arch_prctl`, `modify_ldt`, `userfaultfd` (see below) |
| System V IPC | `shmget`, `shmat`, `shmdt`, `shmctl` (shared memory); `semget`, `semop`, `semtimedop`, `semctl` (semaphores); `msgget`, `msgsnd`, `msgrcv`, `msgctl` (message queues) |
| POSIX message queues | `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr` |
| Keys | `add_key`, `request_key`, `keyctl` |
| System information | `uname`, `sethostname`, `setdomainname`, `sysinfo`, `getrusage`, `times`, `acct`, `iopl`, `ioperm`, `syslog`, `sysfs`, `perf_event_open` (see below) |
| Credentials | `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`/`getresgid`, `setuid`/`setgid`, `setreuid`/`setregid`, `setresuid`/`setresgid`, `setfsuid`/`setfsgid`, `getgroups`/`setgroups`, `capget`/`capset` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`, `tgkill`, `getitimer`/`setitimer`, `alarm`, `rt_sigtimedwait`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `timer_create`/`timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete`, `adjtimex`, `clock_adjtime`, `settimeofday`, `clock_settime` |
| Files | `open`/`openat`/`openat2`/`creat`, `read`, `write`, `readv`/`writev`, `pread64`/`pwrite64`, `preadv`/`pwritev`, `preadv2`/`pwritev2`, `copy_file_range`, `sendfile`, `splice`, `tee`, `vmsplice`, `setxattr`/`lsetxattr`/`fsetxattr`, `getxattr`/`lgetxattr`/`fgetxattr`, `listxattr`/`llistxattr`/`flistxattr`, `removexattr`/`lremovexattr`/`fremovexattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat`, `file_getattr`, `file_setattr`, `close`, `close_range`, `lseek`, `stat`/`fstat`/`lstat`/`newfstatat`, `statx`, `name_to_handle_at`, `open_by_handle_at`, `getdents`/`getdents64`, `mkdir`/`mkdirat`, `mknod`/`mknodat`, `rmdir`, `unlink`/`unlinkat`, `rename`/`renameat`/`renameat2`, `link`/`linkat`, `symlink`/`symlinkat`, `readlink`/`readlinkat`, `truncate`/`ftruncate`, `fallocate`, `memfd_create`, `memfd_secret`, `flock`, `fcntl`, `dup`/`dup2`/`dup3`, `pipe`/`pipe2`, `chdir`/`fchdir`, `getcwd`, `chroot`, `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_tree_attr`, `statmount`, `listmount`, `umask`, `chmod`/`fchmod`/`fchmodat`/`fchmodat2`, `chown`/`fchown`/`lchown`/`fchownat`, `utimensat`, `utime`/`utimes`/`futimesat`, `fsync`/`fdatasync`, `sync_file_range`, `sync`, `syncfs`, `fadvise64`, `readahead`, `access`/`faccessat`/`faccessat2`, `statfs`/`fstatfs`, `ustat` |
| Landlock | `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` |
| Security modules | `lsm_list_modules`, `lsm_get_self_attr`, `lsm_set_self_attr` |
| Probes | `uprobe`, `uretprobe` |
| Administration | `reboot`, `swapon`/`swapoff`, `init_module`/`finit_module`/`delete_module`, `kexec_load`/`kexec_file_load`, `quotactl`/`quotactl_fd` |
| seccomp | `seccomp` (see below) |
| BPF | `bpf`, for maps, and `BPF_PROG_LOAD` of socket filters, with a verifier and an interpreter, attached to AF_UNIX, UDP and TCP sockets or run with `BPF_PROG_TEST_RUN` (see below) |
| I/O | `poll`, `ppoll`, `select`, `pselect6`, `vhangup`, `ioctl` (`TCGETS`, `TIOCGWINSZ`, `FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, `FIOQSIZE`, `FIGETBSZ`, `SIOCATMARK`, `FIONREAD`/`SIOCINQ`, `SIOCOUTQ`, `SIOCGIFFLAGS`, `SIOCSIFFLAGS`, `SIOCGIFINDEX` and `SIOCGIFNAME` of the loopback and veth ends, `INOTIFY_IOC_SETNEXTWD`, the seccomp listener's `SECCOMP_IOCTL_NOTIF_*` (see seccomp below), `FS_IOC_GETFLAGS`, `FS_IOC_SETFLAGS`, `FS_IOC_FSGETXATTR`, `FS_IOC_FSSETXATTR`, and the pseudo-terminals' requests below) |
| Events | `eventfd`/`eventfd2`, `timerfd_create`/`timerfd_settime`/`timerfd_gettime`, `signalfd`/`signalfd4`, `inotify_init`/`inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`, `fanotify_init`, `fanotify_mark`, `epoll_create`/`epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `io_uring_setup`, `io_uring_enter`, `io_uring_register` (see below) |
| Asynchronous I/O | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents` (see below) |
| Sockets | `socket` (`AF_UNIX` streams, packet and datagram sockets; `AF_INET`, `AF_INET6`, `AF_NETLINK` (`NETLINK_ROUTE`, `NETLINK_SOCK_DIAG` and `NETLINK_GENERIC`) and `AF_MCTP` datagrams with a [network](#network) or in a new network namespace, else `EAFNOSUPPORT`), `connect`, `getsockname`, `getpeername`, `bind`, `listen`, `accept` and `accept4` (AF_UNIX streams and packet sockets, and on the guest's own [loopback](#loopback-servers) TCP), `socketpair` (AF_UNIX, `SOCK_STREAM`, `SOCK_SEQPACKET` and `SOCK_DGRAM`), `sendto`, `recvfrom`, `sendmsg` and `recvmsg` (passing descriptors with `SCM_RIGHTS`, credentials with `SCM_CREDENTIALS` and the sender's pidfd with `SCM_PIDFD`), `sendmmsg` and `recvmmsg`, `setsockopt` and `getsockopt` (`SOL_SOCKET`), `shutdown` |
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
  since Linux 6.18, also one to a pipe whose last reader leaves after part
  of it went, which returns that part. `RWF_NOAPPEND` turns an `O_APPEND` file's append off
  for the call: a write goes to the offset (growing the file past its end)
  or, at -1, to the position, which then moves past it; an append-only file
  (`FS_APPEND_FL`) gives `EPERM`, for a read too. `RWF_APPEND` writes a
  regular file at its end, `RWF_DSYNC` and `RWF_SYNC` write it through as
  `fdatasync`, and `RWF_HIPRI` changes nothing.

- `copy_file_range` copies between two regular files on one mount (`EXDEV`
  across mounts), stopping at the input's end, with Linux's checks in order
  (`EISDIR`, `EINVAL`, `EBADF`, `EOVERFLOW`, and `EINVAL` for an overlap in
  one file). `sendfile` reads a regular file into any writable file; into a
  pipe it is a `splice`, as Linux's `splice_file_to_pipe`: once the pipe has
  room it takes what fits and does not wait for more, waiting first only
  when the pipe is not `O_NONBLOCK`. Both update the given offsets or the
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
  nothing, as the bytes are copied. A call is atomic against the other
  readers and writers of its pipe, as Linux's pipe lock makes it: while its
  copy waits (for a `userfaultfd`, or the room of a socket), a read of the
  pipe, a write to it, its `FIONREAD`, `F_GETPIPE_SZ` and `F_SETPIPE_SZ`,
  and the close of one of its ends, wait for it too, whatever signal comes,
  as Linux's `mutex_lock` does; a poll does not. A fill of the page that
  needs the same pipe never comes, as on Linux; a fatal signal ends the
  copy's wait. `read`, `readv`, `write`, `writev` and their io_uring and
  aio requests copy with the pipe held too (`anon_pipe_read`,
  `anon_pipe_write`), a pipe's buffer at a time: one that a read or a
  `vmsplice` cannot copy whole stays in the pipe, and one a write cannot
  copy ends it with those before. Only the bytes there need their part of a
  read's buffer.
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
  and in a sticky directory only its owner or a caller with `CAP_FOWNER`
  changes them (`EPERM`). `trusted.*` shows only with `CAP_SYS_ADMIN`.
  `security.*` and `system.*` ask nothing of the file's access, and
  `security.*` needs `CAP_SYS_ADMIN` to change. A name is from 1 to 255 bytes
  (`ERANGE`), a value at most 64 KiB (`E2BIG`), and any other namespace gives
  `EOPNOTSUPP`. The name is read before the file is found, as since Linux 6.13.

- File capabilities (`security.capability`) are checked and converted as
  Linux's capability module does. A value written must be a `vfs_cap_data` of
  revision 2 (20 bytes) or 3 (24 bytes) (`EINVAL`), and the caller needs
  `CAP_SETFCAP` in a user namespace that maps the file's owner and group
  (`EPERM`), which removing them needs too. A caller with `CAP_SETFCAP` over
  the first user namespace keeps a revision 2 value; any other value is
  stored as revision 3 with the kernel ID of the root it names in the
  caller's namespace, which must map it (`EINVAL`). Reading gives a revision 3
  value when the reader's namespace maps that root to an ID other than 0, a
  revision 2 one when it is root there or above, and `EOVERFLOW` otherwise.
  A write or truncation of the file, and a `chown` of anything but a
  directory, takes them away, whoever does it. `execve` gives them to the
  program it runs (see the credentials below).

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
  Linux does: the one `/proc/self/mountinfo` shows (`STATX_MNT_ID`), or
  the 64-bit one unique until the machine ends, which `statmount` and
  `listmount` take, in its place when `STATX_MNT_ID_UNIQUE` is asked for. A file
  of an internal file system (a pipe, a socket, a memfd and the like; see
  `statfs` below) is on a mount with one of the small IDs that mountinfo,
  whose IDs start at 21, does not show, as Linux's internal mounts are.
  `AT_EMPTY_PATH` names the descriptor, or the working directory for
  `AT_FDCWD`, and as since Linux 6.11 a null path with it does too.
  `stx_attributes_mask` has the attributes Linux 7.0 knows for every file
  (`STATX_ATTR_AUTOMOUNT`, `STATX_ATTR_MOUNT_ROOT` and `STATX_ATTR_DAX`, of
  which no file here has the first or the last). A tmpfs or devtmpfs file,
  a symbolic link, a special file or a memfd too, adds
  `STATX_ATTR_IMMUTABLE`, `STATX_ATTR_APPEND` and `STATX_ATTR_NODUMP`, as
  `shmem_getattr` does. `STATX_ATTR_MOUNT_ROOT` is set for a mount's root by
  whatever path names it (`.`, `..`, a link on the way, its descriptor), and
  not for a symbolic link, a chroot's root that is no mount's, or the file
  of a pipe or socket. A `/proc/<pid>` directory has no
  `STATX_ATTR_IMMUTABLE`, though its inode is `S_IMMUTABLE`, as proc's
  `getattr` gives none on Linux.

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
  (`EINVAL`, `EFAULT`); `MFD_HUGETLB` makes a file on hugetlbfs (see
  `MAP_HUGETLB` below). Its seals, through `fcntl`'s `F_ADD_SEALS` and
  `F_GET_SEALS`, start as `F_SEAL_SEAL` unless `MFD_ALLOW_SEALING` is given
  (`F_SEAL_EXEC` with `MFD_NOEXEC_SEAL`), and restrict the file as tmpfs
  does: `F_SEAL_WRITE` and `F_SEAL_FUTURE_WRITE` refuse writes, punch holes
  and writable shared mappings, `F_SEAL_SHRINK` and `F_SEAL_GROW` the size
  (a write stops at the last page that ends within the file), and
  `F_SEAL_EXEC` the execute bits, all with `EPERM`. A fault of a mapping
  of a memfd brings the page into the file, as `shmem_fault` does, a
  private mapping's read or copy-on-write fault too, so `st_blocks` counts
  it, as for the files of a tmpfs mount. Memfds share a
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
  `MADV_POPULATE_WRITE` give `EINVAL`, `process_vm_readv` and
  `process_vm_writev` `EFAULT`, `PTRACE_PEEKDATA` and `PTRACE_POKEDATA`
  `EIO`, and `mlock` `ENOMEM`, with
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
  and `RESOLVE_NO_MAGICLINKS` no link in `/proc/self/fd` or `exe`, `cwd` and
  `root` (`ELOOP`); `RESOLVE_NO_XDEV` crosses no mount, `/proc` and `/dev`
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
  owner ends. A shared operation on a read-only anonymous page is `EFAULT`,
  and on a read-only private mapping's page of a file it names the file, as
  a shared mapping's does. A wake wakes one waiter even when asked for 0 or fewer, as
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
  `AF_INET`, `AF_INET6`, `AF_NETLINK` and `AF_MCTP`.

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
  A file without a poll of its own (a regular file, a directory, `/dev/null`,
  `/dev/zero`, `/dev/full` and `/dev/urandom`, a file of a process's `/proc`
  directory) gives `POLLIN`, `POLLOUT`, `POLLRDNORM` and `POLLWRNORM`
  (`DEFAULT_POLLMASK`) and `epoll_ctl` refuses it (`EPERM`); `/dev/random`
  gives `POLLIN` and `POLLRDNORM`.

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
  The files of `/proc` and `/dev` keep `O_DIRECTORY`, `O_NOFOLLOW` and
  `O_SYNC` of their open too, and one that is no directory is `ENOTDIR`
  with `O_DIRECTORY`.
  `F_SETFL` changes only `O_APPEND`, `O_NONBLOCK`, `O_DIRECT`, `O_NOATIME`
  and, on a file that signals, `O_ASYNC`; the access mode and the other
  flags stay, as Linux's `setfl` keeps them.

- An `O_PATH` descriptor holds only a path, as Linux's `fdget` refuses it:
  reading and writing it, `lseek`, `flock`, `getdents`, `getdents64`, `sendfile`,
  `copy_file_range`, `splice`, `tee`, `vmsplice`, `fsync`, `fdatasync`, `syncfs`, `sync_file_range`,
  `fadvise64`, `readahead`, `ftruncate`,
  `fallocate`, `mmap`, `ioctl`, the `f*xattr` calls, `epoll_ctl` (as the
  epoll descriptor or the target), `epoll_wait` and `fcntl`
  (but for `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_DUPFD_QUERY`, `F_GETFD`,
  `F_SETFD` and `F_GETFL`) are `EBADF`, and `poll` gives `POLLNVAL`, while
  `select` finds it ready in every set. `fstat`, `fstatfs`, `fchdir`, `dup` and `close`
  take it, and it is a directory for the `*at` calls. Of the flags of an
  open with it, only `O_DIRECTORY`, `O_NOFOLLOW` and `O_CLOEXEC` count
  (`build_open_how`): an access mode asks nothing (no `EISDIR`, `EROFS`,
  `ETXTBSY` or `EACCES`), and `O_CREAT` and `O_TRUNC` do nothing.

- `O_DIRECT` and `O_NOATIME` are checked as Linux's `open` and `F_SETFL`
  check them. `O_DIRECT` needs a regular file of a disk file system or
  tmpfs, or a memfd opened again by a path (`EINVAL` for a directory, a
  device, a FIFO, a socket, an anonymous inode or a file of `/proc`);
  `F_SETFL` also takes it on a pipe or FIFO. `O_NOATIME` needs the file's
  owner or `CAP_FOWNER` (`EPERM`), at `open` and when `F_SETFL` newly
  sets it.

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
  `EDEADLK` when that would close a cycle of owners that wait for each
  other's record locks (`posix_locks_deadlock`, through up to 11 waits). A
  wait counts for that only while the lock it waits for stays:
  unlocking, cutting or closing it ends the wait there at once, as
  `locks_wake_up_blocks` does, even before the waiter runs again. A wait
  for a record lock or a `flock` lock that conflicts with an earlier one
  for the same lock is behind that one, which gets the lock first
  (`__locks_insert_block`). The
  locks are the guest's own: a program on the host does not see them, nor
  they its. `/proc/locks` lists the record locks, the `flock` locks and the
  leases as `locks_show` prints them: those of each CPU in turn (as `getcpu`
  numbers it where the lock was taken), the latest first, a merged lock at
  its first one's place and a split one's left piece as new
  (`posix_lock_inode`), each with those that wait for it (`-> `, deeper for
  one behind another), opens that break a lease too, without those of
  processes outside the reader's PID
  namespace. `/proc/<pid>/fdinfo` lists a description's own, its lease last
  (`show_fd_locks`).

- File leases (`fcntl`'s `F_SETLEASE` and `F_GETLEASE`), as Linux's
  `fs/locks.c` takes and gives them back: a read or write lease on an open
  description of a regular file (a file of a mounted file system or a
  memfd), until `F_UNLCK` or the description's last close
  (`locks_remove_file`). A lease is refused in `fcntl_setlease`'s order: a
  directory or an unknown type (`EINVAL`), a file whose owner is not the
  caller's file system user ID without `CAP_LEASE` (`EACCES`), a file that
  takes none, as a pipe or a `/proc` file (`EINVAL`), a conflicting open
  (`lease_open_conflict`, `EAGAIN`: for a read lease, any description open
  for writing; for a write lease, any other description open for reading or
  writing, or a program running from the file), another description's lease
  beside a write lease (`EAGAIN`), and a new lease while
  `/proc/sys/fs/leases-enable` is 0 (`EINVAL`). Asking again through the
  same description changes the lease's type. A lease taken gives the
  description an owner if it has none, and `F_UNLCK` takes the owner and
  the `F_SETSIG` signal away (`f_delown`); `F_UNLCK` with no lease is
  `EAGAIN`. `F_GETLEASE` gives the description's lease type (the one it is
  to become, while it is being broken), or `F_UNLCK`. An open or a
  `truncate` that conflicts with a lease breaks it as `__break_lease` does,
  the opener's own leases too: an open for reading only a write lease, which
  is to become a read lease, and any other both kinds, which are to go. The
  break signals the holder once (`SIGIO`, or the `F_SETSIG` signal with
  `POLL_MSG`), and the opener waits for the holder, its access counted
  already; a wait of `/proc/sys/fs/lease-break-time` seconds (0 or less has
  no end) downgrades or removes the lease itself, `O_NONBLOCK` gives
  `EWOULDBLOCK` instead, and a signal ends the wait (`ERESTARTSYS`).
  `/proc/sys/fs/leases-enable` (1 at first) and `/proc/sys/fs/lease-break-time`
  (45 at first) are root's files of mode 0644, which take any `int`
  (`proc_dointvec`).

- `/proc/sys/fs/nr_open` and `/proc/sys/fs/pipe-max-size` (both 1048576 at
  first) are the machine's, root's files of mode 0644 that take an
  `unsigned int` (`proc_douintvec_minmax`): `nr_open` from 64 to 2147483584
  (`EINVAL` otherwise), and `pipe-max-size` cut to 32 bits and rounded up to
  a power of two of at least a page, as `round_pipe_size` rounds it, past
  2³¹ `EINVAL`. `nr_open` bounds the hard `RLIMIT_NOFILE` (`EPERM` past it)
  and each descriptor table, as Linux's tables grow: a table has room for 64
  descriptors at first, and a number past its room grows it to the least
  power of two that holds the number, but not past `nr_open`, cut back to a
  multiple of 64, nor past 2²⁷ descriptors; a number it cannot grow to is
  `EMFILE` (`EBADF` for `dup2` and `dup3`). A table that grew keeps its room
  when `nr_open` drops. A copy of a table (`fork`, `clone` without
  `CLONE_FILES`, `unshare(CLONE_FILES)`, `CLOSE_RANGE_UNSHARE` and the exec
  of a thread that shares its table) has room for its highest number in use,
  in steps of 64, not counting the numbers `close_range` closes, and fails
  with `EMFILE` when `nr_open` no longer lets a table have that much; the
  exec, past its point of no return, ends with `SIGSEGV`. An embedder's
  ceiling on open files bounds the hard limit beside `nr_open`, whatever
  root writes to it.

- A pipe holds 16 buffers of a page each (64 KiB), as on Linux, and
  `fcntl`'s `F_SETPIPE_SZ` and `F_GETPIPE_SZ` resize and report it like
  `pipe_set_size`: a power of two of at least a page, `EBUSY` below the
  buffers in use and `EINVAL` past 2³¹. Without `CAP_SYS_RESOURCE`, a new
  pipe or FIFO holds no more than `/proc/sys/fs/pipe-max-size`, and
  `F_SETPIPE_SZ` may not grow a pipe past it (`EPERM`), as
  `alloc_pipe_info` and `pipe_set_size` have it. A write's bytes past whole pages
  join the last buffer where it has room, and the rest go into new
  buffers, as `anon_pipe_write` places them; `splice`, `tee` and
  `vmsplice` make buffers of their own, which no write joins.

- A pipe's packet mode: a write end with `O_DIRECT` (`pipe2`, or
  `F_SETFL`, which `F_GETFL` shows) writes each page as a packet of its
  own, and a read ends at the end of a packet and drops the rest of it.
  Packets fill a buffer each, so 16 fill a pipe however small they are.
  `splice` and `tee` to another pipe keep them; a splice to a file takes
  bytes across them.

- A `SOCK_DGRAM` pair keeps message boundaries like `SOCK_SEQPACKET`, but has
  no end of file: when the peer closes, reads wait and the next send gets
  `ECONNREFUSED`, then `ENOTCONN`; that send drops what the end has not
  read, as below. Only `SOCK_STREAM` raises `SIGPIPE` with
  `EPIPE`, as on Linux, and only when nothing was sent; a pipe raises it
  also when its last reader leaves after part of a write, which returns
  that part.

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
  is written back once a message came. `recvmmsg` first gives the socket's
  pending error, unless `MSG_ERRQUEUE` asks for its error queue, and an
  error after some messages other than `EAGAIN` becomes that pending error,
  for the next call or `SO_ERROR` (a wait a signal would restart leaves
  `ERESTARTSYS`'s 512 there, as on Linux). A datagram or packet socket's
  receive gives it before its queue too, and an AF_UNIX stream's only once
  nothing is queued, as Linux's `unix_stream_read_generic` does.

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

  Naming an owner keeps who named it, as `sigio_perm` checks: `F_SETOWN`,
  `F_SETOWN_EX`, and dnotify, a lease or a terminal's `O_ASYNC` making the
  caller the owner of a file that has none. The file's signals, and a
  socket's `SIGURG`, reach a process (or the thread `F_OWNER_TID` names)
  only when the effective user ID kept is root's, or either kept user ID is
  that process's real or saved one. Who makes the file signal does not count,
  nor does a later `F_SETSIG`. A Landlock domain of the one who named the
  owner, if it scopes signals, keeps them from processes outside it, though
  never from that one's own process; a domain entered after naming the owner
  does not count.
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
    the host has no room for. A write to either once its reader is gone (a
    pipe into a `head` that has exited) is `EPIPE` and raises `SIGPIPE`, as
    a write to any pipe with no reader. A write whose reader leaves after
    part of it went still raises `SIGPIPE`, and returns that part, as
    Linux's `pipe_write`.
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

- `mmap` takes the types of `do_mmap` (`MAP_TYPE`, four bits): a file, and
  `/dev/zero`, maps `MAP_SHARED`, `MAP_SHARED_VALIDATE` or `MAP_PRIVATE`;
  anonymous memory `MAP_SHARED`, `MAP_PRIVATE` or `MAP_DROPPABLE`; any other
  value is `EINVAL`. `MAP_SHARED_VALIDATE` is `MAP_SHARED` that refuses a
  flag Linux's `LEGACY_MAP_MASK` does not hold (`EOPNOTSUPP`, after the
  file's size is checked and before its access): `MAP_FIXED_NOREPLACE`, the
  huge page size's bit 31, which neither 2 MiB's nor 1 GiB's has, any unknown
  bit, also above bit 31, and `MAP_SYNC` but on ext4 and xfs (`FOP_MMAP_SYNC`;
  a host file system Linux has no number for counts as ext4); `MAP_SHARED`
  drops them. Of a file of ext4 or xfs, `MAP_SYNC` with any type is then
  `EOPNOTSUPP` after the other checks, as no file is DAX's
  (`daxdev_mapping_supported`). `MAP_DROPPABLE` memory is private anonymous
  memory with `VM_DROPPABLE` (`VmFlags: dp`), `VM_NORESERVE`, `VM_WIPEONFORK` and
  `VM_DONTDUMP`: a `fork`ed child gets it with none of its pages and a core
  holds none of it, for good (`MADV_KEEPONFORK` and `MADV_DODUMP` are
  `EINVAL`). It may not be `MAP_LOCKED`, `MAP_GROWSDOWN` or `MAP_HUGETLB`
  (`EINVAL`), neither `mlock` nor `mlockall`'s `MCL_FUTURE` locks it (as
  Linux master's `vma_supports_mlock`, which the CI runners' kernels follow
  where v7.0's source would lock it), `MADV_MERGEABLE` passes it by, and a
  `userfaultfd` does not register it (`EINVAL`). Linux drops its pages under
  memory pressure, which the emulator never has, so they stay.

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
  end of its file). A writable private mapping's pages are brought in by
  writing them, as Linux's `populate_vma_page_range` does (`FOLL_WRITE`):
  a page of a file there becomes a copy of its own, which no longer shows
  the file's later writes. Any other mapping's pages are brought in by
  reading them (`FOLL_FORCE`), which takes a page of a shmem file (a
  memfd, a tmpfs mount's file) into the file, so that it counts in its
  blocks at once. `MAP_POPULATE` (without `MAP_NONBLOCK`), `MAP_LOCKED`,
  `mlockall` with `MCL_CURRENT` and a growing `mremap` of a locked mapping
  bring their pages in the same way (`mm_populate`), but ignore a page that
  cannot be: it ends its mapping's, so that an `mmap` past a tmpfs mount's
  size still succeeds with the pages that fit. An `mprotect` that makes a
  locked private mapping writable writes its pages in. A lock with
  `MLOCK_ONFAULT` or `MCL_ONFAULT` brings nothing in, and nor does a
  mapping without access, one of a `memfd_secret` file, or one that is
  `VM_IO` or `VM_PFNMAP` (a perf ring). `mlockall` locks every mapping with `MCL_CURRENT`
  (`ENOMEM` when all that is mapped does not fit) and every new one with
  `MCL_FUTURE`, which `mmap`, `brk` and a growing `mremap` then need room
  for (`EAGAIN`; `brk` keeps the break), as `MAP_LOCKED` does; `munlockall`
  undoes both. A locked VMA refuses `MADV_DONTNEED`, `MADV_FREE`,
  `MADV_COLD`, `MADV_PAGEOUT`, `MADV_REMOVE` and `MADV_GUARD_INSTALL`
  (`EINVAL`, after the VMAs before it took the advice) and `msync` with
  `MS_INVALIDATE` (`EBUSY`); `MADV_DONTNEED_LOCKED` takes it. A `fork`ed
  child has no lock, nor does the old range `MREMAP_DONTUNMAP` leaves, and
  the rings of AIO, `io_uring` and perf events are never locked. Unknown flags of
  `mlock2` and `mlockall` give `EINVAL`. Nothing is ever swapped out, so
  memory stays in place without more being done.

- `madvise`: `MADV_DONTNEED` empties private pages and drops their entries.
  Anonymous ones then read as zeros, and those of a file mapping read the
  file again at their next access, as it is then, as Linux faults them in
  from the file; this holds
  after `mremap` moves the mapping and in a `fork`ed child. The program's own
  segments are laid out as Linux lays them out: the pages that hold file
  data are a file mapping and read the executable again, also those of a
  read-only segment (code) that `mprotect` made writable and that was
  written, while the rest (`.bss`) is anonymous memory and reads as zeros.
  Shared memory keeps its own contents and loses its entries, as Linux's
  zap clears them: shmem's, System V shared memory's and a shared file
  mapping's pages are mapped again at their next access. `MADV_FREE` keeps the contents, as
  Linux does without memory pressure.
  `MADV_WILLNEED` is accepted, and so are `MADV_COLD` and `MADV_PAGEOUT`
  (with nothing to reclaim, hints too): each needs the range mapped
  (`ENOMEM`), and the last two refuse locked memory, huge pages
  (`MAP_HUGETLB`) and memory Linux maps `VM_PFNMAP` (`EINVAL`). `MADV_DONTNEED_LOCKED` discards as
  `MADV_DONTNEED` does. `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE`
  fault the pages in, as a read or a write would (the zero page, a page of
  its own), up to a page no mapping holds (`ENOMEM`), one its mapping may
  not read or write (`EINVAL`), or one past the end of its file (`EFAULT`).
  `MADV_DONTFORK` and `MADV_DOFORK`, `MADV_WIPEONFORK` and
  `MADV_KEEPONFORK`, `MADV_DONTDUMP` and `MADV_DODUMP`, the access-pattern
  hints (`MADV_NORMAL`, `MADV_SEQUENTIAL`, `MADV_RANDOM`), `MADV_HUGEPAGE`
  and `MADV_NOHUGEPAGE`, and KSM's `MADV_MERGEABLE` (which leaves shared
  memory as it is) and `MADV_UNMERGEABLE` set and clear flags of the VMAs
  of the range (no page here depends on the last ones), which then split from and merge with
  their neighbours as Linux's do (`/proc/<pid>/maps`). They go VMA by VMA:
  one that refuses the advice stops it with `EINVAL` (`MADV_WIPEONFORK`
  takes only private anonymous memory, memory core mm does not back, as
  the rings of AIO, `io_uring` and perf events, takes no `MADV_DOFORK` or
  `MADV_DODUMP`, though huge pages take `MADV_DODUMP`, huge pages take no
  `MADV_HUGEPAGE`, and a perf ring buffer takes no change to only a part of
  it), and a hole in the range gives
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
  which Linux maps `VM_DONTEXPAND`, huge pages and the vDSO's data take
  neither advice (`EINVAL`). On memory that is not private anonymous
  memory, a uffd-wp marker stops an install, as Linux's
  `madvise_guard_install` meets one its zap keeps (and the zap leaves one
  for each write-protected page): the pages before it take guards, the
  rest lose their entries, and the call runs again until a signal is to
  be taken, and again after its handler (`ERESTARTNOINTR`), so that it
  does not return while the marker is there; `process_madvise` tries the
  range again until a fatal signal, as Linux's `vector_madvise` does, and
  runs no handler meanwhile. Private anonymous memory loses its markers
  to the guards.
  `MADV_COLLAPSE` collapses private anonymous memory and shmem's page
  cache as Linux's `madvise_collapse` does, VMA by VMA: a VMA with
  `MADV_NOHUGEPAGE` or in a space that `PR_SET_THP_DISABLE` disabled for
  every VMA, one with no room for an aligned 2 MiB extent, a
  private anonymous one no page of which was written, a shmem one whose
  addresses and file offsets are not 2 MiB aligned to each other, and a
  regular file's mapping refuse it (`EINVAL`), and a range with no whole
  aligned extent then succeeds. Each whole extent of private anonymous
  memory becomes a huge page that holds every page of it, so `mincore` and
  the resident counts show all 2 MiB, unless no page of it was touched (no
  page table) or it has a guard, a poison or a uffd-wp marker (`EINVAL`,
  once the other extents are done), or it lies in a range a `userfaultfd`
  registered and has an empty page (`EBUSY`, at once). Shmem's page cache
  is that of shared memory of no file, a memfd, a file of a tmpfs mount
  (one a guest mounted, or `/dev/shm`) and System V shared memory, mapped
  shared or private. An extent of it the page cache
  holds no page of ends the collapse (`EINVAL`), as does one with holes in
  a VMA a `userfaultfd` registered for missing pages (`EBUSY`). Otherwise
  every page of the extent within the file comes into the page cache,
  zeros in a hole, which a memfd or a tmpfs mount's file is charged for
  (`EINVAL`, at once, past its mount's size), and the extent is collapsed,
  unless
  the VMA is registered for write protection or a page has a marker
  (`EINVAL`, once the other extents are done) or a private mapping has a
  copy of its own of a page (`EINVAL`, at once). `MADV_HWPOISON` and
  `MADV_SOFT_OFFLINE` check the range's arguments, then `CAP_SYS_ADMIN`
  (`EPERM`), before the address limit or any mapping. With it each page in
  turn is brought in by reading it: `EFAULT` for a page no mapping holds,
  that may not be read or that cannot be brought in, `EHWPOISON` for a
  poisoned one. `MADV_SOFT_OFFLINE` then leaves the page as it is, as
  moving it to another shows nothing, but the zero page gives
  `ENOTRECOVERABLE`. `MADV_HWPOISON` poisons a private page of the
  process's own: its contents go, the caller gets SIGBUS (`BUS_MCEERR_AR`,
  at the first page) at once, and the page is then poisoned as
  `UFFDIO_POISON` poisons one (below). The zero page gives `EBUSY`. Other
  advice gives `EINVAL`.

- `process_madvise` advises each range of its iovecs in turn, of the caller's
  memory (`PIDFD_SELF_THREAD`, `PIDFD_SELF_THREAD_GROUP`, or a pidfd of its
  own process or of one sharing its memory) as `madvise` does, and gives the
  bytes of the ranges before the first that fails, or that one's error.
  Another process's memory takes only `MADV_COLD`, `MADV_PAGEOUT`,
  `MADV_WILLNEED` and `MADV_COLLAPSE` (`EINVAL`), with `CAP_SYS_NICE`
  (`EPERM`), and its ranges need only be mapped (`ENOMEM`), but
  `MADV_COLLAPSE` collapses them as `madvise` would. The checks come
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
  SIGXCPU, SIGXFSZ or SIGSYS, which their taker dumps), a thread wants it
  as Linux's `wants_signal` asks (the thread it is sent to, or another of
  the process's: one that does not block it, does not exit, is in no group
  or ptrace stop and does not sleep with another signal pending), and the
  process is neither stopped nor, but for SIGKILL, traced. The memory goes as the process's last thread ends, so there is
  nothing more to release early.

- `mremap` grows a mapping in place when the pages after it are free, and
  otherwise moves it with its contents under `MREMAP_MAYMOVE`; `MREMAP_FIXED`
  and `MREMAP_DONTUNMAP` work too. Shared memory stays shared with a `fork`ed
  process when it moves. A file mapping grows over more of the file, whose
  pages it reads when they are first touched, and moving a range that spans
  several mappings with `MREMAP_FIXED`, which recent Linux allows, gives
  `EFAULT`. The rings of AIO, `io_uring` and perf events are fixed mappings
  (`VM_DONTEXPAND`): they do not grow (`EFAULT`) or stay behind a move
  (`MREMAP_DONTUNMAP`, `EINVAL`), and an AIO ring moves only whole, as
  Linux master's `aio_ring_mremap` has it (`EINVAL` once the target is
  free and what a shrink drops is gone), with its context.

- `msync` checks its arguments and the range, and with `MS_SYNC` or
  `MS_ASYNC` writes the stores of shared file mappings back to their files.

- `userfaultfd` makes a file through which a thread handles the faults of
  others on memory it registered, as Linux's `fs/userfaultfd.c`. One that
  the kernel's own faults reach as well (without `UFFD_USER_MODE_ONLY`)
  needs `CAP_SYS_PTRACE` unless `vm.unprivileged_userfaultfd` is 1
  (`EPERM`), checked before the flags (`EINVAL`). Those reach it as an
  instruction's do: a system call's own copy to or from a registered page
  waits for it, through any signal that is not fatal, as Linux retries a
  kernel fault (`fault_signal_pending`), and the copy goes on once the page
  is filled or the context released; a SIGKILL or the process's exit ends
  the wait with `EFAULT`, as does `UFFD_USER_MODE_ONLY` or
  `UFFD_FEATURE_SIGBUS` at once. A futex word's read waits with the futex
  queues free. The frame of a signal and an `rseq` area, which the kernel
  writes on the way back to the program, are waited for too, an `rseq` area
  with the thread off its CPU; `clear_child_tid`'s word and the robust list
  of an exiting thread are not (`PF_EXITING`). `get_user_pages` waits too where it may drop the space's
  lock: for `process_vm_readv` and `process_vm_writev`, in the other task's
  memory and with a buffer's pages faulted in before any is copied, for
  `MADV_POPULATE_READ`, `MADV_POPULATE_WRITE`, `mlock` and what else brings
  locked pages in, and for a shared futex's key; it fails where it may not,
  as for `ptrace` and `/proc/<pid>/mem` (`EIO`), a core dump (a hole),
  `FUTEX_WAKE_OP`'s word (`EFAULT`) and what `mprotect` brings in (its error
  ignored). `/dev/userfaultfd`, a
  misc device of root's of mode 0600 (`userfaultfd_misc`, whose minor
  number Linux gives at boot), makes one with its only operation, the
  ioctl `USERFAULTFD_IOC_NEW`, of the flags in the low 32 bits of its
  argument and with no capability, as whoever may open the device may make
  them; any other ioctl, `read` and `write` are `EINVAL`. The file is
  `anon_inode:[userfaultfd]`, open for reading, and belongs to the address
  space it was made in, whoever holds it. It is an anonymous inode of its
  own (`anon_inode_create_getfile`), as a fork's file a read hands over is:
  `fstat` gives a new inode number, mode 0600 without a file type, and the
  maker's `fsuid` and `fsgid`. `UFFDIO_API` takes the version
  and the features once (`EINVAL` again), writing back the features it
  offers and its ioctls, or zeros when it fails; it offers
  `UFFD_FEATURE_PAGEFAULT_FLAG_WP`, `UFFD_FEATURE_SIGBUS`,
  `UFFD_FEATURE_THREAD_ID`, `UFFD_FEATURE_MINOR_SHMEM`,
  `UFFD_FEATURE_MINOR_HUGETLBFS`,
  `UFFD_FEATURE_EXACT_ADDRESS`, `UFFD_FEATURE_MISSING_SHMEM`,
  `UFFD_FEATURE_MISSING_HUGETLBFS`, `UFFD_FEATURE_WP_HUGETLBFS_SHMEM`,
  `UFFD_FEATURE_WP_UNPOPULATED`, `UFFD_FEATURE_POISON`,
  `UFFD_FEATURE_WP_ASYNC`, `UFFD_FEATURE_MOVE`, and the events'
  `UFFD_FEATURE_EVENT_FORK`, `UFFD_FEATURE_EVENT_REMAP`,
  `UFFD_FEATURE_EVENT_REMOVE` and `UFFD_FEATURE_EVENT_UNMAP` (the `HUGETLBFS` ones as Linux reports them,
  though no hugetlbfs memory can be registered: `UFFDIO_REGISTER` does not
  take a hugetlb mapping), and `UFFD_FEATURE_EVENT_FORK` needs
  `CAP_SYS_PTRACE` (`EPERM`). `UFFDIO_REGISTER` registers private anonymous
  memory, shared anonymous memory and the shared or private mappings of a
  memfd or a file of a tmpfs mount, which are shmem's (not System V shared
  memory, whose VMAs Linux does not count as shmem's), for missing pages
  (`UFFDIO_REGISTER_MODE_MISSING`), shmem (shared anonymous memory and
  those files' mappings) for minor faults (`UFFDIO_REGISTER_MODE_MINOR`, which
  adds `UFFDIO_CONTINUE` to the ioctls it reports and `ui` to `smaps`), and
  private anonymous memory and shmem for write
  protection (`UFFDIO_REGISTER_MODE_WP`, which adds `UFFDIO_WRITEPROTECT`
  to the ioctls it reports), and with `UFFD_FEATURE_WP_ASYNC` any memory
  for write protection alone (a file's private or shared mapping and
  System V shared memory too, as `vma_can_userfault` allows), with Linux's checks in its order (the
  range, then each VMA: `EINVAL` for one that cannot be registered,
  `EPERM` for a shared one that may not write its file, `EBUSY` for one
  another `userfaultfd` has); the modes replace a VMA's
  own unless it has them already. The ranges make VMAs of their own, as
  `/proc/<pid>/maps` shows them, with `um` and `uw` in `smaps`; a `fork`ed
  child and a mapping `mremap` moves do not keep it, and
  `UFFDIO_UNREGISTER` and closing the file take it away. An instruction
  that touches a page registered for missing pages that has none (in
  shmem, one its page cache does not have: no mapping of it brought the
  page in and the file does not hold it, as written or allocated, and a
  page past the file's end is SIGBUS first), or that writes to a
  write-protected page of a range registered for write protection, waits,
  and the file reads the fault as a `uffd_msg`, the oldest first: whether
  it was a write, `UFFD_PAGEFAULT_FLAG_WP` for a protected page, the page's
  address (the exact one with `UFFD_FEATURE_EXACT_ADDRESS`) and, with
  `UFFD_FEATURE_THREAD_ID`, the thread's ID. The wait ends when
  `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` fills the page or
  `UFFDIO_WRITEPROTECT` ends its protection (unless `DONTWAKE`),
  `UFFDIO_WAKE` takes its range, `UFFDIO_UNREGISTER` takes it from a range
  registered for missing pages, or the file is closed, and a signal ends
  it too; then the instruction runs again, as Linux retries the fault.
  Unless a signal is to be taken first, the retry counts as a minor fault
  of the thread's own code (`ru_minflt`, `page-faults`, `minor-faults`),
  whether it brings the page in or not: its first try ran under the VMA's
  lock, whose retry is not `FAULT_FLAG_TRIED`. A wait that a signal to be
  taken ends is no retry, and counts in `page-faults` alone, as Linux
  counts a fault there as it starts; the instruction then faults again
  after the signal's handler. The fault of a kernel
  access, which waits as described above, is a major one: a kernel-mode
  fault does not run under the VMA's lock first, so its retry is
  `FAULT_FLAG_TRIED`, and it counts once (`ru_majflt`, `page-faults`,
  `major-faults`, and no minor fault), whether the retry brings the page in
  or not. It counts when the retry completes, as `mm_account_fault` does:
  a retry that waits again (after a `UFFDIO_WAKE` that filled nothing)
  adds nothing, and one that then fails, as for a fatal signal, counts
  none. One through `get_user_pages` finds the page there and counts
  nothing.
  With `UFFD_FEATURE_SIGBUS` the fault raises SIGBUS (`BUS_ADRERR`)
  instead. `UFFDIO_WRITEPROTECT` protects the pages of its range, or ends
  their protection, VMA by VMA as `mwriteprotect_range` does: each must be
  registered for write protection (`ENOENT`, once the ones before it
  changed), and protecting does not take `DONTWAKE` (`EINVAL`). A page
  of private anonymous memory with no entry, which Linux has no present
  PTE for, is protected only with `UFFD_FEATURE_WP_UNPOPULATED`; one only
  read is Linux's zero page, and is. Shmem's pages with no entry are
  always protected. Such a page gets Linux's uffd-wp marker, which
  `/proc/<pid>/pagemap` shows as a swap entry with bit 57, and the entry
  an access makes for it is write-protected, so that a write faults once
  the page is in. `MADV_DONTNEED` takes shmem's entries away, as any shared
  mapping's, the page cache keeping the pages, and leaves a marker for
  each protected one, as
  `zap_install_uffd_wp_if_needed` does; that of private anonymous memory
  drops the markers. A fill or `UFFDIO_CONTINUE` takes a marker's place,
  protected only by its own mode, and a `UFFDIO_ZEROPAGE` of private
  anonymous memory or a `UFFDIO_POISON` is `EEXIST` there. `mprotect` keeps the protection,
  and refuses a write it does not permit with SIGSEGV as before; a
  `fork`ed child and a move by `mremap` (without their events' features),
  `UFFDIO_UNREGISTER` and closing the file take it away. A registration
  that replaces the write-protect mode changes the VMA's flags alone, as
  Linux's `userfaultfd_register_range` does: the pages keep their marks,
  which bit 57 of `/proc/<pid>/pagemap` still shows and which protect
  nothing; registered again, the mode protects them again, but for a page
  a write took meanwhile, whose entry became writable with its mark kept
  (`wp_page_reuse`), until `UFFDIO_WRITEPROTECT` protects it again. With `UFFD_FEATURE_WP_ASYNC`, which brings
  `UFFD_FEATURE_WP_UNPOPULATED` (as `/proc/<pid>/fdinfo` shows), a write
  to a write-protected page, an instruction's or a system call's, does not
  fault: it clears the page's protection and goes on, as `do_wp_page`
  does, so that bit 57 of `/proc/<pid>/pagemap` tells which pages were
  written since `UFFDIO_WRITEPROTECT`, and `PAGEMAP_SCAN` (below) finds
  and protects them again. `MADV_DONTNEED` of a file's private or shared
  mapping, or of System V shared memory, leaves a marker for each page
  still protected, as for shmem; a
  fill there is `EINVAL`, as the memory is neither anonymous nor shmem's.
  `UFFDIO_COPY` and `UFFDIO_ZEROPAGE` fill page by page as `mfill_atomic`
  does: `ENOENT` for a range that does not lie in one registered VMA,
  `EEXIST` for a page that has one, `EFAULT` for a source that cannot be
  read or a page past a shmem file's end, and `EAGAIN` once one stops short, with what was filled in the
  struct's last field; `UFFDIO_COPY_MODE_WP` fills write-protected pages,
  in a range registered for write protection (`EINVAL`). A fill of a
  shared mapping of a shmem file is `EEXIST` where the file's page cache
  has the page, and puts the page in the file, which `read` then sees; one
  of a private mapping gives the mapping a page of its own and leaves the
  file as it was. `UFFDIO_POISON`
  (`UFFD_FEATURE_POISON`) poisons the pages of a registered range the same
  way, its only mode `DONTWAKE`, and is `EEXIST` for a page this mapping
  has, or a guard: an access to a poisoned page raises SIGBUS with
  `BUS_MCEERR_AR` and `si_addr_lsb` 12, after the protection check and
  whether the range is still registered or not, as Linux's poison marker
  gives `VM_FAULT_HWPOISON`; a system call's copy there is `EFAULT` and
  `MADV_POPULATE_READ` `EHWPOISON`; `/proc/<pid>/pagemap` shows it as a
  swap entry. A `UFFDIO_COPY` fills a poisoned page
  in its place, as Linux's `mfill_atomic_install_pte` takes the marker, as
  does a `UFFDIO_ZEROPAGE` of shmem, and one of private anonymous memory
  is `EEXIST` there. The poison stays through `mprotect`
  and `UFFDIO_UNREGISTER`, moves with `mremap`, goes to a `fork`ed child of
  private memory but not of shared, and goes with `MADV_DONTNEED`,
  `MADV_FREE`, `MADV_GUARD_INSTALL` (whose guard takes its place) and
  `munmap`. A minor fault is an access to a page of shmem that its page
  cache has but the mapping has no entry for, as `shmem_get_folio_gfp`
  finds the folio and `handle_userfault` takes `VM_UFFD_MINOR`; its
  message has `UFFD_PAGEFAULT_FLAG_MINOR`, and a hole is brought in unless
  the range is registered for missing pages too. `UFFDIO_CONTINUE` maps
  the page cache's pages into its range page by page, as
  `mfill_atomic_pte_continue`: `EINVAL` for memory that is not shmem, a
  mode other than `DONTWAKE` and `WP` (which needs the write-protect
  mode), or a page past the file's end; `EFAULT` for a page the page cache
  does not have; `EEXIST` for one the mapping has. A private mapping shows
  the page until it writes it, as `mfill_atomic_install_pte` maps it
  read-only, and `UFFDIO_CONTINUE_MODE_WP` maps it write-protected.
  `MADV_DONTNEED` takes a shmem mapping's entries away, so that its pages
  fault as minor faults again. `UFFDIO_MOVE` moves private anonymous pages of the
  context's own address space (`EINVAL` from another) into a registered
  range, whether or not `UFFD_FEATURE_MOVE` was asked for, as Linux's
  `move_pages`: each start in a VMA (`ENOENT`); neither VMA shared, each
  holding its whole range, the same protection, which lets writes, both
  locked or neither, the destination registered with this `userfaultfd`,
  and both anonymous memory (`EINVAL`). Then page by page: `EEXIST` for a
  destination page that has one, or a marker; `ENOENT` for a source page
  with none, which `UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES` counts as moved
  instead; `EFAULT` for a source poison, guard or uffd-wp marker; and `EBUSY` for a page a
  `fork` shares until a write gives it its own (`PageAnonExclusive`). The
  zero page moves as the zero page; any other page takes the
  destination's protection, writable and no longer write-protected, and
  the source has none. What was moved, or the error, goes in the
  struct's last field, the waits for the moved pages end unless
  `DONTWAKE`, and one that stops short is `EAGAIN`.
  A read takes whole messages (`EINVAL` for a buffer
  too small for one, or before `UFFDIO_API`), waiting unless non-blocking;
  `poll` gives `POLLERR` before `UFFDIO_API` and for a file that blocks, as
  Linux's does, else `POLLIN` while a fault or an event is not read yet.
  `/proc/self/fdinfo` shows the faults not read and all those waiting, and
  the API, as `userfaultfd_show_fdinfo`. The events tell the
  `userfaultfd` of changes to its space, as Linux's non-cooperative mode:
  with `UFFD_FEATURE_EVENT_FORK` a `fork`ed child keeps the registrations,
  and the write protection of their pages and markers, in a new
  `userfaultfd` of its own, which `UFFD_EVENT_FORK` hands over as a file
  the read installs (with the old one's `O_CLOEXEC` and `O_NONBLOCK`), its
  number in the message; with `UFFD_FEATURE_EVENT_REMAP` a mapping
  `mremap` moves keeps them too, and `UFFD_EVENT_REMAP` gives where it was,
  where it went and its length; `UFFD_FEATURE_EVENT_REMOVE` tells the
  ranges `MADV_DONTNEED`, `MADV_DONTNEED_LOCKED`, `MADV_FREE` and
  `MADV_REMOVE` (and `process_madvise` of the caller's own memory) are
  about to drop, mapping by mapping (`UFFD_EVENT_REMOVE`), as Linux's
  `madvise_walk_vmas` goes: a mapping's event is read after the mappings
  before it lost their pages and before its own go, and one that fails
  its checks (a sealed one's, `MADV_REMOVE`'s of no shared file) ends the
  discard with no event, and
  `UFFD_FEATURE_EVENT_UNMAP` the whole range `munmap`, `brk`, a `MAP_FIXED`
  `mmap` and `mremap` unmapped (`UFFD_EVENT_UNMAP`), once to each
  `userfaultfd` that registered some of it; `mremap` tells of the range
  `MREMAP_FIXED` replaced, then of the move, then of the range it left
  and what it shrank, as Linux's `notify_uffd`. The thread that made the
  change waits until its event is read, the file is closed or a fatal
  signal comes (`TASK_KILLABLE`); `fork` waits before the child runs, and
  a child's `userfaultfd` whose event was not read leaves the child's
  mappings. A read takes the faults before the events, and while an event
  is not read `UFFDIO_COPY`, `UFFDIO_ZEROPAGE`, `UFFDIO_POISON`,
  `UFFDIO_CONTINUE` and `UFFDIO_MOVE` are `EAGAIN` (written to their last
  field first), as is `UFFDIO_WRITEPROTECT` (`mmap_changing`).

- `remap_file_pages` maps a range of a shared mapping again at another page
  of its file or shared memory, as Linux's `mmap` of the mapping's own file
  does, keeping its protection. As on Linux, `prot` must be 0 and the range
  must lie in shared mappings of the same memory whose file is open for
  writing (`VM_SHARED`, which a memfd's seals leave), with no hole
  (`EINVAL`), and a page past what a file can reach is `EOVERFLOW`.

- System V shared memory (`shmget`, `shmat`, `shmdt`, `shmctl`) belongs to
  the thread's IPC namespace, with Linux's checks in Linux's order and the
  namespace's limits, its `/proc/sys/kernel` files (below): a size from 1
  to `shmmax` (`EINVAL`), one whose pages wrap (`ENOSPC`), all the pages to
  `shmall` and the segments to `shmmni` (`ENOSPC`); a new IPC namespace
  starts with no segments and Linux's defaults. A segment's ID is its index and a sequence number, given
  out in turn as Linux gives them, and `/proc/<pid>/maps` names an attachment
  `/SYSV<key> (deleted)` on device 00:01, with the ID as its inode. The count
  of attachments (`shm_nattch`) counts each VMA that shows the segment, in
  every process, as Linux does: a `fork` copies them, and `munmap`, and an
  `mprotect`, `mlock`, `madvise`, `mseal` or `userfaultfd` registration
  that changes part of one, split them, and they never merge. Each VMA that
  opens (a split, a `fork`'s copy, a move by `mremap`) sets the segment's
  `shm_atime` and `shm_lpid`, and each one that closes (an unmap, `shmdt`,
  an exit, an `exec`) its `shm_dtime` and `shm_lpid`, as Linux's
  `shm_open` and `shm_close` do. `shm_lpid` is the process that acts, as
  Linux's `current`: a child that shares its parent's memory without being
  a thread of it (`CLONE_VM`, `vfork`) stamps what it maps and unmaps as
  itself, and an exit or `exec` closes the VMAs only when no other process
  uses the space, as the last of them. `shmdt` takes every piece of the
  attachment that `munmap` and the others left. A segment removed with `IPC_RMID` while attached keeps its ID, is
  found by no key, and goes at its last detach. `SHM_LOCK` checks the owner
  and `RLIMIT_MEMLOCK` as Linux does.
  `SHM_HUGETLB` makes a segment of hugetlbfs, whose pool is empty (see
  `MAP_HUGETLB` below), as `newseg` does: a huge page size other than 2 MiB
  is `EINVAL`; without `CAP_IPC_LOCK`, a process outside group 0
  (`vm.hugetlb_shm_group`) is `EPERM`; and without `SHM_NORESERVE` the
  reservation is `ENOMEM`. Such a segment keeps its size (`shm_segsz`), but
  `shmat` maps it in whole 2 MiB pages at a 2 MiB boundary (`EINVAL` for a
  fixed address off one), as a `MAP_HUGETLB` mapping that an access makes
  `SIGBUS`, and `SHM_LOCK` and `SHM_UNLOCK` change nothing of it.

- System V semaphores (`semget`, `semop`, `semtimedop`, `semctl`) belong to
  the thread's IPC namespace too, with Linux's checks in Linux's order (as
  `ipc/sem.c`) and the namespace's limits of `/proc/sys/kernel/sem` (Linux's
  defaults `SEMMSL` 32000, `SEMMNS` 1024000000, `SEMOPM` 500 and `SEMMNI`
  32000; `SEMVMX` 32767 is fixed), which `semget`, the semaphores of all
  sets and `semop` keep to (`semopm` compared unsigned, so a negative one
  bounds nothing); a set's IDs are
  given out as a segment's. `semctl` has `IPC_STAT`, `IPC_SET`, `IPC_RMID`,
  `IPC_INFO`, `SEM_INFO`, `SEM_STAT`, `SEM_STAT_ANY`, `GETVAL`, `SETVAL`,
  `GETALL`, `SETALL`, `GETPID` (in the caller's PID namespace, still once
  that process is reaped, as each semaphore keeps its `struct pid`, the
  undo at its exit's included), `GETNCNT`
  and `GETZCNT` (counted by the operation each wait waits on). The
  operations of one call are done all at once or not at all; one that
  cannot go through waits, unless the operation it would wait on has
  `IPC_NOWAIT` (`EAGAIN`), until a change lets it through, the set is
  removed (`EIDRM`), a signal comes (`EINTR`, never restarted, as Linux) or
  `semtimedop`'s timeout passes (`EAGAIN`). The waits are kept in Linux's
  queues: each semaphore's for operations on it alone, and the set's for
  operations on several, which the waiting changes on one semaphore join
  while any such operation waits. A change tries them as Linux's
  `do_smart_update`: the waits for zero on the semaphores it made 0, then
  the waits to change values, each queue in the order its waits began.
  `SEM_UNDO` keeps the adjustments in the process's
  undo list, which `CLONE_SYSVSEM` shares (`pthread_create` passes it) and
  a `fork` does not; `SETVAL` and `SETALL` clear them. The last thread that
  shares the list applies it as it ends, or as it leaves it with `unshare`
  (`CLONE_SYSVSEM` or `CLONE_NEWIPC`) or `setns` to another IPC namespace,
  cut to 0 and `SEMVMX` as Linux cuts them.

- System V message queues (`msgget`, `msgsnd`, `msgrcv`, `msgctl`) belong to
  the thread's IPC namespace too, with Linux's checks in Linux's order (as
  `ipc/msg.c`) and the namespace's limits of `/proc/sys/kernel` (Linux's
  defaults `MSGMAX` 8192, `MSGMNB` 16384, `MSGMNI` 32000): a message's
  size, the bytes a new queue holds and that `IPC_SET` may give without
  `CAP_SYS_RESOURCE`, and the number of queues. A queue holds as many bytes as its `msg_qbytes`, and as
  many messages; a send to a full one waits, unless `IPC_NOWAIT`
  (`EAGAIN`), in the queue's list of senders until a receive or `IPC_SET`
  makes room for its message, the queue is removed (`EIDRM`) or a signal
  comes. As Linux's `ss_wakeup`, a change wakes only the senders whose
  messages then fit, which check the permission again, and moves the
  others behind them in their order. `msgrcv` takes the first message, the
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

- The key retention service (`add_key`, `request_key`, `keyctl`), as
  Linux's `security/keys`: `keyring`, `user` and `logon` keys, each with
  its serial number, owner, group, permissions (possessor, user, group and
  other) and expiry. A thread has its thread, process and session keyrings
  (`fork` and `exec` keep the session one, a new thread gets a thread
  keyring of its own when its creator has one, and a thread keyring
  follows the file-system IDs), and each user its `_uid.<uid>`,
  `_uid_ses.<uid>` and `_persistent.<uid>` keyrings in its user namespace.
  A search walks nested keyrings as `search_nested_keyrings` does, six
  deep, with its order of errors (`EKEYREVOKED`, `EKEYEXPIRED`, `EACCES`,
  a negative key's error), and a key found through the thread's keyrings
  is possessed. Each user has Linux's quotas (200 keys and 20000 bytes, a
  million keys and 25 MB for root), which a keyring's links count against
  too. `keyctl` takes every option of a kernel built without big keys,
  Diffie-Hellman, asymmetric keys and notifications: `GET_KEYRING_ID`,
  `JOIN_SESSION_KEYRING` (named sessions too), `UPDATE`, `REVOKE`, `CHOWN`,
  `SETPERM`, `DESCRIBE`, `CLEAR`, `LINK`, `UNLINK`, `SEARCH`, `READ`,
  `SET_REQKEY_KEYRING`, `SET_TIMEOUT`, `GET_SECURITY`,
  `SESSION_TO_PARENT`, `INVALIDATE`, `GET_PERSISTENT`, `RESTRICT_KEYRING`
  (to take no more links: these types have no restrictions, `ENOENT`), `MOVE` and `CAPABILITIES`; the
  others give `EOPNOTSUPP`. `request_key` with callout information makes
  the key negative for 60 seconds, as a failed `/sbin/request-key` does,
  and gives `ENOENT`, so `INSTANTIATE`, `NEGATE`, `REJECT` and
  `INSTANTIATE_IOV` find no authority (`EPERM`) and `ASSUME_AUTHORITY` of
  a key `ENOKEY`.

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
  `ptrace_scope` (`/proc/sys/kernel/yama/ptrace_scope`, below) must also let
  it in, as Linux's `yama_ptrace_access_check`: at 1, as Debian's, Ubuntu's
  and the CI runners' is at first, the target must be a descendant of the
  caller, or have let it in with `PR_SET_PTRACER`, or the caller must have
  `CAP_SYS_PTRACE` in the target's user namespace; at 0 nothing more is
  asked, at 2 only that capability lets it in, and at 3 nothing does.

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
  it, which must grow down (the main stack, or a `MAP_GROWSDOWN` mapping),
  else `EINVAL`; `PROT_GROWSUP` is
  `EINVAL` on a mapped start, as no VMA grows up on x86-64. Where no VMA is
  in the range, both give `ENOMEM`.

- A mapping that grows down, the main stack or private anonymous memory that
  `mmap` made with `MAP_GROWSDOWN` (`VmFlags` shows `gd`), grows as Linux's
  `expand_downwards` makes it: an access to an unmapped page below it, a
  signal frame written there, a system call's own copy there (as
  `do_user_addr_fault` serves a kernel access), or an access of `ptrace` or
  `/proc/<pid>/mem` there (`__access_remote_vm`, within the limits of the
  one who makes it), extends it down to that
  page, and the access is made again. It does not grow below `mmap_min_addr` (64 KiB), within the
  guard gap of 256 pages (`stack_guard_gap`) above a mapping that does not
  grow down and can be accessed, past `RLIMIT_STACK` for the whole VMA, or,
  locked, past `RLIMIT_MEMLOCK` without `CAP_IPC_LOCK`; the access then gives
  `SIGSEGV`. No mapping is placed within that gap below it, whether at a hint
  or where `mmap` looks for room. A file's mapping, `/dev/zero`'s included,
  and shared memory cannot grow down (`EINVAL`). The main stack's VMA starts
  at 8 MiB, so with a larger `RLIMIT_STACK` it grows past that.

- Private anonymous memory of whole 2 MiB that `mmap` places without a
  hint goes at a 2 MiB boundary, as Linux's `thp_get_unmapped_area_vmflags`
  places it: where `mmap` finds room for 2 MiB more, at the boundary above
  that room's start when it is one in the top-down layout (so that one
  such mapping lies right below the last), else at the next one. A move
  by `mremap` to a length of whole 2 MiB, with no hint, goes there too, and
  so does a private mapping of `/dev/zero` of any length that reaches 2 MiB
  past the first boundary after its offset, at the boundary its offset
  agrees with (`get_unmapped_area_zero`), or at the hint when the longer
  room fits there.

- `MAP_32BIT` puts a mapping in the first 2 GiB, as Linux's `find_start_end`
  does, in either layout: at a free hint that ends by 2 GiB, else in the
  lowest room from 1 GiB up (Linux starts up to 32 MiB higher, at random),
  with the placements at a 2 MiB boundary there too, or `ENOMEM`.
  `MAP_FIXED` overrides it, and `mremap` does not keep to it. A hint below
  `mmap_min_addr` (64 KiB) is taken as that address; a fixed mapping
  below it, a move there by `mremap` (once its target is unmapped and its
  source shrunk; a free address asked for with `MREMAP_DONTUNMAP` alone
  too) and a `shmat` there give `EPERM` without `CAP_SYS_RAWIO`.

- `MAP_HUGETLB` maps as on a Linux whose pool of huge pages is empty
  (`vm.nr_hugepages` 0): `ENOMEM`, after the checks Linux makes first, when
  a fixed mapping has unmapped what it would replace. With `MAP_NORESERVE`
  it succeeds, and an access raises `SIGBUS`. Such a mapping goes at a 2 MiB
  boundary, is split, remapped and dropped only on one (`EINVAL`), cannot
  grow, and shows `ht` and its 2 MiB pages in `smaps`. `madvise` refuses
  it `MADV_FREE`, `MADV_COLD`, `MADV_PAGEOUT`, `MADV_HUGEPAGE` and the
  guards, and `MADV_DONTNEED` from an address off a 2 MiB boundary
  (`EINVAL`). The only size is
  2 MiB (another is `EINVAL`), as the virtual CPU has no 1 GiB pages, and a
  file with the flag is `EINVAL`, but for a hugetlbfs one. The memory is
  a hugetlbfs file's, so it takes a file's types: `MAP_SHARED_VALIDATE`
  maps it (`EOPNOTSUPP` for a flag it refuses), and `MAP_DROPPABLE` is
  `EINVAL`, after the placement and the lock checks, as in `do_mmap`.
  `memfd_create` with `MFD_HUGETLB` makes such a file, of 2 MiB pages
  (another size is `ENODEV`): it has no `write` (`EINVAL`), its size is
  whole huge pages (`ftruncate` to another is `EINVAL`), `fallocate` has no
  page to give it (`ENOSPC`), and a read finds zeros. `fstat` gives a block
  of 2 MiB and no blocks, and `fstatfs` hugetlbfs's type and block. Its
  mapping is as above, the length rounded up to 2 MiB whatever the flags;
  one that may write raises the file's size to its end, and a shared one
  that may write keeps `F_SEAL_WRITE` out (`EBUSY`).

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

- io_uring is Linux 6.12's, but for its registered files, its groups of
  buffers and a NOP's flags, which are Linux 7.0's (`io_uring/rsrc.c`,
  `kbuf.c` and `nop.c`, with master's `IOSQE_FIXED_FILE` for a NOP), the
  kernel the differential tests run on, and so are the operations,
  registrations and setup and `io_uring_enter` flags it knows of. Its
  operations are `IORING_OP_NOP`,
  `IORING_OP_EPOLL_CTL` (which libuv batches its `epoll_ctl` calls with) and
  `_EPOLL_WAIT`, the file transfers `IORING_OP_READ`, `_WRITE`, `_READV`,
  `_WRITEV`, `_FSYNC`, `_READ_FIXED`, `_WRITE_FIXED`, `_READV_FIXED` and
  `_WRITEV_FIXED`, `IORING_OP_FILES_UPDATE`,
  `IORING_OP_PROVIDE_BUFFERS` and `_REMOVE_BUFFERS`,
  `IORING_OP_ASYNC_CANCEL`, the timeouts `IORING_OP_TIMEOUT`,
  `_TIMEOUT_REMOVE` and `_LINK_TIMEOUT`, the polls `IORING_OP_POLL_ADD` and
  `_POLL_REMOVE`, the file requests `IORING_OP_OPENAT`, `_OPENAT2`,
  `_CLOSE`, `_STATX`, `_FALLOCATE`, `_FADVISE`, `_MADVISE`, `_RENAMEAT`,
  `_UNLINKAT`, `_MKDIRAT`, `_SYMLINKAT`, `_LINKAT`, `_FTRUNCATE` and
  `_PIPE`, `IORING_OP_SPLICE` and `_TEE`, and the socket requests
  `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`, `_SEND`,
  `_RECV`, `_SENDMSG` and `_RECVMSG`. The other operations, up to Linux
  7.0's `IORING_OP_URING_CMD128`, complete with `EOPNOTSUPP`, as on a Linux
  built without them, and `IORING_REGISTER_PROBE` reports only these. The
  rings are the sizes, offsets and features Linux gives, and `mmap` of the
  descriptor shows them. The descriptor is an anonymous inode of its own,
  as `anon_inode_create_getfile` makes one: `fstat` gives a new inode
  number, mode 0600 without a file type, and the maker's `fsuid` and
  `fsgid`. A request runs while `io_uring_enter` takes it, so
  its completion is in the queue when the call returns, unless it waits for
  its file or for task work (below); links, completions
  that skip success, and completions kept while the queue is full
  (`IORING_FEAT_NODROP`) behave as on Linux. The completions of one
  submission go in once all its requests ran, as Linux posts them
  (`io_submit_flush_completions`).

- Task work runs as Linux's `io_uring/tw.c` runs it. An `IORING_NOP_TW`, a
  link's next request, and the rest of a link that failed complete as task
  work, after the other completions of their submission.
  - A ring without `IORING_SETUP_DEFER_TASKRUN` runs it as the call returns
    to the program, or as the thread waits on any of its rings. With
    `IORING_SETUP_COOP_TASKRUN` too (`TWA_SIGNAL_NO_IPI`), which only spares
    a thread running its program an interrupt.
  - A ring with `IORING_SETUP_DEFER_TASKRUN` runs it only as
    `io_uring_enter` waits on that ring, 20 at a time unless the wait wants
    more (`IO_LOCAL_TW_DEFAULT_MAX`).

  A wait in `io_uring_enter` ends with the completions it asked for, an
  `IORING_OP_TIMEOUT` done meanwhile (`cq_timeouts`), a signal, or its
  timeout. With `min_wait_usec`, fewer completions end it once that time
  passed, and so does the first one after it; with none and no timeout it
  ends then with `ETIME` (`io_cqring_min_timer_wakeup`).

  With `IORING_SETUP_TASKRUN_FLAG`, `IORING_SQ_TASKRUN` shows that some
  waits. A link whose request fails with `IOSQE_CQE_SKIP_SUCCESS` cancels
  the rest without their completions (`REQ_F_SKIP_LINK_CQES`).

- A transfer that would wait for its file waits, as Linux's
  `io_arm_poll_handler` makes it: a read of a pipe, a socket or an eventfd
  with nothing to read, or a write to a full pipe, even with `O_NONBLOCK`.
  `RWF_NOWAIT` ends it with `EAGAIN` instead. The rest of its link waits
  for it. As with any transfer, one that moves fewer bytes than it asked
  for fails its link (`__io_complete_rw_common`), though its completion
  has the count.
  - Once the file is ready, the request runs again as task work of the
    thread that submitted it (`io_poll_task_func`), even when a thread of
    another process made the file ready. If that thread made it ready
    itself, the request is done as the call that did so returns.
  - Work another thread adds ends that thread's interruptible wait as a
    signal would (`TIF_NOTIFY_SIGNAL`). With no signal to deliver, the call
    runs again as Linux's `arch_do_signal_or_restart` restarts it: a
    blocking `read` again, `nanosleep` for the rest of its time through
    `restart_syscall`. A call that gives `EINTR` to a signal, such as
    `epoll_wait`, gives it. A wait in `io_uring_enter` runs the work and
    goes on waiting.
  - With `IORING_SETUP_DEFER_TASKRUN`, the work waits for the ring's own
    wait and interrupts no call.
  - A read that chose a provided buffer keeps it while it waits
    (`REQ_F_BUFFER_SELECTED`). A ring's buffer stays at the ring's head and
    is chosen again as the read goes on.
  - A request that waits keeps the file it found and its registered buffer
    (`req->file`, `req->buf_node`), and goes on with them though its
    descriptor is closed or its slots are updated meanwhile. A registered
    file or buffer that an update takes from its slot while such a request
    holds it posts its tag once that request completes, after its
    completion (`io_put_rsrc_node`).

- `IORING_OP_ASYNC_CANCEL` and `IORING_REGISTER_SYNC_CANCEL` cancel the
  requests of their ring that wait for their files, as Linux master's
  `io_uring/cancel.c` and `io_poll_cancel` do, or, finding none of those,
  the ring's timeouts. No request runs in a worker, so there is no other
  one to find.
  - A cancellation matches by `user_data`, by file with
    `IORING_ASYNC_CANCEL_FD` (a registered one with `_FD_FIXED` or
    `IOSQE_FIXED_FILE`), by operation with `_OP`, or any request with
    `_ANY`. With `_USERDATA` the `user_data` must match too.
  - Without `_ALL` or `_ANY` it cancels the first match and gives 0, or
    `ENOENT`, which fails its link. With them it cancels every match and
    gives how many, 0 for none. The order is that of the ring's hash table
    (`hash_long` of the `user_data`, latest first within a bucket).
  - A cancelled request completes with `ECANCELED` as task work of the
    thread that submitted it, after the cancellation, and fails its link. A
    provided buffer it kept is used (`IORING_CQE_F_BUFFER`).
  - A request whose file became ready, but whose task work has not run yet,
    is cancelled too: it stays findable until the work runs. The bytes stay
    in the file.
  - `IORING_OP_ASYNC_CANCEL` refuses unknown flags, `_ANY` with `_FD` or
    `_OP`, and an `off` or `splice_fd_in` (`EINVAL`), as Linux 7.0's
    `io_async_cancel_prep` does. A descriptor that is not open is `EBADF`.
  - `IORING_REGISTER_SYNC_CANCEL` takes one `struct
    io_uring_sync_cancel_reg`. Its padding must be zero, and it gives the
    count, 0 or `ENOENT` itself. It never waits, as nothing it finds is
    running, so its timeout is unused.

- A request's submitter or ring may go before it completes, as in Linux's
  `io_uring_cancel_generic`, `tw.c` and `io_ring_ctx_wait_and_kill`.
  - A thread that exits alone leaves the requests it submitted waiting.
    Once a file is ready, its request fails with `ECANCELED` as Linux's
    `io_fallback_tw` runs the work of a thread that is gone, and the bytes
    stay in the file. Task work the thread still has as it exits runs so
    too: a request whose file became ready fails with `ECANCELED`, a
    link's next request with `EFAULT` (`io_should_terminate_tw`), and an
    `IORING_NOP_TW` completes. Work that comes for a thread that is gone
    while another thread holds the ring waits for that thread, and no other
    call waits for it, as Linux's worker alone waits for `uring_lock`. A
    ring that closes first drops it, with the files its requests hold,
    where Linux runs it as cancelled, which no one can see.
  - `execve` cancels every request the thread submitted that waits for its
    file, one whose file became ready too (`io_uring_task_cancel`), on the
    old image's memory, as `io_uring_cancel_generic` loops. The task work of
    the `IORING_SETUP_DEFER_TASKRUN` rings it submits to runs first, so a
    request whose file became ready there goes on. Then the requests are
    cancelled, and its task work and theirs run, so each completes with
    `ECANCELED` before the new program runs.
  - A whole process's exit (`exit_group` or a fatal signal) cancels the
    requests its threads submitted in the same way, after the exit event
    of ptrace and before the thread is exiting, as Linux master's
    `io_task_group_exiting` asks: a link's next request still waiting to
    run then runs as usual.
  - A ring whose last descriptor and mapping close lets go of its waiting
    requests and the files they hold, as Linux master does before `close`
    returns, so a pipe whose only reader was such a request takes no more
    writes (`EPIPE`). Task work left for the ring goes with it.

- `poll` and `epoll` watch a ring's descriptor as Linux's `io_uring_poll`
  answers. It is writable while the submission queue has room, and
  readable while completions wait in the queue or in the kernel, or while
  an `IORING_SETUP_DEFER_TASKRUN` ring has task work. Only a completion
  wakes a waiter, and only one that waits for input, as Linux's keyed
  wake-ups filter it (`pollwake`, `ep_poll_callback`, `aio_poll_wake`). So
  an edge-triggered interest in output is reported once, a level-triggered
  one only as `epoll_ctl` adds or changes it, and a `poll`, `select` or aio
  poll that waits only for room in the submission queue sleeps on until
  another of its files wakes it or its time runs out, when `poll` and
  `select` look a last time (`do_poll`, `do_select`).

- `IORING_OP_NOP` takes Linux 7.0's flags, as `io_nop_prep` and `io_nop`
  do. `IORING_NOP_INJECT_RESULT` completes it with its `len`.
  `IORING_NOP_FILE` looks for the file of its `fd`, a registered one with
  `IORING_NOP_FIXED_FILE`, and `IORING_NOP_FIXED_BUFFER` for registered
  buffer `buf_index`, as Linux master does; `IOSQE_FIXED_FILE` also names
  a registered file. A NOP that does not find its file completes with
  `EBADF`, and one that does not find its buffer with `EFAULT`. `IORING_NOP_CQE32` is `EINVAL`,
  as no ring has 32-byte completions, and so are unknown flags.

- A transfer is checked as Linux's `io_prep_rw` and `io_read` or
  `io_write` check it, and fails at the same step. Its preparation takes the
  priority, the attributes, and the buffer or vector, and an error there
  ends the submission. Its issue completes with the error instead: the
  file (`EBADF` for no descriptor, or with `IOSQE_FIXED_FILE` for an empty
  slot of the registered files), the buffer of a read that selects one
  (`ENOBUFS`, then `EFAULT` for one past the user half), the access mode, the `RWF_*` flags
  (`RWF_HIPRI` is `EINVAL`), the range, a read's `FAN_ACCESS_PERM`, and a
  file that cannot read or write (`EINVAL`, `EISDIR` for a directory). An
  offset of -1 is the file's position, which moves past what was moved,
  and a stream such as a pipe takes any offset. A read that did not fail
  gives `IN_ACCESS`, and any write that reached the file `IN_MODIFY`, as
  `io_req_io_end` tells them, even for no bytes. A buffered write with
  `RWF_NOWAIT` that the file system cannot do without waiting is `EAGAIN`,
  where AIO's is `EOPNOTSUPP`. The attributes are Linux 6.14's, which the
  differential tests' kernel has: only protection information, which no
  file here takes (`EINVAL`). `IORING_OP_FSYNC` takes only
  `IORING_FSYNC_DATASYNC`.

- The timeouts are Linux master's (`io_uring/timeout.c`).
  `IORING_OP_TIMEOUT` waits for its time, relative or
  `IORING_TIMEOUT_ABS`, on the monotonic, boot-time or realtime clock, and
  completes with `ETIME`, which fails its link but with
  `IORING_TIMEOUT_ETIME_SUCCESS`; or, with a count in `off`, completes with
  0 once that many other completions are posted. Completions of timeouts
  that expire or are removed are not counted. With
  `IORING_TIMEOUT_MULTISHOT` it posts a completion with
  `IORING_CQE_F_MORE` each time, up to `off` times in all.
  `IORING_OP_TIMEOUT_REMOVE` cancels the timeout of a `user_data`
  (`ECANCELED`, `ENOENT` for none), or with `IORING_TIMEOUT_UPDATE` gives
  it, or with `IORING_LINK_TIMEOUT_UPDATE` a linked one, a new time.
  `IORING_OP_LINK_TIMEOUT` follows a request in its link: it starts as that
  request is issued, and cancels it by its `user_data` and completes with
  `ETIME` when it expires, or completes with `ECANCELED` once the request is
  done, the rest of the link going on without it. The entries are checked as
  Linux checks them (`EINVAL`), and the time is read as they are taken
  (`EFAULT`, `EINVAL` for a negative one), or is in the entry with
  `IORING_TIMEOUT_IMMEDIATE_ARG`. A cancellation finds the timeouts after
  the requests that wait for their files, but none by a file, and no linked
  one. `execve` and a whole process's exit cancel the thread's.

- The file requests run as the calls they stand for, as Linux's do. Their
  entries are checked as Linux checks them (`EINVAL`, `EBADF` for
  `IOSQE_FIXED_FILE` on one that names a path), and their names, and
  `struct open_how`, are read as the entry is taken (`EFAULT`,
  `ENAMETOOLONG`, `ENOENT` for an empty one), so what a request before it in
  its link writes there does not change them. An open that would not create
  or cut a file does not wait, as Linux's first try (`O_NONBLOCK`) does
  not: a FIFO opens to be read at once. An open can go in a registered slot
  (`file_index`, `IORING_FILE_INDEX_ALLOC`), which a close can empty, and a
  ring cannot be closed (`EBADF`). As on Linux, a call that fails fails its
  link only for an open, a close and an `IORING_OP_FADVISE`, or if its
  descriptor is not open; an `IORING_OP_FSYNC` does not either.

- `IORING_OP_SPLICE` and `_TEE` move and copy bytes as `splice` and `tee`
  do, with offsets in the entry (-1 for the file's position) and a
  registered input with `SPLICE_F_FD_IN_FIXED`. One that would wait waits
  for its file, unless `SPLICE_F_NONBLOCK` or a pipe's `O_NONBLOCK`
  (`EAGAIN`), and one that moves fewer bytes than it asked for fails its
  link.

- The polls are Linux master's (`io_uring/poll.c`). `IORING_OP_POLL_ADD`
  completes with the events its file has of those it asks for and the ones
  that end any poll (`POLLERR`, `POLLHUP`, `POLLNVAL`, and `POLLRDHUP` for a
  reader), or waits for them, holding its file. The events a wake-up tells
  of are those of its key: a socket polled for both directions that gets
  bytes reports `POLLIN` alone. With `IORING_POLL_ADD_MULTI` it posts a
  completion with `IORING_CQE_F_MORE` for the events there and then for each
  wake-up, those before its task work runs as one, until the queue has no
  room. A file without `poll` completes at once (`EINVAL` without the
  events). `IORING_OP_POLL_REMOVE` ends the latest poll of a `user_data`
  with `ECANCELED` (`ENOENT` for none, `EALREADY` for one whose task work is
  queued), or gives it new events (`IORING_POLL_UPDATE_EVENTS`) or
  `user_data` (`IORING_POLL_UPDATE_USER_DATA`), with which it polls again.

- The socket requests are Linux 7.0's (`io_uring/net.c`):
  `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`, `_SEND`,
  `_RECV`, `_SENDMSG` and `_RECVMSG`. The last two read their `msghdr` and
  its iovecs as they are prepared (`io_msg_copy_hdr`: `EFAULT`, `EINVAL`,
  `EMSGSIZE`), so one that waits needs them no more. A receive with
  `MSG_WAITALL` whose message or ancillary data was cut fails its link.
  With `IORING_ACCEPT_MULTISHOT` and `IORING_RECV_MULTISHOT`, an accept and
  a receive post a completion with `IORING_CQE_F_MORE` for each
  connection or each buffer filled, and wait for the next: until an error,
  the end, an `IORING_OP_RECV`'s limit (`optlen`, which an `IORING_OP_RECVMSG`
  refuses with `EINVAL`), no buffer (`ENOBUFS`) or no room in the queue.
  It goes on at once while its socket has more
  (`IORING_CQE_F_SOCK_NONEMPTY`) or does not say, as an AF_UNIX listener
  does not, and otherwise waits for the socket first, so a receive whose
  last buffer went fails with `ENOBUFS` only when more bytes come. An
  `IORING_OP_RECVMSG`'s buffer starts with a `struct io_uring_recvmsg_out`
  (the name's length, the control's, the message's whole one and its
  flags), then the room its `msghdr` gives the name and the control, then
  the bytes, as `io_recvmsg_multishot` puts them; a buffer shorter than all
  but the bytes fails with `EFAULT`, and the `msghdr` is not written. Its
  result is the bytes of the buffer it used, and the end of the stream
  posts the last with none. Each is
  prepared as Linux prepares it, which checks its entry
  (`EINVAL`), then reads a connect's or a send's address
  (`move_addr_to_kernel`: `EINVAL` past 128 bytes, `EFAULT`) and checks a
  buffer in the user half (`EFAULT`). It runs as Linux runs it inline,
  without waiting: one that would wait (`EAGAIN`, or a connect in
  progress) waits for its socket, holding the file it found, and runs
  again once the socket is ready, unless it asked not to (`MSG_DONTWAIT`,
  `IORING_ACCEPT_DONTWAIT`), when it completes with `EAGAIN`.
  `IORING_RECVSEND_POLL_FIRST` and `IORING_ACCEPT_POLL_FIRST` wait first.
  A send adds `MSG_NOSIGNAL`. With `IORING_SEND_VECTORIZED` it sends the
  iovecs at its address, as many as its length says, which it reads as it
  is prepared (`io_net_import_vec`). With `IOSQE_BUFFER_SELECT` it sends
  from the buffers it selects as it first runs, and keeps them while it
  waits (`io_buffers_select`): a group it does not find is `ENOENT`, one
  with none left `ENOBUFS`, and a ring's buffer outside the user half
  `EFAULT`. A buffer is cut to the length, as Linux master cuts it, its
  ring entry as it was. Its completion names the first, as a
  read's does, and so does one that fails. With `IORING_RECVSEND_BUNDLE` a
  send sends all it has (`MSG_WAITALL`), and one that selects takes as
  many of a ring's buffers as its length needs, at most 256, leaving one
  it would cut for the next unless the ring has `IOU_PBUF_RING_INC`; taking
  the last one there is empties the group. A bundle that
  sent anything posts with `IORING_CQE_F_MORE` and sends again at once,
  with no length and new buffers, until it sends nothing, takes its
  group's last buffers or waited (`io_send_finish`); one that selects none
  sends nothing the second time. With `MSG_WAITALL`, a stream or
  sequenced-packet socket's send or receive goes on to its whole length
  and gives all it moved; one that fails on the way, as it asked not to
  wait or was cancelled, gives what it moved too (`io_sendrecv_fail`). A
  receive may select a provided buffer
  (`ENOBUFS`), which goes back to its group while the receive waits, or if
  it read nothing, as Linux master's `io_recv` gives it back. A receive
  has `IORING_CQE_F_SOCK_NONEMPTY` while bytes are left on a TCP socket
  (or once its peer finished, as `tcp_inq_hint` tells) or an AF_UNIX
  stream, and an accept while more TCP connections wait. A new socket or
  connection goes at the lowest free descriptor, which it takes first
  (`EMFILE`), or in a registered slot (`file_index`, one past the slot's
  index, or a free one with `IORING_FILE_INDEX_ALLOC`, `ENFILE` when there
  is none; `ENXIO` with no registered files, `EINVAL` past them), which
  `SOCK_CLOEXEC` cannot go with. A connect in progress completes with the
  socket's error once it has one, or with 0 once it is connected. As
  Linux master has it, a receive checks for a socket (`ENOTSOCK`) before
  `IORING_RECVSEND_POLL_FIRST` waits, and a nonblocking socket's connect
  that gives `EAGAIN` (an AF_UNIX listener's full backlog) completes with
  it, where Linux 7.0 waits for the socket and tries again.

- `IORING_REGISTER_BUFFERS` registers a ring's buffers as Linux's
  `io_sqe_buffers_register` does. It checks in this order:
  - none registered yet (`EBUSY`), and 1 to 16384 of them (`EINVAL`);
  - then each `iovec` (`EFAULT`, `EINVAL` for a negative length); a null
    one with no length is an empty slot;
  - a length of 1 byte to 1 GiB (`EFAULT`), and no end past the address
    space (`EOVERFLOW`);
  - its pages pinned for writing (`io_pin_pages`, `FOLL_LONGTERM`), as
    `check_vma_flags` allows them: `EFAULT` for a page not mapped or not
    writable, of a `perf` ring or a `memfd_secret` file, or of a shared
    mapping of a disk file (one whose pages are written back; shared
    memory, a memfd and tmpfs are pinned, and a private file mapping's copy
    is);
  - room under RLIMIT_MEMLOCK (`ENOMEM`), shared with the user's other
    rings and `memfd_secret` pages, unless the ring's maker had
    `CAP_IPC_LOCK`.

  A failure registers none of them. A fixed transfer moves the pinned
  pages, whatever maps the address now: after `munmap` it moves the old
  pages, which a new mapping there does not show, and a page made
  read-only still takes a read. A process that shares the ring moves the
  registering process's pages; `fork` gives the child a copy of a pinned
  private page, so the parent's later writes are what the ring moves
  (`page_needs_cow_for_dma`). `IORING_UNREGISTER_BUFFERS` takes no
  argument (`EINVAL`) and needs buffers (`ENXIO`).

  `IORING_REGISTER_BUFFERS2` registers them with tags, as Linux 7.0's
  `io_register_rsrc` does. Its `struct io_uring_rsrc_register` must be
  whole (`EINVAL`), with a count, no reserved field and no flag but
  `IORING_RSRC_REGISTER_SPARSE`, which takes no `iovec`s and leaves every
  slot empty. Each slot's tag is read after its `iovec` (`EFAULT`), and an
  empty slot may have none (`EINVAL`). `IORING_REGISTER_BUFFERS_UPDATE`
  (`io_register_rsrc_update`) puts new buffers, or none, in a run of
  slots: a whole `struct io_uring_rsrc_update2` with a count and no
  reserved field (`EINVAL`), an offset and count that do not wrap
  (`EOVERFLOW`), buffers (`ENXIO`) and slots that are there (`EINVAL`).
  It gives how many slots it updated, or the first slot's error. A buffer
  that leaves its slot, by an update or as the buffers are unregistered
  (the last slot first), posts its tag, if not 0, as the `user_data` of a
  completion of 0 once nothing holds it, and gives its RLIMIT_MEMLOCK
  pages back. A fixed transfer, or a NOP with `IORING_NOP_FIXED_BUFFER`,
  holds its buffer until its completion is posted. A failed registration
  posts no tag. `IORING_OP_READ_FIXED` and
  `_WRITE_FIXED` move bytes within the buffer `buf_index` names, after the
  file is found: no buffer there, or a range that leaves it, is `EFAULT`.
  `IORING_OP_READV_FIXED` and `_WRITEV_FIXED` read their `iovec`s as the
  entry is prepared (`ENOMEM` for more than `kmalloc` makes room for at
  once, 4 MiB of them, then `EINVAL` for more than 1024, `EFAULT`, and
  `EINVAL` for a negative length), then, after the file and the buffer
  (`EFAULT`), room is made for the pieces of pages they may take, two more
  than the 4 KiB pages of each: more than `INT_MAX` pieces are `EOVERFLOW`,
  and more than `kmalloc` gives at once (4 MiB of 16-byte pieces) `ENOMEM`.
  Then each buffer must lie in the registered one and have some bytes
  (`EFAULT`), and they may have at most `MAX_RW_COUNT` in all (`EINVAL`). They move the bytes as
  `readv` and `writev` do.

- `IORING_OP_EPOLL_WAIT` takes the events of the epoll its `fd` names, at
  most `len` of them, to `addr`, as `epoll_wait` does with no timeout: its
  `off`, `rw_flags`, `buf_index` and `splice_fd_in` must be 0 (`EINVAL`);
  then the file (`EBADF`), the count, from 1 to `INT_MAX / 12` (`EINVAL`),
  the events' room in the user half (`EFAULT`) and an epoll (`EINVAL`) are
  checked, as Linux's `ep_check_params` does. With none ready it waits until
  the epoll is readable, then takes them; room it cannot write is `EFAULT`
  once some are ready. It gives how many it took.

- `IORING_OP_PIPE` makes a pipe as `pipe2` does with its `pipe_flags`
  (`O_CLOEXEC`, `O_NONBLOCK` and `O_DIRECT`; others, or an `fd`, `off` or
  `addr3`, are `EINVAL`) and writes its ends' numbers to `addr`. Without a
  `file_index` they are the two lowest free descriptors (`EMFILE`). With
  one, they are registered slots, which may not be `O_CLOEXEC` (`EINVAL`):
  `IORING_FILE_INDEX_ALLOC` takes two free ones, looking on from the last
  one taken (`ENFILE`), and a slot takes it and the one after it, each as
  `IORING_OP_OPENAT` would fill it (`ENXIO`, `EINVAL`). A second slot that
  fails, or numbers it cannot write (`EFAULT`), give the descriptors back
  or empty the slots.

- A ring made with `IORING_SETUP_R_DISABLED` refuses `io_uring_enter`
  (`EBADFD`) until `IORING_REGISTER_ENABLE_RINGS` enables it, whose thread
  is then the only submitter with `IORING_SETUP_SINGLE_ISSUER`. Meanwhile
  `IORING_REGISTER_RESTRICTIONS` may give it restrictions once (`EBUSY`,
  `EBADFD` for an enabled ring), as Linux's `io_parse_restrictions` reads
  them: the registrations it allows (`EACCES` for another, once enabled),
  and the operations, with the flags they may have and must have, of its
  requests, each of which fails with `EACCES` otherwise. None at all allows
  nothing.

- A task's restrictions, `IORING_REGISTER_RESTRICTIONS` with descriptor -1
  as Linux 7.0's `io_register_restrictions_task` takes them, go to every
  ring the thread sets up after. A disabled ring is held to them at once,
  as Linux master is since 6da8f402e362, which the test runners' kernel
  has: it takes no restrictions of its own, and only the registrations they
  allow (`EACCES`), so enabling it needs `IORING_REGISTER_ENABLE_RINGS`
  among them. A new thread or process copies them,
  and exec keeps them. A thread with them already is refused (`EPERM`), and
  one needs `no_new_privs` or `CAP_SYS_ADMIN` (`EACCES`). There must be one
  argument (`EINVAL`), a `struct io_uring_task_restriction` that is read
  (`EFAULT`) with no flags or reserved bits (`EINVAL`), whose restrictions
  follow it and are read as a ring's are. Descriptor -1 with another
  registration is `EINVAL`.

- `IORING_REGISTER_PERSONALITY` keeps the thread's credentials, with its
  Landlock domain, and gives their ID, from 1 on (`xa_alloc_cyclic`). A
  request that names one (`EINVAL` for none) runs with them, again as it
  goes on after a wait (`override_creds`), and keeps them after
  `IORING_UNREGISTER_PERSONALITY`.

- `IORING_REGISTER_RING_FDS` registers ring descriptors for the calling
  thread, as Linux's `io_ringfd_register` does: 1 to 16 `struct
  io_uring_rsrc_update`s (`EINVAL`), each with no reserved field
  (`EINVAL`), naming a ring's descriptor (`EBADF`, `EOPNOTSUPP`) and a slot
  of 16, or the first free one for `-1` (`EINVAL` past them, `EBUSY` for
  none free), which is written back. It gives how many it registered.
  `io_uring_enter` with `IORING_ENTER_REGISTERED_RING`, and
  `io_uring_register` with `IORING_REGISTER_USE_REGISTERED_RING`, then name
  the ring by its slot: an empty one is `EBADF`, and one past the table, or
  any from a thread with no io_uring context, `EINVAL`. A thread has one
  once it made a ring, submitted to one or registered a descriptor; a new
  thread and a forked child have none. `IORING_UNREGISTER_RING_FDS` empties
  slots (`EINVAL` for a reserved field, data or a slot past the table), and
  `execve` and the thread's exit empty them all (`io_uring_unreg_ringfd`),
  and take its context away.

- `IORING_REGISTER_FILES` registers a ring's files as Linux 7.0's
  `io_sqe_files_register` does, the kernel the differential tests run on
  (its updates and allocation range are 7.0's too). It needs an argument
  (`EFAULT`), then none may be registered yet (`EBUSY`), 1
  (`EINVAL`) to 1048576 of them and no more than RLIMIT_NOFILE (`EMFILE`),
  then each descriptor (`EFAULT`). A descriptor of -1 leaves its slot
  empty, and one that is not open, an `O_PATH` one or a ring is `EBADF`.
  A failure registers none of them. A request with `IOSQE_FIXED_FILE`
  names its file by slot. A slot holds its file open after the descriptor
  is closed, so the file's close events come when the slot lets it go, and
  a pipe whose write end is in a slot has a writer.
  - `IORING_UNREGISTER_FILES` takes no argument (`EINVAL`) and needs files
    (`ENXIO`).
  - `IORING_REGISTER_FILES_UPDATE` and `IORING_OP_FILES_UPDATE` replace the
    files of slots from an offset, as `__io_sqe_files_update` does. The
    slots must not wrap (`EOVERFLOW`), files must be registered (`ENXIO`),
    and the slots must be within them (`EINVAL`). Each descriptor then
    empties its slot and puts its file there; `IORING_REGISTER_FILES_SKIP`
    leaves the slot as it is, and -1 leaves it empty. One that `fget` does
    not find is `EBADF` after its slot was emptied. They give how many slots
    they went through, or the error if none.
  - `IORING_OP_FILES_UPDATE` with the offset `IORING_FILE_INDEX_ALLOC`
    puts each file in a free slot of the allocation range, looking from
    past the last slot filled (or the last one emptied), then from the
    range's start (`ENFILE` when none is free). It writes the slot's index
    over the descriptor.
  - `IORING_REGISTER_FILE_ALLOC_RANGE` sets that range. It needs an
    argument and takes no count (`EINVAL`), then reads the range
    (`EFAULT`; `EOVERFLOW`, and `EINVAL` for a range past the registered
    files). Registering files
    makes it all of them.
  - `IORING_REGISTER_FILES2` and `IORING_REGISTER_FILES_UPDATE2` register
    and update files with a tag for each slot, as Linux 7.0's
    `io_register_rsrc` and `io_register_rsrc_update` do. The argument must
    be of its size (`EINVAL`), readable (`EFAULT`), with a count and no
    reserved field (`EINVAL`). `IORING_RSRC_REGISTER_SPARSE`, the only
    flag, registers empty slots and takes no descriptors (`EINVAL`), as a
    registration without descriptors does. Each tag is read before its
    descriptor (`EFAULT`), and a tag needs a file (`EINVAL` for an empty or
    skipped slot). Once nothing holds a tagged file, after its slot was
    emptied or the files were unregistered (the last slot first), a
    completion with the tag as its `user_data` and a result of 0 goes in at
    once, ahead of the completions of the submission that emptied the slot,
    or after them if a request of that submission holds the file. A
    registration that fails posts no tag.

- A ring keeps groups of buffers that a read or a socket's receive with
  `IOSQE_BUFFER_SELECT` chooses one of, the group that `buf_group` names, as Linux's
  `io_uring/kbuf.c` does. The read is of its length at most, or of the whole
  buffer, and its completion has `IORING_CQE_F_BUFFER` and the buffer's ID
  in the top 16 bits of its flags. A group with none left, or none, is
  `ENOBUFS`.
  - `IORING_OP_PROVIDE_BUFFERS` adds buffers at the end of a group, making
    it, with IDs from `off`, and `IORING_OP_REMOVE_BUFFERS` takes up to a
    count from its start (`ENOENT` for no group), giving how many. They check
    the entry as `io_provide_buffers_prep` and `io_remove_buffers_prep` do
    (`E2BIG`, `EINVAL`, `EOVERFLOW`, `EFAULT` for buffers past the user
    half). A group holds 65535 at most (`EOVERFLOW` if none could be
    added). A read uses its buffer once it chose it, even if it then fails.
  - `IORING_REGISTER_PBUF_RING` registers a ring of buffers for a group, as
    `io_register_pbuf_ring` does: reserved bytes, an unknown flag, or a
    count of entries not a power of two below 65536 is `EINVAL`, and a ring,
    or a group with buffers, there already is `EEXIST`. The ring is in the
    program's memory, page-aligned (`EINVAL`), not wrapping (`EOVERFLOW`) and
    writable (`EFAULT`), or with `IOU_PBUF_RING_MMAP` in pages the kernel
    gives, which `mmap` of the ring's descriptor at `IORING_OFF_PBUF_RING`
    and the group's ID shows (`ENOMEM` for a group without them). Its pages
    charge RLIMIT_MEMLOCK as registered buffers do.
    `IORING_UNREGISTER_PBUF_RING` takes it away (`ENOENT`, `EINVAL` for
    provided buffers), and `IORING_REGISTER_PBUF_STATUS` gives its head.
  - A read takes the buffer at a ring's head unless the tail is there. A
    file that cannot be polled, such as a regular file, uses it as the read
    chooses it, whatever the read then does; a pipe or socket uses it once
    its read did not fail, and one that failed leaves it in the ring. With
    `IOU_PBUF_RING_INC` a read uses only the bytes it took (a file that
    cannot be polled: the bytes it asked for), moving the buffer's address
    and length past them, and its completion has `IORING_CQE_F_BUF_MORE`
    while some of the buffer is left.

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
  alone; a hang-up, which has no key, what is ready). The call that makes
  the file ready, in this process or another (a forked child's write to the
  pipe), puts the event in the ring before it returns, so a program that
  takes events from the ring itself sees it without a call. So does a
  timerfd that expires while the program runs without a call: the next
  checkpoint of a running thread completes the poll, as Linux's timer does
  from its wake-up. A poll of a signalfd completes only if one of its
  signals is pending at `io_submit`: one that waits is never completed by
  a signal sent later, as Linux polls it again in a kernel worker, whose
  own signals `signalfd_poll` looks at, so only `io_cancel` or the
  context's end completes it. `io_cancel`
  cancels only a poll that waits (`EINPROGRESS`, with an event of no events
  in the ring), and gives `EINVAL` for another request. `io_getevents` and
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

- `modify_ldt` keeps the address space's local descriptor table as Linux's
  `arch/x86/kernel/ldt.c` does. Writing (1, the old mode, or 0x11) takes one
  16-byte `struct user_desc`. An entry number of 8,192 or more gives
  `EINVAL`, and so does a conforming code segment, unless the mode is the
  new one and the segment is not present. It stores
  Linux's descriptor, or clears the entry for an empty one (or, in the old
  mode, one with no base and no limit). The table grows to the highest
  entry written. Reading (0) gives 0 until something is written, then the
  entries, zero-filled up to the count (at most 64 KiB); 2 reads up to 128
  zero bytes, and other functions give `ENOSYS`. A fork keeps a copy and an
  exec starts with none. After a write, `%ds` and `%es` load again if they
  name an entry of the table, and become null if it no longer loads
  (`refresh_ldt_segments`); the entries load into the segment registers as
  above. The result is Linux's `int` as an `unsigned int`,
  so an error comes back as, say, `0xffffffea`, not `-EINVAL`.

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

- `chroot` gives the tasks that share the caller's working directory
  (`CLONE_FS`) a root of their own, as Linux's `set_fs_root`, after its
  checks: the path's lookup (`ENOENT`, `ENOTDIR`, `ELOOP`, `EACCES`), search
  permission on the directory (`EACCES`), then `CAP_SYS_CHROOT` in the
  caller's user namespace (`EPERM`). An absolute path or symbolic link then
  starts at the root and `..` stays there, for exec and its interpreters
  too. In a path that climbs above the root as written, a `..` after a
  symbolic link goes up from the link's target, and a name that is not
  there or is no directory ends the walk, as Linux's `link_path_walk` does.
  The working directory stays where it was, and from one outside the
  root a path goes anywhere, as on Linux. `getcwd` gives a working directory
  from the root, or, when it is not under the root, its path from the
  machine's root after `(unreachable)`. A child of `fork` keeps the root, a
  rename moves it with its directory, and `setns` into a mount namespace
  goes back to the machine's root. The generated `/proc` and `/dev` are under
  another root only where a bind mount of them puts them, as no `proc`
  filesystem is mounted there.

- `mount` mounts a new tmpfs on a directory of the caller's mount namespace,
  after Linux's checks in Linux's order: the type, the source and the
  options are copied (`EFAULT`; a string with no end in 4096 bytes is
  `EINVAL`), the target is looked up with its links followed (`ENOENT`,
  `ENOTDIR`, `ELOOP`, `EACCES`), `MS_NOUSER` is `EINVAL`, a Landlock domain
  that handles file access `EPERM`, and `CAP_SYS_ADMIN` over the mount
  namespace is needed (`EPERM`). A new mount then needs a type (`EINVAL`)
  that is `tmpfs` or `bpf` (a BPF file system, below; `ENODEV` for any
  other), options tmpfs takes (`EINVAL`
  for any other or a value of the wrong kind: `size`, `nr_blocks`,
  `nr_inodes`, `mode`, `uid`, `gid`, `huge`, `mpol`, `inode32`, `inode64`,
  `noswap`, the quota ones, and the common `sync`, `dirsync`, `lazytime` and
  `mand` and their opposites), `CAP_SYS_ADMIN` in the caller's user
  namespace (`EPERM`), and a directory (`ENOTDIR`) whose mount is in the
  caller's namespace (`EINVAL`). The mount hides what is under it and has a
  device and an ID of its own, the lowest free ones, as Linux hands them out;
  its root is a directory of mode 01777 owned by the caller's filesystem
  IDs, unless `mode`, `uid` and `gid` say otherwise. `statfs` gives it
  `TMPFS_MAGIC` and the size and inodes it was mounted with (half the
  memory `sysinfo` reports by default, 0 for no limit), against what its
  files take, which they are held to as tmpfs holds them: a write stops
  at the first page past the size (a short write, `ENOSPC` when nothing
  fits), `fallocate` allocates all of its range or none (`ENOSPC`), a
  long symbolic link (past 127 bytes) takes a page, and each new inode and
  each further name of a file (`link`) takes one of the inodes (`ENOSPC`
  for none left), which an unlinked file still open keeps until its last
  close; a remount changes the limits. Its files, and those of `/dev/shm`,
  are shmem's: a fault of a mapping of one brings its page in (a `SIGBUS`
  past the size), `userfaultfd` registers their mappings, a fill of one
  of their pages past the size is `ENOMEM`, and `MADV_COLLAPSE` takes
  them, as for a memfd. With `huge=always`, `within_size` or `advise`, a
  page that a write, a fault or `fallocate` brings in comes with a large
  folio's others, as `shmem_get_folio_gfp` takes one: the largest aligned
  extent of up to 512 pages in which the file has no page yet, which for
  `within_size` the size or the write's end covers and for `advise` lies
  in a mapping `MADV_HUGEPAGE` advised, and which a fault's mapping holds
  at offsets aligned as its addresses are, unless it was advised
  `MADV_NOHUGEPAGE`. It is charged whole, after the large folio at the
  end of a file that runs past its end is split to make room
  (`shmem_unused_huge_shrink`), or else the page alone. `mmap` without
  `MAP_FIXED` places a mapping of such a file of 2 MiB or more, unless
  at a free hint, at a 2 MiB boundary, or as far past one as its offset
  is past one (`shmem_get_unmapped_area`), so that a fault of it can take
  a 512-page folio; `mremap` moves one there too, shared or private
  (`vrm_set_new_addr` asks the file). The files are held as `shmem`
  counts them (`shmem_inode_acct_blocks`, `shmem_reserve_inode`), and
  `/proc/self/mountinfo` and `/proc/self/mounts` list it with its source,
  its `nosuid`, `nodev`, `noexec`, `noatime`, `nodiratime` and `relatime`,
  and tmpfs's options as Linux's `shmem_show_options` prints them. A path
  steps into the topmost mount on each directory it passes, and `..` at a
  mount's root goes to where it is mounted; `rename` and `link` from one
  mount to another are `EXDEV`, `rmdir`, `unlink` and `rename` of a mount
  point `EBUSY`, and a rename moves the mounts below the directory it
  moves. `MS_RDONLY` makes the new mount and its superblock read-only, and
  the `ro` option the superblock alone, as mountinfo's two `ro` fields show.
  A mount on a shared mount is shared too, in a peer group of its own.

- `mount` with `MS_BIND` makes a bind mount, after the same checks up to
  `CAP_SYS_ADMIN`, as Linux's `do_loopback`: a source (`EINVAL` for none or
  an empty one), looked up with its links followed (`ENOENT`, `ENOTDIR`,
  `ELOOP`, `EACCES`), a target whose mount is in the caller's namespace
  (`EINVAL`), and a directory on a directory or a file on a file
  (`ENOTDIR`). The new mount shows the source's mount's file system from
  the source down, with that mount's device, type, source and flags (the
  type, the data and the other flags of the call change nothing, so
  `MS_RDONLY` with it does not make it read-only), an ID of its own, and the
  source as its root in mountinfo's fourth field. It is not locked; without
  `MS_REC` a locked mount below the source is `EINVAL`
  (`has_locked_children`), and a mount below that is not locked stays
  behind, so the new mount shows the directory it covers (a `--mount`
  directory's too). With `MS_REC` the mounts below come along as copies,
  each locked if its original was. A tmpfs stays while a bind mount
  of it does, after its first mount goes, and a bind mount keeps showing its
  source after a rename of it. `statx` and `/proc/self/fdinfo` give a
  file's mount ID by its path, so a bind mount's files have the bind
  mount's. An unbindable source mount is `EINVAL`, and `MS_REC` leaves out
  the unbindable mounts below it and what is on them (`EPERM` for a locked
  one). The new mount is a peer of the source's mount and a slave of its
  master; on a shared mount it is shared, in a new peer group if the
  source's mount was in none.

- A bind mount's source may be a file the kernel generates in `/dev` or
  `/proc` (`mount --bind /dev/null file`, or a file of a process's
  directory, `/proc/self` taken as the caller's own): the new mount shows
  that file, with its device, as a mount of devtmpfs, procfs, devpts or
  mqueue with the flags Linux mounts each with (locked in a namespace of a
  less privileged owner) and the file's path there as its root in
  mountinfo. A path to the mount's place, or a link followed to it, reaches
  that file, as `stat`, `open`, reading and writing find it; its link in
  `/proc/self/fd` names the mount's place, as Linux's `d_path` does. The
  name itself is the mount's: `unlink` and `rename` find it in use
  (`EBUSY`), `mkdir` there `EEXIST`, `link` of it `EXDEV`; a bind mount of
  the mount is another of the same file, and `umount2` takes it away. A
  directory there binds onto a directory (`/proc`, `/dev` or one below
  them): each path below the mount's place is the kernel's path below the
  directory, so it shows what the kernel generates there, `..` at the
  mount's root leaves it, and a working directory there is the mount's
  place, which `getcwd` names (a missing name is `ENOENT` to `chdir` too).
  No mount below a generated directory is in the table, so none is locked
  (`has_locked_children`) and `MS_REC` brings none along.

- `mount` with `MS_REMOUNT` and `MS_BIND` changes a mount's flags alone, as
  Linux's `do_reconfigure_mnt`: the target is the root of a mount of the
  caller's namespace (`EINVAL`), the flags a copy into a less privileged
  namespace locked stay (`EPERM`: `MNT_LOCK_READONLY`, `MNT_LOCK_NODEV`,
  `MNT_LOCK_NOSUID`, `MNT_LOCK_NOEXEC` and `MNT_LOCK_ATIME`), and making it
  read-only needs no file open for writing on it (`EBUSY`). The flags are
  those of the call, its access-time ones kept unless it names one.
  `MS_REMOUNT` alone (`do_remount`) makes the same checks, then parses the
  options of the mount's file system (`EINVAL`), needs `CAP_SYS_ADMIN` over
  the superblock's user namespace (`EPERM`), and reconfigures the
  superblock as `reconfigure_super` does: an option for a flag a remount
  does not change (`dirsync`) is `EINVAL` (`MS_DIRSYNC` in the flags is
  left out), making it read-only needs no file open for writing on any of
  its mounts (`EBUSY`), and a tmpfs's own options are checked and changed
  as `shmem_reconfigure` does them (`EINVAL` for a limit on one mounted
  without it or below what its files use, `noswap` on one that swaps, a
  quota on one without, a changed quota limit; `size`, `nr_blocks`,
  `nr_inodes`, `huge`, `inode32`, `inode64` and `mpol` change, `mode`,
  `uid` and `gid` do not). The mount then takes the call's flags.

- A `noexec` mount runs nothing, as Linux's `path_noexec`: `execve` of a
  program there, a script's interpreter there and an ELF interpreter
  there are `EACCES` before their permission, as is `access` with `X_OK`
  of a regular file; `mmap` of a file there with `PROT_EXEC` is `EPERM`,
  `READ_IMPLIES_EXEC` adds no `PROT_EXEC` to it, and `mprotect` gives its
  mapping none (`EACCES`, the VMA without `VM_MAYEXEC`). The files the
  kernel generates are on `noexec` mounts, as `/proc` and `/dev` are on
  Linux (with systemd for `/dev`): `mmap` of `/dev/zero` with `PROT_EXEC`
  is `EPERM`, while a file reached through a link there (`/dev/fd`,
  `/proc/self/fd`) is on its own mount. A `nodev` mount
  opens no device there (`EACCES`, `may_open_dev`, for root too). A
  program on a `nosuid` mount, or on a superblock of a user namespace the
  caller is not in, runs without its set-user-ID and set-group-ID bits and
  its file capabilities (`mnt_may_suid`); for a script that is its
  interpreter, the file that runs.

- A read-only mount, or one of a read-only superblock, refuses what writes
  with `EROFS` where Linux's `mnt_want_write` does, after the errors that
  come before it: creating a name (`open` with `O_CREAT`, `O_TMPFILE`,
  `mkdir`, `mknod`, `symlink`, `link`, and `bind` of an `AF_UNIX` socket)
  once the name is found not there (`EEXIST` first) and before the
  permission to write its directory (and `link`'s `EXDEV` and `mknod`'s
  `EPERM` for a device); `unlink`, `rmdir` and `rename` once the directory
  is found and before the name is looked up (so a missing one is `EROFS`
  too); `open` with `O_TRUNC` of a regular file, and opening one for
  writing after its permission and `ETXTBSY` (a FIFO, a socket and a
  device still open); `truncate` after `EISDIR` and `EINVAL`; `chmod`,
  `chown`, `utimensat` and `utimes` and their descriptor forms, `setxattr`,
  `removexattr` and their descriptor forms, `file_setattr` and
  `FS_IOC_SETFLAGS` before their permission checks; and `access` with
  `W_OK` after its permission check. A read-only superblock also refuses
  writing a regular file, a directory or a symbolic link before its
  permission is checked (`sb_permission`). `statfs`'s `f_flags` gives the
  mount's flags (`ST_RDONLY`, `ST_NOSUID`, `ST_NODEV`, `ST_NOEXEC`,
  `ST_NOATIME`, `ST_NODIRATIME`, `ST_RELATIME`), as `flags_by_mnt` does;
  for `/proc` and `/dev` those Linux mounts them with: `/proc` and
  `/dev/mqueue` `nosuid`, `nodev`, `noexec` and `relatime`, `/dev/pts`
  `nosuid`, `noexec` and `relatime`, and the rest of `/dev` (a devtmpfs)
  `nosuid`, `noexec` and `relatime`, as systemd mounts it. `/dev/shm` is a
  tmpfs from start-up on `/dev`, as systemd mounts it (`mode=01777`,
  `nosuid`, `nodev`), where a C library's POSIX shared memory and
  semaphores make their files, and which can be unmounted or mounted
  over. A link in `/proc/self/fd` gives its file's, and
  the kernel's internal mounts (pipes, sockets, anonymous inodes, pidfs,
  memfd, secretmem, a queue `mq_open` opened) `ST_VALID` alone.

- `mount` with `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` or `MS_UNBINDABLE` (and
  `MS_REC` for the mounts on the target too) changes a mount's propagation
  type, after `do_change_type`'s checks: the root of a mount (`EINVAL`),
  one type and no other flag (`EINVAL`), and `CAP_SYS_ADMIN` over the
  mount's namespace (`EPERM`). A shared mount is in a peer group, a new one
  with the lowest free number if it was in none, and is no longer
  unbindable. Any other type takes it out of its group: its slaves then
  follow a peer, or with none left its own master; `MS_SLAVE` makes it a
  slave of its old group if it had peers, else of its master, and
  `MS_PRIVATE` and `MS_UNBINDABLE` leave it no master. `/proc/self/mountinfo`
  shows these as Linux's `show_mountinfo` does: `shared:N`, `master:N`,
  `propagate_from:N` and `unbindable`. A copy into a new mount namespace
  is a peer of the mount it copies, or with another user namespace a slave
  of it. A mount that is unmounted, or whose namespace ends, leaves its
  peer group the same way.

- A mount, a bind mount or a move onto a shared mount propagates as
  Linux's `propagate_mnt` makes it: each other mount its peer group
  reaches (its peers, its slaves and theirs, in every mount namespace)
  whose root holds the place gets a copy of the new mounts there. A
  peer's copies are peers of the new mounts; a slave's are slaves of
  them, and shared in new peer groups when the slave is. A copy into a
  namespace of another user namespace is locked, and a mount already at
  the place goes on the copy's root. An unmount under a shared mount
  takes away the mount at the same place on each of those, as
  `propagate_umount` does, but one that has other mounts on it (a mount on
  its root takes its place). Those at the place unmounted are no longer
  locked (`propagate_mount_unlock`); a locked one below them goes only
  with its parent (`handle_locked`). Without `MNT_DETACH`, a file open on one of
  them makes the unmount `EBUSY` (`propagate_mount_busy`). A slave's own
  mounts reach its own slaves, not its master.

- `mount` with `MS_MOVE` moves a mount, as Linux master's `do_move_mount`
  checks it: a source (`EINVAL` for none or an empty one), looked up with
  its last link followed, at a mount's root (`EINVAL`), a directory onto a
  directory and a file onto a file (`EINVAL`); then the namespace's root, a
  locked mount and one on a shared mount are `EINVAL`, a tree with an
  unbindable mount onto a shared mount `EINVAL`, and a move onto the mount
  itself or a mount on it `ELOOP`. The mount goes on top of what is at the
  target, with the mounts on it, its old place showing the directory under
  it again; on a shared mount each becomes shared, in a new peer group if
  it was in none. The roots and working directories in them go along.

- `pivot_root` (Linux master's `path_pivot_root`) looks both paths up as
  directories with their links followed, the new root first; then it needs
  `CAP_SYS_ADMIN` over the mount namespace and no Landlock domain that
  handles file access (`EPERM`). A shared mount at `put_old`, under the new
  root or under the caller's root is `EINVAL`, as is a locked new root; the
  new root or `put_old` on the root's mount is `EBUSY`; the root and the new
  root must be mounts' roots, `put_old` at or below the new root, and the
  new root below the root (`EINVAL`). The new root's mount, with those on
  it, takes the root's place, and the old root goes on `put_old` with the
  rest of its tree; the new root takes over the old root's lock, so a
  mount namespace of a new user namespace can unmount the old root.
  Every process on the namespace whose root or working directory was the
  old root is then on the new one (`chroot_fs_refs`), and the others' stay
  with their mounts. `pivot_root(".", ".")` stacks the old root on the new
  one, which `umount2(".", MNT_DETACH)` then takes off.

- `open_tree` (Linux master's `vfs_open_tree`) checks its flags first
  (`EINVAL` for an unknown one, `AT_RECURSIVE` without a copy, and
  `OPEN_TREE_DROP_MNTNS_MOUNTS` without a recursive one), then
  `CAP_SYS_ADMIN` over the mount namespace for `OPEN_TREE_CLONE` (`EPERM`),
  then looks the path up, its last link followed unless
  `AT_SYMLINK_NOFOLLOW`, an empty one naming `dfd` with `AT_EMPTY_PATH`.
  It gives an `O_PATH` descriptor of the file, or with `OPEN_TREE_CLONE` of
  a copy of its mount (with `AT_RECURSIVE` the mounts below it too, as a
  bind mount copies them) in a tree of its own, which no path and no
  mountinfo reaches, and which goes with the descriptor's last close
  unless `move_mount` attached it. A path from the descriptor goes into
  the copy, and `..` stays at its root. With `OPEN_TREE_NAMESPACE`, which
  needs `CAP_SYS_ADMIN` in the caller's user namespace (`EPERM`, before
  the lookup), it gives a descriptor of a new mount namespace that user
  namespace owns (Linux master's `create_new_namespace`), as
  `/proc/<pid>/ns/mnt` opens one (`mnt:[...]`), which `setns` enters: its
  root is a copy of the mount, rooted at the directory named (a file is
  `ENOTDIR`), with `AT_RECURSIVE` the mounts below it too, on a mount below
  it that no mountinfo shows (Linux's copy of its nullfs). The root is
  locked when the caller's namespace's root is. From a mount namespace
  another user namespace owns, the copies are slaves instead of peers,
  unbindable mounts below come along, each copy is locked with its flags
  (`lock_mnt_tree`), and a copy without `AT_RECURSIVE` of a mount with
  mounts below the directory is `EINVAL`.

- `move_mount` (Linux master's) needs `CAP_SYS_ADMIN` over the mount
  namespace (`EPERM`) and known flags (`EINVAL`, also for
  `MOVE_MOUNT_BENEATH` with `MOVE_MOUNT_SET_GROUP`); it looks up the target
  and then the source, each following its last link only with its
  `MOVE_MOUNT_*_SYMLINKS` and naming its descriptor when empty with its
  `MOVE_MOUNT_*_EMPTY_PATH`, and a Landlock domain is `EPERM`. It moves a
  mount as `MS_MOVE` does, or attaches a tree from `open_tree`: only its
  root (`EINVAL`), not onto its own tree (`EINVAL`); a mount of the
  namespace goes onto no detached tree (`EINVAL`). With `MOVE_MOUNT_BENEATH`
  the source goes beneath the topmost mount at the target, on that mount's
  parent, and the topmost mount stays on top, on the source's root
  (`do_move_mount` with `MNT_TREE_BENEATH`): the target must be a mount's
  root and not the namespace's root (`EINVAL`), then the checks of a move
  are made on that parent. A source in the topmost mount's tree is `EINVAL`,
  and so is a move where a shared parent would propagate a copy of the
  source onto the topmost mount or onto the source at its root
  (`propagation_would_overmount`). A locked topmost mount's lock passes to the source, so the
  topmost one may then be unmounted. `MOVE_MOUNT_SET_GROUP`
  puts the target in the source's peer group (`do_set_group`): both mounts'
  roots, of one superblock, the target's root at or below the source's,
  the target private and the source shared or a slave (`EINVAL`).

- `fsopen`, `fsconfig`, `fsmount` and `fspick` (Linux master's
  `fs/fsopen.c`) make a tmpfs or a BPF file system through a file system
  context, a descriptor
  (`anon_inode:[fscontext]`) that `fsconfig` fills and acts on. `fsopen`
  needs `CAP_SYS_ADMIN` over the mount namespace (`EPERM`) and known flags
  (`EINVAL`), and any type but those is `ENODEV`. `fsconfig` checks each
  command's arguments (`EINVAL`, `EOPNOTSUPP` for an unknown command), then
  the descriptor (`EBADF`, `EINVAL` for another file); it takes the
  parameters `mount` takes, one at a time, with the same checks, and
  `read` from the descriptor gives the message Linux logs for each one it
  refused (`e tmpfs: Bad value for 'size'`, `e tmpfs: Unknown parameter
  'x'`, ...), oldest first, then `ENODATA`. `FSCONFIG_CMD_CREATE` makes
  the superblock (`CAP_SYS_ADMIN` over the user namespace, `EPERM`), after
  which the context takes no parameter (`EBUSY`). `fsmount` checks its
  flags and mount attributes (`EINVAL`), then mounts it in a detached tree
  as `open_tree` makes one (`EINVAL` before the superblock is made,
  `EBUSY` once mounted), which `move_mount` attaches; the context then
  reconfigures it. `fspick` gives a context of a mount's superblock (at the
  mount's root, `EINVAL`), whose `FSCONFIG_CMD_RECONFIGURE` changes the
  flags named and tmpfs's options as `MS_REMOUNT` does (`EPERM` without
  `CAP_SYS_ADMIN` over the superblock's user namespace, which also leaves
  the context failed, `EBUSY` from then on).

- `mount_setattr` (Linux master's) checks its flags (`EINVAL`), then its
  `struct mount_attr` (`E2BIG` beyond a page or for bytes past it that
  are not 0, `EINVAL` under 32 bytes), `CAP_SYS_ADMIN` over the mount
  namespace (`EPERM`), one propagation type and known attributes
  (`EINVAL`), and an access-time setting only with all of
  `MOUNT_ATTR__ATIME` cleared (`EINVAL`); one that changes nothing is 0
  before the lookup. At a mount's root (`EINVAL`), of the namespace or a
  detached tree's root, it sets and clears the mount's flags, with
  `AT_RECURSIVE` those of each mount below it too, all or none: a locked
  flag that would change is `EPERM`, and read-only with a file open for
  writing `EBUSY`. Then the mounts take the propagation type.
  `open_tree_attr` is `open_tree` with the same change made to its
  descriptor's mount, which goes again when the change fails.

- Each mount has an ID unique until the machine ends (`mnt_id_unique`,
  from `1 << 31` on, in the order the mounts were made, a namespace's
  copies in the order `copy_tree` takes them), and each mount namespace
  an ID (the first's 8). `listmount` (Linux master's) checks its flags,
  count and array (`EINVAL`, `EOVERFLOW`, `EFAULT`) and its `struct
  mnt_id_req` (`E2BIG`, `EINVAL`), and gives, in order or backwards with
  `LISTMOUNT_REVERSE`, after the last ID it was given, the IDs of the
  mounts reachable from the caller's root (`LSMT_ROOT`) or from a mount
  (`ENOENT` for none), of the caller's namespace or of one by its
  namespace file or ID (`ENOENT`, `EBADF`, `EINVAL`; another one's
  only with `CAP_SYS_ADMIN` over it). `statmount` gives what one of them
  is, or with `STATMOUNT_BY_FD` the mount of a descriptor's file: the
  superblock's device, type and flags, the mount's IDs, attributes and
  propagation, its root and its mount point from the caller's root, the
  type's name, its options alone and as an array, its source and its
  namespace's ID, each as asked (`mask`, `supported_mask`); a buffer too
  small for its strings is `EOVERFLOW`, a mount the caller's root does
  not reach `EPERM` without `CAP_SYS_ADMIN`.

- `umount2` checks its flags (`EINVAL`) before it looks the target up, its
  last link followed unless `UMOUNT_NOFOLLOW`, stepping into a mount on
  where the path starts too (`LOOKUP_MOUNTPOINT`); then, as Linux's
  `can_umount` and `do_umount`, it needs `CAP_SYS_ADMIN` over the mount
  namespace (`EPERM`), the root of a mount of that namespace that is not
  locked (`EINVAL`), for `MNT_FORCE` `CAP_SYS_ADMIN` over the superblock's
  user namespace (`EPERM`), and no Landlock domain that handles file access
  (`EPERM`). A mount in use, by an open file (an `O_PATH` one and a mapping
  too), a working directory or a root, or with other mounts on it, is
  `EBUSY`, unless `MNT_DETACH` takes it and those on it away at once, their
  open files still reading and writing. `MNT_EXPIRE` (`EINVAL` with
  `MNT_FORCE` or `MNT_DETACH`, or of the caller's root) marks a mount no one
  uses (`EAGAIN`) and unmounts it the next time; a lookup that ends on the
  mount, or the close of a file on it, clears the mark, as Linux's `mntput`
  does. The caller's root without `MNT_DETACH` needs `CAP_SYS_ADMIN` over
  its superblock's user namespace (`EPERM`), and then stays mounted: its
  superblock is remounted read-only (`do_umount_root`, `EBUSY` with a file
  open for writing on it).

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
  `setdomainname` then change for it alone. A new mount namespace starts
  with a copy of each mount, with a new ID, on the same file system, locked
  when the new namespace's user namespace is another (`lock_mnt_tree`), and
  `mount` and `umount2` in it change its mounts alone; the thread's root and
  working directory stay at their paths, on the copies. A new time namespace is the one
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
  `/proc/<pid>/uid_map` and `gid_map` (and `projid_map`, below) read the extents of the task's user
  namespace, the lower IDs as the reader's namespace has them (its parent's
  for its own), and take one write of up to 340 lines of three numbers, in
  Linux's order and with its checks (`proc_uid_map_write`, `map_write`,
  `new_idmap_permitted`): from a thread of the namespace or its parent that
  has `CAP_SYS_ADMIN` in it, its owner may map its own effective ID alone
  (a group only once `setgroups` is denied), and anything else needs
  `CAP_SETUID` or `CAP_SETGID` in the parent; mapping the parent's root needs
  `CAP_SETFCAP`. `/proc/<pid>/setgroups` reads `allow` or `deny`, which
  may be written before the gid map; `setgroups` needs it allowed and the
  gid map written. Each of these files reads the user namespace the task
  was in when it was opened (`proc_id_map_open`), as that namespace is at
  each read from its start, one line for each extent; a write must be at
  the start and leaves the file position after it, so a read then goes on
  from there.

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
  devices of the namespace the socket was made in, as Linux's `dev_ioctl`
  takes `sock_net`: its loopback (`IFF_UP | IFF_LOOPBACK | IFF_RUNNING`
  while it is up, in the first namespace too) and its veth ends (veth
  pairs, below); an accepted AF_UNIX socket is in its client's.
  `SIOCSIFFLAGS` needs CAP_NET_ADMIN in the user namespace that owns that
  namespace, whichever the caller is in. An AF_UNIX socket of a first
  namespace without a network has none (`ENOTTY`). Another interface name
  is `ENODEV`. `SIOCGIFNAME` (`if_indextoname`) names the device of the
  index (`ENODEV` for none).

- A netlink socket (`AF_NETLINK`, `SOCK_RAW` or `SOCK_DGRAM`, protocol
  `NETLINK_ROUTE`) shows and changes the devices of the network namespace
  it was made in, its loopback and its veth ends (veth pairs, below), so glibc's and musl's `getifaddrs`, `ip link`, `ip addr`
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
    `SO_RCVTIMEO`, `NETLINK_PKTINFO`, `NETLINK_BROADCAST_ERROR`,
    `NETLINK_NO_ENOBUFS`, `NETLINK_LISTEN_ALL_NSID` (which needs
    `CAP_NET_BROADCAST` over the socket's namespace), `NETLINK_CAP_ACK`,
    `NETLINK_EXT_ACK` and `NETLINK_GET_STRICT_CHK` can be set; as in Linux's
    `netlink_setsockopt`, a value shorter than an `int` is 0. With
    `NETLINK_PKTINFO`, `recvmsg` gives each datagram's group (0 for one
    to the socket's own port) in a `SOL_NETLINK` `NETLINK_PKTINFO` control
    message, or `MSG_CTRUNC` when it does not fit.
    `NETLINK_BROADCAST_ERROR` is only kept, as no notification here tells
    anyone that it was not delivered. A message from the kernel that
    finds the receive buffer full is dropped, with `ENOBUFS` for the next
    receive, and the socket is then held congested, as Linux's
    `NETLINK_S_CONGESTED`: it drops the kernel's other messages too, with
    no other `ENOBUFS`, until a receive finds its queue empty. A socket
    with `NETLINK_NO_ENOBUFS` drops them with neither, and setting it
    ends a congestion. A dump's parts do not look at it. A datagram from another socket that finds no
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
    `NETLINK_CAP_ACK` is set. With `NETLINK_EXT_ACK`, an error and a dump's
    `NLMSG_DONE` that ends it at once carry what Linux's
    `netlink_ext_ack` holds (`NLM_F_ACK_TLVS`): Linux's message
    (`NLMSGERR_ATTR_MSG`), the offset of the attribute at fault
    (`NLMSGERR_ATTR_OFFS`) and the policy that refused it
    (`NLMSGERR_ATTR_POLICY`); an acknowledgement carries a warning, such
    as of bytes left over after the attributes. A message type past the
    last `rtnetlink` knows (`RTM_MAX`, 123) is sent, and answered with
    `EOPNOTSUPP`, as `rtnetlink_rcv_msg` does. Anything but a `GET` needs `CAP_NET_ADMIN` in
    the user namespace that owns the network namespace, for the sending
    thread and the socket's opener (`EPERM`); a send that names an
    address (`sendto`, `sendmsg` with a name) needs the sending thread's
    alone, as `netlink_sendmsg` marks it `NETLINK_SKB_DST`, which
    `__netlink_ns_capable` passes the opener over for. A `write` (and
    `writev`, `sendfile`, `splice` and AIO writes) sends as `send` without
    an address does, as the writing thread, since `netlink_sendmsg` runs
    in it: an autobind takes its process ID for the port, a route lookup
    its user ID for `RTA_UID`, and a change needs its `CAP_NET_ADMIN` and
    the opener's. `bind`'s and `NETLINK_ADD_MEMBERSHIP`'s multicast routing
    groups and `connect` to another port or a group ask the calling
    thread alone (`rtnetlink_bind`, `netlink_allowed`).
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
    has no master; `RTM_F_PREFIX` dumps no route, as `lo` has no prefix
    route.
  - **Another namespace by its ID:** a link dump or get with
    `IFLA_TARGET_NETNSID`, checked or not, and a strictly checked address
    dump with `IFA_TARGET_NETNSID`, show the link or addresses of the
    namespace that ID names (see Namespace IDs below), with that ID in
    the answer: `IFLA_TARGET_NETNSID` (`IFLA_IF_NETNSID`) first, before
    the link's name, as Linux 7.0's `rtnl_fill_ifinfo` puts it (Linux's
    master branch puts it after the name), and `IFA_TARGET_NETNSID` first
    in each address, as `inet_fill_ifaddr` and `inet6_fill_ifaddr` put
    it; an `AF_UNSPEC` dump's MCTP addresses are still the socket's own
    namespace's. An ID none has is `EINVAL`, and a namespace whose
    owner the socket's opener or the sender lacks `CAP_NET_ADMIN` in is
    `EACCES` (`rtnl_get_net_ns_capable`), with Linux's extended-ack
    message in a dump. A single IPv6 address (`RTM_GETADDR` with
    `IFA_TARGET_NETNSID`) is looked for in that namespace, and its
    answer, as `inet6_rtm_getaddr` sends it with `rtnl_unicast`, goes to
    the socket that has the requester's port there; with none, the
    request is `ECONNREFUSED`.
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
    (`EINVAL`), and a get neither of the first two (`EOPNOTSUPP`).
  - **Link changes and other namespaces:** `RTM_SETLINK` and `RTM_NEWLINK`
    find the namespace those name as `rtnl_link_get_net_capable` does,
    before `lo` is looked for: `ESRCH`, `EBADF` or `EINVAL` for a process,
    descriptor or ID that names none, and `EPERM` without
    `CAP_NET_ADMIN` over it, the opener's and the sender's (the sender's
    alone for a send that names an address, as above). `lo` is found
    (`RTM_NEWLINK` with `NLM_F_CREATE` and `NLM_F_EXCL` finds it in that
    namespace, where it is too, so `EEXIST`), and moving it to another
    namespace is `EINVAL`, as its namespace is immutable
    (`__dev_change_net_namespace`), before any other attribute; its own
    namespace, by process, descriptor or ID, is no move. `RTM_DELLINK`,
    as `rtnl_dellink`, takes an ID alone (`EOPNOTSUPP` for the first two),
    as `rtnl_get_net_ns_capable` finds it (`EINVAL`, `EACCES`), and finds
    `lo` there by index or name, which may not be deleted (`EOPNOTSUPP`,
    as it has no `rtnl_link_ops`); another link is `ENODEV`, and without
    either, `IFLA_GROUP` is `EPERM` for group 0 and `ENODEV` for another,
    and nothing `EINVAL`.
  - **veth pairs:** `RTM_NEWLINK` of kind `veth` (`IFLA_LINKINFO`) makes a
    pair, as `rtnl_newlink` and `veth_newlink` do: its peer, of
    `VETH_INFO_PEER`'s name, address, MTU and namespace (`IFLA_NET_NS_PID`
    or `IFLA_NET_NS_FD`; the requester's without one), then the first end,
    of the request's, each `veth%d` without a name, of a random address
    without one and of the index the request asks (the peer's only with
    the first end's). Without `VETH_INFO_PEER` the peer takes the
    request's MTU and namespace, but a name and an address of its own. It
    checks in Linux's order: an address of other than six bytes or an MTU
    past 68 to 65535 (`EINVAL`), a multicast address (`EADDRNOTAVAIL`), a
    name or index taken (`EEXIST`, `EBUSY`), a link the request names that
    is there (`EEXIST` with `NLM_F_EXCL`). Each end is an Ethernet device,
    told of with `RTM_NEWLINK` in its namespace; it has its carrier
    (`IFF_LOWER_UP`, then `IFF_RUNNING` and an operational state of up)
    while both ends are up, each telling of it (an end up without it is
    lower layer down where the device of its peer's index in its own
    namespace is not up, as `default_operstate` finds it), and its link
    messages give
    its kind, its peer (`IFLA_LINK`) and, where that is in another
    namespace, that namespace's ID (`IFLA_LINK_NETNSID`, which the
    namespace telling of it gives first, with `RTM_NEWNSID`). `RTM_SETLINK`
    or `RTM_NEWLINK` brings an end up or down, as `SIOCSIFFLAGS` does
    (with `SIOCGIFFLAGS`, `SIOCGIFINDEX` and `SIOCGIFNAME`), and moves it
    to another namespace, as `__dev_change_net_namespace` does: closed
    first if up (told of with `IFF_UP` and `IFF_RUNNING` changed), it is
    told of with `RTM_DELLINK` in the namespace it leaves, which gives the
    other an ID, with that ID and its index there (`IFLA_NEW_NETNSID`,
    `IFLA_NEW_IFINDEX`), then with `RTM_NEWLINK` in the one it enters,
    keeping its index unless that one has it. `RTM_DELLINK` of either end
    takes both, and so does the namespace of either going (after its
    `RTM_DELNSID`); as `unregister_netdevice_many_notify` does, every end
    that is up is closed before either is told gone.
    An end takes IPv4 addresses as `lo` does (`inet_rtm_newaddr`), each
    among its own, so one in a subnet another device's address has is no
    secondary; its name is their label. An address brings its local route
    at once and, while the end is up, its broadcast routes and a unicast
    prefix route in the main table, of link scope (`fib_add_ifaddr`), all
    through the end (`RTA_OIF`); coming up brings them for its addresses
    after its link message, going down takes all but the local ones
    without a word, and while it is up without its carrier they are
    `RTNH_F_LINKDOWN` (`fib_check_nh_nongw`, `NETDEV_CHANGE`). A route the
    guest adds through an end without a gateway is taken as well
    (`ENETDOWN` while the end is down, `ENODEV` for a device there is
    not), and one with a gateway (`RTA_GATEWAY`) goes through the end it
    names or else the one the gateway's route goes through, as
    `fib_check_nh_v4_gw` checks it: a route of link scope or narrower,
    unicast or local, must reach it, through that end if named, and that
    end must be up (`ENETDOWN`); `RTNH_F_ONLINK` takes the gateway to be on
    the named end's link, which must be up, and refuses one that is an
    address of the namespace, a broadcast or a group (`EINVAL`). Its
    packets go to the gateway's neighbour where a route of link scope
    reaches the gateway (`rt_uses_gateway`), else to their destination's.
    A gateway may be one of IPv6 (`RTA_VIA`, `fib_gw_from_via`; one of IPv4
    there is as in `RTA_GATEWAY`, except that 0.0.0.0 is a gateway still,
    and both are `EINVAL`): it is checked as
    an IPv6 route's (`fib_check_nh_v6_gw`), by the IPv6 table of the
    route's number, then the local and main ones, its end needs IPv6 on
    (`EACCES`), and a next hop made without its carrier is not
    `RTNH_F_LINKDOWN`. The packets go to its neighbour, which neighbour
    discovery finds from the end's link-local address, and dumps,
    notifications and lookups give it as `RTA_VIA`.
    A route's `RTA_MULTIPATH` makes one route of its next hops
    (`fib_get_nhs`), each checked as a route's next hop of its own device,
    gateway and flags (`fib_check_nh`), with its weight (`rtnh_hops` + 1):
    `EINVAL` for data past them, a hop `RTNH_F_DEAD` or
    `RTNH_F_LINKDOWN`, a gateway shorter than an address, a first hop not
    of the request's `RTA_OIF` or `RTA_GATEWAY`, a kind that rejects, and
    more than one of host scope. Dumps and notifications give its hops in
    `RTA_MULTIPATH`, each with its flags, weight less one, device and
    gateway, and its `rtm_flags` the route's own, `RTNH_F_LINKDOWN` where
    all its hops are; one of one hop is a route of one. Another of other
    hops or weights is another route; the same again is `EEXIST`. A hop
    whose end goes down turns `RTNH_F_DEAD` and `RTNH_F_LINKDOWN`,
    without a word, which lookups pass over, until the end comes up
    (`fib_sync_down_dev`, `fib_sync_up`); one without its carrier
    `RTNH_F_LINKDOWN`; a route whose hops are all dead goes, as one does
    through an end that goes away. A removal naming a device or gateway
    matches a route's first hop, and one with `RTA_MULTIPATH` each of its
    hops in turn (`fib_nh_match`). A lookup takes the hop the hash of its
    flow falls to, each hop living taking a share of the hashes by its
    weight (`fib_select_multipath`, `fib_rebalance`). With
    `net.ipv4.fib_multipath_use_neigh` 1, it passes over a hop whose
    gateway, reached by a route of link scope, has a neighbour on the
    hop's device that is not valid (`fib_good_nh`), the hop keeping its
    share, and takes the first hop living where it passes over all. The
    hash is of what
    `net.ipv4.fib_multipath_hash_policy` names (`fib_multipath_hash`): the
    source and destination (0 and 2); those, the protocol and the ports
    (1); or the fields `fib_multipath_hash_fields` names (3). An
    `RTM_GETROUTE` hashes the packet `inet_rtm_getroute_build_skb` makes,
    of UDP where it names no protocol, with ports for TCP and UDP alone,
    and its hash of policy 3 mixed with no inner one
    (`fib_multipath_custom_hash_skb`). The key is the machine's random
    seed, every namespace's, or `net.ipv4.fib_multipath_hash_seed`, with
    which each flow's hop is Linux's. Before the hash, one whose device's
    own source is the lookup's; through a device named, the first through
    it. A socket not bound takes
    the source of the hop it hashes to with no source, and a connection or
    a UDP connect then looks its route up from that source
    (`ip_route_connect`). A socket's flow hashes its own port, which a UDP
    socket has before its route (`inet_send_prepare`, `inet_dgram_connect`),
    and a connection with none yet a random one (`FLOWI_FLAG_ANY_SPORT`);
    an answer hashes its own ports. IPv4's port unreachable is looked up
    with the datagram it tells of (`icmp_route_lookup`), hashed as the
    packet of an `RTM_GETROUTE` is. Under policy 1, a datagram from a
    connected socket is hashed instead by the random flow hash that socket
    gave it (`sk_txhash`, `skb_set_hash_from_sk`). A packet may come in
    on the device of any hop of the route back to its source
    (`fib_info_nh_uses_dev`), and its answer goes back by a lookup of its
    own, through whichever end that takes, or the one its listener is bound
    to. An output lookup that goes through
    an end leaves from its first primary address, else from the first of
    the other devices' in the order they were made
    (`inet_select_addr`), and names it as `RTA_OIF`,
    without `RTCF_LOCAL`; one forwarded there from `lo` names it too, with
    its source checked as `__fib_validate_source` does (strict reverse
    path filtering drops one whose route goes out through another device).
    An end that goes, or moves to another namespace, first tells of each
    of its addresses and their local routes going, as `inetdev_destroy`
    does, before its `RTM_DELLINK`. Address and route dumps take an end's
    index (the `ifaddrmsg`'s, `RTA_OIF`).
  - **TCP and UDP across a pair:** a connection or datagram whose route
    goes out through an end, from the address that route leaves from,
    comes to the peer's namespace when the end has its carrier, the
    destination is one of that namespace's addresses (its local routes
    have it, as `arp_process` answers for any), and the peer takes the
    source in on its end (`fib_validate_source`, with its reverse path
    filtering). There it is a connection to the listener of that address
    and port, or a datagram for its socket, as on the loopback; a port
    nobody listens on answers with a reset (`ECONNREFUSED`), and a UDP
    port nobody has with ICMP's port unreachable, which a connected socket
    learns of. Answers come back only where the peer's namespace routes
    the source out through an end whose peer is this one's, which takes
    them in there. To a destination nobody answers ARP for, a connection fails with
    `EHOSTUNREACH` once ARP gives up, 3 seconds later (three probes a
    second apart, `mcast_probes`), as ICMP's host unreachable tells it
    over the loopback (with `ETIMEDOUT` after the handshake's tries where
    the loopback is down, and where answers come back to no one), and a
    datagram is dropped, as is one to a loopback address, which
    `arp_process` takes no request for. A connection or datagram from a
    loopback address out through an end is `EINVAL`, and a route lookup
    of one too (`__mkroute_output`); where no address of a scope to fit is there
    (`inet_select_addr`), it leaves from 0.0.0.0, which ARP asks from too
    and the peer answers, and the peer drops what comes as a martian, so
    a connection times out (`ETIMEDOUT`) and a datagram is lost. TCP
    takes no broadcast or multicast route (`ENETUNREACH`), and UDP no
    broadcast one, to an address a broadcast route has or the limited
    broadcast one, without `SO_BROADCAST` (`EACCES`). With it, a broadcast
    datagram reaches each UDP socket of its port that takes it, a copy
    each (`__udp4_lib_mcast_deliver`): one bound to the unspecified
    address or to the datagram's, not connected or connected to its
    sender, and not `IPV6_V6ONLY`, in the sending namespace, as
    `ip_mc_output` loops a broadcast back even without a carrier, and,
    while the end has its carrier, in the peer's, if it takes the
    address as a broadcast one (the limited one, or one its routes make
    so) from a source its reverse path filtering takes
    (`ip_route_input_slow`). Out through `lo`, to the limited broadcast
    address from a socket bound to `lo` or to its address, or by a
    broadcast route through it (as the local table's to
    `127.255.255.255`), it comes back in on `lo` once, to such sockets
    bound to `lo` or to no device, as `lo` sends it with no copy looped
    back (`__mkroute_output` gives `ip_mc_output` to no loopback device).
    A socket connected from the unspecified
    address has taken its route's source, and takes none. An IPv4 socket
    bound to a broadcast or multicast address keeps it as its name, which
    a UDP connect leaves, but sends from its route's source (`inet_bind`),
    and a TCP connection takes that source as its name too
    (`tcp_v4_connect`). An IPv6 socket bound to such an IPv4-mapped
    address keeps it as its IPv4 source (`__inet6_bind`), so its routes to
    IPv4 fail: `EINVAL` from a group or the limited broadcast address,
    `ENETUNREACH` from a subnet's, for UDP's `sendto` and `connect` and
    TCP's `connect`. A group or the
    limited broadcast address from a socket bound to an end's address, or
    to `lo`'s while it is up, needs no route: it goes out through that
    device (`ip_route_output_key_hash_rcu`).
  - **IPv4 multicast groups:** a UDP socket joins and leaves a group with
    `IP_ADD_MEMBERSHIP` and `IP_DROP_MEMBERSHIP` (`ip_mreqn` or `ip_mreq`),
    on the device of an index, of an address, or of the route to the group
    (`ENODEV` for none): `EINVAL` for no group, `EADDRINUSE` as a member
    there, `ENOBUFS` past 20, `EADDRNOTAVAIL` to leave as none, and
    `EPROTO` of TCP (`__ip_mc_join_group`, `ip_mc_leave_group`); closing it
    leaves all. A device is in a group while a socket of its namespace is
    a member there, and in 224.0.0.1 while it is up. A datagram to a group
    goes out through the socket's device, else `IP_MULTICAST_IF`'s, else
    that of the source's address, else the route's, from the socket's
    address, else `IP_MULTICAST_IF`'s. Where the device is in the group it
    comes back too, unless `IP_MULTICAST_LOOP` is off (which an IPv6
    socket's send does not heed), and goes no further with an
    `IP_MULTICAST_TTL` of 0 (`ip_mc_output`); across the pair, the peer's
    namespace takes it where its end is in the group
    (`ip_route_input_mc`); and through `lo` it comes back where `lo` is.
    There it reaches each UDP socket of its port that a broadcast would,
    and that is a member on that device or has `IP_MULTICAST_ALL` on, as
    an IPv4 one begins with and an IPv6 one does not (`ip_mc_sf_allow`,
    `inet6_create`). An accepted connection's `IP_MULTICAST_TTL` is 64
    (`tcp_v4_syn_recv_sock`).
  - **IPv6 multicast groups:** an IPv6 UDP socket joins and leaves a group
    with `IPV6_ADD_MEMBERSHIP` and `IPV6_DROP_MEMBERSHIP`, on the device of
    an index or that of the route to it (0): `EINVAL` for no group or a
    device without IPv6, `ENODEV` for none, `EADDRINUSE` as a member there
    (anywhere, for 0), `EADDRNOTAVAIL` to leave as none, and `EPROTO` of
    TCP (`__ipv6_sock_mc_join`, `ipv6_sock_mc_drop`). A device joins
    groups of its own too, kept in one list with the sockets', the newest
    first: ff01::1 and ff02::1 as it comes to IPv6 (`ipv6_add_dev`), the
    solicited-node group of each address as the address comes, once for
    each, and leaves it as the address goes (`addrconf_join_solict`), a
    loopback's but; and, a veth end, ff02::2, ff01::2 and ff05::2 as it
    comes to forward, which it leaves as it stops (`dev_forward_change`).
    Down, it keeps them, unloaded (`ipv6_mc_down`), until it is ready
    again or, up, is given an address (`ipv6_mc_up`, `ipv6_find_idev`); going, it leaves ff02::1 and, as it forwards,
    ff02::2, and forgets the rest (`ipv6_mc_destroy_dev`). A
    datagram to a group comes back where its device is in the group,
    unless `IPV6_MULTICAST_LOOP` is off, and then with an
    `IPV6_MULTICAST_HOPS` of 0 goes no further; one to a group of the
    interface's scope (ff01::/16) never does (`ip6_finish_output2`).
    Across the pair it comes where the end is in the group
    (`ip6_mc_input`). There it reaches each IPv6 UDP socket of its port
    bound to `::` or the group, not to another device, and connected to
    none or its sender, that is a member of the group, on whatever device,
    or has `IPV6_MULTICAST_ALL` on (`inet6_mc_check`). An accepted
    connection's `IPV6_MULTICAST_HOPS` is 64 (`tcp_v6_syn_recv_sock`).
  - **IPv6 anycast addresses:** an IPv6 socket, TCP's too, joins and
    leaves an anycast address with `IPV6_JOIN_ANYCAST` and
    `IPV6_LEAVE_ANYCAST`, an `ipv6_mreq` (`EINVAL` for less), on the
    device of an index or that of the route to it (0)
    (`ipv6_sock_ac_join`, `ipv6_sock_ac_drop`): `EPERM` without
    `CAP_NET_ADMIN`; `EINVAL` for a multicast address or one of the
    namespace's addresses that is not tentative; `ENODEV` for no device;
    `EADDRNOTAVAIL` for no route, unless `all` forwards, when it is the
    first device up that is no loopback, and, on a device that does not
    forward, for an address of no prefix of the device's addresses; and
    `ENOENT` to leave as none, on the device named, or the newest joined
    on any (0). A device that forwards joins the subnet-router anycast
    address (the prefix) of each of its addresses, but one of 127 bits or
    more: as the address is ready, after its duplicate address detection
    or at once without, and of those not tentative as it comes to
    forward; it leaves it as the address goes, or as it stops
    (`addrconf_join_anycast`, `dev_forward_change`). Each is counted, once
    for each, the newest first (`__ipv6_dev_ac_inc`). Joined anew, it adds
    a route of type `RTN_ANYCAST` to the local table through the device,
    joins its solicited-node group (a loopback does not) and tells
    `RTNLGRP_IPV6_ACADDR` (39) with `RTM_NEWANYCAST`; left for good, it
    leaves the group, its route goes, if there still, and it tells
    `RTM_DELANYCAST` (`inet6_ifacaddr_notify`). Down, the device's routes go, those of
    what sockets joined too, which stay joined without one; going, what
    is left goes without a word (`ipv6_ac_destroy_dev`); a socket's close
    leaves what it joined. `/proc/net/anycast6` (`ac6_seq_show`) shows
    each device's, in the namespace's order, with their users; an
    `RTM_GETANYCAST` dump (`inet6_dump_ifacaddr`), checked as an IPv6
    address dump, gives them by index, as permanent addresses of 128 bits
    (`IFA_ANYCAST`) of the universe's scope, the site's (200) for a
    site-local one, with endless lifetimes (`inet6_fill_ifacaddr`); and
    `ipv6_route` shows their routes with `RTF_ANYCAST`.
  - **Source filters:** a membership takes what its filter lets in: from its
    sources (`MCAST_INCLUDE`) or from all others (`MCAST_EXCLUDE`, of no
    sources as a join leaves it). IPv4's `IP_ADD_SOURCE_MEMBERSHIP`,
    `IP_DROP_SOURCE_MEMBERSHIP`, `IP_BLOCK_SOURCE`, `IP_UNBLOCK_SOURCE` and
    `IP_MSFILTER` (which `getsockopt` reads too) change it, as do
    `MCAST_JOIN_SOURCE_GROUP`, `MCAST_LEAVE_SOURCE_GROUP`,
    `MCAST_BLOCK_SOURCE`, `MCAST_UNBLOCK_SOURCE` and `MCAST_MSFILTER` of
    both families, beside `MCAST_JOIN_GROUP` and `MCAST_LEAVE_GROUP`; TCP
    sockets take them too. A filter with sources stays of its mode
    (`EINVAL`), a source is added once and taken away once
    (`EADDRNOTAVAIL`), there are at most 10 of IPv4's and 64 of IPv6's
    (`ENOBUFS`), and a membership that includes none ends (`ip_mc_source`,
    `ip_mc_msfilter`, `ip6_mc_source`, `ip6_mc_msfilter`). As on Linux
    master, an IPv6 filter whose last blocked source goes may change its
    mode, which Linux 7.0 refuses, as IPv4's still does. A device takes
    from a source what any membership on it includes, or what one that
    excludes does not name (`ip_check_mc_rcu`, `ipv6_chk_mcast_addr`):
    what it does not take reaches no socket, one that has
    `IP_MULTICAST_ALL` or `IPV6_MULTICAST_ALL` on neither, and a sender's
    own copy of it does not come back.
  - **IPv6 across a pair:** a connection or datagram whose IPv6 route (a
    unicast one, or the multicast `ff00::/8`) goes out through an end
    leaves from the route's preferred source, or the address
    `ipv6_dev_get_saddr` picks: of the end's own for a group or a
    link-local destination, else of every device's, none tentative, by
    its rules (the same address, the scope, not deprecated, the outgoing
    device, the label, the longest prefix; a group's scope is its scope
    nibble, and of two that tie the device's newer one wins), and
    `EADDRNOTAVAIL` where none is. It comes to the peer's namespace when the end has its
    carrier, neighbour discovery finds the peer (below), the peer takes
    IPv6 (an MTU of 1280 at least and `disable_ipv6` off), neither address
    is a loopback one (`ip6_rcv_core`), and the destination is an address
    of that namespace, not tentative. There, and back, it goes as IPv4's
    does, with ICMPv6's port unreachable and address unreachable
    (`EHOSTUNREACH`, 3 seconds on), but without reverse path filtering;
    and one from `::1` goes out, to be dropped there. A datagram holds
    65527 bytes at most (`EMSGSIZE`), and TCP takes no group
    (`ENETUNREACH`).
  - **IPv6 of veth ends:** an end up with its carrier is made ready as
    `addrconf_dev_config` does, once until it goes down: the multicast
    route `ff00::/8` (local table, metric 256), then the prefix route
    `fe80::/64` and its link-local address from its Ethernet address
    (EUI-64, `IFAPROT_KERNEL_LL`). Coming up, it first gives the prefix
    route of each permanent address it has. `RTM_NEWADDR` and
    `RTM_DELADDR` add and remove an end's addresses as `lo`'s (below),
    with its prefix route while it is up. A new address is tentative while
    duplicate address detection checks it (unless `IFA_F_NODAD`, or the
    end's and `all`'s `accept_dad` are below 1), which begins once the
    end is up with its carrier and ends 1.5 seconds on; then it is told of
    again, as it is, with its local route; a change while it is checked is
    not told of (`inet6_addr_modify`). A link-local one is told of
    only then. An end with IPv6 off (`disable_ipv6`) or an MTU below 1280
    has none. An end's IPv6 routes but its local ones are
    `RTNH_F_LINKDOWN` while it is up without its carrier, as IPv4's are.
    `RTM_NEWROUTE` adds an IPv6 route through an end
    (`fib6_nh_init`: `ENODEV` for one without IPv6, an MTU below 1280,
    `EACCES` for one with it off, then `ENETDOWN` while it is down), which
    goes with it as it goes down, and with a gateway (`RTA_GATEWAY`) one
    through the end a route to the gateway goes through, as
    `ip6_validate_gw` checks it: `EINVAL` for a local, unspecified or
    multicast gateway, a link-local one without a device or one through
    `lo`, `EHOSTUNREACH` for one no route without a gateway takes or that
    goes through another device; `RTNH_F_ONLINK` takes the gateway to be
    on the named end's link (`ENODEV` without one, `ENETDOWN` while it is
    down). A route with a gateway goes out to the gateway's neighbour
    entry, and a dump, a notification and a lookup give it as
    `RTA_GATEWAY`. Another route with a gateway of the same metric is its
    multipath sibling (`rt6_qualify_for_ecmp`, `fib6_add_rt2node`): it
    goes after the routes of that metric, and is told of with all the hops
    of its route in `RTA_MULTIPATH`, from itself on, without
    `NLM_F_EXCL` and with the request's `NLM_F_APPEND`. A dump tells of a
    multipath route once, its hops in the order they came, and passes over
    a route of the metric without a gateway that came between them
    (`fib6_dump_node`); `RTM_F_FIB_MATCH` gives the hops from the one a
    lookup took. One of the same device and gateway is `EEXIST`, and
    `NLM_F_REPLACE` takes away all of a multipath route's hops but the new
    one. `RTM_DELROUTE` with a gateway removes only a route through it;
    without one, a multipath route goes with all its hops, told of in one
    message (`__ip6_del_rt_siblings`). A request's `RTA_MULTIPATH` adds
    or removes each of its next hops, with the device and gateway each
    names, else the request's, and its weight (`rtnh_hops`, given back in
    dumps), as `ip6_route_multipath_add` and `ip6_route_multipath_del`
    do: none, a gateway shorter than an address, or a hop added without a
    gateway is `EINVAL`, and one twice `EEXIST`; all are checked before any
    goes in, and one message tells of those put in. Where one then fails,
    those put in are told of, then go, each told of. A removal takes each
    hop alone, and gives the last error. A lookup takes the hop the flow's
    hash falls to, each hop living taking a share of the hashes by its
    weight (`fib6_select_path`, `rt6_multipath_rebalance`), by the same
    seed as IPv4's, of what `net.ipv6.fib_multipath_hash_policy` names
    (`rt6_multipath_hash`): the source, the destination, the flow label and
    the protocol (0 and 2); the addresses, the protocol and the ports (1);
    or the fields `fib_multipath_hash_fields` names (3), of the flow
    `RTM_GETROUTE` asks for too; a socket's packets hash as it is bound,
    `::` unbound, with no flow label, and one unbound takes the source of
    the hop that gives (`ip6_dst_lookup_tail`). ICMPv6's port unreachable is
    looked up with the datagram it tells of (`icmp6_send`), hashed as IPv4's
    is: under policy 1 by the flow hash of a connected socket, and under
    policy 3 mixed with no inner hash. An answer goes back by a lookup of its own,
    through whichever end that takes: the one its listener is bound to, or
    to a link-local address the one the packet came in on
    (`inet6_csk_route_req`, `icmp6_send`). Turning `disable_ipv6` on for an end
    takes its IPv6 routes and addresses as going down does; off again,
    while it is up, makes them as coming up does (`dev_disable_change`).
    Going down, it loses its IPv6 routes, told of in the order of a dump,
    but a multipath route's hop, which turns `RTNH_F_DEAD` and
    `RTNH_F_LINKDOWN` without a word, and which lookups pass over until
    the end is ready again (`fib6_ifdown`, `rt6_sync_up`), unless the
    devices of all its route's hops are then down, when all of it goes;
    then its addresses (`addrconf_ifdown`). Going away, it loses what is
    left of them.
  - **Netconf of veth ends:** each end's settings
    are told of in its namespace (`RTNLGRP_IPV4_NETCONF`,
    `RTNLGRP_IPV6_NETCONF`, as `inetdev_init`, `ipv6_add_dev` and their
    undoing tell them): as it comes, `RTM_NEWNETCONF` of all of IPv4's and
    then IPv6's, before its `RTM_NEWLINK`; as it goes, `RTM_DELNETCONF` of
    each, before its `RTM_DELLINK`. An end whose MTU is below 1280 has no
    IPv6, and so only IPv4's. A move tells them gone before the leaving
    namespace's `RTM_NEWNSID` and `RTM_DELLINK`, and the end takes the
    entered namespace's `default` settings, told of there before its
    `RTM_NEWLINK`.
  - **Namespace IDs:** as Linux's `net_namespace.c`, `RTM_NEWNSID` gives
    the network namespace of a process (`NETNSA_PID`, `ESRCH` for none) or
    of a `/proc/<pid>/ns/net` descriptor (`NETNSA_FD`, `EBADF`, or `EINVAL`
    for another file) the ID `NETNSA_NSID`, or with a negative one the
    lowest free; one without either is `EINVAL`, and a namespace that has
    an ID, or an ID taken, `EEXIST`, each with Linux's extended-ack
    message. Telling of a veth end whose peer is in another namespace
    gives that namespace an ID too, the lowest free, as
    `peernet2id_alloc` does, and so does moving one there (veth pairs,
    above). The members of `RTNLGRP_NSID` hear of each new ID
    (`NLM_F_ECHO` sends it to the requester alone of them), and with
    `RTM_DELNSID` of each that goes with its namespace, once no process,
    descriptor or socket holds that, as `unhash_nsid` tells it; the ID is
    free again then. A request names a process or descriptor as its
    sender sees them, whether sent by `send` or by `write`, and
    `CAP_NET_ADMIN` is the writer's as well as the opener's. `RTM_GETNSID`
    answers with the ID of a namespace named by process, descriptor or ID
    (`ENOENT` for an ID none has), -1 for none, and with
    `NETNSA_TARGET_NSID` with the ID that namespace gives it and this
    one's in `NETNSA_CURRENT_NSID` (`EINVAL` for no such namespace,
    `EACCES` without `CAP_NET_ADMIN` over it); its dump lists the IDs in
    order, and strictly may name another namespace by
    `NETNSA_TARGET_NSID` and nothing else, as `rtnl_net_dumpid` does. A
    socket with `NETLINK_LISTEN_ALL_NSID` also hears the notifications of
    each namespace its own has an ID for, when its opener has
    `CAP_NET_BROADCAST` over that namespace, and `recvmsg` gives that ID
    in a `SOL_NETLINK` `NETLINK_LISTEN_ALL_NSID` control message, after
    `NETLINK_PKTINFO`'s, as `do_one_broadcast` and
    `netlink_cmsg_listen_all_nsid` do.
  - **The link:** `RTM_GETLINK` answers with `lo` (index 1), in a dump or
    for its index or `IFLA_IFNAME` (`ENODEV` for another), with Linux
    7.0's attributes in its order: its flags, name, queue, state, MTU,
    queues, segment sizes, carrier, queueing discipline, statistics (left out
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
    past 32, an IPv6 one without `IFA_LOCAL` or `IFA_ADDRESS`, lifetimes
    with no valid one or a preferred one longer, or a message shorter than
    an `ifaddrmsg`; `ENODEV` for another interface; then, for a new IPv6
    one, `EINVAL` for a prefix past 128, or `IFA_F_MANAGETEMPADDR` but on
    a prefix of 64, and `EADDRNOTAVAIL` for `::` or a multicast address
    without `IFA_F_MCAUTOJOIN`. An IPv4 one in the subnet of one of another
    scope is `EINVAL`. An `IFA_LOCAL` of `0.0.0.0` is taken without effect.
    `IFA_LABEL`, `IFA_BROADCAST`, `IFA_FLAGS` (with `IFA_F_NOPREFIXROUTE`,
    and for IPv6 `IFA_F_NODAD`, which tells of the address once; IPv6 keeps
    only the flags a request may set), `IFA_PROTO`, `IFA_RT_PRIORITY`, the
    metric of the address's prefix route, and the lifetimes of
    `IFA_CACHEINFO` are kept. An address with a valid lifetime is not
    `IFA_F_PERMANENT`, one with a preferred lifetime of 0 is
    `IFA_F_DEPRECATED`, and `IFA_CACHEINFO` tells what each has left and
    when the address was made and its lifetimes set. As Linux's checks do
    (`check_lifetime`, `addrconf_verify_rtnl`), an address becomes
    deprecated when its preferred lifetime ends, and goes with its routes
    when its valid one does, on time without a request: a socket that
    binds or sends finds it gone, and a member of the address and route
    groups waiting in `poll`, `epoll` or a read hears of it as it happens.
    An IPv6 prefix route does not run out by itself, as on Linux, whose routes through a loopback
    lose `RTF_EXPIRES` as they are made (`fib6_is_reject`); it takes a
    lifetime (`rta_expires`) when a change gives its permanent address one
    (`modify_prefix_route`), or when an address of its prefix goes while
    the others have lifetimes, and goes when that runs out. With
    `NLM_F_REPLACE` an address
    `lo` has changes, and is told of: IPv4's takes the request's priority
    (none is 0), protocol and lifetimes, IPv6's its flags, protocol and
    lifetimes, and its priority where the request names one, as
    `inet6_addr_modify` does; its prefix route follows. `RTM_DELADDR` removes
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
    goes down, of its priority), its subnet's `broadcast` route and that of
    an `IFA_BROADCAST`; an IPv6 address has a `local` route in the local
    table and, from the first time `lo` is up with it (for one added while
    down, if it is permanent), a unicast prefix route in the main table, of
    its priority or else metric 256, but for `::1`. `RTM_NEWROUTE` adds a route
    through `lo` or a veth end or of a kind without a device (`blackhole`, `unreachable`,
    `prohibit`, `throw`) to any table, with its metric, protocol, scope,
    TOS, preferred source and a gateway (on link too), as
    `inet_rtm_newroute` and `inet6_rtm_newroute` do: `NLM_F_EXCL`,
    `NLM_F_REPLACE`, `NLM_F_APPEND` and `NLM_F_CREATE` put it in Linux's
    place, or Linux's error refuses it (`EEXIST`, `ENOENT`; `EINVAL` for a
    bad prefix, scope, kind, gateway or preferred source, and for an IPv6
    route with `RTA_FLOWLABEL`, `RTA_VIA` or `RTM_F_CLONED`; `ENODEV` for
    another device, for IPv4 one there is not; `ENETDOWN` while its device
    is down, but for an IPv4 route of host scope). `RTM_DELROUTE` removes the first route that matches what it
    names (`ESRCH` for none), a kernel's too, which a change of an address
    or `lo` coming up brings back. Taking `lo` down removes IPv4's routes
    through it but those of host scope, and every IPv6 route. Removing an
    IPv4 address removes the main table's routes from it, and the last one
    of a device every route through that device; removing an IPv6 address removes the first
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
    `EHOSTUNREACH`, `EACCES`), and a socket's connection or datagram it
    takes fails with it too; one an IPv4 unicast route through `lo` takes
    goes out through `lo`, as one from a socket bound to `lo` does, even
    while `lo` is down by one of host scope, which stays
    (`fib_sync_down_dev`). An IPv4 answer names the main table (with
    `RTM_F_LOOKUP_TABLE`, the table it came from), the source
    `fib_select_path` picks, a gateway reached on link, the `RTA_MARK` the
    request names (none for 0), and the caller's
    `RTA_UID` (or the one the request names, as it is; none for -1, and
    `ERANGE` for one shorter than 4 bytes); `0.0.0.0` goes to the loopback
    from 127.0.0.1. An IPv6 answer names the found hop's source: the
    route's preferred one, else the one `ipv6_dev_get_saddr` picks on the
    hop's device (`ip6_route_get_saddr`). Where no route goes it is `ENETUNREACH`, and `AF_UNSPEC`
    `EOPNOTSUPP`; a destination shorter than its family's address is
    `ERANGE` for IPv4 and `EINVAL` for IPv6. With `RTM_F_FIB_MATCH` the
    answer is the table entry that matched (`EHOSTUNREACH` for `0.0.0.0`,
    which none is).
  - **Route lookup selectors:** a lookup takes what else the request names,
    as `ip route get ... from ... oif ... tos ... ipproto ...` sends it,
    as `ip_route_output_key_hash_rcu` and `ip6_route_output` do. An IPv4
    source (`RTA_SRC`) must be the loopback's (`ENETUNREACH`; `EINVAL` for
    a multicast or broadcast one), and the answer names it as `RTA_SRC`
    instead of the `RTA_PREFSRC` it would pick. An output device
    (`RTA_OIF`) is `ENODEV` but for `lo` and `ENETUNREACH` while it is
    down; where the tables give no route or an error, an IPv4 destination
    is taken to be on link through it (of no table, which
    `RTM_F_FIB_MATCH` makes `EHOSTUNREACH`), and `0.0.0.0` leaves from the
    address of host scope it picks. The IPv4 tables match a route's TOS
    against the request's legacy TOS bits, and the answer gives the TOS of
    the route that matched. An IPv4 answer for a multicast or the limited
    broadcast address is of the multicast or broadcast type, as
    `__mkroute_output` makes it (`RTCF_MULTICAST` or `RTCF_BROADCAST`, and
    `RTCF_LOCAL` for the broadcast address and a group the device is in and
    takes that source's packets to),
    and with `RTM_F_FIB_MATCH` the table's
    entry takes that type too; from a source of the loopback's and no
    device, and through `lo` to a local group (224.0.0.0/24) or the
    broadcast address, it is made with no table looked in (of TOS 0 and no
    table, and `EHOSTUNREACH` with `RTM_F_FIB_MATCH`), from an address of
    link scope where no source is named. An IPv6 answer gives the
    request's source as `RTA_SRC`, and an output device but `lo` finds no
    route (`ENETUNREACH`) without a source, or to a loopback, link-local
    or multicast address. `RTA_IP_PROTO` is `EOPNOTSUPP` but for TCP, UDP
    and the family's ICMP, and `RTA_IIF` is `ENODEV` for a device there is
    not. With `RTA_IIF` of `lo` or a veth end, a route is
    looked up as a packet coming in on that device would take it
    (`ip_route_input_slow`, `ip6_route_input_lookup`), and the answer names
    the device as `RTA_IIF`. IPv4 drops martians
    (`EINVAL`): a multicast, limited broadcast, loopback or 0.0.0.0
    source, a loopback or 0.0.0.0 destination, a group the device has not
    joined or whose source its filters keep out, and a source of the namespace's own, or with a local route a
    request added, one a lookup finds a route to that is not unicast
    (`fib_validate_source`). A local, broadcast or multicast destination
    gives a local route of that type (`RTCF_LOCAL`, `RTCF_BROADCAST`,
    `RTCF_MULTICAST`), of the TOS of the route that matched and without a
    preferred source; it goes out through `lo` (`RTA_OIF`). Anything else
    would be forwarded: with the device's `forwarding` off (`/proc/sys/net`), it is `EHOSTUNREACH`; on, a
    destination no route takes gives the lookup's error, a route of a
    kind other than unicast `EINVAL`, and a unicast one the route it is
    forwarded on (`__mkroute_input`): unicast, out through the route's
    device (`RTA_OIF`), with the route's gateway and metrics, and, out
    through the device it came in on, `RTCF_DOREDIRECT` where the source's
    own route is a unicast one through that device without a gateway, as a
    packet that goes out where it came in asks to redirect. Reverse path
    filtering (`rp_filter`, `all`'s or the device's, the larger) checks every
    source by a lookup of it (`__fib_validate_source`): with it on, a
    source no route takes is dropped too, and so, strictly, is one whose
    route goes through another device than the one it came in on while
    that has an address; loosely, a lookup of it through that device
    decides. IPv6 gives the route the
    tables do, whatever its source and its `forwarding`, through the
    device it came in on only for a loopback, link-local or multicast
    destination (`rt6_need_strict`), and the route's gateway and device;
    a local one goes out through `lo`. A multicast one is `EMSGSIZE`, as
    Linux's multicast routing knows no device of the reply it fills
    (`ip6mr_get_route`). The source, the flow label (`RTA_FLOWLABEL`)
    and the protocol choose among an IPv6 multipath route's hops, as
    `fib6_select_path` hashes them, and the source among an IPv4 one's, as
    `fib_select_path` does, for an input route by the hash alone; the
    mark, the user ID and the ports choose among policy rules, which
    there are none of, so they change nothing.
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
    shorter than 4, whose lookups drop them with the route's gateway); an IPv4 removal that
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
  - **Neighbours:** `RTM_GETNEIGH` dumps the neighbours of the loopback
    and the veth ends (those traffic makes, as the notifications and the
    veth ends' neighbours below tell, and those requests add) as
    `neigh_dump_info` does, each an `RTM_NEWNEIGH` like the `RTM_DELNEIGH`
    that tells of it as it goes: ARP's (IPv4's) and then neighbour
    discovery's (IPv6's) for `AF_UNSPEC`, the one family's for `AF_INET`
    or `AF_INET6`, and none for another family. An `ndmsg` whose flags
    are `NTF_PROXY` asks for the proxy entries instead, in the order of
    their hash's buckets (`pneigh_hash`), the newest first in each.
    `NDA_IFINDEX` and `NDA_MASTER` narrow a dump, and mark each message
    `NLM_F_DUMP_FILTERED`: a device's index keeps its neighbours alone, a
    master of -1 (no master) keeps them all (and of the proxy entries,
    `lo`'s alone for its index), and any other master shows none. Strictly, as
    `neigh_valid_dump_req` checks, an `ndmsg` that is short or has
    padding, an index, a state, a type or a flag but `NTF_PROXY`, and any
    other attribute, are `EINVAL`; unchecked, a dump whose attributes
    break `nda_policy` is not narrowed. An `AF_MCTP` dump shows no
    neighbours (`EINVAL` for a short `ndmsg`, as `mctp_rtm_getneigh`).
    Without a dump, as `neigh_get`, the request names one neighbour by its
    family, key (`NDA_DST`) and its device's index, and the answer counts the
    reference the lookup holds. It is `EINVAL` without the key (told of
    with `NLMSGERR_ATTR_MISS_TYPE`), with another attribute, a key of
    another length, no device, or padding, a state, a type or a flag but
    `NTF_PROXY`; `EAFNOSUPPORT` for a family but IPv4's and IPv6's;
    `ENODEV` for a device the namespace has not; `EOPNOTSUPP` for a proxy
    entry of a veth end; and `ENOENT` for a neighbour
    the device has not, and for a proxy entry neither for the device asked
    nor for none.
  - **Neighbour changes:** `RTM_NEWNEIGH` adds or changes one of the
    neighbours of `lo` or of a veth end (below) and `RTM_DELNEIGH` removes
    one, as `neigh_add` and
    `neigh_delete` do, with `CAP_NET_ADMIN`. They check in Linux's order:
    `nda_policy`, not strictly, for an addition, and a short `ndmsg`; no
    `NDA_DST` (`EINVAL`); a device the namespace has not (`ENODEV`), and
    to add, a link-layer address shorter than the device's six bytes
    (`EINVAL`); a family but IPv4's and IPv6's (`EAFNOSUPPORT`); a key
    shorter than the family's (`EINVAL`); and for a veth end, a proxy
    entry (`EOPNOTSUPP`). An IPv6 neighbour is made only on a device with
    IPv6 (`ndisc_constructor`: `EINVAL` for a veth end whose MTU is below
    1280). IPv4's neighbour of a loopback is keyed by `0.0.0.0`
    whatever is asked, as `arp_constructor` keys it: a request for another
    key makes or changes that one with `NLM_F_CREATE` (`ENOENT` without),
    and removing it is `ENOENT`. An existing one with `NLM_F_EXCL` is
    `EEXIST`, and without `NLM_F_REPLACE` keeps its link-layer address and
    `NTF_ROUTER`. A neighbour is made `NUD_NOARP` with `lo`'s address, then
    changed as `__neigh_update` does: its `NTF_EXT_LEARNED`,
    `NTF_EXT_MANAGED` and `NTF_EXT_VALIDATED` become the request's; an
    invalid state is taken as it is and drops the address; a valid one
    takes the address given, or needs the one it has (`EINVAL`); and each
    change is told to `RTNLGRP_NEIGH` with the requester's port.
    `NTF_USE` and `NTF_MANAGED` take away `NUD_PERMANENT` alone, then use
    it (`neigh_event_send`). A reachable neighbour's timer runs as
    `neigh_timer_handler`: past the reachable time (30 seconds) since it
    was confirmed, it delays if it was used within the 5 seconds before,
    else goes stale and is told of to `RTNLGRP_NEIGH` without a port. A
    permanent neighbour `NTF_EXT_MANAGED`, and one `NTF_EXT_VALIDATED` in
    an invalid state, are `EINVAL`. A removal
    fails the neighbour (`NUD_FAILED`, told of if it was valid), then
    tells it gone with `RTM_DELNEIGH`. With `NTF_PROXY` a request adds,
    changes or removes a proxy entry instead, of `lo` or of no device
    (IPv6's need `lo`, `ENOBUFS`), with the flags and protocol it gives, and
    tells nothing; `NTF_EXT_MANAGED` or `NTF_EXT_VALIDATED` with it is
    `EINVAL`. One is found for `lo` or for no device to change, and only
    for its own device to remove (`ENOENT`). Without `NTF_PROXY`, a request
    without a device is `EINVAL`. `lo` going down takes its neighbours and
    proxy entries, as `neigh_ifdown` does, but not those of no device.
  - **Neighbours of veth ends:** a veth end has IPv4's neighbours,
    resolved by ARP as `arp_constructor`, `neigh_event_send`,
    `arp_process` and `neigh_timer_handler` do, and IPv6's, resolved by
    neighbour discovery as `ndisc_constructor`, `ndisc_solicit`,
    `ndisc_recv_ns` and `ndisc_recv_na` do (below). Each is keyed by the
    address asked, of the type `inet_addr_type` gives that address as it
    is made (`RTN_BROADCAST` while the namespace has no local table): a
    group's is `NUD_NOARP` with the group's Ethernet address
    (`ip_eth_mc_map`), a broadcast address's `NUD_NOARP` with the
    broadcast one, and any other `NUD_NONE`, as a request that then fails
    leaves it. A packet out through an end, of TCP's handshake, UDP or
    ICMP's port unreachable back, takes its next hop's neighbour: a valid
    one's address, which the peer takes only if it is its own; a stale one
    delays; any other asks ARP, its unicast probes (3) and first probe
    counted, and is reachable at once at the peer's address when the
    peer answers, while the peer learns the sender, stale at its address
    (`neigh_event_ns`); unanswered, it is incomplete and fails 3 seconds
    later, its 6 probes sent. A delaying one probes 5 seconds on
    (`NUD_PROBE`) and is reachable once the peer answers, or fails after 3
    probes. Each of these changes but to incomplete and to delaying is
    told to `RTNLGRP_NEIGH`, the timers' as a netlink socket of the
    namespace next reads, polls or writes. A request with `NTF_USE` or
    `NTF_MANAGED` asks ARP as a packet does, from the address
    `inet_select_addr` picks on the end (`arp_solicit`). IPv6's go the
    same way, with neighbour discovery's timers (the same probes and
    times), but: a unicast one's type is `RTN_UNICAST` and a group's
    neighbour has its `33:33` Ethernet address (`ndisc_mc_map`); the
    solicitation leaves from the packet's source if the end has it, not
    tentative, else from the end's link-local address (`ipv6_get_lladdr`),
    and without one none goes; it goes to the target's solicited-node
    group, whose neighbour it makes; the peer answers only for an address
    of its own end, not tentative (`ndisc_recv_ns`); and its advertisement
    goes back through the neighbour it learns, which so delays at once. A
    request with `NTF_USE` or `NTF_MANAGED` solicits from the end's
    link-local address. What IPv6 sends of itself makes the neighbour of
    the group it goes to, `NUD_NOARP` and without a word, on `lo` as on a
    veth end: an MLDv2 report to ff02::16 as a device up joins anew or
    leaves for good a group it reports (not ff02::1, nor one of a scope
    below the link's: `MAF_NOREPORT`), and of its groups as its IPv6 comes
    up, has its carrier again while ready, or is given an address
    (`ipv6_mc_up`); duplicate address detection's probe to the address's
    solicited-node group, half a second after it begins
    (`addrconf_dad_work`); and, as the detection of a veth end's only
    link-local address ends, a report again (`ipv6_mc_dad_complete`) and,
    unless the end forwards, a router solicitation to ff02::2
    (`addrconf_dad_completed`), from that address with the end's own
    Ethernet address (`ndisc_send_rs`): a peer that forwards learns of its
    sender as `ndisc_recv_rs` does, the neighbour of that address made, or
    changed, stale at the Ethernet address, and no router (`NTF_ROUTER`
    goes), told of with `RTM_NEWNEIGH`; one that does not takes no
    notice. IGMPv3's report to 224.0.0.22 (`IGMPV3_ALL_MCR`) makes its
    neighbour so too, on `lo` that of 0.0.0.0 as every IPv4 one there: as
    a device up joins a group anew, leaves one for good or changes a
    filter's sources, and of its groups as it comes up, but for the
    all-hosts group (`igmp_group_added`, `igmp_group_dropped`,
    `ip_mc_up`), its carrier or not; a device down has no route to report
    on (`ENETUNREACH`). An end going down takes its
    neighbours, each told of with `RTM_DELNEIGH` after its
    `RTM_NEWLINK`, IPv4's, then IPv6's; its peer losing its carrier, all
    but the permanent ones (`neigh_carrier_down`); and an end that goes or
    moves away, all.
  - **Neighbour tables:** an `RTM_GETNEIGHTBL` dump, as
    `neightbl_dump_info`, gives each table the family names (ARP's and
    neighbour discovery's for `AF_UNSPEC`, none for another family) with
    its name, garbage collection's interval and thresholds, its
    configuration, statistics and default parameters, then each device's
    parameters, the newest first, which count its neighbours' references:
    ARP's of the veth ends and `lo` (`inetdev_init`), neighbour
    discovery's of `lo` and the ends with IPv6 (`ipv6_add_dev`). Strictly, an
    `ndtmsg` short, with padding or with attributes after it is `EINVAL`
    (`neightbl_valid_dump_info`).
  - **Multicast groups:** an `RTM_GETMULTICAST` dump of `AF_INET`, as
    `inet_dump_ifmcaddr`, gives the IPv4 groups of each device, by index,
    each's the newest first, in messages of that type: a permanent
    address of 32 bits and the universe's scope, the group
    (`IFA_MULTICAST`), its users (`IFA_MC_USERS`, of Linux master; 7.0's
    has none) and endless lifetimes from when the device joined it
    (`inet_fill_ifmcaddr`). Its request is checked as an address dump's: a
    device it names is `ENODEV` for none and marks the messages
    `NLM_F_DUMP_FILTERED`, and a namespace it names (`IFA_TARGET_NETNSID`)
    shows its groups without the ID. `NLMSG_DONE` comes in the last
    messages' read. A device that joins a group anew, or leaves it for
    good, tells `RTNLGRP_IPV4_MCADDR` (37) with `RTM_NEWMULTICAST` or
    `RTM_DELMULTICAST` (`inet_ifmcaddr_notify`): as a socket's membership
    is its first or its last, with a source filter's first source and
    last too; and the all-hosts group as the device comes up, after
    `lo`'s address and before the routes (`ip_mc_up`), and as it goes
    down, before the routes and neighbours go, closes, or goes
    (`ip_mc_down`, `ip_mc_destroy_dev`), which forgets the rest unsaid.
    One of `AF_INET6`, as `inet6_dump_ifmcaddr`, gives the IPv6 groups of
    each device with IPv6 alike, of 128 bits and site scope (200) for a
    group of that scope (ff?5::), a named namespace's with its ID first
    (`inet6_fill_ifmcaddr`). Each IPv6 group joined anew or left for good,
    a device's own too, is told to `RTNLGRP_IPV6_MCADDR` (38)
    (`inet6_ifmcaddr_notify`), of the universe's scope: a new device's
    all-nodes groups before its `RTM_NEWLINK`, and as it goes, after its
    IPv4 settings and before its IPv6 ones; an address's solicited-node
    group as the request that adds or removes the address is done, which
    Linux joins by its work shortly after.
  - **Notifications:** a socket is a member of the groups `bind` names
    (they replace its first 32) and those `NETLINK_ADD_MEMBERSHIP` adds,
    of `RTNLGRP_*` 1 to 39 (`EINVAL` for 0 or one past them; the
    multicast routing groups 30 and 31 need the caller's `CAP_NET_ADMIN`,
    `EPERM`);
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
    `RTNLGRP_NEIGH` hears of the loopback's neighbours as requests change
    them (above) and as they go: a UDP
    datagram through `lo` (and ICMP's port unreachable back from a port
    where nothing listens) and a TCP handshake's first segment (and its
    answer back) make one for the next hop, silently, as
    `___neigh_create` does, IPv4's one keyed by `0.0.0.0`
    (`RTN_BROADCAST`), IPv6's one each (`RTN_LOCAL`), all `NUD_NOARP`;
    each is told of with `RTM_DELNEIGH`, the newest first, when `lo` goes
    down (IPv4's after `RTM_NEWLINK`, IPv6's after its routes and before
    its addresses, as `fib_disable_ip` and `rt6_disable_ip` flush them) and
    IPv4's when it loses its last IPv4 address. No netconf notification
    (`RTNLGRP_IPV4_NETCONF`, `RTNLGRP_IPV6_NETCONF`) comes of `lo`'s
    changes, as on Linux, which sends one only as a device comes or goes
    (veth pairs, above) or a setting in `/proc/sys/net` changes (below).
    Each is a `netconfmsg` with its family, `NETCONFA_IFINDEX` (-1 for
    `all`, -2 for `default`) and the settings told of, of port and
    sequence number 0: for a device that comes, IPv4's forwarding,
    reverse path filter, multicast and broadcast forwarding, proxy ARP and
    ignoring routes with their link down, and IPv6's forwarding,
    multicast forwarding, proxy NDP and the last, as
    `inet_netconf_fill_devconf` and `inet6_netconf_fill_devconf` (of a
    kernel with `CONFIG_IPV6_MROUTE`) give them.

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
    `ESTALE` for a cookie that does not match; each as what comes in on
    the device asked for (`idiag_if`) finds it, so never a socket bound to
    another. The old `TCPDIAG_GETSOCK`
    does the same for TCP of both families, and `SOCK_DESTROY` is
    `EOPNOTSUPP`, as in a kernel built without
    `CONFIG_INET_DIAG_DESTROY`. A request too short is `EINVAL`.
  - **What it tells of TCP and UDP:** each socket's state (`TCP_SYN_SENT`
    while a handshake waits for room in its listener, then that of the
    connection's end, or `TCP_LISTEN`), its addresses and ports (IPv4 ones
    mapped on an IPv6 socket), the device it is bound to, its cookie, its timer (a handshake's
    retransmission, keepalive, or `TIME_WAIT`'s), its queues (a listener's
    waiting connections and backlog), its owner as the user namespace of
    whoever made the netlink socket shows it, and its inode (0 for a
    connection not yet accepted); then, in `inet_sk_diag_fill`'s order,
    its shutdown, as `idiag_ext` asks its `IP_TOS`, an IPv6 socket's
    traffic class, and while listening or closed its `IPV6_V6ONLY`, its
    mark to `CAP_NET_ADMIN`, its priority as its class, its cgroup, its
    options (`inet_diag_sockopt`), its memory (a UDP socket's datagrams
    charged in pages, as `udp_rmem_schedule` does, its buffers, a UDP
    socket's datagrams that its filter or its full buffer dropped, and a
    listener's handshakes that a full queue dropped), a TCP socket's
    `tcp_info` (`INET_DIAG_INFO`, which `ss -i` shows), and its
    congestion control (`cubic`). A hold in `TIME_WAIT` tells
    its addresses, device, state and timer alone.
  - **Groups:** a socket has 32 groups, as Linux makes the four of
    `sock_diag` 32, which anyone may join, and which hear nothing.

- An MCTP socket (`AF_MCTP`, `SOCK_DGRAM` and protocol 0: `EPROTONOSUPPORT`
  for another protocol, then `ESOCKTNOSUPPORT` for another type) sends and
  receives messages between the MCTP endpoint IDs of its network
  namespace's loopback, as Linux 7.0's `af_mctp` does on a kernel built with
  `CONFIG_MCTP`.
  - **Binds:** `bind` takes a `sockaddr_mctp` (`EINVAL` for a short one or
    one with padding, `EAFNOSUPPORT` for another family, `EACCES` without
    `CAP_NET_BIND_SERVICE`): a message type, its integrity check bit left
    out, a local endpoint ID or `MCTP_ADDR_ANY`, and a network, the default
    one (1) for `MCTP_NET_ANY` with an ID. No two sockets bind alike, and a
    socket binds once (`EADDRINUSE`). A `connect` before it names the peer
    and type the bind takes (`EINVAL` for a length other than 12, a tag or
    the integrity check bit, and for a bind of another type or network;
    `EADDRINUSE` after a bind or a connect).
  - **Sending:** `sendto` and `sendmsg` need an address (`EDESTADDRREQ`, as
    a `write` has none) that is whole, without padding, and with no tag
    bits but the tag, `MCTP_TAG_OWNER` and `MCTP_TAG_PREALLOC`, the last
    with the owner bit (`EINVAL`); and `CAP_NET_RAW` (`EACCES`). The
    message, its type first, goes through the route to its endpoint ID, as
    `mctp_route_lookup` follows gateways to a local route (`EHOSTUNREACH`
    for none), from the loopback's first MCTP address, in packets of the
    least MTU on the way, each taken in at once (`mctp_dst_input`), whose
    error is the send's: `ENOENT` where no key or bind takes it, `ENOMEM`
    for a full receive buffer (which counts each packet's `truesize`, as
    Linux's does), and `EINVAL` for a message past 64 KiB, which no key
    reassembles. One too long for a buffer (`kmalloc`'s 4 MiB) is
    `ENOBUFS`.
  - **Receiving:** a message goes to the socket of the key its tag and
    addresses match, or, at the start of one whose tag its sender owns, to
    the bind of its type, in Linux's order: of its destination and source,
    of its source, of its destination, of any address in its network, then
    of any network. `recvfrom` and `recvmsg` give its bytes and a
    `sockaddr_mctp` of its network, source, type and tag, and take
    `MSG_PEEK`, `MSG_TRUNC` and `MSG_DONTWAIT` alone (`EOPNOTSUPP`).
  - **Tags:** a send with `MCTP_TAG_OWNER` takes the lowest tag no key for
    its peer has (`EBUSY` when all eight are taken), whose key stays six
    seconds or until the answer comes with it. `SIOCMCTPALLOCTAG` and
    `SIOCMCTPALLOCTAG2` make one by hand (`EINVAL` for a request with a
    tag, flags or a local ID), which a send with `MCTP_TAG_PREALLOC` uses
    (`ENOENT` for one not made), and which stays until `SIOCMCTPDROPTAG` or
    `SIOCMCTPDROPTAG2` drops it (`EINVAL` for none). Every other `ioctl`
    of the socket's own is `EINVAL`, `FIONREAD` too.
  - **Hardware addresses:** with `MCTP_OPT_ADDR_EXT` (`SOL_MCTP`, an `int`
    exactly, else `EINVAL`), a `sockaddr_mctp_ext` sends out of the
    loopback by its index and hardware address (`ENOENT` for another index,
    `EINVAL` for an address of other than six bytes, or padding). The send
    succeeds and the message is lost, as on Linux: while the loopback is
    down its `noop` queueing discipline drops it, and while it is up it
    comes back in, but `eth_type_trans` takes `ETH_P_MCTP` (0xfa), below
    `ETH_P_802_3_MIN`, for an 802.3 length, so the frame goes to 802.2 and
    never to MCTP. A socket with the option names, in a message it
    receives, the interface it came in by, which is 0, none.
  - **Others:** `getsockname`, `getpeername`, `listen`, `accept`,
    `shutdown` and `socketpair` are `EOPNOTSUPP`; `setsockopt` and
    `getsockopt` of a level but `SOL_SOCKET` and `SOL_MCTP` are `EINVAL`.

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
  and filesystem user and group IDs, the supplementary groups, the
  permitted, effective, inheritable, bounding and ambient capabilities and
  the securebits.
  `capget` reads any thread's capabilities in all three header versions, and
  `capset` changes the calling thread's, within what it holds by Linux's rules
  (an inheritable one also within the bounding set), and keeps the ambient
  set within the new permitted and inheritable ones.
  The `set*id` calls and `setgroups` change them by Linux's rules: an ID
  goes to one of the thread's own, or anywhere with `CAP_SETUID` or
  `CAP_SETGID`; unless `SECBIT_NO_SETUID_FIXUP`, leaving root in every
  user ID drops the capabilities (but for the permitted ones with
  `PR_SET_KEEPCAPS`) and the ambient ones, the effective ID leaving root
  drops the effective ones and coming back raises them, and the filesystem
  ID does the same for the filesystem capabilities. A change of
  an effective or filesystem ID makes the process undumpable
  (`fs.suid_dumpable` is 0) and clears its parent-death signal. `execve`
  of a set-user-ID program makes its owner the effective user ID, and of a
  set-group-ID program its group the effective group ID when the group may
  execute it. With `PR_SET_NO_NEW_PRIVS` it ignores those bits, and an exec
  that would still change the effective IDs (to an effective group the
  thread is not in by its filesystem or a supplementary group) or gain
  capabilities takes the real IDs as effective and keeps no more
  capabilities than the thread had. `execve` then makes the saved and
  filesystem IDs the effective ones and gives the capabilities as Linux's
  `cap_bprm_creds_from_file` does:
  - **File capabilities:** a program's `security.capability` gives its
    permitted ones within the bounding set and its inheritable ones within
    the thread's, effective too when its effective flag is set. A revision 3
    value counts only where its root is root in the thread's user namespace
    or one above it. A value of no known revision, or one whose effective
    flag is set and whose permitted capabilities the bounding set does not
    all allow, refuses the exec (`EINVAL`, `EPERM`), after the program and
    its interpreter are read.
  - **Root:** unless `SECBIT_NOROOT`, root (by its real or effective ID)
    gets the bounding and inheritable sets, effective by its effective ID,
    but not a set-user-ID root program with file capabilities that another
    user runs.
  - **Ambient:** file capabilities or a change of the effective IDs clear
    the ambient set; what stays of it is permitted and effective.
  - It clears `PR_SET_KEEPCAPS` and keeps the other securebits, the bounding
    set and the inheritable set.

  It sets `AT_SECURE` when it changes the effective IDs, when they differ
  from the real ones before it, or when a user other than root takes the
  effective flag or permitted capabilities beyond its ambient ones, and
  such a secure exec
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

- Each program gets a vDSO at `execve`, as Linux's `map_vdso` maps it on
  x86-64: `[vvar]` (4 pages), `[vvar_vclock]` (2 pages) and `[vdso]` (2
  pages), together where the next mapping without an address goes (below
  the program's and its interpreter's), private, of no file, and
  `AT_SYSINFO_EHDR`, first in the auxiliary vector, names `[vdso]`'s start.
  `[vdso]` is `linux-vdso.so.1`, an `ET_DYN` object whose functions
  `__vdso_clock_gettime`, `__vdso_gettimeofday`, `__vdso_time`,
  `__vdso_getcpu` and `__vdso_clock_getres`, and their weak aliases without
  the prefix, of version `LINUX_2.6`, a C library finds through its
  dynamic symbols; each makes its system call. `[vvar]` and
  `[vvar_vclock]` are `VM_IO | VM_PFNMAP`: their pages may not be made
  writable (`EACCES`) or reached through `get_user_pages`
  (`process_vm_readv` `EFAULT`, `PTRACE_PEEKDATA` and `/proc/<pid>/mem`
  `EIO`), `MADV_DONTNEED` is `EINVAL` on them, `[vvar]`'s pages 1 and 3 and
  `[vvar_vclock]`'s are a bus error (`BUS_ADRERR`), and its pages 0 and 2
  read as zeros. `[vdso]` may be made writable, which copies it (so does a
  write through `/proc/<pid>/mem`), and moved by `mremap`, but not grown
  (`EFAULT`). None of the three is split: an `munmap`, `mprotect`, `mremap`,
  `mseal` or the like of a part of one that would split it is `EINVAL`.
  `statm` counts the three, a `fork` keeps them where they are, and a core
  holds them whole, as Linux's `always_dump_vma` dumps a special mapping.

- The `vsyscall` page is Linux's default (`CONFIG_LEGACY_VSYSCALL_XONLY`):
  a gate area at `ffffffffff600000`, no mapping of the process, which is the
  last line of `maps` and `smaps` (`--xp`, `VmFlags: ex`) and the last
  segment of a core (zeros), and which `statm` and `smaps_rollup` leave
  out. It can be run but not read (`SIGSEGV`, `SEGV_MAPERR`). Its
  entries `+0x000` (`gettimeofday`), `+0x400` (`time`) and `+0x800`
  (`getcpu`) do what `emulate_vsyscall` does: seccomp sees the call with the
  entry's address, and a tracer its `PTRACE_EVENT_SECCOMP`, but no system
  call's stop is made; then the result is in `rax` and the thread at its
  caller, with no other register changed. A tracer that changes the call's
  number there, or moves the thread, ends it with `SIGSYS`, whose action is
  then left at its default and `SA_IMMUTABLE` (`force_exit_sig`). Any other
  address there, a stack that cannot be read and a pointer the call cannot
  write are `SIGSEGV` from the kernel (`SI_KERNEL`); a pointer past user
  space is `SEGV_MAPERR` at it. Reads from outside give `EFAULT`
  (`process_vm_readv`) and `EIO` (`/proc/<pid>/mem`, `PTRACE_PEEKDATA`).

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
  program is `ELIBBAD`. A program file cut short loads as Linux's binfmt_elf
  takes it: a short header or program headers past the end of the file are
  `ENOEXEC` and an interpreter path past it `EIO`, while segments past the
  end are mapped, and a page wholly past it raises `SIGBUS` when touched. A
  writable segment whose bss starts in such a page cannot be cleared
  (`padzero`), so the exec fails after its point of no return and the
  process ends by `SIGSEGV`. A file that starts with `#!` runs its
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
  host filesystem's own numbers. `/proc/self/mountinfo` and `/proc/self/mounts`
  list the mounts of the caller's mount namespace, and so does `/proc/mounts`,
  a symbolic link to `self/mounts` (0777, of size 11), as on Linux
  (`tmpfs` for the root, `hostfs` for each `--mount`, without host paths,
  `proc` for `/proc`, `devtmpfs` for `/dev` and the tmpfs on `/dev/shm`
  from start-up,
  and the tmpfs and bind mounts `mount` made, with their sources and, in
  `mountinfo`, the directory each shows as its root, whether the mount
  and its superblock are read-only, and its propagation). After `chroot` they show each mount point
  from the process's root and leave out those not under it, as Linux's
  `seq_path_root` does. `/proc/<pid>/mountinfo` and `mounts` (and those of
  `/proc/thread-self` and `/proc/<pid>/task/<tid>`) are those of that task,
  as Linux's `mounts_open_common` makes them: the mounts of its mount
  namespace, from its root, for any reader, of the namespace and root the
  open took, as they are at each read; a process that has ended,
  until it is reaped, has them, but they open as `EINVAL`, and so do a
  process's when its leader ended before its other threads, whose own
  under `task/<tid>` still open. Each file system has its own `st_dev`, as
  its mounts' lines in `mountinfo` say, so `df` lists every file system. A
  bind mount shares its source's `st_dev`, as in Linux, so `df` leaves it
  out once it has listed that device. A pipe, a socket, a
  pidfd, a memfd, a `memfd_secret` file, a namespace file and an anonymous
  inode (an eventfd, an epoll and the like) that no path opened are each on
  a device of their file system's own (pipefs, sockfs, pidfs, the internal
  tmpfs, secretmem, nsfs, anon_inodefs), as on Linux, none of them a
  mount's. A fifo opened by its name is a file of the file system that
  holds it, and `fstatfs` gives that one, after the name is removed too.
  `ustat` of a mount's `st_dev` gives its free blocks and inodes,
  of one of those devices none (0, as Linux's `simple_statfs` and the
  internal tmpfs, which has no limits, give), and of any other device
  `EINVAL`.

- A file's block size (`st_blksize`, `stx_blksize`, `FIGETBSZ`) is its
  filesystem's, as on Linux: 1024 for `/proc` (procfs), a pseudo-terminal's
  slave and a terminal on standard input, output or error (devpts), and 4096
  for the rest,
  pipes, sockets, `memfd` and `/dev` included. `statfs` there gives
  procfs's, devpts's or (for the rest of `/dev`, a devtmpfs) tmpfs's type with a 4096 `f_bsize`, as Linux's
  `simple_statfs` does. A namespace's link in `/proc/<pid>/ns` leads to its
  nsfs file, which `statfs` and `fstatfs` give as nsfs's (`NSFS_MAGIC`).
  A link in `/proc/self/fd` is procfs's, but a call
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
  `ENOENT`, and a file that is not a directory `ENOTDIR`. So is a link in
  another process's `fd` (`/proc/<pid>/fd/3/name`), for a reader that may
  look at its descriptors (`EACCES`), as Linux's `proc_fd_link` jumps;
  once the process has ended, it is `ENOENT`. The file calls
  that take an absolute path do this (`openat2` with `RESOLVE_*` flags in its
  own walk), and so does `execve` (`/proc/self/fd/3/program` runs `program`
  in the directory descriptor 3 holds); a path relative to a descriptor of
  `/proc` or to a working directory there, one whose `..` or symbolic link
  leads into `/proc`, and a Unix socket's address do not.

- The other `/proc` entries are `/proc/cpuinfo` (below), `/proc/loadavg`, `/proc/locks` (above),
  `/proc/meminfo`, `/proc/stat`, `/proc/uptime`, `/proc/version` and the other system files (below), `/proc/net` and `/proc/sysvipc` (below), `/proc/sys` with only
  `fs`, `kernel`, `net` and `vm` in it (below), a directory per process, and this process's own: `/proc/<pid>`, a
  directory its entries can be opened relative to and that lists them, and `/proc/self`, a
  symbolic link to it (0777, size 0) that `readlink` resolves to the PID:
  `lstat`, and `fstatat` or `statx` with `AT_SYMLINK_NOFOLLOW`, give the
  link, `stat` and a trailing slash follow it, `O_NOFOLLOW` does not
  (`ELOOP`), and `O_PATH | O_NOFOLLOW` opens the link itself, which reads
  as the PID of the process reading it and names itself `/proc/self`; then
  `/proc/self/status`, `stat`, `statm`, `cmdline`, `environ`, `auxv`,
  `limits`, `personality`, `comm`, `syscall`, `exe`, `cwd`, `root`, `maps`, `mem`, `mounts`, `mountinfo`,
  `clear_refs`, `smaps`, `smaps_rollup`, `pagemap`, `wchan`, `cgroup`, `oom_score`, `oom_adj`,
  `oom_score_adj`, `loginuid`, `sessionid`, `coredump_filter`, `io`, `uid_map`, `gid_map`,
  `projid_map`, `setgroups`, `timerslack_ns`, `fd`, `fdinfo`, `ns` and `task`. They are owned by the process's
  effective user and group, or by root once it is not dumpable (after a
  change of its IDs, until `PR_SET_DUMPABLE`), as Linux's `task_dump_owner`
  gives them: root of the user namespace its program runs in, or the first
  one's where that namespace maps no root; the directory, `task` and `fdinfo` (0555) are the process's
  either way, and `/proc/self` itself is root's. `stat` shows that owner and
  the mode, 0400 for `environ`, `auxv`, `pagemap`, `io`, `personality` and `syscall`, 0644 for `comm`, 0600 for
  `mem`, 0200 for `clear_refs` and 0444 for the other files.
  `fstat` of an open file shows its owner as of the last lookup of its path
  (an open, a `stat`, by any process), as Linux's inode, which each lookup
  of the path an open file pins brings up to date (`pid_revalidate`); of
  the open directory and its `ns`, the owner at that moment, as Linux's
  `pid_getattr` asks it. An open checks the mode for that owner, as Linux's
  `generic_permission` does, so opening one for writing is `EACCES` without
  `CAP_DAC_OVERRIDE`, and so is reading `environ`, `auxv`, `pagemap` or `mem` once the
  process is not dumpable; a write to one opened for writing (root's) is
  `EINVAL`, but to `comm`, which renames the thread as Linux's
  `comm_write` does: to its first 15 bytes, up to a NUL, taking the whole
  count, when the writer is of the thread's process (the thread takes
  the name at its next system call; `/proc` shows it at once), `EINVAL`
  from another process and `ESRCH` once the thread is gone. musl's
  `pthread_setname_np` of another thread writes there.
  `root` leads to the root, `/` unless `chroot` moved it. A link of `exe`, `cwd`, `root` or
  `fd` reads, as Linux's `d_path` gives it, as a path from the reader's root
  when its file is under that root, and otherwise from the machine's root,
  unmarked; `maps` and `smaps` name a mapped file the same way, from the
  root of whoever reads them at each read, so a descriptor opened before a
  `chroot` or passed to another process names it from the reader's root.
  `smaps_rollup` is what `smaps` counts of every VMA summed under one line,
  from the first VMA's start to the last one's end with no flags, file or
  name but `[rollup]`, as Linux's `show_smaps_rollup` makes it: `Pss` is
  summed before it is rounded to kB and split by what each page is
  (`Pss_Anon`, `Pss_File`, and `Pss_Shmem` for shared memory of no file, a
  tmpfs file, a memfd or System V shared memory), and its open is `ESRCH`
  for a task with no memory left. `status`
  has Linux's fields in Linux's order (umask, IDs, threads, signal masks,
  capabilities and so on) and the memory ones of Linux's `task_mem`, which
  a zombie does not show: the peak of the size of the mappings and the
  size (`VmPeak`, `VmSize`), the locked memory (`VmLck`), the peak of the
  resident memory and the resident memory (`VmHWM`, `VmRSS`), split into
  what is anonymous, a file's and shmem's (`RssAnon`, `RssFile`,
  `RssShmem`), the private writable mappings and the stack (`VmData`,
  `VmStk`), the code range and the other executable mappings (`VmExe`,
  `VmLib`), and 0 for `VmSwap` and `HugetlbPages`, as nothing is swapped
  out and the pool of huge pages is empty. After them, while the task has
  its memory, come `CoreDumping` (1 from the fatal signal that dumps its
  process's core until the last thread has written it), `THP_enabled` (0
  once `PR_SET_THP_DISABLE` disabled transparent huge pages for the whole
  space) and `untag_mask`, all ones as nothing enables linear address
  masking. `VmPin`, `VmPTE` and the CPU fields are not there, as nothing
  counts them. The peak of the size is
  Linux's `hiwater_vm`: noted when an unmap takes mapped pages away, as
  `vms_complete_munmap_vmas` calls `update_hiwater_vm` (a fixed mapping
  that replaces them counts its own pages only after it), but not when
  `mremap` moves pages (`move_vma` keeps the peak it had). The peak of the resident
  memory is Linux's `hiwater_rss`: noted before `munmap`, `MADV_DONTNEED` and the
  other calls that drop pages, as `update_hiwater_rss` does, so that
  `VmHWM` is never below `VmRSS`. A `fork`ed child's peaks start at what it
  maps and holds, as `dup_mm` sets them, and writing 5 to `clear_refs` resets
  that of the resident memory. `statm` has, in pages, what Linux's `task_statm`
  counts: the size of the mappings, the resident pages, those of them a
  file's or shared memory's, the pages of the code range `stat` gives, 0,
  the private
  writable mappings and the stack, and 0. `stat` gives as `rss` the resident
  pages `VmRSS` shows, and as `starttime` when the task was made, in clock
  ticks since boot, which an `execve` keeps, so `ps` shows `RSS`, `STIME`
  and `START`. `limits` lists the soft and hard
  resource limits as `prlimit` gives them, in Linux's columns. `auxv` (0400)
  is the auxiliary vector the program's `execve` wrote on its stack, kept
  as Linux keeps `saved_auxv`, whatever the program then does to its stack,
  and across `fork`. Any other name in this process's directory or
  elsewhere under `/proc` is `ENOENT`, as a name procfs does not have is on
  Linux, whatever the filesystem holds there (with `--mount /:/`, the
  host's own `/proc`): `/proc` is a mount of its own from start-up, as
  `/dev` is.

- The calls that make, remove or rename a name in a directory of `/proc`
  or `/dev` (`mkdir`, `mknod`, `symlink`, `link`, `unlink`, `rmdir`,
  `rename`, `renameat2` and an `open` with `O_CREAT`, with their `*at`
  forms) give Linux's errors in its order: the directory, a last name of
  `.` or `..` (`EEXIST`, `EISDIR`, `EINVAL`, `ENOTEMPTY`, `EBUSY`), the
  lookup (procfs finds no name it does not have, `ENOENT`, where a name
  that is there is `EEXIST` to make), the trailing slash (`ENOTDIR`,
  `EISDIR`), the permission to write the directory and then `EPERM`, as
  procfs and devpts have no such operation; `link` and `rename` between
  `/proc`, `/dev` and another file system are `EXDEV` first. The
  permission is procfs's own: a process's and a thread's directory are
  immutable (`EPERM`, root's too), a process's `fd` lets its own threads
  write, no directory of `/proc/sys` may be written (`EACCES`, root's
  too), and the rest go by their mode, as `/dev` (0755 root) does, so
  another user gets `EACCES`. `/proc` and `/dev` themselves are mount
  points in the root's directory: `rmdir` and `rename` of them are
  `EBUSY`, `unlink` `EISDIR` and the calls that make them `EEXIST`.

- A path that goes on past a file of `/proc` or `/dev` that is not a
  directory, with a trailing slash or a name after it (`/proc/self/status/`,
  `/proc/mounts/x`, `/dev/null/`, `/dev/stdin/x`), is `ENOTDIR` for every
  call that looks it up, as Linux's walk finds. The links on the way are
  followed, so a link to a directory is gone on in. The calls that make or
  remove the last name only check the names before it, and their own
  errors above come after that.

- `/proc` lists the files above, and nothing the filesystem has there (with
  `--mount /:/`, none of the host's own entries), and then a directory for every process of the guest, zombies included, as
  Linux lists them, which is what `ps`, `pgrep` and `pidof` read. Another
  process's `/proc/<pid>` (0555, owned by its effective IDs) has `status`,
  `stat`, `statm`, `cmdline`, `environ` (0400), `auxv` (0400), `limits`, `personality` (0400),
  `comm`, `syscall` (0400), `maps`, `mem` (0600), `clear_refs` (0200), `smaps`, `smaps_rollup`, `pagemap` (0400), `wchan`,
  `cgroup`, `oom_score`, `oom_adj`, `oom_score_adj`, `loginuid`, `sessionid`,
  `coredump_filter`, `io` (0400), `uid_map`, `gid_map`, `projid_map`, `setgroups`,
  `timerslack_ns` (0666), `exe`, `cwd`, `root`, `mounts`, `mountinfo`, `fd`, `fdinfo`, `ns`
  (0511) and `task`, made as
  `fs/proc/base.c` and `array.c` make them for root; any other name there is
  `ENOENT`, as is the directory of a process that was never there or was
  reaped, whatever a mounted host `/proc` holds. `task` lists the threads of
  the process, and `/proc/<pid>/task/<tid>` (the reader's own threads too)
  has the same files but `task`, `coredump_filter` and `timerslack_ns`, and
  `children` too, of that thread: its name, its signal masks,
  its ID as `Pid` with the process's as `Tgid`, its own credentials (the
  process's `status`, `/proc/self/status` too, shows the leader's, as Linux's
  `proc_pid_status`), and its own `voluntary_ctxt_switches` (the times it
  went to sleep; the process's `status` shows the leader's, as Linux's
  `task_context_switch_counts`). A
  leader that ended before the other threads stays first in `task` as a
  zombie, `Z` in its `stat` and `status`, and `Threads` and `num_threads`
  count it until the process ends, as Linux keeps a delayed group leader.
  Like Linux's after `exit_mm`, `exit_files`, `exit_fs` and
  `exit_task_namespaces`, that leader has no memory, descriptors, directories
  or namespaces but its PID and user ones, in `/proc/<pid>` and `/proc/self`
  as in `task/<pid>`. Its `fd` and `fdinfo` list nothing, so `execveat`
  through `/proc/self/fd/<n>` or `/dev/fd/<n>` is `ENOENT`; `maps`, `smaps` and
  `cmdline` read nothing; its files but its directory are root's, as a
  zombie's are (see limitations), so `environ`, `auxv`, `pagemap` and `mem` are
  `EACCES`, and `ESRCH` for root; `smaps_rollup` is `ESRCH` for any reader
  (`smaps_rollup_open`); `exe`, `cwd`, `root` and its other `ns` links are `ENOENT`; `mountinfo` is
  `EINVAL`; `statm` is zeros; `status` has no `Vm` lines or `Umask` and an
  `FDSize` of 0; and `stat` has no sizes or addresses. A zombie process keeps
  its `pid` and `user` links too until it is reaped, as Linux's `pidns_get`
  and `userns_get` take them from its PID and credentials, while its other
  `ns` links and `pid_for_children` are `ENOENT`. `/proc/thread-self` is
  a link (0777) to the reading thread's, which reads as `<pid>/task/<tid>`. A
  thread's own ID names a directory of its process as that thread sees it,
  which `/proc` does not list, as on Linux. As Linux's `ptrace_may_access`
  decides, a reader that is not of the process and has no `CAP_SYS_PTRACE`
  gets `EACCES` for `environ` unless its real IDs, and for `auxv`, `maps`, `smaps`, `smaps_rollup`, `pagemap`, `mem`, `exe`, `cwd`,
  `root`, `fdinfo` and the links of `ns` and `fd` unless its filesystem IDs, are every user and group ID of a dumpable
  process in its user namespace whose permitted capabilities its own cover
  (its effective ones for the filesystem IDs), as reading another process
  asks above. `CAP_SYS_PTRACE` in the process's user namespace lets a reader
  in, but for an undumpable process only that capability in the user
  namespace its program runs in does, as Linux's `task_still_dumpable` asks:
  the one it ran the program from, or, for a program it could not read, the
  nearest one above that maps the file's owner and group (`would_dump`). So
  after `unshare` of a user namespace, a process that clears
  `PR_SET_DUMPABLE` is not readable by its children there. Its files are
  owned as this process's own are (above), an undumpable process's
  directory (0555) staying its own, and an open checks a regular
  file's mode for that owner before anything else, as Linux's
  `generic_permission` does (`EACCES`): writing needs `CAP_DAC_OVERRIDE`
  but for `comm`, `oom_adj`, `oom_score_adj`, `loginuid`, `coredump_filter`,
  `uid_map`, `gid_map`, `projid_map` and `setgroups` (0644) and `timerslack_ns`
  (0666), and
  reading `environ`, `auxv`, `pagemap` or `mem` needs the owner or
  `CAP_DAC_OVERRIDE`. `fstat` of an opened one shows the owner as this
  process's own do (above). `statm` and `limits` are anyone's to read, as on Linux. `fd` itself is read
  and looked in as its mode (0500) lets the reader, as Linux's
  `proc_fd_permission` decides. `fd` and `fdinfo` are as this process's own
  (below), of the other process's descriptors; a link of `fd` opens its
  descriptor's file again. As on Linux, a link reads as a path from the
  reader's root (`d_path`), but it is found where the other process opened
  it: in its root and mount namespace, and a `/proc/self` there is that
  process's directory. `fdinfo` gives the mount of that process's file and
  the record locks that process holds. What a process shows of
  another is what that process's threads published at their last system call
  or signal check: the name (`PR_SET_NAME`, `execve`), the blocked and pending
  signals and the credentials, with the process's dispositions, memory (for
  `cmdline`, `environ`, `auxv`, `maps`, `smaps`, `smaps_rollup`, `pagemap`, `mem`, `statm` and the sizes in `stat`), resource limits, current directory, umask and
  descriptors as they are. Its state is `R` for the reader, `T (stopped)`
  during a job-control stop, `Z (zombie)` once it has ended and until it is
  reaped, `S (sleeping)` while its thread is blocked in a wait (for a pipe,
  a futex, a timer or anything else it sleeps on), as Linux shows a task
  that is not running, `D (disk sleep)` instead in a wait Linux's task
  sleeps `TASK_KILLABLE` in (a `vfork` parent waiting for its child, an
  open waiting for a fanotify listener's answer, a task waiting for its
  userfaultfd event to be read, and a seccomp notification's wait once
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` makes it killable), and `R`
  otherwise, also while it runs in a system
  call that does not wait. A zombie keeps its name and IDs, counts one
  thread, and has no memory, umask or descriptors: its `cmdline`,
  `maps` and `smaps` are empty, and open for any reader their mode lets,
  as Linux's `proc_mem_open` checks the reader only of a process with
  memory; its `statm` is all 0, its `fd` and `fdinfo` list nothing, and `exe`, `cwd` and `root` are `ENOENT`, as on Linux; its `limits` stay. Its
  `environ`, `auxv`, `pagemap` and `mem` do not open (`ESRCH`, for any reader
  their mode lets), as Linux's `__mem_open` and `pagemap_open` refuse a
  process with no memory before they check the reader, nor does its
  `smaps_rollup` (`ESRCH` for any reader, `smaps_rollup_open`), as for a
  leader that ended before its other threads. Its files but its
  directory are root's, as on the CI runners' kernel (see limitations), so
  their mode lets only root open them, and any other reader gets `EACCES`.

- `personality` of a process or of a thread, 0400 and of size 0, is the
  thread's execution domain and flags in 8 hex digits and a newline, as
  Linux's `proc_pid_personality` writes it when it is read. Only then, as
  Linux's `lock_trace` decides with `ptrace_may_access` in attach mode and
  the reader's filesystem IDs, and with Yama's `ptrace_scope` (at 1 an
  ancestor, one named by `PR_SET_PTRACER`, or `CAP_SYS_PTRACE`), may a
  reader of another process read it (`EPERM`). A reaped task is `ESRCH`.
  `wchan` (0444) reads `0` with no newline, as Linux's `proc_pid_wchan`
  does for a running task and for a reader that may not read the task. The
  `wchan` field of `stat` is something else: 1 for a task that waits, as
  below.

- `oom_score_adj` and `oom_adj` (0644) and `oom_score` (0444) are of the
  process's `oom_score_adj`, which its threads share, a `fork` child and
  `execve` keep, and a `CLONE_VM` child shares with the processes it shares
  its memory with (but a `vfork` child), as Linux's `__set_oom_adj` sets
  it. They are made when read: `oom_score_adj` as it is, `oom_adj` scaled to
  -17 to 15 (`adj * 17 / 1000`, 15 for 1000), and `oom_score` as
  `oom_badness` finds it, `(1000 + badness * 1000 / pages) * 2 / 3` with
  `badness` the resident pages and `oom_score_adj` thousandths of the
  memory `sysinfo` reports: 0 at -1000, for a `vfork` child before its exec
  or exit, and for a process with no memory left. A write takes up to 12
  bytes, which it returns, read by `kstrtoint` with their spaces stripped
  in the base their prefix gives (`EINVAL`, `ERANGE` past an `int`); a value
  outside -1000 to 1000 is `EINVAL`, and for `oom_adj` one outside -16 to
  15 but -17, which it scales by 1000 / 17 (15 to 1000). Below the least
  value the process may set (`oom_score_adj_min`, which a write with
  `CAP_SYS_RESOURCE` sets), and through `oom_adj` below the value it has,
  a writer without `CAP_SYS_RESOURCE` gets `EACCES`. A write leaves the file
  position where it was. Another process's are written by whom their owner
  lets, and a reaped task's are `ESRCH`.

- `coredump_filter` (0644) of a process holds the filter bits of its
  address space in 8 hex digits, `00000033` at first, as Linux's
  `MMF_DUMP_FILTER_DEFAULT` with ELF headers; a `fork` child and `execve`
  keep them, and the processes sharing the memory share them. A write sets
  the low 9 bits of what `kstrtouint` reads in the base its prefix gives, a
  newline allowed after it but no space (`EINVAL`, `ERANGE` past 32 bits),
  and returns all it was given; once no thread runs in the memory it reads
  empty and a write is `ESRCH`. A thread's directory has none.

- `timerslack_ns` (0666) of a process is its leader thread's timer slack in
  nanoseconds, which `PR_SET_TIMERSLACK` and `PR_GET_TIMERSLACK` set and read
  for the calling thread: 50000 for the first task, and a new thread's or
  process's is its maker's, whose slack then is also its default. A reader
  or writer other than that thread needs `CAP_SYS_NICE` in its user
  namespace (`EPERM` at the read or the write, as Linux's
  `timerslack_ns_show` and `timerslack_ns_write` check it). A write takes
  what `kstrtoull` reads in decimal, of up to 66 bytes (`EINVAL`, `ERANGE`
  past 64 bits), and returns all it was given, leaving the position where it
  was. Setting 0 gives back the default. A real-time or deadline thread has
  no slack: `sched_setscheduler` and the like make it 0, a write keeps it 0,
  `PR_SET_TIMERSLACK` leaves it, and leaving those policies gives back the
  default. Nothing waits longer for it: the host's timers keep their own
  slack. A thread's directory has none.

- `loginuid` (0644) and `sessionid` (0444) are the thread's audit login
  user and session, as Linux's `proc_loginuid_read` and `proc_sessionid_read`
  write them, with no newline: 4294967295 (none) for both at first, a
  thread's and a process's taken from its maker, and kept across `execve`.
  The login user reads as the opener's user namespace maps it (4294967295
  for one it does not). Only the thread the file is of may write its
  `loginuid` (`EPERM` else), only at its start (`EINVAL` after a read), a
  decimal user ID as `kstrtou32` reads it in the opener's namespace
  (`EINVAL` for one it does not map), or 4294967295 for none; once it has
  one, a change needs `CAP_AUDIT_CONTROL` in the first user namespace
  (`EPERM`). Setting a user starts a session with a number no other has had
  (from 1 in each emulator), and none ends it. Nothing audits.

- `cgroup` (0444) reads `0::/`: every task is in the root group of a
  unified hierarchy, as a cgroup v2 host shows a task in its root,
  whichever control group namespace reads it. There is no `cpuset`, as in
  Ubuntu's kernel, which leaves out the cgroup v1 cpusets
  (`CONFIG_CPUSETS_V1`) that it comes with.

- `children` (0444) of a thread lists, each followed by a space, the
  processes it made that are not yet reaped, zombies too, as Linux's
  `children_seq_show`; a child whose maker has ended is its process's first
  thread's, as `forget_original_parent` gives it to that one. They are in PID
  order, where Linux's are in the order they came to the thread, which
  differs once PIDs wrap or an orphan is given to the process. The process's
  own directory has none.

- `projid_map` (0644) reads and takes the project IDs of the task's user
  namespace as `uid_map` does (above), but a write needs no capability and
  maps any IDs the parent maps, as Linux's `proc_projid_map_write`: the
  first namespace maps them all (`0 0 4294967295`). Nothing else uses
  project IDs.

- `syscall` of a process or of a thread, 0400 and of size 0, is what
  Linux's `proc_pid_syscall` writes when it is read, for a reader that may
  attach to the task, as for `personality` (`EPERM`). The reading thread's
  own is the call it reads with. Another thread that is running (blocked
  in no wait and not stopped, in a system call or not) is `running`; one
  asleep in a call or stopped shows the registers of its last entry into the kernel, as Linux's
  `pt_regs` keeps them: the call's number and its six arguments, then the
  stack pointer and the instruction pointer (past the `syscall`
  instruction), in hex, or `-1` and the two pointers for an entry that was
  no call (a stop from user code, or a fault that waits for its
  `userfaultfd`, asleep as Linux's `handle_userfault` leaves it). A thread that has ended has no kernel
  stack left: `-1 0x0 0x0`. Each thread records the registers as it enters
  the kernel, with a few plain stores that another reads whole; a new
  thread or child starts with its parent's in the call that made it, as
  Linux's `copy_thread` copies them.

- `io` of a process or of a thread (`/proc/<pid>/task/<tid>/io`), 0400 and
  of size 0, has the counts Linux's `task_io_accounting` keeps: `rchar` and
  `wchar`, the bytes the read and write calls moved (`read`, `pread64`,
  `readv`, `preadv`, `preadv2`, the writes, and both for `sendfile` and
  `copy_file_range`, writes to the host's stdout and stderr too), and
  `syscr` and `syscw`, how many of them ran: a call that failed in the
  file's own read or write counts, one refused before it does not, as
  Linux's `vfs_read`, `do_readv` and `do_preadv` each decide (`readv`
  counts even a bad descriptor, `pread64` not a file without a position).
  `splice`, `tee`, `vmsplice`, the `recv` and `send` families and `io_uring`
  count nothing, as on Linux. `read_bytes`, `write_bytes` and
  `cancelled_write_bytes` are 0, as on a Linux whose files are all in
  memory: there is no block device. A thread's file has its own counts; the
  process's adds those of its threads, of its threads that have ended, and
  of the children it reaped with `wait` (with theirs), as Linux's
  `do_io_accounting` and `wait_task_zombie` add them; a forked child starts
  from 0, and a zombie keeps its counts. The text is made when it is read,
  and when an `lseek` goes to another place, as Linux's `seq_file` makes
  it. Only then, as Linux's `ptrace_may_access` decides with the reader's
  filesystem IDs, may a reader that is not of the process read it
  (`EACCES`), so a descriptor opened while the process was dumpable cannot
  read it once it is not; a thread or process that has been reaped since
  is `ESRCH`. An `lseek` that fails so leaves the file at the start, as
  Linux's `seq_lseek` does.

- `/proc/self/stat` has Linux's 52 fields after the name in parentheses:
  state `R` (the process is running, reading it; another process's as above), the parent, process group
  and session, the controlling terminal's device and foreground group (0
  and -1 without one), the CPU time of the process and of its waited-for
  children in `USER_HZ` (100) ticks, the priority (Linux's `task_prio`: 20
  more than the nice value, -1 less the real-time priority under
  `SCHED_FIFO` and `SCHED_RR`, and -101 under `SCHED_DEADLINE`) and nice
  value, the threads,
  the size of the mappings, the `RLIMIT_RSS` limit, the start and end of
  the program's code (Linux's `start_code` and `end_code`, as
  `load_elf_binary` finds them: the lowest address and the highest end in
  the file of its executable `PT_LOAD` segments; 0 for a zombie), the start
  of the stack and of the heap, the signal sets as decimal numbers, `wchan` (1 for a task that
  waits, as Linux shows root, though not for a process of more than one thread
  as a whole), `exit_signal`, the start and end
  of the program's data (Linux's `start_data` and `end_data`, as
  `load_elf_binary` finds them: the highest address and the highest end in
  the file of all its `PT_LOAD` segments), and where
  the argument and environment strings lie, the minor faults, the resident
  pages, the start time, the CPU the task was on at its latest system call
  (as Linux's `task_cpu` is the one it last ran on; `getcpu` looks at the
  mask again at once, so after `sched_setaffinity` `stat` follows from the
  task's next system call), and the real-time priority and policy. A path under
  `task` gives the thread's own, its CPU time and faults too; the
  process's CPU time and faults are all its threads', the rest its leader's. What
  nothing measures is 0: the system time, as all the CPU time counts as
  the user's.
  A reader that may not see the task's memory, as Linux's
  `ptrace_may_access` decides with its filesystem IDs, gets 1 for
  `start_code` and `end_code` and 0 for the start of the stack, `wchan` and
  every field from `start_data` on, as Linux's `do_task_stat` hides them.
  The last of those, `exit_code`, is the wait status of a process that has
  ended (its code times 256, or its signal, with 0x80 for a core dumped), and
  a stopped process's signal in its own `stat` until a wait reports the stop
  (Linux's `group_exit_code`); a thread's `stat` under `task` has no stop's.
  A task in a ptrace stop shows that stop's `exit_code` (its signal, or
  `SIGTRAP | 0x80` for a syscall stop under `PTRACE_O_TRACESYSGOOD`), its
  process's `stat` too for the leader, until the tracer's wait reports it
  (one with `WNOWAIT` does not), as Linux's `ptrace_stop` sets it.
  A process whose leader ends with `exit` before its other threads shows the
  leader's own code in its `stat` while they run, as Linux's leader
  `exit_code` is; once they end it has the status of the last one's `exit`,
  or the group's for `exit_group` or a fatal signal, as Linux's
  `synchronize_group_exit` makes it, for `stat` and the wait alike.
  `stat` is made at each read from its start, as Linux's is, so a descriptor
  shows what the task and the reader are then: one that drops its rights
  sees the addresses hidden, and a task that has been reaped is `ESRCH`.
  `status`, `statm`, `limits`, `cmdline` and `comm` are made at each read
  the same way, as Linux's `proc_single_show`, `proc_pid_cmdline_read` and
  `comm_show` make them, with the IDs in `status` as the opener's user
  namespace sees them; `environ` reads the address space it was opened on,
  as Linux's `environ_read` reads the `mm` its open took, so nothing after
  the process's `execve` or exit, and `auxv` what the `execve` of that
  address space saved (`auxv_read`). This process's own are made so too,
  from what its threads published at their last system call, as another
  process's are. A `pwrite` to any but `cmdline` and `environ` is `ESPIPE`,
  as to every file Linux makes through `seq_open`.
  `cmdline` and `environ` are the argument and environment strings
  as they are in memory now, each ending in its NUL, and `comm` the name and a
  newline.

- `/proc/self/exe` and `/proc/self/cwd` are symbolic links (0777, size 0) to
  the program the process runs (the one `execve` loaded, with symbolic links
  resolved; for the first program, the path the CLI gives it: its path in a
  `--mount`, else `/<file name>`)
  and to the current directory. `stat` and `open` follow them, and
  `O_NOFOLLOW` does not (`ELOOP`). `execve` of `exe` (this process's or,
  for a reader that may look at it, another's) runs the program it leads
  to, as Linux's walk jumps to the file without searching its
  directories; `AT_SYMLINK_NOFOLLOW` refuses it (`ELOOP`), and a
  generated file that is no link is `EACCES`. Under a root of its own it
  does so through a bind mount of `/proc` there, and a symbolic link in
  that root into such a bind mount of `/proc` or `/dev` (an absolute one
  from the new root) leads every call to the generated file, as its own
  path does. `readlink` of a generated file that is no link, `/proc`
  itself too, is `EINVAL`.

- `/proc/sys/fs/mqueue` has the POSIX message queue limits of the
  reader's IPC namespace, as Linux's `ipc/mq_sysctl.c`: `queues_max`,
  `msg_max` and `msg_default` (1 to 65536), `msgsize_max` and
  `msgsize_default` (128 to 16 MiB), regular files of mode 0644 that the
  root of the user namespace owning the IPC namespace owns, and only that
  root may open to write (`EACCES`). Each file of `/proc/sys` has an inode
  of its own and a size of 0, as Linux's `proc_sys_make_inode` makes it,
  so `copy_file_range` into one copies nothing from another sysctl and is
  `EXDEV` from another filesystem. A read gives the value and a newline
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
  `/proc/sys/fs` lists only these, `dir-notify-enable`, `fanotify`,
  `inotify`, `mqueue`, `lease-break-time` and `leases-enable`.

- `/proc/sys/fs/inotify` has the machine's inotify limits, root's regular
  files of mode 0644 that only root (user ID 0 outside any user namespace)
  may open to write, read and written as the files above:
  `max_user_instances` (128 at first) and `max_user_watches` (31956 at first,
  as the instances below say), unsigned longs from 0 to `INT_MAX`, are what
  each user may have from then on, and `max_queued_events` (16384 at first),
  an `int` from 0, is how many events an instance made from then on queues
  before `IN_Q_OVERFLOW`.

- `/proc/sys/fs/fanotify` has the machine's fanotify limits in the same way:
  `max_user_groups` (128 at first) and `max_user_marks` (33979 at first, 1%
  of the memory `sysinfo` reports over twice an inode's size), unsigned
  longs from 0 to `INT_MAX`, and `max_queued_events` (16384 at first) and
  `watchdog_timeout` (0), `int`s from 0.

- `/proc/sys/kernel` has the System V IPC limits of the opener's IPC
  namespace, as Linux's `ipc/ipc_sysctl.c`, each a new namespace has at
  Linux's defaults, owned and opened to write as the files of
  `/proc/sys/fs/mqueue`: `shmmax` and `shmall` (unsigned longs, as
  `aio-max-nr`), `shmmni` and `msgmni` (`int`s from 0 to 32768), `msgmax`
  and `msgmnb` (`int`s from 0), and `sem`, its four `int`s `semmsl`,
  `semmns`, `semopm` and `semmni` read with tabs between them. A write to
  `sem` sets as many as it gives, as Linux's `proc_dointvec` reads a
  vector: a bad one is `EINVAL` and leaves the ones before it set, and
  `semmni` goes back to what it was unless it ends from 0 to 32768
  (`ERANGE`, `proc_ipc_sem_dointvec`). Beside them are the machine's
  `perf_cpu_time_max_percent`, `perf_event_max_sample_rate`,
  `perf_event_mlock_kb`, `perf_event_paranoid` and
  `unprivileged_bpf_disabled`, one each for the whole emulated machine and
  at Linux's defaults at first (25, 100000, 516, 2 and 2): root's files of
  mode 0644, which only root (user ID 0 outside any user namespace) may
  open to write (`EACCES`). `perf_event_mlock_kb` and `perf_event_paranoid`
  take any `int` (`proc_dointvec`); `perf_cpu_time_max_percent` takes 0 to
  100 and `perf_event_max_sample_rate` 1 or more (`EINVAL`), the latter
  refused (`EINVAL`) while the former is 0 or 100, as Linux's
  `perf_event_max_sample_rate_handler`; `unprivileged_bpf_disabled` takes 0 to 2 (`EINVAL`)
  from a writer with `CAP_SYS_ADMIN` (`EPERM` before anything else, so also
  for an empty write or one past the start), and once 1 it takes no
  other value (`EPERM`), as Linux's `bpf_unpriv_handler`; `perf_event_open`
  and `bpf` check what they are now. `shm_rmid_forced` (0 or 1, owned and
  written as the limits) makes a segment go at its last detach and those
  its maker never attached go when it exits or leaves the namespace, as
  Linux's `shm_close` and `exit_shm` do; setting it removes the orphans no
  mapping shows (`shm_destroy_orphaned`). `auto_msgmni` reads 0 and takes 0
  or 1 to no effect. `shm_next_id`, `sem_next_id` and `msg_next_id` (mode
  0444, which whoever has `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN` over
  the namespace's user namespace may write) are the ID the next object of
  their kind takes, once, -1 for none: a write sets it from 0 to `INT_MAX`,
  and the object takes its sequence number and the first free index from
  its own below 32768, `ENOSPC` with none, as Linux master's `idr_alloc`
  stops at `ipc_mni` (7.0's went past it), the next ID used up all the
  same. A write of any of these files is checked again at the write,
  as Linux's `proc_sys_call_handler` does: a writer who may not write it
  now is `EPERM`, though the open let it, and `unprivileged_bpf_disabled`
  asks the writer, not the opener, for `CAP_SYS_ADMIN`. Only a write that
  sets `shm_rmid_forced` removes orphans, as Linux master's handler; 7.0's
  did so at a read of it set too. `/proc/sys/kernel/yama` has the machine's
  `ptrace_scope` alone, as Linux's `security/yama/yama_lsm.c`: 1 at first,
  root's, of mode 0644, which only root may open to write (`EACCES`). A
  write needs `CAP_SYS_PTRACE` of the writer (`EPERM`) before anything
  else, so also when it writes nothing or past the start, as
  `yama_dointvec_minmax` asks; it takes 0 to 3 (`EINVAL`), and once 3 it
  takes no other value (`EINVAL`). The scope applies to every attach
  (`ptrace`, `process_vm_readv`, `pidfd_getfd`, `/proc/<pid>/mem` and the
  other files that attach), and at 2 `PTRACE_TRACEME` needs a tracer with
  `CAP_SYS_PTRACE` in the caller's user namespace and at 3 is refused
  (`EPERM`), as `yama_ptrace_traceme`.
  `/proc/sys/kernel` also has the machine's constants, of mode 0444 and
  root's, which no one opens to write (`EACCES`): `cap_last_cap` (40, the
  highest capability `prctl` takes) and `ngroups_max` (65536, the most
  groups `setgroups` takes), as Linux's `kernel/sysctl.c`; and
  `seccomp/actions_avail`, the names of the actions
  `SECCOMP_GET_ACTION_AVAIL` takes, as `kernel/seccomp.c` has it
  (`actions_logged`, which Linux has beside it, is not made, as nothing is
  logged). `/proc/sys/kernel/random` has the files of Linux's
  `drivers/char/random.c`: `poolsize`, `entropy_avail` and
  `write_wakeup_threshold` 256, the bits of a pool that is ready, as on a
  booted machine, and `urandom_min_reseed_secs` 60, of which the last two
  are of mode 0644 and take what root writes whole, to no effect
  (`proc_do_rointvec`); `boot_id`, a random version 4 UUID the machine draws
  at its first read and keeps, and `uuid`, a new one at each read
  (`proc_do_uuid`). A string among these is read from where the file is, as
  `proc_dostring` reads it, and an `int` only from the start.
  `/proc/sys/kernel` lists only these, the six below and the directories
  `random`, `seccomp` and `yama`, and each directory of `/proc/sys` lists
  its entries by name, directories among files, as Linux's tree of them
  keeps them.

- `/proc/sys/kernel` also shows the UTS namespace's names, as Linux's
  `kernel/utsname_sysctl.c`: `arch`, `ostype`, `osrelease` and `version`
  (root's, mode 0444) and `hostname` and `domainname` (0644), each what
  `uname` gives and a newline; a personality, which changes what `uname`
  gives, does not change them. The namespace is that of the thread that
  reads or writes, not of the one that opened the file, and a file of that
  name that `--mount` gives does not show. Only root (user ID 0 outside any
  user namespace) may open `hostname` and `domainname` to write (`EACCES`),
  with or without `CAP_SYS_ADMIN`, and a write is checked again (`EPERM`);
  the root of a user namespace has `sethostname` alone. They are strings
  (`proc_dostring`): a read goes on from where the file is, and a write is
  taken whole, its bytes up to a NUL or newline put at its offset, 64 in all
  at most, with a NUL after them. The bytes of the old name past that NUL
  stay, and `uname` gives them too, where `sethostname` clears them. A write
  past the end of the name changes nothing. `poll`, `select` and `epoll` take
  the files of `/proc/sys`, as `proc_sys_poll` does, and find them ready;
  after a change of `hostname` or `domainname`, by `sethostname`,
  `setdomainname` or a write to the file that is not refused, in any UTS
  namespace, the first poll of each open file description gives `POLLIN`,
  `POLLRDNORM`, `POLLERR` and `POLLPRI` and no `POLLOUT`. A `dup` and a child
  share what it has seen, and a poll of an epoll that watches it is one too.

- `/proc/sys/vm` has `drop_caches`, `max_map_count` and
  `unprivileged_userfaultfd` alone, so its listing differs from Linux's,
  which has the rest of the `vm` sysctls too. `max_map_count` is the
  machine's 65530 (`DEFAULT_MAX_MAP_COUNT`), root's, of mode 0444, which no
  one opens to write (`EACCES`), as nothing here bounds a process's
  mappings by it. `unprivileged_userfaultfd` is the machine's, 0 at first, root's of
  mode 0644, which only root opens to write, and takes 0 or 1
  (`proc_dointvec_minmax`, else `EINVAL`). As Linux's
  `fs/drop_caches.c` has it, the file is root's, of mode 0200: no one may
  open it to read, root included (`EACCES`, as `test_perm` gives root the
  owner's bits), and only root may open it to write. A write takes one
  `int` from 1 to 4 (`proc_dointvec_minmax`, else `EINVAL`). Each write
  that goes through, one past the start too (with the value last written),
  then drops as `drop_caches_sysctl_handler` does: 2 (`drop_slab`) evicts
  the inodes nothing uses, and their evictable fanotify marks go (below);
  1 drops the page cache, of which nothing here shows; 4 only quiets the
  kernel log's line, which there is none of here.

- `/proc/sys/net` has the settings of the opener's network namespace, as
  Linux's `net/ipv4/devinet.c` and `net/ipv6/addrconf.c` keep them for
  `all`, `default` and each device (`lo` and the veth ends): `ipv4/ip_forward`,
  `ipv4/conf/<device>/forwarding` and `rp_filter`, and
  `ipv6/conf/<device>/accept_dad`, `disable_ipv6` and `forwarding`,
  `ipv4/fib_multipath_hash_seed`, `ipv4/fib_multipath_use_neigh`, and
  `fib_multipath_hash_policy` and `fib_multipath_hash_fields` of `ipv4`
  and of `ipv6`. They and their
  directories belong to the root of the user namespace that owns the
  network namespace; the files are 0644, which root and whoever has
  `CAP_NET_ADMIN` over that namespace may open to write
  (`net_ctl_permissions`, `EACCES`, and `EPERM` at a write that may not).
  Each takes an `int` as `proc_dointvec` does. The first namespace starts
  with them all 0, as Linux is built; a new one copies the first one's
  IPv4 `all` and `default` and starts IPv6's as built
  (`devconf_inherit_init_net` at 0), and its `lo` takes its `default`. As
  the handlers:
  - IPv4's `forwarding` (`ip_forward` is `all`'s) needs `CAP_NET_ADMIN`
    of the writer (`EPERM`, `devinet_sysctl_forward`); `all`'s, when it
    changes, sets `default`'s and every device's, while `default`'s
    reaches no device. A write that changes one is told to the members of
    `RTNLGRP_IPV4_NETCONF` with `RTM_NEWNETCONF` of its forwarding: of
    `all`'s, then `default`'s and every device's, of `default`'s or of a
    device's alone.
  - `rp_filter` set on a device stays its own; one set on `default` goes
    to every device that has not been set, even by a write that failed
    (`devinet_conf_proc`). A write that changes it tells of the one written
    to alone, not of the devices that take `default`'s.
  - IPv6's two report a bad value (`EINVAL`), as Linux master's
    `addrconf_sysctl_forward` and `addrconf_sysctl_disable` do and the CI
    kernel does (7.0's left it unreported and had `forwarding` of `all` or
    a device return 1). `all`'s sets
    `default`'s and every device's. `forwarding` is told of to the members
    of `RTNLGRP_IPV6_NETCONF` only as it turns on or off (from 1 to 2 tells
    nothing), as `addrconf_fixup_forwarding` does: of `all`'s, `default`'s
    first, then each device's that turns, in the order the devices were
    registered in, then `all`'s own;
    `disable_ipv6` is told of so by nothing. A device whose `disable_ipv6` turns
    on loses its IPv6 addresses and routes, told of as when it goes down
    (`addrconf_ifdown`); turning off while it is up gives `::1` back, and
    IPv6's own `RTM_NEWLINK` (`RTNLGRP_IPV6_IFINFO`), as `NETDEV_UP`
    does. While it is on, `lo` coming up takes no IPv6 and a new IPv6
    address is `EACCES` (`addrconf_add_dev`).
  - `fib_multipath_hash_seed` takes an unsigned `int` as
    `proc_douintvec_minmax` does (the rest of the write taken with it), 0
    for the machine's random seed, as a new namespace has it. So does
    `fib_multipath_hash_policy`, of 0 to 3 (`proc_dou8vec_minmax`), and
    `fib_multipath_hash_fields`, of 1 to 0xfff (`proc_douintvec_minmax`),
    `EINVAL` past them; a new namespace has policy 0 and fields 7 (the
    source, the destination and the protocol), each family its own.
    `fib_multipath_use_neigh` takes 0 or 1 so (`proc_dou8vec_minmax`), 0
    in a new namespace.
  - A link's `IFLA_AF_SPEC` shows them in its IPv4 and IPv6 settings,
    and IPv6 is ready only with `disable_ipv6` off.

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
  `name_to_handle_at` gives with `AT_HANDLE_FID`. A pidfd's adds `Pid:` and
  `NSpid:`, as `pidfd_show_fdinfo`: the number of its process (or thread) in
  the first PID namespace, that of `/proc`, a zombie's too, or -1 once it is
  reaped, then its numbers in each namespace below down to its own. The other kinds add Linux's lines
  too. After the first four come `lock:` lines (`show_fd_locks`): the
  description's `flock` lock, then each record lock set through it that the
  process's table or the description owns, in the file's order (each owner's
  together by where they start, the owners as they first locked the file), then
  its lease, numbered from 1 across all. Each has `FLOCK`, `POSIX`, `OFDLCK` or
  `LEASE`, `READ` or `WRITE` (for a lease being broken, `BREAKING` and the type
  it is to have, which can be `UNLCK`), the ID of the process that set it (-1 for a
  description's record lock), the device and inode, and the range (`0 EOF` for
  a `flock` lock or a lease). Asking again for the kind of `flock` lock a
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
  in Linux's formats: load averages of 0 with the running tasks (the threads
  `/proc/stat`'s `procs_running` counts), the live tasks and the last ID
  handed out; 4 GiB of total, free and available memory and
  nothing else used, no swap and no huge pages; and the monotonic clock's
  uptime with no idle time.

- The system's other files are those of a machine that booted with nothing
  but what the emulator has, in Linux's formats:
  - `/proc/version` is Linux's banner with `uname`'s system name, release and
    version, built by `paludarium@paludarium` with `rustc`.
  - `/proc/cmdline` is the fixed command line `ro`, and its size is that of its
    line, as Linux sets it.
  - `/proc/filesystems` lists the types `sysfs` numbers, in its order, each
    but ext4 marked `nodev`.
  - `/proc/devices` lists the character majors of the memory devices,
    `/dev/tty` and `/dev/ptmx`, the misc devices and the pseudo-terminals'
    masters (`ptm`) and slaves (`pts`), then the block major `blkext` alone.
  - `/proc/misc` lists `/dev/userfaultfd`'s minor.
  - `/proc/swaps` and `/proc/cgroups` are their headers alone: nothing swaps,
    and the emulator has no cgroup controller at all, as a kernel built with
    none (the only cgroup is version 2's root).

- `/proc/stat` is in the format of Linux's `show_stat`.
  - A `cpu` line and one for each CPU `sched_getaffinity` reports give, in
    clock ticks, the CPU time every thread has run, the reaped processes'
    included, so the counts only grow. A thread's time counts to the CPU it
    was on at its latest system call, or to the one another thread's
    `sched_setaffinity` moved it to since. It is all user time, as
    in `getrusage` and `times`, and the other times are 0, idle too, as
    `/proc/uptime` counts no idle time.
  - `intr 0`; `ctxt`, the times threads went to sleep; `btime`, the
    real-time clock less the monotonic one in seconds, so `ps` finds the boot
    time; `processes`, the IDs handed out; `procs_running`, the threads
    running as `/proc/<pid>/stat` shows them (`R`), the reader included;
    `procs_blocked 0`; and a `softirq` line of zeros.

- `/proc/cpuinfo` is in the format of Linux 7.0's `show_cpuinfo`, with a
  record for each CPU `sched_getaffinity` reports. It is made from the
  virtual CPU's `CPUID` as Linux makes it when it boots on such a CPU, never
  from the host's CPU.
  - `vendor_id`, `cpu family`, `model`, `stepping` and `cpuid level` are
    `CPUID`'s. `model name` is `Hammer`, the name Linux gives an AMD CPU of
    family 15 without a brand string.
  - `flags` names, by Linux's names and in its order (`x86_cap_flags`), the
    features of the `CPUID` words Linux copies, and those Linux sets itself on
    such a CPU: `nopl`, `cpuid`, `3dnowprefetch` and `vmmcall`. `bugs` names
    what Linux's tables give that family: `fxsave_leak`, `sysret_ss_attrs`,
    `null_seg`, `swapgs_fence`, `spectre_v1`, `spectre_v2` and
    `spectre_v2_user`.
  - `CPUID` describes no topology, so each CPU is a package of its own with
    one core: `physical id` and `apicid` are its number, `siblings` and
    `cpu cores` 1, and `core id` 0. `initial apicid` is what `CPUID`'s leaf 1
    gives, 0.
  - `clflush size` and `cache_alignment` are 64, and the address sizes 36
    bits physical and 48 virtual: a 64-bit Linux's defaults without `CPUID`
    leaf 0x80000008.
  - There is no `microcode`, `cpu MHz` (`CPUID` reports no time stamp
    counter), `cache size` or `TLB size` line. `power management` is empty,
    and `bogomips` is 0.00, as nothing is calibrated.

- `/proc/net` is a link to `self/net`; `/proc/<pid>/net`, and a thread's,
  holds the files of the task's network namespace, whose names are looked
  up in the one it has then (`get_proc_task_net`), by any reader: `ENOENT`
  for a zombie's, whose directory lists nothing (`EINVAL`). A file open stays
  with the namespace it was opened in. Each is 0444 and the root's of the
  user namespace that owns the network namespace, as that mapped it when
  the network namespace was made, else the first's (`proc_net_ns_init`),
  opens for reading only (`EACCES`, `seq_open_net`), and is made as it is
  read:
  - `dev` (`dev_seq_show`), the devices, with their counters (see below);
    `if_inet6`
    (`if6_seq_show`), the IPv6 addresses; `route` (`fib_route_seq_show`),
    IPv4's main table, nothing while there is none, with a gateway of IPv6
    (`RTA_VIA`) as 00000000, `RTF_GATEWAY` where its first 4 bytes are not
    0 (`fib_flag_trans`); `ipv6_route`
    (`ipv6_route_native_seq_show`), each IPv6 table, with a reference each;
    and `arp` (`arp_seq_show`), the IPv4 neighbours that need ARP.
  - The counters of `dev`, as of a link's `IFLA_STATS64` and `IFLA_STATS`
    (`dev_get_stats`), are the packets and bytes each device has sent and
    taken in. The loopback counts each packet once each way from its IP
    header (`loopback_xmit`); a veth end counts what it sends with its
    Ethernet header (`veth_xmit`) and takes in what its peer sends
    (`veth_get_stats64`), in whatever namespace that is. They count each
    UDP datagram, or each fragment of one past the device's MTU
    (`__ip_append_data`, `__ip6_append_data`), as it leaves: through the
    loopback to an own address, through a veth end to its peer, or once
    for a broadcast or a group whoever takes it, the sender's own copy
    looping back uncounted (`dev_loopback_xmit`); ICMP's port unreachable
    that answers one, out through the end its own route takes, quoting at
    most what fits in 576 bytes or, of IPv6, 1280 (`icmp_send`,
    `icmp6_send`); an ARP request and its answer (`arp_send`); and each TCP
    segment, a GSO buffer of several as one (`__tcp_transmit_skb`), with its
    TCP header: the SYN's and SYN-ACK's options, a reset's to a closed port
    none (`tcp_v4_send_reset`), the rest the timestamps and their SACK blocks
    (`tcp_options_write`). What they leave out is in the
    [limitations](./limitations).
  - `igmp` (`igmp_mc_seq_show`), each device's IPv4 groups, the newest
    first, with their users, under a line of the device with how many it
    has and the querier `V3`: no IGMP report is heard, and none is sent
    again on a timer, so no timer runs and no device is the reporter.
    `igmp6` (`igmp6_mc_seq_show`), each IPv6 group of each device with IPv6, the newest first, with its
    users and its flags, `MAF_NOREPORT` for ff02::1 and a group of a scope
    below a link's and `MAF_LOADED` for the rest from when they are joined
    or their device comes up until it goes down, and no timer, as no MLDv1
    report is waited for. `mcfilter` and `mcfilter6`
    (`igmp_mcf_seq_show`, `igmp6_mcf_seq_show`), the sources the
    memberships of each group name, with how many include and how many
    exclude each, from the first device whose newest group names one, as
    Linux's begin there.
  - `dev_mcast` (`dev_mc_seq_show`), the link-layer multicast addresses
    each device takes packets to, in the order of their indexes, each
    device's in the order they came, with how many of its groups map to
    each and whether it is global, which none is. A veth end maps each
    IPv4 group in its filter to an Ethernet address (`ip_eth_mc_map`), and
    each IPv6 group of a link's scope or wider (`ipv6_eth_mc_map`), as it is
    joined or the device comes up, from the all-hosts group, the rest the
    newest first (`ip_mc_up`, `ipv6_mc_up`); down or with its IPv6 off,
    they come out (`ip_mc_down`, `ipv6_mc_down`), but a group joined then
    comes in all the same. The loopback maps none.
  - `tcp`, `tcp6`, `udp` and `udp6`, the sockets `sock_diag` tells of, but
    for TCP ones bound alone, in the format of Linux 7.0's `tcp4_seq_show` and
    the like: first the listeners, then the connections, with those in
    `TIME_WAIT`. `unix` (`unix_seq_show`) has a connection not yet accepted
    too, and `netlink` (`netlink_native_seq_show`) the sockets that are
    bound. Owners show as the opener's user namespace has them.
  - `raw`, `raw6`, `icmp`, `icmp6` and `packet`, of kinds of socket there are
    none of, hold their header alone. There is no `udplite`, as Linux has no
    UDP-Lite any more.
  - Any other name there is `ENOENT`, with `--mount /:/` too: the host's
    sockets and devices are not the guest's.

- `/proc/sysvipc` holds `msg`, `sem` and `shm`, listed in that order, each in
  the format of Linux's `sysvipc_*_proc_show` on a 64-bit kernel.
  - Each is a header, then a line for each queue, set or segment of the
    opener's IPC namespace, by index.
  - As Linux's `seq_file`, each `read` makes the lines it reaches from the
    objects as they are then, from the index the reader had got to. An
    object made or removed between reads shows or not by where the reader
    is, and a file opened before an `unshare` of the IPC namespace still
    reads the one it was opened in. `lseek` goes from the start or the
    current position, and `SEEK_END` is `EINVAL`.
  - A line shows the key, ID and mode, with `SHM_DEST` and `SHM_LOCKED`
    for a segment.
  - It also shows the counts, the PIDs in the opener's PID namespace (0
    for one it cannot see), the owner and creator in the opener's user
    namespace, and the times.
  - A segment's line adds the bytes of its pages in memory, and 0 swapped.
  - A segment's or queue's PIDs, which `IPC_STAT` gives too, still show
    once their process is gone, as the object keeps its `struct pid`.

- These system files (`cpuinfo`, `loadavg`, `locks`, `meminfo`, `stat`, `uptime`, the
  files above but `cmdline`, and `sysvipc`'s) are of size 0, as Linux's `proc_create` makes them, and a
  read goes on to the end of what they hold. So is every file of a process's
  or a thread's directory (`stat` and `fstat` alike), as Linux's
  `proc_pid_make_inode` leaves it, whatever its reads give.

- Root may open these system files for writing, but a write gives `EIO`,
  as Linux's `pde_write` gives for a file without a write operation. A
  process's own files give `EINVAL`.

- `/proc/self/maps` lists the VMAs in Linux's format, with adjacent mappings
  merged and split as Linux does: the range, the protection, `s` or `p`, the
  offset in the file, the file's device and inode as `stat` gives them (the
  device as glibc's `major` and `minor` take it apart), and
  the name in Linux's column: the file's path, with a newline in it as
  `\012`, where renames of it or of a directory above it have moved it
  (`d_move`), followed by a space and `(deleted)` once the name it has is
  removed, `/memfd:<name> (deleted)`,
  `/dev/zero (deleted)` for shared anonymous memory, `[heap]` or `[stack]`.
  A program's segments and its interpreter's are named as
  `/proc/self/exe` names the program, as Linux's `d_path` of the file:
  by its path with symbolic links resolved, moved by renames, and
  `(deleted)` once that name is removed. A core's `NT_FILE` note names
  them all the same way. A rename moves a name whichever root (`chroot`) it
  is made under, and a name under the reader's root, or the dumping
  process's, is shown from it, as `d_path` shows it.
  It is made as it is read, as Linux's `seq_file` makes it: a read gathers
  whole lines up to a page, goes on from the VMA it found next, and sees the
  mappings of that moment, `lseek` goes from the start or the current
  position only (`EINVAL` from the end), and its size is 0. A descriptor
  shows the address space it was opened on, which a forked child reading it
  sees too, and nothing once no thread uses that space, as after an `execve`.
  It cannot be mapped (`ENODEV`). Its lines are Linux's VMAs, merged as
  `is_mergeable_anon_vma` and `can_vma_merge_right` merge them: two that
  differ in nothing else are one only if their private memory has one
  `anon_vma`, or one of them none. A VMA takes an `anon_vma` at its first
  write (`mlock`'s faults included): that of the VMA after it, or else of
  the one before it, if they differ in no more than protection, name and
  which `userfaultfd` they are registered with, or else one of its own. A
  `fork`ed child's VMAs each have one of their own, which none without one
  merges with; and anonymous memory that `mremap` moves once written keeps
  its page offset (`vm_pgoff`), so it merges with nothing there.

- `/proc/self/smaps` follows each line of `maps` with Linux's `show_smap`
  block, read as `maps` is: the size, what the pages hold (`Rss`, `Pss`,
  `Pss_Dirty`, the shared and private clean and dirty pages, `Anonymous`,
  `Locked`, with 0 for huge pages, swap and KSM), `THPeligible` and
  `VmFlags`. A page counts once it has an entry: anonymous private memory only read
  shows the zero page, which is not counted, written private memory is
  anonymous and dirty, and a page that more than one page table entry
  maps, in this process or any other (one a `fork` shares until it is
  written, a file's page two mappings show), is shared, with its size
  divided by that count in `Pss`, as Linux's `smaps_account` takes the
  precise map count. A read fault in a file's mapping gives entries to
  the pages around it too, as Linux's `do_fault_around` maps them, and so
  does a read that faults in through `get_user_pages` (a core dump's, a
  tracer's `PTRACE_PEEKDATA`): up to
  16 (the default `fault_around_bytes`, 64 KiB) from the faulting page's
  aligned block of 16, or from the VMA's start if that is later, within
  the VMA, its page table and the file, and only pages the page cache
  holds: a memfd's written pages, shared memory's that any process
  touched, and every page of another file within its size. A loaded
  program's segments, whose pages are all there from the load, are mapped
  around too once `MADV_DONTNEED` dropped their pages. A page that
  has an entry or a marker keeps it. System V shared memory and secret
  memory map none around, as Linux's have no `map_pages`, nor does a VMA
  that `userfaultfd` watches for writes or minor faults. The present bits of `pagemap`
  show the same pages. `VmFlags` names Linux's flags of the VMA
  in Linux's order: the protection and what it may become (`mr`, `mw`, `me`,
  `ms`, without `mw` for a file open only for reading or sealed against
  writes, and without `me` for the rings of AIO and `io_uring` and secret
  memory, whose pseudo file systems run nothing), `sh`, `gd` for the initial
  stack, `um` and `uw` for a range a `userfaultfd` registered, the locks (`lo`, `lf`), the guards (`gu`), the advice (`sr`, `rr`,
  `dc`, `wf`, `dd`, `hg`, `nh`, `mg`), `de`, `mm` and `dd` of the rings and
  secret memory, the charge (`ac`, which private memory that was writable
  has unless `MAP_NORESERVE` gave it `nr`, and which anonymous memory never
  written gives back as it stops being writable), `nh` of a `MAP_STACK`
  mapping, `nr`, `wf`, `dd` and `dp` of a `MAP_DROPPABLE` one, the seal
  (`sl`), and `sd` (`VM_SOFTDIRTY`) on every VMA
  `clear_refs` has not cleared since it was made, but the initial stack:
  one that merges with a new VMA has it again, as Linux's sticky flags.

- `/proc/self/pagemap` (mode 0400, size 0) has an entry of 8 bytes for
  each page of user space, as Linux's `pagemap_read` gives them: the
  entry of the page at an address is at that address divided by the page
  size, times 8. An entry outside every mapping is 0. In a mapping it is
  soft-dirty (bit 55) while its VMA has `sd`, and a page with an entry also
  once it is written after `clear_refs` (below), as Linux's write fault
  sets `_PAGE_SOFT_DIRTY`; a guard region's
  page (`MADV_GUARD_INSTALL`) is also a swap entry (bit 62) with the guard
  bit (58); and a page any access gave an entry is present (bit 63). The
  zero page that a read of private anonymous memory shows is only that.
  Any other present page is a file's or shared memory's (bit 61) unless it
  is anonymous, as `smaps` counts it, and mapped exclusively (bit 56) while
  exactly one page table entry maps it, in this process or any other, as
  Linux takes a precise map count of 1: a page `fork` shares is mapped
  twice until either process writes its own copy or lets it go, and a
  file's page that two mappings show is mapped twice; one `userfaultfd` write-protects
  has bit 57. The frame number (bits 0 to 54) is 0, as Linux gives it to a
  reader without `CAP_SYS_ADMIN`. A read or `pread` must start at a whole
  entry and ask for whole entries (`EINVAL`), and gives nothing from the end
  of user space on, or once no thread uses the address space it was opened
  on. `lseek` goes from the start or the current position to any position,
  as Linux's `mem_lseek`, a negative one too, from which a read is `EINVAL`;
  from the end it is `EINVAL`. It cannot be written (`EINVAL`, `EBADF` on a
  descriptor open only for reading).
  Its ioctl `PAGEMAP_SCAN` finds the pages of a range by their categories, as
  Linux master's `do_pagemap_scan` does:
  - The categories are `PAGE_IS_WPALLOWED`, `WRITTEN`, `FILE`, `PRESENT`,
    `SWAPPED` (a guard, poison or uffd-wp marker), `PFNZERO`, `SOFT_DIRTY`
    and `GUARD`, from the same state as the entries.
    - `PAGE_IS_WPALLOWED`: the VMA is registered for write protection by a
      `userfaultfd` with `UFFD_FEATURE_WP_ASYNC`, and is not private
      anonymous memory or has `UFFD_FEATURE_WP_UNPOPULATED`.
    - `PAGE_IS_WRITTEN`: in a VMA registered for write protection, a page
      that is not write-protected, an empty one too.
  - A page is matched by `category_mask`, `category_anyof_mask` and
    `category_inverted`, and reported with the categories of `return_mask`.
    Pages that meet with the same categories are joined into one region.
  - The scan stops early for `vec_len` regions or `max_pages` pages.
    `walk_end` tells where it stopped, and the result is the number of
    regions.
  - With `PM_SCAN_WP_MATCHING`, the written pages it matches are
    write-protected again, as `UFFDIO_WRITEPROTECT` does, and VMAs that
    cannot be protected are passed over. Without a buffer, every page
    where Linux would have a page table is protected.
  - With `PM_SCAN_CHECK_WPASYNC`, such a VMA stops the scan (`EPERM`).
  - The request is checked as `pagemap_scan_get_args` does: its size, flags
    and categories (`EINVAL`), a start on a page boundary (`EINVAL`), the
    range and the buffer in user space (`EFAULT`), and a buffer for a
    length (`EINVAL`).
  - Any other ioctl is `ENOTTY`, and a scan once the address space is gone
    is `ESRCH`.

- `/proc/<pid>/mem` (mode 0600, size 0, a thread's too) reads and writes
  the task's memory at the address its position gives, as Linux's `mem_rw`
  does through `access_remote_vm` with `FOLL_FORCE`: a page whatever its
  protection, a private one written to a copy of its own, a page at a time.
  A call that moves no byte (no page there, nor a stack the caller can grow
  down to it, a `perf` ring's or a
  `memfd_secret` file's, which `get_user_pages` refuses) is `EIO`, and one
  that stops later gives what it moved. `lseek` takes `SEEK_SET` and
  `SEEK_CUR` only (`EINVAL`), and its positions are unsigned
  (`FOP_UNSIGNED_OFFSET`): `lseek` goes past `i64::MAX`, and a read or
  write there moves bytes at that address; `pread64` and `pwrite64` refuse
  such an offset (`EINVAL`), as Linux v7.0 does (see limitations). An open
  takes the memory the task has then, which the file keeps: after an
  `execve` or the end of the task, that memory is gone and nothing moves.
  It is the reader's own
  or one it may attach to (`mm_access` with `PTRACE_MODE_ATTACH` and the
  filesystem IDs: `EACCES`), and a task with no memory (a zombie) is
  `ESRCH`. It cannot be mapped, nor can `pagemap` or `clear_refs`
  (`ENODEV`).

- `/proc/<pid>/clear_refs` (mode 0200, size 0, a thread's too), as Linux's
  `clear_refs_write`: a write's first 12 bytes at most, which is what it
  returns, are a number as `kstrtoint` reads one in base 10 (spaces
  stripped, a sign, one newline; `EINVAL`, `ERANGE` past an `int`) from 1
  to 5 (`EINVAL`), and then the process must still be there (`ESRCH`). 4
  clears the soft-dirty bit of every VMA and every page of the address
  space the process has at that moment: a page's next write sets it again,
  as does `mremap` for a page it moves and `UFFDIO_COPY`, `UFFDIO_CONTINUE`
  and `UFFDIO_MOVE` for the page they map, and a `fork`ed child keeps each
  page's bit. 5 (`CLEAR_REFS_MM_HIWATER_RSS`) makes the peak of the
  resident memory (`status`' `VmHWM`) the resident memory now, as
  `reset_mm_hiwater_rss` does. 1 makes every page unreferenced, 2 those of
  VMAs with no file and 3 those of VMAs with one (shared memory's too):
  `smaps` and `smaps_rollup` leave a page out of `Referenced` until its
  next access, an instruction fetch too. A `fork`ed child has referenced
  none of the pages it gets (`pte_mkold`). It has no read operation
  (`EINVAL`, `EBADF` on a descriptor open only for writing), and `lseek`
  leaves it at 0.

- `/proc/self/fd` (mode 0500, its size the number of open descriptors, as
  Linux's `proc_fd_getattr` gives it) lists `.`, `..` and a link per open
  descriptor, named by its number as Linux reads one (no leading zero). Each
  link's `lstat` shows the descriptor's access in its user bits (none for `O_PATH`) and size 64,
  and `stat` follows it to the file. `readlink` gives Linux's names: the
  file's path with `.`, `..` and symbolic links resolved (`/proc/<pid>/…`
  for this process's entries, `/proc` for procfs's root), followed by a space and `(deleted)` once
  nothing names it, `pipe:[<inode>]`, `socket:[<inode>]`,
  `anon_inode:[eventfd]`, `[eventpoll]`, `[timerfd]`, `[signalfd]`, `[perf_event]` or `[pidfd]` (an
  anonymous inode's name, which pidfs, from Linux 6.9, still gives),
  `anon_inode:inotify` (without brackets, as Linux names it), `anon_inode:bpf-map`, and
  `/memfd:<name> (deleted)`; pipes and sockets have inode numbers of their
  own for it. The files of those anonymous inodes (eventfds, epolls,
  timerfds, signalfds, inotify and fanotify instances, perf events,
  seccomp listeners, BPF maps and programs, Landlock rulesets and file
  system contexts) share one inode, as Linux's `anon_inode_getfd` gives
  them: `fstat` and a BPF map's mappings in `/proc/<pid>/maps` show the
  anonymous inodes' device and that inode's number, which, as on Linux, is
  taken once like a pipe's. Opening a link opens the file again by its path, or, for a
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
  `O_PATH` descriptor of anything else; for a link of a process's `/proc`
  directory, `fd/<n>`, `exe`, `cwd` or `root`, where it leads at that
  moment, of the process that opened it and as the reader's root shows it,
  as Linux's `proc_pid_readlink` reads it), whose own link names the link, and
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
  mapping of `zero` is anonymous memory, shared with `MAP_SHARED`.
  `userfaultfd` is root's misc device (10:122, mode 0600), which opens for
  whoever its mode lets (`EACCES`) and makes `userfaultfd` contexts (see
  `userfaultfd` above). `fd`,
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
  guest thread's start to its end, where the host can measure it (Linux,
  macOS, Windows); elsewhere, as in WebAssembly, it is wall time instead.
  `CLOCK_THREAD_CPUTIME_ID` reads the thread's, and `CLOCK_PROCESS_CPUTIME_ID`
  the sum of the process's threads. A thread's clock read by another thread,
  a process's, `/proc`, `getrusage`, `times`, a wait's rusage and a `perf`
  clock show what a thread that runs without a system call has used by
  then, as `task_sched_runtime` does, and a thread that ended its last time;
  none of them goes back. What the emulator's own threads use, such as the
  JIT's that compiles in the background, is no guest thread's and is not
  counted. A child starts from zero, and its time joins its parent's children's when it
  is waited for. `getrusage`, `times` and the rusage of `wait4` and `waitid`
  report it all as user time, as the emulator's work for system calls runs
  in the host's user space. Their `ru_maxrss` is the peak resident size in
  KiB, the same peak `VmHWM` shows: for the process (`RUSAGE_SELF`, and
  `RUSAGE_THREAD` too), the largest of its address space's and of those it
  left by `execve` or exited in; for `RUSAGE_CHILDREN`, the largest of the
  children waited for and of their own children; and a wait's rusage gives
  the child's and its children's together, as Linux's `RUSAGE_BOTH`, the
  CPU time as well as `ru_maxrss`, a tracer's wait for a tracee too. A
  forked child starts from zero, and an `execve` keeps both. Their
  `ru_minflt` counts the minor faults, as Linux's `mm_account_fault` adds
  them to the task: a thread's first read or write of a page and its write
  to a page `fork` shares or of a private mapping of a file (in its own code
  and in the kernel's accesses for it: a system call's copies, a signal
  frame, an `rseq` area's update), each as it is taken, and the faults of the reads and writes
  through `get_user_pages` made for it, which `perf` does not count:
  `mlock`'s, `mlockall`'s and `MAP_POPULATE`'s population,
  `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE`, `process_vm_readv` and
  `process_vm_writev` (counted to the caller), a tracer's `PTRACE_PEEKDATA`
  and `PTRACE_POKEDATA` (counted to the tracer) and a core dump's (counted
  to the thread the signal ended, which dumps while the others wait,
  regardless of which thread exits last; it leaves private anonymous memory never touched
  a hole, with no fault). An instruction of its code that reads and writes
  its operand takes one fault, a write, as x86-64's do. `RUSAGE_SELF` gives the sum of the
  process's threads, `RUSAGE_THREAD` the thread's, and `RUSAGE_CHILDREN` and
  a wait those of the children as with the CPU time; a forked child starts
  from none, and an `execve` keeps them. `ru_nvcsw` counts the voluntary
  context switches, the times a thread went to sleep, as Linux's `nvcsw`,
  for the same processes and threads and with a wait's and
  `RUSAGE_CHILDREN`'s the children's (`cnvcsw`), as of each thread's latest
  system call. `ru_majflt` counts the major faults, for the same processes
  and threads and children (`cmaj_flt`): the faults of the kernel's
  accesses that a `userfaultfd` had try again, as described for
  `userfaultfd`, each counted once as its retry completes, and to no
  minor fault. The other counts (involuntary context switches, blocks) are 0.
  `/proc/<pid>/stat` gives the same counts as `minflt` and `majflt` (a
  thread's own under `task`) and `cminflt` and `cmajflt`.

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
  fall on whole multiples of it on the monotonic clock, both coarse clocks
  moving at the same instant, as Linux's timekeeping updates both at each
  tick. `clock_getres` gives 1 ns,
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
  process and threads, and of other processes, by number; a timer on
  another process's CPU time is expired by that process's checkpoints
  while it is armed, as Linux's tick of that process expires it, and its
  signal comes to the process that made it; once that process is reaped
  the timer gives `ESRCH` to set and shows nothing. It finds the task after the ID is out,
  as Linux's `posix_cpu_timer_create` does, so a task that is not there
  gives `EINVAL` with the ID used up. A dynamic clock has no timers and
  cannot sleep (`EOPNOTSUPP`). A sleep on a CPU clock by number reads its
  request, refuses the caller's own thread's clock (`EINVAL`) and then a
  task that is not there (`EINVAL`); then it sleeps as below, until the
  caller's process, another process (a zombie's clock does not move) or
  another thread of the caller's process has used the time, that task's
  threads accounting their CPU time while it waits. A task that goes while
  it waits leaves the sleep to a signal, which ends it as it ends any but
  with the whole request as the time left, as Linux's `do_cpu_nanosleep`
  copies out what it was asked once `posix_cpu_timer_set` finds no task;
  a restart after a stop then finds no task (`EINVAL`).

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
  as Linux's `alarm_setitimer`. Any wait a signal ends, `wait4`'s and
  `waitid`'s too, ends as a timer's signal comes. The waits only a fatal
  signal ends (a `vfork` parent's, a fanotify permission event's, a seccomp
  listener's with `WAIT_KILLABLE_RECV` and the kernel's own for a
  `userfaultfd`) end for a timer's too, but not for a signal that dumps core
  (`complete_signal` makes the others `SIGKILL`).

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

- `adjtimex` and `clock_adjtime` on `CLOCK_REALTIME` read the clock's NTP
  state. On native Linux the real-time clock is the host's, and so is its
  state: the host's result, status, errors, corrections, tick and TAI
  offset, as the host's own `adjtimex` reads them. Elsewhere (WebAssembly,
  macOS, Windows, or a host whose sandbox refuses even that read) it is the
  state Linux starts with: unsynchronised
  (`STA_UNSYNC`, so the result is `TIME_ERROR`), the errors at 16 s, no
  offset or frequency correction, a time constant of 2, a 10,000 µs tick and
  no PPS or TAI offset. The time is the real-time clock's, in nanoseconds
  when the status has `STA_NANO`. They take
  only reads (no mode, or adjtime's `ADJ_OFFSET_SS_READ`), after Linux's
  checks of the modes; `adjtimex` writes the structure back whatever the
  result, and `clock_adjtime` reads it before it looks at the clock (other
  clocks give `EOPNOTSUPP`, or `EINVAL` for unknown ones). `settimeofday` and
  `clock_settime` (only on `CLOCK_REALTIME`, or `EINVAL`) check the time as
  Linux does, `EINVAL` past 30 years short of `KTIME_MAX`, and then give
  `EPERM`.

- `sysinfo` reports a fixed 4 GiB of free memory and no swap, without
  revealing the host's; the uptime is the monotonic clock's, rounded up to
  a whole second as Linux rounds it.

- `iopl` and `ioperm` check their arguments as Linux does (a level past 3,
  or a range that is empty or goes past port 65,535, gives `EINVAL`), keep
  the thread's level of 0 and give up ports it never had, and give `EPERM`
  for anything more, as a kernel locked down against port access does.
  `acct` needs `CAP_SYS_PACCT` (`EPERM`), and then turns accounting off,
  which is never on, or gives `EPERM` for a file.

- `syslog` reads a kernel log that is empty, as nothing writes to it. As
  with Ubuntu's `kernel.dmesg_restrict` of 1, every action needs
  `CAP_SYSLOG` (`EPERM`). Then, as Linux's `do_syslog`, an unknown action
  or a console level outside 1 to 8 is `EINVAL`; a read wants a buffer and a
  length that is not negative (`EINVAL`), and a buffer in the user half
  (`EFAULT`). `SYSLOG_ACTION_READ` waits for a message that never comes,
  until a signal (`ERESTARTSYS`); the other reads copy nothing and give 0.
  The buffer size is 256 KiB (`CONFIG_LOG_BUF_SHIFT` 18), and nothing is
  unread.

- `sysfs` numbers the file system types: `tmpfs`, `proc`, `sockfs`, `bpf`,
  `pipefs`, `devpts`, `ext4` and `mqueue`, the types of the files paludarium
  gives (a host file's as `ext4`), in the order Linux registers them. Option
  1 gives a name's index, 2 copies an index's name and 3 gives the count; an
  unknown option, name or index is `EINVAL`, and a name that does not end
  within `PATH_MAX` bytes too.

- The security modules are the ones paludarium has, in the order Linux
  starts them with Ubuntu's configuration: Lockdown (an early module there,
  whose port access paludarium refuses), the capability module, Landlock
  and Yama, which
  `lsm_list_modules` lists (`E2BIG` with the size they take for a smaller
  buffer). None of them keeps an attribute of a task, so
  `lsm_get_self_attr` and `lsm_set_self_attr` give `EOPNOTSUPP` (and a size
  of 0) once their arguments pass Linux's checks, in its order.

- No uprobe is ever set, so there is no probe trampoline: `uretprobe` forces
  `SIGILL` (`SI_KERNEL`) and returns -1, and `uprobe` gives `EPROTO`, as
  Linux does when they are called from anywhere else.

- The administration calls take Linux master's checks in its order, on a
  kernel locked down for integrity, as Ubuntu's is under Secure Boot (and as
  `iopl` and `ioperm` refuse port access): nothing can load code into it, and
  no file system has swap or quotas, as tmpfs has neither.
  - `reboot` needs `CAP_SYS_BOOT` in the user namespace that owns the
    caller's PID namespace (`EPERM`) and Linux's magic numbers (`EINVAL`).
    A restart (`LINUX_REBOOT_CMD_RESTART` or `RESTART2`) kills the
    namespace's init, which then ends with `SIGHUP`, and a halt or power-off
    likewise with `SIGINT`, as Linux's `reboot_pid_ns` does; the calling
    thread ends with status 0. In a nested PID namespace any other command
    is `EINVAL`. In the first namespace its init is the first process, so the
    run ends; `RESTART2`'s string is read first (`EFAULT`). There,
    `CAD_ON` and `CAD_OFF` succeed, `KEXEC` finds no kernel loaded
    (`EINVAL`) and `SW_SUSPEND` cannot hibernate a locked-down kernel
    (`EPERM`).
  - `swapon` checks its flags (`EINVAL`) and `CAP_SYS_ADMIN` (`EPERM`),
    opens the path for reading and writing with that open's errors, and then
    gives `EINVAL`, as tmpfs has no page reads for swap. `swapoff` checks
    `CAP_SYS_ADMIN`, opens the path, and gives `EINVAL`, as no swap is on.
  - `init_module`, `finit_module` and `delete_module` need
    `CAP_SYS_MODULE` (`EPERM`). `init_module` refuses an image shorter than
    an ELF header (`ENOEXEC`) and reads it (`EFAULT`); `finit_module`
    checks its flags (`EINVAL`) and reads its file as Linux's
    `kernel_read_file` does (`EBADF` for a descriptor not open for reading,
    `EINVAL` for one that is not a regular file or is empty). Then a
    signature that `mod_check_sig` refuses gives its error (`EBADMSG`,
    `ENOPKG`), and any other module `EPERM`, as no key verifies it and
    lockdown refuses an unsigned one. `delete_module` reads the name
    (`EFAULT`) and finds no module (`ENOENT`).
  - `kexec_load` needs `CAP_SYS_BOOT`, and lockdown then refuses it
    (`EPERM` either way). `kexec_file_load` needs `CAP_SYS_BOOT` (`EPERM`)
    and known flags (`EINVAL`); `KEXEC_FILE_UNLOAD` succeeds, as nothing is
    loaded. Otherwise the kernel's file is read as `finit_module`'s, a file
    that is not a 64-bit bzImage that can load above 4 GiB is `ENOEXEC`, and
    one that is gives `EPERM`, as no key verifies it.
  - `quotactl` checks the quota type (`EINVAL`); with no device `Q_SYNC`
    succeeds and anything else is `ENODEV`, and a device path is looked up
    with its errors and is `ENOTBLK`, as nothing is a block device.
    `quotactl_fd` takes any descriptor (`EBADF`), checks the type
    (`EINVAL`) and gives `ENOSYS`, as Linux's `do_quotactl` does for a file
    system without quotas.

- `perf_event_open` checks its arguments in the order of Linux's
  `kernel/events/core.c`: unknown flags, then the structure
  (`perf_copy_attr`: a size of 0 is the first one's 64 bytes, less than that
  or more than a page `E2BIG`, which writes back the size Linux master
  knows, 176, as does a larger one with bytes past that which are not 0;
  then the reserved fields, unknown sample and read formats, branch
  sampling without a branch, register masks with DS, ES, FS, GS or the
  reserved bits, a user stack too large or not 8-byte aligned, both
  weights, `inherit_thread` without `inherit`, `remove_on_exec` with
  `enable_on_exec`, and `sigtrap` without `remove_on_exec`, all `EINVAL`),
  then the machine's `perf_event_paranoid` (2, Linux's default, until root
  writes `/proc/sys/kernel/perf_event_paranoid`): above 1, an event of the
  kernel (one without `exclude_kernel`, `text_poke`, a kernel callchain,
  physical addresses, kernel or hypervisor branches), and above 0, one of a
  CPU, need `CAP_PERFMON` or `CAP_SYS_ADMIN` (`EACCES`); `namespaces`
  always does. Then a
  period with bit 63 or a frequency above `perf_event_max_sample_rate`
  (100000 at first) is `EINVAL`, `PERF_FLAG_PID_CGROUP` without a CPU and a task
  `EINVAL`, a group descriptor that is no event `EBADF`, a task that is not
  there `ESRCH`, no task and no CPU or a CPU past the last `EINVAL`, and an
  unknown `clockid` `EINVAL`. The events that count are the software
  `cpu-clock` and `task-clock`, in nanoseconds of the thread's CPU time (an
  event of a CPU counts the time that passes, and of the counts below those
  of every thread of the machine there, an ended one's too, and samples each
  thread's); a thread's `page-faults` and
  `minor-faults` (a first read or write of a page, and a write to a page
  `fork` shares or a private mapping of a file's: the faults of the
  thread's code, left out with `exclude_user`, and those of the kernel's
  accesses for it, a system call's copies, a signal frame or an `rseq`
  area's update, left out with `exclude_kernel`), `context-switches` (each time it
  sleeps) and `cpu-migrations` (each time the CPU `getcpu` reports
  changes), the last two made by the kernel and so left out with
  `exclude_kernel`, as Linux leaves them out; `major-faults` (the faults of
  the kernel's accesses that a `userfaultfd` had try again, which
  `page-faults` counts too and `minor-faults` does not; `page-faults`
  alone counts a fault of the thread's code whose `userfaultfd` wait a
  signal ends, as it is not tried again, and one that ends in `SIGSEGV`
  or `SIGBUS`, as Linux counts a fault of a user address or the
  `vsyscall` page as it starts and no fault that fails in the others, and
  so does a fault of a kernel access that fails, as a system call's copy
  does with `EFAULT`; a kernel address counts nothing, and so does a
  system call's access past user space, which `access_ok` refuses, or one
  with faults disabled); and
  `alignment-faults`,
  `emulation-faults`, `dummy` and `bpf-output`, which count nothing, as on
  x86-64. An event of a thread on one CPU, as `perf record` opens one for
  each, counts and runs only while the thread is on that CPU
  (`event_filter_match`), and is enabled all the while; a migration counts
  on the CPU the thread comes to, and `sched_setaffinity` moves the thread
  before it returns, another thread's too: its faults and the time it runs
  are the new CPU's at once (a sleep it made before counts where it slept). Branch sampling or the XMM registers of one is
  `EOPNOTSUPP`. Hardware, cache and raw events are `ENOENT`, as on a machine without a
  PMU. An event of another process needs `CAP_PERFMON` or to be able to
  read it (`ptrace_may_access`, `EACCES`). `read` gives the count with the
  times enabled and running, the ID and the lost samples as the read
  format asks, and with `PERF_FORMAT_GROUP` the whole group's, `ENOSPC` for
  a buffer too small. A group member must be of its leader's task, CPU and
  clock, and neither pinned nor exclusive (`EINVAL`); it counts only while
  its leader is enabled. The ioctls `PERF_EVENT_IOC_ENABLE`, `DISABLE` and
  `RESET`, each of the event or with `PERF_IOC_FLAG_GROUP` of its group,
  and `PERF_EVENT_IOC_ID` are there; `PERIOD` is `EINVAL` for an event
  that does not sample, and gives a sampling event a new period (or with
  `freq` a new frequency) that starts over; `REFRESH` is `EINVAL` for an
  event that does not sample or that new tasks inherit, and else allows
  that many more overflows and enables the event (`event_limit`): the
  last of them disables it, its count stopped there, and signals
  `POLL_HUP`. `enable_on_exec` enables a disabled
  event when its task runs `execve`, as `perf stat` uses it, and
  `remove_on_exec` takes one out then for good, as Linux master does: it
  counts no more, keeps its last count and times to be read, has no owner
  any more and leaves its group, whose members, if it led one, each count
  on their own; such an event leads no new group (`ENODEV`). A thread that
  ends without an `execve` owns the events it opened no more
  (`perf_event_exit_task`), and the events that count it go to Linux's
  `EXIT` state: they count no more, keep their last count and times to be
  read, stay in their group and lead no new group (`ENODEV`). With
  `inherit`, a new thread or process inherits the groups that count the
  thread that makes it, as `perf_event_init_task` does: each event of them
  gets one of its own, counting the new task, enabled as the one it comes
  from is. `inherit_thread` keeps them from a new process, and `sigtrap`
  from `CLONE_CLEAR_SIGHAND`. A read of the opened event adds in the
  inherited ones and what those of tasks that ended gave back, counts and
  times, a group's member by member (`ECHILD` for a group whose members
  changed since a task inherited it). With `inherit_stat`, the end of a
  task writes `PERF_RECORD_READ` of each event it inherited, with the count
  and times that event alone has (`perf_event_read_event`), the latest
  first, each then out of its group. Its `ENABLE`, `DISABLE` and `RESET`
  (which keeps what ended tasks gave back), and the `prctl` below, reach
  the inherited events too. `prctl`'s
  `PR_TASK_PERF_EVENTS_DISABLE` and `ENABLE` disable and enable every
  event the calling thread opened, whatever task it counts (one opened
  disabled too), and read no other argument; a thread that runs `execve`
  keeps the events it opened. With `sample_simd_regs_enabled`, the SIMD
  register fields of Linux master's structure are checked as x86's
  `perf_simd_reg_validate` checks them (`EINVAL`): XMM or YMM (2 or 4
  quadwords) all 16 registers, ZMM (8) all 32, the opmask ones (1) all 8,
  or none; a valid use of them is `EOPNOTSUPP`, as a software event takes
  none. `mmap` of an event maps its ring buffer, as Linux's
  `perf_mmap`: a shared mapping (`EINVAL`) of a user page and a power of
  two of data pages, or none (`EINVAL`), and none of an event of every CPU
  that new tasks inherit (`EINVAL`). The first mapping makes the buffer; a
  later one must be as large (`EINVAL`) and shares it. An offset past the
  buffer asks for its AUX area, which must lie where the user page's
  `aux_offset` and `aux_size` put it, past the data pages, a power of two
  of pages (`EINVAL`); a software event has none (`EOPNOTSUPP`). The
  pages are charged to the mapping's user up to `perf_event_mlock_kb` for
  each CPU, and the rest to the address space's pinned pages, which may
  not pass `RLIMIT_MEMLOCK` (`EPERM`) unless `perf_event_paranoid` is -1
  or the caller has `CAP_IPC_LOCK`; a later mapping is charged to the user
  too and never given back, as in Linux master. The mapping is not copied
  to a `fork`ed child nor held in a core dump (`VM_DONTCOPY`,
  `VM_DONTDUMP`), and is memory of no pages (`VM_IO | VM_PFNMAP`), which
  `get_user_pages` refuses: `process_vm_readv` and `process_vm_writev`
  give `EFAULT` for it, `PTRACE_PEEKDATA` and `PTRACE_POKEDATA` `EIO`, and
  `MADV_POPULATE_READ` and `MADV_POPULATE_WRITE` `EINVAL`. It keeps the
  event counting though its descriptors are closed; its last unmapping
  frees the buffer and its charges. It is a
  mapping of the event's file, which `/proc/<pid>/maps` and the `MMAP2`
  records name `anon_inode:[perf_event]` with the device and inode its
  descriptor's `fstat` gives, the anonymous inodes' one. It keeps
  Linux's rules for a `VM_PFNMAP` mapping (`perf_mmap_vmops`): its data
  pages are read-only, a write to one raising `SIGBUS`; no part of it is
  unmapped, mapped over, moved, given another protection or other flags,
  or sealed on its own (`EINVAL`), though a part that the call would not
  change takes it; and as memory core mm does not back, it takes no
  `MADV_DOFORK` or `MADV_DODUMP`, gives `MADV_DONTNEED` and
  `MADV_DONTNEED_LOCKED` no pages (`EINVAL`), and stays unlocked through
  `mlock`. The user page is `struct perf_event_mmap_page`: version 0,
  `size` 96, the data's offset and size, `cap_bit0_is_deprecated` and no
  `cap_user_rdpmc`, index 0, and the count and times enabled and running
  between two bumps of the sequence lock. These are updated at the
  `mmap`, the event's enabling and its reset, and when its thread runs
  again after a sleep or a move to another CPU, where Linux schedules the
  event in (`perf_swevent_add`, a clock's `add`); a system call that does
  not sleep leaves them. `PERF_EVENT_IOC_SET_OUTPUT`, and
  `PERF_FLAG_FD_OUTPUT` at open through the group's descriptor, make an
  event write to another event's buffer, as Linux's
  `perf_event_set_output`: the other must be an event (`EBADF`), not the
  same one, of the same CPU, of the same task for an event of every CPU,
  with the same clock and `write_backward`, and have a buffer, its own or
  one it writes to; the event may not map a buffer of its own
  (`EINVAL`), and -1 (`SET_OUTPUT` alone) makes it write to none. Such an
  event shares the user page, but a mapping of it is `EBUSY` (`EINVAL`
  for another size), and when the buffer's last mapping goes, every event
  that wrote to it is free again. A sampling event writes a
  `PERF_RECORD_SAMPLE` to its buffer at each overflow, as Linux's
  `perf_swevent_event` and `perf_swevent_hrtimer`: every `sample_period`
  occurrences, each one with `PERF_SAMPLE_PERIOD` (of a period of 1), or
  for `cpu-clock` and `task-clock` every period of nanoseconds of its count
  and at least every 10 µs; with `freq`, a clock's period is a second over
  the frequency, and another event's starts at 1 and moves an eighth of the
  way to the rate it counts at (`perf_adjust_period`). The sample has the
  fields `sample_type` asks for in `perf_output_sample`'s order: the
  identifier, address, process and thread in the opener's PID namespace,
  time on the event's clock, ID and stream ID, CPU, period, the values
  `PERF_SAMPLE_READ` reads (with `PERF_FORMAT_GROUP` the group's), the
  callchain (`PERF_CONTEXT_USER`, the address and the return addresses the
  `rbp` chain leads to, up to `sample_max_stack`, which is
  `perf_event_max_stack` (127) when 0, and more is `EOVERFLOW`), empty raw
  data, the user registers of the mask and a dump of the user stack as far
  as its pages are in memory, and the rest as a software event has them
  (no weight, data source `PERF_MEM_NA`, the root cgroup). A record goes in
  where the reader has left room (`data_tail`), forward or with
  `write_backward` back from 0; one that finds none is lost and counted,
  and the next that fits follows a `PERF_RECORD_LOST` of them, with the
  `sample_id` that `sample_id_all` adds. A buffer mapped read-only
  overwrites what it holds and loses nothing. `PERF_EVENT_IOC_PAUSE_OUTPUT`
  pauses and resumes the buffer (`EINVAL` without one, or for one of no
  data pages), which counts what it does not take as lost. An inherited
  event writes to the buffer of the one it comes from. Every
  `wakeup_events` samples, or with `watermark` every `wakeup_watermark`
  bytes (half the data without one), the buffer wakes those who wait for
  it in `poll` or `epoll`: it is readable (`POLLIN`) once, as
  `perf_poll` takes what the wakeup left, until the next. An event
  without a buffer, and one whose task has ended with no inherited events
  left, is hung up (`POLLHUP`). With `O_ASYNC`, each overflow signals the
  file's owner (`F_SETOWN`) with `POLL_IN`, `F_SETSIG`'s signal carrying
  `si_code`, `si_band` and `si_fd`, with or without a buffer; and with
  `sigtrap`, an overflow sends the thread SIGTRAP of `TRAP_PERF` with
  `sig_data` and the event's type in `si_perf_data` and `si_perf_type`, the
  fault's address in `si_addr` as a sample has it with
  `PERF_SAMPLE_ADDR`, and `TRAP_PERF_FLAG_ASYNC` if the thread blocks it. An event
  that asks for them takes side-band records, as `perf_iterate_sb` gives
  them to the enabled events of the CPU (pid -1) of the thread that makes
  them, whatever process it is of, and then to those that count the thread,
  the latest first, each with that thread's `sample_id` (`EXIT` goes to the
  thread's first), those of mappings while an event with `mmap` or
  `mmap_data` is open, enabled or not (`nr_mmap_events`, which `mmap2` alone
  does not raise): `PERF_RECORD_MMAP` (`mmap`) or `MMAP2`
  (`mmap2`) of an executable mapping, and with `mmap_data` of any other
  (`PERF_RECORD_MISC_MMAP_DATA`), as `mmap`, `brk`'s growth, `shmat`,
  `remap_file_pages` and `mprotect` (of each VMA whose protection it
  changed, in turn) leave the VMA, merged with its neighbours, with its address,
  length and offset (a file's, and the address of private anonymous
  memory), and for `MMAP2` its file's device and inode, its protection and
  sharing, and the name `d_path` gives (`[heap]`, `[stack]`, `//anon`,
  `/dev/zero (deleted)` for shared anonymous memory). With `build_id`, as
  `perf record` asks by default, an `MMAP2` record of an ELF executable
  or shared object gives its GNU build ID in place of the device and inode
  (`PERF_RECORD_MISC_MMAP_BUILD_ID`: its size, three zero bytes and 20
  bytes), as Linux's `build_id_parse_nofault` finds it in the first 256
  program headers' `PT_NOTE`s; none comes of secret memory or of a page a
  tmpfs file or memfd does not hold, as Linux reads only the page cache;
  `PERF_RECORD_COMM`
  (`comm`) of `PR_SET_NAME`, of a write to `/proc/<pid>/comm` (to the events
  that count the writer, of the thread it renames) and of `execve`
  (`PERF_RECORD_MISC_COMM_EXEC`), which then writes the new program's stack
  and mappings; and
  `PERF_RECORD_FORK` and `EXIT` (`task`, or any of the others) of a thread
  that is made or ends; with `namespaces` (which takes `CAP_PERFMON`),
  `PERF_RECORD_NAMESPACES` of a thread's namespaces, the device and inode
  of each of its `/proc/<pid>/ns` files of net, uts, ipc, pid, user, mnt
  and cgroup: of a new thread or child, written by its creator, and of a
  thread after each `unshare` that succeeds, new namespaces or not, and
  each `setns`; and with `context_switch`, `PERF_RECORD_SWITCH`
  (`SWITCH_CPU_WIDE` for an event of a CPU, with the thread that ran
  instead) of each sleep of a thread, one with `PERF_RECORD_MISC_SWITCH_OUT`
  and one without it as it runs again, and one without it alone for a new
  thread's or child's first run, which inherited events take. A
  `cpu-clock` or `task-clock` event whose interrupts in a tick reach
  `perf_event_max_sample_rate` over `HZ` is throttled until the next tick,
  its count stopped meanwhile, with
  `PERF_RECORD_THROTTLE` and `UNTHROTTLE` of its group's leader (its time,
  ID and `stream_id`). It stops its group's other clocks too
  (`perf_event_throttle_group`): they leave that time out of their counts,
  and one that samples starts again with a whole period. The descriptor's link is `anon_inode:[perf_event]`, it is open for reading
  and writing, and a write is `EINVAL`. See [limitations](./limitations)
  for what is not there.

- `bpf` has maps, as Linux's `kernel/bpf/syscall.c`, `arraymap.c`,
  `hashtab.c`, `bpf_lru_list.c`, `lpm_trie.c`, `queue_stack_maps.c` and
  `bloom_filter.c` have them. Every command first takes the size of its union
  (more than a page, or bytes past Linux master's 168 that are not 0, is
  `E2BIG`) and its fields past the command's own (`CHECK_ATTR`, `EINVAL`).
  `BPF_MAP_CREATE` makes a `BPF_MAP_TYPE_ARRAY` (4-byte keys, every
  element there and zero from the start) or a `BPF_MAP_TYPE_HASH`, in the
  order of Linux's checks: BTF type IDs, `map_extra`, the NUMA node (there
  is one), the type, the type's own sizes and flags (`EINVAL`, too large a
  hash element `E2BIG`, `BPF_F_ZERO_SEED` without `CAP_SYS_ADMIN`
  `EPERM`), the machine's `kernel.unprivileged_bpf_disabled` (2, Linux's
  default, until root writes it), with which, unless it is 0, a map needs
  `CAP_BPF` or `CAP_SYS_ADMIN` (`EPERM`), the name
  (letters, digits, `_` and `.`), BTF (no file is, `EINVAL`), and
  `BPF_F_RDONLY` with `BPF_F_WRONLY` (`EINVAL`). The descriptor is
  close-on-exec, open for reading, writing or both as `BPF_F_RDONLY` and
  `BPF_F_WRONLY` say, its link is `anon_inode:bpf-map`, and a read or write
  of it is `EINVAL`. `BPF_MAP_LOOKUP_ELEM`, `UPDATE_ELEM` (`BPF_ANY`,
  `BPF_NOEXIST`, `BPF_EXIST`; a full hash is `E2BIG`, an index past an
  array's end `E2BIG`), `DELETE_ELEM` (`EINVAL` for an array),
  `GET_NEXT_KEY`, `LOOKUP_AND_DELETE_ELEM` (the kernel's `ENOTSUPP`, 524,
  for an array) and `BPF_MAP_FREEZE` (which stops writes through every
  descriptor, so that a second one is `EPERM` too) take the access the descriptor has
  (`EPERM`). The batch commands look up, update, delete and look up and
  delete by count, with `count` written back (an array deletes nothing,
  `ENOTSUPP`). `BPF_OBJ_GET_INFO_BY_FD` gives a map's `struct bpf_map_info`
  up to the length asked for (`EBADFD` for no descriptor, `EINVAL` for one
  of no map). Every map has an ID of the machine's, handed out from 1 up
  as Linux's `idr_alloc_cyclic` does and freed as the map's last
  reference goes: `BPF_MAP_GET_NEXT_ID` gives the first one past
  `start_id` (`ENOENT` past the last, `EINVAL` from `INT_MAX`) and
  `BPF_MAP_GET_FD_BY_ID` a new close-on-exec descriptor of a map, open as
  `open_flags` (`BPF_F_RDONLY` or `BPF_F_WRONLY`) asks (`ENOENT` for an ID
  no map has); both need `CAP_SYS_ADMIN` (`EPERM`), after their fields are
  checked (`EINVAL`). A map takes the memory the x86-64 test machines'
  kernel, Ubuntu's Linux 7.0, gives it on x86-64: an array its 312-byte header and
  every value rounded up to 8 bytes (a mappable one each page-aligned), a
  hash its 896-byte header, 16 bytes a bucket (as many as `max_entries`
  rounded up to a power of two; more than 2^31 entries, or buckets past
  4 GiB, are `E2BIG`) and its elements, 48 bytes and the key and value
  each rounded up to 8: every one and a spare a CPU, with 8 bytes a CPU
  for it, when preallocated, or those it holds and 8 bytes each with
  `BPF_F_NO_PREALLOC`. A map whose memory is more than the machine's
  (`sysinfo`'s 4 GiB), checked as `vmalloc` checks it, is `ENOMEM`. Its
  fdinfo has `map_type`, `key_size`, `value_size`, `max_entries`,
  `map_flags`, `map_extra`, `memlock` (that memory), `map_id` and
  `frozen`. An array made with `BPF_F_MMAPABLE` maps with `mmap`, as
  Linux's `bpf_map_mmap` and `array_map_mmap` map it: a shared mapping of
  its values, each `value_size` rounded up to 8 bytes from the last, that
  shows what the system calls and programs read and write. It reaches no
  further than the values, rounded up to a page (`EINVAL`). Another map
  type is the kernel's `ENOTSUPP` (524), and an array without the flag
  `EINVAL`; so is a private mapping, or a shared one of a descriptor open
  only for reading, while one of a descriptor open only for writing is
  `EACCES` and one that executes `EPERM`. A mapping that writes may not be
  of a frozen map (`EPERM`) or of one made with `BPF_F_RDONLY_PROG`
  (`EACCES`), and while one lasts, a child's copy included,
  `BPF_MAP_FREEZE` is `EBUSY`. The VMA, which `/proc/<pid>/maps` names
  `anon_inode:bpf-map`, is `VM_DONTEXPAND`, `VM_DONTDUMP` and
  `VM_MIXEDMAP`, never executes, and never writes unless it was mapped to
  (`mprotect` gives `EACCES`); it keeps the map after the map's
  descriptors close. A `BPF_MAP_TYPE_LRU_HASH` is a hash that, when full, gives up
  a key for a new one instead of `E2BIG`, as Linux's `bpf_lru_list.c`
  chooses it: its elements move between the free, active and inactive
  lists and a CPU's local free and pending lists, so that the key that
  goes is the one Linux gives up, also when an update is refused or
  replaces a key, which takes an element first. It needs `CAP_BPF` even
  where any user may make maps (`EPERM`), is always preallocated
  (`BPF_F_NO_PREALLOC` is `ENOTSUPP`), and with `BPF_F_NO_COMMON_LRU` keeps
  lists for each CPU (`max_entries` rounded up to a multiple of the CPUs,
  as many for each; with `BPF_F_NUMA_NODE` `EINVAL`). It takes the memory
  of its elements alone, with no spares. `BPF_MAP_TYPE_QUEUE` and
  `BPF_MAP_TYPE_STACK` hold values without keys (`key_size` 0, and a key
  pointer that is not null is `EINVAL`), as Linux's `queue_stack_maps.c`:
  `UPDATE_ELEM` pushes (a full one is `E2BIG`, unless `BPF_EXIST` makes room
  by giving up the oldest; `BPF_NOEXIST` is `EINVAL`), `LOOKUP_ELEM` peeks
  and `LOOKUP_AND_DELETE_ELEM` pops, a queue its oldest value and a stack
  its newest (`ENOENT` for none); `DELETE_ELEM` and `GET_NEXT_KEY` are
  `EINVAL` and the batch commands `ENOTSUPP`. They need `CAP_BPF`, take
  only `BPF_F_NUMA_NODE` and the access flags, and refuse a value past
  4 MiB or `max_entries` times the value size past 32 bits (`E2BIG`, as
  Linux master). One takes a 312-byte header and `max_entries + 1` value
  slots. A `BPF_MAP_TYPE_BLOOM_FILTER` takes values without keys too, as
  Linux's `bloom_filter.c`: `UPDATE_ELEM` (`BPF_ANY` alone) sets a bit for
  each of its hashes (`map_extra`'s low four bits, 5 for 0; more bits are
  `EINVAL`), and `LOOKUP_ELEM` reads the value and says whether every bit
  is set (`ENOENT` if not), writing nothing back. The hashes are Linux's
  `jhash2` of a value of whole words, `jhash` of any other, with a random
  seed, or 0 with `BPF_F_ZERO_SEED`, so a filter with it gives the same
  false positives as Linux. The bits are `max_entries` times the hashes,
  times 7 / 5, a power of two of at least 64 (2^32 past 2^31). `DELETE_ELEM`
  and `GET_NEXT_KEY` are `EOPNOTSUPP`, `LOOKUP_AND_DELETE_ELEM` and the batch
  commands `ENOTSUPP`; it needs `CAP_BPF`, and takes a 312-byte header and
  its bits in 8-byte words. `map_extra` is in its fdinfo and
  `bpf_map_info`. A `BPF_MAP_TYPE_LPM_TRIE` holds prefixes, as Linux's
  `lpm_trie.c`: a key is a prefix length (a `u32`) and 1 to 256 bytes of
  data, the most significant first, and `LOOKUP_ELEM` gives the value of
  the longest prefix that holds the key's (`ENOENT` for none, and for a
  prefix length past the data's bits). `GET_NEXT_KEY` gives the keys in
  Linux's order: of two prefixes where one holds the other, the more
  specific first, and otherwise the one whose first differing bit is 0
  (from the first
  for no key, a prefix length past the data's bits, or a key that is no
  element's), each with the bytes past its prefix that its last update
  gave. `UPDATE_ELEM` takes `BPF_ANY`, `BPF_NOEXIST` and `BPF_EXIST`
  (`EINVAL` for any other flag and for a prefix length past the data's
  bits; a full one is `ENOSPC`), `DELETE_ELEM` takes the exact prefix
  (`ENOENT` for none), `LOOKUP_AND_DELETE_ELEM` and its batch are
  `ENOTSUPP`, and the other batch commands follow the next keys. It needs
  `CAP_BPF` and `BPF_F_NO_PREALLOC`, takes only that, `BPF_F_NUMA_NODE`
  and the access flags, and a value of 1 byte up to 4 MiB less 280
  (`EINVAL`). Its memory is 24 bytes, the data and the value for each
  element, with nothing for its header or intermediate nodes. A
  `BPF_MAP_TYPE_ARRAY_OF_MAPS` or `BPF_MAP_TYPE_HASH_OF_MAPS` holds other
  maps, as Linux's `map_in_map.c`: its value is a 4-byte descriptor (any
  other size is `EINVAL`), and the map of `inner_map_fd` is the template its
  maps must be like (no descriptor is `EBADF`, one of no map `EINVAL`, and
  a map of maps `EINVAL`, for there is one level alone). A map fits when its
  type, key and value sizes and flags are the template's, and an array its
  entries too unless the template has `BPF_F_INNER_MAP` (`EINVAL` if not).
  `UPDATE_ELEM` takes the descriptor of such a map, `LOOKUP_ELEM` gives the
  ID of the map an element holds, and the outer map keeps its maps after
  their descriptors close, until they are deleted or replaced. An array of
  maps takes `BPF_ANY` alone (`EINVAL`, before the descriptor is looked at)
  and an index below `max_entries` (`E2BIG`); an index that holds no map is
  `ENOENT`, its next keys are an array's, a batch lookup passes over the
  indexes that hold none, and it has no batch delete (`ENOTSUPP`). It takes
  neither `BPF_F_RDONLY_PROG`, `BPF_F_WRONLY_PROG`, `BPF_F_MMAPABLE` nor
  `BPF_F_INNER_MAP` (`EINVAL`). A hash of maps looks at the descriptor
  before its flags, which are a hash's; it has a hash's batch commands but
  no `LOOKUP_AND_DELETE_ELEM` (`ENOTSUPP`), and preallocated it counts no
  spare elements. Neither needs `CAP_BPF`. A map made with `excl_prog_hash`
  is no map's inner map (`ENOTSUPP`), as Linux master has it; the test
  machines' Linux 7.0 takes one. `BPF_F_RDONLY` and `BPF_F_WRONLY` are the
  descriptor's, not the map's: `map_flags` (in fdinfo, `bpf_map_info` and a
  template) leaves them out, as Linux's `bpf_map_flags_retain_permanent`
  does. See [limitations](./limitations) for what is not there.

- `BPF_OBJ_PIN` leaves a map in a file of a BPF file system and
  `BPF_OBJ_GET` gives a descriptor of it again, as Linux's
  `bpf_obj_pin_user` and `bpf_obj_get_user` do. A BPF file system is a
  mount of type `bpf`, by `mount` or `fsopen`: it is `FS_USERNS_MOUNT`, but
  `bpf_fill_super` needs `CAP_SYS_ADMIN` in the first user namespace from a
  caller outside it (`EPERM`). `uid`, `gid` and `mode` give its root, which
  is 0777 and the sticky bit by default; the common superblock flags apply,
  and other options are ignored, as Linux ignores them. `delegate_cmds`,
  `delegate_maps`, `delegate_progs` and `delegate_attachs` take names of
  Linux master's UAPI enums (in any case, without their `BPF_`,
  `BPF_MAP_TYPE_` or `BPF_PROG_TYPE_` prefix), numbers (`EINVAL`, `ERANGE`)
  or `any`, joined by `:`, and need `CAP_SYS_ADMIN` (`EPERM`); mountinfo
  shows them as `bpf_show_options` does, by name, `any` or in hex, after
  the mount root's owner and mode as they are now (a `chmod` or `chown` of
  it shows). Its
  `statfs` is `BPF_FS_MAGIC`, with no size and no inodes, and a remount
  changes its superblock flags alone. Both commands take no flag but
  theirs (`BPF_F_PATH_FD`; for a get, `BPF_F_RDONLY` or `BPF_F_WRONLY`, not
  both), and a `path_fd` only with `BPF_F_PATH_FD` (`EINVAL`). A pin takes
  a map's descriptor of any access (`EINVAL` for another), then a new name
  (`EEXIST`, and `ENOENT` with a slash after it) on a writable mount
  (`EROFS`) in a BPF file system's directory (`EPERM` for another), which
  the thread may write (`EACCES`): a regular file of mode 0600 less the
  umask, the thread's, that holds the map while a name of it is there, with
  no descriptor of the map left. A get follows the path's links and needs
  the access it asks for on the file (`EACCES`), which must hold a map
  (`EACCES` for another file); the new descriptor has that access. Opening
  the file is `EIO`, as Linux's `bpffs_obj_fops` give a map with no BTF to
  show. Its directories make directories, symbolic links, hard links and
  renames, as `bpf_dir_iops` do, and no other file: a new regular file is
  `EACCES`, a node (a FIFO, a socket's `bind`) `EPERM` and `O_TMPFILE`
  `EOPNOTSUPP`; a name with a dot that is not there is `EPERM` wherever a
  walk looks it up in a directory with any mode bits, so for `stat`,
  `open` and `unlink` too (`bpf_lookup`), after any `EACCES` of the walk to
  it. Its files and directories hold `trusted.*` and `security.*` extended
  attributes, as Linux master's from 7.2 (`bpf_fs_xattr_handlers`), and no
  others (`EOPNOTSUPP`); `security.*` ones are up to 128 names and 128 KiB
  of values for each inode, counting a new one before any it replaces
  (`simple_xattr_set_limited`, `ENOSPC`).

- `BPF_PROG_LOAD` loads socket filters (`BPF_PROG_TYPE_SOCKET_FILTER`),
  which a verifier checks as Linux's does, and an interpreter runs them on
  the sockets they are attached to (below). It checks
  its arguments as Linux's `bpf_prog_load` does, in master's order and with
  its errors: the log's arguments first (a buffer without a size or a size
  without a buffer, a buffer without a level, an unknown level, `EINVAL`;
  the test machines' kernel, Ubuntu's Linux 7.0, checks them as its
  verifier starts), the fields past the command (`EINVAL`), the program
  flags (`EINVAL`), a token descriptor (`EBADF` for none, `EINVAL` for
  another file, as there are no tokens here),
  `kernel.unprivileged_bpf_disabled` without `CAP_BPF` (`EPERM`), the count
  of instructions (0, or more than 4096 without `CAP_BPF` and 1,000,000
  with it, `E2BIG`), `CAP_BPF` for a type other than a socket filter or a
  cgroup skb program, `CAP_NET_ADMIN` and `CAP_PERFMON` for the types that
  need them (`EPERM`; `CAP_SYS_ADMIN` stands in for each), an attach
  program or BTF ID, or one of master's multi-function attach types
  (`EINVAL` for every type here), the copies of the instructions and the
  license (`EFAULT`), a device to bind to (`EINVAL`), and the type: any but
  a socket filter is `EINVAL`, as on a kernel built without it. The name
  comes last, as a map's (`EINVAL`).
  With `BPF_F_STRICT_ALIGNMENT`, and without `BPF_F_ANY_ALIGNMENT`, the
  verifier requires every access to be aligned to its size, as Linux's
  `check_ptr_alignment` does: through the context ("misaligned context
  access off %s+%d+%d size %d"), a map's value ("misaligned value
  access ..."), a lookup's result before its null check, and a scalar
  ("misaligned access ...", checked before the access is refused), all
  `EACCES`. The stack, and every `BPF_ATOMIC`, is aligned whatever the
  flags.

- The verifier (`kernel/bpf/verifier.c`) takes a program only if both of
  the kernels the tests know take it, master and 7.0, and rejects what
  either rejects. It checks the structure first, in master's order, all
  `EINVAL`: the last instruction is not half of a `BPF_LD_IMM64`, the
  jumps stay in the program ("jump out of range from insn %d to %d") and
  the last instruction is an exit or a jump, each instruction's
  registers, opcode ("unknown opcode %02x") and reserved fields (each
  class's "... uses reserved fields"), a `BPF_LD_IMM64`'s second half,
  and then the edges between instructions: every one reachable
  ("unreachable insn %d") and no jump into a `BPF_LD_IMM64`. Then it walks
  every path from the first instruction, with what each register holds
  (R1 the context, R10 the frame pointer, the others nothing yet) and the
  512 bytes of stack: a register read before it is written ("R%d
  !read_ok", `EACCES`), the frame pointer written, a division by a 0
  immediate and a shift past the width (`EINVAL`), pointer arithmetic as
  Linux allows it (an offset added to the stack or context pointer, a
  pointer less a pointer, a 32-bit difference; no subtraction from the
  stack pointer, no other operator, no 32-bit addition, `EACCES`; an
  offset past 2^29, `EINVAL`), the stack's loads and stores (aligned to
  their size, within the 512 bytes, `EACCES`), pointers spilled to the
  stack whole and filled whole, the value of a load of the stack where
  Linux knows it (zeros stored, or a scalar spilled, read from its start
  and no wider than the spill, which the load zero- or sign-extends), a
  load through a scalar ("R%d invalid mem
  access 'scalar'", `EACCES`) and the exit's R0, which may be any value.
  A conditional jump whose operands it knows goes one way; any other is
  walked both ways. It gives up as Linux does after 1,000,000 instructions
  or 8,192 jumps waiting to be walked (`E2BIG`).

- Programs use maps as Linux's verifier lets them. A `BPF_LD_IMM64` of a
  map's descriptor (`BPF_PSEUDO_MAP_FD`) gives the map, and one of its
  value (`BPF_PSEUDO_MAP_VALUE`) a pointer into the value of an array of
  one element: a descriptor of no map is `EBADF` or `EINVAL` ("fd %d is
  not pointing to valid bpf_map"), a value of another type `EINVAL`, of an
  array of more elements `ENOTSUPP`, and past the value `EINVAL`; a map
  named twice is one, and a program uses 64 at most (`E2BIG`). It may call
  `bpf_map_lookup_elem`, `bpf_map_update_elem` and `bpf_map_delete_elem`
  with the map in R1 ("R1 type=%s expected=map_ptr", `EACCES`) and the key
  and value on the stack or in a map's value, their sizes within it; R1 to
  R5 are gone after a call, and R0 is its result. An update or delete of
  a map made with `BPF_F_RDONLY_PROG` is "write into map forbidden"
  (`EACCES`). A lookup's result may be null: nothing may be read or
  written through it, nor added to it, until a 64-bit `BPF_JEQ` or `BPF_JNE` compares it with 0, which
  makes it, and every copy of it in a register or on the stack, a pointer
  to the value on one side and 0 on the other ("R%d invalid mem access
  'map_value_or_null'", `EACCES`). An array's element needs no check
  when the stack holds its key as Linux's `get_constant_map_key` knows
  it, within the array's entries: zeros stored other than as a spill, or
  a scalar spilled at the start of a slot whose spilled bytes from the
  key are the key's 4 (so an 8-byte spill's whole register, from the
  slot's middle); not when the array was made with `BPF_F_INNER_MAP`,
  whose entries need not be those of the array it stands for (master's
  53040a81ae57). A 64-bit `BPF_JEQ` or `BPF_JNE` of a value's or a map's
  pointer with 0 goes one way only, as Linux knows such a pointer is not
  0; a 32-bit one goes both ways, as on master (e51179a4e098). A 64-bit
  `BPF_JEQ` or `BPF_JNE` of a lookup's result with such a pointer makes
  that register, not its copies, a pointer to the value where the two are
  equal (`mark_ptr_not_null_reg`). A value is read and written within its
  size ("invalid access to map value", `EACCES`), not written when the
  map has `BPF_F_RDONLY_PROG` and not read when it has
  `BPF_F_WRONLY_PROG` (`EACCES`). The program keeps the maps it uses.

- `BPF_ATOMIC`'s read-modify-write operations change 4 or 8 bytes of the
  stack or of a map's value in one step, as Linux's `check_atomic` checks
  them: add, or, and and xor, each with or without `BPF_FETCH`,
  `BPF_XCHG` and `BPF_CMPXCHG`. Another operation is "BPF_ATOMIC uses
  invalid atomic opcode %02x", and another size for these
  "invalid atomic operand size" (`EINVAL`). The source and
  destination registers, and R0 for `BPF_CMPXCHG`, must be written; the
  context is "BPF_ATOMIC stores into R%d ctx is not allowed" (`EACCES`).
  The register the old value goes to, the source with `BPF_FETCH` and R0
  for `BPF_CMPXCHG`, is unknown before the memory is read, even when it is
  the destination, which then reads through a scalar, and then holds what
  the read gives. The memory is read,
  then written, aligned to the size whatever the program's flags, and a
  stack slot written so holds bytes, even where a pointer was spilled.
  `BPF_LOAD_ACQ` and `BPF_STORE_REL`, of any size, are checked as a load
  and a store are, aligned whatever the flags, and refused through the
  context ("BPF_ATOMIC loads from R%d ctx is not allowed",
  "BPF_ATOMIC stores into R%d ctx is not allowed", `EACCES`): a load as
  soon as its source is read, before its access is checked, as master and
  the test machines' 7.0 refuse it, and a store after its access.

- The context, R1 as a program starts, is the packet's `struct
  __sk_buff`, read and written as Linux lets a socket filter: its 4-byte
  fields read whole or narrower, at an offset that is a multiple of the
  read's size, `cb[0]` to
  `cb[4]` read and written at any size within them, and nothing else
  written; `data`, `data_end`, `data_meta`, `tc_classid`, the socket's
  addresses and ports, `tstamp`, `wire_len`, `hwtstamp` and `flow_keys`
  are not a socket filter's ("invalid bpf_context access off=%d size=%d",
  `EACCES`). Only the context as it came may be read through or passed to
  a helper ("dereference of modified ctx ptr R%d off=%d disallowed",
  `EACCES`), and an instruction that loads or stores through the context
  on one path may not through another pointer on another ("same insn
  cannot be used with different pointers", `EINVAL`). Besides the map
  helpers, a program may call `bpf_skb_load_bytes` and
  `bpf_skb_load_bytes_relative`, with the context, an offset, a buffer on
  the stack or in a writable map value and its size, a constant from 1 to
  2^29 - 1 within the buffer (each with Linux's line, `EACCES`, or `EINVAL`
  for a buffer past the frame); `bpf_get_socket_cookie` and
  `bpf_get_socket_uid` of the context, `bpf_get_netns_cookie` of the
  context or 0 ("R1 type=%s expected=ctx", `EACCES`); and the helpers of
  no arguments: `bpf_ktime_get_ns`, `bpf_ktime_get_boot_ns`,
  `bpf_ktime_get_coarse_ns`, `bpf_ktime_get_tai_ns`,
  `bpf_get_prandom_u32`, `bpf_get_smp_processor_id`,
  `bpf_get_numa_node_id`, `bpf_get_current_pid_tgid` and
  `bpf_get_current_uid_gid`. A helper a socket filter may not call is
  "program of this type cannot use helper %s#%d" and a number that is no
  helper "invalid func %s#%d" (`EINVAL`).

- `BPF_LD_ABS` and `BPF_LD_IND` load 1, 2 or 4 bytes of the packet into
  R0, at `imm` or at the source register plus `imm`, as Linux's
  `check_ld_abs` checks them. Their reserved fields, a destination, an
  offset or, for `BPF_LD_ABS`, a source, are "BPF_LD_[ABS|IND] uses
  reserved fields", checked before any path is walked as master does,
  and 8 bytes is an unknown opcode (`EINVAL`). R6 must be written ("R6
  !read_ok", `EACCES`) and be the context ("at the time of
  BPF_LD_ABS|IND R6 != pointer to skb", `EINVAL`); then the source of a
  `BPF_LD_IND` must be written, and the context in R6 must be as it came
  ("dereference of modified ctx ptr R6 off=%d disallowed", `EACCES`).
  R1 to R5 are not readable after one, and R0 is a number.

- A `BPF_CALL` with `BPF_PSEUDO_CALL` calls a function of the program,
  `imm` instructions after the call, as Linux checks a call of a static
  function, the only kind without BTF. Each target starts a function
  ("call to invalid destination" outside the program, `EINVAL`; "too many
  subprograms" past 256, `E2BIG`). A function's jumps stay in it ("jump
  out of range from insn %d to %d"), its last instruction is an exit or a
  jump ("last insn is not an exit or jmp"), and one other than the main
  program has no `BPF_LD_ABS`, `BPF_LD_IND` or `bpf_tail_call` ("LD_ABS
  is not allowed in subprogs without BTF", "tail_call is not allowed in
  subprogs without BTF", as 7.0 refuses them; master takes them), all
  `EINVAL` before any path is walked. The callee starts with the caller's
  R1 to R5 and a frame pointer and 512-byte stack of its own; its R0 and
  R6 to R9 are not readable until written, and the caller's R0 to R5 are
  not readable after the call, which gives it the callee's R0. A callee
  may not return a pointer to a stack ("cannot return stack pointer to
  the caller") or store one in a caller's frame ("cannot spill pointers to
  stack into stack frame of the caller", both `EINVAL`), but reads and
  writes a caller's stack through a pointer to it. Calls go 8 frames deep
  at most ("the call stack of %d frames is too deep", `E2BIG`), which is
  how a recursive call is refused, as the test machines' 7.0 does (master
  refuses one before the walk, "recursive call from %s() to %s()", which
  comes here once the test machines' kernel has it); after
  the walk, along every chain of calls, each function's stack depth,
  rounded up to 16 bytes as with the JIT, adds up to 512 bytes at most
  ("combined stack size of %d calls is %d. Too large", `EACCES`). With
  `BPF_LOG_STATS` the log gives each function's stack depth and the most
  a chain of calls takes ("stack depth %d+%d max %d", as the test
  machines' 7.0 writes it).

- After the walk, a program is as long as Linux's rewrites make it,
  though the interpreter runs the instructions as loaded. A conditional
  jump one of whose sides no path took becomes a jump, then the code no
  path reached goes, and each jump of 0 (`opt_remove_dead_code`,
  `opt_remove_nops`). An access to the context becomes the loads of
  `struct sk_buff` the x86-64 kernel makes of it, with a narrower load's
  shift and mask and a sign extension's move (`convert_ctx_accesses`). A
  division or remainder by a register gets its checks of 0 and -1,
  `BPF_LD_ABS` and `BPF_LD_IND` get their calls, and
  `bpf_get_smp_processor_id` and a lookup of one array, hash or LRU hash
  are inlined (`do_misc_fixups`). A 32-bit `BPF_CMPXCHG` whose R0 is read
  as 64 bits is zero-extended, and with `BPF_F_TEST_RND_HI32` a 32-bit
  result never read as more gets three instructions that fill its upper
  half (`opt_subreg_zext_lo32_rnd_hi32`). No `bpf_fastcall` spill and
  fill goes: a socket filter's `bpf_get_smp_processor_id` is
  `bpf_get_raw_smp_processor_id_proto`, which has none. A
  rewrite after which a jump no longer reaches in 16 bits is `ENOMEM`
  ("insn %d cannot be patched due to 16-bit range"). The program's memory
  grows to the instructions the rewrites make (`bpf_prog_realloc`), and
  its socket is charged for them.

- `BPF_PROG_TEST_RUN` runs a socket filter on a packet the caller gives,
  as Linux master's `bpf_prog_test_run_skb`: the packet starts with an
  Ethernet header, which `eth_type_trans` takes off as the loopback (or
  the device the context's `ifindex` names, `ENODEV` for none) receives
  it, finding the packet's type and its protocol (`ETH_P_802_2` for a
  length, as master has it with no IPX). As many of its bytes as fit in a
  page with Linux's headroom and tailroom (3712), or as the context's
  `data_end` says, are in the linear part, and the rest in pages, at most
  `MAX_SKB_FRAGS` (`ENOMEM`). The program runs `repeat` times (once for
  0) on the same packet, whose `cb[]` it may change for the next run, and
  a signal between runs ends them (`EINTR`). `retval` is its result,
  `duration` the time a run took, and `data_out` the packet with its
  Ethernet header zeroed, as much as `data_size_out` takes (`ENOSPC`
  after the sizes are written), its linear part first. A copy out that
  runs into a page the caller may not write writes up to it and is
  `EFAULT`, with nothing written after it. A context
  (`struct __sk_buff`, in and out) gives `mark`, `priority`,
  `ingress_ifindex`, `ifindex`, `cb[]`, `wire_len`, `gso_segs` and
  `gso_size` and must have zeros elsewhere (`EINVAL`), and past its 192
  bytes (`E2BIG`); what comes back has the fields Linux gives back. Before
  that come the checks of the call: a context's size without its address
  or the other way, the program (`EBADF`, `EINVAL`), flags other than
  `BPF_F_TEST_SKB_CHECKSUM_COMPLETE`, a processor or a batch size, fewer
  bytes than an Ethernet header, and, as master has it, an IPv4 or IPv6
  packet shorter than its header (`EINVAL`). A socket filter cannot change
  the packet, so its checksum never changes (`EBADMSG`). The program
  reads the socket of the run as one of its own (`bpf_dummy_proto`), with
  a cookie of its own and, as its owner, root of the user namespace that
  owns the network namespace, as that namespace sees it: 0, or the
  overflow ID while it maps no root.

- A socket filter attaches to an AF_UNIX `SOCK_DGRAM` or `SOCK_SEQPACKET`
  socket with `SO_ATTACH_BPF`, or a classic one with `SO_ATTACH_FILTER`
  (below), and runs on each message sent to it, as
  Linux's `sk_filter` and `unix_dgram_sendmsg`. Before the receiver's
  checks, but after the sender's own shutdown and send buffer, it decides
  the message's fate: 0 drops it, and the send still gives its length;
  any other value keeps that many bytes. The interpreter runs the program
  as Linux's `___bpf_prog_run` does after the verifier's rewrites. A
  division by a register that is 0 gives 0, and a remainder by it keeps
  the dividend. A signed division by -1 negates, and a signed remainder by
  -1 gives 0. An atomic in 32 bits changes the lower half of a slot with
  the source's lower half and compares R0's, and the old value comes back
  zero-extended; no other access to a map's value comes between its read
  and its write, a mapping's write to a mappable array's value included.
  A load-acquire comes back zero-extended, and a
  store-release writes the source's lower bytes. A `BPF_LD_ABS` or
  `BPF_LD_IND` loads big-endian, as Linux's `bpf_gen_ld_abs` rewrites it
  into a call of `bpf_skb_load_helper_8`, `_16` or `_32`: its offset is
  an `int` (the lower half of the register plus `imm`), from the
  message's start or, from `SKF_NET_OFF`, the network header, its start;
  where the bytes are not in the message, or the offset is from the MAC
  header, which is not set, or below it, the program returns 0 then and
  there. A called function runs in a frame of its own, and the caller's
  R6 to R9 are as they were after it. The context is the message's
  `__sk_buff`: its `len`, `cb[]`
  from 0 and 0 for the fields an AF_UNIX message does not set.
  `bpf_skb_load_bytes` reads the message, and its relative form reads it
  from the network header, its start, where there is no MAC header
  (`EFAULT`). The maps a program updates are the ones user space reads.
  - `SO_ATTACH_BPF` takes a 4-byte descriptor (`EINVAL` for any other
    size). It is `EBADF` for no descriptor and `EINVAL` for one that is no
    socket filter. A new filter replaces the old.
  - `SO_DETACH_FILTER` (`SO_DETACH_BPF`) takes the filter away, or gives
    `ENOENT` when there is none.
  - `SO_LOCK_FILTER` keeps the filter as it is (`EPERM`) until the socket
    goes, and it cannot be unlocked.
  - `SO_GET_FILTER` gives 0 blocks with no filter and `EACCES` for one
    attached with `SO_ATTACH_BPF`. For a classic one it gives the
    instructions as attached and their number in `*len`, in blocks: a
    `*len` of 0 only asks for it, and one short of it is `EINVAL`.
  - `SO_BPF_EXTENSIONS` gives 64 (`SKF_AD_MAX`).

- On a UDP socket, IPv4 or IPv6, a filter takes the same options and runs
  on each datagram that comes to it through the loopback or a veth pair, as
  Linux's `udp_queue_rcv_one_skb` and `udpv6_queue_rcv_one_skb` run
  `sk_filter_trim_cap`: before the receive buffer's check, so that a
  datagram it drops is never queued. 0 drops it, and any other value keeps
  that many bytes from the UDP header on, the header always: what is
  received (and `FIONREAD`) is the rest. The datagram takes of the receive
  buffer what it took as it came. A drop, the filter's or the full
  buffer's, counts in `sk_drops` (`INET_DIAG_SKMEMINFO`). The filter runs
  on the `sk_buff` Linux 7.0 makes:
  - `skb->data` is at the UDP header, with the IP header before it
    (`SKF_NET_OFF`, `BPF_HDR_START_NET`) and the MAC header before that
    (`SKF_LL_OFF`, `BPF_HDR_START_MAC`): the loopback's Ethernet header of
    zeros, a veth end's from its address to its peer's (or to the
    broadcast address), and for a broadcast's copy looped back on the
    sending end (`dev_loopback_xmit`) the network header itself.
    `BPF_LD_ABS` and `BPF_LD_IND` from a header reach the datagram's end;
    `bpf_skb_load_bytes_relative` the linear part's, which is the whole
    datagram unless
    `__ip_append_data` or `__ip6_append_data` puts it in pages (past
    `SKB_MAX_ALLOC` with the headers and the room they reserve), when it is
    the UDP header's.
  - The IPv4 header has `IP_TOS`, `DF`, a TTL of 64 and a connected
    socket's IDs from the random one `connect` gives (else a random one);
    the IPv6 header a hop limit of 64 and the auto flow label of the
    datagram's hash. The UDP checksum is the pseudo-header's, as the device
    takes the rest (`CHECKSUM_PARTIAL`), or the whole one for a datagram
    that goes in fragments.
  - The context's `len` is the UDP header's and the payload's; `protocol`
    is `ETH_P_IP` or `ETH_P_IPV6`; `pkt_type` `PACKET_HOST`,
    `PACKET_BROADCAST` or `PACKET_LOOPBACK`; `ifindex` and
    `ingress_ifindex` the loopback's (1) or the veth end it came in on;
    `priority` the sender's `SO_PRIORITY`, or 0 across a veth pair
    (`____dev_forward_skb`); `hash` a connected socket's `sk_txhash`, the
    flow's for IPv6, else 0; the rest 0. Classic loads see the same, with
    `SKF_AD_HATYPE` `ARPHRD_LOOPBACK` or `ARPHRD_ETHER` and
    `SKF_AD_PAY_OFFSET` 8. The helpers run as the sending task, in whose
    context Linux's softirq runs the receive.

- On a TCP listener, IPv4 or IPv6, the filter runs on each SYN that
  comes to it through the loopback or a veth pair, as `tcp_v4_rcv` and
  `tcp_v6_rcv` run `tcp_filter` before `tcp_v4_do_rcv` takes it, and so
  before the accept queue's check: a SYN it drops counts in the
  listener's `sk_drops` and is sent again on the handshake's schedule,
  as one a full queue dropped. The SYN is Linux 7.0's: a 40-byte TCP
  header with a random sequence number, the window that half the
  receive buffer holds rounded down to the MSS, and the options MSS (the
  device's MTU less the headers), SACK permitted, the timestamps (a
  random value, then 0) and a window scale of 10, for `tcp_rmem[2]`'s 32
  MiB; the IP header, MAC
  header and `__sk_buff` fields as a UDP datagram's (above), with the
  connecting socket's flow hash, which `connect` gives it and each SYN
  sent again draws anew (`sk_rethink_txhash`), and `SKF_AD_PAY_OFFSET`
  40; a SYN sent again is the connecting socket's, with its options. An accepted socket
  takes the listener's filter and its lock, as `sk_clone_lock` copies
  them.
  - The SYN-ACK that answers is the client's filter's to keep: dropped, the
    client goes on trying. The connection goes on from the sequence numbers
    and timestamps of the two.
  - The handshake's last acknowledgement is the listener's again. Dropped,
    the client is connected and the listener has a request (`SYN_RECV` to
    `sock_diag`), with nothing to accept: the SYN-ACK goes again after 1
    second, then 2, 4, 8 and 16 more, and the client answers it
    (`tcp_send_challenge_ack`). The first segment that the listener's filter
    of that time keeps, data and an end too, opens the connection, which is
    accepted in that order; a reset drops the request, as 63 seconds do.
    What comes after that, or after the listener has closed, is answered
    with a reset.

- On a TCP connection on the loopback or across a veth pair, the filter
  runs on each segment that comes to its socket, data, acknowledgements,
  ends and resets, as `tcp_v4_rcv` and `tcp_v6_rcv` run `tcp_filter`: until
  the socket is closed and its end acknowledged.
  - It sees the TCP header, 32 bytes with the timestamps and more with SACK
    blocks, and the data after it: each side's sequence numbers going on from
    its SYN's or SYN-ACK's,
    the flags (`PSH` on a write's last, `URG` and its pointer up to an
    urgent byte), the window the side offers, scaled, the pseudo-header's
    checksum and the `sk_buff` fields, with `gso_segs` and `gso_size`.
    Classic loads see the same, with `SKF_AD_PAY_OFFSET` where the data
    starts.
  - 0 drops the segment, which is then not counted (`tcpi_segs_in`). Any
    other value keeps that many bytes from the TCP header on, the header
    always: the data past them has not come, and an end on the segment
    comes with what is kept of it.
  - What was dropped or cut is sent again as Linux 7.0 sends it: by a tail
    loss probe; on a SACK of something sent later (RACK); or at the
    retransmission timeout, 201 ms that doubles, the small segments at the
    head joined into one (`tcp_retrans_try_collapse`). It comes at its time,
    whether or not a call is made then. `tcp_info` tells of it:
    the recovery's state, the segments lost, SACKed and sent again, the
    congestion window and its threshold (cubic's, with proportional rate
    reduction), the timeouts, the duplicates the peer told of (D-SACK),
    which may undo the reduction, and those that came out of order.
  - A connection ends with `ETIMEDOUT` after `TCP_USER_TIMEOUT`, else after
    15 timeouts (`tcp_retries2`), or 8 for one whose socket has closed. A
    reset that is dropped leaves the connection open; each segment it
    sends then gets another.
  - What a side ends with, as it goes into `TIME_WAIT` or its `LAST_ACK`
    ends, is kept for the next connection between the same two addresses
    in its network namespace, as Linux's `tcp_metrics` keeps it
    (`tcp_update_metrics`): the round trip (a longer one at once, a shorter
    one an eighth of the way), its variation, the threshold and window, and
    the reordering. The next starts from the threshold and the reordering,
    and from a longer first timeout when the round trip kept is longer than
    its handshake's (`tcp_init_metrics`). A side that measured no round
    trip, or backed off, forgets the one kept; an entry an hour old starts
    over.

- A classic filter (`SO_ATTACH_FILTER`, a `struct sock_fprog`; `EINVAL`
  for another size) is checked as Linux's `bpf_check_classic` checks it
  and converted to eBPF, which the interpreter runs. The converted
  program's instructions are paludarium's own, but each classic
  instruction converts to as many as `bpf_convert_filter` converts it to,
  with its jumps in the same places: the program's length is what the
  socket is charged for, and with the jumps' places it decides which
  programs are too long to convert.
  - It is `EINVAL` for no instructions or more than 4096, a code Linux
    does not know, a division or remainder by a constant 0, a constant
    shift of 32 or more, a scratch word past the 16th or one read where
    some path has not written it, a jump past the end, an ancillary load
    Linux does not know, and a last instruction that does not return. It
    is `EFAULT` for instructions that cannot be read, and `EPERM` on a
    locked socket. On a TCP socket it is `EPERM`, before the program is
    read, without `CAP_NET_ADMIN` in the user namespace that owns the
    socket's network namespace, as Linux's `sk_setsockopt` asks.
  - The conversion is `EINVAL` for a jump that the converted program's
    16-bit offset cannot hold, and for any jump placed past its 32,767th
    instruction, as Linux's first pass, which takes every target to be at
    0, refuses it. The socket is charged the converted program's size, as
    on Linux (`ENOMEM`).
  - The accumulator and X are 32 bits, and the jumps compare them
    unsigned. A division or remainder by an X of 0 returns 0, and a shift
    by X takes its count modulo 32.
  - A load of the message gives its bytes big-endian, and returns 0 where
    they are past its end. A negative offset from `SKF_NET_OFF` on reads
    from the network header, the message's start; one from the MAC header
    (`SKF_LL_OFF`), which an AF_UNIX message has not set, returns 0.
  - The ancillary loads are those of an AF_UNIX message. The protocol,
    packet type, mark, queue, hash, VLAN fields and payload offset are 0.
    The interface index and hardware type return the accumulator as it
    is, since there is no device. The netlink attribute searches are
    Linux's `nla_find`, and give 0 for a message in pages.

- The log (`log_level`, `log_buf`, `log_size`) gets the line that says
  why a program was refused, in 7.0's words where the two kernels word it
  differently, and the "processed %d insns" line, in a fixed
  (`BPF_LOG_FIXED`) or rotating buffer; a log too small is `ENOSPC` and one
  that cannot be written `EFAULT`, in place of the load's result, and
  `log_true_size` gives its length. A program loaded is a descriptor,
  close-on-exec, of `anon_inode:bpf-prog`, whose fdinfo gives its type,
  its tag (the first 8 bytes of the SHA-256 of its instructions, with
  maps' descriptors taken out, as Linux's `bpf_prog_calc_tag`), its memory
  (its 96-byte header and instructions, in pages, as many as the rewrites
  make if they make more), its ID (from IDs of
  programs, apart from the maps') and the instructions the verifier went
  through; `prog_jited` and the run statistics are 0. See
  [Limitations](./limitations) for what the verifier refuses that Linux
  takes.

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
  wakes the file for each, as it is sent, even when another thread has yet
  to take it in: another real-time signal of a number already
  waiting counts, a standard signal already pending or one ignored and
  unblocked does not, nor one the init of a nested PID namespace drops
  unblocked as it has no handler (`SIGNAL_UNKILLABLE`); a new mask is an
  edge too. `signalfd` on a
  signalfd's descriptor gives it a new mask (`EINVAL` for another file);
  `SIGKILL` and `SIGSTOP` never enter one, and neither a read nor a poll
  takes a signal whose action is `SA_IMMUTABLE` (below), as Linux master's
  `refine_sigmask` leaves it out (v7.0 takes it). A write gives `EINVAL`, `pread`
  and `pwrite` `ESPIPE`, and `lseek` 0, as Linux's `noop_llseek`.

- Directory notifications (dnotify), as Linux's `dnotify.c`: `fcntl`'s
  `F_NOTIFY` on a directory's descriptor asks for a signal when the
  directory or a file in it is read (`DN_ACCESS`), written (`DN_MODIFY`),
  made or moved in (`DN_CREATE`), removed or moved out (`DN_DELETE`),
  renamed within it (`DN_RENAME`) or changes its attributes (`DN_ATTRIB`).
  - The signal goes to the open file's owner. An open file with no owner
    gets the caller's process as its owner.
  - It is `SIGIO` from the kernel, or with `F_SETSIG` that signal, with
    `POLL_MSG`, its band and the descriptor asked through as `si_fd`.
  - A watch signals once and goes, unless `DN_MULTISHOT` keeps it.
  - Asking again through the same open file and descriptor table adds the
    events and names the new descriptor. Watches of one directory signal
    the newest first.
  - Any close of a descriptor of that open file through that table ends
    its watch, as do asking with no events and the table's end.
  - The directory's mark stays after a one-shot watch's signal took its
    last watch off. Any close of a descriptor of the directory, through any
    table and at a table's end too, then takes the mark off
    (`dnotify_flush`), which moves the directory's place in `IN_UNMOUNT`'s
    order.
  - A file that is not a directory gives `ENOTDIR`, an `O_PATH` descriptor
    `EBADF`. Unknown bits are ignored.
  - `/proc/sys/fs/dir-notify-enable`, the machine's (1 at first), is root's
    file of mode 0644 that takes any `int` (`proc_dointvec`). While it is 0,
    `F_NOTIFY` gives `EINVAL` before anything else, even with no events;
    watches already there keep signalling.

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
  `IN_IGNORED`. When a tmpfs's superblock goes with its last mount (a bind
  mount left keeps it, and a detached one goes with the last file open on
  it), each watch on one of its files hears `IN_UNMOUNT`, with `IN_ISDIR`
  for a directory, whatever it asked for, then goes with `IN_IGNORED`, as
  Linux's `fsnotify_sb_delete` ends them. The files go as
  `fsnotify_unmount_inodes` takes them, the newest connector first: the
  order in which they got the first of the marks of any group (an
  inotify instance's, dnotify's or fanotify's) that they still hold, not
  the order one instance watched them. Each instance queues its events, merging one into the same
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

- A fanotify group (`fanotify_init`) is as Linux's `fs/notify/fanotify`:
  the flags are checked in its order (`EPERM` without CAP_SYS_ADMIN but for
  a group that reports file handles or mounts, which reports no
  descriptors and the IDs of no other process), the user's groups count
  (`EMFILE`), and the file is `anon_inode:[fanotify]`, read and written,
  with `O_NONBLOCK` and `O_CLOEXEC` as asked. `fanotify_mark` adds, removes
  or flushes marks on a file, a mount or a file system (and on a mount
  namespace, by its file in `/proc/<pid>/ns` or a descriptor of it, for
  mount events; another namespace's file is `EINVAL`, as
  `mnt_ns_from_dentry` finds none); a mount's mark, by the mount's ID, hears only of the paths
  in that mount, not of a bind mount of the same file system, and fdinfo
  shows that ID; it goes when its mount is freed (`fsnotify_vfsmount_delete`),
  so a mount that takes the ID next is not marked. As a tmpfs's superblock
  goes with its last mount, the marks on its files and on itself go
  (`fsnotify_sb_delete`), so one that takes the device next is not marked.
  An evictable mark (`FAN_MARK_EVICTABLE`) holds no reference to its inode:
  once `/proc/sys/vm/drop_caches` evicts the inode, the mark goes, as
  `fsnotify_inode_delete` takes off its marks. That is a file outside a
  tmpfs (whose dentries stay) that no open description, working
  directory, running program, inotify watch or mark without
  `FAN_MARK_EVICTABLE` holds, and that no open is on its way to (from its
  path lookup on, a FIFO's wait for its other end too, as the lookup's
  dentry reference keeps Linux's inode).
  A use made while the eviction looks keeps the mark too. Exec's open of the
  program and its interpreter is told as `FAN_OPEN` with `FAN_OPEN_EXEC`,
  as `do_open_execat` opens them with `__FMODE_EXEC`; inotify hears it as
  `IN_OPEN`. Before that, each such open asks `FAN_OPEN_EXEC_PERM`, then
  `FAN_OPEN_PERM`, and each of exec's reads of the file (`kernel_read`)
  asks `FAN_ACCESS_PERM`, then tells `IN_ACCESS` if it read a byte, in
  their order: one of a script's first bytes, and of an ELF program those,
  its program headers and its `PT_INTERP` name, then its interpreter's ELF
  header and program headers (x86-64 reads no `PT_GNU_PROPERTY`), before
  exec commits; a denial fails `execve` with `EPERM`, and what would come
  after it is not asked. An exec that fails later (a
  missing interpreter, an argument it cannot read) has asked them all the
  same: a denial's `EPERM` comes first, and an open let through tells its
  open and close. It makes its checks in its order: the flags and mask
  (`EINVAL`), the descriptor (`EBADF`, `EINVAL`), the group's class and
  modes, the path (`ENOENT`, `ENOTDIR`), the events the file system takes
  (`EINVAL` for permission events on /proc, and for mount and file system
  marks on the kernel's own file systems, which nsfs is not, as `nsfs_init`
  clears its `SB_NOUSER`; `ENOTDIR` for directory events of
  a file with the newer flags), read permission (`EACCES`), the file
  system's ID and handles in the FID modes (`ENODEV`, `EOPNOTSUPP`,
  `EXDEV`), the ignore masks' rules (`EISDIR`, `EEXIST`, and none for a
  file open for writing), and the user's marks (`ENOSPC`). A mark keeps
  `FAN_EVENT_ON_CHILD` and `FAN_ONDIR` as Linux does (taking off the first
  but for a directory's mark, adding it in `FAN_REPORT_DIR_FID` so that the
  directory and name are known), and its ignore mask ends at a
  modification unless `FAN_MARK_IGNORED_SURV_MODIFY`.
  The groups hear what inotify watches hear, by the same hooks, as Linux's
  `fsnotify` sends it: the file's, its mount's and its file system's marks,
  its directory's when it watches its children, and for `FAN_RENAME` the
  new directory's. A FIFO's or device's read or write is not its
  directory's, as `__fsnotify_parent` keeps it from the directory's
  interest, but a group that needs the directory and name hears of it with
  them, without `FAN_EVENT_ON_CHILD`. An event is queued as
  `fanotify_handle_event` makes it:
  without a FID mode only the open, access, modification and close of a
  regular file or directory, with a descriptor of it opened again with the
  group's flags, which `F_GETFL` shows with `O_CLOEXEC` and which a
  directory gets for writing too, as `dentry_open` gives it (one that tells
  no watch of anything, the error with
  `FAN_REPORT_FD_ERROR`, else the read's); in the FID modes with the
  records of the file's handle (`name_to_handle_at`'s identifier), its
  directory's and its name, a rename's old and new directory and name, and
  `.` for a directory's own event. An event of the same object, process and
  kind as one still queued among the newest 128 of its bucket of the merge
  hash merges into it (`fanotify_merge`). The bucket comes from the hash
  `fanotify_alloc_event` mixes: the file system ID, the handles and the
  names as Linux hashes them (`full_name_hash` on x86-64), so the events of
  names in one directory by one task share a bucket exactly when they do on
  Linux; the process, and a path in the non-FID modes, which Linux hashes
  by kernel address, by a hash of their own. Past `max_queued_events` there is
  one `FAN_Q_OVERFLOW`, and `FAN_REPORT_PIDFD` adds the process's pidfd
  (with `FAN_REPORT_TID` it is `EINVAL`, as on Linux 7.0, which the CI
  runners have; master takes both and gives the thread's). A group with
  `FAN_REPORT_MNT` hears of each mount that comes into a mount namespace it
  marks (`FAN_MNT_ATTACH`), goes from it (`FAN_MNT_DETACH`) or moves within
  it (both), once the change is made, in the order Linux's `mnt_notify_add`
  queues them: a new mount, a bind and each copy a propagation makes, each
  mount before those on it; an unmount, a propagated or lazy one too, each
  mount before those on it, after the mounts it slides down onto their
  parent move; `move_mount` and `MS_MOVE` the moved tree's root alone, or
  each mount of a detached tree they attach; `pivot_root` the old root, then
  the new one. A namespace that ends (`put_mnt_ns`, when the last process
  in it and the last descriptor of it are gone; a task lets go of it as it
  exits, before its parent's wait can end, as `exit_task_namespaces` comes
  before `exit_notify`, and the events then name that task) takes out each of its
  mounts, as `umount_tree` takes them from its root: the mount below its
  root first, then each mount before those on it; then its marks go
  (`fsnotify_mntns_delete` in `free_mnt_ns`, as in Linux master since
  1a116222acdc; a kernel before that change removes them only as the last
  passive reference goes, after an RCU grace period). A detached tree is in no namespace and tells nothing. Such an
  event has no descriptor and, after any pidfd's, a record of the mount's
  unique ID (`FAN_EVENT_INFO_TYPE_MNT`, the `statx` `STATX_MNT_ID_UNIQUE`
  one), and is never merged. A read takes whole events (`EINVAL`
  for a buffer too small for the first), waits unless non-blocking, and
  `FIONREAD` gives the bytes queued; `/proc/self/fdinfo` shows the flags and
  each mark, the newest first, as `fanotify_show_fdinfo`. A write is a
  permission response, checked as Linux checks it, to the read event its
  descriptor names (`ENOENT` when none waits by it). An open by `open`,
  `openat`, `openat2`, `creat` or `open_by_handle_at`, a link in
  `/proc/self/fd` too, of a file a content or pre-content
  group's mark wants `FAN_OPEN_PERM` of waits for each such group's
  answer in turn, the pre-content ones first, as `fanotify_get_response`:
  `FAN_DENY` fails it with `EPERM`, `FAN_ALLOW` lets it through, and so
  does the group's last close; only a fatal signal ends the wait. Its
  `FAN_OPEN` comes once it is let through, and a denied open is never
  opened, so it tells no close. A permission event is never merged; a full
  queue lets it through after the overflow event; a read that cannot give
  it a descriptor denies it. Such an open's `FAN_OPEN_PERM` is asked once
  Landlock's check of it has passed, as `do_dentry_open` calls
  `security_file_open` first. A read of a description opened while a
  group's mark wanted `FAN_ACCESS_PERM` of the file (`read`, `pread64`,
  `readv`, `preadv`, `preadv2`, and the input of `sendfile`, `splice` and
  `copy_file_range`) waits for the answers the same way, after the checks
  of the descriptor, the buffer, the size and the position, as
  `rw_verify_area` asks it; `readv` and `preadv` of no bytes ask nothing,
  as `vfs_readv`, where `read` and `pread64` of none ask too. An AIO read
  (`IOCB_CMD_PREAD`, `IOCB_CMD_PREADV`) asks at `io_submit`, as `aio_read`
  calls `rw_verify_area` there, for no bytes too: a denied one fails that
  request as `io_submit` fails any (`EPERM` when it is the first). `statfs`'s `f_fsid` is the file system ID the events give: the
  device of the kernel's own file systems, /proc, devpts and mqueue, as
  `simple_statfs` gives it, and a number drawn for each other file system,
  as tmpfs draws a UUID.

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
  describes; `CLONE_CLEAR_SIGHAND` resets the child's actions as `execve` does.
  `set_tid` is as under the PID namespaces above, and `CLONE_INTO_CGROUP`
  gives `EINVAL`. `clone` itself reads only
  the low 32 bits of its flags, as in Linux, so `CLONE_CLEAR_SIGHAND` is
  `clone3`'s alone.

- `prctl` supports `PR_SET_NAME`/`PR_GET_NAME` (a name of up to 15 bytes per
  thread, taken from the program's file name at `execve` and inherited by new
  threads and processes), `PR_SET_PDEATHSIG` (per thread, none for a new
  thread or process; as Linux's `forget_original_parent` sends it, each
  thread's signal goes to its process when the parent's thread that made
  the process exits, even if the parent goes on, and again as each thread
  the process is then a child of exits), `PR_SET_DUMPABLE` (`execve` makes the process dumpable
  again, but for the cases above), `PR_SET_KEEPCAPS` (per thread, cleared
  by `execve`), the capability module's `PR_CAPBSET_READ`, `PR_CAPBSET_DROP`
  (with `CAP_SETPCAP`), `PR_GET_SECUREBITS`, `PR_SET_SECUREBITS` (which
  changes no locked bit; without `CAP_SETPCAP` only the two bits for exec's
  checks in user space, and only a change) and `PR_CAP_AMBIENT` (a raised
  capability must be permitted and inheritable, unless
  `SECBIT_NO_CAP_AMBIENT_RAISE` refuses it), all per thread,
  `PR_SET_CHILD_SUBREAPER` (not inherited on `fork`, kept on
  `execve`), `PR_SET_TIMERSLACK` and `PR_GET_TIMERSLACK` (per thread; see
  `/proc/<pid>/timerslack_ns`), `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECCOMP` (see seccomp below)
  with their `PR_GET_*`, and Yama's `PR_SET_PTRACER`, which reads no other
  argument: 0 clears it, `PR_SET_PTRACER_ANY` (or -1 as an `int`) lets any
  process attach, and another value, taken as an `int`, names a task in the
  caller's PID namespace (`EINVAL` for none) whose process, and its
  descendants, may attach while that task is there. It is the process's,
  whichever thread sets it, and a child does not inherit it.
  `PR_SET_VMA` with `PR_SET_VMA_ANON_NAME` names anonymous memory, as
  Linux's `set_anon_vma_name` does: a name of up to 80 bytes with its NUL
  (`EINVAL` past them, `EFAULT` where it cannot be read), of printable
  ASCII but `` \`$[] `` (`EINVAL`), or none to clear it, from a
  page-aligned start (`EINVAL`) over a size rounded up to pages. Each VMA
  of the range takes it, split where the range starts and ends within it
  with its lock and `userfaultfd` kept, a file's mapping ending it with
  `EBADF` and a hole with `ENOMEM` once the rest has it. `/proc/<pid>/maps`
  and `smaps` show it as `[anon:<name>]`, and as `[anon_shmem:<name>]` for
  shared anonymous memory, the heap and the stack keeping their own names;
  VMAs of different names do not merge, and a `fork`ed child keeps them.
  `PR_SET_THP_DISABLE` and `PR_GET_THP_DISABLE` are of the address space,
  which a thread shares and a `fork`ed child and an `execve` keep, as
  Linux's `MMF_DISABLE_THP_*` flags: a nonzero second argument disables
  transparent huge pages, with `PR_THP_DISABLE_EXCEPT_ADVISED` (2) as the
  third only where `MADV_HUGEPAGE` did not ask for them, and 0 with no flag
  enables them again (`EINVAL` for another flag, a flag when enabling, or a
  fourth or fifth argument). `PR_GET_THP_DISABLE` takes no argument
  (`EINVAL`) and gives 0, 1, or 3 for the kind that excepts advised
  memory. Disabled for every VMA, `MADV_COLLAPSE` is refused (`EINVAL`),
  as Linux's `vma_thp_disabled` decides; nothing else changes, as the
  emulator places a mapping where a huge page would fit either way, as
  Linux does.
  Other options give `EINVAL`.

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
  parent's PID and the real user ID of its thread that exited, which needs
  the same permission of that thread over the thread that set the signal.

- `rt_sigqueueinfo` (behind `sigqueue`) sends a process the caller's siginfo
  as it is, and `rt_tgsigqueueinfo` sends it to one thread, so the signal
  carries its value; each realtime signal sent is kept. As in Linux, only a
  thread signalling itself may give a `si_code` that the kernel, `kill` or
  `tkill` would give (`EPERM`, checked before the target), and a `si_code`
  whose layout Linux does not know must leave the rest of the siginfo zero
  (`E2BIG`).

- Resource limits start at Linux's defaults (`RLIMIT_NOFILE` 1024/4096,
  `RLIMIT_STACK` 8 MiB/unlimited, ...), are inherited on `fork` and can be
  read and changed; the hard `RLIMIT_NOFILE` goes up to `fs.nr_open`
  (1048576 at first, which root may change through `/proc/sys/fs/nr_open`),
  or to a lower ceiling the embedder sets. Raising a hard limit
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
    signal (`NT_SIGINFO`), the auxiliary vector its exec saved (Linux's
    `saved_auxv`, whatever the program did to its stack), the mapped files
    (`NT_FILE`:
    each VMA that maps a file, where renames have moved it, followed by
    `(deleted)` once the name it has is removed, as in `/proc/<pid>/maps`,
    from the process's root when it is under it, and shared anonymous
    memory as `/dev/zero (deleted)`, as Linux names it) and the memory. It
    has no `NT_X86_XSTATE` note, as Linux writes none on a CPU without XSAVE, which the virtual CPU is. The memory is
    chosen as Linux's `vma_dump_size` chooses it with the process's
    `coredump_filter` (below; with the default `0x33`): a hugetlb mapping is
    there whole for its private or shared hugetlb bit, and an I/O mapping
    never; a private mapping is there whole for the anonymous private bit
    once a page of its VMA was written (Linux's `anon_vma`, which a split and
    `MADV_DONTNEED` keep, a mapping merging with the VMA shares, and bringing
    a writable one's pages in gives it: `MAP_POPULATE`, `MAP_LOCKED`, or a
    lock not on fault; a `fork`ed child's VMAs each get their own), else, for
    a file mapping, whole for the file-backed private bit, else only its first
    page for the ELF headers bit when it maps the file from its start and the
    file has an execute bit when the core is written, or else starts with
    the ELF magic (an ELF library need not be executable); a shared mapping
    is there whole for the anonymous shared bit when no name links its file
    (an anonymous one, a memfd, a file unlinked since), else for the
    file-backed shared bit. Of the program's own image, the stack and a
    writable segment count as written and the first page is its ELF header.
    Whether a mapping can be read matters only for that ELF header's page:
    Linux reads the others whatever their protection. Each VMA is one segment, with the
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
    the host), `TCP_CORK` (which does not), `TCP_KEEPIDLE`, `TCP_KEEPINTVL`,
    `TCP_KEEPCNT`, `TCP_QUICKACK`, `TCP_USER_TIMEOUT`, `TCP_INFO` (read
    only), `IP_TOS` and `IPV6_V6ONLY`, with Linux's defaults and range checks: `SO_SNDBUF` and `SO_RCVBUF` are at most the default
    `wmem_max` and `rmem_max` (212992), doubled; a new `IP_TOS` sets
    `SO_PRIORITY` from its TOS bits too (`rt_tos2priority`), and takes one
    byte for an `int` (`do_ip_setsockopt`); a datagram socket takes its two
    bits of ECN, and TCP keeps its own (`__ip_sock_set_tos`).
    `SO_TIMESTAMP`, its kin
    and `SO_TIMESTAMPING` are set and read back as on AF_UNIX sockets, and
    `SOF_TIMESTAMPING_OPT_ID` needs a TCP socket's connection (`EINVAL`
    while it is closed or listening). `SO_BINDTODEVICE` takes a device's
    name, of at most 15 bytes (`ENODEV` for one there is not), none or an
    empty one for no device, and `SO_BINDTOIFINDEX` an index (`EINVAL` for
    a negative one, any other taken); without `CAP_NET_RAW` a socket bound
    to a device stays so (`EPERM`, `sock_bindtoindex_locked`). Read back,
    `SO_BINDTODEVICE` gives the name in room for a whole one (`EINVAL` for
    less, `ENODEV` for an index of no device), nothing for none. Bound so,
    a socket takes only what comes in on that device, or for one bound to
    no device anything, one bound to it before one bound to none and
    after a connected one (`compute_score`); a packet to the namespace's
    own address comes in on that address's device (its local route's, or
    `lo` for none), for IPv4 as for IPv6. Its IPv4 packets go
    by the routes through the device only, and where none goes, on link
    through it; a group of 224.0.0.0/24 or the limited broadcast address
    straight out through it (`ip_route_output_key_hash_rcu`): `ENODEV`
    once it has gone, `ENETUNREACH` while it is down. What goes out
    through `lo` so comes back in on it, whatever its address
    (`rt_dst_alloc`): a datagram to whatever takes it there, and a
    connection's SYN, whose answer finds no route from an address not
    the namespace's own, and from one that is comes in on that address's
    device. A connection
    accepted is bound as its listener, or, where that has no device, one
    from a link-local address to the device it came in on
    (`tcp_v6_init_req`), which is also the `IPV6_MULTICAST_IF` of any one
    accepted on an IPv6 socket (`tcp_v6_syn_recv_sock`). Of an IPv6 socket,
    `IPV6_MULTICAST_IF` (not of TCP, `ENOPROTOOPT`) and `IPV6_UNICAST_IF`
    (in network byte order) take the index of a device (`ENODEV` and
    `EADDRNOTAVAIL` for one there is not), 0 for none, and `IPV6_PKTINFO`
    (set only, its address unused, as UDP sends) any; each `EINVAL` for
    one other than the device the socket is bound to, `IPV6_UNICAST_IF`
    for any then (`do_ipv6_setsockopt`). A UDP datagram to an address
    without a scope ID, and a UDP `connect`, go through the socket's own
    device, else `IPV6_PKTINFO`'s, else `IPV6_MULTICAST_IF`'s to a group
    and `IPV6_UNICAST_IF`'s to another address (`udpv6_sendmsg`,
    `ip6_datagram_flow_key_init`): strictly where the socket has a device or
    is bound to no address, or the destination is a group, a link-local
    address or `::1`;
    else through it rather than another, among the routes of one prefix
    and metric (`rt6_score_route`). Connecting a socket of no device to a
    group of the link makes `IPV6_MULTICAST_IF`'s its own. A connected
    socket keeps the route its `connect` found, with its hop
    (`ip6_sk_dst_lookup_flow`, of Linux master: `sendto` with an address
    looks one up): a `send` takes it while one of these options names
    another device no more, until the route goes or its node changes
    (`ip6_dst_check`), as a route added there or at a longer prefix, a hop
    gone dead, an address gone and one whose duplicate address detection
    is done change it, or `SO_BINDTODEVICE`, `SO_BINDTOIFINDEX` or another
    `IP_TOS` drops it; then it keeps the one it looks up.
    `IP_UNICAST_IF`, of IPv4 and IPv6 sockets and TCP's too, takes the
    index of a device in network byte order (`EADDRNOTAVAIL` for one there
    is not) in an `int` exactly (`EINVAL` for another length), 0 for none,
    and is `EINVAL` on a socket bound to a device (`do_ip_setsockopt`). A
    UDP datagram to an IPv4 address other than a group, an IPv6 socket's
    IPv4-mapped one too, and a UDP `connect` go through its device where
    the socket has none of its own (`udp_sendmsg`,
    `__ip4_datagram_connect`), as through `SO_BINDTODEVICE`'s; TCP goes by
    its routes. Each IPv4 send looks its route up, where Linux's connected
    socket keeps the one its `connect` found (`sk_dst_check`), until the
    routes change, when the option changes after it.
  - **`TCP_INFO`** gives Linux's 280-byte `struct tcp_info`, as much of it
    as the room asks (`tcp_get_info`): a listener's state, connections
    waiting and backlog; a socket that has not connected, Linux's
    defaults; a handshake, its retries, with the timeout doubling past
    `tcp_syn_linear_timeouts`; a connection, its state, options
    (timestamps, SACK and window scaling), window scales (10, or less for a
    receive buffer the guest set), the bytes it sent, had acknowledged and
    received with its handshake and ends, those not sent yet, its segments
    and the times since data went and came. On the loopback the segments are
    those Linux sends: each write its own, held while a small one waits for
    its acknowledgement (Nagle's algorithm, unless `TCP_NODELAY` or urgent
    data) or for what `MSG_MORE` or `TCP_CORK` says comes next (up to
    201 ms, or until the cork is cleared or `TCP_NODELAY` set); the first 16
    acknowledgements at once, then with the data a side replies with, on a
    read, or after 40 ms (`TCP_QUICKACK` sets which); at most 10 in flight
    at first; a tail loss probe, which sends the last again; and the end,
    with the data held before it. `FIN_WAIT1` lasts until the end is
    acknowledged. What is held reaches the peer, with its time, when it
    does on Linux, whether or not a call is made then: `SIGIO` for it ends
    a sleep. A UDP socket has no TCP options (`EOPNOTSUPP`).
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

- **`bind`** takes an address of its network namespace (the loopback's
  `127.0.0.0/8` and `::1`, a veth end's, or IPv4 ones IPv4-mapped on an
  IPv6 socket) or the unspecified one, with a port
  or, for port 0, an ephemeral one from 32768–60999 (none of the ports
  that an `--allow-net` entry with a port reaches the host's loopback at,
  where a connection would reach the host's socket; an entry for every
  port leaves none out, but a connection to a loopback port a guest socket
  holds is refused on the guest's loopback, not sent to the host), with
  Linux's checks in
  its order: `EADDRNOTAVAIL` for another address, `EINVAL` once bound,
  `EADDRINUSE` for a port another socket holds on an address both cover (a
  listener's, a connection it accepted, a client's), unless both set
  `SO_REUSEADDR` and the other does not listen, or both set
  `SO_REUSEPORT`, or the two are bound to other devices
  (`inet_bind_conflict`, `udp_lib_lport_inuse`). An IPv6 socket on `::` holds the port for IPv4 too,
  unless `IPV6_V6ONLY`; binding to another IPv6 address that is not an
  IPv4 one sets `IPV6_V6ONLY`, as `__inet6_bind` does. A link-local
  address, or a group of the node or the link (which only a UDP socket
  binds, as any group), needs a device: its scope ID's (`sin6_scope_id`,
  of a 28-byte address), which becomes the socket's and stays though the
  bind fails, or the one the socket has: `EINVAL` without one, `ENODEV`
  for one there is not, and `EADDRNOTAVAIL` for a link-local or loopback
  address of another device (`ipv6_chk_addr`). `getsockname` and
  `getpeername` give the socket's device as the scope ID of an address
  that needs one, and `recvfrom` the device a datagram came in on. UDP's
  `sendto` goes through the scope ID's device, for an address that needs
  one, else the socket's, strictly (`ENETUNREACH` where no route goes
  through it), from an address of that device's where it is bound to
  none, and `connect`, UDP's and TCP's, the same way: the scope ID
  becomes the socket's device, which a TCP socket keeps though the connect
  fails and a UDP one does not, as Linux master puts it back; `EINVAL`
  for one other than the device the socket has, or for none where the
  socket has none (`__ip6_datagram_connect`, `tcp_v6_connect`).
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
  not set holds 256 KiB. `SIOCOUTQ` counts what waits to be sent or
  acknowledged, and `FIONREAD` what has arrived.
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
  bound itself, and no device (`__udp_disconnect`). An IPv6 socket keeps its
  peer's address too (`sk_v6_daddr`), which `sock_diag` tells with port 0: it
  takes an IPv6 datagram from that address alone, one to a group too
  (`__udp_v6_is_mcast_sock`), and any IPv4 one, until it
  connects again. A datagram holds up to 65507 bytes over IPv4 and 65527 over
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
- `execve` keeps the signals pending for the thread that runs it and for the
  process, and the signals it blocks; the other threads end with theirs
  (`de_thread`). It resets the actions as Linux's `flush_signal_handlers`
  does: a handled signal goes back to its default, and an ignored one stays
  ignored, with no flags or mask. `CLONE_CLEAR_SIGHAND` resets the child's
  actions the same way.
- The first program starts with the signals the emulator was started with
  ignored still ignored, as the `execve` that started it on Linux would leave
  them. A job a shell starts in the background with `&` has `SIGINT` and
  `SIGQUIT` ignored, for example. `SIGPIPE` is the exception: Rust's runtime
  ignores it in the emulator itself, so it always starts at its default.
  In WebAssembly no signal starts ignored.
- The threads of a process share its signal dispositions, as Linux's
  `sighand_struct` does. A thread that was already waiting (in `epoll_wait`,
  `poll` or a `futex` wait, say) when another thread called `sigaction` takes
  a process-directed signal in with the new handler. So a SIGCHLD handler
  set after a helper thread began to wait still runs, as Node.js's child
  processes need.
- `ptrace` traces another task as Linux's `kernel/ptrace.c` does.
  `PTRACE_TRACEME` makes the thread that forked the caller its tracer;
  `PTRACE_ATTACH` sends the task `SIGSTOP` from the kernel, and
  `PTRACE_SEIZE` stops it only at `PTRACE_INTERRUPT`. `PTRACE_ATTACH` and
  `PTRACE_SEIZE` both refuse a task of
  the caller's own process, one already traced or exited, and one the caller
  may not attach to (`ptrace_may_access` with the real IDs, and Yama's
  `ptrace_scope`), with `EPERM`. Only the tracer thread may make requests,
  and only of a tracee in a ptrace stop, but for `PTRACE_KILL` and
  `PTRACE_INTERRUPT` (`ESRCH`). A task already in a group stop when it is
  attached or seized is made to report that stop to its new tracer, and the
  call returns once it has.
- A traced thread stops for its tracer at every signal it takes but
  `SIGKILL`, ignored ones too, and at a group stop, which a seized task
  reports as `PTRACE_EVENT_STOP` with its siginfo and one attached otherwise
  as the stop signal alone. `PTRACE_CONT` resumes it with the signal it
  stopped for, none or another, which then comes from the tracer
  (`SI_USER`), or with the siginfo `PTRACE_SETSIGINFO` left; a signal it
  blocks waits. A tracee resumed from a group stop runs while the group
  stays stopped. `PTRACE_DETACH` lets it go with a signal, and `PTRACE_KILL`
  sends its process `SIGKILL`. While traced, a process takes no fatal signal
  but `SIGKILL` as it is sent: its tracer sees each first.
- `wait4` and `waitid` report a tracee's ptrace stops to its tracer whatever
  their options ask for (`CLD_TRAPPED`, the event above the signal in the
  status), a traced thread without `__WALL` too, and with `__WNOTHREAD` only
  what the calling thread traces. A parent that traces its child sees its
  ptrace stops in place of its group stops. A traced thread that exits waits
  for its tracer, and a process traced by another than its parent exits to
  its tracer first, then to its parent.
- While a tracee is stopped, its tracer reads and writes its memory with
  `PTRACE_PEEKTEXT`/`PTRACE_PEEKDATA` and `PTRACE_POKETEXT`/`PTRACE_POKEDATA`
  as `FOLL_FORCE` lets it: any mapped page reads, a private one that may not
  be written takes a copy of its own, and a shared one that may not be
  written refuses (`EIO`). It reads and writes the registers with
  `PTRACE_PEEKUSER`/`PTRACE_POKEUSER` (`struct user`), `PTRACE_GETREGS`/
  `PTRACE_SETREGS`, `PTRACE_GETFPREGS`/`PTRACE_SETFPREGS` and
  `PTRACE_GETREGSET`/`PTRACE_SETREGSET` with `NT_PRSTATUS` and `NT_PRFPREG`,
  as Linux's `putreg` takes them (only the flags a tracer may change, a
  segment base below `TASK_SIZE_MAX`, a null or user segment selector and
  `cs` and `ss` not null, `EIO` otherwise; a selector is kept as written,
  and a new `fs` or `gs` selector leaves the base, as with FSGSBASE; exec
  gives back the ones a task starts with), and the stop's
  siginfo with `PTRACE_GETSIGINFO`/`PTRACE_SETSIGINFO` (`EINVAL` for a stop
  without one). `orig_rax` is the call the tracee stopped after, -1 after
  anything else, and a call the stop interrupted shows its restart code in
  `rax` (`-ERESTARTSYS`, `-ERESTARTNOINTR`, `-ERESTARTNOHAND`,
  `-ERESTART_RESTARTBLOCK`): the code the tracer leaves there decides
  whether it runs again, as Linux restarts by it (another restart code
  restarts as that one does, `-ERESTART_RESTARTBLOCK` as `restart_syscall`),
  any other value ends the restart, `orig_rax` set to -1 too, when the code
  is what the call returns, and another `orig_rax` is the call that runs.
  A signal sent to the tracee while it is stopped is taken as the stop ends,
  before the call runs again, as Linux's `get_signal` goes on past the stop:
  the tracee stops for it with the restart code still in `rax`. A tracee let
  go while its group is stopped stays stopped and takes its signals once
  the group continues.
  `PTRACE_O_SUSPEND_SECCOMP` lets the tracee's calls past its seccomp
  filters and strict mode; setting it needs `CAP_SYS_ADMIN` and a tracer
  under no seccomp mode (`EPERM`), as on a Linux with checkpoint and
  restore.
- With `PTRACE_SYSCALL`, a tracee stops at the entry and at the exit of each
  system call (`SIGTRAP`, or `SIGTRAP | 0x80` with `PTRACE_O_TRACESYSGOOD`),
  and with `PTRACE_SYSEMU` at the entry only, where the call does not run.
  At an entry `rax` is `-ENOSYS` and `orig_rax` the call: the tracer may
  change the call and its arguments, or set `orig_rax` to -1 to skip it,
  leaving the `rax` it wants; at an exit `rax` has what the call returned,
  which the tracer may change. A signal the tracer resumes a syscall stop
  with is sent to the thread from the kernel (`SI_KERNEL`).
  `PTRACE_GET_SYSCALL_INFO`
  describes the stop as Linux's `struct ptrace_syscall_info` does: the call
  and its arguments at an entry, the return value and whether it is an
  error at an exit, and only the instruction and stack pointers at another
  stop or without `PTRACE_O_TRACESYSGOOD`. `PTRACE_SET_SYSCALL_INFO` changes
  the call, its arguments or the return value, refusing another kind of
  stop, flags or a short buffer (`EINVAL`) and a number that is not an
  `int` (`ERANGE`).
- The events of `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACEVFORK`,
  `PTRACE_O_TRACECLONE`, `PTRACE_O_TRACEEXEC`, `PTRACE_O_TRACEVFORKDONE` and
  `PTRACE_O_TRACEEXIT` stop the tracee with the event above `SIGTRAP` in the
  status, `rax` at `-ENOSYS`, and `PTRACE_GETEVENTMSG` gives the new task,
  the thread's ID before `execve`, or the exit status. A task a `clone`,
  `fork` or `vfork` makes while its maker's tracer asks for the event, or
  with `CLONE_PTRACE` (never with `CLONE_UNTRACED`), is traced by the same
  tracer with the same options, and starts in `PTRACE_EVENT_STOP` if
  seized, otherwise with `SIGSTOP` pending; it starts with no syscall stops.
  A `vfork` parent reports `PTRACE_EVENT_VFORK_DONE` once its child has
  exited or run another program. The thread that ends its process reports
  `PTRACE_EVENT_EXIT`, its status with 0x80 when a fatal signal dumps a
  core; the threads that end with it do not.
- A tracer sets hardware breakpoints in the debug registers with
  `PTRACE_POKEUSER`, as Linux's `ptrace_set_debugreg` takes them: DR0–DR3
  hold the addresses, which must be in user space and aligned to the
  breakpoint's length (`EINVAL`), and DR7 enables them and gives each its
  type, an instruction (1 byte), a write, or a read or write, and its
  length, 1, 2, 4 or 8 (`EINVAL` for an I/O breakpoint or a longer
  instruction one, leaving DR7 as it was); there is no DR4 or DR5 (`EIO`).
  An instruction breakpoint stops the tracee before the instruction, with
  RF set so that it runs once resumed, and a data one after the instruction
  that accesses the range, after the iteration for a `rep` string
  instruction, with `rip` still on it while it repeats: `SIGTRAP` with `TRAP_HWBKPT` and the address in
  `rip`, and DR6 with the breakpoint's bit, and with `DR_STEP` after a
  single step. A new task has none, and exec clears them. While none is
  set, the guest runs as fast as before; while one is, it runs one
  instruction at a time.
- `PTRACE_SINGLESTEP` resumes a tracee with the trap flag set, which the
  tracer does not see in its registers unless the tracee set it itself
  (`TIF_FORCED_TF`), and any other resume takes it back: the tracee stops
  with `SIGTRAP` after one instruction, and after a `syscall` at the call's
  exit with `TRAP_BRKPT`. A single-stepped tracee entering a signal handler
  stops with `SIGTRAP` before it, and is no longer stepped: the handler's
  frame keeps no trap flag the tracer set. `PTRACE_SYSEMU_SINGLESTEP` steps as well,
  and stops at each call's entry, which does not run, as `PTRACE_SYSEMU`.
- `PTRACE_PEEKSIGINFO` reads the siginfo of the signals pending for a
  stopped tracee, or with `PTRACE_PEEKSIGINFO_SHARED` for its process, in
  the order they came. `PTRACE_GETSIGMASK` shows the signals it blocks
  (the mask a `sigsuspend` or `ppoll` puts back while it waits), and
  `PTRACE_SETSIGMASK` sets them, never SIGKILL or SIGSTOP, for when it goes
  on. `PTRACE_LISTEN` lets a seized tracee in a group stop wait there
  without being in a stop that wait or another request sees, until the
  group stop ends or begins again or `PTRACE_INTERRUPT` comes, when it
  reports `PTRACE_EVENT_STOP` again. `PTRACE_ARCH_PRCTL` reads and sets the
  `fs` and `gs` bases as `arch_prctl` does, and
  `PTRACE_GET_RSEQ_CONFIGURATION` shows the tracee's `rseq` registration.
- After `execve`, a task traced without `PTRACE_SEIZE` or
  `PTRACE_O_TRACEEXEC` gets `SIGTRAP` from itself. A thread other than the
  leader that runs `execve` is traced by the leader's number after it. A
  tracer thread's exit lets go of its tracees, killing those that
  set `PTRACE_O_EXITKILL`. `/proc/<pid>/status` shows `TracerPid`, and a
  tracee in a ptrace stop is in `t (tracing stop)`.

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
  which give `EINTR`. A signal with a handler that is pending as the stop ends,
  such as one sent before the `SIGCONT`, is taken then, as Linux's
  `get_signal` goes on past the stop: the call ends as that handler decides,
  `pause` with `EINTR`. One sent right after the `SIGCONT` may come only once
  no signal was found, as on Linux: the call has been rewound by then, and the
  handler returns into it.
  `epoll_wait`, `epoll_pwait`, `epoll_pwait2` and `rt_sigtimedwait` give
  `EINTR`, as on Linux. `rt_sigsuspend` waits with its mask in place of the signal mask until a
  handler has run, which runs with that mask; the original mask is back after
  it. The mask stays through a stop, as on Linux, so a signal that only it
  unblocks, sent while the thread is stopped, is taken as the stop ends.
- On its way back to user space a thread takes every signal it may, as
  Linux's `exit_to_user_mode_loop`: its own pending ones by number, then the
  process's by number (`dequeue_signal`), the synchronous ones (`SIGSEGV`,
  `SIGBUS`, `SIGILL`, `SIGTRAP`, `SIGFPE`, `SIGSYS`) first, a queued
  real-time signal's instances in the order they came. Each handler's frame
  goes on the one before, with the mask that handler runs with, so the last
  frame's handler runs first, and a signal that mask blocks waits for its
  `rt_sigreturn`. Only the first can restart the call the thread was in.
- `sigaction` keeps and shows only the flags Linux knows (`UAPI_SA_FLAGS`:
  `SA_NOCLDSTOP`, `SA_NOCLDWAIT`, `SA_SIGINFO`, `SA_ONSTACK`, `SA_RESTART`,
  `SA_NODEFER`, `SA_RESETHAND`, `SA_EXPOSE_TAGBITS`, `SA_RESTORER`), so a
  program sees that `SA_UNSUPPORTED` is not. A new action it cannot read is
  `EFAULT` before the signal is checked, and an old action it cannot write
  is `EFAULT` after the change is made, as in Linux's `rt_sigaction`.
- A `sigaction` that makes a signal ignored (`SIG_IGN`, or `SIG_DFL` for
  `SIGCHLD`, `SIGCONT`, `SIGURG` and `SIGWINCH`, which are ignored by
  default) discards its pending instances in the process and in every thread,
  as Linux's `do_sigaction` does. A blocked signal sent after that stays
  pending. An unblocked ignored signal, such as the `SIGCHLD` of a child that
  ends, ends no wait in any thread: a blocked `read` stays blocked and a
  `nanosleep` sleeps on, as Linux drops the signal as it is sent
  (`sig_ignored`), so that a handler set later does not run for it. It is
  kept if the thread it is sent to (the leader, for a process) blocks it or
  is traced. `SIGCONT` takes the pending stop signals away, and a stop signal
  the pending `SIGCONT`, even one that is then dropped.
- A signal sent to a process goes to the thread Linux's `complete_signal`
  chooses: the one it is sent to, or else the first that wants it, from the
  thread last chosen so on. That is the leader for `kill` (or the thread whose
  ID it names), signal-driven I/O and `ITIMER_REAL`, the thread that made the
  child for `SIGCHLD`, and the one that runs for the timers on CPU time. A
  thread wants a signal it does not block, unless it is in a group stop or a
  ptrace stop, exits, or sleeps with another pending. The others sleep on. A
  thread that takes a signal in takes every other of the process's it does
  not block; those it then blocks, or leaves as it exits, go to another
  (`retarget_shared_pending`), and one no thread wants waits until one
  unblocks it. `rt_sigtimedwait` counts as unblocking what it waits for.

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
- A symbolic link outside `/dev` and `/proc` that leads into them, as
  `ln -s /dev/null f` makes, or a link to `/dev` on the way, leads to the
  file the kernel generates there: `stat`, `statx`, `access`, `open` and
  the other calls that look a path up go on there as for the path it
  leads to, as do `execve` and the calls that make or remove a name
  through it (`mkdir`, `mknod`, `symlink`, `link`, `unlink`, `rmdir` and
  `rename`) (`readlink` reads a link there, as `/dev/fd`, and the `xattr`
  calls, `statfs`, `link` and `name_to_handle_at`, with their `*at`
  forms, take the generated file), and a descriptor opened through it
  names that file in `/proc/self/fd`.
- The files the kernel generates in `/dev` and `/proc` take the path calls
  that change a file, by their own path or through such a link, as Linux's
  `notify_change` makes them there: `chmod`, `chown`, `utimensat` and the
  other time calls check the file's owner and mode as on any file, and
  procfs refuses a new mode of a process's file (`proc_setattr`) and a new
  mode or owner of a sysctl's (`proc_sys_setattr`), `EPERM`; a
  pseudo-terminal's slave in `/dev/pts` takes a new mode and owner from its
  owner. `truncate` of a regular file there that the caller may write
  succeeds and changes nothing, of a directory is `EISDIR` and of a device
  `EINVAL`. `chdir` and `fchdir` make a directory there the working
  directory, which `getcwd` names and relative paths start from.
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
  adds a classic BPF program, checked as Linux checks one: first as a
  socket's classic filter is (`bpf_check_classic`), then for the
  instructions seccomp takes (`seccomp_check_filter`). It has up to 4096
  instructions, only 32-bit loads of `struct seccomp_data` and no `mod`,
  forward jumps inside the program, scratch words written before they are
  read on every path, and a return at the end, else `EINVAL`. All of a
  thread's filters may hold 32768 instructions, each counting 4 more
  (`ENOMEM`). Before each call every filter runs over the
  call's number, `AUDIT_ARCH_X86_64`, the address after its `syscall`
  instruction and its six argument registers, whole, and the lowest action
  decides. `SECCOMP_RET_KILL_PROCESS` ends the process by `SIGSYS`, and
  `SECCOMP_RET_KILL_THREAD` the thread, or the process when it is the last
  thread (a division by an X of 0 returns 0, which is this action). A kill
  of the process leaves `SIGSYS`'s action at its default and
  `SA_IMMUTABLE`, as `force_sig_seccomp` forces it: a process that shares
  the actions (`CLONE_SIGHAND`) then gets `EINVAL` from `sigaction` for
  `SIGSYS`, a process it forks copies that, a tracer sees no stop for its
  delivery, and `execve` clears it;
  `SECCOMP_RET_TRAP` forces a `SIGSYS` with `SYS_SECCOMP`, the data in
  `si_errno`, the call's address, number and architecture, and the call's
  number back in `rax`; `SECCOMP_RET_ERRNO` returns its data, at most 4095,
  as an error; `SECCOMP_RET_TRACE` stops the thread for its tracer with
  `PTRACE_EVENT_SECCOMP` and the data as the event's message if the tracer
  asked for it with `PTRACE_O_TRACESECCOMP`, and the call, which the tracer
  may change or skip by setting `orig_rax` below 0, runs past the filters
  again; without such a tracer it gives `ENOSYS`;
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
- **aube**: a Node.js package manager written in Rust (v2.10.1). `--version`,
  `install`, `install --frozen-lockfile` and `list` give the same output and
  exit status as on real Linux.
- **ripgrep**: a text search tool written in Rust (16.0.0), which runs its
  searches on several threads. Nine searches, including a regular expression
  replacement, a parallel search, one through a memory-mapped file and two
  errors, give the same output and exit status as on real Linux. `--version`
  is not compared, because it reports the SIMD features `CPUID` shows, which
  paludarium limits on purpose.
- **coreutils**: uutils coreutils (0.13.0), the GNU utilities rewritten in
  Rust, built as one multicall binary. 68 cases of 47 utilities give the
  same output, exit status and, for the 15 that change files, the same files
  as on real Linux. They read, sort, cut and count text, hash and encode it,
  list and stat files, print dates in two time zones, and copy, move, link,
  split and remove files, with errors such as a missing file or a directory
  that is not empty. `id`, `uname`, `pwd` and `env` are not compared, because
  they print the host's identity, path and environment.

All of them give the same results as a real x86-64 Linux on Linux, macOS and
Windows, and on Node.js, Chromium, Firefox and Safari.
