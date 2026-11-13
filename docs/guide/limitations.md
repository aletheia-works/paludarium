# Limitations

paludarium is a young project. These things are not possible yet, or not
verified.

## Not supported

- **Part of x87, for now**: the transcendental instructions (`FSIN`, `FCOS`,
  `FSINCOS`, `FPTAN`, `FPATAN`, `F2XM1`, `FYL2X`, `FYL2XP1`) and packed decimals
  (`FBLD`, `FBSTP`) are not implemented yet, so a program stops with `SIGILL`
  where it reaches one. An x87 exception always takes its masked response: an
  unmasked one sets the status word's summary and does not raise `SIGFPE`. The
  16-bit forms of `FNSTENV` and `FLDENV` (with a `0x66` prefix) are not
  implemented either. `FISTTP` belongs to SSE3, which `CPUID` does not report,
  and is not implemented. Where `FPREM` and `FPREM1` stop on the way when their
  operands are far apart is each CPU's choice: the final remainder is the same.
- **A dynamically linked program's files, unless given**: a program runs with
  its interpreter as on Linux, on musl's dynamic linker or glibc's. A session
  reads the interpreter and the libraries from its own files, so they must be
  mounted or given to it.
- **32-bit x86, AVX, AVX-512, MMX**: out of scope. `CPUID` reports MMX because
  glibc requires it, but its instructions stop with `SIGILL`, as do the SSE and
  SSE2 ones that use MMX registers (`CVTPI2PS`, `MOVQ2DQ`, `PSHUFW` and the like).
- **The exact results of `RCPPS`, `RCPSS`, `RSQRTPS` and `RSQRTSS`**: x86 only
  bounds their error (1.5 × 2⁻¹²), and each CPU answers from its own table. The
  emulator computes them by floating-point division (after a square root for
  `RSQRT`), so the low bits can differ from a real CPU's. The tests check that
  bound and the special values, not the bits.
- **`MASKMOVDQU` with an empty mask on memory it cannot reach**: the emulator
  makes no access, and a real CPU may fault (an AMD EPYC does, and exits with
  `SIGSEGV`). A fault on a later byte also leaves the earlier ones written, which
  has not been compared with a real CPU.
- **`/proc/self/maps`, in part**: the emulator has no vDSO or `vsyscall` page,
  so the `[vvar]`, `[vdso]` and `[vsyscall]` lines are not there. The stack's
  VMA has its full size from the start, where Linux's grows as it is used. A
  program's own segments and its interpreter's are named by the path it was
  started by, never marked `(deleted)`, where Linux follows a rename and resolves
  symbolic links. `/proc/<pid>/maps` of another process, `smaps` and
  `[anon:<name>]` names (`PR_SET_VMA`) do not exist.
- **The rest of `/proc`, in part**: only the process directories and a few
  system files are made (see [features](./features)). The other system files
  (`/proc/cpuinfo`, `/proc/sys` but for `fs/mqueue`, ...) and the other names in
  the reader's own directory (`auxv`, `limits`, ...) are looked up like any
  path, which with `--mount /:/` finds the host's `/proc`; in another
  process's directory they are `ENOENT`, where Linux shows root `fd`, `maps`,
  `statm` and the rest. In `stat`, page faults, resident memory, the start
  time and the code range are 0, so `ps` shows no `RSS`, and its `STIME` and
  `START` are the boot time in `/proc/stat`. `/proc/stat` counts no CPU time,
  interrupts or context switches, and lists no interrupt numbers. A thread's `stat` gives its process's CPU time, and
  another process's state is taken from where its thread is (in a system
  call or not), not from whether it waits. A thread shows another process
  what it published at its last system call or signal check, so a mask
  changed only for the length of a call (`rt_sigsuspend`, `ppoll`) is not
  seen. `meminfo` shows the fixed 4 GiB that `sysinfo` reports, with nothing
  used.
- **Device nodes and FIFOs on the host**: `mknod` of a character or block
  device is `EPERM`, although the guest runs as root, since paludarium has
  no device for it to stand for. A FIFO in a mounted host directory can be
  made on Linux hosts only, and connects only the guest's own openers, not
  host programs that open the same node.
- **Network**: without an allow list (`--allow-net`,
  `Config::with_network`, or the JavaScript `network` option, which a
  browser needs a [relay](./relay) for) `socket()` returns `EAFNOSUPPORT` for every family.
  With one, only TCP clients, TCP and UDP servers for the guest's own
  sockets and name resolution work ([Network](./features#network)):
  - A guest serves only its own sockets, on its loopback
    ([Loopback servers](./features#loopback-servers)): neither the host nor
    another machine can connect to it, and `bind` takes only the loopback's
    addresses and the unspecified one (`EADDRNOTAVAIL` for any other, where
    Linux takes each of the machine's own).
  - A UDP socket reaches the DNS stub and the guest's own sockets on the
    loopback; a datagram to any other address is `ENETUNREACH`. One
    connected elsewhere to a peer the policy does not allow, or in
    WebAssembly, which cannot see the host's routes, keeps its port on every
    address, where Linux takes it on the
    route's source address: `getsockname` gives the unspecified address,
    and a `bind` of that port on a loopback address is `EADDRINUSE`, where
    Linux allows it.
    Multicast and broadcast datagrams reach no one. A datagram is always
    stamped as it comes, as Linux stamps it while some socket on the
    machine takes timestamps; with none, Linux stamps it only when
    `SO_TIMESTAMP` or its kin read it, at that time. A DNS stub's answer
    is stamped when it is read. Raw sockets are `EPERM`,
    ICMP sockets `EACCES`, and other kinds (SCTP's `SOCK_SEQPACKET`, which
    Linux loads a module for) `ESOCKTNOSUPPORT`.
  - Under a directory mounted from the host, an AF_UNIX socket binds to a
    path only on a Linux host, which makes the socket file there; on macOS,
    which lets only root make one, and on Windows, `bind` to a path there
    is `EPERM`. Guest sockets reach one another through such a file, but a
    host program's socket file finds no socket (`ECONNREFUSED`), and a
    host program cannot reach a guest's. A host without `/proc` (a chroot,
    a minimal container) also takes its own umask's bits from the file's
    mode. A socket file's write permission is not checked, as for root.
  - The DNS stub answers only `A` and `AAAA`, and ignores EDNS, so a
    datagram answer holds at most 512 bytes; a name the host cannot resolve
    is `SERVFAIL`. A TCP connection to port 53 always reaches the stub, never
    a real DNS server.
  - Before a connection through the host is open, `getsockname` gives the
    address the socket is bound to, or the unspecified one with port 0,
    where Linux gives the port it took; a port the socket bound does not
    reach the host, whose connection leaves from a port of its own. `SIOCOUTQ` counts what the
    host has not yet taken to send, not what the peer has not acknowledged.
    Through the host, `SO_SNDBUF` and `SO_RCVBUF` are kept for `getsockopt`
    but do not size the buffers, which hold 256 KiB each way; the other options but
    `TCP_NODELAY` do not reach the host's socket.
  - TCP bytes are always stamped as they come, as Linux stamps a segment
    while some socket on the machine takes timestamps; with none, Linux
    gives a segment that came then no timestamp. All the bytes waiting
    unread take the time the last came, where Linux joins a segment to
    the one before it only while that holds fewer than its limit of
    fragments (`MAX_SKB_FRAGS`), so a read of an earlier one can get an
    earlier time.
  - Through the host, `MSG_OOB` sends its byte as an ordinary one and finds
    no urgent data (`EINVAL`), so no `SIGURG` comes either.
  - On the loopback, an urgent byte sends `SIGURG` once, when it reaches
    the peer. Linux sends one more for each segment that arrives while the
    byte is more than 64 KiB further on, as when it waits behind a full
    buffer: the sender's `__tcp_transmit_skb` then gives each segment a
    stand-in urgent pointer 65535 bytes past its start, which the
    receiver's `tcp_check_urg` takes for a new one. How many segments that
    is hangs on Linux's own segmenting and window updates: with the default
    buffers, a few tens.
  - On the loopback, the `SO_SNDBUF` and `SO_RCVBUF` a guest sets bound a
    connection's buffers only roughly ([Loopback servers](./features#loopback-servers)):
    Linux also counts each segment's overhead and sizes its window in steps
    of its own, so a sender that nobody reads fits a different number of
    bytes before it waits. One the guest does not set holds 256 KiB, where
    Linux grows it as it tunes the connection (to megabytes).
  - `tcp_info` (`TCP_INFO`, `INET_DIAG_INFO`) has what the loopback
    carries as Linux counts it: the state, options, window scales,
    listener's queue, bytes sent, acknowledged, received and not yet sent,
    and the slow start threshold, congestion window, path MTU, advertised
    MSS and reordering Linux starts with. What Linux's TCP measures or
    tunes takes the values of a loopback connection in the simplest case:
    the round trip (30 µs) and the timeout, rates and pacing it gives, the
    send and receive MSS and windows, which never grow, and segment counts
    of the bytes sent and received in 32 KiB segments, one acknowledgement
    for each; the window scale its handshake offered stays; times
    since data came count from its read. Beyond a handshake's tries nothing
    is retransmitted or lost, so those counts are 0; the peer's window scale is taken as Linux's
    default, whatever buffer it set; and a connection the host made is
    told the same way as one on the loopback.
- **File mappings**: a file mapping shows the file's page cache as on Linux
  (a `MAP_PRIVATE` one in the pages it has not written), but the stores of a
  `MAP_SHARED` mapping reach the file on the host only when the guest reads
  the file, `stat`s it or calls `msync` or `fsync`, or the file's last
  mapping goes away (Linux writes them back in its own time), and a change
  another host program makes to the file does not reach the mappings. On a
  Windows host, the stores of a shared mapping made through a descriptor
  open with `O_APPEND` do not reach the file. The end of a mapped file, past
  which a page raises `SIGBUS`, is the size the guest's own file operations
  give it, so a host program changing the size does not move it.
- **Mappings that grow down**: only the main stack is a VMA that grows down.
  A mapping made with `MAP_GROWSDOWN` is an ordinary one, so it does not grow
  and `mprotect` with `PROT_GROWSDOWN` on it gives `EINVAL`, where Linux
  changes it.
- **Virtual CPUs**: a thread that has registered `rseq` runs on a virtual
  CPU, not on a CPU of the host's, so the CPU its area and `getcpu` show is
  not where the host runs it, and `/proc/<pid>/stat` shows CPU 0. Its
  critical section is aborted when it changes CPU or another thread ran on
  its own, which is when Linux's could be interrupted too, but not when the
  host preempts it, which no other thread with `rseq` can notice. A CPU mask
  another thread sets takes effect at the thread's next stop, and a thread
  in a system call holds no CPU, so its area shows the CPU it last ran on.
  Threads without `rseq` run on no virtual CPU and are not counted. There is
  no time slice extension: `RSEQ_FLAG_SLICE_EXT_DEFAULT_ON` gives `EINVAL`
  and `rseq_slice_yield` gives `ENOSYS`, as on a Linux built without it.
- **Protection keys**: the virtual CPU has none (`CPUID` reports no PKU), so
  `pkey_alloc` gives `ENOSPC` as Linux does on such a CPU, and programs carry
  on without them. `RDPKRU` and `WRPKRU` stop a program with `SIGILL`, as on
  such a CPU.
- **io_uring, in part**: only `IORING_OP_NOP` and `IORING_OP_EPOLL_CTL`
  run; the other operations complete with `EOPNOTSUPP`. The setup flags
  `IORING_SETUP_IOPOLL`, `_SQPOLL`, `_SQ_AFF`, `_ATTACH_WQ`, `_R_DISABLED`,
  `_SQE128`, `_CQE32`, `_NO_MMAP` and `_REGISTERED_FD_ONLY` give `EINVAL`,
  and `io_uring_register` has only `IORING_REGISTER_PROBE` (the others give
  `EINVAL`), so no ring descriptor, file, buffer or personality can be
  registered. A ring maps only shared (`MAP_PRIVATE` gives `EINVAL`), and
  `poll` and `epoll` cannot watch its descriptor. As every request completes
  in `io_uring_enter`, a wait for more completions than there are ends only
  by a signal or its timeout. The features are Linux 6.12's, so
  `IORING_FEAT_REG_REG_RING` is reported though no ring descriptor can be
  registered, and `IORING_FEAT_MIN_TIMEOUT` though a wait's `min_wait_usec`
  changes nothing (no request is ever in flight).
- **Native AIO, in part**: every read, write and sync runs as `io_submit`
  takes it, as Linux's buffered I/O does; one of a file opened with
  `O_DIRECT` does not run in the background as on Linux, and a sync's event
  is in the ring when the call returns, where Linux's comes from a worker
  soon after. A poll that waits is looked at only as a thread of the
  process makes a call (any call) and while one waits: a program that takes
  events from the ring without ever calling the kernel does not see it
  complete. Which files' polls wait on two queues, which Linux refuses with
  `EINVAL` unless the file is ready, is guessed from the kind of file: a FIFO
  open to read and write, and a character device (a terminal). A ring holds
  exactly one request fewer than its events, where Linux's per-CPU counts
  can stop one sooner; the I/O priority of `IOCB_FLAG_IOPRIO` is checked but
  changes nothing; and a ring `mremap` moves is found at its new address
  only when it moved whole (Linux refuses a partial move).
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature.
  - `pwritev2`'s `RWF_NOAPPEND` cannot turn an `O_APPEND` file's append off
    on a Windows host, which gives `EOPNOTSUPP` for such a file there.
    A regular file's `RWF_NOWAIT` read never finds its pages uncached
    (Linux's `EAGAIN`). On a macOS or Windows host a host file takes
    `RWF_NOWAIT` and `RWF_DONTCACHE` as ext4's does, whatever its own file
    system, and only ext4, xfs, btrfs and f2fs are told apart on a Linux
    host (any other file system takes neither).
  - `madvise` refuses (`EINVAL`) `MADV_COLLAPSE`, `MADV_HWPOISON` and
    `MADV_SOFT_OFFLINE`, which Linux takes. `MADV_REMOVE` and
    `MADV_GUARD_INSTALL` take the memory of a locked mapping too, where
    Linux gives `EINVAL`, as no mapping here is locked apart.
    `/proc/<pid>/smaps` shows no `VmFlags`, so not the `gu` flag of a VMA
    that had guards, and `/proc/<pid>/pagemap` is not there to show a
    guard page. `MADV_POPULATE_READ` and
    `MADV_POPULATE_WRITE` bring in the pages of a `memfd_secret` mapping,
    where Linux gives `EINVAL`.
  - `process_madvise` takes for the caller's own memory only the advice
    `madvise` takes, and another process's ranges are only checked to be
    mapped. It refuses advice Linux does not know before any range
    (`EINVAL`), as Linux master does; the CI's kernel checks it with each
    range, so with no ranges, or only empty ones, it gives 0 there.
  - `process_mrelease` takes a process as dying from the moment a SIGKILL
    is sent to it, but from another fatal signal only once one of its
    threads takes it, where Linux marks the process as it sends any signal
    that will end it (`EINVAL` here until then).
  - In a child of `fork`, `move_pages` shows a page of a shared mapping, or
    of a private one never written, that the parent had touched as there,
    where Linux copies no page table of such a VMA (`-ENOENT`
    until the child touches the page).
  - An error that ends `recvmmsg` after some messages is dropped, where
    Linux keeps it as the socket's error for the next call and
    `SO_ERROR`, and `recvmmsg` does not first give a socket's pending error.
  - The pages of a `memfd_secret` file do not count against
    `RLIMIT_MEMLOCK`, where Linux's fault past it raises `SIGBUS`, and
    `msync` with `MS_SYNC` of its mapping succeeds, where Linux gives
    `EINVAL` as the file has no `fsync`.
  - The interval timers of CPU time, `ITIMER_VIRTUAL` and `ITIMER_PROF`, and
    `RLIMIT_CPU` all count the process's whole CPU time, as all of it is user time here
    (Linux's `ITIMER_VIRTUAL` leaves out the system time; its `RLIMIT_CPU`
    counts it). Where the host
    cannot measure a thread's CPU time, as in WebAssembly, that is wall time,
    so they also count the time a thread sleeps or waits. They are looked
    at as a thread makes a system call and every 100,000 instructions it
    runs, not at each tick as on Linux, and a tick is taken as 1 ms, the
    CI runners' `CONFIG_HZ`. POSIX timers on the CPU-time clocks count
    and are looked at the same way, and so does a sleep on the process's
    CPU clock, which the sleeping thread looks at every tick; where that is
    wall time, the sleep counts its own time too, so a process alone ends
    it after the wall time it asked for.
    `timer_create` on another process's or thread's CPU clock (a negative
    clock ID) gives `EINVAL`, where Linux makes the timer, `clock_gettime`
    gives `EINVAL` for those clocks, where Linux reads them, and so does
    `clock_nanosleep`, where Linux sleeps on them.
  - `ustat` finds only the mounts' devices. The `st_dev` of a pipe, a
    socket, a memfd or a namespace file gives `EINVAL`, where Linux finds
    the superblock of its pseudo filesystem and gives its counts (0). A
    file in `/proc` or `/dev` has the `st_dev` of the mount holding the
    path, so `ustat` of it gives that mount's counts, where Linux gives
    procfs's or devtmpfs's.
  - A file handle (`name_to_handle_at`, an inotify watch's in
    `/proc/self/fdinfo`) has the generation 0 (1 for a memfd), where tmpfs
    picks a random one for each inode. A file of a host's directory is taken as one of a
    file system without NFS export (`EOPNOTSUPP`, or the `FILEID_INO64_GEN`
    identifier with `AT_HANDLE_FID`), where Linux gives the handle of that
    file system (ext4's, say). `open_by_handle_at` decodes only pidfs's
    handles and, with `CAP_DAC_READ_SEARCH`, those of the in-memory root's
    tmpfs, of a file a name still links (Linux also opens one that is
    unlinked but open); on another mount (a host's directory, a memfd's) it
    gives `ESTALE`. A caller without `CAP_DAC_READ_SEARCH` gets `EPERM`
    there even for a directory with `O_DIRECTORY`, where Linux 6.10 and
    later let one with `CAP_SYS_ADMIN` over the mount in. A namespace file
    has no nsfs handle (`EOPNOTSUPP`, where Linux 6.18 gives one of type
    `FILEID_NSFS`), so nothing decodes on nsfs (`ESTALE`). A pidfs handle
    opens a process that never had a pidfd, where Linux gives `ESTALE`, and
    a pidfd with `PIDFD_THREAD` has the inode of its whole process. A pidfd
    opened from a handle with `O_EXCL` does not keep `PIDFD_THREAD`, as on
    the CI runners' Linux 7.0, where Linux 7.2 and later keep it.
  - System V IPC has no `/proc/sysvipc`, and the limits of its shared
    memory, semaphores and message queues are Linux's defaults, which
    `/proc/sys/kernel` cannot change. A message queue's waiting senders
    all look again whenever it changes, where Linux wakes them in the order
    they began only while each one's message fits.
  - The POSIX message queues' filesystem cannot be mounted anywhere else:
    `/dev/mqueue` always shows the first IPC namespace's, and
    `/proc/self/mountinfo` does not list it. Through it, `open`, `stat`,
    `access`, `getdents`, `unlink`, `rmdir`, `statfs`, `mkdir`, `mknod`,
    `symlink`, `link`, `rename`, `chmod`, `chown`, `utimensat` and
    `truncate` work as on Linux, but only on a path that names
    `/dev/mqueue` itself: one that reaches it through a symbolic link
    elsewhere is looked up on the host. The first namespace's root has the
    host's boot time until a queue is made or unlinked there, where Linux's is
    when the kernel made it as it booted, a little later.
  - A `SIGEV_THREAD` cookie takes 960 bytes of its netlink socket's
    receive buffer, its `truesize` on the CI runner's kernel, while the
    socket's other datagrams take their length, where Linux counts their
    `truesize` too, so a socket may hold more of them before it is full.
  - A `/proc/sys/fs/mqueue` file checks who may write it when it is opened,
    where Linux checks the writer again at each write, and it reports its
    value's length as its size, where Linux reports 0.
  - A set's waiting semaphore operations are tried in one queue in the
    order they began, the waits for zero first. Linux keeps a queue for
    each semaphore beside one for operations on several, and which of two
    waits that both could go through goes first can differ where waits of
    both kinds are mixed.
  - `get_robust_list` of another process is `ESRCH`, where Linux gives it to a
    caller that may trace that process.
  - Whether a caller may attach to another process (`process_vm_readv`,
    `process_vm_writev`, `pidfd_getfd`) is decided by the IDs, dumpability,
    `CAP_SYS_PTRACE` and Landlock alone, as Linux with no Yama does: there is
    no `kernel.yama.ptrace_scope`, so a process may reach its parent, where
    Yama's default scope 1 lets only an ancestor in, and the capability
    module's check that the caller's permitted capabilities cover the
    target's is not made.
  - `mincore` counts a page of a file as in memory whenever it lies within the
    file, where Linux asks its page cache, and does not count a page that
    `MAP_POPULATE`, `MAP_LOCKED` or a memory lock brought in until it is touched.
  - Memory locks leave no state. So `RLIMIT_MEMLOCK` is not enforced on
    them (only on `SHM_LOCK`), which matters only to a guest that gave up
    `CAP_IPC_LOCK`, `MADV_DONTNEED`, `MADV_COLD` and `MADV_PAGEOUT` work on
    locked memory where Linux gives `EINVAL`, `mlock` succeeds on the pages of a
    file mapping past the end of the file where Linux gives `ENOMEM`, and
    `/proc` shows no locked memory.
  - A memory policy that `mbind` gives a shared mapping belongs to that
    mapping, where Linux keeps it with the shared memory itself, for every
    process that maps it. `/proc/<pid>/numa_maps` does not exist.
  - A System V shared memory segment's `shm_atime`, `shm_dtime` and
    `shm_lpid` change at `shmat` and `shmdt` only, where Linux also changes
    them when a `fork` copies an attachment, `munmap` or `mprotect` splits
    one, or a process exits or execs with one. `shmdt` finds the
    attachments of the segments of the thread's IPC namespace only, where
    Linux detaches one made before `setns` or `unshare` moved the thread to
    another. An `mprotect` that gives part
    of an attachment back the protection of the piece next to it makes a
    piece of its own, which counts as an attachment, where recent Linux
    moves the boundary between the two.
- **Extended attributes**: a mounted host directory behaves as a file system
  without them, so reading finds none (`ENODATA`) and writing gives `EOPNOTSUPP`.
  In memory, a file's `system.*` attributes do not exist (`EOPNOTSUPP`), a value
  of `security.capability` is not checked, and a sticky directory does not limit
  `user.*` to its owner.
- **Rename flags**: on a Windows host, `renameat2` in a mounted directory
  takes neither `RENAME_NOREPLACE` nor `RENAME_EXCHANGE` (`EINVAL`), as a
  Linux filesystem without them.
- **File owners**: in a mounted host directory, the owner and group that
  `chown` gives a file, and those of a file a guest makes there, are kept
  only while the emulator runs, not on the host file. The next run sees
  every file there as root's again.
- **Landlock**: ABI version 8 is the newest there; the logging flags are
  taken, but nothing is logged. With `LANDLOCK_RESTRICT_SELF_TSYNC` the other
  threads take the new domain for their own checks when they next enter the
  kernel, where Linux waits until they all have. Signals to them meet it at
  once, and `/proc` shows it after each one's next system call. `SIGIO` and
  `SIGURG` from `F_SETOWN` are not scoped, as `F_SETOWN` records no sender. A
  rename's Landlock check comes after its permission checks, where Linux's
  comes before them, which shows only when both refuse. A rule on a file under
  `/proc` does not count for `execve`. An open checks the file its path
  reaches before it opens it (and the file it made after), so another thread
  renaming the name in between can make the two differ. There is no `mount`,
  `umount2` or `pivot_root` (`ENOSYS`), which Linux refuses a thread in a
  domain (`EPERM`).
- **seccomp**: a call that `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` keeps
  waiting for its listener looks for a fatal signal every 10 ms rather than
  waking for it. Nothing is logged (`SECCOMP_FILTER_FLAG_LOG`,
  `SECCOMP_RET_LOG`). Strict mode does not make `rdtsc` fault, as Linux's
  `TIF_NOTSC` does. After `SECCOMP_FILTER_FLAG_TSYNC`, `/proc` shows another
  thread's new filter only after its next system call.
- **Credentials**: the IDs and capabilities a thread takes are checked on
  files, signals, resource limits, priorities, socket credentials and core
  files but nowhere else yet. `F_SETOWN` records no sender's credentials, so
  `SIGIO` and `SIGURG` reach their owner whoever set it, where Linux's
  `sigio_perm` checks.
  The `PR_SET_PDEATHSIG` signal is sent when the parent process ends, with the
  IDs of its leader, where Linux sends it when the thread that made the child
  ends, with that thread's. Of the files, those under `/proc` and `/dev` are
  not checked, and `fs.protected_hardlinks`,
  `fs.protected_symlinks`, `fs.protected_fifos` and `fs.protected_regular`
  act as 0, the kernel's defaults, which many distributions raise. `execve`
  reads no file capabilities (`security.capability`), no mount is
  `nosuid`, and a set-user-ID or set-group-ID program takes its owner or
  group even when another process shares the caller's working directory
  (`CLONE_FS`), where Linux takes the real IDs as effective unless the
  caller has `CAP_SETUID`. `/proc/self/status` shows the calling thread's
  credentials, where Linux shows the thread group leader's. Every thread's
  bounding set holds every capability and its ambient set none, as there is
  no `PR_CAPBSET_DROP` or `PR_CAP_AMBIENT`.
- **Socket messages**: `sendmsg` and `recvmsg` pass descriptors with
  `SCM_RIGHTS` and credentials with `SCM_CREDENTIALS` as Linux does, with
  these differences:
  - The sockets only unread messages hold are closed at once when another
    socket goes, where Linux's garbage collector closes them a little
    later, from a work queue.
- **Socket options**: `setsockopt` refuses, with `ENOPROTOOPT`, the options
  whose effect is not modelled, where Linux takes them: filters and the
  other options Linux has. No security module is modelled, so `SO_PASSSEC`
  brings no `SCM_SECURITY` and `SO_PEERSEC` is `ENOPROTOOPT`, as on a Linux
  without one; with SELinux, Linux gives the sender's or peer's context, and
  with AppArmor `SO_PEERSEC` gives the peer's label. `SO_RCVTIMEO` and
  `SO_SNDTIMEO` round to a 1000 Hz tick, where Linux rounds to its own
  `CONFIG_HZ`.
  Capabilities are not checked here, so the options that need
  `CAP_NET_ADMIN` (`SO_DEBUG`, `SO_SNDBUFFORCE`, …) are set as for root.
- **Signal-driven I/O**: the host's standard input, looked at every 10 ms,
  sends `SIGIO` once each time input comes where there was none, where
  Linux's pipe or terminal sends one for every piece of input. Standard
  output and standard error, looked at the same way, send it once each
  time they have room again after being full, where Linux's pipe signals
  its writer at every read of its reader. A stream full or empty for less
  than those 10 ms can go unseen and send none, unless a read or write told
  the guest `EAGAIN`, which always gets its signal. In WebAssembly, which has
  no thread to look, they send none.
- **Edge-triggered `epoll` on a signalfd**: a signal queued for another
  thread of the process gives the waiting thread its edge once that thread
  takes it in, at its next system call or within 10 ms of a wait, where
  Linux's `signalfd_notify` wakes the file as the signal is sent; an
  `epoll_wait` that does not wait can come before it.
- **inotify, in part**: `IN_UNMOUNT` is never sent, as nothing is ever
  unmounted (there is no `umount2`). `/proc/self/fdinfo` lists an epoll's files by
  descriptor where Linux's order follows the files' addresses, and numbers
  eventfds within the emulator, where Linux's `eventfd-id` counts the whole
  system's. Changes the host makes to a mounted directory are not seen, and
  a descriptor's place does not follow them.
- **Namespaces**: a user namespace has no `projid_map` and no
  `user.max_*` limits; its map files check a write with the credentials
  the file was opened with, where Linux also takes the writer's for the
  `CAP_SETUID` and `CAP_SETGID` it needs in the parent; and the `/proc` files
  of a process that is not dumpable belong to root of the first namespace,
  where Linux gives them to root of the process's own when it maps one.
  There are no file capabilities, in a user namespace either. A network
  namespace has no interface but its loopback (no `veth` pairs to reach
  another), and the interface requests and netlink change no other flag
  than `IFF_UP`. The first namespace shows `lo` alone too, where Linux
  shows the host's interfaces. Netlink has only `NETLINK_ROUTE`,
  `NETLINK_SOCK_DIAG` and `NETLINK_GENERIC` (`EPROTONOSUPPORT` for the
  rest). Socket diagnostics tell only of AF_UNIX, TCP and UDP sockets:
  AF_NETLINK and AF_PACKET have no handler (`ENOENT`), nor have raw
  sockets, SCTP and MPTCP, whose handlers Linux loads as modules, and
  `SOCK_DESTROY` is `EOPNOTSUPP`. A dump lists the sockets oldest first,
  where Linux's order follows its hash tables, and what an AF_UNIX socket
  sent that waits is counted as its send buffer is charged here, where
  Linux counts its buffers' true sizes. Of a TCP socket they tell its
  memory but for its buffers as 0; its keepalive timer ends a whole
  `TCP_KEEPIDLE` from now, and only a handshake on the loopback has its
  retransmission's time and count. A connection the host made has no
  `TIME_WAIT` after it, and a closed socket whose bytes still wait to go
  shows as a hold in `FIN_WAIT1`, where Linux keeps the socket itself.
  Every socket's cgroup is the root, 1, and its traffic class 0. A request
  that names a BPF map (`INET_DIAG_REQ_SK_BPF_STORAGES`) is `EINVAL`, as
  no descriptor here is one, where Linux's is `EBADF` for one that is not
  open. Generic netlink has no family but `nlctrl`, where Linux has those
  of the host's kernel and modules (`ethtool`, `nl80211`, `devlink` and
  others), so a lookup of one is `ENOENT` and a socket has 64 groups
  however many those take. Of `NETLINK_ROUTE` there
  are only the link, address and route requests: neighbours, rules, queueing
  disciplines and the rest are `EOPNOTSUPP`, as are an input route
  lookup (`RTA_IIF`, as `ip route get ... iif` sends), renaming `lo`
  and setting any other attribute of it. A
  route goes through `lo` or rejects: IPv6 gateways, multipath routes,
  metrics (`RTA_METRICS`, as `ip route add ... mtu` sends), encapsulations,
  nexthop objects, realms, expiries, source prefixes, router preferences
  and the anycast, multicast and NAT kinds (and broadcast for IPv6) are
  `EOPNOTSUPP`, and so are policy rules (`RTM_NEWRULE`), so no lookup
  reaches a table but the local, main and default ones. In a new network
  namespace a connection or datagram to an address no local route has is
  still `ENETUNREACH`, whatever route takes it, where Linux's goes out
  through `lo` and is dropped, or fails with a rejecting route's error.
  An address is always permanent: lifetimes (`IFA_CACHEINFO`) and
  `IFA_RT_PRIORITY` are not kept, a peer address is
  not a point-to-point one, and an IPv6 address is never tentative, where
  Linux's is until its duplicate address detection work, which ends at
  once on a loopback, has run. A connection or datagram to an address of
  `lo` while it is down is `ENETUNREACH`, where Linux's goes out and is
  dropped, and so is one to an IPv6 address in a prefix that is not one
  of `lo`'s, which Linux's prefix route sends to it and drops; an IPv6
  lookup while `lo` is down is `ENETUNREACH` too. A route lookup looks at
  no selector but its destination (`RTA_SRC`, `RTA_OIF`, `RTA_MARK` and
  the rest are not); its `rta_cacheinfo` counts one reference, where
  Linux counts the other users of the cached route too.
  Notifications go out for the link, its IPv6 information, addresses and
  routes alone, not for neighbours, netconf or the other groups, nor to a
  socket in another namespace (`NETLINK_LISTEN_ALL_NSID` is not
  supported); IPv4's routes through `lo` go without one when it goes down,
  as on Linux.
  `NETLINK_PKTINFO`, `NETLINK_NO_ENOBUFS` and the other options not
  listed in the features are `ENOPROTOOPT`. MCTP is as Ubuntu's kernel,
  built with `CONFIG_MCTP`, has it: a link's `IFLA_AF_SPEC` carries
  MCTP's settings and `AF_MCTP` address and route dumps have their own
  answers, where a kernel without it gives no MCTP settings, dumps
  IPv4's and IPv6's addresses and routes for those dumps, and takes no
  MCTP address or route; MCTP's addresses and routes carry nothing, as
  there are no `AF_MCTP` sockets (`EAFNOSUPPORT`). A link message's
  statistics are zero; its IPv4 and IPv6 settings are those of a kernel
  whose sysctls are as built, where Linux's new namespace copies the
  host's, and IPv6's creation time is 0 and its reachable time 30
  seconds, where Linux's is random. An address's creation times are 0.
  `NETLINK_EXT_ACK` adds no attributes to an error or to a dump's
  `NLMSG_DONE`. A link dump's `IFLA_LINKINFO` is taken without effect,
  where Linux shows only the devices of a kind its modules know. The
  least `IFLA_GSO_MAX_SIZE` and `IFLA_GSO_IPV4_MAX_SIZE` the link policy
  takes is 321, as for Ubuntu's kernel (`MAX_TCP_HEADER` + 1), where
  another build's may differ. A message type past the last
  that `rtnetlink` knows is answered with `EOPNOTSUPP` in `NLMSG_ERROR`,
  where Linux 7.0 refuses the send itself with `EOPNOTSUPP`. A socket
  whose receive buffer is full drops an answer with `ENOBUFS` without
  waiting. A `write` to a netlink socket acts with the capability of the
  thread that opened it alone. The other namespaces keep nothing apart
  that paludarium has, but for the System V shared memory, semaphores and
  message queues and the POSIX message queues of an IPC namespace: there is
  no `mount` for a mount namespace (whose mounts keep their IDs
  in `/proc/self/mountinfo`, where Linux gives a new namespace's copies new
  ones), no `/proc/self/cgroup` for a cgroup namespace, and no
  `/proc/<pid>/timens_offsets` for a time namespace, whose clocks are the
  first one's. A PID namespace hands out its numbers once each, where
  Linux's wrap at `pid_max` and are used again; for the same reason
  `clone3`'s `set_tid` cannot take an ID of the first namespace that a task
  had before, even once it is freed (`EEXIST`), where Linux takes it again,
  and its numbers are below 4194304, Linux's highest `pid_max`, whatever the
  host's is; and a queued signal (`rt_sigqueueinfo`) from
  outside the receiver's namespace has its `si_pid` cleared whatever its
  `si_code`. A namespace file has none of the `NS_GET_*` `ioctl` requests,
  and the numbers of new namespaces are not Linux's, which reuses freed
  ones.
- **Files of a mounted host directory on hosts other than Linux and macOS**:
  `lseek` with `SEEK_DATA` or `SEEK_HOLE` treats the whole file as data,
  where Linux finds the holes. On Windows `st_blocks` is also the size
  rounded up to 512-byte blocks, where Linux counts what the host's
  filesystem allocated; other Unix hosts give their own. On Linux and macOS
  hosts both come from the host. `FIOQSIZE` gives `st_blocks` in bytes on
  every host, where Linux gives what the filesystem has allocated so far,
  which some (ext4 with delayed allocation, overlayfs) count later than
  `st_blocks`.
- **Block size**: `st_blksize`, `stx_blksize` and `FIGETBSZ` are 1024 for
  `/proc` and terminals, pseudo-terminals' slaves included, as on Linux
  ([System calls](./features#system-calls)), and 4096 for every other
  file, where Linux gives a mounted directory its host filesystem's (4096
  for most), whose `statfs` here does report the host's. A host terminal
  is taken for a pseudo-terminal (devpts), where a Linux console
  (`/dev/tty1`, devtmpfs) gives 4096. `FIGETBSZ` on a filesystem without a
  block size, such as overlayfs in most containers, is `EINVAL` on Linux.
- **Standard input on Windows**: `poll`, `select` and `epoll` see the host's
  standard input as always readable, as the Windows host cannot tell whether
  input is waiting, and a read of it waits on the host: with `O_NONBLOCK`
  it waits for input rather than being `EAGAIN`, and a signal does not end
  the wait (no `EINTR`); on Linux and macOS hosts and in WebAssembly it is
  readable only with input or at its end.
- **Nonblocking standard output**: with `O_NONBLOCK`, a write to standard
  output or standard error is `EAGAIN` only when the host has no room at
  all; with some room it goes whole, waiting on the host for the rest, where
  Linux writes what fits and returns that count. Only the host descriptor's
  own `O_NONBLOCK` could stop it short, and the host's other processes
  share that flag. A Windows host cannot tell, so there it is never
  `EAGAIN`.
- **Pseudo-terminals, in part** ([features](./features#system-calls)):
  One side's write reaches the other's line discipline at once, where Linux
  passes it on from a work queue, so a reader here never finds only part of
  a write, and `O_ASYNC` signals once for each write (or echo) where Linux
  signals once for each piece its work queue passes on, which a queued
  `F_SETSIG` signal counts; each side holds up to Linux's default flip
  buffer of 640 KiB, without Linux's memory accounting behind it. There is
  no `/dev/console`, so a `TIOCCONS` redirect is never written to, and
  `vhangup` does nothing when the controlling terminal is the host's, which
  Linux would hang up. The host's own terminal is not one of
  these: the guest's standard streams on it answer only `TCGETS` and
  `TIOCGWINSZ`.
- **`FIONREAD` and `SIOCOUTQ` on the host's standard streams**: both return
  `ENOTTY`, where Linux answers for what is behind them: `FIONREAD` for a
  pipe, terminal, socket or regular file, `SIOCOUTQ` for a terminal or
  socket. A guest's own pipes, sockets and regular files are counted as on
  Linux.
- **Core files**: a core is written as with the kernel's default
  `core_pattern` (`core` in the working directory); a host that pipes cores to
  a crash handler (systemd-coredump, apport) is not modelled. Its `NT_FILE`
  note names a mapped file by the path it had when it was mapped, and the
  program by the path it was started by, where Linux follows a rename and
  resolves symbolic links.
- **Memory limit**: a write beyond the limit ends the process that made it,
  where Linux's OOM killer picks the process using the most memory.
- **The native JIT**: it is experimental and off unless `--jit` asks for it,
  and only Linux on x86-64 hosts has it; the other native builds use the
  interpreter. It compiles only the instructions with a simple form at the
  start of a block ([Architecture](../design/architecture#the-native-jit)).
- **Stable Rust**: a nightly Rust is required.

## Not verified

- What is verified are the programs listed under
  [Supported features](./features) and the per-instruction tests. Other
  programs are not yet guaranteed to behave exactly the same.
- Fuzzing shows that no problem was found in a fixed time. It is not a proof
  that every input is safe.
- Differential references were taken on some recorded AMD and Intel CPUs. On a
  CPU profile not observed yet, the tests stop on purpose.
- Memory, tasks (threads and processes) and open files are unlimited unless
  the embedder sets limits, so without them an untrusted program could use up
  the host's memory. The memory limit counts the guest's pages, not file
  contents, pipe and socket buffers or the emulator's own memory
  ([command line](./cli), [Rust](./rust),
  [JavaScript](./javascript#run-options)).
- Automated Safari tests sometimes timed out while waiting for the browser to
  start. A fix passed ten times in a row, which does not guarantee it never
  happens again.

## Found a problem?

When a CPU fault kills the guest, the command prints the signal, the address
and the instruction bytes. Run it again with `--report-enosys` to list the
system calls that returned `ENOSYS` ([Command line](./cli#finding-what-is-missing)).
Please include both in an
[issue](https://github.com/aletheia-works/paludarium/issues).
