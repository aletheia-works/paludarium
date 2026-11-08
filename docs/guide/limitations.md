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
  (`/proc/cpuinfo`, `/proc/sys`, ...) and the other names in
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
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature.
  - `rseq` is one of them, as on a Linux built without `CONFIG_RSEQ`, and glibc
    carries on without it. Its promise is that a thread's critical section is
    abandoned if it is preempted, which emulated threads running truly in
    parallel cannot keep, so registering would let per-CPU data break.
  - `pkey_alloc` and `io_uring_setup` are too, as on a Linux built without
    them. Programs check for that and carry on. Saying yes would be wrong
    without the rest: protection keys need the CPU feature, which `CPUID` does
    not report, and io_uring's rings would do no work.
  - `get_robust_list` of another process is `ESRCH`, where Linux gives it to a
    caller that may trace that process.
  - `mincore` counts a page of a file as in memory whenever it lies within the
    file, where Linux asks its page cache, and does not count a page that
    `MAP_POPULATE`, `MAP_LOCKED` or a memory lock brought in until it is touched.
  - Memory locks leave no state. So `RLIMIT_MEMLOCK` is not enforced, which
    matters only to a guest that gave up `CAP_IPC_LOCK`, `MADV_DONTNEED` works on
    locked memory where Linux gives `EINVAL`, `mlock` succeeds on the pages of a
    file mapping past the end of the file where Linux gives `ENOMEM`, and
    `/proc` shows no locked memory.
  - A memory policy that `mbind` gives a shared mapping belongs to that
    mapping, where Linux keeps it with the shared memory itself, for every
    process that maps it. `/proc/<pid>/numa_maps` does not exist.
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
- **Landlock**: only ABI version 3 is there, so `LANDLOCK_CREATE_RULESET_VERSION`
  gives 3 where a recent Linux gives more: no network rules
  (`LANDLOCK_RULE_NET_PORT`), no `LANDLOCK_ACCESS_FS_IOCTL_DEV`, no scopes, no
  `landlock_restrict_self` flags and no errata query (`EINVAL`), and nothing
  is logged. A rename's Landlock check comes after its permission checks,
  where Linux's comes before them, which shows only when both refuse. A rule
  on a file under `/proc` does not count for `execve`. An open checks the
  file its path reaches before it opens it (and the file it made after), so
  another thread renaming the name in between can make the two differ. There
  is no `mount`, `umount2` or `pivot_root` (`ENOSYS`), which Linux refuses a
  thread in a domain (`EPERM`).
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
- **Namespaces**: `clone` and `clone3` with a namespace flag
  (`CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`,
  `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWCGROUP`, or `CLONE_NEWTIME` for
  `clone3`) fail with `EINVAL` and create no child, where Linux lets the
  guest, which runs as root, create the namespace. `unshare` with a
  namespace flag fails too, with `EINVAL` (`EPERM` for a thread without
  `CAP_SYS_ADMIN`, as on Linux), and so does `CLONE_NEWUSER`, which Linux
  also lets a user have. `setns` returns `ENOSYS`.
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
- **A native JIT**: only the WebAssembly build has a JIT; native builds use the
  interpreter.
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
