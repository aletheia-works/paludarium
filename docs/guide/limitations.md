# Limitations

paludarium is a young project. These things are not possible yet, or not
verified.

## Not supported

- **Part of x87, for now**: `FISTTP` belongs to SSE3, which `CPUID` does not
  report, and is not implemented. Where the last instruction and its memory
  operand were, which `FNSTENV`, `FNSAVE` and `FXSAVE` write, is not kept:
  those fields are zero, and Intel's and AMD's CPUs fill them in differently.
  Where `FPREM` and `FPREM1` stop on the way when their operands are far apart
  is each CPU's choice: the final remainder is the same.
- **A dynamically linked program's files, unless given**: a program runs with
  its interpreter as on Linux, on musl's dynamic linker or glibc's. A session
  reads the interpreter and the libraries from its own files, so they must be
  mounted or given to it.
- **32-bit x86, AVX, AVX-512, MMX**: out of scope. `CPUID` reports MMX because
  glibc requires it, but its instructions stop with `SIGILL`, as do the SSE and
  SSE2 ones that use MMX registers (`CVTPI2PS`, `MOVQ2DQ`, `PSHUFW` and the like).
- **The last bit of x87's transcendental instructions**: `FSIN`, `FCOS`,
  `FSINCOS`, `FPTAN`, `FPATAN`, `F2XM1`, `FYL2X` and `FYL2XP1` give the correctly
  rounded result of what Intel's and AMD's CPUs compute (the four that take an
  angle take multiples of π/2 away as π/2 cut to 66 bits, as both do). A real
  CPU's result is within one unit in the last place of that, and differs from
  it in a few values in a hundred, Intel's more often than AMD's, which differ
  from each other too; C1 then goes by the CPU's own result. Where the result of
  a tiny value is that value, Intel's CPUs give it as it is in every rounding
  mode, and the emulator and AMD's round it. `FSINCOS` sets C1 by the sine, as
  AMD's CPUs do (Intel's go by the cosine). So the `long double` functions of
  glibc and musl that use these (`expl`, `logl`, `atan2l` and the like) can
  differ from a real CPU's in their last bit or two. Where the manuals leave the
  result undefined, the emulator does as both CPUs: `F2XM1` leaves a value
  beyond ±1 as it is, and `FYL2XP1` a value where 1 + x is not positive. The
  tests compare every bit where the CPUs agree, and that bound elsewhere.
- **The exact results of `RCPPS`, `RCPSS`, `RSQRTPS` and `RSQRTSS`**: x86 only
  bounds their error (1.5 × 2⁻¹²), and each CPU answers from its own table. The
  emulator computes them by floating-point division (after a square root for
  `RSQRT`), so the low bits can differ from a real CPU's. The tests check that
  bound and the special values, not the bits.
- **`MASKMOVDQU` with an empty mask on memory it cannot reach**: the emulator
  makes no access, and a real CPU may fault (an AMD EPYC does, and exits with
  `SIGSEGV`). A fault on a later byte also leaves the earlier ones written, which
  has not been compared with a real CPU.
- **`/proc/self/maps`, in part**: the stack's VMA has its full size from the
  start, where Linux's grows as it is used.
  A rename does not move the names of files that were opened in another
  mount namespace, or by a process that entered this one apart (`unshare`
  and `setns` each begin anew), in the maps, a core's `NT_FILE` note and
  `/proc/<pid>/exe`, where Linux's `d_move` moves them in each.
- **The vDSO, in part**: its functions make their system calls, as Linux's
  vDSO does only when no clock can be read from user space, so a seccomp
  filter, a ptrace tracer's syscall stops and syscall counts see a call
  where Linux's fast path makes none. `[vvar]` holds zeros, where Linux's
  holds the time, which nothing here reads. `__vdso_getrandom` and
  `__vdso_sgx_enter_enclave` (and their weak aliases) are not there: the
  first's contract, the opaque state a C library asks it for, is not a
  system call's, and SGX is not emulated; a C library falls back to
  `getrandom(2)`. `smaps` counts a touched page of `[vdso]` as the process's
  own (`Private_Clean`), where Linux's is shared by every process
  (`Shared_Clean`, `Pss` 0). `[vvar]` is the test machines' Linux 7.0's:
  since 7.2 it is `VM_MIXEDMAP` instead of `VM_IO | VM_PFNMAP` (c27e727c9a60),
  so `mlock` fills it and `get_user_pages` may reach it, and its pages 1 and 3
  hold zeros (43648f9f3a67) instead of being a bus error.
- **`/proc/self/smaps` and `smaps_rollup`, in part**: what they count comes from the emulator's
  page entries. A page of a loaded program's segment counts as
  anonymous once the segment was written, not once the page was. A read fault in a file's mapping
  maps no more than the 16 pages around it
  ([features](./features#system-calls)), where Linux maps a large folio
  of its page cache whole when the folio lies within the file, the VMA
  and the page table (`filemap_map_folio_range`): the emulator's page
  cache has no large folios, whose size each file system picks. `pagemap`
  shows the same pages.
  `THPeligible` is always 0 and there is no `ProtectionKey`, as there are
  no huge pages and the CPU has no protection keys. A page of a host file
  that `write` filled is clean (see "Pages `write` filled" below).
- **Huge pages**: the pool of hugetlbfs is empty and cannot be filled. There
  is no `/proc/sys/vm/nr_hugepages` (so no write to it), no
  `/sys/kernel/mm/hugepages`, and `hugetlbfs` cannot be mounted (`ENODEV`),
  though `sysfs` lists it. `MAP_HUGETLB` and `SHM_HUGETLB` of 1 GiB pages
  are `EINVAL`, and `MFD_HUGETLB` of them `ENODEV`, as on a CPU without
  them; the differential tests do not compare them. `userfaultfd` does not
  register such a mapping, and the device in `maps` of an anonymous one is
  0, and of a segment's 00:01.
- **`/proc/<pid>/mem`'s offsets past `i64::MAX`**: `pread64` and
  `pwrite64` refuse them (`EINVAL`), as Linux v7.0's `ksys_pread64` and
  `ksys_pwrite64` do for every file, where Linux master takes them for a
  file of unsigned offsets (`FOP_UNSIGNED_OFFSET`). This follows v7.0
  until the runners' kernel has master's change.
- **`statx`'s `STATX_ATTR_VERITY` in `stx_attributes_mask`**: Linux
  master's `vfs_getattr_nosec` says every file knows it (since its
  f9e450420da2), where Linux 7.0's says it only for a file system with
  fs-verity. No file here has fs-verity, and the mask follows v7.0, which
  the differential tests compare, until the runners' kernel has master's
  change.
- **`/proc/<pid>/pagemap`, in part**: its entries come from the
  emulator's page entries, as `smaps`'s counts do. A page of a loaded
  program's segment, which has no page cache, is a file's (bit 61) until
  the mapping was written, not until the page was. The frame number is 0 for every reader, also one
  with `CAP_SYS_ADMIN`, to whom Linux shows the physical frame; and
  user space ends at 2^47 bytes, as with 4-level page tables.
- **`PAGEMAP_SCAN`, in part**:
  - It follows Linux master where the CI runners' Linux 7.0 differs:
    - A page is written (`PAGE_IS_WRITTEN`) only in a VMA registered for
      write protection, where an empty page is written too. Linux 7.0
      calls every present page and marker that is not write-protected
      written, and no empty one.
    - `PAGE_IS_ACCESSED` is taken. No page has it, as there is no read
      protection.
    - An unknown ioctl is `ENOTTY`, where Linux 7.0 gives `EINVAL`.
    - A scan once the address space is gone is `ESRCH`, where Linux 7.0
      finds no pages.
  - No page is `PAGE_IS_HUGE`, as there are no huge pages.
  - Protecting a guard or poison marker's page leaves it written. Linux
    sets the marker's uffd-wp bit.
  - A 2 MiB block has a page table while one of its pages has an entry or
    a marker. Linux keeps page tables otherwise. This matters only for
    `PM_SCAN_WP_MATCHING` without a buffer, which protects every page
    where there is a page table.
  - User space ends at 2^47 bytes for its checks, as with 4-level page
    tables.
- **`Referenced` of `smaps`, in part**: a page counts when it was accessed
  through its own page table entry since `clear_refs` 1 to 3 cleared it.
  Linux also counts one whose folio is marked as referenced, as a `read` of
  its file or another process's access may have it. The kernel never ages
  a page here, as it may on Linux, and `MADV_COLD` and `MADV_FREE` leave
  the bit, which they clear on Linux. Linux flushes no TLB for 1 to 3, so
  there an access to a page that the CPU's TLB still holds may leave it
  unreferenced; here the next access always marks it.
- **4-level paging only**: the emulated machine always has 4-level page
  tables, whatever CPU the host has: user space ends below 2^47 bytes, and
  `TASK_SIZE_MAX` is 2^47 - 4096 for every check that asks for it, as the
  `fs` and `gs` bases `ptrace`'s `PTRACE_POKEUSER`, `PTRACE_SETREGS` and
  `PTRACE_ARCH_PRCTL` take (`EIO`, `EPERM`) and the range of a hardware
  breakpoint in a debug register (`EINVAL`). Linux on a CPU with 5-level paging (LA57) maps
  above 2^47 only for a process that asks with an `mmap` hint there, but
  its `TASK_SIZE_MAX` is 2^56 - 4096, so these checks take a value between
  the two that paludarium refuses ([decisions](../design/decisions)).
- **Device counters, in part**: `/proc/net/dev` and a link's
  `IFLA_STATS64` and `IFLA_STATS` count UDP datagrams, ICMP's port
  unreachable, ARP and TCP's segments alone (see [features](./features)).
  ICMP's port unreachable is sent, and counted, for each datagram to a
  closed port, where Linux limits how many go (`icmp_ratelimit`,
  `icmp_msgs_per_sec`, and per peer through a veth pair).
  A SYN that a listener's full queue drops, or that nothing answers, is
  not counted, nor are its retries; a connection's own retransmissions,
  the SYN-ACK's sent again among them, are, as is its handshake once
  the listener has answered, whether or not the request is dropped
  later. Nor are the packets of IPv6 that the kernel sends of
  itself (neighbour discovery, MLD reports, router solicitations and
  duplicate address detection), nor ARP's probes of a neighbour whose
  entry ages, nor what goes to the host (a TCP connection to a port no
  guest socket holds, the DNS stub's answers) or through the loopback to
  a broadcast or group address, nor an MCTP send out through the
  loopback. No error, drop or multicast is counted: a packet that Linux
  drops as it leaves a veth end whose peer is down (`tx_dropped`) is
  not sent here at all.
- **`/proc/net`, in part**: it has `anycast6`, `arp`, `dev`, `dev_mcast`,
  `if_inet6`, `igmp`, `igmp6`, `ipv6_route`, `mcfilter`, `mcfilter6`, `route`
  and those of the sockets (see [features](./features)) alone; `snmp`,
  `sockstat` and the rest are `ENOENT`. `SIOCADDMULTI` and `SIOCDELMULTI` are not supported, so
  `dev_mcast` has only the addresses the devices' groups map to, none of
  them global; nor is the `RTM_GETMULTICAST` dump of those addresses
  (`AF_PACKET`) that Linux master has. A session with no network has files of no device and no
  Internet socket. Of a socket, its address in the kernel is 0, its
  references are the same for each of a kind, the memory its unsent
  datagrams and messages take is 0, and so is a TCP connection's `quick` with
  `pingpong`; no timer shows while it waits for an acknowledgement. `netlink` leaves out
  the kernel's own sockets, whose port is 0.
- **`/proc/cpuinfo` of the virtual CPU**: `bogomips` is 0.00 and there is no
  `cpu MHz`, as `CPUID` reports no time stamp counter though `RDTSC` works;
  `initial apicid` is 0 on every CPU, as `CPUID`'s leaf 1 gives no CPU its
  own ID; and `bugs` lists what Linux 7.0 assumes of an AMD CPU of family
  15, though the virtual CPU does not speculate.
- **The rest of `/proc`, in part**: only the process directories and a few
  system files are made (see [features](./features)). The other system files
  (`/proc/interrupts`, `/proc/partitions`, `/proc/kallsyms`, the files of `/proc/sys` but for the ones of `fs`,
  `kernel` and `net` it has and `vm/drop_caches`, `vm/max_map_count` and
  `vm/unprivileged_userfaultfd`, ...) and the other names in
  the reader's own directory (`stack`, `sched`, `attr`, ...) are `ENOENT`, as in
  another process's directory, whatever the filesystem holds there (with
  `--mount /:/`, the host's `/proc`), where Linux shows them, and root
  `stack` and the rest of another's. With a security module Linux has `attr`,
  whose `current` reads `unconfined` under AppArmor; there is none here. `wchan` is `0` for a waiting task too, where Linux names the
  kernel function it waits in for a reader that may read the task: there are
  no kernel functions here to name. A poll of an epoll that watches several
  of `hostname` and `domainname` polls them by descriptor number until one is
  ready, where Linux does in the order they changed, so that of several that
  changed another may be the one it has seen.
  `vm/max_map_count` is of mode 0444 and bounds nothing, where Linux's is
  root's to write (0644) and makes a mapping past it `ENOMEM`. There are no
  `fs/pipe-user-pages-soft` and `fs/pipe-user-pages-hard`, and nothing counts
  a user's pipe pages, so a pipe of a user past Linux's soft limit is not
  made smaller nor refused growth (`EPERM`).
  `io` does not count what Linux's
  `kernel_read` and `kernel_write` count for the process (`execve` reading its
  program and interpreter, a core dump's writes), and a read or write that
  fails with an errno Linux gives both before and in the file's operation
  (`EINVAL`, `EFAULT`: an eventfd's too small a buffer) is taken as refused
  before it, so not counted.
  `/proc/stat` counts all CPU time as user time, as `getrusage` does, each
  thread's to the CPU it was on at its system calls or that another thread's
  `sched_setaffinity` moved it to since, and none as idle; it
  counts no interrupts or softirqs, and as context switches only the times
  threads went to sleep, as nothing preempts a guest thread, so `status` shows
  those as `voluntary_ctxt_switches` and 0 as `nonvoluntary_ctxt_switches`,
  and `getrusage` and a wait's rusage as `ru_nvcsw` and 0 as `ru_nivcsw`.
  `status` has no `VmPin` or `VmPTE`, as nothing counts the pages pinned
  (`pinned_vm`) or the bytes of the page tables.
  Another process's thread is `S (sleeping)` in every wait, where Linux shows
  some waits it cannot interrupt as `D (disk sleep)`. A thread shows another
  process what it published at its last system call or signal check, so a mask
  changed only for the length of a call (`rt_sigsuspend`, `ppoll`) is seen
  only while the thread is stopped in it. A task with no memory left (a
  zombie, or a leader that ended before its other threads) has its files but
  its directory owned by root, so a reader that is not root gets `EACCES` for
  `environ`, `auxv` and `pagemap`: this follows the kernel of the x86-64 CI
  runners that the differential tests compare with, from before Linux 7.2's
  commit 6b1c66c9 ("exec_state: relocate dumpable information"). From 7.2,
  `task_dump_owner` takes the owner from the dumpable flag in `exec_state`,
  which outlives the memory, so those files stay the task's and their open
  is `ESRCH`; paludarium follows that once the runners run 7.2 or later, and
  the `gone-leader-files` case and the unit test
  `a_task_without_memory_has_its_files_owned_by_root` change with it.
  `meminfo` shows the fixed 4 GiB that `sysinfo` reports, with nothing used.
- **Roots of their own, in part**: `chroot` into the generated `/proc` or
  `/dev` (or a directory in them) gives `EINVAL`, where Linux makes it the
  root. `mount` mounts no `proc` filesystem and nothing on `/proc` or
  `/dev`, so the new root's `/proc` or `/dev` shows the generated files
  only through a bind mount of `/proc` or `/dev` (or a directory in them)
  made onto it before. In a path that climbs above the root as written,
  `..` in the generated files such a bind mount shows is taken from the
  names as written, where Linux takes a `..` after a link in `/proc` (such
  as `/proc/self/cwd`) from its target.
  `fchroot`, new in Linux master, is not there (`ENOSYS`).
- **Names in `/dev`**: as root, a call that makes a name in `/dev`
  (`mkdir`, `mknod`, `symlink`, an `open` with `O_CREAT`) gives `ENOENT`,
  and `unlink`, `rmdir` and `rename` of a name there give `EPERM`, where
  Linux's devtmpfs makes, removes and renames them. Another user gets
  Linux's `EACCES`.
- **`O_PATH` of `/dev/tty`**: it opens the controlling terminal as any
  open does, so without one it fails (`ENOENT`), where Linux's `O_PATH`
  opens the name without the device.
- **Changing the generated files, in part**: a new mode or owner of
  `/dev`, its devices and links, `/proc` or `/proc`'s system-wide files, which only
  root may give these files of root's, is `EPERM`, where Linux keeps it;
  a pseudo-terminal's slave keeps its own. Times set on a generated file
  are not kept either: its `stat` shows the times it had. Removing or
  renaming a generated name (`unlink`, `rmdir`, `rename`) gives `ENOENT`,
  where Linux gives `EPERM`.
- **Device nodes and FIFOs on the host**: `mknod` of a character or block
  device is `EPERM`, although the guest runs as root, since paludarium has
  no device for it to stand for. A FIFO in a mounted host directory can be
  made on Linux hosts only, and connects only the guest's own openers, not
  host programs that open the same node.
- **`O_DIRECT`'s alignment**: a read or write of a file opened with
  `O_DIRECT` goes through as any other. On a disk file system such as
  ext4, Linux refuses a buffer, offset or length that is not aligned to its
  block size (`EINVAL`); the emulator does not.
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
    Broadcast datagrams reach no one but through a veth end or `lo` (below). A
    datagram is always
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
    the round trip (30 µs) and the timeout, rates and pacing it gives, and
    the windows, which never grow, so the send MSS stays 32 KiB and no
    acknowledgement goes for a grown window; the window scale its handshake
    offered stays. The segments, and so what waits in the sender and how
    long, are Linux's ([Network](./features#network)) while the
    reader keeps up with writes of at most 536 bytes; larger ones and a
    full window take more or fewer than Linux. What has reached the peer
    and waits for its acknowledgement takes no room of `SO_SNDBUF`, though
    `SIOCOUTQ` counts it. A connection across a veth pair has segments of
    its device's MTU, but the loopback's path MTU, advertised MSS and
    windows. A segment is lost only when a socket filter drops or cuts it
    ([System calls](./features#system-calls)); its recovery is Linux's with its
    default congestion control, cubic, but past the slow start threshold the
    window grows by a segment a window, where cubic's grows with the time
    since the loss, and an acknowledgement of a gap goes at once,
    where Linux puts the fourth and later ones off a little. What a
    connection ends with is kept for the next between the same addresses
    (`tcp_metrics`), but the round trip kept is the model's own, and there
    is no bound on the entries, no route metric that locks one, no netlink
    `TCP_METRICS` family, no `tcp_no_metrics_save` or
    `tcp_no_ssthresh_metrics_save`, no check that a peer is known when the
    SYN queue is nearly full (`tcp_peer_is_proven`), and no Fast Open
    cookies. The peer's
    window scale is taken as Linux's default, whatever buffer it set; and a connection the host made has
    its segments estimated, in 32 KiB segments with one acknowledgement
    for each.
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
- **Pages `write` filled**: a page of a host file that `write` (or another
  system call) filled is clean at once, as the data goes straight to the
  file on the host, so a mapping of it counts it among the clean pages in
  `smaps`. On Linux it stays dirty in the page cache until writeback, and
  `smaps` counts it among the dirty ones until then.
- **Mappings that grow down**: `RLIMIT_AS` does not stop the growth of
  such a mapping ([features](./features#system-calls)), as it does not stop
  `mmap`.
- **Page-fault counts**: `ru_minflt` counts each fault as it is taken, as
  Linux does, from a thread's first fault, before its first system call.
  `execve`'s loader fills the pages of the program's segments
  with its file's bytes and counts a fault for each page then, where Linux
  maps the file and counts the faults as the program first touches the
  pages, a read fault for several of them at once (`fault_around_bytes`);
  these faults are no `perf` event. Every page of a file is taken to be in
  the page cache, so the only major faults (`ru_majflt`, `major-faults`)
  are those of the kernel's accesses that a `userfaultfd` had try again.
  `/proc/<pid>/stat`'s `minflt`, `cminflt`, `majflt` and `cmajflt` read
  the same counts, with the same limits.
- **perf events, in part**: only the software events count; cgroup
  switches, tracepoints, breakpoints, kprobes and uprobes are `ENOENT`, as
  are hardware events even on a host with a PMU: cycles and cache misses
  mean nothing here, and the x86-64 test machines, which are virtual, have
  no PMU to compare a count of instructions with. A thread's context
  switches and CPU migrations are those it last accounted, at its latest
  system call; its CPU time is looked at as the event is read, and its page
  faults count as they are taken. An event of
  a CPU counts those of every thread there, with the same limits. A
  system call that checks its buffer before it copies (inotify's and
  fanotify's reads, `epoll_wait`, some socket calls, among others) and
  fails with `EFAULT` there counts no `page-faults`, where Linux's copy
  counts one; a copy that fails counts one, as on Linux. A
  context switch is a sleep of the thread, not a preemption (but for a
  thread with `rseq` that gives its virtual CPU to another); and a thread
  without `rseq` moves to another CPU only when a new CPU mask changes the
  lowest CPU it allows.
  A fault of a thread's own code is sampled, and signalled, at its
  instruction, as on Linux. A sampling event's other samples are taken as
  its thread enters or leaves a system call, or reaches the emulator's
  checkpoint, of what it did since then, where Linux takes each at its
  occurrence: they show the thread's instruction, registers, stack and
  frames as of then (a fault's own address is its own, but 0 for one
  before the thread's last 4096), and one of the kernel (a fault in a
  system call, a switch or a migration) has the instruction 0 and no
  kernel frames. While a `cpu-clock` or `task-clock` samples a thread, the
  thread's runs end about when the clock is to fire next, at the rate its
  last run went at, and run at least 5,000 instructions, so that its
  samples come about one at each checkpoint, with their own registers. That
  is not an interrupt: a sample comes as much later as that estimate is off,
  and two can still share a checkpoint. `freq` follows the rate at those
  points, not at each tick. A `cpu-clock` or `task-clock` event is throttled at
  `perf_event_max_sample_rate` over `HZ` (1000) interrupts in a tick, as
  Linux's hrtimer events are, the ticks being those of its own count, and
  is unthrottled at the next one, when it is enabled again or when its
  period is set: the `PERF_RECORD_UNTHROTTLE` of the latter two is written
  with its next samples, by the thread it counts. It stops its group, as
  on Linux, but for the members that count faults, switches or
  migrations, which count on, as when those came is not known here, where
  Linux stops them too; and a member of a group with two sampling clocks
  whose samples were taken before the other's throttling was can keep the
  samples it took in the time it stopped. The sample rate is not lowered
  for samples that take too long (`perf_sample_event_took`), which
  `perf_cpu_time_max_percent` sets the limit of; and no other event is
  throttled, as no other event here is an hrtimer's or the hardware's. An
  event of a CPU takes a thread's samples as that thread enters a system
  call or reaches a checkpoint too, so that what it did there after its
  last one before the event is disabled is counted but has no samples; its
  `cpu-clock` or `task-clock` samples only the time the guest's threads ran
  on the CPU, where Linux samples the idle task too. Of the side-band records, an `execve` writes the new program's mappings once it
  has loaded it, the stack's two first and the rest by address: the
  temporary stack's is placed at the top of 4-level user space with the
  length of the arguments' pages, where Linux gives where it was. Linux
  first writes a position-independent program's or interpreter's first
  segment as long as the whole image, before it trims it; a stack that
  grows down as the program touches it writes none; a mapping's inode
  generation is 0; a build ID is read from a file whose page cache the
  emulator does not keep (a host's, or one of the in-memory file system from
  start-up) as if its pages were all cached, where Linux gives none for a
  page it has not read or has evicted; a thread the host cannot
  start gets `FORK` and `EXIT` records, the latter on CPU 0, where Linux's
  failed `clone` writes neither; and `CGROUP`,
  `KSYMBOL`, `BPF_EVENT`, `TEXT_POKE`, `SWITCH` and `AUX` records are not
  written. When `REFRESH`'s last overflow disables the event, its count
  stops there, but its times (a clock's apart) and its group's other
  events go on up to that point. Its user page shows the count and
  times as of the `mmap`, the event's enabling and its reset, and of its
  thread's return from each sleep and move to another CPU, which is when
  Linux schedules the event in again here, as a thread here is switched
  out only when it sleeps. An event of a CPU's is not updated at those,
  where Linux also updates it each time it is scheduled in again.
  `cap_user_time` is never set.
  Where Linux's checks of a mapping and of where it goes both fail, the
  mapping's are the error here. The cgroup mode
  (`PERF_FLAG_PID_CGROUP`) is `EBADF`. The ioctls `SET_FILTER`,
  `SET_BPF`, `QUERY_BPF` and `MODIFY_ATTRIBUTES` are `ENOTTY`. `remove_on_exec`
  takes the event out of its group as Linux master has done since 7.2
  (037a3c43edfb), and such an event leads no new group (`ENODEV`,
  fa091f46c383); the test machines' Linux 7.0 leaves it in its group and
  takes it as a leader, so these are checked by the unit tests alone. The
  events that wait for an `execve`, and those each thread opened, are kept
  per emulated machine, matched by thread group and thread, and dropped as
  they close. An event whose task has ended also leads no new group
  (`ENODEV`), as in master, where the test machines' 7.0 takes it. A
  group's members count whenever their leader does, whatever software
  event they are. In Linux, a member of another software PMU than its
  leader's (a `cpu-clock` member of a `task-clock` group, the other way
  round, or either with `dummy`) keeps its own PMU's context
  (`find_get_pmu_context`), which is scheduled in and out apart from its
  leader's, so it runs for a part of its leader's time that changes from
  run to run, from none to nearly all, on the x86-64 test machines; the
  tests group only events of one PMU.
  The SIMD register fields of Linux master's 176-byte structure are checked
  as master checks them and not compared with Linux: the test machines'
  Linux 7.0 knows 144 bytes and gives `E2BIG` for any of them that is not
  0. `kernel.perf_event_paranoid` starts at Linux's 2 (Debian's and
  Ubuntu's kernels default to more).
- **BPF, maps and socket filters only**: `bpf` makes
  arrays, hashes, LRU hashes, longest-prefix-match tries, queues, stacks,
  bloom filters, and arrays and hashes of maps, and loads socket filters,
  and nothing else. A socket filter, attached with `SO_ATTACH_BPF` or a
  classic one with `SO_ATTACH_FILTER`, runs only on an AF_UNIX datagram
  or packet socket, on a UDP socket, and on the segments of a handshake and
  connection on the loopback or across a veth pair. A handshake whose SYN-ACK
  the client's filter drops leaves no request with the listener, whose
  SYN-ACK so comes again only with the client's SYN; a request that opens is
  taken though the queue has filled up since its SYN; what a filter asks of
  the socket (`bpf_get_socket_cookie`) is the connection's while that is a
  request, where Linux's is the listener's; and data
  that goes again after it has come, where no filter saw it before, reads
  as zeros. A connection the host made has no segments here, and its filter
  never runs. On a UDP socket no
  filter runs on the DNS stub's answers, which come through no device
  here; a datagram that Linux sends in fragments across a veth pair comes
  whole, though its filter sees the reassembled one's linear part and
  checksum; the IPv4 ID, the IPv6 flow label and `skb->hash` are random,
  as on Linux, but not drawn as Linux draws them.
  No JIT compiles a program: the interpreter runs it. Of the helpers'
  values, the processor is 0, a network namespace's cookie is 1 (the
  initial one's) in every namespace, the boot and coarse clocks are the
  monotonic one, and `CLOCK_TAI` is the real time. The verifier's
  rewrites are counted, not made: the interpreter runs the instructions as
  loaded. Linux's verifier knows of more branches that they are never
  taken than the one here does (below), and removes the code only those
  reach, which is counted here, with the registers it reads as 64 bits
  and the maps its lookups get: so a program with such code may take
  other memory in fdinfo (`memlock`) and be charged otherwise to its
  socket than on Linux.
  Every other program type is
  `EINVAL`, as on a kernel built without it. The verifier refuses, where
  Linux may take them, with a log line of its own ("paludarium: ... are
  not verified yet", `EINVAL`; a helper call's starts "unknown func %s#%d",
  so that libbpf and bpftool take the helper as missing): the helpers
  Linux gives a socket filter other than those
  [Features](./features) lists (`bpf_tail_call`, `bpf_perf_event_output`,
  `bpf_trace_printk`, the ring buffer, spin locks and the rest), the map
  helpers of maps of maps, queues, stacks and bloom filters, a helper's
  size whose value the verifier does not know, `bpf_get_netns_cookie` of
  a scalar it does not know is 0, kfuncs, the context's socket
  (`__sk_buff.sk`) and a map's own fields (`struct bpf_map`), maps from
  `fd_array` and maps made with `excl_prog_hash`, `BPF_LD_IMM64` of BTF
  IDs and of functions (and so callbacks), `may_goto`, indirect jumps, a
  pointer with a variable offset, and `BPF_F_TEST_REG_INVARIANTS` with a
  conditional jump; and with
  Linux's line, a back-edge ("back-edge from insn %d to %d", where Linux
  takes a bounded loop from a privileged loader). A recursive call is
  refused as the test machines' 7.0 refuses it, as the walk goes 9
  frames deep ("the call stack of 9 frames is too deep", `E2BIG`), not
  before the walk as master does ("recursive call from %s() to %s()",
  `EINVAL`): the differential tests compare the line with that kernel,
  and master's check comes here once it has it. A scalar is a value the
  verifier knows or nothing at all, where Linux keeps its bounds, so it
  walks both ways of a jump Linux knows goes one way, and it prunes no
  states, so a program with many branches may reach the limits sooner. A
  lookup's result may be null until a 64-bit `BPF_JEQ` or `BPF_JNE` with
  the immediate 0, or with a value's or a map's pointer it equals, tells,
  or an array's key is one the stack holds
  ([System calls](./features#system-calls)). Linux 7.0 also learns it
  from equality with the stack's or the context's pointer, and master
  from equality with a register it knows is 0; where the two decide
  differently it refuses, so neither tells here. A read of the stack is
  known where Linux knows it (zeros stored, a scalar spilled read from
  its start, an atomic's old value), but not one of zeros and a spill of
  0 together, which master knows as 0 and Linux 7.0 does not.
  Where master and the test machines' Linux 7.0 decide differently, it
  refuses: master takes a larger stack where its JIT can, makes a number
  of a pointer that any operator is applied to, and takes an exit for
  unwinding. It checks every instruction's fields (the "uses reserved
  fields" errors) before it walks any path, in master's order; Linux 7.0
  checks them only when a path reaches the instruction, so for a program
  wrong in more than one way it may give another error first. It has
  only a privileged loader's rules (pointers may leak, the stack may be
  read before it is written, no Spectre sanitizing), so a loader without
  `CAP_PERFMON` gets `EPERM` once the type is known. With no BTF objects
  or keys here, func and line info, CO-RE relocations, `fd_array_cnt` and
  a signature are refused. The log has no trace of each instruction or
  state, which Linux writes at levels 1 and 2, and master's diagnostics
  after an error are not written, so its size (`log_true_size`) is
  smaller than Linux's. `BPF_PROG_TEST_RUN` runs socket filters as
  master does, which the test machines' Linux 7.0 does otherwise in three
  ways: it takes an IPv4 or IPv6 packet shorter than its header, gives a
  packet's protocol after a length as `ETH_P_802_3` when it starts with
  `0xffff` (IPX), and copies none of a packet in pages that
  `data_size_out` cuts; so the unit tests alone check those. The other
  program commands (`BPF_PROG_QUERY`, `BPF_PROG_BIND_MAP` and the rest),
  BTF (`BPF_BTF_LOAD`), links, attachment, the IDs of
  programs, BTF and links
  (`BPF_PROG_GET_NEXT_ID`, `BPF_PROG_GET_FD_BY_ID` and the rest), tokens,
  iterators and statistics are `ENOSYS`, as each command Linux has that is
  not here; a number Linux has no command for is `EINVAL`, as there.
  `BPF_OBJ_PIN` pins maps alone: a program's descriptor is `EINVAL`, as
  for no object. A BPF file system's extended attributes follow Linux
  master, which has had `trusted.` and `security.` ones since 7.2
  (9722955b5430); the test machines' Linux 7.0 has none (each call is
  `EOPNOTSUPP` there), so the unit tests alone check them, and the
  differential case can compare them once the runners have 7.2. So
  libbpf's trivial-program probe loads a socket filter and finds no other
  program type, and `bpftool feature` finds socket filters and only the
  helpers the verifier checks. A command with master's `BPF_COMMON_ATTRS`
  (bit 16) is `EINVAL` too: the test machines' Linux 7.0 has no such flag,
  though master would read a `struct bpf_common_attr` from the fourth and
  fifth arguments and run the command. The other map types are `EINVAL`,
  as on a kernel built without them; the per-CPU ones
  (`BPF_MAP_TYPE_PERCPU_ARRAY`, `PERCPU_HASH`, `LRU_PERCPU_HASH`) could not
  be compared with Linux anyway, as their values are one per possible CPU,
  which a test machine and the emulator count differently. A hash gives
  its keys in the order of their bytes, where Linux's order follows its
  buckets and a random seed, and a batch of it takes each element as a
  bucket of its own, so `in_batch` and `out_batch` count elements. An LRU
  hash keeps the lists of one CPU, which every command uses: on Linux each
  CPU has its own local lists, so where updates of one map come from
  several CPUs, the key that goes when it is full may be another (the
  differential test pins itself to one CPU). A trie takes memory only as
  elements come, as Linux counts it, but Linux also fills a cache of
  nodes for each CPU when it makes one, so a trie with a value of
  megabytes may be `ENOMEM` there and is not here. A map's
  memory follows the structure sizes of the test machines' kernel,
  Ubuntu's Linux 7.0, not upstream Linux's: its `struct bpf_map` carries
  the `u32 excl` that Ubuntu took from Linux 7.2 (0fb6c9ed6493, removed in
  7.3), so an array's header is 312 bytes where upstream v7.0's is 304.
  Linux master's array header is 312 bytes too, through another field,
  but its hash header (832 bytes) and elements are smaller than the 896
  and 48 bytes here. The elements are not taken from
  the machine until they are written: no memory cgroup is charged, and
  only a map larger than the machine's 4 GiB is `ENOMEM`, where Linux may
  also run out of the memory it really has. A preallocated hash counts a
  spare element for each CPU of the host, where Linux counts the possible
  CPUs, which may be more. The checks follow Linux master where the test
  machines' Linux 7.0 differs: a hash whose key and value take 4 MiB less
  64 bytes or more is `E2BIG` (7.0 takes up to 4 MiB less 48), and
  `BPF_F_RDONLY` with `BPF_F_WRONLY` is refused once the map is made (7.0
  refuses it before the NUMA node and the type, so another error may come
  first here). Map IDs are the emulated machine's, so they
  start at 1 and do not see the host's maps. A map's SHA-256
  (`bpf_map_info.hash`) is `EINVAL`.
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
- **Segment registers, in part**: `lfs`, `lgs` and `lss`, `lar`, `lsl`,
  `verr` and `verw` stop a program with `SIGILL`. The CPU runs only in
  64-bit mode: a far `jmp`, `call` or `ret` to a compatibility-mode
  segment (`__USER32_CS`, or any code segment `modify_ldt` writes, which
  Linux never makes 64-bit) is `SIGILL` at the transfer, where Linux runs
  32-bit code there, and an `rt_sigreturn` frame whose `cs` is one is a bad
  frame. A far `jmp` or `call` with REX.W takes an `m16:64` pointer, as
  Intel's CPUs do, where AMD's read `m16:32`. `set_thread_area` is not implemented,
  so the GDT's thread-local entries stay empty, and the limit of the CPU
  number segment is 0. A `mov` or `pop` to `%ss` does not hold off the
  single-step trap of the instruction after it, as the CPU does. After
  `modify_ldt` only the calling thread's `%ds` and `%es` load again, where
  Linux reloads them in every thread of the address space. A null selector
  clears the `%fs` or `%gs` base, where AMD's CPUs before Zen 2 keep it.
- **io_uring, in part**: only `IORING_OP_NOP`, `IORING_OP_EPOLL_CTL`,
  `_EPOLL_WAIT`, `IORING_OP_READ`, `_WRITE`, `_READV`, `_WRITEV`, `_FSYNC`,
  `_READ_FIXED`, `_WRITE_FIXED`, `_READV_FIXED`, `_WRITEV_FIXED`,
  `IORING_OP_FILES_UPDATE`, `IORING_OP_PROVIDE_BUFFERS`,
  `_REMOVE_BUFFERS`, `IORING_OP_ASYNC_CANCEL`, `IORING_OP_TIMEOUT`,
  `_TIMEOUT_REMOVE`, `_LINK_TIMEOUT`, `IORING_OP_POLL_ADD`,
  `_POLL_REMOVE`, the file requests `IORING_OP_OPENAT`, `_OPENAT2`,
  `_CLOSE`, `_STATX`, `_FALLOCATE`, `_FADVISE`, `_MADVISE`, `_RENAMEAT`,
  `_UNLINKAT`, `_MKDIRAT`, `_SYMLINKAT`, `_LINKAT`, `_FTRUNCATE` and
  `_PIPE`, `IORING_OP_SPLICE` and `_TEE`, and the socket requests
  `IORING_OP_SHUTDOWN`, `_SOCKET`, `_ACCEPT`, `_CONNECT`, `_SEND`,
  `_RECV`, `_SENDMSG` and `_RECVMSG` run; the other operations, up to
  Linux 7.0's `IORING_OP_URING_CMD128`, complete with `EOPNOTSUPP`. Of the
  socket requests, a receive's bundle (`IORING_RECVSEND_BUNDLE`) and a
  receive with `MSG_WAITALL` that selects a buffer are not there yet
  (`EINVAL`). A send's selected buffers follow Linux master; the kernel of
  the differential tests' runners still sends a provided buffer whole
  whatever the length (before master's b7322810d187), so the tests do not
  compare that, nor whether a bundle whose length runs out on the last
  buffer goes on (8742f4b5a472). A multishot receive whose socket keeps
  having more goes on at once however many times in a row, where Linux
  requeues it after 32 (`MULTISHOT_MAX_RETRY`), letting other task work
  run first. A send or a receive with
  `IORING_RECVSEND_FIXED_BUF` is `EINVAL`, as on Linux 7.0, the kernel the
  differential tests run on; Linux master moves the bytes of a registered
  buffer. This follows master once the test runners' kernel does. A
  send's address is read again as it runs, and an `IORING_OP_RECV` with
  `MSG_WAITALL` does not fail its link for ancillary data it has no room
  for, as Linux's does. An `IORING_OP_SHUTDOWN`, an `IORING_OP_FSYNC`
  and a file request run while `io_uring_enter` takes them, where Linux
  runs them, but for a close and some opens and advice, in a worker, so
  their completions can come before those Linux posts first, and an open of
  a FIFO that may create it waits there. An `IORING_OP_SPLICE` or `_TEE`
  that waits is cancelled as a request that waits for its file, where Linux
  interrupts its worker, and a splice to a socket can wait there for part
  of it. A timeout expires at
  the checkpoints where its process can run: one due while every thread
  sleeps in `nanosleep` completes as the sleep ends, where Linux's timer
  completes it then. A thread that exits alone leaves its polls of rings
  waiting, where Linux cancels them, and a ring polled by a request of its
  own stays until that request ends. The setup flags
  `IORING_SETUP_IOPOLL`, `_SQPOLL`, `_SQ_AFF`, `_ATTACH_WQ`,
  `_SQE128`, `_CQE32`, `_NO_MMAP`, `_REGISTERED_FD_ONLY`,
  `_HYBRID_IOPOLL`, `_CQE_MIXED`, `_SQE_MIXED` and `_SQ_REWIND` give
  `EINVAL`. No wait region can be registered (`IORING_REGISTER_MEM_REGION`),
  so a wait with `IORING_ENTER_EXT_ARG_REG` fails with `EFAULT` (`EINVAL`
  for a size other than `struct io_uring_reg_wait`'s),
  and `io_uring_register` has only `IORING_REGISTER_PROBE`,
  `IORING_REGISTER_BUFFERS`, `IORING_UNREGISTER_BUFFERS`,
  `IORING_REGISTER_BUFFERS2`, `IORING_REGISTER_BUFFERS_UPDATE`,
  `IORING_REGISTER_FILES`, `IORING_UNREGISTER_FILES`,
  `IORING_REGISTER_FILES_UPDATE`, `IORING_REGISTER_FILE_ALLOC_RANGE`,
  `IORING_REGISTER_FILES2`, `IORING_REGISTER_FILES_UPDATE2`,
  `IORING_REGISTER_PBUF_RING`, `IORING_UNREGISTER_PBUF_RING`,
  `IORING_REGISTER_PBUF_STATUS`, `IORING_REGISTER_SYNC_CANCEL`,
  `IORING_REGISTER_PERSONALITY`, `IORING_UNREGISTER_PERSONALITY`,
  `IORING_REGISTER_RESTRICTIONS`, `IORING_REGISTER_ENABLE_RINGS`,
  `IORING_REGISTER_RING_FDS` and `IORING_UNREGISTER_RING_FDS` (the others
  give `EINVAL`). Restrictions of a task, which Linux 7.0 has, are not
  there (`EBADF` for descriptor -1).
  `IORING_REGISTER_BUFFERS_UPDATE` reads each slot's `iovec`
  before its tag and refuses `IORING_RSRC_UPDATE_EXTENDED`, as Linux 7.0,
  the kernel the differential tests run on, does; Linux master reads the
  tag first and takes that flag's `struct io_uring_regbuf_desc`s. This
  follows master once the test runners' kernel does. A process's
  whole exit cancels the requests its threads submitted that wait for
  their files, as Linux master's `io_task_group_exiting` does. Linux 7.0,
  the kernel the differential tests run on, cancels them only once their
  files are ready, as for a thread that exits alone. A huge page of a
  registered buffer charges RLIMIT_MEMLOCK for each of its 4 KiB pages, where
  Linux charges it once. A ring maps only shared (`MAP_PRIVATE` gives
  `EINVAL`). An offset that no region of a ring has gives its mapping
  `ENOMEM`, as on Linux 7.0, the kernel the differential tests run on;
  Linux master's `io_uring_get_unmapped_area` gives `EINVAL`. This follows
  master once the test runners' kernel does.
  The features are Linux
  6.12's, so `IORING_FEAT_RW_ATTR` and `_NO_IOWAIT` are not reported,
  though `IORING_ENTER_NO_IOWAIT` is taken. A pseudo-terminal's read waits in
  `io_uring_enter` instead of waiting for its file as a pipe's read does. A file that is never read (an epoll instance, a ring)
  fails with `EINVAL` at once, where Linux first waits for it to be ready.
  An `IORING_OP_ASYNC_CANCEL` with `IORING_ASYNC_CANCEL_OP` and an
  operation past `IORING_OP_LAST` finds no request (`ENOENT`), as on Linux
  7.0, the kernel the differential tests run on; Linux master's
  `io_async_cancel_prep` refuses it with `EINVAL`. This follows master once
  the test runners' kernel does.
  A file without a position (a pipe, a socket, a terminal, an eventfd) is
  taken as one that can be polled, which decides when a read uses a ring's
  buffer and whether a transfer waits for it. A ring of buffers in the
  program's memory is not pinned, unlike a registered buffer: the kernel
  reads and writes it through its mapping at each use, so a read that finds
  it unmapped fails with `EFAULT`, where Linux uses the pages it pinned.
- **Native AIO, in part**: every read, write and sync runs as `io_submit`
  takes it, as Linux's buffered I/O does; one of a file opened with
  `O_DIRECT` does not run in the background as on Linux, and a sync's event
  is in the ring when the call returns, where Linux's comes from a worker
  soon after. A poll that waits for a file made ready by no call (a
  timerfd that expires, input from the host) completes at the next call of
  any process, while a call waits for files, or at the next checkpoint of
  a running thread, where Linux's comes at once: while every thread sleeps
  in a call that waits for no file, it comes once one wakes. Which files'
  polls wait on two queues, which Linux refuses with `EINVAL` unless the
  file is ready, is guessed from the kind of file: a FIFO
  open to read and write, and a character device (a terminal). A ring holds
  exactly one request fewer than its events, where Linux's per-CPU counts
  can stop one sooner; and the I/O priority of `IOCB_FLAG_IOPRIO` is checked
  but changes nothing.
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature.
  - `pwritev2`'s `RWF_NOAPPEND` cannot turn an `O_APPEND` file's append off
    on a Windows host, which gives `EOPNOTSUPP` for such a file there.
    A regular file's `RWF_NOWAIT` read never finds its pages uncached
    (Linux's `EAGAIN`). On a macOS or Windows host a host file takes
    `RWF_NOWAIT` and `RWF_DONTCACHE` as ext4's does, whatever its own file
    system, and only ext4, xfs, btrfs and f2fs are told apart on a Linux
    host (any other file system takes neither).
  - `MADV_COLLAPSE` refuses a regular file's mappings (`EINVAL`). Linux's
    rules for them changed after v6.12, which collapses only a file nobody
    has open for writing (`READ_ONLY_THP_FOR_FS`), where later kernels take
    any file on a file system with large folios. The result also depends
    on the host's page cache: pages not read in yet, and dirty ones, which
    are written back once and are otherwise `EAGAIN`. A collapsed extent
    stays 512 ordinary pages, so `/proc/<pid>/smaps` shows no
    `AnonHugePages` or `ShmemPmdMapped` for it. Whether an extent of
    private anonymous memory has a page table is taken as whether a page of
    it has an entry or a marker. For shmem only the collapsing VMA's own
    `userfaultfd` registration counts, where Linux refuses holes if any VMA
    of the file, in any process, is registered for missing pages, and
    sysfs's `shmem_enabled` is taken as never `deny`. Linux can also fail a
    collapse for want of a free huge page (`ENOMEM`) or for a page in use
    (`EAGAIN`), which never happens here.
  - With `CAP_SYS_ADMIN`, `MADV_HWPOISON` refuses (`EIO`) a page of a file
    or of shared memory, which Linux poisons in the page cache, for every
    mapping and for the file. Of a page `fork` shares it poisons only the
    caller's entry, where Linux unmaps it from every process. The zero page
    gives `EBUSY` each time, where Linux marks the machine's zero page
    poisoned at the first. Nothing of the advice with `CAP_SYS_ADMIN` is
    differentially tested, as natively it would poison the host's memory.
  - `process_madvise` takes for the caller's own memory only the advice
    `madvise` takes, and another process's ranges are only checked to be
    mapped, but for `MADV_COLLAPSE`. It refuses advice Linux does not know
    before any range (`EINVAL`), as Linux master does; the CI's kernel
    checks it with each range, so with no ranges, or only empty ones, it
    gives 0 there.
  - In a child of `fork`, `move_pages` shows a page of a program's own
    ELF segment that the loader wrote and nothing wrote since as there,
    where Linux copies no page table of a VMA without an `anon_vma`
    (`-ENOENT` until the child touches the page): the loader's copy is
    the only one the page has here.
  - A program's ELF segments are backed by the bytes the loader read at
    `execve`. The program's own file cannot be written while it runs
    (`ETXTBSY`), but Linux gives its interpreter's back for writing once it
    is loaded: a later write to that file is not seen in a segment page
    nothing wrote yet, and a page past the end at `execve` stays `SIGBUS`
    when the file grows, where Linux maps both from the page cache.
  - A fault of a `memfd_secret` page takes the faulting process's
    `RLIMIT_MEMLOCK` as of its last system call (its creator's before
    one), and the pages count only `memfd_secret` files and `io_uring`'s
    registered buffers and rings of buffers, where Linux's `locked_vm` of a user also counts
    `perf`'s buffers and the like.
    Kernels without the change that counts them as they are faulted in
    (97d34aa65c29, "mm/secretmem: properly account locked pages") count
    its mappings as locked instead: `mmap` gives `EAGAIN` past the limit,
    and `msync` with `MS_INVALIDATE` of the mapping gives `EBUSY`, where it
    succeeds here, as on kernels with the change.
  - The interval timers of CPU time, `ITIMER_VIRTUAL` and `ITIMER_PROF`, and
    `RLIMIT_CPU` all count the process's whole CPU time, as all of it is user time here
    (Linux's `ITIMER_VIRTUAL` leaves out the system time; its `RLIMIT_CPU`
    counts it). Where the host
    cannot measure a thread's CPU time, as in WebAssembly, that is wall time,
    so they also count the time a thread sleeps or waits, all of it once it
    wakes. They are looked
    at as a thread makes a system call and at least every 100,000
    instructions it runs, not at each tick as on Linux, and a tick is taken as 1 ms, the
    CI runners' `CONFIG_HZ`. POSIX timers on the CPU-time clocks count
    and are looked at the same way, and so does a sleep on the process's
    CPU clock, which the sleeping thread looks at every tick; where that is
    wall time, the sleep counts its own time too, so a process alone ends
    it after the wall time it asked for.
    A timer on another process's CPU time is looked at as that process's
    threads make system calls, the same way. A process's CPU time, read or
    set from any of its threads or from outside it, is each running
    thread's as of then, where Linux counts all but the calling thread's as
    of its last tick, at most a millisecond before on the CI runners (a
    thread's own clock is exact on Linux too); so it can be ahead of
    Linux's by as much. A thread's CPU time is as fine as the host shows
    another thread's: 1 ns on Linux, 1 µs on macOS, and on Windows its
    scheduler's tick, about 15.6 ms.
  - The time cannot be set: `settimeofday`, `clock_settime` and an
    `adjtimex` or `clock_adjtime` that changes something give `EPERM` even
    to a caller with `CAP_SYS_TIME`, where Linux sets the clock, its time
    zone or its NTP state, so the NTP state is only ever read: the host's on
    native Linux, and elsewhere the one Linux starts with. The host's state
    is read at each call, so two reads can differ when the host's time
    daemon changes it in between (chrony, for one, moves the tick by a few
    microseconds); a comparison with a native run therefore matches only
    while the host leaves it as it is. Where the host's sandbox refuses
    even that read (Docker's default seccomp profile without
    `CAP_SYS_TIME`), a native `adjtimex` gives `EPERM`, while here it reads
    the state Linux starts with. `clock_settime` on a CPU clock named by a negative clock ID gives
    `EINVAL` without reading the time, where Linux reads it, finds the task
    and gives `EPERM`, and the auxiliary clocks (`CLOCK_AUX`) are not there.
  - The host's I/O ports cannot be used: `iopl` above level 0 and `ioperm`
    turning ports on give `EPERM` even to a caller with `CAP_SYS_RAWIO`, as
    a kernel locked down against port access gives, where Linux without
    lockdown grants them. Process accounting cannot be turned on: `acct`
    with a file gives `EPERM` even with `CAP_SYS_PACCT`, without reading
    its name, where Linux opens the file (so a bad pointer gives `EFAULT`,
    a missing file `ENOENT` and one that is not regular `EACCES`) and writes
    a record as each process exits.
  - The kernel log that `syslog` reads is always empty, where Linux's holds
    its boot messages, and `kernel.dmesg_restrict` is always 1 (there is no
    `/proc/sys/kernel/dmesg_restrict`, `/proc/kmsg` or `/dev/kmsg`).
    `sysfs` knows only nine file system types, where Linux has dozens, so
    their indexes differ from Linux's though not their order. There is no
    AppArmor or SELinux: `lsm_list_modules` lists four modules, and
    `lsm_get_self_attr` finds no attribute where Linux gives AppArmor's
    context.
  - The kernel is always locked down for integrity, where Linux without
    Secure Boot is not: a module or kexec image is never loaded, even one
    signed by a key Linux trusts, and a module's PKCS#7 signature is not
    parsed, so a malformed one gives `EPERM` where Linux gives `EBADMSG`.
    `finit_module` does not decompress a `MODULE_INIT_COMPRESSED_FILE`
    module, and neither it nor `kexec_file_load` refuses a file open for
    writing (Linux's `ETXTBSY`). A restart by `reboot` in the first PID
    namespace ends the run rather than starting it again.
  - There is no swap and no quota: `swapon` of a host file gives `EINVAL`
    where Linux on ext4 swaps on a file with a swap signature, and
    `quotactl_fd` of a host file gives `ENOSYS` where ext4 answers.
  - A file in `/proc` or `/dev` has the `st_dev` of the mount holding the
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
  - System V IPC's `IPCMNI` is always 32768, as without the
    `ipcmni_extend` boot option.
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
  - Keys have no `/proc/keys`, `/proc/key-users` or `/proc/sys/kernel/keys`,
    no `big_key`, `asymmetric`, `encrypted` or `trusted` types, no
    Diffie-Hellman, public-key or watch operations (`EOPNOTSUPP`) and no
    `/sbin/request-key` to construct a key. The first process starts with
    no session keyring, where a login gives one, and the kernel's own
    `.builtin_trusted_keys`, BPF, dm-verity and fs-verity keyrings are not
    there (`ENOKEY`). The garbage collector's work (unlinking invalidated
    keys, and keys 5 minutes after they expire) is done as the next key
    call begins, not by a worker of its own, and a key whose last link
    goes is gone at once, its quota given back, where Linux frees it a
    little later; a thread
    keyring follows only the file-system IDs that `setfsuid`, `setuid`
    and the like change.
  - `ptrace` requests the features do not list give `EIO`. `PTRACE_ARCH_PRCTL` has only the `fs` and `gs` bases,
    as the emulator's `arch_prctl`, and gives `EINVAL` for the rest.
    `NT_X86_XSTATE` gives `ENODEV`, as on a CPU
    without XSAVE, which the emulated CPU does not offer. A data
    breakpoint on a `rep` string instruction stops after the iteration that
    touched its range, as the architecture defines it; a CPU's fast-string
    operation may report it some iterations later.
    A read breakpoint on the 48 bytes at the end of an `FXRSTOR` area,
    which the architecture leaves to software, is not hit, as `FXRSTOR`
    reads only the 416 bytes it restores; an AMD CPU reads them too, and
    stops there.
    A write breakpoint on a byte that `MASKMOVDQU`'s mask leaves out is not
    hit either, as no byte there is written; an Intel CPU stops there, and
    an AMD CPU does not.
    A `cs` or `ss` selector a tracer writes other than the 64-bit user ones
    is kept and shown, but the tracee runs on in 64-bit mode, where Linux
    would run it in that segment or fault.
  - `mincore` counts a page of a file as in memory whenever it lies within the
    file, where Linux asks its page cache.
  - Adjacent VMAs never written that a `fork`ed child's lost locks or
    `userfaultfd` registrations make alike are one VMA in
    `/proc/<pid>/maps`, where Linux merges none at a `fork`.
  - `mmap` with
    `MAP_LOCKED` checks `can_do_mlock` (`EPERM`) and room under
    `RLIMIT_MEMLOCK` (`EAGAIN`) before it finds room for the mapping
    (`ENOMEM`) and looks at the file, where Linux does those first, and `mremap` checks the room for a locked VMA
    that grows before its other checks of the new range.
  - A memory policy that `mbind` gives a shared mapping belongs to that
    mapping, where Linux keeps it with the shared memory itself, for every
    process that maps it. `/proc/<pid>/numa_maps` does not exist.
  - `shmdt` finds the attachments of the segments of the thread's IPC
    namespace only, where Linux detaches one made before `setns` or
    `unshare` moved the thread to another. An `mprotect`, `mlock`,
    `madvise`, `mseal` or `userfaultfd` registration that gives part of an
    attachment back the flags of the piece next to it makes a piece of its
    own, which counts as an attachment, where recent Linux moves the
    boundary between the two.
- **Extended attributes**: a mounted host directory behaves as a file system
  without them, so reading finds none (`ENODATA`) and writing gives `EOPNOTSUPP`.
  In memory, a file's `system.*` attributes do not exist (`EOPNOTSUPP`), so it
  has no POSIX ACLs (`system.posix_acl_access`) where tmpfs has them. A
  socket file has no `user.*` attributes (writing gives `EPERM`), as on the CI runners'
  Linux 7.0, where Linux master gives them to sockets too.
- **Rename flags**: on a Windows host, `renameat2` in a mounted directory
  takes neither `RENAME_NOREPLACE` nor `RENAME_EXCHANGE` (`EINVAL`), as a
  Linux filesystem without them.
- **File owners**: in a mounted host directory, the owner and group that
  `chown` gives a file, and those of a file a guest makes there, are kept
  only while the emulator runs, not on the host file. The next run sees
  every file there as root's again.
- **mount and umount2, in part**: `mount` makes only tmpfs, BPF file
  systems and bind mounts;
  any other type is `ENODEV`, as from a kernel without it. Once Linux's
  checks before them pass, `MS_NOSYMFOLLOW` on a tmpfs or set by a
  remount, a mount on or a move of the generated `/proc` or `/dev` (or a
  file in them, but for `/dev/shm` and what is below it), and a bind mount of a descriptor's link to a file no path
  names, give `EOPNOTSUPP`, so a program
  learns they are not supported, as do `fsmount`'s
  `FSMOUNT_NAMESPACE` (new in Linux master) and `MOUNT_ATTR_NOSYMFOLLOW` on
  a tmpfs, `fspick` of `/proc` or `/dev`, and an idmapped mount
  (`mount_setattr`'s and `open_tree_attr`'s `MOUNT_ATTR_IDMAP`, after the
  checks of its user namespace's descriptor). Unique mount IDs and mount
  namespace IDs count among this machine's alone, where Linux's are shared
  with the host's (the first namespace's ID is Linux's 8), and the
  namespace files take no `NS_GET_MNTNS_ID` or `NS_GET_ID`. `statmount`'s
  `propagate_from` is found from the namespace's root, as mountinfo's is;
  its `STATMOUNT_BY_FD` of a detached tree's mount is `ENOENT`, as Linux's
  is for one alone in its anonymous namespace, and finds a mount by where
  its file now is, in the caller's namespace, where Linux takes the
  file's own mount (one opened before a `setns` is looked for in the
  namespace the caller is in now). A file a bind mount of a generated
  file shows has, in `statx` and `/proc/self/fdinfo`, the mount ID of
  `/dev` or `/proc`, not the bind mount's. Of the mounts Linux has under
  `/proc` and `/dev`, the table has only `/proc` and `/dev` themselves and
  the tmpfs on `/dev/shm`, not `/dev/pts`, `/dev/mqueue` or
  `/proc/sys/fs/binfmt_misc`: a bind mount of `/proc` or `/dev` (or a
  directory in them) still shows what is generated in those directories,
  and what is in `/dev/shm`, where Linux shows their empty mount points,
  and with `MS_REC` takes no mount along. In a namespace of a less
  privileged owner a bind mount of `/dev` without `MS_REC` is `EINVAL`,
  as Linux refuses it for its locked `/dev/shm`, but one of `/proc` or
  `/dev/pts` is made, where Linux refuses it for its locked mounts below
  (`EINVAL`); with `MS_REC` each is made, as on Linux. Once
  `/dev/shm` is unmounted, its name is not found there (`ENOENT`) nor
  listed in `/dev`, where Linux shows devtmpfs's empty directory. A file system context makes
  only a tmpfs, as `mount` does, and logs no message but those of its
  parameters and of a reconfiguration; one of a superblock from start-up
  takes only the common flags (`ro`, `sync`, ...). A context keeps its
  superblock by its mount, so once that mount is gone its
  reconfiguration is `EINVAL`, where Linux's keeps the superblock. A detached tree from `open_tree`
  belongs to the table of the mount namespace it was made in, where Linux
  gives it an anonymous namespace of its own: after an
  `unshare(CLONE_NEWNS)` its descriptor no longer reaches it, and only a
  tree from the caller's namespace attaches. It goes at the next change of
  the mounts after its descriptor's last close, not at the close. A detached tree gets no copy of
  a mount propagated to its peers. The mounts from start-up are
  private, where Linux's root is often shared (`shared:1`, and `master:1`
  in a mount namespace of another user namespace). Peer group numbers
  count from 1 among this machine's mounts alone, where Linux's are
  shared with the host's. `propagate_from:` is found from the namespace's
  root, not the reader's after `chroot`. `MS_RDONLY` (`EROFS`), `noexec`,
  `nodev` and `nosuid` are enforced, and so are a tmpfs mount's `size`,
  `nr_blocks` and `nr_inodes`, and a page a fault brings into a file of a
  tmpfs mount or a memfd counts in its blocks, as `shmem_fault` charges
  it, one past the mount's size being a `SIGBUS`, with a large folio's
  others on a mount with `huge=`. Not yet so: a large folio is mapped a
  page at a time, so `/proc/<pid>/smaps` and `/proc/meminfo` count no
  `ShmemPmdMapped`, `FilePmdMapped` or `ShmemHugePages` for it and a
  fault maps (and counts in `Rss`) only the pages around it, not the whole
  folio; a large folio always comes, where Linux
  takes a smaller one when memory has no free extent so large; and none
  is split under memory pressure but to make room for another. Its extended attributes
  take none of the inodes' room (`ENOSPC` from `setxattr` past it, as
  `shmem_xattr_handler_set` counts them, does not happen); the root from
  start-up has no limit but
  `fallocate`'s, the memory reported. Not enforced either are the atime
  flags, `sync`, `dirsync` and `mand`; no mount here holds a
  device node but a host directory's (`mknod` of one is `EPERM`), so
  `nodev` only refuses those;
  `mpol`, `noswap` and the quota options are taken, checked as
  Linux checks them (a remount that turns on `noswap` or quotas, or
  changes a quota limit, is `EINVAL`) and shown, but do nothing, and
  `casefold` and `strict_encoding` are `EINVAL`, as from a
  kernel without `CONFIG_UNICODE`. `statfs`'s `f_flags` leaves out
  `ST_SYNCHRONOUS` and `ST_MANDLOCK`. A remount read-only is not refused
  for a file that is unlinked but still open (Linux's `s_remove_count`).
  A remount of a mount from start-up changes only whether its superblock
  is read-only: a `hostfs` one takes no option but the common ones
  (`EINVAL`), and the root's tmpfs options are checked but keep nothing.
  A descriptor's mount, for `EROFS` of `fchmod`, `fchown`, `futimens`,
  `fsetxattr` and the like, is found by the path it was opened at, and for
  `noexec` of `mmap` by where its file now is, so a remount or a mount on
  that path since the open counts, where Linux's keeps the file's own
  mount.
  `MNT_EXPIRE`'s mark is cleared by a lookup that ends on the mount and by
  the close of a file on it, but not by a lookup that only passes through
  it, as Linux's every `mntput` does.
  The mounts from start-up (the root and each `--mount`) cannot be
  unmounted: `umount2` gives `EINVAL` when one is locked (in a mount
  namespace a new user namespace made, where the root is locked too, as
  Linux's `/` is a locked mount on its rootfs) and `EBUSY` otherwise, and
  `MS_MOVE` of one gives `EOPNOTSUPP`: the lower filesystem shows each
  `--mount` itself, so taking one away would show it again, not the
  directory under it. For the same reason `move_mount` with
  `MOVE_MOUNT_BENEATH` beneath one gives `EOPNOTSUPP`. Beneath the
  namespace's root after `pivot_root` it gives `EINVAL`, as the mount left
  below the root here takes no mounts, where Linux master mounts the
  source on that mount. After `pivot_root` the old root can go, but a
  `--mount` under it still stays, and a new root that is a `--mount` shows
  its files at its old place under `put_old` too, where Linux shows
  the directory it covered. The generated `/proc` and `/dev` stay at the
  root's `/proc` and `/dev` after `pivot_root`, where Linux's go to
  `put_old` with the old root, and at `/proc` and `/dev` in a namespace
  from `open_tree`'s `OPEN_TREE_NAMESPACE`, where Linux has them only
  where the copy has their mounts. `umount2` of either gives `EINVAL`,
  where Linux unmounts it. A move or a `pivot_root` takes the roots
  and working directories along, but an open descriptor keeps the path it
  was opened at for what it does by path (`fchdir`, a lookup from it).
  Mounts are kept by their mount
  points' paths: a rename moves the mounts below the directory in the
  caller's namespace only, so another namespace's copies stay at the old
  path, and `rmdir` of a directory that is a mount point in another
  namespace leaves that mount there, where Linux detaches it. A detached
  mount's open files keep working, but a working directory or a descriptor
  in it is used by its path, which no longer leads there. A mount ID is the
  lowest free one from 21, and the root's parent is shown as 1. A bind mount keeps its source by path: a rename
  in another namespace leaves it at the old path, and when its source is
  removed it shows nothing, where Linux keeps the deleted directory and
  mountinfo marks it `//deleted`. A descriptor's mount ID (`statx` with
  `AT_EMPTY_PATH`, fdinfo) is found by the path it was opened by, and so
  is the mount of a descriptor's events for fanotify's mount marks
  (`FAN_MARK_MOUNT`); once that path no longer leads to the file's file
  system (renamed or replaced since), the event is the first mount's of
  that file system.
- **Landlock**: ABI version 8 is the newest there; the logging flags are
  taken, but nothing is logged. With `LANDLOCK_RESTRICT_SELF_TSYNC` the other
  threads take the new domain for their own checks when they next enter the
  kernel, where Linux waits until they all have. Signals to them meet it at
  once, and `/proc` shows it after each one's next system call. A
  rename's Landlock check comes after its permission checks, where Linux's
  comes before them, which shows only when both refuse. A rule on a file under
  `/proc` does not count for `execve`. An open checks the file its path
  reaches before it opens it (and the file it made after), so another thread
  renaming the name in between can make the two differ.
- **seccomp**: a call that `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` keeps
  waiting for its listener looks for a fatal signal every 10 ms rather than
  waking for it. Nothing is logged (`SECCOMP_FILTER_FLAG_LOG`,
  `SECCOMP_RET_LOG`). Strict mode does not make `rdtsc` fault, as Linux's
  `TIF_NOTSC` does. After `SECCOMP_FILTER_FLAG_TSYNC`, `/proc` shows another
  thread's new filter only after its next system call.
- **Credentials**: the IDs and capabilities a thread takes are checked on
  files, signals, resource limits, priorities, socket credentials and core
  files but nowhere else yet.
  Of the files, those under `/proc` and `/dev` are
  not checked, and `fs.protected_hardlinks`,
  `fs.protected_symlinks`, `fs.protected_fifos` and `fs.protected_regular`
  act as 0, the kernel's defaults, which many distributions raise. A
  set-user-ID or set-group-ID program takes its owner or group, and a
  program with file capabilities takes them, even when another process
  shares the caller's working directory (`CLONE_FS`),
  where Linux takes the real IDs as effective unless the caller has
  `CAP_SETUID` and gives no more capabilities than the caller had.
  `execveat`'s `AT_EXECVE_CHECK` (Linux 6.14), with which user space checks
  a file before it runs it under `SECBIT_EXEC_RESTRICT_FILE`, is `EINVAL`:
  the securebits for those checks are kept and shown, but nothing here acts
  on them.
- **Socket messages**: `sendmsg` and `recvmsg` pass descriptors with
  `SCM_RIGHTS` and credentials with `SCM_CREDENTIALS` as Linux does, with
  these differences:
  - The sockets only unread messages hold are closed at once when another
    socket goes, where Linux's garbage collector closes them a little
    later, from a work queue.
- **Socket options**: `setsockopt` refuses, with `ENOPROTOOPT`, the options
  whose effect is not modelled, where Linux takes them: filters on sockets
  other than AF_UNIX and internet ones, and the other options Linux has. No security module is modelled, so `SO_PASSSEC`
  brings no `SCM_SECURITY` and `SO_PEERSEC` is `ENOPROTOOPT`, as on a Linux
  without one; with SELinux, Linux gives the sender's or peer's context, and
  with AppArmor `SO_PEERSEC` gives the peer's label. `SO_RCVTIMEO` and
  `SO_SNDTIMEO` round to a 1000 Hz tick, where Linux rounds to its own
  `CONFIG_HZ`.
  Capabilities are not checked here, so the options that need
  `CAP_NET_ADMIN` (`SO_DEBUG`, `SO_SNDBUFFORCE`, …) are set as for root.
- **Signals ignored at the start**: the first program starts with the
  signals the emulator was started with ignored still ignored, but for
  `SIGPIPE`, which starts at its default. Rust's runtime ignores `SIGPIPE`
  in the emulator itself, so whether it came ignored can't be told. On Linux
  a program started with `SIGPIPE` ignored keeps it ignored. In WebAssembly
  no signal starts ignored.
- **Notification pipes**: there are no watch queues, so `pipe2` and
  io_uring's `IORING_OP_PIPE` with `O_NOTIFICATION_PIPE` give `EINVAL`,
  where Linux built with `CONFIG_WATCH_QUEUE` makes a pipe that key and
  device notifications are posted to.
- **Signal-driven I/O**: the host's standard input, looked at every 10 ms,
  sends `SIGIO` once each time input comes where there was none, where
  Linux's pipe or terminal sends one for every piece of input. Standard
  output and standard error, looked at the same way, send it once each
  time they have room again after being full, where Linux's pipe signals
  its writer at every read of its reader. A stream full or empty for less
  than those 10 ms can go unseen and send none, unless a read or write told
  the guest `EAGAIN`, which always gets its signal. In WebAssembly, which has
  no thread to look, they send none.
- **Edge-triggered `epoll` on a signalfd, in part**: a signal queued for
  another thread of the process is the waiting thread's edge as it is sent,
  but a thread already waiting sees it within 10 ms, where Linux's
  `signalfd_notify` wakes the file at once.
- **A POSIX timer's signal, in part**: a timer on a clock of real time
  sends to the process's leader first, where Linux's `posixtimer_get_target`
  sends to a thread of the process that its interrupt finds running. One
  whose signal is ignored is dropped as it is taken, where Linux keeps it
  aside until it is no longer ignored.
- **inotify, in part**: when a superblock goes, its files' watches hear
  `IN_UNMOUNT` in the order the files got their first mark of any group, as
  on Linux. `/proc/self/fdinfo` lists an epoll's files by
  descriptor where Linux's order follows the files' addresses, and numbers
  eventfds within the emulator, where Linux's `eventfd-id` counts the whole
  system's. Changes the host makes to a mounted directory are not seen, and
  a descriptor's place does not follow them.
- **Shared futexes in a program's read-only segments**: a word in a
  read-only private mapping of a file is the file's (`get_futex_key`), but
  in the segments `execve` maps, of the program and its interpreter, which
  have their own copy of the file, it is its address in the process: a wake
  by another process, or through another mapping of the file, does not find
  its waiters.
- **userfaultfd, in part**: missing pages, write protection and the minor
  faults of shmem are registered. Registered mappings of one `userfaultfd`
  that meet are one range of `UFFD_EVENT_REMOVE`, as when Linux's VMAs
  merge, though Linux keeps apart VMAs whose other flags differ; the
  checks before the event look at the range's first mapping, so that
  `MADV_REMOVE` of such a range whose later mapping is no shared file
  tells of all of it and fails as it drops that mapping, where Linux
  tells of the first VMA alone.
  Of shmem's files a memfd and a file of a tmpfs mount (one a guest
  mounted, or `/dev/shm`) are registered, but for write protection alone
  with `UFFD_FEATURE_WP_ASYNC`, which takes any file: a file of the
  in-memory file system from start-up (`/tmp` among them) is refused
  (`EINVAL`) though it says it is on a tmpfs, as it stands for the files a
  guest has on disk, and a host's tmpfs file is not kept here. A zero
  page `UFFDIO_ZEROPAGE` gives a private mapping of a shmem file is a
  page of zeros of its own, which
  `/proc/<pid>/pagemap` and `smaps` count as such, where Linux maps its
  zero page. A `UFFDIO_MOVE` source
  hole is `ENOENT` before the destination is looked at when nothing
  touched the 2 MiB around it here, as when Linux has no page table there,
  which Linux may also have freed or kept otherwise.
- **`/proc/locks`, in part**: PIDs are those of the reader's PID namespace,
  where Linux's are those of the one `/proc` was mounted in. A `flock` lock a
  program on the host holds on a file of the host is not listed, though it
  conflicts with the guest's, nor are those that wait for it alone. One that
  waits looks again every 10 ms, where Linux wakes it: until then it is not
  listed once the lock it waited for has gone.
- **File leases, in part**: the opens `execve` makes of a program, its
  interpreter and its script, and those of the descriptors fanotify's events
  give, break no lease, where Linux's do. A lease is broken before
  `FAN_OPEN_PERM` is asked, where Linux breaks it after, and after
  Landlock's check of a `truncate`, where Linux breaks it before.
  Delegations (`F_GETDELEG` and `F_SETDELEG`) are `EINVAL`.
- **fanotify, in part**: `FAN_PRE_ACCESS` is `EOPNOTSUPP` (no file system here
  allows it), and `FAN_FS_ERROR` never comes, as no file system here
  reports errors. Linux's ext4 reports them, and since 7.0 its XFS, Btrfs,
  F2FS, iomap's I/O and fsverity do too, through `fserror_report`; its
  tmpfs and procfs report none. An evictable mark on a
  directory is never evicted, where Linux's goes once none of the
  directory's children's dentries is in use; one on a file Linux would
  still write back, or one a mount is on, goes all the same. An open
  keeps the file its own look before the open found, so if the path names
  another file by the time the open is made, that other file's mark may go
  meanwhile; Linux's lookup and open see one file. Which events
  share a bucket of a group's merge hash follows a hash of the emulator's
  own where Linux's mixes in kernel addresses (of the process, and of a
  path in the non-FID modes), so only events of one task's names in one
  directory collide as on Linux. A file a
  descriptor does not hold (a program exec runs) is opened again by the path
  it had, which fails once it is gone.
- **Namespaces**: a user namespace has no
  `user.max_*` limits; its map files check a write with the credentials
  the file was opened with, where Linux also takes the writer's for the
  `CAP_SETUID` and `CAP_SETGID` it needs in the parent; and the `/proc` files
  of a process that is not dumpable belong to root of the first namespace,
  where Linux gives them to root of the process's own when it maps one. A network
  namespace has no interface but its loopback and the veth ends requests
  make. A veth end takes IPv4 addresses and routes, and TCP and UDP go
  across a pair to an address of the peer's namespace; it takes IPv6
  addresses, makes its link-local one and its routes, and takes IPv6
  routes a request adds, with a gateway too, as IPv4's, and IPv6's TCP
  and UDP and its neighbours, but no proxy entry (`EOPNOTSUPP`). An IPv6
  gateway's neighbour state does not steer a lookup, as Linux's
  `rt6_check_neigh` does among routes of one metric. Of an IPv6 multipath
  route's hops through the device asked for, the flow's hash picks one, as
  Linux 7.0 does; Linux master takes the hop the lookup found
  (`have_oif_match` in `ip6_pol_route`). An IPv6 connection
  takes a multipath route's hop by the hash of its addresses and protocol,
  as Linux 7.0 and 7.1 do, and its answers by theirs; from 7.2 Linux takes
  it by the connection's own random hash and takes another as a segment
  sent again draws a new one (`ip6_ecmp_set_mp_hash`,
  `sk_rethink_txhash`), but here a connection's path is settled as it
  opens, so a hop whose answers do not come back fails it. An ICMPv6 error
  takes the hop of its own flow, where Linux's takes that of the packet
  it tells of (`icmp6_send`). A connection with no port of its own yet
  hashes a random source port, as on Linux (`FLOWI_FLAG_ANY_SPORT`): one
  in each of its lookups, where Linux's IPv4 one draws a new one at each
  (`ip_route_connect`, `ip_route_newports`); IPv6's looks its route up
  once (`tcp_v6_connect`). A UDP
  connect whose route fails puts the socket's device back, as Linux
  master does since "ipv6: fix device binding after failed datagram
  connect"; a CI kernel without that fix keeps the device the scope ID
  gave. Neighbour discovery sends no advertisement unasked, and no
  redirect; the
  probe a delaying neighbour sends teaches the peer nothing, where
  Linux's, from the end's link-local address, makes it a neighbour of
  that address. Its duplicate address detection finds no duplicate and
  ends 1.5 seconds after it begins (half of `rtr_solicit_delay`, then its
  probe and a retransmit time), where Linux's
  ends 1 to 2 seconds on after a random delay; its link-local address is always made from its
  Ethernet address (EUI-64, `addr_gen_mode` 0). What IPv6 sends of
  itself, its MLD reports, duplicate address detection's probes and the
  router solicitation, makes the neighbours of the groups it goes to
  (`ff02::16`, the solicited-node ones, `ff02::2`), but only the router
  solicitation reaches the peer, which learns from it if it forwards.
  A report goes at once,
  where Linux's goes two ticks on (`mld_ifc_start_work`); none is sent
  again as Linux's timers send them (`mld_ifc_work`, `mld_dad_work`,
  `addrconf_rs_timer`), so a neighbour of one that is deleted is not made
  again by those; and a
  change of a group's sources sends none (`ip6_mc_add_src`,
  `ip6_mc_del_src`). IGMPv3's report makes its neighbour at once, where
  Linux's goes from its timer a tick on (`igmp_ifc_start_timer`), and is
  not sent again (`igmp_ifc_timer_expire`). Traffic through
  an end moves no counters; a namespace forwards nothing
  on to another. A multicast group is one of the guest's namespaces alone:
  the first has no device to the host's network, so no route to one, and
  joining one there without naming a device is `ENODEV`.
  No IGMP or MLD packet reaches anything: nothing in the guest would see
  one, as raw sockets are `EPERM` and there are no packet sockets
  (`AF_PACKET`).
  A route lookup passes over the route of an anycast address
  (`RTN_ANYCAST`), where Linux's finds it: a lookup of one
  (`RTM_GETROUTE`) gives the route of its prefix, and a packet to one
  goes out as that route takes it, where Linux takes it in.
  `RTM_GETMULTICAST` of Linux master's
  link-layer groups (`AF_PACKET`, `dev_mc_dump`) is `EOPNOTSUPP`. ICMP's port unreachable is not rate limited
  (`icmpv4_xrlim_allow`, `icmpv6_xrlim_allow`), so every datagram to a closed port of the
  peer's makes a connected socket's next send `ECONNREFUSED`; and a
  connection across a pair goes on after an end goes down, goes or moves,
  or the address or route it took goes, where Linux's packets stop. A connection to an address nobody answers ARP or neighbour discovery for fails
  3 seconds after each connect, where Linux's attempts made while the
  neighbour is resolving fail together. An end's neighbour is answered or
  not as the peer would answer when it begins to resolve or to delay,
  where Linux asks again with each probe, and so a packet waiting for one
  never goes once it is answered later; `NTF_MANAGED` ones are never
  probed again; no traffic confirms one (`dst_confirm`, `MSG_CONFIRM`), so
  a delaying one is always probed. The addresses of an end that goes tell
  their lifetimes as of the last netlink request, read or poll in its
  namespace, where Linux takes the time it goes. Making one takes
  only a name, an address and an MTU for each end (`EOPNOTSUPP` for the
  other attributes) and none of the `ifinfomsg`s' flags; changing one,
  only `IFF_UP` and its namespace. A veth end's address without one asked
  comes from a sequence of the emulator's own, not the kernel's random
  numbers; its link watch comes at once, where Linux's may come a second
  later, and so its operational state is found as it is told of; it has one queue each way, where Linux's has one for each
  possible CPU, and no `IFLA_AF_SPEC`. The interface
  requests and netlink change no other flag than `IFF_UP`. The first namespace shows `lo` alone too, where Linux
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
  are only the link, address, route and neighbour requests and the
  neighbour table dump: setting a neighbour table (`RTM_SETNEIGHTBL`), MCTP's
  neighbours (an `AF_MCTP` `RTM_NEWNEIGH` or `RTM_DELNEIGH`), a bridge's
  forwarding database (an `AF_BRIDGE` `RTM_GETNEIGH`, `RTM_NEWNEIGH` or
  `RTM_DELNEIGH`), rules, netconf requests (`RTM_GETNETCONF`), queueing disciplines and the rest are
  `EOPNOTSUPP`, as are renaming `lo` and setting any other attribute of
  it. An input route lookup (`RTA_IIF`) starts with forwarding and
  reverse path filtering off, as Linux is built, where a new namespace of
  Linux takes the first one's for IPv4, which a host may have changed
  (Docker turns forwarding on, Ubuntu reverse path filtering to 2); it
  takes `accept_local`, `send_redirects`, `shared_media` and
  `route_localnet` to be as built, which have no files. `/proc/sys/net` has only `ip_forward`,
  `fib_multipath_hash_seed`, `fib_multipath_hash_policy`,
  `fib_multipath_hash_fields`, `fib_multipath_use_neigh` and the
  `forwarding`, `rp_filter`,
  `accept_dad` and `disable_ipv6` of `all`, `default`,
  `lo` and the veth ends, where Linux has many more; their first namespace's values are as
  Linux is built, not a host's, so a new namespace starts from those.
  A write of `fib_multipath_hash_seed`, `fib_multipath_hash_policy`,
  `fib_multipath_hash_fields` or `fib_multipath_use_neigh` is taken whole and leaves the file where it
  was, as Linux 7.0 to 7.2 do; master takes what it reads and
  moves the file on (`proc_vec`).
  A netconf notification gives
  the settings that have no file (proxy ARP and NDP, multicast and
  broadcast forwarding, ignoring routes with their link down) as 0, as
  Linux is built. A veth end whose MTU is below 1280 still has the files
  of `ipv6/conf/<device>`, where Linux's has none, as it has no IPv6
  (it makes no IPv6 address, as Linux's does not).
  A route goes through `lo` or a veth end, or rejects;
  encapsulations, nexthop objects, realms, expiries, source prefixes, router preferences and the
  anycast, multicast and NAT kinds (and broadcast for IPv6) are
  `EOPNOTSUPP`, and so are policy rules (`RTM_NEWRULE`), so no lookup
  reaches a table but the local, main and default ones. In a new network
  namespace a connection or datagram to an address that an IPv6 route
  through `lo` takes is `ENETUNREACH`, where Linux makes that route a
  rejecting one (`fib6_is_reject`) whose packets go nowhere: a datagram
  is sent, and ICMPv6's no route comes back, which a TCP connection takes
  as a soft error, its `SO_ERROR` until read.
  A route's metrics (`RTA_METRICS`) are kept and shown, but change
  nothing a socket does: its MTU, hop limit, window and congestion control
  are their defaults whatever its route holds. A route may name no
  congestion control but `cubic` and `reno` (`EINVAL`), where Linux, for a
  caller with `CAP_NET_ADMIN`, loads the module of another first.
  An address runs out as its lifetime ends, where Linux's checks are
  deferrable work, which comes up to a second later (`round_jiffies_up`)
  and, on an idle machine, may wait seconds more, unless an address of the
  family is added or changed, which has them run at once. What a socket
  that binds or sends finds run out is told of when a netlink socket of
  the namespace next reads, polls or writes, where Linux tells of it as
  its check runs. An IPv6 route that has run out goes from its table at
  once, where Linux's, which lookups pass over, stays in dumps until its
  garbage collection (`gc_interval`, 30 seconds), and from 7.3 marks its
  notification of that with `RTA_DEL_REASON`. A change that gives a
  permanent IPv6 address a lifetime gives its prefix route the same, as
  Linux does from 7.3; before it, one that has already run out. No
  temporary addresses are made for `IFA_F_MANAGETEMPADDR`, and
  `IFA_F_MCAUTOJOIN` joins no group. A peer address is
  not a point-to-point one, and an IPv6 address of `lo` is never
  tentative, where Linux's is until its duplicate address detection work,
  which ends at once on a loopback, has run. A connection or datagram to an address of
  the namespace's own, of `lo` or a veth end, while `lo` is down is
  `ENETUNREACH`, where Linux's goes out and is
  dropped, and so is one to an IPv6 address in a prefix that is not one
  of `lo`'s, which Linux's prefix route sends to it and drops; an IPv6
  lookup while `lo` is down is `ENETUNREACH` too. A
  lookup's `rta_cacheinfo` counts one reference, where Linux counts the
  other users of the cached route too.
  `RTM_F_NOTIFY` marks a lookup's own answer alone, where Linux marks the
  cached route, so that later lookups through it are marked too.
  Notifications go out for the link, its IPv6 information, addresses,
  routes, neighbours and namespace IDs alone, not for the other groups;
  IPv4's routes through `lo` go without one when it goes down, as on
  Linux. Traffic makes a neighbour through UDP, TCP's handshakes and ICMP's
  port unreachable back alone, which are the only packets paludarium sends
  through `lo` or a veth end (a TCP handshake retried into a full backlog
  makes none of its answer), and none times
  out (`gc_thresh1` is never reached). A dump gives a family's neighbours
  the newest first, where Linux gives them in the order of its hash
  table, which a random key sets. Proxy entries of one hash bucket come
  the newest first, as `pneigh_create` puts each at its head, but one
  x86-64 runner's Linux gave two of them the other way. One without a
  device goes with its namespace, where Linux 7.0, whose proxy table is
  every namespace's, keeps it, for a namespace made later where that one
  was to see (Linux's master gives each namespace its own). Of a loopback neighbour's
  timers only a reachable one's runs: once its reachable time since it
  was confirmed has passed, it goes stale, or delays if it was used
  within the delay before a probe (5 seconds), and its going stale is
  told of when a netlink socket of the namespace next reads, polls or
  writes, as an address that runs out is. One delaying or probing never
  probes nor becomes reachable or failed, and one `NTF_USE` or
  `NTF_MANAGED` makes incomplete counts its first probe but never sends
  another nor fails;
  `NTF_EXT_MANAGED` ones are not probed from time to time. A loopback
  neighbour's state and link-layer address change nothing traffic does, where Linux's
  `lo` holds a packet for one that is not valid until it resolves. Its
  references count only those of the request and of its timer. An IPv6
  proxy entry joins no solicited-node group (`pndisc_constructor`), and
  no request is refused for IPv6 disabled on `lo` (`ndisc_allow_add`). A
  neighbour table dump gives the tables' defaults, which no sysctl
  (`net.ipv4.neigh.*`, `net.ipv6.neigh.*`) changes, nor the host's (its
  garbage collection's thresholds are 128, 512 and 1024, where an AWS
  runner's Linux has its second and third raised to 15360 and 16384): a reachable time of
  the base one, where Linux's is random from half to one and a half times
  it; an entry's size and the queue's length in packets of x86-64's
  `struct neighbour` and `SKB_TRUESIZE`. A table counts the namespace's
  neighbours, with statistics of 0, the hash key and mask of a new table,
  and the times since its flush and new key since the emulator began,
  where Linux's count every namespace's; its own parameters' references
  are 1.
  The options not listed in the features are `ENOPROTOOPT`. A namespace
  ID is given by `RTM_NEWNSID`, by telling of a veth end whose peer is in
  another namespace and by moving a veth end there: Linux's `peernet2id_alloc` gives one on its own
  for a queue lease, a devlink instance, a PSP device, an ovpn peer and
  an openvswitch vport too, none of which is here; the `RTM_DELNSID` of a
  namespace that goes is sent as its last holder lets it go, where
  Linux sends it a little later, from a work queue. MCTP is as Ubuntu's kernel,
  built with `CONFIG_MCTP`, has it: a link's `IFLA_AF_SPEC` carries
  MCTP's settings and `AF_MCTP` address and route dumps have their own
  answers, where a kernel without it gives no MCTP settings, dumps
  IPv4's and IPv6's addresses and routes for those dumps, and takes no
  MCTP address or route. MCTP messages go between the loopback's own
  endpoint IDs alone, as there is no other interface; a tag's key runs out
  by the host's monotonic clock. An `AF_MCTP` socket has `SO_SNDBUF`,
  `SO_RCVBUF` and `SO_RCVTIMEO` alone of the `SOL_SOCKET` options (the
  others are `ENOPROTOOPT`), no timestamps, and of the `ioctl` requests
  Linux answers for every socket only those paludarium has for any. A send
  by hardware address while the loopback has no MCTP address is
  `EHOSTUNREACH`, as on Linux 7.0, where later kernels send it from
  `MCTP_ADDR_NULL`. A link message's IPv4 and IPv6 settings are those of a kernel
  whose sysctls are as built, where Linux's new namespace copies the
  host's, and IPv6's creation time is 0 and its reachable time 30
  seconds, where Linux's is random. The first namespace's `127.0.0.1`
  and `::1` were made at 0, where Linux's were made as it booted.
  With `NETLINK_EXT_ACK`, a request refused for a feature paludarium does
  not have (a route's encapsulation, say, or a link of a kind) carries no
  message, as Linux would take it; an IPv6 route replaced without
  `NLM_F_CREATE` that is not there is told of
  ("Can not replace route - no match found") only where its prefix has
  no route, where Linux looks for a node of its tree; and no answer
  carries a missing attribute (`NLMSGERR_ATTR_MISS_TYPE`) or a cookie, as
  no request taken asks for one. `NLM_F_BULK` is refused ("Bulk delete is
  not supported") for address and route removals alone. A link dump's `IFLA_LINKINFO` is taken without effect,
  where Linux shows only the devices of a kind its modules know. The
  least `IFLA_GSO_MAX_SIZE` and `IFLA_GSO_IPV4_MAX_SIZE` the link policy
  takes is 321, as for Ubuntu's kernel (`MAX_TCP_HEADER` + 1), where
  another build's may differ. A socket
  whose receive buffer is full drops an answer with `ENOBUFS` without
  waiting. The other namespaces keep nothing apart
  that paludarium has, but for the System V shared memory, semaphores and
  message queues and the POSIX message queues of an IPC namespace and the
  mounts of a mount namespace: there are no control groups, so
  `/proc/<pid>/cgroup` shows every task in the root of one hierarchy whatever
  cgroup namespace it is in, and there is no
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
  a crash handler (systemd-coredump, apport) is not modelled.
- **Memory limit**: a write beyond the limit ends the process that made it,
  where Linux's OOM killer picks the process using the most memory.
- **The native JIT**: it is experimental and off unless `--jit` asks for it,
  and only Linux on x86-64 hosts has it; the other native builds use the
  interpreter. It compiles only the instructions with a simple form at the
  start of a block ([Architecture](../design/architecture#the-native-jit)).
- **The WebAssembly build with stable Rust**: it needs a nightly Rust. The
  native crates build with the latest stable Rust, but not with older stable
  releases ([Supported platforms](platforms#rust-toolchain)).

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
- Automated Safari tests on CI sometimes fail to start a session: safaridriver
  times out launching Safari, or the launched Safari never becomes ready. The
  test driver waits, up to 15 seconds, until a Safari told to quit has exited
  before it asks for a session; on CI it logs a Safari still running then,
  with its process ID, and kills it. It asks once more after either failure,
  never for a third time. It retries nothing else, no test and no result, and
  each retry is logged with its error and timing. These failures come and go,
  so a run that passes does not show they are gone.
- Ending a WebDriver session leaves running the Safari that safaridriver
  launched for it. So after each session, and after a failed request for one,
  the test driver asks each Safari that was not running before the request to
  quit, and waits up to 15 seconds for it to exit. A Safari already running,
  such as your own, is never asked. A Safari that does not quit is logged, not
  killed.
- safaridriver exits at startup, with no message, if it starts while the
  previous driver's helper process is still connected to `webinspectord`, or
  while `webinspectord` is exiting after its last client left. So after
  safaridriver stops, the test driver waits up to 15 seconds for that helper
  and each `webinspectord` to exit. One that keeps running, such as a
  `webinspectord` serving another client, is logged, not killed.

## Found a problem?

When a CPU fault kills the guest, the command prints the signal, the address
and the instruction bytes. Run it again with `--report-enosys` to list the
system calls that returned `ENOSYS` ([Command line](./cli#finding-what-is-missing)).
Please include both in an
[issue](https://github.com/aletheia-works/paludarium/issues).
