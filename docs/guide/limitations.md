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
- **`/proc/self/maps`, in part**: the emulator has no vDSO or `vsyscall` page,
  so the `[vvar]`, `[vdso]` and `[vsyscall]` lines are not there. The stack's
  VMA has its full size from the start, where Linux's grows as it is used. A
  program's own segments and its interpreter's are named by the path it was
  started by, never marked `(deleted)`, where Linux follows a rename and resolves
  symbolic links. `smaps_rollup` and `[anon:<name>]` names (`PR_SET_VMA`)
  do not exist.
- **`/proc/self/smaps`, in part**: what it counts comes from the emulator's
  page entries. `Referenced` is every page counted. A page of a loaded program's segment counts as
  anonymous once the segment was written, not once the page was. The
  pages that `MAP_POPULATE`, `MAP_LOCKED` or a lock would read in of a
  file (a mapping not both private and writable) are counted only once
  touched. A read fault in a file's mapping
  maps no more than the 16 pages around it
  ([features](./features#system-calls)), where Linux maps a large folio
  of its page cache whole when the folio lies within the file, the VMA
  and the page table (`filemap_map_folio_range`): the emulator's page
  cache has no large folios, whose size each file system picks. `pagemap`
  shows the same pages.
  `THPeligible` is always 0 and there is no `ProtectionKey`, as there are
  no huge pages and the CPU has no protection keys. `VmFlags` shows no
  `ht` or `dp` (`MAP_HUGETLB`, `MAP_DROPPABLE`). A page of a host file
  that `write` filled is clean (see "Pages `write` filled" below).
- **`/proc/<pid>/pagemap`, in part**: its entries come from the
  emulator's page entries, as `smaps`'s counts do. A page of a loaded program's segment, or of a
  private file mapping, is a file's (bit 61) until the mapping was
  written, not until the page was. The frame number is 0 for every reader, also one
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
- **`/proc/<pid>/clear_refs`, in part**: only 4 (soft-dirty) and 5 (the
  peak resident size) change anything. 1, 2 and 3 are taken, but no
  referenced bits are kept, so `smaps`' `Referenced` stays the resident
  size, where Linux's drops until the pages are touched again.
- **4-level paging only**: the emulated machine always has 4-level page
  tables, whatever CPU the host has: user space ends below 2^47 bytes, and
  `TASK_SIZE_MAX` is 2^47 - 4096 for every check that asks for it, as the
  `fs` and `gs` bases `ptrace`'s `PTRACE_POKEUSER`, `PTRACE_SETREGS` and
  `PTRACE_ARCH_PRCTL` take (`EIO`, `EPERM`) and the range of a hardware
  breakpoint in a debug register (`EINVAL`). Linux on a CPU with 5-level paging (LA57) maps
  above 2^47 only for a process that asks with an `mmap` hint there, but
  its `TASK_SIZE_MAX` is 2^56 - 4096, so these checks take a value between
  the two that paludarium refuses ([decisions](../design/decisions)).
- **The rest of `/proc`, in part**: only the process directories and a few
  system files are made (see [features](./features)). The other system files
  (`/proc/cpuinfo`, the files of `/proc/sys` but for the ones of `fs`,
  `kernel` and `net` it has and `vm/drop_caches`, ...) and the other names in
  the reader's own directory (`stack`, `sched`, ...) are looked up like any
  path, which with `--mount /:/` finds the host's `/proc`; in another
  process's directory they are `ENOENT`, where Linux shows root `stack`
  and the rest. `wchan` is `0` for a waiting task too, where Linux names
  the kernel function it waits in for a reader that may read the task:
  there are no kernel functions here to name. `io` does not count what Linux's `kernel_read` and
  `kernel_write` count for the process (`execve` reading its program and
  interpreter, a core dump's writes), and a read or write that fails with
  an errno Linux gives both before and in the file's operation (`EINVAL`,
  `EFAULT`: an eventfd's too small a buffer) is taken as refused before it,
  so not counted.
  `exit_code` in `stat` is 0 while a thread is in a ptrace stop, where
  Linux has the stop's signal until the tracer's wait. After a leader's
  `exit`, while its process's other threads run, the leader's directory
  under `task` is `ENOENT`, where Linux shows it as a zombie. `/proc/stat` counts all CPU time as
  user time, as `getrusage` does, each thread's to the CPU it was on at its
  system calls, and none as idle; it counts no interrupts or softirqs, and
  as context switches only the times threads went to sleep, as nothing
  preempts a guest thread. A thread's `stat` gives its process's CPU time, and
  another process's thread is `S (sleeping)` in every wait, where Linux
  shows some waits it cannot interrupt as `D (disk sleep)`. A thread shows another process
  what it published at its last system call or signal check, so a mask
  changed only for the length of a call (`rt_sigsuspend`, `ppoll`) is seen
  only while the thread is stopped in it. `meminfo` shows the fixed 4 GiB that `sysinfo` reports, with nothing
  used.
- **Roots of their own, in part**: `chroot` into the generated `/proc` or
  `/dev` (or a directory in them) gives `EINVAL`, where Linux makes it the
  root. `mount` mounts no `proc` filesystem and nothing on `/proc` or
  `/dev`, so the new root's `/proc` or `/dev` shows the generated files
  only through a bind mount of `/proc` or `/dev` (or a directory in them)
  made onto it before. In a path that climbs above the root as written,
  `..` is taken from the names as written, where Linux takes a `..` after a
  symbolic link from the link's target. `maps` and `smaps` in `/proc` name
  files from the root their opener had when it opened them, where Linux
  takes the root of whoever reads them, at each read.
  `fchroot`, new in Linux master, is not there (`ENOSYS`).
- **Links into `/dev` and `/proc`, in part**: a symbolic link elsewhere
  that leads into them is followed to the generated file by the calls
  that look a path up, but not by `execve` or by the calls that make or
  remove a name through it (`mkdir`, `mknod`, `unlink`, `rename` and the
  like), which give `ENOENT`, and under a root of its own no such link is
  followed.
- **Changing the generated files, in part**: a new mode or owner of
  `/dev`, its devices and links, `/proc` or `/proc`'s system-wide files, which only
  root may give these files of root's, is `EPERM`, where Linux keeps it;
  a pseudo-terminal's slave keeps its own. Times set on a generated file
  are not kept either: its `stat` shows the times it had.
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
    Multicast datagrams reach no one, nor do broadcast ones but through a
    veth end (below). A datagram is always
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
- **Pages `write` filled**: a page of a host file that `write` (or another
  system call) filled is clean at once, as the data goes straight to the
  file on the host, so a mapping of it counts it among the clean pages in
  `smaps`. On Linux it stays dirty in the page cache until writeback, and
  `smaps` counts it among the dirty ones until then.
- **Mappings that grow down**: such a mapping grows when the guest's own
  code touches a page below it or a signal frame is written there
  ([features](./features#system-calls)), but not when a system call reads or
  writes there: the call gives `EFAULT`, where Linux's copy of user memory
  grows it as a fault in the guest would. `RLIMIT_AS` does not stop the
  growth, as it does not stop `mmap`.
- **Page-fault counts**: `ru_minflt` counts each fault as it is taken, as
  Linux does, from a thread's first fault, before its first system call.
  `execve`'s loader fills the pages of the program's segments
  with its file's bytes and counts a fault for each page then, where Linux
  maps the file and counts the faults as the program first touches the
  pages, a read fault for several of them at once (`fault_around_bytes`);
  these faults are no `perf` event. No fault is major (`ru_majflt` is 0),
  as every page of a file is taken to be in the page cache. A core dump's faults count to the
  last thread to exit, where Linux counts them to the thread that dumps.
  `process_vm_readv`, `process_vm_writev`, `MADV_POPULATE_READ` and
  `MADV_POPULATE_WRITE` count their faults in `perf`'s `page-faults` too,
  where Linux's `get_user_pages` gives no `perf` event. `/proc/<pid>/stat`'s
  `minflt` and `cminflt` read the same counts, with the same limits.
- **perf events, in part**: only the software events count; cgroup
  switches, tracepoints, breakpoints, kprobes and uprobes are `ENOENT`, as
  are hardware events even on a host with a PMU. A thread's CPU time,
  context switches and CPU migrations are those it last accounted, at its
  latest system call; its page faults count as they are taken. An event of
  a CPU counts the time that passes, and no faults, switches or migrations.
  A fault that ends in `SIGSEGV` or `SIGBUS` is not counted, where Linux
  counts it in `page-faults`; a context switch is a sleep of the thread,
  not a preemption (but for a thread with `rseq` that gives its virtual CPU
  to another); and a thread without `rseq` moves to
  another CPU only when a new CPU mask changes the lowest CPU it allows.
  A sampling event's samples are taken as its thread enters a system call,
  or reaches the emulator's checkpoint, of what it did since then, where
  Linux takes each at its occurrence: they show the thread's address,
  registers, stack and frames as of then, a fault's address is 0, and one
  of the kernel (a fault in a system call, a switch or a migration) has the
  address 0 and no kernel frames. `freq` follows the rate at those points,
  not at each tick. A `cpu-clock` or `task-clock` event is throttled at
  `perf_event_max_sample_rate` over `HZ` (1000) interrupts in a tick, as
  Linux's hrtimer events are, the ticks being those of its own count, and
  is unthrottled at the next one, when it is enabled again or when its
  period is set: the `PERF_RECORD_UNTHROTTLE` of the latter two is written
  with its next samples, by the thread it counts. Only the throttled event
  stops, where Linux stops its whole group; the sample rate is not lowered
  for samples that take too long (`perf_sample_event_took`), which
  `perf_cpu_time_max_percent` sets the limit of; and no other event is
  throttled, as no other event here is an hrtimer's or the hardware's. An
  event of a CPU takes no samples, nor any side-band record. Of those, an `execve` writes the new program's mappings once it
  has loaded it, the stack's two first and the rest by address: the
  temporary stack's is placed at the top of 4-level user space with the
  length of the arguments' pages, where Linux gives where it was. Linux
  first writes a position-independent program's or interpreter's first
  segment as long as the whole image, before it trims it; a stack that
  grows down as the program touches it writes none; a mapping's inode
  generation is 0 and no build ID is given (`build_id`); `mprotect` writes
  one record of each VMA as it ends up, where Linux writes one each time it
  changes one, of the VMA as merged so far; a thread the host cannot
  start gets `FORK` and `EXIT` records, the latter on CPU 0, where Linux's
  failed `clone` writes neither; and `NAMESPACES`, `CGROUP`,
  `KSYMBOL`, `BPF_EVENT`, `TEXT_POKE`, `SWITCH` and `AUX` records are not
  written. With no vDSO, no record of one is written either. The overflows
  of one such point send one SIGTRAP for `sigtrap`, where Linux sends one
  each time the thread returns to its code, and its `si_addr` is 0, where
  Linux gives a fault's address. When `REFRESH`'s last overflow disables
  the event, the occurrences after it up to that point are still counted,
  where Linux stops the count at it. Its user page shows the count and times as of the
  `mmap`, the event's enabling and its reset, where Linux updates them
  each time the event is scheduled in, and `cap_user_time` is never set.
  Where Linux's checks of a mapping and of where it goes both fail, the
  mapping's are the error here. Until the memory manager knows Linux's
  rules for the mapping (`VM_PFNMAP`), a write to a data page lands, where
  Linux raises `SIGBUS`; a part of the mapping may be unmapped, moved or
  given another protection, where Linux refuses to split it (`EINVAL`); and
  `MADV_DOFORK` takes it into a child, where Linux refuses it on `VM_IO`
  (`EINVAL`); and `mlock` locks it, where Linux leaves a `VM_SPECIAL`
  mapping unlocked. `inherit_stat` is taken, but an
  inherited event's end sends no read record, as nothing is recorded. An
  event of a task on one CPU counts on any, and the cgroup mode
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
- **BPF, maps and socket filters on AF_UNIX sockets only**: `bpf` makes
  arrays, hashes, LRU hashes, longest-prefix-match tries, queues, stacks,
  bloom filters, and arrays and hashes of maps, and loads socket filters,
  and nothing else. A socket filter, attached with `SO_ATTACH_BPF` or a
  classic one with `SO_ATTACH_FILTER`, runs only on an AF_UNIX datagram
  or packet socket; on an internet socket the options are `ENOPROTOOPT`.
  No JIT compiles a program: the interpreter runs it. Of the helpers'
  values, the processor is 0, a network namespace's cookie is 1 (the
  initial one's) in every namespace, the boot and coarse clocks are the
  monotonic one, and `CLOCK_TAI` is the real time. A program is charged to
  its socket as though Linux's rewrites made it 16 times longer, so
  `SO_ATTACH_BPF` is `ENOMEM` sooner than on Linux for a long one; a
  classic filter is charged what Linux charges for it. A program's memory
  in fdinfo (`memlock`) is not yet what Linux's is for a long program:
  it counts the instructions as loaded, where Linux's rewrites (a
  division's, a context access's, `BPF_LD_ABS`'s and the rest) may make
  more of them and take another page (`bpf_prog_realloc`).
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
  a scalar it does not know is 0, bpf-to-bpf calls and kfuncs, the
  context's socket (`__sk_buff.sk`) and a map's own fields (`struct
  bpf_map`), maps from `fd_array` and maps made with `excl_prog_hash`,
  `BPF_LD_IMM64` of BTF IDs
  and of functions, `may_goto`, indirect
  jumps, a pointer with a variable offset, and
  `BPF_F_TEST_REG_INVARIANTS` with a conditional jump; and with
  Linux's line, a back-edge ("back-edge from insn %d to %d", where Linux
  takes a bounded loop from a privileged loader). A scalar is a value the
  verifier knows or nothing at all, where Linux keeps its bounds, so it
  walks both ways of a jump Linux knows goes one way, and it prunes no
  states, so a program with many branches may reach the limits sooner. A
  lookup's result may be null until a 64-bit `BPF_JEQ` or `BPF_JNE` with
  the immediate 0 tells, where Linux also knows that an array's element
  of a constant key is there and learns from comparing two pointers.
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
  smaller than Linux's. The other program commands (`BPF_PROG_TEST_RUN`
  and the rest), BTF (`BPF_BTF_LOAD`), links, attachment, pins
  (`BPF_OBJ_PIN`, `BPF_OBJ_GET`), the IDs of programs, BTF and links
  (`BPF_PROG_GET_NEXT_ID`, `BPF_PROG_GET_FD_BY_ID` and the rest), tokens,
  iterators and statistics are `ENOSYS`, as each command Linux has that is
  not here; a number Linux has no command for is `EINVAL`, as there. So
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
  start at 1 and do not see the host's maps. `BPF_F_MMAPABLE` is taken but `mmap` of a map
  is `ENODEV`, and a map's SHA-256 (`bpf_map_info.hash`) is `EINVAL`.
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
  `verr` and `verw`, and far jumps, calls and returns stop a program with
  `SIGILL`, and the CPU runs only in `__USER_CS`: an `rt_sigreturn` frame
  with another `cs` is a bad frame. `set_thread_area` is not implemented,
  so the GDT's thread-local entries stay empty, and the limit of the CPU
  number segment is 0. A `mov` or `pop` to `%ss` does not hold off the
  single-step trap of the instruction after it, as the CPU does. After
  `modify_ldt` only the calling thread's `%ds` and `%es` load again, where
  Linux reloads them in every thread of the address space. A null selector
  clears the `%fs` or `%gs` base, where AMD's CPUs before Zen 2 keep it.
- **io_uring, in part**: only `IORING_OP_NOP`, `IORING_OP_EPOLL_CTL`,
  `IORING_OP_READ`, `_WRITE`, `_READV`, `_WRITEV`, `_FSYNC`, `_READ_FIXED`,
  `_WRITE_FIXED`, `IORING_OP_FILES_UPDATE`, `IORING_OP_PROVIDE_BUFFERS` and
  `_REMOVE_BUFFERS` run; the other operations
  complete with `EOPNOTSUPP`.
  The setup flags
  `IORING_SETUP_IOPOLL`, `_SQPOLL`, `_SQ_AFF`, `_ATTACH_WQ`, `_R_DISABLED`,
  `_SQE128`, `_CQE32`, `_NO_MMAP` and `_REGISTERED_FD_ONLY` give `EINVAL`,
  and `io_uring_register` has only `IORING_REGISTER_PROBE`,
  `IORING_REGISTER_BUFFERS`, `IORING_UNREGISTER_BUFFERS`,
  `IORING_REGISTER_FILES`, `IORING_UNREGISTER_FILES`,
  `IORING_REGISTER_FILES_UPDATE`, `IORING_REGISTER_FILE_ALLOC_RANGE`,
  `IORING_REGISTER_FILES2`, `IORING_REGISTER_FILES_UPDATE2`,
  `IORING_REGISTER_PBUF_RING`, `IORING_UNREGISTER_PBUF_RING` and
  `IORING_REGISTER_PBUF_STATUS` (the others give `EINVAL`). So no ring descriptor or personality can be
  registered, buffers cannot be updated, and buffers cannot be registered
  with `IORING_REGISTER_BUFFERS2`, which gives them tags.
  `IORING_NOP_TW` completes a NOP as any other, where Linux posts it as
  task work after the other completions of its submission, and on an
  `IORING_SETUP_DEFER_TASKRUN` ring only once `io_uring_enter` waits.
  A request after the first of a link runs with the submission's others,
  where Linux runs it as task work once their completions are in, so a
  tag its update of the registered files posts comes before them. A registered buffer's pages
  are not pinned: a fixed transfer moves the memory at its address as that
  is mapped then, so it fails with `EFAULT` once the buffer is unmapped or
  made read-only, and a process that shares the ring moves its own memory.
  Linux moves the pages it pinned. A shared mapping of a disk file can be
  registered, where Linux's long-term pin refuses it (`EFAULT`), and a huge
  page charges RLIMIT_MEMLOCK for each of its 4 KiB pages, where Linux
  charges it once. A ring maps only shared (`MAP_PRIVATE` gives `EINVAL`), and
  `poll` and `epoll` cannot watch its descriptor. As every request completes
  in `io_uring_enter`, a wait for more completions than there are ends only
  by a signal or its timeout. The features are Linux 6.12's, so
  `IORING_FEAT_REG_REG_RING` is reported though no ring descriptor can be
  registered, and `IORING_FEAT_MIN_TIMEOUT` though a wait's `min_wait_usec`
  changes nothing (no request is ever in flight). A transfer that would
  wait for its file does not: Linux keeps it in flight until the file is
  ready (a pipe, a socket or an eventfd with nothing to read, or a full
  pipe, even with `O_NONBLOCK`), and the emulator completes it with
  `EAGAIN`. A
  terminal's read waits in `io_uring_enter`. A file that is never read
  (an epoll instance, a ring) fails with `EINVAL` at once, where Linux
  first waits for it to be ready. Such a read that selected a buffer
  completes with `EAGAIN` as one with `RWF_NOWAIT` would: a ring's buffer
  stays in the ring, and a provided buffer is used, where Linux keeps it for
  the read. A file without a position (a pipe, a socket, a terminal, an
  eventfd) is taken as one that can be polled, which decides when a read
  uses a ring's buffer. A ring of buffers in the program's memory is not
  pinned either: the kernel reads and writes it through its mapping at each
  use, so a read that finds it unmapped fails with `EFAULT`, where Linux uses
  the pages it pinned.
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
  - A fatal signal other than SIGKILL marks a process as dying for
    `process_mrelease` as it is sent even when the only thread that does
    not block it already has a signal pending and is not running, or is
    exiting. Linux's `wants_signal` passes over such a thread, so Linux
    marks the process only once one of its threads takes the signal.
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
    registered buffers, where Linux's `locked_vm` of a user also counts
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
    so they also count the time a thread sleeps or waits. They are looked
    at as a thread makes a system call and every 100,000 instructions it
    runs, not at each tick as on Linux, and a tick is taken as 1 ms, the
    CI runners' `CONFIG_HZ`. POSIX timers on the CPU-time clocks count
    and are looked at the same way, and so does a sleep on the process's
    CPU clock, which the sleeping thread looks at every tick; where that is
    wall time, the sleep counts its own time too, so a process alone ends
    it after the wall time it asked for.
    A timer on another process's CPU time is looked at as that process's
    threads make system calls, the same way, and so is a sleep on another
    task's CPU clock. Another process's CPU time,
    read or set from outside it, is each of its threads' as of that thread's
    last account (its last system call, while nothing timed that process),
    as a thread's CPU time can only be measured by the thread itself: a
    timer set on it counts from there, so its first expiry can come early
    by what the process ran since then without a system call, and
    `timer_gettime` can show more time left, where Linux samples the
    running threads at once.
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
    `sysfs` knows only seven file system types, where Linux has dozens, so
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
  - Yama's `ptrace_scope` is always 1: there is no
    `/proc/sys/kernel/yama/ptrace_scope` to read or change it.
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
    file, where Linux asks its page cache, and does not count a page that
    `MAP_POPULATE`, `MAP_LOCKED` or a memory lock read in (a mapping not both
    private and writable) until it is touched.
  - Adjacent private VMAs merge once their flags agree again (after
    `munlock`, for one), whatever their `anon_vma`s. Linux merges them only
    when they share one. A VMA gets its `anon_vma` on its first write, and
    takes a neighbour's only if their flags agreed then
    (`anon_vma_compatible`), so pieces written while apart may stay
    separate VMAs in `/proc/<pid>/maps`.
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
- **mount and umount2, in part**: `mount` makes only tmpfs and bind mounts;
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
  `/proc` and `/dev`, the table has only `/dev` itself and the tmpfs on
  `/dev/shm`, not `/proc`, `/dev/pts`, `/dev/mqueue` or
  `/proc/sys/fs/binfmt_misc`: a bind mount of `/proc` or `/dev` (or a
  directory in them) still shows what is generated in those directories,
  and what is in `/dev/shm`, where Linux shows their empty mount points,
  and with `MS_REC` takes no mount along. In a namespace of a less
  privileged owner a bind mount of `/dev` is `EINVAL`, as Linux refuses
  it for its locked `/dev/shm`, but one of `/proc` or `/dev/pts` is made,
  where Linux refuses it for its locked mounts below (`EINVAL`). Once
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
  `nr_blocks` and `nr_inodes`, but not for what a mapping writes (a write
  fault past the size is no `SIGBUS`, and the pages go back to the file
  whatever its size; nor are the pages a fault brings into a tmpfs file
  or a memfd counted in its blocks, which only `MADV_COLLAPSE` charges
  for the holes it fills), and its extended attributes take none of the inodes'
  room (`ENOSPC` from `setxattr` past it, as `shmem_xattr_handler_set`
  counts them, does not happen); the root from start-up has no limit but
  `fallocate`'s, the memory reported. Not enforced either are the atime
  flags, `sync`, `dirsync` and `mand`; no mount here holds a
  device node but a host directory's (`mknod` of one is `EPERM`), so
  `nodev` only refuses those;
  `huge`, `mpol`, `noswap` and the quota options are taken, checked as
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
  where the copy has their mounts. A move or a `pivot_root` takes the roots
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
  once, and `/proc` shows it after each one's next system call. `SIGIO` and
  `SIGURG` from `F_SETOWN` are not scoped, as `F_SETOWN` records no sender. A
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
  files but nowhere else yet. `F_SETOWN` records no sender's credentials, so
  `SIGIO` and `SIGURG` reach their owner whoever set it, where Linux's
  `sigio_perm` checks.
  The `PR_SET_PDEATHSIG` signal is sent when the parent process ends, with the
  IDs of its leader, where Linux sends it when the thread that made the child
  ends, with that thread's. Of the files, those under `/proc` and `/dev` are
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
  `/proc/self/status` shows the calling thread's credentials, where Linux
  shows the thread group leader's.
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
- **inotify, in part**: when a superblock goes, an instance's watches
  hear `IN_UNMOUNT` the newest watch first, where Linux takes the files the
  newest first that any instance began to watch, so the orders can differ
  when instances watch the same files. `/proc/self/fdinfo` lists an epoll's files by
  descriptor where Linux's order follows the files' addresses, and numbers
  eventfds within the emulator, where Linux's `eventfd-id` counts the whole
  system's. Changes the host makes to a mounted directory are not seen, and
  a descriptor's place does not follow them.
- **userfaultfd, in part**: missing pages, write protection and the minor
  faults of shmem are registered. A discard tells of all its ranges
  before it drops the pages of any, where Linux tells and drops VMA by VMA,
  and registered mappings of one `userfaultfd` that meet are one range of
  `UFFD_EVENT_REMOVE`, as when Linux's VMAs merge; `MADV_REMOVE` tells of
  its whole range once its first mapping passes the checks. A
  registration that replaces the write-protect mode with others ends the
  protection of the range's pages, whose marks Linux leaves in their PTEs.
  `MADV_GUARD_INSTALL` over a uffd-wp marker of shmem puts the guard in
  the marker's place, where Linux, whose zap keeps the marker, restarts
  the call until a signal comes.
  Of shmem's files only a memfd is registered, but for write protection
  alone with `UFFD_FEATURE_WP_ASYNC`, which takes any file: a tmpfs file
  is refused (`EINVAL`), where Linux takes it, as the in-memory file
  system says it is a tmpfs but stands for the files a guest has on disk,
  and a host's tmpfs file is not kept here. A zero page `UFFDIO_ZEROPAGE` gives a
  private mapping of a shmem file is a page of zeros of its own, which
  `/proc/<pid>/pagemap` and `smaps` count as such, where Linux maps its
  zero page. A system call's own
  copy to or from a missing page of a registered range, or to a
  write-protected one without `UFFD_FEATURE_WP_ASYNC`, is `EFAULT`, as with `UFFD_USER_MODE_ONLY`, where
  Linux waits for the page as for an instruction. A `UFFDIO_MOVE` source
  hole is `ENOENT` before the destination is looked at when nothing
  touched the 2 MiB around it here, as when Linux has no page table there,
  which Linux may also have freed or kept otherwise. There is no `/dev/userfaultfd` and no
  `/proc/sys/vm/unprivileged_userfaultfd`, which is taken as 0.
- **fanotify, in part**: `FAN_PRE_ACCESS` is `EOPNOTSUPP` (no file system here
  allows it), and `FAN_FS_ERROR` never comes. An evictable mark on a
  directory is never evicted, where Linux's goes once none of the
  directory's children's dentries is in use; one on a file Linux would
  still write back, or one a mount is on, goes all the same, and so does
  one on a file another thread is opening at that moment but has not yet
  opened, which Linux's path lookup keeps. Which events
  share a bucket of a group's merge hash follows a hash of the emulator's
  own where Linux's mixes in kernel addresses (of the process, and of a
  path in the non-FID modes), so only events of one task's names in one
  directory collide as on Linux. Whether a directory watches its children
  is judged by the
  fanotify marks alone, where Linux's counts inotify's too. A file a
  descriptor does not hold (a program exec runs) is opened again by the path
  it had, which fails once it is gone, and a FIFO's or device's read or
  write is told of without its directory and name.
- **Namespaces**: a user namespace has no `projid_map` and no
  `user.max_*` limits; its map files check a write with the credentials
  the file was opened with, where Linux also takes the writer's for the
  `CAP_SETUID` and `CAP_SETGID` it needs in the parent; and the `/proc` files
  of a process that is not dumpable belong to root of the first namespace,
  where Linux gives them to root of the process's own when it maps one. A network
  namespace has no interface but its loopback and the veth ends requests
  make. A veth end takes IPv4 addresses and routes, and TCP and UDP go
  across a pair to an address of the peer's namespace; it takes IPv6
  addresses, makes its link-local one and its routes, and takes IPv6
  routes a request adds without a gateway, and IPv6's TCP and UDP and its
  neighbours, but no proxy entry, no route through a gateway and no IPv6
  route lookup in through it (`RTA_IIF`), each `EOPNOTSUPP`. A link-local
  destination's scope ID is not taken: the first route to it is. A
  connect without one to it, or a UDP one to a group of the node or the
  link, is `EINVAL`, as Linux's is with no device bound and no multicast
  interface, which sockets here have none of. Neighbour discovery makes none of
  the neighbours of the groups router solicitation, MLD reports and
  duplicate address detection send to (`ff02::2`, `ff02::16`, the
  solicited-node ones), no advertisement unasked, and no redirect; the
  probe a delaying neighbour sends teaches the peer nothing, where
  Linux's, from the end's link-local address, makes it a neighbour of
  that address. Its duplicate address detection sends no probe, finds
  no duplicate and ends 1.5 seconds after it begins (half of
  `rtr_solicit_delay`, then a probe and a retransmit time), where Linux's
  ends 1 to 2 seconds on after a random delay; its link-local address is always made from its
  Ethernet address (EUI-64, `addr_gen_mode` 0), and IPv6 sends no router
  solicitation nor MLD report. Traffic through
  an end moves no counters; a namespace forwards nothing
  on to another; and a multicast destination through an end reaches no
  one, as no socket joins a group (`IP_ADD_MEMBERSHIP`, `IPV6_ADD_MEMBERSHIP`). ICMP's port unreachable is not rate limited
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
  possible CPU, no `IFLA_AF_SPEC`, and statistics of zero. The interface
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
  `route_localnet` to be as built, which have no files. `/proc/sys/net` has only `ip_forward` and
  the `forwarding`, `rp_filter` and `disable_ipv6` of `all`, `default`,
  `lo` and the veth ends, where Linux has many more; their first namespace's values are as
  Linux is built, not a host's, so a new namespace starts from those.
  IPv6's `forwarding` joins no router multicast or anycast address, and a
  write of `all`'s tells of the devices in the order of their indices,
  where Linux's goes in the order they came. A netconf notification gives
  the settings that have no file (proxy ARP and NDP, multicast and
  broadcast forwarding, ignoring routes with their link down) as 0, as
  Linux is built. A veth end whose MTU is below 1280 still has the files
  of `ipv6/conf/<device>`, where Linux's has none, as it has no IPv6
  (it makes no IPv6 address, as Linux's does not).
  A
  route goes through `lo`, a veth end (without a gateway) or rejects: IPv6 gateways, multipath routes,
  encapsulations, nexthop objects, realms, expiries, source prefixes, router preferences
  and the anycast, multicast and NAT kinds (and broadcast for IPv6) are
  `EOPNOTSUPP`, and so are policy rules (`RTM_NEWRULE`), so no lookup
  reaches a table but the local, main and default ones. In a new network
  namespace a connection or datagram to an address no local route has is
  still `ENETUNREACH`, whatever route takes it, where Linux's goes out
  through `lo` and is dropped, or fails with a rejecting route's error.
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
  lookup while `lo` is down is `ENETUNREACH` too. A route lookup's answer
  for a multicast address is local (`RTCF_LOCAL`) only for 224.0.0.1, the
  group `lo` is a member of while up, as no socket here joins a group,
  where Linux's is local for each group a socket joined on `lo` too. A
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
  `MCTP_ADDR_NULL`. A link message's
  statistics are zero; its IPv4 and IPv6 settings are those of a kernel
  whose sysctls are as built, where Linux's new namespace copies the
  host's, and IPv6's creation time is 0 and its reachable time 30
  seconds, where Linux's is random. The first namespace's `127.0.0.1`
  and `::1` were made at 0, where Linux's were made as it booted.
  With `NETLINK_EXT_ACK`, a request refused for a feature paludarium does
  not have (a multipath route, say, or a link of a kind) carries no
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
  mounts of a mount namespace: there is no `/proc/self/cgroup` for a cgroup
  namespace, and no
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
  before it asks for a session, and asks once more after either failure,
  never for a third time. It retries nothing else, no test and no result, and
  each retry is logged with its error and timing. These failures come and go,
  so a run that passes does not show they are gone.

## Found a problem?

When a CPU fault kills the guest, the command prints the signal, the address
and the instruction bytes. Run it again with `--report-enosys` to list the
system calls that returned `ENOSYS` ([Command line](./cli#finding-what-is-missing)).
Please include both in an
[issue](https://github.com/aletheia-works/paludarium/issues).
