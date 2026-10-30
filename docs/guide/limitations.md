# Limitations

paludarium is a young project. These things are not possible yet, or not
verified.

## Not supported

- **Dynamically linked programs**: only statically linked programs run.
- **32-bit x86, AVX, AVX-512, x87, MMX**: out of scope.
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
  - On the loopback, a nonzero `SO_LINGER` time never holds `close`, as the
    bytes are delivered at once.
  - A UDP socket reaches the DNS stub and the guest's own sockets on the
    loopback; a datagram to any other address is `ENETUNREACH`. One
    connected elsewhere takes its port on every address, as the guest has
    no address of its own there, where Linux takes it on the route's source
    address: `getsockname` gives the unspecified address, and a `bind` of
    that port on a loopback address is `EADDRINUSE`, where Linux allows it.
    Multicast and broadcast datagrams reach no one. Raw sockets are `EPERM`,
    ICMP sockets `EACCES`, and other kinds (SCTP's `SOCK_SEQPACKET`, which
    Linux loads a module for) `ESOCKTNOSUPPORT`.
  - `socket(AF_UNIX)` is `EAFNOSUPPORT` as before, and `connect` and `bind`
    on a socket pair are `ENOSYS`.
  - The DNS stub answers only `A` and `AAAA`, and ignores EDNS, so a
    datagram answer holds at most 512 bytes; a name the host cannot resolve
    is `SERVFAIL`. A TCP connection to port 53 always reaches the stub, never
    a real DNS server.
  - Before a connection through the host is open, `getsockname` gives the
    address the socket is bound to, or the unspecified one with port 0,
    where Linux gives the port it took; a port the socket bound does not
    reach the host, whose connection leaves from a port of its own. `SIOCOUTQ` counts what the
    host has not yet taken to send, not what the peer has not acknowledged.
    `SO_SNDBUF` and `SO_RCVBUF` are kept for `getsockopt` but do not size the
    buffers, which hold 256 KiB each way; the other options but
    `TCP_NODELAY` do not reach the host's socket.
  - Through the host, `MSG_OOB` sends its byte as an ordinary one and finds
    no urgent data (`EINVAL`), so no `SIGURG` comes either.
  - On the loopback, an urgent byte sent while the peer's buffer is full
    sends `SIGURG` once, when it reaches the peer; Linux can send more, as
    a later segment that carries the urgent pointer signals again once the
    byte has been read or passed over.
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
- **File owners**: a file in a mounted host directory stays root's, so
  `chown` to any other owner or group returns `EPERM` there. The guest stays
  root when it runs a set-user-ID or set-group-ID program, where Linux would
  take the file's owner or group.
- **Socket messages**: `sendmsg` and `recvmsg` pass descriptors with
  `SCM_RIGHTS` and credentials with `SCM_CREDENTIALS` as Linux does, with
  these differences:
  - The guest is root, so `SCM_CREDENTIALS` may name any process, user and
    group, where Linux lets an unprivileged process send only its own.
  - The sockets only unread messages hold are closed at once when another
    socket goes, where Linux's garbage collector closes them a little
    later, from a work queue.
- **Socket options**: `setsockopt` refuses, with `ENOPROTOOPT`, the options
  whose effect is not modelled, where Linux takes them: `SO_PASSSEC` and
  `SO_TIMESTAMPING`, as well as filters and the other options Linux has. `SO_RCVTIMEO` and `SO_SNDTIMEO`
  round to a 1000 Hz tick, where Linux rounds to its own `CONFIG_HZ`.
  `SO_SNDBUF` and `SO_RCVBUF` are reported but leave the pair's buffer as it
  is. The buffer counts only the bytes in it, where Linux also counts each
  message's or part's overhead, so more small messages fit before a send
  finds it full, and `SIOCOUTQ` counts only the bytes the peer has not
  read. The guest is root, so the options that need `CAP_NET_ADMIN`
  (`SO_DEBUG`, `SO_SNDBUFFORCE`, …) are set, and `SO_PEERCRED` names uid and
  gid 0.
- **Signal-driven I/O**: `O_ASYNC` works on pipes and sockets only, so
  standard input and terminals never send `SIGIO`, and `FIOASYNC` setting
  it on them is `ENOTTY`, where Linux's do.
- **Namespaces**: `clone` and `clone3` with a namespace flag
  (`CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`,
  `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWCGROUP`, or `CLONE_NEWTIME` for
  `clone3`) fail with `EINVAL` and create no child, where Linux lets the
  guest, which runs as root, create the namespace. `unshare` and `setns`
  return `ENOSYS`.
- **Files of a mounted host directory on hosts other than Linux and macOS**:
  `lseek` with `SEEK_DATA` or `SEEK_HOLE` treats the whole file as data,
  where Linux finds the holes. On Windows `st_blocks` is also the size
  rounded up to 512-byte blocks, where Linux counts what the host's
  filesystem allocated; other Unix hosts give their own. On Linux and macOS
  hosts both come from the host. `FIOQSIZE` gives `st_blocks` in bytes on
  every host, where Linux gives what the filesystem has allocated so far,
  which some (ext4 with delayed allocation, overlayfs) count later than
  `st_blocks`.
- **Block size**: `st_blksize`, `stx_blksize` and `FIGETBSZ` are 4096 for
  every file, where Linux gives the block size of the file's filesystem:
  1024 for `/proc` and terminals (devpts), and the host filesystem's for a
  mounted directory (4096 for most), whose `statfs` here does report the
  host's. `FIGETBSZ` on a filesystem without a block size, such as
  overlayfs in most containers, is `EINVAL` on Linux. Pipes, sockets,
  `memfd` and other in-memory files are 4096 on Linux too.
- **Standard input on Windows**: `poll`, `select` and `epoll` see the host's
  standard input as always readable, as the Windows host cannot tell whether
  input is waiting; on Linux and macOS hosts and in WebAssembly it is
  readable only with input or at its end.
- **`FIONREAD` and `SIOCOUTQ` on the host's standard streams**: both return
  `ENOTTY`, where Linux answers for what is behind them: `FIONREAD` for a
  pipe, terminal, socket or regular file, `SIOCOUTQ` for a terminal or
  socket. A guest's own pipes, sockets and regular files are counted as on
  Linux.
- **Core files**: a core is written as with the kernel's default
  `core_pattern` (`core` in the working directory); a host that pipes cores to
  a crash handler (systemd-coredump, apport) is not modelled. The core holds
  the registers, the fatal signal, the auxiliary vector and the memory, but
  not every note Linux writes (`NT_FILE`, `NT_X86_XSTATE`), and it holds every
  anonymous mapping, where Linux leaves out one never written.
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
