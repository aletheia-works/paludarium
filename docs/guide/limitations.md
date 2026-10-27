# Limitations

paludarium is a young project. These things are not possible yet, or not
verified.

## Not supported

- **Dynamically linked programs**: only statically linked programs run.
- **32-bit x86, AVX, AVX-512, x87, MMX**: out of scope.
- **Network**: `socket()` always returns `EAFNOSUPPORT`; only AF_UNIX
  `socketpair` (`SOCK_STREAM`, `SOCK_SEQPACKET` or `SOCK_DGRAM`) is
  available.
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
- **`MADV_DONTNEED` on a read-only ELF segment**: the program's writable
  segments read the executable again, as on Linux, but a read-only one (its
  code) keeps its contents. It differs only if `mprotect` made it writable
  and it was changed, where Linux reads it from the executable again.
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature.
- **File owners**: a file in a mounted host directory stays root's, so
  `chown` to any other owner or group returns `EPERM` there. The guest stays
  root when it runs a set-user-ID or set-group-ID program, where Linux would
  take the file's owner or group.
- **Socket messages**: `sendmsg` and `recvmsg` pass descriptors with
  `SCM_RIGHTS` as Linux does, with these differences:
  - `sendmsg` and `sendto` take only the flags `MSG_NOSIGNAL` and
    `MSG_DONTWAIT`, and `recvmsg` and `recvfrom` only `MSG_DONTWAIT` and
    `MSG_CMSG_CLOEXEC`; others return `EOPNOTSUPP`.
  - `SCM_CREDENTIALS` returns `EINVAL`, and nothing can turn on
    `SO_PASSCRED`.
  - Linux splits a stream write of more than about 32 KiB into parts and
    passes its descriptors with the first part, so a read ends at the end of
    that part. Here it ends at the end of the whole write.
  - A socket whose descriptor waits unread in a socket that only that
    descriptor keeps open, such as its own, stays open: Linux's garbage
    collector would close both.
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
  hosts both come from the host.
- **Standard input on Windows**: `poll`, `select` and `epoll` see the host's
  standard input as always readable, as the Windows host cannot tell whether
  input is waiting; on Linux and macOS hosts and in WebAssembly it is
  readable only with input or at its end.
- **Core files**: a core is written as with the kernel's default
  `core_pattern` (`core` in the working directory); a host that pipes cores to
  a crash handler (systemd-coredump, apport) is not modelled. The core holds
  the registers, the fatal signal, the auxiliary vector and the memory, but
  not every note Linux writes (`NT_FILE`, `NT_X86_XSTATE`), and it holds every
  anonymous mapping, where Linux leaves out one never written.
- **Memory limit**: `fork` copies the private pages at once, where Linux
  shares them until one side writes, so under a memory limit a `fork` fails
  with `ENOMEM` when the copies do not fit, where Linux would succeed. A write
  beyond the limit ends the process that made it, where Linux's OOM killer
  picks the process using the most memory.
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
