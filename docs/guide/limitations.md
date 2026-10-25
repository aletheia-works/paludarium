# Limitations

paludarium is a young project. These things are not possible yet, or not
verified.

## Not supported

- **Dynamically linked programs**: only statically linked programs run.
- **32-bit x86, AVX, AVX-512, x87, MMX**: out of scope.
- **Network**: `socket()` always returns `EAFNOSUPPORT`; only AF_UNIX
  `socketpair` (`SOCK_STREAM`, `SOCK_SEQPACKET` or `SOCK_DGRAM`) is
  available.
- **Writable shared file mappings**: `mmap` copies a file in when the
  mapping is made. A `MAP_PRIVATE` mapping behaves as on Linux, and so does a
  read-only `MAP_SHARED` one until the file changes, which the mapping does not
  see. `MAP_SHARED` with `PROT_WRITE` returns `ENODEV`, and `mprotect` cannot
  make a shared file mapping writable (`EACCES`), as nothing would write it
  back to the file. A page wholly past the end of the file reads as zeros
  instead of raising `SIGBUS`, also after `MADV_DONTNEED`.
- **`MADV_DONTNEED` on a read-only ELF segment**: the program's writable
  segments read the executable again, as on Linux, but a read-only one (its
  code) keeps its contents. It differs only if `mprotect` made it writable
  and it was changed, where Linux reads it from the executable again.
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature. Among them are `sendmsg` and
  `recvmsg`, so descriptors cannot be passed over a socket (`SCM_RIGHTS`),
  and `chown`, `fchown`, `lchown` and `fchownat`: every file belongs to root
  (user and group 0).
- **Namespaces**: `clone` and `clone3` with a namespace flag
  (`CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`,
  `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWCGROUP`, or `CLONE_NEWTIME` for
  `clone3`) fail with `EINVAL` and create no child, where Linux lets the
  guest, which runs as root, create the namespace. `unshare` and `setns`
  return `ENOSYS`.
- **Sparse files**: a file of the in-memory filesystem has no holes, so
  growing it with `ftruncate` or `fallocate` takes as much host memory as its
  new size.
- **Core files**: a core is written as with the kernel's default
  `core_pattern` (`core` in the working directory); a host that pipes cores to
  a crash handler (systemd-coredump, apport) is not modelled. The core holds
  the registers, the fatal signal, the auxiliary vector and the memory, but
  not every note Linux writes (`NT_FILE`, `NT_X86_XSTATE`), and it holds every
  anonymous mapping, where Linux leaves out one never written.
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
- Memory has no limit yet, so an untrusted program could use up the host's
  memory. Tasks (threads and processes) and open files are unlimited unless
  the embedder sets limits ([command line](./cli), [Rust](./rust),
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
