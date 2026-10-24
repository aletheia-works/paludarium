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
- **`MADV_DONTNEED` on ELF segments**: a private file mapping reads its file
  again, as on Linux, but the program's own data segments keep their
  contents, where Linux reads them from the executable again.
- **Some system calls**: unimplemented system calls return `ENOSYS`, so some
  programs can carry on without the feature.
- **Some signal details**: no core file is written, so a child killed by `SIGSEGV`,
  `SIGABRT` or another core-dumping signal is reported as `CLD_KILLED`,
  without the core flag in its `wait` status, where Linux may report
  `CLD_DUMPED`.
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
- There are no limits yet on memory or threads, and open files are bounded
  only by the guest's own `RLIMIT_NOFILE`, which it may raise to its hard
  limit. An untrusted program could use up the host's resources.
- Automated Safari tests sometimes timed out while waiting for the browser to
  start. A fix passed ten times in a row, which does not guarantee it never
  happens again.

## Found a problem?

When a CPU fault kills the guest, the command prints the signal, the address
and the instruction bytes. Run it again with `--report-enosys` to list the
system calls that returned `ENOSYS` ([Command line](./cli#finding-what-is-missing)).
Please include both in an
[issue](https://github.com/aletheia-works/paludarium/issues).
