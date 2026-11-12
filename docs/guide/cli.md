# Command line

The `paludarium` crate also builds a `paludarium` command that runs one static
x86-64 Linux program on the host.

```sh
cargo install paludarium
paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] [--jit[=N]] [--report-enosys]
           [--max-tasks N] [--max-open-files N] [--max-memory N]
           [--allow-net HOST[:PORT]]... <program> [args...]
```

- `<program>` is a file on the host, and `argv[0]` is the string you gave.
  When it lies inside a `--mount` host directory, the guest runs it from
  there, at the path the mount gives it, as Linux's `execve` of that path
  would: `/proc/self/exe`, `AT_EXECFN` and so the dynamic loader's `$ORIGIN`
  name it there (with `--mount /:/`, `/usr/bin/java` runs as
  `/usr/bin/java`). It counts as inside when its path, as written or with
  the symbolic links and `..` of its directory and of the host directory
  resolved, starts with the host directory, and only through the mount the
  guest sees that path through (the one with the deepest guest directory
  above it).
  Any other program is copied into the guest at `/<file name>`.
- A program that starts with `#!` is a script and runs its interpreter, as
  `execve` runs one ([System calls](./features#system-calls)). The interpreter is a
  guest path, so the script needs a `--mount` that shows it (`#!/bin/sh` with
  `--mount /:/`). On a Windows host the files of a mount have no execute
  bits (mode `0644`), so neither an interpreter nor any other program in a
  mount may be run from the guest (`EACCES`); only the program given on the
  command line starts.
- `--env KEY=VALUE` (or `--env=KEY=VALUE`) adds an environment variable.
  Repeat it for more.
- `--mount HOST:GUEST` (or `--mount=HOST:GUEST`) shows one host directory to
  the guest at the absolute guest path `GUEST`. Repeat it for more. The guest
  cannot leave the directory through `..` or symbolic links.
- `--jit` (or `--jit=N`) turns on the native JIT, which is experimental.
  A block of instructions that has run `N` times (100 without `=N`, at most
  65535) is compiled to host code with Cranelift on a thread of its own, and
  runs as host code once it is ready; the interpreter runs everything else
  ([Architecture](../design/architecture#the-native-jit)). Only Linux on
  x86-64 hosts has it: elsewhere `--jit` stops with an error. Without
  `--jit` the JIT is off.
- `--no-jit` turns the native JIT off, even with `--jit`.
- `--report-enosys` lists, after the run, the system calls the guest called
  that paludarium does not implement (they returned `ENOSYS`), by number.
- `--max-tasks N` lets the guest have at most `N` tasks (at least 1): threads,
  and processes until they are reaped, as a cgroup's `pids.max`. A `clone` or
  `fork` beyond it fails with `EAGAIN`.
- `--max-open-files N` caps `RLIMIT_NOFILE` at `N` (at most 1048576), as
  Linux's `fs.nr_open`: the guest starts with both limits at most `N` and
  cannot raise them above it (`EPERM`), so opening more files fails with
  `EMFILE`.
- `--max-memory N` lets the guest have at most `N` bytes of memory, as a
  cgroup's `memory.max`; `N` may end in `K`, `M`, `G` or `T` (powers of
  1024). A page counts from its first write until every process that has it
  unmaps it or ends, and shared memory counts once, as does a page that
  `fork` shares until a write copies it. A write beyond the limit ends the
  process that made it with `SIGKILL`, as the OOM killer does, and an
  `execve` that does not fit fails with `ENOMEM`. A program that
  does not fit at all is not started. File contents and pipe and socket
  buffers are not counted.
- Without these options there is no limit.
- `--allow-net HOST[:PORT]` (or `--allow-net=HOST[:PORT]`) lets the guest
  connect to `HOST` over TCP, on `PORT` or every port, and resolve its name.
  `HOST` is a name, `*.` and a name for its subdomains, an IPv4 address, or
  an IPv6 one in brackets (`[::1]:8080`). Repeat it for more. Without it the
  guest has no network ([Network](./features#network)).
- `-h`, `--help` print the usage line and exit with status 0.
- `--` ends the options, so a program name may start with `-`.

## Exit status

| Status | Meaning |
|---|---|
| the guest's exit status | the guest called `exit` or `exit_group` |
| 128 + signal number | the guest was ended by a signal |
| 2 | a usage error on the command line, or a program file that cannot be read |
| 70 | the guest could not be started, or an error of the emulator itself (`EX_SOFTWARE`) |

The guest cannot be started when, for example, the program is not an ELF file
paludarium can load nor a script whose interpreter is one, it does not fit in
`--max-memory`, or a `--mount` host directory cannot be opened. A
`paludarium:` line on standard error then names the kind of the error, such as
`invalid-program` or `host`.

## Finding what is missing

When a CPU fault kills the guest, a line on standard error says which signal
it was and where, as a shell reports a crash. The guest itself sees exactly
what it would see on Linux.

```text
paludarium: SIGILL: cannot run the instruction at 0x5555556e1189 (bytes 41 0f 18 0b 48 83 c0 04 41 0f 18 4b 40 8b 7a)
paludarium: SIGSEGV: read of an unmapped address 0x0 at 0x401000
```

The bytes begin with the instruction paludarium could not run; the rest is
what follows it in memory. A program that calls an unimplemented system call
gets `ENOSYS` and often carries on, so nothing is printed unless you ask with
`--report-enosys`:

```text
paludarium: unimplemented system calls (they returned ENOSYS): 101, 165, 298
```

The numbers are those of the x86-64 Linux system call table. An error of the
emulator itself is printed as `paludarium: <kind>: <message>`.
