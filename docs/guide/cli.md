# Command line

The `paludarium` crate also builds a `paludarium` command that runs one static
x86-64 Linux program on the host.

```sh
cargo install paludarium
paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] [--report-enosys]
           [--max-tasks N] [--max-open-files N] <program> [args...]
```

- `<program>` is a file on the host. Inside the guest it is placed at
  `/<file name>`, and `argv[0]` is the string you gave.
- `--env KEY=VALUE` adds an environment variable. Repeat it for more.
- `--mount HOST:GUEST` shows one host directory to the guest at the absolute
  guest path `GUEST`. Repeat it for more. The guest cannot leave the directory
  through `..` or symbolic links.
- `--no-jit` is accepted for compatibility; the native build has no JIT.
- `--report-enosys` lists, after the run, the system calls the guest called
  that paludarium does not implement (they returned `ENOSYS`), by number.
- `--max-tasks N` lets the guest have at most `N` tasks (at least 1): threads,
  and processes until they are reaped, as a cgroup's `pids.max`. A `clone` or
  `fork` beyond it fails with `EAGAIN`.
- `--max-open-files N` caps `RLIMIT_NOFILE` at `N` (at most 1048576), as
  Linux's `fs.nr_open`: the guest starts with both limits at most `N` and
  cannot raise them above it (`EPERM`), so opening more files fails with
  `EMFILE`. Without these options there is no limit.
- `--` ends the options, so a program name may start with `-`.

## Exit status

| Status | Meaning |
|---|---|
| the guest's exit status | the guest called `exit` or `exit_group` |
| 128 + signal number | the guest was ended by a signal |
| 2 | a usage error on the command line |
| 70 | an error of the emulator itself (`EX_SOFTWARE`) |

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
paludarium: unimplemented system calls (they returned ENOSYS): 28, 63, 204
```

The numbers are those of the x86-64 Linux system call table. An error of the
emulator itself is printed as `paludarium: <kind>: <message>`.
