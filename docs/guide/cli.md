# Command line

The `paludarium` crate also builds a `paludarium` command that runs one static
x86-64 Linux program on the host.

```sh
cargo install paludarium
paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] <program> [args...]
```

- `<program>` is a file on the host. Inside the guest it is placed at
  `/<file name>`, and `argv[0]` is the string you gave.
- `--env KEY=VALUE` adds an environment variable. Repeat it for more.
- `--mount HOST:GUEST` shows one host directory to the guest at the absolute
  guest path `GUEST`. Repeat it for more. The guest cannot leave the directory
  through `..` or symbolic links.
- `--no-jit` is accepted for compatibility; the native build has no JIT.
- `--` ends the options, so a program name may start with `-`.

## Exit status

| Status | Meaning |
|---|---|
| the guest's exit status | the guest called `exit` or `exit_group` |
| 128 + signal number | the guest was ended by a signal |
| 2 | a usage error on the command line |
| 70 | an error of the emulator itself (`EX_SOFTWARE`) |

When the emulator stops on an error, it prints the instruction address, the
instruction bytes or the system call number it stopped at, so that the missing
piece can be found.
