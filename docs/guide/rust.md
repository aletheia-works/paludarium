# Rust library

The [`paludarium`](https://crates.io/crates/paludarium) crate runs a guest
program from Rust. It re-exports the types you need from the internal crates.

```sh
cargo add paludarium
```

## Run a program

```rust
use std::sync::Arc;
use paludarium::{Config, ExitStatus, NativeHost, Session};

fn main() -> Result<(), paludarium::Error> {
    let program = std::fs::read("hello").expect("read the guest program");
    let config = Config::new("/hello", vec![b"hello".to_vec()])
        .with_env("LANG", "C.UTF-8")
        .with_file("/hello", program);
    let session = Session::new(config, Arc::new(NativeHost::new()))?;
    match session.run()? {
        ExitStatus::Exited(code) => println!("exited with {code}"),
        ExitStatus::Signaled(signal) => println!("ended by signal {signal}"),
        other => println!("{other:?}"), // ExitStatus is #[non_exhaustive]
    }
    Ok(())
}
```

- `Config::new(program, args)` takes the absolute guest path of the program and
  `argv`, including `argv[0]`. Paths, arguments and environment entries are
  bytes, as on Linux.
- `with_file(path, bytes)` places a file in the guest's virtual filesystem
  before the start (mode `0755`); `with_file_mode` sets other permission bits.
  `with_env(key, value)` adds an environment variable.
- `Config` also has public fields: `program`, `args` and `env` (what `new`
  and `with_env` set), `files` and `file_modes` (what `with_file` and
  `with_file_mode` add, as path and content or mode pairs), `cwd` (the initial
  working directory as `Some(path)`; `None`, the default, is `/`), `mounts`
  (host directories, see below), `tty`
  (`Some(TerminalInfo::new(columns, rows))` gives the guest's standard streams
  a terminal of that size; `None`, the default, leaves the terminal to the
  `Host`), `jit` (used only by the WebAssembly build; the native build has no
  JIT) and `limits`.
- `limits` is a `Limits`, unlimited by default.
  `Limits::default().with_tasks(n)` lets the guest have at most `n` tasks
  (threads, and processes until they are reaped, as a cgroup's `pids.max`;
  `clone` and `fork` beyond it fail with `EAGAIN`). `with_open_files(n)`
  caps `RLIMIT_NOFILE` at `n`, as Linux's `fs.nr_open`, so opening more
  files fails with `EMFILE`. They set the fields `tasks` and `open_files`, where
  `None` is no limit. Memory has no limit yet.
- `Session::new` validates the configuration before anything runs, and
  `run()` runs the guest to the end. `NativeHost`, the native implementation
  of the `Host` trait, connects the guest's standard input and output to the
  host process.
- `ExitStatus::command_exit_code()` is the status a command reports: the exit
  code, or 128 + the signal number.

## Show a host directory

```rust
use paludarium::Mount;

let mut config = Config::new("/work/app", vec![b"app".to_vec()]);
config.mounts.push(Mount { host: "/srv/data".into(), guest: b"/work".to_vec() });
```

The guest sees only the directories you mount. Paths are resolved inside the
mounted directory, and neither `..` nor a symbolic link can lead outside it.

## Stop or signal a guest

`Session` can be shared with another thread:

- `kill()` asks the guest to stop. It ends with `SIGKILL` the next time the
  interpreter checks (every `DEFAULT_BUDGET` = 100,000 instructions).
- `signal(number)` sends a Linux signal to the guest process. It comes from
  outside the guest, so its `si_code` is `SI_USER` and its `si_pid` is 0, as
  for a sender outside a PID namespace.
- `is_stopped()` tells whether the guest is stopped by job control, such as
  by `SIGSTOP`.
- After a run, `unimplemented_syscalls()` lists, in ascending order, the system
  calls the guest called that returned `ENOSYS` (what the command's
  `--report-enosys` prints), and `termination_detail()` gives the CPU stop
  (an `ExitReason`) when a CPU fault ended the guest.

## Errors

`run()` returns `Ok(ExitStatus)` when the guest exits or is ended by a signal,
and `Err(Error)` only for problems of the emulator. `Error::kind` is one of:

| `ErrorKind` | Meaning |
|---|---|
| `Unimplemented` | the guest used something paludarium does not support yet |
| `Internal` | an internal inconsistency of the emulator |
| `InvalidProgram` | the program cannot be loaded |
| `Host` | the host failed (I/O error, no randomness, …) |

The error has a `message`, and keeps the instruction address (`rip`, a
`GuestAddr`), the instruction `bytes` and the system call number (`syscall`)
when they are known. System calls that paludarium does not
implement are not errors: the guest gets `ENOSYS`, as from an older kernel.
