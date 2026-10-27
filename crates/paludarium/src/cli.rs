//! The `paludarium` command:
//!
//! ```text
//! paludarium [options] <program> [args...]
//!   --env KEY=VALUE   add a guest environment variable (repeatable)
//!   --no-jit          accepted; the native build has no JIT
//!   --mount HOST:GUEST expose one explicit host directory (repeatable)
//!   --report-enosys   list the unimplemented system calls the guest called
//!   --max-tasks N     at most N threads and unreaped processes (EAGAIN)
//!   --max-open-files N  cap RLIMIT_NOFILE at N, as fs.nr_open (EMFILE)
//!   --max-memory N[K|M|G|T]  at most N bytes of guest memory, as memory.max
//! ```
//!
//! Exit codes: the guest's exit code; 128 + signal number when the guest was
//! killed by a signal; 2 for usage errors and an unreadable program file; 70
//! for a program that cannot be started and for errors of the emulator itself.
//!
//! When a CPU fault (an instruction paludarium cannot run, a bad memory
//! access, a divide error) kills the guest, a `paludarium:` line on standard
//! error says where, as a shell reports a crash; the guest itself sees exactly
//! what it would see on Linux.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use paludarium_host::{Host, read_program_file};
use paludarium_runtime::{Config, Limits, Mount, Session};
use paludarium_types::{Error, ExitReason, ExitStatus};

/// Exit code for command-line usage errors.
pub const EXIT_USAGE: i32 = 2;

/// Exit code for a program that cannot be started and for errors of the
/// emulator itself (70 = `EX_SOFTWARE`).
pub const EXIT_EMULATOR_ERROR: i32 = 70;

/// Usage text printed on errors and for `--help`.
pub const USAGE: &str = "usage: paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] [--report-enosys] [--max-tasks N] [--max-open-files N] [--max-memory N] <program> [args...]\n";

/// A parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The program as given on the command line (host path; also `argv[0]`).
    pub program: OsString,
    /// Arguments after the program.
    pub args: Vec<OsString>,
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
    pub no_jit: bool,
    pub mounts: Vec<Mount>,
    /// List the unimplemented system calls the guest called, after the run.
    pub report_enosys: bool,
    /// `--max-tasks`, `--max-open-files` and `--max-memory`; unlimited
    /// without them.
    pub limits: Limits,
}

/// What the command line asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run(Invocation),
    Help,
}

/// A usage error with a fixed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageError(pub &'static str);

fn parse_env(value: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UsageError> {
    let eq = value
        .iter()
        .position(|&b| b == b'=')
        .ok_or(UsageError("--env needs KEY=VALUE"))?;
    if eq == 0 {
        return Err(UsageError("--env needs a non-empty KEY"));
    }
    Ok((value[..eq].to_vec(), value[eq + 1..].to_vec()))
}

fn parse_mount(value: &OsStr, prefix: usize) -> Result<Mount, UsageError> {
    let bytes = &value.as_encoded_bytes()[prefix..];
    // The final separator preserves a Windows drive letter in HOST.
    let colon = bytes
        .iter()
        .rposition(|b| *b == b':')
        .ok_or(UsageError("--mount needs HOST:GUEST"))?;
    let guest = &bytes[colon + 1..];
    if colon == 0 || guest.first() != Some(&b'/') || bytes.contains(&0) {
        return Err(UsageError(
            "--mount needs a host directory and absolute guest path",
        ));
    }
    #[cfg(unix)]
    let host = {
        use std::os::unix::ffi::OsStrExt;
        std::path::PathBuf::from(OsStr::from_bytes(&bytes[..colon]))
    };
    #[cfg(not(unix))]
    let host = std::path::PathBuf::from(
        &value
            .to_str()
            .ok_or(UsageError("--mount host path is not valid Unicode"))?[prefix..prefix + colon],
    );
    Ok(Mount {
        host,
        guest: guest.to_vec(),
    })
}

fn parse_limit(
    value: Option<OsString>,
    range: std::ops::RangeInclusive<u64>,
    error: &'static str,
) -> Result<u64, UsageError> {
    value
        .and_then(|value| value.to_str()?.parse::<u64>().ok())
        .filter(|max| range.contains(max))
        .ok_or(UsageError(error))
}

/// A size in bytes with an optional binary suffix (`K`, `M`, `G`, `T`), as
/// a cgroup's `memory.max` reads it.
fn parse_size(value: Option<OsString>, error: &'static str) -> Result<u64, UsageError> {
    let value = value.ok_or(UsageError(error))?;
    let value = value.to_str().ok_or(UsageError(error))?;
    let (digits, shift) = match value.as_bytes().last() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 10),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 20),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 30),
        Some(b'T' | b't') => (&value[..value.len() - 1], 40),
        _ => (value, 0),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(1 << shift))
        .ok_or(UsageError(error))
}

/// Parses the arguments after the command name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut args = args.into_iter();
    let mut env = Vec::new();
    let mut no_jit = false;
    let mut mounts = Vec::new();
    let mut report_enosys = false;
    let mut limits = Limits::default();
    let program = loop {
        let Some(arg) = args.next() else {
            return Err(UsageError("no program given"));
        };
        let bytes = arg.as_encoded_bytes();
        match bytes {
            b"--" => break args.next().ok_or(UsageError("no program given"))?,
            b"-h" | b"--help" => return Ok(Command::Help),
            b"--no-jit" => no_jit = true,
            b"--report-enosys" => report_enosys = true,
            b"--max-tasks" => {
                let max = parse_limit(
                    args.next(),
                    1..=u64::MAX,
                    "--max-tasks needs a number of at least 1",
                )?;
                limits = limits.with_tasks(max);
            }
            b"--max-open-files" => {
                let max = parse_limit(
                    args.next(),
                    0..=1 << 20,
                    "--max-open-files needs a number up to 1048576",
                )?;
                limits = limits.with_open_files(max);
            }
            b"--max-memory" => {
                let max = parse_size(args.next(), "--max-memory needs a size in bytes")?;
                limits = limits.with_memory(max);
            }
            b"--env" => {
                let value = args.next().ok_or(UsageError("--env needs KEY=VALUE"))?;
                env.push(parse_env(value.as_encoded_bytes())?);
            }
            b"--mount" => {
                let value = args.next().ok_or(UsageError("--mount needs HOST:GUEST"))?;
                mounts.push(parse_mount(&value, 0)?);
            }
            _ if bytes.starts_with(b"--mount=") => {
                mounts.push(parse_mount(&arg, 8)?);
            }
            _ if bytes.starts_with(b"--env=") => env.push(parse_env(&bytes[6..])?),
            _ if bytes.starts_with(b"-") && bytes.len() > 1 => {
                return Err(UsageError("unknown option"));
            }
            _ => break arg,
        }
    };
    Ok(Command::Run(Invocation {
        program,
        args: args.collect(),
        env,
        no_jit,
        mounts,
        report_enosys,
        limits,
    }))
}

/// The guest path a host program is placed at: `/<file name>`.
pub fn guest_path(program: &Path) -> Result<Vec<u8>, UsageError> {
    let name = program
        .file_name()
        .ok_or(UsageError("the program must name a file"))?;
    let mut path = b"/".to_vec();
    path.extend_from_slice(name.as_encoded_bytes());
    Ok(path)
}

fn signal_name(number: i32) -> String {
    match number {
        4 => "SIGILL".into(),
        7 => "SIGBUS".into(),
        8 => "SIGFPE".into(),
        11 => "SIGSEGV".into(),
        n => format!("signal {n}"),
    }
}

/// What a CPU stop that killed the guest was, for the `paludarium:` line.
#[must_use]
pub fn describe_stop(reason: &ExitReason) -> Option<String> {
    Some(match *reason {
        ExitReason::InvalidOpcode { rip, bytes } => format!(
            "cannot run the instruction at {:#x} (bytes {})",
            rip.0,
            bytes
                .as_slice()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        ExitReason::PageFault {
            rip,
            addr,
            write,
            fetch,
            mapped,
            ..
        } => format!(
            "{} {} address {:#x} at {:#x}",
            if fetch {
                "instruction fetch from"
            } else if write {
                "write to"
            } else {
                "read of"
            },
            if mapped { "a protected" } else { "an unmapped" },
            addr.0,
            rip.0
        ),
        ExitReason::BusError {
            rip,
            addr,
            write,
            fetch,
            ..
        } => format!(
            "{} address {:#x}, past the end of its mapped file, at {:#x}",
            if fetch {
                "instruction fetch from"
            } else if write {
                "write to"
            } else {
                "read of"
            },
            addr.0,
            rip.0
        ),
        ExitReason::Halt { rip } => format!("privileged instruction at {:#x}", rip.0),
        ExitReason::GeneralProtection { rip } => {
            format!("general-protection fault at {:#x}", rip.0)
        }
        ExitReason::ArithmeticFault { rip } => format!("divide error at {:#x}", rip.0),
        ExitReason::FloatingPointFault { rip, .. } => {
            format!("SIMD floating-point exception at {:#x}", rip.0)
        }
        _ => return None,
    })
}

/// The command's exit code for a run result.
#[must_use]
pub fn exit_code(result: &Result<ExitStatus, Error>) -> i32 {
    match result {
        Ok(status) => status.command_exit_code(),
        Err(_) => EXIT_EMULATOR_ERROR,
    }
}

fn usage_error(stderr: &mut dyn Write, e: UsageError) -> i32 {
    // Diagnostics are best effort: a closed stderr must not change the code.
    let _ = write!(stderr, "paludarium: {}\n{USAGE}", e.0);
    EXIT_USAGE
}

/// Runs the command with `args` (without the command name).
pub fn main_with(
    args: impl IntoIterator<Item = OsString>,
    host: Arc<dyn Host>,
    stderr: &mut dyn Write,
) -> i32 {
    let invocation = match parse(args) {
        Ok(Command::Run(i)) => i,
        Ok(Command::Help) => {
            let _ = host.write_stdout(USAGE.as_bytes());
            return 0;
        }
        Err(e) => return usage_error(stderr, e),
    };
    let program_path = Path::new(&invocation.program);
    let guest = match guest_path(program_path) {
        Ok(p) => p,
        Err(e) => return usage_error(stderr, e),
    };
    let Ok(content) = read_program_file(program_path) else {
        return usage_error(stderr, UsageError("cannot read the program file"));
    };
    let mut argv = vec![invocation.program.as_encoded_bytes().to_vec()];
    argv.extend(
        invocation
            .args
            .iter()
            .map(|a| a.as_encoded_bytes().to_vec()),
    );
    let mut config = Config::new(guest.clone(), argv).with_file(guest, content);
    config.env = invocation.env;
    config.mounts = invocation.mounts;
    config.limits = invocation.limits;
    // --no-jit is accepted and has no effect: the native build has no JIT.
    config.jit = false;
    let session = match Session::new(config, host) {
        Ok(session) => session,
        Err(e) => {
            let _ = writeln!(stderr, "paludarium: {e}");
            return EXIT_EMULATOR_ERROR;
        }
    };
    let result = session.run();
    match &result {
        Err(e) => {
            let _ = writeln!(stderr, "paludarium: {e}");
        }
        Ok(ExitStatus::Signaled(number)) => {
            if let Some(detail) = session
                .termination_detail()
                .as_ref()
                .and_then(describe_stop)
            {
                let _ = writeln!(stderr, "paludarium: {}: {detail}", signal_name(*number));
            }
        }
        Ok(_) => {}
    }
    if invocation.report_enosys {
        let numbers = session.unimplemented_syscalls();
        if !numbers.is_empty() {
            let list: Vec<String> = numbers.iter().map(u64::to_string).collect();
            let _ = writeln!(
                stderr,
                "paludarium: unimplemented system calls (they returned ENOSYS): {}",
                list.join(", ")
            );
        }
    }
    exit_code(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_host::testing::RecordingHost;
    use paludarium_types::ErrorKind;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn run(args: &[&str]) -> (i32, String) {
        let mut err = Vec::new();
        let code = main_with(os(args), Arc::new(RecordingHost::new()), &mut err);
        (code, String::from_utf8(err).unwrap())
    }

    #[test]
    fn parses_options_program_and_guest_arguments() {
        let parsed = parse(os(&[
            "--env",
            "A=1",
            "--no-jit",
            "--env=B=x=y",
            "./hello",
            "-v",
            "--env",
        ]));
        assert_eq!(
            parsed,
            Ok(Command::Run(Invocation {
                program: "./hello".into(),
                args: os(&["-v", "--env"]),
                env: vec![
                    (b"A".to_vec(), b"1".to_vec()),
                    (b"B".to_vec(), b"x=y".to_vec())
                ],
                no_jit: true,
                mounts: vec![],
                report_enosys: false,
                limits: Limits::default(),
            }))
        );
        assert!(matches!(
            parse(os(&["--max-tasks", "8", "--max-open-files", "0", "p"])),
            Ok(Command::Run(i)) if i.limits == Limits::default().with_tasks(8).with_open_files(0)
        ));
        for (size, bytes) in [
            ("4096", 4096),
            ("0", 0),
            ("64K", 64 << 10),
            ("3m", 3 << 20),
            ("2G", 2 << 30),
            ("1T", 1 << 40),
        ] {
            assert!(matches!(
                parse(os(&["--max-memory", size, "p"])),
                Ok(Command::Run(i)) if i.limits == Limits::default().with_memory(bytes)
            ));
        }
        assert!(matches!(parse(os(&["--", "-dash"])), Ok(Command::Run(i)) if i.program == "-dash"));
        assert_eq!(parse(os(&["--help"])), Ok(Command::Help));
    }

    #[test]
    fn usage_errors_exit_with_two() {
        for args in [
            &[][..],
            &["--mount", "a:b", "x"],
            &["--mount=a:b", "x"],
            &["--bogus", "x"],
            &["--env", "NOEQUALS", "x"],
            &["--env", "=v", "x"],
            &["--env"],
            &["--"],
            &["--max-tasks", "0", "x"],
            &["--max-tasks", "many", "x"],
            &["--max-tasks"],
            &["--max-open-files", "1048577", "x"],
            &["--max-memory", "x"],
            &["--max-memory", "1.5G", "x"],
            &["--max-memory", "G", "x"],
            &["--max-memory", "-1", "x"],
            &["--max-memory", "16777216T", "x"],
            &["--max-memory"],
        ] {
            let (code, err) = run(args);
            assert_eq!(code, EXIT_USAGE, "{args:?}");
            assert!(err.contains("usage: paludarium"), "{args:?}");
        }
    }

    #[test]
    fn unreadable_program_is_a_usage_error_without_the_path() {
        let (code, err) = run(&["/definitely/not/here/prog-xyz"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(!err.contains("prog-xyz"));
    }

    #[test]
    fn guest_path_is_root_plus_file_name() {
        assert_eq!(guest_path(Path::new("some/dir/hello")).unwrap(), b"/hello");
        assert_eq!(guest_path(Path::new("hello")).unwrap(), b"/hello");
        assert!(guest_path(Path::new("..")).is_err());
    }

    #[test]
    fn exit_codes_follow_br5_2() {
        assert_eq!(exit_code(&Ok(ExitStatus::Exited(7))), 7);
        assert_eq!(exit_code(&Ok(ExitStatus::Signaled(11))), 139);
        let err = Error::new(ErrorKind::Internal, "x");
        assert_eq!(exit_code(&Err(err)), EXIT_EMULATOR_ERROR);
    }

    /// Runs a tiny guest from a temporary file with `options` before it.
    fn run_guest(name: &str, options: &[&str], code: &[u8]) -> (i32, String) {
        let path =
            std::env::temp_dir().join(format!("paludarium-cli-{name}-{}", std::process::id()));
        std::fs::write(&path, paludarium_loader::testing::tiny_exec(code, b"")).unwrap();
        let mut args = options.to_vec();
        args.push(path.to_str().unwrap());
        let result = run(&args);
        std::fs::remove_file(&path).unwrap();
        result
    }

    // mov eax, 999; syscall; mov eax, 60; xor edi, edi; syscall
    const UNKNOWN_SYSCALL_THEN_EXIT: &[u8] = &[
        0xb8, 0xe7, 0x03, 0, 0, 0x0f, 0x05, 0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
    ];

    #[test]
    fn a_fatal_cpu_fault_names_the_signal_address_and_bytes() {
        let (code, err) = run_guest("ud2", &[], &[0x0f, 0x0b]);
        assert_eq!(code, 128 + 4);
        assert!(
            err.starts_with(
                "paludarium: SIGILL: cannot run the instruction at 0x401000 (bytes 0f 0b"
            ),
            "{err}"
        );
        // mov rax, [0]
        let (code, err) = run_guest("null", &[], &[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0]);
        assert_eq!(code, 128 + 11);
        assert_eq!(
            err,
            "paludarium: SIGSEGV: read of an unmapped address 0x0 at 0x401000\n"
        );
    }

    #[test]
    fn unimplemented_system_calls_are_listed_only_on_request() {
        let (code, err) = run_guest("enosys", &[], UNKNOWN_SYSCALL_THEN_EXIT);
        assert_eq!((code, err.as_str()), (0, ""));
        let (code, err) = run_guest(
            "enosys-report",
            &["--report-enosys"],
            UNKNOWN_SYSCALL_THEN_EXIT,
        );
        assert_eq!(code, 0);
        assert_eq!(
            err,
            "paludarium: unimplemented system calls (they returned ENOSYS): 999\n"
        );
    }

    #[test]
    fn describe_stop_covers_every_fatal_fault() {
        use paludarium_types::GuestAddr;
        let rip = GuestAddr(0x10);
        for (reason, text) in [
            (ExitReason::Halt { rip }, "privileged instruction at 0x10"),
            (
                ExitReason::GeneralProtection { rip },
                "general-protection fault at 0x10",
            ),
            (ExitReason::ArithmeticFault { rip }, "divide error at 0x10"),
            (
                ExitReason::FloatingPointFault { rip, code: 1 },
                "SIMD floating-point exception at 0x10",
            ),
            (
                ExitReason::PageFault {
                    rip,
                    addr: GuestAddr(0x2000),
                    write: true,
                    fetch: false,
                    mapped: true,
                    present: true,
                },
                "write to a protected address 0x2000 at 0x10",
            ),
            (
                ExitReason::PageFault {
                    rip,
                    addr: GuestAddr(0x3000),
                    write: false,
                    fetch: true,
                    mapped: false,
                    present: false,
                },
                "instruction fetch from an unmapped address 0x3000 at 0x10",
            ),
            (
                ExitReason::BusError {
                    rip,
                    addr: GuestAddr(0x4000),
                    write: false,
                    fetch: false,
                    present: true,
                },
                "read of address 0x4000, past the end of its mapped file, at 0x10",
            ),
        ] {
            assert_eq!(describe_stop(&reason).as_deref(), Some(text));
        }
        assert_eq!(describe_stop(&ExitReason::Syscall { rip }), None);
        assert_eq!(signal_name(8), "SIGFPE");
        assert_eq!(signal_name(7), "SIGBUS");
        assert_eq!(signal_name(6), "signal 6");
    }

    #[test]
    fn invalid_program_file_is_an_emulator_error() {
        let path =
            std::env::temp_dir().join(format!("paludarium-cli-notelf-{}", std::process::id()));
        std::fs::write(&path, b"not an elf").unwrap();
        let (code, err) = run(&[path.to_str().unwrap()]);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(code, EXIT_EMULATOR_ERROR);
        assert_eq!(err, "paludarium: invalid-program: not an ELF file\n");
    }
    #[test]
    fn cli_mount_separate_argument() {
        let Command::Run(i) = parse(os(&["--mount", "fixtures:/data", "prog"])).unwrap() else {
            panic!()
        };
        assert_eq!(
            i.mounts,
            vec![Mount {
                host: "fixtures".into(),
                guest: b"/data".to_vec()
            }]
        );
    }
    #[test]
    fn cli_mount_equals_and_repeat() {
        let Command::Run(i) = parse(os(&["--mount=a:/", "--mount=b:/data", "prog"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(i.mounts.len(), 2);
        assert_eq!(i.mounts[0].guest, b"/");
        assert_eq!(i.mounts[1].host, std::path::PathBuf::from("b"));
    }
    #[test]
    fn cli_mount_windows_drive() {
        let Command::Run(i) = parse(os(&["--mount=C:\\fixtures:/data", "prog"])).unwrap() else {
            panic!()
        };
        assert_eq!(i.mounts[0].host, std::path::PathBuf::from("C:\\fixtures"));
    }
    #[test]
    fn cli_mount_invalid() {
        for args in [
            &["--mount"][..],
            &["--mount=x", "prog"],
            &["--mount=:/x", "prog"],
            &["--mount=x:relative", "prog"],
            &["--mount=x:/bad\0", "prog"],
        ] {
            assert!(parse(os(args)).is_err(), "{args:?}");
        }
    }
    #[test]
    fn cli_mount_after_program_is_guest_argument() {
        let Command::Run(i) = parse(os(&["prog", "--mount=a:/x"])).unwrap() else {
            panic!()
        };
        assert!(i.mounts.is_empty());
        assert_eq!(i.args, os(&["--mount=a:/x"]));
    }
    #[cfg(unix)]
    #[test]
    fn cli_mount_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let value = OsString::from_vec(b"--mount=\xff:/data".to_vec());
        let Command::Run(i) = parse([value, "prog".into()]).unwrap() else {
            panic!()
        };
        assert_eq!(i.mounts[0].host.as_os_str().as_encoded_bytes(), b"\xff");
    }
}
