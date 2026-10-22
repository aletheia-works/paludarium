//! Differential test harness for paludarium (not published).
//!
//! A guest program is run natively on x86-64 Linux and under the emulator;
//! standard output, standard error and the exit status must match byte for
//! byte. The expected result is always produced by the native run at test
//! time, never stored.
//! Each run has a 30-second limit.
//!
//! This crate is test tooling: unlike the emulator crates it uses
//! `std::process`, `std::thread` and `std::time` directly.
#![forbid(unsafe_code)]

pub mod coverage;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use paludarium::testing::RecordingHost;
use paludarium::{Config, ExitReason, ExitStatus, Session};

/// Time limit of one run.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Which toolchain builds a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestSource {
    CMusl,
    RustMusl,
}

/// One differential test. The core tests compare
/// stdout, stderr and the exit status for every case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffTestCase {
    pub name: &'static str,
    /// File name of the guest binary in the guest directory.
    pub binary: &'static str,
    pub source: GuestSource,
    pub arguments: Vec<String>,
}

/// What a run produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
    pub elapsed: Duration,
}

/// The repository root (two levels above this crate).
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Where guest binaries are built: `$PALUDARIUM_GUEST_DIR` or
/// `target/guests` under the workspace.
#[must_use]
pub fn guest_dir() -> PathBuf {
    std::env::var_os("PALUDARIUM_GUEST_DIR").map_or_else(
        || workspace_root().join("target").join("guests"),
        PathBuf::from,
    )
}

/// Builds the guests once per test process with `tests/guests/build.sh` and
/// returns the guest directory.
pub fn ensure_guests_built() -> Result<PathBuf, String> {
    static BUILT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let dir = guest_dir();
            let script = workspace_root()
                .join("tests")
                .join("guests")
                .join("build.sh");
            let status = Command::new("bash")
                .arg(&script)
                .arg(&dir)
                .status()
                .map_err(|e| format!("cannot run {}: {e}", script.display()))?;
            if status.success() {
                Ok(dir)
            } else {
                Err(format!("{} failed: {status}", script.display()))
            }
        })
        .clone()
}

fn drain(mut source: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        // A read error only truncates the captured output, which then fails
        // the comparison visibly.
        let _ = source.read_to_end(&mut buf);
        buf
    })
}

#[cfg(unix)]
fn native_status(status: std::process::ExitStatus) -> Result<ExitStatus, String> {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => Ok(ExitStatus::Exited(code)),
        (None, Some(signal)) => Ok(ExitStatus::Signaled(signal)),
        _ => Err(format!("unexpected native status {status}")),
    }
}

#[cfg(not(unix))]
fn native_status(status: std::process::ExitStatus) -> Result<ExitStatus, String> {
    status
        .code()
        .map(ExitStatus::Exited)
        .ok_or_else(|| format!("unexpected native status {status}"))
}

/// Runs `program` directly on the host with `argv0` and `args`.
pub fn run_native(program: &Path, argv0: &str, args: &[String]) -> Result<Outcome, String> {
    let started = Instant::now();
    let mut command = Command::new(program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.arg0(argv0);
    }
    #[cfg(not(unix))]
    let _ = argv0;
    let mut child = command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", program.display()))?;
    let stdout = drain(child.stdout.take().ok_or("no stdout pipe")?);
    let stderr = drain(child.stderr.take().ok_or("no stderr pipe")?);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            let _ = child.kill();
            return Err(format!("native run of {} timed out", program.display()));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    Ok(Outcome {
        stdout: stdout.join().map_err(|_| "stdout reader panicked")?,
        stderr: stderr.join().map_err(|_| "stderr reader panicked")?,
        status: native_status(status)?,
        elapsed: started.elapsed(),
    })
}

/// Runs `program` under paludarium, placed at `/<file name>` like the
/// command does. Returns the outcome and the stop that ended the
/// guest when it died of an exception (for diagnostics).
pub fn run_emulated(
    program: &Path,
    argv0: &str,
    args: &[String],
) -> Result<(Outcome, Option<ExitReason>), String> {
    let content =
        std::fs::read(program).map_err(|e| format!("cannot read {}: {e}", program.display()))?;
    let name = program
        .file_name()
        .ok_or("program has no file name")?
        .to_string_lossy()
        .into_owned();
    let guest_path = format!("/{name}");
    let mut argv = vec![argv0.as_bytes().to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    let config = Config::new(guest_path.clone(), argv).with_file(guest_path, content);
    let host = Arc::new(RecordingHost::new());
    let session = Arc::new(Session::new(config, host.clone()).map_err(|e| e.to_string())?);
    let started = Instant::now();
    let runner = {
        let session = Arc::clone(&session);
        std::thread::spawn(move || session.run())
    };
    while !runner.is_finished() {
        if started.elapsed() > TIMEOUT {
            session.kill();
            let _ = runner.join();
            return Err(format!("emulated run of {} timed out", program.display()));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = runner
        .join()
        .map_err(|_| "emulator thread panicked".to_string())?
        .map_err(|e| format!("emulator error: {e}"))?;
    Ok((
        Outcome {
            stdout: host.stdout(),
            stderr: host.stderr(),
            status,
            elapsed: started.elapsed(),
        },
        session.termination_detail(),
    ))
}

fn first_difference(a: &[u8], b: &[u8]) -> String {
    let at = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let line_start = a[..at]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |p| p + 1);
    let excerpt = |s: &[u8]| {
        let end = s[line_start.min(s.len())..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(s.len(), |p| line_start + p);
        String::from_utf8_lossy(&s[line_start.min(s.len())..end.max(line_start.min(s.len()))])
            .into_owned()
    };
    format!(
        "first difference at byte {at} (native {} bytes, emulated {} bytes)\n  native:   {}\n  emulated: {}",
        a.len(),
        b.len(),
        excerpt(a),
        excerpt(b)
    )
}

/// Compares two outcomes byte for byte; the error describes the
/// first mismatch.
pub fn compare(native: &Outcome, emulated: &Outcome) -> Result<(), String> {
    let mut problems = Vec::new();
    if native.stdout != emulated.stdout {
        problems.push(format!(
            "stdout differs: {}",
            first_difference(&native.stdout, &emulated.stdout)
        ));
    }
    if native.stderr != emulated.stderr {
        problems.push(format!(
            "stderr differs: {}",
            first_difference(&native.stderr, &emulated.stderr)
        ));
    }
    if native.status != emulated.status {
        problems.push(format!(
            "exit status differs: native {:?}, emulated {:?}",
            native.status, emulated.status
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// Runs one case natively and emulated and compares the results.
/// Returns (native, emulated) on success for timing records.
pub fn run_case(case: &DiffTestCase) -> Result<(Outcome, Outcome), String> {
    let dir = ensure_guests_built()?;
    let program = dir.join(case.binary);
    let native = run_native(&program, case.binary, &case.arguments)?;
    let (emulated, stop) = run_emulated(&program, case.binary, &case.arguments)?;
    compare(&native, &emulated)
        .map_err(|e| format!("{}: {e}\n  emulator stop: {stop:?}", case.name))?;
    Ok((native, emulated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(stdout: &[u8], status: ExitStatus) -> Outcome {
        Outcome {
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            status,
            elapsed: Duration::ZERO,
        }
    }

    #[test]
    fn identical_outcomes_compare_equal_regardless_of_time() {
        let a = outcome(b"hello\n", ExitStatus::Exited(0));
        let mut b = a.clone();
        b.elapsed = Duration::from_secs(3);
        assert_eq!(compare(&a, &b), Ok(()));
    }

    #[test]
    fn differences_are_reported_with_the_line() {
        let a = outcome(b"one\ntwo\n", ExitStatus::Exited(0));
        let b = outcome(b"one\ntwX\n", ExitStatus::Signaled(11));
        let err = compare(&a, &b).unwrap_err();
        assert!(err.contains("first difference at byte 6"), "{err}");
        assert!(err.contains("native:   two"), "{err}");
        assert!(err.contains("emulated: twX"), "{err}");
        assert!(err.contains("exit status differs"), "{err}");
    }

    #[test]
    fn length_differences_are_detected() {
        let a = outcome(b"abc", ExitStatus::Exited(0));
        let b = outcome(b"ab", ExitStatus::Exited(0));
        assert!(
            compare(&a, &b)
                .unwrap_err()
                .contains("native 3 bytes, emulated 2 bytes")
        );
    }

    #[test]
    fn emulated_run_of_a_code_built_guest() {
        let dir = std::env::temp_dir().join(format!("paludarium-harness-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("exit9");
        // mov edi, 9; mov eax, 231; syscall
        let code = [0xbf, 9, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05];
        std::fs::write(&path, paludarium::testing::tiny_exec(&code, b"")).unwrap();
        let (out, stop) = run_emulated(&path, "exit9", &[]).unwrap();
        assert_eq!(out.status, ExitStatus::Exited(9));
        assert_eq!(stop, None);
        assert!(run_emulated(&dir.join("missing"), "x", &[]).is_err());
    }
}
