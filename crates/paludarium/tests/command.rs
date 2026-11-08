//! End-to-end tests of the `paludarium` binary with a guest built in
//! code. They run on Linux, macOS and Windows: the guest is emulated.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use paludarium::testing::tiny_exec;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_paludarium"))
}

fn write_guest(name: &str, code: &[u8], data: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("paludarium-command-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, tiny_exec(code, data)).unwrap();
    path
}

/// write(1, DATA, 3); write(2, DATA+3, 2); exit_group(5)
const GUEST: [u8; 56] = [
    0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0x00, 0x20, 0x40, 0x00, 0xba, 3, 0, 0, 0, 0x0f, 0x05,
    0xb8, 1, 0, 0, 0, 0xbf, 2, 0, 0, 0, 0xbe, 0x03, 0x20, 0x40, 0x00, 0xba, 2, 0, 0, 0, 0x0f, 0x05,
    0xb8, 231, 0, 0, 0, 0xbf, 5, 0, 0, 0, 0x0f, 0x05,
];

#[test]
fn runs_guest_and_forwards_streams_and_exit_code() {
    let path = write_guest("streams", &GUEST, b"out\nE!");
    let out = binary()
        .arg("--no-jit")
        .arg(&path)
        .arg("extra")
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"out");
    assert_eq!(out.stderr, b"\nE");
    assert_eq!(out.status.code(), Some(5));
}

#[test]
fn guest_signal_becomes_128_plus_signal() {
    let path = write_guest("ud2", &[0x0f, 0x0b], b"");
    let out = binary().arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(128 + 4));
    let path = write_guest("segv", &[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0], b"");
    assert_eq!(
        binary().arg(&path).output().unwrap().status.code(),
        Some(128 + 11)
    );
}

#[test]
fn usage_errors_exit_with_two() {
    assert_eq!(binary().output().unwrap().status.code(), Some(2));
    let out = binary()
        .args(["--mount", "a:relative", "prog"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--mount"));
    assert_eq!(
        binary()
            .args(["--what", "prog"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn emulator_errors_exit_with_seventy() {
    let dir = std::env::temp_dir().join(format!("paludarium-command-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("script");
    std::fs::write(&path, b"echo hi\n").unwrap();
    let out = binary().arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(70));
    assert_eq!(
        out.stderr,
        b"paludarium: invalid-program: not an ELF file\n"
    );
    // A script outside every mount runs its interpreter, which the guest
    // does not have without one.
    std::fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
    let out = binary().arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(70));
    assert_eq!(
        out.stderr,
        b"paludarium: invalid-program: the script's interpreter was not found\n"
    );
}

#[test]
fn cli_root_mount_keeps_private_program() {
    let path = write_guest("files-root", &GUEST, b"out\nE!");
    let root =
        std::env::temp_dir().join(format!("paludarium-files-cli-root-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("sentinel"), b"unchanged").unwrap();
    let option = format!("{}:/", root.display());
    let out = binary()
        .args(["--mount", &option])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"out");
    assert_eq!(out.stderr, b"\nE");
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(std::fs::read(root.join("sentinel")).unwrap(), b"unchanged");
    assert!(!root.join("files-root").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_mount_missing_root_is_emulator_error() {
    let path = write_guest("files-missing-root", &GUEST, b"out\nE!");
    let root = std::env::temp_dir().join(format!(
        "paludarium-files-cli-missing-{}",
        std::process::id()
    ));
    assert!(!root.exists());
    let out = binary()
        .args(["--mount", &format!("{}:/data", root.display())])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(70));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn cli_forward_stdout_stderr() {
    let path = write_guest("terminal-streams", &GUEST, b"outERR");
    let out = binary().arg(&path).output().unwrap();
    assert_eq!(out.stdout, b"out");
    assert_eq!(out.stderr, b"ER");
    assert_eq!(out.status.code(), Some(5));
    std::fs::remove_file(path).unwrap();
}
#[test]
fn cli_empty_argument_is_preserved() {
    let code = vec![
        0x48, 0x8b, 0x74, 0x24, 0x10, 0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xba, 1, 0, 0, 0, 0x0f,
        0x05, 0xb8, 60, 0, 0, 0, 0xbf, 0, 0, 0, 0, 0x0f, 0x05,
    ];
    let path = write_guest("terminal-empty", &code, b"");
    let out = binary()
        .arg(&path)
        .arg("")
        .arg("two words")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, [0]);
    assert!(out.stderr.is_empty());
    std::fs::remove_file(path).unwrap();
}

/// Writes `length` bytes from `argv[1]` on, then where `/proc/self/exe` leads.
fn interpreter(length: u8) -> Vec<u8> {
    #[rustfmt::skip]
    let code = [
        0x48, 0x8b, 0x74, 0x24, 0x10, // mov rsi, [rsp + 16]
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xba, length, 0, 0, 0, 0x0f, 0x05, // write
        0xb8, 89, 0, 0, 0, 0xbf, 0x00, 0x20, 0x40, 0x00, // readlink(data,
        0xbe, 0x20, 0x20, 0x40, 0x00, 0xba, 64, 0, 0, 0, 0x0f, 0x05, // data + 32, 64)
        0x89, 0xc2, 0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05, // write
        0xb8, 231, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, // exit_group(0)
    ];
    let mut data = b"/proc/self/exe".to_vec();
    data.resize(32 + 64, 0);
    tiny_exec(&code, &data)
}

fn executable(path: &std::path::Path, content: &[u8]) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn cli_program_in_a_mount_runs_at_its_guest_path() {
    let root = std::env::temp_dir().join(format!("paludarium-cli-mounted-{}", std::process::id()));
    std::fs::create_dir_all(root.join("bin")).unwrap();
    executable(&root.join("bin/interp"), &interpreter(0));
    executable(&root.join("run.sh"), b"#!/bin/interp -x\n");
    let option = format!("{}:/", root.display());
    let run = |program: &str, args: &[&str]| {
        let out = binary()
            .args(["--mount", &option])
            .arg(root.join(program))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        out.stdout
    };
    // /proc/self/exe names the program where the guest finds it.
    assert_eq!(run("bin/interp", &[]), b"/bin/interp");
    assert_eq!(run("bin/./interp", &[]), b"/bin/interp");
    // A script runs its interpreter with its guest path, as exec does.
    executable(&root.join("bin/interp"), &interpreter(16));
    #[cfg(unix)]
    assert_eq!(run("run.sh", &["extra"]), b"-x\0/run.sh\0extra/bin/interp");
    // A Windows host's files have no execute bits (0644), so an interpreter
    // in a mount there may not be run.
    #[cfg(windows)]
    {
        let out = binary()
            .args(["--mount", &option])
            .arg(root.join("run.sh"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(70));
        assert_eq!(
            out.stderr,
            b"paludarium: invalid-program: the script's interpreter may not be run\n"
        );
    }
    #[cfg(unix)]
    {
        // /proc/self/exe resolves the links on the way, as on Linux.
        std::os::unix::fs::symlink("interp", root.join("bin/link")).unwrap();
        executable(&root.join("bin/interp"), &interpreter(0));
        assert_eq!(run("bin/link", &[]), b"/bin/interp");
        // An absolute link names a guest path, which the host need not have.
        std::os::unix::fs::symlink("/bin/interp", root.join("bin/absolute")).unwrap();
        assert_eq!(run("bin/absolute", &[]), b"/bin/interp");
    }
    // Under a deeper mount the program has that mount's path.
    std::fs::create_dir_all(root.join("opt/tools")).unwrap();
    let deeper = format!("{}:/opt/tools", root.join("bin").display());
    let out = binary()
        .args(["--mount", &option, "--mount", &deeper])
        .arg(root.join("bin/interp"))
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"/opt/tools/interp");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_missing_program_in_a_mount_is_a_usage_error() {
    let root = std::env::temp_dir().join(format!("paludarium-cli-missing-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let out = binary()
        .args(["--mount", &format!("{}:/", root.display())])
        .arg(root.join("missing"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read the program file"));
    std::fs::remove_dir_all(root).unwrap();
}
