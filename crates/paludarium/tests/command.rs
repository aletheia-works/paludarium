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
    std::fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
    let out = binary().arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(70));
    assert_eq!(
        out.stderr,
        b"paludarium: invalid-program: not an ELF file\n"
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
