#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/programs.rs"]
mod support;

/// Python owns the per-operation process-group watchdog and fresh oracle.
#[test]
#[ignore = "fixed guest artifacts and isolated x86 Linux namespace required"]
fn programs_differential() {
    assert_eq!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("linux", "x86_64")
    );
    let root = paludarium_harness::workspace_root();
    let status = std::process::Command::new("python3")
        .arg(root.join("tests/guests/programs/differential.py"))
        .arg(std::env::current_exe().unwrap())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "U10 differential failed; inspect target/programs/differential"
    );
}

#[test]
fn programs_guest_operation() {
    if std::env::var_os("PALUDARIUM_U10_OPERATION").is_some() {
        support::operation();
    }
}
