//! Native-generated threads expectations, using the process-group watchdog runner.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{path::PathBuf, process::Command, sync::OnceLock};

fn case(id: usize) {
    let root = paludarium_harness::workspace_root();
    let guests = root.join("target/guests/threads");
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        assert!(
            Command::new("bash")
                .arg(root.join("tests/guests/threads/build.sh"))
                .arg(&guests)
                .status()
                .unwrap()
                .success()
        );
    });
    let emulator = std::env::var_os("PALUDARIUM_THREADS_EMULATOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/debug/paludarium"));
    assert!(
        emulator.is_file(),
        "Build cargo build --locked -p paludarium first"
    );
    assert!(
        Command::new("python3")
            .arg(root.join("scripts/threads-native-observe.py"))
            .arg("--guests")
            .arg(&guests)
            .arg("--out")
            .arg(root.join(format!("target/threads-diff/{id}")))
            .arg("--case")
            .arg(id.to_string())
            .arg("--emulator")
            .arg(emulator)
            .status()
            .unwrap()
            .success(),
        "threads native/emulator case {id}"
    );
}
macro_rules! cases { ($($name:ident => $id:literal),* $(,)?) => {$(
    #[test] fn $name() { case($id); }
)*}; }
cases!(
    mismatch=>0, invalid_address=>1, unaligned=>2, wait_empty_bitset=>3,
    wake_empty_bitset=>4, invalid_timespec=>5, relative_timeout=>6,
    monotonic_bitset_timeout=>7, realtime_bitset_timeout=>8, no_waiters=>9,
    invalid_timeout_pointer=>10, unsupported_realtime_wait=>11,
    tls=>12, child_tid=>13, individual_exit=>14, parent_exit_retains_child=>15,
    exit_group=>16, private_wake=>17, bitset_selection=>18, shared_bitset=>19,
    tgkill_lookup=>20, interrupt_wait=>21, invalid_clone_flags=>22,
    invalid_parent_tid=>23, locked_increments=>24, mutex_condvar_handoff=>25,
    shared_wake=>26,
    timer_set_during_sleep=>27, timer_shorten_during_sleep=>28,
    timer_cancel_during_sleep=>29, wait_restart_wake=>30, bitset_restart_wake=>31,
    wait_no_restart=>32, bitset_no_restart=>33, wait_restart_value_change=>34,
    bitset_restart_value_change=>35, wait_restart_relative_timeout=>36,
    bitset_restart_absolute_timeout=>37,
    timer_disarm_before_sleep=>38, timer_set_before_sleep=>39,
    timer_repeated_changes_before_sleep=>40, timer_disarm_before_absolute_sleep=>41,
    timer_disarm_before_timed_futex=>42,
);
