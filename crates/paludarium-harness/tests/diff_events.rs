//! Native-generated U6 expectations, using the process-group watchdog runner.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{path::PathBuf, process::Command, sync::OnceLock};

fn case(id: usize) {
    let root = paludarium_harness::workspace_root();
    let guests = root.join("target/guests/u6");
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        assert!(
            Command::new("bash")
                .arg(root.join("tests/guests/events/build.sh"))
                .arg(&guests)
                .status()
                .unwrap()
                .success()
        );
    });
    let emulator = std::env::var_os("PALUDARIUM_U6_EMULATOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/debug/paludarium"));
    assert!(
        emulator.is_file(),
        "Build cargo build --locked -p paludarium first"
    );
    assert!(
        Command::new("python3")
            .arg(root.join("scripts/events-native-observe.py"))
            .arg("--guests")
            .arg(&guests)
            .arg("--out")
            .arg(root.join(format!("target/u6-diff/{id}")))
            .arg("--case")
            .arg(id.to_string())
            .arg("--emulator")
            .arg(emulator)
            .status()
            .unwrap()
            .success(),
        "U6 native/emulator case {id}"
    );
}
macro_rules! cases { ($($name:ident => $id:literal),* $(,)?) => {$(
    #[test] fn $name() { case($id); }
)*}; }
cases!(
    event_initial=>0,
    event_add=>1,
    event_semaphore=>2,
    event_empty=>3,
    event_zero_write=>4,
    event_max_write=>5,
    event_overflow=>6,
    event_short_read=>7,
    event_short_write=>8,
    event_fault_read=>9,
    event_fault_write=>10,
    event_invalid_flags=>11,
    event_dup_lifetime=>12,
    event_shared_flags=>13,
    event_cloexec=>14,
    event_poll=>15,
    epoll_invalid_flags=>16,
    epoll_legacy_size=>17,
    epoll_data=>18,
    epoll_lt=>19,
    epoll_et=>20,
    epoll_oneshot=>21,
    epoll_duplicate_add=>22,
    epoll_missing_mod=>23,
    epoll_missing_del=>24,
    epoll_del_null=>25,
    epoll_self=>26,
    epoll_bad_fd=>27,
    epoll_maxevents=>28,
    epoll_not_epoll=>29,
    epoll_fault_out=>30,
    epoll_dup_close=>31,
    epoll_duplicate_ofd=>32,
    epoll_fd_reuse=>33,
    epoll_fairness=>34,
    epoll_timeout=>35,
    socket_transfer=>36,
    socket_bidirectional=>37,
    socket_empty=>38,
    socket_partial=>39,
    socket_eof=>40,
    socket_epipe=>41,
    socket_shutdown=>42,
    socket_flags=>43,
    socket_send_recv=>44,
    socket_hangup=>45,
    socket_et=>46,
    socket_bad_pointer=>47,
    epoll_signal=>48,
    epoll_masked_signal=>49,
    epoll_ignored_signal=>50,
    epoll_pwait=>51,
    network_inet=>52,
    network_inet6=>53,
    socketpair_wrong_domain=>54,
    socketpair_bad_output=>55,
    socketpair_bad_flags=>56,
    epoll_invalid_op=>57,
    epoll_mod_ready=>58,
    event_blocking_signal=>59,
    group_kill=>60, timer_metadata_before_epoll=>61,
    epoll_nested=>62, socket_nosignal=>63,
    socket_backpressure_readiness=>64, socket_short_write_saturation=>65,
    socket_blocking_write_peer_drains=>66,
    event_et_unread_write=>67, event_et_drain_rewrite=>68, event_et_oneshot_unread=>69,
    socket_et_unread_write=>70, socket_et_drain_rewrite=>71, socket_et_oneshot_unread=>72,
    pwait_temporary_unblock_handler=>73, pwait_normal_signal=>74,
    pwait_masked_signal=>75, pwait_ignored_signal=>76,
    pwait_ready_restores_mask=>77, pwait_invalid_restores_mask=>78,
    event_et_output_read=>79, socket_et_output_partial_drain=>80,
    socket_et_output_write_boundaries=>81,
);
#[test]
fn tokio_timer() {
    named_case("timer");
}
#[test]
fn unix_stream() {
    named_case("unix");
}
fn named_case(name: &str) {
    let root = paludarium_harness::workspace_root();
    assert!(
        Command::new("bash")
            .arg(root.join("tests/guests/events/build.sh"))
            .arg(root.join("target/guests/u6"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("python3")
            .arg(root.join("scripts/events-native-observe.py"))
            .arg("--case")
            .arg(name)
            .arg("--guests")
            .arg(root.join("target/guests/u6"))
            .arg("--out")
            .arg(root.join(format!("target/u6-diff/{name}")))
            .arg("--emulator")
            .arg(
                std::env::var_os("PALUDARIUM_U6_EMULATOR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| root.join("target/debug/paludarium"))
            )
            .status()
            .unwrap()
            .success()
    );
}
