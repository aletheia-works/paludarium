#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/processes.rs"]
mod support;

#[test]
fn runner_ready() {
    let platform = (
        std::env::consts::OS.to_owned(),
        std::env::consts::ARCH.to_owned(),
    );
    assert_eq!(
        platform,
        ("linux".to_owned(), "x86_64".to_owned()),
        "processes native oracle requires x86-64 Linux; unsupported platform is not a zero-test PASS"
    );
    assert!(
        std::process::Command::new("musl-gcc")
            .arg("--version")
            .status()
            .unwrap()
            .success()
    );
    let status = std::process::Command::new("timeout")
        .args(["--kill-after=1s", "0.1s", "sleep", "2"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(124),
        "watchdog must interrupt blocked guests"
    );
    support::bounded("runner_ready", || {});
}

/// The tests below run exactly the cases of `tests/guests/processes/cases.json`,
/// so that a case cannot be listed there and never run.
#[test]
fn every_listed_case_runs() {
    let listed = std::fs::read_to_string(
        paludarium_harness::workspace_root().join("tests/guests/processes/cases.json"),
    )
    .unwrap();
    let mut listed: Vec<_> = listed
        .split("{\"name\":\"")
        .skip(1)
        .map(|case| {
            let (name, rest) = case.split_once("\",\"binary\":\"").unwrap();
            (name.to_owned(), rest.split_once('"').unwrap().0.to_owned())
        })
        .collect();
    let source = include_str!("diff_processes.rs");
    let tests = source.split_once("cases!(\n").unwrap().1;
    let mut run: Vec<_> = tests
        .lines()
        .map_while(|line| line.split_once("=> (\""))
        .map(|(_, case)| {
            let (name, rest) = case.split_once("\",\"").unwrap();
            (name.to_owned(), rest.split_once('"').unwrap().0.to_owned())
        })
        .collect();
    assert!(!listed.is_empty());
    listed.sort();
    run.sort();
    assert_eq!(listed, run);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::support;
    use paludarium::{Config, Session, testing::RecordingHost};
    use paludarium_harness::{Outcome, compare, run_native, workspace_root};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Instant;

    fn case(test: &str, mode: &str, binary: &str) {
        static FIXTURE: Mutex<()> = Mutex::new(());
        let _fixture = FIXTURE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = workspace_root().join("target/guests/processes");
        if std::env::var("PALUDARIUM_PROCESSES_CHILD").is_err() {
            static BUILT: OnceLock<()> = OnceLock::new();
            BUILT.get_or_init(|| {
                assert!(
                    std::process::Command::new("bash")
                        .arg(workspace_root().join("tests/guests/processes/build.sh"))
                        .arg(&dir)
                        .status()
                        .unwrap()
                        .success()
                )
            });
        }
        // Linux writes the core the case reads only with the kernel's
        // default core_pattern, which CI sets.
        if mode == "core-dump" {
            for (setting, wanted) in [("core_pattern", "core\n"), ("core_uses_pid", "0\n")] {
                let value = std::fs::read_to_string(format!("/proc/sys/kernel/{setting}"))
                    .unwrap_or_default();
                assert_eq!(
                    value, wanted,
                    "the core-dump case needs `sysctl kernel.core_pattern=core kernel.core_uses_pid=0`"
                );
            }
        }
        // The datagram case fills a queue to the kernel's default length,
        // which the emulator keeps; systemd raises it.
        if mode == "unix-datagram" {
            let value =
                std::fs::read_to_string("/proc/sys/net/unix/max_dgram_qlen").unwrap_or_default();
            assert_eq!(
                value, "10\n",
                "the unix-datagram case needs `sysctl net.unix.max_dgram_qlen=10`"
            );
        }
        support::bounded(test, || {
            let program = dir.join(binary);
            let self_path = program.to_str().unwrap().to_owned();
            let args = [mode.to_owned(), self_path.clone()];
            let native = run_native(&program, binary, &args).unwrap();
            let bytes = std::fs::read(&program).unwrap();
            let config = Config::new(
                format!("/{binary}"),
                vec![
                    binary.as_bytes().to_vec(),
                    mode.as_bytes().to_vec(),
                    self_path.as_bytes().to_vec(),
                ],
            )
            .with_file(format!("/{binary}"), bytes.clone())
            .with_file(self_path, bytes);
            let host = Arc::new(RecordingHost::new());
            let session = Session::new(config, host.clone()).unwrap();
            let start = Instant::now();
            let status = session.run().unwrap();
            let emulated = Outcome {
                stdout: host.stdout(),
                stderr: host.stderr(),
                status,
                elapsed: start.elapsed(),
            };
            println!(
                "{mode}: native {:?} {:?}, emulated {:?} {:?}; stop {:?}",
                native.status,
                native.stdout,
                emulated.status,
                emulated.stdout,
                session.termination_detail()
            );
            if let Err(error) = compare(&native, &emulated) {
                eprintln!(
                    "{mode}: emulated stderr: {}",
                    String::from_utf8_lossy(&emulated.stderr)
                );
                panic!("{error}");
            }
        });
    }
    macro_rules! cases {($($name:ident => ($mode:literal,$binary:literal)),* $(,)?) => {$(#[test] fn $name(){case(concat!("linux::",stringify!($name)),$mode,$binary);})*};}
    cases!(
        processes_fork => ("fork","process"),
        processes_uname => ("uname","process"),
        processes_affinity => ("affinity","process"),
        processes_ids => ("ids","process"),
        processes_access => ("access","process"),
        processes_chown => ("chown","process"),
        processes_fd_attributes => ("fd-attributes","process"),
        processes_shared_file_mapping => ("shared-file-mapping","process"),
        processes_file_mapping_end => ("file-mapping-end","process"),
        processes_private_file_mapping => ("private-file-mapping","process"),
        processes_dontneed_read_only_segment => ("dontneed-read-only-segment","process"),
        processes_fork_copy_on_write => ("fork-copy-on-write","process"),
        processes_rlimit => ("rlimit","process"),
        processes_nofile_limit => ("nofile-limit","process"),
        processes_fsize_limit => ("fsize-limit","process"),
        processes_pgid => ("pgid","process"),
        processes_session => ("session","process"),
        processes_pgid_exec => ("pgid-exec","process"),
        processes_priority => ("priority","process"),
        processes_sysinfo => ("sysinfo","process"),
        processes_statfs => ("statfs","process"),
        processes_posix_timer => ("posix-timer","process"),
        processes_prctl => ("prctl","process"),
        processes_pdeathsig => ("pdeathsig","process"),
        processes_job_stop => ("job-stop","process"),
        processes_select => ("select","process"),
        processes_sigsuspend => ("sigsuspend","process"),
        processes_pio => ("pio","process"),
        processes_stop_restart => ("stop-restart","process"),
        processes_timerfd => ("timerfd","process"),
        processes_cpu_clocks => ("cpu-clocks","process"),
        processes_pipe_size => ("pipe-size","process"),
        processes_poll => ("poll","process"),
        processes_proc_status => ("proc-status","process"),
        processes_waitid => ("waitid","process"),
        processes_autoreap => ("autoreap","process"),
        processes_reparent => ("reparent","process"),
        processes_orphaned_group => ("orphaned-group","process"),
        processes_kill_group => ("kill-group","process"),
        processes_signal_sender => ("signal-sender","process"),
        processes_core_dump => ("core-dump","process"),
        processes_sigqueue => ("sigqueue","process"),
        processes_sparse => ("sparse","process"),
        processes_ignore_discards => ("ignore-discards","process"),
        processes_thread_name => ("thread-name","process"),
        processes_timer_thread => ("timer-thread","process"),
        processes_clone3 => ("clone3","process"),
        processes_seqpacket => ("seqpacket","process"),
        processes_dgram => ("dgram","process"),
        processes_scm_rights => ("scm-rights","process"),
        processes_scm_garbage => ("scm-garbage","process"),
        processes_unix_abstract => ("unix-abstract","process"),
        processes_unix_datagram => ("unix-datagram","process"),
        processes_unix_dgram_sndbuf => ("unix-dgram-sndbuf","process"),
        processes_stdio_flags => ("stdio-flags","process"),
        processes_unix_peercred => ("unix-peercred","process"),
        processes_unix_socketpair => ("unix-socketpair","process"),
        processes_unix_dgram_disconnect => ("unix-dgram-disconnect","process"),
        processes_unix_path => ("unix-path","process"),
        processes_socket_flags => ("socket-flags","process"),
        processes_socket_oob => ("socket-oob","process"),
        processes_socket_options => ("socket-options","process"),
        processes_socket_credentials => ("socket-credentials","process"),
        processes_socket_pidfd => ("socket-pidfd","process"),
        processes_fionread => ("fionread","process"),
        processes_generic_ioctl => ("generic-ioctl","process"),
        processes_socket_rcvlowat => ("socket-rcvlowat","process"),
        processes_socket_peek_off => ("socket-peek-off","process"),
        processes_socket_parts => ("socket-parts","process"),
        processes_socket_timestamp => ("socket-timestamp","process"),
        processes_socket_timeouts => ("socket-timeouts","process"),
        processes_signal_restart => ("signal-restart","process"),
        processes_signal_io => ("signal-io","process"),
        processes_signal_io_wait => ("signal-io-wait","process"),
        processes_socket_addresses => ("socket-addresses","process"),
        command_pre_exec => ("pre-exec","command"),
        command_pre_exec_missing => ("pre-exec-missing","command"),
        processes_private => ("private","process"),
        processes_shared => ("shared","process"),
        processes_offset => ("offset","process"),
        vfork_exec => ("vfork-exec","process"),
        vfork_exit => ("vfork-exit","process"),
        processes_exec => ("exec","process"),
        exec_thread => ("exec-thread","process"),
        clone_vm => ("clone-vm","process"),
        clone_sighand => ("clone-sighand","process"),
        clone_high_bits => ("clone-high-bits","process"),
        wait_interrupt => ("wait-interrupt","process"),
        wait_restart => ("wait-restart","process"),
        processes_enoent => ("enoent","process"),
        exec_fault => ("exec-fault","process"),
        bad_elf => ("bad-elf","process"),
        processes_cloexec => ("cloexec","process"),
        wait_specific => ("wait-specific","process"),
        wait_any => ("wait-any","process"),
        processes_wnohang => ("wnohang","process"),
        processes_signal => ("signal","process"),
        double_reap => ("double-reap","process"),
        wait_fault => ("wait-fault","process"),
        processes_usage => ("usage","process"),
        no_child => ("no-child","process"),
        invalid_clone => ("invalid-clone","process"),
        invalid_wait => ("invalid-wait","process"),
        command_spawn => ("spawn","command"),
        command_status => ("status","command"),
        command_output => ("output","command"),
        command_missing => ("missing","command"),
    );
}
