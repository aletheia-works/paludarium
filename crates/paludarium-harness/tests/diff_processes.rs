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
        processes_rlimit => ("rlimit","process"),
        processes_pgid => ("pgid","process"),
        processes_sysinfo => ("sysinfo","process"),
        processes_statfs => ("statfs","process"),
        processes_posix_timer => ("posix-timer","process"),
        processes_prctl => ("prctl","process"),
        processes_pdeathsig => ("pdeathsig","process"),
        processes_waitid => ("waitid","process"),
        processes_thread_name => ("thread-name","process"),
        processes_timer_thread => ("timer-thread","process"),
        processes_clone3 => ("clone3","process"),
        processes_seqpacket => ("seqpacket","process"),
        processes_dgram => ("dgram","process"),
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
