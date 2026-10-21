#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/processes.rs"]
mod support;

#[test]
fn u8_runner_ready() {
    let platform = (
        std::env::consts::OS.to_owned(),
        std::env::consts::ARCH.to_owned(),
    );
    assert_eq!(
        platform,
        ("linux".to_owned(), "x86_64".to_owned()),
        "U8 native oracle requires x86-64 Linux; unsupported platform is not a zero-test PASS"
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
    support::bounded("u8_runner_ready", || {});
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
        let dir = workspace_root().join("target/guests/u8");
        if std::env::var("PALUDARIUM_U8_CHILD").is_err() {
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
        u8_fork => ("fork","u8-process"),
        u8_private => ("private","u8-process"),
        u8_shared => ("shared","u8-process"),
        u8_offset => ("offset","u8-process"),
        u8_vfork_exec => ("vfork-exec","u8-process"),
        u8_vfork_exit => ("vfork-exit","u8-process"),
        u8_exec => ("exec","u8-process"),
        u8_exec_thread => ("exec-thread","u8-process"),
        u8_clone_vm => ("clone-vm","u8-process"),
        u8_wait_interrupt => ("wait-interrupt","u8-process"),
        u8_wait_restart => ("wait-restart","u8-process"),
        u8_enoent => ("enoent","u8-process"),
        u8_exec_fault => ("exec-fault","u8-process"),
        u8_bad_elf => ("bad-elf","u8-process"),
        u8_cloexec => ("cloexec","u8-process"),
        u8_wait_specific => ("wait-specific","u8-process"),
        u8_wait_any => ("wait-any","u8-process"),
        u8_wnohang => ("wnohang","u8-process"),
        u8_signal => ("signal","u8-process"),
        u8_double_reap => ("double-reap","u8-process"),
        u8_wait_fault => ("wait-fault","u8-process"),
        u8_usage => ("usage","u8-process"),
        u8_no_child => ("no-child","u8-process"),
        u8_invalid_clone => ("invalid-clone","u8-process"),
        u8_invalid_wait => ("invalid-wait","u8-process"),
        u8_command_spawn => ("spawn","u8-command"),
        u8_command_status => ("status","u8-command"),
        u8_command_output => ("output","u8-command"),
        u8_command_missing => ("missing","u8-command"),
    );
}
