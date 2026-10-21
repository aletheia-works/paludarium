use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bound the whole test, including fixture generation and process cleanup.
///
/// The test runs again in a child process selected by its exact name. The
/// child also gets `--include-ignored`, so an `#[ignore]` test started with
/// `--ignored` is not filtered out there, and it writes a marker after `run`
/// returns: a child that ran no test cannot pass as a success.
pub fn bounded(name: &str, run: impl FnOnce()) {
    if std::env::var("PALUDARIUM_ENCODINGS_CHILD").as_deref() == Ok(name) {
        run();
        if let Some(done) = std::env::var_os("PALUDARIUM_ENCODINGS_CHILD_DONE") {
            std::fs::write(done, name).expect("write encodings child marker");
        }
        return;
    }
    let done = paludarium_harness::workspace_root()
        .join("target/encodings-bounded")
        .join(format!("{name}-{}.done", std::process::id()));
    std::fs::create_dir_all(done.parent().expect("marker directory"))
        .expect("create marker directory");
    let _ = std::fs::remove_file(&done);
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--include-ignored", "--nocapture"])
        .env("PALUDARIUM_ENCODINGS_CHILD", name)
        .env("PALUDARIUM_ENCODINGS_CHILD_DONE", &done)
        .process_group(0)
        .stdin(Stdio::null())
        .spawn()
        .expect("start isolated encodings test");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll isolated encodings test") {
            assert!(status.success(), "isolated {name}: {status}");
            let ran = std::fs::read_to_string(&done).is_ok_and(|marker| marker == name);
            let _ = std::fs::remove_file(&done);
            assert!(ran, "isolated {name}: the child ran no test");
            return;
        }
        if start.elapsed() >= Duration::from_secs(30) {
            let group = format!("-{}", child.id());
            let killed = Command::new("kill").args(["-KILL", "--", &group]).status();
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                killed.is_ok_and(|s| s.success()),
                "whole encodings process-group cleanup failed"
            );
            panic!("{name}: outer 30-second watchdog expired");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
