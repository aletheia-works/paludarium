use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Isolate both executions in a process group and reap it on timeout.
pub fn bounded(name: &str, run: impl FnOnce()) {
    if std::env::var("PALUDARIUM_U8_CHILD").as_deref() == Ok(name) {
        run();
        return;
    }
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", name, "--nocapture"])
        .env("PALUDARIUM_U8_CHILD", name)
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("isolated U8 test");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert!(status.success(), "isolated {name}: {status}");
            return;
        }
        if start.elapsed() >= Duration::from_secs(60) {
            #[cfg(unix)]
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .status();
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name}: outer 60-second process-group watchdog expired");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
