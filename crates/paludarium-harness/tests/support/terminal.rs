use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Enclose the complete native/emulated comparison in a kill-and-reap watchdog.
pub fn bounded(name: &str, run: impl FnOnce()) {
    if std::env::var("PALUDARIUM_U9_CHILD").as_deref() == Ok(name) {
        run();
        return;
    }
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture"])
        .env("PALUDARIUM_U9_CHILD", name)
        .stdin(Stdio::null())
        .spawn()
        .expect("isolated U9 test");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert!(status.success(), "isolated {name}: {status}");
            return;
        }
        if start.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name}: outer 30-second watchdog expired");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
