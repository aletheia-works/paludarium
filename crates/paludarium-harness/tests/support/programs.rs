use paludarium::{Config, ExitStatus, Mount, Session};
use paludarium_host::{ClockId, Host, NativeHost, WaitOutcome, testing::RecordingHost};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

struct CaptureHost(RecordingHost);
impl Host for CaptureHost {
    fn read_stdin(&self, bytes: &mut [u8]) -> Result<usize, paludarium_types::Errno> {
        self.0.read_stdin(bytes)
    }
    fn write_stdout(&self, bytes: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.0.write_stdout(bytes)
    }
    fn write_stderr(&self, bytes: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.0.write_stderr(bytes)
    }
    fn random_bytes(&self, bytes: &mut [u8]) -> Result<(), paludarium_types::Error> {
        NativeHost::new().random_bytes(bytes)
    }
    fn clock(&self, clock: ClockId) -> Result<u64, paludarium_types::Errno> {
        NativeHost::new().clock(clock)
    }
    fn wait_until(
        &self,
        clock: ClockId,
        deadline: u64,
        aborted: &AtomicBool,
    ) -> Result<WaitOutcome, paludarium_types::Errno> {
        NativeHost::new().wait_until(clock, deadline, aborted)
    }
    fn mount_fs(
        &self,
        root: &Path,
    ) -> Result<Arc<dyn paludarium_host::HostFs>, paludarium_types::Errno> {
        NativeHost::new().mount_fs(root)
    }
}

fn fixture_files(config: &mut Config, directory: &Path, guest: &str) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = format!("{guest}/{}", entry.file_name().to_str().unwrap());
        if entry.file_type().unwrap().is_dir() {
            fixture_files(config, &entry.path(), &path);
        } else {
            let mode = fixture_mode(&entry.path());
            assert_eq!(
                mode, 0o644,
                "U10 fixture permissions must match native 0644"
            );
            *config = std::mem::take(config).with_file_mode(
                path,
                std::fs::read(entry.path()).unwrap(),
                mode,
            );
        }
    }
}

#[cfg(unix)]
fn fixture_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn fixture_mode(_path: &Path) -> u32 {
    panic!("U10 fixture metadata requires Unix")
}

/// Executed only as a child of the 30-second Python group watchdog.
pub fn operation() {
    let directory = PathBuf::from(std::env::var_os("PALUDARIUM_U10_OPERATION").unwrap());
    let binary = PathBuf::from(std::env::var_os("PALUDARIUM_U10_BINARY").unwrap());
    let mut args = vec![b"/program".to_vec()];
    args.extend(
        std::fs::read_to_string(directory.join("args"))
            .unwrap()
            .lines()
            .map(|s| s.as_bytes().to_vec()),
    );
    let mut config = Config::new("/program", args)
        .with_file("/program", std::fs::read(binary).unwrap())
        .with_file("/tmp/.u10", Vec::new())
        .with_file("/home/u10/.u10", Vec::new());
    for line in std::fs::read_to_string(directory.join("environment"))
        .unwrap()
        .lines()
    {
        let (key, value) = line.split_once('=').unwrap();
        config
            .env
            .push((key.as_bytes().to_vec(), value.as_bytes().to_vec()));
    }
    if let Some(fixture) = std::env::var_os("PALUDARIUM_U10_FIXTURE") {
        let fixture = PathBuf::from(fixture).canonicalize().unwrap();
        if std::env::var_os("PALUDARIUM_U10_MOUNTED").is_some() {
            config.mounts.push(Mount {
                host: fixture.join("app"),
                guest: b"/".to_vec(),
            });
            config.mounts.push(Mount {
                host: fixture.join("outside"),
                guest: b"/outside".to_vec(),
            });
        } else {
            fixture_files(&mut config, &fixture.join("app"), "");
            fixture_files(&mut config, &fixture.join("outside"), "/outside");
        }
    }
    let host = Arc::new(CaptureHost(RecordingHost::new()));
    std::fs::write(
        directory.join("fixture-modes"),
        config
            .file_modes
            .iter()
            .map(|(path, mode)| format!("{}\t{mode}\n", String::from_utf8_lossy(path)))
            .collect::<String>(),
    )
    .unwrap();
    let session = Session::new(config, host.clone()).unwrap();
    let started = Instant::now();
    let result = session.run();
    std::fs::write(directory.join("stdout"), host.0.stdout()).unwrap();
    std::fs::write(directory.join("stderr"), host.0.stderr()).unwrap();
    std::fs::write(
        directory.join("stop"),
        format!("{:?}\n{result:?}", session.termination_detail()),
    )
    .unwrap();
    std::fs::write(
        directory.join("seconds"),
        started.elapsed().as_secs_f64().to_string(),
    )
    .unwrap();
    let status = match result {
        Ok(ExitStatus::Exited(code)) => code,
        Ok(ExitStatus::Signaled(signal)) => -signal,
        Err(_) | Ok(_) => -255,
    };
    std::fs::write(directory.join("exit"), status.to_string()).unwrap();
}
