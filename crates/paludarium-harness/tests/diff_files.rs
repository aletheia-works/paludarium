#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/files.rs"]
mod support;
use paludarium_harness::{compare, run_emulated, run_native, workspace_root};
fn case(name_arg: &'static str, id: usize) {
    // Native guests use the same absolute fixture names in this process's /tmp.
    // Keep each bounded native/emulated pair together, even under cargo's
    // default parallel test runner.
    static FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _fixture = FIXTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let out = workspace_root().join("target/guests/u7");
    let name = name_arg;
    if std::env::var("PALUDARIUM_U7_CHILD").is_err() {
        static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        BUILT.get_or_init(|| {
            assert!(
                std::process::Command::new("bash")
                    .arg(workspace_root().join("tests/guests/files/build.sh"))
                    .arg(&out)
                    .status()
                    .unwrap()
                    .success()
            )
        });
    }
    support::bounded(name, || {
        let name = format!("files-{id}");
        let path = out.join(&name);
        let native = run_native(&path, &name, &[]).unwrap();
        println!("native {id}: {:?} {:02x?}", native.status, native.stdout);
        let (emulated, stop) = if name_arg.starts_with("u7_host_") {
            run_mounted(&path, &name)
        } else {
            run_emulated(&path, &name, &[]).unwrap()
        };
        println!(
            "emulated {id}: {:?} {:02x?} {stop:?}",
            emulated.status, emulated.stdout
        );
        compare(&native, &emulated).unwrap();
    });
}
macro_rules! cases {($($name:ident=>$id:literal),*)=>{$(#[test]fn $name(){case(stringify!($name),$id);})*};}
cases!(u7_trailing_operations=>32,u7_host_trailing_operations=>32);
cases!(u7_null_stat=>0,u7_null_lstat=>1,u7_null_statat=>2,u7_read_write=>3,u7_hard_link=>4,u7_symlink=>5,u7_rename=>6,u7_flock=>7,u7_fstat_errors=>8,u7_unlink_open=>9,u7_dup_offset=>10,u7_open_errors=>11,u7_directory=>12,u7_getdents=>13,u7_at_operations=>14,u7_symlinkat=>15,u7_statat_flags=>16,u7_truncate=>17,u7_fcntl=>18,u7_dangling=>19,u7_empty_path=>20,u7_create_dangling=>21,u7_renamed_dirfd=>22,u7_closed_stdio=>23,u7_redirect_stdout=>24,u7_dup_stdout=>25,u7_flock_dup_close=>26,u7_append_fcntl=>27,u7_huge_invalid_buffer=>28,u7_directory_link_count=>29,u7_rename_replace=>30,u7_readonly_create=>31);

use paludarium_host::{ClockId, Host, WaitOutcome, testing::RecordingHost};
struct MountedHost {
    record: RecordingHost,
}
impl Host for MountedHost {
    fn read_stdin(&self, b: &mut [u8]) -> Result<usize, paludarium_types::Errno> {
        self.record.read_stdin(b)
    }
    fn write_stdout(&self, b: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.record.write_stdout(b)
    }
    fn write_stderr(&self, b: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.record.write_stderr(b)
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), paludarium_types::Error> {
        self.record.random_bytes(b)
    }
    fn clock(&self, c: ClockId) -> Result<u64, paludarium_types::Errno> {
        self.record.clock(c)
    }
    fn wait_until(
        &self,
        c: ClockId,
        d: u64,
        a: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, paludarium_types::Errno> {
        self.record.wait_until(c, d, a)
    }
    fn mount_fs(
        &self,
        root: &std::path::Path,
    ) -> Result<std::sync::Arc<dyn paludarium_host::HostFs>, paludarium_types::Errno> {
        paludarium_host::NativeHost::new().mount_fs(root)
    }
}
fn run_mounted(
    program: &std::path::Path,
    name: &str,
) -> (
    paludarium_harness::Outcome,
    Option<paludarium_types::ExitReason>,
) {
    let root = std::env::temp_dir().join(format!("paludarium-u7-host-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut config = paludarium::Config::new("/program", vec![name.as_bytes().to_vec()])
        .with_file("/program", std::fs::read(program).unwrap());
    config.mounts.push(paludarium::Mount {
        host: root.clone(),
        guest: b"/tmp".to_vec(),
    });
    let host = std::sync::Arc::new(MountedHost {
        record: RecordingHost::new(),
    });
    let session = paludarium::Session::new(config, host.clone()).unwrap();
    let start = std::time::Instant::now();
    let status = session.run().unwrap();
    let stop = session.termination_detail();
    let out = paludarium_harness::Outcome {
        stdout: host.record.stdout(),
        stderr: host.record.stderr(),
        status,
        elapsed: start.elapsed(),
    };
    std::fs::remove_dir_all(root).unwrap();
    (out, stop)
}
cases!(u7_host_read_write=>3,u7_host_hard_link=>4,u7_host_symlink=>5,u7_host_rename=>6,u7_host_flock=>7,u7_host_fstat_errors=>8,u7_host_unlink_open=>9,u7_host_dup_offset=>10,u7_host_open_errors=>11,u7_host_directory=>12,u7_host_getdents=>13,u7_host_at_operations=>14,u7_host_symlinkat=>15,u7_host_statat_flags=>16,u7_host_truncate=>17,u7_host_fcntl=>18,u7_host_dangling=>19,u7_host_empty_path=>20,u7_host_create_dangling=>21,u7_host_renamed_dirfd=>22,u7_host_closed_stdio=>23,u7_host_redirect_stdout=>24,u7_host_dup_stdout=>25,u7_host_flock_dup_close=>26,u7_host_append_fcntl=>27,u7_host_huge_invalid_buffer=>28,u7_host_directory_link_count=>29,u7_host_rename_replace=>30,u7_host_readonly_create=>31);

#[test]
fn u7_host_signed_mtime_stat_fstat() {
    let name = "u7_host_signed_mtime_stat_fstat";
    let out = workspace_root().join("target/guests/u7");
    assert!(
        std::process::Command::new("bash")
            .arg(workspace_root().join("tests/guests/files/build.sh"))
            .arg(&out)
            .status()
            .unwrap()
            .success()
    );
    support::bounded(name, || {
        let root = std::env::temp_dir().join(format!("paludarium-u7-mtime-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("mtime");
        let file = std::fs::File::create(&path).unwrap();
        let mut mismatches = Vec::new();
        for ns in [-1_000_000_000i128, -500_000_000, -1, 0, 1, 1_500_000_000] {
            let duration =
                std::time::Duration::from_nanos(u64::try_from(ns.unsigned_abs()).unwrap());
            let time = if ns < 0 {
                std::time::UNIX_EPOCH - duration
            } else {
                std::time::UNIX_EPOCH + duration
            };
            file.set_times(std::fs::FileTimes::new().set_modified(time))
                .unwrap();
            let native = run_native(
                &out.join("mtime"),
                "mtime",
                &[path.to_str().unwrap().to_owned()],
            )
            .unwrap();
            let values: Vec<i64> = native
                .stdout
                .as_chunks::<8>()
                .0
                .iter()
                .map(|bytes| i64::from_le_bytes(*bytes))
                .collect();
            assert_eq!(
                values,
                vec![
                    0,
                    i64::try_from(ns.div_euclid(1_000_000_000)).unwrap(),
                    i64::try_from(ns.rem_euclid(1_000_000_000)).unwrap(),
                    0,
                    i64::try_from(ns.div_euclid(1_000_000_000)).unwrap(),
                    i64::try_from(ns.rem_euclid(1_000_000_000)).unwrap()
                ]
            );
            println!("U7_MTIME_NATIVE ns={ns} values={values:?}");
            let mut config = paludarium::Config::new(
                "/program",
                vec![b"mtime".to_vec(), b"/fixture/mtime".to_vec()],
            )
            .with_file("/program", std::fs::read(out.join("mtime")).unwrap());
            config.mounts.push(paludarium::Mount {
                host: root.clone(),
                guest: b"/fixture".to_vec(),
            });
            let host = std::sync::Arc::new(MountedHost {
                record: RecordingHost::new(),
            });
            let session = paludarium::Session::new(config, host.clone()).unwrap();
            let start = std::time::Instant::now();
            let status = session.run().unwrap();
            let emulated = paludarium_harness::Outcome {
                stdout: host.record.stdout(),
                stderr: host.record.stderr(),
                status,
                elapsed: start.elapsed(),
            };
            println!("U7_MTIME_EMULATED ns={ns} bytes={:?}", emulated.stdout);
            if let Err(error) = compare(&native, &emulated) {
                mismatches.push(format!("ns={ns}: {error}"));
            }
        }
        drop(file);
        std::fs::remove_dir_all(root).unwrap();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    });
}
