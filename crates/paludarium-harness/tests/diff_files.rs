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
    let out = workspace_root().join("target/guests/files");
    let name = name_arg;
    if std::env::var("PALUDARIUM_FILES_CHILD").is_err() {
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
        let (emulated, stop) = if name_arg.starts_with("host_") {
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
cases!(trailing_operations=>32,host_trailing_operations=>32);
cases!(files_umask=>33,host_files_umask=>33,files_chmod=>34,host_files_chmod=>34,files_utimensat=>35,host_files_utimensat=>35,files_sync_fadvise=>36,host_files_sync_fadvise=>36);
cases!(files_mmap=>37,host_files_mmap=>37,mmap_errors=>38,host_mmap_errors=>38);
cases!(copy_file_range=>39,host_copy_file_range=>39,sendfile=>40,host_sendfile=>40);
cases!(files_statx=>41,host_files_statx=>41);
cases!(close_range=>42);
cases!(files_fallocate=>43,host_files_fallocate=>43);
cases!(memfd=>44);
cases!(proc_fd=>45,host_proc_fd=>45);
cases!(dev_files=>46);
cases!(dontneed_file=>47,host_dontneed_file=>47);
cases!(dontneed_elf=>48);
cases!(unix_bind=>49,host_unix_bind=>49);
cases!(null_stat=>0,null_lstat=>1,null_statat=>2,read_write=>3,files_hard_link=>4,files_symlink=>5,files_rename=>6,files_flock=>7,fstat_errors=>8,unlink_open=>9,dup_offset=>10,open_errors=>11,files_directory=>12,getdents=>13,at_operations=>14,symlinkat=>15,statat_flags=>16,files_truncate=>17,fcntl=>18,files_dangling=>19,empty_path=>20,create_dangling=>21,renamed_dirfd=>22,closed_stdio=>23,redirect_stdout=>24,dup_stdout=>25,flock_dup_close=>26,append_fcntl=>27,huge_invalid_buffer=>28,directory_link_count=>29,rename_replace=>30,files_readonly_create=>31);

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
    let root = std::env::temp_dir().join(format!("paludarium-files-host-{}", std::process::id()));
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
cases!(host_read_write=>3,host_hard_link=>4,host_symlink=>5,host_rename=>6,host_flock=>7,host_fstat_errors=>8,host_unlink_open=>9,host_dup_offset=>10,host_open_errors=>11,host_directory=>12,host_getdents=>13,host_at_operations=>14,host_symlinkat=>15,host_statat_flags=>16,host_truncate=>17,host_fcntl=>18,host_dangling=>19,host_empty_path=>20,host_create_dangling=>21,host_renamed_dirfd=>22,host_closed_stdio=>23,host_redirect_stdout=>24,host_dup_stdout=>25,host_flock_dup_close=>26,host_append_fcntl=>27,host_huge_invalid_buffer=>28,host_directory_link_count=>29,host_rename_replace=>30,host_readonly_create=>31);

#[test]
fn host_signed_mtime_stat_fstat() {
    let name = "host_signed_mtime_stat_fstat";
    let out = workspace_root().join("target/guests/files");
    assert!(
        std::process::Command::new("bash")
            .arg(workspace_root().join("tests/guests/files/build.sh"))
            .arg(&out)
            .status()
            .unwrap()
            .success()
    );
    support::bounded(name, || {
        let root =
            std::env::temp_dir().join(format!("paludarium-files-mtime-{}", std::process::id()));
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
            println!("FILES_MTIME_NATIVE ns={ns} values={values:?}");
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
            println!("FILES_MTIME_EMULATED ns={ns} bytes={:?}", emulated.stdout);
            if let Err(error) = compare(&native, &emulated) {
                mismatches.push(format!("ns={ns}: {error}"));
            }
        }
        drop(file);
        std::fs::remove_dir_all(root).unwrap();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    });
}
