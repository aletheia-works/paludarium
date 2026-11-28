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
    support::bounded("runner_ready", 60, || {});
}

/// `cases!` below is the only list of the process cases. Its entries are
/// sorted by test name, and no test name or (mode, guest) is there twice; every
/// line of it is an entry or a comment, so that none is read past.
#[test]
fn cases_are_listed_once_in_order() {
    let source = include_str!("diff_processes.rs");
    let list = source
        .split_once("    cases!(\n")
        .unwrap()
        .1
        .split_once("\n    );\n")
        .unwrap()
        .0;
    let entries: Vec<_> = list
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            let (name, rest) = line.trim_start().split_once(" => (\"").unwrap();
            let (mode, rest) = rest.split_once("\", \"").unwrap();
            let (binary, root) = rest.split_once('"').unwrap();
            assert!(root == ")," || root == ", root),", "{line}");
            (name, (mode, binary))
        })
        .collect();
    assert!(entries.len() > 600, "{}", entries.len());
    for pair in entries.windows(2) {
        assert!(
            pair[0].0 < pair[1].0,
            "{} is not before {}",
            pair[0].0,
            pair[1].0
        );
    }
    let mut runs: Vec<_> = entries.iter().map(|(_, run)| *run).collect();
    runs.sort_unstable();
    for pair in runs.windows(2) {
        assert_ne!(pair[0], pair[1], "{:?} is there twice", pair[0]);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::support;
    use paludarium::{Config, Session, testing::RecordingHost};
    use paludarium_harness::{Outcome, TIMEOUT, compare, run_native_within, workspace_root};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    fn running_as_root() -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
    }

    /// The host's `kernel.perf_event_max_sample_rate` before the throttle
    /// case, written back when dropped if the case left another.
    struct SampleRate(String);

    impl SampleRate {
        const PATH: &str = "/proc/sys/kernel/perf_event_max_sample_rate";
        fn save() -> Self {
            Self(std::fs::read_to_string(Self::PATH).unwrap())
        }
    }

    impl Drop for SampleRate {
        fn drop(&mut self) {
            if std::fs::read_to_string(Self::PATH).is_ok_and(|now| now == self.0) {
                return;
            }
            let value = self.0.trim();
            let restored = if running_as_root() {
                std::fs::write(Self::PATH, value).is_ok()
            } else {
                std::process::Command::new("/usr/bin/sudo")
                    .args(["-n", "sysctl", "-q", "-w"])
                    .arg(format!("kernel.perf_event_max_sample_rate={value}"))
                    .status()
                    .is_ok_and(|status| status.success())
            };
            assert!(
                restored || std::thread::panicking(),
                "kernel.perf_event_max_sample_rate could not be put back to {value}"
            );
        }
    }

    fn case(test: &str, mode: &str, binary: &str, as_root: bool) {
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
        // Linux writes the core the cases read only with the kernel's
        // default core_pattern, which CI sets.
        if mode == "core-dump"
            || mode == "exec-names"
            || mode == "rename-names"
            || mode == "chroot-names"
            || mode == "core-dump-faults"
            || mode == "core-mappings"
            || mode == "core-credentials"
            || mode == "ptrace-exit-core"
        {
            for (setting, wanted) in [("core_pattern", "core\n"), ("core_uses_pid", "0\n")] {
                let value = std::fs::read_to_string(format!("/proc/sys/kernel/{setting}"))
                    .unwrap_or_default();
                assert_eq!(
                    value, wanted,
                    "the {mode} case needs `sysctl kernel.core_pattern=core kernel.core_uses_pid=0`"
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
        // The throttle case sets kernel.perf_event_max_sample_rate, which
        // is the whole kernel's, to 1 while it runs: only where the
        // workflow lets it (CI). The cases run one at a time (`FIXTURE`),
        // so no other perf case sees that value, and it is put back after
        // the case, should the case not have.
        let _sample_rate = (mode == "perf-throttle").then(|| {
            assert!(
                std::env::var_os("PALUDARIUM_PERF_SAMPLE_RATE_WRITES").is_some(),
                "the perf-throttle case sets the host's kernel.perf_event_max_sample_rate to 1 \
                 while it runs; it runs only where PALUDARIUM_PERF_SAMPLE_RATE_WRITES=1 lets \
                 it, as CI does"
            );
            SampleRate::save()
        });
        let watchdog = if mode == "neighbour-ageing" { 150 } else { 60 };
        support::bounded(test, watchdog, || {
            let program = dir.join(binary);
            let self_path = program.to_str().unwrap().to_owned();
            let args = [mode.to_owned(), self_path.clone()];
            // The neighbour-ageing case waits out Linux's reachable time,
            // which may be 45 seconds.
            let limit = if mode == "neighbour-ageing" {
                Duration::from_secs(70)
            } else {
                TIMEOUT
            };
            // The ignored-start case starts with SIGINT and SIGQUIT ignored,
            // as a shell's `&` job does: through `sh`'s `trap ''`, which
            // `exec` keeps, natively, and from the host emulated.
            let native = if mode == "ignored-start" {
                let mut sh = vec![
                    "-c".to_owned(),
                    "trap '' INT QUIT; exec \"$0\" \"$@\"".to_owned(),
                    self_path.clone(),
                ];
                sh.extend(args.iter().cloned());
                run_native_within(std::path::Path::new("/bin/sh"), "sh", &sh, limit).unwrap()
            } else if as_root && !running_as_root() {
                let mut sudo = vec!["-n".to_owned(), self_path.clone()];
                sudo.extend(args.iter().cloned());
                run_native_within(std::path::Path::new("/usr/bin/sudo"), "sudo", &sudo, limit)
                    .unwrap()
            } else {
                run_native_within(&program, binary, &args, limit).unwrap()
            };
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
            // The dynamic cases find these where Linux does.
            let config = if mode == "dynamic-exec" {
                let path = dir.join("dynamic");
                config.with_file(
                    path.to_str().unwrap().to_owned(),
                    std::fs::read(&path).unwrap(),
                )
            } else {
                config
            };
            // glibc's files where Debian and Ubuntu have them, which CI is; on
            // another layout this case cannot find them.
            let config = if mode == "dynamic-glibc" {
                let beside = |name: &str| std::fs::read(dir.join(name)).unwrap();
                config
                    .with_file(
                        "/lib64/ld-linux-x86-64.so.2",
                        std::fs::read("/lib64/ld-linux-x86-64.so.2").unwrap(),
                    )
                    .with_file(
                        "/lib/x86_64-linux-gnu/libc.so.6",
                        std::fs::read("/lib/x86_64-linux-gnu/libc.so.6").unwrap(),
                    )
                    .with_file(
                        dir.join("dynamic-glibc-plugin.so")
                            .to_str()
                            .unwrap()
                            .to_owned(),
                        beside("dynamic-glibc-plugin.so"),
                    )
            } else if mode.starts_with("dynamic") {
                let beside = |name: &str| std::fs::read(dir.join(name)).unwrap();
                config
                    .with_file(
                        "/lib/ld-musl-x86_64.so.1",
                        std::fs::read("/lib/ld-musl-x86_64.so.1").unwrap(),
                    )
                    .with_file(
                        dir.join("dynamic-plugin.so").to_str().unwrap().to_owned(),
                        beside("dynamic-plugin.so"),
                    )
            } else if mode == "inotify-interpreter"
                || mode == "inotify-exec"
                || mode == "inotify-exec-order"
            {
                // The loader it copies, and beside the program (`/inotify`,
                // as `/proc/self/exe` names it) the one it runs with the copy.
                config
                    .with_file(
                        "/lib/ld-musl-x86_64.so.1",
                        std::fs::read("/lib/ld-musl-x86_64.so.1").unwrap(),
                    )
                    .with_file(
                        "/inotify-interp",
                        std::fs::read(dir.join("inotify-interp")).unwrap(),
                    )
            } else {
                config
            };
            let host = Arc::new(RecordingHost::new());
            if mode == "ignored-start" {
                host.start_ignoring(1 << (2 - 1) | 1 << (3 - 1));
            }
            // Its files must be on a host's file system, as the native run's
            // /tmp is, whose inodes go once nothing uses them (a tmpfs keeps
            // its own): a host directory of its own is the guest's /tmp, as
            // the files tests' is.
            let mut config = config;
            let host_tmp = (mode == "fanotify-drop-caches").then(|| {
                let dir =
                    std::env::temp_dir().join(format!("paludarium-{mode}-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                config.mounts.push(paludarium::Mount {
                    host: dir.clone(),
                    guest: b"/tmp".to_vec(),
                });
                host.mount_host_directories();
                dir
            });
            // Their timers and limits wait for CPU time, which the virtual
            // clock does not pass, and the perf cases' clocks count it.
            if matches!(
                mode,
                "cpu-itimer"
                    | "rlimit-cpu"
                    | "cpu-timer"
                    | "cpu-sleep"
                    | "cpu-sleep-others"
                    | "cpu-clock-running"
                    | "cpu-timer-others"
                    | "perf-counts"
                    | "perf-exec"
                    | "perf-prctl"
                    | "perf-inherit"
                    | "perf-throttle"
                    | "perf-clock-samples"
                    | "perf-software"
            ) {
                host.measure_cpu_time();
            }
            let session = paludarium_harness::with_test_jit(
                Session::new(config, host.clone()).unwrap(),
                &host,
            )
            .unwrap();
            let start = Instant::now();
            let status = session.run().unwrap();
            let emulated = Outcome {
                stdout: host.stdout(),
                stderr: host.stderr(),
                status,
                elapsed: start.elapsed(),
            };
            if let Some(dir) = host_tmp {
                let _ = std::fs::remove_dir_all(dir);
            }
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
    /// One test a case: its name, the guest's mode and the guest. `root` runs
    /// Linux's side as root, through sudo when the tests do not run as root, as
    /// the emulator's guest starts as root; the line above an entry says why
    /// where it needs saying. The entries are sorted by name, one a line, so
    /// that two branches that add cases seldom add them at the same place.
    macro_rules! cases {
        ($($name:ident => ($mode:literal, $binary:literal $(, $root:ident)?)),* $(,)?) => {$(
            #[test]
            fn $name() {
                case(
                    concat!("linux::", stringify!($name)),
                    $mode,
                    $binary,
                    cases!(@root $($root)?),
                );
            }
        )*};
        (@root) => { false };
        (@root root) => { true };
    }
    cases!(
        aio_calls => ("aio-calls", "aio"),
        aio_full => ("aio-full", "aio"),
        aio_getevents => ("aio-getevents", "aio"),
        aio_lifetime => ("aio-lifetime", "aio"),
        aio_mremap => ("aio-mremap", "aio"),
        aio_poll => ("aio-poll", "aio"),
        aio_reap => ("aio-reap", "aio"),
        aio_rw => ("aio-rw", "aio"),
        aio_signalfd => ("aio-signalfd", "aio"),
        aio_streams => ("aio-streams", "aio"),
        aio_timer => ("aio-timer", "aio"),
        bad_elf => ("bad-elf", "process"),
        // Its maps need CAP_BPF.
        bpf_batch => ("bpf-batch", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_bloom => ("bpf-bloom", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_calls => ("bpf-calls", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_elements => ("bpf-elements", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_ids => ("bpf-ids", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_lpm => ("bpf-lpm", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_lru => ("bpf-lru", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_maps => ("bpf-maps", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_memory => ("bpf-memory", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_mmap => ("bpf-mmap", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_pin => ("bpf-pin", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_prog_acqrel => ("bpf-prog-acqrel", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_atomic => ("bpf-prog-atomic", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_attach => ("bpf-prog-attach", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_calls => ("bpf-prog-calls", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_cfg => ("bpf-prog-cfg", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_classic => ("bpf-prog-classic", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_context => ("bpf-prog-context", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_corpus => ("bpf-prog-corpus", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_ldabs => ("bpf-prog-ldabs", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_load => ("bpf-prog-load", "bpf", root),
        // Its maps need CAP_BPF.
        bpf_prog_maps => ("bpf-prog-maps", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_rewrites => ("bpf-prog-rewrites", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_segments => ("bpf-prog-segments", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_tcp => ("bpf-prog-tcp", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_testrun => ("bpf-prog-testrun", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_udp => ("bpf-prog-udp", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_prog_verify => ("bpf-prog-verify", "bpf-prog", root),
        // Its maps need CAP_BPF.
        bpf_queue => ("bpf-queue", "bpf", root),
        clone_high_bits => ("clone-high-bits", "process"),
        clone_sighand => ("clone-sighand", "process"),
        clone_vm => ("clone-vm", "process"),
        command_missing => ("missing", "command"),
        command_output => ("output", "command"),
        command_pre_exec => ("pre-exec", "command"),
        command_pre_exec_missing => ("pre-exec-missing", "command"),
        command_spawn => ("spawn", "command"),
        command_status => ("status", "command"),
        dnotify_calls => ("dnotify-calls", "inotify"),
        dnotify_events => ("dnotify-events", "inotify"),
        // Writes fs.dir-notify-enable.
        dnotify_switch => ("dnotify-switch", "inotify", root),
        double_reap => ("double-reap", "process"),
        exec_fault => ("exec-fault", "process"),
        exec_thread => ("exec-thread", "process"),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_access_perm => ("fanotify-access-perm", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_aio_perm => ("fanotify-aio-perm", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_drop_caches => ("fanotify-drop-caches", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_events => ("fanotify-events", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_exec_perm => ("fanotify-exec-perm", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_fid => ("fanotify-fid", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_fifo_names => ("fanotify-fifo-names", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_init => ("fanotify-init", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_marks => ("fanotify-marks", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_merge_window => ("fanotify-merge-window", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_mount_events => ("fanotify-mount-events", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_mount_moves => ("fanotify-mount-moves", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_mounts => ("fanotify-mounts", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_open_exec => ("fanotify-open-exec", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_perm => ("fanotify-perm", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_pidfd => ("fanotify-pidfd", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_superblock_marks => ("fanotify-superblock-marks", "fanotify", root),
        // Its groups and marks need CAP_SYS_ADMIN.
        fanotify_unprivileged => ("fanotify-unprivileged", "fanotify", root),
        hw_probe_fxrstor => ("hw-probe-fxrstor", "single-step"),
        hw_probe_fxsave => ("hw-probe-fxsave", "single-step"),
        hw_probe_maskmovdqu => ("hw-probe-maskmovdqu", "single-step"),
        hw_probe_x87 => ("hw-probe-x87", "single-step"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        inet_diag_device => ("inet-diag-device", "inet-diag-device", root),
        inotify_calls => ("inotify-calls", "inotify"),
        inotify_content => ("inotify-content", "inotify"),
        inotify_directory => ("inotify-directory", "inotify"),
        inotify_exec => ("inotify-exec", "inotify"),
        inotify_exec_order => ("inotify-exec-order", "inotify"),
        inotify_fifo => ("inotify-fifo", "inotify"),
        inotify_fifo_moved => ("inotify-fifo-moved", "inotify"),
        inotify_files => ("inotify-files", "inotify"),
        inotify_flags => ("inotify-flags", "inotify"),
        inotify_handles => ("inotify-handles", "inotify"),
        inotify_held => ("inotify-held", "inotify"),
        inotify_home => ("inotify-home", "inotify"),
        inotify_instance => ("inotify-instance", "inotify"),
        inotify_interpreter => ("inotify-interpreter", "inotify"),
        inotify_moved => ("inotify-moved", "inotify"),
        inotify_open_handles => ("inotify-open-handles", "inotify"),
        inotify_overflow => ("inotify-overflow", "inotify"),
        inotify_read => ("inotify-read", "inotify"),
        inotify_running => ("inotify-running", "inotify"),
        // Mounts a tmpfs in a mount namespace of its own.
        inotify_unmount => ("inotify-unmount", "inotify", root),
        inotify_wait => ("inotify-wait", "inotify"),
        int3 => ("int3", "single-step"),
        invalid_clone => ("invalid-clone", "process"),
        invalid_wait => ("invalid-wait", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        ip_options => ("ip-options", "ip-options", root),
        // Sets up keyrings as root and becomes other users.
        keys_calls => ("keys-calls", "keys", root),
        // Sets up keyrings as root and becomes other users.
        keys_keyrings => ("keys-keyrings", "keys", root),
        // Sets up keyrings as root and becomes other users.
        keys_parent => ("keys-parent", "keys", root),
        // Sets up keyrings as root and becomes other users.
        keys_permissions => ("keys-permissions", "keys", root),
        // Sets up keyrings as root and becomes other users.
        keys_threads => ("keys-threads", "keys", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        mapped_source => ("mapped-source", "mapped-source", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_accounts => ("mqueue-accounts", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_calls => ("mqueue-calls", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_congested => ("mqueue-congested", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_dev => ("mqueue-dev", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_files => ("mqueue-files", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_fork => ("mqueue-fork", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_limits => ("mqueue-limits", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_links => ("mqueue-links", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_notify => ("mqueue-notify", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_poll => ("mqueue-poll", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_room => ("mqueue-room", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_sysctl => ("mqueue-sysctl", "mqueue", root),
        // Makes IPC and network namespaces of its own, for the namespace's default limits, and
        // becomes an unprivileged user.
        mqueue_wait => ("mqueue-wait", "mqueue", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        multicast_groups => ("multicast-groups", "multicast-groups", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        multicast_groups6 => ("multicast-groups6", "multicast-groups6", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        multicast_sources => ("multicast-sources", "multicast-sources", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        net_dev_counters => ("net-dev-counters", "net-dev-counters", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        net_dev_tcp => ("net-dev-tcp", "net-dev-tcp", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_link_netns => ("netlink-link-netns", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_listen_all_nsid => ("netlink-listen-all-nsid", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_no_enobufs => ("netlink-no-enobufs", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_nsid => ("netlink-nsid", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_nsid_gone => ("netlink-nsid-gone", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_nsid_write => ("netlink-nsid-write", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_option_flags => ("netlink-option-flags", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_pktinfo => ("netlink-pktinfo", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_target_netnsid => ("netlink-target-netnsid", "netlink-options", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        netlink_write_credentials => ("netlink-write-credentials", "netlink-options", root),
        no_child => ("no-child", "process"),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_calls => ("perf-calls", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_clock_samples => ("perf-clock-samples", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_counts => ("perf-counts", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_cpu_samples => ("perf-cpu-samples", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_exec => ("perf-exec", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_fault_signals => ("perf-fault-signals", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_gup => ("perf-gup", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_inherit => ("perf-inherit", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_inherit_stat => ("perf-inherit-stat", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_mmap => ("perf-mmap", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_output => ("perf-output", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_prctl => ("perf-prctl", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_ring_gup => ("perf-ring-gup", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_sample => ("perf-sample", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band => ("perf-side-band", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band_comm => ("perf-side-band-comm", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band_cpu => ("perf-side-band-cpu", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band_exec => ("perf-side-band-exec", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band_namespaces => ("perf-side-band-namespaces", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_side_band_switch => ("perf-side-band-switch", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_software => ("perf-software", "perf", root),
        // Its events need CAP_PERFMON, and it writes a sysctl.
        perf_throttle => ("perf-throttle", "perf", root),
        // Its events of the kernel and of CPUs need CAP_PERFMON.
        perf_wakeup => ("perf-wakeup", "perf", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        proc_net => ("proc-net", "proc-net", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        proc_net_groups => ("proc-net-groups", "proc-net-groups", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        proc_net_sockets => ("proc-net-sockets", "proc-net-sockets", root),
        processes_access => ("access", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_address_lifetimes => ("address-lifetimes", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_addresses => ("addresses", "process", root),
        // Makes a user namespace with its capabilities before it becomes an unprivileged user:
        // Ubuntu's AppArmor gives none to one an unprivileged user makes.
        processes_admin => ("admin", "process", root),
        processes_affinity => ("affinity", "process"),
        processes_alarm_clocks => ("alarm-clocks", "process"),
        processes_anon_reopen => ("anon-reopen", "process"),
        processes_anon_thp_placement => ("anon-thp-placement", "process"),
        processes_autoreap => ("autoreap", "process"),
        processes_beneath => ("beneath", "process"),
        processes_binds => ("binds", "process"),
        // Changes IDs as root.
        processes_capabilities => ("capabilities", "process", root),
        processes_chown => ("chown", "process"),
        processes_chroot => ("chroot", "process"),
        processes_chroot_names => ("chroot-names", "process", root),
        processes_clear_refs => ("clear-refs", "process", root),
        processes_cloexec => ("cloexec", "process"),
        processes_clone3 => ("clone3", "process"),
        processes_context_switches => ("context-switches", "process"),
        processes_contexts => ("contexts", "process"),
        // Changes IDs as root.
        processes_core_credentials => ("core-credentials", "process", root),
        processes_core_dump => ("core-dump", "process"),
        processes_core_dump_faults => ("core-dump-faults", "process"),
        processes_core_filter => ("core-filter", "process"),
        processes_core_mappings => ("core-mappings", "process"),
        processes_cpu_clock_ids => ("cpu-clock-ids", "process"),
        processes_cpu_clock_running => ("cpu-clock-running", "process"),
        processes_cpu_clocks => ("cpu-clocks", "process"),
        processes_cpu_itimer => ("cpu-itimer", "process"),
        processes_cpu_sleep => ("cpu-sleep", "process"),
        processes_cpu_sleep_others => ("cpu-sleep-others", "process"),
        processes_cpu_state => ("cpu-state", "process"),
        processes_cpu_timer => ("cpu-timer", "process"),
        processes_cpu_timer_others => ("cpu-timer-others", "process"),
        // Changes IDs as root.
        processes_credentials => ("credentials", "process", root),
        processes_dev_shm => ("dev-shm", "process"),
        processes_dgram => ("dgram", "process"),
        processes_dontneed_read_only_segment => ("dontneed-read-only-segment", "process"),
        processes_dump_min_sysctls => ("dump-min-sysctls", "process"),
        processes_dynamic => ("dynamic", "dynamic"),
        processes_dynamic_exec => ("dynamic-exec", "process", root),
        processes_dynamic_glibc => ("dynamic-glibc", "dynamic-glibc"),
        processes_dynamic_no_pie => ("dynamic-no-pie", "dynamic-no-pie"),
        processes_enoent => ("enoent", "process"),
        processes_etxtbsy => ("etxtbsy", "process"),
        processes_exec => ("exec", "process"),
        processes_exec_names => ("exec-names", "process"),
        processes_exec_pending => ("exec-pending", "exec-pending"),
        processes_exec_truncated => ("exec-truncated", "process"),
        processes_execveat => ("execveat", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_address_lifetimes => ("ext-ack-address-lifetimes", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_addresses => ("ext-ack-addresses", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_generic_netlink => ("ext-ack-generic-netlink", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_link_attributes => ("ext-ack-link-attributes", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_monitor => ("ext-ack-monitor", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_neighbour_changes => ("ext-ack-neighbour-changes", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_neighbour_requests => ("ext-ack-neighbour-requests", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_netlink => ("ext-ack-netlink", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_netlink_strict => ("ext-ack-netlink-strict", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_route_dump => ("ext-ack-route-dump", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_route_input => ("ext-ack-route-input", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_route_metrics => ("ext-ack-route-metrics", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_route_selectors => ("ext-ack-route-selectors", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_ext_ack_routes => ("ext-ack-routes", "process", root),
        processes_fault_around => ("fault-around", "process"),
        processes_fd_attributes => ("fd-attributes", "process"),
        processes_fifo => ("fifo", "process"),
        // Changes IDs as root.
        processes_file_capabilities => ("file-capabilities", "process", root),
        processes_file_code => ("file-code", "process"),
        // Writes fs.leases-enable and fs.lease-break-time, then becomes an unprivileged user.
        processes_file_leases => ("file-leases", "process", root),
        processes_file_mapping_end => ("file-mapping-end", "process"),
        processes_fionread => ("fionread", "process"),
        processes_fork => ("fork", "process"),
        processes_fork_copy_on_write => ("fork-copy-on-write", "process"),
        processes_fork_page_tables => ("fork-page-tables", "process"),
        processes_fsize_limit => ("fsize-limit", "process"),
        processes_futex2 => ("futex2", "process"),
        processes_futex_requeue => ("futex-requeue", "process"),
        processes_futex_shared => ("futex-shared", "process"),
        processes_futex_wake_op => ("futex-wake-op", "process"),
        processes_generated_binds => ("generated-binds", "process"),
        processes_generated_changes => ("generated-changes", "process"),
        processes_generated_enotdir => ("generated-enotdir", "process"),
        processes_generated_link_names => ("generated-link-names", "process"),
        // Makes, removes and renames names in /proc as root, then becomes nobody.
        processes_generated_name_errors => ("generated-name-errors", "process", root),
        processes_generated_noexec => ("generated-noexec", "process"),
        processes_generated_rooted_links => ("generated-rooted-links", "process"),
        processes_generic_ioctl => ("generic-ioctl", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_generic_netlink => ("generic-netlink", "process", root),
        processes_gone_leader_files => ("gone-leader-files", "process"),
        processes_grows_down => ("grows-down", "process"),
        processes_hiwater => ("hiwater", "process"),
        processes_ids => ("ids", "process"),
        processes_ignore_discards => ("ignore-discards", "process"),
        processes_ignored_signal_wait => ("ignored-signal-wait", "process"),
        processes_ignored_start => ("ignored-start", "ignored-start"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_inet_diag => ("inet-diag", "process", root),
        processes_io_uring => ("io-uring", "process"),
        processes_io_uring_buffers => ("io-uring-buffers", "process"),
        processes_io_uring_buffers2 => ("io-uring-buffers2", "process"),
        processes_io_uring_cancel => ("io-uring-cancel", "process"),
        processes_io_uring_exit => ("io-uring-exit", "process"),
        processes_io_uring_files => ("io-uring-files", "process"),
        processes_io_uring_fs => ("io-uring-fs", "process"),
        processes_io_uring_held_buffer => ("io-uring-held-buffer", "process"),
        processes_io_uring_held_tag => ("io-uring-held-tag", "process"),
        processes_io_uring_message => ("io-uring-message", "process"),
        processes_io_uring_min_wait => ("io-uring-min-wait", "process"),
        processes_io_uring_multishot => ("io-uring-multishot", "process"),
        processes_io_uring_net => ("io-uring-net", "process"),
        processes_io_uring_personality => ("io-uring-personality", "process"),
        processes_io_uring_pinned => ("io-uring-pinned", "process"),
        processes_io_uring_placement => ("io-uring-placement", "process"),
        processes_io_uring_poll => ("io-uring-poll", "process"),
        processes_io_uring_poll_add => ("io-uring-poll-add", "process"),
        processes_io_uring_restrictions => ("io-uring-restrictions", "process"),
        processes_io_uring_ring_fds => ("io-uring-ring-fds", "process"),
        processes_io_uring_ring_poll => ("io-uring-ring-poll", "process"),
        processes_io_uring_splice => ("io-uring-splice", "process"),
        processes_io_uring_task_work => ("io-uring-task-work", "process"),
        processes_io_uring_timeout => ("io-uring-timeout", "process"),
        processes_io_uring_transfers => ("io-uring-transfers", "process"),
        processes_ipc_sysctl => ("ipc-sysctl", "process", root),
        processes_itimer => ("itimer", "process"),
        processes_job_stop => ("job-stop", "process"),
        processes_kcmp => ("kcmp", "process"),
        processes_kernel_info => ("kernel-info", "process"),
        processes_kernel_sysctl => ("kernel-sysctl", "process", root),
        processes_kill_before_sleep => ("kill-before-sleep", "process"),
        processes_kill_group => ("kill-group", "process"),
        processes_landlock => ("landlock", "process"),
        processes_late_handler => ("late-handler", "process"),
        processes_leader_exit_status => ("leader-exit-status", "process"),
        processes_leader_zombie_task => ("leader-zombie-task", "process"),
        // Changes IDs as root.
        processes_limit_permissions => ("limit-permissions", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_link_attributes => ("link-attributes", "process", root),
        processes_link_path => ("link-path", "process"),
        processes_listings => ("listings", "process"),
        processes_loadavg_running => ("loadavg-running", "process"),
        processes_lock_state => ("lock-state", "process"),
        processes_madvise_advice => ("madvise-advice", "process"),
        processes_madvise_collapse => ("madvise-collapse", "process"),
        processes_madvise_collapse_shmem => ("madvise-collapse-shmem", "process"),
        processes_madvise_fork => ("madvise-fork", "process"),
        processes_madvise_guard => ("madvise-guard", "process"),
        processes_madvise_remove => ("madvise-remove", "process"),
        processes_map_count => ("map-count", "process", root),
        // Reads maps across a chroot.
        processes_maps_root => ("maps-root", "process", root),
        processes_maxrss => ("maxrss", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_mctp_sockets => ("mctp-sockets", "process", root),
        processes_membarrier => ("membarrier", "process"),
        processes_memfd_hugetlb => ("memfd-hugetlb", "process"),
        processes_memfd_secret => ("memfd-secret", "process"),
        processes_memfd_secret_memlock => ("memfd-secret-memlock", "process"),
        processes_memory_locks => ("memory-locks", "process"),
        processes_mempolicy => ("mempolicy", "process"),
        processes_mincore => ("mincore", "process"),
        processes_mlock_private_copy => ("mlock-private-copy", "process"),
        processes_mmap_32bit => ("mmap-32bit", "process"),
        processes_mmap_hugetlb => ("mmap-hugetlb", "process"),
        processes_mmap_low => ("mmap-low", "process"),
        processes_mmap_types => ("mmap-types", "process"),
        processes_mmsg => ("mmsg", "process"),
        processes_modify_ldt => ("modify-ldt", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_monitor => ("monitor", "process", root),
        // Runs a program of another user's on its own mounts.
        processes_mount_flags => ("mount-flags", "process", root),
        processes_mounts => ("mounts", "process"),
        processes_moves => ("moves", "process"),
        processes_mprotect_checks => ("mprotect-checks", "process"),
        processes_mrelease => ("mrelease", "process"),
        processes_mrelease_fatal => ("mrelease-fatal", "process"),
        processes_mseal => ("mseal", "process"),
        // Makes an IPC namespace of its own, for its counts.
        processes_msg => ("msg", "process", root),
        processes_named_fifo_statfs => ("named-fifo-statfs", "process"),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_namespaces => ("namespaces", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_neighbour_ageing => ("neighbour-ageing", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_neighbour_changes => ("neighbour-changes", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_neighbour_requests => ("neighbour-requests", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_neighbours => ("neighbours", "process", root),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_net_namespaces => ("net-namespaces", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_net_sysctl => ("net-sysctl", "process", root),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_netlink => ("netlink", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_netlink_strict => ("netlink-strict", "process", root),
        processes_nofile_limit => ("nofile-limit", "process"),
        processes_offset => ("offset", "process"),
        processes_old_forms => ("old-forms", "process"),
        processes_old_times => ("old-times", "process"),
        processes_open_flags => ("open-flags", "process"),
        processes_orphaned_group => ("orphaned-group", "process"),
        processes_page_faults => ("page-faults", "process"),
        processes_page_faults_live => ("page-faults-live", "process"),
        processes_page_nodes => ("page-nodes", "process"),
        // Becomes an unprivileged user.
        processes_pagemap => ("pagemap", "process", root),
        processes_path_flags => ("path-flags", "process", root),
        processes_pdeath_thread => ("pdeath-thread", "pdeath-thread"),
        processes_pdeathsig => ("pdeathsig", "process"),
        // Changes IDs as root.
        processes_peer_credentials => ("peer-credentials", "process", root),
        // Changes IDs as root.
        processes_permissions => ("permissions", "process", root),
        processes_personality => ("personality", "process"),
        // Maps page 0.
        processes_personality_layout => ("personality-layout", "process", root),
        processes_pgid => ("pgid", "process"),
        processes_pgid_exec => ("pgid-exec", "process"),
        // Makes PID namespaces.
        processes_pid_namespace => ("pid-namespace", "process", root),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_pid_namespaces => ("pid-namespaces", "process", root),
        // Makes PID namespaces.
        processes_pid_set_tid => ("pid-set-tid", "process", root),
        processes_pidfd_fdinfo => ("pidfd-fdinfo", "process"),
        processes_pidfd_getfd => ("pidfd-getfd", "process"),
        processes_pio => ("pio", "process"),
        processes_pipe_async => ("pipe-async", "process"),
        processes_pipe_packets => ("pipe-packets", "process"),
        processes_pipe_reopen => ("pipe-reopen", "process"),
        processes_pipe_size => ("pipe-size", "process"),
        processes_pkey => ("pkey", "process"),
        processes_poll => ("poll", "process"),
        processes_poll_default => ("poll-default", "process"),
        processes_port_access => ("port-access", "process"),
        processes_posix_timer => ("posix-timer", "process"),
        processes_prctl => ("prctl", "process"),
        processes_priority => ("priority", "process"),
        processes_private => ("private", "process"),
        processes_private_file_mapping => ("private-file-mapping", "process"),
        processes_proc_at_read => ("proc-at-read", "process"),
        processes_proc_block_size => ("proc-block-size", "process"),
        // Makes user namespaces, then becomes an unprivileged user.
        processes_proc_cgroup_ids => ("proc-cgroup-ids", "process", root),
        processes_proc_children => ("proc-children", "process"),
        processes_proc_cpuinfo => ("proc-cpuinfo", "process"),
        // Reads links from a chroot of its own mount namespace.
        processes_proc_fd_links => ("proc-fd-links", "process", root),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_io => ("proc-io", "process", root),
        processes_proc_links => ("proc-links", "process"),
        processes_proc_locks => ("proc-locks", "process"),
        // Changes a set login user, then becomes an unprivileged user.
        processes_proc_login => ("proc-login", "process", root),
        processes_proc_maps => ("proc-maps", "process", root),
        processes_proc_mem => ("proc-mem", "process", root),
        // Sets an oom_score_adj below 0, then becomes an unprivileged user.
        processes_proc_oom => ("proc-oom", "process", root),
        // Goes through a process's descriptors as another user.
        processes_proc_other_fd_paths => ("proc-other-fd-paths", "process", root),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_other_fds => ("proc-other-fds", "process", root),
        processes_proc_other_files => ("proc-other-files", "process"),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_other_limits => ("proc-other-limits", "process", root),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_other_maps => ("proc-other-maps", "process", root),
        processes_proc_other_mounts => ("proc-other-mounts", "process"),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_other_pagemap => ("proc-other-pagemap", "process", root),
        processes_proc_own_at_read => ("proc-own-at-read", "process"),
        processes_proc_own_files => ("proc-own-files", "process"),
        // Reads a process's maps, descriptors, auxv, pagemap or io as other users, or makes it
        // another user's.
        processes_proc_owner_rename => ("proc-owner-rename", "process", root),
        // Becomes an unprivileged user.
        processes_proc_owners => ("proc-owners", "process", root),
        // Reads a process's personality and wchan as other users.
        processes_proc_personality_wchan => ("proc-personality-wchan", "process", root),
        processes_proc_self_link => ("proc-self-link", "process"),
        processes_proc_sizes => ("proc-sizes", "process"),
        processes_proc_stat_counters => ("proc-stat-counters", "process"),
        processes_proc_stat_counts => ("proc-stat-counts", "process"),
        // Reads a child's stat as another user.
        processes_proc_stat_exit_code => ("proc-stat-exit-code", "process", root),
        // Sets real-time and deadline policies.
        processes_proc_stat_sched => ("proc-stat-sched", "process", root),
        processes_proc_status => ("proc-status", "process"),
        // Reads a child's syscall file as another user.
        processes_proc_syscall => ("proc-syscall", "process", root),
        processes_proc_system => ("proc-system", "process"),
        // Sets a real-time policy, then becomes an unprivileged user.
        processes_proc_timerslack => ("proc-timerslack", "process", root),
        processes_process_vm => ("process-vm", "process"),
        processes_propagation => ("propagation", "process"),
        processes_ptrace_stop_exit_code => ("ptrace-stop-exit-code", "process"),
        processes_ptrace_stop_signal => ("ptrace-stop-signal", "process"),
        processes_read_modify_write => ("read-modify-write", "read-modify-write"),
        processes_remounts => ("remounts", "process"),
        processes_rename_names => ("rename-names", "process"),
        processes_reparent => ("reparent", "process"),
        processes_rlimit => ("rlimit", "process"),
        processes_rlimit_cpu => ("rlimit-cpu", "process"),
        processes_robust_list => ("robust-list", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_route_dump => ("route-dump", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_route_input => ("route-input", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_route_metrics => ("route-metrics", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_route_selectors => ("route-selectors", "process", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_routes => ("routes", "process", root),
        processes_rseq => ("rseq", "process"),
        processes_sa_immutable => ("sa-immutable", "sa-immutable"),
        processes_scheduling => ("scheduling", "process"),
        // Sets real-time and deadline policies.
        processes_scheduling_set => ("scheduling-set", "process", root),
        processes_scm_garbage => ("scm-garbage", "process"),
        processes_scm_rights => ("scm-rights", "process"),
        // Changes IDs as root.
        processes_script_exec => ("script-exec", "process", root),
        processes_seccomp => ("seccomp", "process"),
        processes_seccomp_notify => ("seccomp-notify", "process"),
        processes_segment_registers => ("segment-registers", "process"),
        processes_select => ("select", "process"),
        processes_sem => ("sem", "process"),
        processes_seqpacket => ("seqpacket", "process"),
        processes_session => ("session", "process"),
        // Changes IDs as root.
        processes_set_id_writes => ("set-id-writes", "process", root),
        processes_setattrs => ("setattrs", "process"),
        processes_setfl_checks => ("setfl-checks", "process"),
        processes_setfl_kinds => ("setfl-kinds", "process"),
        // Changes IDs as root.
        processes_setuid => ("setuid", "process", root),
        processes_shared => ("shared", "process"),
        processes_shared_file_mapping => ("shared-file-mapping", "process"),
        processes_shm => ("shm", "process"),
        processes_shm_hugetlb => ("shm-hugetlb", "process"),
        processes_shmem_fault_charge => ("shmem-fault-charge", "process"),
        processes_shmem_populate => ("shmem-populate", "process"),
        // Changes IDs as root.
        processes_sigio_owner => ("sigio-owner", "sigio-owner", root),
        processes_signal => ("signal", "process"),
        processes_signal_io => ("signal-io", "process"),
        processes_signal_io_wait => ("signal-io-wait", "process"),
        // Changes IDs as root.
        processes_signal_permissions => ("signal-permissions", "process", root),
        processes_signal_restart => ("signal-restart", "process"),
        processes_signal_sender => ("signal-sender", "process"),
        processes_signal_threads => ("signal-threads", "signal-threads"),
        processes_sigqueue => ("sigqueue", "process"),
        processes_sigsuspend => ("sigsuspend", "process"),
        processes_sigsuspend_stop => ("sigsuspend-stop", "process"),
        processes_smaps_flags => ("smaps-flags", "process"),
        processes_smaps_rollup => ("smaps-rollup", "process"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_sock_diag => ("sock-diag", "process", root),
        processes_socket_addresses => ("socket-addresses", "process"),
        processes_socket_credentials => ("socket-credentials", "process"),
        processes_socket_flags => ("socket-flags", "process"),
        processes_socket_oob => ("socket-oob", "process"),
        processes_socket_options => ("socket-options", "process"),
        // Changes IDs as root.
        processes_socket_owners => ("socket-owners", "process", root),
        processes_socket_parts => ("socket-parts", "process"),
        processes_socket_passrights => ("socket-passrights", "process"),
        processes_socket_passsec => ("socket-passsec", "process"),
        processes_socket_peek_off => ("socket-peek-off", "process"),
        processes_socket_pidfd => ("socket-pidfd", "process"),
        processes_socket_rcvlowat => ("socket-rcvlowat", "process"),
        processes_socket_timeouts => ("socket-timeouts", "process"),
        processes_socket_timestamp => ("socket-timestamp", "process"),
        processes_socket_timestamping => ("socket-timestamping", "process"),
        processes_sparse => ("sparse", "process"),
        processes_statfs => ("statfs", "process"),
        processes_status_memory => ("status-memory", "process"),
        processes_status_space => ("status-space", "process"),
        processes_statx_attributes => ("statx-attributes", "process"),
        processes_stdio_flags => ("stdio-flags", "process"),
        processes_stop_cont_handler => ("stop-cont-handler", "process"),
        processes_stop_restart => ("stop-restart", "process"),
        processes_sysctl_constants => ("sysctl-constants", "process"),
        processes_sysctl_limits => ("sysctl-limits", "process"),
        processes_sysinfo => ("sysinfo", "process"),
        // Makes IPC and PID namespaces, for its IDs and PIDs.
        processes_sysvipc_proc => ("sysvipc-proc", "process", root),
        processes_thread_caps_status => ("thread-caps-status", "process"),
        processes_thread_name => ("thread-name", "process"),
        processes_thread_own_counters => ("thread-own-counters", "process"),
        processes_time_calls => ("time-calls", "process"),
        processes_time_set => ("time-set", "process"),
        processes_timer_limits => ("timer-limits", "process"),
        processes_timer_thread => ("timer-thread", "process"),
        // Makes a fanotify group and a userfaultfd for the kernel's faults.
        processes_timer_waits_default => ("timer-waits-default", "timer-waits", root),
        // Makes a fanotify group and a userfaultfd for the kernel's faults.
        processes_timer_waits_plain => ("timer-waits-plain", "timer-waits", root),
        // Makes a fanotify group and a userfaultfd for the kernel's faults.
        processes_timer_waits_restart => ("timer-waits-restart", "timer-waits", root),
        processes_timerfd => ("timerfd", "process"),
        processes_tmpfs_huge => ("tmpfs-huge", "process"),
        processes_tmpfs_huge_placement => ("tmpfs-huge-placement", "process"),
        processes_tmpfs_limits => ("tmpfs-limits", "process"),
        processes_traced_rusage => ("traced-rusage", "process"),
        processes_tree_namespace => ("tree-namespace", "process"),
        processes_trees => ("trees", "process"),
        processes_uname => ("uname", "process"),
        processes_unix_abstract => ("unix-abstract", "process"),
        processes_unix_datagram => ("unix-datagram", "process"),
        processes_unix_dgram_disconnect => ("unix-dgram-disconnect", "process"),
        processes_unix_dgram_sndbuf => ("unix-dgram-sndbuf", "process"),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_unix_interfaces => ("unix-interfaces", "process", root),
        processes_unix_path => ("unix-path", "process"),
        processes_unix_peercred => ("unix-peercred", "process"),
        processes_unix_socketpair => ("unix-socketpair", "process"),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_unshare => ("unshare", "process", root),
        processes_usage => ("usage", "process"),
        // Makes namespaces, and its checks depend on CAP_SYS_ADMIN.
        processes_user_namespaces => ("user-namespaces", "process", root),
        processes_userns_nondumpable_read => ("userns-nondumpable-read", "process"),
        processes_uts_sysctl => ("uts-sysctl", "process", root),
        processes_uts_sysctl_poll => ("uts-sysctl-poll", "process", root),
        processes_vdso_mappings => ("vdso-mappings", "process"),
        processes_vector_flags => ("vector-flags", "process"),
        processes_vma_merges => ("vma-merges", "process"),
        processes_vma_names => ("vma-names", "process"),
        processes_vsyscall_entries => ("vsyscall-entries", "process"),
        processes_vsyscall_immutable => ("vsyscall-immutable", "sa-immutable"),
        processes_waitid => ("waitid", "process"),
        processes_wnohang => ("wnohang", "process"),
        processes_x87 => ("x87", "process"),
        processes_x87_arithmetic => ("x87-arithmetic", "process"),
        processes_x87_decimal => ("x87-decimal", "x87"),
        processes_x87_exceptions => ("x87-exceptions", "x87"),
        processes_x87_state => ("x87-state", "x87"),
        processes_x87_transcendental => ("x87-transcendental", "x87"),
        processes_yama => ("yama", "process"),
        processes_zombie_ns_links => ("zombie-ns-links", "process"),
        ptrace_arch_rseq => ("ptrace-arch-rseq", "ptrace-requests"),
        ptrace_attach => ("ptrace-attach", "ptrace"),
        ptrace_attach_stopped => ("ptrace-attach-stopped", "ptrace"),
        ptrace_clone => ("ptrace-clone", "ptrace-syscalls"),
        ptrace_detach => ("ptrace-detach", "ptrace"),
        ptrace_events => ("ptrace-events", "ptrace-syscalls"),
        ptrace_exit_core => ("ptrace-exit-core", "ptrace-requests"),
        ptrace_forced_edges => ("ptrace-forced-edges", "single-step"),
        ptrace_forced_frame => ("ptrace-forced-frame", "single-step"),
        ptrace_held => ("ptrace-held", "ptrace-syscalls"),
        ptrace_hw_breakpoint => ("ptrace-hw-breakpoint", "single-step"),
        ptrace_hw_implicit => ("ptrace-hw-implicit", "single-step"),
        ptrace_listen => ("ptrace-listen", "ptrace-requests"),
        ptrace_memory => ("ptrace-memory", "ptrace"),
        ptrace_regs => ("ptrace-regs", "ptrace"),
        ptrace_restart_codes => ("ptrace-restart-codes", "ptrace-requests"),
        ptrace_seccomp => ("ptrace-seccomp", "ptrace-requests"),
        ptrace_seize => ("ptrace-seize", "ptrace"),
        ptrace_selectors => ("ptrace-selectors", "ptrace-requests"),
        ptrace_sibling => ("ptrace-sibling", "ptrace"),
        ptrace_sigmask => ("ptrace-sigmask", "ptrace-requests"),
        ptrace_signals => ("ptrace-signals", "ptrace"),
        ptrace_singlestep => ("ptrace-singlestep", "single-step"),
        ptrace_strace => ("ptrace-strace", "ptrace-syscalls"),
        ptrace_suspend_seccomp => ("ptrace-suspend-seccomp", "ptrace-requests"),
        ptrace_syscall_signal => ("ptrace-syscall-signal", "ptrace-requests"),
        ptrace_syscall_signal_thread => ("ptrace-syscall-signal-thread", "ptrace-requests"),
        ptrace_sysemu => ("ptrace-sysemu", "ptrace-syscalls"),
        ptrace_thread => ("ptrace-thread", "ptrace"),
        ptrace_thread_exec => ("ptrace-thread-exec", "ptrace-syscalls"),
        ptrace_traceme => ("ptrace-traceme", "ptrace"),
        ptrace_tracer_exit => ("ptrace-tracer-exit", "ptrace"),
        ptrace_wait => ("ptrace-wait", "ptrace"),
        pty_async => ("pty-async", "pty"),
        pty_canonical => ("pty-canonical", "pty"),
        pty_hangup => ("pty-hangup", "pty"),
        pty_open => ("pty-open", "pty"),
        pty_packet => ("pty-packet", "pty"),
        pty_proc_stat => ("pty-proc-stat", "pty"),
        pty_raw => ("pty-raw", "pty"),
        pty_session => ("pty-session", "pty"),
        pty_signals => ("pty-signals", "pty"),
        pty_termio => ("pty-termio", "pty"),
        pty_termios => ("pty-termios", "pty"),
        // Needs root's capabilities.
        pty_vhangup => ("pty-vhangup", "pty", root),
        signalfd_calls => ("signalfd-calls", "signalfd"),
        signalfd_child => ("signalfd-child", "signalfd"),
        signalfd_edges => ("signalfd-edges", "signalfd"),
        signalfd_epoll => ("signalfd-epoll", "signalfd"),
        signalfd_fdinfo => ("signalfd-fdinfo", "signalfd"),
        signalfd_fork => ("signalfd-fork", "signalfd"),
        signalfd_interrupt => ("signalfd-interrupt", "signalfd"),
        signalfd_shared_locks => ("signalfd-shared-locks", "signalfd"),
        signalfd_threads => ("signalfd-threads", "signalfd"),
        trap_flag => ("trap-flag", "single-step"),
        trap_flag_rep => ("trap-flag-rep", "single-step"),
        trap_flag_signal => ("trap-flag-signal", "single-step"),
        trap_flag_syscall => ("trap-flag-syscall", "single-step"),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        udp_disconnect => ("udp-disconnect", "udp-disconnect", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_calls => ("userfaultfd-calls", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_events => ("userfaultfd-events", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_faults => ("userfaultfd-faults", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_gup => ("userfaultfd-gup", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_held => ("userfaultfd-held", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_major => ("userfaultfd-major", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_minor => ("userfaultfd-minor", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_move => ("userfaultfd-move", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_poison => ("userfaultfd-poison", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_scan => ("userfaultfd-scan", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_shared => ("userfaultfd-shared", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_shmem => ("userfaultfd-shmem", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_sigbus => ("userfaultfd-sigbus", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_signals => ("userfaultfd-signals", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_wp => ("userfaultfd-wp", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_wp_async => ("userfaultfd-wp-async", "userfaultfd", root),
        // Its files take the kernel's faults too (CAP_SYS_PTRACE).
        userfaultfd_wp_shmem => ("userfaultfd-wp-shmem", "userfaultfd", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_answers => ("veth-answers", "veth-answers", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_bindtodevice => ("veth-bindtodevice", "veth-bindtodevice", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_broadcast => ("veth-broadcast", "veth-broadcast", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_broadcast_source => ("veth-broadcast-source", "veth-broadcast-source", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_dev_mcast => ("veth-dev-mcast", "veth-dev-mcast", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_filter => ("veth-filter", "veth-filter", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_hash_policy => ("veth-hash-policy", "veth-hash-policy", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_hash_seed => ("veth-hash-seed", "veth-hash-seed", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_icmp6_hop => ("veth-icmp6-hop", "veth-icmp6-hop", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_icmp_hop => ("veth-icmp-hop", "veth-icmp-hop", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_igmp_neighbours => ("veth-igmp-neighbours", "veth-igmp-neighbours", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_iif => ("veth-iif", "veth-iif", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv4 => ("veth-ipv4", "veth-ipv4", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv4_ecmp => ("veth-ipv4-ecmp", "veth-ipv4-ecmp", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv4_gateway => ("veth-ipv4-gateway", "veth-ipv4-gateway", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv4_hash => ("veth-ipv4-hash", "veth-ipv4-hash", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv4_via => ("veth-ipv4-via", "veth-ipv4-via", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6 => ("veth-ipv6", "veth-ipv6", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_accept => ("veth-ipv6-accept", "veth-ipv6-accept", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_anycast => ("veth-ipv6-anycast", "veth-ipv6-anycast", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_ecmp => ("veth-ipv6-ecmp", "veth-ipv6-ecmp", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_gateway => ("veth-ipv6-gateway", "veth-ipv6-gateway", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_kept => ("veth-ipv6-kept", "veth-ipv6-kept", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_multicast => ("veth-ipv6-multicast", "veth-ipv6-multicast", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_oif => ("veth-ipv6-oif", "veth-ipv6-oif", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_own_neighbours => ("veth-ipv6-own-neighbours", "veth-ipv6-own-neighbours", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_scope => ("veth-ipv6-scope", "veth-ipv6-scope", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_solicited_routers => ("veth-ipv6-solicited-routers", "veth-ipv6-solicited-routers", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_source => ("veth-ipv6-source", "veth-ipv6-source", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_ipv6_traffic => ("veth-ipv6-traffic", "veth-ipv6-traffic", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_links => ("veth-links", "veth", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_multicast => ("veth-multicast", "veth-multicast", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_neigh => ("veth-neigh", "veth-neigh", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_traffic => ("veth-traffic", "veth-traffic", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_unicast_if => ("veth-unicast-if", "veth-unicast-if", root),
        // Makes network namespaces, and its checks depend on CAP_SYS_ADMIN.
        veth_use_neigh => ("veth-use-neigh", "veth-use-neigh", root),
        vfork_exec => ("vfork-exec", "process"),
        vfork_exit => ("vfork-exit", "process"),
        vfork_state => ("vfork-state", "process"),
        wait_any => ("wait-any", "process"),
        wait_fault => ("wait-fault", "process"),
        wait_interrupt => ("wait-interrupt", "process"),
        wait_restart => ("wait-restart", "process"),
        wait_specific => ("wait-specific", "process"),
    );
}
