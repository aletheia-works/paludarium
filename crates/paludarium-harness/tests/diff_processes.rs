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
    use paludarium_harness::{Outcome, TIMEOUT, compare, run_native_within, workspace_root};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    fn running_as_root() -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
    }

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
        // Linux writes the core the cases read only with the kernel's
        // default core_pattern, which CI sets.
        if mode == "core-dump"
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
        let watchdog = if mode == "neighbour-ageing" { 150 } else { 60 };
        support::bounded(test, watchdog, || {
            let program = dir.join(binary);
            let self_path = program.to_str().unwrap().to_owned();
            let args = [mode.to_owned(), self_path.clone()];
            // The credentials, permissions, setuid, signal-permissions,
            // limit-permissions, peer-credentials, core-credentials,
            // set-id-writes, socket-owners, capabilities, file-capabilities and script-exec cases
            // change IDs as root, pty-vhangup needs root's capabilities and
            // pid-namespace and pid-set-tid make PID namespaces, so Linux runs
            // them as root, through sudo when the tests do not run as root; so
            // do the unshare, namespaces, *-namespaces, netlink, unix-interfaces,
            // sysvipc-proc, addresses, monitor, routes, route-dump, route-metrics, route-selectors, route-input, address-lifetimes, neighbours, neighbour-requests, neighbour-changes, neighbour-ageing, mctp-sockets, link-attributes, generic-netlink, sock-diag, inet-diag, ext-ack-*, netlink-option-flags, netlink-pktinfo, netlink-no-enobufs, netlink-nsid, netlink-listen-all-nsid, netlink-nsid-gone, netlink-nsid-write, netlink-target-netnsid, netlink-link-netns, netlink-write-credentials, veth-links and msg cases, whose checks depend on
            // CAP_SYS_ADMIN and which make namespaces (msg an IPC namespace of
            // its own, for its counts, and sysvipc-proc IPC and PID namespaces,
            // for its IDs and PIDs), the fanotify cases, whose groups and
            // marks need CAP_SYS_ADMIN, the userfaultfd cases, whose files take
            // the kernel's faults too (CAP_SYS_PTRACE), the perf cases, whose
            // events of the kernel and of CPUs need CAP_PERFMON, the bpf cases, whose
            // maps need CAP_BPF, the keys cases, which set up keyrings as root
            // and become other users, the mqueue cases, which make IPC and
            // network namespaces of their own for the namespace's default
            // limits and become an unprivileged user, the scheduling-set case, which sets
            // real-time and deadline policies, the admin case, which makes a
            // user namespace with its capabilities (Ubuntu's AppArmor gives none
            // to one an unprivileged user makes) before it becomes one,
            // the personality-layout case, which maps page 0, the
            // proc-other-maps, proc-other-fds, proc-other-limits,
            // proc-other-pagemap, proc-owner-rename and proc-io cases, which
            // read a process's maps, descriptors, auxv, pagemap and io as
            // other users or make it another user's, the proc-fd-links case,
            // which reads links from a chroot of its own mount namespace,
            // the proc-other-fd-paths case, which goes through a process's
            // descriptors as another user, the proc-personality-wchan case,
            // which reads them as other users, the proc-syscall case, which
            // reads a child's as another user, and the pagemap
            // and proc-owners cases, which become an unprivileged user, and
            // the mount-flags case, which runs a program of another user's
            // on its own mounts, as the emulator's guest starts as root.
            let as_root = matches!(
                mode,
                "credentials"
                    | "permissions"
                    | "setuid"
                    | "signal-permissions"
                    | "limit-permissions"
                    | "peer-credentials"
                    | "core-credentials"
                    | "set-id-writes"
                    | "socket-owners"
                    | "capabilities"
                    | "file-capabilities"
                    | "script-exec"
                    | "proc-maps"
                    | "proc-other-maps"
                    | "proc-other-fds"
                    | "proc-other-limits"
                    | "proc-other-pagemap"
                    | "proc-owner-rename"
                    | "proc-io"
                    | "proc-other-fd-paths"
                    | "proc-personality-wchan"
                    | "proc-syscall"
                    | "proc-fd-links"
                    | "dynamic-exec"
                    | "pty-vhangup"
                    | "pid-namespace"
                    | "unshare"
                    | "namespaces"
                    | "pid-namespaces"
                    | "pid-set-tid"
                    | "net-namespaces"
                    | "msg"
                    | "ipc-sysctl"
                    | "sysvipc-proc"
                    | "kernel-sysctl"
                    | "net-sysctl"
                    | "mqueue-calls"
                    | "mqueue-limits"
                    | "mqueue-wait"
                    | "mqueue-poll"
                    | "mqueue-notify"
                    | "mqueue-fork"
                    | "mqueue-sysctl"
                    | "mqueue-accounts"
                    | "mqueue-files"
                    | "mqueue-dev"
                    | "mqueue-room"
                    | "mqueue-congested"
                    | "mqueue-links"
                    | "fanotify-init"
                    | "fanotify-marks"
                    | "fanotify-events"
                    | "fanotify-fid"
                    | "fanotify-pidfd"
                    | "fanotify-unprivileged"
                    | "fanotify-mounts"
                    | "fanotify-perm"
                    | "fanotify-access-perm"
                    | "fanotify-open-exec"
                    | "fanotify-aio-perm"
                    | "fanotify-exec-perm"
                    | "userfaultfd-calls"
                    | "userfaultfd-faults"
                    | "userfaultfd-signals"
                    | "userfaultfd-sigbus"
                    | "userfaultfd-shared"
                    | "userfaultfd-wp"
                    | "userfaultfd-poison"
                    | "userfaultfd-move"
                    | "userfaultfd-shmem"
                    | "userfaultfd-minor"
                    | "userfaultfd-wp-shmem"
                    | "userfaultfd-wp-async"
                    | "userfaultfd-events"
                    | "userfaultfd-scan"
                    | "perf-calls"
                    | "perf-counts"
                    | "perf-exec"
                    | "perf-prctl"
                    | "perf-inherit"
                    | "perf-software"
                    | "perf-mmap"
                    | "perf-output"
                    | "perf-sample"
                    | "bpf-calls"
                    | "bpf-elements"
                    | "bpf-batch"
                    | "bpf-ids"
                    | "bpf-memory"
                    | "bpf-lru"
                    | "bpf-queue"
                    | "bpf-bloom"
                    | "bpf-lpm"
                    | "bpf-maps"
                    | "bpf-prog-load"
                    | "bpf-prog-verify"
                    | "keys-calls"
                    | "keys-keyrings"
                    | "keys-threads"
                    | "keys-parent"
                    | "keys-permissions"
                    | "netlink"
                    | "unix-interfaces"
                    | "addresses"
                    | "monitor"
                    | "routes"
                    | "route-dump"
                    | "route-metrics"
                    | "route-selectors"
                    | "route-input"
                    | "address-lifetimes"
                    | "neighbours"
                    | "neighbour-requests"
                    | "neighbour-changes"
                    | "neighbour-ageing"
                    | "mctp-sockets"
                    | "netlink-strict"
                    | "link-attributes"
                    | "generic-netlink"
                    | "sock-diag"
                    | "inet-diag"
                    | "ext-ack-netlink"
                    | "ext-ack-addresses"
                    | "ext-ack-monitor"
                    | "ext-ack-routes"
                    | "ext-ack-route-dump"
                    | "ext-ack-route-metrics"
                    | "ext-ack-route-selectors"
                    | "ext-ack-route-input"
                    | "ext-ack-address-lifetimes"
                    | "ext-ack-neighbour-requests"
                    | "ext-ack-neighbour-changes"
                    | "ext-ack-netlink-strict"
                    | "ext-ack-link-attributes"
                    | "ext-ack-generic-netlink"
                    | "netlink-option-flags"
                    | "netlink-pktinfo"
                    | "netlink-no-enobufs"
                    | "netlink-nsid"
                    | "netlink-listen-all-nsid"
                    | "netlink-nsid-gone"
                    | "netlink-nsid-write"
                    | "netlink-target-netnsid"
                    | "netlink-link-netns"
                    | "netlink-write-credentials"
                    | "veth-links"
                    | "user-namespaces"
                    | "scheduling-set"
                    | "personality-layout"
                    | "pagemap"
                    | "clear-refs"
                    | "map-count"
                    | "proc-owners"
                    | "admin"
                    | "mount-flags"
            );
            // The neighbour-ageing case waits out Linux's reachable time,
            // which may be 45 seconds.
            let limit = if mode == "neighbour-ageing" {
                Duration::from_secs(70)
            } else {
                TIMEOUT
            };
            let native = if as_root && !running_as_root() {
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
            // Their timers and limits wait for CPU time, which the virtual
            // clock does not pass, and the perf cases' clocks count it.
            if matches!(
                mode,
                "cpu-itimer"
                    | "rlimit-cpu"
                    | "cpu-timer"
                    | "cpu-sleep"
                    | "cpu-sleep-others"
                    | "cpu-timer-others"
                    | "perf-counts"
                    | "perf-exec"
                    | "perf-prctl"
                    | "perf-inherit"
            ) {
                host.measure_cpu_time();
            }
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
        processes_scheduling => ("scheduling","process"),
        processes_personality => ("personality","process"),
        processes_membarrier => ("membarrier","process"),
        processes_unshare => ("unshare","process"),
        processes_namespaces => ("namespaces","process"),
        processes_pid_namespaces => ("pid-namespaces","process"),
        processes_pid_set_tid => ("pid-set-tid","process"),
        processes_net_namespaces => ("net-namespaces","process"),
        processes_netlink => ("netlink","process"),
        processes_unix_interfaces => ("unix-interfaces","process"),
        processes_addresses => ("addresses","process"),
        processes_monitor => ("monitor","process"),
        processes_routes => ("routes","process"),
        processes_route_dump => ("route-dump","process"),
        processes_route_metrics => ("route-metrics","process"),
        processes_route_selectors => ("route-selectors","process"),
        processes_route_input => ("route-input","process"),
        processes_address_lifetimes => ("address-lifetimes","process"),
        processes_neighbours => ("neighbours","process"),
        processes_neighbour_requests => ("neighbour-requests","process"),
        processes_neighbour_changes => ("neighbour-changes","process"),
        processes_neighbour_ageing => ("neighbour-ageing","process"),
        processes_mctp_sockets => ("mctp-sockets","process"),
        processes_netlink_strict => ("netlink-strict","process"),
        processes_link_attributes => ("link-attributes","process"),
        processes_generic_netlink => ("generic-netlink","process"),
        processes_sock_diag => ("sock-diag","process"),
        processes_inet_diag => ("inet-diag","process"),
        processes_ext_ack_netlink => ("ext-ack-netlink","process"),
        processes_ext_ack_addresses => ("ext-ack-addresses","process"),
        processes_ext_ack_monitor => ("ext-ack-monitor","process"),
        processes_ext_ack_routes => ("ext-ack-routes","process"),
        processes_ext_ack_route_dump => ("ext-ack-route-dump","process"),
        processes_ext_ack_route_metrics => ("ext-ack-route-metrics","process"),
        processes_ext_ack_route_selectors => ("ext-ack-route-selectors","process"),
        processes_ext_ack_route_input => ("ext-ack-route-input","process"),
        processes_ext_ack_address_lifetimes => ("ext-ack-address-lifetimes","process"),
        processes_ext_ack_neighbour_requests => ("ext-ack-neighbour-requests","process"),
        processes_ext_ack_neighbour_changes => ("ext-ack-neighbour-changes","process"),
        processes_ext_ack_netlink_strict => ("ext-ack-netlink-strict","process"),
        processes_ext_ack_link_attributes => ("ext-ack-link-attributes","process"),
        processes_ext_ack_generic_netlink => ("ext-ack-generic-netlink","process"),
        netlink_option_flags => ("netlink-option-flags","netlink-options"),
        netlink_pktinfo => ("netlink-pktinfo","netlink-options"),
        netlink_no_enobufs => ("netlink-no-enobufs","netlink-options"),
        netlink_nsid => ("netlink-nsid","netlink-options"),
        netlink_listen_all_nsid => ("netlink-listen-all-nsid","netlink-options"),
        netlink_nsid_gone => ("netlink-nsid-gone","netlink-options"),
        netlink_nsid_write => ("netlink-nsid-write","netlink-options"),
        netlink_target_netnsid => ("netlink-target-netnsid","netlink-options"),
        netlink_link_netns => ("netlink-link-netns","netlink-options"),
        netlink_write_credentials => ("netlink-write-credentials","netlink-options"),
        veth_links => ("veth-links","veth"),
        processes_user_namespaces => ("user-namespaces","process"),
        processes_scheduling_set => ("scheduling-set","process"),
        processes_personality_layout => ("personality-layout","process"),
        processes_landlock => ("landlock","process"),
        processes_madvise_advice => ("madvise-advice","process"),
        processes_madvise_fork => ("madvise-fork","process"),
        processes_madvise_remove => ("madvise-remove","process"),
        processes_lock_state => ("lock-state","process"),
        processes_smaps_flags => ("smaps-flags","process"),
        processes_mrelease_fatal => ("mrelease-fatal","process"),
        processes_madvise_guard => ("madvise-guard","process"),
        processes_grows_down => ("grows-down","process"),
        processes_fork_page_tables => ("fork-page-tables","process"),
        processes_mrelease => ("mrelease","process"),
        processes_mempolicy => ("mempolicy","process"),
        processes_memfd_secret => ("memfd-secret","process"),
        processes_memfd_secret_memlock => ("memfd-secret-memlock","process"),
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
        processes_pid_namespace => ("pid-namespace","process"),
        pty_open => ("pty-open","pty"),
        pty_termios => ("pty-termios","pty"),
        pty_canonical => ("pty-canonical","pty"),
        pty_raw => ("pty-raw","pty"),
        pty_session => ("pty-session","pty"),
        pty_signals => ("pty-signals","pty"),
        pty_hangup => ("pty-hangup","pty"),
        pty_packet => ("pty-packet","pty"),
        pty_termio => ("pty-termio","pty"),
        pty_proc_stat => ("pty-proc-stat","pty"),
        pty_async => ("pty-async","pty"),
        pty_vhangup => ("pty-vhangup","pty"),
        signalfd_calls => ("signalfd-calls","signalfd"),
        signalfd_child => ("signalfd-child","signalfd"),
        signalfd_epoll => ("signalfd-epoll","signalfd"),
        signalfd_threads => ("signalfd-threads","signalfd"),
        signalfd_fork => ("signalfd-fork","signalfd"),
        signalfd_interrupt => ("signalfd-interrupt","signalfd"),
        signalfd_edges => ("signalfd-edges","signalfd"),
        signalfd_fdinfo => ("signalfd-fdinfo","signalfd"),
        signalfd_shared_locks => ("signalfd-shared-locks","signalfd"),
        aio_calls => ("aio-calls","aio"),
        aio_rw => ("aio-rw","aio"),
        aio_streams => ("aio-streams","aio"),
        aio_poll => ("aio-poll","aio"),
        aio_getevents => ("aio-getevents","aio"),
        aio_full => ("aio-full","aio"),
        aio_lifetime => ("aio-lifetime","aio"),
        aio_mremap => ("aio-mremap","aio"),
        perf_calls => ("perf-calls","perf"),
        perf_counts => ("perf-counts","perf"),
        perf_exec => ("perf-exec","perf"),
        perf_prctl => ("perf-prctl","perf"),
        perf_inherit => ("perf-inherit","perf"),
        perf_software => ("perf-software","perf"),
        perf_mmap => ("perf-mmap","perf"),
        perf_output => ("perf-output","perf"),
        perf_sample => ("perf-sample","perf"),
        bpf_calls => ("bpf-calls","bpf"),
        bpf_elements => ("bpf-elements","bpf"),
        bpf_batch => ("bpf-batch","bpf"),
        bpf_ids => ("bpf-ids","bpf"),
        bpf_memory => ("bpf-memory","bpf"),
        bpf_lru => ("bpf-lru","bpf"),
        bpf_queue => ("bpf-queue","bpf"),
        bpf_bloom => ("bpf-bloom","bpf"),
        bpf_lpm => ("bpf-lpm","bpf"),
        bpf_maps => ("bpf-maps","bpf"),
        bpf_prog_load => ("bpf-prog-load","bpf"),
        bpf_prog_verify => ("bpf-prog-verify","bpf-prog"),
        inotify_calls => ("inotify-calls","inotify"),
        inotify_directory => ("inotify-directory","inotify"),
        inotify_files => ("inotify-files","inotify"),
        inotify_flags => ("inotify-flags","inotify"),
        inotify_overflow => ("inotify-overflow","inotify"),
        inotify_wait => ("inotify-wait","inotify"),
        inotify_content => ("inotify-content","inotify"),
        inotify_held => ("inotify-held","inotify"),
        inotify_home => ("inotify-home","inotify"),
        inotify_running => ("inotify-running","inotify"),
        inotify_interpreter => ("inotify-interpreter","inotify"),
        inotify_moved => ("inotify-moved","inotify"),
        inotify_fifo => ("inotify-fifo","inotify"),
        inotify_exec => ("inotify-exec","inotify"),
        inotify_instance => ("inotify-instance","inotify"),
        inotify_read => ("inotify-read","inotify"),
        inotify_fifo_moved => ("inotify-fifo-moved","inotify"),
        inotify_exec_order => ("inotify-exec-order","inotify"),
        inotify_handles => ("inotify-handles","inotify"),
        inotify_open_handles => ("inotify-open-handles","inotify"),
        fanotify_init => ("fanotify-init","fanotify"),
        fanotify_marks => ("fanotify-marks","fanotify"),
        fanotify_events => ("fanotify-events","fanotify"),
        fanotify_fid => ("fanotify-fid","fanotify"),
        fanotify_pidfd => ("fanotify-pidfd","fanotify"),
        fanotify_unprivileged => ("fanotify-unprivileged","fanotify"),
        fanotify_mounts => ("fanotify-mounts","fanotify"),
        fanotify_perm => ("fanotify-perm","fanotify"),
        fanotify_access_perm => ("fanotify-access-perm","fanotify"),
        fanotify_open_exec => ("fanotify-open-exec","fanotify"),
        fanotify_aio_perm => ("fanotify-aio-perm","fanotify"),
        fanotify_exec_perm => ("fanotify-exec-perm","fanotify"),
        userfaultfd_calls => ("userfaultfd-calls","userfaultfd"),
        userfaultfd_faults => ("userfaultfd-faults","userfaultfd"),
        userfaultfd_signals => ("userfaultfd-signals","userfaultfd"),
        userfaultfd_sigbus => ("userfaultfd-sigbus","userfaultfd"),
        userfaultfd_shared => ("userfaultfd-shared","userfaultfd"),
        userfaultfd_wp => ("userfaultfd-wp","userfaultfd"),
        userfaultfd_poison => ("userfaultfd-poison","userfaultfd"),
        userfaultfd_move => ("userfaultfd-move","userfaultfd"),
        userfaultfd_shmem => ("userfaultfd-shmem","userfaultfd"),
        userfaultfd_minor => ("userfaultfd-minor","userfaultfd"),
        userfaultfd_wp_shmem => ("userfaultfd-wp-shmem","userfaultfd"),
        userfaultfd_wp_async => ("userfaultfd-wp-async","userfaultfd"),
        userfaultfd_events => ("userfaultfd-events","userfaultfd"),
        userfaultfd_scan => ("userfaultfd-scan","userfaultfd"),
        mqueue_calls => ("mqueue-calls","mqueue"),
        mqueue_limits => ("mqueue-limits","mqueue"),
        mqueue_wait => ("mqueue-wait","mqueue"),
        mqueue_poll => ("mqueue-poll","mqueue"),
        mqueue_notify => ("mqueue-notify","mqueue"),
        mqueue_fork => ("mqueue-fork","mqueue"),
        mqueue_sysctl => ("mqueue-sysctl","mqueue"),
        mqueue_accounts => ("mqueue-accounts","mqueue"),
        mqueue_files => ("mqueue-files","mqueue"),
        mqueue_dev => ("mqueue-dev","mqueue"),
        mqueue_room => ("mqueue-room","mqueue"),
        mqueue_congested => ("mqueue-congested","mqueue"),
        mqueue_links => ("mqueue-links","mqueue"),
        keys_calls => ("keys-calls","keys"),
        keys_keyrings => ("keys-keyrings","keys"),
        keys_threads => ("keys-threads","keys"),
        keys_parent => ("keys-parent","keys"),
        keys_permissions => ("keys-permissions","keys"),
        ptrace_traceme => ("ptrace-traceme","ptrace"),
        ptrace_attach => ("ptrace-attach","ptrace"),
        ptrace_seize => ("ptrace-seize","ptrace"),
        ptrace_signals => ("ptrace-signals","ptrace"),
        ptrace_regs => ("ptrace-regs","ptrace"),
        ptrace_memory => ("ptrace-memory","ptrace"),
        ptrace_thread => ("ptrace-thread","ptrace"),
        ptrace_sibling => ("ptrace-sibling","ptrace"),
        ptrace_attach_stopped => ("ptrace-attach-stopped","ptrace"),
        ptrace_tracer_exit => ("ptrace-tracer-exit","ptrace"),
        ptrace_strace => ("ptrace-strace","ptrace-syscalls"),
        ptrace_sysemu => ("ptrace-sysemu","ptrace-syscalls"),
        ptrace_events => ("ptrace-events","ptrace-syscalls"),
        ptrace_clone => ("ptrace-clone","ptrace-syscalls"),
        ptrace_sigmask => ("ptrace-sigmask","ptrace-requests"),
        ptrace_listen => ("ptrace-listen","ptrace-requests"),
        ptrace_seccomp => ("ptrace-seccomp","ptrace-requests"),
        ptrace_arch_rseq => ("ptrace-arch-rseq","ptrace-requests"),
        ptrace_syscall_signal => ("ptrace-syscall-signal","ptrace-requests"),
        ptrace_exit_core => ("ptrace-exit-core","ptrace-requests"),
        trap_flag => ("trap-flag","single-step"),
        trap_flag_syscall => ("trap-flag-syscall","single-step"),
        trap_flag_signal => ("trap-flag-signal","single-step"),
        int3 => ("int3","single-step"),
        trap_flag_rep => ("trap-flag-rep","single-step"),
        ptrace_singlestep => ("ptrace-singlestep","single-step"),
        ptrace_forced_frame => ("ptrace-forced-frame","single-step"),
        ptrace_hw_breakpoint => ("ptrace-hw-breakpoint","single-step"),
        ptrace_hw_implicit => ("ptrace-hw-implicit","single-step"),
        hw_probe_fxsave => ("hw-probe-fxsave","single-step"),
        hw_probe_fxrstor => ("hw-probe-fxrstor","single-step"),
        hw_probe_x87 => ("hw-probe-x87","single-step"),
        hw_probe_maskmovdqu => ("hw-probe-maskmovdqu","single-step"),
        ptrace_restart_codes => ("ptrace-restart-codes","ptrace-requests"),
        ptrace_selectors => ("ptrace-selectors","ptrace-requests"),
        ptrace_suspend_seccomp => ("ptrace-suspend-seccomp","ptrace-requests"),
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
        processes_credentials => ("credentials","process"),
        processes_permissions => ("permissions","process"),
        processes_setuid => ("setuid","process"),
        processes_signal_permissions => ("signal-permissions","process"),
        processes_limit_permissions => ("limit-permissions","process"),
        processes_cpu_state => ("cpu-state","process"),
        processes_x87 => ("x87","process"),
        processes_x87_arithmetic => ("x87-arithmetic","process"),
        processes_x87_transcendental => ("x87-transcendental","x87"),
        processes_x87_decimal => ("x87-decimal","x87"),
        processes_x87_state => ("x87-state","x87"),
        processes_x87_exceptions => ("x87-exceptions","x87"),
        processes_robust_list => ("robust-list","process"),
        processes_futex_shared => ("futex-shared","process"),
        processes_late_handler => ("late-handler","process"),
        processes_mincore => ("mincore","process"),
        processes_pagemap => ("pagemap","process"),
        processes_clear_refs => ("clear-refs","process"),
        processes_map_count => ("map-count","process"),
        processes_hiwater => ("hiwater","process"),
        processes_maxrss => ("maxrss","process"),
        processes_proc_owners => ("proc-owners","process"),
        processes_memory_locks => ("memory-locks","process"),
        processes_proc_maps => ("proc-maps","process"),
        processes_fifo => ("fifo","process"),
        processes_proc_own_files => ("proc-own-files","process"),
        processes_proc_other_files => ("proc-other-files","process"),
        processes_time_calls => ("time-calls","process"),
        processes_dynamic => ("dynamic","dynamic"),
        processes_dynamic_no_pie => ("dynamic-no-pie","dynamic-no-pie"),
        processes_dynamic_glibc => ("dynamic-glibc","dynamic-glibc"),
        processes_dynamic_exec => ("dynamic-exec","process"),
        processes_script_exec => ("script-exec","process"),
        processes_capabilities => ("capabilities","process"),
        processes_file_capabilities => ("file-capabilities","process"),
        processes_set_id_writes => ("set-id-writes","process"),
        processes_socket_owners => ("socket-owners","process"),
        processes_peer_credentials => ("peer-credentials","process"),
        processes_core_credentials => ("core-credentials","process"),
        processes_waitid => ("waitid","process"),
        processes_autoreap => ("autoreap","process"),
        processes_reparent => ("reparent","process"),
        processes_orphaned_group => ("orphaned-group","process"),
        processes_kill_group => ("kill-group","process"),
        processes_signal_sender => ("signal-sender","process"),
        processes_kill_before_sleep => ("kill-before-sleep","process"),
        processes_core_dump => ("core-dump","process"),
        processes_core_mappings => ("core-mappings","process"),
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
        processes_socket_timestamping => ("socket-timestamping","process"),
        processes_socket_passsec => ("socket-passsec","process"),
        processes_socket_passrights => ("socket-passrights","process"),
        processes_proc_block_size => ("proc-block-size","process"),
        processes_open_flags => ("open-flags","process"),
        processes_pipe_reopen => ("pipe-reopen","process"),
        processes_pipe_async => ("pipe-async","process"),
        processes_link_path => ("link-path","process"),
        processes_proc_self_link => ("proc-self-link","process"),
        processes_anon_reopen => ("anon-reopen","process"),
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
        processes_execveat => ("execveat","process"),
        processes_etxtbsy => ("etxtbsy","process"),
        processes_shm => ("shm","process"),
        processes_sem => ("sem","process"),
        processes_msg => ("msg","process"),
        processes_ipc_sysctl => ("ipc-sysctl","process"),
        processes_sysvipc_proc => ("sysvipc-proc","process"),
        processes_kernel_sysctl => ("kernel-sysctl","process"),
        processes_net_sysctl => ("net-sysctl","process"),
        processes_rseq => ("rseq","process"),
        processes_pkey => ("pkey","process"),
        processes_vector_flags => ("vector-flags","process"),
        processes_old_times => ("old-times","process"),
        processes_old_forms => ("old-forms","process"),
        processes_futex2 => ("futex2","process"),
        processes_futex_requeue => ("futex-requeue","process"),
        processes_futex_wake_op => ("futex-wake-op","process"),
        processes_kcmp => ("kcmp","process"),
        processes_mseal => ("mseal","process"),
        processes_seccomp => ("seccomp","process"),
        processes_seccomp_notify => ("seccomp-notify","process"),
        processes_process_vm => ("process-vm","process"),
        processes_page_nodes => ("page-nodes","process"),
        processes_kernel_info => ("kernel-info","process"),
        processes_admin => ("admin","process"),
        processes_pidfd_getfd => ("pidfd-getfd","process"),
        processes_pidfd_fdinfo => ("pidfd-fdinfo","process"),
        processes_cpu_clock_ids => ("cpu-clock-ids","process"),
        processes_alarm_clocks => ("alarm-clocks","process"),
        processes_yama => ("yama","process"),
        processes_ignored_signal_wait => ("ignored-signal-wait","process"),
        processes_mmsg => ("mmsg","process"),
        processes_itimer => ("itimer","process"),
        processes_cpu_itimer => ("cpu-itimer","process"),
        processes_rlimit_cpu => ("rlimit-cpu","process"),
        processes_cpu_timer => ("cpu-timer","process"),
        processes_time_set => ("time-set","process"),
        processes_chroot => ("chroot","process"),
        processes_mounts => ("mounts","process"),
        processes_binds => ("binds","process"),
        processes_remounts => ("remounts","process"),
        processes_moves => ("moves","process"),
        processes_trees => ("trees","process"),
        processes_contexts => ("contexts","process"),
        processes_setattrs => ("setattrs","process"),
        processes_mount_flags => ("mount-flags","process"),
        processes_listings => ("listings","process"),
        processes_generated_binds => ("generated-binds","process"),
        processes_generated_changes => ("generated-changes","process"),
        processes_tmpfs_limits => ("tmpfs-limits","process"),
        processes_beneath => ("beneath","process"),
        processes_propagation => ("propagation","process"),
        processes_proc_other_mounts => ("proc-other-mounts","process"),
        processes_proc_other_maps => ("proc-other-maps","process"),
        processes_proc_other_fds => ("proc-other-fds","process"),
        processes_proc_other_limits => ("proc-other-limits","process"),
        processes_proc_other_pagemap => ("proc-other-pagemap","process"),
        processes_proc_owner_rename => ("proc-owner-rename","process"),
        processes_proc_io => ("proc-io","process"),
        processes_proc_other_fd_paths => ("proc-other-fd-paths","process"),
        processes_proc_personality_wchan => ("proc-personality-wchan","process"),
        processes_proc_syscall => ("proc-syscall","process"),
        processes_proc_fd_links => ("proc-fd-links","process"),
        processes_modify_ldt => ("modify-ldt","process"),
        processes_port_access => ("port-access","process"),
        processes_timer_limits => ("timer-limits","process"),
        processes_cpu_sleep => ("cpu-sleep","process"),
        processes_cpu_sleep_others => ("cpu-sleep-others","process"),
        processes_cpu_timer_others => ("cpu-timer-others","process"),
        processes_mprotect_checks => ("mprotect-checks","process"),
        processes_io_uring => ("io-uring","process"),
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
