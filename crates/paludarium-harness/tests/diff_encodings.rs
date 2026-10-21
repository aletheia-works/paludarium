//! Encodings runner bootstrap. Native instruction cases follow native observations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/encodings.rs"]
mod support;

#[path = "support/encodings_oracle.rs"]
mod oracle;

#[test]
#[ignore = "diagnostic replay requires explicitly supplied native observations"]
fn saved_observation_replay() {
    let normal =
        std::fs::read_to_string(std::env::var("PALUDARIUM_ENCODINGS_NATIVE_OBSERVATIONS").unwrap())
            .unwrap();
    let fault =
        std::fs::read_to_string(std::env::var("PALUDARIUM_ENCODINGS_NATIVE_FAULTS").unwrap())
            .unwrap();
    let cpuid =
        std::fs::read_to_string(std::env::var("PALUDARIUM_ENCODINGS_NATIVE_CPUID").unwrap())
            .unwrap();
    println!(
        "normal:{} fault:{}",
        oracle::compare(&normal, false),
        oracle::compare_profile(&fault, true, Some(&cpuid))
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fresh_native_differential() {
    support::bounded("fresh_native_differential", || {
        let root = paludarium_harness::workspace_root();
        let output = root.join("target/encodings-guests");
        assert!(
            std::process::Command::new("bash")
                .arg(root.join("tests/guests/encodings/build.sh"))
                .arg(&output)
                .status()
                .unwrap()
                .success()
        );
        let cpuid =
            paludarium_harness::run_native(&output.join("cpuid-observe"), "cpuid", &[]).unwrap();
        assert_eq!(cpuid.status, paludarium::ExitStatus::Exited(0));
        assert!(cpuid.stderr.is_empty());
        std::fs::write(output.join("cpuid-observe.native"), &cpuid.stdout).unwrap();
        for (name, fault) in [("observe", false), ("fault-observe", true)] {
            let observation =
                paludarium_harness::run_native(&output.join(name), name, &[]).unwrap();
            assert_eq!(observation.status, paludarium::ExitStatus::Exited(0));
            assert!(observation.stderr.is_empty());
            std::fs::write(output.join(format!("{name}.native")), &observation.stdout).unwrap();
            let rows = oracle::compare_profile(
                std::str::from_utf8(&observation.stdout).unwrap(),
                fault,
                Some(std::str::from_utf8(&cpuid.stdout).unwrap()),
            );
            println!("{name}: {rows} freshly generated native states agree");
        }
        assert_eq!(cpuid.status, paludarium::ExitStatus::Exited(0));
        assert_eq!(
            cpuid
                .stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count(),
            12
        );
        std::fs::write(output.join("cpuid-observe.native"), &cpuid.stdout).unwrap();
    });
}

#[test]
fn runner_bootstrap() {
    assert!(
        paludarium_harness::workspace_root()
            .join("tests/guests/encodings/build.sh")
            .is_file()
    );
}

/// Started only by `bounded_reaches_ignored_tests`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "probe for the bounded runner; started by bounded_reaches_ignored_tests"]
fn bounded_ignored_probe() {
    support::bounded("bounded_ignored_probe", || {
        let marker =
            std::env::var_os("PALUDARIUM_ENCODINGS_PROBE_MARKER").expect("probe marker path");
        std::fs::write(marker, "ran").expect("write probe marker");
    });
}

/// `cargo test -- --ignored` must reach the body of an ignored bounded test:
/// its isolated child used to filter the test out, run nothing and pass.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn bounded_reaches_ignored_tests() {
    let marker = paludarium_harness::workspace_root()
        .join("target/encodings-bounded")
        .join(format!("probe-{}.marker", std::process::id()));
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(&marker);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "bounded_ignored_probe",
            "--ignored",
            "--nocapture",
        ])
        .env("PALUDARIUM_ENCODINGS_PROBE_MARKER", &marker)
        .env_remove("PALUDARIUM_ENCODINGS_CHILD")
        .status()
        .unwrap();
    assert!(status.success(), "ignored bounded probe: {status}");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ran");
    std::fs::remove_file(&marker).unwrap();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "Explicit native-only collection; does not assert emulator agreement"]
fn native_observation() {
    support::bounded("native_observation", || {
        let root = paludarium_harness::workspace_root();
        let output = root.join("target/encodings-guests");
        assert!(
            std::process::Command::new("bash")
                .arg(root.join("tests/guests/encodings/build.sh"))
                .arg(&output)
                .status()
                .expect("build native encodings fixtures")
                .success()
        );
        for name in ["observe", "cpuid-observe", "fault-observe"] {
            let observation = paludarium_harness::run_native(&output.join(name), name, &[])
                .expect("bounded native observation");
            assert_eq!(observation.status, paludarium::ExitStatus::Exited(0));
            let rows = observation
                .stdout
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .count();
            assert!(rows > 0, "zero native rows: {name}");
            std::fs::write(output.join(format!("{name}.native")), &observation.stdout)
                .expect("save fresh native observations");
            std::fs::write(output.join(format!("{name}.stderr")), &observation.stderr)
                .expect("save native stderr");
            println!("{name}: {rows} fresh native rows; emulator agreement not measured");
        }
    });
}
