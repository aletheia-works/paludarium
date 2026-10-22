//! Signals and time expectations are produced by x86-64 Linux on each test execution.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/signals_time_oracles.rs"]
mod oracles;
#[path = "support/signals_time.rs"]
mod support;
use paludarium_harness::{compare, run_emulated, run_native, workspace_root};

fn build_signals_time() -> std::path::PathBuf {
    let out = workspace_root().join("target/guests/signals-time");
    if std::env::var("PALUDARIUM_SIGNALS_TIME_CHILD").is_err() {
        static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        BUILT.get_or_init(|| {
            assert!(
                std::process::Command::new("bash")
                    .arg(workspace_root().join("tests/guests/signals-time/build.sh"))
                    .arg(&out)
                    .status()
                    .expect("signals/time native build")
                    .success()
            );
        });
    }
    out
}
fn guest(group: &str, name: &'static str, case: usize) {
    let out = build_signals_time();
    support::bounded(name, || {
        let binary = format!("{group}-{case}");
        let path = out.join(&binary);
        let native = run_native(&path, &binary, &[]).expect("native signals/time memory");
        let (emulated, stop) =
            run_emulated(&path, &binary, &[]).expect("emulated signals/time memory");
        println!(
            "{name}: native={:?}/{:02x?}; emulated={:?}/{:02x?}; stop={stop:?}",
            native.status, native.stdout, emulated.status, emulated.stdout
        );
        compare(&native, &emulated).unwrap();
    });
}
macro_rules! cases { ($($name:ident => $case:literal),* $(,)?) => {$(
    #[test] fn $name(){guest("memory",stringify!($name),$case);}
)*}; }
cases!(
    memory_zero_length => 0,
    memory_shared_anonymous => 1,
    memory_fixed_invalid_non_destructive => 2,
    memory_noreplace_non_destructive => 3,
    memory_protect_holes => 4,
    memory_unmap_holes_fault => 5,
    memory_break => 6,
    memory_unaligned_hint => 7,
    memory_madvise_dontneed_free => 10,
    memory_madvise_errors => 11,
);

macro_rules! time_cases { ($($name:ident => $case:literal),* $(,)?) => {$(
    #[test] fn $name(){guest("time",stringify!($name),$case);}
)*}; }
time_cases!(
 time_monotonic => 0,
 time_realtime => 1,
 time_clock_invalid_pointer => 2,
 time_zero_sleep => 3,
 time_nanoseconds_and_pointer => 4,
 time_negative_sleep => 5,
 time_absolute_past => 6,
 time_absolute_invalid_pointer => 7,
);

macro_rules! signal_cases { ($($name:ident => $case:literal),* $(,)?) => {$(
    #[test] fn $name(){guest("signals",stringify!($name),$case);}
)*}; }
signal_cases!(
 signal_registration => 0,
 signal_self_handler => 1,
 signal_ignore => 2,
 signal_default => 3,
 signal_blocked_pending => 4,
 signal_altstack => 5,
 signal_nodefer_nested => 6,
 signal_reset_hand => 7,
 signal_segv_maperr_context => 8,
 signal_segv_accerr_context => 9,
 signal_ill_context => 10,
 signal_fpe_context => 11,
 signal_modified_return => 12,
 signal_malformed_return => 13,
 signal_abi_offsets => 14,
);

signal_cases!(signal_fpstate_alignment => 15,signal_timer_interrupt => 16,signal_timer_restart_sleep => 17);

cases!(memory_partial_protect_fault=>8,memory_offset_alignment=>9);
signal_cases!(signal_relocated_frame=>18,signal_huge_sleep_interrupt=>19);

signal_cases!(signal_execute_fault_context=>20,signal_none_fault_context=>21,signal_virgin_readonly_fault=>22);
