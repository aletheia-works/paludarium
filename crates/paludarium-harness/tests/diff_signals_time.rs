//! U4 expectations are produced by x86-64 Linux on each test execution.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/signals_time_oracles.rs"]
mod oracles;
#[path = "support/signals_time.rs"]
mod support;
use paludarium_harness::{compare, run_emulated, run_native, workspace_root};

fn build_u4() -> std::path::PathBuf {
    let out = workspace_root().join("target/guests/signals-time");
    if std::env::var("PALUDARIUM_U4_CHILD").is_err() {
        static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        BUILT.get_or_init(|| {
            assert!(
                std::process::Command::new("bash")
                    .arg(workspace_root().join("tests/guests/signals-time/build.sh"))
                    .arg(&out)
                    .status()
                    .expect("U4 native build")
                    .success()
            );
        });
    }
    out
}
fn guest(group: &str, name: &'static str, case: usize) {
    let out = build_u4();
    support::bounded(name, || {
        let binary = format!("{group}-{case}");
        let path = out.join(&binary);
        let native = run_native(&path, &binary, &[]).expect("native U4 memory");
        let (emulated, stop) = run_emulated(&path, &binary, &[]).expect("emulated U4 memory");
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
    u4_memory_zero_length => 0,
    u4_memory_shared_anonymous => 1,
    u4_memory_fixed_invalid_non_destructive => 2,
    u4_memory_noreplace_non_destructive => 3,
    u4_memory_protect_holes => 4,
    u4_memory_unmap_holes_fault => 5,
    u4_memory_break => 6,
    u4_memory_unaligned_hint => 7,
);

macro_rules! time_cases { ($($name:ident => $case:literal),* $(,)?) => {$(
    #[test] fn $name(){guest("time",stringify!($name),$case);}
)*}; }
time_cases!(
 u4_time_monotonic => 0,
 u4_time_realtime => 1,
 u4_time_clock_invalid_pointer => 2,
 u4_time_zero_sleep => 3,
 u4_time_nanoseconds_and_pointer => 4,
 u4_time_negative_sleep => 5,
 u4_time_absolute_past => 6,
 u4_time_absolute_invalid_pointer => 7,
);

macro_rules! signal_cases { ($($name:ident => $case:literal),* $(,)?) => {$(
    #[test] fn $name(){guest("signals",stringify!($name),$case);}
)*}; }
signal_cases!(
 u4_signal_registration => 0,
 u4_signal_self_handler => 1,
 u4_signal_ignore => 2,
 u4_signal_default => 3,
 u4_signal_blocked_pending => 4,
 u4_signal_altstack => 5,
 u4_signal_nodefer_nested => 6,
 u4_signal_reset_hand => 7,
 u4_signal_segv_maperr_context => 8,
 u4_signal_segv_accerr_context => 9,
 u4_signal_ill_context => 10,
 u4_signal_fpe_context => 11,
 u4_signal_modified_return => 12,
 u4_signal_malformed_return => 13,
 u4_signal_abi_offsets => 14,
);

signal_cases!(u4_signal_fpstate_alignment => 15,u4_signal_timer_interrupt => 16,u4_signal_timer_restart_sleep => 17);

cases!(u4_memory_partial_protect_fault=>8,u4_memory_offset_alignment=>9);
signal_cases!(u4_signal_relocated_frame=>18,u4_signal_huge_sleep_interrupt=>19);

signal_cases!(u4_signal_execute_fault_context=>20,u4_signal_none_fault_context=>21,u4_signal_virgin_readonly_fault=>22);
