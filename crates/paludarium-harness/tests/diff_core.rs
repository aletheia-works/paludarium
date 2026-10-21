//! Core differential tests: every guest runs natively
//! on x86-64 Linux and under paludarium, and the results must be identical.
//!
//!   cargo test --locked -p paludarium-harness --test diff_core
//!
//! The guests are built from `tests/guests/` by `tests/guests/build.sh` on
//! first use (musl-gcc and the x86_64-unknown-linux-musl target required).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use paludarium_harness::{DiffTestCase, GuestSource, run_case};

fn case(name: &'static str, binary: &'static str, source: GuestSource) -> DiffTestCase {
    DiffTestCase {
        name,
        binary,
        source,
        arguments: Vec::new(),
    }
}

fn check(case: &DiffTestCase) {
    match run_case(case) {
        Ok((native, emulated)) => {
            // Run-time record: printed with --nocapture / in CI logs.
            println!(
                "timing {}: native {:?}, emulated {:?}",
                case.name, native.elapsed, emulated.elapsed
            );
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn hello_c() {
    check(&case("hello-c", "hello-c", GuestSource::CMusl));
}

#[test]
fn hello_rs() {
    check(&case("hello-rs", "hello-rs", GuestSource::RustMusl));
}

#[test]
fn hello_rs_with_arguments() {
    let mut c = case("hello-rs-args", "hello-rs", GuestSource::RustMusl);
    c.arguments = vec!["--flag".into(), "two words".into()];
    check(&c);
}

macro_rules! insn_tests {
    ($($test:ident => $binary:literal),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                check(&case($binary, $binary, GuestSource::CMusl));
            }
        )*
    };
}

insn_tests!(
    insn_alu => "insn-alu",
    insn_cmptest => "insn-cmptest",
    insn_incdec => "insn-incdec",
    insn_shift => "insn-shift",
    insn_muldiv => "insn-muldiv",
    insn_bt => "insn-bt",
    insn_cond_set => "insn-cond-set",
    insn_cond_cmov => "insn-cond-cmov",
    insn_cond_jcc => "insn-cond-jcc",
    insn_mov => "insn-mov",
    insn_string => "insn-string",
    insn_atomic => "insn-atomic",
    insn_sse => "insn-sse",
);
