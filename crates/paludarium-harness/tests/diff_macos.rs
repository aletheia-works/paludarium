//! U12 fixed guest operation. The Python supervisor owns the hard deadline.
#[path = "support/programs.rs"]
// The reused operation fixture intentionally fails tests on setup/I/O errors.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;

#[test]
fn programs_guest_operation() {
    if std::env::var_os("PALUDARIUM_PROGRAMS_OPERATION").is_some() {
        support::operation();
    }
}
