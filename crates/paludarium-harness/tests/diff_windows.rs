//! U13 fixed guest operation. The Python supervisor owns the hard deadline.
#[path = "support/windows.rs"]
// The reused operation fixture intentionally fails tests on setup/I/O errors.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod support;

#[test]
fn windows_guest_operation() {
    if std::env::var_os("PALUDARIUM_WINDOWS_OPERATION").is_some() {
        support::operation();
    }
}
