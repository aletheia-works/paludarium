use crate::files::Files;
use paludarium_types::Errno;
use paludarium_vfs::{HostFs, MemFs};
use std::sync::Arc;
fn fixture() -> Files {
    let fs = MemFs::new();
    fs.mkdir(b"/app", 0o755).unwrap();
    fs.open(b"/file", 66, 0o644).unwrap();
    let mut files = Files::default();
    files.fs = Arc::new(fs);
    files
}
#[test]
fn u11_cwd_existing_directory() {
    assert!(fixture().set_current_directory(b"/app").is_ok());
}
#[test]
fn u11_cwd_root() {
    assert!(fixture().set_current_directory(b"/").is_ok());
}
#[test]
fn u11_cwd_missing() {
    assert_eq!(
        fixture().set_current_directory(b"/missing"),
        Err(Errno::ENOENT)
    );
}
#[test]
fn u11_cwd_file() {
    assert_eq!(
        fixture().set_current_directory(b"/file"),
        Err(Errno::ENOTDIR)
    );
}
#[test]
fn u11_cwd_nul() {
    assert!(fixture().set_current_directory(b"/app\0").is_err());
}
#[test]
fn u11_cwd_dot_components() {
    assert!(fixture().set_current_directory(b"/app/../app/.").is_ok());
}
#[test]
fn u11_cwd_symlink_directory() {
    let mut files = fixture();
    files.fs.symlink(b"/app", b"/link").unwrap();
    assert!(files.set_current_directory(b"/link").is_ok());
}
