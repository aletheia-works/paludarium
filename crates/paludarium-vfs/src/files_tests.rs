use crate::*;
#[test]
fn u7_create_read_write_seek() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    f.write(b"abc").unwrap();
    f.seek(0, 0).unwrap();
    let mut b = [0; 4];
    assert_eq!(f.read(&mut b), Ok(3));
    assert_eq!(&b[..3], b"abc");
}
#[test]
fn u7_links_and_unlink_lifetime() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    fs.link(b"/a", b"/b").unwrap();
    assert_eq!(f.stat().unwrap().links, 2);
    fs.unlink(b"/a", false).unwrap();
    f.write(b"x").unwrap();
    assert_eq!(&*fs.read_file(b"/b").unwrap(), b"x");
}
#[test]
fn u7_symlink_component_dotdot() {
    let fs = MemFs::new();
    fs.mkdir(b"/a", 0o755).unwrap();
    fs.mkdir(b"/a/sub", 0o755).unwrap();
    fs.open(b"/a/file", 66, 0o644).unwrap();
    fs.symlink(b"/a/sub", b"/s").unwrap();
    assert!(fs.metadata(b"/s/../file", true).is_ok());
    assert_eq!(fs.metadata(b"/s", false).unwrap().mode, 0o120777);
}
#[test]
fn u7_symlink_loop() {
    let fs = MemFs::new();
    fs.symlink(b"/b", b"/a").unwrap();
    fs.symlink(b"/a", b"/b").unwrap();
    assert_eq!(fs.metadata(b"/a", true), Err(Errno(40)));
}
#[test]
fn u7_directory_rename_and_errors() {
    let fs = MemFs::new();
    fs.mkdir(b"/d", 0o755).unwrap();
    fs.open(b"/d/a", 66, 0o644).unwrap();
    assert_eq!(fs.unlink(b"/d", true), Err(Errno(39)));
    assert_eq!(fs.rename(b"/d", b"/d/child"), Err(Errno::EINVAL));
    fs.rename(b"/d/a", b"/d/b").unwrap();
    assert_eq!(fs.read_dir(b"/d").unwrap().len(), 3);
}
#[test]
fn u7_flock_shared_and_release() {
    let fs = MemFs::new();
    let a = fs.open(b"/a", 66, 0o644).unwrap();
    let b = fs.open(b"/a", 2, 0).unwrap();
    a.flock(1).unwrap();
    b.flock(1).unwrap();
    assert_eq!(a.flock(6), Err(Errno::EAGAIN));
    drop(b);
    a.flock(6).unwrap();
    a.flock(8).unwrap();
}
#[test]
fn u7_append_truncate_and_flags() {
    let fs = MemFs::new();
    let a = fs.open(b"/a", 66, 0o644).unwrap();
    a.write(b"a").unwrap();
    a.set_flags(1024).unwrap();
    a.seek(0, 0).unwrap();
    a.write(b"b").unwrap();
    assert_eq!(&*fs.read_file(b"/a").unwrap(), b"ab");
    a.truncate(5).unwrap();
    assert_eq!(a.stat().unwrap().size, 5);
    assert_eq!(a.seek(-1, 0), Err(Errno::EINVAL));
}
#[test]
fn u7_non_utf8_nofollow_and_invalid() {
    let fs = MemFs::new();
    fs.open(b"/\xff", 66, 0o644).unwrap();
    fs.symlink(b"/\xff", b"/s").unwrap();
    assert!(fs.open(b"/s", 131072, 0).is_err());
    assert_eq!(fs.mkdir(b"/x\0", 0), Err(Errno::EINVAL));
    assert!(fs.open(b"/\xff/child", 0, 0).is_err());
}

#[test]
fn u7_path_missing_component_before_dotdot() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/missing/../", true), Err(Errno::ENOENT));
}
#[test]
fn u7_path_regular_before_dotdot() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.metadata(b"/a/../", true), Err(Errno::ENOTDIR));
}
#[test]
fn u7_path_trailing_slash() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.metadata(b"/a/", true), Err(Errno::ENOTDIR));
}
#[test]
fn u7_path_name_limit() {
    let fs = MemFs::new();
    let mut p = b"/".to_vec();
    p.extend([b'a'; 256]);
    assert_eq!(fs.metadata(&p, true), Err(Errno::ENAMETOOLONG));
}
#[test]
fn u7_path_root_clamped() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/../../", true).unwrap().inode, 1);
}
#[test]
fn u7_path_dangling_create() {
    let fs = MemFs::new();
    fs.symlink(b"a", b"/s").unwrap();
    fs.open(b"/s", 66, 0o600).unwrap();
    assert!(fs.metadata(b"/a", true).is_ok());
}
#[test]
fn u7_inode_directory_links() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 2);
    fs.mkdir(b"/d", 0o755).unwrap();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 3);
    fs.unlink(b"/d", true).unwrap();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 2);
}
#[test]
fn u7_inode_unlink_reclaims_map() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    let id = f.stat().unwrap().inode;
    fs.unlink(b"/a", false).unwrap();
    assert!(!lock(&fs.tree).nodes.contains_key(&id));
    assert_eq!(f.write(b"alive"), Ok(5));
}
#[test]
fn u7_open_readonly_write() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.open(b"/a", 0, 0).unwrap().write(b"x"), Err(Errno::EBADF));
}
#[test]
fn u7_open_writeonly_read() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 65, 0o600).unwrap();
    assert_eq!(f.read(&mut [0]), Err(Errno::EBADF));
}
#[test]
fn u7_open_exclusive() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert!(matches!(fs.open(b"/a", 194, 0o600), Err(Errno::EEXIST)));
}
#[test]
fn u7_open_directory_flags() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert!(matches!(fs.open(b"/a", 65536, 0), Err(Errno::ENOTDIR)));
    assert!(matches!(fs.open(b"/", 2, 0), Err(Errno::EISDIR)));
}
#[test]
fn u7_open_truncate() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap().write(b"data").unwrap();
    fs.open(b"/a", 514, 0).unwrap();
    assert_eq!(fs.metadata(b"/a", true).unwrap().size, 0);
}
#[test]
fn u7_open_sparse() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    f.seek(3, 0).unwrap();
    f.write(b"x").unwrap();
    assert_eq!(&*fs.read_file(b"/a").unwrap(), b"\0\0\0x");
}
#[test]
fn u7_open_eof() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(f.read(&mut [0; 4]), Ok(0));
}
#[test]
fn u7_open_shared_lock_drop() {
    let fs = MemFs::new();
    let a = fs.open(b"/a", 66, 0o600).unwrap();
    let dup = Arc::clone(&a);
    let b = fs.open(b"/a", 2, 0).unwrap();
    a.flock(2).unwrap();
    drop(a);
    assert_eq!(b.flock(6), Err(Errno::EAGAIN));
    drop(dup);
    b.flock(6).unwrap();
}
