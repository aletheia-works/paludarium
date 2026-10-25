use crate::*;
#[test]
fn create_read_write_seek() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    f.write(b"abc").unwrap();
    f.seek(0, 0).unwrap();
    let mut b = [0; 4];
    assert_eq!(f.read(&mut b), Ok(3));
    assert_eq!(&b[..3], b"abc");
}
#[test]
fn links_and_unlink_lifetime() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    fs.link(b"/a", b"/b").unwrap();
    assert_eq!(f.stat().unwrap().links, 2);
    fs.unlink(b"/a", false).unwrap();
    f.write(b"x").unwrap();
    assert_eq!(&*fs.read_file(b"/b").unwrap(), b"x");
}
#[test]
fn symlink_component_dotdot() {
    let fs = MemFs::new();
    fs.mkdir(b"/a", 0o755).unwrap();
    fs.mkdir(b"/a/sub", 0o755).unwrap();
    fs.open(b"/a/file", 66, 0o644).unwrap();
    fs.symlink(b"/a/sub", b"/s").unwrap();
    assert!(fs.metadata(b"/s/../file", true).is_ok());
    assert_eq!(fs.metadata(b"/s", false).unwrap().mode, 0o120777);
}
#[test]
fn symlink_loop() {
    let fs = MemFs::new();
    fs.symlink(b"/b", b"/a").unwrap();
    fs.symlink(b"/a", b"/b").unwrap();
    assert_eq!(fs.metadata(b"/a", true), Err(Errno(40)));
}
#[test]
fn directory_rename_and_errors() {
    let fs = MemFs::new();
    fs.mkdir(b"/d", 0o755).unwrap();
    fs.open(b"/d/a", 66, 0o644).unwrap();
    assert_eq!(fs.unlink(b"/d", true), Err(Errno(39)));
    assert_eq!(fs.rename(b"/d", b"/d/child"), Err(Errno::EINVAL));
    fs.rename(b"/d/a", b"/d/b").unwrap();
    assert_eq!(fs.read_dir(b"/d").unwrap().len(), 3);
}
#[test]
fn flock_shared_and_release() {
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
fn append_truncate_and_flags() {
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
fn non_utf8_nofollow_and_invalid() {
    let fs = MemFs::new();
    fs.open(b"/\xff", 66, 0o644).unwrap();
    fs.symlink(b"/\xff", b"/s").unwrap();
    assert!(fs.open(b"/s", 131072, 0).is_err());
    assert_eq!(fs.mkdir(b"/x\0", 0), Err(Errno::EINVAL));
    assert!(fs.open(b"/\xff/child", 0, 0).is_err());
}

#[test]
fn path_missing_component_before_dotdot() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/missing/../", true), Err(Errno::ENOENT));
}
#[test]
fn path_regular_before_dotdot() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.metadata(b"/a/../", true), Err(Errno::ENOTDIR));
}
#[test]
fn path_trailing_slash() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.metadata(b"/a/", true), Err(Errno::ENOTDIR));
}
#[test]
fn path_name_limit() {
    let fs = MemFs::new();
    let mut p = b"/".to_vec();
    p.extend([b'a'; 256]);
    assert_eq!(fs.metadata(&p, true), Err(Errno::ENAMETOOLONG));
}
#[test]
fn path_root_clamped() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/../../", true).unwrap().inode, 1);
}
#[test]
fn path_dangling_create() {
    let fs = MemFs::new();
    fs.symlink(b"a", b"/s").unwrap();
    fs.open(b"/s", 66, 0o600).unwrap();
    assert!(fs.metadata(b"/a", true).is_ok());
}
#[test]
fn inode_directory_links() {
    let fs = MemFs::new();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 2);
    fs.mkdir(b"/d", 0o755).unwrap();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 3);
    fs.unlink(b"/d", true).unwrap();
    assert_eq!(fs.metadata(b"/", true).unwrap().links, 2);
}
#[test]
fn inode_unlink_reclaims_map() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    let id = f.stat().unwrap().inode;
    fs.unlink(b"/a", false).unwrap();
    assert!(!lock(&fs.tree).nodes.contains_key(&id));
    assert_eq!(f.write(b"alive"), Ok(5));
}
#[test]
fn open_readonly_write() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(fs.open(b"/a", 0, 0).unwrap().write(b"x"), Err(Errno::EBADF));
}
#[test]
fn open_writeonly_read() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 65, 0o600).unwrap();
    assert_eq!(f.read(&mut [0]), Err(Errno::EBADF));
}
#[test]
fn open_exclusive() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert!(matches!(fs.open(b"/a", 194, 0o600), Err(Errno::EEXIST)));
}
#[test]
fn open_directory_flags() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap();
    assert!(matches!(fs.open(b"/a", 65536, 0), Err(Errno::ENOTDIR)));
    assert!(matches!(fs.open(b"/", 2, 0), Err(Errno::EISDIR)));
}
#[test]
fn open_truncate() {
    let fs = MemFs::new();
    fs.open(b"/a", 66, 0o600).unwrap().write(b"data").unwrap();
    fs.open(b"/a", 514, 0).unwrap();
    assert_eq!(fs.metadata(b"/a", true).unwrap().size, 0);
}
#[test]
fn open_sparse() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    f.seek(3, 0).unwrap();
    f.write(b"x").unwrap();
    assert_eq!(&*fs.read_file(b"/a").unwrap(), b"\0\0\0x");
}
#[test]
fn open_eof() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o600).unwrap();
    assert_eq!(f.read(&mut [0; 4]), Ok(0));
}
#[test]
fn open_shared_lock_drop() {
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
#[test]
fn set_mode_and_times_keep_the_file_type() {
    let fs = MemFs::new();
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    fs.symlink(b"/a", b"/link").unwrap();
    // chmod follows a final symbolic link and keeps the file type.
    fs.set_mode(b"/link", 0o170_600).unwrap();
    assert_eq!(fs.metadata(b"/a", false).unwrap().mode, 0o100_600);
    assert_eq!(fs.metadata(b"/link", false).unwrap().mode, 0o120_777);
    f.set_mode(0o4755).unwrap();
    assert_eq!(f.stat().unwrap().mode, 0o104_755);
    fs.set_times(b"/link", true, Some(1), Some(-5)).unwrap();
    assert_eq!(fs.metadata(b"/a", false).unwrap().mtime_ns, -5);
    fs.set_times(b"/link", false, None, Some(7)).unwrap();
    assert_eq!(fs.metadata(b"/link", false).unwrap().mtime_ns, 7);
    assert_eq!(fs.metadata(b"/a", false).unwrap().mtime_ns, -5);
    f.set_times(None, None).unwrap();
    assert_eq!(f.stat().unwrap().mtime_ns, -5);
    f.set_times(Some(0), Some(9)).unwrap();
    assert_eq!(f.stat().unwrap().mtime_ns, 9);
    assert_eq!(f.sync(), Ok(()));
    assert_eq!(fs.set_mode(b"/missing", 0o600), Err(Errno::ENOENT));
    assert_eq!(
        fs.set_times(b"/missing", true, None, Some(1)),
        Err(Errno::ENOENT)
    );
}
#[test]
fn statfs_reports_a_tmpfs_with_what_the_tree_holds() {
    let fs = MemFs::new();
    let empty = fs.statfs(b"/").unwrap();
    assert_eq!((empty.kind, empty.block_size), (TMPFS_MAGIC, 4096));
    assert_eq!(empty.blocks, MEMORY_BYTES / 4096);
    let f = fs.open(b"/a", 66, 0o644).unwrap();
    f.write(&[0; 5000]).unwrap();
    let used = fs.statfs(b"/a").unwrap();
    assert_eq!(empty.blocks_free - used.blocks_free, 2);
    assert_eq!(used.blocks_available, used.blocks_free);
    assert_eq!(empty.files_free - used.files_free, 1);
    assert_eq!(used.name_max, 255);
    assert_eq!(fs.statfs(b"/missing"), Err(Errno::ENOENT));
    assert_eq!(
        fs.mounts(),
        vec![MountPoint {
            path: b"/".to_vec(),
            kind: "tmpfs"
        }]
    );
}
mod sparse {
    use super::*;
    const SEEK_DATA: u32 = 3;
    const SEEK_HOLE: u32 = 4;
    const ENXIO: Errno = Errno(6);
    fn file() -> (MemFs, Arc<dyn FileHandle>) {
        let fs = MemFs::new();
        let f = fs.open(b"/a", 66, 0o644).unwrap();
        (fs, f)
    }
    fn blocks(f: &Arc<dyn FileHandle>) -> u64 {
        f.stat().unwrap().blocks.unwrap()
    }
    #[test]
    fn a_grown_file_is_a_hole_that_takes_nothing() {
        let (fs, f) = file();
        f.truncate(1 << 40).unwrap();
        assert_eq!(f.stat().unwrap().size, 1 << 40);
        assert_eq!(blocks(&f), 0);
        let mut b = [1u8; 8];
        assert_eq!(f.read_at(1 << 39, &mut b), Ok(8));
        assert_eq!(b, [0; 8]);
        assert_eq!(f.seek(0, SEEK_DATA), Err(ENXIO));
        assert_eq!(f.seek(5, SEEK_HOLE), Ok(5));
        let empty = MemFs::new().statfs(b"/").unwrap();
        assert_eq!(fs.statfs(b"/").unwrap().blocks_free, empty.blocks_free);
    }
    #[test]
    fn a_write_allocates_the_pages_it_touches() {
        let (fs, f) = file();
        f.write_at(1 << 20, b"x").unwrap();
        // One byte past the end of a page takes the next one too.
        f.write_at(3 * 4096 - 1, b"yz").unwrap();
        assert_eq!(f.stat().unwrap().size, (1 << 20) + 1);
        assert_eq!(blocks(&f), 3 * 8);
        let empty = MemFs::new().statfs(b"/").unwrap();
        assert_eq!(fs.statfs(b"/").unwrap().blocks_free, empty.blocks_free - 3);
        assert_eq!(f.seek(0, SEEK_DATA), Ok(2 * 4096));
        assert_eq!(f.seek(2 * 4096 + 9, SEEK_HOLE), Ok(4 * 4096));
        assert_eq!(f.seek(4 * 4096, SEEK_DATA), Ok(1 << 20));
        // The end of the file is a hole.
        assert_eq!(f.seek(1 << 20, SEEK_HOLE), Ok((1 << 20) + 1));
        assert_eq!(f.seek((1 << 20) + 1, SEEK_DATA), Err(ENXIO));
        assert_eq!(f.seek(-1, SEEK_HOLE), Err(ENXIO));
        let mut b = [0u8; 4];
        assert_eq!(f.read_at(3 * 4096 - 2, &mut b), Ok(4));
        assert_eq!(&b, b"\0yz\0");
    }
    #[test]
    fn fallocate_allocates_without_data() {
        let (_fs, f) = file();
        f.truncate(4 * 4096).unwrap();
        f.allocate(4096, 4096 + 1).unwrap();
        assert_eq!(blocks(&f), 2 * 8);
        // Allocated pages read as zeros and are still a hole.
        assert_eq!(f.seek(0, SEEK_DATA), Err(ENXIO));
        f.write_at(4096 + 5, b"a").unwrap();
        assert_eq!(blocks(&f), 2 * 8);
        assert_eq!(f.seek(0, SEEK_DATA), Ok(4096));
        assert_eq!(f.seek(4096, SEEK_HOLE), Ok(2 * 4096));
    }
    #[test]
    fn punching_frees_whole_pages_and_clears_the_rest() {
        let (_fs, f) = file();
        f.write_at(0, &[b'x'; 4 * 4096]).unwrap();
        f.zero_range(100, 2 * 4096).unwrap();
        // Page 1 is freed; pages 0 and 2 are cleared from 100 and up to 100.
        assert_eq!(blocks(&f), 3 * 8);
        assert_eq!(f.stat().unwrap().size, 4 * 4096);
        let mut b = vec![0u8; 4 * 4096];
        f.read_at(0, &mut b).unwrap();
        assert!(b[..100].iter().all(|&c| c == b'x'));
        assert!(b[100..2 * 4096 + 100].iter().all(|&c| c == 0));
        assert!(b[2 * 4096 + 100..].iter().all(|&c| c == b'x'));
        assert_eq!(f.seek(0, SEEK_HOLE), Ok(4096));
    }
    #[test]
    fn shrinking_frees_the_pages_past_the_end_and_clears_the_last() {
        let (_fs, f) = file();
        f.write_at(0, &[b'x'; 3 * 4096]).unwrap();
        f.truncate(100).unwrap();
        assert_eq!(blocks(&f), 8);
        f.truncate(3 * 4096).unwrap();
        let mut b = vec![1u8; 3 * 4096];
        f.read_at(0, &mut b).unwrap();
        assert!(b[100..].iter().all(|&c| c == 0));
        assert_eq!(blocks(&f), 8);
    }
}
mod sparse_limits {
    use super::*;
    #[test]
    fn allocating_past_the_file_system_size_is_enospc_and_allocates_nothing() {
        let fs = MemFs::new();
        let f = fs.open(b"/a", 66, 0o644).unwrap();
        assert_eq!(f.allocate(0, 1 << 40), Err(Errno(28)));
        assert_eq!(f.stat().unwrap().blocks, Some(0));
        // Up to the size it is fine, and what is held counts.
        assert_eq!(f.allocate(0, MEMORY_BYTES), Ok(()));
        let g = fs.open(b"/b", 66, 0o644).unwrap();
        assert_eq!(g.allocate(0, 1), Err(Errno(28)));
        // Allocating pages the file already has needs nothing more.
        assert_eq!(f.allocate(4096, 4096), Ok(()));
    }
    #[test]
    fn an_unlinked_open_file_keeps_its_pages_until_it_is_closed() {
        let fs = MemFs::new();
        let free = fs.statfs(b"/").unwrap().blocks_free;
        let f = fs.open(b"/a", 66, 0o644).unwrap();
        fs.unlink(b"/a", false).unwrap();
        assert_eq!(f.allocate(0, 3 << 30), Ok(()));
        assert_eq!(
            fs.statfs(b"/").unwrap().blocks_free,
            free - (3 << 30) / 4096
        );
        // Its pages still count: another 3 GiB would pass the 4 GiB.
        assert_eq!(f.allocate(3 << 30, 3 << 30), Err(Errno(28)));
        drop(f);
        assert_eq!(fs.statfs(b"/").unwrap().blocks_free, free);
    }
}
