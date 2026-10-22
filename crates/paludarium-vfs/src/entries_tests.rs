use crate::*;
fn entry(path: &[u8], kind: EntryKind, mode: u32, mtime_ns: i128) -> GuestEntry {
    GuestEntry {
        path: path.to_vec(),
        kind,
        mode,
        mtime_ns,
    }
}
fn file(path: &[u8], content: &[u8]) -> GuestEntry {
    entry(path, EntryKind::File(content.to_vec()), 0o644, 7)
}
fn dir(path: &[u8]) -> GuestEntry {
    entry(path, EntryKind::Directory, 0o755, 5)
}
#[test]
fn places_directories_symlinks_and_hard_links_with_times() {
    let mut fs = MemFs::new();
    // Any order: parents and link targets come later in the list.
    fs.add_entries(&[
        entry(b"/b/link", EntryKind::HardLink(b"/a/x/f".to_vec()), 0, 0),
        entry(b"/a/s", EntryKind::Symlink(b"x/f".to_vec()), 0o777, -3),
        entry(b"/a/s2", EntryKind::HardLink(b"/a/s".to_vec()), 0, 0),
        file(b"/a/x/f", b"data"),
        entry(b"/a/x", EntryKind::Directory, 0o2775, 11),
        entry(b"/a/empty", EntryKind::Directory, 0o700, -1_500_000_000),
        dir(b"/a"),
        dir(b"/b"),
        entry(b"/", EntryKind::Directory, 0o711, 9),
    ])
    .unwrap();
    let f = fs.metadata(b"/a/x/f", false).unwrap();
    let l = fs.metadata(b"/b/link", false).unwrap();
    assert_eq!(
        (f.inode, f.links, f.mode, f.mtime_ns),
        (l.inode, 2, 0o100644, 7)
    );
    let s = fs.metadata(b"/a/s", false).unwrap();
    let s2 = fs.metadata(b"/a/s2", false).unwrap();
    assert_eq!(
        (s.inode, s.links, s.mode, s.mtime_ns),
        (s2.inode, 2, 0o120777, -3)
    );
    assert_eq!(fs.readlink(b"/a/s2").unwrap(), b"x/f");
    assert_eq!(&*fs.read_file(b"/a/s").unwrap(), b"data");
    let x = fs.metadata(b"/a/x", false).unwrap();
    assert_eq!((x.mode, x.mtime_ns), (0o042775, 11));
    let empty = fs.metadata(b"/a/empty", false).unwrap();
    assert_eq!(
        (empty.mode, empty.links, empty.mtime_ns),
        (0o040700, 2, -1_500_000_000)
    );
    assert_eq!(fs.metadata(b"/a", false).unwrap().mtime_ns, 5);
    let root = fs.metadata(b"/", false).unwrap();
    assert_eq!((root.mode, root.mtime_ns), (0o040711, 9));
}
#[test]
fn an_existing_directory_takes_the_entry_mode() {
    let mut fs = MemFs::new();
    fs.mkdir(b"/tmp", 0o1777).unwrap();
    fs.add_entries(&[entry(b"/tmp", EntryKind::Directory, 0o700, 1)])
        .unwrap();
    assert_eq!(fs.metadata(b"/tmp", false).unwrap().mode, 0o040700);
    assert_eq!(fs.add_entries(&[file(b"/tmp", b"")]), Err(Errno::EEXIST));
}
#[test]
fn rejects_what_a_snapshot_cannot_hold() {
    let reject = |entries: &[GuestEntry], errno: Errno| {
        assert_eq!(MemFs::new().add_entries(entries), Err(errno), "{entries:?}");
    };
    reject(&[file(b"/a/../b", b"")], Errno::EINVAL);
    reject(&[file(b"/a/", b"")], Errno::EINVAL);
    reject(&[file(b"//a", b"")], Errno::EINVAL);
    reject(&[file(b"relative", b"")], Errno::ENOENT);
    reject(&[file(b"/a\0", b"")], Errno::EINVAL);
    reject(&[file(b"/a/f", b"")], Errno::ENOENT);
    reject(&[file(b"/a", b""), file(b"/a/f", b"")], Errno::ENOTDIR);
    reject(&[file(b"/a", b""), file(b"/a", b"")], Errno::EEXIST);
    reject(&[file(b"/a", b""), dir(b"/a")], Errno::EEXIST);
    reject(&[file(b"/", b"")], Errno::EEXIST);
    reject(
        &[entry(b"/a", EntryKind::File(vec![]), 0o10000, 0)],
        Errno::EINVAL,
    );
    reject(
        &[entry(b"/s", EntryKind::Symlink(b"t".to_vec()), 0o755, 0)],
        Errno::EINVAL,
    );
    reject(
        &[entry(b"/s", EntryKind::Symlink(vec![]), 0o777, 0)],
        Errno::EINVAL,
    );
    reject(
        &[entry(b"/s", EntryKind::Symlink(b"t\0".to_vec()), 0o777, 0)],
        Errno::EINVAL,
    );
    reject(
        &[entry(
            b"/s",
            EntryKind::Symlink(vec![b'a'; PATH_MAX]),
            0o777,
            0,
        )],
        Errno::ENAMETOOLONG,
    );
    reject(
        &[
            dir(b"/d"),
            entry(b"/l", EntryKind::HardLink(b"/d".to_vec()), 0, 0),
        ],
        Errno::EPERM,
    );
    reject(
        &[entry(b"/l", EntryKind::HardLink(b"/none".to_vec()), 0, 0)],
        Errno::ENOENT,
    );
    // A symlink on the way to a parent is not a directory.
    reject(
        &[
            dir(b"/d"),
            entry(b"/s", EntryKind::Symlink(b"d".to_vec()), 0o777, 0),
            file(b"/s/f", b""),
        ],
        Errno::ENOTDIR,
    );
}
#[test]
fn limits_count_entries_and_content_bytes() {
    let big = |n| file(b"/big", &vec![0; n]);
    assert!(MemFs::new().add_entries(&[big(MAX_ENTRY_BYTES)]).is_ok());
    assert_eq!(
        MemFs::new().add_entries(&[big(MAX_ENTRY_BYTES), file(b"/one", b"x")]),
        Err(Errno::EINVAL)
    );
    let many: Vec<_> = (0..=MAX_ENTRIES)
        .map(|i| file(format!("/{i}").as_bytes(), b""))
        .collect();
    assert_eq!(MemFs::new().add_entries(&many), Err(Errno::EINVAL));
}
