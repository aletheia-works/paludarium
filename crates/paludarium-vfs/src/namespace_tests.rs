use super::*;

/// The machine's filesystem with `/tmp/m`, `/tmp/m/under` and `/tmp/f`,
/// seen through a first table.
fn machine() -> (Arc<dyn FileSystem>, NamespacedFs) {
    let base = MemFs::new();
    base.mkdir(b"/tmp", 0o1777).unwrap();
    base.mkdir(b"/tmp/m", 0o755).unwrap();
    base.mkdir(b"/tmp/m/under", 0o755).unwrap();
    base.open(b"/tmp/f", 66, 0o644)
        .unwrap()
        .write(b"out")
        .unwrap();
    let lower: Arc<dyn FileSystem> = Arc::new(MountedFs::new(base));
    let table = MountTable::new(&*lower);
    let fs = NamespacedFs::new(Arc::clone(&lower), table);
    (lower, fs)
}

fn tmpfs(blocks: u64) -> NewTmpfs {
    let fs = MemFs::new();
    fs.set_mode(b"/", 0o1777).unwrap();
    NewTmpfs {
        fs,
        settings: Settings {
            blocks,
            inodes: 0,
            common_options: String::new(),
            super_options: format!(",size={}k", blocks * 4),
            parsed: Arc::new(()),
            show: None,
        },
        read_only: false,
        flags: mount_flags::RELATIME,
        source: b"none".to_vec(),
        owner: None,
        kind: "tmpfs",
    }
}

#[test]
fn a_table_of_boot_mounts_is_the_lower_filesystem() {
    let (lower, fs) = machine();
    // But for what a table adds: unique IDs, and its flags.
    let listed: Vec<MountPoint> = fs
        .mounts()
        .into_iter()
        .map(|m| {
            assert!(m.unique > UNIQUE_OFFSET + 1 && m.parent_unique == UNIQUE_OFFSET + 1);
            MountPoint {
                unique: 0,
                parent_unique: 0,
                flags: 0,
                ..m
            }
        })
        .collect();
    assert_eq!(listed, lower.mounts());
    for path in [&b"/tmp/f"[..], b"/tmp/m", b"/", b"/missing"] {
        assert_eq!(fs.metadata(path, true), lower.metadata(path, true));
        assert_eq!(fs.device(path), lower.device(path));
        assert_eq!(fs.mount_id(path), lower.mount_id(path));
        assert!(fs.mount_pin(path).is_none());
    }
    assert_eq!(
        fs.read_dir(b"/tmp").unwrap(),
        lower.read_dir(b"/tmp").unwrap()
    );
    assert_eq!(fs.statfs(b"/tmp"), lower.statfs(b"/tmp"));
}

#[test]
fn a_mount_hides_what_is_under_it() {
    let (_, fs) = machine();
    let under = fs.metadata(b"/tmp/m", true).unwrap();
    fs.mount(b"/tmp/m", tmpfs(256)).unwrap();
    assert_eq!(fs.metadata(b"/tmp/m/under", true), Err(Errno::ENOENT));
    let root = fs.metadata(b"/tmp/m", true).unwrap();
    assert_eq!((root.inode, root.mode), (1, 0o041777));
    assert_ne!(root.inode, under.inode);
    fs.open(b"/tmp/m/new", 66, 0o600)
        .unwrap()
        .write(b"in")
        .unwrap();
    assert_eq!(&*fs.read_file(b"/tmp/m/new").unwrap(), b"in");
    // Its own device, its own ID, and a line in the table.
    assert_ne!(fs.device(b"/tmp/m/new"), fs.device(b"/tmp/f"));
    let mounts = fs.mounts();
    let line = mounts.last().unwrap();
    assert_eq!(line.path, b"/tmp/m");
    assert_eq!((line.kind, line.device), ("tmpfs", fs.device(b"/tmp/m")));
    assert_eq!(line.id, fs.mount_id(b"/tmp/m/new"));
    assert_eq!(line.parent, mounts[0].id);
    assert_eq!(fs.mount_root(b"/tmp/m/new"), b"/tmp/m");
    // statfs reports its size, and its type.
    let stats = fs.statfs(b"/tmp/m").unwrap();
    assert_eq!(
        (stats.kind, stats.blocks, stats.files),
        (TMPFS_MAGIC, 256, 0)
    );
    assert_eq!(stats.blocks_free, 255);
    // Gone, the directory under it is back.
    let target = fs.target(b"/tmp/m").unwrap();
    assert!(target.root && !target.boot && !target.locked);
    fs.umount(target.id, false).unwrap();
    assert!(fs.metadata(b"/tmp/m/under", true).is_ok());
    assert_eq!(fs.metadata(b"/tmp/m/new", true), Err(Errno::ENOENT));
}

#[test]
fn dotdot_leaves_a_mount_for_where_it_is_mounted() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    let tmp = fs.metadata(b"/tmp", true).unwrap().inode;
    assert_eq!(fs.metadata(b"/tmp/m/..", true).unwrap().inode, tmp);
    assert_eq!(fs.metadata(b"/tmp/m/d/../..", true).unwrap().inode, tmp);
    assert_eq!(&*fs.read_file(b"/tmp/m/d/../../f").unwrap(), b"out");
    // A link in the mount out of it, and one into it from outside.
    fs.symlink(b"../f", b"/tmp/m/up").unwrap();
    assert_eq!(&*fs.read_file(b"/tmp/m/up").unwrap(), b"out");
    fs.symlink(b"/tmp/m/d", b"/tmp/into").unwrap();
    fs.open(b"/tmp/into/g", 66, 0o600).unwrap();
    assert!(fs.metadata(b"/tmp/m/d/g", false).is_ok());
}

#[test]
fn a_mount_on_a_mount_stacks_and_comes_off_in_turn() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/first", 66, 0o600).unwrap();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    assert_eq!(fs.metadata(b"/tmp/m/first", true), Err(Errno::ENOENT));
    let top = fs.target(b"/tmp/m").unwrap();
    assert!(fs.metadata(b"/tmp/m/..", true).is_ok());
    fs.umount(top.id, false).unwrap();
    assert!(fs.metadata(b"/tmp/m/first", true).is_ok());
}

#[test]
fn a_chroot_keeps_dotdot_and_links_at_its_root_across_mounts() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/jail", 0o755).unwrap();
    fs.open(b"/tmp/m/jail/f", 66, 0o600)
        .unwrap()
        .write(b"in")
        .unwrap();
    fs.symlink(b"/f", b"/tmp/m/jail/abs").unwrap();
    let jail = fs.rooted(b"/tmp/m/jail").unwrap();
    assert_eq!(jail.root(), b"/tmp/m/jail");
    for path in [
        &b"/tmp/m/jail/abs"[..],
        b"/tmp/m/jail/../../../f",
        b"/tmp/m/jail/f",
    ] {
        assert_eq!(&*jail.read_file(path).unwrap(), b"in", "{path:?}");
    }
    // The view shares the table.
    assert_eq!(jail.mounts(), fs.mounts());
}

#[test]
fn renames_and_links_stay_on_one_mount_and_mount_points_stay() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/a", 66, 0o600).unwrap();
    assert_eq!(fs.rename(b"/tmp/f", b"/tmp/m/f"), Err(EXDEV));
    assert_eq!(fs.link(b"/tmp/f", b"/tmp/m/f"), Err(EXDEV));
    assert_eq!(fs.rename(b"/tmp/m/a", b"/tmp/a"), Err(EXDEV));
    fs.rename(b"/tmp/m/a", b"/tmp/m/b").unwrap();
    // The mount point is in use for rmdir and rename.
    assert_eq!(fs.unlink(b"/tmp/m", true), Err(EBUSY));
    assert_eq!(fs.rename(b"/tmp/m", b"/tmp/n"), Err(EBUSY));
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    assert_eq!(fs.rename(b"/tmp/n", b"/tmp/m"), Err(EBUSY));
    // Renaming a directory above a mount moves the mount with it.
    fs.mkdir(b"/tmp/n/p", 0o755).unwrap();
    fs.mount(b"/tmp/n/p", tmpfs(0)).unwrap();
    fs.open(b"/tmp/n/p/x", 66, 0o600).unwrap();
    fs.rename(b"/tmp/n", b"/tmp/o").unwrap();
    assert!(fs.metadata(b"/tmp/o/p/x", true).is_ok());
    assert!(fs.mounts().iter().any(|m| m.path == b"/tmp/o/p"));
}

#[test]
fn a_mount_in_use_or_covered_is_busy_unless_detached() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let id = fs.target(b"/tmp/m").unwrap().id;
    let file = fs.open(b"/tmp/m/a", 66, 0o600).unwrap();
    file.write(b"kept").unwrap();
    let pin = fs.mount_pin(b"/tmp/m/a").unwrap();
    assert_eq!(fs.umount(id, false), Err(EBUSY));
    drop(pin);
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    assert!(fs.target(b"/tmp/m").unwrap().covered);
    assert_eq!(fs.umount(id, false), Err(EBUSY));
    let pin = fs.mount_pin(b"/tmp/m/a").unwrap();
    // Detached, the mount and the one on it go; the open file stays.
    fs.umount(id, true).unwrap();
    assert_eq!(fs.mounts().len(), 1);
    let mut buf = [0; 4];
    assert_eq!(file.read_at(0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"kept");
    drop(pin);
    assert_eq!(fs.umount(id, false), Err(Errno::EINVAL));
}

#[test]
fn ids_and_devices_stay_and_free_ones_are_reused() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    fs.mount(b"/tmp/n", tmpfs(0)).unwrap();
    let (m, n) = (fs.target(b"/tmp/m").unwrap(), fs.target(b"/tmp/n").unwrap());
    let n_device = fs.device(b"/tmp/n");
    assert_eq!((m.id, n.id), (22, 23));
    assert_eq!((fs.device(b"/tmp/m"), n_device), (2, 3));
    fs.umount(m.id, false).unwrap();
    // The other keeps its ID and device; the lowest free ones come next.
    assert_eq!(
        (fs.target(b"/tmp/n").unwrap().id, fs.device(b"/tmp/n")),
        (23, 3)
    );
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    assert_eq!(
        (fs.target(b"/tmp/m").unwrap().id, fs.device(b"/tmp/m")),
        (22, 2)
    );
    assert_eq!(fs.device(b"/tmp/f"), lower.device(b"/tmp/f"));
}

#[test]
fn a_copy_has_new_ids_the_same_files_and_mounts_of_its_own() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/a", 66, 0o600).unwrap();
    let copy = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    let (mine, theirs) = (fs.mounts(), copy.mounts());
    assert_eq!(mine.len(), theirs.len());
    for (a, b) in mine.iter().zip(&theirs) {
        assert_ne!(a.id, b.id);
        assert_eq!((&a.path, a.device), (&b.path, b.device));
    }
    assert_eq!(theirs[1].parent, theirs[0].id);
    assert!(copy.target(b"/tmp/m").unwrap().locked);
    assert!(copy.target(b"/").unwrap().locked);
    // The same file system, mounted in each on its own.
    assert!(copy.metadata(b"/tmp/m/a", true).is_ok());
    let id = copy.target(b"/tmp/m").unwrap().id;
    copy.umount(id, false).unwrap();
    assert!(fs.metadata(b"/tmp/m/a", true).is_ok());
    assert!(copy.metadata(b"/tmp/m/a", true).is_err());
}

#[test]
fn expire_marks_then_unmounts() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let id = fs.target(b"/tmp/m").unwrap().id;
    assert_eq!(fs.expire(id), Err(Errno::EAGAIN));
    assert_eq!(fs.expire(id), Ok(()));
    assert!(fs.metadata(b"/tmp/m/under", true).is_ok());
}

#[test]
fn mountinfo_fields_of_a_tmpfs() {
    let (_, fs) = machine();
    let mut new = tmpfs(256);
    new.flags |= mount_flags::NOSUID | mount_flags::NOEXEC;
    fs.mount(b"/tmp/m", new).unwrap();
    let line = fs.mounts().pop().unwrap();
    assert_eq!(line.options, ",nosuid,noexec,relatime");
    assert_eq!(line.super_options, ",size=1024k");
    assert_eq!(line.source, b"none");
}

#[test]
fn a_bind_mount_shows_the_same_files_from_its_root() {
    let (lower, fs) = machine();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m", b"/tmp/b", false).unwrap();
    // The directory under the source, on the same device, a mount of its own.
    assert_eq!(
        fs.metadata(b"/tmp/b/under", true).unwrap().inode,
        fs.metadata(b"/tmp/m/under", true).unwrap().inode
    );
    assert_eq!(fs.device(b"/tmp/b"), lower.device(b"/tmp/m"));
    assert_ne!(fs.mount_id(b"/tmp/b"), fs.mount_id(b"/tmp/m"));
    // A file made through one is in the other.
    fs.open(b"/tmp/b/new", 66, 0o600)
        .unwrap()
        .write(b"x")
        .unwrap();
    assert_eq!(&*lower.read_file(b"/tmp/m/new").unwrap(), b"x");
    // `..` from its root leaves it for where it is mounted.
    assert_eq!(&*fs.read_file(b"/tmp/b/../f").unwrap(), b"out");
    let line = fs.mounts().pop().unwrap();
    assert_eq!(
        (&line.path[..], &line.root[..]),
        (&b"/tmp/b"[..], &b"/tmp/m"[..])
    );
    assert_eq!(line.parent, fs.mounts()[0].id);
    // Linking or renaming across the two mounts is EXDEV.
    assert_eq!(fs.link(b"/tmp/m/new", b"/tmp/b/again"), Err(EXDEV));
    assert_eq!(fs.rename(b"/tmp/b/new", b"/tmp/m/moved"), Err(EXDEV));
    fs.rename(b"/tmp/b/new", b"/tmp/b/moved").unwrap();
    assert!(fs.metadata(b"/tmp/m/moved", true).is_ok());
    let id = fs.target(b"/tmp/b").unwrap().id;
    fs.umount(id, false).unwrap();
    assert_eq!(fs.metadata(b"/tmp/b/under", true), Err(Errno::ENOENT));
}

#[test]
fn a_bind_mount_of_a_tmpfs_keeps_it_after_the_first_goes() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(256)).unwrap();
    fs.mkdir(b"/tmp/m/sub", 0o755).unwrap();
    fs.open(b"/tmp/m/sub/a", 66, 0o600)
        .unwrap()
        .write(b"in")
        .unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m/sub", b"/tmp/b", false).unwrap();
    assert_eq!(fs.device(b"/tmp/b/a"), fs.device(b"/tmp/m"));
    let line = fs.mounts().pop().unwrap();
    assert_eq!((line.kind, &line.root[..]), ("tmpfs", &b"/sub"[..]));
    assert_eq!(fs.statfs(b"/tmp/b").unwrap().blocks, 256);
    // The first mount is not in use by the second.
    let first = fs.target(b"/tmp/m").unwrap().id;
    fs.umount(first, false).unwrap();
    assert_eq!(&*fs.read_file(b"/tmp/b/a").unwrap(), b"in");
    // `..` at the bind's root goes up where it is mounted, not to `/sub`'s.
    assert_eq!(&*fs.read_file(b"/tmp/b/../f").unwrap(), b"out");
}

#[test]
fn a_file_binds_onto_a_file_only() {
    let (_, fs) = machine();
    fs.open(b"/tmp/g", 66, 0o644)
        .unwrap()
        .write(b"gee")
        .unwrap();
    assert_eq!(fs.bind(b"/tmp/f", b"/tmp/m", false), Err(Errno::ENOTDIR));
    assert_eq!(fs.bind(b"/tmp/m", b"/tmp/g", false), Err(Errno::ENOTDIR));
    fs.bind(b"/tmp/f", b"/tmp/g", false).unwrap();
    assert_eq!(&*fs.read_file(b"/tmp/g").unwrap(), b"out");
    // The file under it is in use, to unlink and rename.
    assert_eq!(fs.unlink(b"/tmp/g", false), Err(EBUSY));
    assert_eq!(fs.rename(b"/tmp/g", b"/tmp/h"), Err(EBUSY));
    let id = fs.target(b"/tmp/g").unwrap().id;
    fs.umount(id, false).unwrap();
    assert_eq!(&*fs.read_file(b"/tmp/g").unwrap(), b"gee");
}

/// `/dev/null`, as the kernel tells of it to a bind mount of it.
fn null() -> GeneratedSource {
    GeneratedSource {
        kind: "devtmpfs",
        device: 5,
        base: b"/dev".to_vec(),
        path: b"/null".to_vec(),
        stat: FileStat {
            inode: 4,
            mode: 0o020_666,
            rdev: 0x103,
            links: 1,
            ..FileStat::default()
        },
        flags: mount_flags::NOSUID | mount_flags::RELATIME,
        shallow: false,
    }
}

#[test]
fn a_bind_mount_of_a_generated_file_leads_the_kernel_to_it() {
    let (lower, fs) = machine();
    assert_eq!(fs.generated(b"/tmp/f", true), None);
    // A file on a file only.
    assert_eq!(
        fs.bind_generated(null(), b"/tmp/m", false),
        Err(Errno::ENOTDIR)
    );
    fs.bind_generated(null(), b"/tmp/f", false).unwrap();
    assert_eq!(
        fs.generated(b"/tmp/f", false),
        Some((b"/dev/null".to_vec(), b"/tmp/f".to_vec()))
    );
    assert_eq!(
        fs.generated(b"/tmp/m/../f", false),
        Some((b"/dev/null".to_vec(), b"/tmp/f".to_vec()))
    );
    assert_eq!(fs.generated(b"/tmp/f/x", false), None);
    // A link to it leads there only when it is followed.
    fs.symlink(b"/tmp/f", b"/tmp/l").unwrap();
    assert_eq!(fs.generated(b"/tmp/l", false), None);
    assert_eq!(
        fs.generated(b"/tmp/l", true),
        Some((b"/dev/null".to_vec(), b"/tmp/f".to_vec()))
    );
    assert_eq!(fs.metadata(b"/tmp/f", true).unwrap().rdev, 0x103);
    // The name is the mount's place.
    assert_eq!(fs.unlink(b"/tmp/f", false), Err(EBUSY));
    let mount = fs
        .mounts()
        .into_iter()
        .find(|m| m.path == b"/tmp/f")
        .unwrap();
    assert_eq!((mount.kind, mount.device), ("devtmpfs", 5));
    assert_eq!(mount.root, b"/null");
    // A bind mount of it is another of the file; a copy of the table has it.
    fs.open(b"/tmp/g", 66, 0o644).unwrap();
    fs.bind(b"/tmp/f", b"/tmp/g", false).unwrap();
    assert_eq!(
        fs.generated(b"/tmp/g", false),
        Some((b"/dev/null".to_vec(), b"/tmp/g".to_vec()))
    );
    let copy = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    assert!(copy.generated(b"/tmp/f", false).is_some());
    let id = fs.target(b"/tmp/f").unwrap().id;
    fs.umount(id, false).unwrap();
    assert_eq!(fs.generated(b"/tmp/f", false), None);
    assert_eq!(&*fs.read_file(b"/tmp/f").unwrap(), b"out");
}

#[test]
fn a_bind_mount_of_a_generated_directory_leads_each_name_to_the_kernel() {
    let (_, fs) = machine();
    let dev = GeneratedSource {
        path: b"/".to_vec(),
        stat: FileStat {
            mode: 0o040_755,
            links: 2,
            ..FileStat::default()
        },
        ..null()
    };
    assert_eq!(
        fs.bind_generated(dev.clone(), b"/tmp/f", false),
        Err(Errno::ENOTDIR)
    );
    fs.bind_generated(dev, b"/tmp/m", false).unwrap();
    let to = |path: &[u8]| fs.generated(path, true).map(|(file, _)| file);
    assert_eq!(to(b"/tmp/m"), Some(b"/dev".to_vec()));
    assert_eq!(to(b"/tmp/m/pts/0"), Some(b"/dev/pts/0".to_vec()));
    assert_eq!(to(b"/tmp/m/pts/.."), Some(b"/dev".to_vec()));
    // `..` at its root leaves it, for where it is mounted.
    assert_eq!(to(b"/tmp/m/.."), None);
    assert_eq!(to(b"/tmp/m/../f"), None);
    assert_eq!(fs.metadata(b"/tmp/m", true).unwrap().mode, 0o040_755);
    assert_eq!(fs.metadata(b"/tmp/m/x", true).unwrap().mode, 0o040_555);
}

#[test]
fn a_bind_mount_of_a_generated_file_keeps_its_locks_in_a_locked_copy() {
    let (lower, fs) = machine();
    let locked = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    locked.bind_generated(null(), b"/tmp/f", false).unwrap();
    use mount_flags::*;
    assert_eq!(
        locked.target(b"/tmp/f").unwrap().locks,
        LOCK_ATIME | LOCK_NOSUID
    );
    fs.bind_generated(null(), b"/tmp/f", false).unwrap();
    assert_eq!(fs.target(b"/tmp/f").unwrap().locks, 0);
    // The locks are those of the start-up `/dev`, locked in the copy
    // whatever mount the target is on: a new, unlocked one too.
    locked.mount(b"/tmp/m", tmpfs(0)).unwrap();
    locked.open(b"/tmp/m/f", 66, 0o600).unwrap();
    locked.bind_generated(null(), b"/tmp/m/f", false).unwrap();
    assert_eq!(
        locked.target(b"/tmp/m/f").unwrap().locks,
        LOCK_ATIME | LOCK_NOSUID
    );
}

#[test]
fn a_recursive_bind_copies_the_mounts_below() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m/under", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/under/in", 66, 0o600).unwrap();
    fs.mkdir(b"/tmp/m/under/deep", 0o755).unwrap();
    fs.mount(b"/tmp/m/under/deep", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/under/deep/z", 66, 0o600).unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.mkdir(b"/tmp/c", 0o755).unwrap();
    // Without MS_REC the mount on `under` stays behind.
    fs.bind(b"/tmp/m", b"/tmp/b", false).unwrap();
    assert_eq!(fs.metadata(b"/tmp/b/under/in", true), Err(Errno::ENOENT));
    fs.bind(b"/tmp/m", b"/tmp/c", true).unwrap();
    assert!(fs.metadata(b"/tmp/c/under/in", true).is_ok());
    assert!(fs.metadata(b"/tmp/c/under/deep/z", true).is_ok());
    let mounts = fs.mounts();
    let at = |p: &[u8]| mounts.iter().find(|m| m.path == p).unwrap().clone();
    let (c, under, deep) = (at(b"/tmp/c"), at(b"/tmp/c/under"), at(b"/tmp/c/under/deep"));
    assert_eq!((under.parent, deep.parent), (c.id, under.id));
    assert_eq!(under.device, at(b"/tmp/m/under").device);
    // The copies' order is the tree's.
    assert!(c.id < under.id && under.id < deep.id);
}

#[test]
fn a_bind_below_locked_mounts_needs_recursion() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m/under", tmpfs(0)).unwrap();
    let copy = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    copy.mkdir(b"/tmp/b", 0o755).unwrap();
    assert_eq!(copy.bind(b"/tmp/m", b"/tmp/b", false), Err(Errno::EINVAL));
    // The source itself may be locked; only mounts below it count.
    copy.bind(b"/tmp/m/under", b"/tmp/b", false).unwrap();
    assert!(!copy.target(b"/tmp/b").unwrap().locked);
    copy.mkdir(b"/tmp/c", 0o755).unwrap();
    copy.bind(b"/tmp/m", b"/tmp/c", true).unwrap();
    assert!(!copy.target(b"/tmp/c").unwrap().locked);
    assert!(copy.target(b"/tmp/c/under").unwrap().locked);
}

#[test]
fn a_bind_mount_follows_a_rename_of_its_source() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/src", 0o755).unwrap();
    fs.open(b"/tmp/m/src/a", 66, 0o600).unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m/src", b"/tmp/b", false).unwrap();
    fs.rename(b"/tmp/m/src", b"/tmp/m/dst").unwrap();
    assert!(fs.metadata(b"/tmp/b/a", true).is_ok());
    assert_eq!(fs.mounts().pop().unwrap().root, b"/dst");
}

#[test]
fn a_recursive_bind_of_the_root_copies_the_boot_mounts() {
    let base = MemFs::new();
    base.mkdir(b"/tmp", 0o1777).unwrap();
    let host =
        std::env::temp_dir().join(format!("paludarium-namespace-boot-{}", std::process::id()));
    std::fs::create_dir(&host).unwrap();
    let mut mounted = MountedFs::new(base);
    mounted
        .mount(
            b"/data".to_vec(),
            Arc::new(paludarium_host::NativeFs::new(&host).unwrap()),
        )
        .unwrap();
    mounted.mkdir(b"/data/sub", 0o755).unwrap();
    mounted
        .open(b"/data/sub/x", 66, 0o644)
        .unwrap()
        .write(b"in")
        .unwrap();
    let lower: Arc<dyn FileSystem> = Arc::new(mounted);
    let fs = NamespacedFs::new(Arc::clone(&lower), MountTable::new(&*lower));
    fs.mkdir(b"/tmp/r", 0o755).unwrap();
    fs.mkdir(b"/tmp/t", 0o755).unwrap();
    fs.bind(b"/", b"/tmp/r", true).unwrap();
    let x = fs.metadata(b"/tmp/r/data/sub/x", true).unwrap();
    assert_eq!(x, fs.metadata(b"/data/sub/x", true).unwrap());
    assert_eq!(fs.device(b"/tmp/r/data"), fs.device(b"/data"));
    // A part of a boot mount, with its root in that mount's coordinates.
    fs.bind(b"/data/sub", b"/tmp/t", false).unwrap();
    assert_eq!(fs.metadata(b"/tmp/t/x", true).unwrap(), x);
    let mounts = fs.mounts();
    let at = |p: &[u8]| mounts.iter().find(|m| m.path == p).unwrap().clone();
    let (r, copy, t) = (at(b"/tmp/r"), at(b"/tmp/r/data"), at(b"/tmp/t"));
    assert_eq!(
        (r.root.as_slice(), copy.root.as_slice()),
        (&b"/"[..], &b"/"[..])
    );
    assert_eq!(copy.parent, r.id);
    assert_eq!(copy.device, at(b"/data").device);
    assert_eq!(t.root, b"/sub");
    assert_eq!(fs.mount_id(b"/tmp/t/x"), t.id);
    assert_eq!(fs.mount_id(b"/tmp/r/data/sub"), copy.id);
    drop((fs, lower));
    std::fs::remove_dir_all(&host).unwrap();
}

/// The optional fields of the mountinfo line at `path`.
fn tags(fs: &NamespacedFs, path: &[u8]) -> String {
    fs.mounts()
        .into_iter()
        .rev()
        .find(|m| m.path == path)
        .unwrap()
        .tags
}

#[test]
fn a_read_only_mount_is_found_by_its_paths() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    assert!(!fs.any_read_only());
    let id = fs.target(b"/tmp/m").unwrap().id;
    fs.reconfigure_mount(id, mount_flags::READONLY | mount_flags::NOATIME)
        .unwrap();
    assert!(fs.any_read_only());
    let ro = ReadOnly {
        mount: true,
        superblock: false,
    };
    assert_eq!(fs.read_only(b"/tmp/m/d", true), ro);
    // A missing name is on its directory's mount.
    assert_eq!(fs.read_only(b"/tmp/m/new", true), ro);
    assert_eq!(fs.read_only(b"/tmp/f", true), ReadOnly::default());
    let line = fs.mounts().pop().unwrap();
    assert!(line.read_only && !line.super_read_only);
    assert_eq!(line.options, ",noatime");
    assert_eq!(fs.statfs_flags(b"/tmp/m"), 0x421);
}

#[test]
fn a_writer_keeps_a_mount_and_its_superblock_writable() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m", b"/tmp/b", false).unwrap();
    let (m, b) = (
        fs.target(b"/tmp/m").unwrap().id,
        fs.target(b"/tmp/b").unwrap().id,
    );
    fs.open(b"/tmp/m/f", 66, 0o600).unwrap();
    let writer = fs.mount_writer(b"/tmp/m/f", true);
    assert!(writer.is_some());
    assert_eq!(fs.reconfigure_mount(m, mount_flags::READONLY), Err(EBUSY));
    // The bind mount has no writer of its own, but its superblock has.
    fs.reconfigure_mount(b, mount_flags::READONLY).unwrap();
    let mut keep = |_: InUse<'_>| Ok(None);
    assert_eq!(fs.reconfigure(b, true, 0, &mut keep), Err(EBUSY));
    drop(writer);
    fs.reconfigure(b, true, mount_flags::RELATIME, &mut keep)
        .unwrap();
    let ro = fs.read_only(b"/tmp/m", true);
    assert!(ro.mount && ro.superblock);
    let lines = fs.mounts();
    let m_line = lines.iter().find(|l| l.id == m).unwrap();
    assert!(!m_line.read_only && m_line.super_read_only);
}

#[test]
fn propagation_types_show_peer_groups_and_masters() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    fs.bind(b"/tmp/m", b"/tmp/b", false).unwrap();
    let b = fs.target(b"/tmp/b").unwrap().id;
    assert_eq!(tags(&fs, b"/tmp/m"), " shared:1");
    assert_eq!(tags(&fs, b"/tmp/b"), " shared:1");
    fs.change_type(b, Propagation::Slave, false).unwrap();
    assert_eq!(tags(&fs, b"/tmp/b"), " master:1");
    fs.change_type(b, Propagation::Shared, false).unwrap();
    assert_eq!(tags(&fs, b"/tmp/b"), " shared:2 master:1");
    // The master's last peer goes: its slave follows its master, none.
    fs.change_type(m, Propagation::Private, false).unwrap();
    assert_eq!(tags(&fs, b"/tmp/m"), "");
    assert_eq!(tags(&fs, b"/tmp/b"), " shared:2");
    fs.change_type(b, Propagation::Unbindable, false).unwrap();
    assert_eq!(tags(&fs, b"/tmp/b"), " unbindable");
    fs.mkdir(b"/tmp/c", 0o755).unwrap();
    assert_eq!(fs.bind(b"/tmp/b", b"/tmp/c", false), Err(Errno::EINVAL));
    // Group 1 is free again, and a mount on a shared one is shared.
    fs.change_type(m, Propagation::Shared, false).unwrap();
    assert_eq!(tags(&fs, b"/tmp/m"), " shared:1");
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    assert_eq!(tags(&fs, b"/tmp/m/d"), " shared:2");
    fs.change_type(m, Propagation::Private, true).unwrap();
    assert_eq!(tags(&fs, b"/tmp/m/d"), "");
}

#[test]
fn a_copy_into_another_user_namespace_is_a_locked_slave() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.reconfigure_mount(m, mount_flags::READONLY | mount_flags::NOSUID)
        .unwrap();
    fs.change_type(m, Propagation::Shared, false).unwrap();
    let peer = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(false));
    assert_eq!(tags(&peer, b"/tmp/m"), " shared:1");
    let slave = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    assert_eq!(tags(&slave, b"/tmp/m"), " master:1");
    let found = slave.target(b"/tmp/m").unwrap();
    use mount_flags::*;
    assert_eq!(found.locks, LOCK_ATIME | LOCK_READONLY | LOCK_NOSUID);
    // The first namespace's mount goes private; a peer is left in the copy.
    fs.change_type(m, Propagation::Private, false).unwrap();
    assert_eq!(tags(&slave, b"/tmp/m"), " master:1");
    drop(peer);
    // With the last peer gone, the slave is private.
    assert_eq!(tags(&slave, b"/tmp/m"), "");
}

#[test]
fn an_expiry_mark_goes_with_a_use() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let id = fs.target(b"/tmp/m").unwrap().id;
    assert_eq!(fs.expire(id), Err(Errno::EAGAIN));
    fs.metadata(b"/tmp/m", true).unwrap();
    assert_eq!(fs.expire(id), Err(Errno::EAGAIN));
    keeping_expiry(|| fs.metadata(b"/tmp/m", true)).unwrap();
    fs.expire(id).unwrap();
}

#[test]
fn a_moved_mount_takes_the_mounts_on_it_and_uncovers_its_old_place() {
    let (_, fs) = machine();
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/d/x", 66, 0o644)
        .unwrap()
        .write(b"in")
        .unwrap();
    let (m, d) = (
        fs.target(b"/tmp/m").unwrap().id,
        fs.target(b"/tmp/m/d").unwrap().id,
    );
    let n = fs.mount_id(b"/tmp/n");
    let paths = [b"/tmp/m/d".to_vec(), b"/tmp/m".to_vec(), b"/tmp".to_vec()];
    let placed = fs.move_mount(b"/tmp/m", b"/tmp/n", &paths).unwrap();
    assert_eq!(
        placed,
        [b"/tmp/n/d".to_vec(), b"/tmp/n".to_vec(), b"/tmp".to_vec()]
    );
    assert_eq!(&*fs.read_file(b"/tmp/n/d/x").unwrap(), b"in");
    assert!(fs.metadata(b"/tmp/m/under", true).is_ok());
    let mounts = fs.mounts();
    let at = |id: u64| mounts.iter().find(|e| e.id == id).unwrap().clone();
    assert_eq!((at(m).path, at(m).parent), (b"/tmp/n".to_vec(), n));
    assert_eq!((at(d).path, at(d).parent), (b"/tmp/n/d".to_vec(), m));
    // A move onto a shared mount makes the tree shared.
    fs.mkdir(b"/tmp/s", 0o755).unwrap();
    fs.mount(b"/tmp/s", tmpfs(0)).unwrap();
    let s = fs.target(b"/tmp/s").unwrap().id;
    fs.change_type(s, Propagation::Shared, false).unwrap();
    fs.mkdir(b"/tmp/s/in", 0o755).unwrap();
    fs.move_mount(b"/tmp/n", b"/tmp/s/in", &[]).unwrap();
    assert_eq!(tags(&fs, b"/tmp/s/in"), " shared:2");
    assert_eq!(tags(&fs, b"/tmp/s/in/d"), " shared:3");
}

#[test]
fn a_move_is_checked_in_linux_order() {
    let (_, fs) = machine();
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    // Not a mount's root, then the root of the namespace.
    assert_eq!(fs.move_mount(b"/tmp", b"/tmp/n", &[]), Err(Errno::EINVAL));
    assert_eq!(fs.move_mount(b"/", b"/tmp/n", &[]), Err(Errno::EINVAL));
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/in", 0o755).unwrap();
    // A directory onto a file, onto itself and into itself.
    assert_eq!(fs.move_mount(b"/tmp/m", b"/tmp/f", &[]), Err(Errno::EINVAL));
    assert_eq!(fs.move_mount(b"/tmp/m", b"/tmp/m", &[]), Err(ELOOP));
    assert_eq!(fs.move_mount(b"/tmp/m", b"/tmp/m/in", &[]), Err(ELOOP));
    // One on a shared mount.
    fs.mount(b"/tmp/m/in", tmpfs(0)).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    assert_eq!(
        fs.move_mount(b"/tmp/m/in", b"/tmp/n", &[]),
        Err(Errno::EINVAL)
    );
    // An unbindable tree onto a shared mount.
    fs.change_type(m, Propagation::Unbindable, false).unwrap();
    fs.mkdir(b"/tmp/n/s", 0o755).unwrap();
    fs.mount(b"/tmp/n/s", tmpfs(0)).unwrap();
    let s = fs.target(b"/tmp/n/s").unwrap().id;
    fs.change_type(s, Propagation::Shared, false).unwrap();
    assert_eq!(
        fs.move_mount(b"/tmp/m", b"/tmp/n/s", &[]),
        Err(Errno::EINVAL)
    );
}

/// A machine with `/tmp`, `/new` and a mount from start-up of a host
/// directory, named `name`, at `/data` holding `/data/x`; the directory
/// goes when the guard does.
fn machine_with_data(name: &str) -> (NamespacedFs, HostDir) {
    let base = MemFs::new();
    base.mkdir(b"/tmp", 0o1777).unwrap();
    base.mkdir(b"/new", 0o755).unwrap();
    let host = std::env::temp_dir().join(format!(
        "paludarium-namespace-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir(&host).unwrap();
    std::fs::write(host.join("x"), b"data").unwrap();
    let mut mounted = MountedFs::new(base);
    mounted
        .mount(
            b"/data".to_vec(),
            Arc::new(paludarium_host::NativeFs::new(&host).unwrap()),
        )
        .unwrap();
    let lower: Arc<dyn FileSystem> = Arc::new(mounted);
    let fs = NamespacedFs::new(Arc::clone(&lower), MountTable::new(&*lower));
    (fs, HostDir(host))
}
/// The names in the directory at `path`, but for `.` and `..`.
fn names(fs: &NamespacedFs, path: &[u8]) -> Vec<Vec<u8>> {
    fs.read_dir(path)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != b"." && n != b"..")
        .collect()
}
/// A host directory removed when it goes.
struct HostDir(std::path::PathBuf);
impl Drop for HostDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pivot_root_puts_the_old_root_under_the_new() {
    let (fs, _host) = machine_with_data("pivot");
    let lower = Arc::clone(&fs.lower);
    let boot = fs.mounts();
    let (root, data) = (boot[0].clone(), boot[1].clone());
    // A mount from start-up stays where the lower filesystem has it.
    assert!(fs.target(b"/data").unwrap().boot);
    assert_eq!(
        fs.move_mount(b"/data", b"/tmp", &[]),
        Err(Errno::EOPNOTSUPP)
    );
    fs.mount(b"/new", tmpfs(0)).unwrap();
    fs.mkdir(b"/new/old", 0o755).unwrap();
    fs.open(b"/new/file", 66, 0o644)
        .unwrap()
        .write(b"new")
        .unwrap();
    let new = fs.target(b"/new").unwrap().id;
    let paths = [
        b"/".to_vec(),
        b"/new".to_vec(),
        b"/tmp".to_vec(),
        b"/data".to_vec(),
    ];
    let placed = fs.pivot_root(b"/new", b"/new/old", b"/", &paths).unwrap();
    assert_eq!(
        placed,
        [
            b"/".to_vec(),
            b"/".to_vec(),
            b"/old/tmp".to_vec(),
            b"/old/data".to_vec()
        ]
    );
    assert_eq!(&*fs.read_file(b"/file").unwrap(), b"new");
    assert_eq!(&*fs.read_file(b"/old/data/x").unwrap(), b"data");
    assert!(fs.metadata(b"/old/tmp", true).is_ok());
    // The old root's place under it is the new root's mount point.
    assert_eq!(names(&fs, b"/old/new"), Vec::<Vec<u8>>::new());
    let mounts = fs.mounts();
    let at = |id: u64| mounts.iter().find(|e| e.id == id).unwrap().clone();
    assert_eq!(mounts.len(), 3);
    assert_eq!((at(new).path, at(new).parent), (b"/".to_vec(), root.parent));
    assert_eq!(
        (at(root.id).path, at(root.id).parent),
        (b"/old".to_vec(), new)
    );
    assert_eq!(
        (at(data.id).path, at(data.id).parent),
        (b"/old/data".to_vec(), root.id)
    );
    assert_eq!(
        (at(root.id).root, at(data.id).root),
        (b"/".to_vec(), b"/".to_vec())
    );
    let found = fs.target(b"/").unwrap();
    assert!(found.namespace_root && found.id == new);
    // The data mount still stays; the old root goes, with it.
    assert!(fs.target(b"/old/data").unwrap().boot);
    let old = fs.target(b"/old").unwrap();
    assert!(!old.boot && !old.namespace_root);
    // A copy keeps it all.
    let copy = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(false));
    assert_eq!(&*copy.read_file(b"/old/data/x").unwrap(), b"data");
    assert_eq!(copy.mounts().len(), 3);
    // In the order `copy_tree` takes them, from the root, which their
    // unique IDs follow.
    let copied = copy.mounts();
    assert_eq!(copied[0].path, b"/");
    assert_eq!(copied[0].parent, root.parent);
    assert_eq!(copied[1].parent, copied[0].id);
    assert!(copied.windows(2).all(|w| w[0].unique < w[1].unique));
    assert_eq!(copied[0].parent_unique + 1, copied[0].unique);
    fs.umount(old.id, true).unwrap();
    assert_eq!(names(&fs, b"/old"), Vec::<Vec<u8>>::new());
    assert_eq!(fs.mounts().len(), 1);
}

#[test]
fn pivot_root_is_checked_in_linux_order() {
    let (fs, _host) = machine_with_data("pivot-order");
    fs.mount(b"/new", tmpfs(0)).unwrap();
    fs.mkdir(b"/new/old", 0o755).unwrap();
    fs.mkdir(b"/new/sub", 0o755).unwrap();
    // On the root's mount, or the root itself.
    assert_eq!(fs.pivot_root(b"/new", b"/tmp", b"/", &[]), Err(EBUSY));
    assert_eq!(fs.pivot_root(b"/", b"/new/old", b"/", &[]), Err(EBUSY));
    // Not a mount's root.
    assert_eq!(
        fs.pivot_root(b"/new/sub", b"/new/old", b"/", &[]),
        Err(Errno::EINVAL)
    );
    // put_old not under the new root.
    assert_eq!(
        fs.pivot_root(b"/new", b"/data", b"/", &[]),
        Err(Errno::EINVAL)
    );
    // A shared new root's parent, then a locked new root.
    let new = fs.target(b"/new").unwrap().id;
    fs.change_type(new, Propagation::Shared, false).unwrap();
    assert_eq!(
        fs.pivot_root(b"/new", b"/new/old", b"/", &[]),
        Err(Errno::EINVAL)
    );
    fs.change_type(new, Propagation::Private, false).unwrap();
    let locked = NamespacedFs::new(Arc::clone(&fs.lower), fs.table().copy(true));
    assert_eq!(
        locked.pivot_root(b"/new", b"/new/old", b"/", &[]),
        Err(Errno::EINVAL)
    );
    // The new root takes over the old root's lock.
    let (first, _locked_host) = machine_with_data("pivot-locked");
    let fs = NamespacedFs::new(Arc::clone(&first.lower), first.table().copy(true));
    fs.mkdir(b"/tmp/new", 0o755).unwrap();
    fs.mount(b"/tmp/new", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/new/old", 0o755).unwrap();
    fs.pivot_root(b"/tmp/new", b"/tmp/new/old", b"/", &[])
        .unwrap();
    assert!(fs.target(b"/").unwrap().locked);
    assert!(!fs.target(b"/old").unwrap().locked);
}

#[test]
fn a_detached_tree_is_reached_by_its_name_only_and_attaches() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/x", 66, 0o644)
        .unwrap()
        .write(b"x")
        .unwrap();
    fs.mkdir(b"/tmp/m/in", 0o755).unwrap();
    fs.mount(b"/tmp/m/in", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/in/y", 66, 0o644)
        .unwrap()
        .write(b"y")
        .unwrap();
    let listed = fs.mounts().len();
    // Without recursion the mount below is not there: its directory is.
    let (flat, pin) = fs.clone_tree(b"/tmp/m", true, false).unwrap();
    assert!(flat.starts_with(b"/\0"));
    assert_eq!(&*fs.read_file(&[&flat[..], b"/x"].concat()).unwrap(), b"x");
    assert_eq!(
        names(&fs, &[&flat[..], b"/in"].concat()),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(fs.mounts().len(), listed);
    // `..` stays at its root.
    assert_eq!(
        fs.metadata(&[&flat[..], b"/../x"].concat(), true).unwrap(),
        fs.metadata(&[&flat[..], b"/x"].concat(), true).unwrap()
    );
    // Gone once nothing holds it.
    drop(pin);
    assert_eq!(fs.mounts().len(), listed);
    assert_eq!(fs.metadata(&flat, true), Err(Errno::ENOENT));
    // With recursion, attached by a move.
    let (tree, pin) = fs.clone_tree(b"/tmp/m", true, true).unwrap();
    assert_eq!(
        &*fs.read_file(&[&tree[..], b"/in/y"].concat()).unwrap(),
        b"y"
    );
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    // Not onto its own tree, and not a mount below its root.
    assert_eq!(
        fs.move_mount(&tree, &[&tree[..], b"/in"].concat(), &[]),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        fs.move_mount(&[&tree[..], b"/in"].concat(), b"/tmp/n", &[]),
        Err(Errno::EINVAL)
    );
    // A mount of the namespace goes onto no detached tree.
    assert_eq!(fs.move_mount(b"/tmp/m/in", &tree, &[]), Err(Errno::EINVAL));
    fs.move_mount(&tree, b"/tmp/n", &[]).unwrap();
    drop(pin);
    assert_eq!(&*fs.read_file(b"/tmp/n/in/y").unwrap(), b"y");
    assert_eq!(fs.mounts().len(), listed + 2);
    let mounts = fs.mounts();
    let n = mounts.iter().find(|m| m.path == b"/tmp/n").unwrap();
    let below = mounts.iter().find(|m| m.path == b"/tmp/n/in").unwrap();
    assert_eq!(below.parent, n.id);
    assert_eq!(n.parent, fs.mount_id(b"/tmp"));
}

#[test]
fn set_group_joins_a_peer_group() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m/d", b"/tmp/b", false).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    // From a private mount.
    assert_eq!(
        fs.set_group(b"/tmp/m", true, b"/tmp/b", true),
        Err(Errno::EINVAL)
    );
    fs.change_type(m, Propagation::Shared, false).unwrap();
    // Not at a mount's root, then the wrong way round (`/` is wider).
    assert_eq!(
        fs.set_group(b"/tmp/m/d", true, b"/tmp/b", true),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        fs.set_group(b"/tmp/b", true, b"/tmp/m", true),
        Err(Errno::EINVAL)
    );
    // Another superblock.
    assert_eq!(
        fs.set_group(b"/tmp/m", true, b"/", true),
        Err(Errno::EINVAL)
    );
    fs.set_group(b"/tmp/m", true, b"/tmp/b", true).unwrap();
    assert_eq!(tags(&fs, b"/tmp/b"), " shared:1");
    // Only onto a private one.
    assert_eq!(
        fs.set_group(b"/tmp/m", true, b"/tmp/b", true),
        Err(Errno::EINVAL)
    );
}

#[test]
fn a_file_open_in_a_detached_tree_outlasts_the_tree() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/in", 0o755).unwrap();
    fs.mount(b"/tmp/m/in", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/in/y", 66, 0o644)
        .unwrap()
        .write(b"y")
        .unwrap();
    let (tree, pin) = fs.clone_tree(b"/tmp/m", true, true).unwrap();
    let y = [&tree[..], b"/in/y"].concat();
    let file = fs.open(&y, 2, 0).unwrap();
    let held = fs.mount_pin(&y);
    // The tree goes with its root's last hold, as Linux's dissolves at the
    // last close of `open_tree`'s descriptor (`umount_tree` with
    // `UMOUNT_COVER`); the file on its mount below still reads and writes.
    drop(pin);
    let _ = fs.mounts();
    assert_eq!(fs.metadata(&tree, true), Err(Errno::ENOENT));
    file.write(b"z").unwrap();
    let mut out = [0; 2];
    file.seek(0, 0).unwrap();
    assert_eq!(file.read(&mut out).unwrap(), 1);
    assert_eq!(&out[..1], b"z");
    drop(held);
}

#[test]
fn a_mount_hook_hears_each_mount_that_comes_goes_or_moves() {
    use MountChange::{Attach, Detach, Move};
    let (_, fs) = machine();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let hearing = Arc::clone(&heard);
    fs.table()
        .set_mount_hook(Some(Arc::new(move |changes: &[(u64, MountChange)], _| {
            lock(&hearing).push(changes.to_vec());
        })));
    let unique = |path: &[u8]| {
        fs.mounts()
            .iter()
            .find(|m| m.path == path)
            .map(|m| m.unique)
            .unwrap()
    };
    let take = || std::mem::take(&mut *lock(&heard));
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let m = unique(b"/tmp/m");
    fs.mkdir(b"/tmp/m/in", 0o755).unwrap();
    fs.mount(b"/tmp/m/in", tmpfs(0)).unwrap();
    let inner = unique(b"/tmp/m/in");
    assert_eq!(take(), [vec![(m, Attach)], vec![(inner, Attach)]]);
    // A recursive bind takes in each copy, each before those on it.
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.bind(b"/tmp/m", b"/tmp/b", true).unwrap();
    let (b, b_in) = (unique(b"/tmp/b"), unique(b"/tmp/b/in"));
    assert_eq!(take(), [vec![(b, Attach), (b_in, Attach)]]);
    // A move tells of the tree's root alone.
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    fs.move_mount(b"/tmp/b", b"/tmp/n", &[]).unwrap();
    assert_eq!(take(), [vec![(b, Move)]]);
    // A detached tree tells nothing until it is attached, and then each of
    // its mounts comes in.
    let (tree, pin) = fs.clone_tree(b"/tmp/m", true, true).unwrap();
    assert!(take().is_empty());
    fs.mkdir(b"/tmp/c", 0o755).unwrap();
    fs.move_mount(&tree, b"/tmp/c", &[]).unwrap();
    drop(pin);
    let (c, c_in) = (unique(b"/tmp/c"), unique(b"/tmp/c/in"));
    assert_eq!(take(), [vec![(c, Attach), (c_in, Attach)]]);
    // One that goes before it is attached tells nothing.
    let (_, pin) = fs.clone_tree(b"/tmp/m", true, false).unwrap();
    drop(pin);
    let _ = fs.mounts();
    fs.umount(fs.target(b"/tmp/m").unwrap().id, true).unwrap();
    assert_eq!(take(), [vec![(m, Detach), (inner, Detach)]]);
}

#[test]
fn a_release_hook_hears_each_mount_freed() {
    let (_, fs) = machine();
    let freed = Arc::new(Mutex::new(Vec::new()));
    let hearing = Arc::clone(&freed);
    fs.table()
        .set_release_hook(Some(Arc::new(move |id| lock(&hearing).push(id))));
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/x", 66, 0o644).unwrap();
    let id = fs.target(b"/tmp/m").unwrap().id;
    // Held by an open file, a detached mount is freed with it.
    let pin = fs.mount_pin(b"/tmp/m/x");
    fs.umount(id, true).unwrap();
    assert_eq!(*lock(&freed), Vec::<u64>::new());
    drop(pin);
    assert_eq!(*lock(&freed), [id]);
    // So is a namespace's copy when the namespace ends.
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let copy = fs.table().copy(false);
    let copied: Vec<u64> = NamespacedFs::new(Arc::clone(&fs.lower), Arc::clone(&copy))
        .mounts()
        .iter()
        .map(|m| m.id)
        .collect();
    lock(&freed).clear();
    drop(copy);
    let mut heard = lock(&freed).clone();
    heard.sort_unstable();
    assert_eq!(heard, copied);
}

#[test]
fn a_move_beneath_puts_the_mount_under_the_topmost_one() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/a", 66, 0o644).unwrap();
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    fs.mount(b"/tmp/n", tmpfs(0)).unwrap();
    fs.open(b"/tmp/n/b", 66, 0o644).unwrap();
    let (top, below) = (
        fs.target(b"/tmp/m").unwrap().id,
        fs.target(b"/tmp/n").unwrap().id,
    );
    let parent = fs.mount_id(b"/tmp");
    let paths = [b"/tmp/n".to_vec(), b"/tmp/m".to_vec()];
    let placed = fs
        .move_mount_beneath(b"/tmp/n", true, b"/tmp/m", true, &paths)
        .unwrap();
    assert_eq!(placed, [b"/tmp/m".to_vec(), b"/tmp/m".to_vec()]);
    // The topmost mount still shows; the moved one is on its parent, and
    // the topmost on it.
    assert!(fs.metadata(b"/tmp/m/a", true).is_ok());
    assert_eq!(fs.metadata(b"/tmp/n/b", true), Err(Errno::ENOENT));
    let mounts = fs.mounts();
    let at = |id: u64| mounts.iter().find(|e| e.id == id).unwrap().clone();
    assert_eq!(
        (at(below).path, at(below).parent),
        (b"/tmp/m".to_vec(), parent)
    );
    assert_eq!((at(top).path, at(top).parent), (b"/tmp/m".to_vec(), below));
    // Its unmount uncovers the moved mount.
    fs.umount(top, false).unwrap();
    assert!(fs.metadata(b"/tmp/m/b", true).is_ok());
}

#[test]
fn a_move_beneath_is_checked_in_linux_order() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/in", 0o755).unwrap();
    fs.mkdir(b"/tmp/n", 0o755).unwrap();
    fs.mount(b"/tmp/n", tmpfs(0)).unwrap();
    let beneath = |from: &[u8], to: &[u8]| fs.move_mount_beneath(from, true, to, true, &[]);
    // Not a mount's root, then the namespace's root.
    assert_eq!(beneath(b"/tmp/n", b"/tmp/m/in"), Err(Errno::EINVAL));
    assert_eq!(beneath(b"/tmp/n", b"/"), Err(Errno::EINVAL));
    // A source in the topmost mount's tree.
    fs.mount(b"/tmp/m/in", tmpfs(0)).unwrap();
    assert_eq!(beneath(b"/tmp/m/in", b"/tmp/m"), Err(Errno::EINVAL));
    // A shared parent that would propagate a copy onto the topmost mount
    // at its root: a bind of the parent's directory onto itself.
    fs.mkdir(b"/tmp/s", 0o755).unwrap();
    fs.mount(b"/tmp/s", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/s/d", 0o755).unwrap();
    let s = fs.target(b"/tmp/s").unwrap().id;
    fs.change_type(s, Propagation::Shared, false).unwrap();
    fs.bind(b"/tmp/s/d", b"/tmp/s/d", false).unwrap();
    assert_eq!(beneath(b"/tmp/n", b"/tmp/s/d"), Err(Errno::EINVAL));
}

#[test]
fn a_move_beneath_a_locked_mount_takes_its_lock() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let locked = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    locked.mkdir(b"/tmp/n", 0o755).unwrap();
    locked.mount(b"/tmp/n", tmpfs(0)).unwrap();
    let below = locked.target(b"/tmp/n").unwrap().id;
    let top = locked.target(b"/tmp/m").unwrap();
    assert!(top.locked);
    locked
        .move_mount_beneath(b"/tmp/n", true, b"/tmp/m", true, &[])
        .unwrap();
    // The moved mount hides what is below now, and the topmost one may go.
    let mounts = locked.mounts();
    assert!(mounts.iter().any(|e| e.id == below && e.parent != top.id));
    locked.umount(top.id, false).unwrap();
    let moved = locked.target(b"/tmp/m").unwrap();
    assert_eq!((moved.id, moved.locked), (below, true));
}

#[test]
fn a_bind_without_recursion_shows_the_directory_a_boot_mount_covers() {
    let (fs, _host) = machine_with_data("uncover");
    fs.mkdir(b"/tmp/b", 0o755).unwrap();
    fs.mkdir(b"/tmp/c", 0o755).unwrap();
    // `clone_mnt` copies the root mount alone: `/data` there is the
    // directory under the boot mount, empty, on the root's device.
    fs.bind(b"/", b"/tmp/b", false).unwrap();
    assert!(names(&fs, b"/tmp/b/data").is_empty());
    assert_eq!(fs.metadata(b"/tmp/b/data/x", true), Err(Errno::ENOENT));
    assert_eq!(fs.device(b"/tmp/b/data"), fs.device(b"/"));
    assert_ne!(fs.device(b"/data"), fs.device(b"/"));
    // With `MS_REC` the boot mount comes along, and shows its files.
    fs.bind(b"/", b"/tmp/c", true).unwrap();
    assert_eq!(names(&fs, b"/tmp/c/data"), [b"x".to_vec()]);
    assert_eq!(fs.device(b"/tmp/c/data/x"), fs.device(b"/data"));
    // The source itself is unchanged.
    assert_eq!(names(&fs, b"/data"), [b"x".to_vec()]);
}

/// Whether a file of the content `text` is at `path`.
fn holds(fs: &NamespacedFs, path: &[u8], text: &[u8]) -> bool {
    let Ok(file) = fs.open(path, 0, 0) else {
        return false;
    };
    let mut buf = vec![0; text.len() + 1];
    let n = file.read(&mut buf).unwrap();
    &buf[..n] == text
}

#[test]
fn a_mount_on_a_shared_mount_propagates_to_its_peers_and_slaves() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    for dir in [&b"/tmp/p"[..], b"/tmp/s"] {
        fs.mkdir(dir, 0o755).unwrap();
        fs.bind(b"/tmp/m", dir, false).unwrap();
    }
    let s = fs.target(b"/tmp/s").unwrap().id;
    fs.change_type(s, Propagation::Slave, false).unwrap();
    // A mount on the master shows on its peer and on its slave.
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/d/x", 66, 0o644)
        .unwrap()
        .write(b"ex")
        .unwrap();
    assert!(holds(&fs, b"/tmp/p/d/x", b"ex"));
    assert!(holds(&fs, b"/tmp/s/d/x", b"ex"));
    let at_m = tags(&fs, b"/tmp/m/d");
    assert_eq!(tags(&fs, b"/tmp/p/d"), at_m);
    assert_eq!(tags(&fs, b"/tmp/s/d"), at_m.replace("shared", "master"));
    // An unmount there takes the copies away.
    let d = fs.target(b"/tmp/m/d").unwrap().id;
    fs.umount(d, false).unwrap();
    assert!(fs.mounts().iter().all(|l| !l.path.ends_with(b"/d")));
    // A slave's own mount does not go back to its master.
    fs.mount(b"/tmp/s/d", tmpfs(0)).unwrap();
    fs.open(b"/tmp/s/d/y", 66, 0o644).unwrap();
    assert!(fs.metadata(b"/tmp/m/d/y", false).is_err());
    assert!(fs.metadata(b"/tmp/p/d/y", false).is_err());
}

#[test]
fn a_mount_propagates_into_a_copy_of_the_namespace() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    let peer = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(false));
    let slave = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    fs.open(b"/tmp/m/d/x", 66, 0o644)
        .unwrap()
        .write(b"ex")
        .unwrap();
    assert!(holds(&peer, b"/tmp/m/d/x", b"ex"));
    assert!(holds(&slave, b"/tmp/m/d/x", b"ex"));
    assert_eq!(
        tags(&slave, b"/tmp/m/d"),
        tags(&fs, b"/tmp/m/d").replace("shared", "master")
    );
    // A mount in the peer comes back; the slave's stays its own.
    peer.mkdir(b"/tmp/m/e", 0o755).unwrap();
    peer.mount(b"/tmp/m/e", tmpfs(0)).unwrap();
    assert_eq!(tags(&fs, b"/tmp/m/e"), tags(&peer, b"/tmp/m/e"));
    slave.mkdir(b"/tmp/m/f", 0o755).unwrap();
    slave.mount(b"/tmp/m/f", tmpfs(0)).unwrap();
    assert!(fs.mounts().iter().all(|l| l.path != b"/tmp/m/f"));
    // An unmount goes to each copy.
    let d = fs.target(b"/tmp/m/d").unwrap().id;
    fs.umount(d, true).unwrap();
    for other in [&peer, &slave] {
        assert!(other.mounts().iter().all(|l| l.path != b"/tmp/m/d"));
    }
}

#[test]
fn a_propagated_unmount_leaves_a_busy_or_covered_copy() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    fs.mkdir(b"/tmp/p", 0o755).unwrap();
    fs.bind(b"/tmp/m", b"/tmp/p", false).unwrap();
    let p = fs.target(b"/tmp/p").unwrap().id;
    fs.change_type(p, Propagation::Slave, false).unwrap();
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    // A file open on the copy keeps the unmount from happening.
    fs.open(b"/tmp/p/d/f", 66, 0o644).unwrap();
    let held = fs.mount_writer(b"/tmp/p/d/f", true);
    let d = fs.target(b"/tmp/m/d").unwrap().id;
    assert!(held.is_some());
    assert_eq!(fs.umount(d, false), Err(EBUSY));
    drop(held);
    // A mount on the copy keeps the copy there.
    fs.mkdir(b"/tmp/p/d/e", 0o755).unwrap();
    fs.mount(b"/tmp/p/d/e", tmpfs(0)).unwrap();
    fs.umount(d, false).unwrap();
    assert!(fs.mounts().iter().any(|l| l.path == b"/tmp/p/d"));
    assert!(fs.mounts().iter().all(|l| l.path != b"/tmp/m/d"));
}

#[test]
fn a_propagated_unmount_takes_a_locked_copy_only_with_its_parent() {
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d", 0o755).unwrap();
    let m = fs.target(b"/tmp/m").unwrap().id;
    fs.change_type(m, Propagation::Shared, false).unwrap();
    let slave = NamespacedFs::new(Arc::clone(&lower), fs.table().copy(true));
    // Of another user namespace.
    slave.table().set_owner(Arc::new(()));
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d/x", 0o755).unwrap();
    fs.mkdir(b"/tmp/m/d/y", 0o755).unwrap();
    fs.mount(b"/tmp/m/d/x", tmpfs(0)).unwrap();
    // The slave's copies are locked; one of its own keeps its copy of
    // /tmp/m/d there.
    slave.mount(b"/tmp/m/d/y", tmpfs(0)).unwrap();
    let d = fs.target(b"/tmp/m/d").unwrap().id;
    fs.umount(d, true).unwrap();
    // The copy at the unmounted place is unlocked but stays for the
    // slave's own mount on it, so the locked copy on it stays too.
    let kept: Vec<Vec<u8>> = slave.mounts().into_iter().map(|l| l.path).collect();
    assert!(kept.iter().any(|p| p == b"/tmp/m/d"));
    assert!(kept.iter().any(|p| p == b"/tmp/m/d/x"));
    // Without the slave's own mount, both go.
    let y = slave.target(b"/tmp/m/d/y").unwrap().id;
    slave.umount(y, false).unwrap();
    fs.mount(b"/tmp/m/d", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/d/x", 0o755).unwrap();
    fs.mount(b"/tmp/m/d/x", tmpfs(0)).unwrap();
    let d = fs.target(b"/tmp/m/d").unwrap().id;
    let before = slave.mounts().len();
    fs.umount(d, true).unwrap();
    assert_eq!(slave.mounts().len(), before - 2);
}

/// A table whose hook keeps what it hears, and the unique ID of the
/// topmost mount at a path.
type Heard = Arc<Mutex<Vec<(Vec<(u64, MountChange)>, bool)>>>;
fn hearing(fs: &NamespacedFs) -> Heard {
    let heard = Arc::new(Mutex::new(Vec::new()));
    let hearing = Arc::clone(&heard);
    fs.table().set_mount_hook(Some(Arc::new(
        move |changes: &[(u64, MountChange)], ended| {
            lock(&hearing).push((changes.to_vec(), ended));
        },
    )));
    heard
}
fn unique_at(fs: &NamespacedFs, path: &[u8]) -> u64 {
    fs.mounts()
        .iter()
        .rfind(|m| m.path == path)
        .map(|m| m.unique)
        .unwrap()
}

#[test]
fn pivot_root_moves_the_old_root_then_the_new_one() {
    let (_, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    fs.mkdir(b"/tmp/m/old", 0o755).unwrap();
    let (root, new) = (unique_at(&fs, b"/"), unique_at(&fs, b"/tmp/m"));
    let heard = hearing(&fs);
    fs.pivot_root(b"/tmp/m", b"/tmp/m/old", b"/", &[]).unwrap();
    assert_eq!(
        *lock(&heard),
        [(
            vec![(root, MountChange::Move), (new, MountChange::Move)],
            false
        )]
    );
}

#[test]
fn a_propagated_unmount_moves_what_it_slides_down_first() {
    use MountChange::{Detach, Move};
    let (_, fs) = machine();
    fs.mkdir(b"/tmp/a", 0o755).unwrap();
    fs.mkdir(b"/tmp/e", 0o755).unwrap();
    fs.mount(b"/tmp/a", tmpfs(0)).unwrap();
    let a = fs.target(b"/tmp/a").unwrap().id;
    fs.change_type(a, Propagation::Shared, false).unwrap();
    fs.bind(b"/tmp/a", b"/tmp/e", false).unwrap();
    fs.mkdir(b"/tmp/a/x", 0o755).unwrap();
    // A mount at a/x and its copy at e/x, which a private mount covers.
    fs.mount(b"/tmp/a/x", tmpfs(0)).unwrap();
    let (p, q) = (unique_at(&fs, b"/tmp/a/x"), unique_at(&fs, b"/tmp/e/x"));
    let copy = fs.target(b"/tmp/e/x").unwrap().id;
    fs.change_type(copy, Propagation::Private, false).unwrap();
    fs.mount(b"/tmp/e/x", tmpfs(0)).unwrap();
    let top = unique_at(&fs, b"/tmp/e/x");
    assert!(top != q);
    let heard = hearing(&fs);
    fs.umount(fs.target(b"/tmp/a/x").unwrap().id, true).unwrap();
    // The cover slides down onto e, then both go.
    assert_eq!(
        *lock(&heard),
        [(vec![(top, Move), (p, Detach), (q, Detach)], false)]
    );
    assert_eq!(unique_at(&fs, b"/tmp/e/x"), top);
}

#[test]
fn a_table_that_goes_takes_out_every_mount() {
    use MountChange::Detach;
    let (lower, fs) = machine();
    fs.mount(b"/tmp/m", tmpfs(0)).unwrap();
    let copy = fs.table().copy(false);
    let other = NamespacedFs::new(lower, Arc::clone(&copy));
    let heard = hearing(&other);
    let listed = other.mounts();
    let below = listed[0].parent_unique;
    drop(listed);
    drop(other);
    drop(copy);
    let heard = lock(&heard).clone();
    assert_eq!(heard.len(), 1);
    let (changes, ended) = &heard[0];
    assert!(ended);
    assert_eq!(changes[0], (below, Detach));
    assert!(changes.iter().all(|(_, change)| *change == Detach));
    assert_eq!(changes.len(), 1 + fs.mounts().len());
}
