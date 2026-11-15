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
        },
        read_only: false,
        flags: mount_flags::RELATIME,
        source: b"none".to_vec(),
        owner: None,
    }
}

#[test]
fn a_table_of_boot_mounts_is_the_lower_filesystem() {
    let (lower, fs) = machine();
    assert_eq!(fs.mounts(), lower.mounts());
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
