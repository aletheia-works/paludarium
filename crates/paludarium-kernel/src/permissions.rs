//! Linux's discretionary access control (`fs/namei.c`, `fs/attr.c`): the
//! permission bits and owners of files against a thread's filesystem IDs,
//! supplementary groups and capabilities. Root, with every filesystem
//! capability and filesystem IDs of 0, passes every check but executing a
//! file that no one may execute, so its calls skip them.
use crate::credentials::Credentials;
use crate::files::Files;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;

pub(crate) const MAY_EXEC: u32 = 1;
pub(crate) const MAY_WRITE: u32 = 2;
pub(crate) const MAY_READ: u32 = 4;
const CAP_CHOWN: u64 = 1 << 0;
const CAP_DAC_OVERRIDE: u64 = 1 << 1;
const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
const CAP_FOWNER: u64 = 1 << 3;
const CAP_FSETID: u64 = 1 << 4;
const DIRECTORY: u32 = 0o040000;
const REGULAR: u32 = 0o100000;
const SYMLINK: u32 = 0o120000;
const TYPE: u32 = 0o170000;

fn capable(creds: &Credentials, capability: u64) -> bool {
    creds.effective & capability != 0
}

/// `in_group_p`: the filesystem group or a supplementary one.
pub(crate) fn in_group(creds: &Credentials, gid: u32) -> bool {
    creds.fsgid == gid || creds.groups.binary_search(&gid).is_ok()
}

/// Whether no check on files can fail for `creds` (but executing a file
/// with no execute bit), and nothing they make needs another owner.
pub(crate) fn unchecked(creds: &Credentials) -> bool {
    let all = CAP_CHOWN | CAP_DAC_OVERRIDE | CAP_DAC_READ_SEARCH | CAP_FOWNER | CAP_FSETID;
    creds.effective & all == all && creds.fsuid == 0 && creds.fsgid == 0
}

/// `inode_owner_or_capable`.
fn owner_or_capable(creds: &Credentials, stat: &FileStat) -> bool {
    creds.fsuid == stat.uid || capable(creds, CAP_FOWNER)
}

/// `generic_permission`: the owner's bits for the owner, the group's for a
/// member when they differ from the others', else the others'; then
/// `CAP_DAC_READ_SEARCH` to read or search and `CAP_DAC_OVERRIDE` for the
/// rest, but executing a file no one may execute (EACCES).
pub(crate) fn permission(creds: &Credentials, stat: &FileStat, mask: u32) -> Result<(), Errno> {
    let mask = mask & 7;
    let mut mode = stat.mode;
    if creds.fsuid == stat.uid {
        mode >>= 6;
    } else if mask & (mode ^ (mode >> 3)) != 0 && in_group(creds, stat.gid) {
        mode >>= 3;
    }
    if mask & !mode == 0 {
        return Ok(());
    }
    if stat.mode & TYPE == DIRECTORY {
        if mask & MAY_WRITE == 0 && capable(creds, CAP_DAC_READ_SEARCH) {
            return Ok(());
        }
        if capable(creds, CAP_DAC_OVERRIDE) {
            return Ok(());
        }
        return Err(Errno::EACCES);
    }
    if mask == MAY_READ && capable(creds, CAP_DAC_READ_SEARCH) {
        return Ok(());
    }
    if (mask & MAY_EXEC == 0 || stat.mode & 0o111 != 0) && capable(creds, CAP_DAC_OVERRIDE) {
        return Ok(());
    }
    Err(Errno::EACCES)
}

/// `may_create`: writing and searching the directory a name goes into.
fn may_create(creds: &Credentials, parent: &FileStat) -> Result<(), Errno> {
    permission(creds, parent, MAY_WRITE | MAY_EXEC)
}

/// `may_delete`: writing and searching the directory, and in a sticky one
/// (`check_sticky`) owning the file or the directory, or `CAP_FOWNER`
/// (EPERM).
fn may_delete(creds: &Credentials, parent: &FileStat, file: &FileStat) -> Result<(), Errno> {
    permission(creds, parent, MAY_WRITE | MAY_EXEC)?;
    if parent.mode & 0o1000 != 0
        && creds.fsuid != file.uid
        && creds.fsuid != parent.uid
        && !capable(creds, CAP_FOWNER)
    {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// What a path walk found: the directory that holds the last component and
/// the file it names. A file that is not there has a directory and no
/// file; with neither, the walk could not tell (a missing or non-directory
/// component, a path paludarium makes itself, too many links), which the
/// call then reports itself.
#[derive(Default)]
pub(crate) struct Found {
    pub(crate) parent: Option<FileStat>,
    pub(crate) file: Option<FileStat>,
}

/// Linux's path walk (`link_path_walk`) of `raw` from `dir` (`AT_FDCWD` or
/// a descriptor), with its permission checks: searching (`MAY_EXEC`) each
/// directory a component is looked up in, from the starting directory,
/// whose own ancestors are not checked, and through each symbolic link on
/// the way and, when `follow`, the last. Returns what it found. Paths under
/// `/proc` and `/dev` are not checked.
pub(crate) fn walk(
    files: &Files,
    creds: &Credentials,
    dir: u64,
    raw: &[u8],
    follow: bool,
) -> Result<Found, Errno> {
    let follow = follow || raw.last() == Some(&b'/');
    let start = if raw.first() == Some(&b'/') {
        b"/".to_vec()
    } else {
        files.path(dir, b".".to_vec())?
    };
    let Some(start) = crate::files::resolved(files, &start) else {
        return Ok(Found::default());
    };
    let components = |path: &[u8]| -> Vec<Vec<u8>> {
        path.split(|&b| b == b'/')
            .filter(|part| !part.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    let join = |parts: &[Vec<u8>]| -> Vec<u8> {
        if parts.is_empty() {
            return b"/".to_vec();
        }
        parts
            .iter()
            .flat_map(|part| [&b"/"[..], part].concat())
            .collect()
    };
    let mut parts = components(&start);
    let mut pending: Vec<Vec<u8>> = components(raw).into_iter().rev().collect();
    let mut links = 0;
    while let Some(part) = pending.pop() {
        let here = join(&parts);
        if crate::files::generated(&here) {
            return Ok(Found::default());
        }
        let Ok(directory) = files.fs.metadata(&here, false) else {
            return Ok(Found::default());
        };
        if directory.mode & TYPE != DIRECTORY {
            return Ok(Found::default());
        }
        permission(creds, &directory, MAY_EXEC)?;
        match &part[..] {
            b"." => continue,
            b".." => {
                parts.pop();
                continue;
            }
            _ => {}
        }
        parts.push(part);
        let candidate = join(&parts);
        let last = pending.is_empty();
        if crate::files::generated(&candidate) {
            return Ok(Found::default());
        }
        let Ok(stat) = files.fs.metadata(&candidate, false) else {
            return Ok(Found {
                parent: last.then_some(directory),
                file: None,
            });
        };
        if stat.mode & TYPE == SYMLINK && (!last || follow) {
            links += 1;
            let Ok(target) = files.fs.readlink(&candidate) else {
                return Ok(Found::default());
            };
            if links > 40 || target.is_empty() {
                return Ok(Found::default());
            }
            parts.pop();
            if target.first() == Some(&b'/') {
                parts.clear();
            }
            pending.extend(components(&target).into_iter().rev());
            continue;
        }
        if last {
            return Ok(Found {
                parent: Some(directory),
                file: Some(stat),
            });
        }
    }
    // The path ends in a directory reached by `.`, `..` or a link, or is the
    // starting directory itself.
    Ok(Found {
        parent: None,
        file: files.fs.metadata(&join(&parts), false).ok(),
    })
}

/// [`walk`] with the thread's credentials, which root skips.
pub(crate) fn search(
    files: &Files,
    creds: &Credentials,
    dir: u64,
    raw: &[u8],
    follow: bool,
) -> Result<Found, Errno> {
    if unchecked(creds) {
        return Ok(Found::default());
    }
    walk(files, creds, dir, raw, follow)
}

/// `open`'s checks (`may_open`, `may_o_create`): reading or writing the
/// file it opens, as its access mode and `O_TRUNC` ask, or writing and
/// searching the directory a new file goes into. Returns that directory's
/// status when the call creates the file, which then takes the thread's
/// owner ([`own`]).
pub(crate) fn open(
    files: &Files,
    creds: &Credentials,
    dir: u64,
    raw: &[u8],
    flags: u32,
) -> Result<Option<FileStat>, Errno> {
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_TRUNC: u32 = 0o1000;
    const O_NOFOLLOW: u32 = 0o400000;
    const O_PATH: u32 = 0o10000000;
    let follow = flags & O_NOFOLLOW == 0 && flags & (O_CREAT | O_EXCL) != O_CREAT | O_EXCL;
    let found = search(files, creds, dir, raw, follow)?;
    match (found.parent, found.file) {
        (Some(parent), None) if flags & O_CREAT != 0 => {
            may_create(creds, &parent)?;
            Ok(Some(parent))
        }
        // An existing file with O_EXCL is EEXIST, which open finds.
        (_, Some(file))
            if flags & O_PATH == 0 && flags & (O_CREAT | O_EXCL) != O_CREAT | O_EXCL =>
        {
            let mut mask = match flags & 3 {
                0 => MAY_READ,
                1 => MAY_WRITE,
                _ => MAY_READ | MAY_WRITE,
            };
            if flags & O_TRUNC != 0 {
                mask |= MAY_WRITE;
            }
            match file.mode & TYPE {
                // A symbolic link not followed is ELOOP, and a directory
                // opened to write EISDIR, which open finds.
                SYMLINK => Ok(None),
                DIRECTORY if mask & MAY_WRITE != 0 => Ok(None),
                _ => permission(creds, &file, mask).map(|()| None),
            }
        }
        _ => Ok(None),
    }
}

/// `mkdir`, `symlink` and `link`'s new name: a name that is not there yet
/// goes into a directory the thread may write and search (one that is is
/// EEXIST, which the call finds). Returns that directory's status, for the
/// new file's owner ([`own`]).
pub(crate) fn create(
    files: &Files,
    creds: &Credentials,
    dir: u64,
    raw: &[u8],
) -> Result<Option<FileStat>, Errno> {
    let found = search(files, creds, dir, raw, false)?;
    match (found.parent, found.file) {
        (Some(parent), None) => may_create(creds, &parent).map(|()| Some(parent)),
        _ => Ok(None),
    }
}

/// Makes a file the thread just made at `path` its own: its filesystem
/// user ID, and its filesystem group ID unless the directory `parent` is
/// set-group-ID, whose group the file already took. A mounted host
/// directory keeps its files root's, which this leaves.
pub(crate) fn own(
    files: &Files,
    creds: &Credentials,
    path: &[u8],
    follow: bool,
    parent: &FileStat,
) {
    let group = (parent.mode & 0o2000 == 0).then_some(creds.fsgid);
    let _ = files.fs.set_owner(path, follow, Some(creds.fsuid), group);
}

/// `unlink` and `rmdir`: [`may_delete`] on a file that is there.
pub(crate) fn delete(
    files: &Files,
    creds: &Credentials,
    dir: u64,
    raw: &[u8],
) -> Result<(), Errno> {
    let found = search(files, creds, dir, raw, false)?;
    match (found.parent, found.file) {
        (Some(parent), Some(file)) => may_delete(creds, &parent, &file),
        _ => Ok(()),
    }
}

/// `rename`'s checks, in `vfs_rename`'s order, when both names are on one
/// filesystem (else EXDEV, which the call finds first): nothing when both
/// name one file; deleting the old name; deleting the file the new name
/// replaces, or creating the name; and writing a directory that moves to
/// another one, whose `..` changes.
pub(crate) fn rename(
    files: &Files,
    creds: &Credentials,
    old: (u64, &[u8]),
    new: (u64, &[u8]),
    devices: impl Fn() -> bool,
) -> Result<(), Errno> {
    let from = search(files, creds, old.0, old.1, false)?;
    let to = search(files, creds, new.0, new.1, false)?;
    let (Some(old_parent), Some(source), Some(new_parent)) = (from.parent, from.file, to.parent)
    else {
        return Ok(());
    };
    if !devices() || to.file.is_some_and(|target| target.inode == source.inode) {
        return Ok(());
    }
    may_delete(creds, &old_parent, &source)?;
    match to.file {
        Some(target) => may_delete(creds, &new_parent, &target)?,
        None => may_create(creds, &new_parent)?,
    }
    if source.mode & TYPE == DIRECTORY && old_parent.inode != new_parent.inode {
        permission(creds, &source, MAY_WRITE)?;
    }
    Ok(())
}

/// `chmod`'s check (`setattr_prepare`): the owner or `CAP_FOWNER`, else
/// EPERM. Returns the mode to set, without the set-group-ID bit when the
/// thread is not in the file's group and lacks `CAP_FSETID`.
pub(crate) fn chmod(creds: &Credentials, stat: &FileStat, mode: u32) -> Result<u32, Errno> {
    if unchecked(creds) {
        return Ok(mode);
    }
    if !owner_or_capable(creds, stat) {
        return Err(Errno::EPERM);
    }
    if mode & 0o2000 != 0 && !in_group(creds, stat.gid) && !capable(creds, CAP_FSETID) {
        return Ok(mode & !0o2000);
    }
    Ok(mode)
}

/// `chown`'s checks (`chown_ok`, `chgrp_ok`): a new owner only with
/// `CAP_CHOWN` (the owner may name itself), a new group by the owner when
/// it is a member, or with `CAP_CHOWN`; else EPERM. Returns whether a file
/// keeps a set-group-ID bit without group execution
/// (`setattr_should_drop_sgid`): a member of its group, or `CAP_FSETID`.
pub(crate) fn chown(
    creds: &Credentials,
    stat: &FileStat,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool, Errno> {
    let owner = creds.fsuid == stat.uid;
    let chown = capable(creds, CAP_CHOWN);
    if uid.is_some_and(|uid| !(owner && uid == stat.uid) && !chown) {
        return Err(Errno::EPERM);
    }
    if gid.is_some_and(|gid| !(owner && (gid == stat.gid || in_group(creds, gid))) && !chown) {
        return Err(Errno::EPERM);
    }
    Ok(in_group(creds, stat.gid) || capable(creds, CAP_FSETID))
}

/// What a write or a truncation takes from a regular file without
/// `CAP_FSETID` (`setattr_should_drop_suidgid`): its set-user-ID bit, and its
/// set-group-ID bit with group execution or when the thread is not in its
/// group. Linux's `file_remove_privs` and `do_truncate`.
pub(crate) fn remove_set_ids(creds: &Credentials, file: &dyn FileHandle) {
    if capable(creds, CAP_FSETID) {
        return;
    }
    let Ok(stat) = file.stat() else {
        return;
    };
    if stat.mode & TYPE != REGULAR {
        return;
    }
    let mut kill = stat.mode & 0o4000;
    if stat.mode & 0o2000 != 0 && (stat.mode & 0o010 != 0 || !in_group(creds, stat.gid)) {
        kill |= 0o2000;
    }
    if kill != 0 {
        let _ = file.set_mode(stat.mode & 0o7777 & !kill);
    }
}

/// `connect` and `sendto` to the socket file `raw` names, as Linux's
/// `unix_find_bsd`: searching on the way there, and writing the file it finds,
/// whatever it is.
pub(crate) fn connect(files: &Files, creds: &Credentials, raw: &[u8]) -> Result<(), Errno> {
    const AT_FDCWD: u64 = -100i64 as u64;
    match search(files, creds, AT_FDCWD, raw, true)?.file {
        Some(file) => permission(creds, &file, MAY_WRITE),
        None => Ok(()),
    }
}

/// `utimensat`'s check (`may_setattr`, `setattr_prepare`): the owner or
/// `CAP_FOWNER` sets any time; anyone else may only `touch` it to now,
/// with permission to write it (EACCES), and else gets EPERM.
pub(crate) fn times(creds: &Credentials, stat: &FileStat, touch: bool) -> Result<(), Errno> {
    if unchecked(creds) || owner_or_capable(creds, stat) {
        return Ok(());
    }
    if touch {
        return permission(creds, stat, MAY_WRITE);
    }
    Err(Errno::EPERM)
}

/// `truncate`'s checks (`vfs_truncate`), on a file found: a directory is
/// EISDIR, any other file but a regular one EINVAL, and it needs
/// permission to write.
pub(crate) fn truncate(creds: &Credentials, stat: &FileStat) -> Result<(), Errno> {
    match stat.mode & TYPE {
        DIRECTORY => Err(Errno::EISDIR),
        REGULAR => permission(creds, stat, MAY_WRITE),
        _ => Err(Errno::EINVAL),
    }
}

/// exec's checks (`do_open_execat`, `would_dump`) of the program `raw`
/// names from the working directory, at `path`: a file it finds must be a
/// regular file the thread may execute (EACCES). Returns the file, whose
/// set-user-ID and set-group-ID bits exec takes, and whether the thread may
/// also read it; a program it may not read runs undumpable.
pub(crate) fn exec(
    files: &Files,
    creds: &Credentials,
    raw: &[u8],
    path: &[u8],
) -> Result<(Option<FileStat>, bool), Errno> {
    search(files, creds, (-100i32) as u64, raw, true)?;
    let stat = match files.fs.metadata(path, true) {
        Ok(stat) => stat,
        Err(e) if e == Errno::ENOTDIR => return Err(e),
        Err(_) => return Ok((None, true)),
    };
    if stat.mode & TYPE != REGULAR {
        return Err(Errno::EACCES);
    }
    permission(creds, &stat, MAY_EXEC)?;
    let readable = permission(creds, &stat, MAY_READ).is_ok();
    Ok((Some(stat), readable))
}

#[cfg(test)]
mod permissions_tests {
    use super::*;

    fn file(mode: u32, uid: u32, gid: u32) -> FileStat {
        FileStat {
            mode,
            uid,
            gid,
            ..FileStat::default()
        }
    }
    /// User 1000 in group 2000, with 4000 as a supplementary group.
    fn user() -> Credentials {
        let mut user = Credentials::default()
            .setresgid(2000, 2000, 2000)
            .and_then(|c| c.setresuid(1000, 1000, 1000))
            .unwrap();
        user.groups = vec![4000];
        user
    }

    #[test]
    fn the_owner_group_or_other_bits_apply_and_root_overrides_them() {
        let (user, root) = (user(), Credentials::default());
        // The owner's bits alone, even when others may do more.
        assert_eq!(
            permission(&user, &file(0o100047, 1000, 0), MAY_READ),
            Err(Errno::EACCES)
        );
        assert_eq!(
            permission(&user, &file(0o100640, 0, 2000), MAY_READ),
            Ok(())
        );
        assert_eq!(
            permission(&user, &file(0o100640, 0, 4000), MAY_READ),
            Ok(())
        );
        assert_eq!(
            permission(&user, &file(0o100640, 0, 2000), MAY_WRITE),
            Err(Errno::EACCES)
        );
        assert_eq!(permission(&user, &file(0o100604, 0, 0), MAY_READ), Ok(()));
        // Root reads and writes anything, searches any directory, and
        // executes a file only when someone may.
        let secret = file(0o100000, 1000, 1000);
        assert_eq!(permission(&root, &secret, MAY_READ | MAY_WRITE), Ok(()));
        assert_eq!(permission(&root, &secret, MAY_EXEC), Err(Errno::EACCES));
        assert_eq!(
            permission(&root, &file(0o100001, 1000, 1000), MAY_EXEC),
            Ok(())
        );
        assert_eq!(
            permission(&root, &file(0o040000, 1000, 1000), MAY_EXEC),
            Ok(())
        );
        // CAP_DAC_READ_SEARCH alone reads files and searches directories.
        let mut reader = user.clone();
        reader.effective = CAP_DAC_READ_SEARCH;
        assert_eq!(permission(&reader, &secret, MAY_READ), Ok(()));
        assert_eq!(permission(&reader, &secret, MAY_WRITE), Err(Errno::EACCES));
        assert_eq!(
            permission(&reader, &file(0o040000, 0, 0), MAY_EXEC | MAY_READ),
            Ok(())
        );
        assert_eq!(
            permission(&reader, &file(0o040000, 0, 0), MAY_WRITE),
            Err(Errno::EACCES)
        );
        assert!(unchecked(&root) && !unchecked(&user) && !unchecked(&reader));
    }

    #[test]
    fn a_sticky_directory_keeps_others_files() {
        let user = user();
        let sticky = file(0o041777, 0, 0);
        assert_eq!(
            may_delete(&user, &sticky, &file(0o100666, 0, 0)),
            Err(Errno::EPERM)
        );
        assert_eq!(may_delete(&user, &sticky, &file(0o100600, 1000, 0)), Ok(()));
        assert_eq!(
            may_delete(&user, &file(0o041777, 1000, 0), &file(0o100600, 0, 0)),
            Ok(())
        );
        assert_eq!(
            may_delete(&user, &file(0o040755, 0, 0), &file(0o100600, 1000, 0)),
            Err(Errno::EACCES)
        );
        assert_eq!(
            may_delete(&Credentials::default(), &sticky, &file(0o100600, 1, 1)),
            Ok(())
        );
    }

    #[test]
    fn the_owner_changes_modes_groups_and_times() {
        let user = user();
        let mine = file(0o100640, 1000, 3000);
        assert_eq!(
            chmod(&user, &file(0o100644, 0, 0), 0o600),
            Err(Errno::EPERM)
        );
        // Outside the file's group the set-group-ID bit goes.
        assert_eq!(chmod(&user, &mine, 0o2750), Ok(0o750));
        assert_eq!(
            chmod(&user, &file(0o100640, 1000, 2000), 0o2750),
            Ok(0o2750)
        );
        assert_eq!(chown(&user, &mine, Some(0), None), Err(Errno::EPERM));
        assert_eq!(chown(&user, &mine, Some(1000), None), Ok(false));
        assert_eq!(chown(&user, &mine, None, Some(5000)), Err(Errno::EPERM));
        assert_eq!(chown(&user, &mine, None, Some(4000)), Ok(false));
        assert_eq!(chown(&user, &file(0o100640, 0, 2000), None, None), Ok(true));
        assert_eq!(
            chown(&user, &file(0o100640, 0, 2000), None, Some(2000)),
            Err(Errno::EPERM)
        );
        assert_eq!(
            chown(&Credentials::default(), &mine, Some(5), Some(5)),
            Ok(true)
        );
        assert_eq!(times(&user, &mine, false), Ok(()));
        assert_eq!(times(&user, &file(0o100666, 0, 0), true), Ok(()));
        assert_eq!(
            times(&user, &file(0o100666, 0, 0), false),
            Err(Errno::EPERM)
        );
        assert_eq!(
            times(&user, &file(0o100644, 0, 0), true),
            Err(Errno::EACCES)
        );
        assert_eq!(truncate(&user, &file(0o040777, 0, 0)), Err(Errno::EISDIR));
        assert_eq!(truncate(&user, &file(0o010666, 0, 0)), Err(Errno::EINVAL));
        assert_eq!(truncate(&user, &file(0o100644, 0, 0)), Err(Errno::EACCES));
    }

    #[test]
    fn access_takes_the_real_ids() {
        let root = Credentials::default();
        let away = root.setresuid(0, 1000, 0).unwrap();
        let checked = away.for_access();
        assert_eq!((checked.fsuid, checked.effective), (0, away.permitted));
        let back = root.setresuid(1000, 0, 0).unwrap().for_access();
        assert_eq!((back.fsuid, back.effective), (1000, 0));
    }
}
