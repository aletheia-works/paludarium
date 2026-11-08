//! Landlock (`landlock_create_ruleset`, `landlock_add_rule`,
//! `landlock_restrict_self`), as Linux's `security/landlock` restricts a
//! thread's access to file hierarchies. This is ABI version 3: the file
//! system access rights of versions 1 to 3 (`LANDLOCK_ACCESS_FS_EXECUTE` to
//! `LANDLOCK_ACCESS_FS_TRUNCATE`, with `REFER`); network rules, device
//! ioctls and scopes come with later versions, which this does not report.
//!
//! A domain is a stack of up to 16 layers, one for each enforced ruleset.
//! Each layer handles some access rights and allows them only beneath the
//! files and directories its rules name; an access is allowed when every
//! layer that handles it has a rule granting it on the file or one of its
//! ancestors. Rules name objects by device and inode, as Linux ties them to
//! inodes, so they follow a renamed directory and every link of a file.
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The ABI version `LANDLOCK_CREATE_RULESET_VERSION` reports.
const ABI: u64 = 3;
const CREATE_RULESET_VERSION: u64 = 1;
const RULE_PATH_BENEATH: u64 = 1;
/// Linux's `LANDLOCK_MAX_NUM_LAYERS`.
const MAX_LAYERS: usize = 16;

pub(crate) const EXECUTE: u64 = 1 << 0;
pub(crate) const WRITE_FILE: u64 = 1 << 1;
pub(crate) const READ_FILE: u64 = 1 << 2;
pub(crate) const READ_DIR: u64 = 1 << 3;
pub(crate) const REMOVE_DIR: u64 = 1 << 4;
pub(crate) const REMOVE_FILE: u64 = 1 << 5;
pub(crate) const MAKE_CHAR: u64 = 1 << 6;
pub(crate) const MAKE_DIR: u64 = 1 << 7;
pub(crate) const MAKE_REG: u64 = 1 << 8;
pub(crate) const MAKE_SOCK: u64 = 1 << 9;
pub(crate) const MAKE_FIFO: u64 = 1 << 10;
pub(crate) const MAKE_BLOCK: u64 = 1 << 11;
pub(crate) const MAKE_SYM: u64 = 1 << 12;
pub(crate) const REFER: u64 = 1 << 13;
pub(crate) const TRUNCATE: u64 = 1 << 14;
/// Every file system access right of this ABI.
pub(crate) const FS: u64 = (1 << 15) - 1;
/// The rights a rule on a file that is not a directory may grant.
const ACCESS_FILE: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE;

/// A file or directory, as `stat` names it: device and inode.
pub(crate) type Object = (u64, u64);

/// A ruleset being built, behind a `[landlock-ruleset]` descriptor.
pub(crate) struct Ruleset {
    handled: u64,
    rules: Mutex<BTreeMap<Object, u64>>,
}

/// An enforced stack of rulesets (Linux's domain).
#[derive(Debug)]
pub(crate) struct Domain {
    /// What each layer handles, the oldest first.
    layers: Vec<u64>,
    /// For each object, the layers with a rule on it and what that rule
    /// allows.
    rules: BTreeMap<Object, Vec<(usize, u64)>>,
}

/// A thread's domain, kept with its credentials: threads, processes and
/// `execve` keep it, and it can only grow.
#[derive(Clone, Debug, Default)]
pub struct Landlock(Option<Arc<Domain>>);

impl PartialEq for Landlock {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}
impl Eq for Landlock {}

impl Landlock {
    /// The domain, if one handles any of `request`.
    fn applicable(&self, request: u64) -> Option<&Domain> {
        self.0
            .as_deref()
            .filter(|d| d.layers.iter().any(|h| h & request != 0))
    }
}

/// For each layer, the requested rights it handles that no rule granted yet
/// (Linux's `layer_access_masks`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Masks(Vec<u64>);

impl Masks {
    /// `landlock_init_layer_masks`: the masks for `request`, and which of it
    /// any layer handles.
    fn new(domain: &Domain, request: u64) -> (u64, Masks) {
        let masks: Vec<u64> = domain.layers.iter().map(|h| h & request).collect();
        let handled = masks.iter().fold(0, |a, m| a | m);
        (handled, Masks(masks))
    }
    fn allowed(&self) -> bool {
        self.0.iter().all(|m| *m == 0)
    }
    /// `landlock_unmask_layers`: what a rule on an object grants. Returns
    /// whether every layer is now satisfied.
    fn unmask(&mut self, domain: &Domain, object: Option<Object>) -> bool {
        if let Some(rule) = object.and_then(|o| domain.rules.get(&o)) {
            for (layer, allowed) in rule {
                self.0[*layer] &= !allowed;
            }
        }
        self.allowed()
    }
    /// `scope_to_request`: keeps only `request`, and returns whether all of
    /// it is granted.
    fn scope(&mut self, request: u64) -> bool {
        for m in &mut self.0 {
            *m &= request;
        }
        self.allowed()
    }
    /// The rights some layer still lacks.
    fn missing(&self) -> u64 {
        self.0.iter().fold(0, |a, m| a | m)
    }
}

/// `may_refer`: a child under `src_parent` would not gain rights under
/// `new_parent`. The masks hold what is not granted, so what is denied to
/// the child where it is must stay denied where it goes.
fn may_refer(
    src_parent: &Masks,
    src_child: &Masks,
    new_parent: &Masks,
    child_is_dir: bool,
) -> bool {
    src_parent
        .0
        .iter()
        .zip(&src_child.0)
        .zip(&new_parent.0)
        .all(|((parent, child), new)| {
            let (mut child, mut new) = (parent & child, *new);
            if !child_is_dir {
                child &= ACCESS_FILE;
                new &= ACCESS_FILE;
            }
            child & !new == 0
        })
}

/// The parent directory of an absolute, normalised path; `/` is its own.
pub(crate) fn parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/",
        Some(i) => &path[..i],
    }
}

/// The mount that holds `path`: the longest mount point that is `path` or
/// one of its ancestors.
fn mount_root(c: &Context<'_>, path: &[u8]) -> Vec<u8> {
    c.files
        .fs
        .mounts()
        .into_iter()
        .map(|m| m.path)
        .filter(|root| {
            root == b"/"
                || path == &root[..]
                || path.starts_with(root) && path.get(root.len()) == Some(&b'/')
        })
        .max_by_key(Vec::len)
        .unwrap_or_else(|| b"/".to_vec())
}

/// How a check names the object at a resolved path.
type Identity<'a> = &'a dyn Fn(&[u8]) -> Option<Object>;

/// Walks from `path` up to `/`, granting what each object's rule allows
/// (`is_access_to_paths_allowed` for one path). Returns whether every layer
/// was satisfied.
fn walk(identity: Identity<'_>, domain: &Domain, path: &[u8], masks: &mut Masks) -> bool {
    if masks.allowed() {
        return true;
    }
    let mut here = path.to_vec();
    loop {
        if masks.unmask(domain, identity(&here)) {
            return true;
        }
        if here == b"/" {
            return false;
        }
        here = parent(&here).to_vec();
    }
}

/// `current_check_access_path`: `request` on the file or directory at the
/// resolved path `path`, `EACCES` when a layer does not allow it.
pub(crate) fn check(c: &Context<'_>, path: &[u8], request: u64) -> Result<(), Errno> {
    check_with(
        &c.process.credentials.landlock,
        &|p| crate::files::identity(c, p),
        path,
        request,
    )
}

/// [`check`] for a caller with no context, naming objects with `identity`.
pub(crate) fn check_with(
    landlock: &Landlock,
    identity: Identity<'_>,
    path: &[u8],
    request: u64,
) -> Result<(), Errno> {
    let Some(domain) = landlock.applicable(request) else {
        return Ok(());
    };
    let (_, mut masks) = Masks::new(domain, request);
    if walk(identity, domain, path, &mut masks) {
        Ok(())
    } else {
        Err(Errno(13))
    }
}

/// `hook_file_open`: the rights an open needs (`READ_DIR` for a directory,
/// else `READ_FILE`, `WRITE_FILE` and `EXECUTE` as its mode asks) on the
/// file at `path`, with `stat` its status. Returns the rights the open file
/// description keeps (`TRUNCATE`), all of them for a thread without a domain.
pub(crate) fn open(
    c: &Context<'_>,
    path: &[u8],
    stat: &FileStat,
    read: bool,
    write: bool,
    exec: bool,
) -> Result<u64, Errno> {
    let Some(domain) = c.process.credentials.landlock.applicable(FS) else {
        return Ok(FS);
    };
    let mut request = 0;
    if read {
        request = if stat.mode & 0o170000 == 0o040000 {
            READ_DIR
        } else {
            READ_FILE
        };
    }
    if write {
        request |= WRITE_FILE;
    }
    if exec {
        request |= EXECUTE;
    }
    let full = request | TRUNCATE;
    let (_, mut masks) = Masks::new(domain, full);
    walk(&|p| crate::files::identity(c, p), domain, path, &mut masks);
    let allowed = full & !masks.missing();
    if request & !allowed != 0 {
        return Err(Errno(13));
    }
    Ok(allowed)
}

/// `get_mode_access`: the right to make a file of `mode`.
pub(crate) fn make_access(mode: u32) -> u64 {
    match mode & 0o170000 {
        0o120000 => MAKE_SYM,
        0o040000 => MAKE_DIR,
        0o020000 => MAKE_CHAR,
        0o060000 => MAKE_BLOCK,
        0o010000 => MAKE_FIFO,
        0o140000 => MAKE_SOCK,
        _ => MAKE_REG,
    }
}

/// `maybe_remove`: the right to remove the file of `stat`, if there is one.
fn remove_access(stat: Option<&FileStat>) -> u64 {
    match stat {
        None => 0,
        Some(s) if s.mode & 0o170000 == 0o040000 => REMOVE_DIR,
        Some(_) => REMOVE_FILE,
    }
}

/// The rights a rule directly on `object` gives, for each layer (the
/// masks of `REFER`'s children).
fn child_masks(domain: &Domain, object: Option<Object>) -> Masks {
    let (_, mut masks) = Masks::new(domain, FS);
    masks.unmask(domain, object);
    masks
}

/// `collect_domain_accesses`: every right of every layer, granted by the
/// rules from `dir` up to the mount root `root`. Returns whether every
/// layer got all of them.
fn collect(
    identity: Identity<'_>,
    domain: &Domain,
    root: &[u8],
    dir: &[u8],
    masks: &mut Masks,
) -> bool {
    let (handled, all) = Masks::new(domain, FS);
    *masks = all;
    if handled == 0 {
        return true;
    }
    let mut here = dir.to_vec();
    loop {
        if masks.unmask(domain, identity(&here)) {
            return true;
        }
        if here == root || here == b"/" {
            return false;
        }
        here = parent(&here).to_vec();
    }
}

/// `current_check_refer_path`: a link (`removable` false) or rename of the
/// file at the resolved path `old` to `new`, or their exchange. A move to
/// another directory needs `REFER` on both and must not give the file more
/// rights than it had: `EXDEV` when only that fails, as Linux's lets the
/// caller copy instead, and `EACCES` for a missing right to make or remove.
pub(crate) fn refer(
    c: &Context<'_>,
    old: &[u8],
    new: &[u8],
    removable: bool,
    exchange: bool,
) -> Result<(), Errno> {
    let Some(domain) = c.process.credentials.landlock.applicable(FS) else {
        return Ok(());
    };
    let stat = |p: &[u8]| c.files.fs.metadata(p, false).ok();
    let Some(old_stat) = stat(old) else {
        return Err(Errno::ENOENT);
    };
    let new_stat = stat(new);
    let mut request1 = 0;
    if exchange {
        let Some(new_stat) = &new_stat else {
            return Err(Errno::ENOENT);
        };
        request1 = make_access(new_stat.mode);
    }
    let mut request2 = make_access(old_stat.mode);
    if removable {
        request1 |= remove_access(Some(&old_stat));
        request2 |= remove_access(new_stat.as_ref());
    }
    let identity = |p: &[u8]| crate::files::identity(c, p);
    let (old_dir, new_dir) = (parent(old), parent(new));
    if old_dir == new_dir {
        let (_, mut masks) = Masks::new(domain, request1 | request2);
        return if walk(&identity, domain, new_dir, &mut masks) {
            Ok(())
        } else {
            Err(Errno(13))
        };
    }
    request1 |= REFER;
    request2 |= REFER;
    let root = mount_root(c, new_dir);
    let (mut masks1, mut masks2) = (Masks(Vec::new()), Masks(Vec::new()));
    let mut allowed1 = collect(&identity, domain, &root, old_dir, &mut masks1);
    let mut allowed2 = collect(&identity, domain, &root, new_dir, &mut masks2);
    if allowed1 && allowed2 {
        return Ok(());
    }
    let child1 = child_masks(domain, identity(old));
    let child2 = exchange.then(|| child_masks(domain, identity(new)));
    let is_dir = |s: Option<&FileStat>| s.is_some_and(|s| s.mode & 0o170000 == 0o040000);
    let (dir1, dir2) = (is_dir(Some(&old_stat)), is_dir(new_stat.as_ref()));
    let mut checking_domain = true;
    let mut here = root;
    loop {
        if checking_domain
            && may_refer(&masks1, &child1, &masks2, dir1)
            && child2
                .as_ref()
                .is_none_or(|child2| may_refer(&masks2, child2, &masks1, dir2))
        {
            checking_domain = false;
            allowed1 = allowed1 || masks1.scope(request1);
            allowed2 = allowed2 || masks2.scope(request2);
            if allowed1 && allowed2 {
                break;
            }
        }
        let object = identity(&here);
        allowed1 = allowed1 || masks1.unmask(domain, object);
        allowed2 = allowed2 || masks2.unmask(domain, object);
        if allowed1 && allowed2 || here == b"/" {
            break;
        }
        here = parent(&here).to_vec();
    }
    if allowed1 && allowed2 {
        return Ok(());
    }
    let denied = |m: &Masks, request: u64| m.0.iter().any(|l| l & request & !REFER != 0);
    if denied(&masks1, request1) || denied(&masks2, request2) {
        Err(Errno(13))
    } else {
        Err(Errno(18))
    }
}

impl FileHandle for Ruleset {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        2
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// The ruleset behind descriptor `fd`: `EBADF` for none, `EBADFD` for
/// another kind of file.
fn ruleset(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(u64::from(fd as u32))?.file;
    if file.as_any().is_some_and(|f| f.is::<Ruleset>()) {
        Ok(file)
    } else {
        Err(Errno(77))
    }
}

/// `landlock_create_ruleset(attr, size, flags)`.
pub(crate) fn sys_create_ruleset(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (attr, size, flags) = (a[0], a[1], a[2] as u32 as u64);
    if flags != 0 {
        if attr != 0 || size != 0 {
            return Err(Errno::EINVAL);
        }
        return if flags == CREATE_RULESET_VERSION {
            Ok(ABI)
        } else {
            Err(Errno::EINVAL)
        };
    }
    // copy_min_struct_from_user: handled_access_fs, the only field of this
    // ABI; any other byte the caller gives must be zero.
    if attr == 0 {
        return Err(Errno::EFAULT);
    }
    if size < 8 {
        return Err(Errno::EINVAL);
    }
    if size > 4096 {
        return Err(Errno(7)); // E2BIG
    }
    let mut bytes = vec![0u8; size as usize];
    c.mem
        .read(GuestAddr(attr), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    if bytes[8..].iter().any(|b| *b != 0) {
        return Err(Errno(7));
    }
    let handled = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
    if handled & !FS != 0 {
        return Err(Errno::EINVAL);
    }
    if handled == 0 {
        return Err(Errno(42)); // ENOMSG
    }
    let ruleset = Arc::new(Ruleset {
        handled,
        rules: Mutex::default(),
    });
    c.files
        .install(ruleset, true, c.group.nofile())
        .map(u64::from)
}

/// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`.
pub(crate) fn sys_add_rule(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    if a[3] as u32 != 0 {
        return Err(Errno::EINVAL);
    }
    let file = ruleset(c, a[0])?;
    let Some(ruleset) = file.as_any().and_then(|f| f.downcast_ref::<Ruleset>()) else {
        return Err(Errno(77));
    };
    if a[1] as u32 as u64 != RULE_PATH_BENEATH {
        return Err(Errno::EINVAL);
    }
    let mut attr = [0u8; 12];
    c.mem
        .read(GuestAddr(a[2]), &mut attr)
        .map_err(|_| Errno::EFAULT)?;
    let allowed = u64::from_le_bytes(attr[..8].try_into().unwrap_or([0; 8]));
    let parent_fd = i32::from_le_bytes(attr[8..].try_into().unwrap_or([0; 4]));
    if allowed == 0 {
        return Err(Errno(42)); // ENOMSG
    }
    if allowed & !ruleset.handled != 0 {
        return Err(Errno::EINVAL);
    }
    let (object, directory) = crate::files::rule_object(c, parent_fd)?;
    if !directory && allowed & !ACCESS_FILE != 0 {
        return Err(Errno::EINVAL);
    }
    // landlock_append_fs_rule: what the ruleset does not handle is allowed,
    // except REFER, which every layer denies unless a rule grants it.
    let allowed = allowed | FS & !(ruleset.handled | REFER);
    *ruleset
        .rules
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(object)
        .or_insert(0) |= allowed;
    Ok(0)
}

/// `landlock_restrict_self(ruleset_fd, flags)`: the thread's domain with the
/// ruleset as a new layer on top.
pub(crate) fn sys_restrict_self(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    let no_new_privs = c.processes.status_of(c.process.pid).2;
    if !no_new_privs && c.process.credentials.effective & CAP_SYS_ADMIN == 0 {
        return Err(Errno::EPERM);
    }
    if a[1] as u32 != 0 {
        return Err(Errno::EINVAL);
    }
    let file = ruleset(c, a[0])?;
    let Some(ruleset) = file.as_any().and_then(|f| f.downcast_ref::<Ruleset>()) else {
        return Err(Errno(77));
    };
    let old = c.process.credentials.landlock.0.as_deref();
    let mut layers = old.map_or_else(Vec::new, |d| d.layers.clone());
    if layers.len() >= MAX_LAYERS {
        return Err(Errno(7)); // E2BIG
    }
    let mut rules = old.map_or_else(BTreeMap::new, |d| d.rules.clone());
    let layer = layers.len();
    // A layer that handles any file right also denies REFER
    // (`_LANDLOCK_ACCESS_FS_INITIALLY_DENIED`).
    layers.push(ruleset.handled | REFER);
    for (object, allowed) in ruleset
        .rules
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        rules.entry(*object).or_default().push((layer, *allowed));
    }
    c.process.credentials.landlock = Landlock(Some(Arc::new(Domain { layers, rules })));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(layers: &[(u64, &[(Object, u64)])]) -> Domain {
        let mut d = Domain {
            layers: Vec::new(),
            rules: BTreeMap::new(),
        };
        for (i, (handled, rules)) in layers.iter().enumerate() {
            d.layers.push(handled | REFER);
            for (object, allowed) in *rules {
                d.rules
                    .entry(*object)
                    .or_default()
                    .push((i, allowed | FS & !(handled | REFER)));
            }
        }
        d
    }

    #[test]
    fn every_layer_that_handles_a_right_must_grant_it() {
        let d = domain(&[
            (READ_FILE | WRITE_FILE, &[((1, 2), READ_FILE)]),
            (READ_FILE, &[((1, 3), READ_FILE)]),
        ]);
        let (handled, mut m) = Masks::new(&d, READ_FILE | EXECUTE);
        assert_eq!(handled, READ_FILE);
        assert!(!m.unmask(&d, Some((1, 2))));
        assert!(m.unmask(&d, Some((1, 3))));
        let (_, mut w) = Masks::new(&d, WRITE_FILE);
        assert!(!w.unmask(&d, Some((1, 2))) && w.missing() == WRITE_FILE);
    }

    #[test]
    fn a_move_may_not_gain_rights() {
        // The masks of a parent where `granted` is allowed, of a child with
        // no rule, and of one with a rule granting `granted`.
        let parent = |granted: u64| Masks(vec![FS & !granted]);
        let child = parent;
        // Readable where it is, moved where it would also be writable.
        assert!(!may_refer(
            &parent(READ_FILE),
            &child(0),
            &parent(READ_FILE | WRITE_FILE),
            false
        ));
        // Moved where it loses execution: allowed.
        assert!(may_refer(
            &parent(READ_FILE | EXECUTE),
            &child(0),
            &parent(READ_FILE),
            false
        ));
        // Its own rule goes with it.
        assert!(may_refer(
            &parent(READ_FILE),
            &child(EXECUTE),
            &parent(READ_FILE | EXECUTE),
            false
        ));
        // A right only directories have does not count for a file.
        assert!(may_refer(&parent(0), &child(0), &parent(MAKE_DIR), false));
        assert!(!may_refer(&parent(0), &child(0), &parent(MAKE_DIR), true));
    }

    #[test]
    fn make_access_follows_the_file_type() {
        assert_eq!(make_access(0o100644), MAKE_REG);
        assert_eq!(make_access(0), MAKE_REG);
        assert_eq!(make_access(0o040755), MAKE_DIR);
        assert_eq!(make_access(0o120777), MAKE_SYM);
        assert_eq!(make_access(0o010644), MAKE_FIFO);
        assert_eq!(make_access(0o140755), MAKE_SOCK);
    }
}
