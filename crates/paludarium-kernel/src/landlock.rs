//! Landlock (`landlock_create_ruleset`, `landlock_add_rule`,
//! `landlock_restrict_self`), as Linux's `security/landlock` restricts a
//! thread's access to file hierarchies and TCP ports and what it may reach
//! outside its domain. This is ABI version 8: the file system access rights
//! of versions 1 to 3 (`LANDLOCK_ACCESS_FS_EXECUTE` to
//! `LANDLOCK_ACCESS_FS_TRUNCATE`, with `REFER`), TCP `bind` and `connect` by
//! port (version 4), `ioctl` on devices (`LANDLOCK_ACCESS_FS_IOCTL_DEV`,
//! version 5), the abstract unix socket and signal scopes (version 6), the
//! logging flags of `landlock_restrict_self` (version 7, accepted; nothing is
//! logged) and `LANDLOCK_RESTRICT_SELF_TSYNC` (version 8), with errata 1 to 4.
//!
//! A domain is a stack of up to 16 layers, one for each enforced ruleset.
//! Each layer handles some access rights and allows them only beneath the
//! files and directories its rules name; an access is allowed when every
//! layer that handles it has a rule granting it on the file or one of its
//! ancestors. Rules name objects by device and inode, as Linux ties them to
//! inodes, so they follow a renamed directory and every link of a file, and
//! ports by number.
//!
//! Each layer also belongs to a hierarchy, Linux's `landlock_hierarchy`: the
//! domains made from it share it, and a scope keeps a thread from what lives
//! outside its own hierarchy at that layer.
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// The ABI version `LANDLOCK_CREATE_RULESET_VERSION` reports.
const ABI: u64 = 8;
const CREATE_RULESET_VERSION: u64 = 1;
const CREATE_RULESET_ERRATA: u64 = 2;
/// The errata `LANDLOCK_CREATE_RULESET_ERRATA` reports, as Linux's
/// `security/landlock/errata`: 1, only TCP sockets meet the TCP rights (no
/// other stream protocol is here); 2, threads of one process may always
/// signal each other; 3, a disconnected directory widens no right (no bind
/// mount moves one here); 4, a whiteout needs `MAKE_REG`.
const ERRATA: u64 = 0b1111;
const RULE_PATH_BENEATH: u64 = 1;
const RULE_NET_PORT: u64 = 2;
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
pub(crate) const IOCTL_DEV: u64 = 1 << 15;
/// Every file system access right of this ABI.
pub(crate) const FS: u64 = (1 << 16) - 1;
/// The rights a rule on a file that is not a directory may grant.
const ACCESS_FILE: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
pub(crate) const BIND_TCP: u64 = 1 << 0;
pub(crate) const CONNECT_TCP: u64 = 1 << 1;
/// Every network access right of this ABI.
const NET: u64 = (1 << 2) - 1;
pub(crate) const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub(crate) const SCOPE_SIGNAL: u64 = 1 << 1;
/// Every scope of this ABI.
const SCOPE: u64 = (1 << 2) - 1;
const RESTRICT_SELF_LOG_SUBDOMAINS_OFF: u32 = 1 << 2;
const RESTRICT_SELF_TSYNC: u32 = 1 << 3;
/// Every `landlock_restrict_self` flag of this ABI.
const RESTRICT_SELF: u32 = (1 << 4) - 1;

/// The next hierarchy a `landlock_restrict_self` makes.
static HIERARCHIES: AtomicU64 = AtomicU64::new(1);

/// A file or directory, as `stat` names it: device and inode.
pub(crate) type Object = (u64, u64);

/// A ruleset being built, behind a `[landlock-ruleset]` descriptor.
pub(crate) struct Ruleset {
    handled: u64,
    handled_net: u64,
    scoped: u64,
    rules: Mutex<BTreeMap<Object, u64>>,
    ports: Mutex<BTreeMap<u16, u64>>,
}

/// An enforced stack of rulesets (Linux's domain).
#[derive(Debug)]
pub(crate) struct Domain {
    /// The file system rights each layer handles, the oldest first, with
    /// `REFER` when it handles any (`landlock_upgrade_handled_access_masks`).
    layers: Vec<u64>,
    /// The network rights each layer handles.
    net: Vec<u64>,
    /// What each layer scopes.
    scopes: Vec<u64>,
    /// The hierarchy of each layer: a domain made from another shares its
    /// layers' hierarchies.
    hierarchies: Vec<u64>,
    /// For each object, the layers with a rule on it and what that rule
    /// allows.
    rules: BTreeMap<Object, Vec<(usize, u64)>>,
    /// For each port, the same.
    ports: BTreeMap<u16, Vec<(usize, u64)>>,
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
    /// The domain, if one handles any of the file system rights `request`.
    fn applicable(&self, request: u64) -> Option<&Domain> {
        self.0
            .as_deref()
            .filter(|d| d.layers.iter().any(|h| h & request != 0))
    }
    /// The domain, if one handles any of the network rights `request`.
    fn applicable_net(&self, request: u64) -> Option<&Domain> {
        self.0
            .as_deref()
            .filter(|d| d.net.iter().any(|h| h & request != 0))
    }
    /// The hierarchies of the domain's layers, the oldest first.
    fn hierarchies(&self) -> &[u64] {
        self.0.as_deref().map_or(&[], |d| &d.hierarchies)
    }
}

/// `domain_is_scoped`: whether `client`, scoping `scope`, may not reach what
/// belongs to `server`. A layer of the client that scopes it keeps the client
/// from anything outside that layer's hierarchy, so the server must share it.
pub(crate) fn scoped(client: &Landlock, server: &Landlock, scope: u64) -> bool {
    let Some(domain) = client.0.as_deref() else {
        return false;
    };
    let theirs = server.hierarchies();
    domain
        .scopes
        .iter()
        .zip(&domain.hierarchies)
        .enumerate()
        .any(|(layer, (scopes, hierarchy))| {
            scopes & scope != 0 && theirs.get(layer) != Some(hierarchy)
        })
}

/// `domain_scope_le`, Landlock's ptrace check: `tracer` may act on `tracee`
/// when the tracer has no domain or the tracee's descends from it.
pub(crate) fn may_trace(tracer: &Landlock, tracee: &Landlock) -> bool {
    let mine = tracer.hierarchies();
    let Some(top) = mine.last() else {
        return true;
    };
    tracee.hierarchies().get(mine.len() - 1) == Some(top)
}

/// For each layer, the requested rights it handles that no rule granted yet
/// (Linux's `layer_access_masks`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Masks(Vec<u64>);

impl Masks {
    /// `landlock_init_layer_masks`: the masks for the file system rights
    /// `request`, and which of it any layer handles. Every layer handles
    /// `REFER` here, even one that handles no other file right
    /// (`landlock_get_fs_access_mask`).
    fn new(domain: &Domain, request: u64) -> (u64, Masks) {
        Self::of(domain.layers.iter().map(|h| h | REFER), request)
    }
    /// The masks for `request`, of layers that handle `handled`.
    fn of(handled: impl Iterator<Item = u64>, request: u64) -> (u64, Masks) {
        let masks: Vec<u64> = handled.map(|h| h & request).collect();
        let handled = masks.iter().fold(0, |a, m| a | m);
        (handled, Masks(masks))
    }
    fn allowed(&self) -> bool {
        self.0.iter().all(|m| *m == 0)
    }
    /// `landlock_unmask_layers`: what a rule on an object grants. Returns
    /// whether every layer is now satisfied.
    fn unmask(&mut self, domain: &Domain, object: Option<Object>) -> bool {
        self.grant(object.and_then(|o| domain.rules.get(&o)))
    }
    /// What `rule`, for each of its layers, grants.
    fn grant(&mut self, rule: Option<&Vec<(usize, u64)>>) -> bool {
        for (layer, allowed) in rule.into_iter().flatten() {
            self.0[*layer] &= !allowed;
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
/// description keeps (`TRUNCATE`, and `IOCTL_DEV` for a device), all of them
/// for a thread without a domain.
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
    let mut full = request | TRUNCATE;
    if is_device(stat) {
        full |= IOCTL_DEV;
    }
    let (_, mut masks) = Masks::new(domain, full);
    walk(&|p| crate::files::identity(c, p), domain, path, &mut masks);
    let allowed = full & !masks.missing();
    if request & !allowed != 0 {
        return Err(Errno(13));
    }
    Ok(allowed)
}

/// `is_device`: a character or block device.
pub(crate) fn is_device(stat: &FileStat) -> bool {
    matches!(stat.mode & 0o170000, 0o020000 | 0o060000)
}

/// `hook_file_ioctl`: `ioctl` command `command` on an open file description
/// whose open kept the rights `allowed`, with `stat` its status. A device
/// needs `IOCTL_DEV` unless the command is one `do_vfs_ioctl` answers for
/// every file (`is_masked_device_ioctl`); as Linux's, this holds whoever
/// calls, with or without a domain.
pub(crate) fn ioctl(allowed: u64, stat: &FileStat, command: u32) -> Result<(), Errno> {
    const MASKED: [u32; 14] = [
        0x5451,      // FIOCLEX
        0x5450,      // FIONCLEX
        0x5421,      // FIONBIO
        0x5452,      // FIOASYNC
        0x5460,      // FIOQSIZE
        0xc004_5877, // FIFREEZE
        0xc004_5878, // FITHAW
        0xc020_660b, // FS_IOC_FIEMAP
        0x2,         // FIGETBSZ
        0x4004_9409, // FICLONE
        0x4020_940d, // FICLONERANGE
        0xc018_9436, // FIDEDUPERANGE
        0x8011_1500, // FS_IOC_GETFSUUID
        0x8081_1501, // FS_IOC_GETFSSYSFSPATH
    ];
    if allowed & IOCTL_DEV != 0 || !is_device(stat) || MASKED.contains(&command) {
        Ok(())
    } else {
        Err(Errno(13))
    }
}

/// `current_check_access_socket`: `bind` (`BIND_TCP`) or `connect`
/// (`CONNECT_TCP`) of a TCP socket of `v6` or IPv4 to the address `raw`,
/// before the protocol looks at it. Only the port matters; a family other
/// than IPv4, IPv6 and `AF_UNSPEC` is the protocol's to refuse.
pub(crate) fn socket(c: &Context<'_>, v6: bool, raw: &[u8], request: u64) -> Result<(), Errno> {
    const AF_UNSPEC: u16 = 0;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    // sizeof(struct sockaddr_in) and SIN6_LEN_RFC2133.
    const V4_LEN: usize = 16;
    const V6_LEN: usize = 24;
    let Some(domain) = c.process.credentials.landlock.applicable_net(request) else {
        return Ok(());
    };
    if raw.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    let length = match family {
        // Dissolving a connection is always allowed.
        AF_UNSPEC if request == CONNECT_TCP => return Ok(()),
        // IPv4 binds the unspecified address of AF_UNSPEC as AF_INET; IPv6
        // never does.
        AF_UNSPEC if v6 => {
            return Err(if raw.len() < V6_LEN {
                Errno::EINVAL
            } else {
                Errno(97) // EAFNOSUPPORT
            });
        }
        AF_UNSPEC => {
            if raw.len() >= V4_LEN && raw[4..8] != [0; 4] {
                return Err(Errno(97));
            }
            V4_LEN
        }
        AF_INET => V4_LEN,
        AF_INET6 => V6_LEN,
        _ => return Ok(()),
    };
    if raw.len() < length {
        return Err(Errno::EINVAL);
    }
    if family != AF_UNSPEC && family != if v6 { AF_INET6 } else { AF_INET } {
        return Err(Errno::EINVAL);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let (handled, mut masks) = Masks::of(domain.net.iter().copied(), request);
    if handled == 0 || masks.grant(domain.ports.get(&port)) {
        Ok(())
    } else {
        Err(Errno(13))
    }
}

/// `get_mode_access`: the right to make a file of `mode` and device `rdev`.
/// A whiteout, a character device numbered 0, is guarded as a regular file
/// (erratum 4).
pub(crate) fn make_access(mode: u32, rdev: u64) -> u64 {
    match mode & 0o170000 {
        0o120000 => MAKE_SYM,
        0o040000 => MAKE_DIR,
        0o020000 if rdev == 0 => MAKE_REG,
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
/// file at the resolved path `old` to `new`, with the `renameat2` flags
/// `flags`: an exchange, or a whiteout left where the file was, which needs
/// `MAKE_REG` there. A move to another directory needs `REFER` on both and
/// must not give the file more rights than it had: `EXDEV` when only that
/// fails, as Linux's lets the caller copy instead, and `EACCES` for a missing
/// right to make or remove.
pub(crate) fn refer(
    c: &Context<'_>,
    old: &[u8],
    new: &[u8],
    removable: bool,
    flags: u32,
) -> Result<(), Errno> {
    if c.process.credentials.landlock.applicable(FS).is_none() {
        return Ok(());
    }
    let stat = |p: &[u8]| c.files.fs.metadata(p, false).ok();
    let Some(old_stat) = stat(old) else {
        return Err(Errno::ENOENT);
    };
    let new_stat = stat(new);
    refer_stated(
        c,
        (old, new),
        (&old_stat, new_stat.as_ref()),
        removable,
        flags,
    )
}

/// [`refer`] of the files `old` and `new` whose status the caller found:
/// the new one's is none when it is not there.
pub(crate) fn refer_stated(
    c: &Context<'_>,
    (old, new): (&[u8], &[u8]),
    (old_stat, new_stat): (&FileStat, Option<&FileStat>),
    removable: bool,
    flags: u32,
) -> Result<(), Errno> {
    const RENAME_EXCHANGE: u32 = 2;
    const RENAME_WHITEOUT: u32 = 4;
    let exchange = flags & RENAME_EXCHANGE != 0;
    let Some(domain) = c.process.credentials.landlock.applicable(FS) else {
        return Ok(());
    };
    let mut request1 = 0;
    if exchange {
        let Some(new_stat) = &new_stat else {
            return Err(Errno::ENOENT);
        };
        request1 = make_access(new_stat.mode, new_stat.rdev);
    }
    let mut request2 = make_access(old_stat.mode, old_stat.rdev);
    if removable {
        request1 |= remove_access(Some(old_stat));
        request2 |= remove_access(new_stat);
    }
    if flags & RENAME_WHITEOUT != 0 {
        request1 |= make_access(0o020000, 0);
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
    let (dir1, dir2) = (is_dir(Some(old_stat)), is_dir(new_stat));
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
        return match flags {
            CREATE_RULESET_VERSION => Ok(ABI),
            CREATE_RULESET_ERRATA => Ok(ERRATA),
            _ => Err(Errno::EINVAL),
        };
    }
    // copy_min_struct_from_user: at least handled_access_fs, then
    // handled_access_net and scoped, the fields of this ABI; any other byte
    // the caller gives must be zero.
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
    if bytes
        .get(24..)
        .is_some_and(|rest| rest.iter().any(|b| *b != 0))
    {
        return Err(Errno(7));
    }
    bytes.resize(24, 0);
    let field = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
    let (handled, handled_net, scoped) = (field(0), field(8), field(16));
    if handled & !FS != 0 || handled_net & !NET != 0 || scoped & !SCOPE != 0 {
        return Err(Errno::EINVAL);
    }
    if handled == 0 && handled_net == 0 && scoped == 0 {
        return Err(Errno(42)); // ENOMSG
    }
    let ruleset = Arc::new(Ruleset {
        handled,
        handled_net,
        scoped,
        rules: Mutex::default(),
        ports: Mutex::default(),
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
    match a[1] as u32 as u64 {
        RULE_PATH_BENEATH => {}
        RULE_NET_PORT => return add_port(c, ruleset, a[2]),
        _ => return Err(Errno::EINVAL),
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

/// `add_rule_net_port`: a `landlock_net_port_attr` at `at`, the rights
/// `allowed` on TCP port `port`.
fn add_port(c: &Context<'_>, ruleset: &Ruleset, at: u64) -> Result<u64, Errno> {
    let mut attr = [0u8; 16];
    c.mem
        .read(GuestAddr(at), &mut attr)
        .map_err(|_| Errno::EFAULT)?;
    let allowed = u64::from_le_bytes(attr[..8].try_into().unwrap_or([0; 8]));
    let port = u64::from_le_bytes(attr[8..].try_into().unwrap_or([0; 8]));
    if allowed == 0 {
        return Err(Errno(42)); // ENOMSG
    }
    if allowed & !ruleset.handled_net != 0 {
        return Err(Errno::EINVAL);
    }
    let Ok(port) = u16::try_from(port) else {
        return Err(Errno::EINVAL);
    };
    // landlock_append_net_rule: what the ruleset does not handle is allowed.
    *ruleset
        .ports
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(port)
        .or_insert(0) |= allowed | NET & !ruleset.handled_net;
    Ok(0)
}

/// `landlock_restrict_self(ruleset_fd, flags)`: the thread's domain with the
/// ruleset as a new layer on top, in a hierarchy of its own, and with
/// `LANDLOCK_RESTRICT_SELF_TSYNC` every other thread's too. The logging
/// flags are taken and change nothing, as nothing is logged. With
/// `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF`, and optionally
/// `LANDLOCK_RESTRICT_SELF_TSYNC`, a descriptor of -1 makes no new domain;
/// TSYNC then gives the other threads the caller's own, as Linux's does
/// (the check in its `syscalls.c` after 7.0, which the runner's kernel has).
pub(crate) fn sys_restrict_self(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    let no_new_privs = c.processes.status_of(c.process.pid).2;
    if !no_new_privs && c.process.credentials.effective & CAP_SYS_ADMIN == 0 {
        return Err(Errno::EPERM);
    }
    let flags = a[1] as u32;
    if flags & !RESTRICT_SELF != 0 {
        return Err(Errno::EINVAL);
    }
    if a[0] as i32 == -1 && flags & !RESTRICT_SELF_TSYNC == RESTRICT_SELF_LOG_SUBDOMAINS_OFF {
        if flags & RESTRICT_SELF_TSYNC != 0 {
            let domain = c.process.credentials.landlock.clone();
            c.process.credentials.landlock_sync = c.group.sync_landlock(&domain);
        }
        return Ok(0);
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
    let mut net = old.map_or_else(Vec::new, |d| d.net.clone());
    let mut scopes = old.map_or_else(Vec::new, |d| d.scopes.clone());
    let mut hierarchies = old.map_or_else(Vec::new, |d| d.hierarchies.clone());
    let mut rules = old.map_or_else(BTreeMap::new, |d| d.rules.clone());
    let mut ports = old.map_or_else(BTreeMap::new, |d| d.ports.clone());
    let layer = layers.len();
    // A layer that handles any file right also denies REFER
    // (`_LANDLOCK_ACCESS_FS_INITIALLY_DENIED`).
    layers.push(if ruleset.handled == 0 {
        0
    } else {
        ruleset.handled | REFER
    });
    net.push(ruleset.handled_net);
    scopes.push(ruleset.scoped);
    hierarchies.push(HIERARCHIES.fetch_add(1, Ordering::Relaxed));
    for (port, allowed) in ruleset
        .ports
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        ports.entry(*port).or_default().push((layer, *allowed));
    }
    for (object, allowed) in ruleset
        .rules
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        rules.entry(*object).or_default().push((layer, *allowed));
    }
    let domain = Landlock(Some(Arc::new(Domain {
        layers,
        net,
        scopes,
        hierarchies,
        rules,
        ports,
    })));
    if flags & RESTRICT_SELF_TSYNC != 0 {
        // Every other thread takes the same domain when it next enters the
        // kernel, as Linux's task works do before they return to it; what
        // others see of them changes now.
        c.process.credentials.landlock_sync = c.group.sync_landlock(&domain);
    }
    c.process.credentials.landlock = domain;
    c.group
        .set_task_ids(c.tid, c.process.credentials.task_ids());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(layers: &[(u64, &[(Object, u64)])]) -> Domain {
        let mut d = Domain {
            layers: Vec::new(),
            net: Vec::new(),
            scopes: Vec::new(),
            hierarchies: Vec::new(),
            rules: BTreeMap::new(),
            ports: BTreeMap::new(),
        };
        for (i, (handled, rules)) in layers.iter().enumerate() {
            d.layers.push(handled | REFER);
            d.net.push(0);
            d.scopes.push(0);
            d.hierarchies.push(i as u64);
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

    /// A domain whose layers scope `scopes` and belong to `hierarchies`.
    fn scoping(scopes: &[u64], hierarchies: &[u64]) -> Landlock {
        Landlock(Some(Arc::new(Domain {
            layers: vec![0; scopes.len()],
            net: vec![0; scopes.len()],
            scopes: scopes.to_vec(),
            hierarchies: hierarchies.to_vec(),
            rules: BTreeMap::new(),
            ports: BTreeMap::new(),
        })))
    }

    #[test]
    fn a_scope_keeps_a_thread_inside_its_hierarchy() {
        let none = Landlock::default();
        let parent = scoping(&[SCOPE_SIGNAL], &[1]);
        let child = scoping(&[SCOPE_SIGNAL, 0], &[1, 2]);
        let sibling = scoping(&[SCOPE_SIGNAL], &[3]);
        // No domain scopes nothing; a domain scoping signals reaches its own
        // hierarchy and what descends from it, not what is outside.
        assert!(!scoped(&none, &parent, SCOPE_SIGNAL));
        assert!(scoped(&parent, &none, SCOPE_SIGNAL));
        assert!(!scoped(&parent, &child, SCOPE_SIGNAL));
        assert!(scoped(&parent, &sibling, SCOPE_SIGNAL));
        // Another scope is not asked for.
        assert!(!scoped(&parent, &none, SCOPE_ABSTRACT_UNIX_SOCKET));
        // The child's own layer scopes nothing, so its parent is reachable;
        // a layer that does scope keeps it from the parent.
        assert!(!scoped(&child, &parent, SCOPE_SIGNAL));
        let strict = scoping(&[0, SCOPE_SIGNAL], &[1, 4]);
        assert!(scoped(&strict, &parent, SCOPE_SIGNAL));
        // ptrace: a tracer reaches only what descends from its domain.
        assert!(may_trace(&none, &parent));
        assert!(may_trace(&parent, &child));
        assert!(!may_trace(&child, &parent));
        assert!(!may_trace(&parent, &none));
        assert!(!may_trace(&parent, &sibling));
    }

    #[test]
    fn make_access_follows_the_file_type() {
        assert_eq!(make_access(0o100644, 0), MAKE_REG);
        assert_eq!(make_access(0, 0), MAKE_REG);
        assert_eq!(make_access(0o040755, 0), MAKE_DIR);
        assert_eq!(make_access(0o120777, 0), MAKE_SYM);
        assert_eq!(make_access(0o010644, 0), MAKE_FIFO);
        assert_eq!(make_access(0o140755, 0), MAKE_SOCK);
        // A whiteout is guarded as a regular file (erratum 4).
        assert_eq!(make_access(0o020000, 0), MAKE_REG);
        assert_eq!(make_access(0o020644, 0x0103), MAKE_CHAR);
        assert_eq!(make_access(0o060644, 0x0801), MAKE_BLOCK);
    }
}
