//! `statmount` and `listmount` (Linux master's `fs/namespace.c`): what a
//! mount is and which mounts a namespace has, by the mounts' unique IDs.
use std::sync::Arc;

use paludarium_host::HostFs;
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, MountPoint, MountTable, NamespacedFs, Reach, mount_flags as mnt};

use super::{CAP_SYS_ADMIN, MS_PRIVATE, MS_SHARED, MS_SLAVE, MS_UNBINDABLE, PAGE, outcome};
use crate::namespaces::Namespace;
use crate::syscalls::{Context, Outcome};

const E2BIG: Errno = Errno(7);
const EOVERFLOW: Errno = Errno(75);

/// `MNT_ID_REQ_SIZE_VER0` and `_VER1`: `struct mnt_id_req` without and with
/// `mnt_ns_id`.
const REQ_SIZE_VER0: u64 = 24;
const REQ_SIZE_VER1: u64 = 32;
/// `LSMT_ROOT`: `listmount` from the caller's root.
const LSMT_ROOT: u64 = u64::MAX;
const LISTMOUNT_REVERSE: u64 = 1;
const STATMOUNT_BY_FD: u64 = 1;
/// The most IDs one `listmount` gives.
const LIST_MAX: u64 = 1_000_000;
/// `sizeof(struct statmount)`, after which its strings come.
const STATMOUNT_SIZE: usize = 512;
/// The top of the address space a buffer may reach (`access_ok`).
const USER_END: u64 = 0x7fff_ffff_f000;

const STATMOUNT_SB_BASIC: u64 = 0x1;
const STATMOUNT_MNT_BASIC: u64 = 0x2;
const STATMOUNT_PROPAGATE_FROM: u64 = 0x4;
const STATMOUNT_MNT_ROOT: u64 = 0x8;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE: u64 = 0x20;
const STATMOUNT_MNT_NS_ID: u64 = 0x40;
const STATMOUNT_MNT_OPTS: u64 = 0x80;
const STATMOUNT_FS_SUBTYPE: u64 = 0x100;
const STATMOUNT_SB_SOURCE: u64 = 0x200;
const STATMOUNT_OPT_ARRAY: u64 = 0x400;
const STATMOUNT_OPT_SEC_ARRAY: u64 = 0x800;
const STATMOUNT_SUPPORTED_MASK: u64 = 0x1000;
const STATMOUNT_MNT_UIDMAP: u64 = 0x2000;
const STATMOUNT_MNT_GIDMAP: u64 = 0x4000;
/// `STATMOUNT_SUPPORTED`.
const STATMOUNT_SUPPORTED: u64 = 0x7fff;
/// `STATMOUNT_STRING_REQ`: the requests that give strings.
const STATMOUNT_STRING_REQ: u64 = STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_OPTS
    | STATMOUNT_FS_SUBTYPE
    | STATMOUNT_SB_SOURCE
    | STATMOUNT_OPT_ARRAY
    | STATMOUNT_OPT_SEC_ARRAY
    | STATMOUNT_MNT_UIDMAP
    | STATMOUNT_MNT_GIDMAP;

pub(crate) fn sys_statmount(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(statmount(c, a[0], a[1], a[2], a[3] & 0xffff_ffff))
}
pub(crate) fn sys_listmount(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(listmount(c, a[0], a[1], a[2], a[3] & 0xffff_ffff))
}

/// `struct mnt_id_req`.
struct Request {
    /// `mnt_ns_fd`, or `mnt_fd` with `STATMOUNT_BY_FD`.
    fd: u32,
    mnt_id: u64,
    param: u64,
    ns_id: u64,
}

/// `copy_mnt_id_req`: its size (`EFAULT`, `E2BIG` beyond a page, `EINVAL`
/// under the first version's), then the request (`EFAULT`, `E2BIG` for bytes
/// past it that are not 0); by descriptor no mount or namespace ID
/// (`EINVAL`), else not both a namespace descriptor and ID, and a mount ID
/// past [`paludarium_vfs::UNIQUE_OFFSET`] (`EINVAL`).
fn request(c: &Context<'_>, ptr: u64, by_fd: bool) -> Result<Request, Errno> {
    let mut size = [0; 4];
    c.mem
        .read(GuestAddr(ptr), &mut size)
        .map_err(|_| Errno::EFAULT)?;
    let size = u64::from(u32::from_le_bytes(size));
    if size > PAGE {
        return Err(E2BIG);
    }
    if size < REQ_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let mut raw = vec![0; size as usize];
    c.mem
        .read(GuestAddr(ptr), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    if raw.iter().skip(REQ_SIZE_VER1 as usize).any(|&b| b != 0) {
        return Err(E2BIG);
    }
    raw.resize(REQ_SIZE_VER1 as usize, 0);
    let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or_default());
    let req = Request {
        fd: u32::from_le_bytes(raw[4..8].try_into().unwrap_or_default()),
        mnt_id: word(8),
        param: word(16),
        ns_id: word(24),
    };
    if by_fd {
        if req.mnt_id != 0 || req.ns_id != 0 {
            return Err(Errno::EINVAL);
        }
    } else if req.fd != 0 && req.ns_id != 0 || req.mnt_id <= paludarium_vfs::UNIQUE_OFFSET {
        return Err(Errno::EINVAL);
    }
    Ok(req)
}

/// The mount namespace a request names (`grab_requested_mnt_ns`): the one
/// numbered `mnt_ns_id` (`ENOENT`), the one of the namespace file
/// `mnt_ns_fd` (`EBADF`, `EINVAL` for another file or kind), or the
/// caller's.
struct Space {
    fs: Arc<NamespacedFs>,
    table: Arc<MountTable>,
    owner: Arc<dyn std::any::Any + Send + Sync>,
    own: bool,
    /// Where it is looked at from (`grab_requested_root`): the caller's
    /// root in its own namespace, another's root mount.
    root: Vec<u8>,
}
impl Space {
    /// The caller has CAP_SYS_ADMIN over the namespace's user namespace.
    fn administered(&self, c: &Context<'_>) -> bool {
        let creds = &c.process.credentials;
        match self.owner.downcast_ref::<Namespace>() {
            Some(owner) => creds.capable_in(CAP_SYS_ADMIN, owner),
            None => creds.capable(CAP_SYS_ADMIN),
        }
    }
}
fn space(c: &Context<'_>, req: &Request) -> Result<Space, Errno> {
    let own_table = c.files.mount_table();
    let namespaces = c.group.namespaces(c.tid);
    let first: Arc<dyn std::any::Any + Send + Sync> =
        Arc::clone(crate::users::first()) as Arc<dyn std::any::Any + Send + Sync>;
    let (table, owner) = if req.ns_id != 0 {
        let table = own_table.by_namespace_id(req.ns_id).ok_or(Errno::ENOENT)?;
        let owner = table.owner().unwrap_or(first);
        (table, owner)
    } else if req.fd != 0 {
        let file = c.files.descriptor(u64::from(req.fd))?.file;
        let ns = file
            .as_any()
            .and_then(|v| v.downcast_ref::<crate::namespaces::NamespaceFile>())
            .ok_or(Errno::EINVAL)?;
        if ns.namespace.kind != crate::namespaces::Kind::Mnt {
            return Err(Errno::EINVAL);
        }
        let table = crate::namespaces::mount_table(&ns.namespace, c.files);
        let owner = table.owner().unwrap_or(first);
        (table, owner)
    } else {
        let owner = own_table.owner().unwrap_or(first);
        (own_table.clone(), owner)
    };
    let own = Arc::ptr_eq(&table, &own_table);
    let fs = if own {
        c.files.namespaced()
    } else {
        c.files.namespaced_for(Arc::clone(&table))
    };
    drop(namespaces);
    Ok(Space {
        fs,
        table,
        owner,
        own,
        root: if own { c.files.root() } else { b"/".to_vec() },
    })
}

/// `access_ok`: the range is in user space.
fn accessible(addr: u64, len: u64) -> bool {
    addr.checked_add(len).is_some_and(|end| end <= USER_END)
}

/// `mnt_to_attr_flags`.
fn attributes(flags: u32) -> u64 {
    let mut out = 0;
    for (flag, attr) in [
        (mnt::READONLY, 0x01),
        (mnt::NOSUID, 0x02),
        (mnt::NODEV, 0x04),
        (mnt::NOEXEC, 0x08),
        (mnt::NODIRATIME, 0x80),
        (mnt::NOSYMFOLLOW, 0x0020_0000),
    ] {
        if flags & flag != 0 {
            out |= attr;
        }
    }
    out | if flags & mnt::NOATIME != 0 {
        0x10
    } else if flags & mnt::RELATIME != 0 {
        0
    } else {
        0x20
    }
}

/// `mnt_to_propagation_flags`.
fn propagation(m: &MountPoint) -> u64 {
    let mut out = 0;
    if m.group != 0 {
        out |= MS_SHARED;
    }
    if m.master != 0 {
        out |= MS_SLAVE;
    }
    if m.unbindable {
        out |= MS_UNBINDABLE;
    }
    if out == 0 { MS_PRIVATE } else { out }
}

/// `struct statmount` and its strings as `do_statmount` fills them.
struct Stat {
    fixed: [u8; STATMOUNT_SIZE],
    /// The strings, the first an empty one any unset offset points at
    /// (`seq`).
    strings: Vec<u8>,
    mask: u64,
    bufsize: u64,
}
impl Stat {
    fn put32(&mut self, at: usize, value: u32) {
        self.fixed[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(&mut self, at: usize, value: u64) {
        self.fixed[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    /// `statmount_string`: `text` at the field's offset `at`, unless it is
    /// empty, when nothing is set; `EOVERFLOW` when it and its 0 do not fit
    /// the buffer past the fixed part.
    fn string(&mut self, flag: u64, at: usize, text: &[u8]) -> Result<(), Errno> {
        if self.strings.is_empty() {
            self.strings.push(0);
        }
        if text.is_empty() {
            return Ok(());
        }
        let start = self.strings.len();
        self.strings.extend_from_slice(text);
        if (STATMOUNT_SIZE + self.strings.len()) as u64 >= self.bufsize {
            return Err(EOVERFLOW);
        }
        self.strings.push(0);
        self.mask |= flag;
        self.put32(at, start as u32);
        Ok(())
    }
}

/// The superblock flags `statmount` shows (`SB_RDONLY`, `SB_SYNCHRONOUS`,
/// `SB_DIRSYNC`, `SB_LAZYTIME`).
fn superblock_flags(m: &MountPoint) -> u32 {
    let mut out = u32::from(m.super_read_only);
    for word in m.common_options.split(',') {
        out |= match word {
            "sync" => 0x10,
            "dirsync" => 0x80,
            "lazytime" => 1 << 25,
            _ => 0,
        };
    }
    out
}

/// What `statfs` reports as the type of the file system of `m`.
fn magic(fs: &NamespacedFs, m: &MountPoint) -> u64 {
    if m.kind == "tmpfs" {
        return 0x0102_1994;
    }
    fs.statfs(&m.path).map_or(0, |stats| stats.kind)
}

/// `statmount(req, buf, bufsize, flags)`, as Linux master's: the flags
/// (`EINVAL`), the request ([`request`]), then the mount: by descriptor its
/// file's (`EBADF`), else the namespace ([`space`]), whose mounts another
/// namespace's caller sees only with CAP_SYS_ADMIN over it (`EPERM`), and
/// its mount with the unique ID (`ENOENT`), one not reachable from where it
/// is looked at from `EPERM` without that capability. A buffer out of user
/// space is `EFAULT`, and one too small for the strings asked for
/// `EOVERFLOW`. The results asked for are written (`mask`): the
/// superblock's device, type and flags, the mount's IDs, flags and
/// propagation, its root, its mount point from the caller's root (none
/// outside it), the type's name, its options alone and as an array, its
/// source and its namespace's ID; it has no subtype, security options or
/// ID mappings to give. A detached tree's mount by its descriptor is
/// `ENOENT`, as Linux's is for one alone in its anonymous namespace, and
/// one is found in the caller's namespace, not its file's.
fn statmount(
    c: &mut Context<'_>,
    req: u64,
    buf: u64,
    bufsize: u64,
    flags: u64,
) -> Result<u64, Errno> {
    if flags & !STATMOUNT_BY_FD != 0 {
        return Err(Errno::EINVAL);
    }
    let by_fd = flags & STATMOUNT_BY_FD != 0;
    let req = request(c, req, by_fd)?;
    // By descriptor: the file's (`fget_raw`), whose mount is looked for in
    // the caller's own namespace, where Linux takes the file's mount and
    // its namespace (one opened before a `setns` differs); else the
    // namespace named.
    let (space, file) = if by_fd {
        let d = c.files.descriptor(u64::from(req.fd))?;
        let own = Request {
            fd: 0,
            mnt_id: 0,
            param: 0,
            ns_id: 0,
        };
        (space(c, &own)?, Some(d))
    } else {
        let space = space(c, &req)?;
        if req.ns_id != 0 && !space.own && !space.administered(c) {
            return Err(Errno::EPERM);
        }
        (space, None)
    };
    // `prepare_kstatmount`.
    if !accessible(buf, bufsize) {
        return Err(Errno::EFAULT);
    }
    let mask = req.param;
    if mask & STATMOUNT_STRING_REQ != 0 && bufsize <= STATMOUNT_SIZE as u64 {
        return Err(EOVERFLOW);
    }
    // `do_statmount`: the mount, then whether it is seen from the root.
    let record = match file {
        Some(d) => {
            if d.path.is_empty() {
                return Err(Errno::EINVAL);
            }
            let at = d.file.guest_path_hint().unwrap_or(d.path);
            if at.windows(2).any(|w| w == b"/\0") {
                return Err(Errno::ENOENT);
            }
            let id = space.fs.mount_id(&at);
            space
                .fs
                .mounts()
                .into_iter()
                .find(|m| m.id == id)
                .ok_or(Errno::ENOENT)?
        }
        None => {
            let record = space
                .fs
                .mounts()
                .into_iter()
                .find(|m| m.unique == req.mnt_id)
                .ok_or(Errno::ENOENT)?;
            if space.fs.reaches(record.unique, Reach::Path(&space.root)) != Some(true)
                && !space.administered(c)
            {
                return Err(Errno::EPERM);
            }
            record
        }
    };
    let m = &record;
    let mut s = Stat {
        fixed: [0; STATMOUNT_SIZE],
        strings: Vec::new(),
        mask: 0,
        bufsize,
    };
    if mask & STATMOUNT_MNT_BASIC != 0 {
        s.mask |= STATMOUNT_MNT_BASIC;
        s.put64(40, m.unique);
        s.put64(48, m.parent_unique);
        s.put32(56, m.id as u32);
        s.put32(60, m.parent as u32);
        s.put64(64, attributes(m.flags));
        s.put64(72, propagation(m));
        s.put64(80, m.group);
        s.put64(88, m.master);
    }
    if mask & STATMOUNT_SB_BASIC != 0 {
        s.mask |= STATMOUNT_SB_BASIC;
        let (major, minor) = (
            (m.device & 0xfff00) >> 8,
            m.device & 0xff | (m.device >> 12) & 0xfff00,
        );
        s.put32(16, major as u32);
        s.put32(20, minor as u32);
        s.put64(24, magic(&space.fs, m));
        s.put32(32, superblock_flags(m));
    }
    if mask & STATMOUNT_PROPAGATE_FROM != 0 {
        s.mask |= STATMOUNT_PROPAGATE_FROM;
        s.put64(96, m.propagate_from);
    }
    let options = m
        .super_options
        .strip_prefix(',')
        .unwrap_or(&m.super_options);
    let point = crate::files::seen_from(&space.root, &m.path).unwrap_or_default();
    let array: Vec<u8> = options
        .split(',')
        .filter(|o| !o.is_empty())
        .collect::<Vec<_>>()
        .join("\0")
        .into_bytes();
    let strings: [(u64, usize, &[u8]); 7] = [
        (STATMOUNT_FS_TYPE, 36, m.kind.as_bytes()),
        (STATMOUNT_MNT_ROOT, 104, &m.root),
        (STATMOUNT_MNT_POINT, 108, &point),
        (STATMOUNT_MNT_OPTS, 4, options.as_bytes()),
        (STATMOUNT_OPT_ARRAY, 132, &array),
        (STATMOUNT_OPT_SEC_ARRAY, 140, b""),
        (STATMOUNT_SB_SOURCE, 124, &m.source),
    ];
    for (flag, at, text) in strings {
        if mask & flag != 0 {
            s.string(flag, at, text)?;
            if flag == STATMOUNT_OPT_ARRAY && !array.is_empty() {
                s.put32(
                    128,
                    options.split(',').filter(|o| !o.is_empty()).count() as u32,
                );
            }
        }
    }
    // No subtype nor ID mappings: nothing is written for them.
    for flag in [
        STATMOUNT_FS_SUBTYPE,
        STATMOUNT_MNT_UIDMAP,
        STATMOUNT_MNT_GIDMAP,
    ] {
        if mask & flag != 0 && s.strings.is_empty() {
            s.strings.push(0);
        }
    }
    if mask & STATMOUNT_MNT_NS_ID != 0 {
        s.mask |= STATMOUNT_MNT_NS_ID;
        s.put64(112, space.table.namespace_id());
    }
    if mask & STATMOUNT_SUPPORTED_MASK != 0 {
        s.mask |= STATMOUNT_SUPPORTED_MASK;
        s.put64(144, STATMOUNT_SUPPORTED);
    }
    let copied = (bufsize as usize).min(STATMOUNT_SIZE);
    let mask_now = s.mask;
    s.put64(8, mask_now);
    s.put32(0, (copied + s.strings.len()) as u32);
    if !s.strings.is_empty() {
        c.mem
            .write(GuestAddr(buf + STATMOUNT_SIZE as u64), &s.strings)
            .map_err(|_| Errno::EFAULT)?;
    }
    c.mem
        .write(GuestAddr(buf), &s.fixed[..copied])
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// `listmount(req, mnt_ids, nr_mnt_ids, flags)`, as Linux master's: the
/// flags (`EINVAL`), the count (`EOVERFLOW` past a million), the array in
/// user space (`EFAULT`), the request ([`request`]) and the last ID it gives
/// (`EINVAL` for one not past the offset), then the namespace ([`space`],
/// `ENOENT` for another one without CAP_SYS_ADMIN over it). From the
/// caller's root (`LSMT_ROOT`) or from the mount with that ID (`ENOENT`),
/// one not reachable from the root needing that capability (`EPERM`), it
/// gives the unique IDs of the mounts reachable from there but that mount,
/// in order (backwards with `LISTMOUNT_REVERSE`), after the last ID it was
/// given, as many as fit.
fn listmount(c: &mut Context<'_>, req: u64, ids: u64, nr: u64, flags: u64) -> Result<u64, Errno> {
    if flags & !LISTMOUNT_REVERSE != 0 {
        return Err(Errno::EINVAL);
    }
    if nr > LIST_MAX {
        return Err(EOVERFLOW);
    }
    if !accessible(ids, nr * 8) {
        return Err(Errno::EFAULT);
    }
    let req = request(c, req, false)?;
    let last = req.param;
    if last != 0 && last <= paludarium_vfs::UNIQUE_OFFSET {
        return Err(Errno::EINVAL);
    }
    let space = space(c, &req)?;
    if req.ns_id != 0 && !space.own && !space.administered(c) {
        return Err(Errno::ENOENT);
    }
    let from = if req.mnt_id == LSMT_ROOT {
        Reach::Path(&space.root)
    } else {
        Reach::Mount(req.mnt_id)
    };
    let mut uniques: Vec<u64> = space.fs.mounts().iter().map(|m| m.unique).collect();
    uniques.sort_unstable();
    if let Reach::Mount(unique) = from {
        if !uniques.contains(&unique) {
            return Err(Errno::ENOENT);
        }
        if space.fs.reaches(unique, Reach::Path(&space.root)) != Some(true)
            && !space.administered(c)
        {
            return Err(Errno::EPERM);
        }
    }
    let reverse = flags & LISTMOUNT_REVERSE != 0;
    if reverse {
        uniques.reverse();
    }
    let after = |u: u64| match (last, reverse) {
        (0, _) => true,
        (_, false) => u > last,
        (_, true) => u < last,
    };
    let mut out = Vec::new();
    for unique in uniques.into_iter().filter(|&u| after(u)) {
        if out.len() as u64 == nr {
            break;
        }
        if unique == req.mnt_id {
            continue;
        }
        if space.fs.reaches(unique, from) == Some(true) {
            out.push(unique);
        }
    }
    let bytes: Vec<u8> = out.iter().flat_map(|u| u.to_le_bytes()).collect();
    c.mem
        .write(GuestAddr(ids), &bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(out.len() as u64)
}
