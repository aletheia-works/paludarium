//! User namespaces, as Linux's `struct user_namespace`: the user and group
//! IDs a namespace maps onto its parent's (`uid_map`, `gid_map`), whether
//! `setgroups` may run in it, and who made it, which the capabilities of a
//! thread are counted against.
//!
//! The kernel names users and groups by their IDs in the first namespace,
//! which maps every ID onto itself (Linux's `kuid_t` and `kgid_t`); a
//! nested namespace's map is kept in those IDs too, so an ID crosses a
//! system call through the caller's namespace only ([`Namespace::id_of`]
//! out, [`Namespace::kernel_of`] in). A thread's capabilities count in its
//! own user namespace and in those nested in it that its effective user
//! made ([`Namespace::grants`]), as Linux's `cap_capable`.
use crate::credentials::Credentials;
use crate::namespaces::Namespace;
use paludarium_types::Errno;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

/// The ID an unmapped user or group shows as (`overflowuid`,
/// `overflowgid`).
pub(crate) const OVERFLOW: u32 = 65534;
/// The ID that names nobody (`(uid_t) -1`).
pub(crate) const INVALID: u32 = u32::MAX;
/// `UID_GID_MAP_MAX_EXTENTS`.
const MAX_EXTENTS: usize = 340;
/// How deep user namespaces nest: Linux refuses a new one below level 32.
const MAX_DEPTH: u32 = 32;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SETUID: u64 = 1 << 7;
const CAP_SETGID: u64 = 1 << 6;
const CAP_SETFCAP: u64 = 1 << 31;
const ENOSPC: Errno = Errno(28);

/// The first user namespace, which every thread starts in.
static FIRST: LazyLock<Arc<Namespace>> = LazyLock::new(Namespace::first_user);
pub(crate) fn first() -> &'static Arc<Namespace> {
    &FIRST
}

/// Which IDs a map is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ids {
    User,
    Group,
}

/// One line of a map: `count` IDs from `first` in the namespace, from
/// `lower` in the first one's (Linux's `uid_gid_extent`, whose
/// `lower_first` is kept as a kernel ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Extent {
    first: u32,
    lower: u32,
    count: u32,
}
impl Extent {
    fn up(&self, kernel: u32) -> Option<u32> {
        let offset = kernel.checked_sub(self.lower)?;
        (offset < self.count).then(|| self.first + offset)
    }
    fn down(&self, id: u32) -> Option<u32> {
        let offset = id.checked_sub(self.first)?;
        (offset < self.count).then(|| self.lower + offset)
    }
}

#[derive(Debug, Default)]
struct Maps {
    uid: Vec<Extent>,
    gid: Vec<Extent>,
    /// `setgroups` has been denied (Linux's `USERNS_SETGROUPS_ALLOWED`
    /// cleared), which a new namespace takes from its parent.
    setgroups_denied: bool,
}
impl Maps {
    fn of(&self, ids: Ids) -> &Vec<Extent> {
        match ids {
            Ids::User => &self.uid,
            Ids::Group => &self.gid,
        }
    }
}

/// What a user namespace holds: its parent, how deep it is, the effective
/// IDs of the thread that made it (its owner), whether that thread had
/// CAP_SETFCAP, that thread's `RLIMIT_MSGQUEUE` then, and its maps.
#[derive(Debug, Default)]
pub(crate) struct Users {
    parent: Option<Arc<Namespace>>,
    depth: u32,
    owner: u32,
    could_setfcap: bool,
    /// The most bytes of POSIX message queues the namespace's users may
    /// charge together, in its parent's count of its owner
    /// (`set_userns_rlimit_max` of `UCOUNT_RLIMIT_MSGQUEUE`).
    msgqueue_max: u64,
    maps: Mutex<Maps>,
}

impl Users {
    pub(crate) fn parent(&self) -> Option<&Arc<Namespace>> {
        self.parent.as_ref()
    }
    /// The kernel user ID of the thread that made the namespace.
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
    pub(crate) fn msgqueue_max(&self) -> u64 {
        self.msgqueue_max
    }
}

impl Namespace {
    fn maps(&self) -> MutexGuard<'_, Maps> {
        self.users
            .maps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    fn is_first_user(&self) -> bool {
        self.users.parent.is_none()
    }
    /// A new user namespace in `parent`, made by a thread with `creds`, as
    /// Linux's `create_user_ns`: `ENOSPC` past [`MAX_DEPTH`], `EPERM` when
    /// the thread's effective IDs have no mapping in `parent`.
    pub(crate) fn new_user(
        parent: &Arc<Namespace>,
        inode: u32,
        creds: &Credentials,
        msgqueue_max: u64,
    ) -> Result<Arc<Namespace>, Errno> {
        if parent.users.depth > MAX_DEPTH {
            return Err(ENOSPC);
        }
        if parent.id_of(Ids::User, creds.euid).is_none()
            || parent.id_of(Ids::Group, creds.egid).is_none()
        {
            return Err(Errno::EPERM);
        }
        let users = Users {
            parent: Some(Arc::clone(parent)),
            depth: parent.users.depth + 1,
            owner: creds.euid,
            could_setfcap: creds.effective & CAP_SETFCAP != 0,
            msgqueue_max,
            maps: Mutex::new(Maps {
                setgroups_denied: parent.maps().setgroups_denied,
                ..Maps::default()
            }),
        };
        Ok(Namespace::user(inode, users))
    }
    /// The ID that `kernel` (an ID of the first namespace) is here
    /// (`from_kuid`): `None` when the namespace does not map it, and for
    /// [`INVALID`], which names nobody.
    pub(crate) fn id_of(&self, ids: Ids, kernel: u32) -> Option<u32> {
        if kernel == INVALID {
            return None;
        }
        if self.is_first_user() {
            return Some(kernel);
        }
        self.maps()
            .of(ids)
            .iter()
            .find_map(|extent| extent.up(kernel))
    }
    /// The same, or [`OVERFLOW`] for an ID it does not map, as a system call
    /// shows one (`from_kuid_munged`).
    pub(crate) fn shown(&self, ids: Ids, kernel: u32) -> u32 {
        self.id_of(ids, kernel).unwrap_or(OVERFLOW)
    }
    /// The kernel ID that `id` here names (`make_kuid`): `None` for `-1` and
    /// for an ID the namespace does not map.
    pub(crate) fn kernel_of(&self, ids: Ids, id: u32) -> Option<u32> {
        if id == INVALID {
            return None;
        }
        if self.is_first_user() {
            return Some(id);
        }
        self.maps()
            .of(ids)
            .iter()
            .find_map(|extent| extent.down(id))
    }
    /// Whether a thread of user namespace `own`, with effective user ID
    /// `euid` and effective capabilities `effective`, has capability `cap`
    /// in this one, as Linux's `cap_capable`: in its own namespace by its
    /// effective set; in one nested in it by being the owner of the
    /// outermost one below its own; in no other.
    pub(crate) fn grants(&self, own: &Namespace, euid: u32, effective: u64, cap: u64) -> bool {
        let mut at = self;
        loop {
            if std::ptr::eq(at, own) {
                return effective & cap == cap;
            }
            if at.users.depth <= own.users.depth {
                return false;
            }
            let Some(parent) = at.users.parent.as_deref() else {
                return false;
            };
            if std::ptr::eq(parent, own) && at.users.owner == euid {
                return true;
            }
            at = parent;
        }
    }
    /// Whether `setgroups` may run here (`userns_may_setgroups`): its gid
    /// map is written and `setgroups` is not denied.
    pub(crate) fn may_setgroups(&self) -> bool {
        let maps = self.maps();
        self.is_first_user() || !maps.gid.is_empty() && !maps.setgroups_denied
    }
    /// What `/proc/<pid>/uid_map` or `gid_map` reads to a thread of user
    /// namespace `reader`: each extent, its lower IDs as the reader's
    /// namespace has them, or its parent's when it is this one (Linux's
    /// `uid_m_show`).
    pub(crate) fn map_text(&self, ids: Ids, reader: &Namespace) -> Vec<u8> {
        let lower_ns = match &self.users.parent {
            Some(parent) if std::ptr::eq(reader, self) => &**parent,
            _ => reader,
        };
        let extents: Vec<Extent> = if self.is_first_user() {
            vec![Extent {
                first: 0,
                lower: 0,
                count: u32::MAX,
            }]
        } else {
            self.maps().of(ids).clone()
        };
        let mut text = Vec::new();
        for extent in extents {
            let lower = lower_ns.id_of(ids, extent.lower).unwrap_or(INVALID);
            text.extend(
                format!("{:>10} {:>10} {:>10}\n", extent.first, lower, extent.count).into_bytes(),
            );
        }
        text
    }
    /// What `/proc/<pid>/setgroups` reads.
    pub(crate) fn setgroups_text(&self) -> &'static [u8] {
        if self.maps().setgroups_denied {
            b"deny\n"
        } else {
            b"allow\n"
        }
    }
    /// A write of `text` to `/proc/<pid>/setgroups`, as Linux's
    /// `proc_setgroups_write`: `allow` or `deny`, with spaces after it
    /// (`EINVAL` else). Allowing it again once denied is `EPERM`, and so is
    /// denying it once the gid map is written.
    pub(crate) fn write_setgroups(&self, text: &[u8]) -> Result<(), Errno> {
        let (allow, rest) = if let Some(rest) = text.strip_prefix(b"allow") {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix(b"deny") {
            (false, rest)
        } else {
            return Err(Errno::EINVAL);
        };
        if !rest.iter().all(u8::is_ascii_whitespace) {
            return Err(Errno::EINVAL);
        }
        let mut maps = self.maps();
        if allow {
            if maps.setgroups_denied {
                return Err(Errno::EPERM);
            }
        } else {
            if self.is_first_user() || !maps.gid.is_empty() {
                return Err(Errno::EPERM);
            }
            maps.setgroups_denied = true;
        }
        Ok(())
    }
    /// A write of `text` to this namespace's uid or gid map, by a thread
    /// with `writer`'s credentials, through a file opened with `opener`'s,
    /// as Linux's `proc_uid_map_write` and `map_write`, in their order: the
    /// first namespace's map, a map written before, an opener of neither
    /// this namespace nor its parent and one without CAP_SYS_ADMIN here are
    /// `EPERM`; a line that is not three numbers, an extent of no IDs or one
    /// that wraps, overlaps another or is one too many is `EINVAL`, and so is
    /// no line at all; IDs neither the opener's own (alone, by the owner) nor
    /// allowed by CAP_SETUID or CAP_SETGID in the parent, and lower IDs the
    /// parent does not map, are `EPERM`.
    pub(crate) fn write_map(
        &self,
        ids: Ids,
        text: &[u8],
        opener: &Credentials,
        writer: &Credentials,
    ) -> Result<(), Errno> {
        let Some(parent) = self.users.parent.as_deref() else {
            return Err(Errno::EPERM);
        };
        let opener_ns = &*opener.user.0;
        if !std::ptr::eq(opener_ns, self) && !std::ptr::eq(opener_ns, parent) {
            return Err(Errno::EPERM);
        }
        if !self.maps().of(ids).is_empty() {
            return Err(Errno::EPERM);
        }
        if !opener.capable_in(CAP_SYS_ADMIN, self) {
            return Err(Errno::EPERM);
        }
        let extents = parse_map(text)?;
        let cap = match ids {
            Ids::User => CAP_SETUID,
            Ids::Group => CAP_SETGID,
        };
        if !self.idmap_permitted(ids, &extents, cap, opener, writer, parent) {
            return Err(Errno::EPERM);
        }
        // The lower IDs, through the parent's map, as kernel IDs: an
        // extent must lie within one of the parent's.
        let mut lowered = Vec::with_capacity(extents.len());
        for extent in extents {
            let lower = parent
                .lower_range(ids, extent.lower, extent.count)
                .ok_or(Errno::EPERM)?;
            lowered.push(Extent { lower, ..extent });
        }
        let mut maps = self.maps();
        let map = match ids {
            Ids::User => &mut maps.uid,
            Ids::Group => &mut maps.gid,
        };
        if !map.is_empty() {
            return Err(Errno::EPERM);
        }
        *map = lowered;
        Ok(())
    }
    /// The kernel ID of `id`, with the `count - 1` after it in the same
    /// extent (`map_id_range_down`).
    fn lower_range(&self, ids: Ids, id: u32, count: u32) -> Option<u32> {
        if self.is_first_user() {
            return Some(id);
        }
        let last = id.checked_add(count - 1)?;
        self.maps()
            .of(ids)
            .iter()
            .find(|extent| extent.down(id).is_some() && extent.down(last).is_some())
            .and_then(|extent| extent.down(id))
    }
    /// Linux's `new_idmap_permitted` (with `verify_root_map` for the uid
    /// map): a map of the parent's root needs CAP_SETFCAP, which the
    /// namespace's maker had when it is the opener's own; the owner may map
    /// its own effective ID alone (a group only once `setgroups` is
    /// denied); anything else needs CAP_SETUID or CAP_SETGID in the parent,
    /// for the writer and the opener.
    fn idmap_permitted(
        &self,
        ids: Ids,
        extents: &[Extent],
        cap: u64,
        opener: &Credentials,
        writer: &Credentials,
        parent: &Namespace,
    ) -> bool {
        if ids == Ids::User && extents.iter().any(|extent| extent.lower == 0) {
            let root_allowed = if std::ptr::eq(&*opener.user.0, self) {
                self.users.could_setfcap
            } else {
                opener.capable_in(CAP_SETFCAP, parent)
            };
            if !root_allowed {
                return false;
            }
        }
        if let [extent] = extents
            && extent.count == 1
            && self.users.owner == opener.euid
        {
            match ids {
                Ids::User if parent.kernel_of(ids, extent.lower) == Some(opener.euid) => {
                    return true;
                }
                Ids::Group
                    if self.maps().setgroups_denied
                        && parent.kernel_of(ids, extent.lower) == Some(opener.egid) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        writer.capable_in(cap, parent) && opener.capable_in(cap, parent)
    }
}

/// The extents of a map's text, as Linux's `map_write` parses it: lines of
/// three decimal numbers apart by spaces; `EINVAL` for anything else, an
/// ID of `-1`, an extent of no IDs or that wraps, extents that overlap, and
/// more than [`MAX_EXTENTS`].
fn parse_map(text: &[u8]) -> Result<Vec<Extent>, Errno> {
    let mut extents: Vec<Extent> = Vec::new();
    let text = text.trim_suffix(b"\n");
    for line in text.split(|&b| b == b'\n') {
        let mut numbers = line
            .split(u8::is_ascii_whitespace)
            .filter(|part| !part.is_empty());
        let mut number = || -> Result<u32, Errno> {
            let part = numbers.next().ok_or(Errno::EINVAL)?;
            if !part.iter().all(u8::is_ascii_digit) {
                return Err(Errno::EINVAL);
            }
            // `simple_strtoul`, cut to 32 bits.
            Ok(part.iter().fold(0u64, |value, &digit| {
                value.wrapping_mul(10).wrapping_add(u64::from(digit - b'0'))
            }) as u32)
        };
        let extent = Extent {
            first: number()?,
            lower: number()?,
            count: number()?,
        };
        if numbers.next().is_some() {
            return Err(Errno::EINVAL);
        }
        if extent.first == INVALID || extent.lower == INVALID {
            return Err(Errno::EINVAL);
        }
        if extent.first.wrapping_add(extent.count) <= extent.first
            || extent.lower.wrapping_add(extent.count) <= extent.lower
        {
            return Err(Errno::EINVAL);
        }
        let overlaps = |a: u32, b: u32, count_a: u32, count_b: u32| {
            a <= b + (count_b - 1) && b <= a + (count_a - 1)
        };
        if extents.iter().any(|other| {
            overlaps(extent.first, other.first, extent.count, other.count)
                || overlaps(extent.lower, other.lower, extent.count, other.count)
        }) {
            return Err(Errno::EINVAL);
        }
        if extents.len() == MAX_EXTENTS {
            return Err(Errno::EINVAL);
        }
        extents.push(extent);
    }
    if extents.is_empty() {
        return Err(Errno::EINVAL);
    }
    Ok(extents)
}

/// A thread's user namespace, as its credentials hold it; two are equal
/// when they are the same namespace.
#[derive(Clone)]
pub(crate) struct UserNs(pub Arc<Namespace>);
impl Default for UserNs {
    fn default() -> Self {
        Self(Arc::clone(first()))
    }
}
impl PartialEq for UserNs {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for UserNs {}
impl std::fmt::Debug for UserNs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserNs({})", self.0.inode)
    }
}
impl std::ops::Deref for UserNs {
    type Target = Namespace;
    fn deref(&self) -> &Namespace {
        &self.0
    }
}

/// An open `/proc/<pid>/uid_map`, `gid_map` (`ids`) or `setgroups` (no
/// `ids`) of user namespace `namespace`: what it read when it was opened,
/// and one write at its start, checked with the credentials of the thread
/// that opened it, as Linux's `file->f_cred`.
pub(crate) struct MapFile {
    namespace: Arc<Namespace>,
    ids: Option<Ids>,
    content: Vec<u8>,
    opener: Credentials,
    position: Mutex<u64>,
    flags: u32,
}
impl MapFile {
    pub(crate) fn open(
        namespace: Arc<Namespace>,
        ids: Option<Ids>,
        content: Vec<u8>,
        opener: Credentials,
        flags: u32,
    ) -> Self {
        Self {
            namespace,
            ids,
            content,
            opener,
            position: Mutex::new(0),
            flags,
        }
    }
    fn position(&self) -> MutexGuard<'_, u64> {
        self.position.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
impl paludarium_host::FileHandle for MapFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.flags & 3 == 1 {
            return Err(Errno::EBADF);
        }
        let mut position = self.position();
        let at = usize::try_from(*position).unwrap_or(usize::MAX);
        let rest = self.content.get(at..).unwrap_or(&[]);
        let count = buf.len().min(rest.len());
        buf[..count].copy_from_slice(&rest[..count]);
        *position += count as u64;
        Ok(count)
    }
    /// One write of the whole text at the file's start, under a page (a
    /// map) or shorter than `deny` with its NUL (`setgroups`), else
    /// `EINVAL`.
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if self.flags & 3 == 0 {
            return Err(Errno::EBADF);
        }
        let mut position = self.position();
        let limit = if self.ids.is_some() { 4096 } else { 8 };
        if *position != 0 || buf.len() >= limit {
            return Err(Errno::EINVAL);
        }
        match self.ids {
            Some(ids) => self
                .namespace
                .write_map(ids, buf, &self.opener, &self.opener)?,
            None => self.namespace.write_setgroups(buf)?,
        }
        *position = buf.len() as u64;
        Ok(buf.len())
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position();
        let base = match whence {
            0 => 0,
            1 => *position as i64,
            2 => self.content.len() as i64,
            _ => return Err(Errno::EINVAL),
        };
        let target = base
            .checked_add(offset)
            .filter(|&t| t >= 0)
            .ok_or(Errno::EINVAL)?;
        *position = target as u64;
        Ok(target as u64)
    }
    fn stat(&self) -> Result<paludarium_host::FileStat, Errno> {
        Ok(paludarium_host::FileStat {
            mode: 0o100_644,
            ..crate::proc::stat(self.content.len())
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.flags
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nobody_shows_as_the_overflow_id_where_65534_is_mapped() {
        let root = Credentials::default();
        let ns = Namespace::new_user(first(), 0xF000_1000, &root, u64::MAX).unwrap();
        ns.write_map(Ids::User, b"0 65534 1", &root, &root).unwrap();
        assert_eq!(ns.shown(Ids::User, OVERFLOW), 0);
        assert_eq!(ns.shown(Ids::User, INVALID), OVERFLOW);
        assert_eq!(first().shown(Ids::User, INVALID), OVERFLOW);
        assert_eq!(first().id_of(Ids::Group, INVALID), None);
    }

    #[test]
    fn maps_parse_as_linux_reads_them() {
        assert_eq!(
            parse_map(b"0 1000 1\n").unwrap(),
            [Extent {
                first: 0,
                lower: 1000,
                count: 1
            }]
        );
        assert_eq!(parse_map(b"  0   1000   10  \n5000 0 1").unwrap().len(), 2);
        for bad in [
            &b""[..],
            b"\n",
            b"0 1000",
            b"0 1000 0",
            b"0 1000 1 4",
            b"0 x 1",
            b"4294967295 0 1",
            b"0 0 10\n5 100 1",
            b"0 0 10\n100 5 1",
        ] {
            assert_eq!(parse_map(bad), Err(Errno::EINVAL), "{bad:?}");
        }
        let many: Vec<u8> = (0..341)
            .flat_map(|i| format!("{i} {i} 1\n").into_bytes())
            .collect();
        assert_eq!(parse_map(&many), Err(Errno::EINVAL));
    }
}
