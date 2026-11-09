//! What System V shared memory ([`crate::shm`]) and semaphores
//! ([`crate::sem`]) have in common, as Linux's `ipc/util.c`: the IDs of a
//! kind of object in an IPC namespace, the permissions of one
//! (`kern_ipc_perm`), and the capability checks against the user namespace
//! that owns the IPC namespace.
use crate::credentials::Credentials;
use crate::namespaces::Namespace;
use crate::syscalls::Context;
use crate::users::Ids as Kind;
use paludarium_host::ClockId;
use paludarium_types::Errno;
use std::collections::BTreeMap;

pub(crate) const IPC_PRIVATE: i32 = 0;
pub(crate) const IPC_CREAT: i32 = 0o1000;
pub(crate) const IPC_EXCL: i32 = 0o2000;
pub(crate) const IPC_NOWAIT: i32 = 0o4000;

pub(crate) const IPC_RMID: i32 = 0;
pub(crate) const IPC_SET: i32 = 1;
pub(crate) const IPC_STAT: i32 = 2;
pub(crate) const IPC_INFO: i32 = 3;

pub(crate) const CAP_IPC_OWNER: u64 = 1 << 15;
pub(crate) const CAP_SYS_ADMIN: u64 = 1 << 21;

/// An ID is its index plus its sequence number shifted by this (Linux's
/// `IPCMNI_SHIFT`), and indexes are allocated in turn below at least 64.
pub(crate) const SEQ_SHIFT: u32 = 15;
pub(crate) const IPCMNI: u32 = 1 << SEQ_SHIFT;
const SEQ_MAX: u32 = i32::MAX as u32 >> SEQ_SHIFT;
const MIN_CYCLE: usize = 64;

/// The IDs given out of one kind of object in an IPC namespace (Linux's
/// `struct ipc_ids`).
#[derive(Default)]
pub(crate) struct Ids {
    /// The sequence number of the IDs given out, which goes up whenever an
    /// index is given out again after a higher one (Linux's `ids->seq`).
    seq: u32,
    /// The index given out last, and where the search for the next starts.
    last: Option<u32>,
    next: u32,
}

impl Ids {
    /// A new ID, as Linux's `ipc_addid` and `ipc_idr_alloc`: `ENOSPC` with
    /// `limit` objects in use, else the next free index from the last one
    /// given out, below the larger of 64 and half as many again as are in
    /// use, or the first free one from 0, which starts a new sequence
    /// number.
    pub fn allocate<T>(&mut self, objects: &BTreeMap<u32, T>, limit: usize) -> Result<i32, Errno> {
        let in_use = objects.len();
        if in_use >= limit {
            return Err(Errno::ENOSPC);
        }
        let end = (in_use * 3 / 2).clamp(MIN_CYCLE, IPCMNI as usize) as u32;
        let free = |from: u32| (from..end).find(|index| !objects.contains_key(index));
        let index = free(self.next).or_else(|| free(0)).ok_or(Errno::ENOSPC)?;
        self.next = index + 1;
        if self.last.is_some_and(|last| index <= last) {
            self.seq += 1;
            if self.seq >= SEQ_MAX {
                self.seq = 0;
            }
        }
        self.last = Some(index);
        Ok(((self.seq << SEQ_SHIFT) + index) as i32)
    }
}

/// The index of an ID, which also takes the low bits of an index given as
/// an ID (`ipcid_to_idx`).
pub(crate) fn index(id: i32) -> u32 {
    id as u32 % IPCMNI
}

/// The highest index in use, or 0 for none (Linux's `ipc_get_maxidx`, which
/// the commands that give it make 0 for none).
pub(crate) fn max_index<T>(objects: &BTreeMap<u32, T>) -> u64 {
    objects
        .keys()
        .next_back()
        .map_or(0, |&index| u64::from(index))
}

/// An object's owner, creator and permissions (`struct kern_ipc_perm`).
#[derive(Clone)]
pub(crate) struct Perm {
    /// Its key, `IPC_PRIVATE` once a segment is marked for removal.
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    /// The permissions, and the kind's own mode bits above them.
    pub mode: u32,
}

impl Perm {
    /// Made by `credentials` for `key` with the permissions of `flag`.
    pub fn new(key: i32, credentials: &Credentials, flag: i32) -> Self {
        Self {
            key,
            uid: credentials.euid,
            gid: credentials.egid,
            cuid: credentials.euid,
            cgid: credentials.egid,
            mode: flag as u32 & 0o777,
        }
    }
    /// Whether `credentials` may use the object for `flag`'s permission
    /// bits, as Linux's `ipcperms`: as its owner or creator, else as a
    /// member of its group (by the filesystem group ID, as `in_group_p`),
    /// else as anyone, or with `CAP_IPC_OWNER` over the IPC namespace
    /// (`owner_capable`).
    pub fn permitted(&self, credentials: &Credentials, flag: u32, owner_capable: bool) -> bool {
        let requested = (flag >> 6) | (flag >> 3) | flag;
        let in_group = |gid: u32| credentials.fsgid == gid || credentials.groups.contains(&gid);
        let granted = if credentials.euid == self.cuid || credentials.euid == self.uid {
            self.mode >> 6
        } else if in_group(self.cgid) || in_group(self.gid) {
            self.mode >> 3
        } else {
            self.mode
        };
        requested & !granted & 0o7 == 0 || owner_capable
    }
    /// Whether `credentials` are its owner's or creator's, as Linux's
    /// `ipcctl_obtain_check` asks before `IPC_SET` and `IPC_RMID`.
    pub fn owned_by(&self, credentials: &Credentials) -> bool {
        credentials.euid == self.cuid || credentials.euid == self.uid
    }
    /// `IPC_SET`'s owner and permissions from `struct ipc64_perm` in `ds`,
    /// in the caller's user namespace `user` (`ipc_update_perm`): `EINVAL`
    /// for an ID it does not map.
    pub fn update(&mut self, ds: &[u8], user: &Namespace) -> Result<(), Errno> {
        let field = |at: usize| u32::from_le_bytes([ds[at], ds[at + 1], ds[at + 2], ds[at + 3]]);
        let (uid, gid, mode) = (field(4), field(8), field(20));
        let (Some(uid), Some(gid)) = (
            user.kernel_of(Kind::User, uid),
            user.kernel_of(Kind::Group, gid),
        ) else {
            return Err(Errno::EINVAL);
        };
        self.uid = uid;
        self.gid = gid;
        self.mode = self.mode & !0o777 | mode & 0o777;
        Ok(())
    }
    /// Writes it as x86-64's `struct ipc64_perm` to the start of `ds`, its
    /// IDs as the caller's user namespace `user` shows them, with the
    /// sequence number of `id`.
    pub fn put(&self, ds: &mut [u8], id: i32, user: &Namespace) {
        let mut put = |at: usize, bytes: &[u8]| ds[at..at + bytes.len()].copy_from_slice(bytes);
        put(0, &self.key.to_le_bytes());
        put(4, &user.shown(Kind::User, self.uid).to_le_bytes());
        put(8, &user.shown(Kind::Group, self.gid).to_le_bytes());
        put(12, &user.shown(Kind::User, self.cuid).to_le_bytes());
        put(16, &user.shown(Kind::Group, self.cgid).to_le_bytes());
        put(20, &self.mode.to_le_bytes());
        put(24, &((id as u32 >> SEQ_SHIFT) as u16).to_le_bytes());
    }
}

/// Whether the caller has `cap` in the user namespace that owns its IPC
/// namespace (`ns_capable(ns->user_ns, cap)`).
pub(crate) fn capable(c: &Context<'_>, cap: u64) -> bool {
    let namespaces = c.group.namespaces(c.tid);
    c.process
        .credentials
        .capable_in(cap, namespaces.ipc.owner())
}

/// The time of day in seconds, which the objects' times are in.
pub(crate) fn now(c: &Context<'_>) -> i64 {
    c.host
        .clock(ClockId::Realtime)
        .map_or(0, |nanos| (nanos / 1_000_000_000) as i64)
}
