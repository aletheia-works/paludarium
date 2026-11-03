//! A thread's credentials, as Linux's `struct cred`: the real, effective,
//! saved and filesystem user and group IDs, the supplementary groups and
//! the permitted and effective capabilities, with the `set*id` system calls
//! that change them (`kernel/sys.c`) and the capability changes that follow
//! (`cap_task_fix_setuid`). Like Linux's, they belong to a thread: a raw
//! system call changes only the calling thread's, and the C library applies
//! it to every thread.
use crate::syscalls::{Context, Outcome, err, ok};
use paludarium_types::{Errno, GuestAddr};

/// Every capability, up to `CAP_LAST_CAP` (40): root's.
pub(crate) const ALL_CAPABILITIES: u64 = (1 << 41) - 1;
const CAP_SETGID: u64 = 1 << 6;
const CAP_SETUID: u64 = 1 << 7;
/// The capabilities a filesystem ID of root brings (`CAP_FS_MASK`):
/// CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
/// CAP_FSETID, CAP_LINUX_IMMUTABLE, CAP_MKNOD and CAP_MAC_OVERRIDE.
const FS_CAPABILITIES: u64 = 0x1f | 1 << 9 | 1 << 27 | 1 << 32;
/// `NGROUPS_MAX`.
const MAX_GROUPS: u64 = 65536;
/// The ID that means "unchanged", and that names no user or group.
const UNCHANGED: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    /// The supplementary groups, sorted, as `setgroups` keeps them.
    pub groups: Vec<u32>,
    pub permitted: u64,
    pub effective: u64,
    /// `PR_SET_KEEPCAPS` (`SECBIT_KEEP_CAPS`): leaving root keeps the
    /// permitted capabilities. Cleared by exec.
    pub keep_caps: bool,
}

/// Root with every capability, as the first process starts.
impl Default for Credentials {
    fn default() -> Self {
        Credentials {
            uid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: Vec::new(),
            permitted: ALL_CAPABILITIES,
            effective: ALL_CAPABILITIES,
            keep_caps: false,
        }
    }
}

impl Credentials {
    fn may_setuid(&self) -> bool {
        self.effective & CAP_SETUID != 0
    }
    fn may_setgid(&self) -> bool {
        self.effective & CAP_SETGID != 0
    }
    fn is_uid(&self, id: u32) -> bool {
        id == self.uid || id == self.euid || id == self.suid
    }
    fn is_gid(&self, id: u32) -> bool {
        id == self.gid || id == self.egid || id == self.sgid
    }

    /// `setuid`: all four user IDs with CAP_SETUID, else only the effective
    /// and filesystem ones, to the real or saved ID.
    pub(crate) fn setuid(&self, uid: u32) -> Result<Self, Errno> {
        if uid == UNCHANGED {
            return Err(Errno::EINVAL);
        }
        let mut new = self.clone();
        if self.may_setuid() {
            new.uid = uid;
            new.suid = uid;
        } else if uid != self.uid && uid != self.suid {
            return Err(Errno::EPERM);
        }
        new.euid = uid;
        new.fsuid = uid;
        Ok(new.fix_setuid(self))
    }
    /// `setreuid`: the real ID to the real or effective one, the effective
    /// ID to any of the three, or anything with CAP_SETUID; the saved ID
    /// follows the effective one when the real ID is set or the effective
    /// one leaves the real one.
    pub(crate) fn setreuid(&self, ruid: u32, euid: u32) -> Result<Self, Errno> {
        let mut new = self.clone();
        if ruid != UNCHANGED {
            new.uid = ruid;
            if ruid != self.uid && ruid != self.euid && !self.may_setuid() {
                return Err(Errno::EPERM);
            }
        }
        if euid != UNCHANGED {
            new.euid = euid;
            if !self.is_uid(euid) && !self.may_setuid() {
                return Err(Errno::EPERM);
            }
        }
        if ruid != UNCHANGED || (euid != UNCHANGED && euid != self.uid) {
            new.suid = new.euid;
        }
        new.fsuid = new.euid;
        Ok(new.fix_setuid(self))
    }
    /// `setresuid`: each ID to one of the three, or anything with
    /// CAP_SETUID. Nothing to change changes nothing.
    pub(crate) fn setresuid(&self, ruid: u32, euid: u32, suid: u32) -> Result<Self, Errno> {
        if (ruid == UNCHANGED || ruid == self.uid)
            && (euid == UNCHANGED || (euid == self.euid && euid == self.fsuid))
            && (suid == UNCHANGED || suid == self.suid)
        {
            return Ok(self.clone());
        }
        let foreign = |id: u32| id != UNCHANGED && !self.is_uid(id);
        if (foreign(ruid) || foreign(euid) || foreign(suid)) && !self.may_setuid() {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        if ruid != UNCHANGED {
            new.uid = ruid;
        }
        if euid != UNCHANGED {
            new.euid = euid;
        }
        if suid != UNCHANGED {
            new.suid = suid;
        }
        new.fsuid = new.euid;
        Ok(new.fix_setuid(self))
    }
    /// `setfsuid`: to one of the four user IDs, or anything with
    /// CAP_SETUID; `None` when it stays. An ID that names no user changes
    /// nothing.
    pub(crate) fn setfsuid(&self, fsuid: u32) -> Option<Self> {
        if fsuid == UNCHANGED || fsuid == self.fsuid || !(self.is_uid(fsuid) || self.may_setuid()) {
            return None;
        }
        let mut new = self.clone();
        new.fsuid = fsuid;
        if self.fsuid == 0 && fsuid != 0 {
            new.effective &= !FS_CAPABILITIES;
        }
        if self.fsuid != 0 && fsuid == 0 {
            new.effective |= new.permitted & FS_CAPABILITIES;
        }
        Some(new)
    }
    /// The capabilities after a change of user IDs from `old`, as Linux's
    /// `cap_emulate_setxuid`: leaving root in all three IDs drops them (but
    /// for `keep_caps`, the permitted ones), an effective ID leaving root
    /// drops the effective ones, and one coming back to it raises them.
    fn fix_setuid(mut self, old: &Self) -> Self {
        let root = |c: &Self| c.uid == 0 || c.euid == 0 || c.suid == 0;
        if root(old) && !root(&self) && !self.keep_caps {
            self.permitted = 0;
            self.effective = 0;
        }
        if old.euid == 0 && self.euid != 0 {
            self.effective = 0;
        }
        if old.euid != 0 && self.euid == 0 {
            self.effective = self.permitted;
        }
        self
    }

    /// `setgid`, as `setuid` with CAP_SETGID.
    pub(crate) fn setgid(&self, gid: u32) -> Result<Self, Errno> {
        if gid == UNCHANGED {
            return Err(Errno::EINVAL);
        }
        let mut new = self.clone();
        if self.may_setgid() {
            new.gid = gid;
            new.sgid = gid;
        } else if gid != self.gid && gid != self.sgid {
            return Err(Errno::EPERM);
        }
        new.egid = gid;
        new.fsgid = gid;
        Ok(new)
    }
    /// `setregid`, as `setreuid` with CAP_SETGID.
    pub(crate) fn setregid(&self, rgid: u32, egid: u32) -> Result<Self, Errno> {
        let mut new = self.clone();
        if rgid != UNCHANGED {
            new.gid = rgid;
            if rgid != self.gid && rgid != self.egid && !self.may_setgid() {
                return Err(Errno::EPERM);
            }
        }
        if egid != UNCHANGED {
            new.egid = egid;
            if !self.is_gid(egid) && !self.may_setgid() {
                return Err(Errno::EPERM);
            }
        }
        if rgid != UNCHANGED || (egid != UNCHANGED && egid != self.gid) {
            new.sgid = new.egid;
        }
        new.fsgid = new.egid;
        Ok(new)
    }
    /// `setresgid`, as `setresuid` with CAP_SETGID.
    pub(crate) fn setresgid(&self, rgid: u32, egid: u32, sgid: u32) -> Result<Self, Errno> {
        if (rgid == UNCHANGED || rgid == self.gid)
            && (egid == UNCHANGED || (egid == self.egid && egid == self.fsgid))
            && (sgid == UNCHANGED || sgid == self.sgid)
        {
            return Ok(self.clone());
        }
        let foreign = |id: u32| id != UNCHANGED && !self.is_gid(id);
        if (foreign(rgid) || foreign(egid) || foreign(sgid)) && !self.may_setgid() {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        if rgid != UNCHANGED {
            new.gid = rgid;
        }
        if egid != UNCHANGED {
            new.egid = egid;
        }
        if sgid != UNCHANGED {
            new.sgid = sgid;
        }
        new.fsgid = new.egid;
        Ok(new)
    }
    /// `setfsgid`, as `setfsuid` with CAP_SETGID and no capability change.
    pub(crate) fn setfsgid(&self, fsgid: u32) -> Option<Self> {
        if fsgid == UNCHANGED || fsgid == self.fsgid || !(self.is_gid(fsgid) || self.may_setgid()) {
            return None;
        }
        let mut new = self.clone();
        new.fsgid = fsgid;
        Some(new)
    }

    /// Whether a change to `new` makes the process undumpable and clears
    /// its parent-death signal, as Linux's `commit_creds` does when an
    /// effective or filesystem ID changes.
    pub(crate) fn resets_dumpable(&self, new: &Self) -> bool {
        self.euid != new.euid
            || self.egid != new.egid
            || self.fsuid != new.fsuid
            || self.fsgid != new.fsgid
    }

    /// The credentials `access` checks with (`access_override_creds`): the
    /// real IDs as the filesystem ones, and for root every permitted
    /// capability as effective, for anyone else none.
    pub(crate) fn for_access(&self) -> Self {
        let mut new = self.clone();
        new.fsuid = new.uid;
        new.fsgid = new.gid;
        new.effective = if new.uid == 0 { new.permitted } else { 0 };
        new
    }

    /// The credentials a program runs with after exec, as Linux's
    /// `cap_bprm_creds_from_file` gives them without file capabilities:
    /// the saved and filesystem IDs take the effective ones, root (by its
    /// real or effective ID) gets every permitted capability and, by its
    /// effective ID, every effective one, anyone else none, and
    /// `keep_caps` is cleared. Also returns whether the exec is secure
    /// (`AT_SECURE`): the effective IDs differ from the real ones.
    pub(crate) fn after_exec(&self) -> (Self, bool) {
        let mut new = self.clone();
        new.suid = new.euid;
        new.fsuid = new.euid;
        new.sgid = new.egid;
        new.fsgid = new.egid;
        new.keep_caps = false;
        new.permitted = if new.uid == 0 || new.euid == 0 {
            ALL_CAPABILITIES
        } else {
            0
        };
        new.effective = if new.euid == 0 { new.permitted } else { 0 };
        let secure = new.euid != new.uid || new.egid != new.gid;
        (new, secure)
    }
}

fn id(value: u64) -> u32 {
    value as u32
}

/// Makes `new` the thread's credentials, with what a change of its
/// effective or filesystem IDs brings.
fn commit(c: &mut Context<'_>, new: Credentials) {
    if c.process.credentials.resets_dumpable(&new) {
        c.processes.credentials_changed(c.process.pid);
    }
    c.process.credentials = new;
}

fn set(c: &mut Context<'_>, change: Result<Credentials, Errno>) -> Outcome {
    match change {
        Ok(new) => {
            commit(c, new);
            ok(0)
        }
        Err(e) => err(e),
    }
}

pub(crate) fn sys_getuid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.process.credentials.uid))
}
pub(crate) fn sys_geteuid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.process.credentials.euid))
}
pub(crate) fn sys_getgid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.process.credentials.gid))
}
pub(crate) fn sys_getegid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.process.credentials.egid))
}
pub(crate) fn sys_setuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c.process.credentials.setuid(id(a[0]));
    set(c, change)
}
pub(crate) fn sys_setgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c.process.credentials.setgid(id(a[0]));
    set(c, change)
}
pub(crate) fn sys_setreuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c.process.credentials.setreuid(id(a[0]), id(a[1]));
    set(c, change)
}
pub(crate) fn sys_setregid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c.process.credentials.setregid(id(a[0]), id(a[1]));
    set(c, change)
}
pub(crate) fn sys_setresuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c
        .process
        .credentials
        .setresuid(id(a[0]), id(a[1]), id(a[2]));
    set(c, change)
}
pub(crate) fn sys_setresgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = c
        .process
        .credentials
        .setresgid(id(a[0]), id(a[1]), id(a[2]));
    set(c, change)
}
/// `getresuid` and `getresgid`: the three IDs, each written in turn.
fn write_three(c: &mut Context<'_>, a: [u64; 6], ids: [u32; 3]) -> Outcome {
    for (at, value) in a.iter().zip(ids) {
        if c.mem.write(GuestAddr(*at), &value.to_le_bytes()).is_err() {
            return err(Errno::EFAULT);
        }
    }
    ok(0)
}
pub(crate) fn sys_getresuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let s = &c.process.credentials;
    let ids = [s.uid, s.euid, s.suid];
    write_three(c, a, ids)
}
pub(crate) fn sys_getresgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let s = &c.process.credentials;
    let ids = [s.gid, s.egid, s.sgid];
    write_three(c, a, ids)
}
/// `setfsuid` and `setfsgid` return the old ID whether or not it changed.
pub(crate) fn sys_setfsuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let old = c.process.credentials.fsuid;
    if let Some(new) = c.process.credentials.setfsuid(id(a[0])) {
        commit(c, new);
    }
    ok(u64::from(old))
}
pub(crate) fn sys_setfsgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let old = c.process.credentials.fsgid;
    if let Some(new) = c.process.credentials.setfsgid(id(a[0])) {
        commit(c, new);
    }
    ok(u64::from(old))
}
/// `getgroups(size, list)`: the number of groups, written to `list` unless
/// `size` is 0; EINVAL when they do not fit.
pub(crate) fn sys_getgroups(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let size = a[0] as u32 as i32;
    if size < 0 {
        return err(Errno::EINVAL);
    }
    let groups = &c.process.credentials.groups;
    if size == 0 {
        return ok(groups.len() as u64);
    }
    if groups.len() > size as usize {
        return err(Errno::EINVAL);
    }
    let bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_le_bytes()).collect();
    match c.mem.write(GuestAddr(a[1]), &bytes) {
        Ok(()) => ok(groups.len() as u64),
        Err(_) => err(Errno::EFAULT),
    }
}
/// `setgroups(size, list)`: with CAP_SETGID, at most `NGROUPS_MAX` groups,
/// none the ID that names no group; kept sorted.
pub(crate) fn sys_setgroups(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if !c.process.credentials.may_setgid() {
        return err(Errno::EPERM);
    }
    let size = u64::from(a[0] as u32);
    if size > MAX_GROUPS {
        return err(Errno::EINVAL);
    }
    // No groups read nothing, as Linux leaves the list alone then.
    let mut bytes = vec![0u8; size as usize * 4];
    if size != 0 && c.mem.read(GuestAddr(a[1]), &mut bytes).is_err() {
        return err(Errno::EFAULT);
    }
    let mut groups: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&b| u32::from_le_bytes(b))
        .collect();
    if groups.contains(&UNCHANGED) {
        return err(Errno::EINVAL);
    }
    groups.sort_unstable();
    let mut new = c.process.credentials.clone();
    new.groups = groups;
    commit(c, new);
    ok(0)
}

#[cfg(test)]
mod credentials_tests {
    use super::*;

    fn ids(c: &Credentials) -> [u32; 4] {
        [c.uid, c.euid, c.suid, c.fsuid]
    }

    #[test]
    fn root_sets_every_user_id_and_loses_its_capabilities_leaving_root() {
        let root = Credentials::default();
        let user = root.setresuid(1000, 1001, 1002).unwrap();
        assert_eq!(ids(&user), [1000, 1001, 1002, 1001]);
        assert_eq!((user.permitted, user.effective), (0, 0));
        assert_eq!(user.setuid(0), Err(Errno::EPERM));
        // An unprivileged setuid moves only the effective and filesystem IDs,
        // to the real or saved one.
        let saved = user.setuid(1002).unwrap();
        assert_eq!(ids(&saved), [1000, 1002, 1002, 1002]);
        assert_eq!(
            user.setresuid(1003, UNCHANGED, UNCHANGED),
            Err(Errno::EPERM)
        );
        assert_eq!(root.setuid(UNCHANGED), Err(Errno::EINVAL));
    }

    #[test]
    fn an_effective_id_leaving_root_and_coming_back_drops_and_raises_capabilities() {
        let root = Credentials::default();
        let away = root.setresuid(UNCHANGED, 1000, UNCHANGED).unwrap();
        assert_eq!((away.permitted, away.effective), (ALL_CAPABILITIES, 0));
        let back = away.setreuid(UNCHANGED, 0).unwrap();
        assert_eq!(back.effective, ALL_CAPABILITIES);
        // setreuid with an effective ID other than the real one moves the
        // saved ID too.
        let moved = root.setreuid(UNCHANGED, 5).unwrap();
        assert_eq!(ids(&moved), [0, 5, 5, 5]);
    }

    #[test]
    fn keep_caps_keeps_the_permitted_capabilities() {
        let root = Credentials {
            keep_caps: true,
            ..Credentials::default()
        };
        let user = root.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!((user.permitted, user.effective), (ALL_CAPABILITIES, 0));
        let (exec, secure) = user.after_exec();
        assert_eq!((exec.permitted, exec.keep_caps, secure), (0, false, false));
    }

    #[test]
    fn a_filesystem_id_leaving_root_drops_the_filesystem_capabilities() {
        let root = Credentials::default();
        let away = root.setfsuid(1000).unwrap();
        assert_eq!(away.effective, ALL_CAPABILITIES & !FS_CAPABILITIES);
        assert_eq!(away.setfsuid(0).unwrap().effective, ALL_CAPABILITIES);
        let user = root.setresuid(1, 1, 1).unwrap();
        assert_eq!(user.setfsuid(2), None);
        assert_eq!(root.setfsuid(UNCHANGED), None);
    }

    #[test]
    fn exec_takes_the_effective_ids_as_saved_and_reports_a_secure_exec() {
        let root = Credentials::default();
        let user = root.setresuid(1000, 1001, 1002).unwrap();
        let (exec, secure) = user.after_exec();
        assert_eq!(ids(&exec), [1000, 1001, 1001, 1001]);
        assert!(secure);
        let (exec, secure) = root.setresuid(1000, 0, 0).unwrap().after_exec();
        assert_eq!(
            (exec.permitted, exec.effective, secure),
            (ALL_CAPABILITIES, ALL_CAPABILITIES, true)
        );
    }

    #[test]
    fn group_ids_follow_the_same_rules_with_cap_setgid() {
        let root = Credentials::default();
        let groups = root.setresgid(100, 101, 102).unwrap();
        assert_eq!(
            [groups.gid, groups.egid, groups.sgid, groups.fsgid],
            [100, 101, 102, 101]
        );
        let user = groups.setresuid(1, 1, 1).unwrap();
        assert_eq!(user.setgid(102).unwrap().egid, 102);
        assert_eq!(user.setgid(5), Err(Errno::EPERM));
        assert!(root.resets_dumpable(&groups));
        assert!(!root.resets_dumpable(&root.setresuid(UNCHANGED, UNCHANGED, UNCHANGED).unwrap()));
    }
}
