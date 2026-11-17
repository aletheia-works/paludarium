//! A thread's credentials, as Linux's `struct cred`: the real, effective,
//! saved and filesystem user and group IDs, the supplementary groups and
//! the capability sets and securebits, with the `set*id` system calls
//! that change them (`kernel/sys.c`) and the capability changes that follow
//! (`cap_task_fix_setuid`). Like Linux's, they belong to a thread: a raw
//! system call changes only the calling thread's, and the C library applies
//! it to every thread.
use crate::syscalls::{Context, Outcome, err, ok};
use paludarium_host::FileStat;
use paludarium_types::{Errno, GuestAddr};

/// Every capability, up to `CAP_LAST_CAP` (40): root's.
pub(crate) const ALL_CAPABILITIES: u64 = (1 << 41) - 1;
const CAP_KILL: u64 = 1 << 5;
const CAP_SETGID: u64 = 1 << 6;
const CAP_SETUID: u64 = 1 << 7;
const CAP_SETPCAP: u64 = 1 << 8;
/// `CAP_LAST_CAP`, the highest capability `prctl` takes.
const CAP_LAST_CAP: u64 = 40;
const CAP_SYS_RAWIO: u64 = 1 << 17;
const CAP_SYS_CHROOT: u64 = 1 << 18;
pub(crate) const CAP_SYS_PTRACE: u64 = 1 << 19;
const CAP_SYS_PACCT: u64 = 1 << 20;
pub(crate) const CAP_SYS_ADMIN: u64 = 1 << 21;
pub(crate) const CAP_SYS_NICE: u64 = 1 << 23;
pub(crate) const CAP_SYS_RESOURCE: u64 = 1 << 24;
const CAP_SYS_TTY_CONFIG: u64 = 1 << 26;
pub(crate) const CAP_WAKE_ALARM: u64 = 1 << 35;
pub(crate) const CAP_CHECKPOINT_RESTORE: u64 = 1 << 40;
/// The capabilities a filesystem ID of root brings (`CAP_FS_MASK`):
/// CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
/// CAP_FSETID, CAP_LINUX_IMMUTABLE, CAP_MKNOD and CAP_MAC_OVERRIDE.
const FS_CAPABILITIES: u64 = 0x1f | 1 << 9 | 1 << 27 | 1 << 32;
const SET_USER_ID: u32 = 0o4000;
const SET_GROUP_ID: u32 = 0o2000;
const GROUP_EXECUTE: u32 = 0o010;
/// `NGROUPS_MAX`.
const MAX_GROUPS: u64 = 65536;
/// The ID that means "unchanged", and that names no user or group.
const UNCHANGED: u32 = u32::MAX;
/// `capget` and `capset`'s header versions: one 32-bit set of each kind, then
/// two.
const CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// The securebits (`include/uapi/linux/securebits.h`): each bit, then the
/// lock above it that keeps it as it is.
const SECBIT_NOROOT: u32 = 1 << 0;
const SECBIT_NO_SETUID_FIXUP: u32 = 1 << 2;
const SECBIT_KEEP_CAPS: u32 = 1 << 4;
const SECBIT_KEEP_CAPS_LOCKED: u32 = 1 << 5;
const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
/// `SECURE_ALL_BITS` (with `SECBIT_EXEC_RESTRICT_FILE` and
/// `SECBIT_EXEC_DENY_INTERACTIVE`, which only user space acts on), and
/// `SECURE_ALL_LOCKS`.
const SECURE_ALL_BITS: u64 = 0x555;
const SECURE_ALL_LOCKS: u64 = SECURE_ALL_BITS << 1;
/// `SECURE_ALL_UNPRIVILEGED`: the bits a thread without CAP_SETPCAP may
/// change, the two of exec's checks in user space.
const SECURE_ALL_UNPRIVILEGED: u64 = 0x500;
/// The revisions of file capabilities (`VFS_CAP_REVISION_*`), the mask of
/// their magic that names one, and its effective flag.
const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 1;

/// What acting on another thread looks at in credentials, which another
/// process can read ([`crate::ThreadGroup::task_ids`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TaskIds {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// The user namespace its capabilities count in.
    pub user: crate::users::UserNs,
    /// The sets `capget` reads of another thread.
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    /// The thread's Landlock domain, which scopes the signals it may send
    /// and be sent.
    pub landlock: crate::landlock::Landlock,
}

impl TaskIds {
    /// Whether the thread has `cap` in the first user namespace (Linux's
    /// `capable`).
    pub(crate) fn capable(&self, cap: u64) -> bool {
        crate::users::first().grants(&self.user, self.euid, self.effective, cap)
    }
    /// Whether it has `cap` in the user namespace of `target`'s
    /// credentials (`ns_capable(tcred->user_ns, cap)`).
    fn capable_over(&self, cap: u64, target: &Self) -> bool {
        target
            .user
            .grants(&self.user, self.euid, self.effective, cap)
    }
    /// Linux's `kill_ok_by_cred`: the sender's real or effective user ID is
    /// the target's real or saved one, or the sender has CAP_KILL in the
    /// target's user namespace.
    pub(crate) fn may_signal(&self, target: &Self) -> bool {
        self.capable_over(CAP_KILL, target)
            || self.euid == target.suid
            || self.euid == target.uid
            || self.uid == target.suid
            || self.uid == target.uid
    }
    /// Linux's `check_prlimit_permission`, to read or set another thread's
    /// limits: the sender's real IDs are all of the target's IDs, or the
    /// sender has CAP_SYS_RESOURCE in the target's user namespace.
    pub(crate) fn may_prlimit(&self, target: &Self) -> bool {
        self.capable_over(CAP_SYS_RESOURCE, target)
            || (self.uid == target.uid
                && self.uid == target.euid
                && self.uid == target.suid
                && self.gid == target.gid
                && self.gid == target.egid
                && self.gid == target.sgid)
    }
    /// Linux's `set_one_prio_perm`: the sender's effective user ID is the
    /// target's real or effective one, or the sender has CAP_SYS_NICE in
    /// the target's user namespace.
    pub(crate) fn may_set_priority(&self, target: &Self) -> bool {
        self.capable_over(CAP_SYS_NICE, target)
            || self.euid == target.uid
            || self.euid == target.euid
    }
}

/// Root's, as a thread has until its credentials change.
impl Default for TaskIds {
    fn default() -> Self {
        Credentials::default().task_ids()
    }
}

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
    /// What a program may take from a file's inheritable capabilities. Set
    /// only by `capset`, and kept by `set*id` and exec.
    pub inheritable: u64,
    /// The bounding set, which limits what exec takes from a file's
    /// permitted capabilities and what `capset` may add to the inheritable
    /// set; `PR_CAPBSET_DROP` lowers it, and nothing raises it.
    pub bounding: u64,
    /// The ambient set, always within the permitted and inheritable ones
    /// (`PR_CAP_AMBIENT`), which exec of a program without file
    /// capabilities or set-ID bits keeps as permitted and effective.
    pub ambient: u64,
    /// The securebits (`PR_SET_SECUREBITS`; `PR_SET_KEEPCAPS` sets
    /// `SECBIT_KEEP_CAPS`, which exec clears).
    pub securebits: u32,
    /// The Landlock domain ([`crate::landlock`]), which exec keeps.
    pub landlock: crate::landlock::Landlock,
    /// The last `LANDLOCK_RESTRICT_SELF_TSYNC` of its process this thread has
    /// taken ([`crate::ThreadGroup::sync_landlock`]).
    pub landlock_sync: u64,
    /// The user namespace the capabilities count in, and the IDs a system
    /// call takes and gives are in; the IDs here are kernel IDs, those of
    /// the first user namespace ([`crate::users`]).
    pub(crate) user: crate::users::UserNs,
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
            inheritable: 0,
            bounding: ALL_CAPABILITIES,
            ambient: 0,
            securebits: 0,
            landlock: crate::landlock::Landlock::default(),
            landlock_sync: 0,
            user: crate::users::UserNs::default(),
        }
    }
}

impl Credentials {
    pub(crate) fn task_ids(&self) -> TaskIds {
        TaskIds {
            uid: self.uid,
            euid: self.euid,
            suid: self.suid,
            gid: self.gid,
            egid: self.egid,
            sgid: self.sgid,
            user: self.user.clone(),
            effective: self.effective,
            permitted: self.permitted,
            inheritable: self.inheritable,
            landlock: self.landlock.clone(),
        }
    }
    /// `capset`, as Linux's `cap_capset`: a new inheritable set within the
    /// old inheritable and permitted ones unless the thread has CAP_SETPCAP,
    /// and within the old inheritable and bounding ones whatever it has,
    /// permitted within the old permitted, and effective within the new
    /// permitted (EPERM). The ambient set keeps only what is still both
    /// permitted and inheritable.
    pub(crate) fn capset(
        &self,
        effective: u64,
        permitted: u64,
        inheritable: u64,
    ) -> Result<Self, Errno> {
        let capped = self.effective & CAP_SETPCAP == 0;
        if (capped && inheritable & !(self.inheritable | self.permitted) != 0)
            || inheritable & !(self.inheritable | self.bounding) != 0
            || permitted & !self.permitted != 0
            || effective & !permitted != 0
        {
            return Err(Errno::EPERM);
        }
        Ok(Self {
            effective,
            permitted,
            inheritable,
            ambient: self.ambient & permitted & inheritable,
            ..self.clone()
        })
    }
    /// The credentials a thread takes in user namespace `user`, which it
    /// made or entered (`set_cred_user_ns`): every capability there,
    /// permitted, effective and bounding, none inheritable or ambient, and
    /// no securebits.
    pub(crate) fn in_user_namespace(&self, user: crate::users::UserNs) -> Self {
        Self {
            user,
            permitted: ALL_CAPABILITIES,
            effective: ALL_CAPABILITIES,
            inheritable: 0,
            bounding: ALL_CAPABILITIES,
            ambient: 0,
            securebits: 0,
            ..self.clone()
        }
    }
    fn secure(&self, bit: u32) -> bool {
        self.securebits & bit != 0
    }
    /// Whether a task with these credentials may read the details of a task
    /// of another process with `target`'s, as Linux's `__ptrace_may_access`
    /// in read mode decides: `CAP_SYS_PTRACE` in the target's user
    /// namespace, or every user and group ID of a dumpable target equal to
    /// the reader's filesystem ones, or with `real`
    /// (`PTRACE_MODE_REALCREDS`) its real ones. The capability module then
    /// asks the same capability again, or a reader in the target's user
    /// namespace whose permitted capabilities (with `real`; its effective
    /// ones for `PTRACE_MODE_FSCREDS`) cover the target's permitted ones
    /// (`cap_ptrace_access_check`), and Landlock keeps a reader in a domain
    /// from a task outside it (`hook_ptrace_access_check`).
    pub(crate) fn may_read_task(&self, target: &Credentials, dumpable: bool, real: bool) -> bool {
        self.may_read_ids(&target.task_ids(), dumpable, real)
    }
    /// [`Self::may_read_task`] of a task with the IDs and sets `target`.
    pub(crate) fn may_read_ids(&self, target: &TaskIds, dumpable: bool, real: bool) -> bool {
        let (uid, gid, caps) = if real {
            (self.uid, self.gid, self.permitted)
        } else {
            (self.fsuid, self.fsgid, self.effective)
        };
        let tracer = self.capable_in(CAP_SYS_PTRACE, &target.user);
        (tracer
            || dumpable
                && [target.uid, target.euid, target.suid] == [uid; 3]
                && [target.gid, target.egid, target.sgid] == [gid; 3]
                && self.user == target.user
                && target.permitted & !caps == 0)
            && crate::landlock::may_trace(&self.landlock, &target.landlock)
    }
    /// Whether its user namespace is `ns` or one below it
    /// (`current_in_userns`).
    pub(crate) fn in_user_namespace_of(&self, ns: &crate::namespaces::Namespace) -> bool {
        let mut at: &crate::namespaces::Namespace = &self.user.0;
        loop {
            if std::ptr::eq(at, ns) {
                return true;
            }
            let up = at.owner();
            if std::ptr::eq(up, at) {
                return false;
            }
            at = up;
        }
    }
    /// Whether the thread has `cap` in user namespace `ns`, as Linux's
    /// `ns_capable` ([`crate::namespaces::Namespace::grants`]).
    pub(crate) fn capable_in(&self, cap: u64, ns: &crate::namespaces::Namespace) -> bool {
        ns.grants(&self.user, self.euid, self.effective, cap)
    }
    /// Whether it has `cap` in the first user namespace (`capable`), as a
    /// capability over the whole machine asks.
    pub(crate) fn capable(&self, cap: u64) -> bool {
        self.capable_in(cap, crate::users::first())
    }
    /// The kernel ID of root in the thread's user namespace, which the
    /// capability rules of `set*id` and exec take as root.
    fn root_uid(&self) -> Option<u32> {
        self.user.kernel_of(crate::users::Ids::User, 0)
    }
    fn is_root(&self, uid: u32) -> bool {
        self.root_uid() == Some(uid)
    }
    /// CAP_SYS_TTY_CONFIG, which `vhangup` asks for.
    pub(crate) fn may_configure_terminals(&self) -> bool {
        self.capable(CAP_SYS_TTY_CONFIG)
    }
    /// CAP_SYS_RAWIO, which a mapping below `mmap_min_addr` needs (Linux's
    /// `cap_mmap_addr`).
    pub(crate) fn may_map_low(&self) -> bool {
        self.capable(CAP_SYS_RAWIO)
    }
    /// CAP_SYS_PACCT over the machine, which `acct` asks for.
    pub(crate) fn may_account(&self) -> bool {
        self.capable(CAP_SYS_PACCT)
    }
    /// CAP_SYS_ADMIN over the machine, which `trusted.*` and `security.*`
    /// attributes and a terminal's `TIOCEXCL` and `TIOCSCTTY` ask for.
    pub(crate) fn may_administer(&self) -> bool {
        self.capable(CAP_SYS_ADMIN)
    }
    /// CAP_SYS_CHROOT in the thread's own user namespace, which `chroot`
    /// asks for.
    pub(crate) fn may_chroot(&self) -> bool {
        self.effective & CAP_SYS_CHROOT != 0
    }
    /// CAP_SYS_ADMIN in the thread's own user namespace, which new
    /// namespaces ask for.
    pub(crate) fn administers_own(&self) -> bool {
        self.effective & CAP_SYS_ADMIN != 0
    }
    /// Linux's `scm_check_creds`, for what `SCM_CREDENTIALS` may say: the
    /// caller's own process, or CAP_SYS_ADMIN over its PID namespace
    /// (`pid_owner`, the user namespace that owns it); one of its real,
    /// effective and saved user IDs, or CAP_SETUID; and one of its group
    /// IDs, or CAP_SETGID. The IDs are kernel IDs.
    pub(crate) fn may_send_credentials(
        &self,
        own_process: bool,
        pid_owner: &crate::namespaces::Namespace,
        uid: u32,
        gid: u32,
    ) -> bool {
        (own_process || self.capable_in(CAP_SYS_ADMIN, pid_owner))
            && (uid == self.uid || uid == self.euid || uid == self.suid || self.may_setuid())
            && (gid == self.gid || gid == self.egid || gid == self.sgid || self.may_setgid())
    }
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
        if self.secure(SECBIT_NO_SETUID_FIXUP) {
            return Some(new);
        }
        if self.is_root(self.fsuid) && !self.is_root(fsuid) {
            new.effective &= !FS_CAPABILITIES;
        }
        if !self.is_root(self.fsuid) && self.is_root(fsuid) {
            new.effective |= new.permitted & FS_CAPABILITIES;
        }
        Some(new)
    }
    /// The capabilities after a change of user IDs from `old`, as Linux's
    /// `cap_emulate_setxuid`, unless `SECBIT_NO_SETUID_FIXUP`: leaving root
    /// in all three IDs drops them (but for `SECBIT_KEEP_CAPS`, the
    /// permitted ones) and the ambient ones, an effective ID leaving root
    /// drops the effective ones, and one coming back to it raises them.
    fn fix_setuid(mut self, old: &Self) -> Self {
        if old.secure(SECBIT_NO_SETUID_FIXUP) {
            return self;
        }
        let root = |c: &Self| c.is_root(c.uid) || c.is_root(c.euid) || c.is_root(c.suid);
        if root(old) && !root(&self) {
            if !old.secure(SECBIT_KEEP_CAPS) {
                self.permitted = 0;
                self.effective = 0;
            }
            self.ambient = 0;
        }
        if old.is_root(old.euid) && !self.is_root(self.euid) {
            self.effective = 0;
        }
        if !old.is_root(old.euid) && self.is_root(self.euid) {
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
        new.effective = if new.is_root(new.uid) {
            new.permitted
        } else {
            0
        };
        new
    }

    /// The credentials a program runs with after exec from `program`, as
    /// Linux's `bprm_fill_uid` and `cap_bprm_creds_from_file` give them, with
    /// `capabilities` the value of its `security.capability` attribute:
    /// - **IDs:** a set-user-ID program's owner becomes the effective user
    ///   ID, and a set-group-ID one's group (when the group may execute it)
    ///   the effective group ID, unless `no_new_privs`.
    /// - **Permitted:** the file's permitted capabilities within the bounding
    ///   set, and its inheritable ones within the thread's
    ///   ([`Self::file_capabilities`]). Unless `SECBIT_NOROOT`, root (by its
    ///   real or effective ID) gets the bounding and inheritable sets instead,
    ///   but not a set-user-ID root program with file capabilities that
    ///   another user runs. A program whose effective flag is set and that
    ///   would not get all its permitted capabilities is `EPERM`.
    /// - **`no_new_privs`:** an exec that would change the effective user ID,
    ///   give an effective group ID the thread is not in (by its filesystem
    ///   or a supplementary group) or gain capabilities instead takes the real
    ///   IDs as effective and keeps no more capabilities than it had.
    /// - **Ambient:** file capabilities or such a change of IDs clear the
    ///   ambient set; what stays of it is permitted too.
    /// - **Effective:** every permitted capability with the file's effective
    ///   flag, or for root by its effective ID; otherwise the ambient set.
    ///
    /// The saved and filesystem IDs take the effective ones, and
    /// `SECBIT_KEEP_CAPS` is cleared. Also returns whether the exec is secure
    /// (`AT_SECURE`): it changes the effective IDs, they differ from the real
    /// ones before it, or a user other than root takes an effective flag or
    /// permitted capabilities beyond the ambient ones.
    pub(crate) fn after_exec(
        &self,
        program: Option<&FileStat>,
        capabilities: Option<&[u8]>,
        no_new_privs: bool,
    ) -> Result<(Self, bool), Errno> {
        let mut new = self.clone();
        // A program whose owner or group the user namespace does not map
        // changes no ID (`bprm_fill_uid`).
        let mapped = |program: &&FileStat| {
            self.user
                .id_of(crate::users::Ids::User, program.uid)
                .is_some()
                && self
                    .user
                    .id_of(crate::users::Ids::Group, program.gid)
                    .is_some()
        };
        if let Some(program) = program.filter(|_| !no_new_privs).filter(mapped) {
            if program.mode & SET_USER_ID != 0 {
                new.euid = program.uid;
            }
            if program.mode & (SET_GROUP_ID | GROUP_EXECUTE) == SET_GROUP_ID | GROUP_EXECUTE {
                new.egid = program.gid;
            }
        }
        // `get_file_caps`.
        let file = match capabilities {
            Some(value) => self.file_capabilities(value)?,
            None => None,
        };
        let mut effective = false;
        new.permitted = 0;
        if let Some(file) = &file {
            effective = file.effective;
            new.permitted = self.bounding & file.permitted | self.inheritable & file.inheritable;
            if effective && file.permitted & !new.permitted != 0 {
                return Err(Errno::EPERM);
            }
        }
        // `handle_privileged_root`.
        let set_user_id_root = new.is_root(new.euid) && !new.is_root(new.uid);
        if !self.secure(SECBIT_NOROOT) && !(file.is_some() && set_user_id_root) {
            if new.is_root(new.uid) || new.is_root(new.euid) {
                new.permitted = self.bounding | self.inheritable;
            }
            effective |= new.is_root(new.euid);
        }
        let changed =
            new.euid != self.euid || (new.egid != self.fsgid && !self.groups.contains(&new.egid));
        if no_new_privs && (changed || new.permitted & !self.permitted != 0) {
            new.euid = new.uid;
            new.egid = new.gid;
            new.permitted &= self.permitted;
        }
        new.suid = new.euid;
        new.fsuid = new.euid;
        new.sgid = new.egid;
        new.fsgid = new.egid;
        if file.is_some() || changed {
            new.ambient = 0;
        }
        new.permitted |= new.ambient;
        new.effective = if effective {
            new.permitted
        } else {
            new.ambient
        };
        new.securebits &= !SECBIT_KEEP_CAPS;
        let secure = changed
            || new.euid != self.uid
            || new.egid != self.gid
            || (!new.is_root(new.uid) && (effective || new.permitted & !new.ambient != 0));
        Ok((new, secure))
    }

    /// The file capabilities of `value`, a `security.capability` attribute,
    /// as Linux's `get_vfs_caps_from_disk` reads them for exec: a revision
    /// 1 (12 bytes), 2 (20 bytes) or 3 (24 bytes) value, or `EINVAL`. They
    /// count only when the root they name (a revision 3 one's own, or root
    /// of the first namespace) is root in the thread's user namespace or one
    /// it is nested in.
    fn file_capabilities(&self, value: &[u8]) -> Result<Option<FileCapabilities>, Errno> {
        let word = |at: usize| {
            u32::from_le_bytes([value[at], value[at + 1], value[at + 2], value[at + 3]])
        };
        if value.len() < 4 {
            return Err(Errno::EINVAL);
        }
        let magic = word(0);
        let revision = magic & VFS_CAP_REVISION_MASK;
        let size = match revision {
            VFS_CAP_REVISION_1 => 12,
            VFS_CAP_REVISION_2 => 20,
            VFS_CAP_REVISION_3 => 24,
            _ => return Err(Errno::EINVAL),
        };
        if value.len() != size {
            return Err(Errno::EINVAL);
        }
        let root = if revision == VFS_CAP_REVISION_3 {
            word(20)
        } else {
            0
        };
        // -1 names no user (`make_kuid`).
        if root == UNCHANGED || !self.user.root_here_or_above(root) {
            return Ok(None);
        }
        let (mut permitted, mut inheritable) = (u64::from(word(4)), u64::from(word(8)));
        if revision != VFS_CAP_REVISION_1 {
            permitted |= u64::from(word(12)) << 32;
            inheritable |= u64::from(word(16)) << 32;
        }
        Ok(Some(FileCapabilities {
            permitted: permitted & ALL_CAPABILITIES,
            inheritable: inheritable & ALL_CAPABILITIES,
            effective: magic & VFS_CAP_FLAGS_EFFECTIVE != 0,
        }))
    }

    /// The `prctl` options of the capability module (`cap_task_prctl`),
    /// which change only the calling thread's credentials, or `None` for
    /// another option:
    /// - `PR_GET_KEEPCAPS` and `PR_SET_KEEPCAPS` (0 or 1, `EINVAL`; `EPERM`
    ///   once `SECBIT_KEEP_CAPS_LOCKED` is set);
    /// - `PR_CAPBSET_READ` and `PR_CAPBSET_DROP` (`EPERM` without
    ///   CAP_SETPCAP, then `EINVAL` past `CAP_LAST_CAP`);
    /// - `PR_GET_SECUREBITS` and `PR_SET_SECUREBITS`, which changes no
    ///   locked bit, unlocks nothing and sets no unknown bit, and without
    ///   CAP_SETPCAP must change something and only the bits user space acts
    ///   on (`EPERM`);
    /// - `PR_CAP_AMBIENT`'s `IS_SET`, `RAISE` (of a capability both
    ///   permitted and inheritable, unless `SECBIT_NO_CAP_AMBIENT_RAISE`:
    ///   `EPERM`), `LOWER` and `CLEAR_ALL`, whose unused arguments must be
    ///   0 (`EINVAL`).
    pub(crate) fn prctl(&mut self, a: [u64; 6]) -> Option<Result<u64, Errno>> {
        let [option, arg2, arg3, arg4, arg5, _] = a;
        let setpcap = self.effective & CAP_SETPCAP != 0;
        let valid = |cap: u64| cap <= CAP_LAST_CAP;
        Some(match option {
            // PR_GET_KEEPCAPS, PR_SET_KEEPCAPS
            7 => Ok(u64::from(self.secure(SECBIT_KEEP_CAPS))),
            8 if arg2 > 1 => Err(Errno::EINVAL),
            8 if self.secure(SECBIT_KEEP_CAPS_LOCKED) => Err(Errno::EPERM),
            8 => {
                self.securebits = self.securebits & !SECBIT_KEEP_CAPS
                    | if arg2 == 1 { SECBIT_KEEP_CAPS } else { 0 };
                Ok(0)
            }
            // PR_CAPBSET_READ, PR_CAPBSET_DROP
            23 if !valid(arg2) => Err(Errno::EINVAL),
            23 => Ok(self.bounding >> arg2 & 1),
            24 if !setpcap => Err(Errno::EPERM),
            24 if !valid(arg2) => Err(Errno::EINVAL),
            24 => {
                self.bounding &= !(1 << arg2);
                Ok(0)
            }
            // PR_GET_SECUREBITS, PR_SET_SECUREBITS
            27 => Ok(u64::from(self.securebits)),
            28 => {
                let old = u64::from(self.securebits);
                let changed = old ^ arg2;
                if (old & SECURE_ALL_LOCKS) >> 1 & changed != 0
                    || old & SECURE_ALL_LOCKS & !arg2 != 0
                    || arg2 & !(SECURE_ALL_LOCKS | SECURE_ALL_BITS) != 0
                    || (!setpcap
                        && (changed == 0
                            || changed & !(SECURE_ALL_UNPRIVILEGED | SECURE_ALL_UNPRIVILEGED << 1)
                                != 0))
                {
                    return Some(Err(Errno::EPERM));
                }
                self.securebits = arg2 as u32;
                Ok(0)
            }
            // PR_CAP_AMBIENT: IS_SET (1), RAISE (2), LOWER (3), CLEAR_ALL (4)
            47 if arg2 == 4 && arg3 | arg4 | arg5 != 0 => Err(Errno::EINVAL),
            47 if arg2 == 4 => {
                self.ambient = 0;
                Ok(0)
            }
            47 if !valid(arg3) || arg4 | arg5 != 0 => Err(Errno::EINVAL),
            47 if arg2 == 1 => Ok(self.ambient >> arg3 & 1),
            47 if arg2 == 2 => {
                let cap = 1 << arg3;
                if self.permitted & cap == 0
                    || self.inheritable & cap == 0
                    || self.secure(SECBIT_NO_CAP_AMBIENT_RAISE)
                {
                    return Some(Err(Errno::EPERM));
                }
                self.ambient |= cap;
                Ok(0)
            }
            47 if arg2 == 3 => {
                self.ambient &= !(1 << arg3);
                Ok(0)
            }
            47 => Err(Errno::EINVAL),
            _ => return None,
        })
    }
}

/// What a program's file capabilities give (`struct cpu_vfs_cap_data`).
struct FileCapabilities {
    permitted: u64,
    inheritable: u64,
    effective: bool,
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
    c.group.set_task_ids(c.tid, new.task_ids());
    c.group
        .keyrings(c.tid)
        .follow_ids(&c.process.credentials, &new);
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

impl Context<'_> {
    /// User ID `kernel` as the caller's user namespace shows it.
    pub(crate) fn shown_uid(&self, kernel: u32) -> u32 {
        self.process
            .credentials
            .user
            .shown(crate::users::Ids::User, kernel)
    }
    /// Group ID `kernel` as the caller's user namespace shows it.
    pub(crate) fn shown_gid(&self, kernel: u32) -> u32 {
        self.process
            .credentials
            .user
            .shown(crate::users::Ids::Group, kernel)
    }
}
/// The kernel ID a `set*id` argument names in the caller's user namespace:
/// `-1` stays "unchanged", and an ID the namespace does not map is
/// `EINVAL` (`make_kuid`, `uid_valid`).
fn kernel_id(c: &Context<'_>, ids: crate::users::Ids, value: u64) -> Result<u32, Errno> {
    match id(value) {
        UNCHANGED => Ok(UNCHANGED),
        id => c
            .process
            .credentials
            .user
            .kernel_of(ids, id)
            .ok_or(Errno::EINVAL),
    }
}
fn uids<const N: usize>(c: &Context<'_>, a: [u64; 6]) -> Result<[u32; N], Errno> {
    let mut ids = [0; N];
    for (slot, &value) in ids.iter_mut().zip(&a) {
        *slot = kernel_id(c, crate::users::Ids::User, value)?;
    }
    Ok(ids)
}
fn gids<const N: usize>(c: &Context<'_>, a: [u64; 6]) -> Result<[u32; N], Errno> {
    let mut ids = [0; N];
    for (slot, &value) in ids.iter_mut().zip(&a) {
        *slot = kernel_id(c, crate::users::Ids::Group, value)?;
    }
    Ok(ids)
}
pub(crate) fn sys_getuid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.shown_uid(c.process.credentials.uid)))
}
pub(crate) fn sys_geteuid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.shown_uid(c.process.credentials.euid)))
}
pub(crate) fn sys_getgid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.shown_gid(c.process.credentials.gid)))
}
pub(crate) fn sys_getegid(c: &mut Context<'_>, _a: [u64; 6]) -> Outcome {
    ok(u64::from(c.shown_gid(c.process.credentials.egid)))
}
pub(crate) fn sys_setuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = uids::<1>(c, a).and_then(|[uid]| c.process.credentials.setuid(uid));
    set(c, change)
}
pub(crate) fn sys_setgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = gids::<1>(c, a).and_then(|[gid]| c.process.credentials.setgid(gid));
    set(c, change)
}
pub(crate) fn sys_setreuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = uids::<2>(c, a).and_then(|[r, e]| c.process.credentials.setreuid(r, e));
    set(c, change)
}
pub(crate) fn sys_setregid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = gids::<2>(c, a).and_then(|[r, e]| c.process.credentials.setregid(r, e));
    set(c, change)
}
pub(crate) fn sys_setresuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = uids::<3>(c, a).and_then(|[r, e, s]| c.process.credentials.setresuid(r, e, s));
    set(c, change)
}
pub(crate) fn sys_setresgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let change = gids::<3>(c, a).and_then(|[r, e, s]| c.process.credentials.setresgid(r, e, s));
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
    let ids = [s.uid, s.euid, s.suid].map(|id| c.shown_uid(id));
    write_three(c, a, ids)
}
pub(crate) fn sys_getresgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let s = &c.process.credentials;
    let ids = [s.gid, s.egid, s.sgid].map(|id| c.shown_gid(id));
    write_three(c, a, ids)
}
/// `setfsuid` and `setfsgid` return the old ID whether or not it changed;
/// one the user namespace does not map changes nothing.
pub(crate) fn sys_setfsuid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let old = c.shown_uid(c.process.credentials.fsuid);
    if let Ok([uid]) = uids::<1>(c, a)
        && let Some(new) = c.process.credentials.setfsuid(uid)
    {
        commit(c, new);
    }
    ok(u64::from(old))
}
pub(crate) fn sys_setfsgid(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let old = c.shown_gid(c.process.credentials.fsgid);
    if let Ok([gid]) = gids::<1>(c, a)
        && let Some(new) = c.process.credentials.setfsgid(gid)
    {
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
    let bytes: Vec<u8> = groups
        .iter()
        .flat_map(|&g| c.shown_gid(g).to_le_bytes())
        .collect();
    match c.mem.write(GuestAddr(a[1]), &bytes) {
        Ok(()) => ok(groups.len() as u64),
        Err(_) => err(Errno::EFAULT),
    }
}
/// Linux's `cap_validate_magic`: how many 32-bit sets the header's version
/// has, or for another version writes back the newest and is EINVAL.
fn capability_sets(c: &Context<'_>, header: u64) -> Result<usize, Errno> {
    let mut version = [0; 4];
    c.mem
        .read(GuestAddr(header), &mut version)
        .map_err(|_| Errno::EFAULT)?;
    match u32::from_le_bytes(version) {
        CAPABILITY_VERSION_1 => Ok(1),
        CAPABILITY_VERSION_2 | CAPABILITY_VERSION_3 => Ok(2),
        _ => {
            c.mem
                .write(GuestAddr(header), &CAPABILITY_VERSION_3.to_le_bytes())
                .map_err(|_| Errno::EFAULT)?;
            Err(Errno::EINVAL)
        }
    }
}
/// The process ID of a `capget` or `capset` header.
fn capability_pid(c: &Context<'_>, header: u64) -> Result<i32, Errno> {
    let mut pid = [0; 4];
    c.mem
        .read(GuestAddr(header + 4), &mut pid)
        .map_err(|_| Errno::EFAULT)?;
    Ok(i32::from_le_bytes(pid))
}
/// `capget(header, data)`, as Linux's: no `data` only asks for the version,
/// so a version it does not know then succeeds. Each set's low 32 bits come
/// in the first `struct __user_cap_data_struct`, its high ones in the second;
/// the first version has no second. Any thread may be read.
pub(crate) fn sys_capget(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let [header, data, ..] = a;
    let sets = match capability_sets(c, header) {
        Ok(_) if data == 0 => return ok(0),
        Err(e) if data == 0 && e == Errno::EINVAL => return ok(0),
        Err(e) => return err(e),
        Ok(sets) => sets,
    };
    let pid = match capability_pid(c, header) {
        Ok(pid) if pid < 0 => return err(Errno::EINVAL),
        Ok(pid) => pid.cast_unsigned(),
        Err(e) => return err(e),
    };
    // The PID as the caller's PID namespace numbers it.
    let pid = if pid == 0 { 0 } else { c.named(pid) };
    let ids = if pid == 0 || pid == c.tid {
        c.process.credentials.task_ids()
    } else {
        match c.processes.task_ids(pid) {
            Some(ids) => ids,
            None => return err(Errno(3)), // ESRCH
        }
    };
    let mut bytes = Vec::with_capacity(sets * 12);
    for shift in [0, 32].into_iter().take(sets) {
        for set in [ids.effective, ids.permitted, ids.inheritable] {
            bytes.extend(((set >> shift) as u32).to_le_bytes());
        }
    }
    match c.mem.write(GuestAddr(data), &bytes) {
        Ok(()) => ok(0),
        Err(_) => err(Errno::EFAULT),
    }
}
/// `capset(header, data)`, as Linux's: only the calling thread (EPERM), and
/// bits past the last capability do not count. The first version says
/// nothing of the high bits, which it clears.
pub(crate) fn sys_capset(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let [header, data, ..] = a;
    let sets = match capability_sets(c, header) {
        Ok(sets) => sets,
        Err(e) => return err(e),
    };
    match capability_pid(c, header) {
        Ok(pid) if pid != 0 && c.named(pid.cast_unsigned()) != c.tid => return err(Errno::EPERM),
        Ok(_) => {}
        Err(e) => return err(e),
    }
    let mut bytes = [0; 24];
    if c.mem
        .read(GuestAddr(data), &mut bytes[..sets * 12])
        .is_err()
    {
        return err(Errno::EFAULT);
    }
    let word = |at: usize| {
        u64::from(u32::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        ]))
    };
    let [effective, permitted, inheritable] =
        [0, 4, 8].map(|at| (word(at) | word(at + 12) << 32) & ALL_CAPABILITIES);
    let change = c
        .process
        .credentials
        .capset(effective, permitted, inheritable);
    set(c, change)
}
/// `setgroups(size, list)`: with CAP_SETGID, in a user namespace that
/// allows it (`may_setgroups`), at most `NGROUPS_MAX` groups, none one the
/// namespace does not map; kept sorted, as kernel IDs.
pub(crate) fn sys_setgroups(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    if !c.process.credentials.may_setgid() || !c.process.credentials.user.may_setgroups() {
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
    for group in &mut groups {
        match c
            .process
            .credentials
            .user
            .kernel_of(crate::users::Ids::Group, *group)
        {
            Some(kernel) => *group = kernel,
            None => return err(Errno::EINVAL),
        }
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
    fn another_threads_limits_need_all_its_ids_or_cap_sys_resource() {
        let ids = |r, e, s| {
            Credentials::default()
                .setresuid(r, e, s)
                .unwrap()
                .task_ids()
        };
        let sender = ids(2000, 3000, 3000);
        assert!(sender.may_prlimit(&ids(2000, 2000, 2000)), "the real ID");
        assert!(!sender.may_prlimit(&ids(2000, 3000, 2000)), "its effective");
        assert!(!sender.may_prlimit(&ids(2000, 2000, 3000)), "its saved");
        assert!(!sender.may_prlimit(&ids(3000, 2000, 2000)), "its real");
        let group = |change: fn(&mut TaskIds)| {
            let mut target = ids(2000, 2000, 2000);
            change(&mut target);
            target
        };
        assert!(!sender.may_prlimit(&group(|t| t.gid = 1)));
        assert!(!sender.may_prlimit(&group(|t| t.egid = 1)));
        assert!(!sender.may_prlimit(&group(|t| t.sgid = 1)));
        assert!(Credentials::default().task_ids().may_prlimit(&sender));
        let groups = Credentials::default()
            .setresgid(1, 2, 3)
            .unwrap()
            .task_ids();
        assert_eq!([groups.gid, groups.egid, groups.sgid], [1, 2, 3]);
    }
    #[test]
    fn reading_another_task_needs_its_capabilities_or_cap_sys_ptrace() {
        let no_ptrace = ALL_CAPABILITIES & !CAP_SYS_PTRACE;
        let target = Credentials::default()
            .capset(no_ptrace, no_ptrace, 0)
            .unwrap();
        // The same permitted set; with the filesystem IDs, the effective
        // one counts.
        let same = target.capset(0, no_ptrace, 0).unwrap();
        assert!(same.may_read_task(&target, true, true));
        assert!(!same.may_read_task(&target, true, false));
        assert!(target.may_read_task(&target, true, false));
        // One permitted capability fewer.
        let fewer = target.capset(0, no_ptrace & !(1 << 13), 0).unwrap();
        assert!(!fewer.may_read_task(&target, true, true));
        assert!(fewer.may_read_task(&fewer, true, true));
        // CAP_SYS_PTRACE lets it read anything.
        assert!(Credentials::default().may_read_task(&target, false, true));
        assert!(!same.may_read_task(&target, false, true), "not dumpable");
    }
    #[test]
    fn capset_keeps_within_what_the_thread_holds() {
        const SOME: u64 = 0xf0;
        let root = Credentials::default();
        // Effective within the new permitted, permitted within the old one.
        let less = root.capset(0x30, SOME, 0).unwrap();
        assert_eq!(
            [less.effective, less.permitted, less.inheritable],
            [0x30, SOME, 0]
        );
        assert_eq!(less.capset(SOME | 1, SOME, 0), Err(Errno::EPERM));
        assert_eq!(less.capset(0, SOME | 1, 0), Err(Errno::EPERM));
        // Effective counts against the new permitted set, not the old one.
        assert_eq!(less.capset(0x80, 0x70, 0), Err(Errno::EPERM));
        assert!(less.capset(SOME, SOME, 0).is_ok());
        // Without CAP_SETPCAP, inheritable within old inheritable and permitted.
        assert_eq!(less.capset(0, SOME, 0x100), Err(Errno::EPERM));
        let inherits = less.capset(0, SOME, 0x10).unwrap();
        // ... where the old inheritable counts even when no longer permitted.
        let lost = inherits.capset(0, 0x20, 0x10).unwrap();
        assert!(lost.capset(0, 0x20, 0x30).is_ok());
        assert_eq!(lost.capset(0, 0x20, 0x40), Err(Errno::EPERM));
        // With it, any.
        let with = root.capset(CAP_SETPCAP, CAP_SETPCAP, 0).unwrap();
        assert!(with.capset(CAP_SETPCAP, CAP_SETPCAP, 1 << 20).is_ok());
    }
    #[test]
    fn set_id_calls_and_exec_keep_the_inheritable_set() {
        let root = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x42)
            .unwrap();
        let user = root.setresuid(2000, 2000, 2000).unwrap();
        assert_eq!((user.inheritable, user.permitted), (0x42, 0));
        assert_eq!(
            root.after_exec(None, None, false).unwrap().0.inheritable,
            0x42
        );
        assert_eq!(user.after_exec(None, None, false).unwrap().0.permitted, 0);
    }
    #[test]
    fn scm_credentials_name_the_callers_own_ids_without_capabilities() {
        let root = Credentials::default();
        assert!(root.may_send_credentials(false, crate::users::first(), 4000, 4100));
        let user = root
            .setresgid(1100, 2100, 3100)
            .unwrap()
            .setresuid(1000, 2000, 3000)
            .unwrap();
        for uid in [1000, 2000, 3000] {
            assert!(
                user.may_send_credentials(true, crate::users::first(), uid, 1100),
                "{uid}"
            );
        }
        for gid in [1100, 2100, 3100] {
            assert!(
                user.may_send_credentials(true, crate::users::first(), 1000, gid),
                "{gid}"
            );
        }
        assert!(
            !user.may_send_credentials(false, crate::users::first(), 1000, 1100),
            "a process"
        );
        assert!(
            !user.may_send_credentials(true, crate::users::first(), 4000, 1100),
            "a user"
        );
        assert!(
            !user.may_send_credentials(true, crate::users::first(), 1000, 4100),
            "a group"
        );
        // Each capability allows its own part alone.
        let with = |capability| Credentials {
            effective: capability,
            ..user.clone()
        };
        assert!(with(CAP_SYS_ADMIN).may_send_credentials(false, crate::users::first(), 1000, 1100));
        assert!(!with(CAP_SYS_ADMIN).may_send_credentials(true, crate::users::first(), 4000, 4100));
        assert!(with(CAP_SETUID).may_send_credentials(true, crate::users::first(), 4000, 1100));
        assert!(!with(CAP_SETUID).may_send_credentials(false, crate::users::first(), 4000, 4100));
        assert!(with(CAP_SETGID).may_send_credentials(true, crate::users::first(), 1000, 4100));
        assert!(!with(CAP_SETGID).may_send_credentials(true, crate::users::first(), 4000, 4100));
    }
    #[test]
    fn another_threads_priority_needs_the_effective_id_or_cap_sys_nice() {
        let ids = |r, e, s| {
            Credentials::default()
                .setresuid(r, e, s)
                .unwrap()
                .task_ids()
        };
        let sender = ids(3000, 2000, 2000);
        assert!(sender.may_set_priority(&ids(2000, 3000, 3000)), "its real");
        assert!(
            sender.may_set_priority(&ids(3000, 2000, 3000)),
            "its effective"
        );
        assert!(
            !sender.may_set_priority(&ids(3000, 3000, 2000)),
            "its saved"
        );
        assert!(
            !ids(2000, 3000, 3000).may_set_priority(&ids(2000, 2000, 2000)),
            "the sender's real ID does not count"
        );
        assert!(Credentials::default().task_ids().may_set_priority(&sender));
    }
    #[test]
    fn a_signal_needs_a_shared_real_or_saved_id_or_cap_kill() {
        let root = Credentials::default();
        let ids = |r, e, s| root.setresuid(r, e, s).unwrap().task_ids();
        let sender = ids(2000, 2000, 2000);
        assert!(sender.may_signal(&ids(2000, 3000, 3000)), "the real ID");
        assert!(sender.may_signal(&ids(3000, 3000, 2000)), "the saved ID");
        assert!(
            !sender.may_signal(&ids(3000, 2000, 3000)),
            "the effective ID"
        );
        assert!(
            ids(2001, 2000, 2001).may_signal(&ids(2000, 3000, 3000)),
            "by euid"
        );
        assert!(
            !ids(2001, 2001, 2000).may_signal(&ids(2000, 3000, 2000)),
            "by suid"
        );
        // The effective capability decides: a real ID of root gives none.
        assert!(root.task_ids().may_signal(&ids(3000, 3000, 3000)));
        assert!(!ids(0, 3000, 0).may_signal(&ids(4000, 4000, 4000)));
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
            securebits: SECBIT_KEEP_CAPS,
            ..Credentials::default()
        };
        let user = root.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!((user.permitted, user.effective), (ALL_CAPABILITIES, 0));
        let (exec, secure) = user.after_exec(None, None, false).unwrap();
        assert_eq!((exec.permitted, exec.securebits, secure), (0, 0, false));
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
        let (exec, secure) = user.after_exec(None, None, false).unwrap();
        assert_eq!(ids(&exec), [1000, 1001, 1001, 1001]);
        assert!(secure);
        let (exec, secure) = root
            .setresuid(1000, 0, 0)
            .unwrap()
            .after_exec(None, None, false)
            .unwrap();
        assert_eq!(
            (exec.permitted, exec.effective, secure),
            (ALL_CAPABILITIES, ALL_CAPABILITIES, true)
        );
    }

    fn program(mode: u32, uid: u32, gid: u32) -> FileStat {
        FileStat {
            mode: 0o100000 | mode,
            uid,
            gid,
            ..FileStat::default()
        }
    }

    #[test]
    fn a_set_user_id_or_set_group_id_program_gives_its_owner_as_effective() {
        let user = Credentials::default()
            .setresgid(2000, 2000, 2000)
            .and_then(|c| c.setresuid(1000, 1000, 1000))
            .unwrap();
        let (exec, secure) = user
            .after_exec(Some(&program(0o4755, 1001, 0)), None, false)
            .unwrap();
        assert_eq!(ids(&exec), [1000, 1001, 1001, 1001]);
        assert_eq!((exec.permitted, secure), (0, true));
        let (exec, secure) = user
            .after_exec(Some(&program(0o2755, 0, 3000)), None, false)
            .unwrap();
        assert_eq!(
            [exec.gid, exec.egid, exec.sgid, exec.fsgid],
            [2000, 3000, 3000, 3000]
        );
        assert!(secure);
        // Without the group's execute bit, set-group-ID means locking.
        let (exec, secure) = user
            .after_exec(Some(&program(0o2745, 0, 3000)), None, false)
            .unwrap();
        assert_eq!((exec.egid, secure), (2000, false));
        // A set-user-ID root program gives every capability.
        let (exec, secure) = user
            .after_exec(Some(&program(0o4755, 0, 0)), None, false)
            .unwrap();
        assert_eq!(ids(&exec), [1000, 0, 0, 0]);
        assert_eq!(
            (exec.permitted, exec.effective, secure),
            (ALL_CAPABILITIES, ALL_CAPABILITIES, true)
        );
        // The program's own owner gains nothing.
        let (exec, secure) = user
            .after_exec(Some(&program(0o4755, 1000, 0)), None, false)
            .unwrap();
        assert_eq!((ids(&exec), secure), ([1000; 4], false));
        // Going back to the real ID changes the effective one: secure.
        let away = Credentials::default().setresuid(1000, 1001, 1001).unwrap();
        let (exec, secure) = away
            .after_exec(Some(&program(0o4755, 1000, 0)), None, false)
            .unwrap();
        assert_eq!((ids(&exec), secure), ([1000; 4], true));
    }

    #[test]
    fn no_new_privs_ignores_set_id_bits_and_keeps_the_effective_ids() {
        let user = Credentials::default().setresuid(1000, 1000, 1000).unwrap();
        let (exec, secure) = user
            .after_exec(Some(&program(0o6755, 0, 3000)), None, true)
            .unwrap();
        assert_eq!((ids(&exec), exec.egid, secure), ([1000; 4], 0, false));
        // Effective IDs other than the real ones stay, and the exec counts
        // as secure.
        let root = Credentials::default();
        let away = root.setresuid(1000, 1001, 1001).unwrap();
        let (exec, secure) = away.after_exec(None, None, true).unwrap();
        assert_eq!((ids(&exec), secure), ([1000, 1001, 1001, 1001], true));
        // Root by its effective ID keeps its capabilities.
        let (exec, secure) = root
            .setresuid(1000, 0, 0)
            .unwrap()
            .after_exec(None, None, true)
            .unwrap();
        assert_eq!(ids(&exec), [1000, 0, 0, 0]);
        assert_eq!(
            (exec.permitted, exec.effective, secure),
            (ALL_CAPABILITIES, ALL_CAPABILITIES, true)
        );
        // An effective group the thread is not in (its filesystem group
        // being another) changes, so the real IDs become effective.
        let elsewhere = root
            .setfsgid(5)
            .unwrap()
            .setresuid(1000, 1001, 1001)
            .unwrap();
        let (exec, secure) = elsewhere.after_exec(None, None, true).unwrap();
        assert_eq!(
            (ids(&exec), exec.egid, exec.fsgid, secure),
            ([1000; 4], 0, 0, true)
        );
    }

    /// A `security.capability` value of `revision` (1 to 3), with the
    /// effective flag when `effective`, and a revision 3 one's `root`.
    fn file_caps(
        revision: u32,
        effective: bool,
        permitted: u64,
        inheritable: u64,
        root: u32,
    ) -> Vec<u8> {
        let mut v = (revision << 24 | u32::from(effective))
            .to_le_bytes()
            .to_vec();
        v.extend_from_slice(&(permitted as u32).to_le_bytes());
        v.extend_from_slice(&(inheritable as u32).to_le_bytes());
        if revision > 1 {
            v.extend_from_slice(&((permitted >> 32) as u32).to_le_bytes());
            v.extend_from_slice(&((inheritable >> 32) as u32).to_le_bytes());
        }
        if revision == 3 {
            v.extend_from_slice(&root.to_le_bytes());
        }
        v
    }

    #[test]
    fn exec_takes_file_capabilities_within_the_bounding_and_inheritable_sets() {
        let user = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x30)
            .and_then(|c| c.setresuid(1000, 1000, 1000))
            .unwrap();
        let none = program(0o755, 0, 0);
        let exec = |c: &Credentials, value: &[u8]| c.after_exec(Some(&none), Some(value), false);
        // Permitted ones within the bounding set, inheritable ones within
        // the thread's, effective only with the flag; and the exec is
        // secure, as a user other than root gains them.
        let mut bounded = user.clone();
        bounded.bounding = ALL_CAPABILITIES & !0x2;
        let (new, secure) = exec(&bounded, &file_caps(2, false, 0x3, 0x10 | 0x40, 0)).unwrap();
        assert_eq!((new.permitted, new.effective, secure), (0x11, 0, true));
        let (new, secure) = exec(&user, &file_caps(2, true, 1 << 40, 0, 0)).unwrap();
        assert_eq!(
            (new.permitted, new.effective, secure),
            (1 << 40, 1 << 40, true)
        );
        // With the effective flag, a permitted capability the bounding set
        // holds back refuses the exec; without it, the program runs with
        // less.
        assert_eq!(
            exec(&bounded, &file_caps(2, true, 0x3, 0, 0)),
            Err(Errno::EPERM)
        );
        assert_eq!(
            exec(&bounded, &file_caps(2, false, 0x3, 0, 0))
                .unwrap()
                .0
                .permitted,
            0x1
        );
        // A revision 1 value has the low word alone, a revision 3 one
        // counts when its root is root here, and the bits past the last
        // capability go.
        let (new, _) = exec(&user, &file_caps(1, true, 0x5, 0, 0)).unwrap();
        assert_eq!(new.permitted, 0x5);
        let (new, _) = exec(&user, &file_caps(3, true, 0x5, 0, 0)).unwrap();
        assert_eq!(new.permitted, 0x5);
        let (new, secure) = exec(&user, &file_caps(3, true, 0x5, 0, 1000)).unwrap();
        assert_eq!((new.permitted, secure), (0, false));
        assert_eq!(
            exec(&user, &file_caps(3, true, 0x5, 0, u32::MAX))
                .unwrap()
                .0
                .permitted,
            0
        );
        assert_eq!(
            exec(&user, &file_caps(2, false, u64::MAX, 0, 0))
                .unwrap()
                .0
                .permitted,
            ALL_CAPABILITIES
        );
        // A value of no known revision or of the wrong size refuses it.
        for bad in [
            Vec::new(),
            vec![0; 3],
            file_caps(4, false, 1, 0, 0),
            file_caps(2, false, 1, 0, 0)[..12].to_vec(),
            file_caps(3, false, 1, 0, 0)[..20].to_vec(),
            [file_caps(1, false, 1, 0, 0), vec![0]].concat(),
        ] {
            assert_eq!(exec(&user, &bad), Err(Errno::EINVAL), "{bad:?}");
        }
    }

    #[test]
    fn root_takes_the_bounding_and_inheritable_sets_unless_noroot() {
        let mut root = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x3)
            .unwrap();
        root.bounding = 0xf0;
        let (new, secure) = root.after_exec(None, None, false).unwrap();
        assert_eq!((new.permitted, new.effective, secure), (0xf3, 0xf3, false));
        // File capabilities do not lessen root's.
        let caps = file_caps(2, false, 0x100, 0, 0);
        let (new, _) = root.after_exec(None, Some(&caps), false).unwrap();
        assert_eq!((new.permitted, new.effective), (0xf3, 0xf3));
        // A set-user-ID root program with file capabilities that another
        // user runs gives only those.
        let user = root.setresuid(1000, 1000, 1000).unwrap();
        let caps = file_caps(2, false, 0x30, 0, 0);
        let (new, secure) = user
            .after_exec(Some(&program(0o4755, 0, 0)), Some(&caps), false)
            .unwrap();
        assert_eq!(
            (new.euid, new.permitted, new.effective, secure),
            (0, 0x30, 0, true)
        );
        // SECBIT_NOROOT: root is no one special.
        root.securebits = SECBIT_NOROOT;
        let (new, secure) = root.after_exec(None, None, false).unwrap();
        assert_eq!((new.permitted, new.effective, secure), (0, 0, false));
        let caps = file_caps(2, true, 0x10, 0, 0);
        let (new, _) = root.after_exec(None, Some(&caps), false).unwrap();
        assert_eq!((new.permitted, new.effective), (0x10, 0x10));
    }

    #[test]
    fn the_ambient_set_lasts_through_exec_without_file_capabilities_or_set_ids() {
        let mut user = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x6)
            .unwrap();
        user.securebits = SECBIT_KEEP_CAPS;
        let mut user = user.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(user.prctl([47, 2, 1, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(user.prctl([47, 2, 2, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(user.ambient, 0x6);
        let (new, secure) = user.after_exec(None, None, false).unwrap();
        assert_eq!(
            (new.permitted, new.effective, new.ambient, secure),
            (0x6, 0x6, 0x6, false)
        );
        // File capabilities clear it.
        let caps = file_caps(2, false, 0x1, 0, 0);
        let (new, _) = user.after_exec(None, Some(&caps), false).unwrap();
        assert_eq!((new.permitted, new.effective, new.ambient), (0x1, 0, 0));
        // So does a set-user-ID program, but not one that changes nothing.
        let (new, _) = user
            .after_exec(Some(&program(0o4755, 1001, 0)), None, false)
            .unwrap();
        assert_eq!((new.permitted, new.ambient), (0, 0));
        let (new, _) = user
            .after_exec(Some(&program(0o4755, 1000, 0)), None, false)
            .unwrap();
        assert_eq!(new.ambient, 0x6);
        // capset keeps it within the new permitted and inheritable sets,
        // and leaving root clears it.
        let less = user.capset(0, 0x2 | 0x4, 0x2).unwrap();
        assert_eq!(less.ambient, 0x2);
        let mut root = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x2)
            .unwrap();
        root.securebits = SECBIT_KEEP_CAPS;
        assert_eq!(root.prctl([47, 2, 1, 0, 0, 0]), Some(Ok(0)));
        let left = root.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!((left.permitted, left.ambient), (ALL_CAPABILITIES, 0));
    }

    #[test]
    fn prctl_reads_and_drops_the_bounding_set() {
        let mut root = Credentials::default();
        assert_eq!(root.prctl([23, 40, 0, 0, 0, 0]), Some(Ok(1)));
        assert_eq!(root.prctl([23, 41, 0, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(root.prctl([24, 41, 0, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(root.prctl([24, 7, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(root.prctl([23, 7, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(root.bounding, ALL_CAPABILITIES & !CAP_SETUID);
        // A dropped capability cannot be made inheritable, even with
        // CAP_SETPCAP, but one inheritable already stays.
        assert_eq!(
            root.capset(ALL_CAPABILITIES, ALL_CAPABILITIES, CAP_SETUID),
            Err(Errno::EPERM)
        );
        // Without CAP_SETPCAP, EPERM comes first.
        let mut user = root.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(user.prctl([24, 41, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(user.prctl([23, 0, 0, 0, 0, 0]), Some(Ok(1)));
        assert_eq!(user.prctl([99, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn prctl_raises_the_ambient_set_only_within_permitted_and_inheritable() {
        let mut c = Credentials::default()
            .capset(ALL_CAPABILITIES, ALL_CAPABILITIES, 0x1)
            .unwrap();
        assert_eq!(c.prctl([47, 2, 2, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(c.prctl([47, 2, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(c.prctl([47, 1, 0, 0, 0, 0]), Some(Ok(1)));
        assert_eq!(c.prctl([47, 1, 1, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(c.prctl([47, 3, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(c.ambient, 0);
        // Unused arguments, a bad capability and an unknown operation.
        assert_eq!(c.prctl([47, 4, 1, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(c.prctl([47, 1, 41, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(c.prctl([47, 1, 0, 0, 1, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(c.prctl([47, 5, 0, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(c.prctl([47, 0, 41, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(c.prctl([47, 0, 0, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        c.prctl([47, 2, 0, 0, 0, 0]);
        assert_eq!(c.prctl([47, 4, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(c.ambient, 0);
        // SECBIT_NO_CAP_AMBIENT_RAISE refuses it.
        c.securebits = SECBIT_NO_CAP_AMBIENT_RAISE;
        assert_eq!(c.prctl([47, 2, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
    }

    #[test]
    fn prctl_sets_securebits_within_their_locks() {
        let mut root = Credentials::default();
        assert_eq!(root.prctl([27, 0, 0, 0, 0, 0]), Some(Ok(0)));
        // An unknown bit, then each bit and its lock.
        assert_eq!(
            root.prctl([28, 0x1000, 0, 0, 0, 0]),
            Some(Err(Errno::EPERM))
        );
        assert_eq!(
            root.prctl([28, 0, 0, 0, 0, 0]),
            Some(Ok(0)),
            "no change, with CAP_SETPCAP"
        );
        assert_eq!(root.prctl([28, 0x30, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(root.prctl([7, 0, 0, 0, 0, 0]), Some(Ok(1)));
        assert_eq!(root.prctl([8, 0, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(root.prctl([8, 2, 0, 0, 0, 0]), Some(Err(Errno::EINVAL)));
        assert_eq!(
            root.prctl([28, 0x20, 0, 0, 0, 0]),
            Some(Err(Errno::EPERM)),
            "a locked bit"
        );
        assert_eq!(
            root.prctl([28, 0x10, 0, 0, 0, 0]),
            Some(Err(Errno::EPERM)),
            "a lock"
        );
        assert_eq!(root.prctl([28, 0x31, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(root.prctl([27, 0, 0, 0, 0, 0]), Some(Ok(0x31)));
        // Exec clears SECBIT_KEEP_CAPS even when it is locked.
        let (new, _) = root.after_exec(None, None, false).unwrap();
        assert_eq!(new.securebits, 0x21);
        // Without CAP_SETPCAP, only the bits user space acts on, and a change.
        let mut user = Credentials::default().setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(user.prctl([28, 0, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(user.prctl([28, 0x1, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(user.prctl([28, 0x100, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(user.prctl([28, 0x300, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(user.prctl([28, 0x200, 0, 0, 0, 0]), Some(Err(Errno::EPERM)));
        assert_eq!(user.prctl([8, 1, 0, 0, 0, 0]), Some(Ok(0)));
        assert_eq!(user.securebits, 0x310);
    }

    #[test]
    fn no_setuid_fixup_keeps_the_capabilities_through_set_id_calls() {
        let root = Credentials {
            securebits: SECBIT_NO_SETUID_FIXUP,
            ..Credentials::default()
        };
        let user = root.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(
            (user.permitted, user.effective),
            (ALL_CAPABILITIES, ALL_CAPABILITIES)
        );
        assert_eq!(root.setfsuid(1000).unwrap().effective, ALL_CAPABILITIES);
    }

    #[test]
    fn a_new_user_namespace_starts_with_full_sets_and_no_securebits() {
        let c = Credentials {
            bounding: 0x1,
            ambient: 0x1,
            inheritable: 0x1,
            securebits: 0x31,
            ..Credentials::default()
        };
        let new = c.in_user_namespace(crate::users::UserNs::default());
        assert_eq!(
            (
                new.permitted,
                new.effective,
                new.inheritable,
                new.bounding,
                new.ambient,
                new.securebits
            ),
            (
                ALL_CAPABILITIES,
                ALL_CAPABILITIES,
                0,
                ALL_CAPABILITIES,
                0,
                0
            )
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
