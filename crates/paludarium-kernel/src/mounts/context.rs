//! The file system context of `fsopen` and `fspick` (Linux's `fs_context`,
//! `fs/fsopen.c`), which `fsconfig` fills and acts on and `fsmount` mounts,
//! in Linux master's order of checks. Only tmpfs is there, as for `mount`.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{NewTmpfs, Target, mount_flags as mnt};

use super::{
    AT_FDCWD, CAP_SYS_ADMIN, MS_RDONLY, MS_RMT_MASK, O_CLOEXEC, O_NOFOLLOW, O_PATH, Refused, Tmpfs,
    Value, built_tmpfs, may_mount, outcome, over_superblock, reconfigure_superblock, user_string,
};
use crate::syscalls::{Context, Outcome};

const EBUSY: Errno = Errno(16);
const ENODATA: Errno = Errno(61);
const EMSGSIZE: Errno = Errno(90);
const O_RDWR: u32 = 2;

const FSOPEN_CLOEXEC: u64 = 1;
const FSPICK_CLOEXEC: u64 = 1;
const FSPICK_SYMLINK_NOFOLLOW: u64 = 2;
const FSPICK_NO_AUTOMOUNT: u64 = 4;
const FSPICK_EMPTY_PATH: u64 = 8;
const FSCONFIG_SET_FLAG: u64 = 0;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_SET_BINARY: u64 = 2;
const FSCONFIG_SET_PATH: u64 = 3;
const FSCONFIG_SET_PATH_EMPTY: u64 = 4;
const FSCONFIG_SET_FD: u64 = 5;
const FSCONFIG_CMD_CREATE: u64 = 6;
const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;
const FSMOUNT_CLOEXEC: u64 = 1;
const FSMOUNT_NAMESPACE: u64 = 2;
const MOUNT_ATTR_RDONLY: u64 = 0x01;
const MOUNT_ATTR_NOSUID: u64 = 0x02;
const MOUNT_ATTR_NODEV: u64 = 0x04;
const MOUNT_ATTR_NOEXEC: u64 = 0x08;
const MOUNT_ATTR_ATIME: u64 = 0x70;
const MOUNT_ATTR_NOATIME: u64 = 0x10;
const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;
/// `FSMOUNT_VALID_FLAGS`.
const FSMOUNT_VALID: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_ATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_NOSYMFOLLOW;
/// How many messages the log keeps (`struct fc_log`'s buffer), the oldest
/// going for a new one.
const LOG_SIZE: usize = 8;
/// The longest key and string value `fsconfig` takes, with its 0.
const PARAM_MAX: u64 = 256;
/// The largest blob `FSCONFIG_SET_BINARY` takes.
const BLOB_MAX: u64 = 1024 * 1024;

/// Where a context is (`enum fs_context_phase`); it is never seen between
/// steps, so the steps of `CREATING` and `RECONFIGURING` are not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    CreateParams,
    AwaitingMount,
    AwaitingReconf,
    ReconfParams,
    Failed,
}

/// What a context makes or changes.
enum Purpose {
    /// A new tmpfs (`FS_CONTEXT_FOR_MOUNT`): its options, then the
    /// superblock `FSCONFIG_CMD_CREATE` made, which `fsmount` takes.
    Mount {
        options: Box<Tmpfs>,
        made: Option<NewTmpfs>,
    },
    /// The superblock of mount `mount` (`FS_CONTEXT_FOR_RECONFIGURE`), and
    /// the options asked of it.
    Reconfigure { mount: u64, asked: Box<Tmpfs> },
}

struct State {
    phase: Phase,
    purpose: Purpose,
    /// It has a superblock (`fc->root`): from `FSCONFIG_CMD_CREATE` on, or
    /// from `fspick`.
    root: bool,
    /// The messages not read yet, oldest first, each as `read` gives it.
    log: VecDeque<Vec<u8>>,
}

/// A descriptor of a file system context (`anon_inode:[fscontext]`): `read`
/// gives its messages one at a time.
pub(crate) struct FsContext {
    state: Mutex<State>,
    status: AtomicU32,
}
impl FsContext {
    fn new(purpose: Purpose, phase: Phase, root: bool) -> Self {
        Self {
            state: Mutex::new(State {
                phase,
                purpose,
                root,
                log: VecDeque::new(),
            }),
            status: AtomicU32::new(O_RDWR),
        }
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
impl State {
    /// `logfc`: `e <message>\n`, the oldest going once there are
    /// [`LOG_SIZE`].
    fn log(&mut self, refused: &Refused) {
        if refused.message.is_empty() {
            return;
        }
        if self.log.len() == LOG_SIZE {
            self.log.pop_front();
        }
        self.log
            .push_back(format!("e {}\n", refused.message).into_bytes());
    }
}
impl FileHandle for FsContext {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// `fscontext_read` (Linux master's): the oldest message, `ENODATA` for
    /// none, and `EMSGSIZE`, keeping it, when it does not fit.
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut state = self.state();
        let message = state.log.front().ok_or(ENODATA)?;
        if message.len() > buf.len() {
            return Err(EMSGSIZE);
        }
        let n = message.len();
        buf[..n].copy_from_slice(message);
        state.log.pop_front();
        Ok(n)
    }
    /// It has no `write` (`FMODE_CAN_WRITE`).
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    /// It has no `llseek` (`FMODE_LSEEK`).
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    /// An anonymous inode's.
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
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.store(flags, Ordering::SeqCst);
        Ok(())
    }
}

pub(crate) fn sys_fsopen(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(fsopen(c, a[0], a[1] & 0xffff_ffff))
}
pub(crate) fn sys_fsconfig(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(fsconfig(c, a))
}
pub(crate) fn sys_fsmount(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(fsmount(c, a[0], a[1] & 0xffff_ffff, a[2] & 0xffff_ffff))
}
pub(crate) fn sys_fspick(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(fspick(c, a[0], a[1], a[2] & 0xffff_ffff))
}

/// Installs a context's descriptor, open for reading and writing.
fn installed(c: &mut Context<'_>, context: FsContext, cloexec: bool) -> Result<u64, Errno> {
    c.files
        .install(Arc::new(context), cloexec, c.group.nofile())
        .map(u64::from)
}

/// `fsopen(fs_name, flags)`: `CAP_SYS_ADMIN` over the caller's mount
/// namespace (`EPERM`), the flags (`EINVAL`), the name (`EFAULT`, `EINVAL`
/// beyond a page), then the type: tmpfs, or `ENODEV` for any other, as
/// from a kernel without it. The context starts from tmpfs's defaults
/// (`shmem_init_fs_context`).
fn fsopen(c: &mut Context<'_>, name: u64, flags: u64) -> Result<u64, Errno> {
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    if flags & !FSOPEN_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let name = user_string(c, name, super::PAGE)?.ok_or(Errno::EFAULT)?;
    if name != b"tmpfs" {
        return Err(super::ENODEV);
    }
    let purpose = Purpose::Mount {
        options: Box::new(Tmpfs::fresh(c, None)),
        made: None,
    };
    let context = FsContext::new(purpose, Phase::CreateParams, false);
    installed(c, context, flags & FSOPEN_CLOEXEC != 0)
}

/// `fspick(dfd, path, flags)`: `CAP_SYS_ADMIN` over the caller's mount
/// namespace (`EPERM`), the flags (`EINVAL`), the lookup (its last link
/// followed unless `FSPICK_SYMLINK_NOFOLLOW`, an empty path naming `dfd`
/// with `FSPICK_EMPTY_PATH`), then the root of a mount (`EINVAL`), whose
/// superblock the context reconfigures. `/proc` and `/dev`, which the kernel
/// generates, are not supported (`EOPNOTSUPP`).
fn fspick(c: &mut Context<'_>, dfd: u64, ptr: u64, flags: u64) -> Result<u64, Errno> {
    let namespaces = c.group.namespaces(c.tid);
    if !may_mount(c, &namespaces.mnt) {
        return Err(Errno::EPERM);
    }
    let known = FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let empty = flags & FSPICK_EMPTY_PATH != 0;
    let raw = crate::files::path(c, ptr)?;
    let follow = flags & FSPICK_SYMLINK_NOFOLLOW == 0;
    let found = crate::files::mount_at(c, dfd, raw, follow, empty)?.ok_or(Errno::EOPNOTSUPP)?;
    let target = c.files.namespaced().target(&found)?;
    if !target.root {
        return Err(Errno::EINVAL);
    }
    let purpose = Purpose::Reconfigure {
        mount: target.id,
        asked: Box::new(Tmpfs::fresh(c, None)),
    };
    let context = FsContext::new(purpose, Phase::ReconfParams, true);
    installed(c, context, flags & FSPICK_CLOEXEC != 0)
}

/// The value `fsconfig` was given, read from the caller.
enum Given {
    Flag,
    String(Vec<u8>),
    /// A blob, a path or a descriptor, which no tmpfs parameter takes.
    Other,
}

/// `fsconfig(fd, cmd, key, value, aux)`, as Linux master's: a descriptor
/// number (`EINVAL` for a negative one), then each command's arguments
/// (`EINVAL`; `EOPNOTSUPP` for an unknown command), then the descriptor
/// (`EBADF`, `EINVAL` for another kind of file), the key and the value
/// (`EFAULT`, `EINVAL` beyond 255 bytes; a path as a lookup names it, a
/// descriptor `EBADF`). A parameter is taken while the context is
/// gathering them (`EBUSY` otherwise), as `mount`'s options are, a refused
/// one logging Linux's message; `FSCONFIG_CMD_CREATE` (and `_EXCL`) makes
/// the superblock, needing `CAP_SYS_ADMIN` over the caller's user namespace
/// (`EPERM`), and `FSCONFIG_CMD_RECONFIGURE` changes a picked or mounted
/// one, as `MS_REMOUNT` does but only for the flags named; a context that
/// failed takes nothing more (`EBUSY`).
fn fsconfig(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (fd, cmd, key, value) = (a[0] as i32, a[1] & 0xffff_ffff, a[2], a[3]);
    let aux = a[4] as i32;
    if fd < 0 {
        return Err(Errno::EINVAL);
    }
    let fine = match cmd {
        FSCONFIG_SET_FLAG => key != 0 && value == 0 && aux == 0,
        FSCONFIG_SET_STRING => key != 0 && value != 0 && aux == 0,
        FSCONFIG_SET_BINARY => {
            key != 0 && value != 0 && aux > 0 && i64::from(aux) <= BLOB_MAX as i64
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            key != 0 && value != 0 && (aux == -100 || aux >= 0)
        }
        FSCONFIG_SET_FD => key != 0 && value == 0 && aux >= 0,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL | FSCONFIG_CMD_RECONFIGURE => {
            key == 0 && value == 0 && aux == 0
        }
        _ => return Err(Errno::EOPNOTSUPP),
    };
    if !fine {
        return Err(Errno::EINVAL);
    }
    let file = c.files.descriptor(fd as u64)?.file;
    let Some(context) = file.as_any().and_then(|v| v.downcast_ref::<FsContext>()) else {
        return Err(Errno::EINVAL);
    };
    let key = user_string(c, key, PARAM_MAX)?;
    let given = match cmd {
        FSCONFIG_SET_FLAG => Given::Flag,
        FSCONFIG_SET_STRING => Given::String(user_string(c, value, PARAM_MAX)?.unwrap_or_default()),
        FSCONFIG_SET_BINARY => {
            let mut blob = vec![0; aux as usize];
            c.mem
                .read(GuestAddr(value), &mut blob)
                .map_err(|_| Errno::EFAULT)?;
            Given::Other
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            // `getname_flags`: the name itself, empty only with
            // `LOOKUP_EMPTY`; tmpfs looks no path up.
            let name = crate::files::path(c, value)?;
            if name.is_empty() && cmd == FSCONFIG_SET_PATH {
                return Err(Errno::ENOENT);
            }
            Given::Other
        }
        FSCONFIG_SET_FD => {
            c.files.descriptor(aux as u64)?;
            Given::Other
        }
        _ => Given::Flag,
    };
    let mut state = context.state();
    // `finish_clean_context`: a context mounted or reconfigured gathers
    // parameters for the next reconfiguration.
    if state.phase == Phase::AwaitingReconf {
        if let Purpose::Reconfigure { asked, .. } = &mut state.purpose {
            **asked = Tmpfs::fresh(c, None);
        }
        state.phase = Phase::ReconfParams;
    }
    match cmd {
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => create(c, &mut state),
        FSCONFIG_CMD_RECONFIGURE => reconfigure(c, &mut state),
        _ => {
            if !matches!(state.phase, Phase::CreateParams | Phase::ReconfParams) {
                return Err(EBUSY);
            }
            let key = key.unwrap_or_default();
            let value = match &given {
                Given::Flag => Value::Flag,
                Given::String(s) => Value::String(s),
                Given::Other => Value::Other,
            };
            let kind = match &state.purpose {
                Purpose::Mount { .. } => "tmpfs",
                Purpose::Reconfigure { mount, .. } => c
                    .files
                    .namespaced()
                    .target_of(*mount)
                    .map_or("tmpfs", |t| t.kind),
            };
            let parsed = match &mut state.purpose {
                Purpose::Mount { options, .. } => options.parse(c, &key, value),
                Purpose::Reconfigure { asked, .. } if kind == "tmpfs" => {
                    asked.parse(c, &key, value)
                }
                // Another file system takes only the common flags here.
                Purpose::Reconfigure { asked, .. } => {
                    if asked.parse_common(&key) {
                        Ok(())
                    } else {
                        Err(Refused::plain(format!(
                            "{kind}: Unknown parameter '{}'",
                            String::from_utf8_lossy(&key)
                        )))
                    }
                }
            };
            match parsed {
                Ok(()) => Ok(0),
                Err(refused) => {
                    state.log(&refused);
                    Err(refused.errno)
                }
            }
        }
    }
}

/// `vfs_cmd_create`: a context gathering parameters for a new superblock
/// (`EBUSY`), `CAP_SYS_ADMIN` over the caller's user namespace
/// (`mount_capable`, `EPERM`), then the superblock (`vfs_get_tree`), which
/// a failure leaves the context without.
fn create(c: &Context<'_>, state: &mut State) -> Result<u64, Errno> {
    if state.phase != Phase::CreateParams {
        return Err(EBUSY);
    }
    if !c.process.credentials.administers_own() {
        return Err(Errno::EPERM);
    }
    let Purpose::Mount { options, made } = &mut state.purpose else {
        return Err(EBUSY);
    };
    match built_tmpfs(c, (**options).clone(), 0, mnt::RELATIME) {
        Ok(new) => {
            *made = Some(new);
            state.root = true;
            state.phase = Phase::AwaitingMount;
            Ok(0)
        }
        Err(errno) => {
            state.phase = Phase::Failed;
            Err(errno)
        }
    }
}

/// `vfs_cmd_reconfigure`: a context gathering parameters for a
/// reconfiguration (`EBUSY`), `CAP_SYS_ADMIN` over the superblock's user
/// namespace (`EPERM`), then `reconfigure_super` with the flags named
/// (`EINVAL` for one a remount may not change) and tmpfs's own, a failure
/// failing the context; then it gathers for the next one.
fn reconfigure(c: &Context<'_>, state: &mut State) -> Result<u64, Errno> {
    if state.phase != Phase::ReconfParams {
        return Err(EBUSY);
    }
    let Purpose::Reconfigure { mount, asked } = &state.purpose else {
        return Err(EBUSY);
    };
    let Some(found) = c.files.namespaced().target_of(*mount) else {
        state.phase = Phase::Failed;
        return Err(Errno::EINVAL);
    };
    if !over_superblock(c, &found) {
        state.phase = Phase::Failed;
        return Err(Errno::EPERM);
    }
    let asked = (**asked).clone();
    let result = changed(c, &found, &asked);
    match result {
        Ok(()) => {
            state.phase = Phase::AwaitingReconf;
            Ok(0)
        }
        Err(refused) => {
            state.log(&refused);
            state.phase = Phase::Failed;
            Err(refused.errno)
        }
    }
}

/// `reconfigure_super` of `found`'s superblock with the flags `asked`
/// named, and its options.
fn changed(c: &Context<'_>, found: &Target, asked: &Tmpfs) -> Result<(), Refused> {
    let mask = asked.sb_set | asked.sb_clear;
    if mask & !MS_RMT_MASK != 0 {
        return Err(Errno::EINVAL.into());
    }
    let read_only = if mask & MS_RDONLY != 0 {
        asked.sb_set & MS_RDONLY != 0
    } else {
        found.read_only.superblock
    };
    reconfigure_superblock(c, found, asked, read_only, mask, asked.sb_set, found.flags)
}

/// `fsmount(fs_fd, flags, attr_flags)`, as Linux master's: the flags
/// (`EINVAL`), `CAP_SYS_ADMIN` over the caller's mount namespace
/// (`EPERM`), the mount attributes (`EINVAL`, one access-time setting),
/// then the descriptor (`EBADF`, `EINVAL` for another kind of file), a
/// superblock (`EINVAL` before one is made) not yet mounted (`EBUSY`). It
/// gives an `O_PATH` descriptor of the new mount, in a detached tree of its
/// own, as `open_tree` gives one; the context then reconfigures it.
/// `FSMOUNT_NAMESPACE`, new in Linux master, and `MOUNT_ATTR_NOSYMFOLLOW`
/// on a tmpfs are not supported (`EOPNOTSUPP`).
fn fsmount(c: &mut Context<'_>, fd: u64, flags: u64, attrs: u64) -> Result<u64, Errno> {
    if flags & !(FSMOUNT_CLOEXEC | FSMOUNT_NAMESPACE) != 0 {
        return Err(Errno::EINVAL);
    }
    let creds = &c.process.credentials;
    if flags & FSMOUNT_NAMESPACE != 0 {
        if !creds.capable_in(CAP_SYS_ADMIN, &creds.user.0) {
            return Err(Errno::EPERM);
        }
    } else {
        let namespaces = c.group.namespaces(c.tid);
        if !may_mount(c, &namespaces.mnt) {
            return Err(Errno::EPERM);
        }
    }
    if attrs & !FSMOUNT_VALID != 0 {
        return Err(Errno::EINVAL);
    }
    let mut mount_flags = 0;
    for (attr, flag) in [
        (MOUNT_ATTR_RDONLY, mnt::READONLY),
        (MOUNT_ATTR_NOSUID, mnt::NOSUID),
        (MOUNT_ATTR_NODEV, mnt::NODEV),
        (MOUNT_ATTR_NOEXEC, mnt::NOEXEC),
        (MOUNT_ATTR_NODIRATIME, mnt::NODIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, mnt::NOSYMFOLLOW),
    ] {
        if attrs & attr != 0 {
            mount_flags |= flag;
        }
    }
    mount_flags |= match attrs & MOUNT_ATTR_ATIME {
        MOUNT_ATTR_STRICTATIME => 0,
        MOUNT_ATTR_NOATIME => mnt::NOATIME,
        0 => mnt::RELATIME,
        _ => return Err(Errno::EINVAL),
    };
    let file = c.files.descriptor(fd)?.file;
    let Some(context) = file.as_any().and_then(|v| v.downcast_ref::<FsContext>()) else {
        return Err(Errno::EINVAL);
    };
    let mut state = context.state();
    if !state.root {
        return Err(Errno::EINVAL);
    }
    if state.phase != Phase::AwaitingMount {
        return Err(EBUSY);
    }
    if flags & FSMOUNT_NAMESPACE != 0 || mount_flags & mnt::NOSYMFOLLOW != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let Purpose::Mount { made, .. } = &mut state.purpose else {
        return Err(EBUSY);
    };
    let Some(mut new) = made.take() else {
        return Err(EBUSY);
    };
    new.flags = mount_flags;
    // As Linux master's `fsmount`, the mount is made and the context
    // cleaned before the descriptor is: a descriptor it cannot have
    // (`EMFILE`) leaves the context cleaned, and the mount goes with the
    // last hold on it (`dissolve_on_fput`), so a second `fsmount` is
    // `EBUSY` there too. Making the mount itself does not fail.
    let (point, pin, id) = c.files.namespaced().mount_detached(new)?;
    // `vfs_clean_context`: the context now reconfigures the new mount.
    state.purpose = Purpose::Reconfigure {
        mount: id,
        asked: Box::new(Tmpfs::fresh(c, None)),
    };
    state.phase = Phase::AwaitingReconf;
    drop(state);
    let cloexec = if flags & FSMOUNT_CLOEXEC != 0 {
        O_CLOEXEC
    } else {
        0
    };
    let opened = crate::files::open_at(c, AT_FDCWD, point, O_PATH | O_NOFOLLOW | cloexec, 0, 0);
    drop(pin);
    opened
}
