//! The sysctls paludarium has under `/proc/sys`: the POSIX message queue
//! limits of `/proc/sys/fs/mqueue` (`queues_max`, `msg_max`,
//! `msgsize_max`, `msg_default`, `msgsize_default`), as Linux's
//! `ipc/mq_sysctl.c` has them, and the machine's aio events
//! (`/proc/sys/fs/aio-nr`, mode 0444) and their limit (`aio-max-nr`), as
//! `fs/aio.c` has them: unsigned longs (`proc_doulongvec_minmax`), whose
//! write takes no `-`, and which only root (user ID 0 outside any user
//! namespace) may open to write. The machine's inotify limits
//! (`/proc/sys/fs/inotify`), as `fs/notify/inotify/inotify_user.c` has
//! them, are root's in the same way: `max_user_instances` and
//! `max_user_watches` unsigned longs from 0 to `INT_MAX`, and
//! `max_queued_events` an `int` from 0; so are its fanotify limits
//! (`/proc/sys/fs/fanotify`, `fs/notify/fanotify/fanotify_user.c`):
//! `max_user_groups` and `max_user_marks` unsigned longs from 0 to
//! `INT_MAX`, `max_queued_events` and `watchdog_timeout` `int`s from 0.
//!
//! `/proc/sys/kernel` has the System V IPC limits of the opener's IPC
//! namespace, as Linux's `ipc/ipc_sysctl.c` has them: `shmmax` and `shmall`
//! unsigned longs, `shmmni` and `msgmni` `int`s from 0 to `IPCMNI`, `msgmax`
//! and `msgmnb` `int`s from 0, and `sem`, four `int`s (`semmsl`, `semmns`,
//! `semopm`, `semmni`) read with tabs between them and written as many as
//! are given, the ones before a bad one kept, and `semmni` back as it was
//! unless it ends from 0 to `IPCMNI` (`ERANGE`, `proc_ipc_sem_dointvec`). Their
//! owners and who may write them are the mqueue files'. Beside them are
//! `perf_event_paranoid` and `unprivileged_bpf_disabled`, the values
//! [`crate::perf`] and [`crate::bpf`] keep to (2, Linux's defaults), which
//! no one may write.
//!
//! Each file is the opener's IPC namespace's ([`crate::mqueue::Limits`]),
//! so a new namespace shows Linux's defaults again. A read gives the value
//! and a newline from the start of the file, nothing from elsewhere; a
//! write at the start sets it as Linux's `proc_dointvec_minmax` reads one
//! `int` (spaces, an optional `-`, digits in base 10, or 16 after `0x` or 8
//! after `0`, then a space, tab or newline or the end), bounded as Linux
//! bounds each (`EINVAL`), and consumes what it read and the spaces after
//! it; a write elsewhere is taken and does nothing, as
//! `sysctl_writes_strict` has it. A file's mode is 0644, and only the root
//! of the user namespace that owns the IPC namespace may open it to write
//! (`mq_permissions`, `EACCES`).
use crate::ipc::IPCMNI;
use crate::mqueue::{HARD_MSGMAX, HARD_MSGSIZEMAX, Limits, Queues};
use crate::namespaces::Namespace;
use crate::syscalls::Context;
use crate::users::Ids as Kind;
use paludarium_host::{DirectoryEntry, FileHandle, FileStat};
use paludarium_types::Errno;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;

/// The least of `msg_max` and `msg_default` (`MIN_MSGMAX`), and of
/// `msgsize_max` and `msgsize_default` (`MIN_MSGSIZEMAX`).
const MIN_MSGMAX: i32 = 1;
const MIN_MSGSIZEMAX: i32 = 128;

/// A directory of `/proc/sys` paludarium has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Directory {
    Sys,
    Fs,
    Mqueue,
    Inotify,
    Fanotify,
    Kernel,
}

/// A file of `/proc/sys/fs/mqueue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Setting {
    MsgDefault,
    MsgMax,
    MsgsizeDefault,
    MsgsizeMax,
    QueuesMax,
}

/// The settings by name, in the order Linux lists them.
const SETTINGS: [(&[u8], Setting); 5] = [
    (b"queues_max", Setting::QueuesMax),
    (b"msg_max", Setting::MsgMax),
    (b"msgsize_max", Setting::MsgsizeMax),
    (b"msg_default", Setting::MsgDefault),
    (b"msgsize_default", Setting::MsgsizeDefault),
];

impl Setting {
    /// Its value among `limits`, and the bounds a write keeps to: none
    /// for `queues_max` (`proc_dointvec`).
    fn of(self, limits: &Limits) -> (&AtomicI32, Option<(i32, i32)>) {
        match self {
            Self::QueuesMax => (&limits.queues_max, None),
            Self::MsgMax => (&limits.msg_max, Some((MIN_MSGMAX, HARD_MSGMAX))),
            Self::MsgsizeMax => (&limits.msgsize_max, Some((MIN_MSGSIZEMAX, HARD_MSGSIZEMAX))),
            Self::MsgDefault => (&limits.msg_default, Some((MIN_MSGMAX, HARD_MSGMAX))),
            Self::MsgsizeDefault => (
                &limits.msgsize_default,
                Some((MIN_MSGSIZEMAX, HARD_MSGSIZEMAX)),
            ),
        }
    }
}

/// A file of `/proc/sys/fs` for aio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Aio {
    MaxNr,
    Nr,
}

/// A file of `/proc/sys/fs/inotify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inotify {
    QueuedEvents,
    UserInstances,
    UserWatches,
}

/// The inotify files by name, in the order Linux lists them (by name).
const INOTIFY: [(&[u8], Inotify); 3] = [
    (b"max_queued_events", Inotify::QueuedEvents),
    (b"max_user_instances", Inotify::UserInstances),
    (b"max_user_watches", Inotify::UserWatches),
];

/// A file of `/proc/sys/fs/fanotify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fanotify {
    QueuedEvents,
    UserGroups,
    UserMarks,
    WatchdogTimeout,
}

/// The fanotify files by name, in the order Linux lists them (by name).
const FANOTIFY: [(&[u8], Fanotify); 4] = [
    (b"max_queued_events", Fanotify::QueuedEvents),
    (b"max_user_groups", Fanotify::UserGroups),
    (b"max_user_marks", Fanotify::UserMarks),
    (b"watchdog_timeout", Fanotify::WatchdogTimeout),
];

/// A file of `/proc/sys/kernel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    Msgmax,
    Msgmnb,
    Msgmni,
    PerfEventParanoid,
    Sem,
    Shmall,
    Shmmax,
    Shmmni,
    UnprivilegedBpfDisabled,
}

/// The `/proc/sys/kernel` files by name, in the order Linux lists them (by
/// name).
const KERNEL: [(&[u8], Kernel); 9] = [
    (b"msgmax", Kernel::Msgmax),
    (b"msgmnb", Kernel::Msgmnb),
    (b"msgmni", Kernel::Msgmni),
    (b"perf_event_paranoid", Kernel::PerfEventParanoid),
    (b"sem", Kernel::Sem),
    (b"shmall", Kernel::Shmall),
    (b"shmmax", Kernel::Shmmax),
    (b"shmmni", Kernel::Shmmni),
    (
        b"unprivileged_bpf_disabled",
        Kernel::UnprivilegedBpfDisabled,
    ),
];

impl Kernel {
    /// Whether it is one of the IPC namespace's limits; else it is a
    /// fixed value no one may write.
    fn ipc(self) -> bool {
        !matches!(
            self,
            Self::PerfEventParanoid | Self::UnprivilegedBpfDisabled
        )
    }
}

/// What `path` names under `/proc/sys`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Directory(Directory),
    Setting(Setting),
    Aio(Aio),
    Inotify(Inotify),
    Fanotify(Fanotify),
    Kernel(Kernel),
}

/// The entry `path` names, if it is one of these.
pub(crate) fn entry(path: &[u8]) -> Option<Entry> {
    if !path.starts_with(b"/proc/sys") {
        return None;
    }
    let path = paludarium_vfs::normalize_path(path).ok()?;
    let rest = path.strip_prefix(b"/proc/sys")?;
    match rest {
        b"" => Some(Entry::Directory(Directory::Sys)),
        b"/fs" => Some(Entry::Directory(Directory::Fs)),
        b"/fs/mqueue" => Some(Entry::Directory(Directory::Mqueue)),
        b"/fs/inotify" => Some(Entry::Directory(Directory::Inotify)),
        b"/fs/fanotify" => Some(Entry::Directory(Directory::Fanotify)),
        b"/fs/aio-max-nr" => Some(Entry::Aio(Aio::MaxNr)),
        b"/fs/aio-nr" => Some(Entry::Aio(Aio::Nr)),
        b"/kernel" => Some(Entry::Directory(Directory::Kernel)),
        _ => {
            if let Some(name) = rest.strip_prefix(b"/kernel/") {
                return KERNEL
                    .iter()
                    .find(|(known, _)| *known == name)
                    .map(|&(_, file)| Entry::Kernel(file));
            }
            if let Some(name) = rest.strip_prefix(b"/fs/fanotify/") {
                return FANOTIFY
                    .iter()
                    .find(|(known, _)| *known == name)
                    .map(|&(_, file)| Entry::Fanotify(file));
            }
            if let Some(name) = rest.strip_prefix(b"/fs/inotify/") {
                return INOTIFY
                    .iter()
                    .find(|(known, _)| *known == name)
                    .map(|&(_, file)| Entry::Inotify(file));
            }
            let name = rest.strip_prefix(b"/fs/mqueue/")?;
            SETTINGS
                .iter()
                .find(|(known, _)| *known == name)
                .map(|&(_, setting)| Entry::Setting(setting))
        }
    }
}

/// The entries of `directory`.
pub(crate) fn entries(directory: Directory) -> Vec<DirectoryEntry> {
    let names: Vec<(&[u8], u8)> = match directory {
        Directory::Sys => vec![(b"fs", DT_DIR), (b"kernel", DT_DIR)],
        Directory::Fs => vec![
            (b"aio-max-nr", DT_REG),
            (b"aio-nr", DT_REG),
            (b"fanotify", DT_DIR),
            (b"inotify", DT_DIR),
            (b"mqueue", DT_DIR),
        ],
        Directory::Mqueue => SETTINGS.iter().map(|&(name, _)| (name, DT_REG)).collect(),
        Directory::Inotify => INOTIFY.iter().map(|&(name, _)| (name, DT_REG)).collect(),
        Directory::Fanotify => FANOTIFY.iter().map(|&(name, _)| (name, DT_REG)).collect(),
        Directory::Kernel => KERNEL.iter().map(|&(name, _)| (name, DT_REG)).collect(),
    };
    [(&b"."[..], DT_DIR), (b"..", DT_DIR)]
        .into_iter()
        .chain(names)
        .enumerate()
        .map(|(i, (name, kind))| DirectoryEntry {
            name: name.to_vec(),
            inode: i as u64 + 1,
            kind,
        })
        .collect()
}

/// The limits of the caller's IPC namespace.
fn queues(c: &Context<'_>) -> Queues {
    c.group.namespaces(c.tid).ipc.mq.clone()
}

/// The root of the user namespace that owns the caller's IPC namespace,
/// whom the files belong to (`mq_set_ownership`), or root.
fn owner(c: &Context<'_>) -> (u32, u32) {
    let namespaces = c.group.namespaces(c.tid);
    let user = namespaces.ipc.owner();
    (
        user.kernel_of(Kind::User, 0).unwrap_or(0),
        user.kernel_of(Kind::Group, 0).unwrap_or(0),
    )
}

/// The caller's IPC namespace.
fn ipc(c: &Context<'_>) -> Arc<Namespace> {
    Arc::clone(&c.group.namespaces(c.tid).ipc)
}

/// The value of a `/proc/sys/kernel` file of `ipc`, as a line: `sem`'s
/// four with tabs between them.
fn kernel_line(ipc: &Namespace, file: Kernel) -> Vec<u8> {
    match file {
        Kernel::Shmmax => format!("{}\n", ipc.shm.with_limits(|limits| limits.max)).into_bytes(),
        Kernel::Shmall => format!("{}\n", ipc.shm.with_limits(|limits| limits.all)).into_bytes(),
        Kernel::Shmmni => line(ipc.shm.with_limits(|limits| limits.mni)),
        Kernel::Msgmax => line(ipc.msg.with_limits(|limits| limits.max)),
        Kernel::Msgmnb => line(ipc.msg.with_limits(|limits| limits.mnb)),
        Kernel::Msgmni => line(ipc.msg.with_limits(|limits| limits.mni)),
        Kernel::Sem => {
            let [msl, mns, opm, mni] = ipc.sem.with_limits(|limits| limits.0);
            format!("{msl}\t{mns}\t{opm}\t{mni}\n").into_bytes()
        }
        Kernel::PerfEventParanoid => line(crate::perf::PARANOID),
        Kernel::UnprivilegedBpfDisabled => line(crate::bpf::UNPRIVILEGED_DISABLED),
    }
}

/// Takes the value of a `/proc/sys/kernel` file of `ipc` written at the
/// start of the file: the bytes taken.
fn kernel_write(ipc: &Namespace, file: Kernel, buf: &[u8]) -> Result<usize, Errno> {
    let mni = Some((0, IPCMNI as i32));
    let int = Some((0, i32::MAX));
    match file {
        // `proc_doulongvec_minmax`, with no bounds.
        Kernel::Shmmax | Kernel::Shmall => {
            let (negative, value, consumed) = scan(buf)?;
            if negative {
                return Err(Errno::EINVAL);
            }
            ipc.shm.with_limits(|limits| {
                if file == Kernel::Shmmax {
                    limits.max = value;
                } else {
                    limits.all = value;
                }
            });
            Ok(consumed)
        }
        Kernel::Shmmni => {
            let (value, consumed) = parse(buf, mni)?;
            ipc.shm.with_limits(|limits| limits.mni = value);
            Ok(consumed)
        }
        Kernel::Msgmax | Kernel::Msgmnb | Kernel::Msgmni => {
            let (value, consumed) = parse(buf, if file == Kernel::Msgmni { mni } else { int })?;
            ipc.msg.with_limits(|limits| match file {
                Kernel::Msgmax => limits.max = value,
                Kernel::Msgmnb => limits.mnb = value,
                _ => limits.mni = value,
            });
            Ok(consumed)
        }
        // `proc_ipc_sem_dointvec`: the values before a bad one stay, and
        // `semmni` goes back unless it ends in its bounds (`ERANGE`,
        // `sem_check_semmni`).
        Kernel::Sem => ipc.sem.with_limits(|limits| {
            let semmni = limits.0[3];
            let written = parse_ints(buf, &mut limits.0).and_then(|consumed| {
                if (0..=IPCMNI as i32).contains(&limits.0[3]) {
                    Ok(consumed)
                } else {
                    Err(Errno::ERANGE)
                }
            });
            if written.is_err() {
                limits.0[3] = semmni;
            }
            written
        }),
        Kernel::PerfEventParanoid | Kernel::UnprivilegedBpfDisabled => Err(Errno::EINVAL),
    }
}

/// The value of an aio file, as a line.
fn aio_line(limits: &crate::aio::Limits, aio: Aio) -> Vec<u8> {
    let value = match aio {
        Aio::MaxNr => limits.max(),
        Aio::Nr => limits.nr(),
    };
    format!("{value}\n").into_bytes()
}

/// The value of an inotify file, as a line.
fn inotify_line(limits: &crate::inotify::Limits, file: Inotify) -> Vec<u8> {
    match file {
        Inotify::QueuedEvents => line(limits.events.load(Ordering::SeqCst)),
        Inotify::UserInstances => {
            format!("{}\n", limits.instances.load(Ordering::SeqCst)).into_bytes()
        }
        Inotify::UserWatches => format!("{}\n", limits.watches.load(Ordering::SeqCst)).into_bytes(),
    }
}

/// The value of a fanotify file, as a line.
fn fanotify_line(limits: &crate::fanotify::Limits, file: Fanotify) -> Vec<u8> {
    match file {
        Fanotify::QueuedEvents => line(limits.events.load(Ordering::SeqCst)),
        Fanotify::WatchdogTimeout => line(limits.watchdog.load(Ordering::SeqCst)),
        Fanotify::UserGroups => format!("{}\n", limits.groups.load(Ordering::SeqCst)).into_bytes(),
        Fanotify::UserMarks => format!("{}\n", limits.marks.load(Ordering::SeqCst)).into_bytes(),
    }
}

/// The status of `entry`: a directory anyone may read and search, a
/// regular file of mode 0644, its owner's root's, or an aio file, root's,
/// 0644 or for `aio-nr` 0444.
pub(crate) fn stat(c: &Context<'_>, entry: Entry) -> FileStat {
    match entry {
        Entry::Directory(_) => crate::proc::directory_stat(),
        Entry::Aio(aio) => FileStat {
            mode: if aio == Aio::Nr { 0o100_444 } else { 0o100_644 },
            ..crate::proc::stat(aio_line(&c.processes.aio, aio).len())
        },
        Entry::Inotify(file) => FileStat {
            mode: 0o100_644,
            ..crate::proc::stat(inotify_line(&c.files.caches.notify.limits, file).len())
        },
        Entry::Fanotify(file) => FileStat {
            mode: 0o100_644,
            ..crate::proc::stat(fanotify_line(&c.files.caches.notify.fan.limits, file).len())
        },
        Entry::Kernel(file) if !file.ipc() => FileStat {
            mode: 0o100_444,
            ..crate::proc::stat(kernel_line(&ipc(c), file).len())
        },
        Entry::Kernel(file) => {
            let (uid, gid) = owner(c);
            FileStat {
                mode: 0o100_644,
                uid,
                gid,
                ..crate::proc::stat(kernel_line(&ipc(c), file).len())
            }
        }
        Entry::Setting(setting) => {
            let (uid, gid) = owner(c);
            let queues = queues(c);
            let (value, _) = setting.of(queues.limits());
            FileStat {
                mode: 0o100_644,
                uid,
                gid,
                ..crate::proc::stat(line(value.load(Ordering::SeqCst)).len())
            }
        }
    }
}

fn line(value: i32) -> Vec<u8> {
    format!("{value}\n").into_bytes()
}

/// Opens `entry` with `flags`: a directory only to read (`EISDIR`), a
/// setting to write only by the root of the namespace's owner (`EACCES`),
/// as `mq_permissions` lets the owner's root have the owner's bits and
/// everyone else the others', and so a `/proc/sys/kernel` IPC limit
/// (`ipc_permissions`); `perf_event_paranoid` and
/// `unprivileged_bpf_disabled` to no one (`EACCES`).
pub(crate) fn open(
    c: &Context<'_>,
    entry: Entry,
    flags: u32,
) -> Result<Arc<dyn FileHandle>, Errno> {
    match entry {
        Entry::Directory(_) if flags & 3 != 0 => Err(Errno::EISDIR),
        Entry::Directory(_) => Ok(Arc::new(crate::proc::OwnDirectory::new(
            crate::proc::directory_stat(),
        ))),
        Entry::Setting(setting) => {
            if flags & 3 != 0 && c.process.credentials.euid != owner(c).0 {
                return Err(Errno::EACCES);
            }
            Ok(Arc::new(SettingFile {
                value: Value::Mqueue(queues(c), setting),
                stat: stat(c, entry),
                position: Mutex::new(0),
                flags,
            }))
        }
        Entry::Kernel(file) => {
            if flags & 3 != 0 && (!file.ipc() || c.process.credentials.euid != owner(c).0) {
                return Err(Errno::EACCES);
            }
            Ok(Arc::new(SettingFile {
                value: Value::Kernel(ipc(c), file),
                stat: stat(c, entry),
                position: Mutex::new(0),
                flags,
            }))
        }
        Entry::Inotify(file) => {
            if flags & 3 != 0 && c.process.credentials.euid != 0 {
                return Err(Errno::EACCES);
            }
            Ok(Arc::new(SettingFile {
                value: Value::Inotify(Arc::clone(&c.files.caches.notify), file),
                stat: stat(c, entry),
                position: Mutex::new(0),
                flags,
            }))
        }
        Entry::Fanotify(file) => {
            if flags & 3 != 0 && c.process.credentials.euid != 0 {
                return Err(Errno::EACCES);
            }
            Ok(Arc::new(SettingFile {
                value: Value::Fanotify(Arc::clone(&c.files.caches.notify.fan), file),
                stat: stat(c, entry),
                position: Mutex::new(0),
                flags,
            }))
        }
        // `test_perm`: root has the owner's bits, everyone else the others'.
        Entry::Aio(aio) => {
            if flags & 3 != 0 && (aio == Aio::Nr || c.process.credentials.euid != 0) {
                return Err(Errno::EACCES);
            }
            Ok(Arc::new(SettingFile {
                value: Value::Aio(Arc::clone(&c.processes.aio), aio),
                stat: stat(c, entry),
                position: Mutex::new(0),
                flags,
            }))
        }
    }
}

/// What an open sysctl file shows.
enum Value {
    Mqueue(Queues, Setting),
    Aio(Arc<crate::aio::Limits>, Aio),
    Inotify(Arc<crate::inotify::Notifier>, Inotify),
    Fanotify(Arc<crate::fanotify::Registry>, Fanotify),
    Kernel(Arc<Namespace>, Kernel),
}

impl Value {
    fn line(&self) -> Vec<u8> {
        match self {
            Self::Mqueue(queues, setting) => {
                line(setting.of(queues.limits()).0.load(Ordering::SeqCst))
            }
            Self::Aio(limits, aio) => aio_line(limits, *aio),
            Self::Inotify(notifier, file) => inotify_line(&notifier.limits, *file),
            Self::Fanotify(registry, file) => fanotify_line(&registry.limits, *file),
            Self::Kernel(ipc, file) => kernel_line(ipc, *file),
        }
    }
    /// Takes the value written at the start of the file: the bytes taken.
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        match self {
            Self::Mqueue(queues, setting) => {
                let (value, bounds) = setting.of(queues.limits());
                let (parsed, consumed) = parse(buf, bounds)?;
                value.store(parsed, Ordering::SeqCst);
                Ok(consumed)
            }
            Self::Kernel(ipc, file) => kernel_write(ipc, *file, buf),
            Self::Aio(limits, _) => {
                let (negative, value, consumed) = scan(buf)?;
                if negative {
                    return Err(Errno::EINVAL);
                }
                limits.set_max(value);
                Ok(consumed)
            }
            Self::Inotify(notifier, file) => {
                let limits = &notifier.limits;
                if *file == Inotify::QueuedEvents {
                    let (value, consumed) = parse(buf, Some((0, i32::MAX)))?;
                    limits.events.store(value, Ordering::SeqCst);
                    return Ok(consumed);
                }
                // `proc_doulongvec_minmax`, from 0 to `INT_MAX`.
                let (negative, value, consumed) = scan(buf)?;
                if negative || value > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                let limit = if *file == Inotify::UserInstances {
                    &limits.instances
                } else {
                    &limits.watches
                };
                limit.store(value, Ordering::SeqCst);
                Ok(consumed)
            }
            Self::Fanotify(registry, file) => {
                let limits = &registry.limits;
                let int = match file {
                    Fanotify::QueuedEvents => Some(&limits.events),
                    Fanotify::WatchdogTimeout => Some(&limits.watchdog),
                    _ => None,
                };
                if let Some(int) = int {
                    let (value, consumed) = parse(buf, Some((0, i32::MAX)))?;
                    int.store(value, Ordering::SeqCst);
                    return Ok(consumed);
                }
                let (negative, value, consumed) = scan(buf)?;
                if negative || value > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                let limit = if *file == Fanotify::UserGroups {
                    &limits.groups
                } else {
                    &limits.marks
                };
                limit.store(value, Ordering::SeqCst);
                Ok(consumed)
            }
        }
    }
}

/// An open file of `/proc/sys`.
struct SettingFile {
    value: Value,
    stat: FileStat,
    position: Mutex<u64>,
    flags: u32,
}

impl SettingFile {
    fn position(&self) -> MutexGuard<'_, u64> {
        self.position.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FileHandle for SettingFile {
    /// The value and a newline, as much as fits, from the start; nothing
    /// from anywhere else (`__do_proc_dointvec`).
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.flags & 3 == 1 {
            return Err(Errno::EBADF);
        }
        let mut position = self.position();
        if *position != 0 || buf.is_empty() {
            return Ok(0);
        }
        let line = self.value.line();
        let count = buf.len().min(line.len());
        buf[..count].copy_from_slice(&line[..count]);
        *position += count as u64;
        Ok(count)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if self.flags & 3 == 0 {
            return Err(Errno::EBADF);
        }
        let mut position = self.position();
        if buf.is_empty() {
            return Ok(0);
        }
        // `sysctl_writes_strict`: a write past the start is taken whole and
        // changes nothing.
        if *position != 0 {
            *position += buf.len() as u64;
            return Ok(buf.len());
        }
        let consumed = self.value.write(buf)?;
        *position += consumed as u64;
        Ok(consumed)
    }
    /// `default_llseek`, whose end is the size of 0 a sysctl reports.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position();
        let base = match whence {
            0 | 2 => 0,
            1 => *position as i64,
            _ => return Err(Errno::EINVAL),
        };
        let target = base
            .checked_add(offset)
            .filter(|&t| t >= 0)
            .ok_or(Errno::EINVAL)?;
        *position = target as u64;
        Ok(target as u64)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Ok(())
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

/// `isspace`, which `proc_skip_spaces` skips.
fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// One number written to a sysctl, as Linux's `proc_get_long` reads it:
/// whether it is negative, its magnitude, and the bytes taken, the spaces
/// after it too. `EINVAL` for no value, one not followed by a space, tab,
/// newline or the end, one of 21 characters or more, or one past 64 bits.
fn scan(buf: &[u8]) -> Result<(bool, u64, usize), Errno> {
    let buf = &buf[..buf.len().min(4095)];
    let mut at = buf.iter().take_while(|&&b| space(b)).count();
    if at == buf.len() {
        return Err(Errno::EINVAL);
    }
    // `proc_get_long` looks at no more than 21 characters.
    let window = &buf[at..buf.len().min(at + 21)];
    let negative = window[0] == b'-';
    let digits = &window[usize::from(negative)..];
    if !digits.first().is_some_and(u8::is_ascii_digit) {
        return Err(Errno::EINVAL);
    }
    let (value, used) = strtoul(digits).ok_or(Errno::EINVAL)?;
    let length = usize::from(negative) + used;
    if length == 21 {
        return Err(Errno::EINVAL);
    }
    at += length;
    if buf
        .get(at)
        .is_some_and(|&b| !matches!(b, b' ' | b'\t' | b'\n'))
    {
        return Err(Errno::EINVAL);
    }
    at += buf[at..].iter().take_while(|&&b| space(b)).count();
    Ok((negative, value, at))
}

/// One `int` written to a sysctl, as Linux's `__do_proc_dointvec` with
/// `proc_get_long` reads it ([`scan`]), and `do_proc_dointvec_minmax_conv`
/// bounds it: the value and the bytes taken. `EINVAL` as [`scan`] gives
/// it, and for one an `int` cannot hold or one out of `bounds`.
fn parse(buf: &[u8], bounds: Option<(i32, i32)>) -> Result<(i32, usize), Errno> {
    let (negative, value, consumed) = scan(buf)?;
    let value = if negative {
        if value > i32::MAX as u64 + 1 {
            return Err(Errno::EINVAL);
        }
        (value as i64).wrapping_neg() as i32
    } else {
        i32::try_from(value).map_err(|_| Errno::EINVAL)?
    };
    if let Some((least, most)) = bounds
        && !(least..=most).contains(&value)
    {
        return Err(Errno::EINVAL);
    }
    Ok((value, consumed))
}

/// The `int`s of a vector written to a sysctl, as Linux's
/// `__do_proc_dointvec` reads them into `values`: each as [`parse`] reads
/// one, until the end or the last of `values`. A bad one ends it with
/// `EINVAL`, the ones before it kept; none at all is `EINVAL` too. The
/// bytes taken, the spaces after the last one too.
fn parse_ints(buf: &[u8], values: &mut [i32]) -> Result<usize, Errno> {
    let buf = &buf[..buf.len().min(4095)];
    let mut at = 0;
    for (n, value) in values.iter_mut().enumerate() {
        at += buf[at..].iter().take_while(|&&b| space(b)).count();
        if at == buf.len() {
            return if n == 0 { Err(Errno::EINVAL) } else { Ok(at) };
        }
        let (parsed, consumed) = parse(&buf[at..], None)?;
        *value = parsed;
        at += consumed;
    }
    Ok(at)
}

/// `strtoul` with base 0 on digits that start with a digit: 16 after `0x`
/// followed by a hexadecimal digit, 8 after another `0`, else 10. The value
/// and the characters it took; none when it overflows.
fn strtoul(digits: &[u8]) -> Option<(u64, usize)> {
    let (radix, start) = match digits {
        [b'0', b'x' | b'X', next, ..] if next.is_ascii_hexdigit() => (16, 2),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let mut value: u64 = 0;
    let mut at = start;
    while let Some(digit) = digits.get(at).and_then(|&b| char::from(b).to_digit(radix)) {
        value = value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))?;
        at += 1;
    }
    Some((value, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_the_directories_and_settings() {
        assert_eq!(entry(b"/proc/sys"), Some(Entry::Directory(Directory::Sys)));
        assert_eq!(entry(b"/proc/sys/"), Some(Entry::Directory(Directory::Sys)));
        assert_eq!(
            entry(b"/proc/sys/fs"),
            Some(Entry::Directory(Directory::Fs))
        );
        assert_eq!(
            entry(b"/proc/sys/fs/mqueue/"),
            Some(Entry::Directory(Directory::Mqueue))
        );
        assert_eq!(
            entry(b"/proc/sys/fs/mqueue/msg_max"),
            Some(Entry::Setting(Setting::MsgMax))
        );
        assert_eq!(entry(b"/proc/sys/fs/mqueue/other"), None);
        assert_eq!(
            entry(b"/proc/sys/fs/aio-max-nr"),
            Some(Entry::Aio(Aio::MaxNr))
        );
        assert_eq!(entry(b"/proc/sys/fs/aio-nr"), Some(Entry::Aio(Aio::Nr)));
        assert_eq!(entries(Directory::Fs).len(), 7);
        assert_eq!(
            entry(b"/proc/sys/fs/inotify"),
            Some(Entry::Directory(Directory::Inotify))
        );
        assert_eq!(
            entry(b"/proc/sys/fs/inotify/max_user_watches"),
            Some(Entry::Inotify(Inotify::UserWatches))
        );
        assert_eq!(entry(b"/proc/sys/fs/inotify/other"), None);
        assert_eq!(entries(Directory::Inotify).len(), 5);
        assert_eq!(entries(Directory::Fanotify).len(), 6);
        assert_eq!(
            entry(b"/proc/sys/fs/fanotify/max_user_marks"),
            Some(Entry::Fanotify(Fanotify::UserMarks))
        );
        assert_eq!(entry(b"/proc/sys/fs/fanotify/other"), None);
        assert_eq!(
            entry(b"/proc/sys/kernel"),
            Some(Entry::Directory(Directory::Kernel))
        );
        assert_eq!(
            entry(b"/proc/sys/kernel/sem"),
            Some(Entry::Kernel(Kernel::Sem))
        );
        assert_eq!(entry(b"/proc/sys/kernel/other"), None);
        assert_eq!(entries(Directory::Sys).len(), 4);
        assert_eq!(entries(Directory::Kernel).len(), 11);
        assert_eq!(entry(b"/proc/system"), None);
        assert_eq!(entries(Directory::Mqueue).len(), 7);
    }

    #[test]
    fn writes_read_one_int_as_linux_does() {
        let any = None;
        assert_eq!(parse(b"20\n", any), Ok((20, 3)));
        assert_eq!(parse(b"  7  \n", any), Ok((7, 6)));
        assert_eq!(parse(b"5 6\n", any), Ok((5, 2)));
        assert_eq!(parse(b"0x10", any), Ok((16, 4)));
        assert_eq!(parse(b"010", any), Ok((8, 3)));
        assert_eq!(parse(b"0", any), Ok((0, 1)));
        assert_eq!(parse(b"-5", any), Ok((-5, 2)));
        assert_eq!(parse(b"-2147483648", any), Ok((i32::MIN, 11)));
        for bad in [
            &b""[..],
            b" \n",
            b"abc",
            b"-",
            b"- 1",
            b"5x",
            b"09",
            b"0x",
            b"2147483648",
            b"-2147483649",
            b"99999999999999999999999",
            b"000000000000000000001",
            b"5\0",
        ] {
            assert_eq!(parse(bad, any), Err(Errno::EINVAL), "{bad:?}");
        }
        let bounded = Some((1, 65536));
        assert_eq!(parse(b"65536", bounded), Ok((65536, 5)));
        assert_eq!(parse(b"0", bounded), Err(Errno::EINVAL));
        assert_eq!(parse(b"65537", bounded), Err(Errno::EINVAL));
        // An unsigned long takes all 64 bits, and a sign is seen.
        assert_eq!(scan(b"18446744073709551615\n"), Ok((false, u64::MAX, 21)));
        assert_eq!(scan(b"-1"), Ok((true, 1, 2)));
        assert_eq!(scan(b"18446744073709551616"), Err(Errno::EINVAL));
    }

    #[test]
    fn a_vector_takes_the_ints_given_and_keeps_those_before_a_bad_one() {
        let mut values = [1, 2, 3, 4];
        assert_eq!(parse_ints(b"10\t20\t5\t3\n", &mut values), Ok(10));
        assert_eq!(values, [10, 20, 5, 3]);
        assert_eq!(parse_ints(b"  6  7  ", &mut values), Ok(8));
        assert_eq!(values, [6, 7, 5, 3]);
        // Past the last value the rest is not taken.
        assert_eq!(parse_ints(b"11 22 33 1 99", &mut values), Ok(11));
        assert_eq!(values, [11, 22, 33, 1]);
        assert_eq!(parse_ints(b"8 9 x", &mut values), Err(Errno::EINVAL));
        assert_eq!(values, [8, 9, 33, 1]);
        assert_eq!(parse_ints(b"-1", &mut values), Ok(2));
        assert_eq!(values[0], -1);
        for none in [&b""[..], b" \n"] {
            assert_eq!(parse_ints(none, &mut values), Err(Errno::EINVAL));
        }
    }
}
