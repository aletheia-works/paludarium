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
//! owners and who may write them are the mqueue files'. So are those of
//! `shm_rmid_forced`, 0 or 1, which removes the orphaned segments no mapping
//! shows once set ([`crate::shm::Segments::set_rmid_forced`]), and
//! `auto_msgmni`, which reads 0 and takes 0 or 1 to no effect. Each
//! `*_next_id` (`shm`, `sem`, `msg`) is the ID the next object of its kind
//! takes, -1 for none, which a write from 0 sets: mode 0444, which
//! `ipc_permissions` makes 0666 for whoever has `CAP_CHECKPOINT_RESTORE` or
//! `CAP_SYS_ADMIN` over the namespace's user namespace. Beside them are the
//! machine's `perf_cpu_time_max_percent`, `perf_event_max_sample_rate`,
//! `perf_event_mlock_kb`, `perf_event_paranoid` and
//! `unprivileged_bpf_disabled` ([`Machine`]), which [`crate::perf`] and
//! [`crate::bpf`] check: root's files of mode 0644, which only root opens to
//! write. `perf_event_mlock_kb` and `perf_event_paranoid` take any `int`
//! (`proc_dointvec`); `perf_cpu_time_max_percent` 0 to 100, and
//! `perf_event_max_sample_rate` 1 or more, refused (`EINVAL`) while
//! `perf_cpu_time_max_percent` is 0 or 100, as Linux's
//! `perf_event_max_sample_rate_handler`;
//! `unprivileged_bpf_disabled` takes 0 to 2 from a writer with
//! `CAP_SYS_ADMIN` (`EPERM`), and once 1 it stays (`EPERM`), as Linux's
//! `bpf_unpriv_handler`.
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
//! (`mq_permissions`, `EACCES`). A write asks the writer again, as Linux's
//! `proc_sys_call_handler` does (`EPERM`) ([`write`], [`write_as`]). Each
//! file has an inode of its own and a size of 0 ([`stat`]), so, as on
//! Linux, `copy_file_range` never writes one: from another filesystem it is
//! `EXDEV`, and from a sysctl it copies nothing.
use crate::ipc::IPCMNI;
use crate::mqueue::{HARD_MSGMAX, HARD_MSGSIZEMAX, Limits, Queues};
use crate::namespaces::Namespace;
use crate::netconf::Target;
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
    /// `net`, and in it `ipv4`, `ipv6`, their `conf` and a device's
    /// directory in each.
    Net,
    Ipv4,
    Ipv6,
    Conf4,
    Conf6,
    Device4(Target),
    Device6(Target),
}

impl Directory {
    /// Whether it is one of `/proc/sys/net`'s, which belong to the root of
    /// the user namespace that owns the network namespace
    /// (`net_ctl_set_ownership`).
    fn net(self) -> bool {
        matches!(
            self,
            Self::Net
                | Self::Ipv4
                | Self::Ipv6
                | Self::Conf4
                | Self::Conf6
                | Self::Device4(_)
                | Self::Device6(_)
        )
    }
}

/// A file of `/proc/sys/net`, of the caller's network namespace
/// ([`crate::netconf`]): `ipv4/ip_forward` (`all`'s forwarding),
/// `ipv4/conf/<device>/forwarding` and `rp_filter`, and
/// `ipv6/conf/<device>/disable_ipv6` and `forwarding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Net {
    IpForward,
    Forwarding(Target),
    RpFilter(Target),
    DisableIpv6(Target),
    Forwarding6(Target),
}

/// A file of a device's directory, by name, and what it is for a device.
type DeviceFile = (&'static [u8], fn(Target) -> Net);
/// The files of a device's directory of `ipv4/conf` and `ipv6/conf`, in
/// Linux's order.
const CONF4: [DeviceFile; 2] = [
    (b"forwarding", Net::Forwarding),
    (b"rp_filter", Net::RpFilter),
];
const CONF6: [DeviceFile; 2] = [
    (b"disable_ipv6", Net::DisableIpv6),
    (b"forwarding", Net::Forwarding6),
];

/// A file of `/proc/sys/fs/mqueue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Setting {
    MsgDefault,
    MsgMax,
    MsgsizeDefault,
    MsgsizeMax,
    QueuesMax,
}

/// The settings by name, in the order Linux lists them: a directory's
/// entries by name, as its tree keeps them (`namecmp`, which puts a name
/// before a longer one it begins).
const SETTINGS: [(&[u8], Setting); 5] = [
    (b"msg_default", Setting::MsgDefault),
    (b"msg_max", Setting::MsgMax),
    (b"msgsize_default", Setting::MsgsizeDefault),
    (b"msgsize_max", Setting::MsgsizeMax),
    (b"queues_max", Setting::QueuesMax),
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
    AutoMsgmni,
    MsgNextId,
    Msgmax,
    Msgmnb,
    Msgmni,
    PerfCpuTimeMaxPercent,
    PerfEventMaxSampleRate,
    PerfEventMlockKb,
    PerfEventParanoid,
    Sem,
    SemNextId,
    ShmNextId,
    ShmRmidForced,
    Shmall,
    Shmmax,
    Shmmni,
    UnprivilegedBpfDisabled,
}

/// The `/proc/sys/kernel` files by name, in the order Linux lists them (by
/// name).
const KERNEL: [(&[u8], Kernel); 17] = [
    (b"auto_msgmni", Kernel::AutoMsgmni),
    (b"msg_next_id", Kernel::MsgNextId),
    (b"msgmax", Kernel::Msgmax),
    (b"msgmnb", Kernel::Msgmnb),
    (b"msgmni", Kernel::Msgmni),
    (b"perf_cpu_time_max_percent", Kernel::PerfCpuTimeMaxPercent),
    (
        b"perf_event_max_sample_rate",
        Kernel::PerfEventMaxSampleRate,
    ),
    (b"perf_event_mlock_kb", Kernel::PerfEventMlockKb),
    (b"perf_event_paranoid", Kernel::PerfEventParanoid),
    (b"sem", Kernel::Sem),
    (b"sem_next_id", Kernel::SemNextId),
    (b"shm_next_id", Kernel::ShmNextId),
    (b"shm_rmid_forced", Kernel::ShmRmidForced),
    (b"shmall", Kernel::Shmall),
    (b"shmmax", Kernel::Shmmax),
    (b"shmmni", Kernel::Shmmni),
    (
        b"unprivileged_bpf_disabled",
        Kernel::UnprivilegedBpfDisabled,
    ),
];

impl Kernel {
    /// Whether it is one of the IPC namespace's limits; else it is the
    /// machine's ([`Machine`]).
    fn ipc(self) -> bool {
        !matches!(
            self,
            Self::PerfCpuTimeMaxPercent
                | Self::PerfEventMaxSampleRate
                | Self::PerfEventMlockKb
                | Self::PerfEventParanoid
                | Self::UnprivilegedBpfDisabled
        )
    }
    /// Whether it is one of the IPC namespace's next IDs.
    fn next_id(self) -> bool {
        matches!(self, Self::MsgNextId | Self::SemNextId | Self::ShmNextId)
    }
}

/// The machine's `kernel.perf_cpu_time_max_percent`,
/// `kernel.perf_event_max_sample_rate`, `kernel.perf_event_mlock_kb`,
/// `kernel.perf_event_paranoid` and `kernel.unprivileged_bpf_disabled`, one
/// each for the whole emulated machine as Linux's are for the whole kernel,
/// at Linux's defaults at first.
pub(crate) struct Machine {
    perf_cpu_time_max_percent: AtomicI32,
    perf_event_max_sample_rate: AtomicI32,
    perf_event_mlock_kb: AtomicI32,
    perf_event_paranoid: AtomicI32,
    unprivileged_bpf_disabled: AtomicI32,
}

impl Default for Machine {
    fn default() -> Self {
        Self {
            perf_cpu_time_max_percent: AtomicI32::new(crate::perf::CPU_TIME_MAX_PERCENT),
            perf_event_max_sample_rate: AtomicI32::new(crate::perf::MAX_SAMPLE_RATE),
            perf_event_mlock_kb: AtomicI32::new(crate::perf::MLOCK_KB),
            perf_event_paranoid: AtomicI32::new(crate::perf::PARANOID),
            unprivileged_bpf_disabled: AtomicI32::new(crate::bpf::UNPRIVILEGED_DISABLED),
        }
    }
}

impl Machine {
    /// What `perf_event_open` checks (`sysctl_perf_event_paranoid`).
    pub(crate) fn perf_event_paranoid(&self) -> i32 {
        self.perf_event_paranoid.load(Ordering::SeqCst)
    }
    /// What a ring buffer's `mmap` may lock of a user's, per CPU
    /// (`sysctl_perf_event_mlock`), in KiB.
    pub(crate) fn perf_event_mlock_kb(&self) -> i32 {
        self.perf_event_mlock_kb.load(Ordering::SeqCst)
    }
    /// The highest frequency a sampling event may ask for
    /// (`sysctl_perf_event_sample_rate`).
    pub(crate) fn perf_event_max_sample_rate(&self) -> u64 {
        self.perf_event_max_sample_rate.load(Ordering::SeqCst) as u64
    }
    /// The interrupts of an event in one tick that throttle it
    /// (`max_samples_per_tick`): the sample rate over `HZ`, rounded up.
    pub(crate) fn perf_max_samples_per_tick(&self) -> u64 {
        const HZ: u64 = 1_000_000_000 / crate::threads::TICK_NSEC;
        self.perf_event_max_sample_rate().div_ceil(HZ)
    }
    /// What `bpf` checks (`sysctl_unprivileged_bpf_disabled`).
    pub(crate) fn unprivileged_bpf_disabled(&self) -> i32 {
        self.unprivileged_bpf_disabled.load(Ordering::SeqCst)
    }
    fn line(&self, file: Kernel) -> Vec<u8> {
        line(match file {
            Kernel::PerfCpuTimeMaxPercent => self.perf_cpu_time_max_percent.load(Ordering::SeqCst),
            Kernel::PerfEventMaxSampleRate => {
                self.perf_event_max_sample_rate.load(Ordering::SeqCst)
            }
            Kernel::PerfEventMlockKb => self.perf_event_mlock_kb(),
            Kernel::PerfEventParanoid => self.perf_event_paranoid(),
            _ => self.unprivileged_bpf_disabled(),
        })
    }
    /// Takes a value written at the start of the file, by a writer with
    /// `CAP_SYS_ADMIN` (`admin`) or without.
    fn write(&self, file: Kernel, buf: &[u8], admin: bool) -> Result<usize, Errno> {
        // Both take any `int` (`proc_dointvec`).
        if let Some(sysctl) = match file {
            Kernel::PerfEventMlockKb => Some(&self.perf_event_mlock_kb),
            Kernel::PerfEventParanoid => Some(&self.perf_event_paranoid),
            _ => None,
        } {
            let (value, consumed) = parse(buf, None)?;
            sysctl.store(value, Ordering::SeqCst);
            return Ok(consumed);
        }
        match file {
            // `perf_cpu_time_max_percent_handler`: 0 to 100, where 0 and
            // 100 turn off the lowering of the sample rate that the
            // emulator does not do (`perf_sample_event_took`).
            Kernel::PerfCpuTimeMaxPercent => {
                let (value, consumed) = parse(buf, Some((0, 100)))?;
                self.perf_cpu_time_max_percent
                    .store(value, Ordering::SeqCst);
                return Ok(consumed);
            }
            // `perf_event_max_sample_rate_handler`: refused before it is
            // read while that lowering is off, then 1 or more.
            Kernel::PerfEventMaxSampleRate => {
                if matches!(
                    self.perf_cpu_time_max_percent.load(Ordering::SeqCst),
                    0 | 100
                ) {
                    return Err(Errno::EINVAL);
                }
                let (value, consumed) = parse(buf, Some((1, i32::MAX)))?;
                self.perf_event_max_sample_rate
                    .store(value, Ordering::SeqCst);
                return Ok(consumed);
            }
            _ => {}
        }
        // `bpf_unpriv_handler`.
        if !admin {
            return Err(Errno::EPERM);
        }
        let (value, consumed) = parse(buf, Some((0, 2)))?;
        // Once 1, it stays: checked and set in one step, so that writers at
        // once cannot take it from 1.
        self.unprivileged_bpf_disabled
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                (now != 1 || value == 1).then_some(value)
            })
            .map_err(|_| Errno::EPERM)?;
        Ok(consumed)
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
    Net(Net),
}

/// The entry under `/proc/sys/net` that `rest` (the path after it) names,
/// whose devices are `network`'s.
fn net_entry(rest: &[u8], network: &crate::inet::Network) -> Option<Entry> {
    let directory = |d| Some(Entry::Directory(d));
    match rest {
        b"" => return directory(Directory::Net),
        b"/ipv4" => return directory(Directory::Ipv4),
        b"/ipv6" => return directory(Directory::Ipv6),
        b"/ipv4/conf" => return directory(Directory::Conf4),
        b"/ipv6/conf" => return directory(Directory::Conf6),
        b"/ipv4/ip_forward" => return Some(Entry::Net(Net::IpForward)),
        _ => {}
    }
    let (v6, rest) = if let Some(rest) = rest.strip_prefix(b"/ipv4/conf/") {
        (false, rest)
    } else {
        (true, rest.strip_prefix(b"/ipv6/conf/")?)
    };
    let (name, file) = match rest.iter().position(|&b| b == b'/') {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    };
    let device = match name {
        b"all" => Target::All,
        b"default" => Target::Default,
        _ => Target::Device(network.devices().by_name(name)?.index),
    };
    let Some(file) = file else {
        return directory(if v6 {
            Directory::Device6(device)
        } else {
            Directory::Device4(device)
        });
    };
    let files: &[DeviceFile] = if v6 { &CONF6 } else { &CONF4 };
    files
        .iter()
        .find(|(known, _)| *known == file)
        .map(|&(_, make)| Entry::Net(make(device)))
}

/// The entry `path` names, if it is one of these, for the caller, whose
/// network namespace `/proc/sys/net` shows.
pub(crate) fn entry(c: &Context<'_>, path: &[u8]) -> Option<Entry> {
    lookup(path, c.network().as_deref())
}

/// The entry `path` names, with `/proc/sys/net` that of `network`, which
/// has none without one.
fn lookup(path: &[u8], network: Option<&crate::inet::Network>) -> Option<Entry> {
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
            if let Some(rest) = rest.strip_prefix(b"/net")
                && (rest.is_empty() || rest.starts_with(b"/"))
            {
                return net_entry(rest, network?);
            }
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

/// The entries of `directory`, for the caller.
pub(crate) fn entries(c: &Context<'_>, directory: Directory) -> Vec<DirectoryEntry> {
    entries_of(directory, c.network().as_deref())
}

/// The entries of `directory`, a device directory's being `network`'s
/// devices after `all` and `default`, all by name, as Linux's tree of
/// them keeps them.
fn entries_of(directory: Directory, network: Option<&crate::inet::Network>) -> Vec<DirectoryEntry> {
    let mut devices: Vec<Vec<u8>> = vec![b"all".to_vec(), b"default".to_vec()];
    if let Some(network) = network {
        devices.extend(network.devices().iter().map(|d| d.name.clone()));
    }
    devices.sort();
    let names: Vec<(&[u8], u8)> = match directory {
        Directory::Sys => vec![(b"fs", DT_DIR), (b"kernel", DT_DIR), (b"net", DT_DIR)],
        Directory::Net => vec![(b"ipv4", DT_DIR), (b"ipv6", DT_DIR)],
        Directory::Ipv4 => vec![(b"conf", DT_DIR), (b"ip_forward", DT_REG)],
        Directory::Ipv6 => vec![(b"conf", DT_DIR)],
        Directory::Conf4 | Directory::Conf6 => devices
            .iter()
            .map(|name| (name.as_slice(), DT_DIR))
            .collect(),
        Directory::Device4(_) => CONF4.iter().map(|&(name, _)| (name, DT_REG)).collect(),
        Directory::Device6(_) => CONF6.iter().map(|&(name, _)| (name, DT_REG)).collect(),
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
    // Each entry's number is the inode its `stat` gives, as Linux's
    // `proc_sys_fill_cache` gives `d_ino`; `..` of `/proc/sys` keeps its
    // place, `/proc` not being one of these.
    let dots = [
        (&b"."[..], DT_DIR, Some(Entry::Directory(directory))),
        (b"..", DT_DIR, parent(directory).map(Entry::Directory)),
    ];
    dots.into_iter()
        .chain(
            names
                .into_iter()
                .map(|(name, kind)| (name, kind, child(directory, name, network))),
        )
        .enumerate()
        .map(|(i, (name, kind, entry))| DirectoryEntry {
            name: name.to_vec(),
            inode: entry.map_or(i as u64 + 1, inode),
            kind,
        })
        .collect()
}

/// The directory `directory` is in, none for `/proc/sys`.
fn parent(directory: Directory) -> Option<Directory> {
    Some(match directory {
        Directory::Sys => return None,
        Directory::Fs | Directory::Kernel | Directory::Net => Directory::Sys,
        Directory::Mqueue | Directory::Inotify | Directory::Fanotify => Directory::Fs,
        Directory::Ipv4 | Directory::Ipv6 => Directory::Net,
        Directory::Conf4 => Directory::Ipv4,
        Directory::Conf6 => Directory::Ipv6,
        Directory::Device4(_) => Directory::Conf4,
        Directory::Device6(_) => Directory::Conf6,
    })
}

/// The entry `name` in `directory` is, as [`entries_of`] lists it.
fn child(
    directory: Directory,
    name: &[u8],
    network: Option<&crate::inet::Network>,
) -> Option<Entry> {
    let dir = |d| Some(Entry::Directory(d));
    let find = |table: &[(&[u8], Entry)]| {
        table
            .iter()
            .find(|(known, _)| *known == name)
            .map(|&(_, entry)| entry)
    };
    match directory {
        Directory::Sys => match name {
            b"fs" => dir(Directory::Fs),
            b"kernel" => dir(Directory::Kernel),
            b"net" => dir(Directory::Net),
            _ => None,
        },
        Directory::Net => match name {
            b"ipv4" => dir(Directory::Ipv4),
            b"ipv6" => dir(Directory::Ipv6),
            _ => None,
        },
        Directory::Ipv4 => match name {
            b"conf" => dir(Directory::Conf4),
            b"ip_forward" => Some(Entry::Net(Net::IpForward)),
            _ => None,
        },
        Directory::Ipv6 => (name == b"conf").then_some(Entry::Directory(Directory::Conf6)),
        Directory::Conf4 | Directory::Conf6 => {
            let target = match name {
                b"all" => Target::All,
                b"default" => Target::Default,
                _ => Target::Device(network?.devices().by_name(name)?.index),
            };
            dir(if directory == Directory::Conf4 {
                Directory::Device4(target)
            } else {
                Directory::Device6(target)
            })
        }
        Directory::Device4(target) | Directory::Device6(target) => {
            let files: &[DeviceFile] = if matches!(directory, Directory::Device4(_)) {
                &CONF4
            } else {
                &CONF6
            };
            files
                .iter()
                .find(|(known, _)| *known == name)
                .map(|&(_, make)| Entry::Net(make(target)))
        }
        Directory::Fs => match name {
            b"aio-max-nr" => Some(Entry::Aio(Aio::MaxNr)),
            b"aio-nr" => Some(Entry::Aio(Aio::Nr)),
            b"fanotify" => dir(Directory::Fanotify),
            b"inotify" => dir(Directory::Inotify),
            b"mqueue" => dir(Directory::Mqueue),
            _ => None,
        },
        Directory::Mqueue => find(&SETTINGS.map(|(n, s)| (n, Entry::Setting(s)))),
        Directory::Inotify => find(&INOTIFY.map(|(n, f)| (n, Entry::Inotify(f)))),
        Directory::Fanotify => find(&FANOTIFY.map(|(n, f)| (n, Entry::Fanotify(f)))),
        Directory::Kernel => find(&KERNEL.map(|(n, f)| (n, Entry::Kernel(f)))),
    }
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

/// The root of the user namespace that owns the caller's network
/// namespace, whom `/proc/sys/net` belongs to (`net_ctl_set_ownership`).
fn net_owner(c: &Context<'_>) -> (u32, u32) {
    let namespaces = c.group.namespaces(c.tid);
    let user = namespaces.net.owner();
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
        Kernel::AutoMsgmni => line(0),
        Kernel::ShmRmidForced => line(ipc.shm.with_limits(|limits| limits.rmid_forced)),
        Kernel::ShmNextId => line(ipc.shm.with_ids(|ids| ids.next_id())),
        Kernel::SemNextId => line(ipc.sem.with_ids(|ids| ids.next_id())),
        Kernel::MsgNextId => line(ipc.msg.with_ids(|ids| ids.next_id())),
        // The machine's ([`Machine`]), which are not the namespace's.
        Kernel::PerfCpuTimeMaxPercent
        | Kernel::PerfEventMaxSampleRate
        | Kernel::PerfEventMlockKb
        | Kernel::PerfEventParanoid
        | Kernel::UnprivilegedBpfDisabled => Vec::new(),
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
        // `proc_ipc_auto_msgmni`: 0 or 1, to no effect.
        Kernel::AutoMsgmni => Ok(parse(buf, Some((0, 1)))?.1),
        // `proc_ipc_dointvec_minmax_orphans`.
        Kernel::ShmRmidForced => {
            let (value, consumed) = parse(buf, Some((0, 1)))?;
            ipc.shm.set_rmid_forced(value);
            Ok(consumed)
        }
        Kernel::ShmNextId | Kernel::SemNextId | Kernel::MsgNextId => {
            let (value, consumed) = parse(buf, int)?;
            let set = |ids: &mut crate::ipc::Ids| ids.set_next_id(value);
            match file {
                Kernel::ShmNextId => ipc.shm.with_ids(set),
                Kernel::SemNextId => ipc.sem.with_ids(set),
                _ => ipc.msg.with_ids(set),
            }
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
        Kernel::PerfCpuTimeMaxPercent
        | Kernel::PerfEventMaxSampleRate
        | Kernel::PerfEventMlockKb
        | Kernel::PerfEventParanoid
        | Kernel::UnprivilegedBpfDisabled => Err(Errno::EINVAL),
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

/// The status of `entry`, as Linux's `proc_sys_make_inode` gives it: an
/// inode of its own ([`inode`]), and for a file a size of 0, whatever its
/// value's length, so that `copy_file_range` from it copies nothing.
pub(crate) fn stat(c: &Context<'_>, entry: Entry) -> FileStat {
    let mut stat = shown(c, entry);
    stat.inode = inode(entry);
    if stat.mode & 0o170_000 == 0o100_000 {
        stat.size = 0;
    }
    stat
}

/// An inode number for `entry`, the same at each `stat` and another for
/// each entry: Linux numbers each sysctl's inode as it makes it
/// (`get_next_ino`), so only that it is its own is compared. An FNV-1a
/// hash of the entry, kept to 32 bits and above the small numbers.
fn inode(entry: Entry) -> u64 {
    let hash = format!("{entry:?}")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    (hash % 0xffff_0000) + 0x1_0000
}

/// The status of `entry`: a directory anyone may read and search, a
/// regular file of mode 0644, its owner's root's, or an aio file, root's,
/// 0644 or for `aio-nr` 0444.
fn shown(c: &Context<'_>, entry: Entry) -> FileStat {
    match entry {
        Entry::Directory(directory) if directory.net() => {
            let (uid, gid) = net_owner(c);
            FileStat {
                uid,
                gid,
                ..crate::proc::directory_stat()
            }
        }
        Entry::Directory(_) => crate::proc::directory_stat(),
        Entry::Net(file) => {
            let (uid, gid) = net_owner(c);
            FileStat {
                mode: 0o100_644,
                uid,
                gid,
                ..crate::proc::stat(
                    c.network()
                        .map_or(0, |network| line(net_value(&network, file)).len()),
                )
            }
        }
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
            mode: 0o100_644,
            ..crate::proc::stat(c.processes.sysctls.line(file).len())
        },
        Entry::Kernel(file) => {
            let (uid, gid) = owner(c);
            FileStat {
                mode: if file.next_id() { 0o100_444 } else { 0o100_644 },
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

/// What a file of `/proc/sys/net` of `network` shows: 0 for a device it
/// no longer has.
fn net_value(network: &crate::inet::Network, file: Net) -> i32 {
    let target = match file {
        Net::IpForward => Target::All,
        Net::Forwarding(target)
        | Net::RpFilter(target)
        | Net::DisableIpv6(target)
        | Net::Forwarding6(target) => target,
    };
    let Some((conf4, conf6)) = crate::netconf::get(&network.devices(), target) else {
        return 0;
    };
    match file {
        Net::IpForward | Net::Forwarding(_) => conf4.forwarding,
        Net::RpFilter(_) => conf4.rp_filter,
        Net::DisableIpv6(_) => conf6.disable_ipv6,
        Net::Forwarding6(_) => conf6.forwarding,
    }
}

/// Opens `entry` with `flags`: a directory only to read (`EISDIR`), a
/// setting to write only by the root of the namespace's owner (`EACCES`),
/// as `mq_permissions` lets the owner's root have the owner's bits and
/// everyone else the others', and so a `/proc/sys/kernel` IPC limit
/// (`ipc_permissions`); the machine's `perf_event_mlock_kb`,
/// `perf_event_paranoid` and `unprivileged_bpf_disabled` to write only by
/// root (`EACCES`), as
/// `test_perm` gives the root user ID the owner's bits.
pub(crate) fn open(
    c: &Context<'_>,
    entry: Entry,
    flags: u32,
) -> Result<Arc<dyn FileHandle>, Errno> {
    let (value, writers) = match entry {
        Entry::Directory(_) if flags & 3 != 0 => return Err(Errno::EISDIR),
        Entry::Directory(_) => {
            return Ok(Arc::new(crate::proc::OwnDirectory::new(
                crate::proc::directory_stat(),
            )));
        }
        Entry::Setting(setting) => (
            Value::Mqueue(queues(c), setting),
            Writers::Owner(owner(c).0),
        ),
        // The machine's: root's, which only root may open to write.
        Entry::Kernel(file) if !file.ipc() => (
            Value::Machine(Arc::clone(&c.processes.sysctls), file),
            Writers::Root,
        ),
        Entry::Kernel(file) if file.next_id() => {
            (Value::Kernel(ipc(c), file), Writers::Restorer(ipc(c)))
        }
        Entry::Kernel(file) => (Value::Kernel(ipc(c), file), Writers::Owner(owner(c).0)),
        Entry::Inotify(file) => (
            Value::Inotify(Arc::clone(&c.files.caches.notify), file),
            Writers::Root,
        ),
        // `net_ctl_permissions`: whoever has `CAP_NET_ADMIN` over the
        // namespace has the owner's bits, and so has root (`test_perm`).
        Entry::Net(file) => (
            Value::Net(NetFile {
                file,
                network: c.network().ok_or(Errno::ENOENT)?,
                host: Arc::clone(c.shared_host),
            }),
            Writers::NetAdmin(Arc::clone(&c.group.namespaces(c.tid).net)),
        ),
        Entry::Fanotify(file) => (
            Value::Fanotify(Arc::clone(&c.files.caches.notify.fan), file),
            Writers::Root,
        ),
        // `test_perm`: root has the owner's bits, everyone else the others'.
        Entry::Aio(aio) => (
            Value::Aio(Arc::clone(&c.processes.aio), aio),
            if aio == Aio::Nr {
                Writers::None
            } else {
                Writers::Root
            },
        ),
    };
    let credentials = &c.process.credentials;
    if flags & 3 != 0 && !writers.allow(credentials) {
        return Err(Errno::EACCES);
    }
    let net_admin = writers.net_admin(credentials);
    Ok(Arc::new(SettingFile {
        value,
        admin: credentials.capable(crate::credentials::CAP_SYS_ADMIN),
        net_admin,
        writers,
        stat: stat(c, entry),
        position: Mutex::new(0),
        flags,
    }))
}

/// Who may write an open sysctl file, which Linux's `sysctl_perm` asks at
/// the open (`EACCES`) and again at each write (`proc_sys_call_handler`,
/// `EPERM`).
enum Writers {
    /// No one (`aio-nr`).
    None,
    /// Root: user ID 0 outside any user namespace (`test_perm`).
    Root,
    /// The root of the user namespace that owns the IPC namespace, by its
    /// user ID (`mq_permissions`, `ipc_permissions`).
    Owner(u32),
    /// Whoever has `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN` over the user
    /// namespace that owns this IPC namespace (`ipc_permissions` for the
    /// `*_next_id` files).
    Restorer(Arc<Namespace>),
    /// Root, or whoever has `CAP_NET_ADMIN` over the user namespace that
    /// owns this network namespace (`net_ctl_permissions`).
    NetAdmin(Arc<Namespace>),
}

impl Writers {
    fn allow(&self, credentials: &crate::credentials::Credentials) -> bool {
        match self {
            Self::None => false,
            Self::Root => credentials.euid == 0,
            Self::Owner(uid) => credentials.euid == *uid,
            Self::Restorer(ipc) => {
                let owner = ipc.owner();
                credentials.capable_in(crate::credentials::CAP_CHECKPOINT_RESTORE, owner)
                    || credentials.capable_in(crate::credentials::CAP_SYS_ADMIN, owner)
            }
            Self::NetAdmin(_) => credentials.euid == 0 || self.net_admin(credentials),
        }
    }
    /// Whether `credentials` have `CAP_NET_ADMIN` over the network
    /// namespace, which IPv4's `forwarding` asks of its writer
    /// (`devinet_sysctl_forward`); never for another file.
    fn net_admin(&self, credentials: &crate::credentials::Credentials) -> bool {
        const CAP_NET_ADMIN: u64 = 1 << 12;
        match self {
            Self::NetAdmin(net) => credentials.capable_in(CAP_NET_ADMIN, net.owner()),
            _ => false,
        }
    }
}

/// A write of an open sysctl file by the calling thread, whom Linux's
/// `proc_sys_call_handler` checks again (`EPERM`): one the open let write
/// may since have lost the right, and `unprivileged_bpf_disabled` asks for
/// `CAP_SYS_ADMIN` of the writer, not the opener.
pub(crate) fn write(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    buf: &[u8],
) -> Option<Result<u64, Errno>> {
    Some(write_as(file, buf, &c.process.credentials)?.map(|n| n as u64))
}

/// A write of an open sysctl file by `writer`, checked again as [`write`]
/// checks the calling thread; a positioned write (`pwrite64`, `pwritev`,
/// `splice`) comes this way, at the position it moved the file to.
pub(crate) fn write_as(
    file: &Arc<dyn FileHandle>,
    buf: &[u8],
    writer: &crate::credentials::Credentials,
) -> Option<Result<usize, Errno>> {
    let setting = file.as_any()?.downcast_ref::<SettingFile>()?;
    Some(setting.write_by(buf, Some(writer)))
}

/// What an open sysctl file shows.
enum Value {
    Mqueue(Queues, Setting),
    Aio(Arc<crate::aio::Limits>, Aio),
    Inotify(Arc<crate::inotify::Notifier>, Inotify),
    Fanotify(Arc<crate::fanotify::Registry>, Fanotify),
    Kernel(Arc<Namespace>, Kernel),
    /// The machine's.
    Machine(Arc<Machine>, Kernel),
    Net(NetFile),
}

/// A file of `/proc/sys/net` as opened: of the opener's network
/// namespace, whose devices have the settings and follow them.
struct NetFile {
    file: Net,
    network: Arc<crate::inet::Network>,
    host: Arc<dyn paludarium_host::Host>,
}

impl NetFile {
    /// A write of `buf` at `position` by a writer with `CAP_NET_ADMIN`
    /// over the namespace (`net_admin`) or without, as each handler takes
    /// it: what the write returns.
    /// - IPv4's `forwarding` (`devinet_sysctl_forward`) is `EPERM` without
    ///   `CAP_NET_ADMIN`, then takes an `int` as `proc_dointvec` does.
    /// - `rp_filter` (`devinet_conf_proc`) takes one so, and marks the
    ///   device as set whatever comes of it.
    /// - IPv6's (`addrconf_sysctl_disable`, `addrconf_sysctl_forward`) take
    ///   one so too, as Linux master's handlers do (7.0's left a bad value
    ///   unreported, and had `forwarding` of `all` or a device return 1).
    fn take(&self, buf: &[u8], position: &mut u64, net_admin: bool) -> Result<usize, Errno> {
        // `proc_first_pos_non_zero_ignore`: past the start, a write is
        // taken whole and sets nothing.
        let parsed = if *position != 0 {
            Err(true)
        } else {
            parse(buf, None).map_err(|_| false)
        };
        let advance = |position: &mut u64, by: usize| {
            *position += by as u64;
            Ok(by)
        };
        match self.file {
            Net::IpForward | Net::Forwarding(_) => {
                if !net_admin {
                    return Err(Errno::EPERM);
                }
                let target = match self.file {
                    Net::Forwarding(target) => target,
                    _ => Target::All,
                };
                match parsed {
                    Ok((value, consumed)) => {
                        let told = crate::netconf::set_forwarding(
                            &mut self.network.devices(),
                            target,
                            value,
                        );
                        crate::netlink::devconf::tell(&self.network, told);
                        advance(position, consumed)
                    }
                    Err(true) => advance(position, buf.len()),
                    Err(false) => Err(Errno::EINVAL),
                }
            }
            Net::RpFilter(target) => {
                let told = crate::netconf::set_rp_filter(
                    &mut self.network.devices(),
                    target,
                    parsed.ok().map(|(value, _)| value),
                );
                crate::netlink::devconf::tell(&self.network, told);
                match parsed {
                    Ok((_, consumed)) => advance(position, consumed),
                    Err(true) => advance(position, buf.len()),
                    Err(false) => Err(Errno::EINVAL),
                }
            }
            Net::DisableIpv6(target) | Net::Forwarding6(target) => {
                // `proc_dointvec`'s error first, as Linux master's handlers
                // (and the CI kernel's) return it; past the start, the value
                // as it was.
                let (value, taken) = match parsed {
                    Ok((value, consumed)) => (value, consumed),
                    Err(true) => (net_value(&self.network, self.file), buf.len()),
                    Err(false) => return Err(Errno::EINVAL),
                };
                if let Net::Forwarding6(_) = self.file {
                    let told =
                        crate::netconf::set_forwarding6(&mut self.network.devices(), target, value);
                    crate::netlink::devconf::tell(&self.network, told);
                } else {
                    let changed = crate::netconf::set_disable_ipv6(
                        &mut self.network.devices(),
                        target,
                        value,
                    );
                    let now = self
                        .host
                        .clock(paludarium_host::ClockId::Monotonic)
                        .unwrap_or(0);
                    for (index, change) in changed {
                        if index == crate::netdev::LOOPBACK_INDEX {
                            crate::netlink::set_ipv6(
                                &self.network,
                                change == crate::netconf::Change::On,
                                now,
                            );
                        }
                    }
                }
                advance(position, taken)
            }
        }
    }
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
            Self::Machine(machine, file) => machine.line(*file),
            Self::Net(net) => line(net_value(&net.network, net.file)),
        }
    }
    /// After a write that went through, one past the start too: a set
    /// `kernel.shm_rmid_forced` removes the orphans no mapping shows, as
    /// Linux master's `proc_ipc_dointvec_minmax_orphans` does (7.0's did so
    /// after a read too).
    fn touched(&self) {
        if let Self::Kernel(ipc, Kernel::ShmRmidForced) = self {
            ipc.shm.remove_orphans();
        }
    }
    /// Takes the value written at the start of the file, by a writer with
    /// `CAP_SYS_ADMIN` (`admin`) or without: the bytes taken.
    fn write(&self, buf: &[u8], admin: bool) -> Result<usize, Errno> {
        match self {
            Self::Mqueue(queues, setting) => {
                let (value, bounds) = setting.of(queues.limits());
                let (parsed, consumed) = parse(buf, bounds)?;
                value.store(parsed, Ordering::SeqCst);
                Ok(consumed)
            }
            Self::Kernel(ipc, file) => kernel_write(ipc, *file, buf),
            Self::Machine(machine, file) => machine.write(*file, buf, admin),
            // Taken whole by [`NetFile::take`].
            Self::Net(_) => Err(Errno::EINVAL),
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

/// Whether `file` is an open file of `/proc/sys`, whose size of 0 does not
/// bound what a read gives ([`stat`]).
pub(crate) fn is_file(file: &dyn std::any::Any) -> bool {
    file.is::<SettingFile>()
}

/// An open file of `/proc/sys`.
struct SettingFile {
    value: Value,
    /// Who may write it, and whether the opener had `CAP_SYS_ADMIN`, for a
    /// write that does not say who makes it.
    writers: Writers,
    admin: bool,
    /// Whether the opener had `CAP_NET_ADMIN` over the network namespace,
    /// for a write of `/proc/sys/net` that does not say who makes it.
    net_admin: bool,
    stat: FileStat,
    position: Mutex<u64>,
    flags: u32,
}

impl SettingFile {
    fn position(&self) -> MutexGuard<'_, u64> {
        self.position.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// A write by `writer`, checked again as Linux's `proc_sys_call_handler`
    /// does (`EPERM`), or, for none, by the opener.
    fn write_by(
        &self,
        buf: &[u8],
        writer: Option<&crate::credentials::Credentials>,
    ) -> Result<usize, Errno> {
        if self.flags & 3 == 0 {
            return Err(Errno::EBADF);
        }
        let (admin, net_admin) = match writer {
            Some(credentials) => {
                if !self.writers.allow(credentials) {
                    return Err(Errno::EPERM);
                }
                (
                    credentials.capable(crate::credentials::CAP_SYS_ADMIN),
                    self.writers.net_admin(credentials),
                )
            }
            None => (self.admin, self.net_admin),
        };
        let written = self.take(buf, admin, net_admin);
        if written.is_ok() {
            self.value.touched();
        }
        written
    }
    fn take(&self, buf: &[u8], admin: bool, net_admin: bool) -> Result<usize, Errno> {
        let mut position = self.position();
        if buf.is_empty() {
            return Ok(0);
        }
        if let Value::Net(net) = &self.value {
            return net.take(buf, &mut position, net_admin);
        }
        // `sysctl_writes_strict`: a write past the start is taken whole and
        // changes nothing.
        if *position != 0 {
            *position += buf.len() as u64;
            return Ok(buf.len());
        }
        let consumed = self.value.write(buf, admin)?;
        *position += consumed as u64;
        Ok(consumed)
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
    /// A write that does not say who makes it, checked at the open only.
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.write_by(buf, None)
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
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
    fn each_entry_has_an_inode_of_its_own_which_its_listing_gives() {
        let mut all = vec![];
        for directory in [
            Directory::Sys,
            Directory::Fs,
            Directory::Mqueue,
            Directory::Inotify,
            Directory::Fanotify,
            Directory::Kernel,
            Directory::Net,
            Directory::Ipv4,
            Directory::Ipv6,
            Directory::Conf4,
            Directory::Conf6,
            Directory::Device4(Target::All),
            Directory::Device4(Target::Default),
            Directory::Device6(Target::All),
            Directory::Device6(Target::Default),
        ] {
            all.push(Entry::Directory(directory));
            let listed = entries_of(directory, None);
            assert_eq!(listed[0].inode, inode(Entry::Directory(directory)));
            for named in &listed[2..] {
                let entry = child(directory, &named.name, None).unwrap();
                assert_eq!(named.inode, inode(entry), "{entry:?}");
                if !matches!(entry, Entry::Directory(_)) {
                    all.push(entry);
                }
            }
        }
        let mut inodes: Vec<u64> = all.iter().map(|&entry| inode(entry)).collect();
        inodes.sort_unstable();
        inodes.dedup();
        assert_eq!(inodes.len(), all.len());
        assert!(
            inodes
                .iter()
                .all(|&n| n >= 0x1_0000 && n <= u32::MAX as u64)
        );
    }

    #[test]
    fn paths_name_the_directories_and_settings() {
        assert_eq!(
            lookup(b"/proc/sys", None),
            Some(Entry::Directory(Directory::Sys))
        );
        assert_eq!(
            lookup(b"/proc/sys/", None),
            Some(Entry::Directory(Directory::Sys))
        );
        assert_eq!(
            lookup(b"/proc/sys/fs", None),
            Some(Entry::Directory(Directory::Fs))
        );
        assert_eq!(
            lookup(b"/proc/sys/fs/mqueue/", None),
            Some(Entry::Directory(Directory::Mqueue))
        );
        assert_eq!(
            lookup(b"/proc/sys/fs/mqueue/msg_max", None),
            Some(Entry::Setting(Setting::MsgMax))
        );
        assert_eq!(lookup(b"/proc/sys/fs/mqueue/other", None), None);
        assert_eq!(
            lookup(b"/proc/sys/fs/aio-max-nr", None),
            Some(Entry::Aio(Aio::MaxNr))
        );
        assert_eq!(
            lookup(b"/proc/sys/fs/aio-nr", None),
            Some(Entry::Aio(Aio::Nr))
        );
        assert_eq!(entries_of(Directory::Fs, None).len(), 7);
        assert_eq!(
            lookup(b"/proc/sys/fs/inotify", None),
            Some(Entry::Directory(Directory::Inotify))
        );
        assert_eq!(
            lookup(b"/proc/sys/fs/inotify/max_user_watches", None),
            Some(Entry::Inotify(Inotify::UserWatches))
        );
        assert_eq!(lookup(b"/proc/sys/fs/inotify/other", None), None);
        assert_eq!(entries_of(Directory::Inotify, None).len(), 5);
        assert_eq!(entries_of(Directory::Fanotify, None).len(), 6);
        assert_eq!(
            lookup(b"/proc/sys/fs/fanotify/max_user_marks", None),
            Some(Entry::Fanotify(Fanotify::UserMarks))
        );
        assert_eq!(lookup(b"/proc/sys/fs/fanotify/other", None), None);
        assert_eq!(
            lookup(b"/proc/sys/kernel", None),
            Some(Entry::Directory(Directory::Kernel))
        );
        assert_eq!(
            lookup(b"/proc/sys/kernel/sem", None),
            Some(Entry::Kernel(Kernel::Sem))
        );
        assert_eq!(lookup(b"/proc/sys/kernel/other", None), None);
        assert_eq!(entries_of(Directory::Sys, None).len(), 5);
        assert_eq!(entries_of(Directory::Kernel, None).len(), 19);
        assert_eq!(lookup(b"/proc/system", None), None);
        assert_eq!(entries_of(Directory::Mqueue, None).len(), 7);
    }

    #[test]
    fn net_paths_name_their_directories_and_files() {
        let network = crate::inet::Network::isolated(crate::users::first());
        let named = |path: &[u8]| lookup(path, Some(&network));
        assert_eq!(
            named(b"/proc/sys/net"),
            Some(Entry::Directory(Directory::Net))
        );
        assert_eq!(lookup(b"/proc/sys/net", None), None);
        assert_eq!(named(b"/proc/sys/network"), None);
        assert_eq!(
            named(b"/proc/sys/net/ipv4/"),
            Some(Entry::Directory(Directory::Ipv4))
        );
        assert_eq!(
            named(b"/proc/sys/net/ipv4/ip_forward"),
            Some(Entry::Net(Net::IpForward))
        );
        let lo = Target::Device(crate::netdev::LOOPBACK_INDEX);
        assert_eq!(
            named(b"/proc/sys/net/ipv6/conf/lo"),
            Some(Entry::Directory(Directory::Device6(lo)))
        );
        assert_eq!(
            named(b"/proc/sys/net/ipv6/conf/all/disable_ipv6"),
            Some(Entry::Net(Net::DisableIpv6(Target::All)))
        );
        assert_eq!(
            named(b"/proc/sys/net/ipv4/conf/default/rp_filter"),
            Some(Entry::Net(Net::RpFilter(Target::Default)))
        );
        assert_eq!(named(b"/proc/sys/net/ipv4/conf/eth0/rp_filter"), None);
        assert_eq!(named(b"/proc/sys/net/ipv6/conf/lo/rp_filter"), None);
        assert_eq!(named(b"/proc/sys/net/ipv6/ip_forward"), None);
        let names = |d| -> Vec<Vec<u8>> {
            entries_of(d, Some(&network))
                .into_iter()
                .map(|e| e.name)
                .collect()
        };
        assert_eq!(
            names(Directory::Conf4),
            [&b"."[..], b"..", b"all", b"default", b"lo"]
        );
        assert_eq!(
            names(Directory::Device6(lo)),
            [&b"."[..], b"..", b"disable_ipv6", b"forwarding"]
        );
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
